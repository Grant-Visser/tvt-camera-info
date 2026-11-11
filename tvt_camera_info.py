#!/usr/bin/env python3
"""
tvt-camera-info.py — look up a TVT / Provision-ISR / Xiongmai-family camera's
serial number and MAC address over the LAN.

These devices speak DVRIP ("NetSurveillance" / "Sofia") — a JSON protocol
sent as length-prefixed binary frames. Login is command 1000 with a
"sofia hash" of the password (never plaintext). Attempt order (auto):
  1. TCP   DVRIP on port 34567   (the protocol's native transport)
  2. HTTP  port 80, two documented shapes in this device family:
       a. DVRIP JSON relay at "/"          (Xiongmai-style firmwares)
       b. Provision-ISR XML API: command in the URL path (/GetDeviceInfo, …)
          with mandatory HTTP Basic/Digest auth on every request
          (official "HTTP API Protocol User Guide v1.9", 2020-05 — this is
          what answers 401 + WWW-Authenticate when unauthenticated)
  3. ONVIF SOAP on ports 80, then 8899 (last resort — often disabled; modern
     firmware serves it on the web port with HTTP Basic/Digest auth)

TVT-family "data port" 9008 / NVR 6036 serve the vendor's proprietary
NET_SDK binary protocol (libdvrnetsdk); they are not the DVRIP JSON port and
are intentionally not probed by this stdlib-only tool.

The MAC is cross-checked against the local ARP table when a protocol doesn't
report one. Works on Windows, Linux and macOS. Python 3.8+, standard library
only.
"""

import argparse
import base64
import hashlib
import html
import json
import re
import socket
import struct
import subprocess
import sys
import time
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET

# ── Exit codes ────────────────────────────────────────────────────────────────
EXIT_OK = 0
EXIT_NO_ROUTE = 1        # host unreachable / timed out / wrong network
EXIT_AUTH = 2            # wrong username or password
EXIT_ALL_FAILED = 3      # every protocol attempted and none produced info
EXIT_UNEXPECTED = 4      # anything else

TIMEOUT_DEFAULT = 8.0

DVRIP_HTTP_PORT = 80
DVRIP_TCP_PORT = 34567
ONVIF_PORT = 8899
# TVT/Provision "data port" — vendor NET_SDK protocol, not DVRIP (see module docstring)
TVT_DATA_PORT = 9008

ONVIF_PATH = "/onvif/device_service"

# ── DVRIP command codes (NETsurveillance / Sofia) ─────────────────────────────
CMD_LOGIN = 1000            # CMD_LOGIN (OPMachine variant used by all real stacks)
CMD_LOGOUT = 1201           # CMD_LOGOUT
CMD_KEEPALIVE = 1006        # CMD_KEEPALIVE
CMD_CONFIG_GET = 1042       # CMD_CONFIG_GET — Name may be "SystemInfo"/"General"/...
CMD_SYSINFO = 1020          # CMD_SYSINFO


def die(msg: str, code: int) -> "None":
    print(f"ERROR: {msg}")
    sys.exit(code)


# ── Debug tracing (stderr only; --debug enables) ─────────────────────────────

DEBUG = False


def dbg(msg: str) -> None:
    """One debug line to stderr; never touches normal stdout output."""
    if DEBUG:
        print(f"  [dbg] {msg}", file=sys.stderr, flush=True)


def _redact(text: str) -> str:
    """Mask anything that looks like Basic credentials in a header value."""
    return re.sub(r"(Basic\s+)[A-Za-z0-9+/=]+", r"\1<redacted>", text or "")


class AuthError(Exception):
    pass


class RouteError(Exception):
    pass


class UnexpectedError(Exception):
    pass


class HttpAuthChallenge(Exception):
    """HTTP 401 persisted even after a credentialed retry."""

    def __init__(self, www_authenticate: str = ""):
        super().__init__("HTTP authentication failed")
        self.www_authenticate = www_authenticate or ""


# ── DVRIP password hashing ────────────────────────────────────────────────────

def md5_upper(s: str) -> str:
    """MD5 hex digest, uppercase — hash used by some web-login variants."""
    return hashlib.md5(s.encode("utf-8")).hexdigest().upper()


def sofia_hash(password: str = "") -> str:
    """
    The DVRIP "sofia hash": MD5 of the password, then each pair of adjacent
    digest bytes summed mod 62 into an alphanumeric character. This is what
    every known Xiongmai/TVT-family client sends in Body.PassWord.
    """
    md5 = hashlib.md5(password.encode("utf-8")).digest()
    chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    return "".join(chars[(a + b) % 62] for a, b in zip(md5[::2], md5[1::2]))


def is_valid_ipv4(ip: str) -> bool:
    """True when ip is a dotted-quad IPv4 address."""
    try:
        socket.inet_aton(ip)
        parts = ip.split(".")
        return len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255
                                       for p in parts)
    except (OSError, ValueError):
        return False


def scan_camera_ports(ip: str, timeout: float) -> "list[int]":
    """Quick TCP connect sweep of the ports that matter in this device family
    (HTTP/XML 80+8080, DVRIP 34567, TVT data 9008/6036, ONVIF 8899, others).
    Returns the sorted list of open ports. Debug/diagnostic only."""
    interesting = [80, 81, 8899, 8000, 8080, 8554, 9000, 9008, 9527, 9530,
                   554, 6036, 34567, 34599, 49152]
    open_ports: "list[int]" = []
    for port in interesting:
        try:
            with socket.create_connection((ip, port), timeout=max(0.5, timeout / 2)):
                open_ports.append(port)
            dbg(f"portscan {ip}:{port} OPEN")
        except (socket.timeout, TimeoutError):
            dbg(f"portscan {ip}:{port} filtered/timeout")
        except OSError as e:
            dbg(f"portscan {ip}:{port} closed ({getattr(e, 'errno', '?')})")
    return open_ports


def ping_host(ip: str, timeout: float) -> "tuple[bool, str]":
    """
    Single ICMP ping before any auth is attempted.
    Returns (alive, detail). detail is a human-readable line either way.
    Uses the OS ping binary so no raw sockets/admin rights are needed;
    falls back to a TCP connect check on the DVRIP ports when ICMP is
    blocked (common on Windows firewalls and camera VLANs).
    """
    count = "-n" if sys.platform.startswith("win") else "-c"
    wait = "-w" if sys.platform.startswith("win") else "-W"
    # Windows -w is milliseconds; nix -W is seconds
    wait_arg = str(int(timeout * 1000)) if sys.platform.startswith("win") \
        else str(max(1, int(timeout)))
    cmd = ["ping", count, "1", wait, wait_arg, ip]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=timeout + 5)
    except (OSError, subprocess.TimeoutExpired):
        alive, detail = False, "ping could not run or timed out"
    else:
        out = (proc.stdout or "") + (proc.stderr or "")
        alive = proc.returncode == 0
        m = re.search(r"time[=<]([\d.]+)\s*ms", out)
        rtt = f", {m.group(1)} ms" if m else ""
        if alive:
            detail = f"host answered ICMP echo (1 packet{rtt})"
        elif "unreachable" in out.lower():
            detail = "host unreachable (no route / wrong VLAN?)"
        elif "timed out" in out.lower() or "100%" in out:
            detail = "no ICMP reply (host down, or ICMP blocked)"
        else:
            detail = f"no ICMP reply (ping exit {proc.returncode})"

    if alive:
        return True, detail

    # ICMP blocked ≠ camera absent: try a TCP connect on known ports.
    for port in (DVRIP_TCP_PORT, DVRIP_HTTP_PORT):
        try:
            with socket.create_connection((ip, port), timeout=timeout):
                dbg(f"ping fallback: TCP {port} open → treating host as alive")
                return True, (f"ICMP blocked, but TCP port {port} is open — "
                              f"camera is up (ping is just firewalled)")
        except OSError:
            continue
    return False, detail


# ── DVRIP frames ──────────────────────────────────────────────────────────────

def dvr_login_body(user: str, password: str, encrypt: str = "MD5") -> dict:
    """
    DVRIP login frame for command 1000. Password is the sofia hash,
    never plaintext. Known-good default hash for an empty password
    is "tlJwpbo6", and "admin" hashes to "6QNMIQGe".
    """
    return {"EncryptType": encrypt,
            "LoginType": "DVRIP-Web",
            "PassWord": sofia_hash(password),
            "UserName": user}


def dvr_logout_body() -> dict:
    """DVRIP logout body for command 1201."""
    return {"Name": "", "SessionID": "0x0"}


def dvr_config_get_body(name: str) -> dict:
    """Config-Get body for command 1042 (e.g. SystemInfo / NetWork.NetCommon)."""
    return {"Name": name, "SessionID": "0x0"}


def dvr_frame(payload: dict, msg_id: int,
              session_id: "int | None" = None, seq: int = 0) -> bytes:
    """
    Wrap a JSON body in the 20-byte DVRIP binary envelope:
      0xFF | version(0) | 2 reserved | SessionID (u32 LE) | packet seq (u32 LE)
      | MsgID (u16 LE) | 2 reserved | payload length (u32 LE, includes trailer)
    followed by the JSON payload and a b"\\x0a\\x00" trailer.
    """
    data = json.dumps(payload).encode("utf-8")
    if session_id is None:
        session_id = 0
    header = struct.pack("BB2xII2xHI", 0xFF, 0, session_id, seq, msg_id,
                         len(data) + 2)
    return header + data + b"\x0a\x00"


def dvr_unpack_header(frame: bytes) -> "tuple[int, int, int, int]":
    """(session_id, seq, msg_id, payload_len) from a 20-byte DVRIP header."""
    _head, _ver, session_id, seq, msg_id, length = struct.unpack(
        "BB2xII2xHI", frame[:20])
    return session_id, seq, msg_id, length


def is_dvrip_header(frame: bytes) -> bool:
    """Header sanity: starts with 0xFF, version byte 0, plausible length."""
    if len(frame) < 20 or frame[0] != 0xFF:
        return False
    try:
        length = dvr_unpack_header(frame)[3]
    except struct.error:
        return False
    return 0 < length <= 16 * 1024 * 1024


# ── Shared DVRIP helpers ──────────────────────────────────────────────────────

DEVICE_INFO_KEYS = ("serialnumber", "manufacturer", "model", "firmware",
                    "firmwareversion", "devicename", "hardware",
                    "devicetype", "hardware", "hardwareversion",
                    "softwareversion", "serialno", "macaddress",
                    "sn", "mac")  # TVT XML API tag spellings (sn/mac)


def extract_device_info(obj) -> dict:
    """Recursively pull device-info fields out of any DVRIP JSON reply body."""
    found: dict = {}
    stack = [obj]
    while stack:
        cur = stack.pop()
        if isinstance(cur, dict):
            for k, v in cur.items():
                kl = str(k).lower()
                if kl in DEVICE_INFO_KEYS and isinstance(v, (str, int, float)) \
                        and str(v).strip():
                    found[k] = str(v).strip()
                elif isinstance(v, (dict, list)):
                    stack.append(v)
        elif isinstance(cur, list):
            stack.extend(cur)
    return found


def _session_from(any_dicts) -> "str | None":
    """SessionID from a JSON body (may appear at root or nested)."""
    stack = list(any_dicts)
    while stack:
        cur = stack.pop()
        if isinstance(cur, dict):
            for k, v in cur.items():
                if k.lower() == "sessionid" and v:
                    return str(v)
                if isinstance(v, (dict, list)):
                    stack.append(v)
        elif isinstance(cur, list):
            stack.extend(cur)
    return None


# Xiongmai return codes that mean "credentials rejected"
AUTH_FAIL_RETS = {103, 106, 203, 204, 214, 216, 606}
# Non-auth-specific error codes worth surfacing distinctly
GENERIC_FAIL_RETS = {101, 117, 502, 605}


def classify_login_reply(reply: dict) -> str:
    """
    Classify a login (1000) reply: "ok", "auth", "error" or "terse".
    Success = Ret in {100, 150, ...OK codes} AND a real SessionID.
    """
    ret = reply.get("Ret")
    try:
        ret_i = int(ret)
    except (TypeError, ValueError):
        ret_i = None
    session = _session_from([reply])
    good_session = bool(session) and str(session).strip().lower() not in (
        "0x0", "0", "null", "none", "")
    if ret_i in (100, 150, 515) and good_session:
        return "ok"
    if ret_i in AUTH_FAIL_RETS:
        return "auth"
    if ret_i in GENERIC_FAIL_RETS:
        return "error"
    if ret_i is not None:
        # Unknown numeric code — auth if no session was granted, else terse
        return "error" if good_session else "auth"
    if good_session:
        return "terse"  # no Ret but a real session id — treat as success
    return "auth"


# ── TCP transport (the protocol's native transport, port 34567) ───────────────

class _DvripTcpSession:
    """
    One DVRIP-over-TCP session: connect → login(1000) → queries → logout(1201).
    Implements the exact framing used by every known Xiongmai client.
    """

    def __init__(self, ip: str, port: int, timeout: float):
        self.timeout = timeout
        try:
            self.sock = socket.create_connection((ip, port), timeout=timeout)
        except OSError as e:
            raise RouteError(f"could not connect ({e})") from None
        self.sock.settimeout(timeout)
        self.session = 0
        self.seq = 0

    def _recv_exact(self, n: int) -> bytes:
        buf = bytearray()
        while len(buf) < n:
            chunk = self.sock.recv(n - len(buf))
            if not chunk:
                raise RouteError("connection closed by camera mid-frame")
            buf.extend(chunk)
        return bytes(buf)

    def send(self, payload: dict, msg_id: int) -> dict:
        self.seq += 1
        self.sock.sendall(dvr_frame(payload, msg_id, self.session, self.seq))
        prefix = self._recv_exact(20)
        if not is_dvrip_header(prefix):
            raise UnexpectedError("camera sent a frame that is not DVRIP")
        sid, _seq, _mid, length = dvr_unpack_header(prefix)
        raw = self._recv_exact(length)
        if raw.endswith(b"\x0a\x00"):
            raw = raw[:-2]
        try:
            reply = json.loads(raw.decode("utf-8", errors="replace"))
        except ValueError:
            raise UnexpectedError("camera reply was not valid DVRIP JSON") from None
        if sid:
            self.session = sid
        return reply

    def login(self, user: str, password: str) -> dict:
        reply = self.send(dvr_login_body(user, password), CMD_LOGIN)
        verdict = classify_login_reply(reply)
        if verdict == "ok":
            try:
                self.session = int(str(_session_from([reply])), 16)
            except (TypeError, ValueError):
                pass
            return reply
        if verdict == "auth":
            raise AuthError("camera rejected the login (bad username/password)")
        if verdict == "terse":
            return reply
        raise UnexpectedError(f"camera returned error code {reply.get('Ret')!r} "
                              f"for the login")

    def config_get(self, name: str) -> dict:
        body = dvr_config_get_body(name)
        body["SessionID"] = f"0x{self.session:08X}" if self.session else "0x0"
        return self.send(body, CMD_CONFIG_GET)

    def logout(self) -> None:
        try:
            body = dvr_logout_body()
            body["SessionID"] = f"0x{self.session:08X}" if self.session else "0x0"
            self.send(body, CMD_LOGOUT)
        except (AuthError, RouteError, UnexpectedError, OSError):
            pass

    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass


def dvrip_tcp_query(ip: str, port: int, user: str, password: str,
                    timeout: float) -> dict:
    """Full DVRIP session over raw TCP: login → info queries → logout."""
    sess = _DvripTcpSession(ip, port, timeout)
    try:
        login_reply = sess.login(user, password)
        info = extract_device_info(login_reply)
        for name in ("SystemInfo", "NetWork.NetCommon", "General"):
            try:
                info.update(extract_device_info(sess.config_get(name)))
            except (AuthError, RouteError, UnexpectedError):
                continue  # best-effort
        if not info.get("MACAddress"):
            nc = sess.config_get("NetWork.NetCommon")
            mac = _mac_from_netcommon(nc)
            if mac:
                info["MACAddress"] = mac
        sess.logout()
        return info
    finally:
        sess.close()


def _mac_from_netcommon(reply: dict) -> "str | None":
    """MACAddress inside NetWork.NetCommon config replies."""
    stack = [reply]
    while stack:
        cur = stack.pop()
        if isinstance(cur, dict):
            for k, v in cur.items():
                if k.lower() == "macaddress" and isinstance(v, str) \
                        and re.match(r"^[0-9A-Fa-f: -]{12,17}$", v):
                    return v.replace("-", ":").upper()
                if isinstance(v, (dict, list)):
                    stack.append(v)
        elif isinstance(cur, list):
            stack.extend(cur)
    return None


# ── HTTP transport (the web service relays the same JSON, port 80) ────────────

def _http_post_json(url: str, frame: bytes, timeout: float,
                    session_id: "str | None" = None,
                    auth_header: "str | None" = None,
                    content_type: str = "application/json",
                    method: str = "POST") -> "tuple[bytes, dict | None]":
    headers = {"Content-Type": content_type, "Connection": "keep-alive",
               "User-Agent": "tvt-camera-info/1.2"}
    if session_id:
        headers["SessionID"] = session_id
    if auth_header:
        headers["Authorization"] = auth_header
    dbg(f"HTTP {method} {url}  auth={_redact(auth_header) if auth_header else 'none'} "
        f"body={len(frame)}B")
    req = urllib.request.Request(url, data=frame if method == "POST" else None,
                                 method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body_out = resp.read()
            dbg(f"← {resp.status} ct={resp.headers.get('Content-Type', '?')} "
                f"{len(body_out)}B: {body_out[:200]!r}")
            return body_out, resp.headers
    except urllib.error.HTTPError as e:
        body_out = b""
        try:
            body_out = e.read()
        except Exception:
            pass
        dbg(f"← HTTP {e.code} WWW-Auth={_redact(e.headers.get('WWW-Authenticate', '') if e.headers else '')} "
            f"Server={e.headers.get('Server', '?') if e.headers else '?'} "
            f"body={body_out[:200]!r}")
        if e.code == 401:
            raise HttpAuthChallenge(e.headers.get("WWW-Authenticate", "") if e.headers else "") from None
        if e.code in (400, 403):
            raise AuthError(f"camera rejected the request (HTTP {e.code})") from None
        raise UnexpectedError(f"camera answered HTTP {e.code}") from None
    except (socket.timeout, TimeoutError):
        dbg("← timeout")
        raise RouteError("connection timed out") from None
    except (ConnectionError, OSError) as e:
        dbg(f"← connection failed: {e}")
        raise RouteError(f"could not connect ({e})") from None


def _basic_auth_header(user: str, password: str) -> str:
    token = base64.b64encode(f"{user}:{password}".encode("utf-8")).decode("ascii")
    return f"Basic {token}"


def _auth_scheme_from_challenge(www_authenticate: str) -> str:
    """"Basic" or "digest" from a WWW-Authenticate header; Basic is the
    documented default for the Provision-ISR API (User Guide v1.9 §1.3.3)."""
    m = re.search(r"\b(basic|digest)\b", www_authenticate or "", re.IGNORECASE)
    return m.group(1).lower() if m else "basic"


def _http_request_with_auth(url: str, user: str, password: str, timeout: float,
                            content_type: str = "application/xml",
                            method: str = "POST") -> bytes:
    """
    HTTP request with layered credentials, per the Provision-ISR/TVT HTTP API
    (auth required on EVERY request; 401 + WWW-Authenticate when omitted).
    Sequence: unauthenticated probe → read the camera's challenge header →
    retry with Basic (documented default) or Digest (stdlib handler, same
    credentials — password never rides in a URL or query string).
    """
    challenges: "list[str]" = []
    for attempt in range(2):
        if attempt == 0:
            auth = None                     # first probe: no Authorization header
        else:
            scheme = _auth_scheme_from_challenge(" ".join(challenges))
            dbg(f"challenge(s)={_redact(' '.join(challenges))!r} → retrying {method} with scheme={scheme}")
            if scheme == "digest":
                mgr = urllib.request.HTTPPasswordMgrWithDefaultRealm()
                mgr.add_password(None, url, user, password)
                opener = urllib.request.build_opener(
                    urllib.request.HTTPDigestAuthHandler(mgr))
                req = urllib.request.Request(
                    url, data=b"" if method == "POST" else None, method=method,
                    headers={"Content-Type": content_type, "Connection": "keep-alive",
                             "User-Agent": "tvt-camera-info/1.2"})
                try:
                    with opener.open(req, timeout=timeout) as resp:
                        out = resp.read()
                        dbg(f"← {resp.status} ({method}, digest) {len(out)}B: {out[:200]!r}")
                        return out
                except urllib.error.HTTPError as e:
                    dbg(f"← digest retry HTTP {e.code} WWW-Auth="
                        f"{_redact(e.headers.get('WWW-Authenticate', '') if e.headers else '')}")
                    raise HttpAuthChallenge(
                        e.headers.get("WWW-Authenticate", "") if e.headers else "") from None
                except (socket.timeout, TimeoutError):
                    raise RouteError("connection timed out") from None
                except (ConnectionError, OSError) as e:
                    raise RouteError(f"could not connect ({e})") from None
            auth = _basic_auth_header(user, password)
        try:
            raw, _hdrs = _http_post_json(url, b"", timeout, auth_header=auth,
                                         content_type=content_type, method=method)
            return raw
        except HttpAuthChallenge as e:
            challenges.append(e.www_authenticate)
            if attempt == 1:
                raise
    raise UnexpectedError("unreachable")  # pragma: no cover


def _http_get_with_auth(url: str, body: bytes, user: str, password: str,
                        timeout: float, content_type: str = "application/xml") -> bytes:
    """GET variant — the vendor's own Postman collection uses GET; same
    probe → challenge → Basic/Digest retry sequence."""
    return _http_request_with_auth(url, user, password, timeout,
                                   content_type=content_type, method="GET")


def _http_post_with_auth(url: str, body: bytes, user: str, password: str,
                         timeout: float, content_type: str = "application/xml") -> bytes:
    """POST variant of the credentialed request (see _http_request_with_auth)."""
    return _http_request_with_auth(url, user, password, timeout,
                                   content_type=content_type, method="POST")


def _xml_text_all(xml_bytes: bytes) -> dict:
    """Flatten an XML document to {tag: text} (leaf elements only,
    namespace-agnostic). Tags keep their case as found."""
    out: dict = {}
    try:
        root = ET.fromstring(xml_bytes)
    except ET.ParseError:
        return out
    stack = [root]
    while stack:
        el = stack.pop()
        tag = el.tag.split("}")[-1]
        if tag not in out and el.text and el.text.strip() and len(list(el)) == 0:
            out[tag] = el.text.strip()
        stack.extend(el)
    return out


def provision_xml_query(ip: str, port: int, user: str, password: str,
                        timeout: float) -> dict:
    """
    Provision-ISR / TVT official XML-over-HTTP API ("HTTP API Protocol User
    Guide v1.9", 2020-05): the command is the URL path, HTTP Basic (or Digest)
    auth is required on every request, bodies are XML, and an unauthenticated
    request draws 401 + WWW-Authenticate — exactly the observed "401
    authentication failure". Device info via GetDeviceInfo + GetDeviceDetail
    (+ GetNetBasicConfig for network details).
    """
    base = f"http://{ip}:{port}"
    info: dict = {}
    for command in ("GetDeviceInfo", "GetDeviceDetail", "GetNetBasicConfig"):
        url = f"{base}/{command}"
        # spec allows POST or GET; the vendor's own Postman collection uses
        # GET, so GET first and fall back to POST for POST-only firmwares
        raw: "bytes | None" = None
        last_err: "Exception | None" = None
        for fetch in (_http_get_with_auth, _http_post_with_auth):
            try:
                raw = fetch(url, b"", user, password, timeout)
                break
            except HttpAuthChallenge as e:
                raise AuthError(
                    "camera rejected the HTTP credentials (scheme: "
                    f"{_auth_scheme_from_challenge(e.www_authenticate) or 'basic'})") from None
            except (AuthError, RouteError):
                raise
            except UnexpectedError as e:
                last_err = e
                dbg(f"{command}: {fetch.__name__} failed ({e}); trying next method")
                continue
        if raw is None:
            dbg(f"{command}: both GET and POST failed — skipping")
            continue
        fields = _xml_text_all(raw)
        for k, v in fields.items():
            info.setdefault(k, v)
    if not info:
        raise UnexpectedError("camera returned no parseable XML device info")
    # serial fallback: this API's device-info commands may not carry a serial
    # tag (observed on TD-9423A3-LR ANPR firmware 5.1.1.0). Probe GetCaps for
    # a SerialNumber/SN element. If the device reports no serial anywhere, the
    # field is omitted — never derived or synthesized from the UUID or anything
    # else; a later transport (ONVIF) may still report the real one.
    if not any(k.lower() in ("serialnumber", "sn", "serialno") for k in info):
        try:
            url = f"{base}/GetCaps"
            raw = _http_get_with_auth(url, b"", user, password, timeout)
            caps = _xml_text_all(raw)
            for k, v in caps.items():
                if k.lower() in ("serialnumber", "sn", "serialno"):
                    info[k] = v
                    break
        except (AuthError, RouteError, HttpAuthChallenge, UnexpectedError):
            dbg("GetCaps probe unavailable")
    if not any(k.lower() in ("serialnumber", "sn", "serialno") for k in info):
        dbg("device reported no serial on this API — omitting SerialNumber")
    # normalize the XML "mac" tag to the MACAddress key used elsewhere
    mac = info.pop("mac", None) or info.pop("MAC", None)
    if mac and not info.get("MACAddress"):
        info["MACAddress"] = mac
    return info


def dvrip_http_query(ip: str, port: int, user: str, password: str,
                     timeout: float) -> dict:
    """
    Xiongmai-style DVRIP JSON relay at "/" — kept for firmwares that expose it.
    """
    url = f"http://{ip}:{port}/"
    last_err: "Exception | None" = None
    for mode in ("with-header", "plain"):
        try:
            info = _dvrip_http_attempt(url, user, password, timeout,
                                       send_command_header=(mode == "with-header"))
            if info:
                return info
            last_err = UnexpectedError("camera returned empty device info")
        except AuthError:
            raise
        except HttpAuthChallenge:
            # The JSON relay exists but sits behind HTTP-layer auth → this
            # firmware's port 80 is the XML-API shape; let the xml transport
            # (next in auto order) handle the challenge with its own scheme.
            raise
        except (RouteError, UnexpectedError) as e:
            last_err = e
            continue
    raise last_err if last_err else UnexpectedError("DVRIP HTTP session failed")


def _dvrip_http_attempt(url: str, user: str, password: str, timeout: float,
                        send_command_header: bool) -> dict:
    def post(payload: dict, msg_id: int, session: "str | None" = None) -> dict:
        headers = {}
        if send_command_header:
            headers["Command"] = str(msg_id)
        frame = json.dumps(payload).encode("utf-8")
        raw, hdrs = _http_post_json(url, frame, timeout, session_id=session,
                                    content_type="application/json")
        del hdrs
        try:
            return json.loads(raw.decode("utf-8", errors="replace"))
        except ValueError:
            raise UnexpectedError("camera answer was not valid DVRIP JSON") from None

    reply = post(dvr_login_body(user, password), CMD_LOGIN)
    verdict = classify_login_reply(reply)
    if verdict == "auth":
        raise AuthError("camera rejected the login (bad username/password)")
    if verdict not in ("ok", "terse"):
        raise UnexpectedError(f"camera returned error code {reply.get('Ret')!r} "
                              f"for the login")
    session = _session_from([reply]) or "0x0"
    info = extract_device_info(reply)

    for name in ("SystemInfo", "NetWork.NetCommon", "General"):
        try:
            body = dvr_config_get_body(name)
            body["SessionID"] = session
            info.update(extract_device_info(post(body, CMD_CONFIG_GET, session)))
        except (AuthError, RouteError, UnexpectedError):
            continue
    if not info.get("MACAddress"):
        try:
            body = dvr_config_get_body("NetWork.NetCommon")
            body["SessionID"] = session
            mac = _mac_from_netcommon(post(body, CMD_CONFIG_GET, session))
            if mac:
                info["MACAddress"] = mac
        except (AuthError, RouteError, UnexpectedError):
            pass

    try:
        body = dvr_logout_body()
        body["SessionID"] = session
        post(body, CMD_LOGOUT, session)
    except (AuthError, RouteError, UnexpectedError):
        pass
    return info


# ── ONVIF SOAP (legacy 8899 / port 80, last resort) ──────────────────────────

def soap_request(url: str, user: str, password: str, body: str,
                 timeout: float) -> str:
    """
    POST a raw SOAP envelope with WS-UsernameToken auth; return response text.
    Modern TVT/Provision-ISR IPC firmware serves ONVIF on the main web port
    with HTTP Basic/Digest auth (challenge first) instead of WS-Security
    headers — mirror the XML transport's probe → challenge → credentialed
    retry, and fall back to WS-UsernameToken for legacy 8899 services.
    """
    def envelope() -> str:
        return f"""<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
  <s:Header>
    <Security xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
      <UsernameToken>
        <Username>{user}</Username>
        <Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd#PasswordText">{password}</Password>
      </UsernameToken>
    </Security>
  </s:Header>
  <s:Body>{body}</s:Body>
</s:Envelope>"""
    last_challenge = ""
    for attempt in range(2):
        headers = {
            "Content-Type": 'application/soap+xml; charset=utf-8; '
                            'action="http://www.onvif.org/ver10/device/wsdl/GetDeviceInformation"',
            "User-Agent": "tvt-camera-info/1.2",
        }
        auth = None
        if attempt == 1:
            scheme = _auth_scheme_from_challenge(last_challenge)
            dbg(f"ONVIF challenge(s)={_redact(last_challenge)!r} → retrying with {scheme}")
            if scheme == "digest":
                mgr = urllib.request.HTTPPasswordMgrWithDefaultRealm()
                mgr.add_password(None, url, user, password)
                opener = urllib.request.build_opener(
                    urllib.request.HTTPDigestAuthHandler(mgr))
                req = urllib.request.Request(url, data=envelope().encode("utf-8"),
                                             method="POST", headers=headers)
                try:
                    with opener.open(req, timeout=timeout) as resp:
                        return resp.read().decode("utf-8", errors="replace")
                except urllib.error.HTTPError as e:
                    raise HttpAuthChallenge(
                        e.headers.get("WWW-Authenticate", "") if e.headers else "") from None
                except (socket.timeout, TimeoutError):
                    raise RouteError("connection timed out") from None
                except (ConnectionError, OSError) as e:
                    raise RouteError(f"could not connect ({e})") from None
            auth = _basic_auth_header(user, password)
            headers["Authorization"] = auth
        req = urllib.request.Request(url, data=envelope().encode("utf-8"),
                                     method="POST", headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as e:
            if e.code == 401:
                challenge = e.headers.get("WWW-Authenticate", "") if e.headers else ""
                if attempt == 0:
                    last_challenge = challenge
                    dbg(f"ONVIF probe ← 401 WWW-Auth={_redact(challenge)!r}")
                    continue
                raise HttpAuthChallenge(challenge) from None
            if e.code in (400, 403):
                raise AuthError(f"camera rejected the request (HTTP {e.code})") from None
            raise UnexpectedError(f"camera answered HTTP {e.code}") from None
        except (socket.timeout, TimeoutError):
            raise RouteError("connection timed out") from None
        except (ConnectionError, OSError) as e:
            raise RouteError(f"could not connect ({e})") from None
    raise UnexpectedError("unreachable")  # pragma: no cover


def xml_text(xml: str, tag: str) -> "str | None":
    """Text of the first <tag>...</tag> occurrence (namespace-tolerant)."""
    m = re.search(rf"<(?:[\w.-]+:)?{tag}(?:\s[^>]*)?>(.*?)</(?:[\w.-]+:)?{tag}>",
                  xml, re.DOTALL | re.IGNORECASE)
    if not m:
        return None
    return html.unescape(m.group(1)).strip() or None


def onvif_get_device_information(base_url: str, user: str, password: str,
                                 timeout: float) -> dict:
    body = '<GetDeviceInformation xmlns="http://www.onvif.org/ver10/device/wsdl"/>'
    xml = soap_request(base_url, user, password, body, timeout)
    info = {}
    for tag, key in (("Manufacturer", "Manufacturer"), ("Model", "Model"),
                     ("SerialNumber", "SerialNumber"), ("FirmwareVersion", "Firmware"),
                     ("HardwareId", "HardwareId"), ("Name", "Name")):
        val = xml_text(xml, tag)
        if val:
            info[key] = val
    return info


def onvif_get_network_interfaces(base_url: str, user: str, password: str,
                                 timeout: float) -> "str | None":
    body = '<GetNetworkInterfaces xmlns="http://www.onvif.org/ver10/device/wsdl"/>'
    xml = soap_request(base_url, user, password, body, timeout)
    return xml_text(xml, "HwAddress")


# ── ARP fallback ──────────────────────────────────────────────────────────────

def arp_lookup(ip: str) -> "str | None":
    """Best-effort MAC lookup from the local ARP table (Linux/Windows/macOS)."""
    try:
        if sys.platform.startswith("win"):
            out = subprocess.run(["arp", "-a", ip], capture_output=True, text=True,
                                 timeout=5).stdout
        elif sys.platform == "darwin":
            out = subprocess.run(["arp", ip], capture_output=True, text=True,
                                 timeout=5).stdout
        else:  # Linux
            out = subprocess.run(["ip", "neigh", "show", ip], capture_output=True,
                                 text=True, timeout=5).stdout or \
                  subprocess.run(["arp", "-n", ip], capture_output=True, text=True,
                                 timeout=5).stdout
    except (OSError, subprocess.TimeoutExpired):
        return None

    m = re.search(r"([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})", out)
    if m and m.group(1).lower() != "00:00:00:00:00:00":
        return m.group(1).upper().replace("-", ":")
    return None


# ── Orchestration ─────────────────────────────────────────────────────────────

PROTO_NAMES = {"tcp": "DVRIP over TCP", "http": "DVRIP over HTTP",
               "xml": "Provision-ISR XML API (HTTP)", "onvif": "ONVIF SOAP"}


def _run_proto(proto: str, ip: str, port: int, user: str, password: str,
               timeout: float) -> "tuple[dict | None, str, str, str]":
    """
    Attempt one protocol.
    Returns (info, mac, transport_label, ok) on success, or
    (None, err, label, kind) on failure, where kind ∈ {auth, route, error}.
    """
    label = PROTO_NAMES[proto]
    try:
        if proto == "tcp":
            info = dvrip_tcp_query(ip, port or DVRIP_TCP_PORT, user, password, timeout)
        elif proto == "http":
            info = dvrip_http_query(ip, port or DVRIP_HTTP_PORT, user, password, timeout)
        elif proto == "xml":
            info = provision_xml_query(ip, port or DVRIP_HTTP_PORT, user, password, timeout)
        else:
            # ONVIF is usually served by the main web service on port 80 on
            # modern TVT IPC firmware that advertises onvifVer; 8899 is the
            # legacy standalone service. Try 80 first, then 8899.
            candidates = [(port or ONVIF_PORT, ONVIF_PATH)]
            if (port or ONVIF_PORT) != DVRIP_HTTP_PORT:
                candidates.insert(0, (DVRIP_HTTP_PORT, ONVIF_PATH))
            last_exc: "Exception | None" = None
            for onvif_port, onvif_path in candidates:
                base = f"http://{ip}:{onvif_port}{onvif_path}"
                try:
                    dbg(f"ONVIF attempt: {base}")
                    return onvif_get_device_information(base, user, password, timeout), \
                        onvif_get_network_interfaces(base, user, password, timeout), \
                        label, "ok"
                except (AuthError, RouteError, UnexpectedError) as e:
                    last_exc = e
                    dbg(f"ONVIF {base} failed: {e}")
            raise last_exc if last_exc else UnexpectedError("ONVIF unavailable")
        return info, None, label, "ok"
    except AuthError as e:
        return None, f"auth: {e}", label, "auth"
    except HttpAuthChallenge as e:
        # HTTP-layer auth persisted after a credentialed retry
        return None, ("auth: HTTP 401 after credentialed retry "
                      f"(challenge: {e.www_authenticate or 'none reported'})"), label, "auth"
    except RouteError as e:
        return None, f"unreachable: {e}", label, "route"
    except UnexpectedError as e:
        return None, f"error: {e}", label, "error"


def main() -> None:
    p = argparse.ArgumentParser(
        description="Look up a TVT / Provision-ISR camera's serial number and MAC "
                    "address (DVRIP first, ONVIF as fallback). LAN tool.")
    p.add_argument("--ip", required=True, help="camera IP address, e.g. 192.168.1.64")
    p.add_argument("--user", default="admin", help="camera username (default: admin)")
    p.add_argument("--password", default="", help="camera password")
    p.add_argument("--port", type=int, default=0,
                   help="override the port for the active transport "
                        "(defaults: tcp=34567, http/xml=80, onvif=8899)")
    p.add_argument("--proto", default="auto",
                   choices=["auto", "http", "xml", "tcp", "onvif"],
                   help="which protocol(s) to try: auto tries tcp → http → xml → "
                        "onvif 80/8899 (default: auto)")
    p.add_argument("--timeout", type=float, default=TIMEOUT_DEFAULT,
                   help="network timeout in seconds (default: 8)")
    p.add_argument("--no-ping", action="store_true",
                   help="skip the initial ICMP reachability check")
    p.add_argument("--debug", action="store_true",
                   help="print a wire-level trace of every connection, HTTP "
                        "status, challenge header and reply snippet to stderr "
                        "(credentials redacted) — for remote troubleshooting")
    args = p.parse_args()

    global DEBUG
    if args.debug:
        DEBUG = True
        dbg(f"tvt-camera-info debug trace — target={args.ip} proto={args.proto} "
            f"user={args.user} timeout={args.timeout}s")

    order = ["tcp", "http", "xml", "onvif"] if args.proto == "auto" else [args.proto]

    if not is_valid_ipv4(args.ip):
        die(f"'{args.ip}' doesn't look like an IPv4 address — pass the camera's IP, "
            f"e.g. --ip 192.168.1.64", EXIT_UNEXPECTED)
    failures: "list[str]" = []
    failure_kinds: "list[str]" = []

    print(f"Querying camera at {args.ip} — protocol(s): "
          f"{', '.join(PROTO_NAMES[o] for o in order)}\n")

    # ── Step 0: reachability ping (before any auth is attempted) ────────────
    if not args.no_ping:
        print(f"  pinging {args.ip}...", flush=True)
        alive, detail = ping_host(args.ip, args.timeout)
        print(f"  {'✓' if alive else '✗'} ping: {detail}\n", flush=True)
        if not alive:
            print("=" * 60)
            print(" CAMERA DID NOT RESPOND TO PING")
            print("=" * 60)
            print("  The tool has not tried any login yet. First fix reachability:")
            print("  1. Confirm the camera is powered on and connected (link LED).")
            print("  2. Check your PC is on the same network/VLAN as the camera.")
            print("  3. Verify the IP — wrong address is the most common cause.")
            print("  4. Re-run, or skip this check with --no-ping.")
            print("=" * 60)
            sys.exit(EXIT_NO_ROUTE)

    info = mac = label = None
    held_info = held_mac = held_label = None
    for proto in order:
        print(f"  trying {PROTO_NAMES[proto]}...", flush=True)
        info, mac, label, kind = _run_proto(proto, args.ip, args.port, args.user,
                                            args.password, args.timeout)
        if info and any(k.lower() == "serialnumber" for k in info):
            print(f"  ✓ {label} answered\n")
            break
        if info:
            # The transport answered but did not report a serial: keep trying
            # the remaining transports rather than stopping here. A serial is
            # only ever printed when the device itself reported it.
            print(f"  ✓ {label} answered (no serial reported)\n")
            failures.append(f"{label}: answered but did not report a serial")
            failure_kinds.append(kind)
            if held_info is None:
                held_info, held_mac, held_label = info, mac, label
            info = None
            continue
        failures.append(f"{label}: {mac}")
        failure_kinds.append(kind)
        print(f"  ✗ {label} failed ({mac})\n")

    if info is None and held_info is not None:
        # No transport reported a serial: show the best device info we did
        # get, with the serial honestly omitted (the NOTE below explains).
        info, mac, label = held_info, held_mac, held_label
        print(f"  (no transport reported a serial — showing {label} info "
              f"without one)\n")

    if not info:
        # Remote-debug aid: sweep the family's known ports once, after the
        # protocol attempts, so the operator's paste shows the real port map.
        if args.debug:
            print("  running diagnostic port sweep (debug)...", flush=True)
            open_ports = scan_camera_ports(args.ip, args.timeout)
            if open_ports:
                print(f"  → OPEN TCP ports on {args.ip}: "
                      f"{', '.join(map(str, open_ports))}")
            else:
                print(f"  → no TCP ports open on {args.ip} out of the scanned "
                      f"family set (80, 34567, 9008, 6036, 8899, ...)")
        print("=" * 60)
        print(" NO DEVICE INFORMATION RETURNED")
        print("=" * 60)
        for f in failures:
            print(f"  - {f}")
        print("=" * 60)
        print("\nHow to fix:")
        print("  1. Can't reach the camera → check it is powered on and your PC is on")
        print("     the same network/VLAN; verify the IP with a ping.")
        print("  2. Auth failed → the DVRIP/ONVIF password is wrong. Out of the box")
        print("     these cameras often use admin / admin or admin / (empty). If your")
        print("     password has special characters and works on the web UI but not here,")
        print("     capture the reply shown above and send it to the tool maintainer.")
        print("  3. All protocols unavailable → DVRIP/ONVIF may be switched off in the")
        print("     camera's web UI (Network/System settings). Enable a protocol and")
        print("     re-run.")
        # Exit code: forced single protocol → map its kind specifically;
        # auto (all three) → 3 (all protocols unavailable)
        if len(order) == 1 and failure_kinds:
            sys.exit({"auth": EXIT_AUTH, "route": EXIT_NO_ROUTE,
                      "error": EXIT_UNEXPECTED,
                      "ok": EXIT_UNEXPECTED}.get(failure_kinds[0], EXIT_UNEXPECTED))
        sys.exit(EXIT_ALL_FAILED)

    # MAC: prefer the protocol's own report; otherwise the local ARP table
    if not info.get("MACAddress") and not mac:
        mac = arp_lookup(args.ip)

    print("=" * 60)
    print(" CAMERA INFORMATION")
    print("=" * 60)
    shown = set()
    for key, val in info.items():
        if key.lower() == "macaddress":
            continue
        print(f"  {key:<15}: {val}")
        shown.add(key.lower())
    print(f"  {'MAC address':<15}: {info.get('MACAddress') or mac or 'not found'}")
    print("=" * 60)

    serial = next((v for k, v in info.items() if k.lower() == "serialnumber"), None)
    if not serial:
        print("\nNOTE: no transport reported a serial number for this camera.")
        print("      It is deliberately omitted rather than derived. Try the")
        print("      web UI (Settings → Version/Info) or the label on the unit.")
        sys.exit(EXIT_ALL_FAILED)

    sys.exit(EXIT_OK)


if __name__ == "__main__":
    main()
