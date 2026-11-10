#!/usr/bin/env python3
"""
tvt-camera-info.py — look up a TVT / Provision-ISR camera's serial number and
MAC address over the LAN.

TVT / Provision-ISR devices speak DVRIP ("NetSurveillance") — a JSON protocol.
Attempt order (auto):
  1. HTTP  DVRIP on port 80      (http://<ip>/ — plain HTTP POST of JSON frames)
  2. TCP   DVRIP on port 34567   (length-prefixed JSON frames)
  3. ONVIF SOAP on port 8899     (last resort — often disabled on these cameras)

The MAC is cross-checked against the local ARP table when a protocol doesn't
report one. Works on Windows, Linux and macOS. Python 3.8+, standard library only.
"""

import argparse
import hashlib
import html
import json
import re
import socket
import struct
import subprocess
import sys
import urllib.error
import urllib.request

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

ONVIF_PATH = "/onvif/device_service"
DVRIP_SUBPATHS = ["/", "/RPC2", "/cgi-bin/interface"]  # some firmwares differ


def die(msg: str, code: int) -> "None":
    print(f"ERROR: {msg}")
    sys.exit(code)


class AuthError(Exception):
    pass


class RouteError(Exception):
    pass


class UnexpectedError(Exception):
    pass


class AmbiguousAuthError(Exception):
    """Login reply could be a rejection or just a terse session grant."""


# ── DVRIP framing ─────────────────────────────────────────────────────────────

def md5_upper(s: str) -> str:
    """MD5 hex digest, uppercase — the DVRIP password hash sent on the wire."""
    return hashlib.md5(s.encode("utf-8")).hexdigest().upper()


def dvr_login_body(user: str, password: str) -> dict:
    """DVRIP login frame (MsgID 766). Password is MD5-hex-uppercase, never plaintext."""
    return {"Version": "2.0", "SessionID": "0x0", "RequestType": 0,
            "Type": "OPMachine", "MsgID": 766,
            "Body": {"EncryptType": "MD5",
                     "PassWord": md5_upper(password),
                     "UserName": user}}


def dvr_logout_body() -> dict:
    """DVRIP logout frame (MsgID 767)."""
    return {"Type": "OPMachine", "MsgID": 767, "Body": {}}


def dvr_generic_body(msgid: int) -> dict:
    """A generic OPMachine query — used to probe for device info (best-effort)."""
    return {"Type": "OPMachine", "MsgID": msgid, "Body": {}}


def dvr_frame(payload: dict, session_id: "str | None" = None) -> bytes:
    """JSON-encode a DVRIP message, injecting the session id if known."""
    msg = dict(payload)
    if session_id:
        msg["SessionID"] = session_id
    return json.dumps(msg).encode("utf-8")


# ── TCP DVRIP framing (port 34567) ───────────────────────────────────────────
#
# Frame layout: 16-byte header | 4-byte little-endian payload length | JSON.
# The 16-byte header starts with the "HI" magic used by TVT's NetSurveillance
# protocol; the length field is the byte length of the JSON payload that follows.

DVRIP_TCP_HEADER = 16
DVRIP_TCP_LEN = 4
DVRIP_TCP_PREFIX = DVRIP_TCP_HEADER + DVRIP_TCP_LEN  # 20


def dvrip_tcp_frame(payload: bytes) -> bytes:
    """Wrap a JSON payload in a DVRIP TCP frame."""
    header = b"HI" + (b"\x00" * (DVRIP_TCP_HEADER - 2))
    return header + struct.pack("<I", len(payload)) + payload


def dvrip_tcp_decode(frame: bytes) -> "tuple[bytes, int]":
    """
    Unpack one DVRIP TCP frame.
    Returns (payload, consumed) — consumed is 20 + len(payload), so a buffer
    holding several concatenated frames can be split correctly.
    """
    if len(frame) < DVRIP_TCP_PREFIX:
        raise ValueError("frame too short for DVRIP prefix")
    header, length = frame[:DVRIP_TCP_HEADER], struct.unpack("<I", frame[
        DVRIP_TCP_HEADER:DVRIP_TCP_PREFIX])[0]
    if len(frame) < DVRIP_TCP_PREFIX + length:
        raise ValueError("frame truncated")
    return frame[DVRIP_TCP_PREFIX:DVRIP_TCP_PREFIX + length], DVRIP_TCP_PREFIX + length


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise RouteError("connection closed by camera mid-frame")
        buf.extend(chunk)
    return bytes(buf)


def _recv_tcp_frame(sock: socket.socket) -> bytes:
    prefix = _recv_exact(sock, DVRIP_TCP_PREFIX)
    length = struct.unpack("<I", prefix[DVRIP_TCP_HEADER:])[0]
    if length < 0 or length > 16 * 1024 * 1024:
        raise RouteError(f"implausible DVRIP frame length {length}")
    return _recv_exact(sock, length)


# ── Shared DVRIP helpers ──────────────────────────────────────────────────────

DEVICE_INFO_KEYS = ("serialnumber", "manufacturer", "model", "firmware",
                    "firmwareversion", "devicename", "hardware")


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


def _is_auth_failure(obj) -> bool:
    """Best-effort detection of a rejected login in a DVRIP reply."""
    if not isinstance(obj, dict):
        return False
    body = obj.get("Body") or {}
    if isinstance(body, dict):
        if str(body.get("Ret")).strip().lower() in ("false", "fail"):
            return True
        if str(body.get("Ret")).strip() == "0" and not _is_positive_login(obj):
            return True
        if body.get("Error") or body.get("Reason"):
            return True
    return False


def _is_positive_login(obj) -> bool:
    """True only when the reply carries a real session id."""
    if not isinstance(obj, dict):
        return False
    s = _session_from([obj])
    if not s:
        return False
    if str(s).strip().lower() in ("0x0", "0", "null", "none", ""):
        return False
    return True


def _http_post_json(url: str, frame: bytes, timeout: float,
                    session_id: "str | None" = None,
                    digest_auth: "str | None" = None) -> "tuple[bytes, dict | None]":
    headers = {"Content-Type": "application/json", "Connection": "keep-alive",
               "User-Agent": "tvt-camera-info/1.0"}
    if session_id:
        headers["SessionID"] = session_id
    if digest_auth:
        headers["Authorization"] = digest_auth
    req = urllib.request.Request(url, data=frame, method="POST", headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read(), resp.headers
    except urllib.error.HTTPError as e:
        if e.code in (401, 400, 403):
            raise AuthError(f"camera rejected the request (HTTP {e.code})") from None
        raise UnexpectedError(f"camera answered HTTP {e.code}") from None


def _digest_authorization(challenge: str, user: str, password: str,
                          method: str, uri: str) -> "str | None":
    """RFC 2617 Digest challenge → Authorization header (password never sent plaintext)."""
    parts = {}
    for m in re.finditer(r'(\w+)="([^"]*)"', challenge):
        parts[m.group(1)] = m.group(2)
    if "realm" not in parts or "nonce" not in parts:
        return None
    ha1 = md5_upper(f"{user}:{parts['realm']}:{password}")
    ha2 = md5_upper(f"{method}:{uri}")
    response = md5_upper(f"{ha1}:{parts['nonce']}:{ha2}")
    qop = parts.get("qop")
    if qop:
        nc = "00000001"
        cnonce = hashlib.md5(str(time_ns_placeholder()).encode()).hexdigest()[:8]
        response = md5_upper(f"{ha1}:{parts['nonce']}:{nc}:{cnonce}:{qop.split(',')[0]}:{ha2}")
    auth = (f'Digest username="{user}", realm="{parts["realm"]}", '
            f'nonce="{parts["nonce"]}", uri="{uri}", '
            f'response="{response}"')
    if qop:
        auth += f', qop={qop.split(",")[0]}, nc={nc}, cnonce="{cnonce}"'
    return auth


def time_ns_placeholder() -> int:
    import time
    try:
        return time.time_ns()
    except AttributeError:  # Python < 3.7
        return int(time.time() * 1e9)


# ── DVRIP over HTTP (port 80) ────────────────────────────────────────────────

def dvrip_http_query(ip: str, port: int, user: str, password: str,
                     timeout: float) -> dict:
    """
    Full DVRIP session over plain HTTP: login → device-info probe → logout.
    Raises AuthError / RouteError. Returns the device-info fields found.
    """
    last_route_err = None

    def attempt(path: str, digest: "str | None" = None) -> "dict | None":
        url = f"http://{ip}:{port}{path}"
        frame = dvr_frame(dvr_login_body(user, password))
        try:
            raw, headers = _http_post_json(url, frame, timeout,
                                           digest_auth=digest)
        except AuthError:
            raise
        except (socket.timeout, TimeoutError):
            raise RouteError("connection timed out") from None
        except (ConnectionError, OSError) as e:
            raise RouteError(f"could not connect ({e})") from None
        try:
            reply = json.loads(raw.decode("utf-8", errors="replace"))
        except ValueError:
            raise RouteError("camera answer was not valid DVRIP JSON") from None
        body = reply.get("Body") if isinstance(reply, dict) else None
        ret_code = body.get("Ret") if isinstance(body, dict) else None
        ret_norm = str(ret_code).strip().lower() if ret_code is not None else ""

        success_ret = (ret_code == 0 and ret_code is not False) \
            or ret_norm in ("true", "ok")
        if success_ret and _is_positive_login(reply):
            pass  # terse success: harmless Ret plus a real session id
        elif isinstance(ret_code, (int, float)) and not isinstance(ret_code, bool) \
                and ret_code != 0:
            raise AuthError("camera rejected the login (numeric Ret=%s)" % ret_code)
        elif _is_auth_failure(reply):
            raise AuthError("camera rejected the login (bad username/password)")
        else:
            raise AmbiguousAuthError(json.dumps(reply)[:200])
        session = headers.get("SessionID") or _session_from([reply]) or "0x0"
        info = extract_device_info(reply)

        # Device-info probe (best-effort — reply tooling varies by firmware)
        try:
            qframe = dvr_frame(dvr_generic_body(1470), session)
            raw2, _ = _http_post_json(url, qframe, timeout, session_id=session)
            info2 = extract_device_info(json.loads(raw2.decode("utf-8", errors="replace")))
            info.update(info2)
        except (AuthError, RouteError, UnexpectedError, ValueError, OSError):
            pass  # probe is best-effort; login reply fields already captured

        # Logout
        try:
            _http_post_json(url, dvr_frame(dvr_logout_body(), session), timeout,
                            session_id=session)
        except (AuthError, RouteError, UnexpectedError):
            pass
        return info

    # Plain JSON POST on each subpath; if a Digest challenge appears, retry
    # that path with proper Digest auth before moving on.
    for path in DVRIP_SUBPATHS:
        try:
            return attempt(path)
        except AuthError as e:
            if "401" not in str(e):
                raise
            # Digest challenge → try authenticated retry on the same path
            try:
                challenge = _probe_digest_challenge(ip, port, path, timeout)
                if challenge:
                    uri = path or "/"
                    auth = _digest_authorization(challenge, user, password, "POST", uri)
                    if auth:
                        return attempt(path, digest=auth)
            except (AuthError, RouteError, UnexpectedError):
                raise
            continue  # 401 without usable digest → try next subpath

    raise AuthError("authentication failed on all DVRIP HTTP paths")


def _probe_digest_challenge(ip: str, port: int, path: str, timeout: float) -> "str | None":
    """A GET to elicit the WWW-Authenticate header (cheap, no login attempt)."""
    url = f"http://{ip}:{port}{path}"
    req = urllib.request.Request(url, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout):
            return None
    except urllib.error.HTTPError as e:
        if e.code == 401:
            return e.headers.get("WWW-Authenticate")
        return None
    except (OSError, socket.timeout, TimeoutError):
        return None


# ── DVRIP over TCP (port 34567) ──────────────────────────────────────────────

def dvrip_tcp_query(ip: str, port: int, user: str, password: str,
                    timeout: float) -> dict:
    """Full DVRIP session over raw TCP: login → probe → logout. Returns info dict."""
    try:
        sock = socket.create_connection((ip, port), timeout=timeout)
    except OSError as e:
        raise RouteError(f"could not connect ({e})") from None

    def send(msg: dict, session: "str | None" = None):
        sock.sendall(dvrip_tcp_frame(dvr_frame(msg, session)))

    def recv_reply() -> dict:
        try:
            payload = _recv_tcp_frame(sock)
        except (socket.timeout, TimeoutError):
            raise RouteError("connection timed out waiting for reply") from None
        return json.loads(payload.decode("utf-8", errors="replace"))

    try:
        send(dvr_login_body(user, password))
        reply = recv_reply()
        body = reply.get("Body") if isinstance(reply, dict) else None
        ret_code = body.get("Ret") if isinstance(body, dict) else None
        ret_norm = str(ret_code).strip().lower() if ret_code is not None else ""

        success_ret = (ret_code == 0 and ret_code is not False) \
            or ret_norm in ("true", "ok")
        if success_ret and _is_positive_login(reply):
            pass
        elif isinstance(ret_code, (int, float)) and not isinstance(ret_code, bool) \
                and ret_code != 0:
            raise AuthError("camera rejected the login (bad username/password)")
        elif _is_auth_failure(reply):
            raise AuthError("camera rejected the login (bad username/password)")
        else:
            raise AmbiguousAuthError(json.dumps(reply)[:200])
        session = _session_from([reply]) or "0x0"
        info = extract_device_info(reply)

        try:
            send(dvr_generic_body(1470), session)
            info.update(extract_device_info(recv_reply()))
        except (AuthError, RouteError, ValueError):
            pass  # best-effort

        try:
            send(dvr_logout_body(), session)
            recv_reply()
        except (AuthError, RouteError, ValueError):
            pass
        return info
    finally:
        try:
            sock.close()
        except OSError:
            pass


# ── ONVIF SOAP (port 8899, last resort) ──────────────────────────────────────

def soap_request(url: str, user: str, password: str, body: str, timeout: float) -> str:
    """POST a raw SOAP envelope with WS-UsernameToken auth; return response text."""
    envelope = f"""<?xml version="1.0" encoding="UTF-8"?>
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
    req = urllib.request.Request(
        url, data=envelope.encode("utf-8"), method="POST",
        headers={"Content-Type": 'application/soap+xml; charset=utf-8; action="http://www.onvif.org/ver10/device/wsdl/GetDeviceInformation"',
                 "User-Agent": "tvt-camera-info/1.0"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        if e.code in (401, 400, 403):
            raise AuthError(f"camera rejected the request (HTTP {e.code})") from None
        raise UnexpectedError(f"camera answered HTTP {e.code}") from None
    except (socket.timeout, TimeoutError):
        raise RouteError("connection timed out") from None
    except (ConnectionError, OSError) as e:
        raise RouteError(f"could not connect ({e})") from None


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

PROTO_NAMES = {"http": "DVRIP over HTTP", "tcp": "DVRIP over TCP",
               "onvif": "ONVIF SOAP"}


def _run_proto(proto: str, ip: str, port: int, user: str, password: str,
               timeout: float) -> "tuple[dict | None, str, str, str]":
    """
    Attempt one protocol.
    Returns (info, mac, transport_label, ok) on success, or
    (None, err, label, kind) on failure, where kind ∈ {auth, route, error}.
    """
    label = PROTO_NAMES[proto]
    try:
        if proto == "http":
            info = dvrip_http_query(ip, port or DVRIP_HTTP_PORT, user, password, timeout)
        elif proto == "tcp":
            info = dvrip_tcp_query(ip, port or DVRIP_TCP_PORT, user, password, timeout)
        else:
            base = f"http://{ip}:{port or ONVIF_PORT}{ONVIF_PATH}"
            return onvif_get_device_information(base, user, password, timeout), \
                   onvif_get_network_interfaces(base, user, password, timeout), label, "ok"
        return info, None, label, "ok"
    except AuthError as e:
        return None, f"auth: {e}", label, "auth"
    except AmbiguousAuthError as e:
        return None, (f"auth-ambiguous: camera replied with a terse frame this tool "
                      f"can't classify — reply started with: {e}"), label, "auth"
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
                        "(defaults: http=80, tcp=34567, onvif=8899)")
    p.add_argument("--proto", default="auto", choices=["auto", "http", "tcp", "onvif"],
                   help="which protocol(s) to try: auto tries http → tcp → onvif "
                        "(default: auto)")
    p.add_argument("--timeout", type=float, default=TIMEOUT_DEFAULT,
                   help="network timeout in seconds (default: 8)")
    args = p.parse_args()

    order = ["http", "tcp", "onvif"] if args.proto == "auto" else [args.proto]
    failures: "list[str]" = []
    failure_kinds: "list[str]" = []

    print(f"Querying camera at {args.ip} — protocol(s): "
          f"{', '.join(PROTO_NAMES[o] for o in order)}\n")

    info = mac = label = None
    for proto in order:
        print(f"  trying {PROTO_NAMES[proto]}...", flush=True)
        info, mac, label, kind = _run_proto(proto, args.ip, args.port, args.user,
                                            args.password, args.timeout)
        if info:
            print(f"  ✓ {label} answered\n")
            break
        failures.append(f"{label}: {mac}")
        failure_kinds.append(kind)
        print(f"  ✗ {label} failed ({mac})\n")

    if not info:
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
                       "error": EXIT_UNEXPECTED}[failure_kinds[0]])
        sys.exit(EXIT_ALL_FAILED)

    # MAC: prefer ONVIF's GetNetworkInterfaces; otherwise the ARP table
    if not mac:
        mac = arp_lookup(args.ip)
        if mac:
            mac += "  (from this PC's ARP table)"

    print("=" * 60)
    print(" CAMERA INFORMATION")
    print("=" * 60)
    for key, val in info.items():
        print(f"  {key:<15}: {val}")
    print(f"  {'MAC address':<15}: {mac or 'not found'}")
    print("=" * 60)

    serial = next((v for k, v in info.items() if k.lower() == "serialnumber"), None)
    if not serial:
        print("\nNOTE: this camera did not report a serial number.")
        print("      Try its web UI (Settings → Version/Info) or the label on the unit.")
        sys.exit(EXIT_ALL_FAILED)

    sys.exit(EXIT_OK)


if __name__ == "__main__":
    main()