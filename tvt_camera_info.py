#!/usr/bin/env python3
"""
tvt-camera-info.py — look up a TVT / Provision-ISR camera's serial number and
MAC address over the LAN.

Talks to the camera's ONVIF service (default port 8899) with raw SOAP:
  - GetDeviceInformation  -> SerialNumber, Model, Firmware, etc.
  - GetNetworkInterfaces  -> MAC (hardware) address
Falls back to the local ARP table for the MAC if ONVIF doesn't report one,
and optionally to TVT's proprietary port 34567 if ONVIF is switched off.

Works on Windows, Linux and macOS. Python 3.8+, standard library only.
"""

import argparse
import re
import socket
import subprocess
import sys
import urllib.error
import urllib.request

# ── Exit codes ────────────────────────────────────────────────────────────────
EXIT_OK = 0
EXIT_NO_ROUTE = 1        # host unreachable / timed out / wrong network
EXIT_AUTH = 2            # wrong username or password
EXIT_ONVIF_DISABLED = 3  # nothing answered on the ONVIF port / not ONVIF
EXIT_UNEXPECTED = 4      # anything else

TIMEOUT_DEFAULT = 8.0


def die(msg: str, code: int) -> "None":
    print(f"ERROR: {msg}")
    sys.exit(code)


# ── SOAP helpers ──────────────────────────────────────────────────────────────

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
            # Some cameras return 400/403 instead of 401 on bad credentials.
            raise AuthError(f"camera rejected the request (HTTP {e.code})") from None
        raise UnexpectedError(f"camera answered HTTP {e.code}") from None
    except (socket.timeout, TimeoutError):
        raise RouteError("connection timed out") from None
    except (ConnectionError, OSError) as e:
        raise RouteError(f"could not connect ({e})") from None


class AuthError(Exception): pass
class RouteError(Exception): pass
class UnexpectedError(Exception): pass


def xml_text(xml: str, tag: str) -> "str | None":
    """Text of the first <tag>...</tag> occurrence (namespace-tolerant)."""
    m = re.search(rf"<(?:[\w.-]+:)?{tag}(?:\s[^>]*)?>(.*?)</(?:[\w.-]+:)?{tag}>",
                  xml, re.DOTALL | re.IGNORECASE)
    if not m:
        return None
    import html
    return html.unescape(m.group(1)).strip() or None


# ── ONVIF queries ─────────────────────────────────────────────────────────────

def onvif_get_device_information(base_url: str, user: str, password: str,
                                 timeout: float) -> dict:
    body = ('<GetDeviceInformation xmlns="http://www.onvif.org/ver10/device/wsdl"/>')
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
    body = ('<GetNetworkInterfaces xmlns="http://www.onvif.org/ver10/device/wsdl"/>')
    xml = soap_request(base_url, user, password, body, timeout)
    # HwAddress appears under tt:NetworkInterface/tt:Info/tt:HwAddress
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


def probe_tvt_port(ip: str, port: int, timeout: float) -> bool:
    """True if something is listening on TVT's proprietary port 34567."""
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    p = argparse.ArgumentParser(
        description="Look up a TVT / Provision-ISR camera's serial number and "
                    "MAC address via ONVIF (LAN tool).")
    p.add_argument("--ip", required=True, help="camera IP address, e.g. 192.168.1.64")
    p.add_argument("--user", default="admin", help="camera username (default: admin)")
    p.add_argument("--password", default="", help="camera password")
    p.add_argument("--port", type=int, default=8899,
                   help="ONVIF port (default: 8899)")
    p.add_argument("--timeout", type=float, default=TIMEOUT_DEFAULT,
                   help="network timeout in seconds (default: 8)")
    args = p.parse_args()

    base_url = f"http://{args.ip}:{args.port}/onvif/device_service"

    print(f"Querying camera at {args.ip}:{args.port} (ONVIF)...\n")

    # ── Step 1: ONVIF device info ────────────────────────────────────────────
    try:
        info = onvif_get_device_information(base_url, args.user, args.password,
                                            args.timeout)
    except AuthError:
        die(f"Authentication failed — the camera rejected the username/password.\n"
            f"       Check the password (often blank or 'admin' out of the box), "
            f"then retry:\n"
            f"       python tvt_camera_info.py --ip {args.ip} --user {args.user} "
            f"--password <password>", EXIT_AUTH)
    except RouteError as e:
        hint = ""
        if probe_tvt_port(args.ip, 34567, args.timeout):
            hint = (f"\n       NOTE: TVT's proprietary port 34567 IS open on this camera — "
                    f"ONVIF may be disabled in its web UI. Enable ONVIF there, or query "
                    f"port 34567 with a TVT-SDK tool.")
        die(f"{e} — is the camera reachable at {args.ip}:{args.port}?\n"
            f"       Check: camera powered on, PC on the same network/VLAN, "
            f"correct IP.\n{hint}", EXIT_NO_ROUTE)
    except UnexpectedError as e:
        die(str(e), EXIT_UNEXPECTED)

    if not info:
        die("The camera answered, but returned no device information.",
            EXIT_ONVIF_DISABLED)

    # ── Step 2: ONVIF network interfaces (MAC) ───────────────────────────────
    mac = None
    try:
        mac = onvif_get_network_interfaces(base_url, args.user, args.password,
                                           args.timeout)
    except (AuthError, RouteError, UnexpectedError):
        pass  # fall through to ARP

    if not mac:
        mac = arp_lookup(args.ip)
        if mac:
            mac += "  (from this PC's ARP table)"

    # ── Report ───────────────────────────────────────────────────────────────
    print("=" * 60)
    print(" CAMERA INFORMATION")
    print("=" * 60)
    for key, val in info.items():
        print(f"  {key:<15}: {val}")
    print(f"  {'MAC address':<15}: {mac or 'not found'}")
    print("=" * 60)

    if "SerialNumber" not in info:
        print("\nNOTE: this camera did not report a serial number over ONVIF.")
        print("      Try its web UI (Settings → Version/Info) or the label on the unit.")
        sys.exit(EXIT_UNEXPECTED)

    sys.exit(EXIT_OK)


if __name__ == "__main__":
    main()
