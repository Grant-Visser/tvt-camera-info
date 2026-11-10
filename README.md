# TVT / Provision-ISR Camera Info Tool

A small helper that asks a **TVT** or **Provision-ISR** camera (or NVR) on your
network for its **serial number** and **MAC address**, and prints them in a
clear list.

- Works on **Windows** and **Linux** (and macOS)
- Needs only **Python 3** — no extra installs, no admin rights
- The serial number is **not visible in the camera's web UI**, which is why
  this tool exists — it talks to the camera's own protocol
- Read-only: it only *asks* the camera for information, never changes anything

---

## 1. Install Python (once)

### Windows

1. Go to <https://www.python.org/downloads/> and click **Download Python 3.x**
2. Run the downloaded file.
   - **Important:** tick the box **"Add python.exe to PATH"** on the first
     screen, then click *Install Now*
3. Open **Command Prompt** (press Start, type `cmd`, Enter) and type:
   ```
   python --version
   ```
   You should see something like `Python 3.12.4`. If it says `'python' is not
   recognized`, re-run the installer and tick the PATH box.

### Linux (Ubuntu / Debian)

```bash
sudo apt update && sudo apt install -y python3
```

Most Linux desktops already have Python 3 — check with `python3 --version`.

---

## 2. Get the tool

Download **`tvt_camera_info.py`** from this page
(click it, then **Raw**, then save the file — or use Code → Download ZIP and
extract it). Put it somewhere easy, like your Desktop or `C:\Users\you\Downloads`.

---

## 3. Find the camera's IP address

You need to know the camera's IP (e.g. `192.168.1.64`). Ways to find it:

- Your router's admin page (list of connected devices)
- The TVT/Provision-ISR **SADP / device-search tool** from the vendor
- If you know the recorder's IP, cameras are often numbered nearby
  (e.g. recorder `192.168.1.20`, cameras `.21`–`.28`)

---

## 4. Run it

Open a terminal **in the folder where you saved the file**:

- **Windows:** open the folder in File Explorer, click the address bar, type
  `cmd` and press Enter
- **Linux:** open a terminal and `cd` to the folder

Then run (replace the IP with your camera's):

```bash
python tvt_camera_info.py --ip 192.168.1.64
```

> Linux users: use `python3` instead of `python`.

If the camera has a password, add it:

```bash
python tvt_camera_info.py --ip 192.168.1.64 --password YourCameraPassword
```

### How it talks to the camera (attempt order)

By default the tool tries three protocols, in this order, and prints the
result of the first one that works:

1. **DVRIP over HTTP (port 80)** — the TVT/Provision-ISR native "NetSurveillance"
   protocol. The camera's model/serial/firmware are returned as JSON. This is
   the protocol these cameras use by default.
2. **DVRIP over TCP (port 34567)** — the same protocol over a raw socket with
   length-prefixed frames, for cameras where the HTTP service is off.
3. **ONVIF (port 8899)** — the open camera standard. **Last resort only** —
   many of these cameras ship with ONVIF disabled.

The password is **never sent in plaintext**: it is hashed with MD5 first
(that's what the camera protocol requires).

Optional flags:

```bash
--proto http       # force one protocol only: http | tcp | onvif | auto
--port 80          # override the port for the active transport
                   # (defaults: HTTP=80, TCP=34567, ONVIF=8899)
--user admin       # username, only change if it isn't 'admin'
--timeout 8        # seconds to wait for the camera
```

For example, to try only the native protocol over HTTP:

```bash
python tvt_camera_info.py --ip 192.168.1.64 --proto http --password secret
```

### Example output (DVRIP)

```
Querying camera at 192.168.1.64 — protocol(s): DVRIP over HTTP, DVRIP over TCP, ONVIF SOAP

  trying DVRIP over HTTP...
  ✓ DVRIP over HTTP answered

============================================================
 CAMERA INFORMATION
============================================================
  SerialNumber    : 4C09B6PA8888123456
  Manufacturer    : TVT
  Model           : NV-4032RX
  Firmware        : V5.0.R12.12345678
  MAC address     : 8C:30:66:98:0C:06
============================================================
```

---

## 5. If something goes wrong

| Message | What it means | How to fix |
|---|---|---|
| `connection timed out` / `could not connect` (all three protocols) | The PC couldn't reach the camera at that IP | Camera powered on? Your PC on the **same network** (same office/site, not on guest Wi-Fi)? IP correct? Try `ping <ip>` |
| `camera rejected the login` / `authentication failed` | Wrong username or password | Out-of-the-box cameras often use `admin` with an **empty password** or `admin`. Check with whoever set it up. Special characters (`#`, `@`, spaces…) are safe — the password is hashed before it's sent; quote it on the command line: `--password "YourPassword!"` |
| `auth-ambiguous: … reply started with: {json}` | The camera answered with a terse frame this tool can't classify (often a nonstandard firmware) | Copy the shown JSON and send it to the tool maintainer — it says exactly what the camera replied |
| `camera answer was not valid DVRIP JSON` | Something else answered on that port (not a TVT camera, or a protocol mismatch) | Double-check the IP is the camera's; try `--proto onvif` or a different port |
| All three protocols fail but the camera is definitely reachable | DVRIP **and** ONVIF are both switched off | Log into the camera's web UI → Network / System settings → enable **DVRIP** and/or **ONVIF**; then re-run |
| `did not report a serial number` | The camera answered but didn't give a serial | Check the sticker on the camera, or its web UI's Info/Version page |
| `python is not recognized` (Windows) | Python wasn't added to PATH | Re-run the Python installer and tick **"Add python.exe to PATH"** |

Anything else: note the exact error text and ask the person who sent you this
tool.

---

## 6. Security notes

- Runs entirely on your PC and the local network — nothing is uploaded anywhere
- Your password is **hashed (MD5)** before it is sent to the camera, never typed
  or sent in plaintext
- The camera password exists only on your own command line

---

## For the technical reader

- **DVRIP HTTP:** raw JSON POSTs (`Content-Type: application/json`) to
  `http://<ip>/` (with `/RPC2` and `/cgi-bin/interface` fallbacks). Login =
  `MsgID 766` (`OPMachine`), logout = `MsgID 767`. Password is MD5-hex-uppercase
  in `Body.PassWord`. The `SessionID` from the reply (header and/or body) is
  echoed back on every subsequent request. If a digest challenge appears, the
  tool retries with RFC 2617 Digest auth (password still never sent plaintext).
- **DVRIP TCP:** same JSON envelope over port 34567, framed as a 16-byte header
  (`HI` magic) + 4-byte little-endian payload length + JSON.
- **ONVIF:** raw SOAP (`GetDeviceInformation`, `GetNetworkInterfaces`) to
  `http://<ip>:8899/onvif/device_service` — no ONVIF library dependency.
- MAC address is cross-checked against the local ARP table when a protocol
  doesn't report one.
- Exit codes: `0` ok, `1` unreachable/timeout, `2` auth failed,
  `3` all protocols unavailable / no serial returned, `4` other.

### ⚠️ Tested against mock servers, NOT yet against a real camera

The DVRIP framing, login/logout flow, session handling and error paths are
covered by automated tests against local mock HTTP/TCP servers
(`test_tvt_camera_info.py` — 14 tests). The exact **device-info request** a
given firmware family answers with (and the exact field names it returns) can
vary between TVT firmware revisions, so this build was **not validated against
real hardware** — if a field is missing from the output on a live camera, the
information is still usually present in the login reply; report the exact
output and firmware version when asking for support.