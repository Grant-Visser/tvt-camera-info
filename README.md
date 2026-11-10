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

1. **DVRIP over TCP (port 34567)** — the camera's native "NetSurveillance"
   (DVRIP/Sofia) protocol. The camera's model/serial/firmware/MAC are returned
   as JSON. This is what these devices actually speak.
2. **DVRIP over HTTP (port 80)** — the web service relaying the same JSON, for
   devices where the raw TCP service is firewalled.
3. **ONVIF (port 8899)** — the open camera standard. **Last resort only** —
   many of these cameras ship with ONVIF disabled.

The password is **never sent in plaintext**: it is sent as the protocol's
required "sofia hash" (an MD5-derived digest), and special characters are
safe — the hash step is exactly what the camera expects. Quote complex
passwords on the command line: `--password "YourPassword!"`

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

- **DVRIP TCP:** the NETsurveillance binary envelope on port 34567 —
  a 20-byte header (`0xFF` magic, session id, packet sequence, command id,
  payload length) + JSON + a `\x0a\x00` trailer. Login is **command 1000**
  with `LoginType: DVRIP-Web` and the password as a **sofia hash** in
  `PassWord` (MD5 digest bytes folded pairwise mod 62 into alphanumeric
  characters — the canonical vectors: empty password → `tlJwpbo6`,
  `admin` → `6QNMIQGe`). Device info comes from `Config-Get` (command 1042)
  for `SystemInfo` and `NetWork.NetCommon` (MAC address); logout is command
  1201. The session id returned by the camera is echoed in every following
  frame header. Return codes follow the Xiongmai table: `100` = OK,
  `106`/`203` = wrong username or password.
- **DVRIP HTTP:** the camera's web service (port 80) relays the same JSON —
  each POST carries one command's JSON body; the reply is the same JSON as
  over TCP. The tool retries the session with and without a `Command` header
  for firmwares that differ.
- **ONVIF:** raw SOAP (`GetDeviceInformation`, `GetNetworkInterfaces`) to
  `http://<ip>:8899/onvif/device_service` — no ONVIF library dependency.
- MAC address is cross-checked against the local ARP table when a protocol
  doesn't report one.
- Exit codes: `0` ok, `1` unreachable/timeout, `2` auth failed,
  `3` all protocols unavailable / no serial returned, `4` other.

### ⚠️ Tested against mock servers, NOT yet against a real camera

The DVRIP binary framing, command-1000 login with sofia-hash credentials,
config-get queries, logout, session handling and error paths are covered by
automated tests against local mock servers speaking the real frame format
(`test_tvt_camera_info.py` — 21 tests, verified end-to-end). The protocol
implementation follows the reference NETsurveillance client stacks
(OpenIPC/python-dvr and peers). The exact **device-info fields** a given
firmware returns can still vary between TVT firmware revisions — if a field
is missing from the output on a live camera, report the exact output and
firmware version when asking for support.