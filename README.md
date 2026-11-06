# TVT / Provision-ISR Camera Info Tool

A small helper that asks a **TVT** or **Provision-ISR** camera (or NVR) on your
network for its **serial number** and **MAC address**, and prints them in a
clear list.

- Works on **Windows** and **Linux** (and macOS)
- Needs only **Python 3** — no extra installs, no admin rights
- The serial number is **not visible in the camera's web UI**, which is why
  this tool exists — it asks the camera's ONVIF service (port 8899) directly
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

Other options:

```bash
--user admin            # username, only change if it isn't 'admin'
--port 8899             # ONVIF port, rarely needs changing
--timeout 8             # seconds to wait for the camera
```

### Example output

```
Querying camera at 192.168.1.64:8899 (ONVIF)...

============================================================
 CAMERA INFORMATION
============================================================
  Manufacturer   : TVT
  Model          : NV-4032RX
  SerialNumber   : 4C09B6PA8888123456
  Firmware       : V5.0.R12.12345678
  MAC address    : 8C:30:66:98:0C:06
============================================================
```

---

## 5. If something goes wrong

| Message | What it means | How to fix |
|---|---|---|
| `connection timed out` / `could not connect` | The PC couldn't reach the camera at that IP/port | Camera powered on? Your PC on the **same network** (same office/site, not on guest Wi-Fi)? IP correct? Try `ping <ip>` |
| `Authentication failed` | Wrong username or password | Out-of-the-box cameras often use `admin` with an **empty password** or `admin`. Check with whoever set it up |
| `NOTE: TVT's proprietary port 34567 IS open ... ONVIF may be disabled` | The camera is reachable but its ONVIF service is switched off | Log into the camera's web UI → Network / System settings → enable **ONVIF**; then re-run this tool |
| `did not report a serial number` | The camera answered but didn't give a serial | Check the sticker on the camera, or its web UI's Info/Version page |
| `python is not recognized` (Windows) | Python wasn't added to PATH | Re-run the Python installer and tick **"Add python.exe to PATH"** |

Anything else: note the exact error text and ask the person who sent you this
tool.

---

## 6. Security notes

- Runs entirely on your PC and the local network — nothing is uploaded anywhere
- Your camera password is only sent to the camera itself, and only typed on
  your own command line
- ONVIF queries here use plain HTTP on your LAN (that's how these cameras ship)

---

## For the technical reader

- Speaks raw ONVIF SOAP (`GetDeviceInformation`, `GetNetworkInterfaces`) to
  `http://<ip>:8899/onvif/device_service` — no ONVIF library dependency
- If ONVIF doesn't report the MAC, the tool cross-checks your PC's local ARP
  table (the camera must have answered at least one packet for this to work)
- Detects TVT's proprietary port 34567 to hint when ONVIF is disabled
- Exit codes: `0` ok, `1` unreachable/timeout, `2` auth failed,
  `3` ONVIF unavailable, `4` other
