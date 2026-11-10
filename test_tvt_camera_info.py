#!/usr/bin/env python3
"""
Unit + mock-server tests for tvt_camera_info.py.

Run:  python3 test_tvt_camera_info.py
No network beyond loopback; no real camera required.
"""

import json
import socket
import struct
import threading
import unittest
import unittest.mock
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import tvt_camera_info as T


# ── Pure logic tests ──────────────────────────────────────────────────────────

class LogicTests(unittest.TestCase):

    def test_sofia_hash_known_vectors(self):
        # Canonical Xiongmai DVRIP vectors
        self.assertEqual(T.sofia_hash(""), "tlJwpbo6")
        self.assertEqual(T.sofia_hash("admin"), "6QNMIQGe")

    def test_login_frame_never_contains_plaintext(self):
        body = T.dvr_login_body("admin", "s3cret")
        self.assertEqual(body["PassWord"], T.sofia_hash("s3cret"))
        self.assertEqual(body["EncryptType"], "MD5")
        self.assertEqual(body["LoginType"], "DVRIP-Web")
        self.assertNotIn("s3cret", json.dumps(body))

    def test_login_body_is_command_1000_shape(self):
        # Login body has no MsgID inside the JSON — it rides in the header
        body = T.dvr_login_body("admin", "x")
        self.assertNotIn("MsgID", body)
        self.assertNotIn("Body", body)

    def test_logout_body(self):
        body = T.dvr_logout_body()
        self.assertIn("SessionID", body)

    def test_frame_roundtrip_header(self):
        payload = {"EncryptType": "MD5", "LoginType": "DVRIP-Web",
                   "PassWord": "tlJwpbo6", "UserName": "admin"}
        frame = T.dvr_frame(payload, 1000, session_id=0, seq=0)
        self.assertEqual(len(frame), 20 + len(json.dumps(payload).encode()) + 2)
        self.assertEqual(frame[0], 0xFF)
        self.assertEqual(frame[1], 0)
        sid, seq, msg_id, length = T.dvr_unpack_header(frame)
        self.assertEqual((sid, seq, msg_id), (0, 0, 1000))
        self.assertEqual(length, len(json.dumps(payload).encode()) + 2)
        # trailer
        self.assertEqual(frame[-2:], b"\x0a\x00")

    def test_frame_session_and_seq(self):
        frame = T.dvr_frame({"Name": "SystemInfo"}, 1042, session_id=0x5F2A1, seq=7)
        sid, seq, msg_id, _ = T.dvr_unpack_header(frame)
        self.assertEqual(sid, 0x5F2A1)
        self.assertEqual(seq, 7)
        self.assertEqual(msg_id, 1042)

    def test_is_dvrip_header(self):
        good = T.dvr_frame({"a": 1}, 1000)
        self.assertTrue(T.is_dvrip_header(good))
        self.assertFalse(T.is_dvrip_header(b"GET / HTTP/1.1\r\n\r\n"))
        self.assertFalse(T.is_dvrip_header(b"\x00" * 20))
        self.assertFalse(T.is_dvrip_header(b"\xff"))

    def test_extract_device_info_recursive(self):
        reply = {"Version": "2.0", "SessionID": "0x5f2a1", "Ret": 100,
                 "SystemInfo": {"SerialNumber": "4C09B6PA8888123456",
                                "DeviceType": "NVR",
                                "SoftWareVersion": "V5.0.R12.1"}}
        info = T.extract_device_info(reply)
        self.assertEqual(info["SerialNumber"], "4C09B6PA8888123456")
        self.assertEqual(info["DeviceType"], "NVR")

    def test_session_from_body(self):
        reply = {"Version": "2.0", "SessionID": "0x5f2a1", "Body": {}}
        self.assertEqual(T._session_from([reply]), "0x5f2a1")
        self.assertIsNone(T._session_from([{"Body": {}}]))

    def test_classify_login_reply(self):
        ok = {"Ret": 100, "SessionID": "0x5f2a1"}
        self.assertEqual(T.classify_login_reply(ok), "ok")
        badpw = {"Ret": 106, "SessionID": "0x0"}
        self.assertEqual(T.classify_login_reply(badpw), "auth")
        lock = {"Ret": 203}
        self.assertEqual(T.classify_login_reply(lock), "auth")
        err = {"Ret": 117}
        self.assertEqual(T.classify_login_reply(err), "error")
        terse = {"SessionID": "0x9"}
        self.assertEqual(T.classify_login_reply(terse), "terse")
        none = {"Ret": "true"}
        self.assertEqual(T.classify_login_reply(none), "auth")

    def test_is_valid_ipv4(self):
        self.assertTrue(T.is_valid_ipv4("192.168.1.64"))
        self.assertFalse(T.is_valid_ipv4("999.1.1.1"))
        self.assertFalse(T.is_valid_ipv4("banana"))

    def test_mac_from_netcommon(self):
        self.assertEqual(
            T._mac_from_netcommon({"NetWork": {"NetCommon": {"MACAddress": "8c-30-66-98-0c-06"}}}),
            "8C:30:66:98:0C:06")
        self.assertIsNone(T._mac_from_netcommon({"NetWork": {}}))


# ── Ping preflight tests ──────────────────────────────────────────────────

class PingPreflightTests(unittest.TestCase):

    def test_ping_loopback_alive(self):
        alive, detail = T.ping_host("127.0.0.1", 2.0)
        self.assertTrue(alive)
        self.assertIn("ICMP", detail)

    def test_ping_dead_ip(self):
        # TEST-NET-1 never answers; subprocess still runs.
        alive, detail = T.ping_host("192.0.2.123", 1.0)
        self.assertFalse(alive)
        self.assertTrue(detail)

    def test_tcp_fallback_when_icmp_unavailable(self):
        # ICMP "blocked" (ping binary unusable) but a DVRIP port is open → alive
        srv = socket.socket()
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        port = srv.getsockname()[1]
        try:
            with unittest.mock.patch.object(T.subprocess, "run",
                                            side_effect=OSError("blocked")), \
                 unittest.mock.patch.object(T, "DVRIP_TCP_PORT", port):
                alive, detail = T.ping_host("127.0.0.1", 2.0)
            self.assertTrue(alive)
            self.assertIn("ICMP blocked", detail)
            self.assertIn(str(port), detail)
        finally:
            srv.close()


# ── Mock TCP server (DVRIP over 34567) ────────────────────────────────────────

class MockDvripTCP:
    """
    Speaks the real DVRIP TCP envelope: 20-byte binary header
    (0xFF | ver | 2 pad | session u32 | seq u32 | msgid u16 | 2 pad | len u32)
    + JSON payload + b"\x0a\x00" trailer.
    """

    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(1)
        self.log = []
        self.bad_password_hashes = set()
        threading.Thread(target=self._serve, daemon=True).start()

    @property
    def port(self):
        return self.sock.getsockname()[1]

    def _recv_exact(self, conn, n):
        buf = bytearray()
        while len(buf) < n:
            c = conn.recv(n - len(buf))
            if not c:
                raise ConnectionError
            buf.extend(c)
        return bytes(buf)

    def _serve(self):
        conn, _ = self.sock.accept()
        with conn:
            while True:
                try:
                    prefix = self._recv_exact(conn, 20)
                except Exception:
                    return
                if not T.is_dvrip_header(prefix):
                    return
                sid, seq, mid, length = T.dvr_unpack_header(prefix)
                payload = self._recv_exact(conn, length)
                if payload.endswith(b"\x0a\x00"):
                    payload = payload[:-2]
                msg = json.loads(payload)
                self.log.append(msg)
                if mid == T.CMD_LOGIN:
                    pw_hash = msg.get("PassWord", "")
                    if msg.get("UserName") == "admin" and \
                            pw_hash not in self.bad_password_hashes:
                        reply = {"Ret": 100, "SessionID": "0xb0b",
                                 "AliveInterval": 20,
                                 "DeviceType": "NVR",
                                 "SystemInfo": {
                                     "SerialNumber": "SN-TCP-0001",
                                     "DeviceType": "NVR",
                                     "HardWare": "IPC-2345"}}
                    else:
                        reply = {"Ret": 106, "SessionID": "0x0"}
                elif mid == T.CMD_CONFIG_GET:
                    name = msg.get("Name", "")
                    if name == "SystemInfo":
                        reply = {"Name": name, "Ret": 100,
                                 "SystemInfo": {"SerialNumber": "SN-TCP-0001",
                                                "SoftWareVersion": "V5.0.R12"}}
                    elif name == "NetWork.NetCommon":
                        reply = {"Name": name, "Ret": 100,
                                 "NetWork": {"NetCommon": {
                                     "MACAddress": "8C:30:66:98:0C:06"}}}
                    else:
                        reply = {"Name": name, "Ret": 100}
                elif mid == T.CMD_LOGOUT:
                    reply = {"Ret": 100}
                else:
                    reply = {"Ret": 103}
                self._send(conn, reply, sid or 0xB0B, seq)

    def _send(self, conn, reply, sid, seq):
        frame = T.dvr_frame(reply, 1000, sid, seq)
        conn.sendall(frame)


class TcpTransportTests(unittest.TestCase):

    def setUp(self):
        self.mock = MockDvripTCP()

    def test_full_session_over_real_framing(self):
        info = T.dvrip_tcp_query("127.0.0.1", self.mock.port, "admin", "pw123", 5)
        self.assertEqual(info["SerialNumber"], "SN-TCP-0001")
        self.assertEqual(info["MACAddress"], "8C:30:66:98:0C:06")
        self.assertEqual(info["SoftWareVersion"], "V5.0.R12")

    def test_password_on_wire_is_sofia_hash(self):
        T.dvrip_tcp_query("127.0.0.1", self.mock.port, "admin", "pw123", 5)
        login = self.mock.log[0]
        self.assertEqual(login["PassWord"], T.sofia_hash("pw123"))
        self.assertNotIn("pw123", json.dumps(self.mock.log))
        self.assertEqual(login["LoginType"], "DVRIP-Web")

    def test_auth_failure_raises_auth_error(self):
        self.mock.bad_password_hashes = {T.sofia_hash("wrongpw")}
        with self.assertRaises(T.AuthError):
            T.dvrip_tcp_query("127.0.0.1", self.mock.port, "admin", "wrongpw", 5)

    def test_tcp_unreachable_raises_route_error(self):
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        with self.assertRaises(T.RouteError):
            T.dvrip_tcp_query("127.0.0.1", port, "admin", "x", 2)


# ── Mock HTTP server (DVRIP JSON relay on port 80) ────────────────────────────

class MockDvripHTTP(BaseHTTPRequestHandler):
    seen = {"posts": []}
    reject = False

    def log_message(self, *a):
        pass

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length)
        self.seen["posts"].append((self.path, raw, self.headers.get("Content-Type", "")))
        msg = json.loads(raw)

        if self.reject:
            self.send_response(401)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return

        if msg.get("UserName") == "admin" and \
                msg.get("PassWord") == T.sofia_hash("pw123"):
            body = {"Ret": 100, "SessionID": "0xdeadbeef",
                    "SystemInfo": {"SerialNumber": "SN-HTTP-0001",
                                   "Manufacturer": "TVT"}}
        else:
            body = {"Ret": 106, "SessionID": "0x0"}

        data = json.dumps(body).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


class HttpTransportTests(unittest.TestCase):

    def test_http_json_relay_session(self):
        srv = ThreadingHTTPServer(("127.0.0.1", 0), MockDvripHTTP)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            info = T.dvrip_http_query("127.0.0.1", srv.server_address[1],
                                      "admin", "pw123", 5)
            self.assertEqual(info["SerialNumber"], "SN-HTTP-0001")
            self.assertEqual(info["Manufacturer"], "TVT")
        finally:
            srv.shutdown()

    def test_http_auth_failure_raises(self):
        MockDvripHTTP.reject = True
        srv = ThreadingHTTPServer(("127.0.0.1", 0), MockDvripHTTP)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            with self.assertRaises(T.AuthError):
                T.dvrip_http_query("127.0.0.1", srv.server_address[1],
                                   "admin", "x", 5)
        finally:
            srv.shutdown()
            MockDvripHTTP.reject = False


if __name__ == "__main__":
    unittest.main(verbosity=2)
