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
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import tvt_camera_info as T


# ── Pure logic tests ──────────────────────────────────────────────────────────

class LogicTests(unittest.TestCase):

    def test_md5_password_hash(self):
        # MD5("admin") uppercase hex — known vector
        self.assertEqual(T.md5_upper("admin"), "21232F297A57A5A743894A0E4A801FC3")
        self.assertEqual(T.md5_upper(""), "D41D8CD98F00B204E9800998ECF8427E")
        self.assertTrue(T.md5_upper("secret").isupper())

    def test_login_frame_never_contains_plaintext(self):
        body = T.dvr_login_body("admin", "s3cret")
        self.assertEqual(body["Body"]["PassWord"], T.md5_upper("s3cret"))
        self.assertNotIn("s3cret", json.dumps(body))
        self.assertEqual(body["MsgID"], 766)
        self.assertEqual(json.dumps(body).find("s3cret"), -1)

    def test_logout_frame(self):
        self.assertEqual(T.dvr_logout_body()["MsgID"], 767)

    def test_tcp_frame_roundtrip(self):
        payload = json.dumps({"Type": "OPMachine", "MsgID": 766,
                              "Body": {"UserName": "admin"}}).encode()
        frame = T.dvrip_tcp_frame(payload)
        # 16-byte header + 4-byte LE length + payload
        self.assertEqual(len(frame), 20 + len(payload))
        self.assertEqual(frame[:2], b"HI")
        (n,) = struct.unpack("<I", frame[16:20])
        self.assertEqual(n, len(payload))
        out, consumed = T.dvrip_tcp_decode(frame)
        self.assertEqual(out, payload)
        self.assertEqual(consumed, len(frame))

    def test_tcp_frame_roundtrip_unicode(self):
        payload = '{"Body":{"Model":"NVR-код"}}'.encode("utf-8")
        frame = T.dvrip_tcp_frame(payload)
        out, consumed = T.dvrip_tcp_decode(frame)
        self.assertEqual(out, payload)
        self.assertEqual(consumed, len(frame))

    def test_tcp_frame_concatenated_buffer(self):
        p1 = b'{"a":1}'
        p2 = b'{"b":"two"}'
        buf = T.dvrip_tcp_frame(p1) + T.dvrip_tcp_frame(p2)
        out1, c1 = T.dvrip_tcp_decode(buf)
        out2, c2 = T.dvrip_tcp_decode(buf[c1:])
        self.assertEqual(out1, p1)
        self.assertEqual(out2, p2)

    def test_tcp_decode_truncated(self):
        frame = T.dvrip_tcp_frame(b'{"x":1}')
        with self.assertRaises(ValueError):
            T.dvrip_tcp_decode(frame[:10])
        with self.assertRaises(ValueError):
            T.dvrip_tcp_decode(frame[:-2])

    def test_extract_device_info_recursive(self):
        reply = {"Version": "2.0", "Body": {
            "Info": {"SerialNumber": "4C09B6PA8888123456",
                     "Manufacturer": "TVT",
                     "Detail": {"Model": "NV-4032RX",
                                "FirmwareVersion": "V5.0.R12.1"}}}}
        info = T.extract_device_info(reply)
        self.assertEqual(info["SerialNumber"], "4C09B6PA8888123456")
        self.assertEqual(info["Manufacturer"], "TVT")
        self.assertEqual(info["Model"], "NV-4032RX")
        self.assertEqual(info["FirmwareVersion"], "V5.0.R12.1")

    def test_session_from_body(self):
        reply = {"Version": "2.0", "SessionID": "0x5f2a1", "Body": {}}
        self.assertEqual(T._session_from([reply]), "0x5f2a1")
        self.assertIsNone(T._session_from([{"Body": {}}]))

    def test_auth_failure_detection(self):
        self.assertTrue(T._is_auth_failure({"Body": {"Ret": "false"}}))
        self.assertTrue(T._is_auth_failure({"Body": {"Error": "bad login"}}))
        self.assertFalse(T._is_auth_failure({"Body": {"Ret": "true"}}))


# ── Mock HTTP server (DVRIP over port 80) ─────────────────────────────────────

class MockDvripHTTP(BaseHTTPRequestHandler):
    seen = {"posts": [], "session_header_on_probe": None}

    def log_message(self, *a):
        pass

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length)
        ct = self.headers.get("Content-Type", "")
        self.seen["posts"].append((self.path, raw, ct, self.headers.get("SessionID")))
        msg = json.loads(raw)
        mid = msg.get("MsgID")

        if mid == 766:  # login
            body = {"Version": "2.0", "Status": "Init", "SessionID": "0xdeadbeef",
                    "Body": {"EncryptType": "MD5", "LoginType": 1,
                             "UserName": msg["Body"]["UserName"],
                             "Ret": "true",
                             "SerialNumber": "4C09B6PA8888123456",
                             "Manufacturer": "TVT",
                             "Model": "NV-4032RX",
                             "FirmwareVersion": "V5.0.R12.1"}}
            self.send_response(200)
            self.send_header("SessionID", "0xdeadbeef")
        elif mid == 1470:  # device-info probe
            sid = self.headers.get("SessionID")
            self.seen["session_header_on_probe"] = sid
            body = {"SessionID": sid, "Body": {"Ret": "true",
                                               "SerialNumber": "4C09B6PA8888123456"}}
            self.send_response(200)
        elif mid == 767:  # logout
            self.seen["logout_session"] = self.headers.get("SessionID")
            body = {"SessionID": self.headers.get("SessionID"), "Body": {"Ret": "true"}}
            self.send_response(200)
        else:
            body = {"Body": {"Ret": "false"}}
            self.send_response(400)

        data = json.dumps(body).encode()
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def _start_http_server():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), MockDvripHTTP)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv


class HttpTransportTests(unittest.TestCase):

    def test_full_session_and_sessionid_header_reuse(self):
        srv = _start_http_server()
        try:
            port = srv.server_address[1]
            info = T.dvrip_http_query("127.0.0.1", port, "admin", "admin", 5)
            self.assertEqual(info["SerialNumber"], "4C09B6PA8888123456")
            self.assertEqual(info["Manufacturer"], "TVT")
            # login POST had no session header yet; probe + logout carried it
            posts = MockDvripHTTP.seen["posts"]
            mids = [json.loads(p[1])["MsgID"] for p in posts]
            self.assertEqual(mids, [766, 1470, 767])
            self.assertEqual(MockDvripHTTP.seen["session_header_on_probe"], "0xdeadbeef")
            self.assertEqual(MockDvripHTTP.seen["logout_session"], "0xdeadbeef")
            # content type was JSON on every request
            for _path, _raw, ct, _sid in posts:
                self.assertEqual(ct, "application/json")
        finally:
            srv.shutdown()

    def test_auth_failure_raises(self):
        from http.server import BaseHTTPRequestHandler as B, ThreadingHTTPServer as S
        class Reject(B):
            def log_message(self, *a):
                pass

            def do_POST(self):
                self.send_response(401)
                self.send_header("Content-Length", "0")
                self.end_headers()
        srv = S(("127.0.0.1", 0), Reject)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            with self.assertRaises(T.AuthError):
                T.dvrip_http_query("127.0.0.1", srv.server_address[1], "admin", "x", 5)
        finally:
            srv.shutdown()


# ── Mock TCP server (DVRIP over 34567) ────────────────────────────────────────

class MockDvripTCP:
    """Speaks the DVRIP TCP envelope: 16B header + 4B LE len + JSON."""

    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(1)
        self.log = []
        threading.Thread(target=self._serve, daemon=True).start()

    @property
    def port(self):
        return self.sock.getsockname()[1]

    def _serve(self):
        conn, _ = self.sock.accept()
        with conn:
            while True:
                try:
                    prefix = self._recv_exact(conn, 20)
                except Exception:
                    return
                (n,) = struct.unpack("<I", prefix[16:20])
                payload = self._recv_exact(conn, n)
                msg = json.loads(payload)
                self.log.append(msg)
                mid = msg.get("MsgID")
                sid = msg.get("SessionID")
                if mid == 766:
                    reply = {"Version": "2.0", "SessionID": "0xb0b",
                             "Body": {"Ret": "true", "UserName": msg["Body"]["UserName"],
                                      "SerialNumber": "SN-TCP-0001",
                                      "Manufacturer": "Provision-ISR",
                                      "Model": "IPC-2345"}}
                elif mid == 1470:
                    reply = {"SessionID": sid, "Body": {"Ret": "true"}}
                elif mid == 767:
                    reply = {"SessionID": sid, "Body": {"Ret": "true"}}
                else:
                    reply = {"SessionID": sid, "Body": {"Ret": "false"}}
                self._send(conn, json.dumps(reply).encode())

    @staticmethod
    def _recv_exact(conn, n):
        buf = bytearray()
        while len(buf) < n:
            c = conn.recv(n - len(buf))
            if not c:
                raise ConnectionError
            buf.extend(c)
        return bytes(buf)

    @staticmethod
    def _send(conn, payload):
        conn.sendall(T.dvrip_tcp_frame(payload))


class TcpTransportTests(unittest.TestCase):

    def test_session_over_tcp_reuses_sessionid_in_body(self):
        mock = MockDvripTCP()
        info = T.dvrip_tcp_query("127.0.0.1", mock.port, "admin", "pw123", 5)
        self.assertEqual(info["SerialNumber"], "SN-TCP-0001")
        self.assertEqual(info["Manufacturer"], "Provision-ISR")
        mids = [m["MsgID"] for m in mock.log]
        self.assertEqual(mids, [766, 1470, 767])
        # login carries 0x0; subsequent frames carry the session from the reply
        self.assertEqual(mock.log[0]["SessionID"], "0x0")
        self.assertEqual(mock.log[1]["SessionID"], "0xb0b")
        self.assertEqual(mock.log[2]["SessionID"], "0xb0b")
        # password on the wire is the MD5 hash, never plaintext
        self.assertEqual(mock.log[0]["Body"]["PassWord"], T.md5_upper("pw123"))
        self.assertNotIn("pw123", json.dumps(mock.log))

    def test_tcp_unreachable_raises_route_error(self):
        # connect to a port with nothing listening
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        with self.assertRaises(T.RouteError):
            T.dvrip_tcp_query("127.0.0.1", port, "admin", "x", 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)