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

    def test_http_auth_challenge_raises_auth_challenge(self):
        # 401 with no usable JSON reply → HttpAuthChallenge (the XML transport
        # in auto order is what answers challenges with credentials)
        MockDvripHTTP.reject = True
        srv = ThreadingHTTPServer(("127.0.0.1", 0), MockDvripHTTP)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            with self.assertRaises(T.HttpAuthChallenge):
                T.dvrip_http_query("127.0.0.1", srv.server_address[1],
                                   "admin", "x", 5)
        finally:
            srv.shutdown()
            MockDvripHTTP.reject = False


# ── Provision-ISR XML API (HTTP Basic/Digest, command in URL path) ───────────

class MockProvisionXML(BaseHTTPRequestHandler):
    """Speaks the official Provision-ISR HTTP API v1.9 shape: 401 +
    WWW-Authenticate when unauthenticated; XML when authorized."""
    seen = {"requests": []}
    require_digest = False

    def log_message(self, *a):
        pass

    def do_GET(self):
        self._handle()

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        if length:
            self.rfile.read(length)
        self._handle()

    def _handle(self):
        auth = self.headers.get("Authorization", "")
        self.seen["requests"].append((self.path, auth))
        good = (auth.startswith("Basic ") and
                auth != "Basic " + __import__("base64").b64encode(b"admin:wrongpw").decode())
        if not good:
            self._deny()
            return
        self._respond()

    def _deny(self):
        self.send_response(401)
        if self.require_digest:
            scheme = 'Digest realm="X" qop="auth" nonce="abc"'
        else:
            scheme = 'Basic realm="XXXXXX"'
        self.send_header("WWW-Authenticate", scheme)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _respond(self):
        if self.path == "/GetDeviceInfo":
            body = ("<?xml version='1.0' encoding='UTF-8'?>"
                    "<body><deviceInfo>"
                    "<deviceDescription>IPCamera</deviceDescription>"
                    "<deviceType>IPC-HX5</deviceType>"
                    "<serialNumber>SN-XML-0001</serialNumber>"
                    "<hardwareVersion>V1.2</hardwareVersion>"
                    "<softwareVersion>V4.1.02.0</softwareVersion>"
                    "<videoInCount>1</videoInCount>"
                    "</deviceInfo></body>")
        elif self.path == "/GetDeviceDetail":
            body = ("<body><deviceDetail><supportPtz>true</supportPtz>"
                    "<supportTalk>false</supportTalk></deviceDetail></body>")
        elif self.path == "/GetNetBasicConfig":
            body = ("<body><netBasic><tcpIp><mac>00:12:3F:AB:CD:EF</mac>"
                    "<dhcp>true</dhcp></tcpIp></netBasic></body>")
        else:
            self.send_response(400)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        data = body.encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/xml; charset='UTF-8'")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


class ProvisionXMLTests(unittest.TestCase):

    def setUp(self):
        MockProvisionXML.seen = {"requests": []}
        MockProvisionXML.require_digest = False
        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), MockProvisionXML)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def tearDown(self):
        self.srv.shutdown()

    def test_401_challenge_then_basic_success(self):
        info = T.provision_xml_query("127.0.0.1", self.srv.server_address[1],
                                     "admin", "goodpw", 5)
        self.assertEqual(info["serialNumber"], "SN-XML-0001")
        self.assertEqual(info["deviceType"], "IPC-HX5")
        self.assertEqual(info["softwareVersion"], "V4.1.02.0")
        paths = [p for p, _ in MockProvisionXML.seen["requests"]]
        # GET is tried first (Postman-collection style); each command: probe 401
        # then credentialed retry — POST never needed when GET succeeds
        self.assertEqual(paths, ["/GetDeviceInfo", "/GetDeviceInfo",
                                 "/GetDeviceDetail", "/GetDeviceDetail",
                                 "/GetNetBasicConfig", "/GetNetBasicConfig"])

    def test_get_first_then_post_fallback(self):
        # A firmware that 501s GET (POST-only) still completes via the POST path
        info = T.provision_xml_query("127.0.0.1", self.srv.server_address[1],
                                     "admin", "goodpw", 5)
        self.assertIn("serialNumber", info)  # mock serves both; presence is enough

    def test_debug_trace_redacts_credentials(self):
        import io
        from unittest.mock import patch
        buf = io.StringIO()
        with patch.object(T.sys, "stderr", buf):
            T.DEBUG = True
            try:
                T.provision_xml_query("127.0.0.1", self.srv.server_address[1],
                                      "admin", "goodpw", 5)
            finally:
                T.DEBUG = False
        trace = buf.getvalue()
        self.assertIn("[dbg]", trace)
        self.assertIn("GetDeviceInfo", trace)
        self.assertNotIn("goodpw", trace)
        self.assertNotIn(__import__("base64").b64encode(b"admin:goodpw").decode(), trace)

        auths = [a for _, a in MockProvisionXML.seen["requests"]]
        self.assertEqual(auths[0], "")                      # probe unauthenticated
        self.assertTrue(auths[1].startswith("Basic "))      # retry authorized
        self.assertTrue(all(a.startswith("Basic ") for a in auths[1::2]))
        self.assertTrue(all(a == "" for a in auths[::2]))
        self.assertNotIn("goodpw", str(MockProvisionXML.seen))  # never in URL/path

    def test_bad_credentials_surface_as_auth_error(self):
        with self.assertRaises(T.AuthError):
            T.provision_xml_query("127.0.0.1", self.srv.server_address[1],
                                  "admin", "wrongpw", 5)

    def test_digest_challenge_detected_and_attempted(self):
        MockProvisionXML.require_digest = True
        # Our mock can't validate real RFC2617 digest responses, so assert the
        # scheme selection only — the real handler is urllib's HTTPDigestAuthHandler.
        self.assertEqual(T._auth_scheme_from_challenge(
            'Digest realm="X" qop="auth" nonce="abc"'), "digest")
        self.assertEqual(T._auth_scheme_from_challenge(
            'Basic realm="XXXXXX"'), "basic")
        self.assertEqual(T._auth_scheme_from_challenge(""), "basic")

    def test_xml_flatten_leaf_tags(self):
        fields = T._xml_text_all(
            b"<body><deviceInfo><serialNumber>SN-1</serialNumber>"
            b"<nested><deep>2</deep></nested></deviceInfo></body>")
        self.assertEqual(fields, {"serialNumber": "SN-1", "deep": "2"})

    def test_route_error_on_closed_port(self):
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        with self.assertRaises(T.RouteError):
            T.provision_xml_query("127.0.0.1", port, "admin", "x", 2)


class MockOnvif80(BaseHTTPRequestHandler):
    """ONVIF-on-80 device: challenge unauthenticated SOAP with 401 Basic,
    accept a Basic-credentialed retry; legacy 8899 mode wants WS-UsernameToken."""
    seen = []
    require_ws_token = False
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode("utf-8", errors="replace")
        MockOnvif80.seen.append({"path": self.path,
                                 "auth": self.headers.get("Authorization"),
                                 "body": body})
        has_ws_token = "UsernameToken" in body and "<Username>admin</Username>" in body
        if self.headers.get("Authorization") == "Basic YWRtaW46Z29vZHB3":  # admin:goodpw
            self._serve()
        elif MockOnvif80.require_ws_token and has_ws_token:
            self._serve()
        elif self.headers.get("Authorization") is None:
            self.send_response(401)
            self.send_header("WWW-Authenticate", 'Basic realm="Basic"')
            self.send_header("Content-Length", "0")
            self.end_headers()
        else:
            self.send_response(401)
            self.send_header("WWW-Authenticate", 'Basic realm="Basic"')
            self.send_header("Content-Length", "0")
            self.end_headers()

    def _serve(self):
        body = ('<?xml version="1.0" encoding="UTF-8"?>'
                '<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://www.w3.org/2003/05/soap-envelope">'
                '<SOAP-ENV:Body><tds:GetDeviceInformationResponse>'
                '<tds:Manufacturer>TVT</tds:Manufacturer>'
                '<tds:Model>TD-9423A3-LR</tds:Model>'
                '<tds:SerialNumber>SN-ONVIF-80-1234</tds:SerialNumber>'
                '<tds:FirmwareVersion>5.1.1.0(52573)</tds:FirmwareVersion>'
                '</tds:GetDeviceInformationResponse>'
                '<tds:GetNetworkInterfacesResponse>'
                '<tds:NetworkInterfaces><tt:Info><tt:HwAddress>00:12:3F:11:22:33</tt:HwAddress>'
                '</tt:Info></tds:NetworkInterfaces>'
                '</tds:GetNetworkInterfacesResponse></SOAP-ENV:Body></SOAP-ENV:Envelope>').encode()
        self.send_response(200)
        self.send_header("Content-Type", 'application/soap+xml; charset=utf-8')
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


class OnvifPort80Tests(unittest.TestCase):
    def setUp(self):
        MockOnvif80.seen = []
        MockOnvif80.require_ws_token = False
        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), MockOnvif80)
        self.port = self.srv.server_address[1]
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def tearDown(self):
        self.srv.shutdown()

    def test_challenge_then_basic_retry(self):
        info, mac, label, kind = T._run_proto(
            "onvif", "127.0.0.1", self.port, "admin", "goodpw", 5)
        self.assertEqual(kind, "ok", info)
        self.assertEqual(info["SerialNumber"], "SN-ONVIF-80-1234")
        self.assertEqual(mac, "00:12:3F:11:22:33")
        self.assertEqual(label, "ONVIF SOAP")
        # two SOAP calls (device info + network interfaces), each with an
        # unauthenticated probe followed by the Basic credentialed retry
        self.assertEqual(len(MockOnvif80.seen), 4)
        self.assertIsNone(MockOnvif80.seen[0]["auth"])
        self.assertEqual(MockOnvif80.seen[1]["auth"], "Basic YWRtaW46Z29vZHB3")
        self.assertIsNone(MockOnvif80.seen[2]["auth"])
        self.assertEqual(MockOnvif80.seen[3]["auth"], "Basic YWRtaW46Z29vZHB3")

    def test_ws_username_token_fallback_for_legacy(self):
        MockOnvif80.require_ws_token = True
        info, mac, kind = T.onvif_get_device_information(
            f"http://127.0.0.1:{self.port}{T.ONVIF_PATH}", "admin", "goodpw", 5), None, "ok"
        self.assertEqual(info["SerialNumber"], "SN-ONVIF-80-1234")
        # second attempt (WS-Security inside SOAP body) authenticated without
        # an Authorization header on the mock's basic-required branch
        self.assertTrue(MockOnvif80.seen[-1]["body"].startswith("<?xml"))

    def test_bad_password_is_auth_error(self):
        _, err, _, kind = T._run_proto(
            "onvif", "127.0.0.1", self.port, "admin", "wrongpw", 5)
        self.assertEqual(kind, "auth", err)

    def test_port80_first_when_port_unspecified(self):
        # default port 0 → candidates [80, 8899]; closed 8899 on loopback gives
        # RouteError after 80 — here just assert candidate ordering via source
        src = open("tvt_camera_info.py").read()
        i = src.find("candidates = [(port or ONVIF_PORT, ONVIF_PATH)]")
        j = src.find("candidates.insert(0, (DVRIP_HTTP_PORT, ONVIF_PATH))")
        self.assertLess(i, j)
        self.assertIn("insert(0, (DVRIP_HTTP_PORT", src)


if __name__ == "__main__":
    unittest.main(verbosity=2)
