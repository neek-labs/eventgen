from __future__ import annotations

import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from app.http_client import (
    MAX_CUSTOM_HEADERS,
    send_once,
    validate_custom_headers,
)


class HeaderFixtureHandler(BaseHTTPRequestHandler):
    marker_seen = ""

    def do_GET(self) -> None:
        type(self).marker_seen = self.headers.get("X-EventGen-Marker", "")
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, format: str, *args: object) -> None:
        return


class HttpClientHeaderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), HeaderFixtureHandler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.url = f"http://127.0.0.1:{cls.server.server_port}/headers"

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)

    def setUp(self) -> None:
        HeaderFixtureHandler.marker_seen = ""

    def test_send_once_transmits_and_records_custom_header(self) -> None:
        snapshot = send_once(
            self.url,
            custom_headers=(("X-EventGen-Marker", "java4shell-lab"),),
        )

        self.assertEqual(HeaderFixtureHandler.marker_seen, "java4shell-lab")
        self.assertIn(
            ("X-EventGen-Marker", "java4shell-lab"), snapshot.request_headers
        )

    def test_custom_header_validation_rejects_reserved_and_unsafe_inputs(self) -> None:
        invalid_headers = (
            (("User-Agent", "other"),),
            (("Host", "example.test"),),
            (("Authorization", "Bearer secret"),),
            (("Bad Header", "value"),),
            (("X-Test", "line\r\nbreak"),),
            (("X-Test", " leading"),),
            (("X-Test", "one"), ("x-test", "two")),
        )

        for headers in invalid_headers:
            with self.subTest(headers=headers):
                with self.assertRaises(ValueError):
                    validate_custom_headers(headers)

    def test_custom_header_validation_enforces_count_limit(self) -> None:
        headers = tuple((f"X-Test-{index}", "value") for index in range(21))

        with self.assertRaisesRegex(ValueError, str(MAX_CUSTOM_HEADERS)):
            validate_custom_headers(headers)

