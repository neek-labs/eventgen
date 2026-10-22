from __future__ import annotations

import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from cli.web_indicators import (
    MAX_ATTEMPTS,
    HttpResult,
    TransportFailure,
    configuration_to_dict,
    default_sender,
    execute,
    parse_configuration,
    preview,
    validate_run_options,
    main,
)


def valid_document() -> dict[str, object]:
    return {
        "destination": {"scheme": "https", "hostname": "example.test", "port": 8443},
        "run_id_header": "X-EventGen-Run-ID",
        "profiles": [
            {
                "name": "first",
                "method": "GET",
                "path": "/hunt marker",
                "query": {"marker": "one & two", "repeat": ["a", "b"]},
                "headers": {"User-Agent": "EventGen-Test/1.0", "X-Test": "safe"},
            },
            {
                "name": "second",
                "method": "POST",
                "path": "/submit",
                "query": {},
                "headers": {},
                "body": {"type": "json", "value": {"marker": "harmless"}},
            },
        ],
    }


class FakeClock:
    def __init__(self) -> None:
        self.value = 100.0
        self.sleeps: list[float] = []

    def __call__(self) -> float:
        return self.value

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.value += seconds


class ConfigurationTests(unittest.TestCase):
    def test_configuration_round_trip_and_structured_encoding(self) -> None:
        configuration = parse_configuration(valid_document())
        restored = parse_configuration(configuration_to_dict(configuration))
        plan = preview(restored, mode="once")

        self.assertEqual(restored.destination.origin, "https://example.test:8443")
        self.assertIn("/hunt%20marker?marker=one+%26+two&repeat=a&repeat=b", plan["profiles"][0]["url"])
        self.assertEqual(plan["profiles"][1]["body_utf8"], '{"marker":"harmless"}')
        self.assertEqual(plan["profiles"][1]["headers"]["Content-Type"], "application/json; charset=utf-8")

    def test_ipv6_destination_is_serialized_with_brackets(self) -> None:
        document = valid_document()
        document["destination"] = {"scheme": "http", "hostname": "::1", "port": 8080}
        configuration = parse_configuration(document)
        self.assertEqual(configuration.destination.origin, "http://[::1]:8080")

    def test_destination_changing_and_absolute_paths_are_rejected(self) -> None:
        for path in ("https://other.test/x", "//other.test/x", "/ok?next=https://other.test", "/ok#fragment", "/a\\b"):
            document = valid_document()
            document["profiles"][0]["path"] = path
            with self.subTest(path=path), self.assertRaisesRegex(ValueError, "relative-origin"):
                parse_configuration(document)

    def test_managed_and_control_character_headers_are_rejected(self) -> None:
        for name, value in (("Host", "other.test"), ("Content-Length", "1"), ("X-Test", "bad\r\nInjected: yes")):
            document = valid_document()
            document["profiles"][0]["headers"] = {name: value}
            with self.subTest(name=name), self.assertRaises(ValueError):
                parse_configuration(document)

    def test_duplicate_case_insensitive_headers_are_rejected(self) -> None:
        document = valid_document()
        document["profiles"][0]["headers"] = {"X-Test": "one", "x-test": "two"}
        with self.assertRaisesRegex(ValueError, "duplicate"):
            parse_configuration(document)

    def test_body_and_url_limits_are_enforced(self) -> None:
        document = valid_document()
        document["profiles"][1]["body"] = {"type": "text", "value": "x" * 4097}
        with self.assertRaisesRegex(ValueError, "4096"):
            parse_configuration(document)

        document = valid_document()
        document["profiles"][0]["query"] = {"marker": "x" * 2100}
        with self.assertRaisesRegex(ValueError, "URL exceeds"):
            parse_configuration(document)

    def test_invalid_schedule_values_are_rejected(self) -> None:
        invalid = (0, -1, float("inf"), float("nan"), "5")
        for value in invalid:
            with self.subTest(value=value), self.assertRaises(ValueError):
                validate_run_options(mode="loop", interval=value, duration=60, timeout=10)
        with self.assertRaisesRegex(ValueError, "at least 1"):
            validate_run_options(mode="loop", interval=0.5, duration=60, timeout=10)
        with self.assertRaises(ValueError):
            validate_run_options(mode="loop", interval=1, duration=901, timeout=10)
        with self.assertRaises(ValueError):
            validate_run_options(mode="once", interval=1, duration=60, timeout=10)


class ExecutionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.configuration = parse_configuration(valid_document())
        self.clock = FakeClock()
        self.starts: list[tuple[str, float]] = []

    def sender(self, request, timeout):
        self.starts.append((request.profile, self.clock()))
        return HttpResult(200)

    def execute(self, **kwargs):
        return execute(
            self.configuration,
            sender=self.sender,
            clock=self.clock,
            sleeper=self.clock.sleep,
            utc_clock=lambda: "2026-10-21T12:00:00.000Z",
            run_id_factory=lambda: "run-id",
            **kwargs,
        )

    def test_preview_performs_no_network_activity(self) -> None:
        with patch("cli.web_indicators.default_sender", side_effect=AssertionError("network called")):
            result = preview(self.configuration, mode="loop", duration=60)
        self.assertFalse(result["network_activity"])
        self.assertEqual(result["maximum_attempted_requests"], 12)

    def test_preview_cli_accepts_a_duration_without_executing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "config.json")
            path.write_text(json.dumps(valid_document()), encoding="utf-8")
            with (
                patch("cli.web_indicators.execute", side_effect=AssertionError("network called")),
                redirect_stdout(StringIO()) as output,
                redirect_stderr(StringIO()),
            ):
                result = main([str(path), "--preview", "--duration", "30"])
        self.assertEqual(result, 0)
        self.assertEqual(json.loads(output.getvalue())["duration_seconds"], 30.0)

    def test_profiles_cycle_in_order_with_shared_spacing(self) -> None:
        report = self.execute(mode="loop", interval=2, duration=7)

        self.assertEqual([name for name, _ in self.starts], ["first", "second", "first", "second"])
        self.assertEqual([when for _, when in self.starts], [100.0, 102.0, 104.0, 106.0])
        self.assertEqual(report["stop_reason"], "duration_elapsed")

    def test_slow_request_does_not_cause_catch_up_burst(self) -> None:
        def slow_sender(request, timeout):
            self.starts.append((request.profile, self.clock()))
            self.clock.value += 3
            return HttpResult(200)

        report = execute(
            self.configuration,
            mode="loop",
            interval=2,
            duration=12,
            sender=slow_sender,
            clock=self.clock,
            sleeper=self.clock.sleep,
            utc_clock=lambda: "2026-10-21T12:00:00.000Z",
        )

        self.assertEqual([when for _, when in self.starts], [100.0, 105.0, 110.0])
        self.assertEqual(report["totals"]["attempted"], 3)

    def test_once_mode_spaces_profiles(self) -> None:
        report = self.execute(mode="once", interval=1)
        self.assertEqual([when for _, when in self.starts], [100.0, 101.0])
        self.assertEqual(report["stop_reason"], "once_complete")

    def test_attempt_limit_is_hard_cap(self) -> None:
        one_profile = valid_document()
        one_profile["profiles"] = one_profile["profiles"][:1]
        configuration = parse_configuration(one_profile)
        clock = FakeClock()
        report = execute(
            configuration,
            mode="loop",
            interval=1,
            duration=900,
            sender=lambda request, timeout: HttpResult(200),
            clock=clock,
            sleeper=clock.sleep,
            utc_clock=lambda: "2026-10-21T12:00:00.000Z",
        )
        self.assertEqual(report["totals"]["attempted"], MAX_ATTEMPTS)
        self.assertEqual(report["stop_reason"], "attempt_limit")

    def test_429_and_503_stop_immediately(self) -> None:
        for status in (429, 503):
            self.clock = FakeClock()
            self.starts.clear()
            with self.subTest(status=status):
                report = execute(
                    self.configuration,
                    mode="loop",
                    duration=60,
                    sender=lambda request, timeout: HttpResult(status),
                    clock=self.clock,
                    sleeper=self.clock.sleep,
                    utc_clock=lambda: "2026-10-21T12:00:00.000Z",
                )
                self.assertEqual(report["totals"]["attempted"], 1)
                self.assertEqual(report["stop_reason"], f"http_{status}")

    def test_three_transport_failures_stop_and_preserve_report(self) -> None:
        def fail(request, timeout):
            raise TransportFailure("fixture offline")

        report = execute(
            self.configuration,
            mode="loop",
            interval=1,
            duration=60,
            sender=fail,
            clock=self.clock,
            sleeper=self.clock.sleep,
            utc_clock=lambda: "2026-10-21T12:00:00.000Z",
        )
        self.assertEqual(report["totals"], {"attempted": 3, "http_responses": 0, "transport_failures": 3})
        self.assertEqual(report["stop_reason"], "three_consecutive_transport_failures")
        self.assertTrue(all(item["error"] for item in report["attempts"]))

    def test_keyboard_interrupt_in_request_preserves_partial_attempt(self) -> None:
        report = execute(
            self.configuration,
            mode="loop",
            duration=60,
            sender=lambda request, timeout: (_ for _ in ()).throw(KeyboardInterrupt()),
            clock=self.clock,
            sleeper=self.clock.sleep,
            utc_clock=lambda: "2026-10-21T12:00:00.000Z",
        )
        self.assertEqual(report["stop_reason"], "interrupted")
        self.assertEqual(report["totals"]["attempted"], 1)
        self.assertEqual(report["attempts"][0]["error"], "interrupted")

    def test_default_sender_disables_proxy_redirects_and_reads_no_body(self) -> None:
        configuration = parse_configuration(valid_document())
        request = preview(configuration, mode="once")["profiles"][0]
        built_handlers = []

        class Response:
            def __enter__(self):
                return self

            def __exit__(self, *args):
                self.closed = True

            def getcode(self):
                return 302

            def read(self, *args):
                raise AssertionError("response body must not be read")

        class Opener:
            def open(self, outgoing, timeout):
                self.timeout = timeout
                return Response()

        opener = Opener()
        opener.addheaders = [("User-Agent", "implicit-test-agent")]

        def capture(*handlers):
            built_handlers.extend(handlers)
            return opener

        from cli.web_indicators import _build_request

        spec = _build_request(configuration, configuration.profiles[0], "run-id")
        with patch("cli.web_indicators.build_opener", side_effect=capture):
            result = default_sender(spec, 10)

        self.assertEqual(result.status_code, 302)
        self.assertEqual(built_handlers[0].proxies, {})
        self.assertTrue(any(handler.__class__.__name__ == "RedirectBlocked" for handler in built_handlers))
        self.assertEqual(opener.addheaders, [])


if __name__ == "__main__":
    unittest.main()
