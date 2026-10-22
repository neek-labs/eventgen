"""Bounded HTTP indicator generation for defensive telemetry validation."""

from __future__ import annotations

import argparse
import ipaddress
import json
import math
import re
import ssl
import sys
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping, Protocol, Sequence
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode, urlsplit, urlunsplit
from urllib.request import (
    HTTPRedirectHandler,
    HTTPSHandler,
    ProxyHandler,
    Request,
    build_opener,
)


DEFAULT_INTERVAL_SECONDS = 5.0
MIN_INTERVAL_SECONDS = 1.0
MAX_INTERVAL_SECONDS = 900.0
DEFAULT_DURATION_SECONDS = 60.0
MAX_DURATION_SECONDS = 900.0
MAX_ATTEMPTS = 900
MAX_PROFILES = 100
MAX_BODY_BYTES = 4 * 1024
MAX_URL_BYTES = 2048
MAX_HEADER_BYTES = 8 * 1024
MAX_HEADER_NAME_BYTES = 128
MAX_HEADER_VALUE_BYTES = 2048
MAX_HEADERS = 32
DEFAULT_TIMEOUT_SECONDS = 10.0
MAX_TIMEOUT_SECONDS = 30.0

_HEADER_NAME = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
_FORBIDDEN_HEADERS = {
    "connection",
    "content-length",
    "host",
    "proxy-authorization",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
}
_SENSITIVE_NAMES = ("authorization", "cookie", "credential", "password", "secret", "token")


class RedirectBlocked(HTTPRedirectHandler):
    """Expose redirects as responses rather than following them."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        return None


class TransportFailure(Exception):
    """A request did not produce an HTTP response."""


@dataclass(frozen=True)
class Destination:
    scheme: str
    hostname: str
    port: int | None = None

    @property
    def origin(self) -> str:
        host = f"[{self.hostname}]" if ":" in self.hostname else self.hostname
        netloc = f"{host}:{self.port}" if self.port is not None else host
        return urlunsplit((self.scheme, netloc, "", "", ""))


@dataclass(frozen=True)
class Profile:
    name: str
    method: str
    path: str
    query: tuple[tuple[str, str], ...]
    headers: tuple[tuple[str, str], ...]
    body: bytes | None


@dataclass(frozen=True)
class Configuration:
    destination: Destination
    profiles: tuple[Profile, ...]
    run_id_header: str | None = None


@dataclass(frozen=True)
class RequestSpec:
    profile: str
    method: str
    url: str
    headers: tuple[tuple[str, str], ...]
    body: bytes | None


@dataclass(frozen=True)
class HttpResult:
    status_code: int


class Sender(Protocol):
    def __call__(self, request: RequestSpec, timeout: float) -> HttpResult: ...


def _plain_object(value: object, label: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a JSON object.")
    return value


def _only_keys(value: Mapping[str, Any], allowed: set[str], label: str) -> None:
    extras = sorted(set(value) - allowed)
    if extras:
        raise ValueError(f"{label} contains unsupported field(s): {', '.join(extras)}.")


def _nonempty_string(value: object, label: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError(f"{label} must be a non-empty string without surrounding whitespace.")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise ValueError(f"{label} must not contain control characters.")
    return value


def _validate_header_name(value: object, label: str) -> str:
    name = _nonempty_string(value, label)
    if not _HEADER_NAME.fullmatch(name):
        raise ValueError(f"{label} is not a valid HTTP header name.")
    if len(name.encode("ascii")) > MAX_HEADER_NAME_BYTES:
        raise ValueError(f"{label} exceeds {MAX_HEADER_NAME_BYTES} bytes.")
    if name.casefold() in _FORBIDDEN_HEADERS:
        raise ValueError(f"{label} is transport-managed and cannot be configured.")
    return name


def _string_pairs(value: object, label: str, *, headers: bool = False) -> tuple[tuple[str, str], ...]:
    mapping = _plain_object(value, label)
    pairs: list[tuple[str, str]] = []
    for raw_name, raw_value in mapping.items():
        name = _validate_header_name(raw_name, f"{label} name") if headers else _nonempty_string(raw_name, f"{label} name")
        values = raw_value if isinstance(raw_value, list) and not headers else [raw_value]
        if not values:
            raise ValueError(f"{label}.{name} must contain at least one value.")
        for item in values:
            if not isinstance(item, (str, int, float, bool)) or isinstance(item, float) and not math.isfinite(item):
                raise ValueError(f"{label}.{name} must contain scalar JSON values.")
            rendered = str(item).lower() if isinstance(item, bool) else str(item)
            if any(ord(character) < 32 or ord(character) == 127 for character in rendered):
                raise ValueError(f"{label}.{name} must not contain control characters.")
            if headers and len(rendered.encode("utf-8")) > MAX_HEADER_VALUE_BYTES:
                raise ValueError(f"{label}.{name} exceeds {MAX_HEADER_VALUE_BYTES} bytes.")
            pairs.append((name, rendered))
    return tuple(pairs)


def _parse_destination(value: object) -> Destination:
    item = _plain_object(value, "destination")
    _only_keys(item, {"scheme", "hostname", "port"}, "destination")
    scheme = _nonempty_string(item.get("scheme"), "destination.scheme").casefold()
    if scheme not in {"http", "https"}:
        raise ValueError("destination.scheme must be http or https.")
    hostname = _nonempty_string(item.get("hostname"), "destination.hostname")
    if any(character in hostname for character in "/?#@[]"):
        raise ValueError("destination.hostname must be a hostname or IP address only.")
    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        try:
            ascii_hostname = hostname.encode("idna").decode("ascii").casefold()
        except UnicodeError as exc:
            raise ValueError("destination.hostname is not a valid hostname.") from exc
        labels = ascii_hostname.removesuffix(".").split(".")
        if (
            len(ascii_hostname) > 253
            or not labels
            or any(
                not label
                or len(label) > 63
                or not re.fullmatch(r"[a-z0-9-]+", label)
                or label.startswith("-")
                or label.endswith("-")
                for label in labels
            )
        ):
            raise ValueError("destination.hostname is not a valid hostname.")
        hostname = ascii_hostname
    else:
        hostname = str(address)
    port = item.get("port")
    if port is not None and (isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535):
        raise ValueError("destination.port must be an integer from 1 through 65535.")
    return Destination(scheme=scheme, hostname=hostname, port=port)


def _parse_body(value: object, method: str, profile_name: str) -> tuple[bytes | None, str | None]:
    if value is None:
        return None, None
    if method != "POST":
        raise ValueError(f"profile {profile_name!r} may specify a body only for POST.")
    item = _plain_object(value, f"profile {profile_name!r} body")
    _only_keys(item, {"type", "value"}, f"profile {profile_name!r} body")
    body_type = item.get("type")
    if body_type == "text":
        if not isinstance(item.get("value"), str):
            raise ValueError(f"profile {profile_name!r} text body value must be a string.")
        data = item["value"].encode("utf-8")
        content_type = "text/plain; charset=utf-8"
    elif body_type == "json":
        try:
            data = json.dumps(item.get("value"), ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")
        except (TypeError, ValueError) as exc:
            raise ValueError(f"profile {profile_name!r} JSON body is invalid: {exc}") from exc
        content_type = "application/json; charset=utf-8"
    else:
        raise ValueError(f"profile {profile_name!r} body.type must be text or json.")
    if len(data) > MAX_BODY_BYTES:
        raise ValueError(f"profile {profile_name!r} body exceeds {MAX_BODY_BYTES} bytes.")
    return data, content_type


def parse_configuration(document: object) -> Configuration:
    """Validate and convert a decoded JSON configuration before any I/O."""

    root = _plain_object(document, "configuration")
    _only_keys(root, {"destination", "profiles", "run_id_header"}, "configuration")
    destination = _parse_destination(root.get("destination"))
    raw_profiles = root.get("profiles")
    if not isinstance(raw_profiles, list) or not raw_profiles:
        raise ValueError("profiles must be a non-empty JSON array.")
    if len(raw_profiles) > MAX_PROFILES:
        raise ValueError(f"profiles may contain at most {MAX_PROFILES} entries.")

    run_id_header = root.get("run_id_header")
    if run_id_header is not None:
        run_id_header = _validate_header_name(run_id_header, "run_id_header")

    profiles: list[Profile] = []
    seen_names: set[str] = set()
    for index, raw_profile in enumerate(raw_profiles):
        item = _plain_object(raw_profile, f"profiles[{index}]")
        _only_keys(item, {"name", "method", "path", "query", "headers", "body"}, f"profiles[{index}]")
        name = _nonempty_string(item.get("name"), f"profiles[{index}].name")
        if name in seen_names:
            raise ValueError(f"profile name {name!r} is duplicated.")
        seen_names.add(name)
        method = _nonempty_string(item.get("method"), f"profile {name!r} method").upper()
        if method not in {"GET", "POST"}:
            raise ValueError(f"profile {name!r} method must be GET or POST.")
        path = _nonempty_string(item.get("path"), f"profile {name!r} path")
        parsed_path = urlsplit(path)
        if not path.startswith("/") or path.startswith("//") or "\\" in path or parsed_path.scheme or parsed_path.netloc or parsed_path.query or parsed_path.fragment:
            raise ValueError(f"profile {name!r} path must be a relative-origin path without a query or fragment.")
        query = _string_pairs(item.get("query", {}), f"profile {name!r} query")
        headers = list(_string_pairs(item.get("headers", {}), f"profile {name!r} headers", headers=True))
        if len(headers) > MAX_HEADERS:
            raise ValueError(f"profile {name!r} has more than {MAX_HEADERS} headers.")
        folded_header_names = [header_name.casefold() for header_name, _ in headers]
        if len(folded_header_names) != len(set(folded_header_names)):
            raise ValueError(f"profile {name!r} contains duplicate case-insensitive header names.")
        if run_id_header and any(header_name.casefold() == run_id_header.casefold() for header_name, _ in headers):
            raise ValueError(f"profile {name!r} must not override run_id_header {run_id_header!r}.")
        body, default_content_type = _parse_body(item.get("body"), method, name)
        if default_content_type and not any(header_name.casefold() == "content-type" for header_name, _ in headers):
            headers.append(("Content-Type", default_content_type))
        header_bytes = sum(len(header_name.encode("ascii")) + len(value.encode("utf-8")) + 4 for header_name, value in headers)
        if run_id_header:
            header_bytes += len(run_id_header.encode("ascii")) + 36 + 4
        if header_bytes > MAX_HEADER_BYTES:
            raise ValueError(f"profile {name!r} headers exceed {MAX_HEADER_BYTES} bytes.")
        profile = Profile(name, method, path, query, tuple(headers), body)
        _build_request(Configuration(destination, (profile,), run_id_header), profile, "00000000-0000-0000-0000-000000000000")
        profiles.append(profile)
    return Configuration(destination, tuple(profiles), run_id_header)


def load_configuration(path: str | Path) -> Configuration:
    with Path(path).open("r", encoding="utf-8") as source:
        try:
            document = json.load(source)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Configuration is not valid JSON: {exc}") from exc
    return parse_configuration(document)


def _encoded_path(path: str) -> str:
    return quote(path, safe="/%:@!$&'()*+,;=-._~")


def _build_request(configuration: Configuration, profile: Profile, run_id: str) -> RequestSpec:
    query = urlencode(profile.query, doseq=True)
    url = urlunsplit((configuration.destination.scheme, urlsplit(configuration.destination.origin).netloc, _encoded_path(profile.path), query, ""))
    if len(url.encode("utf-8")) > MAX_URL_BYTES:
        raise ValueError(f"profile {profile.name!r} encoded URL exceeds {MAX_URL_BYTES} bytes.")
    headers = list(profile.headers)
    if configuration.run_id_header:
        headers.append((configuration.run_id_header, run_id))
    return RequestSpec(profile.name, profile.method, url, tuple(headers), profile.body)


def _is_sensitive(name: str) -> bool:
    lowered = name.casefold()
    return any(marker in lowered for marker in _SENSITIVE_NAMES)


def _redacted_url(url: str) -> str:
    parts = urlsplit(url)
    from urllib.parse import parse_qsl

    query = urlencode([(name, "<redacted>" if _is_sensitive(name) else value) for name, value in parse_qsl(parts.query, keep_blank_values=True)])
    return urlunsplit((parts.scheme, parts.netloc, parts.path, query, ""))


def _request_record(request: RequestSpec, *, preview: bool = False) -> dict[str, object]:
    headers = {name: "<redacted>" if _is_sensitive(name) else value for name, value in request.headers}
    if preview:
        headers = {name: "<generated run ID>" if value == "00000000-0000-0000-0000-000000000000" else value for name, value in headers.items()}
    return {
        "profile": request.profile,
        "method": request.method,
        "url": _redacted_url(request.url),
        "headers": headers,
        "body_utf8": request.body.decode("utf-8") if request.body is not None else None,
    }


def _positive_finite(value: object, label: str, maximum: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{label} must be a number.")
    result = float(value)
    if not math.isfinite(result) or result <= 0 or result > maximum:
        raise ValueError(f"{label} must be greater than zero and at most {maximum:g} seconds.")
    return result


def validate_run_options(*, mode: str, interval: object, duration: object | None, timeout: object) -> tuple[float, float | None, float]:
    if mode not in {"once", "loop"}:
        raise ValueError("mode must be once or loop.")
    interval_value = _positive_finite(interval, "interval", MAX_INTERVAL_SECONDS)
    if interval_value < MIN_INTERVAL_SECONDS:
        raise ValueError(f"interval must be at least {MIN_INTERVAL_SECONDS:g} second.")
    timeout_value = _positive_finite(timeout, "timeout", MAX_TIMEOUT_SECONDS)
    if mode == "once":
        if duration is not None:
            raise ValueError("duration is valid only in loop mode.")
        return interval_value, None, timeout_value
    duration_value = _positive_finite(DEFAULT_DURATION_SECONDS if duration is None else duration, "duration", MAX_DURATION_SECONDS)
    return interval_value, duration_value, timeout_value


def maximum_attempts(configuration: Configuration, *, mode: str, interval: float, duration: float | None) -> int:
    if mode == "once":
        return min(len(configuration.profiles), MAX_ATTEMPTS)
    assert duration is not None
    return min(MAX_ATTEMPTS, math.ceil(duration / interval))


def preview(configuration: Configuration, *, mode: str, interval: object = DEFAULT_INTERVAL_SECONDS, duration: object | None = None, timeout: object = DEFAULT_TIMEOUT_SECONDS) -> dict[str, object]:
    interval_value, duration_value, timeout_value = validate_run_options(mode=mode, interval=interval, duration=duration, timeout=timeout)
    placeholder = "00000000-0000-0000-0000-000000000000"
    requests = [_request_record(_build_request(configuration, profile, placeholder), preview=True) for profile in configuration.profiles]
    return {
        "network_activity": False,
        "destination": configuration.destination.origin,
        "mode": mode,
        "interval_seconds": interval_value,
        "duration_seconds": duration_value,
        "timeout_seconds": timeout_value,
        "maximum_attempted_requests": maximum_attempts(configuration, mode=mode, interval=interval_value, duration=duration_value),
        "profiles": requests,
        "note": "An HTTP response confirms receipt only; it does not prove telemetry collection or a detection match.",
    }


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def default_sender(request: RequestSpec, timeout: float) -> HttpResult:
    """Send one request with verified TLS, no proxy, redirect, retry, or body read."""

    opener = build_opener(
        ProxyHandler({}),
        HTTPSHandler(context=ssl.create_default_context()),
        RedirectBlocked(),
    )
    # urllib otherwise injects its own User-Agent, which would make the actual
    # application header set differ from the validated preview.
    opener.addheaders = []
    outgoing = Request(request.url, data=request.body, method=request.method, headers=dict(request.headers))
    try:
        response = opener.open(outgoing, timeout=timeout)
    except HTTPError as exc:
        response = exc
    except (URLError, TimeoutError, OSError, ssl.SSLError) as exc:
        reason = getattr(exc, "reason", exc)
        raise TransportFailure(str(reason)) from exc
    with response:
        return HttpResult(status_code=int(response.getcode()))


def execute(
    configuration: Configuration,
    *,
    mode: str,
    interval: object = DEFAULT_INTERVAL_SECONDS,
    duration: object | None = None,
    timeout: object = DEFAULT_TIMEOUT_SECONDS,
    sender: Sender = default_sender,
    clock: Callable[[], float] = time.monotonic,
    sleeper: Callable[[float], None] = time.sleep,
    utc_clock: Callable[[], str] = utc_now,
    run_id_factory: Callable[[], object] = uuid.uuid4,
) -> dict[str, object]:
    """Execute a fully bounded run; safety rules apply to all callers."""

    # Re-validate serialized values so hand-constructed configurations cannot
    # use the execution API to bypass configuration safeguards.
    configuration = parse_configuration(configuration_to_dict(configuration))
    interval_value, duration_value, timeout_value = validate_run_options(mode=mode, interval=interval, duration=duration, timeout=timeout)
    run_id = str(run_id_factory())
    started_utc = utc_clock()
    started = clock()
    deadline = started + duration_value if duration_value is not None else None
    attempts: list[dict[str, object]] = []
    stop_reason = "once_complete" if mode == "once" else "duration_elapsed"
    consecutive_failures = 0
    profile_index = 0
    interrupted = False

    while len(attempts) < MAX_ATTEMPTS:
        if mode == "once" and profile_index >= len(configuration.profiles):
            break
        if deadline is not None and clock() >= deadline:
            break
        profile = configuration.profiles[profile_index % len(configuration.profiles)]
        request = _build_request(configuration, profile, run_id)
        attempt_started = clock()
        attempt: dict[str, object] = {
            "profile": profile.name,
            "timestamp_utc": utc_clock(),
            "method": request.method,
            "url": _redacted_url(request.url),
            "status_code": None,
            "error": None,
            "elapsed_seconds": None,
        }
        attempts.append(attempt)
        try:
            result = sender(request, timeout_value)
            attempt["status_code"] = result.status_code
            consecutive_failures = 0
            if result.status_code in {429, 503}:
                stop_reason = f"http_{result.status_code}"
                break
        except KeyboardInterrupt:
            attempt["error"] = "interrupted"
            stop_reason = "interrupted"
            interrupted = True
        except Exception as exc:  # A sender exception means no HTTP response.
            attempt["error"] = f"{type(exc).__name__}: {exc}"
            consecutive_failures += 1
            if consecutive_failures >= 3:
                stop_reason = "three_consecutive_transport_failures"
        finally:
            attempt["elapsed_seconds"] = round(max(0.0, clock() - attempt_started), 6)
        if interrupted or consecutive_failures >= 3:
            break
        profile_index += 1
        if mode == "once" and profile_index >= len(configuration.profiles):
            break
        if len(attempts) >= MAX_ATTEMPTS:
            stop_reason = "attempt_limit"
            break

        # Schedule from completion, never from an old target time. This both
        # enforces shared spacing and prevents catch-up bursts after delays.
        next_start = clock() + interval_value
        try:
            while clock() < next_start:
                if deadline is not None and clock() >= deadline:
                    break
                sleep_for = next_start - clock()
                if deadline is not None:
                    sleep_for = min(sleep_for, max(0.0, deadline - clock()))
                if sleep_for <= 0:
                    break
                sleeper(sleep_for)
        except KeyboardInterrupt:
            stop_reason = "interrupted"
            interrupted = True
        if interrupted:
            break

    if len(attempts) >= MAX_ATTEMPTS and stop_reason not in {"http_429", "http_503", "three_consecutive_transport_failures", "interrupted"}:
        stop_reason = "attempt_limit"
    response_count = sum(attempt["status_code"] is not None for attempt in attempts)
    return {
        "run_id": run_id,
        "destination": configuration.destination.origin,
        "started_at_utc": started_utc,
        "completed_at_utc": utc_clock(),
        "mode": mode,
        "interval_seconds": interval_value,
        "duration_seconds": duration_value,
        "timeout_seconds": timeout_value,
        "attempts": attempts,
        "totals": {
            "attempted": len(attempts),
            "http_responses": response_count,
            "transport_failures": len(attempts) - response_count,
        },
        "stop_reason": stop_reason,
        "note": "HTTP responses confirm receipt only; telemetry collection and detection matches must be verified separately.",
    }


def configuration_to_dict(configuration: Configuration) -> dict[str, object]:
    profiles: list[dict[str, object]] = []
    for profile in configuration.profiles:
        item: dict[str, object] = {
            "name": profile.name,
            "method": profile.method,
            "path": profile.path,
            "query": _pairs_to_mapping(profile.query),
            "headers": dict(profile.headers),
        }
        if profile.body is not None:
            content_type = next((value for name, value in profile.headers if name.casefold() == "content-type"), "")
            if content_type.casefold().startswith("application/json"):
                item["body"] = {"type": "json", "value": json.loads(profile.body.decode("utf-8"))}
            else:
                item["body"] = {"type": "text", "value": profile.body.decode("utf-8")}
        profiles.append(item)
    destination: dict[str, object] = {"scheme": configuration.destination.scheme, "hostname": configuration.destination.hostname}
    if configuration.destination.port is not None:
        destination["port"] = configuration.destination.port
    return {"destination": destination, "profiles": profiles, "run_id_header": configuration.run_id_header}


def _pairs_to_mapping(pairs: Sequence[tuple[str, str]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for name, value in pairs:
        existing = result.get(name)
        if existing is None:
            result[name] = value
        elif isinstance(existing, list):
            existing.append(value)
        else:
            result[name] = [existing, value]
    return result


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Generate bounded web indicators for defensive telemetry validation.")
    parser.add_argument("config", help="JSON configuration file")
    action = parser.add_mutually_exclusive_group()
    action.add_argument("--once", action="store_true", help="send each profile once")
    action.add_argument("--loop", action="store_true", help="cycle profiles for a bounded duration")
    parser.add_argument("--preview", action="store_true", help="show the validated plan without network activity (defaults to loop mode)")
    parser.add_argument("--interval", type=float, default=DEFAULT_INTERVAL_SECONDS, help="seconds between request starts (default: 5; minimum: 1)")
    parser.add_argument("--duration", type=float, help="loop duration in seconds (default: 60; maximum: 900)")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT_SECONDS, help="per-request timeout in seconds (default: 10; maximum: 30)")
    parser.add_argument("--report", type=Path, help="also write preview/report JSON to this path")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    try:
        if not args.preview and not args.once and not args.loop:
            raise ValueError("choose --preview, --once, or --loop.")
        configuration = load_configuration(args.config)
        mode = "once" if args.once else "loop"
        if mode == "once" and args.duration is not None:
            raise ValueError("--duration is valid only with --loop.")
        plan = preview(configuration, mode=mode, interval=args.interval, duration=args.duration, timeout=args.timeout)
        if args.preview:
            result = plan
        else:
            print("Validated request plan (network has not started):", file=sys.stderr)
            print(json.dumps(plan, indent=2, ensure_ascii=False), file=sys.stderr)
            result = execute(configuration, mode=mode, interval=args.interval, duration=args.duration, timeout=args.timeout)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    rendered = json.dumps(result, indent=2, ensure_ascii=False)
    print(rendered)
    if args.report:
        args.report.write_text(rendered + "\n", encoding="utf-8")
    return 130 if result.get("stop_reason") == "interrupted" else 0


if __name__ == "__main__":
    sys.exit(main())
