#!/usr/bin/env python3

from __future__ import annotations

import argparse
import getpass
import html
import json
import math
import os
import re
import select
import ssl
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable


ENV_ORDER = [
    "FALCON_CLIENT_ID",
    "FALCON_CLIENT_SECRET",
    "FALCON_BASE_URL",
]

DEFAULTS = {
    "FALCON_BASE_URL": "https://api.eu-1.crowdstrike.com",
}

SEVERITY_LABELS = ["critical", "high", "medium", "low", "informational", "unknown"]
REPORT_RANGE_CHOICES = ["1h", "1d", "2d", "3d", "7d", "14d", "30d", "90d"]
REPORT_RANGE_TO_DELTA = {
    "1h": timedelta(hours=1),
    "1d": timedelta(days=1),
    "2d": timedelta(days=2),
    "3d": timedelta(days=3),
    "7d": timedelta(days=7),
    "14d": timedelta(days=14),
    "30d": timedelta(days=30),
    "90d": timedelta(days=90),
}
DEFAULT_REPORT_RANGE = "7d"
AGE_CHART_WINDOW = timedelta(days=365)
MAX_DISPLAY_AGE_SECONDS = int(timedelta(days=365 * 5).total_seconds())
CATEGORY_ORDER = ["network", "endpoint", "identity", "data protection", "saas", "cloud", "automated leads", "other"]
CORE_DETECTION_PRODUCTS = {"thirdparty", "epp", "idp", "data-protection", "saas-security"}
CATEGORY_LABEL_MAP = {
    "epp": "endpoint",
    "idp": "identity",
    "cwpp": "cloud",
    "data-protection": "data protection",
    "saas-security": "saas",
    "thirdparty": "third party",
    "automated-lead": "automated leads",
    "automated-lead-context": "automated lead context",
    "overwatch": "overwatch",
}

VERSION = "0.01a"
ANSI_RESET = "\033[0m"
ANSI_RED = "\033[31m"
ANSI_GREEN = "\033[32m"
ANSI_PATTERN = re.compile(r"\x1b\[[0-9;]*m")


@dataclass
class Config:
    client_id: str
    client_secret: str
    base_url: str
    member_cid: str
    lookback_days: int
    include_hidden_alerts: bool
    max_detail_records: int
    detections_filter: str
    overwatch_analyzed_events_filter: str
    overwatch_hunting_leads_filter: str
    overwatch_triggered_detections_filter: str
    ngsiem_detections_filter: str
    ngsiem_detections_category_field: str
    ngsiem_automated_leads_filter: str
    ngsiem_leads_confidence_field: str
    ngsiem_leads_category_field: str

    @property
    def start_time(self) -> datetime:
        return datetime.now(timezone.utc) - timedelta(days=self.lookback_days)

    @property
    def end_time(self) -> datetime:
        return datetime.now(timezone.utc)

    @property
    def start_iso(self) -> str:
        return self.start_time.strftime("%Y-%m-%dT%H:%M:%SZ")

    @property
    def end_iso(self) -> str:
        return self.end_time.strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class CountResult:
    label: str
    total: int | None
    error: str | None = None


@dataclass
class RecordSummary:
    total: int
    counters: dict[str, Counter[str]]
    truncated: bool
    error: str | None = None


@dataclass
class OverwatchMetric:
    label: str
    value: int | None
    source: str
    note: str | None = None


@dataclass
class OverwatchSummary:
    analyzed_events: int | None
    endpoint_hunting_leads: int | None
    detections: int | None
    analyzed_source: str = ""
    endpoint_hunting_leads_source: str = ""
    detections_source: str = ""


@dataclass
class GatheredData:
    core_records: list[dict[str, Any]]
    core_records_365d: list[dict[str, Any]]
    cases: list[dict[str, Any]]
    cases_365d: list[dict[str, Any]]
    leads: list[dict[str, Any]]
    leads_365d: list[dict[str, Any]]
    overwatch: OverwatchSummary
    cid_name: str
    cid: str


@dataclass
class PreflightCheck:
    name: str
    required: bool
    ok: bool
    detail: str = ""


@dataclass
class PreflightReport:
    checks: list[PreflightCheck]

    @property
    def required_ok(self) -> bool:
        return all(check.ok for check in self.checks if check.required)

    @property
    def missing_required(self) -> list[PreflightCheck]:
        return [check for check in self.checks if check.required and not check.ok]

    @property
    def missing_optional(self) -> list[PreflightCheck]:
        return [check for check in self.checks if not check.required and not check.ok]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build an ASCII CrowdStrike Falcon activity overview."
    )
    parser.add_argument(
        "--setup",
        action="store_true",
        help="Re-run configuration prompts and overwrite .env in the current directory.",
    )
    parser.add_argument(
        "--range",
        dest="report_range",
        choices=REPORT_RANGE_CHOICES,
        help="Choose the report time range (1h, 1d, 2d, 3d, 7d, 14d, 30d, 90d).",
    )
    return parser.parse_args()


def prompt_text(prompt: str, default: str = "", secret: bool = False) -> str:
    if default:
        suffix = " [saved]" if secret else f" [{default}]"
    else:
        suffix = ""
    value = getpass.getpass(f"{prompt}{suffix}: ") if secret else input(f"{prompt}{suffix}: ")
    return value.strip() or default


def prompt_bool(prompt: str, default: bool, timeout_seconds: int | None = None) -> bool:
    suffix = "Y/n" if default else "y/N"
    if timeout_seconds and timeout_seconds > 0:
        default_label = "yes" if default else "no"
        for remaining in range(timeout_seconds, 0, -1):
            print(
                f"\r{prompt} [{suffix}] (auto {default_label} in {remaining}s): ",
                end="",
                flush=True,
            )
            ready, _, _ = select.select([sys.stdin], [], [], 1)
            if ready:
                raw = sys.stdin.readline().strip().lower()
                print()
                if not raw:
                    return default
                return raw in {"y", "yes", "true", "1"}
        print()
        return default
    raw = input(f"{prompt} [{suffix}]: ").strip().lower()
    if not raw:
        return default
    return raw in {"y", "yes", "true", "1"}


def mask_secret(value: str, visible_tail: int = 4) -> str:
    text = value.strip()
    if not text:
        return ""
    if len(text) <= visible_tail:
        return "*" * len(text)
    return f"{'*' * (len(text) - visible_tail)}{text[-visible_tail:]}"


def render_saved_config_preview(values: dict[str, str]) -> None:
    print("[info] Saved configuration details:")
    shown_any = False
    for key in ENV_ORDER:
        if key not in values:
            continue
        shown_any = True
        value = values.get(key, "").strip()
        if key == "FALCON_CLIENT_SECRET":
            rendered = mask_secret(value)
        else:
            rendered = value or "(empty)"
        print(f"  {key}: {rendered}")
    if not shown_any:
        print("  (no saved values found)")
    print()


def prompt_report_range(default: str = DEFAULT_REPORT_RANGE) -> str:
    selected_default = default if default in REPORT_RANGE_CHOICES else DEFAULT_REPORT_RANGE
    print("Report time range presets:")
    default_index = REPORT_RANGE_CHOICES.index(selected_default) + 1
    for index, label in enumerate(REPORT_RANGE_CHOICES, start=1):
        print(f"{index}. {label}")
    raw = input(f"Choose preset number [default {default_index}]: ").strip()
    if not raw:
        return selected_default
    try:
        chosen = int(raw)
    except ValueError:
        return selected_default
    if 1 <= chosen <= len(REPORT_RANGE_CHOICES):
        return REPORT_RANGE_CHOICES[chosen - 1]
    return selected_default


def range_to_timedelta(range_label: str) -> timedelta:
    return REPORT_RANGE_TO_DELTA.get(range_label, REPORT_RANGE_TO_DELTA[DEFAULT_REPORT_RANGE])


def window_bounds(window: timedelta) -> tuple[datetime, datetime]:
    end_time = datetime.now(timezone.utc)
    start_time = end_time - window
    return start_time, end_time


def to_iso_z(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def window_filter(window: timedelta, field_name: str) -> str:
    start_time, end_time = window_bounds(window)
    return merge_filters(
        f"{field_name}:>='{to_iso_z(start_time)}'",
        f"{field_name}:<='{to_iso_z(end_time)}'",
    )


def env_quote(value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def parse_env_line(raw: str) -> tuple[str, str] | None:
    line = raw.strip()
    if not line or line.startswith("#") or "=" not in line:
        return None
    key, value = line.split("=", 1)
    key = key.strip()
    value = value.strip()
    if value.startswith('"') and value.endswith('"'):
        value = value[1:-1].replace('\\"', '"').replace("\\\\", "\\")
    return key, value


def load_env_file(path: Path) -> dict[str, str]:
    if not path.exists():
        return {}
    loaded: dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        parsed = parse_env_line(raw)
        if parsed:
            key, value = parsed
            loaded[key] = value
    return loaded


def write_env_file(path: Path, values: dict[str, str]) -> None:
    lines = ["# CrowdStrike Falcon report configuration"]
    for key in ENV_ORDER:
        lines.append(f"{key}={env_quote(values.get(key, ''))}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def coerce_bool(value: str) -> bool:
    return value.strip().lower() in {"1", "true", "yes", "y", "on"}


def merged_defaults(existing: dict[str, str]) -> dict[str, str]:
    merged = dict(DEFAULTS)
    merged.update(existing)
    return merged


def safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return default


def config_from_values(values: dict[str, str]) -> Config:
    missing = [
        key
        for key in ("FALCON_CLIENT_ID", "FALCON_CLIENT_SECRET")
        if not values.get(key, "").strip()
    ]
    if missing:
        raise ValueError(f"Missing required configuration values: {', '.join(missing)}")

    return Config(
        client_id=values["FALCON_CLIENT_ID"].strip(),
        client_secret=values["FALCON_CLIENT_SECRET"].strip(),
        base_url=values.get("FALCON_BASE_URL", "").strip(),
        member_cid="",
        lookback_days=7,
        include_hidden_alerts=False,
        max_detail_records=1000,
        detections_filter="",
        overwatch_analyzed_events_filter="",
        overwatch_hunting_leads_filter="",
        overwatch_triggered_detections_filter="",
        ngsiem_detections_filter="",
        ngsiem_detections_category_field="type",
        ngsiem_automated_leads_filter="",
        ngsiem_leads_confidence_field="confidence",
        ngsiem_leads_category_field="type",
    )


def prompt_for_config(env_path: Path, existing: dict[str, str] | None = None) -> Config:
    current = merged_defaults(existing or {})
    values = dict(current)
    values["FALCON_CLIENT_ID"] = prompt_text("FALCON_CLIENT_ID", current.get("FALCON_CLIENT_ID", ""))
    values["FALCON_CLIENT_SECRET"] = prompt_text(
        "FALCON_CLIENT_SECRET",
        current.get("FALCON_CLIENT_SECRET", ""),
        secret=True,
    )
    values["FALCON_BASE_URL"] = prompt_text(
        "FALCON_BASE_URL",
        current.get("FALCON_BASE_URL", DEFAULTS["FALCON_BASE_URL"]),
    )
    print("Writing configuration...", end=" ")
    write_env_file(env_path, values)
    print("done\n")
    return config_from_values(values)


def resolve_config(args: argparse.Namespace) -> Config:
    env_path = Path.cwd() / ".env"
    existing = load_env_file(env_path)
    if args.setup:
        return prompt_for_config(env_path, existing)
    if env_path.exists() and existing:
        print("[info] Found saved configuration...", end=" ", flush=True)
        print("done")
        render_saved_config_preview(existing)
        if prompt_bool("Update saved configuration", False, timeout_seconds=5):
            return prompt_for_config(env_path, existing)
        print("[info] Using saved configuration...", end=" ", flush=True)
        print("done")
        return config_from_values(merged_defaults(existing))
    print("No configuration found.\n")
    return prompt_for_config(env_path, existing)


def iso_date_range(config: Config) -> list[dict[str, str]]:
    return [{"from": config.start_iso, "to": config.end_iso}]


def build_client_kwargs(config: Config) -> dict[str, Any]:
    kwargs: dict[str, Any] = {
        "client_id": config.client_id,
        "client_secret": config.client_secret,
        "user_agent": "socdb-falcon-overview/0.01a",
    }
    if config.base_url:
        kwargs["base_url"] = config.base_url
    if config.member_cid:
        kwargs["member_cid"] = config.member_cid
    return kwargs


def build_date() -> str:
    timestamp = Path(__file__).stat().st_mtime
    return datetime.fromtimestamp(timestamp, tz=timezone.utc).strftime("%d.%m.%Y")


def print_banner() -> None:
    print("Welcome to Falcon Report")
    print(f"Version {VERSION} | Build date {build_date()}")
    print("This is not an official CrowdStrike tool.")
    print()


def merge_filters(*parts: str) -> str:
    cleaned = [part.strip() for part in parts if part and part.strip()]
    return "+".join(cleaned)


def time_filter_for_alerts(config: Config) -> str:
    return merge_filters(
        f"created_timestamp:>='{config.start_iso}'",
        f"created_timestamp:<='{config.end_iso}'",
    )


def chunked(values: list[str], size: int) -> Iterable[list[str]]:
    for index in range(0, len(values), size):
        yield values[index:index + size]


class CrowdStrikeAPI:
    CLOUD_ALIASES = {
        "us1": "https://api.crowdstrike.com",
        "us2": "https://api.us-2.crowdstrike.com",
        "eu1": "https://api.eu-1.crowdstrike.com",
        "usgov1": "https://api.laggar.gcw.crowdstrike.com",
        "usgov2": "https://api.us-gov-2.crowdstrike.mil",
    }

    def __init__(self, config: Config) -> None:
        kwargs = build_client_kwargs(config)
        self.client_id = str(kwargs["client_id"])
        self.client_secret = str(kwargs["client_secret"])
        self.user_agent = str(kwargs["user_agent"])
        self.member_cid = str(kwargs.get("member_cid", ""))
        self.base_url = self.resolve_base_url(str(kwargs.get("base_url", "")))
        self.token: str | None = None
        self.token_expiry = datetime.now(timezone.utc)
        self.ssl_context = self._build_ssl_context()
        self._ssl_warning_emitted = False

    def _build_ssl_context(self) -> ssl.SSLContext:
        explicit = os.environ.get("SSL_CERT_FILE", "").strip()
        if explicit and Path(explicit).is_file():
            return ssl.create_default_context(cafile=explicit)
        for candidate in (
            "/etc/ssl/cert.pem",
            "/private/etc/ssl/cert.pem",
            "/etc/ssl/certs/ca-certificates.crt",
            "/etc/pki/tls/certs/ca-bundle.crt",
        ):
            if Path(candidate).is_file():
                return ssl.create_default_context(cafile=candidate)
        return ssl.create_default_context()

    def resolve_base_url(self, configured: str) -> str:
        if not configured:
            return self.CLOUD_ALIASES["us1"]
        value = configured.strip()
        lowered = value.lower()
        if lowered in self.CLOUD_ALIASES:
            return self.CLOUD_ALIASES[lowered]
        if lowered.startswith("https://"):
            return value.rstrip("/")
        return f"https://{value.rstrip('/')}"

    def authenticate(self) -> None:
        body = {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
        }
        if self.member_cid:
            body["member_cid"] = self.member_cid
        request = urllib.request.Request(
            f"{self.base_url}/oauth2/token",
            data=urllib.parse.urlencode(body).encode("utf-8"),
            headers={
                "Accept": "application/json",
                "Content-Type": "application/x-www-form-urlencoded",
                "User-Agent": self.user_agent,
            },
            method="POST",
        )
        payload = self._send_json(request)
        access_token = payload.get("access_token")
        expires_in = safe_int(payload.get("expires_in", 1800), 1800)
        if not isinstance(access_token, str) or not access_token:
            raise RuntimeError("authentication failed: access token missing from response")
        self.token = access_token
        self.token_expiry = datetime.now(timezone.utc) + timedelta(seconds=max(60, expires_in - 120))

    def ensure_token(self) -> None:
        if self.token and datetime.now(timezone.utc) < self.token_expiry:
            return
        self.authenticate()

    def request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        body: dict[str, Any] | list[Any] | None = None,
        retry_on_unauthorized: bool = True,
    ) -> dict[str, Any]:
        self.ensure_token()
        query_string = ""
        if params:
            filtered = {
                key: value
                for key, value in params.items()
                if value is not None and value != ""
            }
            if filtered:
                query_string = "?" + urllib.parse.urlencode(filtered, doseq=True)

        headers = {
            "Accept": "application/json",
            "Authorization": f"Bearer {self.token}",
            "User-Agent": self.user_agent,
        }
        data = None
        if body is not None:
            headers["Content-Type"] = "application/json"
            data = json.dumps(body).encode("utf-8")

        request = urllib.request.Request(
            f"{self.base_url}{path}{query_string}",
            data=data,
            headers=headers,
            method=method.upper(),
        )
        try:
            return {"status_code": 200, "body": self._send_json(request)}
        except urllib.error.HTTPError as exc:
            if exc.code == 401 and retry_on_unauthorized:
                self.token = None
                self.authenticate()
                return self.request(
                    method,
                    path,
                    params=params,
                    body=body,
                    retry_on_unauthorized=False,
                )
            return {"status_code": exc.code, "body": self._decode_error_body(exc)}

    def _send_json(self, request: urllib.request.Request) -> dict[str, Any]:
        with self._urlopen(request) as response:
            raw = response.read().decode("utf-8")
        if not raw:
            return {}
        payload = json.loads(raw)
        return payload if isinstance(payload, dict) else {"resources": payload}

    def _urlopen(self, request: urllib.request.Request):
        try:
            return urllib.request.urlopen(request, timeout=60, context=self.ssl_context)
        except (urllib.error.URLError, ssl.SSLError) as exc:
            if not self._should_retry_without_ssl_verification(exc):
                raise
            if not self._ssl_warning_emitted:
                print(
                    "[warning] TLS certificate verification failed with the local Python trust store; retrying without certificate verification.",
                    file=sys.stderr,
                )
                self._ssl_warning_emitted = True
            insecure_context = ssl._create_unverified_context()
            return urllib.request.urlopen(request, timeout=60, context=insecure_context)

    def _should_retry_without_ssl_verification(self, exc: Exception) -> bool:
        reason = getattr(exc, "reason", exc)
        if isinstance(reason, ssl.SSLCertVerificationError):
            return True
        if isinstance(reason, ssl.SSLError):
            message = str(reason).lower()
            return (
                "certificate_verify_failed" in message
                or "unable to get local issuer certificate" in message
            )
        message = str(reason or exc)
        lowered = message.lower()
        return (
            "certificate_verify_failed" in lowered
            or "unable to get local issuer certificate" in lowered
        )

    def _decode_error_body(self, exc: urllib.error.HTTPError) -> dict[str, Any]:
        try:
            raw = exc.read().decode("utf-8")
        except Exception:
            raw = ""
        if not raw:
            return {"errors": [{"message": exc.reason or f"HTTP {exc.code}"}]}
        try:
            payload = json.loads(raw)
            return payload if isinstance(payload, dict) else {"errors": [{"message": raw}]}
        except json.JSONDecodeError:
            return {"errors": [{"message": raw}]}


def ensure_success(response: dict[str, Any], operation: str) -> None:
    status_code = safe_int(response.get("status_code", 500), 500)
    if 200 <= status_code < 300:
        return
    body = response.get("body")
    messages: list[str] = []
    if isinstance(body, dict):
        for error in body.get("errors", []):
            if isinstance(error, dict) and error.get("message"):
                messages.append(str(error["message"]))
    message = "; ".join(messages) if messages else f"HTTP {status_code}"
    raise RuntimeError(f"{operation} failed: {message}")


def get_resources(response: dict[str, Any]) -> list[Any]:
    body = response.get("body")
    if not isinstance(body, dict):
        return []
    resources = body.get("resources")
    if isinstance(resources, list):
        return resources
    if isinstance(resources, dict):
        return [resources]
    return []


def get_after_token(response: dict[str, Any]) -> str:
    body = response.get("body")
    if not isinstance(body, dict):
        return ""
    meta = body.get("meta")
    if isinstance(meta, dict):
        pagination = meta.get("pagination")
        if isinstance(pagination, dict):
            after = pagination.get("after")
            if isinstance(after, str):
                return after
    return ""


def walk_values(value: Any) -> Iterable[Any]:
    yield value
    if isinstance(value, dict):
        for nested in value.values():
            yield from walk_values(nested)
    elif isinstance(value, list):
        for nested in value:
            yield from walk_values(nested)


def find_numeric_candidates(value: Any, names: set[str]) -> list[float]:
    matches: list[float] = []
    if isinstance(value, dict):
        for key, nested in value.items():
            lowered = str(key).lower()
            if lowered in names and isinstance(nested, (int, float)):
                matches.append(float(nested))
            matches.extend(find_numeric_candidates(nested, names))
    elif isinstance(value, list):
        for nested in value:
            matches.extend(find_numeric_candidates(nested, names))
    return matches


def parse_totalish(response: dict[str, Any]) -> int:
    body = response.get("body")
    for value in walk_values(body):
        if not isinstance(value, dict):
            continue
        for key, nested in value.items():
            if str(key).lower() in {"count", "total", "total_count", "value"} and isinstance(nested, (int, float)):
                return int(nested)
    return 0


def parse_aggregate_counter(response: dict[str, Any]) -> Counter[str]:
    counter: Counter[str] = Counter()
    body = response.get("body")
    for value in walk_values(body):
        if not isinstance(value, dict):
            continue
        label = value.get("label")
        count = value.get("count")
        if label is not None and isinstance(count, (int, float)):
            counter[str(label)] += int(count)
            continue
        name = value.get("name")
        if isinstance(name, str) and isinstance(count, (int, float)):
            counter[name] += int(count)
            continue
        key = value.get("key")
        doc_count = value.get("doc_count")
        if key is not None and isinstance(doc_count, (int, float)):
            counter[str(key)] += int(doc_count)
    return counter


def friendly_category_label(value: Any) -> str:
    label = normalize_label(value)
    return CATEGORY_LABEL_MAP.get(label, label)


def classify_detection_category(record: dict[str, Any]) -> str:
    product = normalize_label(record.get("product"))
    if product == "thirdparty":
        raw = record.get("categorization")
        if isinstance(raw, list):
            text = " ".join(str(item).lower() for item in raw)
        else:
            text = str(raw).lower()
        if "malware-network-threat" in text:
            return "endpoint"
        if "network" in text:
            return "network"
        if "endpoint" in text:
            return "endpoint"
        if "identity" in text:
            return "identity"
        if "data-protection" in text or "data protection" in text:
            return "data protection"
        if "saas" in text:
            return "saas"
        return "other"
    if product == "epp":
        return "endpoint"
    if product == "idp":
        return "identity"
    if product == "data-protection":
        return "data protection"
    if product == "saas-security":
        return "saas"
    if product == "cwpp":
        return "cloud"
    if product.startswith("automated-lead"):
        return "automated leads"
    return "other"


def is_core_detection_record(record: dict[str, Any]) -> bool:
    return normalize_label(record.get("product")) in CORE_DETECTION_PRODUCTS


def normalize_label(value: Any) -> str:
    if value is None:
        return "unknown"
    text = str(value).strip().lower()
    return text or "unknown"


def normalize_severity_value(value: Any) -> str:
    if value is None or isinstance(value, bool):
        return "unknown"
    if isinstance(value, (int, float)):
        numeric = float(value)
        if numeric >= 90:
            return "critical"
        if numeric >= 70:
            return "high"
        if numeric >= 40:
            return "medium"
        if numeric >= 20:
            return "low"
        if numeric >= 0:
            return "informational"
        return "unknown"

    text = str(value).strip().lower()
    mapping = {
        "critical": "critical",
        "crit": "critical",
        "high": "high",
        "medium": "medium",
        "med": "medium",
        "low": "low",
        "informational": "informational",
        "info": "informational",
        "inform": "informational",
        "unknown": "unknown",
    }
    if text in mapping:
        return mapping[text]
    try:
        return normalize_severity_value(float(text))
    except ValueError:
        return text or "unknown"


def normalize_severity_counter(counter: Counter[str]) -> Counter[str]:
    normalized: Counter[str] = Counter()
    for key, value in counter.items():
        normalized[normalize_severity_value(key)] += int(value)
    return normalized


CONFIDENCE_BANDS = ["75-100", "50-74", "25-49", "1-24", "unknown"]


def confidence_band(value: Any) -> str:
    if value is None or isinstance(value, bool):
        return "unknown"
    try:
        numeric = float(value)
    except (TypeError, ValueError):
        return "unknown"
    if numeric <= 0:
        return "unknown"
    if numeric <= 24:
        return "1-24"
    if numeric <= 49:
        return "25-49"
    if numeric <= 74:
        return "50-74"
    return "75-100"


def parse_iso_timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def format_duration(seconds: float | int) -> str:
    total = max(0, int(seconds))
    days, remainder = divmod(total, 86400)
    hours, remainder = divmod(remainder, 3600)
    minutes, _ = divmod(remainder, 60)
    if days:
        return f"{days}d {hours}h {minutes}m"
    return f"{hours}h {minutes}m"


def average_unassigned_age_seconds(records: list[dict[str, Any]]) -> float | None:
    now = datetime.now(timezone.utc)
    ages: list[float] = []
    for record in records:
        created = parse_iso_timestamp(record.get("created_timestamp"))
        if created is None:
            continue
        ages.append(max(0.0, (now - created).total_seconds()))
    if not ages:
        return None
    return sum(ages) / len(ages)


def record_age_seconds(record: dict[str, Any]) -> float | None:
    created = parse_iso_timestamp(record.get("created_timestamp"))
    if created is None:
        return None
    return max(0.0, (datetime.now(timezone.utc) - created).total_seconds())


def is_unassigned_alert(record: dict[str, Any]) -> bool:
    for key in ("assigned_to", "assigned_to_uuid", "assigned_to_uid", "assignee"):
        value = record.get(key)
        if value not in (None, "", []):
            return False
    status = normalize_label(record.get("status"))
    if status in {"new", "open"}:
        return True
    if status in {"closed", "resolved", "in_progress", "in-progress", "triaged"}:
        return False
    return False


def is_unassigned_case(record: dict[str, Any]) -> bool:
    value = record.get("assigned_to")
    if value in (None, "", []):
        return True
    if isinstance(value, dict):
        if not any(value.get(key) for key in ("uuid", "email", "full_name", "user_uuid")):
            return True
    return False


def extract_field(record: dict[str, Any], field: str) -> Any:
    current: Any = record
    for part in field.split("."):
        if not isinstance(current, dict):
            return None
        current = current.get(part)
    return current


def summarise_records(
    records: list[dict[str, Any]],
    *,
    category_fields: list[str] | None = None,
    confidence_fields: list[str] | None = None,
    severity_fields: list[str] | None = None,
) -> dict[str, Counter[str]]:
    counters: dict[str, Counter[str]] = {
        "categories": Counter(),
        "confidence": Counter(),
        "severity": Counter(),
    }

    for record in records:
        if category_fields:
            for field in category_fields:
                value = extract_field(record, field)
                if value is not None:
                    counters["categories"][normalize_label(value)] += 1
                    break

        if confidence_fields:
            for field in confidence_fields:
                value = extract_field(record, field)
                if value is not None:
                    counters["confidence"][normalize_label(value)] += 1
                    break

        if severity_fields:
            for field in severity_fields:
                value = extract_field(record, field)
                if value is not None:
                    counters["severity"][normalize_severity_value(value)] += 1
                    break

    return counters


def case_severity_bucket(case_record: dict[str, Any]) -> str:
    for key in ("severity", "max_severity", "fine_score"):
        value = case_record.get(key)
        if value is not None:
            return normalize_severity_value(value)
    return "unknown"


def render_title(title: str) -> None:
    print(title)
    print("=" * len(title))


def render_kv(label: str, value: Any) -> None:
    print(f"{label:<24} {value}")


def render_note(message: str) -> None:
    print(f"[note] {message}")


def color_text(text: str, color_code: str) -> str:
    return f"{color_code}{text}{ANSI_RESET}"


def visible_length(text: str) -> int:
    return len(ANSI_PATTERN.sub("", text))


def ansi_align(text: str, width: int, align: str = "right") -> str:
    padding = max(0, width - visible_length(text))
    if align == "left":
        return text + (" " * padding)
    if align == "center":
        left = padding // 2
        right = padding - left
        return (" " * left) + text + (" " * right)
    return (" " * padding) + text


def format_avg_unassigned_age(age_seconds: float | None) -> str:
    if age_seconds is None:
        return "n/a"
    shown = format_duration(age_seconds)
    if age_seconds > 30 * 60:
        return color_text(shown, ANSI_RED)
    return shown


def bounded_display_age(age_seconds: float | None) -> float | None:
    if age_seconds is None:
        return None
    if age_seconds < 0:
        return None
    if age_seconds > MAX_DISPLAY_AGE_SECONDS:
        return None
    return age_seconds


def format_age_cell(age_seconds: float | None) -> str:
    if age_seconds is None:
        return "n/a"
    shown = format_duration(age_seconds)
    if age_seconds > 30 * 60:
        return color_text(shown, ANSI_RED)
    return shown


def format_age_minutes_cell(age_seconds: float | None) -> str:
    if age_seconds is None:
        return "n/a"
    minutes = max(0, int(round(age_seconds / 60.0)))
    shown = f"{minutes}m"
    if age_seconds > 30 * 60:
        return color_text(shown, ANSI_RED)
    return shown


def display_label(label: str) -> str:
    text = str(label).strip()
    if not text:
        return text
    if normalize_label(text) == "saas":
        return "SaaS"
    return text[:1].upper() + text[1:]


def matrix_category_label(category: str) -> str:
    mapping = {
        "network": "Net",
        "endpoint": "Endp",
        "identity": "Id",
        "data protection": "Data",
        "saas": "SaaS",
        "cloud": "Cloud",
        "automated leads": "Auto",
        "other": "Other",
    }
    return mapping.get(category, display_label(category))


def matrix_severity_label(severity: str) -> str:
    mapping = {
        "critical": "Crit",
        "high": "High",
        "medium": "Med",
        "low": "Low",
        "informational": "Inf",
        "unknown": "Unk",
    }
    return mapping.get(severity, display_label(severity))


def severity_css_class(label: str) -> str:
    normalized = normalize_label(label)
    if normalized in {"critical", "crit"}:
        return "sev-critical"
    if normalized == "high":
        return "sev-high"
    if normalized in {"medium", "med"}:
        return "sev-medium"
    if normalized == "low":
        return "sev-low"
    if normalized in {"informational", "inf", "info", "inform"}:
        return "sev-informational"
    return ""


def extract_named_string_candidates(item: Any, keys: set[str], found: list[str]) -> None:
    if isinstance(item, dict):
        for key, value in item.items():
            key_name = str(key).strip().lower()
            if key_name in keys and isinstance(value, str):
                cleaned = value.strip()
                if cleaned:
                    found.append(cleaned)
            extract_named_string_candidates(value, keys, found)
        return
    if isinstance(item, list):
        for value in item:
            extract_named_string_candidates(value, keys, found)


def extract_all_string_candidates(item: Any, found: list[str]) -> None:
    if isinstance(item, dict):
        for value in item.values():
            extract_all_string_candidates(value, found)
        return
    if isinstance(item, list):
        for value in item:
            extract_all_string_candidates(value, found)
        return
    if isinstance(item, str):
        cleaned = item.strip()
        if cleaned:
            found.append(cleaned)


def extract_cid_candidates(item: Any, found: list[str]) -> None:
    if isinstance(item, dict):
        for key, value in item.items():
            key_name = str(key).strip().lower()
            if key_name in {"cid", "origin_cid", "customer_id", "tenant_id"} and isinstance(value, str):
                text = value.strip().lower()
                if re.fullmatch(r"[0-9a-f]{16,64}", text):
                    found.append(text)
            extract_cid_candidates(value, found)
        return
    if isinstance(item, list):
        for value in item:
            extract_cid_candidates(value, found)


def infer_cid_value(config: Config, *datasets: list[dict[str, Any]]) -> str:
    candidates: list[str] = []
    for dataset in datasets:
        extract_cid_candidates(dataset, candidates)
    if candidates:
        ranked = sorted(Counter(candidates).items(), key=lambda item: (-item[1], item[0]))
        return ranked[0][0]
    member = config.member_cid.strip().lower()
    if re.fullmatch(r"[0-9a-f]{16,64}", member):
        return member
    return "unknown"


def infer_cid_name(config: Config, *datasets: list[dict[str, Any]]) -> str:
    preferred_keys = {
        "cid_name",
        "customer_name",
        "tenant_name",
        "cid_display_name",
        "display_name",
        "organization_name",
        "org_name",
    }
    candidates: list[str] = []
    for dataset in datasets:
        extract_named_string_candidates(dataset, preferred_keys, candidates)

    filtered = [
        value
        for value in candidates
        if any(ch.isalpha() for ch in value)
        and len(value) <= 120
        and normalize_label(value) not in {"unknown", "none", "n/a"}
    ]
    if filtered:
        def sanitize_name(value: str) -> str:
            # Normalize connector-style labels such as "AV-Server-to-AVEMO-GROUP".
            match = re.search(r"-to-([a-z0-9]+)-group", value, flags=re.IGNORECASE)
            if match:
                return match.group(1).upper()
            if re.search(r"\b[a-z0-9-]+\.avemo-group\.net\b", value, flags=re.IGNORECASE):
                return "AVEMO"
            return value

        def is_technical_label(value: str) -> bool:
            lowered = value.lower()
            if "@" in lowered:
                return True
            if re.search(r"\b[a-z0-9-]+\.[a-z]{2,}\b", lowered):
                return True
            if value.count(".") >= 2 and " " not in value:
                return True
            return any(token in lowered for token in ("server", "workstation", "host", "-to-", "group"))

        def has_company_suffix(value: str) -> bool:
            return bool(
                re.search(
                    r"\b(inc\.?|corp\.?|corporation|llc|ltd\.?|limited|gmbh|ag|bv|nv|oy|ab|sas|sarl|s\.r\.l\.?|s\.p\.a\.?|s\.a\.?|co\.?\s*kg|kg)\b",
                    value,
                    flags=re.IGNORECASE,
                )
            )

        legal_name_candidates = [
            (value, count)
            for value, count in Counter(filtered).items()
            if has_company_suffix(value) and not is_technical_label(value)
        ]
        if legal_name_candidates:
            legal_ranked = sorted(
                legal_name_candidates,
                key=lambda item: (-item[1], -len(item[0]), item[0].lower()),
            )
            return sanitize_name(legal_ranked[0][0])

        avemo_name_candidates = [
            (value, count)
            for value, count in Counter(filtered).items()
            if "avemo" in value.lower() and not is_technical_label(value)
        ]
        if avemo_name_candidates:
            avemo_ranked = sorted(
                avemo_name_candidates,
                key=lambda item: (-item[1], -len(item[0]), item[0].lower()),
            )
            return sanitize_name(avemo_ranked[0][0])

        def rank_name(value: str, count: int) -> tuple[int, int, str]:
            lowered = value.lower()
            hostish_penalty = 1 if any(token in lowered for token in ("server", "workstation", "host", "-to-", "group")) else 0
            avemo_bonus = 0 if "avemo" in lowered else 1
            return (hostish_penalty + avemo_bonus, -count, lowered)

        ranked = sorted(
            Counter(filtered).items(),
            key=lambda item: rank_name(item[0], item[1]),
        )
        return sanitize_name(ranked[0][0])

    parsed_host = urllib.parse.urlparse(config.base_url).hostname or ""
    if parsed_host:
        return parsed_host
    if config.member_cid:
        return config.member_cid
    return "unknown"


def categories_for_records(core_records: list[dict[str, Any]]) -> list[str]:
    counts = detections_category_counter(core_records)
    return [label for label in CATEGORY_ORDER if counts.get(label, 0)]


def matrix_payload_for_categories(
    core_records: list[dict[str, Any]],
    categories: list[str],
) -> tuple[dict[str, Counter[str]], list[str]]:
    per_category: dict[str, Counter[str]] = {
        category: severity_counter_for_category(core_records, category)
        for category in categories
    }
    severity_rows = ["critical", "high", "medium", "low", "informational"]
    if any(per_category[category].get("unknown", 0) for category in categories):
        severity_rows.append("unknown")
    return per_category, severity_rows


def render_counter(title: str, counter: Counter[str], preferred_order: list[str] | None = None) -> None:
    render_title(title)
    if not counter:
        print("No data\n")
        return

    maximum = max(counter.values()) if counter else 0
    ordered: list[str] = []
    if preferred_order:
        ordered.extend([label for label in preferred_order if counter.get(label)])
    ordered.extend(
        sorted(
            [label for label in counter.keys() if label not in ordered],
            key=lambda label: (-counter[label], label),
        )
    )
    total = sum(counter.values())
    for label in ordered:
        value = counter[label]
        bar_length = 0 if maximum == 0 else max(1, math.ceil((value / maximum) * 24))
        bar = "#" * bar_length
        pct = (value / total * 100.0) if total else 0.0
        shown = display_label(label)
        print(f"{shown:<16} {value:>6}  {bar}  {pct:>5.1f}%")
    print()


def run_with_spinner(label: str, task) -> Any:
    frames = ["|", "/", "-", "\\"]
    done = threading.Event()

    def spin() -> None:
        index = 0
        while not done.is_set():
            print(f"\r{label} {frames[index % len(frames)]}", end="", flush=True)
            time.sleep(0.1)
            index += 1

    thread = threading.Thread(target=spin, daemon=True)
    thread.start()
    try:
        result = task()
    finally:
        done.set()
        thread.join(timeout=1.0)
    print(f"\r{label} done")
    return result


def gather_data(config: Config, report_window: timedelta) -> GatheredData:
    client = FalconOverviewClient(config)
    records_365d = client.fetch_alert_records_for_window(AGE_CHART_WINDOW, config.detections_filter)
    if report_window >= AGE_CHART_WINDOW:
        records = list(records_365d)
    else:
        start_time, end_time = window_bounds(report_window)
        records = []
        for record in records_365d:
            created = parse_iso_timestamp(record.get("created_timestamp"))
            if created is None:
                continue
            if start_time <= created <= end_time:
                records.append(record)
    core_records = [record for record in records if is_core_detection_record(record)]
    core_records_365d = [record for record in records_365d if is_core_detection_record(record)]
    leads = [
        record
        for record in records
        if isinstance(record, dict) and normalize_label(record.get("product")) == "automated-lead"
    ]
    leads_365d = [
        record
        for record in records_365d
        if isinstance(record, dict) and normalize_label(record.get("product")) == "automated-lead"
    ]
    cases = client.fetch_cases_for_window(report_window)
    cases_365d = client.fetch_cases_for_window(AGE_CHART_WINDOW)
    overwatch = fetch_overwatch_summary(config, report_window)
    cid = infer_cid_value(config, records_365d, cases_365d, leads_365d)
    cid_name = infer_cid_name(config, records_365d, cases_365d, leads_365d)
    return GatheredData(
        core_records=core_records,
        core_records_365d=core_records_365d,
        cases=cases,
        cases_365d=cases_365d,
        leads=leads,
        leads_365d=leads_365d,
        overwatch=overwatch,
        cid_name=cid_name,
        cid=cid,
    )


def gathering_spinner(seconds: float = 1.0) -> None:
    frames = ["|", "/", "-", "\\"]
    deadline = time.monotonic() + max(0.1, seconds)
    index = 0
    while time.monotonic() < deadline:
        print(f"\rGathering data ... {frames[index % len(frames)]}", end="", flush=True)
        time.sleep(0.1)
        index += 1
    print("\rGathering data ... done")


def detections_category_counter(core_records: list[dict[str, Any]]) -> Counter[str]:
    counter: Counter[str] = Counter()
    for record in core_records:
        label = classify_detection_category(record)
        if label in {"cloud", "automated leads"}:
            continue
        counter[label] += 1
    return counter


def severity_counter_for_category(core_records: list[dict[str, Any]], category: str) -> Counter[str]:
    counter: Counter[str] = Counter()
    for record in core_records:
        if classify_detection_category(record) != category:
            continue
        severity_value = record.get("severity_name")
        if severity_value is None:
            severity_value = record.get("severity")
        counter[normalize_severity_value(severity_value)] += 1
    return counter


def render_category_details(core_records: list[dict[str, Any]], category: str) -> None:
    severity = severity_counter_for_category(core_records, category)
    render_title(f"Detections Details - {display_label(category)}")
    print()
    render_kv("Total detections", sum(severity.values()))
    print()
    render_counter("Detections by Severity", severity, SEVERITY_LABELS)


def render_all_categories_details(core_records: list[dict[str, Any]], categories: list[str]) -> None:
    for index, category in enumerate(categories):
        render_category_details(core_records, category)
        if index < len(categories) - 1:
            print()


def render_categories_severity_matrix(core_records: list[dict[str, Any]], categories: list[str]) -> None:
    per_category, severity_rows = matrix_payload_for_categories(core_records, categories)

    headers = [display_label(category) for category in categories]
    row_label_width = max(len("Severity"), max(len(display_label(row)) for row in severity_rows))
    col_widths = [
        max(len(header), len(str(max(per_category[category].values() or [0]))), 3)
        for header, category in zip(headers, categories)
    ]

    render_title("Detections Severity Matrix (All Categories)")
    print()

    header_line = f"{'Severity':<{row_label_width}}  "
    header_line += "  ".join(f"{header:>{width}}" for header, width in zip(headers, col_widths))
    print(header_line)
    print("-" * len(header_line))

    for severity in severity_rows:
        values = [per_category[category].get(severity, 0) for category in categories]
        row = f"{display_label(severity):<{row_label_width}}  "
        row += "  ".join(f"{value:>{width}}" for value, width in zip(values, col_widths))
        print(row)
    print()


def render_avg_unassigned_age_matrix(
    core_records: list[dict[str, Any]],
    categories: list[str],
    category_label: str = "Category",
    title_suffix: str = "",
) -> None:
    age_buckets: dict[str, dict[str, list[float]]] = {
        category: {severity: [] for severity in SEVERITY_LABELS}
        for category in categories
    }
    for record in core_records:
        if not is_unassigned_alert(record):
            continue
        category = classify_detection_category(record)
        if category not in age_buckets:
            continue
        severity = normalize_severity_value(
            record.get("severity_name") if record.get("severity_name") is not None else record.get("severity")
        )
        age_seconds = record_age_seconds(record)
        if age_seconds is None:
            continue
        age_buckets[category].setdefault(severity, []).append(age_seconds)

    severity_columns = ["critical", "high", "medium", "low", "informational"]
    if any(age_buckets[category].get("unknown") for category in categories):
        severity_columns.append("unknown")

    per_category_average: dict[str, dict[str, float | None]] = {
        category: {
            severity: (sum(values) / len(values) if values else None)
            for severity, values in buckets.items()
        }
        for category, buckets in age_buckets.items()
    }

    headers = [matrix_severity_label(severity) for severity in severity_columns]
    row_values = [display_label(category) for category in categories]
    row_label_width = max(len(category_label), max(len(value) for value in row_values)) + 2
    cell_samples = [
        [format_age_minutes_cell(per_category_average[category].get(severity)) for severity in severity_columns]
        for category in categories
    ]
    col_widths = [
        max(len(header), max((visible_length(row[index]) for row in cell_samples), default=0), 4) + 1
        for index, header in enumerate(headers)
    ]
    gap = "  "

    render_title(f"Avg Unassigned Age by Category and Severity{title_suffix}")
    print()

    header_line = f"{category_label:<{row_label_width}}{gap}"
    header_line += gap.join(f"{header:^{width}}" for header, width in zip(headers, col_widths))
    print(header_line)
    print("-" * len(header_line))

    for category in categories:
        row = f"{display_label(category):<{row_label_width}}{gap}"
        values = [per_category_average[category].get(severity) for severity in severity_columns]
        row += gap.join(ansi_align(format_age_minutes_cell(value), width, "right") for value, width in zip(values, col_widths))
        print(row)
    print()


def render_detection_age_range_by_category_severity(core_records: list[dict[str, Any]], title_suffix: str = "") -> None:
    grouped_ages: dict[tuple[str, str], list[float]] = {}
    for record in core_records:
        category = classify_detection_category(record)
        severity_raw = record.get("severity_name") if record.get("severity_name") is not None else record.get("severity")
        severity = normalize_severity_value(severity_raw)
        age_seconds = record_age_seconds(record)
        if age_seconds is None:
            continue
        key = (category, severity)
        grouped_ages.setdefault(key, []).append(age_seconds)

    if not grouped_ages:
        render_title(f"Detection Age Range by Category and Severity{title_suffix}")
        print("No detection age data\n")
        return

    category_rank = {label: index for index, label in enumerate(CATEGORY_ORDER)}
    severity_rank = {label: index for index, label in enumerate(SEVERITY_LABELS)}

    sorted_keys = sorted(
        grouped_ages.keys(),
        key=lambda key: (
            category_rank.get(key[0], len(CATEGORY_ORDER)),
            key[0],
            severity_rank.get(key[1], len(SEVERITY_LABELS)),
            key[1],
        ),
    )

    rows: list[tuple[str, float, float]] = []
    for category, severity in sorted_keys:
        ages = grouped_ages[(category, severity)]
        newest = min(ages)
        oldest = max(ages)
        rows.append((f"{display_label(category)} {display_label(severity)}", newest, oldest))

    max_age = max(oldest for _, _, oldest in rows)
    chart_width = 36
    y_label_width = max(len("Category Severity"), max(len(label) for label, _, _ in rows))

    render_title(f"Detection Age Range by Category and Severity{title_suffix}")
    print()
    print(f"{'Category Severity':<{y_label_width}}  {'Age Range (newest -> oldest)':<{chart_width}}  Newest    Oldest")
    print("-" * (y_label_width + 2 + chart_width + 2 + len("Newest    Oldest")))

    for label, newest, oldest in rows:
        if max_age <= 0:
            newest_pos = 0
            oldest_pos = 0
        else:
            newest_pos = int(round((newest / max_age) * (chart_width - 1)))
            oldest_pos = int(round((oldest / max_age) * (chart_width - 1)))
            newest_pos = max(0, min(chart_width - 1, newest_pos))
            oldest_pos = max(0, min(chart_width - 1, oldest_pos))

        chars = [" "] * chart_width
        if newest_pos == oldest_pos:
            chars[newest_pos] = "*"
        else:
            left = min(newest_pos, oldest_pos)
            right = max(newest_pos, oldest_pos)
            for index in range(left + 1, right):
                chars[index] = "-"
            chars[newest_pos] = "N"
            chars[oldest_pos] = "O"

        range_bar = "".join(chars)
        newest_text = ansi_align(format_age_cell(newest), 8, "right")
        oldest_text = ansi_align(format_age_cell(oldest), 8, "right")
        print(f"{label:<{y_label_width}}  {range_bar}  {newest_text}  {oldest_text}")
    print()


def details_menu(core_records: list[dict[str, Any]]) -> str:
    categories = categories_for_records(core_records)
    if not categories:
        answer = input("No category details available. Start over? [y/N]: ").strip().lower()
        return "restart" if answer in {"y", "yes"} else "quit"

    while True:
        print("Would you like to see more details about:")
        all_option = 1
        print(f"{all_option}. All categories")
        for index, label in enumerate(categories, start=2):
            print(f"{index}. {display_label(label)}")
        restart_option = len(categories) + 2
        quit_option = len(categories) + 3
        print(f"{restart_option}. Start over")
        print(f"{quit_option}. Quit")
        raw = input(f"Press a number to select an item [{all_option}]: ").strip()
        if not raw:
            choice = all_option
        else:
            try:
                choice = int(raw)
            except ValueError:
                print("Invalid choice. Please enter a number.")
                continue

        if choice == restart_option:
            return "restart"
        if choice == quit_option:
            return "quit"
        if choice == all_option:
            print()
            render_categories_severity_matrix(core_records, categories)
            continue
        if not (2 <= choice <= len(categories) + 1):
            print("Invalid choice. Please enter a number from the list.")
            continue

        selected = categories[choice - 2]
        render_category_details(core_records, selected)


class FalconOverviewClient:
    def __init__(self, config: Config) -> None:
        self.config = config
        self.api = CrowdStrikeAPI(config)

    def run_preflight_checks(self) -> PreflightReport:
        checks: list[PreflightCheck] = []

        def check_request(
            name: str,
            required: bool,
            method: str,
            path: str,
            *,
            params: dict[str, Any] | None = None,
            body: dict[str, Any] | list[Any] | None = None,
        ) -> dict[str, Any] | None:
            try:
                response = self.api.request(method, path, params=params, body=body)
                ensure_success(response, name)
                checks.append(PreflightCheck(name=name, required=required, ok=True))
                return response
            except Exception as exc:
                checks.append(PreflightCheck(name=name, required=required, ok=False, detail=str(exc)))
                return None

        check_request(
            "alerts.read (query)",
            True,
            "GET",
            "/alerts/queries/alerts/v2",
            params={"limit": 1, "sort": "created_timestamp.desc"},
        )
        check_request(
            "alerts.read (combined)",
            True,
            "POST",
            "/alerts/combined/alerts/v1",
            body={
                "limit": 1,
                "sort": "created_timestamp.desc",
                "filter": window_filter(timedelta(days=1), "created_timestamp"),
            },
        )
        check_request(
            "alerts.read (aggregate)",
            True,
            "POST",
            "/alerts/aggregates/alerts/v2",
            params={"include_hidden": "true"},
            body=[
                {
                    "field": "product",
                    "filter": window_filter(timedelta(days=1), "created_timestamp"),
                    "type": "terms",
                    "size": 5,
                    "sort": "_count|desc",
                }
            ],
        )

        cases_query = check_request(
            "cases.read (query)",
            True,
            "GET",
            "/cases/queries/cases/v1",
            params={
                "offset": 0,
                "limit": 1,
                "sort": "status.desc",
                "filter": window_filter(timedelta(days=30), "created_timestamp"),
            },
        )
        if cases_query is not None:
            ids = [value for value in get_resources(cases_query) if isinstance(value, str)]
            if ids:
                check_request(
                    "cases.read (entities)",
                    True,
                    "POST",
                    "/cases/entities/cases/v2",
                    body={"ids": ids[:1]},
                )
            else:
                checks.append(
                    PreflightCheck(
                        name="cases.read (entities)",
                        required=True,
                        ok=True,
                        detail="no recent case IDs in window; entity call skipped",
                    )
                )

        check_request(
            "falcon_complete_dashboard (ow events)",
            False,
            "GET",
            "/overwatch-dashboards/aggregates/ow-events-global-counts/v1",
            params={"filter": None},
        )
        check_request(
            "falcon_complete_dashboard (ow detections)",
            False,
            "GET",
            "/overwatch-dashboards/aggregates/detections-global-counts/v1",
            params={"filter": None},
        )

        return PreflightReport(checks=checks)

    def aggregate_alert_terms(self, field: str, filter_value: str = "") -> Counter[str]:
        response = self.api.request(
            "POST",
            "/alerts/aggregates/alerts/v2",
            params={"include_hidden": str(self.config.include_hidden_alerts).lower()},
            body=[
                {
                    "field": field,
                    "filter": merge_filters(filter_value, time_filter_for_alerts(self.config)),
                    "type": "terms",
                    "size": 25,
                    "sort": "_count|desc",
                }
            ],
        )
        ensure_success(response, f"alert aggregate for {field}")
        return parse_aggregate_counter(response)

    def aggregate_alert_terms_with_days(self, field: str, days: int, filter_value: str = "") -> Counter[str]:
        scoped = replace(self.config, lookback_days=max(1, days))
        response = self.api.request(
            "POST",
            "/alerts/aggregates/alerts/v2",
            params={"include_hidden": str(self.config.include_hidden_alerts).lower()},
            body=[
                {
                    "field": field,
                    "filter": merge_filters(filter_value, time_filter_for_alerts(scoped)),
                    "type": "terms",
                    "size": 200,
                    "sort": "_count|desc",
                }
            ],
        )
        ensure_success(response, f"alert aggregate for {field}")
        return parse_aggregate_counter(response)

    def aggregate_alert_terms_for_days(
        self,
        field: str,
        days: int,
        filter_value: str = "",
        include_hidden: bool | None = None,
    ) -> Counter[str]:
        scoped = replace(self.config, lookback_days=max(1, days))
        hidden_value = self.config.include_hidden_alerts if include_hidden is None else include_hidden
        response = self.api.request(
            "POST",
            "/alerts/aggregates/alerts/v2",
            params={"include_hidden": str(hidden_value).lower()},
            body=[
                {
                    "field": field,
                    "filter": merge_filters(filter_value, time_filter_for_alerts(scoped)),
                    "type": "terms",
                    "size": 200,
                    "sort": "_count|desc",
                }
            ],
        )
        ensure_success(response, f"alert aggregate for {field}")
        return parse_aggregate_counter(response)

    def aggregate_alert_terms_for_window(
        self,
        field: str,
        report_window: timedelta,
        filter_value: str = "",
        include_hidden: bool | None = None,
    ) -> Counter[str]:
        hidden_value = self.config.include_hidden_alerts if include_hidden is None else include_hidden
        response = self.api.request(
            "POST",
            "/alerts/aggregates/alerts/v2",
            params={"include_hidden": str(hidden_value).lower()},
            body=[
                {
                    "field": field,
                    "filter": merge_filters(filter_value, window_filter(report_window, "created_timestamp")),
                    "type": "terms",
                    "size": 200,
                    "sort": "_count|desc",
                }
            ],
        )
        ensure_success(response, f"alert aggregate for {field}")
        return parse_aggregate_counter(response)

    def fetch_alert_records_for_window(self, report_window: timedelta, filter_value: str = "") -> list[dict[str, Any]]:
        time_filter = window_filter(report_window, "created_timestamp")
        results: list[dict[str, Any]] = []
        after = ""
        while True:
            body: dict[str, Any] = {
                "filter": merge_filters(filter_value, time_filter),
                "limit": 500,
                "sort": "created_timestamp.desc",
            }
            if after:
                body["after"] = after
            response = self.api.request(
                "POST",
                "/alerts/combined/alerts/v1",
                body=body,
            )
            ensure_success(response, "combined alerts")
            resources = get_resources(response)
            if not resources:
                break
            for item in resources:
                if isinstance(item, dict):
                    results.append(item)
            after = get_after_token(response)
            if not after:
                break
        return results

    def alerts_total_for_window(self, report_window: timedelta, filter_value: str = "", include_hidden: bool = True) -> int:
        response = self.api.request(
            "GET",
            "/alerts/queries/alerts/v2",
            params={
                "include_hidden": str(include_hidden).lower(),
                "limit": 1,
                "sort": "created_timestamp.desc",
                "filter": merge_filters(filter_value, window_filter(report_window, "created_timestamp")),
            },
        )
        ensure_success(response, "alerts total query")
        body = response.get("body") if isinstance(response, dict) else None
        if isinstance(body, dict):
            meta = body.get("meta")
            if isinstance(meta, dict):
                pagination = meta.get("pagination")
                if isinstance(pagination, dict):
                    total = pagination.get("total")
                    if total is not None:
                        return safe_int(total, 0)
        return 0

    def fetch_alert_records(self, filter_value: str, max_records: int) -> tuple[list[dict[str, Any]], bool]:
        results: list[dict[str, Any]] = []
        after = ""
        truncated = False
        while len(results) < max_records:
            response = self.api.request(
                "POST",
                "/alerts/combined/alerts/v1",
                body={
                    "after": after or None,
                    "filter": merge_filters(filter_value, time_filter_for_alerts(self.config)),
                    "limit": min(500, max_records - len(results)),
                    "sort": "created_timestamp.desc",
                },
            )
            ensure_success(response, "combined alerts")
            resources = get_resources(response)
            if not resources:
                break
            for item in resources:
                if isinstance(item, dict):
                    results.append(item)
            after = get_after_token(response)
            if not after:
                break
        if after:
            truncated = True
        return results, truncated

    def query_case_ids_for_window(self, report_window: timedelta) -> list[str]:
        case_ids: list[str] = []
        offset = 0
        page_size = 500
        filter_value = window_filter(report_window, "created_timestamp")
        while True:
            response = self.api.request(
                "GET",
                "/cases/queries/cases/v1",
                params={
                    "offset": offset,
                    "limit": page_size,
                    "sort": "status.desc",
                    "filter": filter_value,
                },
            )
            ensure_success(response, "case query")
            page_ids = [value for value in get_resources(response) if isinstance(value, str)]
            if not page_ids:
                break
            case_ids.extend(page_ids)
            if len(page_ids) < page_size:
                break
            offset += page_size
        return case_ids

    def fetch_cases_for_window(self, report_window: timedelta) -> list[dict[str, Any]]:
        case_ids = self.query_case_ids_for_window(report_window)
        details: list[dict[str, Any]] = []
        for batch in chunked(case_ids, 100):
            response = self.api.request(
                "POST",
                "/cases/entities/cases/v2",
                body={"ids": batch},
            )
            ensure_success(response, "case details")
            for item in get_resources(response):
                if isinstance(item, dict):
                    details.append(item)
        return details

    def overwatch_events_count(self, filter_value: str) -> int:
        response = self.api.request(
            "GET",
            "/overwatch-dashboards/aggregates/ow-events-global-counts/v1",
            params={"filter": filter_value or None},
        )
        ensure_success(response, "overwatch events count")
        return parse_totalish(response)

    def overwatch_detections_count(self, filter_value: str) -> int:
        response = self.api.request(
            "GET",
            "/overwatch-dashboards/aggregates/detections-global-counts/v1",
            params={"filter": filter_value or None},
        )
        ensure_success(response, "overwatch detections count")
        return parse_totalish(response)

def fetch_overwatch_metrics(config: Config, report_window: timedelta, range_label: str) -> list[OverwatchMetric]:
    client = FalconOverviewClient(config)
    results: list[OverwatchMetric] = []

    try:
        analyzed = client.overwatch_events_count(config.overwatch_analyzed_events_filter)
        results.append(
            OverwatchMetric(
                label="OverWatch analyzed events",
                value=analyzed,
                source="overwatch-dashboards ow-events-global-counts",
            )
        )
    except Exception as exc:
        try:
            query_total = client.alerts_total_for_window(AGE_CHART_WINDOW, "", include_hidden=True)
            results.append(
                OverwatchMetric(
                    label="OverWatch analyzed events",
                    value=query_total,
                    source="alerts query total fallback (365d include_hidden=true)",
                    note=f"primary endpoint unavailable: {exc}",
                )
            )
        except Exception as query_exc:
            try:
                fallback = client.aggregate_alert_terms_for_window(
                    "product",
                    AGE_CHART_WINDOW,
                    "",
                    include_hidden=True,
                )
                results.append(
                    OverwatchMetric(
                        label="OverWatch analyzed events",
                        value=sum(fallback.values()),
                        source="alerts aggregate fallback (365d all products)",
                        note=f"primary endpoint unavailable: {exc}; query fallback unavailable: {query_exc}",
                    )
                )
            except Exception as fallback_exc:
                results.append(
                    OverwatchMetric(
                        label="OverWatch analyzed events",
                        value=None,
                        source="unavailable",
                        note=f"primary endpoint unavailable: {exc}; fallback failed: {fallback_exc}",
                    )
                )

    try:
        hunting = client.aggregate_alert_terms_for_window(
            "product",
            AGE_CHART_WINDOW,
            config.overwatch_hunting_leads_filter,
            include_hidden=True,
        )
        leads = hunting.get("overwatch", 0)
        results.append(
            OverwatchMetric(
                label="OverWatch endpoint hunting leads",
                value=leads,
                source=f"alerts aggregate product=overwatch ({range_label})",
            )
        )
    except Exception as exc:
        results.append(
            OverwatchMetric(
                label="OverWatch endpoint hunting leads",
                value=None,
                source="unavailable",
                note=str(exc),
            )
        )

    try:
        detections = client.overwatch_detections_count(config.overwatch_triggered_detections_filter)
        results.append(
            OverwatchMetric(
                label="OverWatch detections triggered",
                value=detections,
                source="overwatch-dashboards detections-global-counts",
            )
        )
    except Exception as exc:
        results.append(
            OverwatchMetric(
                label="OverWatch detections triggered",
                value=None,
                source="unavailable",
                note=str(exc),
            )
        )

    return results


def fetch_overwatch_summary(config: Config, report_window: timedelta) -> OverwatchSummary:
    range_label = next(
        (label for label, delta in REPORT_RANGE_TO_DELTA.items() if delta == report_window),
        DEFAULT_REPORT_RANGE,
    )
    metrics = fetch_overwatch_metrics(config, report_window, range_label)
    analyzed: int | None = None
    leads: int | None = None
    detections: int | None = None
    analyzed_source = ""
    leads_source = ""
    detections_source = ""
    for metric in metrics:
        lowered = metric.label.lower()
        if "analyzed events" in lowered:
            analyzed = metric.value
            analyzed_source = metric.source
        elif "endpoint hunting leads" in lowered:
            leads = metric.value
            leads_source = metric.source
        elif "detections triggered" in lowered:
            detections = metric.value
            detections_source = metric.source

    return OverwatchSummary(
        analyzed_events=analyzed,
        endpoint_hunting_leads=leads,
        detections=detections,
        analyzed_source=analyzed_source,
        endpoint_hunting_leads_source=leads_source,
        detections_source=detections_source,
    )


def prompt_selected_report_range(default: str = DEFAULT_REPORT_RANGE) -> str:
    return prompt_report_range(default)


def render_category_counter(title: str, counter: Counter[str]) -> None:
    render_counter(title, counter)


def render_cases_section(range_label: str, cases: list[dict[str, Any]]) -> None:
    render_title(f"Cases - Last {range_label}")
    severity = Counter()
    for case in cases:
        severity[case_severity_bucket(case)] += 1
    unassigned_cases = [case for case in cases if is_unassigned_case(case)]
    render_kv("Cases", sum(severity.values()))
    render_kv("Unassigned cases", len(unassigned_cases))
    avg_unassigned = average_unassigned_age_seconds(unassigned_cases)
    render_kv(
        "Avg unassigned age",
        format_avg_unassigned_age(avg_unassigned),
    )
    print()
    render_counter("Cases by Severity", severity, SEVERITY_LABELS)


def render_automated_leads_section(leads: list[dict[str, Any]]) -> None:
    render_title("Automated Leads - Last 365d")
    confidence: Counter[str] = Counter()
    for record in leads:
        confidence[confidence_band(record.get("score"))] += 1
    render_kv("Total automated leads (365d)", len(leads))
    unassigned_leads = [record for record in leads if is_unassigned_alert(record)]
    render_kv("Unassigned leads (365d)", len(unassigned_leads))
    avg_unassigned = average_unassigned_age_seconds(unassigned_leads)
    render_kv(
        "Avg unassigned age (365d)",
        format_avg_unassigned_age(avg_unassigned),
    )
    print()
    render_counter("Automated Leads by Confidence (365d)", confidence, CONFIDENCE_BANDS)


def render_overwatch_summary(summary: OverwatchSummary, range_label: str) -> None:
    render_title("OverWatch")
    analyzed = str(summary.analyzed_events) if summary.analyzed_events is not None else "n/a"
    leads = str(summary.endpoint_hunting_leads) if summary.endpoint_hunting_leads is not None else "n/a"
    detections = str(summary.detections) if summary.detections is not None else "n/a"
    print(f"Analyzed events (current): {analyzed}")
    print(f"Endpoint hunting leads (365d): {leads}")
    print(f"Detections triggered (current): {detections}")
    print()


def generate_report(config: Config, range_label: str, gathered: GatheredData) -> None:

    detections_by_severity: Counter[str] = Counter()
    detections_by_category: Counter[str] = Counter()
    total_detections = 0
    core_records = gathered.core_records
    render_title(f"Detections - Last {range_label}")

    total_detections = len(core_records)
    for record in core_records:
        severity_value = record.get("severity_name")
        if severity_value is None:
            severity_value = record.get("severity")
        detections_by_severity[normalize_severity_value(severity_value)] += 1
        detections_by_category[classify_detection_category(record)] += 1

    normalized_detections = normalize_severity_counter(detections_by_severity)
    render_kv("Total detections", total_detections)
    unassigned_detections = [record for record in core_records]
    unassigned_detections = [record for record in unassigned_detections if is_unassigned_alert(record)]
    unassigned_pct = (len(unassigned_detections) / total_detections * 100.0) if total_detections else 0.0
    render_kv("Unassigned detections", f"{len(unassigned_detections)} ({unassigned_pct:.1f}%)")
    avg_unassigned = average_unassigned_age_seconds(unassigned_detections)
    render_kv(
        "Avg unassigned age",
        format_avg_unassigned_age(avg_unassigned),
    )
    print()

    render_counter(
        "Detections by Severity",
        normalized_detections,
        SEVERITY_LABELS,
    )

    category_visible = Counter(
        {
            label: value
            for label, value in detections_by_category.items()
            if label not in {"cloud", "automated leads"}
        }
    )
    render_category_counter("Detections by Category", category_visible)
    detections_by_category_365d: Counter[str] = Counter()
    for record in gathered.core_records_365d:
        detections_by_category_365d[classify_detection_category(record)] += 1
    categories_365d = [
        label
        for label in CATEGORY_ORDER
        if detections_by_category_365d.get(label, 0) and label not in {"cloud", "automated leads"}
    ]
    render_avg_unassigned_age_matrix(
        gathered.core_records_365d,
        categories_365d,
        category_label="Category",
        title_suffix=" (365d)",
    )
    render_detection_age_range_by_category_severity(gathered.core_records_365d, title_suffix=" (365d)")

    render_cases_section(range_label, gathered.cases)
    render_automated_leads_section(gathered.leads_365d)


def age_value_html(age_seconds: float | None) -> str:
        if age_seconds is None:
                return '<span class="muted">n/a</span>'
        classes = "age age-stale" if age_seconds >= 30 * 60 else "age"
        return f'<span class="{classes}">{html.escape(format_duration(age_seconds))}</span>'


def _overview_unassigned_rows_html(
    unassigned: Counter[str],
    total: Counter[str],
    pct_map: dict[str, str],
    order: list[str],
) -> str:
    maximum = max(unassigned.values(), default=0)
    lines: list[str] = []
    for label in order:
        value = unassigned.get(label, 0)
        width = 0.0 if maximum == 0 else (value / maximum) * 100.0
        pct = pct_map.get(label, "")
        lines.append(
            "<div class=\"bar-row\">"
            f"<div class=\"bar-label\" title=\"{html.escape(label)}\">{html.escape(label)}</div>"
            f"<div class=\"bar-track\"><div class=\"bar-fill\" style=\"width:{width:.2f}%; background:linear-gradient(90deg,#c74a4a,#ff6d6d)\"></div></div>"
            f"<div class=\"bar-value\">{value}</div>"
            f"<div class=\"bar-pct{' unassigned-val' if pct and pct != '0.0%' else ''}\">{html.escape(pct)}</div>"
            "</div>"
        )
    return "\n".join(lines)


def counter_rows_html(
    counter: Counter[str],
    *,
    preferred_order: list[str] | None = None,
    include_zero: bool = False,
    show_percent: bool = True,
    label_map: dict[str, tuple[str, str | None]] | None = None,
) -> str:
    if not counter and not include_zero:
        return '<div class="empty">No data</div>'

    ordered: list[str] = []
    if preferred_order:
        if include_zero:
            ordered.extend([label for label in preferred_order if label in counter])
        else:
            ordered.extend([label for label in preferred_order if counter.get(label)])
    ordered.extend(
        sorted(
            [label for label in counter.keys() if label not in ordered],
            key=lambda label: (-counter[label], label),
        )
    )

    maximum = max(counter.values()) if counter else 0
    total = sum(counter.values())
    lines: list[str] = []
    for label in ordered:
        value = counter[label]
        width = 0.0 if maximum == 0 else (value / maximum) * 100.0
        pct = 0.0 if total == 0 else (value / total) * 100.0
        full_label = display_label(label)
        if label_map and label in label_map:
            mapped_label, mapped_title = label_map[label]
            full_label = mapped_title if mapped_title else mapped_label
            shown_base = html.escape(mapped_label)
            shown = f'<span title="{html.escape(mapped_title)}">{shown_base}</span>' if mapped_title else shown_base
        else:
            shown = html.escape(display_label(label))
        severity_class = severity_css_class(label)
        if severity_class:
            shown = f'<span class="{severity_class}">{shown}</span>'
        lines.append(
            "<div class=\"bar-row\">"
            f"<div class=\"bar-label\" title=\"{html.escape(full_label)}\">{shown}</div>"
            f"<div class=\"bar-track\"><div class=\"bar-fill\" style=\"width:{width:.2f}%\"></div></div>"
            f"<div class=\"bar-value\">{value}</div>"
            f"<div class=\"bar-pct\">{(f'{pct:.1f}%' if show_percent else '')}</div>"
            "</div>"
        )
    return "\n".join(lines)


def build_html_report(range_label: str, gathered: GatheredData) -> str:
        local_now = datetime.now().astimezone()
        generated_at = local_now.strftime("%d.%m.%Y %H:%M:%S %Z")

        selector_windows: list[tuple[str, timedelta]] = [
            ("1h", timedelta(hours=1)),
            ("1d", timedelta(days=1)),
            ("2d", timedelta(days=2)),
            ("3d", timedelta(days=3)),
            ("7d", timedelta(days=7)),
            ("14d", timedelta(days=14)),
            ("30d", timedelta(days=30)),
            ("90d", timedelta(days=90)),
            ("365d", timedelta(days=365)),
        ]

        def records_for_window(records: list[dict[str, Any]], window: timedelta) -> list[dict[str, Any]]:
            start_time, end_time = window_bounds(window)
            selected: list[dict[str, Any]] = []
            for record in records:
                created = parse_iso_timestamp(record.get("created_timestamp"))
                if created is None:
                    continue
                if start_time <= created <= end_time:
                    selected.append(record)
            return selected

        def build_detection_payload(records: list[dict[str, Any]]) -> dict[str, Any]:
            def first_nonempty_string(record: dict[str, Any], fields: list[str]) -> str:
                for field in fields:
                    value = extract_field(record, field)
                    if isinstance(value, str) and value.strip():
                        return value.strip()
                return "unknown"

            def abbreviate_activity_label(value: str, max_length: int = 18) -> tuple[str, str | None]:
                clean = value.strip() if value else "unknown"
                if len(clean) <= max_length:
                    return clean, clean
                return f"{clean[:max_length - 3]}...", clean

            def is_known_activity_value(value: str) -> bool:
                return bool(value and value.strip() and value.strip().lower() != "unknown")

            def looks_like_technique_id(value: str) -> bool:
                token = value.strip().upper()
                return bool(re.fullmatch(r"(T\d{4}(?:\.\d{3})?|TA\d{4}|CST\d+|CSTA\d+)", token))

            def extract_activity_strings(value: Any) -> list[str]:
                if isinstance(value, str):
                    return [value.strip()] if value.strip() else []
                if isinstance(value, dict):
                    collected: list[str] = []
                    for key in ("technique", "name", "display_name", "value"):
                        if key in value:
                            collected.extend(extract_activity_strings(value[key]))
                    return collected
                if isinstance(value, (list, tuple, set)):
                    collected: list[str] = []
                    for item in value:
                        collected.extend(extract_activity_strings(item))
                    return collected
                return []

            def build_activity_label_map(counter: Counter[str]) -> dict[str, tuple[str, str | None]]:
                return {key: abbreviate_activity_label(key) for key in counter.keys()}

            def top_n_counter(counter: Counter[str], limit: int = 10) -> Counter[str]:
                ranked = sorted(counter.items(), key=lambda item: (-item[1], item[0]))[:limit]
                return Counter(dict(ranked))

            detections_by_severity: Counter[str] = Counter()
            detections_by_category: Counter[str] = Counter()
            category_severity: dict[str, Counter[str]] = {}
            category_unassigned: Counter[str] = Counter()
            identity_counter: Counter[str] = Counter()
            endpoint_counter: Counter[str] = Counter()
            triggering_files_counter: Counter[str] = Counter()
            technique_counter: Counter[str] = Counter()

            for record in records:
                severity_value = record.get("severity_name") if record.get("severity_name") is not None else record.get("severity")
                severity = normalize_severity_value(severity_value)
                detections_by_severity[severity] += 1

                category = classify_detection_category(record)
                if category in {"cloud", "automated leads"}:
                    continue
                detections_by_category[category] += 1
                category_severity.setdefault(category, Counter())[severity] += 1
                if is_unassigned_alert(record):
                    category_unassigned[category] += 1

                identity_value = first_nonempty_string(
                    record,
                    [
                        "user_name",
                        "username",
                        "user",
                        "principal_name",
                        "email",
                        "account_name",
                        "device.user_name",
                    ],
                )
                endpoint_value = first_nonempty_string(
                    record,
                    [
                        "device.hostname",
                        "hostname",
                        "host_name",
                        "device_name",
                        "aid",
                        "device_id",
                    ],
                )
                triggering_file_value = first_nonempty_string(
                    record,
                    [
                        "filename",
                        "file_name",
                        "filepath",
                        "file_path",
                        "image_filename",
                        "ImageFileName",
                    ],
                )
                if is_known_activity_value(identity_value):
                    identity_counter[identity_value] += 1
                if is_known_activity_value(endpoint_value):
                    endpoint_counter[endpoint_value] += 1
                if is_known_activity_value(triggering_file_value):
                    triggering_files_counter[triggering_file_value] += 1

                technique_values: set[str] = set()
                for field in ("technique", "mitre_attack", "techniques"):
                    for technique_value in extract_activity_strings(extract_field(record, field)):
                        if is_known_activity_value(technique_value) and not looks_like_technique_id(technique_value):
                            technique_values.add(technique_value)
                for technique_value in technique_values:
                    technique_counter[technique_value] += 1

            identity_ranked = top_n_counter(identity_counter)
            endpoint_ranked = top_n_counter(endpoint_counter)
            files_ranked = top_n_counter(triggering_files_counter)
            techniques_ranked = top_n_counter(technique_counter)

            detections_by_severity = normalize_severity_counter(detections_by_severity)
            total_detections = len(records)
            unassigned_detections = [record for record in records if is_unassigned_alert(record)]
            unassigned_detection_pct = (len(unassigned_detections) / total_detections * 100.0) if total_detections else 0.0
            avg_unassigned_detection_age = average_unassigned_age_seconds(unassigned_detections)
            unassigned_detection_ages = [
                age
                for age in (bounded_display_age(record_age_seconds(record)) for record in unassigned_detections)
                if age is not None
            ]
            oldest_unassigned_detection_age = max(unassigned_detection_ages) if unassigned_detection_ages else None
            newest_unassigned_detection_age = min(unassigned_detection_ages) if unassigned_detection_ages else None

            category_ordered = [
                label for label, _ in sorted(detections_by_category.items(), key=lambda item: (-item[1], item[0]))
            ]
            breakdown_rows_new: list[str] = []
            breakdown_rows_unassigned_age: list[str] = []
            for category in category_ordered:
                total = detections_by_category[category]
                unassigned = category_unassigned.get(category, 0)
                unassigned_pct = (unassigned / total * 100.0) if total else 0.0
                sev_counts = category_severity.get(category, Counter())
                category_ages = [
                    record_age_seconds(record)
                    for record in records
                    if classify_detection_category(record) == category
                ]
                category_ages = [age for age in category_ages if age is not None]
                newest_age = min(category_ages) if category_ages else None
                oldest_age = max(category_ages) if category_ages else None
                breakdown_rows_new.append(
                    "<tr>"
                    f"<th>{html.escape(display_label(category))}</th>"
                    f"<td>{total}</td>"
                    f"<td>{sev_counts.get('critical', 0)}</td>"
                    f"<td>{sev_counts.get('high', 0)}</td>"
                    f"<td>{sev_counts.get('medium', 0)}</td>"
                    f"<td>{sev_counts.get('low', 0)}</td>"
                    f"<td>{sev_counts.get('informational', 0)}</td>"
                    "</tr>"
                )
                _upct_str = f"{unassigned_pct:.1f}%"
                _ucell = (
                    f'{unassigned} <span class="unassigned-val">{_upct_str}</span>'
                    if _upct_str != "0.0%" else f"{unassigned} {_upct_str}"
                )
                breakdown_rows_unassigned_age.append(
                    "<tr>"
                    f"<th>{html.escape(display_label(category))}</th>"
                    f"<td>{_ucell}</td>"
                    f"<td>{age_value_html(newest_age)}</td>"
                    f"<td>{age_value_html(oldest_age)}</td>"
                    "</tr>"
                )

            return {
                "new_detections": total_detections,
                "new_unassigned": len(unassigned_detections),
                "new_unassigned_pct": f"{unassigned_detection_pct:.1f}%",
                "new_unassigned_class": "unassigned-val" if len(unassigned_detections) >= 1 else "",
                "avg_unassigned_age_html": age_value_html(avg_unassigned_detection_age),
                "oldest_unassigned_age_html": age_value_html(oldest_unassigned_detection_age),
                "newest_unassigned_age_html": age_value_html(newest_unassigned_detection_age),
                "by_category_html": counter_rows_html(detections_by_category),
                "by_severity_html": counter_rows_html(detections_by_severity, preferred_order=SEVERITY_LABELS),
                "table_category_severity_html": "".join(breakdown_rows_new) if breakdown_rows_new else '<tr><td colspan="7" class="empty">No data</td></tr>',
                "table_unassigned_html": "".join(breakdown_rows_unassigned_age) if breakdown_rows_unassigned_age else '<tr><td colspan="4" class="empty">No data</td></tr>',
                "activity_top_identities_html": counter_rows_html(identity_ranked, label_map=build_activity_label_map(identity_ranked)),
                "activity_top_endpoints_html": counter_rows_html(endpoint_ranked, label_map=build_activity_label_map(endpoint_ranked)),
                "activity_top_files_html": counter_rows_html(files_ranked, label_map=build_activity_label_map(files_ranked)),
                "activity_top_techniques_html": counter_rows_html(techniques_ranked, label_map=build_activity_label_map(techniques_ranked)),
            }

        def build_cases_payload(records: list[dict[str, Any]]) -> dict[str, Any]:
            cases_by_severity: Counter[str] = Counter(case_severity_bucket(case) for case in records)
            unassigned_cases = [case for case in records if is_unassigned_case(case)]
            cases_avg_age = average_unassigned_age_seconds(unassigned_cases)
            unassigned_case_ages = [
                age
                for age in (bounded_display_age(record_age_seconds(case)) for case in unassigned_cases)
                if age is not None
            ]
            oldest_unassigned_case_age = max(unassigned_case_ages) if unassigned_case_ages else None
            newest_unassigned_case_age = min(unassigned_case_ages) if unassigned_case_ages else None
            cases_total = sum(cases_by_severity.values())
            unassigned_cases_pct = (len(unassigned_cases) / cases_total * 100.0) if cases_total else 0.0
            return {
                "cases": cases_total,
                "unassigned_cases": len(unassigned_cases),
                "unassigned_cases_pct": f"{unassigned_cases_pct:.1f}%",
                "unassigned_cases_class": "unassigned-val" if len(unassigned_cases) >= 1 else "",
                "oldest_unassigned_age_html": age_value_html(oldest_unassigned_case_age),
                "newest_unassigned_age_html": age_value_html(newest_unassigned_case_age),
                "avg_unassigned_age_html": age_value_html(cases_avg_age),
                "by_severity_html": counter_rows_html(cases_by_severity, preferred_order=SEVERITY_LABELS),
            }

        detections_by_range: dict[str, dict[str, Any]] = {}
        cases_by_range: dict[str, dict[str, Any]] = {}
        for selector_label, selector_window in selector_windows:
            detections_by_range[selector_label] = build_detection_payload(
                records_for_window(gathered.core_records_365d, selector_window)
            )
            cases_by_range[selector_label] = build_cases_payload(
                records_for_window(gathered.cases_365d, selector_window)
            )

        default_selector = "7d"
        detection_initial = detections_by_range[default_selector]
        detection_365d = detections_by_range["365d"]
        cases_initial = cases_by_range[default_selector]
        cases_365d = cases_by_range["365d"]
        unassigned_detections_365d = [record for record in gathered.core_records_365d if is_unassigned_alert(record)]
        avg_unassigned_detection_age_365d = average_unassigned_age_seconds(unassigned_detections_365d)

        leads_365d = gathered.leads_365d
        leads_confidence: Counter[str] = Counter(confidence_band(record.get("score")) for record in leads_365d)
        unassigned_leads = [record for record in leads_365d if is_unassigned_alert(record)]
        leads_avg_age = average_unassigned_age_seconds(unassigned_leads)
        unassigned_lead_ages = [
            age for age in (record_age_seconds(record) for record in unassigned_leads) if age is not None
        ]
        oldest_unassigned_lead_age = max(unassigned_lead_ages) if unassigned_lead_ages else None
        newest_unassigned_lead_age = min(unassigned_lead_ages) if unassigned_lead_ages else None
        unassigned_leads_pct = (len(unassigned_leads) / len(leads_365d) * 100.0) if leads_365d else 0.0
        unassigned_leads_class = "unassigned-val" if len(unassigned_leads) >= 1 else ""
        unassigned_cases_365d = [case for case in gathered.cases_365d if is_unassigned_case(case)]
        avg_unassigned_case_age_365d = average_unassigned_age_seconds(unassigned_cases_365d)

        def count_records_for_window(records: list[dict[str, Any]], window: timedelta) -> int:
            start_time, end_time = window_bounds(window)
            total = 0
            for record in records:
                created = parse_iso_timestamp(record.get("created_timestamp"))
                if created is None:
                    continue
                if start_time <= created <= end_time:
                    total += 1
            return total

        overview_order = [label for label, _ in selector_windows]
        overview_unassigned_detections = Counter(
            {
                label: detections_by_range[label]["new_unassigned"]
                for label, _ in selector_windows
            }
        )
        overview_unassigned_pct: dict[str, str] = {
            label: detections_by_range[label]["new_unassigned_pct"]
            for label, _ in selector_windows
        }
        overview_detections = Counter(
            {
                label: count_records_for_window(gathered.core_records_365d, window)
                for label, window in selector_windows
            }
        )
        overview_cases = Counter(
            {
                label: count_records_for_window(gathered.cases_365d, window)
                for label, window in selector_windows
            }
        )
        overview_unassigned_cases = Counter(
            {
                label: cases_by_range[label]["unassigned_cases"]
                for label, _ in selector_windows
            }
        )
        overview_unassigned_cases_pct: dict[str, str] = {
            label: cases_by_range[label]["unassigned_cases_pct"]
            for label, _ in selector_windows
        }
        overview_automated_leads = Counter(
            {
                label: count_records_for_window(gathered.leads_365d, window)
                for label, window in selector_windows
            }
        )
        selector_button_html_parts: list[str] = []
        for label, _ in selector_windows:
            active_class = " active" if label == default_selector else ""
            selector_button_html_parts.append(
                f'<button class="range-pill{active_class}" data-range="{label}">{label}</button>'
            )
        selector_button_html = "".join(selector_button_html_parts)

        def metric_badge(source: str, value: int | None) -> tuple[str, str]:
            lowered = source.lower()
            if value is None:
                return ("Unavailable", "badge-unavailable")
            if "fallback" in lowered:
                return ("Fallback", "badge-fallback")
            return ("Available", "badge-available")

        analyzed_badge_text, analyzed_badge_class = metric_badge(gathered.overwatch.analyzed_source, gathered.overwatch.analyzed_events)
        leads_badge_text, leads_badge_class = metric_badge(gathered.overwatch.endpoint_hunting_leads_source, gathered.overwatch.endpoint_hunting_leads)
        detections_badge_text, detections_badge_class = metric_badge(gathered.overwatch.detections_source, gathered.overwatch.detections)

        age_rows: list[tuple[str, str, str, int, float, float]] = []
        grouped_ages: dict[tuple[str, str], list[float]] = {}
        grouped_unassigned_counts: dict[tuple[str, str], int] = {}
        for record in gathered.core_records_365d:
            category = classify_detection_category(record)
            if category in {"cloud", "automated leads"}:
                continue
            severity_value = record.get("severity_name") if record.get("severity_name") is not None else record.get("severity")
            severity = normalize_severity_value(severity_value)
            age_seconds = record_age_seconds(record)
            if age_seconds is None:
                continue
            grouped_ages.setdefault((category, severity), []).append(age_seconds)
            if is_unassigned_alert(record):
                grouped_unassigned_counts[(category, severity)] = grouped_unassigned_counts.get((category, severity), 0) + 1

        category_rank = {label: index for index, label in enumerate(CATEGORY_ORDER)}
        severity_rank = {label: index for index, label in enumerate(SEVERITY_LABELS)}
        for category, severity in sorted(
            grouped_ages.keys(),
            key=lambda key: (
            category_rank.get(key[0], len(CATEGORY_ORDER)),
            key[0],
            severity_rank.get(key[1], len(SEVERITY_LABELS)),
            key[1],
            ),
        ):
            ages = grouped_ages[(category, severity)]
            unassigned_count = grouped_unassigned_counts.get((category, severity), 0)
            age_rows.append((category, display_label(category), severity, unassigned_count, min(ages), max(ages)))

        age_table_row_parts: list[str] = []
        previous_category = ""
        for category_key, category_label, severity_label, unassigned_count, newest, oldest in age_rows:
            if category_key != previous_category:
                age_table_row_parts.append(
                    "<tr class=\"group-header-row\">"
                    f"<th colspan=\"4\">{html.escape(category_label)}</th>"
                    "</tr>"
                )
                previous_category = category_key
            age_table_row_parts.append(
                "<tr>"
                f"<td><span class=\"{severity_css_class(severity_label)}\">{html.escape(display_label(severity_label))}</span></td>"
                f"<td><span class=\"{'unassigned-val' if unassigned_count >= 1 else ''}\">{unassigned_count}</span></td>"
                f"<td>{age_value_html(newest)}</td>"
                f"<td>{age_value_html(oldest)}</td>"
                "</tr>"
            )
        age_table_rows = "\n".join(age_table_row_parts)

        # ── pct display helpers: number plain, pct red (no brackets) ──
        _det_pct = detection_initial['new_unassigned_pct']
        _det_pct_html = (f'<span class="unassigned-val">{_det_pct}</span>'
                         if _det_pct != "0.0%" else _det_pct)
        _cases_pct = cases_initial['unassigned_cases_pct']
        _cases_pct_html = (f'<span class="unassigned-val">{_cases_pct}</span>'
                           if _cases_pct != "0.0%" else _cases_pct)
        _leads_pct_str = f"{unassigned_leads_pct:.1f}%"
        _leads_pct_html = (f'<span class="unassigned-val">{_leads_pct_str}</span>'
                           if _leads_pct_str != "0.0%" else _leads_pct_str)

        return f"""<!doctype html>
<html lang=\"en\">
<head>
    <meta charset=\"utf-8\" />
    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />
    <title>Falcon Report - Current</title>
    <style>
        :root {{
            --bg0: #000000;
            --bg1: #060606;
            --bg2: #0b0b0b;
            --surface: #171b22;
            --text: #f2f2f2;
            --muted: #b3bac4;
            --accent: #52c7b8;
            --danger: #ff6d6d;
            --line: #3a404a;
        }}
        * {{ box-sizing: border-box; }}
        body {{
            margin: 0;
            color: var(--text);
            font-family: "Space Grotesk", "Manrope", "Segoe UI", sans-serif;
            background:
                radial-gradient(1000px 420px at 88% -8%, rgba(82,199,184,0.12), transparent 62%),
                radial-gradient(900px 500px at -8% 8%, rgba(255,255,255,0.06), transparent 60%),
                linear-gradient(135deg, var(--bg0), var(--bg1) 56%, var(--bg2));
            min-height: 100vh;
        }}
        .wrap {{ max-width: 1220px; margin: 0 auto; padding: 28px 20px 34px; }}
        .hero {{
            display: grid;
            gap: 4px;
            margin-bottom: 18px;
            padding: 18px;
            border-radius: 18px;
            background: linear-gradient(120deg, rgba(255,255,255,0.13), rgba(255,255,255,0.05));
            border: 1px solid var(--line);
            backdrop-filter: blur(3px);
        }}
        .hero h1 {{ margin: 0; font-size: clamp(1.45rem, 2vw, 2rem); letter-spacing: 0.2px; }}
        .hero .sub {{ color: var(--muted); font-size: 0.96rem; }}
        .section-divider {{
            margin: 22px 0 10px;
            padding-bottom: 8px;
            border-bottom: 1px solid var(--line);
            outline: none;
            font-size: 1.12rem;
            letter-spacing: 0.04em;
            text-transform: uppercase;
            color: #d7e6ff;
        }}
        .section-divider.collapsible {{ display: flex; align-items: center; justify-content: flex-start; gap: 10px; cursor: pointer; }}
        .section-title-text {{ text-decoration: none; }}
        .section-divider.collapsible:hover .section-title-text {{ color: var(--accent); text-decoration: underline; text-underline-offset: 4px; text-shadow: 0 0 12px rgba(82,199,184,0.28); }}
        .section-divider.collapsible:focus-visible .section-title-text {{ color: #d7e6ff; text-decoration: none; text-shadow: none; }}
        .section-divider .collapse-indicator {{ line-height: 0; color: var(--muted); opacity: 0.65; margin-left: 0; }}
        .section-divider .collapse-indicator:hover {{ opacity: 1; }}
        a:hover {{ text-decoration: underline; text-underline-offset: 3px; }}
        .stat-value-sub {{ font-size: 0.76rem; color: var(--muted); margin-top: 5px; font-weight: 400; line-height: 1.5; }}
        .panel {{
            border: 1px solid var(--line);
            background: var(--surface);
            border-radius: 16px;
            padding: 14px;
            margin-bottom: 14px;
        }}
        .panel h2 {{ margin: 0 0 10px; font-size: 1.05rem; }}
        .stat-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 10px; }}
        .stat {{ padding: 10px; border-radius: 12px; background: #232935; border: 1px solid #4a5363; }}
        .subpanel {{
            border: 1px solid #495363;
            background: #202734;
            border-radius: 12px;
            padding: 12px;
        }}
        .stack-col {{ display: flex; flex-direction: column; gap: 12px; }}
        .stat-label {{ color: var(--muted); font-size: 0.78rem; text-transform: uppercase; letter-spacing: 0.08em; }}
        .stat-value {{ margin-top: 4px; font-size: 1.15rem; font-weight: 700; }}
        .grid-2 {{ display: grid; grid-template-columns: repeat(2, minmax(0,1fr)); gap: 14px; margin-bottom: 14px; }}
        .grid-3 {{ display: grid; grid-template-columns: repeat(3, minmax(0,1fr)); gap: 14px; margin-bottom: 14px; }}
        .bar-row {{ display: grid; grid-template-columns: 96px 1fr 62px 54px; gap: 8px; align-items: center; margin-bottom: 9px; }}
        .bar-label {{ color: #e5e9ec; font-size: 0.93rem; min-width: 0; overflow: hidden; white-space: nowrap; text-overflow: ellipsis; }}
        .bar-label > span {{ display: block; overflow: hidden; white-space: nowrap; text-overflow: ellipsis; }}
        .bar-track {{ height: 10px; background: #2f3746; border-radius: 999px; overflow: hidden; }}
        .bar-fill {{ height: 100%; background: linear-gradient(90deg, #3a9f93, #52c7b8); border-radius: 999px; }}
        .bar-value {{ text-align: right; font-weight: 700; }}
        .bar-pct {{ text-align: right; color: var(--muted); }}
        table {{ width: 100%; border-collapse: collapse; font-size: 0.93rem; }}
        th, td {{ border-bottom: 1px solid #434c5c; padding: 8px 6px; text-align: left; }}
        th {{ color: #d3d8de; font-weight: 700; }}
        .grouped-age-table .group-header-row th {{
            background: #2d3647;
            color: #f1f6ff;
            border-top: 1px solid #5c697f;
            border-bottom: 1px solid #5c697f;
            text-transform: uppercase;
            letter-spacing: 0.08em;
            font-size: 0.76rem;
            padding: 8px 10px;
        }}
        .grouped-age-table tbody tr:not(.group-header-row) td:first-child {{ padding-left: 18px; }}
        .note {{ color: var(--muted); font-size: 0.85rem; margin-top: 8px; }}
        .empty {{ color: var(--muted); padding: 10px 0; }}
        .muted {{ color: var(--muted); }}
        .subsection-title {{ margin: 0 0 10px; font-size: 1.05rem; font-weight: 700; letter-spacing: 0.02em; color: #d7e6ff; }}
        .title-toggle {{ transition: color 0.15s ease, opacity 0.15s ease, text-shadow 0.15s ease; }}
        .title-toggle:hover {{ color: var(--accent); text-decoration: underline; text-underline-offset: 3px; text-shadow: 0 0 10px rgba(82,199,184,0.28); }}
        .title-toggle:active {{ opacity: 0.82; }}
        .age-stale {{ color: var(--danger); font-weight: 700; }}
        .unassigned-val {{ color: var(--danger); font-weight: 700; }}
        .jump-nav {{ margin-top: 6px; }}
        .jump-link {{ color: var(--accent); text-decoration: none; font-size: 0.88rem; }}
        .jump-link:hover {{ text-decoration: underline; }}
        .overview-focus-link {{ color: inherit; text-decoration: none; }}
        .overview-focus-link:hover {{ color: var(--accent); text-decoration: underline; }}
        .back-to-top {{ color: var(--muted); text-decoration: none; margin-right: 10px; font-size: 1.1rem; opacity: 0.55; transition: opacity 0.15s, color 0.15s; }}
        .back-to-top:hover {{ color: var(--accent); opacity: 1; }}
        .panel-h2-row {{ display: flex; align-items: center; justify-content: flex-start; gap: 10px; margin: 0 0 10px; }}
        .panel-h3-row {{ display: flex; align-items: center; justify-content: flex-start; gap: 10px; margin: 0 0 10px; }}
        .panel-h2-row h2, .panel-h3-row h3 {{ margin: 0; font-size: 1.05rem; font-weight: 700; letter-spacing: 0.02em; color: #d7e6ff; }}
        .toggle-btn {{ line-height: 0; color: var(--muted); background: none; border: none; cursor: pointer; padding: 0; vertical-align: middle; opacity: 0.65; }}
        .toggle-btn:hover {{ opacity: 1; }}
        .toggle-btn:hover {{ color: var(--text); }}
        .sev-critical {{ color: #ff6a6a; font-weight: 700; }}
        .sev-high {{ color: #ff9c40; font-weight: 700; }}
        .sev-medium {{ color: #f4df6f; font-weight: 700; }}
        .sev-low {{ color: #43d1c8; font-weight: 700; }}
        .sev-informational {{ color: #8fd4ff; font-weight: 700; }}
        .range-selector {{ display: flex; flex-wrap: wrap; gap: 8px; margin: 2px 0 12px; }}
        .range-pill {{
            border: 1px solid #465061;
            background: #252d3b;
            color: var(--text);
            border-radius: 999px;
            padding: 4px 10px;
            cursor: pointer;
            font-size: 0.84rem;
            font-weight: 500;
            opacity: 0.82;
        }}
        .range-pill.active {{
            font-weight: 900;
            opacity: 1;
            color: #f1fffd;
            background: linear-gradient(120deg, rgba(82,199,184,0.34), rgba(82,199,184,0.18));
            border-color: rgba(82,199,184,0.95);
            box-shadow: 0 0 0 1px rgba(82,199,184,0.35), 0 0 14px rgba(82,199,184,0.22);
            transform: translateY(-1px);
        }}
        @media (max-width: 1024px) {{
            .grid-2 {{ grid-template-columns: 1fr; }}
            .grid-3 {{ grid-template-columns: 1fr; }}
            .bar-row {{ grid-template-columns: 84px 1fr 50px 46px; }}
            .stat-grid {{ grid-template-columns: 1fr; }}
        }}
    </style>
</head>
<body>
    <div class=\"wrap\" id=\"top\">
        <section class=\"hero\">
            <h1>Falcon Report</h1>
            <div class=\"sub\">Version {html.escape(VERSION)} (build date {html.escape(build_date())})</div>
            <div class=\"sub\">Tenant: {html.escape(gathered.cid_name)}</div>
            <div class=\"sub\">CID: {html.escape(gathered.cid)}</div>
            <div class=\"sub\">Generated: {html.escape(generated_at)}</div>
                        <div class=\"sub jump-nav\">Jump to: <a class=\"jump-link\" href=\"#sect-overview\">General Overview</a> &middot; <a class=\"jump-link\" href=\"#sect-detections\">Detections</a> &middot; <a class=\"jump-link\" href=\"#sect-cases\">Cases</a> &middot; <a class=\"jump-link\" href=\"#sect-leads\">Automated Leads</a> &middot; <a class=\"jump-link\" href=\"#sect-activity\">Activity</a></div>
        </section>

        <h2 class=\"section-divider\" id=\"sect-overview\" data-section=\"general overview\"><a class=\"back-to-top\" href=\"#top\" title=\"Back to top\">&#8962;</a> <span class=\"section-title-text\">General Overview</span></h2>
        <section class=\"panel\">
            <div class=\"grid-3\" style=\"margin-top:12px\">
                <article class=\"subpanel\">
                    <h3 class=\"muted subsection-title\"><a class=\"overview-focus-link\" href=\"#sect-detections\">Detections</a></h3>
                    {counter_rows_html(overview_detections, preferred_order=overview_order, include_zero=True, show_percent=False)}
                    <div class=\"stat-value-sub\" style=\"margin-top:10px\">Avg <span>{detection_365d['avg_unassigned_age_html']}</span> &middot; Newest <span>{detection_365d['newest_unassigned_age_html']}</span> &middot; Oldest <span>{detection_365d['oldest_unassigned_age_html']}</span></div>
                </article>
                <article class=\"subpanel\">
                    <h3 class=\"muted subsection-title\"><a class=\"overview-focus-link\" href=\"#sect-cases\">Cases</a></h3>
                    {counter_rows_html(overview_cases, preferred_order=overview_order, include_zero=True, show_percent=False)}
                    <div class=\"stat-value-sub\" style=\"margin-top:10px\">Avg <span>{cases_365d['avg_unassigned_age_html']}</span> &middot; Newest <span>{cases_365d['newest_unassigned_age_html']}</span> &middot; Oldest <span>{cases_365d['oldest_unassigned_age_html']}</span></div>
                </article>
                <article class=\"subpanel\">
                    <h3 class=\"muted subsection-title\"><a class=\"overview-focus-link\" href=\"#sect-leads\">Automated Leads</a></h3>
                    {counter_rows_html(overview_automated_leads, preferred_order=overview_order, include_zero=True, show_percent=False)}
                    <div class=\"stat-value-sub\" style=\"margin-top:10px\">Avg <span>{age_value_html(leads_avg_age)}</span> &middot; Newest <span>{age_value_html(newest_unassigned_lead_age)}</span> &middot; Oldest <span>{age_value_html(oldest_unassigned_lead_age)}</span></div>
                </article>
            </div>
        </section>

        <h2 class=\"section-divider\" id=\"sect-detections\" data-section=\"detections\"><a class=\"back-to-top\" href=\"#top\" title=\"Back to top\">&#8962;</a> <span class=\"section-title-text\">Detections</span></h2>
        <section class=\"panel\">
            <div class=\"panel-h2-row\"><h2 id=\"det-overview-title\">New and Unassigned Detections</h2><button class=\"toggle-btn\" id=\"det-overview-toggle\" title=\"Toggle\"><svg xmlns=\"http://www.w3.org/2000/svg\" width=\"15\" height=\"15\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\"><path d=\"M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24\"/><line x1=\"1\" y1=\"1\" x2=\"23\" y2=\"23\"/></svg></button></div>
            <article class=\"subpanel\" id=\"det-overview-article\" style=\"margin-bottom:12px\">
                <div style=\"display:grid; grid-template-columns:1fr 1fr; gap:16px\">
                    <div>
                        <div class=\"stat-label\" style=\"margin-bottom:7px\">New</div>
                        {counter_rows_html(overview_detections, preferred_order=overview_order, include_zero=True, show_percent=False)}
                    </div>
                    <div>
                        <div class=\"stat-label\" style=\"margin-bottom:7px\">Unassigned</div>
                        {_overview_unassigned_rows_html(overview_unassigned_detections, overview_detections, overview_unassigned_pct, overview_order)}
                    </div>
                </div>
                <div class=\"stat-value-sub\" style=\"margin-top:10px; text-align:right\">Avg <span id=\"det-unassigned-avg\">{detection_365d['avg_unassigned_age_html']}</span> &middot; Newest <span id=\"det-unassigned-newest\">{detection_365d['newest_unassigned_age_html']}</span> &middot; Oldest <span id=\"det-unassigned-oldest\">{detection_365d['oldest_unassigned_age_html']}</span></div>
            </article>
            <div class=\"range-selector\" id=\"detections-range-selector\">{selector_button_html}</div>
            <div class=\"stat-grid\">
                <div class=\"stat\"><div class=\"stat-label\">New detections</div><div class=\"stat-value\" id=\"det-new-count\">{detection_initial['new_detections']}</div></div>
                <div class=\"stat\"><div class=\"stat-label\">Unassigned Detections</div><div class=\"stat-value\" id=\"det-unassigned-count\">{detection_initial['new_unassigned']} {_det_pct_html}</div></div>
                <div class=\"stat\"><div class=\"stat-label\">Avg Unassn Age (365d)</div><div class=\"stat-value\">{detection_365d['avg_unassigned_age_html']}</div></div>
                <div class=\"stat\"><div class=\"stat-label\">Newest Unassn (365d)</div><div class=\"stat-value\">{detection_365d['newest_unassigned_age_html']}</div></div>
                <div class=\"stat\"><div class=\"stat-label\">Oldest Unassn (365d)</div><div class=\"stat-value\">{detection_365d['oldest_unassigned_age_html']}</div></div>
            </div>
            <div class=\"grid-2\" style=\"margin-top:12px\">
                <article class=\"subpanel\">
                    <h3 class=\"muted subsection-title\" id=\"det-category-title\">Category</h3>
                    <div id=\"det-by-category\">{detection_initial['by_category_html']}</div>
                </article>
                <article class=\"subpanel\">
                    <h3 class=\"muted subsection-title\" id=\"det-severity-title\">Severity</h3>
                    <div id=\"det-by-severity\">{detection_initial['by_severity_html']}</div>
                </article>
            </div>
            <article class=\"subpanel\" style=\"margin-top:12px\">
                <div class=\"panel-h3-row\"><h3 id=\"det-cat-sev-title\">Category and Severity</h3><button class=\"toggle-btn\" id=\"det-cat-sev-toggle\" title=\"Toggle\"><svg xmlns=\"http://www.w3.org/2000/svg\" width=\"15\" height=\"15\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\"><path d=\"M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24\"/><line x1=\"1\" y1=\"1\" x2=\"23\" y2=\"23\"/></svg></button></div>
                <div id=\"det-cat-sev-article\">
                    <table>
                        <thead>
                            <tr>
                                <th>Category</th><th>New detections</th>
                                <th class=\"sev-critical\">Crit</th><th class=\"sev-high\">High</th><th class=\"sev-medium\">Med</th><th class=\"sev-low\">Low</th><th class=\"sev-informational\">Inf</th>
                            </tr>
                        </thead>
                        <tbody id=\"det-category-severity-table\">{detection_initial['table_category_severity_html']}</tbody>
                    </table>
                </div>
            </article>
            <article class=\"subpanel\" style=\"margin-top:12px\">
                <div class=\"panel-h3-row\"><h3 id=\"det-unassigned-title\">Unassigned Detections: Summary</h3><button class=\"toggle-btn\" id=\"det-unassigned-toggle\" title=\"Toggle\"><svg xmlns=\"http://www.w3.org/2000/svg\" width=\"15\" height=\"15\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\"><path d=\"M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24\"/><line x1=\"1\" y1=\"1\" x2=\"23\" y2=\"23\"/></svg></button></div>
                <div id=\"det-unassigned-article\">
                    <table>
                        <thead>
                            <tr>
                                <th>Category</th><th>Unassigned</th>
                                <th>Newest</th><th>Oldest</th>
                            </tr>
                        </thead>
                        <tbody id=\"det-unassigned-table\">{detection_initial['table_unassigned_html']}</tbody>
                    </table>
                </div>
            </article>
        </section>

        <h2 class=\"section-divider\" id=\"sect-cases\" data-section=\"cases\"><a class=\"back-to-top\" href=\"#top\" title=\"Back to top\">&#8962;</a> <span class=\"section-title-text\">Cases</span></h2>
        <section class=\"panel\">
            <div class=\"panel-h2-row\"><h2 id=\"cases-overview-title\">New and Unassigned Cases</h2><button class=\"toggle-btn\" id=\"cases-overview-toggle\" title=\"Toggle\"><svg xmlns=\"http://www.w3.org/2000/svg\" width=\"15\" height=\"15\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\"><path d=\"M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24\"/><line x1=\"1\" y1=\"1\" x2=\"23\" y2=\"23\"/></svg></button></div>
            <article class=\"subpanel\" id=\"cases-overview-article\" style=\"margin-bottom:12px\">
                <div style=\"display:grid; grid-template-columns:1fr 1fr; gap:16px\">
                    <div>
                        <div class=\"stat-label\" style=\"margin-bottom:7px\">New</div>
                        {counter_rows_html(overview_cases, preferred_order=overview_order, include_zero=True, show_percent=False)}
                    </div>
                    <div>
                        <div class=\"stat-label\" style=\"margin-bottom:7px\">Unassigned</div>
                        {_overview_unassigned_rows_html(overview_unassigned_cases, overview_cases, overview_unassigned_cases_pct, overview_order)}
                    </div>
                </div>
                <div class=\"stat-value-sub\" style=\"margin-top:10px; text-align:right\">Avg <span id=\"cases-unassigned-avg\">{cases_365d['avg_unassigned_age_html']}</span> &middot; Newest <span id=\"cases-unassigned-newest\">{cases_365d['newest_unassigned_age_html']}</span> &middot; Oldest <span id=\"cases-unassigned-oldest\">{cases_365d['oldest_unassigned_age_html']}</span></div>
            </article>
            <div class=\"range-selector\" id=\"cases-range-selector\">{selector_button_html}</div>
            <div class=\"stat-grid\">
                <div class=\"stat\"><div class=\"stat-label\">Cases</div><div class=\"stat-value\" id=\"cases-count\">{cases_initial['cases']}</div></div>
                <div class=\"stat\"><div class=\"stat-label\">Unassn Cases</div><div class=\"stat-value\" id=\"cases-unassigned-count\">{cases_initial['unassigned_cases']} {_cases_pct_html}</div></div>
                <div class=\"stat\"><div class=\"stat-label\">Avg Unassn Age (365d)</div><div class=\"stat-value\">{cases_365d['avg_unassigned_age_html']}</div></div>
                <div class=\"stat\"><div class=\"stat-label\">Newest Unassn (365d)</div><div class=\"stat-value\">{cases_365d['newest_unassigned_age_html']}</div></div>
                <div class=\"stat\"><div class=\"stat-label\">Oldest Unassn (365d)</div><div class=\"stat-value\">{cases_365d['oldest_unassigned_age_html']}</div></div>
            </div>
            <article class=\"subpanel\" style=\"margin-top:12px\">
                <h3 class=\"muted subsection-title\">Cases by Severity</h3>
                <div id=\"cases-by-severity\">{cases_initial['by_severity_html']}</div>
            </article>
        </section>

        <h2 class=\"section-divider\" id=\"sect-leads\" data-section=\"automated leads\"><a class=\"back-to-top\" href=\"#top\" title=\"Back to top\">&#8962;</a> <span class=\"section-title-text\">Automated Leads</span></h2>
        <section class=\"panel\">
            <div class=\"panel-h2-row\"><h2 id=\"leads-overview-title\">Automated Leads</h2></div>
            <div id=\"leads-overview-article\">
                <div class=\"range-selector\" id=\"leads-range-selector\"><button class=\"range-pill active\" data-range=\"365d\">365d</button></div>
                <div class=\"stat-grid\">
                    <div class=\"stat\"><div class=\"stat-label\">Automated leads</div><div class=\"stat-value\">{len(leads_365d)}</div></div>
                    <div class=\"stat\"><div class=\"stat-label\">Unassn Leads</div><div class=\"stat-value\">{len(unassigned_leads)} {_leads_pct_html}</div></div>
                    <div class=\"stat\"><div class=\"stat-label\">Avg Unassn Age</div><div class=\"stat-value\">{age_value_html(leads_avg_age)}</div></div>
                    <div class=\"stat\"><div class=\"stat-label\">Newest Unassn</div><div class=\"stat-value\">{age_value_html(newest_unassigned_lead_age)}</div></div>
                    <div class=\"stat\"><div class=\"stat-label\">Oldest Unassn</div><div class=\"stat-value\">{age_value_html(oldest_unassigned_lead_age)}</div></div>
                </div>
                <article class=\"subpanel\" style=\"margin-top:12px\">
                    <h3 class=\"muted subsection-title\">Automated Leads by Confidence</h3>
                    {counter_rows_html(leads_confidence, preferred_order=CONFIDENCE_BANDS)}
                </article>
            </div>
        </section>

        <section class=\"panel\">
            <div class=\"panel-h2-row\"><h2 id=\"detection-age-title\">Detection Age Range by Category and Severity</h2><button class=\"toggle-btn\" id=\"detection-age-toggle\" title=\"Toggle\"><svg xmlns=\"http://www.w3.org/2000/svg\" width=\"15\" height=\"15\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\"><path d=\"M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24\"/><line x1=\"1\" y1=\"1\" x2=\"23\" y2=\"23\"/></svg></button></div>
            <div id=\"detection-age-article\">
                <div class=\"range-selector\" id=\"detection-age-range-selector\"><button class=\"range-pill active\" data-range=\"365d\">365d</button></div>
                <table class="grouped-age-table">
                    <thead><tr><th>Severity</th><th>Number</th><th>Newest</th><th>Oldest</th></tr></thead>
                    <tbody>{age_table_rows if age_table_rows else '<tr><td colspan="4" class="empty">No data</td></tr>'}</tbody>
                </table>
                <div class=\"note\">All durations 30 minutes and older are highlighted in red.</div>
            </div>
        </section>

        <h2 class=\"section-divider\" id=\"sect-activity\" data-section=\"activity\"><a class=\"back-to-top\" href=\"#top\" title=\"Back to top\">&#8962;</a> <span class=\"section-title-text\">Activity</span></h2>
        <section class=\"panel\">
            <h2>Activity</h2>
            <div class=\"range-selector\" id=\"activity-range-selector\">{selector_button_html}</div>
            <div class=\"grid-2\" style=\"margin-top:12px\">
                <div class=\"stack-col\">
                    <article class=\"subpanel\">
                        <h3 class=\"muted subsection-title\">Top 10 Identities by Detections</h3>
                        <div id=\"activity-top-identities\">{detection_initial['activity_top_identities_html']}</div>
                    </article>
                    <article class=\"subpanel\">
                        <h3 class=\"muted subsection-title\">Top 10 Triggering Files</h3>
                        <div id=\"activity-top-files\">{detection_initial['activity_top_files_html']}</div>
                    </article>
                </div>
                <div class=\"stack-col\">
                    <article class=\"subpanel\">
                        <h3 class=\"muted subsection-title\">Top 10 Endpoints by Detections</h3>
                        <div id=\"activity-top-endpoints\">{detection_initial['activity_top_endpoints_html']}</div>
                    </article>
                    <article class=\"subpanel\">
                        <h3 class=\"muted subsection-title\">Top 10 Techniques</h3>
                        <div id=\"activity-top-techniques\">{detection_initial['activity_top_techniques_html']}</div>
                    </article>
                </div>
            </div>
        </section>
    </div>
    <script>
        const detectionsData = {json.dumps(detections_by_range)};
        const casesData = {json.dumps(cases_by_range)};

        const EYE_OPEN = `<svg xmlns="http://www.w3.org/2000/svg" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>`;
        const EYE_CLOSED = `<svg xmlns="http://www.w3.org/2000/svg" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></svg>`;

        function processUnassignedTableHtml(rawHtml) {{
            return rawHtml.replace(
                /<span class="unassigned-val">(\\d+) \\(([^)]+)\\)<\\/span>/g,
                (_, num, pct) => pct === '0.0%' ? `${{num}} ${{pct}}` : `${{num}} <span class="unassigned-val">${{pct}}</span>`
            );
        }}

        function toggleDetOverview() {{
            const art = document.getElementById('det-overview-article');
            const btn = document.getElementById('det-overview-toggle');
            const hidden = art.style.display === 'none';
            art.style.display = hidden ? '' : 'none';
            btn.innerHTML = hidden ? EYE_CLOSED : EYE_OPEN;
        }}

        function toggleCasesOverview() {{
            const art = document.getElementById('cases-overview-article');
            const btn = document.getElementById('cases-overview-toggle');
            const hidden = art.style.display === 'none';
            art.style.display = hidden ? '' : 'none';
            btn.innerHTML = hidden ? EYE_CLOSED : EYE_OPEN;
        }}

        function toggleLeadsOverview() {{
            const art = document.getElementById('leads-overview-article');
            const btn = document.getElementById('leads-overview-toggle');
            const hidden = art.style.display === 'none';
            art.style.display = hidden ? '' : 'none';
            if (btn) btn.innerHTML = hidden ? EYE_CLOSED : EYE_OPEN;
        }}

        function toggleDetectionAgeOverview() {{
            const art = document.getElementById('detection-age-article');
            const btn = document.getElementById('detection-age-toggle');
            const hidden = art.style.display === 'none';
            art.style.display = hidden ? '' : 'none';
            btn.innerHTML = hidden ? EYE_CLOSED : EYE_OPEN;
        }}

        function toggleDetCategorySeverity() {{
            const art = document.getElementById('det-cat-sev-article');
            const btn = document.getElementById('det-cat-sev-toggle');
            const hidden = art.style.display === 'none';
            art.style.display = hidden ? '' : 'none';
            btn.innerHTML = hidden ? EYE_CLOSED : EYE_OPEN;
        }}

        function toggleDetUnassignedPanel() {{
            const art = document.getElementById('det-unassigned-article');
            const btn = document.getElementById('det-unassigned-toggle');
            const hidden = art.style.display === 'none';
            art.style.display = hidden ? '' : 'none';
            btn.innerHTML = hidden ? EYE_CLOSED : EYE_OPEN;
        }}

        function setActiveRange(containerId, selectedRange) {{
            document.querySelectorAll(`#${{containerId}} .range-pill`).forEach((button) => {{
                button.classList.toggle('active', button.dataset.range === selectedRange);
            }});
        }}

        function renderDetections(range) {{
            const payload = detectionsData[range];
            const payload365 = detectionsData['365d'];
            if (!payload) return;
            document.getElementById('det-new-count').textContent = String(payload.new_detections);
            const detPctClass = payload.new_unassigned_pct !== '0.0%' ? 'unassigned-val' : '';
            document.getElementById('det-unassigned-count').innerHTML = `${{payload.new_unassigned}} <span class="${{detPctClass}}">${{payload.new_unassigned_pct}}</span>`;
            if (payload365) {{
                document.getElementById('det-unassigned-avg').innerHTML = payload365.avg_unassigned_age_html;
                document.getElementById('det-unassigned-newest').innerHTML = payload365.newest_unassigned_age_html;
                document.getElementById('det-unassigned-oldest').innerHTML = payload365.oldest_unassigned_age_html;
            }}
            document.getElementById('det-by-category').innerHTML = payload.by_category_html;
            document.getElementById('det-by-severity').innerHTML = payload.by_severity_html;
            document.getElementById('det-category-severity-table').innerHTML = payload.table_category_severity_html;
            document.getElementById('det-unassigned-table').innerHTML = processUnassignedTableHtml(payload.table_unassigned_html);
            document.getElementById('det-category-title').textContent = `Category (${{range}})`;
            document.getElementById('det-severity-title').textContent = `Severity (${{range}})`;
            document.getElementById('det-cat-sev-title').textContent = `Category and Severity (${{range}})`;
            document.getElementById('det-unassigned-title').textContent = `Unassigned Detections: Summary (${{range}})`;
            setActiveRange('detections-range-selector', range);
        }}

        function renderActivity(range) {{
            const payload = detectionsData[range];
            if (!payload) return;
            document.getElementById('activity-top-identities').innerHTML = payload.activity_top_identities_html;
            document.getElementById('activity-top-files').innerHTML = payload.activity_top_files_html;
            document.getElementById('activity-top-endpoints').innerHTML = payload.activity_top_endpoints_html;
            document.getElementById('activity-top-techniques').innerHTML = payload.activity_top_techniques_html;
            setActiveRange('activity-range-selector', range);
        }}

        function renderCases(range) {{
            const payload = casesData[range];
            const payload365 = casesData['365d'];
            if (!payload) return;
            document.getElementById('cases-count').textContent = String(payload.cases);
            const casesPctClass = payload.unassigned_cases_pct !== '0.0%' ? 'unassigned-val' : '';
            document.getElementById('cases-unassigned-count').innerHTML = `${{payload.unassigned_cases}} <span class="${{casesPctClass}}">${{payload.unassigned_cases_pct}}</span>`;
            if (payload365) {{
                document.getElementById('cases-unassigned-avg').innerHTML = payload365.avg_unassigned_age_html;
                document.getElementById('cases-unassigned-newest').innerHTML = payload365.newest_unassigned_age_html;
                document.getElementById('cases-unassigned-oldest').innerHTML = payload365.oldest_unassigned_age_html;
            }}
            document.getElementById('cases-by-severity').innerHTML = payload.by_severity_html;
            setActiveRange('cases-range-selector', range);
        }}

        const sectionControllers = new Map();

        document.getElementById('det-overview-toggle')?.addEventListener('click', toggleDetOverview);
        document.getElementById('cases-overview-toggle')?.addEventListener('click', toggleCasesOverview);
        document.getElementById('leads-overview-toggle')?.addEventListener('click', toggleLeadsOverview);
        document.getElementById('detection-age-toggle')?.addEventListener('click', toggleDetectionAgeOverview);
        document.getElementById('det-cat-sev-toggle')?.addEventListener('click', toggleDetCategorySeverity);
        document.getElementById('det-unassigned-toggle')?.addEventListener('click', toggleDetUnassignedPanel);

        function bindTitleToggle(titleId, toggleFn) {{
            const title = document.getElementById(titleId);
            if (!title) return;
            title.classList.add('title-toggle');
            title.style.cursor = 'pointer';
            title.addEventListener('click', toggleFn);
        }}

        bindTitleToggle('det-overview-title', toggleDetOverview);
        bindTitleToggle('cases-overview-title', toggleCasesOverview);
        bindTitleToggle('detection-age-title', toggleDetectionAgeOverview);
        bindTitleToggle('det-cat-sev-title', toggleDetCategorySeverity);
        bindTitleToggle('det-unassigned-title', toggleDetUnassignedPanel);
        renderDetections('{default_selector}');
        document.querySelectorAll('#detections-range-selector .range-pill').forEach((button) => {{
            button.addEventListener('click', () => renderDetections(button.dataset.range));
        }});
        document.querySelectorAll('#cases-range-selector .range-pill').forEach((button) => {{
            button.addEventListener('click', () => renderCases(button.dataset.range));
        }});
        document.querySelectorAll('#activity-range-selector .range-pill').forEach((button) => {{
            button.addEventListener('click', () => renderActivity(button.dataset.range));
        }});

        function initCollapsibleSections() {{
            const collapsibleSections = new Set(['general overview', 'detections', 'cases', 'automated leads', 'activity']);
            const initiallyCollapsed = new Set(['detections', 'cases', 'automated leads', 'activity']);
            const allDividers = Array.from(document.querySelectorAll('.section-divider'));

            allDividers.forEach((divider, index) => {{
                const label = (divider.dataset.section || divider.textContent || '').trim().toLowerCase();
                if (!collapsibleSections.has(label)) return;

                const controlledPanels = [];
                let cursor = divider.nextElementSibling;
                while (cursor && !cursor.classList.contains('section-divider')) {{
                    if (cursor.classList.contains('panel')) controlledPanels.push(cursor);
                    cursor = cursor.nextElementSibling;
                }}
                if (!controlledPanels.length) return;

                divider.classList.add('collapsible');
                divider.setAttribute('role', 'button');
                divider.setAttribute('tabindex', '0');
                divider.setAttribute('aria-controls', `collapsible-section-${{index}}`);

                const indicator = document.createElement('span');
                indicator.className = 'collapse-indicator';
                divider.appendChild(indicator);

                const setExpanded = (expanded) => {{
                    divider.setAttribute('aria-expanded', expanded ? 'true' : 'false');
                    indicator.innerHTML = expanded ? EYE_CLOSED : EYE_OPEN;
                    controlledPanels.forEach((panel) => {{
                        panel.style.display = expanded ? '' : 'none';
                    }});
                }};

                const toggle = () => {{
                    const currentlyExpanded = divider.getAttribute('aria-expanded') === 'true';
                    setExpanded(!currentlyExpanded);
                }};

                sectionControllers.set(label, {{ divider, setExpanded }});

                setExpanded(!initiallyCollapsed.has(label));
                divider.addEventListener('click', (event) => {{
                    if (event.target.closest('.back-to-top')) return;
                    if (event.target.closest('.collapse-indicator')) {{
                        toggle();
                        return;
                    }}
                    focusSection(label, divider.id);
                }});
                divider.addEventListener('keydown', (event) => {{
                    if (event.key === 'Enter' || event.key === ' ') {{
                        event.preventDefault();
                        focusSection(label, divider.id);
                    }}
                }});
            }});
        }}

        function relocateDetectionAgePanel() {{
            const detUnassignedCard = document.getElementById('det-unassigned-title')?.closest('article.subpanel');
            const detectionAgeToggle = document.getElementById('detection-age-toggle');
            const detectionAgePanel = detectionAgeToggle?.closest('section.panel');
            if (!detUnassignedCard || !detectionAgePanel) return;

            const heading = detectionAgePanel.querySelector('.panel-h2-row h2');
            if (heading) heading.textContent = 'Unassigned Detections: Long-Term Breakdown';

            detectionAgePanel.classList.add('subpanel');
            detectionAgePanel.style.marginTop = '12px';
            detUnassignedCard.insertAdjacentElement('afterend', detectionAgePanel);
        }}

        function setPanelToggleState(articleId, buttonId, expanded) {{
            const article = document.getElementById(articleId);
            const button = document.getElementById(buttonId);
            if (!article) return;
            article.style.display = expanded ? '' : 'none';
            if (button) button.innerHTML = expanded ? EYE_CLOSED : EYE_OPEN;
        }}

        function expandSubsectionsForSection(sectionLabel) {{
            if (sectionLabel === 'detections') {{
                setPanelToggleState('det-overview-article', 'det-overview-toggle', true);
                setPanelToggleState('det-cat-sev-article', 'det-cat-sev-toggle', true);
                setPanelToggleState('det-unassigned-article', 'det-unassigned-toggle', true);
                setPanelToggleState('detection-age-article', 'detection-age-toggle', true);
                return;
            }}
            if (sectionLabel === 'cases') {{
                setPanelToggleState('cases-overview-article', 'cases-overview-toggle', true);
                return;
            }}
            if (sectionLabel === 'automated leads') {{
                setPanelToggleState('leads-overview-article', 'leads-overview-toggle', true);
            }}
        }}

        function focusSection(sectionLabel, sectionId) {{
            sectionControllers.forEach((controller, label) => {{
                controller.setExpanded(label === sectionLabel);
            }});
            expandSubsectionsForSection(sectionLabel);
            const target = sectionId ? document.getElementById(sectionId) : null;
            if (target) target.scrollIntoView({{ behavior: 'smooth', block: 'start' }});
        }}

        function resetToOverview() {{
            sectionControllers.forEach((controller, label) => {{
                controller.setExpanded(label === 'general overview');
            }});
            const top = document.getElementById('top');
            if (top) top.scrollIntoView({{ behavior: 'smooth', block: 'start' }});
        }}

        relocateDetectionAgePanel();
        initCollapsibleSections();

        document.querySelectorAll('.jump-link, .overview-focus-link').forEach((link) => {{
            link.addEventListener('click', (event) => {{
                event.preventDefault();
                const targetId = (link.getAttribute('href') || '').replace('#', '');
                const divider = document.getElementById(targetId);
                if (!divider) return;
                const sectionLabel = (divider.dataset.section || '').trim().toLowerCase();
                if (!sectionLabel) return;
                focusSection(sectionLabel, targetId);
            }});
        }});

        document.querySelectorAll('.section-divider .back-to-top').forEach((a) => {{
            a.addEventListener('click', (event) => {{
                event.preventDefault();
                event.stopPropagation();
                resetToOverview();
            }});
        }});

        renderDetections('{default_selector}');
        renderCases('{default_selector}');
        renderActivity('{default_selector}');
    </script>
</body>
</html>
"""


def write_html_report(range_label: str, gathered: GatheredData) -> Path:
    print("Generating HTML report...", end=" ", flush=True)
    report_html = build_html_report(range_label, gathered)
    print("done")
    output_path = Path.cwd() / "falcon_report.html"
    print(f"Writing {output_path.name}...", end=" ", flush=True)
    output_path.write_text(report_html, encoding="utf-8")
    print("done")
    from datetime import datetime as _dt

    ts = _dt.now().strftime('%Y-%m-%d-%H-%M')
    archive_path = Path.cwd() / f"falcon_report_{ts}.html"
    print(f"Writing archive {archive_path.name}...", end=" ", flush=True)
    archive_path.write_text(report_html, encoding="utf-8")
    print("done")
    return output_path


def main() -> int:
    print("\033[2J\033[H", end="")
    print_banner()
    args = parse_args()

    try:
        config = resolve_config(args)
    except Exception as exc:
        print(f"[error] Configuration failed: {exc}", file=sys.stderr)
        return 1

    def validate_current_config(current_config: Config) -> bool:
        try:
            print("[info] Running pre-flight access check...", end=" ", flush=True)
            report = FalconOverviewClient(current_config).run_preflight_checks()
            if report.required_ok:
                print(color_text("done", ANSI_GREEN))
            else:
                print(color_text("failed", ANSI_RED))

            if report.missing_required:
                print("[error] Missing required API access:")
                for check in report.missing_required:
                    detail = f" - {check.detail}" if check.detail else ""
                    print(f"  - {check.name}{detail}")
                return False

            if report.missing_optional:
                print("[warn] Optional API access unavailable (non-blocking):")
                for check in report.missing_optional:
                    detail = f" - {check.detail}" if check.detail else ""
                    print(f"  - {check.name}{detail}")

            return True
        except Exception as exc:
            print(f"[error] Authentication or API access failed: {exc}", file=sys.stderr)
            return False

    if not validate_current_config(config):
        return 2

    selected_range = args.report_range if args.report_range in REPORT_RANGE_CHOICES else DEFAULT_REPORT_RANGE
    selected_window = range_to_timedelta(selected_range)
    print()
    gathered = run_with_spinner("Gathering data ...", lambda: gather_data(config, selected_window))
    html_output = write_html_report(selected_range, gathered)
    print(f"[info] Wrote HTML report: {html_output}")
    print("Thanks for using Falcon Report. Bye!")

    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\nAborted by user.")
        raise SystemExit(130)
