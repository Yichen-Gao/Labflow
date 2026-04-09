from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo


@dataclass(frozen=True)
class ExtraUser:
    uid: int
    login_name: str
    display_name: str
    data_dir: str | None = None


@dataclass(frozen=True)
class UserOverride:
    uid: int
    login_name: str | None = None
    display_name: str | None = None
    data_dir: str | None = None
    source: str | None = None


@dataclass(frozen=True)
class LabflowConfig:
    data_root: Path
    db_path: Path
    table_name: str = "labflow"
    external_interfaces: tuple[str, ...] = field(default_factory=tuple)
    timezone: str = "UTC"
    total_monthly_quota_gb: float | None = None
    user_soft_limit_gb: float | None = None
    skip_hidden_dirs: bool = True
    exclude_dirs: tuple[str, ...] = field(default_factory=tuple)
    nft_binary: str = "nft"
    extra_users: tuple[ExtraUser, ...] = field(default_factory=tuple)
    user_overrides: tuple[UserOverride, ...] = field(default_factory=tuple)
    free_traffic_windows: tuple[str, ...] = field(default_factory=tuple)
    daily_alert_gb: float | None = None
    alert_email_to: tuple[str, ...] = field(default_factory=tuple)
    smtp_host: str | None = None
    smtp_port: int = 587
    smtp_username: str | None = None
    smtp_password: str | None = None
    smtp_password_env: str | None = None
    smtp_from: str | None = None
    smtp_use_tls: bool = True
    smtp_use_ssl: bool = False
    smtp_subject_prefix: str = "[Labflow]"

    @property
    def total_monthly_quota_bytes(self) -> int | None:
        if self.total_monthly_quota_gb is None:
            return None
        return int(self.total_monthly_quota_gb * 1024**3)

    @property
    def user_soft_limit_bytes(self) -> int | None:
        if self.user_soft_limit_gb is None:
            return None
        return int(self.user_soft_limit_gb * 1024**3)

    @property
    def daily_alert_bytes(self) -> int | None:
        if self.daily_alert_gb is None:
            return None
        return int(self.daily_alert_gb * 1024**3)

    @property
    def smtp_password_resolved(self) -> str | None:
        if self.smtp_password_env:
            value = os.environ.get(self.smtp_password_env)
            if value:
                return value
        return self.smtp_password

    @property
    def smtp_recipients(self) -> tuple[str, ...]:
        if self.alert_email_to:
            return self.alert_email_to
        if self.smtp_from:
            return (self.smtp_from,)
        return tuple()

    def is_free_traffic_time(self, dt: datetime) -> bool:
        if not self.free_traffic_windows:
            return False
        local = dt.astimezone(ZoneInfo(self.timezone))
        minute_of_day = local.hour * 60 + local.minute
        for raw_window in self.free_traffic_windows:
            start_minute, end_minute = _parse_time_window(raw_window)
            if start_minute == end_minute:
                return True
            if start_minute < end_minute:
                if start_minute <= minute_of_day < end_minute:
                    return True
            else:
                if minute_of_day >= start_minute or minute_of_day < end_minute:
                    return True
        return False


def _parse_extra_users(items: list[dict[str, object]]) -> tuple[ExtraUser, ...]:
    users: list[ExtraUser] = []
    for item in items:
        uid = int(item["uid"])
        login_name = str(item.get("login_name") or f"uid_{uid}")
        display_name = str(item.get("display_name") or login_name)
        data_dir = item.get("data_dir")
        users.append(
            ExtraUser(
                uid=uid,
                login_name=login_name,
                display_name=display_name,
                data_dir=None if data_dir is None else str(data_dir),
            )
        )
    return tuple(users)


def _parse_user_overrides(items: list[dict[str, object]]) -> tuple[UserOverride, ...]:
    overrides: list[UserOverride] = []
    for item in items:
        overrides.append(
            UserOverride(
                uid=int(item["uid"]),
                login_name=None if item.get("login_name") is None else str(item["login_name"]),
                display_name=None if item.get("display_name") is None else str(item["display_name"]),
                data_dir=None if item.get("data_dir") is None else str(item["data_dir"]),
                source=None if item.get("source") is None else str(item["source"]),
            )
        )
    return tuple(overrides)


def _resolve_path(raw_value: str, base_dir: Path) -> Path:
    path = Path(raw_value).expanduser()
    if not path.is_absolute():
        path = base_dir / path
    return path.resolve()


def _parse_string_tuple(value: object) -> tuple[str, ...]:
    if value is None:
        return tuple()
    if isinstance(value, str):
        return tuple(item.strip() for item in value.split(",") if item.strip())
    if isinstance(value, list):
        return tuple(str(item).strip() for item in value if str(item).strip())
    return tuple()


def _parse_time_window(raw_value: str) -> tuple[int, int]:
    text = raw_value.strip()
    if "-" not in text:
        raise ValueError(f"invalid free_traffic_windows item: {raw_value}")
    start_text, end_text = text.split("-", 1)
    return _parse_clock_minutes(start_text), _parse_clock_minutes(end_text)


def _parse_clock_minutes(raw_value: str) -> int:
    text = raw_value.strip()
    parts = text.split(":")
    if len(parts) != 2 or not all(part.isdigit() for part in parts):
        raise ValueError(f"invalid clock value: {raw_value}")
    hour = int(parts[0])
    minute = int(parts[1])
    if not (0 <= hour <= 23 and 0 <= minute <= 59):
        raise ValueError(f"invalid clock value: {raw_value}")
    return hour * 60 + minute


def load_config(path: str | Path) -> LabflowConfig:
    config_path = Path(path).expanduser().resolve()
    base_dir = config_path.parent
    raw = json.loads(config_path.read_text(encoding="utf-8"))
    external_interfaces = tuple(str(item) for item in raw.get("external_interfaces", []))
    if not external_interfaces:
        raise ValueError("config must define at least one external interface")
    return LabflowConfig(
        data_root=_resolve_path(str(raw.get("data_root", "/datas")), base_dir),
        db_path=_resolve_path(str(raw.get("db_path", "./labflow.db")), base_dir),
        table_name=str(raw.get("table_name", "labflow")),
        external_interfaces=external_interfaces,
        timezone=str(raw.get("timezone", "UTC")),
        total_monthly_quota_gb=(
            None
            if raw.get("total_monthly_quota_gb") is None
            else float(raw["total_monthly_quota_gb"])
        ),
        user_soft_limit_gb=(
            None if raw.get("user_soft_limit_gb") is None else float(raw["user_soft_limit_gb"])
        ),
        skip_hidden_dirs=bool(raw.get("skip_hidden_dirs", True)),
        exclude_dirs=tuple(str(item) for item in raw.get("exclude_dirs", [])),
        nft_binary=str(raw.get("nft_binary", "nft")),
        extra_users=_parse_extra_users(list(raw.get("extra_users", []))),
        user_overrides=_parse_user_overrides(list(raw.get("user_overrides", []))),
        free_traffic_windows=_parse_string_tuple(raw.get("free_traffic_windows")),
        daily_alert_gb=(
            None if raw.get("daily_alert_gb") is None else float(raw["daily_alert_gb"])
        ),
        alert_email_to=_parse_string_tuple(raw.get("alert_email_to")),
        smtp_host=None if raw.get("smtp_host") is None else str(raw["smtp_host"]),
        smtp_port=int(raw.get("smtp_port", 587)),
        smtp_username=None if raw.get("smtp_username") is None else str(raw["smtp_username"]),
        smtp_password=None if raw.get("smtp_password") is None else str(raw["smtp_password"]),
        smtp_password_env=None if raw.get("smtp_password_env") is None else str(raw["smtp_password_env"]),
        smtp_from=None if raw.get("smtp_from") is None else str(raw["smtp_from"]),
        smtp_use_tls=bool(raw.get("smtp_use_tls", True)),
        smtp_use_ssl=bool(raw.get("smtp_use_ssl", False)),
        smtp_subject_prefix=str(raw.get("smtp_subject_prefix", "[Labflow]")),
    )
