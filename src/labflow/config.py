from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path


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
    )
