from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class UserRecord:
    uid: int
    login_name: str
    display_name: str
    data_dir: str | None
    source: str = "datas"


@dataclass(frozen=True)
class DiscoveryResult:
    users: list[UserRecord]
    conflicts: list[str]


@dataclass(frozen=True)
class CollectResult:
    month: str
    processed_users: int
    delta_rx_bytes: int
    delta_tx_bytes: int
    reset_counters: list[str]
