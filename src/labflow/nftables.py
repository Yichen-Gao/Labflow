from __future__ import annotations

import json
import re
import subprocess
from typing import Iterable

from .config import LabflowConfig
from .models import UserRecord

COUNTER_RE = re.compile(r"^uid_(?P<uid>\d+)_(?P<direction>rx|tx)$")


def counter_name(uid: int, direction: str) -> str:
    return f"uid_{uid}_{direction}"


def _iface_expr(interfaces: tuple[str, ...]) -> str:
    if len(interfaces) == 1:
        return f'"{interfaces[0]}"'
    inner = ", ".join(f'"{item}"' for item in interfaces)
    return f"{{ {inner} }}"


def build_rules(config: LabflowConfig, users: Iterable[UserRecord]) -> str:
    table_name = config.table_name
    iface_expr = _iface_expr(config.external_interfaces)
    lines = [
        f"add table inet {table_name}",
        (
            f"add chain inet {table_name} output "
            "{ type filter hook output priority mangle; policy accept; }"
        ),
        (
            f"add chain inet {table_name} input "
            "{ type filter hook input priority mangle; policy accept; }"
        ),
    ]

    for user in sorted(users, key=lambda item: item.uid):
        lines.append(f"add counter inet {table_name} {counter_name(user.uid, 'tx')}")
        lines.append(f"add counter inet {table_name} {counter_name(user.uid, 'rx')}")

    for user in sorted(users, key=lambda item: item.uid):
        lines.append(
            f"add rule inet {table_name} output oifname {iface_expr} meta skuid {user.uid} "
            f"ct mark set {user.uid} counter name {counter_name(user.uid, 'tx')}"
        )
        lines.append(
            f"add rule inet {table_name} input iifname {iface_expr} ct mark {user.uid} "
            f"counter name {counter_name(user.uid, 'rx')}"
        )

    return "\n".join(lines) + "\n"


def install_rules(config: LabflowConfig, rules_text: str) -> None:
    subprocess.run(
        [config.nft_binary, "delete", "table", "inet", config.table_name],
        capture_output=True,
        text=True,
        check=False,
    )
    subprocess.run(
        [config.nft_binary, "-f", "-"],
        input=rules_text,
        text=True,
        check=True,
    )


def parse_counter_listing(payload: dict[str, object]) -> dict[int, dict[str, int]]:
    result: dict[int, dict[str, int]] = {}
    for item in payload.get("nftables", []):
        if not isinstance(item, dict):
            continue
        counter = item.get("counter")
        if not isinstance(counter, dict):
            continue
        name = counter.get("name")
        if not isinstance(name, str):
            continue
        match = COUNTER_RE.match(name)
        if not match:
            continue
        uid = int(match.group("uid"))
        direction = match.group("direction")
        bytes_value = int(counter.get("bytes", 0))
        result.setdefault(uid, {"rx": 0, "tx": 0})[direction] = bytes_value
    return result


def list_counters(config: LabflowConfig) -> dict[int, dict[str, int]]:
    raw = subprocess.run(
        [config.nft_binary, "-j", "list", "table", "inet", config.table_name],
        capture_output=True,
        text=True,
        check=True,
    )
    payload = json.loads(raw.stdout)
    return parse_counter_listing(payload)
