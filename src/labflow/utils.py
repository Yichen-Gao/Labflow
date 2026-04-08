from __future__ import annotations

from datetime import datetime
from zoneinfo import ZoneInfo


def now_in_timezone(timezone_name: str) -> datetime:
    return datetime.now(ZoneInfo(timezone_name))


def month_key(dt: datetime, timezone_name: str) -> str:
    local_dt = dt.astimezone(ZoneInfo(timezone_name))
    return local_dt.strftime("%Y-%m")


def format_bytes(value: int) -> str:
    units = ["B", "KiB", "MiB", "GiB", "TiB"]
    size = float(value)
    unit = units[0]
    for unit in units:
        if size < 1024.0 or unit == units[-1]:
            break
        size /= 1024.0
    if unit == "B":
        return f"{int(size)} {unit}"
    return f"{size:.2f} {unit}"
