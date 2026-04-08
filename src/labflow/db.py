from __future__ import annotations

import sqlite3
from collections import defaultdict
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Iterable, Iterator

from .config import LabflowConfig
from .models import CollectResult, UserRecord
from .utils import month_key

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    uid INTEGER PRIMARY KEY,
    login_name TEXT NOT NULL,
    display_name TEXT NOT NULL,
    data_dir TEXT,
    source TEXT NOT NULL,
    active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS samples (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    month TEXT NOT NULL,
    uid INTEGER NOT NULL,
    rx_bytes INTEGER NOT NULL DEFAULT 0,
    tx_bytes INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS monthly_usage (
    month TEXT NOT NULL,
    uid INTEGER NOT NULL,
    rx_bytes INTEGER NOT NULL DEFAULT 0,
    tx_bytes INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (month, uid)
);

CREATE TABLE IF NOT EXISTS counter_state (
    counter_key TEXT PRIMARY KEY,
    bytes INTEGER NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS daily_alerts (
    alert_date TEXT NOT NULL,
    uid INTEGER NOT NULL,
    threshold_bytes INTEGER NOT NULL,
    observed_total_bytes INTEGER NOT NULL,
    sent_at TEXT NOT NULL,
    PRIMARY KEY (alert_date, uid, threshold_bytes)
);

CREATE INDEX IF NOT EXISTS idx_samples_month_uid ON samples(month, uid);
CREATE INDEX IF NOT EXISTS idx_monthly_usage_month ON monthly_usage(month);
CREATE INDEX IF NOT EXISTS idx_daily_alerts_date ON daily_alerts(alert_date);
"""


class Database:
    def __init__(self, config: LabflowConfig):
        self.config = config
        self.db_path = config.db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as conn:
            conn.executescript(SCHEMA)

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def sync_users(self, users: Iterable[UserRecord], ts: datetime) -> tuple[int, int]:
        timestamp = ts.isoformat(timespec="seconds")
        incoming = list(users)
        active_uids = {user.uid for user in incoming}
        inserted = 0
        updated = 0
        with self.connect() as conn:
            for user in incoming:
                row = conn.execute(
                    "SELECT uid, login_name, display_name, data_dir, source, active FROM users WHERE uid = ?",
                    (user.uid,),
                ).fetchone()
                if row is None:
                    conn.execute(
                        """
                        INSERT INTO users(uid, login_name, display_name, data_dir, source, active, created_at, updated_at)
                        VALUES (?, ?, ?, ?, ?, 1, ?, ?)
                        """,
                        (
                            user.uid,
                            user.login_name,
                            user.display_name,
                            user.data_dir,
                            user.source,
                            timestamp,
                            timestamp,
                        ),
                    )
                    inserted += 1
                    continue
                if (
                    row["login_name"],
                    row["display_name"],
                    row["data_dir"],
                    row["source"],
                    row["active"],
                ) != (user.login_name, user.display_name, user.data_dir, user.source, 1):
                    conn.execute(
                        """
                        UPDATE users
                        SET login_name = ?, display_name = ?, data_dir = ?, source = ?, active = 1, updated_at = ?
                        WHERE uid = ?
                        """,
                        (
                            user.login_name,
                            user.display_name,
                            user.data_dir,
                            user.source,
                            timestamp,
                            user.uid,
                        ),
                    )
                    updated += 1
            if active_uids:
                placeholders = ", ".join("?" for _ in active_uids)
                conn.execute(
                    f"UPDATE users SET active = 0, updated_at = ? WHERE uid NOT IN ({placeholders}) AND active = 1",
                    (timestamp, *sorted(active_uids)),
                )
            else:
                conn.execute("UPDATE users SET active = 0, updated_at = ? WHERE active = 1", (timestamp,))
        return inserted, updated

    def list_users(self, active_only: bool = True) -> list[sqlite3.Row]:
        clause = "WHERE active = 1" if active_only else ""
        with self.connect() as conn:
            return conn.execute(
                f"SELECT uid, login_name, display_name, data_dir, source, active FROM users {clause} ORDER BY uid"
            ).fetchall()

    def find_user(self, selector: str) -> sqlite3.Row | None:
        with self.connect() as conn:
            if selector.isdigit():
                row = conn.execute(
                    "SELECT uid, login_name, display_name, data_dir, source, active FROM users WHERE uid = ?",
                    (int(selector),),
                ).fetchone()
                if row is not None:
                    return row
            return conn.execute(
                """
                SELECT uid, login_name, display_name, data_dir, source, active
                FROM users
                WHERE login_name = ? OR display_name = ? OR data_dir = ?
                ORDER BY active DESC, uid ASC
                LIMIT 1
                """,
                (selector, selector, selector),
            ).fetchone()

    def active_users(self) -> list[sqlite3.Row]:
        return self.list_users(active_only=True)

    def _load_counter_state(self, conn: sqlite3.Connection) -> dict[str, int]:
        rows = conn.execute("SELECT counter_key, bytes FROM counter_state").fetchall()
        return {row["counter_key"]: int(row["bytes"]) for row in rows}

    def apply_counter_snapshot(
        self,
        ts: datetime,
        absolute_counters: dict[int, dict[str, int]],
    ) -> CollectResult:
        month = month_key(ts, self.config.timezone)
        timestamp = ts.isoformat(timespec="seconds")
        delta_by_uid: dict[int, dict[str, int]] = defaultdict(lambda: {"rx": 0, "tx": 0})
        current_state: dict[str, int] = {}
        reset_counters: list[str] = []

        with self.connect() as conn:
            previous_state = self._load_counter_state(conn)
            for uid, values in absolute_counters.items():
                for direction in ("rx", "tx"):
                    current = int(values.get(direction, 0))
                    key = f"uid:{uid}:{direction}"
                    previous = previous_state.get(key)
                    if previous is None:
                        delta = current
                    elif current < previous:
                        delta = current
                        reset_counters.append(key)
                    else:
                        delta = current - previous
                    delta_by_uid[uid][direction] += delta
                    current_state[key] = current

            for uid, deltas in delta_by_uid.items():
                if deltas["rx"] == 0 and deltas["tx"] == 0:
                    continue
                conn.execute(
                    "INSERT INTO samples(ts, month, uid, rx_bytes, tx_bytes) VALUES (?, ?, ?, ?, ?)",
                    (timestamp, month, uid, deltas["rx"], deltas["tx"]),
                )
                conn.execute(
                    """
                    INSERT INTO monthly_usage(month, uid, rx_bytes, tx_bytes)
                    VALUES (?, ?, ?, ?)
                    ON CONFLICT(month, uid) DO UPDATE SET
                        rx_bytes = rx_bytes + excluded.rx_bytes,
                        tx_bytes = tx_bytes + excluded.tx_bytes
                    """,
                    (month, uid, deltas["rx"], deltas["tx"]),
                )

            for key, value in current_state.items():
                conn.execute(
                    """
                    INSERT INTO counter_state(counter_key, bytes, updated_at)
                    VALUES (?, ?, ?)
                    ON CONFLICT(counter_key) DO UPDATE SET
                        bytes = excluded.bytes,
                        updated_at = excluded.updated_at
                    """,
                    (key, value, timestamp),
                )

        total_rx = sum(item["rx"] for item in delta_by_uid.values())
        total_tx = sum(item["tx"] for item in delta_by_uid.values())
        return CollectResult(
            month=month,
            processed_users=len(absolute_counters),
            delta_rx_bytes=total_rx,
            delta_tx_bytes=total_tx,
            reset_counters=sorted(reset_counters),
        )

    def monthly_report(self, month: str) -> list[sqlite3.Row]:
        with self.connect() as conn:
            return conn.execute(
                """
                SELECT
                    mu.month,
                    mu.uid,
                    mu.rx_bytes,
                    mu.tx_bytes,
                    (mu.rx_bytes + mu.tx_bytes) AS total_bytes,
                    COALESCE(u.login_name, printf('uid_%d', mu.uid)) AS login_name,
                    COALESCE(u.display_name, printf('uid_%d', mu.uid)) AS display_name,
                    u.data_dir,
                    COALESCE(u.active, 0) AS active
                FROM monthly_usage mu
                LEFT JOIN users u ON u.uid = mu.uid
                WHERE mu.month = ?
                ORDER BY total_bytes DESC, mu.uid ASC
                """,
                (month,),
            ).fetchall()

    def month_total(self, month: str) -> int:
        with self.connect() as conn:
            row = conn.execute(
                "SELECT COALESCE(SUM(rx_bytes + tx_bytes), 0) AS total FROM monthly_usage WHERE month = ?",
                (month,),
            ).fetchone()
            return int(row["total"])

    def user_history(self, uid: int, limit: int = 12) -> list[sqlite3.Row]:
        with self.connect() as conn:
            return conn.execute(
                """
                SELECT month, uid, rx_bytes, tx_bytes, (rx_bytes + tx_bytes) AS total_bytes
                FROM monthly_usage
                WHERE uid = ?
                ORDER BY month DESC
                LIMIT ?
                """,
                (uid, limit),
            ).fetchall()

    def user_top_samples(self, uid: int, month: str, limit: int = 10) -> list[sqlite3.Row]:
        with self.connect() as conn:
            return conn.execute(
                """
                SELECT ts, month, uid, rx_bytes, tx_bytes, (rx_bytes + tx_bytes) AS total_bytes
                FROM samples
                WHERE uid = ? AND month = ?
                ORDER BY total_bytes DESC, ts DESC
                LIMIT ?
                """,
                (uid, month, limit),
            ).fetchall()

    def user_samples_between(self, uid: int, start_ts: str, end_ts: str, limit: int = 200) -> list[sqlite3.Row]:
        with self.connect() as conn:
            return conn.execute(
                """
                SELECT ts, month, uid, rx_bytes, tx_bytes, (rx_bytes + tx_bytes) AS total_bytes
                FROM samples
                WHERE uid = ? AND ts >= ? AND ts <= ?
                ORDER BY ts ASC
                LIMIT ?
                """,
                (uid, start_ts, end_ts, limit),
            ).fetchall()

    def daily_usage_between(self, start_ts: str, end_ts: str) -> list[sqlite3.Row]:
        with self.connect() as conn:
            return conn.execute(
                """
                SELECT
                    s.uid,
                    COALESCE(u.login_name, printf('uid_%d', s.uid)) AS login_name,
                    COALESCE(u.display_name, printf('uid_%d', s.uid)) AS display_name,
                    u.data_dir,
                    COALESCE(SUM(s.rx_bytes), 0) AS rx_bytes,
                    COALESCE(SUM(s.tx_bytes), 0) AS tx_bytes,
                    COALESCE(SUM(s.rx_bytes + s.tx_bytes), 0) AS total_bytes
                FROM samples s
                LEFT JOIN users u ON u.uid = s.uid
                WHERE s.ts >= ? AND s.ts <= ?
                GROUP BY s.uid, u.login_name, u.display_name, u.data_dir
                ORDER BY total_bytes DESC, s.uid ASC
                """,
                (start_ts, end_ts),
            ).fetchall()

    def user_month_usage(self, uid: int, month: str) -> sqlite3.Row | None:
        with self.connect() as conn:
            return conn.execute(
                """
                SELECT month, uid, rx_bytes, tx_bytes, (rx_bytes + tx_bytes) AS total_bytes
                FROM monthly_usage
                WHERE uid = ? AND month = ?
                LIMIT 1
                """,
                (uid, month),
            ).fetchone()

    def has_daily_alert(self, alert_date: str, uid: int, threshold_bytes: int) -> bool:
        with self.connect() as conn:
            row = conn.execute(
                """
                SELECT 1
                FROM daily_alerts
                WHERE alert_date = ? AND uid = ? AND threshold_bytes = ?
                LIMIT 1
                """,
                (alert_date, uid, threshold_bytes),
            ).fetchone()
            return row is not None

    def record_daily_alert(
        self,
        alert_date: str,
        uid: int,
        threshold_bytes: int,
        observed_total_bytes: int,
        sent_at: datetime,
    ) -> None:
        with self.connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO daily_alerts(
                    alert_date, uid, threshold_bytes, observed_total_bytes, sent_at
                )
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    alert_date,
                    uid,
                    threshold_bytes,
                    observed_total_bytes,
                    sent_at.isoformat(timespec="seconds"),
                ),
            )
