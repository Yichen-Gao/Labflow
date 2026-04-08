from __future__ import annotations

import csv
import curses
import re
from pathlib import Path

from .db import Database
from .utils import format_bytes

try:
    import readline  # type: ignore
except ImportError:  # pragma: no cover
    readline = None


MONTH_RE = re.compile(r"^\d{4}-\d{2}$")


def _score_user_match(row: dict[str, object], query: str) -> int | None:
    normalized = query.strip().lower()
    if not normalized:
        return None

    uid_text = str(row["uid"])
    login = str(row["login_name"]).lower()
    display = str(row["display_name"]).lower()
    data_dir = str(row.get("data_dir") or "").lower()
    score = 0

    if normalized == uid_text:
        score += 1000
    if normalized == login:
        score += 900
    if normalized == display:
        score += 850
    if normalized in data_dir:
        score += 300
    if login.startswith(normalized):
        score += 250
    if display.startswith(normalized):
        score += 220
    if normalized in login:
        score += 180
    if normalized in display:
        score += 160

    return score if score > 0 else None


def find_matching_users(rows, query: str, limit: int = 10) -> list[dict[str, object]]:
    scored: list[tuple[int, dict[str, object]]] = []
    for row in rows:
        normalized = dict(row)
        score = _score_user_match(normalized, query)
        if score is None:
            continue
        scored.append((score, normalized))
    scored.sort(key=lambda item: (-item[0], int(item[1]["uid"])))
    return [item[1] for item in scored[:limit]]


def sanitize_filename(value: str) -> str:
    sanitized = re.sub(r"[^A-Za-z0-9._-]+", "-", value.strip())
    sanitized = sanitized.strip("-._")
    return sanitized or "user"


def build_monitor_rows(db: Database, month: str) -> tuple[list[dict[str, object]], int]:
    users = [dict(row) for row in db.list_users(active_only=True)]
    usage_rows = [dict(row) for row in db.monthly_report(month)]
    usage_by_uid = {int(row["uid"]): row for row in usage_rows}

    merged: list[dict[str, object]] = []
    for user in users:
        uid = int(user["uid"])
        usage = usage_by_uid.get(uid)
        merged.append(
            {
                "uid": uid,
                "login_name": user["login_name"],
                "display_name": user["display_name"],
                "data_dir": user["data_dir"],
                "active": user["active"],
                "rx_bytes": int(usage["rx_bytes"]) if usage else 0,
                "tx_bytes": int(usage["tx_bytes"]) if usage else 0,
                "total_bytes": int(usage["total_bytes"]) if usage else 0,
            }
        )

    merged.sort(key=lambda row: (-int(row["total_bytes"]), int(row["uid"])))
    for index, row in enumerate(merged, start=1):
        row["rank"] = index
    total_bytes = sum(int(row["total_bytes"]) for row in merged)
    return merged, total_bytes


def _write_user_history_csv(rows, uid: int, login_name: str, display_name: str, output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "uid",
                "login_name",
                "display_name",
                "month",
                "rx_bytes",
                "tx_bytes",
                "total_bytes",
            ],
        )
        writer.writeheader()
        for row in rows:
            writer.writerow(
                {
                    "uid": uid,
                    "login_name": login_name,
                    "display_name": display_name,
                    "month": row["month"],
                    "rx_bytes": int(row["rx_bytes"]),
                    "tx_bytes": int(row["tx_bytes"]),
                    "total_bytes": int(row["total_bytes"]),
                }
            )


def _setup_readline_history(history_path: Path) -> None:
    if readline is None:
        return
    history_path.parent.mkdir(parents=True, exist_ok=True)
    if history_path.exists():
        try:
            readline.read_history_file(str(history_path))
        except OSError:
            pass


def _save_readline_history(history_path: Path) -> None:
    if readline is None:
        return
    try:
        readline.write_history_file(str(history_path))
    except OSError:
        pass


class CursesMonitor:
    def __init__(
        self,
        db: Database,
        month: str,
        top_limit: int = 10,
        history_limit: int = 12,
        export_dir: str = "exports",
    ):
        self.db = db
        self.month = month
        self.top_limit = max(top_limit, 1)
        self.history_limit = max(history_limit, 1)
        self.export_dir = Path(export_dir).expanduser().resolve()
        self.rows: list[dict[str, object]] = []
        self.filtered_rows: list[dict[str, object]] = []
        self.total_bytes = 0
        self.query = ""
        self.selected = 0
        self.scroll_offset = 0
        self.status_message = "Ready"
        self.history_cache: dict[int, list[dict[str, object]]] = {}
        self.stdscr = None

    def refresh(self) -> None:
        self.rows, self.total_bytes = build_monitor_rows(self.db, self.month)
        self.history_cache.clear()
        self._apply_filter()

    def _apply_filter(self) -> None:
        if not self.query:
            self.filtered_rows = list(self.rows)
        else:
            self.filtered_rows = find_matching_users(self.rows, self.query, limit=len(self.rows))
        if not self.filtered_rows:
            self.selected = 0
            self.scroll_offset = 0
            return
        self.selected = min(self.selected, len(self.filtered_rows) - 1)
        self.scroll_offset = min(self.scroll_offset, max(len(self.filtered_rows) - 1, 0))

    def _selected_row(self) -> dict[str, object] | None:
        if not self.filtered_rows:
            return None
        return self.filtered_rows[self.selected]

    def _history_for_selected(self) -> list[dict[str, object]]:
        row = self._selected_row()
        if row is None:
            return []
        uid = int(row["uid"])
        if uid not in self.history_cache:
            self.history_cache[uid] = [dict(item) for item in self.db.user_history(uid, limit=self.history_limit)]
        return self.history_cache[uid]

    def _set_status(self, message: str) -> None:
        self.status_message = message

    def _move_selection(self, delta: int) -> None:
        if not self.filtered_rows:
            return
        self.selected = max(0, min(self.selected + delta, len(self.filtered_rows) - 1))

    def _visible_list_height(self, height: int) -> int:
        return max(height - 6, 3)

    def _ensure_visible(self, visible_height: int) -> None:
        if self.selected < self.scroll_offset:
            self.scroll_offset = self.selected
        elif self.selected >= self.scroll_offset + visible_height:
            self.scroll_offset = self.selected - visible_height + 1

    def _draw_line(self, y: int, x: int, width: int, text: str, attr: int = 0) -> None:
        if width <= 0 or y < 0:
            return
        try:
            self.stdscr.addnstr(y, x, text.ljust(width), width, attr)
        except curses.error:
            pass

    def _draw(self) -> None:
        self.stdscr.erase()
        height, width = self.stdscr.getmaxyx()
        if height < 16 or width < 80:
            self._draw_line(0, 0, width, "Terminal too small for lab monitor. Resize to at least 80x16.", curses.A_BOLD)
            self._draw_line(2, 0, width, "Press q to quit.")
            self.stdscr.refresh()
            return

        self._draw_line(
            0,
            0,
            width,
            f"lab monitor | month {self.month} | total {format_bytes(self.total_bytes)} | users {len(self.rows)}",
            curses.A_BOLD,
        )
        query_text = self.query if self.query else "(all users)"
        self._draw_line(
            1,
            0,
            width,
            f"Search: {query_text} | / search  c clear  m month  e export month  u export user  r refresh  q quit",
        )

        left_width = max(32, width // 2)
        right_x = left_width + 1
        right_width = width - right_x - 1
        visible_height = self._visible_list_height(height)
        self._ensure_visible(visible_height)

        self._draw_line(3, 0, left_width, "Rank  User                         Total", curses.A_UNDERLINE)
        self._draw_line(3, right_x, right_width, "Selected user details", curses.A_UNDERLINE)

        if not self.filtered_rows:
            self._draw_line(5, 0, left_width, "No users match the current filter.")
        else:
            for index in range(visible_height):
                row_index = self.scroll_offset + index
                if row_index >= len(self.filtered_rows):
                    break
                row = self.filtered_rows[row_index]
                attr = curses.A_REVERSE if row_index == self.selected else 0
                label = (
                    f"{int(row['rank']):>4}  {str(row['display_name'])[:24]:<24} "
                    f"{format_bytes(int(row['total_bytes'])):>12}"
                )
                self._draw_line(4 + index, 0, left_width, label, attr)

        selected = self._selected_row()
        if selected is None:
            self._draw_line(5, right_x, right_width, "No user selected.")
        else:
            percent = (int(selected["total_bytes"]) / self.total_bytes * 100) if self.total_bytes else 0.0
            detail_lines = [
                f"Name: {selected['display_name']}",
                f"Login: {selected['login_name']}  UID: {selected['uid']}  Rank: {selected['rank']}",
                f"Path: {selected['data_dir'] or '-'}",
                f"Month total: {format_bytes(int(selected['total_bytes']))} ({percent:.2f}%)",
                f"RX: {format_bytes(int(selected['rx_bytes']))}",
                f"TX: {format_bytes(int(selected['tx_bytes']))}",
                "",
                f"Recent {self.history_limit} months:",
            ]
            history_rows = self._history_for_selected()
            if history_rows:
                for history_row in history_rows[: max(height - 14, 3)]:
                    detail_lines.append(
                        f"{history_row['month']}: {format_bytes(int(history_row['total_bytes']))} "
                        f"(rx {format_bytes(int(history_row['rx_bytes']))}, tx {format_bytes(int(history_row['tx_bytes']))})"
                    )
            else:
                detail_lines.append("No history recorded yet")

            for offset, line in enumerate(detail_lines):
                self._draw_line(4 + offset, right_x, right_width, line)

        self._draw_line(
            height - 2,
            0,
            width,
            "Arrows/j/k move  PgUp/PgDn scroll  Home/End jump  Enter keeps detail pane focused",
        )
        self._draw_line(height - 1, 0, width, f"Status: {self.status_message}")
        self.stdscr.refresh()

    def _prompt(self, prompt: str, initial: str = "") -> str | None:
        height, width = self.stdscr.getmaxyx()
        text = initial
        while True:
            self._draw_line(height - 1, 0, width, f"{prompt}{text}")
            try:
                key = self.stdscr.get_wch()
            except curses.error:
                return None
            if key in ("\n", "\r"):
                return text.strip()
            if key == "\x1b":
                return None
            if key in ("\b", "\x7f") or key == curses.KEY_BACKSPACE:
                text = text[:-1]
                continue
            if isinstance(key, str) and key.isprintable():
                text += key

    def _export_month_csv(self) -> None:
        from .cli import _write_report_csv  # local import avoids circular import

        filename = self.export_dir / f"usage-{self.month}.csv"
        _write_report_csv(self.filtered_rows or self.rows, self.month, str(filename))
        self._set_status(f"Exported month CSV to {filename}")

    def _export_user_history(self) -> None:
        selected = self._selected_row()
        if selected is None:
            self._set_status("No user selected")
            return
        filename = self.export_dir / (
            f"user-history-{sanitize_filename(str(selected['display_name']))}-{int(selected['uid'])}.csv"
        )
        _write_user_history_csv(
            self._history_for_selected(),
            uid=int(selected["uid"]),
            login_name=str(selected["login_name"]),
            display_name=str(selected["display_name"]),
            output_path=filename,
        )
        self._set_status(f"Exported user CSV to {filename}")

    def _change_month(self) -> None:
        result = self._prompt("Enter month YYYY-MM (Esc cancels): ", self.month)
        if result is None:
            self._set_status("Month change cancelled")
            return
        if not MONTH_RE.match(result):
            self._set_status("Invalid month format; use YYYY-MM")
            return
        self.month = result
        self.selected = 0
        self.scroll_offset = 0
        self.refresh()
        self._set_status(f"Switched to {self.month}")

    def _change_search(self) -> None:
        result = self._prompt("Search user (Esc cancels): ", self.query)
        if result is None:
            self._set_status("Search cancelled")
            return
        self.query = result
        self.selected = 0
        self.scroll_offset = 0
        self._apply_filter()
        if self.query:
            self._set_status(f"Filtered by '{self.query}'")
        else:
            self._set_status("Showing all users")

    def _main(self, stdscr) -> int:
        self.stdscr = stdscr
        curses.curs_set(0)
        stdscr.keypad(True)
        self.refresh()
        self._set_status("Ready")
        while True:
            self._draw()
            key = stdscr.getch()
            if key in (ord("q"), 27):
                return 0
            if key in (curses.KEY_UP, ord("k")):
                self._move_selection(-1)
                continue
            if key in (curses.KEY_DOWN, ord("j")):
                self._move_selection(1)
                continue
            if key == curses.KEY_PPAGE:
                self._move_selection(-self._visible_list_height(stdscr.getmaxyx()[0]) + 1)
                continue
            if key == curses.KEY_NPAGE:
                self._move_selection(self._visible_list_height(stdscr.getmaxyx()[0]) - 1)
                continue
            if key == curses.KEY_HOME:
                self.selected = 0
                continue
            if key == curses.KEY_END:
                if self.filtered_rows:
                    self.selected = len(self.filtered_rows) - 1
                continue
            if key in (ord("/"),):
                self._change_search()
                continue
            if key in (ord("c"),):
                self.query = ""
                self.selected = 0
                self.scroll_offset = 0
                self._apply_filter()
                self._set_status("Cleared search")
                continue
            if key in (ord("m"),):
                self._change_month()
                continue
            if key in (ord("e"),):
                self._export_month_csv()
                continue
            if key in (ord("u"),):
                self._export_user_history()
                continue
            if key in (ord("r"),):
                self.refresh()
                self._set_status("Refreshed")
                continue
            if key in (10, 13):
                selected = self._selected_row()
                if selected is None:
                    self._set_status("No user selected")
                else:
                    self._set_status(
                        f"{selected['display_name']} | total {format_bytes(int(selected['total_bytes']))} | "
                        f"history shown on the right"
                    )
                continue
            self._set_status("Keys: arrows/jk, /, c, m, e, u, r, q")
        return 0

    def run(self) -> int:
        return curses.wrapper(self._main)


class InteractiveMenu:
    def __init__(
        self,
        db: Database,
        month: str,
        top_limit: int = 10,
        history_limit: int = 12,
        export_dir: str = "exports",
    ):
        self.db = db
        self.month = month
        self.top_limit = max(top_limit, 1)
        self.history_limit = max(history_limit, 1)
        self.export_dir = Path(export_dir).expanduser().resolve()
        self.rows: list[dict[str, object]] = []
        self.rows_by_uid: dict[int, dict[str, object]] = {}
        self.total_bytes = 0
        self.users = []
        self.history_path = Path.home() / ".labflow_history"

    def refresh(self) -> None:
        from .cli import _sorted_report_rows  # local import avoids circular import

        self.rows = _sorted_report_rows(self.db.monthly_report(self.month))
        self.rows_by_uid = {int(row["uid"]): row for row in self.rows}
        self.total_bytes = self.db.month_total(self.month)
        self.users = [dict(row) for row in self.db.list_users(active_only=True)]

    def print_dashboard(self) -> None:
        self.refresh()
        print("\n=== labflow menu ===")
        print(f"Month: {self.month}")
        print(f"Total external traffic: {format_bytes(self.total_bytes)}")
        print(
            "Shortcuts: [t] top  [a] all  [k] quota  [e] export month CSV  "
            "[m] change month  [x] exit"
        )
        print("Tip: type a user name, display name, or UID directly.")
        print(f"Top preview (top {min(self.top_limit, len(self.rows))}):")
        if not self.rows:
            print("  No usage recorded yet")
            return
        for index, row in enumerate(self.rows[: self.top_limit], start=1):
            print(
                f"  {index:>2}. {row['display_name']} (uid={row['uid']}) "
                f"{format_bytes(int(row['total_bytes']))}"
            )

    def _show_all(self) -> None:
        print(f"\nRanking for {self.month} (descending by total traffic):")
        if not self.rows:
            print("No usage recorded yet")
            return
        for index, row in enumerate(self.rows, start=1):
            print(
                f"{index:>2}. {row['display_name']} (uid={row['uid']}) "
                f"total={format_bytes(int(row['total_bytes']))} "
                f"rx={format_bytes(int(row['rx_bytes']))} tx={format_bytes(int(row['tx_bytes']))}"
            )

    def _show_top(self) -> None:
        print(f"\nTop {min(self.top_limit, len(self.rows))} users for {self.month}:")
        if not self.rows:
            print("No usage recorded yet")
            return
        for index, row in enumerate(self.rows[: self.top_limit], start=1):
            print(
                f"{index:>2}. {row['display_name']} (uid={row['uid']}) "
                f"{format_bytes(int(row['total_bytes']))}"
            )

    def _show_quota(self) -> None:
        config = self.db.config
        print(f"\nQuota status for {self.month}:")
        print(f"Total external traffic: {format_bytes(self.total_bytes)}")
        if config.total_monthly_quota_bytes is not None:
            remaining = config.total_monthly_quota_bytes - self.total_bytes
            status = "OK" if remaining >= 0 else "EXCEEDED"
            print(
                f"Total quota: {status}  remaining={format_bytes(abs(remaining))}  "
                f"quota={format_bytes(config.total_monthly_quota_bytes)}"
            )
        else:
            print("Total quota: not configured")
        if config.user_soft_limit_bytes is None:
            print("User soft limit: not configured")
            return
        offenders = [row for row in self.rows if int(row["total_bytes"]) >= config.user_soft_limit_bytes]
        print(f"User soft limit: {format_bytes(config.user_soft_limit_bytes)}")
        if not offenders:
            print("No users above the soft limit")
            return
        for row in offenders:
            print(f"  - {row['display_name']} (uid={row['uid']}): {format_bytes(int(row['total_bytes']))}")

    def _export_month_csv(self) -> None:
        from .cli import _write_report_csv  # local import avoids circular import

        filename = self.export_dir / f"usage-{self.month}.csv"
        _write_report_csv(self.rows, self.month, str(filename))
        print(f"Exported monthly ranking to {filename}")

    def _change_month(self) -> None:
        raw = input("Enter month (YYYY-MM), or blank to keep current: ").strip()
        if not raw:
            return
        if not MONTH_RE.match(raw):
            print("Invalid month format. Use YYYY-MM, for example 2026-04.")
            return
        self.month = raw
        print(f"Switched to month {self.month}")

    def _select_user(self, query: str) -> dict[str, object] | None:
        matches = find_matching_users(self.users, query, limit=10)
        if not matches:
            print(f"No user matched: {query}")
            return None
        if len(matches) == 1:
            return matches[0]
        print("\nMatched users:")
        for index, row in enumerate(matches, start=1):
            print(
                f"  {index}. {row['display_name']} (login={row['login_name']}, uid={row['uid']}, "
                f"path={row['data_dir'] or '-'})"
            )
        choice = input("Select a number, or blank to cancel: ").strip()
        if not choice:
            return None
        if not choice.isdigit():
            print("Selection must be a number.")
            return None
        index = int(choice)
        if index < 1 or index > len(matches):
            print("Selection is out of range.")
            return None
        return matches[index - 1]

    def _show_user_month(self, user: dict[str, object]) -> None:
        uid = int(user["uid"])
        row = self.rows_by_uid.get(uid)
        rank = next((index for index, item in enumerate(self.rows, start=1) if int(item["uid"]) == uid), None)
        print(
            f"\nUser: {user['display_name']} (login={user['login_name']}, uid={uid}, "
            f"path={user['data_dir'] or '-'})"
        )
        if row is None:
            print(f"No traffic recorded for {self.month}.")
            return
        percent = (int(row["total_bytes"]) / self.total_bytes * 100) if self.total_bytes else 0.0
        print(f"Month: {self.month}")
        print(f"Rank: {rank}")
        print(f"Total: {format_bytes(int(row['total_bytes']))} ({percent:.2f}% of this month)")
        print(f"RX: {format_bytes(int(row['rx_bytes']))}")
        print(f"TX: {format_bytes(int(row['tx_bytes']))}")

    def _show_user_history(self, user: dict[str, object]) -> list[dict[str, object]]:
        rows = [dict(row) for row in self.db.user_history(int(user["uid"]), limit=self.history_limit)]
        print(f"\nRecent {self.history_limit} months for {user['display_name']}:")
        if not rows:
            print("No usage recorded yet")
            return rows
        for row in rows:
            print(
                f"  {row['month']}: total={format_bytes(int(row['total_bytes']))} "
                f"rx={format_bytes(int(row['rx_bytes']))} tx={format_bytes(int(row['tx_bytes']))}"
            )
        return rows

    def _export_user_history(self, user: dict[str, object]) -> None:
        rows = [dict(row) for row in self.db.user_history(int(user["uid"]), limit=self.history_limit)]
        filename = self.export_dir / (
            f"user-history-{sanitize_filename(str(user['display_name']))}-{int(user['uid'])}.csv"
        )
        _write_user_history_csv(
            rows,
            uid=int(user["uid"]),
            login_name=str(user["login_name"]),
            display_name=str(user["display_name"]),
            output_path=filename,
        )
        print(f"Exported user history to {filename}")

    def _user_menu(self, user: dict[str, object]) -> bool:
        while True:
            self.refresh()
            self._show_user_month(user)
            print("User actions: [m] month  [h] history  [e] export history CSV  [b] back  [x] exit")
            command = input(f"user:{user['display_name']}> ").strip().lower()
            if command in ("", "m"):
                continue
            if command in ("b", "back"):
                return False
            if command in ("x", "exit", "q", "quit"):
                return True
            if command in ("h", "history"):
                self._show_user_history(user)
                continue
            if command in ("e", "export"):
                self._export_user_history(user)
                continue
            print("Unknown action. Use m, h, e, b, or x.")

    def run(self) -> int:
        _setup_readline_history(self.history_path)
        try:
            while True:
                self.print_dashboard()
                command = input("menu> ").strip()
                lowered = command.lower()
                if lowered in ("x", "exit", "quit", "q"):
                    return 0
                if lowered in ("", "r", "refresh"):
                    continue
                if lowered in ("t", "top"):
                    self._show_top()
                    continue
                if lowered in ("a", "all", "report"):
                    self._show_all()
                    continue
                if lowered in ("k", "quota"):
                    self._show_quota()
                    continue
                if lowered in ("e", "export"):
                    self._export_month_csv()
                    continue
                if lowered in ("m", "month"):
                    self._change_month()
                    continue
                if lowered in ("h", "help", "?"):
                    print(
                        "\nCommands: t=top, a=all ranking, k=quota, e=export monthly CSV, "
                        "m=change month, x=exit"
                    )
                    print("Type a user name, display name, or UID to open a user menu.")
                    continue

                user = self._select_user(command)
                if user is None:
                    continue
                if self._user_menu(user):
                    return 0
        finally:
            _save_readline_history(self.history_path)
