from __future__ import annotations

import csv
import curses
import os
import re
import textwrap
from datetime import datetime, timedelta
from pathlib import Path

from .db import Database
from .forensics import _is_background_command, load_command_events, load_recent_commands
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


def _command_source_label(source: str) -> str:
    labels = {
        "bash_history": "bash",
        "zsh_history": "zsh",
        "fish_history": "fish",
        "auditd": "audit",
    }
    return labels.get(source, source)


def _should_show_command_source(rows: list[dict[str, object]]) -> bool:
    normalized = {_command_source_label(str(row.get("source") or "")) for row in rows}
    normalized.discard("")
    return len(normalized) > 1 or ("audit" in normalized)


def _format_command_event_line(event: dict[str, object], show_source: bool = True) -> str:
    timestamp = event.get("ts")
    if isinstance(timestamp, datetime):
        prefix = timestamp.strftime("%m-%d %H:%M")
    elif isinstance(timestamp, str) and timestamp:
        prefix = timestamp[5:16].replace("T", " ")
    else:
        prefix = "未记时"
    command = str(event.get("command") or "(unknown)")
    if show_source:
        source = _command_source_label(str(event.get("source") or "history"))
        return f"{prefix} [{source}] {command}"
    return f"{prefix}  {command}"


def _recent_command_title(rows: list[dict[str, object]], notes: list[str]) -> str:
    if any("无时间戳" in note for note in notes):
        return "最近命令（无时间戳，按近似顺序）"
    if rows and any(str(row.get("source") or "") == "auditd" for row in rows):
        return "最近命令（含精确时间）"
    if any("需要 root" in note or "建议用 sudo" in note for note in notes):
        return "最近命令（建议用 sudo 打开）"
    return "最近命令"


def _humanize_command_note(notes: list[str], has_rows: bool) -> str | None:
    for note in notes:
        if "需要 root" in note or "建议用 sudo" in note:
            return "想看其他用户命令，建议用 sudo 打开"
    if not has_rows:
        for note in notes:
            if "auditd" in note:
                return "暂时还没有可用的审计记录"
            if "shell history 不可读" in note:
                return "当前权限读不到这个用户的 history"
    return None


def _format_sample_time(value: object) -> str:
    if isinstance(value, str) and "T" in value:
        return value[5:16].replace("T", " ")
    return str(value)


def _wrap_lines(lines: list[str], width: int) -> list[str]:
    wrapped: list[str] = []
    max_width = max(width, 8)
    for line in lines:
        if not line:
            wrapped.append("")
            continue
        pieces = textwrap.wrap(line, width=max_width, replace_whitespace=False, drop_whitespace=False)
        wrapped.extend(pieces or [""])
    return wrapped


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
        self.sample_cache: dict[int, list[dict[str, object]]] = {}
        self.command_cache: dict[int, list[dict[str, object]]] = {}
        self.command_notes_cache: dict[int, list[str]] = {}
        self.trace_cache: dict[tuple[int, str], tuple[list[dict[str, object]], list[str], datetime, datetime]] = {}
        self.colors: dict[str, int] = {}
        self.stdscr = None

    def refresh(self) -> None:
        self.rows, self.total_bytes = build_monitor_rows(self.db, self.month)
        self.history_cache.clear()
        self.sample_cache.clear()
        self.command_cache.clear()
        self.command_notes_cache.clear()
        self.trace_cache.clear()
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

    def _top_samples_for_selected(self, limit: int = 3) -> list[dict[str, object]]:
        row = self._selected_row()
        if row is None:
            return []
        uid = int(row["uid"])
        if uid not in self.sample_cache:
            self.sample_cache[uid] = [dict(item) for item in self.db.user_top_samples(uid, self.month, limit=max(limit, 1))]
        return self.sample_cache[uid][: max(limit, 1)]

    def _recent_commands_for_selected(self, limit: int = 5) -> tuple[list[dict[str, object]], list[str]]:
        row = self._selected_row()
        if row is None:
            return [], []
        uid = int(row["uid"])
        viewer_uid = int(os.environ.get("SUDO_UID") or os.getuid())
        if uid not in self.command_cache:
            events, notes = load_recent_commands(
                login_name=str(row["login_name"]),
                data_dir=None if row["data_dir"] is None else str(row["data_dir"]),
                target_uid=uid,
                timezone_name=self.db.config.timezone,
                limit=max(limit, 1),
                prefer_audit=(uid != viewer_uid),
            )
            self.command_cache[uid] = [
                {
                    "ts": event.ts,
                    "source": event.source,
                    "command": event.command,
                    "cwd": event.cwd,
                }
                for event in events
            ]
            self.command_notes_cache[uid] = list(notes)
        return self.command_cache[uid][: max(limit, 1)], self.command_notes_cache.get(uid, [])

    def _trace_for_sample(self, sample_row: dict[str, object], window_minutes: int = 20) -> tuple[list[dict[str, object]], list[str], datetime, datetime]:
        selected = self._selected_row()
        if selected is None:
            now = datetime.now()
            return [], [], now, now
        cache_key = (int(selected["uid"]), str(sample_row["ts"]))
        if cache_key not in self.trace_cache:
            center = datetime.fromisoformat(str(sample_row["ts"]))
            window = timedelta(minutes=max(window_minutes, 1))
            start = center - window
            end = center + window
            events, notes = load_command_events(
                login_name=str(selected["login_name"]),
                data_dir=None if selected["data_dir"] is None else str(selected["data_dir"]),
                target_uid=int(selected["uid"]),
                start=start,
                end=end,
                timezone_name=self.db.config.timezone,
            )
            self.trace_cache[cache_key] = (
                [
                    {
                        "ts": event.ts,
                        "source": event.source,
                        "command": event.command,
                        "cwd": event.cwd,
                        "pid": event.pid,
                    }
                    for event in events
                ],
                list(notes),
                start,
                end,
            )
        return self.trace_cache[cache_key]

    def _set_status(self, message: str) -> None:
        self.status_message = message

    def _move_selection(self, delta: int) -> None:
        if not self.filtered_rows:
            return
        self.selected = max(0, min(self.selected + delta, len(self.filtered_rows) - 1))

    def _visible_list_height(self, height: int) -> int:
        return max(height - 9, 3)

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

    def _init_colors(self) -> None:
        if not curses.has_colors():
            self.colors = {}
            return
        curses.start_color()
        try:
            curses.use_default_colors()
        except curses.error:
            pass
        palette = {
            "title": (curses.COLOR_BLACK, curses.COLOR_CYAN),
            "shortcuts": (curses.COLOR_BLACK, curses.COLOR_YELLOW),
            "border": (curses.COLOR_CYAN, -1),
            "pane_title": (curses.COLOR_GREEN, -1),
            "selected": (curses.COLOR_BLACK, curses.COLOR_GREEN),
            "row_alt": (curses.COLOR_CYAN, -1),
            "muted": (curses.COLOR_BLUE, -1),
            "accent": (curses.COLOR_MAGENTA, -1),
            "value": (curses.COLOR_GREEN, -1),
            "warning": (curses.COLOR_YELLOW, -1),
            "popup": (curses.COLOR_BLACK, curses.COLOR_WHITE),
            "popup_title": (curses.COLOR_BLACK, curses.COLOR_MAGENTA),
        }
        self.colors = {}
        for index, (name, (fg, bg)) in enumerate(palette.items(), start=1):
            try:
                curses.init_pair(index, fg, bg)
                self.colors[name] = curses.color_pair(index)
            except curses.error:
                self.colors[name] = 0

    def _color(self, name: str, extra: int = 0) -> int:
        return self.colors.get(name, 0) | extra

    def _draw_box(self, y: int, x: int, height: int, width: int, title: str, attr: int = 0) -> None:
        if height < 3 or width < 4:
            return
        try:
            self.stdscr.attron(attr)
            self.stdscr.addch(y, x, curses.ACS_ULCORNER)
            self.stdscr.hline(y, x + 1, curses.ACS_HLINE, width - 2)
            self.stdscr.addch(y, x + width - 1, curses.ACS_URCORNER)
            for row in range(y + 1, y + height - 1):
                self.stdscr.addch(row, x, curses.ACS_VLINE)
                self.stdscr.addch(row, x + width - 1, curses.ACS_VLINE)
            self.stdscr.addch(y + height - 1, x, curses.ACS_LLCORNER)
            self.stdscr.hline(y + height - 1, x + 1, curses.ACS_HLINE, width - 2)
            self.stdscr.addch(y + height - 1, x + width - 1, curses.ACS_LRCORNER)
            self.stdscr.attroff(attr)
        except curses.error:
            pass
        if title:
            self._draw_line(y, x + 2, max(width - 4, 0), f" {title} ", attr | curses.A_BOLD)

    def _draw_user_row(self, y: int, width: int, row: dict[str, object], selected: bool, zebra: bool) -> None:
        content_width = max(width - 4, 8)
        attr = 0
        if selected:
            attr = self._color("selected", curses.A_BOLD)
        elif zebra:
            attr = self._color("row_alt")
        self._draw_line(y, 2, content_width, " " * content_width, attr)
        rank_text = f"{int(row['rank']):>4}"
        total_text = f"{format_bytes(int(row['total_bytes'])):>12}"
        name_width = max(content_width - 4 - 2 - 12 - 2, 6)
        name_text = str(row["display_name"])[:name_width].ljust(name_width)
        self._draw_line(y, 2, 4, rank_text, attr)
        self._draw_line(y, 8, name_width, name_text, attr)
        self._draw_line(y, 8 + name_width + 2, 12, total_text, attr)

    def _draw(self) -> None:
        self.stdscr.erase()
        height, width = self.stdscr.getmaxyx()
        if height < 18 or width < 88:
            self._draw_line(0, 0, width, "窗口太小，建议至少调整到 88x18。", curses.A_BOLD)
            self._draw_line(2, 0, width, "按 q 退出。")
            self.stdscr.refresh()
            return

        self._draw_line(
            0,
            0,
            width,
            f" Labflow 监控  |  月份 {self.month}  |  总流量 {format_bytes(self.total_bytes)}  |  用户 {len(self.rows)} ",
            self._color("title", curses.A_BOLD),
        )
        query_text = self.query if self.query else "全部用户"
        self._draw_line(
            1,
            0,
            width,
            f" 筛选：{query_text}  |  / 搜索  c 清空  m 月份  t 追踪  e 导出排行  u 导出历史  r 刷新  q 退出 ",
            self._color("shortcuts"),
        )

        pane_top = 3
        pane_height = height - 6
        left_width = max(34, width * 2 // 5)
        left_width = min(left_width, width - 38)
        right_x = left_width + 1
        right_width = width - right_x
        visible_height = max(pane_height - 3, 3)
        self._ensure_visible(visible_height)

        self._draw_box(pane_top, 0, pane_height, left_width, "用户排行", self._color("border"))
        self._draw_box(pane_top, right_x, pane_height, right_width, "用户详情", self._color("border"))
        self._draw_line(
            pane_top + 1,
            2,
            left_width - 4,
            "序号  用户                       总流量",
            self._color("pane_title", curses.A_BOLD),
        )

        if not self.filtered_rows:
            self._draw_line(pane_top + 3, 2, left_width - 4, "没有匹配当前筛选条件的用户。", self._color("warning"))
        else:
            for index in range(visible_height):
                row_index = self.scroll_offset + index
                if row_index >= len(self.filtered_rows):
                    break
                row = self.filtered_rows[row_index]
                self._draw_user_row(
                    pane_top + 2 + index,
                    left_width,
                    row,
                    selected=(row_index == self.selected),
                    zebra=(row_index % 2 == 1),
                )

        selected = self._selected_row()
        if selected is None:
            self._draw_line(pane_top + 3, right_x + 2, right_width - 4, "当前没有选中用户。", self._color("warning"))
        else:
            percent = (int(selected["total_bytes"]) / self.total_bytes * 100) if self.total_bytes else 0.0
            detail_height = max(pane_height - 2, 8)
            detail_lines = [
                f"姓名：{selected['display_name']}",
                f"登录名：{selected['login_name']}",
                f"UID：{selected['uid']}   本月排名：{selected['rank']}",
                f"目录：{selected['data_dir'] or '-'}",
                f"本月总量：{format_bytes(int(selected['total_bytes']))}（占 {percent:.2f}%）",
                f"接收：{format_bytes(int(selected['rx_bytes']))}",
                f"发送：{format_bytes(int(selected['tx_bytes']))}",
            ]

            spike_rows = self._top_samples_for_selected(limit=3)
            detail_lines.extend(["", "本月峰值："])
            if spike_rows:
                for sample_row in spike_rows:
                    detail_lines.append(
                        f"{_format_sample_time(sample_row['ts'])}  "
                        f"{format_bytes(int(sample_row['total_bytes']))} "
                        f"(rx {format_bytes(int(sample_row['rx_bytes']))}, tx {format_bytes(int(sample_row['tx_bytes']))})"
                    )
            else:
                detail_lines.append("这个月还没有记录到峰值样本")

            command_rows, command_notes = self._recent_commands_for_selected(limit=5)
            command_title = _recent_command_title(command_rows, command_notes)
            command_show_source = _should_show_command_source(command_rows)
            detail_lines.extend(["", f"{command_title}："])
            if command_rows:
                for command_row in command_rows:
                    detail_lines.append(_format_command_event_line(command_row, show_source=command_show_source))
            else:
                fallback = _humanize_command_note(command_notes, has_rows=False)
                detail_lines.append(fallback or "暂时没有可显示的最近命令")

            detail_lines.extend(["", f"最近 {self.history_limit} 个月："])
            history_rows = self._history_for_selected()
            history_room = max(detail_height - len(detail_lines), 2)
            if history_rows:
                for history_row in history_rows[:history_room]:
                    detail_lines.append(
                        f"{history_row['month']}: {format_bytes(int(history_row['total_bytes']))} "
                        f"(rx {format_bytes(int(history_row['rx_bytes']))}, tx {format_bytes(int(history_row['tx_bytes']))})"
                    )
            else:
                detail_lines.append("这个月之前还没有历史记录")

            wrapped_detail_lines = _wrap_lines(detail_lines, right_width - 4)
            for offset, line in enumerate(wrapped_detail_lines[:detail_height]):
                attr = 0
                if line.endswith("："):
                    attr = self._color("pane_title", curses.A_BOLD)
                elif "这个月之前还没有历史记录" in line or "暂时没有可显示的最近命令" in line:
                    attr = self._color("muted")
                elif "本月总量" in line or "接收：" in line or "发送：" in line:
                    attr = self._color("value")
                self._draw_line(pane_top + 1 + offset, right_x + 2, right_width - 4, line, attr)

        self._draw_line(
            height - 2,
            0,
            width,
            " 方向键 / j k 移动  PgUp/PgDn 翻页  Home/End 跳转  Enter 聚焦  t 打开追踪窗口 ",
            self._color("muted"),
        )
        self._draw_line(height - 1, 0, width, f" 状态：{self.status_message} ", self._color("border"))
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
        self._set_status(f"已导出当月排行：{filename}")

    def _export_user_history(self) -> None:
        selected = self._selected_row()
        if selected is None:
            self._set_status("当前没有选中用户")
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
        self._set_status(f"已导出该用户历史：{filename}")

    def _change_month(self) -> None:
        result = self._prompt("输入月份 YYYY-MM（Esc 取消）：", self.month)
        if result is None:
            self._set_status("已取消切换月份")
            return
        if not MONTH_RE.match(result):
            self._set_status("月份格式不对，请用 YYYY-MM")
            return
        self.month = result
        self.selected = 0
        self.scroll_offset = 0
        self.refresh()
        self._set_status(f"已切换到 {self.month}")

    def _change_search(self) -> None:
        result = self._prompt("输入用户名 / 显示名 / UID（Esc 取消）：", self.query)
        if result is None:
            self._set_status("已取消搜索")
            return
        self.query = result
        self.selected = 0
        self.scroll_offset = 0
        self._apply_filter()
        if self.query:
            self._set_status(f"已按“{self.query}”筛选")
        else:
            self._set_status("已恢复全部用户")

    def _build_trace_lines(self, sample_index: int) -> tuple[list[str], int]:
        selected = self._selected_row()
        if selected is None:
            return ["当前没有选中用户。"], 0

        samples = self._top_samples_for_selected(limit=5)
        if not samples:
            return ["这个用户本月还没有峰值样本。"], 0

        sample_index = max(0, min(sample_index, len(samples) - 1))
        sample_row = samples[sample_index]
        events, notes, start, end = self._trace_for_sample(sample_row, window_minutes=20)
        visible_events = [row for row in events if not _is_background_command(str(row.get("command") or ""))]
        if visible_events:
            if len(visible_events) < len(events):
                notes = list(notes) + ["已自动隐藏一部分明显的后台探活命令"]
            events = visible_events
        show_source = _should_show_command_source(events)

        lines = [
            f"用户：{selected['display_name']}（{selected['login_name']} / uid={selected['uid']}）",
            f"正在查看峰值 {sample_index + 1}/{len(samples)}：{_format_sample_time(sample_row['ts'])}",
            f"峰值流量：{format_bytes(int(sample_row['total_bytes']))}  "
            f"(接收 {format_bytes(int(sample_row['rx_bytes']))} / 发送 {format_bytes(int(sample_row['tx_bytes']))})",
            f"追踪窗口：{start.strftime('%m-%d %H:%M:%S')} ~ {end.strftime('%m-%d %H:%M:%S')}",
            "",
            "本月峰值列表：",
        ]
        for index, row in enumerate(samples):
            marker = ">" if index == sample_index else " "
            lines.append(
                f"{marker} {_format_sample_time(row['ts'])}  {format_bytes(int(row['total_bytes']))}  "
                f"(接收 {format_bytes(int(row['rx_bytes']))} / 发送 {format_bytes(int(row['tx_bytes']))})"
            )

        lines.extend(["", "这个时间窗里的命令："])
        if events:
            for row in events[:20]:
                line = _format_command_event_line(row, show_source=show_source)
                if row.get("cwd"):
                    line = f"{line}  @ {row['cwd']}"
                lines.append(line)
        else:
            lines.append("这个时间窗里还没有能对齐上的命令记录。")

        if notes:
            lines.extend(["", "说明："])
            lines.extend(f"- {note}" for note in notes[:3])
        return lines, sample_index

    def _show_trace_popup(self) -> None:
        if self._selected_row() is None:
            self._set_status("当前没有选中用户")
            return
        samples = self._top_samples_for_selected(limit=5)
        if not samples:
            self._set_status("这个用户本月还没有峰值样本")
            return

        sample_index = 0
        scroll = 0
        while True:
            self._draw()
            height, width = self.stdscr.getmaxyx()
            popup_height = min(height - 4, 22)
            popup_width = min(width - 6, 112)
            popup_y = max((height - popup_height) // 2, 1)
            popup_x = max((width - popup_width) // 2, 2)
            visible_height = popup_height - 4

            lines, sample_index = self._build_trace_lines(sample_index)
            wrapped = _wrap_lines(lines, popup_width - 4)
            scroll = min(scroll, max(len(wrapped) - visible_height, 0))

            window = curses.newwin(popup_height, popup_width, popup_y, popup_x)
            window.bkgd(" ", self._color("popup"))
            window.erase()
            window.box()
            try:
                window.addnstr(
                    0,
                    2,
                    " 流量追踪 ",
                    popup_width - 4,
                    self._color("popup_title", curses.A_BOLD),
                )
            except curses.error:
                pass
            footer = "←/→ 切换峰值  ↑/↓ 滚动  r 重载  q 关闭"
            try:
                window.addnstr(
                    popup_height - 1,
                    2,
                    footer.ljust(popup_width - 4),
                    popup_width - 4,
                    self._color("pane_title"),
                )
            except curses.error:
                pass
            for offset, line in enumerate(wrapped[scroll : scroll + visible_height]):
                attr = 0
                if line.endswith("："):
                    attr = self._color("pane_title", curses.A_BOLD)
                elif line.startswith("> "):
                    attr = self._color("selected", curses.A_BOLD)
                elif line.startswith("- "):
                    attr = self._color("warning")
                try:
                    window.addnstr(1 + offset, 2, line.ljust(popup_width - 4), popup_width - 4, attr)
                except curses.error:
                    pass
            window.refresh()

            key = self.stdscr.getch()
            if key in (ord("q"), 27, ord("t")):
                self._set_status("已关闭追踪窗口")
                return
            if key in (curses.KEY_LEFT, ord("h")):
                sample_index = max(sample_index - 1, 0)
                scroll = 0
                continue
            if key in (curses.KEY_RIGHT, ord("l")):
                sample_index = min(sample_index + 1, len(samples) - 1)
                scroll = 0
                continue
            if key in (curses.KEY_UP, ord("k")):
                scroll = max(scroll - 1, 0)
                continue
            if key in (curses.KEY_DOWN, ord("j")):
                scroll = min(scroll + 1, max(len(wrapped) - visible_height, 0))
                continue
            if key in (ord("r"),):
                self.trace_cache.clear()
                continue

    def _main(self, stdscr) -> int:
        self.stdscr = stdscr
        self._init_colors()
        curses.curs_set(0)
        stdscr.keypad(True)
        self.refresh()
        self._set_status("就绪")
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
                self._set_status("已清空筛选")
                continue
            if key in (ord("m"),):
                self._change_month()
                continue
            if key in (ord("t"),):
                self._show_trace_popup()
                continue
            if key in (ord("e"),):
                self._export_month_csv()
                continue
            if key in (ord("u"),):
                self._export_user_history()
                continue
            if key in (ord("r"),):
                self.refresh()
                self._set_status("已刷新")
                continue
            if key in (10, 13):
                selected = self._selected_row()
                if selected is None:
                    self._set_status("当前没有选中用户")
                else:
                    self._set_status(
                        f"{selected['display_name']}：右侧可看流量、峰值、最近命令和历史"
                    )
                continue
            self._set_status("可用按键：方向键/jk、/、c、m、t、e、u、r、q")
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
