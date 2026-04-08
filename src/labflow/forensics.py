from __future__ import annotations

import gzip
import pwd
import re
import shutil
import subprocess
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Iterable
from zoneinfo import ZoneInfo

_AUDIT_LINE_RE = re.compile(r"type=(\w+)\s+msg=audit\(([^)]+)\):\s*(.*)")
_KV_RE = re.compile(r'(\w+)=("([^"\\]|\\.)*"|\([^)]*\)|\S+)')
_BASH_TS_RE = re.compile(r"^#(\d{10,})$")
_ZSH_HISTORY_RE = re.compile(r"^: (\d+):\d+;(.*)$")
_FISH_CMD_RE = re.compile(r"^- cmd:\s*(.*)$")
_FISH_WHEN_RE = re.compile(r"^\s*when:\s*(\d+)\s*$")


@dataclass(frozen=True)
class CommandEvent:
    ts: datetime | None
    source: str
    command: str
    pid: int | None = None
    ppid: int | None = None
    uid: int | None = None
    auid: int | None = None
    exe: str | None = None
    cwd: str | None = None
    tty: str | None = None


def _unquote(value: str) -> str:
    if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
        value = bytes(value[1:-1], "utf-8").decode("unicode_escape")
    return _maybe_decode_hex(value)


def _maybe_decode_hex(value: str) -> str:
    if len(value) < 8 or len(value) % 2 != 0:
        return value
    if any(ch not in "0123456789abcdefABCDEF" for ch in value):
        return value
    try:
        decoded = bytes.fromhex(value)
    except ValueError:
        return value
    if not decoded:
        return value
    text = decoded.decode("utf-8", errors="replace")
    printable = sum(1 for char in text if char.isprintable() or char.isspace())
    if printable / max(len(text), 1) < 0.9:
        return value
    if any(marker in text for marker in ("/", " ", ".", "-", "_")):
        return text
    return value


def _parse_key_values(payload: str) -> dict[str, str]:
    return {match.group(1): _unquote(match.group(2)) for match in _KV_RE.finditer(payload)}


def _parse_uid(value: str | None) -> int | None:
    if value is None or not value.lstrip("-").isdigit():
        return None
    parsed = int(value)
    if parsed < 0 or parsed == 4294967295:
        return None
    return parsed


def _parse_audit_timestamp(msg_id: str, timezone_name: str) -> datetime | None:
    seconds_raw = msg_id.split(":", 1)[0]
    try:
        seconds = float(seconds_raw)
    except ValueError:
        return None
    return datetime.fromtimestamp(seconds, tz=ZoneInfo(timezone_name))


def parse_audit_exec_events(
    lines: Iterable[str],
    target_uid: int,
    start: datetime,
    end: datetime,
    timezone_name: str,
) -> list[CommandEvent]:
    grouped: dict[str, dict[str, object]] = {}

    for raw_line in lines:
        line = raw_line.strip()
        match = _AUDIT_LINE_RE.search(line)
        if match is None:
            continue
        record_type, msg_id, payload = match.groups()
        event = grouped.setdefault(
            msg_id,
            {
                "ts": _parse_audit_timestamp(msg_id, timezone_name),
                "argv": {},
                "uids": set(),
                "syscall": {},
                "cwd": None,
            },
        )
        if record_type == "SYSCALL":
            fields = _parse_key_values(payload)
            event["syscall"] = fields
            for key in ("uid", "auid", "euid", "suid", "fsuid"):
                uid_value = _parse_uid(fields.get(key))
                if uid_value is not None:
                    event["uids"].add(uid_value)
            continue
        if record_type == "EXECVE":
            fields = _parse_key_values(payload)
            argv = event["argv"]
            for key, value in fields.items():
                if key.startswith("a") and key[1:].isdigit():
                    argv[int(key[1:])] = value
            continue
        if record_type == "CWD":
            fields = _parse_key_values(payload)
            event["cwd"] = fields.get("cwd")

    results: list[CommandEvent] = []
    for event in grouped.values():
        ts = event["ts"]
        if not isinstance(ts, datetime) or ts < start or ts > end:
            continue
        if target_uid not in event["uids"]:
            continue
        syscall_fields = event["syscall"]
        argv = event["argv"]
        command = " ".join(str(argv[index]) for index in sorted(argv)) if argv else ""
        if not command:
            command = str(syscall_fields.get("comm") or syscall_fields.get("exe") or "(unknown)")
        results.append(
            CommandEvent(
                ts=ts,
                source="auditd",
                command=command,
                pid=_parse_uid(syscall_fields.get("pid")),
                ppid=_parse_uid(syscall_fields.get("ppid")),
                uid=_parse_uid(syscall_fields.get("uid")),
                auid=_parse_uid(syscall_fields.get("auid")),
                exe=None if syscall_fields.get("exe") is None else str(syscall_fields["exe"]),
                cwd=None if event["cwd"] is None else str(event["cwd"]),
                tty=None if syscall_fields.get("tty") is None else str(syscall_fields["tty"]),
            )
        )
    return sorted(results, key=lambda item: item.ts or datetime.min.replace(tzinfo=ZoneInfo(timezone_name)))


def parse_bash_history(text: str, timezone_name: str) -> list[CommandEvent]:
    tz = ZoneInfo(timezone_name)
    current_ts: datetime | None = None
    events: list[CommandEvent] = []
    for raw_line in text.splitlines():
        line = raw_line.rstrip("\n")
        ts_match = _BASH_TS_RE.match(line)
        if ts_match is not None:
            current_ts = datetime.fromtimestamp(int(ts_match.group(1)), tz=tz)
            continue
        stripped = line.strip()
        if not stripped:
            continue
        events.append(CommandEvent(ts=current_ts, source="bash_history", command=stripped))
        current_ts = None
    return events


def parse_zsh_history(text: str, timezone_name: str) -> list[CommandEvent]:
    tz = ZoneInfo(timezone_name)
    events: list[CommandEvent] = []
    for raw_line in text.splitlines():
        line = raw_line.rstrip("\n")
        match = _ZSH_HISTORY_RE.match(line)
        if match is None:
            continue
        ts = datetime.fromtimestamp(int(match.group(1)), tz=tz)
        events.append(CommandEvent(ts=ts, source="zsh_history", command=match.group(2).strip()))
    return events


def parse_fish_history(text: str, timezone_name: str) -> list[CommandEvent]:
    tz = ZoneInfo(timezone_name)
    events: list[CommandEvent] = []
    pending_command: str | None = None
    for raw_line in text.splitlines():
        line = raw_line.rstrip("\n")
        cmd_match = _FISH_CMD_RE.match(line)
        if cmd_match is not None:
            pending_command = cmd_match.group(1).strip()
            continue
        when_match = _FISH_WHEN_RE.match(line)
        if when_match is not None and pending_command:
            ts = datetime.fromtimestamp(int(when_match.group(1)), tz=tz)
            events.append(CommandEvent(ts=ts, source="fish_history", command=pending_command))
            pending_command = None
    return events


def _history_candidates(login_name: str, data_dir: str | None) -> list[Path]:
    bases: list[Path] = []
    if data_dir:
        bases.append(Path(data_dir))
    try:
        pw_record = pwd.getpwnam(login_name)
    except KeyError:
        pw_record = None
    if pw_record is not None:
        home_dir = Path(pw_record.pw_dir)
        if home_dir not in bases:
            bases.append(home_dir)
    seen: set[Path] = set()
    candidates: list[Path] = []
    for base in bases:
        for suffix in (".bash_history", ".zsh_history", ".local/share/fish/fish_history"):
            candidate = base / suffix
            if candidate in seen:
                continue
            seen.add(candidate)
            candidates.append(candidate)
    return candidates


def _filter_events(events: Iterable[CommandEvent], start: datetime, end: datetime) -> list[CommandEvent]:
    filtered: list[CommandEvent] = []
    for event in events:
        if event.ts is None:
            continue
        if start <= event.ts <= end:
            filtered.append(event)
    return filtered


def _read_text_maybe_gzip(path: Path) -> str:
    if path.suffix == ".gz":
        return gzip.open(path, "rt", encoding="utf-8", errors="replace").read()
    return path.read_text(encoding="utf-8", errors="replace")


def _read_tail_text(path: Path, max_bytes: int = 131072) -> str:
    with path.open("rb") as handle:
        handle.seek(0, 2)
        size = handle.tell()
        if size > max_bytes:
            handle.seek(-max_bytes, 2)
            chunk = handle.read()
            newline = chunk.find(b"\n")
            if newline >= 0:
                chunk = chunk[newline + 1 :]
        else:
            handle.seek(0)
            chunk = handle.read()
    return chunk.decode("utf-8", errors="replace")


def _ausearch_timestamp_parts(dt: datetime) -> tuple[str, str]:
    local = dt.astimezone(dt.tzinfo or ZoneInfo("UTC"))
    return local.strftime("%Y-%m-%d"), local.strftime("%H:%M:%S")


def _run_ausearch(
    target_uid: int,
    start: datetime | None,
    end: datetime | None,
    key: str = "labflow-exec",
) -> tuple[list[str], list[str]]:
    ausearch_bin = shutil.which("ausearch")
    if ausearch_bin is None:
        return [], ["系统里没有 `ausearch`，无法直接读取 auditd 审计结果"]

    command = [
        ausearch_bin,
        "--input-logs",
        "--format",
        "raw",
        "-m",
        "SYSCALL,EXECVE,CWD",
        "-ui",
        str(target_uid),
    ]
    if key:
        command.extend(["-k", key])
    if start is not None:
        start_date, start_time = _ausearch_timestamp_parts(start)
        command.extend(["-ts", start_date, start_time])
    if end is not None:
        end_date, end_time = _ausearch_timestamp_parts(end)
        command.extend(["-te", end_date, end_time])

    completed = subprocess.run(command, capture_output=True, text=True, check=False)
    stdout = completed.stdout or ""
    stderr = completed.stderr or ""
    if completed.returncode not in (0, 1):
        return [], [f"ausearch 执行失败：{stderr.strip() or f'退出码 {completed.returncode}'}"]
    if "You must be root" in stderr or "Only root" in stderr:
        return [], ["读取 auditd 审计结果需要 root 权限，建议用 sudo 打开"]
    lines = stdout.splitlines()
    return lines, []


def _load_recent_audit_events(
    target_uid: int,
    timezone_name: str,
    limit: int,
    lookback_minutes: int = 240,
) -> tuple[list[CommandEvent], list[str]]:
    notes: list[str] = []
    tz = ZoneInfo(timezone_name)
    end = datetime.now(tz)
    start = end - timedelta(minutes=max(lookback_minutes, 1))
    lines, ausearch_notes = _run_ausearch(target_uid=target_uid, start=start, end=end)
    notes.extend(ausearch_notes)
    if lines:
        all_events = parse_audit_exec_events_all(lines, target_uid=target_uid, timezone_name=timezone_name)
        if all_events:
            return list(reversed(all_events))[: max(limit, 1)], notes

    audit_paths = [path for path in sorted(Path("/var/log/audit").glob("audit.log*")) if path.is_file()]
    if not audit_paths and not notes:
        notes.append("未找到 auditd 审计日志")
    events: list[CommandEvent] = []
    for path in audit_paths:
        try:
            text = _read_text_maybe_gzip(path)
        except PermissionError:
            notes.append(f"auditd 日志不可读：{path}")
            continue
        events.extend(parse_audit_exec_events_all(text.splitlines(), target_uid=target_uid, timezone_name=timezone_name))
    if events:
        ordered = sorted(events, key=lambda item: item.ts or datetime.min.replace(tzinfo=ZoneInfo(timezone_name)), reverse=True)
        return ordered[: max(limit, 1)], notes
    return [], notes


def _is_background_command(event: CommandEvent | str) -> bool:
    command = event.command.strip() if isinstance(event, CommandEvent) else str(event).strip()
    if command in {
        "sleep 1",
        "grep socket:",
        "grep root",
        "ps -F -A -l",
        "free",
        "uptime",
        "df",
        "cat /proc/net/dev",
        "trae-helper",
    }:
        return True
    noisy_prefixes = (
        "cat /proc/",
        "sed -n s/^cpu",
        "ps -ax -o ",
        "/usr/bin/ps -ax -o ",
        "ps -HewO lstart ex",
        "bash -c ps -HewO lstart ex",
        "/bin/sh -c /usr/bin/ps -ax -o ",
        "/bin/sh -c which ps",
        "/bin/sh /usr/bin/which ps",
        "/bin/sh -c ps -F -A -l | grep root",
        "/bin/sh -c ls -l /proc/",
        "bash -c export LANG=\"en_US\";export LANGUAGE=\"en_US\";export LC_ALL=\"en_US\";free;",
        "kill -0 ",
        "ls -l /proc/",
    )
    if command.startswith(noisy_prefixes):
        return True
    if "finalshell_separator" in command:
        return True
    if "from labflow.forensics import load_recent_commands" in command:
        return True
    if command.startswith("/usr/sbin/ausearch "):
        return True
    if command == "env":
        return True
    if ".trae-server" in command and ("cpuUsage.sh" in command or "which ps" in command):
        return True
    return False


def parse_audit_exec_events_all(
    lines: Iterable[str],
    target_uid: int,
    timezone_name: str,
) -> list[CommandEvent]:
    start = datetime.min.replace(tzinfo=ZoneInfo(timezone_name))
    end = datetime.max.replace(tzinfo=ZoneInfo(timezone_name))
    return parse_audit_exec_events(lines, target_uid=target_uid, start=start, end=end, timezone_name=timezone_name)


def _load_shell_history_events(
    login_name: str,
    data_dir: str | None,
    timezone_name: str,
) -> tuple[list[CommandEvent], list[str], bool, bool]:
    events: list[CommandEvent] = []
    notes: list[str] = []
    history_events_found = False
    undated_history_found = False

    for path in _history_candidates(login_name, data_dir):
        try:
            exists = path.exists()
        except PermissionError:
            notes.append(f"shell history 不可读：{path}")
            continue
        if not exists:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except PermissionError:
            notes.append(f"shell history 不可读：{path}")
            continue
        if path.name == ".bash_history":
            parsed = parse_bash_history(text, timezone_name)
        elif path.name == ".zsh_history":
            parsed = parse_zsh_history(text, timezone_name)
        else:
            parsed = parse_fish_history(text, timezone_name)
        if parsed:
            history_events_found = True
            events.extend(parsed)
        if any(event.ts is None for event in parsed):
            undated_history_found = True

    return events, notes, history_events_found, undated_history_found


def _parse_quick_history_events(path: Path, text: str, timezone_name: str) -> list[CommandEvent]:
    if path.name == ".bash_history":
        parsed = parse_bash_history(text, timezone_name)
        if parsed:
            return parsed
        fallback: list[CommandEvent] = []
        for raw_line in text.splitlines():
            line = raw_line.strip()
            if not line or _BASH_TS_RE.match(line):
                continue
            fallback.append(CommandEvent(ts=None, source="bash_history", command=line))
        return fallback
    if path.name == ".zsh_history":
        return parse_zsh_history(text, timezone_name)
    return parse_fish_history(text, timezone_name)


def _load_recent_shell_events_quick(
    login_name: str,
    data_dir: str | None,
    timezone_name: str,
    limit: int,
) -> tuple[list[CommandEvent], list[str]]:
    notes: list[str] = []
    events: list[CommandEvent] = []
    history_found = False
    min_ts = datetime.min.replace(tzinfo=ZoneInfo(timezone_name))

    for path in _history_candidates(login_name, data_dir):
        try:
            exists = path.exists()
        except PermissionError:
            notes.append(f"shell history 不可读：{path}")
            continue
        if not exists:
            continue
        history_found = True
        try:
            text = _read_tail_text(path)
        except PermissionError:
            notes.append(f"shell history 不可读：{path}")
            continue
        parsed = _parse_quick_history_events(path, text, timezone_name)
        if not parsed:
            continue
        if any(event.ts is not None for event in parsed):
            ordered = sorted(parsed, key=lambda item: item.ts or min_ts, reverse=True)
        else:
            ordered = list(reversed(parsed))
        events.extend(ordered[: max(limit * 3, 12)])

    unique: dict[tuple[datetime | None, str, str], CommandEvent] = {}
    for event in events:
        unique[(event.ts, event.source, event.command)] = event

    timestamped = sorted([event for event in unique.values() if event.ts is not None], key=lambda item: item.ts or min_ts, reverse=True)
    undated = [event for event in unique.values() if event.ts is None]
    ordered = timestamped + undated
    if ordered:
        return ordered[: max(limit, 1)], notes
    if history_found and not notes:
        notes.append("找到了 shell history，但暂时没解析出可显示的命令")
    return [], notes


def load_command_events(
    login_name: str,
    data_dir: str | None,
    target_uid: int,
    start: datetime,
    end: datetime,
    timezone_name: str,
) -> tuple[list[CommandEvent], list[str]]:
    events: list[CommandEvent] = []
    notes: list[str] = []

    ausearch_lines, ausearch_notes = _run_ausearch(target_uid=target_uid, start=start, end=end)
    notes.extend(ausearch_notes)
    if ausearch_lines:
        events.extend(
            parse_audit_exec_events(
                ausearch_lines,
                target_uid=target_uid,
                start=start,
                end=end,
                timezone_name=timezone_name,
            )
        )
    elif not ausearch_notes:
        audit_paths = [path for path in sorted(Path("/var/log/audit").glob("audit.log*")) if path.is_file()]
        if audit_paths:
            audit_loaded = False
            for path in audit_paths:
                try:
                    text = _read_text_maybe_gzip(path)
                except PermissionError:
                    notes.append(f"auditd 日志不可读：{path}")
                    continue
                audit_loaded = True
                events.extend(
                    parse_audit_exec_events(
                        text.splitlines(),
                        target_uid=target_uid,
                        start=start,
                        end=end,
                        timezone_name=timezone_name,
                    )
                )
            if not audit_loaded:
                notes.append("找到 auditd 日志路径，但当前权限不足，建议用 sudo 运行 trace")
        else:
            notes.append("未找到 auditd 审计结果；如果想精确关联命令，请确认 execve 规则已经启用")

    history_events, history_notes, history_events_found, undated_history_found = _load_shell_history_events(
        login_name=login_name,
        data_dir=data_dir,
        timezone_name=timezone_name,
    )
    notes.extend(history_notes)
    timestamped = [event for event in history_events if event.ts is not None]
    if timestamped:
        events.extend(_filter_events(timestamped, start, end))

    if not history_events_found and undated_history_found:
        notes.append("找到了 shell history，但没有时间戳，无法和流量突增做可靠对齐")
    if history_events_found and not timestamped and undated_history_found:
        notes.append("找到了 shell history，但没有时间戳，无法和流量突增做可靠对齐")
    if history_events_found and not timestamped and not undated_history_found:
        notes.append("找到了 shell history，但没有可解析的时间戳")
    if not history_events_found:
        notes.append("未找到可用的带时间戳 shell history")

    unique: dict[tuple[datetime | None, str, str, int | None], CommandEvent] = {}
    for event in events:
        key = (event.ts, event.source, event.command, event.pid)
        unique[key] = event
    ordered = sorted(
        unique.values(),
        key=lambda item: item.ts or datetime.min.replace(tzinfo=ZoneInfo(timezone_name)),
    )
    return ordered, notes


def load_recent_commands(
    login_name: str,
    data_dir: str | None,
    target_uid: int,
    timezone_name: str,
    limit: int = 5,
    prefer_audit: bool = True,
) -> tuple[list[CommandEvent], list[str]]:
    notes: list[str] = []
    audit_events: list[CommandEvent] = []
    if prefer_audit:
        audit_events, audit_notes = _load_recent_audit_events(
            target_uid=target_uid,
            timezone_name=timezone_name,
            limit=max(limit * 3, 10),
            lookback_minutes=180,
        )
        notes.extend(audit_notes)
    else:
        quick_events, quick_notes = _load_recent_shell_events_quick(
            login_name=login_name,
            data_dir=data_dir,
            timezone_name=timezone_name,
            limit=max(limit, 1),
        )
        notes.extend(quick_notes)
        if quick_events:
            meaningful = [event for event in quick_events if not _is_background_command(event)]
            if meaningful:
                return meaningful[: max(limit, 1)], notes
            return quick_events[: max(limit, 1)], notes

    history_events, history_notes, history_found, undated_history_found = _load_shell_history_events(
        login_name=login_name,
        data_dir=data_dir,
        timezone_name=timezone_name,
    )
    notes.extend(history_notes)

    combined_timestamped = [event for event in audit_events]
    combined_timestamped.extend(event for event in history_events if event.ts is not None)
    if combined_timestamped:
        unique: dict[tuple[datetime | None, str, str, int | None], CommandEvent] = {}
        for event in combined_timestamped:
            key = (event.ts, event.source, event.command, event.pid)
            unique[key] = event
        ordered = sorted(
            unique.values(),
            key=lambda item: item.ts or datetime.min.replace(tzinfo=ZoneInfo(timezone_name)),
            reverse=True,
        )
        meaningful = [event for event in ordered if not _is_background_command(event)]
        if meaningful:
            return meaningful[: max(limit, 1)], notes
        if history_found and undated_history_found:
            fallback = list(reversed(history_events))
            notes.append("审计里最近大多是后台工具命令，已改用无时间戳的 shell history 近似展示")
            return fallback[: max(limit, 1)], notes
        return ordered[: max(limit, 1)], notes

    if history_found and undated_history_found:
        ordered = list(reversed(history_events))
        notes.append("以下命令来自无时间戳的 shell history，只能近似看作“最近执行过”")
        return ordered[: max(limit, 1)], notes

    if not history_found and not audit_events and not notes:
        notes.append("最近命令暂时不可用")
    return [], notes


def command_event_to_dict(event: CommandEvent) -> dict[str, object]:
    return {
        "ts": None if event.ts is None else event.ts.isoformat(timespec="seconds"),
        "source": event.source,
        "command": event.command,
        "pid": event.pid,
        "ppid": event.ppid,
        "uid": event.uid,
        "auid": event.auid,
        "exe": event.exe,
        "cwd": event.cwd,
        "tty": event.tty,
    }
