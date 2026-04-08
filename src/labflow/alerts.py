from __future__ import annotations

import smtplib
import ssl
from datetime import datetime, timedelta
from email.message import EmailMessage
from zoneinfo import ZoneInfo

from .db import Database
from .forensics import _is_background_command, load_command_events, load_recent_commands
from .utils import format_bytes, month_key


def _format_alert_command_line(ts: datetime | None, source: str, command: str) -> str:
    if ts is None:
        prefix = "未记时"
    else:
        prefix = ts.strftime("%m-%d %H:%M")
    return f"{prefix} [{source}] {command}"


def _peak_sample_for_day(
    db: Database,
    uid: int,
    start_ts: str,
    end_ts: str,
) -> dict[str, object] | None:
    samples = [dict(row) for row in db.user_samples_between(uid, start_ts, end_ts, limit=4000)]
    if not samples:
        return None
    return max(samples, key=lambda row: (int(row["total_bytes"]), str(row["ts"])))


def _command_summary_for_alert(
    login_name: str,
    data_dir: str | None,
    uid: int,
    peak_sample: dict[str, object] | None,
    timezone_name: str,
) -> tuple[list[str], list[str]]:
    if peak_sample is not None:
        center = datetime.fromisoformat(str(peak_sample["ts"]))
        events, notes = load_command_events(
            login_name=login_name,
            data_dir=data_dir,
            target_uid=uid,
            start=center - timedelta(minutes=15),
            end=center + timedelta(minutes=15),
            timezone_name=timezone_name,
        )
        visible = [event for event in events if not _is_background_command(event)]
        if visible:
            return [_format_alert_command_line(event.ts, event.source, event.command) for event in visible[:6]], notes

    recent, notes = load_recent_commands(
        login_name=login_name,
        data_dir=data_dir,
        target_uid=uid,
        timezone_name=timezone_name,
        limit=5,
        prefer_audit=False,
    )
    if recent:
        return [str(event.command) for event in recent[:5]], notes
    return [], notes


def _build_alert_subject(config, display_name: str, total_bytes: int, threshold_bytes: int) -> str:
    prefix = (config.smtp_subject_prefix or "").strip()
    core = f"{display_name} 今日流量 {format_bytes(total_bytes)} 超过阈值 {format_bytes(threshold_bytes)}"
    return f"{prefix} {core}".strip()


def _build_alert_body(config, db: Database, row: dict[str, object], threshold_bytes: int, now: datetime) -> str:
    timezone = ZoneInfo(config.timezone)
    today = now.astimezone(timezone)
    day_start = today.replace(hour=0, minute=0, second=0, microsecond=0)
    start_ts = day_start.isoformat(timespec="seconds")
    end_ts = today.isoformat(timespec="seconds")
    uid = int(row["uid"])
    month = month_key(today, config.timezone)
    month_row = db.user_month_usage(uid, month)
    peak_sample = _peak_sample_for_day(db, uid, start_ts, end_ts)
    command_lines, notes = _command_summary_for_alert(
        login_name=str(row["login_name"]),
        data_dir=None if row["data_dir"] is None else str(row["data_dir"]),
        uid=uid,
        peak_sample=peak_sample,
        timezone_name=config.timezone,
    )

    lines = [
        "Labflow 检测到单日流量异常阈值提醒。",
        "",
        f"日期：{today.strftime('%Y-%m-%d')}",
        f"用户：{row['display_name']} ({row['login_name']}, uid={uid})",
        f"今日总量：{format_bytes(int(row['total_bytes']))}",
        f"今日接收：{format_bytes(int(row['rx_bytes']))}",
        f"今日发送：{format_bytes(int(row['tx_bytes']))}",
        f"提醒阈值：{format_bytes(threshold_bytes)}",
    ]
    if month_row is not None:
        lines.append(f"本月累计：{format_bytes(int(month_row['total_bytes']))}")
    if peak_sample is not None:
        lines.extend(
            [
                "",
                "今日最大峰值：",
                f"- 时间：{str(peak_sample['ts']).replace('T', ' ')}",
                f"- 总量：{format_bytes(int(peak_sample['total_bytes']))}",
                f"- 接收：{format_bytes(int(peak_sample['rx_bytes']))}",
                f"- 发送：{format_bytes(int(peak_sample['tx_bytes']))}",
            ]
        )
    if command_lines:
        lines.extend(["", "峰值附近/最近命令："])
        lines.extend(f"- {line}" for line in command_lines)
    if notes:
        lines.extend(["", "备注："])
        lines.extend(f"- {note}" for note in notes[:3])
    lines.extend(
        [
            "",
            "排查建议：",
            f"- 在服务器上执行：lab trace {row['login_name']}",
            f"- 或进入监控界面后选中该用户，按 t 查看峰值附近命令",
        ]
    )
    return "\n".join(lines)


def send_smtp_email(config, subject: str, body: str) -> None:
    from_addr = config.smtp_from or config.smtp_username
    if not from_addr:
        raise ValueError("smtp_from 未配置")
    if not config.smtp_host:
        raise ValueError("smtp_host 未配置")
    recipients = list(config.smtp_recipients)
    if not recipients:
        raise ValueError("alert_email_to 未配置")

    message = EmailMessage()
    message["From"] = from_addr
    message["To"] = ", ".join(recipients)
    message["Subject"] = subject
    message.set_content(body)

    password = config.smtp_password_resolved
    username = config.smtp_username or from_addr
    timeout = 30
    if config.smtp_use_ssl:
        with smtplib.SMTP_SSL(config.smtp_host, config.smtp_port, timeout=timeout, context=ssl.create_default_context()) as server:
            if username and password:
                server.login(username, password)
            server.send_message(message)
        return

    with smtplib.SMTP(config.smtp_host, config.smtp_port, timeout=timeout) as server:
        server.ehlo()
        if config.smtp_use_tls:
            server.starttls(context=ssl.create_default_context())
            server.ehlo()
        if username and password:
            server.login(username, password)
        server.send_message(message)


def check_daily_alerts(config, db: Database, now: datetime, dry_run: bool = False) -> list[str]:
    threshold_bytes = config.daily_alert_bytes
    if threshold_bytes is None:
        return []

    today = now.astimezone(ZoneInfo(config.timezone))
    alert_date = today.strftime("%Y-%m-%d")
    start_ts = today.replace(hour=0, minute=0, second=0, microsecond=0).isoformat(timespec="seconds")
    end_ts = today.isoformat(timespec="seconds")
    rows = [dict(row) for row in db.daily_usage_between(start_ts, end_ts)]
    messages: list[str] = []

    for row in rows:
        total_bytes = int(row["total_bytes"])
        uid = int(row["uid"])
        if total_bytes < threshold_bytes:
            continue
        if db.has_daily_alert(alert_date, uid, threshold_bytes):
            continue

        subject = _build_alert_subject(config, str(row["display_name"]), total_bytes, threshold_bytes)
        body = _build_alert_body(config, db, row, threshold_bytes, today)
        if dry_run:
            messages.append(
                f"[dry-run] would alert {row['display_name']} uid={uid} total={format_bytes(total_bytes)}"
            )
            continue

        send_smtp_email(config, subject, body)
        db.record_daily_alert(
            alert_date=alert_date,
            uid=uid,
            threshold_bytes=threshold_bytes,
            observed_total_bytes=total_bytes,
            sent_at=today,
        )
        messages.append(
            f"Sent daily alert for {row['display_name']} uid={uid} total={format_bytes(total_bytes)}"
        )
    return messages
