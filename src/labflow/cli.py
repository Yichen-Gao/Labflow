from __future__ import annotations

import argparse
import csv
import json
import subprocess
import sys
from pathlib import Path

from .config import load_config
from .db import Database
from .discovery import discover_users
from .interactive import CursesMonitor, InteractiveMenu
from .models import UserRecord
from .nftables import build_rules, install_rules, list_counters
from .systemd_assets import detect_default_interface, write_systemd_assets
from .utils import format_bytes, month_key, now_in_timezone


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="labflow", description="Per-UID traffic accounting")
    parser.add_argument(
        "--config",
        default="labflow.json",
        help="Path to a JSON config file (default: %(default)s)",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    init_config = subparsers.add_parser("init-config", help="Write a starter config file")
    init_config.add_argument("--force", action="store_true", help="Overwrite existing config")

    subparsers.add_parser("sync-users", help="Discover users from the data root and save them")

    show_users = subparsers.add_parser("show-users", help="List tracked users")
    show_users.add_argument("--all", action="store_true", help="Include inactive users")
    show_users.add_argument("--json", action="store_true", help="Emit JSON")

    subparsers.add_parser("render-rules", help="Print the nftables batch file")
    subparsers.add_parser("install-rules", help="Install nftables rules using the configured nft binary")
    subparsers.add_parser("collect", help="Read nft counters and persist usage deltas")
    subparsers.add_parser("detect-iface", help="Guess the default external interface from the routing table")

    write_systemd = subparsers.add_parser("write-systemd", help="Generate systemd units and helper scripts")
    write_systemd.add_argument(
        "--output-dir",
        default="contrib/systemd/generated",
        help="Where to write generated unit files",
    )
    write_systemd.add_argument(
        "--project-dir",
        default=str(Path(__file__).resolve().parents[2]),
        help="Project root used by generated helper scripts",
    )
    write_systemd.add_argument(
        "--python",
        default=sys.executable,
        help="Python interpreter path used in generated helper scripts",
    )
    write_systemd.add_argument(
        "--collect-every-minutes",
        type=int,
        default=1,
        help="How often the collector timer should run",
    )

    report = subparsers.add_parser("report", help="Show per-user traffic for one month")
    report.add_argument("--month", help="Month in YYYY-MM format; defaults to the current month")
    report.add_argument("--json", action="store_true", help="Emit JSON")

    top = subparsers.add_parser("top", help="Show the top N users for one month")
    top.add_argument("--month", help="Month in YYYY-MM format; defaults to the current month")
    top.add_argument("--limit", type=int, default=10, help="How many rows to show")
    top.add_argument("--json", action="store_true", help="Emit JSON")

    monitor = subparsers.add_parser("monitor", help="Full-screen monitor with arrow-key navigation")
    monitor.add_argument("--month", help="Month in YYYY-MM format; defaults to the current month")
    monitor.add_argument("--top-limit", type=int, default=10, help="How many users to show in previews")
    monitor.add_argument("--history-limit", type=int, default=12, help="How many history rows to show per user")
    monitor.add_argument(
        "--export-dir",
        default="exports",
        help="Where monitor exports should be written",
    )

    menu = subparsers.add_parser("menu", help="Interactive human-friendly menu")
    menu.add_argument("--month", help="Month in YYYY-MM format; defaults to the current month")
    menu.add_argument("--top-limit", type=int, default=10, help="How many users to show in previews")
    menu.add_argument("--history-limit", type=int, default=12, help="How many history rows to show per user")
    menu.add_argument(
        "--export-dir",
        default="exports",
        help="Where interactive exports should be written",
    )

    export_csv = subparsers.add_parser("export-csv", help="Export one month's ranked report to CSV")
    export_csv.add_argument("--month", help="Month in YYYY-MM format; defaults to the current month")
    export_csv.add_argument(
        "--output",
        default="-",
        help="CSV output path, or - for stdout (default: %(default)s)",
    )

    history = subparsers.add_parser("history", help="Show monthly history for one user")
    history.add_argument("selector", help="UID, login name, display name, or exact data_dir")
    history.add_argument("--limit", type=int, default=12, help="How many months to show")
    history.add_argument("--json", action="store_true", help="Emit JSON")

    check_quota = subparsers.add_parser("check-quota", help="Compare current month usage against quotas")
    check_quota.add_argument("--month", help="Month in YYYY-MM format; defaults to the current month")

    return parser


def load_runtime(config_path: str) -> tuple[object, Database]:
    config = load_config(config_path)
    db = Database(config)
    return config, db


def current_month(config) -> str:
    return month_key(now_in_timezone(config.timezone), config.timezone)


def _user_rows_to_json(rows) -> list[dict[str, object]]:
    return [dict(row) for row in rows]


def _write_report_csv(rows, month: str, output_path: str) -> None:
    fieldnames = [
        "month",
        "rank",
        "uid",
        "login_name",
        "display_name",
        "data_dir",
        "active",
        "rx_bytes",
        "tx_bytes",
        "total_bytes",
    ]
    if output_path != "-":
        Path(output_path).expanduser().resolve().parent.mkdir(parents=True, exist_ok=True)
    destination = sys.stdout if output_path == "-" else open(output_path, "w", encoding="utf-8", newline="")
    try:
        writer = csv.DictWriter(destination, fieldnames=fieldnames)
        writer.writeheader()
        for rank, row in enumerate(rows, start=1):
            writer.writerow(
                {
                    "month": month,
                    "rank": rank,
                    "uid": int(row["uid"]),
                    "login_name": row["login_name"],
                    "display_name": row["display_name"],
                    "data_dir": row["data_dir"] or "",
                    "active": int(row["active"]),
                    "rx_bytes": int(row["rx_bytes"]),
                    "tx_bytes": int(row["tx_bytes"]),
                    "total_bytes": int(row["total_bytes"]),
                }
            )
    finally:
        if destination is not sys.stdout:
            destination.close()


def _active_user_records(rows) -> list[UserRecord]:
    return [
        UserRecord(
            uid=int(row["uid"]),
            login_name=str(row["login_name"]),
            display_name=str(row["display_name"]),
            data_dir=row["data_dir"],
            source=str(row["source"]),
        )
        for row in rows
    ]


def _sorted_report_rows(rows) -> list[dict[str, object]]:
    normalized = [dict(row) for row in rows]
    return sorted(
        normalized,
        key=lambda row: (-int(row["total_bytes"]), int(row["uid"])),
    )


def _print_ranked_rows(rows: list[dict[str, object]]) -> None:
    for row in rows:
        print(
            f"uid={row['uid']} display={row['display_name']} total={format_bytes(int(row['total_bytes']))} "
            f"rx={format_bytes(int(row['rx_bytes']))} tx={format_bytes(int(row['tx_bytes']))}"
        )


def handle_init_config(args: argparse.Namespace) -> int:
    target = Path(args.config)
    example = target.parent / "labflow.example.json"
    if not example.exists():
        project_example = Path(__file__).resolve().parents[2] / "labflow.example.json"
        example = project_example
    if target.exists() and not args.force:
        print(f"Refusing to overwrite existing config: {target}", file=sys.stderr)
        return 1
    target.write_text(example.read_text(encoding="utf-8"), encoding="utf-8")
    print(f"Wrote starter config to {target}")
    return 0


def handle_sync_users(args: argparse.Namespace) -> int:
    config, db = load_runtime(args.config)
    result = discover_users(config)
    inserted, updated = db.sync_users(result.users, now_in_timezone(config.timezone))
    print(f"Synced {len(result.users)} users ({inserted} new, {updated} updated)")
    for conflict in result.conflicts:
        print(f"WARN: {conflict}")
    return 0


def handle_show_users(args: argparse.Namespace) -> int:
    _, db = load_runtime(args.config)
    rows = db.list_users(active_only=not args.all)
    if args.json:
        print(json.dumps(_user_rows_to_json(rows), ensure_ascii=False, indent=2))
        return 0
    if not rows:
        print("No users found")
        return 0
    for row in rows:
        state = "active" if row["active"] else "inactive"
        print(
            f"uid={row['uid']} login={row['login_name']} display={row['display_name']} "
            f"state={state} source={row['source']} data_dir={row['data_dir'] or '-'}"
        )
    return 0


def handle_render_rules(args: argparse.Namespace) -> int:
    _, db = load_runtime(args.config)
    config = load_config(args.config)
    users = _active_user_records(db.active_users())
    if not users:
        print("No active users in the database. Run sync-users first.", file=sys.stderr)
        return 1
    print(build_rules(config, users), end="")
    return 0


def handle_install_rules(args: argparse.Namespace) -> int:
    config, db = load_runtime(args.config)
    users = _active_user_records(db.active_users())
    if not users:
        print("No active users in the database. Run sync-users first.", file=sys.stderr)
        return 1
    rules_text = build_rules(config, users)
    install_rules(config, rules_text)
    print(f"Installed nftables rules for {len(users)} users into table {config.table_name}")
    return 0


def handle_collect(args: argparse.Namespace) -> int:
    config, db = load_runtime(args.config)
    absolute = list_counters(config)
    result = db.apply_counter_snapshot(now_in_timezone(config.timezone), absolute)
    print(
        f"Collected month={result.month} users={result.processed_users} "
        f"rx_delta={format_bytes(result.delta_rx_bytes)} tx_delta={format_bytes(result.delta_tx_bytes)}"
    )
    if result.reset_counters:
        print("Detected counter resets: " + ", ".join(result.reset_counters))
    return 0


def handle_detect_iface(_: argparse.Namespace) -> int:
    route_output = subprocess.run(
        ["ip", "route", "show", "default"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    iface = detect_default_interface(route_output)
    if iface is None:
        print("Could not detect a default interface", file=sys.stderr)
        return 1
    print(iface)
    return 0


def handle_write_systemd(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    paths = write_systemd_assets(
        project_dir=Path(args.project_dir),
        config_path=Path(args.config),
        python_bin=args.python,
        output_dir=Path(args.output_dir),
        collect_interval_minutes=args.collect_every_minutes,
    )
    print(f"Generated systemd assets for {config.db_path}:")
    for path in paths:
        print(path)
    return 0


def handle_report(args: argparse.Namespace) -> int:
    config, db = load_runtime(args.config)
    month = args.month or current_month(config)
    rows = _sorted_report_rows(db.monthly_report(month))
    if args.json:
        print(json.dumps(rows, ensure_ascii=False, indent=2))
        return 0
    total = db.month_total(month)
    print(f"Month: {month}")
    print(f"Total external traffic: {format_bytes(total)}")
    if config.total_monthly_quota_bytes:
        percent = (total / config.total_monthly_quota_bytes) * 100 if config.total_monthly_quota_bytes else 0
        print(f"Quota usage: {percent:.2f}% of {format_bytes(config.total_monthly_quota_bytes)}")
    if not rows:
        print("No usage recorded yet")
        return 0
    _print_ranked_rows(rows)
    return 0


def handle_top(args: argparse.Namespace) -> int:
    config, db = load_runtime(args.config)
    month = args.month or current_month(config)
    rows = _sorted_report_rows(db.monthly_report(month))[: max(args.limit, 0)]
    if args.json:
        print(json.dumps(rows, ensure_ascii=False, indent=2))
        return 0
    print(f"Month: {month}")
    print(f"Top {len(rows)} users by external traffic")
    if not rows:
        print("No usage recorded yet")
        return 0
    _print_ranked_rows(rows)
    return 0


def handle_monitor(args: argparse.Namespace) -> int:
    config, db = load_runtime(args.config)
    month = args.month or current_month(config)
    monitor = CursesMonitor(
        db=db,
        month=month,
        top_limit=args.top_limit,
        history_limit=args.history_limit,
        export_dir=args.export_dir,
    )
    return monitor.run()


def handle_menu(args: argparse.Namespace) -> int:
    config, db = load_runtime(args.config)
    month = args.month or current_month(config)
    menu = InteractiveMenu(
        db=db,
        month=month,
        top_limit=args.top_limit,
        history_limit=args.history_limit,
        export_dir=args.export_dir,
    )
    return menu.run()


def handle_export_csv(args: argparse.Namespace) -> int:
    config, db = load_runtime(args.config)
    month = args.month or current_month(config)
    rows = _sorted_report_rows(db.monthly_report(month))
    _write_report_csv(rows, month, args.output)
    if args.output != "-":
        print(f"Wrote {len(rows)} rows to {args.output}")
    return 0


def handle_history(args: argparse.Namespace) -> int:
    _, db = load_runtime(args.config)
    user = db.find_user(args.selector)
    if user is None:
        print(f"Unknown user selector: {args.selector}", file=sys.stderr)
        return 1
    rows = db.user_history(int(user["uid"]), limit=args.limit)
    if args.json:
        payload = {"user": dict(user), "history": _user_rows_to_json(rows)}
        print(json.dumps(payload, ensure_ascii=False, indent=2))
        return 0
    print(f"History for uid={user['uid']} display={user['display_name']} login={user['login_name']}")
    if not rows:
        print("No usage recorded yet")
        return 0
    for row in rows:
        print(
            f"month={row['month']} total={format_bytes(row['total_bytes'])} "
            f"rx={format_bytes(row['rx_bytes'])} tx={format_bytes(row['tx_bytes'])}"
        )
    return 0


def handle_check_quota(args: argparse.Namespace) -> int:
    config, db = load_runtime(args.config)
    month = args.month or current_month(config)
    rows = db.monthly_report(month)
    month_total = db.month_total(month)

    print(f"Month: {month}")
    print(f"Total external traffic: {format_bytes(month_total)}")
    if config.total_monthly_quota_bytes is not None:
        remaining = config.total_monthly_quota_bytes - month_total
        status = "OK" if remaining >= 0 else "EXCEEDED"
        print(
            f"Total quota status: {status} remaining={format_bytes(abs(remaining))} "
            f"quota={format_bytes(config.total_monthly_quota_bytes)}"
        )
    else:
        print("Total quota status: no total_monthly_quota_gb configured")

    if config.user_soft_limit_bytes is None:
        print("Per-user soft limit: not configured")
        return 0

    offenders = [row for row in rows if int(row["total_bytes"]) >= config.user_soft_limit_bytes]
    print(f"Per-user soft limit: {format_bytes(config.user_soft_limit_bytes)}")
    if not offenders:
        print("No users above the soft limit")
        return 0
    for row in offenders:
        print(f"SOFT-LIMIT uid={row['uid']} display={row['display_name']} total={format_bytes(row['total_bytes'])}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    handlers = {
        "init-config": handle_init_config,
        "sync-users": handle_sync_users,
        "show-users": handle_show_users,
        "render-rules": handle_render_rules,
        "install-rules": handle_install_rules,
        "collect": handle_collect,
        "detect-iface": handle_detect_iface,
        "write-systemd": handle_write_systemd,
        "report": handle_report,
        "top": handle_top,
        "monitor": handle_monitor,
        "menu": handle_menu,
        "export-csv": handle_export_csv,
        "history": handle_history,
        "check-quota": handle_check_quota,
    }
    return handlers[args.command](args)


if __name__ == "__main__":
    raise SystemExit(main())
