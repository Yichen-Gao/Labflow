from __future__ import annotations

import csv
import tempfile
import unittest
from datetime import datetime
from pathlib import Path
import pwd
from zoneinfo import ZoneInfo

from labflow.config import LabflowConfig
from labflow.db import Database
from labflow.discovery import discover_users
from labflow.cli import _sorted_report_rows, _write_report_csv
from labflow.forensics import (
    CommandEvent,
    load_recent_commands,
    parse_audit_exec_events,
    parse_bash_history,
    parse_zsh_history,
)
from labflow.interactive import (
    _display_width,
    _fit_display,
    _trim_to_width,
    _wrap_lines,
    build_monitor_rows,
    find_matching_users,
    sanitize_filename,
)
from labflow.nftables import build_rules, parse_counter_listing
from labflow.systemd_assets import parse_default_interface, write_systemd_assets


class LabflowTests(unittest.TestCase):
    def make_config(self, root: Path, db_path: Path) -> LabflowConfig:
        return LabflowConfig(
            data_root=root,
            db_path=db_path,
            external_interfaces=("eth0",),
            timezone="Asia/Shanghai",
            skip_hidden_dirs=True,
        )

    def test_discovery_uses_data_root(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "alice").mkdir()
            (root / "bob").mkdir()
            config = self.make_config(root, root / "labflow.db")
            result = discover_users(config)
            self.assertEqual(1, len(result.conflicts))
            self.assertEqual(1, len(result.users))
            self.assertEqual("alice", result.users[0].display_name)

    def test_discovery_prefers_directory_that_matches_login(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            login_name = pwd.getpwuid(Path(tmpdir).stat().st_uid).pw_name
            (root / "shared_data").mkdir()
            (root / login_name).mkdir()
            config = self.make_config(root, root / "labflow.db")
            result = discover_users(config)
            self.assertEqual(login_name, result.users[0].display_name)

    def test_counter_snapshot_handles_reset(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            config = self.make_config(root, root / "labflow.db")
            db = Database(config)
            ts = datetime(2026, 4, 8, 12, 0, tzinfo=ZoneInfo("Asia/Shanghai"))
            first = db.apply_counter_snapshot(ts, {1000: {"rx": 100, "tx": 200}})
            self.assertEqual(100, first.delta_rx_bytes)
            self.assertEqual(200, first.delta_tx_bytes)
            second = db.apply_counter_snapshot(ts, {1000: {"rx": 160, "tx": 260}})
            self.assertEqual(60, second.delta_rx_bytes)
            self.assertEqual(60, second.delta_tx_bytes)
            third = db.apply_counter_snapshot(ts, {1000: {"rx": 10, "tx": 20}})
            self.assertEqual(10, third.delta_rx_bytes)
            self.assertEqual(20, third.delta_tx_bytes)
            self.assertEqual(["uid:1000:rx", "uid:1000:tx"], third.reset_counters)

    def test_build_rules_and_parse_counters(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            config = self.make_config(root, root / "labflow.db")
            db = Database(config)
            db.sync_users([], datetime(2026, 4, 8, 12, 0, tzinfo=ZoneInfo("Asia/Shanghai")))
            rules = build_rules(
                config,
                [
                    type("User", (), {"uid": 0, "login_name": "root", "display_name": "root", "data_dir": "/root", "source": "extra"})(),
                    type("User", (), {"uid": 1000, "login_name": "alice", "display_name": "alice", "data_dir": "/datas/alice", "source": "datas"})(),
                ],
            )
            self.assertIn("meta skuid 1000", rules)
            self.assertIn("ct mark 1000", rules)
            payload = {
                "nftables": [
                    {"counter": {"name": "uid_0_tx", "bytes": 42}},
                    {"counter": {"name": "uid_0_rx", "bytes": 24}},
                    {"counter": {"name": "uid_1000_tx", "bytes": 4096}},
                    {"counter": {"name": "uid_1000_rx", "bytes": 8192}},
                ]
            }
            parsed = parse_counter_listing(payload)
            self.assertEqual({"rx": 8192, "tx": 4096}, parsed[1000])
            self.assertEqual({"rx": 24, "tx": 42}, parsed[0])

    def test_parse_default_interface(self) -> None:
        route_output = "default via 219.216.65.254 dev ens2f2 proto dhcp metric 100\n"
        self.assertEqual("ens2f2", parse_default_interface(route_output))

    def test_write_systemd_assets_root_installer_uses_generated_scripts(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            output_dir = root / "generated"
            config_path = root / "labflow.json"
            config_path.write_text("{}", encoding="utf-8")
            write_systemd_assets(
                project_dir=root,
                config_path=config_path,
                python_bin="/usr/bin/python3",
                output_dir=output_dir,
            )
            install_script = (output_dir / "install-systemd-root.sh").read_text(encoding="utf-8")
            self.assertIn(str(output_dir / "run-refresh.sh"), install_script)
            self.assertIn(str(output_dir / "run-collect.sh"), install_script)
            self.assertNotIn(str(root / "scripts" / "run-refresh.sh"), install_script)

    def test_write_report_csv(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "usage.csv"
            rows = [
                {
                    "uid": 1000,
                    "login_name": "alice",
                    "display_name": "alice",
                    "data_dir": "/datas/alice",
                    "active": 1,
                    "rx_bytes": 10,
                    "tx_bytes": 20,
                    "total_bytes": 30,
                }
            ]
            _write_report_csv(rows, "2026-04", str(output_path))
            with output_path.open("r", encoding="utf-8", newline="") as handle:
                parsed = list(csv.DictReader(handle))
            self.assertEqual(1, len(parsed))
            self.assertEqual("2026-04", parsed[0]["month"])
            self.assertEqual("1", parsed[0]["rank"])
            self.assertEqual("30", parsed[0]["total_bytes"])

    def test_sorted_report_rows_descending(self) -> None:
        rows = [
            {"uid": 3, "total_bytes": 10, "rx_bytes": 5, "tx_bytes": 5, "display_name": "c"},
            {"uid": 1, "total_bytes": 30, "rx_bytes": 20, "tx_bytes": 10, "display_name": "a"},
            {"uid": 2, "total_bytes": 30, "rx_bytes": 15, "tx_bytes": 15, "display_name": "b"},
        ]
        sorted_rows = _sorted_report_rows(rows)
        self.assertEqual([1, 2, 3], [row["uid"] for row in sorted_rows])

    def test_find_matching_users_prefers_exact_and_prefix_matches(self) -> None:
        rows = [
            {"uid": 937, "login_name": "gaoyichen", "display_name": "gaoyichen", "data_dir": "/datas/gaoyichen"},
            {"uid": 993, "login_name": "wzjtest", "display_name": "wzjtest", "data_dir": "/datas/wzjtest"},
            {"uid": 1005, "login_name": "wangyanfei", "display_name": "wangyanfei", "data_dir": "/datas/wangyanfei"},
        ]
        matches = find_matching_users(rows, "gao")
        self.assertEqual(937, matches[0]["uid"])
        exact = find_matching_users(rows, "wzjtest")
        self.assertEqual(993, exact[0]["uid"])

    def test_sanitize_filename(self) -> None:
        self.assertEqual("gaoyichen-937", sanitize_filename("gaoyichen 937"))

    def test_build_monitor_rows_includes_zero_usage_users(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            config = self.make_config(root, root / "labflow.db")
            db = Database(config)
            ts = datetime(2026, 4, 8, 12, 0, tzinfo=ZoneInfo("Asia/Shanghai"))
            db.sync_users(
                [
                    type("User", (), {"uid": 1000, "login_name": "alice", "display_name": "alice", "data_dir": "/datas/alice", "source": "datas"})(),
                    type("User", (), {"uid": 1001, "login_name": "bob", "display_name": "bob", "data_dir": "/datas/bob", "source": "datas"})(),
                ],
                ts,
            )
            db.apply_counter_snapshot(ts, {1000: {"rx": 10, "tx": 20}})
            rows, total = build_monitor_rows(db, "2026-04")
            self.assertEqual(30, total)
            self.assertEqual([1000, 1001], [row["uid"] for row in rows])
            self.assertEqual(0, rows[1]["total_bytes"])

    def test_parse_audit_exec_events(self) -> None:
        lines = [
            'type=SYSCALL msg=audit(1775638895.000:420): arch=c000003e syscall=59 success=yes exit=0 ppid=111 pid=222 auid=952 uid=952 gid=952 euid=952 suid=952 fsuid=952 tty=pts0 ses=7 comm="python3" exe="/usr/bin/python3" key="labflow-exec"',
            'type=EXECVE msg=audit(1775638895.000:420): argc=3 a0="python3" a1="-m" a2="http.server"',
            'type=CWD msg=audit(1775638895.000:420): cwd="/datas/wuxi/project"',
        ]
        start = datetime(2026, 4, 8, 17, 0, tzinfo=ZoneInfo("Asia/Shanghai"))
        end = datetime(2026, 4, 8, 17, 30, tzinfo=ZoneInfo("Asia/Shanghai"))
        parsed = parse_audit_exec_events(lines, target_uid=952, start=start, end=end, timezone_name="Asia/Shanghai")
        self.assertEqual(1, len(parsed))
        self.assertEqual("python3 -m http.server", parsed[0].command)
        self.assertEqual("/datas/wuxi/project", parsed[0].cwd)
        self.assertEqual(222, parsed[0].pid)

    def test_parse_audit_exec_events_decodes_hex_arguments(self) -> None:
        lines = [
            'type=SYSCALL msg=audit(1775638895.000:421): arch=c000003e syscall=59 success=yes exit=0 ppid=111 pid=223 auid=952 uid=952 gid=952 euid=952 suid=952 fsuid=952 tty=pts0 ses=7 comm="sh" exe="/bin/sh" key="labflow-exec"',
            'type=EXECVE msg=audit(1775638895.000:421): argc=3 a0="/bin/sh" a1="-c" a2="6C73202D6C202F64617461732F77757869"',
        ]
        start = datetime(2026, 4, 8, 17, 0, tzinfo=ZoneInfo("Asia/Shanghai"))
        end = datetime(2026, 4, 8, 17, 30, tzinfo=ZoneInfo("Asia/Shanghai"))
        parsed = parse_audit_exec_events(lines, target_uid=952, start=start, end=end, timezone_name="Asia/Shanghai")
        self.assertEqual("/bin/sh -c ls -l /datas/wuxi", parsed[0].command)

    def test_parse_bash_history_with_timestamps(self) -> None:
        text = "\n".join(
            [
                "#1775638860",
                "ls -lah",
                "#1775638895",
                "python train.py --epochs 1",
            ]
        )
        parsed = parse_bash_history(text, "Asia/Shanghai")
        self.assertEqual(2, len(parsed))
        self.assertEqual("python train.py --epochs 1", parsed[1].command)
        self.assertIsNotNone(parsed[1].ts)

    def test_parse_zsh_history(self) -> None:
        text = ": 1775638895:0;wget https://example.com/file\n"
        parsed = parse_zsh_history(text, "Asia/Shanghai")
        self.assertEqual(1, len(parsed))
        self.assertEqual("wget https://example.com/file", parsed[0].command)

    def test_display_width_helpers_handle_cjk(self) -> None:
        self.assertEqual("流量", _trim_to_width("流量监控", 4))
        self.assertEqual(7, _display_width(_fit_display("A流量", 7)))
        self.assertEqual(["流量峰值", "追踪abc"], _wrap_lines(["流量峰值追踪abc"], 8))

    def test_load_recent_commands_prefers_timestamped_entries(self) -> None:
        from unittest.mock import patch

        events = [
            CommandEvent(ts=datetime(2026, 4, 8, 17, 1, tzinfo=ZoneInfo("Asia/Shanghai")), source="bash_history", command="ls"),
            CommandEvent(ts=datetime(2026, 4, 8, 17, 3, tzinfo=ZoneInfo("Asia/Shanghai")), source="bash_history", command="python train.py"),
            CommandEvent(ts=None, source="bash_history", command="cat log.txt"),
        ]
        with patch("labflow.forensics._load_recent_audit_events", return_value=([], [])):
            with patch("labflow.forensics._load_shell_history_events", return_value=(events, [], True, True)):
                recent, notes = load_recent_commands("wuxi", "/datas/wuxi", 952, "Asia/Shanghai", limit=2)
        self.assertEqual(["python train.py", "ls"], [item.command for item in recent])
        self.assertEqual([], notes)

    def test_load_recent_commands_falls_back_to_undated_history(self) -> None:
        from unittest.mock import patch

        events = [
            CommandEvent(ts=None, source="bash_history", command="cd /tmp"),
            CommandEvent(ts=None, source="bash_history", command="tail -f train.log"),
            CommandEvent(ts=None, source="bash_history", command="python eval.py"),
        ]
        with patch("labflow.forensics._load_recent_audit_events", return_value=([], [])):
            with patch("labflow.forensics._load_shell_history_events", return_value=(events, [], True, True)):
                recent, notes = load_recent_commands("wuxi", "/datas/wuxi", 952, "Asia/Shanghai", limit=2)
        self.assertEqual(["python eval.py", "tail -f train.log"], [item.command for item in recent])
        self.assertTrue(any("无时间戳" in note for note in notes))

    def test_load_recent_commands_filters_background_audit_noise(self) -> None:
        from unittest.mock import patch

        audit_events = [
            CommandEvent(ts=datetime(2026, 4, 8, 19, 7, tzinfo=ZoneInfo("Asia/Shanghai")), source="auditd", command="cat /proc/123/stat"),
            CommandEvent(ts=datetime(2026, 4, 8, 19, 6, tzinfo=ZoneInfo("Asia/Shanghai")), source="auditd", command="python train.py"),
        ]
        with patch("labflow.forensics._load_recent_audit_events", return_value=(audit_events, [])):
            with patch("labflow.forensics._load_shell_history_events", return_value=([], [], False, False)):
                recent, notes = load_recent_commands("wuxi", "/datas/wuxi", 952, "Asia/Shanghai", limit=2)
        self.assertEqual(["python train.py"], [item.command for item in recent])
        self.assertEqual([], notes)

    def test_load_recent_commands_uses_quick_shell_path_for_monitor(self) -> None:
        from unittest.mock import patch

        events = [
            CommandEvent(ts=None, source="bash_history", command="python train.py"),
            CommandEvent(ts=None, source="bash_history", command="tail -f train.log"),
        ]
        with patch("labflow.forensics._load_recent_shell_events_quick", return_value=(events, [])):
            with patch("labflow.forensics._load_shell_history_events", side_effect=AssertionError("slow path should not run")):
                recent, notes = load_recent_commands(
                    "wuxi",
                    "/datas/wuxi",
                    952,
                    "Asia/Shanghai",
                    limit=2,
                    prefer_audit=False,
                )
        self.assertEqual(["python train.py", "tail -f train.log"], [item.command for item in recent])
        self.assertEqual([], notes)


if __name__ == "__main__":
    unittest.main()
