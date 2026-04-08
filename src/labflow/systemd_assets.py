from __future__ import annotations

import re
import textwrap
from pathlib import Path


DEFAULT_COLLECT_INTERVAL_MINUTES = 1


def parse_default_interface(route_output: str) -> str | None:
    for line in route_output.splitlines():
        match = re.search(r"\bdev\s+(\S+)", line)
        if match:
            return match.group(1)
    return None


def detect_default_interface(route_output: str) -> str | None:
    return parse_default_interface(route_output)


def _script_text(project_dir: Path, config_path: Path, python_bin: str, command: str) -> str:
    return textwrap.dedent(
        f"""\
        #!/usr/bin/env bash
        set -euo pipefail
        cd {project_dir}
        export PYTHONPATH={project_dir / 'src'}
        exec {python_bin} -m labflow --config {config_path} {command}
        """
    )


def _refresh_script_text(project_dir: Path, config_path: Path, python_bin: str) -> str:
    return textwrap.dedent(
        f"""\
        #!/usr/bin/env bash
        set -euo pipefail
        cd {project_dir}
        export PYTHONPATH={project_dir / 'src'}
        {python_bin} -m labflow --config {config_path} sync-users
        exec {python_bin} -m labflow --config {config_path} install-rules
        """
    )


def _service_text(description: str, exec_path: Path) -> str:
    return textwrap.dedent(
        f"""\
        [Unit]
        Description={description}
        After=network-online.target

        [Service]
        Type=oneshot
        ExecStart={exec_path}
        """
    )


def _timer_text(description: str, cadence: str, unit_name: str) -> str:
    return textwrap.dedent(
        f"""\
        [Unit]
        Description={description}

        [Timer]
        {cadence}
        Unit={unit_name}

        [Install]
        WantedBy=timers.target
        """
    )


def _root_install_script_text(generated_dir: Path) -> str:
    return textwrap.dedent(
        f"""\
        #!/usr/bin/env bash
        set -euo pipefail
        if [[ "${{EUID}}" -ne 0 ]]; then
          echo "Run this script as root, for example: sudo {generated_dir / 'install-systemd-root.sh'}" >&2
          exit 1
        fi

        install -m 0644 {generated_dir / 'labflow-collect.service'} /etc/systemd/system/labflow-collect.service
        install -m 0644 {generated_dir / 'labflow-collect.timer'} /etc/systemd/system/labflow-collect.timer
        install -m 0644 {generated_dir / 'labflow-refresh.service'} /etc/systemd/system/labflow-refresh.service
        install -m 0644 {generated_dir / 'labflow-refresh.timer'} /etc/systemd/system/labflow-refresh.timer

        systemctl daemon-reload
        {generated_dir / 'run-refresh.sh'}
        {generated_dir / 'run-collect.sh'}
        systemctl enable --now labflow-refresh.timer
        systemctl enable --now labflow-collect.timer
        echo "labflow timers installed and started."
        """
    )


def write_systemd_assets(
    project_dir: Path,
    config_path: Path,
    python_bin: str,
    output_dir: Path,
    collect_interval_minutes: int = DEFAULT_COLLECT_INTERVAL_MINUTES,
) -> list[Path]:
    project_dir = project_dir.resolve()
    config_path = config_path.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    collect_script = output_dir / "run-collect.sh"
    refresh_script = output_dir / "run-refresh.sh"
    collect_script.write_text(_script_text(project_dir, config_path, python_bin, "collect"), encoding="utf-8")
    refresh_script.write_text(_refresh_script_text(project_dir, config_path, python_bin), encoding="utf-8")
    collect_script.chmod(0o755)
    refresh_script.chmod(0o755)

    collect_service = output_dir / "labflow-collect.service"
    collect_timer = output_dir / "labflow-collect.timer"
    refresh_service = output_dir / "labflow-refresh.service"
    refresh_timer = output_dir / "labflow-refresh.timer"
    root_install_script = output_dir / "install-systemd-root.sh"

    collect_service.write_text(
        _service_text("Collect labflow nftables counters", collect_script),
        encoding="utf-8",
    )
    collect_timer.write_text(
        _timer_text(
            f"Run labflow collector every {collect_interval_minutes} minute(s)",
            f"OnBootSec=1min\nOnUnitActiveSec={collect_interval_minutes}min",
            collect_service.name,
        ),
        encoding="utf-8",
    )
    refresh_service.write_text(
        _service_text("Refresh labflow users and nftables rules", refresh_script),
        encoding="utf-8",
    )
    refresh_timer.write_text(
        _timer_text(
            "Refresh labflow users and rules every day",
            "OnBootSec=2min\nOnCalendar=*-*-* 00:01:00\nPersistent=true",
            refresh_service.name,
        ),
        encoding="utf-8",
    )
    root_install_script.write_text(
        _root_install_script_text(output_dir.resolve()),
        encoding="utf-8",
    )
    root_install_script.chmod(0o755)

    return [
        collect_script,
        refresh_script,
        collect_service,
        collect_timer,
        refresh_service,
        refresh_timer,
        root_install_script,
    ]
