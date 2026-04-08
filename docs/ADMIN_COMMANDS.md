# Admin Commands

## Core status

Install the global launcher once:

```bash
./contrib/install-lab-launcher.sh
```

Install it for all users on the server:

```bash
sudo ./contrib/install-system-wide-lab.sh
```

Open the full-screen monitor from any directory:

```bash
lab monitor
```

Inside the monitor:

- arrow keys or `j`/`k` move through users
- `/` searches by display name, login name, or UID
- `c` clears the current search
- `m` changes month
- `e` exports the current month CSV
- `u` exports the selected user's history CSV
- `r` refreshes
- `q` exits

Open the older line-based menu if you need a simpler fallback terminal mode:

```bash
./labflow-menu
```

If you still want a direct non-interactive launcher, use:

```bash
lab report --month 2026-04
```

Show the current month ranking, highest traffic first:

```bash
PYTHONPATH=src python3 -m labflow --config labflow.json report
```

Show a specific month such as `2026-04`. If the current date is April 8, 2026, that report means April 1, 2026 00:00 through now in `Asia/Shanghai`:

```bash
PYTHONPATH=src python3 -m labflow --config labflow.json report --month 2026-04
```

Show only the top 10 users for that month:

```bash
PYTHONPATH=src python3 -m labflow --config labflow.json top --month 2026-04 --limit 10
```

Check total quota and user soft limit:

```bash
PYTHONPATH=src python3 -m labflow --config labflow.json check-quota
```

## Export

Export the ranked monthly report to CSV:

```bash
PYTHONPATH=src python3 -m labflow --config labflow.json export-csv --month 2026-04 --output usage-2026-04.csv
```

## User details

Show history for one user:

```bash
PYTHONPATH=src python3 -m labflow --config labflow.json history gaoyichen
```

List the tracked users:

```bash
PYTHONPATH=src python3 -m labflow --config labflow.json show-users
```

## Service management

Show timers:

```bash
systemctl status labflow-refresh.timer labflow-collect.timer
```

Show the latest collection runs:

```bash
journalctl -u labflow-collect.service -u labflow-refresh.service -n 50 --no-pager
```

Show the installed nftables table:

```bash
sudo nft list table inet labflow
```

## Maintenance

Refresh users and reinstall rules immediately:

```bash
sudo contrib/systemd/generated/run-refresh.sh
```

Collect once immediately:

```bash
sudo contrib/systemd/generated/run-collect.sh
```

If you change `labflow.json`, regenerate the units:

```bash
PYTHONPATH=src python3 -m labflow --config labflow.json write-systemd
sudo contrib/systemd/generated/install-systemd-root.sh
```
