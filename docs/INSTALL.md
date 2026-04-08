# Install

This document describes a clean installation for a new server.

## Requirements

- Linux server with `nftables`
- Python 3.10 or newer
- `systemd`
- Root access for the final install step

## 1. Copy the project

```bash
git clone <your-repo-url>
cd labflow
```

## 2. Prepare config

Create a machine-local config file that will not be committed:

```bash
cp labflow.example.json labflow.json
```

Edit at least:

- `data_root`
- `external_interfaces`
- `timezone`
- `exclude_dirs`
- `total_monthly_quota_gb`
- `user_soft_limit_gb`

To auto-detect the default external interface:

```bash
PYTHONPATH=src python3 -m labflow --config labflow.json detect-iface
```

## 3. Generate helper scripts and units

```bash
PYTHONPATH=src python3 -m labflow --config labflow.json write-systemd
```

## 4. Install on the host

```bash
sudo contrib/systemd/generated/install-systemd-root.sh
```

This will:

- sync users from `/datas`
- install the `nftables` rules
- take an initial sample
- enable the `labflow-refresh.timer`
- enable the `labflow-collect.timer`

## 5. Verify

```bash
systemctl status labflow-refresh.timer labflow-collect.timer
sudo nft list table inet labflow
./contrib/install-lab-launcher.sh
sudo ./contrib/install-system-wide-lab.sh
lab monitor
PYTHONPATH=src python3 -m labflow --config labflow.json report
PYTHONPATH=src python3 -m labflow --config labflow.json top --limit 10
```
