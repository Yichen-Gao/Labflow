# 管理命令速查

这份文档按“管理员日常最常做的事情”来整理，尽量做到拿起来就能用。

## 先记住一个入口

```bash
lab monitor
```

如果你平时只记一个命令，就记这个。它会打开全屏界面，默认按总流量从高到低排序。

## 最常用的 6 条命令

看本月完整排行：

```bash
lab report
```

看某个月排行：

```bash
lab report --month 2026-04
```

只看前 10 名：

```bash
lab top --month 2026-04 --limit 10
```

看某个用户的历史：

```bash
lab history wuxi
```

导出某个月 CSV：

```bash
lab export-csv --month 2026-04 --output usage-2026-04.csv
```

看整机额度状态：

```bash
lab check-quota
```

## `lab monitor` 里怎么操作

- `↑ / ↓` 或 `j / k`：上下移动
- `/`：搜索用户名 / 显示名 / UID
- `c`：清空搜索
- `m`：切换月份
- `e`：导出当前月份 CSV
- `u`：导出当前选中用户历史 CSV
- `r`：刷新
- `q`：退出

## 想快速回答管理员常见问题

### 谁从本月 1 号到现在用得最多？

```bash
lab report
```

### 只想看前几名，不想刷一大屏？

```bash
lab top --limit 10
```

### 想看某个人是不是最近几个月都偏高？

```bash
lab history <用户名>
```

### 想把排行榜发给老师或做存档？

```bash
lab export-csv --month 2026-04 --output usage-2026-04.csv
```

## 服务和部署排查

查看定时任务状态：

```bash
systemctl status labflow-refresh.timer labflow-collect.timer
```

查看最近执行日志：

```bash
journalctl -u labflow-collect.service -u labflow-refresh.service -n 50 --no-pager
```

查看当前 `nftables` 规则：

```bash
sudo nft list table inet labflow
```

改完配置后重新部署：

```bash
PYTHONPATH=src python3 -m labflow --config labflow.json write-systemd
sudo ./contrib/systemd/generated/install-systemd-root.sh
```

## 排查“某个用户突然暴涨”时怎么做

先看这个用户的历史月报：

```bash
lab history <用户名>
```

再看本月总排行，确认是不是刚刚冲上来：

```bash
lab report --month 2026-04
```

最后结合采集日志看时间段：

```bash
journalctl -u labflow-collect.service -n 100 --no-pager
```

经验上：

- 纯 `SSH` 登录通常只有少量流量
- 如果某一分钟突然出现很高的 `RX`，更像是发生了真实下载
- `VSCode Remote`、`Jupyter`、远程文件预览、网络挂载目录读取，都可能带来明显流量

## 如果 `lab` 命令在别的用户下不可用

说明你大概率只装了当前用户版本。给整台机器安装：

```bash
sudo ./contrib/install-system-wide-lab.sh
```
