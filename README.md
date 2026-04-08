# labflow

`labflow` 是一个面向实验室共享服务器的流量统计工具。

它会：
- 从类似 `/datas/<用户名>` 的目录结构里发现用户
- 将目录 owner 映射到 Linux UID
- 用 `nftables` 统计每个 UID 的外网流量
- 按月保存历史，支持查看“本月 1 号到现在”的用量
- 提供命令行和全屏交互界面

如果你也有一台多人共用的 Linux 服务器，想知道“谁这个月用了多少外网流量”，这个仓库就是干这个的。

## 适合什么场景

适合：
- 多用户共享 Linux 服务器
- 每个人有自己的系统账号
- 每个人有自己的目录，比如 `/datas/alice`、`/datas/bob`
- 想按“自然月”统计每个人的外网流量，并保留历史

不适合：
- 多个人共用同一个 Linux 账号跑任务
- 只靠目录名区分用户，但进程实际都跑在同一个 UID 下

一句话讲清楚：
`labflow` 实际上是“按 UID 记账”，`/datas/<用户名>` 只是帮助识别“这个 UID 对应谁”。

## 工作原理

- 扫描 `data_root` 下的用户目录，默认是 `/datas`
- 读取目录 owner，得到 UID 和登录名
- 在外网网卡上安装 `nftables` 规则
  - 发出去的流量：按 `meta skuid` 记到对应 UID
  - 回来的流量：通过 `ct mark` 归回同一个 UID
- 定时把计数器增量写入 SQLite
- 以 `YYYY-MM` 为单位聚合，所以历史会一直保留

`2026-04` 的意思就是：`2026-04-01 00:00` 到当前时刻，使用配置文件里的时区。

## 使用前提

部署前先确认这几点：

- 每个用户最好有独立 Linux UID
- 用户目录 owner 和实际跑任务的 UID 基本一致
- 你知道服务器的外网接口名，例如 `eth0`、`ens2f2`
- 机器上有 `Python 3.10+`、`nftables`、`systemd`
- 你有 root 权限，至少能执行一次安装脚本

建议把这些共享目录排除掉，不要当成个人身份：
- `datasets`
- `shared_datasets`
- `models`
- `software`
- 其他公共目录

## 仓库里最重要的东西

- `labflow.example.json`：示例配置
- `labflow.json`：你的本机配置，不应提交到 Git
- `src/labflow/`：核心代码
- `contrib/install-system-wide-lab.sh`：给所有用户安装 `lab` 命令
- `contrib/install-lab-launcher.sh`：只给当前用户安装 `lab` 命令

## 快速部署

下面是一套最短可用流程。

### 1. 准备配置

```bash
cp labflow.example.json labflow.json
PYTHONPATH=src python3 -m labflow --config labflow.json detect-iface
```

然后编辑 `labflow.json`，至少确认这些字段：

- `data_root`：用户目录根目录，例如 `/datas`
- `external_interfaces`：外网接口，例如 `ens2f2`
- `timezone`：例如 `Asia/Shanghai`
- `total_monthly_quota_gb`：整机月额度
- `user_soft_limit_gb`：单用户提醒阈值
- `exclude_dirs`：共享目录排除列表
- `extra_users`：如果你想把 `root` 也纳入统计，可以保留

### 2. 先同步用户，确认识别是否正确

```bash
PYTHONPATH=src python3 -m labflow --config labflow.json sync-users
PYTHONPATH=src python3 -m labflow --config labflow.json show-users
```

如果这里识别出来的用户不对，先改 `exclude_dirs`，不要急着安装规则。

### 3. 生成 systemd 部署文件

```bash
PYTHONPATH=src python3 -m labflow --config labflow.json write-systemd
```

### 4. 安装规则和定时采集

```bash
sudo ./contrib/systemd/generated/install-systemd-root.sh
```

这个脚本会：
- 同步用户
- 安装 `nftables` 规则
- 采一轮初始数据
- 启用定时任务

### 5. 给命令行装一个统一入口

只给当前用户安装：

```bash
./contrib/install-lab-launcher.sh
```

给整台服务器所有用户安装：

```bash
sudo ./contrib/install-system-wide-lab.sh
```

如果你希望任何用户在任何目录都能直接输入 `lab monitor`，用第二个。

## 最推荐的使用方式

安装完以后，直接：

```bash
lab monitor
```

这是一个全屏界面，不需要记很多命令。

### 界面快捷键

- `↑ / ↓` 或 `j / k`：上下选择用户
- `/`：搜索用户，支持用户名 / 显示名 / UID
- `c`：清空搜索
- `m`：切换月份
- `e`：导出当前月份 CSV
- `u`：导出当前选中用户的历史 CSV
- `r`：刷新
- `q`：退出

左边是用户排行，默认按总流量从大到小排序；右边是当前选中用户的本月明细和历史。

## 常用命令

看本月完整排行：

```bash
lab report
```

看某个月完整排行，例如看 2026 年 4 月：

```bash
lab report --month 2026-04
```

只看前 10 名：

```bash
lab top --month 2026-04 --limit 10
```

导出某个月的排行 CSV：

```bash
lab export-csv --month 2026-04 --output usage-2026-04.csv
```

看某个用户的历史：

```bash
lab history gaoyichen
```

看额度状态：

```bash
lab check-quota
```

## 运维排查

看定时任务是否正常：

```bash
systemctl status labflow-refresh.timer labflow-collect.timer
```

看最近执行日志：

```bash
journalctl -u labflow-collect.service -u labflow-refresh.service -n 50 --no-pager
```

看当前安装的规则：

```bash
sudo nft list table inet labflow
```

修改了 `labflow.json` 后，重新生成并安装：

```bash
PYTHONPATH=src python3 -m labflow --config labflow.json write-systemd
sudo ./contrib/systemd/generated/install-systemd-root.sh
```

## 常见问题

### 1. 为什么切换到别的用户后 `lab` 找不到？

因为你装的是“当前用户自己的启动器”。

如果想让所有用户都能用：

```bash
sudo ./contrib/install-system-wide-lab.sh
```

### 2. 为什么有些用户统计不到？

通常是下面几种情况：
- 用户实际跑任务时不是自己的 UID
- 多个人共用同一个账号
- 目录 owner 和真实运行 UID 不一致
- 这个连接不是“本机用户主动发起的外网连接”

### 3. 为什么公共目录会干扰识别？

因为 `labflow` 会扫描 `data_root` 下的目录 owner。公共目录如果不排除，也会被当成“一个身份”。

所以要把共享目录加入 `exclude_dirs`。

## 额外说明

- 当前版本重点是“用户主动发起的外网流量”
- 历史不会清空，而是按月保存
- 数据库存放在 `var/labflow.db`
- 本机配置 `labflow.json`、数据库 `var/`、生成的 systemd 文件默认都不会提交到 Git

## 相关文档

- `docs/INSTALL.md`
- `docs/ADMIN_COMMANDS.md`
