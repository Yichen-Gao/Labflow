# 安装说明

这份文档面向第一次在自己服务器上部署 `Labflow` 的管理员，尽量只保留真正需要知道的内容。

## 部署前先确认

你至少需要满足这些条件：

- 服务器是 Linux
- 已安装 `Python 3.10+`
- 已安装 `nftables`
- 已安装 `systemd`
- 你有 root 权限
- 用户目录结构大致是 `/datas/<用户名>`
- 每个用户最好有自己的 Linux UID

如果多人共用同一个系统账号，或者目录 owner 和真实运行任务的 UID 不一致，统计就会不准。

## 统计口径先说明白

`Labflow` 统计的是：

- 服务器上某个 UID 经过指定外网接口产生的流量
- 从每月 1 号 00:00 到当前时刻的累计值
- 月份结束后自动进入下一个月，旧数据保留为历史

它适合做实验室内部排行、预警和审计。

如果你学校最终结算依据是 `ipgw s` 或校园网网关账单，请把 `Labflow` 当成“本机侧观测工具”；通常会很接近，但不承诺和网关计费完全一致。

## 第一步：获取代码

```bash
git clone https://github.com/Yichen-Gao/Labflow.git
cd Labflow
```

## 第二步：准备本机配置

```bash
cp labflow.example.json labflow.json
PYTHONPATH=src python3 -m labflow --config labflow.json detect-iface
```

然后编辑 `labflow.json`，重点看这几个字段：

- `data_root`：用户目录根目录，例如 `/datas`
- `external_interfaces`：外网接口，例如 `ens2f2`
- `timezone`：建议按服务器所在时区填写，例如 `Asia/Shanghai`
- `free_traffic_windows`：免费时段，例如 `["00:00-06:00"]`
- `total_monthly_quota_gb`：整机月总额度
- `user_soft_limit_gb`：单用户提醒阈值
- `daily_alert_gb`：单日异常流量提醒阈值，例如 `2`
- `alert_email_to`：异常提醒收件邮箱
- `smtp_*`：SMTP 发信配置；如果要让 systemd 定时器直接发信，最省事是把授权码写进本机 `labflow.json`
- `exclude_dirs`：不参与身份识别的共享目录

建议把这类共享目录放进 `exclude_dirs`：

- `datasets`
- `shared_datasets`
- `models`
- `software`
- 其他你们实验室所有人共用的目录

如果你们学校 `0:00-6:00` 是免费时段，直接加上：

```json
"free_traffic_windows": ["00:00-06:00"]
```

这样这段时间的流量不会被计入统计，但计数器状态仍会继续更新，不会把免费时段流量串到早上 6 点以后。

如果你是部署一段时间后才想起加这个配置，还可以执行一次：

```bash
lab apply-free-windows
```

它会先备份数据库，再把历史上已经记进去的免费时段样本清掉，并重建月统计。

## 第三步：先检查识别出来的用户对不对

```bash
PYTHONPATH=src python3 -m labflow --config labflow.json sync-users
PYTHONPATH=src python3 -m labflow --config labflow.json show-users
```

这一步非常重要。

如果这里就识别错了，后面装好规则也只会“稳定地统计错误对象”。先把目录 owner、排除目录和配置修好，再继续下一步。

## 第四步：生成部署文件

```bash
PYTHONPATH=src python3 -m labflow --config labflow.json write-systemd
```

这个命令会在 `contrib/systemd/generated/` 下生成：

- systemd service / timer 文件
- root 安装脚本
- 用于定时执行的辅助脚本

## 第五步：安装到系统

```bash
sudo ./contrib/systemd/generated/install-systemd-root.sh
```

安装脚本会自动完成这些动作：

- 同步用户
- 安装 `nftables` 规则
- 采集一轮初始样本
- 启用 `labflow-refresh.timer`
- 启用 `labflow-collect.timer`

## 第六步：安装 `lab` 启动命令

只给当前用户安装：

```bash
./contrib/install-lab-launcher.sh
```

给整台服务器所有用户安装：

```bash
sudo ./contrib/install-system-wide-lab.sh
```

如果你希望任何用户在任何目录都能直接运行 `lab monitor`，请使用系统级安装。

## 第七步：验收

先看服务状态：

```bash
systemctl status labflow-refresh.timer labflow-collect.timer
```

再看规则有没有装进去：

```bash
sudo nft list table inet labflow
```

然后直接打开界面：

```bash
lab monitor
```

如果你还想在右侧看到“其他用户最近执行过什么命令”，建议直接用：

```bash
sudo lab monitor
```

右侧默认显示的是“最近输入过的命令概览”，更适合快速浏览；启用 `auditd` 后，`lab monitor` 里按 `t` 可以直接打开“最大峰值”追踪窗口，查看那个时间点附近更精确的命令明细。

如果你暂时不想开界面，也可以先看文本报表：

```bash
lab report
lab top --limit 10
lab check-quota
```

如果你还想在“某个用户一天内突然用到 2G”时自动收到邮件，可以再配置 `daily_alert_gb` 和 `smtp_*`，然后先手动试一次：

```bash
export LABFLOW_SMTP_PASSWORD='你的 SMTP 授权码'
lab check-alerts --dry-run
```

如果要让定时执行的 `collect` 也能直接发信，最简单的是把 `smtp_password` 写进本机的 `labflow.json`；这个文件默认不会进 Git。

后面定时执行的 `collect` 会自动附带检查，达到阈值就发邮件，同一个用户同一天只提醒一次。

## 可选：如果你还想排查“他当时跑了什么命令”

只做流量统计时，`Labflow` 只能告诉你：

- 谁在什么时间段出现了流量突增
- 这次突增大概是下载多还是上传多

如果你还想继续看到“这段时间附近执行过什么命令”，建议额外开启 `auditd` 的 `execve` 审计：

```bash
sudo apt install auditd
sudo ./contrib/install-auditd-exec-rules.sh
```

之后可以这样排查：

```bash
lab trace <用户名>
lab trace <用户名> --around 2026-04-08T17:01:35+08:00 --window-minutes 20
```

注意：`trace` 能帮你把“流量高峰”和“附近执行过的命令”对起来，但不能严格证明某条命令精确消耗了多少字节。

## 后续如果改了配置怎么办

修改 `labflow.json` 后，重新生成并安装一次即可：

```bash
PYTHONPATH=src python3 -m labflow --config labflow.json write-systemd
sudo ./contrib/systemd/generated/install-systemd-root.sh
```

## 常见问题

### 为什么切换用户后 `lab` 命令没了？

因为你只给当前用户装了启动器。想让所有用户都能直接运行，请执行：

```bash
sudo ./contrib/install-system-wide-lab.sh
```

### 为什么有些人明明有目录，却没有统计到？

最常见的原因是：

- 目录 owner 和真实运行任务的 UID 不一致
- 多个人共用一个系统账号
- 那些连接并不是由本机用户主动发起的外网连接
