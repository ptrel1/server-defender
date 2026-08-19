# 🛡️ Server Defender

服务器安全监控与自动防御中心。实时监控 SSH 暴力破解、frps 代理扫描、SYN Flood 攻击，自动封禁恶意 IP，并内置主机进程健康自愈（Process Reaper），自动收割跑飞失控的死循环孤儿进程。

## 功能

- 📊 **实时监控** — SSH 暴力破解次数、fail2ban 封禁统计、iptables 屏蔽列表
- 🌍 **境外 IP 自动阻断与归属地解析** — 基于多源高可用 IP 库，实时识别攻击源国家/地区，境外非法探测直接触发永久 iptables 封禁并同步至中转机
- ⚡ **失控进程自愈 (Process Reaper)** — 自动巡检并收割跑飞的 `grep`/`find` 等死循环高 CPU 孤儿进程（>15分钟）
- 🔥 **实时高 CPU 监控** — Web 面板一览 CPU 占用 TOP 进程，支持手动一键终止
- 🛡️ **frps 自动封禁** — 通过 fail2ban 监控 frps 日志，自动封禁扫描 SSH 代理的恶意 IP
- 🔐 **用户名风暴防御** — 检测字典爆破用户名风暴，自动触发永久 iptables 封禁
- 🔍 **frps 扫描分析** — 展示 frps 端口扫描 TOP IP 排行
- 🚧 **iptables 手动屏蔽** — 支持手动封禁恶意 IP
- 🏅 **攻击 IP 排行** — SSH 暴力破解 TOP 攻击来源
- 🎯 **被尝试账号排行** — 被暴力破解最多的账号
- 💣 **SYN Flood 告警** — 检测 SYN Flood 攻击
- 🎨 **多主题切换** — 经典红、黑客终端、暗夜战报、警示警戒、蓝焰科技

## 架构

```
┌─────────────────────────────────────────────────────────────────┐
│                       服务器安全与自愈防御中心                     │
│                                                                 │
│  frps ──▶ fail2ban(frps-ssh) ──▶ iptables 黑名单                │
│                                     │                           │
│  SSH ──▶ fail2ban(sshd) ──▶ iptables 黑名单                     │
│                                     │                           │
│  系统进程 ──▶ Process Reaper ──▶ 自动收割失控孤儿进程 (reaper.py)  │
│                                     │                           │
│  lastb / dmesg / ps ──▶ Server Defender ──▶ Web 面板 :8899      │
└─────────────────────────────────────────────────────────────────┘
```

## 访问

面板地址：http://47.98.244.173:8899 或本地 http://127.0.0.1:8899

## 维护

```bash
# 重启服务
supervisorctl restart psup-server-defender
supervisorctl restart usernames

# 手动单次触发进程巡检
venv/bin/python reaper.py
```
