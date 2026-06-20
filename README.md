# 🛡️ Server Defender

服务器安全监控与自动防御面板。实时监控 SSH 暴力破解、frps 代理扫描，自动封禁恶意 IP。

## 功能

- 📊 **实时监控** — SSH 暴力破解次数、fail2ban 封禁统计、iptables 屏蔽列表
- 🛡️ **frps 自动封禁** — 通过 fail2ban 监控 frps 日志，自动封禁扫描 SSH 代理的恶意 IP
- 🔍 **frps 扫描分析** — 展示 frps 端口扫描 TOP IP 排行
- 🚧 **iptables 手动屏蔽** — 支持手动封禁 IP
- 🏅 **攻击 IP 排行** — SSH 暴力破解 TOP 攻击来源
- 🎯 **被尝试账号排行** — 被暴力破解最多的账号
- 💣 **SYN Flood 告警** — 检测 SYN Flood 攻击
- 🎨 **多主题切换** — 经典红、黑客终端、暗夜战报、警示警戒、蓝焰科技

## 架构

```
┌─────────────────────────────────────────────────────┐
│                   阿里云服务器                        │
│                                                     │
│  frps ──▶ fail2ban(frps-ssh) ──▶ iptables 黑名单    │
│                                     │               │
│  SSH ──▶ fail2ban(sshd) ──▶ iptables 黑名单         │
│                                     │               │
│  lastb ──▶ Server Defender ──▶ Web 面板 :8899       │
│  dmesg ──▶ (Flask)                                  │
└─────────────────────────────────────────────────────┘
```

## 部署

### 依赖

```bash
pip install flask
```

### fail2ban 配置

```bash
# 过滤规则
cat > /etc/fail2ban/filter.d/frps-ssh.conf << 'EOF'
[Definition]
failregex = ^.*\[I\] \[proxy/proxy\.go:\d+\] \[[^\]]+\] \[[^\]]*ssh[^\]]*\] get a user connection \[<HOST>:\d+\]
ignoreregex =
EOF

# Jail 配置
cat > /etc/fail2ban/jail.d/frps-ssh.conf << 'EOF'
[frps-ssh]
enabled = true
port = 7001
logpath = /main/app/log/frps.log
backend = auto
bantime = 86400
findtime = 600
maxretry = 5
EOF

systemctl restart fail2ban
```

### supervisor 配置

```bash
cp server-defender.conf /main/server/supervisor/conf.d/
supervisorctl update
supervisorctl start server-defender
```

## 访问

面板地址：http://47.98.244.173:8899

## API

### GET /api/data

返回监控数据 JSON。

### POST /api/block_ip

手动封禁 IP：

```json
{"ip": "1.2.3.4"}
```

## 维护

```bash
# fail2ban 状态
fail2ban-client status
fail2ban-client status sshd
fail2ban-client status frps-ssh

# iptables 规则
iptables -L INPUT -n --line-numbers

# 重启
supervisorctl restart server-defender
systemctl restart fail2ban
```

## 日志

- 面板日志：/main/app/log/server-defender.log
- frps 日志：/main/app/log/frps.log
- fail2ban 日志：journalctl -u fail2ban
