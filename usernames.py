#!/usr/bin/env python3
"""
usernames.py — server-defender 模块
检测与防御：
1. 境外 IP 阻断：非国内 IP 一旦探测连接，直接永久封禁(本机 iptables + 同步中转机)
2. 用户名风暴防御：国内 IP 若尝试不同用户名 > THRESHOLD 个，永久封禁
3. 白名单机制：成功登录(公钥 a1)或手动加白的 IP 自动放行，永不封禁
supervisor 以 root 运行。
"""
import re, json, os, time, subprocess
from geo import get_ip_geo

THRESHOLD = 100          # 国内 IP 不同用户名阈值
STATE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "usernames.json")
BAN_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "perm_ban.txt")
RELAY = "root@47.98.244.173"
SAVE_INTERVAL = 30       # 秒

# 永不封禁的来源(隧道/回环)
ALWAYS_IGNORE = {"127.0.0.1", "::1", "127.0.0.2"}
# journald sshd 日志正则
RE_FAIL   = re.compile(r"Failed password for (?:invalid user )?(\S+) from ([\d\.:a-fA-F]+) port")
RE_ACCEPT = re.compile(r"Accepted publickey for (\S+) from ([\d\.:a-fA-F]+)")

def load_state():
    if os.path.exists(STATE_FILE):
        try:
            return json.load(open(STATE_FILE))
        except Exception:
            pass
    return {"ips": {}, "whitelist": []}

def save_state(state):
    try:
        os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
        tmp = STATE_FILE + ".tmp"
        json.dump(state, open(tmp, "w"), ensure_ascii=False)
        os.replace(tmp, STATE_FILE)
    except Exception as e:
        print("save_state err", e)

def write_ban_file(state):
    """面板读用的永久封禁列表 (ip \t 用户名数/原因 \t 时间 \t 归属地)"""
    try:
        os.makedirs(os.path.dirname(BAN_FILE), exist_ok=True)
        with open(BAN_FILE, "w", encoding="utf-8") as f:
            for ip, rec in state["ips"].items():
                if rec.get("banned"):
                    reason = rec.get("reason", f"不同账号数:{len(rec.get('users', []))}")
                    loc = rec.get("location", "未知")
                    f.write(f"{ip}\t{reason}\t{rec.get('time','')}\t{loc}\n")
    except Exception as e:
        print("write_ban_file err", e)

def is_banned(ip):
    return subprocess.run(["iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"],
                          capture_output=True).returncode == 0

def ban_local(ip):
    subprocess.run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], capture_output=True)
    subprocess.run(["iptables-save"], capture_output=True)

def sync_relay(ip):
    """同步到中转机: 中转机也永久封禁该 IP"""
    try:
        cmd = ("iptables -C INPUT -s {0} -j DROP >/dev/null 2>&1 "
               "|| iptables -A INPUT -s {0} -j DROP; iptables-save >/dev/null").format(ip)
        subprocess.run(["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no",
                        "-o", "ConnectTimeout=8", RELAY, cmd], timeout=12)
        print("synced to relay:", ip)
    except Exception as e:
        print("sync_relay err", ip, e)

def apply_all_bans(state):
    """启动时重新下发所有已封 IP(持久化, 重启不丢)"""
    for ip, rec in state["ips"].items():
        if rec.get("banned") and not is_banned(ip):
            ban_local(ip)
    write_ban_file(state)

def main():
    state = load_state()
    apply_all_bans(state)
    last_save = time.time()
    
    # 跟随 journald sshd 日志(需 root)
    proc = subprocess.Popen(["journalctl", "-f", "-u", "sshd", "-o", "cat"],
                            stdout=subprocess.PIPE, text=True, errors="replace", bufsize=1)
    for line in proc.stdout:
        line = line.strip()
        # 1) 成功登录 → 自动白名单
        m = RE_ACCEPT.search(line)
        if m:
            ip = m.group(2)
            if ip not in ALWAYS_IGNORE and ip not in state["whitelist"]:
                state["whitelist"].append(ip)
                print("auto-whitelist", ip)
            continue
            
        # 2) 失败尝试 → 判定地理位置与用户名
        m = RE_FAIL.search(line)
        if not m:
            continue
        user, ip = m.group(1), m.group(2)
        if ip in ALWAYS_IGNORE or ip in state["whitelist"]:
            continue
            
        rec = state["ips"].setdefault(ip, {"users": [], "banned": False})
        if user not in rec["users"]:
            rec["users"].append(user)
            
        # 查询归属地信息
        geo_info = get_ip_geo(ip)
        rec["location"] = geo_info.get("location", "未知")
        is_cn = geo_info.get("is_cn", True)
        
        # 触发封禁条件：
        # 条件 A: 境外 IP (is_cn is False)
        # 条件 B: 境内 IP 尝试不同用户名 > THRESHOLD
        should_ban = False
        ban_reason = ""
        
        if not is_cn:
            should_ban = True
            ban_reason = f"境外IP拦截 ({geo_info.get('location', '国外')})"
        elif len(rec["users"]) > THRESHOLD:
            should_ban = True
            ban_reason = f"用户名风暴 (不同账号:{len(rec['users'])})"
            
        if should_ban and not rec["banned"]:
            rec["banned"] = True
            rec["reason"] = ban_reason
            rec["time"] = time.strftime("%Y-%m-%d %H:%M:%S")
            if not is_banned(ip):
                ban_local(ip)
            sync_relay(ip)
            write_ban_file(state)
            print(f"PERM-BANNED [{ban_reason}] {ip}")

        # 周期持久化
        if time.time() - last_save > SAVE_INTERVAL:
            save_state(state)
            last_save = time.time()

if __name__ == "__main__":
    main()
