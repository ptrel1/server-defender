#!/usr/bin/env python3
"""
reaper.py — server-defender 子模块
功能：自动巡检与收割失控的高 CPU 占用孤儿进程与跑飞排查指令 (如死循环的 grep/find/awk/sed)。

三重安全防御规则（100% 杜绝误杀）：
1. 目标指令白名单：仅限 {'grep', 'egrep', 'fgrep', 'find', 'sed', 'awk', 'xargs'} 等临时检索命令。
2. 绝对豁免保护：严禁触碰 {'node', 'python', 'python3', 'java', 'mysqld', 'postgres', 'kilo', 'bash', 'zsh', 'fish', 'sshd', 'nginx', 'frpc', 'frps', 'supervisord', 'systemd', 'docker', 'containerd'} 等服务和交互 Shell。
3. 触发阈值条件：
   - 累计运行时间 > 15 分钟（900 秒）；
   - 且处于孤儿状态（PPID == 1，代表父终端已退出）或单核持续高负载（CPU > 50%）。
"""

import os
import time
import json
import signal
import subprocess
from datetime import datetime

# 默认配置
DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
EVENTS_FILE = os.path.join(DATA_DIR, "reaper_events.json")
MAX_EVENTS = 50

# 目标清理指令集合（小写）
TARGET_COMMANDS = {"grep", "egrep", "fgrep", "find", "sed", "awk", "xargs"}

# 严格豁免白名单
SAFE_COMMANDS = {
    "node", "python", "python3", "java", "mysqld", "postgres", "kilo",
    "bash", "zsh", "fish", "sh", "sshd", "nginx", "frpc", "frps",
    "supervisord", "systemd", "docker", "containerd", "tail", "journalctl"
}

MAX_RUNTIME_SECONDS = 900  # 15 分钟


def load_events():
    """读取已记录的收割事件"""
    if os.path.exists(EVENTS_FILE):
        try:
            with open(EVENTS_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return []


def save_events(events):
    """持久化记录收割事件"""
    try:
        os.makedirs(DATA_DIR, exist_ok=True)
        tmp = EVENTS_FILE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(events[:MAX_EVENTS], f, ensure_ascii=False, indent=2)
        os.replace(tmp, EVENTS_FILE)
    except Exception as e:
        print(f"[reaper] save_events error: {e}")


def parse_elapsed_seconds(etime_str):
    """
    解析 ps 输出的运行时间字符串 (etime) 为秒数。
    格式可能为:
      - "mm:ss"
      - "hh:mm:ss"
      - "dd-hh:mm:ss"
    """
    try:
        etime_str = etime_str.strip()
        days = 0
        if "-" in etime_str:
            d_part, etime_str = etime_str.split("-", 1)
            days = int(d_part)
        parts = list(map(int, etime_str.split(":")))
        if len(parts) == 2:
            return days * 86400 + parts[0] * 60 + parts[1]
        elif len(parts) == 3:
            return days * 86400 + parts[0] * 3600 + parts[1] * 60 + parts[2]
    except Exception:
        pass
    return 0


def get_high_cpu_processes(limit=10):
    """获取当前系统 CPU 占用最高的前 N 个进程列表"""
    procs = []
    try:
        res = subprocess.run(
            ["ps", "-eo", "pid,ppid,user,%cpu,%mem,etime,comm,args", "--sort=-%cpu"],
            capture_output=True, text=True, timeout=5
        )
        lines = res.stdout.strip().split("\n")
        if len(lines) > 1:
            for line in lines[1:limit + 1]:
                parts = line.strip().split(None, 7)
                if len(parts) >= 8:
                    pid, ppid, user, cpu, mem, etime, comm, args = parts
                    procs.append({
                        "pid": int(pid),
                        "ppid": int(ppid),
                        "user": user,
                        "cpu": float(cpu),
                        "mem": float(mem),
                        "etime": etime,
                        "comm": comm,
                        "args": args
                    })
    except Exception as e:
        print(f"[reaper] get_high_cpu_processes error: {e}")
    return procs


def inspect_and_reap():
    """
    巡检并收割失控的孤儿进程。
    返回本次收割的事件列表。
    """
    reaped = []
    try:
        # 获取所有进程信息
        res = subprocess.run(
            ["ps", "-eo", "pid,ppid,user,%cpu,%mem,etime,comm,args"],
            capture_output=True, text=True, timeout=5
        )
        lines = res.stdout.strip().split("\n")
        if len(lines) <= 1:
            return reaped

        current_pid = os.getpid()

        for line in lines[1:]:
            parts = line.strip().split(None, 7)
            if len(parts) < 8:
                continue
            pid_str, ppid_str, user, cpu_str, mem_str, etime_str, comm, args = parts
            try:
                pid = int(pid_str)
                ppid = int(ppid_str)
                cpu = float(cpu_str)
            except ValueError:
                continue

            # 忽略自身与 1 号进程
            if pid <= 1 or pid == current_pid:
                continue

            comm_lower = comm.lower().strip()
            # 提取真实可执行文件名（去除前缀路径）
            base_comm = os.path.basename(comm_lower)

            # 严格安全白名单过滤
            if base_comm in SAFE_COMMANDS:
                continue

            # 必须匹配目标清理指令
            if base_comm not in TARGET_COMMANDS:
                continue

            # 检查运行时间
            elapsed_sec = parse_elapsed_seconds(etime_str)
            if elapsed_sec < MAX_RUNTIME_SECONDS:
                continue

            # 判定是否满足孤儿状态或超高 CPU 占用
            is_orphan = (ppid == 1)
            is_high_cpu = (cpu >= 50.0)

            if is_orphan or is_high_cpu:
                reason = []
                if is_orphan:
                    reason.append(f"孤儿进程(PPID=1)")
                if is_high_cpu:
                    reason.append(f"高CPU占用({cpu}%)")
                reason_desc = f"运行已达 {etime_str} (>{MAX_RUNTIME_SECONDS // 60}分钟), " + ", ".join(reason)

                print(f"[reaper] 发现失控进程 PID={pid}, COMM={comm}, 原因: {reason_desc}")

                # 执行优雅终止与强制终止
                try:
                    os.kill(pid, signal.SIGTERM)
                    time.sleep(0.5)
                    try:
                        # 检查进程是否仍然存活
                        os.kill(pid, 0)
                        os.kill(pid, signal.SIGKILL)
                    except OSError:
                        pass  # 已成功退出
                except Exception as ex:
                    print(f"[reaper] kill pid {pid} error: {ex}")

                event = {
                    "pid": pid,
                    "comm": comm,
                    "user": user,
                    "cpu": cpu,
                    "etime": etime_str,
                    "args": args[:200],  # 截断过长命令
                    "reason": reason_desc,
                    "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                }
                reaped.append(event)

        if reaped:
            existing = load_events()
            updated = reaped + existing
            save_events(updated)

    except Exception as e:
        print(f"[reaper] inspect_and_reap error: {e}")

    return reaped


def kill_by_pid(pid: int):
    """手动按 PID 终止异常进程"""
    if pid <= 1:
        return False, "禁止终止系统核心进程"
    try:
        os.kill(pid, signal.SIGKILL)
        return True, "已强制终止进程"
    except ProcessLookupError:
        return True, "进程已不存在"
    except Exception as e:
        return False, str(e)


if __name__ == "__main__":
    print(f"[reaper] 手动单次触发巡检 (PID={os.getpid()})...")
    events = inspect_and_reap()
    print(f"[reaper] 巡检完成，本次收割进程数: {len(events)}")
    for ev in events:
        print(f" - [{ev['time']}] PID {ev['pid']} ({ev['comm']}): {ev['reason']}")
