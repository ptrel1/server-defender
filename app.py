#!/usr/bin/env python3
"""
Server Defender — 服务器安全与健康自愈中心
Apple Sonoma 毛玻璃设计风格 / 双栏结构 / 实时态势感知
"""
import subprocess, re, json, os, time, threading
from datetime import datetime
from flask import Flask, jsonify, render_template_string, request
from reaper import inspect_and_reap, load_events, get_high_cpu_processes, kill_by_pid

app = Flask(__name__)

# 后台自动巡检守护线程
def reaper_background_worker():
    while True:
        try:
            inspect_and_reap()
        except Exception as e:
            print(f"[reaper_worker] error: {e}")
        time.sleep(30)

HTML = r"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Server Defender — 服务器安全与自愈防御中心</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600&family=SF+Pro+Display:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
:root {
  --bg: #090d16;
  --bg-gradient: radial-gradient(circle at 50% 0%, #151e32 0%, #090d16 85%);
  --panel-bg: rgba(21, 30, 48, 0.65);
  --panel-border: rgba(255, 255, 255, 0.08);
  --panel-hover: rgba(255, 255, 255, 0.14);
  --card-bg: rgba(14, 21, 35, 0.7);
  --card-border: rgba(255, 255, 255, 0.06);
  
  --text-primary: #f1f5f9;
  --text-secondary: #94a3b8;
  --text-muted: #64748b;
  
  --apple-blue: #0a84ff;
  --apple-green: #30d158;
  --apple-indigo: #5e5ce6;
  --apple-orange: #ff9f0a;
  --apple-red: #ff453a;
  --apple-purple: #bf5af2;
  --apple-teal: #64d2ff;
  
  --shadow-sm: 0 2px 8px rgba(0, 0, 0, 0.25);
  --shadow-md: 0 8px 24px rgba(0, 0, 0, 0.35);
  --shadow-lg: 0 16px 40px rgba(0, 0, 0, 0.5);
  --glow-blue: 0 0 20px rgba(10, 132, 255, 0.25);
  --glow-green: 0 0 20px rgba(48, 209, 88, 0.25);
}

* { margin: 0; padding: 0; box-sizing: border-box; }

body {
  font-family: -apple-system, BlinkMacSystemFont, "SF Pro Display", "PingFang SC", "Segoe UI", Roboto, sans-serif;
  background: var(--bg);
  background-image: var(--bg-gradient);
  background-attachment: fixed;
  color: var(--text-primary);
  min-height: 100vh;
  padding: 24px 32px;
  line-height: 1.5;
  -webkit-font-smoothing: antialiased;
}

/* 顶部导航 Header */
.header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 24px;
  padding: 16px 24px;
  background: var(--panel-bg);
  backdrop-filter: blur(24px);
  -webkit-backdrop-filter: blur(24px);
  border: 1px solid var(--panel-border);
  border-radius: 18px;
  box-shadow: var(--shadow-md);
}

.brand {
  display: flex;
  align-items: center;
  gap: 14px;
}

.brand-icon {
  width: 42px;
  height: 42px;
  border-radius: 12px;
  background: linear-gradient(135deg, var(--apple-blue), var(--apple-indigo));
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 22px;
  box-shadow: var(--glow-blue);
}

.brand-info h1 {
  font-size: 19px;
  font-weight: 700;
  letter-spacing: -0.3px;
  color: #fff;
  display: flex;
  align-items: center;
  gap: 10px;
}

.status-tag {
  font-size: 11px;
  padding: 2px 9px;
  border-radius: 20px;
  background: rgba(48, 209, 88, 0.15);
  color: var(--apple-green);
  border: 1px solid rgba(48, 209, 88, 0.3);
  display: inline-flex;
  align-items: center;
  gap: 5px;
  font-weight: 500;
}

.status-tag::before {
  content: "";
  width: 6px;
  height: 6px;
  border-radius: 50%;
  background: var(--apple-green);
  box-shadow: 0 0 8px var(--apple-green);
}

.brand-info p {
  font-size: 12px;
  color: var(--text-secondary);
  margin-top: 1px;
}

.header-actions {
  display: flex;
  align-items: center;
  gap: 14px;
}

.time-badge {
  font-size: 12px;
  color: var(--text-muted);
  font-family: "JetBrains Mono", monospace;
  background: rgba(0, 0, 0, 0.2);
  padding: 6px 12px;
  border-radius: 10px;
  border: 1px solid rgba(255, 255, 255, 0.04);
}

.btn {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  padding: 8px 16px;
  border-radius: 10px;
  font-size: 13px;
  font-weight: 600;
  cursor: pointer;
  transition: all 0.2s cubic-bezier(0.16, 1, 0.3, 1);
  border: 1px solid transparent;
  outline: none;
}

.btn-primary {
  background: linear-gradient(135deg, var(--apple-blue), #0066cc);
  color: #fff;
  box-shadow: 0 2px 10px rgba(10, 132, 255, 0.3);
}

.btn-primary:hover {
  transform: translateY(-1px);
  box-shadow: 0 4px 16px rgba(10, 132, 255, 0.45);
}

.btn-primary:active {
  transform: translateY(0);
}

/* 核心指标 KPI 仪表盘 */
.metrics-row {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
  gap: 14px;
  margin-bottom: 24px;
}

.metric-card {
  background: var(--panel-bg);
  backdrop-filter: blur(20px);
  -webkit-backdrop-filter: blur(20px);
  border: 1px solid var(--panel-border);
  border-radius: 16px;
  padding: 16px 18px;
  box-shadow: var(--shadow-sm);
  transition: all 0.25s ease;
  position: relative;
  overflow: hidden;
}

.metric-card:hover {
  border-color: var(--panel-hover);
  transform: translateY(-2px);
  box-shadow: var(--shadow-md);
}

.metric-card::after {
  content: "";
  position: absolute;
  top: 0;
  left: 0;
  right: 0;
  height: 2px;
  background: linear-gradient(90deg, transparent, rgba(255, 255, 255, 0.15), transparent);
}

.metric-label {
  font-size: 12px;
  color: var(--text-secondary);
  display: flex;
  align-items: center;
  gap: 6px;
  font-weight: 500;
}

.metric-value {
  font-size: 28px;
  font-weight: 700;
  color: #fff;
  margin-top: 6px;
  font-family: "JetBrains Mono", -apple-system, sans-serif;
  letter-spacing: -0.5px;
}

.metric-sub {
  font-size: 11px;
  color: var(--text-muted);
  margin-top: 4px;
}

.text-danger { color: var(--apple-red) !important; }
.text-success { color: var(--apple-green) !important; }
.text-warning { color: var(--apple-orange) !important; }
.text-blue { color: var(--apple-blue) !important; }
.text-purple { color: var(--apple-purple) !important; }

/* 主工作台双栏结构 */
.main-workspace {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 20px;
}

@media (max-width: 1180px) {
  .main-workspace { grid-template-columns: 1fr; }
  body { padding: 16px; }
}

.column {
  display: flex;
  flex-direction: column;
  gap: 20px;
}

/* 玻璃拟物卡片 Card */
.glass-card {
  background: var(--panel-bg);
  backdrop-filter: blur(24px);
  -webkit-backdrop-filter: blur(24px);
  border: 1px solid var(--panel-border);
  border-radius: 18px;
  padding: 20px 22px;
  box-shadow: var(--shadow-md);
  transition: border-color 0.25s;
}

.glass-card:hover {
  border-color: var(--panel-hover);
}

.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 14px;
  padding-bottom: 12px;
  border-bottom: 1px solid rgba(255, 255, 255, 0.05);
}

.card-title {
  font-size: 15px;
  font-weight: 600;
  color: #fff;
  display: flex;
  align-items: center;
  gap: 8px;
}

.count-badge {
  font-size: 11px;
  font-weight: 600;
  padding: 2px 8px;
  border-radius: 12px;
  background: rgba(255, 255, 255, 0.08);
  color: var(--text-secondary);
  border: 1px solid rgba(255, 255, 255, 0.05);
}

/* 表格体系 Table */
.table-container {
  overflow-x: auto;
  margin: 0 -8px;
  padding: 0 8px;
}

table {
  width: 100%;
  border-collapse: collapse;
  font-size: 13px;
  text-align: left;
}

th {
  color: var(--text-muted);
  font-weight: 500;
  padding: 8px 12px;
  border-bottom: 1px solid rgba(255, 255, 255, 0.05);
  font-size: 12px;
  letter-spacing: 0.2px;
}

td {
  padding: 10px 12px;
  border-bottom: 1px solid rgba(255, 255, 255, 0.03);
  color: var(--text-secondary);
  transition: background 0.15s;
}

tr:last-child td { border-bottom: none; }
tr:hover td { background: rgba(255, 255, 255, 0.03); }

.ip-cell {
  font-family: "JetBrains Mono", monospace;
  font-size: 12.5px;
  color: var(--text-primary);
  font-weight: 500;
}

.time-cell {
  font-family: "JetBrains Mono", monospace;
  font-size: 11.5px;
  color: var(--text-muted);
}

.user-cell {
  color: var(--apple-teal);
  font-weight: 500;
}

/* 标签 Badge */
.tag {
  display: inline-flex;
  align-items: center;
  padding: 2px 8px;
  border-radius: 6px;
  font-size: 11px;
  font-weight: 500;
}

.tag-danger {
  background: rgba(255, 69, 58, 0.15);
  color: #ff6b62;
  border: 1px solid rgba(255, 69, 58, 0.3);
}

.tag-warning {
  background: rgba(255, 159, 10, 0.15);
  color: #ffb340;
  border: 1px solid rgba(255, 159, 10, 0.3);
}

.tag-success {
  background: rgba(48, 209, 88, 0.15);
  color: #52dc74;
  border: 1px solid rgba(48, 209, 88, 0.3);
}

.tag-blue {
  background: rgba(10, 132, 255, 0.15);
  color: #4da3ff;
  border: 1px solid rgba(10, 132, 255, 0.3);
}

.empty-state {
  padding: 28px 0;
  text-align: center;
  color: var(--text-muted);
  font-size: 13px;
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 6px;
}

.empty-icon {
  font-size: 24px;
  opacity: 0.6;
}

/* 进程操作按钮 */
.btn-terminate {
  padding: 3px 9px;
  border-radius: 6px;
  font-size: 11px;
  font-weight: 600;
  background: rgba(255, 69, 58, 0.15);
  color: #ff5e52;
  border: 1px solid rgba(255, 69, 58, 0.3);
  cursor: pointer;
  transition: all 0.2s;
}

.btn-terminate:hover {
  background: var(--apple-red);
  color: #fff;
  box-shadow: 0 0 10px rgba(255, 69, 58, 0.4);
}

/* 模态框 Modal */
.modal {
  display: none;
  position: fixed;
  top: 0; left: 0; right: 0; bottom: 0;
  background: rgba(0, 0, 0, 0.65);
  backdrop-filter: blur(16px);
  -webkit-backdrop-filter: blur(16px);
  z-index: 999;
  align-items: center;
  justify-content: center;
  opacity: 0;
  transition: opacity 0.25s ease;
}

.modal.show {
  display: flex;
  opacity: 1;
}

.modal-dialog {
  background: #182236;
  border: 1px solid rgba(255, 255, 255, 0.12);
  border-radius: 20px;
  padding: 28px;
  width: 90%;
  max-width: 420px;
  box-shadow: var(--shadow-lg);
  transform: scale(0.95);
  transition: transform 0.25s cubic-bezier(0.16, 1, 0.3, 1);
}

.modal.show .modal-dialog {
  transform: scale(1);
}

.modal-title {
  font-size: 17px;
  font-weight: 600;
  color: #fff;
  margin-bottom: 8px;
}

.modal-desc {
  font-size: 13px;
  color: var(--text-secondary);
  margin-bottom: 18px;
}

.modal-input {
  width: 100%;
  padding: 10px 14px;
  border-radius: 10px;
  background: rgba(0, 0, 0, 0.35);
  border: 1px solid rgba(255, 255, 255, 0.1);
  color: #fff;
  font-family: "JetBrains Mono", monospace;
  font-size: 14px;
  margin-bottom: 20px;
  outline: none;
  transition: border-color 0.2s;
}

.modal-input:focus {
  border-color: var(--apple-blue);
  box-shadow: 0 0 0 3px rgba(10, 132, 255, 0.25);
}

.modal-footer {
  display: flex;
  justify-content: flex-end;
  gap: 10px;
}

.btn-secondary {
  background: rgba(255, 255, 255, 0.08);
  color: var(--text-secondary);
  border: 1px solid rgba(255, 255, 255, 0.05);
}

.btn-secondary:hover {
  background: rgba(255, 255, 255, 0.12);
  color: #fff;
}
</style>
</head>
<body>

<!-- 顶部导航 -->
<header class="header">
  <div class="brand">
    <div class="brand-icon">🛡️</div>
    <div class="brand-info">
      <h1>Server Defender <span class="status-tag">实时防护中</span></h1>
      <p>服务器安全监控与孤儿进程自愈中心</p>
    </div>
  </div>
  <div class="header-actions">
    <div class="time-badge" id="update-time">初始化中...</div>
    <button class="btn btn-primary" onclick="showBlockModal()">
      <span>🚧</span> 手动封禁 IP
    </button>
  </div>
</header>

<!-- 核心指标 KPI 仪表盘 -->
<section class="metrics-row">
  <div class="metric-card">
    <div class="metric-label">🛡️ 境外 / 爆破永久封禁</div>
    <div class="metric-value text-danger" id="stat-unames">-</div>
    <div class="metric-sub">自动下发 iptables 并同步</div>
  </div>
  <div class="metric-card">
    <div class="metric-label">🔒 fail2ban SSH 封禁</div>
    <div class="metric-value text-warning" id="stat-f2b-banned">-</div>
    <div class="metric-sub">累计阻断: <span id="stat-f2b-total">-</span> 次</div>
  </div>
  <div class="metric-card">
    <div class="metric-label">🌐 frps 隧道防御封禁</div>
    <div class="metric-value text-blue" id="stat-frps-banned">-</div>
    <div class="metric-sub">累计封禁: <span id="stat-frps-total">-</span> 次</div>
  </div>
  <div class="metric-card">
    <div class="metric-label">⚡ 进程自愈收割</div>
    <div class="metric-value text-purple" id="stat-reaper">-</div>
    <div class="metric-sub">失控孤儿进程收割数</div>
  </div>
  <div class="metric-card">
    <div class="metric-label">🗡️ SSH 探测尝试</div>
    <div class="metric-value text-success" id="stat-total-attacks">-</div>
    <div class="metric-sub">历史探测与攻击频次</div>
  </div>
</section>

<!-- 主工作台：双栏架构 -->
<main class="main-workspace">
  <!-- 左栏：网络安全与主动防御 -->
  <div class="column">
    <!-- 境外拦截与用户名封禁 -->
    <div class="glass-card">
      <div class="card-header">
        <div class="card-title">🔐 境外 IP 阻断与用户名风暴封禁</div>
        <div class="count-badge" id="badge-unames">0</div>
      </div>
      <div class="table-container" id="container-unames">
        <div class="empty-state"><div class="empty-icon">✅</div><span>系统平稳，暂无永久封禁 IP</span></div>
      </div>
    </div>

    <!-- fail2ban 隧道动态封禁 -->
    <div class="glass-card">
      <div class="card-header">
        <div class="card-title">🛡️ frps 隧道 fail2ban 动态封禁</div>
        <div class="count-badge" id="badge-frps-f2b">0</div>
      </div>
      <div class="table-container" id="container-frps-f2b">
        <div class="empty-state"><div class="empty-icon">✅</div><span>暂无动态封禁 IP</span></div>
      </div>
    </div>

    <!-- 最近攻击记录 -->
    <div class="glass-card">
      <div class="card-header">
        <div class="card-title">🕒 实时探测与攻击事件流</div>
      </div>
      <div class="table-container" id="container-recent">
        <div class="empty-state"><div class="empty-icon">⏳</div><span>数据加载中...</span></div>
      </div>
    </div>

    <!-- 攻击 TOP IP 排行 -->
    <div class="glass-card">
      <div class="card-header">
        <div class="card-title">🏅 攻击来源 TOP IP</div>
      </div>
      <div class="table-container" id="container-top-ips">
        <div class="empty-state"><div class="empty-icon">⏳</div><span>数据加载中...</span></div>
      </div>
    </div>
  </div>

  <!-- 右栏：主机进程健康自愈与系统监控 -->
  <div class="column">
    <!-- 实时高负载进程监控 -->
    <div class="glass-card">
      <div class="card-header">
        <div class="card-title">🔥 实时 TOP 负载进程监控 (CPU)</div>
      </div>
      <div class="table-container" id="container-top-procs">
        <div class="empty-state"><div class="empty-icon">⏳</div><span>扫描系统负载中...</span></div>
      </div>
    </div>

    <!-- 进程自愈收割战报 -->
    <div class="glass-card">
      <div class="card-header">
        <div class="card-title">⚡ 异常失控进程自愈收割战报</div>
        <div class="count-badge" id="badge-reaper">0</div>
      </div>
      <div class="table-container" id="container-reaper">
        <div class="empty-state"><div class="empty-icon">✅</div><span>系统平稳，未出现失控死循环孤儿进程</span></div>
      </div>
    </div>

    <!-- 被尝试用户名排行 -->
    <div class="glass-card">
      <div class="card-header">
        <div class="card-title">🎯 被探测爆破账号排行</div>
      </div>
      <div class="table-container" id="container-top-users">
        <div class="empty-state"><div class="empty-icon">⏳</div><span>数据加载中...</span></div>
      </div>
    </div>

    <!-- fail2ban 本机 SSH 封禁 -->
    <div class="glass-card">
      <div class="card-header">
        <div class="card-title">📋 本机 SSH fail2ban 封禁态势</div>
        <div class="count-badge" id="badge-f2b">0</div>
      </div>
      <div class="table-container" id="container-f2b">
        <div class="empty-state"><div class="empty-icon">✅</div><span>本机直连 22 端口无异常</span></div>
      </div>
    </div>
  </div>
</main>

<!-- 手动封禁模态框 -->
<div class="modal" id="blockModal">
  <div class="modal-dialog">
    <div class="modal-title">🚧 手动封禁恶意 IP</div>
    <div class="modal-desc">下发 iptables DROP 规则至本机并自动同步至公网中转机。</div>
    <input type="text" id="blockIpInput" class="modal-input" placeholder="输入 IP 地址 (如: 198.51.100.24)" />
    <div class="modal-footer">
      <button class="btn btn-secondary" onclick="hideBlockModal()">取消</button>
      <button class="btn btn-primary" onclick="submitBlockIP()">确认封禁</button>
    </div>
  </div>
</div>

<script>
async function fetchData() {
  try {
    const res = await fetch('/api/data');
    const data = await res.json();

    // 更新指标卡片
    document.getElementById('stat-unames').textContent = data.unames_count || 0;
    document.getElementById('stat-f2b-banned').textContent = data.f2b_banned_count || 0;
    document.getElementById('stat-f2b-total').textContent = data.f2b_total_banned || 0;
    document.getElementById('stat-frps-banned').textContent = data.frps_f2b_banned_count || 0;
    document.getElementById('stat-frps-total').textContent = data.frps_f2b_total_banned || 0;
    document.getElementById('stat-reaper').textContent = data.reaper_count || 0;
    document.getElementById('stat-total-attacks').textContent = data.total_attacks || 0;

    // 更新角标
    document.getElementById('badge-unames').textContent = data.unames_count || 0;
    document.getElementById('badge-frps-f2b').textContent = data.frps_f2b_banned_count || 0;
    document.getElementById('badge-f2b').textContent = data.f2b_banned_count || 0;
    document.getElementById('badge-reaper').textContent = data.reaper_count || 0;

    // 更新各板块内容
    document.getElementById('container-unames').innerHTML = data.unames_html;
    document.getElementById('container-frps-f2b').innerHTML = data.frps_f2b_html;
    document.getElementById('container-recent').innerHTML = data.recent_html;
    document.getElementById('container-top-ips').innerHTML = data.top_ips_html;
    document.getElementById('container-top-procs').innerHTML = data.top_procs_html;
    document.getElementById('container-reaper').innerHTML = data.reaper_events_html;
    document.getElementById('container-top-users').innerHTML = data.top_users_html;
    document.getElementById('container-f2b').innerHTML = data.f2b_html;

    document.getElementById('update-time').textContent = data.time;
  } catch (err) {
    console.error('Fetch error:', err);
  }
}

async function doKillProcess(pid, comm) {
  if (!confirm(`⚠️ 确认强制终止异常失控进程 PID ${pid} (${comm}) 吗？`)) return;
  try {
    const res = await fetch('/api/reaper/kill', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({pid: pid})
    });
    const result = await res.json();
    alert(result.msg);
    fetchData();
  } catch (err) {
    alert('终止失败: ' + err);
  }
}

function showBlockModal() {
  document.getElementById('blockModal').classList.add('show');
  document.getElementById('blockIpInput').focus();
}

function hideBlockModal() {
  document.getElementById('blockModal').classList.remove('show');
}

async function submitBlockIP() {
  const ip = document.getElementById('blockIpInput').value.trim();
  if (!ip) return;
  try {
    await fetch('/api/block_ip', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({ip: ip})
    });
    document.getElementById('blockIpInput').value = '';
    hideBlockModal();
    fetchData();
  } catch (err) {
    alert('封禁操作失败: ' + err);
  }
}

document.getElementById('blockIpInput').addEventListener('keydown', (e) => {
  if (e.key === 'Enter') submitBlockIP();
});

fetchData();
setInterval(fetchData, 4000);
</script>
</body>
</html>
"""

def run(cmd, timeout=5):
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.STDOUT, timeout=timeout).decode("utf-8", errors="replace")
        return out
    except Exception as e:
        return ""

def get_fail2ban_status():
    f2b_out = run(["fail2ban-client", "status", "sshd"])
    banned_ips = []
    total_banned = 0
    total_failed = 0
    m = re.search(r"Banned IP list:\s*(.*)", f2b_out)
    if m and m.group(1).strip():
        banned_ips = m.group(1).strip().split()
    m2 = re.search(r"Total banned:\s*(\d+)", f2b_out)
    if m2: total_banned = int(m2.group(1))
    m3 = re.search(r"Total failed:\s*(\d+)", f2b_out)
    if m3: total_failed = int(m3.group(1))

    frps_banned_ips = []
    frps_total_banned = 0
    frps_total_failed = 0
    frps_out = run(["fail2ban-client", "status", "frps-ssh"])
    if frps_out:
        m = re.search(r"Banned IP list:\s*(.*)", frps_out)
        if m and m.group(1).strip():
            frps_banned_ips = m.group(1).strip().split()
        m2 = re.search(r"Total banned:\s*(\d+)", frps_out)
        if m2: frps_total_banned = int(m2.group(1))
        m3 = re.search(r"Total failed:\s*(\d+)", frps_out)
        if m3: frps_total_failed = int(m3.group(1))

    return {
        "banned_count": len(banned_ips),
        "banned_list": banned_ips,
        "total_banned": total_banned,
        "total_failed": total_failed,
        "frps_banned_count": len(frps_banned_ips),
        "frps_banned_list": frps_banned_ips,
        "frps_total_banned": frps_total_banned,
        "frps_total_failed": frps_total_failed
    }

def get_iptables_blocked():
    out = run(["iptables", "-L", "INPUT", "-v", "-n", "--line-numbers"])
    blocked = []
    for line in out.split("\n"):
        if "DROP" in line or "REJECT" in line:
            parts = line.split()
            if len(parts) >= 9:
                num = parts[0]
                pkts = parts[1]
                src = parts[8]
                if src != "0.0.0.0/0":
                    blocked.append({"num": num, "pkts": pkts, "src": src})
    return blocked

def get_syn_flood():
    out = run(["dmesg", "-T"])
    entries = []
    for line in out.split("\n"):
        if "SYN flood" in line or "possible SYN flooding" in line:
            m = re.search(r"\[(.*?)\]", line)
            time_str = m.group(1) if m else "Recently"
            m_port = re.search(r"port (\d+)", line)
            port_str = m_port.group(1) if m_port else "Unknown"
            entries.append({"time": time_str, "port": port_str})
    return entries

def get_lastb_stats():
    out = run(["lastb", "-n", "300"])
    ip_counts = {}
    user_counts = {}
    recent = []
    total = 0
    try:
        lines = out.strip().split("\n")
        for line in lines:
            if not line or "btmp begins" in line: continue
            total += 1
            parts = line.split()
            if len(parts) >= 3:
                user = parts[0]
                ip = parts[2]
                user_counts[user] = user_counts.get(user, 0) + 1
                if ip not in ["127.0.0.1", "::1", "0.0.0.0", "localhost"]:
                    ip_counts[ip] = ip_counts.get(ip, 0) + 1
                if len(recent) < 10:
                    recent.append({"user": user, "ip": ip})
        top_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:8]
        top_users = sorted(user_counts.items(), key=lambda x: x[1], reverse=True)[:8]
        return {
            "total": total,
            "top_ips": [{"ip": ip, "count": count} for ip, count in top_ips],
            "top_users": [{"user": user, "count": count} for user, count in top_users],
            "recent": recent
        }
    except:
        return {"total": 0, "top_ips": [], "top_users": [], "recent": []}

# 渲染函数体系 (现代 Apple 风格)
def render_f2b_html(f2b):
    if not f2b["banned_list"]:
        return "<div class=\"empty-state\"><div class=\"empty-icon\">✅</div><span>暂无动态封禁 IP</span></div>"
    html = "<table><tr><th>#</th><th>IP 地址</th><th>状态</th></tr>"
    for i, ip in enumerate(f2b["banned_list"], 1):
        html += f"<tr><td>{i}</td><td class=\"ip-cell\">{ip}</td><td><span class=\"tag tag-danger\">封禁中</span></td></tr>"
    return html + "</table>"

def render_frps_f2b_html(f2b):
    if not f2b["frps_banned_list"]:
        return "<div class=\"empty-state\"><div class=\"empty-icon\">✅</div><span>暂无动态封禁 IP</span></div>"
    html = "<table><tr><th>#</th><th>IP 地址</th><th>防护状态</th></tr>"
    for i, ip in enumerate(f2b["frps_banned_list"], 1):
        html += f"<tr><td>{i}</td><td class=\"ip-cell\">{ip}</td><td><span class=\"tag tag-warning\">隧道隔离中</span></td></tr>"
    return html + "</table>"

def render_top_ips_html(top_ips):
    if not top_ips:
        return "<div class=\"empty-state\"><div class=\"empty-icon\">✅</div><span>暂无高频攻击记录</span></div>"
    html = "<table><tr><th>#</th><th>攻击来源 IP</th><th>探测次数</th></tr>"
    for i, item in enumerate(top_ips, 1):
        tag_cls = "tag-danger" if item['count'] >= 50 else ("tag-warning" if item['count'] >= 10 else "tag-blue")
        html += f"<tr><td>{i}</td><td class=\"ip-cell\">{item['ip']}</td><td><span class=\"tag {tag_cls}\">{item['count']} 次</span></td></tr>"
    return html + "</table>"

def render_top_users_html(top_users):
    if not top_users:
        return "<div class=\"empty-state\"><div class=\"empty-icon\">✅</div><span>暂无记录</span></div>"
    html = "<table><tr><th>#</th><th>被尝试账号</th><th>探测频次</th></tr>"
    for i, item in enumerate(top_users, 1):
        tag_cls = "tag-danger" if item['count'] >= 50 else ("tag-warning" if item['count'] >= 10 else "tag-blue")
        html += f"<tr><td>{i}</td><td class=\"user-cell\">{item['user']}</td><td><span class=\"tag {tag_cls}\">{item['count']} 次</span></td></tr>"
    return html + "</table>"

def render_recent_html(recent):
    if not recent:
        return "<div class=\"empty-state\"><div class=\"empty-icon\">✅</div><span>暂无攻击记录</span></div>"
    html = "<table><tr><th>#</th><th>尝试账号</th><th>来源 IP</th></tr>"
    for i, item in enumerate(recent, 1):
        html += f"<tr><td>{i}</td><td class=\"user-cell\">{item['user']}</td><td class=\"ip-cell\">{item['ip']}</td></tr>"
    return html + "</table>"

# 用户名与境外封禁列表
UNAMES_BAN_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "perm_ban.txt")

def get_usernames_bans():
    bans = []
    try:
        with open(UNAMES_BAN_FILE, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line: continue
                parts = line.split("\t")
                bans.append({
                    "ip": parts[0],
                    "reason": parts[1] if len(parts) > 1 else "-",
                    "time": parts[2] if len(parts) > 2 else "-",
                    "location": parts[3] if len(parts) > 3 else "-"
                })
    except Exception:
        pass
    return bans

def render_usernames_html(bans):
    if not bans:
        return "<div class=\"empty-state\"><div class=\"empty-icon\">✅</div><span>系统平稳，暂无永久封禁 IP</span></div>"
    html = "<table><tr><th>#</th><th>来源 IP</th><th>拦截策略 / 原因</th><th>归属地</th><th>时间</th></tr>"
    for i, b in enumerate(bans, 1):
        reason = b.get('reason', '')
        tag_cls = "tag-danger" if "境外" in reason else "tag-warning"
        loc = b.get('location', '-')
        html += f"<tr><td>{i}</td><td class=\"ip-cell\">{b['ip']}</td><td><span class=\"tag {tag_cls}\">{reason}</span></td><td style=\"color:var(--text-primary)\">{loc}</td><td class=\"time-cell\">{b['time']}</td></tr>"
    return html + "</table>"

def render_top_procs_html(procs):
    if not procs:
        return "<div class=\"empty-state\"><div class=\"empty-icon\">✅</div><span>系统运行平稳，无高负载异常进程</span></div>"
    html = "<table><tr><th>PID</th><th>用户</th><th>%CPU</th><th>运行时长</th><th>命令</th><th>操作</th></tr>"
    for p in procs[:6]:
        cpu_tag = "tag-danger" if p['cpu'] >= 50.0 else ("tag-warning" if p['cpu'] >= 20.0 else "tag-success")
        html += f"<tr><td><b>{p['pid']}</b></td><td>{p['user']}</td><td><span class=\"tag {cpu_tag}\">{p['cpu']}%</span></td><td class=\"time-cell\">{p['etime']}</td><td title=\"{p['args']}\" style=\"color:var(--text-primary)\">{p['comm']}</td><td><button class=\"btn-terminate\" onclick=\"doKillProcess({p['pid']}, '{p['comm']}')\">终止</button></td></tr>"
    return html + "</table>"

def render_reaper_events_html(events):
    if not events:
        return "<div class=\"empty-state\"><div class=\"empty-icon\">✅</div><span>系统自愈引擎正常，无失控孤儿进程</span></div>"
    html = "<table><tr><th>时间</th><th>PID</th><th>命令</th><th>收割原因</th></tr>"
    for ev in events[:8]:
        html += f"<tr><td class=\"time-cell\">{ev['time']}</td><td>{ev['pid']}</td><td style=\"color:var(--text-primary)\"><b>{ev['comm']}</b></td><td><span class=\"tag tag-warning\">{ev['reason']}</span></td></tr>"
    return html + "</table>"

@app.route("/")
def index():
    return render_template_string(HTML)

@app.route("/api/data")
def api_data():
    f2b = get_fail2ban_status()
    lastb = get_lastb_stats()
    unames_bans = get_usernames_bans()
    top_procs = get_high_cpu_processes(limit=6)
    reaper_events = load_events()
    return jsonify({
        "total_attacks": lastb["total"],
        "f2b_banned_count": f2b["banned_count"],
        "f2b_total_banned": f2b["total_banned"],
        "f2b_html": render_f2b_html(f2b),
        "frps_f2b_banned_count": f2b["frps_banned_count"],
        "frps_f2b_total_banned": f2b["frps_total_banned"],
        "frps_f2b_html": render_frps_f2b_html(f2b),
        "top_ips_html": render_top_ips_html(lastb["top_ips"]),
        "top_users_html": render_top_users_html(lastb["top_users"]),
        "recent_html": render_recent_html(lastb["recent"]),
        "unames_count": len(unames_bans),
        "unames_html": render_usernames_html(unames_bans),
        "reaper_count": len(reaper_events),
        "reaper_events_html": render_reaper_events_html(reaper_events),
        "top_procs_html": render_top_procs_html(top_procs),
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    })

@app.route("/api/block_ip", methods=["POST"])
def block_ip():
    data = request.get_json() or {}
    ip = data.get("ip", "").strip()
    if not ip:
        return jsonify({"code": 1, "msg": "IP 不能为空"})
    try:
        run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"])
        run(["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=5", "root@47.98.244.173", f"iptables -A INPUT -s {ip} -j DROP"])
        return jsonify({"code": 0, "msg": f"IP {ip} 已成功下发双端永久屏蔽"})
    except Exception as e:
        return jsonify({"code": 1, "msg": str(e)})

@app.route("/api/reaper/kill", methods=["POST"])
def kill_process():
    data = request.get_json() or {}
    pid = data.get("pid")
    if not pid:
        return jsonify({"code": 1, "msg": "PID 不能为空"})
    ok, msg = kill_by_pid(int(pid))
    return jsonify({"code": 0 if ok else 1, "msg": msg})

if __name__ == "__main__":
    t = threading.Thread(target=reaper_background_worker, daemon=True)
    t.start()
    app.run(host="0.0.0.0", port=8899, debug=False)
