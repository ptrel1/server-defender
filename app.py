#!/usr/bin/env python3
"""SSH attack monitor dashboard & Host Health Defender"""
import subprocess, re, json, os, threading, time
from datetime import datetime
from flask import Flask, jsonify, render_template_string, request

# 导入进程收割模块
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
<html lang="zh">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>🛡️ Server Defender — 服务器安全与健康防御中心</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{
  --bg: #1a0000; --bg2: #2d0000; --bg-card: #1a0000; --bg-card-end: #2d0000;
  --text: #ffd700; --text2: #ffeb99; --text3: #daa520;
  --accent: #ff4500; --accent2: #8b0000; --accent-glow: rgba(255,215,0,0.2);
  --border: #8b0000; --border-hover: #ffd700;
  --danger: #ff6347; --success: #7cfc00; --warn: #9370db; --info: #4169e1;
  --banner-start: #8b0000; --banner-mid: #cc0000; --banner-end: #8b0000;
  --hero-text: #ffd700; --hero-glow: #ffd700;
  --stat-attack-bg: #4a0000; --stat-attack-end: #6b0000;
  --badge-bg: #8b0000; --badge-text: #ffd700; --badge-border: #ff4500;
  --badge-high-bg: #cc0000; --badge-high-end: #ff4500; --badge-high-border: #ffd700;
  --bg-hover: rgba(255,69,0,0.1);
}
body{
  font-family:-apple-system,"PingFang SC","Microsoft YaHei",sans-serif;
  background:linear-gradient(135deg,var(--bg) 0%,var(--bg2) 30%,var(--bg) 60%,#0d0000 100%);
  color:var(--text); padding:20px; min-height:100vh; position:relative; overflow-x:hidden;
  transition:background 0.5s,color 0.3s
}

.theme-bar{display:flex;justify-content:flex-end;gap:3px;margin-bottom:8px;position:relative;z-index:2}
.theme-dot{width:28px;height:28px;border-radius:50%;cursor:pointer;border:2px solid transparent;transition:all 0.2s;position:relative}
.theme-dot:hover{transform:scale(1.2);border-color:#fff}
.theme-dot.active{border-color:#fff!important;box-shadow:0 0 12px currentColor}
.theme-dot[data-theme="red"]{background:linear-gradient(135deg,#cc0000,#ff4500)}
.theme-dot[data-theme="hacker"]{background:linear-gradient(135deg,#003300,#00ff41)}
.theme-dot[data-theme="dark"]{background:linear-gradient(135deg,#161b22,#30363d)}
.theme-dot[data-theme="warn"]{background:linear-gradient(135deg,#ffcc00,#ff4444)}
.theme-dot[data-theme="cyber"]{background:linear-gradient(135deg,#001a3d,#00bfff)}

.hero-banner{
  background:linear-gradient(135deg,var(--banner-start),var(--banner-mid),var(--banner-end));
  border:3px solid var(--border-hover);
  border-radius:16px; padding:20px 32px; margin-bottom:18px;
  text-align:center; position:relative;
  box-shadow:0 0 40px var(--accent-glow),inset 0 0 40px rgba(255,215,0,0.05);
  animation:borderPulse 3s ease-in-out infinite; z-index:1; transition:all 0.5s
}
.hero-banner h1{font-size:28px;color:var(--hero-text);animation:glow 2s ease-in-out infinite;letter-spacing:4px;transition:all 0.5s}
.hero-banner .subtitle{color:var(--text2);font-size:14px;margin-top:6px;opacity:0.9}
@keyframes borderPulse{0%,100%{border-color:var(--accent)}50%{border-color:var(--border-hover)}}
@keyframes glow{0%,100%{text-shadow:0 0 10px var(--hero-glow),0 0 20px var(--accent)}50%{text-shadow:0 0 20px var(--hero-glow),0 0 40px var(--accent),0 0 60px var(--accent)}}

.top-stats{display:flex;gap:14px;margin-bottom:18px;flex-wrap:wrap;z-index:1;position:relative}
.stat-card{
  background:linear-gradient(135deg,var(--bg-card),var(--bg-card-end));
  border:2px solid var(--accent); border-radius:12px;
  padding:16px 20px; min-width:130px; flex:1; text-align:center; position:relative;
  box-shadow:0 4px 20px rgba(255,69,0,0.15); transition:all 0.3s
}
.stat-card:hover{border-color:var(--border-hover);box-shadow:0 4px 30px var(--accent-glow)}
.stat-card .num{font-size:32px;font-weight:900;line-height:1.2}
.stat-card .label{font-size:12px;margin-top:4px;letter-spacing:1px;color:var(--text2)}
.stat-card.attack{background:linear-gradient(135deg,var(--stat-attack-bg),var(--stat-attack-end));border-color:var(--accent)}
.stat-card.attack .num{color:var(--danger)}
.stat-card.banned{background:linear-gradient(135deg,#2d4a00,#3d6b00);border-color:#7cfc00}
.stat-card.banned .num{color:#7cfc00}.stat-card.banned .label{color:#adff2f}
.stat-card.blocked{background:linear-gradient(135deg,#00004a,#00006b);border-color:var(--info)}
.stat-card.blocked .num{color:var(--info)}.stat-card.blocked .label{color:#87ceeb}
.stat-card.syn{background:linear-gradient(135deg,#2d004a,#4a006b);border-color:var(--warn)}
.stat-card.syn .num{color:var(--warn)}.stat-card.syn .label{color:#dda0dd}
.stat-card.reaper{background:linear-gradient(135deg,#3d2000,#5c3000);border-color:#ff8c00}
.stat-card.reaper .num{color:#ffa500}.stat-card.reaper .label{color:#ffd700}
.stat-card .badge-wrapper{position:absolute;top:-8px;right:-8px;background:var(--accent);color:#fff;border-radius:50%;width:28px;height:28px;line-height:28px;font-size:13px;font-weight:bold;box-shadow:0 2px 8px rgba(255,69,0,0.4)}

.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(480px,1fr));gap:14px;z-index:1;position:relative}
.card{
  background:linear-gradient(135deg,var(--bg),var(--bg2) 50%,var(--bg));
  border:2px solid var(--border); border-radius:12px;
  padding:18px; box-shadow:0 4px 20px rgba(0,0,0,0.3); transition:all 0.3s
}
.card:hover{border-color:var(--accent);box-shadow:0 4px 30px rgba(255,69,0,0.15)}
.card h2{
  color:var(--hero-text); font-size:15px; margin-bottom:12px; padding-bottom:8px;
  border-bottom:2px solid var(--border); display:flex; align-items:center; gap:8px; letter-spacing:1px
}
.card h2 .badge{
  font-size:11px; background:var(--badge-bg); color:var(--badge-text);
  padding:2px 10px; border-radius:10px; font-weight:400; border:1px solid var(--badge-border)
}

table{width:100%;border-collapse:collapse;font-size:13px}
th{text-align:left;color:var(--accent);padding:5px 10px;border-bottom:1px solid var(--border);font-weight:500;white-space:nowrap}
td{padding:5px 10px;border-bottom:1px solid var(--bg2);white-space:nowrap;color:var(--text2)}
tr:hover td{background:var(--bg-hover)}
.ip{font-family:"Consolas","Courier New",monospace;font-size:12px;color:var(--danger)}
.time{color:var(--text3);font-size:12px}
.user{color:var(--success);font-weight:bold}
.attack-row td{color:var(--danger)}
.badge-cnt{display:inline-block;padding:2px 8px;border-radius:10px;font-size:11px;min-width:22px;text-align:center;font-weight:bold}
.badge-high{background:linear-gradient(135deg,var(--badge-high-bg),var(--badge-high-end));color:#fff;border:1px solid var(--badge-high-border)}
.badge-mid{background:linear-gradient(135deg,#8b4500,#daa520);color:#fff}
.badge-low{background:linear-gradient(135deg,#1a4a00,#3d6b00);color:#adff2f}
.empty{color:var(--border);font-size:13px;padding:16px 0;text-align:center;font-style:italic}

.btn-kill{
  background:linear-gradient(135deg,#8b0000,#cc0000);
  color:#fff; border:1px solid #ff4500; border-radius:4px;
  padding:2px 8px; font-size:11px; cursor:pointer; font-weight:bold; transition:all 0.2s
}
.btn-kill:hover{background:#ff4500;box-shadow:0 0 10px rgba(255,69,0,0.6)}

.footer{color:var(--border);font-size:12px;margin-top:14px;display:flex;justify-content:space-between;align-items:center;z-index:1;position:relative}
.footer button{
  background:linear-gradient(135deg,var(--accent2),var(--accent));
  color:var(--text); border:2px solid var(--border-hover); border-radius:8px;
  padding:6px 18px; cursor:pointer; font-size:12px; font-weight:bold; letter-spacing:1px; transition:all 0.2s
}
.footer button:hover{box-shadow:0 0 20px var(--accent-glow)}

.modal{display:none;position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,.8);z-index:2000;align-items:center;justify-content:center}
.modal.show{display:flex}
.modal-box{
  background:linear-gradient(135deg,var(--bg2),#4a0000);
  border:3px solid var(--border-hover); border-radius:16px;
  padding:28px; min-width:340px; max-width:90%; box-shadow:0 0 60px var(--accent-glow)
}
.modal-box h3{color:var(--text);margin-bottom:14px;font-size:18px;text-align:center}
.modal-box input{width:100%;padding:10px 14px;background:var(--bg);border:2px solid var(--border);border-radius:8px;color:var(--text);font-size:14px;margin-bottom:14px;font-family:monospace}
.modal-box input:focus{outline:none;border-color:var(--border-hover)}
.modal-box .btn-group{display:flex;gap:10px;justify-content:flex-end}
.modal-box .btn-group button{padding:8px 20px;border-radius:8px;border:2px solid var(--border-hover);cursor:pointer;font-size:13px;font-weight:bold;letter-spacing:1px}
.btn-primary{background:linear-gradient(135deg,var(--accent2),var(--accent));color:var(--text)}
.btn-primary:hover{box-shadow:0 0 20px rgba(255,69,0,0.4)}
.btn-cancel{background:var(--bg);color:var(--border);border-color:var(--border)!important}
.btn-cancel:hover{color:var(--accent);border-color:var(--accent)!important}

@media(max-width:600px){.grid{grid-template-columns:1fr}.stat-card{min-width:100px;padding:12px 14px}.stat-card .num{font-size:24px}.hero-banner h1{font-size:20px}}
</style>
</head>
<body>

<div class="theme-bar">
  <div class="theme-dot active" data-theme="red" title="🏮 经典红" onclick="setTheme('red')"></div>
  <div class="theme-dot" data-theme="hacker" title="💀 黑客终端" onclick="setTheme('hacker')"></div>
  <div class="theme-dot" data-theme="dark" title="🌙 暗夜战报" onclick="setTheme('dark')"></div>
  <div class="theme-dot" data-theme="warn" title="🚨 警示警戒" onclick="setTheme('warn')"></div>
  <div class="theme-dot" data-theme="cyber" title="🔵 蓝焰科技" onclick="setTheme('cyber')"></div>
</div>

<div class="hero-banner">
  <h1>🛡️ SSH 攻击与主机健康防御</h1>
  <div class="subtitle">全功能服务器卫士 &nbsp;|&nbsp; <span id="update-info">加载中...</span></div>
</div>

<div class="top-stats">
  <div class="stat-card attack"><div class="num" id="stat-attack">-</div><div class="label">🗡️ 暴力破解次数</div></div>
  <div class="stat-card banned"><div class="num" id="stat-banned">-</div><div class="label">🔒 fail2ban 封禁中</div><div class="badge-wrapper">!</div></div>
  <div class="stat-card banned"><div class="num" id="stat-total-banned">-</div><div class="label">🏆 SSH 累计封禁</div></div>
  <div class="stat-card blocked"><div class="num" id="stat-frps-banned">-</div><div class="label">🛡️ frps 封禁中</div></div>
  <div class="stat-card blocked"><div class="num" id="stat-frps-total">-</div><div class="label">🏆 frps 累计封禁</div></div>
  <div class="stat-card blocked"><div class="num" id="stat-iptables">-</div><div class="label">🛡️ iptables 屏蔽</div></div>
  <div class="stat-card syn"><div class="num" id="stat-syn">-</div><div class="label">💣 SYN Flood 告警</div></div>
  <div class="stat-card banned"><div class="num" id="stat-unames">-</div><div class="label">🔐 用户名风暴封禁</div><div class="badge-wrapper">!</div></div>
  <div class="stat-card reaper"><div class="num" id="stat-reaper">-</div><div class="label">⚡ 自动自愈收割</div><div class="badge-wrapper">!</div></div>
</div>

<div class="grid">
  <div class="card"><h2>📋 fail2ban SSH 封禁 <span class="badge" id="f2b-badge">0</span></h2><div id="f2b-list"><div class="empty">✅ 暂无封禁</div></div></div>
  <div class="card"><h2>🛡️ fail2ban frps 自动封禁 <span class="badge" id="frps-f2b-badge">0</span></h2><div id="frps-f2b-list"><div class="empty">⏳ 监控中...</div></div></div>
  <div class="card"><h2>🚧 iptables 手动屏蔽</h2><div id="iptables-list"><div class="empty">加载中...</div></div></div>
  <div class="card"><h2>🏅 攻击 IP 排行</h2><div id="top-ips"><div class="empty">加载中...</div></div></div>
  <div class="card"><h2>🎯 被尝试账号排行</h2><div id="top-users"><div class="empty">加载中...</div></div></div>
  <div class="card"><h2>🔥 实时高 CPU 进程监控</h2><div id="top-procs"><div class="empty">加载中...</div></div></div>
  <div class="card"><h2>⚡ 异常失控进程收割战报 <span class="badge" id="reaper-badge">0</span></h2><div id="reaper-events"><div class="empty">✅ 系统平稳，暂无失控进程</div></div></div>
  <div class="card"><h2>🔐 用户名风暴永久封禁 <span class="badge" id="unames-badge">0</span></h2><div id="unames-list"><div class="empty">✅ 暂无封禁</div></div></div>
  <div class="card"><h2>📊 frps 端口扫描 TOP IP</h2><div id="frps-scan"><div class="empty">⏳ 分析中...</div></div></div>
  <div class="card"><h2>💣 SYN Flood 告警历史</h2><div id="syn-history"><div class="empty">✅ 未检测到攻击</div></div></div>
  <div class="card"><h2>🕒 最近攻击记录</h2><div id="recent-attacks"><div class="empty">加载中...</div></div></div>
</div>

<div class="footer">
  <span>🛡️ Server Defender 安全与主机健康防护</span>
  <button onclick="showBlockIP()">🚧 手动屏蔽 IP</button>
</div>

<div class="modal" id="block-modal">
  <div class="modal-box">
    <h3>🚧 手动屏蔽恶意 IP</h3>
    <input type="text" id="block-ip-input" placeholder="输入要屏蔽的 IP 地址 (如 1.2.3.4)" />
    <div class="btn-group">
      <button class="btn-cancel" onclick="hideBlockIP()">取消</button>
      <button class="btn-primary" onclick="doBlockIP()">确认屏蔽</button>
    </div>
  </div>
</div>

<script>
const THEMES = {
  red: {
    label:'🏮 经典红',
    bg:'#1a0000',bg2:'#2d0000',bgCard:'#1a0000',bgCardEnd:'#2d0000',
    text:'#ffd700',text2:'#ffeb99',text3:'#daa520',
    accent:'#ff4500',accent2:'#8b0000',accentGlow:'rgba(255,215,0,0.2)',
    border:'#8b0000',borderHover:'#ffd700',
    danger:'#ff6347',success:'#7cfc00',warn:'#9370db',info:'#4169e1',
    bannerStart:'#8b0000',bannerMid:'#cc0000',bannerEnd:'#8b0000',
    heroText:'#ffd700',heroGlow:'#ffd700',
    statAttackBg:'#4a0000',statAttackEnd:'#6b0000',
    badgeBg:'#8b0000',badgeText:'#ffd700',badgeBorder:'#ff4500',
    badgeHighBg:'#cc0000',badgeHighEnd:'#ff4500',badgeHighBorder:'#ffd700',
    bgHover:'rgba(255,69,0,0.1)',
    hero:'🛡️ SSH 攻击与主机健康防御',subtitle:'全功能服务器卫士',footer:'🛡️ 实时安全防护中'
  },
  hacker: {
    label:'💀 黑客终端',
    bg:'#0a0e0a',bg2:'#0d140d',bgCard:'#0a0e0a',bgCardEnd:'#0d140d',
    text:'#00ff41',text2:'#80ff80',text3:'#40aa40',
    accent:'#00ff41',accent2:'#003300',accentGlow:'rgba(0,255,65,0.2)',
    border:'#00ff41',borderHover:'#00ff41',
    danger:'#ff3333',success:'#00ff41',warn:'#ffff00',info:'#00bfff',
    bannerStart:'#002200',bannerMid:'#004400',bannerEnd:'#002200',
    heroText:'#00ff41',heroGlow:'#00ff41',
    statAttackBg:'#1a0000',statAttackEnd:'#2d0000',
    badgeBg:'#003300',badgeText:'#00ff41',badgeBorder:'#00ff41',
    badgeHighBg:'#006600',badgeHighEnd:'#00ff41',badgeHighBorder:'#00ff41',
    bgHover:'rgba(0,255,65,0.08)',
    hero:'💀 DEFENDER TERMINAL',subtitle:'系统底层安全防护终端',footer:'💀 终端监控已接入'
  },
  dark: {
    label:'🌙 暗夜战报',
    bg:'#0d1117',bg2:'#161b22',bgCard:'#0d1117',bgCardEnd:'#161b22',
    text:'#c9d1d9',text2:'#8b949e',text3:'#58a6ff',
    accent:'#58a6ff',accent2:'#1f6feb',accentGlow:'rgba(88,166,255,0.2)',
    border:'#30363d',borderHover:'#58a6ff',
    danger:'#f85149',success:'#3fb950',warn:'#d29922',info:'#58a6ff',
    bannerStart:'#161b22',bannerMid:'#21262d',bannerEnd:'#161b22',
    heroText:'#58a6ff',heroGlow:'#58a6ff',
    statAttackBg:'#21262d',statAttackEnd:'#30363d',
    badgeBg:'#21262d',badgeText:'#58a6ff',badgeBorder:'#30363d',
    badgeHighBg:'#1f6feb',badgeHighEnd:'#58a6ff',badgeHighBorder:'#58a6ff',
    bgHover:'rgba(88,166,255,0.08)',
    hero:'🌙 SERVER WATCHDOG',subtitle:'主机安全战报中心',footer:'🌙 暗夜守护运行中'
  },
  warn: {
    label:'🚨 警示警戒',
    bg:'#1a1a00',bg2:'#2d2d00',bgCard:'#1a1a00',bgCardEnd:'#2d2d00',
    text:'#ffeb3b',text2:'#fff59d',text3:'#fbc02d',
    accent:'#ff4444',accent2:'#cc0000',accentGlow:'rgba(255,68,68,0.2)',
    border:'#ff4444',borderHover:'#ffeb3b',
    danger:'#ff4444',success:'#00e676',warn:'#ff9100',info:'#40c4ff',
    bannerStart:'#1a1a00',bannerMid:'#ff4444',bannerEnd:'#1a1a00',
    heroText:'#ffd700',heroGlow:'#ff4444',
    statAttackBg:'#4a1a00',statAttackEnd:'#6b2a00',
    badgeBg:'#8b0000',badgeText:'#ffd700',badgeBorder:'#ff4444',
    badgeHighBg:'#cc0000',badgeHighEnd:'#ff4444',badgeHighBorder:'#ffd700',
    bgHover:'rgba(255,68,68,0.08)',
    hero:'🚨 ALERT DEFENDER',subtitle:'⚠️ 入侵与资源警戒系统',footer:'🚨 紧急通报中'
  },
  cyber: {
    label:'🔵 蓝焰科技',
    bg:'#000a1a',bg2:'#001a3d',bgCard:'#000a1a',bgCardEnd:'#001a3d',
    text:'#00bfff',text2:'#87ceeb',text3:'#4682b4',
    accent:'#00bfff',accent2:'#1e90ff',accentGlow:'rgba(0,191,255,0.2)',
    border:'#1e90ff',borderHover:'#00bfff',
    danger:'#ff4444',success:'#00ff88',warn:'#ffaa00',info:'#00bfff',
    bannerStart:'#001a3d',bannerMid:'#003366',bannerEnd:'#001a3d',
    heroText:'#00bfff',heroGlow:'#00bfff',
    statAttackBg:'#001a3d',statAttackEnd:'#002244',
    badgeBg:'#1e90ff',badgeText:'#fff',badgeBorder:'#00bfff',
    badgeHighBg:'#0066cc',badgeHighEnd:'#00bfff',badgeHighBorder:'#00bfff',
    bgHover:'rgba(0,191,255,0.08)',
    hero:'🔵 CYBER DEFENDER',subtitle:'网络与主机健康防御体系',footer:'🔵 实时态势感知'
  }
};

function applyTheme(name) {
  const t = THEMES[name];
  if (!t) return;
  const r = document.documentElement.style;
  r.setProperty('--bg', t.bg); r.setProperty('--bg2', t.bg2);
  r.setProperty('--bg-card', t.bgCard); r.setProperty('--bg-card-end', t.bgCardEnd);
  r.setProperty('--text', t.text); r.setProperty('--text2', t.text2); r.setProperty('--text3', t.text3);
  r.setProperty('--accent', t.accent); r.setProperty('--accent2', t.accent2); r.setProperty('--accent-glow', t.accentGlow);
  r.setProperty('--border', t.border); r.setProperty('--border-hover', t.borderHover);
  r.setProperty('--danger', t.danger); r.setProperty('--success', t.success); r.setProperty('--warn', t.warn); r.setProperty('--info', t.info);
  r.setProperty('--banner-start', t.bannerStart); r.setProperty('--banner-mid', t.bannerMid); r.setProperty('--banner-end', t.bannerEnd);
  r.setProperty('--hero-text', t.heroText); r.setProperty('--hero-glow', t.heroGlow);
  r.setProperty('--stat-attack-bg', t.statAttackBg); r.setProperty('--stat-attack-end', t.statAttackEnd);
  r.setProperty('--badge-bg', t.badgeBg); r.setProperty('--badge-text', t.badgeText); r.setProperty('--badge-border', t.badgeBorder);
  r.setProperty('--badge-high-bg', t.badgeHighBg); r.setProperty('--badge-high-end', t.badgeHighEnd); r.setProperty('--badge-high-border', t.badgeHighBorder);
  r.setProperty('--bg-hover', t.bgHover);
  document.querySelector('.hero-banner h1').textContent = t.hero;
  document.querySelector('.hero-banner .subtitle').innerHTML = t.subtitle + ' &nbsp;|&nbsp; <span id="update-info">加载中...</span>';
  document.querySelector('.footer span').textContent = t.footer;
  document.querySelectorAll('.theme-dot').forEach(d=>d.classList.remove('active'));
  const activeDot = document.querySelector('.theme-dot[data-theme="'+name+'"]');
  if(activeDot) activeDot.classList.add('active');
  localStorage.setItem('attack-monitor-theme', name);
}

function setTheme(name) { applyTheme(name); }

(function(){
  const saved = localStorage.getItem('attack-monitor-theme') || 'red';
  applyTheme(saved);
})();

// === Data refresh ===
let autoTimer = null;
async function refresh(){
  try{
    const r=await fetch('/api/data');
    const d=await r.json();
    document.getElementById('stat-attack').textContent=d.total_attacks;
    document.getElementById('stat-banned').textContent=d.f2b_banned_count;
    document.getElementById('stat-total-banned').textContent=d.f2b_total_banned;
    document.getElementById('stat-iptables').textContent=d.iptables_blocked;
    document.getElementById('stat-frps-banned').textContent=d.frps_f2b_banned_count;
    document.getElementById('stat-frps-total').textContent=d.frps_f2b_total_banned;
    document.getElementById('stat-syn').textContent=d.syn_count;
    document.getElementById('stat-unames').textContent=d.unames_count;
    document.getElementById('stat-reaper').textContent=d.reaper_count;
    
    document.getElementById('f2b-list').innerHTML=d.f2b_html;
    document.getElementById('f2b-badge').textContent=d.f2b_banned_count;
    document.getElementById('frps-f2b-list').innerHTML=d.frps_f2b_html;
    document.getElementById('frps-f2b-badge').textContent=d.frps_f2b_banned_count;
    document.getElementById('iptables-list').innerHTML=d.iptables_html;
    document.getElementById('top-ips').innerHTML=d.top_ips_html;
    document.getElementById('top-users').innerHTML=d.top_users_html;
    document.getElementById('top-procs').innerHTML=d.top_procs_html;
    document.getElementById('reaper-events').innerHTML=d.reaper_events_html;
    document.getElementById('reaper-badge').textContent=d.reaper_count;
    document.getElementById('unames-badge').textContent=d.unames_count;
    document.getElementById('unames-list').innerHTML=d.unames_html;
    document.getElementById('recent-attacks').innerHTML=d.recent_html;
    document.getElementById('syn-history').innerHTML=d.syn_html;
    document.getElementById('frps-scan').innerHTML=d.frps_scan_html;
    document.getElementById('update-info').textContent='最后更新: '+d.time;
  }catch(e){console.error(e)}
}

async function doKillProcess(pid, comm){
  if(!confirm(`⚠️ 确认强制终止异常进程 PID ${pid} (${comm}) 吗？`)) return;
  try{
    const r=await fetch('/api/reaper/kill',{
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({pid:pid})
    });
    const res=await r.json();
    alert(res.msg);
    refresh();
  }catch(e){alert('操作失败: '+e)}
}

function showBlockIP(){document.getElementById('block-modal').classList.add('show');document.getElementById('block-ip-input').focus()}
function hideBlockIP(){document.getElementById('block-modal').classList.remove('show')}
async function doBlockIP(){const ip=document.getElementById('block-ip-input').value.trim();if(!ip)return;try{await fetch('/api/block_ip',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({ip:ip})});document.getElementById('block-ip-input').value='';hideBlockIP();refresh()}catch(e){console.error(e)}}
document.getElementById('block-ip-input').addEventListener('keydown',function(e){if(e.key==='Enter')doBlockIP()});
refresh();autoTimer=setInterval(refresh,5000);
</script>
</body>
</html>
"""

def run(cmd, timeout=5):
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.STDOUT, timeout=timeout).decode("utf-8", errors="replace")
        return out
    except: return ""

def get_fail2ban_status():
    banned_list = []; total_failed = 0; banned_count = 0; total_banned = 0
    frps_banned_list = []; frps_banned_count = 0; frps_total_banned = 0; frps_total_failed = 0
    try:
        out = run(["fail2ban-client", "status", "sshd"])
        for line in out.split("\n"):
            line = line.strip()
            if "Total failed" in line: total_failed = int(line.split(":")[-1].strip())
            if "Total banned" in line: total_banned = int(line.split(":")[-1].strip())
            if "Currently banned" in line: banned_count = int(line.split(":")[-1].strip())
            if "Banned IP list" in line:
                ips = line.split(":")[-1].strip()
                if ips: banned_list = [ip.strip() for ip in ips.split() if ip.strip()]
    except: pass
    try:
        out2 = run(["fail2ban-client", "status", "frps-ssh"])
        for line in out2.split("\n"):
            line = line.strip()
            if "Total failed" in line: frps_total_failed = int(line.split(":")[-1].strip())
            if "Total banned" in line: frps_total_banned = int(line.split(":")[-1].strip())
            if "Currently banned" in line: frps_banned_count = int(line.split(":")[-1].strip())
            if "Banned IP list" in line:
                ips = line.split(":")[-1].strip()
                if ips: frps_banned_list = [ip.strip() for ip in ips.split() if ip.strip()]
    except: pass
    return {
        "banned_count": banned_count,
        "total_banned": total_banned,
        "total_failed": total_failed,
        "banned_list": banned_list,
        "frps_banned_count": frps_banned_count,
        "frps_total_banned": frps_total_banned,
        "frps_total_failed": frps_total_failed,
        "frps_banned_list": frps_banned_list
    }

def get_iptables_blocked():
    blocked = []
    try:
        out = run(["iptables", "-L", "INPUT", "-v", "-n", "--line-numbers"])
        for line in out.split("\n"):
            if "DROP" in line:
                parts = line.split()
                if len(parts) >= 9:
                    num = parts[0]
                    pkts = parts[1]
                    bytes_ = parts[2]
                    src = parts[8]
                    if src != "0.0.0.0/0":
                        blocked.append({"num": num, "pkts": pkts, "bytes": bytes_, "src": src})
    except: pass
    return blocked

def get_syn_flood():
    entries = []
    try:
        out = run(["dmesg", "-T"])
        for line in out.split("\n"):
            if "possible SYN flooding" in line:
                m = re.search(r"\[(.*?)\]", line)
                time_str = m.group(1) if m else "Unknown"
                m2 = re.search(r"Sending cookies to ([\d\.:a-fA-F]+)", line)
                ip = m2.group(1) if m2 else "Unknown"
                m3 = re.search(r"port (\d+)", line)
                port = m3.group(1) if m3 else "Unknown"
                entries.append({"time": time_str, "ip": ip, "port": port})
    except: pass
    return entries

def get_frps_scan_stats():
    stats = []
    try:
        out = run(["journalctl", "-u", "frps", "--since", "24 hours ago", "--no-pager"])
        if not out:
            out = run(["tail", "-n", "5000", "/main/app/log/frps.log"])
        ip_counts = {}
        for line in out.split("\n"):
            if "[ssh" in line and "get a user connection" in line:
                m = re.search(r"\[([\d\.:a-fA-F]+):\d+\]", line)
                if m:
                    ip = m.group(1)
                    if ip not in ["127.0.0.1", "::1"]:
                        ip_counts[ip] = ip_counts.get(ip, 0) + 1
        sorted_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        stats = [{"ip": ip, "count": count} for ip, count in sorted_ips]
    except: pass
    return stats

def get_lastb_stats():
    total = 0; ip_counts = {}; user_counts = {}; recent = []
    try:
        out = run(["lastb", "-n", "1000", "-F", "-w"])
        for line in out.split("\n"):
            line = line.strip()
            if not line or line.startswith("btmp begins"): continue
            total += 1
            parts = line.split()
            if len(parts) >= 3:
                user = parts[0]
                ip = parts[2]
                user_counts[user] = user_counts.get(user, 0) + 1
                if ip not in ["127.0.0.1", "::1", "0.0.0.0", "localhost"]:
                    ip_counts[ip] = ip_counts.get(ip, 0) + 1
                if len(recent) < 15:
                    recent.append({"user": user, "ip": ip})
        top_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        top_users = sorted(user_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        return {
            "total": total,
            "top_ips": [{"ip": ip, "count": count} for ip, count in top_ips],
            "top_users": [{"user": user, "count": count} for user, count in top_users],
            "recent": recent
        }
    except:
        return {"total": 0, "top_ips": [], "top_users": [], "recent": []}

def render_f2b_html(f2b):
    if not f2b["banned_list"]: return "<div class=\"empty\">✅ 暂无封禁 IP</div>"
    html = "<table><tr><th>#</th><th>IP 地址</th><th>状态</th></tr>"
    for i, ip in enumerate(f2b["banned_list"], 1):
        html += f"<tr><td>{i}</td><td class=\"ip\">{ip}</td><td><span class=\"badge-cnt badge-high\">封禁中</span></td></tr>"
    return html + "</table>"

def render_frps_f2b_html(f2b):
    if not f2b["frps_banned_list"]: return "<div class=\"empty\">✅ 暂无 frps 封禁 IP</div>"
    html = "<table><tr><th>#</th><th>IP 地址</th><th>状态</th></tr>"
    for i, ip in enumerate(f2b["frps_banned_list"], 1):
        html += f"<tr><td>{i}</td><td class=\"ip\">{ip}</td><td><span class=\"badge-cnt badge-high\">封禁中</span></td></tr>"
    return html + "</table>"

def render_iptables_html(blocked):
    if not blocked: return "<div class=\"empty\">✅ 暂无 iptables 规则</div>"
    html = "<table><tr><th>#</th><th>来源 IP</th><th>拦截包数</th></tr>"
    for b in blocked:
        html += f"<tr><td>{b['num']}</td><td class=\"ip\">{b['src']}</td><td><span class=\"badge-cnt badge-mid\">{b['pkts']}</span></td></tr>"
    return html + "</table>"

def render_top_ips_html(top_ips):
    if not top_ips: return "<div class=\"empty\">暂无数据</div>"
    html = "<table><tr><th>#</th><th>IP</th><th>次数</th></tr>"
    for i, item in enumerate(top_ips, 1):
        badge = "badge-high" if item['count'] >= 50 else ("badge-mid" if item['count'] >= 10 else "badge-low")
        html += f"<tr><td>{i}</td><td class=\"ip\">{item['ip']}</td><td><span class=\"badge-cnt {badge}\">{item['count']}</span></td></tr>"
    return html + "</table>"

def render_top_users_html(top_users):
    if not top_users: return "<div class=\"empty\">暂无数据</div>"
    html = "<table><tr><th>#</th><th>用户名</th><th>次数</th></tr>"
    for i, item in enumerate(top_users, 1):
        badge = "badge-high" if item['count'] >= 50 else ("badge-mid" if item['count'] >= 10 else "badge-low")
        html += f"<tr><td>{i}</td><td class=\"user\">{item['user']}</td><td><span class=\"badge-cnt {badge}\">{item['count']}</span></td></tr>"
    return html + "</table>"

def render_frps_scan_html(frps_scan):
    if not frps_scan: return "<div class=\"empty\">✅ 暂无扫描记录</div>"
    html = "<table><tr><th>#</th><th>IP</th><th>扫描连接数</th></tr>"
    for i, item in enumerate(frps_scan, 1):
        badge = "badge-high" if item['count'] >= 50 else ("badge-mid" if item['count'] >= 10 else "badge-low")
        html += f"<tr><td>{i}</td><td class=\"ip\">{item['ip']}</td><td><span class=\"badge-cnt {badge}\">{item['count']}</span></td></tr>"
    return html + "</table>"

def render_recent_html(recent):
    if not recent: return "<div class=\"empty\">暂无记录</div>"
    html = "<table><tr><th>#</th><th>账号</th><th>来源 IP</th></tr>"
    for i, item in enumerate(recent, 1):
        html += f"<tr class=\"attack-row\"><td>{i}</td><td class=\"user\">{item['user']}</td><td class=\"ip\">{item['ip']}</td></tr>"
    return html + "</table>"

def render_syn_html(entries):
    if not entries: return "<div class=\"empty\">✅ 未检测到 SYN Flood</div>"
    html = "<table><tr><th>时间</th><th>Port</th></tr>"
    for e in reversed(entries[-15:]):
        html += f"<tr><td class=\"time\">{e['time']}</td><td class=\"ip attack-row\">{e['port']}</td></tr>"
    return html + "</table>"

# ===== 用户名风暴永久封禁 =====
UNAMES_BAN_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "perm_ban.txt")

def get_usernames_bans():
    bans = []
    try:
        with open(UNAMES_BAN_FILE) as f:
            for line in f:
                line = line.strip()
                if not line: continue
                parts = line.split("\t")
                bans.append({"ip": parts[0], "users": parts[1] if len(parts) > 1 else "-",
                             "time": parts[2] if len(parts) > 2 else "-"})
    except Exception:
        pass
    return bans

def render_usernames_html(bans):
    if not bans: return "<div class=\"empty\">✅ 暂无用户名风暴封禁</div>"
    html = "<table><tr><th>#</th><th>IP</th><th>不同用户名</th><th>封禁时间</th></tr>"
    for i, b in enumerate(bans, 1):
        html += f"<tr><td>{i}</td><td class=\"ip attack-row\">{b['ip']}</td><td><span class=\"badge-cnt badge-high\">{b['users']}</span></td><td class=\"time\">{b['time']}</td></tr>"
    return html + "</table>"

# ===== 异常进程收割与实时高 CPU 监控 (Reaper 模块) =====
def render_top_procs_html(procs):
    if not procs: return "<div class=\"empty\">✅ 暂无高负载进程</div>"
    html = "<table><tr><th>PID</th><th>用户</th><th>%CPU</th><th>运行时长</th><th>命令</th><th>操作</th></tr>"
    for p in procs[:6]:
        cpu_badge = "badge-high" if p['cpu'] >= 50.0 else ("badge-mid" if p['cpu'] >= 20.0 else "badge-low")
        cmd_short = p['comm']
        html += f"<tr><td><b>{p['pid']}</b></td><td>{p['user']}</td><td><span class=\"badge-cnt {cpu_badge}\">{p['cpu']}%</span></td><td class=\"time\">{p['etime']}</td><td title=\"{p['args']}\">{cmd_short}</td><td><button class=\"btn-kill\" onclick=\"doKillProcess({p['pid']}, '{p['comm']}')\">终止</button></td></tr>"
    return html + "</table>"

def render_reaper_events_html(events):
    if not events: return "<div class=\"empty\">✅ 系统平稳，暂无失控异常进程</div>"
    html = "<table><tr><th>时间</th><th>PID</th><th>命令</th><th>收割原因</th></tr>"
    for ev in events[:10]:
        html += f"<tr><td class=\"time\">{ev['time']}</td><td class=\"ip\">{ev['pid']}</td><td><b>{ev['comm']}</b></td><td style=\"color:var(--danger)\">{ev['reason']}</td></tr>"
    return html + "</table>"

@app.route("/")
def index():
    return render_template_string(HTML)

@app.route("/api/data")
def api_data():
    f2b = get_fail2ban_status()
    iptables_blocked = get_iptables_blocked()
    syn_entries = get_syn_flood()
    lastb = get_lastb_stats()
    frps_scan = get_frps_scan_stats()
    unames_bans = get_usernames_bans()
    top_procs = get_high_cpu_processes(limit=6)
    reaper_events = load_events()
    return jsonify({
        "total_attacks": lastb["total"],
        "f2b_banned_count": f2b["banned_count"],
        "f2b_total_banned": f2b["total_banned"],
        "f2b_failed": f2b["total_failed"],
        "f2b_html": render_f2b_html(f2b),
        "frps_f2b_banned_count": f2b["frps_banned_count"],
        "frps_f2b_total_banned": f2b["frps_total_banned"],
        "frps_f2b_failed": f2b["frps_total_failed"],
        "frps_f2b_html": render_frps_f2b_html(f2b),
        "iptables_blocked": len(iptables_blocked),
        "iptables_html": render_iptables_html(iptables_blocked),
        "top_ips_html": render_top_ips_html(lastb["top_ips"]),
        "top_users_html": render_top_users_html(lastb["top_users"]),
        "recent_html": render_recent_html(lastb["recent"]),
        "syn_count": len(syn_entries),
        "syn_html": render_syn_html(syn_entries),
        "frps_scan_html": render_frps_scan_html(frps_scan),
        "unames_count": len(unames_bans),
        "unames_html": render_usernames_html(unames_bans),
        "reaper_count": len(reaper_events),
        "reaper_events_html": render_reaper_events_html(reaper_events),
        "top_procs_html": render_top_procs_html(top_procs),
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    })

@app.route("/api/block_ip", methods=["POST"])
def block_ip():
    data = request.get_json()
    ip = data.get("ip", "").strip()
    if not ip or not re.match(r"^\d+\.\d+\.\d+\.\d+$", ip):
        return jsonify({"status": "error", "msg": "无效 IP"})
    try:
        run(["iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"])
        return jsonify({"status": "ok", "msg": "该 IP 已在封禁列表中"})
    except: pass
    try:
        run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], timeout=3)
        run(["iptables-save"], timeout=3)
        return jsonify({"status": "ok", "msg": "封禁成功"})
    except Exception as e:
        return jsonify({"status": "error", "msg": str(e)})

@app.route("/api/reaper/kill", methods=["POST"])
def api_kill_process():
    data = request.get_json() or {}
    pid = data.get("pid")
    try:
        pid = int(pid)
    except (TypeError, ValueError):
        return jsonify({"status": "error", "msg": "无效 PID"})
    ok, msg = kill_by_pid(pid)
    return jsonify({"status": "ok" if ok else "error", "msg": msg})

if __name__ == "__main__":
    # 启动后台收割巡检线程
    t = threading.Thread(target=reaper_background_worker, daemon=True)
    t.start()
    app.run(host="0.0.0.0", port=8899, debug=False)
