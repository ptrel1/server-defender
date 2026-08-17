#!/usr/bin/env python3
"""SSH attack monitor dashboard"""
import subprocess, re, json, os
from datetime import datetime
from flask import Flask, jsonify, render_template_string, request

app = Flask(__name__)

HTML = r"""<!DOCTYPE html>
<html lang="zh">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>🛡 SSH 攻击监控面板</title>
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
  <h1>🛡️ SSH 攻击监控</h1>
  <div class="subtitle">SSH 攻击监控面板 &nbsp;|&nbsp; <span id="update-info">加载中...</span></div>
</div>

<div class="top-stats">
  <div class="stat-card attack"><div class="num" id="stat-attack">-</div><div class="label">🗡️ 暴力破解次数</div></div>
  <div class="stat-card banned"><div class="num" id="stat-banned">-</div><div class="label">🔒 fail2ban 封禁中</div><div class="badge-wrapper">!</div></div>
  <div class="stat-card banned"><div class="num" id="stat-total-banned">-</div><div class="label">🏆 SSH 累计封禁</div></div>
  <div class="stat-card blocked"><div class="num" id="stat-frps-banned">-</div><div class="label">🛡️ frps 封禁中</div></div>
  <div class="stat-card blocked"><div class="num" id="stat-frps-total">-</div><div class="label">🏆 frps 累计封禁</div></div>
  <div class="stat-card blocked"><div class="num" id="stat-iptables">-</div><div class="label">🛡️ iptables 屏蔽</div></div>
  <div class="stat-card syn"><div class="num" id="stat-syn">-</div><div class="label">💣 SYN Flood 告警</div></div>
  <div class="stat-card banned"><div class="num" id="stat-unames">-</div><div class="label">🔐 用户名风暴永久封禁</div><div class="badge-wrapper">!</div></div>
</div>

<div class="grid">
  <div class="card"><h2>📋 fail2ban SSH 封禁 <span class="badge" id="f2b-badge">0</span></h2><div id="f2b-list"><div class="empty">✅ 暂无封禁</div></div></div>
  <div class="card"><h2>🛡️ fail2ban frps 自动封禁 <span class="badge" id="frps-f2b-badge">0</span></h2><div id="frps-f2b-list"><div class="empty">⏳ 监控中...</div></div></div>
  <div class="card"><h2>🚧 iptables 手动屏蔽</h2><div id="iptables-list"><div class="empty">加载中...</div></div></div>
  <div class="card"><h2>🏅 攻击 IP 排行</h2><div id="top-ips"><div class="empty">加载中...</div></div></div>
  <div class="card"><h2>🎯 被尝试账号排行</h2><div id="top-users"><div class="empty">加载中...</div></div></div>
  <div class="card"><h2>📜 最近攻击记录</h2><div id="recent-attacks"><div class="empty">加载中...</div></div></div>
  <div class="card"><h2>🔍 frps 端口扫描 TOP IP</h2><div id="frps-scan"><div class="empty">加载中...</div></div></div>
  <div class="card"><h2>💣 SYN Flood 历史</h2><div id="syn-history"><div class="empty">加载中...</div></div></div>
  <div class="card"><h2>🔐 用户名风暴永久封禁 <span class="badge" id="unames-badge">0</span></h2><div id="unames-list"><div class="empty">✅ 暂无</div></div></div>
</div>

<div class="footer">
  <span id="footer-msg">⏱ 每 5 秒自动刷新</span>
  <div>
    <button onclick="showBlockIP()">⚔️ 封禁 IP</button>
    <button onclick="refresh()">🔄 刷新</button>
  </div>
</div>

<div class="modal" id="block-modal">
  <div class="modal-box">
    <h3>⚔️ 封禁 IP</h3>
    <input type="text" id="block-ip-input" placeholder="输入 IP，如 1.2.3.4">
    <div class="btn-group">
      <button class="btn-cancel" onclick="hideBlockIP()">取消</button>
      <button class="btn-primary" onclick="doBlockIP()">确认封禁</button>
    </div>
  </div>
</div>

<script>
// === 主题系统 ===
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
    hero:'🛡️ SSH 攻击监控',subtitle:'SSH 攻击监控面板',footer:'⏱ 每 5 秒自动刷新'
  },
  hacker: {
    label:'💀 黑客终端',
    bg:'#000000',bg2:'#0a0a0a',bgCard:'#0d0d0d',bgCardEnd:'#0a0a0a',
    text:'#00ff41',text2:'#00cc33',text3:'#009922',
    accent:'#00ff41',accent2:'#003300',accentGlow:'rgba(0,255,65,0.2)',
    border:'#003300',borderHover:'#00ff41',
    danger:'#ff0040',success:'#00ff41',warn:'#ffcc00',info:'#00ccff',
    bannerStart:'#001a00',bannerMid:'#003300',bannerEnd:'#001a00',
    heroText:'#00ff41',heroGlow:'#00ff41',
    statAttackBg:'#002200',statAttackEnd:'#004400',
    badgeBg:'#003300',badgeText:'#00ff41',badgeBorder:'#00ff41',
    badgeHighBg:'#00cc00',badgeHighEnd:'#00ff41',badgeHighBorder:'#00ff41',
    bgHover:'rgba(0,255,65,0.08)',
    hero:'💀 TERMINAL',subtitle:'SSH INTRUSION DETECTION SYSTEM',footer:'⏱ AUTO-REFRESH 5s'
  },
  dark: {
    label:'🌙 暗夜战报',
    bg:'#0d1117',bg2:'#161b22',bgCard:'#161b22',bgCardEnd:'#161b22',
    text:'#c9d1d9',text2:'#8b949e',text3:'#484f58',
    accent:'#58a6ff',accent2:'#1f6feb',accentGlow:'rgba(88,166,255,0.1)',
    border:'#30363d',borderHover:'#58a6ff',
    danger:'#f85149',success:'#3fb950',warn:'#d2991d',info:'#58a6ff',
    bannerStart:'#161b22',bannerMid:'#1c2128',bannerEnd:'#161b22',
    heroText:'#58a6ff',heroGlow:'#58a6ff',
    statAttackBg:'#161b22',statAttackEnd:'#1c2128',
    badgeBg:'#21262d',badgeText:'#c9d1d9',badgeBorder:'#30363d',
    badgeHighBg:'#d73a49',badgeHighEnd:'#d73a49',badgeHighBorder:'#f85149',
    bgHover:'rgba(88,166,255,0.06)',
    hero:'🛡️ 战报',subtitle:'SSH 攻击监控面板',footer:'⏱ 每 5 秒自动刷新'
  },
  warn: {
    label:'🚨 警示警戒',
    bg:'#1a1a00',bg2:'#2d2d00',bgCard:'#1a1a00',bgCardEnd:'#2d2d00',
    text:'#ffd700',text2:'#ffeb00',text3:'#ccaa00',
    accent:'#ff4444',accent2:'#cc0000',accentGlow:'rgba(255,68,68,0.2)',
    border:'#ff4444',borderHover:'#ffd700',
    danger:'#ff0000',success:'#00ff00',warn:'#ffff00',info:'#ff8800',
    bannerStart:'#1a1a00',bannerMid:'#ff4444',bannerEnd:'#1a1a00',
    heroText:'#ffd700',heroGlow:'#ff4444',
    statAttackBg:'#4a1a00',statAttackEnd:'#6b2a00',
    badgeBg:'#8b0000',badgeText:'#ffd700',badgeBorder:'#ff4444',
    badgeHighBg:'#cc0000',badgeHighEnd:'#ff4444',badgeHighBorder:'#ffd700',
    bgHover:'rgba(255,68,68,0.08)',
    hero:'🚨 ALERT',subtitle:'⚠️ 入侵警报系统',footer:'🚨 紧急通报中'
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
    hero:'🔵 CYBER COMMAND',subtitle:'网络安全态势感知系统',footer:'🔵 实时态势感知'
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

// Init theme from localStorage
(function(){
  const saved = localStorage.getItem('attack-monitor-theme') || 'red';
  applyTheme(saved);
})();

// === Data refresh ===
let autoTimer = null;
async function refresh(){try{const r=await fetch('/api/data');const d=await r.json();document.getElementById('stat-attack').textContent=d.total_attacks;document.getElementById('stat-banned').textContent=d.f2b_banned_count;document.getElementById('stat-total-banned').textContent=d.f2b_total_banned;document.getElementById('stat-iptables').textContent=d.iptables_blocked;document.getElementById('stat-frps-banned').textContent=d.frps_f2b_banned_count;document.getElementById('stat-frps-total').textContent=d.frps_f2b_total_banned;document.getElementById('stat-syn').textContent=d.syn_count;document.getElementById('f2b-list').innerHTML=d.f2b_html;document.getElementById('f2b-badge').textContent=d.f2b_banned_count;document.getElementById('frps-f2b-list').innerHTML=d.frps_f2b_html;document.getElementById('frps-f2b-badge').textContent=d.frps_f2b_banned_count;document.getElementById('iptables-list').innerHTML=d.iptables_html;document.getElementById('top-ips').innerHTML=d.top_ips_html;document.getElementById('top-users').innerHTML=d.top_users_html;document.getElementById('recent-attacks').innerHTML=d.recent_html;document.getElementById('syn-history').innerHTML=d.syn_html;document.getElementById('frps-scan').innerHTML=d.frps_scan_html;document.getElementById('stat-unames').textContent=d.unames_count;document.getElementById('unames-badge').textContent=d.unames_count;document.getElementById('unames-list').innerHTML=d.unames_html;document.getElementById('update-info').textContent='最后更新: '+d.time}catch(e){console.error(e)}}
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
        for line in out2.split(chr(10)):
            line = line.strip()
            if "Total failed" in line: frps_total_failed = int(line.split(":")[-1].strip())
            if "Total banned" in line: frps_total_banned = int(line.split(":")[-1].strip())
            if "Currently banned" in line: frps_banned_count = int(line.split(":")[-1].strip())
            if "Banned IP list" in line:
                ips = line.split(":")[-1].strip()
                if ips: frps_banned_list = [ip.strip() for ip in ips.split() if ip.strip()]
    except: pass
    return {"banned_list": banned_list, "banned_count": banned_count, "total_banned": total_banned, "total_failed": total_failed,
            "frps_banned_list": frps_banned_list, "frps_banned_count": frps_banned_count, "frps_total_banned": frps_total_banned, "frps_total_failed": frps_total_failed}

def get_iptables_blocked():
    blocked = []
    try:
        out = run(["iptables", "-L", "INPUT", "-n", "--line-numbers"])
        for line in out.split("\n"):
            parts = line.split()
            if len(parts) >= 5 and parts[0].isdigit() and parts[1] == "DROP":
                blocked.append({"num": parts[0], "ip": parts[4]})
    except: pass
    return blocked

# ===== frps 扫描分析 =====

def get_frps_scan_stats():
    try:
        out = run(["tail", "-2000", "/main/app/log/frps.log"])
        lines = out.strip().split(chr(10))
        ip_count = {}
        for line in lines:
            if "get a user connection" in line:
                m = re.search(r"\[(\d+\.\d+\.\d+\.\d+):\d+\]", line)
                if m:
                    ip = m.group(1)
                    ip_count[ip] = ip_count.get(ip, 0) + 1
        top_ips = sorted(ip_count.items(), key=lambda x: -x[1])[:15]
        return top_ips
    except: return []

def render_frps_scan_html(top_ips):
    if not top_ips: return "<div class=\"empty\">\u6682\u65e0\u6570\u636e</div>"
    total = sum(c for _, c in top_ips)
    html = "<table><tr><th>#</th><th>IP</th><th>\u8fde\u63a5\u6b21\u6570</th><th>\u5360\u6bd4</th></tr>"
    for i, (ip, cnt) in enumerate(top_ips, 1):
        pct = f"{cnt/total*100:.1f}%" if total else "0%"
        cls = "badge-high" if cnt > 50 else ("badge-mid" if cnt > 10 else "badge-low")
        html += f"<tr><td>{i}</td><td class=\"ip attack-row\">{ip}</td><td><span class=\"badge-cnt {cls}\">{cnt}</span></td><td>{pct}</td></tr>"
    return html + "</table>"

def get_syn_flood():
    entries = []
    try:
        out = run(["dmesg"], timeout=3)
        for line in out.split("\n"):
            if "SYN flooding" in line:
                m = re.search(r"\[(\d+\.\d+)\]", line)
                port_m = re.search(r"port\s+(\S+)", line)
                if m and port_m:
                    uptime_sec = float(m.group(1))
                    days = int(uptime_sec / 86400)
                    hours = int((uptime_sec % 86400) / 3600)
                    entries.append({"time": f"{days}d {hours}h ago", "port": port_m.group(1).rstrip(".")})
    except: pass
    return entries

def get_lastb_stats():
    try:
        out = run(["lastb"])
        lines = out.strip().split("\n")
        data_lines = [l for l in lines if not l.startswith("btmp") and l.strip()]
        total = len(data_lines)
        ip_count = {}; user_count = {}; recent = []
        for line in data_lines:
            parts = line.split()
            if len(parts) >= 3:
                username = parts[0]; ip = parts[2]
                if not re.match(r"^\d+\.\d+\.\d+\.\d+$", ip): continue
                ip_count[ip] = ip_count.get(ip, 0) + 1
                user_count[username] = user_count.get(username, 0) + 1
                recent.append({"user": username, "ip": ip})
        top_ips = sorted(ip_count.items(), key=lambda x: -x[1])[:15]
        top_users = sorted(user_count.items(), key=lambda x: -x[1])[:15]
        recent = recent[-20:]
        return {"total": total, "top_ips": top_ips, "top_users": top_users, "recent": recent}
    except: return {"total": 0, "top_ips": [], "top_users": [], "recent": []}

def render_f2b_html(s):
    if not s["banned_list"]: return "<div class=\"empty\">✅ 暂无封禁</div>"
    html = "<table><tr><th>#</th><th>IP</th></tr>"
    for i, ip in enumerate(s["banned_list"], 1):
        html += f"<tr><td>{i}</td><td class=\"ip attack-row\">{ip}</td></tr>"
    return html + "</table>"

def render_frps_f2b_html(s):
    if not s["frps_banned_list"]: return chr(60) + chr(100) + chr(105) + chr(118) + chr(32) + chr(99) + chr(108) + chr(97) + chr(115) + chr(115) + chr(61) + chr(34) + chr(101) + chr(109) + chr(112) + chr(116) + chr(121) + chr(34) + chr(62) + chr(9203) + chr(32) + chr(30417) + chr(25511) + chr(20013) + chr(65292) + chr(26242) + chr(23553) + chr(23553) + chr(31105) + chr(60) + chr(47) + chr(100) + chr(105) + chr(118) + chr(62)
    html = chr(60) + chr(116) + chr(97) + chr(98) + chr(108) + chr(101) + chr(62) + chr(60) + chr(116) + chr(114) + chr(62) + chr(60) + chr(116) + chr(104) + chr(62) + chr(35) + chr(60) + chr(47) + chr(116) + chr(104) + chr(62) + chr(60) + chr(116) + chr(104) + chr(62) + chr(73) + chr(80) + chr(60) + chr(47) + chr(116) + chr(104) + chr(62) + chr(60) + chr(47) + chr(116) + chr(114) + chr(62)
    for i, ip in enumerate(s["frps_banned_list"], 1):
        html += chr(60) + chr(116) + chr(114) + chr(62) + chr(60) + chr(116) + chr(100) + chr(62) + str(i) + chr(60) + chr(47) + chr(116) + chr(100) + chr(62) + chr(60) + chr(116) + chr(100) + chr(32) + chr(99) + chr(108) + chr(97) + chr(115) + chr(115) + chr(61) + chr(34) + chr(105) + chr(112) + chr(32) + chr(97) + chr(116) + chr(116) + chr(97) + chr(99) + chr(107) + chr(45) + chr(114) + chr(111) + chr(119) + chr(34) + chr(62) + ip + chr(60) + chr(47) + chr(116) + chr(100) + chr(62) + chr(60) + chr(116) + chr(100) + chr(62) + chr(102) + chr(114) + chr(112) + chr(115) + chr(45) + chr(115) + chr(115) + chr(104) + chr(60) + chr(47) + chr(116) + chr(100) + chr(62) + chr(60) + chr(47) + chr(116) + chr(114) + chr(62)
    return html + chr(60) + chr(47) + chr(116) + chr(97) + chr(98) + chr(108) + chr(101) + chr(62)

def render_iptables_html(lst):
    if not lst: return "<div class=\"empty\">✅ 暂无 ipTables 规则</div>"
    html = "<table><tr><th>#</th><th>IP</th><th>方式</th></tr>"
    for item in lst:
        html += f"<tr><td>{item['num']}</td><td class=\"ip attack-row\">{item['ip']}</td><td>已封禁</td></tr>"
    return html + "</table>"

def render_top_ips_html(top_ips):
    if not top_ips: return "<div class=\"empty\">暂无数据</div>"
    total = sum(c for _, c in top_ips)
    html = "<table><tr><th>#</th><th>IP</th><th>次数</th><th>占比</th></tr>"
    for i, (ip, cnt) in enumerate(top_ips, 1):
        pct = f"{cnt/total*100:.1f}%" if total else "0%"
        cls = "badge-high" if cnt > 50 else ("badge-mid" if cnt > 10 else "badge-low")
        html += f"<tr><td>{i}</td><td class=\"ip attack-row\">{ip}</td><td><span class=\"badge-cnt {cls}\">{cnt}</span></td><td>{pct}</td></tr>"
    return html + "</table>"

def render_top_users_html(top_users):
    if not top_users: return "<div class=\"empty\">暂无数据</div>"
    total = sum(c for _, c in top_users)
    html = "<table><tr><th>#</th><th>账号</th><th>次数</th><th>%</th></tr>"
    for i, (user, cnt) in enumerate(top_users, 1):
        pct = f"{cnt/total*100:.1f}%" if total else "0%"
        cls = "badge-high" if cnt > 50 else ("badge-mid" if cnt > 10 else "badge-low")
        html += f"<tr><td>{i}</td><td class=\"user\">{user}</td><td><span class=\"badge-cnt {cls}\">{cnt}</span></td><td>{pct}</td></tr>"
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

# ===== 用户名风暴永久封禁(usernames.py 写入) =====
UNAMES_BAN_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "perm_ban.txt")

def get_usernames_bans():
    """读 usernames.py 生成的永久封禁列表: 每行 ip\t用户名数\t时间"""
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
        return jsonify({"status": "ok", "msg": "封禁ed"})
    except Exception as e:
        return jsonify({"status": "error", "msg": str(e)})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8899, debug=False)
