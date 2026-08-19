#!/usr/bin/env python3
"""
geo.py — IP 归属地解析与境内外判定工具模块
优先使用本地缓存与多源高可用国内接口，零外部三方重依赖。
"""
import urllib.request
import json
import os
import ipaddress

CACHE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "geo_cache.json")
_cache = None

def _load_cache():
    global _cache
    if _cache is None:
        if os.path.exists(CACHE_FILE):
            try:
                with open(CACHE_FILE, "r", encoding="utf-8") as f:
                    _cache = json.load(f)
            except Exception:
                _cache = {}
        else:
            _cache = {}
    return _cache

def _save_cache():
    global _cache
    if _cache is not None:
        try:
            os.makedirs(os.path.dirname(CACHE_FILE), exist_ok=True)
            tmp = CACHE_FILE + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(_cache, f, ensure_ascii=False, indent=2)
            os.replace(tmp, CACHE_FILE)
        except Exception:
            pass

def is_private_or_loopback(ip_str: str) -> bool:
    """检查是否为回环或私网保留地址"""
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_unspecified
    except ValueError:
        return False

def get_ip_geo(ip: str) -> dict:
    """
    解析 IP 归属地，返回结构：
    {
        "ip": ip,
        "is_cn": bool,          # True: 中国境内 (含特区/台湾), False: 境外
        "country": "中国" / "国外",
        "location": "四川省 内江市" / "德国",
        "isp": "联通"
    }
    """
    if is_private_or_loopback(ip):
        return {
            "ip": ip,
            "is_cn": True,
            "country": "局域网/回环",
            "location": "本地",
            "isp": "Local"
        }

    cache = _load_cache()
    if ip in cache:
        return cache[ip]

    res_data = None

    # 1. 尝试太平洋电脑网 whois 接口 (国内高速、稳定、编码 GBK)
    try:
        url = f"https://whois.pconline.com.cn/ipJson.jsp?ip={ip}&json=true"
        req = urllib.request.Request(url, headers={"User-Agent": "curl/7.68.0"})
        with urllib.request.urlopen(req, timeout=2.5) as res:
            raw = res.read().decode("gbk", errors="ignore")
            d = json.loads(raw)
            pro_code = d.get("proCode", "")
            pro = d.get("pro", "").strip()
            city = d.get("city", "").strip()
            addr = d.get("addr", "").strip()

            # proCode 为 999999 代表境外/未识别省份
            if pro_code and pro_code != "999999":
                res_data = {
                    "ip": ip,
                    "is_cn": True,
                    "country": "中国",
                    "location": f"{pro} {city}".strip() or "中国",
                    "isp": addr
                }
            else:
                res_data = {
                    "ip": ip,
                    "is_cn": False,
                    "country": "境外",
                    "location": addr or "境外",
                    "isp": ""
                }
    except Exception:
        pass

    # 2. 备用接口：ip-api.com (带中文字段)
    if not res_data:
        try:
            url = f"http://ip-api.com/json/{ip}?lang=zh-CN"
            req = urllib.request.Request(url, headers={"User-Agent": "curl/7.68.0"})
            with urllib.request.urlopen(req, timeout=2.5) as res:
                d = json.loads(res.read().decode("utf-8"))
                if d.get("status") == "success":
                    cc = d.get("countryCode", "")
                    country = d.get("country", "")
                    reg = d.get("regionName", "")
                    city = d.get("city", "")
                    is_cn = (cc == "CN" or cc == "HK" or cc == "MO" or cc == "TW")
                    res_data = {
                        "ip": ip,
                        "is_cn": is_cn,
                        "country": country,
                        "location": f"{country} {reg} {city}".strip(),
                        "isp": d.get("isp", "")
                    }
        except Exception:
            pass

    # 3. 兜底策略：如果全部接口超时且无法判定，默认为保守不误伤 (is_cn=True)，避免网络抖动封锁正常 IP
    if not res_data:
        res_data = {
            "ip": ip,
            "is_cn": True,
            "country": "未知",
            "location": "未识别",
            "isp": ""
        }

    # 写入缓存
    cache[ip] = res_data
    _save_cache()
    return res_data
