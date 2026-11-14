#!/usr/bin/env python3
# 订阅镜像：用 Clash 系 UA 拉取机场配置 -> 清洗 -> 写 s.yaml
import os, sys, re, copy, ssl, urllib.request
import yaml

SUB = os.environ.get("SUB_URL", "").strip()
OUT = os.environ.get("OUT_FILE", "s.yaml")
UA = "clash.meta/v1.19.32"

if not SUB:
    print("SUB_URL missing"); sys.exit(2)

ctx = ssl.create_default_context()
req = urllib.request.Request(SUB, headers={"User-Agent": UA, "Accept": "*/*"})
try:
    raw = urllib.request.urlopen(req, timeout=60, context=ctx).read()
except Exception as e:
    print("fetch failed:", type(e).__name__, e); sys.exit(3)

try:
    src = yaml.safe_load(raw)
except Exception as e:
    print("not yaml (upstream returned non-clash content):", type(e).__name__); sys.exit(4)
if not isinstance(src, dict) or not src.get("proxies"):
    print("no proxies in payload"); sys.exit(5)

INFO_MARK = ("官网", "到期", "剩余")
def is_info(n):
    return any(m in n for m in INFO_MARK) or (len(n) > 36 and ("http" in n or ":" in n))

def clean_name(n):
    n = n.replace("|", "-").replace(";", "-").replace(":", "-")
    n = re.sub(r"https?-+", "", n)
    n = re.sub(r"-{2,}", "-", n).strip("- ")
    return n

proxies, mapping = [], {}
for p in src["proxies"]:
    if not isinstance(p, dict) or not p.get("name") or not p.get("server"):
        continue
    if is_info(p["name"]):
        continue
    q = copy.deepcopy(p)
    q["name"] = clean_name(p["name"])
    q.setdefault("udp", True)
    proxies.append(q)
    mapping[p["name"]] = q["name"]
if not proxies:
    print("all proxies filtered out, abort"); sys.exit(6)

groups = []
for g in (src.get("proxy-groups") or []):
    ng = copy.deepcopy(g)
    lst = [mapping.get(x, x) for x in (ng.get("proxies") or []) if not is_info(x)]
    ng["proxies"] = lst or ["DIRECT"]
    if ng.get("type") in ("url-test", "fallback", "load-balance"):
        ng["url"] = "https://www.gstatic.com/generate_204"
        ng["interval"] = 300
        ng["timeout"] = 5000
        if ng.get("type") == "url-test":
            ng["tolerance"] = 50
    groups.append(ng)
if not groups:
    groups = [{"name": "PROXY", "type": "select", "proxies": [p["name"] for p in proxies]}]

rules = [
    "IP-CIDR,127.0.0.0/8,DIRECT,no-resolve",
    "IP-CIDR,10.0.0.0/8,DIRECT,no-resolve",
    "IP-CIDR,172.16.0.0/12,DIRECT,no-resolve",
    "IP-CIDR,192.168.0.0/16,DIRECT,no-resolve",
] + [r for r in (src.get("rules") or []) if isinstance(r, str) and not r.startswith("PROCESS-NAME")]

PREF = ["香港", "台湾", "新加坡", "日本", "美国"]
def rank(n):
    for i, k in enumerate(PREF):
        if n.startswith(k):
            return i
    return 90 if (n in ("DIRECT", "REJECT")) else 99
proxies.sort(key=lambda p: rank(p["name"]))
for g in groups:
    g["proxies"].sort(key=rank)

cfg = {
    "allow-lan": False,
    "mode": "rule",
    "log-level": "silent",
    "ipv6": False,
    "unified-delay": True,
    "tcp-concurrent": True,
    "find-process-mode": "off",
    "geox-url": {
        "geoip": "https://gh-proxy.com/https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geoip.dat",
        "geosite": "https://gh-proxy.com/https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geosite.dat",
        "mmdb": "https://gh-proxy.com/https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/country.mmdb",
    },
    "profile": {"store-selected": True, "store-fake-ip": True},
    "sniffer": {
        "enable": True,
        "override-destination": False,
        "sniff": {"HTTP": {"ports": [80, "8080-8880"], "override-destination": True},
                  "TLS": {"ports": [443, 8443]},
                  "QUIC": {"ports": [443, 8443]}},
        "skip-domain": ["+.apple.com", "Mijia Cloud", "dlg.io.mi.com"],
    },
    "dns": {
        "enable": True, "ipv6": False, "respect-rules": False, "use-hosts": True,
        "enhanced-mode": "fake-ip", "fake-ip-range": "198.18.0.1/16",
        "fake-ip-filter-mode": "blacklist",
        "fake-ip-filter": [
            "*.lan", "*.local", "*.localdomain", "+.msftconnecttest.com", "+.msftncsi.com",
            "+.stun.*.*", "+.stun.*.*.*", "time.*.com", "ntp.*.com", "+.pool.ntp.org",
            "localhost.ptlogin2.qq.com", "+.srv.nintendo.net", "+.stun.playstation.net",
            "xbox.*.microsoft.com", "+.xboxlive.com", "*.market.xiaomi.com",
            "stun.*.*", "stun.*.*.*", "lens.l.google.com", "doh.pub", "dns.alidns.com",
        ],
        "default-nameserver": ["223.5.5.5", "119.29.29.29"],
        "nameserver": ["223.5.5.5", "119.29.29.29"],
        "proxy-server-nameserver": ["223.5.5.5", "119.29.29.29"],
    },
    "proxies": proxies,
    "proxy-groups": groups,
    "rules": rules,
}

text = yaml.safe_dump(cfg, allow_unicode=True, sort_keys=False, width=4096)
tmp = OUT + ".tmp"
open(tmp, "w", encoding="utf-8").write(text)
os.replace(tmp, OUT)
print(f"ok: {len(proxies)} nodes, {len(groups)} groups, {len(rules)} rules -> {OUT}")
