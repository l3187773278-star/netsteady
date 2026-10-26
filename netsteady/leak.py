"""真实地址暴露面检查（反指纹 / 反定位）.

回答一个和"IP 干不干净"不同的问题：
服务商有没有办法绕过代理，直接知道你在哪、你在用代理？

能测的通道：
  1. IPv6 直连 —— 只代理 v4 时，v6 会把真实公网地址原样送出去
  2. UDP / STUN —— 只代理 TCP 时，UDP 绕过代理，WebRTC 类协议直接暴露
  3. DNS 出口  —— 解析请求从哪个国家出去
  4. 系统时区 / 语言 —— 浏览器会用 Intl / Accept-Language 主动上报，和 IP 属地矛盾时是硬指纹
  5. CDN 接入点 —— 你以为在美国，流量却落在香港边缘节点

测不了的：WebRTC 的浏览器端 API、Canvas/字体指纹、账号行为回流。
"""

from __future__ import annotations

import json
import locale
import os
import socket
import struct
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Sequence, Tuple

from . import __version__
from .ipcheck import COUNTRY_ZH, collect_dns_egress, collect_egress
from .net import http_get, resolve

MAGIC_COOKIE = 0x2112A442

STUN_SERVERS = (
    ("stun.l.google.com", 19302),
    ("stun.cloudflare.com", 3478),
    ("stun.nextcloud.com", 443),
)

# 国家 -> 合理的本地 UTC 偏移区间（含夏令时余量）
COUNTRY_OFFSETS = {
    "United States": (-10.0, -4.0),
    "Canada": (-8.0, -3.0),
    "Japan": (9.0, 9.0),
    "Singapore": (8.0, 8.0),
    "Hong Kong": (8.0, 8.0),
    "Taiwan": (8.0, 8.0),
    "South Korea": (9.0, 9.0),
    "United Kingdom": (0.0, 1.0),
    "Germany": (1.0, 2.0),
    "Netherlands": (1.0, 2.0),
    "France": (1.0, 2.0),
    "Ireland": (0.0, 1.0),
    "Australia": (8.0, 11.0),
    "China": (8.0, 8.0),
}

SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3, "ok": 4}
SEVERITY_ZH = {"high": "高", "medium": "中", "low": "低", "info": "提示", "ok": "无"}
STATUS_ICON = {"leak": "✗", "suspicious": "!", "clean": "✓", "skip": "–"}


@dataclass
class LeakCheck:
    key: str
    title: str
    severity: str  # high | medium | low | info | ok
    status: str  # leak | suspicious | clean | skip
    detail: str
    advice: str = ""
    evidence: Dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "key": self.key,
            "title": self.title,
            "severity": self.severity,
            "status": self.status,
            "detail": self.detail,
            "advice": self.advice,
            "evidence": self.evidence,
        }


@dataclass
class LeakReport:
    egress_ipv4: Optional[str] = None
    egress_country: Optional[str] = None
    egress_country_zh: Optional[str] = None
    colo: Optional[str] = None
    checks: List[LeakCheck] = field(default_factory=list)
    local_offset: Optional[float] = None
    local_tzname: str = ""
    local_lang: str = ""

    def sorted_checks(self) -> List[LeakCheck]:
        return sorted(self.checks, key=lambda c: SEVERITY_ORDER.get(c.severity, 9))

    @property
    def leaks(self) -> List[LeakCheck]:
        return [c for c in self.checks if c.status in ("leak", "suspicious")]

    @property
    def risk_level(self) -> str:
        if any(c.status == "leak" and c.severity == "high" for c in self.checks):
            return "high"
        if any(c.status in ("leak", "suspicious") for c in self.checks):
            return "medium"
        return "low"

    def as_dict(self) -> Dict[str, Any]:
        return {
            "version": __version__,
            "egress_ipv4": self.egress_ipv4,
            "egress_country": self.egress_country,
            "egress_country_zh": self.egress_country_zh,
            "colo": self.colo,
            "risk_level": self.risk_level,
            "local": {
                "utc_offset": self.local_offset,
                "timezone": self.local_tzname,
                "language": self.local_lang,
            },
            "checks": [c.as_dict() for c in self.sorted_checks()],
        }


# ------------------------------------------------------------------ STUN


def stun_query(host: str, port: int, timeout: float = 3.0) -> Tuple[Optional[Tuple[str, int]], Optional[str]]:
    """发一个 STUN Binding Request，取回 NAT 映射后的公网地址."""
    transaction = os.urandom(12)
    packet = struct.pack("!HHI", 0x0001, 0x0000, MAGIC_COOKIE) + transaction
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(packet, (host, port))
        data, _ = sock.recvfrom(2048)
    except socket.timeout:
        return None, "timeout"
    except OSError as exc:
        return None, "%s: %s" % (type(exc).__name__, exc)
    finally:
        sock.close()

    if len(data) < 20:
        return None, "响应过短"
    length = struct.unpack("!H", data[2:4])[0]
    pos, end = 20, min(len(data), 20 + length)
    while pos + 4 <= end:
        attr_type, attr_len = struct.unpack("!HH", data[pos : pos + 4])
        value = data[pos + 4 : pos + 4 + attr_len]
        if attr_type in (0x0020, 0x0001) and len(value) >= 8:
            family = value[1]
            raw_port = struct.unpack("!H", value[2:4])[0]
            if attr_type == 0x0020:
                raw_port ^= MAGIC_COOKIE >> 16
            if family == 0x01:
                raw_ip = struct.unpack("!I", value[4:8])[0]
                if attr_type == 0x0020:
                    raw_ip ^= MAGIC_COOKIE
                return (socket.inet_ntoa(struct.pack("!I", raw_ip)), raw_port), None
        pos += 4 + attr_len + ((4 - attr_len % 4) % 4)
    return None, "响应里没有映射地址"


def probe_stun(timeout: float = 3.0) -> List[Dict[str, Any]]:
    results = []
    for host, port in STUN_SERVERS:
        ips, error = resolve(host, timeout=3.0)
        if not ips:
            results.append({"server": "%s:%d" % (host, port), "ip": None, "error": error or "解析失败"})
            continue
        mapped, error = stun_query(ips[0], port, timeout=timeout)
        results.append(
            {
                "server": "%s:%d" % (host, port),
                "ip": mapped[0] if mapped else None,
                "port": mapped[1] if mapped else None,
                "error": error,
            }
        )
    return results


# ------------------------------------------------------------------ 本机指纹


def local_offset_hours() -> Optional[float]:
    try:
        moment = datetime.now().astimezone()
        delta = moment.utcoffset()
        return round(delta.total_seconds() / 3600.0, 1) if delta else None
    except Exception:
        return None


def local_language() -> str:
    try:
        value = locale.getlocale()[0]
    except Exception:
        value = None
    return value or os.environ.get("LANG") or os.environ.get("LC_ALL") or ""


def geo_lookup(ip: str, timeout: float = 8.0) -> Dict[str, Any]:
    response = http_get(
        "http://ip-api.com/json/%s?fields=status,country,countryCode,isp,org,as,hosting" % ip,
        timeout=timeout,
    )
    if response.ok and response.status == 200:
        payload = response.json() or {}
        if payload.get("status") == "success":
            return payload
    return {}


def ipv6_egress(timeout: float = 6.0) -> Tuple[Optional[str], Optional[str]]:
    for url in ("https://api6.ipify.org", "https://v6.ident.me"):
        response = http_get(url, timeout=timeout)
        if response.ok and response.status == 200 and ":" in response.body:
            return response.body.strip(), None
    return None, "没有可用的 IPv6 出口"


# ------------------------------------------------------------------ 检查项


def check_ipv6(
    egress_v4: Optional[str], egress_country: Optional[str], timeout: float = 6.0
) -> LeakCheck:
    address, error = ipv6_egress(timeout=timeout)
    if address is None:
        return LeakCheck(
            "ipv6",
            "IPv6 出口",
            "ok",
            "clean",
            "没有可用的 IPv6 出口，这一条不构成泄漏。",
            evidence={"error": error},
        )

    geo = geo_lookup(address)
    country = geo.get("country")
    evidence = {"ipv6": address, "ipv4": egress_v4, "ipv6_country": country, "ipv6_org": geo.get("org")}

    if country == "China":
        return LeakCheck(
            "ipv6",
            "IPv6 出口",
            "high",
            "leak",
            "IPv6 出口是 %s，归属中国。也就是说：只走 IPv4 的访问被代理保护了，"
            "但任何支持 IPv6 的站点会直接看到你的国内地址。这是最彻底的一种暴露。" % address,
            "在代理客户端里关闭 IPv6（Clash：dns.ipv6 = false，或 TUN 里禁用 v6），"
            "或在系统网络适配器里取消 IPv6 勾选。",
            evidence=evidence,
        )
    if country and egress_country and country != egress_country:
        return LeakCheck(
            "ipv6",
            "IPv6 出口",
            "medium",
            "suspicious",
            "IPv4 出口在 %s，IPv6 出口 %s 却在 %s。双栈用户会同时暴露两个地址，"
            "而这两个地址指向不同国家，本身就是一条可疑信号。"
            % (COUNTRY_ZH.get(egress_country, egress_country), address, COUNTRY_ZH.get(country, country)),
            "让 v6 与 v4 走同一个出口，或干脆关掉 v6。",
            evidence=evidence,
        )
    if country:
        return LeakCheck(
            "ipv6",
            "IPv6 出口",
            "low",
            "clean",
            "IPv6 出口 %s 与 IPv4 同属%s（%s），是代理自己的双栈地址，没有泄露你的位置。"
            % (
                address,
                COUNTRY_ZH.get(country, country),
                geo.get("org") or geo.get("isp") or "同一运营商",
            ),
            "无需处理。要减少指纹面，仍然建议只在 v4 上暴露。",
            evidence=evidence,
        )
    return LeakCheck(
        "ipv6",
        "IPv6 出口",
        "info",
        "skip",
        "IPv6 出口是 %s，但查不到它的归属，无法判断是不是你的真实地址。" % address,
        evidence=evidence,
    )


def check_stun(
    egress_v4: Optional[str], egress_country: Optional[str] = None, timeout: float = 3.0
) -> LeakCheck:
    results = probe_stun(timeout=timeout)
    mapped = [item for item in results if item.get("ip")]
    if not mapped:
        return LeakCheck(
            "stun",
            "UDP / STUN",
            "info",
            "skip",
            "所有 STUN 服务器都没有响应。UDP 被完全阻断，可能是代理接管，也可能是防火墙丢弃。",
            "如果想确认，可以在浏览器里打开 WebRTC 测试页对照。",
            evidence={"servers": results},
        )

    exposed = sorted({item["ip"] for item in mapped})
    if egress_v4 and all(address == egress_v4 for address in exposed):
        return LeakCheck(
            "stun",
            "UDP / STUN",
            "ok",
            "clean",
            "STUN 服务器看到的公网地址就是代理出口 %s，UDP 走的是同一条链路。" % egress_v4,
            evidence={"servers": results},
        )

    # 地址不同不一定是泄漏：NAT 池、多出口节点都会让同一个代理显示成不同地址。
    # 真正要看的是这个地址落在哪个国家。
    countries = {}
    for address in exposed:
        if address == egress_v4:
            continue
        countries[address] = geo_lookup(address).get("country")

    if any(country == "China" for country in countries.values()):
        return LeakCheck(
            "stun",
            "UDP / STUN",
            "high",
            "leak",
            "STUN 回显 %s，归属中国；而代理出口是 %s。UDP 没有走代理，"
            "WebRTC、语音、QUIC 这类流量会直接暴露你的真实出口地址。"
            % ("、".join(addresses for addresses, country in countries.items() if country == "China"), egress_v4),
            "让代理接管 UDP（Clash TUN 默认接管，检查配置里的 udp 项），"
            "或在浏览器里禁用 WebRTC（chrome://flags 关闭）。",
            evidence={"servers": results, "ipv4": egress_v4, "countries": countries},
        )
    if countries and all(country and country == egress_country for country in countries.values()):
        return LeakCheck(
            "stun",
            "UDP / STUN",
            "low",
            "clean",
            "STUN 回显 %s，与 IPv4 出口 %s 不同，但同属%s，是代理的 NAT 地址池，不是你的真实地址。"
            % ("、".join(exposed), egress_v4 or "未知", COUNTRY_ZH.get(egress_country or "", egress_country or "")),
            "无需处理。",
            evidence={"servers": results, "ipv4": egress_v4, "countries": countries},
        )
    return LeakCheck(
        "stun",
        "UDP / STUN",
        "medium",
        "suspicious",
        "STUN 回显 %s，与代理出口 %s 不同，归属也无法确认。UDP 可能走了另一条线路，"
        "建议用浏览器 WebRTC 测试页复核。" % ("、".join(exposed), egress_v4 or "未知"),
        "在浏览器里搜 WebRTC leak test 对照一次；确认代理接管了 UDP。",
        evidence={"servers": results, "ipv4": egress_v4, "countries": countries},
    )


def check_dns(dns_ip: Optional[str], dns_geo: Optional[str], egress_country: Optional[str]) -> LeakCheck:
    if not dns_geo:
        return LeakCheck(
            "dns",
            "DNS 解析出口",
            "info",
            "skip",
            "拿不到解析器出口位置。",
            evidence={"dns_ip": dns_ip},
        )
    same = bool(egress_country) and egress_country in dns_geo
    if same:
        return LeakCheck(
            "dns",
            "DNS 解析出口",
            "ok",
            "clean",
            "解析器出口与 IP 属地一致（%s），DNS 没有指向别处。" % dns_geo,
            evidence={"dns_ip": dns_ip, "dns_geo": dns_geo},
        )
    return LeakCheck(
        "dns",
        "DNS 解析出口",
        "medium",
        "suspicious",
        "IP 归属 %s，但 DNS 解析出口在 %s。解析器知道你从哪来，"
        "部分 CDN 还会通过 EDNS Client Subnet 把这个位置转告给网站。"
        % (egress_country or "未知", dns_geo),
        "让代理接管 DNS（TUN 模式一般会），或改用加密 DNS（DoH/DoT），"
        "并确认没有开启 ECS。",
        evidence={"dns_ip": dns_ip, "dns_geo": dns_geo, "egress_country": egress_country},
    )


def check_timezone(country: Optional[str], offset: Optional[float], language: str) -> LeakCheck:
    if offset is None:
        return LeakCheck("tz", "系统时区 / 语言", "info", "skip", "读不到本机时区。")

    window = COUNTRY_OFFSETS.get(country or "")
    evidence = {
        "utc_offset": offset,
        "language": language,
        "country": country,
        "expected": window,
    }
    lowered = (language or "").lower()
    lang_cn = lowered.startswith("zh") or "chinese" in lowered
    if window is None:
        return LeakCheck(
            "tz",
            "系统时区 / 语言",
            "info",
            "skip",
            "UTC%+g，语言 %s。该国家没有内置时区基线，只做记录。"
            % (offset, language or "未知"),
            evidence=evidence,
        )

    outside = offset < window[0] or offset > window[1]
    if not outside and not lang_cn:
        return LeakCheck(
            "tz",
            "系统时区 / 语言",
            "ok",
            "clean",
            "UTC%+g、语言 %s，和 IP 属地一致，浏览器不会自相矛盾。"
            % (offset, language or "未知"),
            evidence=evidence,
        )
    if outside and lang_cn:
        return LeakCheck(
            "tz",
            "系统时区 / 语言",
            "medium",
            "leak",
            "系统时区 UTC%+g、语言 %s，IP 却在 %s。浏览器会把这两项主动上报给网站，"
            "比 IP 本身更能说明你实际在哪。"
            % (offset, language or "未知", COUNTRY_ZH.get(country or "", country or "未知")),
            "把浏览器时区和系统语言改成与出口一致（Chrome 可用 --lang 启动参数，"
            "或换一个独立的浏览器配置专门访问这些服务）。",
            evidence=evidence,
        )
    if outside:
        return LeakCheck(
            "tz",
            "系统时区 / 语言",
            "low",
            "suspicious",
            "系统时区 UTC%+g 与 IP 属地 %s 的正常区间不符，语言 %s。" % (offset, country, language or "未知"),
            "把时区调整到出口所在地。",
            evidence=evidence,
        )
    return LeakCheck(
        "tz",
        "系统时区 / 语言",
        "low",
        "suspicious",
        "语言是 %s，但 IP 归属 %s。" % (language, COUNTRY_ZH.get(country or "", country or "未知")),
        "如果不需要中文界面，把浏览器语言改成目标地区。",
        evidence=evidence,
    )


def check_colo(colo: Optional[str], country: Optional[str]) -> LeakCheck:
    if not colo:
        return LeakCheck("colo", "CDN 接入点", "info", "skip", "没取到 Cloudflare 接入点。")
    return LeakCheck(
        "colo",
        "CDN 接入点",
        "info",
        "clean",
        "请求落在 Cloudflare %s 节点。如果你认为出口在别处而这里是另一个大区，"
        "说明流量并没有真的从那里出去。" % colo,
        evidence={"colo": colo, "country": country},
    )


# ------------------------------------------------------------------ 主流程


def run(timeout: float = 8.0) -> LeakReport:
    report = LeakReport()
    egress, _sources = collect_egress(timeout=min(timeout, 8.0))
    report.egress_ipv4 = egress

    trace = http_get("https://www.cloudflare.com/cdn-cgi/trace", timeout=min(timeout, 8.0))
    colo = None
    if trace.ok and trace.status == 200:
        for line in trace.body.splitlines():
            if line.startswith("colo="):
                colo = line[5:].strip()
            if line.startswith("loc=") and not report.egress_country:
                report.egress_country = line[4:].strip()
    report.colo = colo

    if report.egress_country and len(report.egress_country) == 2:
        # Cloudflare 给的是二位国家码，转成全称，和 ip-api 的字段对齐
        from .ipcheck import collect_geo

        geo = collect_geo(egress, timeout=timeout).get("ip-api", {}) if egress else {}
        report.egress_country = geo.get("country") or report.egress_country
    report.egress_country_zh = COUNTRY_ZH.get(report.egress_country or "", None)

    report.local_offset = local_offset_hours()
    report.local_tzname = time.tzname[0] if time.tzname else ""
    report.local_lang = local_language()

    dns_ip, dns_geo = collect_dns_egress(timeout=min(timeout, 8.0))

    report.checks.append(
        check_ipv6(report.egress_ipv4, report.egress_country, timeout=min(timeout, 6.0))
    )
    report.checks.append(check_stun(report.egress_ipv4, report.egress_country, timeout=3.0))
    report.checks.append(check_dns(dns_ip, dns_geo, report.egress_country))
    report.checks.append(
        check_timezone(report.egress_country, report.local_offset, report.local_lang)
    )
    report.checks.append(check_colo(report.colo, report.egress_country))
    return report


def render_text(report: LeakReport) -> str:
    lines = []
    lines.append("=" * 72)
    lines.append(" netsteady · 真实地址暴露面检查")
    lines.append("=" * 72)
    if report.egress_ipv4:
        place = report.egress_country_zh or report.egress_country or "未知"
        lines.append(" 出口 IPv4  %s  （%s）" % (report.egress_ipv4, place))
    else:
        lines.append(" 出口 IPv4  探测失败")
    lines.append(
        " 本机指纹   UTC%+g  时区 %s  语言 %s"
        % (
            report.local_offset if report.local_offset is not None else 0.0,
            report.local_tzname or "未知",
            report.local_lang or "未知",
        )
    )
    lines.append("")

    headers = ["检查项", "风险", "判定", "说明"]
    rows = []
    for check in report.sorted_checks():
        rows.append(
            [
                "%s %s" % (STATUS_ICON.get(check.status, "?"), check.title),
                SEVERITY_ZH.get(check.severity, check.severity),
                {"leak": "泄漏", "suspicious": "可疑", "clean": "正常", "skip": "跳过"}.get(
                    check.status, check.status
                ),
                check.detail,
            ]
        )

    from .report import display_width, pad

    widths = [0, 0, 0]
    for index in range(3):
        widths[index] = max([display_width(headers[index])] + [display_width(row[index]) for row in rows]) + 2

    lines.append(" " + "".join(pad(headers[i], widths[i]) for i in range(3)).rstrip())
    for row in rows:
        head = "".join(pad(row[i], widths[i]) for i in range(3)).rstrip()
        lines.append(" " + head)
        for chunk in _wrap(row[3], 62):
            lines.append(" " * (sum(widths) + 1) + chunk)
    lines.append("")

    level = {"high": "高", "medium": "中", "low": "低"}[report.risk_level]
    lines.append(" 暴露面评级：%s" % level)
    if report.leaks:
        lines.append(" 发现 %d 处可疑通道，下面逐条给处理建议：" % len(report.leaks))
        for check in report.leaks:
            lines.append("   · %s：%s" % (check.title, check.advice or "见上方说明"))
    else:
        lines.append(" 没有发现绕过代理直接暴露真实地址的通道。")

    lines.append("")
    lines.append(" 注意：看不到你的真实地址，不等于这个 IP 就是纯净的。")
    lines.append(" 服务商还握着一套完全独立的判断依据：IP 是否归属于机房或代理、")
    lines.append(" ASN 在商业风控库里的信誉、这个 IP 上跑过多少注册、浏览器的")
    lines.append(" TLS 指纹像不像脚本。这些和你在哪里无关，和你像不像真人有关。")
    lines.append("=" * 72)
    return "\n".join(lines)


def _wrap(text: str, width: int) -> List[str]:
    from .report import display_width

    out, current = [], ""
    for char in text:
        if display_width(current) >= width:
            out.append(current)
            current = ""
        current += char
    if current:
        out.append(current)
    return out or [""]


def render_json(report: LeakReport) -> str:
    return json.dumps(report.as_dict(), ensure_ascii=False, indent=2)
