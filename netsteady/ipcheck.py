"""出口 IP 纯净度体检.

目标：回答"我用这个出口 IP 去访问 ChatGPT / Claude，会撞上哪类拦截"。

能测的：出口 IP 归属、ASN、是否机房段、多源地理是否一致、
DNS 出口是否和 IP 同区、反查、黑名单、目标服务的实际响应码。
测不了的：服务商内部风控评分（含账号历史、浏览器指纹、行为特征），
任何号称能从外部算出这个分数的工具都是编的。
"""

from __future__ import annotations

import json
import socket
import sys
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple

from . import __version__
from .net import http_get, reverse_dns, tcp_probe
from .report import pad

COUNTRY_ZH = {
    "United States": "美国",
    "Japan": "日本",
    "Singapore": "新加坡",
    "Hong Kong": "中国香港",
    "Taiwan": "中国台湾",
    "Korea": "韩国",
    "South Korea": "韩国",
    "Germany": "德国",
    "Netherlands": "荷兰",
    "United Kingdom": "英国",
    "Canada": "加拿大",
    "Australia": "澳大利亚",
    "France": "法国",
    "Russia": "俄罗斯",
    "India": "印度",
    "Turkey": "土耳其",
    "Brazil": "巴西",
    "Argentina": "阿根廷",
    "Thailand": "泰国",
    "Malaysia": "马来西亚",
    "Vietnam": "越南",
    "Philippines": "菲律宾",
    "Indonesia": "印度尼西亚",
    "Sweden": "瑞典",
    "Switzerland": "瑞士",
    "Finland": "芬兰",
    "Poland": "波兰",
    "Ukraine": "乌克兰",
    "Spain": "西班牙",
    "Italy": "意大利",
    "Ireland": "爱尔兰",
    "Romania": "罗马尼亚",
    "United Arab Emirates": "阿联酋",
    "Israel": "以色列",
}

CLOUD_KEYWORDS = (
    "amazon", "aws", "google", "microsoft", "azure", "digitalocean", "linode",
    "vultr", "hetzner", "ovh", "contabo", "alibaba", "aliyun", "tencent",
    "cloudflare", "oracle", "leaseweb", "colocation", "datacenter", "data center",
    "hosting", "cloud", "server", "vps", "dedicated", "m247", "choopa", "gcore",
    "psychz", "buyvm", "racknerd", "bandwagonhost", "hostwinds", "ionic",
)

SERVICES = {
    "claude": {
        "label": "Anthropic / Claude",
        "web": "https://claude.ai/",
        "api": "https://api.anthropic.com/v1/models",
        "markers": ["not available in your region", "unavailable in your region", "forbidden"],
    },
    "openai": {
        "label": "OpenAI / ChatGPT",
        "web": "https://chatgpt.com/",
        "api": "https://api.openai.com/v1/models",
        "markers": ["unsupported_country", "not available in your country", "country not supported"],
    },
}

DNSBL_ZONES = ("zen.spamhaus.org", "bl.spamcop.net", "b.barracudacentral.org")


@dataclass
class Check:
    key: str
    title: str
    status: str  # ok | warn | fail | skip
    detail: str
    weight: float
    points: Optional[float] = None

    def as_dict(self) -> Dict[str, Any]:
        return {
            "key": self.key,
            "title": self.title,
            "status": self.status,
            "detail": self.detail,
            "weight": self.weight,
            "points": self.points,
        }


@dataclass
class ServiceResult:
    key: str
    label: str
    state: str  # reachable | blocked | challenge | unreachable | unknown
    detail: str
    status: Optional[int] = None
    elapsed_ms: Optional[float] = None

    def as_dict(self) -> Dict[str, Any]:
        return {
            "key": self.key,
            "label": self.label,
            "state": self.state,
            "detail": self.detail,
            "status": self.status,
            "elapsed_ms": self.elapsed_ms,
        }


@dataclass
class IpReport:
    egress_ip: Optional[str] = None
    egress_sources: Dict[str, Optional[str]] = field(default_factory=dict)
    country: Optional[str] = None
    country_zh: Optional[str] = None
    region: Optional[str] = None
    city: Optional[str] = None
    isp: Optional[str] = None
    org: Optional[str] = None
    asn: Optional[str] = None
    as_name: Optional[str] = None
    rdns: Optional[str] = None
    network_type: str = "unknown"
    hosting: Optional[bool] = None
    proxy: Optional[bool] = None
    mobile: Optional[bool] = None
    dns_ip: Optional[str] = None
    dns_geo: Optional[str] = None
    checks: List[Check] = field(default_factory=list)
    services: List[ServiceResult] = field(default_factory=list)
    score: int = 0
    geo_sources: Dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "version": __version__,
            "egress_ip": self.egress_ip,
            "egress_sources": self.egress_sources,
            "geo": {
                "country": self.country,
                "country_zh": self.country_zh,
                "region": self.region,
                "city": self.city,
                "isp": self.isp,
                "org": self.org,
                "asn": self.asn,
                "as_name": self.as_name,
                "rdns": self.rdns,
                "hosting": self.hosting,
                "proxy": self.proxy,
                "mobile": self.mobile,
                "network_type": self.network_type,
            },
            "dns": {"ip": self.dns_ip, "geo": self.dns_geo},
            "checks": [c.as_dict() for c in self.checks],
            "services": [s.as_dict() for s in self.services],
            "score": self.score,
            "raw_geo": self.geo_sources,
        }


def _plain_ip(body: str) -> Optional[str]:
    text = body.strip().split(";")[0].strip()
    if text.count(".") == 3 or ":" in text:
        return text
    return None


def _trace_ip(body: str) -> Optional[str]:
    for line in body.splitlines():
        if line.startswith("ip="):
            return line[3:].strip()
    return None


def collect_egress(timeout: float = 8.0) -> Tuple[Optional[str], Dict[str, Optional[str]]]:
    sources: Dict[str, Optional[str]] = {}
    response = http_get("https://www.cloudflare.com/cdn-cgi/trace", timeout=timeout)
    sources["cloudflare"] = _trace_ip(response.body) if response.ok and response.status == 200 else None
    response = http_get("https://api.ip.sb/ip", timeout=timeout)
    sources["ip.sb"] = _plain_ip(response.body) if response.ok and response.status == 200 else None
    response = http_get("http://checkip.amazonaws.com", timeout=timeout)
    sources["aws"] = _plain_ip(response.body) if response.ok and response.status == 200 else None

    counts: Dict[str, int] = {}
    for value in sources.values():
        if value:
            counts[value] = counts.get(value, 0) + 1
    primary = max(counts.items(), key=lambda kv: kv[1])[0] if counts else None
    return primary, sources


def collect_geo(ip: str, timeout: float = 10.0) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    response = http_get(
        "http://ip-api.com/json/%s?fields=status,message,country,countryCode,regionName,"
        "city,isp,org,as,asname,reverse,mobile,proxy,hosting,timezone" % ip,
        timeout=timeout,
    )
    if response.ok and response.status == 200:
        out["ip-api"] = response.json() or {}
    response = http_get("https://api.ip.sb/geoip/%s" % ip, timeout=timeout)
    if response.ok and response.status == 200:
        out["ip.sb"] = response.json() or {}
    response = http_get("https://ipapi.co/%s/json/" % ip, timeout=timeout)
    if response.ok and response.status == 200:
        out["ipapi.co"] = response.json() or {}
    return out


def collect_dns_egress(timeout: float = 8.0) -> Tuple[Optional[str], Optional[str]]:
    response = http_get("https://edns.ip-api.com/json", timeout=timeout)
    if not response.ok or response.status != 200:
        return None, None
    data = response.json() or {}
    dns = data.get("dns") or {}
    return dns.get("ip"), dns.get("geo")


def check_dnsbl(ip: str) -> Tuple[str, str]:
    """返回 (status, detail)。命中任意 zone 即视为有记录."""
    if ":" in ip:
        return "skip", "IPv6 暂不支持 DNSBL 查询"
    reversed_ip = ".".join(reversed(ip.split(".")))
    hits = []
    errors = 0
    for zone in DNSBL_ZONES:
        try:
            answer = socket.gethostbyname("%s.%s" % (reversed_ip, zone))
        except socket.gaierror:
            continue
        except Exception:
            errors += 1
            continue
        if answer.startswith("127.255.255"):
            errors += 1
            continue
        hits.append("%s(%s)" % (zone, answer))
    if hits:
        return "warn", "命中公共黑名单：" + "、".join(hits)
    if errors == len(DNSBL_ZONES):
        return "skip", "全部查询失败（公共 DNS 常被 DNSBL 拒绝），本项不参与评分"
    return "ok", "未命中 Spamhaus / SpamCop / Barracuda"


def classify_service(key: str, response) -> ServiceResult:
    spec = SERVICES[key]
    label = spec["label"]
    if not response.ok:
        return ServiceResult(key, label, "unreachable", "连接失败：%s" % (response.error or "unknown"), None, response.elapsed_ms)

    status = response.status or 0
    body = (response.body or "").lower()
    hit = next((m for m in spec["markers"] if m in body), None)

    if hit:
        return ServiceResult(key, label, "blocked", "区域封锁（命中 %s）" % hit, status, response.elapsed_ms)
    if 200 <= status < 300:
        return ServiceResult(key, label, "reachable", "HTTP %d，正常响应" % status, status, response.elapsed_ms)
    if status in (401, 403, 404, 405, 422, 429):
        state = "challenge" if status == 403 else "reachable"
        note = "HTTP %d，请求被受理（无凭据）" % status
        if status == 403:
            note = "HTTP 403，疑似 WAF 或区域限制，但未命中明确文案"
        return ServiceResult(key, label, state, note, status, response.elapsed_ms)
    if status >= 500:
        return ServiceResult(key, label, "unknown", "HTTP %d，服务端异常" % status, status, response.elapsed_ms)
    return ServiceResult(key, label, "unknown", "HTTP %d" % status, status, response.elapsed_ms)


def probe_services(keys: Sequence[str], timeout: float = 10.0) -> List[ServiceResult]:
    results = []
    for key in keys:
        spec = SERVICES.get(key)
        if spec is None:
            continue
        response = http_get(spec["api"], timeout=timeout, headers={"Accept": "application/json"})
        result = classify_service(key, response)
        if result.state == "unreachable":
            response = http_get(spec["web"], timeout=timeout)
            result = classify_service(key, response)
        results.append(result)
    return results


def _network_verdict(report: IpReport) -> Tuple[str, float, str]:
    """判断 IP 类型，返回 (类型, 分数, 说明)."""
    reasons = []
    datacenter = False
    if report.hosting is True:
        datacenter = True
        reasons.append("ip-api 标记为 hosting")
    if report.proxy is True:
        reasons.append("ip-api 标记为 proxy")
    blob = (" ".join(filter(None, [report.org, report.isp, report.as_name, report.rdns])) or "").lower()
    keyword = next((k for k in CLOUD_KEYWORDS if k in blob), None)
    if keyword:
        datacenter = True
        reasons.append("归属名含 %s" % keyword)
    if report.rdns and any(token in report.rdns.lower() for token in ("amazonaws", "googleusercontent", "cloud", "vps", "host", "server", "static.")):
        datacenter = True
        reasons.append("反向解析像云主机")

    if report.mobile is True:
        return "mobile", 24.0, "移动网络出口" + ("（" + "；".join(reasons) + "）" if reasons else "")
    if report.proxy is True:
        return "proxy", 4.0, "公开代理特征"
    if datacenter:
        return "datacenter", 8.0, "机房/云主机段（" + "；".join(reasons) + "）"
    if reasons:
        return "unknown", 14.0, "；".join(reasons)
    return "residential", 22.0, "未见机房或代理特征，疑似家宽/企业线路"


def run(services: Sequence[str] = ("claude", "openai"), dnsbl: bool = False, timeout: float = 10.0) -> IpReport:
    report = IpReport()
    ip, sources = collect_egress(timeout=min(timeout, 8.0))
    report.egress_ip = ip
    report.egress_sources = sources

    if not ip:
        report.checks.append(
            Check("egress", "出口探测", "fail", "三个出口 IP 服务全部失败，网络不通或全被拦截", 10.0, 0.0)
        )
        report.score = 0
        return report

    geo = collect_geo(ip, timeout=timeout)
    report.geo_sources = geo
    primary = geo.get("ip-api") or geo.get("ip.sb") or {}
    report.country = primary.get("country") or primary.get("country_name")
    report.country_zh = COUNTRY_ZH.get(report.country or "", None)
    report.region = primary.get("regionName") or primary.get("region")
    report.city = primary.get("city")
    report.isp = primary.get("isp")
    report.org = primary.get("org") or primary.get("organization")
    report.asn = primary.get("as") or (("AS%s" % primary["asn"]) if primary.get("asn") else None)
    report.as_name = primary.get("asname")
    report.hosting = primary.get("hosting")
    report.proxy = primary.get("proxy")
    report.mobile = primary.get("mobile")
    report.rdns = primary.get("reverse") or reverse_dns(ip)

    report.dns_ip, report.dns_geo = collect_dns_egress(timeout=min(timeout, 8.0))

    # 1. 出口一致性
    values = {v for v in sources.values() if v}
    if len(values) <= 1:
        status, points = "ok", 10.0
        detail = "多家出口服务返回同一 IP"
    else:
        status, points = "warn", 4.0
        detail = "出口不一致：" + "、".join("%s=%s" % (k, v or "失败") for k, v in sources.items())
    report.checks.append(Check("egress", "出口 IP 一致性", status, detail, 10.0, points))

    # 2. 地理一致性
    countries = []
    for name, payload in geo.items():
        value = payload.get("country_name") or payload.get("country")
        if value:
            countries.append(value)
    unique = sorted(set(countries))
    if len(unique) == 0:
        report.checks.append(Check("geo", "地理一致性", "skip", "地理库全部查询失败，本项不参与评分", 25.0, None))
    elif len(unique) == 1:
        report.checks.append(
            Check("geo", "地理一致性", "ok", "%d 个来源一致指向 %s" % (len(countries), unique[0]), 25.0, 25.0)
        )
    elif len(unique) == 2:
        report.checks.append(
            Check("geo", "地理一致性", "warn", "来源分歧：%s" % "、".join(unique), 25.0, 12.0)
        )
    else:
        report.checks.append(
            Check("geo", "地理一致性", "fail", "来源严重分歧：%s" % "、".join(unique), 25.0, 0.0)
        )

    # 3. 网络类型
    report.network_type, points, detail = _network_verdict(report)
    status = {"residential": "ok", "mobile": "ok", "unknown": "warn", "datacenter": "warn", "proxy": "fail"}[
        report.network_type
    ]
    report.checks.append(Check("type", "网络类型", status, detail, 25.0, points))

    # 4. DNS 出口
    dns_country = None
    if report.dns_geo:
        for english, zh in COUNTRY_ZH.items():
            if english in report.dns_geo or zh in report.dns_geo:
                dns_country = english
                break
        if dns_country is None:
            dns_country = report.dns_geo
    if not report.dns_geo:
        report.checks.append(Check("dns", "DNS 出口", "skip", "无法取到解析器出口位置，本项不参与评分", 20.0, None))
    elif dns_country and report.country and dns_country == report.country:
        report.checks.append(
            Check("dns", "DNS 出口", "ok", "解析器与出口 IP 同区（%s）" % report.dns_geo, 20.0, 20.0)
        )
    elif dns_country:
        report.checks.append(
            Check(
                "dns",
                "DNS 出口",
                "warn",
                "解析器出口 %s 与 IP 归属 %s 不一致，DNS 可能泄漏真实位置" % (report.dns_geo, report.country or "未知"),
                20.0,
                6.0,
            )
        )
    else:
        report.checks.append(Check("dns", "DNS 出口", "warn", "解析器位置未知（%s）" % report.dns_geo, 20.0, 8.0))

    # 5. 链路可信度
    points = 0.0
    bits = []
    if report.asn:
        points += 5.0
        bits.append("ASN 完整")
    if report.rdns:
        points += 4.0
        bits.append("有反向解析")
    ok_any = any(tcp_probe(host, port, 5.0)[0] for host, port in (("claude.ai", 443), ("chatgpt.com", 443)))
    if ok_any:
        points += 6.0
        bits.append("目标站点可建连")
    status = "ok" if points >= 12 else ("warn" if points >= 6 else "fail")
    report.checks.append(Check("path", "链路可信度", status, "；".join(bits) or "信息缺失", 15.0, points))

    # 6. 黑名单（可选）
    if dnsbl:
        status, detail = check_dnsbl(ip)
        points_map = {"ok": 15.0, "warn": 4.0, "skip": None}
        report.checks.append(Check("blacklist", "公共黑名单", status, detail, 15.0, points_map.get(status)))
    else:
        report.checks.append(
            Check("blacklist", "公共黑名单", "skip", "未启用（加 --dnsbl 开启，公共 DNS 常被 DNSBL 拒绝）", 15.0, None)
        )

    report.services = probe_services(services, timeout=timeout)
    report.score = _score(report.checks)
    return report


def _score(checks: Sequence[Check]) -> int:
    total = sum(c.weight for c in checks if c.points is not None)
    earned = sum(c.points for c in checks if c.points is not None)
    if total <= 0:
        return 0
    return int(round(earned / total * 100))


STATUS_ICON = {"ok": "✓", "warn": "!", "fail": "✗", "skip": "–"}
STATE_ICON = {"reachable": "✓", "blocked": "✗", "challenge": "!", "unreachable": "✗", "unknown": "?"}


def render_text(report: IpReport) -> str:
    lines = []
    lines.append("=" * 66)
    lines.append(" netsteady · 出口 IP 纯净度体检")
    lines.append("=" * 66)

    if not report.egress_ip:
        lines.append(" 无法确定出口 IP，检查网络后重试。")
        return "\n".join(lines)

    place = " ".join(filter(None, [report.country_zh or report.country, report.region, report.city]))
    lines.append(" 出口 IP    %s%s" % (report.egress_ip, ("  （%s）" % place) if place else ""))
    as_text = report.asn or ""
    org_text = report.org or report.isp or ""
    if as_text and org_text and org_text.lower() in as_text.lower():
        org_text = ""
    if as_text or org_text:
        lines.append(" 归属       %s" % "  ".join(filter(None, [as_text, org_text])))
    if report.rdns:
        lines.append(" 反向解析   %s" % report.rdns)
    kind_zh = {
        "residential": "家宽 / 企业线路",
        "mobile": "移动网络",
        "datacenter": "机房 / 云主机",
        "proxy": "公开代理",
        "unknown": "未知",
    }.get(report.network_type, report.network_type)
    lines.append(" 网络类型   %s" % kind_zh)
    if report.dns_ip or report.dns_geo:
        lines.append(" DNS 出口   %s%s" % (report.dns_geo or "未知", ("  " + report.dns_ip) if report.dns_ip else ""))
    lines.append("")

    filled = int(report.score / 100 * 24)
    bar = "█" * filled + "░" * (24 - filled)
    grade = "高" if report.score >= 75 else ("中" if report.score >= 50 else "低")
    lines.append(" 综合评分   %d / 100   %s   可信度：%s" % (report.score, bar, grade))
    lines.append("")

    lines.append(" 检查明细")
    for check in report.checks:
        icon = STATUS_ICON.get(check.status, "?")
        weight = "" if check.points is None else "  (%.0f/%.0f)" % (check.points, check.weight)
        lines.append("   %s %s%s%s" % (icon, pad(check.title, 16), check.detail, weight))
    lines.append("")

    if report.services:
        lines.append(" 目标服务")
        for service in report.services:
            icon = STATE_ICON.get(service.state, "?")
            lines.append("   %s %s%s" % (icon, pad(service.label, 20), service.detail))
        lines.append("")

    lines.append(" 说明：本评分是公开数据的启发式推断，不等同于服务商内部风控结论。")
    lines.append("=" * 66)
    return "\n".join(lines)


def render_json(report: IpReport) -> str:
    return json.dumps(report.as_dict(), ensure_ascii=False, indent=2)
