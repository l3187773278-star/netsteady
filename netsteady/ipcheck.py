"""出口 IP 纯净度体检 + 目标服务可达性判定.

回答三个问题：
1. 我现在的出口 IP 是谁、在哪、什么类型；
2. 用它去访问各个限制中国 IP 的 AI 服务，会撞上哪类拦截；
3. 每个服务域名实际解析到哪个 IP、那个 IP 又归属于哪里。

能测的：出口 IP 归属、ASN、是否机房段、多源地理是否一致、
DNS 出口、反查、黑名单、目标域名的解析 IP 与属地、实际响应码。
测不了的：服务商内部风控评分（含账号历史、浏览器指纹、行为特征）。
"""

from __future__ import annotations

import json
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple

from . import __version__
from .net import http_get, resolve, reverse_dns, tcp_probe
from .report import display_width, pad

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
    "China": "中国",
}

CLOUD_KEYWORDS = (
    "amazon", "aws", "google", "microsoft", "azure", "digitalocean", "linode",
    "vultr", "hetzner", "ovh", "contabo", "alibaba", "aliyun", "tencent",
    "cloudflare", "oracle", "leaseweb", "colocation", "datacenter", "data center",
    "hosting", "cloud", "server", "vps", "dedicated", "m247", "choopa", "gcore",
    "psychz", "buyvm", "racknerd", "bandwagonhost", "hostwinds", "ionic",
)

# 区域限制的通用文案。各家措辞不同，命中任意一条即视为明确的区域拒绝。
REGION_MARKERS = (
    "unsupported_country",
    "not available in your country",
    "not available in your region",
    "unavailable in your region",
    "not supported in your country",
    "not supported in your region",
    "user location is not supported",
    "location is not supported",
    "country not supported",
    "not available in this country",
    "service is not available in your",
)

# 需要逐个探测的 AI 服务。host 用于解析，probe 是实际请求的地址。
SERVICES: Dict[str, Dict[str, Any]] = {
    "claude": {
        "label": "Claude",
        "host": "claude.ai",
        "probe": "https://claude.ai/",
    },
    "claude-api": {
        "label": "Claude API",
        "host": "api.anthropic.com",
        "probe": "https://api.anthropic.com/v1/models",
    },
    "chatgpt": {
        "label": "ChatGPT",
        "host": "chatgpt.com",
        "probe": "https://chatgpt.com/",
    },
    "codex": {
        "label": "OpenAI Codex",
        "host": "chatgpt.com",
        "probe": "https://chatgpt.com/backend-api/codex/responses",
    },
    "openai-api": {
        "label": "OpenAI API",
        "host": "api.openai.com",
        "probe": "https://api.openai.com/v1/models",
    },
    "gemini": {
        "label": "Google Gemini",
        "host": "gemini.google.com",
        "probe": "https://gemini.google.com/",
    },
    "gemini-api": {
        "label": "Gemini API",
        "host": "generativelanguage.googleapis.com",
        "probe": "https://generativelanguage.googleapis.com/v1beta/models",
    },
    "copilot": {
        "label": "Microsoft Copilot",
        "host": "copilot.microsoft.com",
        "probe": "https://copilot.microsoft.com/",
    },
    "github-copilot": {
        "label": "GitHub Copilot",
        "host": "api.githubcopilot.com",
        "probe": "https://api.githubcopilot.com/models",
    },
    "perplexity": {
        "label": "Perplexity",
        "host": "perplexity.ai",
        "probe": "https://perplexity.ai/",
    },
    "grok": {
        "label": "xAI Grok",
        "host": "grok.com",
        "probe": "https://grok.com/",
    },
    "mistral": {
        "label": "Mistral",
        "host": "chat.mistral.ai",
        "probe": "https://chat.mistral.ai/",
    },
    "midjourney": {
        "label": "Midjourney",
        "host": "midjourney.com",
        "probe": "https://midjourney.com/",
    },
    "cursor": {
        "label": "Cursor",
        "host": "cursor.com",
        "probe": "https://cursor.com/",
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
    host: str
    ip: Optional[str] = None
    ip_source: str = "local"  # local | doh
    geo: Dict[str, Any] = field(default_factory=dict)
    tcp_ms: Optional[float] = None
    tcp_ok: bool = False
    status: Optional[int] = None
    state: str = "unknown"  # ok | blocked | challenge | unreachable | unknown
    detail: str = ""

    @property
    def place(self) -> str:
        country = self.geo.get("country") or ""
        country_zh = COUNTRY_ZH.get(country, country)
        region = self.geo.get("city") or self.geo.get("regionName") or ""
        return " · ".join(filter(None, [country_zh, region])) or "-"

    def as_dict(self) -> Dict[str, Any]:
        return {
            "key": self.key,
            "label": self.label,
            "host": self.host,
            "ip": self.ip,
            "ip_source": self.ip_source,
            "ip_country": self.geo.get("country"),
            "ip_region": self.geo.get("regionName"),
            "ip_city": self.geo.get("city"),
            "ip_org": self.geo.get("org"),
            "tcp_ok": self.tcp_ok,
            "tcp_ms": None if self.tcp_ms is None else round(self.tcp_ms, 1),
            "http_status": self.status,
            "state": self.state,
            "detail": self.detail,
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

    @property
    def passing(self) -> List[ServiceResult]:
        return [s for s in self.services if s.state == "ok"]

    @property
    def blocked(self) -> List[ServiceResult]:
        return [s for s in self.services if s.state in ("blocked", "challenge")]

    @property
    def unreachable(self) -> List[ServiceResult]:
        return [s for s in self.services if s.state == "unreachable"]

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
            "summary": {
                "total": len(self.services),
                "passing": len(self.passing),
                "blocked": len(self.blocked),
                "unreachable": len(self.unreachable),
            },
            "score": self.score,
            "raw_geo": self.geo_sources,
        }


# ---------------------------------------------------------------- 出口 IP


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


def batch_geo(ips: Sequence[str], timeout: float = 12.0) -> Dict[str, Dict[str, Any]]:
    """一次批量查询多个 IP 的归属，ip-api 的 /batch 接口限制较松."""
    unique = [ip for ip in dict.fromkeys(ips) if ip]
    if not unique:
        return {}
    body = json.dumps(
        [
            {
                "query": ip,
                "fields": "status,country,countryCode,regionName,city,isp,org,as,hosting,proxy",
            }
            for ip in unique
        ]
    ).encode("utf-8")
    response = http_get(
        "http://ip-api.com/batch",
        timeout=timeout,
        headers={"Content-Type": "application/json"},
        method="POST",
        data=body,
    )
    result: Dict[str, Dict[str, Any]] = {}
    payload = response.json() if response.ok else None
    if isinstance(payload, list) and len(payload) == len(unique):
        for ip, item in zip(unique, payload):
            if isinstance(item, dict) and item.get("status") == "success":
                result[ip] = item
    return result


def collect_dns_egress(timeout: float = 8.0) -> Tuple[Optional[str], Optional[str]]:
    response = http_get("https://edns.ip-api.com/json", timeout=timeout)
    if not response.ok or response.status != 200:
        return None, None
    data = response.json() or {}
    dns = data.get("dns") or {}
    return dns.get("ip"), dns.get("geo")


def is_fake_ip(ip: str) -> bool:
    """198.18.0.0/15 是 Clash 等 TUN 代理 fake-ip 模式的保留段."""
    try:
        parts = [int(part) for part in ip.split(".")]
    except ValueError:
        return False
    return len(parts) == 4 and parts[0] == 198 and 18 <= parts[1] <= 19


# 按可用性排序：Google 与国内 DoH 通常都能连上，Cloudflare 在部分网络下证书会被劫持。
DOH_ENDPOINTS = (
    "https://dns.google/resolve?name=%s&type=A",
    "https://doh.pub/dns-query?name=%s&type=A",
    "https://223.5.5.5/resolve?name=%s&type=A",
    "https://cloudflare-dns.com/dns-query?name=%s&type=A",
)


def resolve_doh(host: str, timeout: float = 6.0) -> List[str]:
    """走 DoH 拿真实解析结果，绕开本机 fake-ip 的伪造应答."""
    for template in DOH_ENDPOINTS:
        response = http_get(
            template % host,
            timeout=timeout,
            headers={"Accept": "application/dns-json"},
        )
        if not response.ok or response.status != 200:
            continue
        data = response.json() or {}
        answers = data.get("Answer") or []
        if isinstance(answers, dict):
            answers = [answers]
        ips = [
            answer["data"]
            for answer in answers
            if isinstance(answer, dict) and answer.get("type") == 1 and answer.get("data")
        ]
        if ips:
            return ips
    return []


def check_dnsbl(ip: str) -> Tuple[str, str]:
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


# ---------------------------------------------------------------- 服务探测


CHALLENGE_MARKERS = (
    "just a moment",
    "cf-challenge",
    "enable javascript and cookies",
    "attention required",
    "checking your browser",
    "verifying you are human",
)


def classify(markers: Sequence[str], response) -> Tuple[str, str]:
    """把一次 HTTP 响应翻译成可达性结论。纯函数，方便测试。"""
    if not response.ok:
        return "unreachable", "连接失败：%s" % (response.error or "unknown")

    status = response.status or 0
    body = (response.body or "").lower()
    headers = {k.lower(): v for k, v in (response.headers or {}).items()}

    hit = next((m for m in markers if m in body), None)
    if hit:
        return "blocked", "区域限制（命中 %s）" % hit

    if 200 <= status < 300:
        return "ok", "HTTP %d，正常响应" % status

    if status == 403:
        if headers.get("cf-mitigated") == "challenge" or any(m in body for m in CHALLENGE_MARKERS):
            return "challenge", "Cloudflare 人机质询（机房/代理 IP 的典型遭遇）"
        return "challenge", "HTTP 403，疑似风控或区域限制（未给明确文案）"

    if status in (401, 404, 405, 422, 429):
        return "ok", "HTTP %d，请求已被受理（无凭据）" % status

    if status >= 500:
        return "unknown", "HTTP %d，服务端异常" % status
    return "unknown", "HTTP %d" % status


def _probe_one(key: str, spec: Dict[str, Any], ip: Optional[str], geo: Dict[str, Any],
               timeout: float, source: str = "local") -> ServiceResult:
    result = ServiceResult(
        key=key,
        label=spec["label"],
        host=spec["host"],
        ip=ip,
        ip_source=source,
        geo=geo,
    )
    if not ip:
        result.state = "unreachable"
        result.detail = "DNS 解析失败"
        return result

    # 连两次取最小值：TUN 代理会缓存会话，第一次可能被本地协议栈秒回。
    samples: List[float] = []
    error = None
    for _ in range(2):
        ok, rtt, err = tcp_probe(ip, 443, timeout=min(timeout, 6.0))
        if ok and rtt is not None:
            samples.append(rtt)
            if rtt < 100:
                break
        else:
            error = err

    result.tcp_ok = bool(samples)
    result.tcp_ms = min(samples) if samples else None
    if not samples:
        result.state = "unreachable"
        result.detail = "TCP 连接失败：%s" % (error or "unknown")
        return result

    response = http_get(
        spec["probe"],
        timeout=timeout,
        headers={"Accept": "text/html,application/json;q=0.9,*/*;q=0.8"},
    )
    state, detail = classify(REGION_MARKERS, response)
    result.state = state
    result.status = response.status
    result.detail = detail
    return result


def probe_services(keys: Sequence[str], timeout: float = 10.0, workers: int = 8) -> List[ServiceResult]:
    selected = [k for k in keys if k in SERVICES]
    hosts: Dict[str, Dict[str, Any]] = {}
    errors: Dict[str, str] = {}
    for key in selected:
        host = SERVICES[key]["host"]
        if host in hosts or host in errors:
            continue
        ips, error = resolve(host, timeout=4.0)
        ip = ips[0] if ips else None
        source = "local"
        if ip and is_fake_ip(ip):
            real = [candidate for candidate in resolve_doh(host) if not is_fake_ip(candidate)]
            if real:
                ip, source = real[0], "doh"
        if ip:
            hosts[host] = {"ip": ip, "source": source}
        else:
            errors[host] = error or "解析失败"

    geo = batch_geo([entry["ip"] for entry in hosts.values() if entry["ip"]])

    results: Dict[str, ServiceResult] = {}
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {}
        for key in selected:
            host = SERVICES[key]["host"]
            entry = hosts.get(host)
            ip = entry["ip"] if entry else None
            if ip is None:
                results[key] = ServiceResult(
                    key=key,
                    label=SERVICES[key]["label"],
                    host=host,
                    state="unreachable",
                    detail="DNS 解析失败：%s" % errors.get(host, "unknown"),
                )
                continue
            futures[
                pool.submit(
                    _probe_one,
                    key,
                    SERVICES[key],
                    ip,
                    geo.get(ip, {}),
                    timeout,
                    entry["source"],
                )
            ] = key
        for future in futures:
            try:
                result = future.result(timeout=timeout + 8)
            except Exception as exc:
                result = ServiceResult(
                    key=futures[future],
                    label=SERVICES[futures[future]]["label"],
                    host=SERVICES[futures[future]]["host"],
                    state="unknown",
                    detail="探测异常：%s" % exc,
                )
            results[result.key] = result

    return [results[k] for k in selected if k in results]


# ---------------------------------------------------------------- 评分


def _network_verdict(report: IpReport) -> Tuple[str, float, str]:
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
    if report.rdns and any(
        token in report.rdns.lower()
        for token in ("amazonaws", "googleusercontent", "cloud", "vps", "host", "server", "static.")
    ):
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


def _score(checks: Sequence[Check]) -> int:
    total = sum(c.weight for c in checks if c.points is not None)
    earned = sum(c.points for c in checks if c.points is not None)
    if total <= 0:
        return 0
    return int(round(earned / total * 100))


def run(
    services: Optional[Sequence[str]] = None,
    dnsbl: bool = False,
    timeout: float = 10.0,
    skip_services: bool = False,
) -> IpReport:
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

    values = {v for v in sources.values() if v}
    if len(values) <= 1:
        report.checks.append(Check("egress", "出口 IP 一致性", "ok", "多家出口服务返回同一 IP", 10.0, 10.0))
    else:
        report.checks.append(
            Check(
                "egress",
                "出口 IP 一致性",
                "warn",
                "出口不一致：" + "、".join("%s=%s" % (k, v or "失败") for k, v in sources.items()),
                10.0,
                4.0,
            )
        )

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
        report.checks.append(Check("geo", "地理一致性", "warn", "来源分歧：%s" % "、".join(unique), 25.0, 12.0))
    else:
        report.checks.append(Check("geo", "地理一致性", "fail", "来源严重分歧：%s" % "、".join(unique), 25.0, 0.0))

    report.network_type, points, detail = _network_verdict(report)
    status = {"residential": "ok", "mobile": "ok", "unknown": "warn", "datacenter": "warn", "proxy": "fail"}[
        report.network_type
    ]
    report.checks.append(Check("type", "网络类型", status, detail, 25.0, points))

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

    points = 0.0
    bits = []
    if report.asn:
        points += 5.0
        bits.append("ASN 完整")
    if report.rdns:
        points += 4.0
        bits.append("有反向解析")
    if report.isp or report.org:
        points += 6.0
        bits.append("运营商信息可查")
    status = "ok" if points >= 12 else ("warn" if points >= 6 else "fail")
    report.checks.append(Check("path", "链路可信度", status, "；".join(bits) or "信息缺失", 15.0, points))

    if dnsbl:
        status, detail = check_dnsbl(ip)
        points_map = {"ok": 15.0, "warn": 4.0, "skip": None}
        report.checks.append(Check("blacklist", "公共黑名单", status, detail, 15.0, points_map.get(status)))
    else:
        report.checks.append(
            Check("blacklist", "公共黑名单", "skip", "未启用（加 --dnsbl 开启，公共 DNS 常被 DNSBL 拒绝）", 15.0, None)
        )

    if not skip_services:
        keys = list(SERVICES) if not services or "all" in services else list(services)
        report.services = probe_services(keys, timeout=timeout)

    report.score = _score(report.checks)
    return report


# ---------------------------------------------------------------- 渲染

STATUS_ICON = {"ok": "✓", "warn": "!", "fail": "✗", "skip": "–"}
STATE_ICON = {"ok": "✓", "blocked": "✗", "challenge": "!", "unreachable": "✗", "unknown": "?"}
STATE_ZH = {
    "ok": "可达",
    "blocked": "区域拒绝",
    "challenge": "WAF 质询",
    "unreachable": "连不上",
    "unknown": "未知",
}


def _service_table(services: Sequence[ServiceResult]) -> List[str]:
    rows = []
    for item in services:
        rows.append(
            [
                "%s %s" % (STATE_ICON.get(item.state, "?"), item.label),
                item.host,
                item.ip or "-",
                item.place,
                ("%.0fms" % item.tcp_ms) if item.tcp_ms is not None else "-",
                STATE_ZH.get(item.state, item.state),
            ]
        )
    headers = ["服务", "域名", "解析 IP", "IP 属地", "握手", "结果"]
    widths = []
    for index, head in enumerate(headers):
        width = max([display_width(head)] + [display_width(row[index]) for row in rows]) + 2
        widths.append(width)

    lines = ["".join(pad(h, w) for h, w in zip(headers, widths)).rstrip()]
    lines.append("-" * sum(widths))
    for row in rows:
        lines.append("".join(pad(c, w) for c, w in zip(row, widths)).rstrip())
    return lines


def _verdict_line(report: IpReport) -> str:
    total = len(report.services)
    if total == 0:
        return "未探测任何服务。"
    passing = len(report.passing)
    blocked = len(report.blocked)
    unreachable = len(report.unreachable)
    if blocked == 0 and passing == total:
        return "全部 %d 个服务可达，当前出口 IP 未触发已知的区域拦截。" % total
    if blocked == total:
        return "全部 %d 个服务被拒绝，当前出口 IP 基本无法使用这些 AI 服务。" % total
    hard = [s for s in report.services if s.state == "blocked"]
    soft = [s for s in report.services if s.state == "challenge"]
    bits = ["%d/%d 个服务可达" % (passing, total)]
    if hard:
        bits.append("明确拒绝 %d 个（%s）" % (len(hard), "、".join(s.label for s in hard[:3])))
    if soft:
        bits.append("遭遇 WAF 质询 %d 个（%s）" % (len(soft), "、".join(s.label for s in soft[:3])))
    if unreachable:
        bits.append("连不上 %d 个" % unreachable)
    return "；".join(bits) + "。"


def render_text(report: IpReport) -> str:
    lines = []
    lines.append("=" * 72)
    lines.append(" netsteady · 出口 IP 纯净度体检")
    lines.append("=" * 72)

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
        lines.append(" 目标服务（域名解析 → IP 属地 → 连通性 → 区域限制）")
        for line in _service_table(report.services):
            lines.append("   " + line)
        lines.append("")
        if any(s.ip_source == "doh" for s in report.services):
            lines.append("   注意：本机 DNS 返回的是 fake-ip（198.18.0.0/15），上表的解析 IP 已改用 DoH 取得。")
            lines.append("")
        lines.append(" 结论：%s" % _verdict_line(report))
        lines.append("")

    lines.append(" 说明：本评分是公开数据的启发式推断，不等同于服务商内部风控结论。")
    lines.append("=" * 72)
    return "\n".join(lines)


def render_json(report: IpReport) -> str:
    return json.dumps(report.as_dict(), ensure_ascii=False, indent=2)
