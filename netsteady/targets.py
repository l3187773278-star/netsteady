"""内置目标清单与自定义加载."""

from __future__ import annotations

import json
from typing import List, Optional, Sequence, Tuple

from .model import Target

# 境外锚点：挑的是全球任播、长期在线、零鉴权的服务。
# 它们不对 ICMP 友好，所以统一用 TCP 握手探测。
OVERSEAS_PRESETS: Tuple[Target, ...] = (
    Target("cf-1.1.1.1", "1.1.1.1", 443, "overseas", "Cloudflare DNS"),
    Target("cf-1.0.0.1", "1.0.0.1", 443, "overseas", "Cloudflare DNS 备"),
    Target("goog-dns-8.8.8.8", "8.8.8.8", 53, "overseas", "Google Public DNS"),
    Target("quad9-9.9.9.9", "9.9.9.9", 53, "overseas", "Quad9"),
    Target("opendns-208.67.222.222", "208.67.222.222", 443, "overseas", "Cisco OpenDNS"),
)

# 境内对照组：国内三大公共 DNS，用来区分"我本地坏了"和"国际出口堵了"。
DOMESTIC_PRESETS: Tuple[Target, ...] = (
    Target("cn-114", "114.114.114.114", 53, "domestic", "114 DNS"),
    Target("cn-ali", "223.5.5.5", 53, "domestic", "阿里公共 DNS"),
    Target("cn-tencent", "119.29.29.29", 53, "domestic", "腾讯 DNSPod"),
)


def parse_endpoint(spec: str, group: str = "custom") -> Target:
    """把 host / host:port 解析成 Target."""
    spec = spec.strip()
    if not spec:
        raise ValueError("empty target")
    if spec.count(":") == 1:
        host, _, port_text = spec.partition(":")
        port = int(port_text)
    else:
        host, port = spec, 443
    if not host:
        raise ValueError("bad target: %r" % spec)
    return Target(host, host, port, group, "自定义")


def load_targets(path: Optional[str] = None) -> List[Target]:
    """从 JSON 文件加载目标清单，格式见 examples/targets.json."""
    if not path:
        return list(OVERSEAS_PRESETS) + list(DOMESTIC_PRESETS)
    with open(path, "r", encoding="utf-8") as handle:
        raw = json.load(handle)
    if isinstance(raw, dict):
        raw = raw.get("targets", [])
    out: List[Target] = []
    for index, item in enumerate(raw):
        if isinstance(item, str):
            out.append(parse_endpoint(item))
            continue
        host = item["host"]
        out.append(
            Target(
                name=item.get("name") or host,
                host=host,
                port=int(item.get("port", 443)),
                group=item.get("group", "custom"),
                note=item.get("note", ""),
            )
        )
    if not out:
        raise ValueError("targets file %s contains no targets" % path)
    return out


def split_groups(targets: Sequence[Target]) -> Tuple[List[Target], List[Target]]:
    overseas = [t for t in targets if t.group != "domestic"]
    domestic = [t for t in targets if t.group == "domestic"]
    return overseas, domestic
