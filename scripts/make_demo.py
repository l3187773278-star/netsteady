"""生成 docs/demo.html 的示例报告.

所有数据都是合成的，不含任何真实测量结果。
"""

from __future__ import annotations

import os
import random
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from netsteady import html_report  # noqa: E402
from netsteady.model import Sample, Target  # noqa: E402
from netsteady.report import render_text_report  # noqa: E402
from netsteady.stats import build_verdict, summarize  # noqa: E402

# 固定的合成时间轴：19:40 开始，40 分钟，每 2 秒一次
START = 1737037200  # 2025-01-16 19:40:00 +08:00
INTERVAL = 2
ROUNDS = 1200

TARGETS = [
    Target("cf-1.1.1.1", "1.1.1.1", 443, "overseas", "Cloudflare DNS"),
    Target("goog-dns-8.8.8.8", "8.8.8.8", 53, "overseas", "Google Public DNS"),
    Target("opendns-208.67.222.222", "208.67.222.222", 443, "overseas", "Cisco OpenDNS"),
    Target("cn-114", "114.114.114.114", 53, "domestic", "114 DNS"),
    Target("cn-ali", "223.5.5.5", 53, "domestic", "阿里公共 DNS"),
]

BASE = {
    "cf-1.1.1.1": (42.0, 3.0),
    "goog-dns-8.8.8.8": (48.0, 4.0),
    "opendns-208.67.222.222": (158.0, 12.0),
    "cn-114": (12.0, 1.5),
    "cn-ali": (9.0, 1.0),
}

# 晚高峰劣化窗口：20:05 起持续 20 分钟
DEGRADE_FROM = START + 25 * 60
DEGRADE_TO = START + 45 * 60


def main() -> int:
    rng = random.Random(20250116)
    samples = {target.name: [] for target in TARGETS}

    for index in range(ROUNDS):
        ts = START + index * INTERVAL
        peak = DEGRADE_FROM <= ts < DEGRADE_TO
        for target in TARGETS:
            base, spread = BASE[target.name]
            overseas = target.group == "overseas"
            if peak and overseas:
                loss_rate = 0.18 if target.host != "208.67.222.222" else 0.26
                extra = 120.0 if target.host != "208.67.222.222" else 90.0
            else:
                loss_rate = 0.0
                extra = 0.0
            ok = rng.random() > loss_rate
            rtt = None
            if ok:
                rtt = base + extra + rng.gauss(0, spread) + (rng.random() < 0.02) * 40
                rtt = max(1.0, rtt)
            samples[target.name].append(
                Sample(ts=ts, target=target.name, ok=ok, rtt_ms=rtt, error=None if ok else "timeout")
            )

    summaries = [summarize(samples[target.name]) for target in TARGETS]
    overseas = [s for s in summaries if s.target not in ("cn-114", "cn-ali")]
    domestic = [s for s in summaries if s.target in ("cn-114", "cn-ali")]
    verdict = build_verdict(overseas, domestic)
    groups = {target.name: target.group for target in TARGETS}
    meta = {
        "开始": "2025-01-16 19:40:00",
        "结束": "2025-01-16 20:20:00",
        "持续": "40m00s",
        "探测间隔": "2s",
        "样本总数": str(sum(s.sent for s in summaries)),
    }

    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    out = os.path.join(root, "docs", "demo.html")
    content = html_report.render_html(summaries, samples, verdict, meta, groups)
    with open(out, "w", encoding="utf-8") as handle:
        handle.write(content)

    text = render_text_report(summaries, samples, verdict, meta, groups)
    print(text.split("【结论】")[1].split("=")[0].strip()[:200])
    print("wrote", out, len(content), "bytes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
