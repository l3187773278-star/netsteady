"""报告渲染：终端文本、CSV、单文件 HTML."""

from __future__ import annotations

import csv
import html
import time
import unicodedata
from typing import Dict, List, Optional, Sequence, Tuple

from .model import Sample
from .stats import Summary, Verdict, estimate_interval

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
CYAN = "\033[36m"

PALETTE = [
    "#4c9aff",
    "#36b37e",
    "#ffab00",
    "#ff5630",
    "#6554c0",
    "#00b8d9",
    "#ff8b00",
    "#57d9a3",
]


def display_width(text: str) -> int:
    """中文等全角字符占两列."""
    width = 0
    for char in text:
        width += 2 if unicodedata.east_asian_width(char) in ("W", "F") else 1
    return width


def pad(text: str, width: int, align: str = "left") -> str:
    filler = " " * max(0, width - display_width(text))
    return filler + text if align == "right" else text + filler


def fmt_duration(seconds: float) -> str:
    seconds = max(0.0, float(seconds))
    if seconds < 60:
        return "%.0fs" % seconds
    minutes, rest = divmod(int(round(seconds)), 60)
    if minutes < 60:
        return "%dm%02ds" % (minutes, rest)
    hours, minutes = divmod(minutes, 60)
    if hours < 24:
        return "%dh%02dm" % (hours, minutes)
    days, hours = divmod(hours, 24)
    return "%dd%02dh" % (days, hours)


def fmt_ms(value: Optional[float]) -> str:
    if value is None:
        return "-"
    if value >= 1000:
        return "%.1fs" % (value / 1000.0)
    return "%.0f" % value


def group_label(target: str, groups: Dict[str, str]) -> str:
    return "境内" if groups.get(target) == "domestic" else "境外"


def summary_table(
    summaries: Sequence[Summary],
    groups: Optional[Dict[str, str]] = None,
    color: bool = False,
) -> str:
    """目标概览表."""
    groups = groups or {}
    headers = ["目标", "组别", "样本", "丢包%", "最小", "中位", "P95", "P99", "抖动", "最长断流"]
    aligns = ["left", "left", "right", "right", "right", "right", "right", "right", "right", "right"]
    rows = []
    for item in summaries:
        loss = "%.1f" % item.loss_pct
        if color and item.loss_pct >= 5.0:
            loss = RED + loss + RESET
        elif color and item.loss_pct > 0:
            loss = YELLOW + loss + RESET
        rows.append(
            [
                item.target,
                group_label(item.target, groups),
                str(item.sent),
                loss,
                fmt_ms(item.rtt_min),
                fmt_ms(item.rtt_p50),
                fmt_ms(item.rtt_p95),
                fmt_ms(item.rtt_p99),
                fmt_ms(item.jitter_ms),
                fmt_duration(item.longest_outage_s),
            ]
        )

    widths = []
    for index, header in enumerate(headers):
        width = display_width(header)
        for row in rows:
            width = max(width, display_width(row[index]))
        widths.append(width + 2)

    lines = ["".join(pad(h, w) for h, w in zip(headers, widths)).rstrip()]
    lines.append("-" * sum(widths))
    for row in rows:
        lines.append("".join(pad(c, w, a) for c, w, a in zip(row, widths, aligns)).rstrip())
    return "\n".join(lines)


def hourly_table(
    per_target: Dict[str, List[Sample]],
    summaries: Sequence[Summary],
    groups: Optional[Dict[str, str]] = None,
) -> str:
    """按小时聚合的丢包率 / 中位延迟."""
    from .stats import hourly_summaries

    groups = groups or {}
    buckets = hourly_summaries({s.target: per_target.get(s.target, []) for s in summaries})
    hours = sorted({h for per in buckets.values() for h in per})
    if not hours:
        return "（没有足够样本按时段聚合）"

    header = ["目标"] + ["%02d:00" % h for h in hours]
    rows = []
    for item in summaries:
        row = [item.target]
        per = buckets.get(item.target, {})
        for hour in hours:
            summary = per.get(hour)
            if not summary or summary.sent == 0:
                row.append("-")
            else:
                row.append("%.0f%%/%.0f" % (summary.loss_pct, summary.rtt_p50 or 0.0))
        rows.append(row)

    widths = []
    for index, head in enumerate(header):
        width = display_width(head)
        for row in rows:
            width = max(width, display_width(row[index]))
        widths.append(max(width, 9 if index else width) + 2)

    lines = ["".join(pad(h, w) for h, w in zip(header, widths)).rstrip()]
    lines.append("-" * sum(widths))
    for row in rows:
        lines.append("".join(pad(c, w) for c, w in zip(row, widths)).rstrip())
    lines.append("")
    lines.append("（单元格 = 丢包率 / 中位延迟 ms，按本地时间整点分桶）")
    return "\n".join(lines)


def render_text_report(
    summaries: Sequence[Summary],
    per_target: Dict[str, List[Sample]],
    verdict: Verdict,
    meta: Dict[str, str],
    groups: Optional[Dict[str, str]] = None,
) -> str:
    total = 0
    span = 0.0
    for item in summaries:
        total += item.sent
        span = max(span, item.span_s)

    blocks = []
    blocks.append("=" * 78)
    blocks.append(" netsteady · 跨境网络稳定性报告")
    blocks.append("=" * 78)
    for key in ("开始", "结束", "持续", "探测间隔", "样本总数"):
        if key in meta:
            blocks.append(" %-6s %s" % (key + "：", meta[key]))
    blocks.append("")
    groups = groups or {}
    blocks.append("【目标概览】")
    blocks.append(summary_table(summaries, groups))
    blocks.append("")

    fast = [
        s
        for s in summaries
        if groups.get(s.target) != "domestic" and s.rtt_p50 is not None and s.rtt_p50 < 8.0
    ]
    if fast:
        blocks.append("【提示】")
        blocks.append(" 以下境外目标的中位 RTT 低得不合常理（< 8ms），通常意味着流量被本地代理")
        blocks.append(" 或 TUN 模式接管，或该目标走的是就近 anycast 节点：此时你测到的是本地")
        blocks.append(" 协议栈的响应，而不是真实的跨境物理链路。")
        blocks.append("   " + "、".join(s.target for s in fast))
        blocks.append("")
    blocks.append("【分时段聚合】")
    blocks.append(hourly_table(per_target, summaries, groups))
    blocks.append("")
    blocks.append("【结论】")
    marker = {"ok": "[ OK ]", "warn": "[WARN]", "bad": "[BAD ]"}.get(verdict.level, "[ ?? ]")
    blocks.append(" %s %s" % (marker, verdict.headline))
    for line in _wrap(verdict.detail, 74, indent="        "):
        blocks.append(line)
    blocks.append("")
    blocks.append(" 说明：丢包率与尾延迟同时超标才算劣化；判定以境内对照组为基线。")
    blocks.append("=" * 78)
    return "\n".join(blocks)


def _wrap(text: str, width: int, indent: str = "") -> List[str]:
    lines = []
    current = ""
    for char in text:
        if display_width(current) >= width and char in "，。、；：）":
            lines.append(indent + current + char)
            current = ""
            continue
        if display_width(current) >= width:
            lines.append(indent + current)
            current = ""
        current += char
    if current:
        lines.append(indent + current)
    return lines or [indent]


def write_csv(path: str, summaries: Sequence[Summary], groups: Optional[Dict[str, str]] = None) -> None:
    groups = groups or {}
    with open(path, "w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(
            [
                "target",
                "group",
                "sent",
                "ok",
                "loss_pct",
                "rtt_min_ms",
                "rtt_avg_ms",
                "rtt_p50_ms",
                "rtt_p95_ms",
                "rtt_p99_ms",
                "rtt_max_ms",
                "jitter_ms",
                "outage_count",
                "longest_outage_s",
            ]
        )
        for item in summaries:
            writer.writerow(
                [
                    item.target,
                    groups.get(item.target, "overseas"),
                    item.sent,
                    item.ok,
                    round(item.loss_pct, 3),
                    _round(item.rtt_min),
                    _round(item.rtt_avg),
                    _round(item.rtt_p50),
                    _round(item.rtt_p95),
                    _round(item.rtt_p99),
                    _round(item.rtt_max),
                    _round(item.jitter_ms),
                    len(item.outages),
                    round(item.longest_outage_s, 2),
                ]
            )


def _round(value: Optional[float]) -> Optional[float]:
    return None if value is None else round(value, 2)
