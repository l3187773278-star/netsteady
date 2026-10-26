"""单文件 HTML 报告：内联 CSS + 内联 SVG，零外部依赖、离线可看."""

from __future__ import annotations

import html
import time
from typing import Dict, List, Optional, Sequence, Tuple

from .model import Sample
from .report import PALETTE, fmt_duration, fmt_ms, display_width
from .stats import Summary, Verdict, estimate_interval, hourly_summaries

CSS = """
:root{--bg:#f6f7f9;--card:#fff;--ink:#1f2430;--muted:#6b7280;--line:#e5e7eb;
--ok:#1f9d55;--warn:#d97706;--bad:#dc2626;--accent:#2563eb}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);
font:14px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI","PingFang SC","Microsoft YaHei",sans-serif}
.wrap{max-width:1040px;margin:0 auto;padding:32px 20px 64px}
h1{font-size:22px;margin:0 0 6px}
h2{font-size:15px;margin:0 0 14px;font-weight:600;letter-spacing:.02em}
.sub{color:var(--muted);font-size:13px;margin:0 0 22px}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;
padding:18px 20px;margin-bottom:18px}
.verdict{border-left:4px solid var(--accent)}
.verdict.ok{border-left-color:var(--ok)}.verdict.warn{border-left-color:var(--warn)}
.verdict.bad{border-left-color:var(--bad)}
.verdict .head{font-size:16px;font-weight:600;margin-bottom:6px}
.verdict .body{color:var(--muted);font-size:13px}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{padding:7px 10px;text-align:right;border-bottom:1px solid var(--line);white-space:nowrap}
th{color:var(--muted);font-weight:500;text-align:right;font-size:12px}
th:first-child,td:first-child{text-align:left}
tbody tr:hover{background:#fafbfc}
.tag{display:inline-block;padding:1px 7px;border-radius:20px;font-size:11px;
background:#eef2ff;color:#3730a3}
.tag.dom{background:#ecfdf5;color:#065f46}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px}
.kpi{background:#fbfcfd;border:1px solid var(--line);border-radius:10px;padding:12px 14px}
.kpi .k{color:var(--muted);font-size:12px}
.kpi .v{font-size:20px;font-weight:600;margin-top:2px}
.heat td{text-align:center;font-size:12px;padding:6px 4px;border:1px solid #fff}
.heat th{text-align:center}
.legend{display:flex;gap:16px;flex-wrap:wrap;font-size:12px;color:var(--muted);margin-top:10px}
.dot{display:inline-block;width:9px;height:9px;border-radius:50%;margin-right:5px}
footer{color:var(--muted);font-size:12px;text-align:center;margin-top:8px}
"""


def _esc(text: object) -> str:
    return html.escape(str(text), quote=True)


def _loss_color(loss: float) -> Tuple[str, str]:
    """丢包率 -> (背景, 文字)."""
    if loss <= 0.01:
        return "#ecfdf5", "#047857"
    if loss < 2:
        return "#fefce8", "#a16207"
    if loss < 5:
        return "#fff7ed", "#c2410c"
    if loss < 15:
        return "#fee2e2", "#b91c1c"
    return "#fecaca", "#7f1d1d"


def _segments(samples: Sequence[Sample], x0: float, y0: float, w: float, h: float,
              t_min: float, t_max: float, y_max: float, step: float) -> List[List[Tuple[float, float]]]:
    ordered = sorted(samples, key=lambda s: s.ts)
    out: List[List[Tuple[float, float]]] = []
    current: List[Tuple[float, float]] = []
    previous: Optional[float] = None
    for sample in ordered:
        if not sample.ok or sample.rtt_ms is None:
            if current:
                out.append(current)
                current = []
            previous = sample.ts
            continue
        if previous is not None and step > 0 and sample.ts - previous > step * 3 and current:
            out.append(current)
            current = []
        span = max(1e-6, t_max - t_min)
        x = x0 + (sample.ts - t_min) / span * w
        y = y0 + h - min(sample.rtt_ms / y_max, 1.0) * h
        current.append((x, y))
        previous = sample.ts
    if current:
        out.append(current)
    return out


def _chart(summaries: Sequence[Summary], per_target: Dict[str, List[Sample]],
           groups: Dict[str, str]) -> str:
    width, height = 960, 300
    left, right, top, bottom = 56, 16, 16, 34
    plot_w = width - left - right
    plot_h = height - top - bottom

    all_times: List[float] = []
    for item in summaries:
        all_times.extend(s.ts for s in per_target.get(item.target, []))
    if not all_times:
        return "<p class='sub'>没有采样数据</p>"
    t_min, t_max = min(all_times), max(all_times)
    if t_max - t_min < 1:
        t_max = t_min + 1

    y_max = max([s.rtt_p99 or 0 for s in summaries] + [10.0]) * 1.15

    parts: List[str] = []
    parts.append('<svg viewBox="0 0 %d %d" width="100%%" height="%d" role="img">' % (width, height, height))
    for y in range(0, int(y_max) + 1, max(1, int(y_max / 5))):
        yy = top + plot_h - (y / y_max) * plot_h
        parts.append(
            '<line x1="%d" y1="%.1f" x2="%d" y2="%.1f" stroke="#eef0f3" stroke-width="1"/>'
            % (left, yy, left + plot_w, yy)
        )
        parts.append(
            '<text x="%d" y="%.1f" font-size="10" fill="#9ca3af" text-anchor="end">%d</text>'
            % (left - 8, yy + 3, y)
        )

    for index, item in enumerate(summaries):
        color = PALETTE[index % len(PALETTE)]
        samples = per_target.get(item.target, [])
        step = estimate_interval(samples)
        for segment in _segments(samples, left, top, plot_w, plot_h, t_min, t_max, y_max, step):
            if len(segment) < 2:
                continue
            points = " ".join("%.1f,%.1f" % (x, y) for x, y in segment)
            parts.append(
                '<polyline fill="none" stroke="%s" stroke-width="1.6" stroke-linejoin="round" '
                'stroke-linecap="round" points="%s"/>' % (color, points)
            )
        for sample in samples:
            if not sample.ok:
                x = left + (sample.ts - t_min) / (t_max - t_min) * plot_w
                parts.append(
                    '<line x1="%.1f" y1="%d" x2="%.1f" y2="%d" stroke="#fca5a5" stroke-width="1"/>'
                    % (x, top, x, top + plot_h)
                )

    for fraction in (0.0, 0.5, 1.0):
        ts = t_min + (t_max - t_min) * fraction
        x = left + plot_w * fraction
        label = time.strftime("%H:%M:%S", time.localtime(ts))
        anchor = "start" if fraction == 0 else ("end" if fraction == 1 else "middle")
        parts.append(
            '<text x="%.1f" y="%d" font-size="10" fill="#9ca3af" text-anchor="%s">%s</text>'
            % (x, top + plot_h + 18, anchor, label)
        )
    parts.append("</svg>")

    legend = []
    for index, item in enumerate(summaries):
        color = PALETTE[index % len(PALETTE)]
        legend.append(
            '<span><i class="dot" style="background:%s"></i>%s %s</span>'
            % (color, _esc(item.target), _esc(groups.get(item.target, "overseas")))
        )
    legend.append('<span><i class="dot" style="background:#fca5a5"></i>红竖线 = 探测失败</span>')
    parts.append('<div class="legend">%s</div>' % "".join(legend))
    return "".join(parts)


def _heat_table(summaries: Sequence[Summary], per_target: Dict[str, List[Sample]]) -> str:
    buckets = hourly_summaries({s.target: per_target.get(s.target, []) for s in summaries})
    hours = sorted({h for per in buckets.values() for h in per})
    if not hours:
        return "<p class='sub'>样本不足，无法按时段聚合</p>"
    head = ["目标"] + ["%02d:00" % h for h in hours]
    rows = []
    for item in summaries:
        cells = ['<th style="text-align:left">%s</th>' % _esc(item.target)]
        for hour in hours:
            summary = buckets.get(item.target, {}).get(hour)
            if not summary or summary.sent == 0:
                cells.append("<td>-</td>")
                continue
            bg, fg = _loss_color(summary.loss_pct)
            text = "%.0f%%<br><span style='font-size:10px;opacity:.75'>%s</span>" % (
                summary.loss_pct,
                fmt_ms(summary.rtt_p50),
            )
            cells.append(
                "<td style='background:%s;color:%s'>%s</td>" % (bg, fg, text)
            )
        rows.append("<tr>%s</tr>" % "".join(cells))
    return (
        "<table class='heat'><thead><tr>%s</tr></thead><tbody>%s</tbody></table>"
        % ("".join("<th>%s</th>" % _esc(h) for h in head), "".join(rows))
    )


def render_html(
    summaries: Sequence[Summary],
    per_target: Dict[str, List[Sample]],
    verdict: Verdict,
    meta: Dict[str, str],
    groups: Optional[Dict[str, str]] = None,
) -> str:
    groups = groups or {}
    total_samples = sum(s.sent for s in summaries)
    total_loss = (
        sum(s.loss_pct * s.sent for s in summaries) / total_samples if total_samples else 0.0
    )
    worst = max(summaries, key=lambda s: s.rtt_p95 or 0, default=None)

    kpis = [
        ("样本总数", "%d" % total_samples),
        ("平均丢包率", "%.2f%%" % total_loss),
        ("最差 P95", "%s ms" % fmt_ms(worst.rtt_p95) if worst else "-"),
        ("最长断流", fmt_duration(max((s.longest_outage_s for s in summaries), default=0.0))),
    ]
    kpi_html = "".join(
        '<div class="kpi"><div class="k">%s</div><div class="v">%s</div></div>' % (_esc(k), _esc(v))
        for k, v in kpis
    )

    rows = []
    for item in summaries:
        tag_cls = "tag dom" if groups.get(item.target) == "domestic" else "tag"
        tag_txt = "境内" if groups.get(item.target) == "domestic" else "境外"
        rows.append(
            "<tr><td>%s</td><td><span class='%s'>%s</span></td><td>%d</td>"
            "<td>%.1f</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>"
            % (
                _esc(item.target),
                tag_cls,
                tag_txt,
                item.sent,
                item.loss_pct,
                fmt_ms(item.rtt_min),
                fmt_ms(item.rtt_p50),
                fmt_ms(item.rtt_p95),
                fmt_ms(item.rtt_p99),
                fmt_ms(item.jitter_ms),
                fmt_duration(item.longest_outage_s),
            )
        )

    meta_html = " · ".join("%s %s" % (_esc(k), _esc(v)) for k, v in meta.items())
    level = verdict.level if verdict.level in ("ok", "warn", "bad") else "warn"

    return """<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>netsteady 跨境链路报告 · %s</title>
<style>%s</style>
</head>
<body>
<div class="wrap">
  <h1>netsteady · 跨境链路稳定性报告</h1>
  <p class="sub">%s</p>

  <div class="card verdict %s">
    <div class="head">%s</div>
    <div class="body">%s</div>
  </div>

  <div class="card"><div class="grid">%s</div></div>

  <div class="card">
    <h2>目标概览</h2>
    <table><thead><tr>
      <th>目标</th><th>组别</th><th>样本</th><th>丢包%%</th><th>最小</th>
      <th>中位</th><th>P95</th><th>P99</th><th>抖动</th><th>最长断流</th>
    </tr></thead><tbody>%s</tbody></table>
  </div>

  <div class="card">
    <h2>延迟时线（ms）</h2>
    %s
  </div>

  <div class="card">
    <h2>分时段聚合（本地小时）</h2>
    %s
  </div>

  <footer>由 netsteady 生成 · 数据来自本机实测 · 仅供参考</footer>
</div>
</body>
</html>
""" % (
        _esc(meta.get("开始", "")),
        CSS,
        meta_html,
        level,
        _esc(verdict.headline),
        _esc(verdict.detail),
        kpi_html,
        "".join(rows),
        _chart(summaries, per_target, groups),
        _heat_table(summaries, per_target),
    )


def write_html(path: str, content: str) -> None:
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(content)
