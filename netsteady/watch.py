"""持续监测主循环：并发探测、实时表格、JSONL 落盘."""

from __future__ import annotations

import json
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, TextIO

from . import html_report
from .model import Sample, Target
from .net import tcp_probe
from .report import GREEN, RED, RESET, YELLOW, fmt_duration, fmt_ms, summary_table
from .stats import Summary, Verdict, build_verdict, percentile, summarize

SPARK = "▁▂▃▄▅▆▇█"


def sparkline(values: Sequence[float]) -> str:
    if not values:
        return ""
    low, high = min(values), max(values)
    if high - low < 1e-9:
        return SPARK[0] * len(values)
    step = len(SPARK) - 1
    return "".join(SPARK[int((value - low) / (high - low) * step)] for value in values)


class LiveTable:
    """原地重绘的实时表格；非 TTY 时自动退化为逐轮输出."""

    def __init__(self, stream: TextIO, enabled: bool = True) -> None:
        self.stream = stream
        self.enabled = bool(enabled) and bool(getattr(stream, "isatty", lambda: False)())
        self.drawn = 0

    def draw(self, lines: List[str]) -> None:
        if not self.enabled:
            return
        if self.drawn:
            self.stream.write("\033[%dA" % self.drawn)
        for line in lines:
            self.stream.write("\033[2K" + line + "\n")
        self.drawn = len(lines)
        self.stream.flush()

    def finish(self) -> None:
        if self.enabled and self.drawn:
            self.stream.write("\n")
            self.stream.flush()


@dataclass
class RunResult:
    samples: Dict[str, List[Sample]] = field(default_factory=dict)
    summaries: List[Summary] = field(default_factory=list)
    verdict: Optional[Verdict] = None
    started: float = 0.0
    ended: float = 0.0
    rounds: int = 0
    interrupted: bool = False
    interval: float = 0.0


def _probe_round(targets: Sequence[Target], pool: ThreadPoolExecutor, timeout: float) -> List[Sample]:
    started = time.time()
    futures = [pool.submit(tcp_probe, t.host, t.port, timeout) for t in targets]
    samples = []
    for target, future in zip(targets, futures):
        try:
            ok, rtt, error = future.result()
        except Exception as exc:  # 理论上不会，兜底防止一轮崩掉
            ok, rtt, error = False, None, "%s: %s" % (type(exc).__name__, exc)
        samples.append(Sample(ts=time.time(), target=target.name, ok=ok, rtt_ms=rtt, error=error))
    del started
    return samples


def run(
    targets: Sequence[Target],
    interval: float = 2.0,
    duration: Optional[float] = None,
    timeout: float = 3.0,
    jsonl_path: Optional[str] = None,
    live: bool = True,
    stream: Optional[TextIO] = None,
    quiet: bool = False,
) -> RunResult:
    stream = stream or sys.stdout
    result = RunResult(started=time.time(), interval=interval)
    for target in targets:
        result.samples[target.name] = []

    handle = None
    if jsonl_path:
        directory = os.path.dirname(os.path.abspath(jsonl_path))
        if directory:
            os.makedirs(directory, exist_ok=True)
        handle = open(jsonl_path, "a", encoding="utf-8")

    table = LiveTable(stream, enabled=live and not quiet)
    workers = max(1, min(len(targets), 32))

    try:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            next_at = time.time()
            while True:
                now = time.time()
                if duration is not None and now - result.started >= duration:
                    break
                if now < next_at:
                    time.sleep(min(next_at - now, 0.2))
                    continue

                samples = _probe_round(targets, pool, timeout)
                result.rounds += 1
                for sample in samples:
                    result.samples[sample.target].append(sample)
                    if handle is not None:
                        handle.write(json.dumps(sample.as_dict(), ensure_ascii=False) + "\n")

                if handle is not None:
                    handle.flush()

                if not quiet:
                    table.draw(
                        _render_live(
                            targets, result, interval, duration, bool(getattr(stream, "isatty", lambda: False)())
                        )
                    )

                next_at += interval
                if next_at < time.time() - interval:
                    next_at = time.time()
    except KeyboardInterrupt:
        result.interrupted = True
        if not quiet:
            stream.write("\n^C 收到中断，正在汇总...\n")
    finally:
        if handle is not None:
            handle.close()
        table.finish()
        result.ended = time.time()

    result.summaries = [summarize(result.samples[t.name]) for t in targets]
    overseas = [s for s in result.summaries if _group_of(targets, s.target) != "domestic"]
    domestic = [s for s in result.summaries if _group_of(targets, s.target) == "domestic"]
    result.verdict = build_verdict(overseas, domestic)
    return result


def _group_of(targets: Sequence[Target], name: str) -> str:
    for target in targets:
        if target.name == name:
            return target.group
    return "custom"


def _render_live(
    targets: Sequence[Target],
    result: RunResult,
    interval: float,
    duration: Optional[float],
    use_color: bool = False,
) -> List[str]:
    elapsed = time.time() - result.started
    clock = "%s" % fmt_duration(elapsed)
    if duration:
        clock += " / %s" % fmt_duration(duration)
    header = " netsteady  %s  第 %d 轮  间隔 %gs  Ctrl+C 结束" % (clock, result.rounds, interval)
    title = " %-22s %8s %7s %7s  %s" % ("目标", "当前", "丢包%", "P95", "趋势")
    lines = [header, title]

    for target in targets:
        samples = result.samples[target.name]
        rtts = [s.rtt_ms for s in samples if s.ok and s.rtt_ms is not None]
        last = samples[-1] if samples else None
        loss = (len(samples) - len(rtts)) / len(samples) * 100.0 if samples else 0.0
        p95 = percentile([float(r) for r in rtts], 95)
        name = "%s:%d" % (target.host, target.port)
        if len(name) > 22:
            name = name[:21] + "."

        if last is None:
            state = "-"
        elif last.ok:
            state = fmt_ms(last.rtt_ms) + "ms"
        else:
            state = "超时"
        tint = ""
        if use_color and loss >= 5:
            tint = RED
        elif use_color and loss > 0:
            tint = YELLOW
        spark = sparkline([float(v) for v in rtts[-24:]])
        line = " %-22s %6s %6.1f %7s  %s" % (name, state, loss, fmt_ms(p95), spark)
        if tint:
            line = tint + line + RESET
        lines.append(line)
    lines.append("")
    return lines


def finalize(
    targets: Sequence[Target],
    result: RunResult,
    stream: Optional[TextIO] = None,
    html_path: Optional[str] = None,
    csv_path: Optional[str] = None,
    text_path: Optional[str] = None,
) -> str:
    from .report import render_text_report, write_csv

    stream = stream or sys.stdout
    groups = {t.name: t.group for t in targets}
    meta = {
        "开始": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(result.started)),
        "结束": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(result.ended)),
        "持续": fmt_duration(result.ended - result.started),
        "探测间隔": "%gs" % result.interval,
        "样本总数": str(sum(s.sent for s in result.summaries)),
    }
    text = render_text_report(result.summaries, result.samples, result.verdict, meta, groups)

    if text_path:
        with open(text_path, "w", encoding="utf-8") as handle:
            handle.write(text + "\n")
    if csv_path:
        write_csv(csv_path, result.summaries, groups)
    if html_path:
        content = html_report.render_html(
            result.summaries, result.samples, result.verdict, meta, groups
        )
        html_report.write_html(html_path, content)

    stream.write(text + "\n")
    return text
