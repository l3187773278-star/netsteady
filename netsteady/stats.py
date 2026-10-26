"""统计与判定.

所有函数都是纯函数，不碰网络，方便离线单元测试。
"""

from __future__ import annotations

import math
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence

from .model import Sample

# 判定阈值：低于这些值算正常，高于算劣化。
UNSTABLE_LOSS_PCT = 5.0
UNSTABLE_P95_FACTOR = 2.0
UNSTABLE_P95_MIN_DELTA_MS = 40.0
# 尾延迟要同时超过中位数的 2 倍、且多出 40ms 以上，才算劣化。
# 只按倍数判断，会在 10ms 的链路上把 21ms 也误判为劣化。


def percentile(values: Sequence[float], p: float) -> Optional[float]:
    """线性插值分位数（与 numpy 默认行为一致）."""
    if not values:
        return None
    ordered = sorted(values)
    if len(ordered) == 1:
        return float(ordered[0])
    rank = (len(ordered) - 1) * (p / 100.0)
    low = int(math.floor(rank))
    high = int(math.ceil(rank))
    if low == high:
        return float(ordered[low])
    return float(ordered[low] * (high - rank) + ordered[high] * (rank - low))


def median(values: Sequence[float]) -> Optional[float]:
    return percentile(values, 50.0)


@dataclass
class Outage:
    """一段连续失败."""

    start: float
    end: float
    samples: int

    @property
    def duration_s(self) -> float:
        return max(0.0, self.end - self.start)


@dataclass
class Summary:
    target: str
    sent: int = 0
    ok: int = 0
    loss_pct: float = 0.0
    rtt_min: Optional[float] = None
    rtt_avg: Optional[float] = None
    rtt_p50: Optional[float] = None
    rtt_p95: Optional[float] = None
    rtt_p99: Optional[float] = None
    rtt_max: Optional[float] = None
    jitter_ms: Optional[float] = None
    outages: List[Outage] = field(default_factory=list)
    span_s: float = 0.0

    @property
    def availability_pct(self) -> float:
        return 100.0 - self.loss_pct

    @property
    def longest_outage_s(self) -> float:
        return max((o.duration_s for o in self.outages), default=0.0)

    def tail_value(self):
        """命中的尾延迟指标，返回 (名称, 毫秒) 或 None。"""
        for name, value in (("P95", self.rtt_p95), ("P99", self.rtt_p99)):
            if value is None or self.rtt_p50 is None:
                continue
            if (
                value >= self.rtt_p50 * UNSTABLE_P95_FACTOR
                and value - self.rtt_p50 >= UNSTABLE_P95_MIN_DELTA_MS
            ):
                return name, value
        return None

    @property
    def unstable(self) -> bool:
        if self.sent == 0:
            return False
        if self.loss_pct >= UNSTABLE_LOSS_PCT:
            return True
        return self.tail_value() is not None

    def reason(self) -> str:
        bits = []
        if self.loss_pct >= UNSTABLE_LOSS_PCT:
            bits.append("丢包 %.1f%%" % self.loss_pct)
        hit = self.tail_value()
        if hit is not None:
            bits.append("尾延迟 %s %.0fms（中位 %.0fms）" % (hit[0], hit[1], self.rtt_p50))
        return "，".join(bits)


def estimate_interval(samples: Sequence[Sample]) -> float:
    """从采样间隔推断一个探测周期的秒数."""
    ordered = sorted(samples, key=lambda s: s.ts)
    diffs = [b.ts - a.ts for a, b in zip(ordered, ordered[1:]) if b.ts > a.ts]
    med = median(diffs)
    return float(med) if med is not None else 0.0


def find_outages(samples: Sequence[Sample], interval: Optional[float] = None) -> List[Outage]:
    """找出所有连续失败区间，用采样间隔把结束时间补齐."""
    ordered = sorted(samples, key=lambda s: s.ts)
    if not ordered:
        return []
    step = interval if interval and interval > 0 else estimate_interval(ordered)
    step = step if step > 0 else 0.0

    outages = []
    start = None
    last = None
    count = 0
    for sample in ordered:
        if not sample.ok:
            if start is None:
                start, last, count = sample.ts, sample.ts, 1
            else:
                last, count = sample.ts, count + 1
        else:
            if start is not None and last is not None:
                outages.append(Outage(start=start, end=last + step, samples=count))
            start, last, count = None, None, 0
    if start is not None and last is not None:
        outages.append(Outage(start=start, end=last + step, samples=count))
    return outages


def summarize(samples: Sequence[Sample]) -> Summary:
    """对单个目标的采样做完整统计."""
    ordered = sorted(samples, key=lambda s: s.ts)
    if not ordered:
        return Summary(target="")
    target = ordered[0].target
    sent = len(ordered)
    ok = sum(1 for s in ordered if s.ok)
    seq = [float(s.rtt_ms) for s in ordered if s.ok and s.rtt_ms is not None]
    interval = estimate_interval(ordered)

    jitter = None
    if len(seq) >= 2:
        deltas = [abs(b - a) for a, b in zip(seq, seq[1:])]
        jitter = sum(deltas) / len(deltas)

    return Summary(
        target=target,
        sent=sent,
        ok=ok,
        loss_pct=(sent - ok) / sent * 100.0 if sent else 0.0,
        rtt_min=min(seq) if seq else None,
        rtt_avg=sum(seq) / len(seq) if seq else None,
        rtt_p50=percentile(seq, 50),
        rtt_p95=percentile(seq, 95),
        rtt_p99=percentile(seq, 99),
        rtt_max=max(seq) if seq else None,
        jitter_ms=jitter,
        outages=find_outages(ordered, interval),
        span_s=(ordered[-1].ts - ordered[0].ts) if sent > 1 else 0.0,
    )


def bucket_by_hour(samples: Sequence[Sample]) -> Dict[int, List[Sample]]:
    """按本地时间的整点分桶."""
    buckets = {}
    for sample in samples:
        hour = time.localtime(sample.ts).tm_hour
        buckets.setdefault(hour, []).append(sample)
    return buckets


def hourly_summaries(per_target: Dict[str, Sequence[Sample]]) -> Dict[str, Dict[int, Summary]]:
    """每个目标 × 每个小时桶的统计."""
    result = {}
    for target, samples in per_target.items():
        buckets = bucket_by_hour(samples)
        result[target] = {hour: summarize(items) for hour, items in sorted(buckets.items())}
    return result


@dataclass
class Verdict:
    level: str  # ok | warn | bad
    headline: str
    detail: str


def build_verdict(overseas: Sequence[Summary], domestic: Sequence[Summary]) -> Verdict:
    """用境内对照组当基线，判断问题出在哪一层."""
    dom_bad = [s for s in domestic if s.unstable]
    ovs_bad = [s for s in overseas if s.unstable]

    if not overseas:
        return Verdict("warn", "没有境外目标", "至少需要一个境外目标才能判断跨境链路。")

    if dom_bad:
        names = "、".join(s.target for s in dom_bad)
        return Verdict(
            "bad",
            "本地网络异常（境内目标也在丢包或抖动）",
            "境内对照组 %s 同时劣化，问题大概率在你本机、局域网或运营商接入段，"
            "与跨境链路无关。先排查本地：换网线、重启光猫、确认没有人占满上行带宽。" % names,
        )

    if len(ovs_bad) >= 2:
        names = "、".join(s.target for s in ovs_bad)
        return Verdict(
            "bad",
            "跨境链路劣化（境内正常，境外多目标同时异常）",
            "境外目标 %s 同时劣化而境内对照组正常，典型特征是国际出口拥塞或"
            "跨境路由抖动，通常集中在 20:00 到 24:00 的晚高峰。" % names,
        )

    if len(ovs_bad) == 1:
        item = ovs_bad[0]
        return Verdict(
            "warn",
            "单目标异常（疑似目标侧问题）",
            "只有 %s 劣化（%s），其余境外目标正常，更像是该目标自身限流、"
            "就近调度或对该段路由不友好，不能据此认定跨境链路有问题。"
            % (item.target, item.reason()),
        )

    return Verdict(
        "ok",
        "跨境链路稳定",
        "所有境外目标丢包率均低于 %.0f%%，尾延迟未见明显抬升，境内对照组正常。"
        % UNSTABLE_LOSS_PCT,
    )
