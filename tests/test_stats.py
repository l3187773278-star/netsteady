"""统计与判定逻辑的离线单元测试（不碰网络）."""

import unittest

from netsteady.model import Sample
from netsteady.stats import (
    Summary,
    Outage,
    build_verdict,
    bucket_by_hour,
    find_outages,
    percentile,
    summarize,
)


def sample(ts, ok=True, rtt=10.0, target="t"):
    return Sample(ts=ts, target=target, ok=ok, rtt_ms=rtt if ok else None)


class PercentileTest(unittest.TestCase):
    def test_empty(self):
        self.assertIsNone(percentile([], 50))

    def test_single(self):
        self.assertEqual(percentile([7.0], 99), 7.0)

    def test_interpolates(self):
        self.assertAlmostEqual(percentile([1, 2, 3, 4], 50), 2.5)
        self.assertAlmostEqual(percentile([1, 2, 3, 4], 0), 1.0)
        self.assertAlmostEqual(percentile([1, 2, 3, 4], 100), 4.0)

    def test_p95_tail(self):
        values = [float(i) for i in range(1, 101)]
        self.assertGreater(percentile(values, 95), 94.0)
        self.assertLessEqual(percentile(values, 95), 96.0)


class SummarizeTest(unittest.TestCase):
    def test_loss_rate(self):
        samples = [sample(0), sample(1), sample(2), sample(3, ok=False)]
        summary = summarize(samples)
        self.assertEqual(summary.sent, 4)
        self.assertEqual(summary.ok, 3)
        self.assertAlmostEqual(summary.loss_pct, 25.0)

    def test_rtt_stats(self):
        samples = [sample(i, rtt=v) for i, v in enumerate([10, 12, 14, 16])]
        summary = summarize(samples)
        self.assertAlmostEqual(summary.rtt_min, 10.0)
        self.assertAlmostEqual(summary.rtt_max, 16.0)
        self.assertAlmostEqual(summary.rtt_avg, 13.0)

    def test_jitter_is_mean_absolute_delta(self):
        samples = [sample(i, rtt=v) for i, v in enumerate([10, 12, 10])]
        summary = summarize(samples)
        self.assertAlmostEqual(summary.jitter_ms, 2.0)

    def test_jitter_needs_two_points(self):
        self.assertIsNone(summarize([sample(0)]).jitter_ms)

    def test_unstable_by_loss(self):
        samples = [sample(i, ok=(i % 10 == 0)) for i in range(20)]
        self.assertTrue(summarize(samples).unstable)

    def test_stable_short_link(self):
        samples = [sample(i, rtt=10.0 + (i % 3)) for i in range(20)]
        self.assertFalse(summarize(samples).unstable)

    def test_tail_latency_counts_as_unstable(self):
        samples = [sample(i, rtt=10.0) for i in range(19)]
        samples.append(sample(19, rtt=90.0))
        self.assertTrue(summarize(samples).unstable)

    def test_reason_mentions_loss(self):
        samples = [sample(i, ok=(i % 2 == 0)) for i in range(10)]
        self.assertIn("丢包", summarize(samples).reason())


class OutageTest(unittest.TestCase):
    def test_detects_single_outage(self):
        samples = [sample(0), sample(1, ok=False), sample(2, ok=False), sample(3)]
        outages = find_outages(samples)
        self.assertEqual(len(outages), 1)
        self.assertAlmostEqual(outages[0].duration_s, 2.0)
        self.assertEqual(outages[0].samples, 2)

    def test_outage_at_tail(self):
        samples = [sample(0), sample(1, ok=False)]
        outages = find_outages(samples, interval=1.0)
        self.assertEqual(len(outages), 1)
        self.assertAlmostEqual(outages[0].duration_s, 1.0)

    def test_no_outage_when_all_ok(self):
        self.assertEqual(find_outages([sample(0), sample(1)]), [])

    def test_longest_outage_property(self):
        summary = Summary(
            target="t",
            sent=10,
            ok=5,
            loss_pct=50.0,
            outages=[Outage(0, 1, 1), Outage(5, 9, 4)],
        )
        self.assertAlmostEqual(summary.longest_outage_s, 4.0)


class VerdictTest(unittest.TestCase):
    def _summary(self, target, loss=0.0, p50=20.0, p95=25.0):
        return Summary(target=target, sent=10, ok=10, loss_pct=loss, rtt_p50=p50, rtt_p95=p95)

    def test_healthy(self):
        verdict = build_verdict([self._summary("us")], [self._summary("cn")])
        self.assertEqual(verdict.level, "ok")

    def test_domestic_breakage_short_circuits(self):
        verdict = build_verdict(
            [self._summary("us")],
            [self._summary("cn", loss=40.0)],
        )
        self.assertEqual(verdict.level, "bad")
        self.assertIn("本地", verdict.headline)

    def test_multi_target_cross_border(self):
        verdict = build_verdict(
            [self._summary("us", loss=30.0), self._summary("jp", loss=20.0)],
            [self._summary("cn")],
        )
        self.assertEqual(verdict.level, "bad")
        self.assertIn("跨境", verdict.headline)

    def test_single_target_is_target_side(self):
        verdict = build_verdict(
            [self._summary("us", loss=30.0), self._summary("jp")],
            [self._summary("cn")],
        )
        self.assertEqual(verdict.level, "warn")
        self.assertIn("单目标", verdict.headline)

    def test_no_overseas(self):
        self.assertEqual(build_verdict([], [self._summary("cn")]).level, "warn")


class BucketTest(unittest.TestCase):
    def test_bucket_by_hour_groups(self):
        samples = [sample(0), sample(3600), sample(7200)]
        buckets = bucket_by_hour(samples)
        self.assertEqual(sum(len(v) for v in buckets.values()), 3)


if __name__ == "__main__":
    unittest.main()
