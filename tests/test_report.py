"""报告渲染的离线测试."""

import csv
import os
import tempfile
import unittest

from netsteady.model import Sample
from netsteady.report import (
    display_width,
    fmt_duration,
    fmt_ms,
    pad,
    render_text_report,
    summary_table,
    write_csv,
)
from netsteady.stats import Summary, Verdict


def make_summary(target="us", group="overseas", loss=0.0):
    return Summary(
        target=target,
        sent=10,
        ok=10,
        loss_pct=loss,
        rtt_min=10.0,
        rtt_avg=12.0,
        rtt_p50=12.0,
        rtt_p95=15.0,
        rtt_p99=18.0,
        rtt_max=20.0,
        jitter_ms=1.5,
    )


class WidthTest(unittest.TestCase):
    def test_cjk_counts_double(self):
        self.assertEqual(display_width("abc"), 3)
        self.assertEqual(display_width("境外"), 4)

    def test_pad_aligns_by_display_width(self):
        self.assertEqual(display_width(pad("境外", 8)), 8)
        self.assertEqual(display_width(pad("abc", 8, "right")), 8)


class FormatTest(unittest.TestCase):
    def test_duration(self):
        self.assertEqual(fmt_duration(45), "45s")
        self.assertEqual(fmt_duration(125), "2m05s")
        self.assertEqual(fmt_duration(3700), "1h01m")

    def test_ms(self):
        self.assertEqual(fmt_ms(None), "-")
        self.assertEqual(fmt_ms(12.4), "12")
        self.assertEqual(fmt_ms(2500), "2.5s")


class TableTest(unittest.TestCase):
    def test_summary_table_contains_targets(self):
        table = summary_table([make_summary("1.1.1.1:443")], {"1.1.1.1:443": "overseas"})
        self.assertIn("1.1.1.1:443", table)
        self.assertIn("境外", table)
        self.assertIn("丢包", table)

    def test_rows_are_aligned(self):
        table = summary_table([make_summary("a"), make_summary("bbbbbbbb")])
        lengths = {display_width(line) for line in table.splitlines()[2:]}
        self.assertEqual(len(lengths), 1)

    def test_text_report_has_verdict(self):
        verdict = Verdict("ok", "一切正常", "细节")
        report = render_text_report(
            [make_summary()],
            {"us": [Sample(ts=0, target="us", ok=True, rtt_ms=12.0)]},
            verdict,
            {"开始": "18:00:00", "样本总数": "10"},
            {"us": "overseas"},
        )
        self.assertIn("跨境网络稳定性报告", report)
        self.assertIn("一切正常", report)
        self.assertIn("[ OK ]", report)


class CsvTest(unittest.TestCase):
    def test_writes_header_and_row(self):
        handle = tempfile.NamedTemporaryFile("w", suffix=".csv", delete=False, encoding="utf-8")
        handle.close()
        try:
            write_csv(handle.name, [make_summary("1.1.1.1:443")], {"1.1.1.1:443": "overseas"})
            with open(handle.name, "r", encoding="utf-8-sig", newline="") as reader:
                rows = list(csv.reader(reader))
        finally:
            os.unlink(handle.name)
        self.assertEqual(rows[0][0], "target")
        self.assertEqual(rows[1][0], "1.1.1.1:443")
        self.assertEqual(rows[1][1], "overseas")


if __name__ == "__main__":
    unittest.main()
