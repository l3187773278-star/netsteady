"""暴露面检查的离线测试（纯逻辑部分，不依赖真实网络）."""

import json
import unittest

from netsteady.leak import (
    LeakCheck,
    LeakReport,
    _wrap,
    check_colo,
    check_dns,
    check_timezone,
    local_offset_hours,
    render_json,
    render_text,
)


class TimezoneTest(unittest.TestCase):
    def test_cn_offset_with_us_ip_is_a_leak(self):
        check = check_timezone("United States", 8.0, "zh_CN")
        self.assertEqual(check.status, "leak")
        self.assertEqual(check.severity, "medium")
        self.assertIn("UTC+8", check.detail)

    def test_windows_style_chinese_locale(self):
        check = check_timezone("United States", 8.0, "Chinese (Simplified)_China")
        self.assertEqual(check.status, "leak")

    def test_matching_offset_and_language_is_clean(self):
        check = check_timezone("United States", -7.0, "en-US")
        self.assertEqual(check.status, "clean")
        self.assertEqual(check.severity, "ok")

    def test_offset_only_is_suspicious(self):
        check = check_timezone("United States", 8.0, "en-US")
        self.assertEqual(check.status, "suspicious")
        self.assertEqual(check.severity, "low")

    def test_language_only_is_suspicious(self):
        check = check_timezone("Japan", 9.0, "zh_CN")
        self.assertEqual(check.status, "suspicious")

    def test_unknown_country_skips(self):
        self.assertEqual(check_timezone("Narnia", 8.0, "zh_CN").status, "skip")

    def test_missing_offset_skips(self):
        self.assertEqual(check_timezone("United States", None, "zh_CN").status, "skip")

    def test_local_offset_reads_something(self):
        offset = local_offset_hours()
        self.assertTrue(offset is None or -12 <= offset <= 14)


class DnsTest(unittest.TestCase):
    def test_same_country_is_clean(self):
        check = check_dns("1.2.3.4", "United States - Cloudflare", "United States")
        self.assertEqual(check.status, "clean")

    def test_mismatch_is_suspicious(self):
        check = check_dns("1.2.3.4", "Japan - Google LLC", "United States")
        self.assertEqual(check.status, "suspicious")
        self.assertEqual(check.severity, "medium")

    def test_unknown_geo_skips(self):
        self.assertEqual(check_dns("1.2.3.4", None, "United States").status, "skip")


class ColoTest(unittest.TestCase):
    def test_colo_is_informational(self):
        check = check_colo("LAX", "United States")
        self.assertEqual(check.severity, "info")
        self.assertIn("LAX", check.detail)

    def test_missing_colo_skips(self):
        self.assertEqual(check_colo(None, "United States").status, "skip")


class ReportTest(unittest.TestCase):
    def _report(self, checks):
        report = LeakReport(egress_ipv4="203.0.113.7", egress_country="United States")
        report.checks.extend(checks)
        return report

    def test_high_severity_leak_raises_level(self):
        report = self._report(
            [LeakCheck("ipv6", "IPv6", "high", "leak", "x"), LeakCheck("tz", "时区", "low", "clean", "y")]
        )
        self.assertEqual(report.risk_level, "high")

    def test_medium_leak_is_medium(self):
        report = self._report([LeakCheck("tz", "时区", "low", "suspicious", "x")])
        self.assertEqual(report.risk_level, "medium")

    def test_all_clean_is_low(self):
        report = self._report([LeakCheck("tz", "时区", "low", "clean", "x")])
        self.assertEqual(report.risk_level, "low")

    def test_sorted_checks_put_severe_first(self):
        report = self._report(
            [
                LeakCheck("a", "低", "low", "clean", "x"),
                LeakCheck("b", "高", "high", "leak", "x"),
                LeakCheck("c", "中", "medium", "suspicious", "x"),
            ]
        )
        self.assertEqual([c.key for c in report.sorted_checks()], ["b", "c", "a"])

    def test_json_roundtrip(self):
        report = self._report([LeakCheck("tz", "时区", "medium", "leak", "说明", "建议")])
        payload = json.loads(render_json(report))
        self.assertEqual(payload["egress_ipv4"], "203.0.113.7")
        self.assertEqual(payload["risk_level"], "medium")
        self.assertEqual(payload["checks"][0]["advice"], "建议")

    def test_render_text_mentions_the_caveat(self):
        text = render_text(self._report([LeakCheck("tz", "时区", "medium", "leak", "说明", "建议")]))
        self.assertIn("不等于这个 IP 就是纯净的", text)


class WrapTest(unittest.TestCase):
    def test_wraps_long_chinese(self):
        lines = _wrap("一" * 100, 20)
        self.assertTrue(all(len(line) <= 21 for line in lines))

    def test_empty_input(self):
        self.assertEqual(_wrap("", 20), [""])


if __name__ == "__main__":
    unittest.main()
