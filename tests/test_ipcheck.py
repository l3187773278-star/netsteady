"""出口 IP 体检的离线测试（不依赖真实网络）."""

import json
import unittest

from netsteady.ipcheck import (
    Check,
    IpReport,
    ServiceResult,
    _network_verdict,
    _plain_ip,
    _score,
    _trace_ip,
    classify_service,
    render_json,
)
from netsteady.net import HttpResponse


def response(status=200, body="", ok=True, error=None):
    return HttpResponse(ok=ok, status=status, body=body, elapsed_ms=12.0, error=error)


class ParsingTest(unittest.TestCase):
    def test_plain_ip(self):
        self.assertEqual(_plain_ip("203.0.113.7\n"), "203.0.113.7")
        self.assertIsNone(_plain_ip("<html>oops</html>"))

    def test_cloudflare_trace(self):
        body = "fl=1a2b\nh=cloudflare.com\nip=203.0.113.7\nts=1234\nloc=US\n"
        self.assertEqual(_trace_ip(body), "203.0.113.7")
        self.assertIsNone(_trace_ip("no ip here"))


class ClassifyTest(unittest.TestCase):
    def test_401_means_reachable(self):
        result = classify_service("claude", response(401, '{"error":"missing key"}'))
        self.assertEqual(result.state, "reachable")

    def test_region_block_detected(self):
        result = classify_service("claude", response(403, "This service is not available in your region"))
        self.assertEqual(result.state, "blocked")

    def test_openai_country_marker(self):
        result = classify_service("openai", response(403, '{"error":"unsupported_country"}'))
        self.assertEqual(result.state, "blocked")

    def test_403_without_marker_is_challenge(self):
        result = classify_service("openai", response(403, "just a moment"))
        self.assertEqual(result.state, "challenge")

    def test_transport_failure(self):
        result = classify_service("openai", response(0, "", ok=False, error="URLError: timed out"))
        self.assertEqual(result.state, "unreachable")
        self.assertIn("timed out", result.detail)

    def test_500_is_unknown(self):
        result = classify_service("openai", response(500, "boom"))
        self.assertEqual(result.state, "unknown")


class ScoreTest(unittest.TestCase):
    def test_all_fail_is_zero(self):
        checks = [Check("a", "甲", "fail", "", 25.0, 0.0), Check("b", "乙", "fail", "", 25.0, 0.0)]
        self.assertEqual(_score(checks), 0)

    def test_skips_are_normalized_away(self):
        checks = [Check("a", "甲", "ok", "", 25.0, 25.0), Check("b", "乙", "skip", "", 25.0, None)]
        self.assertEqual(_score(checks), 100)

    def test_partial(self):
        checks = [Check("a", "甲", "ok", "", 10.0, 10.0), Check("b", "乙", "warn", "", 10.0, 5.0)]
        self.assertEqual(_score(checks), 75)

    def test_all_skipped_is_zero(self):
        self.assertEqual(_score([Check("a", "甲", "skip", "", 10.0, None)]), 0)


class NetworkTypeTest(unittest.TestCase):
    def test_hosting_flag(self):
        report = IpReport(hosting=True)
        kind, points, _ = _network_verdict(report)
        self.assertEqual(kind, "datacenter")
        self.assertLess(points, 10)

    def test_mobile_wins(self):
        report = IpReport(mobile=True, hosting=True)
        self.assertEqual(_network_verdict(report)[0], "mobile")

    def test_proxy_flag(self):
        self.assertEqual(_network_verdict(IpReport(proxy=True))[0], "proxy")

    def test_residential_by_default(self):
        report = IpReport(org="Comcast Cable Communications")
        self.assertEqual(_network_verdict(report)[0], "residential")

    def test_keyword_in_org(self):
        self.assertEqual(_network_verdict(IpReport(org="DigitalOcean LLC"))[0], "datacenter")


class JsonTest(unittest.TestCase):
    def test_render_json_is_valid(self):
        report = IpReport(egress_ip="203.0.113.7", country="United States", score=59)
        report.checks.append(Check("egress", "出口", "ok", "一致", 10.0, 10.0))
        report.services.append(ServiceResult("claude", "Claude", "reachable", "ok", 401, 88.0))
        payload = json.loads(render_json(report))
        self.assertEqual(payload["egress_ip"], "203.0.113.7")
        self.assertEqual(payload["score"], 59)
        self.assertEqual(payload["checks"][0]["key"], "egress")


if __name__ == "__main__":
    unittest.main()
