"""出口 IP 体检的离线测试（不依赖真实网络）."""

import json
import unittest

from netsteady.ipcheck import (
    REGION_MARKERS,
    Check,
    IpReport,
    ServiceResult,
    _network_verdict,
    _plain_ip,
    _score,
    _trace_ip,
    _verdict_line,
    classify,
    is_fake_ip,
    render_json,
    render_text,
)
from netsteady.net import HttpResponse


def response(status=200, body="", ok=True, error=None, headers=None):
    return HttpResponse(
        ok=ok,
        status=status,
        body=body,
        elapsed_ms=12.0,
        error=error,
        headers=headers or {},
    )


class ParsingTest(unittest.TestCase):
    def test_plain_ip(self):
        self.assertEqual(_plain_ip("203.0.113.7\n"), "203.0.113.7")
        self.assertIsNone(_plain_ip("<html>oops</html>"))

    def test_cloudflare_trace(self):
        body = "fl=1a2b\nh=cloudflare.com\nip=203.0.113.7\nts=1234\nloc=US\n"
        self.assertEqual(_trace_ip(body), "203.0.113.7")
        self.assertIsNone(_trace_ip("no ip here"))


class FakeIpTest(unittest.TestCase):
    def test_detects_clash_range(self):
        self.assertTrue(is_fake_ip("198.18.0.35"))
        self.assertTrue(is_fake_ip("198.19.255.1"))

    def test_leaves_real_addresses_alone(self):
        self.assertFalse(is_fake_ip("198.20.0.1"))
        self.assertFalse(is_fake_ip("8.8.8.8"))
        self.assertFalse(is_fake_ip("not-an-ip"))


class ClassifyTest(unittest.TestCase):
    def test_401_means_reachable(self):
        state, detail = classify(REGION_MARKERS, response(401, '{"error":"missing key"}'))
        self.assertEqual(state, "ok")
        self.assertIn("受理", detail)

    def test_region_marker_is_blocked(self):
        state, _ = classify(
            REGION_MARKERS, response(403, "This service is not available in your region")
        )
        self.assertEqual(state, "blocked")

    def test_unsupported_country_marker(self):
        state, _ = classify(REGION_MARKERS, response(403, '{"error":"unsupported_country"}'))
        self.assertEqual(state, "blocked")

    def test_cloudflare_challenge_detected_by_header(self):
        state, detail = classify(
            REGION_MARKERS,
            response(403, "", headers={"cf-mitigated": "challenge"}),
        )
        self.assertEqual(state, "challenge")
        self.assertIn("Cloudflare", detail)

    def test_cloudflare_challenge_detected_by_body(self):
        state, _ = classify(REGION_MARKERS, response(403, "<title>Just a moment...</title>"))
        self.assertEqual(state, "challenge")

    def test_plain_403_is_challenge(self):
        state, _ = classify(REGION_MARKERS, response(403, "nope"))
        self.assertEqual(state, "challenge")

    def test_transport_failure(self):
        state, detail = classify(
            REGION_MARKERS, response(0, "", ok=False, error="URLError: timed out")
        )
        self.assertEqual(state, "unreachable")
        self.assertIn("timed out", detail)

    def test_200_is_ok(self):
        self.assertEqual(classify(REGION_MARKERS, response(200, "hello"))[0], "ok")

    def test_500_is_unknown(self):
        self.assertEqual(classify(REGION_MARKERS, response(500, "boom"))[0], "unknown")


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
        kind, points, _ = _network_verdict(IpReport(hosting=True))
        self.assertEqual(kind, "datacenter")
        self.assertLess(points, 10)

    def test_mobile_wins(self):
        self.assertEqual(_network_verdict(IpReport(mobile=True, hosting=True))[0], "mobile")

    def test_proxy_flag(self):
        self.assertEqual(_network_verdict(IpReport(proxy=True))[0], "proxy")

    def test_residential_by_default(self):
        report = IpReport(org="Comcast Cable Communications")
        self.assertEqual(_network_verdict(report)[0], "residential")

    def test_keyword_in_org(self):
        self.assertEqual(_network_verdict(IpReport(org="DigitalOcean LLC"))[0], "datacenter")


class ServiceResultTest(unittest.TestCase):
    def test_place_combines_country_and_city(self):
        item = ServiceResult(
            key="claude",
            label="Claude",
            host="claude.ai",
            ip="160.79.104.10",
            geo={"country": "United States", "city": "San Francisco"},
        )
        self.assertEqual(item.place, "美国 · San Francisco")

    def test_place_without_geo(self):
        self.assertEqual(ServiceResult("a", "A", "a.com").place, "-")

    def test_as_dict_exposes_ip_and_state(self):
        item = ServiceResult("a", "A", "a.com", ip="1.2.3.4", state="blocked", detail="x")
        payload = item.as_dict()
        self.assertEqual(payload["ip"], "1.2.3.4")
        self.assertEqual(payload["state"], "blocked")


class VerdictLineTest(unittest.TestCase):
    def _report(self, states):
        report = IpReport()
        for index, state in enumerate(states):
            report.services.append(
                ServiceResult("s%d" % index, "S%d" % index, "h", state=state)
            )
        return report

    def test_all_ok(self):
        self.assertIn("全部", _verdict_line(self._report(["ok", "ok"])))

    def test_all_blocked(self):
        self.assertIn("全部", _verdict_line(self._report(["blocked", "blocked"])))

    def test_mixed_mentions_challenge(self):
        line = _verdict_line(self._report(["ok", "ok", "challenge", "blocked"]))
        self.assertIn("2/4", line)
        self.assertIn("WAF", line)

    def test_empty(self):
        self.assertIn("未探测", _verdict_line(IpReport()))


class JsonTest(unittest.TestCase):
    def test_render_json_is_valid(self):
        report = IpReport(egress_ip="203.0.113.7", country="United States", score=59)
        report.checks.append(Check("egress", "出口", "ok", "一致", 10.0, 10.0))
        report.services.append(
            ServiceResult("claude", "Claude", "claude.ai", ip="1.2.3.4", state="ok", tcp_ms=41.2)
        )
        payload = json.loads(render_json(report))
        self.assertEqual(payload["egress_ip"], "203.0.113.7")
        self.assertEqual(payload["services"][0]["ip"], "1.2.3.4")
        self.assertEqual(payload["summary"]["total"], 1)
        self.assertEqual(payload["summary"]["passing"], 1)

    def test_render_text_contains_service_table(self):
        report = IpReport(egress_ip="203.0.113.7", country="United States")
        report.services.append(
            ServiceResult(
                "claude",
                "Claude",
                "claude.ai",
                ip="160.79.104.10",
                geo={"country": "United States", "city": "SF"},
                state="blocked",
                detail="region",
            )
        )
        text = render_text(report)
        self.assertIn("claude.ai", text)
        self.assertIn("160.79.104.10", text)
        self.assertIn("区域拒绝", text)


if __name__ == "__main__":
    unittest.main()
