"""目标解析与加载."""

import json
import os
import tempfile
import unittest

from netsteady.targets import (
    DOMESTIC_PRESETS,
    OVERSEAS_PRESETS,
    load_targets,
    parse_endpoint,
    split_groups,
)


class ParseEndpointTest(unittest.TestCase):
    def test_host_only_defaults_to_443(self):
        target = parse_endpoint("example.com")
        self.assertEqual(target.host, "example.com")
        self.assertEqual(target.port, 443)

    def test_host_and_port(self):
        target = parse_endpoint("1.2.3.4:8080")
        self.assertEqual(target.port, 8080)

    def test_rejects_empty(self):
        with self.assertRaises(ValueError):
            parse_endpoint("  ")


class LoadTargetsTest(unittest.TestCase):
    def test_defaults_have_both_groups(self):
        targets = load_targets(None)
        self.assertEqual(len(targets), len(OVERSEAS_PRESETS) + len(DOMESTIC_PRESETS))
        overseas, domestic = split_groups(targets)
        self.assertTrue(overseas)
        self.assertTrue(domestic)

    def test_load_from_json(self):
        payload = {
            "targets": [
                {"name": "hk", "host": "1.1.1.1", "port": 443, "group": "overseas"},
                "9.9.9.9:53",
            ]
        }
        handle = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8")
        try:
            json.dump(payload, handle)
            handle.close()
            targets = load_targets(handle.name)
        finally:
            os.unlink(handle.name)
        self.assertEqual(len(targets), 2)
        self.assertEqual(targets[0].name, "hk")
        self.assertEqual(targets[1].port, 53)

    def test_empty_file_raises(self):
        handle = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8")
        try:
            json.dump({"targets": []}, handle)
            handle.close()
            with self.assertRaises(ValueError):
                load_targets(handle.name)
        finally:
            os.unlink(handle.name)


if __name__ == "__main__":
    unittest.main()
