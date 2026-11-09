import tempfile
import unittest
from pathlib import Path

from scripts.compare_baseline import read_rsc_lists, compare_list
import ipaddress


class BaselineComparisonTests(unittest.TestCase):
    def test_reads_expected_routeros_lists(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "baseline.rsc"
            path.write_text(
                "/ip firewall address-list\n"
                "add list=dpbr-CT address=10.0.0.0/24\n"
                "add list=dpbr-CMCC address=10.0.1.0/24\n",
                encoding="utf-8",
            )
            parsed = read_rsc_lists(path)
            self.assertEqual(str(parsed["dpbr-CT"][0]), "10.0.0.0/24")
            self.assertEqual(str(parsed["dpbr-CMCC"][0]), "10.0.1.0/24")

    def test_comparison_reports_added_and_removed_address_space(self):
        baseline = [ipaddress.ip_network("10.0.0.0/24")]
        candidate = [ipaddress.ip_network("10.0.0.0/25")]
        result = compare_list(baseline, candidate)
        self.assertEqual(result["common_addresses"], 128)
        self.assertEqual(result["baseline_only_addresses"], 128)
        self.assertEqual(result["candidate_only_addresses"], 0)
        self.assertEqual(result["baseline_coverage_pct"], 50.0)
        self.assertEqual(result["candidate_coverage_pct"], 100.0)


if __name__ == "__main__":
    unittest.main()
