import ipaddress
import tempfile
import unittest
from pathlib import Path

from scripts.generate import read_networks, subtract_networks, overlap_networks, validate_disjoint


class CidrGeneratorTests(unittest.TestCase):
    def test_partial_overlap_is_subtracted_exactly(self):
        ct = [ipaddress.ip_network("43.0.0.0/16")]
        cmcc = [ipaddress.ip_network("43.0.0.0/17")]
        self.assertEqual(
            [str(n) for n in subtract_networks(ct, cmcc)],
            ["43.0.128.0/17"],
        )
        self.assertEqual(
            [str(n) for n in overlap_networks(ct, cmcc)],
            ["43.0.0.0/17"],
        )

    def test_identical_network_is_fully_excluded(self):
        net = ipaddress.ip_network("192.0.2.0/24")
        self.assertEqual(subtract_networks([net], [net]), [])

    def test_nested_network_exclusion(self):
        source = ipaddress.ip_network("10.0.0.0/8")
        excluded = ipaddress.ip_network("10.1.0.0/16")
        pieces = subtract_networks([source], [excluded])
        self.assertEqual(sum(n.num_addresses for n in pieces),
                         source.num_addresses - excluded.num_addresses)
        self.assertFalse(any(n.overlaps(excluded) for n in pieces))

    def test_final_sets_are_disjoint(self):
        validate_disjoint(
            [ipaddress.ip_network("43.0.128.0/17")],
            [ipaddress.ip_network("43.0.0.0/17")],
        )

    def test_invalid_source_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bad.txt"
            path.write_text("1.2.3.0/24\nnot-a-cidr\n", encoding="utf-8")
            with self.assertRaises(ValueError):
                read_networks(path)

    def test_ipv6_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "v6.txt"
            path.write_text("2001:db8::/32\n", encoding="utf-8")
            with self.assertRaises(ValueError):
                read_networks(path)


if __name__ == "__main__":
    unittest.main()
