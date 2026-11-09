import ipaddress
import random
import tempfile
import unittest
from pathlib import Path

from scripts.generate import (
    read_networks,
    subtract_networks,
    overlap_networks,
    validate_disjoint,
)


def addresses(networks):
    return {int(address) for network in networks for address in network}


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

    def test_non_aligned_overlap_is_split_without_loss(self):
        ct = [ipaddress.ip_network("192.0.2.0/24")]
        cmcc = [ipaddress.ip_network("192.0.2.64/26")]
        remaining = subtract_networks(ct, cmcc)
        self.assertEqual(addresses(remaining), addresses(ct) - addresses(cmcc))
        self.assertEqual(addresses(overlap_networks(ct, cmcc)), addresses(ct) & addresses(cmcc))

    def test_identical_network_is_fully_excluded(self):
        net = ipaddress.ip_network("192.0.2.0/24")
        self.assertEqual(subtract_networks([net], [net]), [])

    def test_nested_network_exclusion(self):
        source = ipaddress.ip_network("10.0.0.0/8")
        excluded = ipaddress.ip_network("10.1.0.0/16")
        pieces = subtract_networks([source], [excluded])
        self.assertEqual(addresses(pieces), addresses([source]) - addresses([excluded]))

    def test_disjoint_networks_are_preserved(self):
        source = [ipaddress.ip_network("10.0.0.0/24")]
        excluded = [ipaddress.ip_network("10.0.2.0/24")]
        self.assertEqual(subtract_networks(source, excluded), source)
        self.assertEqual(overlap_networks(source, excluded), [])

    def test_randomized_small_network_sets_match_address_math(self):
        rng = random.Random(20261109)
        universe = ipaddress.ip_network("198.51.100.0/24")
        candidates = [
            ipaddress.ip_network((int(universe.network_address) + offset, prefix))
            for prefix in range(25, 33)
            for offset in range(0, 256, 2 ** (32 - prefix))
        ]
        for _ in range(100):
            left = rng.sample(candidates, rng.randint(1, 12))
            right = rng.sample(candidates, rng.randint(1, 12))
            left_set, right_set = addresses(left), addresses(right)
            self.assertEqual(addresses(subtract_networks(left, right)), left_set - right_set)
            self.assertEqual(addresses(overlap_networks(left, right)), left_set & right_set)

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

    def test_empty_source_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "empty.txt"
            path.write_text("# no entries\n\n", encoding="utf-8")
            with self.assertRaises(ValueError):
                read_networks(path)


if __name__ == "__main__":
    unittest.main()
