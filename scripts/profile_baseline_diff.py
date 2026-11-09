#!/usr/bin/env python3
"""Summarize baseline-only address space without publishing raw ranges.

This report is intended to guide manual investigation. It groups differences by
IPv4 first octet and prefix length; it does not infer an operator or ASN.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
from collections import defaultdict
from pathlib import Path

from scripts.compare_baseline import read_rsc_lists
from scripts.generate import read_networks, subtract_networks


def summarize(networks):
    by_first_octet = defaultdict(int)
    by_prefix_length = defaultdict(int)
    total = 0
    for net in networks:
        count = net.num_addresses
        total += count
        by_first_octet[str(net.network_address).split(".")[0]] += count
        by_prefix_length[str(net.prefixlen)] += count
    return {
        "total_addresses": total,
        "cidr_count": len(networks),
        "by_first_octet": dict(sorted(by_first_octet.items(), key=lambda x: int(x[0]))),
        "by_prefix_length": dict(sorted(by_prefix_length.items(), key=lambda x: int(x[0]))),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline-rsc", required=True, type=Path)
    parser.add_argument("--ct-file", required=True, type=Path)
    parser.add_argument("--cmcc-file", required=True, type=Path)
    parser.add_argument("--report", required=True, type=Path)
    args = parser.parse_args()

    baseline = read_rsc_lists(args.baseline_rsc)
    ct_source, _ = read_networks(args.ct_file)
    cmcc_source, _ = read_networks(args.cmcc_file)
    ct_candidate = subtract_networks(ct_source, cmcc_source)
    cmcc_candidate = subtract_networks(cmcc_source, ct_source)

    ct_only_old = subtract_networks(baseline["dpbr-CT"], ct_candidate)
    cmcc_only_old = subtract_networks(baseline["dpbr-CMCC"], cmcc_candidate)

    report = {
        "purpose": "Descriptive distribution only; no operator/ASN classification is inferred.",
        "baseline_file": args.baseline_rsc.name,
        "old_only": {
            "dpbr-CT": summarize(ct_only_old),
            "dpbr-CMCC": summarize(cmcc_only_old),
        },
        "privacy": "No individual CIDR ranges or raw baseline entries are written to this report.",
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
