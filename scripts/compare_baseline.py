#!/usr/bin/env python3
"""Compare an existing RouterOS RSC baseline with candidate ISP CIDR sources.

This is an offline review tool. It does not modify a router or publish output.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import re
from pathlib import Path

from scripts.generate import read_networks, subtract_networks, overlap_networks

ENTRY = re.compile(
    r'^\s*add\s+list=(?P<list>[^\s]+)\s+address=(?P<address>[^\s]+)(?:\s|$)'
)


def read_rsc_lists(path: Path) -> dict[str, list[ipaddress.IPv4Network]]:
    found = {"dpbr-CT": [], "dpbr-CMCC": []}
    errors = []
    for line_no, line in enumerate(path.read_text(encoding="utf-8-sig").splitlines(), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped == "/ip firewall address-list":
            continue
        match = ENTRY.match(line)
        if not match:
            # This RSC is expected to contain only address-list add statements.
            errors.append(f"{path}:{line_no}: unexpected command: {stripped[:120]}")
            continue
        list_name = match.group("list")
        if list_name not in found:
            errors.append(f"{path}:{line_no}: unexpected list {list_name}")
            continue
        try:
            network = ipaddress.ip_network(match.group("address"), strict=False)
            if not isinstance(network, ipaddress.IPv4Network):
                raise ValueError("IPv6 entry")
            found[list_name].append(network)
        except ValueError as exc:
            errors.append(f"{path}:{line_no}: invalid address: {exc}")
    if errors:
        raise ValueError("\n".join(errors[:30]))
    for name, networks in found.items():
        if not networks:
            raise ValueError(f"{path}: baseline list {name} is empty")
        found[name] = list(ipaddress.collapse_addresses(networks))
    return found


def count(networks):
    return sum(n.num_addresses for n in networks)


def compare_list(baseline, candidate):
    baseline_only = subtract_networks(baseline, candidate)
    candidate_only = subtract_networks(candidate, baseline)
    common = overlap_networks(baseline, candidate)
    return {
        "baseline_prefixes": len(baseline),
        "candidate_prefixes": len(candidate),
        "baseline_addresses": count(baseline),
        "candidate_addresses": count(candidate),
        "common_addresses": count(common),
        "baseline_only_addresses": count(baseline_only),
        "candidate_only_addresses": count(candidate_only),
        "baseline_coverage_pct": round(count(common) / count(baseline) * 100, 6),
        "candidate_coverage_pct": round(count(common) / count(candidate) * 100, 6),
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

    report = {
        "baseline_file": args.baseline_rsc.name,
        "policy": "Candidate is each source's exclusive address space after subtracting the other ISP.",
        "lists": {
            "dpbr-CT": compare_list(baseline["dpbr-CT"], ct_candidate),
            "dpbr-CMCC": compare_list(baseline["dpbr-CMCC"], cmcc_candidate),
        },
        "baseline_cross_list_overlap_addresses": count(
            overlap_networks(baseline["dpbr-CT"], baseline["dpbr-CMCC"])
        ),
        "candidate_cross_list_overlap_addresses": count(
            overlap_networks(ct_candidate, cmcc_candidate)
        ),
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
