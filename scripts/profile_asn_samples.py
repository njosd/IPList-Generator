#!/usr/bin/env python3
"""Build a local, privacy-preserving ASN sampling report for baseline-only IP space.

This is a screening tool, not a complete BGP route-table dump. For every CIDR in
the old baseline that is absent from the candidate operator-exclusive list, it
samples five addresses (first, 25%, midpoint, 75%, last), then queries Team Cymru's bulk WHOIS TCP/43 origin-ASN service in bounded batches.

The raw baseline, extracted CIDRs, sample IPs, and individual ASN results remain
local. Only aggregate JSON summaries are written. No router is contacted.
"""
from __future__ import annotations

import argparse
import collections
import ipaddress
import json
import socket
import sys
from pathlib import Path

from scripts.compare_baseline import read_rsc_lists
from scripts.generate import read_networks, subtract_networks

def count(networks):
    return sum(n.num_addresses for n in networks)

def sample_ips(networks):
    samples = set()
    for net in networks:
        first = int(net.network_address)
        last = int(net.broadcast_address)
        span = last - first
        for offset in (0, span // 4, span // 2, (span * 3) // 4, span):
            samples.add(str(ipaddress.IPv4Address(first + offset)))
    return sorted(samples, key=lambda x: int(ipaddress.IPv4Address(x)))

def query_cymru(ips, timeout, batch_size):
    """Query Team Cymru bulk WHOIS over TCP/43; return results keyed by input IP."""
    results = {}
    total_batches = (len(ips) + batch_size - 1) // batch_size
    for batch_no, start in enumerate(range(0, len(ips), batch_size), 1):
        chunk = ips[start:start + batch_size]
        payload = "begin\\nverbose\\n" + "\\n".join(chunk) + "\\nend\\n"
        try:
            with socket.create_connection(("whois.cymru.com", 43), timeout=timeout) as sock:
                sock.settimeout(timeout)
                sock.sendall(payload.encode("ascii"))
                sock.shutdown(socket.SHUT_WR)
                chunks = []
                while True:
                    data = sock.recv(65536)
                    if not data:
                        break
                    chunks.append(data)
            response = b"".join(chunks).decode("utf-8", errors="replace")
        except (OSError, TimeoutError) as exc:
            raise RuntimeError(
                f"Team Cymru TCP/43 batch {batch_no}/{total_batches} failed: {exc}"
            ) from exc

        for ip in chunk:
            results[ip] = None
        for line in response.splitlines():
            if "|" not in line:
                continue
            fields = [part.strip() for part in line.split("|")]
            if len(fields) < 3:
                continue
            try:
                returned_ip = str(ipaddress.IPv4Address(fields[1]))
            except ValueError:
                continue
            if returned_ip not in results:
                continue
            try:
                asn = int(fields[0])
                prefix = str(ipaddress.ip_network(fields[2], strict=False))
            except (ValueError, TypeError):
                continue
            results[returned_ip] = {
                "asn": asn,
                "prefix": prefix,
                "country": fields[3] if len(fields) > 3 else "",
                "registry": fields[4] if len(fields) > 4 else "",
                "allocated": fields[5] if len(fields) > 5 else "",
                "as_name": fields[6] if len(fields) > 6 else "",
            }
        answered = sum(value is not None for value in results.values())
        print(
            f"WHOIS batch {batch_no}/{total_batches}: "
            f"{len(chunk)} samples submitted; {answered}/{len(ips)} answered",
            file=sys.stderr,
            flush=True,
        )
    return results

def parse_answer(line):
    # Typical TXT payload: "4134 | 1.0.1.0/24 | CN | apnic | 2011-..."
    cleaned = line.strip().strip('"')
    parts = [p.strip() for p in cleaned.split("|")]
    if len(parts) < 2:
        return None
    try:
        asn = int(parts[0])
        prefix = str(ipaddress.ip_network(parts[1], strict=False))
    except (ValueError, TypeError):
        return None
    return {
        "asn": asn,
        "prefix": prefix,
        "country": parts[2] if len(parts) > 2 else "",
        "registry": parts[3] if len(parts) > 3 else "",
        "allocated": parts[4] if len(parts) > 4 else "",
    }

def summarize(label, baseline, candidate, timeout, batch_size):
    old_only = subtract_networks(baseline, candidate)
    ips = sample_ips(old_only)
    answers = query_cymru(ips, timeout, batch_size)
    by_asn = collections.defaultdict(lambda: {"sample_count": 0, "sampled_ips": 0, "bgp_prefixes": set(), "countries": set()})
    no_answer = 0
    for ip, answer in answers.items():
        if not answer:
            no_answer += 1
            continue
        row = by_asn[str(answer["asn"])]
        row["sample_count"] += 1
        row["sampled_ips"] += 1
        row["bgp_prefixes"].add(answer["prefix"])
        if answer["country"]:
            row["countries"].add(answer["country"])
    asn_rows = []
    for asn, row in sorted(by_asn.items(), key=lambda item: (-item[1]["sample_count"], int(item[0]))):
        asn_rows.append({
            "asn": int(asn),
            "sample_count": row["sample_count"],
            "bgp_prefix_count": len(row["bgp_prefixes"]),
            "countries": sorted(row["countries"]),
        })
    return {
        "list": label,
        "baseline_only_addresses": count(old_only),
        "baseline_only_cidr_count": len(old_only),
        "unique_sample_ips": len(ips),
        "answered_sample_ips": len(ips) - no_answer,
        "unanswered_sample_ips": no_answer,
        "asn_distribution": asn_rows,
        "limitations": [
            "Five point samples per CIDR are screening evidence only.",
            "A sampled ASN does not prove every address in its CIDR has the same origin ASN.",
            "More-specific BGP routes between sample points may be missed.",
            "Unanswered samples may reflect no route, DNS filtering, or temporary query failure."
        ]
    }

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--baseline-rsc", required=True, type=Path)
    p.add_argument("--ct-file", required=True, type=Path)
    p.add_argument("--cmcc-file", required=True, type=Path)
    p.add_argument("--report", required=True, type=Path)
    p.add_argument("--timeout", type=int, default=20, help="TCP connect/read timeout per batch, seconds")
    p.add_argument("--batch-size", type=int, default=500, help="sample IPs per WHOIS connection")
    args = p.parse_args()
    if args.timeout < 1 or args.batch_size < 1:
        p.error("--timeout and --batch-size must be positive")
    try:
        baseline = read_rsc_lists(args.baseline_rsc)
        ct_source, _ = read_networks(args.ct_file)
        cmcc_source, _ = read_networks(args.cmcc_file)
        ct_candidate = subtract_networks(ct_source, cmcc_source)
        cmcc_candidate = subtract_networks(cmcc_source, ct_source)
        report = {
            "purpose": "ASN screening of baseline-only address space; local aggregate report only.",
            "baseline_file": args.baseline_rsc.name,
            "source_pair": {
                "ct_file": args.ct_file.name,
                "cmcc_file": args.cmcc_file.name
            },
            "query_service": "Team Cymru bulk WHOIS TCP/43 origin ASN service",
            "sampling": "first, 25%, midpoint, 75%, last address of each baseline-only CIDR; deduplicated",
            "query_batch_size": args.batch_size,
            "per_batch_timeout_seconds": args.timeout,
            "results": [
                summarize("dpbr-CT vs candidate", baseline["dpbr-CT"], ct_candidate, args.timeout, args.batch_size),
                summarize("dpbr-CMCC vs candidate", baseline["dpbr-CMCC"], cmcc_candidate, args.timeout, args.batch_size)
            ],
            "privacy": "No raw CIDRs, sample IPs, or per-IP ASN records are written to this report."
        }
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        print(json.dumps(report, indent=2, ensure_ascii=False))
        return 0
    except (ValueError, OSError, RuntimeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

if __name__ == "__main__":
    raise SystemExit(main())
