# IPList-Generator

Generate mutually exclusive MikroTik RouterOS IPv4 address lists from upstream China ISP CIDR datasets.

## Current phase

The generator and source-selection policy are established. GitHub Actions downloads the selected source, validates it, generates candidate RSC and JSON report files, and stores them as a workflow artifact. This is **not** a production release: no RouterOS device is contacted or changed, and generated files are not published as a stable production download.

## Selected data source

- Primary and only generation source: [gaoyifan/china-operator-ip](https://github.com/gaoyifan/china-operator-ip)
  - Telecom: `ip-lists/chinanet.txt`
  - China Mobile: `ip-lists/cmcc.txt`
- [metowolf/iplist](https://github.com/metowolf/iplist) is retained only as an optional comparison reference. Its data is not merged into the generated lists.
- The historical production RSC is a comparison reference only, not a correctness target. Differences from it do not justify retaining old ranges automatically.

## Classification policy

Given the two gaoyifan IPv4 source files:

- CT-only address space: CT minus CMCC -> `dpbr-CT`
- CMCC-only address space: CMCC minus CT -> `dpbr-CMCC`
- Any address space present in both source lists -> excluded from both lists; the router's existing default route handles it.
- Unclassified address space -> excluded from both lists; the router's existing default route handles it.

The subtraction is performed on address ranges, not merely identical CIDR strings. No per-IP ASN lookup or multi-source fusion is performed. A small amount of classification imperfection is acceptable in favor of a simple, reliable, low-maintenance process.

## Generator

`scripts/generate.py` uses Python's standard-library `ipaddress` module. It accepts local source files, validates IPv4 CIDRs, merges address ranges, performs sorted interval subtraction/intersection, and writes:

- RouterOS RSC containing only `dpbr-CT` and `dpbr-CMCC` address-list entries
- JSON report with source counts, normalized counts, overlap size, exclusive counts and output checksums

No third-party Python packages are required. The generator does not fetch upstream data, publish files, or contact a router.

## GitHub Actions

`.github/workflows/generate.yml` runs daily at 03:30 UTC, on relevant source/test/workflow pushes, or manually. It:

1. Runs the unit tests.
2. Downloads the two selected gaoyifan source files.
3. Rejects missing or empty source files and lets the generator reject malformed, IPv6, or empty data.
4. Generates the candidate RSC and JSON report.
5. Saves both files as a 30-day workflow artifact only after successful generation.

A failed run does not overwrite or delete any previous successful artifact. The workflow does not create a stable public download URL or publish a production release.

The separate `.github/workflows/validate.yml` remains the lightweight code-validation workflow.

## Router integration and dual-WAN behavior

No RouterOS configuration is changed by this repository. The eventual hEX updater is intended to download a reviewed RSC, validate it, back up current lists, import, verify, and roll back on failure. It must not change existing mangle, NAT, routing, DNS, firewall, or interface configuration.

The network design requirement is:

- When both WANs are healthy, CT and CMCC destinations use their respective policy routes.
- If either WAN fails, the surviving WAN must carry all traffic, including traffic normally assigned to the failed WAN's policy table.
- When the failed WAN recovers and is confirmed healthy, normal dual-WAN policy routing resumes.

The existence of backup default routes in `rt-ct` and `rt-cm` and the earlier simulated primary-route disable test are historical facts; physical WAN failure detection and end-to-end single-WAN takeover still require targeted verification. Main-table failover alone is not sufficient evidence.

The existing hEX weekly Friday 03:30 updater remains unchanged until a separately reviewed and approved router-side deployment.

## Run locally

```sh
python3 scripts/generate.py --ct-file path/to/chinanet.txt --cmcc-file path/to/cmcc.txt --output output/ros-dpbr-CT-CMCC.rsc --report output/report.json
```

Each input file must contain one IPv4 CIDR (or IPv4 address) per non-empty line. Blank lines and lines beginning with `#` are ignored. The script fails closed on malformed lines, empty inputs, IPv6 entries, or an empty exclusive result.

## Historical source comparison

The snapshot comparison is recorded in [reports/source-comparison-2026-11-09.json](reports/source-comparison-2026-11-09.json). It documents differences between gaoyifan and metowolf at that time; it is not a reason to combine them or to treat the historical RouterOS list as authoritative.
