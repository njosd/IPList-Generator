# IPList-Generator

Generate mutually exclusive MikroTik RouterOS IPv4 address lists from upstream China ISP CIDR datasets.

## Current phase

This repository is an isolated generator prototype. It does **not** update a MikroTik router and does not publish production RSC files yet. Upstream source selection and comparison against the existing production lists must be completed before enabling scheduled publication.

## Classification policy

Given upstream IPv4 networks:

- CT-only address space: CT minus CMCC -> `dpbr-CT`
- CMCC-only address space: CMCC minus CT -> `dpbr-CMCC`
- Any address space present in both sources -> excluded from both lists; the router's existing default route handles it.
- Unclassified address space -> excluded from both lists; the router's existing default route handles it.

The subtraction is performed on address ranges, not merely identical CIDR strings. For example, if CT contains `43.0.0.0/16` and CMCC contains `43.0.0.0/17`, only `43.0.128.0/17` remains CT-only.

## Generator

`scripts/generate.py` uses Python's standard-library `ipaddress` module. It accepts local source files, validates IPv4 CIDRs, collapses each input set, subtracts the other ISP's address space, and writes:

- RouterOS RSC containing only `dpbr-CT` and `dpbr-CMCC` address-list entries
- JSON report with source counts, normalized counts, overlap size, exclusive counts and output checksums

No third-party Python packages are required.

## Run locally

```sh
python3 scripts/generate.py --ct-file path/to/chinanet.txt --cmcc-file path/to/cmcc.txt --output output/ros-dpbr-CT-CMCC.rsc --report output/report.json
```

Each input file must contain one IPv4 CIDR (or IPv4 address) per non-empty line. Blank lines and lines beginning with `#` are ignored. The script fails closed on malformed lines, empty inputs, IPv6 entries, or an empty exclusive result.

## GitHub Actions

The workflow is initially manual-only and runs validation tests. Scheduled production generation and publication will remain disabled until the upstream URLs, source quality, output thresholds, and comparison report have been reviewed.

## Router integration

No RouterOS configuration is changed by this repository. The eventual hEX updater will only download a reviewed RSC, validate it, back up current lists, import, verify, and roll back on failure. The existing weekly Friday 03:30 schedule remains unchanged until a separately approved router-side deployment.
