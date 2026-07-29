#!/usr/bin/env bash
set -euo pipefail
if [[ ${EUID} -ne 0 ]]; then
  echo "Run as root." >&2
  exit 1
fi
nft delete table inet halovpn_filter 2>/dev/null || true
nft delete table ip halovpn_nat 2>/dev/null || true
