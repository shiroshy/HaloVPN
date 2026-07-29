#!/usr/bin/env bash
set -euo pipefail
control_url=${HALOVPN_HEALTH_URL:-https://127.0.0.1:8443/health/ready}
curl --fail --silent --show-error --max-time 5 "$control_url" >/dev/null
systemctl is-active --quiet halovpn-node.service
ip link show halo0 >/dev/null
