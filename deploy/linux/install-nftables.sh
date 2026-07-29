#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
  echo "Run as root." >&2
  exit 1
fi
if [[ $# -ne 1 ]]; then
  echo "Usage: $0 <external-interface>" >&2
  exit 2
fi
external_interface=$1
tun_interface=${HALOVPN_TUN_INTERFACE:-halo0}
tunnel_subnet=${HALOVPN_TUNNEL_SUBNET:-10.77.0.0/24}
denied_cidrs=${HALOVPN_DENIED_CIDRS:-"0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.0.0.0/24, 192.0.2.0/24, 192.88.99.0/24, 192.168.0.0/16, 198.18.0.0/15, 198.51.100.0/24, 203.0.113.0/24, 224.0.0.0/4, 240.0.0.0/4"}
if ! ip link show dev "$external_interface" >/dev/null 2>&1; then
  echo "External interface does not exist: $external_interface" >&2
  exit 2
fi

# An accept verdict in a separate nftables base chain cannot override a later
# drop verdict from UFW's FORWARD chain. Require the narrow routed exception
# before installing the owned tables when UFW is active.
if command -v ufw >/dev/null 2>&1 && ufw status | grep -q '^Status: active'; then
  if ! command -v iptables >/dev/null 2>&1 ||
    ! iptables -C ufw-user-forward -i "$tun_interface" -o "$external_interface" -s "$tunnel_subnet" -j ACCEPT 2>/dev/null; then
    echo "UFW is active and would drop HaloVPN forwarding." >&2
    echo "Add the exact routed rule first:" >&2
    echo "  ufw route allow in on $tun_interface out on $external_interface from $tunnel_subnet to any comment 'HaloVPN tunnel egress'" >&2
    exit 3
  fi
fi

# Only HaloVPN-owned tables are replaced. Existing firewall tables are untouched.
nft delete table inet halovpn_filter 2>/dev/null || true
nft delete table ip halovpn_nat 2>/dev/null || true
nft -f - <<EOF
table inet halovpn_filter {
  set denied_v4 {
    type ipv4_addr
    flags interval
    auto-merge
    elements = { $denied_cidrs, $tunnel_subnet }
  }
  chain input {
    type filter hook input priority filter; policy accept;
    iifname "$tun_interface" drop
  }
  chain forward {
    type filter hook forward priority filter; policy accept;
    iifname "$tun_interface" oifname "$tun_interface" drop
    iifname "$tun_interface" ip daddr @denied_v4 drop
    iifname "$tun_interface" oifname != "$external_interface" drop
    iifname "$tun_interface" oifname "$external_interface" ip saddr $tunnel_subnet accept
    iifname "$external_interface" oifname "$tun_interface" ct state established,related accept
    oifname "$tun_interface" drop
    iifname "$tun_interface" drop
  }
}
table ip halovpn_nat {
  chain postrouting {
    type nat hook postrouting priority srcnat; policy accept;
    oifname "$external_interface" ip saddr $tunnel_subnet masquerade
  }
}
EOF
nft list table inet halovpn_filter
nft list table ip halovpn_nat
