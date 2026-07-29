#!/usr/bin/env bash
set -euo pipefail

failures=0
check() {
  local description=$1
  shift
  if "$@" >/dev/null 2>&1; then
    printf 'OK   %s\n' "$description"
  else
    printf 'FAIL %s\n' "$description" >&2
    failures=$((failures + 1))
  fi
}

external_interface=${HALOVPN_EXTERNAL_INTERFACE:-}
tunnel_subnet=${HALOVPN_TUNNEL_SUBNET:-10.77.0.0/24}
udp_port=${HALOVPN_UDP_PORT:-45000}
controlplane_port=${HALOVPN_CONTROLPLANE_PORT:-8443}
tls_certificate=${HALOVPN_TLS_CERTIFICATE_PATH:-}
tls_key=${HALOVPN_TLS_KEY_PATH:-}
node_key=${HALOVPN_NODE_PRIVATE_KEY_PATH:-/etc/halovpn/node.key}
public_host=${HALOVPN_PUBLIC_HOST:-}
dns_servers=${HALOVPN_DNS_SERVERS:-}
denied_cidrs=${HALOVPN_DENIED_CIDRS:-}
postgres_host=${HALOVPN_POSTGRES_HOST:-/var/run/postgresql}
postgres_port=${HALOVPN_POSTGRES_PORT:-5432}
postgres_database=${HALOVPN_POSTGRES_DATABASE:-halovpn}
postgres_user=${HALOVPN_POSTGRES_USER:-halovpn_app}

check "Linux x64" test "$(uname -s)-$(uname -m)" = "Linux-x86_64"
check "/dev/net/tun exists" test -c /dev/net/tun
check "ip command" command -v ip
check "nft command" command -v nft
check "systemd is running" test -d /run/systemd/system
check "external interface configured" test -n "$external_interface"
if [[ -n $external_interface ]]; then
  check "external interface exists" ip link show dev "$external_interface"
  if command -v ufw >/dev/null 2>&1 && ufw status | grep -q '^Status: active'; then
    check "UFW permits HaloVPN routed egress" iptables -C ufw-user-forward \
      -i "${HALOVPN_TUN_INTERFACE:-halo0}" -o "$external_interface" -s "$tunnel_subnet" -j ACCEPT
  fi
fi
check "IPv4 forwarding enabled" test "$(cat /proc/sys/net/ipv4/ip_forward)" = "1"
check "UDP port is numeric" bash -c '[[ $1 =~ ^[0-9]+$ ]] && (( $1 >= 1 && $1 <= 65535 ))' _ "$udp_port"
check "ControlPlane port is numeric" bash -c '[[ $1 =~ ^[0-9]+$ ]] && (( $1 >= 1 && $1 <= 65535 ))' _ "$controlplane_port"
check "socket inspection command" command -v ss
if command -v ss >/dev/null 2>&1; then
  check "UDP port is not already bound" bash -c '! ss -H -lun "sport = :$1" | grep -q .' _ "$udp_port"
  check "ControlPlane port is not already bound" bash -c '! ss -H -ltn "sport = :$1" | grep -q .' _ "$controlplane_port"
fi
check "PostgreSQL reachability tool" command -v pg_isready
if command -v pg_isready >/dev/null 2>&1; then
  check "PostgreSQL is reachable" pg_isready -q -h "$postgres_host" -p "$postgres_port" -d "$postgres_database" -U "$postgres_user"
fi
check "TLS certificate exists" test -f "$tls_certificate"
check "TLS private key exists" test -f "$tls_key"
check "node private key exists" test -f "$node_key"
for protected_file in "$tls_key" "$node_key"; do
  if [[ -f $protected_file ]]; then
    mode=$(stat -c '%a' "$protected_file")
    check "restricted permissions on $(basename "$protected_file")" bash -c '(( (8#$1 & 0077) == 0 ))' _ "$mode"
  fi
done
check "tunnel subnet is valid" ip route get "${tunnel_subnet%/*}"
if ip route show | grep -Fq "$tunnel_subnet"; then
  printf 'FAIL tunnel subnet conflicts with an existing route\n' >&2
  failures=$((failures + 1))
else
  printf 'OK   tunnel subnet has no exact existing route\n'
fi
check "public host configured" test -n "$public_host"
if [[ -n $public_host ]]; then
  check "public host resolves to IPv4" getent ahostsv4 "$public_host"
fi
check "DNS servers configured" test -n "$dns_servers"
check "destination deny CIDRs loaded" test -n "$denied_cidrs"
required_denials=(
  0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 127.0.0.0/8 169.254.0.0/16 172.16.0.0/12
  192.0.0.0/24 192.0.2.0/24 192.88.99.0/24 192.168.0.0/16 198.18.0.0/15
  198.51.100.0/24 203.0.113.0/24 224.0.0.0/4 240.0.0.0/4
)
for required_cidr in "${required_denials[@]}"; do
  if [[ ",$denied_cidrs," != *",$required_cidr,"* && ",$denied_cidrs," != *", $required_cidr,"* ]]; then
    printf 'FAIL destination deny list is missing a required prefix\n' >&2
    failures=$((failures + 1))
    break
  fi
done

if (( failures > 0 )); then
  printf '%d preflight check(s) failed. No system state was changed.\n' "$failures" >&2
  exit 1
fi
printf 'All preflight checks passed. No system state was changed.\n'
