# Linux VPS deployment notes

This bundle is intentionally not an automatic VPS installer. Review every command, supply the external interface explicitly, and keep populated environment/key files outside Git.

Run the read-only preflight before installation (values shown are examples, not VPS configuration):

```bash
sudo -E HALOVPN_EXTERNAL_INTERFACE=eth0 \
  HALOVPN_TUNNEL_SUBNET=10.77.0.0/24 HALOVPN_UDP_PORT=45000 HALOVPN_CONTROLPLANE_PORT=8443 \
  HALOVPN_TLS_CERTIFICATE_PATH=/etc/halovpn/tls/controlplane.crt \
  HALOVPN_TLS_KEY_PATH=/etc/halovpn/tls/controlplane.key HALOVPN_NODE_PRIVATE_KEY_PATH=/etc/halovpn/node.key \
  HALOVPN_PUBLIC_HOST=vpn.example.invalid HALOVPN_DNS_SERVERS=1.1.1.1,9.9.9.9 \
  HALOVPN_DENIED_CIDRS='0.0.0.0/8,10.0.0.0/8,...' \
  HALOVPN_POSTGRES_HOST=/var/run/postgresql HALOVPN_POSTGRES_DATABASE=halovpn \
  ./deploy/linux/preflight.sh
```

It never reads or prints a PostgreSQL password and changes no state. Replace every example, including the complete deny list, before relying on its result.

1. Run `./deploy/linux/build-publish.sh Release` on Linux x64 with .NET 10 and stable Rust.
2. Create the `halovpn` and `halovpn-node` system users, install the published directories under `/opt/halovpn`, and install `halovpn-tmpfiles.conf` with `systemd-tmpfiles --create`. Generate the node key into a new protected path with `/opt/halovpn/tools/HaloVPN.KeyGen --private-key /etc/halovpn/node.key`, then copy only its printed public key into the ControlPlane node configuration.
3. Copy the two `.env.example` files without the `.example` suffix to `/etc/halovpn`, replace placeholders, set owner `root:halovpn`, mode `0640`; store `node.key` as `halovpn-node:halovpn` mode `0600`.
4. Apply PostgreSQL migrations with `HALOVPN_DATABASE=... dotnet /opt/halovpn/admin/HaloVPN.AdminCli.dll database migrate` using the schema-owner role. Give the node a separate read-only role limited to `SELECT` on `users` and `devices`.
5. Install the sysctl file and run `sysctl --system`. If UFW is active with routed traffic denied, add the exact interface/source rule shown below first. Then run `install-nftables.sh <external-interface>`; it modifies only `halovpn_filter` and `halovpn_nat` tables and refuses to install when an active UFW policy would still drop forwarded packets.
6. Install and enable the two systemd units. The ControlPlane certificate must be provisioned separately from a trusted CA or pinned explicitly on clients.

Verify the owned rules without changing them:

```bash
sudo nft list table inet halovpn_filter
sudo nft list set inet halovpn_filter denied_v4
sudo nft list table ip halovpn_nat
sudo iptables -vnL ufw-user-forward --line-numbers
```

For a host with active UFW, use an explicit rule; do not change UFW's global routed policy:

```bash
sudo ufw route allow in on halo0 out on eth0 from 10.77.0.0/24 to any comment 'HaloVPN tunnel egress'
sudo iptables -C ufw-user-forward -i halo0 -o eth0 -s 10.77.0.0/24 -j ACCEPT
```

Replace `eth0` and the subnet with the reviewed deployment values. The owned nftables deny set still drops special/private destinations before this UFW allow rule. During uninstall, remove the same rule by its exact specification; do not flush UFW:

```bash
sudo ufw route delete allow in on halo0 out on eth0 from 10.77.0.0/24 to any
```

Negative checks from a connected test client must fail: `169.254.169.254`, the VPS tunnel gateway, the VPS public/private addresses, RFC1918, CGNAT and documentation/benchmark prefixes. Confirm the counters on `denied_v4`, the `input` drop and the final `iifname halo0 drop`; do not log destination addresses while doing application-level diagnostics. An explicit `HALOVPN_DENIED_CIDRS` deployment override must contain the complete desired set, and should match `Node:DeniedDestinationCidrs`.

Back up PostgreSQL with the operator's normal encrypted `pg_dump` workflow and test restoration. The database contains password hashes, token hashes, device public keys, leases and audit events; it does not contain device or node private keys. The Node's authorization cache keeps established sessions during a short database outage but rejects new sessions until a fresh allowlist is available.
