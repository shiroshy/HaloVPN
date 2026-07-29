#!/usr/bin/env bash
set -euo pipefail
repository_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
configuration=${1:-Release}
if [[ "$configuration" != "Release" && "$configuration" != "Debug" ]]; then
  echo "Configuration must be Release or Debug." >&2
  exit 2
fi
command -v cargo >/dev/null || { echo "cargo is required" >&2; exit 1; }
command -v dotnet >/dev/null || { echo "dotnet is required" >&2; exit 1; }
profile_argument=()
native_profile=debug
if [[ "$configuration" == "Release" ]]; then
  profile_argument=(--release)
  native_profile=release
fi
pushd "$repository_root/native/halo-protocol" >/dev/null
cargo build --locked "${profile_argument[@]}"
popd >/dev/null
publish_root="$repository_root/publish/linux-x64/$configuration"
dotnet publish "$repository_root/src/HaloVPN.ControlPlane/HaloVPN.ControlPlane.csproj" -c "$configuration" -r linux-x64 --self-contained false -o "$publish_root/controlplane"
dotnet publish "$repository_root/src/HaloVPN.Node/HaloVPN.Node.csproj" -c "$configuration" -r linux-x64 --self-contained false -o "$publish_root/node"
dotnet publish "$repository_root/src/HaloVPN.AdminCli/HaloVPN.AdminCli.csproj" -c "$configuration" -r linux-x64 --self-contained false -o "$publish_root/admin"
dotnet publish "$repository_root/src/HaloVPN.KeyGen/HaloVPN.KeyGen.csproj" -c "$configuration" -r linux-x64 --self-contained false -o "$publish_root/tools"
install -m 0755 "$repository_root/native/halo-protocol/target/$native_profile/libhalo_protocol.so" "$publish_root/node/libhalo_protocol.so"
install -m 0755 "$repository_root/native/halo-protocol/target/$native_profile/libhalo_protocol.so" "$publish_root/tools/libhalo_protocol.so"
echo "Published to $publish_root"
