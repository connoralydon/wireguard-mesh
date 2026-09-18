# wireguard-mesh

`wireguard-meshd` is a small Linux Go service for direct LAN paths between trusted WireGuard nodes. See [PLAN.md](PLAN.md) for the design.

**Status:** the Go checks and four QEMU/KVM integration tests have passed on Linux x86-64. The VM tests cover relay-only operation, direct LAN operation and recovery, separate NAT networks, and Rosenpass exchange and rekey. See [tests/README.md](tests/README.md) for commands and limits. An independent security review is still required before production use.

Wireguard is an incredible VPN. One issue is that peers and routes are statically defined.

You CAN create a mesh, but the routes all need to be predefined. 

This service allows you to statically set a meshing configuration so already authenticated peers will be able to discover each other.

---
## Problem

Here's a concrete example on inter-LAN routing.
```
You have three nodes: A, B & C.
Node A is a cloud node with a public IP, ie an ingress point.
Nodes B and C are on the same LAN.

For the sake of simplicity Nodes B and C are routed to each other via A. B might be a laptop that roams and C might be a persistent server. Or, B & C might be servers and you'd like to reach them via the WAN through A.

The problem is that if B & C want to pass data over the wireguard VPN, they need to route through A. This introduces extra latency and extra bandwidth quota consumption on your A node.
```

That example can extend to another scenario where B and C are on separate LANs.

Nodes on separate LANs would need NAT traversal. Hole punching is not supported and is not an implementation goal. DERP is a relay mechanism, not hole punching.

---
## Usage
The `wireguard-meshd` service assumes that your initial Wireguard configuration defines *stable* routes. It will attempt to find *unstable* non-defined routes by encrypted broadcast via multicast or broadcast. You need one of these for it to work. Make sure your network supports this.

Multicast is preferred so it doesn't over-advertise its presence to the network.

The daemon continues multicast and also sends IPv4 broadcasts after five minutes without a confirmed multicast response. This delay is configurable. Both listeners are active from startup.

You may experience some packet loss during the switch-over.

The wireguard ip needs to be accessible
- Some outbound nodes may not advertise their presence over a public IP.


--- 
## Architecture
The daemon is simple. It changes the Wireguard configuration at runtime. No guarantees on packet/network drops. I'm sure there's some optimization possible for faster failover.

## Configuration

Pass the name of one existing WireGuard configuration/interface:

```sh
wireguard-meshd -wireguard wg0 -config /etc/wireguard-mesh/wg0.json
```

`wg0` is the interface created by your existing WireGuard setup, not a path to a `.conf` file. The daemon does not execute `wg-quick`, create interfaces, or change persistent WireGuard configuration.

The known default discovery address is **`239.255.77.77:51823`**. IPv6 discovery uses **`[ff12::5747:4d53]:51823`**. These are multicast destination addresses; do not assign them to an interface. This daemon port is separate from the WireGuard listen port. All participating nodes must use the same daemon port and compatible multicast groups.

Copy [example.json](example.json) and replace its public-key placeholder. For node B:

```json
{
  "address": "10.77.0.2",
  "peers": [
    {"public_key": "C_WIREGUARD_PUBLIC_KEY", "ip": "10.77.0.3"}
  ]
}
```

On C, use C's local tunnel address and B's public key and tunnel address. The `address` must already be assigned to the selected WireGuard interface. Peer keys are WireGuard public keys in base64. An optional `preshared_key` belongs to the new B-to-C relationship; do not copy a hub relationship's preshared key.

The local WireGuard private key is read through `wgctrl`. Do not duplicate it in this file. Protect configuration files, especially when they contain preshared keys.

### Stable Setup

- Start with working B-to-A-to-C tunnel connectivity. A keeps its ordinary WireGuard forwarding configuration and runs no discovery daemon.
- B and C must each permit the other node in their **daemon** peer list. Their stable **WireGuard** peer list contains the hub, not the direct target.
- This version rejects pre-existing direct peers, including peers with empty `AllowedIPs`. This keeps recovery small and avoids saving existing peer secrets.
- Each configured peer has one tunnel host address, in the same address family as the local tunnel address. Only that `/32` or `/128` can move to the direct peer.
- OS routes must already select the named WireGuard interface. Policy-route changes, multipath routing, subnet advertisements, and default-route ownership changes are outside this version.
- Run only one daemon for an interface. Stop other programs that rewrite its managed peers while the daemon runs. WireGuard has no atomic compare-and-change API.

### Options

All JSON settings other than `address` and `peers` have defaults:

| Setting | Default | Function |
|---|---|---|
| `port` | `51823` | Multicast, broadcast, and authenticated unicast UDP port |
| `multicast4` | `239.255.77.77` | IPv4 multicast group |
| `multicast6` | `ff12::5747:4d53` | IPv6 link-local multicast group |
| `include` | `[]` | Optional interface allowlist; permits explicit bridge, VLAN, bond, or test interfaces |
| `exclude` | `[]` | Interfaces that must not participate; takes precedence over `include` |
| `discovery_interval` | `"1m"` | Announcement interval |
| `broadcast_after` | `"5m"` | Delay without multicast confirmation before additional IPv4 broadcasts |
| `probe_interval` | `"1s"` | Authenticated unicast health and latency probes |
| `latency_window` | `"15s"` | Rolling measurement window and direct-path trial window |
| `failure_timeout` | `"5s"` | Failed-path recovery timeout |
| `cooldown` | `"30s"` | Delay before another performance-driven switch |
| `minimum_gain` | `"2ms"` | Minimum absolute RTT improvement |
| `minimum_gain_fraction` | `0.2` | Minimum relative improvement; `0.2` means 20% |

The default interface policy selects addressed physical devices that are up. It excludes the managed WireGuard interface and other virtual devices. Netlink events and periodic refresh handle interface changes. Multicast TTL/hop limit is one. IPv4 broadcast uses the directly attached subnet; IPv6 has no broadcast.

Probe intervals must be 100 ms–1 s. The window must be at least three probe intervals and at most one minute. The failure timeout must be at least two probe intervals and no longer than the window. Discovery intervals must be at least one probe interval and at most five minutes. Broadcast delay and cooldown must each be at least one probe interval.

At least 80% of the window's expected probes must produce responses. A path must meet both improvement thresholds. The lower public key coordinates a trial, so simultaneous discoveries do not start competing trials.

LAN UDP RTT is only an estimate. The daemon first qualifies that estimate against the current tunnel path, then tests the actual direct WireGuard route for a complete window. Both nodes must confirm the result. During a direct connection, tunnel probes measure the direct path, not a fresh hub baseline.

### Recovery And Permissions

The daemon needs `CAP_NET_ADMIN` to read WireGuard keys and change peers. It uses UDP, not raw ICMP. It does not need `CAP_NET_RAW` or `CAP_NET_BIND_SERVICE` with the default port. The capability grants broad network control; it cannot be limited to one WireGuard device by itself.

Permit the daemon UDP port on participating LAN interfaces and inside the tunnel. Also permit the existing WireGuard UDP port on the LAN. The daemon does not change firewall rules.

Before a change, the daemon writes a private recovery journal. The default is `/var/lib/wireguard-mesh-wg0/recovery.json` for `wg0`. Its directory must be owned by the service user with mode `0700`; the journal and lock use mode `0600`. Do not delete an unresolved journal or run another instance with a different journal for the same interface.

On normal shutdown, restore the stable host ownership and remove newly added peers. On startup, recover the previous journal before accepting a new baseline. Conflicting external changes stop optimization and retain the journal instead of blindly overwriting those changes.

For manual recovery, with the same user and capabilities:

```sh
wireguard-meshd -wireguard wg0 -restore
```

`-state PATH` selects a different journal. `-dry-run` performs discovery and measurements without route changes; it refuses an existing journal. A dry run still sends network packets and reads the WireGuard private key. Use only an authorized test network.

Install [wireguard-meshd@.service](wireguard-meshd@.service) on the target Linux host. Place the binary in systemd's executable search path, or use its absolute path in both `ExecStart` and `ExecStopPost`. The template uses a dynamic user, configuration credentials, a private state directory, `CAP_NET_ADMIN`, and a watchdog. Start the existing WireGuard setup before the template instance `wireguard-meshd@wg0.service`. If you use `wg-quick`, add the appropriate ordering dependency in a local unit override.

The watchdog covers an unresponsive daemon. `ExecStopPost` runs journal recovery after process failure. Without a supervisor, a killed process cannot restore its local configuration until recovery is run. Restoring routes cannot repair a failed physical uplink.

### Rosenpass And Runtime Keys

Rosenpass **0.2.3** was tested in file-output mode. Rosenpass negotiates the PSK; `wireguard-meshd` remains the only writer of direct WireGuard peers. Do not use Rosenpass's `device`/`peer` output or the `rp` wrapper on the managed interface.

On B, replace the static peer PSK with a runtime file:

```json
{
  "address": "10.77.0.2",
  "peers": [{
    "public_key": "C_WIREGUARD_PUBLIC_KEY",
    "ip": "10.77.0.3",
    "preshared_key_file": "/run/rosenpass/peer.psk",
    "preshared_key_max_age": "3m"
  }]
}
```

`preshared_key_file` must be absolute. It cannot be combined with `preshared_key`. The optional maximum file age defaults to `3m`; allowed values are `130s` through `3m`. Use the default to allow time for Rosenpass's normal 120–130 second rekey.

The daemon checks the file on each probe tick and before a direct-route change:

- A missing, expired, malformed, unsafe, or all-zero key prevents direct routing. The relay remains available.
- An unchanged valid key does not cause a route change.
- A changed key first restores the relay with the old recovery journal. The daemon then repeats qualification and the direct WireGuard trial with the new key.
- A recovery conflict stops the operation. It does not replace the old journal or overwrite an external WireGuard change.

This method causes a temporary return to the relay on every rekey. It is not an uninterrupted in-place PSK update. With default timers, recovery, cooldown, and qualification can take much longer than the short VM test timers.

For B, use this Rosenpass TOML configuration:

```toml
public_key = "/var/lib/rosenpass/public"
secret_key = "/var/lib/rosenpass/secret"
listen = ["10.77.0.2:51822"]

[[peers]]
public_key = "/var/lib/rosenpass/peer-public"
endpoint = "10.77.0.3:51822"
key_out = "/run/rosenpass/peer.psk"
```

On C, reverse the tunnel addresses and use B's Rosenpass public key. Rosenpass keys are separate from WireGuard keys. Generate them with `rosenpass gen-keys --public-key PATH --secret-key PATH` in a private directory. Exchange public keys through a trusted channel. Never put private keys or PSK output in the Nix store.

Run `rosenpass exchange-config /etc/rosenpass.toml` as a separate service user, without capabilities. Permit UDP port `51822` inside the existing tunnel. The initial exchange can use the relay; no direct LAN endpoint update is required. The test's [service configuration](tests/default.nix) is a working reference.

For the dynamic-user mesh service, use a dedicated shared group such as `mesh-psk`:

```ini
# Drop-in for wireguard-meshd@wg0.service
[Service]
SupplementaryGroups=mesh-psk
```

Give only the Rosenpass producer write access to its runtime directory. Use `Group=mesh-psk`, `RuntimeDirectory=rosenpass`, `RuntimeDirectoryMode=0750`, and `UMask=0027` for that service. Its output will be readable by the mesh group, with mode `0640`. Keep the Rosenpass secret-key directory private to the producer, with mode `0700` and secret files with mode `0600`.

The PSK file must be a regular file, not a symlink. It must contain one canonical base64 WireGuard key, with an optional final newline. Group write, access by others, execute bits, and special permission bits are rejected. The owner must be root, the daemon user, or a producer that shares a daemon group with group-read permission. All parent directories must be trusted; parent symlinks are not checked. Keep the file on a local filesystem so reads cannot block on a network filesystem.

**Freshness limit:** file modification time is not proof of a successful Rosenpass exchange. Rosenpass can write a random replacement key when an exchange becomes stale. Different keys fail the direct tunnel trial and return traffic to the relay. A retained output file can remain usable until the age limit after producer failure. Remove output on service stop and before producer restart; do not restore old output files or refresh their timestamps. A partial in-place write can also cause a safe return to the relay. The daemon does not supervise Rosenpass or consume its exchange-status events.

Rosenpass protects the direct WireGuard relationship only. It does not add post-quantum protection to discovery or to the existing relay links. This fallback policy is not a guarantee of end-to-end post-quantum protection.

### Security Limits

Discovery uses Noise IK with the configured X25519 identities. Packets have a separate protocol domain, directional session keys, counters, and replay windows. Each recipient gets a separately encrypted announcement. Public-key headers and packet timing are visible; multicast does not provide anonymity.

The protocol does not inherit all WireGuard security properties or its optional preshared-key protection. The new peer's preshared key protects WireGuard traffic, not discovery. Identity-key reuse and the complete discovery protocol need independent review before production use.

Resource limits include 128 configured peers, 16 candidate paths per peer, 64 sessions per peer, 512 sessions in total, and 1200-byte packets. These bounds can limit discovery on very large or heavily addressed networks.

IPv6 link-local discovery is available, but link-local **WireGuard endpoints** are not selected: the pinned `wgctrl` Linux encoder omits their scope IDs. Use IPv4 or global/ULA IPv6 LAN addresses for direct routes.

## Build And Test

Run these commands on an authorized Linux test machine. The flake pins nixpkgs and includes a daemon package, a development shell, and four isolated QEMU tests. `flake.lock` and the Go vendor hash are verified build inputs.

Build the daemon:

```sh
nix build path:.#packages.x86_64-linux.default
```

Run the QEMU/KVM tests:

```sh
nix build --no-link --print-out-paths -L --max-jobs 1 \
  path:.#checks.x86_64-linux.relay-only \
  path:.#checks.x86_64-linux.same-lan \
  path:.#checks.x86_64-linux.nat \
  path:.#checks.x86_64-linux.rosenpass
```

The NixOS test driver starts QEMU directly. Libvirt is not required. The builder needs access to `/dev/kvm` and the Nix system features `kvm` and `nixos-test`. It creates isolated virtual Ethernet networks; it does not change host network interfaces, firewall rules, or WireGuard services. Each successful output contains guest journals and key-free network state. See [the test guide](tests/README.md) for details.

For Go development, the shell supplies Go 1.26, a C compiler, and `gopls`:

```sh
nix develop path:.
go build -mod=readonly -trimpath -o wireguard-meshd .
go vet ./...
CGO_ENABLED=1 go test -race -count=1 ./...
go test -run='^$' -fuzz=FuzzSecureReceive -fuzztime=30s -parallel=2 .
```

`path:.` includes new files in an uncommitted checkout. Alternatively, use Go 1.26 and a C compiler without Nix. The race detector requires cgo; a host with no C compiler can disable it by default.

Tests include strict configuration parsing, encrypted packet exchange and replay rejection, fake-clock path selection, broadcast fallback, dry run, one-way loss, blocked WireGuard traffic, separate-LAN safety, journal recovery, and real loopback UDP transport. The separate-LAN test asserts no unsafe route change; it does not implement hole punching.

An additional Linux network-namespace test uses real kernel WireGuard and a three-node topology. It is skipped unless explicitly enabled. On a disposable Linux test machine with `ip`, `wg`, `tc`, `sysctl`, and `ping` installed:

```sh
sudo env PATH="$PATH" WGMESH_NETNS_TEST=1 WGMESH_TEST_BINARY="$PWD/wireguard-meshd" \
  go test -run '^TestNetNSDirectFailover$' -count=1 -timeout=2m .
```

The harness needs root to create isolated network namespaces; the daemon itself does not need this full privilege in deployment. The test creates temporary namespaces, not QEMU guests. It checks hub connectivity, direct activation, and fallback after LAN removal, then cleans up.

The QEMU tests exercise the packaged non-root systemd service, including stop and crash recovery. The namespace test is a separate opt-in check. The QEMU suite does not yet cover watchdog expiry, every planned network fault, or production timing defaults.
