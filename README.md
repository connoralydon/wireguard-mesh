# wireguard-mesh

`wireguard-meshd` is a small Linux Go service for direct LAN paths between trusted WireGuard nodes. See [PLAN.md](PLAN.md) for the design.

**Status:** the Go checks and six QEMU/KVM integration tests have passed on Linux x86-64. The VM tests cover relay-only operation, direct LAN operation, interface-loss recovery, separate NAT networks, Rosenpass file output, the LAN adapter, and experimental rekey. Passing tests do not prove which PSK established a WireGuard handshake. See [tests/README.md](tests/README.md) for commands and limits. An independent security review is still required before production use.

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

To replace an active direct path, the daemon compares the candidate's LAN UDP RTT with the active path's LAN UDP RTT. Equal address aliases do not qualify because of WireGuard overhead. A pending replacement keeps the active route, health probes, and approvals unchanged. A refused proposal, missing coordination messages, or a failed candidate cancels only the pending replacement. The old route stays installed while it remains healthy. A key transition cancels the pending replacement before the existing key policy runs.

The commit boundary is not atomic across nodes. After a valid `ready`, the leader completes local preflight and applies the replacement before it sends `commit`. The follower applies only after a valid `commit` and its own preflight. Proposal deadlines include time spent in key checks and preflight. The trial clock starts after successful application.

During a replacement trial, each node retains one previous active route. An abort or failed trial restores that endpoint and its protocol state if the old LAN path still responds. This update does not delete the peer or rewrite its PSK or host route. The old WireGuard endpoint cannot be measured while the new endpoint is installed. After rollback, a new tunnel reply must arrive within the normal failure timeout, or the daemon restores the hub. A missing old interface, failed old LAN path, remote abort of the old route, or key change prevents rollback to that route. Confirmation of the replacement trial releases the saved route. Abort replies use the failed token and do not form a reply loop.

Cancelled and refused tokens are retained for 13 minutes after local retirement. This covers the ten-minute secure-session lifetime plus the supported remote retry bounds: one minute for coordination and two minutes for trial confirmation. A remote peer can retry in a later Noise session before its own timeout. The extra retention rejects those delayed, previously unreceived messages after cooldown. Each peer has at most 1,024 retired tokens. If this bound is reached, new proposals are blocked until the full 13-minute retention period passes without another blocked proposal. Active-route health checks continue. A trusted peer must use a new random token for a new transaction; this cache does not prevent a trusted peer from deliberately reusing tokens after the retention period.

The protocol version 2 messages, PSK proofs, single-owner controller, and journal format are unchanged. Older version 2 daemons can exchange these messages, but do not have these route and replay protections. Kernel update errors and daemon restart still use the existing journal recovery rules.

### Recovery And Permissions

The daemon needs `CAP_NET_ADMIN` to read WireGuard keys and change peers. It uses UDP, not raw ICMP. It does not need `CAP_NET_RAW` or `CAP_NET_BIND_SERVICE` with the default port. The capability grants broad network control; it cannot be limited to one WireGuard device by itself.

Permit the daemon UDP port on participating LAN interfaces and inside the tunnel. Also permit the existing WireGuard UDP port on the LAN. The daemon does not change firewall rules.

Before a change, the daemon writes a private recovery journal. The default is `/var/lib/wireguard-mesh-wg0/recovery.json` for `wg0`. Its directory must be owned by the service user with mode `0700`; the journal and lock use mode `0600`. Do not delete an unresolved journal or run another instance with a different journal for the same interface.

On normal shutdown, restore the stable host ownership and remove newly added peers. On startup, recover the previous journal before accepting a new baseline. Conflicting external changes stop optimization and retain the journal instead of blindly overwriting those changes.

An abrupt reboot can remove the direct peer before journal recovery. Recovery accepts this state only when the interface identity and stable owner match the journal. It checks the recorded prefix as well. Conflicting state retains the journal and stops recovery. Do not delete the journal to make startup succeed.

For manual recovery, with the same user and capabilities:

```sh
wireguard-meshd -wireguard wg0 -restore
```

`-state PATH` selects a different journal. `-dry-run` performs discovery and measurements without route changes; it refuses an existing journal. A dry run still sends network packets and reads the WireGuard private key. Use only an authorized test network.

Install [wireguard-meshd@.service](wireguard-meshd@.service) on the target Linux host. Place the binary in systemd's executable search path, or use its absolute path in both `ExecStart` and `ExecStopPost`. The template uses a dynamic user, configuration credentials, a private state directory, `CAP_NET_ADMIN`, and a watchdog. Start the existing WireGuard setup before the template instance `wireguard-meshd@wg0.service`. If you use `wg-quick`, add the appropriate ordering dependency in a local unit override.

The watchdog covers an unresponsive daemon. `ExecStopPost` runs journal recovery after process failure. Without a supervisor, a killed process cannot restore its local configuration until recovery is run. Restoring routes cannot repair a failed physical uplink.

### Rosenpass And Runtime Keys

Rosenpass support is optional. The separate, unprivileged adapter supports **Rosenpass 0.2.3** and one mesh peer per node. Discovery supplies an authenticated LAN address before a PSK exists. The adapter does not use the hub's Rosenpass process.

An existing valid PSK is reused. Normal Rosenpass rekeys do not restart the process. Endpoint changes, process failure, expiry, and `stale` events invalidate its output. Both nodes must confirm key possession before a direct-path change. The PSK is not sent through discovery.

The default key-change policy still returns to the stable hub path before a new direct trial. In-place rekey is an explicit experiment, disabled by default. A newer handshake timestamp does not prove which PSK created the session. The Linux prototype demonstrates this limit; zero packet loss is not promised.

See [ROSENPASS.md](ROSENPASS.md) for configuration, fixed account permissions, exchange status, PSK reuse, experimental rekey, and test commands. Existing `preshared_key` and `preshared_key_file` configurations remain available without the adapter. Upgrade both nodes together when using PSKs: older daemons do not send the new possession proofs.

### Discovery Privacy

Protocol version 2 encrypts the complete daemon packet, including its header. Sender and recipient WireGuard public keys, message type, version, session ID, counters, and control contents are not sent in plaintext. This applies to multicast, broadcast, LAN unicast, and tunnel probes.

No additional secret is required. Each node derives a pairwise secret with X25519 from its existing WireGuard private key and the configured peer public key. HKDF-SHA256 derives separate sending and receiving keys:

```text
shared = X25519(local_private, peer_public)
key(sender, recipient) = HKDF-SHA256(
    IKM  = shared,
    salt = ASCII("wireguard-mesh/envelope/v2"),
    info = sender_public[32] || recipient_public[32],
    L    = 32)
```

Every UDP payload is exactly **512 bytes**. A fresh random 24-byte nonce precedes an XChaCha20-Poly1305 encrypted record and its 16-byte authentication tag. The encrypted record contains a two-byte big-endian inner length, the inner Noise packet, and zero padding. The associated data is the ASCII envelope domain above. There is no plaintext version marker or stable recipient tag. The maximum inner packet is 470 bytes; the maximum control body is 364 bytes.

The receiver tries only configured peer keys, with a bounded work budget. It verifies the outer sender binding before the inner Noise protocol can change session state. Noise still performs its own authentication, replay checks, expiry, and key confirmation. The envelope does not replace those checks.

**Upgrade all participating daemons together.** Version 1 plaintext-header packets are rejected, with no compatibility fallback. Stop the old daemons and complete journal recovery before replacing them. Keep the stable hub links available during the update. Configuration and WireGuard keys do not need to change. Mixed versions cannot establish mesh discovery sessions.

### Security Limits

Discovery uses Noise IK with the configured X25519 identities inside the encrypted envelope. Each recipient gets a separate announcement. **This remains classical cryptography, not post-quantum protection.** Neither the WireGuard PSK nor Rosenpass protects discovery.

IP and MAC addresses, UDP ports, packet counts, and timing remain visible. Fixed size hides application length and explicit message types, but traffic patterns can still reveal communication relationships. Recorded requests can cause unconfirmed replies after session expiry. This is header privacy, not anonymity or resistance to traffic analysis.

The outer envelope is not forward-secret. With the other peer's public key, compromise of either endpoint's WireGuard private key permits decryption of that pair's recorded outer headers. This does not by itself recover completed Noise session payloads. The envelope does not change WireGuard's own packet format, Rosenpass packets, or application traffic.

The protocol does not inherit all WireGuard security properties or its optional preshared-key protection. The new peer's preshared key protects WireGuard traffic, not discovery. Identity-key reuse and the complete discovery protocol need independent review before production use.

Resource limits include 128 configured peers, 16 candidate paths per peer, 64 sessions per peer, and 512 sessions in total. Outer decryption is limited to 131,072 key attempts per fixed one-second window. Successful attempts, rejected packets, and multicast packets for other recipients all consume this budget. At 128 configured peers, 1,024 unaddressed packets can consume a full window. The limiter permits bursts across window boundaries; it does not guarantee availability under a flood. These bounds and packet padding can limit discovery on large or heavily addressed networks. No claim is made that every maximum peer, interface, and probe-rate setting works together.

IPv6 link-local discovery is available, but link-local **WireGuard endpoints** are not selected: the pinned `wgctrl` Linux encoder omits their scope IDs. Use IPv4 or global/ULA IPv6 LAN addresses for direct routes.

## Build And Test

Run these commands on an authorized Linux test machine. The flake pins nixpkgs and includes a daemon package, a development shell, and six isolated QEMU tests. `flake.lock` and the Go vendor hash are verified build inputs.

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
  path:.#checks.x86_64-linux.rosenpass \
  path:.#checks.x86_64-linux.rosenpass-adapter \
  path:.#checks.x86_64-linux.rosenpass-rekey
```

The NixOS test driver starts QEMU directly. Libvirt is not required. The builder needs access to `/dev/kvm` and the Nix system features `kvm` and `nixos-test`. It creates isolated virtual Ethernet networks; it does not change host network interfaces, firewall rules, or WireGuard services. Each successful output contains guest journals and key-free network state. See [the test guide](tests/README.md) for details.

For Go development, the shell supplies Go 1.26, a C compiler, and `gopls`:

```sh
nix develop path:.
go build -mod=readonly -trimpath -o wireguard-meshd .
go vet ./...
CGO_ENABLED=1 go test -race -count=1 ./...
go test -run='^$' -fuzz=FuzzSecureReceive -fuzztime=30s -parallel=2 .
go test -run='^$' -fuzz=FuzzSecureInnerReceive -fuzztime=30s -parallel=2 .
```

`path:.` includes new files in an uncommitted checkout. Alternatively, use Go 1.26 and a C compiler without Nix. The race detector requires cgo; a host with no C compiler can disable it by default.

Tests include strict configuration parsing, whole-packet privacy, KDF vectors, malformed envelopes, replay rejection, entropy failures, receive-work limits, fake-clock path selection, broadcast fallback, dry run, one-way loss, blocked WireGuard traffic, separate-LAN safety, journal recovery, and real loopback UDP transport. The separate-LAN test asserts no unsafe route change; it does not implement hole punching. The shared-LAN VM test captures multicast, broadcast, and unicast packets and checks their size and absence of plaintext identities.

An additional Linux network-namespace test uses real kernel WireGuard and a three-node topology. It is skipped unless explicitly enabled. On a disposable Linux test machine with `ip`, `wg`, `tc`, `sysctl`, and `ping` installed:

```sh
sudo env PATH="$PATH" WGMESH_NETNS_TEST=1 WGMESH_TEST_BINARY="$PWD/wireguard-meshd" \
  go test -run '^TestNetNSDirectFailover$' -count=1 -timeout=2m .
```

The harness needs root to create isolated network namespaces; the daemon itself does not need this full privilege in deployment. The test creates temporary namespaces, not QEMU guests. It checks hub connectivity, direct activation, and fallback after LAN removal, then cleans up.

The QEMU tests exercise the packaged non-root systemd service, including stop and crash recovery. The namespace test is a separate opt-in check. The QEMU suite does not yet cover watchdog expiry, every planned network fault, or production timing defaults.
