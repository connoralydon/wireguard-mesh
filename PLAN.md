# WireGuard Mesh Plan

Build `wireguard-meshd` as a **Linux-first, decentralized Go service**. Each node discovers trusted peers on its local networks, tests direct paths, and makes temporary WireGuard changes.

The hub remains the stable fallback. It does not need a new service, discovery support, or diagnostic addresses.

This follows the hub example and the runtime configuration model in `README.md`.

## Implementation Constraints

- Use Go and keep the service small. Use one package and one protocol event loop. Do not add a central discovery service, a metrics server, or a general routing framework.
- Require an explicit WireGuard configuration/interface name with `-wireguard NAME`. Do not select a device automatically.
- Use the known default discovery address `239.255.77.77:51823`. Keep the multicast groups and port configurable.
- Provide a Nix development flake and isolated QEMU tests. Run builds and verification on an authorized Linux machine.
- Local QEMU/KVM testing is now authorized. Four implemented scenarios have passed; see `tests/README.md`. The larger matrix below remains the target, not a claim that every case has run.
- The first implementation supports one tunnel host address per peer and existing OS routes through the named Linux kernel WireGuard interface. Direct peers must not already exist in the stable WireGuard configuration. Their identities belong in the daemon's local peer list.
- Do not install IPv6 link-local WireGuard endpoints while the pinned control library omits their scope IDs. IPv4 and global/ULA IPv6 endpoints remain candidates. Link-local multicast discovery remains enabled.
- Unit tests, protocol simulations, UDP tests, fuzz tests, race tests, and opt-in Linux network-namespace tests supplement QEMU tests. Do not claim a test passed without executing it on an authorized machine.

## Important Constraints

1. **Discovery is separate from WireGuard.** The daemon uses ordinary UDP for multicast, broadcast, and probe messages. It uses the WireGuard control API to change peers and `AllowedIPs`.
2. **Private-key encryption with public-key decryption is not the correct model.** WireGuard uses X25519 keys for key agreement, not digital signatures. Discovery must use authenticated encryption. Each receiver also needs its own private key.
3. **A hub-only configuration does not identify all other nodes.** If B knows only A's public key, B cannot authenticate C. Each node must have a local configuration that maps permitted direct peers' public keys to their tunnel addresses.
4. **Route changes can cause brief packet loss.** In the hub configuration, both ends must coordinate because `AllowedIPs` controls outgoing peer selection and incoming source validation.

## Go Packages

These packages provide the required functions:

| Package | Purpose | Recommendation |
|---|---|---|
| [`golang.zx2c4.com/wireguard/wgctrl`](https://pkg.go.dev/golang.zx2c4.com/wireguard/wgctrl) | Read and change WireGuard devices and peers | Use as the main WireGuard API |
| `golang.zx2c4.com/wireguard/wgctrl/wgtypes` | Keys, peer settings, endpoints, and `AllowedIPs` | Use with `wgctrl` |
| [`github.com/vishvananda/netlink`](https://github.com/vishvananda/netlink) | Linux interface events, addresses, and routes | Use for interface detection and necessary route changes |
| [`golang.org/x/net/ipv4`](https://pkg.go.dev/golang.org/x/net/ipv4) and `ipv6` | Multicast groups, interface selection, and packet metadata | Use for discovery sockets |
| [`github.com/flynn/noise`](https://pkg.go.dev/github.com/flynn/noise) | Authenticated key exchange and encryption | Candidate for the discovery protocol; review before production |
| [`golang.zx2c4.com/wireguard`](https://github.com/WireGuard/wireguard-go) | A complete userspace WireGuard implementation | Not needed for the Linux version |

`wgctrl` configures existing WireGuard devices. It does **not** manage OS routes or interface addresses. It provides handshake times and byte counters, but **no RTT measurement**.

## 1. Configuration

Use one predefined daemon UDP port, with a configuration override. Keep this separate from the existing WireGuard UDP port.

Proposed defaults:

| Setting | Default |
|---|---|
| WireGuard interface | Explicit configuration, for example `wg0` |
| Daemon UDP port | `51823`, proposed application default |
| IPv4 multicast group | `239.255.77.77`, configurable |
| IPv6 multicast group | Configurable link-local multicast group |
| Multicast TTL / hop limit | `1` |
| Discovery interval | `1m` |
| Broadcast fallback delay | `5m` |
| Interface selection | All eligible physical interfaces |
| Unicast probe interval | `1s` |
| Latency window | `15s` |
| Path failure timeout | `5s`, configurable |
| Minimum improvement | Proposed: both `20%` and `2ms`, configurable |
| Switch cooldown | Proposed: `30s`; does not delay failure recovery |

Also configure each permitted direct peer's public key and tunnel host addresses. Include a direct-peer preshared key if required.

For the first version, optimize node addresses using `/32` and `/128` entries. Do not automatically accept advertised subnets or default routes.

## 2. Interface Discovery

At startup, inspect all physical interfaces.

- Select interfaces that are up and have a usable IP address.
- Include Ethernet and Wi-Fi.
- Exclude loopback, WireGuard, tunnels, and container interfaces by default.
- Use Linux device information, not interface-name patterns, to identify physical interfaces.
- Allow explicit include and exclude lists.
- Allow explicit inclusion of bridges, bonds, and VLANs. These can hold the IP address instead of the physical interface.
- Track link and address changes through netlink.
- Rejoin multicast groups and reset discovery state when an interface changes networks.
- Remove candidates immediately when their local interface or source address disappears.

Inspect every eligible interface independently. A working Wi-Fi path must not prevent discovery on Ethernet.

Select the source address and outgoing interface explicitly. Use received interface metadata to check incoming packets.

## 3. Multicast And Broadcast

Open listeners at startup and keep them active until shutdown.

**Listen for multicast, broadcast, and unicast from the start.** The five-minute delay controls broadcast transmission, not reception. This lets nodes with different startup times discover each other.

Discovery behavior:

1. Send an initial multicast announcement.
2. Repeat discovery every minute on each eligible interface.
3. Require an authenticated response tied to the announcement. A successful UDP send does not prove multicast works.
4. After five minutes without multicast confirmation for a peer on an interface, also send that peer's discovery messages by broadcast.
5. Continue multicast when broadcast is active.
6. Use the same encryption and authentication for both transports.

Track this state per interface and peer. One reachable peer must not prevent broadcast discovery of another peer.

For IPv4 broadcast, use each directly attached subnet's broadcast address. Skip interfaces and prefixes that have no usable broadcast address. Do not send broadcasts through routers.

IPv6 has no broadcast. On IPv6-only interfaces, continue multicast and report that broadcast fallback is unavailable.

**Silence cannot distinguish blocked multicast from an absent peer.** The timeout means "no confirmed multicast discovery," not "multicast is proven broken."

For a simple first policy, keep broadcast enabled for that peer and interface until the local network changes or the service restarts.

## 4. Packet Security

Use a separate authenticated protocol based on **Noise IK with X25519**, subject to security review.

- Use the local WireGuard identity and the configured remote public key.
- Give the protocol its own version and Noise prologue. Do not reuse WireGuard session keys or packet formats.
- Send a separately encrypted discovery message for each permitted recipient.
- Encrypt the complete header in a directional, static-X25519/HKDF-derived XChaCha20-Poly1305 envelope. Use fresh random nonces and fixed 512-byte UDP payloads. Do not expose public keys or a stable recipient tag.
- Require version 2 envelopes, with no plaintext-header fallback. Bound trial decryption across configured peers before processing the inner packet.
- Complete the response and confirmation exchange through unicast on the daemon port.
- Check the authenticated peer identity against the local configuration before creating a candidate.
- Accept endpoint candidates only on the receiving local network, using the observed source address and an authenticated advertised WireGuard port.
- Never accept new trusted keys or route ownership from an announcement.

With pairwise encryption, a discovery cycle needs approximately one message per configured recipient per interface. A single message readable by every trusted node would require a different group-key design.

The protocol must also define:

- Random session identifiers and challenges.
- Explicit packet counters and replay protection.
- Handling for lost, reordered, and duplicate UDP packets.
- Session expiry and restart behavior.
- Packet-size limits and bounded pending handshakes.
- Rate limits for processing and responses.

A recorded announcement must not change a route or keep a failed candidate alive. Require a fresh challenge response.

Noise provides cryptographic building blocks, not the complete discovery protocol. Key reuse, packet framing, and replay handling need a separate review. Initial discovery messages must not be described as having the same forward-secrecy protection as an established session.

The static-key envelope hides headers from outsiders but is not post-quantum or forward-secret after identity-key compromise. Network addresses, counts, and timing remain observable. Padding is not an anonymity guarantee. See the README for the current wire format and coordinated upgrade requirements.

## 5. Latency Measurement

Keep discovery traffic at one-minute intervals. Use **separate authenticated unicast probes every second** for latency and health checks.

Before a route change, measure:

- The current path through the existing WireGuard tunnel and hub.
- Each discovered LAN path through the daemon's UDP port.

Maintain a 15-second rolling window per candidate. Use median RTT and packet-loss measurements. Require a full window and enough successful samples before selecting a path.

Use local monotonic time to measure RTT. Do not depend on synchronized clocks.

The improvement threshold and cooldown prevent frequent changes when paths have similar latency.

**Measurement limitation:** A LAN UDP probe estimates direct-path latency. It does not prove the WireGuard port is reachable or measure the exact direct WireGuard path. Without extra addresses or a second tunnel, that path needs a temporary route trial.

After the LAN candidate qualifies:

1. Coordinate a short trial with the remote node.
2. Install the temporary direct WireGuard configuration.
3. Confirm authenticated probe responses through the actual tunnel.
4. Measure the direct tunnel over a full 15-second window.
5. Keep the route only if the measured result satisfies the policy. Otherwise, restore the stable configuration.

Use a short failure timeout during the trial. Do not wait 15 seconds if no tunnel traffic can pass.

Once traffic is direct, a probe to the same tunnel address also takes the direct path. The service must not report it as a fresh hub measurement. A new hub measurement requires a coordinated return to the stable path.

## 6. Route Changes

For the README example:

```text
Stable:  B -> A -> C
Direct:  B ------> C
```

B and C run the daemon. A continues its existing forwarding function.

On both B and C:

- Add or prepare the locally authorized direct peer.
- Set its endpoint to the discovered LAN address and WireGuard port.
- Assign only the permitted tunnel host addresses to it.
- Change OS routes only when the existing route does not already select the correct WireGuard interface.
- Preserve unrelated peers, keys, keepalive settings, and routes.

If A owns a broad prefix, a more-specific host entry can select the direct peer.

If A owns the exact host entry, assigning that entry to C transfers its ownership. Recovery must explicitly restore it to A. Removing C alone is not sufficient.

Use one serialized configuration writer per WireGuard interface. Check each applied change and record enough information to reverse partial updates. Do not assume a multi-peer update is fully transactional.

Use authenticated prepare, ready, and commit messages with a short-lived trial identifier. Resolve simultaneous proposals deterministically.

Both nodes must expire a direct-path lease unless bidirectional health checks renew it. Include acknowledgments of recent probes so one-way connectivity does not keep the route active.

## 7. Stable Recovery

Keep the stable baseline separate from discovered runtime state.

- Record the original managed settings before the first change.
- Write a protected recovery journal before applying changes.
- Never replace the baseline with the current optimized configuration after a restart.
- Do not write temporary paths to the persistent WireGuard configuration.
- Restore only settings the daemon owns.
- Detect external configuration changes. Stop optimization for conflicting entries instead of overwriting them.

Restore the stable path when:

- The selected physical interface or address disappears.
- Direct tunnel probes fail for the configured timeout.
- The peer's lease expires.
- A route trial or configuration update fails.
- The service stops.

Start local recovery immediately on a link-down event. Otherwise, target recovery after the five-second health timeout, plus configuration time.

A crashed process cannot undo its own changes. Provide systemd cleanup and startup recovery from the journal. Test both process crashes and unresponsive processes.

During an asymmetric failure, one node can recover before the other. Expiring leases must return both ends to the hub without requiring a working LAN connection.

Restoring the configuration does not restore a failed uplink. The stable path must still be physically reachable.

## 8. Permissions

For Linux kernel WireGuard:

| Operation | Required access |
|---|---|
| List interfaces and addresses | Normally no elevated capability |
| Join multicast groups and use UDP on a high port | Normally no elevated capability |
| Send IPv4 broadcast | `SO_BROADCAST`; no special capability |
| Read WireGuard configuration, including private keys | `CAP_NET_ADMIN` |
| Change WireGuard peers and `AllowedIPs` | `CAP_NET_ADMIN` |
| Change OS routes or addresses | `CAP_NET_ADMIN` |
| Use raw ICMP probes | Usually `CAP_NET_RAW`; avoid by using UDP |
| Bind a privileged port | `CAP_NET_BIND_SERVICE`; avoid with the default port |

Run the service as a dedicated user with **`CAP_NET_ADMIN`**, not unrestricted root. The capability must apply to the network namespace containing the managed device.

`CAP_NET_ADMIN` grants broad network control. It cannot restrict the daemon to one WireGuard interface. The service must enforce that restriction itself.

Use systemd restrictions, protected configuration and state files, and disabled core dumps. Do not log private keys, preshared keys, or full device structures.

Firewall configuration must permit:

- The daemon UDP port on selected LAN interfaces.
- The WireGuard UDP port for direct LAN traffic.
- Probe traffic inside the existing tunnel.
- Required multicast membership traffic where filtering applies.

Do not automatically weaken firewall rules.

The [Linux WireGuard sources](https://github.com/torvalds/linux/blob/master/drivers/net/wireguard/generated/netlink.c) require administrative access for both WireGuard read and write operations. The [`ip(7)` documentation](https://man7.org/linux/man-pages/man7/ip.7.html) confirms that `SO_BROADCAST` is not privileged. [`capabilities(7)`](https://man7.org/linux/man-pages/man7/capabilities.7.html) documents the capability boundaries.

## Implementation Order

1. Define configuration, trust rules, protocol messages, and the route state machine. Update the README's unsupported broadcast-fallback statement.
2. Build read-only device inspection, physical-interface discovery, and configuration validation.
3. Implement encrypted multicast, continuous listeners, and timed broadcast transmission.
4. Add authenticated probes, rolling measurements, and a mode that reports proposed changes without applying them.
5. Implement coordinated WireGuard trials, narrow route updates, and stable recovery.
6. Add systemd packaging, crash recovery, and operational status output.
7. Test with three Linux network namespaces representing A, B, and C.
8. Use QEMU Linux guests for the supported same-LAN scenarios below. Keep the two-LAN hole-punching scenario separate from acceptance of the supported mode.

Acceptance tests should cover multicast success, blocked multicast, different startup times, multiple interfaces, LAN loss, one-way loss, blocked WireGuard traffic, route oscillation, duplicate packets, unknown keys, process crashes, and external configuration changes.

Use real kernel WireGuard and controlled delay/loss in integration tests. Unit-test timers and route decisions with a fake clock.

## QEMU Tests

The implemented `relay-only`, `same-lan`, `nat`, and `rosenpass` checks have passed on Linux x86-64 with KVM. They include a real Rosenpass exchange and natural rekey. See [tests/README.md](tests/README.md) for the executed scope and remaining coverage.

Use QEMU in addition to network-namespace tests. Run real kernel WireGuard and the packaged systemd service inside Linux guests. Test the service with its documented user and capabilities.

Create isolated virtual Ethernet networks for the LAN and simulated WAN. Do not depend on QEMU's default user-mode NAT for multicast or broadcast delivery. Present Ethernet adapters to the guests and verify that default interface detection selects all eligible adapters without an explicit include list.

### Supported Mode

Use three nodes: hub A on the simulated WAN, and B and C on a shared LAN. Give B and C stable paths to A. Apply controlled delay to the hub path so the direct LAN path has a measurable advantage. A must not run the discovery service.

| Scenario | Required result |
|---|---|
| Multicast discovery | B and C discover each other on the configured group and UDP port. After latency qualification and a successful WireGuard trial, application traffic uses the direct LAN path. |
| Broadcast fallback | Block discovery multicast but permit broadcast. Verify that broadcast transmission starts only after the configured delay. Use different service startup times to check that broadcast listeners are active before transmission starts. Multicast attempts must continue. |
| Multiple interfaces | Give B and C more than one addressed Ethernet adapter, with different path delays. Verify discovery on every eligible interface and selection of the better path after the rolling window. Small or brief improvements must not cause repeated route changes. |
| LAN failure | Disconnect the selected LAN adapter or drop direct-path traffic while the hub path remains reachable. Verify recovery to the initial stable configuration. Include one-way loss and a blocked WireGuard port with the discovery port still reachable. |
| Service failure | Stop, kill, and make a daemon unresponsive while a direct path is active. Verify cleanup, lease expiry, and startup recovery. The optimized state must not become the new stable baseline. |

Use tunnel probes, route and peer state, and packet captures to confirm the actual traffic path. A successful discovery response alone is not sufficient.

Run at least one scenario with the default one-minute discovery interval and five-minute broadcast delay. Other scenarios can use documented shorter timer overrides. Record timing, packet loss, route changes, and recovery results. Clean up guests and isolated networks after each run.

### Unsupported Hole Punching

Add a separate QEMU scenario with B and C on two different LANs. Put each LAN behind its own NAT router and connect both routers to a simulated WAN containing A.

```text
LAN 1: B -> NAT 1 -> simulated WAN <- NAT 2 <- C :LAN 2
                              |
                              A
```

Do not forward discovery multicast or broadcast between the LANs. Do not add inbound port forwarding or a preconfigured direct B-to-C endpoint that would bypass hole punching.

Verify that the initial B-to-A-to-C WireGuard path remains usable and that failed discovery does not damage it. This is a required passing safety check.

Record direct B-to-C connectivity through NAT hole punching as a separate **expected failure**. This capability does not work in the current design. It is **not an implementation goal or a release requirement**.

Do not add NAT traversal, endpoint exchange, or a rendezvous service to make this scenario pass. An expected-failure marker must apply only to the unsupported direct-path check, not to guest setup, network isolation, or the stable-path safety check.
