# Direct LAN pairing and experimental NAT traversal

LAN pairing is the main feature. It does not require STUN, ICE, or
`CAP_NET_RAW`. Hole punching is a separate, explicitly experimental option.
An independent security review is still required before production use.

## Automatic direct interface

New configurations use version 2:

```json
{
  "version": 2,
  "address": "10.77.0.2",
  "peers": [
    {"public_key": "C_WIREGUARD_PUBLIC_KEY", "ip": "10.77.0.3"}
  ]
}
```

The daemon creates an unnumbered kernel WireGuard interface with the stable
interface's identity and a different UDP port. Its name is `wgm-<hash>`, with
a suffix on name conflicts. Linux names remain within 15 bytes. A full random
ownership marker is stored in the interface alias and a private journal.
The daemon never adopts an unrelated interface with a matching name.

The kernel selects a free port by default. Set `direct_listen_port` when a
fixed direct port is needed for firewall policy. It must differ from the stable
WireGuard and discovery ports. Neither private keys nor ICE credentials are
written in the recovery journals or logs.

The startup sequence is:

1. Keep application traffic on the stable hub interface, such as `wg0`.
2. Discover and authenticate a LAN peer.
3. Add that peer to the dedicated interface and send WireGuard keepalives.
4. Wait for a real WireGuard handshake and coordinate with the remote node.
5. Add the preferred host route and test actual tunnel traffic.
6. Remove the temporary route and peer on a failed trial or health check.

The stable interface's peer configuration and `AllowedIPs` stay unchanged.
The tunnel IP stays on the stable interface. Both receive paths remain valid
while the nodes switch routes at different times. Shutdown and crash recovery
remove managed routes and peers before deleting the owned interface.

Normal LAN discovery is preferred when both LAN and ICE candidates qualify.
An experimental ICE candidate cannot replace an active healthy LAN path.

### Compatibility and prerequisites

- Configurations without `version`, or with `version: 1`, retain the legacy
  in-place mode unless `direct_interface` is set explicitly.
- In version 2, omitted `direct_interface` means `"auto"`. An explicit empty
  string selects legacy mode. An explicit interface name uses an existing
  operator-created interface, which the daemon does not delete.
- Upgrade both endpoints together. The mesh protocol checks that route modes
  match before changing routes.
- Both WireGuard receive interfaces need loose or disabled IPv4 `rp_filter`.
  The daemon validates this setting; it does not change sysctls or firewalls.
- The first route mode supports IPv4 tunnel host routes in the main table.
  Policy routing, multipath, nonzero direct-interface firewall marks, and
  default-route changes are unsupported.
- The Rosenpass adapter and experimental in-place rekey require legacy mode.
  Static PSKs and PSK files retain possession checks and hub fallback on changes.
- Route mode does not support `-dry-run`. The legacy mode retains its IPv6 and
  dry-run support.

Linux selects the longest matching route prefix before comparing metrics.
The direct route uses `route_metric`, default `50`. If the stable route is
already an exact host route, it must have a greater metric. Conflicts cause
refusal; the daemon does not replace external routes.

## Experimental hole punching

Enable it only when needed:

```json
"nat_traversal": {
  "experimental": true,
  "stun_servers": ["198.51.100.10:3478", "203.0.113.10:3478"],
  "refresh_interval": "20s"
}
```

Use route mode and one to four IPv4 STUN endpoints. The refresh interval
controls authenticated signaling and must be between 1 second and 1 minute.
The NAT underlay must be eligible under the `include` and `exclude` policy.

The implementation uses pinned [Pion ICE](https://github.com/pion/ice) and
[Pion STUN](https://github.com/pion/stun) libraries for gathering, STUN
transactions, authenticated connectivity checks, retries, and pair selection.
It does not implement a second ICE protocol. TCP, mDNS, and TURN candidates
are disabled; the existing hub remains the fallback.

A small Linux raw-socket adapter shares the **actual direct WireGuard port**
with ICE and encrypted mesh probes. Using another UDP port would discover a
different NAT mapping. WireGuard data remains in the kernel. Raw sends refuse
routes through excluded interfaces, WireGuard, or loopback.

ICE credentials and candidates travel only through pairwise-authenticated Noise
sessions over the stable tunnel. A selected ICE pair permits fresh encrypted
mesh probes, not a route change. The normal measurement, PSK, coordinated
WireGuard handshake, trial, and recovery checks still apply.

Healthy direct paths do not require continued STUN or signaling availability.
Failed reachability causes bounded re-gathering attempts. Restrictive or
destination-dependent NATs can prevent punching; hub traffic must remain usable.
The experimental signaling format is not compatible with the earlier custom
traversal prototype. Upgrade both endpoints.

NAT clients need an explicit service override:

```ini
[Service]
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW
```

The base LAN service does not grant the extra capability. STUN/ICE packets are
not private discovery envelopes: they expose transport addresses and protocol
metadata. Limits and authenticated checks do not provide general flood defense.

## STUN service

Use an established STUN service such as [Coturn](https://github.com/coturn/coturn).
For a self-hosted UDP STUN-only instance, an example is:

```sh
turnserver -n --stun-only --no-auth --no-cli --no-tls --no-dtls \
  --listening-ip=198.51.100.10 --listening-port=3478 --log-file=stdout
```

Choose the actual public listen address and firewall policy. `--stun-only`
disables TURN allocations; do not deploy an unauthenticated TURN relay. The old
daemon `-stun-listen` role and custom STUN codec have been removed.

## Ownership and recovery

The existing interface lock covers `recovery.json`, `recovery.json.routes`,
and `recovery.json.interface`. `-restore` does not need the configuration file.
Cleanup validates interface type, alias, index, public identity, port, and
external peer/address/route conflicts. Ambiguous state retains the journal.

Stop other network writers, or make them use the same lock. Linux does not
provide atomic ownership checks for these operations. An alias is an ownership
aid, not protection against a privileged writer. Never delete an unresolved
journal to force startup.

See [tests/README.md](tests/README.md) for the QEMU matrix, measured LAN
activation loss, NAT classifications, fault coverage, and executed results.
