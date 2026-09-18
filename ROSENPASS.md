# Optional Rosenpass Support

Rosenpass negotiates a PSK. `wireguard-meshd` remains the only writer of direct WireGuard peers. Do not use Rosenpass's WireGuard output or the `rp` wrapper on the managed interface.

This adapter supports Rosenpass **0.2.3**, with one mesh peer and one child process per node. Keep hub Rosenpass separate. Use separate mesh keys, output paths, listening ports, and service accounts. More peers will require additional design work; per-peer processes need distinct ports.

## Mesh Configuration

On B, configure the approved C peer:

```json
{
  "address": "10.77.0.2",
  "peers": [{
    "public_key": "C_WIREGUARD_PUBLIC_KEY",
    "ip": "10.77.0.3",
    "preshared_key_file": "/run/wireguard-mesh-rosenpass-wg0/peer.psk",
    "preshared_key_max_age": "3m",
    "rosenpass_socket": "/run/wireguard-mesh-rosenpass-wg0/adapter.sock"
  }]
}
```

On C, use C's tunnel address and B's peer identity. No LAN endpoint is configured here. The lower WireGuard public key selects a confirmed LAN address pair. It reports the choice through the authenticated LAN channel. Each daemon gives its adapter the remote address and the receiving local interface. This happens before the first PSK exists.

Permit discovery, WireGuard, and the mesh Rosenpass UDP port on participating LANs. Rosenpass needs a reachable address to exchange keys. No NAT traversal is provided. A healthy Rosenpass endpoint is retained even if a WireGuard path trial selects another LAN.

`-dry-run` does not contact the adapter or start its child. It still performs ordinary discovery and measurements.

## Adapter Configuration

Use this structure for `/etc/wireguard-mesh/rosenpass-wg0.json` on B:

```json
{
  "executable": "/usr/bin/rosenpass",
  "peer": "C_WIREGUARD_PUBLIC_KEY",
  "public_key_file": "/var/lib/mesh-rosenpass-wg0/public",
  "secret_key_file": "/var/lib/mesh-rosenpass-wg0/secret",
  "peer_public_key_file": "/var/lib/mesh-rosenpass-wg0/peer-public",
  "listen_port": 51822,
  "remote_port": 51822,
  "psk_file": "/run/wireguard-mesh-rosenpass-wg0/peer.psk",
  "runtime_dir": "/run/wireguard-mesh-rosenpass-wg0/private",
  "socket": "/run/wireguard-mesh-rosenpass-wg0/adapter.sock",
  "daemon_uid": 991
}
```

Replace the executable path, peer key, and example UID with the actual values. All paths are absolute. The adapter configuration fixes the peer, keys, ports, and output path. Socket messages cannot change these mappings. Use matching ports on the other node, or reverse unequal local and remote port values.

Generate Rosenpass keys with `rosenpass gen-keys --public-key PATH --secret-key PATH` in a private directory. Exchange public keys through a trusted channel. Never put secret keys or PSKs in the Nix store.

Run the adapter without root privileges or capabilities:

```sh
wireguard-meshd -rosenpass-adapter /etc/wireguard-mesh/rosenpass-wg0.json
```

The adapter invokes Rosenpass directly, without a shell. Version 0.2.3 has no live endpoint-update or reload API. An endpoint change therefore invalidates output and restarts the child. A normal rekey does not restart it.

## Service Permissions

The optional [service template](wireguard-mesh-rosenpass@.service) uses these fixed accounts and group for `wg0`:

- Producer account: `mesh-rosenpass-wg0`.
- Mesh account: `mesh-wg0`, with a fixed UID matching `daemon_uid`.
- Shared group: `mesh-psk-wg0`, containing both accounts.

Create the accounts and group before enabling the service. Give the producer sole write access to its key and runtime directories. Protect its secret directory with mode `0700` and secret files with mode `0600`.

The template creates the runtime parent with mode `0750` and its private child directory with mode `0700`. The socket uses `0660`; published PSKs use `0640`. Linux `SO_PEERCRED` checks the configured daemon UID. Other group members cannot submit endpoint changes. The runtime parent is not writable by the shared group.

Add this override to `wireguard-meshd@wg0.service`:

```ini
[Unit]
Requires=wireguard-mesh-rosenpass@wg0.service
After=wireguard-mesh-rosenpass@wg0.service

[Service]
DynamicUser=no
User=mesh-wg0
SupplementaryGroups=mesh-psk-wg0
```

Before changing an existing service identity, stop it and complete recovery as the old user. Retain any unresolved journal. Arrange private state-directory ownership for the new account after recovery. Do not change an unresolved journal to bypass its ownership checks.

For a manual adapter launch, create its directories first with the same ownership and permissions. The adapter rejects missing or unsafe directories. Keep all output on a local filesystem. Do not share its runtime directory with another adapter or a hub service.

## Status And Reuse

The adapter consumes Rosenpass's exact `exchanged` and `stale` stdout records. A fresh modification time alone is not exchange evidence. Rosenpass can replace an expired exchange key with random bytes.

After an exchanged event, the adapter validates the raw file and publishes a complete PSK through atomic rename. A separate socket response supplies the process instance, process counter, key counter, hash, and expiry. The mesh daemon reads status before and after the file. Both records must match the file hash and remain valid.

- An unchanged, valid PSK is reused without a peer update or child restart.
- A daemon restart can reuse a valid key from an adapter that is still running, after normal journal recovery and discovery.
- An adapter restart invalidates old output. An old file alone cannot establish a valid exchange.
- A stale event invalidates output and stops that child generation. The next endpoint report starts a fresh child.
- Child exit, endpoint change, lost stdout, and expiry also invalidate output.
- Missing or unsafe output returns the direct peer to the stable hub path. Recovery conflicts stop changes and retain the journal.

The stdout event and raw file are not one atomic record. Both nodes therefore confirm key possession independently. Confirmation uses HMACs bound to the operation, transaction token, and sender and receiver identities. Only these proofs cross the authenticated LAN control channel. Neither the PSK nor its unkeyed hash is sent through discovery.

The file checks remain mandatory: canonical nonzero base64, optional final newline, regular file, trusted owner, and restricted permissions. Symlinks, group write, world access, executable bits, and special permission bits are rejected. File age defaults to `3m`; `preshared_key_max_age` permits `130s` through `3m`. The adapter also expires an exchange within three minutes, independently of later file timestamps.

Static `preshared_key` remains supported. It cannot be combined with `preshared_key_file`. Without `rosenpass_socket`, the file-only mode also remains supported, but it cannot detect producer failure or stale events before file expiry. Do not restore old output or refresh its timestamps. Do not copy a hub PSK into the direct relationship. Pre-existing direct WireGuard peers remain unsupported.

## Experimental Rekey

The default policy restores the hub and repeats the direct trial when the key changes. To test PSK-only updates, set `experimental_in_place_rekey` to `true` for the peer on **both** nodes. This requires `preshared_key_file`; it is disabled by default.

Both nodes must advertise support and confirm the new key before either updates WireGuard. The controller journals the old and new hashes before the update. It reads back the installed peer and hash before completing the local transaction. Recovery accepts only the expected hashes, not an unrelated key. A successful PSK-only update retains the peer, endpoint, and AllowedIPs.

Coordination uses `failure_timeout`. The experimental handshake-observation phase has a 90-second limit. Missing key confirmation, failed updates, lost health, invalid output, or observation timeout restores the hub. A completed transaction can answer lost-message retries. A file change during an unfinished update also restores the hub.

New performance-driven path changes wait for 90 seconds after local completion so that retries use the same path. Health failures still cause immediate fallback under the normal timeout rules.

**This is not verified new-PSK handshake protection.** Existing WireGuard transport keys survive a PSK update. An old pending session can also produce a newer `LastHandshakeTime`. The experimental path requires later handshake observations at both nodes, not traffic alone. Its logs explicitly state that the PSK generation remains unverified. The current WireGuard API exposes no handshake-to-PSK generation identifier. Do not enable this experiment in production. Zero packet loss is not promised.

Fallback retains the existing hub configuration. Protect and monitor those hub links separately if the deployment requires post-quantum protection during fallback. Mesh Rosenpass does not protect discovery, validate hub Rosenpass status, or add end-to-end post-quantum protection.

## Verification

The Go tests cover adapter permissions, process and key generations, event ordering, file/status races, LAN selection, confirmation failures, rekey deadlines, and journal recovery.

For a real Rosenpass 0.2.3 exchange, without root privileges:

```sh
ROSENPASS_TEST_EXECUTABLE=/absolute/path/to/rosenpass \
ROSENPASS_TEST_STALE=1 go test -run '^TestRosenpassExecutable$' -count=1 -v -timeout=5m
```

The test uses loopback and temporary keys. It also waits for the natural three-minute stale event.

On an authorized Linux test host, run the kernel prototype as root with `ip`, `wg`, `tc`, and `ping` available:

```sh
WGMESH_REKEY_TEST=1 go test -run '^TestLinuxPSKRekey$' -count=1 -v -timeout=6m
```

It creates and removes isolated network namespaces. It demonstrates working old transport after a PSK mismatch and a post-update timestamp from an old pending key. A separate case blocks handshakes until old transport keys expire, then observes a fresh handshake with matching new PSKs. That controlled experiment preserves endpoints and AllowedIPs. Its timing assumptions are not a production verification guarantee.

The existing Rosenpass QEMU test covers the older file-only mode through the relay. It does not test this LAN adapter or prove the experimental in-place path safe.
