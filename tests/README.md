# QEMU Integration Tests

These tests use the NixOS test driver, QEMU/KVM, real kernel WireGuard, and the repository's systemd service templates. The mesh daemon runs as a non-root user with `CAP_NET_ADMIN`. The adapter cases use a fixed daemon UID for socket authentication; other cases use a dynamic user. Rosenpass and its adapter run as a separate user, without capabilities.

## How QEMU Is Used

These are full VM integration tests, not mocked network tests or containers. The NixOS test driver starts QEMU directly; it does not use libvirt.

1. [The flake](../flake.nix) builds the Go daemon and exposes six mesh checks plus an IPv6 transport check. [default.nix](default.nix) and [ipv6.nix](ipv6.nix) use `pkgs.testers.runNixOSTest`. Their `qemu.forceAccel = true` setting requires KVM hardware acceleration.
2. The driver starts three guests for the relay-only, shared-LAN, and Rosenpass cases: relay A and nodes B and C. The NAT case adds two router guests. Each guest has its own Linux kernel, interfaces, WireGuard state, and systemd services.
3. The guests connect through isolated virtual Ethernet networks. The `vlan` numbers in the test configuration identify these test networks; they do not configure VLANs on the host's physical network. Initially, B and C have only A as their WireGuard peer. A forwards their tunnel traffic.
4. [base.py](base.py) controls the guests through the Python test driver. Commands such as `b.succeed("ip link set lan down")` run inside guest B. [guest.py](guest.py) creates the real WireGuard interfaces, test keys, routes, and NAT rules. Setup commands run as root inside the guests; the mesh daemon runs through its non-root systemd service.
5. The driver checks traffic and WireGuard state, introduces faults, and waits for recovery. Successful pings alone are not sufficient: direct operation also requires the correct peer, endpoint, handshake, and increased direct-peer byte counters. [rosenpass.py](rosenpass.py) and [adapter.py](adapter.py) use actual Rosenpass processes and natural rekeys. [recovery.py](recovery.py) tests interface recreation with an active recovery journal.
6. A failed command or assertion fails the Nix test build. Successful outputs retain guest journals and network-state records. The driver stops the guests after the test.

The shared-LAN case has this topology:

```text
             Simulated WAN
           B ----- A ----- C
           |     relay     |
           +-- shared LAN--+
```

The test adds delay inside relay A so that the direct LAN route has a measurable advantage. It then removes the LAN connection or kills the daemon to check recovery through A. Host network interfaces, firewall rules, and WireGuard services are not changed.

## Run

From the repository root on an authorized Linux x86-64 machine:

```sh
nix build --no-link --print-out-paths -L --max-jobs 1 \
  path:.#checks.x86_64-linux.relay-only \
  path:.#checks.x86_64-linux.same-lan \
  path:.#checks.x86_64-linux.nat \
  path:.#checks.x86_64-linux.rosenpass \
  path:.#checks.x86_64-linux.rosenpass-adapter \
  path:.#checks.x86_64-linux.rosenpass-rekey \
  path:.#checks.x86_64-linux.ipv6-transport
```

The builder needs access to `/dev/kvm` and Nix system features `kvm` and `nixos-test`. Hardware acceleration is required. Libvirt is not used. Allow approximately 4 GiB of guest memory for the largest test, plus host overhead. The first build must download the guest dependencies.

Nix reuses successful results for unchanged inputs. To execute an unchanged check again, add `--rebuild` to its `nix build` command. Do not use `--rebuild` to compare logs byte for byte: runtime timestamps and generated test keys differ.

For example, force a fresh QEMU run of the shared-LAN test:

```sh
nix build --rebuild --no-link -L \
  path:.#checks.x86_64-linux.same-lan
```

## Opt-in CPU Profiles

The profiling packages are separate from the seven safety checks. They add a
loopback-only pprof listener to a test build. The normal daemon has no profiling
listener, and the normal timing defaults are unchanged.

```sh
nix build --no-link --print-out-paths -L --max-jobs 1 \
  path:.#packages.x86_64-linux.cpu-profile
nix build --no-link --print-out-paths -L --max-jobs 1 \
  path:.#packages.x86_64-linux.cpu-profile-rosenpass
```

The first target captures three 60-second samples on each daemon for default
idle operation, default timers with TCP traffic, and the fast test timers. The
Rosenpass target captures three 60-second samples of both daemons and both
adapters at default timers, with experimental rekey enabled. These are steady
samples before a rekey: each requires an unchanged PSK and producer processes,
with no relay fallback. They do not test a live rekey or prove which PSK
established a WireGuard handshake. Each daemon has one mesh peer; these are not
maximum-size benchmarks.

The output contains `b/mesh-artifacts/cpu-results.json`, CPU and allocation
profiles in both node directories, traffic results, and syscall count summaries.
CPU use is a percentage of one core, from process user and system CPU counters.
Allocation rates use Go runtime counters. Syscall tracing runs **after** each
timed capture; it records counts, not arguments. The tests check direct peer
state, increasing traffic counters, unchanged process IDs, and relay recovery
on service stop.

For a paired comparison, import [profile.nix](profile.nix) with `pkgs`, `mesh`
(the candidate package), and `baseline` (the reference package). Use
`mode = "rosenpass-rekey"` for the adapter case. The driver alternates package
order between repetitions and records both package paths in
`b/mesh-artifacts/profile-builds.json`. Run other builds and VM checks before
profiling so their load cannot affect the comparison. Compare repeated CPU
counter measurements as well as sampled functions; VM scheduling, CPU
frequency, and clock costs can affect individual runs.

With distributed builders, `--max-jobs 1` does not serialize remote VM checks.
Run one check per build when timing or CPU measurements matter.

Inspect a saved profile with:

```sh
go tool pprof -top -cum /path/to/output/b/mesh-artifacts/default-idle-candidate-1-daemon-cpu.pprof
```

The Go tests also check that interface discovery uses one link dump and one
address dump for 1, 8, and 128 interfaces. These are fresh snapshots, not a
cross-tick cache. Interrupted dumps are rejected. Controller inspection returns
one validated WireGuard device per tick; route and key mutations still perform
their own fresh checks before and after writes.

## Cases

| Check | Topology and required result |
|---|---|
| `relay-only` | A is the relay. B and C have no eligible LAN interface. Tunnel traffic works through A before and after daemon startup. No direct peer is added. |
| `same-lan` | B and C share a LAN and initially use A. Captured multicast, broadcast, and unicast discovery packets must have fixed sizes and no plaintext identities. LAN loss, `SIGKILL`, and service stop must restore A. Interface recreation with an active journal must accept the correct baseline, reject conflicting ownership, and recover after only the kernel ownership is repaired. |
| `nat` | B and C are on separate LANs behind different NAT guests. Only outbound WireGuard to A and return traffic are forwarded. Both nodes must retain relay connectivity without direct peers. |
| `rosenpass` | A shared LAN is available, but missing PSK files prevent direct routing. Real Rosenpass output enables a direct trial. A natural rekey must change the installed PSK and produce a new handshake. Stopping Rosenpass and deleting output must restore A. |
| `rosenpass-adapter` | Only discovery supplies the LAN endpoints. The packaged adapter must reject unauthorized socket callers and output mappings. A natural rekey retains the child. A prompt daemon restart reuses its valid PSK. LAN renumbering replaces the child and endpoint. Child failure, adapter loss, fresh orphan output, and expiry despite refreshed timestamps must return traffic to A without restarting the mesh daemon. |
| `rosenpass-rekey` | Both nodes enable the experimental PSK-only operation. A natural rekey must preserve direct peers, endpoints, AllowedIPs, counters, and producer processes. A second rekey with WireGuard handshakes blocked must not complete from working old direct transport; it must fall back within the observation deadline. |
| `ipv6-transport` | One guest tests real Linux IPv6 link-local unicast and multicast with packet-info source-interface selection. Empty, named, and numeric zones must work. A zone for another interface must be rejected. |

The two-NAT topology is:

```text
B -- LAN 2 -- NAT B -- WAN -- NAT C -- LAN 3 -- C
                       |
                       A
```

**Hole punching is unsupported.** The NAT check passes only if the relay remains usable and no unsafe direct route appears. It does not mark a broken relay or failed guest setup as an expected failure.

Guest A adds 40 ms of egress delay on `wg0`. B and C use tunnel addresses `10.77.0.2` and `10.77.0.3`. The discovery daemon excludes the test-management adapter and simulated WAN adapter. LAN adapters use the normal physical-device detection, without an `include` override.

Assertions check peer sets, `AllowedIPs`, LAN endpoint addresses, recent handshakes, bidirectional pings, and direct-peer byte-counter increases. The Rosenpass check compares keys inside each guest without printing them. Relay packet counters prove that the initial Rosenpass exchange crosses A.

[privacy_guest.py](privacy_guest.py) captures IPv4 LAN discovery traffic on B and C before daemon startup. Both guests temporarily drop received IPv4 multicast announcements, which forces broadcast fallback. The captures must contain multicast, broadcast, and bidirectional unicast packets. Every daemon UDP payload must be exactly 512 bytes, without raw or base64 WireGuard public keys or known plaintext JSON fields. The test stops both captures and removes its firewall rules before the later recovery cases. This is a wire-format regression check, not proof of anonymity. It does not inspect IPv6 or tunnel captures.

Go tests separately check the directional X25519/HKDF derivation, envelope tampering, encrypted length and padding, identity binding before state changes, replay protection, expiry, entropy failures, and plaintext-version rejection. The 128-peer load test accepts 512 valid data packets and rejects 256 unaddressed frames per simulated second within the decryption-attempt budget. It is not a flood-resistance or maximum-rate benchmark. `FuzzSecureReceive` tests public wire packets; `FuzzSecureInnerReceive` tests the inner Noise parser.

The adapter cases reject Rosenpass UDP traffic through `wg0` and the WAN. No test command supplies an authorized endpoint to the adapter. Initial exchange therefore requires mesh discovery to provide the LAN address. These cases use independent, nonzero test PSKs on the hub links and verify that mesh changes do not replace them.

[adapter_guest.py](adapter_guest.py) compares output and installed keys inside each guest. It checks both adapter and child UIDs and capability sets. A second account has socket group access but must fail the UID check. Failure tests compare mesh daemon PIDs to prevent automatic service restart from concealing a daemon exit. Received Rosenpass packets are dropped on both guests to simulate a network outage without returning local send errors.

[recovery_guest.py](recovery_guest.py) freezes B's daemon, recreates `wg0`, and verifies the unchanged active journal before killing the daemon. The real `ExecStopPost` controller must leave an empty journal for the correct baseline. A conflicting hub prefix must remain unchanged, with the original journal retained, through recovery and failed startup. The test repairs only the kernel prefix before a successful restart. Temporary restart and watchdog overrides are removed and their active settings are verified during cleanup.

## Results And Limits

The original six checks have passed in earlier QEMU/KVM runs on `x86_64-linux`. During performance validation on 18 October 2026, `rosenpass-rekey` failed its first rekey completion assertion on both the unchanged baseline and the optimized binary. Both reached the 90-second handshake observation timeout and restored the relay. The 95-second test wait and its safety assertions were not relaxed. The pinned inputs include Go 1.26.7, Rosenpass 0.2.3, and WireGuard tools 1.0.20260223.

The observation limit is now 150 seconds. The completion test allows 155 seconds, and the blocked-handshake case allows 160 seconds for fallback. After the blocked case installs its new PSK, it also blocks further Rosenpass exchanges so that another PSK change cannot mask the observation deadline. Exchange expiry and all peer, traffic, key-confirmation, and recovery assertions remain in place. Go regression tests cover handshakes delayed by 95 and 120 seconds, the observation deadline, future timestamps, tunnel loss, and another key change during observation.

The 150-second QEMU run still failed the first completion assertion. Both nodes installed the update about 144 seconds after boot. Another Rosenpass key arrived about 120 seconds later, before completion, and triggered relay restoration. The blocked-handshake subtest was not reached. Go tests, race tests, vet, and the separate kernel namespace observation test in QEMU passed. Increasing the observation limit alone has not established reliable in-place rekey.

Each mesh output path printed by Nix contains `<node>/mesh-artifacts/`. These directories contain service logs, service state, routes, interface state, and WireGuard state without private or preshared keys. File-only Rosenpass results also include `initial-psk-check.json`, `rekey-psk-check.json`, and relay packet counts. Adapter cases retain captures for exchange, reuse, endpoint replacement, expiry, and experimental rekey outcomes. Recovery cases add `interface-recovery-*.json` markers. The privacy check exports only counts in `packet-privacy.json`; raw packet captures are deleted inside the guest. Private key comparisons and saved recovery-journal copies remain inside the guest and are not exported. The IPv6 transport check records its Go test results in the build log. Use `nix log` on a check to read the full build log. The driver stops the guests after each test, including failed tests.

All generated keys and deterministic WireGuard fixtures are for tests only. Never use them in production. Guest firewall settings and router rules are test fixtures, not deployment policy. Host network settings are not changed.

The VM suite uses short timers: discovery `1s`, broadcast delay `3s`, probes `200ms`, measurement window `5s`, and cooldown `3s`. Failure timeout is `5s` for the two adapter cases and `2s` otherwise. Rosenpass uses its real rekey interval and the default three-minute file age limit. The file-only and adapter cases require one natural rekey; the experimental case requires two. The adapter expiry case waits for the real exchange lifetime. Allow several minutes for each Rosenpass check.

The regular mesh safety cases use fast timers. The opt-in profiles also exercise default timings, but do not replace the fault tests. The suite does not yet cover multiple candidate LANs, IPv6 WireGuard routing, watchdog expiry, or a crash at every PSK transaction stage. The IPv6 transport case checks UDP source-interface selection, not IPv6 WireGuard endpoints. The privacy case forces IPv4 broadcast fallback; it does not disable IPv6 discovery. Adapter fixtures disable IPv6 so that LAN renumbering tests have one address family. Several network and journal fault cases have Go tests, but those are not VM coverage. The opt-in namespace tests remain separate. Only the x86-64 checks have been executed; the flake also defines ARM Linux checks.

The older `rosenpass` case reads file output without adapter exchange status. Producer failure with a retained file can take up to the age limit to disable a direct path. The adapter cases additionally require current exchange status and independent key-possession confirmation.

**Passing the experimental test is not proof of a new-PSK handshake.** WireGuard can retain old transport keys and report completion of an old pending handshake after a PSK update. The blocked-handshake case checks that old traffic alone is insufficient. It does not remove the handshake-generation limit. In-place rekey remains experimental and disabled by default. See [ROSENPASS.md](../ROSENPASS.md).
