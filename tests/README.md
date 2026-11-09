# QEMU Integration Tests

These tests use the NixOS test driver, QEMU/KVM, real kernel WireGuard, and the repository's systemd service templates. The mesh daemon runs as a non-root user with `CAP_NET_ADMIN`. NAT traversal also requires `CAP_NET_RAW`. The adapter cases use a fixed daemon UID for socket authentication; other cases use a dynamic user. Rosenpass and its adapter run as a separate user, without capabilities.

## How QEMU Is Used

These are full VM integration tests, not mocked network tests or containers. The NixOS test driver starts QEMU directly; it does not use libvirt.

1. [The flake](../flake.nix) builds the Go daemon and exposes seven original regression checks and fifteen route/NAT profiles, for 22 checks total. [default.nix](default.nix), [direct.nix](direct.nix), and [ipv6.nix](ipv6.nix) use `pkgs.testers.runNixOSTest`. Their `qemu.forceAccel = true` setting requires KVM hardware acceleration.
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

The profiling packages are separate from the safety checks. They add a
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

**The original `nat` fixture does not permit hole punching.** That check passes only if the relay remains usable and no unsafe direct route appears. It does not mark a broken relay or failed guest setup as an expected failure. The separate `nat-traversal` check permits outbound peer UDP and tests the opt-in feature.

## Route And NAT Checks

Run one check at a time when collecting timing results:

```sh
nix build --no-link --print-out-paths -L --max-jobs 1 --builders '' \
  path:.#checks.x86_64-linux.same-lan-routes
nix build --no-link --print-out-paths -L --max-jobs 1 --builders '' \
  path:.#checks.x86_64-linux.nat-traversal
nix build --no-link --print-out-paths -L --max-jobs 1 --builders '' \
  path:.#checks.x86_64-linux.same-lan-rosenpass-routes
nix build --no-link --print-out-paths -L --max-jobs 1 --builders '' \
  path:.#checks.x86_64-linux.nat-traversal-rosenpass
nix build --no-link --print-out-paths -L --max-jobs 1 --builders '' \
  path:.#checks.x86_64-linux.lan-first-nat-fallback
nix build --no-link --print-out-paths -L --max-jobs 1 --builders '' \
  path:.#checks.x86_64-linux.lan-first-wg-blocked
```

`--builders ''` keeps these runs on the local KVM host. An unchanged successful
check is cached; use `--rebuild` for a fresh measurement. The tests use the real
packaged daemon and kernel WireGuard, not a test-only traversal implementation.
See [NAT.md](../NAT.md) for production configuration and limits.

| Check | Required behavior |
|---|---|
| `same-lan-routes` | Compare default in-place peering and separate-interface route peering on the same three guests, with three repetitions and alternating order. Check direct handshakes, host routes, traffic counters, and unchanged stable configuration in route mode. Exercise silent one-way and two-way failure, LAN loss, daemon death, restart, and stop. |
| `same-lan-auto` | Use automatic interface naming and a kernel-selected port. Check a conflicting foreign interface remains unchanged, direct traffic works, and recovery after a one-way outage, daemon kill, restart, and stop removes only the owned interface. |
| `same-lan-stun-down` | Enable experimental traversal with an unavailable STUN server. Require a healthy direct LAN path and unchanged daemon processes over 35 seconds. |
| `same-lan-rosenpass-routes` | Exchange real Rosenpass keys inside the VPN. Require valid adapter status and a matching installed PSK before direct routing. Reject orphan output, recover after both adapters restart, and recover after only the initial listener restarts. Keep mesh daemon PIDs unchanged. |
| `lan-first-nat-fallback` | Start on LAN without outbound ICE/STUN. Fall back to NAT after LAN loss, then return to a slower LAN path using fresh hub measurements. Require the correct kernel endpoint, increasing LAN WireGuard transport counters, and unchanged WAN transport counters during the LAN measurement. |
| `lan-first-wg-blocked` | Keep LAN control usable but block LAN WireGuard packets. Require a WAN direct path instead of the failed LAN host candidate. Remove the block and cycle the LAN; require return to LAN with the same endpoint and transport-counter checks. |
| `nat-traversal` | Use Coturn STUN on A, peers B/C, and two NAT routers. Use Pion ICE to select a direct candidate without configured peer endpoints or inbound forwarding. Check translated ports, blocked direct UDP, mapping changes, STUN and signaling loss, daemon death, restart, and stop. |
| `nat-traversal-rosenpass` | Apply the Rosenpass status and installed-key checks through two NAT routers. During natural rotation, record old-peer removal, hub fallback, and a handshake with the matching new key before route return. Reject orphan output and recover after adapter restart without restarting the mesh daemons. |
| `nat-traversal-port-preserving` | Both routers preserve direct port `51821`; require direct WireGuard traffic. |
| `nat-traversal-blocked` | Block peer-bound direct UDP. Require the stable relay, no direct host route, and running daemons. |
| `nat-traversal-wg-blocked` | Permit ICE selection but drop peer-bound WireGuard packets. Require packet-drop evidence, no WireGuard handshake or direct host route during the watch, and a usable relay. |
| `nat-traversal-symmetric` | Use destination-dependent mappings. Verify different STUN and peer mappings with conntrack, and require relay operation without a direct host route. |
| `nat-traversal-stun-failover` | Put an unavailable STUN endpoint before the working Coturn endpoint; require direct WireGuard traffic. |
| `nat-traversal-one-nat` | Put B behind one NAT router and C on the WAN; require direct WireGuard traffic. |
| `nat-traversal-long-outage` | After direct activation, stop Coturn and block signaling for 660 seconds. Require the direct path to remain active without a daemon restart or relay fallback. |

The default positive NAT fixture forces an endpoint-independent mapping with external
ports `40001` and `40002`, different from the clients' direct WireGuard listen
port (`51821`). This catches use of an advertised local port instead of the
observed external port. Routers drop unsolicited WAN UDP input to the router
itself; stateful return traffic to the LAN uses forwarding. No inbound DNAT or
port-forward rule is installed. The rebinding case changes only B's direct
mapping and deletes only its direct-port conntrack entries; the stable hub mapping is kept.
Blocked peer traffic must leave hub connectivity usable. Passing these cases is
not proof that traversal works through endpoint-dependent or arbitrary real NATs.

Both directions carry continuous numbered UDP probes at a target 20 ms interval
and TCP echo traffic on a connection that is retained across temporary loss.
Measurements include sent and received probes, missing replies, mean RTT, longest
no-reply interval, observed route changes, and fault-to-relay convergence.
The full LAN comparison records separate activation, confirmed steady direct
operation, and failure recovery. Measurements also include median and p95 RTT.
Recovery faults in the full profiles start after both daemons confirm the direct
trial, not merely after a peer or route appears. Negative profiles and the
initial blocked NAT trial start with faults already in place.
The recovery limit is 7 seconds for a configured 2-second failure timeout. Link
state alone is not treated as proof of WireGuard connectivity.

The full profiles use a fault schedule with seed `73109`. LAN faults also use seeded `netem` loss,
delay, jitter, and reordering. NAT forwarding faults select only direct-port
traffic. The schedule and applied settings are recorded; VM scheduling and packet
arrival order mean that a seed does not guarantee identical packet loss.

Each output retains `<node>/mesh-artifacts/measurements.json`, raw probe samples,
key-safe WireGuard state, routes, firewall counters, and service logs. Guest clock
offsets are measured once against the driver. Clock drift, guest scheduling,
polling resolution, and application recovery affect the results. The prewarm
watch records a handshake observed before a host route appears; controller tests
also require a handshake before route installation. The comparison does not
assert that the new mode is faster. Use the measured interruption and loss, not
only successful pings, to judge it.

The NAT guests also retain bounded underlay packet-header traces. These contain
test IP addresses, ports, and packet sizes, not private keys or decoded tunnel
payloads. Use `--keep-failed` when debugging a failed build so that its guest
artifacts remain in the failed Nix build directory.

These checks change interfaces, NAT rules, and sysctls only inside disposable
guests. They do not change host networking or deploy the daemon on the host.

Guest A adds 40 ms of egress delay on `wg0`. B and C use tunnel addresses `10.77.0.2` and `10.77.0.3`. The discovery daemon excludes the test-management adapter and simulated WAN adapter. LAN adapters use the normal physical-device detection, without an `include` override.

Assertions check peer sets, `AllowedIPs`, LAN endpoint addresses, recent handshakes, bidirectional pings, and direct-peer byte-counter increases. The Rosenpass check compares keys inside each guest without printing them. Relay packet counters prove that the initial Rosenpass exchange crosses A.

[privacy_guest.py](privacy_guest.py) captures IPv4 LAN discovery traffic on B and C before daemon startup. Both guests temporarily drop received IPv4 multicast announcements, which forces broadcast fallback. The captures must contain multicast, broadcast, and bidirectional unicast packets. Every daemon UDP payload must be exactly 512 bytes, without raw or base64 WireGuard public keys or known plaintext JSON fields. The test stops both captures and removes its firewall rules before the later recovery cases. This is a wire-format regression check, not proof of anonymity. It does not inspect IPv6 or tunnel captures.

Go tests separately check the directional X25519/HKDF derivation, envelope tampering, encrypted length and padding, identity binding before state changes, replay protection, expiry, entropy failures, and plaintext-version rejection. The 128-peer load test accepts 512 valid data packets and rejects 256 unaddressed frames per simulated second within the decryption-attempt budget. It is not a flood-resistance or maximum-rate benchmark. `FuzzSecureReceive` tests public wire packets; `FuzzSecureInnerReceive` tests the inner Noise parser.

The legacy adapter cases reject Rosenpass UDP traffic through `wg0` and the WAN. No test command supplies an authorized endpoint to the adapter. Initial exchange therefore requires mesh discovery to provide the LAN address. The route-mode adapter cases instead require Rosenpass exchange inside the VPN. These cases use independent, nonzero test PSKs on the hub links and verify that mesh changes do not replace them.

[adapter_guest.py](adapter_guest.py) compares output and installed keys inside each guest. It checks both adapter and child UIDs and capability sets. A second account has socket group access but must fail the UID check. Failure tests compare mesh daemon PIDs to prevent automatic service restart from concealing a daemon exit. Received Rosenpass packets are dropped on both guests to simulate a network outage without returning local send errors.

[recovery_guest.py](recovery_guest.py) freezes B's daemon, recreates `wg0`, and verifies the unchanged active journal before killing the daemon. The real `ExecStopPost` controller must leave an empty journal for the correct baseline. A conflicting hub prefix must remain unchanged, with the original journal retained, through recovery and failed startup. The test repairs only the kernel prefix before a successful restart. Temporary restart and watchdog overrides are removed and their active settings are verified during cleanup.

## Results And Limits

### Current Rosenpass And LAN-First Results

All **22 QEMU checks passed** on `x86_64-linux` in one complete sequential local
KVM run on 9 November 2026. This includes all fifteen route/NAT profiles and all
seven original regression checks. Every log contains an executed VM test script;
these were not only cached results. Total QEMU build elapsed time was
4,651.506 seconds, about 77.5 minutes.

The build-input manifest ID is
`fdf89f93c211cc9645cf2d8bd905dce01ee4adaaac989817b8468f5d163afa89`.
It identifies SHA-256 hashes of 73 build-input files, not a Git commit. All
inputs stayed unchanged through the run. Documentation is outside this manifest.
The previous `a58ffdd` results below are historical, not the measurements for
this revision.

Both Rosenpass profiles rejected direct routing without valid adapter status
and rejected orphan output. They recovered with a new installed key after both
adapters restarted, without restarting the mesh daemons. The LAN profile also
passed listener-only restart. During natural NAT rekey, both nodes recorded
`peer_absent`, `relay_seen`, `new_handshake_before_route`, and
`new_key_installed` as true.

The profiles checked process arguments inside the guests and found exactly one
initial initiator: B in the LAN case, C in the NAT case. Only role booleans were
exported. PSKs and private keys stayed inside the guests.

The four new profiles, full LAN/NAT comparisons, and 660-second outage each
retained TCP connection 1 in both directions, with traffic after the faults.
The route monitor required a handshake and then a hub-route observation before
direct promotion; a handshake first seen after the route change did not pass.

The [test-only observer](observer/main.go) keeps kernel clients open and reads
WireGuard state before each route lookup. It starts before the daemon and does
not run `wg` or `ip` subprocesses. This removes process-start delays from the
short pre-route observation interval without changing daemon timing. Rekey
observations also require the same new PSK in the file and kernel snapshot.
The observer exports only result booleans and a route-observation timestamp.

#### Measurements

The fresh LAN comparison used three repetitions per mode with alternating
order. UDP counts combine both directions. Activation includes discovery,
qualification, WireGuard handshake, and trial confirmation.

| Measurement | Legacy in-place mode | Automatic-interface route mode |
|---|---:|---:|
| Median confirmed activation | 11.114 s | 11.737 s |
| Missing activation UDP replies | 23 / 2,970 | 10 / 3,127 |
| Longest activation no-reply interval, range | 30–89 ms | 29–32 ms |
| Steady direct median RTT, range | 1.170–1.221 ms | 1.092–1.243 ms |

Route mode had fewer missing activation replies in this sample. These short
VM runs do not establish a general speed or reliability advantage.

Both LAN-first profiles returned from NAT to LAN even though LAN had the higher
RTT. These are round-trip measurements through the tunnel:

| Profile | Node | NAT RTT | LAN RTT |
|---|---|---:|---:|
| `lan-first-nat-fallback` | B | 5.624 ms | 21.638 ms |
| `lan-first-nat-fallback` | C | 5.352 ms | 21.494 ms |
| `lan-first-wg-blocked` | B | 2.588 ms | 21.496 ms |
| `lan-first-wg-blocked` | C | 2.462 ms | 22.458 ms |

During each LAN measurement, LAN WireGuard transport counters increased and
WAN transport counters stayed unchanged. Both blocked-LAN nodes counted a
dropped handshake initiation. LAN control replies did not authorize that
blocked WireGuard path. Removing the block and cycling the LAN permitted
return to LAN with the expected kernel endpoint.

The 660-second signaling and STUN outage recorded eleven progress snapshots.
During the outage, B received 28,992 UDP and 26,149 TCP replies; C received
29,019 UDP and 26,139 TCP replies. Both retained connection 1 without a daemon
restart or hub fallback. This covers renewal beyond the ten-minute Noise
session lifetime with real timers.

#### Source Checks

These checks passed on the same frozen inputs:

- `go test -count=1 ./...`
- `nix --option eval-cache false develop path:. --command env CGO_ENABLED=1 GOMAXPROCS=2 go test -race -count=1 ./...`
- `go test -run '^(TestICE|TestDirect|TestNAT|TestFailedLAN|TestLAN|TestRosenpassRoute|TestRosenpassVPN|TestRouteControl)' -count=5 .`
- `go test -count=20 ./tests/observer`
- `go vet ./...`
- Thirty-second fuzz runs with two workers: `FuzzRawUDP` (417,806 executions),
  `FuzzSecureReceive` (14,943), and `FuzzSecureInnerReceive` (6,128).
- `gofmt -l .` returned no files; all guest Python files passed AST parsing.
- `nixfmt --check tests/direct.nix flake.nix` and
  `nix-instantiate --parse tests/direct.nix` passed. QEMU builds also passed
  the NixOS test-script type and lint checks.
- `git diff --check` passed.

The local run records are `/tmp/opencode/wgmesh-rp-final-summary.json` and
`/tmp/opencode/wgmesh-rp-artifact-proof.json`. Source-check logs use
`/tmp/opencode/wgmesh-rp-final-*.log`. These temporary paths are local evidence,
not repository files.

#### Successful Outputs

All 22 successful outputs for this revision are:

```text
/nix/store/86cc5rzi39jbg1hbib1m85233n7zha8p-vm-test-run-wireguard-mesh-same-lan-routes
/nix/store/bxyryjpikpv18fgkyw587rvbcmnlkan4-vm-test-run-wireguard-mesh-same-lan-rosenpass-routes
/nix/store/603g8scwfv6hk34h8mnivi4ysq03lix3-vm-test-run-wireguard-mesh-nat-traversal-rosenpass
/nix/store/82snsd5vc6h9bp780mqnlk8kh8dxhbnx-vm-test-run-wireguard-mesh-lan-first-nat-fallback
/nix/store/z4nbhz1fqsxqm2spgbknxlgai4a9z5q5-vm-test-run-wireguard-mesh-lan-first-wg-blocked
/nix/store/imbpjj8jd1qs5vmzzn1p6rvlnm121k62-vm-test-run-wireguard-mesh-same-lan-stun-down
/nix/store/z2rfzdx67b3jgkjcvp9xss56s1by5cn5-vm-test-run-wireguard-mesh-same-lan-auto
/nix/store/dax4kl3y0adzb3k6fsfa6s2978harvgx-vm-test-run-wireguard-mesh-nat-traversal
/nix/store/7k8xqgfikzkcnh9ds4q37d71fw1q3g0s-vm-test-run-wireguard-mesh-nat-traversal-port-preserving
/nix/store/k3ka93khv08p0igldq3wk5c332ax70g9-vm-test-run-wireguard-mesh-nat-traversal-blocked
/nix/store/8xwl3vw1iza72q82xz4g5lxavgcsixs1-vm-test-run-wireguard-mesh-nat-traversal-wg-blocked
/nix/store/r6g10wl5kbj893kgkfc67w277ydfa4bp-vm-test-run-wireguard-mesh-nat-traversal-symmetric
/nix/store/wnw3k2ir9q3klrm40v7m7kf7ykij1vip-vm-test-run-wireguard-mesh-nat-traversal-stun-failover
/nix/store/f9bqwhmk9qx74j9di5x0wl8f8as8dbva-vm-test-run-wireguard-mesh-nat-traversal-one-nat
/nix/store/iwarf5bjd5g1k7yscrjz58hgal5ai0fi-vm-test-run-wireguard-mesh-nat-traversal-long-outage
/nix/store/9h2is44lqsqpaxigl9rxk4w708zq295x-vm-test-run-wireguard-mesh-relay-only
/nix/store/jfqx0q5b140y1z85xa96fbp0gb94z70l-vm-test-run-wireguard-mesh-same-lan
/nix/store/lnlapya0s5j7w6wjcpx5516lpk6ljcls-vm-test-run-wireguard-mesh-nat
/nix/store/zzpwqrdivbbcpr4cqwqqjx6yglf5m9fr-vm-test-run-wireguard-mesh-ipv6-transport
/nix/store/lqsniq2finiyw8zgy7hwffvh8h7pl39b-vm-test-run-wireguard-mesh-rosenpass
/nix/store/swi8gb32k9w759fba266lp5p6bsw3py5-vm-test-run-wireguard-mesh-rosenpass-adapter
/nix/store/0gvkq0g946zsrqqs36ccvwwn5wr8q0r4-vm-test-run-wireguard-mesh-rosenpass-rekey
```

Read `b/mesh-artifacts/measurements.json` in a route/NAT output for both
directions and event times. Raw samples are in each node's
`mesh-artifacts/probe.json`. The NAT Rosenpass output also has
`rp-rekey-watch.json` with the four rotation checks listed above.

#### Limits

Hole punching remains IPv4-only, experimental, and explicitly enabled. These
runs do not cover arbitrary real NAT devices, ARM execution, route-mode IPv6,
broader multiple-LAN behavior, maximum mesh size, or public-port flood
resistance. Endpoint checks are periodic, not a firewall rule. Passing the
legacy in-place rekey check does not prove a new-PSK handshake. Independent
security review is still required before production use.

The test run changed no host networking and did not deploy the daemon.

### Previous LAN And NAT Results (a58ffdd)

All eleven automatic-interface and Pion ICE/Coturn profiles passed on
`x86_64-linux` in separate local KVM runs. All seven original regression checks
also passed on this source: **18 QEMU checks passed in total**. These were
executed checks, not only cached results. Regression runs started after the LAN
timing runs finished. Older results below are labeled separately.

The LAN comparison used three repetitions per mode, with alternating order.
Counts combine both directions. Activation includes discovery, qualification,
WireGuard handshake, and trial confirmation, not only the route change.

| Measurement | Legacy in-place mode | Automatic-interface route mode |
|---|---:|---:|
| Median confirmed activation | 11.986 s | 12.019 s |
| Missing activation UDP replies | 23 / 3,229 | 9 / 3,201 |
| Longest activation no-reply interval, range | 28–70 ms | 29–32 ms |
| Steady direct median RTT, range | 1.133–1.272 ms | 1.089–1.215 ms |
| Missing one-way-failure UDP replies | 572 / 797 | 587 / 789 |
| Longest failure no-reply interval, range | 1.895–2.270 s | 2.108–2.239 s |

Route mode reduced activation loss in this sample. It did not establish a
general speed or failure-loss advantage. Both directions retained TCP connection
1 through the full LAN and NAT runs, with successful echoes after the final
fault. The LAN comparison recorded eight pre-route handshake observations.

The main two-NAT run used external ports `40001` and `40002`, then recovered
after B changed to `40011`. Its silent one-way and two-way failures returned to
the hub in 3.159 and 2.181 seconds; daemon death took 2.168 seconds. Route
convergence and TCP retransmission are separate measurements.

The negative fixtures also passed their evidence checks:

- Symmetric NAT used STUN mappings `40001`/`40002` and peer mappings
  `41001`/`41002`. Both STUN replies and outbound peer attempts were present in
  conntrack. No unsafe direct route appeared.
- The WireGuard-blocked case selected ICE candidates, but neither node observed
  a WireGuard handshake or host route. Both routers counted five blocked
  handshake initiations. The hub remained usable.
- LAN pairing used the normal discovery path with STUN unavailable.
- The 660-second outage blocked signaling and stopped STUN. Eleven progress
  snapshots showed fresh UDP and TCP replies. During the recorded outage, each
  direction received more than 28,000 UDP replies and 29,000 TCP replies on
  connection 1, without a daemon restart or hub fallback. This covers renewal
  beyond the ten-minute Noise session lifetime without a fake clock.

QEMU found two real-kernel issues during development: the alias needed an
explicit post-creation write, and cleanup needed to recognize the exact
kernel-generated IPv6 multicast route. Ownership conflicts still cause refusal.
The probe artifact checks also caught a data-transfer problem; they remain
strict and now use the driver's shared artifact transport.

Successful outputs for this matrix are:

```text
/nix/store/m2v4zm22v9fnjk957kq7ny76iin834d1-vm-test-run-wireguard-mesh-same-lan-auto
/nix/store/kak86bhij2iyngxa7bcfvwnrsiyvzf0d-vm-test-run-wireguard-mesh-same-lan-routes
/nix/store/89dvspgn3x6v28b76028avj0plh2jnpq-vm-test-run-wireguard-mesh-same-lan-stun-down
/nix/store/l1c44d2zf8vfzp7xjl1qm12zq946l5rw-vm-test-run-wireguard-mesh-nat-traversal
/nix/store/bwvgqc5yrf8h0a05q1ck1s86rn7yk5pi-vm-test-run-wireguard-mesh-nat-traversal-port-preserving
/nix/store/rvxlpddd0dw9frnwy4nknmpxm0nln3hr-vm-test-run-wireguard-mesh-nat-traversal-blocked
/nix/store/bn6gj5cappj8j92lhgai3j7g5dnzq137-vm-test-run-wireguard-mesh-nat-traversal-wg-blocked
/nix/store/d39awrbn5xawiw28b61nqw8i84vlw6jm-vm-test-run-wireguard-mesh-nat-traversal-symmetric
/nix/store/iiz5fr8v4zwd8brfkwkqf9yfjpygsi1x-vm-test-run-wireguard-mesh-nat-traversal-stun-failover
/nix/store/07809zi7v5qcsli9p29j1y6f1qhsjgcz-vm-test-run-wireguard-mesh-nat-traversal-one-nat
/nix/store/s69d3zrjfswxhp51imxi5r95hhsgd737-vm-test-run-wireguard-mesh-nat-traversal-long-outage
```

The existing regression outputs are:

```text
/nix/store/ar80yiymzjv6z8pssj17c8x38i15b4lv-vm-test-run-wireguard-mesh-relay-only
/nix/store/fjd3njqa6wqz0mp38ginxmi1zqfi8svl-vm-test-run-wireguard-mesh-same-lan
/nix/store/9247jhvymzi50wxf27bnl38ssqvgrqam-vm-test-run-wireguard-mesh-nat
/nix/store/3pfzzvm920mfwz2kdvpjlicrh62v2m5v-vm-test-run-wireguard-mesh-ipv6-transport
/nix/store/ly4wy010lf2b90zfrdj43k7l24iks2yn-vm-test-run-wireguard-mesh-rosenpass
/nix/store/i1i7yj1y5wrkb05pj4csf6pdbhb8kysz-vm-test-run-wireguard-mesh-rosenpass-adapter
/nix/store/0aighq9kf5srlkrirsbn48vjsl4mvrhb-vm-test-run-wireguard-mesh-rosenpass-rekey
```

The experimental rekey run completed both the retained-peer update and the
blocked-new-handshake fallback case. Its earlier failures and handshake-generation
limit still apply; the successful run does not make it production-ready.

Source checks passed:

- `go test -count=1 ./...`
- `nix develop path:. --command env CGO_ENABLED=1 go test -race -count=1 ./...`
- `go vet ./...`
- `go test -run '^(TestICE|TestDirect|TestNAT)' -count=5 .`
- Thirty-second fuzz runs with two workers: `FuzzRawUDP` (328,307 executions),
  `FuzzSecureReceive` (12,894), and `FuzzSecureInnerReceive` (8,456).
- Go formatting, Python AST parsing, Nix formatting, Nix test-script checks,
  and `git diff --check`.

These results do not cover arbitrary NAT devices, ARM execution, route-mode
IPv6 tunnel addresses, multiple candidate LANs, or public-port flood resistance.
Hole punching remains experimental and requires an explicit opt-in. No host
networking was changed and no daemon was deployed.

### Historical Pre-Pion Route And NAT Results

Both route/NAT checks passed on the previous custom-STUN, manual-interface
revision on `x86_64-linux`, using separate
local KVM runs and seed `73109`. The guests used Linux `6.18.52` and
iproute2 `7.1.0`. The Go package used the pinned Go `1.26.7` toolchain.

The LAN check ran three repetitions of each mode, with alternating order.
The UDP counts below combine both directions across all three repetitions.
Activation starts at daemon startup and ends when both direct trials are
confirmed. It includes discovery, qualification, handshake, and trial time;
it is not a measurement of only the kernel route change.

| Measurement | Default in-place mode | Separate-interface route mode |
|---|---:|---:|
| Median confirmed activation time | 11.976 s | 11.940 s |
| Missing UDP replies during activation | 25 / 3,098 | 8 / 3,172 |
| Longest activation no-reply interval, range | 28–123 ms | 27–30 ms |
| Steady direct median RTT, range | 1.220–1.581 ms | 1.158–1.303 ms |
| Missing UDP replies during one-way failure recovery | 513 / 665 | 532 / 659 |
| Longest failure no-reply interval, range | 1.986–2.024 s | 1.935–2.158 s |

Route mode had fewer missing replies during activation in this sample. It did
not show a clear overall speed or failure-loss advantage. Both modes retain
the configured failure-detection delay. These short VM samples do not establish
statistical significance or predict production performance.

The route-mode silent-loss cases returned to the hub in 2.146–2.267 seconds.
LAN link loss took 0.100 seconds, and daemon kill took 3.193 seconds. The NAT
check recorded 2.160 seconds for one-way loss, 2.195 seconds for two-way loss,
and 2.185 seconds after daemon kill. These are observed route-convergence times,
not bounds on TCP retransmission or every application's recovery time.

The NAT check established real direct WireGuard traffic on public translated
ports `40001` and `40002`, recovered after B changed to `40011`, and retained
the direct path during a 35-second STUN outage. The stable WireGuard peer
configuration remained unchanged. A separate Go simulation kept a healthy
direct path through a 13-minute STUN outage, including Noise session renewal.

Each direction used one TCP connection for the full LAN run and one for the
full NAT run. Successful echo replies continued at the end of both runs. One
last in-flight echo in C was unfinished when each probe stopped; this was not
a connection replacement. The LAN run recorded eight pre-route handshake
observations, and the NAT run recorded two.

The complete measurement and guest-state artifacts are:

```text
/nix/store/kwcnrr62baldgy7sqwakx57ph7b4z67a-vm-test-run-wireguard-mesh-same-lan-routes
/nix/store/hx79gkimwgq2nl8qq3v7cf33dvxdmdf7-vm-test-run-wireguard-mesh-nat-traversal
```

Read `b/mesh-artifacts/measurements.json` in either output for both directions,
all phase intervals, event times, and the fault schedule. Raw samples are in
each node's `mesh-artifacts/probe.json`.

Checks reported for that previous revision:

- `go test -count=1 ./...`
- `nix develop path:. --command env CGO_ENABLED=1 go test -race -count=1 ./...`
- `go vet ./...`
- The former custom STUN parser fuzz target completed 769,278 executions
  without a failure. That target is not present in the Pion implementation.
- Go formatting, Python syntax, Nix test-script checks, and `git diff --check`.

All seven existing VM regression checks also passed on that previous revision:
`relay-only`, `same-lan`, `nat`, `ipv6-transport`, `rosenpass`,
`rosenpass-adapter`, and `rosenpass-rekey`. Each ran locally with
`nix build --keep-failed --no-link --print-out-paths -L --max-jobs 1 --builders ''`
and its `path:.#checks.x86_64-linux.<name>` target. These were executed tests,
not only cached results. Together with the two route/NAT checks then present,
all nine VM checks passed on that revision. Regression runs started after the
timing measurements finished.

The experimental rekey check completed both the retained-peer update and the
blocked-new-handshake fallback cases. Its output is:

```text
/nix/store/ck30b5zx9d40cqkrfzjwv0vyxqycq64x-vm-test-run-wireguard-mesh-rosenpass-rekey
```

This successful run does not remove the earlier failures or prove which PSK
established a handshake. In-place rekey remains experimental and disabled by
default. Its assertions and observation limits were not relaxed for this work.

These results do not replace independent security review. ARM VM checks,
arbitrary real NAT devices, and route-mode IPv6 tunnel addresses were not tested.
Each client had one direct mesh peer. These runs do not measure maximum mesh
size, long-term CPU use, or resistance to a public-port flood.

### Earlier Rekey Results

The original six checks have passed in earlier QEMU/KVM runs on `x86_64-linux`. During performance validation on 18 October 2026, `rosenpass-rekey` failed its first rekey completion assertion on both the unchanged baseline and the optimized binary. Both reached the 90-second handshake observation timeout and restored the relay. The 95-second test wait and its safety assertions were not relaxed. The pinned inputs include Go 1.26.7, Rosenpass 0.2.3, and WireGuard tools 1.0.20260223.

The observation limit is now 150 seconds. The completion test allows 155 seconds, and the blocked-handshake case allows 160 seconds for fallback. After the blocked case installs its new PSK, it also blocks further Rosenpass exchanges so that another PSK change cannot mask the observation deadline. Exchange expiry and all peer, traffic, key-confirmation, and recovery assertions remain in place. Go regression tests cover handshakes delayed by 95 and 120 seconds, the observation deadline, future timestamps, tunnel loss, and another key change during observation.

The 150-second QEMU run still failed the first completion assertion. Both nodes installed the update about 144 seconds after boot. Another Rosenpass key arrived about 120 seconds later, before completion, and triggered relay restoration. The blocked-handshake subtest was not reached. Go tests, race tests, vet, and the separate kernel namespace observation test in QEMU passed. Increasing the observation limit alone has not established reliable in-place rekey.

Each mesh output path printed by Nix contains `<node>/mesh-artifacts/`. These directories contain service logs, service state, routes, interface state, and WireGuard state without private or preshared keys. File-only Rosenpass results also include `initial-psk-check.json`, `rekey-psk-check.json`, and relay packet counts. Adapter cases retain captures for exchange, reuse, endpoint replacement, expiry, and experimental rekey outcomes. Recovery cases add `interface-recovery-*.json` markers. The privacy check exports only counts in `packet-privacy.json`; raw packet captures are deleted inside the guest. Private key comparisons and saved recovery-journal copies remain inside the guest and are not exported. The IPv6 transport check records its Go test results in the build log. Use `nix log` on a check to read the full build log. The driver stops the guests after each test, including failed tests.

All generated keys and deterministic WireGuard fixtures are for tests only. Never use them in production. Guest firewall settings and router rules are test fixtures, not deployment policy. Host network settings are not changed.

The VM suite uses short timers: discovery `1s`, broadcast delay `3s`, probes `200ms`, measurement window `5s`, and cooldown `3s`. Failure timeout is `5s` for the two adapter cases and `2s` otherwise. Rosenpass uses its real rekey interval and the default three-minute file age limit. The file-only and adapter cases require one natural rekey; the experimental case requires two. The adapter expiry case waits for the real exchange lifetime. Allow several minutes for each Rosenpass check.

The regular mesh safety cases use fast timers. The opt-in profiles also exercise default timings, but do not replace the fault tests. The suite does not yet cover multiple candidate LANs, IPv6 WireGuard routing, watchdog expiry, or a crash at every PSK transaction stage. The IPv6 transport case checks UDP source-interface selection, not IPv6 WireGuard endpoints. The privacy case forces IPv4 broadcast fallback; it does not disable IPv6 discovery. Adapter fixtures disable IPv6 so that LAN renumbering tests have one address family. Several network and journal fault cases have Go tests, but those are not VM coverage. The opt-in namespace tests remain separate. Only the x86-64 checks have been executed; the flake also defines ARM Linux checks.

The older `rosenpass` case reads file output without adapter exchange status. Producer failure with a retained file can take up to the age limit to disable a direct path. The adapter cases additionally require current exchange status and independent key-possession confirmation.

**Passing the experimental test is not proof of a new-PSK handshake.** WireGuard can retain old transport keys and report completion of an old pending handshake after a PSK update. The blocked-handshake case checks that old traffic alone is insufficient. It does not remove the handshake-generation limit. In-place rekey remains experimental and disabled by default. See [ROSENPASS.md](../ROSENPASS.md).
