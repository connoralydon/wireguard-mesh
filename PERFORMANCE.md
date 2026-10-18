# Performance Results

## Changes

- Linux interface discovery uses one link dump and one address dump. It no
  longer repeats these queries for each interface.
- A scoped netlink handle shares its socket within each inspection. It is
  closed after the inspection; no network snapshot is cached across ticks.
- The controller and runtime checks share one validated WireGuard device read
  per steady probe tick. Route and key changes still make fresh checks before
  and after writes. Routes use the interface index already checked in that
  inspection, instead of looking up the same interface name again.
- Linux IPv6 sends use the existing `IPV6_PKTINFO` source address and interface
  index for scope. The pinned socket library scans all interfaces before it
  parses a numeric destination zone. Removing that redundant zone avoids the
  scan on each send. Input zones are still checked against the selected link.
  Other platforms retain the previous zone handling.

Probe and discovery defaults remain **1 second** and **1 minute**. Key checks,
recovery journals, packet encryption, and resource limits are unchanged.

## Paired QEMU Measurements

Measured on 18 October 2026 against commit
`4dc4faf805bd6dc573fa37bbc2754b3abd742a6e`, with pinned Go 1.26.7.
Three x86-64 QEMU/KVM guests each had two virtual CPUs and 768 MiB of memory.
Nodes B and C each had one mesh peer and a confirmed direct LAN path.

Each cell is the median of three runs. Each run uses the mean of nodes B and C.
Each timed capture lasts 60 seconds. Package order alternates between runs.
Both packages use the same test-only profiling instrumentation.

CPU values are percentages of **one core per Go process**, from process user
and system CPU counters. Allocation reduction refers to allocated bytes per
second, not resident memory.

| Workload | Baseline CPU | Optimized CPU | CPU reduction | Allocation reduction |
| --- | ---: | ---: | ---: | ---: |
| Default timers, idle daemon | 0.939% | 0.707% | 24.8% | 48.3% |
| Default timers, TCP traffic | 0.241% | 0.183% | 24.1% | 48.7% |
| Fast test timers, idle daemon | 4.898% | 3.992% | 18.5% | 60.9% |
| Default timers with Rosenpass, daemon | 0.779% | 0.638% | 18.1% | 33.8% |
| Default timers with Rosenpass, adapter | 0.505% | 0.514% | -1.6% | -0.3% |

The adapter showed no improvement. Its key and status checks were not reduced.
The combined daemon and adapter CPU reduction was about 10% in this fixture.
The Rosenpass fixture disables IPv6 and enables experimental rekey, but each
steady capture requires an unchanged key and producer processes. It does not
measure a successful live rekey.

TCP receiver throughput remained about 1.5 Gbit/s: median 1.541 Gbit/s before
and 1.584 Gbit/s after. The run ranges overlap. This is not evidence of a
throughput improvement. WireGuard forwards bulk traffic in the kernel, not
through this daemon.

Separate five-second syscall traces followed each capture. At default idle
timers, median socket creation fell from 11 to 4 calls per second. These traces
record counts, not arguments, and do not overlap the CPU samples.

The initial pass removed duplicate queries but reduced default idle CPU by
only about 5%. Its profiles identified the remaining IPv6 zone lookup cost.
The second pass produced the results above. The initial 25% idle CPU target
was nearly reached, but is not established as a minimum for all workloads.
No broader cache or weaker validation was added to pursue that margin.

Do not compare absolute CPU values between separate VM runs. CPU frequency,
host scheduling, VM clocks, and profiling overhead can affect them. These
results do not cover maximum peer counts, packet floods, or all kernel and
Rosenpass child-process CPU use.

## Validation

- Go tests, race tests, and `go vet` passed.
- Both secure packet fuzz tests passed 30-second runs.
- Six QEMU checks passed: `ipv6-transport`, `relay-only`, `same-lan`, `nat`,
  `rosenpass`, and `rosenpass-adapter`.
- The IPv6 check uses real Linux link-local unicast and multicast. It tests
  empty, named, and numeric zones, and rejection of a different interface zone.
- Unit tests check the two-query bound for 1, 8, and 128 interfaces. Interrupted
  dumps are rejected. Fresh device reads and mutation preflight are also tested.
- Linux ARM64 and macOS ARM64 cross-builds passed. This does not make macOS a
  supported daemon platform; runtime support remains Linux-only.

The existing `rosenpass-rekey` check failed on both the unchanged baseline and
the first optimization pass. Both versions restored the relay after the
handshake observation timeout. Its 95-second test wait and safety assertions
were not relaxed. The final IPv6 change is not active in that IPv6-disabled
fixture. Successful live-rekey profiling remains blocked by this baseline
failure. No new-PSK handshake claim is made.

See [the test guide](tests/README.md#opt-in-cpu-profiles) for profiling targets,
saved data, and paired package comparisons. The normal daemon has no pprof
listener. These changes have not been deployed by this task.
