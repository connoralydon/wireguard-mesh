import json
import random
import shlex
import sys
import time

unit = "wireguard-meshd@wg0.service"
is_nat = mode.startswith("nat-traversal")
is_lan = not is_nat
short_profile = mode not in ("same-lan-routes", "nat-traversal")
nodes_by_name = {machine.name: machine for machine in machines}
seed = 73109
rng = random.Random(seed)
schedule = [{"duration": rng.choice([0.25, 0.5, 3.5]), "both": rng.choice([False, True]),
             "delay_ms": rng.choice([5, 10, 15]), "jitter_ms": 2, "loss_percent": rng.choice([1, 3, 5]), "reorder_percent": 5}
            for _ in range(3)]
events = []
mode_kind = "route"
nat_ports = {"b": 40001, "c": 40002}
if mode == "nat-traversal-port-preserving":
    nat_ports = {"b": 51821, "c": 51821}
if mode == "nat-traversal-one-nat":
    nat_ports["c"] = 51821
watch_generation = 0
clock_offsets = {}


class ProfileComplete(Exception):
    pass


def record(name, **settings):
    events.append({"event": name, "time": time.time(), **settings})


def state(machine, interface):
    return json.loads(machine.succeed(f"mesh-direct-test state {interface}"))


def ping():
    for machine, remote in ((b, 3), (c, 2)):
        machine.wait_until_succeeds(f"ping -n -c 1 -W 2 10.77.0.{remote}", timeout=30)
        machine.succeed(f"ping -n -c 3 -i 0.2 -W 2 10.77.0.{remote}")


def stable():
    for machine in (b, c):
        current = state(machine, "wg0")
        assert current["allowed-ips"] == {public["a"]: "10.77.0.0/24"}
        assert current["endpoints"] == {public["a"]: "192.0.2.1:51820"}


def wait_relay(since=None):
    for machine, remote in ((b, 3), (c, 2)):
        if mode_kind == "legacy":
            machine.wait_until_succeeds("test $(wg show wg0 peers | wc -l) -eq 1", timeout=7)
        else:
            machine.wait_until_succeeds(f"ip route get 10.77.0.{remote} | grep -q 'dev wg0'", timeout=7)
    elapsed = time.monotonic() - since if since is not None else None
    if elapsed is not None:
        assert elapsed <= 7, f"relay convergence took {elapsed:.3f}s, limit is 7s"
    stable()
    record("relay", convergence_seconds=elapsed)
    ping()


def wait_direct():
    for machine, remote, peer in ((b, 3, "c"), (c, 2, "b")):
        if mode_kind != "legacy":
            machine.wait_until_succeeds("mesh-direct-test owned", timeout=90)
        interface = "wg0" if mode_kind == "legacy" else machine.succeed("mesh-direct-test owned").strip()
        if mode_kind == "legacy":
            machine.wait_until_succeeds("test $(wg show wg0 peers | wc -l) -eq 2", timeout=90)
        else:
            machine.wait_until_succeeds(f"ip route get 10.77.0.{remote} | grep -q 'dev {interface}'", timeout=90)
        current = state(machine, interface)
        assert current["allowed-ips"][public[peer]] == f"10.77.0.{remote}/32"
        assert int(current["latest-handshakes"][public[peer]]) > 0
        if is_nat:
            address = 3 if mode == "nat-traversal-one-nat" and peer == "c" else (13 if peer == "c" else 12)
            assert current["endpoints"][public[peer]] == f"192.0.2.{address}:{nat_ports[peer]}"
        if mode == "same-lan-stun-down":
            assert current["endpoints"][public[peer]].startswith(f"172.20.2.{remote}:")
    record("direct-route-observed", path=mode_kind)
    for machine in (b, c):
        machine.wait_until_succeeds("mesh-direct-test active", timeout=90)
        if mode == "same-lan-stun-down":
            remote = 3 if machine.name == "b" else 2
            machine.succeed(f"mesh-direct-test active 172.20.2.{remote}:51823")
    record("direct-active", path=mode_kind)
    if mode_kind == "route":
        stable()
    before = {machine.name: [int(x) for x in state(machine, "wg0" if mode_kind == "legacy" else machine.succeed("mesh-direct-test owned").strip())["transfer"][public[peer]].split()] for machine, peer in ((b, "c"), (c, "b"))}
    ping()
    for machine, peer in ((b, "c"), (c, "b")):
        interface = "wg0" if mode_kind == "legacy" else machine.succeed("mesh-direct-test owned").strip()
        after = [int(x) for x in state(machine, interface)["transfer"][public[peer]].split()]
        assert all(new > old for old, new in zip(before[machine.name], after))
    record("direct", path=mode_kind)


def drop(enable, both=False):
    action = "-I" if enable else "-D"
    if is_nat:
        for machine in ([nodes_by_name[name] for name in ("nb", "nc") if name in nodes_by_name] if both else [nodes_by_name["nb"]]):
            machine.succeed(f"iptables {action} FORWARD -i lan -o wan -p udp --sport 51821 ! -d 192.0.2.1 -j DROP")
    else:
        for machine in ([b, c] if both else [b]):
            interface = "wg0" if mode_kind == "legacy" else machine.succeed("mesh-direct-test owned").strip()
            port = int(machine.succeed(f"wg show {interface} listen-port").strip())
            machine.succeed(f"iptables {action} OUTPUT -o lan -p udp --sport {port} -j DROP")
    record("drop-on" if enable else "drop-off", both=both, path=mode_kind)


def start_watch():
    global watch_generation
    watch_generation += 1
    for machine, remote, peer in ((b, 3, "c"), (c, 2, "b")):
        machine.succeed("rm -f /tmp/mesh-artifacts/route-watch.json")
        machine.succeed(f"systemd-run --collect --unit=mesh-watch-{watch_generation} {guest_helper} watch-route 10.77.0.{remote} {public[peer]}")


def check_watch():
    for machine in (b, c):
        machine.wait_until_succeeds("test -s /tmp/mesh-artifacts/route-watch.json", timeout=30)
        result = json.loads(machine.succeed("cat /tmp/mesh-artifacts/route-watch.json"))
        assert result["route_seen"] and result["handshake_before_route"], result
        record("prewarm-observed", machine=machine.name, observed_time=result["time"])


def start_daemons():
    if mode_kind == "route":
        start_watch()
    record("daemon-start", path=mode_kind)
    for machine in (b, c):
        machine.succeed(f"systemctl start {unit}")
        machine.wait_for_unit(unit)
    wait_direct()
    if mode_kind == "route":
        check_watch()


def stop_daemons():
    for machine in (b, c):
        interface = None if mode_kind == "legacy" else machine.succeed("mesh-direct-test owned").strip()
        machine.succeed(f"systemctl show {unit} -p PartOf,Requires,BindsTo,PropagatesStopTo")
        machine.succeed(f"systemctl stop {unit}")
        if interface:
            machine.succeed(f"! ip link show dev {shlex.quote(interface)}")
        if mode == "same-lan-auto":
            machine.succeed("mesh-direct-test foreign-check")
    wait_relay()
    record("daemon-stopped", path=mode_kind)


def outage(both):
    start = time.monotonic()
    drop(True, both)
    wait_relay(start)
    drop(False, both)
    wait_direct()


def start_stun(name):
    a.succeed(f"systemd-run --unit={name} {turnserver} -n --stun-only --no-cli --no-tls --no-dtls --log-file=stdout --pidfile=/run/{name}.pid --listening-ip=192.0.2.1 --listening-port=3478")
    a.wait_until_succeeds("ss -lun | grep -q '192.0.2.1:3478'", timeout=30)


def daemon_snapshot():
    result = {}
    for machine in (b, c):
        pid = machine.succeed(f"systemctl show {unit} -p MainPID --value").strip()
        count = machine.succeed("mesh-direct-test fallback-count").strip()
        assert pid != "0"
        result[machine.name] = (pid, count)
    return result


def probe_progress(machine):
    return json.loads(machine.succeed("cat /tmp/mesh-artifacts/probe-progress.json"))


def signaling_outage(seconds, stop_stun=False):
    before = daemon_snapshot()
    if stop_stun:
        a.succeed("systemctl show mesh-stun -p PartOf,Requires,BindsTo,PropagatesStopTo")
        a.succeed("systemctl stop mesh-stun")
    rule = "FORWARD -i wg0 -o wg0 -p udp --dport 51823 -j DROP"
    a.succeed(f"iptables -I {rule}")
    record("signaling-outage-start", seconds=seconds, stun_stopped=stop_stun)
    if seconds >= 660:
        start = time.monotonic()
        before_progress = {machine.name: probe_progress(machine) for machine in (b, c)}
        for elapsed in range(60, seconds + 1, 60):
            time.sleep(max(0, start + elapsed - time.monotonic()))
            for machine in (b, c):
                current = probe_progress(machine)
                previous = before_progress[machine.name]
                for kind in ("udp", "tcp"):
                    assert current[kind]["seq"] > previous[kind]["seq"], (machine.name, kind, previous, current)
                assert current["tcp"]["connection"] == 1, (machine.name, current)
                assert time.time() + clock_offsets[machine.name] - current["tcp"]["received"] < 10, (machine.name, current)
                assert time.time() + clock_offsets[machine.name] - current["udp"]["received"] < 10, (machine.name, current)
                before_progress[machine.name] = current
            record("signaling-outage-progress", elapsed=elapsed, progress=before_progress.copy())
        time.sleep(max(0, start + seconds - time.monotonic()))
    else:
        time.sleep(seconds)
    wait_direct()
    assert daemon_snapshot() == before, "daemon restarted or direct path fell back"
    a.succeed(f"iptables -D {rule}")
    record("signaling-outage-end", seconds=seconds)


def summarize(samples, start, end):
    selected = [item for item in samples if start <= item["sent"] < end]
    received = [item for item in selected if item["received"] is not None]
    # Include replies to probes sent before the interval. Otherwise the normal
    # relay RTT creates an artificial gap at every event boundary.
    times = [start] + sorted(item["received"] for item in samples
                             if item["received"] is not None and start <= item["received"] <= end) + [end]
    rtts = sorted(1000 * (item["received"] - item["sent"]) for item in received)
    return {"sent": len(selected), "received": len(received), "lost": len(selected) - len(received),
            "longest_no_reply_seconds": max((right - left for left, right in zip(times, times[1:])), default=0),
             "mean_rtt_ms": sum(rtts) / len(rtts) if rtts else None,
            "median_rtt_ms": rtts[len(rtts) // 2] if rtts else None,
            "p95_rtt_ms": rtts[min(len(rtts) - 1, (len(rtts) * 95 + 99) // 100 - 1)] if rtts else None,
            "tcp_connections": sorted({item["connection"] for item in selected if "connection" in item})}


try:
    start_all()
    for machine in machines:
        machine.wait_for_unit("multi-user.target")
        machine.succeed(f"mesh-direct-test setup {machine.name} {mode}")
    public = {name: a.succeed(f"mesh-direct-test public {name}").strip() for name in ("a", "b", "c")}
    for machine in (b, c):
        before = time.time()
        guest_now = float(machine.succeed("date +%s.%N"))
        clock_offsets[machine.name] = guest_now - (before + time.time()) / 2
    for machine, local, remote in ((b, 2, 3), (c, 3, 2)):
        machine.succeed(f"systemd-run --unit=mesh-probe {guest_helper} probe 10.77.0.{local} 10.77.0.{remote}")
    record("probes-started")
    wait_relay()
    for machine in (b, c):
        machine.wait_until_succeeds("test -e /tmp/mesh-probe-tcp-ready", timeout=30)
    if short_profile and is_lan:
        start_daemons()
        before = daemon_snapshot()
        if mode == "same-lan-auto":
            for machine in (b, c):
                interface = machine.succeed("mesh-direct-test owned").strip()
                machine.succeed(f"mesh-direct-test foreign-check {shlex.quote(interface)}")
                port = int(machine.succeed(f"wg show {interface} listen-port").strip())
                assert 0 < port <= 65535 and port not in (51820, 51823)
                record("auto-port", machine=machine.name, port=port)
            outage(False)
            old_interface = b.succeed("mesh-direct-test owned").strip()
            old_index = int(b.succeed(f"cat /sys/class/net/{shlex.quote(old_interface)}/ifindex").strip())
            when = time.monotonic()
            b.succeed(f"systemctl kill --kill-whom=main --signal=SIGKILL {unit}")
            wait_relay(when)
            b.wait_for_unit(unit, timeout=40)
            wait_direct()
            new_interface = b.succeed("mesh-direct-test owned").strip()
            new_index = int(b.succeed(f"cat /sys/class/net/{shlex.quote(new_interface)}/ifindex").strip())
            assert new_index != old_index, "owned interface was not cleaned after crash"
            for machine in (b, c):
                machine.succeed("mesh-direct-test foreign-check")
        else:
            time.sleep(35)
            wait_direct()
            assert daemon_snapshot() == before
        stop_daemons()
        raise ProfileComplete()
    if short_profile and is_nat:
        start_stun("mesh-stun")
        for machine in (b, c):
            machine.succeed("mkdir -p /tmp/mesh-artifacts")
            capture_interface = "wan" if mode == "nat-traversal-one-nat" and machine.name == "c" else "lan"
            machine.succeed(f"systemd-run --unit=mesh-headers --property=RuntimeMaxSec=120 --property=StandardOutput=append:/tmp/mesh-artifacts/underlay-headers.txt {tcpdump} -nn -l -i {capture_interface} udp port 3478")
            if mode == "nat-traversal-wg-blocked":
                remote, peer = (3, "c") if machine.name == "b" else (2, "b")
                machine.succeed(f"systemd-run --unit=mesh-no-route-watch --property=RuntimeMaxSec=120 {guest_helper} watch-no-route 10.77.0.{remote} {public[peer]}")
                machine.wait_until_succeeds("test -e /tmp/mesh-no-route-watch-ready", timeout=30)
        for machine in (b, c):
            machine.succeed(f"systemctl start {unit}")
        if mode == "nat-traversal-symmetric":
            for name in ("nb", "nc"):
                nodes_by_name[name].wait_until_succeeds(f"mesh-direct-test symmetric-proof {name}", timeout=30)
        if mode in ("nat-traversal-blocked", "nat-traversal-symmetric", "nat-traversal-wg-blocked"):
            pids = {machine.name: machine.succeed(f"systemctl show {unit} -p MainPID --value").strip() for machine in (b, c)}
            time.sleep(30)
            if mode == "nat-traversal-wg-blocked":
                for machine in (b, c):
                    machine.wait_until_succeeds("mesh-direct-test ice-selected", timeout=30)
                record("ice-selected-observation-start")
                time.sleep(10)
                for machine in (b, c):
                    machine.succeed("systemctl is-active --quiet mesh-no-route-watch")
                    machine.succeed("systemctl stop mesh-no-route-watch")
            for machine, remote in ((b, 3), (c, 2)):
                assert pids[machine.name] != "0"
                assert machine.succeed(f"systemctl show {unit} -p MainPID --value").strip() == pids[machine.name]
                machine.succeed(f"grep -q '172.20.{2 if machine.name == 'b' else 3}.{2 if machine.name == 'b' else 3}.51821 > 192.0.2.1.3478' /tmp/mesh-artifacts/underlay-headers.txt")
                machine.succeed(f"grep -q '192.0.2.1.3478 > 172.20.{2 if machine.name == 'b' else 3}.{2 if machine.name == 'b' else 3}.51821' /tmp/mesh-artifacts/underlay-headers.txt")
                machine.succeed(f"ip route get 10.77.0.{remote} | grep -q 'dev wg0'")
                machine.succeed(f"test -z \"$(ip -4 route show exact 10.77.0.{remote}/32)\"")
                machine.succeed("! mesh-direct-test active")
                if mode == "nat-traversal-wg-blocked":
                    machine.wait_until_succeeds("test -s /tmp/mesh-artifacts/no-route-watch.json", timeout=30)
                    result = json.loads(machine.succeed("cat /tmp/mesh-artifacts/no-route-watch.json"))
                    record("no-route-watch-observed", machine=machine.name, result=result)
                    assert result["stopped"] and not result["host_route_seen"] and not result["handshake_seen"], result
                    assert machine.succeed(f"systemctl show {unit} -p MainPID --value").strip() == pids[machine.name]
            if mode == "nat-traversal-wg-blocked":
                counters = {name: json.loads(nodes_by_name[name].succeed("mesh-direct-test wg-blocked-counter")) for name in ("nb", "nc")}
                record("wireguard-blocked-counters", counters=counters)
                assert all(sum(counts[:2]) > 0 for counts in counters.values()), counters
            stable()
            ping()
        else:
            wait_direct()
            if mode == "nat-traversal-long-outage":
                signaling_outage(660, stop_stun=True)
        stop_daemons()
        raise ProfileComplete()
    if mode == "same-lan-routes":
        for repetition in range(3):
            order = ("legacy", "route") if repetition % 2 == 0 else ("route", "legacy")
            for mode_kind in order:
                record("comparison-start", repetition=repetition, path=mode_kind)
                for machine in (b, c):
                    machine.succeed(f"mesh-direct-test configure {mode_kind}")
                start_daemons()
                outage(False)
                stop_daemons()
                record("comparison-end", repetition=repetition, path=mode_kind)
        mode_kind = "route"
        for machine in (b, c):
            machine.succeed("mesh-direct-test configure route")
    else:
        for machine in (b, c):
            machine.succeed("mkdir -p /tmp/mesh-artifacts")
            machine.succeed(f"systemd-run --unit=mesh-headers --property=RuntimeMaxSec=900 --property=StandardOutput=append:/tmp/mesh-artifacts/underlay-headers.txt {tcpdump} -nn -l -i lan -c 2000 'udp port 3478 or udp port 51821'")
        start_stun("mesh-stun")
        drop(True, both=True)
        for machine in (b, c):
            machine.succeed(f"systemctl start {unit}")
        time.sleep(12)
        stable()
        wait_relay()
        drop(False, both=True)
        wait_direct()
        stop_daemons()
    start_daemons()
    outage(False)
    outage(True)
    if mode == "same-lan-routes":
        when = time.monotonic()
        for machine in (b, c):
            machine.succeed("ip link set lan down")
        record("lan-down")
        wait_relay(when)
        for machine in (b, c):
            machine.succeed("ip link set lan up")
        record("lan-up")
        wait_direct()
    else:
        # Change only B's direct mapping. Stable-port conntrack entries remain intact.
        nodes_by_name["nb"].succeed("iptables -t nat -R POSTROUTING 1 -o wan -p udp --sport 51821 -j SNAT --to-source 192.0.2.12:40011")
        nodes_by_name["nb"].succeed("conntrack -D -p udp --orig-src 172.20.2.2 --sport 51821")
        nat_ports["b"] = 40011
        record("nat-rebind", translated_port=40011)
        interface = c.succeed("mesh-direct-test owned").strip()
        c.wait_until_succeeds(f"wg show {interface} endpoints | grep -F '{public['b']}' | grep -q '192.0.2.12:40011'", timeout=90)
        wait_direct()
        a.succeed("systemctl show mesh-stun -p PartOf,Requires,BindsTo,PropagatesStopTo")
        a.succeed("systemctl stop mesh-stun")
        record("stun-off")
        time.sleep(35)  # Exceed the 30-second minimum lifetime of STUN mappings.
        wait_direct()
        start_stun("mesh-stun-resumed")
        record("stun-on")
        signaling_outage(35)
    for entry in schedule:
        record("random-start", netem_applied=(mode == "same-lan-routes"), **entry)
        # NAT forwarding drops are classified by direct source port; they never touch wg0.
        if mode == "same-lan-routes":
            b.succeed(f"tc qdisc replace dev lan root netem delay {entry['delay_ms']}ms {entry['jitter_ms']}ms loss {entry['loss_percent']}% reorder {entry['reorder_percent']}% seed {seed}")
        time.sleep(1)
        drop(True, entry["both"])
        time.sleep(entry["duration"])
        drop(False, entry["both"])
        if mode == "same-lan-routes":
            b.succeed("tc qdisc del dev lan root")
        record("random-end", **entry)
        wait_direct()
    record("kill-start")
    when = time.monotonic()
    b.succeed(f"systemctl kill --kill-whom=main --signal=SIGKILL {unit}")
    wait_relay(when)
    b.wait_for_unit(unit, timeout=40)
    wait_direct()
    stop_daemons()
except ProfileComplete:
    pass
finally:
    failed = sys.exc_info()[0] is not None
    tcp_errors = []
    if not failed:
        # Wait for a new echo, not just route convergence or a fixed delay.
        after = time.time()
        for machine in (b, c):
            threshold = after + clock_offsets[machine.name]
            status, _ = machine.execute(f"timeout 120 sh -c 'until {guest_helper} probe-progress-after {threshold}; do sleep 1; done'", timeout=130)
            if status != 0:
                tcp_errors.append(f"{machine.name}: no post-fault TCP progress")
    record("test-end")
    for machine in (b, c):
        status, _ = machine.execute("systemctl stop mesh-probe", timeout=15)
        if not failed and status != 0:
            tcp_errors.append(f"{machine.name}: probe service stop failed")
    measurements: dict[str, dict[str, object]] = {}
    for machine in (b, c):
        status, _ = machine.execute("test -s /tmp/mesh-artifacts/probe.json")
        if status == 0:
            try:
                # Long runs produce megabytes. Use the driver's artifact
                # transport, not a large shell response on its control socket.
                target = f"probe-input/{machine.name}"
                machine.copy_from_machine("/tmp/mesh-artifacts/probe.json", target)
                samples = json.loads((machine.out_dir / target / "probe.json").read_text())
                if not isinstance(samples, dict) or not all(isinstance(samples.get(kind), list) for kind in ("tcp", "udp")):
                    raise ValueError("invalid probe data")
            except (ValueError, TypeError, OSError) as error:
                print(f"{machine.name}: probe artifact error: {error}")
                status = 1
        if status != 0 and not failed:
            tcp_errors.append(f"{machine.name}: probe artifact missing or unreadable")
        if status == 0:
            for items in samples.values():
                for item in items:
                    item["sent"] -= clock_offsets.get(machine.name, 0)
                    if item["received"] is not None:
                        item["received"] -= clock_offsets.get(machine.name, 0)
            if not failed:
                replies = [item for item in samples["tcp"] if item["received"] is not None]
                last_change = max((event["time"] for event in events if event["event"] in
                                   ("kill-start", "daemon-stopped", "relay")), default=events[0]["time"])
                if (not replies or {item["connection"] for item in samples["tcp"]} != {1}
                        or not any(item["received"] > last_change and item["received"] >= events[-1]["time"] - 10 for item in replies)):
                    tcp_errors.append(f"{machine.name}: TCP connection or final echo check failed")
            comparisons = []
            for begin in (event for event in events if event["event"] == "comparison-start"):
                ends = [event for event in events if event["event"] == "comparison-end" and
                        event["path"] == begin["path"] and event["repetition"] == begin["repetition"]]
                if ends:
                    interval = [event for event in events if begin["time"] <= event["time"] <= ends[0]["time"]]
                    phases = {}
                    daemon = next((event for event in interval if event["event"] == "daemon-start"), None)
                    active = next((event for event in interval if event["event"] == "direct-active"), None)
                    fault = next((event for event in interval if event["event"] == "drop-on"), None)
                    recovered = next((event for event in interval if event["event"] == "relay" and event.get("convergence_seconds") is not None), None)
                    for label, first, last in (("activation", daemon, active), ("steady_direct", active, fault), ("failure", fault, recovered)):
                        if first is not None and last is not None:
                            phases[label] = {"seconds": last["time"] - first["time"],
                                             "traffic": {kind: summarize(items, first["time"], last["time"])
                                                         for kind, items in samples.items()}}
                    comparisons.append({"path": begin["path"], "repetition": begin["repetition"],
                                        "start": begin["time"], "end": ends[0]["time"],
                                        "phases": phases,
                                        "traffic": {kind: summarize(items, begin["time"], ends[0]["time"])
                                                    for kind, items in samples.items()}})
            measurements[machine.name] = {kind: {"overall": summarize(items, events[0]["time"], events[-1]["time"]),
                "intervals": [{"event": event["event"], "start": event["time"], "end": next_event["time"],
                               **summarize(items, event["time"], next_event["time"])}
                              for event, next_event in zip(events, events[1:])]}
                for kind, items in samples.items()}
            measurements[machine.name]["comparisons"] = comparisons
    data = json.dumps({"mode": mode, "seed": seed, "schedule": schedule, "events": events,
                       "measurements": measurements, "failure_timeout_seconds": 2,
                       "convergence_limit_seconds": 7, "interval_seconds": 0.02,
                       "guest_clock_offsets_seconds": clock_offsets,
                       "clock": "initial midpoint wall-clock offset; drift and packet timing are not deterministic"}, indent=2)
    for machine in machines:
        machine.execute("mesh-direct-test capture final")
        if failed:
            status, output = machine.execute("ip -j -d link show")
            if status == 0:
                print(f"{machine.name} final links: {output}")
            for family in ("-4", "-6"):
                status, output = machine.execute(f"ip {family} -j route show table all")
                if status == 0:
                    print(f"{machine.name} final {family} routes: {output}")
        if failed and mode.startswith("nat-traversal"):
            for path in ("underlay-headers.txt", "final-firewall.txt"):
                status, output = machine.execute(f"tail -n 60 /tmp/mesh-artifacts/{path}")
                if status == 0:
                    print(f"{machine.name} {path}:\n{output}")
        machine.execute("mkdir -p /tmp/mesh-artifacts")
        machine.execute(": > /tmp/mesh-artifacts/measurements.json")
        for offset in range(0, len(data), 16000):
            machine.execute(f"printf %s {shlex.quote(data[offset:offset + 16000])} >> /tmp/mesh-artifacts/measurements.json")
        machine.copy_from_machine("/tmp/mesh-artifacts", machine.name)
    if tcp_errors:
        raise AssertionError(f"TCP connection 1 did not survive and progress: {tcp_errors}")
