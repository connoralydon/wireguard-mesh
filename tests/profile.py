"""Opt-in CPU profiles. Test keys and PSK comparisons stay inside the guests."""

import concurrent.futures
import json
import shlex

unit = "wireguard-meshd@wg0.service"
adapter_unit = "wireguard-mesh-rosenpass@wg0.service"
use_adapter = mode == "rosenpass-rekey"
results = []


def write_json(machine, path, value):
    machine.succeed("printf %s " + shlex.quote(json.dumps(value)) + " > " + shlex.quote(path))


def state(machine):
    return json.loads(machine.succeed("mesh-test state"))


def log_count(machine, text):
    return int(machine.succeed(f"journalctl -b -u {unit} --no-pager | grep -c '{text}' || true"))


def direct():
    for machine, remote, number in [(b, "c", 3), (c, "b", 2)]:
        current = state(machine)
        assert current["allowed-ips"] == {public["a"]: "10.77.0.0/24", public[remote]: f"10.77.0.{number}/32"}
        assert current["endpoints"][public[remote]] == f"172.20.2.{number}:51820"
        assert int(current["latest-handshakes"][public[remote]]) > 0
        if use_adapter:
            machine.succeed(f"mesh-adapter-test check {remote}")


def snapshot(machine, service, port):
    script = '''import json, os, pathlib, subprocess, time
pid = int(subprocess.check_output(["systemctl", "show", SERVICE, "-p", "MainPID", "--value"]))
stat = pathlib.Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
print(json.dumps({"pid": pid, "monotonic": time.monotonic(), "user_seconds": int(stat[11]) / os.sysconf("SC_CLK_TCK"), "system_seconds": int(stat[12]) / os.sysconf("SC_CLK_TCK"), "rss_bytes": int(stat[21]) * os.sysconf("SC_PAGE_SIZE")}))
'''.replace("SERVICE", repr(service))
    result = json.loads(machine.succeed("python3 -c " + shlex.quote(script)))
    result.update(json.loads(machine.succeed(f"curl -fsS --max-time 5 http://127.0.0.1:{port}/profile/metrics")))
    return result


def start_variant(variant, timers):
    binary = profile_binaries[variant]
    counts = {machine.name: log_count(machine, "direct path active") for machine in [b, c]}
    services = [unit, adapter_unit] if use_adapter else [unit]
    for machine in [b, c]:
        for service in services:
            machine.succeed(f"systemctl show {service} -p PartOf,Requires,BindsTo,PropagatesStopTo")
            machine.succeed(f"systemctl stop {service}")
        assert state(machine)["allowed-ips"] == {public["a"]: "10.77.0.0/24"}
        config = dict(configs[machine.name])
        if timers == "default":
            for field in ["discovery_interval", "broadcast_after", "probe_interval", "latency_window", "failure_timeout", "cooldown"]:
                config.pop(field)
        write_json(machine, "/etc/wireguard-mesh/wg0.json", config)
        for service in services:
            machine.succeed(f"mkdir -p /run/systemd/system/{service}.d")
            args = "-rosenpass-adapter /etc/wireguard-mesh/rosenpass-wg0.json" if service == adapter_unit else (
                "-wireguard wg0 -config %d/config -state /var/lib/wireguard-mesh-wg0/recovery.json"
            )
            override = f"[Service]\nExecStart=\nExecStart={binary} {args}\n"
            machine.succeed("printf %s " + shlex.quote(override) + f" > /run/systemd/system/{service}.d/profile.conf")
        machine.succeed("systemctl daemon-reload")
    if use_adapter:
        for machine in [b, c]:
            machine.succeed(f"systemctl start {adapter_unit}")
            machine.wait_for_unit(adapter_unit)
    for machine in [b, c]:
        machine.succeed(f"systemctl start {unit}")
        machine.wait_for_unit(unit)
        machine.succeed(f"test $(ps -o uid= -p $(systemctl show {unit} -p MainPID --value)) -ne 0")
    for machine in [b, c]:
        machine.wait_until_succeeds(
            f"test $(journalctl -b -u {unit} --no-pager | grep -c 'direct path active') -gt {counts[machine.name]}", timeout=210
        )
    direct()


def profile(variant, stage, repetition, seconds):
    label = f"{stage}-{variant}-{repetition}"
    roles = [("daemon", unit, 6060)] + ([("adapter", adapter_unit, 6061)] if use_adapter else [])
    counts = {machine.name: log_count(machine, "direct path active") for machine in [b, c]}
    restores = {machine.name: log_count(machine, "stable path restored") for machine in [b, c]}
    before_state = {machine.name: state(machine) for machine in [b, c]}
    before = {(machine.name, role): snapshot(machine, service, port) for machine in [b, c] for role, service, port in roles}
    if use_adapter:
        for machine in [b, c]:
            machine.succeed("mesh-adapter-test mark")
    if stage == "default-traffic":
        b.succeed(
            f"systemd-run --quiet --remain-after-exit --unit=traffic-{label} iperf3 "
            f"-c 10.77.0.3 -t {seconds + 8} -P 2 -J --logfile /tmp/mesh-artifacts/{label}-iperf.json"
        )
        b.wait_for_unit(f"traffic-{label}.service")

    def collect(machine):
        # One driver command per guest. Run the curl requests in the guest so
        # its command channel cannot serialize CPU and allocation captures.
        commands = ["pids=''"]
        for role, _, port in roles:
            for kind, endpoint in [("cpu", "profile"), ("allocs", "allocs")]:
                commands.append(
                    f"curl -fsS --max-time {seconds + 20} -o /tmp/mesh-artifacts/{label}-{role}-{kind}.pprof "
                    f"'http://127.0.0.1:{port}/debug/pprof/{endpoint}?seconds={seconds}' &\npids=\"$pids $!\""
                )
        commands.append('for pid in $pids; do wait "$pid" || exit 1; done')
        machine.succeed("\n".join(commands), timeout=seconds + 30)

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(collect, [b, c]))
    after = {(machine.name, role): snapshot(machine, service, port) for machine in [b, c] for role, service, port in roles}
    direct()
    for machine in [b, c]:
        assert log_count(machine, "direct path active") == counts[machine.name]
        assert log_count(machine, "stable path restored") == restores[machine.name]
        for role, _, _ in roles:
            old, new = before[machine.name, role], after[machine.name, role]
            assert old["pid"] == new["pid"], "Profiled process restarted"
            elapsed = new["monotonic"] - old["monotonic"]
            cpu = new["user_seconds"] + new["system_seconds"] - old["user_seconds"] - old["system_seconds"]
            result = {
                "variant": variant, "stage": stage, "repetition": repetition, "node": machine.name, "role": role,
                "elapsed_seconds": elapsed, "cpu_seconds": cpu, "cpu_percent_one_core": 100 * cpu / elapsed,
                "alloc_bytes_per_second": (new["total_alloc_bytes"] - old["total_alloc_bytes"]) / elapsed,
                "mallocs_per_second": (new["mallocs"] - old["mallocs"]) / elapsed, "rss_bytes": new["rss_bytes"],
            }
            results.append(result)
            print(json.dumps(result))
        remote = "c" if machine == b else "b"
        old = [int(n) for n in before_state[machine.name]["transfer"][public[remote]].split()]
        new = [int(n) for n in state(machine)["transfer"][public[remote]].split()]
        assert all(end > start for start, end in zip(old, new)), "No direct traffic"
        machine.succeed(f"mesh-test capture {label}")
    if use_adapter:
        for machine in [b, c]:
            machine.succeed("mesh-adapter-test unchanged")
    if stage == "default-traffic":
        b.wait_until_succeeds(f"test $(systemctl show traffic-{label}.service -p SubState --value) = exited", timeout=30)
        b.succeed(f"test $(systemctl show traffic-{label}.service -p ExecMainStatus --value) = 0")
        report = json.loads(b.succeed(f"cat /tmp/mesh-artifacts/{label}-iperf.json"))
        assert "error" not in report
        print(label, "TCP bits/second:", report["end"]["sum_received"]["bits_per_second"])
    # Trace only syscall counts, after the timed samples. Do not capture arguments.
    for machine in [b, c]:
        pid = after[machine.name, "daemon"]["pid"]
        code, _ = machine.execute(
            f"timeout --signal=INT 5s strace -f -c -p {pid} -o /tmp/mesh-artifacts/{label}-syscalls.txt", timeout=15
        )
        assert code == 124, "Unexpected strace result"


start_all()
try:
    configs = {}
    for machine in machines:
        machine.wait_for_unit("multi-user.target")
        machine.succeed("command -v python3 curl iperf3 strace")
        machine.succeed(f"mesh-test setup {machine.name} {mode}")
        machine.succeed("mkdir -p /tmp/mesh-artifacts")
    public = {name: a.succeed(f"mesh-test public {name}").strip() for name in ["a", "b", "c"]}
    write_json(b, "/tmp/mesh-artifacts/profile-builds.json", profile_binaries)
    for machine in [b, c]:
        configs[machine.name] = json.loads(machine.succeed("cat /etc/wireguard-mesh/wg0.json"))
        if use_adapter:
            machine.succeed(f"mesh-adapter-test setup {machine.name}")
    if use_adapter:
        for machine, remote in [(b, "c"), (c, "b")]:
            machine.succeed(f"install -m 0444 /tmp/shared/adapter-{remote}.pub /var/lib/mesh-rosenpass-wg0/peer-public")
    c.succeed("systemd-run --quiet --unit=profile-iperf iperf3 -s -B 10.77.0.3")
    c.wait_for_unit("profile-iperf.service")
    # Keep steady-state CPU measurements separate from the experimental rekey
    # handshake observation test. The adapter fixture checks key/PID stability.
    stages = [("default-idle", "default", 60)] if use_adapter else [
        ("default-idle", "default", 60), ("default-traffic", "default", 60), ("fast-idle", "fast", 60)
    ]
    for stage, timers, seconds in stages:
        for repetition in range(1, 4):
            variants = sorted(profile_binaries)
            if repetition % 2 == 0:
                variants.reverse()
            for variant in variants:
                with subtest(f"{stage}: {variant}, repetition {repetition}"):
                    start_variant(variant, timers)
                    profile(variant, stage, repetition, seconds)
    for machine in [b, c]:
        machine.succeed(f"systemctl show {unit} -p PartOf,Requires,BindsTo,PropagatesStopTo")
        machine.succeed(f"systemctl stop {unit}")
        assert state(machine)["allowed-ips"] == {public["a"]: "10.77.0.0/24"}
    write_json(b, "/tmp/mesh-artifacts/cpu-results.json", results)
finally:
    for machine in machines:
        machine.execute("mesh-test capture final")
        machine.copy_from_machine("/tmp/mesh-artifacts", machine.name)
