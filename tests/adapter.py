ADAPTER_UNIT = "wireguard-mesh-rosenpass@wg0.service"
ADAPTER_OUTPUT = "/run/wireguard-mesh-rosenpass-wg0/peer.psk"


def adapter_processes(machine):
    return json.loads(machine.succeed("mesh-adapter-test processes"))


def adapter_hub_check():
    for machine in [a, b, c]:
        machine.succeed(f"mesh-adapter-test hub-check {machine.name}")


def adapter_mesh_pids():
    result = []
    for machine in [b, c]:
        machine.succeed(f"systemctl is-active {unit}")
        pid = int(machine.succeed(f"systemctl show {unit} -p MainPID --value"))
        assert pid > 0
        result.append(pid)
    return result


def adapter_dependencies(machine, service):
    machine.succeed(f"systemctl show {service} -p PartOf,Requires,BindsTo,PropagatesStopTo")


def adapter_wait_direct(previous):
    for machine, count in zip([b, c], previous):
        machine.wait_until_succeeds(
            f"test $(journalctl -b -u {unit} --no-pager | grep -c 'direct path active') -gt {count}", timeout=210
        )
    direct_traffic()
    for machine, remote in [(b, "c"), (c, "b")]:
        machine.succeed(f"mesh-adapter-test check {remote}")
        process = adapter_processes(machine)
        local = 2 if machine == b else 3
        other = 3 if machine == b else 2
        assert process["listen"] == f"{lan_subnet}.{local}:51822"
        assert process["endpoint"] == f"{lan_subnet}.{other}:51822"
    adapter_hub_check()


def adapter_log_counts(text):
    return [int(machine.succeed(
        f"journalctl -b -u {unit} --no-pager | grep -c '{text}' || true"
    )) for machine in [b, c]]


def adapter_test():
    global lan_subnet
    with subtest("LAN discovery runs before a PSK or adapter is available"):
        time.sleep(6)
        relay()
        assert active_counts() == [0, 0]
        for machine in [b, c]:
            machine.fail(f"test -e {ADAPTER_OUTPUT}")
            machine.succeed(f"mesh-adapter-test setup {machine.name}")
        for machine, remote in [(b, "c"), (c, "b")]:
            machine.succeed(f"install -m 0444 /tmp/shared/adapter-{remote}.pub /var/lib/mesh-rosenpass-wg0/peer-public")
        adapter_hub_check()

    with subtest("packaged unprivileged adapter exchanges over the discovered LAN"):
        # Let B's first initiation leave before C starts. No test command submits
        # an endpoint: only the two mesh daemons can start these exchanges.
        b.succeed(f"systemctl start {ADAPTER_UNIT}")
        b.wait_until_succeeds("mesh-adapter-test sent", timeout=30)
        c.succeed(f"systemctl start {ADAPTER_UNIT}")
        for machine in [b, c]:
            machine.wait_for_unit(ADAPTER_UNIT)
            machine.succeed(f"test -z \"$(systemctl show {ADAPTER_UNIT} -p CapabilityBoundingSet --value)\"")
            machine.succeed(f"test $(systemctl show {ADAPTER_UNIT} -p NoNewPrivileges --value) = yes")
        adapter_wait_direct([0, 0])
        capture("adapter-lan-exchange")

    with subtest("socket UID and fixed mappings reject unauthorized changes"):
        for machine in [b, c]:
            machine.succeed("mesh-adapter-test mark")
            machine.succeed("runuser -u mesh-intruder -- mesh-adapter-test reject-request uid")
            machine.succeed("runuser -u mesh-wg0 -- mesh-adapter-test reject-request mapping")
            machine.succeed("runuser -u mesh-wg0 -- mesh-adapter-test reject-request peer")
            machine.succeed("mesh-adapter-test unchanged")
            machine.fail("test -e /run/unapproved-output")
        direct_traffic()

    if mode == "rosenpass-rekey":
        adapter_rekey_test()
        return

    with subtest("natural rekey changes the PSK without restarting Rosenpass"):
        before = active_counts()
        children = [adapter_processes(machine) for machine in [b, c]]
        b.wait_until_succeeds("mesh-adapter-test changed", timeout=180)
        c.wait_until_succeeds("mesh-adapter-test changed", timeout=30)
        adapter_wait_direct(before)
        assert [adapter_processes(machine) for machine in [b, c]] == children
        capture("adapter-natural-rekey")

    with subtest("prompt daemon restart reuses the existing live exchange and PSK"):
        before = active_counts()
        for machine in [b, c]:
            machine.succeed("mesh-adapter-test mark")
        adapter_dependencies(b, unit)
        # Restart before LAN health expires. A prolonged stop must instead
        # withdraw the remote endpoint and invalidate that exchange.
        b.succeed(f"systemctl restart {unit}")
        adapter_wait_direct(before)
        for machine in [b, c]:
            machine.succeed("mesh-adapter-test unchanged")
        capture("adapter-psk-reused")

    with subtest("LAN renumbering replaces the child and its reachable endpoint"):
        before = active_counts()
        children = [adapter_processes(machine) for machine in [b, c]]
        for machine in [b, c]:
            machine.succeed("ip link set lan down")
        wait_relay()
        ping()
        for machine in [b, c]:
            machine.wait_until_succeeds(f"test ! -e {ADAPTER_OUTPUT}", timeout=10)
        lan_subnet = "172.21.2"
        for machine, number in [(b, 2), (c, 3)]:
            machine.succeed("ip -4 address flush dev lan")
            machine.succeed(f"ip address add {lan_subnet}.{number}/24 dev lan")
            machine.succeed("ip link set lan up")
        adapter_wait_direct(before)
        for machine, old in zip([b, c], children):
            current = adapter_processes(machine)
            assert current["adapter_pid"] == old["adapter_pid"]
            assert current["child_pid"] != old["child_pid"]
        capture("adapter-endpoint-replaced")

    with subtest("child failure invalidates output while the adapter remains running"):
        before = active_counts()
        mesh_pids = adapter_mesh_pids()
        prior = adapter_processes(b)
        for machine in [b, c]:
            machine.succeed("mesh-adapter-test block on")
        adapter_dependencies(b, ADAPTER_UNIT)
        b.succeed("mesh-adapter-test kill-child")
        b.wait_until_succeeds(f"test ! -e {ADAPTER_OUTPUT}", timeout=10)
        wait_relay()
        ping()
        assert adapter_mesh_pids() == mesh_pids
        b.wait_until_succeeds("mesh-adapter-test processes", timeout=10)
        current = adapter_processes(b)
        assert current["adapter_pid"] == prior["adapter_pid"]
        assert current["child_pid"] != prior["child_pid"]
        for machine in [b, c]:
            machine.succeed("mesh-adapter-test block off")
        adapter_wait_direct(before)
        assert adapter_mesh_pids() == mesh_pids

    with subtest("fresh orphan output cannot replace live exchange status"):
        before = active_counts()
        mesh_pids = adapter_mesh_pids()
        b.succeed("mesh-adapter-test mark")
        for machine in [b, c]:
            machine.succeed("mesh-adapter-test block on")
        adapter_dependencies(b, ADAPTER_UNIT)
        b.succeed(f"systemctl stop {ADAPTER_UNIT}")
        b.wait_until_succeeds(f"test ! -e {ADAPTER_OUTPUT}", timeout=10)
        b.succeed("mesh-adapter-test restore-file")
        wait_relay()
        assert adapter_mesh_pids() == mesh_pids
        for _ in range(5):
            relay()
            b.succeed(f"test -s {ADAPTER_OUTPUT}")
            time.sleep(1)
        b.succeed(f"systemctl start {ADAPTER_UNIT}")
        b.wait_until_succeeds(f"test ! -e {ADAPTER_OUTPUT}", timeout=10)
        for machine in [b, c]:
            machine.succeed("mesh-adapter-test block off")
        adapter_wait_direct(before)
        assert adapter_mesh_pids() == mesh_pids
        capture("adapter-orphan-rejected")

    with subtest("exchange expiry defeats repeated fresh file timestamps"):
        mesh_pids = adapter_mesh_pids()
        for machine in [b, c]:
            machine.succeed("mesh-adapter-test block on")
        direct_traffic()
        deadline = time.monotonic() + 210
        last_touch = {}
        missing = set()
        while time.monotonic() < deadline and len(missing) != 2:
            for machine in [b, c]:
                if machine.name in missing:
                    continue
                if machine.execute(f"test -e {ADAPTER_OUTPUT}")[0] == 0:
                    # The producer can expire between this check and touch.
                    code, _ = machine.execute("mesh-adapter-test touch-output")
                    if code == 0:
                        last_touch[machine.name] = time.monotonic()
                        continue
                    machine.succeed(f"test ! -e {ADAPTER_OUTPUT}")
                assert machine.name in last_touch and time.monotonic() - last_touch[machine.name] < 10
                missing.add(machine.name)
            time.sleep(2)
        assert len(missing) == 2, "Exchange output survived expiry despite blocked Rosenpass"
        wait_relay()
        ping()
        assert adapter_mesh_pids() == mesh_pids
        adapter_hub_check()
        capture("adapter-exchange-expired")


def adapter_rekey_test():
    with subtest("experimental PSK-only rekey retains both installed peers"):
        before = active_counts()
        restores = adapter_log_counts("stable path restored")
        observed = adapter_log_counts("experimental PSK update observed at both peers")
        children = [adapter_processes(machine) for machine in [b, c]]
        traffic = [state(machine)["transfer"][public[remote]] for machine, remote in [(b, "c"), (c, "b")]]
        b.wait_until_succeeds("mesh-adapter-test changed", timeout=180)
        c.wait_until_succeeds("mesh-adapter-test changed", timeout=30)
        for machine, remote, count in [(b, "c", observed[0]), (c, "b", observed[1])]:
            machine.wait_until_succeeds(f"mesh-adapter-test check {remote}", timeout=10)
            machine.wait_until_succeeds(
                f"test $(journalctl -b -u {unit} --no-pager | grep -c 'experimental PSK update observed at both peers') -gt {count}", timeout=95
            )
        assert active_counts() == before
        assert adapter_log_counts("stable path restored") == restores
        assert [adapter_processes(machine) for machine in [b, c]] == children
        for machine, remote, old in zip([b, c], ["c", "b"], traffic):
            current = state(machine)["transfer"][public[remote]].split()
            assert all(int(new) > int(previous) for new, previous in zip(current, old.split()))
        direct_traffic()
        adapter_hub_check()
        capture("adapter-experimental-rekey-observed")

    with subtest("old transport cannot complete rekey when new handshakes are blocked"):
        observed = adapter_log_counts("experimental PSK update observed at both peers")
        applied = adapter_log_counts("experimental PSK-only update applied")
        handshakes = [state(machine)["latest-handshakes"] for machine in [b, c]]
        for machine in [b, c]:
            machine.succeed("mesh-adapter-test mark")
            machine.succeed("mesh-adapter-test block-handshakes")
        b.wait_until_succeeds("mesh-adapter-test changed", timeout=180)
        c.wait_until_succeeds("mesh-adapter-test changed", timeout=30)
        for machine, remote, count in [(b, "c", applied[0]), (c, "b", applied[1])]:
            machine.wait_until_succeeds(
                f"test $(journalctl -b -u {unit} --no-pager | grep -c 'experimental PSK-only update applied') -gt {count}", timeout=10
            )
            machine.succeed(f"mesh-adapter-test check {remote}")
        # Old direct transport still works, but it is not new-key evidence.
        direct_traffic()
        for machine, remote, old in zip([b, c], ["c", "b"], handshakes):
            assert state(machine)["latest-handshakes"][public[remote]] == old[public[remote]]
        assert adapter_log_counts("experimental PSK update observed at both peers") == observed
        for machine in [b, c]:
            machine.wait_until_succeeds("test $(wg show wg0 peers | wc -l) -eq 1", timeout=100)
        relay()
        ping()
        assert adapter_log_counts("experimental PSK update observed at both peers") == observed
        assert any("PSK handshake observation timeout" in machine.succeed(
            f"journalctl -b -u {unit} --no-pager"
        ) for machine in [b, c])
        adapter_hub_check()
        capture("adapter-experimental-handshake-timeout")
