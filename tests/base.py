import json
import time

unit = "wireguard-meshd@wg0.service"
participants = machines
lan_subnet = "172.20.2"


def state(machine):
    return json.loads(machine.succeed("mesh-test state"))


def capture(stage):
    for machine in participants:
        machine.succeed(f"mesh-test capture {stage}")


def ping():
    for machine, remote in [(b, 3), (c, 2)]:
        machine.succeed(f"ping -n -I wg0 -c 5 -i 0.2 -W 2 10.77.0.{remote}")


def relay():
    for machine in [b, c]:
        assert state(machine)["allowed-ips"] == {public["a"]: "10.77.0.0/24"}


def wait_relay():
    for machine in [b, c]:
        machine.wait_until_succeeds("test $(wg show wg0 peers | wc -l) -eq 1", timeout=15)
    relay()


def direct():
    for machine, remote in [(b, "c"), (c, "b")]:
        n = 3 if remote == "c" else 2
        current = state(machine)
        assert current["allowed-ips"] == {public["a"]: "10.77.0.0/24", public[remote]: f"10.77.0.{n}/32"}
        assert current["endpoints"][public[remote]] == f"{lan_subnet}.{n}:51820"
        handshake = int(current["latest-handshakes"][public[remote]])
        assert handshake > 0
        now = int(machine.succeed("date +%s"))
        assert 0 <= now - handshake < 150


def wait_direct(previous):
    for machine, count in zip([b, c], previous):
        machine.wait_until_succeeds(
            f"test $(journalctl -b -u {unit} --no-pager | grep -c 'direct path active') -gt {count}", timeout=60
        )
    direct()


def active_counts():
    return [int(machine.succeed(f"journalctl -b -u {unit} --no-pager | grep -c 'direct path active' || true")) for machine in [b, c]]


def direct_traffic():
    before = {machine.name: state(machine)["transfer"][public[remote]] for machine, remote in [(b, "c"), (c, "b")]}
    ping()
    direct()
    for machine, remote in [(b, "c"), (c, "b")]:
        old = [int(n) for n in before[machine.name].split()]
        new = [int(n) for n in state(machine)["transfer"][public[remote]].split()]
        assert all(after > prior + 500 for prior, after in zip(old, new))


start_all()
try:
    for machine in participants:
        machine.wait_for_unit("multi-user.target")
        machine.succeed(f"mesh-test setup {machine.name} {mode}")
    public = {name: a.succeed(f"mesh-test public {name}").strip() for name in ["a", "b", "c"]}

    with subtest("initial kernel WireGuard relay B-A-C"):
        relay()
        for machine, remote in [(b, 3), (c, 2)]:
            machine.wait_until_succeeds(f"ping -n -I wg0 -c 1 -W 2 10.77.0.{remote}", timeout=30)
        ping()
        # The hub must decrypt and forward both directions, not just route UDP.
        for peer in ["b", "c"]:
            assert all(int(n) > 500 for n in state(a)["transfer"][public[peer]].split())
        capture("initial-relay")

    with subtest("hardened non-root daemon"):
        for machine in [b, c]:
            machine.succeed(f"systemctl start {unit}")
            machine.wait_for_unit(unit)
            dynamic = "no" if mode.startswith("rosenpass-") else "yes"
            machine.succeed(f"test $(systemctl show {unit} -p DynamicUser --value) = {dynamic}")
            machine.succeed(f"test $(systemctl show {unit} -p NoNewPrivileges --value) = yes")
            machine.succeed(f"test $(ps -o uid= -p $(systemctl show {unit} -p MainPID --value)) -ne 0")

    if mode.startswith("rosenpass-"):
        adapter_test()
    elif mode == "rosenpass":
        rosenpass_test()
    elif mode != "same-lan":
        with subtest("no direct LAN, no hole punching, relay retained"):
            if mode == "nat":
                b.fail("ping -c 1 -W 1 172.20.3.3")
                c.fail("ping -c 1 -W 1 172.20.2.2")
                # A sees distinct translated endpoints, not the private LAN IPs.
                endpoints = state(a)["endpoints"]
                assert endpoints[public["b"]].startswith("192.0.2.12:")
                assert endpoints[public["c"]].startswith("192.0.2.13:")
            for _ in range(15):
                relay()
                time.sleep(1)
            assert active_counts() == [0, 0]
            ping()
            capture("relay-retained")
    else:
        with subtest("same LAN selected after delayed relay baseline"):
            for machine in [b, c]:
                machine.succeed("test -e /sys/class/net/lan/device")
            wait_direct([0, 0])
            direct_traffic()
            capture("direct")

        with subtest("LAN loss restores relay"):
            before = active_counts()
            for machine in [b, c]:
                machine.succeed("ip link set lan down")
            wait_relay()
            ping()
            capture("lan-down")
            for machine in [b, c]:
                machine.succeed("ip link set lan up")
            wait_direct(before)
            direct_traffic()

        with subtest("SIGKILL recovery and automatic restart"):
            before = active_counts()
            b.succeed(f"systemctl show {unit} -p PartOf,Requires,BindsTo,PropagatesStopTo")
            b.succeed(f"systemctl kill --kill-whom=main --signal=SIGKILL {unit}")
            wait_relay()
            ping()
            capture("crash-restored")
            b.wait_for_unit(unit, timeout=40)
            wait_direct(before)
            direct_traffic()

        interface_recovery_test()

    with subtest("service stop restores relay"):
        for machine in [b, c]:
            machine.succeed(f"systemctl stop {unit}")
        wait_relay()
        ping()
        capture("stopped")
finally:
    for machine in participants:
        machine.execute("mesh-test capture final")
        machine.copy_from_machine("/tmp/mesh-artifacts", machine.name)
