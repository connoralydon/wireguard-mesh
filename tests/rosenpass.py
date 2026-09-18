def rosenpass_test():
    rp = "rosenpass.service"
    with subtest("missing PSK inhibits direct despite a shared LAN"):
        for machine in [b, c]:
            machine.wait_until_succeeds(
                f"journalctl -b -u {unit} --no-pager | grep -q 'PSK file unavailable'", timeout=15
            )
        time.sleep(6)
        relay()
        assert active_counts() == [0, 0]
        ping()

    with subtest("real Rosenpass file-output exchange through the relay"):
        for machine in [b, c]:
            machine.succeed("ip link set lan down")
            machine.succeed(f"mesh-test rp-setup {machine.name}")
        for machine, remote in [(b, "c"), (c, "b")]:
            machine.succeed(f"install -m 0444 /tmp/shared/rosenpass-{remote}.pub /var/lib/rosenpass/peer-public")
            machine.succeed(f"systemctl start {rp}")
            machine.wait_for_unit(rp)
            machine.succeed(f"test $(ps -o uid= -p $(systemctl show {rp} -p MainPID --value)) -ne 0")
            machine.succeed(f"test $(systemctl show {rp} -p User --value) = rosenpass")
            machine.succeed(f"test -z \"$(systemctl show {rp} -p CapabilityBoundingSet --value)\"")
            machine.succeed(f"test $(systemctl show {rp} -p User --value) != $(systemctl show {unit} -p User --value)")
        for machine in [b, c]:
            machine.wait_until_succeeds(
                f"journalctl -b -u {rp} --no-pager | grep -q 'key-file .* exchanged'", timeout=60
            )
            machine.succeed("mesh-test psk-mark")
        relay()
        a.succeed("mesh-test rp-relay-check > /tmp/mesh-artifacts/rosenpass-relay.json")
        capture("rosenpass-exchanged-via-relay")

    with subtest("generated output is installed by the mesh daemon"):
        for machine in [b, c]:
            machine.succeed("ip link set lan up")
        wait_direct([0, 0])
        for machine, remote in [(b, "c"), (c, "b")]:
            machine.succeed(f"mesh-test psk-check {remote} > /tmp/mesh-artifacts/initial-psk-check.json")
            machine.succeed("mesh-test psk-mark")
        direct_traffic()
        capture("rosenpass-direct")

    with subtest("natural Rosenpass rekey requalifies a fresh WireGuard path"):
        before = active_counts()
        handshakes = [int(state(machine)["latest-handshakes"][public[remote]]) for machine, remote in [(b, "c"), (c, "b")]]
        pids = [machine.succeed(f"systemctl show {rp} -p MainPID --value") for machine in [b, c]]
        started = time.monotonic()
        b.wait_until_succeeds("mesh-test psk-changed", timeout=210)
        c.wait_until_succeeds("mesh-test psk-changed", timeout=30)
        wait_direct(before)
        for machine, remote, old, pid in zip([b, c], ["c", "b"], handshakes, pids):
            machine.succeed(f"mesh-test psk-check {remote} > /tmp/mesh-artifacts/rekey-psk-check.json")
            assert int(state(machine)["latest-handshakes"][public[remote]]) > old
            assert machine.succeed(f"systemctl show {rp} -p MainPID --value") == pid
            # Either peer can send the rollback before the other's file poll.
            machine.succeed(f"journalctl -b -u {unit} --no-pager | grep -Eq 'reason=\"(PSK file changed or unavailable|remote rollback)\"'")
        assert any("PSK file changed or unavailable" in machine.succeed(f"journalctl -b -u {unit} --no-pager") for machine in [b, c])
        print(f"Natural Rosenpass rekey and WireGuard requalification: {time.monotonic() - started:.2f}s")
        direct_traffic()
        capture("rosenpass-rekey")

    with subtest("stopped Rosenpass and deleted output restore the relay"):
        for machine in [b, c]:
            machine.succeed(f"systemctl show {rp} -p PartOf,Requires,BindsTo,PropagatesStopTo")
            machine.succeed(f"systemctl stop {rp}")
            machine.succeed("rm /run/rosenpass/peer.psk")
        wait_relay()
        ping()
        for _ in range(8):
            relay()
            time.sleep(1)
        for machine in [b, c]:
            machine.succeed(f"systemctl is-active {unit}")
            machine.fail(f"systemctl is-active {rp}")
        capture("rosenpass-unavailable")
