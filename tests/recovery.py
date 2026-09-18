def interface_recovery_test():
    assert mode == "same-lan"
    try:
        before = active_counts()
        b.succeed("mesh-recovery-test prepare", timeout=120)
        wait_direct(before)
        direct_traffic()
        for case in ["baseline", "conflict"]:
            with subtest(f"active journal survives interface recreation: {case}"):
                b.succeed(f"mesh-recovery-test recreate {case}", timeout=120)
                prefix = "10.77.0.0/24" if case == "baseline" else "10.77.0.0/25"
                assert state(b)["allowed-ips"] == {public["a"]: prefix}
                c.succeed(f"systemctl is-active {unit}", timeout=10)

                if case == "conflict":
                    b.succeed("mesh-recovery-test refuse-start", timeout=60)
                    assert state(b)["allowed-ips"] == {public["a"]: prefix}
                    capture("interface-recovery-conflict-refused")
                    b.succeed("mesh-recovery-test repair", timeout=30)

                wait_relay()
                ping()
                capture(f"interface-recovery-{case}-relay")
                before = active_counts()
                b.succeed(f"mesh-recovery-test restart {case}", timeout=60)
                b.wait_for_unit(unit, timeout=30)
                c.succeed(f"systemctl is-active {unit}", timeout=10)
                wait_direct(before)
                direct_traffic()
                capture(f"interface-recovery-{case}-direct")
    finally:
        # This also kills a frozen main process if a fixture command failed.
        b.succeed("mesh-recovery-test cleanup", timeout=120)
        c.succeed(f"systemctl is-active {unit}", timeout=10)
