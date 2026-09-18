"""Guest-only interface recovery fixtures. Never copy the saved journal out."""

import base64
import json
import os
import pathlib
import re
import subprocess
import sys
import time


UNIT = "wireguard-meshd@wg0.service"
JOURNAL = pathlib.Path("/var/lib/wireguard-mesh-wg0/recovery.json")
PRIVATE = pathlib.Path("/run/mesh-recovery-test")
OVERRIDE = pathlib.Path(f"/run/systemd/system/{UNIT}.d/zz-mesh-recovery-test.conf")
DEPENDENCIES = ["PartOf", "Requires", "BindsTo", "PropagatesStopTo", "RequiredBy", "BoundBy", "ConsistsOf"]
PROPERTIES = DEPENDENCIES + [
    "ActiveState", "SubState", "MainPID", "ControlPID", "Result", "ExecMainStatus",
    "ExecStopPost", "Restart", "WatchdogUSec", "DynamicUser", "NoNewPrivileges",
    "CapabilityBoundingSet", "AmbientCapabilities", "Type",
]


def run(*args):
    result = subprocess.run(args, text=True, capture_output=True, timeout=10)
    # Do not include command output: a WireGuard query can contain keys.
    label = " ".join(args[:2]) if args[0] == "systemctl" else args[0]
    assert result.returncode == 0, f"{label} failed with exit status {result.returncode}"
    return result.stdout.strip()


def emit(stage, **values):
    text = json.dumps({"stage": stage, **values}, sort_keys=True)
    directory = pathlib.Path("/tmp/mesh-artifacts")
    directory.mkdir(exist_ok=True)
    (directory / f"interface-recovery-{stage}.json").write_text(text + "\n")
    print(text, flush=True)


def service():
    return dict(line.split("=", 1) for line in run(
        "systemctl", "show", UNIT, "--all", "--property=" + ",".join(PROPERTIES)
    ).splitlines())


def service_settings(current):
    return {name: current[name] for name in ["Restart", "WatchdogUSec"]}


def inspect_dependencies(stage):
    current = service()
    emit(stage, dependencies={name: current[name] for name in DEPENDENCIES})
    assert not any(current[name] for name in ["PropagatesStopTo", "RequiredBy", "BoundBy", "ConsistsOf"]), "Unexpected stop propagation"
    return current


def wait_for(check, message):
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        result = check()
        if result:
            return result
        time.sleep(0.1)
    raise AssertionError(message)


def stopped():
    current = service()
    if current["ActiveState"] in ["failed", "inactive"] and current["MainPID"] == current["ControlPID"] == "0":
        return current
    return None


def frozen(pid):
    status = pathlib.Path(f"/proc/{pid}/status")
    if not status.exists():
        return False
    return any(line.startswith("State:") and line.split()[1] in ["T", "t"] for line in status.read_text().splitlines())


def public(name):
    return run("mesh-test", "public", name)


def journal():
    assert JOURNAL.is_file(), "Recovery journal was removed"
    assert JOURNAL.stat().st_mode & 0o777 == 0o600, "Unsafe journal permissions"
    data = JOURNAL.read_bytes()
    value = json.loads(data)
    assert value["Version"] == 1 and value["Name"] == "wg0", "Unexpected journal header"
    assert value["Public"] == list(base64.b64decode(public("b"))), "Journal identity changed"
    assert isinstance(value["Peers"], dict), "Invalid journal records"
    return data, value


def active_journal():
    data, value = journal()
    assert set(value["Peers"]) == {public("c")}, "Expected one journal record"
    record = next(iter(value["Peers"].values()))
    assert record["Phase"] == "active", "Expected an active journal record"
    assert record["IP"] == "10.77.0.3" and record["Prefix"] == "10.77.0.0/24", "Unexpected journal prefix"
    assert record["Owner"] == list(base64.b64decode(public("a"))), "Unexpected journal owner"
    return data


def unchanged_journal(case):
    assert active_journal() == (PRIVATE / f"{case}-active.json").read_bytes(), "Active journal bytes changed"


def completed_journal():
    assert journal()[1]["Peers"] == {}, "Recovery did not retain an empty completed journal"


def kernel():
    # Compare configuration, not changing handshake times or traffic counters.
    # PSKs stay in guest memory and are never included in markers or artifacts.
    return {field: run("wg", "show", "wg0", field) for field in [
        "public-key", "listen-port", "fwmark", "peers", "allowed-ips",
        "endpoints", "persistent-keepalive", "preshared-keys",
    ]}


def baseline(prefix="10.77.0.0/24"):
    current = kernel()
    hub = public("a")
    assert current["public-key"] == public("b"), "Interface identity changed"
    assert current["listen-port"] == "51820", "Interface listen port changed"
    assert current["peers"] == hub, "Recreated interface must have only the hub peer"
    assert current["allowed-ips"] == f"{hub}\t{prefix}", "Unexpected stable ownership"
    assert current["endpoints"] == f"{hub}\t192.0.2.1:51820", "Hub endpoint changed"
    return current


def stoppost(previous, expected_status, main_status):
    def finished():
        current = stopped()
        if current and current["ActiveState"] == "failed" and current["ExecStopPost"] != previous:
            return current
        return None

    current = wait_for(finished, "Service did not finish a new ExecStopPost invocation")
    assert current["ActiveState"] == "failed" and current["Restart"] == "no", "Service did not stay stopped"
    assert current["ExecMainStatus"] == str(main_status), "Unexpected main process exit"
    entry = current["ExecStopPost"]
    assert entry != previous, "ExecStopPost did not run again"
    match = re.search(r"\bpid=(\d+)\s*;\s*code=exited\s*;\s*status=(\d+)", entry)
    assert match and int(match[1]) > 0 and int(match[2]) == expected_status, "Unexpected ExecStopPost result"


def start():
    # A cleanly stopped unit can be unloaded, so reset-failed can reject it.
    if service()["ActiveState"] == "failed":
        run("systemctl", "reset-failed", UNIT)
    run("systemctl", "start", "--no-block", UNIT)


def ready():
    current = service()
    return current if current["ActiveState"] in ["active", "failed"] else None


def restart_service(stage):
    inspect_dependencies(f"{stage}-restart-dependencies")
    run("systemctl", "stop", "--no-block", UNIT)
    wait_for(stopped, "Service did not stop for settings restart")
    start()
    assert wait_for(ready, "Settings restart did not finish")["ActiveState"] == "active", "Settings restart failed"


def prepare():
    current = inspect_dependencies("prepare-dependencies")
    assert current["ActiveState"] == "active" and current["Type"] == "notify", "Expected a running notify service"
    assert current["DynamicUser"] == current["NoNewPrivileges"] == "yes", "Service hardening changed"
    assert int(run("ps", "-o", "uid=", "-p", current["MainPID"])) != 0, "Daemon runs as root"
    for name in ["CapabilityBoundingSet", "AmbientCapabilities"]:
        assert "cap_net_admin" in current[name].split(), "Controller lacks CAP_NET_ADMIN"
    assert "wireguard-meshd " in current["ExecStopPost"] and "-restore" in current["ExecStopPost"], "Expected the real recovery controller"
    assert not OVERRIDE.exists(), "Recovery override already exists"
    PRIVATE.mkdir(mode=0o700)
    original = service_settings(current)
    (PRIVATE / "settings.json").write_text(json.dumps(original))
    OVERRIDE.parent.mkdir(parents=True, exist_ok=True)
    # A frozen daemon cannot send watchdog notifications. Restore both settings.
    OVERRIDE.write_text("[Service]\nRestart=no\nWatchdogSec=0\n")
    OVERRIDE.chmod(0o644)
    run("systemctl", "daemon-reload")
    emit("prepare-reloaded", saved=original, read=service_settings(service()))
    # Reload alone need not update the running service's watchdog interval.
    restart_service("prepare")
    current = service_settings(service())
    emit("prepare-restarted", saved=original, read=current)
    assert current["Restart"] == "no" and current["WatchdogUSec"] in ["0", "infinity"], f"Recovery override was not applied: saved={original}, read={current}"
    emit("prepared", saved=original, read=current, restart_disabled=True, watchdog_disabled=True)


def recreate(case):
    current = inspect_dependencies(f"{case}-freeze-dependencies")
    assert current["ActiveState"] == "active", "Daemon is not active"
    assert current["Restart"] == "no" and current["WatchdogUSec"] in ["0", "infinity"], f"Missing recovery override: read={service_settings(current)}"
    active_journal()
    pid = current["MainPID"]
    must_kill = True
    try:
        run("systemctl", "kill", "--kill-whom=main", "--signal=SIGSTOP", UNIT)
        wait_for(lambda: frozen(pid), "Daemon did not stop on SIGSTOP")
        saved = active_journal()
        (PRIVATE / f"{case}-active.json").write_bytes(saved)
        index = pathlib.Path("/sys/class/net/wg0/ifindex").read_text()
        run("ip", "link", "delete", "dev", "wg0")
        run("mesh-test", "setup", "b", "same-lan")
        assert pathlib.Path("/sys/class/net/wg0/ifindex").read_text() != index, "Interface was not recreated"
        baseline()
        if case == "conflict":
            # The host still belongs to the hub, but not through the saved prefix.
            run("wg", "set", "wg0", "peer", public("a"), "allowed-ips", "10.77.0.0/25")
        expected = baseline("10.77.0.0/25" if case == "conflict" else "10.77.0.0/24")
        unchanged_journal(case)
        assert frozen(pid), "Daemon was not frozen throughout interface recreation"
        emit(f"{case}-recreated", interface_recreated=True, identity_matches=True,
             mesh_peer_absent=True, active_records=1, journal_unchanged=True,
             conflicting_prefix=case == "conflict")
        inspect_dependencies(f"{case}-kill-dependencies")
        run("systemctl", "kill", "--kill-whom=main", "--signal=SIGKILL", UNIT)
        must_kill = False
        stoppost(current["ExecStopPost"], 1 if case == "conflict" else 0, 9)
        assert kernel() == expected, "ExecStopPost changed the recreated kernel configuration"
        if case == "conflict":
            unchanged_journal(case)
        else:
            completed_journal()
        emit(f"{case}-stoppost", stoppost_status=1 if case == "conflict" else 0,
             service_stopped=True, kernel_unchanged=True, journal_present=True,
             journal_unchanged=case == "conflict", completed=case == "baseline")
    finally:
        if must_kill:
            remaining = inspect_dependencies(f"{case}-abort-dependencies")
            if remaining["MainPID"] == pid:
                run("systemctl", "kill", "--kill-whom=main", "--signal=SIGKILL", UNIT)
            wait_for(stopped, "Fixture abort did not finish recovery")


def refuse_start():
    current = inspect_dependencies("conflict-start-dependencies")
    assert stopped(), "Service must be stopped before the conflicting restart"
    unchanged_journal("conflict")
    expected = baseline("10.77.0.0/25")
    start()
    stoppost(current["ExecStopPost"], 1, 1)
    unchanged_journal("conflict")
    assert kernel() == expected, "Failed startup changed the conflicting kernel configuration"
    emit("conflict-start-refused", service_stopped=True, stoppost_status=1,
         journal_unchanged=True, kernel_unchanged=True)


def repair():
    assert stopped(), "Service must be stopped before ownership repair"
    unchanged_journal("conflict")
    expected = baseline("10.77.0.0/25")
    run("wg", "set", "wg0", "peer", public("a"), "allowed-ips", "10.77.0.0/24")
    expected["allowed-ips"] = f"{public('a')}\t10.77.0.0/24"
    assert kernel() == expected, "Repair changed more than the hub AllowedIPs"
    unchanged_journal("conflict")
    emit("conflict-repaired", only_hub_allowed_ips_changed=True, journal_unchanged=True)


def restart(case):
    assert stopped(), "Service must be stopped before recovery startup"
    baseline()
    if case == "conflict":
        unchanged_journal(case)
    else:
        completed_journal()
    start()
    assert wait_for(ready, "Service startup did not finish")["ActiveState"] == "active", "Recovery startup failed"
    completed_journal()
    emit(f"{case}-restarted", service_active=True, journal_present=True, completed=True)


def cleanup():
    settings = PRIVATE / "settings.json"
    if not settings.exists():
        assert not OVERRIDE.exists(), "Cannot restore an override without its saved settings"
        return
    original = json.loads(settings.read_text())
    needs_start = True
    try:
        current = inspect_dependencies("cleanup-dependencies")
        if current["ActiveState"] == "active" and current["MainPID"] != "0" and not frozen(current["MainPID"]):
            needs_start = False
        else:
            if not stopped():
                if current["MainPID"] != "0" and frozen(current["MainPID"]):
                    run("systemctl", "kill", "--kill-whom=main", "--signal=SIGKILL", UNIT)
                else:
                    run("systemctl", "stop", "--no-block", UNIT)
                wait_for(stopped, "Cleanup could not stop the service")
            if not pathlib.Path("/sys/class/net/wg0").exists():
                run("mesh-test", "setup", "b", "same-lan")
            run("wg", "set", "wg0", "peer", public("a"), "allowed-ips", "10.77.0.0/24")
    finally:
        # Remove only our drop-in. Never remove or rewrite the recovery journal.
        OVERRIDE.unlink(missing_ok=True)
        run("systemctl", "daemon-reload")
        emit("cleanup-reloaded", saved=original, read=service_settings(service()))
    if needs_start:
        start()
        assert wait_for(ready, "Cleanup startup did not finish")["ActiveState"] == "active", "Cleanup could not restore the service"
    else:
        restart_service("cleanup")
    restored = service_settings(service())
    emit("cleanup-restarted", saved=original, read=restored)
    assert restored == original, f"Service settings were not restored: saved={original}, read={restored}"
    emit("cleanup", saved=original, read=restored, settings_restored=True, service_active=True)


if __name__ == "__main__":
    os.umask(0o077)
    command = sys.argv[1]
    try:
        assert os.geteuid() == 0, "Fixture requires guest root"
        if command in ["recreate", "restart"]:
            case = sys.argv[2]
            assert case in ["baseline", "conflict"], "Unknown recovery case"
            {"recreate": recreate, "restart": restart}[command](case)
        else:
            {"prepare": prepare, "refuse-start": refuse_start, "repair": repair, "cleanup": cleanup}[command]()
    except Exception as error:
        # Do not print subprocess output, journal contents, or exception operands.
        reason = str(error) if isinstance(error, AssertionError) else type(error).__name__
        emit("failed", command=command, reason=reason)
        sys.exit(1)
