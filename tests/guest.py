"""Guest-only test support. All keys are NON-PRODUCTION test data."""

import base64
import hashlib
import json
import os
import pathlib
import pwd
import shutil
import subprocess
import sys


def run(*args, **kwargs):
    return subprocess.check_output(args, text=True, **kwargs).strip()


def keys(name):
    # Deterministic NON-PRODUCTION keys. Never use these outside these VMs.
    private = base64.b64encode(hashlib.sha256(f"wgmesh-QEMU-TEST-ONLY-{name}".encode()).digest()).decode()
    return private, run("wg", "pubkey", input=private)


def state():
    # Do not use dump/showconf: they expose private and preshared keys.
    result = {}
    for field in ["allowed-ips", "endpoints", "latest-handshakes", "transfer"]:
        result[field] = dict(line.split("\t", 1) for line in run("wg", "show", "wg0", field).splitlines())
    return result


command = sys.argv[1]
if command == "setup":
    name, mode = sys.argv[2:]
    if name in ["nb", "nc"]:
        run("iptables", "-t", "nat", "-A", "POSTROUTING", "-o", "wan", "-j", "MASQUERADE")
        run("iptables", "-P", "FORWARD", "DROP")
        run("iptables", "-A", "FORWARD", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT")
        run("iptables", "-A", "FORWARD", "-i", "lan", "-o", "wan", "-d", "192.0.2.1", "-p", "udp", "--dport", "51820", "-j", "ACCEPT")
        sys.exit(0)
    number = {"a": 1, "b": 2, "c": 3}[name]
    private, _ = keys(name)
    keyfile = pathlib.Path("/run/test-only-wg.key")
    keyfile.write_text(private)
    keyfile.chmod(0o600)
    run("ip", "link", "add", "wg0", "type", "wireguard")
    run("wg", "set", "wg0", "private-key", str(keyfile), "listen-port", "51820")
    keyfile.unlink()
    run("ip", "address", "add", f"10.77.0.{number}/24", "dev", "wg0")
    run("ip", "link", "set", "wg0", "up")
    if name == "a":
        for peer, n in [("b", 2), ("c", 3)]:
            run("wg", "set", "wg0", "peer", keys(peer)[1], "allowed-ips", f"10.77.0.{n}/32")
        run("tc", "qdisc", "add", "dev", "wg0", "root", "netem", "delay", "40ms")
        if mode == "rosenpass":
            run("iptables", "-N", "ROSENPASS_TEST")
            run("iptables", "-A", "FORWARD", "-i", "wg0", "-o", "wg0", "-p", "udp", "--dport", "51822", "-j", "ROSENPASS_TEST")
            for source in ["10.77.0.2", "10.77.0.3"]:
                run("iptables", "-A", "ROSENPASS_TEST", "-s", source, "-j", "RETURN")
    else:
        if mode == "nat":
            run("ip", "route", "replace", "192.0.2.0/24", "via", f"172.20.{number}.1", "dev", "lan")
        run("wg", "set", "wg0", "peer", keys("a")[1], "allowed-ips", "10.77.0.0/24", "endpoint", "192.0.2.1:51820", "persistent-keepalive", "1")
        peer = "c" if name == "b" else "b"
        config = {
            "address": f"10.77.0.{number}",
            "peers": [{"public_key": keys(peer)[1], "ip": "10.77.0.3" if name == "b" else "10.77.0.2"}],
            # No include override: exercise physical-interface autodetection.
            "exclude": ["eth0", "wan"],
            "discovery_interval": "1s", "broadcast_after": "3s",
            "probe_interval": "200ms", "latency_window": "5s",
            "failure_timeout": "2s", "cooldown": "3s",
            "minimum_gain": "2ms", "minimum_gain_fraction": 0.2,
        }
        if mode == "rosenpass":
            config["peers"][0]["preshared_key_file"] = "/run/rosenpass/peer.psk"
            # Leave max age unset to exercise the three-minute default.
        directory = pathlib.Path("/etc/wireguard-mesh")
        directory.mkdir(exist_ok=True)
        (directory / "wg0.json").write_text(json.dumps(config))
elif command == "state":
    print(json.dumps(state()))
elif command == "public":
    print(keys(sys.argv[2])[1])
elif command == "rp-setup":
    name = sys.argv[2]
    number, remote = (2, 3) if name == "b" else (3, 2)
    os.umask(0o077)
    directory = pathlib.Path("/var/lib/rosenpass")
    directory.mkdir(mode=0o700)
    shutil.chown(directory, "rosenpass", "mesh-psk")
    run("runuser", "-u", "rosenpass", "--", "rosenpass", "gen-keys",
        "--public-key", str(directory / "public"), "--secret-key", str(directory / "secret"))
    # Only public keys cross the VM boundary. Private keys remain in each VM.
    public = pathlib.Path(f"/tmp/shared/rosenpass-{name}.pub")
    shutil.copyfile(directory / "public", public)
    public.chmod(0o644)
    config = pathlib.Path("/etc/rosenpass.toml")
    config.write_text(f'''public_key = "/var/lib/rosenpass/public"
secret_key = "/var/lib/rosenpass/secret"
listen = ["10.77.0.{number}:51822"]
[[peers]]
public_key = "/var/lib/rosenpass/peer-public"
endpoint = "10.77.0.{remote}:51822"
key_out = "/run/rosenpass/peer.psk"
''')
    config.chmod(0o644)
elif command == "rp-relay-check":
    counters = [int(line.split()[0]) for line in run("iptables", "-L", "ROSENPASS_TEST", "-nvx").splitlines() if "RETURN" in line]
    assert len(counters) == 2 and all(n > 0 for n in counters), "No Rosenpass relay traffic"
    print(json.dumps({"relay_packets": counters}))
elif command in ["psk-check", "psk-mark", "psk-changed"]:
    output = pathlib.Path("/run/rosenpass/peer.psk")
    text = output.read_text().removesuffix("\n")
    raw = base64.b64decode(text, validate=True)
    assert len(raw) == 32 and any(raw), "Invalid Rosenpass output"
    assert base64.b64encode(raw).decode() == text, "Noncanonical Rosenpass output"
    info = output.stat()
    assert info.st_uid == pwd.getpwnam("rosenpass").pw_uid and info.st_mode & 0o7777 == 0o640, "Unsafe output permissions"
    baseline = pathlib.Path("/run/rosenpass-test-baseline")
    if command == "psk-mark":
        os.umask(0o077)
        baseline.write_text(text)
    elif command == "psk-changed":
        sys.exit(0 if text != baseline.read_text() else 1)
    else:
        # Read PSKs only inside the guest. Never print keys or assertion operands.
        peers = dict(line.split("\t", 1) for line in run("wg", "show", "wg0", "preshared-keys").splitlines())
        assert peers.get(keys(sys.argv[2])[1]) == text, "WireGuard PSK differs from Rosenpass output"
        print(json.dumps({"matches_output": True, "producer_uid": info.st_uid, "mode": "0640"}))
elif command == "capture":
    directory = pathlib.Path("/tmp/mesh-artifacts")
    directory.mkdir(exist_ok=True)
    stage = sys.argv[2]
    commands = {
        "network": ["ip", "-details", "address"],
        "routes": ["ip", "route", "show", "table", "all"],
        "journal": ["journalctl", "-b", "-u", "wireguard-meshd@wg0", "--no-pager"],
        "service": ["systemctl", "show", "wireguard-meshd@wg0", "-p", "ActiveState,SubState,Result,ExecMainStatus,DynamicUser,User,MainPID,CapabilityBoundingSet,AmbientCapabilities,NoNewPrivileges"],
        "nat": ["iptables-save", "-c"],
        "rosenpass-journal": ["journalctl", "-b", "-u", "rosenpass", "--no-pager"],
    }
    for label, args in commands.items():
        output = subprocess.run(args, text=True, capture_output=True)
        (directory / f"{stage}-{label}.txt").write_text(output.stdout + output.stderr)
    if subprocess.run(["ip", "link", "show", "wg0"], capture_output=True).returncode == 0:
        (directory / f"{stage}-wireguard.json").write_text(json.dumps(state(), indent=2))
else:
    raise SystemExit("Unknown test command")
