"""Guest-only Rosenpass adapter fixtures. Never print private or preshared keys."""

import base64
import hashlib
import json
import os
import pathlib
import pwd
import shutil
import signal
import socket
import subprocess
import sys
import time


UNIT = "wireguard-mesh-rosenpass@wg0.service"
PRODUCER = "mesh-rosenpass-wg0"
GROUP = "mesh-psk-wg0"
DIRECTORY = pathlib.Path("/run/wireguard-mesh-rosenpass-wg0")
OUTPUT = DIRECTORY / "peer.psk"
PRIVATE = pathlib.Path("/run/mesh-adapter-test")


def run(*args, **kwargs):
    result = subprocess.run(args, text=True, capture_output=True, timeout=10, **kwargs)
    assert result.returncode == 0, f"{args[0]} failed with status {result.returncode}"
    return result.stdout.strip()


def public(name):
    return run("mesh-test", "public", name)


def output_key():
    text = OUTPUT.read_text().removesuffix("\n")
    raw = base64.b64decode(text, validate=True)
    assert len(raw) == 32 and any(raw), "Invalid published PSK"
    assert base64.b64encode(raw).decode() == text, "Noncanonical published PSK"
    info = OUTPUT.stat()
    assert info.st_uid == pwd.getpwnam(PRODUCER).pw_uid and info.st_mode & 0o7777 == 0o640, "Unsafe published PSK"
    return text


def processes():
    parent = int(run("systemctl", "show", UNIT, "-p", "MainPID", "--value"))
    assert parent > 0, "Adapter is not running"
    children = run("pgrep", "-P", str(parent), "-x", "rosenpass").splitlines()
    assert len(children) == 1, "Expected one mesh-only Rosenpass child"
    child = int(children[0])
    for pid in [parent, child]:
        status = dict(line.split(":", 1) for line in pathlib.Path(f"/proc/{pid}/status").read_text().splitlines() if ":" in line)
        assert set(status["Uid"].split()) == {str(pwd.getpwnam(PRODUCER).pw_uid)}, "Wrong process UID"
        assert int(status["CapEff"], 16) == int(status["CapPrm"], 16) == int(status["CapAmb"], 16) == 0, "Unexpected capabilities"
    args = pathlib.Path(f"/proc/{child}/cmdline").read_bytes().decode().rstrip("\0").split("\0")
    assert args[1:3] == ["exchange", "public-key"] and "device" not in args, "Unexpected Rosenpass invocation"
    assert args[args.index("outfile") + 1] == "psk.raw", "Unpinned raw output"
    return {"adapter_pid": parent, "child_pid": child,
            "listen": args[args.index("listen") + 1], "endpoint": args[args.index("endpoint") + 1]}


def setup(name):
    os.umask(0o077)
    PRIVATE.mkdir(mode=0o700)
    directory = pathlib.Path("/var/lib/mesh-rosenpass-wg0")
    directory.mkdir(mode=0o700)
    shutil.chown(directory, PRODUCER, GROUP)
    assert run("rosenpass", "--version") == "rosenpass 0.2.3", "Unexpected Rosenpass version"
    run("runuser", "-u", PRODUCER, "--", "rosenpass", "gen-keys",
        "--public-key", str(directory / "public"), "--secret-key", str(directory / "secret"))
    shared = pathlib.Path(f"/tmp/shared/adapter-{name}.pub")
    shutil.copyfile(directory / "public", shared)
    shared.chmod(0o644)
    config = {
        "executable": shutil.which("rosenpass"), "peer": public("c" if name == "b" else "b"),
        "public_key_file": str(directory / "public"), "secret_key_file": str(directory / "secret"),
        "peer_public_key_file": str(directory / "peer-public"), "listen_port": 51822, "remote_port": 51822,
        "psk_file": str(OUTPUT), "runtime_dir": str(DIRECTORY / "private"),
        "socket": str(DIRECTORY / "adapter.sock"), "daemon_uid": pwd.getpwnam("mesh-wg0").pw_uid,
    }
    path = pathlib.Path("/etc/wireguard-mesh/rosenpass-wg0.json")
    path.write_text(json.dumps(config))
    path.chmod(0o644)
    # No tunnel or WAN fallback can conceal a missing LAN endpoint update.
    for interface in ["wg0", "wan"]:
        run("iptables", "-A", "OUTPUT", "-o", interface, "-p", "udp", "--dport", "51822", "-j", "REJECT")
    run("iptables", "-N", "MESH_RP_TEST")
    run("iptables", "-A", "OUTPUT", "-o", "lan", "-p", "udp", "--dport", "51822", "-j", "MESH_RP_TEST")
    run("iptables", "-A", "MESH_RP_TEST", "-j", "RETURN")


def hub_check(name):
    peers = dict(line.split("\t", 1) for line in run("wg", "show", "wg0", "preshared-keys").splitlines())
    for peer in (["b", "c"] if name == "a" else [name]):
        expected = base64.b64encode(hashlib.sha256(f"wgmesh-QEMU-TEST-ONLY-hub-{peer}".encode()).digest()).decode()
        assert peers.get(public(peer if name == "a" else "a")) == expected, "Hub PSK changed"
    print(json.dumps({"hub_psk_unchanged": True}))


def main():
    command = sys.argv[1]
    if command == "setup":
        setup(sys.argv[2])
    elif command == "processes":
        print(json.dumps(processes()))
    elif command == "sent":
        counters = [int(line.split()[0]) for line in run("iptables", "-L", "MESH_RP_TEST", "-nvx").splitlines() if "RETURN" in line]
        return 0 if len(counters) == 1 and counters[0] > 0 else 1
    elif command == "check":
        key = output_key()
        peers = dict(line.split("\t", 1) for line in run("wg", "show", "wg0", "preshared-keys").splitlines())
        assert peers.get(public(sys.argv[2])) == key, "Installed PSK differs from adapter output"
        print(json.dumps({"matches_output": True, "permissions": "0640", **processes()}))
    elif command == "mark":
        (PRIVATE / "key").write_text(output_key())
        (PRIVATE / "processes.json").write_text(json.dumps(processes()))
    elif command == "changed":
        return 0 if output_key() != (PRIVATE / "key").read_text() else 1
    elif command == "unchanged":
        assert output_key() == (PRIVATE / "key").read_text(), "Existing valid PSK was replaced"
        assert processes() == json.loads((PRIVATE / "processes.json").read_text()), "Rosenpass restarted"
    elif command == "hub-check":
        hub_check(sys.argv[2])
    elif command == "reject-request":
        # The account has socket group access. A valid withdrawal would stop the
        # process if the server failed to check the caller's UID.
        config = json.loads(pathlib.Path("/etc/wireguard-mesh/rosenpass-wg0.json").read_text())
        request = {"Peer": config["peer"]}
        if sys.argv[2] == "mapping":
            request["PSKFile"] = "/run/unapproved-output"
        elif sys.argv[2] == "peer":
            request["Peer"] = public("a")
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
            conn.settimeout(3)
            conn.connect(config["socket"])
            try:
                conn.sendall(json.dumps(request).encode() + b"\n")
                data = conn.recv(4096)
            except ConnectionResetError:
                data = b""
        assert data == b"", "Restricted adapter request was accepted"
    elif command == "block":
        operation = "-I" if sys.argv[2] == "on" else "-D"
        # Both guests drop received packets. An OUTPUT drop can return EPERM
        # to sendto(), which tests producer exit instead of network loss.
        run("iptables", operation, "INPUT", "-i", "lan", "-p", "udp", "--dport", "51822", "-j", "DROP")
    elif command == "block-handshakes":
        run("tc", "qdisc", "add", "dev", "lan", "clsact")
        for kind in [1, 2]:
            run("tc", "filter", "add", "dev", "lan", "egress", "protocol", "ip", "pref", str(kind),
                "u32", "match", "ip", "protocol", "17", "0xff", "match", "ip", "dport", "51820", "0xffff",
                "match", "u32", f"0x{kind:02x}000000", "0xffffffff", "at", "28", "action", "drop")
    elif command == "kill-child":
        os.kill(processes()["child_pid"], signal.SIGKILL)
    elif command == "restore-file":
        DIRECTORY.mkdir(mode=0o750, exist_ok=True)
        shutil.chown(DIRECTORY, PRODUCER, GROUP)
        OUTPUT.write_text((PRIVATE / "key").read_text() + "\n")
        shutil.chown(OUTPUT, PRODUCER, GROUP)
        OUTPUT.chmod(0o640)
    elif command == "touch-output":
        # Keep the mtime recent but never ahead of a queued daemon probe tick.
        stamp = time.time() - 2
        os.utime(OUTPUT, (stamp, stamp))
    else:
        raise AssertionError("Unknown adapter test command")
    return 0


if __name__ == "__main__":
    os.umask(0o077)
    try:
        sys.exit(main())
    except Exception as error:
        # Never include subprocess output, key values, or assertion operands.
        print(str(error) if isinstance(error, AssertionError) else type(error).__name__, file=sys.stderr)
        sys.exit(1)
