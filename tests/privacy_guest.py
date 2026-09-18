"""Guest-only packet checks. Raw captures and keys must not leave the VM."""

import base64
import json
import os
import pathlib
import shutil
import socket
import struct
import subprocess
import sys
import time


PRIVATE = pathlib.Path("/run/mesh-privacy-test")
PCAP = PRIVATE / "discovery.pcap"
LOG = PRIVATE / "tcpdump.log"
UNIT = "mesh-privacy-capture.service"
DEPENDENCIES = ["PartOf", "Requires", "BindsTo", "PropagatesStopTo", "RequiredBy", "BoundBy", "ConsistsOf"]
DROP = [
    "INPUT", "-i", "lan", "-d", "239.255.77.77", "-p", "udp", "--dport", "51823",
    "-m", "comment", "--comment", "mesh-privacy-test", "-j", "DROP",
]


def run(*args, check=True):
    result = subprocess.run(args, text=True, capture_output=True, timeout=10)
    assert not check or result.returncode == 0, f"{args[0]} failed"
    return result


def service():
    result = run("systemctl", "show", UNIT, "--property=" + ",".join(
        DEPENDENCIES + ["LoadState", "ActiveState", "MainPID", "ControlPID"]
    ), check=False)
    current = dict(line.split("=", 1) for line in result.stdout.splitlines())
    assert result.returncode == 0 or current.get("LoadState") == "not-found", "Cannot inspect capture service"
    return current


def start():
    PRIVATE.mkdir(mode=0o700)
    # INPUT drops preserve outgoing announcements in the capture without EPERM.
    run("iptables", "-w", "5", "-I", *DROP)
    tcpdump = shutil.which("tcpdump")
    assert tcpdump, "tcpdump is not installed"
    run(
        "systemd-run", "--unit=" + UNIT, "--property=Type=exec",
        "--property=RuntimeMaxSec=180", "--property=TimeoutStopSec=5",
        "--property=KillSignal=SIGINT", "--property=UMask=0077",
        "--property=StandardOutput=null", "--property=StandardError=append:" + str(LOG),
        "--", tcpdump, "-i", "lan", "-nn", "-p", "-s", "0", "-U", "-Z", "root",
        "-w", str(PCAP), "ip and udp port 51823",
    )
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        assert service()["ActiveState"] == "active", "Capture service exited before readiness"
        # Type=exec alone does not prove that the packet socket and filter are ready.
        if LOG.exists() and "listening on lan," in LOG.read_text() and PCAP.exists():
            return
        time.sleep(0.1)
    raise AssertionError("Capture did not become ready")


def stop(require_active=True):
    current = service()
    if require_active:
        assert current["ActiveState"] == "active" and int(current["MainPID"]) > 0, "Capture ended before direct activation"
    if current["LoadState"] != "not-found":
        # Inspect stop propagation before stopping this fixture, not the mesh daemon.
        assert not any(current[name] for name in ["PropagatesStopTo", "RequiredBy", "BoundBy", "ConsistsOf"]), "Unexpected capture stop propagation"
        run("systemctl", "stop", UNIT)
        current = service()
        assert current["ActiveState"] == "inactive" and current["MainPID"] == current["ControlPID"] == "0", "Capture did not stop"
    if require_active:
        assert "0 packets dropped by kernel" in LOG.read_text().splitlines(), "Capture lost packets or did not flush"
        (PRIVATE / "stopped").touch()


def inspect_capture(stream, public_keys):
    header = stream.read(24)
    assert len(header) == 24, "Missing PCAP header"
    endian = {
        b"\xd4\xc3\xb2\xa1": "<", b"\xa1\xb2\xc3\xd4": ">",
        b"\x4d\x3c\xb2\xa1": "<", b"\xa1\xb2\x3c\x4d": ">",
    }.get(header[:4])
    assert endian, "Unsupported PCAP format"
    major, minor, _, _, snaplen, linktype = struct.unpack(endian + "HHIIII", header[4:])
    assert (major, minor) == (2, 4) and linktype == 1, "Expected Ethernet PCAP"
    assert 554 <= snaplen <= 262144, "Unexpected capture snap length"
    destinations = {
        "239.255.77.77": "multicast", "172.20.2.255": "broadcast",
        "172.20.2.2": "unicast_b", "172.20.2.3": "unicast_c",
    }
    counts = dict.fromkeys(destinations.values(), 0)
    fields = [
        b'"op":', b'"token":', b'"port":', b'"proof":', b'"experimental_rekey":',
        b'"sender":', b'"recipient":', b'"version":', b'"type":', b'"session":', b'"counter":',
    ]
    forbidden = list(fields)
    for encoded in public_keys:
        raw = base64.b64decode(encoded, validate=True)
        assert len(encoded) == 44 and len(raw) == 32, "Invalid test public key"
        forbidden.extend([encoded, raw])
    while True:
        record = stream.read(16)
        if not record:
            break
        assert len(record) == 16, "Truncated PCAP record header"
        _, _, captured, original = struct.unpack(endian + "IIII", record)
        assert 42 <= captured == original <= snaplen, "Truncated or invalid captured packet"
        frame = stream.read(captured)
        assert len(frame) == captured, "Truncated PCAP packet"
        assert frame[12:14] == b"\x08\x00", "Expected IPv4 Ethernet packet"
        ip = frame[14:]
        ihl = (ip[0] & 15) * 4
        total = struct.unpack_from("!H", ip, 2)[0]
        assert ip[0] >> 4 == 4 and 20 <= ihl <= total - 8 and total <= len(ip), "Invalid IPv4 length"
        assert ip[9] == 17 and struct.unpack_from("!H", ip, 6)[0] & 0x3FFF == 0, "Expected unfragmented UDP"
        source, destination, length, _ = struct.unpack_from("!HHHH", ip, ihl)
        assert 51823 in [source, destination] and length == total - ihl, "Invalid discovery UDP packet"
        payload = ip[ihl + 8:total]
        assert len(payload) == 512, "Discovery UDP payload is not exactly 512 bytes"
        assert not any(value in payload for value in forbidden), "Plaintext key or control field in discovery payload"
        address = socket.inet_ntoa(ip[16:20])
        assert address in destinations, "Unexpected discovery destination"
        counts[destinations[address]] += 1
    assert all(counts.values()), "Missing multicast, broadcast, or bidirectional unicast discovery"
    return {"packets": sum(counts.values()), "payload_bytes": 512, "destinations": counts, "public_keys_checked": len(public_keys)}


def check():
    assert (PRIVATE / "stopped").exists(), "Capture must be stopped before inspection"
    assert PRIVATE.stat().st_mode & 0o777 == 0o700, "Unsafe capture directory permissions"
    assert PCAP.stat().st_mode & 0o077 == 0, "Unsafe capture file permissions"
    public_keys = [run("mesh-test", "public", name).stdout.strip().encode("ascii") for name in ["a", "b", "c"]]
    with PCAP.open("rb") as stream:
        counts = inspect_capture(stream, public_keys)
    directory = pathlib.Path("/tmp/mesh-artifacts")
    directory.mkdir(exist_ok=True)
    text = json.dumps(counts, sort_keys=True)
    (directory / "packet-privacy.json").write_text(text + "\n")
    print(text, flush=True)


def cleanup():
    try:
        stop(require_active=False)
    finally:
        # Delete only this exact INPUT rule. Leave all other firewall rules alone.
        result = run("iptables", "-w", "5", "-C", *DROP, check=False)
        assert result.returncode in [0, 1], "Cannot inspect multicast drop rule"
        if result.returncode == 0:
            run("iptables", "-w", "5", "-D", *DROP)
        if PRIVATE.exists():
            shutil.rmtree(PRIVATE)


if __name__ == "__main__":
    os.umask(0o077)
    try:
        assert os.geteuid() == 0, "Fixture requires guest root"
        {"start": start, "stop": stop, "check": check, "cleanup": cleanup}[sys.argv[1]]()
    except Exception as error:
        # Never print packet bytes, key values, subprocess output, or tracebacks.
        reason = str(error) if isinstance(error, AssertionError) else type(error).__name__
        print(json.dumps({"packet_privacy_error": reason}), flush=True)
        sys.exit(1)
