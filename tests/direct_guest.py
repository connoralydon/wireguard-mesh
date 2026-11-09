"""Guest-only helpers. Keys are deterministic and used only by these VMs."""
import base64
import hashlib
import json
import pathlib
import re
import signal
import socket
import subprocess
import sys
import threading
import time


def run(*args, **kwargs):
    return subprocess.check_output(args, text=True, **kwargs).strip()


def keys(name):
    private = base64.b64encode(hashlib.sha256(f"wgmesh-QEMU-TEST-ONLY-{name}".encode()).digest()).decode()
    return private, run("wg", "pubkey", input=private)


def state(interface):
    return {field: dict(line.split("\t", 1) for line in run("wg", "show", interface, field).splitlines())
            for field in ("allowed-ips", "endpoints", "latest-handshakes", "transfer")}


def owned_interface():
    links = json.loads(run("ip", "-j", "-d", "link", "show"))
    matches = [link["ifname"] for link in links
               if link.get("ifalias", "").startswith("wireguard-mesh:")
               and link.get("linkinfo", {}).get("info_kind") == "wireguard"]
    if len(matches) != 1:
        raise ValueError(f"expected one owned WireGuard interface, got {matches}")
    return matches[0]


def probe(local, remote):
    """Keep both echo servers and both clients alive until the service stops."""
    done = threading.Event()
    samples = {"udp": [], "tcp": []}
    progress = {"udp": {"seq": -1, "received": None}, "tcp": {"seq": -1, "received": None, "connection": 0}}
    signal.signal(signal.SIGTERM, lambda *_: done.set())

    def udp_server():
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(.2)
        sock.bind((local, 19001))
        while not done.is_set():
            try:
                data, address = sock.recvfrom(1024)
                sock.sendto(data, address)
            except (socket.timeout, OSError):
                pass
        sock.close()

    def tcp_server():
        sock = socket.socket()
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.settimeout(.2)
        sock.bind((local, 19002))
        sock.listen(4)
        while not done.is_set():
            try:
                conn, _ = sock.accept()
                conn.settimeout(.2)
                with conn:
                    while not done.is_set():
                        try:
                            data = conn.recv(4096)
                            if not data:
                                break
                            conn.sendall(data)
                        except socket.timeout:
                            pass
                        except OSError:
                            break
            except socket.timeout:
                pass
        sock.close()

    def udp_client():
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((local, 0))
        sock.settimeout(.005)
        pending = {}
        seq = 0
        next_send = time.monotonic()
        while not done.is_set():
            now = time.monotonic()
            if now >= next_send:
                sample = {"seq": seq, "sent": time.time(), "received": None}
                samples["udp"].append(sample)
                pending[seq] = sample
                try:
                    sock.sendto(str(seq).encode(), (remote, 19001))
                except OSError:
                    pass
                seq += 1
                next_send = now + .02
            try:
                data, _ = sock.recvfrom(1024)
                item = pending.pop(int(data), None)
                if item is not None:
                    item["received"] = time.time()
                    progress["udp"] = {"seq": item["seq"], "received": item["received"]}
            except (socket.timeout, OSError, ValueError):
                pass
        sock.close()

    def tcp_client():
        seq = 0
        connection = 0
        while not done.is_set():
            sock = socket.socket()
            sock.settimeout(1)
            try:
                sock.bind((local, 0))
                if connection:
                    connection += 1
                    progress["tcp"] = {**progress["tcp"], "connection": connection}
                    samples["tcp"].append({"seq": seq, "sent": time.time(), "received": None, "connection": connection})
                sock.connect((remote, 19002))
                if not connection:
                    connection = 1
                progress["tcp"] = {**progress["tcp"], "connection": connection}
                buffer = b""
                while not done.is_set():
                    sample = {"seq": seq, "sent": time.time(), "received": None, "connection": connection}
                    samples["tcp"].append(sample)
                    sock.sendall(f"{seq}\n".encode())
                    while b"\n" not in buffer:
                        if done.is_set():
                            return
                        try:
                            chunk = sock.recv(4096)
                        except socket.timeout:
                            # A test outage must not cause the probe itself to
                            # discard an otherwise recoverable TCP connection.
                            continue
                        if not chunk:
                            raise OSError("TCP connection closed")
                        buffer += chunk
                    line, buffer = buffer.split(b"\n", 1)
                    if int(line) != seq:
                        raise ValueError("TCP sequence mismatch")
                    sample["received"] = time.time()
                    progress["tcp"] = {"seq": seq, "received": sample["received"], "connection": connection}
                    pathlib.Path("/tmp/mesh-probe-tcp-ready").touch()
                    seq += 1
                    done.wait(.02)
            except (OSError, ValueError):
                seq += 1
                done.wait(.2)
            finally:
                sock.close()

    def publish_progress():
        directory = pathlib.Path("/tmp/mesh-artifacts")
        directory.mkdir(exist_ok=True)
        while not done.is_set():
            temporary = directory / "probe-progress.tmp"
            temporary.write_text(json.dumps(progress))
            temporary.replace(directory / "probe-progress.json")
            done.wait(1)

    threads = [threading.Thread(target=fn) for fn in (udp_server, tcp_server, udp_client, tcp_client, publish_progress)]
    for thread in threads:
        thread.start()
    done.wait()
    for thread in threads:
        thread.join()
    pathlib.Path("/tmp/mesh-artifacts").mkdir(exist_ok=True)
    pathlib.Path("/tmp/mesh-artifacts/probe.json").write_text(json.dumps(samples))


command = sys.argv[1]
if command == "setup":
    name, mode = sys.argv[2:]
    if name in ("nb", "nc"):
        port = "51821" if mode == "nat-traversal-port-preserving" else ("40001" if name == "nb" else "40002")
        # Unmatched WAN packets belong to the router, not a forwarded LAN
        # flow. Drop them before conntrack confirmation, as a NAT firewall
        # does, instead of creating closed-router-port flows that can clash
        # with the later outbound SNAT tuple.
        run("iptables", "-A", "INPUT", "-i", "wan", "-p", "udp", "-j", "DROP")
        run("iptables", "-P", "FORWARD", "DROP")
        if mode == "nat-traversal-blocked":
            run("iptables", "-A", "FORWARD", "-i", "lan", "-o", "wan", "-p", "udp", "--sport", "51821", "!", "-d", "192.0.2.1", "-j", "DROP")
        if mode == "nat-traversal-wg-blocked":
            for packet_type in range(1, 5):
                expression = f"0>>22&0x3C@8=0x{packet_type:02x}000000"
                run("iptables", "-A", "FORWARD", "-i", "lan", "-o", "wan", "-p", "udp", "--sport", "51821", "!", "-d", "192.0.2.1", "-m", "u32", "--u32", expression, "-j", "DROP")
        run("iptables", "-A", "FORWARD", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT")
        run("iptables", "-A", "FORWARD", "-i", "lan", "-o", "wan", "-p", "udp", "-j", "ACCEPT")
        if mode == "nat-traversal-symmetric":
            run("iptables", "-t", "nat", "-A", "POSTROUTING", "-o", "wan", "-p", "udp", "--sport", "51821", "!", "-d", "192.0.2.1", "-j", "SNAT", "--to-source", f"192.0.2.{12 if name == 'nb' else 13}:{41001 if name == 'nb' else 41002}")
        run("iptables", "-t", "nat", "-A", "POSTROUTING", "-o", "wan", "-p", "udp", "--sport", "51821", "-j", "SNAT", "--to-source", f"192.0.2.{12 if name == 'nb' else 13}:{port}")
        run("iptables", "-t", "nat", "-A", "POSTROUTING", "-o", "wan", "-j", "MASQUERADE")
        sys.exit(0)
    number = {"a": 1, "b": 2, "c": 3}[name]
    keyfile = pathlib.Path("/run/test-only-wg.key")
    keyfile.write_text(keys(name)[0])
    keyfile.chmod(0o600)
    for interface, port in [("wg0", "51820")]:
        run("ip", "link", "add", interface, "type", "wireguard")
        run("wg", "set", interface, "private-key", str(keyfile), "listen-port", port)
        run("ip", "link", "set", interface, "up")
    keyfile.unlink()
    run("ip", "address", "add", f"10.77.0.{number}/24", "dev", "wg0")
    if name == "a":
        for peer, n in (("b", 2), ("c", 3)):
            run("wg", "set", "wg0", "peer", keys(peer)[1], "allowed-ips", f"10.77.0.{n}/32")
        run("tc", "qdisc", "add", "dev", "wg0", "root", "netem", "delay", "40ms")
    else:
        if mode.startswith("nat-traversal") and not (mode == "nat-traversal-one-nat" and name == "c"):
            run("ip", "route", "replace", "192.0.2.0/24", "via", f"172.20.{number}.1", "dev", "lan")
        run("wg", "set", "wg0", "peer", keys("a")[1], "allowed-ips", "10.77.0.0/24", "endpoint", "192.0.2.1:51820", "persistent-keepalive", "1")
        peer, remote = ("c", 3) if name == "b" else ("b", 2)
        config = {"version": 2, "address": f"10.77.0.{number}", "peers": [{"public_key": keys(peer)[1], "ip": f"10.77.0.{remote}"}], "exclude": ["eth0", "wan"], "discovery_interval": "1s", "broadcast_after": "3s", "probe_interval": "200ms", "latency_window": "5s", "failure_timeout": "2s", "cooldown": "3s", "minimum_gain": "2ms", "minimum_gain_fraction": 0.2, "direct_listen_port": 51821, "route_metric": 50}
        if mode == "same-lan-auto":
            config.pop("direct_listen_port")
            foreign = "wgm-" + hashlib.sha256(("wg0\0" + keys(name)[1]).encode()).hexdigest()[:8]
            run("ip", "link", "add", foreign, "type", "dummy")
            run("ip", "link", "set", foreign, "alias", "foreign-test-interface", "up")
            pathlib.Path("/tmp/mesh-foreign-name").write_text(foreign)
            pathlib.Path("/tmp/mesh-foreign-snapshot").write_text(run("ip", "-j", "-d", "link", "show", "dev", foreign))
        if mode.startswith("nat-traversal"):
            config["nat_traversal"] = {"experimental": True, "stun_servers": ["192.0.2.1:3478"], "refresh_interval": "1s"}
            if mode == "nat-traversal-one-nat" and name == "c":
                config["exclude"] = ["eth0"]
            if mode == "nat-traversal-stun-failover":
                config["nat_traversal"]["stun_servers"].insert(0, "192.0.2.1:3479")
        if mode == "same-lan-stun-down":
            config["nat_traversal"] = {"experimental": True, "stun_servers": ["192.0.2.1:3479"], "refresh_interval": "1s"}
        directory = pathlib.Path("/etc/wireguard-mesh")
        directory.mkdir(exist_ok=True)
        (directory / "wg0.json").write_text(json.dumps(config))
elif command == "public":
    print(keys(sys.argv[2])[1])
elif command == "state":
    print(json.dumps(state(sys.argv[2])))
elif command == "owned":
    print(owned_interface())
elif command == "foreign-check":
    foreign = pathlib.Path("/tmp/mesh-foreign-name").read_text()
    assert run("ip", "-j", "-d", "link", "show", "dev", foreign) == pathlib.Path("/tmp/mesh-foreign-snapshot").read_text()
    if len(sys.argv) > 2:
        assert sys.argv[2].startswith(foreign + "-")
elif command == "symmetric-proof":
    name = sys.argv[2]
    client = "172.20.2.2" if name == "nb" else "172.20.3.3"
    peer = "192.0.2.13" if name == "nb" else "192.0.2.12"
    external = "192.0.2.12" if name == "nb" else "192.0.2.13"
    output = run("conntrack", "-L", "-p", "udp", "--orig-src", client, "--sport", "51821", "-o", "extended")
    found = {}
    for line in output.splitlines():
        fields = {key: re.findall(r"\b" + key + r"=([^ ]+)", line) for key in ("src", "dst", "sport", "dport", "packets")}
        if any(len(fields[key]) < 2 for key in ("src", "dst", "sport", "dport", "packets")):
            continue
        target = fields["dst"][0]
        if target not in ("192.0.2.1", peer) or fields["dst"][1] != external or fields["sport"][0] != "51821":
            continue
        kind = "stun" if target == "192.0.2.1" and fields["dport"][0] == "3478" else "peer" if target == peer else None
        if kind and int(fields["packets"][0]) > 0:
            found[kind] = {"destination": target, "destination_port": int(fields["dport"][0]), "mapped_port": int(fields["dport"][1]), "outbound_packets": int(fields["packets"][0]), "reply_packets": int(fields["packets"][1])}
    assert found.get("stun", {}).get("mapped_port") == (40001 if name == "nb" else 40002)
    assert found["stun"]["reply_packets"] > 0
    assert found.get("peer", {}).get("mapped_port") == (41001 if name == "nb" else 41002)
    directory = pathlib.Path("/tmp/mesh-artifacts")
    directory.mkdir(exist_ok=True)
    (directory / "symmetric-proof.json").write_text(json.dumps(found, indent=2))
elif command == "wg-blocked-counter":
    lines = run("iptables-save", "-c").splitlines()
    counts = [int(match.group(1)) for line in lines if "--u32" in line and "-j DROP" in line
              if (match := re.match(r"\[(\d+):\d+\]", line))]
    assert len(counts) == 4
    print(json.dumps(counts))
elif command == "ice-selected":
    invocation = run("systemctl", "show", "wireguard-meshd@wg0.service", "-p", "InvocationID", "--value")
    lines = run("journalctl", "-b", "_SYSTEMD_INVOCATION_ID=" + invocation, "--no-pager", "-o", "cat").splitlines()
    assert any("ICE direct candidate selected" in line for line in lines)
elif command == "active":
    invocation = run("systemctl", "show", "wireguard-meshd@wg0.service", "-p", "InvocationID", "--value")
    lines = run("journalctl", "-b", "_SYSTEMD_INVOCATION_ID=" + invocation, "--no-pager", "-o", "cat").splitlines()
    transitions = [line for line in lines if any(event in line for event in
                   ("direct path trial", "direct path active", "stable path restored", "previous direct path restored"))]
    if not transitions or "direct path active" not in transitions[-1]:
        raise SystemExit(1)
    if len(sys.argv) > 2:
        assert transitions[-1].endswith("endpoint=" + sys.argv[2]), "active path did not use LAN discovery"
elif command == "fallback-count":
    invocation = run("systemctl", "show", "wireguard-meshd@wg0.service", "-p", "InvocationID", "--value")
    lines = run("journalctl", "-b", "_SYSTEMD_INVOCATION_ID=" + invocation, "--no-pager", "-o", "cat").splitlines()
    print(sum("stable path restored" in line for line in lines))
elif command == "configure":
    path = pathlib.Path("/etc/wireguard-mesh/wg0.json")
    config = json.loads(path.read_text())
    if sys.argv[2] == "legacy":
        config["direct_interface"] = ""
        config.pop("route_metric", None)
        config.pop("direct_listen_port", None)
        config.pop("nat_traversal", None)
    else:
        config.pop("direct_interface", None)
        config["route_metric"] = 50
        config["direct_listen_port"] = 51821
    path.write_text(json.dumps(config))
elif command == "probe":
    probe(sys.argv[2], sys.argv[3])
elif command == "probe-progress-after":
    progress = json.loads(pathlib.Path("/tmp/mesh-artifacts/probe-progress.json").read_text())
    assert progress["tcp"]["connection"] == 1 and progress["tcp"]["received"] is not None
    assert progress["tcp"]["received"] > float(sys.argv[2])
elif command == "watch-route":
    remote, peer = sys.argv[2:]
    deadline = time.monotonic() + 120
    previous = 0
    result = {"route_seen": False, "handshake_before_route": False}
    while time.monotonic() < deadline:
        route = run("ip", "route", "get", remote)
        try:
            interface = owned_interface()
        except ValueError:
            time.sleep(.02)
            continue
        if f"dev {interface}" in route:
            result.update({"route_seen": True, "handshake_before_route": previous > 0, "time": time.time()})
            break
        previous = int(state(interface)["latest-handshakes"].get(peer, "0"))
        time.sleep(.02)
    pathlib.Path("/tmp/mesh-artifacts").mkdir(exist_ok=True)
    pathlib.Path("/tmp/mesh-artifacts/route-watch.json").write_text(json.dumps(result))
elif command == "watch-no-route":
    remote, peer = sys.argv[2:]
    done = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: done.set())
    deadline = time.monotonic() + 120
    result = {"host_route_seen": False, "handshake_seen": False}
    while not done.is_set() and time.monotonic() < deadline:
        if run("ip", "-4", "route", "show", "exact", remote + "/32"):
            result["host_route_seen"] = True
        try:
            interface = owned_interface()
        except ValueError:
            interface = None
        if interface and int(state(interface)["latest-handshakes"].get(peer, "0")) > 0:
            result["handshake_seen"] = True
        pathlib.Path("/tmp/mesh-no-route-watch-ready").touch()
        done.wait(.05)
    result["stopped"] = done.is_set()
    pathlib.Path("/tmp/mesh-artifacts").mkdir(exist_ok=True)
    pathlib.Path("/tmp/mesh-artifacts/no-route-watch.json").write_text(json.dumps(result))
elif command == "capture":
    directory = pathlib.Path("/tmp/mesh-artifacts")
    directory.mkdir(exist_ok=True)
    for label, args in {"routes": ["ip", "route", "show", "table", "all"], "firewall": ["iptables-save", "-c"], "kernel": ["uname", "-a"], "tc-version": ["tc", "-V"]}.items():
        result = subprocess.run(args, text=True, capture_output=True)
        (directory / f"{sys.argv[2]}-{label}.txt").write_text(result.stdout + result.stderr)
    try:
        interfaces = ("wg0", owned_interface())
    except ValueError:
        interfaces = ("wg0",)
    for interface in interfaces:
        if subprocess.run(["ip", "link", "show", interface], capture_output=True).returncode == 0:
            (directory / f"{sys.argv[2]}-{interface}.json").write_text(json.dumps(state(interface), indent=2))
else:
    raise SystemExit("Unknown test command")
