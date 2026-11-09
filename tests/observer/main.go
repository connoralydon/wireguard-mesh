//go:build linux

// mesh-kernel-observer is used only in isolated test VMs.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

var errObservation = errors.New("observer operation failed")

type snapshot struct {
	present, handshake bool
	key                wgtypes.Key
}
type routeResult struct {
	RouteSeen            bool    `json:"route_seen"`
	HandshakeBeforeRoute bool    `json:"handshake_before_route"`
	Time                 float64 `json:"time"`
}
type rekeyResult struct {
	PeerAbsent              bool `json:"peer_absent"`
	RelaySeen               bool `json:"relay_seen"`
	NewHandshakeBeforeRoute bool `json:"new_handshake_before_route"`
	NewKeyInstalled         bool `json:"new_key_installed"`
}
type observerState struct {
	route    routeResult
	rekey    rekeyResult
	proof    bool
	proofKey wgtypes.Key
}

// Each step receives a WireGuard snapshot taken before the route lookup.
func (s *observerState) step(mode string, p snapshot, routeKnown, direct bool, before, after, old wgtypes.Key, keysOK bool) bool {
	if !p.present || !p.handshake {
		s.proof = false
	}
	if mode == "route" {
		if routeKnown && direct {
			s.route.RouteSeen = true
			s.route.HandshakeBeforeRoute = s.proof && p.present && p.handshake
			s.route.Time = float64(time.Now().UnixNano()) / 1e9
			return true
		}
		if routeKnown && !direct && p.present && p.handshake {
			s.proof = true
		}
		return false
	}
	if !p.present {
		s.rekey.PeerAbsent = true
	}
	if s.rekey.PeerAbsent && routeKnown && !direct {
		s.rekey.RelaySeen = true
	}
	same := keysOK && before == after && before != old && p.present && p.key == before
	if s.proof && (!same || s.proofKey != before) {
		s.proof = false
	}
	if routeKnown && direct && same {
		s.rekey.NewKeyInstalled = true
		s.rekey.NewHandshakeBeforeRoute = s.proof && p.handshake && s.rekey.PeerAbsent && s.rekey.RelaySeen
		return true
	}
	if routeKnown && !direct && same && p.handshake && s.rekey.PeerAbsent && s.rekey.RelaySeen {
		s.proof = true
		s.proofKey = before
	}
	return false
}

func readKey(path string) (wgtypes.Key, error) {
	var zero wgtypes.Key
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return zero, errObservation
	}
	f := os.NewFile(uintptr(fd), "key")
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > 128 {
		return zero, errObservation
	}
	b, err := io.ReadAll(io.LimitReader(f, 129))
	if err != nil || len(b) > 128 {
		return zero, errObservation
	}
	k, err := wgtypes.ParseKey(strings.TrimSpace(string(b)))
	if err != nil || k == zero {
		return zero, errObservation
	}
	return k, nil
}

type kernel struct {
	nl     *netlink.Handle
	wg     *wgctrl.Client
	name   string
	index  int
	stable int
	peer   wgtypes.Key
	remote net.IP
}

func (k *kernel) snapshot() (snapshot, error) {
	if k.name == "" {
		links, err := k.nl.LinkList()
		if err != nil {
			return snapshot{}, errObservation
		}
		var found netlink.Link
		for _, l := range links {
			if l.Type() == "wireguard" && strings.HasPrefix(l.Attrs().Alias, "wireguard-mesh:") {
				if found != nil {
					return snapshot{}, errObservation
				}
				found = l
			}
		}
		if found == nil {
			return snapshot{}, nil
		}
		k.name, k.index = found.Attrs().Name, found.Attrs().Index
	}
	d, err := k.wg.Device(k.name)
	if errors.Is(err, os.ErrNotExist) || errors.Is(err, unix.ENODEV) {
		k.name, k.index = "", 0
		return snapshot{}, nil
	}
	if err != nil {
		return snapshot{}, errObservation
	}
	for _, p := range d.Peers {
		if p.PublicKey == k.peer {
			return snapshot{true, !p.LastHandshakeTime.IsZero(), p.PresharedKey}, nil
		}
	}
	return snapshot{}, nil
}
func (k *kernel) route() (bool, bool, error) {
	routes, err := k.nl.RouteGet(k.remote)
	if err != nil {
		return false, false, errObservation
	}
	if len(routes) == 0 {
		return false, false, nil
	}
	known, direct := k.routeKind(routes[0].LinkIndex)
	return known, direct, nil
}

func (k *kernel) routeKind(index int) (bool, bool) {
	direct := k.index != 0 && index == k.index
	return direct || k.stable != 0 && index == k.stable, direct
}

func run() error {
	flag.CommandLine.SetOutput(io.Discard)
	mode := flag.String("mode", "", "observation mode")
	remote := flag.String("remote", "", "remote IP")
	peer := flag.String("peer", "", "peer public key")
	timeout := flag.Duration("timeout", 120*time.Second, "observation timeout")
	output := flag.String("output", "", "result file")
	ready := flag.String("ready", "", "readiness file")
	oldFile := flag.String("old-key-file", "", "old key file")
	keyFile := flag.String("key-file", "", "current key file")
	flag.Parse()
	ip := net.ParseIP(*remote)
	pub, err := wgtypes.ParseKey(*peer)
	if err != nil || pub == (wgtypes.Key{}) || ip == nil || (*mode != "route" && *mode != "rekey") || *timeout <= 0 || *timeout > 240*time.Second || *output == "" || *ready == "" || (*mode == "rekey" && (*oldFile == "" || *keyFile == "")) {
		return errObservation
	}
	var old wgtypes.Key
	if *mode == "rekey" {
		old, err = readKey(*oldFile)
		if err != nil {
			return errObservation
		}
	}
	nl, err := netlink.NewHandle(unix.NETLINK_ROUTE)
	if err != nil {
		return errObservation
	}
	defer nl.Close()
	wg, err := wgctrl.New()
	if err != nil {
		return errObservation
	}
	defer wg.Close()
	stable, err := nl.LinkByName("wg0")
	if err != nil {
		return errObservation
	}
	if err := os.MkdirAll(filepath.Dir(*output), 0755); err != nil {
		return errObservation
	}
	if err := os.WriteFile(*ready, []byte("ready\n"), 0600); err != nil {
		return errObservation
	}
	k := kernel{nl: nl, wg: wg, stable: stable.Attrs().Index, peer: pub, remote: ip}
	var s observerState
	deadline := time.Now().Add(*timeout)
	for time.Now().Before(deadline) {
		var before, after wgtypes.Key
		keysOK := false
		if *mode == "rekey" {
			before, err = readKey(*keyFile)
			if err != nil || before == old {
				s.proof = false
				time.Sleep(20 * time.Millisecond)
				continue
			}
		}
		p, e := k.snapshot()
		if e != nil {
			return errObservation
		}
		known, direct, e := k.route()
		if e != nil {
			return errObservation
		}
		if *mode == "rekey" {
			after, err = readKey(*keyFile)
			keysOK = err == nil
		}
		if s.step(*mode, p, known, direct, before, after, old, keysOK) {
			break
		}
		time.Sleep(time.Millisecond)
	}
	var result any = s.route
	if *mode == "rekey" {
		result = s.rekey
	}
	data, err := json.Marshal(result)
	if err != nil {
		return errObservation
	}
	if err := os.WriteFile(*output, data, 0600); err != nil {
		return errObservation
	}
	return nil
}
func main() {
	if run() != nil {
		_, _ = os.Stderr.WriteString("observer failed\n")
		os.Exit(1)
	}
}
