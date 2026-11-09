package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pion/ice/v4"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type iceLoopTransport struct {
	conn    *net.UDPConn
	once    sync.Once
	mu      sync.Mutex
	sources []netip.AddrPort
}

func (t *iceLoopTransport) Send(b []byte, dst netip.AddrPort) error {
	_, err := t.conn.WriteToUDPAddrPort(b, dst)
	return err
}
func (t *iceLoopTransport) Incoming() <-chan packet { return nil }
func (t *iceLoopTransport) Close() error {
	var err error
	t.once.Do(func() { err = t.conn.Close() })
	return err
}
func (t *iceLoopTransport) pump(x *iceTraversal) {
	go func() {
		buf := make([]byte, 2048)
		for {
			n, src, err := t.conn.ReadFromUDPAddrPort(buf)
			if err != nil {
				return
			}
			t.mu.Lock()
			t.sources = append(t.sources, src)
			t.mu.Unlock()
			x.Input(packet{Data: buf[:n], Source: src})
		}
	}()
}

func iceTestPair(t *testing.T) ([2]*iceTraversal, [2]*iceLoopTransport, [2]wgtypes.Key) {
	t.Helper()
	var nodes [2]*iceTraversal
	var transports [2]*iceLoopTransport
	keys := [2]wgtypes.Key{{1}, {2}}
	for i := range nodes {
		conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		transports[i] = &iceLoopTransport{conn: conn}
		port := uint16(conn.LocalAddr().(*net.UDPAddr).Port)
		nodes[i], err = newICETraversal(transports[i], port, nil, []linkAddr{{Name: "lo", Prefix: netip.MustParsePrefix("127.0.0.1/8")}})
		if err != nil {
			t.Fatal(err)
		}
		transports[i].pump(nodes[i])
		if err := nodes[i].EnsurePeer(keys[1-i], i == 0); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		for i := range nodes {
			_ = nodes[i].Close()
			_ = nodes[i].Close()
			_ = transports[i].Close()
		}
	})
	return nodes, transports, keys
}

func iceExchange(nodes [2]*iceTraversal, keys [2]wgtypes.Key, badPassword bool) error {
	for i := range nodes {
		for _, sig := range nodes[i].Signals(keys[1-i]) {
			if badPassword && i == 0 {
				sig.Password = "wrongwrongwrongwrongwrongwrong"
			}
			if err := nodes[1-i].Remote(keys[i], sig); err != nil {
				return err
			}
		}
	}
	return nil
}

func TestICETraversalConnectivity(t *testing.T) {
	nodes, transports, keys := iceTestPair(t)
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		if err := iceExchange(nodes, keys, false); err != nil {
			t.Fatal(err)
		}
		a, b := nodes[0].Selected(keys[1]), nodes[1].Selected(keys[0])
		if a.Endpoint.IsValid() && b.Endpoint.IsValid() {
			for i, update := range []iceUpdate{a, b} {
				want := transports[1-i].conn.LocalAddr().(*net.UDPAddr).AddrPort()
				if update.Endpoint != want {
					t.Fatal("selected wrong transport endpoint")
				}
				transports[i].mu.Lock()
				for _, source := range transports[i].sources {
					if source != want {
						transports[i].mu.Unlock()
						t.Fatal("packet used a different source port")
					}
				}
				transports[i].mu.Unlock()
			}
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("ICE did not select a pair")
}

func TestICETraversalRejectsWrongPassword(t *testing.T) {
	nodes, _, keys := iceTestPair(t)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if err := iceExchange(nodes, keys, true); err != nil {
			t.Fatal(err)
		}
		// Node 1 has the wrong password. Node 0 can still authenticate node 1:
		// node 1 knows node 0's actual password and can send valid checks.
		u := nodes[1].Selected(keys[0])
		if u.Endpoint.IsValid() || u.State == ice.ConnectionStateConnected {
			t.Fatal("node with wrong credentials connected")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestICETraversalSignalValidationAndRestart(t *testing.T) {
	nodes, _, keys := iceTestPair(t)
	x := nodes[0]
	s := nodes[1].Signals(keys[0])[0]
	bad := s
	bad.Candidate = "not a candidate"
	if x.Remote(keys[1], bad) == nil {
		t.Fatal("accepted malformed candidate")
	}
	if err := x.Remote(keys[1], s); err != nil {
		t.Fatal(err)
	}
	local := x.Signals(keys[1])[0]
	next := s
	next.Generation = "newgeneration1"
	if err := x.Remote(keys[1], next); err != nil {
		t.Fatal(err)
	}
	if x.Remote(keys[1], s) == nil {
		t.Fatal("accepted retired generation")
	}
	after := x.Signals(keys[1])[0]
	if local != after {
		t.Fatal("remote restart changed local credentials")
	}
	if err := x.Restart(keys[1]); err != nil {
		t.Fatal(err)
	}
	if local != x.Signals(keys[1])[0] {
		t.Fatal("restart changed local credentials")
	}
}

type iceSilentTransport struct{ sent chan struct{} }

func (t *iceSilentTransport) Send([]byte, netip.AddrPort) error {
	select {
	case t.sent <- struct{}{}:
	default:
	}
	return nil
}
func (*iceSilentTransport) Incoming() <-chan packet { return nil }
func (*iceSilentTransport) Close() error            { return nil }

func TestICETraversalDeadSTUNCancellation(t *testing.T) {
	raw := &iceSilentTransport{sent: make(chan struct{}, 128)}
	x, err := newICETraversal(raw, 51900, []netip.AddrPort{netip.MustParseAddrPort("192.0.2.10:3478")}, []linkAddr{{Name: "lo", Prefix: netip.MustParsePrefix("127.0.0.1/8")}})
	if err != nil {
		t.Fatal(err)
	}
	defer x.Close()
	key := wgtypes.Key{1}
	if err := x.EnsurePeer(key, true); err != nil {
		t.Fatal(err)
	}
	select {
	case <-raw.sent:
	case <-time.After(time.Second):
		t.Fatal("STUN request did not start")
	}
	// The wrapper must retain Pion's cancellable extension.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	_, _ = x.mux.GetXORMappedAddrContext(ctx, net.UDPAddrFromAddrPort(netip.MustParseAddrPort("192.0.2.11:3478")), 5*time.Second)
	if time.Since(start) > time.Second {
		t.Fatal("canceled STUN transaction took too long")
	}
	done := make(chan error, 1)
	go func() { done <- x.Restart(key) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("restart waited for dead STUN server")
	}
	s := iceSignal{Generation: "generation1", Ufrag: "remoteufrag", Password: "remotepasswordremotepassword", Candidate: "1 1 udp 2130706431 192.0.2.22 51901 typ host"}
	if err := x.Remote(key, s); err != nil {
		t.Fatal(err)
	}
	go func() { done <- x.Close() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("close waited for unanswered ICE checks")
	}
	if x.Selected(key).Endpoint.IsValid() {
		t.Fatal("closed engine retained endpoint")
	}
}

func TestICETraversalInvalidCandidatesAndBounds(t *testing.T) {
	nodes, _, keys := iceTestPair(t)
	x := nodes[0]
	s := nodes[1].Signals(keys[0])[0]
	for _, candidate := range []string{
		"1 1 tcp 2130706431 192.0.2.3 1234 typ host tcptype passive",
		"1 2 udp 2130706431 192.0.2.3 1234 typ host",
		"1 1 udp 1 192.0.2.3 1234 typ relay",
		"1 1 udp 1 169.254.1.1 1234 typ host",
		"1 1 udp 1 255.255.255.255 1234 typ host",
	} {
		bad := s
		bad.Candidate = candidate
		if x.Remote(keys[1], bad) == nil {
			t.Fatal("invalid candidate accepted")
		}
	}
	production := iceTraversal{}
	if production.validRemoteIP(netip.MustParseAddr("127.0.0.1")) {
		t.Fatal("loopback accepted for production links")
	}
	if x.Remote(wgtypes.Key{99}, s) == nil {
		t.Fatal("unknown peer accepted")
	}
	if err := x.Remote(keys[1], s); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < iceLimit; i++ {
		next := s
		next.Generation = fmt.Sprintf("generation%03d", i)
		if err := x.Remote(keys[1], next); err != nil {
			t.Fatal("premature retired-generation limit")
		}
	}
	next := s
	next.Generation = "generation999"
	if x.Remote(keys[1], next) == nil {
		t.Fatal("retired generation limit not enforced")
	}
}

func TestICEExcludedRemoteCannotBeSelected(t *testing.T) {
	nodes, _, keys := iceTestPair(t)
	x, key := nodes[0], keys[1]
	ip := netip.MustParseAddr("127.0.0.1")
	before := x.Signals(key)[0]
	changed, err := x.SetExcludedIPs(key, []netip.Addr{ip})
	if err != nil || !changed {
		t.Fatalf("set exclusion: changed %v, error %v", changed, err)
	}
	after := x.Signals(key)[0]
	if before.Generation != after.Generation || before.Ufrag != after.Ufrag {
		t.Fatal("policy change replaced local generation")
	}
	if x.allowedRemoteIP(key, ip) || !x.allowedRemoteIP(key, netip.MustParseAddr("192.0.2.13")) {
		t.Fatal("remote IP filter did not apply per-peer policy")
	}
	s := nodes[1].Signals(keys[0])[0]
	s.Candidate = "1 1 udp 2130706431 127.0.0.1 51901 typ host"
	if x.Remote(key, s) == nil {
		t.Fatal("excluded signaled candidate accepted")
	}
	x.mu.Lock()
	x.peers[key].selected = netip.MustParseAddrPort("127.0.0.1:51901")
	x.mu.Unlock()
	if x.Selected(key).Endpoint.IsValid() {
		t.Fatal("snapshot returned excluded endpoint")
	}
}

func TestICEExclusionReplacementReconnects(t *testing.T) {
	nodes, transports, keys := iceTestPair(t)
	connect := func() {
		t.Helper()
		deadline := time.Now().Add(8 * time.Second)
		for time.Now().Before(deadline) {
			if err := iceExchange(nodes, keys, false); err != nil {
				t.Fatal(err)
			}
			if nodes[0].Selected(keys[1]).Endpoint.IsValid() && nodes[1].Selected(keys[0]).Endpoint.IsValid() {
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
		t.Fatal("replacement agents did not reconnect")
	}
	connect()
	local := nodes[0].Signals(keys[1])[0]
	// Change one side only. The other agent must accept checks and candidates
	// after replacement without a reciprocal generation/restart loop.
	if _, err := nodes[0].SetExcludedIPs(keys[1], []netip.Addr{netip.MustParseAddr("192.0.2.99")}); err != nil {
		t.Fatal(err)
	}
	connect()
	if _, err := nodes[0].SetExcludedIPs(keys[1], nil); err != nil {
		t.Fatal(err)
	}
	connect()
	if nodes[0].Signals(keys[1])[0] != local {
		t.Fatal("policy replacement changed local credentials")
	}
	for i, node := range nodes {
		want := transports[1-i].conn.LocalAddr().(*net.UDPAddr).AddrPort()
		if node.Selected(keys[1-i]).Endpoint != want {
			t.Fatal("replacement selected an old or incorrect endpoint")
		}
	}
}

func TestICESignalFitsNoiseBody(t *testing.T) {
	nodes, _, keys := iceTestPair(t)
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) && len(nodes[0].Signals(keys[1])) < 2 {
		time.Sleep(10 * time.Millisecond)
	}
	signals := nodes[0].Signals(keys[1])
	if len(signals) < 2 {
		t.Fatal("no gathered candidates")
	}
	maxSignal := signals[0]
	maxSignal.Candidate = strings.Repeat("x", iceCandidateLimit)
	signals = append(signals, maxSignal)
	for _, s := range signals {
		prototype := struct {
			Op    string     `json:"op"`
			Token string     `json:"token"`
			Port  uint16     `json:"port"`
			ICE   *iceSignal `json:"ice,omitempty"`
		}{"signal", strings.Repeat("x", 64), 65535, &s}
		b, err := json.Marshal(prototype)
		if err != nil || len(b) > secureInnerMaxSize-secureHeaderN-16 {
			t.Fatal("ICE signal exceeds Noise body")
		}
	}
}

func TestICETraversalFailedRestartDoesNotPanic(t *testing.T) {
	nodes, _, keys := iceTestPair(t)
	x := nodes[0]
	x.mu.Lock()
	x.peers[keys[1]].local.Password = "x"
	x.mu.Unlock()
	if x.Restart(keys[1]) == nil {
		t.Fatal("restart unexpectedly succeeded")
	}
	s := nodes[1].Signals(keys[0])[0]
	if x.Remote(keys[1], s) == nil {
		t.Fatal("signal accepted without an agent")
	}
	if x.Selected(keys[1]).Endpoint.IsValid() {
		t.Fatal("failed restart retained endpoint")
	}
}

func TestICETraversalPeerAndCandidateLimits(t *testing.T) {
	nodes, _, keys := iceTestPair(t)
	x := nodes[0]
	s := nodes[1].Signals(keys[0])[0]
	for i := 0; i < iceLimit; i++ {
		s.Candidate = fmt.Sprintf("1 1 udp 2130706431 192.0.2.1 %d typ host", 30000+i)
		if err := x.Remote(keys[1], s); err != nil {
			t.Fatal("candidate rejected before limit")
		}
	}
	s.Candidate = "1 1 udp 2130706431 192.0.2.1 31000 typ host"
	if x.Remote(keys[1], s) == nil {
		t.Fatal("candidate limit not enforced")
	}
	x.mu.Lock()
	for i := 0; len(x.peers) < 128; i++ {
		k := wgtypes.Key{byte(i), byte(i >> 8), 255}
		x.peers[k] = &icePeer{}
	}
	x.mu.Unlock()
	if x.EnsurePeer(wgtypes.Key{254, 254}, true) == nil {
		t.Fatal("peer limit not enforced")
	}
}
