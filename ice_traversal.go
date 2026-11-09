package main

import (
	"context"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/pion/ice/v4"
	"github.com/pion/logging"
	"github.com/pion/stun/v4"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type iceSignal struct {
	Generation string `json:"g"`
	Ufrag      string `json:"u"`
	Password   string `json:"p"`
	Candidate  string `json:"c,omitempty"`
}

type iceUpdate struct {
	Peer       wgtypes.Key
	Generation string
	Revision   uint64 // Changes on every local agent replacement.
	Endpoint   netip.AddrPort
	State      ice.ConnectionState
	Err        error
}

const iceLimit = 16

// Leaves room for the signal envelope, credentials and a 64-byte token in
// the encrypted Noise body. Longer local candidates cannot be signaled.
const iceCandidateLimit = 140

// Never evict a live retired generation. At the limit, new generations wait
// for expiry rather than allowing a replay to replace the active agent.
const iceRetireTime = 15 * time.Minute

var errICEInvalid = errors.New("invalid ICE signal")
var errICEClosed = errors.New("ICE traversal closed")

// Unlike Pion's wildcard mux, this exposes only the event loop's link snapshot.
type iceFilteredMux struct {
	*ice.UniversalUDPMuxDefault
	addresses []net.Addr
}

func (m *iceFilteredMux) GetXORMappedAddrContext(ctx context.Context, addr net.Addr, deadline time.Duration) (*stun.XORMappedAddress, error) {
	return m.UniversalUDPMuxDefault.GetXORMappedAddrContext(ctx, addr, deadline)
}

func (m *iceFilteredMux) GetListenAddresses() []net.Addr {
	return append([]net.Addr(nil), m.addresses...)
}

type icePeer struct {
	agent            *ice.Agent
	cancel           context.CancelFunc
	controlling      bool
	local            iceSignal
	remote           iceSignal
	retired          map[string]time.Time
	localCandidates  []string
	remoteCandidates map[string]bool
	started          bool
	epoch            uint64
	selected         netip.AddrPort
	paired           netip.AddrPort
	connected        bool
	state            ice.ConnectionState
}

type iceTraversal struct {
	mu         sync.Mutex
	conn       *icePacketConn
	mux        *iceFilteredMux
	urls       []*stun.URI
	peers      map[wgtypes.Key]*icePeer
	events     chan iceUpdate
	closed     bool
	closeDone  chan struct{}
	logger     logging.LoggerFactory
	interfaces map[string]bool
	ips        map[netip.Addr]bool
	broadcasts map[netip.Addr]bool
	loopback   bool
	workers    sync.WaitGroup
}

func newICETraversal(t wireGuardUDP, port uint16, servers []netip.AddrPort, links []linkAddr) (*iceTraversal, error) {
	if t == nil || port == 0 || len(servers) > iceLimit {
		return nil, errICEInvalid
	}
	x := &iceTraversal{conn: newICEPacketConn(t, port), peers: make(map[wgtypes.Key]*icePeer), events: make(chan iceUpdate, 256), closeDone: make(chan struct{}), interfaces: make(map[string]bool), ips: make(map[netip.Addr]bool), broadcasts: make(map[netip.Addr]bool)}
	factory := logging.NewDefaultLoggerFactory()
	factory.Writer = io.Discard
	x.logger = factory
	for _, server := range servers {
		if !server.IsValid() || !server.Addr().Is4() || server.Port() == 0 {
			return nil, errICEInvalid
		}
		u, err := stun.ParseURI("stun:" + server.String())
		if err != nil {
			return nil, errICEInvalid
		}
		x.urls = append(x.urls, u)
	}
	var addresses []net.Addr
	for _, link := range links {
		a := link.Prefix.Addr().Unmap()
		if link.Name == "" || !a.Is4() || a.IsUnspecified() || a.IsMulticast() || x.ips[a] {
			continue
		}
		x.ips[a], x.interfaces[link.Name] = true, true
		if link.Broadcast.IsValid() {
			x.broadcasts[link.Broadcast.Unmap()] = true
		}
		if a.IsLoopback() {
			x.loopback = true
		}
		addresses = append(addresses, net.UDPAddrFromAddrPort(netip.AddrPortFrom(a, port)))
	}
	if len(addresses) == 0 || len(addresses) > iceLimit {
		return nil, errICEInvalid
	}
	base := ice.NewUniversalUDPMuxDefault(ice.UniversalUDPMuxParams{UDPConn: x.conn, Logger: factory.NewLogger("ice"), XORMappedAddrCacheTTL: time.Second})
	x.mux = &iceFilteredMux{UniversalUDPMuxDefault: base, addresses: addresses}
	return x, nil
}

func (x *iceTraversal) EnsurePeer(key wgtypes.Key, controlling bool) error {
	x.mu.Lock()
	if x.closed {
		x.mu.Unlock()
		return errICEClosed
	}
	if p := x.peers[key]; p != nil {
		x.mu.Unlock()
		if p.controlling != controlling {
			return errICEInvalid
		}
		return nil
	}
	if len(x.peers) >= 128 {
		x.mu.Unlock()
		return errors.New("ICE peer limit")
	}
	p := &icePeer{controlling: controlling, local: iceSignal{Generation: rand.Text(), Ufrag: rand.Text(), Password: rand.Text()}, retired: make(map[string]time.Time), remoteCandidates: make(map[string]bool)}
	x.peers[key] = p
	x.mu.Unlock()
	if err := x.createAgent(key, p); err != nil {
		x.mu.Lock()
		delete(x.peers, key)
		x.mu.Unlock()
		return err
	}
	return nil
}

func (x *iceTraversal) createAgent(key wgtypes.Key, p *icePeer) error {
	keep, check, disconnected, failed := time.Second, 200*time.Millisecond, 5*time.Second, 5*time.Second
	config := &ice.AgentConfig{Urls: x.urls, LocalUfrag: p.local.Ufrag, LocalPwd: p.local.Password, MulticastDNSMode: ice.MulticastDNSModeDisabled, NetworkTypes: []ice.NetworkType{ice.NetworkTypeUDP4}, CandidateTypes: []ice.CandidateType{ice.CandidateTypeHost, ice.CandidateTypeServerReflexive}, UDPMux: x.mux, UDPMuxSrflx: x.mux, KeepaliveInterval: &keep, CheckInterval: &check, DisconnectedTimeout: &disconnected, FailedTimeout: &failed, IncludeLoopback: true, LoggerFactory: x.logger,
		InterfaceFilter: func(name string) bool { return x.interfaces[name] }, IPFilter: func(ip net.IP) bool { a, ok := netip.AddrFromSlice(ip); return ok && x.ips[a.Unmap()] }, RemoteIPFilter: func(ip net.IP) bool { a, ok := netip.AddrFromSlice(ip); return ok && x.validRemoteIP(a.Unmap()) }}
	a, err := ice.NewAgent(config)
	if err != nil {
		return errors.New("ICE agent creation failed")
	}
	x.mu.Lock()
	if x.closed {
		x.mu.Unlock()
		_ = a.Close()
		return errICEClosed
	}
	p.epoch++
	epoch := p.epoch
	_, cancel := context.WithCancel(context.Background())
	p.agent, p.cancel = a, cancel
	p.localCandidates, p.remoteCandidates, p.started = nil, make(map[string]bool), false
	p.selected, p.paired, p.connected, p.state = netip.AddrPort{}, netip.AddrPort{}, false, ice.ConnectionStateNew
	x.mu.Unlock()
	_ = a.OnCandidate(func(c ice.Candidate) {
		if c == nil {
			return
		}
		line := c.Marshal()
		if len(line) > iceCandidateLimit {
			return
		}
		x.mu.Lock()
		defer x.mu.Unlock()
		if !x.closed && p.epoch == epoch && len(p.localCandidates) < iceLimit {
			p.localCandidates = append(p.localCandidates, line)
		}
	})
	_ = a.OnConnectionStateChange(func(state ice.ConnectionState) {
		x.mu.Lock()
		defer x.mu.Unlock()
		if x.closed || p.epoch != epoch {
			return
		}
		p.state = state
		if state == ice.ConnectionStateFailed || state == ice.ConnectionStateClosed {
			p.selected = netip.AddrPort{}
		}
		x.emit(iceUpdate{Peer: key, Generation: p.local.Generation, Revision: epoch, State: state})
	})
	_ = a.OnSelectedCandidatePairChange(func(_, remote ice.Candidate) {
		addr, err := netip.ParseAddr(remote.Address())
		if err != nil || !x.validRemoteIP(addr) || remote.Port() <= 0 || remote.Port() > 65535 {
			return
		}
		x.mu.Lock()
		defer x.mu.Unlock()
		if x.closed || p.epoch != epoch {
			return
		}
		p.paired = netip.AddrPortFrom(addr, uint16(remote.Port()))
		if p.connected {
			p.selected = p.paired
			x.emit(iceUpdate{Peer: key, Generation: p.local.Generation, Revision: epoch, Endpoint: p.selected, State: p.state})
		}
	})
	if err := a.GatherCandidates(); err != nil {
		cancel()
		_ = a.Close()
		x.mu.Lock()
		if p.agent == a {
			p.agent = nil
			p.selected = netip.AddrPort{}
			p.state = ice.ConnectionStateFailed
		}
		x.mu.Unlock()
		return errors.New("ICE gathering failed")
	}
	return nil
}

func (x *iceTraversal) emit(u iceUpdate) {
	select {
	case x.events <- u:
	default:
	}
}
func (x *iceTraversal) Events() <-chan iceUpdate { return x.events }

// Selected is a snapshot for recovery if the bounded event queue is full.
func (x *iceTraversal) Selected(key wgtypes.Key) iceUpdate {
	x.mu.Lock()
	defer x.mu.Unlock()
	if p := x.peers[key]; p != nil && !x.closed && p.agent != nil {
		return iceUpdate{Peer: key, Generation: p.local.Generation, Revision: p.epoch, Endpoint: p.selected, State: p.state}
	}
	return iceUpdate{Peer: key}
}
func (x *iceTraversal) Input(p packet) bool { return x.conn.deliver(p) }

func (x *iceTraversal) Signals(key wgtypes.Key) []iceSignal {
	x.mu.Lock()
	defer x.mu.Unlock()
	p := x.peers[key]
	if p == nil || x.closed {
		return nil
	}
	out := []iceSignal{p.local}
	for _, candidate := range p.localCandidates {
		s := p.local
		s.Candidate = candidate
		out = append(out, s)
	}
	return out
}

func (x *iceTraversal) validRemoteIP(a netip.Addr) bool {
	return a.Is4() && (a.IsGlobalUnicast() || a.IsLoopback() && x.loopback) && (!a.IsLoopback() || x.loopback) && !a.IsLinkLocalUnicast() && a != netip.MustParseAddr("255.255.255.255") && !x.broadcasts[a]
}

func (x *iceTraversal) iceCandidate(line string) (ice.Candidate, error) {
	if len(line) == 0 || len(line) > iceCandidateLimit {
		return nil, errICEInvalid
	}
	c, err := ice.UnmarshalCandidate(line)
	if err != nil {
		return nil, errICEInvalid
	}
	a, err := netip.ParseAddr(c.Address())
	if err != nil || !x.validRemoteIP(a) || c.Port() <= 0 || c.Port() > 65535 || c.Component() != 1 || c.NetworkType() != ice.NetworkTypeUDP4 || (c.Type() != ice.CandidateTypeHost && c.Type() != ice.CandidateTypeServerReflexive) {
		return nil, errICEInvalid
	}
	return c, nil
}

func validICEText(s string, minLen, maxLen int) bool {
	if len(s) < minLen || len(s) > maxLen {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '+' || c == '/') {
			return false
		}
	}
	return true
}

func (x *iceTraversal) Remote(key wgtypes.Key, s iceSignal) error {
	if !validICEText(s.Generation, 8, 64) || !validICEText(s.Ufrag, 4, 64) || !validICEText(s.Password, 22, 64) {
		return errICEInvalid
	}
	var candidate ice.Candidate
	if s.Candidate != "" {
		var err error
		candidate, err = x.iceCandidate(s.Candidate)
		if err != nil {
			return err
		}
	}
	x.mu.Lock()
	p := x.peers[key]
	if x.closed {
		x.mu.Unlock()
		return errICEClosed
	}
	if p == nil {
		x.mu.Unlock()
		return errICEInvalid
	}
	if p.agent == nil {
		x.mu.Unlock()
		return errors.New("ICE agent unavailable")
	}
	now := time.Now()
	for gen, until := range p.retired {
		if !now.Before(until) {
			delete(p.retired, gen)
		}
	}
	if _, old := p.retired[s.Generation]; old {
		x.mu.Unlock()
		return errICEInvalid
	}
	if p.remote.Generation != "" && p.remote.Generation != s.Generation {
		if len(p.retired) >= iceLimit {
			x.mu.Unlock()
			return errICEInvalid
		}
		p.retired[p.remote.Generation] = now.Add(iceRetireTime)
		x.mu.Unlock()
		if err := x.restart(key, p); err != nil {
			return err
		}
		x.mu.Lock()
	}
	if p.remote.Generation == s.Generation && (p.remote.Ufrag != s.Ufrag || p.remote.Password != s.Password) {
		x.mu.Unlock()
		return errICEInvalid
	}
	p.remote = iceSignal{Generation: s.Generation, Ufrag: s.Ufrag, Password: s.Password}
	if candidate != nil && !p.remoteCandidates[s.Candidate] && len(p.remoteCandidates) >= iceLimit {
		x.mu.Unlock()
		return errICEInvalid
	}
	a := p.agent
	add := candidate != nil && !p.remoteCandidates[s.Candidate]
	if add {
		p.remoteCandidates[s.Candidate] = true
	}
	start := !p.started
	if start {
		p.started = true
		x.workers.Add(1)
	}
	ctx := context.Background()
	// The cancellation context is installed with the agent; obtain a worker
	// context through a separate cancel that restart and Close can stop.
	if start {
		var cancel context.CancelFunc
		ctx, cancel = context.WithCancel(context.Background())
		previous := p.cancel
		p.cancel = func() { cancel(); previous() }
	}
	controlling, epoch := p.controlling, p.epoch
	x.mu.Unlock()
	if add {
		if err := a.AddRemoteCandidate(candidate); err != nil {
			x.mu.Lock()
			if p.epoch == epoch {
				delete(p.remoteCandidates, s.Candidate)
				if start {
					p.started = false
				}
			}
			x.mu.Unlock()
			if start {
				x.workers.Done()
			}
			return errors.New("ICE candidate rejected")
		}
	}
	if start {
		go func() {
			defer x.workers.Done()
			var err error
			if controlling {
				_, err = a.Dial(ctx, s.Ufrag, s.Password)
			} else {
				_, err = a.Accept(ctx, s.Ufrag, s.Password)
			}
			if err == nil {
				x.mu.Lock()
				if !x.closed && p.epoch == epoch {
					p.connected = true
					p.selected = p.paired
					if p.selected.IsValid() {
						x.emit(iceUpdate{Peer: key, Generation: p.local.Generation, Revision: epoch, Endpoint: p.selected, State: p.state})
					}
				}
				x.mu.Unlock()
			} else if ctx.Err() == nil {
				x.mu.Lock()
				defer x.mu.Unlock()
				if !x.closed && p.epoch == epoch {
					x.emit(iceUpdate{Peer: key, Generation: p.local.Generation, Revision: epoch, Err: errors.New("ICE checks failed")})
				}
			}
		}()
	}
	return nil
}

func (x *iceTraversal) restart(key wgtypes.Key, p *icePeer) error {
	x.mu.Lock()
	old, cancel := p.agent, p.cancel
	p.epoch++
	p.agent = nil
	p.remote = iceSignal{}
	p.selected, p.paired, p.connected, p.state = netip.AddrPort{}, netip.AddrPort{}, false, ice.ConnectionStateFailed
	x.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if old != nil {
		_ = old.Close()
	}
	return x.createAgent(key, p)
}
func (x *iceTraversal) Restart(key wgtypes.Key) error {
	x.mu.Lock()
	p := x.peers[key]
	closed := x.closed
	x.mu.Unlock()
	if closed {
		return errICEClosed
	}
	if p == nil {
		return errICEInvalid
	}
	return x.restart(key, p)
}
func (x *iceTraversal) Close() error {
	x.mu.Lock()
	if x.closed {
		x.mu.Unlock()
		<-x.closeDone
		return nil
	}
	x.closed = true
	peers := make([]*icePeer, 0, len(x.peers))
	for _, p := range x.peers {
		peers = append(peers, p)
	}
	x.mu.Unlock()
	for _, p := range peers {
		if p.cancel != nil {
			p.cancel()
		}
		if p.agent != nil {
			_ = p.agent.Close()
		}
	}
	err := x.mux.Close()
	x.workers.Wait()
	close(x.closeDone)
	return err
}
