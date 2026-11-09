package main

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Route operations do not offer compare-and-swap. The caller must hold the
// journal lock, and all other writers must use the same lock or be stopped.
type routeOperations interface {
	index(string) (int, error)
	list(netip.Addr) ([]netlink.Route, error)
	add(netlink.Route) error
	del(netlink.Route) error
}
type linuxRouteOperations struct{}

func (linuxRouteOperations) index(name string) (int, error) {
	l, e := netlink.LinkByName(name)
	if e != nil {
		return 0, e
	}
	return l.Attrs().Index, nil
}
func (linuxRouteOperations) list(ip netip.Addr) ([]netlink.Route, error) {
	family := netlink.FAMILY_V6
	if ip.Is4() {
		family = netlink.FAMILY_V4
	}
	n := controlHostNet(ip)
	return netlink.RouteListFiltered(family, &netlink.Route{Table: unix.RT_TABLE_MAIN, Dst: &n}, netlink.RT_FILTER_TABLE|netlink.RT_FILTER_DST)
}
func (linuxRouteOperations) add(r netlink.Route) error { return netlink.RouteAdd(&r) }
func (linuxRouteOperations) del(r netlink.Route) error { return netlink.RouteDel(&r) }

type routeRecord struct {
	IP      netip.Addr
	Owner   wgtypes.Key
	Prefix  netip.Prefix
	PSKHash [32]byte
	Phase   string
}
type routeJournal struct {
	Version                               int
	Stable, Direct                        string
	Public                                wgtypes.Key
	StablePort, DirectPort, Index, Metric int
	Source                                netip.Addr
	Peers                                 map[string]*routeRecord
}
type routeController struct {
	mu      sync.Mutex
	client  wgClient
	routes  routeOperations
	path    string
	journal routeJournal
	private wgtypes.Key
}

func newRouteController(client wgClient, stableName, directName, journalPath string, source netip.Addr, metric int) (*routeController, error) {
	return openRouteController(client, stableName, directName, journalPath, source, metric, linuxRouteOperations{}, false)
}
func recoverRouteController(client wgClient, stableName, journalPath string) error {
	_, err := openRouteController(client, stableName, "", journalPath, netip.Addr{}, 0, linuxRouteOperations{}, true)
	return err
}
func routeValidName(name string) bool {
	return len(name) > 0 && len(name) < unix.IFNAMSIZ && name != "." && name != ".." && !strings.ContainsAny(name, "/: \t\n\r\v\f\x00")
}
func routeValidEndpoint(endpoint netip.AddrPort) bool {
	return endpoint.IsValid() && endpoint.Port() != 0 && controlHost(endpoint.Addr().WithZone("")) && !(endpoint.Addr().Is6() && endpoint.Addr().IsLinkLocalUnicast() && endpoint.Addr().Zone() == "")
}
func openRouteController(client wgClient, stable, direct, path string, source netip.Addr, metric int, routes routeOperations, recovery bool) (*routeController, error) {
	if client == nil || !routeValidName(stable) || path == "" || routes == nil || (!recovery && !routeValidName(direct)) {
		return nil, errors.New("client, stable interface and journal are required")
	}
	dir := filepath.Dir(path)
	if err := os.Mkdir(dir, 0700); err == nil {
		if err = controlSyncDir(filepath.Dir(dir)); err != nil {
			return nil, err
		}
	} else if !errors.Is(err, os.ErrExist) {
		return nil, err
	}
	if err := controlCheckDir(dir); err != nil {
		return nil, err
	}
	c := &routeController{client: client, routes: routes, path: path}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err == nil {
		defer f.Close()
		info, e := f.Stat()
		if e != nil {
			return nil, e
		}
		if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() > 1<<20 || info.Sys().(*syscall.Stat_t).Uid != uint32(os.Geteuid()) {
			return nil, errors.New("unsafe route journal")
		}
		dec := json.NewDecoder(io.LimitReader(f, 1<<20+1))
		dec.DisallowUnknownFields()
		if dec.Decode(&c.journal) != nil || dec.Decode(new(any)) != io.EOF {
			return nil, errors.New("invalid route journal")
		}
		if err := c.journal.validate(stable); err != nil {
			return nil, err
		}
		if len(c.journal.Peers) == 0 {
			// Resolved state owns no peers or routes. Disabling route mode or
			// changing its settings must not require the old direct device.
			if recovery {
				return c, nil
			}
			f = nil // The original file's Close receiver was captured above.
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	} else if recovery {
		return c, nil
	}
	if f == nil {
		if direct == "" || direct == stable || !controlHost(source) || metric < 0 {
			return nil, errors.New("invalid route controller configuration")
		}
		s, e := client.Device(stable)
		if e != nil {
			return nil, e
		}
		d, e := client.Device(direct)
		if e != nil {
			return nil, e
		}
		idx, e := routes.index(direct)
		if e != nil {
			return nil, e
		}
		c.journal = routeJournal{Version: 1, Stable: stable, Direct: direct, Public: s.PublicKey, StablePort: s.ListenPort, DirectPort: d.ListenPort, Index: idx, Metric: metric, Source: source, Peers: map[string]*routeRecord{}}
	}
	j := &c.journal
	if err := j.validate(stable); err != nil {
		return nil, err
	}
	if !recovery && (j.Direct != direct || j.Source != source || j.Metric != metric) {
		return nil, errors.New("route journal configuration mismatch")
	}
	if _, err = c.devices(); err != nil {
		return nil, err
	}
	if err = c.RestoreAll(); err != nil {
		return nil, fmt.Errorf("route startup recovery: %w", err)
	}
	d, err := c.devices()
	if err != nil {
		return nil, err
	}
	if len(d.Peers) != 0 {
		return nil, errors.New("direct interface must have an empty peer baseline")
	}
	c.private = d.PrivateKey
	return c, nil
}

func (j routeJournal) validate(stable string) error {
	if j.Version != 1 || j.Stable != stable || !routeValidName(j.Direct) || j.Direct == stable || j.Public == (wgtypes.Key{}) || j.StablePort <= 0 || j.StablePort > 65535 || j.DirectPort <= 0 || j.DirectPort > 65535 || j.StablePort == j.DirectPort || j.Index <= 0 || j.Metric < 0 || !controlHost(j.Source) || j.Peers == nil {
		return errors.New("invalid route journal configuration")
	}
	ips := map[netip.Addr]bool{}
	for text, r := range j.Peers {
		k, e := wgtypes.ParseKey(text)
		if e != nil || k.String() != text || k == (wgtypes.Key{}) || k == j.Public || r == nil || !controlHost(r.IP) || r.IP.BitLen() != j.Source.BitLen() || ips[r.IP] || r.Owner == (wgtypes.Key{}) || r.Owner == k || r.Owner == j.Public || !r.Prefix.IsValid() || r.Prefix != r.Prefix.Masked() || !r.Prefix.Contains(r.IP) || r.PSKHash == ([32]byte{}) || (r.Phase != "planning" && r.Phase != "adding" && r.Phase != "aborting" && r.Phase != "staged" && r.Phase != "routing" && r.Phase != "active" && r.Phase != "restoring") {
			return errors.New("invalid route journal record")
		}
		ips[r.IP] = true
	}
	return nil
}
func (c *routeController) devices() (*wgtypes.Device, error) {
	j := c.journal
	s, e := c.client.Device(j.Stable)
	if e != nil {
		return nil, e
	}
	d, e := c.client.Device(j.Direct)
	if e != nil {
		return nil, e
	}
	idx, e := c.routes.index(j.Direct)
	if e != nil {
		return nil, e
	}
	if s.Type != wgtypes.LinuxKernel || d.Type != wgtypes.LinuxKernel || s.Name != j.Stable || d.Name != j.Direct || s.PublicKey != j.Public || d.PublicKey != j.Public || s.PrivateKey == (wgtypes.Key{}) || s.PrivateKey != d.PrivateKey || s.PrivateKey.PublicKey() != j.Public || s.ListenPort != j.StablePort || d.ListenPort != j.DirectPort || d.FirewallMark != 0 || idx != j.Index {
		return nil, errors.New("WireGuard device identity, port, or interface changed")
	}
	for _, r := range j.Peers {
		owner, prefix, err := controlOwner(s, r.IP, wgtypes.Key{})
		if err != nil || owner != r.Owner || prefix != r.Prefix {
			return nil, errors.New("stable WireGuard host ownership changed")
		}
	}
	for _, p := range d.Peers {
		if c.journal.Peers[p.PublicKey.String()] == nil {
			return nil, errors.New("unmanaged direct peer")
		}
	}
	return d, nil
}
func (c *routeController) Identity() (wgtypes.Key, int) { return c.private, c.journal.DirectPort }
func (c *routeController) route(ip netip.Addr) netlink.Route {
	n := controlHostNet(ip)
	return netlink.Route{LinkIndex: c.journal.Index, Dst: &n, Src: net.IP(c.journal.Source.AsSlice()), Priority: c.journal.Metric, Table: unix.RT_TABLE_MAIN, Protocol: unix.RTPROT_BOOT, Scope: netlink.SCOPE_LINK, Type: unix.RTN_UNICAST}
}

// Route.Equal does not compare route metrics such as MTU and RTT.
func routeExtraEqual(a, b netlink.Route) bool {
	return a.MTU == b.MTU && a.MTULock == b.MTULock && a.Window == b.Window &&
		a.Rtt == b.Rtt && a.RttVar == b.RttVar && a.Ssthresh == b.Ssthresh &&
		a.Cwnd == b.Cwnd && a.AdvMSS == b.AdvMSS && a.Reordering == b.Reordering &&
		a.InitCwnd == b.InitCwnd && a.Features == b.Features && a.RtoMin == b.RtoMin &&
		a.RtoMinLock == b.RtoMinLock && a.InitRwnd == b.InitRwnd && a.QuickACK == b.QuickACK &&
		a.Congctl == b.Congctl && a.FastOpenNoCookie == b.FastOpenNoCookie
}
func routeUsesLink(r netlink.Route, index int) bool {
	if r.LinkIndex == index {
		return true
	}
	for _, next := range r.MultiPath {
		if next != nil && next.LinkIndex == index {
			return true
		}
	}
	return false
}
func (c *routeController) inspectRoute(r *routeRecord) (bool, error) {
	routes, e := c.routes.list(r.IP)
	if e != nil {
		return false, e
	}
	want := c.route(r.IP)
	found := false
	for _, v := range routes {
		if v.Equal(want) && routeExtraEqual(v, want) {
			if found {
				return false, errors.New("duplicate direct route")
			}
			found = true
		} else if v.Priority <= want.Priority || routeUsesLink(v, want.LinkIndex) {
			return false, errors.New("conflicting exact host route")
		}
	}
	return found, nil
}
func (c *routeController) peer(d *wgtypes.Device, k wgtypes.Key, r *routeRecord) error {
	p := controlFindPeer(d, k)
	if p == nil {
		if r.Phase == "staged" || r.Phase == "active" {
			return errors.New("managed peer disappeared")
		}
		return nil
	}
	if r.Phase == "planning" {
		return errors.New("peer appeared before add")
	}
	partial := r.Phase == "adding" || r.Phase == "aborting"
	keyOK := sha256.Sum256(p.PresharedKey[:]) == r.PSKHash
	hostOK := len(p.AllowedIPs) == 1 && p.AllowedIPs[0].String() == netip.PrefixFrom(r.IP, r.IP.BitLen()).String()
	full := keyOK && p.PersistentKeepaliveInterval == time.Second && hostOK
	// Kernel netlink writes are not transactional. During add recovery, each
	// field can be either absent or the exact value this transaction requested.
	// Unrelated keys, prefixes, or keepalive values remain conflicts.
	subset := (keyOK || p.PresharedKey == (wgtypes.Key{})) && (p.PersistentKeepaliveInterval == 0 || p.PersistentKeepaliveInterval == time.Second) && (len(p.AllowedIPs) == 0 || hostOK)
	if (!full && !(partial && subset)) || p.ProtocolVersion < 0 || p.ProtocolVersion > 1 {
		return errors.New("managed peer changed")
	}
	return nil
}
func (c *routeController) Stage(k wgtypes.Key, ip netip.Addr, psk wgtypes.Key, endpoint netip.AddrPort) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if k == (wgtypes.Key{}) || k == c.journal.Public || !controlHost(ip) || ip.BitLen() != c.journal.Source.BitLen() || !routeValidEndpoint(endpoint) {
		return false, errors.New("invalid direct peer")
	}
	d, e := c.devices()
	if e != nil {
		return false, e
	}
	for text, x := range c.journal.Peers {
		key, _ := wgtypes.ParseKey(text)
		if x.IP == ip && key != k {
			return false, errors.New("address already managed")
		}
		if e = c.peer(d, key, x); e != nil {
			return false, e
		}
		if x.Phase != "staged" && x.Phase != "active" {
			return false, errors.New("unfinished route recovery")
		}
	}
	r := c.journal.Peers[k.String()]
	if r != nil {
		if r.IP != ip || r.PSKHash != sha256.Sum256(psk[:]) {
			return false, errors.New("restore before changing peer")
		}
		found, e := c.inspectRoute(r)
		if e != nil {
			return false, e
		}
		if found != (r.Phase == "active") {
			return false, errors.New("unexpected host route")
		}
		return !controlFindPeer(d, k).LastHandshakeTime.IsZero(), nil
	}
	if controlFindPeer(d, k) != nil {
		return false, errors.New("pre-existing peer")
	}
	stable, e := c.client.Device(c.journal.Stable)
	if e != nil {
		return false, e
	}
	owner, prefix, e := controlOwner(stable, ip, wgtypes.Key{})
	if e != nil || owner == (wgtypes.Key{}) || owner == k || owner == c.journal.Public {
		return false, errors.New("host address has no independent stable WireGuard owner")
	}
	r = &routeRecord{IP: ip, Owner: owner, Prefix: prefix, PSKHash: sha256.Sum256(psk[:]), Phase: "planning"}
	if found, e := c.inspectRoute(r); e != nil {
		return false, e
	} else if found {
		return false, errors.New("pre-existing direct route")
	}
	c.journal.Peers[k.String()] = r
	if e = c.save(); e != nil {
		return false, e
	}
	d, e = c.devices()
	if e != nil {
		return false, e
	}
	if e = c.peer(d, k, r); e != nil {
		return false, e
	}
	r.Phase = "adding"
	if e = c.save(); e != nil {
		r.Phase = "planning"
		return false, e
	}
	keep := time.Second
	e = c.client.ConfigureDevice(c.journal.Direct, wgtypes.Config{Peers: []wgtypes.PeerConfig{{PublicKey: k, PresharedKey: &psk, Endpoint: net.UDPAddrFromAddrPort(endpoint), PersistentKeepaliveInterval: &keep, AllowedIPs: []net.IPNet{controlHostNet(ip)}}}})
	if e != nil {
		return false, e
	}
	d, e = c.devices()
	if e != nil {
		return false, e
	}
	expected := *r
	expected.Phase = "staged"
	if e = c.peer(d, k, &expected); e != nil {
		return false, e
	}
	if controlFindPeer(d, k) == nil {
		return false, errors.New("peer add not applied")
	}
	r.Phase = "staged"
	if e = c.save(); e != nil {
		return false, e
	}
	return !controlFindPeer(d, k).LastHandshakeTime.IsZero(), nil
}
func (c *routeController) Apply(k wgtypes.Key, ip netip.Addr, psk wgtypes.Key, endpoint netip.AddrPort) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, err := c.apply(k, ip, psk, endpoint, false)
	return err
}

func (c *routeController) EnsureEndpoint(k wgtypes.Key, ip netip.Addr, psk wgtypes.Key, endpoint netip.AddrPort) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.apply(k, ip, psk, endpoint, true)
}

func (c *routeController) apply(k wgtypes.Key, ip netip.Addr, psk wgtypes.Key, endpoint netip.AddrPort, activeOnly bool) (bool, error) {
	if !routeValidEndpoint(endpoint) {
		return false, errors.New("invalid direct endpoint")
	}
	r := c.journal.Peers[k.String()]
	if r == nil || (r.Phase != "staged" && r.Phase != "active") || (activeOnly && r.Phase != "active") || r.IP != ip || r.PSKHash != sha256.Sum256(psk[:]) {
		return false, errors.New("stage peer before apply")
	}
	d, e := c.devices()
	if e != nil {
		return false, e
	}
	if e = c.peer(d, k, r); e != nil {
		return false, e
	}
	if controlFindPeer(d, k).LastHandshakeTime.IsZero() {
		return false, errors.New("direct handshake required")
	}
	found, e := c.inspectRoute(r)
	if e != nil {
		return false, e
	}
	if found != (r.Phase == "active") {
		return false, errors.New("unexpected host route")
	}
	changed := controlFindPeer(d, k).Endpoint == nil || controlFindPeer(d, k).Endpoint.AddrPort() != endpoint
	if changed {
		if e = c.client.ConfigureDevice(c.journal.Direct, wgtypes.Config{Peers: []wgtypes.PeerConfig{{PublicKey: k, UpdateOnly: true, Endpoint: net.UDPAddrFromAddrPort(endpoint)}}}); e != nil {
			return false, e
		}
		d, e = c.devices()
		if e != nil {
			return false, e
		}
		if e = c.peer(d, k, r); e != nil {
			return false, e
		}
		p := controlFindPeer(d, k)
		if p.LastHandshakeTime.IsZero() {
			return false, errors.New("direct handshake disappeared")
		}
		found, e = c.inspectRoute(r)
		if e != nil {
			return false, e
		}
		if found != (r.Phase == "active") {
			return false, errors.New("unexpected host route")
		}
		if p.Endpoint == nil || p.Endpoint.AddrPort() != endpoint {
			// Valid transport packets can race this update. Do not add a
			// staged route or report endpoint maintenance as successful.
			return true, errEndpointRoamed
		}
	}
	if r.Phase == "active" {
		return changed, nil
	}
	r.Phase = "routing"
	if e = c.save(); e != nil {
		r.Phase = "staged"
		return false, e
	}
	found, e = c.inspectRoute(r)
	if e != nil {
		return false, e
	}
	if found {
		return false, errors.New("route appeared before add")
	}
	if e = c.routes.add(c.route(ip)); e != nil {
		return false, e
	}
	found, e = c.inspectRoute(r)
	if e != nil {
		return false, e
	}
	if !found {
		return false, errors.New("route add not applied")
	}
	r.Phase = "active"
	return changed, c.save()
}
func (c *routeController) Restore(k wgtypes.Key) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.restore(k)
}
func (c *routeController) RestoreAll() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	var e error
	for text := range c.journal.Peers {
		k, _ := wgtypes.ParseKey(text)
		e = errors.Join(e, c.restore(k))
	}
	return e
}
func (c *routeController) restore(k wgtypes.Key) error {
	r := c.journal.Peers[k.String()]
	if r == nil {
		return nil
	}
	d, e := c.devices()
	if e != nil {
		return e
	}
	if e = c.peer(d, k, r); e != nil {
		return e
	}
	found, e := c.inspectRoute(r)
	if e != nil {
		return e
	}
	if found && r.Phase != "routing" && r.Phase != "active" && r.Phase != "restoring" {
		return errors.New("unexpected route before route add")
	}
	if r.Phase == "planning" && controlFindPeer(d, k) != nil {
		return errors.New("unexpected peer")
	}
	if r.Phase == "adding" || r.Phase == "aborting" {
		r.Phase = "aborting"
	} else {
		r.Phase = "restoring"
	}
	if e = c.save(); e != nil {
		return e
	}
	if found {
		if e = c.routes.del(c.route(r.IP)); e != nil {
			return e
		}
		found, e = c.inspectRoute(r)
		if e != nil {
			return e
		}
		if found {
			return errors.New("route removal not applied")
		}
	}
	d, e = c.devices()
	if e != nil {
		return e
	}
	if e = c.peer(d, k, r); e != nil {
		return e
	}
	if controlFindPeer(d, k) != nil {
		if e = c.client.ConfigureDevice(c.journal.Direct, wgtypes.Config{Peers: []wgtypes.PeerConfig{{PublicKey: k, Remove: true}}}); e != nil {
			return e
		}
	}
	d, e = c.devices()
	if e != nil {
		return e
	}
	if controlFindPeer(d, k) != nil {
		return errors.New("peer removal not applied")
	}
	delete(c.journal.Peers, k.String())
	if e = c.save(); e != nil {
		c.journal.Peers[k.String()] = r
		return e
	}
	return nil
}
func (c *routeController) Check() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	d, e := c.devices()
	if e != nil {
		return e
	}
	for text, r := range c.journal.Peers {
		k, _ := wgtypes.ParseKey(text)
		if r.Phase != "staged" && r.Phase != "active" {
			return errors.New("unfinished route recovery")
		}
		if e = c.peer(d, k, r); e != nil {
			return e
		}
		found, e := c.inspectRoute(r)
		if e != nil {
			return e
		}
		if found != (r.Phase == "active") {
			return errors.New("unexpected route state")
		}
	}
	return nil
}
func (c *routeController) save() error {
	if e := controlCheckDir(filepath.Dir(c.path)); e != nil {
		return e
	}
	if info, e := os.Lstat(c.path); e == nil && (!info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Sys().(*syscall.Stat_t).Uid != uint32(os.Geteuid())) {
		return errors.New("unsafe route journal")
	} else if e != nil && !errors.Is(e, os.ErrNotExist) {
		return e
	}
	data, e := json.Marshal(c.journal)
	if e != nil {
		return e
	}
	if len(data) > 1<<20 {
		return errors.New("route journal exceeds 1 MiB")
	}
	f, e := os.CreateTemp(filepath.Dir(c.path), ".route-recovery-*")
	if e != nil {
		return e
	}
	defer os.Remove(f.Name())
	if e = f.Chmod(0600); e == nil {
		_, e = f.Write(data)
	}
	if e == nil {
		e = f.Sync()
	}
	e = errors.Join(e, f.Close())
	if e == nil {
		e = os.Rename(f.Name(), c.path)
	}
	if e == nil {
		e = controlSyncDir(filepath.Dir(c.path))
	}
	return e
}
