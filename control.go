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
	"sync"
	"syscall"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type wgClient interface {
	Device(string) (*wgtypes.Device, error)
	ConfigureDevice(string, wgtypes.Config) error
}

// Only new peers with one host address are supported. Existing peers, including
// empty peers, are refused: their secrets and endpoints cannot be safely restored.
// The caller must hold journalPath+".lock" and verify the existing OS route.
type controller struct {
	mu      sync.Mutex
	client  wgClient
	path    string
	journal controlJournal
	private wgtypes.Key
	port    int
}

type controlJournal struct {
	Version int
	Name    string
	Public  wgtypes.Key
	Peers   map[string]*controlPeer
}

type controlPeer struct {
	IP      netip.Addr
	Owner   wgtypes.Key
	Prefix  netip.Prefix
	PSKHash [32]byte // A fingerprint detects edits without retaining the PSK.
	Phase   string   // adding, active, restoring, or aborting a partial add.
}

func newController(client wgClient, name, journalPath string) (*controller, error) {
	if client == nil || name == "" || journalPath == "" {
		return nil, errors.New("WireGuard client, interface, and journal path are required")
	}
	dir := filepath.Dir(journalPath)
	if err := os.Mkdir(dir, 0700); err == nil {
		if err := controlSyncDir(filepath.Dir(dir)); err != nil {
			return nil, err
		}
	} else if !errors.Is(err, os.ErrExist) {
		return nil, err
	}
	if err := controlCheckDir(dir); err != nil {
		return nil, err
	}
	c := &controller{client: client, path: journalPath}
	f, err := os.OpenFile(journalPath, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err == nil {
		defer f.Close()
		info, err := f.Stat()
		if err != nil {
			return nil, err
		}
		if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() > 1<<20 || info.Sys().(*syscall.Stat_t).Uid != uint32(os.Geteuid()) {
			return nil, errors.New("journal must be a regular file owned by this user, mode 0600, at most 1 MiB")
		}
		decoder := json.NewDecoder(io.LimitReader(f, 1<<20+1))
		decoder.DisallowUnknownFields()
		if err = decoder.Decode(&c.journal); err != nil {
			return nil, errors.New("invalid recovery journal")
		}
		if decoder.Decode(new(any)) != io.EOF {
			return nil, errors.New("trailing recovery journal data")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	d, err := client.Device(name)
	if err != nil {
		return nil, err
	}
	if f == nil {
		c.journal = controlJournal{1, name, d.PublicKey, make(map[string]*controlPeer)}
	}
	if c.journal.Version != 1 || c.journal.Name != name || c.journal.Public == (wgtypes.Key{}) || c.journal.Public != d.PublicKey || c.journal.Peers == nil {
		return nil, errors.New("invalid journal version, interface, identity, or peer records")
	}
	ips := make(map[netip.Addr]bool)
	for text, r := range c.journal.Peers {
		key, err := wgtypes.ParseKey(text)
		if err != nil || key.String() != text || r == nil || !controlHost(r.IP) || !r.Prefix.IsValid() || r.Prefix != r.Prefix.Masked() || !r.Prefix.Contains(r.IP) ||
			key == (wgtypes.Key{}) || key == d.PublicKey || r.Owner == (wgtypes.Key{}) || r.Owner == key || r.Owner == d.PublicKey ||
			c.journal.Peers[r.Owner.String()] != nil || ips[r.IP] || r.PSKHash == ([32]byte{}) || (r.Phase != "adding" && r.Phase != "active" && r.Phase != "restoring" && r.Phase != "aborting") {
			return nil, errors.New("invalid journal peer ownership record")
		}
		ips[r.IP] = true
	}
	// Recover first. Never adopt a crashed process's direct state as a baseline.
	if err = c.RestoreAll(); err != nil {
		return nil, fmt.Errorf("startup recovery: %w", err)
	}
	d, err = client.Device(name)
	if err != nil {
		return nil, err
	}
	if d.PublicKey != c.journal.Public {
		return nil, errors.New("WireGuard identity changed during recovery")
	}
	c.private, c.port = d.PrivateKey, d.ListenPort
	return c, nil
}

func (c *controller) Identity() (wgtypes.Key, int) { return c.private, c.port }

func controlHost(ip netip.Addr) bool {
	return ip.IsValid() && !ip.Is4In6() && ip.Zone() == "" && (ip.IsGlobalUnicast() || ip.IsLinkLocalUnicast())
}

func (c *controller) Apply(key wgtypes.Key, ip netip.Addr, psk wgtypes.Key, endpoint netip.AddrPort) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if key == (wgtypes.Key{}) || key == c.journal.Public || !controlHost(ip) || !endpoint.IsValid() || endpoint.Port() == 0 ||
		!controlHost(endpoint.Addr().WithZone("")) || (endpoint.Addr().IsLinkLocalUnicast() && endpoint.Addr().Is6() && endpoint.Addr().Zone() == "") {
		return errors.New("invalid direct peer key, host address, or endpoint")
	}
	d, err := c.device()
	if err != nil {
		return err
	}
	for text, r := range c.journal.Peers {
		k, _ := wgtypes.ParseKey(text)
		if r.Phase != "active" {
			return errors.New("unfinished recovery; restore before applying")
		}
		if err := c.checkPeer(d, k, r); err != nil {
			return err
		}
		if r.IP == ip && k != key {
			return errors.New("host address is already managed")
		}
	}
	r := c.journal.Peers[key.String()]
	if r != nil {
		if r.IP != ip || r.PSKHash != sha256.Sum256(psk[:]) {
			return errors.New("restore the managed peer before changing its host address or PSK")
		}
	} else {
		if controlFindPeer(d, key) != nil {
			return errors.New("pre-existing direct peers are unsupported, including peers with empty AllowedIPs")
		}
		owner, prefix, err := controlOwner(d, ip, wgtypes.Key{})
		if err != nil {
			return err
		}
		if owner == (wgtypes.Key{}) || owner == key || owner == d.PublicKey || c.journal.Peers[owner.String()] != nil {
			return errors.New("host address has no independent stable WireGuard owner")
		}
		r = &controlPeer{ip, owner, prefix, sha256.Sum256(psk[:]), "adding"}
		c.journal.Peers[key.String()] = r
		if err := c.save(); err != nil {
			return err
		}
	}
	// Recheck after journal I/O. wgctrl has no compare-and-swap; external writers
	// must be stopped or use the same lock to exclude the final read/write race.
	d, err = c.device()
	if err == nil {
		err = c.checkPeer(d, key, r)
	}
	if err == nil && r.Phase == "adding" && controlFindPeer(d, key) != nil {
		err = errors.New("direct peer appeared before apply")
	}
	if err != nil {
		if r.Phase == "adding" {
			delete(c.journal.Peers, key.String())
			err = errors.Join(err, c.save())
		}
		return err
	}
	peer := wgtypes.PeerConfig{PublicKey: key, UpdateOnly: r.Phase == "active", Endpoint: net.UDPAddrFromAddrPort(endpoint)}
	if r.Phase == "adding" {
		peer.PresharedKey, peer.AllowedIPs = &psk, []net.IPNet{controlHostNet(ip)}
	}
	err = c.client.ConfigureDevice(c.journal.Name, wgtypes.Config{Peers: []wgtypes.PeerConfig{peer}})
	if err == nil {
		expected := *r
		expected.Phase = "active"
		d, err = c.device()
		if err == nil {
			err = c.checkPeer(d, key, &expected)
		}
		if err == nil {
			r.Phase = "active"
			err = c.save()
		}
	}
	if err != nil {
		return errors.Join(err, c.restore(key))
	}
	return nil
}

func (c *controller) Restore(key wgtypes.Key) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.restore(key)
}

func (c *controller) RestoreAll() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	var err error
	for text := range c.journal.Peers {
		key, _ := wgtypes.ParseKey(text)
		err = errors.Join(err, c.restore(key))
	}
	return err
}

func (c *controller) restore(key wgtypes.Key) error {
	r := c.journal.Peers[key.String()]
	if r == nil {
		return nil
	}
	d, err := c.device()
	if err != nil {
		return err
	}
	if err := c.checkPeer(d, key, r); err != nil {
		return err
	}
	if r.Phase == "adding" {
		r.Phase = "aborting"
	} else if r.Phase == "active" {
		r.Phase = "restoring"
	}
	// Persist intent even on retry: the previous save may have failed to sync.
	if err := c.save(); err != nil {
		return err
	}
	// Move an exact host back before deleting the direct peer. Each operation is
	// independently recoverable, including an error after the kernel applied it.
	if r.Prefix.Bits() == r.IP.BitLen() {
		d, err = c.device()
		if err == nil {
			err = c.checkPeer(d, key, r)
		}
		if err != nil {
			return err
		}
		owner, _, err := controlOwner(d, r.IP, wgtypes.Key{})
		if err != nil {
			return err
		}
		if owner == key {
			if err := c.client.ConfigureDevice(c.journal.Name, wgtypes.Config{Peers: []wgtypes.PeerConfig{{PublicKey: r.Owner, UpdateOnly: true, AllowedIPs: []net.IPNet{controlHostNet(r.IP)}}}}); err != nil {
				return err
			}
		}
	}
	d, err = c.device()
	if err == nil {
		err = c.checkPeer(d, key, r)
	}
	if err != nil {
		return err
	}
	if controlFindPeer(d, key) != nil {
		if r.Prefix.Bits() == r.IP.BitLen() {
			owner, _, err := controlOwner(d, r.IP, wgtypes.Key{})
			if err != nil || owner != r.Owner {
				return errors.New("stable host ownership was not restored")
			}
		}
		if err := c.client.ConfigureDevice(c.journal.Name, wgtypes.Config{Peers: []wgtypes.PeerConfig{{PublicKey: key, Remove: true}}}); err != nil {
			return err
		}
	}
	d, err = c.device()
	if err == nil {
		err = c.checkPeer(d, key, r)
	}
	if err != nil {
		return err
	}
	if controlFindPeer(d, key) != nil {
		return errors.New("direct peer removal was not applied")
	}
	delete(c.journal.Peers, key.String())
	if err := c.save(); err != nil {
		c.journal.Peers[key.String()] = r
		return err
	}
	return nil
}

func (c *controller) Check() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	d, err := c.device()
	if err != nil {
		return err
	}
	for text, r := range c.journal.Peers {
		key, _ := wgtypes.ParseKey(text)
		if err := c.checkPeer(d, key, r); err != nil {
			return err
		}
		if r.Phase != "active" {
			return errors.New("unfinished peer recovery")
		}
	}
	return nil
}

func (c *controller) device() (*wgtypes.Device, error) {
	d, err := c.client.Device(c.journal.Name)
	if err == nil && d.PublicKey != c.journal.Public {
		err = errors.New("WireGuard identity changed")
	}
	return d, err
}

func (c *controller) checkPeer(d *wgtypes.Device, key wgtypes.Key, r *controlPeer) error {
	conflict := fmt.Errorf("external change conflicts with managed peer %s", key)
	p := controlFindPeer(d, key)
	exact := r.Prefix.Bits() == r.IP.BitLen()
	partial := r.Phase == "adding" || r.Phase == "aborting"
	if p == nil && r.Phase == "active" {
		return conflict
	}
	if p != nil {
		empty := len(p.AllowedIPs) == 0
		if p.PersistentKeepaliveInterval != 0 || p.ProtocolVersion < 0 || p.ProtocolVersion > 1 ||
			(sha256.Sum256(p.PresharedKey[:]) != r.PSKHash && !(partial && empty && p.PresharedKey == (wgtypes.Key{}))) ||
			(!empty && (len(p.AllowedIPs) != 1 || p.AllowedIPs[0].String() != netip.PrefixFrom(r.IP, r.IP.BitLen()).String())) ||
			(empty && !partial && !(exact && r.Phase == "restoring")) {
			return conflict
		}
	}
	if controlFindPeer(d, r.Owner) == nil {
		return conflict
	}
	skip := key
	if exact {
		skip = wgtypes.Key{}
	}
	owner, prefix, err := controlOwner(d, r.IP, skip)
	if err != nil {
		return err
	}
	if exact && p != nil && len(p.AllowedIPs) == 1 {
		if owner != key || prefix != r.Prefix {
			return conflict
		}
	} else if owner != r.Owner || prefix != r.Prefix {
		return conflict
	}
	return nil
}

func controlFindPeer(d *wgtypes.Device, key wgtypes.Key) *wgtypes.Peer {
	for i := range d.Peers {
		if d.Peers[i].PublicKey == key {
			return &d.Peers[i]
		}
	}
	return nil
}

func controlOwner(d *wgtypes.Device, ip netip.Addr, skip wgtypes.Key) (wgtypes.Key, netip.Prefix, error) {
	var owner wgtypes.Key
	var best netip.Prefix
	for _, p := range d.Peers {
		if p.PublicKey == skip {
			continue
		}
		for _, n := range p.AllowedIPs {
			prefix, err := netip.ParsePrefix(n.String())
			if err != nil {
				return owner, best, errors.New("invalid WireGuard AllowedIP")
			}
			prefix = prefix.Masked()
			if prefix.Contains(ip) && prefix.Bits() >= best.Bits() {
				if prefix.Bits() == best.Bits() && owner != p.PublicKey {
					return owner, best, errors.New("ambiguous WireGuard host ownership")
				}
				owner, best = p.PublicKey, prefix
			}
		}
	}
	return owner, best, nil
}

func controlHostNet(ip netip.Addr) net.IPNet {
	return net.IPNet{IP: net.IP(ip.AsSlice()), Mask: net.CIDRMask(ip.BitLen(), ip.BitLen())}
}

func controlSyncDir(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	return errors.Join(f.Sync(), f.Close())
}

func controlCheckDir(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode().Perm() != 0700 || info.Sys().(*syscall.Stat_t).Uid != uint32(os.Geteuid()) {
		return errors.New("journal directory must be owned by this user, mode 0700, and not a symlink")
	}
	return nil
}

func (c *controller) save() error {
	if err := controlCheckDir(filepath.Dir(c.path)); err != nil {
		return err
	}
	if info, err := os.Lstat(c.path); err == nil && (!info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Sys().(*syscall.Stat_t).Uid != uint32(os.Geteuid())) {
		return errors.New("refuse to replace an unsafe journal file")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	data, err := json.Marshal(c.journal)
	if err != nil {
		return err
	}
	if len(data) > 1<<20 {
		return errors.New("recovery journal exceeds 1 MiB")
	}
	f, err := os.CreateTemp(filepath.Dir(c.path), ".recovery-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	err = errors.Join(err, f.Close())
	if err == nil {
		err = os.Rename(f.Name(), c.path)
	}
	if err == nil {
		err = controlSyncDir(filepath.Dir(c.path))
	}
	return err
}
