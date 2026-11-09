//go:build linux

package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// All network writers must stop or use the caller's journal lock. Netlink and
// wgctrl do not provide compare-and-swap. The alias is not a security boundary
// against privileged writers.
type directInterfaceOps interface {
	add(string, string) error
	lookup(string) (netlink.Link, error)
	up(netlink.Link) error
	del(netlink.Link) error
	addresses(netlink.Link) ([]netlink.Addr, error)
	routes() ([]netlink.Route, error)
}
type linuxDirectInterfaceOps struct{}

func (linuxDirectInterfaceOps) add(name, alias string) error {
	if err := netlink.LinkAdd(&netlink.GenericLink{LinkAttrs: netlink.LinkAttrs{Name: name}, LinkType: "wireguard"}); err != nil {
		return err
	}
	// Kernel WireGuard does not retain IFLA_IFALIAS from RTM_NEWLINK. Mark
	// the exclusively created link explicitly. A crash before marking is
	// deliberately ambiguous: recovery must refuse an unmarked interface.
	link, err := netlink.LinkByName(name)
	if err != nil {
		return err
	}
	if link.Type() != "wireguard" || link.Attrs().Alias != "" {
		return errors.New("new interface changed before ownership marking")
	}
	return netlink.LinkSetAlias(link, alias)
}
func (linuxDirectInterfaceOps) lookup(name string) (netlink.Link, error) {
	return netlink.LinkByName(name)
}
func (linuxDirectInterfaceOps) up(l netlink.Link) error  { return netlink.LinkSetUp(l) }
func (linuxDirectInterfaceOps) del(l netlink.Link) error { return netlink.LinkDel(l) }
func (linuxDirectInterfaceOps) addresses(l netlink.Link) ([]netlink.Addr, error) {
	return netlink.AddrList(l, netlink.FAMILY_ALL)
}
func (linuxDirectInterfaceOps) routes() ([]netlink.Route, error) {
	// RT_FILTER_TABLE with table zero requests all tables, not just main.
	return netlink.RouteListFiltered(netlink.FAMILY_ALL, &netlink.Route{}, netlink.RT_FILTER_TABLE)
}

// Linux adds this route when an unnumbered WireGuard link comes up. Require
// the exact kernel shape; other or modified routes remain cleanup conflicts.
func directKernelMulticastRoute(index int) netlink.Route {
	return netlink.Route{LinkIndex: index, Family: unix.AF_INET6,
		Dst:   &net.IPNet{IP: net.ParseIP("ff00::"), Mask: net.CIDRMask(8, 128)},
		Table: unix.RT_TABLE_LOCAL, Protocol: unix.RTPROT_KERNEL,
		Type: unix.RTN_MULTICAST, Scope: netlink.SCOPE_UNIVERSE, Priority: 256}
}

const directAliasPrefix = "wireguard-mesh:"

type directInterfaceJournal struct {
	Version                                               int
	Stable, Name, Marker, Phase                           string
	Public                                                wgtypes.Key
	Index, Port, RequestedPort, StablePort, DiscoveryPort int
}
type ownedDirectInterface struct {
	Name    string
	client  wgClient
	ops     directInterfaceOps
	path    string
	journal directInterfaceJournal
}

func ensureDirectInterface(client wgClient, stableName, journalPath string, discoveryPort, requestedPort uint16) (*ownedDirectInterface, error) {
	return ensureDirectInterfaceWithOps(client, stableName, journalPath, discoveryPort, requestedPort, linuxDirectInterfaceOps{})
}
func recoverDirectInterface(client wgClient, stableName, journalPath string) error {
	return recoverDirectInterfaceWithOps(client, stableName, journalPath, linuxDirectInterfaceOps{})
}
func directDir(path string) error {
	dir := filepath.Dir(path)
	if e := os.Mkdir(dir, 0700); e == nil {
		if e = controlSyncDir(filepath.Dir(dir)); e != nil {
			return e
		}
	} else if !errors.Is(e, os.ErrExist) {
		return e
	}
	return controlCheckDir(dir)
}
func directRead(path string) (*directInterfaceJournal, error) {
	f, e := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if errors.Is(e, os.ErrNotExist) {
		return nil, nil
	}
	if e != nil {
		return nil, e
	}
	defer f.Close()
	info, e := f.Stat()
	if e != nil {
		return nil, e
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() > 1<<20 || info.Sys().(*syscall.Stat_t).Uid != uint32(os.Geteuid()) {
		return nil, errors.New("unsafe interface journal")
	}
	var j directInterfaceJournal
	dec := json.NewDecoder(io.LimitReader(f, 1<<20+1))
	dec.DisallowUnknownFields()
	if dec.Decode(&j) != nil || dec.Decode(new(any)) != io.EOF {
		return nil, errors.New("invalid interface journal")
	}
	if j.Version != 1 || !routeValidName(j.Stable) || !routeValidName(j.Name) || j.Name == j.Stable || j.Public == (wgtypes.Key{}) || !strings.HasPrefix(j.Marker, directAliasPrefix) || len(j.Marker) != len(directAliasPrefix)+64 || j.Index < 0 || j.Port < 0 || j.Port > 65535 || j.RequestedPort < 0 || j.RequestedPort > 65535 || j.StablePort <= 0 || j.StablePort > 65535 || j.DiscoveryPort < 0 || j.DiscoveryPort > 65535 || (j.Phase != "creating" && j.Phase != "configuring" && j.Phase != "active" && j.Phase != "deleting" && j.Phase != "resolved") {
		return nil, errors.New("invalid interface journal")
	}
	if _, e = hex.DecodeString(j.Marker[len(directAliasPrefix):]); e != nil {
		return nil, errors.New("invalid interface marker")
	}
	return &j, nil
}
func (o *ownedDirectInterface) save() error {
	if e := controlCheckDir(filepath.Dir(o.path)); e != nil {
		return e
	}
	if info, e := os.Lstat(o.path); e == nil && (!info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Sys().(*syscall.Stat_t).Uid != uint32(os.Geteuid())) {
		return errors.New("unsafe interface journal")
	} else if e != nil && !errors.Is(e, os.ErrNotExist) {
		return e
	}
	data, e := json.Marshal(o.journal)
	if e != nil {
		return e
	}
	if len(data) > 1<<20 {
		return errors.New("interface journal too large")
	}
	f, e := os.CreateTemp(filepath.Dir(o.path), ".interface-recovery-*")
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
		e = os.Rename(f.Name(), o.path)
	}
	if e == nil {
		e = controlSyncDir(filepath.Dir(o.path))
	}
	return e
}
func directMissing(e error) bool {
	var nf netlink.LinkNotFoundError
	return errors.As(e, &nf) || errors.Is(e, syscall.ENODEV) || errors.Is(e, os.ErrNotExist)
}
func recoverDirectInterfaceWithOps(client wgClient, stable, path string, ops directInterfaceOps) error {
	if client == nil || path == "" || !routeValidName(stable) || ops == nil {
		return errors.New("invalid interface recovery arguments")
	}
	if e := directDir(path); e != nil {
		return e
	}
	j, e := directRead(path)
	if e != nil || j == nil {
		return e
	}
	if j.Phase == "resolved" {
		return nil
	}
	if j.Stable != stable {
		return errors.New("interface journal stable name mismatch")
	}
	o := &ownedDirectInterface{Name: j.Name, client: client, ops: ops, path: path, journal: *j}
	return o.Close()
}
func ensureDirectInterfaceWithOps(client wgClient, stable, path string, discovery, requested uint16, ops directInterfaceOps) (result *ownedDirectInterface, resultErr error) {
	if client == nil || !routeValidName(stable) || path == "" || ops == nil {
		return nil, errors.New("invalid interface arguments")
	}
	if e := recoverDirectInterfaceWithOps(client, stable, path, ops); e != nil {
		return nil, e
	}
	s, e := client.Device(stable)
	if e != nil {
		return nil, e
	}
	if s.Name != stable || s.Type != wgtypes.LinuxKernel || s.PrivateKey == (wgtypes.Key{}) || s.PrivateKey.PublicKey() != s.PublicKey || s.ListenPort <= 0 || s.ListenPort > 65535 {
		return nil, errors.New("invalid stable WireGuard identity or port")
	}
	if requested != 0 && (int(requested) == s.ListenPort || requested == discovery) {
		return nil, errors.New("requested port conflicts with stable or discovery port")
	}
	var token [32]byte
	if _, e = rand.Read(token[:]); e != nil {
		return nil, e
	}
	sum := sha256.Sum256([]byte(stable + "\x00" + s.PublicKey.String()))
	base := fmt.Sprintf("wgm-%x", sum[:4])
	o := &ownedDirectInterface{client: client, ops: ops, path: path, journal: directInterfaceJournal{Version: 1, Stable: stable, Public: s.PublicKey, Marker: directAliasPrefix + hex.EncodeToString(token[:]), Phase: "creating", StablePort: s.ListenPort, DiscoveryPort: int(discovery), RequestedPort: int(requested)}}
	candidate := false
	defer func() {
		if resultErr != nil && candidate {
			resultErr = errors.Join(resultErr, o.Close())
		}
	}()
	for i := 0; i <= 99; i++ {
		name := base
		if i > 0 {
			name = fmt.Sprintf("%s-%d", base, i)
		}
		o.Name = name
		o.journal.Name = name
		if e = o.save(); e != nil {
			return nil, e
		}
		e = ops.add(name, o.journal.Marker)
		if errors.Is(e, syscall.EEXIST) {
			continue
		}
		candidate = true // The add may have succeeded even when it returned an error.
		if e != nil {
			return nil, e
		}
		l, e := ops.lookup(name)
		if e != nil {
			return nil, e
		}
		if l.Type() != "wireguard" || l.Attrs().Alias != o.journal.Marker || l.Attrs().Index <= 0 {
			return nil, errors.New("created interface ownership mismatch")
		}
		o.journal.Index = l.Attrs().Index
		o.journal.Phase = "configuring"
		if e = o.save(); e != nil {
			return nil, e
		}
		port := int(requested)
		if e = client.ConfigureDevice(name, wgtypes.Config{PrivateKey: &s.PrivateKey, ListenPort: &port}); e != nil {
			return nil, e
		}
		if e = ops.up(l); e != nil {
			return nil, e
		}
		var d *wgtypes.Device
		for attempt := 0; ; attempt++ {
			d, e = client.Device(name)
			if e != nil {
				return nil, e
			}
			if d.Type != wgtypes.LinuxKernel || d.Name != name || d.PublicKey != s.PublicKey || d.PrivateKey != s.PrivateKey || d.ListenPort <= 0 || d.ListenPort > 65535 || (requested != 0 && d.ListenPort != int(requested)) || len(d.Peers) != 0 || d.FirewallMark != 0 {
				return nil, errors.New("direct WireGuard identity or port mismatch")
			}
			if d.ListenPort != s.ListenPort && d.ListenPort != int(discovery) {
				break
			}
			if requested != 0 || attempt == 15 {
				return nil, errors.New("direct WireGuard port conflicts with stable or discovery port")
			}
			zero := 0
			if e = client.ConfigureDevice(name, wgtypes.Config{ListenPort: &zero}); e != nil {
				return nil, e
			}
		}
		o.journal.Port = d.ListenPort
		if e = o.save(); e != nil {
			return nil, e
		}
		l, e = ops.lookup(name)
		if e != nil {
			return nil, e
		}
		if l.Attrs().Index != o.journal.Index || l.Attrs().Alias != o.journal.Marker || l.Type() != "wireguard" || l.Attrs().Flags&1 == 0 {
			return nil, errors.New("interface up or ownership mismatch")
		}
		o.journal.Phase = "active"
		if e = o.save(); e != nil {
			return nil, e
		}
		return o, nil
	}
	// No add succeeded. Resolve so the final unrelated collision is never adopted.
	o.journal.Phase = "resolved"
	if e = o.save(); e != nil {
		return nil, e
	}
	return nil, errors.New("no available direct interface name")
}
func (o *ownedDirectInterface) Close() error {
	j := &o.journal
	if j.Phase == "resolved" {
		return nil
	}
	l, e := o.ops.lookup(j.Name)
	if directMissing(e) {
		j.Phase = "resolved"
		return o.save()
	}
	if e != nil {
		return e
	}
	if l.Type() != "wireguard" || l.Attrs().Name != j.Name || l.Attrs().Alias != j.Marker || l.Attrs().Index <= 0 || (j.Index != 0 && l.Attrs().Index != j.Index) {
		return errors.New("interface ownership conflict")
	}
	d, e := o.client.Device(j.Name)
	if e != nil {
		return e
	}
	partial := j.Phase == "creating" || j.Phase == "configuring" || (j.Phase == "deleting" && j.Port == 0)
	if d.Type != wgtypes.LinuxKernel || d.Name != j.Name || len(d.Peers) != 0 || d.FirewallMark != 0 || (d.PublicKey != j.Public && !(partial && d.PublicKey == (wgtypes.Key{}))) || (d.PrivateKey != (wgtypes.Key{}) && d.PrivateKey.PublicKey() != j.Public) || (!partial && (d.PublicKey != j.Public || d.ListenPort != j.Port)) || (partial && j.RequestedPort != 0 && d.ListenPort != 0 && d.ListenPort != j.RequestedPort) {
		return errors.New("interface WireGuard state conflict")
	}
	addrs, e := o.ops.addresses(l)
	if e != nil {
		return e
	}
	if len(addrs) != 0 {
		return errors.New("interface has external addresses")
	}
	routes, e := o.ops.routes()
	if e != nil {
		return e
	}
	for _, r := range routes {
		if routeUsesLink(r, l.Attrs().Index) || r.ILinkIndex == l.Attrs().Index {
			kernel := directKernelMulticastRoute(l.Attrs().Index)
			if r.Family == kernel.Family && r.Equal(kernel) && routeExtraEqual(r, kernel) {
				continue
			}
			return fmt.Errorf("interface has external route: %s", r.String())
		}
	}
	j.Index = l.Attrs().Index
	j.Phase = "deleting"
	if e = o.save(); e != nil {
		return e
	}
	if e = o.ops.del(l); e != nil {
		return e
	}
	l, e = o.ops.lookup(j.Name)
	if !directMissing(e) {
		if e != nil {
			return e
		}
		return errors.New("interface deletion not applied")
	}
	j.Phase = "resolved"
	return o.save()
}
