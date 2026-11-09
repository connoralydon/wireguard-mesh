package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		slog.Error("service stopped", "error", err)
		os.Exit(1)
	}
}

func run(args []string) (err error) {
	flags := flag.NewFlagSet("wireguard-meshd", flag.ContinueOnError)
	name := flags.String("wireguard", "", "required existing WireGuard configuration/interface name, for example wg0")
	file := flags.String("config", "", "peer configuration JSON (default /etc/wireguard-mesh/NAME.json)")
	state := flags.String("state", "", "recovery journal (default /var/lib/wireguard-mesh-NAME/recovery.json)")
	restore := flags.Bool("restore", false, "restore the journal and exit; no peer configuration needed")
	dry := flags.Bool("dry-run", false, "discover and measure without changing WireGuard")
	adapter := flags.String("rosenpass-adapter", "", "run the unprivileged mesh-only Rosenpass adapter with this JSON configuration")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if *adapter != "" {
		if *name != "" || *file != "" || *state != "" || *restore || *dry || flags.NArg() != 0 {
			return errors.New("-rosenpass-adapter cannot be combined with daemon options")
		}
		ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
		defer stop()
		return runRosenpassAdapter(ctx, *adapter)
	}
	if !validName(*name) || flags.NArg() != 0 {
		return errors.New("pass -wireguard NAME for one existing WireGuard interface")
	}
	if runtime.GOOS != "linux" {
		return errors.New("the service supports Linux only")
	}
	if *restore && *dry {
		return errors.New("-restore and -dry-run are mutually exclusive")
	}
	if *file == "" {
		*file = "/etc/wireguard-mesh/" + *name + ".json"
	}
	if *state == "" {
		*state = "/var/lib/wireguard-mesh-" + *name + "/recovery.json"
	}
	client, err := wgctrl.New()
	if err != nil {
		return err
	}
	defer client.Close()
	var control routeControl
	var checkDevice func() (*wgtypes.Device, error)
	var private wgtypes.Key
	var port int
	var journalPath string
	if *dry {
		for _, path := range []string{*state, *state + ".routes", *state + ".interface"} {
			if _, e := os.Stat(path); e == nil {
				return errors.New("recover and remove the old journals before a dry run")
			} else if !errors.Is(e, os.ErrNotExist) {
				return e
			}
		}
		d, e := client.Device(*name)
		if e != nil {
			return e
		}
		private, port = d.PrivateKey, d.ListenPort
		readOnly := &readOnlyControl{client, *name, d.PublicKey}
		control, checkDevice = readOnly, readOnly.checkDevice
	} else {
		resolved, unlock, e := lockJournal(*state)
		if e != nil {
			return e
		}
		defer unlock()
		journalPath = resolved
		if e := recoverRouteController(client, *name, resolved+".routes"); e != nil {
			return e
		}
		if e := recoverDirectInterface(client, *name, resolved+".interface"); e != nil {
			return e
		}
		c, e := newController(client, *name, resolved)
		if e != nil {
			return e
		}
		defer func() { err = errors.Join(err, c.RestoreAll()) }()
		if *restore {
			return nil
		}
		control = c
		checkDevice = c.checkDevice
		private, port = c.Identity()
	}
	f, err := os.Open(*file)
	if err != nil {
		return err
	}
	c, err := readConfig(f)
	f.Close()
	if err != nil {
		return err
	}
	if private == (wgtypes.Key{}) || port <= 0 || port > 65535 || uint16(port) == c.Port {
		return errors.New("WireGuard needs a private key and a nonzero listen port distinct from the discovery port")
	}
	for _, p := range c.Peers {
		if p.key == private.PublicKey() {
			return errors.New("peer list contains the local identity")
		}
	}
	d, err := client.Device(*name)
	if err != nil {
		return err
	}
	if err := checkPeers(d, c.Peers); err != nil {
		return err
	}
	tunnel, err := tunnelLink(*name, c.Address)
	if err != nil {
		return err
	}
	if err := checkRoutes(*name, c.Address, c.Peers); err != nil {
		return err
	}
	stablePort := port
	var routed *routeController
	var directTunnel linkAddr
	if c.DirectInterface != "" {
		if *dry {
			return errors.New("route-based peering does not support dry-run; use the LAN-only dry-run without direct_interface")
		}
		if c.DirectInterface == "auto" {
			owned, e := ensureDirectInterface(client, *name, journalPath+".interface", c.Port, c.DirectListenPort)
			if e != nil {
				return e
			}
			// Added before the route controller's defer: restore its routes and
			// peers first, then delete only the interface that we created.
			defer func() { err = errors.Join(err, owned.Close()) }()
			c.DirectInterface = owned.Name
		}
		routed, err = newRouteController(client, *name, c.DirectInterface, journalPath+".routes", c.Address, c.RouteMetric)
		if err != nil {
			return err
		}
		defer func() { err = errors.Join(err, routed.RestoreAll()) }()
		private, port = routed.Identity()
		if uint16(port) == c.Port {
			return errors.New("direct WireGuard listen port must differ from the discovery port")
		}
		iface, e := net.InterfaceByName(c.DirectInterface)
		if e != nil {
			return e
		}
		if iface.Flags&net.FlagUp == 0 {
			return errors.New("direct WireGuard interface must already be up")
		}
		directTunnel = linkAddr{Index: iface.Index, Name: iface.Name, Prefix: netip.PrefixFrom(c.Address, c.Address.BitLen())}
		if err := checkRouteModeRuntime(*name, c, tunnel, stablePort, checkDevice, routed); err != nil {
			return err
		}
		control = routed
	}
	n, err := openNetwork(int(c.Port), c.Include, c.Exclude, c.groups(), *name)
	if err != nil {
		return err
	}
	defer n.Close()
	m := newMesh(c, n, control, private, uint16(port), tunnel, *dry)
	m.directTunnel = directTunnel
	if c.NAT != nil {
		raw, e := openWireGuardUDP(uint16(port))
		if e != nil {
			return e
		}
		defer raw.Close()
		m.enableNAT(raw)
		defer func() { err = errors.Join(err, m.closeNAT()) }()
	}
	m.notify = func() { notify("WATCHDOG=1") }
	m.verify = func() error {
		if routed != nil {
			return checkRouteModeRuntime(*name, c, tunnel, stablePort, checkDevice, routed)
		}
		return checkRuntime(*name, c, tunnel, stablePort, checkDevice)
	}
	// The runtime check includes controller validation and the listen port from
	// one device read. Mutation preflight calls verify again, not a cached result.
	m.inspect = m.verify
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	notify("READY=1")
	defer notify("STOPPING=1")
	slog.Info("discovery started", "wireguard", *name, "multicast4", c.Multicast4, "multicast6", c.Multicast6, "port", c.Port, "dry_run", *dry)
	return m.run(ctx)
}

func checkRuntime(name string, c config, tunnel linkAddr, port int, device func() (*wgtypes.Device, error)) error {
	current, err := tunnelLink(name, c.Address)
	if err != nil {
		return err
	}
	if current.Index != tunnel.Index {
		return errors.New("WireGuard interface was replaced")
	}
	d, err := device()
	if err != nil {
		return err
	}
	if d.ListenPort != port {
		return errors.New("WireGuard listen port changed")
	}
	return checkLinkRoutes(current.Index, c.Address, c.Peers)
}

func checkPeers(d *wgtypes.Device, peers []peerSpec) error {
	if d.Type != wgtypes.LinuxKernel {
		return errors.New("this version requires a Linux kernel WireGuard interface")
	}
	for _, p := range peers {
		if controlFindPeer(d, p.key) != nil {
			return fmt.Errorf("peer %s already exists in WireGuard; this version requires hub-only stable routing", p.IP)
		}
		owner, _, err := controlOwner(d, p.IP, wgtypes.Key{})
		if err != nil {
			return err
		}
		if owner == (wgtypes.Key{}) || owner == d.PublicKey {
			return fmt.Errorf("peer %s has no stable WireGuard route", p.IP)
		}
	}
	return nil
}

// Resolve systemd's StateDirectory symlink, then require a private owned target.
func lockJournal(path string) (string, func(), error) {
	dir := filepath.Dir(path)
	if err := os.Mkdir(dir, 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return "", nil, err
	}
	dir, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return "", nil, err
	}
	if err := controlCheckDir(dir); err != nil {
		return "", nil, err
	}
	path = filepath.Join(dir, filepath.Base(path))
	f, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0600)
	if err != nil {
		return "", nil, err
	}
	info, err := f.Stat()
	if err == nil && (!info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Sys().(*syscall.Stat_t).Uid != uint32(os.Geteuid())) {
		err = errors.New("unsafe journal lock file")
	}
	if err == nil {
		err = unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
	}
	if err != nil {
		f.Close()
		return "", nil, fmt.Errorf("lock recovery journal: %w", err)
	}
	return path, func() { _ = f.Close() }, nil
}

func notify(message string) {
	path := os.Getenv("NOTIFY_SOCKET")
	if path == "" {
		return
	}
	c, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: path, Net: "unixgram"})
	if err == nil {
		defer c.Close()
		_ = c.SetWriteDeadline(time.Now().Add(time.Second))
		_, _ = c.Write([]byte(message))
	}
}

type readOnlyControl struct {
	client wgClient
	name   string
	public wgtypes.Key
}

func (c *readOnlyControl) Check() error {
	_, err := c.checkDevice()
	return err
}

func (c *readOnlyControl) checkDevice() (*wgtypes.Device, error) {
	d, err := c.client.Device(c.name)
	if err == nil && d.PublicKey != c.public {
		return nil, errors.New("WireGuard identity changed")
	}
	return d, err
}
func (*readOnlyControl) Apply(wgtypes.Key, netip.Addr, wgtypes.Key, netip.AddrPort) error {
	return errors.New("dry run cannot apply routes")
}
func (*readOnlyControl) Restore(wgtypes.Key) error {
	return errors.New("dry run cannot restore routes")
}
