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
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
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
	var private wgtypes.Key
	var port int
	if *dry {
		if _, e := os.Stat(*state); e == nil {
			return errors.New("recover and remove the old journal before a dry run")
		} else if !errors.Is(e, os.ErrNotExist) {
			return e
		}
		d, e := client.Device(*name)
		if e != nil {
			return e
		}
		private, port = d.PrivateKey, d.ListenPort
		control = &readOnlyControl{client, *name, d.PublicKey}
	} else {
		resolved, unlock, e := lockJournal(*state)
		if e != nil {
			return e
		}
		defer unlock()
		c, e := newController(client, *name, resolved)
		if e != nil {
			return e
		}
		defer func() { err = errors.Join(err, c.RestoreAll()) }()
		if *restore {
			return nil
		}
		control = c
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
	n, err := openNetwork(int(c.Port), c.Include, c.Exclude, c.groups(), *name)
	if err != nil {
		return err
	}
	defer n.Close()
	m := newMesh(c, n, control, private, uint16(port), tunnel, *dry)
	m.notify = func() { notify("WATCHDOG=1") }
	m.verify = func() error {
		current, err := tunnelLink(*name, c.Address)
		if err != nil {
			return err
		}
		if current.Index != tunnel.Index {
			return errors.New("WireGuard interface was replaced")
		}
		d, err := client.Device(*name)
		if err != nil {
			return err
		}
		if d.ListenPort != port {
			return errors.New("WireGuard listen port changed")
		}
		return checkRoutes(*name, c.Address, c.Peers)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	notify("READY=1")
	defer notify("STOPPING=1")
	slog.Info("discovery started", "wireguard", *name, "multicast4", c.Multicast4, "multicast6", c.Multicast6, "port", c.Port, "dry_run", *dry)
	return m.run(ctx)
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
	d, err := c.client.Device(c.name)
	if err == nil && d.PublicKey != c.public {
		return errors.New("WireGuard identity changed")
	}
	return err
}
func (*readOnlyControl) Apply(wgtypes.Key, netip.Addr, wgtypes.Key, netip.AddrPort) error {
	return errors.New("dry run cannot apply routes")
}
func (*readOnlyControl) Restore(wgtypes.Key) error {
	return errors.New("dry run cannot restore routes")
}
