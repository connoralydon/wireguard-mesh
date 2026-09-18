package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type rosenpassConfig struct {
	Executable        string  `json:"executable"`
	Peer              string  `json:"peer"`
	PublicKeyFile     string  `json:"public_key_file"`
	SecretKeyFile     string  `json:"secret_key_file"`
	PeerPublicKeyFile string  `json:"peer_public_key_file"`
	ListenPort        uint16  `json:"listen_port"`
	RemotePort        uint16  `json:"remote_port"`
	PSKFile           string  `json:"psk_file"`
	RuntimeDir        string  `json:"runtime_dir"`
	Socket            string  `json:"socket"`
	DaemonUID         *uint32 `json:"daemon_uid"` // Required; UID 0 is permitted for the mesh daemon.
}

func readRosenpassConfig(r io.Reader) (rosenpassConfig, error) {
	var c rosenpassConfig
	data, err := io.ReadAll(io.LimitReader(r, 16385))
	if err != nil || len(data) > 16384 {
		return c, errors.New("Rosenpass configuration exceeds 16 KiB or is unreadable")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if d.Decode(&c) != nil || d.Decode(new(any)) != io.EOF {
		return c, errors.New("invalid Rosenpass configuration JSON")
	}
	key, err := wgtypes.ParseKey(c.Peer)
	if err != nil || key == (wgtypes.Key{}) || key.String() != c.Peer ||
		c.ListenPort < 1024 || c.RemotePort < 1024 || c.DaemonUID == nil {
		return c, errors.New("set a fixed WireGuard peer, unprivileged ports, and daemon_uid")
	}
	paths := []string{c.Executable, c.PublicKeyFile, c.SecretKeyFile, c.PeerPublicKeyFile, c.PSKFile, c.RuntimeDir, c.Socket}
	for i, path := range paths {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path || strings.ContainsAny(path, "\x00\r\n") ||
			slices.Contains(paths[:i], path) || path == filepath.Join(c.RuntimeDir, "adapter.lock") {
			return c, errors.New("Rosenpass paths must be distinct, clean, and absolute")
		}
	}
	return c, nil
}

type rosenpassChild struct {
	generation uint64
	dir, raw   string
	done       chan struct{}
	kill       func() error
	stopEvent  string
}

type rosenpassAdapter struct {
	mu         sync.Mutex
	config     rosenpassConfig
	status     rosenpassResponse
	endpoint   rosenpassRequest
	child      *rosenpassChild
	err        error
	lastHash   [32]byte
	retryAfter time.Time
	start      func(rosenpassRequest, uint64) (*rosenpassChild, error)
	validate   func(rosenpassRequest) (rosenpassRequest, error)
}

func runRosenpassAdapter(ctx context.Context, configPath string) error {
	if os.Geteuid() == 0 || os.Getuid() == 0 {
		return errors.New("Rosenpass adapter must not run as root")
	}
	f, err := os.Open(configPath)
	if err != nil {
		return err
	}
	c, err := readRosenpassConfig(f)
	f.Close()
	if err != nil {
		return err
	}
	return serveRosenpassAdapter(ctx, c)
}

// Configured directories must already exist. Use a dedicated producer UID and
// a daemon-readable group, not the hub's Rosenpass keys, ports, or directories.
func serveRosenpassAdapter(ctx context.Context, c rosenpassConfig) (result error) {
	for _, dir := range []string{c.RuntimeDir, filepath.Dir(c.Socket), filepath.Dir(c.PSKFile)} {
		if err := rosenpassTrustedDir(dir, dir == c.RuntimeDir); err != nil {
			return err
		}
	}
	lock, err := os.OpenFile(filepath.Join(c.RuntimeDir, "adapter.lock"), os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0600)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return errors.New("Rosenpass adapter runtime is already in use")
	}
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		return err
	}
	a := &rosenpassAdapter{config: c, status: rosenpassResponse{Instance: hex.EncodeToString(id)}, validate: validateRosenpassRequest}
	a.start = a.startProcess
	if err := a.invalidate(); err != nil {
		return err
	}
	defer func() {
		a.mu.Lock()
		result = errors.Join(result, a.stop(), a.err)
		a.mu.Unlock()
	}()
	if info, err := os.Lstat(c.Socket); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return errors.New("Rosenpass socket path is not a socket")
		}
		if err := os.Remove(c.Socket); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: c.Socket, Net: "unix"})
	if err != nil {
		return err
	}
	defer listener.Close()
	if err := os.Chmod(c.Socket, 0660); err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stopClose := context.AfterFunc(ctx, func() { listener.Close() })
	defer stopClose()
	var workers sync.WaitGroup
	defer workers.Wait()
	workers.Go(func() {
		ticker := time.NewTicker(250 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-ticker.C:
				a.mu.Lock()
				err := a.refresh(now)
				a.mu.Unlock()
				if err != nil {
					cancel()
					return
				}
			}
		}
	})
	// Bound concurrent clients as well as bytes and time per connection.
	slots := make(chan struct{}, 8)
	for {
		conn, err := listener.AcceptUnix()
		if err != nil {
			cancel()
			if ctx.Err() != nil && errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		select {
		case slots <- struct{}{}:
			workers.Go(func() {
				defer func() { <-slots }()
				a.handleConnection(conn)
			})
		default:
			conn.Close()
		}
	}
}

func rosenpassTrustedDir(path string, private bool) error {
	for current := path; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil {
			return errors.New("Rosenpass directory is missing or unsafe")
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return errors.New("Rosenpass directory ownership is unavailable")
		}
		if !info.IsDir() || (stat.Uid != 0 && stat.Uid != uint32(os.Geteuid())) ||
			(info.Mode().Perm()&0022 != 0 && !(current != path && info.Mode()&os.ModeSticky != 0)) ||
			(current == path && (stat.Uid != uint32(os.Geteuid()) || (private && info.Mode().Perm()&0077 != 0))) {
			return fmt.Errorf("Rosenpass directory %q must have a trusted owner and protected write permissions (owner %d, user %d, mode %s)", current, stat.Uid, os.Geteuid(), info.Mode())
		}
		if current == "/" {
			return nil
		}
	}
}

func rosenpassAuthorized(conn *net.UnixConn, uid uint32) bool {
	raw, err := conn.SyscallConn()
	if err != nil {
		return false
	}
	var credentials *unix.Ucred
	if raw.Control(func(fd uintptr) { credentials, err = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) }) != nil {
		return false
	}
	return err == nil && credentials != nil && credentials.Uid == uid
}

func (a *rosenpassAdapter) handleConnection(conn *net.UnixConn) {
	defer conn.Close()
	if conn.SetDeadline(time.Now().Add(rosenpassTimeout)) != nil || !rosenpassAuthorized(conn, *a.config.DaemonUID) {
		return
	}
	var request rosenpassRequest
	if readRosenpassJSON(conn, &request) != nil {
		return
	}
	response, err := a.request(request, time.Now())
	if err == nil {
		_ = json.NewEncoder(conn).Encode(response)
	}
}

func validateRosenpassRequest(r rosenpassRequest) (rosenpassRequest, error) {
	iface, err := net.InterfaceByIndex(r.Link.Index)
	if err != nil {
		return r, errors.New("Rosenpass interface is unavailable")
	}
	prefixes, err := interfacePrefixes(*iface)
	if err != nil {
		return r, errors.New("Rosenpass interface addresses are unavailable")
	}
	return rosenpassOnLink(r, *iface, prefixes)
}

func rosenpassOnLink(r rosenpassRequest, iface net.Interface, prefixes []netip.Prefix) (rosenpassRequest, error) {
	p, remote := r.Link.Prefix, r.Address.WithZone("")
	zone := strconv.Itoa(iface.Index)
	if iface.Index <= 0 || r.Link.Index != iface.Index || r.Link.Name != iface.Name ||
		iface.Flags&net.FlagUp == 0 || iface.Flags&(net.FlagLoopback|net.FlagPointToPoint) != 0 ||
		!p.IsValid() || p.Bits() == 0 || !slices.Contains(prefixes, p) ||
		!usableLinkAddress(p.Addr()) || p.Addr().IsLoopback() || !usableLinkAddress(remote) || remote.IsLoopback() ||
		!p.Contains(remote) || remote == p.Addr() || remote == broadcastAddress(p) ||
		(p.Addr().Is4() && p.Bits() <= 30 && remote == p.Masked().Addr()) ||
		(r.Address.Zone() != "" && (remote.Is4() || (r.Address.Zone() != iface.Name && r.Address.Zone() != zone))) {
		return r, errors.New("Rosenpass endpoint must use an assigned interface address and an on-link unicast peer")
	}
	if remote.Is6() && remote.IsLinkLocalUnicast() {
		remote = remote.WithZone(zone)
	}
	r.Address = remote
	r.Link = linkAddr{Index: iface.Index, Name: iface.Name, Prefix: p}
	return r, nil
}

func (a *rosenpassAdapter) request(r rosenpassRequest, now time.Time) (rosenpassResponse, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if r.Peer != a.config.Peer {
		return rosenpassResponse{}, errors.New("unknown Rosenpass WireGuard peer")
	}
	if !r.Address.IsValid() {
		a.endpoint = rosenpassRequest{}
		err := a.stop()
		return a.status, err
	}
	var err error
	r, err = a.validate(r)
	if err != nil {
		return rosenpassResponse{}, errors.Join(err, a.stop())
	}
	if err := a.refresh(now); err != nil {
		return rosenpassResponse{}, err
	}
	if r != a.endpoint {
		if err := a.stop(); err != nil {
			return rosenpassResponse{}, err
		}
		a.endpoint, a.retryAfter = r, time.Time{}
	}
	if a.child == nil && !now.Before(a.retryAfter) {
		a.status.Generation++
		a.lastHash = [32]byte{}
		a.retryAfter = now.Add(time.Second)
		a.child, err = a.start(r, a.status.Generation)
		if err != nil {
			return rosenpassResponse{}, errors.New("cannot start Rosenpass child")
		}
	}
	return a.status, nil
}

func (a *rosenpassAdapter) invalidate() error {
	a.status.Valid, a.status.Hash, a.status.Expires = false, [32]byte{}, time.Time{}
	if err := os.Remove(a.config.PSKFile); err != nil && !errors.Is(err, os.ErrNotExist) {
		a.err = errors.New("cannot invalidate Rosenpass output")
	}
	return a.err
}

func (a *rosenpassAdapter) stop() error {
	a.invalidate() // Never leave published output while stopping or replacing a child.
	child := a.child
	a.child = nil
	if child != nil {
		_ = child.kill()
		select {
		case <-child.done:
			if err := os.RemoveAll(child.dir); err != nil {
				a.err = errors.New("cannot remove Rosenpass child files")
			}
		case <-time.After(time.Second):
			a.err = errors.New("Rosenpass child did not stop; refusing to start another")
		}
	}
	return a.err
}

func (a *rosenpassAdapter) refresh(now time.Time) error {
	if a.child != nil {
		select {
		case <-a.child.done:
			return a.stop()
		default:
		}
	}
	if a.status.Valid && (a.child == nil || !now.Before(a.status.Expires)) {
		return a.invalidate()
	}
	return a.err
}

// Verified against v0.2.3 rosenpass/src/{cli,config,app_server}.rs:
// https://github.com/rosenpass/rosenpass/tree/v0.2.3/rosenpass/src
// One peer only; no WireGuard output, commands, or hub configuration is passed.
func (a *rosenpassAdapter) startProcess(r rosenpassRequest, generation uint64) (*rosenpassChild, error) {
	dir, err := os.MkdirTemp(a.config.RuntimeDir, "child-")
	if err != nil {
		return nil, err
	}
	c := &rosenpassChild{generation: generation, dir: dir, raw: filepath.Join(dir, "psk.raw"), done: make(chan struct{})}
	// v0.2.3 truncates in place and otherwise creates with the inherited umask.
	if err := os.WriteFile(c.raw, nil, 0600); err != nil {
		os.RemoveAll(dir)
		return nil, err
	}
	local := r.Link.Prefix.Addr()
	if local.Is6() && local.IsLinkLocalUnicast() {
		local = local.WithZone(strconv.Itoa(r.Link.Index))
	}
	cmd := exec.Command(a.config.Executable, "exchange", "public-key", a.config.PublicKeyFile,
		"secret-key", a.config.SecretKeyFile, "listen", netip.AddrPortFrom(local, a.config.ListenPort).String(),
		"peer", "public-key", a.config.PeerPublicKeyFile, "endpoint", netip.AddrPortFrom(r.Address, a.config.RemotePort).String(),
		"outfile", "psk.raw")
	cmd.Dir = dir
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	// Wait must not close the reader while the scanner is using it.
	stdout, writer, err := os.Pipe()
	if err == nil {
		cmd.Stdout = writer
		err = cmd.Start()
		writer.Close()
	}
	if err != nil {
		if stdout != nil {
			stdout.Close()
		}
		os.RemoveAll(dir)
		return nil, err
	}
	c.kill = func() error {
		err := cmd.Process.Kill()
		stdout.Close() // Explicit shutdown also releases a blocked scanner.
		return err
	}
	go func() {
		_ = cmd.Wait()
		close(c.done)
		a.mu.Lock()
		if a.child == c {
			a.stop()
		}
		a.mu.Unlock()
	}()
	go func() {
		defer stdout.Close()
		// Do not log stdout, stderr, parse errors, or key material.
		scanner := bufio.NewScanner(stdout)
		scanner.Buffer(make([]byte, 512), 1024)
		for scanner.Scan() {
			at := time.Now()
			event := parseRosenpassEvent(scanner.Text())
			a.mu.Lock()
			a.event(c, event, at)
			a.mu.Unlock()
		}
		// Lost or oversized stdout means exchange state is no longer reliable.
		a.mu.Lock()
		if a.child == c {
			a.stop()
		}
		a.mu.Unlock()
	}()
	return c, nil
}

func parseRosenpassEvent(line string) string {
	const prefix = "output-key peer "
	if !strings.HasPrefix(strings.TrimSpace(line), "output-key") {
		return ""
	}
	if !strings.HasPrefix(line, prefix) || len(line) < len(prefix)+44 {
		return "invalid"
	}
	id := line[len(prefix) : len(prefix)+44]
	decoded, err := base64.StdEncoding.Strict().DecodeString(id)
	if err != nil || len(decoded) != 32 {
		return "invalid"
	}
	// The relative path is adapter-generated ASCII, so Rust debug quoting is
	// exact. The peer ID is not a WG key; the child has only the pinned RP peer.
	switch line[len(prefix)+44:] {
	case ` key-file "psk.raw" exchanged`:
		return "exchanged"
	case ` key-file "psk.raw" stale`:
		return "stale"
	}
	return "invalid"
}

func (a *rosenpassAdapter) event(c *rosenpassChild, event string, at time.Time) {
	if a.child != c || c.generation != a.status.Generation || a.refresh(at) != nil || a.child != c {
		return
	}
	if event == "invalid" || event == "stale" {
		// Raw output can already contain a later exchange. Discard this
		// process and its queued events instead of reading it on stale.
		c.stopEvent = event
		a.stop()
		return
	}
	if event != "exchanged" {
		return
	}
	key, err := readPSKFile(peerSpec{PresharedKeyFile: c.raw}, at)
	if err != nil {
		a.invalidate()
		return
	}
	hash := sha256.Sum256(key[:])
	if hash == a.lastHash {
		return // A duplicate cannot republish, renew, or revive invalid output.
	}
	expires := at.Add(rosenpassLifetime)
	// A delayed stdout event must not give an old raw file a new lifetime.
	info, err := os.Lstat(c.raw)
	if err != nil {
		a.invalidate()
		return
	}
	if bound := info.ModTime().Add(rosenpassLifetime); bound.Before(expires) {
		expires = at.Add(bound.Sub(at)) // Retain the event's monotonic clock.
	}
	if !at.Before(expires) {
		a.invalidate()
		return
	}
	if err := publishRosenpassPSK(a.config.PSKFile, key); err != nil {
		a.invalidate()
		return
	}
	a.lastHash = hash
	a.status.KeyGeneration++
	a.status.Hash, a.status.Expires, a.status.Valid = hash, expires, true
}

func publishRosenpassPSK(path string, key wgtypes.Key) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".rosenpass-psk-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if err := f.Chmod(0640); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(f, key.String()); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}
