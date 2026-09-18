package main

import (
	"errors"
	"io"
	"log/slog"
	"os"
	"slices"
	"strings"
	"syscall"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

var errPSKFile = errors.New("PSK file is missing, unsafe, changing, invalid, or stale")

// The configured directory must be trusted. Reject a symlink at the file itself
// and use nonblocking open so a FIFO cannot stop the mesh event loop.
func readPSKFile(spec peerSpec, now time.Time) (wgtypes.Key, error) {
	before, err := os.Lstat(spec.PresharedKeyFile)
	if err != nil || !before.Mode().IsRegular() {
		return wgtypes.Key{}, errPSKFile
	}
	f, err := os.OpenFile(spec.PresharedKeyFile, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return wgtypes.Key{}, errPSKFile
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !os.SameFile(before, info) || !info.Mode().IsRegular() || info.Mode().Perm() & ^os.FileMode(0640) != 0 ||
		info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 || info.Size() < 44 || info.Size() > 45 {
		return wgtypes.Key{}, errPSKFile
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return wgtypes.Key{}, errPSKFile
	}
	// A producer with another UID is trusted only through a daemon group and a
	// group-readable file. Group write and all access by others are forbidden.
	if stat.Uid != 0 && stat.Uid != uint32(os.Geteuid()) {
		groups, err := os.Getgroups()
		if err != nil || info.Mode().Perm()&0040 == 0 || (stat.Gid != uint32(os.Getegid()) && !slices.Contains(groups, int(stat.Gid))) {
			return wgtypes.Key{}, errPSKFile
		}
	}
	maxAge := 3 * time.Minute
	if spec.PresharedKeyMaxAge != nil {
		maxAge = time.Duration(*spec.PresharedKeyMaxAge)
	}
	if now.Before(info.ModTime()) || now.Sub(info.ModTime()) >= maxAge {
		return wgtypes.Key{}, errPSKFile
	}
	data, err := io.ReadAll(io.LimitReader(f, 46))
	if err != nil || len(data) != int(info.Size()) {
		return wgtypes.Key{}, errPSKFile
	}
	// Rosenpass rewrites key_out in place. Reject an observed concurrent rewrite
	// instead of retaining a key from a partial read.
	after, err := f.Stat()
	if err != nil || after.Size() != info.Size() || after.Mode() != info.Mode() || !after.ModTime().Equal(info.ModTime()) {
		return wgtypes.Key{}, errPSKFile
	}
	if final, ok := after.Sys().(*syscall.Stat_t); !ok || final.Uid != stat.Uid || final.Gid != stat.Gid {
		return wgtypes.Key{}, errPSKFile
	}
	text := strings.TrimSuffix(string(data), "\n")
	key, err := wgtypes.ParseKey(text)
	if err != nil || key == (wgtypes.Key{}) || key.String() != text {
		return wgtypes.Key{}, errPSKFile
	}
	return key, nil
}

// A fresh file does not prove a fresh Rosenpass exchange: Rosenpass can write a
// random key on expiry. Only the existing direct tunnel trial proves usability.
func (m *mesh) pollPSK(p *meshPeer, now time.Time) (bool, error) {
	if p.spec.PresharedKeyFile == "" {
		return true, nil
	}
	key, err := readPSKFile(p.spec, now)
	valid := err == nil
	if !valid && !now.Before(p.pskLogAfter) {
		slog.Warn("direct path disabled: PSK file unavailable", "peer", p.spec.IP)
		p.pskLogAfter = now.Add(time.Minute)
	}
	if valid && p.pskValid && key == p.spec.psk {
		return true, nil
	}
	if p.selected != nil || p.phase != "" {
		// Keep the old key and controller journal until restoration succeeds.
		if err := m.restore(p, now, "PSK file changed or unavailable"); err != nil {
			return false, err
		}
	}
	p.spec.psk, p.pskValid = key, valid
	return valid, nil
}
