package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
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

// Proofs bind possession to one operation, transaction, and direction. Neither
// the PSK nor a reusable unkeyed fingerprint is sent over discovery.
func pskProof(key wgtypes.Key, op, token string, sender, receiver wgtypes.Key) string {
	if key == (wgtypes.Key{}) {
		return ""
	}
	mac := hmac.New(sha256.New, key[:])
	mac.Write([]byte("wireguard-mesh PSK confirmation v1\x00" + op + "\x00" + token + "\x00"))
	mac.Write(sender[:])
	mac.Write(receiver[:])
	return hex.EncodeToString(mac.Sum(nil))
}

func checkPSKProof(key wgtypes.Key, msg message, sender, receiver wgtypes.Key) bool {
	return hmac.Equal([]byte(msg.Proof), []byte(pskProof(key, msg.Op, msg.Token, sender, receiver)))
}

// Reporting a confirmed LAN path must not depend on having a PSK: Rosenpass
// needs this address to obtain the first key. Retain a healthy endpoint to avoid
// restarting exchanges merely because map iteration or RTT measurements change.
func (m *mesh) readPeerPSK(p *meshPeer, now time.Time) (wgtypes.Key, rosenpassResponse, error) {
	started := time.Now()
	if p.spec.RosenpassSocket == "" {
		key, err := readPSKFile(p.spec, now)
		return key, rosenpassResponse{}, err
	}
	if m.dry {
		return wgtypes.Key{}, rosenpassResponse{}, errPSKFile
	}
	fresh := func(c *path) bool { return c != nil && slices.Contains(m.links, c.link) && m.fresh(c, now) }
	c := p.rosenpassPath
	known := c != nil
	leader := bytes.Compare(m.public[:], p.spec.key[:]) < 0
	if !fresh(c) {
		c = nil
		if leader {
			for _, candidate := range p.paths {
				if fresh(candidate) && (c == nil || pathName(candidate.link, candidate.addr) < pathName(c.link, c.addr)) {
					c = candidate
				}
			}
			p.rosenpassToken = rand.Text()
		}
	}
	p.rosenpassPath = c
	if c == nil && !known {
		// At startup there is no endpoint decision yet. Do not destroy a live
		// adapter's existing exchange before discovery can confirm its LAN.
		return wgtypes.Key{}, rosenpassResponse{}, errPSKFile
	}
	request := rosenpassRequest{Peer: p.spec.key.String()}
	if c != nil {
		request.Address, request.Link = c.addr.Addr(), c.link
		if leader {
			// The follower uses the receiving interface for this authenticated
			// message. Local interface ordering need not agree between nodes.
			m.send(c.session, message{Op: "rosenpass-select", Token: p.rosenpassToken, Port: m.wgPort}, c.addr, c.link, now)
		}
	}
	before, err := m.rosenpass(p.spec.RosenpassSocket, request)
	if err != nil || !before.Valid || !now.Add(time.Since(started)).Before(before.Expires) {
		return wgtypes.Key{}, rosenpassResponse{}, errPSKFile
	}
	key, err := readPSKFile(p.spec, now.Add(time.Since(started)))
	if err != nil || sha256.Sum256(key[:]) != before.Hash {
		return wgtypes.Key{}, rosenpassResponse{}, errPSKFile
	}
	after, err := m.rosenpass(p.spec.RosenpassSocket, request)
	if err != nil || !after.Valid || before != after || !now.Add(time.Since(started)).Before(after.Expires) {
		return wgtypes.Key{}, rosenpassResponse{}, errPSKFile
	}
	return key, after, nil
}

func (m *mesh) pollPSK(p *meshPeer, now time.Time) (bool, error) {
	started := time.Now()
	if p.spec.PresharedKeyFile == "" {
		return true, nil
	}
	key, status, err := m.readPeerPSK(p, now)
	now = now.Add(time.Since(started))
	valid := err == nil
	if !valid && !now.Before(p.pskLogAfter) {
		slog.Warn("direct path disabled: PSK file unavailable", "peer", p.spec.IP)
		p.pskLogAfter = now.Add(time.Minute)
	}
	restarted := p.pskStatus.Valid && (status.Instance != p.pskStatus.Instance || status.Generation != p.pskStatus.Generation)
	if valid && !restarted && p.pskValid && key == p.spec.psk && (p.rekey == nil || key == p.rekey.key) {
		p.pskStatus = status
		return true, nil
	}
	if p.previous != nil {
		m.retire(p, p.previous.trial, now)
		p.previous = nil // A fallback must not cross a key transition.
	}
	if valid && !restarted && p.pskValid && p.phase == "active" && p.spec.ExperimentalRekey && p.remoteRekey {
		if p.rekey == nil {
			m.cancelReplacement(p, now)
			phase := "waiting"
			if bytes.Compare(m.public[:], p.spec.key[:]) < 0 {
				phase = "offer"
			}
			p.rekey = &pskTransition{key: key, phase: phase, token: rand.Text(), since: now}
		}
		if key == p.rekey.key {
			p.pskStatus = status
			return true, nil
		}
	}
	if p.selected != nil || p.phase != "" {
		// Keep the old key and controller journal until restoration succeeds.
		if err := m.restore(p, now, "PSK file changed or unavailable"); err != nil {
			return false, err
		}
	}
	p.spec.psk, p.pskValid, p.pskStatus = key, valid, status
	return valid, nil
}

type rekeyControl interface {
	Rekey(key, oldPSK, newPSK wgtypes.Key) error
	Handshake(key wgtypes.Key) (time.Time, error)
}

type pskTransition struct {
	key                                     wgtypes.Key
	phase, token                            string
	since, appliedAt, handshake, finishedAt time.Time
	remoteApplied                           bool
	remoteObserved                          time.Time
}

func (m *mesh) rekeyCommand(p *meshPeer, r *pskTransition, op string, now time.Time) {
	c := p.selected
	msg := message{Op: op, Token: r.token, Port: m.wgPort}
	msg.Proof = pskProof(r.key, op, r.token, m.public, p.spec.key)
	m.send(c.session, msg, c.addr, c.link, now)
}

func (m *mesh) coordinateRekey(p *meshPeer, c *path, msg message, now time.Time) error {
	if !p.spec.ExperimentalRekey || !p.remoteRekey || p.phase != "active" || p.selected != c {
		return nil
	}
	if ok, err := m.pollPSK(p, now); err != nil || !ok {
		return err
	}
	r := p.rekey
	if r == nil && p.completedRekey != nil {
		done := p.completedRekey
		if now.Sub(done.finishedAt) < 90*time.Second && msg.Op == "rekey-observed" && msg.Token == done.token && checkPSKProof(done.key, msg, p.spec.key, m.public) {
			m.rekeyCommand(p, done, "rekey-finished", now)
		}
		return nil
	}
	if r == nil || !checkPSKProof(r.key, msg, p.spec.key, m.public) {
		return nil
	}
	if r.phase != "observing" && now.Sub(r.since) >= time.Duration(m.c.Failure) {
		return m.restore(p, now, "PSK confirmation timeout")
	}
	leader := bytes.Compare(m.public[:], p.spec.key[:]) < 0
	if msg.Op == "rekey-offer" && !leader && r.phase == "waiting" {
		r.phase, r.token = "prepared", msg.Token
	}
	if msg.Token != r.token {
		return nil
	}
	switch msg.Op {
	case "rekey-offer":
		if !leader && r.phase == "prepared" {
			m.rekeyCommand(p, r, "rekey-ready", now)
		}
	case "rekey-ready":
		if leader && r.phase == "offer" {
			m.rekeyCommand(p, r, "rekey-commit", now)
			return m.applyRekey(p, now)
		}
	case "rekey-commit":
		if !leader && r.phase == "prepared" {
			if err := m.applyRekey(p, now); err != nil || p.rekey == nil {
				return err
			}
		}
		if !leader && r.phase == "observing" {
			r.remoteApplied = true
			m.rekeyCommand(p, r, "rekey-applied", now)
		}
	case "rekey-applied":
		if r.phase == "observing" {
			r.remoteApplied = true
		}
	case "rekey-observed", "rekey-finished":
		if r.phase == "observing" {
			r.remoteApplied, r.remoteObserved = true, now
		}
	}
	return nil
}

func (m *mesh) applyRekey(p *meshPeer, now time.Time) error {
	started := time.Now()
	if m.verify != nil {
		if err := m.verify(); err != nil {
			return err
		}
	}
	if ok, err := m.pollPSK(p, now.Add(time.Since(started))); err != nil || !ok || p.rekey == nil {
		return err
	}
	control, ok := m.control.(rekeyControl)
	if !ok {
		return m.restore(p, now, "in-place rekey unavailable")
	}
	r := p.rekey
	handshake, err := control.Handshake(p.spec.key)
	if err == nil {
		err = control.Rekey(p.spec.key, p.spec.psk, r.key)
	}
	if err != nil {
		// Restore accepts either journaled hash, but not an unrelated third key.
		return m.restore(p, now, "PSK-only update failed")
	}
	p.spec.psk = r.key
	r.phase, r.appliedAt, r.handshake = "observing", now.Add(time.Since(started)), handshake
	slog.Warn("experimental PSK-only update applied; handshake generation unverified", "peer", p.spec.IP)
	return nil
}

func (m *mesh) advanceRekey(p *meshPeer, now time.Time) error {
	r := p.rekey
	if r.phase != "observing" {
		if now.Sub(r.since) >= time.Duration(m.c.Failure) {
			return m.restore(p, now, "PSK confirmation timeout")
		}
		switch r.phase {
		case "offer":
			m.rekeyCommand(p, r, "rekey-offer", now)
		case "prepared":
			m.rekeyCommand(p, r, "rekey-ready", now)
		}
		return nil
	}
	if now.Sub(r.appliedAt) >= 90*time.Second || now.Sub(p.lastTunnel) >= time.Duration(m.c.Failure) {
		return m.restore(p, now, "PSK handshake observation timeout")
	}
	if !r.remoteApplied && bytes.Compare(m.public[:], p.spec.key[:]) < 0 {
		m.rekeyCommand(p, r, "rekey-commit", now)
	}
	control := m.control.(rekeyControl) // applyRekey checked this before changing the key.
	handshake, err := control.Handshake(p.spec.key)
	if err != nil {
		return err
	}
	// This is an observation, NOT proof of the PSK generation. An old pending
	// keypair can update this timestamp. See the opt-in Linux kernel prototype.
	if handshake.After(r.handshake) && handshake.After(r.appliedAt) && !handshake.After(now) {
		m.rekeyCommand(p, r, "rekey-observed", now)
		if !r.remoteObserved.IsZero() && now.Sub(r.remoteObserved) < time.Duration(m.c.Failure) {
			p.rekey = nil
			r.finishedAt, p.completedRekey = now, r
			// Completion retries use this same path until the remote deadline.
			if until := now.Add(90 * time.Second); until.After(p.cooldown) {
				p.cooldown = until
			}
			p.remoteAt = now
			slog.Warn("experimental PSK update observed at both peers; not cryptographic handshake proof", "peer", p.spec.IP)
		}
	}
	return nil
}
