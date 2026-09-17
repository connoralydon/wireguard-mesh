package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"time"

	"github.com/flynn/noise"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const (
	secureDomain  = "wireguard-mesh/v1"
	secureHeaderN = 90 // version, type, sender[32], recipient[32], ID[16], counter[8]
	secureMaxSize = 1200
	secureRequest = 1
	secureReply   = 2
	secureData    = 3
)

var errSecure = errors.New("secure: invalid, expired, replayed, or limited packet/session")

// secure belongs to one event loop. Addresses and fresh ping/pong checks belong
// to the engine; Ready does not authorize a peer, endpoint, or route change.
type secure struct {
	private, public wgtypes.Key
	peers           map[wgtypes.Key]*secureRate
	sessions        map[[16]byte]*secureSession
	global          secureRate
	random          io.Reader
	ids             cipher.Block
	serial          uint64
}

type secureEvent struct {
	Peer  wgtypes.Key
	ID    [16]byte
	Body  []byte
	Reply []byte
	Ready bool
}

type secureSession struct {
	peer                  wgtypes.Key
	seed                  [32]byte
	tx, rx                noise.Cipher
	next, highest, window uint64
	expires               time.Time
	unusedSince           time.Time
	ready                 bool
}

type secureRate struct {
	until time.Time
	used  int
}

func (r *secureRate) allow(now time.Time, limit int) bool {
	if !now.Before(r.until) {
		r.until, r.used = now.Add(time.Second), 0
	}
	if r.used >= limit {
		return false
	}
	r.used++
	return true
}

func newSecure(private wgtypes.Key, peers []wgtypes.Key) *secure {
	s := &secure{private: private, public: private.PublicKey(), random: rand.Reader,
		peers: make(map[wgtypes.Key]*secureRate), sessions: make(map[[16]byte]*secureSession)}
	for _, peer := range peers {
		if peer != (wgtypes.Key{}) && peer != s.public {
			s.peers[peer] = &secureRate{}
		}
	}
	return s
}

func (s *secure) expire(now time.Time) {
	for id, session := range s.sessions {
		if !now.Before(session.expires) {
			delete(s.sessions, id)
		}
	}
}

// Prune retires ready sessions absent from the engine's live references for
// 10 seconds. Absolute expiry and pending lifetimes do not change.
func (s *secure) Prune(used map[[16]byte]bool, now time.Time) {
	s.expire(now)
	for id, session := range s.sessions {
		if !session.ready {
			continue
		}
		if used[id] {
			session.unusedSince = time.Time{}
		} else if session.unusedSince.IsZero() {
			session.unusedSince = now
		} else if !now.Before(session.unusedSince.Add(10 * time.Second)) {
			delete(s.sessions, id)
		}
	}
}

func (s *secure) room(peer wgtypes.Key) bool {
	count := 0
	for _, session := range s.sessions {
		if session.peer == peer {
			count++
		}
	}
	return len(s.sessions) < 512 && count < 64
}

func secureHeader(kind byte, sender, recipient wgtypes.Key, id [16]byte, counter uint64) []byte {
	h := make([]byte, secureHeaderN)
	h[0], h[1] = 1, kind
	copy(h[2:34], sender[:])
	copy(h[34:66], recipient[:])
	copy(h[66:82], id[:])
	binary.BigEndian.PutUint64(h[82:90], counter)
	return h
}

func (s *secure) handshake(peer wgtypes.Key, id [16]byte, initiator bool, seed []byte) (*noise.HandshakeState, error) {
	a, b := s.public, peer
	if !initiator {
		a, b = b, a
	}
	// Both canonical handshake headers are known before the first message.
	prologue := append([]byte(secureDomain), secureHeader(secureRequest, a, b, id, 0)...)
	prologue = append(prologue, secureHeader(secureReply, b, a, id, 0)...)
	cfg := noise.Config{CipherSuite: noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashBLAKE2s),
		Pattern: noise.HandshakeIK, Initiator: initiator, Prologue: prologue, Random: s.random,
		StaticKeypair: noise.DHKey{Private: s.private[:], Public: s.public[:]}}
	if initiator {
		cfg.PeerStatic, cfg.Random = peer[:], bytes.NewReader(seed)
	}
	return noise.NewHandshakeState(cfg)
}

func (s *secure) Start(peer wgtypes.Key, now time.Time) (id [16]byte, data []byte, err error) {
	s.expire(now)
	if s.private == (wgtypes.Key{}) || s.peers[peer] == nil || !s.room(peer) || s.serial == ^uint64(0) {
		return id, nil, errSecure
	}
	if s.ids == nil {
		var key [32]byte
		if _, err = io.ReadFull(s.random, key[:]); err != nil {
			return id, nil, err
		}
		s.ids, err = aes.NewCipher(key[:])
		if err != nil {
			return id, nil, err
		}
	}
	// A random-key permutation gives random IDs without an unbounded used-ID set.
	// Burn each serial even on failure; expiry must never permit local ID reuse.
	s.serial++
	binary.BigEndian.PutUint64(id[8:], s.serial)
	s.ids.Encrypt(id[:], id[:])
	if id == ([16]byte{}) || s.sessions[id] != nil {
		return id, nil, errSecure
	}
	session := &secureSession{peer: peer, expires: now.Add(10 * time.Second)}
	if _, err = io.ReadFull(s.random, session.seed[:]); err != nil {
		return id, nil, err
	}
	hs, err := s.handshake(peer, id, true, session.seed[:])
	if err != nil {
		return id, nil, err
	}
	data, _, _, err = hs.WriteMessage(secureHeader(secureRequest, s.public, peer, id, 0), nil)
	if err == nil {
		s.sessions[id] = session
	}
	return id, data, err
}

func (s *secure) Receive(data []byte, now time.Time) (secureEvent, error) {
	s.expire(now)
	if s.private == (wgtypes.Key{}) || len(data) < secureHeaderN || len(data) > secureMaxSize || data[0] != 1 {
		return secureEvent{}, errSecure
	}
	peer, recipient := wgtypes.Key(data[2:34]), wgtypes.Key(data[34:66])
	id, n, kind := [16]byte(data[66:82]), binary.BigEndian.Uint64(data[82:90]), data[1]
	if recipient != s.public || peer == s.public || id == ([16]byte{}) || n > noise.MaxNonce ||
		(kind != secureRequest && kind != secureReply && kind != secureData) ||
		(kind == secureRequest && (n != 0 || len(data) != secureHeaderN+96)) ||
		(kind == secureReply && (n != 0 || len(data) != secureHeaderN+48)) ||
		(kind == secureData && len(data) <= secureHeaderN+16) {
		return secureEvent{}, errSecure
	}
	// Unknown keys consume only the global budget, never a map entry or a reply.
	if kind != secureData && !s.global.allow(now, 64) {
		return secureEvent{}, errSecure
	}
	limit := s.peers[peer]
	if limit == nil || (kind != secureData && !limit.allow(now, 8)) {
		return secureEvent{}, errSecure
	}
	session := s.sessions[id]
	event := secureEvent{Peer: peer, ID: id}
	if kind == secureRequest {
		if session != nil || !s.room(peer) {
			return secureEvent{}, errSecure
		}
		hs, err := s.handshake(peer, id, false, nil)
		if err != nil {
			return secureEvent{}, err
		}
		body, _, _, err := hs.ReadMessage(nil, data[secureHeaderN:])
		if err != nil || len(body) != 0 || !bytes.Equal(hs.PeerStatic(), peer[:]) {
			return secureEvent{}, errSecure
		}
		reply, c1, c2, err := hs.WriteMessage(secureHeader(secureReply, s.public, peer, id, 0), nil)
		if err != nil {
			return secureEvent{}, err
		}
		// Noise Split is directional: c1 is initiator -> responder, c2 is reverse.
		s.sessions[id] = &secureSession{peer: peer, tx: c2.Cipher(), rx: c1.Cipher(), expires: now.Add(10 * time.Second)}
		event.Reply = reply
		return event, nil
	}
	if session == nil || session.peer != peer {
		return secureEvent{}, errSecure
	}
	if kind == secureReply {
		if session.rx != nil {
			return secureEvent{}, errSecure
		}
		// Reconstruct instead of reusing state: Noise v1.1.0 does not roll back
		// every DH error. A forged response must not spoil a pending handshake.
		hs, err := s.handshake(peer, id, true, session.seed[:])
		if err != nil {
			return secureEvent{}, err
		}
		if _, _, _, err = hs.WriteMessage(nil, nil); err != nil {
			return secureEvent{}, err
		}
		body, c1, c2, err := hs.ReadMessage(nil, data[secureHeaderN:])
		if err != nil || len(body) != 0 {
			return secureEvent{}, errSecure
		}
		session.tx, session.rx, session.seed = c1.Cipher(), c2.Cipher(), [32]byte{}
	} else {
		if session.rx == nil || (n <= session.highest && (session.highest-n >= 64 || session.window&(uint64(1)<<(session.highest-n)) != 0)) {
			return secureEvent{}, errSecure
		}
		body, err := session.rx.Decrypt(nil, n, data[:secureHeaderN], data[secureHeaderN:])
		if err != nil {
			return secureEvent{}, errSecure
		}
		// Commit the replay window only after authentication succeeds.
		if n > session.highest {
			session.window <<= n - session.highest
			session.highest = n
		}
		session.window |= uint64(1) << (session.highest - n)
		event.Body = body
	}
	if !session.ready {
		session.ready, session.expires = true, now.Add(10*time.Minute)
	}
	event.Ready = true
	return event, nil
}

func (s *secure) Seal(id [16]byte, body []byte, now time.Time) ([]byte, error) {
	s.expire(now)
	session := s.sessions[id]
	if session == nil || !session.ready || len(body) == 0 || len(body) > secureMaxSize-secureHeaderN-16 || session.next > noise.MaxNonce {
		return nil, errSecure
	}
	h := secureHeader(secureData, s.public, session.peer, id, session.next)
	data := session.tx.Encrypt(h, session.next, h, body)
	session.next++
	return data, nil
}
