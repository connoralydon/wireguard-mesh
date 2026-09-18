package main

import (
	"bytes"
	"encoding/binary"
	"io"
	mathrand "math/rand"
	"testing"
	"time"

	"github.com/flynn/noise"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func secureTestKey(n byte) (key wgtypes.Key) {
	for i := range key {
		key[i] = n
	}
	return key
}

func secureTestPair() (*secure, *secure, time.Time) {
	ka, kb := secureTestKey(1), secureTestKey(2)
	a, b := newSecure(ka, []wgtypes.Key{kb.PublicKey()}), newSecure(kb, []wgtypes.Key{ka.PublicKey()})
	// Repeatable streams are for tests only; successive ephemeral keys differ.
	a.random = mathrand.New(mathrand.NewSource(11))
	b.random = mathrand.New(mathrand.NewSource(22))
	return a, b, time.Unix(1000, 0)
}

func secureTestReject(t testing.TB, s *secure, packet []byte, now time.Time) {
	t.Helper()
	event, err := s.receive(packet, now)
	if err == nil || event.Peer != (wgtypes.Key{}) || event.ID != ([16]byte{}) || event.Ready || event.Body != nil || event.Reply != nil {
		t.Fatal("rejected packet returned success or an event")
	}
}

func secureTestOpen(t testing.TB, a, b *secure, now time.Time) ([16]byte, []byte, []byte) {
	t.Helper()
	// Return inner packets for Noise tests; mesh tests only need the session.
	id, request, err := a.start(b.public, now)
	if err != nil {
		t.Fatal(err)
	}
	if id == ([16]byte{}) || len(request) != secureHeaderN+96 {
		t.Fatal("invalid request framing")
	}
	if _, err := a.seal(id, []byte("too soon"), now); err == nil {
		t.Fatal("initiator sent data before the response")
	}
	event, err := b.receive(request, now)
	if err != nil || event.Peer != a.public || event.ID != id || event.Ready || event.Body != nil || len(event.Reply) != secureHeaderN+48 {
		t.Fatal("invalid request event:", err)
	}
	if _, err := b.seal(id, []byte("too soon"), now); err == nil {
		t.Fatal("responder sent data before key confirmation")
	}
	reply := event.Reply
	event, err = a.receive(reply, now)
	if err != nil || event.Peer != b.public || event.ID != id || !event.Ready || event.Body != nil || event.Reply != nil {
		t.Fatal("invalid response event:", err)
	}
	return id, request, reply
}

func secureTestSend(t testing.TB, a, b *secure, id [16]byte, body []byte, now time.Time) []byte {
	t.Helper()
	packet, err := a.seal(id, body, now)
	if err != nil {
		t.Fatal(err)
	}
	event, err := b.receive(packet, now)
	if err != nil || !event.Ready || event.ID != id || event.Peer != a.public || !bytes.Equal(event.Body, body) || event.Reply != nil {
		t.Fatal("invalid data event:", err)
	}
	return packet
}

func TestSecureRoundTrip(t *testing.T) {
	a, b, now := secureTestPair()
	id, request, reply := secureTestOpen(t, a, b, now)
	secureTestSend(t, a, b, id, []byte("LAN ping: fresh challenge"), now)
	secureTestSend(t, b, a, id, []byte("LAN pong: matching challenge"), now)
	secureTestSend(t, a, b, id, []byte("tunnel ping: another challenge"), now)
	secureTestSend(t, b, a, id, []byte("tunnel pong: matching challenge"), now)
	secureTestReject(t, b, request, now)
	secureTestReject(t, a, reply, now)
	// Simultaneous or reverse initiation creates an independent session.
	other, _, _ := secureTestOpen(t, b, a, now)
	if other == id {
		t.Fatal("opposite initiators produced the same ID")
	}
	secureTestSend(t, b, a, other, []byte("reverse session"), now)
	secureTestSend(t, a, b, other, []byte("reverse response"), now)
}

func TestSecureUnknownAndInvalidKeys(t *testing.T) {
	a, b, now := secureTestPair()
	unknown := secureTestKey(3)
	for _, peer := range []wgtypes.Key{unknown.PublicKey(), a.public, {}} {
		if _, _, err := a.start(peer, now); err == nil {
			t.Fatal("invalid or unknown peer accepted")
		}
	}
	outsider := newSecure(unknown, []wgtypes.Key{b.public})
	_, request, err := outsider.start(b.public, now)
	if err != nil {
		t.Fatal(err)
	}
	secureTestReject(t, b, request, now)
	if len(b.sessions) != 0 || len(b.peers) != 1 {
		t.Fatal("unknown key allocated state")
	}
	disabled := newSecure(wgtypes.Key{}, []wgtypes.Key{a.public})
	if _, _, err := disabled.start(a.public, now); err == nil {
		t.Fatal("missing local private key accepted")
	}
	secureTestReject(t, disabled, request, now)
	_, request, err = a.start(b.public, now)
	if err != nil {
		t.Fatal(err)
	}
	b.private = unknown // Keep the addressed public identity but use the wrong secret.
	secureTestReject(t, b, request, now)
	if len(b.sessions) != 0 {
		t.Fatal("wrong private key created a session")
	}
}

func TestSecureReflection(t *testing.T) {
	a, b, now := secureTestPair()
	id, request, reply := secureTestOpen(t, a, b, now)
	secureTestReject(t, a, request, now)
	secureTestReject(t, b, reply, now)
	packet := secureTestSend(t, a, b, id, []byte("challenge"), now)
	secureTestReject(t, a, packet, now)
	reflected := bytes.Clone(packet)
	copy(reflected[2:34], b.public[:])
	copy(reflected[34:66], a.public[:])
	secureTestReject(t, a, reflected, now)
	secureTestSend(t, b, a, id, []byte("response"), now)
}

func TestSecureHandshakeTamper(t *testing.T) {
	for _, kind := range []byte{secureRequest, secureReply} {
		for _, offset := range []int{0, 1, 2, 34, 66, 81, 82, 89, 90, 121, 137} {
			a, b, now := secureTestPair()
			id, request, err := a.start(b.public, now)
			if err != nil {
				t.Fatal(err)
			}
			packet, receiver := request, b
			if kind == secureReply {
				event, err := b.receive(request, now)
				if err != nil {
					t.Fatal(err)
				}
				packet, receiver = event.Reply, a
			}
			bad := bytes.Clone(packet)
			bad[offset] ^= 1
			secureTestReject(t, receiver, bad, now)
			if kind == secureRequest && len(b.sessions) != 0 {
				t.Fatal("forged initial request allocated a session")
			}
			if _, err := receiver.receive(packet, now); err != nil {
				t.Fatalf("kind %d offset %d spoiled valid handshake: %v", kind, offset, err)
			}
			if receiver.sessions[id] == nil {
				t.Fatal("valid handshake did not retain session")
			}
		}
	}
	// X25519 rejects this response before Noise's normal rollback path.
	a, b, now := secureTestPair()
	id, request, err := a.start(b.public, now)
	if err != nil {
		t.Fatal(err)
	}
	event, err := b.receive(request, now)
	if err != nil {
		t.Fatal(err)
	}
	bad := bytes.Clone(event.Reply)
	clear(bad[secureHeaderN : secureHeaderN+32])
	secureTestReject(t, a, bad, now)
	if _, err := a.receive(event.Reply, now); err != nil {
		t.Fatal("low-order ephemeral spoiled pending state:", err)
	}
	secureTestSend(t, a, b, id, []byte("still usable"), now)
}

func TestSecureHandshakeIdentityDomainAndPayload(t *testing.T) {
	for _, mode := range []string{"claimed identity", "domain", "request payload"} {
		t.Run(mode, func(t *testing.T) {
			a, b, now := secureTestPair()
			id := [16]byte{1}
			private, domain, payload := a.private, secureDomain, []byte(nil)
			switch mode {
			case "claimed identity":
				private = secureTestKey(3)
			case "domain":
				domain = "another-protocol/v1"
			case "request payload":
				payload = []byte("not allowed")
			}
			public := private.PublicKey()
			header := secureHeader(secureRequest, a.public, b.public, id, 0)
			prologue := append([]byte(domain), header...)
			prologue = append(prologue, secureHeader(secureReply, b.public, a.public, id, 0)...)
			hs, err := noise.NewHandshakeState(noise.Config{
				CipherSuite: noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashBLAKE2s),
				Pattern:     noise.HandshakeIK, Initiator: true, Prologue: prologue,
				StaticKeypair: noise.DHKey{Private: private[:], Public: public[:]}, PeerStatic: b.public[:],
			})
			if err != nil {
				t.Fatal(err)
			}
			request, _, _, err := hs.WriteMessage(header, payload)
			if err != nil {
				t.Fatal(err)
			}
			secureTestReject(t, b, request, now)
			if len(b.sessions) != 0 {
				t.Fatal("invalid authenticated handshake allocated state")
			}
		})
	}
	a, b, now := secureTestPair()
	id, request, err := a.start(b.public, now)
	if err != nil {
		t.Fatal(err)
	}
	hs, err := b.handshake(a.public, id, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := hs.ReadMessage(nil, request[secureHeaderN:]); err != nil {
		t.Fatal(err)
	}
	reply, _, _, err := hs.WriteMessage(secureHeader(secureReply, b.public, a.public, id, 0), []byte("not allowed"))
	if err != nil {
		t.Fatal(err)
	}
	secureTestReject(t, a, reply, now)
	event, err := b.receive(request, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.receive(event.Reply, now); err != nil {
		t.Fatal("payload rejection spoiled pending handshake:", err)
	}
}

func TestSecureTamperPreservesReplayState(t *testing.T) {
	a, b, now := secureTestPair()
	id, _, _ := secureTestOpen(t, a, b, now)
	packet, err := a.seal(id, []byte("authenticate before committing state"), now)
	if err != nil {
		t.Fatal(err)
	}
	before := *b.sessions[id]
	for i := range packet {
		bad := bytes.Clone(packet)
		bad[i] ^= 1
		secureTestReject(t, b, bad, now)
		got := b.sessions[id]
		if got.highest != before.highest || got.window != before.window || got.ready != before.ready || got.expires != before.expires {
			t.Fatalf("tamper at offset %d changed receive state", i)
		}
	}
	bad := bytes.Clone(packet)
	binary.BigEndian.PutUint64(bad[82:90], noise.MaxNonce)
	secureTestReject(t, b, bad, now)
	if event, err := b.receive(packet, now); err != nil || !event.Ready {
		t.Fatal("forgery burned the valid counter:", err)
	}
	secureTestReject(t, b, packet, now)
	secureTestSend(t, a, b, id, []byte("next counter"), now)
}

func TestSecureLossReorderAndWindow(t *testing.T) {
	a, b, now := secureTestPair()
	_, lost, err := a.start(b.public, now)
	if err != nil || len(lost) == 0 {
		t.Fatal("could not create lost request:", err)
	}
	id, request, err := a.start(b.public, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.receive(request, now); err != nil {
		t.Fatal(err)
	}
	// A lost response requires a new Start, not replay of an old request.
	secureTestReject(t, b, request, now)
	if _, err := a.seal(id, []byte("response was lost"), now); err == nil {
		t.Fatal("lost response still permitted data")
	}
	id, _, _ = secureTestOpen(t, a, b, now)
	packets := make([][]byte, 71)
	for i := range packets {
		packets[i], err = a.seal(id, []byte{byte(i)}, now)
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, i := range []int{70, 7, 9, 8, 69} {
		event, err := b.receive(packets[i], now)
		if err != nil || !bytes.Equal(event.Body, []byte{byte(i)}) {
			t.Fatalf("in-window packet %d rejected: %v", i, err)
		}
		secureTestReject(t, b, packets[i], now)
	}
	for _, i := range []int{0, 1, 6} {
		secureTestReject(t, b, packets[i], now)
	}
	secureTestSend(t, b, a, id, []byte("independent reverse counter"), now)
}

func TestSecureExpiry(t *testing.T) {
	for _, established := range []bool{false, true} {
		for _, operation := range []string{"start", "receive", "seal"} {
			a, b, now := secureTestPair()
			id, _, err := a.start(b.public, now)
			if err != nil {
				t.Fatal(err)
			}
			ttl := 10 * time.Second
			if established {
				// Remove the extra pending session through the inner expiry path.
				now = now.Add(ttl)
				id, _, _ = secureTestOpen(t, a, b, now)
				ttl = 10 * time.Minute
				secureTestSend(t, a, b, id, []byte("confirm"), now)
				secureTestSend(t, b, a, id, []byte("no sliding expiry"), now.Add(ttl-time.Nanosecond))
			}
			at := now.Add(ttl)
			switch operation {
			case "start":
				_, _, _ = a.start(wgtypes.Key{}, at)
			case "receive":
				secureTestReject(t, a, nil, at)
			case "seal":
				if _, err := a.seal(id, []byte("expired"), at); err == nil {
					t.Fatal("expired session sealed data")
				}
			}
			if len(a.sessions) != 0 {
				t.Fatalf("%s did not expire sessions (established=%v)", operation, established)
			}
		}
	}
	a, b, now := secureTestPair()
	id, request, reply := secureTestOpen(t, a, b, now)
	packet, err := a.seal(id, []byte("delayed confirmation"), now)
	if err != nil {
		t.Fatal(err)
	}
	secureTestReject(t, b, packet, now.Add(10*time.Second))
	if len(b.sessions) != 0 {
		t.Fatal("unconfirmed responder did not expire")
	}
	// A recorded initial request cannot renew a live, established session.
	a, b, now = secureTestPair()
	id, request, reply = secureTestOpen(t, a, b, now)
	packet = secureTestSend(t, a, b, id, []byte("confirm"), now)
	old, expiry := b.sessions[id], b.sessions[id].expires
	secureTestReject(t, b, request, now.Add(time.Minute))
	secureTestReject(t, a, reply, now.Add(time.Minute))
	if b.sessions[id] != old || old.expires != expiry {
		t.Fatal("recorded handshake renewed or replaced a live session")
	}
	secureTestReject(t, b, packet, now.Add(10*time.Minute))
	// After expiry, an old request can only create unconfirmed, short-lived state.
	event, err := b.receive(request, now.Add(10*time.Minute))
	if err != nil || event.Ready || event.Body != nil || len(event.Reply) == 0 {
		t.Fatal("recorded request bypassed fresh confirmation:", err)
	}
	if bytes.Equal(event.Reply, reply) {
		t.Fatal("responder reused its ephemeral key")
	}
	secureTestReject(t, b, packet, now.Add(10*time.Minute))
	if _, err := b.seal(id, []byte("not confirmed"), now.Add(10*time.Minute)); err == nil {
		t.Fatal("recorded request permitted application data")
	}
	restarted := newSecure(b.private, []wgtypes.Key{a.public})
	event, err = restarted.receive(request, now.Add(10*time.Minute))
	if err != nil || event.Ready || event.Body != nil {
		t.Fatal("restart bypassed fresh confirmation:", err)
	}
	secureTestReject(t, restarted, packet, now.Add(10*time.Minute))
}

func TestSecurePendingResponseExpiry(t *testing.T) {
	a, b, now := secureTestPair()
	_, request, err := a.start(b.public, now)
	if err != nil {
		t.Fatal(err)
	}
	event, err := b.receive(request, now)
	if err != nil {
		t.Fatal(err)
	}
	secureTestReject(t, a, event.Reply, now.Add(10*time.Second))
	if len(a.sessions) != 0 {
		t.Fatal("late response restored expired initiator")
	}
}

func TestSecurePruneUsedSessions(t *testing.T) {
	a, b, now := secureTestPair()
	id, _, _ := secureTestOpen(t, a, b, now)
	session, expiry := a.sessions[id], a.sessions[id].expires
	used := map[[16]byte]bool{id: true}
	a.Prune(nil, now)
	if session.unusedSince != now {
		t.Fatal("unreferenced ready session did not start its grace period")
	}
	a.Prune(used, now.Add(9*time.Second))
	a.Prune(used, now.Add(20*time.Second))
	if a.sessions[id] != session || !session.unusedSince.IsZero() || session.expires != expiry {
		t.Fatal("reference did not preserve the session and clear its unused time")
	}
	a.Prune(nil, now.Add(21*time.Second))
	a.Prune(nil, now.Add(30*time.Second))
	if a.sessions[id] != session || session.unusedSince != now.Add(21*time.Second) || session.expires != expiry {
		t.Fatal("released reference did not start a new grace period")
	}
	a.Prune(nil, now.Add(31*time.Second))
	if a.sessions[id] != nil {
		t.Fatal("released session survived its new grace period")
	}
}

func TestSecurePruneUnusedSessions(t *testing.T) {
	a, b, now := secureTestPair()
	id, _, _ := secureTestOpen(t, a, b, now)
	session, expiry := a.sessions[id], a.sessions[id].expires
	unused := now.Add(time.Minute)
	a.Prune(map[[16]byte]bool{id: false}, unused)
	a.Prune(nil, unused.Add(10*time.Second-time.Nanosecond))
	if a.sessions[id] != session || session.unusedSince != unused || session.expires != expiry {
		t.Fatal("unreferenced session was retired early or its deadlines changed")
	}
	a.Prune(nil, unused.Add(10*time.Second))
	if a.sessions[id] != nil {
		t.Fatal("unreferenced session survived the grace period")
	}
}

func TestSecurePruneAbsoluteExpiry(t *testing.T) {
	for _, ready := range []bool{false, true} {
		for _, referenced := range []bool{false, true} {
			a, b, now := secureTestPair()
			var id [16]byte
			ttl := 10 * time.Second
			if ready {
				id, _, _ = secureTestOpen(t, a, b, now)
				secureTestSend(t, a, b, id, []byte("confirm"), now)
				ttl = 10 * time.Minute
			} else {
				var request []byte
				var err error
				id, request, err = a.start(b.public, now)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := b.receive(request, now); err != nil {
					t.Fatal(err)
				}
			}
			expiry := now.Add(ttl)
			used := map[[16]byte]bool{id: referenced}
			for _, s := range []*secure{a, b} {
				s.Prune(used, expiry.Add(-time.Nanosecond))
				session := s.sessions[id]
				if session == nil || session.expires != expiry || session.ready != ready || (!ready && !session.unusedSince.IsZero()) {
					t.Fatal("Prune changed absolute expiry or pending state")
				}
				s.Prune(used, expiry)
				if s.sessions[id] != nil {
					t.Fatalf("absolute expiry was extended (ready=%v, referenced=%v)", ready, referenced)
				}
			}
		}
	}
}

func TestSecurePacketAndNonceBounds(t *testing.T) {
	a, b, now := secureTestPair()
	id, _, _ := secureTestOpen(t, a, b, now)
	for _, body := range [][]byte{nil, {}, make([]byte, secureInnerMaxSize-secureHeaderN-15)} {
		if _, err := a.seal(id, body, now); err == nil {
			t.Fatal("invalid body length accepted")
		}
	}
	if a.sessions[id].next != 0 {
		t.Fatal("invalid body consumed send counter")
	}
	packet := secureTestSend(t, a, b, id, make([]byte, secureInnerMaxSize-secureHeaderN-16), now)
	if len(packet) != secureInnerMaxSize {
		t.Fatal("maximum-size packet has wrong length")
	}
	secureTestReject(t, b, append(bytes.Clone(packet), 0), now)
	h := secureHeader(secureData, a.public, b.public, id, 1)
	secureTestReject(t, b, a.sessions[id].tx.Encrypt(h, 1, h, nil), now)
	a.sessions[id].next = noise.MaxNonce - 1
	penultimate, err := a.seal(id, []byte("penultimate nonce"), now)
	if err != nil {
		t.Fatal(err)
	}
	last, err := a.seal(id, []byte("last nonce"), now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.seal(id, []byte("overflow"), now); err == nil {
		t.Fatal("nonce overflow accepted")
	}
	for _, packet := range [][]byte{last, penultimate} {
		if _, err := b.receive(packet, now); err != nil {
			t.Fatal("valid final nonce rejected:", err)
		}
		secureTestReject(t, b, packet, now)
	}
	h = secureHeader(secureData, a.public, b.public, id, ^uint64(0))
	secureTestReject(t, b, a.sessions[id].tx.Encrypt(h, ^uint64(0), h, []byte("reserved")), now)
	secureTestSend(t, b, a, id, []byte("reverse direction remains usable"), now)
}

func TestSecureIDUniquenessAndEntropyFailure(t *testing.T) {
	a, b, now := secureTestPair()
	a.random = bytes.NewReader(bytes.Repeat([]byte{11}, 4096))
	id, _, err := a.start(b.public, now)
	if err != nil {
		t.Fatal(err)
	}
	// Even repeated entropy and expiry cannot repeat a locally generated ID.
	other, _, err := a.start(b.public, now.Add(10*time.Second))
	if err != nil || other == id {
		t.Fatal("expired local ID was reused:", err)
	}
	// Force the next generated ID to collide with an incoming live session.
	var collision [16]byte
	binary.BigEndian.PutUint64(collision[8:], a.serial+1)
	a.ids.Encrypt(collision[:], collision[:])
	live := &secureSession{peer: b.public, expires: now.Add(time.Minute)}
	a.sessions[collision] = live
	if _, _, err := a.start(b.public, now.Add(11*time.Second)); err == nil || a.sessions[collision] != live {
		t.Fatal("generated duplicate ID replaced live state")
	}
	a.random = bytes.NewReader(nil)
	failed, _, err := a.start(b.public, now.Add(12*time.Second))
	if err != io.EOF || a.sessions[failed] != nil {
		t.Fatal("entropy failure created a session:", err)
	}
	a.random = bytes.NewReader(bytes.Repeat([]byte{11}, 32))
	next, _, err := a.start(b.public, now.Add(13*time.Second))
	if err != nil || next == failed || next == collision || next == id || next == other {
		t.Fatal("failed or previous ID was reused:", err)
	}
	a.serial = ^uint64(0)
	if _, _, err := a.start(b.public, now.Add(14*time.Second)); err == nil {
		t.Fatal("ID serial wrapped")
	}
	c := newSecure(a.private, []wgtypes.Key{b.public})
	c.random = bytes.NewReader(nil)
	if _, _, err := c.start(b.public, now); err != io.EOF || len(c.sessions) != 0 {
		t.Fatal("ID-key entropy failure created a session:", err)
	}
}

func TestSecureSessionBounds(t *testing.T) {
	a, b, now := secureTestPair()
	var first [16]byte
	for i := 0; i < 64; i++ {
		at := now.Add(time.Duration(i) * time.Second)
		id, _, _ := secureTestOpen(t, a, b, at)
		secureTestSend(t, a, b, id, []byte("confirm"), at)
		if i == 0 {
			first = id
		}
	}
	at := now.Add(64 * time.Second)
	if _, _, err := a.start(b.public, at); err == nil || len(a.sessions) != 64 {
		t.Fatal("per-peer Start bound failed")
	}
	fresh := newSecure(a.private, []wgtypes.Key{b.public})
	_, request, err := fresh.start(b.public, at)
	if err != nil {
		t.Fatal(err)
	}
	bad := bytes.Clone(request)
	bad[len(bad)-1] ^= 1
	secureTestReject(t, b, bad, at)
	secureTestReject(t, b, request, at)
	if len(b.sessions) != 64 {
		t.Fatal("incoming handshake evicted live sessions")
	}
	secureTestSend(t, a, b, first, []byte("old session survives"), at)
	secureTestSend(t, b, a, first, []byte("still bidirectional"), at)
	used := map[[16]byte]bool{first: true}
	for _, s := range []*secure{a, b} {
		s.Prune(used, at)
		s.Prune(used, at.Add(10*time.Second))
		if len(s.sessions) != 1 || s.sessions[first] == nil {
			t.Fatal("Prune did not release unused capacity and preserve the live session")
		}
	}
	secureTestOpen(t, a, b, at.Add(10*time.Second))
	peers := make([]wgtypes.Key, 17)
	for i := range peers {
		peers[i] = secureTestKey(byte(i + 10)).PublicKey()
	}
	c := newSecure(secureTestKey(200), peers)
	for i := 0; i < 512; i++ {
		if _, _, err := c.start(peers[i/32], now); err != nil {
			t.Fatal("global bound reached too early:", err)
		}
	}
	if _, _, err := c.start(peers[16], now); err == nil || len(c.sessions) != 512 {
		t.Fatal("global Start bound failed")
	}
	d := newSecure(secureTestKey(26), []wgtypes.Key{c.public})
	_, request, err = d.start(c.public, now)
	if err != nil {
		t.Fatal(err)
	}
	secureTestReject(t, c, request, now)
	if len(c.sessions) != 512 {
		t.Fatal("global Receive bound evicted sessions")
	}
	if _, _, err := c.start(peers[16], now.Add(10*time.Second)); err != nil || len(c.sessions) != 1 {
		t.Fatal("expired capacity was not recovered:", err)
	}
}

func TestSecureHandshakeRateLimits(t *testing.T) {
	t.Run("configured key", func(t *testing.T) {
		a, b, now := secureTestPair()
		_, request, err := a.start(b.public, now)
		if err != nil {
			t.Fatal(err)
		}
		bad := bytes.Clone(request)
		bad[len(bad)-1] ^= 1
		for i := 0; i < 8; i++ {
			secureTestReject(t, b, bad, now)
		}
		secureTestReject(t, b, request, now)
		if len(b.sessions) != 0 || b.peers[a.public].used != 8 {
			t.Fatal("per-key budget failed")
		}
		if _, err := b.receive(request, now.Add(time.Second)); err != nil {
			t.Fatal("per-key budget did not recover:", err)
		}
	})
	t.Run("unknown keys", func(t *testing.T) {
		a, b, now := secureTestPair()
		outsider := newSecure(secureTestKey(3), []wgtypes.Key{b.public})
		_, unknown, err := outsider.start(b.public, now)
		if err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 64; i++ {
			secureTestReject(t, b, unknown, now)
		}
		_, request, err := a.start(b.public, now)
		if err != nil {
			t.Fatal(err)
		}
		secureTestReject(t, b, request, now)
		if len(b.peers) != 1 || len(b.sessions) != 0 || b.global.used != 64 {
			t.Fatal("unknown keys bypassed global budget or allocated state")
		}
		if _, err := b.receive(request, now.Add(time.Second)); err != nil {
			t.Fatal("global budget did not recover:", err)
		}
	})
	t.Run("global configured keys", func(t *testing.T) {
		peers := make([]wgtypes.Key, 9)
		for i := range peers {
			peers[i] = secureTestKey(byte(i + 1)).PublicKey()
		}
		b := newSecure(secureTestKey(200), peers)
		now := time.Unix(1000, 0)
		for i := range peers {
			a := newSecure(secureTestKey(byte(i+1)), []wgtypes.Key{b.public})
			_, request, err := a.start(b.public, now)
			if err != nil {
				t.Fatal(err)
			}
			if i == 8 {
				secureTestReject(t, b, request, now)
				if _, err := b.receive(request, now.Add(time.Second)); err != nil {
					t.Fatal(err)
				}
				break
			}
			request[len(request)-1] ^= 1
			for j := 0; j < 8; j++ {
				secureTestReject(t, b, request, now)
			}
		}
	})
}

func TestSecureTruncatedPackets(t *testing.T) {
	a, b, now := secureTestPair()
	id, request, reply := secureTestOpen(t, a, b, now)
	packet, err := a.seal(id, []byte("truncation must not consume a counter"), now)
	if err != nil {
		t.Fatal(err)
	}
	for _, full := range [][]byte{request, reply, packet} {
		for n := 0; n < len(full); n++ {
			secureTestReject(t, a, full[:n], now)
			secureTestReject(t, b, full[:n], now)
		}
	}
	if _, err := b.receive(packet, now); err != nil {
		t.Fatal("truncation spoiled valid packet:", err)
	}
	for _, kind := range []byte{0, 4, 255} {
		bad := bytes.Clone(packet)
		bad[1] = kind
		secureTestReject(t, b, bad, now)
	}
}

func FuzzSecureInnerReceive(f *testing.F) {
	a, b, now := secureTestPair()
	id, request, reply := secureTestOpen(f, a, b, now)
	packet, err := a.seal(id, []byte("fuzz transport"), now)
	if err != nil {
		f.Fatal(err)
	}
	for _, full := range [][]byte{request, reply, packet} {
		for n := 0; n <= len(full); n++ {
			f.Add(bytes.Clone(full[:n]))
		}
	}
	f.Add(make([]byte, secureInnerMaxSize+1))
	f.Fuzz(func(t *testing.T, data []byte) {
		a, b, now := secureTestPair()
		secureTestOpen(t, a, b, now)
		pending, _, _ := secureTestPair()
		if _, _, err := pending.start(b.public, now); err != nil {
			t.Fatal(err)
		}
		for _, receiver := range []*secure{a, b, pending, newSecure(b.private, []wgtypes.Key{a.public})} {
			event, err := receiver.receive(data, now)
			if err != nil {
				if event.Peer != (wgtypes.Key{}) || event.ID != ([16]byte{}) || event.Ready || event.Body != nil || event.Reply != nil {
					t.Fatal("error exposed an event")
				}
				continue
			}
			if len(data) < secureHeaderN || len(data) > secureInnerMaxSize || receiver.peers[event.Peer] == nil || event.ID == ([16]byte{}) {
				t.Fatal("invalid successful fuzz event")
			}
			switch data[1] {
			case secureRequest:
				if event.Ready || event.Body != nil || len(event.Reply) != secureHeaderN+48 {
					t.Fatal("invalid fuzz request event")
				}
			case secureReply:
				if !event.Ready || event.Body != nil || event.Reply != nil {
					t.Fatal("invalid fuzz response event")
				}
			case secureData:
				if !event.Ready || len(event.Body) == 0 || event.Reply != nil {
					t.Fatal("invalid fuzz data event")
				}
			default:
				t.Fatal("unknown fuzz packet type accepted")
			}
			secureTestReject(t, receiver, data, now)
		}
	})
}
