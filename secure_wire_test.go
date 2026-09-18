package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	mathrand "math/rand"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/flynn/noise"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func secureWireReject(t testing.TB, s *secure, wire []byte, now time.Time) {
	t.Helper()
	event, err := s.Receive(wire, now)
	if err == nil || !reflect.DeepEqual(event, secureEvent{}) {
		t.Fatal("rejected wire packet returned success or an event:", err)
	}
}

func secureWireSameSession(a, b secureSession) bool {
	// Noise ciphers contain functions. Compare their output, not function values.
	for _, pair := range [][2]noise.Cipher{{a.tx, b.tx}, {a.rx, b.rx}} {
		if (pair[0] == nil) != (pair[1] == nil) {
			return false
		}
		if pair[0] != nil && !bytes.Equal(pair[0].Encrypt(nil, 0, nil, nil), pair[1].Encrypt(nil, 0, nil, nil)) {
			return false
		}
	}
	a.tx, a.rx, b.tx, b.rx = nil, nil, nil, nil
	return a == b
}

func secureWireOpen(t testing.TB, a, b *secure, now time.Time) ([16]byte, []byte, []byte) {
	t.Helper()
	id, request, err := a.Start(b.public, now)
	if err != nil || id == ([16]byte{}) || len(request) != 512 {
		t.Fatal("invalid wire request:", err)
	}
	if _, err := a.Seal(id, []byte("too soon"), now); err == nil {
		t.Fatal("initiator sent data before the response")
	}
	event, err := b.Receive(request, now)
	if err != nil || event.Peer != a.public || event.ID != id || event.Ready || event.Body != nil || len(event.Reply) != 512 {
		t.Fatal("invalid wire request event:", err)
	}
	if _, err := b.Seal(id, []byte("too soon"), now); err == nil {
		t.Fatal("responder sent data before key confirmation")
	}
	reply := event.Reply
	event, err = a.Receive(reply, now)
	if err != nil || event.Peer != b.public || event.ID != id || !event.Ready || event.Body != nil || event.Reply != nil {
		t.Fatal("invalid wire response event:", err)
	}
	return id, request, reply
}

func secureWireSend(t testing.TB, a, b *secure, id [16]byte, body []byte, now time.Time) []byte {
	t.Helper()
	wire, err := a.Seal(id, body, now)
	if err != nil || len(wire) != 512 {
		t.Fatal("invalid wire data packet:", err)
	}
	event, err := b.Receive(wire, now)
	if err != nil || !event.Ready || event.ID != id || event.Peer != a.public || !bytes.Equal(event.Body, body) || event.Reply != nil {
		t.Fatal("invalid wire data event:", err)
	}
	return wire
}

func TestSecureWireRoundTripAndPrivacy(t *testing.T) {
	a, b, now := secureTestPair()
	id, request, reply := secureWireOpen(t, a, b, now)
	ping, pong := []byte("LAN ping: private application challenge"), []byte("LAN pong: private application response")
	data := secureWireSend(t, a, b, id, ping, now)
	reverse := secureWireSend(t, b, a, id, pong, now)
	seen := make(map[string]bool)
	for _, wire := range [][]byte{request, reply, data, reverse} {
		if len(wire) != 512 {
			t.Fatal("wire length exposed the packet type or body length")
		}
		for _, secret := range [][]byte{a.public[:], b.public[:], []byte(a.public.String()), []byte(b.public.String()), id[:], ping, pong} {
			if bytes.Contains(wire, secret) {
				t.Fatal("wire packet exposed an identity, session ID, or application plaintext")
			}
		}
		nonce := string(wire[:24])
		if seen[nonce] {
			t.Fatal("wire packets reused an outer nonce")
		}
		seen[nonce] = true
	}
	secureWireReject(t, b, request, now)
	secureWireReject(t, a, reply, now)
	secureWireReject(t, b, data, now)
	secureWireReject(t, a, reverse, now)
}

func TestSecureEnvelopeDirectionalVector(t *testing.T) {
	decode := func(s string) []byte {
		t.Helper()
		b, err := hex.DecodeString(s)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	// RFC 7748 section 6.1 supplies the private keys, public keys, and shared secret.
	ka := wgtypes.Key(decode("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"))
	kb := wgtypes.Key(decode("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"))
	pa := wgtypes.Key(decode("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"))
	pb := wgtypes.Key(decode("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"))
	shared := decode("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")
	if ka.PublicKey() != pa || kb.PublicKey() != pb {
		t.Fatal("incorrect X25519 test vector")
	}
	if secureEnvelopeDomain != "wireguard-mesh/envelope/v2" || secureDomain != "wireguard-mesh/v2" || secureHeader(secureRequest, pa, pb, [16]byte{1}, 0)[0] != 2 {
		t.Fatal("incorrect protocol domains or inner version")
	}
	a, b := newSecure(ka, []wgtypes.Key{pb}), newSecure(kb, []wgtypes.Key{pa})
	for _, pair := range [][2]*secure{{a, b}, {b, a}} {
		sender, receiver := pair[0], pair[1]
		// Independent RFC 5869 extract and one-block expand. Info is raw sender || recipient.
		extract := hmac.New(sha256.New, []byte("wireguard-mesh/envelope/v2"))
		extract.Write(shared)
		expand := hmac.New(sha256.New, extract.Sum(nil))
		expand.Write(sender.public[:])
		expand.Write(receiver.public[:])
		expand.Write([]byte{1})
		aead, err := chacha20poly1305.NewX(expand.Sum(nil))
		if err != nil {
			t.Fatal(err)
		}
		inner := secureHeader(secureRequest, sender.public, receiver.public, [16]byte{1}, 0)
		plain := make([]byte, 472)
		binary.BigEndian.PutUint16(plain, uint16(len(inner)))
		copy(plain[2:], inner)
		nonce := decode("000102030405060708090a0b0c0d0e0f1011121314151617")
		sender.random = bytes.NewReader(nonce)
		wire, err := sender.wrap(receiver.public, inner)
		want := aead.Seal(bytes.Clone(nonce), nonce, plain, []byte("wireguard-mesh/envelope/v2"))
		if err != nil || !bytes.Equal(wire, want) {
			t.Fatal("wire does not match the directional X25519/HKDF/XChaCha20-Poly1305 vector:", err)
		}
		got, err := receiver.unwrap(wire, time.Unix(1000, 0))
		if err != nil || !bytes.Equal(got, inner) {
			t.Fatal("opposite receive key does not match the send key:", err)
		}
		if _, err := sender.envelopes[receiver.public].rx.Open(nil, nonce, wire[24:], []byte(secureEnvelopeDomain)); err == nil {
			t.Fatal("opposite directions used the same key")
		}
	}
}

func TestSecureEnvelopeInvalidKeysAndPeerLimit(t *testing.T) {
	a, b, now := secureTestPair()
	lowOrder := []wgtypes.Key{{}, {1}}
	for _, first := range []byte{0xec, 0xed, 0xee} {
		key := wgtypes.Key(bytes.Repeat([]byte{0xff}, 32))
		key[0], key[31] = first, 0x7f // p-1, p, p+1.
		lowOrder = append(lowOrder, key)
	}
	peers := append([]wgtypes.Key{b.public, a.public, b.public}, lowOrder...)
	s := newSecure(a.private, peers)
	if len(s.peers) != 1 || len(s.envelopes) != 1 || s.peers[b.public] == nil {
		t.Fatal("constructor retained an invalid, duplicate, or local key")
	}
	for _, peer := range lowOrder {
		if _, _, err := s.Start(peer, now); err == nil {
			t.Fatal("low-order key accepted")
		}
		if _, err := s.wrap(peer, make([]byte, secureHeaderN)); err == nil {
			t.Fatal("low-order key has an envelope")
		}
	}
	peers = make([]wgtypes.Key, 129)
	for i := range peers {
		peers[i] = secureTestKey(byte(i + 1)).PublicKey()
	}
	blocked := newSecure(secureTestKey(200), peers)
	for _, disabled := range []*secure{blocked, newSecure(wgtypes.Key{}, []wgtypes.Key{a.public})} {
		if len(disabled.peers) != 0 || len(disabled.envelopes) != 0 || len(disabled.sessions) != 0 {
			t.Fatal("disabled constructor retained keys or sessions")
		}
		if _, _, err := disabled.Start(a.public, now); err == nil {
			t.Fatal("disabled constructor permitted Start")
		}
		if _, err := disabled.wrap(a.public, make([]byte, secureHeaderN)); err == nil {
			t.Fatal("disabled constructor permitted wrap")
		}
	}
	outside := newSecure(a.private, []wgtypes.Key{blocked.public})
	_, wire, err := outside.Start(blocked.public, now)
	if err != nil {
		t.Fatal(err)
	}
	secureWireReject(t, blocked, wire, now)
	if len(blocked.sessions) != 0 || blocked.openRate.used != 0 {
		t.Fatal("blocked constructor processed a wire packet")
	}
}

func TestSecureEnvelopeRandomizationAndNoInnerEffects(t *testing.T) {
	a, b, now := secureTestPair()
	id, inner, err := a.start(b.public, now)
	if err != nil {
		t.Fatal(err)
	}
	before := *a.sessions[id]
	// An expired sentinel must survive unwrap: only inner processing may expire it.
	expired := &secureSession{peer: a.public, expires: now}
	b.sessions[[16]byte{9}] = expired
	seen := make(map[string]bool)
	for i := 0; i < 16; i++ {
		wire, err := a.wrap(b.public, inner)
		if err != nil || len(wire) != 512 {
			t.Fatal("wrap failed:", err)
		}
		for _, part := range [][]byte{wire[:24], wire[24:]} {
			if seen[string(part)] {
				t.Fatal("wrapping the same inner packet did not randomize the nonce and ciphertext")
			}
			seen[string(part)] = true
		}
		got, err := b.unwrap(wire, now)
		if err != nil || !bytes.Equal(got, inner) {
			t.Fatal("unwrap changed the inner packet:", err)
		}
	}
	if !secureWireSameSession(*a.sessions[id], before) || len(b.sessions) != 1 || b.sessions[[16]byte{9}] != expired || b.global != (secureRate{}) || *b.peers[a.public] != (secureRate{}) || b.openRate.used != 16 {
		t.Fatal("wrap or unwrap changed inner state, or failed to charge opens")
	}
	for _, n := range []int{0, secureHeaderN - 1, secureInnerMaxSize + 1} {
		if _, err := a.wrap(b.public, make([]byte, n)); err == nil {
			t.Fatalf("wrap accepted inner length %d", n)
		}
	}
	// Cached envelopes do not need another static DH operation for each packet.
	a.private, b.private = wgtypes.Key{}, wgtypes.Key{}
	wire, err := a.wrap(b.public, inner)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := b.unwrap(wire, now); err != nil || !bytes.Equal(got, inner) {
		t.Fatal("cached envelope keys were not retained:", err)
	}
}

func TestSecureWireBodyBounds(t *testing.T) {
	if secureMaxSize != 512 || secureInnerMaxSize != 470 || secureInnerMaxSize-secureHeaderN-16 != 364 {
		t.Fatal("incorrect wire, inner, or application size limit")
	}
	a, b, now := secureTestPair()
	id, _, _ := secureWireOpen(t, a, b, now)
	for _, body := range [][]byte{nil, {}, make([]byte, 365)} {
		if wire, err := a.Seal(id, body, now); err == nil || wire != nil {
			t.Fatal("invalid body length accepted")
		}
	}
	if a.sessions[id].next != 0 {
		t.Fatal("invalid body consumed an inner nonce")
	}
	secureWireSend(t, a, b, id, bytes.Repeat([]byte{0xff}, 364), now)
	// Maximum protocol fields use printable tokens and hexadecimal proofs.
	msg := message{Op: "rosenpass-select", Token: strings.Repeat("A", 64), Port: 65535, Proof: strings.Repeat("f", 64), Rekey: true}
	body, err := json.Marshal(msg)
	if err != nil || len(body) > 364 {
		t.Fatalf("maximum message JSON does not fit: %d bytes, %v", len(body), err)
	}
	secureWireSend(t, b, a, id, body, now)
}

func TestSecureWireUnknownOutsideAndReflection(t *testing.T) {
	a, b, now := secureTestPair()
	id, request, reply := secureWireOpen(t, a, b, now)
	data := secureWireSend(t, a, b, id, []byte("do not reflect"), now)
	secureWireReject(t, a, request, now)
	secureWireReject(t, b, reply, now)
	secureWireReject(t, a, data, now)
	outsider := newSecure(secureTestKey(3), []wgtypes.Key{a.public, b.public})
	for _, wire := range [][]byte{request, reply, data} {
		secureWireReject(t, outsider, wire, now)
	}
	_, unknown, err := outsider.Start(b.public, now)
	if err != nil {
		t.Fatal(err)
	}
	before, global, peerRate := *b.sessions[id], b.global, *b.peers[a.public]
	secureWireReject(t, b, unknown, now)
	if !secureWireSameSession(*b.sessions[id], before) || len(b.sessions) != 1 || b.global != global || *b.peers[a.public] != peerRate || len(outsider.sessions) != 1 {
		t.Fatal("unknown or outside traffic changed inner state")
	}
	for _, peer := range []wgtypes.Key{outsider.public, a.public, {}} {
		if _, _, err := a.Start(peer, now); err == nil {
			t.Fatal("invalid or unconfigured peer accepted by public Start")
		}
	}
}

func TestSecureWireTamperAndLengths(t *testing.T) {
	a, b, now := secureTestPair()
	id, request, reply := secureWireOpen(t, a, b, now)
	data, err := a.Seal(id, []byte("authenticate before changing replay state"), now)
	if err != nil {
		t.Fatal(err)
	}
	before := *b.sessions[id]
	for _, wire := range [][]byte{request, reply, data} {
		for i := range wire {
			bad := bytes.Clone(wire)
			bad[i] ^= 1 // Includes every nonce, ciphertext, and tag byte.
			secureWireReject(t, a, bad, now)
			secureWireReject(t, b, bad, now)
		}
		used := b.openRate.used
		for n := 0; n < len(wire); n++ {
			secureWireReject(t, b, wire[:n], now)
		}
		secureWireReject(t, b, append(bytes.Clone(wire), 0), now)
		secureWireReject(t, b, append(bytes.Clone(wire), wire...), now)
		if b.openRate.used != used {
			t.Fatal("invalid wire length consumed an AEAD attempt")
		}
	}
	if !secureWireSameSession(*b.sessions[id], before) || len(b.sessions) != 1 {
		t.Fatal("wire tampering changed inner session state")
	}
	if event, err := b.Receive(data, now); err != nil || !event.Ready || string(event.Body) != "authenticate before changing replay state" {
		t.Fatal("wire tampering prevented valid data reception:", err)
	}
}

func TestSecureEnvelopeAuthenticatedFraming(t *testing.T) {
	a, b, now := secureTestPair()
	_, inner, err := a.start(b.public, now)
	if err != nil {
		t.Fatal(err)
	}
	plain := make([]byte, 472)
	binary.BigEndian.PutUint16(plain, uint16(len(inner)))
	copy(plain[2:], inner)
	nonce := bytes.Repeat([]byte{7}, 24)
	seal := func(p, ad []byte) []byte {
		return a.envelopes[b.public].tx.Seal(bytes.Clone(nonce), nonce, p, ad)
	}
	for _, n := range []int{0, secureHeaderN - 1, secureInnerMaxSize + 1, 65535} {
		bad := bytes.Clone(plain)
		binary.BigEndian.PutUint16(bad, uint16(n))
		secureWireReject(t, b, seal(bad, []byte(secureEnvelopeDomain)), now)
	}
	for _, offset := range []int{2 + len(inner), len(plain) - 1, 2 + 2, 2 + 34} {
		bad := bytes.Clone(plain)
		bad[offset] ^= 1 // Nonzero padding, wrong inner sender, or wrong recipient.
		secureWireReject(t, b, seal(bad, []byte(secureEnvelopeDomain)), now)
	}
	for _, ad := range [][]byte{nil, []byte("wireguard-mesh/envelope/v1")} {
		secureWireReject(t, b, seal(plain, ad), now)
	}
	if len(b.sessions) != 0 || b.global != (secureRate{}) || *b.peers[a.public] != (secureRate{}) {
		t.Fatal("invalid envelope framing reached inner processing")
	}
	if event, err := b.Receive(seal(plain, []byte(secureEnvelopeDomain)), now); err != nil || event.Ready || len(event.Reply) != 512 {
		t.Fatal("valid authenticated framing was rejected:", err)
	}
}

func TestSecureWireMatchedPeerMustOwnInner(t *testing.T) {
	a, b, now := secureTestPair()
	c := newSecure(secureTestKey(3), []wgtypes.Key{b.public})
	b = newSecure(b.private, []wgtypes.Key{a.public, c.public})
	live, _, _ := secureWireOpen(t, a, b, now)
	secureWireSend(t, a, b, live, []byte("preserve this session"), now)
	id, request, err := c.Start(b.public, now)
	if err != nil {
		t.Fatal(err)
	}
	wire := request
	for _, kind := range []string{"request", "data"} {
		inner, err := b.unwrap(wire, now)
		if err != nil {
			t.Fatal(err)
		}
		// A is configured, but must not submit C's valid Noise packet under A's envelope.
		forged, err := a.wrap(b.public, inner)
		if err != nil {
			t.Fatal(err)
		}
		before := make(map[[16]byte]secureSession)
		for id, session := range b.sessions {
			before[id] = *session
		}
		global, aRate, cRate := b.global, *b.peers[a.public], *b.peers[c.public]
		secureWireReject(t, b, forged, now)
		if len(b.sessions) != len(before) || b.global != global || *b.peers[a.public] != aRate || *b.peers[c.public] != cRate {
			t.Fatalf("mismatched %s reached inner processing or allocated a session", kind)
		}
		for id, session := range before {
			if got := b.sessions[id]; got == nil || !secureWireSameSession(*got, session) {
				t.Fatalf("mismatched %s changed confirmation, expiry, or replay state", kind)
			}
		}
		event, err := b.Receive(wire, now)
		if err != nil || event.Peer != c.public || event.ID != id {
			t.Fatal("mismatched outer peer prevented the legitimate packet:", err)
		}
		if kind == "request" {
			if event.Ready || event.Body != nil || len(event.Reply) != 512 {
				t.Fatal("invalid legitimate request event")
			}
			if _, err := c.Receive(event.Reply, now); err != nil {
				t.Fatal(err)
			}
			wire, err = c.Seal(id, []byte("C's authenticated data"), now)
			if err != nil {
				t.Fatal(err)
			}
		} else if !event.Ready || string(event.Body) != "C's authenticated data" || event.Reply != nil {
			t.Fatal("invalid legitimate data event")
		}
	}
}

func TestSecureWireFreshEnvelopeDoesNotBypassReplay(t *testing.T) {
	a, b, now := secureTestPair()
	id, request, reply := secureWireOpen(t, a, b, now)
	data := secureWireSend(t, a, b, id, []byte("accept only once"), now)
	for _, tc := range []struct {
		sender, receiver *secure
		wire             []byte
	}{{a, b, request}, {b, a, reply}, {a, b, data}} {
		inner, err := tc.receiver.unwrap(tc.wire, now)
		if err != nil {
			t.Fatal(err)
		}
		fresh, err := tc.sender.wrap(tc.receiver.public, inner)
		if err != nil || bytes.Equal(fresh[:24], tc.wire[:24]) {
			t.Fatal("could not create a fresh outer nonce:", err)
		}
		before := *tc.receiver.sessions[id]
		secureWireReject(t, tc.receiver, fresh, now)
		if !secureWireSameSession(*tc.receiver.sessions[id], before) {
			t.Fatal("rewrapped replay changed the session")
		}
	}
}

func TestSecureWireExpiryAndRestart(t *testing.T) {
	a, b, now := secureTestPair()
	id, request, reply := secureWireOpen(t, a, b, now)
	data := secureWireSend(t, a, b, id, []byte("old confirmation"), now)
	before := *b.sessions[id]
	secureWireReject(t, b, request, now.Add(time.Minute))
	secureWireReject(t, a, reply, now.Add(time.Minute))
	if !secureWireSameSession(*b.sessions[id], before) {
		t.Fatal("old request replaced or renewed a live session")
	}
	later := now.Add(10 * time.Minute)
	secureWireReject(t, b, data, later)
	if len(b.sessions) != 0 {
		t.Fatal("expired wire data retained a session")
	}
	oldInner, err := a.unwrap(reply, later)
	if err != nil {
		t.Fatal(err)
	}
	for _, receiver := range []*secure{b, newSecure(b.private, []wgtypes.Key{a.public})} {
		event, err := receiver.Receive(request, later)
		if err != nil || event.Peer != a.public || event.ID != id || event.Ready || event.Body != nil || len(event.Reply) != 512 {
			t.Fatal("old request bypassed fresh confirmation after expiry or restart:", err)
		}
		session := receiver.sessions[id]
		if session == nil || session.ready || session.expires != later.Add(10*time.Second) || session.window != 0 {
			t.Fatal("old request did not create only short-lived, unconfirmed state")
		}
		inner, err := a.unwrap(event.Reply, later)
		if err != nil || bytes.Equal(inner, oldInner) {
			t.Fatal("old request reused the Noise response, not just a new envelope:", err)
		}
		secureWireReject(t, receiver, data, later)
		if wire, err := receiver.Seal(id, []byte("not confirmed"), later); err == nil || wire != nil {
			t.Fatal("old request permitted application data")
		}
		receiver.Prune(nil, later.Add(10*time.Second))
		if len(receiver.sessions) != 0 {
			t.Fatal("old request's unconfirmed session did not expire")
		}
	}
	// A response cannot restore an expired initiating session either.
	a, b, now = secureTestPair()
	_, request, err = a.Start(b.public, now)
	if err != nil {
		t.Fatal(err)
	}
	event, err := b.Receive(request, now)
	if err != nil {
		t.Fatal(err)
	}
	secureWireReject(t, a, event.Reply, now.Add(10*time.Second))
	if len(a.sessions) != 0 {
		t.Fatal("late wire response restored an expired initiator")
	}
}

func TestSecureWireRejectsPlaintextVersions(t *testing.T) {
	for _, version := range []byte{1, 2} {
		t.Run(fmt.Sprint(version), func(t *testing.T) {
			a, b, now := secureTestPair()
			id, inner, err := a.start(b.public, now)
			if err != nil {
				t.Fatal(err)
			}
			plain := bytes.Clone(inner)
			if version == 1 {
				header := secureHeader(secureRequest, a.public, b.public, id, 0)
				replyHeader := secureHeader(secureReply, b.public, a.public, id, 0)
				header[0], replyHeader[0] = 1, 1
				prologue := append([]byte("wireguard-mesh/v1"), header...)
				prologue = append(prologue, replyHeader...)
				hs, err := noise.NewHandshakeState(noise.Config{
					CipherSuite: noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashBLAKE2s),
					Pattern:     noise.HandshakeIK, Initiator: true, Prologue: prologue, Random: a.random,
					StaticKeypair: noise.DHKey{Private: a.private[:], Public: a.public[:]}, PeerStatic: b.public[:],
				})
				if err != nil {
					t.Fatal(err)
				}
				plain, _, _, err = hs.WriteMessage(header, nil)
				if err != nil {
					t.Fatal(err)
				}
			}
			padded := make([]byte, 512)
			copy(padded, plain)
			for _, wire := range [][]byte{plain, padded} {
				secureWireReject(t, b, wire, now)
			}
			if len(b.sessions) != 0 || b.global != (secureRate{}) || *b.peers[a.public] != (secureRate{}) {
				t.Fatal("plaintext packet reached an inner fallback")
			}
			wire, err := a.wrap(b.public, inner)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := b.Receive(wire, now); err != nil {
				t.Fatal("plaintext rejection prevented a valid envelope:", err)
			}
		})
	}
}

func TestSecureWireEntropyFailure(t *testing.T) {
	for _, operation := range []string{"Start", "reply", "Seal"} {
		for _, nonceBytes := range []int{0, 23} {
			t.Run(fmt.Sprintf("%s/nonce-bytes-%d", operation, nonceBytes), func(t *testing.T) {
				a, b, now := secureTestPair()
				live, _, _ := secureWireOpen(t, a, b, now)
				secureWireSend(t, a, b, live, []byte("keep the live session"), now)
				// Both endpoints also retain an unrelated pending session.
				if _, _, err := a.Start(b.public, now); err != nil {
					t.Fatal(err)
				}
				if _, _, err := b.Start(a.public, now); err != nil {
					t.Fatal(err)
				}
				s := a
				var request []byte
				var failed [16]byte
				var err error
				if operation == "reply" {
					s = b
					failed, request, err = a.Start(b.public, now)
					if err != nil {
						t.Fatal(err)
					}
				}
				before := make(map[[16]byte]secureSession)
				for id, session := range s.sessions {
					before[id] = *session
				}
				serial, next, random := s.serial, s.sessions[live].next, s.random
				available := nonceBytes
				if operation != "Seal" {
					available += 32 // Allow the Noise ephemeral seed, then fail inside wrap.
				}
				limited := &io.LimitedReader{R: random, N: int64(available)}
				s.random = limited
				var wire []byte
				switch operation {
				case "Start":
					failed, wire, err = s.Start(b.public, now)
					serial++
					if failed == ([16]byte{}) {
						t.Fatal("Start failed before allocating its ID")
					}
				case "reply":
					var event secureEvent
					event, err = s.Receive(request, now)
					if !reflect.DeepEqual(event, secureEvent{}) {
						t.Fatal("reply entropy failure exposed an event")
					}
				case "Seal":
					wire, err = s.Seal(live, []byte("lost outer nonce"), now)
					want := before[live]
					want.next++
					before[live] = want
				}
				if (!errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF)) || wire != nil || limited.N != 0 {
					t.Fatal("did not fail at outer nonce generation:", err)
				}
				if s.serial != serial || len(s.sessions) != len(before) || (operation != "Seal" && s.sessions[failed] != nil) {
					t.Fatal("outer entropy failure retained new state or did not preserve the serial")
				}
				for id, want := range before {
					if got := s.sessions[id]; got == nil || !secureWireSameSession(*got, want) {
						t.Fatal("outer entropy failure changed another session or reused the inner nonce")
					}
				}
				s.random = random
				switch operation {
				case "Start":
					id, _, err := s.Start(b.public, now)
					if err != nil || id == failed || s.serial != serial+1 {
						t.Fatal("Start reused a burned ID or failed to recover:", err)
					}
				case "reply":
					event, err := b.Receive(request, now)
					if err != nil || event.Ready || len(event.Reply) != 512 {
						t.Fatal("reply failure prevented a retry:", err)
					}
					if _, err := a.Receive(event.Reply, now); err != nil {
						t.Fatal(err)
					}
					secureWireSend(t, a, b, failed, []byte("retry confirmed"), now)
				case "Seal":
					wire := secureWireSend(t, a, b, live, []byte("counter after failure"), now)
					inner, err := b.unwrap(wire, now)
					if err != nil || binary.BigEndian.Uint64(inner[82:90]) != next+1 {
						t.Fatal("Seal reused the consumed inner nonce:", err)
					}
				}
			})
		}
	}
}

func TestSecureWire128PeerLoad(t *testing.T) {
	if secureEnvelopeBudget != 131072 {
		t.Fatal("unexpected envelope attempt budget")
	}
	keys := make([]wgtypes.Key, 128)
	for i := range keys {
		keys[i] = secureTestKey(byte(i + 1)).PublicKey()
	}
	hub := newSecure(secureTestKey(200), keys)
	if len(hub.peers) != 128 || len(hub.envelopes) != 128 {
		t.Fatal("constructor did not retain 128 configured peers")
	}
	peers, ids := make([]*secure, 128), make([][16]byte, 128)
	now := time.Unix(1000, 0)
	for i := range peers {
		peers[i] = newSecure(secureTestKey(byte(i+1)), []wgtypes.Key{hub.public})
		at := now.Add(time.Duration(i/64) * time.Second)
		ids[i], _, _ = secureWireOpen(t, peers[i], hub, at)
		secureWireSend(t, peers[i], hub, ids[i], []byte("confirm before load"), at)
	}
	// A real packet to another recipient costs all 128 unsuccessful key attempts.
	other := secureTestKey(201).PublicKey()
	sender := newSecure(secureTestKey(1), []wgtypes.Key{other})
	_, unaddressed, err := sender.Start(other, now)
	if err != nil {
		t.Fatal(err)
	}
	// This checks only the stated traffic volume, not a flooded 100 ms broadcast mesh.
	for pass := 0; pass < 2; pass++ {
		at := now.Add(time.Duration(3+pass) * time.Second)
		attempts := 0
		for i := 0; i < 512; i++ {
			before := hub.openRate.used
			if i == 0 {
				before = 0 // The first packet opens a new fixed window.
			}
			p := i % len(peers)
			secureWireSend(t, peers[p], hub, ids[p], []byte(fmt.Sprintf("pass %d packet %d", pass, i)), at)
			used := hub.openRate.used - before
			if used < 1 || used > 128 {
				t.Fatalf("addressed packet charged %d attempts", used)
			}
			attempts += used
			if i%2 == 0 {
				before = hub.openRate.used
				secureWireReject(t, hub, unaddressed, at)
				if hub.openRate.used-before != 128 {
					t.Fatal("unaddressed packet did not charge every configured receive key")
				}
				attempts += 128
			}
		}
		if hub.openRate.used != attempts || attempts > (512+256)*128 || attempts >= secureEnvelopeBudget || len(hub.sessions) != 128 {
			t.Fatalf("load exceeded its attempt bound or changed session count: %d attempts", attempts)
		}
		t.Logf("pass %d: 512 valid data packets and 256 unaddressed frames, %d/131072 attempts", pass, attempts)
	}
}

func TestSecureWireAttemptBudgetExhaustionAndRecovery(t *testing.T) {
	a, b, now := secureTestPair()
	id, _, _ := secureWireOpen(t, a, b, now)
	at := now.Add(time.Second)
	secureWireSend(t, a, b, id, []byte("successful opens also count"), at)
	if b.openRate.used != 1 || b.openRate.until != at.Add(time.Second) {
		t.Fatal("successful open did not start and charge the fixed window")
	}
	data, err := a.Seal(id, []byte("accept after recovery"), at)
	if err != nil {
		t.Fatal(err)
	}
	before, global, peerRate := *b.sessions[id], b.global, *b.peers[a.public]
	garbage := make([]byte, 512)
	for i := 1; i < secureEnvelopeBudget; i++ {
		secureWireReject(t, b, garbage, at)
		if b.openRate.used != i+1 {
			t.Fatal("failed AEAD open was not charged")
		}
	}
	for _, when := range []time.Time{at, at.Add(time.Second - time.Nanosecond)} {
		secureWireReject(t, b, data, when)
		secureWireReject(t, b, garbage, when)
	}
	if b.openRate.used != secureEnvelopeBudget || b.openRate.until != at.Add(time.Second) || b.global != global || *b.peers[a.public] != peerRate || len(b.sessions) != 1 || !secureWireSameSession(*b.sessions[id], before) {
		t.Fatal("exhausted budget allowed inner processing, overran, or moved the window")
	}
	event, err := b.Receive(data, at.Add(time.Second))
	if err != nil || !event.Ready || event.ID != id || event.Peer != a.public || string(event.Body) != "accept after recovery" || event.Reply != nil || b.openRate.used != 1 {
		t.Fatal("fixed window did not recover without consuming the rejected inner nonce:", err)
	}
	secureWireReject(t, b, data, at.Add(time.Second))
	if b.openRate.used != 2 {
		t.Fatal("authenticated inner replay did not charge an outer open")
	}
}

func FuzzSecureReceive(f *testing.F) {
	a, b, now := secureTestPair()
	id, request, reply := secureWireOpen(f, a, b, now)
	data, err := a.Seal(id, []byte("fuzz wire transport"), now)
	if err != nil {
		f.Fatal(err)
	}
	for _, wire := range [][]byte{request, reply, data} {
		f.Add(wire)
		for _, offset := range []int{0, 23, 24, 255, 495, 511} {
			bad := bytes.Clone(wire)
			bad[offset] ^= 1
			f.Add(bad)
		}
		for _, n := range []int{0, 1, 23, 24, 40, 90, 138, 186, 470, 511} {
			f.Add(bytes.Clone(wire[:n]))
		}
		f.Add(append(bytes.Clone(wire), 0))
	}
	random := mathrand.New(mathrand.NewSource(33))
	for _, n := range []int{24, 90, 470, 512, 513, 1024} {
		garbage := make([]byte, n)
		if _, err := random.Read(garbage); err != nil {
			f.Fatal(err)
		}
		f.Add(garbage)
	}
	f.Add(make([]byte, 512))
	f.Fuzz(func(t *testing.T, wire []byte) {
		a, b, now := secureTestPair()
		id, _, _ := secureWireOpen(t, a, b, now)
		pending, _, _ := secureTestPair()
		if _, _, err := pending.Start(b.public, now); err != nil {
			t.Fatal(err)
		}
		fresh := newSecure(b.private, []wgtypes.Key{a.public})
		for _, receiver := range []*secure{a, b, pending, fresh} {
			wantRequest := receiver == fresh && bytes.Equal(wire, request)
			wantReply := receiver == pending && bytes.Equal(wire, reply)
			wantData := receiver == b && bytes.Equal(wire, data)
			wantSuccess := wantRequest || wantReply || wantData
			event, err := receiver.Receive(wire, now)
			if err != nil {
				if wantSuccess || !reflect.DeepEqual(event, secureEvent{}) {
					t.Fatal("valid fuzz seed rejected or error exposed an event:", err)
				}
				continue
			}
			// Only these recorded packets authenticate in these deterministic session states.
			if !wantSuccess || len(wire) != 512 || receiver.peers[event.Peer] == nil || event.ID != id || receiver.sessions[id] == nil {
				t.Fatal("invalid successful public-wire fuzz event")
			}
			if wantRequest {
				if event.Peer != a.public || event.Ready || event.Body != nil || len(event.Reply) != 512 || receiver.sessions[id].ready {
					t.Fatal("invalid fuzz request event")
				}
			} else if wantReply {
				if event.Peer != b.public || !event.Ready || event.Body != nil || event.Reply != nil {
					t.Fatal("invalid fuzz reply event")
				}
			} else if event.Peer != a.public || !event.Ready || string(event.Body) != "fuzz wire transport" || event.Reply != nil {
				t.Fatal("invalid fuzz data event")
			}
			secureWireReject(t, receiver, wire, now)
		}
	})
}
