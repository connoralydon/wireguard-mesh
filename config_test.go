package main

import (
	"fmt"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestConfigDefaults(t *testing.T) {
	key, psk := controlTestKey(7).PublicKey(), controlTestKey(9)
	text := fmt.Sprintf(`{"address":"10.0.0.2","peers":[{"public_key":%q,"ip":"10.0.0.3","preshared_key":%q}]}`, key.String(), psk.String())
	c, err := readConfig(strings.NewReader(text))
	if err != nil {
		t.Fatal(err)
	}
	want := config{
		Address: netip.MustParseAddr("10.0.0.2"),
		Peers:   []peerSpec{{PublicKey: key.String(), IP: netip.MustParseAddr("10.0.0.3"), PresharedKey: psk.String(), key: key, psk: psk}},
		Port:    51821, Multicast4: netip.MustParseAddr("239.255.77.77"), Multicast6: netip.MustParseAddr("ff12::5747:4d53"),
		Discovery: duration(time.Minute), BroadcastAfter: duration(5 * time.Minute),
		Probe: duration(time.Second), Window: duration(15 * time.Second), Failure: duration(5 * time.Second),
		Cooldown: duration(30 * time.Second), MinGain: duration(2 * time.Millisecond), Gain: 0.2,
	}
	if !reflect.DeepEqual(c, want) {
		t.Fatal("configuration defaults or parsed peer keys differ")
	}
	text = strings.ReplaceAll(text, "10.0.0.2", "fd00::2")
	text = strings.ReplaceAll(text, "10.0.0.3", "fd00::3")
	if _, err := readConfig(strings.NewReader(text)); err != nil {
		t.Fatal("valid IPv6 configuration:", err)
	}
}

func TestConfigRejectsInvalid(t *testing.T) {
	peer := fmt.Sprintf(`{"public_key":%q,"ip":"10.0.0.3"}`, controlTestKey(7).PublicKey().String())
	base := `"address":"10.0.0.2","peers":[` + peer + `]`
	for _, field := range []string{
		`"unknown":true`, `"port":1023`, `"port":65536`, `"address":"0.0.0.0"`,
		`"address":"fe80::2%lan0"`, `"address":"::ffff:10.0.0.2"`, `"address":"fd00::2"`,
		`"multicast4":"192.0.2.1"`, `"multicast6":"ff05::1"`, `"multicast6":"ff02::1%lan0"`,
		`"probe_interval":"99ms"`, `"probe_interval":"2s"`, `"probe_interval":"bad"`,
		`"latency_window":"2s"`, `"latency_window":"61s"`, `"failure_timeout":"1s"`, `"failure_timeout":"16s"`,
		`"discovery_interval":"500ms"`, `"discovery_interval":"6m"`, `"broadcast_after":"0s"`,
		`"cooldown":"0s"`, `"minimum_gain":"-1ms"`, `"minimum_gain_fraction":-0.1`, `"minimum_gain_fraction":1`,
		`"peers":[]`, `"peers":[` + peer + `,` + peer + `]`,
		`"peers":[{"public_key":"SECRET","ip":"10.0.0.3"}]`,
		`"peers":[` + strings.Replace(peer, "10.0.0.3", "10.0.0.2", 1) + `]`,
		`"peers":[` + strings.TrimSuffix(peer, "}") + `,"preshared_key":"SECRET"}]`,
	} {
		t.Run(field, func(t *testing.T) {
			// JSON permits repeated names; the final value replaces the valid fixture field.
			_, err := readConfig(strings.NewReader(`{` + base + `,` + field + `}`))
			if err == nil || strings.Contains(err.Error(), "SECRET") {
				t.Fatal("invalid configuration accepted or secret included in error")
			}
		})
	}
	for _, text := range []string{`{`, `{}`, `{` + base + `} {}`, `{` + base + `} trailing`} {
		if _, err := readConfig(strings.NewReader(text)); err == nil {
			t.Fatal("invalid or trailing JSON accepted")
		}
	}
}

func TestValidName(t *testing.T) {
	for _, name := range []string{"wg0", "WG-0_test.1", "123456789012345"} {
		if !validName(name) {
			t.Errorf("valid interface name rejected: %q", name)
		}
	}
	for _, name := range []string{"", ".", "..", "1234567890123456", "wg/0", "wg 0", "wg\n0", "wg\x00", "wg\u00e9"} {
		if validName(name) {
			t.Errorf("invalid interface name accepted: %q", name)
		}
	}
}

func TestConfigSizeLimit(t *testing.T) {
	text := fmt.Sprintf(`{"address":"10.0.0.2","peers":[{"public_key":%q,"ip":"10.0.0.3"}]}`, controlTestKey(7).PublicKey().String())
	text += strings.Repeat(" ", (1<<20)-len(text)) + "trailing"
	if _, err := readConfig(strings.NewReader(text)); err == nil {
		t.Fatal("oversized input with trailing data was accepted")
	}
}

func TestConfigMaximumWindow(t *testing.T) {
	text := fmt.Sprintf(`{"address":"10.0.0.2","peers":[{"public_key":%q,"ip":"10.0.0.3"}],"latency_window":"60s"}`, controlTestKey(7).PublicKey().String())
	c, err := readConfig(strings.NewReader(text))
	if err != nil || c.Window != duration(time.Minute) {
		t.Fatal("maximum supported measurement window was not accepted:", err)
	}
}

func TestConfigPSKFile(t *testing.T) {
	for _, tc := range []struct {
		fields string
		age    time.Duration
	}{
		{`"preshared_key_file":"/run/rosenpass/peer.key"`, 3 * time.Minute},
		{`"preshared_key_file":"/run/rosenpass/peer.key","preshared_key_max_age":"130s"`, 130 * time.Second},
		{`"preshared_key_file":"/run/rosenpass/peer.key","preshared_key_max_age":"150s"`, 150 * time.Second},
		{`"preshared_key_file":"/run/rosenpass/peer.key","preshared_key_max_age":"3m"`, 3 * time.Minute},
		{`"preshared_key_file":"relative.key"`, 0},
		{`"preshared_key_file":"/run/rosenpass/peer.key","preshared_key":"SECRET"`, 0},
		{`"preshared_key_file":"/run/rosenpass/peer.key","preshared_key_max_age":"0s"`, 0},
		{`"preshared_key_file":"/run/rosenpass/peer.key","preshared_key_max_age":"-1s"`, 0},
		{`"preshared_key_file":"/run/rosenpass/peer.key","preshared_key_max_age":"129s"`, 0},
		{`"preshared_key_file":"/run/rosenpass/peer.key","preshared_key_max_age":"181s"`, 0},
		{`"preshared_key_file":"/run/rosenpass/peer.key","preshared_key_max_age":"SECRET"`, 0},
		{`"preshared_key_max_age":"3m"`, 0},
	} {
		t.Run(tc.fields, func(t *testing.T) {
			text := fmt.Sprintf(`{"address":"10.0.0.2","peers":[{"public_key":%q,"ip":"10.0.0.3",%s}]}`, controlTestKey(7).PublicKey().String(), tc.fields)
			c, err := readConfig(strings.NewReader(text))
			if tc.age == 0 {
				if err == nil || strings.Contains(err.Error(), "SECRET") {
					t.Fatal("invalid file configuration accepted or secret included in error")
				}
			} else if err != nil || c.Peers[0].PresharedKeyMaxAge == nil || time.Duration(*c.Peers[0].PresharedKeyMaxAge) != tc.age || c.Peers[0].psk != controlTestKey(0) {
				t.Fatal("file configuration was not accepted without reading the runtime file:", err)
			}
		})
	}
}
