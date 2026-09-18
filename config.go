package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"path/filepath"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type duration time.Duration

func (d *duration) UnmarshalText(text []byte) error {
	v, err := time.ParseDuration(string(text))
	*d = duration(v)
	return err
}

type peerSpec struct {
	PublicKey          string     `json:"public_key"`
	IP                 netip.Addr `json:"ip"`
	PresharedKey       string     `json:"preshared_key,omitempty"`
	PresharedKeyFile   string     `json:"preshared_key_file,omitempty"`
	PresharedKeyMaxAge *duration  `json:"preshared_key_max_age,omitempty"`
	key, psk           wgtypes.Key
}

type config struct {
	Address        netip.Addr `json:"address"`
	Peers          []peerSpec `json:"peers"`
	Port           uint16     `json:"port"`
	Multicast4     netip.Addr `json:"multicast4"`
	Multicast6     netip.Addr `json:"multicast6"`
	Include        []string   `json:"include"`
	Exclude        []string   `json:"exclude"`
	Discovery      duration   `json:"discovery_interval"`
	BroadcastAfter duration   `json:"broadcast_after"`
	Probe          duration   `json:"probe_interval"`
	Window         duration   `json:"latency_window"`
	Failure        duration   `json:"failure_timeout"`
	Cooldown       duration   `json:"cooldown"`
	MinGain        duration   `json:"minimum_gain"`
	Gain           float64    `json:"minimum_gain_fraction"`
}

func defaults() config {
	return config{
		Port: 51823, Multicast4: netip.MustParseAddr("239.255.77.77"),
		Multicast6: netip.MustParseAddr("ff12::5747:4d53"),
		Discovery:  duration(time.Minute), BroadcastAfter: duration(5 * time.Minute),
		Probe: duration(time.Second), Window: duration(15 * time.Second),
		Failure: duration(5 * time.Second), Cooldown: duration(30 * time.Second),
		MinGain: duration(2 * time.Millisecond), Gain: 0.2,
	}
}

func readConfig(r io.Reader) (config, error) {
	c := defaults()
	body, err := io.ReadAll(io.LimitReader(r, (1<<20)+1))
	if err != nil || len(body) > 1<<20 {
		return c, errors.New("configuration is unreadable or exceeds 1 MiB")
	}
	d := json.NewDecoder(bytes.NewReader(body))
	d.DisallowUnknownFields()
	if err := d.Decode(&c); err != nil {
		return c, errors.New("invalid configuration JSON") // Do not print secret input.
	}
	if d.Decode(new(any)) != io.EOF {
		return c, errors.New("trailing configuration data")
	}
	if !overlayAddress(c.Address) || len(c.Peers) == 0 || len(c.Peers) > 128 || c.Port < 1024 {
		return c, errors.New("set a tunnel address, 1–128 peers, and an unprivileged UDP port")
	}
	if !c.Multicast4.Is4() || !c.Multicast4.IsMulticast() || !c.Multicast6.Is6() || !c.Multicast6.IsLinkLocalMulticast() || c.Multicast6.Zone() != "" {
		return c, errors.New("set an IPv4 multicast group and an IPv6 link-local multicast group")
	}
	if c.Probe < duration(100*time.Millisecond) || c.Probe > duration(time.Second) ||
		c.Window < 3*c.Probe || c.Window > duration(time.Minute) ||
		c.Failure < 2*c.Probe || c.Failure > c.Window ||
		c.Discovery < c.Probe || c.Discovery > duration(5*time.Minute) ||
		c.BroadcastAfter < c.Probe || c.Cooldown < c.Probe || c.MinGain < 0 || c.Gain < 0 || c.Gain >= 1 {
		return c, errors.New("invalid timing or improvement policy; see README")
	}
	keys, ips := map[wgtypes.Key]bool{}, map[netip.Addr]bool{c.Address: true}
	for i := range c.Peers {
		p := &c.Peers[i]
		var err error
		p.key, err = wgtypes.ParseKey(p.PublicKey)
		if err != nil || p.key == (wgtypes.Key{}) || keys[p.key] || ips[p.IP] || !overlayAddress(p.IP) || p.IP.Is4() != c.Address.Is4() {
			return c, fmt.Errorf("peer %d: invalid or duplicate key/address, or tunnel address family mismatch", i)
		}
		if p.PresharedKeyFile != "" {
			if !filepath.IsAbs(p.PresharedKeyFile) || p.PresharedKey != "" {
				return c, fmt.Errorf("peer %d: preshared_key_file must be absolute and excludes preshared_key", i)
			}
			if p.PresharedKeyMaxAge == nil {
				p.PresharedKeyMaxAge = new(duration(3 * time.Minute))
			}
		} else if p.PresharedKeyMaxAge != nil {
			return c, fmt.Errorf("peer %d: preshared_key_max_age requires preshared_key_file", i)
		}
		if p.PresharedKeyMaxAge != nil && (*p.PresharedKeyMaxAge < duration(130*time.Second) || *p.PresharedKeyMaxAge > duration(3*time.Minute)) {
			return c, fmt.Errorf("peer %d: preshared_key_max_age must be between 130s and 3m", i)
		}
		if p.PresharedKey != "" {
			p.psk, err = wgtypes.ParseKey(p.PresharedKey)
			if err != nil || p.psk == (wgtypes.Key{}) {
				return c, fmt.Errorf("peer %d: invalid preshared key", i)
			}
		}
		keys[p.key], ips[p.IP] = true, true
	}
	return c, nil
}

func overlayAddress(a netip.Addr) bool {
	return a.IsGlobalUnicast() && !a.Is4In6() && a.Zone() == ""
}

func (c config) groups() []netip.Addr { return []netip.Addr{c.Multicast4, c.Multicast6} }

func validName(s string) bool {
	if len(s) == 0 || len(s) > 15 || s == "." || s == ".." {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-' || r == '.') {
			return false
		}
	}
	return true
}
