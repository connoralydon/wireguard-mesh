package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func writeTestPSK(t *testing.T, path, text string, at time.Time) {
	t.Helper()
	if err := os.WriteFile(path, []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, at, at); err != nil {
		t.Fatal(err)
	}
}

func TestReadPSKFile(t *testing.T) {
	key, now := controlTestKey(77), time.Unix(1000, 0)
	for _, tc := range []struct {
		name, text string
		mode       os.FileMode
		age        time.Duration
		want       bool
	}{
		{"raw", key.String(), 0600, 0, true},
		{"Rosenpass", key.String() + "\n", 0600, 0, true},
		{"group read", key.String(), 0640, 0, true},
		{"read only", key.String(), 0400, 0, true},
		{"group read only", key.String(), 0440, 0, true},
		{"before expiry", key.String(), 0600, 3*time.Minute - time.Nanosecond, true},
		{"expired", key.String(), 0600, 3 * time.Minute, false},
		{"old", key.String(), 0600, 4 * time.Minute, false},
		{"future", key.String(), 0600, -time.Nanosecond, false},
		{"empty", "", 0600, 0, false},
		{"zero", (wgtypes.Key{}).String() + "\n", 0600, 0, false},
		{"partial", key.String()[:43], 0600, 0, false},
		{"malformed", strings.Repeat("!", 44), 0600, 0, false},
		{"noncanonical", key.String()[:42] + "1=", 0600, 0, false},
		{"binary", string(key[:]), 0600, 0, false},
		{"leading space", " " + key.String(), 0600, 0, false},
		{"trailing space", key.String() + " ", 0600, 0, false},
		{"embedded newline", key.String()[:20] + "\n" + key.String()[20:], 0600, 0, false},
		{"extra newline", key.String() + "\n\n", 0600, 0, false},
		{"oversized", strings.Repeat("A", 1<<20), 0600, 0, false},
		{"world read", key.String(), 0644, 0, false},
		{"world write", key.String(), 0602, 0, false},
		{"group write", key.String(), 0660, 0, false},
		{"execute", key.String(), 0700, 0, false},
		{"setuid", key.String(), 0600 | os.ModeSetuid, 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "psk")
			writeTestPSK(t, path, tc.text, now.Add(-tc.age))
			if err := os.Chmod(path, tc.mode); err != nil {
				if tc.mode&os.ModeSetuid != 0 && errors.Is(err, os.ErrPermission) {
					t.Skip("sandbox prohibits setuid test fixtures")
				}
				t.Fatal(err)
			}
			got, err := readPSKFile(peerSpec{PresharedKeyFile: path}, now)
			if tc.want {
				if err != nil || got != key {
					t.Fatal("valid file rejected:", err)
				}
			} else if err != errPSKFile || got != (wgtypes.Key{}) {
				t.Fatal("invalid file accepted or returned an unsafe error")
			}
		})
	}
	t.Run("configured age", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "psk")
		writeTestPSK(t, path, key.String(), now.Add(-150*time.Second))
		if _, err := readPSKFile(peerSpec{PresharedKeyFile: path, PresharedKeyMaxAge: new(duration(150 * time.Second))}, now); err == nil {
			t.Fatal("configured expiry was ignored")
		}
	})
}

func TestReadPSKFileType(t *testing.T) {
	for _, kind := range []string{"missing", "symlink", "directory", "FIFO", "device"} {
		t.Run(kind, func(t *testing.T) {
			path, now := filepath.Join(t.TempDir(), "psk"), time.Now()
			var err error
			switch kind {
			case "symlink":
				writeTestPSK(t, path+"-target", controlTestKey(7).String(), now)
				err = os.Symlink(path+"-target", path)
			case "directory":
				err = os.Mkdir(path, 0700)
			case "FIFO":
				err = syscall.Mkfifo(path, 0600)
			case "device":
				path = "/dev/null"
			}
			if err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() {
				_, err := readPSKFile(peerSpec{PresharedKeyFile: path}, now)
				done <- err
			}()
			select {
			case err := <-done:
				if err != errPSKFile {
					t.Fatal("unsafe file type accepted")
				}
			case <-time.After(time.Second):
				t.Fatal("file read blocked")
			}
		})
	}
}

func TestReadPSKFileProducerOwnership(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("ownership changes require root")
	}
	for _, tc := range []struct {
		name     string
		uid, gid int
		mode     os.FileMode
		want     bool
	}{
		{"root", 0, 12345, 0600, true},
		{"producer mesh group", 12345, os.Getegid(), 0640, true},
		{"producer without group read", 12345, os.Getegid(), 0600, false},
		{"producer untrusted group", 12345, 12345, 0640, false},
		{"producer writable group", 12345, os.Getegid(), 0660, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path, now := filepath.Join(t.TempDir(), "psk"), time.Now()
			writeTestPSK(t, path, controlTestKey(7).String(), now)
			if err := os.Chown(path, tc.uid, tc.gid); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(path, tc.mode); err != nil {
				t.Fatal(err)
			}
			_, err := readPSKFile(peerSpec{PresharedKeyFile: path}, now)
			if (err == nil) != tc.want {
				t.Fatal("incorrect ownership decision:", err)
			}
		})
	}
}

func meshPSKFiles(t *testing.T, s *meshSimulation, present bool) {
	t.Helper()
	for _, n := range s.nodes {
		n.p.spec.PresharedKeyFile = filepath.Join(t.TempDir(), "peer.psk")
		n.p.spec.psk = wgtypes.Key{}
		if present {
			writeTestPSK(t, n.p.spec.PresharedKeyFile, controlTestKey(33).String(), s.now)
		}
	}
}

func TestMeshPSKFileArrivalAndRotation(t *testing.T) {
	s := newMeshSimulation(t)
	meshPSKFiles(t, s, false)
	s.run(35 * time.Second)
	for _, n := range s.nodes {
		if n.applies != 0 || n.p.phase != "" {
			t.Fatal("missing files permitted a direct trial")
		}
	}
	key := controlTestKey(33)
	writeTestPSK(t, s.nodes[0].p.spec.PresharedKeyFile, key.String(), s.now)
	s.run(10 * time.Second)
	for _, n := range s.nodes {
		if n.applies != 0 {
			t.Fatal("one missing key permitted a direct route")
		}
	}
	writeTestPSK(t, s.nodes[1].p.spec.PresharedKeyFile, key.String(), s.now)
	s.run(65 * time.Second)
	s.active()
	for _, n := range s.nodes {
		if n.appliedPSK != key || n.applies != 1 {
			t.Fatal("initial file key was not installed exactly once")
		}
		// Refresh the same key without a route change.
		writeTestPSK(t, n.p.spec.PresharedKeyFile, key.String(), s.now)
	}
	s.run(10 * time.Second)
	for _, n := range s.nodes {
		if n.applies != 1 || n.restores > 1 || !n.applied {
			t.Fatal("unchanged key caused route changes")
		}
	}
	key = controlTestKey(44)
	writeTestPSK(t, s.nodes[0].p.spec.PresharedKeyFile, key.String(), s.now)
	s.run(8 * time.Second)
	for _, n := range s.nodes {
		if n.applied || n.p.phase != "" {
			t.Fatal("asymmetric rekey did not restore both relay routes")
		}
	}
	writeTestPSK(t, s.nodes[1].p.spec.PresharedKeyFile, key.String(), s.now)
	s.run(80 * time.Second)
	s.active()
	for _, n := range s.nodes {
		if n.appliedPSK != key || n.applies != 2 {
			t.Fatal("rotated key was not installed by a new trial")
		}
	}
}

func TestMeshPSKFileLoss(t *testing.T) {
	for _, mode := range []string{"missing", "partial", "zero", "expired"} {
		t.Run(mode, func(t *testing.T) {
			s := newMeshSimulation(t)
			meshPSKFiles(t, s, true)
			s.run(35 * time.Second)
			s.active()
			n := s.nodes[0]
			path := n.p.spec.PresharedKeyFile
			switch mode {
			case "missing":
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			case "partial":
				writeTestPSK(t, path, "partial", s.now)
			case "zero":
				writeTestPSK(t, path, (wgtypes.Key{}).String(), s.now)
			case "expired":
				writeTestPSK(t, path, n.p.spec.psk.String(), s.now.Add(-3*time.Minute))
			}
			s.run(50 * time.Second)
			for _, node := range s.nodes {
				if node.applied || node.applies != 1 {
					t.Fatal("invalid file did not retain the relay path")
				}
			}
			if n.p.pskValid || n.p.spec.psk != (wgtypes.Key{}) {
				t.Fatal("invalid file retained a cached key")
			}
		})
	}
}

func TestMeshPSKFileMismatch(t *testing.T) {
	s := newMeshSimulation(t)
	meshPSKFiles(t, s, true)
	writeTestPSK(t, s.nodes[0].p.spec.PresharedKeyFile, controlTestKey(44).String(), s.now)
	s.run(25 * time.Second)
	for _, n := range s.nodes {
		if n.applies != 0 || n.applied || n.p.phase != "" {
			t.Fatal("different file keys passed key confirmation")
		}
	}
}

func TestMeshPSKFileChangeCancelsCoordination(t *testing.T) {
	for _, op := range []string{"prepare", "ready", "commit", "apply"} {
		for _, valid := range []bool{false, true} {
			t.Run(op+"/"+map[bool]string{false: "missing", true: "changed"}[valid], func(t *testing.T) {
				s := newMeshSimulation(t)
				meshPSKFiles(t, s, true)
				s.run(18 * time.Second)
				n := s.nodes[0]
				candidate, token := n.p.selected, n.p.trial
				if candidate == nil || !n.applied {
					t.Fatal("test needs a direct trial")
				}
				if valid {
					writeTestPSK(t, n.p.spec.PresharedKeyFile, controlTestKey(44).String(), s.now)
				} else if err := os.Remove(n.p.spec.PresharedKeyFile); err != nil {
					t.Fatal(err)
				}
				var err error
				if op == "apply" {
					err = n.m.apply(n.p, s.now)
				} else {
					err = n.m.coordinate(n.p, candidate, message{Op: op, Token: token, Port: n.other.m.wgPort}, s.now)
				}
				if err != nil || n.applies != 1 || n.applied || n.p.selected != nil || n.p.phase != "" {
					t.Fatal("key change did not cancel the pending coordination:", err)
				}
			})
		}
	}
}

type failingPSKRestore struct {
	routeControl
	err error
}

func (c failingPSKRestore) Restore(wgtypes.Key) error { return c.err }

func TestMeshPSKFileRestoreConflict(t *testing.T) {
	s := newMeshSimulation(t)
	meshPSKFiles(t, s, true)
	s.run(35 * time.Second)
	s.active()
	n := s.nodes[0]
	old := n.p.spec.psk
	writeTestPSK(t, n.p.spec.PresharedKeyFile, controlTestKey(44).String(), s.now)
	conflict := errors.New("external WireGuard edit")
	n.m.control = failingPSKRestore{n.m.control, conflict}
	if _, err := n.m.pollPSK(n.p, s.now); !errors.Is(err, conflict) {
		t.Fatal("restore conflict was ignored:", err)
	}
	if n.p.spec.psk != old || !n.p.pskValid || !n.applied || n.p.phase != "active" || n.applies != 1 {
		t.Fatal("failed restoration replaced the owned PSK or route state")
	}
}
