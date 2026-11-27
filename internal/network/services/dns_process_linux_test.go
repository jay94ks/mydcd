// SPDX-License-Identifier: Apache-2.0

package services

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/network"
	"github.com/jay94ks/seafield/internal/storage"
	"github.com/jay94ks/seafield/internal/workload"
)

func TestDNSProcessIdentityRequiresOriginalExit(t *testing.T) {
	current, err := currentDNSProcess()
	if err != nil {
		t.Fatal(err)
	}
	if err = dnsOriginalProcessEnded(&current, current); err == nil {
		t.Fatal("live original accepted")
	}
	for _, name := range []string{"missing", "namespace", "start"} {
		t.Run(name, func(t *testing.T) {
			old := current
			pointer := &old
			switch name {
			case "missing":
				pointer = nil
			case "namespace":
				old.NamespaceInode++
			case "start":
				old.StartTicks = 0
			}
			if err := dnsOriginalProcessEnded(pointer, current); err == nil {
				t.Fatal("unknown original accepted")
			}
		})
	}
	reused := current
	reused.StartTicks++ // counterexample of a different original process at this PID
	if err = dnsOriginalProcessEnded(&reused, current); err != nil {
		t.Fatal("PID reuse retained the already gone original", err)
	}
	if _, err = dnsProcessStart([]byte("invalid proc stat")); err == nil {
		t.Fatal("malformed process start accepted")
	}
	raw, err := os.ReadFile("/proc/self/stat")
	if err != nil {
		t.Fatal(err)
	}
	end := strings.LastIndexByte(string(raw), ')')
	start, err := dnsProcessStart(append([]byte("1 (name with ) and spaces)"), raw[end+1:]...))
	if err != nil || start != current.StartTicks {
		t.Fatal("comm parsing", start, err)
	}
}

// A real child owns the actual DB and durable paired query. Policy/native facts
// are fixture input; this case proves process exit and atomic journal recovery,
// not a Docker/Bridge/socket or cluster authorization boundary.
func TestDNSOwnerUncleanSameDBChildExit(t *testing.T) {
	if path := os.Getenv("SFC_DNS_QUERY_CRASH_DB"); path != "" {
		n, err := network.OpenManager(path+".network", nil)
		if err != nil {
			t.Fatal(err)
		}
		w, err := workload.OpenManager(path+".workload", nil, n)
		if err != nil {
			t.Fatal(err)
		}
		boot, err := dnsNativeBoot()
		if err != nil {
			t.Fatal(err)
		}
		f := settingsServing(t)
		f.d.m.maxViews = f.m.maxSlots
		f, _ = settingsQuery(t, f, 200)
		f.m.boot = boot
		for id, view := range f.d.m.views {
			for token, origin := range view.Origins {
				origin.Boot = boot
				view.Origins[token] = origin
			}
			f.d.m.views[id] = view
		}
		// Changing the query's bound boot changes its opaque request ID; retain
		// the matching original user rather than submitting a second request.
		query := f.d.m.Queries()[0]
		for id, slot := range f.m.slots {
			for token := range slot.Users {
				slot.Users[token] = settingsDNSRequest(query)
			}
			f.m.slots[id] = slot
		}
		options := dnsCrashDBOptions(f, n, w)
		o, err := OpenDNSOwner(path, options)
		if err != nil {
			t.Fatal(err)
		}
		if err = o.save(f.m, f.d.m, false); err != nil {
			t.Fatal(err)
		}
		process, err := currentDNSProcess()
		if err != nil {
			t.Fatal(err)
		}
		if err = json.NewEncoder(os.Stdout).Encode(process); err != nil {
			t.Fatal(err)
		}
		_, _ = os.Stdin.Read(make([]byte, 1))
		t.Fatal("child must be explicitly killed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	path := filepath.Join(t.TempDir(), "dns.db")
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestDNSOwnerUncleanSameDBChildExit$", "-test.v")
	cmd.Env = append(os.Environ(), "SFC_DNS_QUERY_CRASH_DB="+path)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	defer stdin.Close()
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	waited := false
	defer func() {
		if !waited {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	}()
	scanner := bufio.NewScanner(stdout)
	var original dnsProcessIdentity
	for scanner.Scan() {
		if json.Unmarshal(scanner.Bytes(), &original) == nil && original.PID != 0 {
			break
		}
	}
	if original.PID != cmd.Process.Pid {
		t.Fatal("child identity", original, stderr.String())
	}
	current, err := currentDNSProcess()
	if err != nil {
		t.Fatal(err)
	}
	if err = dnsOriginalProcessEnded(&original, current); err == nil {
		t.Fatal("live child accepted")
	}
	if err = cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if err = cmd.Wait(); err == nil {
		t.Fatal("child exited cleanly")
	}
	waited = true
	if err = dnsOriginalProcessEnded(&original, current); err != nil {
		t.Fatal("explicit child exit", err)
	}
	db, err := storage.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := db.Get("dns-owner")
	_ = db.Close()
	if err != nil {
		t.Fatal(err)
	}
	var disk dnsOwnerDisk
	if err = json.Unmarshal(raw, &disk); err != nil || disk.Stopped || disk.Process == nil || *disk.Process != original {
		t.Fatal("original unclean disk", err)
	}
	before, err := DecodeSettings(disk.Settings)
	if err != nil {
		t.Fatal(err)
	}
	n, err := network.OpenManager(path+".network", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close()
	w, err := workload.OpenManager(path+".workload", nil, n)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	f := settingsServing(t)
	o, err := OpenDNSOwner(path, dnsCrashDBOptions(f, n, w))
	if err != nil {
		t.Fatal("same DB recovery", err)
	}
	defer o.Close()
	if len(o.dns.Queries()) != 0 || len(o.settings.slots) != len(before.slots) || len(o.settings.groups) != len(before.groups) || o.Status("first", "dns").Ready {
		t.Fatal("recovery lost dependencies or claimed ready")
	}
	for id, group := range before.groups {
		if !reflect.DeepEqual(group, o.settings.groups[id]) {
			t.Fatal("original group state/pins changed")
		}
	}
	if o.process != current || o.settings.Status("dns/first/dns").Users != 0 {
		t.Fatal("new process/paired release missing")
	}
	t.Log("actual child SIGKILL/Wait; same DB, original Settings operations/group pins, no fake Ready, paired query/user release")
}

func dnsCrashDBOptions(f settingsFixture, n *network.Manager, w *workload.Manager) DNSOwnerOptions {
	return DNSOwnerOptions{Cluster: f.d.f.a.cluster, Key: f.d.f.key, Network: n, Workload: w, Roots: f.d.m.protected, MaxViews: 16, MaxQueries: 8, MaxConnections: 4, IdleTimeout: time.Second,
		Current: func(context.Context, string, string) (DNSOwnerPolicy, error) { return DNSOwnerPolicy{}, ErrLease },
		Permit:  func(context.Context, DNSOwnerPolicy) error { return ErrLease },
	}
}

func TestDNSOwnerLegacyAndUnknownProcessPreserveOriginalDB(t *testing.T) {
	for _, name := range []string{"legacy-unclean", "live-process", "other-namespace", "other-boot", "legacy-clean"} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			n, err := network.OpenManager(filepath.Join(root, "network"), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer n.Close()
			w, err := workload.OpenManager(filepath.Join(root, "workload"), nil, n)
			if err != nil {
				t.Fatal(err)
			}
			defer w.Close()
			f := settingsServing(t)
			options := dnsCrashDBOptions(f, n, w)
			path := filepath.Join(root, "dns")
			o, err := OpenDNSOwner(path, options)
			if err != nil {
				t.Fatal(err)
			}
			if err = o.Close(); err != nil {
				t.Fatal(err)
			}
			db, err := storage.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			raw, err := db.Get("dns-owner")
			if err != nil {
				_ = db.Close()
				t.Fatal(err)
			}
			var disk dnsOwnerDisk
			if err = json.Unmarshal(raw, &disk); err != nil {
				_ = db.Close()
				t.Fatal(err)
			}
			disk.Stopped = false
			switch name {
			case "legacy-unclean":
				disk.Process = nil
			case "other-namespace":
				disk.Process.NamespaceInode++
			case "other-boot":
				disk.Boot[0]++
			case "legacy-clean":
				disk.Process = nil
				disk.Stopped = true
			}
			raw, err = json.Marshal(disk)
			if err == nil {
				err = db.Write(map[string][]byte{"dns-owner": raw})
			}
			_ = db.Close()
			if err != nil {
				t.Fatal(err)
			}
			o, err = OpenDNSOwner(path, options)
			if name == "legacy-clean" {
				if err != nil {
					t.Fatal("legacy clean pause lost compatibility", err)
				}
				if err = o.Close(); err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil {
				_ = o.Close()
				t.Fatal("unknown original process was adopted")
			}
			db, err = storage.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			after, err := db.Get("dns-owner")
			_ = db.Close()
			if err != nil || !bytes.Equal(raw, after) {
				t.Fatal("rejection rewrote original journal", err)
			}
		})
	}
}
