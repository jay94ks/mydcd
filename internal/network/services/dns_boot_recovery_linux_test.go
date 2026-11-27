// SPDX-License-Identifier: Apache-2.0

package services

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/jay94ks/seafield/internal/network"
	"github.com/jay94ks/seafield/internal/reconcile"
	"github.com/jay94ks/seafield/internal/storage"
)

// The prior boot below is injected journal input. This exercises actual DB
// reopen and the production recovery core, not a real kernel reboot or socket.
func TestDNSOwnerCrossBootPreservesOperationsAndRebasesOriginalTTL(t *testing.T) {
	for _, pending := range []bool{false, true} {
		t.Run(map[bool]string{false: "clean", true: "unclean-query"}[pending], func(t *testing.T) {
			f := settingsServing(t)
			f.d.m.maxViews = f.m.maxSlots
			var query SettingsDNSUse
			if pending {
				f, query = settingsQuery(t, f, 200)
			}
			old := f.d.m.current["first/dns"]
			cfg := ownDNSConfig(f.d.cfg)
			cfg.Source++
			cfg.Serial++
			f, _ = settingsTarget(t, f, cfg, f.scope)
			f = settingsSwitch(t, f)
			f = settingsPublish(t, f, 201)
			original := settingsRaw(t, f.m)
			dns, err := f.d.m.Encode()
			if err != nil {
				t.Fatal(err)
			}
			root := t.TempDir()
			n, err := network.OpenManager(filepath.Join(root, "network"), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer n.Close()
			options := dnsCrashDBOptions(f, n, nil) // network-only owner
			path := filepath.Join(root, "dns")
			o, err := OpenDNSOwner(path, options)
			if err != nil {
				t.Fatal("network-only open", err)
			}
			boot, process := o.boot, o.process
			if boot == f.m.boot {
				t.Fatal("fixture must represent a different kernel boot")
			}
			if err = o.Close(); err != nil {
				t.Fatal(err)
			}
			disk := dnsOwnerDisk{Schema: 1, Cluster: options.Cluster, Owner: pub(options.Key), Boot: f.m.boot, Stopped: !pending, Settings: original, DNS: dns, Roots: options.Roots, Process: &process}
			lease := network.BridgeLease{Key: "network/original", Consumer: "dns/original", NetworkID: "native-original", NetworkName: "bridge-original", Pin: reconcile.Lease{Token: 9, Generation: 7}}
			for id, group := range f.m.groups {
				// Legacy schema1 has no explicit receipt Boot. Open must bind it
				// to the ORIGINAL outer boot before resuming Settings.
				disk.Bridges = append(disk.Bridges, dnsBridgeReceipt{Group: id, Lease: lease, Namespace: group.Binding.Native.Namespace, Interface: group.Binding.Native.Interface, Index: 17})
			}
			raw, err := json.Marshal(disk)
			if err != nil {
				t.Fatal(err)
			}
			db, err := storage.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			err = db.Write(map[string][]byte{"dns-owner": raw})
			closeErr := db.Close()
			if err != nil || closeErr != nil {
				t.Fatal(err, closeErr)
			}
			o, err = OpenDNSOwner(path, options)
			if err != nil {
				t.Fatal("cross-boot same DB", err)
			}
			defer func() {
				if o != nil {
					_ = o.Close()
				}
			}()
			if o.settings.boot != boot || len(o.dns.Queries()) != 0 || o.settings.Status(f.key).Users != 0 || o.Status("first", "dns").Ready {
				t.Fatal("original query not settled or recovery claimed ready")
			}
			if !reflect.DeepEqual(o.settings.groups, f.m.groups) || !reflect.DeepEqual(o.settings.scopes, f.m.scopes) || o.settings.next != f.m.next || len(o.settings.slots) != len(f.m.slots) {
				t.Fatal("recovery replaced original native operations, slots or Bridge pins")
			}
			if pending {
				if _, err = o.settings.UseFacts(query.Runtime); err == nil {
					t.Fatal("original query user still borrowed")
				}
			}
			hold := o.dns.views[old].Hold
			if hold.Boot != boot || !validClock(hold) {
				t.Fatal("old monotonic TTL was reused", hold)
			}
			ttl := int64(f.d.cfg.TTL)
			beforeTTL := hold
			beforeTTL.Wall += ttl - 1
			beforeTTL.Mono += ttl - 1
			if _, err = o.dns.Collect(old, beforeTTL); err == nil {
				t.Fatal("original full TTL bypassed")
			}
			afterTTL := hold
			afterTTL.Wall += ttl
			afterTTL.Mono += ttl
			if _, err = o.dns.Collect(old, afterTTL); err != nil {
				t.Fatal("original full TTL did not end", err)
			}
			if _, err = o.origin(context.Background(), DNSOwnerPolicy{Authority: f.d.f.a}, nil, f.d.origin.Address); err == nil {
				t.Fatal("missing workload/native endpoint authorized a Task query")
			}
			for id, group := range o.settings.groups {
				if o.bridges[id].Boot != f.m.boot {
					t.Fatal("legacy receipt lost original boot")
				}
				// Explicitly injected read-back, not an actual interface. The
				// native fixture supplies real ServiceBinding/UDP+TCP effects.
				actual := NativeScope{[32]byte{239}, group.Binding.Native.Interface}
				bound, e := o.boundDNSBridge(group, lease, actual, 21)
				if e != nil {
					t.Fatal(e)
				}
				o.bridges[id] = bound
			}
			if err = o.Close(); err != nil {
				t.Fatal(err)
			}
			o, err = OpenDNSOwner(path, options)
			if err != nil {
				t.Fatal("same-boot reopen after recovery", err)
			}
			if o.dns.views[old].Hold != hold || o.dns.Applied("first", "dns") != cfg.Source {
				t.Fatal("same-boot reopen moved TTL or original source")
			}
			for _, bound := range o.bridges {
				if bound.Boot != boot || bound.Namespace != ([32]byte{239}) || bound.Original == nil || *bound.Original != f.scope {
					t.Fatal("same DB lost actual/original binding relationship")
				}
			}
			if !bytes.Equal(original, settingsRaw(t, f.m)) {
				t.Fatal("recovery mutated original input")
			}
		})
	}
}

func TestDNSBootRecoveryRejectsUnpairedOrUnprovenJournal(t *testing.T) {
	for _, name := range []string{"outer-boot", "missing-process", "missing-user", "missing-query", "clean-with-query"} {
		t.Run(name, func(t *testing.T) {
			f, query := settingsQuery(t, settingsServing(t), 200)
			o := &DNSOwner{options: DNSOwnerOptions{Key: f.d.f.key}, settings: f.m, dns: f.d.m, boot: [32]byte{240}}
			process := dnsProcessIdentity{PID: 1, StartTicks: 1, NamespaceInode: 1}
			disk := dnsOwnerDisk{Boot: f.m.boot, Process: &process}
			switch name {
			case "outer-boot":
				disk.Boot[0]++
			case "missing-process":
				disk.Process = nil
			case "missing-user":
				slot := o.settings.slots[query.Runtime.slot]
				delete(slot.Users, query.Runtime.pin.Token)
				o.settings.slots[slot.ID] = slot
			case "missing-query":
				var err error
				o.dns, err = o.dns.Release(query.Query, f.d.clock(201))
				if err != nil {
					t.Fatal(err)
				}
			case "clean-with-query":
				disk.Stopped = true
			}
			if err := o.resumeJournal(disk); err == nil {
				t.Fatal("unproven recovery accepted")
			}
		})
	}
}
