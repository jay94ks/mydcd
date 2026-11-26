// SPDX-License-Identifier: Apache-2.0

package services

import (
	"testing"

	"github.com/jay94ks/mydcd/internal/reconcile"
)

// Mirrors the real owner's full Retire path: stop, collect original views and
// native slots/groups, close the shared lifetime, then explicitly reapply.
// Native facts below are fixture inputs, not an actual socket/Bridge claim.
func TestSettingsDNSReopensAfterWholeLifetimeClosure(t *testing.T) {
	for _, recreate := range []bool{false, true} {
		name := "same-network"
		if recreate {
			name = "new-network-generation"
		}
		t.Run(name, func(t *testing.T) {
			f := settingsServing(t)
			old := f.m.scopes[f.key].Current
			oldGroup := f.m.slots[old].Group
			oldView := f.d.m.current["first/dns"]
			oldRef := dnsConsumer(t, f.d)
			cfg := ownDNSConfig(f.d.cfg)
			cfg.Source++
			cfg.Serial++
			cfg.Enabled = false
			f, _ = settingsTarget(t, f, cfg, f.scope)
			f = settingsSwitch(t, f)
			var err error
			f.m, err = f.m.Publish(f.d.f.c, f.d.f.n, f.d.f.a, f.key)
			if err != nil {
				t.Fatal("disabled native publication", err)
			}
			f.d.m, err = f.d.m.RetireCurrent("first", "dns", f.d.cfg.Source, f.d.clock(200))
			if err != nil {
				t.Fatal(err)
			}
			f.d.m, err = f.d.m.Collect(oldView, f.d.clock(232))
			if err != nil {
				t.Fatal(err)
			}
			f.m, err = f.m.CollectSlot(old)
			if err != nil {
				t.Fatal(err)
			}
			f = settingsGroupStep(t, f, oldGroup)
			f.m, err = f.m.DropGroup(oldGroup)
			if err != nil {
				t.Fatal(err)
			}
			f.d.m, err = f.d.m.MarkReferenceClosed(f.d.f.a, oldRef.ID)
			if err != nil {
				t.Fatal(err)
			}
			proof := nativeReferenceProof(t, f.d, oldRef, [32]byte{}, 233)
			f.d.f.a, err = f.d.f.a.ObserveReferenceClose(proof, 233)
			if err != nil {
				t.Fatal(err)
			}
			if recreate {
				// The same native owner returns the old allocations and CIDR only after
				// positive old lifetime/native evidence. Fresh reservation keeps floors.
				oldNetwork, _ := f.d.f.n.Network("first", "lan")
				for _, alloc := range f.d.f.a.AddressBook().Checkpoint().Allocations {
					pool, ok := f.d.f.a.AddressBook().Pool(alloc.Pool)
					if !ok || pool.Network != "first/lan" {
						continue
					}
					f.d.f.a, err = f.d.f.a.BeginStaticRetirement(f.d.f.c, f.d.f.n, "admin", f.d.f.a.Revision(), alloc, 234)
					if err != nil {
						t.Fatal(err)
					}
					fence, _ := f.d.f.a.AddressRetirement(alloc)
					f.d.f.a, err = f.d.f.a.ReleaseStatic(alloc, staticOwnerProof(t, f.d, fence, 235), 235)
					if err != nil {
						t.Fatal(err)
					}
				}
				f.d.f.n, err = f.d.f.n.Drain(f.d.f.c, "admin", "first", "lan", oldNetwork.Revision)
				if err != nil {
					t.Fatal(err)
				}
				f.d.f.a, err = f.d.f.a.SyncPools(f.d.f.n)
				if err != nil {
					t.Fatal(err)
				}
				f.d.f.a, f.d.f.n, err = f.d.f.a.RetireNetwork(f.d.f.c, f.d.f.n, "admin", sourceClosure(f.d.f))
				if err != nil {
					t.Fatal(err)
				}
				next := oldNetwork
				next.Generation = 0
				next.Revision = 0
				next.Draining = false
				f.d.f.n, err = f.d.f.n.Create(f.d.f.c, "admin", f.d.f.n.Revision(), next)
				if err != nil {
					t.Fatal(err)
				}
				f.d.f.a, err = f.d.f.a.SyncPools(f.d.f.n)
				if err != nil {
					t.Fatal(err)
				}
				current, _ := f.d.f.n.Network("first", "lan")
				if current.Generation <= oldNetwork.Generation {
					t.Fatal("lost network generation floor")
				}
			}
			staleSettings := f.m
			cfg.Source++
			cfg.Serial++
			cfg.Enabled = true
			cfg.Names = nil
			cfg.Leases = nil
			scope := f.scope
			scope.Interface = "bridge-recreated"
			f, id := settingsTarget(t, f, cfg, scope)
			nextRef := dnsConsumer(t, f.d)
			if nextRef.ID == oldRef.ID || nextRef.Generation <= oldRef.Generation {
				t.Fatal("reused closed lifetime")
			}
			f = settingsGroupStep(t, f, f.m.slots[id].Group)
			f = settingsSwitch(t, f)
			f = settingsPublish(t, f, 240)
			encodeDNS(t, f.d.m)
			if f.m.Status(f.key).Applied != cfg.Source || f.d.m.Applied("first", "dns") != cfg.Source {
				t.Fatal("new lifetime not published")
			}
			// Old closed serving metadata cannot authorize a fresh request.
			if _, _, err = staleSettings.Borrow(f.d.f.c, f.d.f.n, f.d.f.a, f.key, [32]byte{1}, false); err == nil {
				t.Fatal("old closed settings revived")
			}
			if f.m.scopes[f.key].Switch.Pending != nil {
				t.Fatal("new serving proof left Unknown")
			}
			if f.m.slots[id].Pins.Draining || f.m.groups[f.m.slots[id].Group].State.Pending != nil {
				t.Fatal("new lifetime inherited old Drain/Unknown")
			}
			if _, err = reconcile.RestoreLeases(f.m.slots[id].Pins); err != nil {
				t.Fatal(err)
			}
		})
	}
}
