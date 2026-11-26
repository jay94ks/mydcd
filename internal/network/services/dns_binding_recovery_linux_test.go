// SPDX-License-Identifier: Apache-2.0

package services

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/jay94ks/mydcd/internal/network"
	"github.com/jay94ks/mydcd/internal/reconcile"
)

// Native read-back is injected here. Real socket/Bridge read-back is exercised
// by the native owner fixture; these tests use the identical owner mapping core.
func dnsBindingFixture(t *testing.T) (*DNSOwner, settingsFixture, settingsGroup, network.BridgeLease, NativeScope) {
	t.Helper()
	f := settingsServing(t)
	group := f.m.groups[f.m.slots[f.m.scopes[f.key].Current].Group]
	lease := network.BridgeLease{Key: "network/original", Consumer: "dns/original", NetworkID: "native-original", NetworkName: "bridge-original", Pin: reconcile.Lease{Token: 9, Generation: 7}, Spec: network.BridgeSpec{Schema: 1, Network: "lan", Owner: "owner", MTU: 1500}}
	o := &DNSOwner{boot: [32]byte{240}, settings: f.m, dns: f.d.m, bridges: map[uint64]dnsBridgeReceipt{}, sockets: map[uint64]*dnsSocketGroup{}}
	var err error
	o.settings, err = o.settings.ResumeBoot(o.boot)
	if err != nil {
		t.Fatal(err)
	}
	o.bridges[group.ID] = dnsBridgeReceipt{Group: group.ID, Lease: lease, Namespace: f.scope.Namespace, Interface: f.scope.Interface, Index: 17, Boot: f.m.boot}
	return o, f, group, lease, NativeScope{[32]byte{241}, f.scope.Interface}
}

func TestDNSBindingRebootKeepsIntentOperationsAndConflictCoordinates(t *testing.T) {
	o, f, group, lease, native := dnsBindingFixture(t)
	before := settingsRaw(t, o.settings)
	intent, err := o.dnsSettingsScope(native)
	if err != nil || intent != f.scope {
		t.Fatal("reboot changed original Settings scope", intent, err)
	}
	b, err := o.boundDNSBridge(group, lease, native, 21)
	if err != nil || b.Boot != o.boot || b.Namespace != native.Namespace || b.Index != 21 || b.Original == nil || *b.Original != f.scope || !sameDNSBridgeLease(b.Lease, lease) {
		t.Fatal("rebind did not preserve original pin and actual scope", b, err)
	}
	if o.bridges[group.ID].Boot == o.boot || !bytes.Equal(before, settingsRaw(t, o.settings)) {
		t.Fatal("candidate mutated original binding or Settings")
	}
	o.bridges[group.ID] = b
	if o.settings.nativeReady(o.settings.groups[group.ID]) {
		t.Fatal("receipt replaced actual socket/native revalidation")
	}
	intent, err = o.dnsSettingsScope(native)
	if err != nil || intent != f.scope {
		t.Fatal("same boot forgot original intent after rebind", err)
	}
	target, err := DNSSettings(f.d.f.c, f.d.f.n, f.d.f.a, "admin", f.d.cfg, intent)
	if err != nil {
		t.Fatal(err)
	}
	m, err := o.settings.Desired(f.d.f.c, f.d.f.n, f.d.f.a, "admin", f.d.cfg.Source, target)
	if err != nil || !bytes.Equal(before, settingsRaw(t, m)) {
		t.Fatal("same source required a new local operation after reboot", err)
	}
	if !bindingConflicts(group.Binding, target.binding) {
		t.Fatal("reboot hid native listener conflicts")
	}
	wrong, err := DNSSettings(f.d.f.c, f.d.f.n, f.d.f.a, "admin", f.d.cfg, native)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = o.settings.Desired(f.d.f.c, f.d.f.n, f.d.f.a, "admin", f.d.cfg.Source, wrong); err == nil {
		t.Fatal("reboot rewrote immutable source/operation bytes")
	}
	raw, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	var restored dnsBridgeReceipt
	if err = json.Unmarshal(raw, &restored); err != nil || !reflect.DeepEqual(restored, b) || !validDNSBridgeReceipt(restored, group) {
		t.Fatal("original/current receipt relationship lost", err)
	}
}

func TestDNSBindingRecoveryRejectsReplacementAndUnclosedOriginal(t *testing.T) {
	for _, name := range []string{"same-boot-index", "same-boot-namespace", "interface", "consumer", "network-id", "network-name", "key", "pin", "generation", "spec", "missing-receipt", "live-socket", "query-user", "wrong-origin", "mixed-namespaces"} {
		t.Run(name, func(t *testing.T) {
			o, f, group, lease, native := dnsBindingFixture(t)
			index := 21
			checkScope := false
			switch name {
			case "same-boot-index":
				o.boot = f.m.boot
				o.settings = f.m
				native = f.scope
			case "same-boot-namespace":
				o.boot = f.m.boot
				o.settings = f.m
				checkScope = true
			case "interface":
				native.Interface = "other-bridge"
			case "consumer":
				lease.Consumer = "other-consumer"
			case "network-id":
				lease.NetworkID = "other-native"
			case "network-name":
				lease.NetworkName = "other-name"
			case "key":
				lease.Key = "other-key"
			case "pin":
				lease.Pin.Token++
			case "generation":
				lease.Pin.Generation++
			case "spec":
				lease.Spec.MTU++
			case "missing-receipt":
				delete(o.bridges, group.ID)
			case "live-socket":
				o.sockets[group.ID] = &dnsSocketGroup{}
			case "query-user":
				f, _ = settingsQuery(t, f, 200)
				var err error
				o.settings, err = f.m.ResumeBoot(o.boot) // query pairing never settled
				if err != nil {
					t.Fatal(err)
				}
			case "wrong-origin":
				b := o.bridges[group.ID]
				wrong := NativeScope{[32]byte{99}, f.scope.Interface}
				b.Original = &wrong
				o.bridges[group.ID] = b
			case "mixed-namespaces":
				scope := o.settings.scopes[f.key]
				scope.Desired.binding.Native.Namespace[0]++
				o.settings.scopes[f.key] = scope
				checkScope = true
			}
			if checkScope {
				if _, err := o.dnsSettingsScope(native); err == nil {
					t.Fatal("scope mismatch admitted")
				}
			} else if _, err := o.boundDNSBridge(group, lease, native, index); err == nil {
				t.Fatal("replaced or unclosed original admitted")
			}
		})
	}
}
