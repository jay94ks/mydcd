// SPDX-License-Identifier: Apache-2.0

package services

import (
	"bytes"
	"encoding/json"

	"github.com/jay94ks/seafield/internal/network"
)

// Settings retains an immutable intent scope; receipt is the actual read-back
// in the kernel boot that bound these sockets. Both belong to the SAME original
// group and Bridge pin. Neither journal reconstruction nor a desired name is
// evidence of current native readiness.
func validDNSBridgeReceipt(b dnsBridgeReceipt, g settingsGroup) bool {
	if b.Group == 0 || b.Group != g.ID || b.Boot == ([32]byte{}) || b.Lease.Consumer == "" || b.Index <= 0 || !validNativeScope(NativeScope{b.Namespace, b.Interface}) {
		return false
	}
	actual := NativeScope{b.Namespace, b.Interface}
	if b.Original == nil {
		return actual == g.Binding.Native
	}
	return validNativeScope(*b.Original) && *b.Original == g.Binding.Native && b.Interface == b.Original.Interface && actual != *b.Original
}

// All DNS sockets of this owner live in its one network namespace. Preserve
// the original namespace coordinate for NEW Settings targets as well, so a
// reboot cannot hide listener conflicts from the existing serial-switch core.
// Packet provenance still comes from the actual ServiceBinding, never this
// immutable intent coordinate.
func (o *DNSOwner) dnsSettingsScope(actual NativeScope) (NativeScope, error) {
	if !validNativeScope(actual) || o.boot == ([32]byte{}) || o.settings.boot != o.boot {
		return NativeScope{}, ErrLease
	}
	var namespace [32]byte
	join := func(native NativeScope) bool {
		if !validNativeScope(native) {
			return false
		}
		if namespace == ([32]byte{}) {
			namespace = native.Namespace
		}
		return namespace == native.Namespace
	}
	for _, scope := range o.settings.scopes {
		if scope.Desired.kind != SettingDNS || !join(scope.Desired.binding.Native) {
			return NativeScope{}, ErrLease
		}
		if scope.LastGood.kind != "" && (scope.LastGood.kind != SettingDNS || !join(scope.LastGood.binding.Native)) {
			return NativeScope{}, ErrLease
		}
	}
	for id, group := range o.settings.groups {
		if !join(group.Binding.Native) {
			return NativeScope{}, ErrLease
		}
		receipt, ok := o.bridges[id]
		if !ok || !validDNSBridgeReceipt(receipt, group) {
			return NativeScope{}, ErrLease
		}
		if receipt.Boot == o.boot {
			if receipt.Namespace != actual.Namespace {
				return NativeScope{}, ErrLease
			}
		} else if o.sockets[id] != nil {
			// Open already joined the original boot's process/query lifetime.
			// A live old-boot socket here would contradict that recovery.
			return NativeScope{}, ErrLease
		}
	}
	if namespace == ([32]byte{}) {
		namespace = actual.Namespace
	}
	return NativeScope{namespace, actual.Interface}, nil
}

func sameDNSBridgeLease(a, b network.BridgeLease) bool {
	x, err := json.Marshal(a)
	y, other := json.Marshal(b)
	return err == nil && other == nil && bytes.Equal(x, y)
}

// Called with effects/mu held, after current permit and actual
// Network.ServiceBinding read-back. This only records the binding candidate;
// prepare/UDP+TCP bind and both original Settings proofs still follow it.
func (o *DNSOwner) boundDNSBridge(group settingsGroup, lease network.BridgeLease, actual NativeScope, index int) (dnsBridgeReceipt, error) {
	if !validNativeScope(actual) || group.Binding.Native.Interface != actual.Interface || o.boot == ([32]byte{}) || o.settings.boot != o.boot || index <= 0 {
		return dnsBridgeReceipt{}, ErrLease
	}
	if old, known := o.bridges[group.ID]; known {
		if !validDNSBridgeReceipt(old, group) || !sameDNSBridgeLease(old.Lease, lease) {
			return dnsBridgeReceipt{}, ErrLease
		}
		if old.Boot == o.boot {
			if old.Namespace != actual.Namespace || old.Interface != actual.Interface || old.Index != index {
				return dnsBridgeReceipt{}, ErrLease
			}
		} else {
			if o.sockets[group.ID] != nil {
				return dnsBridgeReceipt{}, ErrLease
			}
			for _, slot := range o.settings.slots {
				if slot.Group == group.ID && len(slot.Users) != 0 {
					return dnsBridgeReceipt{}, ErrLease
				}
			}
		}
	} else if _, original := o.settings.groups[group.ID]; original {
		return dnsBridgeReceipt{}, ErrLease // losing a receipt is not a fresh bind
	}
	b := dnsBridgeReceipt{Group: group.ID, Lease: lease, Namespace: actual.Namespace, Interface: actual.Interface, Index: index, Boot: o.boot}
	if actual != group.Binding.Native {
		original := group.Binding.Native
		b.Original = &original
	}
	if !validDNSBridgeReceipt(b, group) {
		return dnsBridgeReceipt{}, ErrLease
	}
	return b, nil
}
