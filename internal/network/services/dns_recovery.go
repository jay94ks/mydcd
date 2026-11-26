// SPDX-License-Identifier: Apache-2.0

package services

// originalDNSUses restores handles, not authority or completion evidence. The
// two journals must contain exactly the same original requests. In particular,
// a missing query must never turn an orphan Settings user into a free pin.
func (m Settings) originalDNSUses(d DNSManager) ([]SettingsDNSUse, error) {
	if m.cluster != d.cluster || m.owner != d.owner {
		return nil, ErrLease
	}
	type heldUse struct {
		use      SettingsUse
		key      string
		revision uint64
	}
	held := map[[32]byte]heldUse{}
	for _, slot := range m.slots {
		if len(slot.Users) != len(slot.Pins.Active) {
			return nil, ErrLease
		}
		for _, pin := range slot.Pins.Active {
			request := slot.Users[pin.Token]
			use := SettingsUse{slot.ID, pin, request}
			if slot.Target.kind != SettingDNS {
				return nil, ErrLease
			}
			if _, err := m.UseFacts(use); err != nil {
				return nil, err
			}
			if _, duplicate := held[request]; duplicate {
				return nil, ErrLease
			}
			held[request] = heldUse{use, slot.Target.key, slot.Target.revision}
		}
	}
	var uses []SettingsDNSUse
	for _, query := range d.Queries() {
		request := settingsDNSRequest(query)
		original, exists := held[request]
		if !exists || original.key != "dns/"+query.scope || original.revision != query.Source() || query.origin.Boot != m.boot {
			return nil, ErrLease
		}
		uses = append(uses, SettingsDNSUse{original.use, query})
		delete(held, request)
	}
	if len(held) != 0 {
		return nil, ErrLease
	}
	return uses, nil
}
