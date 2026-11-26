// SPDX-License-Identifier: Apache-2.0

package lifecycle

import (
	"encoding/hex"
	"strings"
)

// This compact FSM receipt records an accepted source publication, not another
// synchronization log or copy of source bytes. It survives a fast Use release
// so a node need not have polled during the Use's lifetime to close its hold.
func publicationKey(tenant string, owner, id [32]byte) string {
	return tenant + "/" + hex.EncodeToString(owner[:]) + "/" + hex.EncodeToString(id[:])
}
func publicationTenant(key string) (string, bool) {
	fields := strings.Split(key, "/")
	if len(fields) != 3 || !name(fields[0]) {
		return "", false
	}
	for _, v := range fields[1:] {
		raw, err := hex.DecodeString(v)
		if err != nil || len(raw) != 32 || hex.EncodeToString(raw) != v {
			return "", false
		}
		var zero [32]byte
		var id [32]byte
		copy(id[:], raw)
		if id == zero {
			return "", false
		}
	}
	return fields[0], true
}
func (c *Catalog) rememberPublication(f SourceFact) error {
	if f.Upload == nil {
		return nil
	}
	key := publicationKey(f.Tenant, f.Owner, *f.Upload)
	content := f.ContentDigest()
	if old, exists := c.d.Publications[key]; exists {
		if old != content {
			return ErrReference
		}
		return nil
	}
	if len(c.d.Publications) >= maxCatalogUses {
		return ErrContract
	}
	if c.d.Publications == nil {
		c.d.Publications = map[string][32]byte{}
	}
	c.d.Publications[key] = content
	return nil
}
func (c Catalog) validatePublications() error {
	if len(c.d.Publications) > maxCatalogUses {
		return ErrContract
	}
	for key, content := range c.d.Publications {
		tenant, ok := publicationTenant(key)
		if !ok || content == ([32]byte{}) || len(c.d.Policies[tenant]) == 0 {
			return ErrContract
		}
	}
	check := func(f SourceFact) bool {
		return f.Upload == nil || c.d.Publications[publicationKey(f.Tenant, f.Owner, *f.Upload)] == f.ContentDigest()
	}
	for _, r := range c.d.Scripts {
		for _, v := range r.Versions {
			if !check(v.Source) {
				return ErrContract
			}
		}
	}
	for _, u := range c.d.Uses {
		for _, f := range u.Sources {
			if !check(f) {
				return ErrContract
			}
		}
	}
	return nil
}
