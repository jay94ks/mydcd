// SPDX-License-Identifier: Apache-2.0

package access

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"slices"
	"strings"
)

// A catalog is stored as one meta row plus one row per record (R17 B2b), so
// a change writes only the records it changed, not the whole catalog.
//
// Row keys, relative to the catalog root:
//
//	u/<user>                user
//	t/<tenant>              tenant
//	m/<tenant>/<user>       membership
//	r/<user>/<session>      session revocation
//	f/<sha256 of grant key> volume file folder grant
//
// Every row value is the canonical JSON of that one record.

// catalogMeta is what is not a record: schema, revision, anchor, node CLI policy.
type catalogMeta struct {
	Schema   uint8
	Revision uint64
	Anchor   [32]byte
	NodeCLI  *NodeCLIPolicy `json:",omitempty"`
}

func userRow(id string) string             { return "u/" + id }
func tenantRow(id string) string           { return "t/" + id }
func memberRow(tenant, user string) string { return "m/" + tenant + "/" + user }
func revocationRow(user, session string) string {
	return "r/" + user + "/" + session
}
func volumeFileRow(g VolumeFileFolderGrant) string {
	d := sha256.Sum256([]byte(g.key()))
	return "f/" + hex.EncodeToString(d[:])
}

// canonicalUser is the stored form of u: credentials in ID order.
func canonicalUser(u User) User {
	u.Credentials = ownCredentials(u.Credentials)
	slices.SortFunc(u.Credentials, func(a, b Credential) int { return strings.Compare(a.ID, b.ID) })
	u.Operations = slices.Clone(u.Operations)
	return u
}

func (c Catalog) meta() catalogMeta {
	m := catalogMeta{Schema: 1, Revision: c.revision, Anchor: c.anchor}
	if c.nodeCLI.Revision != 0 {
		policy := c.nodeCLI
		m.NodeCLI = &policy
	}
	return m
}

// records is every record of c as row key → canonical value.
func (c Catalog) records() map[string]any {
	out := make(map[string]any, len(c.users)+len(c.tenants)+len(c.members)+len(c.revocations)+len(c.volumeFiles))
	for id, u := range c.users {
		out[userRow(id)] = canonicalUser(u)
	}
	for id, t := range c.tenants {
		out[tenantRow(id)] = ownTenant(t)
	}
	for _, m := range c.members {
		out[memberRow(m.Tenant, m.User)] = m
	}
	for _, v := range c.revocations {
		out[revocationRow(v.User, v.Session)] = v
	}
	for _, g := range c.volumeFiles {
		out[volumeFileRow(g)] = g
	}
	return out
}

// Rows is the whole stored form of c: its meta row and every record row.
func (c Catalog) Rows() (meta []byte, rows map[string][]byte, err error) {
	if meta, err = json.Marshal(c.meta()); err != nil {
		return nil, nil, err
	}
	rows = map[string][]byte{}
	for key, v := range c.records() {
		if rows[key], err = json.Marshal(v); err != nil {
			return nil, nil, err
		}
	}
	return meta, rows, nil
}

// ChangedRows is the stored form of the change from old to c: the meta row,
// and each record row c added or changed (its new value) or removed (nil).
// Records are compared by value, so an unchanged record is never rewritten.
func (c Catalog) ChangedRows(old Catalog) (meta []byte, rows map[string][]byte, err error) {
	if meta, err = json.Marshal(c.meta()); err != nil {
		return nil, nil, err
	}
	before, after := old.records(), c.records()
	rows = map[string][]byte{}
	for key, v := range after {
		if prev, ok := before[key]; ok && reflect.DeepEqual(prev, v) {
			continue
		}
		if rows[key], err = json.Marshal(v); err != nil {
			return nil, nil, err
		}
	}
	for key := range before {
		if _, ok := after[key]; !ok {
			rows[key] = nil
		}
	}
	return meta, rows, nil
}

// DecodeRows rebuilds a catalog from its meta row and all its record rows,
// with the same checks as Decode. Each row must be the canonical JSON of its
// record, stored under that record's key.
func DecodeRows(meta []byte, rows map[string][]byte) (Catalog, error) {
	var m catalogMeta
	if strictJSON(meta, &m) != nil {
		return Catalog{}, ErrInvalid
	}
	r := catalogRecord{Schema: m.Schema, Revision: m.Revision, Anchor: m.Anchor, NodeCLI: m.NodeCLI}
	for key, raw := range rows {
		kind, _, _ := strings.Cut(key, "/")
		var want string
		switch kind {
		case "u":
			var v User
			if strictJSON(raw, &v) != nil {
				return Catalog{}, ErrInvalid
			}
			r.Users, want = append(r.Users, v), userRow(v.ID)
		case "t":
			var v Tenant
			if strictJSON(raw, &v) != nil {
				return Catalog{}, ErrInvalid
			}
			r.Tenants, want = append(r.Tenants, v), tenantRow(v.ID)
		case "m":
			var v Membership
			if strictJSON(raw, &v) != nil {
				return Catalog{}, ErrInvalid
			}
			r.Members, want = append(r.Members, v), memberRow(v.Tenant, v.User)
		case "r":
			var v Revocation
			if strictJSON(raw, &v) != nil {
				return Catalog{}, ErrInvalid
			}
			r.Revocations, want = append(r.Revocations, v), revocationRow(v.User, v.Session)
		case "f":
			var v VolumeFileFolderGrant
			if strictJSON(raw, &v) != nil {
				return Catalog{}, ErrInvalid
			}
			r.VolumeFiles, want = append(r.VolumeFiles, v), volumeFileRow(v)
		}
		if key != want {
			return Catalog{}, ErrInvalid
		}
	}
	slices.SortFunc(r.VolumeFiles, func(a, b VolumeFileFolderGrant) int { return strings.Compare(a.key(), b.key()) })
	c, err := fromRecord(r)
	if err != nil {
		return Catalog{}, err
	}
	// Each row is exactly the canonical form of what it decoded to.
	canonicalMeta, canonicalRows, err := c.Rows()
	if err != nil || !bytes.Equal(canonicalMeta, meta) || len(canonicalRows) != len(rows) {
		return Catalog{}, ErrInvalid
	}
	for key, raw := range rows {
		if !bytes.Equal(canonicalRows[key], raw) {
			return Catalog{}, ErrInvalid
		}
	}
	return c, nil
}

// ApplyRows is DecodeRows of old's rows with a change applied (rows as
// ChangedRows returns them), without decoding the rows that did not change.
// It runs every check DecodeRows runs on the whole result.
func (old Catalog) ApplyRows(meta []byte, rows map[string][]byte) (Catalog, error) {
	var m catalogMeta
	if strictJSON(meta, &m) != nil {
		return Catalog{}, ErrInvalid
	}
	current := old.records()
	for key, raw := range rows {
		if raw == nil {
			if _, ok := current[key]; !ok {
				return Catalog{}, ErrInvalid
			}
			delete(current, key)
			continue
		}
		kind, _, _ := strings.Cut(key, "/")
		var v any
		var want string
		switch kind {
		case "u":
			var x User
			err := strictJSON(raw, &x)
			v, want = x, userRow(x.ID)
			if err != nil {
				return Catalog{}, ErrInvalid
			}
		case "t":
			var x Tenant
			err := strictJSON(raw, &x)
			v, want = x, tenantRow(x.ID)
			if err != nil {
				return Catalog{}, ErrInvalid
			}
		case "m":
			var x Membership
			err := strictJSON(raw, &x)
			v, want = x, memberRow(x.Tenant, x.User)
			if err != nil {
				return Catalog{}, ErrInvalid
			}
		case "r":
			var x Revocation
			err := strictJSON(raw, &x)
			v, want = x, revocationRow(x.User, x.Session)
			if err != nil {
				return Catalog{}, ErrInvalid
			}
		case "f":
			var x VolumeFileFolderGrant
			err := strictJSON(raw, &x)
			v, want = x, volumeFileRow(x)
			if err != nil {
				return Catalog{}, ErrInvalid
			}
		}
		if key != want {
			return Catalog{}, ErrInvalid
		}
		if canonical, err := json.Marshal(v); err != nil || !bytes.Equal(canonical, raw) {
			return Catalog{}, ErrInvalid
		}
		current[key] = v
	}
	r := catalogRecord{Schema: m.Schema, Revision: m.Revision, Anchor: m.Anchor, NodeCLI: m.NodeCLI}
	for _, v := range current {
		switch x := v.(type) {
		case User:
			r.Users = append(r.Users, x)
		case Tenant:
			r.Tenants = append(r.Tenants, x)
		case Membership:
			r.Members = append(r.Members, x)
		case Revocation:
			r.Revocations = append(r.Revocations, x)
		case VolumeFileFolderGrant:
			r.VolumeFiles = append(r.VolumeFiles, x)
		}
	}
	slices.SortFunc(r.VolumeFiles, func(a, b VolumeFileFolderGrant) int { return strings.Compare(a.key(), b.key()) })
	c, err := fromRecord(r)
	if err != nil {
		return Catalog{}, err
	}
	if canonicalMeta, err := json.Marshal(c.meta()); err != nil || !bytes.Equal(canonicalMeta, meta) {
		return Catalog{}, ErrInvalid
	}
	return c, nil
}

func strictJSON(raw []byte, v any) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return err
	}
	if d.More() {
		return ErrInvalid
	}
	return nil
}
