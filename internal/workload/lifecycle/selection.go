// SPDX-License-Identifier: Apache-2.0

package lifecycle

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"slices"
)

// Selection is accepted input metadata. Sources are staged inline scripts;
// named versions resolve in the catalog. It contains no raw program or binary.
type Selection struct {
	PolicyRevision uint64
	Scripts        []NamedReference `json:",omitempty"`
	Sources        []SourceFact     `json:",omitempty"`
}

func (s Selection) Clone() Selection {
	s.Scripts = slices.Clone(s.Scripts)
	s.Sources = slices.Clone(s.Sources)
	for i := range s.Sources {
		s.Sources[i] = s.Sources[i].Clone()
	}
	return s
}
func (s Selection) Validate() error {
	if s.PolicyRevision == 0 || len(s.Scripts)+len(s.Sources) == 0 || len(s.Scripts)+len(s.Sources) > MaxScripts {
		return ErrContract
	}
	for i, r := range s.Scripts {
		if !name(r.Name) || r.Revision == 0 || i > 0 && (s.Scripts[i-1].Name > r.Name || s.Scripts[i-1].Name == r.Name && s.Scripts[i-1].Revision >= r.Revision) {
			return ErrContract
		}
	}
	for i, f := range s.Sources {
		if f.Verify() != nil {
			return ErrContract
		}
		if i > 0 {
			a, b := s.Sources[i-1].ContentDigest(), f.ContentDigest()
			if bytes.Compare(a[:], b[:]) >= 0 {
				return ErrContract
			}
		}
	}
	return nil
}
func (s Selection) Equal(other Selection) bool {
	a, _ := json.Marshal(s)
	b, _ := json.Marshal(other)
	return bytes.Equal(a, b)
}

func (u Use) Digest() [32]byte {
	raw, _ := json.Marshal(u)
	return sha256.Sum256(append([]byte("sfc-checker-use-1\x00"), raw...))
}

func (u Use) Selection() Selection {
	return Selection{PolicyRevision: u.PolicyRevision, Scripts: slices.Clone(u.Scripts), Sources: ownFacts(u.Sources)}
}
func ownFacts(facts []SourceFact) []SourceFact {
	facts = slices.Clone(facts)
	for i := range facts {
		facts[i] = facts[i].Clone()
	}
	return facts
}

func (c Catalog) Use(tenant, id string) (Use, bool) {
	u, ok := c.d.Uses[catalogKey(tenant, id)]
	return ownUse(u), ok
}
func (c Catalog) Uses() []Use {
	keys := make([]string, 0, len(c.d.Uses))
	for key := range c.d.Uses {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	result := make([]Use, 0, len(keys))
	for _, key := range keys {
		result = append(result, ownUse(c.d.Uses[key]))
	}
	return result
}

// SourceForUse resolves only this accepted input and the current policy. A
// historical fact/use is not a bearer token; the control adapter checks parent,
// current user/node and provider membership before any actual bytes are read.
func (c Catalog) SourceForUse(u Use, content [32]byte) (SourceFact, TenantPolicy, error) {
	actual, ok := c.Use(u.Tenant, u.ID)
	if !ok || !sameUse(actual, u) || content == ([32]byte{}) {
		return SourceFact{}, TenantPolicy{}, ErrReference
	}
	accepted, aok := c.Policy(u.Tenant, u.PolicyRevision)
	current, cok := c.Policy(u.Tenant, 0)
	if !aok || !cok || !accepted.Enabled || !current.Enabled {
		return SourceFact{}, TenantPolicy{}, ErrReference
	}
	facts := ownFacts(u.Sources)
	for _, ref := range u.Scripts {
		v, ok := c.version(u.Tenant, ref)
		if !ok || v.Deleted {
			return SourceFact{}, TenantPolicy{}, ErrReference
		}
		facts = append(facts, v.Source)
	}
	for _, f := range facts {
		if f.ContentDigest() == content && f.Cluster == c.Cluster() && f.Tenant == u.Tenant && accepted.AllowsSource(f) && current.AllowsSource(f) {
			return f.Clone(), current, nil
		}
	}
	return SourceFact{}, TenantPolicy{}, ErrReference
}
