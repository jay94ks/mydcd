// SPDX-License-Identifier: Apache-2.0

package lifecycle

import (
	"bytes"
	"crypto/sha256"
	"unicode/utf8"
)

const SourcePageBytes = 24 << 10

// SourcePage is a read-only slice of the exact signed source. Bytes are not a
// new source fact or an executable-readiness assertion.
type SourcePage struct {
	Tenant, Name                  string
	Revision, Offset, Total, Next uint64
	Digest                        [32]byte
	Data                          []byte
}

func (p SourcePage) Valid() bool {
	if !name(p.Tenant) || !ValidScriptName(p.Name) || p.Revision == 0 || p.Total < 1 || p.Total > MaxScriptBytes || p.Offset >= p.Total || p.Offset%SourcePageBytes != 0 || len(p.Data) < 1 || len(p.Data) > SourcePageBytes || uint64(len(p.Data)) != min(uint64(SourcePageBytes), p.Total-p.Offset) || p.Digest == ([32]byte{}) {
		return false
	}
	end := p.Offset + uint64(len(p.Data))
	return end == p.Total && p.Next == 0 || end < p.Total && p.Next == end
}
func NewSourcePage(tenant, id string, revision, offset uint64, d SourceDescriptor, data []byte) (SourcePage, error) {
	if d.Tenant != tenant || d.Validate() != nil || uint64(len(data)) != d.Length || sha256.Sum256(data) != d.Digest || !utf8.Valid(data) || bytes.IndexByte(data, 0) >= 0 || offset >= d.Length {
		return SourcePage{}, ErrSourceStore
	}
	end := min(d.Length, offset+SourcePageBytes)
	page := SourcePage{Tenant: tenant, Name: id, Revision: revision, Offset: offset, Total: d.Length, Digest: d.Digest, Data: bytes.Clone(data[offset:end])}
	if end < d.Length {
		page.Next = end
	}
	if !page.Valid() {
		return SourcePage{}, ErrSourceStore
	}
	return page, nil
}
