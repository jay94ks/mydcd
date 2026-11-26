// SPDX-License-Identifier: Apache-2.0

package lifecycle

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"slices"

	"golang.org/x/mod/module"

	contract "github.com/jay94ks/mydcd/lifecycle/v1"
)

type ModulePin struct {
	Path, Version string
	Digest        [32]byte
	Length        uint64
}

// SourceDescriptor names exact source bytes and their complete supplied module
// lock before a provider has stored/signed them. It grants no execution rights.
type SourceDescriptor struct {
	Tenant  string
	Digest  [32]byte
	Length  uint64
	SDK     uint8
	Modules []ModulePin
}

func (d SourceDescriptor) Clone() SourceDescriptor {
	d.Modules = slices.Clone(d.Modules)
	return d
}

func (d SourceDescriptor) Validate() error {
	if !name(d.Tenant) || d.Digest == ([32]byte{}) || d.Length < 1 || d.Length > MaxScriptBytes || d.SDK != contract.Schema || len(d.Modules) > 64 {
		return ErrContract
	}
	for i, m := range d.Modules {
		if !m.valid() || i > 0 && d.Modules[i-1].Path >= m.Path {
			return ErrContract
		}
	}
	if raw, err := json.Marshal(d); err != nil || len(raw) > 15<<10 {
		return ErrContract
	}
	return nil
}

func (d SourceDescriptor) ContentDigest() [32]byte {
	modules := d.Modules
	if len(modules) == 0 {
		modules = nil
	}
	raw, _ := json.Marshal(struct {
		Schema  uint8
		SDK     uint8
		Digest  [32]byte
		Length  uint64
		Modules []ModulePin
	}{1, d.SDK, d.Digest, d.Length, modules})
	return sha256.Sum256(append([]byte("mydc-checker-content-1\x00"), raw...))
}

func (p ModulePin) valid() bool {
	return text(p.Path, 256) && text(p.Version, 128) && module.Check(p.Path, p.Version) == nil && module.CanonicalVersion(p.Version) == p.Version && p.Digest != ([32]byte{}) && p.Length > 0 && p.Length <= 1<<30
}

// SourceFact attests that this node durably staged these exact tenant bytes
// and the complete supplied module lock. It is not current availability, a
// permission grant, a parsed/valid program or a compiled artifact receipt.
type SourceFact struct {
	Upload         *[32]byte `json:",omitempty"`
	Schema         uint8
	Cluster, Owner [32]byte
	Tenant         string
	Digest         [32]byte
	Length         uint64
	SDK            uint8
	Modules        []ModulePin
	Signature      []byte
}

func (f SourceFact) Descriptor() SourceDescriptor {
	return SourceDescriptor{Tenant: f.Tenant, Digest: f.Digest, Length: f.Length, SDK: f.SDK, Modules: slices.Clone(f.Modules)}
}

func SourceFactBytes(f SourceFact) []byte {
	f.Signature = nil
	raw, _ := json.Marshal(f)
	return append([]byte("mydc-checker-source-fact-1\x00"), raw...)
}

func (f SourceFact) Verify() error {
	if f.Schema != 1 || f.Cluster == ([32]byte{}) || f.Owner == ([32]byte{}) || f.Descriptor().Validate() != nil || f.Upload != nil && *f.Upload == ([32]byte{}) {
		return ErrContract
	}
	if len(SourceFactBytes(f)) > 16<<10 || !ed25519.Verify(f.Owner[:], SourceFactBytes(f), f.Signature) {
		return ErrContract
	}
	return nil
}

func (f SourceFact) Clone() SourceFact {
	if f.Upload != nil {
		id := *f.Upload
		f.Upload = &id
	}
	f.Modules = slices.Clone(f.Modules)
	f.Signature = bytes.Clone(f.Signature)
	return f
}

// ContentDigest is independent of provider/replication but binds SDK and every
// module's original bytes. Tenant remains a separate cache/authorization key.
func (f SourceFact) ContentDigest() [32]byte {
	return f.Descriptor().ContentDigest()
}

func inlineContentDigest(source string) [32]byte {
	return scriptContentDigest(source, nil)
}

func inlineRootDigest(source string) [32]byte { return sha256.Sum256([]byte(source)) }

func scriptContentDigest(source string, modules []ModulePin) [32]byte {
	return (SourceFact{SDK: contract.Schema, Digest: inlineRootDigest(source), Length: uint64(len(source)), Modules: modules}).ContentDigest()
}
