// SPDX-License-Identifier: Apache-2.0

package lifecycle

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"slices"
)

const MaxCompiledFactBytes = 8 << 10
const MaxCompiledCollectionBytes = 256 << 10

// CompiledBuild is immutable ORIGINAL builder provenance. A receiver/cache
// node keeps this signature instead of claiming that it compiled the source.
type CompiledBuild struct {
	Schema                uint8
	Cluster, Builder, Job [32]byte
	ID                    string
	Recipe                CompileRecipe
	Digest                [32]byte
	Length                uint64
	Signature             []byte
}

func CompiledBuildBytes(b CompiledBuild) []byte {
	b.Signature = nil
	raw, _ := json.Marshal(b)
	return append([]byte("sfc-checker-compiled-build-1\x00"), raw...)
}
func (b CompiledBuild) Verify() error {
	if b.Schema != 1 || b.Cluster == ([32]byte{}) || b.Builder == ([32]byte{}) || b.Job == ([32]byte{}) || !digest(b.ID) || b.Recipe.Validate() != nil || b.Digest == ([32]byte{}) || b.Length == 0 || b.Length > MaxCompiledArtifactBytes || !ed25519.Verify(b.Builder[:], CompiledBuildBytes(b), b.Signature) {
		return ErrSourceStore
	}
	return nil
}
func (b CompiledBuild) Clone() CompiledBuild {
	b.Signature = bytes.Clone(b.Signature)
	b.Recipe.Flags = slices.Clone(b.Recipe.Flags)
	return b
}

// CompiledFact separately attests exact bytes in this node's cache. It is
// neither a build grant, current policy, pin nor permission to exec a checker.
type CompiledFact struct {
	Schema    uint8
	Owner     [32]byte
	Build     CompiledBuild
	Signature []byte
}

func CompiledFactBytes(f CompiledFact) []byte {
	f.Signature = nil
	raw, _ := json.Marshal(f)
	return append([]byte("sfc-checker-compiled-cache-1\x00"), raw...)
}
func (f CompiledFact) Verify() error {
	if f.Schema != 1 || f.Owner == ([32]byte{}) || len(f.Signature) != ed25519.SignatureSize || f.Build.Verify() != nil {
		return ErrSourceStore
	}
	if raw, err := json.Marshal(f); err != nil || len(raw) > MaxCompiledFactBytes {
		return ErrSourceStore
	}
	if !ed25519.Verify(f.Owner[:], CompiledFactBytes(f), f.Signature) {
		return ErrSourceStore
	}
	return nil
}
func (f CompiledFact) Clone() CompiledFact {
	f.Build = f.Build.Clone()
	f.Signature = bytes.Clone(f.Signature)
	return f
}
func (f CompiledFact) Digest() [32]byte { raw, _ := json.Marshal(f); return sha256.Sum256(raw) }

type CompiledDiagnostic struct {
	Original, Stored    [32]byte
	Length, StoredBytes uint64
	Truncated           bool
}
type CompiledCollectionItem struct {
	Key, Cached    [32]byte // Cached fingerprints the exact LOCAL CompiledFact
	Status, Reason string
	Diagnostic     CompiledDiagnostic
}
type CompiledCollection struct {
	Schema                                uint8
	Cluster, Owner, Job, Manifest, Report [32]byte
	Tenant, ID                            string
	ExitKnown                             bool
	ExitCode                              int64
	Outcome                               string
	Items                                 []CompiledCollectionItem
	Signature                             []byte
}

func CompiledCollectionBytes(c CompiledCollection) []byte {
	c.Signature = nil
	raw, _ := json.Marshal(c)
	return append([]byte("sfc-checker-compiled-collection-1\x00"), raw...)
}
func (c CompiledCollection) Digest() [32]byte { raw, _ := json.Marshal(c); return sha256.Sum256(raw) }
func (c CompiledCollection) Clone() CompiledCollection {
	c.Items = slices.Clone(c.Items)
	c.Signature = bytes.Clone(c.Signature)
	return c
}
func collectionOutcome(c CompiledCollection) string {
	cached := 0
	for _, item := range c.Items {
		if item.Status == "cached" {
			cached++
		}
	}
	if cached == 0 {
		return "failed"
	}
	if cached != len(c.Items) || !c.ExitKnown || c.ExitCode != 0 {
		return "partial"
	}
	return "complete"
}
func (c CompiledCollection) Verify() error {
	if len(c.Items) == 0 || len(c.Items) > MaxScripts || len(c.Signature) != ed25519.SignatureSize {
		return ErrSourceStore
	}
	if raw, err := json.Marshal(c); err != nil || len(raw) > MaxCompiledCollectionBytes {
		return ErrSourceStore
	}
	if c.Schema != 1 || c.Cluster == ([32]byte{}) || c.Owner == ([32]byte{}) || c.Job == ([32]byte{}) || c.Manifest == ([32]byte{}) || !name(c.Tenant) || !digest(c.ID) || len(c.Items) == 0 || len(c.Items) > MaxScripts || c.Outcome != collectionOutcome(c) || !ed25519.Verify(c.Owner[:], CompiledCollectionBytes(c), c.Signature) {
		return ErrSourceStore
	}
	for i, item := range c.Items {
		if item.Key == ([32]byte{}) || i > 0 && bytes.Compare(c.Items[i-1].Key[:], item.Key[:]) >= 0 {
			return ErrSourceStore
		}
		switch item.Status {
		case "cached":
			if item.Cached == ([32]byte{}) || item.Reason != "verified" || c.Report == ([32]byte{}) {
				return ErrSourceStore
			}
		case "failed":
			if item.Cached != ([32]byte{}) {
				return ErrSourceStore
			}
			switch item.Reason {
			case "compile-error", "artifact-invalid", "report-invalid", "report-missing", "cache-limit", "cache-conflict", "diagnostic-invalid":
			default:
				return ErrSourceStore
			}
		default:
			return ErrSourceStore
		}
		d := item.Diagnostic
		if d.Length > 64<<10 || d.StoredBytes > d.Length || d.StoredBytes == 0 && d.Stored != ([32]byte{}) || d.StoredBytes > 0 && d.Stored == ([32]byte{}) || d.Length == 0 && d.Original != ([32]byte{}) || d.Length > 0 && d.Original == ([32]byte{}) || d.StoredBytes < d.Length && !d.Truncated {
			return ErrSourceStore
		}
		if d.Length > 0 && d.StoredBytes == d.Length && d.Original != d.Stored {
			return ErrSourceStore
		}
	}
	return nil
}
