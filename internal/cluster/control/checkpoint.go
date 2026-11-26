// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/jay94ks/mydcd/internal/cluster/state"
)

// This header preserves the original catalog's JSON format. BootstrapKey binds
// the namespace's immutable trust anchor; a member directory uses TrustRoot.
type checkpointRoot struct {
	Schema                uint8
	Cluster, BootstrapKey [32]byte
	Revision, Length      uint64
	Parts                 int
	Digest                [32]byte
}

func partKey(root string, i int) string { return fmt.Sprintf("%s/part/%08d", root, i) }
func readCheckpoint(s state.State, key string, cluster, anchor [32]byte) ([]byte, uint64, error) {
	if cluster == ([32]byte{}) || anchor == ([32]byte{}) {
		return nil, 0, ErrCatalog
	}
	root := s.Object(key)
	parts := s.Objects(key + "/")
	if root.Revision == 0 {
		for _, part := range parts {
			if part.Present {
				return nil, 0, ErrCatalog
			}
		}
		return nil, 0, nil
	}
	var header checkpointRoot
	if !root.Present || canonical([]byte(root.Value), &header) != nil || header.Schema != 1 || header.Cluster != cluster || header.BootstrapKey != anchor || header.Revision == 0 || header.Parts < 1 || header.Parts > len(parts) || header.Length == 0 || header.Length/catalogPartSize > uint64(header.Parts) || (header.Length-1)/catalogPartSize+1 != uint64(header.Parts) {
		return nil, 0, ErrCatalog
	}
	var raw []byte
	used := map[string]bool{}
	for i := 0; i < header.Parts; i++ {
		key := partKey(key, i)
		part := parts[key]
		want := min(uint64(catalogPartSize), header.Length-uint64(len(raw)))
		if !part.Present || part.Revision != root.Revision || uint64(len(part.Value)) != want {
			return nil, 0, ErrCatalog
		}
		raw = append(raw, part.Value...)
		used[key] = true
	}
	for key, part := range parts {
		if part.Present && !used[key] {
			return nil, 0, ErrCatalog
		}
	}
	if uint64(len(raw)) != header.Length || sha256.Sum256(raw) != header.Digest {
		return nil, 0, ErrCatalog
	}
	return raw, header.Revision, nil
}

// checkpointPatchKey reports whether key belongs to the checkpoint written
// at root by this reduction: the root itself, or one of its parts. A part may
// be removed (nil), because a checkpoint that shrinks deletes its last parts;
// the root is never removed.
func checkpointPatchKey(writes map[string][]byte, root, key string) bool {
	value, written := writes[key]
	if key == root {
		return written && value != nil
	}
	return written && strings.HasPrefix(key, root+"/part/")
}

func writeCheckpoint(s state.State, key string, cluster, anchor [32]byte, revision uint64, raw []byte) (map[string][]byte, state.Code) {
	if len(raw) == 0 || revision == 0 {
		return nil, state.Invalid
	}
	count := (len(raw) + catalogPartSize - 1) / catalogPartSize
	writes := map[string][]byte{}
	for i := 0; i < count; i++ {
		end := min(len(raw), (i+1)*catalogPartSize)
		writes[partKey(key, i)] = bytes.Clone(raw[i*catalogPartSize : end])
	}
	for part, old := range s.Objects(key + "/") {
		if _, keep := writes[part]; !keep && old.Present {
			writes[part] = nil
		}
	}
	header := checkpointRoot{1, cluster, anchor, revision, uint64(len(raw)), count, sha256.Sum256(raw)}
	var err error
	writes[key], err = json.Marshal(header)
	if err != nil {
		return nil, state.Invalid
	}
	return writes, state.Applied
}
