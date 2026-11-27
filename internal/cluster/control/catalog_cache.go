// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"math/big"
	"strings"
	"sync"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/state"
)

// The access catalog is stored as a head row at CatalogKey and one row per
// record under CatalogKey+"/" (R17 B2b; record keys in access/rows.go). A
// change writes the head and only the rows it changed.
//
// The head carries the row count and a digest of all rows: the sum, modulo
// 2^256, of SHA-256 over each row's key and value. A change updates the sum
// from the rows it replaces, so writing it never reads the other rows, and
// reading the catalog back checks every row against it.
type catalogHead struct {
	Schema                uint8
	Cluster, BootstrapKey [32]byte
	Revision              uint64
	Meta                  json.RawMessage
	Rows                  int
	Digest                [32]byte
}

var two256 = new(big.Int).Lsh(big.NewInt(1), 256)

func catalogRowHash(key string, value []byte) *big.Int {
	h := sha256.New()
	h.Write([]byte("sfc-catalog-row-1\x00"))
	h.Write(binary.LittleEndian.AppendUint64(nil, uint64(len(key))))
	h.Write([]byte(key))
	h.Write(value)
	return new(big.Int).SetBytes(h.Sum(nil))
}

// digestBytes is n modulo 2^256 (Euclidean, so never negative).
func digestBytes(n *big.Int) [32]byte {
	var out [32]byte
	n.Mod(n, two256).FillBytes(out[:])
	return out
}

// catalogRows is every present catalog row of s, keyed relative to the root.
func catalogRows(s state.State) map[string][]byte {
	rows := map[string][]byte{}
	for key, o := range s.RangeObjects(CatalogKey + "/") {
		if o.Present {
			rows[strings.TrimPrefix(key, CatalogKey+"/")] = []byte(o.Value)
		}
	}
	return rows
}

// storedCatalog reads the catalog s holds, without the node key context
// Catalog adds. found is false for a blank installation.
func (p Policy) storedCatalog(s state.State) (c access.Catalog, found bool, err error) {
	root := s.Object(CatalogKey)
	if root.Revision == 0 || !root.Present {
		for _, o := range s.RangeObjects(CatalogKey + "/") {
			if o.Present {
				return access.Catalog{}, false, ErrCatalog
			}
		}
		if root.Revision != 0 {
			return access.Catalog{}, false, ErrCatalog
		}
		return access.Catalog{}, false, nil
	}
	var head catalogHead
	if canonical([]byte(root.Value), &head) != nil || head.Schema != 1 || head.Cluster != p.Cluster || head.BootstrapKey != p.BootstrapKey || head.Revision == 0 || head.Rows < 0 {
		return access.Catalog{}, false, ErrCatalog
	}
	id := catalogMemoID(head)
	if c, ok := decodedCatalogs.get(id); ok {
		return c, true, nil
	}
	rows := catalogRows(s)
	sum := new(big.Int)
	for key, value := range rows {
		sum.Add(sum, catalogRowHash(key, value))
	}
	if len(rows) != head.Rows || digestBytes(sum) != head.Digest {
		return access.Catalog{}, false, ErrCatalog
	}
	c, err = access.DecodeRows(head.Meta, rows)
	if err != nil || c.Revision() != head.Revision {
		return access.Catalog{}, false, ErrCatalog
	}
	decodedCatalogs.put(id, c)
	return c, true, nil
}

// catalogRowWrites is the state writes that store c in place of what s holds.
func (p Policy) catalogRowWrites(s state.State, c access.Catalog) (map[string][]byte, state.Code) {
	old, found, err := p.storedCatalog(s)
	if err != nil {
		return nil, state.Invalid
	}
	var meta []byte
	var changed map[string][]byte
	head := catalogHead{Schema: 1, Cluster: p.Cluster, BootstrapKey: p.BootstrapKey, Revision: c.Revision()}
	sum := new(big.Int)
	if found {
		var prev catalogHead
		if canonical([]byte(s.Object(CatalogKey).Value), &prev) != nil {
			return nil, state.Invalid
		}
		head.Rows = prev.Rows
		sum.SetBytes(prev.Digest[:])
		meta, changed, err = c.ChangedRows(old)
	} else {
		meta, changed, err = c.Rows()
	}
	if err != nil || c.Revision() == 0 {
		return nil, state.Invalid
	}
	writes := make(map[string][]byte, len(changed)+1)
	for key, value := range changed {
		previous := s.Object(CatalogKey + "/" + key)
		if previous.Present {
			sum.Sub(sum, catalogRowHash(key, []byte(previous.Value)))
			head.Rows--
		} else if value == nil {
			return nil, state.Invalid
		}
		if value != nil {
			sum.Add(sum, catalogRowHash(key, value))
			head.Rows++
		}
		writes[CatalogKey+"/"+key] = value
	}
	head.Meta, head.Digest = meta, digestBytes(sum)
	if writes[CatalogKey], err = json.Marshal(head); err != nil {
		return nil, state.Invalid
	}
	// Remember the new catalog as reading the rows back would build it, so
	// validating this very change does not decode every row again.
	var next access.Catalog
	if found {
		next, err = old.ApplyRows(meta, changed)
	} else {
		next, err = access.DecodeRows(meta, changed)
	}
	if err != nil {
		return nil, state.Invalid
	}
	decodedCatalogs.put(catalogMemoID(head), next)
	return writes, state.Applied
}

// decodedCatalogs remembers the last few decoded catalogs by their head (R17
// B1). Every command reads the catalog several times (reduce, then each
// validation stage), and almost every command leaves it unchanged.
//
// It is a pure memo: the head names the catalog's exact rows by their digest,
// DecodeRows is deterministic, and access.Catalog never shares its maps with
// callers (every read returns owned copies and every change clones first), so
// a remembered value is the value a fresh decode returns. It never changes a
// verdict and holds nothing a restart must rebuild.
var decodedCatalogs = &catalogMemo{}

const catalogMemoSize = 4

type catalogMemo struct {
	mu      sync.Mutex
	entries [catalogMemoSize]catalogMemoEntry
	next    int
}

type catalogMemoEntry struct {
	id  [32]byte
	set bool
	c   access.Catalog
}

func catalogMemoID(h catalogHead) [32]byte {
	b, _ := json.Marshal(h)
	return sha256.Sum256(b)
}

func (m *catalogMemo) get(id [32]byte) (access.Catalog, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, e := range m.entries {
		if e.set && e.id == id {
			return e.c, true
		}
	}
	return access.Catalog{}, false
}

func (m *catalogMemo) put(id [32]byte, c access.Catalog) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, e := range m.entries {
		if e.set && e.id == id {
			return
		}
	}
	m.entries[m.next] = catalogMemoEntry{id, true, c}
	m.next = (m.next + 1) % catalogMemoSize
}
