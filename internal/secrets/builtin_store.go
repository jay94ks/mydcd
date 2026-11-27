// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"sync"

	"github.com/jay94ks/seafield/internal/storage"
)

// BuiltinStoreLimit is the default bound of one voter's builtin store.
const BuiltinStoreLimit = 256 << 20

// BuiltinStore is a voter's local store of sealed builtin values, keyed by
// digest, with an index from each original write to the one value it may
// have. Nothing in it is plain: a copy of the file opens nothing without
// the master key. Writes are synced before they return.
type BuiltinStore struct {
	mu    sync.Mutex
	db    *storage.DB
	limit int64
	// seq counts Puts in this process; stored names the seq of each value
	// key stored since it started. A value from before a restart has none.
	seq    uint64
	stored map[string]uint64
}

const (
	builtinValuePrefix = "v/"
	builtinWritePrefix = "w/"
)

// OpenBuiltinStore opens (or creates) the store at path.
func OpenBuiltinStore(path string, limit int64) (*BuiltinStore, error) {
	if limit <= 0 {
		return nil, ErrBuiltin
	}
	db, err := storage.Open(path)
	if err != nil {
		return nil, err
	}
	return &BuiltinStore{db: db, limit: limit, stored: map[string]uint64{}}, nil
}

func (s *BuiltinStore) Close() error { return s.db.Close() }

// Put stores v as the value of the write named writeKey. The same value
// again is a no-op; a different value for the same write is refused, so
// a voter vouches for at most one value per original write.
func (s *BuiltinStore) Put(writeKey string, v BuiltinValue) error {
	raw, err := json.Marshal(v)
	if err != nil || len(raw) > MaxBuiltinValue+4096 {
		return ErrBuiltin
	}
	digest := v.StoreKey()
	s.mu.Lock()
	defer s.mu.Unlock()
	old, err := s.db.GetBounded(builtinWritePrefix+writeKey, 128)
	switch {
	case err == nil && string(old) != digest:
		return ErrBuiltin
	case err == nil:
		if _, err = s.db.GetBounded(builtinValuePrefix+digest, MaxBuiltinValue+4096); err == nil {
			return nil
		}
	case !errors.Is(err, storage.ErrMissing):
		return err
	}
	sizes, err := s.db.SizesBounded(builtinValuePrefix, 1<<20, 128<<20)
	if err != nil {
		return err
	}
	total := int64(len(raw))
	for _, n := range sizes {
		total += int64(n)
	}
	if total > s.limit {
		return ErrBuiltin
	}
	if err = s.db.Write(map[string][]byte{builtinValuePrefix + digest: raw, builtinWritePrefix + writeKey: []byte(digest)}); err != nil {
		return err
	}
	s.seq++
	s.stored[builtinValuePrefix+digest] = s.seq
	return nil
}

// Mark names the current point in this store's Puts. A caller takes it
// before reading the state its keep set comes from, and passes it to
// Retain: a value stored after the mark was stored for a write that state
// may not show yet, so Retain keeps it.
func (s *BuiltinStore) Mark() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.seq
}

// Get returns the value with digest d.
func (s *BuiltinStore) Get(d [32]byte) (BuiltinValue, error) {
	raw, err := s.db.GetBounded(builtinValuePrefix+hex.EncodeToString(d[:]), MaxBuiltinValue+4096)
	if err != nil {
		return BuiltinValue{}, err
	}
	var v BuiltinValue
	if json.Unmarshal(raw, &v) != nil || v.Digest() != d {
		return BuiltinValue{}, ErrBuiltin
	}
	return v, nil
}

// ForWrite returns the value stored for the write named writeKey.
func (s *BuiltinStore) ForWrite(writeKey string) (BuiltinValue, error) {
	raw, err := s.db.GetBounded(builtinWritePrefix+writeKey, 128)
	if err != nil {
		return BuiltinValue{}, err
	}
	d, err := hex.DecodeString(string(raw))
	if err != nil || len(d) != 32 {
		return BuiltinValue{}, ErrBuiltin
	}
	return s.Get([32]byte(d))
}

// Retain deletes every value whose digest is not in keep and that was not
// stored after mark, with the write index entries that point at it. It
// returns how many values it deleted.
func (s *BuiltinStore) Retain(keep map[[32]byte]bool, mark uint64) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	values, err := s.db.SizesBounded(builtinValuePrefix, 1<<20, 128<<20)
	if err != nil {
		return 0, err
	}
	index, err := s.db.ScanBounded(builtinWritePrefix, 1<<20, 128<<20)
	if err != nil {
		return 0, err
	}
	drop := map[string][]byte{}
	for key := range values {
		raw, err := hex.DecodeString(key[len(builtinValuePrefix):])
		if seq, fresh := s.stored[key]; fresh && seq > mark {
			continue
		}
		if err != nil || len(raw) != 32 || !keep[[32]byte(raw)] {
			drop[key] = nil
		}
	}
	for key, digest := range index {
		if _, gone := drop[builtinValuePrefix+string(digest)]; gone {
			drop[key] = nil
		} else if _, present := values[builtinValuePrefix+string(digest)]; !present {
			drop[key] = nil
		}
	}
	if len(drop) == 0 {
		return 0, nil
	}
	deleted := 0
	for key := range drop {
		if len(key) > len(builtinValuePrefix) && key[:len(builtinValuePrefix)] == builtinValuePrefix {
			deleted++
		}
	}
	if err = s.db.Write(drop); err != nil {
		return 0, err
	}
	for key := range drop {
		delete(s.stored, key)
	}
	return deleted, nil
}

// Has reports whether the value with digest d is stored.
func (s *BuiltinStore) Has(d [32]byte) bool {
	_, err := s.db.GetBounded(builtinValuePrefix+hex.EncodeToString(d[:]), MaxBuiltinValue+4096)
	return err == nil
}
