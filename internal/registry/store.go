// SPDX-License-Identifier: Apache-2.0

package registry

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"

	"github.com/jay94ks/mydcd/internal/storage"
)

// Store is the actual serving owner's storage session in its authorized,
// existing private retained Volume root. DB and objects are fixed leaves.
// It does not grant network access, acquire a shared writer or mark Ready.
type Store struct {
	gate     registryIOGate
	Metadata *Metadata
	Blobs    *Blobs
	mu       sync.Mutex
	db       *storage.DB
	lock     *storage.Lock
	closed   bool
	closeErr error
}

func OpenStore(ctx context.Context, path string, scope Scope, metadataLimits MetadataLimits, blobLimits BlobLimits) (*Store, error) {
	if ctx == nil || ctx.Err() != nil || !filepath.IsAbs(path) || filepath.Clean(path) != path || !scope.valid() || !metadataLimits.valid() || !blobLimits.valid() {
		return nil, ErrStorage
	}
	st, err := os.Lstat(path)
	if err != nil || !privateFile(st, true) {
		return nil, ErrStorage
	}
	canonical, err := filepath.EvalSymlinks(path)
	if err != nil || canonical != path {
		return nil, ErrStorage
	}
	s := &Store{}
	ok := false
	defer func() {
		if !ok {
			_ = s.Close()
		}
	}()
	s.lock, err = storage.LockRoot(path)
	if err != nil {
		return nil, ErrStorage
	}
	dbPath := filepath.Join(path, "registry.db")
	if _, e := os.Lstat(dbPath); os.IsNotExist(e) {
		// objects are only created after the original DB/owner. Their presence
		// without that DB is known loss, not an empty registry initialization.
		entries, e := os.ReadDir(path)
		if e != nil {
			return nil, ErrStorage
		}
		for _, entry := range entries {
			if entry.Name() != "node.lock" {
				return nil, ErrStorage
			}
		}
	} else if e != nil {
		return nil, ErrStorage
	}
	s.db, err = storage.Open(dbPath)
	if err != nil {
		return nil, ErrStorage
	}
	s.Metadata, err = OpenMetadata(s.db, scope, metadataLimits)
	if err != nil {
		return nil, err
	}
	s.Blobs, err = openBlobs(ctx, filepath.Join(path, "objects"), s.Metadata, blobLimits)
	if err != nil {
		return nil, err
	}
	if err = s.initializePushState(ctx); err != nil {
		return nil, err
	}
	ok = true
	return s, nil
}

// HTTP admission/body/response join is the serving owner's prerequisite. A
// live returned blob FD prevents closing the DB/root and returning its writer.
func (s *Store) Close() error {
	release, err := s.gate.acquire(context.Background(), true)
	if err != nil {
		return err
	}
	defer release()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return s.closeErr
	}
	if s.Blobs != nil {
		if err := s.Blobs.Close(); err != nil {
			return err
		}
	}
	err = nil
	if s.Metadata != nil {
		err = errors.Join(err, s.Metadata.Close())
	}
	if s.db != nil {
		err = errors.Join(err, s.db.Close())
	}
	if s.lock != nil {
		err = errors.Join(err, s.lock.Close())
	}
	s.closed = true
	s.closeErr = err
	return err
}
