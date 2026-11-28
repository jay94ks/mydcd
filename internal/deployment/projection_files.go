// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/jay94ks/seafield/internal/workload"
)

// This integrity record stays in the private node root. Content digests are
// never sent in the shared journal/API, where weak secrets could be guessed.
type projectionManifest struct {
	Schema  uint8
	Scope   projectionScope
	Sizes   []int
	Digests [][32]byte
	Sources []string `json:",omitempty"`
}

func (m *ProjectionStore) retainScope(b Binding) error {
	ref := projectionReference(b)
	name := "scope-" + projectionName(ref.Key, ref.Generation) + ".json"
	raw, _ := json.Marshal(projectionScope{1, ownBinding(b.d)})
	if _, err := m.root.Lstat(name); err == nil {
		old, err := projectionRead(m.root, name, nil, 1<<20)
		if err != nil || !bytes.Equal(raw, old) {
			return ErrProjectionStore
		}
		return nil
	} else if !os.IsNotExist(err) {
		return ErrProjectionStore
	}
	dir, err := m.root.Open(".")
	if err != nil {
		return ErrProjectionStore
	}
	names, err := dir.Readdirnames(-1)
	_ = dir.Close()
	if err != nil {
		return ErrProjectionStore
	}
	count := 0
	for _, name := range names {
		if strings.HasPrefix(name, "scope-") {
			count++
		}
	}
	if count >= maxBindings {
		return ErrProjectionStore
	}
	if projectionMetadata(m.root, name, raw) != nil {
		return ErrProjectionStore
	}
	return nil
}

func projectionMetadata(root *os.Root, name string, raw []byte) error {
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return ErrProjectionStore
	}
	temp := "metadata-" + hex.EncodeToString(nonce[:])
	defer root.Remove(temp)
	if projectionWrite(root, temp, raw, nil) != nil || root.Rename(temp, name) != nil || projectionSync(root) != nil {
		return ErrProjectionStore
	}
	return nil
}
func (m *ProjectionStore) retainedScope(ref workload.InputRef) (Binding, error) {
	raw, err := projectionRead(m.root, "scope-"+projectionName(ref.Key, ref.Generation)+".json", nil, 1<<20)
	if err != nil {
		return Binding{}, err
	}
	b, err := m.scope(string(raw))
	if err != nil || projectionReference(b) != ref {
		return Binding{}, ErrProjectionStore
	}
	return b, nil
}

func (m *ProjectionStore) directory(b Binding) (*os.Root, error) {
	name := projectionName(projectionKey(b), b.d.Needs.Generation)
	info, err := m.values.Lstat(name)
	if err != nil || !projectionPrivate(info, true) {
		return nil, ErrProjectionStore
	}
	r, err := m.values.OpenRoot(name)
	if err != nil {
		return nil, ErrProjectionStore
	}
	return r, nil
}
func (m *ProjectionStore) verify(b Binding, files []File) error {
	r, err := m.directory(b)
	if err != nil {
		return err
	}
	defer r.Close()
	raw, err := projectionRead(r, "manifest.json", nil, 1<<20)
	if err != nil {
		return err
	}
	var manifest projectionManifest
	if json.Unmarshal(raw, &manifest) != nil || manifest.Schema != 1 || len(manifest.Sizes) != len(b.d.Needs.Files) || len(manifest.Digests) != len(b.d.Needs.Files) {
		return ErrProjectionStore
	}
	if len(manifest.Sources) != 0 && len(manifest.Sources) != len(manifest.Sizes) || files != nil && len(files) != len(manifest.Sizes) {
		return ErrProjectionStore
	}
	for i, source := range manifest.Sources {
		parts := strings.Split(source, "/")
		if len(parts) != 2 || parts[0] != "" && !identifier(parts[0]) || !identifier(parts[1]) || files != nil && files[i].Source != source {
			return ErrProjectionStore
		}
	}
	encoded, _ := json.Marshal(manifest)
	scope, _ := json.Marshal(projectionScope{1, ownBinding(b.d)})
	gotScope, _ := json.Marshal(manifest.Scope)
	if !bytes.Equal(raw, encoded) || !bytes.Equal(scope, gotScope) || files != nil && len(files) != len(manifest.Sizes) {
		return ErrProjectionStore
	}
	total := 0
	for i, p := range b.d.Needs.Files {
		size := manifest.Sizes[i]
		if size < 0 || size > 64<<20-total {
			return ErrProjectionStore
		}
		total += size
		data, err := projectionRead(r, fmt.Sprintf("file-%04d", i), &p, size)
		if err != nil {
			return err
		}
		valid := len(data) == size && sha256.Sum256(data) == manifest.Digests[i] && (files == nil || files[i].Projection == p && bytes.Equal(data, files[i].Data))
		clear(data)
		if !valid {
			return ErrProjectionStore
		}
	}
	entries, err := r.Open(".")
	if err != nil {
		return ErrProjectionStore
	}
	defer entries.Close()
	names, err := entries.Readdirnames(-1)
	if err != nil || len(names) != len(b.d.Needs.Files)+1 {
		return ErrProjectionStore
	}
	return nil
}

func projectionWrite(root *os.Root, name string, data []byte, p *Projection) error {
	f, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return ErrProjectionStore
	}
	defer f.Close()
	n, err := f.Write(data)
	if err == nil && n != len(data) {
		err = io.ErrShortWrite
	}
	if err == nil && p != nil && p.Kind != "env" {
		info, statErr := f.Stat()
		if statErr != nil {
			return ErrProjectionStore
		}
		if info.Sys() == nil {
			return ErrProjectionStore
		}
		if err = f.Chown(int(p.UID), int(p.GID)); err == nil {
			err = f.Chmod(os.FileMode(p.Mode))
		}
	}
	if err != nil || f.Sync() != nil {
		return ErrProjectionStore
	}
	return nil
}

func (m *ProjectionStore) prepare(b Binding, files []File) error {
	name := projectionName(projectionKey(b), b.d.Needs.Generation)
	if _, err := m.values.Lstat(name); err == nil {
		return m.verify(b, files)
	} else if !os.IsNotExist(err) {
		return ErrProjectionStore
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return ErrProjectionStore
	}
	temp := "prepare-" + name + "-" + hex.EncodeToString(nonce[:])
	if m.values.Mkdir(temp, 0700) != nil {
		return ErrProjectionStore
	}
	defer m.values.RemoveAll(temp)
	r, err := m.values.OpenRoot(temp)
	if err != nil {
		return ErrProjectionStore
	}
	defer r.Close()
	manifest := projectionManifest{Schema: 1, Scope: projectionScope{1, ownBinding(b.d)}}
	for i, f := range files {
		if err = projectionWrite(r, fmt.Sprintf("file-%04d", i), f.Data, &f.Projection); err != nil {
			return err
		}
		manifest.Sizes = append(manifest.Sizes, len(f.Data))
		manifest.Digests = append(manifest.Digests, sha256.Sum256(f.Data))
		manifest.Sources = append(manifest.Sources, f.Source)
	}
	raw, _ := json.Marshal(manifest)
	if projectionWrite(r, "manifest.json", raw, nil) != nil || projectionSync(r) != nil {
		return ErrProjectionStore
	}
	// The seen marker goes first: from here on a missing directory of this
	// generation in this boot is a loss, never a restore.
	if _, err = m.values.Lstat("seen-" + name); os.IsNotExist(err) && projectionMetadata(m.values, "seen-"+name, nil) != nil {
		return ErrProjectionStore
	}
	if m.values.Rename(temp, name) != nil || projectionSync(m.values) != nil {
		return ErrProjectionStore
	}
	return m.verify(b, files)
}

// restore writes b's value directory lost with an earlier boot's tmpfs
// again, from values read now: the current gate (the approval for this
// node and deployment) must still admit b, as for a first publication.
func (m *ProjectionStore) restore(ctx context.Context, b Binding, files []File) error {
	if err := m.gate(ctx, b); err != nil {
		return err
	}
	return m.prepare(b, files)
}

// dropDiskValues deletes value directories (and unfinished ones) left in
// the journal root by a daemon that kept values on a disk.
func (m *ProjectionStore) dropDiskValues() error {
	dir, err := m.root.Open(".")
	if err != nil {
		return ErrProjectionStore
	}
	names, err := dir.Readdirnames(-1)
	_ = dir.Close()
	if err != nil {
		return ErrProjectionStore
	}
	dropped := false
	for _, name := range names {
		raw, decodeErr := hex.DecodeString(name)
		if decodeErr == nil && len(raw) == 32 || strings.HasPrefix(name, "prepare-") {
			if m.root.RemoveAll(name) != nil {
				return ErrProjectionStore
			}
			dropped = true
		}
	}
	if dropped {
		return projectionSync(m.root)
	}
	return nil
}
