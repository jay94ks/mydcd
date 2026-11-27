// SPDX-License-Identifier: Apache-2.0

//go:build linux

package lifecycle

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/jay94ks/seafield/internal/engine"
	"github.com/jay94ks/seafield/internal/schema"
)

const compilerUID = 10001

type compilerFiles struct {
	input, output, cache             *os.File
	inputPath, outputPath, cachePath string
	outputRoot                       *os.Root
}

func (f *compilerFiles) Close() error {
	var err error
	if f.outputRoot != nil {
		err = f.outputRoot.Close()
	}
	for _, file := range []*os.File{f.input, f.output, f.cache} {
		if file != nil {
			err = errors.Join(err, file.Close())
		}
	}
	f.input, f.output, f.cache, f.outputRoot = nil, nil, nil, nil
	return err
}
func (f *compilerFiles) Sources() []engine.BindSource {
	return []engine.BindSource{{Path: f.inputPath, DirectoryFD: int(f.input.Fd())}, {Path: f.outputPath, DirectoryFD: int(f.output.Fd())}, {Path: f.cachePath, DirectoryFD: int(f.cache.Fd())}}
}

func compilerCachePath(b BuildIntent, p TenantPolicy) string {
	hash := sha256.Sum256([]byte(p.Build.Image + "\x00" + p.Build.Toolchain + "\x00" + b.Target))
	return "go-cache/" + b.Tenant + "/" + hex.EncodeToString(hash[:])
}

func (m *CompilerOwner) currentDirectory(r compilerDisk) error {
	for _, name := range []string{"jobs", "jobs/" + r.Intent.Tenant} {
		info, err := m.root.Lstat(name)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0700 {
			return ErrCompilerOwner
		}
	}
	info, err := m.root.Lstat(compilerJobPath(r.Intent))
	if err != nil {
		return err
	}
	got, err := directoryIdentity(info)
	if err != nil || got != r.Directory || info.Mode().Perm() != 0700 {
		return ErrCompilerOwner
	}
	return nil
}

func syncCompilerDirectories(root *os.Root, paths map[string]bool) error {
	ordered := make([]string, 0, len(paths))
	for dir := range paths {
		ordered = append(ordered, dir)
	}
	sort.Slice(ordered, func(i, j int) bool { return len(ordered[i]) > len(ordered[j]) })
	for _, dir := range ordered {
		f, err := root.Open(dir)
		if err != nil {
			return err
		}
		err = f.Sync()
		closeErr := f.Close()
		if err != nil || closeErr != nil {
			return errors.Join(err, closeErr)
		}
	}
	return nil
}
func compilerParents(paths map[string]bool, file string) {
	for dir := path.Dir(file); ; dir = path.Dir(dir) {
		paths[dir] = true
		if dir == "." {
			return
		}
	}
}

// Existing directories are checked, never repaired by chmod/chown. Only a new
// owned leaf may receive builder permissions, before it is mounted anywhere.
func (m *CompilerOwner) ensureDirectory(name string, uid, gid int, mode os.FileMode) error {
	created := false
	if err := m.root.Mkdir(name, mode); err == nil {
		created = true
	} else if !os.IsExist(err) {
		return err
	}
	info, err := m.root.Lstat(name)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return ErrCompilerOwner
	}
	if created {
		if err := m.root.Chown(name, uid, gid); err != nil {
			_ = m.root.Remove(name) // only our still-empty new leaf
			return err
		}
		if err := m.root.Chmod(name, mode); err != nil {
			return err
		}
		info, err = m.root.Lstat(name)
		if err != nil {
			return err
		}
	}
	actualUID, actualGID, ok := compilerOwnership(info)
	if !ok || actualUID != uid || actualGID != gid || info.Mode().Perm() != mode {
		return ErrCompilerOwner
	}
	parents := map[string]bool{name: true}
	compilerParents(parents, name)
	return syncCompilerDirectories(m.root, parents)
}

func (m *CompilerOwner) prepareDirectories(r *compilerDisk) error {
	// Every parent is private to sfcd; only the mounted leaves admit UID10001.
	uid, gid := os.Geteuid(), os.Getegid()
	for _, name := range []string{"jobs", "jobs/" + r.Intent.Tenant, "go-cache", "go-cache/" + r.Intent.Tenant} {
		if err := m.ensureDirectory(name, uid, gid, 0700); err != nil {
			return err
		}
	}
	job := compilerJobPath(r.Intent)
	if err := m.ensureDirectory(job, uid, gid, 0700); err != nil {
		return err
	}
	info, err := m.root.Stat(job)
	if err != nil {
		return err
	}
	identity, err := directoryIdentity(info)
	if err != nil {
		return err
	}
	if r.Directory == (compilerDirectory{}) {
		r.Directory = identity
		if err := m.save(*r); err != nil {
			return err
		}
	} else if identity != r.Directory {
		return ErrCompilerOwner
	}
	for _, dir := range []struct {
		name     string
		uid, gid int
		mode     os.FileMode
	}{
		{job + "/input", uid, gid, 0755}, {job + "/output", compilerUID, compilerUID, 0700}, {compilerCachePath(r.Intent, r.Policy), compilerUID, compilerUID, 0700},
	} {
		if err := m.ensureDirectory(dir.name, dir.uid, dir.gid, dir.mode); err != nil {
			return err
		}
	}
	return nil
}

func completeCompilerInput(root *os.Root, batch CompileBatch, inputs []*Compilation) error {
	byKey := map[[32]byte]*Compilation{}
	for _, input := range inputs {
		if input != nil {
			byKey[input.item.Key] = input
		}
	}
	parents := map[string]bool{".": true}
	write := func(name string, data []byte) error {
		info, err := root.Lstat(name)
		if os.IsNotExist(err) {
			if err := writeCompileFile(root, name, data); err != nil {
				return err
			}
		} else {
			if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0444 || info.Size() != int64(len(data)) {
				return ErrSource
			}
			old, err := readCompileFile(root, name, int64(len(data)))
			if err != nil || !bytes.Equal(old, data) {
				clear(old)
				return ErrSource
			}
			clear(old)
		}
		compilerParents(parents, name)
		return nil
	}
	for _, item := range batch.Items {
		input, ok := byKey[item.Key]
		if !ok {
			return ErrSource
		}
		a, _ := json.Marshal(item)
		b, _ := json.Marshal(input.Item())
		if !bytes.Equal(a, b) {
			return ErrSource
		}
		for _, file := range item.Files {
			data, ok := input.files[file.Path]
			if !ok || uint64(len(data)) != file.Length || sha256.Sum256(data) != file.Digest {
				return ErrSource
			}
			if err := write(path.Join("items", hex.EncodeToString(item.Key[:]), file.Path), data); err != nil {
				return err
			}
		}
	}
	raw, _ := json.Marshal(batch)
	if err := write("manifest.json", raw); err != nil {
		return err
	}
	return syncCompilerDirectories(root, parents)
}

// Stage is called with the ORIGINAL accepted intent/policy/batch. A partial
// input resumes only verified identical files before any Create dispatch.
func (m *CompilerOwner) Stage(ctx context.Context, b BuildIntent, p TenantPolicy, batch CompileBatch, inputs []*Compilation) error {
	m.life.RLock()
	defer m.life.RUnlock()
	m.mu.Lock()
	defer m.mu.Unlock()
	if b.ValidateCompilation(p, batch) != nil {
		return ErrCompilerOwner
	}
	r, err := m.accept(ctx, b, p)
	if err != nil {
		return err
	}
	if r.Cancel || r.Closure != nil {
		return ErrCompilerOwner
	}
	if r.InputReady {
		_, err := m.readBatch(r)
		return err
	}
	if r.CreateDispatched {
		return ErrCompilerOwner
	}
	if err := m.prepareDirectories(&r); err != nil {
		return err
	}
	input, err := m.root.OpenRoot(compilerJobPath(b) + "/input")
	if err != nil {
		return err
	}
	err = completeCompilerInput(input, batch, inputs)
	closeErr := input.Close()
	if err != nil || closeErr != nil {
		return errors.Join(err, closeErr)
	}
	r.InputReady = true
	return m.save(r)
}

func (m *CompilerOwner) readBatch(r compilerDisk) (CompileBatch, error) {
	batch, err := m.readOriginalBatch(r)
	if err != nil || r.Intent.ValidateCompilation(r.Policy, batch) != nil {
		return CompileBatch{}, errors.Join(ErrCompilerOwner, err)
	}
	return batch, nil
}

// Cleanup may read an already accepted manifest after the active compiler/SDK
// changed. Exact original bytes/hash, not the current SDK, govern that read.
// This function cannot authorize new execution.
func (m *CompilerOwner) readOriginalBatch(r compilerDisk) (CompileBatch, error) {
	if !r.InputReady || r.WorkspaceClosed || m.currentDirectory(r) != nil {
		return CompileBatch{}, ErrCompilerOwner
	}
	input, err := m.root.OpenRoot(compilerJobPath(r.Intent) + "/input")
	if err != nil {
		return CompileBatch{}, err
	}
	defer input.Close()
	raw, err := readCompileFile(input, "manifest.json", MaxCompileManifestBytes)
	if err != nil {
		return CompileBatch{}, err
	}
	digest := sha256.Sum256(raw)
	batch, err := schema.Decode[CompileBatch](raw)
	clear(raw)
	if err != nil || digest != r.Intent.Manifest || batch.Schema != 1 || batch.Job != r.Intent.ID || batch.Tenant != r.Intent.Tenant || batch.DeadlineUnixMilli != r.Intent.DeadlineUnixMilli || batch.GOOS+"/"+batch.GOARCH != r.Intent.Target {
		return CompileBatch{}, ErrCompilerOwner
	}
	return batch, nil
}

func (m *CompilerOwner) openFiles(r compilerDisk) (*compilerFiles, error) {
	if m.currentDirectory(r) != nil || !r.InputReady || r.WorkspaceClosed {
		return nil, ErrCompilerOwner
	}
	f := &compilerFiles{}
	paths := []string{compilerJobPath(r.Intent) + "/input", compilerJobPath(r.Intent) + "/output", compilerCachePath(r.Intent, r.Policy)}
	var err error
	for i, name := range paths {
		info, e := m.root.Lstat(name)
		if e != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			f.Close()
			return nil, ErrCompilerOwner
		}
		uid, gid, ok := compilerOwnership(info)
		wantUID, wantGID, mode := compilerUID, compilerUID, os.FileMode(0700)
		if i == 0 {
			wantUID, wantGID, mode = os.Geteuid(), os.Getegid(), 0755
		}
		if !ok || uid != wantUID || gid != wantGID || info.Mode().Perm() != mode {
			f.Close()
			return nil, ErrCompilerOwner
		}
		var file *os.File
		file, err = m.root.Open(name)
		if err != nil {
			f.Close()
			return nil, err
		}
		actual, e := file.Stat()
		if e != nil || !os.SameFile(info, actual) {
			file.Close()
			f.Close()
			return nil, ErrCompilerOwner
		}
		absolute := filepath.Join(m.identity.Path, filepath.FromSlash(name))
		switch i {
		case 0:
			f.input, f.inputPath = file, absolute
		case 1:
			f.output, f.outputPath = file, absolute
		case 2:
			f.cache, f.cachePath = file, absolute
		}
	}
	f.outputRoot, err = m.root.OpenRoot(paths[1])
	if err != nil {
		f.Close()
		return nil, err
	}
	actual, err := f.outputRoot.Stat(".")
	original, originalErr := f.output.Stat()
	if err != nil || originalErr != nil || !os.SameFile(actual, original) {
		f.Close()
		return nil, ErrCompilerOwner
	}
	return f, nil
}

func (m *CompilerOwner) removeWorkspace(r compilerDisk) error {
	name := compilerJobPath(r.Intent)
	if _, err := m.root.Lstat(name); os.IsNotExist(err) {
		// Removal is allowed only after positive native closure/output settlement;
		// a crash after our RemoveAll but before save may already have done it.
		parent := path.Dir(name)
		for parent != "." {
			if _, err := m.root.Stat(parent); err == nil {
				break
			} else if !os.IsNotExist(err) {
				return err
			}
			parent = path.Dir(parent)
		}
		return syncCompilerDirectories(m.root, map[string]bool{parent: true})
	}
	if m.currentDirectory(r) != nil || !r.OutputSettled || !r.Removed && !r.CreateNotSent {
		return ErrCompilerOwner
	}
	if err := m.root.RemoveAll(name); err != nil {
		return err
	}
	return syncCompilerDirectories(m.root, map[string]bool{path.Dir(name): true})
}

func (m *CompilerOwner) Pending() ([]BuildIntent, error) {
	m.life.RLock()
	defer m.life.RUnlock()
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed || m.uncertain {
		return nil, ErrCompilerOwner
	}
	var out []BuildIntent
	for key, pending := range m.known {
		if !pending {
			continue
		}
		name := strings.TrimPrefix(key, compilerRecordPrefix)
		parts := strings.Split(name, "/")
		if len(parts) != 2 {
			return nil, ErrCompilerOwner
		}
		r, err := m.load(parts[0], parts[1])
		if err != nil {
			return nil, err
		}
		if r.Closure == nil {
			out = append(out, r.Intent.Clone())
		}
	}
	sort.Slice(out, func(i, j int) bool { return compilerJobKey(out[i]) < compilerJobKey(out[j]) })
	return out, nil
}
