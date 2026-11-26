// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// Files reads explicitly installed, versioned private files. It cannot write,
// choose latest, or fall back to Vault. Current authority is the caller's gate.
type Files struct {
	root            *os.File
	profile, prefix string
	maxBytes        int
}

func (*Files) MarshalJSON() ([]byte, error) { return nil, ErrPrivateMaterial }
func (*Files) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "[redacted installed secret files]")
}

// OpenFiles pins the installed root. Each object/revision directory contains
// manifest.json (schema/profile/object/revision/keys) and one raw key-<key> file.
// Only the installing OS identity can read/write the tree. Values never enter
// the ordinary journal, app document, manifest, or shared metadata.
func OpenFiles(profile, root, prefix string, maxBytes int) (*Files, error) {
	if !identifier(profile) || !providerPath(prefix) || !filepath.IsAbs(root) || filepath.Clean(root) != root || maxBytes < 1 || maxBytes > 4<<20 {
		return nil, ErrProvider
	}
	fd, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, ErrProvider
	}
	f := os.NewFile(uintptr(fd), "installed-secret-root")
	if !privateSecretFile(f, true) {
		_ = f.Close()
		return nil, ErrProvider
	}
	return &Files{f, profile, prefix, maxBytes}, nil
}

func (p *Files) Close() {
	if p != nil && p.root != nil {
		_ = p.root.Close()
	}
}

func privateSecretFile(f *os.File, directory bool) bool {
	var st unix.Stat_t
	if unix.Fstat(int(f.Fd()), &st) != nil || st.Uid != uint32(os.Geteuid()) || st.Mode&0077 != 0 {
		return false
	}
	if directory {
		return st.Mode&unix.S_IFMT == unix.S_IFDIR
	}
	return st.Mode&unix.S_IFMT == unix.S_IFREG && st.Nlink == 1 && st.Mode&0111 == 0
}

func secretFileAt(parent *os.File, name string, directory bool) (*os.File, error) {
	flags := unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC | unix.O_NONBLOCK
	if directory {
		flags |= unix.O_DIRECTORY
	}
	fd, err := unix.Openat(int(parent.Fd()), name, flags, 0)
	if err != nil {
		return nil, ErrProvider
	}
	f := os.NewFile(uintptr(fd), "installed-secret-entry")
	if !privateSecretFile(f, directory) {
		_ = f.Close()
		return nil, ErrProvider
	}
	return f, nil
}

func readSecretFile(dir *os.File, name string, limit int) ([]byte, error) {
	f, err := secretFileAt(dir, name, false)
	if err != nil {
		return nil, ErrProvider
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, int64(limit)+1))
	if err != nil || len(raw) > limit {
		clear(raw)
		return nil, ErrProvider
	}
	return raw, nil
}

func (p *Files) Fetch(ctx context.Context, secret string, ref Reference) (Fetched, error) {
	ref, err := canonicalReference(ref)
	if err != nil || p == nil || p.root == nil || !privateSecretFile(p.root, true) || ctx.Err() != nil || ref.Profile != p.profile || !providerPath(ref.Object) || ref.Object != p.prefix && !strings.HasPrefix(ref.Object, p.prefix+"/") {
		return Fetched{}, ErrProvider
	}
	dir := p.root
	for _, name := range append(strings.Split(ref.Object, "/"), strconv.FormatUint(ref.Revision, 10)) {
		next, err := secretFileAt(dir, name, true)
		if dir != p.root {
			_ = dir.Close()
		}
		if err != nil {
			return Fetched{}, ErrProvider
		}
		dir = next
	}
	defer dir.Close()
	raw, err := readSecretFile(dir, "manifest.json", 64<<10)
	if err != nil {
		return Fetched{}, ErrProvider
	}
	defer clear(raw)
	var manifest struct {
		Schema   uint8    `json:"schema"`
		Profile  string   `json:"profile"`
		Object   string   `json:"object"`
		Revision uint64   `json:"revision"`
		Keys     []string `json:"keys"`
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&manifest) != nil || manifest.Schema != 1 || manifest.Profile != ref.Profile || manifest.Object != ref.Object || manifest.Revision != ref.Revision || !slices.Equal(manifest.Keys, ref.Keys) {
		return Fetched{}, ErrProvider
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return Fetched{}, ErrProvider
	}
	// An incomplete/extra keyset is rejected before any value is returned.
	names, err := dir.Readdirnames(258)
	if err != nil && err != io.EOF || len(names) != len(ref.Keys)+1 {
		return Fetched{}, ErrProvider
	}
	allowed := map[string]bool{"manifest.json": true}
	for _, key := range ref.Keys {
		allowed["key-"+key] = true
	}
	for _, name := range names {
		if !allowed[name] {
			return Fetched{}, ErrProvider
		}
	}
	out := Fetched{Secret: secret, Reference: ref, Values: map[string][]byte{}}
	ok := false
	defer func() {
		if !ok {
			for _, value := range out.Values {
				clear(value)
			}
		}
	}()
	total := 0
	for _, key := range ref.Keys {
		if ctx.Err() != nil {
			return Fetched{}, ErrProvider
		}
		value, err := readSecretFile(dir, "key-"+key, p.maxBytes-total)
		if err != nil {
			return Fetched{}, ErrProvider
		}
		out.Values[key] = value
		total += len(value)
	}
	if ctx.Err() != nil {
		return Fetched{}, ErrProvider
	}
	ok = true
	return out, nil
}
