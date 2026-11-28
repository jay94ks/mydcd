// SPDX-License-Identifier: Apache-2.0

// Package compat holds the upgrade compatibility bundles
// (devel/design/upgrades.md 3-8): a stopped server's state root recorded by
// one build, which every later build of the same major must replay to the
// same bytes.
//
// A bundle is a directory testdata/<name>/ with
//
//	state.tar.gz  the server's state root (control/raft.db, control/fsm.db,
//	              the installation record and the rest), modes kept
//	node-key.tar.gz  the server's identity directory (a test key)
//	node.json     the node.yaml the root was installed with, without paths
//	state.sha256  hex SHA-256 of state.Encode of the recording build's state
//	build.txt     the recording build's version and features
//
// Record writes one; Check replays one with this build.
package compat

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/jay94ks/seafield/internal/app"
	"github.com/jay94ks/seafield/internal/buildinfo"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/config"
)

// Digest is the hex SHA-256 of a state's canonical encoding.
func Digest(s state.State) (string, error) {
	b, err := state.Encode(s)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// Replay checks the stopped server root c.Node.StateDir: it copies it into
// scratch and replays it there with this build (app.Replay), so the root is
// left as it was.
func Replay(c config.Node, scratch string) (state.State, error) {
	dir := filepath.Join(scratch, "state")
	if err := copyTree(c.Node.StateDir, dir); err != nil {
		return state.State{}, err
	}
	c.Node.StateDir = dir
	return app.Replay(c)
}

// Record writes bundle dir from the stopped server root c.Node.StateDir and
// the state this build replays from it.
func Record(dir string, c config.Node, s state.State) error {
	digest, err := Digest(s)
	if err != nil {
		return err
	}
	if err = os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	root, key := c.Node.StateDir, c.Node.IdentityDir
	c.Node.StateDir, c.Node.IdentityDir, c.Node.ManagementSocket = "", "", ""
	node, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	build := fmt.Sprintf("%s\n%s\n", buildinfo.Version(), buildinfo.Own.String())
	for name, b := range map[string][]byte{"node.json": append(node, '\n'), "state.sha256": []byte(digest + "\n"), "build.txt": []byte(build)} {
		if err = os.WriteFile(filepath.Join(dir, name), b, 0o644); err != nil {
			return err
		}
	}
	if err = pack(key, filepath.Join(dir, "node-key.tar.gz")); err != nil {
		return err
	}
	return pack(root, filepath.Join(dir, "state.tar.gz"))
}

// Check replays bundle dir with this build and compares the state with the
// recording build's.
func Check(dir, scratch string) error {
	var c config.Node
	b, err := os.ReadFile(filepath.Join(dir, "node.json"))
	if err != nil {
		return err
	}
	if err = json.Unmarshal(b, &c); err != nil {
		return fmt.Errorf("node.json: %w", err)
	}
	want, err := os.ReadFile(filepath.Join(dir, "state.sha256"))
	if err != nil {
		return err
	}
	root := filepath.Join(scratch, "state")
	if err = unpack(filepath.Join(dir, "state.tar.gz"), root); err != nil {
		return err
	}
	key := filepath.Join(scratch, "node-key")
	if err = unpack(filepath.Join(dir, "node-key.tar.gz"), key); err != nil {
		return err
	}
	c.Node.StateDir, c.Node.IdentityDir = root, key
	s, err := app.Replay(c)
	if err != nil {
		return err
	}
	got, err := Digest(s)
	if err != nil {
		return err
	}
	if got != strings.TrimSpace(string(want)) {
		return fmt.Errorf("replayed state %s differs from the recorded %s", got, strings.TrimSpace(string(want)))
	}
	return nil
}

// Bundles lists the bundle directories under root (testdata).
func Bundles(root string) ([]string, error) {
	entries, err := os.ReadDir(root)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() {
			out = append(out, filepath.Join(root, e.Name()))
		}
	}
	return out, nil
}

func copyTree(from, to string) error {
	return filepath.WalkDir(from, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(from, path)
		if err != nil {
			return err
		}
		target := filepath.Join(to, rel)
		info, err := d.Info()
		if err != nil {
			return err
		}
		switch {
		case d.IsDir():
			return os.MkdirAll(target, info.Mode().Perm())
		case info.Mode().IsRegular():
			return copyFile(path, target, info.Mode().Perm())
		}
		return nil // sockets and the like are not state
	})
}

func copyFile(from, to string, mode fs.FileMode) error {
	in, err := os.Open(from)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(to, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if _, err = io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

func pack(from, file string) error {
	f, err := os.Create(file)
	if err != nil {
		return err
	}
	defer f.Close()
	z := gzip.NewWriter(f)
	w := tar.NewWriter(z)
	err = filepath.WalkDir(from, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if !d.IsDir() && !info.Mode().IsRegular() {
			return nil
		}
		rel, err := filepath.Rel(from, path)
		if err != nil || rel == "." {
			return err
		}
		h := &tar.Header{Name: filepath.ToSlash(rel), Mode: int64(info.Mode().Perm())}
		if d.IsDir() {
			h.Typeflag, h.Name = tar.TypeDir, h.Name+"/"
			return w.WriteHeader(h)
		}
		h.Typeflag, h.Size = tar.TypeReg, info.Size()
		if err = w.WriteHeader(h); err != nil {
			return err
		}
		in, err := os.Open(path)
		if err != nil {
			return err
		}
		defer in.Close()
		_, err = io.Copy(w, in)
		return err
	})
	if err == nil {
		err = w.Close()
	}
	if err == nil {
		err = z.Close()
	}
	if err == nil {
		err = f.Close()
	}
	return err
}

func unpack(file, to string) error {
	f, err := os.Open(file)
	if err != nil {
		return err
	}
	defer f.Close()
	z, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	r := tar.NewReader(z)
	if err = os.MkdirAll(to, 0o700); err != nil {
		return err
	}
	for {
		h, err := r.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		name := filepath.FromSlash(strings.TrimSuffix(h.Name, "/"))
		if !filepath.IsLocal(name) {
			return fmt.Errorf("bundle path %q leaves the root", h.Name)
		}
		target := filepath.Join(to, name)
		mode := fs.FileMode(h.Mode).Perm()
		switch h.Typeflag {
		case tar.TypeDir:
			if err = os.MkdirAll(target, mode); err != nil {
				return err
			}
		case tar.TypeReg:
			out, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
			if err != nil {
				return err
			}
			_, err = io.Copy(out, r)
			if cerr := out.Close(); err == nil {
				err = cerr
			}
			if err != nil {
				return err
			}
		default:
			return fmt.Errorf("bundle entry %q is not a file or directory", h.Name)
		}
	}
}
