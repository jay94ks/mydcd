// SPDX-License-Identifier: Apache-2.0

package lifecycle

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path"
)

// WriteCompileBatch writes only into a newly owned job input root. The node
// owner records the job/manifest before starting a container and owns recovery
// of partial preparation. Existing accepted inputs are never overwritten here.
func WriteCompileBatch(root *os.Root, batch CompileBatch, inputs []*Compilation) error {
	if root == nil || batch.Validate() != nil {
		return ErrSource
	}
	byKey := map[[32]byte]*Compilation{}
	for _, input := range inputs {
		if input != nil {
			byKey[input.item.Key] = input
		}
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
		prefix := path.Join("items", hex.EncodeToString(item.Key[:]))
		for _, file := range item.Files {
			data, ok := input.files[file.Path]
			if !ok || uint64(len(data)) != file.Length || sha256.Sum256(data) != file.Digest {
				return ErrSource
			}
			if err := writeCompileFile(root, path.Join(prefix, file.Path), data); err != nil {
				return err
			}
		}
	}
	raw, err := json.Marshal(batch)
	if err != nil {
		return ErrSource
	}
	if err := writeCompileFile(root, "manifest.json", raw); err != nil {
		return err
	}
	dir, err := root.Open(".")
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func writeCompileFile(root *os.Root, name string, data []byte) error {
	if err := root.MkdirAll(path.Dir(name), 0755); err != nil {
		return err
	}
	f, err := root.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := io.Copy(f, bytes.NewReader(data)); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Chmod(0444); err != nil {
		return err
	}
	return f.Sync()
}

func readCompileFile(root *os.Root, name string, max int64) ([]byte, error) {
	info, err := root.Lstat(name)
	if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > max {
		return nil, ErrSource
	}
	f, err := root.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	actual, err := f.Stat()
	if err != nil || !os.SameFile(info, actual) {
		return nil, ErrSource
	}
	data, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil || int64(len(data)) != info.Size() || int64(len(data)) > max {
		clear(data)
		return nil, ErrSource
	}
	return data, nil
}

// SnapshotCompileItem verifies input bytes as it copies them to the compiler's
// private workspace. Go never rereads a caller-mutable host source path.
func SnapshotCompileItem(input, destination *os.Root, item CompileItem) error {
	if input == nil || destination == nil || !validCompileItem(item) {
		return ErrSource
	}
	prefix := path.Join("items", hex.EncodeToString(item.Key[:]))
	for _, file := range item.Files {
		data, err := readCompileFile(input, path.Join(prefix, file.Path), int64(file.Length))
		if err != nil {
			return err
		}
		if uint64(len(data)) != file.Length || sha256.Sum256(data) != file.Digest {
			clear(data)
			return ErrSource
		}
		err = writeCompileFile(destination, file.Path, data)
		clear(data)
		if err != nil {
			return err
		}
	}
	return nil
}
