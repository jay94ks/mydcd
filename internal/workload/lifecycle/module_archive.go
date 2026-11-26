// SPDX-License-Identifier: Apache-2.0

package lifecycle

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"io"
	"strings"

	"golang.org/x/mod/modfile"
	"golang.org/x/mod/module"
	modzip "golang.org/x/mod/zip"
)

// MaxModuleBytes bounds a single supplied ZIP as well as the ZIP plus its
// expanded contents. It shares the resolver's per-input hard bound.
const MaxModuleBytes = maxResolveBytes

type moduleImage struct {
	files      map[string][]byte
	expanded   uint64
	definition *modfile.File
}

// inspectModuleArchive is used by staging and resolution, never a second ZIP
// algorithm. Selection/import/type correctness is a later source boundary.
func inspectModuleArchive(ctx context.Context, a ModuleArchive, limit uint64) (moduleImage, error) {
	zero := moduleImage{}
	limit = min(limit, uint64(MaxModuleBytes))
	if ctx == nil || !a.Pin.valid() || reservedSourcePath(a.Pin.Path) || a.Pin.Length != uint64(len(a.ZIP)) || a.Pin.Length > limit || sha256.Sum256(a.ZIP) != a.Pin.Digest {
		return zero, ErrSource
	}
	if err := ctx.Err(); err != nil {
		return zero, err
	}
	reader, err := zip.NewReader(bytes.NewReader(a.ZIP), int64(len(a.ZIP)))
	if err != nil || len(reader.File) > maxResolveFiles {
		return zero, ErrSource
	}
	image := moduleImage{files: map[string][]byte{}}
	prefix := a.Pin.Path + "@" + a.Pin.Version + "/"
	files := make([]modzip.File, 0, len(reader.File))
	for _, file := range reader.File {
		if err := ctx.Err(); err != nil {
			return zero, err
		}
		relative, ok := strings.CutPrefix(file.Name, prefix)
		if !ok {
			return zero, ErrSource
		}
		if file.FileInfo().IsDir() {
			if strings.TrimSuffix(relative, "/") != "" && module.CheckFilePath(strings.TrimSuffix(relative, "/")) != nil {
				return zero, ErrSource
			}
			continue
		}
		if !file.Mode().IsRegular() || module.CheckFilePath(relative) != nil || file.UncompressedSize64 > limit-a.Pin.Length-image.expanded {
			return zero, ErrSource
		}
		if _, duplicate := image.files[relative]; duplicate {
			return zero, ErrSource
		}
		stream, err := file.Open()
		if err != nil {
			return zero, ErrSource
		}
		data, readErr := io.ReadAll(io.LimitReader(stream, int64(file.UncompressedSize64)+1))
		closeErr := stream.Close()
		if readErr != nil || closeErr != nil || uint64(len(data)) != file.UncompressedSize64 {
			return zero, ErrSource
		}
		image.expanded += file.UncompressedSize64
		image.files[relative] = data
		files = append(files, moduleFile{name: relative, data: data})
		if relative == "go.mod" {
			definition, err := modfile.Parse("go.mod", data, nil)
			if err != nil || definition.Module == nil || definition.Module.Mod.Path != a.Pin.Path || len(definition.Replace) != 0 || len(definition.Exclude) != 0 {
				return zero, ErrSource
			}
			for _, req := range definition.Require {
				if module.Check(req.Mod.Path, req.Mod.Version) != nil {
					return zero, ErrSource
				}
			}
			image.definition = definition
		}
	}
	checked, err := modzip.CheckFiles(files)
	if err != nil || checked.Err() != nil || len(checked.Omitted) != 0 {
		return zero, ErrSource
	}
	return image, nil
}
