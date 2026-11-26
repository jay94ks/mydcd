// SPDX-License-Identifier: Apache-2.0

package workload

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"path"
	"strings"

	contract "github.com/jay94ks/mydcd/lifecycle/v1"
)

var ErrProbeFileContent = errors.New("container file content unavailable or outside probe limits")

func validFileContent(q contract.FileProbe) bool {
	if q.ContentDigest == "" {
		return q.MaxBytes == 0
	}
	digest, err := hex.DecodeString(q.ContentDigest)
	return err == nil && len(digest) == sha256.Size && hex.EncodeToString(digest) == q.ContentDigest && !bytes.Equal(digest, make([]byte, sha256.Size)) && q.Kind == "regular" && q.MaxBytes > 0 && q.MaxBytes <= 1<<20
}

// Read one regular file from Docker's TAR stream without extraction or
// retaining its contents. Extra/link/sparse entries and oversized metadata
// are errors; only a complete bounded file can produce a hash comparison.
func matchProbeFileArchive(ctx context.Context, body io.ReadCloser, q contract.FileProbe, size int64, mode uint32) (match bool, outcome error) {
	if body == nil {
		return false, ErrProbeFileContent
	}
	defer func() { outcome = errors.Join(outcome, body.Close()) }()
	if ctx == nil || !validFileContent(q) || q.ContentDigest == "" || size < 0 || size > int64(q.MaxBytes) {
		return false, ErrProbeFileContent
	}
	done := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { _ = body.Close(); close(done) })
	defer func() {
		if !stop() {
			<-done
		}
	}()
	if err := ctx.Err(); err != nil {
		return false, err
	}
	limited := &io.LimitedReader{R: body, N: int64(q.MaxBytes) + (64 << 10)}
	reader := tar.NewReader(limited)
	header, err := reader.Next()
	if err != nil {
		return false, errors.Join(ErrProbeFileContent, err)
	}
	base := path.Base(q.Path)
	if header.Name != base && header.Name != "./"+base || header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeRegA || header.Linkname != "" || header.Size != size || header.Mode < 0 || header.Mode > 07777 || uint32(header.Mode) != mode {
		return false, ErrProbeFileContent
	}
	for name := range header.PAXRecords {
		if strings.HasPrefix(name, "GNU.sparse") || strings.HasPrefix(name, "SCHILY.realsize") {
			return false, ErrProbeFileContent
		}
	}
	hash := sha256.New()
	if _, err := io.CopyN(hash, reader, size); err != nil {
		return false, errors.Join(ErrProbeFileContent, err)
	}
	if _, err := reader.Next(); !errors.Is(err, io.EOF) {
		return false, errors.Join(ErrProbeFileContent, err)
	}
	// TAR EOF permits zero padding only. Bound and reject hidden appended
	// archives/garbage without reading an unbounded HTTP response.
	var tail [512]byte
	for {
		n, err := limited.Read(tail[:])
		for _, b := range tail[:n] {
			if b != 0 {
				return false, ErrProbeFileContent
			}
		}
		if err != nil {
			if !errors.Is(err, io.EOF) {
				return false, err
			}
			break
		}
	}
	if limited.N == 0 {
		return false, ErrProbeFileContent
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	return hex.EncodeToString(hash.Sum(nil)) == q.ContentDigest, nil
}
