// SPDX-License-Identifier: Apache-2.0

// Package pack writes and reads Volume archive packages
// (internal/volumearchive).
package pack

import (
	"context"
	"crypto/sha256"
	"hash"
	"io"
	"os"

	"github.com/jay94ks/seafield/internal/clusterbackup"
	"github.com/jay94ks/seafield/internal/volumearchive"
	"github.com/jay94ks/seafield/internal/workload/volumes"
	"github.com/klauspost/compress/zstd"
)

// Params says how to write one package.
type Params struct {
	ID          string
	Scope       volumes.Scope
	Compression volumearchive.Compression
	Recipients  [][32]byte // cluster key, administrator key
}

// counter hashes and counts the bytes written to the data file.
type counter struct {
	w io.Writer
	h hash.Hash
	n uint64
}

func (c *counter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.h.Write(p[:n])
	c.n += uint64(n)
	return n, err
}

// Pack writes data.mdbk for the Volume at root to out and returns the
// manifest without Node, At or Signature, which the caller fills and signs
// once out is synced. The caller holds the cold reader and native pin, as
// for a backup.
func Pack(ctx context.Context, root *os.Root, out io.Writer, o volumes.ArchiveOptions, p Params) (volumearchive.Manifest, error) {
	m, key, err := PackKey(ctx, root, out, o, p)
	clear(key)
	return m, err
}

// PackKey is Pack that also returns the file's data key, so the writer can
// Verify what it wrote before forgetting the key. The caller clears it.
func PackKey(ctx context.Context, root *os.Root, out io.Writer, o volumes.ArchiveOptions, p Params) (m volumearchive.Manifest, key []byte, err error) {
	if !volumearchive.ValidID(p.ID) || !p.Compression.Valid() || len(p.Recipients) == 0 {
		return volumearchive.Manifest{}, nil, volumearchive.ErrPackage
	}
	count := &counter{w: out, h: sha256.New()}
	sealed, key, err := clusterbackup.WriteSealedKey(count, p.Recipients, clusterbackup.SealedTo{Cluster: p.Scope.Cluster, Context: volumearchive.Context(p.ID)})
	if err != nil {
		return volumearchive.Manifest{}, nil, err
	}
	defer func() {
		if err != nil {
			clear(key)
			key = nil
		}
	}()
	var tarOut io.Writer = sealed
	var enc *zstd.Encoder
	if p.Compression == volumearchive.Zstd {
		enc, err = zstd.NewWriter(sealed, zstd.WithEncoderLevel(zstd.SpeedDefault), zstd.WithEncoderConcurrency(1))
		if err != nil {
			return volumearchive.Manifest{}, nil, err
		}
		tarOut = enc
	}
	receipt, err := volumes.WriteArchive(ctx, root, tarOut, o)
	if enc != nil {
		if closeErr := enc.Close(); err == nil {
			err = closeErr
		}
	}
	if err != nil {
		return volumearchive.Manifest{}, nil, err
	}
	if err = sealed.Close(); err != nil {
		return volumearchive.Manifest{}, nil, err
	}
	m = volumearchive.Manifest{Schema: 1, ID: p.ID, Scope: p.Scope, Compression: p.Compression, Tar: receipt, DataBytes: count.n}
	copy(m.DataDigest[:], count.h.Sum(nil))
	return m, key, nil
}

// OpenFile opens a fresh reader over data.mdbk from its start.
type OpenFile func() (io.ReadCloser, error)

// opener turns data.mdbk into tar passes for volumes. Each pass checks, when
// it is closed, that the rest of the stream is empty and authenticated and
// that the whole file matched the manifest's size and digest. The first
// failure is kept in *failed: volumes ignores Close errors.
func opener(open OpenFile, dataKey []byte, m volumearchive.Manifest, failed *error) volumes.ArchiveOpener {
	fail := func(err error) {
		if *failed == nil {
			*failed = err
		}
	}
	return func() (io.ReadCloser, error) {
		file, err := open()
		if err != nil {
			return nil, err
		}
		h := &hashReader{r: file, h: sha256.New()}
		plain, err := clusterbackup.OpenSealed(h, dataKey)
		if err != nil {
			_ = file.Close()
			return nil, volumearchive.ErrPackage
		}
		p := &pass{file: file, hash: h, plain: plain, m: m, fail: fail}
		if m.Compression == volumearchive.Zstd {
			dec, err := zstd.NewReader(plain, zstd.WithDecoderConcurrency(1), zstd.WithDecoderMaxMemory(256<<20))
			if err != nil {
				_ = file.Close()
				return nil, volumearchive.ErrPackage
			}
			p.dec = dec
		}
		return p, nil
	}
}

type hashReader struct {
	r io.Reader
	h hash.Hash
	n uint64
}

func (r *hashReader) Read(p []byte) (int, error) {
	n, err := r.r.Read(p)
	r.h.Write(p[:n])
	r.n += uint64(n)
	return n, err
}

type pass struct {
	file  io.Closer
	hash  *hashReader
	plain io.Reader
	dec   *zstd.Decoder
	m     volumearchive.Manifest
	fail  func(error)
}

func (p *pass) Read(b []byte) (int, error) {
	if p.dec != nil {
		return p.dec.Read(b)
	}
	return p.plain.Read(b)
}

// Close requires the rest of the tar stream to be empty, then drains the
// sealed stream to its authenticated end and compares the file digest.
func (p *pass) Close() error {
	err := p.finish()
	if p.dec != nil {
		p.dec.Close()
	}
	if closeErr := p.file.Close(); err == nil && closeErr != nil {
		err = closeErr
	}
	if err != nil {
		p.fail(err)
	}
	return err
}

func (p *pass) finish() error {
	var one [1]byte
	if n, err := io.ReadFull(p, one[:]); n != 0 || err != io.EOF {
		return volumearchive.ErrPackage
	}
	if p.dec != nil {
		// The zstd frame ended; the sealed stream must end with it.
		if n, err := io.ReadFull(p.plain, one[:]); n != 0 || err != io.EOF {
			return volumearchive.ErrPackage
		}
	}
	var digest [32]byte
	copy(digest[:], p.hash.h.Sum(nil))
	if p.hash.n != p.m.DataBytes || digest != p.m.DataDigest {
		return volumearchive.ErrPackage
	}
	return nil
}

// Verify reads the whole package once: authenticated decryption,
// decompression, the strict tar profile and digest, and the file digest.
// m must already pass Check.
func Verify(ctx context.Context, open OpenFile, dataKey []byte, m volumearchive.Manifest, o volumes.ArchiveOptions) error {
	var failed error
	err := volumes.VerifyArchiveFrom(ctx, opener(open, dataKey, m, &failed), m.Tar, o)
	if err != nil {
		return err
	}
	return failed
}

// Restore unpacks the package into the empty Volume root. On error the
// caller removes what was written, as for a backup restore.
func Restore(ctx context.Context, root *os.Root, open OpenFile, dataKey []byte, m volumearchive.Manifest, o volumes.ArchiveOptions) error {
	var failed error
	err := volumes.RestoreArchiveFrom(ctx, root, opener(open, dataKey, m, &failed), m.Tar, o)
	if err != nil {
		return err
	}
	return failed
}
