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
	"sync"
	"testing"
	"time"

	contract "github.com/jay94ks/seafield/lifecycle/v1"
)

func fileArchive(t *testing.T, headers []*tar.Header, data [][]byte) []byte {
	t.Helper()
	var out bytes.Buffer
	w := tar.NewWriter(&out)
	for i, h := range headers {
		if err := w.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if len(data[i]) > 0 {
			if _, err := w.Write(data[i]); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func TestFileContentArchiveIsBoundedSingleRegularAndNeverExtracted(t *testing.T) {
	payload := []byte("ready\n")
	h := sha256.Sum256(payload)
	query := contract.FileProbe{Service: "web", Path: "/ready", Kind: "regular", ContentDigest: hex.EncodeToString(h[:]), MaxBytes: len(payload)}
	regular := &tar.Header{Name: "ready", Typeflag: tar.TypeReg, Size: int64(len(payload)), Mode: 0444}
	archive := fileArchive(t, []*tar.Header{regular}, [][]byte{payload})
	for _, scenario := range []string{"match", "mismatch", "extra", "link", "hardlink", "mode", "traversal", "short", "appended", "metadata-limit", "size", "budget", "empty"} {
		t.Run(scenario, func(t *testing.T) {
			q, input, size := query, archive, int64(len(payload))
			switch scenario {
			case "mismatch":
				d := sha256.Sum256([]byte("different"))
				q.ContentDigest = hex.EncodeToString(d[:])
			case "extra":
				input = fileArchive(t, []*tar.Header{regular, {Name: "other", Typeflag: tar.TypeReg}}, [][]byte{payload, nil})
			case "link":
				input = fileArchive(t, []*tar.Header{{Name: "ready", Typeflag: tar.TypeSymlink, Linkname: "/host/secret"}}, [][]byte{nil})
			case "hardlink":
				input = fileArchive(t, []*tar.Header{{Name: "ready", Typeflag: tar.TypeLink, Linkname: "other"}}, [][]byte{nil})
			case "mode":
				copy := *regular
				copy.Mode = 0600
				input = fileArchive(t, []*tar.Header{&copy}, [][]byte{payload})
			case "traversal":
				copy := *regular
				copy.Name = "../ready"
				input = fileArchive(t, []*tar.Header{&copy}, [][]byte{payload})
			case "short":
				input = archive[:512+len(payload)-1]
			case "appended":
				input = append(bytes.Clone(archive), []byte("hidden archive")...)
			case "metadata-limit":
				copy := *regular
				copy.Format = tar.FormatPAX
				copy.PAXRecords = map[string]string{"comment": string(bytes.Repeat([]byte{'x'}, 70<<10))}
				input = fileArchive(t, []*tar.Header{&copy}, [][]byte{payload})
			case "size":
				size++
			case "budget":
				q.MaxBytes--
			case "empty":
				d := sha256.Sum256(nil)
				q.ContentDigest = hex.EncodeToString(d[:])
				size = 0
				input = fileArchive(t, []*tar.Header{{Name: "ready", Typeflag: tar.TypeReg, Mode: 0444}}, [][]byte{nil})
			}
			match, err := matchProbeFileArchive(context.Background(), io.NopCloser(bytes.NewReader(input)), q, size, 0444)
			if scenario == "match" || scenario == "empty" {
				if err != nil || !match {
					t.Fatal(match, err)
				}
			} else if scenario == "mismatch" {
				if err != nil || match {
					t.Fatal("digest mismatch was not a completed negative observation", match, err)
				}
			} else if err == nil || match {
				t.Fatal("ambiguous archive accepted", match, err)
			}
		})
	}
}

type blockedFileArchive struct {
	entered, closed chan struct{}
	once, readOnce  sync.Once
}

func (b *blockedFileArchive) Read([]byte) (int, error) {
	b.readOnce.Do(func() { close(b.entered) })
	<-b.closed
	return 0, io.ErrClosedPipe
}
func (b *blockedFileArchive) Close() error { b.once.Do(func() { close(b.closed) }); return nil }

func TestFileContentCancellationClosesAndJoinsOriginalBody(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	body := &blockedFileArchive{entered: make(chan struct{}), closed: make(chan struct{})}
	defer body.Close()
	d := sha256.Sum256([]byte("ready"))
	q := contract.FileProbe{Path: "/ready", Kind: "regular", ContentDigest: hex.EncodeToString(d[:]), MaxBytes: 32}
	done := make(chan error, 1)
	go func() { _, err := matchProbeFileArchive(ctx, body, q, 5, 0444); done <- err }()
	select {
	case <-body.entered:
	case <-time.After(time.Second):
		t.Fatal("read did not start")
	}
	cancel()
	select {
	case err := <-done:
		if err == nil || !errors.Is(err, io.ErrClosedPipe) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("original body remained blocked")
	}
}
