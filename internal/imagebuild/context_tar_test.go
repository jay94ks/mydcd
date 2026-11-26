// SPDX-License-Identifier: Apache-2.0

package imagebuild

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"io"
	"io/fs"
	"testing"
)

func tarContextFixture(t *testing.T) ([]byte, UploadScope, SealReceipt) {
	t.Helper()
	raw := makeZIP(t, zipInput{name: "Dockerfile", body: "FROM scratch\nCOPY data/file /file\n"}, zipInput{name: "data/file", body: "value"}, zipInput{name: "bin/tool", body: "run", mode: 0755})
	scope, key := testScope(int64(len(raw)), sha256.Sum256(raw))
	tree, err := InspectZIP(context.Background(), bytes.NewReader(raw), int64(len(raw)), scope.Dockerfile, scope.ExpandedLimit)
	if err != nil {
		t.Fatal(err)
	}
	seal := SealReceipt{Schema: 1, Scope: scope.Hash(), ZIP: scope.Digest, Tree: tree.Digest(), Entries: uint32(len(tree.Entries)), ExpandedBytes: tree.Bytes}
	seal.Signature = ed25519.Sign(key, SealReceiptBytes(seal))
	return raw, scope, seal
}
func TestContextTARUsesSealedBytesRootOwnedReadonlyPathsAndImplicitParents(t *testing.T) {
	raw, scope, seal := tarContextFixture(t)
	var output, again bytes.Buffer
	tree, err := WriteContextTAR(context.Background(), bytes.NewReader(raw), scope, seal, &output)
	if err != nil || tree.Digest() != seal.Tree {
		t.Fatal(err)
	}
	if _, err := WriteContextTAR(context.Background(), bytes.NewReader(raw), scope, seal, &again); err != nil || !bytes.Equal(output.Bytes(), again.Bytes()) {
		t.Fatal("nondeterministic archive", err)
	}
	tr := tar.NewReader(bytes.NewReader(output.Bytes()))
	seen := map[string]bool{}
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if h.Uid != 0 || h.Gid != 0 || h.Linkname != "" || h.Mode&0222 != 0 || h.Typeflag != tar.TypeReg && h.Typeflag != tar.TypeDir || h.Size > scope.ExpandedLimit {
			t.Fatal("broadened archive entry", h)
		}
		if seen[h.Name] {
			t.Fatal("duplicate output", h.Name)
		}
		seen[h.Name] = true
		if h.Name == "context/bin/tool" && fs.FileMode(h.Mode).Perm() != 0555 {
			t.Fatal("executable mode lost")
		}
		if _, err := io.Copy(io.Discard, tr); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"context/", "context/data/", "context/data/file", "context/bin/", "context/bin/tool", "context/Dockerfile"} {
		if !seen[name] {
			t.Fatal("missing archive entry", name)
		}
	}
	raw[0] ^= 1
	var bad bytes.Buffer
	if _, err := WriteContextTAR(context.Background(), bytes.NewReader(raw), scope, seal, &bad); err == nil || bad.Len() != 0 {
		t.Fatal("corrupt ZIP emitted bytes")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := WriteContextTAR(ctx, bytes.NewReader(raw), scope, seal, io.Discard); err == nil {
		t.Fatal("cancel ignored")
	}
}
