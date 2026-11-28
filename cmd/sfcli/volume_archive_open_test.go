// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/jay94ks/seafield/internal/clusterbackup"
	"github.com/jay94ks/seafield/internal/volumearchive"
	"github.com/jay94ks/seafield/internal/volumearchive/pack"
	"github.com/jay94ks/seafield/internal/workload/volumes"
)

// 'volume archive open' unseals a package with the administrator's key file
// alone, writes the receipt's tar, and keeps nothing when a check fails.
func TestVolumeArchiveOpenWithoutCluster(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	dir := t.TempDir()
	uid, gid := os.Geteuid(), os.Getegid()
	if uid == 0 {
		uid, gid = 10001, 10001
	}
	src := filepath.Join(dir, "src")
	if err := os.MkdirAll(filepath.Join(src, "conf"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "conf", "app.ini"), []byte("[app]\nname=shop\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() == 0 {
		_ = filepath.Walk(src, func(p string, _ os.FileInfo, _ error) error { return os.Lchown(p, uid, gid) })
	}
	_ = os.Chmod(src, 0o750)
	root, err := os.OpenRoot(src)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()

	keyFile := filepath.Join(dir, "admin.key")
	raw, _ := clusterbackup.NewKeyFile()
	_ = os.WriteFile(keyFile, raw, 0o600)
	key, _ := clusterbackup.KeyFromFile(raw)
	admin, err := key.Recipient(volumearchive.AdminKeyLabel)
	if err != nil {
		t.Fatal(err)
	}
	cluster, _ := clusterbackup.NewRecipient()
	o := volumes.ArchiveOptions{MaxBytes: 1 << 20, MaxEntries: 64, MaxDepth: 8, UID: uint32(uid), GID: uint32(gid), RootMode: 0o750}
	var data bytes.Buffer
	m, err := pack.Pack(context.Background(), root, &data, o, pack.Params{ID: "nightly", Scope: volumes.Scope{Cluster: [32]byte{7}, Tenant: "shop", App: "php-shop", ID: "sessions", Generation: 1},
		Compression: volumearchive.Zstd, Recipients: [][32]byte{cluster.Public(), admin.Public()}})
	if err != nil {
		t.Fatal(err)
	}
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	m.Node, m.At = [32]byte(pub), 1
	m = volumearchive.Sign(m, priv)
	pkg := filepath.Join(dir, "pkg")
	_ = os.Mkdir(pkg, 0o700)
	manifest, _ := json.Marshal(m)
	_ = os.WriteFile(filepath.Join(pkg, "manifest"), manifest, 0o600)
	_ = os.WriteFile(filepath.Join(pkg, "data.mdbk"), data.Bytes(), 0o600)

	runCode := func(want int, args ...string) {
		t.Helper()
		var out, diagnostic bytes.Buffer
		if code := run(args, &out, &diagnostic); code != want {
			t.Fatalf("sfcli %v: exit %d, want %d: %s", args, code, want, diagnostic.String())
		}
	}
	tarFile := filepath.Join(dir, "out.tar")
	runCode(0, "volume", "archive", "open", pkg, "--key-file", keyFile, "--out", tarFile)
	got, _ := os.ReadFile(tarFile)
	if sha256.Sum256(got) != m.Tar.Digest {
		t.Fatal("not the receipt's tar")
	}
	runCode(1, "volume", "archive", "open", pkg, "--key-file", keyFile, "--out", tarFile) // never overwrites

	other := filepath.Join(dir, "other.key")
	raw2, _ := clusterbackup.NewKeyFile()
	_ = os.WriteFile(other, raw2, 0o600)
	runCode(3, "volume", "archive", "open", pkg, "--key-file", other, "--out", filepath.Join(dir, "x.tar"))

	bad := bytes.Clone(data.Bytes())
	bad[len(bad)-1] ^= 1
	_ = os.WriteFile(filepath.Join(pkg, "data.mdbk"), bad, 0o600)
	runCode(3, "volume", "archive", "open", pkg, "--key-file", keyFile, "--out", filepath.Join(dir, "y.tar"))
	if _, err := os.Stat(filepath.Join(dir, "y.tar")); !os.IsNotExist(err) {
		t.Fatal("a failed open left its output", err)
	}
	runCode(2, "volume", "archive", "open", pkg)
}
