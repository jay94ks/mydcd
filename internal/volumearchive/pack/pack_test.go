// SPDX-License-Identifier: Apache-2.0

package pack

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jay94ks/seafield/internal/clusterbackup"
	"github.com/jay94ks/seafield/internal/volumearchive"
	"github.com/jay94ks/seafield/internal/workload/volumes"
)

func fixture(t *testing.T) (*os.Root, volumes.ArchiveOptions) {
	t.Helper()
	uid, gid := os.Geteuid(), os.Getegid()
	if uid == 0 {
		uid, gid = 10001, 10001
	}
	name := t.TempDir()
	files := map[string]string{"db/ibdata1": strings.Repeat("page", 40000), "conf/app.ini": "[app]\nname=shop\n", "empty": ""}
	for _, d := range []string{"db", "conf"} {
		if err := os.Mkdir(filepath.Join(name, d), 0750); err != nil {
			t.Fatal(err)
		}
	}
	for f, body := range files {
		if err := os.WriteFile(filepath.Join(name, f), []byte(body), 0640); err != nil {
			t.Fatal(err)
		}
	}
	if os.Geteuid() == 0 {
		_ = filepath.Walk(name, func(p string, _ os.FileInfo, _ error) error { return os.Lchown(p, uid, gid) })
	}
	if err := os.Chmod(name, 0750); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(name)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })
	return root, volumes.ArchiveOptions{MaxBytes: 8 << 20, MaxEntries: 64, MaxDepth: 8, UID: uint32(uid), GID: uint32(gid), RootMode: 0750}
}

func emptyRoot(t *testing.T, o volumes.ArchiveOptions) *os.Root {
	t.Helper()
	name := t.TempDir()
	if err := os.Chmod(name, 0700); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(name)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })
	return root
}

type keys struct {
	cluster, admin clusterbackup.Recipient
	node           ed25519.PrivateKey
	nodeID         [32]byte
}

func newKeys(t *testing.T) keys {
	t.Helper()
	master := make([]byte, 32)
	_, _ = rand.Read(master)
	cluster, err := clusterbackup.RecipientFromSeed(master, "volume-archive")
	if err != nil {
		t.Fatal(err)
	}
	admin, err := clusterbackup.NewRecipient()
	if err != nil {
		t.Fatal(err)
	}
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	var id [32]byte
	copy(id[:], pub)
	return keys{cluster: cluster, admin: admin, node: priv, nodeID: id}
}

func pack(t *testing.T, k keys, c volumearchive.Compression) ([]byte, volumearchive.Manifest, volumes.ArchiveOptions) {
	t.Helper()
	root, o := fixture(t)
	scope := volumes.Scope{Cluster: [32]byte{7}, Tenant: "tenant-a", App: "shop", ID: "data", Generation: 1}
	var out bytes.Buffer
	m, err := Pack(context.Background(), root, &out, o, Params{ID: "a-20261128-0001", Scope: scope, Compression: c, Recipients: [][32]byte{k.cluster.Public(), k.admin.Public()}})
	if err != nil {
		t.Fatal(err)
	}
	m.Node, m.At = k.nodeID, 1
	m = volumearchive.Sign(m, k.node)
	if err := m.Check(o); err != nil {
		t.Fatal("signed manifest rejected", err)
	}
	return out.Bytes(), m, o
}

func fileOpener(data []byte) OpenFile {
	return func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(data)), nil }
}

func dataKey(t *testing.T, r clusterbackup.Recipient, data []byte, m volumearchive.Manifest) []byte {
	t.Helper()
	sealed, err := clusterbackup.SealedKeys(bytes.NewReader(data))
	if err != nil || len(sealed) != 2 {
		t.Fatal("sealed keys", len(sealed), err)
	}
	key, err := r.UnsealDataKey(clusterbackup.SealedTo{Cluster: m.Scope.Cluster, Context: volumearchive.Context(m.ID)}, sealed)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func TestPackVerifyRestoreRoundTrip(t *testing.T) {
	for _, c := range []volumearchive.Compression{volumearchive.Zstd, volumearchive.None} {
		t.Run(string(c), func(t *testing.T) {
			k := newKeys(t)
			data, m, o := pack(t, k, c)
			if bytes.Contains(data, []byte("[app]")) || bytes.Contains(data, []byte("pagepage")) {
				t.Fatal("plaintext in the package")
			}
			if c == volumearchive.Zstd && m.DataBytes >= m.Tar.Bytes/4 {
				t.Fatal("zstd did not shrink a repetitive Volume", m.DataBytes, m.Tar.Bytes)
			}
			// Either recipient opens it: the cluster key while the cluster
			// lives, the administrator key after losing it.
			for _, r := range []clusterbackup.Recipient{k.cluster, k.admin} {
				key := dataKey(t, r, data, m)
				if err := Verify(context.Background(), fileOpener(data), key, m, o); err != nil {
					t.Fatal("verify", err)
				}
				target := emptyRoot(t, o)
				if err := Restore(context.Background(), target, fileOpener(data), key, m, o); err != nil {
					t.Fatal("restore", err)
				}
				got, err := target.ReadFile("conf/app.ini")
				if err != nil || string(got) != "[app]\nname=shop\n" {
					t.Fatal("restored file", string(got), err)
				}
				big, err := target.ReadFile("db/ibdata1")
				if err != nil || len(big) != 160000 {
					t.Fatal("restored large file", len(big), err)
				}
			}
		})
	}
}

func TestDamagedOrMismatchedPackageIsRefused(t *testing.T) {
	k := newKeys(t)
	data, m, o := pack(t, k, volumearchive.Zstd)
	key := dataKey(t, k.cluster, data, m)
	cases := map[string]func() ([]byte, volumearchive.Manifest, []byte){
		"flipped byte": func() ([]byte, volumearchive.Manifest, []byte) {
			d := bytes.Clone(data)
			d[len(d)/2] ^= 1
			return d, m, key
		},
		"truncated": func() ([]byte, volumearchive.Manifest, []byte) { return data[:len(data)-20], m, key },
		"trailing":  func() ([]byte, volumearchive.Manifest, []byte) { return append(bytes.Clone(data), 0), m, key },
		"wrong key": func() ([]byte, volumearchive.Manifest, []byte) {
			other := make([]byte, 32)
			_, _ = rand.Read(other)
			return data, m, other
		},
		"other digest": func() ([]byte, volumearchive.Manifest, []byte) {
			x := m
			x.DataDigest[0] ^= 1
			return data, x, key
		},
		"other tar receipt": func() ([]byte, volumearchive.Manifest, []byte) {
			x := m
			x.Tar.Digest[0] ^= 1
			return data, x, key
		},
		"compression lie": func() ([]byte, volumearchive.Manifest, []byte) {
			x := m
			x.Compression = volumearchive.None
			return data, x, key
		},
	}
	for name, mk := range cases {
		d, x, kk := mk()
		if err := Verify(context.Background(), fileOpener(d), kk, x, o); err == nil {
			t.Fatal("verify accepted", name)
		}
		if err := Restore(context.Background(), emptyRoot(t, o), fileOpener(d), kk, x, o); err == nil {
			t.Fatal("restore accepted", name)
		}
	}
}

func TestSealedKeyIsBoundToArchiveAndCluster(t *testing.T) {
	k := newKeys(t)
	data, m, _ := pack(t, k, volumearchive.None)
	sealed, err := clusterbackup.SealedKeys(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	for _, to := range []clusterbackup.SealedTo{{Cluster: m.Scope.Cluster, Context: volumearchive.Context("a-other")}, {Cluster: [32]byte{8}, Context: volumearchive.Context(m.ID)}} {
		if _, err := k.cluster.UnsealDataKey(to, sealed); err == nil {
			t.Fatal("data key opened for another archive or cluster", to.Context)
		}
	}
	// A plain key-file reader never accepts a sealed file.
	kf, _ := clusterbackup.NewKeyFile()
	key, _ := clusterbackup.KeyFromFile(kf)
	if _, _, err := clusterbackup.Open(bytes.NewReader(data), key); err == nil {
		t.Fatal("kdf 3 file opened as a key-file backup")
	}
}

func TestManifestCheck(t *testing.T) {
	k := newKeys(t)
	_, m, o := pack(t, k, volumearchive.Zstd)
	x := m
	x.Scope.App = "other"
	if x.Check(o) == nil {
		t.Fatal("manifest edited after signing accepted")
	}
	x = m
	x.Compression = "gzip"
	x = volumearchive.Sign(x, k.node)
	if x.Check(o) == nil {
		t.Fatal("unknown compression accepted")
	}
	if _, err := Pack(context.Background(), emptyRoot(t, o), io.Discard, o, Params{ID: "Bad/ID", Compression: volumearchive.Zstd, Recipients: [][32]byte{{1}}}); !errors.Is(err, volumearchive.ErrPackage) {
		t.Fatal("bad archive ID accepted", err)
	}
}

func TestPackKeyOpensWhatItWrote(t *testing.T) {
	k := newKeys(t)
	root, o := fixture(t)
	var out bytes.Buffer
	m, key, err := PackKey(context.Background(), root, &out, o, Params{ID: "a-key", Scope: volumes.Scope{Cluster: [32]byte{7}, Tenant: "t", App: "a", ID: "d", Generation: 1}, Compression: volumearchive.Zstd, Recipients: [][32]byte{k.cluster.Public(), k.admin.Public()}})
	if err != nil || len(key) != 32 {
		t.Fatal(err, len(key))
	}
	if err := Verify(context.Background(), fileOpener(out.Bytes()), key, m, o); err != nil {
		t.Fatal("writer's own key", err)
	}
	if !bytes.Equal(key, dataKey(t, k.admin, out.Bytes(), m)) {
		t.Fatal("returned key is not the sealed one")
	}
}

// Extract hands out the exact tar stream of the receipt with the
// administrator's key alone, and refuses a package changed by one byte.
func TestExtractWritesTheReceiptTar(t *testing.T) {
	k := newKeys(t)
	root, o := fixture(t)
	for _, c := range []volumearchive.Compression{volumearchive.Zstd, volumearchive.None} {
		var out bytes.Buffer
		m, err := Pack(context.Background(), root, &out, o, Params{ID: "a-ex", Scope: volumes.Scope{Cluster: [32]byte{7}, Tenant: "t", App: "a", ID: "d", Generation: 1}, Compression: c, Recipients: [][32]byte{k.cluster.Public(), k.admin.Public()}})
		if err != nil {
			t.Fatal(err)
		}
		m.DataBytes, m.DataDigest = uint64(out.Len()), sha256.Sum256(out.Bytes())
		var tarOut bytes.Buffer
		if err := Extract(fileOpener(out.Bytes()), dataKey(t, k.admin, out.Bytes(), m), m, &tarOut); err != nil {
			t.Fatal(c, err)
		}
		if sha256.Sum256(tarOut.Bytes()) != m.Tar.Digest || uint64(tarOut.Len()) != m.Tar.Bytes {
			t.Fatal(c, "not the receipt's tar")
		}
		if _, err := tar.NewReader(bytes.NewReader(tarOut.Bytes())).Next(); err != nil {
			t.Fatal(c, "not a tar", err)
		}
		bad := bytes.Clone(out.Bytes())
		bad[len(bad)-1] ^= 1
		if err := Extract(fileOpener(bad), dataKey(t, k.admin, out.Bytes(), m), m, io.Discard); err == nil {
			t.Fatal(c, "a changed package was extracted")
		}
	}
}
