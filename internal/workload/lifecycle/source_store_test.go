// SPDX-License-Identifier: Apache-2.0

package lifecycle

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"path/filepath"
	"testing"

	"github.com/jay94ks/mydcd/internal/storage"
)

func sourceDescriptor(tenant string, source []byte) SourceDescriptor {
	return SourceDescriptor{Tenant: tenant, SDK: 1, Digest: sha256.Sum256(source), Length: uint64(len(source))}
}

func TestCheckerSourceActualDBRecoveryPreservesOriginalFactAndIdentity(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "observations.db")
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{91}, 32))
	cluster := [32]byte{92}
	db, err := storage.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	m, err := OpenSources(db, cluster, key)
	if err != nil {
		t.Fatal(err)
	}
	data := []byte("package checker\n")
	d := sourceDescriptor("tenant", data)
	original, err := m.Stage(ctx, d, data, sourcePolicy())
	if err != nil || original.Verify() != nil {
		t.Fatal("actual durable staging", err)
	}
	if err = m.Close(); err != nil {
		t.Fatal(err)
	}
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = storage.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	m, err = OpenSources(db, cluster, key)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	recovered, err := m.Recover(ctx, d)
	if err != nil || !bytes.Equal(SourceFactBytes(recovered), SourceFactBytes(original)) || !bytes.Equal(recovered.Signature, original.Signature) {
		t.Fatal("lost-response/same DB recovery changed original fact", err)
	}
	read, err := m.Read(ctx, d)
	if err != nil || !bytes.Equal(read, data) {
		t.Fatal("actual source bytes", err)
	}
	read[0] ^= 1
	read, err = m.Read(ctx, d)
	if err != nil || !bytes.Equal(read, data) {
		t.Fatal("caller mutated stored source", err)
	}
	again, err := m.Stage(ctx, d, data, sourcePolicy())
	if err != nil || !bytes.Equal(again.Signature, original.Signature) || len(m.entries) != 1 {
		t.Fatal("exact content replay allocated a replacement", err)
	}
	foreign := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{93}, 32))
	brokenKey := bytes.Clone(key)
	brokenKey[len(brokenKey)-1] ^= 1
	if adopted, err := OpenSources(db, cluster, brokenKey); err == nil {
		adopted.Close()
		t.Fatal("inconsistent signing key admitted")
	}
	if adopted, err := OpenSources(db, cluster, foreign); err == nil {
		adopted.Close()
		t.Fatal("foreign node adopted source DB")
	}
	if adopted, err := OpenSources(db, [32]byte{94}, key); err == nil {
		adopted.Close()
		t.Fatal("foreign cluster adopted source DB")
	}
}

func TestCheckerSourceCacheBudgetIsolationAndInvalidInputNeverPublishes(t *testing.T) {
	db, err := storage.Open(filepath.Join(t.TempDir(), "observations.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{95}, 32))
	m, err := OpenSources(db, [32]byte{96}, key)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	p := sourcePolicy()
	p.Resolver.SourceCacheBytes = MaxScriptBytes
	first := bytes.Repeat([]byte("a"), 200<<10)
	d := sourceDescriptor("tenant", first)
	if _, err := m.Stage(context.Background(), d, first, p); err != nil {
		t.Fatal(err)
	}
	second := bytes.Repeat([]byte("b"), 100<<10)
	other := sourceDescriptor("tenant", second)
	if _, err := m.Stage(context.Background(), other, second, p); err == nil {
		t.Fatal("tenant cache quota ignored existing bytes/metadata")
	}
	if _, err := db.Get(sourceMetaPrefix + sourceObjectKey(other)); !errors.Is(err, storage.ErrMissing) {
		t.Fatal("rejected source partly published", err)
	}
	otherTenant := sourceDescriptor("other", first)
	p.Tenant = "other"
	if _, err := m.Stage(context.Background(), otherTenant, first, p); err != nil {
		t.Fatal("separate tenant cache namespace", err)
	}
	if len(m.entries) != 2 || m.bytes["tenant"] == 0 || m.bytes["other"] == 0 {
		t.Fatal("cross-tenant content alias")
	}
	for _, invalid := range [][]byte{{0xff}, {0}, []byte("different digest")} {
		q := sourceDescriptor("other", invalid)
		if bytes.Equal(invalid, []byte("different digest")) {
			q.Digest = d.Digest
		}
		if _, err := m.Stage(context.Background(), q, invalid, p); err == nil {
			t.Fatal("invalid UTF8/NUL/digest source accepted")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	q := sourceDescriptor("other", []byte("cancelled"))
	if _, err := m.Stage(ctx, q, []byte("cancelled"), p); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled stage published", err)
	}
	if _, err := m.Recover(context.Background(), q); !errors.Is(err, storage.ErrMissing) {
		t.Fatal("recover recreated missing source", err)
	}
}

func TestCheckerSourceMetadataCannotMaskMissingOrCorruptActualBytes(t *testing.T) {
	for _, test := range []struct {
		name   string
		broken []byte
	}{{"corrupt", []byte("corrupt")}, {"missing", nil}} {
		t.Run(test.name, func(t *testing.T) {
			db, err := storage.Open(filepath.Join(t.TempDir(), "observations.db"))
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{98}, 32))
			defer clear(private)
			m, err := OpenSources(db, [32]byte{97}, private)
			if err != nil {
				t.Fatal(err)
			}
			defer m.Close()
			data := []byte("package checker\n")
			d := sourceDescriptor("tenant", data)
			if _, err := m.Stage(context.Background(), d, data, sourcePolicy()); err != nil {
				t.Fatal(err)
			}
			key := sourcePrefix + "data/" + sourceObjectKey(d)
			if err := db.Write(map[string][]byte{key: test.broken}); err != nil {
				t.Fatal(err)
			}
			if _, err := m.Read(context.Background(), d); !errors.Is(err, ErrSourceStore) {
				t.Fatal("metadata fact counted as source availability", err)
			}
			if _, err := m.Recover(context.Background(), d); !errors.Is(err, ErrSourceStore) || !errors.Is(err, ErrSourceUncertain) {
				t.Fatal("recover returned fact without original bytes", err)
			}
			if _, err := m.Read(context.Background(), d); !errors.Is(err, ErrSourceUncertain) {
				t.Fatal("known uncertain owner permitted another read", err)
			}
			if _, err := m.Stage(context.Background(), d, data, sourcePolicy()); err == nil {
				t.Fatal("staging silently repaired corrupted original")
			}
			if err := db.Write(map[string][]byte{sourcePrefix + "identity": nil}); err != nil {
				t.Fatal(err)
			}
			if adopted, err := OpenSources(db, [32]byte{97}, private); err == nil {
				adopted.Close()
				t.Fatal("unbound namespace automatically adopted")
			}
		})
	}
}
