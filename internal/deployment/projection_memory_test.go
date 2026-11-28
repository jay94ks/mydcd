// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A reboot empties the values tmpfs (directory and seen marker together):
// the same generation is fetched and written again, through the gate. A
// directory lost while its seen marker stays (same boot) remains closed.
func TestProjectionStoreValuesInMemoryRestoreAfterReboot(t *testing.T) {
	f, b, stage, gate := projectionFixture(t)
	defer stage.Destroy()
	ctx := context.Background()
	base := t.TempDir()
	root, values := filepath.Join(base, "inputs"), filepath.Join(base, "inputs-memory")
	refuse := false
	gated := func(ctx context.Context, b Binding) error {
		if refuse {
			return ErrInputs
		}
		return gate(ctx, b)
	}
	m, err := OpenProjectionsWithValues(root, values, f.cluster, b.d.Needs.Use.NodeKey, 4096, gated)
	if err != nil {
		t.Fatal(err)
	}
	ref, err := m.Publish(ctx, b, stage, 1, 2)
	if err != nil {
		t.Fatal(err)
	}
	consumer, key := projectionConsumer(t, f, b)
	lease, err := m.AcquireInputs(ctx, ref, consumer, key, ref.Generation)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(lease.Files[0].Source, values+string(os.PathSeparator)) {
		t.Fatal("value file outside the memory root", lease.Files[0].Source)
	}
	if err = m.ReturnInputs(ref, consumer, key, ref.Generation); err != nil {
		t.Fatal(err)
	}
	names, _ := os.ReadDir(root)
	for _, e := range names {
		if e.IsDir() && e.Name() != "journal" {
			if _, err := os.Stat(filepath.Join(root, e.Name(), "file-0000")); err == nil {
				t.Fatal("value file written to the journal root")
			}
		}
	}
	m.Close()

	// Reboot: the tmpfs comes back empty.
	if err = os.RemoveAll(values); err != nil {
		t.Fatal(err)
	}
	m, err = OpenProjectionsWithValues(root, values, f.cluster, b.d.Needs.Use.NodeKey, 4096, gated)
	if err != nil {
		t.Fatal(err)
	}
	if ready, err := m.Ready(ctx, ref); err != nil || ready {
		t.Fatal("lost values reported ready", ready, err)
	}
	refuse = true
	if _, err = m.Publish(ctx, b, stage, 1, 2); err == nil {
		t.Fatal("restore passed a refusing gate")
	}
	refuse = false
	if _, err = m.Publish(ctx, b, stage, 1, 2); err != nil {
		t.Fatal("restore after reboot", err)
	}
	if ready, err := m.Ready(ctx, ref); err != nil || !ready {
		t.Fatal("restored values not ready", ready, err)
	}
	lease, err = m.AcquireInputs(ctx, ref, consumer, key, ref.Generation)
	if err != nil {
		t.Fatal(err)
	}
	if err = m.ReturnInputs(ref, consumer, key, ref.Generation); err != nil {
		t.Fatal(err)
	}

	// Same boot: the marker stays, so a lost directory is never restored.
	if err = os.RemoveAll(filepath.Dir(lease.Files[0].Source)); err != nil {
		t.Fatal(err)
	}
	if _, err = m.Publish(ctx, b, stage, 1, 2); err == nil {
		t.Fatal("loss within a boot restored")
	}
	if ready, err := m.Ready(ctx, ref); err == nil && ready {
		t.Fatal("loss within a boot reported ready")
	}
	m.Close()
}

func TestProjectionStoreDropsDiskValuesOnOpen(t *testing.T) {
	f, b, stage, gate := projectionFixture(t)
	defer stage.Destroy()
	base := t.TempDir()
	root, values := filepath.Join(base, "inputs"), filepath.Join(base, "inputs-memory")
	m, err := OpenProjectionsWithValues(root, values, f.cluster, b.d.Needs.Use.NodeKey, 4096, gate)
	if err != nil {
		t.Fatal(err)
	}
	m.Close()
	old := filepath.Join(root, strings.Repeat("ab", 32))
	temp := filepath.Join(root, "prepare-x")
	for _, dir := range []string{old, temp} {
		if err = os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(filepath.Join(dir, "file-0000"), []byte("secret"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	m, err = OpenProjectionsWithValues(root, values, f.cluster, b.d.Needs.Use.NodeKey, 4096, gate)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	for _, dir := range []string{old, temp} {
		if _, err = os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("disk value directory kept", dir, err)
		}
	}
}

func TestProjectionStoreDrainRemovesSeenMarker(t *testing.T) {
	f, b, stage, gate := projectionFixture(t)
	defer stage.Destroy()
	ctx := context.Background()
	base := t.TempDir()
	values := filepath.Join(base, "inputs-memory")
	m, err := OpenProjectionsWithValues(filepath.Join(base, "inputs"), values, f.cluster, b.d.Needs.Use.NodeKey, 4096, gate)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	ref, err := m.Publish(ctx, b, stage, 1, 2)
	if err != nil {
		t.Fatal(err)
	}
	if err = m.Drain(ctx, ref, 2); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(values)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "seen-") || e.IsDir() {
			t.Fatal("drained generation left", e.Name())
		}
	}
}
