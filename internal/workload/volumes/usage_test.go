// SPDX-License-Identifier: Apache-2.0

package volumes

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

func usageFiles(t *testing.T, root string) uint64 {
	t.Helper()
	if err := os.Mkdir(filepath.Join(root, "database"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "database", "row"), []byte("original row"), 0600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Create(filepath.Join(root, "sparse"))
	if err != nil {
		t.Fatal(err)
	}
	err = f.Truncate(1 << 20)
	closeErr := f.Close()
	if err != nil || closeErr != nil {
		t.Fatal(err, closeErr)
	}
	if err := os.Link(filepath.Join(root, "sparse"), filepath.Join(root, "same-inode")); err != nil {
		t.Fatal(err)
	}
	return 1<<20 + uint64(len("original row"))
}

func TestVolumeUsageBoundedFilesystemAccounting(t *testing.T) {
	root := t.TempDir()
	logical := usageFiles(t, root)
	v, err := scanUsage(context.Background(), root, UsageLimits{Entries: 8, Depth: 2})
	if err != nil || v.QuotaMode != "observe" || v.Snapshot || v.Entries != 5 || v.Files != 2 || v.Directories != 2 || v.LogicalBytes != logical || v.AllocatedBytes >= logical || v.FilesystemBytes == 0 || v.FilesystemAvailableBytes > v.FilesystemBytes {
		t.Fatal("sparse/hardlink accounting", v, err)
	}
	for _, limits := range []UsageLimits{{}, {Entries: 4, Depth: 2}, {Entries: 8, Depth: 129}, {Entries: 1_000_001, Depth: 2}} {
		got, err := scanUsage(context.Background(), root, limits)
		if !errors.Is(err, ErrUsageLimit) || got != (Usage{}) {
			t.Fatal("budget failure published partial observation", limits, got, err)
		}
	}
	if err := os.Mkdir(filepath.Join(root, "database", "nested"), 0700); err != nil {
		t.Fatal(err)
	}
	if _, err = scanUsage(context.Background(), root, UsageLimits{Entries: 16, Depth: 1}); !errors.Is(err, ErrUsageLimit) {
		t.Fatal("depth limit", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if v, err = scanUsage(ctx, root, UsageLimits{Entries: 16, Depth: 3}); !errors.Is(err, context.Canceled) || v != (Usage{}) {
		t.Fatal("cancel became a zero-size success", v, err)
	}
	if _, err = usageAdd(math.MaxUint64, 1); !errors.Is(err, ErrVolumeUsage) {
		t.Fatal("usage overflow", err)
	}
}

func TestVolumeUsageRejectsLinksAndUnsupportedFiles(t *testing.T) {
	root, outside := t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "private"), []byte("not part of volume"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, directory := range []bool{false, true} {
		target := filepath.Join(outside, "private")
		if directory {
			target = outside
		}
		link := filepath.Join(root, "escape")
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		got, err := scanUsage(context.Background(), root, UsageLimits{Entries: 8, Depth: 2})
		if !errors.Is(err, ErrVolumeUsage) || got != (Usage{}) || strings.Contains(err.Error(), outside) {
			t.Fatal("symlink observed external data/path", got, err)
		}
		if err := os.Remove(link); err != nil {
			t.Fatal(err)
		}
	}
	if err := syscall.Mkfifo(filepath.Join(root, "pipe"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := scanUsage(context.Background(), root, UsageLimits{Entries: 8, Depth: 2}); !errors.Is(err, ErrVolumeUsage) {
		t.Fatal("FIFO treated as a regular file", err)
	}
}

func TestNativeVolumeUsageIdentityAndDeclarationBoundary(t *testing.T) {
	s := nativeTestSpec(t)
	f := nativeSDK(t, s)
	m, err := OpenNative(filepath.Join(t.TempDir(), "native.db"), f.client)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	key, err := m.Desired(s, 1, 1, 4)
	if err != nil || m.Step(context.Background(), key) != nil {
		t.Fatal("native fixture preparation", err)
	}
	logical := usageFiles(t, f.data)
	got, err := m.Usage(context.Background(), key, UsageLimits{Entries: 8, Depth: 2})
	if err != nil || got.Scope != s.Scope || got.Owner.Key != s.NodeKey || got.Generation != 1 || got.LogicalBytes != logical {
		t.Fatal("original native observation", got, err)
	}
	raw, _ := json.Marshal(got)
	if strings.Contains(string(raw), f.data) || strings.Contains(string(raw), "database") || strings.Contains(string(raw), "original row") {
		t.Fatal("usage leaked private filenames/data/path")
	}
	f.mu.Lock()
	original := f.value.Labels["org.mydc.spec"]
	f.value.Labels["org.mydc.spec"] = "foreign"
	f.mu.Unlock()
	if _, err := m.Usage(context.Background(), key, UsageLimits{Entries: 8, Depth: 2}); !errors.Is(err, ErrNativeVolume) {
		t.Fatal("foreign native identity observed", err)
	}
	f.mu.Lock()
	f.value.Labels["org.mydc.spec"] = original
	f.mu.Unlock()
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	f.mu.Lock()
	f.volumeInspectHook = func() { once.Do(func() { close(entered); <-release }) }
	f.mu.Unlock()
	usageDone := make(chan error, 1)
	go func() {
		_, err := m.Usage(context.Background(), key, UsageLimits{Entries: 8, Depth: 2})
		usageDone <- err
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		close(release)
		t.Fatal("usage did not reach actual SDK boundary")
	}
	deleteDone := make(chan error, 1)
	go func() { deleteDone <- m.DeleteDesired(key, 2, 1) }()
	select {
	case err := <-deleteDone:
		close(release)
		t.Fatal("declaration changed during scan", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	if err := <-usageDone; err != nil {
		t.Fatal(err)
	}
	if err := <-deleteDone; err != nil {
		t.Fatal(err)
	}
	if v, err := m.Usage(context.Background(), key, UsageLimits{Entries: 8, Depth: 2}); !errors.Is(err, ErrNativeVolume) || v != (Usage{}) {
		t.Fatal("retiring volume reported as available", v, err)
	}
	if f.createCount() != 1 || f.deleteCount() != 0 {
		t.Fatal("observation made a native write")
	}
}
