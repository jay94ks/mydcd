// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/workload/volumes"
)

func TestArchiveBoundWriterRefusesPastBound(t *testing.T) {
	var out bytes.Buffer
	w := &boundWriter{w: &out, left: 8}
	if n, err := w.Write([]byte("12345")); n != 5 || err != nil {
		t.Fatal(n, err)
	}
	_, err := w.Write([]byte("6789"))
	if !errors.Is(err, errArchiveRefused) || failureCode(err) != "too-large" || out.Len() != 5 {
		t.Fatal("past bound", err, out.Len())
	}
}

func TestArchiveManifestWrittenWhole(t *testing.T) {
	dir, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	if err := writeSynced(dir, archiveManifestName, []byte("{}")); err != nil {
		t.Fatal(err)
	}
	raw, err := dir.ReadFile(archiveManifestName)
	if err != nil || string(raw) != "{}" {
		t.Fatal(string(raw), err)
	}
	if _, err := dir.Stat(archiveManifestName + ".tmp"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("temporary manifest left", err)
	}
}

func TestArchivePathAndPinNameAreStable(t *testing.T) {
	b := control.VolumeArchiveBinding{Scope: volumes.Scope{Tenant: "t", App: "shop", ID: "data", Generation: 1}, ID: "a-1"}
	if got := archiveRel(b); got != ".sfc-archive/t/shop/data/a-1" {
		t.Fatal(got)
	}
	c := archiveRootConsumer(b)
	b.ID = "a-2"
	if !strings.HasPrefix(c, "volume-archive/") || c == archiveRootConsumer(b) {
		t.Fatal("pin names", c)
	}
}

func TestArchivePackageRemovedThroughTombstone(t *testing.T) {
	base, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer base.Close()
	rel := ".sfc-archive/t/shop/data/a-1"
	if err := base.MkdirAll(rel, 0700); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{archiveDataName, archiveManifestName} {
		if err := base.WriteFile(rel+"/"+f, []byte(f), 0600); err != nil {
			t.Fatal(err)
		}
	}
	// A tombstone from an earlier stop part way through.
	if err := base.MkdirAll(rel+".gone", 0700); err != nil {
		t.Fatal(err)
	}
	if err := base.WriteFile(rel+".gone/"+archiveDataName, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := removePackageDir(base, rel); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{rel, rel + ".gone"} {
		if _, err := base.Stat(name); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("left behind", name, err)
		}
	}
	// Removing again (a lost report) is a no-op.
	if err := removePackageDir(base, rel); err != nil {
		t.Fatal("second removal", err)
	}
}
