// SPDX-License-Identifier: Apache-2.0

package app

import (
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/jay94ks/seafield/internal/clusterapp"
	"github.com/jay94ks/seafield/internal/config"
	"github.com/jay94ks/seafield/internal/tenancy"
)

func TestEnabledClusterAppNeedsItsInstalledImage(t *testing.T) {
	var c config.Node
	if CheckClusterApps(c) != nil {
		t.Fatal("no cluster app refused")
	}
	c.ClusterApps.Web = &config.ClusterAppWeb{Enabled: true}
	// This test build has no web digest pin, so no image is installed.
	if err := CheckClusterApps(c); !errors.Is(err, clusterapp.ErrImageNotFound) || err.Error() != "cluster app web: cluster app image not found" {
		t.Fatal("enabled web without its image", err)
	}
	if _, err := Open(c); !errors.Is(err, clusterapp.ErrImageNotFound) {
		t.Fatal("runtime opened with a missing cluster app image", err)
	}
}

func TestWebTrustsOnlyIngressSources(t *testing.T) {
	member := tenancy.Network{Pools: []tenancy.Subnet{{Prefix: netip.MustParsePrefix("10.254.3.0/24"), Gateway: netip.MustParseAddr("10.254.3.1")}}}
	if got := trustedProxies(member); got != "10.254.240.0/20,10.254.3.1" {
		t.Fatal(got)
	}
}

// The web container runs as its own UID, which cannot read a root-only seal
// key file: it gets a copy it owns, read-only, kept equal to the original.
func TestWebSealKeyCopyIsOwnedByTheContainerUID(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("chown needs root")
	}
	dir := t.TempDir()
	src, dst := filepath.Join(dir, "web-seal.key"), filepath.Join(dir, "copy")
	if err := os.WriteFile(src, []byte("key-1"), 0600); err != nil {
		t.Fatal(err)
	}
	check := func(want string) {
		t.Helper()
		if err := ownedCopy(src, dst, 10001); err != nil {
			t.Fatal(err)
		}
		st, err := os.Stat(dst)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := os.ReadFile(dst)
		if sys := st.Sys().(*syscall.Stat_t); sys.Uid != 10001 || sys.Gid != 10001 || st.Mode().Perm() != 0400 || string(raw) != want {
			t.Fatal("copy", sys.Uid, sys.Gid, st.Mode(), string(raw))
		}
	}
	check("key-1")
	check("key-1")
	if err := os.WriteFile(src, []byte("key-2"), 0600); err != nil {
		t.Fatal(err)
	}
	check("key-2")
	// an empty or missing original is refused, also by sfcd check
	if err := os.WriteFile(src, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if ownedCopy(src, dst, 10001) == nil {
		t.Fatal("empty seal key copied")
	}
	if _, err := readSealKey(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("missing seal key read")
	}
}
