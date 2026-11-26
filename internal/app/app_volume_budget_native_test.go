// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/jay94ks/mydcd/internal/cluster"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/mydcp"
	"github.com/jay94ks/mydcd/internal/userauth"
)

const appVolumeReservation = uint64(1 << 20)

func TestRealBoundaryManagedAppVolumeOriginalBudget(t *testing.T) {
	runManagedAppOwner(t, true, true, true, true, managedAppBudgetedVolume, true, true)
}
func TestRealBoundaryCLICreatedAppVolumeOriginalBudget(t *testing.T) {
	runManagedAppOwner(t, true, true, true, true, managedAppBudgetedPrecreatedVolume, true, true)
}

// The existing owner fixture owns the Engine/container/DB rollback. All policy
// mutations below use the real product CLI -> signed operation -> Raft reducer.
func prepareManagedVolumeBudget(t *testing.T, ctx context.Context, root string, user userauth.Client, peer mydcp.Peer, p control.Policy, read func() cluster.View) func(bool) {
	t.Helper()
	home, profile := filepath.Join(root, "budget-home"), filepath.Join(root, "budget.yaml")
	if err := os.Mkdir(home, 0700); err != nil {
		t.Fatal(err)
	}
	config := fmt.Sprintf("version: 1\nauth: user\ncluster: '%x'\npeers:\n - {id: node-a, key: '%x', endpoint: '%s', voter: true}\n", user.Cluster, peer.Key, peer.Endpoint)
	if err := os.WriteFile(profile, []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	cli := func(want int, args ...string) {
		t.Helper()
		cmd := nativeCLICmd(ctx, os.Getenv("MYDC_TEST_CLI"), home, profile, args...)
		out, err := cmd.CombinedOutput()
		code := 0
		if err != nil {
			if e, ok := err.(*exec.ExitError); ok {
				code = e.ExitCode()
			} else {
				t.Fatal(err)
			}
		}
		if code != want {
			t.Fatal("budget CLI", args, code, string(out))
		}
	}
	cli(0, "login", "--username", "admin", "--method", "private-key", "--key-file", filepath.Join(root, "admin", "key.pem"))
	change := func(id string, limit control.VolumeBackupLimit, want int) {
		t.Helper()
		args, _ := nativeMovedChange(id, "set-volume-backup-limit", limit)
		cli(want, args...)
	}
	for _, tenant := range []string{"", "tenant"} {
		change("original-limit-"+tenant, control.VolumeBackupLimit{Tenant: tenant, Node: "node-a", Original: &control.OriginalVolumeLimit{Bytes: appVolumeReservation, Count: 1}}, 0)
	}
	return func(deleted bool) {
		t.Helper()
		v, err := p.Volumes(read().State)
		if err != nil {
			t.Fatal(err)
		}
		c, err := p.Catalog(read().State)
		if err != nil {
			t.Fatal(err)
		}
		rows, _, err := v.Page(c, "admin", "tenant", "")
		if err != nil || len(rows) != 1 || rows[0].CapacityBytes != appVolumeReservation {
			t.Fatal("actual app original reservation", rows, err)
		}
		if deleted != (rows[0].Phase == "Deleted") {
			t.Fatal("budget probe at wrong native phase", rows[0].Phase)
		}
		if !deleted {
			cli(0, "--tenant", "tenant", "volume", "show", "app/data")
			cli(0, "--tenant", "tenant", "volume", "usage", "app/data")
			cli(3, "--tenant", "tenant", "volume", "create", "app/over-budget", "--node", "node-a", "--uid", "10001", "--gid", "10001", "--size", fmt.Sprint(appVolumeReservation), "--id", "original-competition", "--no-wait")
		}
		for _, limit := range v.BackupLimits() {
			// Placement for the tenant may be revoked by now, which hides the
			// tenant row from the read the CLI does; give its revision directly.
			limit.Original = &control.OriginalVolumeLimit{}
			suffix, want := "retained", 3
			if deleted {
				suffix, want = "gone", 0
			}
			change("original-shrink-"+suffix+"-"+limit.Tenant, limit, want)
		}
		// Inspecting failed policy changes must leave the reservation unchanged.
		if !deleted {
			after, _ := p.Volumes(read().State)
			a, _ := json.Marshal(v.BackupLimits())
			b, _ := json.Marshal(after.BackupLimits())
			if !bytes.Equal(a, b) {
				t.Fatal("rejected shrink changed original policy")
			}
		}
		t.Log("actual CLI original byte/count policy -> same app/native reservation -> observed usage and competing create denial -> retain holds capacity; signed Gone permits zero budget without changing original history")
	}
}
