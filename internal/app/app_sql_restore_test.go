// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/engine"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/internal/workload/volumes"
	"github.com/moby/moby/client"
	"gopkg.in/yaml.v3"
)

// Extends the existing real two-Engine app fixture. It uses the same product
// CLI/controllers and actual MySQL/PDO; it never calls the copy/report helpers.
func testManagedSQLBackupRestore(t *testing.T, ctx context.Context, a *Runtime, root, file, document string, docker [2]*engine.Client, cli func([]*os.File, ...string) []byte, request func(int, string, string, string, ...int) map[string]any, read func() cluster.View, change func(string, string, uint64, any), wait func(string, func() bool), stopB, startB func()) {
	t.Helper()
	p := a.controlPolicy
	registry := func() control.Volumes {
		v, err := p.Volumes(read().State)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	retire := func(operation string) {
		t.Helper()
		cli(nil, "compose", "down", "--tenant", "tenant", "-p", "app", "--operation", operation)
		last, progressed := uint64(0), time.Now()
		wait("SQL app original Task/input/native retirement "+operation, func() bool {
			apps, err := p.Apps(read().State)
			if err != nil {
				return false
			}
			i, ok := apps.Inventory("tenant", "app")
			if i.Revision() != last {
				last, progressed = i.Revision(), time.Now()
			}
			if time.Since(progressed) > 45*time.Second {
				view := read()
				retirement, _ := i.Retirement()
				for _, target := range retirement.Targets {
					if target.Closed {
						continue
					}
					key := target.Original.Step.Key
					t.Log("unsettled original SQL target", target.Original.Step.Kind, key, "eligible", i.CanRetire(key), "generation", target.Original.Result.Generation)
					for phase, m := range map[string]*deployment.Mutation{"drain": target.Drain, "proof": target.Proof, "delete": target.Delete} {
						if m != nil {
							t.Log("phase", phase, "expected", m.Command.Expected, "result", m.Result, "pending", m.Journal.Pending != nil)
						}
					}
					peer, known := a.Mesh.Peer(sfcp.Identity(target.Original.Step.Owner))
					if !known || !view.State.Object(key).Present {
						continue
					}
					fresh, cancel := context.WithTimeout(context.Background(), 3*time.Second)
					reply, e := cluster.CallManagement(fresh, a.Mesh, a.Identity, a.controlPolicy.Cluster, peer, cluster.ManagementRequest{Method: "observe", Key: key})
					cancel()
					var observed ModuleObservation
					if e == nil && json.Unmarshal(reply.Data, &observed) == nil {
						t.Log("unsettled owner cause", observed.ModuleError, observed.Error)
					}
				}
				t.Fatal("SQL retirement stopped progressing; original references preserved", operation)
			}
			_, retiring := i.Retirement()
			return ok && !retiring && len(apps.Bindings().Live()) == 0
		})
		for _, c := range docker {
			rows, err := c.API.ContainerList(ctx, client.ContainerListOptions{All: true, Filters: client.Filters{}.Add("label", "org.sfc.owner="+c.Owner)})
			if err != nil || len(rows.Items) != 0 {
				t.Fatal("SQL app retained original container", err)
			}
		}
	}
	value := strings.Repeat("original-sql-row-", 1024)
	if result := request(0, "POST", "/row?key=cold&operation=cold-write", value); result["value"] != value {
		t.Fatal("original SQL write")
	}
	retire("cold-down")
	t.Log("original SQL app down and all shared/native consumer references returned")
	source, ok := registry().Native("tenant", "app", "data")
	if !ok || source.Verify() != nil {
		t.Fatal("retained original app Volume")
	}
	// These are explicit logical reservations, not a host quota modification.
	const reserve = uint64(512 << 20)
	for _, tenant := range []string{"", "tenant"} {
		change("sql-backup-budget-"+tenant, "set-volume-backup-limit", 0, control.VolumeBackupLimit{Tenant: tenant, Node: "node-b", Bytes: reserve, Count: 2, StagingBytes: reserve, StagingCount: 2})
	}
	// The dry run reads the backup source and fails unless the writer exited cleanly.
	backupArgs := []string{"--tenant", "tenant", "volume", "backup", "create", "app/data", "--name", "sql-cold", "--max-size", strconv.FormatUint(reserve, 10), "--max-entries", "4096", "--id", "sql-backup"}
	cli(nil, append(backupArgs, "--dry-run")...)
	cli(nil, append(backupArgs, "--no-wait")...)
	backup := func() control.VolumeBackup { j, _ := registry().Backup(source.Spec.Scope, "sql-cold"); return j }
	wait("actual MySQL cold backup Ready", func() bool { return backup().Phase == "Ready" })
	if backup().Receipt == nil || backup().Completion == nil || !backup().Completion.CleanShutdown || !backup().Completion.DirectorySynced || backup().Binding.Compatibility == ([32]byte{}) {
		t.Fatal("SQL backup completion lacks original clean source/receipt")
	}
	t.Log("actual MySQL backup Ready", "bytes", backup().Receipt.Bytes, "entries", backup().Receipt.Entries)
	cli(nil, "--tenant", "tenant", "volume", "restore", "app/data", "sql-cold", "--to", "app/restored", "--name", "sql-copy", "--generation", "1", "--max-size", strconv.FormatUint(reserve, 10), "--id", "sql-restore", "--no-wait")
	selection := control.VolumeRestoreSelection{Backup: control.VolumeBackupSelection{Scope: source.Spec.Scope, ID: "sql-cold"}, ID: "sql-copy"}
	job := func() control.VolumeRestore { j, _ := registry().Restore(selection); return j }
	wait("actual MySQL inactive target file verification", func() bool { return job().Phase == "Restored" })
	restored, ok := registry().Native("tenant", "app", "restored")
	if !ok || restored.Verify() != nil || restored.Owner.Native == source.Owner.Native || job().Report == nil || !job().Report.CopyVerified || !job().Report.FilesSynced || !job().Report.ArtifactReturned {
		t.Fatal("original/new SQL target confused or unverified")
	}
	defer func() {
		if !t.Failed() {
			return
		}
		peer, ok := a.Mesh.Peer(sfcp.Identity(restored.Owner.Key))
		if !ok {
			return
		}
		fresh, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		reply, err := cluster.CallManagement(fresh, a.Mesh, a.Identity, source.Spec.Scope.Cluster, peer, cluster.ManagementRequest{Method: "observe", Key: deployment.ResourceKey("task", "tenant", "app", "db")})
		var observed ModuleObservation
		if err == nil && json.Unmarshal(reply.Data, &observed) == nil {
			t.Log("original restored SQL owner cause", observed.ModuleError, observed.Error)
		}
	}()
	core, ok := registry().Volume(restored.Spec.Scope)
	if !ok || len(core.Consumers()) != 0 {
		t.Fatal("restored files published with an active writer")
	}
	t.Log("actual restored target verified and synced; no active writer")
	// Artifact deletion must not erase the original activation facts needed by
	// the first writer. Its shared immutable binding remains a tombstone.
	cli(nil, "--tenant", "tenant", "volume", "backup", "delete", "app/data", "sql-cold", "--id", "sql-backup-delete", "--no-wait")
	wait("original SQL backup artifact Deleted", func() bool { return backup().Phase == "Deleted" })
	t.Log("original backup artifact Deleted; preserve immutable backup/restore binding and writer history")
	if err := a.Engine().Snapshot(ctx); err != nil {
		t.Fatal(err)
	}
	stopB()
	startB()
	// Only the logical mount/declaration name changes; image, executable,
	// protected input selections and database configuration remain pinned.
	replacement := renameAppVolume(t, document, "db", "data", "restored")
	if replacement == document || !strings.Contains(replacement, "restored") {
		t.Fatal("SQL restore declaration did not select new target")
	}
	if err := os.WriteFile(file, []byte(replacement), 0600); err != nil {
		t.Fatal(err)
	}
	cli(nil, "compose", "up", "--operation", "restore-rollout", "--tenant", "tenant", "-f", file, "--no-input")
	started := time.Now()
	wait("restored MySQL app actual readiness", func() bool {
		if time.Since(started) > 120*time.Second {
			t.Fatal("restored app readiness did not progress; inspect original owner cause")
		}
		apps, err := p.Apps(read().State)
		if err != nil {
			return false
		}
		ex, ok := apps.Execution("tenant", "app")
		return ok && ex.Status() == "Succeeded"
	})
	if result := request(0, "GET", "/row?key=cold", ""); result["value"] != value {
		t.Fatal("restored MySQL/PDO did not recover original SQL row")
	}
	if result := request(0, "GET", "/operation?id=cold-write", ""); result["value"] != value || result["operation"] != "cold-write" {
		t.Fatal("restored MySQL lost original committed operation")
	}
	if result := request(0, "PUT", "/row?key=cold&operation=after-restore", "new-target-write"); result["value"] != "new-target-write" {
		t.Fatal("restored target SQL writer unavailable")
	}
	for _, pair := range []struct {
		ready volumes.NativeReady
		live  bool
	}{{source, false}, {restored, true}} {
		rows, err := docker[1].API.ContainerList(ctx, client.ContainerListOptions{All: true, Filters: client.Filters{}.Add("volume", pair.ready.Owner.Native)})
		if err != nil || (len(rows.Items) == 1) != pair.live || len(rows.Items) > 1 {
			t.Fatal("original/restored native writer exclusivity", pair.live, err)
		}
	}
	t.Log("restored MySQL original row/committed operation and new target SQL write passed; source unmounted/target single writer")
	retire("restored-down")
	for _, ready := range []volumes.NativeReady{source, restored} {
		got, err := docker[1].API.VolumeInspect(ctx, ready.Owner.Native, client.VolumeInspectOptions{})
		if err != nil {
			t.Fatal(err)
		}
		marker, err := os.ReadFile(filepath.Join(got.Volume.Mountpoint, ".sfc-app-initialized"))
		if err != nil || string(marker) != "1\n" {
			t.Fatal("original/restored SQL datadir not retained", err)
		}
		core, ok := registry().Volume(ready.Spec.Scope)
		if !ok || len(core.Consumers()) != 0 {
			t.Fatal("SQL app did not return original writer reference")
		}
	}
	cli(nil, "op", "show", "sql-restore")
	t.Log("actual app Binding clean MySQL exit -> CLI backup/daemon artifact -> inactive CLI restore/sync -> artifact Gone/Snapshot/owner DB restart -> same deployment core/new target -> original SQL row/operation/new SQL write -> source unmounted/target single writer -> CLI down/whole references returned/retained datadirs")
}

// renameAppVolume points one service's mount and the volume declaration at a
// new volume name. It edits the parsed YAML, so the result does not depend on
// how the fixture document was formatted or marshalled.
func renameAppVolume(t *testing.T, document, service, from, to string) string {
	t.Helper()
	var root yaml.Node
	if err := yaml.Unmarshal([]byte(document), &root); err != nil || len(root.Content) != 1 {
		t.Fatal("app.yaml", err)
	}
	field := func(n *yaml.Node, key string) *yaml.Node {
		if n == nil || n.Kind != yaml.MappingNode {
			return nil
		}
		for i := 0; i+1 < len(n.Content); i += 2 {
			if n.Content[i].Value == key {
				return n.Content[i+1]
			}
		}
		return nil
	}
	doc := root.Content[0]
	mounts := field(field(field(doc, "services"), service), "volumes")
	if mounts == nil || mounts.Kind != yaml.SequenceNode {
		t.Fatal("app.yaml service has no volumes", service)
	}
	for _, m := range mounts.Content {
		switch {
		case m.Kind == yaml.ScalarNode && strings.HasPrefix(m.Value, from+":"):
			m.Value = to + m.Value[len(from):]
		case m.Kind == yaml.MappingNode && field(m, "source") != nil && field(m, "source").Value == from:
			field(m, "source").Value = to
		}
	}
	declared := field(doc, "volumes")
	for i := 0; declared != nil && i+1 < len(declared.Content); i += 2 {
		if declared.Content[i].Value == from {
			declared.Content[i].Value = to
		}
	}
	out, err := yaml.Marshal(&root)
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}
