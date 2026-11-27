// SPDX-License-Identifier: Apache-2.0

package workload_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/storage"
	"github.com/jay94ks/seafield/internal/workload"
	contract "github.com/jay94ks/seafield/lifecycle/v1"
)

// Reuses the owned frozen-image fixture and its rollback, not another Docker
// deployment. Current authority is injected: this is the actual SDK/A3/exec
// boundary, not managed app authentication or script-integration evidence.
func exerciseContainerExecProbes(t *testing.T, ctx context.Context, m *workload.Manager, key, root string, cluster, node [32]byte) {
	t.Helper()
	digest := sha256.Sum256([]byte(key))
	db, err := storage.Open(filepath.Join(root, "checker-execs-"+hex.EncodeToString(digest[:8])+".db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	text := func(h [32]byte) string { return hex.EncodeToString(h[:]) }
	for _, code := range []int{0, 7} {
		record, err := m.View(key)
		if err != nil {
			t.Fatal(err)
		}
		status, err := m.Status(ctx, key)
		if err != nil || !status.Running {
			t.Fatal(status, err)
		}
		run := sha256.Sum256([]byte(key + "/exec/" + strconv.Itoa(code)))
		boot := sha256.Sum256([]byte("fixture-credential"))
		request := contract.Request{Schema: 1, RunID: text(run), Cluster: text(cluster), Tenant: "tenant", App: "app", Checker: "exec", SourceDigest: text(digest), Phase: contract.Liveness, DeadlineUnixMilli: time.Now().Add(10 * time.Second).UnixMilli(), Targets: []contract.Target{{Service: "fixture", TaskKey: key, NativeID: status.NativeID, Owner: text(node), OwnerBoot: text(boot), Generation: record.State.Applied.Generation, Revision: record.State.Desired.Revision, StartedAt: status.StartedAt}}}
		var receipts []workload.ProbeExecReceipt
		save := func(p workload.ProbeExecReceipt) error {
			if p.Validate(request) != nil {
				return errors.New("invalid original exec receipt")
			}
			raw, err := json.Marshal(p)
			if err != nil {
				return err
			}
			if err = db.Write(map[string][]byte{"exec/" + hex.EncodeToString(p.Call[:]): raw}); err != nil {
				return err
			}
			receipts = append(receipts, p)
			return nil
		}
		probe, err := m.OpenServiceProbe(ctx, request, func(context.Context, string, contract.Target) error { return nil }, save)
		if err != nil {
			t.Fatal(err)
		}
		got, runErr := probe.Exec(ctx, contract.ExecProbe{Service: "fixture", Argv: []string{"/backend", "--exit-code", strconv.Itoa(code)}, MaxBytes: 32})
		closeErr := probe.Close(context.Background())
		if runErr != nil || closeErr != nil || !got.Exited || got.ExitCode != code || len(receipts) == 0 || receipts[len(receipts)-1].Phase != workload.ProbeExecCompleted {
			t.Fatal("actual original Docker exec", got, runErr, closeErr, receipts)
		}
		for _, p := range receipts {
			if p.Call != receipts[0].Call || p.RunID != request.RunID || p.Target != request.Targets[0] {
				t.Fatal("exec substituted original call", p)
			}
		}
		after, err := m.View(key)
		if err != nil || len(after.Consumers) != len(record.Consumers) {
			t.Fatal("exec read pin not returned", err)
		}
		denied := errors.New("current exec authority denied")
		probe, err = m.OpenServiceProbe(ctx, request, func(context.Context, string, contract.Target) error { return denied }, save)
		if err != nil {
			t.Fatal(err)
		}
		before := len(receipts)
		_, runErr = probe.Exec(ctx, contract.ExecProbe{Service: "fixture", Argv: []string{"/backend", "--exit-code", "0"}, MaxBytes: 32})
		closeErr = probe.Close(context.Background())
		if !errors.Is(runErr, denied) || closeErr != nil || len(receipts) != before {
			t.Fatal("revoked authority reached exec", runErr, closeErr)
		}
	}
}
