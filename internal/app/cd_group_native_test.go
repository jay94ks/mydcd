// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jay94ks/mydcd/internal/cli"
	"github.com/jay94ks/mydcd/internal/cluster"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/deployment"
	"github.com/jay94ks/mydcd/internal/userauth"
	"github.com/jay94ks/mydcd/tests/gitfixture"
	"github.com/moby/moby/client"
	"gopkg.in/yaml.v3"
)

// Uses the real moved app's Group grant, native Task and CLI wallet. The
// source server supplies only Git bytes; approvals and denial receipts must
// come from the ordinary current-authority/FSM/provider paths.
func verifyNativeCDGroupRevocation(t *testing.T, ctx context.Context, target *Runtime, root string, source *gitfixture.Fixture, targetDocument []byte, p control.Policy, read func() cluster.View, change func(string, string, uint64, any), wait func(string, func() bool)) string {
	t.Helper()
	input, err := deployment.ParseApp(targetDocument)
	if err != nil || source == nil {
		t.Fatal("original CD move target input", err)
	}
	service := input.Services["web"]
	if service.Environment == nil {
		service.Environment = deployment.Environment{}
	}
	service.Environment["REVISION"] = "after-explicit-move"
	input.Services["web"] = service
	body, err := yaml.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	commit := source.Commit(body)
	var choice deployment.DeliverySelection
	wait("actual next Git candidate uses the moved owner and original Group", func() bool {
		apps, err := p.Apps(read().State)
		d, found := apps.Delivery("tenant", "app")
		selected, exists := d.CandidateSelection()
		choice = selected
		return err == nil && found && exists && selected.Commit == commit && d.SourceError() == ""
	})
	call := func(want int, args ...string) []byte {
		t.Helper()
		out, diagnostic, err := runManagedCLICommand(ctx, os.Getenv("MYDC_TEST_CLI"), filepath.Join(root, "cli-home"), filepath.Join(root, "cli.yaml"), args, nil)
		code := 0
		if err != nil {
			if exited, ok := err.(*exec.ExitError); ok {
				code = exited.ExitCode()
			} else {
				t.Fatal(err)
			}
		}
		if code != want {
			t.Fatal("original CD Group CLI", args, "exit", code, "want", want, string(diagnostic), string(out))
		}
		return out
	}
	candidate := hex.EncodeToString(choice.Candidate[:])
	// No password FD is available. Current same-scope target consent must be
	// reused; this command does not accept a sync or change the native process.
	call(0, "cd", "approve", "app", candidate, "--secrets", "--tenant", "tenant")
	apps, err := p.Apps(read().State)
	if err != nil {
		t.Fatal(err)
	}
	execution, found := apps.Execution("tenant", "app")
	key := deployment.ResourceKey("task", "tenant", "app", "web")
	stage, exists := execution.Stage(key)
	if !found || !exists || stage.Result == nil || execution.Status() != "Succeeded" {
		t.Fatal("actual moved execution before Group revocation")
	}
	operation := execution.ActiveOperation()
	binding, found := apps.Binding(deployment.ObjectRef{Key: key, Generation: stage.Result.Generation, Revision: stage.Result.Revision})
	grants := binding.Grants()
	if !found || len(grants) != 1 || len(grants[0].Pins) != 1 {
		t.Fatal("exact original live Group approval required")
	}
	before, err := target.workload.Status(ctx, key)
	if err != nil || !before.Ready || !before.Running {
		t.Fatal("actual moved native before Group revocation", err)
	}
	id := grants[0].Pins[0].ApprovalID
	readApproval := func(revoking bool) {
		t.Helper()
		var page userauth.Reply
		if raw := call(0, "--tenant", "tenant", "manage", "vault-approvals", "--app", "app"); json.Unmarshal(raw, &page) != nil || page.PublicRead == nil {
			t.Fatal("actual approval listing", string(raw))
		}
		for _, row := range page.PublicRead.Rows {
			if a := row.Approval; a != nil && a.ID == id {
				if a.Revoking != revoking || a.Consumers == 0 || a.App != "app" {
					t.Fatal("listing lost original live/revoking approval", a)
				}
				return
			}
		}
		t.Fatal("original approval was hidden while native consumer remains")
	}
	readApproval(false)
	vault, err := p.Vault(read().State)
	if err != nil {
		t.Fatal(err)
	}
	change("revoke-current-cd-group", "vault-revoke-approval", vault.Approvals.Revision(), control.VaultApprovalSelection{ID: id})
	vault, err = p.Vault(read().State)
	if err != nil || !vault.Approvals.RevocationPending(id) {
		t.Fatal("Group revocation erased a still-live original consumer", err)
	}
	readApproval(true)
	var status struct {
		CD control.AppCDView `json:"detail"`
	}
	if err := json.Unmarshal(call(0, "cd", "show", "app", "--tenant", "tenant"), &status); err != nil || status.CD.Blocked != "group-approval" || status.CD.Candidate == nil || status.CD.Candidate.Candidate != choice.Candidate {
		t.Fatal("current Group denial was not attached to the exact Git candidate", status.CD.Blocked, err)
	}
	// A rejected change exits 1; its op record keeps the server's answer.
	args := []string{"cd", "sync", "app", "--tenant", "tenant", "--id", "revoked-cd-operation", "--candidate", candidate}
	opState := func() cli.Op {
		t.Helper()
		var op cli.Op
		if err := json.Unmarshal(call(0, "op", "show", "revoked-cd-operation"), &op); err != nil {
			t.Fatal("op show", err)
		}
		return op
	}
	call(1, args...)
	first := opState()
	if first.State != cli.Failed || !strings.HasPrefix(first.Detail, "rejected: not permitted") {
		t.Fatal("new sync was not positively denied by current Group authority", first)
	}
	call(1, args...)
	if retained := opState(); retained.State != first.State || retained.Detail != first.Detail {
		t.Fatal("exact denied CD request changed its retained receipt", retained)
	}
	apps, err = p.Apps(read().State)
	current, active := apps.Execution("tenant", "app")
	kept, bound := apps.Binding(deployment.ObjectRef{Key: key, Generation: stage.Result.Generation, Revision: stage.Result.Revision})
	if err != nil || !active || current.ActiveOperation() != operation || !bound || kept.Digest() != binding.Digest() {
		t.Fatal("denied CD sync replaced the original execution/Binding", err)
	}
	// Read native state directly: a revoked input grant may make the current
	// managed Status unavailable, which is not evidence that Docker stopped.
	native, err := target.docker.API.ContainerInspect(ctx, before.NativeID, client.ContainerInspectOptions{})
	if err != nil || native.Container.State == nil || !native.Container.State.Running || native.Container.State.StartedAt != before.StartedAt {
		t.Fatal("Group revocation destroyed the accepted native", err)
	}
	t.Log("actual moved Group/Volume app: next pinned Git candidate reuses consent without password; explicit live approval revocation retains original consumer/native and yields exact Forbidden sync receipt; subsequent ordinary down must settle the original grant")
	return id
}
