// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/secrets"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/internal/userauth"
	"github.com/jay94ks/seafield/internal/workload"
	"github.com/jay94ks/seafield/tests/vaultfixture"
)

func TestRealBoundaryManagedOrderedSecretGroups(t *testing.T) {
	runManagedAppOwner(t, true, true, true, true, managedAppOrderedSecrets, true, true, false, true)
}

func managedOrderedSecretDocument(raw []byte) []byte {
	s := strings.Replace(string(raw), "secrets_from: [data]", "secrets_from: [group/common, group/department, data]", 1)
	s = strings.Replace(s, "mode: '0400'}]", "mode: '0400'}, {source: username, target: /run/secrets/db-user, uid: '10001', gid: '10001', mode: '0400'}, {source: database, target: /run/secrets/database, uid: '10001', gid: '10001', mode: '0400'}]", 1)
	s += " username:\n  x-sfc: {key: DB_USER}\n database:\n  x-sfc: {key: DATABASE}\n"
	return []byte(s)
}

type managedSecretAudit struct {
	path        string
	targets     map[string]string
	before      map[string]int
	publicReads *managedVaultReadChecks
}

func openManagedSecretAudit(t *testing.T, v *vaultfixture.Vault, p control.Policy, read func() cluster.View) *managedSecretAudit {
	t.Helper()
	a := &managedSecretAudit{path: filepath.Join(v.Root, "group-audit.jsonl"), targets: map[string]string{}}
	current, err := p.Vault(read().State)
	if err != nil {
		t.Fatal(err)
	}
	for _, group := range []string{"common", "group"} {
		binding, err := current.Trees["tenant"].Verifier(group)
		if err != nil {
			t.Fatal("published actual Group verifier", err)
		}
		a.targets[group] = "kv/data/" + binding.Reference.Object
	}
	// Default HMAC redaction remains enabled. Only public path/count metadata
	// leaves this private provider audit; values/token/HMACs are not exported.
	v.API("PUT", "sys/audit/sfc-groups", map[string]any{"type": "file", "options": map[string]string{"file_path": a.path, "mode": "0600", "log_raw": "false"}}, nil, v.Admin)
	a.before = a.counts(t)
	return a
}
func (a *managedSecretAudit) counts(t *testing.T) map[string]int {
	t.Helper()
	f, err := os.Open(a.path)
	if err != nil {
		t.Fatal("provider audit", err)
	}
	defer f.Close()
	if info, err := f.Stat(); err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("private provider audit mode", err)
	}
	counts := map[string]int{"common": 0, "group": 0}
	scan := bufio.NewScanner(f)
	scan.Buffer(make([]byte, 4096), 1<<20)
	for scan.Scan() {
		var event struct {
			Type    string                           `json:"type"`
			Request struct{ Path, Operation string } `json:"request"`
		}
		if err := json.Unmarshal(scan.Bytes(), &event); err != nil {
			t.Fatal("invalid provider audit entry")
		}
		if event.Type != "request" || event.Request.Operation != "read" {
			continue
		}
		for group, path := range a.targets {
			if event.Request.Path == path {
				counts[group]++
			}
		}
	}
	if err := scan.Err(); err != nil {
		t.Fatal(err)
	}
	return counts
}

func verifyManagedOrderedSecrets(t *testing.T, ctx context.Context, r *Runtime, root string, user userauth.Client, peer sfcp.Peer, session access.Session, p control.Policy, read func() cluster.View, change func(string, string, uint64, any), audit *managedSecretAudit) map[string]any {
	t.Helper()
	counts := audit.counts(t)
	for group, count := range counts {
		if count != audit.before[group]+1 {
			t.Fatal("Group verifier must be fetched once for first CLI approval and not on resume", group, count-audit.before[group])
		}
	}
	taskKey := deployment.ResourceKey("task", "tenant", "app", "web")
	apps, err := p.Apps(read().State)
	if err != nil {
		t.Fatal(err)
	}
	execution, _ := apps.Execution("tenant", "app")
	stage, _ := execution.Stage(taskKey)
	if stage.Result == nil || stage.Observation == nil || !stage.Observation.Healthy {
		t.Fatal("real native consumer not healthy")
	}
	task := deployment.ObjectRef{Key: taskKey, Generation: stage.Result.Generation, Revision: stage.Result.Revision}
	binding, ok := apps.Binding(task)
	grants := binding.Grants()
	if !ok || len(binding.Needs().Sources) != 3 || len(grants) != 1 || len(grants[0].Pins) != 2 {
		t.Fatal("whole same-realm use and two protected Group pins")
	}
	current, err := p.Vault(read().State)
	if err != nil {
		t.Fatal(err)
	}
	audit.publicReads = captureManagedVaultReads(t, ctx, root, user, peer, session, p, read, grants)
	encoded, err := current.Approvals.Encode()
	if err != nil {
		t.Fatal(err)
	}
	var approvalView struct {
		Records []struct{ Approval secrets.Approval }
	}
	if json.Unmarshal(encoded, &approvalView) != nil {
		t.Fatal("approval view")
	}
	for _, pin := range grants[0].Pins {
		found := false
		for _, row := range approvalView.Records {
			a := row.Approval
			if a.Payload.Target.ApprovalID != pin.ApprovalID {
				continue
			}
			payload, _ := json.Marshal(a.Payload)
			var fields map[string]json.RawMessage
			_ = json.Unmarshal(payload, &fields)
			if len(fields) != 3 || fields["approved_at"] == nil || fields["fact"] == nil || fields["target"] == nil || !ed25519.Verify(a.Issuer[:], secrets.ApprovalBytes(a), a.Signature) {
				t.Fatal("approval contains more than signed time/fact/target or invalid signature")
			}
			found = true
		}
		if !found {
			t.Fatal("original Group approval disappeared")
		}
	}
	row, err := r.workload.View(taskKey)
	if err != nil {
		t.Fatal(err)
	}
	spec, err := workload.DecodeContainer(row.State.Applied.Spec)
	if err != nil || spec.Inputs == nil {
		t.Fatal("original input reference", err)
	}
	physical, err := r.docker.Identity("container", taskKey, row.State.Applied)
	if err != nil {
		t.Fatal(err)
	}
	lease, err := r.projections.InspectInputs(ctx, *spec.Inputs, "workload/"+physical.Name, taskKey, task.Generation)
	if err != nil || len(lease.Files) != 3 {
		t.Fatal("actual projection set", err)
	}
	want := map[string]string{"/run/secrets/db-password": "private-db-value", "/run/secrets/db-user": "base-user", "/run/secrets/database": "database-final"}
	for _, file := range lease.Files {
		raw, err := os.ReadFile(file.Source)
		if err != nil || string(raw) != want[file.Target] || file.Mode != 0400 || file.UID != 10001 || file.GID != 10001 {
			clear(raw)
			t.Fatal("ordered final keyset/private file ownership mismatch", err)
		}
		clear(raw)
	}
	shared, err := state.Encode(read().State)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{"private-db-value", "base-must-not-win", "base-user", "database-final", "private-native-group-password"} {
		if bytes.Contains(shared, []byte(value)) || bytes.Contains(shared, []byte(base64.StdEncoding.EncodeToString([]byte(value)))) {
			t.Fatal("private material reached shared state")
		}
	}
	base, _ := current.Trees["tenant"].Object("base")
	before := current.Approvals.LiveReferences(current.Trees["tenant"], "base", base.Generation)
	if before < 1 {
		t.Fatal("missing original source usage")
	}
	change("ordered-revoke-base", "vault-revoke", base.Revision, control.VaultSelection{Realm: "tenant", ID: "base"})
	audit.publicReads.assert(t, ctx, 1, nil)
	audit.publicReads.usages(t, ctx, 1)
	request := control.AppBindingRequest{Task: task, Digest: binding.Digest()}
	if _, err := r.appInputPermit(ctx, request); err == nil {
		t.Fatal("revoked first source was skipped during whole-source authorization")
	}
	current, _ = p.Vault(read().State)
	if current.Approvals.LiveReferences(current.Trees["tenant"], "base", base.Generation) != before {
		t.Fatal("revoke dropped live source references")
	}
	revokingBase, _ := current.Trees["tenant"].Object("base")
	raw, _ := control.ChangeBytes("vault-retire", session.User, revokingBase.Revision, control.VaultSelection{Realm: "tenant", ID: "base"})
	var command control.Change
	_ = json.Unmarshal(raw, &command)
	op, err := user.Prepare(ctx, peer, session, "ordered-live-retire", command)
	if err != nil {
		t.Fatal(err)
	}
	denied, err := user.Operation(ctx, peer, op, false)
	if err != nil || denied.Result == nil || denied.Result.Code != state.ConditionFailed {
		t.Fatal("live source retirement allowed", err)
	}
	status, err := r.workload.Status(ctx, taskKey)
	if err != nil || !status.Running || status.NativeID != stage.Observation.Native {
		t.Fatal("revocation disturbed original running native consumer", err)
	}
	again, err := r.projections.InspectInputs(ctx, *spec.Inputs, "workload/"+physical.Name, taskKey, task.Generation)
	if err != nil || !reflect.DeepEqual(again.Pin, lease.Pin) || len(again.Files) != len(lease.Files) {
		t.Fatal("revocation lost original private pin/files", err)
	}
	if gone, err := r.projections.Gone(*spec.Inputs); err != nil || gone {
		t.Fatal("live original files were reported Gone", err)
	}
	// The private CLI root must not contain plaintext values or passwords.
	if err := filepath.WalkDir(filepath.Join(root, "cli-home"), func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		defer clear(b)
		for _, value := range []string{"private-db-value", "base-must-not-win", "base-user", "database-final", "private-native-group-password"} {
			if bytes.Contains(b, []byte(value)) || bytes.Contains(b, []byte(base64.StdEncoding.EncodeToString([]byte(value)))) {
				t.Error("private input persisted in CLI intent")
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	t.Log("actual two Group FD approvals fetched each fixed verifier once; no-FD up/resume reused signatures; remote Vault ordered common/department/leaf merge produced exact three private read-only files; first-source revoke denied whole read while original running ID/files/usage remained; live retire rejected and no raw values/passwords in shared or CLI state")
	return map[string]any{"verifier_reads_before": audit.before, "verifier_reads_after_up_resume": counts, "source_count": 3, "protected_groups": 2, "projection_files": 3, "native_id": status.NativeID, "task": task, "binding": binding.Digest(), "original_source_references": before}
}

func finishManagedOrderedSecrets(t *testing.T, ctx context.Context, root string, p control.Policy, read func() cluster.View, change func(string, string, uint64, any), audit *managedSecretAudit) {
	t.Helper()
	current, err := p.Vault(read().State)
	if err != nil {
		t.Fatal(err)
	}
	audit.publicReads.assert(t, ctx, 0, nil)
	audit.publicReads.usages(t, ctx, 0)
	base, _ := current.Trees["tenant"].Object("base")
	if current.Approvals.LiveReferences(current.Trees["tenant"], "base", base.Generation) != 0 {
		t.Fatal("original source usage survived actual whole closure")
	}
	change("ordered-retire-base", "vault-retire", base.Revision, control.VaultSelection{Realm: "tenant", ID: "base"})
	current, _ = p.Vault(read().State)
	common, _ := current.Trees["tenant"].Object("common")
	change("ordered-revoke-common", "vault-revoke", common.Revision, control.VaultSelection{Realm: "tenant", ID: "common"})
	current, _ = p.Vault(read().State)
	common, _ = current.Trees["tenant"].Object("common")
	change("ordered-retire-common", "vault-retire", common.Revision, control.VaultSelection{Realm: "tenant", ID: "common"})
	current, _ = p.Vault(read().State)
	for _, id := range []string{"base", "common"} {
		object, _ := current.Trees["tenant"].Object(id)
		if object.Status != secrets.Retired {
			t.Fatal("source not retired after actual whole consumer closure", id)
		}
	}
	finishManagedVaultApprovalReads(t, ctx, p, read, change, audit.publicReads)
	t.Log("actual CLI down/native Gone returned all original source/Group/writer references; original revoked Secret and protected Group retired afterwards, provider destroy remains separate")
}
