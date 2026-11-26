// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cliprofile"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/mydcp"
	"github.com/jay94ks/mydcd/internal/schema"
	"github.com/jay94ks/mydcd/internal/userauth"
)

func managementHelp(out io.Writer) {
	fmt.Fprintln(out, "mydc --tenant TENANT manage tenant-storage [--node NODE] [--after CURSOR] (current ManageVolumes or ManageRegistry; own allowed root references only, not a Start/build grant)")
	fmt.Fprintln(out, "mydc [account options] --tenant TENANT manage lifecycle-uses --name NAME [--after CURSOR]")
	fmt.Fprintln(out, "mydc [account options] --tenant TENANT manage image-trust [--after CURSOR]")
	fmt.Fprintln(out, "mydc [account options] manage tasks [--node NODE] [--app APP] [--after CURSOR] [--all-tenants] (current tenant Read; defaults to selected tenant)")
	fmt.Fprintln(out, "mydc [account options] manage self-credentials (own public credentials; no tenant or system-admin requirement)")
	fmt.Fprintln(out, "Global --reason TEXT / --incident-id ID / --approved-by ACCOUNT_ID bind display metadata to a new signed operation. Claimed approved-by grants no authority; result/resume preserve the original metadata.")
	fmt.Fprintln(out, "mydc [--config FILE] manage apply --request-id ID --change FILE")
	fmt.Fprintln(out, "mydc [--config FILE] manage result --request-id ID")
	fmt.Fprintln(out, "mydc [--config FILE] manage resume --request-id ID")
	fmt.Fprintln(out, "mydc [--config FILE] manage prune")
	fmt.Fprintln(out, "mydc --tenant TENANT manage app-source --app NAME [--deployment ID] [--revision VERSION] [--section source|local-services|overlays] [--raw]")
	fmt.Fprintln(out, "mydc --tenant TENANT manage app-revisions --app NAME [--deployment ID] [--after CURSOR]")
	fmt.Fprintln(out, "Node storage metadata: add-node-storage, set-node-storage-policy, drain-node-storage, remove-node-storage (system administrator; node storage provides typed convenience commands).")
	fmt.Fprintln(out, "Lifecycle metadata: set-lifecycle-policy, put-lifecycle-script, retire-lifecycle-script, delete-lifecycle-script (tenant manage-services; signed staged artifact metadata only, no raw source/Secret in change files).")
	fmt.Fprintln(out, "Registry metadata: put-registry, start-registry, stop-registry, delete-registry (explicit tenant/ID and record CAS; put/start require manage-registry and manage-volumes on the selected node). Stop/delete retain Volume data; a desired definition does not mean a live TLS server.")
	fmt.Fprintln(out, "External registry metadata: put-external-registry, delete-external-registry (tenant manage-registry; Vault key references only, immutable authority/repository and record CAS). registry external-list/external-show read public references. App registry Secret use requires the original Group approval/Binding. External CA/credential is scoped to the OCI client, not daemon-wide trust. RQ6 native acceptance is pending; unavailable credentials never fall back to anonymous.")
	fmt.Fprintln(out, `Change file: {"schema":1,"action":"create-tenant","expected":0,"payload":{"ID":"example"}}`)
	fmt.Fprintln(out, "Actions: put-user, issue-initial-credential (owner fact only), add-credential, disable-credential, clear-app-logs, set-node-cli-policy, create-tenant, set-nodes, set-membership, set-trust, revoke-session, invite-node, promote-node, set-node-quota, reserve-task, drain-reservation, release-reservation, create-network, create-tun-network, drain-network, retire-network, create-volume, acquire-volume, release-volume, begin-volume-backup, cancel-volume-backup, delete-volume-backup, begin-volume-restore, cancel-volume-restore, begin-app-upload, put-app-part, abort-app-upload, begin-app, down-app, rotate-app-history, rotate-ledger")
	fmt.Fprintln(out, "Vault changes moved to mydc secret (mydc secret --help).")
	fmt.Fprintln(out, "Requires auth: user. An existing request ID only queries its original result. Explicit resume submits that unchanged original. Prune removes only confirmed intents older than the current quorum ledger epoch; unknown intents are retained.")
}

func managementChange(path, principal string) (control.Change, error) {
	f, err := os.Open(path)
	if err != nil {
		return control.Change{}, errors.New("cannot open management metadata file")
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return control.Change{}, schema.ErrInput
	}
	raw, err := io.ReadAll(io.LimitReader(f, (48<<10)+1))
	defer clear(raw)
	if err != nil {
		return control.Change{}, schema.ErrInput
	}
	return control.InputChange(raw, principal)
}

func runManagement(ctx context.Context, args []string, client userauth.Client, target mydcp.Peer, session access.Session, home string, out, diagnostic io.Writer) int {
	return runManagementTarget(ctx, args, client, target, session, home, "", out, diagnostic)
}

func runManagementTarget(ctx context.Context, args []string, client userauth.Client, target mydcp.Peer, session access.Session, home, selectedTenant string, out, diagnostic io.Writer) int {
	if len(args) == 0 {
		return failure(diagnostic, errors.New("manage requires resources, apply, result, resume or prune"), 2)
	}
	method := args[0]
	if method == "tenant-storage" {
		return runTenantStorageQuery(ctx, args[1:], client, target, session, selectedTenant, out, diagnostic)
	}
	if control.PublicReadMethod(method) && method != "network-users" && method != "network-closure" && method != "route-endpoints" {
		return runPublicRead(ctx, args, client, target, session, selectedTenant, out, diagnostic)
	}
	if method == "app-source" || method == "app-revisions" {
		return runAppSourceQuery(ctx, method, args[1:], client, target, session, selectedTenant, out, diagnostic)
	}
	if method == "tasks" {
		return runTaskList(ctx, args[1:], client, target, session, selectedTenant, out, diagnostic)
	}
	if method == "self-credentials" {
		if len(args) != 1 {
			return failure(diagnostic, errors.New("manage self-credentials takes no arguments"), 2)
		}
		reply, err := client.Query(ctx, target, session, "my-credentials", "")
		if err != nil {
			return userFailure(diagnostic, err)
		}
		return userOutput(out, diagnostic, reply)
	}
	if method == "prune" {
		if len(args) != 1 {
			return failure(diagnostic, errors.New("manage prune takes no epoch override or other arguments"), 2)
		}
		view, err := client.Query(ctx, target, session, "whoami", "")
		if err != nil {
			return userFailure(diagnostic, err)
		}
		epoch := view.ModuleEpoch
		if epoch == 0 {
			epoch = 1
		}
		removed := 0
		if epoch > 1 {
			removed, err = userauth.PruneOperations(home, client, session, epoch)
			if errors.Is(err, userauth.ErrOperationMissing) {
				err = nil
			}
			if err != nil {
				return failure(diagnostic, err, 1)
			}
		}
		return userOutput(out, diagnostic, map[string]any{"schema": 1, "status": "pruned", "module_epoch": epoch, "removed": removed})
	}
	if method != "apply" && method != "result" && method != "resume" {
		return failure(diagnostic, errors.New("unsupported management command"), 2)
	}
	flags := flag.NewFlagSet("manage "+method, flag.ContinueOnError)
	flags.SetOutput(diagnostic)
	var id, file onceString
	flags.Var(&id, "request-id", "stable original request ID")
	if method == "apply" {
		flags.Var(&file, "change", "typed metadata JSON file (32KiB; app parts 48KiB)")
	}
	if err := flags.Parse(args[1:]); err != nil || flags.NArg() != 0 || id.value == "" {
		return failure(diagnostic, errors.New("manage requires the original --request-id and valid options"), 2)
	}
	record, err := userauth.LoadOperation(home, client, session, id.value)
	fresh := errors.Is(err, userauth.ErrOperationMissing)
	if fresh && method == "apply" {
		if file.value == "" {
			return failure(diagnostic, errors.New("first apply requires --change FILE"), 2)
		}
		change, err := managementChange(file.value, session.User)
		if err != nil {
			return failure(diagnostic, err, 2)
		}
		if strings.HasPrefix(change.Action, "vault-") || change.Action == "set-volume-capacity" || change.Action == "set-volume-backup-limit" {
			return failure(diagnostic, errors.New("this change moved: use mydc secret, mydc volume resize or mydc volume backup limits set"), 2)
		}
		if err := checkManagementTenant(selectedTenant, change); err != nil {
			return failure(diagnostic, err, 2)
		}
		op, err := client.Prepare(ctx, target, session, id.value, change)
		if err != nil {
			return userFailure(diagnostic, err)
		}
		if op.SelfLogout() {
			return failure(diagnostic, errors.New("use logout for the current session's revocation"), 2)
		}
		record, err = userauth.StageOperation(home, client, op)
		if err != nil {
			return failure(diagnostic, err, 1)
		}
	} else if err != nil {
		return failure(diagnostic, err, 1)
	}
	return runManagementRecord(ctx, method, fresh, client, target, session, home, selectedTenant, record, out, diagnostic)
}

// runManagementRecord submits/renders the same retained operation for generic
// manage and typed CLI callers. It never creates another original.
func runManagementRecord(ctx context.Context, method string, fresh bool, client userauth.Client, target mydcp.Peer, session access.Session, home, selectedTenant string, record userauth.OperationRecord, out, diagnostic io.Writer) int {
	if method != "apply" && method != "result" && method != "resume" {
		return failure(diagnostic, errors.New("invalid original management method"), 2)
	}
	op := record.Operation
	if err := checkManagementTenant(selectedTenant, op.Change); err != nil {
		return failure(diagnostic, err, 2)
	}
	var reply userauth.Reply
	var err error
	if method == "resume" {
		reply, err = client.Resume(ctx, target, session, op)
	} else if fresh {
		reply, err = client.Operation(ctx, target, op, false)
	} else {
		reply, err = client.Result(ctx, target, session, op)
	}
	output := map[string]any{"schema": 1, "request": op.RequestID, "action": op.Change.Action, "epoch": op.Epoch, "root_revision": op.RootRevision, "local_intent_preserved": true}
	if control.UploadCASAllowed(op.Change.Action) {
		output["cas"] = "upload"
		output["expected_revision"] = op.Change.Expected
	}
	if control.AppDownCASAllowed(op.Change) {
		output["cas"] = "app-down"
		output["expected_revision"] = op.Change.Expected
	}
	if control.AppFieldCASAllowed(op.Change) {
		output["cas"] = "app-field"
		output["expected_revision"] = op.Change.Expected
	}
	if control.StandaloneCASAllowed(op.Change) {
		output["cas"] = "standalone-target"
		output["expected_revision"] = op.Change.Expected
	}
	if control.AppLogClearCASAllowed(op.Change) {
		output["cas"] = "app-log-clear-target"
	}
	if control.AppBeginCASAllowed(op.Change) {
		output["cas"] = "app-begin-target"
		output["expected_revision"] = op.Change.Expected
	}
	if control.AppCDTargetCASAllowed(op.Change) {
		output["cas"] = "app-sync-target"
		if op.Change.Action == "configure-app-cd" {
			output["cas"] = "app-configure-target"
		}
		output["expected_revision"] = op.Change.Expected
	}
	if err != nil || !reply.Found || reply.Result == nil {
		output["status"] = "unknown"
		// Keep the original intent Unknown, but do not discard why its current
		// result lookup failed. Codes contain no request or credential bytes.
		var requestError *userauth.Error
		if errors.As(err, &requestError) {
			output["error_code"] = requestError.Code
		}
		if code := userOutput(out, diagnostic, output); code != 0 {
			return code
		}
		return failure(diagnostic, errors.New("management outcome unconfirmed; result queries the original and explicit resume submits it unchanged"), 4)
	}
	if err = userauth.RecordOperationResult(home, client, session, op, *reply.Result); err != nil {
		return failure(diagnostic, err, 1)
	}
	output["result"] = reply.Result
	standaloneExtensionOutput(output, op, reply.Result)
	code := 0
	output["status"] = "applied"
	if reply.Result.Code != state.Applied {
		output["status"], code = "rejected", 3
	} else if control.CommandKey(op.Change.Action) == control.LifecycleKey {
		checkerAppliedIdentity(output, op)
	}
	if userOutput(out, diagnostic, output) != 0 {
		return 1
	}
	return code
}

// This is a CLI target consistency check on already normalized typed metadata,
// not authorization. System-scoped actions keep their own explicit targets;
// the daemon always checks current ACL, original ownership, CAS and quorum.
func checkManagementTenant(selected string, change control.Change) error {
	if selected == "" {
		return nil
	}
	if change.Action == "standalone-extend" {
		// Scope is this action's internal workload name, not a nested tenant
		// scope. Target is a digest; neither is a destination to reinterpret.
		var q control.StandaloneExtendChange
		if json.Unmarshal(change.Payload, &q) != nil {
			return schema.ErrInput
		}
		_, err := (cliprofile.Selection{Tenant: selected}).CheckTenant(q.Tenant, "", false)
		return err
	}
	type scope struct{ Tenant string }
	var target struct {
		Tenant, Realm string
		Scope         scope
		Spec          struct {
			Scope  scope
			Tenant string
		}
		Target      json.RawMessage
		Backup      struct{ Scope scope }
		Selection   struct{ Scope scope }
		Observation struct{ Tenant string }
	}
	if json.Unmarshal(change.Payload, &target) != nil {
		return schema.ErrInput
	}
	var destination struct {
		Scope  scope
		Tenant string
	}
	if raw := bytes.TrimSpace(target.Target); len(raw) > 0 && !bytes.Equal(raw, []byte("null")) {
		switch change.Action {
		case "configure-app-cd", "sync-app", "recover-app", "down-app", "override-app", "release-app-override":
			// These actions sign an intent digest, not a destination scope.
			// Keep the typed shape exact; the daemon validates its authority.
			var digest []byte
			if raw[0] != '[' || json.Unmarshal(raw, &digest) != nil || len(digest) != 32 {
				return schema.ErrInput
			}
		default:
			if json.Unmarshal(raw, &destination) != nil {
				return schema.ErrInput
			}
		}
	}
	selection := cliprofile.Selection{Tenant: selected}
	for _, tenant := range []string{target.Tenant, target.Realm, target.Scope.Tenant, target.Spec.Scope.Tenant, target.Spec.Tenant, destination.Scope.Tenant, destination.Tenant, target.Backup.Scope.Tenant, target.Selection.Scope.Tenant, target.Observation.Tenant} {
		if _, err := selection.CheckTenant(tenant, "", false); err != nil {
			return err
		}
	}
	return nil
}
