// SPDX-License-Identifier: Apache-2.0

package control

import (
	"encoding/json"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/credentials"
	"github.com/jay94ks/mydcd/internal/imagebuild"
	"github.com/jay94ks/mydcd/internal/imagecache"
	"github.com/jay94ks/mydcd/internal/nodestorage"
	"github.com/jay94ks/mydcd/internal/schema"
	"github.com/jay94ks/mydcd/internal/tenancy"
	checker "github.com/jay94ks/mydcd/internal/workload/lifecycle"
	"github.com/jay94ks/mydcd/internal/workload/volumes"
)

// ChangeDocument is a local metadata file, not a signed operation or an app.
// Principal and outer root CAS come only from the current authenticated client.
type ChangeDocument struct {
	Schema   uint8           `json:"schema"`
	Action   string          `json:"action"`
	Expected uint64          `json:"expected"`
	Payload  json.RawMessage `json:"payload"`
}

func normalizedPayload[T any](raw []byte) (json.RawMessage, error) {
	v, err := schema.Input[T](raw)
	if err != nil {
		return nil, err
	}
	b, err := json.Marshal(v)
	return b, err
}

func InputChange(raw []byte, principal string) (Change, error) {
	d, err := schema.InputLimit[ChangeDocument](raw, 48<<10)
	if err != nil || d.Schema != 1 || principal == "" || len(raw) > 32<<10 && d.Action != "put-app-part" {
		return Change{}, schema.ErrInput
	}
	if !explicitFields(d.Action, d.Payload) {
		return Change{}, schema.ErrInput
	}
	var payload json.RawMessage
	switch d.Action {
	case "set-node-shell-policy":
		payload, err = normalizedPayload[NodeShellPolicyChange](d.Payload)
	case "set-node-shell-node":
		payload, err = normalizedPayload[NodeShellNodeChange](d.Payload)
	case "set-node-shell-grant":
		payload, err = normalizedPayload[NodeShellGrantChange](d.Payload)
	case "open-node-shell":
		payload, err = normalizedPayload[NodeShellOpen](d.Payload)
	case "close-node-shell":
		payload, err = normalizedPayload[NodeShellClose](d.Payload)
	case ImageBuildCachePruneAction:
		payload, err = normalizedPayload[ImageBuildCachePruneChange](d.Payload)
	case "begin-image-build":
		payload, err = normalizedPayload[ImageBuildJobStart](d.Payload)
	case "cancel-image-build", "delete-image-build-job":
		payload, err = normalizedPayload[ImageBuildJobSelection](d.Payload)
	case "delete-build-version":
		payload, err = normalizedPayload[ImageBuildVersionSelection](d.Payload)
	case "set-image-build-policy":
		payload, err = normalizedPayload[ImageBuildPolicyPut](d.Payload)
	case "put-build-context":
		var q ImageBuildContextPut
		q, err = schema.Input[ImageBuildContextPut](d.Payload)
		if err == nil && q.Spec.Validate() == nil {
			payload, err = json.Marshal(q)
		} else {
			err = imagebuild.ErrInvalid
		}
	case "delete-image-build-policy", "delete-build-context":
		payload, err = normalizedPayload[ImageBuildSelection](d.Payload)
	case "begin-build-zip-upload":
		payload, err = normalizedPayload[ImageBuildUploadBegin](d.Payload)
	case "put-build-zip-part":
		payload, err = normalizedPayload[ImageBuildUploadPart](d.Payload)
	case "abort-build-zip-upload":
		payload, err = normalizedPayload[ImageBuildUploadSelection](d.Payload)
	case "publish-build-draft":
		payload, err = normalizedPayload[ImageBuildDraftPublish](d.Payload)
	case "publish-build-git":
		payload, err = normalizedPayload[ImageBuildGitPublish](d.Payload)
	case "upload-build-zip":
		payload, err = normalizedPayload[ImageBuildZIPConsume](d.Payload)
	case "delete-registry-image", "gc-registry", RegistryPruneAction:
		payload, err = normalizedPayload[RegistryMaintenanceChange](d.Payload)
	case "put-external-registry":
		payload, err = normalizedPayload[ExternalRegistryPut](d.Payload)
	case "bind-external-registry":
		payload, err = normalizedPayload[ExternalRegistryBind](d.Payload)
	case "delete-external-registry", "unbind-external-registry":
		payload, err = normalizedPayload[RegistrySelection](d.Payload)
	case "put-registry":
		payload, err = normalizedPayload[RegistryPut](d.Payload)
	case "start-registry", "stop-registry", "delete-registry":
		payload, err = normalizedPayload[RegistrySelection](d.Payload)
	case "set-lifecycle-policy":
		payload, err = normalizedPayload[checker.TenantPolicy](d.Payload)
	case "put-lifecycle-script":
		payload, err = normalizedPayload[LifecycleScriptPut](d.Payload)
	case "retire-lifecycle-script", "delete-lifecycle-script":
		payload, err = normalizedPayload[LifecycleScriptSelection](d.Payload)
	case "add-node-storage":
		payload, err = normalizedPayload[nodestorage.Definition](d.Payload)
	case "set-node-storage-policy":
		payload, err = normalizedPayload[NodeStoragePolicy](d.Payload)
	case "drain-node-storage", "remove-node-storage":
		payload, err = normalizedPayload[NodeStorageSelection](d.Payload)
	case "vault-init":
		payload, err = normalizedPayload[VaultRealm](d.Payload)
	case "vault-create":
		payload, err = normalizedPayload[VaultObject](d.Payload)
	case "vault-acl":
		payload, err = normalizedPayload[VaultACL](d.Payload)
	case "vault-reorder":
		payload, err = normalizedPayload[VaultOrder](d.Payload)
	case "vault-move":
		payload, err = normalizedPayload[VaultMove](d.Payload)
	case "vault-approval-age":
		payload, err = normalizedPayload[VaultAge](d.Payload)
	case "vault-set-profile":
		payload, err = normalizedPayload[VaultProfile](d.Payload)
	case "vault-prepare-write":
		payload, err = normalizedPayload[VaultWrite](d.Payload)
	case "vault-dispatch-write", "vault-publish-write", "vault-abandon-write", "vault-rotate-writes":
		payload, err = normalizedPayload[VaultWriteAction](d.Payload)
	case "vault-observe-write":
		payload, err = normalizedPayload[VaultObserve](d.Payload)
	case "vault-revoke", "vault-retire":
		payload, err = normalizedPayload[VaultSelection](d.Payload)
	case "vault-set-issuer":
		payload, err = normalizedPayload[VaultIssuer](d.Payload)
	case "vault-commit-approval":
		payload, err = normalizedPayload[VaultApproval](d.Payload)
	case "vault-revoke-approval":
		payload, err = normalizedPayload[VaultApprovalSelection](d.Payload)
	case "begin-app-upload":
		payload, err = normalizedPayload[AppUploadBegin](d.Payload)
	case "put-app-part":
		var v AppUploadPart
		v, err = schema.InputLimit[AppUploadPart](d.Payload, 48<<10)
		if err == nil && len(v.Data) <= 24<<10 {
			payload, err = json.Marshal(v)
		} else {
			err = schema.ErrInput
		}
	case "abort-app-upload":
		payload, err = normalizedPayload[AppUploadSelection](d.Payload)
	case "standalone-extend":
		payload, err = normalizedPayload[StandaloneExtendChange](d.Payload)
	case "standalone-pin", "standalone-remove":
		payload, err = normalizedPayload[StandaloneChange](d.Payload)
	case "volume-file-put", "volume-file-list", "volume-file-get", "volume-file-delete":
		payload, err = normalizedPayload[VolumeFileChange](d.Payload)
	case "begin-app", "standalone-up":
		payload, err = normalizedPayload[AppBegin](d.Payload)
	case "override-app", "release-app-override":
		payload, err = normalizedPayload[AppOverrideChange](d.Payload)
	case "put-app-local-services", "clear-app-local-services":
		payload, err = normalizedPayload[AppLocalChange](d.Payload)
	case "sync-app", "recover-app", "replan-app", "configure-app-cd", "pause-app-cd", "resume-app-cd", "abandon-app-sync":
		payload, err = normalizedPayload[AppCDChange](d.Payload)
	case "rotate-app-history":
		payload, err = normalizedPayload[AppHistorySelection](d.Payload)
	case "prune-node-images":
		payload, err = normalizedPayload[imagecache.Change](d.Payload)
	case "reconnect-tunnel":
		payload, err = normalizedPayload[TunnelChange](d.Payload)
	case "raft-compact":
		payload, err = normalizedPayload[CompactChange](d.Payload)
	case "cd-approve", "cd-reject":
		payload, err = normalizedPayload[AppCDDecisionChange](d.Payload)
	case "grant-cd-approver", "revoke-cd-approver":
		payload, err = normalizedPayload[AppCDApproverChange](d.Payload)
	case "standalone-stop", "standalone-start", "standalone-restart", "restart-task":
		payload, err = normalizedPayload[TaskRestartChange](d.Payload)
	case "clear-app-logs", "standalone-clear-logs":
		payload, err = normalizedPayload[AppLogClear](d.Payload)
	case "down-app":
		payload, err = normalizedPayload[AppDown](d.Payload)
	case "resume-app-retirement":
		payload, err = normalizedPayload[AppRetirementReplay](d.Payload)
	case "set-volume-capacity":
		payload, err = normalizedPayload[VolumeCapacity](d.Payload)
	case "begin-volume-move":
		payload, err = normalizedPayload[VolumeMoveBegin](d.Payload)
	case "commit-volume-move":
		payload, err = normalizedPayload[VolumeMoveCommit](d.Payload)
	case "cancel-volume-move":
		payload, err = normalizedPayload[VolumeMoveSelection](d.Payload)
	case "set-volume-backup-limit":
		payload, err = normalizedPayload[VolumeBackupLimit](d.Payload)
	case "begin-volume-restore":
		payload, err = normalizedPayload[VolumeRestoreBegin](d.Payload)
	case "cancel-volume-restore":
		payload, err = normalizedPayload[VolumeRestoreSelection](d.Payload)
	case "begin-volume-backup":
		payload, err = normalizedPayload[VolumeBackupBegin](d.Payload)
	case "cancel-volume-backup", "delete-volume-backup":
		payload, err = normalizedPayload[VolumeBackupSelection](d.Payload)
	case "begin-volume-create":
		payload, err = normalizedPayload[VolumeCreate](d.Payload)
	case "register-fixed-volume":
		payload, err = normalizedPayload[VolumeFixedRegister](d.Payload)
	case "cancel-volume-create":
		payload, err = normalizedPayload[volumes.Scope](d.Payload)
	case "delete-volume", "unregister-fixed-volume":
		payload, err = normalizedPayload[volumes.Scope](d.Payload)
	case "delete-retained-volume":
		payload, err = normalizedPayload[VolumeMoveSelection](d.Payload)
	case "create-volume":
		payload, err = normalizedPayload[volumes.NativeReady](d.Payload)
	case "acquire-volume":
		payload, err = normalizedPayload[VolumeAcquire](d.Payload)
	case "release-volume":
		payload, err = normalizedPayload[volumes.Gone](d.Payload)
	case "add-credential":
		payload, err = normalizedPayload[access.CredentialAddition](d.Payload)
	case "disable-credential":
		payload, err = normalizedPayload[access.CredentialDisable](d.Payload)
	case "volume-file-grant", "volume-file-revoke":
		payload, err = normalizedPayload[access.VolumeFileFolderGrant](d.Payload)
	case "put-user":
		payload, err = normalizedPayload[access.User](d.Payload)
	case "set-account-scope":
		payload, err = normalizedPayload[access.AccountScope](d.Payload)
	case "issue-initial-credential":
		payload, err = normalizedPayload[credentials.InitialFact](d.Payload)
	case "set-node-cli-policy":
		payload, err = normalizedPayload[NodeCLIChange](d.Payload)
	case "create-tenant":
		payload, err = normalizedPayload[TenantID](d.Payload)
	case "begin-tenant-retirement", "finish-tenant-retirement":
		payload, err = normalizedPayload[TenantRetirementSelection](d.Payload)
	case "set-nodes":
		payload, err = normalizedPayload[NodeAssignment](d.Payload)
	case "set-membership":
		payload, err = normalizedPayload[access.Membership](d.Payload)
	case "set-trust":
		payload, err = normalizedPayload[TrustAssignment](d.Payload)
	case "revoke-session":
		payload, err = normalizedPayload[SessionRevocation](d.Payload)
	case "rotate-node-identity":
		payload, err = normalizedPayload[NodeIdentityChange](d.Payload)
	case "drain-node":
		payload, err = normalizedPayload[NodeDrainChange](d.Payload)
	case "invite-node":
		payload, err = normalizedPayload[NodeInvitation](d.Payload)
	case "cordon-node":
		payload, err = normalizedPayload[NodeCordonChange](d.Payload)
	case "uncordon-node", "promote-node", "demote-node":
		payload, err = normalizedPayload[NodeSelection](d.Payload)
	case "force-remove-node":
		payload, err = normalizedPayload[NodeForceChange](d.Payload)
	case "isolate-node", "restore-node", "remove-node", "resume-node-operation":
		payload, err = normalizedPayload[NodeLifecycleChange](d.Payload)
	case "rotate-node-operations":
		payload, err = normalizedPayload[NodeOperationWindow](d.Payload)
	case "set-node-quota":
		payload, err = normalizedPayload[tenancy.NodeLimit](d.Payload)
	case "reserve-task":
		payload, err = normalizedPayload[tenancy.Reservation](d.Payload)
	case "drain-reservation":
		payload, err = normalizedPayload[ReservationSelection](d.Payload)
	case "release-reservation":
		payload, err = normalizedPayload[tenancy.ReservationClosure](d.Payload)
	case "create-tun-network":
		payload, err = normalizedPayload[tenancy.TUNDefinition](d.Payload)
	case "join-tun-network":
		payload, err = normalizedPayload[NetworkJoin](d.Payload)
	case "set-network-toggle":
		payload, err = normalizedPayload[NetworkToggleSet](d.Payload)
	case "set-system-network-range":
		payload, err = normalizedPayload[SystemNetworkRange](d.Payload)
	case "plan-network-change":
		payload, err = normalizedPayload[NetworkChangePlan](d.Payload)
	case "propose-route":
		payload, err = normalizedPayload[RouteProposal](d.Payload)
	case "approve-route", "withdraw-route":
		payload, err = normalizedPayload[RouteSelection](d.Payload)
	case "cancel-network-change":
		payload, err = normalizedPayload[NetworkChangeCancel](d.Payload)
	case "fence-network-change":
		payload, err = normalizedPayload[NetworkChangeFence](d.Payload)
	case "commit-network-change":
		payload, err = normalizedPayload[NetworkChangeCommit](d.Payload)
	case "reconfigure-tun-network":
		payload, err = normalizedPayload[NetworkReconfigure](d.Payload)
	case "configure-network-dns":
		payload, err = managedDNSPayload(d.Payload)
	case "drain-network":
		payload, err = normalizedPayload[NetworkSelection](d.Payload)
	case "leave-tun-network":
		payload, err = normalizedPayload[tenancy.NetworkClosure](d.Payload)
	case "rotate-ledger":
		payload, err = normalizedPayload[LedgerWindow](d.Payload)
	default:
		return Change{}, schema.ErrInput
	}
	if err != nil {
		return Change{}, err
	}
	return Change{Schema: 1, Action: d.Action, Principal: principal, Expected: d.Expected, Payload: payload}, nil
}
