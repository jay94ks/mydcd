// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/cluster/membership"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/network/services"
	"github.com/jay94ks/mydcd/internal/schema"
)

// nodeRequestAllowed filters the USER ingress/relay role, not Raft voting or
// the user's authority. Every permitted request still passes the existing
// session/challenge/current-role/CAS checks. An isolated consensus leader may
// serve a request attested by an active ingress; its own ingress is recovery.
func (s Service) nodeRequestAllowed(view state.State, catalog access.Catalog, request Request, envelope Envelope) bool {
	members, err := s.Policy.Members(view)
	if err != nil {
		return false
	}
	knownOriginal := false
	if request.Operation != nil {
		if command, err := request.Operation.Command(); err == nil {
			_, knownOriginal = view.LookupResult(command)
		}
	} else if request.Method == "vault-approval-plan" && request.VaultPlan != nil {
		knownOriginal = acceptedNodeApproval(view, request.VaultPlan.Origin, request.VaultPlan.Selection)
	} else if request.Method == "vault-write-plan" && request.VaultWritePlan != nil {
		if vault, err := s.Policy.Vault(view); err == nil {
			if tree, found := vault.Trees[request.VaultWritePlan.Realm]; found {
				_, knownOriginal = tree.Write(request.VaultWritePlan.ID)
			}
		}
	}
	return nodeIngressAllowed(s.Self.Public, members, catalog, request, envelope, knownOriginal)
}

func nodeIngressAllowed(self [32]byte, members membership.Directory, catalog access.Catalog, request Request, envelope Envelope, knownOriginal bool) bool {
	if !members.MemberKey(self) {
		return false
	}
	switch request.Method {
	case "challenge", "credential-challenge", "login", "credential-login":
		return nodeSessionIssuer(self, members)
	}
	if envelope.Relay != nil {
		if !members.MemberKey(envelope.Relay.Node) {
			return false
		}
		if members.WorkKey(envelope.Relay.Node) {
			return true
		}
	} else if members.WorkKey(self) {
		return true
	}
	if control.PublicReadMethod(request.Method) {
		return true
	}
	switch request.Method {
	case "node-shell-policy", "node-shell-sessions", "node-drain-plan", "node-drain-status", "node-diagnostics", "node-force-remove-plan", "node-demote-plan", "node-remove-plan", "lifecycle-source", "lifecycle-source-recover", "lifecycle-module-recover", "standalone-list", "standalone-get", "volume-file-plan", "volume-file-status", "ingresses", "certificates", "tenant-storage", "image-build-cache", "image-build-logs", "build-context-content", "check-build-context", "image-builds", "events", "app-cd-toggle-plan", "registry-action-plan", "external-registries", "external-registry-bind-plan", "registry-login-test", "image-resolve", "image-content", "image-usages", "registry-maintenance-plan", "registry-maintenance-status", "registry-catalog", "registry-prune-preview", "registry-prune-results", "external-registry-pulls", "raft-status", "node-summary", "node-disks", "node-tenant-usage", "mesh-links", "app-source", "app-revisions", "tasks", "my-credentials", "users", "tenant-members", "container-exec-status", "app-log-clear-plan", "app-log-clear-status", "user-credentials", "node-cli-policy", "container-observe", "tenant-retirement", "whoami", "tenants", "select-tenant", "members", "node-storage", "node-storage-space", "resources", "volumes", "volume-restores", "volume-backups", "volume-usage", "volume-backup-source", "apps", "app-operation", "app-cd-field", "app-cd-history", "app-cd-diff", "app-cd-registration", "app-uploads", "vault", "lifecycles", "registries", "result", "checker-source-recover", "checker-module-recover":
		return true
	case "vault-write-plan", "vault-approval-plan":
		// Locating an original write/accepted approval must remain possible
		// before its sensitive recover call. Fresh planning is not recovery.
		return knownOriginal
	case "submit", "resume":
		if request.Operation == nil {
			return false
		}
		// Existing immutable receipts remain queryable through the normal
		// operation path. This does not grant replay of a missing new workflow.
		if knownOriginal {
			return true
		}
		switch request.Operation.Change.Action {
		case "close-node-shell", "begin-tenant-retirement", "finish-tenant-retirement", "drain-node", "demote-node", "isolate-node", "restore-node", "remove-node", "force-remove-node", "resume-node-operation", "rotate-node-operations",
			"down-app", "resume-app-retirement", "pause-app-cd", "abandon-app-sync", "rotate-app-history",
			"drain-network", "retire-network", "leave-tun-network", "fence-network-change", "cancel-network-change", "withdraw-route", "drain-reservation", "release-reservation",
			"cancel-volume-create", "unregister-fixed-volume", "delete-volume", "delete-retained-volume", "cancel-volume-backup", "delete-volume-backup", "cancel-volume-restore", "cancel-volume-move", "release-volume",
			"cancel-image-build", "delete-image-build-job", "delete-build-version", "abort-build-zip-upload", "delete-build-context", "delete-image-build-policy", "stop-registry", "delete-registry", "drain-node-storage", "remove-node-storage",
			"vault-observe-write", "vault-publish-write", "vault-abandon-write", "vault-revoke", "vault-retire", "vault-revoke-approval", "vault-rotate-writes",
			"retire-lifecycle-script", "delete-lifecycle-script", "disable-credential", "revoke-session", "rotate-ledger":
			return true
		case "begin-volume-move", "commit-volume-move":
			// Explicit evacuation uses the same signed move, owner fence and
			// active target checks; it grants no general deployment admission.
			return true
		case "reconfigure-tun-network":
			// Empty membership is an explicit final retirement. The shared
			// reducer still requires every original member's fenced closure.
			change, err := schema.Decode[control.NetworkReconfigure](request.Operation.Change.Payload)
			return err == nil && len(change.Target.Members) == 0
		case "configure-network-dns":
			change, err := schema.Decode[services.ManagedDNSDefinition](request.Operation.Change.Payload)
			return err == nil && !change.Policy.Enabled
		}
	}
	return false
}

func (s Service) nodeLoginAllowed(view state.State, catalog access.Catalog, user string) bool {
	members, err := s.Policy.Members(view)
	return err == nil && nodeLoginKeyAllowed(s.Self.Public, members, catalog, user)
}

func nodeLoginKeyAllowed(self [32]byte, members membership.Directory, _ access.Catalog, _ string) bool {
	return nodeSessionIssuer(self, members)
}

func nodeSessionIssuer(self [32]byte, members membership.Directory) bool {
	for _, key := range members.SessionIssuers() {
		if key == self {
			return true
		}
	}
	return false
}

func (s Service) nodeSecretAllowed(view state.State, request SecretRequest) bool {
	members, err := s.Policy.Members(view)
	if err != nil || !members.MemberKey(s.Self.Public) {
		return false
	}
	if request.Mode == "certificate" {
		return members.WorkKey(s.Self.Public) || request.Certificate != nil && request.Certificate.Recover
	}
	if members.WorkKey(s.Self.Public) || request.Mode == "recover" {
		return true
	}
	return request.Mode == "approve" && acceptedNodeApproval(view, request.Origin, request.Selection)
}

func acceptedNodeApproval(view state.State, origin *control.UserOperation, selection *control.AppApprovalSelection) bool {
	if origin == nil {
		return false
	}
	command, err := origin.Command()
	if err != nil {
		return false
	}
	acceptedMove := origin.Change.Action == "begin-volume-move" && command.Key == control.VolumesKey && selection == nil
	acceptedSync := origin.Change.Action == "begin-app" && command.Key == control.AppsKey && selection != nil && selection.Valid() && selection.Operation != ""
	if !acceptedMove && !acceptedSync {
		return false
	}
	result, found := view.LookupResult(command)
	// This is only local ingress admission. VaultApprovalPermit still
	// joins the exact accepted operation, current target and current grants.
	return found && result.Code == state.Applied
}
