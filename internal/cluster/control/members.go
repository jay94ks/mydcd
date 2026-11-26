// SPDX-License-Identifier: Apache-2.0

package control

import (
	"strings"
	"unicode/utf8"

	"encoding/json"
	"github.com/jay94ks/mydcd/internal/cluster/lifecycle"
	"github.com/jay94ks/mydcd/internal/cluster/membership"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/config"
	"github.com/jay94ks/mydcd/internal/identity"
)

const MembersKey = "control/members"

type NodeInvitation struct {
	Peer   config.Peer
	JoinID string
}
type NodeSelection struct{ ID string }

// NodeCordonChange is cordon-node's payload. Reason is the operator's note
// (optional, at most 256 characters, one line). It lives only in the signed
// original and is projected on the node's scheduling view; uncordon-node
// keeps NodeSelection.
type NodeCordonChange struct {
	ID     string
	Reason string `json:",omitempty"`
}

func (c NodeCordonChange) Valid() bool {
	return lifecycle.ValidID(c.ID) && utf8.ValidString(c.Reason) && utf8.RuneCountInString(c.Reason) <= 256 && !strings.ContainsAny(c.Reason, "\x00\r\n")
}

// cordonTarget decodes a cordon-node (NodeCordonChange) or uncordon-node
// (NodeSelection) payload.
func cordonTarget(action string, payload []byte) (NodeCordonChange, error) {
	if action == "cordon-node" {
		var q NodeCordonChange
		if canonical(payload, &q) != nil || !q.Valid() {
			return NodeCordonChange{}, ErrCatalog
		}
		return q, nil
	}
	var q NodeSelection
	if canonical(payload, &q) != nil {
		return NodeCordonChange{}, ErrCatalog
	}
	return NodeCordonChange{ID: q.ID}, nil
}

type NodeLifecycleChange struct {
	ID, Operation string
	Epoch         uint64
}
type NodeOperationWindow struct{ Epoch uint64 }

// CommandKey separates the CAS/receipt namespace without changing any existing
// signed operation's JSON shape or catalog root semantics.
func CommandKey(action string) string {
	switch action {
	case "set-node-shell-policy", "set-node-shell-node", "set-node-shell-grant", "open-node-shell", "close-node-shell":
		return NodeShellKey
	case "put-certificate", "delete-certificate", "disable-certificate", "add-domain", "remove-domain", "set-acme-responder":
		return CertificatesKey
	case "set-node-gateways", "set-ingress-balance", "drain-ingress", "undrain-ingress", "set-ingress-host-policy", "ingress-block", "ingress-unblock", "ingress-block-extend":
		return IngressManagementKey
	case ImageBuildCachePruneAction:
		return ImageBuildKey
	case "begin-image-build", "cancel-image-build", "delete-image-build-job":
		return ImageBuildKey
	case "delete-build-version":
		return ImageBuildKey
	case "set-image-build-policy", "delete-image-build-policy", "put-build-context", "delete-build-context", "begin-build-zip-upload", "put-build-zip-part", "abort-build-zip-upload", "upload-build-zip", "publish-build-draft", "publish-build-git":
		return ImageBuildKey
	case "delete-registry-image", "gc-registry", RegistryPruneAction:
		return RegistryMaintenanceKey
	case "put-external-registry", "delete-external-registry", "bind-external-registry", "unbind-external-registry":
		return ExternalRegistriesKey
	case "prune-node-images":
		return ImageCacheKey
	case "reconnect-tunnel":
		return TunnelReconnectKey
	case "raft-compact":
		return CompactKey
	case "override-app", "release-app-override":
		return AppsKey
	case "put-registry", "start-registry", "stop-registry", "delete-registry":
		return RegistriesKey
	case "set-lifecycle-policy", "put-lifecycle-script", "retire-lifecycle-script", "delete-lifecycle-script":
		return LifecycleKey
	case "add-node-storage", "set-node-storage-policy", "drain-node-storage", "remove-node-storage":
		return NodeStorageKey
	case "vault-init", "vault-create", "vault-acl", "vault-reorder", "vault-move", "vault-approval-age", "vault-set-profile", "vault-prepare-write", "vault-dispatch-write", "vault-observe-write", "vault-publish-write", "vault-abandon-write", "vault-rotate-writes", "vault-revoke", "vault-retire", "vault-set-issuer", "vault-commit-approval", "vault-revoke-approval":
		return VaultKey
	case "standalone-extend", "standalone-stop", "standalone-start", "standalone-restart", "standalone-up", "standalone-pin", "standalone-remove", "put-app-local-services", "clear-app-local-services", "cd-approve", "cd-reject", "grant-cd-approver", "revoke-cd-approver", "restart-task", "clear-app-logs", "standalone-clear-logs", "begin-app-upload", "put-app-part", "abort-app-upload", "begin-app", "down-app", "resume-app-retirement", "rotate-app-history", "sync-app", "recover-app", "replan-app", "configure-app-cd", "pause-app-cd", "resume-app-cd", "abandon-app-sync":
		return AppsKey
	case "volume-file-put", "volume-file-list", "volume-file-get", "volume-file-delete", "begin-volume-move", "cancel-volume-move", "commit-volume-move", "begin-volume-create", "register-fixed-volume", "cancel-volume-create", "unregister-fixed-volume", "delete-volume", "delete-retained-volume", "create-volume", "acquire-volume", "release-volume", "set-volume-capacity", "set-volume-backup-limit", "begin-volume-backup", "cancel-volume-backup", "delete-volume-backup", "begin-volume-restore", "cancel-volume-restore":
		return VolumesKey
	case "rotate-ledger":
		return StorageKey
	case "rotate-node-identity", "drain-node", "cordon-node", "uncordon-node", "invite-node", "promote-node", "demote-node", "isolate-node", "restore-node", "remove-node", "force-remove-node", "resume-node-operation", "rotate-node-operations":
		return MembersKey
	case "set-node-quota", "reserve-task", "drain-reservation", "release-reservation", "create-tun-network", "join-tun-network", "leave-tun-network", "set-network-toggle", "set-system-network-range", "configure-network-dns", "plan-network-change", "cancel-network-change", "fence-network-change", "commit-network-change", "reconfigure-tun-network", "propose-route", "approve-route", "withdraw-route", "drain-network":
		return ResourcesKey
	default:
		return CatalogKey
	}
}
func (p Policy) Members(s state.State) (membership.Directory, error) {
	key, err := identity.ParseKey(p.Genesis.Key)
	if err != nil || key != p.TrustRoot {
		return membership.Directory{}, ErrCatalog
	}
	raw, revision, err := readCheckpoint(s, MembersKey, p.Cluster, p.TrustRoot)
	if err != nil {
		return membership.Directory{}, err
	}
	if raw == nil {
		return membership.New(p.Cluster, p.Genesis)
	}
	d, err := membership.Decode(raw)
	if err != nil || d.Revision != revision || d.Cluster != p.Cluster || d.Genesis != p.Genesis {
		return membership.Directory{}, ErrCatalog
	}
	if err := p.validateNodeOrigins(d); err != nil {
		return membership.Directory{}, err
	}
	return d, nil
}

// Current derives new session authority from active installed voters. Installed
// replication/provider membership and committed original grant verification
// are separate boundaries. Legacy static policies retain their pinned issuers.
func (p Policy) Current(s state.State) (Policy, error) {
	d, err := p.Members(s)
	if err != nil {
		return p, err
	}
	p.Issuers = d.SessionIssuers()
	return p, nil
}

// acceptedIssuer is only for records already retained by a committed operation.
// Historical membership is not permission to issue a new login/request, and a
// caller-supplied old timestamp cannot turn a new command into such a record.
func (p Policy) acceptedIssuer(s state.State, key [32]byte) bool {
	d, err := p.Members(s)
	return err == nil && d.HistoricalMemberKey(key)
}
func (p Policy) reduceMembers(s state.State, cmd state.Command) (map[string][]byte, state.Code) {
	current, err := p.Current(s)
	if err != nil {
		return nil, state.Invalid
	}
	p = current
	d, err := p.Members(s)
	if err != nil {
		return nil, state.Invalid
	}
	if strings.HasPrefix(cmd.Actor, "node/") {
		return p.reduceMemberReport(s, d, cmd)
	}
	if !strings.HasPrefix(cmd.Actor, "user/") {
		return nil, state.Forbidden
	}
	c, err := p.Catalog(s)
	if err != nil {
		return nil, state.Invalid
	}
	op, err := p.Operation(c, cmd, false)
	if err != nil || p.authorizeChange(s, c, op) != nil {
		return nil, state.Forbidden
	}
	switch op.Change.Action {
	case "rotate-node-identity":
		var q NodeIdentityChange
		if canonical(op.Change.Payload, &q) != nil {
			return nil, state.Invalid
		}
		origin, _ := json.Marshal(op)
		d, err = d.BeginIdentityRotation(q.ID, q.Operation, op.Change.Expected, s.Index()+1, origin)
	case "drain-node":
		return p.beginNodeDrain(s, op, cmd)
	case "invite-node":
		var target NodeInvitation
		if op.Change.Expected != 0 || canonical(op.Change.Payload, &target) != nil {
			return nil, state.Invalid
		}
		d, err = d.Invite(target.Peer, target.JoinID)
	case "cordon-node", "uncordon-node":
		target, targetErr := cordonTarget(op.Change.Action, op.Change.Payload)
		if targetErr != nil {
			return nil, state.Invalid
		}
		origin, _ := json.Marshal(op)
		d, err = d.SetCordon(target.ID, op.Change.Expected, op.Change.Action == "cordon-node", origin)
	case "promote-node", "demote-node":
		var target NodeSelection
		if canonical(op.Change.Payload, &target) != nil {
			return nil, state.Invalid
		}
		origin, _ := json.Marshal(op)
		if op.Change.Action == "demote-node" {
			plan, planErr := p.nodeVotingPlan(s, target.ID)
			if planErr != nil {
				return nil, state.Invalid
			}
			if plan.Expected != op.Change.Expected {
				return nil, state.ConditionFailed
			}
			if code := plan.Rejection(); code != state.Applied {
				return nil, code
			}
			d, err = d.ChangeVote(target.ID, op.Change.Expected, false, origin)
		} else if entry, found := d.Entry(target.ID); found && entry.Voting != nil {
			d, err = d.ChangeVote(target.ID, op.Change.Expected, true, origin)
		} else {
			d, err = d.Promote(target.ID, op.Change.Expected)
		}
	case "force-remove-node":
		var target NodeForceChange
		if canonical(op.Change.Payload, &target) != nil {
			return nil, state.Invalid
		}
		if code := p.CheckNodeForceProbe(s, target, op.Change.Expected, op.At); code != state.Applied {
			return nil, code
		}
		origin, _ := json.Marshal(op)
		d, err = d.BeginForceRemoval(target.ID, target.Operation, op.Change.Expected, target.Epoch, origin, target.Probe)
	case "isolate-node", "restore-node", "remove-node", "resume-node-operation":
		var target NodeLifecycleChange
		if canonical(op.Change.Payload, &target) != nil {
			return nil, state.Invalid
		}
		origin, _ := json.Marshal(op)
		if op.Change.Action == "resume-node-operation" {
			d, err = d.ResumeNode(target.ID, target.Operation, op.Change.Expected, target.Epoch, origin)
		} else {
			if op.Change.Action == "remove-node" {
				plan, planErr := p.nodeRemovalPlan(s, target.ID)
				if planErr != nil {
					return nil, state.Invalid
				}
				if plan.Expected != op.Change.Expected || plan.Epoch != target.Epoch {
					return nil, state.ConditionFailed
				}
				if code := plan.Rejection(); code != state.Applied {
					return nil, code
				}
			}
			action := map[string]lifecycle.Action{"isolate-node": lifecycle.Isolate, "restore-node": lifecycle.Restore, "remove-node": lifecycle.Remove}[op.Change.Action]
			d, err = d.BeginNode(target.ID, target.Operation, action, op.Change.Expected, target.Epoch, origin)
		}
	case "rotate-node-operations":
		var window NodeOperationWindow
		if canonical(op.Change.Payload, &window) != nil {
			return nil, state.Invalid
		}
		d, err = d.RotateNodeOperations(op.Change.Expected, window.Epoch)
	default:
		return nil, state.Invalid
	}
	if err != nil {
		return nil, state.ConditionFailed
	}
	return p.memberCheckpoint(s, d)
}
func (p Policy) memberCheckpoint(s state.State, d membership.Directory) (map[string][]byte, state.Code) {
	raw, err := d.Encode()
	if err != nil {
		return nil, state.Invalid
	}
	return writeCheckpoint(s, MembersKey, p.Cluster, p.TrustRoot, d.Revision, raw)
}
