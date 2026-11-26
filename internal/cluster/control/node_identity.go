// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/sha256"
	"encoding/json"
	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/lifecycle"
	"github.com/jay94ks/mydcd/internal/cluster/membership"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/tenancy"
)

type NodeIdentityChange struct{ ID, Operation string }

type NodeIdentityActivation struct {
	Schema uint8
	Index  uint64
	Proof  lifecycle.IdentityProof
}

// ObserveIdentityActivation is original-operation recovery for the replacement
// key holder. It grants no new management operation or old-key authentication.
func (p Policy) ObserveIdentityActivation(s state.State, caller [32]byte, q NodeIdentityChange) (NodeIdentityActivation, error) {
	d, err := p.Members(s)
	if err != nil || !lifecycle.ValidID(q.ID) || !lifecycle.ValidID(q.Operation) || !d.MemberKey(caller) {
		return NodeIdentityActivation{}, access.ErrDenied
	}
	row, found := d.IdentityRotation(q.ID, q.Operation)
	if !found || row.Proof == nil || row.Proof.New != caller || row.Phase != "Activated" && row.Phase != "Installed" || row.ActivatedIndex == 0 || row.ActivatedIndex > s.Index() {
		return NodeIdentityActivation{}, access.ErrDenied
	}
	return NodeIdentityActivation{Schema: 1, Index: row.ActivatedIndex, Proof: *row.Proof}, nil
}

// CheckIdentityEffect preserves the original admin operation but checks its
// current grant before local preparation or shared activation. Installed is an
// observation of that original switch and remains collectable after revocation.
func (p Policy) CheckIdentityEffect(s state.State, row membership.IdentityRotation) error {
	var original UserOperation
	if canonical(row.Origin, &original) != nil || original.VerifyOriginal(p.Cluster) != nil {
		return ErrCatalog
	}
	catalog, err := p.Catalog(s)
	if err != nil {
		return err
	}
	return catalog.AuthorizeAccepted(original.Session, p.Cluster, original.At, "", access.ManageCluster, "")
}

func (p Policy) activateIdentityResources(s state.State, d membership.Directory, row membership.IdentityRotation) (map[string][]byte, state.Code) {
	resources, err := p.Resources(s)
	if err != nil || row.Proof == nil {
		return nil, state.Invalid
	}
	raw, _ := json.Marshal(row.Proof)
	digest := sha256.Sum256(raw)
	resources.Quotas, err = resources.Quotas.RotateOwner(tenancy.OwnerRotation{Node: row.Node, Operation: row.Operation, Old: row.Proof.Old, New: row.Proof.New, Proof: digest, Index: s.Index() + 1})
	if err != nil {
		return nil, state.ConditionFailed
	}
	writes, code := p.memberCheckpoint(s, d)
	if code != state.Applied {
		return nil, code
	}
	resourceWrites, code := p.resourceCheckpoint(s, resources)
	if code != state.Applied {
		return nil, code
	}
	for key, value := range resourceWrites {
		writes[key] = value
	}
	// Issuer policy is explicit. Carry the existing node's capability to its
	// replacement key in this same activation; keep the original issuer row and
	// signed approvals untouched for already accepted bindings. Current member
	// admission, rather than the historical issuer table, controls new issuance.
	vault, err := p.Vault(s)
	if err != nil {
		return nil, state.Invalid
	}
	if issuer, registered := vault.Approvals.Issuer(row.Proof.Old); registered {
		var original UserOperation
		catalog, err := p.Catalog(s)
		if err != nil || canonical(row.Origin, &original) != nil {
			return nil, state.Invalid
		}
		vault.Approvals, err = vault.Approvals.SetIssuer(catalog, original.Session.User, vault.Approvals.Revision(), row.Proof.New, issuer.Enabled)
		if err != nil {
			return nil, state.ConditionFailed
		}
		vaultWrites, code := p.vaultCheckpoint(s, vault)
		if code != state.Applied {
			return nil, code
		}
		for key, value := range vaultWrites {
			writes[key] = value
		}
	}
	return writes, state.Applied
}
func (p Policy) admitIdentityResourcePatch(s state.State, cmd state.Command, keys []string) bool {
	var report MemberReport
	if canonical([]byte(cmd.Value), &report) != nil || report.Action != "identity-activate" {
		return false
	}
	writes, code := p.reduceMembers(s, cmd)
	if code != state.Applied {
		return false
	}
	seen := map[string]bool{}
	for _, key := range keys {
		if !checkpointPatchKey(writes, ResourcesKey, key) && !checkpointPatchKey(writes, VaultKey, key) || seen[key] {
			return false
		}
		seen[key] = true
	}
	return true
}
