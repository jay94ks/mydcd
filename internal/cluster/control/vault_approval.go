// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"
	"strings"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/membership"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/config"
	"github.com/jay94ks/seafield/internal/identity"
	"github.com/jay94ks/seafield/internal/secrets"
)

type VaultApprovalPlanRequest struct {
	Selection *AppApprovalSelection `json:",omitempty"`
	Realm, ID string
	Issuer    [32]byte
	Uses      []secrets.Use
	Part      int
	Digest    [32]byte
	Origin    *UserOperation `json:",omitempty"`
}
type VaultApprovalTarget struct {
	Target   secrets.Target
	Existing *secrets.Approval `json:",omitempty"`
	Approver *config.Peer      `json:",omitempty"`
}
type VaultApprovalPlan struct {
	Realm   string
	Targets []VaultApprovalTarget
}
type VaultApprovalPart struct {
	RootRevision uint64
	Digest       [32]byte
	Length, Part int
	Data         []byte
}
type VaultApprovalPermitRequest struct {
	Selection *AppApprovalSelection `json:",omitempty"`
	Session   access.Session
	Target    secrets.Target
	At        int64
	Origin    *UserOperation `json:",omitempty"`
}
type VaultApprovalPermit struct {
	Target              secrets.Target
	Binding             secrets.VerifierBinding
	Existing            *secrets.Approval `json:",omitempty"`
	RootRevision, Epoch uint64
	Capacity            int
}

func (p Policy) PlanVaultApproval(s state.State, session access.Session, at int64, tenant string, q VaultApprovalPlanRequest) (VaultApprovalPart, error) {
	p, err := p.Current(s)
	if err != nil || q.ID == "" || len(q.ID) > 128 || q.Part < 0 {
		return VaultApprovalPart{}, ErrCatalog
	}
	c, err := p.Catalog(s)
	if err != nil {
		return VaultApprovalPart{}, err
	}
	v, err := p.Vault(s)
	if err != nil {
		return VaultApprovalPart{}, err
	}
	tree, ok := v.Trees[q.Realm]
	if !ok {
		return VaultApprovalPart{}, ErrCatalog
	}
	members, err := p.Members(s)
	if err != nil {
		return VaultApprovalPart{}, err
	}
	requester := session.Key
	if q.Origin != nil {
		if len(q.Uses) != 0 {
			return VaultApprovalPart{}, access.ErrDenied
		}
		uses, err := p.approvalUsesFor(s, session, at, q.Origin, q.Selection)
		if err != nil {
			return VaultApprovalPart{}, err
		}
		q.Uses, requester = uses[q.Realm], q.Origin.Session.Key
	}
	if q.Issuer != ([32]byte{}) {
		issuer, registered := v.Approvals.Issuer(q.Issuer)
		if !members.MemberKey(q.Issuer) || !registered || !issuer.Enabled {
			return VaultApprovalPart{}, access.ErrDenied
		}
	}
	if q.Selection != nil && q.Origin == nil {
		return VaultApprovalPart{}, access.ErrDenied
	}
	if len(q.Uses) == 0 {
		return VaultApprovalPart{}, access.ErrDenied
	}
	for _, use := range q.Uses {
		key, err := p.nodeOwner(s, use.Node)
		if err != nil || key != use.NodeKey || use.Tenant != tenant || use.User != session.User || use.RequesterKey != requester || c.AuthorizeSession(session, p.Cluster, p.Issuer(session.Issuer), at, use.Tenant, access.Deploy, use.Node) != nil {
			return VaultApprovalPart{}, access.ErrDenied
		}
	}
	plan, err := tree.Plan(c, q.Uses)
	if err != nil {
		return VaultApprovalPart{}, err
	}
	result := VaultApprovalPlan{Realm: q.Realm}
	for _, target := range plan.Required {
		issuerKey := q.Issuer
		var approver *config.Peer
		if issuerKey == ([32]byte{}) {
			binding, err := tree.Verifier(target.Group)
			if err != nil {
				return VaultApprovalPart{}, err
			}
			profile, ok := tree.WriteProfile(binding.Reference.Profile)
			if ok && profile.Builtin() {
				// A voter that holds the builtin verifier checks the password.
				peer, found := builtinVerifierHolder(members, v.Approvals, tree, binding.Reference)
				if !profile.Enabled || !profile.Verifiers || !found {
					return VaultApprovalPart{}, access.ErrDenied
				}
				issuerKey, _ = identity.ParseKey(peer.Key)
				approver = &peer
			} else {
				entry, found := members.Entry(profile.Node)
				peer := entry.CurrentPeer()
				issuerKey, err = identity.ParseKey(peer.Key)
				if !ok || !profile.Enabled || !profile.Verifiers || !found || err != nil || !p.ownsResource(s, issuerKey, profile.Key) {
					return VaultApprovalPart{}, access.ErrDenied
				}
				approver = &peer
			}
		}
		issuer, registered := v.Approvals.Issuer(issuerKey)
		if !members.MemberKey(issuerKey) || !registered || !issuer.Enabled {
			return VaultApprovalPart{}, access.ErrDenied
		}
		target.IssuerPolicy = issuer.Policy
		raw, _ := json.Marshal(struct {
			ID     string
			Epoch  uint64
			Target secrets.Target
		}{q.ID, s.ModuleEpoch(), target})
		digest := sha256.Sum256(raw)
		target.ApprovalID = "approval-" + hex.EncodeToString(digest[:24])
		permit, err := p.VaultApprovalPermit(s, issuerKey, VaultApprovalPermitRequest{Session: session, Target: target, At: at, Origin: q.Origin, Selection: q.Selection})
		if err != nil {
			return VaultApprovalPart{}, err
		}
		result.Targets = append(result.Targets, VaultApprovalTarget{Target: target, Existing: permit.Existing, Approver: approver})
	}
	raw, err := json.Marshal(result)
	if err != nil || len(raw) > 4<<20 {
		return VaultApprovalPart{}, ErrCatalog
	}
	digest := sha256.Sum256(raw)
	if q.Digest != ([32]byte{}) && q.Digest != digest {
		return VaultApprovalPart{}, access.ErrConflict
	}
	const partBytes = 24 << 10
	if q.Part >= (len(raw)+partBytes-1)/partBytes {
		return VaultApprovalPart{}, ErrCatalog
	}
	start := q.Part * partBytes
	return VaultApprovalPart{RootRevision: s.Object(VaultKey).Revision, Digest: digest, Length: len(raw), Part: q.Part, Data: raw[start:min(len(raw), start+partBytes)]}, nil
}
func (p Policy) VaultApprovalPermit(s state.State, caller [32]byte, q VaultApprovalPermitRequest) (VaultApprovalPermit, error) {
	p, err := p.Current(s)
	if err != nil {
		return VaultApprovalPermit{}, err
	}
	members, err := p.Members(s)
	if err != nil || !members.MemberKey(caller) {
		return VaultApprovalPermit{}, access.ErrDenied
	}
	c, err := p.Catalog(s)
	if err != nil {
		return VaultApprovalPermit{}, err
	}
	if c.OperationAllowed(q.Session, "vault-commit-approval") != nil {
		return VaultApprovalPermit{}, access.ErrDenied
	}
	target := q.Target
	if q.Selection != nil && q.Origin == nil {
		return VaultApprovalPermit{}, access.ErrDenied
	}
	if target.User != q.Session.User || q.Origin == nil && target.RequesterKey != q.Session.Key {
		return VaultApprovalPermit{}, access.ErrDenied
	}
	if q.Origin != nil && p.checkAppApprovalTarget(s, q.Session, q.At, q.Origin, target, q.Selection) != nil {
		return VaultApprovalPermit{}, access.ErrDenied
	}
	if !members.WorkKey(caller) && (q.Origin == nil || q.Origin.Change.Action != "begin-volume-move" && (q.Selection == nil || q.Selection.Operation == "")) {
		return VaultApprovalPermit{}, access.ErrDenied
	}
	capacity := 4096
	resources, err := p.Resources(s)
	if err != nil {
		return VaultApprovalPermit{}, err
	}
	for _, node := range target.Nodes {
		key, err := p.workNodeOwner(s, node.ID)
		if err != nil || key != node.Key || c.AuthorizeSession(q.Session, p.Cluster, p.Issuer(q.Session.Issuer), q.At, target.Tenant, access.Deploy, node.ID) != nil {
			return VaultApprovalPermit{}, access.ErrDenied
		}
		global, gok := resources.Quotas.Limit("", node.ID)
		scoped, sok := resources.Quotas.Limit(target.Tenant, node.ID)
		if !gok || !sok || global.Owner != node.Key || scoped.Owner != node.Key {
			return VaultApprovalPermit{}, access.ErrDenied
		}
		capacity = min(capacity, global.MaxConsumers, scoped.MaxConsumers)
	}
	if capacity < 1 {
		return VaultApprovalPermit{}, access.ErrDenied
	}
	v, err := p.Vault(s)
	if err != nil {
		return VaultApprovalPermit{}, err
	}
	tree, ok := v.Trees[target.Realm]
	if !ok || v.Approvals.CheckTarget(c, tree, caller, target, q.At) != nil {
		return VaultApprovalPermit{}, access.ErrDenied
	}
	binding, err := tree.Verifier(target.Group)
	if err != nil {
		return VaultApprovalPermit{}, err
	}
	profile, ok := tree.WriteProfile(binding.Reference.Profile)
	if !ok || !profile.Enabled || !profile.Verifiers || !p.servesProvider(s, caller, profile) {
		return VaultApprovalPermit{}, access.ErrDenied
	}
	if profile.Builtin() {
		if _, held := tree.BuiltinHolding(secrets.VerifierWrite, binding.Reference.Object, binding.Reference.Revision); !held {
			return VaultApprovalPermit{}, access.ErrDenied
		}
	}
	permit := VaultApprovalPermit{Target: target, Binding: binding, RootRevision: s.Object(VaultKey).Revision, Epoch: s.ModuleEpoch(), Capacity: capacity}
	if existing, ok := v.Approvals.Existing(c, tree, target, q.At); ok {
		permit.Existing = &existing
	}
	return permit, nil
}

type VaultApprovalReport struct {
	Selection           *AppApprovalSelection `json:",omitempty"`
	Schema              uint8
	Cluster, Reporter   [32]byte
	Session             access.Session
	Approval            secrets.Approval
	At                  int64
	Epoch, RootRevision uint64
	Capacity            int
	RequestID           string
	Signature           []byte
	Origin              *UserOperation `json:",omitempty"`
}

func VaultApprovalReportBytes(r VaultApprovalReport) []byte {
	r.Signature = nil
	raw, _ := json.Marshal(r)
	return append([]byte("sfc-vault-approval-report-1\x00"), raw...)
}
func (r VaultApprovalReport) Command() (state.Command, error) {
	raw, err := json.Marshal(r)
	if err != nil {
		return state.Command{}, err
	}
	command := state.Command{Kind: state.Module, Actor: "node/" + hex.EncodeToString(r.Reporter[:]), Epoch: r.Epoch, RequestID: r.RequestID, Key: VaultKey, Expected: r.RootRevision, Value: string(raw)}
	_, err = state.EncodeCommand(command)
	return command, err
}
func (p Policy) vaultApprovalReport(s state.State, command state.Command) (VaultApprovalReport, error) {
	var r VaultApprovalReport
	if command.Kind != state.Module || command.Key != VaultKey || canonical([]byte(command.Value), &r) != nil || r.Schema != 1 || r.Cluster != p.Cluster || r.Reporter == ([32]byte{}) || r.Approval.Issuer != r.Reporter || r.At < 0 || r.Approval.Payload.ApprovedAt != r.At || r.Epoch != s.ModuleEpoch() || r.Capacity < 1 || !ed25519.Verify(r.Reporter[:], VaultApprovalReportBytes(r), r.Signature) {
		return r, ErrCatalog
	}
	want, err := r.Command()
	if err != nil || want != command {
		return r, ErrCatalog
	}
	permit, err := p.VaultApprovalPermit(s, r.Reporter, VaultApprovalPermitRequest{Session: r.Session, Target: r.Approval.Payload.Target, At: r.At, Origin: r.Origin, Selection: r.Selection})
	if err != nil || r.Capacity > permit.Capacity {
		return r, access.ErrDenied
	}
	return r, nil
}
func (p Policy) reduceVaultApproval(s state.State, command state.Command) (map[string][]byte, state.Code) {
	r, err := p.vaultApprovalReport(s, command)
	if err != nil {
		return nil, state.Forbidden
	}
	v, err := p.Vault(s)
	if err != nil {
		return nil, state.Invalid
	}
	c, err := p.Catalog(s)
	if err != nil {
		return nil, state.Invalid
	}
	tree := v.Trees[r.Approval.Payload.Target.Realm]
	v.Approvals, err = v.Approvals.Commit(c, r.Session.User, tree, v.Approvals.Revision(), r.Approval, r.At, r.Capacity)
	if err != nil {
		return nil, vaultFailure(err)
	}
	return p.vaultCheckpoint(s, v)
}
func (p Policy) ResolveVaultApprovalCommand(s state.State, caller [32]byte, raw []byte) (state.Command, error) {
	command, err := state.DecodeCommand(raw)
	if err != nil {
		return command, err
	}
	report, err := p.vaultApprovalReport(s, command)
	if err != nil || report.Reporter != caller {
		return command, access.ErrDenied
	}
	return command, nil
}
func (p Policy) VaultApprovalResult(s state.State, caller [32]byte, command state.Command) (AppResult, error) {
	members, err := p.Members(s)
	if err != nil || !members.MemberKey(caller) {
		return AppResult{}, access.ErrDenied
	}
	var r VaultApprovalReport
	if command.Kind != state.Module || command.Key != VaultKey || !strings.HasPrefix(command.Actor, "node/") || canonical([]byte(command.Value), &r) != nil || r.Cluster != p.Cluster || r.Reporter != caller || !ed25519.Verify(caller[:], VaultApprovalReportBytes(r), r.Signature) {
		return AppResult{}, access.ErrDenied
	}
	want, err := r.Command()
	if err != nil || !bytes.Equal([]byte(want.Value), []byte(command.Value)) || want != command {
		return AppResult{}, access.ErrDenied
	}
	result, ok := s.LookupResult(command)
	if !ok {
		return AppResult{}, nil
	}
	return AppResult{Found: true, Result: &result}, nil
}

// builtinVerifierHolder is the first current voter, in directory order, that
// holds the builtin verifier r and is an enabled issuer: it checks the
// password and signs the approval.
func builtinVerifierHolder(members membership.Directory, approvals secrets.Approvals, tree secrets.Tree, r secrets.Reference) (config.Peer, bool) {
	h, ok := tree.BuiltinHolding(secrets.VerifierWrite, r.Object, r.Revision)
	if !ok {
		return config.Peer{}, false
	}
	for _, e := range members.Entries {
		peer := e.CurrentPeer()
		key, err := identity.ParseKey(peer.Key)
		if err != nil || !members.VoterKey(key) || !slices.Contains(h.Holders, key) {
			continue
		}
		if issuer, registered := approvals.Issuer(key); registered && issuer.Enabled {
			return peer, true
		}
	}
	return config.Peer{}, false
}
