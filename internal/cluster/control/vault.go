// SPDX-License-Identifier: Apache-2.0

package control

import (
	"encoding/json"
	"errors"
	"slices"
	"strings"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/reconcile"
	"github.com/jay94ks/seafield/internal/secrets"
)

const VaultKey = "control/vault"
const maxVaultCheckpoint = 16 << 20

type VaultRealm struct{ Realm, Root string }
type VaultObject struct {
	Realm  string
	Object secrets.Object
}
type VaultSelection struct{ Realm, ID string }

// VaultACL adds and removes names in an object's ACL lists (vault-acl).
// Expected is the object's revision; lists left empty do not change.
type VaultACL struct {
	Realm, ID   string
	Add, Remove secrets.ACL
}

// VaultOrder moves one entry of a group right after another, or to the front
// when After is empty (vault-reorder). Expected is the group's revision.
type VaultOrder struct {
	Realm, ID, Entry string
	After            string `json:",omitempty"`
}
type VaultMove struct{ Realm, ID, Parent string }
type VaultAge struct {
	Realm, ID string
	Seconds   int64
}
type VaultProfile struct {
	Realm   string
	Profile secrets.WriteProfile
}
type VaultWrite struct {
	Realm   string
	Request secrets.WriteRequest
}
type VaultWriteAction struct {
	Realm, ID             string
	Epoch, ObjectRevision uint64
}
type VaultObserve struct{ Observation secrets.WriteObservation }
type VaultIssuer struct {
	Key     [32]byte
	Enabled bool
}
type VaultApproval struct {
	Realm    string
	Approval secrets.Approval
	Capacity int
}
type VaultApprovalSelection struct{ ID string }
type Vault struct {
	Revision  uint64
	Trees     map[string]secrets.Tree
	Approvals secrets.Approvals
}
type vaultTree struct {
	Realm string
	Tree  json.RawMessage
}
type vaultCheckpoint struct {
	Schema    uint8
	Cluster   [32]byte
	Revision  uint64
	Trees     []vaultTree
	Approvals json.RawMessage
}

func (p Policy) Vault(s state.State) (Vault, error) {
	a, err := secrets.NewApprovals(p.Cluster)
	if err != nil {
		return Vault{}, ErrCatalog
	}
	v := Vault{Trees: map[string]secrets.Tree{}, Approvals: a}
	raw, revision, err := readCheckpoint(s, VaultKey, p.Cluster, p.TrustRoot)
	if err != nil || len(raw) > maxVaultCheckpoint {
		return v, ErrCatalog
	}
	if raw == nil {
		return v, nil
	}
	var disk vaultCheckpoint
	if canonical(raw, &disk) != nil || disk.Schema != 1 || disk.Cluster != p.Cluster || disk.Revision != revision || revision == 0 || len(disk.Trees) > 256 {
		return v, ErrCatalog
	}
	c, err := p.Catalog(s)
	if err != nil {
		return v, err
	}
	for i, row := range disk.Trees {
		tree, err := secrets.DecodeTree(row.Tree)
		if err != nil || tree.Cluster() != p.Cluster || tree.Realm() != row.Realm || i > 0 && disk.Trees[i-1].Realm >= row.Realm {
			return v, ErrCatalog
		}
		if row.Realm != "" {
			_, ok := c.Tenant(row.Realm)
			if !ok {
				return v, ErrCatalog
			}
		}
		for _, write := range tree.Writes() {
			if _, ok := c.User(write.Actor); !ok {
				return v, ErrCatalog
			}
		}
		v.Trees[row.Realm] = tree
	}
	v.Approvals, err = secrets.DecodeApprovals(disk.Approvals)
	if err != nil || v.Approvals.Cluster() != p.Cluster {
		return v, ErrCatalog
	}
	v.Revision = revision
	return v, nil
}
func (p Policy) vaultCheckpoint(s state.State, v Vault) (map[string][]byte, state.Code) {
	if v.Revision == ^uint64(0) || len(v.Trees) > 256 {
		return nil, state.Invalid
	}
	disk := vaultCheckpoint{Schema: 1, Cluster: p.Cluster, Revision: v.Revision + 1}
	realms := make([]string, 0, len(v.Trees))
	for realm := range v.Trees {
		realms = append(realms, realm)
	}
	slices.Sort(realms)
	for _, realm := range realms {
		// Every vault write drops builtin holdings nothing can read now.
		raw, err := v.Trees[realm].PruneBuiltin(v.Approvals).Encode()
		if err != nil {
			return nil, state.Invalid
		}
		disk.Trees = append(disk.Trees, vaultTree{realm, raw})
	}
	var err error
	disk.Approvals, err = v.Approvals.Encode()
	if err != nil {
		return nil, state.Invalid
	}
	raw, err := json.Marshal(disk)
	if err != nil || len(raw) > maxVaultCheckpoint {
		return nil, state.Invalid
	}
	return writeCheckpoint(s, VaultKey, p.Cluster, p.TrustRoot, disk.Revision, raw)
}
func (v Vault) Quiescent() bool {
	if !v.Approvals.Quiescent() {
		return false
	}
	for _, t := range v.Trees {
		if !t.Quiescent() {
			return false
		}
	}
	return true
}

func vaultRealm(change Change) (string, error) {
	if change.Action == "vault-set-issuer" || change.Action == "vault-revoke-approval" {
		return "", nil
	}
	if change.Action == "vault-observe-write" {
		var x VaultObserve
		if canonical(change.Payload, &x) != nil {
			return "", ErrCatalog
		}
		return x.Observation.Tenant, nil
	}
	// Decode the complete action type before authorization. Realm alone must not
	// let unknown/private fields enter the signed replicated command.
	var realm string
	switch change.Action {
	case "vault-init":
		var x VaultRealm
		if canonical(change.Payload, &x) != nil {
			return "", ErrCatalog
		}
		realm = x.Realm
	case "vault-create":
		var x VaultObject
		if canonical(change.Payload, &x) != nil {
			return "", ErrCatalog
		}
		realm = x.Realm
	case "vault-acl":
		var x VaultACL
		if canonical(change.Payload, &x) != nil {
			return "", ErrCatalog
		}
		realm = x.Realm
	case "vault-reorder":
		var x VaultOrder
		if canonical(change.Payload, &x) != nil {
			return "", ErrCatalog
		}
		realm = x.Realm
	case "vault-move":
		var x VaultMove
		if canonical(change.Payload, &x) != nil {
			return "", ErrCatalog
		}
		realm = x.Realm
	case "vault-approval-age":
		var x VaultAge
		if canonical(change.Payload, &x) != nil {
			return "", ErrCatalog
		}
		realm = x.Realm
	case "vault-set-profile":
		var x VaultProfile
		if canonical(change.Payload, &x) != nil {
			return "", ErrCatalog
		}
		realm = x.Realm
	case "vault-prepare-write":
		var x VaultWrite
		if canonical(change.Payload, &x) != nil {
			return "", ErrCatalog
		}
		realm = x.Realm
	case "vault-dispatch-write", "vault-publish-write", "vault-abandon-write", "vault-rotate-writes":
		var x VaultWriteAction
		if canonical(change.Payload, &x) != nil {
			return "", ErrCatalog
		}
		realm = x.Realm
	case "vault-commit-approval":
		var x VaultApproval
		if canonical(change.Payload, &x) != nil {
			return "", ErrCatalog
		}
		realm = x.Realm
	case "vault-revoke", "vault-retire":
		var x VaultSelection
		if canonical(change.Payload, &x) != nil {
			return "", ErrCatalog
		}
		realm = x.Realm
	default:
		return "", ErrCatalog
	}
	return realm, nil
}
func (p Policy) authorizeVault(s state.State, c access.Catalog, op UserOperation) error {
	realm, err := vaultRealm(op.Change)
	if err != nil {
		return access.ErrInvalid
	}
	action := access.ManageSecrets
	switch op.Change.Action {
	case "vault-set-profile", "vault-set-issuer":
		action = access.ManageCluster
		realm = ""
	case "vault-revoke-approval":
		// The approval realm's secret managers may revoke it, as Revoke
		// checks (Jay 2026-11-26); a system administrator's cluster session
		// revokes any approval.
		var x VaultApprovalSelection
		if canonical(op.Change.Payload, &x) != nil {
			return access.ErrInvalid
		}
		v, err := p.Vault(s)
		if err != nil {
			return access.ErrInvalid
		}
		if realm, _ = v.Approvals.Realm(x.ID); realm != "" && c.AuthorizeSessionCleanup(op.Session, p.Cluster, p.Issuer(op.Session.Issuer), op.At, realm, action) == nil {
			return nil
		}
		return c.AuthorizeSession(op.Session, p.Cluster, p.Issuer(op.Session.Issuer), op.At, "", access.ManageCluster, "")
	case "vault-commit-approval":
		var x VaultApproval
		if canonical(op.Change.Payload, &x) != nil || x.Approval.Payload.Target.Realm != realm {
			return access.ErrInvalid
		}
		return c.AuthorizeSession(op.Session, p.Cluster, p.Issuer(op.Session.Issuer), op.At, x.Approval.Payload.Target.Tenant, access.Deploy, "")
	}
	if realm == "" {
		action = access.ManageCluster
	}
	if op.Change.Action == "vault-revoke" || op.Change.Action == "vault-retire" || op.Change.Action == "vault-observe-write" {
		return c.AuthorizeSessionCleanup(op.Session, p.Cluster, p.Issuer(op.Session.Issuer), op.At, realm, action)
	}
	return c.AuthorizeSession(op.Session, p.Cluster, p.Issuer(op.Session.Issuer), op.At, realm, action, "")
}
func vaultFailure(err error) state.Code {
	if errors.Is(err, access.ErrDenied) {
		return state.Forbidden
	}
	return state.ConditionFailed
}
func (p Policy) reduceVault(s state.State, cmd state.Command) (map[string][]byte, state.Code) {
	if cmd.Kind != state.Module || cmd.Key != VaultKey || !strings.HasPrefix(cmd.Actor, "user/") {
		return nil, state.Forbidden
	}
	p, err := p.Current(s)
	if err != nil {
		return nil, state.Invalid
	}
	c, err := p.Catalog(s)
	if err != nil {
		return nil, state.Invalid
	}
	op, err := p.Operation(c, cmd, false)
	if err != nil || p.authorizeVault(s, c, op) != nil {
		return nil, state.Forbidden
	}
	v, err := p.Vault(s)
	if err != nil {
		return nil, state.Invalid
	}
	change := op.Change
	realm, err := vaultRealm(change)
	if err != nil {
		return nil, state.Invalid
	}
	tree, exists := v.Trees[realm]
	if change.Action == "vault-init" {
		var x VaultRealm
		if canonical(change.Payload, &x) != nil {
			return nil, state.Invalid
		}
		if exists || change.Expected != 0 || len(v.Trees) >= 256 {
			return nil, state.ConditionFailed
		}
		if realm != "" {
			if c.Authorize(change.Principal, realm, access.ManageSecrets, "") != nil {
				return nil, state.Forbidden
			}
		} else if !c.SystemAllowed(change.Principal) {
			return nil, state.Forbidden
		}
		tree, err = secrets.NewTree(p.Cluster, realm, x.Root)
	} else if change.Action == "vault-set-issuer" {
		var x VaultIssuer
		if canonical(change.Payload, &x) != nil {
			return nil, state.Invalid
		}
		members, e := p.Members(s)
		if e != nil || !members.MemberKey(x.Key) {
			return nil, state.Forbidden
		}
		v.Approvals, err = v.Approvals.SetIssuer(c, change.Principal, change.Expected, x.Key, x.Enabled)
		if err != nil {
			return nil, vaultFailure(err)
		}
		return p.vaultCheckpoint(s, v)
	} else if change.Action == "vault-revoke-approval" {
		var x VaultApprovalSelection
		if canonical(change.Payload, &x) != nil {
			return nil, state.Invalid
		}
		v.Approvals, err = v.Approvals.Revoke(c, change.Principal, x.ID, change.Expected)
		if err != nil {
			return nil, vaultFailure(err)
		}
		return p.vaultCheckpoint(s, v)
	} else {
		if !exists {
			return nil, state.ConditionFailed
		}
		switch change.Action {
		case "vault-create":
			var x VaultObject
			_ = canonical(change.Payload, &x)
			tree, err = tree.Create(c, change.Principal, change.Expected, x.Object)
		case "vault-acl":
			var x VaultACL
			_ = canonical(change.Payload, &x)
			tree, err = tree.ChangeACL(c, change.Principal, x.ID, change.Expected, x.Add, x.Remove)
		case "vault-reorder":
			var x VaultOrder
			_ = canonical(change.Payload, &x)
			tree, err = tree.Reorder(c, change.Principal, x.ID, change.Expected, x.Entry, x.After)
		case "vault-move":
			var x VaultMove
			_ = canonical(change.Payload, &x)
			tree, err = tree.Move(c, change.Principal, x.ID, x.Parent, change.Expected)
		case "vault-approval-age":
			var x VaultAge
			_ = canonical(change.Payload, &x)
			tree, err = tree.SetApprovalAge(c, change.Principal, x.ID, change.Expected, x.Seconds)
		case "vault-set-profile":
			var x VaultProfile
			_ = canonical(change.Payload, &x)
			member, e := p.nodeOwner(s, x.Profile.Node)
			if e != nil || member != x.Profile.Key {
				return nil, state.Forbidden
			}
			if x.Profile.Enabled {
				if active, e := p.workNodeOwner(s, x.Profile.Node); e != nil || active != x.Profile.Key {
					return nil, state.Forbidden
				}
			}
			tree, err = tree.SetWriteProfile(c, change.Principal, change.Expected, x.Profile)
		case "vault-prepare-write":
			var x VaultWrite
			_ = canonical(change.Payload, &x)
			profile, found := tree.WriteProfile(x.Request.Profile)
			if !found {
				return nil, state.Forbidden
			}
			// The builtin profile names no node: a voter writes it later.
			if !profile.Builtin() {
				member, memberErr := p.workNodeOwner(s, profile.Node)
				if memberErr != nil || member != profile.Key {
					return nil, state.Forbidden
				}
			}
			tree, err = tree.PrepareWrite(c, change.Principal, change.Expected, x.Request)
		case "vault-dispatch-write", "vault-publish-write", "vault-abandon-write", "vault-rotate-writes":
			var x VaultWriteAction
			_ = canonical(change.Payload, &x)
			switch change.Action {
			case "vault-dispatch-write":
				write, found := tree.Write(x.ID)
				if !found {
					return nil, state.Forbidden
				}
				if !write.Writer.Builtin() {
					member, memberErr := p.workNodeOwner(s, write.Writer.Node)
					if memberErr != nil || member != write.Writer.Key {
						return nil, state.Forbidden
					}
				}
				tree, err = tree.DispatchWrite(c, change.Principal, x.ID, x.Epoch, change.Expected)
			case "vault-publish-write":
				tree, err = tree.PublishStored(c, change.Principal, x.ID, x.Epoch, x.ObjectRevision, change.Expected)
			case "vault-abandon-write":
				tree, err = tree.AbandonWrite(c, change.Principal, x.ID, x.Epoch, change.Expected)
			case "vault-rotate-writes":
				tree, err = tree.RotateWrites(c, change.Principal, change.Expected, x.Epoch)
			}
		case "vault-observe-write":
			var x VaultObserve
			_ = canonical(change.Payload, &x)
			if change.Expected != tree.Revision() {
				return nil, state.ConditionFailed
			}
			if write, found := tree.Write(x.Observation.Request.ID); found && write.Writer.Builtin() && !p.builtinHolders(s, x.Observation) {
				return nil, state.Forbidden
			}
			tree, err = tree.ObserveWrite(x.Observation)
		case "vault-revoke":
			var x VaultSelection
			_ = canonical(change.Payload, &x)
			tree, err = tree.Revoke(c, change.Principal, x.ID, change.Expected)
		case "vault-retire":
			var x VaultSelection
			_ = canonical(change.Payload, &x)
			tree, err = tree.Retire(c, change.Principal, x.ID, change.Expected, v.Approvals)
		case "vault-commit-approval":
			var x VaultApproval
			_ = canonical(change.Payload, &x)
			members, e := p.Members(s)
			if e != nil || !members.MemberKey(x.Approval.Issuer) {
				return nil, state.Forbidden
			}
			v.Approvals, err = v.Approvals.Commit(c, change.Principal, tree, change.Expected, x.Approval, op.At, x.Capacity)
		default:
			return nil, state.Invalid
		}
	}
	if err != nil {
		return nil, vaultFailure(err)
	}
	v.Trees[realm] = tree
	return p.vaultCheckpoint(s, v)
}

// Page exposes only public metadata to a current realm manager. Cluster realm
// listing is system-admin only, even though explicit tenant grants may allow
// selected secret consumption there later.
type VaultWriteView struct {
	Request                            secrets.WriteRequest
	Actor                              string
	Generation, ExpectedObjectRevision uint64
	Writer                             secrets.WriteProfile
	Operation                          uint64
	Phase                              reconcile.Phase
	Status                             string
	ProviderRevision                   uint64
	VerifierRef                        string
}

func publicVaultWrite(w secrets.WriteRecord) VaultWriteView {
	v := VaultWriteView{Request: w.Request, Actor: w.Actor, Generation: w.Generation, ExpectedObjectRevision: w.ExpectedObjectRevision, Writer: w.Writer, Operation: w.Journal.LastID, Status: w.Status()}
	if w.Journal.Pending != nil {
		v.Phase = w.Journal.Pending.Phase
	}
	if w.Observation != nil {
		v.ProviderRevision = w.Observation.ProviderRevision
		v.VerifierRef = w.Observation.VerifierRef
	}
	return v
}

type VaultView struct {
	Realm  string
	Object *secrets.Object `json:",omitempty"`
	Write  *VaultWriteView `json:",omitempty"`
}

func (v Vault) Page(c access.Catalog, actor, realm, after string) ([]VaultView, string, error) {
	if realm == "" && !c.SystemAllowed(actor) || realm != "" && c.AuthorizeCleanup(actor, realm, access.ManageSecrets) != nil {
		return nil, "", access.ErrDenied
	}
	tree, ok := v.Trees[realm]
	if !ok {
		return nil, "", nil
	}
	var out []VaultView
	usedBytes := 2 // JSON array brackets; row commas accounted below.
	var pageErr error
	appendItem := func(id string, row VaultView) (bool, string) {
		if id <= after {
			return true, ""
		}
		raw, err := json.Marshal(row)
		if err != nil || len(raw) > 112<<10 {
			pageErr = ErrCatalog
			return false, ""
		}
		cost := len(raw)
		if len(out) > 0 {
			cost++
		}
		if len(out) == 8 || usedBytes+cost > 112<<10 {
			return false, after
		}
		out = append(out, row)
		usedBytes += cost
		after = id
		return true, ""
	}
	for _, o := range tree.Objects() {
		if more, next := appendItem("object/"+o.ID, VaultView{Realm: realm, Object: &o}); !more {
			return out, next, pageErr
		}
	}
	for _, w := range tree.Writes() {
		public := publicVaultWrite(w)
		if more, next := appendItem("write/"+w.Request.ID, VaultView{Realm: realm, Write: &public}); !more {
			return out, next, pageErr
		}
	}
	return out, "", nil
}

// builtinHolders admits a builtin write observation: its reporter is a
// current voter and, when Applied, a majority of the current voters signed
// that they hold the sealed value. Signatures are the tree's check.
func (p Policy) builtinHolders(s state.State, o secrets.WriteObservation) bool {
	members, err := p.Members(s)
	if err != nil || !members.VoterKey(o.Reporter) {
		return false
	}
	if o.Outcome != reconcile.EffectApplied {
		return true
	}
	voters := members.SessionIssuers()
	held := 0
	for _, h := range o.Holders {
		if !members.VoterKey(h.Voter) {
			return false
		}
		held++
	}
	return held*2 > len(voters)
}

// vaultBook is the VaultKey book (books.go).
var vaultBook = Book{Key: VaultKey, Reduce: byKind(map[state.CommandKind]reducer{state.ModuleReport: Policy.reduceVaultHolder, state.Module: reduceVaultModule})}

// reduceVaultModule sends a node's Module command (an approval) and a user's
// (a vault change) to their reducers.
func reduceVaultModule(p Policy, s state.State, cmd state.Command) (map[string][]byte, state.Code) {
	if nodeActor(cmd) {
		return p.reduceVaultApproval(s, cmd)
	}
	return p.reduceVault(s, cmd)
}
