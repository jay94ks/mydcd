// SPDX-License-Identifier: Apache-2.0

package control

import (
	"fmt"
	"slices"
	"strings"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	checker "github.com/jay94ks/mydcd/internal/workload/lifecycle"
)

// LifecycleKey stores tenant source/policy metadata and accepted app/build pins.
// Source bytes, binaries and individual probe runs are not shared Raft objects.
const LifecycleKey = "control/checker-lifecycle"

type LifecycleScriptPut struct {
	Tenant, Name string
	Source       checker.SourceFact
}

type LifecycleScriptSelection struct {
	Tenant, Name string
	Revision     uint64 // immutable source revision; Change.Expected is record CAS
}

type LifecycleSourcePermitRequest struct {
	Session access.Session
	Source  checker.SourceDescriptor
	At      int64
	Recover bool
}

type LifecycleSourcePermit struct {
	Schema                     uint8
	Cluster, Provider          [32]byte
	Node                       string
	Source                     checker.SourceDescriptor
	Recover                    bool
	Policy                     checker.TenantPolicy
	Index, Epoch, RootRevision uint64
}

// LifecycleSourcePermit is a quorum-read authorization for one local content
// operation. Recovery may read an original fact after node allocation/policy
// revocation, but cannot register it or authorize new execution.
func (p Policy) LifecycleSourcePermit(s state.State, caller [32]byte, q LifecycleSourcePermitRequest) (LifecycleSourcePermit, error) {
	if q.Source.Validate() != nil || q.At < 0 {
		return LifecycleSourcePermit{}, access.ErrDenied
	}
	p, err := p.Current(s)
	if err != nil {
		return LifecycleSourcePermit{}, err
	}
	directory, err := p.Members(s)
	if err != nil || !q.Recover && !directory.WorkKey(caller) {
		return LifecycleSourcePermit{}, access.ErrDenied
	}
	node := ""
	for _, entry := range directory.Entries {
		owner, err := p.nodeOwner(s, entry.Peer.ID)
		if err == nil && owner == caller {
			node = entry.Peer.ID
			break
		}
	}
	if node == "" {
		return LifecycleSourcePermit{}, access.ErrDenied
	}
	users, err := p.Catalog(s)
	if err != nil {
		return LifecycleSourcePermit{}, err
	}
	if !q.Recover && users.OperationAllowed(q.Session, "lifecycle-source-upload") != nil {
		return LifecycleSourcePermit{}, access.ErrDenied
	}
	if q.Recover {
		err = users.AuthorizeSessionCleanup(q.Session, p.Cluster, p.Issuer(q.Session.Issuer), q.At, q.Source.Tenant, access.ManageServices)
	} else {
		err = users.AuthorizeSession(q.Session, p.Cluster, p.Issuer(q.Session.Issuer), q.At, q.Source.Tenant, access.ManageServices, node)
	}
	if err != nil {
		return LifecycleSourcePermit{}, err
	}
	book, err := p.Lifecycles(s)
	if err != nil {
		return LifecycleSourcePermit{}, err
	}
	policy, exists := book.Policy(q.Source.Tenant, 0)
	if !exists || !q.Recover && !policy.AllowsDescriptor(q.Source) {
		return LifecycleSourcePermit{}, access.ErrDenied
	}
	return LifecycleSourcePermit{Schema: 1, Cluster: p.Cluster, Provider: caller, Node: node, Source: q.Source.Clone(), Recover: q.Recover, Policy: policy, Index: s.Index(), Epoch: s.ModuleEpoch(), RootRevision: s.Object(LifecycleKey).Revision}, nil
}

// LifecycleEntry is a bounded metadata query item, never an artifact/Ready proof.
type LifecycleEntry struct {
	Key             string
	RecordRevision  uint64
	Name            string                `json:",omitempty"`
	SourceRevision  uint64                `json:",omitempty"`
	Source          *checker.SourceFact   `json:",omitempty"`
	Active, Deleted bool                  `json:",omitempty"`
	Policy          *checker.TenantPolicy `json:",omitempty"`
}

func (p Policy) Lifecycles(s state.State) (checker.Catalog, error) {
	raw, revision, err := readCheckpoint(s, LifecycleKey, p.Cluster, p.TrustRoot)
	if err != nil {
		return checker.Catalog{}, err
	}
	if raw == nil {
		return checker.NewCatalog(p.Cluster)
	}
	book, err := checker.DecodeCatalog(raw)
	if err != nil || book.Cluster() != p.Cluster || book.Revision() != revision || revision == 0 {
		return checker.Catalog{}, ErrCatalog
	}
	users, err := p.Catalog(s)
	if err != nil {
		return checker.Catalog{}, err
	}
	for _, tenant := range book.Tenants() {
		if _, exists := users.Tenant(tenant); !exists {
			return checker.Catalog{}, ErrCatalog
		}
	}
	// Original node signatures and policy versions survive provider removal,
	// retirement and current authorization changes. New publication/run checks
	// current membership/authority; snapshot validation must not erase history.
	return book, nil
}

func (p Policy) lifecycleCheckpoint(s state.State, book checker.Catalog) (map[string][]byte, state.Code) {
	raw, err := book.Encode()
	if err != nil || book.Cluster() != p.Cluster {
		return nil, state.Invalid
	}
	return writeCheckpoint(s, LifecycleKey, p.Cluster, p.TrustRoot, book.Revision(), raw)
}

func (p Policy) authorizeLifecycle(users access.Catalog, op UserOperation) error {
	issuer := p.Issuer(op.Session.Issuer)
	switch op.Change.Action {
	case "put-lifecycle-script":
		var q LifecycleScriptPut
		if canonical(op.Change.Payload, &q) != nil || q.Tenant == "" || q.Source.Tenant != q.Tenant {
			return access.ErrInvalid
		}
		return users.AuthorizeSession(op.Session, p.Cluster, issuer, op.At, q.Tenant, access.ManageServices, "")
	case "retire-lifecycle-script", "delete-lifecycle-script":
		var q LifecycleScriptSelection
		if canonical(op.Change.Payload, &q) != nil || q.Tenant == "" {
			return access.ErrInvalid
		}
		return users.AuthorizeSessionCleanup(op.Session, p.Cluster, issuer, op.At, q.Tenant, access.ManageServices)
	case "set-lifecycle-policy":
		var q checker.TenantPolicy
		if canonical(op.Change.Payload, &q) != nil || q.Tenant == "" {
			return access.ErrInvalid
		}
		if err := users.AuthorizeSession(op.Session, p.Cluster, issuer, op.At, q.Tenant, access.ManageServices, ""); err != nil {
			return err
		}
		for _, node := range q.Build.Nodes {
			if err := users.AuthorizeSession(op.Session, p.Cluster, issuer, op.At, q.Tenant, access.ManageServices, node); err != nil {
				return err
			}
		}
		return nil
	}
	return access.ErrInvalid
}

func (p Policy) reduceLifecycle(s state.State, cmd state.Command) (map[string][]byte, state.Code) {
	if strings.HasPrefix(cmd.Actor, "node/") {
		return p.reduceCheckerBuild(s, cmd)
	}
	if cmd.Kind != state.Module || cmd.Key != LifecycleKey || !strings.HasPrefix(cmd.Actor, "user/") {
		return nil, state.Forbidden
	}
	p, err := p.Current(s)
	if err != nil {
		return nil, state.Invalid
	}
	users, err := p.Catalog(s)
	if err != nil {
		return nil, state.Invalid
	}
	op, err := p.Operation(users, cmd, false)
	if err != nil || p.authorizeLifecycle(users, op) != nil {
		return nil, state.Forbidden
	}
	book, err := p.Lifecycles(s)
	if err != nil {
		return nil, state.Invalid
	}
	switch op.Change.Action {
	case "set-lifecycle-policy":
		var q checker.TenantPolicy
		if canonical(op.Change.Payload, &q) != nil {
			return nil, state.Invalid
		}
		for _, node := range q.Build.Nodes {
			if _, err := p.nodeOwner(s, node); err != nil {
				return nil, state.Forbidden
			}
		}
		book, err = book.SetPolicy(users, op.Session.User, op.Change.Expected, q)
	case "put-lifecycle-script":
		var q LifecycleScriptPut
		if canonical(op.Change.Payload, &q) != nil || q.Source.Verify() != nil || q.Source.Cluster != p.Cluster {
			return nil, state.Invalid
		}
		directory, e := p.Members(s)
		if e != nil {
			return nil, state.Invalid
		}
		provider := ""
		for _, entry := range directory.Entries {
			key, e := p.nodeOwner(s, entry.Peer.ID)
			if e == nil && key == q.Source.Owner {
				provider = entry.Peer.ID
				break
			}
		}
		if provider == "" || users.AuthorizeSession(op.Session, p.Cluster, p.Issuer(op.Session.Issuer), op.At, q.Tenant, access.ManageServices, provider) != nil {
			return nil, state.Forbidden
		}
		book, err = book.PutScript(users, op.Session.User, op.Change.Expected, q.Tenant, q.Name, q.Source)
	case "retire-lifecycle-script", "delete-lifecycle-script":
		var q LifecycleScriptSelection
		if canonical(op.Change.Payload, &q) != nil {
			return nil, state.Invalid
		}
		book, err = book.RetireScript(users, op.Session.User, op.Change.Expected, q.Tenant, checker.NamedReference{Name: q.Name, Revision: q.Revision}, op.Change.Action == "delete-lifecycle-script")
	default:
		return nil, state.Invalid
	}
	if err != nil {
		return nil, state.ConditionFailed
	}
	return p.lifecycleCheckpoint(s, book)
}

// LifecyclePage returns one bounded source fact or the current policy. Historical
// policy versions remain in the checkpoint for accepted work, not implicit reuse.
func (p Policy) LifecyclePage(s state.State, session access.Session, now int64, tenant, after string) ([]LifecycleEntry, string, error) {
	current, err := p.Current(s)
	if err != nil {
		return nil, "", err
	}
	p = current
	users, err := p.Catalog(s)
	if err != nil {
		return nil, "", err
	}
	if tenant == "" || users.AuthorizeSessionCleanup(session, p.Cluster, p.Issuer(session.Issuer), now, tenant, access.ManageServices) != nil {
		return nil, "", access.ErrDenied
	}
	book, err := p.Lifecycles(s)
	if err != nil {
		return nil, "", err
	}
	var entries []LifecycleEntry
	if policy, ok := book.Policy(tenant, 0); ok {
		entries = append(entries, LifecycleEntry{Key: "policy", RecordRevision: policy.Revision, Policy: &policy})
	}
	for _, r := range book.Records(tenant) {
		for _, v := range r.Versions {
			fact := v.Source.Clone()
			entries = append(entries, LifecycleEntry{Key: fmt.Sprintf("script/%s/%020d", r.Name, v.Revision), RecordRevision: r.Revision, Name: r.Name, SourceRevision: v.Revision, Source: &fact, Active: v.Active, Deleted: v.Deleted})
		}
	}
	slices.SortFunc(entries, func(a, b LifecycleEntry) int { return strings.Compare(a.Key, b.Key) })
	i := slices.IndexFunc(entries, func(e LifecycleEntry) bool { return e.Key > after })
	if i < 0 {
		return nil, "", nil
	}
	if i+1 < len(entries) {
		return entries[i : i+1], entries[i].Key, nil
	}
	return entries[i : i+1], "", nil
}
