// SPDX-License-Identifier: Apache-2.0

package control

import (
	"errors"
	"sort"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	checker "github.com/jay94ks/mydcd/internal/workload/lifecycle"
)

var ErrLifecycleSourceMissing = errors.New("lifecycle source version missing")

type LifecycleProvider struct {
	Node  string
	Owner [32]byte
}

func (p Policy) LifecycleProviderFor(s state.State, session access.Session, at int64, d checker.SourceDescriptor, node string, preferred [32]byte, recover bool) (LifecycleProvider, error) {
	p, err := p.Current(s)
	if err != nil {
		return LifecycleProvider{}, err
	}
	if d.Validate() != nil || node != "" && !validID(node) || recover && node == "" {
		return LifecycleProvider{}, access.ErrInvalid
	}
	members, err := p.Members(s)
	if err != nil {
		return LifecycleProvider{}, err
	}
	var candidates []LifecycleProvider
	for _, entry := range members.Entries {
		if node != "" && entry.Peer.ID != node {
			continue
		}
		owner, err := p.nodeOwner(s, entry.Peer.ID)
		if err != nil {
			continue
		}
		permit, err := p.LifecycleSourcePermit(s, owner, LifecycleSourcePermitRequest{Session: session, Source: d, At: at, Recover: recover})
		if err == nil && permit.Provider == owner {
			candidates = append(candidates, LifecycleProvider{entry.Peer.ID, owner})
		}
	}
	sort.Slice(candidates, func(i, j int) bool {
		a, b := candidates[i], candidates[j]
		if (a.Owner == preferred) != (b.Owner == preferred) {
			return a.Owner == preferred
		}
		return a.Node < b.Node
	})
	if len(candidates) == 0 {
		return LifecycleProvider{}, access.ErrDenied
	}
	return candidates[0], nil
}

type LifecycleSourceQuery struct {
	Name     string
	Revision uint64
	Offset   uint64
}

func (q LifecycleSourceQuery) Valid() bool {
	return checker.ValidScriptName(q.Name) && q.Revision > 0 && q.Offset <= checker.MaxScriptBytes && q.Offset%checker.SourcePageBytes == 0
}

type LifecycleSourceRead struct {
	Session access.Session
	Tenant  string
	Query   LifecycleSourceQuery
	Source  checker.SourceFact
	Epoch   uint64
}

func (p Policy) LifecycleSourceVersion(s state.State, session access.Session, at int64, tenant string, q LifecycleSourceQuery) (LifecycleSourceRead, error) {
	p, err := p.Current(s)
	if err != nil {
		return LifecycleSourceRead{}, err
	}
	if !validID(tenant) || !q.Valid() {
		return LifecycleSourceRead{}, access.ErrInvalid
	}
	users, err := p.Catalog(s)
	if err != nil || users.AuthorizeSessionCleanup(session, p.Cluster, p.Issuer(session.Issuer), at, tenant, access.ManageServices) != nil || users.OperationAllowed(session, "lifecycle-source") != nil {
		return LifecycleSourceRead{}, access.ErrDenied
	}
	book, err := p.Lifecycles(s)
	if err != nil {
		return LifecycleSourceRead{}, err
	}
	record, found := book.Script(tenant, q.Name)
	if !found {
		return LifecycleSourceRead{}, ErrLifecycleSourceMissing
	}
	for _, version := range record.Versions {
		if version.Revision != q.Revision || version.Deleted {
			continue
		}
		if q.Offset >= version.Source.Length {
			return LifecycleSourceRead{}, access.ErrInvalid
		}
		if p.currentResourceKey(s, version.Source.Owner, false) == ([32]byte{}) {
			return LifecycleSourceRead{}, access.ErrConflict
		}
		return LifecycleSourceRead{session, tenant, q, version.Source.Clone(), s.ModuleEpoch()}, nil
	}
	return LifecycleSourceRead{}, ErrLifecycleSourceMissing
}
func (p Policy) LifecycleSourceReadPermit(s state.State, caller [32]byte, read LifecycleSourceRead, at int64) (uint64, error) {
	current, err := p.LifecycleSourceVersion(s, read.Session, at, read.Tenant, read.Query)
	if err != nil {
		return 0, err
	}
	members, err := p.Members(s)
	if err != nil || !members.MemberKey(caller) {
		return 0, access.ErrDenied
	}
	if read.Source.Verify() != nil || string(checker.SourceFactBytes(read.Source)) != string(checker.SourceFactBytes(current.Source)) || read.Epoch != current.Epoch || read.Source.ContentDigest() != current.Source.ContentDigest() || read.Source.Owner != current.Source.Owner || string(read.Source.Signature) != string(current.Source.Signature) {
		return 0, access.ErrDenied
	}
	return s.Index(), nil
}
