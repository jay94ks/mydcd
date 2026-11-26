// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/sha256"
	"encoding/json"
	"slices"
	"strings"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/identity"
	"github.com/jay94ks/mydcd/internal/observability"
)

// Pulls are actual latest owner measurements, not an image permission, a login
// probe, or a promise of current registry availability. No private grant leaves
// the owner. A deleted source can still have a historical outcome.
type RegistryPullView struct {
	observability.RegistryPull
	Node       string
	ReportedAt uint64
	Stale      bool
}
type RegistryPullPage struct {
	Schema uint8
	Tenant string
	Root   [32]byte
	Index  uint64
	Rows   []RegistryPullView
	Next   string
}

func (p RegistryPullPage) Valid(tenant, after string) bool {
	if p.Schema != 1 || p.Tenant != tenant || !validID(tenant) || p.Root == ([32]byte{}) || p.Index == 0 || len(p.Rows) > 8 {
		return false
	}
	offset, err := taskCursor(after, p.Root)
	if err != nil {
		return false
	}
	last := ""
	for _, row := range p.Rows {
		key := row.Authority + "\x00" + row.Node
		if row.Tenant != tenant || !validID(row.Node) || !row.RegistryPull.Valid(row.ReportedAt) || key <= last {
			return false
		}
		last = key
	}
	return p.Next == "" || len(p.Rows) == 8 && offset <= ^uint32(0)-8 && p.Next == nextTaskCursor(p.Root, offset+8)
}

func (p Policy) RegistryPulls(s state.State, session access.Session, at int64, tenant, after string, reports []observability.Report) (RegistryPullPage, error) {
	current, err := p.Current(s)
	if err != nil {
		return RegistryPullPage{}, err
	}
	c, err := current.Catalog(s)
	if err != nil {
		return RegistryPullPage{}, err
	}
	if _, exists := c.Tenant(tenant); !exists || !validID(tenant) || at <= 0 ||
		c.AuthorizeSession(session, p.Cluster, current.Issuer(session.Issuer), at, tenant, access.Read, "") != nil && c.AuthorizeSession(session, p.Cluster, current.Issuer(session.Issuer), at, tenant, access.ManageRegistry, "") != nil {
		return RegistryPullPage{}, access.ErrDenied
	}
	directory, err := current.Members(s)
	if err != nil {
		return RegistryPullPage{}, err
	}
	latest := map[string]observability.Report{}
	for _, report := range reports {
		pull := report.RegistryPull
		if pull == nil || pull.Tenant != tenant || report.Cluster != p.Cluster || report.Index > s.Index() || report.At > uint64(at)*1000 || !report.Valid() {
			continue
		}
		entry, exists := directory.Entry(report.Node)
		key, err := identity.ParseKey(entry.CurrentPeer().Key)
		if !exists || err != nil || key != report.Key || !directory.MemberKey(key) {
			continue
		}
		id := report.Node + "/" + report.Source()
		previous, exists := latest[id]
		if !exists || previous.RegistryPull.Sequence < pull.Sequence || previous.RegistryPull.Sequence == pull.Sequence && *previous.RegistryPull == *pull && previous.At < report.At {
			latest[id] = report
		}
	}
	rows := make([]RegistryPullView, 0, len(latest))
	for _, report := range latest {
		rows = append(rows, RegistryPullView{RegistryPull: *report.RegistryPull, Node: report.Node, ReportedAt: report.At})
	}
	slices.SortFunc(rows, func(a, b RegistryPullView) int {
		return strings.Compare(a.Authority+"\x00"+a.Node, b.Authority+"\x00"+b.Node)
	})
	// No hidden tenant rows, unrelated Raft index or wall-clock stale bit enters
	// the page identity. Changed actual outcomes/sample envelopes conflict.
	raw, _ := json.Marshal(struct {
		Cluster      [32]byte
		Tenant, User string
		Scopes       []access.Scope
		Rows         []RegistryPullView
	}{p.Cluster, tenant, session.User, session.Scopes, rows})
	root := sha256.Sum256(append([]byte("mydc-registry-pulls-page-1\x00"), raw...))
	start, end, err := observationPage(after, root, len(rows))
	if err != nil {
		return RegistryPullPage{}, err
	}
	page := RegistryPullPage{Schema: 1, Tenant: tenant, Root: root, Index: s.Index(), Rows: rows[start:end]}
	for i := range page.Rows {
		page.Rows[i].Stale = !observability.Fresh(page.Rows[i].ReportedAt, uint64(at)*1000)
	}
	if end < len(rows) {
		page.Next = nextTaskCursor(root, uint32(end))
	}
	return page, nil
}
