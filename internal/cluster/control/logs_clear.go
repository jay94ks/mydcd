// SPDX-License-Identifier: Apache-2.0

package control

import (
	"strings"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/lifecycle"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/containerops"
)

// LogsClear asks each server to clear its stored logs for a selection
// (devel/proposals/seafield-log-clear.md). Logs live only in each server's
// sfcd log store, so this is a direct request to every server and never a
// Raft command: containers are not touched and nothing is recreated.
//
// Service may be empty to clear every service of the app or standalone.
// Instance, when set, is one task key.
type LogsClear struct {
	Tenant    string
	Selection containerops.Selection
}

func (q LogsClear) Valid() bool {
	s := q.Selection
	if !lifecycle.ValidID(q.Tenant) {
		return false
	}
	owner := s.Standalone == "" && lifecycle.ValidID(s.App) || s.App == "" && lifecycle.ValidID(s.Standalone)
	return owner && (s.Service == "" || lifecycle.ValidID(s.Service)) && len(s.Instance) <= 512 && !strings.ContainsAny(s.Instance, "\x00\r\n") && (s.Instance == "" || strings.HasPrefix(s.Instance, "workload/task/"))
}

// LogsClearRelay is what the entry server sends to each server. The
// receiving server checks Session again against its own applied state.
type LogsClearRelay struct {
	Session access.Session
	Query   LogsClear
	// At is when the user asked (Unix nanoseconds). Records at or before it
	// are cleared, and lines the engine still queues from before it are
	// dropped when they arrive.
	At int64
}

func (r LogsClearRelay) Valid() bool {
	return r.Query.Valid() && r.At > 0
}

// LogsClearReply lists every member server's answer, by server name.
type LogsClearReply struct {
	Nodes []LogsClearNode
}

// LogsClearNode is one server's answer. Code is "ok", "denied",
// "unreachable" or "unavailable". Containers counts the stored logs that
// matched, Removed the records removed from them.
type LogsClearNode struct {
	Node                string
	Code                string
	Containers, Removed int `json:",omitempty"`
}

// LogsClearMatch is the selection as a test on a stored log's Meta
// (tenant, internal app scope, service, task key).
type LogsClearMatch struct {
	Tenant, Scope, Service, Instance string
}

func (m LogsClearMatch) Matches(tenant, app, service, key string) bool {
	return tenant == m.Tenant && app == m.Scope && (m.Service == "" || service == m.Service) && (m.Instance == "" || key == m.Instance)
}

// LogsScope authorizes action on node against s and resolves the
// selection's internal app scope. The entry server checks the tenant-wide
// Read (node "") before it passes a request on; each server then checks
// Deploy (a clear) or Read (a stored-log read) for itself. An app that is
// gone still matches its leftover logs; a standalone resolves only while
// its record exists.
func (p Policy) LogsScope(s state.State, session access.Session, at int64, q LogsClear, action access.Action, node string) (LogsClearMatch, error) {
	var out LogsClearMatch
	tenant := q.Tenant
	if !q.Valid() {
		return out, access.ErrDenied
	}
	var err error
	p, err = p.Current(s)
	if err != nil {
		return out, err
	}
	catalog, err := p.Catalog(s)
	if err != nil {
		return out, err
	}
	if catalog.AuthorizeSession(session, p.Cluster, p.Issuer(session.Issuer), at, tenant, action, node) != nil {
		return out, access.ErrDenied
	}
	apps, err := p.readOnlyApps(s)
	if err != nil {
		return out, err
	}
	scope := q.Selection.App
	if q.Selection.Standalone != "" {
		var ok bool
		if scope, ok = apps.StandaloneScope(tenant, q.Selection.Standalone); !ok {
			return out, containerops.ErrTarget
		}
	} else if apps.IsStandalone(tenant, scope) {
		return out, access.ErrDenied
	}
	if q.Selection.Instance != "" && !strings.HasPrefix(q.Selection.Instance, "workload/task/"+tenant+"/"+scope+"/") {
		return out, containerops.ErrTarget
	}
	return LogsClearMatch{Tenant: tenant, Scope: scope, Service: q.Selection.Service, Instance: q.Selection.Instance}, nil
}

// StoredLogsQuery lists what the servers' log stores keep for a
// selection, including logs of containers that are gone: every member
// server, or only Node. Lines are read through container-observe while the
// container exists; a gone container's lines are not served, since its
// secret values can no longer be looked up to hide them.
type StoredLogsQuery struct {
	LogsClear
	Node string `json:",omitempty"`
}

func (q StoredLogsQuery) Valid() bool {
	return q.LogsClear.Valid() && (q.Node == "" || lifecycle.ValidID(q.Node))
}

// StoredLogsRelay is what the entry server sends to a server.
type StoredLogsRelay struct {
	Session access.Session
	Query   StoredLogsQuery
}

// StoredLog is one stored container log. Lines counts the records the
// store holds now.
type StoredLog struct {
	Container, Name, Service, Key string
	Lines                         uint64
	Size                          int64
}

// StoredLogsNode is one server's answer (Code as in LogsClearNode).
type StoredLogsNode struct {
	Node string
	Code string
	Logs []StoredLog `json:",omitempty"`
}

// StoredLogsReply lists the answering servers by name.
type StoredLogsReply struct {
	Nodes []StoredLogsNode
}
