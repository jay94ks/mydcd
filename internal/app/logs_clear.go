// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/containerops"
	"github.com/jay94ks/seafield/internal/eventlog"
	"github.com/jay94ks/seafield/internal/identity"
	"github.com/jay94ks/seafield/internal/logstore"
	"github.com/jay94ks/seafield/internal/schema"
	"github.com/jay94ks/seafield/internal/sfcp"
)

// logsClearWait bounds one server's answer; a server that does not answer
// in time is reported as unreachable and the user sends the clear again.
const logsClearWait = 15 * time.Second

// clearLogs sends a clear to every member server, this one included, and
// returns each server's answer (devel/proposals/seafield-log-clear.md).
// There is no Raft command: a server that is down keeps its logs until the
// user sends the clear again.
func (r *Runtime) clearLogs(ctx context.Context, session access.Session, q control.LogsClear) ([]control.LogsClearNode, error) {
	relay := control.LogsClearRelay{Session: session, Query: q, At: time.Now().UnixNano()}
	if !relay.Valid() {
		return nil, sfcp.ErrAdmission
	}
	return eachLogServer(ctx, r, "", "logs-clear-node", relay,
		func(ctx context.Context) control.LogsClearNode { return r.clearLocalLogs(ctx, relay) },
		func(node, code string) control.LogsClearNode { return control.LogsClearNode{Node: node, Code: code} },
		func(n control.LogsClearNode) string { return n.Node })
}

// eachLogServer asks every member server (or only the one named only)
// over method with input, this server directly, and returns one answer
// per server sorted by name. A server it cannot reach in time answers
// "unreachable"; one whose answer does not decode, "unavailable".
func eachLogServer[T any](ctx context.Context, r *Runtime, only, method string, input any, local func(context.Context) T, failed func(node, code string) T, nodeOf func(T) string) ([]T, error) {
	_, d, err := r.members(ctx, false)
	if err != nil {
		return nil, err
	}
	raw, err := json.Marshal(input)
	if err != nil {
		return nil, err
	}
	var (
		mu  sync.Mutex
		out []T
		wg  sync.WaitGroup
	)
	add := func(n T) {
		mu.Lock()
		out = append(out, n)
		mu.Unlock()
	}
	for _, entry := range d.Entries {
		key, err := identity.ParseKey(entry.CurrentPeer().Key)
		id := entry.Peer.ID
		if err != nil || !d.MemberKey(key) || only != "" && id != only {
			continue
		}
		if key == r.Identity.Public {
			add(local(ctx))
			continue
		}
		peer, ok := r.Mesh.Peer(sfcp.Identity(key))
		if !ok || !peer.Member || peer.ID != id {
			add(failed(id, "unreachable"))
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(ctx, logsClearWait)
			defer cancel()
			reply, err := cluster.CallManagement(ctx, r.Mesh, r.Identity, r.controlPolicy.Cluster, peer, cluster.ManagementRequest{Method: method, Input: raw})
			if err != nil {
				add(failed(id, "unreachable"))
				return
			}
			n, err := schema.Decode[T](reply.Data)
			if err != nil || nodeOf(n) != id {
				add(failed(id, "unavailable"))
				return
			}
			add(n)
		}()
	}
	wg.Wait()
	if only != "" && len(out) == 0 {
		return nil, sfcp.ErrAdmission
	}
	sort.Slice(out, func(i, j int) bool { return nodeOf(out[i]) < nodeOf(out[j]) })
	return out, nil
}

// storedLogs lists what the servers' log stores keep for a
// selection, including logs of containers that are gone. Each server
// checks the session's Read on itself against its own applied state.
func (r *Runtime) storedLogs(ctx context.Context, session access.Session, q control.StoredLogsQuery) ([]control.StoredLogsNode, error) {
	relay := control.StoredLogsRelay{Session: session, Query: q}
	if !q.Valid() {
		return nil, sfcp.ErrAdmission
	}
	return eachLogServer(ctx, r, q.Node, "stored-logs-node", relay,
		func(ctx context.Context) control.StoredLogsNode { return r.localStoredLogs(ctx, relay) },
		func(node, code string) control.StoredLogsNode { return control.StoredLogsNode{Node: node, Code: code} },
		func(n control.StoredLogsNode) string { return n.Node })
}

func (r *Runtime) localStoredLogs(ctx context.Context, relay control.StoredLogsRelay) control.StoredLogsNode {
	self := r.Engine().ObservedNodeID()
	out := control.StoredLogsNode{Node: self, Code: "unavailable"}
	q := relay.Query
	if r.logs == nil || !q.Valid() || q.Node != "" && q.Node != self {
		return out
	}
	view, err := r.Engine().Read(ctx, false)
	if err != nil {
		return out
	}
	match, err := r.controlPolicy.LogsScope(view.State, relay.Session, time.Now().Unix(), q.LogsClear, access.Read, self)
	if errors.Is(err, access.ErrDenied) {
		out.Code = "denied"
		return out
	}
	if errors.Is(err, containerops.ErrTarget) {
		// A standalone whose record is gone: nothing left to match.
		return control.StoredLogsNode{Node: self, Code: "ok"}
	}
	if err != nil {
		return out
	}
	all, err := r.logs.List()
	if err != nil {
		return out
	}
	res := control.StoredLogsNode{Node: self, Code: "ok"}
	for _, in := range all {
		if !match.Matches(in.Tenant, in.App, in.Service, in.Key) {
			continue
		}
		lines := uint64(0)
		if in.Last >= in.First && in.Last > 0 {
			lines = in.Last - in.First + 1
		}
		res.Logs = append(res.Logs, control.StoredLog{Container: in.Container, Name: in.Name, Service: in.Service, Key: in.Key, Lines: lines, Size: in.Size})
	}
	return res
}

// clearLocalLogs clears this server's stored logs for the relay's
// selection after checking the session's Deploy on this server against
// this server's own applied state.
func (r *Runtime) clearLocalLogs(ctx context.Context, relay control.LogsClearRelay) control.LogsClearNode {
	self := r.Engine().ObservedNodeID()
	out := control.LogsClearNode{Node: self, Code: "unavailable"}
	if r.logs == nil || !relay.Valid() {
		return out
	}
	view, err := r.Engine().Read(ctx, false)
	if err != nil {
		return out
	}
	match, err := r.controlPolicy.LogsScope(view.State, relay.Session, time.Now().Unix(), relay.Query, access.Deploy, self)
	if errors.Is(err, access.ErrDenied) {
		out.Code = "denied"
		return out
	}
	if errors.Is(err, containerops.ErrTarget) {
		// A standalone whose record is gone: nothing left to match.
		return control.LogsClearNode{Node: self, Code: "ok"}
	}
	if err != nil {
		return out
	}
	// The entry server's clock may run ahead of this one; never clear past
	// this server's own now, or new lines stamped here would be dropped.
	at := time.Unix(0, min(relay.At, time.Now().UnixNano()))
	logs, removed, err := r.logs.TrimWhere(func(m logstore.Meta) bool { return match.Matches(m.Tenant, m.App, m.Service, m.Key) }, at)
	if err != nil {
		return out
	}
	r.recordLogsClear(self, relay, match, removed)
	return control.LogsClearNode{Node: self, Code: "ok", Containers: logs, Removed: removed}
}

// recordLogsClear keeps who cleared what in this server's diagnostic
// record only; there is no cluster audit record for a clear.
func (r *Runtime) recordLogsClear(self string, relay control.LogsClearRelay, match control.LogsClearMatch, removed int) {
	if r.events == nil {
		return
	}
	now := uint64(time.Now().UnixMilli())
	e := eventlog.Event{Kind: "container-logs-cleared", Scope: "app", At: now, Target: eventlog.Target{Tenant: match.Tenant, App: match.Scope, Service: match.Service, Task: match.Instance, Node: self}, Detail: eventlog.Detail{Actor: relay.Session.User, Value: uint64(removed)}}
	_, _ = r.events.Append(fmt.Sprintf("logs-clear/%s/%d", relay.Session.ID, relay.At), e, now)
}

func (r *Runtime) nodeReadLogsClear(ctx context.Context, method, key string, input []byte, v cluster.View) (json.RawMessage, error) {
	caller, err := identity.ParseKey(key)
	if err != nil {
		return nil, err
	}
	if peer, ok := r.Mesh.Peer(sfcp.Identity(caller)); !ok || !peer.Member {
		return nil, sfcp.ErrAdmission
	}
	relay, err := schema.Decode[control.LogsClearRelay](input)
	if err != nil || !relay.Valid() {
		return nil, sfcp.ErrAdmission
	}
	return json.Marshal(r.clearLocalLogs(ctx, relay))
}

func (r *Runtime) nodeReadStoredLogs(ctx context.Context, method, key string, input []byte, v cluster.View) (json.RawMessage, error) {
	caller, err := identity.ParseKey(key)
	if err != nil {
		return nil, err
	}
	if peer, ok := r.Mesh.Peer(sfcp.Identity(caller)); !ok || !peer.Member {
		return nil, sfcp.ErrAdmission
	}
	relay, err := schema.Decode[control.StoredLogsRelay](input)
	if err != nil || !relay.Query.Valid() {
		return nil, sfcp.ErrAdmission
	}
	return json.Marshal(r.localStoredLogs(ctx, relay))
}

func init() {
	defineNodeRead((*Runtime).nodeReadLogsClear, true, "logs-clear-node")
	defineNodeRead((*Runtime).nodeReadStoredLogs, true, "stored-logs-node")
}
