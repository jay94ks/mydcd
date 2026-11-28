// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/containerops"
	"github.com/jay94ks/seafield/internal/identity"
	"github.com/jay94ks/seafield/internal/logstore"
	"github.com/jay94ks/seafield/internal/schema"
	"github.com/jay94ks/seafield/internal/sfcp"
)

// nodeLogs answers a node-logs read here when this server keeps the log,
// else asks the owner over Management (as nodeDiagnostics does).
func (r *Runtime) nodeLogs(ctx context.Context, read control.NodeLogsRead) (control.NodeLogsPage, error) {
	if !read.Valid() {
		return control.NodeLogsPage{}, sfcp.ErrAdmission
	}
	if read.Read.Owner == r.Identity.Public {
		return r.nodeLogsLocal(ctx, read)
	}
	peer, ok := r.Mesh.Peer(sfcp.Identity(read.Read.Owner))
	if !ok || !peer.Member || peer.ID != read.Read.Node {
		return control.NodeLogsPage{}, sfcp.ErrAdmission
	}
	raw, _ := json.Marshal(read)
	reply, err := cluster.CallManagement(ctx, r.Mesh, r.Identity, r.controlPolicy.Cluster, peer, cluster.ManagementRequest{Method: "node-logs-owner", Input: raw})
	if err != nil {
		return control.NodeLogsPage{}, err
	}
	page, err := schema.Decode[control.NodeLogsPage](reply.Data)
	if err != nil || !page.Valid(read.Query) {
		return page, sfcp.ErrAdmission
	}
	return page, nil
}

func (r *Runtime) nodeLogsLocal(ctx context.Context, read control.NodeLogsRead) (control.NodeLogsPage, error) {
	if _, _, err := r.currentNodeRead(ctx, read.Read); err != nil {
		return control.NodeLogsPage{}, err
	}
	q := read.Query
	page := control.NodeLogsPage{Schema: 1, Code: "not-found", Node: q.Node, Next: q.After, Lines: []control.NodeLogLine{}}
	if r.logs == nil {
		return page, nil
	}
	info, code, err := findNodeLog(r.logs, q)
	if err != nil {
		return control.NodeLogsPage{}, err
	}
	if code != "ok" {
		page.Code = code
		return page, nil
	}
	page.Code, page.Container, page.Name = "ok", info.Container, info.Name
	return readNodeLog(ctx, r.logs, info.Container, q, page)
}

// findNodeLog picks the stored log the query names. A cluster app has one
// log per container generation, and a container name can repeat across
// generations: the newest of those (the most recent line) wins. An ID
// prefix must name exactly one log.
func findNodeLog(store *logstore.Store, q control.NodeLogsQuery) (logstore.Info, string, error) {
	all, err := store.List()
	if err != nil {
		return logstore.Info{}, "", err
	}
	var named, prefixed []logstore.Info
	for _, in := range all {
		switch {
		case q.App != "" && in.Key == containerops.ClusterAppKeyPrefix+q.App:
			named = append(named, in)
		case q.Container != "" && (in.Name == q.Container || in.Container == q.Container):
			named = append(named, in)
		case q.Container != "" && len(q.Container) >= 4 && strings.HasPrefix(in.Container, q.Container):
			prefixed = append(prefixed, in)
		}
	}
	if len(named) == 0 {
		switch len(prefixed) {
		case 0:
			return logstore.Info{}, "not-found", nil
		case 1:
			return prefixed[0], "ok", nil
		}
		return logstore.Info{}, "ambiguous", nil
	}
	newest, at := named[0], lastTime(store, named[0])
	for _, in := range named[1:] {
		if t := lastTime(store, in); t.After(at) {
			newest, at = in, t
		}
	}
	return newest, "ok", nil
}

func lastTime(store *logstore.Store, in logstore.Info) time.Time {
	var t time.Time
	if in.Last == 0 {
		return t
	}
	_, _ = store.Read(in.Container, in.Last-1, func(r logstore.Record) bool {
		t = r.Time
		return false
	})
	return t
}

// readNodeLog fills one page: the last Tail lines on a first read, or the
// lines after q.After. A Wait read with nothing new holds until a line
// arrives or NodeLogsWait passes.
func readNodeLog(ctx context.Context, store *logstore.Store, id string, q control.NodeLogsQuery, page control.NodeLogsPage) (control.NodeLogsPage, error) {
	var since, until time.Time
	if q.Since != "" {
		since, _ = time.Parse(time.RFC3339Nano, q.Since)
	}
	if q.Until != "" {
		until, _ = time.Parse(time.RFC3339Nano, q.Until)
	}
	wants := func(rec logstore.Record) bool {
		if rec.Stderr && !q.Stderr || !rec.Stderr && !q.Stdout {
			return false
		}
		return (since.IsZero() || !rec.Time.Before(since)) && (until.IsZero() || !rec.Time.After(until))
	}
	after := q.After
	if after == 0 && q.Tail > 0 {
		ring := make([]uint64, 0, q.Tail)
		if _, err := store.Read(id, 0, func(rec logstore.Record) bool {
			if wants(rec) {
				if len(ring) == q.Tail {
					ring = ring[1:]
				}
				ring = append(ring, rec.Seq)
			}
			return true
		}); err != nil {
			return control.NodeLogsPage{}, err
		}
		if len(ring) > 0 {
			after = ring[0] - 1
		} else {
			after = store.Last(id)
		}
	}
	page.Next = after
	deadline := time.NewTimer(control.NodeLogsWait)
	defer deadline.Stop()
	for {
		size := 0
		changed, err := store.Read(id, page.Next, func(rec logstore.Record) bool {
			if !wants(rec) {
				page.Next = rec.Seq
				return true
			}
			// A line longer than a whole page is cut to one page, so every
			// page moves Next forward.
			data, partial := rec.Data, rec.Partial
			if len(data) > control.NodeLogsMaxBytes {
				data, partial = data[:control.NodeLogsMaxBytes], true
			}
			if size+len(data) > control.NodeLogsMaxBytes {
				page.More = true
				return false
			}
			page.Next = rec.Seq
			size += len(data)
			page.Lines = append(page.Lines, control.NodeLogLine{Seq: rec.Seq, Time: rec.Time.UTC().Format(time.RFC3339Nano), Stderr: rec.Stderr, Partial: partial, Data: data})
			return true
		})
		if errors.Is(err, logstore.ErrNotFound) {
			page.Code, page.Lines, page.Next = "not-found", []control.NodeLogLine{}, q.After
			return page, nil
		}
		if err != nil {
			return control.NodeLogsPage{}, err
		}
		if len(page.Lines) > 0 || page.More || !q.Wait {
			return page, nil
		}
		select {
		case <-changed:
		case <-deadline.C:
			return page, nil
		case <-ctx.Done():
			return page, nil
		}
	}
}

func (r *Runtime) nodeReadNodeLogs(ctx context.Context, method, key string, input []byte, v cluster.View) (json.RawMessage, error) {
	caller, err := identity.ParseKey(key)
	read, decodeErr := schema.Decode[control.NodeLogsRead](input)
	d, memberErr := r.controlPolicy.Members(v.State)
	if err != nil || decodeErr != nil || memberErr != nil || !d.MemberKey(caller) || !read.Valid() {
		return nil, sfcp.ErrAdmission
	}
	page, err := r.nodeLogsLocal(ctx, read)
	if err != nil {
		return nil, err
	}
	return json.Marshal(page)
}

func init() {
	defineNodeRead((*Runtime).nodeReadNodeLogs, true, "node-logs-owner")
}
