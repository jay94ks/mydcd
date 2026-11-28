// SPDX-License-Identifier: Apache-2.0

package control

import "testing"

func TestNodeLogsQueryValid(t *testing.T) {
	ok := NodeLogsQuery{Node: "node-a", App: "web", Tail: 200, Stdout: true, Stderr: true}
	if !ok.Valid() {
		t.Fatal("valid query rejected")
	}
	for _, mutate := range []func(*NodeLogsQuery){
		func(q *NodeLogsQuery) { q.Node = "../node" },
		func(q *NodeLogsQuery) { q.Container = "web" },
		func(q *NodeLogsQuery) { q.App = "" },
		func(q *NodeLogsQuery) { q.App, q.Container = "", "a/b" },
		func(q *NodeLogsQuery) { q.Tail = 10001 },
		func(q *NodeLogsQuery) { q.After = 3 },
		func(q *NodeLogsQuery) { q.Stdout, q.Stderr = false, false },
		func(q *NodeLogsQuery) { q.Since = "yesterday" },
		func(q *NodeLogsQuery) { q.Wait, q.Until = true, "2026-11-28T00:00:00Z" },
	} {
		q := ok
		mutate(&q)
		if q.Valid() {
			t.Fatal("invalid query accepted", q)
		}
	}
}

func TestNodeLogsPageValid(t *testing.T) {
	q := NodeLogsQuery{Node: "node-a", Container: "abcd", After: 4, Stdout: true}
	line := func(seq uint64) NodeLogLine {
		return NodeLogLine{Seq: seq, Time: "2026-11-28T00:00:00Z", Data: []byte("x")}
	}
	ok := NodeLogsPage{Schema: 1, Code: "ok", Node: "node-a", Lines: []NodeLogLine{line(5), line(7)}, Next: 7}
	if !ok.Valid(q) {
		t.Fatal("valid page rejected")
	}
	for _, mutate := range []func(*NodeLogsPage){
		func(p *NodeLogsPage) { p.Node = "node-b" },
		func(p *NodeLogsPage) { p.Code = "maybe" },
		func(p *NodeLogsPage) { p.Code = "not-found" },
		func(p *NodeLogsPage) { p.Lines = []NodeLogLine{line(4)} },
		func(p *NodeLogsPage) { p.Lines = []NodeLogLine{line(7), line(6)} },
		func(p *NodeLogsPage) { p.Next = 6 },
		func(p *NodeLogsPage) { p.Lines = []NodeLogLine{{Seq: 5, Time: "now"}} },
		func(p *NodeLogsPage) {
			p.Lines = []NodeLogLine{{Seq: 5, Time: "2026-11-28T00:00:00Z", Data: make([]byte, NodeLogsMaxBytes+1)}}
		},
	} {
		p := ok
		mutate(&p)
		if p.Valid(q) {
			t.Fatal("invalid page accepted", p)
		}
	}
}
