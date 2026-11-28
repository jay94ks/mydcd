// SPDX-License-Identifier: Apache-2.0

package control

import (
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jay94ks/seafield/internal/cluster/lifecycle"
)

// NodeLogsMaxBytes bounds the log text in one NodeLogsPage.
const NodeLogsMaxBytes = 64 << 10

// NodeLogsWait is how long a Wait read holds for a new line before it
// answers an empty page with the same Next.
const NodeLogsWait = 15 * time.Second

// NodeLogsQuery reads the stored log of one container on one server: a
// cluster app's (App, e.g. "web") or any container's by name or ID
// (Container). It is for system administrators (ManageCluster), like the
// server's diagnostics, and reads what that server's sfcd keeps, so a
// container that is already gone can still be read.
type NodeLogsQuery struct {
	Node       string
	App        string `json:",omitempty"`
	Container  string `json:",omitempty"`
	Tail       int    `json:",omitempty"`
	Since      string `json:",omitempty"`
	Until      string `json:",omitempty"`
	Stdout     bool
	Stderr     bool
	Timestamps bool `json:",omitempty"`
	// After continues from the Next of an earlier page (lines with a
	// larger sequence number). Wait holds the read until a line arrives
	// or NodeLogsWait passes.
	After uint64 `json:",omitempty"`
	Wait  bool   `json:",omitempty"`
}

func (q NodeLogsQuery) Valid() bool {
	if !lifecycle.ValidID(q.Node) || (q.App == "") == (q.Container == "") || q.App != "" && !lifecycle.ValidID(q.App) || !validLogContainer(q.Container) {
		return false
	}
	if q.Tail < 0 || q.Tail > 10000 || q.After != 0 && q.Tail != 0 || !q.Stdout && !q.Stderr || q.Wait && q.Until != "" {
		return false
	}
	for _, t := range []string{q.Since, q.Until} {
		if _, err := time.Parse(time.RFC3339Nano, t); t != "" && err != nil {
			return false
		}
	}
	return true
}

func validLogContainer(name string) bool {
	return name == "" || len(name) <= 128 && utf8.ValidString(name) && !strings.ContainsAny(name, "\x00\r\n/ ")
}

// NodeLogsRead is what the entry server sends to the server that keeps the
// log: the checked diagnostics read (session, owner, barrier) and the query.
type NodeLogsRead struct {
	Read  NodeDiagnosticsRead
	Query NodeLogsQuery
}

func (r NodeLogsRead) Valid() bool { return r.Query.Valid() && r.Read.Node == r.Query.Node }

// NodeLogLine is one stored line. Data has no trailing newline; Partial is
// a line the container wrote without one.
type NodeLogLine struct {
	Seq     uint64
	Time    string
	Stderr  bool `json:",omitempty"`
	Partial bool `json:",omitempty"`
	Data    []byte
}

// NodeLogsPage is one page of a container's stored log. Next is the
// sequence number to send as After for the following page. Code is "ok",
// "not-found" (no stored log matches) or "ambiguous" (Container names
// several; give more of the ID).
type NodeLogsPage struct {
	Schema    uint8
	Code      string
	Node      string
	Container string `json:",omitempty"`
	Name      string `json:",omitempty"`
	Lines     []NodeLogLine
	Next      uint64
	More      bool `json:",omitempty"`
}

func (p NodeLogsPage) Valid(q NodeLogsQuery) bool {
	if p.Schema != 1 || p.Node != q.Node || len(p.Lines) > 100000 {
		return false
	}
	switch p.Code {
	case "ok":
	case "not-found", "ambiguous":
		return len(p.Lines) == 0
	default:
		return false
	}
	size, last := 0, q.After
	for _, line := range p.Lines {
		if line.Seq <= last {
			return false
		}
		if _, err := time.Parse(time.RFC3339Nano, line.Time); err != nil {
			return false
		}
		last, size = line.Seq, size+len(line.Data)
	}
	return size <= NodeLogsMaxBytes && p.Next >= last
}
