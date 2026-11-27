// SPDX-License-Identifier: Apache-2.0

// Package eventlog stores bounded diagnostic facts. It neither authorizes
// effects nor orders management state; Raft remains the management authority.
package eventlog

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/jay94ks/seafield/internal/cluster/lifecycle"
)

var (
	ErrInvalid       = errors.New("invalid observation event")
	ErrCursorExpired = errors.New("CURSOR_EXPIRED")
	ErrUnavailable   = errors.New("event history unavailable")
)

const (
	MaxRecordBytes  = 8 << 10
	MaxRecords      = 4096
	RetentionMillis = uint64(7 * 24 * 60 * 60 * 1000)
	MaxBatch        = 8
)

type Target struct {
	Gateway, RouteID, Host, Prefix            string `json:",omitempty"`
	Tenant, App, Service, Deployment, Network string `json:",omitempty"`
	Task, Native, Node                        string `json:",omitempty"`
	Generation, Revision                      uint64 `json:",omitempty"`
	FilesystemID, PairID                      string `json:",omitempty"`
	Term                                      uint64 `json:",omitempty"`
}

// Detail is an allowlist. Native errors, logs, argv, environment, probe output,
// provider bodies and arbitrary maps cannot become event detail fields.
type ActorIdentity struct {
	User, Username string
}

type Detail struct {
	ClosedBy                            *ActorIdentity `json:",omitempty"`
	BytesIn, BytesOut                   uint64         `json:",omitempty"`
	Value                               uint64         `json:",omitempty"`
	Reason, OperatorReason, Code, Actor string         `json:",omitempty"`
	IncidentID, ApprovedBy, Operation   string         `json:",omitempty"`
	CandidateID, Commit                 string         `json:",omitempty"`
	FromVersion, ToVersion              uint64         `json:",omitempty"`
	ExitCode                            *int           `json:",omitempty"`
	Checker, RunID                      string         `json:",omitempty"`
	ConsecutiveFailures                 uint32         `json:",omitempty"`
	Resource, State                     string         `json:",omitempty"`
}

type Event struct {
	Kind, Scope string
	Authority   string `json:",omitempty"` // public committed-transition identity, not a chain
	At          uint64 // source Unix milliseconds
	Target      Target
	Detail      Detail
}

func ValidKind(kind string) bool {
	return slices.Contains([]string{"node-shell-opened", "node-shell-closed", "node-shell-denied", "standalone-extended", "task-restarted", "task-exited", "probe-failed", "node-unreachable", "node-resource-low", "tunnel-down", "tunnel-up", "registry-stopped", "quorum-degraded", "cert-expiring", "event-source-gap",
		"cd-candidate-created", "cd-approval-required", "cd-approved", "cd-rejected", "cd-sync-started", "cd-sync-succeeded", "cd-sync-failed", "cd-drift-detected", "cd-paused", "cd-resumed", "cd-rolled-back",
		"raft-compact-started", "raft-compact-completed", "node-cache-cleaned", "tunnel-reconnected", "task-restart-requested", "node-cordoned", "node-uncordoned", "cert-expired", "ingress-blocked", "ingress-unblocked", "ingress-backends-empty", "ingress-backends-restored", "ingress-listener-down", "ingress-listener-up", "ingress-certificate-missing", "ingress-source-rejected-spike", "node-disk-formatted", "node-disk-mounted", "node-disk-unmounted", "node-disk-failed", "node-firewall-changed", "node-firewall-failed", "container-logs-cleared", "cluster-firewall-changed"}, kind)
}
func text(s string, max int) bool { return len(s) <= max && !strings.ContainsAny(s, "\x00\r\n") }
func digest(s string) bool {
	b, e := hex.DecodeString(s)
	return e == nil && len(b) == 32 && hex.EncodeToString(b) == s
}
func (e Event) Valid() bool {
	if !ValidKind(e.Kind) || e.At == 0 || e.Authority != "" && !digest(e.Authority) {
		return false
	}
	t := e.Target
	if !t.Valid() {
		return false
	}
	if e.Scope != "cluster" && e.Scope != "node" && e.Scope != "tenant" && e.Scope != "app" || e.Scope == "cluster" && t.Tenant != "" || e.Scope == "node" && (t.Node == "" || t.Tenant != "") || e.Scope == "tenant" && (t.Tenant == "" || t.App != "") || e.Scope == "app" && (t.Tenant == "" || t.App == "") {
		return false
	}
	d := e.Detail
	if (len(d.Reason) > 2048 || !utf8.ValidString(d.Reason) || strings.ContainsRune(d.Reason, 0)) || (len(d.OperatorReason) > 2048 || !utf8.ValidString(d.OperatorReason) || strings.ContainsRune(d.OperatorReason, 0)) || !text(d.Code, 96) || !text(d.Actor, 63) || !text(d.IncidentID, 128) || !text(d.ApprovedBy, 128) || !text(d.Operation, 256) || !text(d.Checker, 128) || !text(d.State, 64) || !text(d.Resource, 64) || d.CandidateID != "" && !digest(d.CandidateID) || !text(d.Commit, 128) || d.RunID != "" && !digest(d.RunID) {
		return false
	}
	if d.ClosedBy != nil {
		actor := d.ClosedBy
		if e.Kind != "node-shell-closed" || (d.Reason != "closed" && d.Reason != "policy") || !lifecycle.ValidID(actor.User) || actor.Username == "" || len(actor.Username) > 256 || !utf8.ValidString(actor.Username) || strings.ContainsFunc(actor.Username, unicode.IsControl) {
			return false
		}
	}
	if strings.HasPrefix(e.Kind, "node-shell-") {
		if e.Scope != "node" || d.Actor == "" || d.Operation == "" {
			return false
		}
		if e.Kind == "node-shell-closed" {
			if d.ExitCode == nil || *d.ExitCode < 0 || *d.ExitCode > 255 || !slices.Contains([]string{"exit", "idle", "closed", "policy"}, d.Reason) || (d.Reason == "closed" || d.Reason == "policy") != (d.ClosedBy != nil) {
				return false
			}
		} else if d.ClosedBy != nil || d.ExitCode != nil {
			return false
		}
	} else if d.BytesIn != 0 || d.BytesOut != 0 {
		return false
	}
	raw, err := json.Marshal(e)
	return err == nil && len(raw) <= MaxRecordBytes-512
}

func (t Target) Valid() bool {
	if t.Gateway != "" && t.Gateway != "local" && t.Gateway != "external" && t.Gateway != "both" || !text(t.RouteID, 256) || !text(t.Host, 253) || !text(t.Prefix, 2048) {
		return false
	}
	for _, s := range []string{t.Tenant, t.App, t.Service, t.Deployment, t.Node, t.Network} {
		if s != "" && !lifecycle.ValidID(s) {
			return false
		}
	}
	if t.Network != "" && t.Tenant == "" || t.App != "" && t.Tenant == "" || t.Service != "" && t.App == "" || t.Revision < t.Generation || !text(t.Task, 512) || !text(t.Native, 256) || t.FilesystemID != "" && !digest(t.FilesystemID) {
		return false
	}
	if t.PairID != "" {
		parts := strings.Split(t.PairID, "/")
		if len(parts) != 2 || !lifecycle.ValidID(parts[0]) || !lifecycle.ValidID(parts[1]) || parts[0] >= parts[1] {
			return false
		}
	}
	return true
}

type Record struct {
	Schema             uint8
	Cluster, SourceKey [32]byte
	SourceNode         string
	Stream             [16]byte
	Sequence           uint64
	Tag                string // digest of public source identity only, not a secret/value digest
	Event              Event
	Signature          []byte
}

func SigningBytes(r Record) []byte {
	r.Signature = nil
	b, _ := json.Marshal(r)
	return append([]byte("sfc-diagnostic-event-1\x00"), b...)
}
func (r Record) Origin() string {
	return hex.EncodeToString(r.SourceKey[:]) + "/" + hex.EncodeToString(r.Stream[:])
}
func (r Record) ID() string { return fmt.Sprintf("%s/%020d", r.Origin(), r.Sequence) }
func (r Record) PublicID() string {
	if r.Event.Authority != "" {
		return "raft/" + r.Event.Authority
	}
	return r.ID()
}
func (r Record) Valid() bool {
	if r.Schema != 1 || r.Cluster == ([32]byte{}) || r.SourceKey == ([32]byte{}) || !lifecycle.ValidID(r.SourceNode) || r.Stream == ([16]byte{}) || r.Sequence == 0 || !digest(r.Tag) || !r.Event.Valid() {
		return false
	}
	b, err := json.Marshal(r)
	return err == nil && len(b) <= MaxRecordBytes && ed25519.Verify(ed25519.PublicKey(r.SourceKey[:]), SigningBytes(r), r.Signature)
}

type Batch struct {
	Kind            string
	Schema          uint8
	Cluster, Key    [32]byte
	Node            string
	Stream          [16]byte
	Floor, Last, At uint64
	Records         []Record
	Signature       []byte
}

func BatchBytes(b Batch) []byte {
	b.Signature = nil
	r, _ := json.Marshal(b)
	return append([]byte("sfc-diagnostic-event-batch-1\x00"), r...)
}
func (b Batch) Valid() bool {
	if b.Kind != "node-events" || b.Schema != 1 || b.Cluster == ([32]byte{}) || b.Key == ([32]byte{}) || !lifecycle.ValidID(b.Node) || b.Stream == ([16]byte{}) || b.Floor == 0 || b.Floor > b.Last+1 || b.At == 0 || len(b.Records) > MaxBatch {
		return false
	}
	for i, r := range b.Records {
		if !r.Valid() || r.Cluster != b.Cluster || r.SourceKey != b.Key || r.SourceNode != b.Node || r.Stream != b.Stream || r.Sequence < b.Floor || r.Sequence > b.Last || r.Event.At > b.At+30000 || i > 0 && r.Sequence != b.Records[i-1].Sequence+1 {
			return false
		}
	}
	raw, err := json.Marshal(b)
	return err == nil && len(raw) <= 32<<10 && ed25519.Verify(ed25519.PublicKey(b.Key[:]), BatchBytes(b), b.Signature)
}

type Query struct {
	Tenant, App, Node, Kind, After string `json:",omitempty"`
	Limit                          int    `json:",omitempty"`
}

func (q Query) Valid() bool {
	return (q.Tenant == "" || lifecycle.ValidID(q.Tenant)) && (q.App == "" || q.Tenant != "" && lifecycle.ValidID(q.App)) && (q.Node == "" || lifecycle.ValidID(q.Node)) && (q.Kind == "" || ValidKind(q.Kind)) && len(q.After) <= 1536 && q.Limit >= 0 && q.Limit <= 100
}
func (q Query) matches(r Record) bool {
	return (q.Tenant == "" || r.Event.Target.Tenant == q.Tenant) && (q.App == "" || r.Event.Target.App == q.App) && (q.Node == "" || r.Event.Target.Node == q.Node || r.SourceNode == q.Node) && (q.Kind == "" || r.Event.Kind == q.Kind)
}

type Item struct {
	ID, Cursor string
	SourceNode string
	Event
}
type Page struct {
	Schema           uint8
	Items            []Item
	Cursor           string
	More, Incomplete bool
}

type ReceiptQuery struct {
	Key    [32]byte
	Stream [16]byte
}
type Receipt struct {
	Schema uint8
	Query  ReceiptQuery
	Last   uint64
}
