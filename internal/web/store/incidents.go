// SPDX-License-Identifier: Apache-2.0

package store

import (
	"bytes"
	"encoding/json"
	"sort"
	"time"

	bolt "go.etcd.io/bbolt"
)

// Incident response (W2.3): incidents the watcher opened, the cluster and
// app policies, and the watcher's cursor. Incidents are kept until an
// administrator deletes them. The cluster state they describe stays with
// sfcd; an incident holds what was seen and decided.

var (
	bucketIncidents      = []byte("incidents")
	bucketIncidentPolicy = []byte("incident-policy")

	keyClusterPolicy = []byte("cluster")
	keyWatcher       = []byte("watcher")
)

// Incident is one incident.
type Incident struct {
	ID     string `json:"id"`
	Scope  string `json:"scope"` // app, cluster
	Tenant string `json:"tenant,omitempty"`
	App    string `json:"app,omitempty"`
	Node   string `json:"node,omitempty"`
	// Network is the workspace network of a tunnel signal.
	Network string `json:"network,omitempty"`
	// Key groups signals of the same target into one open incident.
	Key        string           `json:"key"`
	Signal     string           `json:"signal"` // event kind that opened it
	Target     string           `json:"target"`
	Title      string           `json:"title"`
	Rule       string           `json:"rule"` // the rule that fired, in words
	Signals    int              `json:"signals"`
	LastSignal time.Time        `json:"lastSignal"`
	Candidates []IncidentAction `json:"candidates,omitempty"`
	// Built is every candidate the rules built, before guidelines and
	// diagnosis (a guidelines test starts from it).
	Built       []IncidentAction  `json:"built,omitempty"`
	Mitigation  string            `json:"mitigation,omitempty"` // chosen action id
	Impact      string            `json:"impact,omitempty"`     // low, medium, high
	Decision    IncidentDecision  `json:"decision"`
	State       string            `json:"state"` // open, mitigating, recovered, closed
	Assessment  json.RawMessage   `json:"assessment,omitempty"`
	Approval    *IncidentApproval `json:"approval,omitempty"`
	Op          string            `json:"op,omitempty"`
	OpID        string            `json:"opId,omitempty"` // the opId the action was sent with
	MitigatedAt time.Time         `json:"mitigatedAt,omitzero"`
	Fallback    bool              `json:"fallback,omitempty"`
	Timeline    []IncidentEntry   `json:"timeline"`
	// MCPCalls counts the MCP tool calls of the diagnosis, per server.
	MCPCalls map[string]int `json:"mcpCalls,omitempty"`
	// MCPRuns are the MCP candidate calls (limits count them).
	MCPRuns []IncidentMCPRun `json:"mcpRuns,omitempty"`
	// Guides are the guideline versions the incident used, by scope.
	Guides    map[string]uint64 `json:"guides,omitempty"`
	At        time.Time         `json:"at"`
	UpdatedAt time.Time         `json:"updatedAt"`
	Revision  uint64            `json:"revision"`
}

// IncidentAction is one temporary action for an incident: the action id
// and the screen API call it is.
type IncidentAction struct {
	ID     string          `json:"id"`
	Label  string          `json:"label"`
	Method string          `json:"method"`
	Path   string          `json:"path"`
	Body   json.RawMessage `json:"body,omitempty"`
	Note   string          `json:"note,omitempty"`
	// NoteText, when set, is the note shown in the reader's language
	// (Note keeps the values).
	NoteText *Phrase `json:"noteText,omitempty"`
	// Also is a second call sent right after this one succeeds (rolling
	// back pauses CD in the same move).
	Also *IncidentAction `json:"also,omitempty"`
	// MCP: an MCP tool call instead of a screen API call (ID
	// "mcp.{server}.{tool}", Body = the arguments).
	MCP *IncidentMCP `json:"mcp,omitempty"`
}

// IncidentMCP is the MCP tool a candidate calls.
type IncidentMCP struct {
	Server string `json:"server"`
	Tool   string `json:"tool"`
	Auto   bool   `json:"auto"`  // propose-auto: may run on its own
	Floor  string `json:"floor"` // the tool's impact floor
	// Revert names the tool that undoes it ("" with Irreversible or when
	// not set).
	Revert       string `json:"revert,omitempty"`
	Irreversible bool   `json:"irreversible,omitempty"`
}

// IncidentMCPRun is one call of an MCP candidate (the answer is not kept).
type IncidentMCPRun struct {
	Tool  string    `json:"tool"` // mcp.{server}.{tool}
	At    time.Time `json:"at"`
	By    string    `json:"by"`
	Auto  bool      `json:"auto,omitempty"`
	OpID  string    `json:"opId,omitempty"` // the approval's opId
	Error string    `json:"error,omitempty"`
}

// IncidentDecision is what was decided about the chosen action.
type IncidentDecision struct {
	Kind      string    `json:"kind"` // none, auto, pending, approved, rejected, expired, stopped
	By        string    `json:"by,omitempty"`
	At        time.Time `json:"at,omitzero"`
	ExpiresAt time.Time `json:"expiresAt,omitzero"`
	Reason    string    `json:"reason,omitempty"`
	Note      string    `json:"note,omitempty"`
	// NoteText is Note in the reader's language (decisions stored before
	// it keep their Korean Note).
	NoteText *Phrase `json:"noteText,omitempty"`
}

// IncidentApproval is the approval card of a pending decision.
type IncidentApproval struct {
	Title     string         `json:"title"`
	Fields    []AIPreviewRow `json:"fields"`
	BasisHash string         `json:"basisHash"`
}

// IncidentEntry is one timeline line.
type IncidentEntry struct {
	At   time.Time `json:"at"`
	Kind string    `json:"kind"` // detect, diagnose, assess, auto, approve, reject, recover, propose, expire, notify
	Text string    `json:"text"`
	// Phrase is the line in the reader's language; Text then is empty
	// (lines stored before it keep their Korean Text; an AI hypothesis
	// stays Text as written).
	Phrase       *Phrase           `json:"phrase,omitempty"`
	Op           string            `json:"op,omitempty"`
	Signer       string            `json:"signer,omitempty"`
	Model        string            `json:"model,omitempty"`
	Inputs       []string          `json:"inputs,omitempty"`
	Candidates   []IncidentOption  `json:"candidates,omitempty"`
	Conversation bool              `json:"conversation,omitempty"`
	Extra        map[string]string `json:"extra,omitempty"`
	// kind webhook: a decide webhook's answer.
	Webhook  string `json:"webhook,omitempty"`
	Status   int    `json:"status,omitempty"`
	Accepted *bool  `json:"accepted,omitempty"`
	Reason   string `json:"reason,omitempty"`
}

// IncidentOption is a candidate as shown in the timeline.
type IncidentOption struct {
	Action string `json:"action"`
	Note   string `json:"note"`
}

// PutIncident stores an incident.
func (s *Store) PutIncident(in *Incident) (err error) {
	defer func() { s.changed(err, Change{Kind: "incident", Tenant: in.Tenant, ID: in.ID}) }()
	return s.db.Update(func(tx *bolt.Tx) error {
		return putJSON(tx.Bucket(bucketIncidents), []byte(in.ID), in)
	})
}

// GetIncident returns one incident.
func (s *Store) GetIncident(id string) (*Incident, error) {
	var out Incident
	err := s.db.View(func(tx *bolt.Tx) error {
		return getJSON(tx.Bucket(bucketIncidents), []byte(id), &out)
	})
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// UpdateIncident changes one incident in a transaction and bumps its
// revision.
func (s *Store) UpdateIncident(id string, fn func(in *Incident) error) (*Incident, error) {
	var out Incident
	err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketIncidents)
		if err := getJSON(b, []byte(id), &out); err != nil {
			return err
		}
		if err := fn(&out); err != nil {
			return err
		}
		out.Revision++
		return putJSON(b, []byte(id), &out)
	})
	s.changed(err, Change{Kind: "incident", Tenant: out.Tenant, ID: id})
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// ListIncidents returns every incident, newest first.
func (s *Store) ListIncidents() ([]*Incident, error) {
	var out []*Incident
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketIncidents).ForEach(func(_, v []byte) error {
			var row Incident
			if err := json.Unmarshal(v, &row); err != nil {
				return err
			}
			out = append(out, &row)
			return nil
		})
	})
	sort.SliceStable(out, func(i, j int) bool {
		if !out[i].At.Equal(out[j].At) {
			return out[i].At.After(out[j].At)
		}
		return out[i].ID > out[j].ID
	})
	return out, err
}

// DeleteIncident deletes one incident.
func (s *Store) DeleteIncident(id string) error {
	var tenant string
	err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketIncidents)
		raw := b.Get([]byte(id))
		if raw == nil {
			return ErrNotFound
		}
		var in Incident
		if json.Unmarshal(raw, &in) == nil {
			tenant = in.Tenant
		}
		return b.Delete([]byte(id))
	})
	s.changed(err, Change{Kind: "incident", Tenant: tenant, ID: id, Deleted: true})
	return err
}

// IncidentPolicy is the cluster policy (system administrators).
type IncidentPolicy struct {
	Level         string            `json:"level"` // off, suggest, auto-low
	Stopped       bool              `json:"stopped"`
	RatePerHour   int               `json:"ratePerHour"`
	Approvers     IncidentApprovers `json:"approvers"`
	Quiet         []string          `json:"quiet"`
	NewAppDefault string            `json:"newAppDefault"`
	Actions       map[string]string `json:"actions"` // action id → allow, approval, human
	Revision      uint64            `json:"revision"`
	UpdatedBy     string            `json:"updatedBy,omitempty"`
	UpdatedAt     time.Time         `json:"updatedAt,omitzero"`
}

// IncidentApprovers says who approves and how long a request waits.
type IncidentApprovers struct {
	// To: system-admins or system-and-tenant-admins (app incidents also
	// ask that app's workspace managers). Label is made by the server.
	To    string `json:"to"`
	Label string `json:"label"`
	// Admins is the system administrator count Label was made with (nil:
	// unknown); screens make the label again in the reader's language.
	Admins          *int `json:"admins,omitempty"`
	DeadlineMinutes int  `json:"deadlineMinutes"`
	Banner          bool `json:"banner"`
}

// AppIncidentPolicy is one app's policy (workspace managers).
type AppIncidentPolicy struct {
	Tenant      string           `json:"tenant"`
	App         string           `json:"app"`
	Level       string           `json:"level"`
	RatePerHour int              `json:"ratePerHour"`
	Quiet       []string         `json:"quiet"`
	CDRollback  CDRollbackPolicy `json:"cdRollback"`
	Actions     map[string]bool  `json:"actions"`
	Migrations  map[uint64]bool  `json:"migrations,omitempty"` // versions marked "data migration"
	Revision    uint64           `json:"revision"`
	UpdatedBy   string           `json:"updatedBy,omitempty"`
	UpdatedAt   time.Time        `json:"updatedAt,omitzero"`
}

// CDRollbackPolicy is the app's "roll back right after CD" setting.
type CDRollbackPolicy struct {
	Enabled       bool `json:"enabled"`
	WindowMinutes int  `json:"windowMinutes"`
	AlwaysApprove bool `json:"alwaysApprove"`
}

// GetIncidentPolicy returns the cluster policy (nil when never set).
func (s *Store) GetIncidentPolicy() (*IncidentPolicy, error) {
	var out *IncidentPolicy
	err := s.db.View(func(tx *bolt.Tx) error {
		var v IncidentPolicy
		err := getJSON(tx.Bucket(bucketIncidentPolicy), keyClusterPolicy, &v)
		if err == ErrNotFound {
			return nil
		}
		out = &v
		return err
	})
	return out, err
}

// UpdateIncidentPolicy changes the cluster policy in a transaction; fn
// gets nil when it was never set and returns the row to store.
func (s *Store) UpdateIncidentPolicy(fn func(p *IncidentPolicy) (*IncidentPolicy, error)) (*IncidentPolicy, error) {
	var out *IncidentPolicy
	err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketIncidentPolicy)
		var cur *IncidentPolicy
		var v IncidentPolicy
		if err := getJSON(b, keyClusterPolicy, &v); err == nil {
			cur = &v
		} else if err != ErrNotFound {
			return err
		}
		next, err := fn(cur)
		if err != nil {
			return err
		}
		next.Revision++
		out = next
		return putJSON(b, keyClusterPolicy, next)
	})
	return out, err
}

func appPolicyKey(tenant, app string) []byte { return key("app", tenant, app) }

// GetAppIncidentPolicy returns one app's policy (nil when never set).
func (s *Store) GetAppIncidentPolicy(tenant, app string) (*AppIncidentPolicy, error) {
	var out *AppIncidentPolicy
	err := s.db.View(func(tx *bolt.Tx) error {
		var v AppIncidentPolicy
		err := getJSON(tx.Bucket(bucketIncidentPolicy), appPolicyKey(tenant, app), &v)
		if err == ErrNotFound {
			return nil
		}
		out = &v
		return err
	})
	return out, err
}

// UpdateAppIncidentPolicy changes one app's policy in a transaction; fn
// gets nil when it was never set.
func (s *Store) UpdateAppIncidentPolicy(tenant, app string, fn func(p *AppIncidentPolicy) (*AppIncidentPolicy, error)) (*AppIncidentPolicy, error) {
	var out *AppIncidentPolicy
	err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketIncidentPolicy)
		var cur *AppIncidentPolicy
		var v AppIncidentPolicy
		if err := getJSON(b, appPolicyKey(tenant, app), &v); err == nil {
			cur = &v
		} else if err != ErrNotFound {
			return err
		}
		next, err := fn(cur)
		if err != nil {
			return err
		}
		next.Tenant, next.App = tenant, app
		next.Revision++
		out = next
		return putJSON(b, appPolicyKey(tenant, app), next)
	})
	return out, err
}

// ListAppIncidentPolicies returns every app policy.
func (s *Store) ListAppIncidentPolicies() ([]*AppIncidentPolicy, error) {
	var out []*AppIncidentPolicy
	err := s.db.View(func(tx *bolt.Tx) error {
		c := tx.Bucket(bucketIncidentPolicy).Cursor()
		p := prefix("app")
		for k, v := c.Seek(p); k != nil && bytes.HasPrefix(k, p); k, v = c.Next() {
			var row AppIncidentPolicy
			if err := json.Unmarshal(v, &row); err != nil {
				return err
			}
			out = append(out, &row)
		}
		return nil
	})
	return out, err
}

// IncidentWatcher is the watcher's place in sfcd's event stream and the
// recent signals its rules count.
type IncidentWatcher struct {
	Cursors map[string]string `json:"cursors,omitempty"` // "" = all workspaces (system admin), else per workspace
	Recent  []IncidentSignal  `json:"recent,omitempty"`
	// Since is when each cursor scope started reading without a break
	// (cleared when the cursor expires, the watcher stops or login fails).
	Since map[string]time.Time `json:"since,omitempty"`
	State string               `json:"state"`
	At    time.Time            `json:"at,omitzero"`
	Error string               `json:"error,omitempty"`
}

// IncidentSignal is one event the rules still count.
type IncidentSignal struct {
	At      time.Time `json:"at"`
	Kind    string    `json:"kind"`
	Scope   string    `json:"scope"`
	Tenant  string    `json:"tenant,omitempty"`
	App     string    `json:"app,omitempty"`
	Node    string    `json:"node,omitempty"`
	Network string    `json:"network,omitempty"`
	Target  string    `json:"target"`
	Detail  string    `json:"detail,omitempty"`
}

// GetIncidentWatcher returns the watcher state (zero when never run).
func (s *Store) GetIncidentWatcher() (*IncidentWatcher, error) {
	var out IncidentWatcher
	err := s.db.View(func(tx *bolt.Tx) error {
		err := getJSON(tx.Bucket(bucketIncidentPolicy), keyWatcher, &out)
		if err == ErrNotFound {
			return nil
		}
		return err
	})
	return &out, err
}

// PutIncidentWatcher stores the watcher state.
func (s *Store) PutIncidentWatcher(w *IncidentWatcher) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		return putJSON(tx.Bucket(bucketIncidentPolicy), keyWatcher, w)
	})
}
