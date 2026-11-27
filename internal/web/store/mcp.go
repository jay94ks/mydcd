// SPDX-License-Identifier: Apache-2.0

package store

import (
	"bytes"
	"encoding/json"
	"slices"
	"time"

	bolt "go.etcd.io/bbolt"
)

// MCP servers (W2.3a): remote tool servers the coordinator and incident
// response may use. The bearer token is sealed, never here; tool results
// are not stored.

var bucketMCPServers = []byte("mcp-servers")

// MCPServer is one connected server and its tool catalog.
type MCPServer struct {
	Name       string     `json:"name"`
	URL        string     `json:"url"`
	Auth       string     `json:"auth"` // bearer, oauth, none
	TokenLast4 string     `json:"tokenLast4,omitempty"`
	Enabled    bool       `json:"enabled"`
	State      string     `json:"state"` // ok, error, unchecked
	Error      string     `json:"error,omitempty"`
	CheckedAt  time.Time  `json:"checkedAt,omitzero"`
	Info       *MCPInfo   `json:"info,omitempty"`
	Users      MCPUsers   `json:"users"`
	Tools      []*MCPTool `json:"tools"`
	// CatalogRevision goes up when tools/list changes the catalog.
	CatalogRevision uint64 `json:"catalogRevision"`
	// OAuth: when the access token ends (renewed on its own) and whether
	// a renewal failed so a person must log in again.
	TokenExpiresAt time.Time `json:"tokenExpiresAt,omitzero"`
	NeedsLogin     bool      `json:"needsLogin,omitempty"`
	CreatedBy      string    `json:"createdBy"`
	CreatedAt      time.Time `json:"createdAt"`
	Revision       uint64    `json:"revision"`
}

// MCPInfo is the initialize answer's serverInfo.
type MCPInfo struct {
	ServerName string `json:"serverName"`
	Version    string `json:"version,omitempty"`
}

// MCPUsers says who may use the server (system administrators always).
type MCPUsers struct {
	Tenants []string `json:"tenants"`
}

// MCPTool is one tool and how it may be used.
type MCPTool struct {
	Name         string         `json:"name"`
	Title        string         `json:"title,omitempty"`
	Description  string         `json:"description"`
	ReadOnlyHint bool           `json:"readOnlyHint"`
	Args         []MCPArg       `json:"args"`
	Schema       map[string]any `json:"schema,omitempty"` // inputSchema as listed
	Kind         string         `json:"kind"`             // read, change, notify
	Coordinator  bool           `json:"coordinator"`
	Incident     string         `json:"incident"`          // off, diagnose, notify, propose-approve, propose-auto
	Tenants      []string       `json:"tenants,omitempty"` // nil = all
	AllTenants   bool           `json:"allTenants"`
	New          bool           `json:"new"`
	Auto         *MCPAuto       `json:"auto,omitempty"`
	Hint         string         `json:"hint,omitempty"`
}

// MCPArg is one inputSchema property.
type MCPArg struct {
	Name        string `json:"name"`
	Type        string `json:"type,omitempty"`
	Description string `json:"description,omitempty"`
	Required    bool   `json:"required,omitempty"`
}

// MCPAuto is what a propose-auto tool needs before it may run on its own.
type MCPAuto struct {
	Floor       string              `json:"floor"` // low, medium, high
	Inputs      map[string]MCPInput `json:"inputs"`
	PerIncident int                 `json:"perIncident"`
	PerDay      int                 `json:"perDay"`
	Revert      MCPRevert           `json:"revert"`
	Signals     []string            `json:"signals,omitempty"`
}

// MCPInput limits one argument.
type MCPInput struct {
	Kind  string `json:"kind"` // max, incident, template, fixed
	Value string `json:"value,omitempty"`
}

// MCPRevert names the tool that undoes it, or says it cannot be undone.
type MCPRevert struct {
	Tool         string `json:"tool,omitempty"`
	Irreversible bool   `json:"irreversible,omitempty"`
}

// Tool returns the named tool (nil when none).
func (m *MCPServer) Tool(name string) *MCPTool {
	for _, t := range m.Tools {
		if t.Name == name {
			return t
		}
	}
	return nil
}

// GetMCPServer returns one server.
func (s *Store) GetMCPServer(name string) (*MCPServer, error) {
	var m MCPServer
	err := s.db.View(func(tx *bolt.Tx) error { return getJSON(tx.Bucket(bucketMCPServers), []byte(name), &m) })
	if err != nil {
		return nil, err
	}
	return &m, nil
}

// CreateMCPServer stores a new server; ErrConflict when the name is taken.
func (s *Store) CreateMCPServer(m *MCPServer) (err error) {
	defer func() { s.changed(err, Change{Kind: "mcp-server", ID: m.Name}) }()
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketMCPServers)
		if b.Get([]byte(m.Name)) != nil {
			return ErrConflict
		}
		m.Revision = 1
		return putJSON(b, []byte(m.Name), m)
	})
}

// UpdateMCPServer changes one server; expected 0 skips the revision check.
func (s *Store) UpdateMCPServer(name string, expected uint64, fn func(m *MCPServer) error) (*MCPServer, error) {
	var m MCPServer
	err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketMCPServers)
		if err := getJSON(b, []byte(name), &m); err != nil {
			return err
		}
		if expected != 0 && m.Revision != expected {
			return ErrConflict
		}
		if err := fn(&m); err != nil {
			return err
		}
		m.Revision++
		return putJSON(b, []byte(name), &m)
	})
	s.changed(err, Change{Kind: "mcp-server", ID: name})
	if err != nil {
		return nil, err
	}
	return &m, nil
}

// ListMCPServers returns every server by name.
func (s *Store) ListMCPServers() ([]*MCPServer, error) {
	var out []*MCPServer
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketMCPServers).ForEach(func(_, v []byte) error {
			var m MCPServer
			if err := json.Unmarshal(v, &m); err != nil {
				return err
			}
			out = append(out, &m)
			return nil
		})
	})
	return out, err
}

// DeleteMCPServer removes a server and takes it out of the current
// guidelines' mcpServers (older versions stay as they were).
func (s *Store) DeleteMCPServer(name string) (err error) {
	defer func() { s.changed(err, Change{Kind: "mcp-server", ID: name, Deleted: true}) }()
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketMCPServers)
		if b.Get([]byte(name)) == nil {
			return ErrNotFound
		}
		if err := b.Delete([]byte(name)); err != nil {
			return err
		}
		gb := tx.Bucket(bucketGuides)
		p := prefix("cur")
		type upd struct {
			k []byte
			g Guide
		}
		var ups []upd
		c := gb.Cursor()
		for k, v := c.Seek(p); k != nil && bytes.HasPrefix(k, p); k, v = c.Next() {
			var g Guide
			if json.Unmarshal(v, &g) == nil && slices.Contains(g.Fields.MCPServers, name) {
				g.Fields.MCPServers = slices.DeleteFunc(g.Fields.MCPServers, func(x string) bool { return x == name })
				ups = append(ups, upd{append([]byte(nil), k...), g})
			}
		}
		for _, u := range ups {
			if err := putJSON(gb, u.k, &u.g); err != nil {
				return err
			}
		}
		return nil
	})
}
