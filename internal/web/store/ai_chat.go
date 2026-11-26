// SPDX-License-Identifier: Apache-2.0

package store

import (
	"bytes"
	"encoding/json"
	"sort"
	"time"

	bolt "go.etcd.io/bbolt"
)

// Coordinator conversations and proposals (W2.2). A conversation holds
// what the person saw: their questions, the answers, the tool activity
// lines (masked arguments, never tool results) and proposal links. Kept
// until the person deletes it; proposals go with their conversation.

var (
	bucketAIConversations = []byte("ai-conversations")
	bucketAIProposals     = []byte("ai-proposals")
)

// AIConversation is one coordinator conversation of one user.
type AIConversation struct {
	ID        string    `json:"id"`
	User      string    `json:"user"`
	Title     string    `json:"title"`
	Model     string    `json:"model,omitempty"`  // display name of the answering model
	Tenant    string    `json:"tenant,omitempty"` // workspace of the screen it started on
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
	// Fallback keeps the conversation on the fallback model once it
	// switched.
	Fallback bool `json:"fallback,omitempty"`
	// Counters for the per-conversation limits.
	ToolCalls int64 `json:"toolCalls,omitempty"`
	Tokens    int64 `json:"tokens,omitempty"`
	// LastInput is the input size of the last request (compaction trigger).
	LastInput int64       `json:"lastInput,omitempty"`
	Messages  []AIMessage `json:"messages"`
	// Notes are proposal outcomes the model has not been told yet.
	Notes []string `json:"notes,omitempty"`
	// Chips are the context chips last attached (kind plus a few names).
	Chips []map[string]string `json:"chips,omitempty"`
}

// AIMessage is one visible message.
type AIMessage struct {
	ID        string              `json:"id"`
	Role      string              `json:"role"` // user, assistant, summary
	Text      string              `json:"text"`
	At        time.Time           `json:"at"`
	Model     string              `json:"model,omitempty"`
	Fallback  bool                `json:"fallback,omitempty"`
	Tools     []AIToolLine        `json:"tools,omitempty"`
	Proposals []string            `json:"proposals,omitempty"`
	Chips     []map[string]string `json:"chips,omitempty"`
}

// AIToolLine is one tool activity line. Args are already masked.
type AIToolLine struct {
	Name    string            `json:"name"`
	Kind    string            `json:"kind"` // find, read, propose
	Summary string            `json:"summary"`
	Args    map[string]string `json:"args"`
}

// PutAIConversation stores a conversation.
func (s *Store) PutAIConversation(c *AIConversation) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		return putJSON(tx.Bucket(bucketAIConversations), key(c.User, c.ID), c)
	})
}

// GetAIConversation returns one of the user's conversations.
func (s *Store) GetAIConversation(user, id string) (*AIConversation, error) {
	var out AIConversation
	err := s.db.View(func(tx *bolt.Tx) error {
		return getJSON(tx.Bucket(bucketAIConversations), key(user, id), &out)
	})
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// UpdateAIConversation changes one conversation in a transaction.
func (s *Store) UpdateAIConversation(user, id string, fn func(c *AIConversation) error) (*AIConversation, error) {
	var out AIConversation
	err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketAIConversations)
		if err := getJSON(b, key(user, id), &out); err != nil {
			return err
		}
		if err := fn(&out); err != nil {
			return err
		}
		return putJSON(b, key(user, id), &out)
	})
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// ListAIConversations returns the user's conversations, newest first.
func (s *Store) ListAIConversations(user string) ([]*AIConversation, error) {
	var out []*AIConversation
	err := s.db.View(func(tx *bolt.Tx) error {
		c := tx.Bucket(bucketAIConversations).Cursor()
		p := prefix(user)
		for k, v := c.Seek(p); k != nil && bytes.HasPrefix(k, p); k, v = c.Next() {
			var row AIConversation
			if err := json.Unmarshal(v, &row); err != nil {
				return err
			}
			out = append(out, &row)
		}
		return nil
	})
	sort.SliceStable(out, func(i, j int) bool { return out[i].UpdatedAt.After(out[j].UpdatedAt) })
	return out, err
}

// DeleteAIConversations deletes the user's conversation id ("" = all of
// them) and their proposals. It returns how many conversations went.
func (s *Store) DeleteAIConversations(user, id string) (int, error) {
	n := 0
	err := s.db.Update(func(tx *bolt.Tx) error {
		convs, props := tx.Bucket(bucketAIConversations), tx.Bucket(bucketAIProposals)
		var dropC, dropP [][]byte
		c := convs.Cursor()
		p := prefix(user)
		for k, _ := c.Seek(p); k != nil && bytes.HasPrefix(k, p); k, _ = c.Next() {
			if id == "" || bytes.Equal(k, key(user, id)) {
				dropC = append(dropC, append([]byte(nil), k...))
			}
		}
		pc := props.Cursor()
		for k, v := pc.Seek(p); k != nil && bytes.HasPrefix(k, p); k, v = pc.Next() {
			var row struct {
				Conversation string `json:"conversation"`
			}
			if json.Unmarshal(v, &row) == nil && (id == "" || row.Conversation == id) {
				dropP = append(dropP, append([]byte(nil), k...))
			}
		}
		for _, k := range dropC {
			if err := convs.Delete(k); err != nil {
				return err
			}
		}
		for _, k := range dropP {
			if err := props.Delete(k); err != nil {
				return err
			}
		}
		n = len(dropC)
		return nil
	})
	return n, err
}

// AIProposal is one proposed change waiting for the person. Request is the
// screen API call it becomes on approval (method, path, body without the
// opId); the basis is what it was planned against.
type AIProposal struct {
	ID           string          `json:"id"`
	User         string          `json:"user"`
	Conversation string          `json:"conversation"`
	Title        string          `json:"title"`
	Index        int             `json:"index"`
	Total        int             `json:"total"`
	After        string          `json:"after,omitempty"`
	Tool         string          `json:"tool"`
	Action       string          `json:"action"`
	Tenant       string          `json:"tenant,omitempty"`
	Target       string          `json:"target"`
	Args         json.RawMessage `json:"args"`
	Method       string          `json:"method"`
	Path         string          `json:"path"`
	Body         json.RawMessage `json:"body,omitempty"`
	Preview      []AIPreviewRow  `json:"preview"`
	Impact       string          `json:"impact"`
	Revert       string          `json:"revert"`
	Irreversible bool            `json:"irreversible"`
	ConfirmName  string          `json:"confirmName,omitempty"`
	Expected     uint64          `json:"expected"`
	BasisHash    string          `json:"basisHash"`
	CreatedAt    time.Time       `json:"createdAt"`
	ExpiresAt    time.Time       `json:"expiresAt"`
	Edited       bool            `json:"edited"`
	State        string          `json:"state"`
	DecidedBy    string          `json:"decidedBy,omitempty"`
	DecidedAt    time.Time       `json:"decidedAt,omitzero"`
	Op           string          `json:"op,omitempty"`
	Reason       string          `json:"reason,omitempty"`
	// MCP: an MCP tool call (Method "MCP"); approving calls it once.
	MCP *AIProposalMCP `json:"mcp,omitempty"`
}

// AIProposalMCP names the tool of an MCP proposal.
type AIProposalMCP struct {
	Server string `json:"server"`
	Tool   string `json:"tool"`
}

// AIPreviewRow is one label/value line of a proposal card.
type AIPreviewRow struct {
	Label string `json:"label"`
	Value string `json:"value"`
}

// Proposal states.
const (
	ProposalPending  = "pending"
	ProposalApproved = "approved"
	ProposalRejected = "rejected"
	ProposalExpired  = "expired"
	ProposalInvalid  = "invalid"
)

// PutAIProposal stores a proposal.
func (s *Store) PutAIProposal(p *AIProposal) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		return putJSON(tx.Bucket(bucketAIProposals), key(p.User, p.ID), p)
	})
}

// GetAIProposal returns one of the user's proposals.
func (s *Store) GetAIProposal(user, id string) (*AIProposal, error) {
	var out AIProposal
	err := s.db.View(func(tx *bolt.Tx) error {
		return getJSON(tx.Bucket(bucketAIProposals), key(user, id), &out)
	})
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// UpdateAIProposal changes one proposal in a transaction.
func (s *Store) UpdateAIProposal(user, id string, fn func(p *AIProposal) error) (*AIProposal, error) {
	var out AIProposal
	err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketAIProposals)
		if err := getJSON(b, key(user, id), &out); err != nil {
			return err
		}
		if err := fn(&out); err != nil {
			return err
		}
		return putJSON(b, key(user, id), &out)
	})
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// ListAIProposals returns the user's proposals of one conversation in
// creation order.
func (s *Store) ListAIProposals(user, conversation string) ([]*AIProposal, error) {
	var out []*AIProposal
	err := s.db.View(func(tx *bolt.Tx) error {
		c := tx.Bucket(bucketAIProposals).Cursor()
		p := prefix(user)
		for k, v := c.Seek(p); k != nil && bytes.HasPrefix(k, p); k, v = c.Next() {
			var row AIProposal
			if err := json.Unmarshal(v, &row); err != nil {
				return err
			}
			if row.Conversation == conversation {
				out = append(out, &row)
			}
		}
		return nil
	})
	sort.SliceStable(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out, err
}
