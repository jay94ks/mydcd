// SPDX-License-Identifier: Apache-2.0

package store

import (
	"bytes"
	"encoding/json"
	"fmt"
	"time"

	bolt "go.etcd.io/bbolt"
)

// AI settings and records (W2.1). No API key is ever stored here: keys are
// sealed files; these rows carry only their last four characters.

var (
	bucketAIConfig  = []byte("ai-config")
	bucketAICatalog = []byte("ai-model-catalog")
	bucketAIUsage   = []byte("ai-usage")
	bucketAIAudit   = []byte("ai-audit")
	keyAIConfig     = []byte("config")
)

// AIConfig is the AI settings screen (UI-B7).
type AIConfig struct {
	Revision  uint64                 `json:"revision"`
	Providers map[string]*AIProvider `json:"providers,omitempty"`
	Roles     map[string]AIRole      `json:"roles,omitempty"`
	Data      AIData                 `json:"data"`
	Limits    AILimits               `json:"limits"`
}

// AIProvider is one registered key's public facts.
type AIProvider struct {
	Last4     string    `json:"last4"`
	SetByID   string    `json:"setById"`
	SetBy     string    `json:"setBy"`
	SetAt     time.Time `json:"setAt"`
	CatalogAt time.Time `json:"catalogAt,omitzero"`
	Error     string    `json:"error,omitempty"` // last catalog refresh failure class
}

// AIModelRef picks a provider's model.
type AIModelRef struct {
	Provider string `json:"provider"`
	Model    string `json:"model"`
}

// AIRole is one role's main and fallback model and call settings.
type AIRole struct {
	Main            *AIModelRef `json:"main"`
	Fallback        *AIModelRef `json:"fallback"`
	Effort          string      `json:"effort"`   // low / medium / high
	Thinking        string      `json:"thinking"` // auto / off
	MaxOutputTokens int64       `json:"maxOutputTokens"`
	Stream          bool        `json:"stream"`
}

// AIData is what may be sent to the vendors.
type AIData struct {
	MaskSecretLikeEnv bool     `json:"maskSecretLikeEnv"`
	LogTailLines      int      `json:"logTailLines"`
	ExcludeTenants    []string `json:"excludeTenants"`
}

// AILimits are the budgets; 0 is unlimited.
type AILimits struct {
	DailyTokensPerUser       int64        `json:"dailyTokensPerUser"`
	ToolCallsPerConversation int64        `json:"toolCallsPerConversation"`
	TokensPerConversation    int64        `json:"tokensPerConversation"`
	Compaction               AICompaction `json:"compaction"`
}

// AICompaction is the automatic summary of long conversations.
type AICompaction struct {
	Enabled       bool  `json:"enabled"`
	TriggerTokens int64 `json:"triggerTokens"`
}

// GetAIConfig returns the AI settings, or nil when never saved.
func (s *Store) GetAIConfig() (*AIConfig, error) {
	var out *AIConfig
	err := s.db.View(func(tx *bolt.Tx) error {
		var v AIConfig
		err := getJSON(tx.Bucket(bucketAIConfig), keyAIConfig, &v)
		if err == ErrNotFound {
			return nil
		}
		out = &v
		return err
	})
	return out, err
}

// UpdateAIConfig reads, changes and writes the settings in one
// transaction; fn gets the current row (nil when never saved) and returns
// the new one. The revision is bumped.
func (s *Store) UpdateAIConfig(fn func(cur *AIConfig) (*AIConfig, error)) (*AIConfig, error) {
	var out *AIConfig
	err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketAIConfig)
		var cur *AIConfig
		var v AIConfig
		if err := getJSON(b, keyAIConfig, &v); err == nil {
			cur = &v
		} else if err != ErrNotFound {
			return err
		}
		next, err := fn(cur)
		if err != nil {
			return err
		}
		if cur != nil {
			next.Revision = cur.Revision + 1
		} else {
			next.Revision = 1
		}
		out = next
		return putJSON(b, keyAIConfig, next)
	})
	return out, err
}

// AIModel is one catalog row.
type AIModel struct {
	ID          string    `json:"id"`
	DisplayName string    `json:"displayName,omitempty"`
	CreatedAt   time.Time `json:"createdAt"`
	Hidden      bool      `json:"hidden"`
}

// AICatalog is a provider's model list as last read.
type AICatalog struct {
	Provider  string    `json:"provider"`
	FetchedAt time.Time `json:"fetchedAt"`
	Models    []AIModel `json:"items"`
}

// GetAICatalog returns a provider's catalog, or nil.
func (s *Store) GetAICatalog(provider string) (*AICatalog, error) {
	var out *AICatalog
	err := s.db.View(func(tx *bolt.Tx) error {
		var v AICatalog
		err := getJSON(tx.Bucket(bucketAICatalog), []byte(provider), &v)
		if err == ErrNotFound {
			return nil
		}
		out = &v
		return err
	})
	return out, err
}

// PutAICatalog replaces a provider's catalog; nil removes it.
func (s *Store) PutAICatalog(provider string, c *AICatalog) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		if c == nil {
			return tx.Bucket(bucketAICatalog).Delete([]byte(provider))
		}
		return putJSON(tx.Bucket(bucketAICatalog), []byte(provider), c)
	})
}

// AIUsage is one day's counters for a role, provider and model.
type AIUsage struct {
	Day        string `json:"day"` // YYYY-MM-DD (UTC)
	Role       string `json:"role"`
	Provider   string `json:"provider"`
	Model      string `json:"model"`
	Fallback   bool   `json:"fallback"`
	User       string `json:"-"` // user ID ("" for automation); kept for the daily budget
	Requests   int64  `json:"requests"`
	Input      int64  `json:"inputTokens"`
	Output     int64  `json:"outputTokens"`
	CacheRead  int64  `json:"cacheReadTokens"`
	CacheWrite int64  `json:"cacheWriteTokens"`
}

type aiUsageRow struct {
	AIUsage
	UserID string `json:"user,omitempty"`
}

func aiUsageKey(u AIUsage) []byte {
	fb := "0"
	if u.Fallback {
		fb = "1"
	}
	return key(u.Day, u.User, u.Role, u.Provider, u.Model, fb)
}

// AddAIUsage adds one request's counts.
func (s *Store) AddAIUsage(u AIUsage) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketAIUsage)
		k := aiUsageKey(u)
		var cur aiUsageRow
		if err := getJSON(b, k, &cur); err != nil && err != ErrNotFound {
			return err
		}
		cur.Day, cur.Role, cur.Provider, cur.Model, cur.Fallback, cur.UserID = u.Day, u.Role, u.Provider, u.Model, u.Fallback, u.User
		cur.Requests += u.Requests
		cur.Input += u.Input
		cur.Output += u.Output
		cur.CacheRead += u.CacheRead
		cur.CacheWrite += u.CacheWrite
		return putJSON(b, k, cur)
	})
}

// ListAIUsage returns the rows from day since (YYYY-MM-DD) on, per user.
func (s *Store) ListAIUsage(since string) ([]AIUsage, error) {
	var out []AIUsage
	err := s.db.View(func(tx *bolt.Tx) error {
		c := tx.Bucket(bucketAIUsage).Cursor()
		for k, v := c.Seek([]byte(since)); k != nil; k, v = c.Next() {
			var r aiUsageRow
			if err := json.Unmarshal(v, &r); err != nil {
				return err
			}
			r.AIUsage.User = r.UserID
			out = append(out, r.AIUsage)
		}
		return nil
	})
	return out, err
}

// AIAudit is one AI audit row: key and settings changes, model requests
// with their tokens, fallbacks, proposal decisions. Never prompt text or
// tool results.
type AIAudit struct {
	ID        string    `json:"id"`
	At        time.Time `json:"at"`
	User      string    `json:"user,omitempty"`     // user ID
	Username  string    `json:"username,omitempty"` // shown
	Kind      string    `json:"kind"`
	Role      string    `json:"role,omitempty"`
	Provider  string    `json:"provider,omitempty"`
	Model     string    `json:"model,omitempty"`
	Fallback  bool      `json:"fallback,omitempty"`
	Reason    string    `json:"reason,omitempty"`
	Tokens    int64     `json:"tokens,omitempty"`
	CacheRead int64     `json:"cacheRead,omitempty"`
	Proposal  string    `json:"proposal,omitempty"`
	Decision  string    `json:"decision,omitempty"`
}

func aiAuditKey(at time.Time, id string) []byte {
	return []byte(fmt.Sprintf("%020d/%s", at.UnixNano(), id))
}

// AppendAIAudit stores one row.
func (s *Store) AppendAIAudit(e *AIAudit) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		return putJSON(tx.Bucket(bucketAIAudit), aiAuditKey(e.At, e.ID), e)
	})
}

// ListAIAudit returns rows newest first after cursor (a row's key from an
// earlier page, "" = from the newest), at most limit, the next cursor (""
// at the end) and the total row count.
func (s *Store) ListAIAudit(cursor string, limit int) ([]*AIAudit, string, int, error) {
	var out []*AIAudit
	next := ""
	total := 0
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketAIAudit)
		total = b.Stats().KeyN
		c := b.Cursor()
		var k, v []byte
		if cursor == "" {
			k, v = c.Last()
		} else {
			// The first row older than the cursor row.
			if k, _ = c.Seek([]byte(cursor)); k == nil {
				k, v = c.Last()
			} else {
				k, v = c.Prev()
			}
		}
		for ; k != nil; k, v = c.Prev() {
			if len(out) == limit {
				next = string(out[len(out)-1].key())
				break
			}
			var e AIAudit
			if err := json.Unmarshal(v, &e); err != nil {
				return err
			}
			out = append(out, &e)
		}
		return nil
	})
	return out, next, total, err
}

func (e *AIAudit) key() []byte { return aiAuditKey(e.At, e.ID) }

// DeleteAIAuditBefore deletes rows older than t.
func (s *Store) DeleteAIAuditBefore(t time.Time) (int, error) {
	n := 0
	end := []byte(fmt.Sprintf("%020d", t.UnixNano()))
	err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketAIAudit)
		var old [][]byte
		c := b.Cursor()
		for k, _ := c.First(); k != nil && bytes.Compare(k, end) < 0; k, _ = c.Next() {
			old = append(old, append([]byte(nil), k...))
		}
		for _, k := range old {
			if err := b.Delete(k); err != nil {
				return err
			}
		}
		n = len(old)
		return nil
	})
	return n, err
}
