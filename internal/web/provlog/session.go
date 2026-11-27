// SPDX-License-Identifier: Apache-2.0

package provlog

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"time"
)

// IdleLimit is how long collection stays on without activity: no request
// with the token and no new entry. Then collection stops and the token no
// longer works.
const IdleLimit = time.Hour

// MaxLifetime bounds one collection however busy it is (provider calls
// count as activity, so periodic calls alone would keep it on): it ends
// this long after it was turned on. Turning it on again starts anew.
const MaxLifetime = 24 * time.Hour

// State is whether collection is on.
type State struct {
	Enabled      bool      `json:"enabled"`
	EnabledAt    time.Time `json:"enabledAt,omitzero"`
	EnabledBy    string    `json:"enabledBy,omitempty"`
	LastActivity time.Time `json:"lastActivity,omitzero"`
	ExpiresAt    time.Time `json:"expiresAt,omitzero"`
	// DisabledReason is why the last collection ended: "user", "idle",
	// "limit" (MaxLifetime), "restart" (the web app started; collection
	// always starts off).
	DisabledReason string    `json:"disabledReason,omitempty"`
	DisabledAt     time.Time `json:"disabledAt,omitzero"`
	Entries        int       `json:"entries"` // entries kept in memory
	Last           uint64    `json:"last"`
}

type session struct {
	enabled  bool
	at       time.Time
	by       string
	activity time.Time
	token    [32]byte // sha256 of the token; the token itself is not kept
	reason   string
	offAt    time.Time
}

// expireLocked turns collection off after IdleLimit without activity.
func (l *Log) expireLocked(now time.Time) {
	if !l.sess.enabled {
		return
	}
	if now.Sub(l.sess.activity) >= IdleLimit {
		l.sess = session{reason: "idle", offAt: l.sess.activity.Add(IdleLimit)}
	} else if now.Sub(l.sess.at) >= MaxLifetime {
		l.sess = session{reason: "limit", offAt: l.sess.at.Add(MaxLifetime)}
	}
}

// Enable starts collection and returns a new bearer token (shown once).
// Enabling while on replaces the token and starts MaxLifetime anew.
func (l *Log) Enable(by string) (string, State, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", State{}, err
	}
	tok := "mpl_" + base64.RawURLEncoding.EncodeToString(raw[:])
	l.mu.Lock()
	now := l.now().UTC()
	l.sess = session{enabled: true, at: now, by: by, activity: now, token: sha256.Sum256([]byte(tok))}
	st := l.stateLocked(now)
	l.mu.Unlock()
	l.Add(Entry{Provider: "sfc-web", Op: "diag-enable", Msg: "provider log collection on", Attrs: map[string]string{"by": by}})
	return tok, st, nil
}

// Disable stops collection; the token stops working.
func (l *Log) Disable(by string) State {
	l.Add(Entry{Provider: "sfc-web", Op: "diag-disable", Msg: "provider log collection off", Attrs: map[string]string{"by": by}})
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now().UTC()
	if l.sess.enabled {
		l.sess = session{reason: "user", offAt: now}
	}
	return l.stateLocked(now)
}

// Authorize checks a bearer token and counts it as activity.
func (l *Log) Authorize(token string) bool {
	if l == nil || token == "" {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now().UTC()
	l.expireLocked(now)
	h := sha256.Sum256([]byte(token))
	if !l.sess.enabled || subtle.ConstantTimeCompare(h[:], l.sess.token[:]) != 1 {
		return false
	}
	l.sess.activity = now
	return true
}

// Enabled reports whether collection is on now.
func (l *Log) Enabled() bool {
	if l == nil {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.expireLocked(l.now().UTC())
	return l.sess.enabled
}

// State returns the collection state.
func (l *Log) State() State {
	if l == nil {
		return State{}
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now().UTC()
	l.expireLocked(now)
	return l.stateLocked(now)
}

func (l *Log) stateLocked(now time.Time) State {
	st := State{Enabled: l.sess.enabled, Entries: len(l.ring), Last: l.seq, DisabledReason: l.sess.reason, DisabledAt: l.sess.offAt}
	if l.sess.enabled {
		st.EnabledAt, st.EnabledBy, st.LastActivity = l.sess.at, l.sess.by, l.sess.activity
		st.ExpiresAt = l.sess.activity.Add(IdleLimit)
		if limit := l.sess.at.Add(MaxLifetime); limit.Before(st.ExpiresAt) {
			st.ExpiresAt = limit
		}
	}
	return st
}
