// SPDX-License-Identifier: Apache-2.0

package store

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	bolt "go.etcd.io/bbolt"
)

// Settings are the web app's own settings (UI-C1). Zero values mean the
// default.
type Settings struct {
	// SessionMaxHours caps a web login (0: until the SFCP session ends).
	SessionMaxHours int `json:"sessionMaxHours"`
	// SessionIdleMinutes ends a login with no browser request for this long
	// (0: off).
	SessionIdleMinutes        int `json:"sessionIdleMinutes"`
	OpRetentionDays           int `json:"opRetentionDays"`
	AuditRetentionDays        int `json:"auditRetentionDays"`
	NotificationRetentionDays int `json:"notificationRetentionDays"`
	// AllowKeyLogin: browser key login (nil: allowed).
	AllowKeyLogin *bool `json:"allowKeyLogin,omitempty"`
	// MaxSessionsPerUser caps one user's live logins; the oldest ends
	// first (0: no cap).
	MaxSessionsPerUser           int `json:"maxSessionsPerUser"`
	WebhookDeliveryRetentionDays int `json:"webhookDeliveryRetentionDays"`
	MCPCallRetentionDays         int `json:"mcpCallRetentionDays"`
	// TrashRetentionDays: how long deleted definitions can be restored
	// (UI-A5; 0: 7 days).
	TrashRetentionDays int       `json:"trashRetentionDays"`
	UpdatedBy          string    `json:"updatedBy,omitempty"`
	UpdatedAt          time.Time `json:"updatedAt,omitzero"`
}

var keyWebSettings = []byte("web")

// GetSettings returns the stored settings, or nil if none were saved.
func (s *Store) GetSettings() (*Settings, error) {
	var out *Settings
	err := s.db.View(func(tx *bolt.Tx) error {
		var v Settings
		err := getJSON(tx.Bucket(bucketSettings), keyWebSettings, &v)
		if err == ErrNotFound {
			return nil
		}
		out = &v
		return err
	})
	return out, err
}

// PutSettings replaces the settings.
func (s *Store) PutSettings(v *Settings) (err error) {
	defer func() { s.changed(err, Change{Kind: "settings", ID: "web"}) }()
	return s.db.Update(func(tx *bolt.Tx) error {
		return putJSON(tx.Bucket(bucketSettings), keyWebSettings, v)
	})
}

// AuditEntry is one change of a web app setting (UI-A3): who changed what,
// where, with before and after values. Secrets appear only as the fact that
// they changed. Entries cannot be deleted; they expire after the retention.
type AuditEntry struct {
	ID       string          `json:"id"`
	At       time.Time       `json:"at"`
	User     string          `json:"user"`
	Username string          `json:"username"`
	Tenant   string          `json:"tenant,omitempty"` // "" for system-wide settings
	Area     string          `json:"area"`             // web-settings, seal, dns, acme, notify, archived, ...
	Action   string          `json:"action"`
	Target   string          `json:"target,omitempty"`
	Before   json.RawMessage `json:"before,omitempty"`
	After    json.RawMessage `json:"after,omitempty"`
}

func auditKey(at time.Time, id string) []byte {
	return key(fmt.Sprintf("%020d", at.UnixNano()), id)
}

// AppendAudit adds an audit entry.
func (s *Store) AppendAudit(e *AuditEntry) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		return putJSON(tx.Bucket(bucketAudit), auditKey(e.At, e.ID), e)
	})
}

// ListAudit returns entries newest first, older than before (zero: now),
// for which keep returns true, at most limit.
func (s *Store) ListAudit(before time.Time, limit int, keep func(*AuditEntry) bool) ([]*AuditEntry, error) {
	var out []*AuditEntry
	err := s.db.View(func(tx *bolt.Tx) error {
		c := tx.Bucket(bucketAudit).Cursor()
		var k, v []byte
		if before.IsZero() {
			k, v = c.Last()
		} else {
			k, v = c.Seek([]byte(fmt.Sprintf("%020d", before.UnixNano())))
			if k == nil {
				k, v = c.Last()
			} else {
				k, v = c.Prev()
			}
		}
		for ; k != nil && (limit <= 0 || len(out) < limit); k, v = c.Prev() {
			var e AuditEntry
			if err := jsonUnmarshal(v, &e); err != nil {
				return err
			}
			if keep == nil || keep(&e) {
				out = append(out, &e)
			}
		}
		return nil
	})
	return out, err
}

// PruneAudit deletes entries older than cutoff.
func (s *Store) PruneAudit(cutoff time.Time) (int, error) {
	return pruneTimeOrdered(s, bucketAudit, nil, cutoff)
}

// pruneTimeOrdered deletes keys of b (optionally under pfx) whose next part
// is a %020d nanosecond time before cutoff.
func pruneTimeOrdered(s *Store, bucket, pfx []byte, cutoff time.Time) (int, error) {
	limit := []byte(fmt.Sprintf("%020d", cutoff.UnixNano()))
	n := 0
	err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucket)
		c := b.Cursor()
		var dead [][]byte
		for k, _ := c.Seek(pfx); k != nil && hasPrefix(k, pfx); k, _ = c.Next() {
			if string(k[len(pfx):min(len(k), len(pfx)+20)]) < string(limit) {
				dead = append(dead, append([]byte(nil), k...))
			}
		}
		for _, k := range dead {
			if err := b.Delete(k); err != nil {
				return err
			}
		}
		n = len(dead)
		return nil
	})
	return n, err
}

// Notification is a copy of an event for one user (UI-C0). The event's
// authority stays with sfcd or the web feature that raised it.
type Notification struct {
	ID       string `json:"id"`
	User     string `json:"user"`
	Kind     string `json:"kind"` // op-failed, op-unknown, deploy-done, ...
	Severity string `json:"severity"`
	Tenant   string `json:"tenant,omitempty"`
	Title    string `json:"title"`
	Body     string `json:"body,omitempty"`
	// Text is the notification as message codes and values; when set, the
	// reader's language renders Title and Body (rows stored before it keep
	// their Korean Title and Body).
	Text      *NoticeText `json:"text,omitempty"`
	Link      string      `json:"link,omitempty"` // UI route
	Action    bool        `json:"action"`         // needs something from the user
	CreatedAt time.Time   `json:"createdAt"`
	ReadAt    time.Time   `json:"readAt,omitzero"`
}

// NoticeText names a notification's message codes: Title, then Body as one
// or more sentences joined in order. Args fill {name} in them; values (an
// sfcd error code, a host) are never translated.
type NoticeText struct {
	Title string            `json:"title"`
	Body  []string          `json:"body,omitempty"`
	Args  map[string]string `json:"args,omitempty"`
	// Phrases fill {name} with text rendered in the same language.
	Phrases map[string]Phrase `json:"phrases,omitempty"`
}

// Phrase is one web-made sentence kept as a message code and values, made
// into text in the reader's language. Args fill {name} as they are;
// Phrases fill {name} with a phrase rendered in the same language; Parts
// fill {parts}, joined with "; ".
type Phrase struct {
	Code    string            `json:"code"`
	Args    map[string]string `json:"args,omitempty"`
	Phrases map[string]Phrase `json:"phrases,omitempty"`
	Parts   []Phrase          `json:"parts,omitempty"`
}

func notifyKey(user string, at time.Time, id string) []byte {
	return key(user, fmt.Sprintf("%020d", at.UnixNano()), id)
}

// PutNotification stores a notification.
func (s *Store) PutNotification(n *Notification) (err error) {
	defer func() { s.changed(err, Change{Kind: "notification", User: n.User, ID: n.ID}) }()
	return s.db.Update(func(tx *bolt.Tx) error {
		return putJSON(tx.Bucket(bucketNotify), notifyKey(n.User, n.CreatedAt, n.ID), n)
	})
}

// ListNotifications returns a user's notifications newest first (at most
// limit, unread only if unread) and the unread count.
func (s *Store) ListNotifications(user string, unreadOnly bool, limit int) ([]*Notification, int, error) {
	var out []*Notification
	unread := 0
	err := s.db.View(func(tx *bolt.Tx) error {
		c := tx.Bucket(bucketNotify).Cursor()
		p := prefix(user)
		var all []*Notification
		for k, v := c.Seek(p); k != nil && hasPrefix(k, p); k, v = c.Next() {
			var n Notification
			if err := jsonUnmarshal(v, &n); err != nil {
				return err
			}
			all = append(all, &n)
		}
		for i := len(all) - 1; i >= 0; i-- {
			n := all[i]
			if n.ReadAt.IsZero() {
				unread++
			} else if unreadOnly {
				continue
			}
			if limit <= 0 || len(out) < limit {
				out = append(out, n)
			}
		}
		return nil
	})
	return out, unread, err
}

// MarkNotificationsRead marks a user's notifications read: the one with id,
// or all when id is "".
func (s *Store) MarkNotificationsRead(user, id string, at time.Time) (err error) {
	defer func() { s.changed(err, Change{Kind: "notification", User: user, ID: id}) }()
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketNotify)
		c := b.Cursor()
		p := prefix(user)
		found := false
		type kv struct {
			k []byte
			n *Notification
		}
		var upd []kv
		for k, v := c.Seek(p); k != nil && hasPrefix(k, p); k, v = c.Next() {
			if id != "" && lastPart(k) != id {
				continue
			}
			found = true
			var n Notification
			if err := jsonUnmarshal(v, &n); err != nil {
				return err
			}
			if n.ReadAt.IsZero() {
				n.ReadAt = at
				upd = append(upd, kv{append([]byte(nil), k...), &n})
			}
		}
		if id != "" && !found {
			return ErrNotFound
		}
		for _, u := range upd {
			if err := putJSON(b, u.k, u.n); err != nil {
				return err
			}
		}
		return nil
	})
}

// PruneNotifications deletes notifications created before cutoff.
func (s *Store) PruneNotifications(cutoff time.Time) (int, error) {
	var users []string
	_ = s.db.View(func(tx *bolt.Tx) error {
		c := tx.Bucket(bucketNotify).Cursor()
		for k, _ := c.First(); k != nil; {
			u := string(k[:indexNUL(k)])
			users = append(users, u)
			k, _ = c.Seek(append(prefix(u)[:len(u)], 1))
		}
		return nil
	})
	total := 0
	for _, u := range users {
		n, err := pruneTimeOrdered(s, bucketNotify, prefix(u), cutoff)
		if err != nil {
			return total, err
		}
		total += n
	}
	return total, nil
}

func indexNUL(k []byte) int {
	for i, c := range k {
		if c == 0 {
			return i
		}
	}
	return len(k)
}

// NotifyPrefs is how a user wants notifications (UI-C0).
type NotifyPrefs struct {
	MutedKinds   []string `json:"mutedKinds"`
	MutedTenants []string `json:"mutedTenants"`
	Browser      bool     `json:"browser"` // browser notifications while a tab is open
}

// GetNotifyPrefs returns a user's notification settings (zero if unset).
func (s *Store) GetNotifyPrefs(user string) (*NotifyPrefs, error) {
	p := &NotifyPrefs{}
	err := s.db.View(func(tx *bolt.Tx) error {
		err := getJSON(tx.Bucket(bucketNotifyPrefs), []byte(user), p)
		if err == ErrNotFound {
			return nil
		}
		return err
	})
	return p, err
}

// PutNotifyPrefs stores a user's notification settings.
func (s *Store) PutNotifyPrefs(user string, p *NotifyPrefs) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		return putJSON(tx.Bucket(bucketNotifyPrefs), []byte(user), p)
	})
}

// Backup writes a consistent copy of the whole DB file. open is called once
// inside the read transaction with the copy's exact size and returns where
// to write it. Sealed files are a different folder and never part of it.
func (s *Store) Backup(open func(size int64) io.Writer) (int64, error) {
	var n int64
	err := s.db.View(func(tx *bolt.Tx) error {
		var err error
		n, err = tx.WriteTo(open(tx.Size()))
		return err
	})
	return n, err
}

// Size returns the DB size in bytes.
func (s *Store) Size() int64 {
	var n int64
	_ = s.db.View(func(tx *bolt.Tx) error { n = tx.Size(); return nil })
	return n
}

// Check opens a DB file read-only and verifies that it is a web DB of a
// supported schema (used before a restore is staged).
func Check(path string) error {
	db, err := bolt.Open(path, 0o600, &bolt.Options{ReadOnly: true, Timeout: time.Second})
	if err != nil {
		return fmt.Errorf("not a web data file: %w", err)
	}
	defer db.Close()
	return db.View(func(tx *bolt.Tx) error {
		meta := tx.Bucket(bucketMeta)
		if meta == nil {
			return fmt.Errorf("not a web data file: no meta")
		}
		raw := meta.Get(keySchema)
		if len(raw) != 8 {
			return fmt.Errorf("not a web data file: no schema")
		}
		if v := binary.BigEndian.Uint64(raw); v != SchemaVersion {
			return fmt.Errorf("web data schema %d is not supported (want %d)", v, SchemaVersion)
		}
		return nil
	})
}

// ApplyRestore swaps a staged restore file in for the DB at dbPath before
// the DB is opened. The replaced DB is kept as <dbPath>.before-restore-<time>.
// It reports whether a restore was applied.
func ApplyRestore(dbPath, restorePath string, now time.Time) (bool, error) {
	if _, err := os.Stat(restorePath); errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err := Check(restorePath); err != nil {
		return false, fmt.Errorf("staged restore %s: %w", restorePath, err)
	}
	if _, err := os.Stat(dbPath); err == nil {
		if err := os.Rename(dbPath, dbPath+".before-restore-"+now.UTC().Format("20060102-150405")); err != nil {
			return false, err
		}
	}
	if err := os.Rename(restorePath, dbPath); err != nil {
		return false, err
	}
	return true, nil
}

// AutoBackup is the web DB's scheduled copy into a tenant volume (UI-C1):
// the schedule (server local time), how many copies to keep, where, and
// the last run. Web-own data; the copies themselves are volume files.
type AutoBackup struct {
	Enabled bool   `json:"enabled"`
	At      string `json:"at"` // "HH:MM", server local time
	Keep    int    `json:"keep"`
	Tenant  string `json:"tenant,omitempty"`
	Volume  string `json:"volume,omitempty"`
	// UpdatedByID is told when a scheduled run cannot run or fails.
	UpdatedByID string         `json:"updatedById,omitempty"`
	UpdatedBy   string         `json:"updatedBy,omitempty"`
	UpdatedAt   time.Time      `json:"updatedAt,omitzero"`
	Last        *AutoBackupRun `json:"last,omitempty"`
	// Slot: the scheduled time last handled (run or skipped).
	Slot time.Time `json:"slot,omitzero"`
}

type AutoBackupRun struct {
	At    time.Time `json:"at"`
	OK    bool      `json:"ok"`
	Bytes int64     `json:"bytes,omitempty"`
	Path  string    `json:"path,omitempty"`
	Error string    `json:"error,omitempty"`
	By    string    `json:"by,omitempty"` // username of the session that ran it
}

var keyAutoBackup = []byte("auto-backup")

// GetAutoBackup returns the stored auto-backup row, or nil.
func (s *Store) GetAutoBackup() (*AutoBackup, error) {
	var out *AutoBackup
	err := s.db.View(func(tx *bolt.Tx) error {
		var v AutoBackup
		err := getJSON(tx.Bucket(bucketSettings), keyAutoBackup, &v)
		if err == ErrNotFound {
			return nil
		}
		out = &v
		return err
	})
	return out, err
}

// PutAutoBackup replaces the auto-backup row.
func (s *Store) PutAutoBackup(v *AutoBackup) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		return putJSON(tx.Bucket(bucketSettings), keyAutoBackup, v)
	})
}

// Automation is the web's automation account: an ordinary sfcd
// account the web logs in to with its own key, for work no person is
// there to sign (scheduled backups, certificate renewal, incident
// actions). Only the public key is kept here; the private key is a sealed
// file. sfcd decides what the account may do (put-user keys,
// set-account-scope, memberships).
type Automation struct {
	Username    string           `json:"username"`
	UserID      string           `json:"userId,omitempty"` // from the last successful login
	PublicKey   string           `json:"publicKey"`        // hex, 32 bytes
	CreatedByID string           `json:"createdById"`
	CreatedBy   string           `json:"createdBy"`
	CreatedAt   time.Time        `json:"createdAt"`
	LastCheck   *AutomationCheck `json:"lastCheck,omitempty"`
}

// AutomationCheck is the last login of the automation account.
type AutomationCheck struct {
	At     time.Time `json:"at"`
	OK     bool      `json:"ok"`
	User   string    `json:"user,omitempty"` // user ID sfcd answered
	Error  string    `json:"error,omitempty"`
	Reason string    `json:"reason,omitempty"` // what the login was for
}

var keyAutomation = []byte("automation")

// GetAutomation returns the automation account row, or nil.
func (s *Store) GetAutomation() (*Automation, error) {
	var out *Automation
	err := s.db.View(func(tx *bolt.Tx) error {
		var v Automation
		err := getJSON(tx.Bucket(bucketSettings), keyAutomation, &v)
		if err == ErrNotFound {
			return nil
		}
		out = &v
		return err
	})
	return out, err
}

// PutAutomation replaces the automation account row; nil removes it.
func (s *Store) PutAutomation(v *Automation) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		if v == nil {
			return tx.Bucket(bucketSettings).Delete(keyAutomation)
		}
		return putJSON(tx.Bucket(bucketSettings), keyAutomation, v)
	})
}
