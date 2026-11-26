// SPDX-License-Identifier: Apache-2.0

package store

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	bolt "go.etcd.io/bbolt"
)

// Webhooks (W2.3b): where mydc-web sends incident, CD and ingress events
// and asks for decisions. Secrets and header tokens are sealed, never here.

var (
	bucketWebhooks          = []byte("webhooks")
	bucketWebhookLinks      = []byte("webhook-links")
	bucketWebhookDeliveries = []byte("webhook-deliveries")
)

// WebhookDeliveriesKeep is how many deliveries each webhook keeps.
const WebhookDeliveriesKeep = 1000

// Webhook is one destination.
type Webhook struct {
	Name           string         `json:"name"`
	Tenant         string         `json:"tenant,omitempty"` // "" = cluster (system administrators)
	Kind           string         `json:"kind"`             // external, internal
	URL            string         `json:"url,omitempty"`
	Target         *WebhookTarget `json:"target,omitempty"`
	Role           string         `json:"role"`   // notify, decide
	Format         string         `json:"format"` // mydc, slack, teams, pagerduty
	Sign           string         `json:"sign"`   // hmac, token, none
	TokenLast4     string         `json:"tokenLast4,omitempty"`
	RotatingUntil  time.Time      `json:"rotatingUntil,omitzero"`
	Enabled        bool           `json:"enabled"`
	DisabledReason string         `json:"disabledReason,omitempty"` // failures, manual
	Failures       int            `json:"failures,omitempty"`       // in a row
	CreatedBy      string         `json:"createdBy"`
	CreatedByID    string         `json:"createdById"`
	CreatedAt      time.Time      `json:"createdAt"`
	Revision       uint64         `json:"revision"`
}

// WebhookTarget is an app service inside a workspace network.
type WebhookTarget struct {
	App     string `json:"app"`
	Service string `json:"service"`
	Port    int    `json:"port"`
	Path    string `json:"path"`
	Scheme  string `json:"scheme"` // http, https
	// InsecureSkipVerify (https): accept a certificate the workspace CA
	// bundle does not trust.
	InsecureSkipVerify bool `json:"insecureSkipVerify,omitempty"`
}

// WebhookLink connects a webhook to a point (incident, cd, ingress).
type WebhookLink struct {
	ID      string           `json:"id"`
	Point   string           `json:"point"`
	Scope   WebhookLinkScope `json:"scope"`
	Events  []string         `json:"events"`
	Webhook string           `json:"webhook"`
	// cd only
	Kind         string `json:"kind,omitempty"` // pre-sync, post-sync, notify
	WaitSeconds  int    `json:"waitSeconds,omitempty"`
	OnTimeout    string `json:"onTimeout,omitempty"`
	When         string `json:"when,omitempty"`
	OnFail       string `json:"onFail,omitempty"`
	OpenIncident bool   `json:"openIncident,omitempty"`
	// ingress only: Threshold (error-rate: percent of 5xx, latency: p95
	// ms) and Minutes it must hold before the notice; Recover also sends
	// the recovery.
	Threshold float64 `json:"threshold,omitempty"`
	Minutes   int     `json:"minutes,omitempty"`
	Recover   bool    `json:"recover,omitempty"`
	// Group: the same event of the same target is sent once in 10 minutes.
	Group bool `json:"group,omitempty"`

	CreatedBy string    `json:"createdBy"`
	CreatedAt time.Time `json:"createdAt"`
	Revision  uint64    `json:"revision"`
}

// WebhookLinkScope narrows a link.
type WebhookLinkScope struct {
	Tenant  string `json:"tenant,omitempty"`
	App     string `json:"app,omitempty"`
	Gateway string `json:"gateway,omitempty"`
	Route   string `json:"route,omitempty"` // ingress: one route of the app
}

// WebhookDelivery is one send (with its retries).
type WebhookDelivery struct {
	ID          string    `json:"id"`
	Webhook     string    `json:"webhook"`
	At          time.Time `json:"at"`
	Point       string    `json:"point"` // incident, cd, ingress, test
	Event       string    `json:"event"`
	Link        string    `json:"link,omitempty"` // the link it was sent for
	Status      int       `json:"status,omitempty"`
	MS          int       `json:"ms"`
	Error       string    `json:"error,omitempty"`
	Retries     int       `json:"retries,omitempty"`
	FirstStatus int       `json:"firstStatus,omitempty"`
	Attempt     int       `json:"attempt,omitempty"` // while retrying
	Of          int       `json:"of,omitempty"`
	Decision    string    `json:"decision,omitempty"` // decide: what the answer said
	Accepted    *bool     `json:"accepted,omitempty"`
	Reason      string    `json:"reason,omitempty"`
	Done        bool      `json:"done"`
	Seq         uint64    `json:"seq"` // store order
}

// OK: the final answer was 2xx.
func (d *WebhookDelivery) OK() bool { return d.Error == "" && d.Status >= 200 && d.Status < 300 }

// GetWebhook returns one webhook.
func (s *Store) GetWebhook(name string) (*Webhook, error) {
	var w Webhook
	err := s.db.View(func(tx *bolt.Tx) error { return getJSON(tx.Bucket(bucketWebhooks), []byte(name), &w) })
	if err != nil {
		return nil, err
	}
	return &w, nil
}

// CreateWebhook stores a new webhook; ErrConflict when the name is taken.
func (s *Store) CreateWebhook(w *Webhook) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketWebhooks)
		if b.Get([]byte(w.Name)) != nil {
			return ErrConflict
		}
		w.Revision = 1
		return putJSON(b, []byte(w.Name), w)
	})
}

// UpdateWebhook changes one webhook; expected 0 skips the revision check.
func (s *Store) UpdateWebhook(name string, expected uint64, fn func(w *Webhook) error) (*Webhook, error) {
	var w Webhook
	err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketWebhooks)
		if err := getJSON(b, []byte(name), &w); err != nil {
			return err
		}
		if expected != 0 && w.Revision != expected {
			return ErrConflict
		}
		if err := fn(&w); err != nil {
			return err
		}
		w.Revision++
		return putJSON(b, []byte(name), &w)
	})
	if err != nil {
		return nil, err
	}
	return &w, nil
}

// ListWebhooks returns every webhook by name.
func (s *Store) ListWebhooks() ([]*Webhook, error) {
	var out []*Webhook
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketWebhooks).ForEach(func(_, v []byte) error {
			var w Webhook
			if err := json.Unmarshal(v, &w); err != nil {
				return err
			}
			out = append(out, &w)
			return nil
		})
	})
	return out, err
}

// DeleteWebhook removes a webhook, its links and deliveries.
func (s *Store) DeleteWebhook(name string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketWebhooks)
		if b.Get([]byte(name)) == nil {
			return ErrNotFound
		}
		if err := b.Delete([]byte(name)); err != nil {
			return err
		}
		lb := tx.Bucket(bucketWebhookLinks)
		var drop [][]byte
		_ = lb.ForEach(func(k, v []byte) error {
			var l WebhookLink
			if json.Unmarshal(v, &l) == nil && l.Webhook == name {
				drop = append(drop, append([]byte(nil), k...))
			}
			return nil
		})
		for _, k := range drop {
			if err := lb.Delete(k); err != nil {
				return err
			}
		}
		return deletePrefix(tx.Bucket(bucketWebhookDeliveries), prefix(name))
	})
}

// PutWebhookLink stores a link; expected is its revision (0 = new).
func (s *Store) PutWebhookLink(l *WebhookLink, expected uint64) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketWebhookLinks)
		var cur WebhookLink
		rev := uint64(0)
		if err := getJSON(b, []byte(l.ID), &cur); err == nil {
			rev = cur.Revision
		} else if err != ErrNotFound {
			return err
		}
		if rev != expected {
			return ErrConflict
		}
		l.Revision = rev + 1
		return putJSON(b, []byte(l.ID), l)
	})
}

// GetWebhookLink returns one link.
func (s *Store) GetWebhookLink(id string) (*WebhookLink, error) {
	var l WebhookLink
	err := s.db.View(func(tx *bolt.Tx) error { return getJSON(tx.Bucket(bucketWebhookLinks), []byte(id), &l) })
	if err != nil {
		return nil, err
	}
	return &l, nil
}

// ListWebhookLinks returns every link, oldest first.
func (s *Store) ListWebhookLinks() ([]*WebhookLink, error) {
	var out []*WebhookLink
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketWebhookLinks).ForEach(func(_, v []byte) error {
			var l WebhookLink
			if err := json.Unmarshal(v, &l); err != nil {
				return err
			}
			out = append(out, &l)
			return nil
		})
	})
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out, err
}

// DeleteWebhookLink removes a link.
func (s *Store) DeleteWebhookLink(id string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketWebhookLinks)
		if b.Get([]byte(id)) == nil {
			return ErrNotFound
		}
		return b.Delete([]byte(id))
	})
}

func deliveryKey(d *WebhookDelivery) []byte {
	return key(d.Webhook, fmt.Sprintf("%020d", d.Seq))
}

// PutWebhookDelivery stores (or updates) a delivery and keeps the newest
// WebhookDeliveriesKeep of its webhook.
func (s *Store) PutWebhookDelivery(d *WebhookDelivery) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketWebhookDeliveries)
		if d.Seq == 0 {
			n, err := b.NextSequence()
			if err != nil {
				return err
			}
			d.Seq = n
		}
		if err := putJSON(b, deliveryKey(d), d); err != nil {
			return err
		}
		p := prefix(d.Webhook)
		var keys [][]byte
		c := b.Cursor()
		for k, _ := c.Seek(p); k != nil && bytes.HasPrefix(k, p); k, _ = c.Next() {
			keys = append(keys, append([]byte(nil), k...))
		}
		for len(keys) > WebhookDeliveriesKeep {
			if err := b.Delete(keys[0]); err != nil {
				return err
			}
			keys = keys[1:]
		}
		return nil
	})
}

// ListWebhookDeliveries returns a webhook's deliveries, newest first.
func (s *Store) ListWebhookDeliveries(name string) ([]*WebhookDelivery, error) {
	var out []*WebhookDelivery
	err := s.db.View(func(tx *bolt.Tx) error {
		c := tx.Bucket(bucketWebhookDeliveries).Cursor()
		p := prefix(name)
		for k, v := c.Seek(p); k != nil && bytes.HasPrefix(k, p); k, v = c.Next() {
			var d WebhookDelivery
			if err := json.Unmarshal(v, &d); err != nil {
				return err
			}
			out = append(out, &d)
		}
		return nil
	})
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out, err
}

var (
	bucketWebhookCDChecks       = []byte("webhook-cd-checks")
	bucketWebhookCDCheckHistory = []byte("webhook-cd-check-history")
)

// CDCheck is the latest pre-sync or post-sync check of an app.
type CDCheck struct {
	Tenant    string    `json:"tenant"`
	App       string    `json:"app"`
	Kind      string    `json:"kind"` // pre-sync, post-sync
	Candidate string    `json:"candidate"`
	Commit    string    `json:"commit,omitempty"`
	Link      string    `json:"link"`
	Webhook   string    `json:"webhook"`
	State     string    `json:"state"` // checking, held, passed, rejected, timeout, failed (pre); checking, ok, failed, timeout (post)
	At        time.Time `json:"at"`
	Reason    string    `json:"reason,omitempty"`
	Status    int       `json:"status,omitempty"`
	Delivery  string    `json:"delivery,omitempty"`
	// post-sync: what followed a failure.
	Actions []CDCheckAction `json:"actions,omitempty"`
}

// CDCheckAction is one step after a failed post-sync check.
type CDCheckAction struct {
	Kind     string `json:"kind"`  // pause, rollback-request
	State    string `json:"state"` // done, failed
	Code     string `json:"code,omitempty"`
	Incident string `json:"incident,omitempty"`
}

// PutCDCheck stores the latest check of its kind for the app.
// It is also kept per candidate (CDCheckHistoryKeep per app) for the
// history rows.
func (s *Store) PutCDCheck(c *CDCheck) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		if err := putJSON(tx.Bucket(bucketWebhookCDChecks), key(c.Kind, c.Tenant, c.App), c); err != nil {
			return err
		}
		if c.Candidate == "" {
			return nil
		}
		hb := tx.Bucket(bucketWebhookCDCheckHistory)
		if err := putJSON(hb, key(c.Tenant, c.App, c.Candidate, c.Kind), c); err != nil {
			return err
		}
		type row struct {
			k  []byte
			at time.Time
		}
		var rows []row
		p := prefix(c.Tenant, c.App)
		cur := hb.Cursor()
		for k, v := cur.Seek(p); k != nil && bytes.HasPrefix(k, p); k, v = cur.Next() {
			var x CDCheck
			if json.Unmarshal(v, &x) == nil {
				rows = append(rows, row{append([]byte(nil), k...), x.At})
			}
		}
		if len(rows) <= CDCheckHistoryKeep {
			return nil
		}
		sort.Slice(rows, func(i, j int) bool { return rows[i].at.Before(rows[j].at) })
		for _, r := range rows[:len(rows)-CDCheckHistoryKeep] {
			if err := hb.Delete(r.k); err != nil {
				return err
			}
		}
		return nil
	})
}

// CDCheckHistoryKeep is how many checks each app keeps for its history.
const CDCheckHistoryKeep = 400

// CDCheckHistory returns an app's kept checks by candidate, then kind.
func (s *Store) CDCheckHistory(tenant, app string) (map[string]map[string]*CDCheck, error) {
	out := map[string]map[string]*CDCheck{}
	err := s.db.View(func(tx *bolt.Tx) error {
		p := prefix(tenant, app)
		cur := tx.Bucket(bucketWebhookCDCheckHistory).Cursor()
		for k, v := cur.Seek(p); k != nil && bytes.HasPrefix(k, p); k, v = cur.Next() {
			var x CDCheck
			if json.Unmarshal(v, &x) != nil {
				continue
			}
			if out[x.Candidate] == nil {
				out[x.Candidate] = map[string]*CDCheck{}
			}
			out[x.Candidate][x.Kind] = &x
		}
		return nil
	})
	return out, err
}

// GetCDCheck returns the latest check of a kind (nil when none).
func (s *Store) GetCDCheck(kind, tenant, app string) (*CDCheck, error) {
	var c CDCheck
	err := s.db.View(func(tx *bolt.Tx) error { return getJSON(tx.Bucket(bucketWebhookCDChecks), key(kind, tenant, app), &c) })
	if err == ErrNotFound {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &c, nil
}
