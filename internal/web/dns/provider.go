// SPDX-License-Identifier: Apache-2.0

// Package dns is mydc-web's external DNS adapter layer (devel/design/
// web-dns-plan.md). The web app calls DNS providers directly; nothing here
// reaches mydcd. Each vendor is one adapter behind Provider; the rest of the
// web code knows only this interface.
//
// Changes are planned and applied per RRSet (one name + type). Applying an
// RRSet replaces the whole set with the wanted value, so applying the same
// change twice gives the same zone.
package dns

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/jay94ks/mydcd/internal/web/provlog"
)

// Record is one value of an RRSet.
type Record struct {
	Content  string `json:"content"`
	Priority int    `json:"priority,omitempty"` // MX, SRV
}

// RRSet is all records of one name and type. Name is relative to the zone:
// "@" for the apex, "www", "*.shop".
type RRSet struct {
	Name    string   `json:"name"`
	Type    string   `json:"type"`
	TTL     int      `json:"ttl"`
	Records []Record `json:"records"`
}

// Key names an RRSet.
type Key struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

func (k Key) String() string { return k.Name + "|" + k.Type }

// Key returns the set's key.
func (r RRSet) Key() Key { return Key{r.Name, r.Type} }

// Zone is a domain's records.
type Zone struct {
	Domain string  `json:"domain"`
	Sets   []RRSet `json:"sets"`
}

// Find returns the set with key k, or nil.
func (z Zone) Find(k Key) *RRSet {
	for i := range z.Sets {
		if z.Sets[i].Name == k.Name && z.Sets[i].Type == k.Type {
			return &z.Sets[i]
		}
	}
	return nil
}

// ChangeSet is a list of RRSets to replace and keys to delete.
type ChangeSet struct {
	Upsert []RRSet `json:"upsert"`
	Delete []Key   `json:"delete"`
}

// Fingerprint identifies an RRSet's content ("absent" for nil). Record
// order does not matter.
func Fingerprint(r *RRSet) string {
	if r == nil {
		return "absent"
	}
	vals := make([]string, len(r.Records))
	for i, v := range r.Records {
		vals[i] = fmt.Sprintf("%d %s", v.Priority, v.Content)
	}
	sort.Strings(vals)
	h := sha256.Sum256([]byte(fmt.Sprintf("%s\x00%s\x00%d\x00%s", r.Name, r.Type, r.TTL, strings.Join(vals, "\x00"))))
	return hex.EncodeToString(h[:12])
}

// ProviderInfo describes a vendor.
type ProviderInfo struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	TokenURL string `json:"tokenUrl,omitempty"` // where to create an API token
	// Ready is false for an adapter that is listed but not usable yet (the
	// screen shows it greyed out).
	Ready bool   `json:"ready"`
	Note  string `json:"note,omitempty"`
}

// Rate is a provider request limit.
type Rate struct {
	Requests int           `json:"requests"`
	Per      time.Duration `json:"per"`
}

// Capabilities says what an adapter can do; the screen hides the rest.
type Capabilities struct {
	RecordTypes []string `json:"recordTypes"`
	Wildcard    bool     `json:"wildcard"`
	MinTTL      int      `json:"minTtl"`
	PerRecordID bool     `json:"perRecordId"`
	Validate    bool     `json:"validate"`
	Snapshots   bool     `json:"snapshots"`
	Nameservers bool     `json:"nameservers"`
	Propagation bool     `json:"propagation"`
	RateLimit   Rate     `json:"rateLimit"`
}

// Account is the result of a token check.
type Account struct {
	Name      string    `json:"name"`
	Scope     string    `json:"scope,omitempty"`
	Domains   int       `json:"domains"`
	Remaining int       `json:"remaining"` // requests left in the current window, -1 unknown
	ExpiresAt time.Time `json:"expiresAt,omitzero"`
}

// Domain is a domain of the provider account.
type Domain struct {
	Name string `json:"name"`
	// HasZone is false when the domain's DNS is not served by this provider
	// (its nameservers point elsewhere): it cannot be connected.
	HasZone bool `json:"hasZone"`
}

// ApplyResult is what Apply did.
type ApplyResult struct {
	Snapshot string `json:"snapshot,omitempty"` // provider snapshot taken before the change
}

// Problem is a provider validation finding.
type Problem struct {
	Name    string `json:"name"`
	Type    string `json:"type"`
	Message string `json:"message"`
}

// Snapshot is a provider-kept restore point.
type Snapshot struct {
	ID        string    `json:"id"`
	CreatedAt time.Time `json:"createdAt"`
	Reason    string    `json:"reason,omitempty"`
}

// Provider is one vendor account (one API token).
type Provider interface {
	Info() ProviderInfo
	Capabilities() Capabilities
	Check(ctx context.Context) (Account, error)
	ListDomains(ctx context.Context) ([]Domain, error)
	GetZone(ctx context.Context, domain string) (Zone, error)
	Apply(ctx context.Context, domain string, c ChangeSet) (ApplyResult, error)
}

// Validator checks a change before it is applied (Capabilities.Validate).
type Validator interface {
	Validate(ctx context.Context, domain string, c ChangeSet) ([]Problem, error)
}

// Snapshotter lists and restores provider snapshots (Capabilities.Snapshots).
type Snapshotter interface {
	ListSnapshots(ctx context.Context, domain string) ([]Snapshot, error)
	RestoreSnapshot(ctx context.Context, domain, id string) error
}

// Kind classifies a provider error. The vendor's own message stays in
// Detail ("자세히" on screen).
type Kind string

const (
	AuthFailed  Kind = "auth-failed"
	Forbidden   Kind = "forbidden"
	NotFound    Kind = "not-found"
	RateLimited Kind = "rate-limited"
	Invalid     Kind = "invalid"
	Conflict    Kind = "conflict"
	Unavailable Kind = "unavailable"
)

// Error is a classified provider error.
type Error struct {
	Kind       Kind
	Detail     string
	RetryAfter time.Duration
}

func (e *Error) Error() string {
	if e.Detail == "" {
		return "dns: " + string(e.Kind)
	}
	return "dns: " + string(e.Kind) + ": " + e.Detail
}

// KindOf returns the error kind (Unavailable for unclassified errors).
func KindOf(err error) Kind {
	var e *Error
	if errors.As(err, &e) {
		return e.Kind
	}
	return Unavailable
}

// Env is what an adapter gets besides its token.
type Env struct {
	// Conn is the web connection ID (empty while a new token is checked).
	Conn string
	// Log is the provider diagnostic log (nil: none).
	Log *provlog.Log
	// Transport reaches the vendor (nil: http.DefaultTransport). The
	// adapter wraps it with provlog.Transport.
	Transport http.RoundTripper
	// BaseURL replaces the vendor API address (tests).
	BaseURL string
}

// Vendor builds providers of one vendor.
type Vendor struct {
	Info         ProviderInfo
	Capabilities Capabilities
	New          func(token string, env Env) Provider // nil when not Ready
}

// Registry is the set of vendor adapters. A new vendor is one adapter file
// and one Register line. Log, Transport and BaseURL go to every adapter
// through Env.
type Registry struct {
	vendors   []Vendor
	Log       *provlog.Log
	Transport http.RoundTripper
	BaseURL   string
}

// NewRegistry returns the default registry. Tests register the in-process
// fake vendor themselves (FakeVendor).
func NewRegistry(log *provlog.Log) *Registry {
	r := &Registry{Log: log}
	r.Register(HostingerVendor())
	return r
}

// Register adds a vendor.
func (r *Registry) Register(v Vendor) { r.vendors = append(r.vendors, v) }

// Capabilities returns the listed capabilities of vendor id (what the
// screen is told), and false for an unknown vendor.
func (r *Registry) Capabilities(id string) (Capabilities, bool) {
	for _, v := range r.Vendors() {
		if v.Info.ID == id {
			return v.Capabilities, true
		}
	}
	return Capabilities{}, false
}

// Vendors lists the vendors in registration order.
func (r *Registry) Vendors() []Vendor {
	if r == nil {
		return nil
	}
	return r.vendors
}

// Open returns a provider of vendor id with token for the web connection
// conn (empty while a new token is checked).
func (r *Registry) Open(id, conn, token string) (Provider, error) {
	for _, v := range r.Vendors() {
		if v.Info.ID == id {
			if v.New == nil {
				return nil, &Error{Kind: Invalid, Detail: v.Info.Name + " is not available yet"}
			}
			return v.New(token, Env{Conn: conn, Log: r.Log, Transport: r.Transport, BaseURL: r.BaseURL}), nil
		}
	}
	return nil, &Error{Kind: Invalid, Detail: "unknown DNS vendor " + id}
}
