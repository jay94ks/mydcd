// SPDX-License-Identifier: Apache-2.0

// Package vps is sfcd's VPS provider layer (devel/design/vps-nodes.md,
// vps-hostinger.md). A vendor is either Managed (sfcd creates, stops,
// starts and deletes VPS nodes and keeps them under a cost cap, through a
// ManagedProvider) or Owned (the operator keeps the instances; sfcd only
// attaches, powers and reads them, through an OwnedProvider). Both share
// Base. The rest of sfcd knows only these interfaces; each vendor is one
// adapter.
//
// Credentials are given to New by the caller and never kept in errors,
// String or JSON output. Errors carry only a fixed Kind and the vendor's
// error code, never a response body.
package vps

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"time"
)

// Kind is a fixed error class. Callers decide retries and messages from it.
type Kind string

const (
	KindAuth        Kind = "AUTH"        // credential or signature refused
	KindIPDenied    Kind = "IP_DENIED"   // the key does not allow this source IP
	KindNotFound    Kind = "NOT_FOUND"   // no such instance (or already returned)
	KindBusy        Kind = "BUSY"        // instance is being worked on or in the wrong state
	KindUnavailable Kind = "UNAVAILABLE" // zone/image/flavor combination not sold now
	KindLimit       Kind = "LIMIT"       // account limit reached
	KindInvalid     Kind = "INVALID"     // request field refused
	KindEmpty       Kind = "EMPTY"       // nothing to report (no traffic or bill yet)
	KindTransport   Kind = "TRANSPORT"   // network, timeout or 5xx; effect unknown for mutations
	KindProtocol    Kind = "PROTOCOL"    // response could not be understood
)

// Error is a provider failure. Code is the vendor's own code (for example
// "UNAVAILABLE_FLAVOR"); Fields names the refused request fields when the
// vendor says so.
type Error struct {
	Kind   Kind
	Code   string
	Fields []string
}

func (e *Error) Error() string {
	if e.Code == "" {
		return "vps provider: " + string(e.Kind)
	}
	return fmt.Sprintf("vps provider: %s (%s)", e.Kind, e.Code)
}

// KindOf returns err's Kind, or "" when err is not a provider error.
func KindOf(err error) Kind {
	var e *Error
	if errors.As(err, &e) {
		return e.Kind
	}
	return ""
}

// Status is a normalized instance state.
type Status string

const (
	StatusPending Status = "pending" // being created
	StatusActive  Status = "active"  // running
	StatusWorking Status = "working" // a vendor job (start, shutdown, rebuild) is running
	StatusOff     Status = "off"     // powered off
	StatusError   Status = "error"
)

// Account is who the credential belongs to.
type Account struct {
	ID, Name string
}

// Zone is a place an instance can be created.
type Zone struct {
	ID, Name string
	Usable   bool // the vendor accepts new instances there now
}

// Image is an OS image.
type Image struct {
	ID, Name string
	Kind     string   // vendor image kind, matched by Flavor.ImageKinds (iwinv "os_linux")
	OS       string   // vendor OS family, for example "UBUNTU"
	Linux    bool     // sfcd only runs on Linux images
	Zones    []string // zones the image can be used in
}

// Price is an amount in KRW (VAT included) per Per.
type Price struct {
	KRW int64
	Per string // vendor billing unit in lower case: "month", "day", "hour"
}

// Provision is how a flavor's CPU is provided.
const (
	ProvideDedicated = "dedicated"
	ProvideShared    = "shared"
	ProvideTest      = "test"
)

// GPU is the GPU part of a flavor.
type GPU struct {
	Count    int
	MemoryGB int64 // per GPU
	Model    string
}

// FlavorZone says whether a flavor can be created in a zone now. A zone
// that is listed but not Available is out of stock for the moment.
type FlavorZone struct {
	ID        string
	Available bool
}

// Flavor is an instance type, as the vendor's catalogue shows it.
type Flavor struct {
	ID, Name    string
	Provide     string // ProvideDedicated, ProvideShared, ProvideTest, or "" when unknown
	CoreType    string // vendor core class, for example "SINGLE", "MAXIO", "STABILITY"
	VCPU        int
	MemoryMiB   int64
	DiskGB      int64
	NetworkGbps float64
	GPU         *GPU     // nil without a GPU
	Full        Price    // fixed-period price
	Partial     *Price   // per-day or per-hour price, nil when not offered
	ImageKinds  []string // Image.Kind values it can boot; empty means not reported
	Zones       []FlavorZone
	// Traffic is the free traffic an instance of this type gets, nil when
	// not known before creation.
	Traffic *Allowance
}

// Allowance is a free traffic allowance: GB per Period ("DAY" or "MONTH"),
// a daily one adding up to at most MaxGB a month (0 = no ceiling).
// Estimated: the vendor's catalogue does not report it, so it is the
// vendor's usual allowance; the created instance reports the real one.
type Allowance struct {
	GB        int64
	Period    string
	MaxGB     int64
	Estimated bool
}

// AvailableIn reports whether f can be created in zone now.
func (f Flavor) AvailableIn(zone string) bool {
	for _, z := range f.Zones {
		if z.ID == zone {
			return z.Available
		}
	}
	return false
}

// Boots reports whether f can be created with img. A flavor that does not
// report its image kinds is taken to boot any image; the vendor still has
// the last word at create time.
func (f Flavor) Boots(img Image) bool {
	if len(f.ImageKinds) == 0 {
		return true
	}
	for _, k := range f.ImageKinds {
		if k == img.Kind {
			return true
		}
	}
	return false
}

// FlavorQuery narrows a flavor list. Zero fields do not filter. Several
// values in one list field mean "any of them".
type FlavorQuery struct {
	Zones, Images, CoreTypes   []string
	MinVCPU, MaxVCPU           int
	MinMemoryMiB, MaxMemoryMiB int64
	MinDiskGB, MaxDiskGB       int64
	MinGPU, MaxGPU             int
}

// SSHKey is a key registered with the vendor.
type SSHKey struct {
	ID, Name string
}

// Script is a user script registered with the vendor. It runs once on the
// new instance's first boot.
type Script struct {
	ID, Name string
}

// CreateRequest creates one instance.
type CreateRequest struct {
	Name        string
	Description string
	Zone        string
	Image       string
	Flavor      string
	SSHKeys     []string
	Script      string // optional user script ID
}

// Instance is one VPS as the vendor reports it.
type Instance struct {
	ID, Name string
	// Description is the vendor's memo field. sfcd writes its creation tag
	// there so a new leader can find an instance it never saw created.
	Description string
	Status      Status
	Zone        string
	Flavor      string
	PublicIPv4  string // "" until assigned
	// IncludedGB is the vendor's free traffic allowance per TrafficPeriod
	// ("MONTH" or "DAY"); 0 when none is reported. A daily allowance adds
	// up over the month to at most IncludedMaxGB (0 = no ceiling).
	IncludedGB    int64
	TrafficPeriod string
	IncludedMaxGB int64
	Started       time.Time // zero until the service started
	// Image is the installed OS image's name when the vendor reports it
	// with the instance (Owned vendors; checked before attaching).
	Image string
	// SubscriptionID is the vendor's billing period behind an Owned
	// instance ("" for Managed vendors).
	SubscriptionID string
}

// Traffic is one month of an instance's traffic.
type Traffic struct {
	Year, Month int
	DailyMB     map[int]int64 // day of month → total MB that day (vendor unit)
	TotalMB     int64
	// BilledUnits is the vendor's billing quantity for the month (total
	// divided by its billing unit, rounded down).
	BilledUnits float64
	First, Last string // YYYY-MM-DD days with records
}

// Bill is the account's charge so far this month.
type Bill struct {
	From, To string // YYYY-MM-DD
	KRW      int64
}

// Catalog is what a vendor sells: zones, OS images and instance types. The
// "new VPS node" form and the cost estimate are built only from it, so a
// vendor adapter reports every field it knows instead of pre-filtering.
type Catalog interface {
	Zones(ctx context.Context) ([]Zone, error)
	// Images lists the images usable in zone ("" = every zone).
	Images(ctx context.Context, zone string) ([]Image, error)
	Flavors(ctx context.Context, q FlavorQuery) ([]Flavor, error)
	// Flavor reads one instance type; KindNotFound when it is not sold.
	Flavor(ctx context.Context, id string) (Flavor, error)
}

// Ownership says who owns a vendor's instances, and so what the cluster may
// do with them (Jay 2026-11-28 14:02–14:04 KST). The two kinds have
// different purposes and are never listed, stored or shown together.
type Ownership string

const (
	// Managed: the cluster creates, powers and deletes the instances, and
	// stops them before the cost cap (iwinv). Interface Managed.
	Managed Ownership = "managed"
	// Owned: the operator buys and keeps the instances at the vendor; the
	// cluster only attaches existing ones, powers them and reads their
	// usage. It never buys, rebuilds or deletes them (Hostinger).
	// Interface Owned.
	Owned Ownership = "owned"
)

// Base is what every vendor account offers: the instances it already has,
// their power and their traffic. Every call is one vendor request (lists
// may page). Mutations that fail with KindTransport have an unknown effect:
// the caller reads Instance (or Instances) to settle before retrying.
type Base interface {
	Kind() string
	Check(ctx context.Context) (Account, error)
	Instances(ctx context.Context) ([]Instance, error)
	Instance(ctx context.Context, id string) (Instance, error)
	Shutdown(ctx context.Context, id string) error
	Start(ctx context.Context, id string) error
	MonthTraffic(ctx context.Context, id string, year, month int) (Traffic, error)
}

// ManagedProvider is one account of a Managed vendor: the cluster also
// buys from its catalogue, deletes instances and reads the live bill.
type ManagedProvider interface {
	Base
	Catalog
	SSHKeys(ctx context.Context) ([]SSHKey, error)
	Scripts(ctx context.Context) ([]Script, error)

	Create(ctx context.Context, r CreateRequest) (Instance, error)
	Delete(ctx context.Context, id string) error

	LiveBill(ctx context.Context) (Bill, error)
}

// OwnedProvider is one account of an Owned vendor. It has no Create or
// Delete, and an adapter sends no request that buys, renews, rebuilds,
// restores or deletes anything: the operator does that at the vendor.
type OwnedProvider interface {
	Base
	// AttachSSHKey adds an OpenSSH public key to the instance's root
	// login without touching its disk, for the SSH install path.
	AttachSSHKey(ctx context.Context, id, publicKey string) error
	// Subscription reads the billing period behind the instance.
	Subscription(ctx context.Context, id string) (Subscription, error)
}

// Subscription is the prepaid period an owned instance runs on. Amounts
// are in the currency's minor unit (cents for USD), as the vendor bills.
type Subscription struct {
	ID          string
	Status      string // vendor status in lower case, for example "active", "not_renewing"
	AutoRenew   bool
	Currency    string // ISO 4217, for example "USD"
	RenewalCost int64  // minor units
	ExpiresAt   time.Time
	NextBilling time.Time // zero unless AutoRenew
}

// Credential is a vendor API key pair, plus the account's SSH key (an
// Ed25519 seed in hex, made by the voter that sealed it) for installing
// sfcd on servers that cannot reach an ingress. It is never printed or
// encoded.
type Credential struct {
	AccessKey, SecretKey string
	SSHSeed              string
}

func (Credential) String() string   { return "[redacted vps credential]" }
func (Credential) GoString() string { return "[redacted vps credential]" }
func (Credential) MarshalJSON() ([]byte, error) {
	return nil, errors.New("vps: credential is not encodable")
}
func (c Credential) Valid() bool {
	if c.SSHSeed != "" {
		if seed, err := hex.DecodeString(c.SSHSeed); err != nil || len(seed) != ed25519.SeedSize || hex.EncodeToString(seed) != c.SSHSeed {
			return false
		}
	}
	// SecretKey is empty for vendors that use one bearer token
	// (Vendor.TokenOnly); the adapter of a signing vendor checks it.
	return c.AccessKey != "" && len(c.AccessKey) <= 256 && len(c.SecretKey) <= 256
}

// SSHSigner is the account SSH key's private half; ok is false without one.
func (c Credential) SSHSigner() (ed25519.PrivateKey, bool) {
	seed, err := hex.DecodeString(c.SSHSeed)
	if c.SSHSeed == "" || err != nil || len(seed) != ed25519.SeedSize {
		return nil, false
	}
	return ed25519.NewKeyFromSeed(seed), true
}
func (Credential) Format(s fmt.State, _ rune) { _, _ = s.Write([]byte("[redacted vps credential]")) }

// Env is what an adapter needs from sfcd besides the credential.
type Env struct {
	BaseURL   string            // "" = the vendor's production address
	Transport http.RoundTripper // nil = http.DefaultTransport
	Now       func() time.Time  // nil = time.Now
}

// Vendor describes one adapter. Exactly one of New and NewOwned is set,
// matching Ownership.
type Vendor struct {
	ID, Name  string
	Ownership Ownership
	New       func(Credential, Env) ManagedProvider
	NewOwned  func(Credential, Env) OwnedProvider
	// TokenOnly: the credential is one API token in AccessKey and
	// SecretKey stays empty.
	TokenOnly bool
	// TrafficCounting is what the vendor's traffic figures count:
	// CountTX (outgoing only), CountRXTX (both ways) or "" (not known).
	// Whether the allowance is daily or monthly comes with each instance.
	TrafficCounting string
	// OverageTiers is the vendor's published price of traffic above the
	// allowance, VAT excluded (shown so, Jay 2026-11-27). Empty: the account's
	// user-entered OverageKRWPerGB is used.
	OverageTiers []OverageTier
}

// Traffic counting rules of a vendor.
const (
	CountTX   = "tx"
	CountRXTX = "rx+tx"
)

// Accepts reports whether c has the parts this vendor's adapter needs.
func (v Vendor) Accepts(c Credential) bool {
	if !c.Valid() {
		return false
	}
	if v.TokenOnly {
		return c.SecretKey == ""
	}
	return c.SecretKey != ""
}

// Vendors lists the adapters sfcd ships, of either ownership.
func Vendors() []Vendor { return []Vendor{HostingerVendor(), IwinvVendor()} }

// Lookup returns the vendor with id, of either ownership. Code that makes
// a provider uses LookupManaged or LookupOwned so the two never mix.
func Lookup(id string) (Vendor, bool) {
	for _, v := range Vendors() {
		if v.ID == id {
			return v, true
		}
	}
	return Vendor{}, false
}

// LookupManaged returns the Managed vendor with id.
func LookupManaged(id string) (Vendor, bool) {
	v, ok := Lookup(id)
	if !ok || v.Ownership != Managed || v.New == nil {
		return Vendor{}, false
	}
	return v, true
}

// LookupOwned returns the Owned vendor with id.
func LookupOwned(id string) (Vendor, bool) {
	v, ok := Lookup(id)
	if !ok || v.Ownership != Owned || v.NewOwned == nil {
		return Vendor{}, false
	}
	return v, true
}
