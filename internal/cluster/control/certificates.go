// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"math"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/certstore"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/ingress"
)

const CertificatesKey = "control/certificates"

// CertificateSelection is the payload of delete-certificate and
// disable-certificate.
type CertificateSelection struct{ ID certstore.ID }

// CertificateQuery reads the store list in ID order, or one certificate with
// its public chain when ID is set. After is "<revision>:<last ID>".
type CertificateQuery struct {
	ID    string `json:",omitempty"`
	After string `json:",omitempty"`
}

func (q CertificateQuery) Valid() bool {
	if q.ID != "" {
		_, ok := certstore.ParseID(q.ID)
		return ok && q.After == ""
	}
	return len(q.After) <= 128
}

const certificatePageSize = 32

type CertificatePage struct {
	Next         string `json:",omitempty"`
	Revision     uint64
	Certificates []certstore.PublicEntry `json:",omitempty"`
	// Chain is the public chain PEM of the one certificate an ID query read.
	Chain []byte `json:",omitempty"`
	// Domains is the whole cluster domain list, on the first page only.
	Domains []certstore.Domain `json:",omitempty"`
	// DeletedOwners names the Domains owners whose tenant no longer exists
	// or is deleted: those domains count as cluster-level (DomainTenant)
	// until an administrator assigns them again. First page only.
	DeletedOwners []string `json:",omitempty"`
	// ACMEResponder is the HTTP-01 responder setting, on the first page only.
	ACMEResponder *certstore.ACMEResponder `json:",omitempty"`
}
type CertificatePut struct{ Certificate certstore.Certificate }

// DomainChange is the payload of add-domain, assign-domain and
// remove-domain. Name is the normalized A-label (certstore.NormalizeDomain).
// Tenant is the owner tenant on add-domain and assign-domain; empty is a
// cluster-level domain. remove-domain carries no Tenant.
type DomainChange struct {
	Name   string
	Tenant string `json:",omitempty"`
}

// DomainTenant is the tenant that owns d now: its Tenant while that tenant
// exists and is not deleted, else empty (cluster-level). A retired tenant's
// domains go back to cluster level without a write.
func DomainTenant(users access.Catalog, d certstore.Domain) string {
	if d.Tenant == "" {
		return ""
	}
	if t, ok := users.Tenant(d.Tenant); !ok || t.Phase == access.TenantDeleted {
		return ""
	}
	return d.Tenant
}

// domainOwnerUsable says whether a domain may be given to tenant now: an
// existing, enabled, active tenant, or cluster level.
func domainOwnerUsable(users access.Catalog, tenant string) bool {
	if tenant == "" {
		return true
	}
	t, ok := users.Tenant(tenant)
	return ok && t.Enabled && t.Phase == access.TenantActive
}

// ACMEResponderChange is the payload of set-acme-responder: a canonical
// IP:port (certstore.NormalizeResponder), or empty to clear it.
type ACMEResponderChange struct{ Address string }

func (p Policy) Certificates(s state.State) (certstore.Catalog, error) {
	c := certstore.New(p.Cluster)

	raw, revision, err := readCheckpoint(s, CertificatesKey, p.Cluster, p.TrustRoot)
	if err != nil {
		return c, err
	}
	if raw == nil {
		return c, nil
	}
	if canonical(raw, &c) != nil || c.Cluster != p.Cluster || c.Revision != revision || c.Validate() != nil {
		return c, ErrCatalog
	}
	return c, nil
}
func (p Policy) CertificateAllowed(s state.State, session access.Session, at int64, action string) error {
	p, err := p.Current(s)
	if err != nil {
		return err
	}
	users, err := p.Catalog(s)
	if err != nil {
		return err
	}
	if users.OperationAllowed(session, action) != nil || users.AuthorizeSession(session, p.Cluster, p.Issuer(session.Issuer), at, "", access.ManageCluster, "") != nil {
		return access.ErrDenied
	}
	return nil
}
func (p Policy) CertificatePage(s state.State, session access.Session, at int64, q CertificateQuery) (CertificatePage, error) {
	if !q.Valid() || p.CertificateAllowed(s, session, at, "certificates") != nil {
		return CertificatePage{}, access.ErrDenied
	}
	c, err := p.Certificates(s)
	if err != nil {
		return CertificatePage{}, err
	}
	out := CertificatePage{Revision: c.Revision}
	if q.ID != "" {
		id, _ := certstore.ParseID(q.ID)
		// A missing ID is an empty page, not a refusal.
		e, ok := c.Entry(id)
		if !ok {
			return out, nil
		}
		for _, row := range c.Public(at) {
			if row.Metadata.ID == id {
				out.Certificates = []certstore.PublicEntry{row}
			}
		}
		out.Chain = e.Certificate.Chain
		return out, nil
	}
	after := ""
	if q.After != "" {
		revision, tail, ok := strings.Cut(q.After, ":")
		n, e := strconv.ParseUint(revision, 10, 64)
		if !ok || e != nil || n != c.Revision || strconv.FormatUint(n, 10) != revision {
			return out, access.ErrConflict
		}
		if _, ok := certstore.ParseID(tail); !ok {
			return out, access.ErrInvalid
		}
		after = tail
	} else {
		out.Domains, out.ACMEResponder = c.Domains, c.ACMEResponder
		users, err := p.Catalog(s)
		if err != nil {
			return CertificatePage{}, err
		}
		for _, d := range c.Domains {
			if d.Tenant != "" && DomainTenant(users, d) == "" && !slices.Contains(out.DeletedOwners, d.Tenant) {
				out.DeletedOwners = append(out.DeletedOwners, d.Tenant)
			}
		}
		slices.Sort(out.DeletedOwners)
	}
	for _, row := range c.Public(at) {
		if row.Metadata.ID.String() <= after {
			continue
		}
		if len(out.Certificates) == certificatePageSize {
			out.Next = strconv.FormatUint(c.Revision, 10) + ":" + out.Certificates[len(out.Certificates)-1].Metadata.ID.String()
			break
		}
		out.Certificates = append(out.Certificates, row)
	}
	return out, nil
}
func (p Policy) authorizeCertificate(c access.Catalog, op UserOperation) error {
	if c.OperationAllowed(op.Session, op.Change.Action) != nil {
		return access.ErrDenied
	}
	return c.AuthorizeSession(op.Session, p.Cluster, p.Issuer(op.Session.Issuer), op.At, "", access.ManageCluster, "")
}
func (p Policy) reduceCertificates(s state.State, cmd state.Command) (map[string][]byte, state.Code) {
	if cmd.Kind == state.ModuleReport {
		return p.reduceCertificateExpiry(s, cmd)
	}
	if cmd.Key != CertificatesKey || cmd.Kind != state.Module {
		return nil, state.Forbidden
	}
	p, err := p.Current(s)
	if err != nil {
		return nil, state.Invalid
	}
	users, err := p.Catalog(s)
	if err != nil {
		return nil, state.Invalid
	}
	op, err := p.Operation(users, cmd, false)
	if err != nil || p.authorizeCertificate(users, op) != nil {
		return nil, state.Forbidden
	}
	c, err := p.Certificates(s)
	if err != nil {
		return nil, state.Invalid
	}
	switch op.Change.Action {
	case "put-certificate":
		var q CertificatePut
		if canonical(op.Change.Payload, &q) != nil || op.Change.Expected != 0 || q.Certificate.Cluster != p.Cluster || q.Certificate.Metadata.UploadedBy != op.Session.User || q.Certificate.Request != op.RequestID {
			return nil, state.Invalid
		}
		members, err := p.Members(s)
		if err != nil || !members.WorkKey(q.Certificate.Sealer) {
			return nil, state.Forbidden
		}
		c, err = c.Put(q.Certificate, op.At)
		if err != nil {
			return nil, state.ConditionFailed
		}
	case "delete-certificate", "disable-certificate":
		var q CertificateSelection
		if canonical(op.Change.Payload, &q) != nil || op.Change.Expected != 0 || q.ID == (certstore.ID{}) {
			return nil, state.Invalid
		}
		if op.Change.Action == "delete-certificate" {
			c, err = c.Delete(q.ID, op.At)
		} else {
			c, err = c.Disable(q.ID, op.Session.User, op.At)
		}
		if err != nil {
			return nil, state.ConditionFailed
		}
	case "add-domain", "assign-domain", "remove-domain":
		var q DomainChange
		if canonical(op.Change.Payload, &q) != nil {
			return nil, state.Invalid
		}
		if n, ok := certstore.NormalizeDomain(q.Name); !ok || n != q.Name || op.Change.Action == "remove-domain" && q.Tenant != "" {
			return nil, state.Invalid
		}
		if !domainOwnerUsable(users, q.Tenant) {
			return nil, state.ConditionFailed
		}
		if op.Change.Action != "remove-domain" {
			if taken, err := p.domainInUseElsewhere(s, c, q.Name, q.Tenant); err != nil {
				return nil, state.Invalid
			} else if taken {
				return nil, state.ConditionFailed
			}
		}
		switch op.Change.Action {
		case "add-domain":
			c, err = c.AddOwnedDomain(q.Name, q.Tenant, op.Session.User, op.Change.Expected, op.At)
		case "assign-domain":
			c, err = c.AssignDomain(q.Name, q.Tenant, op.Change.Expected)
		default:
			c, err = c.RemoveDomain(q.Name, op.Change.Expected)
		}
		if err != nil {
			return nil, state.ConditionFailed
		}
	case "approve-ingress-host", "deny-ingress-host", "revoke-ingress-host":
		var q HostDecision
		if canonical(op.Change.Payload, &q) != nil || !validID(q.Tenant) {
			return nil, state.Invalid
		}
		if n, ok := certstore.NormalizeRouteHost(q.Host); !ok || n != q.Host {
			return nil, state.Invalid
		}
		if op.Change.Action == "revoke-ingress-host" {
			c, err = c.RevokeHost(q.Tenant, q.Host, op.Change.Expected)
		} else {
			approve := op.Change.Action == "approve-ingress-host"
			if !p.decideHostAllowed(s, c, users, q, approve) {
				return nil, state.ConditionFailed
			}
			decision := certstore.GrantDenied
			if approve {
				decision = certstore.GrantApproved
			}
			c, err = c.DecideHost(q.Tenant, q.Host, decision, op.Session.User, op.Change.Expected, op.At)
		}
		if err != nil {
			return nil, state.ConditionFailed
		}
	case "set-acme-responder":
		var q ACMEResponderChange
		if canonical(op.Change.Payload, &q) != nil {
			return nil, state.Invalid
		}
		if n, ok := certstore.NormalizeResponder(q.Address); q.Address != "" && (!ok || n != q.Address) {
			return nil, state.Invalid
		}
		if c, err = c.SetACMEResponder(q.Address, op.Session.User, op.Change.Expected, op.At); err != nil {
			return nil, state.ConditionFailed
		}
	default:
		return nil, state.Invalid
	}
	raw, err := json.Marshal(c)
	if err != nil {
		return nil, state.Invalid
	}
	return writeCheckpoint(s, CertificatesKey, p.Cluster, p.TrustRoot, c.Revision, raw)
}

// certificateSpecUses reports whether an ingress spec serves TLS for host: a
// TLS listener, or a shared listener (whose node gateway may serve TLS), and
// a route covering host. Certificates are chosen by host only.
func certificateSpecUses(spec ingress.Spec, host string) bool {
	tls := slices.ContainsFunc(spec.Listeners, func(l ingress.Listener) bool { return l.TLS || l.Shared != "" })
	return tls && slices.ContainsFunc(spec.Routes, func(r ingress.Route) bool { return certstore.MatchHost(r.Host, host) > 0 })
}

// CertificateMaterialRead asks a holder for the key of one stored
// certificate (ID, pinned by its digest) for a host the consumer serves.
// The consumer serves it either through an ingress goal (Source) or as the
// owner of a registry run whose authority is that host (Registry).
type CertificateMaterialRead struct {
	Schema                         uint8
	Cluster, Consumer, Certificate [32]byte
	ID                             certstore.ID
	Host                           string
	Source                         deployment.ObjectRef
	Registry                       *RegistryCertificateSource `json:",omitempty"`
	At                             int64
}

// RegistryCertificateSource names one active registry run.
type RegistryCertificateSource struct {
	Tenant, ID string
	Generation uint64
}

// RegistryHost is the host a registry authority is served under (an IP in
// canonical form).
func RegistryHost(authority string) string {
	u, err := url.Parse("https://" + authority)
	if err != nil {
		return ""
	}
	host := strings.ToLower(u.Hostname())
	if a, err := netip.ParseAddr(host); err == nil {
		return a.Unmap().String()
	}
	return host
}

func (p Policy) CertificateMaterial(s state.State, caller [32]byte, q CertificateMaterialRead, at int64) (certstore.Certificate, error) {
	if q.Schema != 2 || q.Cluster != p.Cluster || !p.ownsResource(s, caller, q.Consumer) || q.At > at || at-q.At > 60 {
		return certstore.Certificate{}, access.ErrDenied
	}
	members, err := p.Members(s)
	if err != nil || !members.WorkKey(caller) {
		return certstore.Certificate{}, access.ErrDenied
	}
	c, err := p.Certificates(s)
	if err != nil {
		return certstore.Certificate{}, err
	}
	entry, ok := c.Entry(q.ID)
	selected := entry.Certificate
	if !ok || selected.Digest() != q.Certificate || !c.Serves(q.Host, q.ID, at) {
		return certstore.Certificate{}, access.ErrDenied
	}
	if q.Registry != nil {
		book, err := p.Registries(s)
		if err != nil {
			return certstore.Certificate{}, err
		}
		entry, ok := book.Entry(q.Registry.Tenant, q.Registry.ID)
		if q.Source != (deployment.ObjectRef{}) || !ok || entry.Deleted || entry.Active == nil || entry.Active.Generation != q.Registry.Generation || entry.Active.Owner != q.Consumer || RegistryHost(entry.Active.Spec.Authority) != q.Host {
			return certstore.Certificate{}, access.ErrDenied
		}
		return selected, nil
	}
	projection, err := p.ProjectResources(s)
	if err != nil {
		return certstore.Certificate{}, err
	}
	goal, ok := projection.Goals[q.Source.Key]
	object := s.Object(q.Source.Key)
	if !ok || !object.Present || object.Revision != q.Source.Revision || object.Generation != q.Source.Generation || goal.Goal.Owner != q.Consumer || !p.ownsResource(s, caller, goal.Goal.Owner) || goal.Ingress == nil || !certificateSpecUses(*goal.Ingress, q.Host) {
		return certstore.Certificate{}, access.ErrDenied
	}
	return selected, nil
}

type CertificateExpiryReport struct {
	Schema              uint8
	Cluster, Reporter   [32]byte
	RootRevision, Epoch uint64
	At                  uint64
	Signature           []byte
}

func CertificateExpiryBytes(r CertificateExpiryReport) []byte {
	r.Signature = nil
	raw, _ := json.Marshal(r)
	return append([]byte("sfc-certificate-expiry-1\x00"), raw...)
}
func (r CertificateExpiryReport) Command() (state.Command, error) {
	raw, err := json.Marshal(r)
	if err != nil {
		return state.Command{}, err
	}
	cmd := state.Command{Kind: state.ModuleReport, Actor: "node/" + hex.EncodeToString(r.Reporter[:]), Epoch: r.Epoch, Key: CertificatesKey, Expected: r.RootRevision, Value: string(raw)}
	cmd.RequestID = state.ReportRequestID(cmd)
	_, err = state.EncodeCommand(cmd)
	return cmd, err
}
func (p Policy) certificateExpiry(s state.State, cmd state.Command) (CertificateExpiryReport, error) {
	var r CertificateExpiryReport
	if cmd.Key != CertificatesKey || cmd.Kind != state.ModuleReport || canonical([]byte(cmd.Value), &r) != nil || r.Schema != 1 || r.Cluster != p.Cluster || r.Epoch != s.ModuleEpoch() || r.RootRevision != s.Object(CertificatesKey).Revision || r.At == 0 || r.At > math.MaxInt64 || !ed25519.Verify(r.Reporter[:], CertificateExpiryBytes(r), r.Signature) {
		return r, ErrCatalog
	}
	want, err := r.Command()
	current, pe := p.Current(s)
	if err != nil || want != cmd || pe != nil || !current.Issuer(r.Reporter).Enabled {
		return r, ErrCatalog
	}
	return r, nil
}
func (p Policy) ResolveCertificateExpiry(s state.State, caller [32]byte, raw []byte) (state.Command, error) {
	var r CertificateExpiryReport
	if canonical(raw, &r) != nil || r.Reporter != caller {
		return state.Command{}, ErrCatalog
	}
	cmd, err := r.Command()
	if err == nil {
		_, err = p.certificateExpiry(s, cmd)
	}
	return cmd, err
}
func (p Policy) reduceCertificateExpiry(s state.State, cmd state.Command) (map[string][]byte, state.Code) {
	r, err := p.certificateExpiry(s, cmd)
	if err != nil {
		return nil, state.Forbidden
	}
	c, err := p.Certificates(s)
	if err != nil {
		return nil, state.Invalid
	}
	c, expired, err := c.Expire(int64(r.At))
	if err != nil || len(expired) == 0 {
		return nil, state.ConditionFailed
	}
	raw, err := json.Marshal(c)
	if err != nil {
		return nil, state.Invalid
	}
	return writeCheckpoint(s, CertificatesKey, p.Cluster, p.TrustRoot, c.Revision, raw)
}

// certificatesBook is the CertificatesKey book (books.go).
var certificatesBook = Book{Key: CertificatesKey, Reduce: Policy.reduceCertificates}
