// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jay94ks/seafield/internal/certstore"
	"github.com/jay94ks/seafield/internal/web/acme"
	"github.com/jay94ks/seafield/internal/web/dns"
	"github.com/jay94ks/seafield/internal/web/provlog"
	"github.com/jay94ks/seafield/internal/web/store"
)

// Certificate automation (UI-57~59, devel/design/web-acme-plan.md). ACME
// and DNS-01 run here; the issued chain and the new private key go to the
// cluster certificate store as a put-certificate signed by the
// session of the user who started the order (acmestore.go), and the key is
// then dropped. The web app keeps only public data.

func acmeSecretName(id string) string { return "acme-" + id }

var certNameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

// acmeRunner keeps orders running in the background (an order outlives the
// request that started it).
type acmeRunner struct {
	mu      sync.Mutex
	running map[string]bool // cert name → an order is running
	wg      sync.WaitGroup
	// storeRetry overrides acmeStoreRetry (tests).
	storeRetry []time.Duration
}

// WaitOrders waits for background certificate orders (tests, shutdown).
func (s *Server) WaitOrders() { s.acme.wg.Wait() }

func pemChain(s string) [][]byte {
	var out [][]byte
	rest := []byte(s)
	for {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			return out
		}
		if b.Type == "CERTIFICATE" {
			out = append(out, b.Bytes)
		}
	}
}

func (s *Server) acmeOpen(acctID string) (*store.ACMEAccount, acme.CA, crypto.Signer, error) {
	a, err := s.opt.Store.GetACMEAccount(acctID)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("account %s: %w", acctID, err)
	}
	ca, err := s.opt.ACME.Get(a.CA)
	if err != nil {
		return nil, nil, nil, err
	}
	raw, err := s.opt.Seal.Get(acmeSecretName(a.ID))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("account key: %w", err)
	}
	var sec struct {
		Key string `json:"key"`
	}
	if err := json.Unmarshal(raw, &sec); err != nil {
		return nil, nil, nil, err
	}
	k, err := acme.ParseKeyPEM([]byte(sec.Key))
	if err != nil {
		return nil, nil, nil, err
	}
	return a, ca, k, nil
}

// dnsFor finds the connected domain that holds fqdn and returns it with its
// provider and fqdn's name relative to it.
func (s *Server) dnsFor(fqdn string) (*store.DNSDomain, dns.Provider, string, error) {
	ds, err := s.opt.Store.ListDNSDomains()
	if err != nil {
		return nil, nil, "", err
	}
	var best *store.DNSDomain
	for _, d := range ds {
		if (fqdn == d.Domain || strings.HasSuffix(fqdn, "."+d.Domain)) && (best == nil || len(d.Domain) > len(best.Domain)) {
			best = d
		}
	}
	if best == nil {
		return nil, nil, "", fmt.Errorf("%s is not under a connected external domain", fqdn)
	}
	p, err := s.opt.Store.GetDNSProvider(best.Provider)
	if err != nil {
		return nil, nil, "", err
	}
	tok, err := s.opt.Seal.Get(dnsSecretName(p.ID))
	if err != nil {
		return nil, nil, "", fmt.Errorf("DNS token: %w", err)
	}
	prov, err := s.opt.DNS.Open(p.Vendor, p.ID, string(tok))
	if err != nil {
		return nil, nil, "", err
	}
	rel := "@"
	if fqdn != best.Domain {
		rel = strings.TrimSuffix(fqdn, "."+best.Domain)
	}
	return best, prov, rel, nil
}

// TXTLookup reads TXT values at fqdn through the DNS provider of its
// domain. The fake CA validates with it; the propagation check uses it too.
func (s *Server) TXTLookup(ctx context.Context, fqdn string) ([]string, error) {
	d, prov, rel, err := s.dnsFor(fqdn)
	if err != nil {
		return nil, err
	}
	z, err := prov.GetZone(ctx, d.Domain)
	if err != nil {
		return nil, err
	}
	var out []string
	if set := z.Find(dns.Key{Name: rel, Type: "TXT"}); set != nil {
		for _, r := range set.Records {
			out = append(out, r.Content)
		}
	}
	return out, nil
}

// caaAllows checks the CAA records at the apex of fqdn's domain.
func caaAllows(z dns.Zone, issuer string) bool {
	set := z.Find(dns.Key{Name: "@", Type: "CAA"})
	if set == nil {
		return true
	}
	any := false
	for _, r := range set.Records {
		f := strings.Fields(r.Content)
		if len(f) >= 3 && (f[1] == "issue" || f[1] == "issuewild") {
			any = true
			if strings.Trim(f[2], `"`) == issuer {
				return true
			}
		}
	}
	return !any
}

type txtSet struct {
	domain *store.DNSDomain
	prov   dns.Provider
	rel    string
	fqdn   string
	values []string
}

// runOrder issues (or renews) cert. It runs to the end on its own context;
// every step is stored as it finishes.
func (s *Server) runOrder(ctx context.Context, c *store.ACMECert, o *store.ACMEOrder, ws *webSession) {
	step := func(name, state, detail string) {
		lvl := provlog.Info
		if state == "failed" {
			lvl = provlog.Error
		}
		s.opt.ProviderLog.Add(provlog.Entry{Provider: "acme:order", Op: "step:" + name, Level: lvl, Msg: state, Error: provlog.Scrub(detail),
			Attrs: map[string]string{"cert": c.Name, "order": o.ID, "names": strings.Join(c.Names, ",")}})
		o.Steps = append(o.Steps, store.ACMEStep{Name: name, State: state, At: s.now(), Detail: detail})
		o.UpdatedAt = s.now()
		_ = s.opt.Store.PutACMEOrder(o)
	}
	var sets []*txtSet
	fail := func(name, code string, err error) {
		step(name, "failed", err.Error())
		o.State, o.ErrorCode = "failed", code
		o.OrphanTXT = s.acmeCleanup(ctx, sets, c.Name)
		if len(o.OrphanTXT) > 0 {
			step("cleanup", "failed", "TXT records left: "+strings.Join(o.OrphanTXT, ", "))
		}
		o.UpdatedAt = s.now()
		_ = s.opt.Store.PutACMEOrder(o)
		s.acmeAfterFailure(c, o)
	}

	// HTTP-01 names must lie under a registered cluster domain: ingress
	// forwards the challenge path only for those hosts. Checked before
	// the CA is asked, so a miss does not spend its rate limit.
	var domains []string
	var domErr error
	if ws == nil {
		// put-certificate is signed by a sfcd session. Automatic renewal
		// signs as the web's automation account; check it can
		// log in before asking the CA for a certificate whose key would be
		// lost. The store step logs in again (sfcd closes idle
		// connections long before propagation ends).
		as, err := s.automationLogin(ctx, "acme-renew")
		if err != nil {
			fail("preflight", "renew-account", errors.New("automatic renewal signs as the web automation account, which could not log in: "+automationErrorCode(err)))
			return
		}
		domains, domErr = s.orderDomains(ctx, as)
		as.conn.Close()
	} else {
		domains, domErr = s.orderDomains(ctx, ws)
	}
	acct, ca, key, err := s.acmeOpen(c.Account)
	if err != nil {
		fail("preflight", "account", err)
		return
	}
	info := ca.Info()
	kt := ""
	for _, t := range c.KeyTypes {
		if slices.Contains(info.KeyTypes, acme.KeyType(t)) {
			kt = t
			break
		}
	}
	if kt == "" {
		fail("preflight", "key-type", fmt.Errorf("%s supports none of %v", info.Name, c.KeyTypes))
		return
	}
	if kt != c.KeyTypes[0] {
		s.notify(&store.Notification{User: c.OwnerID, Kind: NotifyCertificate, Severity: "warning", Text: notice("cert-key-type", map[string]string{"name": c.Name, "from": string(c.KeyTypes[0]), "to": string(kt)}, "cert-key-type.body"),
			Link: "/certificates/" + c.Name})
	}
	o.KeyType = kt
	// each name gets DNS-01 through its connected domain's provider (whose
	// CAA must allow the CA), or HTTP-01 through the web responder when it
	// is not under a connected domain and is not a wildcard
	byTXT := map[string]*txtSet{}
	method := map[string]string{}
	for _, n := range c.Names {
		m, err := s.acmeMethod(n)
		if err != nil {
			fail("preflight", "no-domain", err)
			return
		}
		method[n] = m
		if m == acme.HTTP01 && domErr == nil && !slices.ContainsFunc(domains, func(d string) bool { return certstore.DomainCovers(d, n) }) {
			fail("preflight", "not-registered", fmt.Errorf("%s is not under a registered cluster domain (sfcli domain add); ingress forwards HTTP-01 only for those hosts", n))
			return
		}
		if m == acme.HTTP01 && domErr != nil {
			s.log.Warn("acme: cluster domain list not readable; HTTP-01 name not checked", "cert", c.Name, "name", n, "err", domErr)
		}
		fq := acme.ChallengeName(n)
		if m != acme.DNS01 || byTXT[fq] != nil {
			continue
		}
		d, prov, rel, err := s.dnsFor(fq)
		if err != nil {
			fail("preflight", "no-domain", err)
			return
		}
		z, err := prov.GetZone(ctx, d.Domain)
		if err != nil {
			fail("preflight", "dns-"+string(dns.KindOf(err)), err)
			return
		}
		if !caaAllows(z, info.CAA) {
			fail("preflight", "caa-blocked", fmt.Errorf("CAA of %s does not allow %s; add a CAA issue record for it", d.Domain, info.CAA))
			return
		}
		byTXT[fq] = &txtSet{domain: d, prov: prov, rel: rel, fqdn: fq}
	}
	step("preflight", "done", "")

	ord, err := ca.NewOrder(ctx, key, acct.URL, c.Names, func(n string) string { return method[n] })
	if err != nil {
		fail("order", "ca-order", err)
		return
	}
	step("order", "done", ord.URL)

	var httpTokens []string
	defer func() {
		for _, tok := range httpTokens {
			s.acmeHTTP.remove(tok)
		}
	}()
	for _, ch := range ord.Challenges {
		if ch.Type == acme.HTTP01 {
			s.acmeHTTP.add(ch.Name, ch.Token, ch.KeyAuth)
			httpTokens = append(httpTokens, ch.Token)
			continue
		}
		t := byTXT[ch.TXTName]
		if t == nil {
			fail("txt", "internal", fmt.Errorf("challenge for unexpected name %s", ch.TXTName))
			return
		}
		if !slices.Contains(t.values, ch.TXTValue) {
			t.values = append(t.values, ch.TXTValue)
		}
	}
	for _, t := range byTXT {
		sets = append(sets, t)
		recs := make([]dns.Record, len(t.values))
		for i, v := range t.values {
			recs[i] = dns.Record{Content: v}
		}
		up := dns.RRSet{Name: t.rel, Type: "TXT", TTL: max(60, t.prov.Capabilities().MinTTL), Records: recs}
		if _, err := t.prov.Apply(ctx, t.domain.Domain, dns.ChangeSet{Upsert: []dns.RRSet{up}}); err != nil {
			fail("txt", "dns-"+string(dns.KindOf(err)), err)
			return
		}
		_ = s.opt.Store.ApplyDNSManaged(t.domain.Domain, []*store.DNSManaged{{Domain: t.domain.Domain, Name: t.rel, Type: "TXT", App: "acme:" + c.Name,
			By: o.By, Fingerprint: dns.Fingerprint(&up), At: s.now()}}, nil)
	}
	step("txt", "done", fmt.Sprintf("%d TXT record sets, %d HTTP-01 tokens", len(sets), len(httpTokens)))

	// propagation: wait until the provider holds every value and every
	// authoritative name server of the domain answers it (the CA asks
	// those, not the provider API)
	deadline := s.now().Add(s.acmePropagation())
	lastLog := time.Time{}
	for {
		missing := ""
		for _, t := range sets {
			vals, err := s.TXTLookup(ctx, t.fqdn)
			if err != nil {
				missing = t.fqdn + " (provider): " + err.Error()
				break
			}
			for _, v := range t.values {
				if !slices.Contains(vals, v) {
					missing = t.fqdn + " (provider)"
				}
			}
			if missing != "" {
				break
			}
			if m := s.acmeAuthoritative(ctx, t); m != "" {
				missing = m
				break
			}
		}
		if missing == "" {
			break
		}
		if s.now().Sub(lastLog) >= 30*time.Second {
			lastLog = s.now()
			s.opt.ProviderLog.Add(provlog.Entry{Provider: "acme:" + info.ID, Conn: acct.URL, Op: "Propagation", Msg: "TXT not visible yet", Attrs: map[string]string{"cert": c.Name, "missing": missing}})
		}
		if !s.now().Before(deadline) || ctx.Err() != nil {
			fail("propagation", "propagation", fmt.Errorf("TXT not visible: %s", missing))
			return
		}
		select {
		case <-ctx.Done():
		case <-time.After(2 * time.Second):
		}
	}
	step("propagation", "done", "")

	if err := ca.Validate(ctx, key, acct.URL, ord); err != nil {
		fail("validate", "ca-validate", err)
		return
	}
	step("validate", "done", "")

	certKey, err := acme.NewKey(acme.KeyType(kt))
	if err != nil {
		fail("finalize", "internal", err)
		return
	}
	csr, err := acme.CSR(certKey, c.Names)
	if err != nil {
		fail("finalize", "internal", err)
		return
	}
	chain, err := ca.Finalize(ctx, key, acct.URL, ord, csr)
	if err != nil {
		fail("finalize", "ca-finalize", err)
		return
	}
	ci, err := acme.Inspect(chain, acme.KeyType(kt))
	if err != nil {
		fail("finalize", "ca-finalize", err)
		return
	}
	o.Fingerprint = ci.Fingerprint
	step("finalize", "done", ci.Fingerprint)

	// the private key goes to the certificate store and nowhere else
	keyPEM, err := acme.KeyPEM(certKey)
	certKey = nil
	if err != nil {
		fail("store", "internal", err)
		return
	}
	defer clear(keyPEM)
	o.StoreOp = acmeStoreOpID(o.ID)
	signer := ws
	if signer == nil {
		as, err := s.automationLogin(ctx, "acme-renew")
		if err != nil {
			fail("store", "renew-account", errors.New("the web automation account could not log in: "+automationErrorCode(err)))
			return
		}
		defer as.conn.Close()
		signer = as
	}
	id, code, err := s.acmeStore(ctx, signer, o.ID, acme.ChainPEM(chain), keyPEM)
	clear(keyPEM)
	if err != nil {
		fail("store", code, err)
		return
	}
	step("store", "done", id)

	o.OrphanTXT = s.acmeCleanup(ctx, sets, c.Name)
	if len(o.OrphanTXT) > 0 {
		step("cleanup", "failed", "TXT records left: "+strings.Join(o.OrphanTXT, ", "))
	} else {
		step("cleanup", "done", "")
	}

	// public state of the definition
	if cur, err := s.opt.Store.GetACMECert(c.Name); err == nil {
		c = cur
	}
	c.Fingerprint, c.KeyType, c.Issuer, c.NotBefore, c.NotAfter = id, kt, ci.Issuer, ci.NotBefore, ci.NotAfter
	c.ChainPEM = string(acme.ChainPEM(chain))
	c.NextRenew = acme.RenewAt(ci.NotBefore, ci.NotAfter)
	c.NextTry, c.Failures, c.Warned, c.LastOrder = time.Time{}, 0, 0, o.ID
	_ = s.opt.Store.PutACMECert(c)
	o.State = "done"
	o.UpdatedAt = s.now()
	_ = s.opt.Store.PutACMEOrder(o)
}

// acmeCleanup removes the challenge TXT sets and returns those it could not
// remove.
func (s *Server) acmeCleanup(ctx context.Context, sets []*txtSet, cert string) []string {
	var left []string
	for _, t := range sets {
		if _, err := t.prov.Apply(ctx, t.domain.Domain, dns.ChangeSet{Delete: []dns.Key{{Name: t.rel, Type: "TXT"}}}); err != nil && dns.KindOf(err) != dns.NotFound {
			left = append(left, t.fqdn)
			continue
		}
		_ = s.opt.Store.ApplyDNSManaged(t.domain.Domain, nil, [][2]string{{t.rel, "TXT"}})
	}
	return left
}

// acmeAfterFailure schedules the next renewal try (1 h, 6 h, then daily) and
// tells the owner.
func (s *Server) acmeAfterFailure(c *store.ACMECert, o *store.ACMEOrder) {
	cur, err := s.opt.Store.GetACMECert(c.Name)
	if err != nil {
		return
	}
	cur.Failures++
	back := []time.Duration{time.Hour, 6 * time.Hour, 24 * time.Hour}[min(cur.Failures, 3)-1]
	cur.NextTry, cur.LastOrder = s.now().Add(back), o.ID
	_ = s.opt.Store.PutACMECert(cur)
	who := o.UserID
	if who == "" {
		who = cur.OwnerID
	}
	s.notify(&store.Notification{User: who, Kind: NotifyCertificate, Severity: "error", Text: notice("cert-issue-failed", map[string]string{"name": c.Name, "code": o.ErrorCode}, bodyIf(o.ErrorCode != "", "op-failed.code")...),
		Link: "/certificates/" + c.Name})
}

func (s *Server) acmePropagation() time.Duration {
	if s.opt.ACMEPropagation > 0 {
		return s.opt.ACMEPropagation
	}
	return 10 * time.Minute
}

// startOrder begins an order unless one is running for the certificate.
func (s *Server) startOrder(c *store.ACMECert, id string, ws *webSession) (*store.ACMEOrder, error) {
	s.acme.mu.Lock()
	if s.acme.running == nil {
		s.acme.running = map[string]bool{}
	}
	if s.acme.running[c.Name] {
		s.acme.mu.Unlock()
		return nil, errOrderRunning
	}
	s.acme.running[c.Name] = true
	s.acme.mu.Unlock()
	o := &store.ACMEOrder{ID: id, Cert: c.Name, At: s.now(), State: "running", Steps: []store.ACMEStep{}, UpdatedAt: s.now(), Auto: ws == nil, By: "자동 갱신"}
	if ws != nil {
		o.By, o.UserID = ws.user.Username, ws.user.ID
	}
	if err := s.opt.Store.PutACMEOrder(o); err != nil {
		s.acmeDone(c.Name)
		return nil, err
	}
	// the caller gets a copy: the running order is changed by its goroutine
	snap := *o
	snap.Steps = slices.Clone(o.Steps)
	s.acme.wg.Add(1)
	go func() {
		defer s.acme.wg.Done()
		defer s.acmeDone(c.Name)
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
		defer cancel()
		s.runOrder(ctx, c, o, ws)
	}()
	return &snap, nil
}

var errOrderRunning = errors.New("an order is already running for this certificate")

func (s *Server) acmeDone(name string) {
	s.acme.mu.Lock()
	delete(s.acme.running, name)
	s.acme.mu.Unlock()
}

// acmeTick renews due certificates and warns about expiring ones. It runs
// from Run (hourly).
func (s *Server) acmeTick() {
	cs, err := s.opt.Store.ListACMECerts()
	if err != nil {
		return
	}
	now := s.now()
	for _, c := range cs {
		if c.NotAfter.IsZero() {
			continue
		}
		left := c.NotAfter.Sub(now)
		for _, d := range []int{3, 7, 14} {
			if left < time.Duration(d)*24*time.Hour && (c.Warned == 0 || c.Warned > d) {
				c.Warned = d
				_ = s.opt.Store.PutACMECert(c)
				s.notify(&store.Notification{User: c.OwnerID, Kind: NotifyCertificate, Severity: "warning", Action: true,
					Text: notice("cert-expiring", map[string]string{"name": c.Name, "days": strconv.Itoa(d)}), Link: "/certificates/" + c.Name})
				break
			}
		}
		if !c.AutoRenew || now.Before(c.NextRenew) {
			continue
		}
		if s.automationRow() != nil {
			// renew as the web automation account (retries follow nextTry)
			if now.Before(c.NextTry) {
				continue
			}
			if _, err := s.startOrder(c, "renew-"+newOpID(), nil); err != nil && !errors.Is(err, errOrderRunning) {
				s.log.Error("acme renew", "cert", c.Name, "err", err)
			}
			continue
		}
		if c.RenewBlocked.Before(c.NextRenew) {
			// No automation account: no order runs, so nothing counts as a
			// failure; the owner is told once per renewal period and issues
			// by hand.
			c.RenewBlocked = now
			_ = s.opt.Store.PutACMECert(c)
			s.notify(&store.Notification{User: c.OwnerID, Kind: NotifyCertificate, Severity: "warning", Action: true,
				Text: notice("cert-manual-renew", map[string]string{"name": c.Name}, "cert-manual-renew.body"), Link: "/certificates/" + c.Name})
		}
	}
}

// ---- handlers (system administrators) ----

func (s *Server) handleACMECAs(w http.ResponseWriter, r *http.Request, ws *webSession) {
	out := []acme.CAInfo{}
	for _, c := range s.opt.ACME.List() {
		out = append(out, c.Info())
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": out})
}

func (s *Server) handleACMEAccounts(w http.ResponseWriter, r *http.Request, ws *webSession) {
	if !s.requireAdmin(w, r, ws) {
		return
	}
	as, err := s.opt.Store.ListACMEAccounts()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	if as == nil {
		as = []*store.ACMEAccount{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": as})
}

// POST /acme/accounts {ca, email?, agreeTos, eab?:{keyId, hmac(base64)}}
func (s *Server) handleACMEAddAccount(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req struct {
		CA       string    `json:"ca"`
		Email    string    `json:"email"`
		AgreeTOS bool      `json:"agreeTos"`
		EAB      *acme.EAB `json:"eab"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	if !s.requireAdmin(w, r, ws) {
		return
	}
	if !req.AgreeTOS {
		writeError(w, http.StatusUnprocessableEntity, "invalid", "the CA terms must be accepted")
		return
	}
	ca, err := s.opt.ACME.Get(req.CA)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, "invalid", err.Error())
		return
	}
	if ca.Info().NeedsEAB && (req.EAB == nil || req.EAB.KeyID == "" || len(req.EAB.HMAC) == 0) {
		writeError(w, http.StatusUnprocessableEntity, "invalid", "this CA needs an external account binding (key ID and HMAC)")
		return
	}
	if !s.opt.Seal.Ready() {
		writeError(w, http.StatusServiceUnavailable, "seal-unavailable", "sealed storage is not available; account keys cannot be kept")
		return
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	ctx, cancel := s.dnsCtx(r)
	url, err := ca.Register(ctx, key, req.Email, req.EAB)
	cancel()
	if err != nil {
		writeError(w, http.StatusBadGateway, "ca-register", err.Error())
		return
	}
	a := &store.ACMEAccount{ID: newProviderID(), CA: req.CA, Email: req.Email, URL: url, EAB: req.EAB != nil, AgreedAt: s.now(), CreatedBy: ws.user.Username, CreatedAt: s.now()}
	kp, _ := acme.KeyPEM(key)
	sec, _ := json.Marshal(map[string]any{"key": string(kp), "eab": req.EAB})
	if err := s.opt.Seal.Put(acmeSecretName(a.ID), sec); err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	if err := s.opt.Store.PutACMEAccount(a); err != nil {
		_ = s.opt.Seal.Delete(acmeSecretName(a.ID))
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	s.audit(ws, "", "acme", "add-account", a.ID, nil, map[string]any{"ca": a.CA, "email": a.Email, "key": "set", "eab": a.EAB})
	writeJSON(w, http.StatusCreated, map[string]any{"account": a})
}

func (s *Server) handleACMEDeleteAccount(w http.ResponseWriter, r *http.Request, ws *webSession) {
	if !s.requireAdmin(w, r, ws) {
		return
	}
	id := r.PathValue("id")
	switch err := s.opt.Store.DeleteACMEAccount(id); {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "missing", "no such account")
		return
	case errors.Is(err, store.ErrConflict):
		writeError(w, http.StatusConflict, "in-use", "certificates use this account")
		return
	case err != nil:
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	_ = s.opt.Seal.Delete(acmeSecretName(id))
	s.audit(ws, "", "acme", "delete-account", id, nil, nil)
	w.WriteHeader(http.StatusNoContent)
}

type certView struct {
	*store.ACMECert
	Running bool `json:"running"`
}

func (s *Server) certView(c *store.ACMECert) certView {
	s.acme.mu.Lock()
	defer s.acme.mu.Unlock()
	return certView{c, s.acme.running[c.Name]}
}

func (s *Server) handleACMECerts(w http.ResponseWriter, r *http.Request, ws *webSession) {
	if !s.requireAdmin(w, r, ws) {
		return
	}
	cs, err := s.opt.Store.ListACMECerts()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	out := []certView{}
	for _, c := range cs {
		out = append(out, s.certView(c))
	}
	// The store is reached through the caller's own sfcd session.
	writeJSON(w, http.StatusOK, map[string]any{"items": out, "certStore": true})
}

func checkCertNames(names []string) error {
	if len(names) == 0 || len(names) > 100 {
		return errors.New("1..100 names")
	}
	seen := map[string]bool{}
	for _, n := range names {
		base := strings.TrimPrefix(n, "*.")
		if seen[n] || base == "" || strings.Contains(base, "*") || strings.Count(base, ".") < 1 {
			return fmt.Errorf("invalid or repeated name %q", n)
		}
		if err := dns.CheckPattern(strings.ReplaceAll(base, ".", "-")); err != nil {
			return fmt.Errorf("invalid name %q", n)
		}
		seen[n] = true
	}
	return nil
}

func checkKeyTypes(kts []string) error {
	if len(kts) == 0 || len(kts) > 5 {
		return errors.New("1..5 key types")
	}
	for _, k := range kts {
		if _, err := acme.NewKeyTypeCheck(acme.KeyType(k)); err != nil {
			return err
		}
	}
	return nil
}

// POST /acme/certs {name, names, account, keyTypes?, autoRenew?}
func (s *Server) handleACMEAddCert(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req struct {
		Name      string   `json:"name"`
		Names     []string `json:"names"`
		Account   string   `json:"account"`
		KeyTypes  []string `json:"keyTypes"`
		AutoRenew *bool    `json:"autoRenew"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	if !s.requireAdmin(w, r, ws) {
		return
	}
	if !certNameRE.MatchString(req.Name) {
		writeError(w, http.StatusUnprocessableEntity, "invalid", "name: lowercase letters, digits and '-', at most 63")
		return
	}
	for i := range req.Names {
		req.Names[i] = strings.ToLower(strings.TrimSuffix(req.Names[i], "."))
	}
	if err := checkCertNames(req.Names); err != nil {
		writeError(w, http.StatusUnprocessableEntity, "invalid", err.Error())
		return
	}
	if len(req.KeyTypes) == 0 {
		for _, k := range acme.DefaultKeyTypes {
			req.KeyTypes = append(req.KeyTypes, string(k))
		}
	}
	if err := checkKeyTypes(req.KeyTypes); err != nil {
		writeError(w, http.StatusUnprocessableEntity, "invalid", err.Error())
		return
	}
	if _, err := s.opt.Store.GetACMEAccount(req.Account); err != nil {
		writeError(w, http.StatusUnprocessableEntity, "invalid", "no such account")
		return
	}
	for _, n := range req.Names {
		if _, err := s.acmeMethod(n); err != nil {
			writeError(w, http.StatusUnprocessableEntity, "no-domain", err.Error())
			return
		}
	}
	auto := true
	if req.AutoRenew != nil {
		auto = *req.AutoRenew
	}
	c := &store.ACMECert{Name: req.Name, Names: req.Names, Account: req.Account, KeyTypes: req.KeyTypes, AutoRenew: auto, OwnerID: ws.user.ID, CreatedBy: ws.user.Username, CreatedAt: s.now()}
	if err := s.opt.Store.CreateACMECert(c); errors.Is(err, store.ErrConflict) {
		writeError(w, http.StatusConflict, "exists", "a certificate with this name exists")
		return
	} else if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	s.audit(ws, "", "acme", "add-certificate", c.Name, nil, c)
	writeJSON(w, http.StatusCreated, map[string]any{"certificate": s.certView(c)})
}

func (s *Server) loadCert(w http.ResponseWriter, r *http.Request) (*store.ACMECert, bool) {
	c, err := s.opt.Store.GetACMECert(r.PathValue("name"))
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "missing", "no such certificate")
		return nil, false
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return nil, false
	}
	return c, true
}

func (s *Server) handleACMECert(w http.ResponseWriter, r *http.Request, ws *webSession) {
	if !s.requireAdmin(w, r, ws) {
		return
	}
	c, ok := s.loadCert(w, r)
	if !ok {
		return
	}
	orders, _ := s.opt.Store.ListACMEOrders(c.Name, 20)
	ctx, cancel := s.callCtx(r)
	methods, reasons := s.certMethods(ctx, ws, c.Names)
	cancel()
	writeJSON(w, http.StatusOK, map[string]any{"certificate": s.certView(c), "orders": orders, "methods": methods, "methodReasons": reasons})
}

// certMethods says how each name would be validated now: "dns-01",
// "http-01", or nil with a reason (no-domain: neither method is possible;
// not-registered: HTTP-01 but not under a registered cluster domain). A
// domain list that cannot be read leaves HTTP-01 names unchecked.
func (s *Server) certMethods(ctx context.Context, ws *webSession, names []string) (map[string]any, map[string]string) {
	methods, reasons := map[string]any{}, map[string]string{}
	var domains []string
	var domErr error
	read := false
	for _, n := range names {
		m, err := s.acmeMethod(n)
		if err != nil {
			methods[n], reasons[n] = nil, "no-domain"
			continue
		}
		if m == acme.HTTP01 {
			if !read {
				domains, domErr = s.orderDomains(ctx, ws)
				read = true
			}
			if domErr == nil && !slices.ContainsFunc(domains, func(d string) bool { return certstore.DomainCovers(d, n) }) {
				methods[n], reasons[n] = nil, "not-registered"
				continue
			}
		}
		methods[n] = m
	}
	return methods, reasons
}

// PUT /acme/certs/{name} {autoRenew, keyTypes}
func (s *Server) handleACMEUpdateCert(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req struct {
		AutoRenew bool     `json:"autoRenew"`
		KeyTypes  []string `json:"keyTypes"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	if !s.requireAdmin(w, r, ws) {
		return
	}
	c, ok := s.loadCert(w, r)
	if !ok {
		return
	}
	if err := checkKeyTypes(req.KeyTypes); err != nil {
		writeError(w, http.StatusUnprocessableEntity, "invalid", err.Error())
		return
	}
	before := map[string]any{"autoRenew": c.AutoRenew, "keyTypes": c.KeyTypes}
	c.AutoRenew, c.KeyTypes = req.AutoRenew, req.KeyTypes
	if err := s.opt.Store.PutACMECert(c); err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	s.audit(ws, "", "acme", "update-certificate", c.Name, before, map[string]any{"autoRenew": c.AutoRenew, "keyTypes": c.KeyTypes})
	writeJSON(w, http.StatusOK, map[string]any{"certificate": s.certView(c)})
}

// DELETE /acme/certs/{name}: forget the definition (the certificate store
// entry is not touched; revoke first if the key may have leaked).
func (s *Server) handleACMEDeleteCert(w http.ResponseWriter, r *http.Request, ws *webSession) {
	if !s.requireAdmin(w, r, ws) {
		return
	}
	name := r.PathValue("name")
	if err := s.opt.Store.DeleteACMECert(name); errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "missing", "no such certificate")
		return
	} else if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	s.audit(ws, "", "acme", "delete-certificate", name, nil, nil)
	w.WriteHeader(http.StatusNoContent)
}

// POST /acme/certs/{name}/issue {opId} → 202 {order}. The order runs in the
// background; poll GET /acme/certs/{name}. The same opId returns that order.
func (s *Server) handleACMEIssue(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req struct {
		OpID string `json:"opId"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	if !uuidRE.MatchString(req.OpID) {
		writeError(w, http.StatusBadRequest, "bad-request", "opId must be a UUID")
		return
	}
	if !s.requireAdmin(w, r, ws) {
		return
	}
	c, ok := s.loadCert(w, r)
	if !ok {
		return
	}
	if o, err := s.opt.Store.GetACMEOrder(c.Name, req.OpID); err == nil {
		writeJSON(w, http.StatusAccepted, map[string]any{"order": o})
		return
	}
	o, err := s.startOrder(c, req.OpID, ws)
	if errors.Is(err, errOrderRunning) {
		writeError(w, http.StatusConflict, "running", err.Error())
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	s.audit(ws, "", "acme", "issue", c.Name, nil, map[string]any{"order": o.ID})
	writeJSON(w, http.StatusAccepted, map[string]any{"order": o})
}

// GET /acme/certs/{name}/chain: the public chain (PEM).
func (s *Server) handleACMEChain(w http.ResponseWriter, r *http.Request, ws *webSession) {
	if !s.requireAdmin(w, r, ws) {
		return
	}
	c, ok := s.loadCert(w, r)
	if !ok {
		return
	}
	if c.ChainPEM == "" {
		writeError(w, http.StatusNotFound, "missing", "not issued yet")
		return
	}
	w.Header().Set("Content-Type", "application/pem-certificate-chain")
	w.Header().Set("Content-Disposition", `attachment; filename="`+c.Name+`.pem"`)
	_, _ = w.Write([]byte(c.ChainPEM))
}

// POST /acme/certs/{name}/revoke {confirm:"<name>"}: cannot be undone.
func (s *Server) handleACMERevoke(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req struct {
		Confirm string            `json:"confirm"`
		Reason  acme.RevokeReason `json:"reason"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	if !s.requireAdmin(w, r, ws) {
		return
	}
	if req.Reason == "" {
		req.Reason = "unspecified"
	}
	if _, ok := acme.RevokeReasons[req.Reason]; !ok {
		writeError(w, http.StatusUnprocessableEntity, "invalid", "reason: keyCompromise, superseded, cessationOfOperation or unspecified")
		return
	}
	c, ok := s.loadCert(w, r)
	if !ok {
		return
	}
	if req.Confirm != c.Name {
		writeError(w, http.StatusBadRequest, "confirm-mismatch", "type the certificate name to confirm")
		return
	}
	chain := pemChain(c.ChainPEM)
	if len(chain) == 0 {
		writeError(w, http.StatusConflict, "not-issued", "nothing to revoke")
		return
	}
	acct, ca, key, err := s.acmeOpen(c.Account)
	if err != nil {
		writeError(w, http.StatusConflict, "account", err.Error())
		return
	}
	ctx, cancel := s.dnsCtx(r)
	err = ca.Revoke(ctx, key, acct.URL, chain[0], req.Reason)
	cancel()
	if err != nil {
		writeError(w, http.StatusBadGateway, "ca-revoke", err.Error())
		return
	}
	before := c.Fingerprint
	c.AutoRenew = false
	_ = s.opt.Store.PutACMECert(c)
	s.audit(ws, "", "acme", "revoke", c.Name, map[string]any{"fingerprint": before}, map[string]any{"revoked": true, "reason": req.Reason})
	writeJSON(w, http.StatusOK, map[string]any{"certificate": s.certView(c), "revoked": before})
}

// acmeAuthoritative asks every authoritative name server of t's domain for
// the TXT values. It returns what is still missing ("" when all servers
// answer every value).
func (s *Server) acmeAuthoritative(ctx context.Context, t *txtSet) string {
	res := s.opt.Resolver
	if res == nil {
		res = dns.NetResolver{}
	}
	qctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	var servers []string
	var nsErr error
	for _, pub := range dns.PublicResolvers {
		ans, err := res.Query(qctx, pub, t.domain.Domain, "NS", true)
		if err == nil && len(ans.Values) > 0 {
			servers = ans.Values
			break
		}
		nsErr = err
	}
	if len(servers) == 0 {
		return fmt.Sprintf("%s: no name servers found for %s (%v)", t.fqdn, t.domain.Domain, nsErr)
	}
	slices.Sort(servers)
	for _, ns := range servers {
		ans, err := res.Query(qctx, strings.TrimSuffix(ns, ".")+":53", t.fqdn, "TXT", false)
		if err != nil {
			return fmt.Sprintf("%s at %s: %v", t.fqdn, ns, err)
		}
		for _, v := range t.values {
			if !slices.Contains(ans.Values, v) {
				return fmt.Sprintf("%s at %s", t.fqdn, ns)
			}
		}
	}
	return ""
}
