// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/jay94ks/mydcd/internal/certstore"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/userauth"
	"github.com/jay94ks/mydcd/internal/web/mydc"
	"github.com/jay94ks/mydcd/internal/web/store"
)

// The certificate store screens (docs/reference/certificate-store.md,
// devel/design/certificate-store.md). Every read and change goes to mydcd
// as the logged-in user's session; mydcd decides who may see or change the
// store (system administrators). The web app keeps no copy of the store.
// It only adds which certificate its own ACME definitions received last
// (definition) and which servers serve a link (servedBy, from the ingress
// mappings' Runtime.Certificates).
//
// A private key sent to POST /certificates goes once to mydcd's protected
// input (WriteCertificate), which seals it and returns a public receipt.
// The key is never stored, logged or echoed back; the stored op holds only
// the signed put-certificate original with that receipt.

// storeCertLink is one (host, family) link of a certificate.
type storeCertLink struct {
	Host     string   `json:"host"`
	Alg      string   `json:"alg"`
	ServedBy []string `json:"servedBy,omitempty"`
}

// storeCertView is the StoreCert of the web API (src/api/certs.ts).
type storeCertView struct {
	ID         string          `json:"id"`
	Names      []string        `json:"names"`
	KeyType    string          `json:"keyType"`
	Issuer     string          `json:"issuer"`
	Serial     string          `json:"serial"`
	NotBefore  string          `json:"notBefore"`
	NotAfter   string          `json:"notAfter"`
	UploadedBy string          `json:"uploadedBy,omitempty"`
	UploadedAt string          `json:"uploadedAt"`
	State      string          `json:"state"`
	Disabled   bool            `json:"disabled,omitempty"`
	Links      []storeCertLink `json:"links"`
	Definition string          `json:"definition,omitempty"`
	Chain      []string        `json:"chain,omitempty"`
}

func rfc(unix int64) string {
	if unix == 0 {
		return ""
	}
	return time.Unix(unix, 0).UTC().Format(time.RFC3339)
}

// certMaxTries: a store page conflicts once the store moved; read again.
const certMaxTries = 3

func isConflict(err error) bool {
	var me *mydc.Error
	return errors.As(err, &me) && me.Code == mydc.CodeConflict
}

// certAll reads every store certificate (restarted if the store moved).
func certAll(ctx context.Context, c mydc.Conn) ([]certstore.PublicEntry, error) {
	for try := 0; ; try++ {
		var out []certstore.PublicEntry
		q := control.CertificateQuery{}
		var err error
		for range ingressMaxPages {
			var p control.CertificatePage
			if p, err = c.QueryCertificates(ctx, q); err != nil {
				break
			}
			out = append(out, p.Certificates...)
			if p.Next == "" {
				return out, nil
			}
			q.After = p.Next
		}
		if err == nil {
			return out, nil
		}
		if try+1 == certMaxTries || !isConflict(err) {
			return nil, err
		}
	}
}

// certByPrefix finds the one certificate whose ID starts with prefix (12
// or more hex characters).
func certByPrefix(all []certstore.PublicEntry, prefix string) (*certstore.PublicEntry, error) {
	prefix = strings.ToLower(prefix)
	if len(prefix) < 12 || len(prefix) > 64 {
		return nil, &httpErr{http.StatusNotFound, "not-found", "no certificate with that ID (give at least 12 characters)"}
	}
	var found *certstore.PublicEntry
	for i := range all {
		if strings.HasPrefix(all[i].Metadata.ID.String(), prefix) {
			if found != nil {
				return nil, &httpErr{http.StatusConflict, "ambiguous", "more than one certificate starts with that ID"}
			}
			found = &all[i]
		}
	}
	if found == nil {
		return nil, &httpErr{http.StatusNotFound, "not-found", "no certificate with that ID"}
	}
	return found, nil
}

func fpHex(fp [32]byte) string {
	if fp == ([32]byte{}) {
		return ""
	}
	return hex.EncodeToString(fp[:])
}

// serialText writes a hex serial as colon-separated byte pairs.
func serialText(s string) string {
	if len(s)%2 == 1 {
		s = "0" + s
	}
	parts := make([]string, 0, len(s)/2)
	for i := 0; i < len(s); i += 2 {
		parts = append(parts, s[i:i+2])
	}
	return strings.Join(parts, ":")
}

// usernames maps user IDs to names for the "by" columns; unknown IDs stay.
func usernames(ctx context.Context, c mydc.Conn) map[string]string {
	out := map[string]string{}
	after := ""
	for range ingressMaxPages {
		p, err := c.Users(ctx, after)
		if err != nil {
			return out
		}
		for _, u := range p.Items {
			out[u.ID] = u.Username
		}
		if after = p.Next; after == "" {
			break
		}
	}
	return out
}

func nonNil[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}

// certDefinitions maps a certificate ID to the web ACME definition that
// received it last.
func (s *Server) certDefinitions() map[string]string {
	out := map[string]string{}
	defs, _ := s.opt.Store.ListACMECerts()
	for _, d := range defs {
		if d.Fingerprint != "" {
			out[d.Fingerprint] = d.Name
		}
	}
	return out
}

func (s *Server) storeCertView(e certstore.PublicEntry, names, defs map[string]string) storeCertView {
	m := e.Metadata
	v := storeCertView{ID: m.ID.String(), Names: nonNil(m.Hosts), KeyType: m.Algorithm, Issuer: m.Issuer, Serial: serialText(m.Serial),
		NotBefore: rfc(m.NotBefore), NotAfter: rfc(m.NotAfter), UploadedBy: m.UploadedBy, UploadedAt: rfc(m.UploadedAt),
		State: e.State, Disabled: e.DisabledAt != 0, Links: []storeCertLink{}, Definition: defs[m.ID.String()]}
	if n := names[m.UploadedBy]; n != "" {
		v.UploadedBy = n
	}
	for _, l := range e.Links {
		v.Links = append(v.Links, storeCertLink{Host: l.Host, Alg: l.Family})
	}
	return v
}

// GET /certificates?host&state → {items, store: true}
func (s *Server) handleCertificates(w http.ResponseWriter, r *http.Request, ws *webSession) {
	host, state := strings.ToLower(r.URL.Query().Get("host")), r.URL.Query().Get("state")
	if state != "" && state != certstore.StateUnlinked && state != certstore.StatePendingDestroy {
		writeError(w, http.StatusBadRequest, "bad-request", "state: unlinked or pending-destroy")
		return
	}
	ctx, cancel := s.callCtx(r)
	defer cancel()
	var certs []certstore.PublicEntry
	var names map[string]string
	err := ws.do(ctx, func(ctx context.Context, c mydc.Conn) error {
		var err error
		if certs, err = certAll(ctx, c); err != nil {
			return err
		}
		names = usernames(ctx, c)
		return nil
	})
	if err != nil {
		s.writeBackendError(w, ws, err)
		return
	}
	defs := s.certDefinitions()
	items := []storeCertView{}
	for _, e := range certs {
		if host != "" && !e.Metadata.Covers(host) || state != "" && e.State != state {
			continue
		}
		items = append(items, s.storeCertView(e, names, defs))
	}
	sort.SliceStable(items, func(i, j int) bool { return items[i].NotAfter > items[j].NotAfter })
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "store": true})
}

// certOne reads one certificate and its public chain by ID prefix.
func certOne(ctx context.Context, c mydc.Conn, prefix string) (*certstore.PublicEntry, []byte, error) {
	all, err := certAll(ctx, c)
	if err != nil {
		return nil, nil, err
	}
	e, err := certByPrefix(all, prefix)
	if err != nil {
		return nil, nil, err
	}
	p, err := c.QueryCertificates(ctx, control.CertificateQuery{ID: e.Metadata.ID.String()})
	if err != nil {
		return nil, nil, err
	}
	if len(p.Certificates) != 1 {
		return nil, nil, &httpErr{http.StatusNotFound, "not-found", "no certificate with that ID"}
	}
	return &p.Certificates[0], p.Chain, nil
}

// GET /certificates/{id} → StoreCert with chain subjects and servedBy.
func (s *Server) handleCertificate(w http.ResponseWriter, r *http.Request, ws *webSession) {
	ctx, cancel := s.callCtx(r)
	defer cancel()
	var e *certstore.PublicEntry
	var chain []byte
	var iv *ingressView
	var names map[string]string
	err := ws.do(ctx, func(ctx context.Context, c mydc.Conn) error {
		var err error
		if e, chain, err = certOne(ctx, c, r.PathValue("id")); err != nil {
			return err
		}
		if iv, err = ingressRead(ctx, c, control.IngressQuery{}); err != nil {
			// The servers column only stays empty.
			s.log.Warn("certificates: ingress observation", "err", err)
		}
		names = usernames(ctx, c)
		return nil
	})
	if err != nil {
		s.writeBackendError(w, ws, err)
		return
	}
	v := s.storeCertView(*e, names, s.certDefinitions())
	if in, err := certstore.Inspect(chain, s.now().Unix()); err == nil {
		v.Chain = in.Subjects
	}
	for i := range v.Links {
		v.Links[i].ServedBy = nonNil(servedBy(iv, e.Metadata.ID, v.Links[i].Host))
	}
	writeJSON(w, http.StatusOK, v)
}

// servedBy lists the servers whose ingress serves certificate id for a host
// the link covers.
func servedBy(iv *ingressView, id certstore.ID, link string) []string {
	if iv == nil {
		return nil
	}
	var out []string
	for _, m := range iv.Mappings {
		if m.Runtime == nil {
			continue
		}
		for _, o := range m.Runtime.Certificates {
			if o.Fingerprint == id && o.Error == "" && certstore.MatchHost(link, o.Host) > 0 && !slices.Contains(out, m.Node) {
				out = append(out, m.Node)
			}
		}
	}
	sort.Strings(out)
	return out
}

// GET /certificates/{id}/chain → the public chain PEM.
func (s *Server) handleCertificateChain(w http.ResponseWriter, r *http.Request, ws *webSession) {
	ctx, cancel := s.callCtx(r)
	defer cancel()
	var e *certstore.PublicEntry
	var chain []byte
	err := ws.do(ctx, func(ctx context.Context, c mydc.Conn) error {
		var err error
		e, chain, err = certOne(ctx, c, r.PathValue("id"))
		return err
	})
	if err != nil {
		s.writeBackendError(w, ws, err)
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", `attachment; filename="`+e.Metadata.ID.String()[:12]+`-chain.pem"`)
	_, _ = w.Write(chain)
}

// certChange signs and sends a delete or disable of one certificate as the
// logged-in user, stored as an op the daemon starts itself.
func (s *Server) certChange(ctx context.Context, c mydc.Conn, ws *webSession, action string, id certstore.ID) (*store.Op, error) {
	p, _ := json.Marshal(control.CertificateSelection{ID: id})
	ch := mydc.Change{Schema: 1, Action: action, Principal: ws.user.ID, Payload: p}
	who, err := c.Whoami(ctx)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(append([]byte(action+"\x00"), p...))
	o := &store.Op{ID: newOpID(), User: ws.user.ID, Username: ws.user.Username, Action: action, Target: id.String(), Digest: hex.EncodeToString(sum[:])}
	if _, err := s.sendStored(ctx, c, o, ch, who.RootFor(action)); err != nil {
		return nil, err
	}
	return o, nil
}

// certOpErr maps a store change that did not apply.
func certOpErr(o *store.Op) error {
	switch o.State {
	case store.OpApplied:
		return nil
	case store.OpFailed:
		return &httpErr{http.StatusConflict, "stale", "the certificate store changed; reload it"}
	case store.OpRejected:
		return &httpErr{http.StatusForbidden, "denied", "mydcd refused the change: " + o.ErrorCode}
	}
	return &httpErr{http.StatusServiceUnavailable, "unknown", "mydcd did not answer; operation " + o.ID + " keeps the signed original, read its result"}
}

func certLinksView(links []certstore.Link) []storeCertLink {
	out := []storeCertLink{}
	for _, l := range links {
		out = append(out, storeCertLink{Host: l.Host, Alg: l.Family})
	}
	return out
}

// DELETE /certificates/{id} → 204. A linked certificate is refused with 409
// linked and its links.
func (s *Server) handleCertificateDelete(w http.ResponseWriter, r *http.Request, ws *webSession) {
	ctx, cancel := s.callCtx(r)
	defer cancel()
	var linked []certstore.Link
	err := ws.do(ctx, func(ctx context.Context, c mydc.Conn) error {
		all, err := certAll(ctx, c)
		if err != nil {
			return err
		}
		e, err := certByPrefix(all, r.PathValue("id"))
		if err != nil {
			return err
		}
		if e.State == certstore.StateLinked {
			linked = e.Links
			return nil
		}
		o, err := s.certChange(ctx, c, ws, mydc.ActionDeleteCertificate, e.Metadata.ID)
		if err != nil {
			return err
		}
		return certOpErr(o)
	})
	if err != nil {
		s.writeBackendError(w, ws, err)
		return
	}
	if linked != nil {
		writeJSON(w, http.StatusConflict, map[string]any{"error": apiError{Code: "linked", Message: "the certificate is linked; disable it first"}, "links": certLinksView(linked)})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// POST /certificates/{id}/disable → {unlinkedHosts}
func (s *Server) handleCertificateDisable(w http.ResponseWriter, r *http.Request, ws *webSession) {
	ctx, cancel := s.callCtx(r)
	defer cancel()
	n := 0
	err := ws.do(ctx, func(ctx context.Context, c mydc.Conn) error {
		all, err := certAll(ctx, c)
		if err != nil {
			return err
		}
		e, err := certByPrefix(all, r.PathValue("id"))
		if err != nil {
			return err
		}
		if e.DisabledAt != 0 {
			return &httpErr{http.StatusConflict, "disabled", "the certificate is already disabled"}
		}
		hosts := map[string]bool{}
		for _, l := range e.Links {
			hosts[l.Host] = true
		}
		n = len(hosts)
		o, err := s.certChange(ctx, c, ws, mydc.ActionDisableCertificate, e.Metadata.ID)
		if err != nil {
			return err
		}
		return certOpErr(o)
	})
	if err != nil {
		s.writeBackendError(w, ws, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"unlinkedHosts": n})
}

func invalidCode(code, msg string) error { return &httpErr{http.StatusUnprocessableEntity, code, msg} }

// readStoreChain inspects a chain the way mydcd will: leaf first, the ID,
// hosts and algorithm. It refuses only what is not a chain.
func readStoreChain(chain string, now time.Time) (certstore.Inspection, []byte, error) {
	ders := pemChain(chain)
	if len(ders) == 0 {
		return certstore.Inspection{}, nil, invalidCode("invalid-chain", "chain: PEM CERTIFICATE blocks, leaf first")
	}
	var out []byte
	for _, d := range ders {
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: d})...)
	}
	in, err := certstore.Inspect(out, now.Unix())
	if err != nil {
		return in, nil, invalidCode("invalid-chain", "chain: the certificates could not be read, or are not one chain leaf first")
	}
	return in, out, nil
}

// POST /certificates/check {chain} → CertCheck: what a put would link.
// Only the public chain is read.
func (s *Server) handleCertificateCheck(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req struct {
		Chain string `json:"chain"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	in, _, err := readStoreChain(req.Chain, s.now())
	if err != nil {
		s.writeBackendError(w, ws, err)
		return
	}
	ctx, cancel := s.callCtx(r)
	defer cancel()
	var catalog certstore.Catalog
	err = ws.do(ctx, func(ctx context.Context, c mydc.Conn) error {
		p, err := c.QueryCertificates(ctx, control.CertificateQuery{})
		if err != nil {
			return err
		}
		catalog.Domains = p.Domains
		all, err := certAll(ctx, c)
		for _, e := range all {
			catalog.Certificates = append(catalog.Certificates, certstore.Entry{Certificate: certstore.Certificate{Metadata: e.Metadata}, DisabledAt: e.DisabledAt, DisabledBy: e.DisabledBy})
		}
		return err
	})
	if err != nil {
		s.writeBackendError(w, ws, err)
		return
	}
	m := in.Metadata
	type checkLink struct {
		Host     string `json:"host"`
		Alg      string `json:"alg"`
		Replaces string `json:"replaces,omitempty"`
	}
	links := []checkLink{}
	if in.Invalid == "" {
		at := s.now().Unix()
		before := catalog.Links(at)
		if _, stored := catalog.Entry(m.ID); !stored {
			m.UploadedAt = at
			catalog.Certificates = append(catalog.Certificates, certstore.Entry{Certificate: certstore.Certificate{Metadata: m}})
			slices.SortFunc(catalog.Certificates, func(a, b certstore.Entry) int {
				return strings.Compare(a.Certificate.Metadata.ID.String(), b.Certificate.Metadata.ID.String())
			})
		}
		for _, l := range catalog.LinksOf(m.ID, at) {
			cl := checkLink{Host: l.Host, Alg: l.Family}
			for _, b := range before {
				if b.Host == l.Host && b.Family == l.Family && b.ID != m.ID {
					cl.Replaces = b.ID.String()
				}
			}
			links = append(links, cl)
		}
	}
	out := map[string]any{"id": m.ID.String(), "names": nonNil(m.Hosts), "keyType": m.Algorithm, "issuer": m.Issuer, "notAfter": rfc(m.NotAfter), "links": links}
	if in.Invalid != "" {
		out["invalid"] = in.Invalid
	}
	writeJSON(w, http.StatusOK, out)
}

// invalidPut maps a chain refusal to the put error codes of the web API.
func invalidPut(code string) error {
	switch code {
	case certstore.InvalidExpired, certstore.InvalidNotYetValid:
		return invalidCode("not-valid-now", "the certificate is not valid now")
	case certstore.InvalidKey:
		return invalidCode("unsupported-key", "the key algorithm is not supported (ECDSA P-256/P-384 or RSA 2048 bits or more)")
	case certstore.InvalidNoNames:
		return invalidCode("no-names", "the certificate has no DNS or IP name and no subject CN")
	}
	return nil
}

// checkKeyPair refuses a key that is not PEM or does not belong to chain.
// Only fixed codes are returned; no key material reaches a message or log.
func checkKeyPair(chain, keyPEM []byte) error {
	if b, _ := pem.Decode(keyPEM); b == nil || b.Type != "PRIVATE KEY" && b.Type != "EC PRIVATE KEY" && b.Type != "RSA PRIVATE KEY" {
		return invalidCode("invalid-key", "key: a PEM private key")
	}
	if _, err := tls.X509KeyPair(chain, keyPEM); err != nil {
		if _, perr := x509.ParsePKCS8PrivateKey(pemBytes(keyPEM)); perr != nil {
			if _, e1 := x509.ParseECPrivateKey(pemBytes(keyPEM)); e1 != nil {
				if _, e2 := x509.ParsePKCS1PrivateKey(pemBytes(keyPEM)); e2 != nil {
					return invalidCode("invalid-key", "key: the private key could not be read")
				}
			}
		}
		return invalidCode("mismatch", "the key does not belong to the certificate")
	}
	return nil
}

// POST /certificates {chain, key} → {id, created, links}. A certificate
// already in the store answers created: false and is not sent again. The
// key is used only for this call.
func (s *Server) handleCertificatePut(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req struct {
		Chain string `json:"chain"`
		Key   string `json:"key"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	keyPEM := []byte(req.Key)
	req.Key = ""
	defer clear(keyPEM)
	reason, err := opReasonOf(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad-request", err.Error())
		return
	}
	in, chain, err := readStoreChain(req.Chain, s.now())
	if err == nil {
		err = checkKeyPair(chain, keyPEM)
	}
	if err == nil {
		err = invalidPut(in.Invalid)
	}
	if err != nil {
		s.writeBackendError(w, ws, err)
		return
	}
	ctx, cancel := s.callCtx(r)
	defer cancel()
	created := false
	var links []certstore.Link
	err = ws.do(ctx, func(ctx context.Context, c mydc.Conn) error {
		var err error
		created, links, err = s.storeCertificate(ctx, c, ws.user.ID, ws.user.Username, newOpID(), chain, keyPEM, reason)
		return err
	})
	if err != nil {
		s.writeBackendError(w, ws, err)
		return
	}
	s.log.Info("create", "user", ws.user.Username, "action", mydc.ActionPutCertificate, "target", in.Metadata.ID.String(), "created", created)
	status := http.StatusOK
	if created {
		status = http.StatusCreated
	}
	writeJSON(w, status, map[string]any{"id": in.Metadata.ID.String(), "created": created, "links": certLinksView(links)})
}

// storeCertificate puts a checked chain and key unless its ID is already
// stored, then returns the certificate's links. opID names the stored op
// (and the protected input's request): one per put, so a lost reply is
// asked again with the same input and never makes a second certificate.
func (s *Server) storeCertificate(ctx context.Context, c mydc.Conn, user, username, opID string, chain, keyPEM []byte, reason *store.OpReason) (bool, []certstore.Link, error) {
	in, err := certstore.Inspect(chain, s.now().Unix())
	if err != nil {
		return false, nil, invalidCode("invalid-chain", "chain: the certificates could not be read")
	}
	find := func() (*certstore.PublicEntry, error) {
		all, err := certAll(ctx, c)
		if err != nil {
			return nil, err
		}
		for i := range all {
			if all[i].Metadata.ID == in.Metadata.ID {
				return &all[i], nil
			}
		}
		return nil, nil
	}
	if e, err := find(); err != nil || e != nil {
		if e != nil {
			return false, e.Links, nil
		}
		return false, nil, err
	}
	_, op, err := certPrepare(ctx, c, user, chain, keyPEM, certRequestID(opID), reason)
	if err != nil {
		return false, nil, err
	}
	sum := sha256.Sum256(op)
	o := &store.Op{ID: opID, User: user, Username: username, Action: mydc.ActionPutCertificate, Target: in.Metadata.ID.String(), Digest: hex.EncodeToString(sum[:]), Reason: reason}
	if _, err := s.sendPrepared(ctx, c, o, op); err != nil {
		return false, nil, err
	}
	if err := certOpErr(o); err != nil {
		return false, nil, err
	}
	e, err := find()
	if err != nil || e == nil {
		return true, nil, err
	}
	return true, e.Links, nil
}

func pemBytes(b []byte) []byte {
	if p, _ := pem.Decode(b); p != nil {
		return p.Bytes
	}
	return nil
}

// certRequestID is the protected input's request: one per web op, so a
// lost reply is asked again with the same input (mydcd gives the same
// receipt) and never makes a second certificate.
func certRequestID(opID string) string { return "web-cert-" + opID }

// certPrepare hands the chain and key to mydcd's protected input, which
// checks them, seals the key and returns the public receipt; only the
// receipt goes into the signed put-certificate original. Nothing durable is
// sent: store the original before Submit. A lost reply is settled by
// resending that same original, which carries no key.
func certPrepare(ctx context.Context, c mydc.Conn, user string, chainPEM, keyPEM []byte, request string, reason *store.OpReason) (certstore.Certificate, mydc.SignedOp, error) {
	in := userauth.CertificateInput{Request: request, Chain: chainPEM, Key: keyPEM}
	receipt, err := c.WriteCertificate(ctx, in)
	if err != nil && !isMydcCode(err, mydc.CodeInvalid, mydc.CodeConflict, mydc.CodeDenied) {
		// Asking again with the same request and input gives the same
		// receipt if the first one was made.
		receipt, err = c.WriteCertificate(ctx, in)
	}
	if err != nil {
		return receipt, nil, certInputErr(err)
	}
	who, err := c.Whoami(ctx)
	if err != nil {
		return receipt, nil, err
	}
	raw, err := json.Marshal(control.CertificatePut{Certificate: receipt})
	if err != nil {
		return receipt, nil, err
	}
	ch := mydc.Change{Schema: 1, Action: mydc.ActionPutCertificate, Principal: user, Payload: raw}
	root := who.RootFor(mydc.ActionPutCertificate)
	var op mydc.SignedOp
	if reason != nil {
		op, err = c.PrepareRequestReason(ctx, receipt.Request, ch, root, mydc.OperationReason{Reason: reason.Reason, Incident: reason.Incident})
	} else {
		op, err = c.PrepareRequest(ctx, receipt.Request, ch, root)
	}
	return receipt, op, err
}

func isMydcCode(err error, codes ...mydc.Code) bool {
	var me *mydc.Error
	return errors.As(err, &me) && slices.Contains(codes, me.Code)
}

// certInputErr maps the protected input's refusals.
func certInputErr(err error) error {
	var me *mydc.Error
	if !errors.As(err, &me) {
		return err
	}
	switch me.Code {
	case mydc.CodeInvalid:
		return invalidCode("invalid-certificate", "mydcd refused the chain or key (key pair, names or validity)")
	case mydc.CodeConflict:
		return &httpErr{http.StatusConflict, "stale", "the certificate is already in the store; reload it"}
	}
	return err
}
