// SPDX-License-Identifier: Apache-2.0

package sfc

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/jay94ks/seafield/internal/certstore"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/userauth"
)

// The certificate store in sfcd's real shape
// (docs/reference/certificate-store.md, unix-sockets.md): `certificates` →
// control.CertificatePage, the protected input WriteCertificate
// (userauth.CertificateInput → a sealed certstore.Certificate receipt), and
// the actions put-certificate {control.CertificatePut}, delete-certificate
// and disable-certificate {control.CertificateSelection}, Expected 0. The
// fake runs sfcd's own certstore.Catalog.
//
// Fake-only:
//   - The catalogue and its domain list are seeded from the fixture
//     (Certificates, Domains).
//   - The receipt is sealed by node-a's fixed key (FixtureKey("node-a")).
//   - Expired certificates are removed on read (sfcd does it from a
//     voter's signed report); that change moves the control/certificates
//     root.
//   - Every change moves the ingress certificate observations to the
//     certificate the store now links for that host, as dynamic loading
//     would.

const fakeCertificateSealer = "node-a"

type certRealState struct {
	cat      certstore.Catalog
	receipts map[string]certReceipt // user/request
}

type certReceipt struct {
	input [32]byte
	v     certstore.Certificate
}

func (w *world) sealCertificate(user, request string, at int64, chain, key []byte) (certstore.Certificate, error) {
	vk := make([]byte, 32)
	if _, err := rand.Read(vk); err != nil {
		return certstore.Certificate{}, err
	}
	defer clear(vk)
	return certstore.Seal(w.cluster, user, request, at, certstore.Material{Chain: bytes.Clone(chain), Key: bytes.Clone(key)}, vk, FixtureKey(fakeCertificateSealer))
}

// expireRealCertificates removes expired certificates, as the voter report
// does.
func (w *world) expireRealCertificates(now int64) {
	next, removed, err := w.creal.cat.Expire(now)
	if err == nil && len(removed) > 0 {
		w.creal.cat = next
		w.bumpKey(control.CertificatesKey)
		w.loadRealCertificates(now)
	}
}

func validRequestID(s string) bool {
	return s != "" && len(s) <= 128 && utf8.ValidString(s) && !strings.ContainsAny(s, "\x00\r\n")
}

const fakeCertificatePage = 32

// QueryCertificates: the list (q.After from Next, 32 rows a page,
// conflicting once the catalogue moved) or one certificate with its chain
// (q.ID; a missing ID is an empty page).
func (c *fakeConn) QueryCertificates(ctx context.Context, q control.CertificateQuery) (control.CertificatePage, error) {
	const m = "certificates"
	if !q.Valid() {
		return control.CertificatePage{}, fail(m, CodeInvalid, "query")
	}
	if err := c.adminOnly(ctx, m); err != nil {
		return control.CertificatePage{}, err
	}
	defer c.unlock()
	w := c.f.w
	now := c.f.now().Unix()
	w.expireRealCertificates(now)
	cat := w.creal.cat
	out := control.CertificatePage{Revision: cat.Revision}
	if q.ID != "" {
		id, _ := certstore.ParseID(q.ID)
		e, ok := cat.Entry(id)
		if !ok {
			return out, nil
		}
		for _, row := range cat.Public(now) {
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
		if !ok || e != nil || n != cat.Revision || strconv.FormatUint(n, 10) != revision {
			return out, fail(m, CodeConflict, "the certificate store changed: read again")
		}
		if _, ok := certstore.ParseID(tail); !ok {
			return out, fail(m, CodeInvalid, "after")
		}
		after = tail
	} else {
		out.Domains, out.ACMEResponder = cat.Domains, cat.ACMEResponder
	}
	for _, row := range cat.Public(now) {
		if row.Metadata.ID.String() <= after {
			continue
		}
		if len(out.Certificates) == fakeCertificatePage {
			out.Next = strconv.FormatUint(cat.Revision, 10) + ":" + out.Certificates[len(out.Certificates)-1].Metadata.ID.String()
			break
		}
		out.Certificates = append(out.Certificates, row)
	}
	return out, nil
}

// WriteCertificate is the protected input (SecretInput mode certificate):
// the chain and key go once to the provider, which checks them, seals the
// key and returns the public receipt. Submit put-certificate with
// {Certificate: receipt}, signed with PrepareRequest(receipt.Request).
// Recover returns the stored receipt of the same request; the same request
// with other input, or a chain already in the store, is a conflict.
func (c *fakeConn) WriteCertificate(ctx context.Context, in userauth.CertificateInput) (certstore.Certificate, error) {
	const m = "certificate-input"
	if !validRequestID(in.Request) ||
		!(in.Recover && in.Chain == nil && in.Key == nil || !in.Recover && len(in.Chain) > 0 && len(in.Chain) <= certstore.MaxChainBytes && len(in.Key) > 0 && len(in.Key) <= certstore.MaxKeyBytes) {
		return certstore.Certificate{}, fail(m, CodeInvalid, "certificate input")
	}
	if err := c.adminOnly(ctx, m); err != nil {
		return certstore.Certificate{}, err
	}
	defer c.unlock()
	w := c.f.w
	user := c.session.User
	key := user + "/" + in.Request
	if in.Recover {
		r, ok := w.creal.receipts[key]
		if !ok {
			return certstore.Certificate{}, fail(m, CodeMissing, "no receipt for this request")
		}
		return r.v, nil
	}
	h := sha256.New()
	for _, b := range [][]byte{in.Chain, in.Key} {
		h.Write([]byte(strconv.Itoa(len(b)) + ":"))
		h.Write(b)
	}
	var digest [32]byte
	copy(digest[:], h.Sum(nil))
	if r, ok := w.creal.receipts[key]; ok {
		if r.input != digest {
			return certstore.Certificate{}, fail(m, CodeConflict, "request ID used with other input")
		}
		return r.v, nil
	}
	now := c.f.now().Unix()
	w.expireRealCertificates(now)
	if in, err := certstore.Inspect(in.Chain, now); err == nil && in.Invalid == "" {
		if _, stored := w.creal.cat.Entry(in.Metadata.ID); stored {
			return certstore.Certificate{}, fail(m, CodeConflict, "the certificate is already in the store")
		}
	}
	v, err := w.sealCertificate(user, in.Request, now, in.Chain, in.Key)
	if err != nil {
		return certstore.Certificate{}, fail(m, CodeInvalid, "chain and key do not match, or the certificate is not valid now")
	}
	w.creal.receipts[key] = certReceipt{input: digest, v: v}
	return v, nil
}

func (c *fakeConn) applyRealCertificate(op UserOperation, actor string) error {
	w := c.f.w
	if !w.admin(actor) {
		return errForbidden
	}
	w.expireRealCertificates(op.At)
	ch := op.Change
	if ch.Expected != 0 && ch.Action != ActionSetACMEResponder && ch.Action != ActionAddDomain && ch.Action != ActionRemoveDomain {
		return errors.New("expected")
	}
	var err error
	cat := w.creal.cat
	switch ch.Action {
	case ActionSetACMEResponder:
		var q control.ACMEResponderChange
		if decodePayload(ch.Payload, &q) != nil {
			return errors.New("payload")
		}
		cat, err = cat.SetACMEResponder(q.Address, op.Session.User, ch.Expected, op.At)
	case ActionAddDomain, ActionRemoveDomain:
		var q control.DomainChange
		if decodePayload(ch.Payload, &q) != nil {
			return errors.New("payload")
		}
		if n, ok := certstore.NormalizeDomain(q.Name); !ok || n != q.Name {
			return errors.New("payload")
		}
		if ch.Action == ActionAddDomain {
			cat, err = cat.AddDomain(q.Name, op.Session.User, ch.Expected, op.At)
		} else {
			cat, err = cat.RemoveDomain(q.Name, ch.Expected)
		}
	case ActionPutCertificate:
		var q control.CertificatePut
		if decodePayload(ch.Payload, &q) != nil || q.Certificate.Cluster != w.cluster || q.Certificate.Metadata.UploadedBy != op.Session.User || q.Certificate.Request != op.RequestID {
			return errors.New("payload")
		}
		if q.Certificate.Sealer != pub32(FixtureKey(fakeCertificateSealer)) {
			return errForbidden
		}
		cat, err = cat.Put(q.Certificate, op.At)
	case ActionDeleteCertificate, ActionDisableCertificate:
		var q control.CertificateSelection
		if decodePayload(ch.Payload, &q) != nil || q.ID == (certstore.ID{}) {
			return errors.New("payload")
		}
		if ch.Action == ActionDeleteCertificate {
			cat, err = cat.Delete(q.ID, op.At)
		} else {
			cat, err = cat.Disable(q.ID, op.Session.User, op.At)
		}
	default:
		return errors.New("action")
	}
	if err != nil {
		return errCAS // sfcd: every catalogue refusal is ConditionFailed
	}
	w.creal.cat = cat
	w.loadRealCertificates(op.At)
	return nil
}
