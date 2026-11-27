// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/certstore"
	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/membership"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/identity"
	"github.com/jay94ks/seafield/internal/ingress"
	"github.com/jay94ks/seafield/internal/schema"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/internal/storage"
	"github.com/jay94ks/seafield/internal/userauth"
)

// certificateUnseal bounds wallet-KDF memory for master unseals across every
// runtime in the process (retained original owners included).
var certificateUnseal sync.Mutex

func (r *Runtime) certificateNative() certstore.Native {
	return certstore.Native{DB: r.reports, Cluster: r.controlPolicy.Cluster, Identity: r.Identity.Private}
}

// certificateMaster is this node's certificate master key, from the current
// identity's native store or a retained original one (storage.ErrMissing
// when it has none). The caller clears it. Unsealing runs the wallet KDF
// (Argon2id, 64 MiB), so one unseal runs at a time per process; concurrent
// key requests wait instead of each allocating its own KDF memory.
func (r *Runtime) certificateMaster() ([]byte, error) {
	certificateUnseal.Lock()
	defer certificateUnseal.Unlock()
	for _, owner := range r.physicalOwners() {
		if owner != r {
			owner.life.RLock()
		}
		if owner.closed || owner.reports == nil {
			if owner != r {
				owner.life.RUnlock()
			}
			continue
		}
		key, err := owner.certificateNative().Master()
		if owner != r {
			owner.life.RUnlock()
		}
		if err == nil {
			return key, nil
		}
		if !errors.Is(err, storage.ErrMissing) {
			return nil, err
		}
	}
	return nil, storage.ErrMissing
}

// voterKey derives the key of certificate id when this node is a current
// voter holding the master key (storage.ErrMissing otherwise).
func (r *Runtime) voterKey(s state.State, id certstore.ID) ([]byte, error) {
	members, err := r.controlPolicy.Members(s)
	if err != nil || !members.VoterKey(r.commandIdentity().Public) {
		return nil, storage.ErrMissing
	}
	master, err := r.certificateMaster()
	if err != nil {
		return nil, err
	}
	defer clear(master)
	return certstore.Derive(master, id)
}

func (r *Runtime) recoverCertificate(ctx context.Context, user, request string) (certstore.Certificate, error) {
	var found *certstore.Certificate
	for _, owner := range r.physicalOwners() {
		if owner != r {
			owner.life.RLock()
		}
		if owner.closed || owner.reports == nil {
			if owner != r {
				owner.life.RUnlock()
			}
			return certstore.Certificate{}, sfcp.ErrAdmission
		}
		v, err := owner.certificateNative().Recover(user, request)
		if owner != r {
			owner.life.RUnlock()
		}
		if err != nil {
			if errors.Is(err, storage.ErrMissing) {
				continue
			}
			return certstore.Certificate{}, err
		}
		if !r.acceptsResourceKey(ctx, owner.Identity.Public) {
			return certstore.Certificate{}, sfcp.ErrAdmission
		}
		if found != nil {
			return certstore.Certificate{}, certstore.ErrConflict
		}
		found = &v
	}
	if found == nil {
		return certstore.Certificate{}, storage.ErrMissing
	}
	return *found, nil
}

func (r *Runtime) writeCertificate(ctx context.Context, session access.Session, q userauth.CertificateInput) (certstore.Certificate, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(r.ctx, cancel)
	defer stop()
	r.life.RLock()
	defer r.life.RUnlock()
	if r.closed || r.reports == nil {
		return certstore.Certificate{}, sfcp.ErrAdmission
	}
	view, err := r.physicalOwners()[0].currentView(ctx)
	at := time.Now().Unix()
	if err != nil || view.Local || r.controlPolicy.CertificateAllowed(view.State, session, at, "put-certificate") != nil {
		return certstore.Certificate{}, sfcp.ErrAdmission
	}
	members, err := r.controlPolicy.Members(view.State)
	if err != nil || !members.MemberKey(r.commandIdentity().Public) || !q.Recover && (!members.WorkKey(r.commandIdentity().Public) || r.historicalOwner) {
		return certstore.Certificate{}, sfcp.ErrAdmission
	}
	if q.Recover {
		v, err := r.recoverCertificate(ctx, session.User, q.Request)
		if err != nil {
			return certstore.Certificate{}, err
		}
		latest, err := r.physicalOwners()[0].currentView(ctx)
		if err != nil || latest.Local || r.controlPolicy.CertificateAllowed(latest.State, session, time.Now().Unix(), "put-certificate") != nil {
			return certstore.Certificate{}, sfcp.ErrAdmission
		}
		members, cause := r.controlPolicy.Members(latest.State)
		if cause != nil || !members.MemberKey(r.commandIdentity().Public) {
			return certstore.Certificate{}, sfcp.ErrAdmission
		}
		return v, nil
	}
	// The same original request cannot be allocated under a replacement key.
	if old, cause := r.recoverCertificate(ctx, session.User, q.Request); cause == nil {
		if old.Sealer != r.Identity.Public {
			return certstore.Certificate{}, certstore.ErrConflict
		}
	} else if !errors.Is(cause, storage.ErrMissing) {
		return certstore.Certificate{}, cause
	}
	catalog, err := r.controlPolicy.Certificates(view.State)
	if err != nil {
		return certstore.Certificate{}, err
	}
	// Callers look the chain's ID up first; a stored ID is a conflict here.
	in, err := certstore.Inspect(q.Chain, at)
	if err != nil || in.Invalid != "" {
		return certstore.Certificate{}, certstore.ErrCertificate
	}
	if _, stored := catalog.Entry(in.Metadata.ID); stored || len(catalog.Certificates) >= certstore.MaxEntries {
		return certstore.Certificate{}, access.ErrConflict
	}
	material := certificateMaterialInput(q)
	key, err := r.uploadKey(ctx, view.State, in.Metadata.ID, material, at)
	if err != nil {
		return certstore.Certificate{}, err
	}
	defer clear(key)
	v, err := r.certificateNative().Prepare(session.User, q.Request, at, material, key)
	if err != nil {
		return certstore.Certificate{}, err
	}
	latest, err := r.physicalOwners()[0].currentView(ctx)
	if err != nil || latest.Local || r.controlPolicy.CertificateAllowed(latest.State, session, time.Now().Unix(), "put-certificate") != nil {
		return certstore.Certificate{}, sfcp.ErrAdmission
	}
	members, cause := r.controlPolicy.Members(latest.State)
	if cause != nil || !members.WorkKey(r.commandIdentity().Public) {
		return certstore.Certificate{}, sfcp.ErrAdmission
	}
	return v, nil
}

func certificateMaterialInput(q userauth.CertificateInput) certstore.Material {
	return certstore.Material{Chain: q.Chain, Key: q.Key}
}

// certificateRequest is the CertificateMaterial body: exactly one of an
// ingress read of a stored certificate's key, a seal request for an upload
// (by a member that is not a voter), or a voter asking for the master key.
type certificateRequest struct {
	Read   *control.CertificateMaterialRead `json:",omitempty"`
	Seal   *certstore.SealRequest           `json:",omitempty"`
	Master *certificateMasterRequest        `json:",omitempty"`
}
type certificateMasterRequest struct {
	Schema         uint8
	Cluster, Voter [32]byte
	At             int64
}

// certificateKeyReply carries a derived certificate key (Certificate is the
// read receipt digest or the sealed ID) or, for a master request, the
// master key (Certificate zero).
type certificateKeyReply struct {
	Schema      uint8
	Certificate [32]byte
	Key         []byte
}

func (q certificateRequest) one() bool {
	n := 0
	for _, set := range []bool{q.Read != nil, q.Seal != nil, q.Master != nil} {
		if set {
			n++
		}
	}
	return n == 1
}

// uploadKey is the key that seals a new upload of certificate id: derived
// here on a voter, otherwise asked of a voter with a proof that this node
// holds the certificate's private key.
func (r *Runtime) uploadKey(ctx context.Context, s state.State, id certstore.ID, material certstore.Material, at int64) ([]byte, error) {
	key, err := r.voterKey(s, id)
	if !errors.Is(err, storage.ErrMissing) {
		return key, err
	}
	pair, err := tls.X509KeyPair(material.Chain, material.Key)
	if err != nil || len(pair.Certificate) == 0 {
		return nil, certstore.ErrCertificate
	}
	signer, ok := pair.PrivateKey.(crypto.Signer)
	if !ok {
		return nil, certstore.ErrCertificate
	}
	q, err := certstore.SignSealRequest(certstore.SealRequest{Schema: 1, Cluster: r.controlPolicy.Cluster, Member: r.commandIdentity().Public, ID: id, Leaf: pair.Certificate[0], At: at}, signer)
	if err != nil {
		return nil, err
	}
	return r.askVoters(ctx, s, certificateRequest{Seal: &q}, [32]byte(id))
}

// askVoters sends one request to the current voters until one answers
// with a 32-byte key for want.
func (r *Runtime) askVoters(ctx context.Context, s state.State, q certificateRequest, want [32]byte) ([]byte, error) {
	members, err := r.controlPolicy.Members(s)
	if err != nil {
		return nil, err
	}
	body, err := json.Marshal(q)
	if err != nil {
		return nil, err
	}
	peers := []sfcp.Peer{}
	for _, entry := range members.Entries {
		key, err := identity.ParseKey(entry.CurrentPeer().Key)
		if err != nil || key == r.commandIdentity().Public || !members.VoterKey(key) {
			continue
		}
		if peer, ok := r.Mesh.Peer(sfcp.Identity(key)); ok && peer.Member {
			peers = append(peers, peer)
		}
	}
	slices.SortFunc(peers, func(a, b sfcp.Peer) int { return strings.Compare(a.ID, b.ID) })
	for _, peer := range peers {
		session, err := r.Mesh.Dial(ctx, peer)
		if err != nil {
			continue
		}
		raw, err := session.FetchCertificateMaterial(ctx, body)
		if err != nil {
			continue
		}
		reply, err := schema.Decode[certificateKeyReply](raw)
		clear(raw)
		if err != nil || reply.Schema != 1 || reply.Certificate != want || len(reply.Key) != 32 {
			clear(reply.Key)
			continue
		}
		return reply.Key, nil
	}
	return nil, certstore.ErrCertificate
}

func (r *Runtime) serveCertificateMaterial() error {
	return r.Mesh.OnCertificateMaterial(func(ctx context.Context, s *sfcp.Session, body []byte) ([]byte, error) {
		ctx, cancel := context.WithCancel(ctx)
		defer cancel()
		stop := context.AfterFunc(r.ctx, cancel)
		defer stop()
		q, err := schema.Decode[certificateRequest](body)
		if err != nil || !q.one() {
			return nil, sfcp.ErrAdmission
		}
		caller := [32]byte(s.Peer().Key)
		r.life.RLock()
		defer r.life.RUnlock()
		if r.closed || r.reports == nil {
			return nil, sfcp.ErrAdmission
		}
		view, err := r.physicalOwners()[0].currentView(ctx)
		if err != nil || view.Local {
			return nil, sfcp.ErrAdmission
		}
		now := time.Now().Unix()
		var reply certificateKeyReply
		switch {
		case q.Read != nil:
			if !r.resourceCaller(ctx, caller, q.Read.Consumer) {
				return nil, sfcp.ErrAdmission
			}
			v, err := r.controlPolicy.CertificateMaterial(view.State, caller, *q.Read, now)
			if err != nil {
				return nil, err
			}
			key, err := r.voterKey(view.State, v.Metadata.ID)
			if err != nil || sha256.Sum256(key) != v.KeyID {
				clear(key)
				return nil, sfcp.ErrAdmission
			}
			reply = certificateKeyReply{1, v.Digest(), key}
		case q.Seal != nil:
			members, err := r.controlPolicy.Members(view.State)
			if err != nil || !members.WorkKey(caller) || q.Seal.Member != caller || q.Seal.At > now+60 || now-q.Seal.At > 60 || q.Seal.Verify(r.controlPolicy.Cluster) != nil {
				return nil, sfcp.ErrAdmission
			}
			key, err := r.voterKey(view.State, q.Seal.ID)
			if err != nil {
				return nil, sfcp.ErrAdmission
			}
			reply = certificateKeyReply{1, [32]byte(q.Seal.ID), key}
		default:
			members, err := r.controlPolicy.Members(view.State)
			m := q.Master
			if err != nil || m.Schema != 1 || m.Cluster != r.controlPolicy.Cluster || m.Voter != caller || m.At > now+60 || now-m.At > 60 || !members.VoterKey(caller) || !members.VoterKey(r.commandIdentity().Public) {
				return nil, sfcp.ErrAdmission
			}
			key, err := r.certificateMaster()
			if err != nil {
				return nil, sfcp.ErrAdmission
			}
			reply = certificateKeyReply{Schema: 1, Key: key}
		}
		defer clear(reply.Key)
		// The answer stands only while this node is still a voter.
		latest, err := r.physicalOwners()[0].currentView(ctx)
		if err != nil || latest.Local {
			return nil, sfcp.ErrAdmission
		}
		members, err := r.controlPolicy.Members(latest.State)
		if err != nil || !members.VoterKey(r.commandIdentity().Public) {
			return nil, sfcp.ErrAdmission
		}
		if q.Read != nil {
			current, err := r.controlPolicy.CertificateMaterial(latest.State, caller, *q.Read, time.Now().Unix())
			if err != nil || current.Digest() != reply.Certificate {
				return nil, sfcp.ErrAdmission
			}
		}
		return json.Marshal(reply)
	})
}

// advanceCertificateMaster keeps the master key on exactly the current
// voters: a voter without it asks another voter; a node whose own entry is
// committed as not a voter, or that was removed, erases it.
func (r *Runtime) advanceCertificateMaster(ctx context.Context) {
	if r.historicalOwner || r.reports == nil {
		return
	}
	// The local applied state is enough to decide; the voter that answers
	// checks the current quorum view.
	view, members, err := r.members(ctx, false)
	if err != nil {
		return
	}
	self := r.commandIdentity().Public
	// Presence only: opening the envelope on every loop tick would run the
	// wallet key derivation each time.
	has := false
	for _, owner := range r.physicalOwners() {
		has = has || owner.reports != nil && owner.certificateNative().HasMaster()
	}
	if members.VoterKey(self) {
		if has {
			return
		}
		key, err := r.askVoters(ctx, view.State, certificateRequest{Master: &certificateMasterRequest{Schema: 1, Cluster: r.controlPolicy.Cluster, Voter: self, At: time.Now().Unix()}}, [32]byte{})
		if err != nil {
			return
		}
		defer clear(key)
		_ = r.certificateNative().InstallMaster(key)
		return
	}
	if !has || !certificateNonVoter(members, self) {
		return
	}
	for _, owner := range r.physicalOwners() {
		if owner.reports != nil {
			_ = owner.certificateNative().EraseMaster()
		}
	}
}

// certificateNonVoter is true only when the committed directory says so
// for this key: its settled entry is not a voter (a demoted voter is
// ready again), or it was removed. A
// promotion or demotion in progress, or an unreadable topology, keeps the
// key.
func certificateNonVoter(d membership.Directory, key [32]byte) bool {
	for _, e := range d.Entries {
		k, err := identity.ParseKey(e.CurrentPeer().Key)
		if err != nil || k != key {
			continue
		}
		if (e.Phase == membership.Ready || e.Phase == membership.Active) && !e.Peer.Voter && e.Job.Pending == nil {
			return true
		}
		return !d.MemberKey(key) && !d.ReplicationKey(key)
	}
	return false
}
func (r *Runtime) certificateRead(ctx context.Context, v certstore.Certificate, host string) (control.CertificateMaterialRead, error) {
	view, err := r.physicalOwners()[0].currentView(ctx)
	if err != nil {
		return control.CertificateMaterialRead{}, err
	}
	if view.Local {
		return control.CertificateMaterialRead{}, sfcp.ErrAdmission
	}
	projection, err := r.controlPolicy.ProjectResources(view.State)
	if err != nil {
		return control.CertificateMaterialRead{}, err
	}
	keys := make([]string, 0, len(projection.Goals))
	for key := range projection.Goals {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	var failure error
	for _, key := range keys {
		g := projection.Goals[key]
		if g.Goal.Owner != r.Identity.Public || g.Ingress == nil {
			continue
		}
		o := view.State.Object(key)
		q := control.CertificateMaterialRead{Schema: 2, Cluster: r.controlPolicy.Cluster, Consumer: r.Identity.Public, Certificate: v.Digest(), ID: v.Metadata.ID, Host: host, Source: deployment.ObjectRef{Key: key, Generation: o.Generation, Revision: o.Revision}, At: time.Now().Unix()}
		if _, err := r.controlPolicy.CertificateMaterial(view.State, r.commandIdentity().Public, q, q.At); err == nil {
			return q, nil
		} else if !errors.Is(err, access.ErrDenied) {
			failure = errors.Join(failure, err)
		}
	}
	if failure != nil {
		return control.CertificateMaterialRead{}, failure
	}
	return control.CertificateMaterialRead{}, ingress.ErrCertificateWithdrawn
}
func (r *Runtime) ingressStoreCertificate(ctx context.Context, v certstore.Certificate, host string, previous []ingress.CertificateVersion) (ingress.CertificateVersion, error) {
	q, err := r.certificateRead(ctx, v, host)
	if err != nil {
		return ingress.CertificateVersion{}, err
	}
	return r.openStoreCertificate(ctx, v, q, previous)
}

// openStoreCertificate gets K for one authorized read (derived here on a
// voter, else from a voter) and opens the pair while the read stays allowed.
func (r *Runtime) openStoreCertificate(ctx context.Context, v certstore.Certificate, q control.CertificateMaterialRead, previous []ingress.CertificateVersion) (ingress.CertificateVersion, error) {
	if cached, ok := reusableIngressCertificate(v, previous); ok {
		return cached, nil
	}
	native := r.certificateNative()
	view, err := r.physicalOwners()[0].currentView(ctx)
	if err != nil || view.Local {
		return ingress.CertificateVersion{}, sfcp.ErrAdmission
	}
	key, err := r.voterKey(view.State, v.Metadata.ID)
	if errors.Is(err, storage.ErrMissing) {
		key, err = r.askVoters(ctx, view.State, certificateRequest{Read: &q}, v.Digest())
	}
	defer clear(key)
	if err != nil || len(key) != 32 {
		return ingress.CertificateVersion{}, certstore.ErrCertificate
	}
	latest, err := r.physicalOwners()[0].currentView(ctx)
	if err != nil {
		return ingress.CertificateVersion{}, err
	}
	if latest.Local {
		return ingress.CertificateVersion{}, sfcp.ErrAdmission
	}
	current, err := r.controlPolicy.CertificateMaterial(latest.State, r.commandIdentity().Public, q, time.Now().Unix())
	if errors.Is(err, access.ErrDenied) || err == nil && current.Digest() != v.Digest() {
		return ingress.CertificateVersion{}, ingress.ErrCertificateWithdrawn
	}
	if err != nil {
		return ingress.CertificateVersion{}, err
	}
	pair, err := certstore.Open(v, key)
	if err != nil {
		return ingress.CertificateVersion{}, err
	}
	final, err := r.physicalOwners()[0].currentView(ctx)
	if err != nil {
		return ingress.CertificateVersion{}, err
	}
	if final.Local {
		return ingress.CertificateVersion{}, sfcp.ErrAdmission
	}
	if current, err := r.controlPolicy.CertificateMaterial(final.State, r.commandIdentity().Public, q, time.Now().Unix()); err != nil || current.Digest() != v.Digest() {
		if err != nil && !errors.Is(err, access.ErrDenied) {
			return ingress.CertificateVersion{}, err
		}
		if catalog, e := r.controlPolicy.Certificates(final.State); e == nil {
			if e = native.Sweep(catalog, time.Now().Unix()); e != nil {
				return ingress.CertificateVersion{}, errors.Join(ingress.ErrCertificateWithdrawn, e)
			}
		}
		return ingress.CertificateVersion{}, ingress.ErrCertificateWithdrawn
	}
	return ingress.CertificateVersion{Digest: v.Digest(), Fingerprint: v.Metadata.ID, NotAfter: v.Metadata.NotAfter, Certificate: pair}, nil
}
func (r *Runtime) ingressCertificates(ctx context.Context, host string, previous []ingress.CertificateVersion) ([]ingress.CertificateVersion, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(r.ctx, cancel)
	defer stop()
	if ctx.Err() != nil || !r.life.TryRLock() {
		return nil, sfcp.ErrAdmission
	}
	defer r.life.RUnlock()
	if r.closed || r.reports == nil {
		return nil, sfcp.ErrAdmission
	}
	view, err := r.physicalOwners()[0].currentView(ctx)
	if err != nil || view.Local {
		return nil, sfcp.ErrAdmission
	}
	catalog, err := r.controlPolicy.Certificates(view.State)
	if err != nil {
		return nil, err
	}
	at := time.Now().Unix()
	selected := catalog.LookupHost(host, at)
	if len(selected) == 0 {
		return nil, ingress.ErrCertificateWithdrawn
	}
	var result []ingress.CertificateVersion
	var failure error
	for _, v := range selected {
		certificate, err := r.ingressStoreCertificate(ctx, v, host, previous)
		if err != nil {
			failure = errors.Join(failure, err)
			continue
		}
		result = append(result, certificate)
	}
	if failure != nil {
		return nil, failure
	}
	return result, nil
}

// registryCertificate returns the store pair for a registry run's authority
// host, preferring ECDSA, or ErrCertificateWithdrawn when the host has none.
// current skips opening when the run already serves the chosen ID.
func (r *Runtime) registryCertificate(ctx context.Context, row registryOwnerRecord, current [32]byte) (ingress.CertificateVersion, bool, error) {
	view, err := r.physicalOwners()[0].currentView(ctx)
	if err != nil || view.Local {
		return ingress.CertificateVersion{}, false, sfcp.ErrAdmission
	}
	catalog, err := r.controlPolicy.Certificates(view.State)
	if err != nil {
		return ingress.CertificateVersion{}, false, err
	}
	host := control.RegistryHost(row.Spec.Authority)
	selected := catalog.LookupHost(host, time.Now().Unix())
	if len(selected) == 0 {
		return ingress.CertificateVersion{}, false, ingress.ErrCertificateWithdrawn
	}
	v := selected[0]
	if [32]byte(v.Metadata.ID) == current {
		return ingress.CertificateVersion{}, false, nil
	}
	q := control.CertificateMaterialRead{Schema: 2, Cluster: r.controlPolicy.Cluster, Consumer: r.Identity.Public, Certificate: v.Digest(), ID: v.Metadata.ID, Host: host, Registry: &control.RegistryCertificateSource{Tenant: row.Spec.Tenant, ID: row.Spec.ID, Generation: row.Generation}, At: time.Now().Unix()}
	pair, err := r.openStoreCertificate(ctx, v, q, nil)
	return pair, err == nil, err
}

// Called from the existing finite reconciliation loop. No background worker or
// alternate raft protocol is created for certificate expiry.
func (r *Runtime) reconcileCertificates(ctx context.Context, view cluster.View) error {
	if r.reports == nil {
		return nil
	}
	catalog, err := r.controlPolicy.Certificates(view.State)
	if err != nil {
		return err
	}
	now := time.Now().Unix()
	if err = r.certificateNative().Sweep(catalog, now); err != nil {
		return err
	}
	if r.historicalOwner {
		return nil
	}
	_, expired, err := catalog.Expire(now)
	if err != nil || len(expired) == 0 {
		return err
	}
	p, err := r.controlPolicy.Current(view.State)
	if err != nil || !p.Issuer(r.commandIdentity().Public).Enabled {
		return err
	}
	report := control.CertificateExpiryReport{Schema: 1, Cluster: p.Cluster, Reporter: r.commandIdentity().Public, RootRevision: view.State.Object(control.CertificatesKey).Revision, Epoch: view.State.ModuleEpoch(), At: uint64(now)}
	report.Signature = ed25519.Sign(r.commandIdentity().Private, control.CertificateExpiryBytes(report))
	raw, _ := json.Marshal(report)
	reply, err := r.appCall(ctx, "certificate-expiry-report", raw)
	if err != nil {
		return err
	}
	if reply.Committed == nil || reply.Committed.Result.Code != state.Applied {
		return access.ErrConflict
	}
	return nil
}

// The existing pair originates only from Manager's already validated private
// cache. Current quorum catalog/consumer authorization is checked before this
// helper is called; a full public certificate digest, not the ID alone,
// pins reuse and avoids repeating wallet key unwrapping for unchanged material.
func reusableIngressCertificate(v certstore.Certificate, previous []ingress.CertificateVersion) (ingress.CertificateVersion, bool) {
	for _, p := range previous {
		if p.Digest == v.Digest() && p.Digest != ([32]byte{}) && p.Fingerprint == v.Metadata.ID && p.NotAfter == v.Metadata.NotAfter && p.Certificate.PrivateKey != nil {
			return p, true
		}
	}
	return ingress.CertificateVersion{}, false
}
