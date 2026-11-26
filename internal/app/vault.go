// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"path/filepath"
	"strings"
	"time"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/config"
	"github.com/jay94ks/mydcd/internal/identity"
	"github.com/jay94ks/mydcd/internal/reconcile"
	"github.com/jay94ks/mydcd/internal/schema"
	"github.com/jay94ks/mydcd/internal/secrets"
	"github.com/jay94ks/mydcd/internal/userauth"
)

type vaultBackend struct {
	config   config.VaultBackend
	provider interface {
		Fetch(context.Context, string, secrets.Reference) (secrets.Fetched, error)
		Close()
	}
	verifier *secrets.Vault
	writer   *secrets.Writer
}

func vaultBackendKey(realm, profile string) string { return realm + "/" + profile }
func (r *Runtime) openVaults(c config.Node) error {
	r.vaultBackends = map[string]*vaultBackend{}
	if len(c.Vaults) > 64 {
		return errors.New("managed local Vault installation required")
	}
	for _, local := range c.Vaults {
		key := vaultBackendKey(local.Realm, local.Profile)
		if r.vaultBackends[key] != nil || !local.Values && !local.Verifiers || strings.HasPrefix(local.Prefix, "system/credentials") {
			return errors.New("invalid or duplicate local Vault role/scope")
		}
		if local.Mode == "local-file" {
			if !local.Values || local.Verifiers || local.Address != "" || local.Mount != "" || local.Namespace != "" || local.CAFile != "" || local.TokenFile != "" {
				return secrets.ErrProvider
			}
			provider, err := secrets.OpenFiles(local.Profile, local.Root, local.Prefix, 128<<10)
			if err != nil {
				return secrets.ErrProvider
			}
			r.vaultBackends[key] = &vaultBackend{config: local, provider: provider}
			continue
		}
		if local.Mode != "" && local.Mode != "vault" || local.Root != "" {
			return secrets.ErrProvider
		}
		profile, err := secrets.InstalledProfile(local.Profile, local.Address, local.Mount, local.Prefix, local.Namespace, local.CAFile, local.TokenFile)
		if err != nil {
			return secrets.ErrProvider
		}
		provider, err := secrets.NewVault(profile)
		if err != nil {
			return secrets.ErrProvider
		}
		digest := sha256.Sum256([]byte(key))
		writer, err := secrets.OpenWriter(filepath.Join(c.Node.StateDir, "vault", fmt.Sprintf("%x.db", digest)), provider)
		if err != nil {
			provider.Close()
			return err
		}
		r.vaultBackends[key] = &vaultBackend{config: local, provider: provider, verifier: provider, writer: writer}
	}
	return nil
}
func (r *Runtime) writeVault(ctx context.Context, session access.Session, q userauth.SecretRequest) (secrets.WriteObservation, error) {
	permitRequest := control.VaultWritePermitRequest{Session: session, Realm: q.Realm, ID: q.ID, Mode: q.Mode, At: time.Now().Unix()}
	raw, _ := json.Marshal(permitRequest)
	// No native/provider lock is held while obtaining a latest quorum permit.
	// A node that just restarted learns the leader from its first heartbeat;
	// until then the permit would fail and read as a denial.
	r.awaitAppLeader(ctx)
	reply, err := r.appCall(ctx, "vault-write-permit", raw)
	if err != nil {
		// Only the realm and write ID are logged; nothing of the values.
		log.Printf("vault write %s/%s: permit: %v", q.Realm, q.ID, err)
		return secrets.WriteObservation{}, secrets.ErrProvider
	}
	permit, err := schema.Decode[control.VaultWritePermit](reply.Data)
	if err != nil || permit.Cluster != r.controlPolicy.Cluster || permit.Realm != q.Realm || permit.Record.Request.ID != q.ID || permit.Observer.Key != r.Identity.Public {
		log.Printf("vault write %s/%s: permit does not match this request or node (decode: %v)", q.Realm, q.ID, err)
		return secrets.WriteObservation{}, secrets.ErrProvider
	}
	r.life.RLock()
	defer r.life.RUnlock()
	if r.closed || r.ctx.Err() != nil {
		log.Printf("vault write %s/%s: daemon is stopping", q.Realm, q.ID)
		return secrets.WriteObservation{}, secrets.ErrProvider
	}
	backend := r.vaultBackends[vaultBackendKey(q.Realm, permit.Record.Request.Profile)]
	if backend == nil || backend.writer == nil || permit.Record.Request.Kind == secrets.ValueWrite && !backend.config.Values || permit.Record.Request.Kind == secrets.VerifierWrite && !backend.config.Verifiers {
		configured := make([]string, 0, len(r.vaultBackends))
		for k := range r.vaultBackends {
			configured = append(configured, k)
		}
		log.Printf("vault write %s/%s: no local Vault backend %q for this %s write (configured: %v)", q.Realm, q.ID, vaultBackendKey(q.Realm, permit.Record.Request.Profile), permit.Record.Request.Kind, configured)
		return secrets.WriteObservation{}, secrets.ErrProvider
	}
	if q.Mode == "execute" && permit.Record.Request.Kind == secrets.VerifierWrite && permit.Record.Request.Protected {
		if _, err := identity.RestorePasswordVerifier(q.Values["verifier"]); err != nil {
			log.Printf("vault write %s/%s: bad password verifier input", q.Realm, q.ID)
			return secrets.WriteObservation{}, secrets.ErrProvider
		}
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(r.ctx, cancel)
	defer stop()
	w := permit.Record
	receipt, callErr := backend.writer.Apply(ctx, permit.Cluster, q.Realm, w, q.Values, q.Mode == "recover")
	if callErr != nil {
		log.Printf("vault write %s/%s: %s: %v", q.Realm, q.ID, q.Mode, callErr)
	}
	fact := secrets.WriteObservation{Cluster: permit.Cluster, Tenant: q.Realm, Request: w.Request, Generation: w.Generation, ExpectedObjectRevision: w.ExpectedObjectRevision, Writer: w.Writer, Operation: w.Journal.LastID, Outcome: reconcile.EffectUnknown}
	if permit.Observer != w.Writer {
		fact.Observer = permit.Observer
	}
	if errors.Is(callErr, secrets.ErrNotCovered) && fact.Observer == (secrets.WriteProfile{}) {
		// Refused before any Put: settle it so the group is not left pending.
		fact.Outcome = reconcile.EffectNotApplied
	}
	if callErr == nil {
		fact.Outcome = reconcile.EffectApplied
		fact.ProviderRevision = receipt.Revision
		if w.Request.Kind == secrets.VerifierWrite && w.Request.Protected {
			fact.VerifierRef, callErr = receipt.VerifierReference()
			if callErr != nil {
				fact.Outcome = reconcile.EffectUnknown
				fact.ProviderRevision = 0
			}
		}
	}
	fact.Signature = ed25519.Sign(r.Identity.Private, secrets.WriteObservationBytes(fact))
	return fact, callErr
}
