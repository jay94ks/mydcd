// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/jay94ks/mydcd/internal/certstore"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/web/mydc"
	"github.com/jay94ks/mydcd/internal/web/store"
)

// The cluster's ACME HTTP-01 responder setting (devel/design
// certificate-store §8). mydc-web fills it with its own advertised responder
// address once it runs: the automation account must be delegated the
// set-acme-responder action (docs/cli/domain.md). It never clears the
// setting; an administrator does with `mydc domain acme-responder clear`.

// acmeResponderRetry spaces attempts while the setting is not ours yet.
const acmeResponderRetry = time.Minute

type acmeResponderState struct {
	mu    sync.Mutex
	done  bool
	tried time.Time
}

// acmeResponderSync makes the cluster setting equal to the advertised
// address, as ws (the watcher's automation session). It stops trying once
// the setting matches.
func (s *Server) acmeResponderSync(ctx context.Context, ws *webSession) {
	address, ok := certstore.NormalizeResponder(s.opt.ACMEAdvertise)
	if !ok {
		return
	}
	st := &s.acmeResponder
	st.mu.Lock()
	due := !st.done && s.now().Sub(st.tried) >= acmeResponderRetry
	if due {
		st.tried = s.now()
	}
	st.mu.Unlock()
	if !due {
		return
	}
	err := ws.do(ctx, func(ctx context.Context, c mydc.Conn) error {
		page, err := c.QueryCertificates(ctx, control.CertificateQuery{})
		if err != nil {
			return err
		}
		if page.ACMEResponder != nil && page.ACMEResponder.Address == address {
			st.mu.Lock()
			st.done = true
			st.mu.Unlock()
			return nil
		}
		raw, _ := json.Marshal(control.ACMEResponderChange{Address: address})
		ch := mydc.Change{Schema: 1, Action: mydc.ActionSetACMEResponder, Principal: ws.user.ID, Expected: page.Revision, Payload: raw}
		who, err := c.Whoami(ctx)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(append([]byte(mydc.ActionSetACMEResponder+"\x00"), raw...))
		o := &store.Op{ID: newOpID(), User: ws.user.ID, Username: ws.user.Username, Action: mydc.ActionSetACMEResponder, Target: address, Digest: hex.EncodeToString(sum[:])}
		if _, err := s.sendStored(ctx, c, o, ch, who.RootFor(mydc.ActionSetACMEResponder)); err != nil {
			return err
		}
		if o.State == store.OpApplied {
			st.mu.Lock()
			st.done = true
			st.mu.Unlock()
		}
		return nil
	})
	if err != nil {
		s.log.Warn("acme responder: set", "err", err)
	}
}

// GET /acme/responder → {address?, setAt?, setBy?, listening, advertised?}.
// address is the cluster setting; listening says this daemon serves the
// responder; advertised is the address it fills in.
func (s *Server) handleACMEResponder(w http.ResponseWriter, r *http.Request, ws *webSession) {
	if !s.requireAdmin(w, r, ws) {
		return
	}
	ctx, cancel := s.callCtx(r)
	defer cancel()
	var page control.CertificatePage
	if err := ws.do(ctx, func(ctx context.Context, c mydc.Conn) error {
		var err error
		page, err = c.QueryCertificates(ctx, control.CertificateQuery{})
		return err
	}); err != nil {
		s.writeBackendError(w, ws, err)
		return
	}
	out := map[string]any{"listening": s.opt.ACMEHTTP01}
	if a, ok := certstore.NormalizeResponder(s.opt.ACMEAdvertise); ok {
		out["advertised"] = a
	}
	if r := page.ACMEResponder; r != nil {
		out["address"], out["setBy"], out["setAt"] = r.Address, r.SetBy, time.Unix(r.SetAt, 0).UTC().Format(time.RFC3339)
	}
	writeJSON(w, http.StatusOK, out)
}
