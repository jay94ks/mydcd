// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/jay94ks/seafield/internal/certstore"
	"github.com/jay94ks/seafield/internal/web/sfc"
	"github.com/jay94ks/seafield/internal/web/store"
)

// The store step of a certificate order (REQ-21,
// docs/reference/certificate-store.md). The issued chain and the new
// private key go once to sfcd's protected input as the user who started
// the order, which seals the key and returns a public receipt; then:
//
//  1. Sign the put-certificate original with that receipt (no key) and
//     store it as that user's op acme-<order>.
//  2. Only then send it.
//  3. A lost reply is settled only by sending the same original again (2 s,
//     5 s, 10 s later). When the outcome is still unknown the order ends
//     store-unknown; the op keeps the original, so its result can be read
//     and it can be resumed.

// acmeStoreRetry is the default wait before each resend after a lost reply.
var acmeStoreRetry = []time.Duration{2 * time.Second, 5 * time.Second, 10 * time.Second}

func acmeStoreOpID(order string) string { return "acme-" + order }

// acmeStore returns the stored certificate's ID, or an order error code and
// the error. A newly issued chain has a fresh leaf, so its ID is never
// already stored.
func (s *Server) acmeStore(ctx context.Context, ws *webSession, order string, chainPEM, keyPEM []byte) (string, string, error) {
	o := &store.Op{ID: acmeStoreOpID(order), User: ws.user.ID, Username: ws.user.Username, Action: sfc.ActionPutCertificate}
	var op sfc.SignedOp
	var receipt certstore.Certificate
	err := ws.do(ctx, func(ctx context.Context, c sfc.Conn) error {
		var err error
		if receipt, op, err = certPrepare(ctx, c, ws.user.ID, chainPEM, keyPEM, certRequestID(o.ID), nil); err != nil {
			return err
		}
		o.Target = receipt.Metadata.ID.String()
		reqID, err := sfc.OperationID(op)
		if err != nil {
			return err
		}
		h := sha256.Sum256(op)
		now := s.now()
		o.RequestID, o.Signed, o.Digest, o.State, o.SubmittedAt, o.UpdatedAt = reqID, op, hex.EncodeToString(h[:]), store.OpPending, now, now
		existing, err := s.opt.Store.CreateOp(o)
		if err != nil {
			return err
		}
		if existing != nil {
			// Order IDs are unique per certificate run; a row here means
			// this order already prepared one. Never sign a second original.
			return fmt.Errorf("operation %s already exists", o.ID)
		}
		return nil
	})
	if err != nil {
		// Nothing was sent.
		return "", "store-prepare", err
	}

	retry := s.acme.storeRetry
	if retry == nil {
		retry = acmeStoreRetry
	}
	for i := 0; ; i++ {
		var res sfc.Result
		var sendErr error
		_ = ws.do(ctx, func(ctx context.Context, c sfc.Conn) error {
			res, sendErr = c.Submit(ctx, op)
			return nil
		})
		settleSubmit(o, res, sendErr, s.now())
		if o.State != store.OpUnknown || i == len(retry) || ctx.Err() != nil {
			break
		}
		// The row stays pending (shown as unknown) until the tries end, so
		// one notice is made for the final state, not one per try.
		select {
		case <-ctx.Done():
		case <-time.After(retry[i]):
		}
	}
	if err := s.saveOp(o); err != nil {
		s.log.Error("update certificate op", "op", o.ID, "err", err)
	}

	switch o.State {
	case store.OpApplied:
	case store.OpUnknown:
		return "", "store-unknown", fmt.Errorf("the certificate store did not answer (%s); operation %s keeps the signed original, read its result", o.ErrorCode, o.ID)
	case store.OpRejected:
		return "", "store-rejected", fmt.Errorf("sfcd refused put-certificate: %s", o.ErrorCode)
	default:
		return "", "store-failed", fmt.Errorf("put-certificate result code %d", o.Result.Code)
	}

	return receipt.Metadata.ID.String(), "", nil
}
