// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"log"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/certstore"
	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/secrets"
	"github.com/jay94ks/seafield/internal/sfcp"
)

var ErrApprovalUnknown = errors.New("original approval submission outcome unknown")

// SecretRequest exists only on the dedicated sensitive input purpose. It is
// never a UserOperation, metadata document, raft payload, or retained intent.
// Its public ID names an already committed/dispatched original provider write.
type SecretRequest struct {
	Certificate     *CertificateInput             `json:",omitempty"`
	VPSCredential   *VPSCredentialInput           `json:",omitempty"`
	Selection       *control.AppApprovalSelection `json:",omitempty"`
	Schema          uint8
	Realm, ID, Mode string
	Nonce           [32]byte
	Values          map[string][]byte      `json:",omitempty"`
	Target          *secrets.Target        `json:",omitempty"`
	Password        []byte                 `json:",omitempty"`
	Origin          *control.UserOperation `json:",omitempty"`
}

func validSecretRequest(q SecretRequest) bool {
	if q.VPSCredential != nil || q.Mode == "vps-credential" {
		return q.Schema == 1 && q.Nonce != ([32]byte{}) && q.Mode == "vps-credential" && q.VPSCredential != nil && validVPSCredentialInput(*q.VPSCredential) && q.ID == q.VPSCredential.Request && q.Certificate == nil && q.Realm == "" && q.Values == nil && q.Target == nil && q.Password == nil && q.Origin == nil && q.Selection == nil
	}
	if q.Certificate != nil || q.Mode == "certificate" {
		return q.Schema == 1 && q.Nonce != ([32]byte{}) && q.Mode == "certificate" && q.Certificate != nil && validCertificateInput(*q.Certificate) && q.ID == q.Certificate.Request && q.Realm == "" && q.Values == nil && q.Target == nil && q.Password == nil && q.Origin == nil && q.Selection == nil
	}
	if q.Selection != nil && (q.Origin == nil || !q.Selection.Valid()) {
		return false
	}
	if q.Mode == "approve" {
		return q.Schema == 1 && q.Nonce != ([32]byte{}) && q.Target != nil && q.ID == q.Target.ApprovalID && q.Realm == q.Target.Realm && q.Values == nil && len(q.Password) <= 1024
	}
	if q.Target != nil || q.Password != nil || q.Origin != nil || q.Selection != nil {
		return false
	}
	if q.Schema != 1 || q.Nonce == ([32]byte{}) || q.ID == "" || q.Mode != "execute" && q.Mode != "recover" || q.Mode == "recover" && q.Values != nil || len(q.Values) > 128 {
		return false
	}
	total := 0
	for key, value := range q.Values {
		if key == "" || len(key) > 128 {
			return false
		}
		total += len(value)
	}
	return total <= 16<<10 && (q.Mode != "execute" || len(q.Values) > 0)
}
func (s Service) secretInput(ctx context.Context, conn *sfcp.Session, stream sfcp.Stream, frame sfcp.Frame) error {
	defer clear(frame.Fields[0].Value)
	if frame.Kind != 1 || frame.Purpose != sfcp.SecretInput || s.VaultWriter == nil && s.VaultApprover == nil && s.CertificateWriter == nil && s.VPSCredentialSealer == nil {
		return sfcp.ErrAdmission
	}
	var envelope Envelope
	if strict(frame.Fields[0].Value, &envelope) != nil {
		return sfcp.ErrFrame
	}
	defer clear(envelope.Body)
	var q SecretRequest
	if strict(envelope.Body, &q) != nil {
		return sfcp.ErrFrame
	}
	defer func() {
		for _, value := range q.Values {
			clear(value)
		}
		clear(q.Password)
		if q.Certificate != nil {
			clear(q.Certificate.Chain)
			clear(q.Certificate.Key)
		}
		if q.VPSCredential != nil {
			clear(q.VPSCredential.AccessKey)
			clear(q.VPSCredential.SecretKey)
		}
	}()
	if q.Mode == "certificate" || q.Mode == "vps-credential" {
		if err := streamEOF(stream); err != nil {
			return err
		}
	}
	digest := sha256.Sum256(frame.Fields[0].Value)
	reply := Reply{Schema: 1, Code: "denied", Node: s.Self.Actor()}
	verified := bytes.Equal(digest[:], frame.Fields[1].Value) && envelope.Relay == nil && envelope.Session != nil && envelope.Session.Key == [32]byte(conn.Peer().Key) && validSecretRequest(q) && access.VerifyRequest(*envelope.Session, conn.Challenge(), envelope.Body, envelope.Signature) == nil
	if !verified {
		log.Printf("secret input %s/%s (%s) refused: the signed request did not verify on this connection", q.Realm, q.ID, q.Mode)
	}
	if verified {
		var view cluster.View
		var err error
		if q.Mode == "certificate" || q.Mode == "vps-credential" {
			// Keep private input on this exact provider. Freshness comes from
			// the quorum status receipt and this provider's durable prefix,
			// rather than forwarding certificate material to the leader.
			view, err = s.authenticationView(ctx)
			if err == nil && view.Local {
				err = sfcp.ErrAdmission
			}
		} else {
			view, err = s.Engine.Read(ctx, false)
		}
		if allowed := err == nil && (s.Enabled == nil || s.Enabled(view.State)) && s.nodeSecretAllowed(view.State, q); !allowed {
			// Names only: the realm, the write ID and the mode. A refusal here is
			// before any provider call, so it is also never an unknown write.
			log.Printf("secret input %s/%s (%s) refused on this node: view error %v, enabled %v, node allowed %v", q.Realm, q.ID, q.Mode, err, err == nil && (s.Enabled == nil || s.Enabled(view.State)), err == nil && s.nodeSecretAllowed(view.State, q))
			raw, marshalErr := json.Marshal(reply)
			if marshalErr != nil {
				return marshalErr
			}
			return sfcp.WriteFrame(stream, sfcp.Frame{Purpose: sfcp.SecretInput, Kind: 2, Request: frame.Request, Fields: []sfcp.Field{{Tag: 1, Required: true, Value: raw}, {Tag: 2, Required: true, Value: digest[:]}}})
		}
		if q.Mode == "vps-credential" && s.VPSCredentialSealer != nil {
			v, err := s.VPSCredentialSealer(ctx, *envelope.Session, *q.VPSCredential)
			if err == nil {
				reply.Code = "ok"
				reply.VPSCredential = &v
			} else {
				reply.Code = "denied"
			}
		} else if q.Mode == "certificate" && s.CertificateWriter != nil {
			v, err := s.CertificateWriter(ctx, *envelope.Session, *q.Certificate)
			if err == nil {
				reply.Code = "ok"
				reply.Certificate = &v
			} else if errors.Is(err, access.ErrConflict) || errors.Is(err, certstore.ErrConflict) {
				reply.Code = "conflict"
			} else if errors.Is(err, access.ErrDenied) || errors.Is(err, sfcp.ErrAdmission) || errors.Is(err, certstore.ErrCertificate) {
				reply.Code = "denied"
			} else {
				reply.Code = "unknown"
			}
		} else if q.Mode == "approve" && s.VaultApprover != nil {
			source, err := conn.CredentialSource()
			if err == nil {
				approval, err := s.VaultApprover(ctx, *envelope.Session, q, source)
				if err == nil {
					reply.Code = "ok"
					reply.VaultApproval = &approval
				} else if errors.Is(err, ErrApprovalUnknown) {
					reply.Code = "unknown"
				}
			}
		} else if q.Mode != "approve" && s.VaultWriter != nil {
			observation, err := s.VaultWriter(ctx, *envelope.Session, q)
			if observation.Operation != 0 {
				reply.VaultObservation = &observation
			}
			if err == nil {
				reply.Code = "ok"
			} else if observation.Operation != 0 {
				reply.Code = "unknown"
			}
		}
	}
	raw, err := json.Marshal(reply)
	if err != nil {
		return err
	}
	return sfcp.WriteFrame(stream, sfcp.Frame{Purpose: sfcp.SecretInput, Kind: 2, Request: frame.Request, Fields: []sfcp.Field{{Tag: 1, Required: true, Value: raw}, {Tag: 2, Required: true, Value: digest[:]}}})
}

// WriteVault never redirects or relays private input. A lost/unknown response
// requires an explicit mode=recover request without private values.
func (c Client) WriteVault(ctx context.Context, target sfcp.Peer, session access.Session, q SecretRequest) (Reply, error) {
	if c.Verify(session) != nil {
		return Reply{}, sfcp.ErrAdmission
	}
	q.Schema = 1
	if _, err := rand.Read(q.Nonce[:]); err != nil {
		return Reply{}, err
	}
	if !validSecretRequest(q) {
		return Reply{}, sfcp.ErrAdmission
	}
	body, err := json.Marshal(q)
	if err != nil {
		return Reply{}, err
	}
	defer clear(body)
	reply, _, err := c.exchangePurpose(ctx, target, func(conn *sfcp.Session) (Envelope, error) {
		return Envelope{Body: body, Session: &session, Signature: ed25519.Sign(c.Self.Private, access.RequestBytes(session, conn.PeerChallenge(), body))}, nil
	}, false, 1, sfcp.SecretInput)
	return reply, err
}

func (c Client) ApproveVault(ctx context.Context, target sfcp.Peer, session access.Session, want secrets.Target, password []byte) (Reply, error) {
	return c.WriteVault(ctx, target, session, SecretRequest{Realm: want.Realm, ID: want.ApprovalID, Mode: "approve", Target: &want, Password: password})
}
