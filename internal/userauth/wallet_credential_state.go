// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cliprofile"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/wallet"
)

func (s *CredentialStore) PrivateKey(name string) (ed25519.PrivateKey, error) {
	if s == nil || !s.ready {
		return nil, wallet.ErrWallet
	}
	entry, err := s.disk.Get(name)
	if err != nil {
		return nil, err
	}
	defer clear(entry.Seed[:])
	return ed25519.NewKeyFromSeed(entry.Seed[:]), nil
}

func (s *CredentialStore) record(c Client) (loginCredential, []byte, error) {
	if s == nil || !s.ready || !cliprofile.ValidUsername(c.Username) {
		return loginCredential{}, nil, ErrLoginRequired
	}
	name := loginRecordName(c.Cluster, c.Profile(), c.Username)
	raw, err := s.disk.Record(name)
	if err != nil {
		return loginCredential{}, nil, err
	}
	r, match, err := decodeLogin(c, name, raw)
	if err != nil || !match || r.Closed {
		clear(raw)
		return loginCredential{}, nil, ErrPrivateState
	}
	return r, raw, nil
}

func (s *CredentialStore) writeRecord(c Client, original []byte, r loginCredential) error {
	if s == nil || !s.ready {
		return wallet.ErrWallet
	}
	name := loginRecordName(c.Cluster, c.Profile(), c.Username)
	raw, err := json.Marshal(r)
	if err != nil {
		return err
	}
	defer clear(raw)
	if _, match, err := decodeLogin(c, name, raw); err != nil || !match {
		return ErrPrivateState
	}
	expected := sha256.Sum256(original)
	if err := s.disk.PutRecord(name, raw, &expected); err != nil {
		return err
	}
	if err := s.disk.Save(s.password); err != nil {
		s.ready = false
		return err
	}
	readback, err := s.disk.ReadBackRecord(name, s.password)
	defer clear(readback)
	if err != nil {
		s.ready = false
		return err
	}
	if !bytes.Equal(readback, raw) {
		s.ready = false
		return ErrPrivateState
	}
	return nil
}

func (s *CredentialStore) saveSession(c Client, session access.Session, tenant string) error {
	if c.Self == nil || c.Verify(session) != nil || tenant != "" && !safeID(tenant) {
		return ErrPrivateState
	}
	r, raw, err := s.record(c)
	if err != nil {
		return err
	}
	defer clear(raw)
	if !sameSession(r.Session, session) || r.Pending != nil {
		return ErrPrivateState
	}
	r.Tenant = tenant
	return s.writeRecord(c, raw, r)
}

func (s *CredentialStore) stageLogout(c Client, op control.UserOperation) error {
	// Public StageLogout already verified the original signed self-revocation.
	r, raw, err := s.record(c)
	if err != nil {
		return err
	}
	defer clear(raw)
	if r.Pending != nil || !sameSession(r.Session, op.Session) || c.Self == nil || r.Session.Key != c.Self.Public {
		return ErrPrivateState
	}
	r.Pending = &op
	return s.writeRecord(c, raw, r)
}

func (s *CredentialStore) settleLogout(c Client, op control.UserOperation, result state.Result) error {
	if result.Index == 0 || result.Code == state.Expired || op.VerifyOriginal(c.Cluster) != nil {
		return ErrPrivateState
	}
	r, raw, err := s.record(c)
	if err != nil {
		return err
	}
	defer clear(raw)
	if r.Pending == nil || r.Session.User != op.Session.User || !bytes.Equal(control.OperationBytes(*r.Pending), control.OperationBytes(op)) || !bytes.Equal(r.Pending.Signature, op.Signature) {
		return ErrPrivateState
	}
	r.Pending = nil
	if result.Code == state.Applied && sameSession(r.Session, op.Session) {
		r.Closed = true
	}
	// A settled current logout removes this account from candidates. Its key and
	// signed provenance remain; another account or a newer login is never erased.
	return s.writeRecord(c, raw, r)
}
