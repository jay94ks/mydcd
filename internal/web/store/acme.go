// SPDX-License-Identifier: Apache-2.0

package store

import (
	"fmt"
	"time"

	bolt "go.etcd.io/bbolt"
)

// Certificate automation rows (devel/design/web-acme-plan.md). The ACME
// account key is in a sealed file; certificate private keys go only to the
// cluster certificate store and never here. The public chain is
// public and kept for download and revocation.

// ACMEAccount is an account at a certificate authority.
type ACMEAccount struct {
	ID        string    `json:"id"`
	CA        string    `json:"ca"`
	Email     string    `json:"email,omitempty"`
	URL       string    `json:"url"`
	EAB       bool      `json:"eab"`
	AgreedAt  time.Time `json:"agreedAt"`
	CreatedBy string    `json:"createdBy"`
	CreatedAt time.Time `json:"createdAt"`
}

// ACMECert is a certificate definition and its current public state.
type ACMECert struct {
	Name        string    `json:"name"` // the definition's own name (the store has no names)
	Names       []string  `json:"names"`
	Account     string    `json:"account"`
	KeyTypes    []string  `json:"keyTypes"`
	AutoRenew   bool      `json:"autoRenew"`
	Fingerprint string    `json:"fingerprint,omitempty"`
	KeyType     string    `json:"keyType,omitempty"`
	Issuer      string    `json:"issuer,omitempty"`
	NotBefore   time.Time `json:"notBefore,omitzero"`
	NotAfter    time.Time `json:"notAfter,omitzero"`
	ChainPEM    string    `json:"-"` // public chain, served by its own endpoint
	NextRenew   time.Time `json:"nextRenew,omitzero"`
	NextTry     time.Time `json:"nextTry,omitzero"` // retry after a failed renewal
	// RenewBlocked: when the owner was told that renewal must be done by
	// hand (no delegated account, REQ-9). Once per renewal period.
	RenewBlocked time.Time `json:"renewBlocked,omitzero"`
	Failures     int       `json:"failures"`
	Warned       int       `json:"warned"` // last "days left" warning sent (14, 7, 3)
	LastOrder    string    `json:"lastOrder,omitempty"`
	OwnerID      string    `json:"ownerId"` // who gets renewal notifications
	CreatedBy    string    `json:"createdBy"`
	CreatedAt    time.Time `json:"createdAt"`
	// AutoIssued: made by automatic issuance for an uncovered ingress host.
	AutoIssued *ACMEAutoIssued `json:"autoIssued,omitempty"`
}

// ACMEAutoIssued records which host made an automatic definition.
type ACMEAutoIssued struct {
	Host       string    `json:"host"`
	DetectedAt time.Time `json:"detectedAt"`
}

// ACMEStep is one step of an order.
type ACMEStep struct {
	Name   string    `json:"name"`
	State  string    `json:"state"` // done, failed, skipped
	At     time.Time `json:"at"`
	Detail string    `json:"detail,omitempty"`
}

// ACMEOrder is one issue or renewal run.
type ACMEOrder struct {
	ID          string     `json:"id"`
	Cert        string     `json:"cert"`
	At          time.Time  `json:"at"`
	By          string     `json:"by"` // username, or "자동 갱신"
	UserID      string     `json:"userId,omitempty"`
	Auto        bool       `json:"auto"`
	State       string     `json:"state"` // running, done, failed
	ErrorCode   string     `json:"errorCode,omitempty"`
	Steps       []ACMEStep `json:"steps"`
	KeyType     string     `json:"keyType,omitempty"`
	Fingerprint string     `json:"fingerprint,omitempty"`
	OrphanTXT   []string   `json:"orphanTxt,omitempty"` // TXT records left behind
	// StoreOp is the web op (acme-<order>) holding the signed put-certificate.
	StoreOp   string    `json:"storeOp,omitempty"`
	UpdatedAt time.Time `json:"updatedAt"`
}

func putRow(s *Store, b []byte, k []byte, v any) error {
	return s.db.Update(func(tx *bolt.Tx) error { return putJSON(tx.Bucket(b), k, v) })
}

func getRow(s *Store, b []byte, k []byte, v any) error {
	return s.db.View(func(tx *bolt.Tx) error { return getJSON(tx.Bucket(b), k, v) })
}

// PutACMEAccount stores an account.
func (s *Store) PutACMEAccount(a *ACMEAccount) error {
	return putRow(s, bucketACMEAcct, []byte(a.ID), a)
}

// GetACMEAccount loads an account.
func (s *Store) GetACMEAccount(id string) (*ACMEAccount, error) {
	var a ACMEAccount
	if err := getRow(s, bucketACMEAcct, []byte(id), &a); err != nil {
		return nil, err
	}
	return &a, nil
}

// ListACMEAccounts lists accounts.
func (s *Store) ListACMEAccounts() ([]*ACMEAccount, error) {
	var out []*ACMEAccount
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketACMEAcct).ForEach(func(_, v []byte) error {
			var a ACMEAccount
			if err := jsonUnmarshal(v, &a); err != nil {
				return err
			}
			out = append(out, &a)
			return nil
		})
	})
	return out, err
}

// DeleteACMEAccount removes an account; ErrConflict while a certificate
// uses it.
func (s *Store) DeleteACMEAccount(id string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		if tx.Bucket(bucketACMEAcct).Get([]byte(id)) == nil {
			return ErrNotFound
		}
		used := false
		_ = tx.Bucket(bucketACMECerts).ForEach(func(_, v []byte) error {
			var c ACMECert
			if jsonUnmarshal(v, &c) == nil && c.Account == id {
				used = true
			}
			return nil
		})
		if used {
			return ErrConflict
		}
		return tx.Bucket(bucketACMEAcct).Delete([]byte(id))
	})
}

type acmeCertRow struct {
	ACMECert
	Chain string `json:"chainPem,omitempty"`
}

// CreateACMECert adds a definition; ErrConflict if the name exists.
func (s *Store) CreateACMECert(c *ACMECert) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketACMECerts)
		if b.Get([]byte(c.Name)) != nil {
			return ErrConflict
		}
		return putJSON(b, []byte(c.Name), acmeCertRow{*c, c.ChainPEM})
	})
}

// PutACMECert replaces a definition.
func (s *Store) PutACMECert(c *ACMECert) error {
	return putRow(s, bucketACMECerts, []byte(c.Name), acmeCertRow{*c, c.ChainPEM})
}

// GetACMECert loads a definition.
func (s *Store) GetACMECert(name string) (*ACMECert, error) {
	var r acmeCertRow
	if err := getRow(s, bucketACMECerts, []byte(name), &r); err != nil {
		return nil, err
	}
	r.ACMECert.ChainPEM = r.Chain
	return &r.ACMECert, nil
}

// ListACMECerts lists definitions.
func (s *Store) ListACMECerts() ([]*ACMECert, error) {
	var out []*ACMECert
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketACMECerts).ForEach(func(_, v []byte) error {
			var r acmeCertRow
			if err := jsonUnmarshal(v, &r); err != nil {
				return err
			}
			r.ACMECert.ChainPEM = r.Chain
			c := r.ACMECert
			out = append(out, &c)
			return nil
		})
	})
	return out, err
}

// DeleteACMECert removes a definition (its order history stays).
func (s *Store) DeleteACMECert(name string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketACMECerts)
		if b.Get([]byte(name)) == nil {
			return ErrNotFound
		}
		return b.Delete([]byte(name))
	})
}

func acmeOrderKey(cert string, at time.Time, id string) []byte {
	return key(cert, fmt.Sprintf("%020d", at.UnixNano()), id)
}

// PutACMEOrder creates or replaces an order.
func (s *Store) PutACMEOrder(o *ACMEOrder) error {
	return putRow(s, bucketACMEOrders, acmeOrderKey(o.Cert, o.At, o.ID), o)
}

// ListACMEOrders lists a certificate's orders, newest first.
func (s *Store) ListACMEOrders(cert string, limit int) ([]*ACMEOrder, error) {
	var all []*ACMEOrder
	err := s.db.View(func(tx *bolt.Tx) error {
		c := tx.Bucket(bucketACMEOrders).Cursor()
		p := prefix(cert)
		for k, v := c.Seek(p); k != nil && hasPrefix(k, p); k, v = c.Next() {
			var o ACMEOrder
			if err := jsonUnmarshal(v, &o); err != nil {
				return err
			}
			all = append(all, &o)
		}
		return nil
	})
	out := make([]*ACMEOrder, 0, len(all))
	for i := len(all) - 1; i >= 0 && (limit <= 0 || len(out) < limit); i-- {
		out = append(out, all[i])
	}
	return out, err
}

// GetACMEOrder finds an order of cert by ID.
func (s *Store) GetACMEOrder(cert, id string) (*ACMEOrder, error) {
	os, err := s.ListACMEOrders(cert, 0)
	if err != nil {
		return nil, err
	}
	for _, o := range os {
		if o.ID == id {
			return o, nil
		}
	}
	return nil, ErrNotFound
}
