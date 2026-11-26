// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"strings"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/certstore"
)

// CertificateIntent is public original input identity plus a sealed receipt.
// It never contains the uploaded private key, and dispatch is durable before FD
// material crosses the protected input path.
type CertificateIntent struct {
	Schema     uint8
	Profile    [32]byte
	User, ID   string
	Owner      [32]byte
	Dispatched bool
	Fact       *certstore.Certificate `json:",omitempty"`
}

func certificateIntentName(id string) string { return "certificate-" + operationName(id) }
func validCertificateIntent(c Client, session access.Session, id string, r CertificateIntent) bool {
	if r.Schema != 1 || r.Profile != c.JournalProfile() || r.User != session.User || r.ID != id || r.Owner == ([32]byte{}) {
		return false
	}
	if r.Fact != nil {
		v := r.Fact
		if !r.Dispatched || v.Validate() != nil || v.Cluster != c.Cluster || v.Metadata.UploadedBy != r.User || v.Request != r.ID || v.Sealer != r.Owner {
			return false
		}
	}
	return true
}
func readCertificateIntent(root *os.Root, c Client, session access.Session, id string) (CertificateIntent, error) {
	var r CertificateIntent
	if readPrivate(root, certificateIntentName(id), &r) != nil || !validCertificateIntent(c, session, id, r) {
		return r, ErrPrivateState
	}
	return r, nil
}
func LoadCertificateIntent(home string, c Client, session access.Session, id string) (CertificateIntent, error) {
	if c.Verify(session) != nil || id == "" {
		return CertificateIntent{}, ErrPrivateState
	}
	root, err := operationRoot(home, c, session.User, false)
	if err != nil {
		return CertificateIntent{}, err
	}
	defer root.Close()
	if _, err = root.Lstat(certificateIntentName(id)); errors.Is(err, os.ErrNotExist) {
		return CertificateIntent{}, ErrOperationMissing
	}
	return readCertificateIntent(root, c, session, id)
}
func StageCertificateIntent(home string, c Client, session access.Session, r CertificateIntent) (CertificateIntent, error) {
	if c.Verify(session) != nil || r.ID == "" || len(r.ID) > 128 || r.Dispatched || r.Fact != nil {
		return CertificateIntent{}, ErrPrivateState
	}
	r.Schema = 1
	r.Profile = c.JournalProfile()
	r.User = session.User
	if !validCertificateIntent(c, session, r.ID, r) {
		return CertificateIntent{}, ErrPrivateState
	}
	root, err := operationRoot(home, c, session.User, true)
	if err != nil {
		return r, err
	}
	defer root.Close()
	unlock, err := lockProfile(root)
	if err != nil {
		return r, err
	}
	defer unlock()
	if _, err = root.Lstat(certificateIntentName(r.ID)); err == nil {
		old, e := readCertificateIntent(root, c, session, r.ID)
		a, _ := json.Marshal(old)
		b, _ := json.Marshal(r)
		if e != nil || !bytes.Equal(a, b) {
			return r, ErrPrivateState
		}
		return old, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return r, ErrPrivateState
	}
	dir, err := root.Open(".")
	if err != nil {
		return r, err
	}
	names, err := dir.Readdirnames(-1)
	_ = dir.Close()
	if err != nil {
		return r, err
	}
	count := 0
	for _, name := range names {
		if strings.HasPrefix(name, "certificate-") && strings.HasSuffix(name, ".json") {
			count++
		}
	}
	if count >= operationLimit {
		return r, ErrPrivateState
	}
	if err = writePrivate(root, certificateIntentName(r.ID), r); err != nil {
		return r, err
	}
	return r, nil
}
func UpdateCertificateIntent(home string, c Client, session access.Session, id string, fact *certstore.Certificate) error {
	if c.Verify(session) != nil {
		return ErrPrivateState
	}
	root, err := operationRoot(home, c, session.User, false)
	if err != nil {
		return err
	}
	defer root.Close()
	unlock, err := lockProfile(root)
	if err != nil {
		return err
	}
	defer unlock()
	r, err := readCertificateIntent(root, c, session, id)
	if err != nil {
		return err
	}
	if fact == nil {
		if r.Dispatched {
			return ErrPrivateState
		}
		r.Dispatched = true
	} else {
		if !r.Dispatched {
			return ErrPrivateState
		}
		if r.Fact != nil && r.Fact.Digest() != fact.Digest() {
			return ErrPrivateState
		}
		r.Fact = fact
	}
	if !validCertificateIntent(c, session, id, r) {
		return ErrPrivateState
	}
	return writePrivate(root, certificateIntentName(id), r)
}
