// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"errors"
	"os"
	"strings"
	"unicode/utf8"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/credentials"
)

// InitialIntent is public provisioning metadata in the same protected,
// profile/account-scoped journal as operations. It never holds token/password
// bytes or verifier hashes. Dispatched is persisted BEFORE private I/O.
type InitialIntent struct {
	Schema     uint8
	Profile    [32]byte
	User, ID   string
	Request    credentials.InitialRequest
	Dispatched bool
	Fact       *credentials.InitialFact `json:",omitempty"`
}

func initialIntentName(id string) string { return "initial-" + operationName(id) }

func readInitialIntent(root *os.Root, c Client, session access.Session, id string) (InitialIntent, error) {
	var r InitialIntent
	if id == "" || readPrivate(root, initialIntentName(id), &r) != nil || r.Schema != 1 || r.ID != id || r.Profile != c.JournalProfile() || r.User != session.User || !r.Request.Valid() || r.Request.Cluster != c.Cluster || r.Fact != nil && (!r.Dispatched || !r.Fact.Verify() || r.Fact.Request != r.Request) {
		return InitialIntent{}, ErrPrivateState
	}
	return r, nil
}

func LoadInitialIntent(home string, c Client, session access.Session, id string) (InitialIntent, error) {
	if c.Verify(session) != nil || id == "" {
		return InitialIntent{}, ErrPrivateState
	}
	r, err := operationRoot(home, c, session.User, false)
	if err != nil {
		return InitialIntent{}, err
	}
	defer r.Close()
	if _, err = r.Lstat(initialIntentName(id)); errors.Is(err, os.ErrNotExist) {
		return InitialIntent{}, ErrOperationMissing
	}
	return readInitialIntent(r, c, session, id)
}

func StageInitialIntent(home string, c Client, session access.Session, id string, request credentials.InitialRequest) (InitialIntent, error) {
	if c.Verify(session) != nil || id == "" || len(id) > 128 || !utf8.ValidString(id) || !request.Valid() || request.Cluster != c.Cluster {
		return InitialIntent{}, ErrPrivateState
	}
	r, err := operationRoot(home, c, session.User, true)
	if err != nil {
		return InitialIntent{}, err
	}
	defer r.Close()
	unlock, err := lockProfile(r)
	if err != nil {
		return InitialIntent{}, err
	}
	defer unlock()
	if _, err = r.Lstat(initialIntentName(id)); err == nil {
		existing, err := readInitialIntent(r, c, session, id)
		if err != nil || existing.Request != request {
			return InitialIntent{}, ErrPrivateState
		}
		return existing, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return InitialIntent{}, ErrPrivateState
	}
	dir, err := r.Open(".")
	if err != nil {
		return InitialIntent{}, ErrPrivateState
	}
	names, err := dir.Readdirnames(-1)
	_ = dir.Close()
	if err != nil {
		return InitialIntent{}, ErrPrivateState
	}
	count := 0
	for _, name := range names {
		if strings.HasPrefix(name, "initial-") && strings.HasSuffix(name, ".json") {
			count++
		}
	}
	if count >= operationLimit {
		return InitialIntent{}, ErrPrivateState
	}
	record := InitialIntent{Schema: 1, Profile: c.JournalProfile(), User: session.User, ID: id, Request: request}
	if err := writePrivate(r, initialIntentName(id), record); err != nil {
		return InitialIntent{}, err
	}
	return record, nil
}

func MarkInitialDispatch(home string, c Client, session access.Session, id string) error {
	return updateInitialIntent(home, c, session, id, func(r *InitialIntent) error {
		if r.Dispatched {
			return ErrPrivateState
		}
		r.Dispatched = true
		return nil
	})
}

func RecordInitialFact(home string, c Client, session access.Session, id string, fact credentials.InitialFact) error {
	return updateInitialIntent(home, c, session, id, func(r *InitialIntent) error {
		if !r.Dispatched || !fact.Verify() || fact.Request != r.Request {
			return ErrPrivateState
		}
		r.Fact = &fact
		return nil
	})
}

func updateInitialIntent(home string, c Client, session access.Session, id string, mutate func(*InitialIntent) error) error {
	if c.Verify(session) != nil {
		return ErrPrivateState
	}
	r, err := operationRoot(home, c, session.User, false)
	if err != nil {
		return err
	}
	defer r.Close()
	unlock, err := lockProfile(r)
	if err != nil {
		return err
	}
	defer unlock()
	record, err := readInitialIntent(r, c, session, id)
	if err != nil {
		return err
	}
	if err = mutate(&record); err != nil {
		return err
	}
	return writePrivate(r, initialIntentName(id), record)
}
