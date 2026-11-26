// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"sort"
	"strings"
	"time"
)

// State is where an operation stands as far as this computer knows.
type State string

const (
	// Sending: saved before sending; whether the server got it is unknown
	// until `mydc op show` asks with the same ID.
	Sending State = "sending"
	// Accepted: the server took it and the work is still running.
	Accepted State = "accepted"
	// Done and Failed are final.
	Done   State = "done"
	Failed State = "failed"
)

// Final reports whether nothing more will happen to the operation.
func (s State) Final() bool { return s == Done || s == Failed }

// Op is one change the CLI sent, or saved just before sending. It is the
// public index entry behind `mydc op`; the signed original and any private
// recovery state stay in the journal of its kind.
type Op struct {
	ID      string    `json:"id"`
	Kind    string    `json:"kind"`    // which handler settles it, such as "volume-backup"
	Context string    `json:"context"` // context it was sent with
	Tenant  string    `json:"tenant,omitempty"`
	Summary string    `json:"summary"` // the command, such as "volume backup create shop/mysql-data"
	Created time.Time `json:"created"`
	Updated time.Time `json:"updated"`
	State   State     `json:"state"`
	Detail  string    `json:"detail,omitempty"` // last result line from the server
}

var (
	ErrOpNotFound  = errors.New("no such operation on this computer")
	ErrOpAmbiguous = errors.New("operation ID prefix matches more than one operation")
	errOpConflict  = errors.New("operation ID already names a different operation")
)

// Ops is the operation index in one private directory (~/.mydc/ops), one
// file per operation. It is local to this computer and user.
type Ops struct{ root *os.Root }

// OpenOps opens or creates the index directory with mode 0700.
func OpenOps(dir string) (*Ops, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%s must be a private directory (mode 0700)", dir)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	return &Ops{root: root}, nil
}

func (x *Ops) Close() error { return x.root.Close() }

// Add saves a new operation before it is sent. Adding the same ID again with
// the same kind and summary is a no-op, so a retried command does not fail;
// the ID can never be reused for a different operation.
func (x *Ops) Add(op Op) error {
	if !ValidID(op.ID) || op.Kind == "" || op.Summary == "" {
		return errors.New("operation needs a valid id, a kind and a summary")
	}
	if old, err := x.read(op.ID); err == nil {
		if old.Kind != op.Kind || old.Summary != op.Summary {
			return errOpConflict
		}
		return nil
	} else if !errors.Is(err, ErrOpNotFound) {
		return err
	}
	now := time.Now().UTC().Truncate(time.Second)
	if op.Created.IsZero() {
		op.Created = now
	}
	op.Updated = op.Created
	if op.State == "" {
		op.State = Sending
	}
	return x.write(op)
}

// Update records what the server said about an operation.
func (x *Ops) Update(id string, state State, detail string) error {
	op, err := x.read(id)
	if err != nil {
		return err
	}
	op.State, op.Detail, op.Updated = state, detail, time.Now().UTC().Truncate(time.Second)
	return x.write(op)
}

// Get finds an operation by its full ID or a unique prefix of at least four
// characters.
func (x *Ops) Get(id string) (Op, error) {
	if op, err := x.read(id); !errors.Is(err, ErrOpNotFound) {
		return op, err
	}
	if len(id) < 4 {
		return Op{}, ErrOpNotFound
	}
	all, err := x.List()
	if err != nil {
		return Op{}, err
	}
	var found []Op
	for _, op := range all {
		if strings.HasPrefix(op.ID, id) {
			found = append(found, op)
		}
	}
	switch len(found) {
	case 0:
		return Op{}, ErrOpNotFound
	case 1:
		return found[0], nil
	}
	return Op{}, ErrOpAmbiguous
}

// List returns every operation, newest first.
func (x *Ops) List() ([]Op, error) {
	entries, err := fs.ReadDir(x.root.FS(), ".")
	if err != nil {
		return nil, err
	}
	out := []Op{}
	for _, e := range entries {
		id, ok := strings.CutSuffix(e.Name(), ".json")
		if !ok || !ValidID(id) || !e.Type().IsRegular() {
			continue
		}
		op, err := x.read(id)
		if err != nil {
			return nil, fmt.Errorf("operation %s: %w", id, err)
		}
		out = append(out, op)
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].Created.Equal(out[j].Created) {
			return out[i].Created.After(out[j].Created)
		}
		return out[i].ID < out[j].ID
	})
	return out, nil
}

// Remove deletes the index entry of a final operation.
func (x *Ops) Remove(id string) error {
	op, err := x.read(id)
	if err != nil {
		return err
	}
	if !op.State.Final() {
		return fmt.Errorf("operation %s is %s; only finished operations can be removed", id, op.State)
	}
	return x.root.Remove(id + ".json")
}

func (x *Ops) read(id string) (Op, error) {
	if !ValidID(id) {
		return Op{}, ErrOpNotFound
	}
	raw, err := x.root.ReadFile(id + ".json")
	if errors.Is(err, fs.ErrNotExist) {
		return Op{}, ErrOpNotFound
	}
	if err != nil {
		return Op{}, err
	}
	var op Op
	if err = json.Unmarshal(raw, &op); err != nil || op.ID != id {
		return Op{}, fmt.Errorf("operation file %s.json is damaged", id)
	}
	return op, nil
}

// write replaces the entry atomically: a crash leaves the old or the new
// file, never a partial one.
func (x *Ops) write(op Op) error {
	raw, err := json.MarshalIndent(op, "", "  ")
	if err != nil {
		return err
	}
	tmp := "." + op.ID + ".tmp"
	f, err := x.root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err = f.Write(append(raw, '\n')); err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = x.root.Rename(tmp, op.ID+".json")
	}
	if err != nil {
		_ = x.root.Remove(tmp)
	}
	return err
}
