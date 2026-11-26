// SPDX-License-Identifier: Apache-2.0

package store

import (
	"encoding/json"
	"fmt"
	"time"

	bolt "go.etcd.io/bbolt"
)

// Op states.
const (
	// OpPending: signed and stored, not yet known to be delivered.
	OpPending = "pending"
	// OpApplied: Result.Code == Applied.
	OpApplied = "applied"
	// OpFailed: delivered with a non-zero Result.Code (CAS failed, forbidden, ...).
	OpFailed = "failed"
	// OpRejected: mydcd refused the request (denied/invalid) before execution.
	OpRejected = "rejected"
	// OpUnknown: delivered or possibly delivered, outcome not known.
	OpUnknown = "unknown"
	// OpRunning: a multi-step job that has more steps to send.
	OpRunning = "running"
)

// Settled reports whether a state is final and may be pruned.
func Settled(state string) bool {
	return state == OpApplied || state == OpFailed || state == OpRejected
}

// OpResult mirrors the original-result view.
type OpResult struct {
	Found      bool   `json:"found"`
	Code       int    `json:"code"`
	Index      uint64 `json:"index"`
	Revision   uint64 `json:"revision"`
	Generation uint64 `json:"generation"`
}

// Op is one original signed UserOperation submitted by a user through the web.
type Op struct {
	ID          string    `json:"id"`        // browser-chosen idempotency ID
	User        string    `json:"user"`      // mydc user ID
	Username    string    `json:"username"`  // for display
	RequestID   string    `json:"requestId"` // UserOperation.RequestID
	Action      string    `json:"action"`
	Tenant      string    `json:"tenant,omitempty"`
	Target      string    `json:"target,omitempty"`
	Digest      string    `json:"digest"` // hash of the browser request, for idempotency checks
	Signed      []byte    `json:"signed"` // original signed operation bytes
	State       string    `json:"state"`
	ErrorCode   string    `json:"errorCode,omitempty"`
	Result      *OpResult `json:"result,omitempty"`
	SubmittedAt time.Time `json:"submittedAt"`
	UpdatedAt   time.Time `json:"updatedAt"`

	// Reason is display-only metadata sent with the op; never
	// used for permission.
	Reason *OpReason `json:"reason,omitempty"`

	// Parent is the web op ID of a multi-step job (deploy) this op belongs to.
	Parent string `json:"parent,omitempty"`
	// Deploy holds a deploy job's input and progress (parent rows only).
	Deploy *DeployJob `json:"deploy,omitempty"`
	// VaultWrite holds a Vault provider write job (parent rows only).
	VaultWrite *VaultWriteJob `json:"vaultWrite,omitempty"`
	// BuildApproval: a begin-image-build original (Signed, not yet sent)
	// waiting for protected Group approvals of its build secrets.
	BuildApproval *BuildApprovalJob `json:"buildApproval,omitempty"`
	// RegistryBind: a bind-external-registry original (Signed, not yet
	// sent) waiting for protected Group approvals of the source's secrets.
	RegistryBind *RegistryBindJob `json:"registryBind,omitempty"`
}

// RegistryBindJob: the source, the reader's server, the realms the bind
// plan uses and their Group approvals (never a password).
type RegistryBindJob struct {
	Tenant    string           `json:"tenant"`
	Source    string           `json:"source"`
	Node      string           `json:"node"`
	Realms    []string         `json:"realms,omitempty"`
	Approvals []DeployApproval `json:"approvals,omitempty"`
}

// BuildApprovalJob: the build and its Group approvals (never a password).
type BuildApprovalJob struct {
	Tenant    string           `json:"tenant"`
	Context   string           `json:"context"`
	Job       string           `json:"job"`
	Approvals []DeployApproval `json:"approvals,omitempty"`
}

// OpReason: why an op was sent (e.g. "autofix") and the incident it
// belongs to, each at most 256 characters.
type OpReason struct {
	Reason   string `json:"reason,omitempty"`
	Incident string `json:"incident,omitempty"`
}

// VaultWriteJob is a Secret value or Group password write (plan → prepare →
// dispatch → private input → observe → publish). It never holds the values
// or the password: only the public write request, whether the private input
// was attempted, and the receiver's signed public observation until it is
// recorded.
type VaultWriteJob struct {
	Realm   string          `json:"realm"`
	Path    string          `json:"path"`
	Object  string          `json:"object"`
	Kind    string          `json:"kind"` // value | verifier
	WriteID string          `json:"writeId"`
	Request json.RawMessage `json:"request"` // secrets.WriteRequest of the first plan
	// Attempted is set (and stored) before the private input is sent; after
	// that only a recover (no values) is ever sent.
	Attempted   bool            `json:"attempted,omitempty"`
	Observation json.RawMessage `json:"observation,omitempty"`
}

// DeployJob is the upload → up job of one app.yaml, kept so an interrupted
// deploy continues with the same upload and original ops.
type DeployJob struct {
	Tenant     string `json:"tenant"`
	App        string `json:"app"`
	Deployment string `json:"deployment,omitempty"`
	Node       string `json:"node,omitempty"`
	UploadID   string `json:"uploadId"`
	Document   []byte `json:"document"`
	Digest     string `json:"digest"`
	Parts      int    `json:"parts"`
	// Step is the next step: 0 begin-app-upload, 1..Parts put-app-part,
	// Parts+1 begin-app, Parts+2 done.
	Step int `json:"step"`
	// Origin is the signed begin-app original, prepared before Group
	// approvals and sent unchanged after them.
	Origin []byte `json:"origin,omitempty"`
	// Approvals are the protected Groups the app uses that need the
	// requester's password before begin-app (never the password).
	Approvals []DeployApproval `json:"approvals,omitempty"`
	// Move makes this a volume move job (UI-64): step Parts+1 sends
	// begin-volume-move instead of begin-app, and Origin is that sent
	// original; its Group approvals follow it (Parts+2 waits for them).
	Move *MoveJob `json:"move,omitempty"`
	// Standalone makes this a standalone-up job: App is the
	// internal scope and step Parts+1 sends standalone-up with Begin.
	Standalone *StandaloneUpJob `json:"standalone,omitempty"`
	// Local makes this a CD app's local services job: the upload is the
	// local services document and step Parts+1 sends
	// put-app-local-services with Change.
	Local *LocalJob `json:"local,omitempty"`
}

// LocalJob: the put-app-local-services payload (control.AppLocalChange,
// naming the job's upload) and its Expected (the CD revision).
type LocalJob struct {
	Change   json.RawMessage `json:"change"`
	Expected uint64          `json:"expected"`
}

// StandaloneUpJob: the standalone-up begin (control.AppBegin with the
// Standalone definition and the management Target read when the job was
// made) and its Expected (the row's revision, 0 for a new name).
type StandaloneUpJob struct {
	Name     string          `json:"name"`
	Begin    json.RawMessage `json:"begin"`
	Expected uint64          `json:"expected"`
}

// MoveJob is the volume move part of a deploy job: mydcd's planned
// begin-volume-move payload and its Expected (the volume revision).
type MoveJob struct {
	Volume   string          `json:"volume"`
	ID       string          `json:"id"`
	From     string          `json:"from"`
	To       string          `json:"to"`
	Begin    json.RawMessage `json:"begin"` // control.VolumeMoveBegin
	Expected uint64          `json:"expected"`
	// CD: the app is under CD; its registrant approves Groups with
	// /apps/{app}/cd/approvals?operation={id}, not this job.
	CD bool `json:"cd,omitempty"`
}

// DeployApproval is one required Group approval of a deploy job.
type DeployApproval struct {
	Realm    string          `json:"realm"`
	Group    string          `json:"group"`
	Services []string        `json:"services,omitempty"`
	Target   json.RawMessage `json:"target"`   // secrets.Target from vault-approval-plan
	Approver json.RawMessage `json:"approver"` // config.Peer
	// State: required / approved / unknown (the approver's answer was lost)
	State string `json:"state"`
}

func stateIndexKey(o *Op) []byte {
	return key(o.User, o.State, fmt.Sprintf("%020d", o.SubmittedAt.UnixNano()), o.ID)
}

// CreateOp stores a new op. If an op with the same ID exists for the user it
// is returned with ok=false; the caller compares digests.
func (s *Store) CreateOp(o *Op) (existing *Op, err error) {
	err = s.db.Update(func(tx *bolt.Tx) error {
		ops := tx.Bucket(bucketOps)
		k := key(o.User, o.ID)
		if raw := ops.Get(k); raw != nil {
			existing = &Op{}
			return getJSON(ops, k, existing)
		}
		if err := putJSON(ops, k, o); err != nil {
			return err
		}
		return tx.Bucket(bucketOpsByState).Put(stateIndexKey(o), nil)
	})
	return existing, err
}

// UpdateOp replaces an op and moves its state index in the same transaction.
func (s *Store) UpdateOp(o *Op) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		ops := tx.Bucket(bucketOps)
		k := key(o.User, o.ID)
		var old Op
		if err := getJSON(ops, k, &old); err != nil {
			return err
		}
		idx := tx.Bucket(bucketOpsByState)
		if err := idx.Delete(stateIndexKey(&old)); err != nil {
			return err
		}
		if err := putJSON(ops, k, o); err != nil {
			return err
		}
		return idx.Put(stateIndexKey(o), nil)
	})
}

// GetOp loads one op of a user.
func (s *Store) GetOp(user, id string) (*Op, error) {
	var o Op
	err := s.db.View(func(tx *bolt.Tx) error {
		return getJSON(tx.Bucket(bucketOps), key(user, id), &o)
	})
	if err != nil {
		return nil, err
	}
	return &o, nil
}

// ListOps lists a user's ops, newest first. state "" lists all states.
// before is an exclusive cursor (op submitted-at nanos + id) for paging.
func (s *Store) ListOps(user, state string, limit int) ([]*Op, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	var out []*Op
	err := s.db.View(func(tx *bolt.Tx) error {
		ops := tx.Bucket(bucketOps)
		if state != "" {
			c := tx.Bucket(bucketOpsByState).Cursor()
			p := prefix(user, state)
			// Walk the state index backwards for newest first.
			var keys [][]byte
			for k, _ := c.Seek(p); k != nil && hasPrefix(k, p); k, _ = c.Next() {
				keys = append(keys, append([]byte(nil), k...))
			}
			for i := len(keys) - 1; i >= 0 && len(out) < limit; i-- {
				id := lastPart(keys[i])
				var o Op
				if err := getJSON(ops, key(user, id), &o); err != nil {
					return err
				}
				out = append(out, &o)
			}
			return nil
		}
		c := ops.Cursor()
		p := prefix(user)
		for k, v := c.Seek(p); k != nil && hasPrefix(k, p); k, v = c.Next() {
			var o Op
			if err := jsonUnmarshal(v, &o); err != nil {
				return err
			}
			out = append(out, &o)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if state == "" {
		sortOpsNewest(out)
		if len(out) > limit {
			out = out[:limit]
		}
	}
	return out, nil
}

// PruneOps deletes settled ops updated before cutoff. Pending and unknown ops
// are kept until they are settled.
func (s *Store) PruneOps(cutoff time.Time) (int, error) {
	n := 0
	err := s.db.Update(func(tx *bolt.Tx) error {
		ops := tx.Bucket(bucketOps)
		idx := tx.Bucket(bucketOpsByState)
		var dead []*Op
		if err := ops.ForEach(func(k, v []byte) error {
			var o Op
			if err := jsonUnmarshal(v, &o); err != nil {
				return err
			}
			if Settled(o.State) && o.UpdatedAt.Before(cutoff) {
				dead = append(dead, &o)
			}
			return nil
		}); err != nil {
			return err
		}
		for _, o := range dead {
			if err := ops.Delete(key(o.User, o.ID)); err != nil {
				return err
			}
			if err := idx.Delete(stateIndexKey(o)); err != nil {
				return err
			}
			n++
		}
		return nil
	})
	return n, err
}
