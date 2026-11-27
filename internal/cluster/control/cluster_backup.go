// SPDX-License-Identifier: Apache-2.0

package control

import (
	"encoding/json"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/lifecycle"
	"github.com/jay94ks/seafield/internal/cluster/state"
)

// ClusterBackupKey records who took a cluster backup and when. The backup
// itself (snapshot and master key) never enters Raft; a voter streams it to
// the CLI only for an operation recorded here.
const ClusterBackupKey = "control/cluster-backups"

const (
	// ClusterBackupWindow is how long after its record a backup may be
	// fetched, in seconds.
	ClusterBackupWindow = 15 * 60
	clusterBackupKeep   = 64
)

// ClusterBackupChange is the signed cluster-backup payload. Recipient is the
// one-time X25519 key the CLI made for this backup; the voter seals the
// master key to it and to nothing else.
type ClusterBackupChange struct {
	Operation string
	Recipient [32]byte
}

func (q ClusterBackupChange) Valid() bool {
	return lifecycle.ValidID(q.Operation) && q.Recipient != ([32]byte{})
}

type ClusterBackupRecord struct {
	Origin    UserOperation
	Operation string
	Recipient [32]byte
	At        uint64
}

// ClusterBackups keeps the latest records; the oldest drop out first.
type ClusterBackups struct {
	Schema   uint8
	Cluster  [32]byte
	Revision uint64
	Records  []ClusterBackupRecord
}

func (b ClusterBackups) Record(id string) (ClusterBackupRecord, bool) {
	for _, r := range b.Records {
		if r.Operation == id {
			return r, true
		}
	}
	return ClusterBackupRecord{}, false
}

func (p Policy) ClusterBackups(s state.State) (ClusterBackups, error) {
	out := ClusterBackups{Schema: 1, Cluster: p.Cluster}
	raw, revision, err := readCheckpoint(s, ClusterBackupKey, p.Cluster, p.TrustRoot)
	if err != nil || raw == nil {
		return out, err
	}
	if canonical(raw, &out) != nil || out.Schema != 1 || out.Cluster != p.Cluster || out.Revision != revision || len(out.Records) > clusterBackupKeep {
		return out, ErrCatalog
	}
	seen := map[string]bool{}
	for _, r := range out.Records {
		var q ClusterBackupChange
		if r.Origin.VerifyOriginal(p.Cluster) != nil || r.Origin.Change.Action != "cluster-backup" || canonical(r.Origin.Change.Payload, &q) != nil || !q.Valid() || q.Operation != r.Operation || q.Recipient != r.Recipient || r.At != uint64(r.Origin.At) || seen[r.Operation] {
			return out, ErrCatalog
		}
		seen[r.Operation] = true
	}
	return out, nil
}

func (p Policy) clusterBackupAuthorized(c access.Catalog, session access.Session, at int64) error {
	if err := c.OperationAllowed(session, "cluster-backup"); err != nil {
		return err
	}
	return c.AuthorizeSession(session, p.Cluster, p.Issuer(session.Issuer), at, "", access.ManageCluster, "")
}

func (p Policy) reduceClusterBackup(s state.State, cmd state.Command) (map[string][]byte, state.Code) {
	p, err := p.Current(s)
	if err != nil || cmd.Kind != state.Module || cmd.Key != ClusterBackupKey {
		return nil, state.Forbidden
	}
	c, err := p.Catalog(s)
	if err != nil {
		return nil, state.Invalid
	}
	op, err := p.Operation(c, cmd, false)
	if err != nil || op.Change.Action != "cluster-backup" || p.clusterBackupAuthorized(c, op.Session, op.At) != nil {
		return nil, state.Forbidden
	}
	var q ClusterBackupChange
	if canonical(op.Change.Payload, &q) != nil || !q.Valid() || op.Change.Expected != 0 {
		return nil, state.Invalid
	}
	b, err := p.ClusterBackups(s)
	if err != nil {
		return nil, state.Invalid
	}
	if _, exists := b.Record(q.Operation); exists || b.Revision == ^uint64(0) {
		return nil, state.ConditionFailed
	}
	b.Records = append(b.Records, ClusterBackupRecord{Origin: op, Operation: q.Operation, Recipient: q.Recipient, At: uint64(op.At)})
	if len(b.Records) > clusterBackupKeep {
		b.Records = b.Records[len(b.Records)-clusterBackupKeep:]
	}
	b.Revision++
	raw, err := json.Marshal(b)
	if err != nil || len(raw) > 4<<20 {
		return nil, state.ConditionFailed
	}
	return writeCheckpoint(s, ClusterBackupKey, p.Cluster, p.TrustRoot, b.Revision, raw)
}

// ClusterBackupWork returns the recorded operation a voter may serve now:
// the same user's session, still allowed to take a backup, within the
// window after the record.
func (p Policy) ClusterBackupWork(s state.State, session access.Session, operation string, now int64) (ClusterBackupRecord, error) {
	p, err := p.Current(s)
	if err != nil || !lifecycle.ValidID(operation) || now <= 0 {
		return ClusterBackupRecord{}, access.ErrDenied
	}
	c, err := p.Catalog(s)
	if err != nil {
		return ClusterBackupRecord{}, err
	}
	if err := p.clusterBackupAuthorized(c, session, now); err != nil {
		return ClusterBackupRecord{}, err
	}
	b, err := p.ClusterBackups(s)
	if err != nil {
		return ClusterBackupRecord{}, err
	}
	r, ok := b.Record(operation)
	if !ok || r.Origin.Session.User != session.User || r.At > uint64(now) || uint64(now)-r.At > ClusterBackupWindow {
		return ClusterBackupRecord{}, access.ErrDenied
	}
	return r, nil
}

// clusterBackupBook is the ClusterBackupKey Raft book (see book.go).
var clusterBackupBook = Book{
	Key:       ClusterBackupKey,
	Actions:   []string{"cluster-backup"},
	Reduce:    Policy.reduceClusterBackup,
	Authorize: authorizeCluster,
}
