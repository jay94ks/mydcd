// SPDX-License-Identifier: Apache-2.0

package app

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"

	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/schema"
	"github.com/jay94ks/seafield/internal/storage"
)

const nodeShellReceiptPrefix = "node-shell/session/"

// The receipt is private metadata in the existing observations DB. Its lock
// belongs to exactly one logical daemon lifetime. No shell input/output or
// client key is stored here, and this is not a second authorization store.
type nodeShellReceipt struct {
	Schema                           uint8
	Cluster, Owner, Origin, Instance [32]byte
	Node, SessionID, Phase           string
	OpenedAt, LastActivity           int64
	BytesIn, BytesOut                uint64
	Code                             int
	Reason                           string
	Pending                          *control.NodeShellReport `json:",omitempty"`
}

func nodeShellOrigin(row control.NodeShellRecord) [32]byte {
	raw, _ := json.Marshal(row.Origin)
	return sha256.Sum256(raw)
}

func nodeShellReceiptKey(id string) string {
	digest := sha256.Sum256([]byte(id))
	return nodeShellReceiptPrefix + hex.EncodeToString(digest[:])
}

func (p nodeShellReceipt) valid(cluster [32]byte, row control.NodeShellRecord) bool {
	if p.Schema != 1 || p.Cluster != cluster || p.Owner != row.Owner || p.Origin != nodeShellOrigin(row) || p.Instance == ([32]byte{}) || p.Node != row.Session.Node || p.SessionID != row.Session.SessionID || p.LastActivity < 0 || p.OpenedAt < 0 || p.BytesIn < row.Session.BytesIn || p.BytesOut < row.Session.BytesOut || p.Code < 0 || p.Code > 255 {
		return false
	}
	if q := p.Pending; q != nil {
		if q.Schema != 1 || q.Cluster != cluster || q.Node != p.Node || q.SessionID != p.SessionID || q.Kind != "opened" && q.Kind != "activity" && q.Kind != "closed" || !ed25519.Verify(ed25519.PublicKey(q.Reporter[:]), control.NodeShellReportBytes(*q), q.Signature) {
			return false
		}
	}
	switch p.Phase {
	case "sent":
		return p.OpenedAt == 0 && p.LastActivity == 0 && p.BytesIn == 0 && p.BytesOut == 0 && p.Code == 0 && p.Reason == ""
	case "opened":
		return p.OpenedAt >= row.Session.CreatedAt && p.LastActivity >= p.OpenedAt && p.Code == 0 && p.Reason == ""
	case "closed":
		return p.Reason == "exit" || p.Reason == "idle" || p.Reason == "closed" || p.Reason == "policy"
	}
	return false
}

func (r *Runtime) nodeShellReceipt(row control.NodeShellRecord) (nodeShellReceipt, *storage.DB, bool, error) {
	for _, owner := range r.physicalOwners() {
		if owner.reports == nil {
			continue
		}
		raw, err := owner.reports.GetBounded(nodeShellReceiptKey(row.Session.SessionID), 8192)
		if errors.Is(err, storage.ErrMissing) {
			continue
		}
		if err != nil {
			return nodeShellReceipt{}, nil, false, err
		}
		p, err := schema.Decode[nodeShellReceipt](raw)
		if err != nil || !p.valid(r.controlPolicy.Cluster, row) {
			return p, nil, false, control.ErrCatalog
		}
		return p, owner.reports, true, nil
	}
	return nodeShellReceipt{}, r.reports, false, nil
}

func saveNodeShellReceipt(db *storage.DB, p nodeShellReceipt) error {
	if db == nil || p.Schema != 1 || p.SessionID == "" {
		return control.ErrCatalog
	}
	raw, err := json.Marshal(p)
	if err != nil || len(raw) > 8192 {
		return control.ErrCatalog
	}
	return db.Write(map[string][]byte{nodeShellReceiptKey(p.SessionID): raw})
}
