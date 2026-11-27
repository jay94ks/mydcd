// SPDX-License-Identifier: Apache-2.0

package app

import (
	"encoding/hex"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/membership"
	"github.com/jay94ks/seafield/internal/config"
	"github.com/jay94ks/seafield/internal/loginlog"
	"github.com/jay94ks/seafield/internal/storage"
)

func TestLoginRecordsAnswerOnlyForMembers(t *testing.T) {
	db, err := storage.Open(filepath.Join(t.TempDir(), "observations.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store, _ := loginlog.Open(db, "node-b")
	now := time.Unix(1_800_000_000, 0)
	_ = store.Add(loginlog.Record{User: "u1", Username: "alice", Reason: "denied", Method: access.Password, Credential: "pw", Source: "10.0.0.9"}, now)
	member, outsider := [32]byte{7}, [32]byte{8}
	members := membership.Directory{Schema: 1, Entries: []membership.Entry{{Peer: config.Peer{ID: "node-a", Key: hex.EncodeToString(member[:])}, Phase: membership.Active}}}
	q, _ := json.Marshal(loginlog.Query{User: "u1", Limit: 10})
	raw, err := loginRecordsAnswer(members, store, member, q, now)
	var p loginlog.Page
	if err != nil || json.Unmarshal(raw, &p) != nil || len(p.Items) != 1 || p.Items[0].Node != "node-b" {
		t.Fatalf("member read = %s, %v", raw, err)
	}
	if _, err := loginRecordsAnswer(members, store, outsider, q, now); err == nil {
		t.Fatal("non-member read records")
	}
	if _, err := loginRecordsAnswer(members, nil, member, q, now); err == nil {
		t.Fatal("answered without a journal")
	}
	bad, _ := json.Marshal(loginlog.Query{User: "u1", Limit: 0})
	if _, err := loginRecordsAnswer(members, store, member, bad, now); err == nil {
		t.Fatal("invalid query answered")
	}
}

func TestPeerLoginPageRejectsForeignItems(t *testing.T) {
	q := loginlog.Query{User: "u1", Limit: 2}
	rec := func(at int64, node, user string) loginlog.Record {
		return loginlog.Record{Schema: 1, ID: "r" + node + user, Node: node, At: at, LastAt: at, Count: 1, User: user, Reason: "denied"}
	}
	page := func(items ...loginlog.Record) []byte {
		raw, _ := json.Marshal(loginlog.Page{Items: items})
		return raw
	}
	if p := peerLoginPage(page(rec(20, "node-b", "u1"), rec(10, "node-b", "u1")), "node-b", q); len(p.Items) != 2 || len(p.Missing) != 0 {
		t.Fatalf("good page = %+v", p)
	}
	for name, data := range map[string][]byte{
		"other user":   page(rec(10, "node-b", "u2")),
		"other node":   page(rec(10, "node-c", "u1")),
		"too many":     page(rec(30, "node-b", "u1"), rec(20, "node-b", "u1"), rec(10, "node-b", "u1")),
		"out of order": page(rec(10, "node-b", "u1"), rec(20, "node-b", "u1")),
		"invalid":      page(loginlog.Record{Schema: 1, Node: "node-b", User: "u1"}),
		"missing list": []byte(`{"Items":[],"Missing":["node-x"]}`),
		"not json":     []byte(`{`),
	} {
		if p := peerLoginPage(data, "node-b", q); len(p.Items) != 0 || len(p.Missing) != 1 || p.Missing[0] != "node-b" {
			t.Errorf("%s accepted: %+v", name, p)
		}
	}
	after := loginlog.Query{User: "u1", Limit: 2, After: loginlog.Cursor{At: 15, Node: "node-b", ID: "x"}.String()}
	if p := peerLoginPage(page(rec(20, "node-b", "u1")), "node-b", after); len(p.Missing) != 1 {
		t.Fatalf("record before the cursor accepted: %+v", p)
	}
}
