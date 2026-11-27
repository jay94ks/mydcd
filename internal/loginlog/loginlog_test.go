// SPDX-License-Identifier: Apache-2.0

package loginlog

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/storage"
)

func openStore(t *testing.T, node string) *Store {
	t.Helper()
	db, err := storage.Open(filepath.Join(t.TempDir(), "reports.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	s, err := Open(db, node)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func failure(user, source string) Record {
	return Record{User: user, Username: "alice", Reason: "denied", Method: access.Password, Credential: "pw", Source: source}
}

func TestStoreCoalescesCapsAndPages(t *testing.T) {
	s := openStore(t, "node-a")
	now := time.Unix(1_800_000_000, 0)
	for i := 0; i < 3; i++ {
		if err := s.Add(failure("u1", "10.0.0.9"), now.Add(time.Duration(i)*time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	p, err := s.Page(Query{User: "u1", Limit: 10}, now.Add(time.Minute))
	if err != nil || len(p.Items) != 1 || p.Items[0].Count != 3 || p.Items[0].LastAt != now.Add(2*time.Second).UnixMilli() {
		t.Fatalf("coalesced page = %+v, %v", p, err)
	}
	// Another source, a throttled reason and a success are separate rows.
	_ = s.Add(failure("u1", "10.0.0.8"), now.Add(3*time.Second))
	f := failure("u1", "10.0.0.8")
	f.Reason = "throttled"
	_ = s.Add(f, now.Add(4*time.Second))
	ok := Record{User: "u1", Username: "alice", OK: true, Method: access.PrivateKey, Credential: "k1", Session: "s1", ExpiresAt: now.Unix() + 3600, AccountRevision: 4, Client: Client{Client: "Firefox", Address: "203.0.113.5"}}
	if err := s.Add(ok, now.Add(5*time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := s.Add(Record{User: "u1", OK: true}, now); err == nil {
		t.Fatal("success without session stored")
	}
	p, _ = s.Page(Query{User: "u1", Limit: 2}, now.Add(time.Minute))
	if len(p.Items) != 2 || !p.Items[0].OK || p.Items[0].Session != "s1" || p.Items[1].Reason != "throttled" || p.Next == "" {
		t.Fatalf("first page = %+v", p)
	}
	p, _ = s.Page(Query{User: "u1", Limit: 2, After: p.Next}, now.Add(time.Minute))
	if len(p.Items) != 2 || p.Next != "" || p.Items[1].Count != 3 {
		t.Fatalf("second page = %+v", p)
	}
	// Other accounts never appear.
	if p, _ := s.Page(Query{User: "u2", Limit: 10}, now); len(p.Items) != 0 {
		t.Fatalf("other user = %+v", p)
	}
	// The per-user cap keeps the newest PerUser rows.
	for i := 0; i < PerUser+5; i++ {
		_ = s.Add(failure("u3", "10.0.0."+string(rune('a'+i%26))+string(rune('a'+i/26))), now.Add(time.Duration(i)*time.Second))
	}
	all, _ := s.Page(Query{User: "u3", Limit: MaxPage}, now.Add(time.Hour))
	if len(all.Items) != PerUser || all.Items[len(all.Items)-1].At != now.Add(5*time.Second).UnixMilli() {
		t.Fatalf("capped = %d rows, oldest %d", len(all.Items), all.Items[len(all.Items)-1].At)
	}
	// Retention hides and then removes old rows.
	if p, _ := s.Page(Query{User: "u1", Limit: 10}, now.Add(Retention+time.Hour)); len(p.Items) != 0 {
		t.Fatalf("expired rows shown: %+v", p)
	}
}

func TestMergeOrdersAcrossNodes(t *testing.T) {
	a, b := openStore(t, "node-a"), openStore(t, "node-b")
	now := time.Unix(1_800_000_000, 0)
	for i := 0; i < 3; i++ {
		_ = a.Add(failure("u1", "a"+string(rune('0'+i))), now.Add(time.Duration(2*i)*time.Minute))
		_ = b.Add(failure("u1", "b"+string(rune('0'+i))), now.Add(time.Duration(2*i+1)*time.Minute))
	}
	var seen []string
	after := ""
	for {
		q := Query{User: "u1", Limit: 4, After: after}
		pa, _ := a.Page(q, now.Add(time.Hour))
		pb, _ := b.Page(q, now.Add(time.Hour))
		m := Merge([]Page{pa, pb, {Missing: []string{"node-c"}}}, q.Limit)
		if len(m.Missing) != 1 {
			t.Fatalf("missing = %v", m.Missing)
		}
		for _, r := range m.Items {
			seen = append(seen, r.Source)
		}
		if m.Next == "" {
			break
		}
		after = m.Next
	}
	want := []string{"b2", "a2", "b1", "a1", "b0", "a0"}
	if len(seen) != len(want) {
		t.Fatalf("seen = %v", seen)
	}
	for i := range want {
		if seen[i] != want[i] {
			t.Fatalf("seen = %v", seen)
		}
	}
	if _, _, err := ParseCursor("x/y"); err == nil {
		t.Fatal("bad cursor accepted")
	}
	if (Client{Client: "a\nb"}).Valid() {
		t.Fatal("control character accepted")
	}
}
