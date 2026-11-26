// SPDX-License-Identifier: Apache-2.0

package store

import (
	"path/filepath"
	"testing"
	"time"
)

func TestAuditAndNotificationRetention(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "web.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	now := time.Now()
	old, recent := now.Add(-48*time.Hour), now.Add(-time.Hour)
	s.AppendAudit(&AuditEntry{ID: "a", At: old, Area: "x"})
	s.AppendAudit(&AuditEntry{ID: "b", At: recent, Area: "x"})
	for _, u := range []string{"u1", "u2", "u10"} {
		s.PutNotification(&Notification{ID: "o", User: u, CreatedAt: old})
		s.PutNotification(&Notification{ID: "r", User: u, CreatedAt: recent})
	}
	if n, _ := s.PruneAudit(now.Add(-24 * time.Hour)); n != 1 {
		t.Fatalf("audit pruned %d", n)
	}
	if n, _ := s.PruneNotifications(now.Add(-24 * time.Hour)); n != 3 {
		t.Fatalf("notifications pruned %d", n)
	}
	es, _ := s.ListAudit(time.Time{}, 10, nil)
	if len(es) != 1 || es[0].ID != "b" {
		t.Fatalf("audit left: %+v", es)
	}
	for _, u := range []string{"u1", "u2", "u10"} {
		ns, unread, _ := s.ListNotifications(u, false, 10)
		if len(ns) != 1 || ns[0].ID != "r" || unread != 1 {
			t.Fatalf("%s left: %+v", u, ns)
		}
	}
	// paging: entries strictly older than before
	s.AppendAudit(&AuditEntry{ID: "c", At: now, Area: "x"})
	es, _ = s.ListAudit(now, 10, nil)
	if len(es) != 1 || es[0].ID != "b" {
		t.Fatalf("before page: %+v", es)
	}
}
