// SPDX-License-Identifier: Apache-2.0

package store

import (
	"testing"
	"time"
)

func TestTrashPrune(t *testing.T) {
	s, _ := open(t)
	now := time.Now()
	for _, it := range []*TrashItem{
		{ID: "old", Kind: TrashWebhook, Name: "a", DeletedAt: now.Add(-8 * 24 * time.Hour), ExpiresAt: now.Add(-time.Hour), Data: []byte(`{}`)},
		{ID: "new", Kind: TrashWebhook, Name: "b", DeletedAt: now, ExpiresAt: now.Add(time.Hour), Data: []byte(`{}`)},
	} {
		if err := s.PutTrash(it); err != nil {
			t.Fatal(err)
		}
	}
	if l, err := s.ListTrash(now); err != nil || len(l) != 1 || l[0].ID != "new" {
		t.Fatalf("list: %v %v", l, err)
	}
	if n, err := s.PruneTrash(now); err != nil || n != 1 {
		t.Fatalf("prune: %d %v", n, err)
	}
	if _, err := s.GetTrash("old"); err != ErrNotFound {
		t.Fatalf("old kept: %v", err)
	}
	if it, err := s.TakeTrash("new"); err != nil || it.Name != "b" {
		t.Fatalf("take: %v %v", it, err)
	}
	if _, err := s.TakeTrash("new"); err != ErrNotFound {
		t.Fatalf("take twice: %v", err)
	}
}
