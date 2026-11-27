// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"context"
	"errors"
	"time"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/lifecycle"
	"github.com/jay94ks/seafield/internal/sfcp"
)

// LifecyclesQuery selects one page of a tenant's lifecycle book: its policy
// and every script version.
type LifecyclesQuery struct {
	Tenant string
	After  string `json:",omitempty"`
}

func (q LifecyclesQuery) Valid() bool { return lifecycle.ValidID(q.Tenant) && len(q.After) <= 512 }

// LifecyclesPage is one lifecycle entry and the cursor of the next.
// Revision is the book's own revision and RootRevision the committed
// object's; a reader joining pages requires both to stay the same.
type LifecyclesPage struct {
	Items        []control.LifecycleEntry
	Next         string `json:",omitempty"`
	Revision     uint64
	RootRevision uint64
}

// LifecyclesMethod needs ManageServices in the tenant (checked by
// control.Policy.LifecyclePage).
var LifecyclesMethod = define(Method[LifecyclesQuery, LifecyclesPage]{Name: "lifecycles"}, true, func(_ context.Context, s Service, view cluster.View, session access.Session, q LifecyclesQuery) (LifecyclesPage, string) {
	book, err := s.Policy.Lifecycles(view.State)
	if err != nil {
		return LifecyclesPage{}, "unavailable"
	}
	items, next, err := s.Policy.LifecyclePage(view.State, session, time.Now().Unix(), q.Tenant, q.After)
	if errors.Is(err, access.ErrDenied) {
		return LifecyclesPage{}, "denied"
	} else if err != nil {
		return LifecyclesPage{}, "unavailable"
	}
	return LifecyclesPage{Items: items, Next: next, Revision: book.Revision(), RootRevision: view.State.Object(control.LifecycleKey).Revision}, "ok"
})

// Lifecycles reads one page of a tenant's lifecycle book.
func (c Client) Lifecycles(ctx context.Context, target sfcp.Peer, session access.Session, q LifecyclesQuery) (LifecyclesPage, error) {
	return call(ctx, c, target, session, LifecyclesMethod, q)
}
