// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"net/http"

	"github.com/jay94ks/mydcd/internal/web/mydc"
)

// GET /api/v1/me/credentials: the caller's own login methods (public data
// only) and the account revision to use as expected for add/disable.
func (s *Server) handleOwnCredentials(w http.ResponseWriter, r *http.Request, ws *webSession) {
	read(s, w, r, ws, func(ctx context.Context, c mydc.Conn) (publicUserView, error) {
		u, err := c.OwnCredentials(ctx)
		return publicUserRow(u), err
	})
}

// userView / publicUserView: mydcd's user rows plus accountRevision (=
// Revision, the Expected of credential changes) that screens read.
type userView struct {
	mydc.User
	AccountRevision uint64 `json:"accountRevision"`
}

type publicUserView struct {
	mydc.PublicUser
	AccountRevision uint64 `json:"accountRevision"`
}

func publicUserRow(u mydc.PublicUser) publicUserView {
	return publicUserView{PublicUser: u, AccountRevision: u.Revision}
}

// mapPage reshapes a page's rows for a screen and keeps its paging fields.
func mapPage[T, U any](p mydc.Page[T], f func(T) U) mydc.Page[U] {
	out := mydc.Page[U]{Items: make([]U, 0, len(p.Items)), Next: p.Next, Revision: p.Revision, Collection: p.Collection, ApprovalRevision: p.ApprovalRevision}
	for _, x := range p.Items {
		out.Items = append(out.Items, f(x))
	}
	return out
}
