// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"context"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cliprofile"
	"github.com/jay94ks/seafield/internal/sfcp"
)

// UserCredentials reads a single owned public account record for a system
// administrator. Username selects the target, not the current actor/session.
func (c Client) UserCredentials(ctx context.Context, peer sfcp.Peer, session access.Session, username string) (Reply, error) {
	if !cliprofile.ValidUsername(username) {
		return Reply{}, access.ErrInvalid
	}
	return c.query(ctx, peer, session, Request{Method: "user-credentials", TargetUser: username})
}
