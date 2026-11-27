// SPDX-License-Identifier: Apache-2.0

package volumeshare

import (
	"context"

	"github.com/jay94ks/seafield/internal/sfcp"
)

// Serve answers VolumeFS on t through s.
func Serve(t *sfcp.Transport, s *Server) error {
	return t.OnVolumeFS(func(ctx context.Context, session *sfcp.Session, header, data []byte) ([]byte, []byte, error) {
		return s.Handle(ctx, session.Peer().Key, header, data)
	})
}

// CallHome reaches the home whose node key is home over t. Each call takes
// the current session (dialing when there is none), so a reconnect is
// picked up; a failed dial never sent anything.
func CallHome(t *sfcp.Transport, home sfcp.Identity) Call {
	return func(ctx context.Context, header, data []byte) ([]byte, []byte, error) {
		peer, ok := t.Peer(home)
		if !ok {
			return nil, nil, sfcp.ErrAdmission
		}
		s, err := t.Dial(ctx, peer)
		if err != nil {
			return nil, nil, err
		}
		return s.CallVolumeFS(ctx, header, data)
	}
}
