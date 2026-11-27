// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"context"
	"github.com/jay94ks/seafield/internal/buildinfo"

	"github.com/jay94ks/seafield/internal/sfcp"
)

// ServerVersion is deliberately independent of a session and a quorum view.
// The transport still authenticates the configured responding server key.
type ServerVersion struct {
	Version   string
	Protocol  uint8
	Commit    string `json:",omitempty"`
	BuildTime string `json:",omitempty"`
}

func localServerVersion() ServerVersion {
	src := buildinfo.Source()
	return ServerVersion{Version: buildinfo.Version(), Protocol: 1, Commit: src.Commit, BuildTime: src.Time}
}
func (c Client) ServerVersion(ctx context.Context, target sfcp.Peer) (ServerVersion, error) {
	body, err := sessionlessRequest(ServerVersionMethod, NoParams{})
	if err != nil {
		return ServerVersion{}, err
	}
	reply, _, err := c.exchange(ctx, target, func(*sfcp.Session) (Envelope, error) { return Envelope{Body: body}, nil }, false)
	if err != nil {
		return ServerVersion{}, err
	}
	v, ok := replyData[ServerVersion](reply)
	if !ok || v.Version == "" || v.Protocol != 1 || len(v.Commit) > 128 || len(v.BuildTime) > 128 {
		return ServerVersion{}, sfcp.ErrAdmission
	}
	return v, nil
}
