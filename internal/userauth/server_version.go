// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"context"
	"reflect"
	"runtime/debug"

	"github.com/jay94ks/mydcd/internal/mydcp"
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
	v := ServerVersion{Version: "1", Protocol: 1}
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, setting := range info.Settings {
			switch setting.Key {
			case "vcs.revision":
				v.Commit = setting.Value
			case "vcs.time":
				v.BuildTime = setting.Value
			}
		}
	}
	return v
}
func (r Request) validServerVersion() bool {
	return r.Method == "server-version" && reflect.DeepEqual(r, Request{Schema: r.Schema, Method: r.Method, Nonce: r.Nonce})
}
func (c Client) ServerVersion(ctx context.Context, target mydcp.Peer) (ServerVersion, error) {
	body, err := requestBody(Request{Method: "server-version"})
	if err != nil {
		return ServerVersion{}, err
	}
	reply, _, err := c.exchange(ctx, target, func(*mydcp.Session) (Envelope, error) { return Envelope{Body: body}, nil }, false)
	if err != nil {
		return ServerVersion{}, err
	}
	if reply.ServerVersion == nil || reply.ServerVersion.Version == "" || reply.ServerVersion.Protocol != 1 || len(reply.ServerVersion.Commit) > 128 || len(reply.ServerVersion.BuildTime) > 128 {
		return ServerVersion{}, mydcp.ErrAdmission
	}
	return *reply.ServerVersion, nil
}
