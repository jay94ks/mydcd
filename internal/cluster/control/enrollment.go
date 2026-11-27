// SPDX-License-Identifier: Apache-2.0

package control

import (
	"encoding/hex"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/state"
)

type Enrollment struct {
	Schema    uint8
	RequestID string
	User      access.User
}

func (e Enrollment) Command(anchor [32]byte) (state.Command, error) {
	if e.Schema != 1 || e.RequestID == "" || len(e.User.Credentials) != 1 || e.User.Credentials[0].Method != access.PrivateKey || e.User.Credentials[0].PublicKey != anchor {
		return state.Command{}, access.ErrDenied
	}
	c, err := access.New(anchor)
	if err != nil {
		return state.Command{}, err
	}
	if _, err = c.Enroll(anchor, e.User); err != nil {
		return state.Command{}, err
	}
	raw, err := ChangeBytes("enroll", "", 0, e.User)
	if err != nil {
		return state.Command{}, err
	}
	command := state.Command{Kind: state.Module, Actor: hex.EncodeToString(anchor[:]), Epoch: 1, RequestID: e.RequestID, Key: CatalogKey, Value: string(raw)}
	_, err = state.EncodeCommand(command)
	return command, err
}
