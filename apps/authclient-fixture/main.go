// SPDX-License-Identifier: Apache-2.0

// authclient-fixture is a finite native test client, not the management UI.
package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"os"
	"time"

	"github.com/jay94ks/seafield/internal/identity"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/internal/userauth"
)

func main() {
	if run() != nil {
		_, _ = os.Stderr.WriteString("authentication fixture failed\n")
		os.Exit(1)
	}
}

func run() error {
	var input struct {
		Cluster      [32]byte
		Local, Voter sfcp.Peer
		Username     string
		PrivateKey   []byte
	}
	decoder := json.NewDecoder(io.LimitReader(os.Stdin, 16<<10))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&input) != nil || len(input.PrivateKey) != ed25519.PrivateKeySize {
		return errors.New("input")
	}
	defer clear(input.PrivateKey)
	self, err := identity.Ephemeral()
	if err != nil {
		return err
	}
	defer clear(self.Private)
	mesh, err := sfcp.NewTransport(self, input.Cluster, func(k sfcp.Identity) (sfcp.Peer, bool) {
		if k == input.Local.Key {
			return input.Local, true
		}
		return input.Voter, k == input.Voter.Key
	})
	if err != nil {
		return err
	}
	defer mesh.Close()
	c := userauth.Client{Self: self, Mesh: mesh, Cluster: input.Cluster, Peers: []sfcp.Peer{input.Local, input.Voter}}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	// The non-voter relays a private-key login to the leader, which issues it.
	if relayed, err := c.Login(ctx, input.Local, input.Username, input.PrivateKey); err != nil || relayed.Issuer != [32]byte(input.Voter.Key) {
		return errors.New("non-voter login relay")
	}
	s, err := c.Login(ctx, input.Voter, input.Username, input.PrivateKey)
	if err != nil {
		return err
	}
	r, err := c.Query(ctx, input.Voter, s, "whoami", "")
	if err != nil || r.User == nil || r.User.Username != input.Username {
		return errors.New("user query")
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"User": r.User.ID, "LocalCode": "relayed", "Issuer": s.Issuer, "Voter": input.Voter.ID})
}
