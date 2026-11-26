// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/hex"
	"errors"
	"io/fs"
	"time"

	"github.com/jay94ks/mydcd/internal/cliprofile"
	"github.com/jay94ks/mydcd/internal/config"
)

// commandProfile is a frozen snapshot of where one invocation connects.
// Context names and defaults never become remote IDs, grants or session keys.
type commandProfile struct {
	Client  config.Client
	Target  cliprofile.Selection
	Context string // context name; empty for an explicit --config file
}

// resolveCommandProfile picks the context named by name (else the current
// one), or loads an explicit client file. The file form goes with the old
// command path.
func resolveCommandProfile(home, contextName, file, tenant string) (commandProfile, error) {
	var result commandProfile
	if file != "" {
		if contextName != "" {
			return result, cliprofile.ErrSelection
		}
		c, err := config.LoadClient(file)
		if err != nil {
			return result, err
		}
		result.Client = c
		result.Target.Tenant = tenant
		result.Target.Timeout = 15 * time.Second
		return result, nil
	}
	store, err := cliprofile.OpenStore(home, false)
	if errors.Is(err, fs.ErrNotExist) {
		return result, cliprofile.ErrNoContext
	}
	if err != nil {
		return result, err
	}
	defer store.Close()
	if result.Target, err = store.Resolve(contextName); err != nil {
		return result, err
	}
	if tenant != "" {
		result.Target.Tenant = tenant
	}
	result.Context = result.Target.ClusterName
	result.Client = clientForSelection(result.Target)
	return result, nil
}

func clientForSelection(selected cliprofile.Selection) config.Client {
	client := config.Client{Version: 1, Auth: "user", Cluster: hex.EncodeToString(selected.Cluster[:])}
	for _, pin := range selected.Pins {
		endpoint := pin.Endpoints[0]
		if pin.ID == selected.Peer {
			endpoint = selected.Endpoint
		}
		// A QUIC peer is HOST:PORT in the transport configuration.
		address := endpoint.Address
		if endpoint.Network == "unix" {
			address = endpoint.URI
		}
		client.Peers = append(client.Peers, config.Peer{ID: pin.ID, Key: hex.EncodeToString(pin.Key[:]), Endpoint: address})
	}
	return client
}
