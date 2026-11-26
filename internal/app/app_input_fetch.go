// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"context"
	"encoding/json"
	"time"

	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/deployment"
	"github.com/jay94ks/mydcd/internal/mydcp"
	"github.com/jay94ks/mydcd/internal/schema"
	"github.com/jay94ks/mydcd/internal/secrets"
)

type appInputFetchResponse struct {
	Schema  uint8
	ReadSet [32]byte
	Value   secrets.Fetched
}

// Ordinary JSON encoding of Fetched remains forbidden. Only this dedicated
// sensitive wire boundary removes that method locally; it never makes the
// private material a management/snapshot/operation serializable type.
func encodeAppInputFetchResponse(readSet [32]byte, value secrets.Fetched) ([]byte, error) {
	type privateWireValue secrets.Fetched
	body, err := json.Marshal(struct {
		Schema  uint8
		ReadSet [32]byte
		Value   privateWireValue
	}{1, readSet, privateWireValue(value)})
	if err != nil {
		return nil, err
	}
	if len(body) > (128<<10)-48 {
		clear(body)
		return nil, mydcp.ErrBudget
	}
	return body, nil
}

func decodeAppInputFetchResponse(raw []byte) (appInputFetchResponse, error) {
	var response appInputFetchResponse
	err := json.Unmarshal(raw, &response)
	canonical, encodeErr := encodeAppInputFetchResponse(response.ReadSet, response.Value)
	defer clear(canonical)
	if err != nil || encodeErr != nil || response.Schema != 1 || !bytes.Equal(canonical, raw) {
		for _, v := range response.Value.Values {
			clear(v)
		}
		return appInputFetchResponse{}, mydcp.ErrFrame
	}
	return response, nil
}

func (r *Runtime) appInputFetchPermit(ctx context.Context, q control.AppInputFetch) (control.AppInputFetchPermit, error) {
	q.Binding.At = time.Now().Unix()
	raw, _ := json.Marshal(q)
	reply, err := r.appCall(ctx, "app-input-read-permit", raw)
	if err != nil {
		return control.AppInputFetchPermit{}, err
	}
	p, err := schema.Decode[control.AppInputFetchPermit](reply.Data)
	if err != nil || p.Schema != 1 || p.ReadSet != q.ReadSet || p.CommandIndex < q.MinimumIndex || p.Realm != q.Realm || p.Leaf.Secret != q.Secret || !r.acceptsResourceOwner(ctx, p.Provider.Node, p.Provider.Key) {
		return control.AppInputFetchPermit{}, deployment.ErrInputs
	}
	return p, nil
}

func (r *Runtime) readAppInputLeaf(ctx context.Context, q control.AppInputFetch) (secrets.Fetched, error) {
	permit, err := r.appInputFetchPermit(ctx, q)
	if err != nil {
		return secrets.Fetched{}, err
	}
	r.life.RLock()
	if r.closed || r.ctx.Err() != nil {
		r.life.RUnlock()
		return secrets.Fetched{}, secrets.ErrProvider
	}
	backend := r.vaultBackends[vaultBackendKey(permit.Realm, permit.Leaf.Reference.Profile)]
	if backend == nil || !backend.config.Values || (backend.config.Mode == "local-file") != (permit.Provider.Mode == "local-file") {
		r.life.RUnlock()
		return secrets.Fetched{}, secrets.ErrProvider
	}
	value, err := backend.provider.Fetch(ctx, permit.Leaf.Secret, permit.Leaf.Reference)
	r.life.RUnlock()
	good := false
	defer func() {
		if !good {
			for _, v := range value.Values {
				clear(v)
			}
		}
	}()
	if err != nil {
		return secrets.Fetched{}, err
	}
	latest, err := r.appInputFetchPermit(ctx, q)
	// Unrelated commits may advance the index; authority/source must not change.
	permit.CommandIndex = 0
	latest.CommandIndex = 0
	a, _ := json.Marshal(permit)
	b, _ := json.Marshal(latest)
	if err != nil || !bytes.Equal(a, b) {
		return secrets.Fetched{}, deployment.ErrInputs
	}
	good = true
	return value, nil
}

func (r *Runtime) serveAppInputFetch() error {
	return r.Mesh.OnSecretFetch(func(ctx context.Context, s *mydcp.Session, body []byte) ([]byte, error) {
		q, err := schema.Decode[control.AppInputFetch](body)
		if err != nil || q.Consumer != [32]byte(s.Peer().Key) {
			return nil, mydcp.ErrAdmission
		}
		ctx, cancel := context.WithCancel(ctx)
		defer cancel()
		stop := context.AfterFunc(r.ctx, cancel)
		defer stop()
		value, err := r.readAppInputLeaf(ctx, q)
		defer func() {
			for _, v := range value.Values {
				clear(v)
			}
		}()
		if err != nil {
			return nil, err
		}
		return encodeAppInputFetchResponse(q.ReadSet, value)
	})
}

func (r *Runtime) fetchAppInputLeaf(ctx context.Context, q control.AppInputFetch, profile secrets.WriteProfile) (secrets.Fetched, error) {
	if r.acceptsResourceOwner(ctx, profile.Node, profile.Key) {
		return r.readAppInputLeaf(ctx, q)
	}
	peer, ok := r.resourcePeer(ctx, profile.Node, profile.Key)
	if !ok || !peer.Member || peer.ID != profile.Node {
		return secrets.Fetched{}, mydcp.ErrAdmission
	}
	s, err := r.Mesh.Dial(ctx, peer)
	if err != nil {
		return secrets.Fetched{}, err
	}
	body, _ := json.Marshal(q)
	defer clear(body)
	raw, err := s.FetchSecret(ctx, body)
	if err != nil {
		return secrets.Fetched{}, err
	}
	defer clear(raw)
	response, err := decodeAppInputFetchResponse(raw)
	if err != nil || response.ReadSet != q.ReadSet || response.Value.Secret != q.Secret {
		for _, v := range response.Value.Values {
			clear(v)
		}
		return secrets.Fetched{}, mydcp.ErrAdmission
	}
	return response.Value, nil
}
