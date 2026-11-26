// SPDX-License-Identifier: Apache-2.0

// Package engine owns the local Docker SDK connection and resource identities.
// Network and workload remain the owners of their respective Engine objects.
package engine

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/jay94ks/mydcd/internal/reconcile"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/moby/moby/client"
)

var ErrOwnership = errors.New("Docker resource identity or specification mismatch")

type Client struct {
	API       *client.Client
	Owner     string
	imageAPI  *client.Client
	stopAPI   *client.Client
	streamAPI *client.Client
	execAPI   *client.Client
	execIdle  func()
}

// Open permits only an explicit local UDS. DOCKER_HOST and ambient TLS/env
// settings cannot silently redirect privileged node operations elsewhere.
func Open(ctx context.Context, endpoint, owner string) (*Client, error) {
	return open(ctx, endpoint, owner, 30*time.Second)
}

func open(ctx context.Context, endpoint, owner string, timeout time.Duration) (*Client, error) {
	if !strings.HasPrefix(endpoint, "unix://") || !filepath.IsAbs(strings.TrimPrefix(endpoint, "unix://")) || owner == "" || len(owner) > 256 {
		return nil, errors.New("explicit local Docker UDS and owner required")
	}
	api, err := client.New(client.WithHost(endpoint), client.WithAPIVersionNegotiation(), client.WithTimeout(timeout))
	if err != nil {
		return nil, err
	}
	ping, err := api.Ping(ctx, client.PingOptions{NegotiateAPIVersion: true})
	if err != nil {
		_ = api.Close()
		return nil, err
	}
	if err = checkEngineAPI(ping.APIVersion); err != nil {
		_ = api.Close()
		return nil, err
	}
	images, err := imageClient(endpoint, timeout)
	if err != nil {
		_ = api.Close()
		return nil, err
	}
	// Stop uses its declared grace/context, not the ordinary short RPC cap.
	// This client stays on the exact configured local Engine endpoint.
	stops, err := client.New(client.WithHost(endpoint), client.WithAPIVersionNegotiation(), client.WithTimeout(0))
	if err != nil {
		_ = api.Close()
		_ = images.Close()
		return nil, err
	}
	streams, err := streamClient(endpoint, api.ClientVersion())
	if err != nil {
		_ = api.Close()
		_ = images.Close()
		_ = stops.Close()
		return nil, err
	}
	execs, closeExec, err := execInspectClient(endpoint, timeout, api.ClientVersion())
	if err != nil {
		_ = api.Close()
		_ = images.Close()
		_ = stops.Close()
		_ = streams.Close()
		return nil, err
	}
	return &Client{API: api, Owner: owner, imageAPI: images, stopAPI: stops, streamAPI: streams, execAPI: execs, execIdle: closeExec}, nil
}

// MinimumAPI is Docker Engine 28.0's API. Managed bridges use its
// nat-unprotected gateway mode; an older Engine rejects that network create,
// which would otherwise leave the bridge journal waiting forever.
const MinimumAPI = "1.48"

var ErrEngineVersion = errors.New("Docker Engine 28.0 (API " + MinimumAPI + ") or newer is required")

func checkEngineAPI(version string) error {
	major, minor, ok := strings.Cut(version, ".")
	if !ok {
		return fmt.Errorf("%w; the Engine reports API %q", ErrEngineVersion, version)
	}
	a, errA := strconv.Atoi(major)
	b, errB := strconv.Atoi(minor)
	if errA != nil || errB != nil || a < 1 || a == 1 && b < 48 {
		return fmt.Errorf("%w; the Engine reports API %q", ErrEngineVersion, version)
	}
	return nil
}

func (c *Client) Close() error {
	err := c.API.Close()
	if c.execAPI != nil {
		err = errors.Join(err, c.execAPI.Close())
	}
	if c.execIdle != nil {
		c.execIdle()
	}
	if c.imageAPI != nil {
		err = errors.Join(err, c.imageAPI.Close())
	}
	if c.stopAPI != nil {
		err = errors.Join(err, c.stopAPI.Close())
	}
	if c.streamAPI != nil {
		err = errors.Join(err, c.streamAPI.Close())
	}
	return err
}

// StreamingAPI bounds dialing/response headers while allowing a context-bound
// response body. Stop retains its independent declared grace budget.
func (c *Client) StreamingAPI() (*client.Client, error) {
	if c == nil || c.streamAPI == nil {
		return nil, ErrOwnership
	}
	return c.streamAPI, nil
}

type Identity struct {
	Name   string
	Labels map[string]string
}

// Owner is shared by physical identities and their deterministic admission.
func Owner(cluster, key [32]byte) string {
	return hex.EncodeToString(cluster[:]) + "/" + hex.EncodeToString(key[:])
}

func (c *Client) Identity(kind, key string, r reconcile.Resource) (Identity, error) {
	if (kind != "bridge" && kind != "container" && kind != "volume") || key == "" || len(key) > 512 || r.Generation == 0 || !r.Present || r.Spec == "" {
		return Identity{}, ErrOwnership
	}
	digest := sha256.Sum256([]byte(r.Spec))
	return c.IdentityDigest(kind, key, r.Generation, digest)
}

// IdentityDigest reuses the same identity algorithm for a retained private
// reference that stores the original spec hash rather than duplicating Spec.
func (c *Client) IdentityDigest(kind, key string, generation uint64, digest [32]byte) (Identity, error) {
	if (kind != "bridge" && kind != "container" && kind != "volume") || key == "" || len(key) > 512 || generation == 0 || digest == ([32]byte{}) {
		return Identity{}, ErrOwnership
	}
	gen := strconv.FormatUint(generation, 10)
	nameHash := sha256.Sum256([]byte(c.Owner + "\x00" + kind + "\x00" + key + "\x00" + gen))
	return Identity{Name: fmt.Sprintf("mydc-%s-%x", kind, nameHash[:12]), Labels: map[string]string{
		"org.mydc.owner": c.Owner, "org.mydc.kind": kind, "org.mydc.key": key, "org.mydc.generation": gen, "org.mydc.spec": hex.EncodeToString(digest[:]),
	}}, nil
}

// IdentityForOwner reads an exact retained native Task identity on this same
// local Engine. The caller verifies the committed resource/key lineage first;
// no connection, key material, owner metadata or current authority is changed.
func (c *Client) IdentityForOwner(owner, kind, key string, r reconcile.Resource) (Identity, error) {
	if owner == "" || len(owner) > 256 {
		return Identity{}, ErrOwnership
	}
	alias := *c
	alias.Owner = owner
	return alias.Identity(kind, key, r)
}

func (i Identity) Matches(name string, labels map[string]string) bool {
	if strings.TrimPrefix(name, "/") != i.Name {
		return false
	}
	for k, v := range i.Labels {
		if labels[k] != v {
			return false
		}
	}
	return true
}
