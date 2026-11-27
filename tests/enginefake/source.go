// SPDX-License-Identifier: Apache-2.0

package enginefake

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"

	dockerspec "github.com/moby/docker-image-spec/specs-go/v1"

	"github.com/jay94ks/seafield/internal/engineimage"
	"github.com/jay94ks/seafield/internal/registryclient"
)

const (
	manifestMedia = "application/vnd.oci.image.manifest.v1+json"
	configMedia   = "application/vnd.oci.image.config.v1+json"
)

// Source is the registry a Published image lives in, as sfcd reads it for an
// anonymous pull (config.Node.AnonymousImages): the root manifest has the
// published digest and one config blob, the image's config, and no layers.
// Only the published digest is a stand-in; the config blob's is real.
func (e *Engine) Source(authority string) (engineimage.Opener, error) {
	return source(authority, func(_ context.Context, ref string) (dockerspec.DockerOCIImage, bool, error) {
		cfg, ok := e.published(ref)
		return cfg, ok, nil
	}), nil
}

// SourceAt is Source for a node in another process: it reads what was
// Published from the engine serving endpoint.
func SourceAt(endpoint string) func(string) (engineimage.Opener, error) {
	socket := strings.TrimPrefix(endpoint, "unix://")
	c := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "unix", socket)
	}}}
	return func(authority string) (engineimage.Opener, error) {
		return source(authority, func(ctx context.Context, ref string) (dockerspec.DockerOCIImage, bool, error) {
			var cfg dockerspec.DockerOCIImage
			req, err := http.NewRequestWithContext(ctx, "GET", "http://engine/enginefake/published?ref="+url.QueryEscape(ref), nil)
			if err != nil {
				return cfg, false, err
			}
			res, err := c.Do(req)
			if err != nil {
				return cfg, false, err
			}
			defer res.Body.Close()
			if res.StatusCode == http.StatusNotFound {
				return cfg, false, nil
			}
			if res.StatusCode != http.StatusOK {
				return cfg, false, &registryclient.Error{Code: "UNAVAILABLE"}
			}
			return cfg, true, json.NewDecoder(res.Body).Decode(&cfg)
		}), nil
	}
}

func (e *Engine) published(ref string) (dockerspec.DockerOCIImage, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	cfg, ok := e.remote[ref]
	if !ok {
		cfg, ok = e.remote[strings.TrimPrefix(ref, "docker.io/")]
	}
	return cfg, ok
}

func (e *Engine) servePublished(w http.ResponseWriter, r *http.Request, _ []string) {
	cfg, ok := e.published(r.URL.Query().Get("ref"))
	if !ok {
		writeError(w, http.StatusNotFound, "not published")
		return
	}
	writeJSON(w, http.StatusOK, cfg)
}

func source(authority string, lookup func(context.Context, string) (dockerspec.DockerOCIImage, bool, error)) engineimage.Opener {
	return func(ctx context.Context, q registryclient.GraphContentQuery, offset int64) (registryclient.ContentInfo, io.ReadCloser, error) {
		name, digest, ok := strings.Cut(q.Root, "@")
		if !ok || len(q.Path) != 0 || offset != 0 || !strings.HasPrefix(name, authority+"/") {
			return registryclient.ContentInfo{}, nil, &registryclient.Error{Code: "NOT_FOUND"}
		}
		cfg, ok, err := lookup(ctx, q.Root)
		if err != nil {
			return registryclient.ContentInfo{}, nil, err
		}
		if !ok {
			return registryclient.ContentInfo{}, nil, &registryclient.Error{Code: "NOT_FOUND"}
		}
		config, err := json.Marshal(cfg)
		if err != nil {
			return registryclient.ContentInfo{}, nil, err
		}
		sum := sha256.Sum256(config)
		configDigest := "sha256:" + hex.EncodeToString(sum[:])
		info := registryclient.ContentInfo{Schema: 1, Ref: q.Root, Kind: q.Kind}
		var body []byte
		switch {
		case q.Kind == "manifest":
			body, err = json.Marshal(map[string]any{"schemaVersion": 2, "mediaType": manifestMedia, "config": map[string]any{"mediaType": configMedia, "digest": configDigest, "size": len(config)}, "layers": []any{}})
			if err != nil {
				return registryclient.ContentInfo{}, nil, err
			}
			info.Digest, info.MediaType = digest, manifestMedia
		case q.Kind == "config" && q.Digest == configDigest:
			body, info.Digest, info.MediaType = config, configDigest, configMedia
		default:
			return registryclient.ContentInfo{}, nil, &registryclient.Error{Code: "NOT_FOUND"}
		}
		info.Bytes = int64(len(body))
		return info, io.NopCloser(bytes.NewReader(body)), nil
	}
}
