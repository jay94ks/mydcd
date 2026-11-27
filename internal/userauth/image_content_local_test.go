// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/jay94ks/seafield/internal/registryclient"
	"github.com/jay94ks/seafield/internal/sfcp"
)

type localContentBody struct {
	*bytes.Reader
	closed atomic.Bool
}

func (b *localContentBody) Close() error { b.closed.Store(true); return nil }

func TestLocalSourceUsesSameCompleteBodyAndFinalAuthorityContractAsWire(t *testing.T) {
	for _, mode := range []string{"ok", "truncated", "corrupt", "extra", "revoked", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			payload := bytes.Repeat([]byte("source-body"), 4000)
			q := registryclient.ContentQuery{Ref: "registry.example/team/app@sha256:" + strings.Repeat("a", 64), Kind: "layer", Digest: fmt.Sprintf("sha256:%x", sha256.Sum256(payload))}
			info := registryclient.ContentInfo{Schema: 1, Ref: q.Ref, Kind: q.Kind, Digest: q.Digest, MediaType: string(types.OCILayer), Bytes: int64(len(payload))}
			raw := bytes.Clone(payload)
			switch mode {
			case "truncated":
				raw = raw[:len(raw)-1]
			case "corrupt":
				raw[0] ^= 1
			case "extra":
				raw = append(raw, 'x')
			}
			body := &localContentBody{Reader: bytes.NewReader(raw)}
			calls := 0
			source := ImageContentSource{Info: info, Body: body, Authorize: func(context.Context) error {
				calls++
				if mode == "revoked" && calls > 1 {
					return sfcp.ErrAdmission
				}
				return nil
			}}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if mode == "cancelled" {
				cancel()
			}
			var output bytes.Buffer
			got, err := ReadImageContentSource(ctx, q, source, &output)
			if mode == "ok" {
				if err != nil || got != info || !bytes.Equal(output.Bytes(), payload) {
					t.Fatal(got, err)
				}
			} else if err == nil {
				t.Fatal("incomplete/revoked/cancelled local source accepted", mode)
			}
			if !body.closed.Load() {
				t.Fatal("local source body was not joined")
			}
		})
	}
}

func TestLocalSourceDoesNotHideConsumerWriteFailure(t *testing.T) {
	q := registryclient.ContentQuery{Ref: "registry.example/team/app@sha256:" + strings.Repeat("a", 64), Kind: "layer", Digest: fmt.Sprintf("sha256:%x", sha256.Sum256([]byte("layer")))}
	for _, cause := range []error{nil, io.ErrClosedPipe} {
		body := &localContentBody{Reader: bytes.NewReader([]byte("layer"))}
		source := ImageContentSource{Info: registryclient.ContentInfo{Schema: 1, Ref: q.Ref, Kind: q.Kind, Digest: q.Digest, MediaType: string(types.OCILayer), Bytes: 5}, Body: body, Authorize: func(context.Context) error { return nil }}
		want := cause
		if want == nil {
			want = io.ErrShortWrite
		}
		if _, err := ReadImageContentSource(context.Background(), q, source, localContentWriter{cause}); !errors.Is(err, want) || !body.closed.Load() {
			t.Fatal("consumer failure hidden or source retained", err)
		}
	}
}

type localContentWriter struct{ err error }

func (w localContentWriter) Write([]byte) (int, error) { return 0, w.err }
