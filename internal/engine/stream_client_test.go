// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/moby/moby/client"
)

func TestStreamSDKKeepsExplicitUDSAndContextBodyWithoutChangingMetadataDeadline(t *testing.T) {
	root, err := os.MkdirTemp("", "mydc-rv5-sdk-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root)
	listener, err := net.Listen("unix", filepath.Join(root, "engine.sock"))
	if err != nil {
		t.Fatal(err)
	}
	ended := make(chan struct{})
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/_ping":
			w.Header().Set("API-Version", "1.53")
			_, _ = io.WriteString(w, "OK")
		case strings.HasSuffix(r.URL.Path, "/info"):
			<-r.Context().Done()
		case strings.HasSuffix(r.URL.Path, "/containers/original/logs"):
			defer close(ended)
			w.Header().Set("Content-Type", "application/vnd.docker.raw-stream")
			w.WriteHeader(http.StatusOK)
			w.(http.Flusher).Flush()
			select {
			case <-time.After(250 * time.Millisecond):
				_, _ = io.WriteString(w, "after-metadata-deadline")
				w.(http.Flusher).Flush()
			case <-r.Context().Done():
				return
			}
			<-r.Context().Done()
		default:
			http.NotFound(w, r)
		}
	})}
	serving := make(chan struct{})
	go func() { _ = server.Serve(listener); close(serving) }()
	defer func() { _ = server.Close(); <-serving }()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	c, err := open(ctx, "unix://"+listener.Addr().String(), "owned-sdk-fixture", 100*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	api, err := c.StreamingAPI()
	if err != nil || api == c.API || api == c.stopAPI || api.ClientVersion() != c.API.ClientVersion() {
		t.Fatal("stream client changed endpoint/version ownership", err)
	}
	bodyCtx, finish := context.WithCancel(ctx)
	defer finish()
	body, err := api.ContainerLogs(bodyCtx, "original", client.ContainerLogsOptions{Follow: true, ShowStdout: true})
	if err != nil {
		t.Fatal(err)
	}
	defer body.Close()
	got := make([]byte, len("after-metadata-deadline"))
	if _, err = io.ReadFull(body, got); err != nil || string(got) != "after-metadata-deadline" {
		t.Fatal("stream body inherited ordinary metadata deadline", err)
	}
	if _, err = c.API.Info(ctx, client.InfoOptions{}); err == nil {
		t.Fatal("ordinary metadata client became unbounded")
	}
	finish()
	if _, err = body.Read(make([]byte, 1)); err == nil {
		t.Fatal("live body ignored parent cancellation")
	}
	select {
	case <-ended:
	case <-ctx.Done():
		t.Fatal("SDK body/handler not released", ctx.Err())
	}
	if _, err = streamClient("tcp://127.0.0.1:2375", "1.53"); err == nil {
		t.Fatal("stream client accepted ambient/remote Docker")
	}
}
