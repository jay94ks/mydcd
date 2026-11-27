// SPDX-License-Identifier: Apache-2.0

package imagebuild

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jay94ks/seafield/internal/containerops"
	bkclient "github.com/moby/buildkit/client"
	digest "github.com/opencontainers/go-digest"
)

func TestBuildKitProgressKeepsVertexAndStreamSecretPrefixesSeparate(t *testing.T) {
	var output bytes.Buffer
	filter, err := containerops.NewRedactor(&output, []containerops.RedactionValue{{Reference: "vault/key", Value: []byte("private-value")}})
	if err != nil {
		t.Fatal(err)
	}
	defer filter.Destroy()
	a, b := digest.FromString("first"), digest.FromString("second")
	status := make(chan *bkclient.SolveStatus, 3)
	status <- &bkclient.SolveStatus{Vertexes: []*bkclient.Vertex{{Digest: a, Name: "RUN private-value"}}, Logs: []*bkclient.VertexLog{{Vertex: a, Stream: 1, Data: []byte("private-")}, {Vertex: b, Stream: 1, Data: []byte("other\n")}, {Vertex: a, Stream: 2, Data: []byte("stderr\n")}}}
	status <- &bkclient.SolveStatus{Logs: []*bkclient.VertexLog{{Vertex: a, Stream: 1, Data: []byte("value\n")}, {Vertex: b, Stream: 1, Data: []byte("private-")}}}
	status <- &bkclient.SolveStatus{Vertexes: []*bkclient.Vertex{{Digest: a, Name: "RUN duplicate", Error: "opaque private credential error body"}}}
	close(status)
	_, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := writeBuildKitProgress(status, filter, cancel); err != nil {
		t.Fatal(err)
	}
	got := output.String()
	if strings.Contains(got, "private-") || strings.Contains(got, "value") || strings.Contains(got, "credential") || strings.Contains(got, "duplicate") || strings.Count(got, "«가림: vault/key»") != 4 {
		t.Fatal("SDK progress leaked or mixed streams", got)
	}
}

func TestBuildKitProgressStorageFailureCancelsAndDrainsOriginalStatus(t *testing.T) {
	filter, err := containerops.NewRedactor(failedSDKLogWriter{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer filter.Destroy()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	status := make(chan *bkclient.SolveStatus, 2)
	status <- &bkclient.SolveStatus{Logs: []*bkclient.VertexLog{{Vertex: digest.FromString("one"), Stream: 1, Data: []byte("output")}}}
	status <- &bkclient.SolveStatus{Logs: []*bkclient.VertexLog{{Vertex: digest.FromString("two"), Stream: 1, Data: []byte("later output")}}}
	close(status)
	if err := writeBuildKitProgress(status, filter, cancel); !errors.Is(err, ErrStorage) || ctx.Err() == nil || len(status) != 0 {
		t.Fatal("failed log writer left SDK status blocked", err)
	}
}

type failedSDKLogWriter struct{}

func (failedSDKLogWriter) Write([]byte) (int, error) { return 0, errors.New("private storage detail") }

// A failed RUN step's exit status is the one part of its vertex error the
// user log takes; the rest stays out.
func TestBuildKitProgressNamesFailedStepExitCode(t *testing.T) {
	var output bytes.Buffer
	filter, err := containerops.NewRedactor(&output, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer filter.Destroy()
	a, b := digest.FromString("run"), digest.FromString("pull")
	status := make(chan *bkclient.SolveStatus, 2)
	status <- &bkclient.SolveStatus{Vertexes: []*bkclient.Vertex{{Digest: a, Name: "[2/3] RUN make"}, {Digest: b, Name: "[1/3] FROM base"}}}
	status <- &bkclient.SolveStatus{Vertexes: []*bkclient.Vertex{{Digest: a, Name: "[2/3] RUN make", Error: "process \"/bin/sh -c make\" did not complete successfully: exit code: 2"}, {Digest: b, Name: "[1/3] FROM base", Error: "failed to authorize: opaque body exit code: 7"}}}
	close(status)
	_, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := writeBuildKitProgress(status, filter, cancel); err != nil {
		t.Fatal(err)
	}
	got := output.String()
	if !strings.Contains(got, "# failed [2/3] RUN make (exit code 2)\n") || !strings.Contains(got, "# failed [1/3] FROM base\n") || strings.Contains(got, "authorize") || strings.Contains(got, "/bin/sh -c") {
		t.Fatal(got)
	}
}
