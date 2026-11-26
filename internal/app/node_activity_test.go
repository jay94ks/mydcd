// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/jay94ks/mydcd/internal/engine"
	"github.com/jay94ks/mydcd/internal/reconcile"
	"github.com/moby/moby/client"
)

type nodeCensusTransport func(*http.Request) (*http.Response, error)

func (f nodeCensusTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// SDK HTTP fixtures are not a live Docker Engine or native closure proof.
func TestNodeCensusReadsOnlyOwnedDockerInventoryAndRetainsErrors(t *testing.T) {
	for _, test := range []struct {
		name, containers, networks string
		fail                       bool
		resources                  uint32
	}{
		{"empty", `[]`, `[]`, false, 0},
		{"original-container", `[{"Id":"original"}]`, `[]`, false, 1},
		{"orphan-owned-network", `[]`, `[{"Id":"original-network"}]`, false, 1},
		{"daemon-unavailable", `[]`, `[]`, true, 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			api, err := client.New(client.WithHost("http://fixture.invalid"), client.WithAPIVersion("1.52"), client.WithHTTPClient(&http.Client{Transport: nodeCensusTransport(func(request *http.Request) (*http.Response, error) {
				if request.Method != http.MethodGet || !strings.Contains(request.URL.Query().Get("filters"), "org.mydc.owner=original-owner") {
					t.Fatal("unowned or mutating inventory request", request.Method, request.URL)
				}
				status, body := 200, ""
				switch {
				case strings.HasSuffix(request.URL.Path, "/containers/json"):
					body = test.containers
				case strings.HasSuffix(request.URL.Path, "/networks"):
					body = test.networks
				default:
					t.Fatal("unexpected SDK request", request.URL)
				}
				if test.fail {
					status, body = 503, `{"message":"unavailable original daemon"}`
				}
				return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(body))}, nil
			})}))
			if err != nil {
				t.Fatal(err)
			}
			defer api.Close()
			runtime := &Runtime{docker: &engine.Client{API: api, Owner: "original-owner"}}
			activity, err := runtime.nodeLocalActivity(context.Background())
			if (err != nil) != test.fail || !test.fail && activity.Resources != test.resources {
				t.Fatal(activity, err)
			}
		})
	}
}

func TestNodeJournalCensusKeepsOriginalUnknownAndRetainedDataSeparate(t *testing.T) {
	for _, test := range []struct {
		name     string
		record   reconcile.Record
		retained bool
		empty    bool
	}{
		{"unused", reconcile.Record{}, false, true},
		{"terminal", reconcile.Record{State: reconcile.State{GenerationFloor: 3}}, false, true},
		{"desired-before-dispatch", reconcile.Record{State: reconcile.State{Desired: reconcile.Desired{Resource: reconcile.Resource{Present: true}}}}, false, false},
		{"running", reconcile.Record{State: reconcile.State{Applied: reconcile.Resource{Present: true}}}, false, false},
		{"idle-kept-volume", reconcile.Record{State: reconcile.State{Applied: reconcile.Resource{Present: true}}}, true, true},
		{"unknown-volume", reconcile.Record{State: reconcile.State{Pending: &reconcile.Operation{ID: 7, Kind: reconcile.Apply, Phase: reconcile.RecoveryRequired}}}, true, false},
		{"original-pin", reconcile.Record{Consumers: map[string]reconcile.Lease{"original": {Token: 17, Generation: 3}}}, true, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			activity, err := nodeJournalActivity([]string{"original"}, func(key string) (reconcile.Record, error) {
				if key != "original" {
					t.Fatal("census changed original source")
				}
				return test.record, nil
			}, test.retained)
			if err != nil || activity.Empty() != test.empty {
				t.Fatal(activity, err)
			}
		})
	}
	failed := errors.New("original journal unavailable")
	if _, err := nodeJournalActivity([]string{"original"}, func(string) (reconcile.Record, error) { return reconcile.Record{}, failed }, false); !errors.Is(err, failed) {
		t.Fatal("journal error became a zero census")
	}
}
