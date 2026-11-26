// SPDX-License-Identifier: Apache-2.0

package registryclient

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Actual HTTPS challenge/token exchange through the pinned OCI SDK. This does
// not assert a BuildKit session, Raft approval or real registry layer pull.
func TestPullTokenExchangeUsesOnlyExactRepositoryOwnerCredentials(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var exchanges atomic.Int32
	var origin string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, q *http.Request) {
		switch q.URL.Path {
		case "/v2/":
			if q.Header.Get("Authorization") != "" {
				t.Error("credential was sent before the registry challenge")
			}
			w.Header().Set("WWW-Authenticate", `Bearer realm="`+origin+`/token",service="fixture"`)
			w.WriteHeader(http.StatusUnauthorized)
		case "/token":
			user, password, _ := q.BasicAuth()
			scope := q.URL.Query().Get("scope")
			if q.Method != http.MethodGet || q.URL.Query().Get("service") != "fixture" || scope != "repository:team/"+user+":pull" || password != user+"-private-password" {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte("private token endpoint error body"))
				return
			}
			exchanges.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "token-" + user, "refresh_token": "never-return-this-refresh-token", "expires_in": 120})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	origin = server.URL
	authority := strings.TrimPrefix(server.URL, "https://")
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	for _, user := range []string{"one", "two"} {
		client, err := New(authority, []byte(user), []byte(user+"-private-password"), ca)
		if err != nil {
			t.Fatal(err)
		}
		image := authority + "/team/" + user + "@sha256:" + strings.Repeat("a", 64)
		challenge := PullTokenChallenge{Host: authority, Realm: origin + "/token", Service: "fixture", Scopes: []string{"repository:team/" + user + ":pull"}}
		token, err := client.FetchPullToken(ctx, image, challenge)
		if err != nil || !token.Valid() || token.Token != "token-"+user || token.ExpiresIn != 120 {
			t.Fatal("owned repository token exchange failed", err)
		}
		if strings.Contains(fmt.Sprintf("%+v", token), token.Token) {
			t.Fatal("token formatter disclosed the bearer token")
		}
		encoded, _ := json.Marshal(token)
		if strings.Contains(string(encoded), "refresh") || strings.Contains(string(encoded), "password") {
			t.Fatal("owner token reply disclosed source credentials or refresh token")
		}
		for _, edit := range []func(*PullTokenChallenge){
			func(q *PullTokenChallenge) { q.Host = "foreign.example" },
			func(q *PullTokenChallenge) { q.Scopes = []string{"repository:team/other:pull"} },
			func(q *PullTokenChallenge) { q.Scopes = []string{"repository:team/" + user + ":pull,push"} },
			func(q *PullTokenChallenge) { q.Realm = origin + "/other-token" },
			func(q *PullTokenChallenge) { q.Service = "other-service" },
			func(q *PullTokenChallenge) { q.Realm = "http://" + authority + "/token" },
		} {
			bad := challenge
			edit(&bad)
			before := exchanges.Load()
			if _, err := client.FetchPullToken(ctx, image, bad); err == nil {
				t.Fatal("changed token scope accepted")
			}
			if exchanges.Load() != before {
				t.Fatal("invalid scope reached token endpoint")
			}
		}
		client.Close()
		if _, err := client.FetchPullToken(ctx, image, challenge); err == nil {
			t.Fatal("closed owner client fetched another token")
		}
	}
	if exchanges.Load() != 2 {
		t.Fatal("repository-specific exchange count", exchanges.Load())
	}
}

func TestPullTokenBasicOnlyAndErrorBodiesDoNotBecomeCredentialsOrTokens(t *testing.T) {
	for _, scheme := range []string{"Basic", "Bearer"} {
		t.Run(scheme, func(t *testing.T) {
			var origin string
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, q *http.Request) {
				if q.URL.Path == "/v2/" {
					w.Header().Set("WWW-Authenticate", scheme+` realm="`+origin+`/token",service="fixture"`)
					w.WriteHeader(http.StatusUnauthorized)
					return
				}
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte("private owner password and error body"))
			}))
			defer server.Close()
			origin = server.URL
			authority := strings.TrimPrefix(origin, "https://")
			ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
			client, err := New(authority, []byte("reader"), []byte("private-password"), ca)
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			q := PullTokenChallenge{Host: authority, Realm: origin + "/token", Service: "fixture", Scopes: []string{"repository:team/base:pull"}}
			token, err := client.FetchPullToken(context.Background(), authority+"/team/base@sha256:"+strings.Repeat("a", 64), q)
			if err == nil || token.Valid() || strings.Contains(err.Error(), "private") {
				t.Fatal("error disclosed credentials or was accepted as token")
			}
			if scheme == "Basic" && err.Error() != "UNSUPPORTED" {
				t.Fatal("basic-only source silently downgraded", err)
			}
		})
	}
}

func TestPullTokenExchangeSendsAllSelectedRepositoryScopesToSameOwner(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var origin string
	var exchanges atomic.Int32
	want := []string{"repository:team/one:pull", "repository:team/two:pull"}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, q *http.Request) {
		switch q.URL.Path {
		case "/v2/":
			if q.Header.Get("Authorization") != "" {
				t.Error("credential sent before challenge")
			}
			w.Header().Set("WWW-Authenticate", `Bearer realm="`+origin+`/token",service="fixture"`)
			w.WriteHeader(http.StatusUnauthorized)
		case "/token":
			user, password, ok := q.BasicAuth()
			if !ok || user != "shared" || password != "owner-private-password" || q.Method != http.MethodGet || q.URL.Query().Get("service") != "fixture" || !slices.Equal(q.URL.Query()["scope"], want) {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			exchanges.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]any{"token": "combined-pull-token", "refresh_token": "never-return-refresh", "expires_in": 120})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	origin = server.URL
	authority := strings.TrimPrefix(origin, "https://")
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	owner, err := New(authority, []byte("shared"), []byte("owner-private-password"), ca)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	refs := []string{authority + "/team/one@sha256:" + strings.Repeat("a", 64), authority + "/team/two@sha256:" + strings.Repeat("b", 64)}
	q := PullTokenChallenge{Host: authority, Realm: origin + "/token", Service: "fixture", Scopes: []string{want[1], want[0], want[1]}}
	token, err := owner.FetchPullTokenForImages(ctx, refs, q)
	if err != nil || token.Token != "combined-pull-token" || exchanges.Load() != 1 {
		t.Fatal("SDK omitted an authorized scope or duplicated the exchange", err, exchanges.Load())
	}
	encoded, _ := json.Marshal(token)
	if strings.Contains(string(encoded), "refresh") || strings.Contains(string(encoded), "password") {
		t.Fatal("token response retained private source material")
	}
	for _, scopes := range [][]string{{want[0]}, {want[0], "repository:team/other:pull"}, {want[0], "repository:team/two:pull,push"}, {want[0], "registry:catalog:*"}} {
		bad := q
		bad.Scopes = scopes
		if _, err := owner.FetchPullTokenForImages(ctx, refs, bad); err == nil || exchanges.Load() != 1 {
			t.Fatal("missing/broader scope reached token endpoint", err, exchanges.Load())
		}
	}
	bad := q
	bad.Realm = origin + "/other-token"
	if _, err := owner.FetchPullTokenForImages(ctx, refs, bad); err == nil || exchanges.Load() != 1 {
		t.Fatal("forged realm received source credentials", err, exchanges.Load())
	}
}
