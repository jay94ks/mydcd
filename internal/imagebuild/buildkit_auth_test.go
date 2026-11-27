// SPDX-License-Identifier: Apache-2.0

package imagebuild

import (
	"context"
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/registryclient"
	"github.com/moby/buildkit/session/auth"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

// Actual pinned AuthServer callback types, with injected token authority.
// This is not a real native BuildKit solve or a credential/CA delivery pass.
func TestBuildKitAuthSessionSelectsFrozenRepositoryAndNeverReturnsBasicSecrets(t *testing.T) {
	spec, _ := testJobSpec(t)
	var inputs []FrozenSource
	for stage, repo := range []string{"one", "two"} {
		inputs = append(inputs, FrozenSource{Source: Source{Reference: "registry.example/team/" + repo + ":latest", Platform: "linux/amd64", Kind: "from", Stage: stage, Line: stage + 1}, Image: "registry.example/team/" + repo + "@sha256:" + strings.Repeat("a", 64)})
	}
	revoked, revokeAfterExchange := false, false
	fetches := 0
	provider, err := NewBuildKitPullAuth(spec, inputs, func(context.Context) error {
		if revoked {
			return errors.New("private authorization detail")
		}
		return nil
	}, func(_ context.Context, sources []Source, q registryclient.PullTokenChallenge) (registryclient.PullToken, error) {
		fetches++
		if len(sources) != 1 || sources[0] != inputs[1].Source || q.Scopes[0] != "repository:team/two:pull" {
			t.Fatal("session changed repository credentials", sources)
		}
		if revokeAfterExchange {
			revoked = true
		}
		return registryclient.PullToken{Token: "private-build-token", IssuedAt: time.Now().Unix(), ExpiresIn: 60}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer provider.Close()
	server := grpc.NewServer()
	defer server.Stop()
	provider.Register(server)
	if _, ok := server.GetServiceInfo()["moby.filesync.v1.Auth"]; !ok {
		t.Fatal("pinned BuildKit Auth service was not registered")
	}
	credential, err := provider.Credentials(context.Background(), &auth.CredentialsRequest{Host: "registry.example"})
	if err != nil || credential.Username != "" || credential.Secret != "" || fetches != 0 || !provider.SourceFailed() {
		t.Fatal("host-only request disclosed source credentials", err)
	}
	salt, payload := []byte(strings.Repeat("s", 32)), []byte(strings.Repeat("p", 32))
	authority, err := provider.GetTokenAuthority(context.Background(), &auth.GetTokenAuthorityRequest{Host: "registry.example", Salt: salt})
	if err != nil || len(authority.PublicKey) != ed25519.PublicKeySize {
		t.Fatal("session token delegation was not advertised", err)
	}
	proof, err := provider.VerifyTokenAuthority(context.Background(), &auth.VerifyTokenAuthorityRequest{Host: "registry.example", Salt: salt, Payload: payload})
	if err != nil || len(proof.Signed) != ed25519.SignatureSize+len(payload) || !ed25519.Verify(ed25519.PublicKey(authority.PublicKey), payload, proof.Signed[:ed25519.SignatureSize]) || string(proof.Signed[ed25519.SignatureSize:]) != string(payload) {
		t.Fatal("token authority proof differs from BuildKit NaCl contract", err)
	}
	request := &auth.FetchTokenRequest{Host: "registry.example", Realm: "https://registry.example/token", Service: "registry", Scopes: []string{"repository:team/two:pull"}}
	response, err := provider.FetchToken(context.Background(), request)
	if err != nil || response.Token != "private-build-token" || response.ExpiresIn != 60 || fetches != 1 {
		t.Fatal("repository-aware token callback missing", err, fetches)
	}
	if _, err := provider.Credentials(context.Background(), &auth.CredentialsRequest{Host: "foreign.example"}); status.Code(err) != codes.PermissionDenied {
		t.Fatal("foreign host requested credentials", err)
	}
	bad := &auth.FetchTokenRequest{Host: request.Host, Realm: request.Realm, Scopes: []string{"repository:team/two:pull,push"}}
	if _, err := provider.FetchToken(context.Background(), bad); status.Code(err) != codes.PermissionDenied || fetches != 1 {
		t.Fatal("broader scope reached token authority", err, fetches)
	}
	revokeAfterExchange = true
	if response, err := provider.FetchToken(context.Background(), request); response != nil || status.Code(err) != codes.PermissionDenied || strings.Contains(err.Error(), "private") {
		t.Fatal("permission changed during exchange but token was returned", err)
	}
	if credential, err := provider.Credentials(context.Background(), &auth.CredentialsRequest{Host: request.Host}); credential != nil || status.Code(err) != codes.PermissionDenied {
		t.Fatal("revoked job retained host access", err)
	}
	revoked = false
	provider.Close()
	if _, err := provider.GetTokenAuthority(context.Background(), &auth.GetTokenAuthorityRequest{Host: request.Host, Salt: salt}); status.Code(err) != codes.PermissionDenied {
		t.Fatal("closed session retained token authority", err)
	}
}

func TestBuildKitAuthForwardsCompleteMergedScopeAndChecksPermissionAfterExchange(t *testing.T) {
	spec, _ := testJobSpec(t)
	var inputs []FrozenSource
	for stage, repo := range []string{"one", "two"} {
		inputs = append(inputs, FrozenSource{Source: Source{Reference: "registry.example/team/" + repo + ":latest", Platform: "linux/amd64", Kind: "from", Stage: stage, Line: stage + 1}, Image: "registry.example/team/" + repo + "@sha256:" + strings.Repeat("a", 64)})
	}
	revoked, revokeAfter := false, false
	fetches := 0
	provider, err := NewBuildKitPullAuth(spec, inputs, func(context.Context) error {
		if revoked {
			return ErrConflict
		}
		return nil
	}, func(_ context.Context, sources []Source, q registryclient.PullTokenChallenge) (registryclient.PullToken, error) {
		fetches++
		if len(sources) != 2 || sources[0] != inputs[1].Source || sources[1] != inputs[0].Source || len(q.Scopes) != 3 {
			t.Fatal("merged authorization silently fell back to its first source", sources, q.Scopes)
		}
		revoked = revokeAfter
		return registryclient.PullToken{Token: "merged-transient-token", IssuedAt: time.Now().Unix(), ExpiresIn: 60}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer provider.Close()
	q := &auth.FetchTokenRequest{Host: "registry.example", Realm: "https://registry.example/token", Scopes: []string{"repository:team/two:pull", "repository:team/one:pull", "repository:team/two:pull"}}
	if token, err := provider.FetchToken(context.Background(), q); err != nil || token.Token != "merged-transient-token" || fetches != 1 {
		t.Fatal("merged callback failed", err, fetches)
	}
	revokeAfter = true
	if token, err := provider.FetchToken(context.Background(), q); token != nil || status.Code(err) != codes.PermissionDenied || fetches != 2 {
		t.Fatal("merged token escaped after grant revocation", err, fetches)
	}
	revoked, revokeAfter = false, false
	bad := proto.Clone(q).(*auth.FetchTokenRequest)
	bad.Scopes = []string{"repository:team/one:pull", "repository:team/other:pull"}
	if token, err := provider.FetchToken(context.Background(), bad); token != nil || status.Code(err) != codes.PermissionDenied || fetches != 2 {
		t.Fatal("unfrozen merged scope reached credential exchange", err, fetches)
	}
}
