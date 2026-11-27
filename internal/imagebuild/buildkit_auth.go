// SPDX-License-Identifier: Apache-2.0

package imagebuild

import (
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jay94ks/seafield/internal/registryclient"
	"github.com/moby/buildkit/session/auth"
	"golang.org/x/crypto/nacl/sign"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type BuildKitPullAuth struct {
	auth.UnimplementedAuthServer
	mu                   sync.RWMutex
	seed                 [32]byte
	closed               bool
	failed               atomic.Bool
	contentStorageFailed atomic.Bool
	inputs               []FrozenSource
	authorize            func(context.Context) error
	fetch                func(context.Context, []Source, registryclient.PullTokenChallenge) (registryclient.PullToken, error)
	contentRead          BuildKitSourceRead
}

func NewBuildKitSourceAuth(spec JobSpec, inputs []FrozenSource, authorize func(context.Context) error, fetch func(context.Context, []Source, registryclient.PullTokenChallenge) (registryclient.PullToken, error), read BuildKitSourceRead) (*BuildKitPullAuth, error) {
	if read == nil {
		return nil, ErrInvalid
	}
	a, err := NewBuildKitPullAuth(spec, inputs, authorize, fetch)
	if err != nil {
		return nil, err
	}
	a.contentRead = read
	return a, nil
}

func (a *BuildKitPullAuth) contentFailure(err error) {
	if errors.Is(err, ErrStorage) {
		a.contentStorageFailed.Store(true)
	} else {
		a.failed.Store(true)
	}
}

// NewBuildKitPullAuth uses the adopted BuildKit session protocol. It reads no
// Docker config, credential helpers, token seeds or ambient HOME directory.
// Basic credentials never leave an approved source owner through this server.
func NewBuildKitPullAuth(spec JobSpec, inputs []FrozenSource, authorize func(context.Context) error, fetch func(context.Context, []Source, registryclient.PullTokenChallenge) (registryclient.PullToken, error)) (*BuildKitPullAuth, error) {
	if spec.Validate() != nil || ValidateJobInputs(spec, inputs) != nil || authorize == nil || fetch == nil {
		return nil, ErrInvalid
	}
	a := &BuildKitPullAuth{inputs: slices.Clone(inputs), authorize: authorize, fetch: fetch}
	if _, err := rand.Read(a.seed[:]); err != nil {
		return nil, ErrStorage
	}
	return a, nil
}

func (a *BuildKitPullAuth) Register(server *grpc.Server) { auth.RegisterAuthServer(server, a) }
func (a *BuildKitPullAuth) SourceFailed() bool           { return a.failed.Load() }

func (*BuildKitPullAuth) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "[redacted build authentication session]")
}

func (a *BuildKitPullAuth) Close() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.closed = true
	clear(a.seed[:])
}

func (a *BuildKitPullAuth) hostAllowed(host string) bool {
	for _, input := range a.inputs {
		_, registry, _, err := registryclient.Normalize(input.Image)
		if err == nil && (host == registry || registry == "docker.io" && (host == "registry-1.docker.io" || host == "index.docker.io")) {
			return true
		}
	}
	return false
}

func (a *BuildKitPullAuth) Credentials(ctx context.Context, request *auth.CredentialsRequest) (*auth.CredentialsResponse, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if request == nil || a.closed || a.authorize(ctx) != nil || !a.hostAllowed(request.Host) {
		return nil, status.Error(codes.PermissionDenied, "image build source unavailable")
	}
	// The pinned daemon uses token authority for bearer auth. A host-only
	// basic challenge cannot receive repository-scoped source secrets here.
	a.failed.Store(true)
	return &auth.CredentialsResponse{}, nil
}

func (a *BuildKitPullAuth) FetchToken(ctx context.Context, request *auth.FetchTokenRequest) (*auth.FetchTokenResponse, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if request == nil || a.closed || a.authorize(ctx) != nil {
		return nil, status.Error(codes.PermissionDenied, "image build source unavailable")
	}
	challenge := registryclient.PullTokenChallenge{Host: request.Host, Realm: request.Realm, Service: request.Service, Scopes: slices.Clone(request.Scopes)}
	sources, err := SelectPullSources(a.inputs, challenge)
	if err != nil {
		a.failed.Store(true)
		return nil, status.Error(codes.PermissionDenied, "image build source unavailable")
	}
	token, err := a.fetch(ctx, sources, challenge)
	if err != nil || !token.Valid() || time.Now().Unix() >= token.IssuedAt+token.ExpiresIn {
		a.failed.Store(true)
		return nil, status.Error(codes.Unavailable, "image build source authentication unavailable")
	}
	if a.authorize(ctx) != nil {
		return nil, status.Error(codes.PermissionDenied, "image build source unavailable")
	}
	return &auth.FetchTokenResponse{Token: token.Token, IssuedAt: token.IssuedAt, ExpiresIn: token.ExpiresIn}, nil
}

// BuildKit delegates FetchToken only when a session advertises token authority.
// This job-local proof uses a fresh in-memory seed; it is neither a registry
// access issuer nor a persistent Docker credential/token-seed file.
func (a *BuildKitPullAuth) authorityKey(host string, salt []byte) ed25519.PrivateKey {
	mac := hmac.New(sha256.New, a.seed[:])
	_, _ = mac.Write([]byte(host))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write(salt)
	seed := mac.Sum(nil)
	defer clear(seed)
	return ed25519.NewKeyFromSeed(seed)
}

func (a *BuildKitPullAuth) GetTokenAuthority(ctx context.Context, request *auth.GetTokenAuthorityRequest) (*auth.GetTokenAuthorityResponse, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if request == nil || a.closed || len(request.Salt) != 32 || !a.hostAllowed(request.Host) || a.authorize(ctx) != nil {
		return nil, status.Error(codes.PermissionDenied, "image build source unavailable")
	}
	key := a.authorityKey(request.Host, request.Salt)
	defer clear(key)
	return &auth.GetTokenAuthorityResponse{PublicKey: slices.Clone(key[32:])}, nil
}

func (a *BuildKitPullAuth) VerifyTokenAuthority(ctx context.Context, request *auth.VerifyTokenAuthorityRequest) (*auth.VerifyTokenAuthorityResponse, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if request == nil || a.closed || len(request.Salt) != 32 || len(request.Payload) != 32 || !a.hostAllowed(request.Host) || a.authorize(ctx) != nil {
		return nil, status.Error(codes.PermissionDenied, "image build source unavailable")
	}
	key := a.authorityKey(request.Host, request.Salt)
	defer clear(key)
	private := new([64]byte)
	copy(private[:], key)
	defer clear(private[:])
	return &auth.VerifyTokenAuthorityResponse{Signed: sign.Sign(nil, request.Payload, private)}, nil
}
