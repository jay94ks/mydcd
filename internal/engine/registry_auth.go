// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"fmt"
	"io"
	"strings"

	"github.com/jay94ks/mydcd/internal/registryclient"

	"github.com/moby/moby/api/pkg/authconfig"
	"github.com/moby/moby/api/types/registry"
)

// RegistryAuth is ephemeral request input, never a ContainerSpec or a journal
// field. Zero means no explicit registry credential. Managed credentials use
// Docker's exchange; explicit external input owns a scoped OCI client and CA.
// Neither installs ambient config nor an anonymous auth retry callback.
type RegistryAuth struct {
	value, authority string
	external         *registryclient.Access
	observePull      func(registryclient.PullOutcome)
}

func (RegistryAuth) Format(s fmt.State, _ rune)   { _, _ = io.WriteString(s, "[redacted registry auth]") }
func (RegistryAuth) MarshalJSON() ([]byte, error) { return nil, ErrOwnership }
func NewRegistryAuth(authority, username string, password []byte) (RegistryAuth, error) {
	if authority == "" || strings.ContainsAny(authority, "/@?#\\ \t\r\n") || username == "" || len(password) == 0 {
		return RegistryAuth{}, ErrOwnership
	}
	value, err := authconfig.Encode(registry.AuthConfig{ServerAddress: authority, Username: username, Password: string(password)})
	if err != nil {
		return RegistryAuth{}, ErrOwnership
	}
	return RegistryAuth{value: value, authority: authority}, nil
}

// NewExternalRegistryAuth uses an isolated registry SDK client so tenant CA and
// authentication never depend on daemon-wide trust or ambient credentials.
// ImageWithAuth owns and closes this single-call private input.
func NewExternalRegistryAuth(authority string, username, password, ca []byte) (RegistryAuth, error) {
	a, err := registryclient.New(authority, username, password, ca)
	if err != nil {
		return RegistryAuth{}, err
	}
	return RegistryAuth{authority: authority, external: a}, nil
}

// WithPullObserver attaches a diagnostic sink to this single-call input. It
// receives no credentials, URLs, bodies or error strings. It cannot turn a
// completed download into another effect or retry it.
func (a RegistryAuth) WithPullObserver(observe func(registryclient.PullOutcome)) RegistryAuth {
	a.observePull = observe
	return a
}
