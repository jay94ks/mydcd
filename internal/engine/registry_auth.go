// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"fmt"
	"io"
	"strings"

	"github.com/jay94ks/seafield/internal/engineimage"
	"github.com/jay94ks/seafield/internal/registryclient"
)

// RegistryAuth is ephemeral request input, never a ContainerSpec or a journal
// field: the one source sfcd reads a pinned image from when the engine pulls
// it (purpose 37). Zero means an anonymous read of the reference's own
// registry. The engine never contacts a registry and receives no credential;
// ImageWithAuth owns and closes the source.
type RegistryAuth struct {
	authority   string
	source      *registryclient.Access
	open        engineimage.Opener
	observePull func(registryclient.PullOutcome)
}

func (RegistryAuth) Format(s fmt.State, _ rune)   { _, _ = io.WriteString(s, "[redacted registry auth]") }
func (RegistryAuth) MarshalJSON() ([]byte, error) { return nil, ErrOwnership }

// NewRegistryAuth reads a cluster registry with a signed Task or build login.
// The registry's own token exchange checks it; trust is the system's.
func NewRegistryAuth(authority, username string, password []byte) (RegistryAuth, error) {
	if authority == "" || strings.ContainsAny(authority, "/@?#\\ \t\r\n") || username == "" || len(password) == 0 {
		return RegistryAuth{}, ErrOwnership
	}
	a, err := registryclient.New(authority, []byte(username), password, nil)
	if err != nil {
		return RegistryAuth{}, ErrOwnership
	}
	return RegistryAuth{authority: authority, source: a}, nil
}

// NewExternalRegistryAuth uses an isolated registry SDK client so tenant CA and
// authentication never depend on daemon-wide trust or ambient credentials.
func NewExternalRegistryAuth(authority string, username, password, ca []byte) (RegistryAuth, error) {
	a, err := registryclient.New(authority, username, password, ca)
	if err != nil {
		return RegistryAuth{}, err
	}
	return RegistryAuth{authority: authority, source: a}, nil
}

// NewOpenerAuth reads a pinned image through open, a source sfcd already
// authorized for this one pull (for example a build's frozen builder image
// read through its source's owner). The engine still sees no credential.
func NewOpenerAuth(authority string, open engineimage.Opener) (RegistryAuth, error) {
	if authority == "" || strings.ContainsAny(authority, "/@?#\\ \t\r\n") || open == nil {
		return RegistryAuth{}, ErrOwnership
	}
	return RegistryAuth{authority: authority, open: open}, nil
}

// WithPullObserver attaches a diagnostic sink to this single-call input. It
// receives no credentials, URLs, bodies or error strings. It cannot turn a
// completed download into another effect or retry it.
func (a RegistryAuth) WithPullObserver(observe func(registryclient.PullOutcome)) RegistryAuth {
	a.observePull = observe
	return a
}
