// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/deployment"
	"github.com/jay94ks/mydcd/internal/engine"
	"github.com/jay94ks/mydcd/internal/secrets"
)

func (r *Runtime) appExternalRegistryAuth(ctx context.Context, task deployment.ObjectRef, binding [32]byte, image string, permit control.RegistryImagePermit) (engine.RegistryAuth, error) {
	spec := permit.External
	if spec == nil {
		return engine.RegistryAuth{}, nil
	}
	if spec.Auth == "none" && spec.CA == nil {
		auth, err := engine.NewExternalRegistryAuth(spec.Authority, nil, nil, nil)
		return r.registryPullAuth(auth, *spec), err
	}
	if spec.Auth != "none" && spec.Credential == nil || permit.ExternalInputs == nil || len(permit.ExternalInputs.Entries) == 0 || len(permit.ExternalInputs.Entries) > 2 {
		return engine.RegistryAuth{}, deployment.ErrInputs
	}
	var username, password, ca []byte
	var fetched []secrets.Fetched
	defer func() {
		for _, value := range fetched {
			for _, data := range value.Values {
				clear(data)
			}
		}
	}()
	for _, entry := range permit.ExternalInputs.Entries {
		q := control.AppInputFetch{Schema: 1, Consumer: r.Identity.Public, Binding: control.AppBindingRequest{Task: task, Digest: binding, At: time.Now().Unix()}, ReadSet: permit.ExternalInputs.ReadSet, MinimumIndex: permit.Index, Realm: entry.Realm, Secret: entry.Leaf.Secret}
		value, err := r.fetchAppInputLeaf(ctx, q, entry.Provider)
		// Values are owned even on an invalid response; all branches clear them.
		fetched = append(fetched, value)
		if err != nil {
			return engine.RegistryAuth{}, err
		}
		if secrets.ValidateFetched(secrets.UsePlan{Leaves: []secrets.Leaf{entry.Leaf}}, []secrets.Fetched{value}, 128<<10) != nil {
			return engine.RegistryAuth{}, deployment.ErrInputs
		}
		c := spec.Credential
		if c != nil && entry.Realm == c.Realm && entry.Leaf.Secret == c.ID {
			username, password = value.Values[c.UsernameKey], value.Values[c.PasswordKey]
		}
		if c := spec.CA; c != nil && entry.Realm == c.Realm && entry.Leaf.Secret == c.ID {
			ca = value.Values[c.Key]
		}
	}
	if spec.Auth != "none" && (len(username) == 0 || len(username) > 1024 || !utf8.Valid(username) || strings.ContainsAny(string(username), ":\x00\r\n") || len(password) == 0 || len(password) > 16<<10 || !utf8.Valid(password)) || spec.CA != nil && len(ca) == 0 {
		return engine.RegistryAuth{}, deployment.ErrInputs
	}
	latest, err := r.appRegistryImagePermit(ctx, task, binding, image)
	if err != nil || !sameRegistryImageAuthority(latest, permit) {
		return engine.RegistryAuth{}, deployment.ErrInputs
	}
	auth, err := engine.NewExternalRegistryAuth(spec.Authority, username, password, ca)
	return r.registryPullAuth(auth, *spec), err
}
