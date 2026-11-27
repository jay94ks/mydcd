// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"context"
	"crypto/x509"
	"io"
	"os"
	"syscall"

	"github.com/jay94ks/seafield/internal/config"
	"github.com/jay94ks/seafield/internal/deployment"
)

func (r *Runtime) openGit(c config.Node) error {
	if len(c.GitCredentials) > 64 {
		return deployment.ErrSource
	}
	r.gitCredentials = map[string]config.GitCredential{}
	for _, p := range c.GitCredentials {
		key := p.Tenant + "/" + p.Profile
		if p.Validate() != nil {
			return deployment.ErrSource
		}
		if _, exists := r.gitCredentials[key]; exists {
			return deployment.ErrSource
		}
		r.gitCredentials[key] = p
	}
	r.gitFetcher = deployment.NewGitFetcher()
	return nil
}

// fetchGit is called after the controller obtains a current quorum permit for
// the registered source. Installation mapping is an additional restriction;
// it never authorizes a fetch or an app operation by itself.
func (r *Runtime) fetchGit(ctx context.Context, tenant string, policy deployment.DeliveryDeclaration, ticket deployment.DeliveryFetch) (deployment.DeliveryInput, error) {
	return r.fetchGitCommit(ctx, tenant, policy, ticket, "")
}
func (r *Runtime) fetchGitCommit(ctx context.Context, tenant string, policy deployment.DeliveryDeclaration, ticket deployment.DeliveryFetch, commit string) (deployment.DeliveryInput, error) {
	var access deployment.GitAccess
	if policy.Source.Credential != "" {
		p, exists := r.gitCredentials[tenant+"/"+policy.Source.Credential]
		if !exists || p.Tenant != tenant || p.Repository != policy.Source.Repository {
			return deployment.DeliveryInput{}, deployment.ErrSource
		}
		var err error
		access, err = installedGitAccess(p)
		if err != nil {
			return deployment.DeliveryInput{}, deployment.ErrSource
		}
		defer clear(access.Password)
		defer clear(access.Username)
	}
	if commit != "" {
		return r.gitFetcher.FetchCommit(ctx, tenant, policy, ticket, access, commit)
	}
	return r.gitFetcher.Fetch(ctx, tenant, policy, ticket, access)
}

func installedGitFile(path string, limit int64, secret bool) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, deployment.ErrSource
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 || secret && info.Mode().Perm()&0077 != 0 {
		return nil, deployment.ErrSource
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) {
		return nil, deployment.ErrSource
	}
	raw, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || len(raw) == 0 || int64(len(raw)) > limit {
		clear(raw)
		return nil, deployment.ErrSource
	}
	return raw, nil
}

func installedGitAccess(p config.GitCredential) (deployment.GitAccess, error) {
	if p.Validate() != nil {
		return deployment.GitAccess{}, deployment.ErrSource
	}
	password, err := installedGitFile(p.PasswordFile, 16384, true)
	if err != nil {
		return deployment.GitAccess{}, err
	}
	password = bytes.TrimSuffix(password, []byte{'\n'})
	if len(password) == 0 || bytes.ContainsAny(password, "\x00\r\n") {
		clear(password)
		return deployment.GitAccess{}, deployment.ErrSource
	}
	var roots *x509.CertPool
	if p.CAFile != "" {
		pem, err := installedGitFile(p.CAFile, 1<<20, false)
		if err != nil {
			clear(password)
			return deployment.GitAccess{}, err
		}
		roots, err = x509.SystemCertPool()
		if err != nil {
			roots = x509.NewCertPool()
		}
		if !roots.AppendCertsFromPEM(pem) {
			clear(password)
			return deployment.GitAccess{}, deployment.ErrSource
		}
	}
	return deployment.GitAccess{Roots: roots, Username: []byte(p.Username), Password: password}, nil
}
