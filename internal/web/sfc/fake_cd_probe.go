// SPDX-License-Identifier: Apache-2.0

package sfc

import (
	"context"
	"net/url"
	"path"
	"regexp"
	"slices"
	"strings"
)

// REQ-56 in the fake. A repository is read from Fake.SetGitSource (or the
// default files plus an app.yaml). Its branches are "main" unless
// Fake.SetGitBranches says otherwise. A URL containing "private" needs a
// credential the server has (Fake.SetGitCredentials, default
// "git-deploy"); "missing" is no-repository, "unreachable" a timeout.
// Each user may probe 10 times a minute.

var cdCredentialName = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)

type cdProbeState struct {
	credentials []string
	branches    map[string][]string
	window      int64
	count       map[string]int
}

func (w *world) cdProbe() *cdProbeState {
	if w.probe == nil {
		w.probe = &cdProbeState{credentials: []string{"git-deploy"}, branches: map[string][]string{}, count: map[string]int{}}
	}
	return w.probe
}

// SetGitCredentials sets the credential names the servers hold.
func (f *Fake) SetGitCredentials(names ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.w.cdProbe().credentials = slices.Clone(names)
}

// SetGitBranches sets a repository's branches (default: main).
func (f *Fake) SetGitBranches(repository string, branches ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.w.cdProbe().branches[repository] = slices.Clone(branches)
}

func (c *fakeConn) probeCD(ctx context.Context, q cdProbeRequest) (cdProbeResult, error) {
	const m = "cd-probe"
	user, err := c.lockSession(ctx, m)
	if err != nil {
		return cdProbeResult{}, err
	}
	defer c.unlock()
	w := c.f.w
	if !w.canManage(user, q.Tenant) {
		return cdProbeResult{}, fail(m, CodeDenied, "")
	}
	u, perr := url.Parse(q.Repository)
	clean := path.Clean(q.Path)
	if perr != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" ||
		q.Branch == "" || len(q.Branch) > 256 || strings.ContainsAny(q.Branch, " \x00\r\n~^:?*[\\") ||
		q.Path == "" || clean != q.Path || strings.HasPrefix(clean, "/") || strings.HasPrefix(clean, "..") ||
		q.Credential != "" && !cdCredentialName.MatchString(q.Credential) {
		return cdProbeResult{}, fail(m, CodeInvalid, "https repository without user info, branch, relative file path, credential name")
	}
	if w.apps[q.Tenant+"/"+q.App] == nil {
		return cdProbeResult{}, fail(m, CodeMissing, "no such app")
	}
	s := w.cdProbe()
	if minute := c.f.now().Unix() / 60; minute != s.window {
		s.window, s.count = minute, map[string]int{}
	}
	if s.count[user] >= 10 {
		return cdProbeResult{Code: CDProbeRateLimited}, nil
	}
	s.count[user]++
	node := ""
	if ns := w.tenantNodes[q.Tenant]; len(ns) > 0 {
		node = ns[0]
	}
	out := cdProbeResult{Node: node}
	switch {
	case q.Credential != "" && !slices.Contains(s.credentials, q.Credential):
		out.Code = CDProbeNoCredential
	case strings.Contains(q.Repository, "unreachable"):
		out.Code = CDProbeTimeout
	case strings.Contains(q.Repository, "private") && q.Credential == "":
		out.Code = CDProbeAuthFailed
	case strings.Contains(q.Repository, "missing"):
		out.Code = CDProbeNoRepository
	}
	if out.Code != "" {
		return out, nil
	}
	branches := s.branches[q.Repository]
	if branches == nil {
		branches = []string{"main"}
	}
	if !slices.Contains(branches, q.Branch) {
		out.Code = CDProbeNoBranch
		return out, nil
	}
	src, ok := w.build.git[q.Repository]
	if !ok {
		src = defaultGitFiles(q.Repository)
		src.files["app.yaml"] = []byte("name: demo\nservices:\n  web:\n    image: docker.io/library/busybox:1.36\n")
	}
	data, ok := src.files[q.Path]
	if !ok {
		out.Code = CDProbeNoFile
		return out, nil
	}
	d := fakeDigest("git-branch", src.commit, q.Branch)
	out.Commit = src.commit
	if q.Branch != "main" {
		out.Commit = hexOf(d[:4])
	}
	out.Size = int64(len(data))
	return out, nil
}
