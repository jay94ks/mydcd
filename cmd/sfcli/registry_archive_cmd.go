// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cli"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/registry"
	"github.com/jay94ks/seafield/internal/registryarchive"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/internal/userauth"
)

// sfcli registry export / import: a built-in registry's tagged images as one
// OCI image layout tar (devel/design/cluster-backup-and-recovery.md, B6).
// The CLI is a registry client like docker: sfcd issues a short-lived
// credential per repository (pull for export, pull and push for import),
// and the images go between this computer and the registry directly.

// repeated is a flag given more than once.
type repeated []string

func (r *repeated) String() string     { return strings.Join(*r, ",") }
func (r *repeated) Set(v string) error { *r = append(*r, v); return nil }

// registryCredential asks sfcd for a credential and checks it is for this
// registry, repository, actions and session, as `registry login` does.
func registryCredential(ctx context.Context, s *session, tenant, id, repository string, push bool) (authority string, secret []byte, expires int64, err error) {
	scope := "repository:" + repository + ":pull"
	if push {
		scope += ",push"
	}
	repo, actions, err := registry.RequestedScope(scope)
	if err != nil {
		return "", nil, 0, cli.Usagef("%q is not a valid repository", repository)
	}
	reply, err := s.Client.RegistryCredential(ctx, s.Target, s.Stored.Session, tenant, userauth.RegistryCredentialRequest{ID: id, Repository: repo, Actions: actions})
	if err != nil {
		clear(reply.RegistryCredential)
		return "", nil, 0, err
	}
	if err = checkRegistryCredential(s, reply, tenant, id, repo, actions); err != nil {
		clear(reply.RegistryCredential)
		return "", nil, 0, err
	}
	return reply.RegistryAuthority, reply.RegistryCredential, reply.RegistryCredentialExpires, nil
}

func checkRegistryCredential(s *session, reply userauth.Reply, tenant, id, repo string, actions []string) error {
	grant, err := registry.ParseLogin(string(reply.RegistryCredential), time.Now().Unix())
	trusted := slices.ContainsFunc(s.Client.Peers, func(p sfcp.Peer) bool { return [32]byte(p.Key) == grant.Issuer })
	if err != nil || !trusted || grant.Cluster != s.Client.Cluster || grant.Tenant != tenant || grant.Registry != id || grant.Repository != repo || !slices.Equal(grant.Actions, actions) || grant.Authority != reply.RegistryAuthority || grant.Subject.Session == nil || !bytes.Equal(access.SessionBytes(*grant.Subject.Session), access.SessionBytes(s.Stored.Session)) {
		return errors.New("the server sent a password for another registry, repository or session")
	}
	return nil
}

// registryRemote opens repositories of one built-in registry. Each
// repository gets its own credential, asked again shortly before it runs
// out, so a long transfer outlives the token while the login lasts.
type registryRemote struct {
	g      *globals
	c      *cli.Context
	s      *session
	tenant string
	id     string

	mu        sync.Mutex
	authority string
	repos     map[string]*repoAuth
}

// registryTransport is the HTTPS transport to registries (tests replace it).
var registryTransport = remote.DefaultTransport

func (r *registryRemote) open(repository string, push bool) (name.Repository, []remote.Option, error) {
	r.mu.Lock()
	key := fmt.Sprint(repository, push)
	a := r.repos[key]
	if a == nil {
		a = &repoAuth{r: r, repository: repository, push: push}
		r.repos[key] = a
	}
	r.mu.Unlock()
	if _, err := a.AuthorizationContext(r.c.Ctx); err != nil {
		return name.Repository{}, nil, err
	}
	repo, err := name.NewRepository(r.authority+"/"+repository, name.StrictValidation)
	if err != nil {
		return name.Repository{}, nil, err
	}
	return repo, []remote.Option{remote.WithAuth(a), remote.WithTransport(registryTransport)}, nil
}

type repoAuth struct {
	r          *registryRemote
	repository string
	push       bool

	mu      sync.Mutex
	secret  []byte
	expires int64
}

func (a *repoAuth) Authorization() (*authn.AuthConfig, error) {
	return a.AuthorizationContext(context.Background())
}

func (a *repoAuth) AuthorizationContext(context.Context) (*authn.AuthConfig, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.secret == nil || time.Now().Unix() > a.expires-30 {
		ctx, cancel := a.r.g.Deadline(a.r.c)
		defer cancel()
		authority, secret, expires, err := registryCredential(ctx, a.r.s, a.r.tenant, a.r.id, a.repository, a.push)
		if err != nil {
			return nil, err
		}
		a.r.mu.Lock()
		if a.r.authority == "" {
			a.r.authority = authority
		}
		same := a.r.authority == authority
		a.r.mu.Unlock()
		if !same {
			clear(secret)
			return nil, errors.New("the registry address changed during the transfer")
		}
		clear(a.secret)
		a.secret, a.expires = secret, expires
	}
	return &authn.AuthConfig{Username: a.r.s.Stored.Username, Password: string(a.secret)}, nil
}

func (r *registryRemote) close() {
	for _, a := range r.repos {
		clear(a.secret)
	}
}

func newRegistryRemote(g *globals, c *cli.Context, s *session, tenant, id string) *registryRemote {
	return &registryRemote{g: g, c: c, s: s, tenant: tenant, id: id, repos: map[string]*repoAuth{}}
}

func registryExportCommand(g *globals) *cli.Command {
	var out string
	var repositories, tags repeated
	return &cli.Command{
		Name:  "export",
		Args:  "NAME --out FILE",
		Short: "Save the registry's tagged images to an OCI layout tar",
		Long: `Writes every tagged image of the registry (or of --repository, and only
--tag) to FILE as one OCI image layout in a tar, which skopeo and crane also
read. The tags are pinned to their digests when the export starts, so later
pushes do not change the file; an image deleted meanwhile fails the export.
The file is written next to FILE and renamed when it is complete. Images go
between this computer and the registry's address directly.`,
		Flags: func(fs *flag.FlagSet) {
			fs.StringVar(&out, "out", "", "new tar `file` to write (required)")
			fs.Var(&repositories, "repository", "only this `repository` (repeat)")
			fs.Var(&tags, "tag", "only this `tag` (repeat)")
		},
		Run: g.withSession(func(c *cli.Context, s *session, args []string) error {
			id, err := oneName(args, "registry name")
			if err != nil {
				return err
			}
			if out == "" {
				return cli.Usagef("--out FILE is required")
			}
			for _, r := range repositories {
				if !registryarchive.ValidRepository(r) {
					return cli.Usagef("%q is not a valid repository", r)
				}
			}
			for _, t := range tags {
				if !registryarchive.ValidTag(t) {
					return cli.Usagef("%q is not a valid tag", t)
				}
			}
			if _, err := os.Lstat(out); err == nil {
				return fmt.Errorf("%s already exists", out)
			}
			tenant, err := g.Tenant(s, true)
			if err != nil {
				return err
			}
			entries, err := exportEntries(c, g, s, tenant, id, repositories, tags)
			if err != nil {
				return err
			}
			fmt.Fprintf(c.Err, "Exporting %d tagged images of %s.\n", len(entries), id)
			r := newRegistryRemote(g, c, s, tenant, id)
			defer r.close()
			partial, err := os.CreateTemp(filepath.Dir(out), "."+filepath.Base(out)+".*.partial")
			if err != nil {
				return err
			}
			sum, err := registryarchive.Export(c.Ctx, partial, entries, r.open)
			if err == nil {
				err = partial.Sync()
			}
			if cerr := partial.Close(); err == nil {
				err = cerr
			}
			if err == nil {
				err = os.Rename(partial.Name(), out)
			}
			if err != nil {
				_ = os.Remove(partial.Name())
			}
			if err != nil {
				return err
			}
			fmt.Fprintf(c.Out, "%s: %d images, %d blobs, %s\n", out, sum.Images, sum.Blobs, cli.Size(sum.Bytes))
			return nil
		}),
	}
}

// exportEntries pins the selected tags to their digests now.
func exportEntries(c *cli.Context, g *globals, s *session, tenant, id string, repositories, tags []string) ([]registryarchive.Entry, error) {
	ctx, cancel := g.Deadline(c)
	defer cancel()
	repos := repositories
	if len(repos) == 0 {
		page, err := readCatalogue(ctx, s, tenant, control.RegistryCatalogueQuery{Kind: "managed", ID: id})
		if err != nil {
			return nil, err
		}
		repos = page.Repositories
	}
	var entries []registryarchive.Entry
	for _, repo := range repos {
		page, err := readCatalogue(ctx, s, tenant, control.RegistryCatalogueQuery{Kind: "managed", ID: id, Repository: repo})
		if err != nil {
			return nil, fmt.Errorf("%s: %w", repo, err)
		}
		for _, m := range page.Images {
			if strings.HasPrefix(m.Reference, "sha256:") || len(tags) != 0 && !slices.Contains(tags, m.Reference) {
				continue
			}
			entries = append(entries, registryarchive.Entry{Repository: repo, Tag: m.Reference, Digest: m.Digest})
		}
	}
	if len(entries) == 0 {
		return nil, errors.New("no tagged image matches; see 'sfcli image list " + id + "'")
	}
	if len(entries) > registryarchive.MaxEntries {
		return nil, fmt.Errorf("%d images is more than one export takes (%d); export by --repository", len(entries), registryarchive.MaxEntries)
	}
	return entries, nil
}

func registryImportCommand(g *globals) *cli.Command {
	var file, repository string
	var dryRun bool
	return &cli.Command{
		Name:  "import",
		Args:  "NAME --file FILE",
		Short: "Push the images of an OCI layout tar into the registry",
		Long: `Pushes every tagged image of the OCI layout tar FILE (from 'sfcli registry
export', skopeo or crane) into the registry under its own repository and tag.
Images keep their digests. Blobs the registry already has are not sent again, so running the
same import again after an interruption continues it. A tag that already
points at another digest is shown, with the apps that use it, and moves only
after you confirm. --repository names the repository of images the file
does not say (a file from another tool). --dry-run shows the plan only.`,
		Flags: func(fs *flag.FlagSet) {
			fs.StringVar(&file, "file", "", "tar `file` to read (required)")
			fs.StringVar(&repository, "repository", "", "`repository` for images the file has none for")
			fs.BoolVar(&dryRun, "dry-run", false, "show what would change and send nothing")
		},
		Run: g.withSession(func(c *cli.Context, s *session, args []string) error {
			id, err := oneName(args, "registry name")
			if err != nil {
				return err
			}
			if file == "" {
				return cli.Usagef("--file FILE is required")
			}
			if repository != "" && !registryarchive.ValidRepository(repository) {
				return cli.Usagef("%q is not a valid repository", repository)
			}
			a, err := registryarchive.Open(file, repository)
			if err != nil {
				return err
			}
			defer a.Close()
			tenant, err := g.Tenant(s, true)
			if err != nil {
				return err
			}
			if err = importFits(c, g, s, tenant, id, a); err != nil {
				return err
			}
			r := newRegistryRemote(g, c, s, tenant, id)
			defer r.close()
			plan, err := a.Plan(c.Ctx, r.open)
			if err != nil {
				return err
			}
			used, err := importUsages(c, g, s, tenant, r.authority, plan)
			if err != nil {
				return err
			}
			var send []registryarchive.Entry
			moves := 0
			if err = cli.Print(c.Out, g.output.Format(), plan, func() cli.Rows {
				t := cli.Rows{Header: []string{"image", "action", "digest", "now", "used by"}}
				for _, ch := range plan {
					t.Add(ch.String(), ch.Action(), ch.Digest, ch.Current, strings.Join(used[ch.String()], ", "))
				}
				return t
			}); err != nil {
				return err
			}
			for _, ch := range plan {
				if ch.Action() == "move" {
					moves++
				}
				if ch.Action() != "same" {
					send = append(send, ch.Entry)
				}
			}
			if dryRun || len(send) == 0 {
				if len(send) == 0 {
					fmt.Fprintln(c.Err, "Every tag already points at the file's image; nothing to send.")
				}
				return nil
			}
			if moves > 0 {
				fmt.Fprintf(c.Err, "%d tags move to another image. Apps that use them get the new image on their next deploy or restart.\n", moves)
				if err = g.Prompter(c).Confirm("Move them?"); err != nil {
					return err
				}
			}
			sum, err := a.Push(c.Ctx, r.open, send)
			if err != nil {
				return fmt.Errorf("%w (run the same import again to continue)", err)
			}
			fmt.Fprintf(c.Out, "imported %d images into %s\n", sum.Images, id)
			return nil
		}),
	}
}

// importFits refuses a file larger than the registry before anything is
// sent. The registry still refuses a push that does not fit what it holds.
func importFits(c *cli.Context, g *globals, s *session, tenant, id string, a *registryarchive.Archive) error {
	ctx, cancel := g.Deadline(c)
	defer cancel()
	row, err := findRegistryRow(ctx, s, tenant, id)
	if err != nil {
		return err
	}
	blobs, total := a.Bytes()
	limits := row.Spec.Blobs
	if total > limits.TotalBytes || blobs > limits.Records {
		return fmt.Errorf("the file holds %s in %d blobs; registry %s holds at most %s in %d", cli.Size(total), blobs, id, cli.Size(limits.TotalBytes), limits.Records)
	}
	return nil
}

// importUsages lists, per image of the plan whose tag moves, the apps
// that use that tag now.
func importUsages(c *cli.Context, g *globals, s *session, tenant, authority string, plan []registryarchive.Change) (map[string][]string, error) {
	used := map[string][]string{}
	ctx, cancel := g.Deadline(c)
	defer cancel()
	for _, ch := range plan {
		if ch.Action() != "move" {
			continue
		}
		q := control.ImageUsageQuery{Refs: []string{authority + "/" + ch.String()}}
		after := ""
		for {
			page, err := s.Client.ImageUsages(ctx, s.Target, s.Stored.Session, tenant, q, after)
			if err != nil {
				return nil, err
			}
			for _, u := range page.Rows {
				what := u.App
				switch {
				case u.Match == "unknown":
					what = "(unknown)"
				case u.Service != "":
					what += "/" + u.Service
				case what == "":
					what = u.Kind
				}
				if !slices.Contains(used[ch.String()], what) {
					used[ch.String()] = append(used[ch.String()], what)
				}
			}
			if page.Next == "" || page.Next == after {
				break
			}
			after = page.Next
		}
	}
	return used, nil
}
