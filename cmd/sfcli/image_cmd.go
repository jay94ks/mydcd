// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"

	"github.com/jay94ks/seafield/internal/cli"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/registryclient"
)

// sfcli image: images in the tenant's registries and external sources.

func imageCommand(g *globals) *cli.Command {
	return &cli.Command{
		Name:  "image",
		Short: "Images in registries: list, show, usages, delete",
		Sub: []*cli.Command{
			imageListCommand(g),
			{Name: "show", Args: "IMAGE", Short: "Resolve an image and show its digest, platforms and trust", Run: g.withSession(imageResolve(g, false))},
			{Name: "resolve", Args: "IMAGE", Short: "Print the image pinned by digest (for scripts)", Run: g.withSession(imageResolve(g, true))},
			imagePullContentCommand(g),
			imageUsagesCommand(g),
			imageDeleteCommand(g),
		},
	}
}

// readCatalogue reads all repositories (repository "") or all images of one
// repository of a registry or external source.
func readCatalogue(ctx context.Context, s *session, tenant string, q control.RegistryCatalogueQuery) (registryclient.CataloguePage, error) {
	var out registryclient.CataloguePage
	after := ""
	for {
		result, err := s.Client.RegistryCatalogue(ctx, s.Target, s.Stored.Session, tenant, q, after)
		if err != nil {
			return out, err
		}
		if result.Page.Code != "OK" {
			return out, fmt.Errorf("the registry answered %s", result.Page.Code)
		}
		if after != "" && result.Page.Root != out.Root {
			return out, errors.New("the registry changed while reading; run the command again")
		}
		if after == "" {
			out = result.Page
			out.Repositories, out.Images = nil, nil
		}
		out.Repositories = append(out.Repositories, result.Page.Repositories...)
		out.Images = append(out.Images, result.Page.Images...)
		if len(out.Repositories)+len(out.Images) > registryclient.MaxCatalogueNames {
			return out, errors.New("too many names to list at once")
		}
		if result.Page.Next == "" {
			out.Next = ""
			return out, nil
		}
		if result.Page.Next == after {
			return out, errors.New("the server sent an invalid catalogue cursor")
		}
		after = result.Page.Next
	}
}

func catalogueKind(external bool) string {
	if external {
		return "external"
	}
	return "managed"
}

func imageListCommand(g *globals) *cli.Command {
	var external bool
	return &cli.Command{
		Name:  "list",
		Args:  "REGISTRY [REPOSITORY]",
		Short: "List the repositories of a registry, or the images of one repository",
		Flags: func(fs *flag.FlagSet) {
			fs.BoolVar(&external, "external", false, "REGISTRY is an external source")
		},
		Run: g.withSession(func(c *cli.Context, s *session, args []string) error {
			if len(args) < 1 || len(args) > 2 {
				return cli.Usagef("needs REGISTRY and optionally REPOSITORY")
			}
			q := control.RegistryCatalogueQuery{Kind: catalogueKind(external), ID: args[0]}
			if len(args) == 2 {
				q.Repository = args[1]
			}
			if !q.Valid() {
				return cli.Usagef("invalid registry or repository name")
			}
			tenant, err := g.Tenant(s, true)
			if err != nil {
				return err
			}
			ctx, cancel := g.Deadline(c)
			defer cancel()
			page, err := readCatalogue(ctx, s, tenant, q)
			if err != nil {
				return err
			}
			if q.Repository == "" {
				return cli.Print(c.Out, g.output.Format(), page.Repositories, func() cli.Rows {
					t := cli.Rows{Header: []string{"repository"}}
					for _, r := range page.Repositories {
						t.Add(r)
					}
					return t
				})
			}
			return cli.Print(c.Out, g.output.Format(), page.Images, func() cli.Rows {
				t := cli.Rows{Header: []string{"reference", "digest", "size"}}
				for _, m := range page.Images {
					t.Add(m.Reference, m.Digest, cli.Size(max(m.ImageBytes, 0)))
				}
				return t
			})
		}),
	}
}

func imageResolve(g *globals, pinnedOnly bool) func(*cli.Context, *session, []string) error {
	return func(c *cli.Context, s *session, args []string) error {
		if len(args) != 1 || !(control.ImageResolveQuery{Ref: args[0]}).Valid() {
			return cli.Usagef("needs one image reference, such as registry.example/shop/web:1.2")
		}
		tenant, err := g.Tenant(s, true)
		if err != nil {
			return err
		}
		ctx, cancel := g.Deadline(c)
		defer cancel()
		result, err := s.Client.ResolveImage(ctx, s.Target, s.Stored.Session, tenant, control.ImageResolveQuery{Ref: args[0]})
		if err != nil {
			return err
		}
		if result.Code != "OK" || result.Image == nil {
			return cli.ExitError{Code: 3, Err: fmt.Errorf("%s: %s", args[0], result.Code)}
		}
		if pinnedOnly && g.output.Format() == cli.Table {
			_, err = fmt.Fprintln(c.Out, result.Image.Pinned)
			return err
		}
		return cli.Print(c.Out, g.output.Format(), result, func() cli.Rows {
			t := cli.Rows{Header: []string{"image", "source", "trusted", "platforms"}}
			var platforms []string
			for _, p := range result.Image.Platforms {
				if p.Platform != nil {
					platforms = append(platforms, p.Platform.String())
				}
			}
			t.Add(result.Image.Pinned, result.Source, result.Trust.Trusted, strings.Join(platforms, ","))
			return t
		})
	}
}

// contentWriter stops writing when the command is interrupted.
type contentWriter struct {
	ctx context.Context
	w   io.Writer
}

func (w contentWriter) Write(p []byte) (int, error) {
	if err := w.ctx.Err(); err != nil {
		return 0, err
	}
	return w.w.Write(p)
}

// outputFile opens -O FILE (created new, mode 0600) or uses stdout when it
// is not a terminal. done must be called with the transfer's error; it
// removes a partial file.
func outputFile(c *cli.Context, path string) (io.Writer, func(error) error, error) {
	if path == "" || path == "-" {
		if f, ok := c.Out.(*os.File); ok && term.IsTerminal(int(f.Fd())) {
			return nil, nil, cli.Usagef("the content is not printed to a terminal; use -O FILE or a pipe")
		}
		return c.Out, func(err error) error { return err }, nil
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, nil, err
	}
	return f, func(err error) error {
		if err == nil {
			err = f.Sync()
		}
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			_ = os.Remove(path)
		}
		return err
	}, nil
}

func imagePullContentCommand(g *globals) *cli.Command {
	var kind, digest, output string
	return &cli.Command{
		Name:  "pull-content",
		Args:  "IMAGE@DIGEST --kind manifest|config|layer",
		Short: "Download an image's manifest, config or one layer",
		Long: `Downloads one part of an image pinned by digest to -O FILE, or to standard
output when it is a pipe. --digest names the config or layer (from the
manifest). A partial file is removed if the download fails. Long downloads
may need a larger --timeout.`,
		Flags: func(fs *flag.FlagSet) {
			fs.StringVar(&kind, "kind", "manifest", "manifest, config or layer")
			fs.StringVar(&digest, "digest", "", "digest of the config or layer")
			fs.StringVar(&output, "O", "", "write to this new `file` instead of standard output")
		},
		Run: g.withSession(func(c *cli.Context, s *session, args []string) error {
			if len(args) != 1 {
				return cli.Usagef("needs one image pinned by digest, such as registry.example/shop/web@sha256:...")
			}
			q := registryclient.ContentQuery{Ref: args[0], Kind: kind, Digest: digest}
			if !q.Valid() {
				return cli.Usagef("needs IMAGE@sha256:..., --kind manifest|config|layer and --digest for config and layer")
			}
			tenant, err := g.Tenant(s, true)
			if err != nil {
				return err
			}
			w, done, err := outputFile(c, output)
			if err != nil {
				return err
			}
			ctx, cancel := g.Deadline(c)
			defer cancel()
			info, err := s.Client.ReadImageContent(ctx, s.Target, s.Stored.Session, tenant, q, contentWriter{ctx, w})
			if err = done(err); err != nil {
				return err
			}
			fmt.Fprintf(c.Err, "%s %s: %s, %s\n", info.Kind, info.Digest, info.MediaType, cli.Size(max(info.Bytes, 0)))
			return nil
		}),
	}
}

func imageUsagesCommand(g *globals) *cli.Command {
	var source string
	return &cli.Command{
		Name:  "usages",
		Args:  "IMAGE | --source NAME",
		Short: "Show which apps, tasks and builds use an image or an external source",
		Flags: func(fs *flag.FlagSet) {
			fs.StringVar(&source, "source", "", "external source instead of an image")
		},
		Run: g.withSession(func(c *cli.Context, s *session, args []string) error {
			q := control.ImageUsageQuery{ExternalSource: source}
			if source == "" && len(args) == 1 {
				q.Refs = []string{args[0]}
			} else if source == "" || len(args) != 0 {
				return cli.Usagef("needs one IMAGE or --source NAME")
			}
			if !q.Valid() {
				return cli.Usagef("invalid image reference or source name")
			}
			tenant, err := g.Tenant(s, true)
			if err != nil {
				return err
			}
			ctx, cancel := g.Deadline(c)
			defer cancel()
			var rows []control.ImageUsage
			var root [32]byte
			after := ""
			for {
				page, err := s.Client.ImageUsages(ctx, s.Target, s.Stored.Session, tenant, q, after)
				if err != nil {
					return err
				}
				if after != "" && page.Root != root {
					return errors.New("usages changed while reading; run the command again")
				}
				root = page.Root
				rows = append(rows, page.Rows...)
				if page.Next == "" {
					break
				}
				if page.Next == after || len(rows) > 65536 {
					return errors.New("the server sent an invalid usage cursor")
				}
				after = page.Next
			}
			if rows == nil {
				rows = []control.ImageUsage{}
			}
			return cli.Print(c.Out, g.output.Format(), rows, func() cli.Rows {
				t := cli.Rows{Header: []string{"kind", "app", "service", "node", "image"}}
				for _, r := range rows {
					t.Add(r.Kind, r.App, r.Service, r.Node, r.Image)
				}
				return t
			})
		}),
	}
}

func imageDeleteCommand(g *globals) *cli.Command {
	var id cli.IDFlag
	var wait waitFlags
	var external, dryRun bool
	return &cli.Command{
		Name:  "delete",
		Args:  "REGISTRY REPOSITORY:TAG|REPOSITORY@DIGEST",
		Short: "Delete one image from a registry",
		Long: `Deletes one tag or digest. An image an app still uses is not deleted.
Run 'sfcli registry gc REGISTRY' afterwards to free its space.`,
		Flags: func(fs *flag.FlagSet) {
			fs.Var(&id, "id", "operation `id` (default: a new one)")
			fs.BoolVar(&external, "external", false, "REGISTRY is an external source")
			fs.BoolVar(&dryRun, "dry-run", false, "only show what would be deleted")
			wait.register(fs)
		},
		Run: g.withSession(func(c *cli.Context, s *session, args []string) error {
			if len(args) != 2 {
				return cli.Usagef("needs REGISTRY and REPOSITORY:TAG or REPOSITORY@DIGEST")
			}
			name, ref := args[0], args[1]
			repo, reference, ok := strings.Cut(ref, "@")
			if !ok {
				i := strings.LastIndexByte(ref, ':')
				if i <= 0 || strings.Contains(ref[i:], "/") {
					return cli.Usagef("%q needs :TAG or @DIGEST", ref)
				}
				repo, reference = ref[:i], ref[i+1:]
			}
			tenant, err := g.Tenant(s, true)
			if err != nil {
				return err
			}
			ctx, cancel := g.Deadline(c)
			defer cancel()
			page, err := readCatalogue(ctx, s, tenant, control.RegistryCatalogueQuery{Kind: catalogueKind(external), ID: name, Repository: repo})
			if err != nil {
				return err
			}
			var digest string
			for _, m := range page.Images {
				if m.Reference == reference || m.Digest == reference {
					digest = m.Digest
					break
				}
			}
			if digest == "" {
				return fmt.Errorf("no image %s in %s", ref, name)
			}
			q := control.RegistryMaintenanceQuery{Action: "delete-registry-image", ID: name, Repository: repo, Reference: reference, Digest: digest, External: external}
			if !q.Valid(true) {
				return cli.Usagef("invalid repository or reference")
			}
			plan, err := s.Client.PlanRegistryMaintenance(ctx, s.Target, s.Stored.Session, tenant, q)
			if err != nil {
				return err
			}
			if plan.InUse {
				return fmt.Errorf("%s (%s) is in use; see 'sfcli image usages %s/%s@%s'", ref, digest, page.Authority, repo, digest)
			}
			fmt.Fprintf(c.Err, "Delete %s/%s:%s (%s) from %s.\n", page.Authority, repo, reference, digest, name)
			if dryRun {
				return nil
			}
			if err = g.Prompter(c).Confirm("Delete it?"); err != nil {
				return err
			}
			return sendMaintenance(c, g, s, tenant, "image delete "+name+" "+ref, id.Get(), plan, wait)
		}),
	}
}
