// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/jay94ks/mydcd/internal/cli"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/cluster/lifecycle"
	"github.com/jay94ks/mydcd/internal/imagebuild"
	"github.com/jay94ks/mydcd/internal/userauth"
)

// mydc build context: where a build's files come from. Kind upload takes a
// ZIP, kind git saves a commit of a repository, kind draft is edited with
// 'mydc build draft'. Each saved set of files is a numbered version.

func buildContextCommand(g *globals) *cli.Command {
	return &cli.Command{
		Name:  "context",
		Short: "Build contexts and their versions",
		Sub: []*cli.Command{
			{Name: "list", Short: "List build contexts", Run: g.withSession(buildContextList(g))},
			{Name: "show", Args: "CONTEXT", Short: "Show a build context (as build-context.yaml with -o yaml)", Run: g.withSession(buildContextShow(g))},
			buildContextCreateCommand(g),
			buildContextDeleteCommand(g),
			{Name: "check", Args: "CONTEXT", Short: "Check that a Git context's repository can be read", Run: g.withSession(buildContextCheck(g))},
			buildContextUploadCommand(g),
			{Name: "versions", Args: "CONTEXT", Short: "List a context's kept versions", Run: g.withSession(buildContextVersions(g))},
			buildContextLsCommand(g),
			buildContextCatCommand(g),
		},
	}
}

func init() {
	opKinds["build-upload"] = buildUploadHandler
}

// buildContextFile is build-context.yaml (mydc build context create -f).
type buildContextFile struct {
	Version    int               `yaml:"version"`
	Kind       string            `yaml:"kind"`
	Node       string            `yaml:"node"`
	Dockerfile string            `yaml:"dockerfile,omitempty"`
	Args       map[string]string `yaml:"args,omitempty"`
	Secrets    []struct {
		ID     string `yaml:"id"`
		Realm  string `yaml:"realm"`
		Secret string `yaml:"secret"`
		Key    string `yaml:"key"`
	} `yaml:"secrets,omitempty"`
	Repository string   `yaml:"repository"`
	Tags       []string `yaml:"tags"`
	Platforms  []string `yaml:"platforms,omitempty"`
	Git        *struct {
		Repository        string `yaml:"repository"`
		Ref               string `yaml:"ref"`
		Path              string `yaml:"path,omitempty"`
		CredentialProfile string `yaml:"credential_profile,omitempty"`
		Automatic         bool   `yaml:"automatic,omitempty"`
	} `yaml:"git,omitempty"`
}

func contextFileOf(sp imagebuild.ContextSpec) buildContextFile {
	f := buildContextFile{Version: 1, Kind: sp.Kind, Node: sp.Root.Node, Dockerfile: sp.Dockerfile, Args: sp.Arguments, Repository: sp.Repository, Tags: sp.Tags, Platforms: sp.Platforms}
	for _, m := range sp.Secrets {
		f.Secrets = append(f.Secrets, struct {
			ID     string `yaml:"id"`
			Realm  string `yaml:"realm"`
			Secret string `yaml:"secret"`
			Key    string `yaml:"key"`
		}{m.ID, m.Realm, m.Secret, m.Key})
	}
	if g := sp.Git; g != nil {
		f.Git = &struct {
			Repository        string `yaml:"repository"`
			Ref               string `yaml:"ref"`
			Path              string `yaml:"path,omitempty"`
			CredentialProfile string `yaml:"credential_profile,omitempty"`
			Automatic         bool   `yaml:"automatic,omitempty"`
		}{g.Repository, g.Ref, g.Path, g.CredentialProfile, g.Automatic}
	}
	return f
}

// findContext returns the context, or nil when there is none.
func findContext(ctx context.Context, s *session, tenant, id string) (*control.ImageBuildContextView, uint64, error) {
	x, epoch, err := findContextRecord(ctx, s, tenant, id)
	if x != nil && x.Deleted {
		x = nil
	}
	return x, epoch, err
}

// findContextRecord also returns a deleted context: creating the name again
// continues from that record's revision.
func findContextRecord(ctx context.Context, s *session, tenant, id string) (*control.ImageBuildContextView, uint64, error) {
	p, err := s.Client.ImageBuilds(ctx, s.Target, s.Stored.Session, tenant, control.ImageBuildQuery{Part: "contexts", ID: id}, "")
	if err != nil {
		return nil, 0, err
	}
	for i := range p.Contexts {
		if x := &p.Contexts[i]; x.Spec.ID == id {
			return x, p.Epoch, nil
		}
	}
	return nil, p.Epoch, nil
}

// contextToReplace checks a new spec against the record kept under the same
// name and returns the live context it replaces (nil for a new or deleted
// one). The server keeps a context's kind and storage for good, also after
// it is deleted, so a changed one needs a new name.
func contextToReplace(record *control.ImageBuildContextView, sp imagebuild.ContextSpec) (*control.ImageBuildContextView, error) {
	if record == nil {
		return nil, nil
	}
	if record.Spec.Root != sp.Root || record.Spec.Kind != sp.Kind {
		return nil, fmt.Errorf("build context %s was made as kind %s on storage %s of %s; its kind and storage cannot change, even after delete. Use a new context name", record.Spec.ID, record.Spec.Kind, record.Spec.Root.ID, record.Spec.Root.Node)
	}
	if record.Deleted {
		return nil, nil
	}
	return record, nil
}

// versionBuilds names the kept builds of one version; the server keeps the
// version while any of them is not deleted.
func versionBuilds(ctx context.Context, s *session, tenant, id string, number uint64) ([]string, error) {
	p, err := buildPart(ctx, s, tenant, control.ImageBuildQuery{Part: "jobs", ID: id})
	if err != nil {
		return nil, err
	}
	return keptBuilds(p.Jobs, id, number), nil
}

func keptBuilds(jobs []control.ImageBuildJobView, id string, number uint64) []string {
	var names []string
	for _, j := range jobs {
		if !j.Deleted && j.Context == id && j.Number == number {
			names = append(names, j.ID)
		}
	}
	slices.Sort(names)
	return names
}

func mustContext(ctx context.Context, s *session, tenant, id string) (*control.ImageBuildContextView, error) {
	x, _, err := findContext(ctx, s, tenant, id)
	if err == nil && x == nil {
		err = fmt.Errorf("no build context %q in tenant %s", id, tenant)
	}
	return x, err
}

func buildContextList(g *globals) func(*cli.Context, *session, []string) error {
	return func(c *cli.Context, s *session, args []string) error {
		if len(args) != 0 {
			return cli.Usagef("list takes no arguments")
		}
		tenant, err := g.Tenant(s, true)
		if err != nil {
			return err
		}
		ctx, cancel := g.Deadline(c)
		defer cancel()
		p, err := buildPart(ctx, s, tenant, control.ImageBuildQuery{Part: "contexts"})
		if err != nil {
			return err
		}
		list := slices.DeleteFunc(p.Contexts, func(x control.ImageBuildContextView) bool { return x.Deleted })
		if list == nil {
			list = []control.ImageBuildContextView{}
		}
		newest := map[string]uint64{}
		for _, x := range list {
			vs, err := liveVersions(ctx, s, tenant, x.Spec.ID)
			if err != nil {
				return err
			}
			if len(vs) > 0 {
				newest[x.Spec.ID] = vs[0].Number
			}
		}
		return cli.Print(c.Out, g.output.Format(), list, func() cli.Rows {
			t := cli.Rows{Header: []string{"context", "kind", "node", "repository", "version", "revision"}}
			for _, x := range list {
				v := "-"
				if n := newest[x.Spec.ID]; n > 0 {
					v = fmt.Sprint(n)
				}
				t.Add(x.Spec.ID, x.Spec.Kind, x.Spec.Root.Node, x.Spec.Repository, v, x.Revision)
			}
			return t
		})
	}
}

func buildContextShow(g *globals) func(*cli.Context, *session, []string) error {
	return func(c *cli.Context, s *session, args []string) error {
		id, err := oneName(args, "context name")
		if err != nil {
			return err
		}
		tenant, err := g.Tenant(s, true)
		if err != nil {
			return err
		}
		ctx, cancel := g.Deadline(c)
		defer cancel()
		x, err := mustContext(ctx, s, tenant, id)
		if err != nil {
			return err
		}
		if g.output.Format() == cli.YAML {
			return yaml.NewEncoder(c.Out).Encode(contextFileOf(x.Spec))
		}
		vs, err := liveVersions(ctx, s, tenant, id)
		if err != nil {
			return err
		}
		return cli.Print(c.Out, g.output.Format(), struct {
			*control.ImageBuildContextView
			Versions []control.ImageBuildVersionView `json:"versions"`
		}{x, vs}, nil)
	}
}

func buildContextCreateCommand(g *globals) *cli.Command {
	var id cli.IDFlag
	var rev cli.RevisionFlag
	var file string
	return &cli.Command{
		Name:  "create",
		Args:  "CONTEXT -f build-context.yaml",
		Short: "Create a build context, or replace its settings",
		Long: `Creates the context from a file, or replaces the settings of an existing
one (after asking). The file (see docs/cli/build.md):

  version: 1
  kind: upload               # upload, git or draft
  node: node-a               # a server of the build policy
  dockerfile: Dockerfile     # default Dockerfile
  args: {NODE_ENV: production}
  secrets: [{id: npm, realm: shop, secret: npm-token, key: token}]
  repository: shop/web       # in the policy's registry
  tags: [latest]
  platforms: [linux/amd64]   # default: the policy's platforms
  git:                       # kind git only
    repository: https://git.example/shop/web.git
    ref: main
    path: web
    credential_profile: git-read
    automatic: true`,
		Flags: func(fs *flag.FlagSet) {
			fs.Var(&id, "id", "operation `id` (default: a new one)")
			fs.Var(&rev, "if-revision", "only if the context is still at this `revision`")
			fs.StringVar(&file, "f", "", "build-context.yaml (required)")
		},
		Run: g.withSession(func(c *cli.Context, s *session, args []string) error {
			name, err := oneName(args, "context name")
			if err != nil {
				return err
			}
			if file == "" {
				return cli.Usagef("needs -f build-context.yaml")
			}
			var f buildContextFile
			if err = readYAMLFile(file, 64<<10, &f); err != nil {
				return err
			}
			if f.Version != 1 {
				return cli.Usagef("%s: version must be 1", file)
			}
			tenant, err := g.Tenant(s, true)
			if err != nil {
				return err
			}
			ctx, cancel := g.Deadline(c)
			defer cancel()
			pol, err := currentPolicy(ctx, s, tenant)
			if err != nil {
				return err
			}
			if pol == nil {
				return fmt.Errorf("tenant %s has no build policy; set one first with 'mydc build policy set -f build-policy.yaml'", tenant)
			}
			sp := imagebuild.ContextSpec{Tenant: tenant, ID: name, Kind: f.Kind, Dockerfile: f.Dockerfile, Arguments: f.Args, Repository: f.Repository, Tags: f.Tags, Platforms: f.Platforms}
			if sp.Dockerfile == "" {
				sp.Dockerfile = "Dockerfile"
			}
			if len(sp.Platforms) == 0 {
				sp.Platforms = pol.Spec.Platforms
			}
			found := false
			for _, n := range pol.Spec.Nodes {
				if n.Node == f.Node {
					sp.Root, found = n.Root, true
				}
			}
			if !found {
				return cli.Usagef("%s: node %q is not a server of the build policy", file, f.Node)
			}
			for _, m := range f.Secrets {
				sp.Secrets = append(sp.Secrets, imagebuild.SecretMount{ID: m.ID, Realm: m.Realm, Secret: m.Secret, Key: m.Key})
			}
			if x := f.Git; x != nil {
				sp.Git = &imagebuild.GitContext{Repository: x.Repository, Ref: x.Ref, Path: x.Path, CredentialProfile: x.CredentialProfile, Automatic: x.Automatic}
			}
			if sp.Validate() != nil {
				return cli.Usagef("%s: invalid context: kind upload, git or draft (git: only for kind git), a clean dockerfile path, a repository name, 1-16 tags and platforms, at most 128 args and 32 secrets", file)
			}
			record, _, err := findContextRecord(ctx, s, tenant, name)
			if err != nil {
				return err
			}
			cur, err := contextToReplace(record, sp)
			if err != nil {
				return err
			}
			expected, err := rev.Resolve(func() (uint64, error) {
				if record == nil {
					return 0, nil
				}
				return record.Revision, nil
			})
			if err != nil {
				return err
			}
			if cur != nil {
				fmt.Fprintf(c.Err, "Replace the settings of build context %s (revision %d).\n", name, cur.Revision)
				if err = g.Prompter(c).Confirm("Replace them?"); err != nil {
					return err
				}
			}
			opID := id.Get()
			if _, err = g.send(c, s, change{Summary: "build context create " + name, ID: opID, Action: "put-build-context", Expected: expected, Payload: control.ImageBuildContextPut{Spec: sp}}); err != nil {
				return err
			}
			fmt.Fprintf(c.Out, "build context %s saved (%s)\n", name, opID)
			return nil
		}),
	}
}

func buildContextDeleteCommand(g *globals) *cli.Command {
	var id cli.IDFlag
	var rev cli.RevisionFlag
	var version string
	return &cli.Command{
		Name:  "delete",
		Args:  "CONTEXT [--version N]",
		Short: "Delete a build context, or one of its versions",
		Long: `Deletes the context. Its versions must be deleted first, one at a time
with --version.`,
		Flags: func(fs *flag.FlagSet) {
			fs.Var(&id, "id", "operation `id` (default: a new one)")
			fs.Var(&rev, "if-revision", "only if the context is still at this `revision`")
			fs.StringVar(&version, "version", "", "delete this version `number` instead of the context")
		},
		Run: g.withSession(func(c *cli.Context, s *session, args []string) error {
			name, err := oneName(args, "context name")
			if err != nil {
				return err
			}
			tenant, err := g.Tenant(s, true)
			if err != nil {
				return err
			}
			ctx, cancel := g.Deadline(c)
			defer cancel()
			x, err := mustContext(ctx, s, tenant, name)
			if err != nil {
				return err
			}
			opID := id.Get()
			if version != "" {
				v, err := pickVersion(ctx, s, tenant, name, version)
				if err != nil {
					return err
				}
				if users, err := versionBuilds(ctx, s, tenant, name, v.Number); err != nil {
					return err
				} else if len(users) > 0 {
					return fmt.Errorf("version %d of build context %s is kept by builds %s; delete them first with 'mydc build delete'", v.Number, name, strings.Join(users, ", "))
				}
				fmt.Fprintf(c.Err, "Delete version %d of build context %s.\n", v.Number, name)
				if err = g.Prompter(c).Confirm("Delete it?"); err != nil {
					return err
				}
				ch := change{Summary: fmt.Sprintf("build context delete %s version %d", name, v.Number), ID: opID, Action: "delete-build-version", Expected: v.Number, Payload: control.ImageBuildVersionSelection{Tenant: tenant, ID: v.ID}}
				if _, err = g.send(c, s, ch); err != nil {
					return err
				}
				fmt.Fprintf(c.Out, "version %d of %s deleted (%s)\n", v.Number, name, opID)
				return nil
			}
			vs, err := liveVersions(ctx, s, tenant, name)
			if err != nil {
				return err
			}
			if len(vs) > 0 {
				nums := make([]string, 0, len(vs))
				for _, v := range vs {
					nums = append(nums, fmt.Sprint(v.Number))
				}
				return fmt.Errorf("build context %s still has versions %s; delete them first with --version", name, strings.Join(nums, ", "))
			}
			expected, err := rev.Resolve(func() (uint64, error) { return x.Revision, nil })
			if err != nil {
				return err
			}
			fmt.Fprintf(c.Err, "Delete build context %s.\n", name)
			if err = g.Prompter(c).Confirm("Delete it?"); err != nil {
				return err
			}
			if _, err = g.send(c, s, change{Summary: "build context delete " + name, ID: opID, Action: "delete-build-context", Expected: expected, Payload: control.ImageBuildSelection{Tenant: tenant, ID: name}}); err != nil {
				return err
			}
			fmt.Fprintf(c.Out, "build context %s deleted (%s)\n", name, opID)
			return nil
		}),
	}
}

func buildContextCheck(g *globals) func(*cli.Context, *session, []string) error {
	return func(c *cli.Context, s *session, args []string) error {
		name, err := oneName(args, "context name")
		if err != nil {
			return err
		}
		tenant, err := g.Tenant(s, true)
		if err != nil {
			return err
		}
		ctx, cancel := g.Deadline(c)
		defer cancel()
		r, err := s.Client.CheckBuildContext(ctx, s.Target, s.Stored.Session, tenant, control.ImageBuildSourceQuery{ID: name})
		if err != nil {
			return err
		}
		if err = cli.Print(c.Out, g.output.Format(), r, func() cli.Rows {
			t := cli.Rows{Header: []string{"context", "result", "commit", "files", "size"}}
			t.Add(r.Context, r.Code, r.Commit, r.Entries, cli.Size(max(r.ExpandedBytes, 0)))
			return t
		}); err != nil {
			return err
		}
		if r.Code != "OK" {
			return cli.ExitError{Code: 3, Err: fmt.Errorf("build context %s: %s", name, r.Code)}
		}
		return nil
	}
}

func buildContextVersions(g *globals) func(*cli.Context, *session, []string) error {
	return func(c *cli.Context, s *session, args []string) error {
		name, err := oneName(args, "context name")
		if err != nil {
			return err
		}
		tenant, err := g.Tenant(s, true)
		if err != nil {
			return err
		}
		ctx, cancel := g.Deadline(c)
		defer cancel()
		vs, err := liveVersions(ctx, s, tenant, name)
		if err != nil {
			return err
		}
		if vs == nil {
			vs = []control.ImageBuildVersionView{}
		}
		return cli.Print(c.Out, g.output.Format(), vs, func() cli.Rows {
			t := cli.Rows{Header: []string{"version", "id", "files", "size", "commit", "saved"}}
			for _, v := range vs {
				t.Add(v.Number, hex.EncodeToString(v.ID[:6]), v.Entries, cli.Size(max(v.ExpandedBytes, 0)), v.Commit, unixTime(uint64(max(v.At, 0))))
			}
			return t
		})
	}
}

func entryRows(entries []imagebuild.Entry) func() cli.Rows {
	return func() cli.Rows {
		t := cli.Rows{Header: []string{"path", "type", "size"}}
		for _, e := range entries {
			kind := "file"
			if e.Directory {
				kind = "dir"
			} else if e.Executable {
				kind = "exec"
			}
			size := ""
			if !e.Directory {
				size = cli.Size(max(e.Bytes, 0)).String()
			}
			t.Add(e.Path, kind, size)
		}
		return t
	}
}

func buildContextLsCommand(g *globals) *cli.Command {
	var version string
	return &cli.Command{
		Name:  "ls",
		Args:  "CONTEXT [--version N]",
		Short: "List the files of a version (default the newest)",
		Flags: func(fs *flag.FlagSet) {
			fs.StringVar(&version, "version", "", "version `number` (default: the newest)")
		},
		Run: g.withSession(func(c *cli.Context, s *session, args []string) error {
			name, err := oneName(args, "context name")
			if err != nil {
				return err
			}
			tenant, err := g.Tenant(s, true)
			if err != nil {
				return err
			}
			ctx, cancel := g.Deadline(c)
			defer cancel()
			v, err := pickVersion(ctx, s, tenant, name, version)
			if err != nil {
				return err
			}
			entries := []imagebuild.Entry{}
			after := ""
			for i := 0; ; i++ {
				p, err := s.Client.BuildContextContent(ctx, s.Target, s.Stored.Session, tenant, imagebuild.ContentQuery{Version: v.ID, Part: "tree"}, after)
				if err != nil {
					return err
				}
				entries = append(entries, p.Page.Entries...)
				if p.Next == "" {
					break
				}
				if p.Next == after || i > 8192 {
					return errors.New("the server sent an invalid file list cursor")
				}
				after = p.Next
			}
			return cli.Print(c.Out, g.output.Format(), entries, entryRows(entries))
		}),
	}
}

func buildContextCatCommand(g *globals) *cli.Command {
	var version, output string
	return &cli.Command{
		Name:  "cat",
		Args:  "CONTEXT PATH [--version N]",
		Short: "Print one file of a version (default the newest)",
		Long:  `Writes the file to -O FILE, or to standard output.`,
		Flags: func(fs *flag.FlagSet) {
			fs.StringVar(&version, "version", "", "version `number` (default: the newest)")
			fs.StringVar(&output, "O", "", "write to this new `file` instead of standard output")
		},
		Run: g.withSession(func(c *cli.Context, s *session, args []string) error {
			if len(args) != 2 || !lifecycle.ValidID(args[0]) || !imagebuild.ContextPath(args[1]) {
				return cli.Usagef("needs CONTEXT and a file PATH such as src/main.go")
			}
			tenant, err := g.Tenant(s, true)
			if err != nil {
				return err
			}
			ctx, cancel := g.Deadline(c)
			defer cancel()
			v, err := pickVersion(ctx, s, tenant, args[0], version)
			if err != nil {
				return err
			}
			w, done, err := plainOutput(c, output)
			if err != nil {
				return err
			}
			_, err = s.Client.ReadBuildContextFile(ctx, s.Target, s.Stored.Session, tenant, imagebuild.ContentQuery{Version: v.ID, Part: "file", Path: args[1]}, contentWriter{ctx, w})
			return done(err)
		}),
	}
}

// plainOutput is outputFile, but a terminal is fine: build files are text.
func plainOutput(c *cli.Context, path string) (io.Writer, func(error) error, error) {
	if path == "" || path == "-" {
		return c.Out, func(err error) error { return err }, nil
	}
	return outputFile(c, path)
}

// --- upload ---

func buildContextUploadCommand(g *globals) *cli.Command {
	var id cli.IDFlag
	return &cli.Command{
		Name:  "upload",
		Args:  "CONTEXT [FILE.zip]",
		Short: "Save a new version: a ZIP, or the Git context's current commit",
		Long: `For a context of kind upload, sends FILE.zip (at most 500 MB) as a new
version. For kind git, saves the configured ref's current commit; no file is
given. A draft is saved with 'mydc build draft freeze'.

If the upload stops part way, run the same command again with the same --id
(or 'mydc op resume ID') to continue it.`,
		Flags: func(fs *flag.FlagSet) {
			fs.Var(&id, "id", "operation `id`; give the earlier one to continue (default: a new one)")
		},
		Run: g.withSession(func(c *cli.Context, s *session, args []string) error {
			if len(args) < 1 || len(args) > 2 || !lifecycle.ValidID(args[0]) {
				return cli.Usagef("needs CONTEXT and, for an upload context, FILE.zip")
			}
			name := args[0]
			tenant, err := g.Tenant(s, true)
			if err != nil {
				return err
			}
			ctx, cancel := g.Deadline(c)
			x, err := mustContext(ctx, s, tenant, name)
			cancel()
			if err != nil {
				return err
			}
			opID := id.Get()
			switch x.Spec.Kind {
			case "upload":
				if len(args) != 2 {
					return cli.Usagef("context %s takes a ZIP: mydc build context upload %s FILE.zip", name, name)
				}
				if len(opID) > 40 {
					return cli.Usagef("--id for an upload is at most 40 characters")
				}
				if strings.ContainsAny(args[1], " \t\n") {
					return cli.Usagef("the ZIP path must not contain spaces")
				}
				if err = g.Record(s, "build-upload", "build context upload "+name+" "+args[1], opID); err != nil {
					return err
				}
				return g.uploadZIP(c, s, tenant, name, args[1], opID, id.String() != "")
			case "git":
				if len(args) != 1 {
					return cli.Usagef("context %s is a Git context; it takes no file", name)
				}
				return g.saveGit(c, s, tenant, name, opID)
			}
			return cli.Usagef("context %s is a draft; save it with 'mydc build draft freeze %s'", name, name)
		}),
	}
}

// uploadZIP sends a ZIP under the op's ID (upload ID and request prefix).
// The whole transfer has the session's time, not one --timeout per call.
func (g *globals) uploadZIP(c *cli.Context, s *session, tenant, name, path, opID string, resume bool) error {
	fmt.Fprintf(c.Err, "%s: uploading %s to %s\n", opID, path, name)
	r, err := uploadBuildZIP(c.Ctx, s, tenant, path, buildUploadTarget{Context: name, Upload: opID, Prefix: opID, Resume: resume})
	if err != nil {
		if c.Ctx.Err() != nil {
			g.settle(opID, cli.Accepted, "incomplete")
			return errStillRunning{opID}
		}
		g.settle(opID, cli.Accepted, "incomplete: "+err.Error())
		return fmt.Errorf("%w; continue with 'mydc op resume %s'", err, opID)
	}
	version, _ := r["version"].(string)
	g.settle(opID, cli.Done, "saved version "+short(version))
	fmt.Fprintf(c.Out, "build context %s: new version %s (%s)\n", name, short(version), opID)
	return nil
}

func short(hexID string) string {
	if len(hexID) > 12 {
		return hexID[:12]
	}
	return hexID
}

// buildUploadHandler settles "build context upload CONTEXT PATH" ops: Show
// reads the upload, Resume sends the rest of the same file.
func buildUploadHandler(g *globals) cli.Handler {
	run := func(c *cli.Context, op cli.Op, resume bool) (cli.State, string, error) {
		words := opWords(op)
		if len(words) != 5 {
			return "", "", fmt.Errorf("op %s has an unexpected summary", op.ID)
		}
		name, path := words[3], words[4]
		s, err := g.opSession(c, op)
		if err != nil {
			return "", "", err
		}
		defer s.Close()
		if resume {
			if err = g.uploadZIP(c, s, op.Tenant, name, path, op.ID, true); err != nil {
				return "", "", err
			}
			return cli.Done, "saved", nil
		}
		ctx, cancel := g.Deadline(c)
		defer cancel()
		p, err := s.Client.ImageBuilds(ctx, s.Target, s.Stored.Session, op.Tenant, control.ImageBuildQuery{Part: "uploads", Upload: op.ID}, "")
		if err != nil {
			return "", "", err
		}
		if len(p.Uploads) == 0 {
			return cli.Failed, "not started; run the upload again", nil
		}
		u := p.Uploads[0]
		switch {
		case u.Closed && u.Version != ([32]byte{}):
			return cli.Done, "saved version " + short(hex.EncodeToString(u.Version[:])), nil
		case u.ExpiredAt != 0 || u.ReclaimedAt != 0:
			return cli.Failed, "expired before it was complete", nil
		}
		return cli.Accepted, fmt.Sprintf("incomplete: %d of %d parts; 'mydc op resume %s' continues it", u.Received, u.Scope.Parts(), op.ID), nil
	}
	return cli.Handler{
		Show:   func(c *cli.Context, op cli.Op) (cli.State, string, error) { return run(c, op, false) },
		Resume: func(c *cli.Context, op cli.Op) (cli.State, string, error) { return run(c, op, true) },
	}
}

// sendSaved sends a change whose payload comes from a one-time step on the
// server (a Git save, a draft freeze): when --id already names a saved
// change it is sent again as it is, and build is not called.
func (g *globals) sendSaved(c *cli.Context, s *session, summary, id string, build func() (change, error)) error {
	record, err := userauth.LoadOperation(s.Home, s.Client, s.Stored.Session, id)
	var ch change
	switch {
	case errors.Is(err, userauth.ErrOperationMissing):
		if ch, err = build(); err != nil {
			return err
		}
	case err != nil:
		return err
	default:
		ch = change{Action: record.Operation.Change.Action, Expected: record.Operation.Change.Expected, Payload: json.RawMessage(record.Operation.Change.Payload)}
	}
	ch.Summary, ch.ID = summary, id
	_, err = g.send(c, s, ch)
	return err
}

// saveGit fetches the Git context's ref on its server and publishes it as a
// new version.
func (g *globals) saveGit(c *cli.Context, s *session, tenant, name, opID string) error {
	err := g.sendSaved(c, s, "build context upload "+name, opID, func() (change, error) {
		ctx, cancel := g.Deadline(c)
		defer cancel()
		plan, err := s.Client.PlanGitSave(ctx, s.Target, s.Stored.Session, tenant, name, opID)
		if err != nil {
			return change{}, err
		}
		fmt.Fprintf(c.Err, "%s: saving commit %s of %s\n", opID, plan.Commit, name)
		r, err := s.Client.SaveGitContext(ctx, s.Target, s.Stored.Session, plan)
		cancel()
		for err == nil && r.Code == "PENDING" {
			select {
			case <-c.Ctx.Done():
				return change{}, c.Ctx.Err()
			case <-time.After(2 * time.Second):
			}
			ctx, cancel := g.Deadline(c)
			r, err = s.Client.GitSaveResult(ctx, s.Target, s.Stored.Session, plan)
			cancel()
		}
		if err != nil {
			return change{}, err
		}
		if r.Code != "SAVED" || r.Saved == nil {
			return change{}, fmt.Errorf("the Git source could not be saved (%s); see 'mydc build context check %s'", r.Code, name)
		}
		return change{Action: "publish-build-git", Expected: plan.ContextRevision, Payload: control.ImageBuildGitPublish{Tenant: tenant, Context: name, Saved: *r.Saved}}, nil
	})
	if err != nil {
		return err
	}
	fmt.Fprintf(c.Out, "build context %s: new version saved (%s)\n", name, opID)
	return nil
}
