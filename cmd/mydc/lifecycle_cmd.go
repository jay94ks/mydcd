// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"strings"

	"github.com/jay94ks/mydcd/internal/cli"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/userauth"
	checker "github.com/jay94ks/mydcd/internal/workload/lifecycle"
)

// mydc lifecycle: a tenant's named lifecycle scripts (Go checks that app
// containers run) and the tenant policy for building and running them.
// Usage: docs/cli/lifecycle.md.

func lifecycleCommand(g *globals) *cli.Command {
	return &cli.Command{
		Name:  "lifecycle",
		Short: "Manage lifecycle scripts and their tenant policy",
		Long: `Lifecycle scripts are Go programs an app's services refer to by name
(x-mydc lifecycle in app.yaml). Each 'script put' stores a new revision;
apps keep the revision they were deployed with.`,
		Sub: []*cli.Command{
			{
				Name:  "script",
				Short: "List, show, upload and retire named scripts",
				Sub: []*cli.Command{
					lifecycleScriptListCommand(g),
					lifecycleScriptShowCommand(g),
					lifecycleScriptPutCommand(g),
					lifecycleScriptSelectCommand(g, "retire", "Stop new apps from using a revision (running apps keep it)"),
					lifecycleScriptSelectCommand(g, "delete", "Delete a retired revision"),
				},
			},
			{
				Name:  "policy",
				Short: "Show or set the tenant's lifecycle policy",
				Sub:   []*cli.Command{lifecyclePolicyShowCommand(g), lifecyclePolicySetCommand(g)},
			},
			lifecycleCheckCommand(g),
		},
	}
}

// lifecycleCatalog reads the tenant's script and policy records at one
// revision.
func lifecycleCatalog(c *cli.Context, g *globals, s *session, tenant string) ([]control.LifecycleEntry, uint64, error) {
	rows := []control.LifecycleEntry{}
	after := ""
	var root, revision uint64
	for range 8192 {
		ctx, cancel := g.Deadline(c)
		reply, err := s.Client.LifecyclePage(ctx, s.Target, s.Stored.Session, tenant, after)
		cancel()
		if err != nil {
			return nil, 0, err
		}
		if after == "" {
			root, revision = reply.LifecycleRootRevision, reply.LifecycleRevision
		} else if root != reply.LifecycleRootRevision || revision != reply.LifecycleRevision {
			return nil, 0, errors.New("the scripts changed while they were read; run the command again")
		}
		for _, row := range reply.Lifecycles {
			rows = append(rows, row)
			after = row.Key
		}
		if reply.LifecyclesNext == "" || len(reply.Lifecycles) == 0 {
			return rows, revision, nil
		}
	}
	return nil, 0, errors.New("too many lifecycle records")
}

func lifecycleScripts(rows []control.LifecycleEntry, name string) []control.LifecycleEntry {
	out := []control.LifecycleEntry{}
	for _, r := range rows {
		if r.Source != nil && (name == "" || r.Name == name) {
			out = append(out, r)
		}
	}
	return out
}

// scriptRecord is the revision of the script name's record (its CAS): it
// grows with every put, retire and delete of the name. 0 means a new name.
func scriptRecord(rows []control.LifecycleEntry, name string) uint64 {
	n := uint64(0)
	for _, r := range rows {
		if r.Source != nil && r.Name == name {
			n = max(n, r.RecordRevision)
		}
	}
	return n
}

func scriptState(r control.LifecycleEntry) string {
	switch {
	case r.Deleted:
		return "deleted"
	case r.Active:
		return "active"
	}
	return "retired"
}

func lifecycleScriptListCommand(g *globals) *cli.Command {
	return &cli.Command{
		Name:  "list",
		Short: "List script revisions",
		Run: g.withSession(func(c *cli.Context, s *session, args []string) error {
			if len(args) != 0 {
				return cli.Usagef("list takes no arguments")
			}
			tenant, err := g.Tenant(s, true)
			if err != nil {
				return err
			}
			rows, _, err := lifecycleCatalog(c, g, s, tenant)
			if err != nil {
				return err
			}
			scripts := lifecycleScripts(rows, "")
			return cli.Print(c.Out, g.output.Format(), scripts, func() cli.Rows {
				t := cli.Rows{Header: []string{"name", "revision", "state", "size", "modules", "digest"}}
				for _, r := range scripts {
					t.Add(r.Name, r.SourceRevision, scriptState(r), r.Source.Length, len(r.Source.Modules), hex.EncodeToString(r.Source.Digest[:6]))
				}
				return t
			})
		}),
	}
}

func scriptNameArg(args []string, verb string) (string, error) {
	if len(args) != 1 || !checker.ValidScriptName(args[0]) {
		return "", cli.Usagef("%s needs one script name", verb)
	}
	return args[0], nil
}

// pickRevision is --revision, or the newest active revision of the script.
func pickRevision(scripts []control.LifecycleEntry, name string, revision uint64) (control.LifecycleEntry, error) {
	var found *control.LifecycleEntry
	for i, r := range scripts {
		if revision != 0 && r.SourceRevision == revision || revision == 0 && r.Active && (found == nil || r.SourceRevision > found.SourceRevision) {
			found = &scripts[i]
		}
	}
	if found == nil {
		if revision != 0 {
			return control.LifecycleEntry{}, fmt.Errorf("script %s has no revision %d", name, revision)
		}
		return control.LifecycleEntry{}, fmt.Errorf("script %s has no active revision; pass --revision", name)
	}
	return *found, nil
}

func lifecycleScriptShowCommand(g *globals) *cli.Command {
	var revision uint64
	var source bool
	return &cli.Command{
		Name:  "show",
		Args:  "NAME",
		Short: "Show a script revision",
		Flags: func(fs *flag.FlagSet) {
			fs.Uint64Var(&revision, "revision", 0, "this `revision` (default: the newest active one)")
			fs.BoolVar(&source, "source", false, "print the Go source")
		},
		Run: g.withSession(func(c *cli.Context, s *session, args []string) error {
			name, err := scriptNameArg(args, "show")
			if err != nil {
				return err
			}
			tenant, err := g.Tenant(s, true)
			if err != nil {
				return err
			}
			rows, _, err := lifecycleCatalog(c, g, s, tenant)
			if err != nil {
				return err
			}
			r, err := pickRevision(lifecycleScripts(rows, name), name, revision)
			if err != nil {
				return err
			}
			if source {
				ctx, cancel := g.Deadline(c)
				text, err := s.Client.LifecycleSource(ctx, s.Target, s.Stored.Session, tenant, name, r.SourceRevision)
				cancel()
				if err != nil {
					return err
				}
				if g.output.Format() != cli.Table {
					return cli.Print(c.Out, g.output.Format(), text, nil)
				}
				_, err = fmt.Fprint(c.Out, text.Source)
				return err
			}
			if g.output.Format() != cli.Table {
				return cli.Print(c.Out, g.output.Format(), r, nil)
			}
			fmt.Fprintf(c.Out, "Name:     %s\nRevision: %d\nState:    %s\nSize:     %d bytes\nDigest:   %s\n", r.Name, r.SourceRevision, scriptState(r), r.Source.Length, hex.EncodeToString(r.Source.Digest[:]))
			for _, m := range r.Source.Modules {
				fmt.Fprintf(c.Out, "Module:   %s %s\n", m.Path, m.Version)
			}
			return nil
		}),
	}
}

// moduleLock is one entry of modules.yaml, the exact modules a script may
// import: path, version, sha256 of the module ZIP and its size in bytes.
type moduleLock struct {
	Path    string `yaml:"path"`
	Version string `yaml:"version"`
	SHA256  string `yaml:"sha256"`
	Size    uint64 `yaml:"size"`
}

func readModuleLock(c *cli.Context, path string) ([]checker.ModulePin, error) {
	var locks []moduleLock
	if err := decodeYAMLFile(c, path, 24<<10, &locks); err != nil {
		return nil, err
	}
	pins := []checker.ModulePin{}
	for _, l := range locks {
		raw, err := hex.DecodeString(l.SHA256)
		if err != nil || len(raw) != 32 {
			return nil, fmt.Errorf("%s: module %s needs sha256 as 64 hex characters", path, l.Path)
		}
		p := checker.ModulePin{Path: l.Path, Version: l.Version, Length: l.Size}
		copy(p.Digest[:], raw)
		pins = append(pins, p)
	}
	return pins, nil
}

// moduleFiles is the repeated --module PATH=FILE.zip option.
type moduleFiles map[string]string

func (m moduleFiles) String() string { return "" }
func (m moduleFiles) Set(v string) error {
	path, file, ok := strings.Cut(v, "=")
	if !ok || path == "" || file == "" {
		return errors.New("use --module PATH=FILE.zip")
	}
	if _, dup := m[path]; dup {
		return fmt.Errorf("module %s given twice", path)
	}
	m[path] = file
	return nil
}

func lifecycleScriptPutCommand(g *globals) *cli.Command {
	var file, lock string
	modules := moduleFiles{}
	var id cli.IDFlag
	var revision cli.RevisionFlag
	return &cli.Command{
		Name:  "put",
		Args:  "NAME",
		Short: "Upload a new revision of a script",
		Long: `Uploads FILE.go as the next revision of script NAME. A server checks and
compiles it first; errors are printed with line and column. Modules the
script imports are listed in modules.yaml:
  - {path: example.com/lib, version: v1.2.0, sha256: <64 hex>, size: 12345}
and their ZIPs given with --module PATH=FILE.zip (once per server cache;
a module already stored is not sent again). If the command is cut off, run
it again with the same --id, or 'mydc op resume ID'.`,
		Flags: func(fs *flag.FlagSet) {
			fs.StringVar(&file, "f", "", "the script's Go source `file`")
			fs.StringVar(&lock, "modules", "", "modules.yaml `file` listing the modules it imports")
			fs.Var(modules, "module", "`PATH=FILE.zip` of a listed module (repeat)")
			fs.Var(&id, "id", "operation `ID` (default: a new one)")
			fs.Var(&revision, "if-revision", "only if the script record is still at this `revision`")
		},
		Run: g.withSession(func(c *cli.Context, s *session, args []string) error {
			name, err := scriptNameArg(args, "put")
			if err != nil {
				return err
			}
			if file == "" {
				return cli.Usagef("put needs -f FILE.go")
			}
			tenant, err := g.Tenant(s, true)
			if err != nil {
				return err
			}
			opID := id.Get()
			intent, err := userauth.LoadCheckerScript(s.Home, s.Client, s.Stored.Session, opID)
			if errors.Is(err, userauth.ErrOperationMissing) {
				data, err := readInputFile(c, file, checker.MaxScriptBytes)
				if err != nil {
					return err
				}
				defer clear(data)
				d := checker.SourceDescriptor{Tenant: tenant, Digest: sha256.Sum256(data), Length: uint64(len(data)), SDK: 1}
				if lock != "" {
					if d.Modules, err = readModuleLock(c, lock); err != nil {
						return err
					}
				}
				if d.Validate() != nil {
					return errors.New("the script or its module list is not valid (size, module count or versions)")
				}
				rows, _, err := lifecycleCatalog(c, g, s, tenant)
				if err != nil {
					return err
				}
				expected, _ := revision.Resolve(func() (uint64, error) { return scriptRecord(rows, name), nil })
				fmt.Fprintf(c.Err, "Upload %s as a new revision of script %s.\n", file, name)
				if err := g.Prompter(c).Confirm("Go ahead?"); err != nil {
					return err
				}
				if err := g.Record(s, "lifecycle-script", "lifecycle script put "+name, opID); err != nil {
					return err
				}
				if intent, err = userauth.StageCheckerScript(s.Home, s.Client, s.Stored.Session, opID, name, s.Target, d, data, expected); err != nil {
					return err
				}
				fmt.Fprintf(c.Err, "Operation %s\n", opID)
			} else if err != nil {
				return err
			} else if intent.Name != name || intent.Tenant != tenant {
				return fmt.Errorf("--id %s uploads script %s/%s, not %s/%s", opID, intent.Tenant, intent.Name, tenant, name)
			}
			result, err := lifecyclePut(c, g, s, intent, modules)
			if err != nil {
				return err
			}
			return printApplied(c, g, opID, result)
		}),
	}
}

// lifecyclePut continues a script upload from its saved intent: the source
// is stored and checked on its provider, the name is registered, then the
// given module ZIPs are stored. Each step that already finished is not sent
// again; a step whose outcome is unknown is asked for first.
func lifecyclePut(c *cli.Context, g *globals, s *session, intent userauth.CheckerScriptIntent, modules moduleFiles) (*state.Result, error) {
	ctx, cancel := g.Deadline(c)
	next, status, err := advanceCheckerSource(ctx, s.Client, s.Stored.Session, s.Home, intent, true, true)
	cancel()
	if err != nil || next.Fact == nil {
		return nil, errOutcomeUnknown{id: intent.ID, err: fmt.Errorf("source %s: %v", status, err)}
	}
	intent = next
	result, err := g.send(c, s, change{Kind: "lifecycle-script", Summary: "lifecycle script put " + intent.Name, ID: intent.ID, Action: "put-lifecycle-script", Expected: intent.Expected, Payload: control.LifecycleScriptPut{Tenant: intent.Tenant, Name: intent.Name, Source: *intent.Fact}})
	if err != nil {
		return result, err
	}
	for path, file := range modules {
		if err := lifecycleModule(c, g, s, &intent, path, file); err != nil {
			return result, fmt.Errorf("the script is registered, but module %s was not stored: %w; run the same command with --id %s to retry", path, err, intent.ID)
		}
	}
	return result, nil
}

// lifecycleModule stores one module ZIP on the script's provider unless the
// provider already has it.
func lifecycleModule(c *cli.Context, g *globals, s *session, intent *userauth.CheckerScriptIntent, path, file string) error {
	pin, ok := userauth.CheckerModulePin(*intent, path)
	if !ok {
		return fmt.Errorf("%s is not in the script's modules.yaml", path)
	}
	progress := intent.ModuleProgress[pin.Path]
	if progress.Fact != nil {
		return nil
	}
	provider, err := userauth.CheckerProviderPeer(s.Client, intent.Provider)
	if err != nil {
		return err
	}
	client := s.Client.WithCheckerUpload(*intent)
	ctx, cancel := g.Deadline(c)
	defer cancel()
	fact, err := client.RecoverCheckerModule(ctx, provider, s.Stored.Session, intent.Descriptor, pin)
	if err != nil {
		if !positiveSourceMissing(err) {
			return err
		}
		data, err := readInputFile(c, file, checker.MaxModuleBytes)
		if err != nil {
			return err
		}
		defer clear(data)
		if uint64(len(data)) != pin.Length || sha256.Sum256(data) != pin.Digest {
			return fmt.Errorf("%s does not match the size and sha256 in modules.yaml", file)
		}
		progress.Sequence++
		if *intent, err = userauth.ReplaceCheckerModule(s.Home, s.Client, s.Stored.Session, *intent, pin.Path, progress); err != nil {
			return err
		}
		if fact, err = client.StageCheckerModule(ctx, provider, s.Stored.Session, intent.Descriptor, checker.ModuleArchive{Pin: pin, ZIP: data}); err != nil {
			return err
		}
	}
	progress.Fact = &fact
	*intent, err = userauth.ReplaceCheckerModule(s.Home, s.Client, s.Stored.Session, *intent, pin.Path, progress)
	return err
}

// lifecycleScriptHandler settles a script upload: resume continues the
// source and registration steps (modules need their files: run the put
// again with the same --id).
func lifecycleScriptHandler(g *globals) cli.Handler {
	registered := changeHandler(g, nil, false)
	return cli.Handler{
		Show: func(c *cli.Context, op cli.Op) (cli.State, string, error) {
			return registered.Show(c, op)
		},
		Resume: func(c *cli.Context, op cli.Op) (cli.State, string, error) {
			s, err := g.opSession(c, op)
			if err != nil {
				return "", "", err
			}
			defer s.Close()
			intent, err := userauth.LoadCheckerScript(s.Home, s.Client, s.Stored.Session, op.ID)
			if errors.Is(err, userauth.ErrOperationMissing) {
				return cli.Failed, "not sent", nil
			}
			if err != nil {
				return "", "", err
			}
			result, err := lifecyclePut(c, g, s, intent, nil)
			if result == nil {
				return "", "", err
			}
			st, detail := changeState(*result, false)
			return st, detail, nil
		},
	}
}

func init() {
	opKinds["lifecycle-script"] = lifecycleScriptHandler
}

func lifecycleScriptSelectCommand(g *globals, verb, short string) *cli.Command {
	var revision uint64
	var id cli.IDFlag
	var ifRevision cli.RevisionFlag
	return &cli.Command{
		Name:  verb,
		Args:  "NAME",
		Short: short,
		Flags: func(fs *flag.FlagSet) {
			fs.Uint64Var(&revision, "revision", 0, "the script `revision` to "+verb)
			fs.Var(&id, "id", "operation `ID` (default: a new one)")
			fs.Var(&ifRevision, "if-revision", "only if the script record is still at this `revision`")
		},
		Run: g.withSession(func(c *cli.Context, s *session, args []string) error {
			name, err := scriptNameArg(args, verb)
			if err != nil {
				return err
			}
			if revision == 0 {
				return cli.Usagef("%s needs --revision N (from 'mydc lifecycle script list')", verb)
			}
			tenant, err := g.Tenant(s, true)
			if err != nil {
				return err
			}
			rows, _, err := lifecycleCatalog(c, g, s, tenant)
			if err != nil {
				return err
			}
			record := scriptRecord(rows, name)
			if _, err := pickRevision(lifecycleScripts(rows, name), name, revision); err != nil {
				return err
			}
			expected, _ := ifRevision.Resolve(func() (uint64, error) { return record, nil })
			impact := fmt.Sprintf("%s revision %d of script %s.", strings.ToUpper(verb[:1])+verb[1:], revision, name)
			return g.sendAndPrint(c, s, impact, change{ID: id.Get(), Summary: fmt.Sprintf("lifecycle script %s %s --revision %d", verb, name, revision), Action: verb + "-lifecycle-script", Expected: expected, Payload: control.LifecycleScriptSelection{Tenant: tenant, Name: name, Revision: revision}})
		}),
	}
}

func lifecyclePolicyShowCommand(g *globals) *cli.Command {
	return &cli.Command{
		Name:  "show",
		Short: "Show the tenant's lifecycle policy as lifecycle-policy.yaml",
		Run: g.withSession(func(c *cli.Context, s *session, args []string) error {
			if len(args) != 0 {
				return cli.Usagef("show takes no arguments")
			}
			tenant, err := g.Tenant(s, true)
			if err != nil {
				return err
			}
			rows, _, err := lifecycleCatalog(c, g, s, tenant)
			if err != nil {
				return err
			}
			for _, r := range rows {
				if r.Policy != nil {
					if g.output.Format() == cli.JSON {
						return cli.Print(c.Out, cli.JSON, r.Policy, nil)
					}
					return writeLifecyclePolicy(c.Out, *r.Policy)
				}
			}
			return fmt.Errorf("tenant %s has no lifecycle policy; set one with 'mydc lifecycle policy set -f lifecycle-policy.yaml'", tenant)
		}),
	}
}

func lifecyclePolicySetCommand(g *globals) *cli.Command {
	var file string
	var id cli.IDFlag
	var revision cli.RevisionFlag
	return &cli.Command{
		Name:  "set",
		Short: "Replace the tenant's lifecycle policy with lifecycle-policy.yaml",
		Flags: func(fs *flag.FlagSet) {
			fs.StringVar(&file, "f", "", "lifecycle-policy.yaml `file`")
			fs.Var(&id, "id", "operation `ID` (default: a new one)")
			fs.Var(&revision, "if-revision", "only if the policy is still at this `revision`")
		},
		Run: g.withSession(func(c *cli.Context, s *session, args []string) error {
			if len(args) != 0 {
				return cli.Usagef("set takes no arguments")
			}
			if file == "" {
				return cli.Usagef("set needs -f lifecycle-policy.yaml")
			}
			tenant, err := g.Tenant(s, true)
			if err != nil {
				return err
			}
			var f lifecyclePolicyFile
			if err := decodeYAMLFile(c, file, 32<<10, &f); err != nil {
				return err
			}
			policy, err := f.policy(tenant)
			if err != nil {
				return fmt.Errorf("%s: %w", file, err)
			}
			rows, _, err := lifecycleCatalog(c, g, s, tenant)
			if err != nil {
				return err
			}
			expected, _ := revision.Resolve(func() (uint64, error) {
				for _, r := range rows {
					if r.Policy != nil {
						return r.RecordRevision, nil
					}
				}
				return 0, nil
			})
			return g.sendAndPrint(c, s, fmt.Sprintf("Replace the lifecycle policy of tenant %s.", tenant), change{ID: id.Get(), Summary: "lifecycle policy set --tenant " + tenant, Action: "set-lifecycle-policy", Expected: expected, Payload: policy})
		}),
	}
}

func lifecycleCheckCommand(g *globals) *cli.Command {
	var lock, node string
	return &cli.Command{
		Name:  "check",
		Args:  "FILE.go",
		Short: "Check that a script compiles, without uploading it as a revision",
		Long:  "A server checks and type-checks FILE.go with the tenant's policy and prints errors with line and column. Nothing is registered.",
		Flags: func(fs *flag.FlagSet) {
			fs.StringVar(&lock, "modules", "", "modules.yaml `file` listing the modules it imports")
			fs.StringVar(&node, "node", "", "check on this `node` (default: the one you are connected to)")
		},
		Run: g.withSession(func(c *cli.Context, s *session, args []string) error {
			if len(args) != 1 {
				return cli.Usagef("check needs one Go file")
			}
			tenant, err := g.Tenant(s, true)
			if err != nil {
				return err
			}
			data, err := readInputFile(c, args[0], checker.MaxScriptBytes)
			if err != nil {
				return err
			}
			defer clear(data)
			d := checker.SourceDescriptor{Tenant: tenant, Digest: sha256.Sum256(data), Length: uint64(len(data)), SDK: 1}
			if lock != "" {
				if d.Modules, err = readModuleLock(c, lock); err != nil {
					return err
				}
			}
			if d.Validate() != nil {
				return errors.New("the script or its module list is not valid (size, module count or versions)")
			}
			var upload [32]byte
			if _, err := rand.Read(upload[:]); err != nil {
				return err
			}
			ctx, cancel := g.Deadline(c)
			result, err := s.Client.StageLifecycleSource(ctx, s.Target, s.Stored.Session, node, d, upload, data)
			cancel()
			if err != nil && !result.MetadataValid() {
				return err
			}
			if g.output.Format() != cli.Table {
				if perr := cli.Print(c.Out, g.output.Format(), result, nil); perr != nil {
					return perr
				}
			} else if len(result.Diagnostics) == 0 && err == nil {
				fmt.Fprintf(c.Out, "%s: ok\n", args[0])
			} else {
				for _, d := range result.Diagnostics {
					fmt.Fprintf(c.Out, "%s:%d:%d: %s\n", args[0], d.Line, d.Column, d.Message)
				}
			}
			if err != nil {
				return err
			}
			if len(result.Diagnostics) > 0 {
				return cli.ExitError{Code: 3}
			}
			return nil
		}),
	}
}
