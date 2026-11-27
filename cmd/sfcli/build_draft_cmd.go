// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/sha256"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/jay94ks/seafield/internal/cli"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/lifecycle"
	"github.com/jay94ks/seafield/internal/imagebuild"
)

// sfcli build draft: edit the files of a draft context on its server, then
// freeze them into a new version. Edits are not ops: each is one call,
// idempotent by its edit ID (--id), and only the freeze is a change.

func buildDraftCommand(g *globals) *cli.Command {
	return &cli.Command{
		Name:  "draft",
		Short: "Edit a draft context's files and save them as a version",
		Sub: []*cli.Command{
			{Name: "ls", Args: "CONTEXT", Short: "List the draft's files", Run: g.withSession(buildDraftLs(g))},
			buildDraftCatCommand(g),
			buildDraftPutCommand(g),
			buildDraftEditCommand(g, "rm", "delete", "CONTEXT PATH", "Delete a file or directory from the draft"),
			buildDraftEditCommand(g, "mv", "move", "CONTEXT PATH NEW-PATH", "Move a file or directory in the draft"),
			buildDraftFreezeCommand(g),
		},
	}
}

// draftTree is the draft's current tree (all pages) and its scope.
type draftTree struct {
	Scope       imagebuild.DraftScope
	Revision    uint64
	Digest      [32]byte
	Initialized bool
	Entries     []imagebuild.Entry
}

func readDraft(ctx context.Context, s *session, tenant, id string) (draftTree, error) {
	var out draftTree
	call := func(q imagebuild.DraftRequest) (imagebuild.DraftResponse, error) {
		return s.Client.BuildDraft(ctx, s.Target, s.Stored.Session, tenant, q)
	}
	plan, err := call(imagebuild.DraftRequest{Context: id, Kind: "plan"})
	if err != nil {
		return out, err
	}
	out.Scope = plan.Scope
	r, err := call(imagebuild.DraftRequest{Context: id, Kind: "tree", Scope: &out.Scope})
	if err != nil {
		return out, err
	}
	out.Entries = []imagebuild.Entry{}
	if r.Code == "NOT_INITIALIZED" {
		out.Revision = 1 // a new draft: the first edit expects revision 1
		return out, nil
	}
	if r.Code != "OK" || r.Digest == nil {
		return out, fmt.Errorf("the draft could not be read (%s)", r.Code)
	}
	out.Initialized, out.Revision, out.Digest = true, r.Revision, *r.Digest
	for range 8192 {
		out.Entries = append(out.Entries, r.Entries...)
		if r.Next == 0 {
			return out, nil
		}
		if r, err = call(imagebuild.DraftRequest{Context: id, Kind: "tree", Scope: &out.Scope, Revision: out.Revision, Digest: &out.Digest, Offset: r.Next}); err != nil {
			return out, err
		}
		if r.Code != "OK" {
			return out, errors.New("the draft changed while reading; run the command again")
		}
	}
	return out, errors.New("the draft file list did not end")
}

func buildDraftLs(g *globals) func(*cli.Context, *session, []string) error {
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
		d, err := readDraft(ctx, s, tenant, name)
		if err != nil {
			return err
		}
		fmt.Fprintf(c.Err, "draft %s, revision %d\n", name, d.Revision)
		return cli.Print(c.Out, g.output.Format(), struct {
			Revision uint64             `json:"revision"`
			Entries  []imagebuild.Entry `json:"entries"`
		}{d.Revision, d.Entries}, entryRows(d.Entries))
	}
}

func buildDraftCatCommand(g *globals) *cli.Command {
	var output string
	return &cli.Command{
		Name:  "cat",
		Args:  "CONTEXT PATH",
		Short: "Print one file of the draft",
		Flags: func(fs *flag.FlagSet) {
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
			d, err := readDraft(ctx, s, tenant, args[0])
			if err != nil {
				return err
			}
			if !d.Initialized {
				return fmt.Errorf("draft %s has no files yet", args[0])
			}
			w, done, err := plainOutput(c, output)
			if err != nil {
				return err
			}
			var offset uint32
			for range 1 << 20 {
				r, err := s.Client.BuildDraft(ctx, s.Target, s.Stored.Session, tenant, imagebuild.DraftRequest{Context: args[0], Kind: "file", Scope: &d.Scope, Revision: d.Revision, Digest: &d.Digest, Path: args[1], Offset: offset})
				if err == nil && r.Content == nil {
					err = fmt.Errorf("the file could not be read (%s)", r.Code)
				}
				if err == nil {
					_, err = w.Write(r.Content.Data)
				}
				if err != nil || r.Content.Next == 0 || r.Content.Next >= r.Content.Total {
					return done(err)
				}
				offset = uint32(r.Content.Next)
			}
			return done(errors.New("the file did not end"))
		}),
	}
}

// draftExpected is --if-revision, else the draft's current revision.
func draftExpected(rev *cli.RevisionFlag, d draftTree) (uint64, error) {
	return rev.Resolve(func() (uint64, error) { return d.Revision, nil })
}

func draftResult(c *cli.Context, name string, r imagebuild.DraftResponse) error {
	switch r.Code {
	case "OK":
		fmt.Fprintf(c.Out, "draft %s: revision %d\n", name, r.Revision)
		return nil
	case "PENDING":
		return fmt.Errorf("the draft is busy with another edit; run 'sfcli build draft ls %s' and try again", name)
	}
	return fmt.Errorf("the draft did not take the edit (%s)", r.Code)
}

func buildDraftEditCommand(g *globals, verb, kind, argsText, short string) *cli.Command {
	var id cli.IDFlag
	var rev cli.RevisionFlag
	want := 2
	if kind == "move" {
		want = 3
	}
	return &cli.Command{
		Name:  verb,
		Args:  argsText,
		Short: short,
		Flags: func(fs *flag.FlagSet) {
			fs.Var(&id, "id", "edit `id`, to repeat an edit safely (default: a new one)")
			fs.Var(&rev, "if-revision", "only if the draft is still at this `revision`")
		},
		Run: g.withSession(func(c *cli.Context, s *session, args []string) error {
			if len(args) != want || !lifecycle.ValidID(args[0]) {
				return cli.Usagef("needs %s", argsText)
			}
			for _, p := range args[1:] {
				if !imagebuild.ContextPath(p) {
					return cli.Usagef("%q is not a clean relative path", p)
				}
			}
			tenant, err := g.Tenant(s, true)
			if err != nil {
				return err
			}
			ctx, cancel := g.Deadline(c)
			defer cancel()
			d, err := readDraft(ctx, s, tenant, args[0])
			if err != nil {
				return err
			}
			expected, err := draftExpected(&rev, d)
			if err != nil {
				return err
			}
			e := imagebuild.DraftEdit{ID: id.Get(), Kind: kind, Path: args[1], Expected: expected}
			if kind == "move" {
				e.To = args[2]
			}
			if e.Validate() != nil {
				return cli.Usagef("cannot %s %s", verb, args[1])
			}
			r, err := s.Client.EditBuildDraft(ctx, s.Target, s.Stored.Session, d.Scope, e, nil)
			if err != nil {
				return err
			}
			return draftResult(c, args[0], r)
		}),
	}
}

func buildDraftPutCommand(g *globals) *cli.Command {
	var id cli.IDFlag
	var rev cli.RevisionFlag
	var exec bool
	return &cli.Command{
		Name:  "put",
		Args:  "CONTEXT PATH [LOCAL-FILE]",
		Short: "Write a file into the draft",
		Long: `Writes LOCAL-FILE (default: the file at PATH here) to PATH in the draft,
replacing what is there. A large file is sent in parts; if it stops part
way, run the same command with the same --id to continue.`,
		Flags: func(fs *flag.FlagSet) {
			fs.Var(&id, "id", "edit `id`, to repeat or continue an edit (default: a new one)")
			fs.Var(&rev, "if-revision", "only if the draft is still at this `revision`")
			fs.BoolVar(&exec, "executable", false, "mark the file executable")
		},
		Run: g.withSession(func(c *cli.Context, s *session, args []string) error {
			if len(args) < 2 || len(args) > 3 || !lifecycle.ValidID(args[0]) || !imagebuild.ContextPath(args[1]) {
				return cli.Usagef("needs CONTEXT, PATH in the draft and optionally LOCAL-FILE")
			}
			local := args[1]
			if len(args) == 3 {
				local = args[2]
			}
			f, err := os.Open(local)
			if err != nil {
				return err
			}
			defer f.Close()
			info, err := f.Stat()
			if err != nil || !info.Mode().IsRegular() || info.Size() > imagebuild.MaxZIPBytes {
				return fmt.Errorf("%s must be a regular file of at most 500 MB", local)
			}
			tenant, err := g.Tenant(s, true)
			if err != nil {
				return err
			}
			ctx, cancel := context.WithTimeout(c.Ctx, max(g.timeout, time.Duration(info.Size()>>20)*time.Second+g.timeout))
			defer cancel()
			digest, err := buildUploadFileDigest(ctx, f, info.Size())
			if err != nil {
				return err
			}
			d, err := readDraft(ctx, s, tenant, args[0])
			if err != nil {
				return err
			}
			expected, err := draftExpected(&rev, d)
			if err != nil {
				return err
			}
			e := imagebuild.DraftEdit{ID: id.Get(), Kind: "put", Path: args[1], Expected: expected,
				File: &imagebuild.Entry{Path: args[1], Executable: exec, Bytes: info.Size(), Digest: digest}}
			if e.Validate() != nil {
				return cli.Usagef("cannot write %s", args[1])
			}
			r, err := putDraftFile(ctx, s, d.Scope, e, f)
			if err != nil {
				return err
			}
			return draftResult(c, args[0], r)
		}),
	}
}

// putDraftFile sends a put edit: small files in the edit itself, larger
// ones part by part (only the parts the server is missing), then commits.
func putDraftFile(ctx context.Context, s *session, scope imagebuild.DraftScope, e imagebuild.DraftEdit, f io.ReaderAt) (imagebuild.DraftResponse, error) {
	read := func(index uint32) ([]byte, error) {
		n := imagebuild.DraftFilePartLength(e, index)
		if n < 0 {
			return nil, errors.New("the server asked for an invalid file part")
		}
		body := make([]byte, n)
		if m, err := f.ReadAt(body, int64(index)*imagebuild.PartBytes); m != n || err != nil && err != io.EOF {
			return nil, errors.New("the local file changed while sending")
		}
		if index == 0 && n == int(e.File.Bytes) && sha256.Sum256(body) != e.File.Digest {
			return nil, errors.New("the local file changed while sending")
		}
		return body, nil
	}
	if e.File.Bytes <= imagebuild.PartBytes {
		body, err := read(0)
		if err != nil {
			return imagebuild.DraftResponse{}, err
		}
		return s.Client.EditBuildDraft(ctx, s.Target, s.Stored.Session, scope, e, body)
	}
	send := func(index uint32) error {
		body, err := read(index)
		if err != nil {
			return err
		}
		r, err := s.Client.PutDraftFilePart(ctx, s.Target, s.Stored.Session, scope, e, index, body)
		if err == nil && r.Code != "STAGED" {
			err = fmt.Errorf("the draft did not take part %d (%s)", index, r.Code)
		}
		return err
	}
	var offset uint32
	started := false
	for range 1 << 16 {
		st, err := s.Client.DraftFileStatus(ctx, s.Target, s.Stored.Session, scope, e, offset)
		if err != nil {
			return st, err
		}
		if st.Code == "NOT_INITIALIZED" {
			if started {
				return st, errors.New("the server lost the file after its first part; run the command again with a new --id")
			}
			if err = send(0); err != nil {
				return st, err
			}
			started = true
			continue
		}
		if st.Code != "STAGED" || st.File == nil {
			return st, nil // OK (already committed) or a refusal
		}
		if st.File.Complete {
			break
		}
		for _, index := range st.File.Missing {
			if err = send(index); err != nil {
				return st, err
			}
		}
		if st.File.Next == 0 {
			break
		}
		offset = st.File.Next
	}
	return s.Client.CommitDraftFile(ctx, s.Target, s.Stored.Session, scope, e)
}

func buildDraftFreezeCommand(g *globals) *cli.Command {
	var id cli.IDFlag
	var rev cli.RevisionFlag
	return &cli.Command{
		Name:  "freeze",
		Args:  "CONTEXT",
		Short: "Save the draft's files as a new version",
		Flags: func(fs *flag.FlagSet) {
			fs.Var(&id, "id", "operation `id` (default: a new one)")
			fs.Var(&rev, "if-revision", "only if the draft is still at this `revision`")
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
			opID := id.Get()
			err = g.sendSaved(c, s, "build draft freeze "+name, opID, func() (change, error) {
				ctx, cancel := g.Deadline(c)
				defer cancel()
				d, err := readDraft(ctx, s, tenant, name)
				if err != nil {
					return change{}, err
				}
				if !d.Initialized {
					return change{}, fmt.Errorf("draft %s has no files yet; add a Dockerfile with 'sfcli build draft put'", name)
				}
				expected, err := draftExpected(&rev, d)
				if err != nil {
					return change{}, err
				}
				if expected != d.Revision {
					return change{}, fmt.Errorf("the draft is at revision %d, not %d", d.Revision, expected)
				}
				now := uint64(time.Now().Unix())
				plan := imagebuild.DraftFreezePlan{Schema: 1, Scope: d.Scope, ID: opID, Creator: s.Stored.Session.User, Revision: d.Revision, Draft: d.Digest, CreatedAt: now, ExpiresAt: now + 3600}
				r, err := s.Client.FreezeBuildDraft(ctx, s.Target, s.Stored.Session, plan)
				if err != nil {
					return change{}, err
				}
				if r.Code != "FROZEN" || r.Frozen == nil {
					return change{}, fmt.Errorf("the draft could not be frozen (%s)", r.Code)
				}
				return change{Action: "publish-build-draft", Expected: plan.Revision, Payload: control.ImageBuildDraftPublish{Tenant: tenant, Context: name, Frozen: *r.Frozen}}, nil
			})
			if err != nil {
				return err
			}
			fmt.Fprintf(c.Out, "draft %s saved as a new version (%s)\n", name, opID)
			return nil
		}),
	}
}
