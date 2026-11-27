// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testTree(got *[]string, rest *[]string, follow *bool, tenant *string) *Command {
	return &Command{
		Name:  "sfcli",
		Flags: func(fs *flag.FlagSet) { fs.StringVar(tenant, "tenant", "", "work in this tenant") },
		Sub: []*Command{{
			Name:  "app",
			Short: "Deploy and run apps",
			Sub: []*Command{
				{
					Name: "logs", Args: "APP [SERVICE]", Short: "Show logs",
					Flags: func(fs *flag.FlagSet) { fs.BoolVar(follow, "f", false, "keep following") },
					Run: func(c *Context, args []string) error {
						*got, *rest = args, c.Rest
						return nil
					},
				},
				{Name: "fail", Run: func(*Context, []string) error { return errors.New("boom") }},
				{Name: "usage", Run: func(*Context, []string) error { return Usagef("needs APP") }},
				{Name: "exit", Run: func(*Context, []string) error { return ExitError{Code: 4} }},
			},
		}},
	}
}

func run(t *testing.T, root *Command, args ...string) (int, string, string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code := Execute(root, args, Env{Out: &out, Err: &errOut, In: strings.NewReader("")})
	return code, out.String(), errOut.String()
}

func TestExecuteOptionsAnywhere(t *testing.T) {
	var got, rest []string
	var follow bool
	var tenant string
	root := testTree(&got, &rest, &follow, &tenant)
	code, _, stderr := run(t, root, "--tenant", "a", "app", "logs", "shop", "-f", "web", "--tenant", "b", "--", "-x", "--tenant")
	if code != 0 {
		t.Fatalf("code %d: %s", code, stderr)
	}
	if strings.Join(got, ",") != "shop,web" || !follow || tenant != "b" || strings.Join(rest, ",") != "-x,--tenant" {
		t.Fatalf("args=%v rest=%v follow=%v tenant=%q", got, rest, follow, tenant)
	}
}

func TestExecuteErrorsAndHelp(t *testing.T) {
	var got, rest []string
	var follow bool
	var tenant string
	root := testTree(&got, &rest, &follow, &tenant)
	for _, tc := range []struct {
		args []string
		code int
		want string
	}{
		{[]string{"nope"}, 2, `unknown command "nope"`},
		{[]string{"app"}, 2, "Commands:"},
		{[]string{"app", "logs", "--bogus"}, 2, "flag provided but not defined"},
		{[]string{"app", "fail"}, 1, "sfcli: boom"},
		{[]string{"app", "usage"}, 2, "sfcli app usage: needs APP"},
		{[]string{"app", "exit"}, 4, ""},
	} {
		code, _, stderr := run(t, root, tc.args...)
		if code != tc.code || !strings.Contains(stderr, tc.want) {
			t.Errorf("%v: code %d, stderr %q", tc.args, code, stderr)
		}
	}
	code, out, _ := run(t, root, "app", "logs", "--help")
	for _, want := range []string{"Usage: sfcli app logs APP [SERVICE] [options]", "Show logs", "Options:", "-f", "keep following", "Global options:", "--tenant string"} {
		if code != 0 || !strings.Contains(out, want) {
			t.Errorf("help misses %q:\n%s", want, out)
		}
	}
	if _, out, _ = run(t, root, "--help"); !strings.Contains(out, "app  Deploy and run apps") {
		t.Errorf("root help:\n%s", out)
	}
}

func TestPrint(t *testing.T) {
	type rec struct {
		Name string `json:"name"`
		Size int    `json:"size,omitempty"`
	}
	values := []rec{{"a", 1}, {"bb", 0}}
	rows := func() Rows {
		t := Rows{Header: []string{"name", "size"}}
		for _, v := range values {
			size := ""
			if v.Size != 0 {
				size = "1"
			}
			t.Add(v.Name, size)
		}
		return t
	}
	var b bytes.Buffer
	if err := Print(&b, Table, values, rows); err != nil || b.String() != "NAME  SIZE\na     1\nbb    -\n" {
		t.Fatalf("table %q %v", b.String(), err)
	}
	b.Reset()
	if err := Print(&b, YAML, values, rows); err != nil || b.String() != "- name: a\n  size: 1\n- name: bb\n" {
		t.Fatalf("yaml %q %v", b.String(), err)
	}
	b.Reset()
	if err := Print(&b, JSON, values[1], nil); err != nil || b.String() != "{\n  \"name\": \"bb\"\n}\n" {
		t.Fatalf("json %q %v", b.String(), err)
	}
	var f FormatFlag
	if f.Format() != Table || f.Set("xml") == nil || f.Set("json") != nil || f.Format() != JSON {
		t.Fatal("format flag")
	}
}

func TestConfirm(t *testing.T) {
	ask := func(p Prompter, answer string) error {
		p.In, p.Out = strings.NewReader(answer), &bytes.Buffer{}
		return p.Confirm("Delete?")
	}
	if ask(Prompter{Interactive: true}, "y\n") != nil || ask(Prompter{Interactive: true}, "YES\n") != nil {
		t.Fatal("yes")
	}
	if !errors.Is(ask(Prompter{Interactive: true}, "\n"), ErrDeclined) || !errors.Is(ask(Prompter{Interactive: true}, ""), ErrDeclined) {
		t.Fatal("no is the default")
	}
	if !errors.Is(ask(Prompter{}, "y\n"), ErrNeedsConfirmation) || !errors.Is(ask(Prompter{Interactive: true, NoInput: true}, "y\n"), ErrNeedsConfirmation) {
		t.Fatal("no terminal means no answer")
	}
	if ask(Prompter{Yes: true}, "") != nil {
		t.Fatal("-y")
	}
}

func TestValues(t *testing.T) {
	for range 64 {
		id := NewID()
		if len(id) != 16 || !ValidID(id) || NewID() == id {
			t.Fatalf("id %q", id)
		}
	}
	for _, bad := range []string{"", "-a", "1a", "A", "a b", "a_b", "a.b", strings.Repeat("a", 64)} {
		if ValidID(bad) {
			t.Errorf("valid %q", bad)
		}
	}
	var idf IDFlag
	if idf.Set("Bad") == nil || idf.Set("nightly-1") != nil || idf.Get() != "nightly-1" {
		t.Fatal("id flag")
	}
	var rev RevisionFlag
	calls := 0
	current := func() (uint64, error) { calls++; return 7, nil }
	if v, _ := rev.Resolve(current); v != 7 || calls != 1 {
		t.Fatal("reads current revision")
	}
	if rev.Set("x") == nil || rev.Set("3") != nil {
		t.Fatal("revision flag")
	}
	if v, _ := rev.Resolve(current); v != 3 || calls != 1 {
		t.Fatal("explicit revision wins")
	}
	for in, want := range map[string]Size{"512": 512, "64KiB": 64 << 10, "10mb": 10 << 20, "2GiB": 2 << 30, "1.5G": 3 << 29, "1TiB": 1 << 40, "7B": 7} {
		if got, err := ParseSize(in); err != nil || got != want {
			t.Errorf("%s: %d %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "GiB", "-1", "x", "99999999999999TiB"} {
		if _, err := ParseSize(bad); err == nil {
			t.Errorf("parsed %q", bad)
		}
	}
	if Size(2<<30).String() != "2GiB" || Size(1536<<10).String() != "1536KiB" || Size(7).String() != "7B" {
		t.Fatal("size string")
	}
}

func TestOps(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ops")
	x, err := OpenOps(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer x.Close()
	if info, _ := os.Stat(dir); info.Mode().Perm() != 0o700 {
		t.Fatalf("mode %v", info.Mode())
	}
	a := Op{ID: "aaaa1111", Kind: "volume-backup", Context: "prod", Summary: "volume backup create shop/db", Created: time.Unix(100, 0).UTC()}
	b := Op{ID: "aaaa2222", Kind: "app-deploy", Context: "prod", Summary: "app deploy shop", Created: time.Unix(200, 0).UTC()}
	if x.Add(a) != nil || x.Add(b) != nil || x.Add(a) != nil {
		t.Fatal("add")
	}
	if err := x.Add(Op{ID: a.ID, Kind: "other", Summary: "x"}); err == nil {
		t.Fatal("an ID never names a different operation")
	}
	if _, err := x.Get("aaaa"); !errors.Is(err, ErrOpAmbiguous) {
		t.Fatalf("ambiguous %v", err)
	}
	if _, err := x.Get("aaa"); !errors.Is(err, ErrOpNotFound) {
		t.Fatalf("short prefix %v", err)
	}
	if op, err := x.Get("aaaa2"); err != nil || op.ID != b.ID || op.State != Sending {
		t.Fatalf("prefix %v %v", op, err)
	}
	list, _ := x.List()
	if len(list) != 2 || list[0].ID != b.ID {
		t.Fatalf("newest first %v", list)
	}
	if err := x.Remove(a.ID); err == nil {
		t.Fatal("an unfinished operation is kept")
	}
	if x.Update(a.ID, Done, "backup done") != nil || x.Remove(a.ID) != nil {
		t.Fatal("remove finished")
	}
	if _, err := x.Get(a.ID); !errors.Is(err, ErrOpNotFound) {
		t.Fatal("removed")
	}
	if err := os.WriteFile(filepath.Join(dir, "bad.json"), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := x.List(); err == nil {
		t.Fatal("damaged file is reported, not skipped")
	}
}

func TestOpCommand(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ops")
	var format FormatFlag
	shown, resumed := 0, 0
	kinds := map[string]Handler{"volume-backup": {
		Show:   func(*Context, Op) (State, string, error) { shown++; return Accepted, "copying", nil },
		Resume: func(*Context, Op) (State, string, error) { resumed++; return Done, "backup done", nil },
	}}
	open := func() (*Ops, error) { return OpenOps(dir) }
	root := &Command{Name: "sfcli", Flags: func(fs *flag.FlagSet) { fs.Var(&format, "o", "output") }, Sub: []*Command{OpCommand(open, &format, kinds)}}
	x, _ := open()
	_ = x.Add(Op{ID: "bk01", Kind: "volume-backup", Context: "prod", Summary: "volume backup create shop/db"})
	_ = x.Add(Op{ID: "old1", Kind: "retired-kind", Context: "prod", Summary: "x"})
	x.Close()

	if code, out, _ := run(t, root, "op", "list"); code != 0 || !strings.Contains(out, "bk01") || !strings.Contains(out, "sending") {
		t.Fatalf("list %d %q", code, out)
	}
	if code, out, _ := run(t, root, "op", "show", "bk01", "-o", "json"); code != 0 || !strings.Contains(out, `"state": "accepted"`) || shown != 1 {
		t.Fatalf("show %d %q", code, out)
	}
	format = FormatFlag{}
	if code, _, stderr := run(t, root, "op", "resume", "old1"); code != 1 || !strings.Contains(stderr, "cannot be resumed") {
		t.Fatalf("unknown kind %d %q", code, stderr)
	}
	if code, out, _ := run(t, root, "op", "resume", "bk01"); code != 0 || !strings.Contains(out, "state: done") || resumed != 1 {
		t.Fatalf("resume %d %q", code, out)
	}
	if code, _, _ := run(t, root, "op", "show", "bk01"); code != 0 || shown != 1 {
		t.Fatal("a finished operation is not asked again")
	}
	if code, out, _ := run(t, root, "op", "prune"); code != 0 || !strings.Contains(out, "bk01") || strings.Contains(out, "old1") {
		t.Fatalf("prune %d %q", code, out)
	}
}
