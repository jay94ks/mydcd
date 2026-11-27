// SPDX-License-Identifier: Apache-2.0

package engineops

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
)

type mountRequest struct {
	Request
	Name    string
	MountID string
}

type mountAnswer struct {
	Reply
	ReadOnly bool
}

func body(t *testing.T, v any) []byte {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func answer(t *testing.T, raw []byte) mountAnswer {
	t.Helper()
	var a mountAnswer
	if err := json.Unmarshal(raw, &a); err != nil {
		t.Fatal(err)
	}
	return a
}

func TestTableAnswersAndMapsErrors(t *testing.T) {
	var fail error
	var sent *os.File
	table, err := NewTable(Op(Volume, "mount", func(_ context.Context, q mountRequest) (mountAnswer, []*os.File, error) {
		if fail != nil {
			return mountAnswer{}, []*os.File{sent}, fail
		}
		return mountAnswer{ReadOnly: q.Name == "ro"}, []*os.File{sent}, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	dir, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	sent = dir
	req := mountRequest{Request: Request{Schema: 1, Op: "mount", OpID: "op1", BootID: "boot2"}, Name: "ro", MountID: "m"}
	ans := table.Serve(context.Background(), Volume, body(t, req))
	raw, files := ans.Body, ans.Files
	a := answer(t, raw)
	if a.Result != Applied || !a.ReadOnly || a.OpID != "op1" || len(files) != 1 || len(a.Fds) != 1 || a.Fds[0] != 0 {
		t.Fatalf("applied answer %s files %d", raw, len(files))
	}

	cases := map[string]struct {
		purpose Purpose
		body    []byte
		fail    error
		result  string
		reason  string
	}{
		"refusal":         {Volume, body(t, req), Refuse(NotReady, errors.New("moving")), NotApplied, NotReady},
		"other error":     {Volume, body(t, req), errors.New("disk"), Unknown, ""},
		"unknown field":   {Volume, []byte(`{"Schema":1,"Op":"mount","OpID":"op1","BootID":"boot2","Name":"x","MountID":"m","Extra":1}`), nil, NotApplied, Invalid},
		"duplicate key":   {Volume, []byte(`{"Schema":1,"Op":"mount","OpID":"op1","BootID":"boot2","Name":"x","Name":"y","MountID":"m"}`), nil, NotApplied, Invalid},
		"unknown op":      {Volume, []byte(`{"Schema":1,"Op":"nope","OpID":"op1","BootID":"boot2"}`), nil, NotApplied, Invalid},
		"other purpose":   {Network, body(t, req), nil, NotApplied, Invalid},
		"no op id":        {Volume, []byte(`{"Schema":1,"Op":"mount","OpID":"","BootID":"boot2","Name":"x","MountID":"m"}`), nil, NotApplied, Invalid},
		"schema":          {Volume, []byte(`{"Schema":2,"Op":"mount","OpID":"op1","BootID":"boot2","Name":"x","MountID":"m"}`), nil, NotApplied, Invalid},
		"not json":        {Volume, []byte(`nope`), nil, NotApplied, Invalid},
		"bad reason kept": {Volume, body(t, req), Refuse("made-up", nil), Unknown, ""},
	}
	for name, c := range cases {
		fail = c.fail
		f, err := os.Open(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		sent = f
		got := table.Serve(context.Background(), c.purpose, c.body)
		raw, files := got.Body, got.Files
		a := answer(t, raw)
		if a.Result != c.result || a.Reason != c.reason || len(files) != 0 || len(a.Fds) != 0 || a.ReadOnly {
			t.Errorf("%s: answer %s files %d", name, raw, len(files))
		}
		if c.fail != nil {
			if _, err := f.Stat(); err == nil {
				t.Errorf("%s: descriptor left open on failure", name)
			}
		}
		_ = f.Close()
	}
	for _, f := range files {
		_ = f.Close()
	}
}

func TestNewTableRefusesConflicts(t *testing.T) {
	fn := func(context.Context, mountRequest) (mountAnswer, []*os.File, error) { return mountAnswer{}, nil, nil }
	for name, list := range map[string][]Entry{
		"duplicate":       {Op(Volume, "mount", fn), Op(Volume, "mount", fn)},
		"empty op":        {Op(Volume, "", fn)},
		"unknown purpose": {Op(Purpose(32), "mount", fn)},
	} {
		if _, err := NewTable(list...); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := NewTable(Op(Volume, "mount", fn), Op(Network, "mount", fn)); err != nil {
		t.Fatalf("same op name on two purposes: %v", err)
	}
}

type closer struct {
	*strings.Reader
	closed bool
}

func (c *closer) Close() error { c.closed = true; return nil }

func TestStreamOpHandsOverOrClosesTheStream(t *testing.T) {
	var fail error
	var s *closer
	table, err := NewTable(StreamOp(Image, "blob", func(_ context.Context, q mountRequest) (mountAnswer, io.ReadCloser, error) {
		s = &closer{Reader: strings.NewReader("bytes")}
		return mountAnswer{}, s, fail
	}))
	if err != nil {
		t.Fatal(err)
	}
	req := body(t, mountRequest{Request: Request{Schema: 1, Op: "blob", OpID: "op1", BootID: "boot2"}})
	got := table.Serve(context.Background(), Image, req)
	if answer(t, got.Body).Result != Applied || got.Stream != s || s.closed {
		t.Fatalf("applied stream: %s", got.Body)
	}
	fail = Refuse(NotFound, nil)
	got = table.Serve(context.Background(), Image, req)
	if a := answer(t, got.Body); a.Result != NotApplied || a.Reason != NotFound || got.Stream != nil || !s.closed {
		t.Fatalf("refused stream: %s", got.Body)
	}
}
