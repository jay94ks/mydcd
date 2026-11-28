// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/containerops"
	"github.com/jay94ks/seafield/internal/logstore"
)

func nodeLogsStore(t *testing.T) *logstore.Store {
	t.Helper()
	store, err := logstore.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	at := time.Unix(1000, 0)
	add := func(id, name, key string, start time.Time, lines ...string) {
		var recs []logstore.Record
		for i, line := range lines {
			recs = append(recs, logstore.Record{Seq: uint64(i + 1), Time: start.Add(time.Duration(i) * time.Second), Stderr: strings.HasPrefix(line, "err"), Data: []byte(line)})
		}
		if _, err := store.Append(id, logstore.Meta{Container: id, Name: name, Key: key}, recs); err != nil {
			t.Fatal(err)
		}
	}
	// Two generations of the web cluster app share a name: the newer wins.
	add("aaaa00000001", "sfc-web", containerops.ClusterAppKeyPrefix+"web", at, "old-1", "old-2")
	add("bbbb00000002", "sfc-web", containerops.ClusterAppKeyPrefix+"web", at.Add(time.Hour), "new-1", "err-1", "new-2")
	add("cccc00000003", "other", "", at, "x")
	add("cccc00000004", "other2", "", at, "y")
	return store
}

func TestFindNodeLogPicksNewestGenerationAndUniquePrefix(t *testing.T) {
	store := nodeLogsStore(t)
	for _, c := range []struct {
		q    control.NodeLogsQuery
		code string
		id   string
	}{
		{control.NodeLogsQuery{App: "web"}, "ok", "bbbb00000002"},
		{control.NodeLogsQuery{Container: "sfc-web"}, "ok", "bbbb00000002"},
		{control.NodeLogsQuery{Container: "aaaa00000001"}, "ok", "aaaa00000001"},
		{control.NodeLogsQuery{Container: "aaaa"}, "ok", "aaaa00000001"},
		{control.NodeLogsQuery{Container: "cccc"}, "ambiguous", ""},
		{control.NodeLogsQuery{Container: "ccc"}, "not-found", ""},
		{control.NodeLogsQuery{App: "missing"}, "not-found", ""},
	} {
		info, code, err := findNodeLog(store, c.q)
		if err != nil || code != c.code || info.Container != c.id {
			t.Fatal(c.q, code, info.Container, err)
		}
	}
}

func TestReadNodeLogTailFiltersAndPages(t *testing.T) {
	store := nodeLogsStore(t)
	id := "bbbb00000002"
	page := func(q control.NodeLogsQuery) control.NodeLogsPage {
		t.Helper()
		q.Node = "node-a"
		start := control.NodeLogsPage{Schema: 1, Code: "ok", Node: "node-a", Lines: []control.NodeLogLine{}}
		p, err := readNodeLog(context.Background(), store, id, q, start)
		if err != nil || !p.Valid(q) {
			t.Fatal(p, err)
		}
		return p
	}
	data := func(p control.NodeLogsPage) string {
		var out []string
		for _, l := range p.Lines {
			out = append(out, string(l.Data))
		}
		return strings.Join(out, ",")
	}
	if p := page(control.NodeLogsQuery{App: "web", Tail: 2, Stdout: true, Stderr: true}); data(p) != "err-1,new-2" || p.Next != 3 {
		t.Fatal("tail", data(p), p.Next)
	}
	if p := page(control.NodeLogsQuery{App: "web", Tail: 2, Stdout: true}); data(p) != "new-1,new-2" {
		t.Fatal("stdout only", data(p))
	}
	if p := page(control.NodeLogsQuery{App: "web", After: 1, Stderr: true}); data(p) != "err-1" || p.Next != 3 {
		t.Fatal("after", data(p), p.Next)
	}
	since := time.Unix(1000, 0).Add(time.Hour + time.Second).UTC().Format(time.RFC3339Nano)
	if p := page(control.NodeLogsQuery{App: "web", Tail: 10, Stdout: true, Stderr: true, Since: since}); data(p) != "err-1,new-2" {
		t.Fatal("since", data(p))
	}
	// Nothing new without Wait answers at once with the same Next.
	if p := page(control.NodeLogsQuery{App: "web", After: 3, Stdout: true, Stderr: true}); len(p.Lines) != 0 || p.Next != 3 {
		t.Fatal("empty continuation", p)
	}
}

func TestReadNodeLogWaitWakesOnNewLineAndBoundsPage(t *testing.T) {
	store := nodeLogsStore(t)
	id := "cccc00000003"
	q := control.NodeLogsQuery{Node: "node-a", Container: id, After: 1, Stdout: true, Stderr: true, Wait: true}
	go func() {
		time.Sleep(50 * time.Millisecond)
		_, _ = store.Append(id, logstore.Meta{Container: id, Name: "other"}, []logstore.Record{{Seq: 2, Time: time.Unix(2000, 0), Data: []byte("late")}})
	}()
	start := control.NodeLogsPage{Schema: 1, Code: "ok", Node: "node-a", Lines: []control.NodeLogLine{}}
	p, err := readNodeLog(context.Background(), store, id, q, start)
	if err != nil || len(p.Lines) != 1 || string(p.Lines[0].Data) != "late" || p.Next != 2 {
		t.Fatal("wait", p, err)
	}

	big := strings.Repeat("z", 30<<10)
	var recs []logstore.Record
	for i := range 4 {
		recs = append(recs, logstore.Record{Seq: uint64(3 + i), Time: time.Unix(3000+int64(i), 0), Data: []byte(fmt.Sprint(i, big))})
	}
	if _, err := store.Append(id, logstore.Meta{Container: id, Name: "other"}, recs); err != nil {
		t.Fatal(err)
	}
	q = control.NodeLogsQuery{Node: "node-a", Container: id, After: 2, Stdout: true, Stderr: true}
	p, err = readNodeLog(context.Background(), store, id, q, start)
	if err != nil || len(p.Lines) != 2 || !p.More || p.Next != 4 || !p.Valid(q) {
		t.Fatal("bounded page", len(p.Lines), p.More, p.Next, err)
	}

	// A line longer than a page is cut to one page and Next moves past it.
	huge := strings.Repeat("h", control.NodeLogsMaxBytes+100)
	if _, err := store.Append(id, logstore.Meta{Container: id, Name: "other"}, []logstore.Record{{Seq: 7, Time: time.Unix(4000, 0), Data: []byte(huge)}, {Seq: 8, Time: time.Unix(4001, 0), Data: []byte("after")}}); err != nil {
		t.Fatal(err)
	}
	q = control.NodeLogsQuery{Node: "node-a", Container: id, After: 6, Stdout: true, Stderr: true}
	p, err = readNodeLog(context.Background(), store, id, q, start)
	if err != nil || len(p.Lines) != 1 || len(p.Lines[0].Data) != control.NodeLogsMaxBytes || !p.Lines[0].Partial || p.Next != 7 || !p.More || !p.Valid(q) {
		t.Fatal("huge line", len(p.Lines), p.Next, p.More, err)
	}
	q.After = p.Next
	if p, err = readNodeLog(context.Background(), store, id, q, start); err != nil || len(p.Lines) != 1 || string(p.Lines[0].Data) != "after" {
		t.Fatal("after huge line", p, err)
	}
}
