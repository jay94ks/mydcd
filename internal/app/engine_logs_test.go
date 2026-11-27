// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"io"
	"slices"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/engineevents"
	"github.com/jay94ks/seafield/internal/engineops"
	"github.com/jay94ks/seafield/internal/eventbus"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/moby/moby/api/types/events"
)

type frameQueue []sfcp.Frame

func (q *frameQueue) ReadFrame(int) (sfcp.Frame, error) {
	if len(*q) == 0 {
		return sfcp.Frame{}, io.EOF
	}
	f := (*q)[0]
	*q = (*q)[1:]
	return f, nil
}

func logChunk(off uint64, data, header []byte) sfcp.Frame {
	var o [8]byte
	binary.LittleEndian.PutUint64(o[:], off)
	return sfcp.Frame{Purpose: sfcp.EngineLog, Kind: 4, Fields: []sfcp.Field{{Tag: 1, Value: o[:]}, {Tag: 2, Value: data}, {Tag: 3, Value: header}}}
}

func TestReadLogBulk(t *testing.T) {
	req := []byte(`{"Schema":1,"Op":"bulk"}`)
	h := sha256.Sum256(req)
	answer := func(size int, result string) sfcp.Frame {
		raw, _ := json.Marshal(engineLogBulkReply{Reply: engineops.Reply{Schema: 1, OpID: "bulk:1", Result: result}, Count: 2, First: 5, Last: 6, Size: size})
		return sfcp.Frame{Purpose: sfcp.EngineLog, Kind: 2, Fields: []sfcp.Field{{Tag: 1, Value: raw}}}
	}
	q := frameQueue{answer(5, engineops.Applied), logChunk(0, []byte("abc"), h[:]), logChunk(3, []byte("de"), h[:])}
	b, err := readLogBulk(&q, req, "bulk:1")
	if err != nil || string(b.Body) != "abcde" || b.Count != 2 || b.First != 5 || b.Last != 6 {
		t.Fatal(b, err)
	}
	bad := map[string]frameQueue{
		"other op":     {answer(0, engineops.Applied)},
		"not applied":  {answer(0, engineops.NotApplied)},
		"gap offset":   {answer(5, engineops.Applied), logChunk(1, []byte("abcde"), h[:])},
		"other digest": {answer(3, engineops.Applied), logChunk(0, []byte("abc"), make([]byte, 32))},
		"short":        {answer(5, engineops.Applied), logChunk(0, []byte("abc"), h[:])},
		"too long":     {answer(2, engineops.Applied), logChunk(0, []byte("abc"), h[:])},
	}
	for name, q := range bad {
		id := "bulk:1"
		if name == "other op" {
			id = "bulk:2"
		}
		if _, err := readLogBulk(&q, req, id); err == nil {
			t.Fatal(name, "accepted")
		}
	}
}

func TestLogMeta(t *testing.T) {
	m := logMeta("c1", map[string]string{"name": "/web-1", "org.sfc.key": "workload/task/t1/shop/web"})
	if m.Container != "c1" || m.Name != "web-1" || m.Tenant != "t1" || m.App != "shop" || m.Service != "web" || m.Key != "workload/task/t1/shop/web" {
		t.Fatal(m)
	}
	if m := logMeta("c3", map[string]string{"org.sfc.key": "workload/task/t1/shop/web/n2/r3"}); m.Tenant != "t1" || m.App != "shop" || m.Service != "web" {
		t.Fatal(m)
	}
	if m := logMeta("c2", map[string]string{"org.sfc.key": "system/x"}); m.Tenant != "" || m.App != "" {
		t.Fatal(m)
	}
}

func TestEngineBusGathersPerContainer(t *testing.T) {
	got := make(chan eventbus.Event, 8)
	b := newEngineBus(func(e eventbus.Event) { got <- e }, func() string { return "n1" })
	b.wait = 20 * time.Millisecond
	h := b.handler()
	attrs := map[string]string{"org.sfc.key": "workload/task/t1/shop/web"}
	for _, a := range []events.Action{"start", "seafield.logs", "health_status: healthy", "start"} {
		_ = h.Handle(context.Background(), engineevents.Record{Boot: "b1", Event: events.Message{Type: events.ContainerEventType, Action: a, Actor: events.Actor{ID: "c1", Attributes: attrs}}})
	}
	e := <-got
	if e.Topic != eventbus.TopicEngine || e.Kind != eventbus.KindEngineContainer || e.Node != "n1" || e.Tenant != "t1" || e.App != "shop" || e.Container != "c1" || !slices.Equal(e.Reasons, []string{"start", "health"}) {
		t.Fatal(e)
	}
	_ = h.Handle(context.Background(), engineevents.Record{Boot: "b2", Event: events.Message{Type: events.ImageEventType, Action: "pull"}})
	if e := <-got; e.Kind != eventbus.KindEngineNode || !slices.Equal(e.Reasons, []string{"boot"}) {
		t.Fatal(e)
	}
	_ = h.Rescan(context.Background())
	if e := <-got; e.Kind != eventbus.KindEngineNode || !slices.Equal(e.Reasons, []string{"lag"}) {
		t.Fatal(e)
	}
	select {
	case e := <-got:
		t.Fatal("extra", e)
	case <-time.After(50 * time.Millisecond):
	}
}
