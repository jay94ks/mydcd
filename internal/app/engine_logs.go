// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/jay94ks/seafield/internal/engineevents"
	"github.com/jay94ks/seafield/internal/engineops"
	"github.com/jay94ks/seafield/internal/logstore"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/moby/moby/api/types/events"
	"github.com/moby/moby/client"
)

// Purpose 33 bulk and 34 ack, as the engine answers them
// (seafield/docs/sfcd-socket.md "op 구조체").
type (
	engineLogBulk struct {
		engineops.Request
		Container string
		After     uint64
		MaxBytes  int
	}
	engineLogBulkReply struct {
		engineops.Reply
		Count       int
		First, Last uint64
		Gap         *engineevents.Range
		Live        bool
		Size        int
	}
	engineLogAck struct {
		engineops.Request
		Container string
		Upto      uint64
	}
)

const engineLogTimeout = time.Minute

// engineLogs is logstore.Engine over the current engine session.
type engineLogs struct{ r *Runtime }

func (e engineLogs) session() (*sfcp.EngineSession, error) {
	if e.r.Mesh == nil {
		return nil, errors.New("no transport")
	}
	s, ok := e.r.Mesh.Engine()
	if !ok {
		return nil, errors.New("engine is not connected")
	}
	return s, nil
}

// sfcdBoot is this sfcd's BootID on the engine socket; it changes on every start.
var sfcdBoot = randomHex(8)

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func engineRequest(op string) engineops.Request {
	return engineops.Request{Schema: 1, Op: op, OpID: op + ":" + randomHex(16), BootID: sfcdBoot}
}

func engineRequestFrame(p sfcp.Purpose, v any) (sfcp.Frame, []byte, error) {
	body, err := json.Marshal(v)
	if err != nil {
		return sfcp.Frame{}, nil, err
	}
	return sfcp.Frame{Purpose: p, Kind: 1, Fields: []sfcp.Field{{Tag: 1, Required: true, Value: body}}}, body, nil
}

func checkEngineReply(r engineops.Reply, opID string) error {
	switch {
	case r.Schema != 1 || r.OpID != opID:
		return errors.New("engine answer does not match the request")
	case r.Result != engineops.Applied:
		return fmt.Errorf("engine answered %s %s", r.Result, r.Reason)
	}
	return nil
}

func (e engineLogs) Bulk(ctx context.Context, container string, after uint64, maxBytes int) (logstore.Bulk, error) {
	s, err := e.session()
	if err != nil {
		return logstore.Bulk{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, engineLogTimeout)
	defer cancel()
	q := engineLogBulk{Request: engineRequest("bulk"), Container: container, After: after, MaxBytes: maxBytes}
	f, body, err := engineRequestFrame(sfcp.EngineLog, q)
	if err != nil {
		return logstore.Bulk{}, err
	}
	st, err := s.Open(ctx)
	if err != nil {
		return logstore.Bulk{}, err
	}
	defer st.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = st.SetDeadline(dl)
	}
	if err = st.WriteFrame(f); err != nil {
		return logstore.Bulk{}, err
	}
	_ = st.Close() // FIN: the request is complete
	return readLogBulk(st, body, q.OpID)
}

// readLogBulk reads a bulk answer and its kind 4 chunks up to FIN: each chunk
// continues at the body's length and carries the request digest.
func readLogBulk(st interface {
	ReadFrame(int) (sfcp.Frame, error)
}, request []byte, opID string) (logstore.Bulk, error) {
	reply, err := st.ReadFrame(sfcp.MaxBody)
	if err != nil || reply.Kind != 2 || len(reply.Fields) != 1 {
		return logstore.Bulk{}, errors.Join(errors.New("engine log bulk: bad answer"), err)
	}
	var a engineLogBulkReply
	if err = json.Unmarshal(reply.Fields[0].Value, &a); err != nil {
		return logstore.Bulk{}, err
	}
	if err = checkEngineReply(a.Reply, opID); err != nil {
		return logstore.Bulk{}, err
	}
	if a.Size < 0 || a.Size > 64<<20 {
		return logstore.Bulk{}, errors.New("engine log bulk: bad size")
	}
	header := sha256.Sum256(request)
	out := logstore.Bulk{Count: a.Count, First: a.First, Last: a.Last, Body: make([]byte, 0, a.Size)}
	for {
		c, err := st.ReadFrame(sfcp.MaxBody)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return logstore.Bulk{}, err
		}
		if c.Kind != 4 || len(c.Fields) != 3 || len(c.Fields[0].Value) != 8 || binary.LittleEndian.Uint64(c.Fields[0].Value) != uint64(len(out.Body)) || string(c.Fields[2].Value) != string(header[:]) || len(out.Body)+len(c.Fields[1].Value) > a.Size {
			return logstore.Bulk{}, errors.New("engine log bulk: bad chunk")
		}
		out.Body = append(out.Body, c.Fields[1].Value...)
	}
	if len(out.Body) != a.Size {
		return logstore.Bulk{}, errors.New("engine log bulk: short body")
	}
	return out, nil
}

func (e engineLogs) Ack(ctx context.Context, container string, upto uint64) error {
	s, err := e.session()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, engineLogTimeout)
	defer cancel()
	q := engineLogAck{Request: engineRequest("ack"), Container: container, Upto: upto}
	f, _, err := engineRequestFrame(sfcp.EngineLogAck, q)
	if err != nil {
		return err
	}
	reply, err := s.Call(ctx, f, sfcp.CallOptions{CloseWrite: true})
	if err != nil {
		return err
	}
	if len(reply.Fields) != 1 {
		return errors.New("engine log ack: bad answer")
	}
	var a engineops.Reply
	if err = json.Unmarshal(reply.Fields[0].Value, &a); err != nil {
		return err
	}
	return checkEngineReply(a, q.OpID)
}

// logMeta names a container's log from its sfc labels: workload keys are
// workload/<kind>/<tenant>/<app>/<name>.
func logMeta(id string, attrs map[string]string) logstore.Meta {
	key := attrs["org.sfc.key"]
	m := logstore.Meta{Container: id, Name: strings.TrimPrefix(attrs["name"], "/"), Key: key}
	// workload/task/TENANT/APP/SERVICE, or .../SERVICE/NODE/rN for a
	// replica (deployment.TaskInstance.ResourceID).
	if parts := strings.Split(key, "/"); (len(parts) == 5 || len(parts) == 7) && parts[0] == "workload" && parts[1] == "task" {
		m.Tenant, m.App, m.Service = parts[2], parts[3], parts[4]
	}
	return m
}

// engineLogHandler moves each container's log from the engine queue into
// the store when the engine says lines are waiting (seafield.logs), and
// takes every queue once after an engine reboot or a feed gap.
func (r *Runtime) engineLogHandler() engineevents.Handler {
	e := engineLogs{r: r}
	return engineevents.Handler{
		Name: "logs",
		Wants: func(m events.Message) bool {
			return m.Type == events.ContainerEventType && m.Action == "seafield.logs"
		},
		Handle: func(ctx context.Context, rec engineevents.Record) error {
			if r.logs == nil {
				return nil
			}
			_, err := r.logs.Fetch(ctx, e, rec.Event.Actor.ID, logMeta(rec.Event.Actor.ID, rec.Event.Actor.Attributes))
			return err
		},
		Rescan: func(ctx context.Context) error {
			if r.logs == nil || r.docker == nil {
				return nil
			}
			listed, err := r.docker.API.ContainerList(ctx, client.ContainerListOptions{All: true, Filters: client.Filters{}.Add("label", "org.sfc.owner="+r.docker.Owner)})
			if err != nil {
				return err
			}
			var errs []error
			for _, c := range listed.Items {
				attrs := map[string]string{"org.sfc.key": c.Labels["org.sfc.key"]}
				if len(c.Names) > 0 {
					attrs["name"] = c.Names[0]
				}
				if _, err := r.logs.Fetch(ctx, e, c.ID, logMeta(c.ID, attrs)); err != nil {
					errs = append(errs, err)
				}
			}
			return errors.Join(errs...)
		},
	}
}
