// SPDX-License-Identifier: Apache-2.0

package mydc

import (
	"encoding/json"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/jay94ks/mydcd/internal/cluster/control"
)

func TestTaskDetail(t *testing.T) {
	f, _ := newTestFake(t)
	f.SetIdleTimeout(0)
	alice := passwordLogin(t, f, "alice", "alice")
	bob, _ := keyLogin(t, f, "bob", FixtureKey("bob"))
	db := ContainerSelection{App: "php-shop", Service: "db", Instance: "1"}
	worker := ContainerSelection{App: "shop-worker", Service: "worker", Instance: "1"}

	// Detail: mounts and networks from app.yaml, no secret value anywhere.
	d, err := bob.TaskDetail(ctx, "shop", db)
	if err != nil || d.Node != "node-b" || d.Image != "mysql:8.4" || !strings.HasPrefix(d.Digest, "sha256:") ||
		len(d.Mounts) != 1 || d.Mounts[0].Source != "mysql-data" || d.Mounts[0].Target != "/var/lib/mysql" || len(d.Networks) != 1 || d.Networks[0].Name != "shop-net" {
		t.Fatalf("detail %+v %v", d, err)
	}
	f.SetTaskDrift("shop", "php-shop", "db", "1", []string{"services.db.image"})
	if d, _ := bob.TaskDetail(ctx, "shop", db); !slices.Equal(d.Drift, []string{"services.db.image"}) {
		t.Fatalf("drift %+v", d.Drift)
	}

	// History: the fixture worker restarted 3 times (OOM); a kill adds 137.
	h, err := bob.TaskHistory(ctx, "shop", worker, 0)
	if err != nil || len(h.Exits) != 3 || h.Exits[0].Reason != ExitReasonOOM || h.Exits[0].ExitCode != 137 || h.Checks[0].ConsecutiveFailures != 3 {
		t.Fatalf("history %+v %v", h, err)
	}
	f.KillTask("shop", "php-shop", "db", "1", ExitReasonExit, 137)
	if h, _ := bob.TaskHistory(ctx, "shop", db, 0); len(h.Exits) != 1 || h.Exits[0].ExitCode != 137 || h.Exits[0].Reason != ExitReasonExit {
		t.Fatalf("kill %+v", h.Exits)
	}

	// Logs: a printed secret value is masked; the cursor reads back over
	// everything with no gap or overlap.
	f.SetTaskSecretValue("shop", "php-shop", "db", "1", "mysql/MYSQL_PASSWORD", "hunter2")
	f.AddTaskLog("shop", "php-shop", "db", "1", "connecting with password hunter2")
	p, err := bob.TaskLogs(ctx, "shop", TaskLogQuery{Selection: db, Limit: 50})
	if err != nil || p.Masked != 1 || !strings.Contains(p.Lines[len(p.Lines)-1].Text, "«가림: mysql/MYSQL_PASSWORD»") || strings.Contains(p.Lines[len(p.Lines)-1].Text, "hunter2") {
		t.Fatalf("mask %+v %v", p, err)
	}
	var seqs []uint64
	for cur := ""; ; {
		pg, err := bob.TaskLogs(ctx, "shop", TaskLogQuery{Selection: db, Cursor: cur, Limit: 70})
		if err != nil {
			t.Fatal(err)
		}
		for i := len(pg.Lines) - 1; i >= 0; i-- {
			seqs = append(seqs, pg.Lines[i].Seq)
		}
		if pg.Cursor == "" {
			break
		}
		cur = pg.Cursor
	}
	if len(seqs) != 301 || seqs[0] != 301 || seqs[300] != 1 {
		t.Fatalf("paged %d lines", len(seqs))
	}
	for i := 1; i < len(seqs); i++ {
		if seqs[i] != seqs[i-1]-1 {
			t.Fatalf("gap at %d", i)
		}
	}
	if s, err := bob.TaskStats(ctx, "shop", db); err != nil || len(s) == 0 {
		t.Fatalf("stats %v %v", len(s), err)
	}

	// restart-task: only that task; reader refused; other tenant refused.
	rs, rev := restartChange(t, alice, "shop", worker, "rs-1")
	if _, res := submit(t, bob, ActionRestartTask, rev, rs, rootFor(t, bob, ActionRestartTask)); res.Code != ResultForbidden {
		t.Fatalf("bob %+v", res)
	}
	before, _ := alice.Tasks(ctx, TaskFilter{Tenant: "shop", App: "php-shop"}, "")
	if _, res := submit(t, alice, ActionRestartTask, rev, rs, rootFor(t, alice, ActionRestartTask)); res.Code != ResultApplied {
		t.Fatalf("restart %+v", res)
	}
	after, _ := alice.Tasks(ctx, TaskFilter{Tenant: "shop", App: "php-shop"}, "")
	if !slices.Equal(before.Items, after.Items) {
		t.Fatal("other app's tasks changed")
	}
	h, _ = bob.TaskHistory(ctx, "shop", worker, 0)
	if h.Exits[0].Reason != ExitReasonUser {
		t.Fatalf("restart history %+v", h.Exits[0])
	}
	if op, err := alice.AppOperation(ctx, "shop", "shop-worker", "rs-1"); err != nil || op.Status != "succeeded" {
		t.Fatalf("op %+v %v", op, err)
	}
	_, err = bob.TaskDetail(ctx, "payments", ContainerSelection{App: "payments-api", Service: "api", Instance: "1"})
	wantCode(t, err, CodeDenied)
}

// Ports carry their host bindings: a fixed published port as written, a
// dynamic one picked by the fake within the range (or Docker's ephemeral range).
func TestTaskDetailPublishedPorts(t *testing.T) {
	f, _ := newTestFake(t)
	f.SetIdleTimeout(0)
	alice := passwordLogin(t, f, "alice", "alice")
	doc := strings.Replace(phpShopYAML, "    networks: [shop-net]\n  db:", "    networks: [shop-net]\n    ports:\n      - \"127.0.0.1:18080:8080/tcp\"\n      - \"18081:8080\"\n      - \"9000\"\n      - \"20000-20010:9100\"\n      - {target: 53, published: \"15353\", host_ip: \"10.0.0.11\", protocol: udp}\n      - \"[::1]:18082:8080\"\n  db:", 1)
	apps, _ := alice.Apps(ctx, "shop", "")
	var cur AppView
	for _, a := range apps.Items {
		if a.App == "php-shop" {
			cur = a
		}
	}
	uploadApp(t, alice, "shop", "php-shop", "up-ports", []byte(doc))
	if _, res := submit(t, alice, ActionBeginApp, cur.Revision, control.AppBegin{Tenant: "shop", App: "php-shop", Deployment: cur.Deployment, Upload: "up-ports", Operation: "ports-1"}, rootFor(t, alice, ActionBeginApp)); res.Code != ResultApplied {
		t.Fatalf("begin %+v", res)
	}
	d, err := alice.TaskDetail(ctx, "shop", ContainerSelection{App: "php-shop", Service: "web", Instance: "1"})
	if err != nil || len(d.Ports) != 4 {
		t.Fatalf("ports %+v %v", d.Ports, err)
	}
	p := d.Ports[0] // 8080/tcp, two bindings
	if p.Port != 8080 || p.Protocol != "tcp" || len(p.Published) != 3 || p.Published[0] != (TaskPortBinding{HostIP: "127.0.0.1", HostPort: "18080"}) || p.Published[1] != (TaskPortBinding{HostPort: "18081"}) || p.Published[2] != (TaskPortBinding{HostIP: "::1", HostPort: "18082"}) {
		t.Fatalf("8080 %+v", p)
	}
	port := func(b TaskPortBinding) int { n, _ := strconv.Atoi(b.HostPort); return n }
	if p := d.Ports[1]; p.Port != 9000 || len(p.Published) != 1 || port(p.Published[0]) < 32768 || port(p.Published[0]) > 60999 {
		t.Fatalf("9000 %+v", p)
	}
	if p := d.Ports[2]; p.Port != 9100 || port(p.Published[0]) < 20000 || port(p.Published[0]) > 20010 {
		t.Fatalf("9100 %+v", p)
	}
	if p := d.Ports[3]; p.Port != 53 || p.Protocol != "udp" || p.Published[0] != (TaskPortBinding{HostIP: "10.0.0.11", HostPort: "15353"}) {
		t.Fatalf("53 %+v", p)
	}
	b, _ := json.Marshal(p.Published[0])
	if string(b) != `{"hostIp":"127.0.0.1","HostPort":"18080"}` {
		t.Fatalf("json %s", b)
	}
}
