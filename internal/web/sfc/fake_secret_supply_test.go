// SPDX-License-Identifier: Apache-2.0

package sfc

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/jay94ks/seafield/internal/cluster/control"
)

// secret values as environment variables and as files at a chosen
// path. Only references appear in plans and task detail.
func TestSecretSupply(t *testing.T) {
	f, _ := newTestFake(t)
	f.SetIdleTimeout(0)
	alice := passwordLogin(t, f, "alice", "alice")
	plan := func(doc string) (AppPlan, error) {
		return alice.AppPlan(ctx, AppPlanRequest{Tenant: "shop", Document: []byte(doc), Project: "php-shop"})
	}
	dbBlock := "      node: node-b\n"
	withEnv := strings.Replace(phpShopYAML, dbBlock, dbBlock+"      secret_env:\n        - {source: mysql, name: MYSQL_ROOT_PASSWORD}\n", 1)
	withEnv = strings.Replace(withEnv, "      - mysql-data:/var/lib/mysql\n", "      - mysql-data:/var/lib/mysql\n    secrets:\n      - {source: tls, target: /etc/app/key.pem, mode: 0440}\n      - plain\n", 1)
	p, err := plan(withEnv)
	if err != nil {
		t.Fatal(err)
	}
	i := slices.IndexFunc(p.Services, func(s PlannedService) bool { return s.Name == "db" })
	if !slices.Equal(p.Services[i].SecretEnv, []string{"MYSQL_ROOT_PASSWORD"}) {
		t.Fatalf("plan %+v", p.Services[i])
	}

	refused := func(doc, code string) {
		t.Helper()
		_, err := plan(doc)
		var e *Error
		if !errors.As(err, &e) || e.InputCode != code {
			t.Fatalf("want %s, got %v", code, err)
		}
	}
	refused(strings.Replace(withEnv, "    secrets:\n", "    environment: {MYSQL_ROOT_PASSWORD: x}\n    secrets:\n", 1), "SECRET_ENV_CONFLICT")
	refused(strings.Replace(withEnv, "name: MYSQL_ROOT_PASSWORD", "name: 1BAD", 1), "SECRET_ENV_INVALID")
	refused(strings.Replace(withEnv, "/etc/app/key.pem", "/proc/x", 1), "SECRET_TARGET_FORBIDDEN")
	refused(strings.Replace(withEnv, "/etc/app/key.pem", "/etc/hosts", 1), "SECRET_TARGET_FORBIDDEN")
	refused(strings.Replace(withEnv, "/etc/app/key.pem", "/etc/../proc/x", 1), "SECRET_TARGET_FORBIDDEN")

	// Deployed: detail lists references, never a value.
	apps, _ := alice.Apps(ctx, "shop", "")
	var cur AppView
	for _, a := range apps.Items {
		if a.App == "php-shop" {
			cur = a
		}
	}
	uploadApp(t, alice, "shop", "php-shop", "up-sec", []byte(withEnv))
	if _, res := submit(t, alice, ActionBeginApp, cur.Revision, control.AppBegin{Tenant: "shop", App: "php-shop", Deployment: cur.Deployment, Upload: "up-sec", Operation: "sec-1"}, rootFor(t, alice, ActionBeginApp)); res.Code != ResultApplied {
		t.Fatalf("begin %+v", res)
	}
	d, err := alice.TaskDetail(ctx, "shop", ContainerSelection{App: "php-shop", Service: "db", Instance: "1"})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(d.Env, func(e TaskEnv) bool {
		return e.Key == "MYSQL_ROOT_PASSWORD" && e.Secret == "secret:mysql" && e.Value == ""
	}) {
		t.Fatalf("env %+v", d.Env)
	}
	if !slices.ContainsFunc(d.Mounts, func(m TaskMount) bool {
		return m.Kind == "secret" && m.Target == "/etc/app/key.pem" && m.Mode == "0440" && m.Source == "secret:tls"
	}) || !slices.ContainsFunc(d.Mounts, func(m TaskMount) bool { return m.Kind == "secret" && m.Target == "/run/secrets/plain" }) {
		t.Fatalf("mounts %+v", d.Mounts)
	}
}
