// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestComposeDockerHealthFormsUseOneNativeConfiguration(t *testing.T) {
	base := "name: example\nservices:\n  web:\n    image: docker.io/library/php@sha256:" + strings.Repeat("a", 64) + "\n    healthcheck: "
	for _, tc := range []struct {
		yaml     string
		test     []string
		start    time.Duration
		disabled bool
	}{
		{"{test: [CMD, probe]}", []string{"CMD", "probe"}, 0, false},
		{"{test: 'exit 0'}", []string{"CMD-SHELL", "exit 0"}, 0, false},
		{"{test: [CMD-SHELL, 'exit 0'], start_interval: 1s}", []string{"CMD-SHELL", "exit 0"}, time.Second, false},
		{"{disable: true}", []string{"NONE"}, 0, true},
		{"{test: [NONE]}", []string{"NONE"}, 0, true},
		{"{timeout: 2s, interval: 0s, retries: 0}", nil, 0, false},
	} {
		t.Run(tc.yaml, func(t *testing.T) {
			c, err := ParseCompose([]byte(base + tc.yaml + "\n"))
			if err != nil {
				t.Fatal(err)
			}
			if _, err = c.Canonical(); err != nil {
				t.Fatal(err)
			}
			h := c.Services["web"].Healthcheck
			cfg, err := h.dockerConfig()
			if err != nil || !reflect.DeepEqual(cfg.Test, tc.test) || cfg.StartInterval != tc.start || h.disabled() != tc.disabled {
				t.Fatal("Compose -> native health configuration", cfg, err)
			}
		})
	}
	for _, bad := range []string{
		"{test: [BOGUS, probe]}", "{test: [NONE, probe]}", "{test: [CMD]}", "{test: [CMD-SHELL]}",
		"{test: [CMD, probe], retries: -1}", "{test: [CMD, probe], retries: 101}",
		"{test: [CMD, probe], start_interval: -1s}", "{test: [CMD, probe], timeout: 1ns}",
		"{disable: 'true'}", "{disable: null}", "{test: [CMD, probe], interval: 2h}",
	} {
		c, err := ParseCompose([]byte(base + bad + "\n"))
		if err == nil {
			_, err = c.Canonical()
		}
		if err == nil {
			t.Fatal("invalid healthcheck accepted", bad)
		}
	}
}

func TestDisabledHealthCannotSatisfyHealthyDependencyOrExecReadiness(t *testing.T) {
	c := smallCompose(t)
	db := c.Services["db"]
	db.Healthcheck = &Healthcheck{Disable: true}
	c.Services["db"] = db
	if _, err := c.Canonical(); err == nil {
		t.Fatal("disabled healthcheck satisfied service_healthy")
	}
	db.MyDC.Readiness = &Readiness{Kind: "exec"}
	c.Services["db"] = db
	if _, err := c.Canonical(); err == nil {
		t.Fatal("exec readiness accepted a disabled healthcheck")
	}
	db.MyDC.Readiness = &Readiness{Kind: "http", Path: "/ready", Port: 8080}
	c.Services["db"] = db
	if _, err := c.Canonical(); err != nil {
		t.Fatal("independent HTTP readiness was removed by health disable", err)
	}
}

func TestExistingHealthcheckSchemaOneBytesDoNotGainOptionalFields(t *testing.T) {
	raw, err := json.Marshal(Healthcheck{Test: []string{"CMD", "/probe"}, Retries: 2})
	if err != nil || string(raw) != `{"Test":["CMD","/probe"],"Interval":"","Timeout":"","Retries":2,"StartPeriod":""}` {
		t.Fatal("old healthcheck metadata changed", string(raw), err)
	}
}
