// SPDX-License-Identifier: Apache-2.0

package app

import (
	"strings"
	"testing"

	"github.com/jay94ks/seafield/internal/eventbus"
)

func TestNodeAlarmReach(t *testing.T) {
	ok := eventbus.Event{Topic: "alarm/disk", Scope: eventbus.Scope{Nodes: []string{"b"}}}
	if !validNodeAlarm(ok) || !alarmReaches(ok.Scope, "b") || alarmReaches(ok.Scope, "c") {
		t.Fatal("named node reach")
	}
	for name, e := range map[string]eventbus.Event{
		"no reach":   {Topic: "alarm/disk"},
		"user":       {Topic: "alarm/disk", Scope: eventbus.Scope{Web: true, User: "u"}},
		"topic":      {Topic: eventbus.TopicReport, Scope: eventbus.Scope{AllNodes: true}},
		"long note":  {Topic: "alarm/disk", Scope: eventbus.Scope{AllNodes: true}, Note: strings.Repeat("x", eventbus.MaxAlarmNote+1)},
		"many nodes": {Topic: "alarm/disk", Scope: eventbus.Scope{Nodes: make([]string, 65)}},
	} {
		if validNodeAlarm(e) {
			t.Fatal("accepted", name)
		}
	}
	web := eventbus.Scope{Web: true}
	if !alarmReaches(web, "any") || !alarmReaches(eventbus.Scope{AllNodes: true}, "any") {
		t.Fatal("broad reach")
	}
}
