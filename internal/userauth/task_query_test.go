// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"encoding/json"
	"testing"
)

func TestTaskQuerySelectorsCannotContaminateOtherMethods(t *testing.T) {
	tasks := func(params string) Request {
		return Request{Schema: 1, Method: "tasks", Params: json.RawMessage(params)}
	}
	for _, q := range []Request{tasks(`{"Node":"","Tenant":"","App":""}`), tasks(`{"Node":"node-a","Tenant":"tenant","App":"app","After":"cursor"}`), tasks(`{"Node":"","Tenant":"tenant","App":"","Standalone":"job"}`)} {
		if !q.validMethodFields() {
			t.Fatal("valid task selectors rejected", string(q.Params))
		}
	}
	for _, q := range []Request{
		tasks(`{"Node":"","Tenant":"","App":"../app"}`),
		tasks(`{"Node":"../node","Tenant":"","App":""}`),
		tasks(`{"Node":"","Tenant":"","App":"app","Standalone":"job"}`),
		tasks(`{"Node":"","Tenant":"","App":"","TargetUser":"other"}`),
		tasks(`{}`),
		{Schema: 1, Method: "tasks", After: "other", Params: json.RawMessage(`{"Node":"","Tenant":"","App":""}`)},
		{Method: "tasks", Node: "node-a"},
	} {
		if q.validMethodFields() {
			t.Fatal("foreign task selectors accepted", string(q.Params))
		}
	}
}
