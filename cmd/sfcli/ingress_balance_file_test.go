// SPDX-License-Identifier: Apache-2.0

package main

import (
	"testing"

	"gopkg.in/yaml.v3"
)

func TestBalanceFileNeedsVersion(t *testing.T) {
	var f balanceFile
	if err := yaml.Unmarshal([]byte("version: 1\nmethod: weighted\nweights: {v1: 90, v2: 10}\nwarmup: 30s\n"), &f); err != nil || f.Method != "weighted" || f.Weights["v1"] != 90 || f.SlowStartMS != 30000 {
		t.Fatalf("parse: %+v %v", f, err)
	}
	for name, bad := range map[string]string{
		"no version":    "method: weighted\nweights: {v1: 1}\n",
		"version 2":     "version: 2\nmethod: weighted\nweights: {v1: 1}\n",
		"unknown field": "version: 1\nmethod: weighted\nslow_start: 3\n",
		"not a map":     "[]\n",
	} {
		var f balanceFile
		if err := yaml.Unmarshal([]byte(bad), &f); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
