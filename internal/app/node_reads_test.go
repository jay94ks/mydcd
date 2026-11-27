// SPDX-License-Identifier: Apache-2.0

package app

import (
	"testing"

	"github.com/jay94ks/seafield/internal/cluster"
)

// Every node read method in the cluster table has exactly one handler here,
// and every handler serves a listed method or a built-in module read.
func TestNodeReadsMatchClusterTable(t *testing.T) {
	listed := map[string]bool{"plan": true}
	for _, m := range cluster.NodeReadMethods() {
		listed[m] = true
		if _, ok := nodeReads[m]; !ok {
			t.Errorf("node read %s has no handler", m)
		}
	}
	for m := range nodeReads {
		if !listed[m] {
			t.Errorf("handler %s serves no listed node method", m)
		}
	}
}
