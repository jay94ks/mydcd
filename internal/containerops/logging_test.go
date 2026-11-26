// SPDX-License-Identifier: Apache-2.0

package containerops

import (
	"strings"
	"testing"
)

func TestObservedDriverDoesNotInventLocalDeletionSupport(t *testing.T) {
	for _, driver := range []string{"", "none", "syslog", "registry.example/logger/plugin:1", "local", "json-file"} {
		if !ValidLogDriver(driver) {
			t.Fatal("valid driver/plugin metadata rejected", driver)
		}
		if LocalLogDriver(driver) != (driver == "local" || driver == "json-file") {
			t.Fatal("external or absent driver gained local deletion support")
		}
	}
	for _, driver := range []string{"json-file\n", "local\x00", "log driver", strings.Repeat("x", 257), "로그"} {
		if ValidLogDriver(driver) {
			t.Fatal("malformed driver metadata accepted")
		}
	}
}
