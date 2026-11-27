// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"os"
)

// This explicit fixture deliberately emits supplied values so the server's
// real Docker log adapters, not a fake logger, must remove them before output.
func secretLogFixture() {
	if os.Getenv("SFC_SECRET_LOG_FIXTURE") != "1" {
		return
	}
	value, err := os.ReadFile(os.Getenv("SFC_PROJECTION_FILE"))
	if err != nil {
		os.Exit(1)
	}
	fmt.Fprintf(os.Stdout, "environment=%s file=%s\n", os.Getenv("SFC_SECRET_ENV_VALUE"), value)
	clear(value)
}
