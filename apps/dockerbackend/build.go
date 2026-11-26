// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

// Commands used only by the owned BuildKit native fixture. The production
// engine does not know these paths, Secret values or result markers.
func buildFixture(args []string) (bool, error) {
	if len(args) < 2 {
		return false, nil
	}
	switch args[1] {
	case "--build-secret-fixture":
		if len(args) != 3 {
			return true, errors.New("invalid build fixture input")
		}
		file, err := os.Open("/run/secrets/native-secret")
		if err != nil {
			return true, errors.New("build Secret mount unavailable")
		}
		value, readErr := io.ReadAll(io.LimitReader(file, 4097))
		closeErr := file.Close()
		defer clear(value)
		digest := sha256.Sum256(value)
		if readErr != nil || closeErr != nil || len(value) > 4096 || hex.EncodeToString(digest[:]) != args[2] {
			return true, errors.New("build Secret mount mismatch")
		}
		// Deliberate test-only disclosure into SDK progress verifies that the
		// production log redactor, not this fixture, protects the saved log.
		if _, err = fmt.Fprintf(os.Stdout, "owned-build-secret=%s\n", value); err != nil {
			return true, err
		}
		// REQ-59's owned native input: a real 400KiB progress stream, not a
		// large Total with fabricated page bytes. Keep memory to one 4KiB block.
		block := strings.Repeat("x", 4095) + "\n"
		for range 100 {
			if _, err = io.WriteString(os.Stdout, block); err != nil {
				return true, err
			}
			// BuildKit's per-step progress limiter clips an instantaneous
			// 400KiB burst. Emit below its default rate so this test measures
			// stored Tail bytes rather than an upstream clipping marker.
			time.Sleep(40 * time.Millisecond)
		}
		if _, err = fmt.Fprintln(os.Stdout, "owned-build-tail-complete"); err != nil {
			return true, err
		}
		return true, os.WriteFile("/build-secret-proof", []byte("owned-build-mount-ok"), 0444)
	case "--build-result-fixture":
		if len(args) != 3 {
			return true, errors.New("invalid result fixture input")
		}
		mount, err := os.ReadFile("/build-secret-proof")
		if err != nil || string(mount) != "owned-build-mount-ok" {
			return true, errors.New("build mount result missing")
		}
		context, err := os.ReadFile("/build-context-proof")
		if err != nil || string(context) != args[2] {
			return true, errors.New("build context result mismatch")
		}
		if _, err = os.Stat("/run/secrets/native-secret"); !os.IsNotExist(err) {
			return true, errors.New("build Secret mount survived in result")
		}
		_, err = fmt.Fprintln(os.Stdout, "owned-build-result-ok")
		return true, err
	case "--build-context-result-fixture":
		if len(args) != 3 && len(args) != 4 {
			return true, errors.New("invalid context result fixture input")
		}
		context, err := os.ReadFile("/build-context-proof")
		if err != nil || string(context) != args[2] {
			return true, errors.New("build context result mismatch")
		}
		if len(args) == 4 {
			multipart, err := os.ReadFile("/build-multipart-proof")
			if err != nil || len(multipart) > 1<<20 {
				return true, errors.New("build multipart result unavailable")
			}
			digest := sha256.Sum256(multipart)
			if hex.EncodeToString(digest[:]) != args[3] {
				return true, errors.New("build multipart result mismatch")
			}
		}
		_, err = fmt.Fprintln(os.Stdout, "owned-build-result-ok")
		return true, err
	case "--build-two-source-result-fixture":
		if len(args) != 4 {
			return true, errors.New("invalid source result fixture input")
		}
		primary, err := os.ReadFile("/registry-repository")
		if err != nil || string(primary) != "fixture" {
			return true, errors.New("first source build result mismatch")
		}
		context, err := os.ReadFile("/build-context-proof")
		if err != nil || string(context) != args[2] {
			return true, errors.New("source build context mismatch")
		}
		other, err := os.ReadFile("/other-source-proof")
		if err != nil || string(other) != args[3] {
			return true, errors.New("second source build result mismatch")
		}
		_, err = fmt.Fprintln(os.Stdout, "owned-build-result-ok")
		return true, err
	}
	return false, nil
}
