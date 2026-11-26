// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"os"
	"runtime/pprof"
	"runtime/trace"
	"strings"
	"testing"
	"time"
)

// Diagnostic entrypoint for the existing daemon, using Go's standard test CPU
// profiler. No profiling listener or production flag is added.
func TestE8DaemonCPUProfile(t *testing.T) {
	path := os.Getenv("MYDC_E8_PROFILE_CONFIG")
	if path == "" {
		t.Skip("explicit owned E8 guest profile only")
	}
	output := os.Getenv("MYDC_E8_PROFILE_OUTPUT")
	steady := path == "/srv/mydc/e8/inputs/app-window53/node-a.yaml" || path == "/srv/mydc/e8/inputs/app-window56/node-a.yaml" || path == "/srv/mydc/e8/inputs/app-window60/node-a.yaml" || path == "/srv/mydc/e8/inputs/app-window61/node-a.yaml" || (path == "/srv/mydc/e8/inputs/app-window64/node-a.yaml" || (path == "/srv/mydc/e8/inputs/app-window65/node-a.yaml" || path == "/srv/mydc/e8/inputs/app-window66/node-a.yaml"))
	if (path != "/srv/mydc/e8/inputs/app-window3/node-a.yaml" && path != "/srv/mydc/e8/inputs/app-window8/node-a.yaml" && path != "/srv/mydc/e8/inputs/app-window36/node-a.yaml" && path != "/srv/mydc/e8/inputs/app-window52/node-a.yaml" && !steady) || !strings.HasPrefix(output, "/srv/mydc/e8/inputs/") {
		t.Fatal("unplanned profiling input")
	}
	var done chan struct{}
	var profiled chan error
	if steady {
		marker := os.Getenv("MYDC_E8_PROFILE_START")
		if marker != output+".start" {
			t.Fatal("steady profile requires its exact private start marker")
		}
		done, profiled = make(chan struct{}), make(chan error, 1)
		traceOutput := os.Getenv("MYDC_E8_PROFILE_TRACE")
		if traceOutput != "" && ((path != "/srv/mydc/e8/inputs/app-window61/node-a.yaml" && path != "/srv/mydc/e8/inputs/app-window64/node-a.yaml" && path != "/srv/mydc/e8/inputs/app-window65/node-a.yaml") || traceOutput != output+".trace") {
			t.Fatal("unplanned steady trace output")
		}
		go func() { profiled <- profileAfterQuorumMarker(done, marker, output, traceOutput) }()
	}
	code := run([]string{"--config", path, "run"}, os.Stdout, os.Stderr)
	if steady {
		close(done)
		if err := <-profiled; err != nil {
			t.Fatal(err)
		}
	}
	if code != 0 {
		t.Fatalf("real daemon returned %d", code)
	}
}

// The owned fixture creates this marker only after both original daemons have
// recovered a fresh N2/Q2 read. It controls measurement, never product state.
func profileAfterQuorumMarker(done <-chan struct{}, marker, output, traceOutput string) error {
	tick := time.NewTicker(25 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-done:
			return fmt.Errorf("daemon stopped before steady profiling began")
		case <-tick.C:
			raw, err := os.ReadFile(marker)
			if os.IsNotExist(err) {
				continue
			}
			if err != nil {
				return fmt.Errorf("read steady profiling marker: %w", err)
			}
			if string(raw) != "after-quorum\n" {
				return fmt.Errorf("invalid steady profiling marker contents")
			}
			file, err := os.OpenFile(output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
			if err != nil {
				return err
			}
			if err := pprof.StartCPUProfile(file); err != nil {
				file.Close()
				return err
			}
			var traceFile *os.File
			if traceOutput != "" {
				traceFile, err = os.OpenFile(traceOutput, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
				if err == nil {
					err = trace.Start(traceFile)
				}
				if err != nil {
					pprof.StopCPUProfile()
					_ = file.Close()
					if traceFile != nil {
						_ = traceFile.Close()
					}
					return err
				}
			}
			<-done
			if traceFile != nil {
				trace.Stop()
			}
			pprof.StopCPUProfile()
			err = file.Sync()
			closeErr := file.Close()
			if traceFile != nil {
				traceSyncErr := traceFile.Sync()
				traceCloseErr := traceFile.Close()
				if traceSyncErr != nil {
					return traceSyncErr
				}
				if traceCloseErr != nil {
					return traceCloseErr
				}
			}
			if err != nil {
				return err
			}
			return closeErr
		}
	}
}
