// SPDX-License-Identifier: Apache-2.0

package workload

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/jay94ks/seafield/internal/containerops"
	"github.com/jay94ks/seafield/internal/engine"
	"github.com/moby/moby/api/pkg/stdcopy"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/client"
)

type observationBuffer struct {
	data      *[]byte
	remaining *int
}

func (b observationBuffer) Write(value []byte) (int, error) {
	n := min(len(value), *b.remaining)
	*b.data = append(*b.data, value[:n]...)
	*b.remaining -= n
	if n < len(value) {
		return n, containerops.ErrLimit
	}
	return n, nil
}

// ObserveContainer never starts a container or borrows long-lived native pins.
// The SDK operates on an exact ID, with journal/ownership fences on both sides;
// concurrent removal/replacement invalidates the response instead of rebinding.
func (m *Manager) ObserveContainer(ctx context.Context, target containerops.Target, q containerops.Query) (containerops.Result, error) {
	if q.Cursor != "" {
		return containerops.Result{}, containerops.ErrQuery
	}
	return m.observeContainer(ctx, target, q, q.MaxBytes)
}

// ObserveContainerLogWindow is owner-local only. The runtime pages the already
// filtered bounded window before any SFCP response; no large wire frame or raw
// log cache is created. Oversized windows fail rather than imply gap-free data.
func (m *Manager) ObserveContainerLogWindow(ctx context.Context, target containerops.Target, q containerops.Query) (containerops.Result, error) {
	if q.Kind != "logs" || q.Cursor != "" {
		return containerops.Result{}, containerops.ErrQuery
	}
	return m.observeContainer(ctx, target, q, containerops.MaxLogWindowBytes)
}

func (m *Manager) observeContainer(ctx context.Context, target containerops.Target, q containerops.Query, budget int) (containerops.Result, error) {
	var out containerops.Result
	if q.Validate() != nil || !target.Valid() || m == nil || m.driver == nil || m.driver.Engine == nil || m.driver.Engine.Owner != engine.Owner(target.Cluster, target.Owner) {
		return out, engine.ErrOwnership
	}
	before, err := m.ProbeTarget(ctx, target.Instance, target.Generation, target.Revision)
	if err != nil {
		return out, err
	}
	actual := target
	actual.NativeID, actual.StartedAt = before.Status.NativeID, before.Status.StartedAt
	if !actual.Matches(target) {
		return out, engine.ErrOwnership
	}
	out = containerops.Result{Schema: 1, Kind: q.Kind, Target: actual, ObservedAt: time.Now().UTC(), LogDriver: before.Status.LogDriver}
	api := m.driver.Engine.API
	switch q.Kind {
	case "logs":
		values, e := m.logRedactionValues(ctx, target)
		if e != nil {
			return containerops.Result{}, e
		}
		defer destroyLogValues(values)
		inspected, e := api.ContainerInspect(ctx, actual.NativeID, client.ContainerInspectOptions{})
		if e != nil {
			return out, e
		}
		if inspected.Container.Config == nil || inspected.Container.ID != actual.NativeID {
			return out, engine.ErrOwnership
		}
		out.TTY = inspected.Container.Config.Tty
		logs, e := m.containerLogs(ctx, actual.NativeID, q, out.TTY, false)
		if e != nil {
			return out, e
		}
		out.Stdout, out.Stderr, out.Truncated, err = readRedactedObservationLogs(logs, out.TTY, budget, values)
		if err != nil {
			return out, err
		}
	case "top":
		top, e := api.ContainerTop(ctx, actual.NativeID, client.ContainerTopOptions{Arguments: []string{"-eo", "pid,user,args"}})
		if e != nil {
			return out, e
		}
		if len(top.Titles) == 0 || len(top.Titles) > 32 {
			return out, containerops.ErrQuery
		}
		out.Titles = top.Titles
		size := 0
		for _, title := range out.Titles {
			size += len(title)
		}
		if size > q.MaxBytes {
			return out, containerops.ErrLimit
		}
		for _, row := range top.Processes {
			if len(row) != len(top.Titles) {
				return out, containerops.ErrQuery
			}
			rowBytes := 0
			for _, field := range row {
				rowBytes += len(field)
			}
			if len(out.Processes) == 256 || size+rowBytes > q.MaxBytes {
				out.Truncated = true
				break
			}
			size += rowBytes
			out.Processes = append(out.Processes, row)
		}
	case "stats":
		stats, e := api.ContainerStats(ctx, actual.NativeID, client.ContainerStatsOptions{IncludePreviousSample: true})
		if e != nil {
			return out, e
		}
		var sample container.StatsResponse
		decodeErr := json.NewDecoder(io.LimitReader(stats.Body, 256<<10)).Decode(&sample)
		closeErr := stats.Body.Close()
		if decodeErr != nil || closeErr != nil {
			return out, errors.Join(decodeErr, closeErr)
		}
		if sample.ID != "" && sample.ID != actual.NativeID {
			return out, engine.ErrOwnership
		}
		summary := containerops.Summarize(sample)
		out.Stats = &summary
	}
	after, err := m.ProbeTarget(ctx, target.Instance, target.Generation, target.Revision)
	if err != nil {
		return out, err
	}
	if before.Status.NativeID != after.Status.NativeID || before.Status.StartedAt != after.Status.StartedAt || before.Status.Running != after.Status.Running {
		return out, engine.ErrOwnership
	}
	validation := out
	if budget > containerops.MaxOutput {
		if out.Truncated {
			clear(out.Stdout)
			clear(out.Stderr)
			out.Stdout, out.Stderr = nil, nil
			return out, containerops.ErrLogWindowLimit
		}
		validation.Stdout, validation.Stderr = nil, nil
	}
	if err = validation.Validate(q, target); err != nil {
		return out, err
	}
	return out, nil
}

// Both finite user queries and stream adapters use the same Docker framing and
// output budget; the caller always joins collection before releasing ownership.
func readObservationLogs(logs io.ReadCloser, tty bool, maxBytes int) (stdout, stderr []byte, truncated bool, err error) {
	if maxBytes < 1 || maxBytes > containerops.MaxOutput {
		return nil, nil, false, errors.Join(containerops.ErrLimit, logs.Close())
	}
	return readRedactedObservationLogs(logs, tty, maxBytes, nil)
}

func readRedactedObservationLogs(logs io.ReadCloser, tty bool, maxBytes int, values []containerops.RedactionValue) (stdout, stderr []byte, truncated bool, err error) {
	if maxBytes < 1 || maxBytes > containerops.MaxLogWindowBytes {
		return nil, nil, false, errors.Join(containerops.ErrLimit, logs.Close())
	}
	remaining := maxBytes
	out, diagnostic := observationBuffer{&stdout, &remaining}, observationBuffer{&stderr, &remaining}
	filteredOut, err := containerops.NewRedactor(out, values)
	if err != nil {
		return nil, nil, false, errors.Join(err, logs.Close())
	}
	defer filteredOut.Destroy()
	filteredDiagnostic, err := containerops.NewRedactor(diagnostic, values)
	if err != nil {
		return nil, nil, false, errors.Join(err, logs.Close())
	}
	defer filteredDiagnostic.Destroy()
	if tty {
		_, err = io.Copy(filteredOut, logs)
	} else {
		_, err = stdcopy.StdCopy(filteredOut, filteredDiagnostic, &probeExecFrames{source: logs})
	}
	if err == nil {
		err = filteredOut.Finish()
		if err == nil {
			err = filteredDiagnostic.Finish()
		}
	}
	closeErr := logs.Close()
	if errors.Is(err, containerops.ErrLimit) {
		truncated = true
		err = nil
	}
	return stdout, stderr, truncated, errors.Join(err, closeErr)
}
