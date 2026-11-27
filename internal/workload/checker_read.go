// SPDX-License-Identifier: Apache-2.0

package workload

import (
	"context"
	"errors"
	"io/fs"
	"path"
	"slices"
	"strings"

	cerrdefs "github.com/containerd/errdefs"
	contract "github.com/jay94ks/seafield/lifecycle/v1"
	"github.com/moby/moby/client"
)

// The callback performs current cluster/tenant/accepted Task authorization.
// These methods retain only an existing read pin and never start native exec.
func (m *Manager) ReadProbeHTTP(ctx context.Context, l ReadProbeLease, q contract.HTTPProbe, authorize func(context.Context) error) (contract.HTTPResult, error) {
	if authorize == nil || ctx == nil || q.MaxBytes < 1 || q.MaxBytes > 1<<20 || q.Method != "GET" && q.Method != "HEAD" || len(q.ExpectedStatus) == 0 || len(q.ExpectedStatus) > 16 {
		return contract.HTTPResult{}, ErrPlacement
	}
	for _, code := range q.ExpectedStatus {
		if code < 100 || code > 599 {
			return contract.HTTPResult{}, ErrPlacement
		}
	}
	ip := l.Target.IPv4
	if !ip.IsValid() {
		ip = l.Target.IPv6
	}
	if _, err := probeHTTPURL(ip, q.Method, q.Path, q.Port, q.TLS, q.MaxBytes); err != nil {
		return contract.HTTPResult{}, err
	}
	if err := authorize(ctx); err != nil {
		return contract.HTTPResult{}, err
	}
	if err := m.CheckReadProbe(ctx, l); err != nil {
		return contract.HTTPResult{}, err
	}
	status, err := probeHTTP(ctx, ip, q.Method, q.Path, q.Port, q.TLS, q.MaxBytes)
	if err != nil {
		return contract.HTTPResult{}, err
	}
	if err = m.CheckReadProbe(ctx, l); err != nil {
		return contract.HTTPResult{}, err
	}
	if err = authorize(ctx); err != nil {
		return contract.HTTPResult{}, err
	}
	return contract.HTTPResult{StatusCode: status, Match: slices.Contains(q.ExpectedStatus, status)}, nil
}
func (m *Manager) ReadProbeFile(ctx context.Context, l ReadProbeLease, q contract.FileProbe, authorize func(context.Context) error) (contract.FileResult, error) {
	if authorize == nil || ctx == nil || !path.IsAbs(q.Path) || path.Clean(q.Path) != q.Path || q.Path == "/" || len(q.Path) > 4096 || strings.ContainsAny(q.Path, "\x00\r\n") || q.Kind != "any" && q.Kind != "regular" && q.Kind != "directory" || !validFileContent(q) {
		return contract.FileResult{}, ErrPlacement
	}
	if err := authorize(ctx); err != nil {
		return contract.FileResult{}, err
	}
	if err := m.CheckReadProbe(ctx, l); err != nil {
		return contract.FileResult{}, err
	}
	got, err := m.driver.Engine.API.ContainerStatPath(ctx, l.Target.Status.NativeID, client.ContainerStatPathOptions{Path: q.Path})
	if err != nil && !cerrdefs.IsNotFound(err) {
		return contract.FileResult{}, err
	}
	// A path404 alone cannot distinguish a removed container. Revalidate the
	// same original container and current grant before publishing Exists=false.
	if check := m.CheckReadProbe(ctx, l); check != nil {
		return contract.FileResult{}, errors.Join(check, err)
	}
	if check := authorize(ctx); check != nil {
		return contract.FileResult{}, check
	}
	if ctx.Err() != nil {
		return contract.FileResult{}, ctx.Err()
	}
	if err != nil {
		return contract.FileResult{}, nil
	}
	kind := "other"
	if got.Stat.LinkTarget == "" {
		if got.Stat.Mode.IsRegular() {
			kind = "regular"
		} else if got.Stat.Mode.IsDir() {
			kind = "directory"
		}
	}
	mode := uint32(got.Stat.Mode.Perm())
	if got.Stat.Mode&fs.ModeSetuid != 0 {
		mode |= 04000
	}
	if got.Stat.Mode&fs.ModeSetgid != 0 {
		mode |= 02000
	}
	if got.Stat.Mode&fs.ModeSticky != 0 {
		mode |= 01000
	}
	result := contract.FileResult{Exists: true, Match: q.Kind == "any" || q.Kind == kind, Kind: kind, Mode: mode}
	if q.ContentDigest != "" && kind == "regular" {
		if got.Stat.Size < 0 || got.Stat.Size > int64(q.MaxBytes) {
			return contract.FileResult{}, ErrProbeFileContent
		}
		copy, err := m.driver.Engine.API.CopyFromContainer(ctx, l.Target.Status.NativeID, client.CopyFromContainerOptions{SourcePath: q.Path})
		if err != nil {
			return contract.FileResult{}, err
		}
		if copy.Stat.Size != got.Stat.Size || copy.Stat.Mode != got.Stat.Mode || copy.Stat.LinkTarget != "" {
			if copy.Content != nil {
				_ = copy.Content.Close()
			}
			return contract.FileResult{}, ErrProbeFileContent
		}
		match, err := matchProbeFileArchive(ctx, copy.Content, q, got.Stat.Size, mode)
		if err != nil {
			return contract.FileResult{}, err
		}
		if err = m.CheckReadProbe(ctx, l); err != nil {
			return contract.FileResult{}, err
		}
		if err = authorize(ctx); err != nil {
			return contract.FileResult{}, err
		}
		if err = ctx.Err(); err != nil {
			return contract.FileResult{}, err
		}
		result.Match = result.Match && match
	}
	return result, nil
}
