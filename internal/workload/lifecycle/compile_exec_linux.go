// SPDX-License-Identifier: Apache-2.0

//go:build linux

package lifecycle

import (
	"bytes"
	"context"
	"crypto/sha256"
	"debug/buildinfo"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/jay94ks/mydcd/internal/schema"
)

const MaxCompileDiagnosticBytes = 64 << 10

// CompileEnvironment paths are fixed by the node's container adapter, never
// by an app or a source manifest. Input is read-only, work is bounded private
// scratch, output/cache are separately owned approved tenant/job mounts.
type CompileEnvironment struct{ Input, Work, Output, Cache, GoRoot string }

func (e CompileEnvironment) valid() bool {
	paths := []string{e.Input, e.Work, e.Output, e.Cache, e.GoRoot}
	for i, p := range paths {
		if !filepath.IsAbs(p) || filepath.Clean(p) != p || p == "/" || strings.ContainsAny(p, "\x00\r\n") {
			return false
		}
		info, err := os.Lstat(p)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return false
		}
		for j := 0; j < i; j++ {
			if p == paths[j] || strings.HasPrefix(p, paths[j]+"/") || strings.HasPrefix(paths[j], p+"/") {
				return false
			}
		}
	}
	return true
}

func compilerEnvironment(e CompileEnvironment, b CompileBatch, work string) []string {
	return []string{"PATH=" + filepath.Join(e.GoRoot, "bin"), "GOROOT=" + e.GoRoot,
		"GOTOOLCHAIN=local", "GOENV=off", "GO111MODULE=off", "GOWORK=off", "GOPROXY=off", "GOSUMDB=off",
		"GONOPROXY=none", "GONOSUMDB=none", "GOVCS=*:off", "GOFLAGS=", "GOEXPERIMENT=", "CGO_ENABLED=0",
		"GOOS=" + b.GOOS, "GOARCH=" + b.GOARCH, "GOAMD64=v1", "GOARM64=v8.0", "GOMAXPROCS=2",
		"GOPATH=" + filepath.Join(work, "checker"), "GOCACHE=" + e.Cache,
		"HOME=" + work, "TMPDIR=" + filepath.Join(work, "tmp"), "GOTMPDIR=" + filepath.Join(work, "tmp")}
}

type compileDiagnostic struct {
	data      bytes.Buffer
	remaining int
	truncated bool
}

func (w *compileDiagnostic) Write(p []byte) (int, error) {
	n := len(p)
	if len(p) > w.remaining {
		p = p[:w.remaining]
		w.truncated = true
	}
	_, _ = w.data.Write(p)
	w.remaining -= len(p)
	// Drain after the private diagnostic cap, so a full diagnostic pipe cannot
	// leave the fixed toolchain blocked until the entire job deadline.
	return n, nil
}

func runCompilerCommand(ctx context.Context, command *exec.Cmd) error {
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	command.Cancel = func() error {
		if command.Process == nil {
			return os.ErrProcessDone
		}
		err := syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
		if errors.Is(err, syscall.ESRCH) {
			return os.ErrProcessDone
		}
		return err
	}
	command.WaitDelay = 2 * time.Second
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := command.Start(); err != nil {
		return err
	}
	err := command.Wait()
	// Go is a fixed trusted toolchain, yet cancellation still closes its whole
	// subprocess group. The container owner separately proves Stop/Wait.
	_ = syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
	return err
}

func publishCompileArtifact(output *os.Root, item CompileItem, binaryPath string, max uint64, target string) (CompileArtifact, error) {
	r := CompileArtifact{Key: item.Key, Status: "failed", Reason: "artifact-invalid"}
	f, err := os.Open(binaryPath)
	if err != nil {
		return r, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || uint64(info.Size()) > max || verifyCompileELF(f, target) != nil {
		return r, ErrSource
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return r, err
	}
	name := hex.EncodeToString(item.Key[:]) + ".cli"
	pending := name + ".pending"
	data, err := output.OpenFile(pending, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if err != nil {
		return r, err
	}
	defer data.Close()
	defer output.Remove(pending)
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(data, h), io.LimitReader(f, int64(max)+1))
	if err != nil || n != info.Size() || uint64(n) > max {
		return r, ErrSource
	}
	if err := data.Chmod(0500); err != nil {
		return r, err
	}
	if err := data.Sync(); err != nil {
		return r, err
	}
	if _, err := data.Seek(0, io.SeekStart); err != nil {
		return r, err
	}
	readBack := sha256.New()
	if _, err := io.Copy(readBack, data); err != nil || !bytes.Equal(readBack.Sum(nil), h.Sum(nil)) {
		return r, ErrSource
	}
	// Never replace an original output by path, even after an uncertain exit.
	if _, err := output.Lstat(name); !os.IsNotExist(err) {
		return r, ErrSource
	}
	if err := output.Rename(pending, name); err != nil {
		return r, err
	}
	r.Status, r.Reason, r.Length = "built", "compiled", uint64(n)
	copy(r.Digest[:], h.Sum(nil))
	return r, nil
}

// ExecuteCompileBatch handles ONE finite manifest and returns. It does not
// poll for jobs, start containers, sign cache facts or infer native closure.
func ExecuteCompileBatch(ctx context.Context, environment CompileEnvironment) (report CompileReport, outcome error) {
	if ctx == nil || !environment.valid() {
		return CompileReport{}, ErrSource
	}
	input, err := os.OpenRoot(environment.Input)
	if err != nil {
		return CompileReport{}, err
	}
	defer input.Close()
	raw, err := readCompileFile(input, "manifest.json", MaxCompileManifestBytes)
	if err != nil {
		return CompileReport{}, err
	}
	batch, err := schema.Decode[CompileBatch](raw)
	clear(raw)
	if err != nil || batch.Validate() != nil || batch.Toolchain != runtime.Version() {
		return CompileReport{}, ErrSource
	}
	toolInfo, err := buildinfo.ReadFile(filepath.Join(environment.GoRoot, "bin/go"))
	if err != nil || toolInfo.GoVersion != batch.Toolchain {
		return CompileReport{}, ErrSource
	}
	ctx, cancel := context.WithDeadline(ctx, time.UnixMilli(batch.DeadlineUnixMilli))
	defer cancel()
	if ctx.Err() != nil {
		return CompileReport{}, ctx.Err()
	}
	output, err := os.OpenRoot(environment.Output)
	if err != nil {
		return CompileReport{}, err
	}
	defer output.Close()
	job := filepath.Join(environment.Work, batch.Job)
	if err := os.Mkdir(job, 0700); err != nil {
		return CompileReport{}, err
	}
	// This compiler owns only its new scratch directory; durable input/output
	// and approved Go caches belong to the node adapter and remain separate.
	defer func() { outcome = errors.Join(outcome, os.RemoveAll(job)) }()
	report = CompileReport{Schema: 1, Job: batch.Job, Tenant: batch.Tenant}
	totalOutput := uint64(0)
	for _, item := range batch.Items {
		if ctx.Err() != nil {
			return report, ctx.Err()
		}
		key := hex.EncodeToString(item.Key[:])
		work := filepath.Join(job, key)
		if err := os.Mkdir(work, 0700); err != nil {
			return report, err
		}
		root, err := os.OpenRoot(work)
		if err != nil {
			return report, err
		}
		err = SnapshotCompileItem(input, root, item)
		root.Close()
		if err != nil {
			return report, err
		}
		if err := os.Mkdir(filepath.Join(work, "tmp"), 0700); err != nil {
			return report, err
		}
		args := append([]string(nil), compileFlags...)
		binary := filepath.Join(work, "checker.cli")
		args = append(args, "-o", binary, "github.com/jay94ks/mydcd/checkercli")
		command := exec.CommandContext(ctx, filepath.Join(environment.GoRoot, "bin/go"), args...)
		command.Dir, command.Env = work, compilerEnvironment(environment, batch, work)
		diagnostic := &compileDiagnostic{remaining: MaxCompileDiagnosticBytes}
		command.Stdout, command.Stderr = diagnostic, diagnostic
		err = runCompilerCommand(ctx, command)
		result := CompileArtifact{Key: item.Key, Status: "failed", Reason: "compile-error"}
		if err == nil {
			remaining := batch.OutputBytes - totalOutput
			result, err = publishCompileArtifact(output, item, binary, min(batch.ArtifactBytes, remaining), batch.GOARCH)
			if err != nil {
				result = CompileArtifact{Key: item.Key, Status: "failed", Reason: "artifact-invalid"}
			} else {
				totalOutput += result.Length
			}
		}
		if diagnostic.data.Len() != 0 {
			file, e := output.OpenFile(key+".diagnostic", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
			if e != nil {
				return report, e
			}
			_, e = file.Write(diagnostic.data.Bytes())
			if e == nil {
				e = file.Sync()
			}
			file.Close()
			if e != nil {
				return report, e
			}
		}
		result.DiagnosticTruncated = diagnostic.truncated
		report.Items = append(report.Items, result)
		if err := os.RemoveAll(work); err != nil {
			return report, err
		}
	}
	encoded, err := json.Marshal(report)
	if err != nil {
		return report, err
	}
	f, err := output.OpenFile("report.json", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return report, err
	}
	_, err = f.Write(encoded)
	if err == nil {
		err = f.Sync()
	}
	f.Close()
	if err != nil {
		return report, err
	}
	dir, err := output.Open(".")
	if err != nil {
		return report, err
	}
	err = dir.Sync()
	dir.Close()
	if err != nil {
		return report, err
	}
	for _, result := range report.Items {
		if result.Status != "built" {
			return report, ErrSource
		}
	}
	return report, nil
}
