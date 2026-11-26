// SPDX-License-Identifier: Apache-2.0

package imagebuild

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"slices"
	"strings"

	"github.com/containerd/containerd/v2/core/content"
	"github.com/jay94ks/mydcd/internal/containerops"
	"github.com/jay94ks/mydcd/internal/engine"
	bkclient "github.com/moby/buildkit/client"
	"github.com/moby/buildkit/session"
	bksecrets "github.com/moby/buildkit/session/secrets"
	"github.com/moby/buildkit/session/secrets/secretsprovider"
	spb "github.com/moby/buildkit/sourcepolicy/pb"
	"github.com/moby/moby/client"
	"github.com/tonistiigi/fsutil"
)

// NativeSolveSession owns the SDK session and all its file/auth/log callbacks.
// Close cancels and joins them before native daemon Stop or workspace return.
type NativeSolveSession struct {
	done   chan struct{}
	cancel context.CancelFunc
	err    error
}

func buildKitCompatible(info *bkclient.Info) bool {
	return info != nil && info.BuildkitVersion.Package == "github.com/moby/buildkit" && strings.TrimPrefix(info.BuildkitVersion.Version, "v") == "0.35.1"
}

func (s *NativeSolveSession) Done() <-chan struct{} { return s.done }
func (s *NativeSolveSession) Wait() error           { <-s.done; return s.err }
func (s *NativeSolveSession) Close() error          { s.cancel(); return s.Wait() }

type buildKitSecretStore struct {
	store bksecrets.SecretStore
	auth  *BuildKitPullAuth
}

func (s buildKitSecretStore) GetSecret(ctx context.Context, id string) ([]byte, error) {
	if s.auth.authorize(ctx) != nil {
		return nil, ErrConflict
	}
	value, err := s.store.GetSecret(ctx, id)
	if err != nil {
		return nil, ErrSourceFetch
	}
	if s.auth.authorize(ctx) != nil {
		clear(value)
		return nil, ErrConflict
	}
	return value, nil
}

func buildKitSolveOptions(ctx context.Context, spec JobSpec, inputs []FrozenSource, input, contextDir, output *os.File, auth *BuildKitPullAuth, sourceContent bool) (options bkclient.SolveOpt, failure error) {
	policyBytes, err := SourcePolicy(inputs)
	if err != nil {
		return bkclient.SolveOpt{}, err
	}
	policy := &spb.Policy{}
	if json.Unmarshal(policyBytes, policy) != nil {
		return bkclient.SolveOpt{}, ErrInvalid
	}
	var stores map[string]content.Store
	defer func() {
		if failure != nil {
			failure = errors.Join(failure, closeSourceStores(stores))
		}
	}()
	if sourceContent {
		if auth.contentRead == nil || !slices.Equal(auth.inputs, inputs) {
			return bkclient.SolveOpt{}, ErrSourceFetch
		}
		converted, err := sourceContentPolicy(inputs)
		if err != nil {
			return bkclient.SolveOpt{}, err
		}
		policy = converted
		stores = map[string]content.Store{}
		for _, frozen := range inputs {
			key := sourceContentStoreID(frozen.Image)
			if stores[key] == nil {
				stores[key] = newBuildKitSourceStore(ctx, frozen, auth.authorize, auth.contentRead, func() (*os.File, error) { return sourceTemporaryFile(output) }, auth.contentFailure)
			}
		}
	}
	contextFS, err := fsutil.NewFS(fmt.Sprintf("/proc/self/fd/%d", contextDir.Fd()))
	if err != nil {
		return bkclient.SolveOpt{}, ErrStorage
	}
	var secretFiles []secretsprovider.Source
	for _, secret := range spec.Context.Secrets {
		secretFiles = append(secretFiles, secretsprovider.Source{ID: secret.ID, FilePath: fmt.Sprintf("/proc/self/fd/%d/secrets/%s", input.Fd(), secret.ID)})
	}
	store, err := secretsprovider.NewStore(secretFiles)
	if err != nil {
		return bkclient.SolveOpt{}, ErrSourceFetch
	}
	attrs := map[string]string{"filename": spec.Scope.Dockerfile, "platform": strings.Join(spec.Context.Platforms, ",")}
	for key, value := range spec.Context.Arguments {
		attrs["build-arg:"+key] = value
	}
	digest := spec.Digest()
	return bkclient.SolveOpt{Ref: hex.EncodeToString(digest[:]), Frontend: "dockerfile.v0", FrontendAttrs: attrs, LocalMounts: map[string]fsutil.FS{"context": contextFS, "dockerfile": contextFS}, SourcePolicy: policy, OCIStores: stores,
		Session: []session.Attachable{auth, secretsprovider.NewSecretProvider(buildKitSecretStore{store, auth})},
		Exports: []bkclient.ExportEntry{{Type: bkclient.ExporterOCI, Attrs: map[string]string{"tar": "false"}, OutputDir: fmt.Sprintf("/proc/self/fd/%d", output.Fd())}}}, nil
}

// StartSolve sends one SDK Solve to the original finite daemon's private local
// socket. Read-only readiness probes may repeat before Sent; Solve never does.
// The caller owns auth/filter until this handle has joined (including failure).
func (n *NativeJobs) StartSolve(ctx context.Context, spec JobSpec, auth *BuildKitPullAuth, filter *containerops.Redactor) (*NativeSolveSession, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if auth == nil || filter == nil {
		return nil, ErrInvalid
	}
	r, err := n.load(spec)
	if err != nil {
		return nil, err
	}
	grant, err := n.current(ctx, &r, false)
	if err != nil {
		return nil, err
	}
	job := spec.Digest()
	if r.Solve == nil || r.Solve.Sent || r.Solve.Stopping || !r.StartSent || r.Cancel || r.Removed || n.solving[job] {
		return nil, ErrConflict
	}
	files, err := n.openWorkspace(r)
	if err != nil {
		return nil, err
	}
	fail := func(err error) (*NativeSolveSession, error) { return nil, errors.Join(err, files.Close()) }
	plan, err := PlanNative(spec, n.docker.Owner)
	if err != nil {
		return fail(err)
	}
	got, err := n.docker.API.ContainerInspect(ctx, r.NativeID, client.ContainerInspectOptions{})
	if err != nil {
		return fail(nativeFailure(ctx))
	}
	if !matchNativeContainer(got.Container, r, plan) || !got.Container.State.Running {
		return fail(engine.ErrOwnership)
	}
	sdk, err := openBuildKitClient(ctx, files.leaves[1])
	if err != nil {
		return fail(err)
	}

	contextDir, _, err := openNativeDirectory(int(files.leaves[0].Fd()), "context")
	if err != nil {
		_ = sdk.Close()
		return fail(ErrStorage)
	}
	closeFiles := func() error { return errors.Join(contextDir.Close(), files.Close()) }
	if r.Solve.Directory == (NativeDirectory{}) {
		r.Solve.Directory, err = prepareNativeDirectory(int(files.leaves[1].Fd()), "image", NativeDirectory{}, os.Geteuid(), os.Getegid(), 0700)
		if err == nil {
			err = n.save(r)
		}
	}
	if err != nil {
		_ = sdk.Close()
		return nil, errors.Join(ErrStorage, closeFiles())
	}
	output, st, err := openNativeDirectory(int(files.leaves[1].Fd()), "image")
	if err != nil || nativeDirectory(st) != r.Solve.Directory {
		if output != nil {
			_ = output.Close()
		}
		_ = sdk.Close()
		return nil, errors.Join(ErrStorage, closeFiles())
	}
	options, err := buildKitSolveOptions(ctx, spec, grant.Run.Inputs, files.leaves[0], contextDir, output, auth, r.Solve.SourceContent)
	if err != nil {
		_ = output.Close()
		_ = sdk.Close()
		return nil, errors.Join(err, closeFiles())
	}
	if _, err := n.current(ctx, &r, false); err != nil {
		_ = closeSourceStores(options.OCIStores)
		_ = output.Close()
		_ = sdk.Close()
		return nil, errors.Join(err, closeFiles())
	}
	r.Solve.Sent = true
	if err := n.save(r); err != nil {
		_ = closeSourceStores(options.OCIStores)
		_ = output.Close()
		_ = sdk.Close()
		return nil, errors.Join(err, closeFiles())
	}
	solveCtx, cancel := context.WithCancel(ctx)
	handle := &NativeSolveSession{done: make(chan struct{}), cancel: cancel}
	n.solving[job] = true
	n.readers[job]++
	go func() {
		defer close(handle.done)
		defer cancel()
		status := make(chan *bkclient.SolveStatus, 16)
		logsDone := make(chan error, 1)
		go func() {
			logsDone <- writeBuildKitProgress(status, filter, cancel)
		}()
		response, solveErr := sdk.Solve(solveCtx, nil, options, status)
		sourceErr := closeSourceStores(options.OCIStores)
		logErr := <-logsDone
		// Fix the solve outcome before optional observation/prune work. A
		// later cleanup deadline must not retroactively fail this solve.
		solveContextErr := solveCtx.Err()
		cacheErr := n.maintainCache(solveCtx, spec, sdk)
		closeErr := errors.Join(sourceErr, sdk.Close(), output.Close(), closeFiles())
		var gapErr error
		if solveContextErr != nil {
			gapErr = n.MarkLogGap(spec)
		}
		code := "OK"
		if solveErr != nil || response == nil {
			code = "BUILD_FAILED"
			if auth.SourceFailed() {
				code = "SOURCE_FETCH"
			}
		}
		if errors.Is(solveContextErr, context.DeadlineExceeded) {
			code = "TIMEOUT"
		}
		if auth.contentStorageFailed.Load() {
			code = "STORAGE_UNAVAILABLE"
		}
		if logErr != nil || closeErr != nil || gapErr != nil {
			code = "STORAGE_UNAVAILABLE"
		}
		n.mu.Lock()
		defer n.mu.Unlock()
		delete(n.solving, job)
		if closeErr == nil {
			n.readers[job]--
			if n.readers[job] == 0 {
				delete(n.readers, job)
			}
		}
		latest, err := n.load(spec)
		if err == nil && latest.Solve != nil && latest.Solve.Sent && !latest.Solve.Returned {
			latest.Solve.Returned, latest.Solve.Code = true, code
			err = n.save(latest)
		}
		if err != nil || closeErr != nil || gapErr != nil || cacheErr != nil {
			handle.err = ErrStorage
		} else if code != "OK" {
			handle.err = ErrConflict // raw SDK/registry errors are never retained
		}
	}()
	return handle, nil
}

func closeSourceStores(stores map[string]content.Store) error {
	var failure error
	for _, store := range stores {
		if closer, ok := store.(io.Closer); ok {
			failure = errors.Join(failure, closer.Close())
		}
	}
	return failure
}

var buildKitExit = regexp.MustCompile(`did not complete successfully: exit code: ([0-9]{1,3})$`)

// buildKitExitCode reads only the exit status of a failed RUN step. The rest
// of a vertex error can carry opaque registry or credential bodies and is
// never written; the step's own output is already in the log.
func buildKitExitCode(vertexError string) (string, bool) {
	m := buildKitExit.FindStringSubmatch(vertexError)
	if m == nil {
		return "", false
	}
	return m[1], true
}

// Retain independent prefix state for each actual SDK vertex/stream; status
// names are complete fields. Raw opaque error bodies/warnings are not logged.
func writeBuildKitProgress(status <-chan *bkclient.SolveStatus, parent *containerops.Redactor, cancel context.CancelFunc) (failure error) {
	streams := map[string]*containerops.Redactor{}
	defer func() {
		for _, stream := range streams {
			stream.Destroy()
		}
	}()
	type step struct {
		name string
		done bool
	}
	steps := map[string]step{}
	for update := range status {
		if update == nil || failure != nil {
			continue
		}
		for _, vertex := range update.Vertexes {
			if vertex == nil || vertex.Name == "" {
				continue
			}
			key := vertex.Digest.String()
			state, exists := steps[key]
			var err error
			if !exists {
				state.name, err = parent.RedactString(vertex.Name)
				if err == nil {
					_, err = parent.Write([]byte("# " + state.name + "\n"))
				}
			}
			if err == nil && !state.done && (vertex.Completed != nil || vertex.Error != "") {
				phase := "completed"
				if vertex.Cached {
					phase = "cached"
				}
				if vertex.Error != "" {
					phase = "failed"
				}
				line := "# " + phase + " " + state.name
				if code, ok := buildKitExitCode(vertex.Error); ok {
					line += " (exit code " + code + ")"
				}
				_, err = parent.Write([]byte(line + "\n"))
				state.done = true
			}
			steps[key] = state
			if err != nil {
				failure = ErrStorage
				cancel()
				break
			}
		}
		for _, log := range update.Logs {
			if log == nil || len(log.Data) == 0 || failure != nil {
				continue
			}
			key := fmt.Sprintf("%s/%d", log.Vertex, log.Stream)
			stream := streams[key]
			if stream == nil {
				var err error
				stream, err = parent.BorrowStream()
				if err != nil {
					failure = ErrStorage
					cancel()
					break
				}
				streams[key] = stream
			}
			if _, err := stream.Write(log.Data); err != nil {
				failure = ErrStorage
				cancel()
				break
			}
		}
	}
	if failure == nil {
		for _, stream := range streams {
			if stream.Finish() != nil {
				failure = ErrStorage
				break
			}
		}
		if parent.Finish() != nil {
			failure = ErrStorage
		}
	}
	return failure
}
