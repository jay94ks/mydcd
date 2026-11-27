// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/imagebuild"
	"github.com/jay94ks/seafield/internal/reconcile"
)

type imageBuildOriginal struct {
	spec   imagebuild.JobSpec
	closed bool
}
type imageBuildFinished struct {
	job            [32]byte
	action         string
	err            error
	prune          *imagebuild.NativeCachePruneSpec
	gitWatch       string
	cacheAutomatic [32]byte
}
type imageBuildPruneOriginal struct {
	spec   imagebuild.NativeCachePruneSpec
	closed bool
}

// A cleanup wait must not hide the error that caused it. errors.Is alone also
// matches errors.Join(primaryFailure, ErrPending), which is a real failure.
func imageBuildOnlyPending(err error) bool {
	if err == reconcile.ErrPending {
		return true
	}
	if many, ok := err.(interface{ Unwrap() []error }); ok {
		children := many.Unwrap()
		if len(children) == 0 {
			return false
		}
		for _, child := range children {
			if !imageBuildOnlyPending(child) {
				return false
			}
		}
		return true
	}
	if one, ok := err.(interface{ Unwrap() error }); ok {
		return imageBuildOnlyPending(one.Unwrap())
	}
	return false
}

// One preparing queued job avoids a burst of unreserved source work. As soon
// as its shared begin reserves the configured budget, further jobs can start.
// All running jobs remain distinct finite workers in this same daemon.
func (r *Runtime) imageBuildLoop() {
	var workers sync.WaitGroup
	defer func() { workers.Wait(); r.imageBuildShutdownError = r.shutdownImageBuildCachePrunes() }()
	active := map[[32]byte]bool{}
	known := map[[32]byte]imageBuildOriginal{}
	knownPrunes := map[[32]byte]imageBuildPruneOriginal{}
	retry := map[[32]byte]time.Time{}
	pruned := map[[32]byte]bool{}
	var preparing [32]byte
	var watching string
	watchNext := map[string]time.Time{}
	automaticNext := map[[32]byte]time.Time{}
	var automaticActive [32]byte
	var automaticGC time.Time
	finished := make(chan imageBuildFinished)
	records, scanErr := r.imageBuildNative.Records()
	if scanErr != nil {
		r.setImageBuildError(scanErr)
	}
	for _, record := range records {
		known[record.Spec.Digest()] = imageBuildOriginal{record.Spec, record.Completion != nil}
	}
	records = nil
	maintenance, maintenanceErr := r.imageBuildNative.CachePruneRecords()
	scanErr = errors.Join(scanErr, maintenanceErr)
	for _, record := range maintenance {
		knownPrunes[record.Spec.Intent] = imageBuildPruneOriginal{record.Spec, record.Completion != nil}
	}
	maintenance = nil
	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()
	var book control.ImageBuildCatalog
	var index uint64
	loaded := false
	failures := map[[32]byte]error{}
	for {
		if r.ctx.Err() != nil {
			return
		}
		changed := r.Engine().Changes()
		view, err := r.Engine().Read(r.ctx, false)
		if err == nil && (!loaded || view.State.Object(control.ImageBuildKey).Revision != index) {
			var current control.ImageBuildCatalog
			current, err = r.controlPolicy.ImageBuilds(view.State)
			if err == nil {
				book, index, loaded = current, view.State.Object(control.ImageBuildKey).Revision, true
			}
		}
		eligibleWatches := map[string]control.ImageBuildContextRecord{}
		for _, row := range book.Contexts {
			if !row.Deleted && row.Spec.Root.Key == r.Identity.Public && row.Spec.Git != nil && row.Spec.Git.Automatic {
				eligibleWatches[row.Spec.Tenant+"/"+row.Spec.ID] = row
			}
		}
		for key := range watchNext {
			if _, eligible := eligibleWatches[key]; !eligible {
				delete(watchNext, key)
				delete(failures, imageBuildGitWatchID(key))
			}
		}
		var jobError error
		var first [32]byte
		for hash, failure := range failures {
			if jobError == nil || string(hash[:]) < string(first[:]) {
				jobError = failure
				first = hash
			}
		}
		if len(failures) > 1 {
			jobError = fmt.Errorf("%w (%d other build errors)", jobError, len(failures)-1)
		}
		r.setImageBuildError(errors.Join(scanErr, err, jobError))
		if err == nil {
			if view.State.Index() > 0 && time.Now().After(automaticGC) {
				keep := map[[32]byte]bool{}
				for _, row := range book.CachePrunes {
					keep[row.Digest()] = true
				}
				removed, cause := r.imageBuildNative.CollectClosedAutomaticCachePrunes(view.State.Index(), keep)
				gcID := imageBuildCacheAutomaticWorkerID([32]byte{})
				if cause != nil {
					failures[gcID] = cause
				} else {
					delete(failures, gcID)
				}
				for _, id := range removed {
					delete(knownPrunes, id)
					delete(retry, id)
					delete(failures, id)
				}
				automaticGC = time.Now().Add(time.Minute)
			}
			if automaticActive == ([32]byte{}) {
				if spec, cache := imageBuildCacheAutomaticCandidate(book, r.Identity.Public, automaticNext, time.Now()); cache != ([32]byte{}) {
					automaticActive = cache
					workers.Add(1)
					go func() {
						defer workers.Done()
						ctx, cancel := context.WithTimeout(r.ctx, 10*time.Second)
						defer cancel()
						cause := r.submitImageBuildCacheAutomatic(ctx, spec)
						select {
						case finished <- imageBuildFinished{job: imageBuildCacheAutomaticWorkerID(cache), action: "cache-automatic", cacheAutomatic: cache, err: cause}:
						case <-r.ctx.Done():
						}
					}()
				}
			}
			if watching == "" {
				// One finite source reader shares this daemon's worker lifetime.
				// Oldest-due selection prevents slow early contexts from starving
				// the rest and never blocks build workers on a source fetch.
				if key, row := imageBuildGitWatchCandidate(eligibleWatches, watchNext, time.Now()); key != "" {
					watching = key
					watchNext[key] = time.Now().Add(time.Minute)
					workers.Add(1)
					go func(tenant, id, key string) {
						defer workers.Done()
						failure := r.observeImageBuildGit(r.ctx, tenant, id)
						select {
						case finished <- imageBuildFinished{job: imageBuildGitWatchID(key), action: "git-watch", gitWatch: key, err: failure}:
						case <-r.ctx.Done():
						}
					}(row.Spec.Tenant, row.Spec.ID, key)
				}
			}
			byHash := map[[32]byte]control.ImageBuildJobRecord{}
			var rows []control.ImageBuildJobRecord
			for _, row := range book.Jobs {
				if row.Run.Spec.Scope.Root.Key != r.Identity.Public {
					continue
				}
				hash := row.Run.Spec.Digest()
				byHash[hash] = row
				if hash == preparing && row.Run.Phase != "queued" {
					preparing = [32]byte{}
				}
				original, retained := known[hash]
				if row.Run.Terminal() && !row.Deleted && (!retained || original.closed) {
					continue
				}
				if row.Deleted && (!retained || pruned[hash]) {
					continue
				}
				rows = append(rows, row)
			}
			sort.Slice(rows, func(i, j int) bool {
				a, b := rows[i].Run.Spec, rows[j].Run.Spec
				if a.CreatedAt != b.CreatedAt {
					return a.CreatedAt < b.CreatedAt
				}
				if a.Tenant != b.Tenant {
					return a.Tenant < b.Tenant
				}
				return a.ID < b.ID
			})
			start := func(spec imagebuild.JobSpec, action string) {
				hash := spec.Digest()
				active[hash] = true
				workers.Add(1)
				go func() {
					defer workers.Done()
					var err error
					switch action {
					case "prune":
						err = r.pruneImageBuildLogs(r.ctx, r.imageBuildNative, spec)
					case "orphan":
						if record, cause := r.imageBuildNative.Record(spec); cause == nil && record.Outcome == nil && record.Publication == nil {
							err = r.imageBuildNative.RecordOutcome(spec, imagebuild.JobResult{Code: "BUILD_FAILED"})
						}
						if err == nil {
							err = r.closeImageBuildNative(spec)
						}
					default:
						err = r.consumeImageBuildJob(r.ctx, spec)
					}
					select {
					case finished <- imageBuildFinished{job: hash, action: action, err: err}:
					case <-r.ctx.Done():
					}
				}()
			}
			for _, row := range rows {
				spec := row.Run.Spec
				hash := spec.Digest()
				if active[hash] || time.Now().Before(retry[hash]) {
					continue
				}
				if row.Deleted {
					if known[hash].closed {
						start(spec, "prune")
					}
					continue
				}
				if row.Run.Phase == "queued" {
					if book.CachePruneBlocks(imagebuild.CacheIdentity(spec), row.SubmissionRootRevision()) {
						continue
					}
					if preparing != ([32]byte{}) {
						continue
					}
					preparing = hash
				}
				start(spec, "run")
			}
			for hash, original := range known {
				if _, present := byHash[hash]; present || original.closed || active[hash] || time.Now().Before(retry[hash]) {
					continue
				}
				start(original.spec, "orphan")
			}
			// Maintenance shares this scheduler/lifetime and its final worker
			// join. Only per-intent finite consumers run; no extra daemon loop.
			startPrune := func(spec imagebuild.NativeCachePruneSpec, orphan bool) {
				hash := spec.Intent
				active[hash] = true
				workers.Add(1)
				go func() {
					defer workers.Done()
					action := "cache-prune"
					var cause error
					if orphan {
						action = "cache-prune-unmapped"
						// Local absence is not a committed deletion. Stop only
						// the known native; retain files/cache owner/original result.
						cleanup, cancel := context.WithTimeout(context.Background(), 30*time.Second)
						cause = errors.Join(imagebuild.ErrStorage, r.imageBuildNative.StopCachePrune(cleanup, spec, nil, true))
						cancel()

					} else {
						cause = r.consumeImageBuildCachePrune(r.ctx, spec)
					}
					select {
					case finished <- imageBuildFinished{job: hash, action: action, err: cause, prune: &spec}:
					case <-r.ctx.Done():
					}
				}()
			}
			presentPrunes := map[[32]byte]bool{}
			for _, row := range book.CachePrunes {
				change, cause := row.Change()
				if cause != nil {
					continue
				}
				source, found := book.Job(change.Tenant, row.Source)
				if !found || source.Run.Spec.Scope.Root.Key != r.Identity.Public {
					continue
				}
				spec, cause := row.NativeSpec(source.Run.Spec)
				if cause != nil {
					continue
				}
				hash := spec.Intent
				presentPrunes[hash] = true
				original, retained := knownPrunes[hash]
				if !row.Pending() && (!retained || original.closed) || active[hash] || time.Now().Before(retry[hash]) {
					continue
				}
				startPrune(spec, false)
			}
			for hash, original := range knownPrunes {
				if !presentPrunes[hash] && !original.closed && !active[hash] && !time.Now().Before(retry[hash]) {
					startPrune(original.spec, true)
				}
			}
		}
		select {
		case <-r.ctx.Done():
			return
		case result := <-finished:
			if result.cacheAutomatic != ([32]byte{}) {
				automaticActive = [32]byte{}
				automaticNext[result.cacheAutomatic] = time.Now().Add(time.Minute)
				if result.err != nil {
					failures[result.job] = result.err
				} else {
					delete(failures, result.job)
				}
				continue
			}
			if result.gitWatch != "" {
				watching = ""
				if _, eligible := eligibleWatches[result.gitWatch]; eligible {
					watchNext[result.gitWatch] = time.Now().Add(time.Minute)
					if result.err != nil {
						failures[result.job] = fmt.Errorf("image build Git source %s: %w", result.gitWatch, result.err)
					} else {
						delete(failures, result.job)
					}
				}
				continue
			}
			delete(active, result.job)
			if preparing == result.job {
				preparing = [32]byte{}
			}
			retry[result.job] = time.Now().Add(2 * time.Second)
			if result.err == nil {
				delete(failures, result.job)
				if result.action == "prune" {
					pruned[result.job] = true
				}
				if result.action == "orphan" {
					original := known[result.job]
					original.closed = true
					known[result.job] = original
				}
			} else if !imageBuildOnlyPending(result.err) {
				failures[result.job] = fmt.Errorf("image build %x: %w", result.job[:8], result.err)
			}
			if result.prune != nil {
				if record, err := r.imageBuildNative.CachePruneRecord(*result.prune); err == nil {
					knownPrunes[result.job] = imageBuildPruneOriginal{record.Spec, record.Completion != nil}
				}
				continue
			}
			for _, row := range book.Jobs {
				if row.Run.Spec.Digest() != result.job {
					continue
				}
				if record, err := r.imageBuildNative.Record(row.Run.Spec); err == nil {
					known[result.job] = imageBuildOriginal{record.Spec, record.Completion != nil}
				}
				break
			}
		case <-tick.C:
		case <-changed:
		}
	}
}

func (r *Runtime) setImageBuildError(err error) {
	r.mu.Lock()
	if r.imageBuildError == nil && err == nil || r.imageBuildError != nil && err != nil && r.imageBuildError.Error() == err.Error() {
		r.mu.Unlock()
		return
	}
	r.imageBuildError = err
	r.mu.Unlock()
	r.wakeReport()
}
