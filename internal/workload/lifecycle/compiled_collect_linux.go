// SPDX-License-Identifier: Apache-2.0

//go:build linux

package lifecycle

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"slices"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/reconcile"
	"github.com/jay94ks/mydcd/internal/schema"
	"github.com/jay94ks/mydcd/internal/storage"
)

// A known missing/structurally invalid closed output is a failed item. An OS
// read error is uncertainty and retains the original job/output for recovery.
func readCollectedFile(root *os.Root, name string, max int64) ([]byte, string, error) {
	info, err := root.Lstat(name)
	if os.IsNotExist(err) {
		return nil, "missing", nil
	}
	if err != nil {
		return nil, "", err
	}
	if !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > max {
		return nil, "invalid", nil
	}
	data, err := readCompileFile(root, name, max)
	return data, "", err
}

// collectionWitness reads the SAME durable original native owner record. No
// recursive CompilerOwner lock is taken while its collector callback runs.
func (m *SourceStore) collectionWitness(o CompilerOutput) error {
	if o.Root == nil || o.Intent.Validate() != nil || o.Intent.Cluster != m.identity.Cluster || o.Intent.Owner != m.identity.Node || o.Policy.Validate() != nil || o.Policy.Tenant != o.Intent.Tenant || o.Policy.Revision != o.Intent.Selection.PolicyRevision {
		return ErrSourceStore
	}
	raw, err := m.db.GetBounded(compilerRecordPrefix+compilerJobKey(o.Intent), maxCompilerRecordBytes)
	if err != nil {
		return err
	}
	r, err := schema.Decode[compilerDisk](raw)
	want, _ := json.Marshal(o.Policy)
	original, _ := json.Marshal(r.Policy)
	if err != nil || r.Schema != 1 || r.Intent.Digest() != o.Intent.Digest() || !bytes.Equal(want, original) || reconcile.Validate(r.State) != nil || r.State.Pending == nil || r.State.Pending.Kind != reconcile.Apply || r.State.Pending.Phase != reconcile.Dispatched && r.State.Pending.Phase != reconcile.RecoveryRequired || r.State.Desired.Spec != compilerSpec(o.Intent, o.Policy) || !r.CollectionDispatched || !r.Removed || !digest(r.NativeID) || !r.InputReady || r.WorkspaceClosed || r.Exited != o.ExitKnown || r.ExitCode != o.ExitCode {
		return ErrSourceStore
	}
	raw, err = m.db.GetBounded(compilerPrefix+"identity", 4096)
	if err != nil {
		return err
	}
	identity, err := schema.Decode[compilerOwnerIdentity](raw)
	if err != nil || identity.Schema != 1 || identity.Cluster != m.identity.Cluster || identity.Node != m.identity.Node {
		return ErrSourceStore
	}
	root, err := os.OpenRoot(identity.Path)
	if err != nil {
		return err
	}
	defer root.Close()
	info, err := root.Stat(".")
	if err != nil {
		return err
	}
	directory, err := directoryIdentity(info)
	if err != nil || directory != identity.Directory {
		return ErrSourceStore
	}
	info, err = root.Lstat(compilerJobPath(o.Intent))
	if err != nil {
		return err
	}
	directory, err = directoryIdentity(info)
	if err != nil || directory != r.Directory {
		return ErrSourceStore
	}
	expected, err := root.Stat(compilerJobPath(o.Intent) + "/output")
	if err != nil {
		return err
	}
	actual, err := o.Root.Stat(".")
	if err != nil || !os.SameFile(actual, expected) {
		return ErrSourceStore
	}
	raw, err = json.Marshal(o.Batch)
	if err != nil || sha256.Sum256(raw) != o.Intent.Manifest || o.Batch.Schema != 1 || o.Batch.Job != o.Intent.ID || o.Batch.Tenant != o.Intent.Tenant || o.Batch.GOOS+"/"+o.Batch.GOARCH != o.Intent.Target || len(o.Batch.Items) != len(o.Intent.Inputs) {
		return ErrSourceStore
	}
	image, err := access.PinImage(o.Policy.Build.Image)
	if err != nil || o.Batch.Toolchain != o.Policy.Build.Toolchain || !slices.Contains(o.Policy.Build.Targets, o.Intent.Target) || o.Batch.WorkspaceBytes > o.Policy.Build.WorkspaceBytes || o.Batch.ArtifactBytes > o.Policy.Build.ArtifactBytes || o.Batch.OutputBytes > min(o.Policy.CompiledCacheBytes, o.Policy.Build.WorkspaceBytes) {
		return ErrSourceStore
	}
	inputs := make([]BuildInput, 0, len(o.Batch.Items))
	for _, item := range o.Batch.Items {
		if item.Recipe.Validate() != nil || item.Recipe.Tenant != o.Intent.Tenant || item.Recipe.Image != image.Reference || item.Recipe.Toolchain != o.Batch.Toolchain || item.Recipe.GOOS != o.Batch.GOOS || item.Recipe.GOARCH != o.Batch.GOARCH || item.Key != item.Recipe.Key() || item.Source.Validate() != nil || item.Source.ContentDigest() != item.Recipe.Source {
			return ErrSourceStore
		}
		inputs = append(inputs, BuildInput{item.Recipe.Source, item.Key})
	}
	slices.SortFunc(inputs, func(a, b BuildInput) int { return bytes.Compare(a.Content[:], b.Content[:]) })
	if !slices.Equal(inputs, o.Intent.Inputs) {
		return ErrSourceStore
	}
	return nil
}

// CollectCompiled persists verified individual cache entries and one original
// signed collection receipt. Invalid/failed items remain explicit failures;
// partial success never invents an artifact or clears an uncertain DB write.
func (m *SourceStore) CollectCompiled(ctx context.Context, o CompilerOutput) ([32]byte, error) {
	if ctx == nil {
		return [32]byte{}, ErrSourceStore
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return [32]byte{}, ErrSourceStore
	}
	if err := ctx.Err(); err != nil {
		return [32]byte{}, err
	}
	if o.Recover {
		if err := m.recover(); err != nil {
			return [32]byte{}, err
		}
		m.uncertain = false
	} else if m.uncertain {
		return [32]byte{}, ErrSourceUncertain
	}
	if err := m.collectionWitness(o); err != nil {
		return [32]byte{}, err
	}
	old, err := m.readCollection(o.Intent.Tenant, o.Intent.Digest(), true)
	if err == nil {
		if old.ID != o.Intent.ID || old.Manifest != o.Intent.Manifest || old.ExitKnown != o.ExitKnown || old.ExitCode != o.ExitCode {
			return [32]byte{}, ErrCompiledConflict
		}
		return old.Digest(), nil
	}
	if !errors.Is(err, storage.ErrMissing) || errors.Is(err, ErrSourceStore) {
		return [32]byte{}, err
	}
	usage, err := m.cacheUsage(o.Intent.Tenant)
	if err != nil {
		return [32]byte{}, err
	}
	if usage.collections >= maxBuildJobs {
		return [32]byte{}, ErrCompiledCapacity
	}
	c := CompiledCollection{Schema: 1, Cluster: m.identity.Cluster, Owner: m.identity.Node, Job: o.Intent.Digest(), Manifest: o.Intent.Manifest, Tenant: o.Intent.Tenant, ID: o.Intent.ID, ExitKnown: o.ExitKnown, ExitCode: o.ExitCode}
	raw, problem, readErr := readCollectedFile(o.Root, "report.json", MaxCompiledCollectionBytes)
	if readErr != nil {
		return [32]byte{}, readErr
	}
	reason := "report-missing"
	var report CompileReport
	if problem == "" {
		c.Report = sha256.Sum256(raw)
		report, err = schema.Decode[CompileReport](raw)
		if err != nil || report.Validate(o.Batch) != nil {
			reason = "report-invalid"
		} else {
			reason = ""
		}
	} else if problem == "invalid" {
		reason = "report-invalid"
	}
	clear(raw)
	diagnostics := map[string][]byte{}
	defer func() {
		for _, data := range diagnostics {
			clear(data)
		}
	}()
	diagnosticBytes := uint64(0)
	used := usage.compiled
	remaining := uint64(0)
	if used < o.Policy.CompiledCacheBytes {
		remaining = o.Policy.CompiledCacheBytes - used
	}
	for i, item := range o.Batch.Items {
		entry := CompiledCollectionItem{Key: item.Key, Status: "failed", Reason: reason}
		if reason == "" {
			entry.Reason = report.Items[i].Reason
			if report.Items[i].Status == "built" {
				entry.Reason = "cache-limit"
			}
		}
		name := hex.EncodeToString(item.Key[:]) + ".diagnostic"
		data, problem, err := readCollectedFile(o.Root, name, 64<<10)
		if err != nil {
			return [32]byte{}, err
		}
		if problem == "" {
			entry.Diagnostic.Length = uint64(len(data))
			entry.Diagnostic.Original = sha256.Sum256(data)
			n := min(uint64(len(data)), remaining)
			if usage.diagnostics+uint64(len(diagnostics)) >= maxCompiledEntries {
				n = 0
			}
			if n > 0 {
				entry.Diagnostic.StoredBytes = n
				entry.Diagnostic.Stored = sha256.Sum256(data[:n])
				diagnostics[compiledDiagnosticPrefix+compiledDiagnosticKey(c.Tenant, c.Job, item.Key)] = bytes.Clone(data[:n])
				diagnosticBytes += n
				remaining -= n
			}
			entry.Diagnostic.Truncated = n < uint64(len(data))
			clear(data)
		} else if problem == "invalid" || reason == "" && report.Items[i].DiagnosticTruncated {
			entry.Reason = "diagnostic-invalid"
		}
		if reason == "" && report.Items[i].DiagnosticTruncated {
			entry.Diagnostic.Truncated = true
		}
		c.Items = append(c.Items, entry)
	}
	for i, item := range o.Batch.Items {
		if err := ctx.Err(); err != nil {
			return [32]byte{}, err
		}
		if reason != "" || c.Items[i].Reason == "diagnostic-invalid" || report.Items[i].Status != "built" {
			continue
		}
		result := report.Items[i]
		name := hex.EncodeToString(item.Key[:]) + ".cli"
		data, problem, err := readCollectedFile(o.Root, name, int64(result.Length))
		if err != nil {
			return [32]byte{}, err
		}
		if problem != "" || uint64(len(data)) != result.Length || sha256.Sum256(data) != result.Digest || verifyCompileELF(bytes.NewReader(data), item.Recipe.GOARCH) != nil {
			clear(data)
			c.Items[i].Reason = "artifact-invalid"
			continue
		}
		build := CompiledBuild{Schema: 1, Cluster: m.identity.Cluster, Builder: m.identity.Node, Job: c.Job, ID: c.ID, Recipe: item.Recipe, Digest: result.Digest, Length: result.Length}
		build.Signature = ed25519.Sign(m.private, CompiledBuildBytes(build))
		fact, err := m.stageCompiled(ctx, item.Source, o.Policy, build, data, diagnosticBytes)
		clear(data)
		if errors.Is(err, ErrCompiledCapacity) {
			c.Items[i].Reason = "cache-limit"
			continue
		}
		if errors.Is(err, ErrCompiledConflict) {
			c.Items[i].Reason = "cache-conflict"
			continue
		}
		if err != nil {
			return [32]byte{}, err
		}
		c.Items[i].Status, c.Items[i].Reason, c.Items[i].Cached = "cached", "verified", fact.Digest()
	}
	c.Outcome = collectionOutcome(c)
	c.Signature = ed25519.Sign(m.private, CompiledCollectionBytes(c))
	raw, err = json.Marshal(c)
	if err != nil || c.Verify() != nil {
		return [32]byte{}, ErrSourceStore
	}
	if err := ctx.Err(); err != nil {
		return [32]byte{}, err
	}
	// Receipt metadata is finite original job history, not an executable cache
	// entry. Binary/fact/private diagnostic bytes consume the tenant cache quota.
	diagnostics[collectionMetaPrefix+compiledCollectionKey(c.Tenant, c.Job)] = raw
	if err := m.db.Write(diagnostics); err != nil {
		m.uncertain = true
		return [32]byte{}, errors.Join(ErrSourceUncertain, err)
	}
	m.compiledBytes[c.Tenant] += diagnosticBytes
	m.compiledDiagnostics += len(diagnostics) - 1
	m.collections[compiledCollectionKey(c.Tenant, c.Job)] = c.Digest()
	return c.Digest(), nil
}

// Compact committed hashes bind remote provenance even if an old builder key
// can later sign new bytes. Read only the exact collector's durable metadata;
// physical availability is checked again at actual cache read/transfer/exec.
func (m *CompilerOwner) collectedArtifacts(r compilerDisk, digest [32]byte) ([]BuildArtifact, error) {
	raw, err := m.db.GetBounded(collectionMetaPrefix+compiledCollectionKey(r.Intent.Tenant, r.Intent.Digest()), MaxCompiledCollectionBytes)
	if err != nil {
		return nil, err
	}
	c, err := schema.Decode[CompiledCollection](raw)
	if err != nil || c.Verify() != nil || c.Digest() != digest || c.Cluster != m.identity.Cluster || c.Owner != m.identity.Node || c.Tenant != r.Intent.Tenant || c.ID != r.Intent.ID || c.Job != r.Intent.Digest() || c.Manifest != r.Intent.Manifest {
		return nil, ErrCompilerOwner
	}
	var artifacts []BuildArtifact
	for _, item := range c.Items {
		if item.Status != "cached" {
			continue
		}
		raw, err := m.db.GetBounded(compiledMetaPrefix+compiledObjectKey(c.Tenant, item.Key), MaxCompiledFactBytes)
		if err != nil {
			return nil, err
		}
		f, err := schema.Decode[CompiledFact](raw)
		if err != nil || f.Verify() != nil || f.Owner != m.identity.Node || f.Build.Cluster != m.identity.Cluster || f.Build.Recipe.Tenant != c.Tenant || f.Digest() != item.Cached || f.Build.Recipe.Key() != item.Key {
			return nil, ErrCompilerOwner
		}
		artifacts = append(artifacts, BuildArtifact{Key: item.Key, Digest: f.Build.Digest, Length: f.Build.Length})
	}
	if validateBuildArtifacts(r.Intent, artifacts) != nil {
		return nil, ErrCompilerOwner
	}
	return artifacts, nil
}
