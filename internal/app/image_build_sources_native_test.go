// SPDX-License-Identifier: Apache-2.0

//go:build linux

package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jay94ks/mydcd/internal/cluster"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/imagebuild"
)

// File preparation is local CLI input only. All plan/edit/save/publication,
// accepted version/job and native outcomes below come from the live engine.
func imageBuildNativeJSON(t *testing.T, root, name string, value any) string {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(root, name+".json")
	if err = os.WriteFile(file, raw, 0600); err != nil {
		t.Fatal(err)
	}
	return file
}

func (f *managedRegistryNative) releaseImageBuildNative(t *testing.T, ctx context.Context, p control.Policy, read func() cluster.View, change func(string, string, uint64, any), job control.ImageBuildJobRecord, prefix string) {
	t.Helper()
	f.cli(nil, "registry", "delete-build-job", job.Run.Spec.ID, "--tenant", "tenant", "--request-id", prefix+"-delete-job")
	book, err := p.ImageBuilds(read().State)
	if err != nil {
		t.Fatal(err)
	}
	version, ok := book.Version("tenant", job.Run.Spec.Version)
	if !ok {
		t.Fatal("original source version missing at release")
	}
	change(prefix+"-delete-version", "delete-build-version", version.Number, control.ImageBuildVersionSelection{Tenant: "tenant", ID: version.ID})
	if job.Run.Closure.Result.Code == "OK" {
		digest := strings.SplitN(job.Run.Closure.Result.Image, "@", 2)[1]
		f.cli(nil, "registry", "delete-image", "private", "--tenant", "tenant", "--repository", "fixture", "--reference", digest, "--expected-digest", digest, "--request-id", prefix+"-delete-output")
		f.maintenanceNativeWait(t, ctx, p, read, prefix+"-delete-output", "done", "OK")
	}
}

func (f *managedRegistryNative) verifyImageBuildGitNative(t *testing.T, ctx context.Context, r *Runtime, root string, base imagebuild.ContextSpec, p control.Policy, read func() cluster.View, change func(string, string, uint64, any)) {
	t.Helper()
	if f.buildGit == nil {
		t.Fatal("Git fixture credential was not installed before runtime initialization")
	}
	const firstProof = "rq6-native-git-first"
	dockerfile := fmt.Sprintf("FROM %s\nCOPY --chmod=0444 context-proof /build-context-proof\nLABEL org.mydc.test.owner=%q\n", f.reference, f.public["Tag"])
	commit := f.buildGit.CommitFiles(map[string][]byte{"Dockerfile": []byte(dockerfile), "context-proof": []byte(firstProof)})
	spec := base.Own()
	spec.ID, spec.Kind, spec.Secrets, spec.Tags = "native-git", "git", nil, []string{"git-{commit}"}
	spec.Git = &imagebuild.GitContext{Repository: f.buildGit.Repository(), Ref: "refs/heads/main", Path: ".", CredentialProfile: "build-git"}
	change("rq6-native-git-context", "put-build-context", 0, control.ImageBuildContextPut{Spec: spec})
	f.buildGit.Mode("unauthorized")
	failed, diagnostic, denied := f.runCLI(nil, "registry", "check-context", spec.ID, "--tenant", "tenant")
	f.buildGit.Mode("")
	var failedCheck control.ImageBuildSourceResult
	var exit interface{ ExitCode() int }
	if !errors.As(denied, &exit) || exit.ExitCode() != 3 || json.Unmarshal(failed, &failedCheck) != nil || failedCheck.Code != "SOURCE_FETCH" || f.buildGit.Stats().Denied == 0 || bytes.Contains(failed, []byte("private-native-git-fixture-token")) || bytes.Contains(diagnostic, []byte("private-fixture-auth-detail")) {
		t.Fatal("actual Git authentication refusal was missing or disclosed provider detail")
	}
	var check control.ImageBuildSourceResult
	if err := json.Unmarshal(f.cli(nil, "registry", "check-context", spec.ID, "--tenant", "tenant"), &check); err != nil || check.Code != "OK" || check.Commit != commit || f.buildGit.Stats().Packs == 0 {
		t.Fatal("actual authenticated Git source check did not inspect the original commit", err)
	}
	var plan imagebuild.GitSavePlan
	if err := json.Unmarshal(f.cli(nil, "registry", "git-plan", spec.ID, "--tenant", "tenant", "--save-id", "rq6-native-git-save"), &plan); err != nil || plan.Commit != commit || plan.Tree != check.Tree {
		t.Fatal("Git save plan drifted from checked source", err)
	}
	planFile := imageBuildNativeJSON(t, root, "git-save-plan", plan)
	var document control.ChangeDocument
	if err := json.Unmarshal(f.cli(nil, "registry", "git-save", spec.ID, planFile, "--tenant", "tenant"), &document); err != nil || document.Action != "publish-build-git" {
		t.Fatal("Git native save did not produce creator publication input", err)
	}
	var publication control.ImageBuildGitPublish
	if err := json.Unmarshal(document.Payload, &publication); err != nil || !publication.Saved.Valid() || publication.Saved.Plan != plan {
		t.Fatal("original Git save owner evidence mismatch", err)
	}
	var saved imagebuild.GitSaveResponse
	if err := json.Unmarshal(f.cli(nil, "registry", "git-result", spec.ID, planFile, "--tenant", "tenant"), &saved); err != nil || saved.Code != "SAVED" || !reflect.DeepEqual(saved.Saved, &publication.Saved) {
		t.Fatal("Git result lookup changed original archive evidence", err)
	}
	publishFile := imageBuildNativeJSON(t, root, "git-publication", document)
	f.cli(nil, "--tenant", "tenant", "manage", "apply", "--change", publishFile, "--request-id", "rq6-native-git-publish")
	version := imagebuild.VersionID(publication.Saved.Fact)
	const jobID = "rq6-native-git-build"
	f.cli(nil, "registry", "build", spec.ID, hex.EncodeToString(version[:]), "--tenant", "tenant", "--job", jobID, "--request-id", "rq6-native-git-submit", "--no-input")
	first := f.waitImageBuildNative(t, ctx, r, p, read, jobID, "OK")
	if first.Run.Spec.Commit != commit || first.Automatic != nil {
		t.Fatal("manual Git job lost its original commit/source")
	}
	f.executeImageBuildResult(t, ctx, r, first.Run.Closure.Result.Image, "--build-context-result-fixture", firstProof)
	f.releaseImageBuildNative(t, ctx, p, read, change, first, "rq6-native-git-first")

	// A changed commit exists before accepting Automatic. The scheduler must
	// consume this accepted definition and real HTTPS source, not a submitted
	// user job or a test-injected saved archive/observation.
	const secondProof = "rq6-native-git-second"
	secondCommit := f.buildGit.CommitFiles(map[string][]byte{"context-proof": []byte(secondProof)})
	book, err := p.ImageBuilds(read().State)
	if err != nil {
		t.Fatal(err)
	}
	row, ok := book.Context("tenant", spec.ID)
	if !ok {
		t.Fatal("original Git context missing")
	}
	spec.Git.Automatic = true
	change("rq6-native-git-automatic", "put-build-context", row.Revision, control.ImageBuildContextPut{Spec: spec})
	var automatic control.ImageBuildJobRecord
	registryNativeWait(t, ctx, "actual Git scheduler submits changed commit", func() bool {
		book, err := p.ImageBuilds(read().State)
		if err != nil {
			t.Fatal(err)
		}
		for _, candidate := range book.Jobs {
			if candidate.Run.Spec.Tenant == "tenant" && candidate.Run.Spec.Context.ID == spec.ID && candidate.Run.Spec.Commit == secondCommit && candidate.Automatic != nil {
				automatic = candidate
				return true
			}
		}
		return false
	})
	automatic = f.waitImageBuildNative(t, ctx, r, p, read, automatic.Run.Spec.ID, "OK")
	if automatic.Origin.Change.Action != "put-build-context" || automatic.Run.Spec.Commit != secondCommit {
		t.Fatal("automatic job replaced the accepted definition/commit")
	}
	f.executeImageBuildResult(t, ctx, r, automatic.Run.Closure.Result.Image, "--build-context-result-fixture", secondProof)
	book, err = p.ImageBuilds(read().State)
	if err != nil {
		t.Fatal(err)
	}
	row, _ = book.Context("tenant", spec.ID)
	if row.GitObservation == nil || row.GitObservation.Report.Result.Commit != secondCommit {
		t.Fatal("automatic result lacks its actual source observation")
	}
	observed := row.GitObservation.Revision
	// The first run above is timer-driven. Repeat the same production worker
	// against real HTTPS/Raft now, without waiting a minute or injecting a
	// changed observation. Identical source facts deliberately keep revision.
	if err = r.observeImageBuildGit(ctx, "tenant", spec.ID); err != nil {
		t.Fatal("same-source real automatic worker failed", err)
	}
	book, err = p.ImageBuilds(read().State)
	if err != nil {
		t.Fatal(err)
	}
	row, _ = book.Context("tenant", spec.ID)
	if row.GitObservation == nil || row.GitObservation.Revision != observed {
		t.Fatal("same source rewrote the original observation")
	}
	count := 0
	for _, candidate := range book.Jobs {
		if candidate.Run.Spec.Tenant == "tenant" && candidate.Run.Spec.Context.ID == spec.ID && candidate.Run.Spec.Commit == secondCommit {
			count++
			if !reflect.DeepEqual(candidate, automatic) {
				t.Fatal("same-source worker changed the original automatic job")
			}
		}
	}
	if count != 1 {
		t.Fatal("same commit created duplicate automatic jobs")
	}
	spec.Git.Automatic = false
	change("rq6-native-git-disable-watch", "put-build-context", row.Revision, control.ImageBuildContextPut{Spec: spec})
	f.releaseImageBuildNative(t, ctx, p, read, change, automatic, "rq6-native-git-second")
	book, err = p.ImageBuilds(read().State)
	if err != nil {
		t.Fatal(err)
	}
	row, _ = book.Context("tenant", spec.ID)
	change("rq6-native-git-delete-context", "delete-build-context", row.Revision, control.ImageBuildSelection{Tenant: "tenant", ID: spec.ID})
	f.public["ImageBuildGitCommits"], f.public["ImageBuildAutomaticJob"] = []string{commit, secondCommit}, automatic.Run.Spec.ID
	f.save()
}

func (f *managedRegistryNative) verifyImageBuildDraftNative(t *testing.T, ctx context.Context, r *Runtime, root string, base imagebuild.ContextSpec, p control.Policy, read func() cluster.View, change func(string, string, uint64, any)) {
	t.Helper()
	spec := base.Own()
	spec.ID, spec.Kind, spec.Secrets, spec.Tags = "native-draft", "draft", nil, []string{"native-draft"}
	change("rq6-native-draft-context", "put-build-context", 0, control.ImageBuildContextPut{Spec: spec})
	var plan imagebuild.DraftResponse
	if err := json.Unmarshal(f.cli(nil, "registry", "draft-plan", spec.ID, "--tenant", "tenant"), &plan); err != nil || plan.Code != "PLAN" {
		t.Fatal("draft scope plan", err)
	}
	initial, _, missing := f.runCLI(nil, "registry", "draft-tree", spec.ID, "--tenant", "tenant")
	var empty struct {
		Draft imagebuild.DraftResponse
		Next  string
	}
	var exit interface{ ExitCode() int }
	if !errors.As(missing, &exit) || exit.ExitCode() != 3 || json.Unmarshal(initial, &empty) != nil || empty.Draft.Code != "NOT_INITIALIZED" || empty.Draft.Scope != plan.Scope || empty.Draft.Revision != 0 || empty.Draft.Digest != nil {
		t.Fatal("draft read initialized or fabricated a ready native draft")
	}
	tree := func() imagebuild.DraftResponse {
		t.Helper()
		var page struct {
			Draft imagebuild.DraftResponse
			Next  string
		}
		if err := json.Unmarshal(f.cli(nil, "registry", "draft-tree", spec.ID, "--tenant", "tenant"), &page); err != nil || page.Draft.Code != "OK" || page.Draft.Scope != plan.Scope || page.Draft.Digest == nil || page.Next != "" {
			t.Fatal("actual draft tree", err)
		}
		return page.Draft
	}
	const proof = "rq6-native-draft-context"
	multipart := bytes.Repeat([]byte("owned-multipart-file\n"), 2000)
	multipartDigest := sha256.Sum256(multipart)
	dockerfile := fmt.Sprintf("FROM %s\nCOPY --chmod=0444 context-proof /build-context-proof\nCOPY --chmod=0444 multipart.txt /build-multipart-proof\nLABEL org.mydc.test.owner=%q\n", f.reference, f.public["Tag"])
	var originalEditFile string
	var originalEdit *imagebuild.DraftEditResult
	for i, file := range []struct {
		path  string
		value []byte
	}{{"Dockerfile", []byte(dockerfile)}, {"context-proof", []byte(proof)}, {"multipart.txt", multipart}, {"remove-me", []byte("temporary")}} {
		// The first explicit edit creates the documented empty revision1.
		// A preceding read must remain NOT_INITIALIZED, not create that state.
		expected := uint64(1)
		if i != 0 {
			expected = tree().Revision
		}
		edit := imagebuild.DraftEdit{ID: fmt.Sprintf("native-edit-%d", i), Kind: "put", Path: file.path, Expected: expected, File: &imagebuild.Entry{Path: file.path, Bytes: int64(len(file.value)), Digest: sha256.Sum256(file.value)}}
		input := struct {
			Scope imagebuild.DraftScope
			Edit  imagebuild.DraftEdit
			Data  []byte `json:",omitempty"`
		}{Scope: plan.Scope, Edit: edit}
		method := "draft-edit"
		if len(file.value) <= imagebuild.PartBytes {
			input.Data = file.value
		} else {
			method = "draft-upload"
		}
		prepared := imageBuildNativeJSON(t, root, fmt.Sprintf("draft-edit-%d", i), input)
		args := []string{"registry", method, spec.ID, prepared}
		if method == "draft-upload" {
			body := filepath.Join(root, "original-draft-multipart")
			if err := os.WriteFile(body, file.value, 0600); err != nil {
				t.Fatal(err)
			}
			args = append(args, body)
		}
		args = append(args, "--tenant", "tenant")
		var edited imagebuild.DraftResponse
		if err := json.Unmarshal(f.cli(nil, args...), &edited); err != nil || edited.Code != "OK" || edited.Edit == nil || edited.Edit.Revision != expected+1 {
			t.Fatal("actual draft edit/file commit", err)
		}
		if i == 0 {
			originalEditFile, originalEdit = prepared, edited.Edit
		}
	}
	for i, edit := range []imagebuild.DraftEdit{{Kind: "move", Path: "remove-me", To: "moved-proof"}, {Kind: "delete", Path: "moved-proof"}} {
		before := tree()
		edit.ID, edit.Expected = fmt.Sprintf("native-edit-final-%d", i), before.Revision
		prepared := imageBuildNativeJSON(t, root, edit.ID, struct {
			Scope imagebuild.DraftScope
			Edit  imagebuild.DraftEdit
		}{plan.Scope, edit})
		var result imagebuild.DraftResponse
		if err := json.Unmarshal(f.cli(nil, "registry", "draft-edit", spec.ID, prepared, "--tenant", "tenant"), &result); err != nil || result.Code != "OK" || result.Edit == nil || result.Edit.Revision != before.Revision+1 {
			t.Fatal("actual draft move/delete", err)
		}
	}
	var historical imagebuild.DraftResponse
	if err := json.Unmarshal(f.cli(nil, "registry", "draft-result", spec.ID, originalEditFile, "--tenant", "tenant"), &historical); err != nil || historical.Code != "OK" || !reflect.DeepEqual(historical.Edit, originalEdit) {
		t.Fatal("original edit result changed after later edits", err)
	}
	current := tree()
	if len(current.Entries) != 3 {
		t.Fatal("draft tree did not reflect actual CRUD")
	}
	book, err := p.ImageBuilds(read().State)
	if err != nil {
		t.Fatal(err)
	}
	context, ok := book.Context("tenant", spec.ID)
	if !ok {
		t.Fatal("original draft definition missing")
	}
	createdAt := uint64(time.Now().Unix())
	freeze := imagebuild.DraftFreezePlan{Schema: 1, Scope: plan.Scope, ID: "rq6-native-draft-save", Creator: context.Definition.Session.User, Revision: current.Revision, Draft: *current.Digest, CreatedAt: createdAt, ExpiresAt: createdAt + 600}
	prepared := imageBuildNativeJSON(t, root, "draft-freeze-plan", freeze)
	var document control.ChangeDocument
	if err := json.Unmarshal(f.cli(nil, "registry", "draft-freeze", spec.ID, prepared, "--tenant", "tenant"), &document); err != nil || document.Action != "publish-build-draft" {
		t.Fatal("draft archive did not produce creator publication", err)
	}
	var publication control.ImageBuildDraftPublish
	if err := json.Unmarshal(document.Payload, &publication); err != nil || !publication.Frozen.Valid() || publication.Frozen.Plan != freeze {
		t.Fatal("draft archive owner evidence mismatch", err)
	}
	var original imagebuild.DraftResponse
	if err := json.Unmarshal(f.cli(nil, "registry", "draft-freeze-result", spec.ID, prepared, "--tenant", "tenant"), &original); err != nil || original.Code != "FROZEN" || !reflect.DeepEqual(original.Frozen, &publication.Frozen) {
		t.Fatal("draft original freeze result changed", err)
	}
	publishFile := imageBuildNativeJSON(t, root, "draft-publication", document)
	f.cli(nil, "--tenant", "tenant", "manage", "apply", "--change", publishFile, "--request-id", "rq6-native-draft-publish")
	version := imagebuild.VersionID(publication.Frozen.Fact)
	const jobID = "rq6-native-draft-build"
	f.cli(nil, "registry", "build", spec.ID, hex.EncodeToString(version[:]), "--tenant", "tenant", "--job", jobID, "--request-id", "rq6-native-draft-submit", "--no-input")
	job := f.waitImageBuildNative(t, ctx, r, p, read, jobID, "OK")
	f.executeImageBuildResult(t, ctx, r, job.Run.Closure.Result.Image, "--build-context-result-fixture", proof, hex.EncodeToString(multipartDigest[:]))
	f.releaseImageBuildNative(t, ctx, p, read, change, job, "rq6-native-draft")
	book, err = p.ImageBuilds(read().State)
	if err != nil {
		t.Fatal(err)
	}
	row, _ := book.Context("tenant", spec.ID)
	change("rq6-native-draft-delete-context", "delete-build-context", row.Revision, control.ImageBuildSelection{Tenant: "tenant", ID: spec.ID})
	f.public["ImageBuildDraftJob"], f.public["ImageBuildDraftRevision"] = jobID, current.Revision
	f.save()
}
