// SPDX-License-Identifier: Apache-2.0

//go:build linux

package app

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"testing"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/imagebuild"
	"github.com/jay94ks/mydcd/internal/imagesource"
	"github.com/jay94ks/mydcd/tests/registryfixture"
	"github.com/moby/moby/api/types/container"
)

// Values reach the real CLI only by private FD, including the actual owned
// TLS CA. They never enter a replicated source definition, argument or log.
func (f *managedRegistryNative) externalNativeValues(t *testing.T, root string, values map[string][]byte) {
	t.Helper()
	keys := []string{"USER_A", "PASS_A", "USER_B", "PASS_B", "CA"}
	args := []string{"--tenant", "tenant", "secret", "create", "--id", "registry-auth", "--parent", "group", "--profile", "values", "--provider-object", "tenant/registry-auth", "--request-id", "rq6-external-secret"}
	for _, key := range keys {
		args = append(args, "--key", key)
	}
	f.cli(nil, args...)
	args = []string{"--tenant", "tenant", "secret", "put", "--object", "registry-auth", "--write-id", "rq6-external-values", "--no-input"}
	var inputs []*os.File
	defer func() {
		for _, file := range inputs {
			_ = file.Close()
			_ = os.Remove(file.Name())
		}
	}()
	for _, key := range keys {
		file, err := os.CreateTemp(root, "external-value-")
		if err != nil {
			t.Fatal(err)
		}
		inputs = append(inputs, file)
		if _, err = file.Write(values[key]); err != nil {
			t.Fatal(err)
		}
		if _, err = file.Seek(0, 0); err != nil {
			t.Fatal(err)
		}
		args = append(args, "--value-fd", fmt.Sprintf("%s=%d", key, len(inputs)+2))
	}
	f.cli(inputs, args...)
}

func (f *managedRegistryNative) bindExternalNative(t *testing.T, root, id, request string) {
	t.Helper()
	file, err := os.CreateTemp(root, "external-group-password-")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = file.Close(); _ = os.Remove(file.Name()) }()
	if _, err = file.WriteString("private-native-group-password"); err != nil {
		t.Fatal(err)
	}
	if _, err = file.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	f.cli([]*os.File{file}, "registry", "external-bind", id, "--node", "node-a", "--tenant", "tenant", "--request-id", request, "--no-input", "--group-password-fd", "tenant/group=3")
}

func (f *managedRegistryNative) verifyImageBuildExternalNative(t *testing.T, ctx context.Context, r *Runtime, root string, base imagebuild.ContextSpec, p control.Policy, read func() cluster.View, change func(string, string, uint64, any)) {
	t.Helper()
	const userA, passwordA = "owned-reader-a", "private-rq6-external-a"
	const userB, passwordB = "owned-reader-b", "private-rq6-external-b"
	external := registryfixture.OpenPrivatePrepared(t, os.Getenv("MYDC_DOCKER_TEST_BACKEND"), container.Config{Labels: map[string]string{"org.mydc.test.owner": f.public["Tag"].(string)}}, map[string]registryfixture.BasicCredential{"fixture": {Username: userA, Password: passwordA}, "second": {Username: userB, Password: passwordB}})
	f.externalNativeValues(t, root, map[string][]byte{"USER_A": []byte(userA), "PASS_A": []byte(passwordA), "USER_B": []byte(userB), "PASS_B": []byte(passwordB), "CA": external.Certificate})
	users, err := p.Catalog(read().State)
	if err != nil {
		t.Fatal(err)
	}
	tenant, _ := users.Tenant("tenant")
	change("rq6-external-trust", "set-trust", tenant.Revision, control.TrustAssignment{Tenant: "tenant", Rules: append(tenant.ImageSources, access.TrustRule{Registry: external.Registry, Repository: "fixture"}, access.TrustRule{Registry: external.Registry, Repository: "second"})})
	expectedReaders := map[string]control.ExternalRegistryReadSelection{}
	for _, selection := range []struct{ id, repository, auth, user, password string }{{"external-a", "fixture", "password", "USER_A", "PASS_A"}, {"external-b", "second", "token", "USER_B", "PASS_B"}} {
		source := imagesource.Source{Tenant: "tenant", ID: selection.id, Authority: external.Registry, Repository: selection.repository, Enabled: true, Auth: selection.auth, Credential: &imagesource.Credential{Realm: "tenant", ID: "registry-auth", UsernameKey: selection.user, PasswordKey: selection.password}, CA: &imagesource.CertificateAuthority{Realm: "tenant", ID: "registry-auth", Key: "CA"}}
		change("rq6-"+selection.id, "put-external-registry", 0, control.ExternalRegistryPut{Spec: source})
		f.bindExternalNative(t, root, selection.id, "rq6-"+selection.id+"-bind")
		entries, err := p.ExternalRegistries(read().State)
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			if entry.Spec.Tenant == "tenant" && entry.Spec.ID == selection.id && entry.Reader != nil && !entry.Reader.Draining {
				expectedReaders[selection.id] = control.ExternalRegistryReadSelection{Tenant: "tenant", ID: selection.id, Generation: entry.Reader.Generation}
			}
		}
	}
	second := external.PrivateReference("second")
	if len(expectedReaders) != 2 || second == "" || second == external.Reference {
		t.Fatal("actual private source definitions missing distinct immutable repository references")
	}
	probe := func(id, image, code string) {
		t.Helper()
		out, diagnostic, err := f.runCLI(nil, "registry", "login-test", id, "--tenant", "tenant", "--image", image)
		var result control.ExternalRegistryProbeResult
		if json.Unmarshal(out, &result) != nil || result.Code != code || bytes.Contains(out, []byte(passwordA)) || bytes.Contains(out, []byte(passwordB)) || bytes.Contains(diagnostic, []byte(passwordA)) || bytes.Contains(diagnostic, []byte(passwordB)) {
			t.Fatal("actual private registry probe missing or exposed credentials")
		}
		if code == "OK" {
			if err != nil {
				t.Fatal("actual private probe failed", err)
			}
		} else {
			var exit interface{ ExitCode() int }
			if !errors.As(err, &exit) || exit.ExitCode() != 3 {
				t.Fatal("actual private probe did not refuse", err)
			}
		}
	}
	probe("external-a", external.Reference, "OK")
	external.DenyPrivate("second", true)
	probe("external-b", second, "UNAUTHORIZED")
	probe("external-a", external.Reference, "OK")
	external.DenyPrivate("second", false)
	probe("external-b", second, "OK")
	firstAuthorized, _ := external.PrivateStats("fixture")
	secondAuthorized, secondDenied := external.PrivateStats("second")
	if firstAuthorized == 0 || secondAuthorized == 0 || secondDenied == 0 {
		t.Fatal("repository-specific private authentication was not exercised")
	}
	spec := base.Own()
	spec.ID, spec.Secrets, spec.Tags = "native-external", nil, []string{"native-external"}
	change("rq6-external-build-context", "put-build-context", 0, control.ImageBuildContextPut{Spec: spec})
	const proof = "rq6-native-external-context"
	dockerfile := fmt.Sprintf("FROM %s AS first\nFROM %s AS second\nFROM first\nCOPY --from=second /registry-repository /other-source-proof\nCOPY --chmod=0444 context-proof /build-context-proof\nLABEL org.mydc.test.owner=%q\n", external.Reference, second, f.public["Tag"])
	version := f.uploadBuildNative(t, root, spec.ID, "rq6-external-upload", dockerfile, proof)
	const jobID = "rq6-native-external-build"
	f.cli(nil, "registry", "build", spec.ID, hex.EncodeToString(version[:]), "--tenant", "tenant", "--job", jobID, "--request-id", "rq6-external-submit", "--no-input")
	job := f.waitImageBuildNative(t, ctx, r, p, read, jobID, "OK")
	if len(job.Sources) != 2 || len(job.Run.Inputs) != 2 {
		t.Fatal("same-host private repositories lost their distinct source bindings")
	}
	remaining := map[string]string{"external-a": external.Reference, "external-b": second}
	for _, binding := range job.Sources {
		if binding.External == nil || *binding.External != expectedReaders[binding.External.ID] || binding.Owner != r.Identity.Public || binding.ReadSet == ([32]byte{}) || binding.Image != remaining[binding.External.ID] {
			t.Fatal("actual build substituted the original repository reader or immutable source")
		}
		delete(remaining, binding.External.ID)
	}
	if len(remaining) != 0 {
		t.Fatal("actual build omitted an original repository reader")
	}
	firstAfter, _ := external.PrivateStats("fixture")
	secondAfter, _ := external.PrivateStats("second")
	if firstAfter <= firstAuthorized || secondAfter <= secondAuthorized {
		t.Fatal("actual build did not read both independently authenticated immutable sources")
	}
	f.executeImageBuildResult(t, ctx, r, job.Run.Closure.Result.Image, "--build-two-source-result-fixture", proof, "second")
	f.releaseImageBuildNative(t, ctx, p, read, change, job, "rq6-native-external")
	book, err := p.ImageBuilds(read().State)
	if err != nil {
		t.Fatal(err)
	}
	row, _ := book.Context("tenant", spec.ID)
	change("rq6-external-delete-context", "delete-build-context", row.Revision, control.ImageBuildSelection{Tenant: "tenant", ID: spec.ID})
	for _, id := range []string{"external-a", "external-b"} {
		entries, err := p.ExternalRegistries(read().State)
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, entry := range entries {
			if entry.Spec.Tenant == "tenant" && entry.Spec.ID == id {
				found = true
				change("rq6-"+id+"-delete", "delete-external-registry", entry.Revision, control.RegistrySelection{Tenant: "tenant", ID: id})
			}
		}
		if !found {
			t.Fatal("original private source disappeared")
		}
		registryNativeWait(t, ctx, "original private reader closure "+id, func() bool {
			entries, err := p.ExternalRegistries(read().State)
			if err != nil {
				t.Fatal(err)
			}
			for _, entry := range entries {
				if entry.Spec.Tenant == "tenant" && entry.Spec.ID == id {
					return entry.Deleted && entry.Reader == nil && entry.Closed != nil
				}
			}
			return false
		})
	}
	f.public["ImageBuildExternalSourceJob"], f.public["ImageBuildExternalPrivateRepositories"] = jobID, []string{"fixture", "second"}
	f.public["ImageBuildExternalReadersClosed"] = true
	f.public["ImageBuildExternalPinnedSources"] = []string{external.Reference, second}
	f.public["ImageBuildExternalBuildReads"] = map[string]int64{"fixture": firstAfter - firstAuthorized, "second": secondAfter - secondAuthorized}
	f.save()
	// Retire requires an explicitly revoked leaf with no remaining readers.
	f.cli(nil, "--tenant", "tenant", "secret", "revoke", "--id", "registry-auth", "--request-id", "rq6-external-revoke-secret")
	f.cli(nil, "--tenant", "tenant", "secret", "retire", "--id", "registry-auth", "--request-id", "rq6-external-retire-secret")
}
