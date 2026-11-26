// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"

	"github.com/jay94ks/mydcd/internal/access"
)

func TestOriginalAppDocumentIsExactBoundedOwnedAndMatchesFrozenPlan(t *testing.T) {
	f, input, ctx, _ := externalFixture(t)
	raw, err := marshalApp(input)
	if err != nil {
		t.Fatal(err)
	}
	raw = append([]byte("# Original spacing and comments must survive.\n\n"), raw...)
	b, err := CompileAppDocument(raw, f.c, ctx)
	if err != nil || b.ValidateCurrent(f.c, ctx) != nil {
		t.Fatal("original compiler/current admission", err)
	}
	encoded, err := b.Encode()
	if err != nil {
		t.Fatal(err)
	}
	restored, err := DecodeBlueprint(encoded)
	if err != nil || restored.Digest() != b.Digest() || restored.OriginalDocument() == nil || !bytes.Equal(restored.OriginalDocument().Body, raw) {
		t.Fatal("source roundtrip lost original bytes", err)
	}
	owned := restored.OriginalDocument()
	owned.Body[0] = '!'
	if !bytes.Equal(restored.OriginalDocument().Body, raw) {
		t.Fatal("source getter aliases private artifact")
	}
	// A matching hash of unrelated bytes would be insufficient. The decoder
	// also checks that the raw declaration normalizes to this frozen plan.
	for _, mutate := range []func(*blueprintRecord){
		func(d *blueprintRecord) {
			d.Document.Body = bytes.ReplaceAll(d.Document.Body, []byte("image:"), []byte("image: unrelated #"))
		},
		func(d *blueprintRecord) {
			d.Document.DefaultNode = "other-node"
			for name, service := range d.Input.Services {
				service.MyDC.Node = ""
				d.Input.Services[name] = service
			}
		},
		func(d *blueprintRecord) { d.Document.Body = append(bytes.Repeat([]byte{'#'}, ArtifactMaxBytes), '\n') },
	} {
		var disk blueprintRecord
		if json.Unmarshal(encoded, &disk) != nil {
			t.Fatal("encoded fixture")
		}
		mutate(&disk)
		bad, _ := json.Marshal(disk)
		if _, err := DecodeBlueprint(bad); err == nil {
			t.Fatal("unrelated/oversized document accepted as original")
		}
	}
	legacy, err := CompileApp(input, f.c, ctx)
	if err != nil || legacy.OriginalDocument() != nil || legacy.ValidateCurrent(f.c, ctx) != nil {
		t.Fatal("legacy source-less artifact reinterpreted", err)
	}
}

func TestLegacyCDFileReplanCannotClaimRegeneratedYAMLAsOriginal(t *testing.T) {
	f, ctx, legacy, delivery := acceptedDeliveryAdapterFixture(t)
	body := delivery.d.Candidate.Artifact.Body
	if delivery.d.Candidate.Artifact.Original || legacy.OriginalDocument() != nil {
		t.Fatal("legacy fixture unexpectedly contains original proof")
	}
	candidate, err := delivery.compile(f.c, ctx, delivery.d.Candidate.Artifact)
	if err != nil || (Blueprint{candidate.Plan}).OriginalDocument() != nil {
		t.Fatal("legacy replan mislabeled generated artifact as original", err)
	}
	original := delivery.d.Candidate.Artifact
	original.Original = true // test a new, explicitly retained exact file input
	candidate, err = delivery.compile(f.c, ctx, original)
	if err != nil || (Blueprint{candidate.Plan}).OriginalDocument() == nil || !bytes.Equal((Blueprint{candidate.Plan}).OriginalDocument().Body, body) {
		t.Fatal("new exact file document was discarded", err)
	}
}

func TestUntrustedImageNamesItsReason(t *testing.T) {
	f, input, ctx, _ := externalFixture(t)
	for name, s := range input.Services {
		s.Image = "untrusted.example/other@sha256:" + "ab0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd"[:64]
		input.Services[name] = s
		raw, err := marshalApp(input)
		if err != nil {
			t.Fatal(err)
		}
		_, err = CompileAppDocument(raw, f.c, ctx)
		var cause *InputError
		if !errors.As(err, &cause) || cause.Code != "IMAGE_NOT_TRUSTED" || cause.Path != "services."+name+".image" {
			t.Fatal("untrusted image without a named reason", err)
		}
		return
	}
	t.Fatal("fixture has no service")
}

// Without Deploy on the node the same denial must not claim a trust cause.
func TestImageDenialWithoutDeployStaysUnnamed(t *testing.T) {
	f, _, ctx, _ := externalFixture(t)
	err := imageCheckError(f.c, "no-such-user", "tenant", "node-a", access.ErrDenied, "x-mydc.registries.r.image")
	if !errors.Is(err, access.ErrDenied) {
		t.Fatal("denial without Deploy was relabelled", err)
	}
	if err = imageCheckError(f.c, ctx.Actor, ctx.Tenant, "node-a", access.ErrDenied, "services.web.image"); func() bool {
		var cause *InputError
		return !errors.As(err, &cause) || cause.Code != "IMAGE_NOT_TRUSTED"
	}() {
		t.Fatal("trust denial for a deployer lost its reason", err, ctx.Actor, ctx.Tenant)
	}
}
