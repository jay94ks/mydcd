// SPDX-License-Identifier: Apache-2.0

package imagebuild

import (
	"crypto/ed25519"
	"slices"
)

func nativeEffectsClosed(r NativeRecord) bool {
	if r.CreateSent && !r.CreateNotSent && !r.Removed || !r.CreateSent && !r.Cancel {
		return false
	}
	if r.Workspace != nil && !r.Workspace.Closed {
		return false
	}
	if r.Publication != nil {
		if _, closed := r.Publication.result(r.Spec); !closed {
			return false
		}
	}
	return true
}
func nativeClosed(r NativeRecord) bool {
	return nativeEffectsClosed(r) && (r.Root == nil || r.Root.Returned)
}
func nativeCompletionWitness(r NativeRecord) [32]byte {
	return digestJSON("sfc-imagebuild-native-completion-1", struct {
		Job, Workspace [32]byte
		Root           *NativeRootHold
	}{r.Spec.Digest(), workspaceClosure(r), r.Root})
}

func (n *NativeJobs) SealCompletion(grant NativeGrant, result JobResult, at uint64, key ed25519.PrivateKey) (JobClosure, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	spec := grant.Run.Spec
	if len(key) != ed25519.PrivateKeySize || [32]byte(key.Public().(ed25519.PublicKey)) != spec.Scope.Root.Key || grant.Run.Shape() != nil || grant.Index == 0 || grant.Epoch == 0 || !result.Valid(spec) || result.Code == "CANCELLED" && !grant.Run.Cancel {
		return JobClosure{}, ErrInvalid
	}
	r, err := n.load(spec)
	if err != nil {
		return JobClosure{}, err
	}
	if r.Outcome != nil && *r.Outcome != result {
		return JobClosure{}, ErrConflict
	}
	if r.Completion != nil {
		if r.Completion.Result != result {
			return JobClosure{}, ErrConflict
		}
		copy := *r.Completion
		copy.Signature = slices.Clone(copy.Signature)
		return copy, nil
	}
	if !nativeClosed(r) || n.readers[spec.Digest()] != 0 || n.publishing[spec.Digest()] || r.Workspace != nil && r.Root == nil {
		return JobClosure{}, ErrUsed
	}
	if grant.Index < r.Index || grant.Run.Revision < r.Revision || at < spec.CreatedAt {
		return JobClosure{}, ErrConflict
	}
	if r.Publication != nil {
		published, closed := r.Publication.result(spec)
		if !closed || published != result && !(grant.Run.Cancel && result.Code == "CANCELLED" && published.Code != "OK") {
			return JobClosure{}, ErrConflict
		}
	} else if result.Code == "OK" {
		return JobClosure{}, ErrConflict
	}
	closure := JobClosure{Schema: 1, Job: spec.Digest(), Native: nativeCompletionWitness(r), Builder: r.ImageID, Result: result, At: at}
	closure.Signature = ed25519.Sign(key, JobClosureBytes(closure))
	if !closure.Valid(spec) {
		return JobClosure{}, ErrInvalid
	}
	r.Completion = &closure
	if err := n.save(r); err != nil {
		return JobClosure{}, err
	}
	closure.Signature = slices.Clone(closure.Signature)
	return closure, nil
}
