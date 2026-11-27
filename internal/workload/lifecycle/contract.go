// SPDX-License-Identifier: Apache-2.0

// Package lifecycle owns deterministic container checker transitions. Adapters
// provide observed time, native identities and positive process/exec closure.
package lifecycle

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"maps"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jay94ks/seafield/internal/schema"
	contract "github.com/jay94ks/seafield/lifecycle/v1"
)

var (
	ErrContract  = errors.New("invalid lifecycle checker contract")
	ErrPending   = errors.New("original checker run is not settled")
	ErrStale     = errors.New("checker completion does not match original run")
	ErrClock     = errors.New("invalid lifecycle observation time")
	ErrNotDue    = errors.New("checker is not due")
	ErrRetiring  = errors.New("checker binding is retiring")
	ErrReference = errors.New("lifecycle source reference unavailable")
)

const (
	MaxRequestBytes = 64 << 10
	MaxResultBytes  = 1024
	MaxTargets      = 128
)

func name(s string) bool {
	if len(s) == 0 || len(s) > 128 {
		return false
	}
	for i, c := range []byte(s) {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || i > 0 && (c == '-' || c == '_' || c == '.')) {
			return false
		}
	}
	return true
}

func digest(s string) bool {
	raw, err := hex.DecodeString(s)
	return err == nil && len(raw) == sha256.Size && s == hex.EncodeToString(raw) && !bytes.Equal(raw, make([]byte, sha256.Size))
}

func text(s string, limit int) bool {
	return s != "" && len(s) <= limit && utf8.ValidString(s) && !strings.ContainsAny(s, "\x00\r\n")
}

func validPhase(p contract.Phase) bool {
	return p == contract.Startup || p == contract.Readiness || p == contract.Liveness || p == contract.Shutdown
}

func validStatus(s contract.Status) bool {
	return s == contract.Pass || s == contract.Fail || s == contract.Unknown
}

func ValidateRequest(r contract.Request) error {
	if !digest(r.RunID) || r.DeadlineUnixMilli <= 0 {
		return ErrContract
	}
	return validateRequestFields(r)
}

func validateRequestFields(r contract.Request) error {
	if r.Schema != contract.Schema || !digest(r.Cluster) || !name(r.Tenant) || !name(r.App) || !name(r.Checker) || !digest(r.SourceDigest) || !validPhase(r.Phase) || len(r.Targets) == 0 || len(r.Targets) > MaxTargets || len(r.Parameters) > 64 {
		return ErrContract
	}
	previous := ""
	for _, t := range r.Targets {
		if !name(t.Service) || t.Service <= previous || !text(t.TaskKey, 512) || !text(t.NativeID, 128) || !digest(t.Owner) || !digest(t.OwnerBoot) || t.Generation == 0 || t.Revision < t.Generation {
			return ErrContract
		}
		if t.StartedAt != "" {
			if _, err := time.Parse(time.RFC3339Nano, t.StartedAt); err != nil || len(t.StartedAt) > 64 {
				return ErrContract
			}
		}
		previous = t.Service
	}
	parameterBytes := 0
	for k, v := range r.Parameters {
		if !name(k) || len(v) > 4096 || !utf8.ValidString(v) || strings.ContainsRune(v, 0) {
			return ErrContract
		}
		parameterBytes += len(k) + len(v)
	}
	if parameterBytes > 32<<10 {
		return ErrContract
	}
	raw, err := json.Marshal(r)
	if err != nil || len(raw) > MaxRequestBytes {
		return ErrContract
	}
	return nil
}

func ValidateResult(r contract.Result) error {
	if r.Schema != contract.Schema || !validStatus(r.Status) || !name(r.Reason) || len(r.Reason) > 96 {
		return ErrContract
	}
	return nil
}

func DecodeRequest(raw []byte) (contract.Request, error) {
	if len(raw) > MaxRequestBytes {
		return contract.Request{}, ErrContract
	}
	r, err := schema.Decode[contract.Request](raw)
	if err != nil || ValidateRequest(r) != nil {
		return contract.Request{}, ErrContract
	}
	return r, nil
}

// DecodeExitResult never maps a signal, panic, partial JSON or contradictory
// process exit to pass. Its diagnostic error must not be published as Reason.
func DecodeExitResult(raw []byte, exitCode int) (contract.Result, error) {
	unknown := contract.Result{Schema: contract.Schema, Status: contract.Unknown, Reason: "invalid-response"}
	if len(raw) > MaxResultBytes {
		return unknown, ErrContract
	}
	r, err := schema.Decode[contract.Result](raw)
	if err != nil || ValidateResult(r) != nil {
		return unknown, ErrContract
	}
	want := 2
	if r.Status == contract.Pass {
		want = 0
	} else if r.Status == contract.Fail {
		want = 1
	}
	if exitCode != want {
		return unknown, ErrContract
	}
	return r, nil
}

func ownRequest(r contract.Request) contract.Request {
	r.Targets = slices.Clone(r.Targets)
	r.Parameters = maps.Clone(r.Parameters)
	return r
}

func requestDigest(r contract.Request) [32]byte {
	raw, _ := json.Marshal(r)
	return sha256.Sum256(append([]byte("sfc-checker-request-1\x00"), raw...))
}

// ProbeBinding is the same original Request identity used by interpreted,
// compiled and node-native adapters. It is metadata, not an execution grant.
func ProbeBinding(r contract.Request) [32]byte { return requestDigest(r) }
