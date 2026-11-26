// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"path"
	"reflect"
	"slices"
	"strings"

	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/identity"
	"github.com/jay94ks/mydcd/internal/secrets"
	"github.com/jay94ks/mydcd/internal/web/mydc"
	"github.com/jay94ks/mydcd/internal/web/store"
)

// Vault provider writes (mydc-web side). mydcd owns the write protocol, the
// receiver, the provider and the Group password check; the web runs the same
// steps as `mydc secret put` / `secret group password` under one web opId,
// stores each signed original before sending it, and passes the values only
// through mydcd's SecretInput. Values and passwords are never stored (bbolt,
// logs, originals, the op digest) and are dropped when the request ends.

// POST /t/{t}/vault/value {opId, path, values:{key: value}}: write a Secret's
// values (mydcd publishes the written keys as the Secret's keys).
func (s *Server) handleVaultValue(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req struct {
		OpID   string            `json:"opId"`
		Path   string            `json:"path"`
		Keys   []string          `json:"keys,omitempty"`
		Values map[string]string `json:"values,omitempty"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	var values map[string][]byte
	defer func() {
		for _, v := range values {
			clear(v)
		}
	}()
	keys := slices.Clone(req.Keys)
	if len(req.Values) > 0 {
		values = map[string][]byte{}
		total := 0
		for k, v := range req.Values {
			values[k] = []byte(v)
			total += len(v)
		}
		req.Values = nil
		vk := slices.Sorted(maps.Keys(values))
		if len(keys) != 0 && !slices.Equal(sortedCopy(keys), vk) {
			writeError(w, http.StatusBadRequest, "bad-request", "keys and values must name the same keys")
			return
		}
		keys = vk
		if len(values) > 128 || total > 16<<10 {
			writeError(w, http.StatusBadRequest, "bad-request", "values: at most 128 keys and 16 KiB")
			return
		}
	}
	s.vaultWrite(w, r, ws, req.OpID, req.Path, "", secrets.ValueWrite, sortedCopy(keys), values)
}

// POST /t/{t}/vault/password {opId, path, password, profile?}: set (or
// change) a Group's password. profile names the verifier writer profile
// the first time (mydcd keeps the Group's own after that). mydcd then protects the Group: an app's use of its
// Secrets needs an approval with this password. The web hashes it (Argon2id,
// as the CLI does) and sends only the hash, as the "verifier" value.
func (s *Server) handleVaultPassword(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req struct {
		OpID     string `json:"opId"`
		Path     string `json:"path"`
		Password string `json:"password,omitempty"`
		Profile  string `json:"profile,omitempty"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	var values map[string][]byte
	defer func() {
		for _, v := range values {
			clear(v)
		}
	}()
	if req.Password != "" {
		pw := []byte(req.Password)
		req.Password = ""
		defer clear(pw)
		if len(pw) > 1024 || strings.ContainsAny(string(pw), "\r\n\x00") {
			writeError(w, http.StatusBadRequest, "bad-request", "password: one line, at most 1024 bytes")
			return
		}
		var salt [16]byte
		if _, err := rand.Read(salt[:]); err != nil {
			writeError(w, http.StatusInternalServerError, "internal", "random")
			return
		}
		h, err := identity.PasswordHash(pw, salt[:], identity.DefaultPasswordCost())
		clear(salt[:])
		if err != nil {
			writeError(w, http.StatusBadRequest, "bad-request", "password: one line, at most 1024 bytes")
			return
		}
		raw, err := h.ProtectedBytes()
		if err != nil {
			writeError(w, http.StatusInternalServerError, "internal", "password hash")
			return
		}
		values = map[string][]byte{"verifier": raw}
	}
	s.vaultWrite(w, r, ws, req.OpID, req.Path, req.Profile, secrets.VerifierWrite, nil, values)
}

func sortedCopy(v []string) []string {
	out := slices.Clone(v)
	slices.Sort(out)
	return out
}

// vaultWriteID names the provider write of a web op: one stable mydcd
// write ID per opId (a lowercase identifier).
func vaultWriteID(opID string) string {
	h := sha256.Sum256([]byte("mydc-web-vault-write\x00" + opID))
	return "web-" + hex.EncodeToString(h[:12])
}

// vaultWrite starts or continues the job of opID. values may be nil when
// only continuing; it is needed only for a first private input. profile is
// used only when the job is planned, so it is not part of the digest.
func (s *Server) vaultWrite(w http.ResponseWriter, r *http.Request, ws *webSession, opID, p, profile string, kind secrets.WriteKind, keys []string, values map[string][]byte) {
	tenant := r.PathValue("t")
	if !uuidRE.MatchString(opID) {
		writeError(w, http.StatusBadRequest, "bad-request", "opId must be a lowercase UUID v4")
		return
	}
	object := path.Base(p)
	if p == "" || strings.HasPrefix(p, "/") || strings.HasSuffix(p, "/") || !validName(object) {
		writeError(w, http.StatusBadRequest, "bad-request", "path: the object's path such as db/mysql")
		return
	}
	action := "vault-value"
	if kind == secrets.VerifierWrite {
		action = "vault-password"
	}
	// the digest names the change, never the values
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s\x00%s\x00%s\x00%s", action, tenant, p, strings.Join(keys, "\x00"))))
	dg := hex.EncodeToString(sum[:])

	parent, err := s.opt.Store.GetOp(ws.user.ID, opID)
	switch {
	case err == nil:
		if parent.Digest != dg || parent.VaultWrite == nil {
			writeError(w, http.StatusConflict, "op-conflict", "this opId was already used for a different change")
			return
		}
	case errors.Is(err, store.ErrNotFound):
		parent = nil
		if values == nil {
			writeError(w, http.StatusBadRequest, "bad-request", "the first request carries the values (or password)")
			return
		}
	default:
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}

	ctx, cancel := s.callCtx(r)
	defer cancel()
	err = ws.do(ctx, func(ctx context.Context, c mydc.Conn) error {
		if parent == nil {
			id := vaultWriteID(opID)
			plan, err := c.PlanVaultWrite(ctx, tenant, mydc.VaultWritePlanRequest{Realm: tenant, ID: id, Object: object, Profile: profile, Kind: kind, Keys: keys})
			if err != nil {
				return err
			}
			if plan.Write != nil {
				return &httpErr{http.StatusConflict, "op-conflict", "a provider write with this id already exists"}
			}
			req, _ := json.Marshal(plan.Request)
			now := s.now()
			parent = &store.Op{ID: opID, User: ws.user.ID, Username: ws.user.Username, Action: action, Tenant: tenant, Target: p, Digest: dg,
				State: store.OpRunning, SubmittedAt: now, UpdatedAt: now,
				VaultWrite: &store.VaultWriteJob{Realm: tenant, Path: p, Object: object, Kind: string(kind), WriteID: id, Request: req}}
			existing, err := s.opt.Store.CreateOp(parent)
			if err != nil {
				return err
			}
			if existing != nil {
				parent = existing
			}
		}
		return s.runVaultWrite(ctx, c, ws, parent, values)
	})
	if err != nil {
		var he *httpErr
		if errors.As(err, &he) {
			writeError(w, he.status, he.code, he.msg)
			return
		}
		s.writeBackendError(w, ws, err)
		return
	}
	writeJSON(w, opStatus(parent), map[string]any{"op": viewOp(parent)})
}

// runVaultWrite moves the job on until it is published, fails, or waits:
//
//	errorCode needs-input  dispatched, values not sent yet: send them again
//	errorCode input-unknown  the private input's outcome is not known: send the
//	                         same opId again (without values) to recover it
//	errorCode step-unknown   a step original's outcome is unknown: settle it
//	                         with /ops/{opId}.{n}/result, then send again
func (s *Server) runVaultWrite(ctx context.Context, c mydc.Conn, ws *webSession, parent *store.Op, values map[string][]byte) error {
	j := parent.VaultWrite
	defer func() {
		parent.UpdatedAt = s.now()
		if err := s.saveOp(parent); err != nil {
			s.log.Error("update vault write job", "op", parent.ID, "err", err)
		}
	}()
	var req secrets.WriteRequest
	if err := json.Unmarshal(j.Request, &req); err != nil {
		return err
	}
	stop := func(state, code string) error { parent.State, parent.ErrorCode = state, code; return nil }
	// step sends (or reads back) one original of the job; done reports
	// whether it applied and the job may go on.
	step := func(n int, action string, expected uint64, payload any) (bool, error) {
		id := stepID(parent.ID, n)
		child, err := s.opt.Store.GetOp(ws.user.ID, id)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return false, err
		}
		if child == nil {
			raw, _ := json.Marshal(payload)
			doc, _ := json.Marshal(control.ChangeDocument{Schema: 1, Action: action, Expected: expected, Payload: raw})
			ch, err := control.InputChange(doc, ws.user.ID)
			if err != nil {
				return false, &httpErr{http.StatusUnprocessableEntity, "invalid", action + ": the values do not make a valid request"}
			}
			who, err := c.Whoami(ctx)
			if err != nil {
				return false, err
			}
			child = &store.Op{ID: id, User: ws.user.ID, Username: ws.user.Username, Action: action, Tenant: parent.Tenant, Target: parent.Target, Parent: parent.ID, Digest: parent.Digest}
			if existing, err := s.sendStored(ctx, c, child, ch, who.RootFor(action)); err != nil {
				return false, err
			} else if existing != nil {
				child = existing
			}
		}
		switch child.State {
		case store.OpApplied:
			return true, nil
		case store.OpPending, store.OpUnknown:
			return false, stop(store.OpUnknown, "step-unknown")
		default:
			parent.Result = child.Result
			code := child.ErrorCode
			if code == "" && child.Result != nil {
				code = fmt.Sprintf("result-%d", child.Result.Code)
			}
			return false, stop(child.State, code)
		}
	}
	for range 8 {
		plan, err := c.PlanVaultWrite(ctx, j.Realm, mydc.VaultWritePlanRequest{Realm: j.Realm, ID: j.WriteID})
		if err != nil {
			return err
		}
		status := ""
		if plan.Write != nil {
			status = plan.Write.Status
			if !reflect.DeepEqual(plan.Write.Request, req) {
				return stop(store.OpFailed, "write-changed")
			}
		}
		var ok bool
		switch status {
		case "Published":
			return stop(store.OpApplied, "")
		case "NotApplied", "Abandoned", "Invalid":
			return stop(store.OpFailed, "write-not-applied")
		case "":
			ok, err = step(0, mydc.ActionVaultPrepareWrite, plan.TreeRevision, control.VaultWrite{Realm: j.Realm, Request: req})
		case "Prepared":
			ok, err = step(1, mydc.ActionVaultDispatchWrite, plan.TreeRevision, control.VaultWriteAction{Realm: j.Realm, ID: j.WriteID, Epoch: req.Epoch})
		case "Dispatched", "Unknown":
			if j.Observation == nil {
				if plan.Receiver == nil {
					return stop(store.OpFailed, "no-receiver")
				}
				q := mydc.SecretWrite{Realm: j.Realm, ID: j.WriteID, Mode: "recover"}
				if !j.Attempted && status == "Dispatched" {
					if values == nil {
						return stop(store.OpRunning, "needs-input")
					}
					q.Mode, q.Values = "execute", values
				}
				if !j.Attempted {
					// stored before the input goes, so it is never sent twice
					j.Attempted = true
					if err := s.opt.Store.UpdateOp(parent); err != nil {
						return err
					}
				}
				reply, _ := c.WriteVault(ctx, j.Realm, *plan.Receiver, q)
				q.Values = nil
				o := reply.Observation
				if o == nil {
					return stop(store.OpUnknown, "input-unknown")
				}
				if o.Tenant != j.Realm || !reflect.DeepEqual(o.Request, req) || o.Operation != plan.Write.Operation || o.Generation != plan.Write.Generation {
					return stop(store.OpFailed, "observation-mismatch")
				}
				j.Observation, _ = json.Marshal(o)
				if err := s.opt.Store.UpdateOp(parent); err != nil {
					return err
				}
			}
			var o secrets.WriteObservation
			if err := json.Unmarshal(j.Observation, &o); err != nil {
				return err
			}
			if ok, err = step(2, mydc.ActionVaultObserveWrite, plan.TreeRevision, control.VaultObserve{Observation: o}); ok {
				j.Observation = nil
			}
		case "StoredUnreferenced":
			ok, err = step(3, mydc.ActionVaultPublishWrite, plan.TreeRevision, control.VaultWriteAction{Realm: j.Realm, ID: j.WriteID, Epoch: req.Epoch, ObjectRevision: plan.Write.ExpectedObjectRevision})
		default:
			return stop(store.OpUnknown, "write-"+strings.ToLower(status))
		}
		if err != nil || !ok {
			return err
		}
	}
	return stop(store.OpUnknown, "write-unsettled")
}
