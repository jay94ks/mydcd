// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"math"
	"slices"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/lifecycle"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/deployment"
)

var ErrAppSourceUnavailable = errors.New("original application document was not retained")
var ErrAppSourceReclaimed = errors.New("application document version was reclaimed")
var ErrAppSourceSection = errors.New("application document section is not present")

// Revision is the monotonically increasing accepted-document number, distinct
// from inventory bookkeeping and the FSM root revision. No secret is fetched.
type AppRevisionView struct {
	Revision                uint64
	Tenant, App, Deployment string
	Digest, Plan            [32]byte
	Length                  int
	SubmittedBy, Operation  string
	AcceptedAt, CompletedAt uint64
	Source, Commit, Status  string
	Automatic               bool
	OriginalRetained        bool
	OverlayDigest           [32]byte
	OverlayLength           int
	LocalRevision           uint64   `json:",omitempty"`
	LocalActor              string   `json:",omitempty"`
	LocalDigest             [32]byte `json:",omitzero"`
	LocalLength             int      `json:",omitempty"`
}

type AppFieldOverlay = deployment.AppFieldOverlay

type appVersion struct {
	AppRevisionView
	Body      []byte            `json:",omitempty"`
	Overlays  []AppFieldOverlay `json:",omitempty"`
	LocalBody []byte            `json:",omitempty"`
}

// All counters and timestamps come from accepted inputs/Execution. Calling
// this while encoding the same FSM candidate makes source/history atomic with
// Inventory acceptance, including CD and a positively completed Volume move.
func captureAppVersion(entry appEntry) (appEntry, error) {
	entry.Versions = slices.Clone(entry.Versions)
	for i := range entry.Versions {
		v := &entry.Versions[i]
		if result, ok := entry.Inventory.Operation(v.Operation); ok {
			v.Status = result.Status
			// Preserve deployment completion, not a later retirement timestamp.
			if v.CompletedAt == 0 && result.Status == "Succeeded" {
				v.CompletedAt = result.CompletedAt
			}
		}
	}
	execution, active := entry.Inventory.Execution()
	if !active || entry.Sync != nil && entry.Sync.Recreate != nil {
		return entry, nil
	}
	operation := execution.ActiveOperation()
	for _, version := range entry.Versions {
		if version.Operation == operation {
			return entry, nil
		}
	}
	if entry.LastVersion == math.MaxUint64 || len(entry.Versions) >= 128 {
		return entry, ErrCatalog
	}
	blueprint := execution.Blueprint()
	scope := blueprint.Scope()
	view := AppRevisionView{Revision: entry.LastVersion + 1, Tenant: scope.Tenant, App: scope.App, Deployment: scope.Deployment, Plan: blueprint.Digest(), SubmittedBy: entry.Origin.Session.User, Operation: operation, AcceptedAt: uint64(entry.Origin.At), Source: "upload", Status: execution.Status()}
	if summary, ok := entry.Inventory.Active(); ok {
		view.CompletedAt = summary.CompletedAt
	}
	if sync := entry.Sync; sync != nil {
		view.Source = "cd"
		if sync.User != nil {
			view.SubmittedBy, view.AcceptedAt = sync.User.Session.User, uint64(sync.User.At)
			if sync.User.Change.Action == "begin-volume-move" {
				view.Source = "move"
			}
		} else if sync.Member != nil {
			view.Automatic, view.AcceptedAt = true, sync.Member.At
		}
		if entry.Delivery != nil {
			if selected, ok := entry.Delivery.Selection(); ok && selected.Operation == operation {
				view.Commit = selected.Commit
			}
		}
	} else if entry.Origin.Change.Action == "begin-volume-move" {
		view.Source = "move"
	}
	version := appVersion{AppRevisionView: view}
	if document := blueprint.OriginalDocument(); document != nil {
		version.Body = document.Body
		version.Digest, version.Length, version.OriginalRetained = sha256.Sum256(document.Body), len(document.Body), true
		if local := document.LocalServices; local != nil {
			version.LocalBody = bytes.Clone(local.Body)
			version.LocalRevision, version.LocalActor = local.Revision, local.Actor
			version.LocalDigest, version.LocalLength = local.Digest, len(local.Body)
		}
		for _, overlay := range document.Overrides {
			version.Overlays = append(version.Overlays, AppFieldOverlay{Path: slices.Clone(overlay.Path), Value: bytes.Clone(overlay.Value), Revision: overlay.Revision, Actor: overlay.Actor})
		}
	}
	if len(version.Overlays) != 0 {
		raw, _ := json.Marshal(version.Overlays)
		version.OverlayLength, version.OverlayDigest = len(raw), sha256.Sum256(raw)
	}
	entry.LastVersion = version.Revision
	entry.Versions = append(entry.Versions, version)
	return entry, nil
}

func validAppVersions(entry appEntry) bool {
	if len(entry.Versions) > 128 {
		return false
	}
	scope := entry.Inventory.Scope()
	previous := uint64(0)
	operations := map[string]bool{}
	for _, v := range entry.Versions {
		if v.Revision == 0 || v.Revision <= previous || v.Revision > entry.LastVersion || v.Tenant != scope.Tenant || v.App != scope.App || v.Deployment != scope.Deployment || v.Plan == ([32]byte{}) || !lifecycle.ValidID(v.SubmittedBy) || !lifecycle.ValidID(v.Operation) || operations[v.Operation] || v.CompletedAt != 0 && v.CompletedAt < v.AcceptedAt || len(v.Overlays) > 128 {
			return false
		}
		switch v.Status {
		case "Planned", "Applying", "Verifying", "Unknown", "Paused", "Failed", "Succeeded", "Stopping", "Closed", "Retired":
		default:
			return false
		}
		if v.Source != "upload" && v.Source != "cd" && v.Source != "move" || v.Source != "cd" && v.Automatic || v.Commit != "" && (len(v.Commit) != 40 || !lowerHex(v.Commit)) {
			return false
		}
		if v.OriginalRetained {
			if len(v.Body) == 0 || len(v.Body) > deployment.ArtifactMaxBytes || v.Length != len(v.Body) || v.Digest != sha256.Sum256(v.Body) {
				return false
			}
		} else if len(v.Body) != 0 || v.Length != 0 || v.Digest != ([32]byte{}) || len(v.Overlays) != 0 {
			return false
		}
		if len(v.Overlays) == 0 {
			if v.OverlayLength != 0 || v.OverlayDigest != ([32]byte{}) {
				return false
			}
		} else {
			raw, _ := json.Marshal(v.Overlays)
			if len(raw) > deployment.ArtifactMaxBytes || v.OverlayLength != len(raw) || v.OverlayDigest != sha256.Sum256(raw) {
				return false
			}
		}
		for _, overlay := range v.Overlays {
			if !deployment.AllowedAppOverride(overlay.Path) || !json.Valid(overlay.Value) || overlay.Revision == 0 || !lifecycle.ValidID(overlay.Actor) {
				return false
			}
		}
		if len(v.LocalBody) == 0 {
			if v.LocalRevision != 0 || v.LocalActor != "" || v.LocalDigest != ([32]byte{}) || v.LocalLength != 0 {
				return false
			}
		} else if !v.OriginalRetained || v.LocalRevision == 0 || !lifecycle.ValidID(v.LocalActor) || len(v.LocalBody) > deployment.ArtifactMaxBytes || v.LocalLength != len(v.LocalBody) || v.LocalDigest != sha256.Sum256(v.LocalBody) {
			return false
		}
		previous, operations[v.Operation] = v.Revision, true
	}
	return len(entry.Versions) == 0 || previous == entry.LastVersion
}

func lowerHex(text string) bool {
	for _, c := range text {
		if c < '0' || c > '9' && c < 'a' || c > 'f' {
			return false
		}
	}
	return true
}

// AppSourceSelection uses an app deployment identity, not a native/container ID.
// Revision zero selects the latest accepted document for the first part only.
type AppSourceSelection struct {
	Standalone      string `json:",omitempty"`
	Section         string `json:",omitempty"`
	App, Deployment string
	Revision        uint64
	Part            int
	Digest          [32]byte
}

func (q AppSourceSelection) Valid(revisions bool) bool {
	if !(q.Standalone == "" && lifecycle.ValidID(q.App) || q.App == "" && lifecycle.ValidID(q.Standalone)) || q.Deployment != "" && !lifecycle.ValidID(q.Deployment) || q.Part < 0 || q.Part >= (deployment.ArtifactMaxBytes+deployment.ArtifactPartBytes-1)/deployment.ArtifactPartBytes {
		return false
	}
	if q.Section != "" && q.Section != "source" && q.Section != "overlays" && q.Section != "local-services" && q.Section != "pending-local" {
		return false
	}
	if q.Section == "pending-local" && (q.Standalone != "" || q.Revision != 0) {
		return false
	}
	if revisions {
		return q.Section == "" && q.Revision == 0 && q.Part == 0 && q.Digest == ([32]byte{})
	}
	return q.Part == 0 || q.Revision != 0 && q.Digest != ([32]byte{})
}

type AppSourcePart struct {
	Standalone   string `json:",omitempty"`
	Section      string
	Version      AppRevisionView
	RootRevision uint64
	Part         int
	Data         []byte
	// Pending: the "pending-local" section's document, the local services
	// put-app-local-services accepted for the next candidate (not yet in a
	// version). Version is then the latest version, for its identity only.
	Pending *AppLocalPending `json:",omitempty"`
}

// AppLocalPending describes the pending local services document.
type AppLocalPending struct {
	Revision uint64
	Actor    string
	Length   int
	Digest   [32]byte
}

type AppRevisionsPage struct {
	Versions     []AppRevisionView
	Next         string
	RootRevision uint64
}

func (p Policy) appSourceEntry(s state.State, session access.Session, at int64, tenant string, q AppSourceSelection) (appEntry, error) {
	current, err := p.Current(s)
	if err != nil || !lifecycle.ValidID(tenant) {
		return appEntry{}, access.ErrDenied
	}
	c, err := current.Catalog(s)
	if err != nil || c.AuthorizeSession(session, current.Cluster, current.Issuer(session.Issuer), at, tenant, access.Read, "") != nil {
		return appEntry{}, access.ErrDenied
	}
	a, err := current.readOnlyApps(s)
	if err != nil {
		return appEntry{}, err
	}
	scope := q.App
	if q.Standalone != "" {
		var ok bool
		scope, ok = a.StandaloneScope(tenant, q.Standalone)
		if !ok {
			return appEntry{}, access.ErrDenied
		}
	} else if a.IsStandalone(tenant, scope) {
		return appEntry{}, access.ErrDenied
	}
	entry, found := a.entries[appKey(tenant, scope)]
	if !found || q.Deployment != "" && entry.Inventory.Scope().Deployment != q.Deployment {
		return appEntry{}, access.ErrDenied
	}
	return entry, nil
}

func appSourceBasis(s state.State, session access.Session, tenant string, q AppSourceSelection) [32]byte {
	raw, _ := json.Marshal(struct {
		Apps, Catalog, Members uint64
		User, Tenant           string
		Scopes                 []access.Scope
		Query                  AppSourceSelection
	}{s.Object(AppsKey).Revision, s.Object(CatalogKey).Revision, s.Object(MembersKey).Revision, session.User, tenant, session.Scopes, q})
	return sha256.Sum256(append([]byte("sfc-app-revisions-1\x00"), raw...))
}

func publicAppRevision(v appVersion) AppRevisionView {
	raw, _ := json.Marshal(v.AppRevisionView)
	var owned AppRevisionView
	_ = json.Unmarshal(raw, &owned)
	return owned
}

func (p Policy) AppRevisions(s state.State, session access.Session, at int64, tenant string, q AppSourceSelection, after string) (AppRevisionsPage, error) {
	if !q.Valid(true) {
		return AppRevisionsPage{}, access.ErrInvalid
	}
	entry, err := p.appSourceEntry(s, session, at, tenant, q)
	if err != nil {
		return AppRevisionsPage{}, err
	}
	basis := appSourceBasis(s, session, tenant, q)
	offset, err := taskCursor(after, basis)
	if err != nil || uint64(offset) > uint64(len(entry.Versions)) {
		if err == nil {
			err = access.ErrInvalid
		}
		return AppRevisionsPage{}, err
	}
	page := AppRevisionsPage{Versions: []AppRevisionView{}, RootRevision: s.Object(AppsKey).Revision}
	end, size := int(offset), 0
	for end < len(entry.Versions) && end-int(offset) < 16 {
		view := publicAppRevision(entry.Versions[len(entry.Versions)-1-end])
		raw, _ := json.Marshal(view)
		if size+len(raw) > 64<<10 {
			if end == int(offset) {
				return AppRevisionsPage{}, access.ErrInvalid
			}
			break
		}
		page.Versions = append(page.Versions, view)
		size += len(raw)
		end++
	}
	if end < len(entry.Versions) {
		page.Next = nextTaskCursor(basis, uint32(end))
	}
	return page, nil
}

func (p Policy) AppSource(s state.State, session access.Session, at int64, tenant string, q AppSourceSelection) (AppSourcePart, error) {
	if !q.Valid(false) {
		return AppSourcePart{}, access.ErrInvalid
	}
	entry, err := p.appSourceEntry(s, session, at, tenant, q)
	if err != nil {
		return AppSourcePart{}, err
	}
	wanted := q.Revision
	if wanted == 0 {
		wanted = entry.LastVersion
	}
	if q.Section == "pending-local" {
		return pendingLocalPart(s, entry, wanted, q)
	}
	for _, version := range entry.Versions {
		if version.Revision != wanted {
			continue
		}
		if !version.OriginalRetained {
			return AppSourcePart{}, ErrAppSourceUnavailable
		}
		section, body, digest := "source", version.Body, version.Digest
		if q.Section == "overlays" {
			if len(version.Overlays) == 0 {
				return AppSourcePart{}, ErrAppSourceSection
			}
			section, digest = "overlays", version.OverlayDigest
			body, _ = json.Marshal(version.Overlays)
		}
		if q.Section == "local-services" {
			if len(version.LocalBody) == 0 {
				return AppSourcePart{}, ErrAppSourceSection
			}
			section, body, digest = "local-services", version.LocalBody, version.LocalDigest
		}
		if q.Digest != ([32]byte{}) && q.Digest != digest {
			return AppSourcePart{}, access.ErrConflict
		}
		start := q.Part * deployment.ArtifactPartBytes
		if start >= len(body) {
			return AppSourcePart{}, access.ErrInvalid
		}
		return AppSourcePart{Standalone: q.Standalone, Section: section, Version: publicAppRevision(version), RootRevision: s.Object(AppsKey).Revision, Part: q.Part, Data: bytes.Clone(body[start:min(start+deployment.ArtifactPartBytes, len(body))])}, nil
	}
	if wanted != 0 && wanted <= entry.LastVersion {
		return AppSourcePart{}, ErrAppSourceReclaimed
	}
	return AppSourcePart{}, ErrAppSourceUnavailable
}

// pendingLocalPart: one part of the CD app's pending local services
// document (put-app-local-services before the next sync takes it).
func pendingLocalPart(s state.State, entry appEntry, latest uint64, q AppSourceSelection) (AppSourcePart, error) {
	var doc *deployment.LocalServicesDocument
	if entry.Delivery != nil {
		doc = entry.Delivery.LocalServices()
	}
	if doc == nil || len(doc.Body) == 0 {
		return AppSourcePart{}, ErrAppSourceSection
	}
	if q.Digest != ([32]byte{}) && q.Digest != doc.Digest {
		return AppSourcePart{}, access.ErrConflict
	}
	i := slices.IndexFunc(entry.Versions, func(v appVersion) bool { return v.Revision == latest })
	if i < 0 {
		return AppSourcePart{}, ErrAppSourceUnavailable
	}
	start := q.Part * deployment.ArtifactPartBytes
	if start >= len(doc.Body) {
		return AppSourcePart{}, access.ErrInvalid
	}
	return AppSourcePart{Section: "pending-local", Version: publicAppRevision(entry.Versions[i]), RootRevision: s.Object(AppsKey).Revision, Part: q.Part,
		Data:    bytes.Clone(doc.Body[start:min(start+deployment.ArtifactPartBytes, len(doc.Body))]),
		Pending: &AppLocalPending{Revision: doc.Revision, Actor: doc.Actor, Length: len(doc.Body), Digest: doc.Digest}}, nil
}
