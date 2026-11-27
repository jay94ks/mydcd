// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"slices"
	"time"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/sfcp"
	checker "github.com/jay94ks/seafield/internal/workload/lifecycle"
)

// ComposeSourcePreparation precedes ComposeIntent: source effects need an
// immutable input before a Blueprint/current inventory CAS can be obtained.
// It is private CLI provenance, not another cluster operation or a Ready fact.
type ComposeSourcePreparation struct {
	Standalone                *control.StandaloneDefinition `json:",omitempty"`
	Schema                    uint8
	Profile, Cluster          [32]byte
	User, ID, Tenant          string
	Project, Deployment, Node string
	Provider                  CheckerProvider
	Length                    int
	DocumentDigest            [32]byte
	Initiator                 access.Session
	At                        int64
	Signature                 []byte
	Document                  []byte `json:"-"`
	scripts                   map[string]checker.Script
}

type composeSourcePreparation ComposeSourcePreparation

func (ComposeSourcePreparation) MarshalJSON() ([]byte, error) { return nil, ErrPrivateState }
func (ComposeSourcePreparation) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "[redacted compose source preparation]")
}

func composeSourceBytes(i ComposeSourcePreparation) []byte {
	i.Signature = nil
	raw, _ := json.Marshal(composeSourcePreparation(i))
	return append([]byte("sfc-compose-source-preparation-1\x00"), raw...)
}

func (i ComposeSourcePreparation) Digest() [32]byte {
	return sha256.Sum256(append(composeSourceBytes(i), i.Signature...))
}

func composeCheckerID(parent [32]byte, alias string) string {
	raw, _ := json.Marshal(struct {
		Parent [32]byte
		Alias  string
	}{parent, alias})
	digest := sha256.Sum256(append([]byte("sfc-compose-source-child-1\x00"), raw...))
	return "compose-source/" + hex.EncodeToString(digest[:])
}

func (i ComposeSourcePreparation) SourceID(alias string) string {
	return composeCheckerID(i.Digest(), alias)
}

func (i ComposeSourcePreparation) Aliases() []string {
	var names []string
	for alias, script := range i.scripts {
		if script.Ref == nil {
			names = append(names, alias)
		}
	}
	slices.Sort(names)
	return names
}

func (i ComposeSourcePreparation) Source(alias string) (checker.SourceDescriptor, []byte, error) {
	script, ok := i.scripts[alias]
	if !ok || script.Ref != nil {
		return checker.SourceDescriptor{}, nil, ErrPrivateState
	}
	d, err := script.Descriptor(i.Tenant)
	if err != nil {
		return checker.SourceDescriptor{}, nil, err
	}
	return d, []byte(script.Source), nil
}

func validComposeSourceMetadata(c Client, user string, i ComposeSourcePreparation) bool {
	name := func(s string) bool { return s == "" || checker.ValidScriptName(s) }
	s := i.Initiator
	return i.Schema == 1 && i.Profile == c.JournalProfile() && i.Cluster == c.Cluster && i.User == user && safeID(user) && safeID(i.ID) && checker.ValidScriptName(i.Tenant) && name(i.Project) && name(i.Deployment) && name(i.Node) && checkerProviderValid(i.Provider) && i.Length > 0 && i.Length <= deployment.ArtifactMaxBytes && i.DocumentDigest != ([32]byte{}) && s.Schema == 1 && s.Cluster == i.Cluster && s.User == user && s.Key != ([32]byte{}) && s.Issuer != ([32]byte{}) && s.IssuedAt >= 0 && i.At >= s.IssuedAt && i.At < s.ExpiresAt && s.ExpiresAt-s.IssuedAt <= access.MaxSessionSeconds && ed25519.Verify(s.Issuer[:], access.SessionBytes(s), s.Signature) && ed25519.Verify(s.Key[:], composeSourceBytes(i), i.Signature)
}

func prepareComposeSources(i ComposeSourcePreparation) (ComposeSourcePreparation, error) {
	if len(i.Document) != i.Length || sha256.Sum256(i.Document) != i.DocumentDigest {
		return ComposeSourcePreparation{}, ErrPrivateState
	}
	parse := deployment.ParseApp
	if i.Standalone != nil {
		parse = deployment.ParseStandalone
	}
	c, err := parse(i.Document)
	if err != nil || c.Sfc.Tenant != "" && c.Sfc.Tenant != i.Tenant {
		return ComposeSourcePreparation{}, ErrPrivateState
	}
	if i.Standalone != nil {
		if c.Name != "" && c.Name != i.Standalone.Name || i.Project != i.Standalone.Name {
			return ComposeSourcePreparation{}, ErrPrivateState
		}
	}
	if c.Name != "" && i.Project != "" && c.Name != i.Project || c.Sfc.Deployment != "" && i.Deployment != "" && c.Sfc.Deployment != i.Deployment || c.Name == "" && i.Project == "" {
		return ComposeSourcePreparation{}, ErrPrivateState
	}
	program, _, err := c.LifecycleProgram()
	if err != nil {
		return ComposeSourcePreparation{}, err
	}
	i.scripts = program.Scripts
	if len(i.Aliases()) == 0 {
		return ComposeSourcePreparation{}, ErrPrivateState
	}
	return i, nil
}

func readComposeSources(root *os.Root, c Client, user, id string) (ComposeSourcePreparation, error) {
	if _, err := root.Lstat("sources.json"); os.IsNotExist(err) {
		return ComposeSourcePreparation{}, ErrOperationMissing
	}
	var disk composeSourcePreparation
	if readPrivate(root, "sources.json", &disk) != nil {
		return ComposeSourcePreparation{}, ErrPrivateState
	}
	i := ComposeSourcePreparation(disk)
	if i.ID != id || !validComposeSourceMetadata(c, user, i) {
		return ComposeSourcePreparation{}, ErrPrivateState
	}
	for index, start := 0, 0; start < i.Length; index, start = index+1, start+deployment.ArtifactPartBytes {
		var part composePart
		if readPrivate(root, fmt.Sprintf("source-part-%03d.json", index), &part) != nil || len(part.Data) != min(deployment.ArtifactPartBytes, i.Length-start) {
			return ComposeSourcePreparation{}, ErrPrivateState
		}
		i.Document = append(i.Document, part.Data...)
	}
	return prepareComposeSources(i)
}

func LoadComposeSources(home string, c Client, current access.Session, id string) (ComposeSourcePreparation, error) {
	if c.Verify(current) != nil {
		return ComposeSourcePreparation{}, ErrPrivateState
	}
	r, err := composeRoot(home, c, current.User, id, false)
	if err != nil {
		return ComposeSourcePreparation{}, err
	}
	defer r.Close()
	return readComposeSources(r, c, current.User, id)
}

func StageComposeSources(home string, c Client, current access.Session, id, tenant, project, deploymentID, node string, provider sfcp.Peer, document []byte, standalone ...*control.StandaloneDefinition) (ComposeSourcePreparation, error) {
	if c.Verify(current) != nil || c.Self == nil {
		return ComposeSourcePreparation{}, ErrPrivateState
	}
	if len(standalone) > 1 {
		return ComposeSourcePreparation{}, ErrPrivateState
	}
	var definition *control.StandaloneDefinition
	if len(standalone) == 1 {
		definition = standalone[0]
	}
	i := ComposeSourcePreparation{Standalone: definition, Schema: 1, Profile: c.JournalProfile(), Cluster: c.Cluster, User: current.User, ID: id, Tenant: tenant,
		Project: project, Deployment: deploymentID, Node: node, Provider: CheckerProvider{Node: provider.ID, Endpoint: provider.Endpoint, Key: [32]byte(provider.Key)},
		Length: len(document), DocumentDigest: sha256.Sum256(document), Document: bytes.Clone(document), Initiator: current, At: time.Now().Unix()}
	i.Signature = ed25519.Sign(c.Self.Private, composeSourceBytes(i))
	if !validComposeSourceMetadata(c, current.User, i) {
		return ComposeSourcePreparation{}, ErrPrivateState
	}
	if _, err := CheckerProviderPeer(c, i.Provider); err != nil {
		return ComposeSourcePreparation{}, err
	}
	i, err := prepareComposeSources(i)
	if err != nil {
		return ComposeSourcePreparation{}, err
	}
	r, err := composeRoot(home, c, current.User, id, true)
	if err != nil {
		return ComposeSourcePreparation{}, err
	}
	defer r.Close()
	unlock, err := lockProfile(r)
	if err != nil {
		return ComposeSourcePreparation{}, err
	}
	defer unlock()
	if _, err := r.Lstat("intent.json"); err == nil || !os.IsNotExist(err) {
		return ComposeSourcePreparation{}, ErrPrivateState
	}
	if old, err := readComposeSources(r, c, current.User, id); err == nil {
		if old.Tenant != tenant || old.Project != project || old.Deployment != deploymentID || old.Node != node || old.Provider != i.Provider || !bytes.Equal(old.Document, document) {
			return ComposeSourcePreparation{}, ErrPrivateState
		}
		return old, nil
	} else if err != ErrOperationMissing {
		return ComposeSourcePreparation{}, err
	}
	for index, start := 0, 0; start < i.Length; index, start = index+1, start+deployment.ArtifactPartBytes {
		if err := writePrivate(r, fmt.Sprintf("source-part-%03d.json", index), composePart{i.Document[start:min(i.Length, start+deployment.ArtifactPartBytes)]}); err != nil {
			return ComposeSourcePreparation{}, err
		}
	}
	if err := writePrivate(r, "sources.json", composeSourcePreparation(i)); err != nil {
		return ComposeSourcePreparation{}, err
	}
	return i, nil
}

func ComposeCheckerSourceMatches(parent ComposeSourcePreparation, alias string, child CheckerScriptIntent) bool {
	d, data, err := parent.Source(alias)
	defer clear(data)
	return err == nil && child.Compose != nil && child.Compose.Operation == parent.ID && child.Compose.Parent == parent.Digest() && child.ID == parent.SourceID(alias) && child.Profile == parent.Profile && child.Cluster == parent.Cluster && child.User == parent.User && child.Name == alias && child.Tenant == parent.Tenant && child.Provider == parent.Provider && child.Descriptor.ContentDigest() == d.ContentDigest() && bytes.Equal(child.Data, data)
}

func StageComposeCheckerSource(home string, c Client, current access.Session, parent ComposeSourcePreparation, alias string) (CheckerScriptIntent, error) {
	if c.Verify(current) != nil || !validComposeSourceMetadata(c, current.User, parent) || len(parent.Document) != parent.Length || sha256.Sum256(parent.Document) != parent.DocumentDigest {
		return CheckerScriptIntent{}, ErrPrivateState
	}
	r, err := composeRoot(home, c, current.User, parent.ID, false)
	if err != nil {
		return CheckerScriptIntent{}, err
	}
	var disk composeSourcePreparation
	err = readPrivate(r, "sources.json", &disk)
	r.Close()
	if err != nil || !samePublic(disk, composeSourcePreparation(parent)) {
		return CheckerScriptIntent{}, ErrPrivateState
	}
	d, data, err := parent.Source(alias)
	if err != nil {
		return CheckerScriptIntent{}, err
	}
	defer clear(data)
	provider, err := CheckerProviderPeer(c, parent.Provider)
	if err != nil {
		return CheckerScriptIntent{}, err
	}
	// Preserve the original endpoint as provenance; sends use current trust.
	provider.Endpoint = parent.Provider.Endpoint
	child, err := stageCheckerScript(home, c, current, parent.SourceID(alias), alias, provider, d, data, 0, &CheckerComposeSource{Operation: parent.ID, Parent: parent.Digest()})
	if err != nil {
		return CheckerScriptIntent{}, err
	}
	if !ComposeCheckerSourceMatches(parent, alias, child) {
		return CheckerScriptIntent{}, ErrPrivateState
	}
	return child, nil
}

func checkPreparedComposePlan(home string, c Client, current access.Session, parent ComposeSourcePreparation, plan deployment.Blueprint) error {
	if parent.Tenant != plan.Scope().Tenant {
		return ErrPrivateState
	}
	parse := deployment.ParseApp
	if parent.Standalone != nil {
		parse = deployment.ParseStandalone
	}
	doc, err := parse(parent.Document)
	if err != nil {
		return ErrPrivateState
	}
	app, deploymentID := doc.Name, doc.Sfc.Deployment
	if app == "" {
		app = parent.Project
	}
	if deploymentID == "" {
		deploymentID = parent.Deployment
	}
	if deploymentID == "" {
		// app.yaml names no deployment: the server picks it (the app's
		// current one, else the app name).
		deploymentID = plan.Scope().Deployment
	}
	if parent.Standalone != nil {
		if plan.StandaloneName() != parent.Standalone.Name {
			return ErrPrivateState
		}
		app = plan.Scope().App
		apply := plan.OriginalDocument()
		if apply == nil {
			return ErrPrivateState
		}
		doc, err = apply.EffectiveInput(plan.Scope())
		if err != nil {
			return err
		}
	}
	if app != plan.Scope().App || deploymentID != plan.Scope().Deployment {
		return ErrPrivateState
	}
	facts := map[string]checker.SourceFact{}
	for _, alias := range parent.Aliases() {
		child, err := LoadCheckerScript(home, c, current, parent.SourceID(alias))
		if err != nil || !ComposeCheckerSourceMatches(parent, alias, child) || child.Fact == nil {
			return ErrPrivateState
		}
		facts[alias] = child.Fact.Clone()
	}
	return plan.CheckLifecycleInputs(doc, facts)
}
