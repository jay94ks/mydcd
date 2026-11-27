// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"slices"
	"strings"
	"testing"

	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/config"
)

func s1Book(key string) bool {
	return slices.Contains([]string{NodeShellKey, VPSKey, ImageCacheKey, TunnelReconnectKey, CompactKey, ClusterBackupKey}, key)
}

// legacyReduce is Reduce as it was before S2 moved the remaining books into
// the registry, kept verbatim so the move is checked against it.
func legacyReduce(p Policy, s state.State, command state.Command) (map[string][]byte, state.Code) {
	if book, ok := bookFor(command.Key); ok && s1Book(command.Key) {
		return book.Reduce(p, s, command)
	}
	if command.Key == CertificatesKey {
		return p.reduceCertificates(s, command)
	}
	if command.Key == CredentialsKey {
		return p.reduceCredentialStore(s, command)
	}
	if command.Key == IngressManagementKey {
		return p.reduceIngressManagement(s, command)
	}
	if command.Key == ImageBuildKey {
		return p.reduceImageBuilds(s, command)
	}
	if command.Key == RegistryMaintenanceKey {
		return p.reduceRegistryMaintenance(s, command)
	}
	if command.Kind == state.ModuleReport && command.Key == CatalogKey {
		return p.reduceTenantRetirementReport(s, command)
	}
	if command.Key == ExternalRegistriesKey {
		return p.reduceExternalRegistries(s, command)
	}
	if (command.Kind == state.Module || command.Kind == state.ModuleReport) && command.Key == RegistriesKey {
		return p.reduceRegistries(s, command)
	}
	if command.Key == LifecycleKey {
		return p.reduceLifecycle(s, command)
	}
	if (command.Kind == state.Module || command.Kind == state.ModuleReport) && command.Key == NodeStorageKey {
		return p.reduceNodeStorage(s, command)
	}
	if command.Kind == state.ModuleReport && command.Key == VaultKey {
		return p.reduceVaultHolder(s, command)
	}
	if command.Kind == state.Module && command.Key == VaultKey {
		if strings.HasPrefix(command.Actor, "node/") {
			return p.reduceVaultApproval(s, command)
		}
		return p.reduceVault(s, command)
	}
	if (command.Kind == state.Module || command.Kind == state.ModuleReport || command.Kind == state.ModuleUpload || command.Kind == state.ModuleAppDown) && command.Key == AppsKey {
		return p.reduceApps(s, command)
	}
	if (command.Kind == state.Module || command.Kind == state.ModuleReport) && command.Key == VolumesKey {
		return p.reduceVolumes(s, command)
	}
	if command.Kind == state.ModuleWindow {
		return p.reduceStorage(s, command)
	}
	if command.Kind == state.ModuleReport && command.Key == ResourcesKey && strings.HasPrefix(command.Actor, "node/") {
		if bridgeClosedValue(command.Value) {
			return p.reduceBridgeClosedReport(s, command)
		}
		return p.reduceSystemNetworkReport(s, command)
	}
	if command.Kind == state.Module && command.Key == ResourcesKey {
		return p.reduceResources(s, command)
	}
	if command.Kind == state.Module && command.Key == MembersKey {
		return p.reduceMembers(s, command)
	}
	// Books added after the move have no older branch: their own reducer.
	if command.Key == ClusterFirewallKey {
		return p.reduceClusterFirewall(s, command)
	}
	if command.Kind != state.Module || command.Key != CatalogKey {
		return nil, state.Invalid
	}
	return p.reduceCatalog(s, command)
}

// Moving a book into the registry must not change any verdict, or replay of
// existing Raft logs differs (R18 S2). Every root and every command kind,
// from a user, a node and a key actor, must get the same answer as before.
func TestBookDispatchKeepsLegacyVerdicts(t *testing.T) {
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{101}, 32))
	var key [32]byte
	copy(key[:], private.Public().(ed25519.PublicKey))
	p := Policy{Cluster: [32]byte{31}, BootstrapKey: key, TrustRoot: key, Genesis: config.Peer{ID: "source", Key: hex.EncodeToString(key[:]), Endpoint: "127.0.0.1:7443", Voter: true}}
	s, err := state.New("admin")
	if err != nil {
		t.Fatal(err)
	}
	keys := append(slices.Clone(bookRoots), StorageKey, "control/unknown")
	actors := []string{"user/admin", "node/" + hex.EncodeToString(key[:]), hex.EncodeToString(key[:])}
	values := []string{"", "{}", `{"Schema":1}`, `{"Closed":true}`}
	for _, k := range keys {
		for kind := state.Mutate; kind <= state.ModuleAppDown; kind++ {
			for _, actor := range actors {
				for _, v := range values {
					cmd := state.Command{Kind: kind, Actor: actor, Epoch: 1, Key: k, Value: v}
					gotW, gotC := p.Reduce(s, cmd)
					wantW, wantC := legacyReduce(p, s, cmd)
					if gotC != wantC || len(gotW) != len(wantW) {
						t.Errorf("%s kind %d actor %s value %q: got %v/%d, want %v/%d", k, kind, strings.SplitN(actor, "/", 2)[0], v, gotC, len(gotW), wantC, len(wantW))
					}
				}
			}
		}
	}
}
