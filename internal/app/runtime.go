// SPDX-License-Identifier: Apache-2.0

// Package app wires runtime owners; executable command handling stays in cmd.
package app

import (
	"context"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"github.com/jay94ks/mydcd/internal/bootstrap"
	"github.com/jay94ks/mydcd/internal/cluster"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/cluster/lifecycle"
	"github.com/jay94ks/mydcd/internal/cluster/membership"
	"github.com/jay94ks/mydcd/internal/config"
	"github.com/jay94ks/mydcd/internal/containerops"
	"github.com/jay94ks/mydcd/internal/credentials"
	"github.com/jay94ks/mydcd/internal/deployment"
	"github.com/jay94ks/mydcd/internal/desired"
	"github.com/jay94ks/mydcd/internal/engine"
	"github.com/jay94ks/mydcd/internal/eventlog"
	"github.com/jay94ks/mydcd/internal/identity"
	"github.com/jay94ks/mydcd/internal/imagebuild"
	"github.com/jay94ks/mydcd/internal/ingress"
	"github.com/jay94ks/mydcd/internal/mydcp"
	"github.com/jay94ks/mydcd/internal/network"
	"github.com/jay94ks/mydcd/internal/network/services"
	"github.com/jay94ks/mydcd/internal/nodestorage"
	"github.com/jay94ks/mydcd/internal/observability"
	"github.com/jay94ks/mydcd/internal/reconcile"
	"github.com/jay94ks/mydcd/internal/servicecall"
	"github.com/jay94ks/mydcd/internal/storage"
	"github.com/jay94ks/mydcd/internal/userauth"
	"github.com/jay94ks/mydcd/internal/workload"
	checker "github.com/jay94ks/mydcd/internal/workload/lifecycle"
	"github.com/jay94ks/mydcd/internal/workload/volumes"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hashicorp/raft"
)

type Runtime struct {
	serviceCallLimit          servicecall.Limiter
	cdProbeLimit              servicecall.Limiter
	serviceCAs                map[string]*x509.CertPool
	moduleStart               func() error
	parentRuntime             *Runtime
	nativeRoot                string
	controlIdentity           *identity.Identity
	historicalOwner           bool
	nativeOwnerMu             sync.RWMutex
	nativeOwners              []*Runtime
	identityRestart           chan struct{}
	identityRestartOnce       sync.Once
	registryPruneMu           sync.Mutex
	registryPruneLoaded       map[string]registryPrunePreviewRecord
	registryMaintenanceBusy   bool
	registryMaintenanceCursor int
	imageCacheBusy            bool
	tunnelBusy                bool
	compactBusy               bool
	logPages                  containerops.ReadPages
	observationMu             sync.Mutex
	observationCPU            observability.CPUCounter
	observationContainers     map[string]observedContainerCPU
	Identity                  *identity.Identity
	Mesh                      *mydcp.Transport
	engine                    *cluster.Engine
	mu                        sync.RWMutex
	closeOnce                 sync.Once
	closeErr                  error
	ctx                       context.Context
	cancel                    context.CancelFunc
	wg                        sync.WaitGroup
	life                      sync.RWMutex
	closed                    bool
	policy                    desired.Policy
	controlPolicy             control.Policy
	owner                     string
	docker                    *engine.Client
	network                   *network.Manager
	dns                       *services.DNSOwner
	dnsMu                     sync.RWMutex
	dnsPolicies               dnsPolicyCache
	dnsPath                   string
	tunnel                    *tunnelRuntime
	networkEnabled            bool
	workload                  *workload.Manager
	ingress                   *ingress.Manager
	registryMu                sync.Mutex
	imageUseMu                sync.Mutex // recipe resolution/publication versus cache removal
	externalReaderMu          sync.Mutex
	externalReaders           map[string]*externalReaderSlot
	registryFailed            atomic.Bool
	registryBoot              [32]byte
	registryRecords           map[string]registryOwnerRecord
	registrySessions          map[string]*registrySession
	reports                   *storage.DB
	events                    *eventlog.Store
	eventError                error
	dockerEventError          error
	eventPeerCursor           int
	eventPeers                map[[32]byte]eventPeerSynced // managedEventLoop only
	standaloneMu              sync.Mutex
	standaloneConnections     map[string]int
	standaloneDisconnected    map[string]int64
	userExecMu                sync.Mutex
	userExecStoreFailed       bool
	routeMu                   sync.Mutex
	routeStoreFailed          bool
	routeDriver               *network.TunnelDriver
	routeGates                map[[32]byte]*routePacketGate
	routeAdmission            atomic.Pointer[routeAdmissionObservation]
	routeAdmissionError       atomic.Pointer[routeAdmissionObservation]
	routeFlowCloseCursor      uint64 // Scheduling only; no resource or admission authority.
	isolationMu               sync.Mutex
	isolationFailed           bool
	checkerSources            *checker.SourceStore
	checkerSourceBudget       *checker.SourceCacheBudget
	checkerCacheNext          time.Time
	checkerCacheRoot          checkerCacheRoot
	checkerCompiler           *checker.CompilerOwner
	compilerError             error
	checkerPreparationMu      sync.Mutex
	checkerPreparation        *checkerPreparationWork
	checkerRunMu              sync.Mutex
	checkerRecovered          bool
	checkerObservationSizes   map[string]int
	checkerRemoteMu           sync.Mutex // provider I/O never takes checkerRunMu
	checkerRemoteSizes        map[string]int
	checkerRemoteReady        bool
	reportMu                  sync.Mutex
	reportWake                chan struct{}
	moduleError               error
	appWaitMu                 sync.Mutex
	appWaits                  map[string]string // app step -> last logged wait reason
	renewMu                   sync.Mutex
	renewSent                 map[string]observationRenewal // owner: stage key -> last renewal sent
	renewSeen                 map[string]observationRenewal // leader: tenant/app/stage -> last renewal admitted
	leaderSince               uint64                        // leader: when this node last became leader
	reportError               error
	deliveryErrors            map[string]string
	gitFetcher                *deployment.GitFetcher
	deliverySourceActive      atomic.Int64
	gitCredentials            map[string]config.GitCredential
	installation              *managedInstallation
	memberMu                  sync.Mutex
	credentials               *credentials.Backend
	vaultBackends             map[string]*vaultBackend
	vaultApprovalLife         sync.RWMutex
	vaultApprovals            *reconcile.Journal
	vaultApprovalBudget       *credentials.Budget
	inputLife                 sync.RWMutex
	inputMu                   sync.Mutex
	projections               *deployment.ProjectionStore
	nativeVolumes             *volumes.NativeManager
	fixedVolumes              *volumes.FixedManager
	nodeRoots                 *nodestorage.RootManager
	imageBuildMu              sync.Mutex
	imageBuildNative          *imagebuild.NativeJobs
	imageBuildShutdownError   error // written before imageBuildLoop joins r.wg
	imageBuildError           error
	imageBuildTree            *imageBuildContentCache
	imageBuildDraftAfter      string            // guarded by imageBuildMu; finite GC passes rotate
	imageBuildGeneratedAfter  map[string]string // same gate; per-context original evidence cursor
	activations               *volumes.Activations
	volumeUsageMu             sync.Mutex
	volumeSourceMu            sync.Mutex
	volumeMoveTargetMu        sync.Mutex // joins prepare/restore/final cleanup of original moves
	backupArtifacts           *backupArtifacts
	volumeRestores            *reconcile.Journal
	volumeBackupError         error
	moveCancelLog             sync.Map // move/side -> last cancel wait line
	reportHold                sync.Map // report stream -> moveReportBackoff after a rejection
	nodeShell                 *nodeShellRuntime
}

func Open(c config.Node) (*Runtime, error) {
	if err := CheckNodeApps(c); err != nil {
		return nil, err
	}
	original := c
	var installation bootstrap.Record
	var err error
	c, installation, err = bootstrap.Effective(c)
	if err != nil {
		return nil, err
	}
	self, err := identity.Load(c.Node.IdentityDir)
	if err != nil {
		return nil, err
	}
	key := mydcp.Identity(self.Public)
	clusterID, _ := config.ClusterKey(c.Common.Cluster)
	managedCatalog := control.Policy{Cluster: clusterID, BootstrapKey: installation.Admin, TrustRoot: installation.Root.TrustRoot, Genesis: installation.Genesis}

	peers := map[mydcp.Identity]mydcp.Peer{}
	byID := map[string]mydcp.Peer{}
	servers := make([]raft.Server, 0, len(c.Common.Peers))
	for _, p := range c.Common.Peers {
		full, _ := identity.ParseKey(p.Key)
		peer := mydcp.Peer{ID: p.ID, Endpoint: p.Endpoint, Policy: mydcp.Policy{Key: mydcp.Identity(full), Member: true, Snapshot: true, Respond: true, Read: true, Report: true}}
		if installation.Join != nil {
			peer.Member, peer.Read, peer.Report, peer.Replicate = false, false, false, true
		}
		peers[peer.Key] = peer
		byID[p.ID] = peer
		suffrage := raft.Nonvoter
		if p.Voter {
			suffrage = raft.Voter
		}
		servers = append(servers, raft.Server{ID: raft.ServerID(p.ID), Address: raft.ServerAddress(p.Endpoint), Suffrage: suffrage})
	}
	if own, ok := peers[key]; !ok || own.ID != c.Node.ID {
		return nil, errors.New("local identity does not match approved node ID")
	}
	r := &Runtime{Identity: self, controlIdentity: self, identityRestart: make(chan struct{}), networkEnabled: c.Modules["network"].Enabled}

	r.installation = &managedInstallation{config: original, record: installation}

	r.ctx, r.cancel = context.WithCancel(context.Background())
	ok := false
	defer func() {
		if !ok {
			_ = r.Close()
		}
	}()
	var peerCache, controlPeerCache peerLookupCache
	lookupPurpose := func(key mydcp.Identity, purpose mydcp.Purpose) (mydcp.Peer, bool) {
		packetPolicy := purpose == 0 || purpose == mydcp.Packet || purpose == mydcp.PathControl
		cache := &controlPeerCache
		if packetPolicy {
			cache = &peerCache
		}
		r.mu.RLock()
		engine := r.engine
		r.mu.RUnlock()
		var view cluster.View
		var readErr error
		if engine != nil {
			view, readErr = engine.Read(context.Background(), false)
		}
		return cache.resolve(engine, view, readErr, key, func() (mydcp.Peer, bool) {
			err := readErr
			peer, known := peers[key]
			member := known && peer.Member
			if !known {
				peer = mydcp.Peer{ID: hex.EncodeToString(key[:]), Policy: mydcp.Policy{Key: key}}
			}
			actor := hex.EncodeToString(key[:])
			allowed := actor == c.Common.Admin && engine == nil
			if engine != nil {

				peer, member = mydcp.Peer{ID: actor, Policy: mydcp.Policy{Key: key}}, false
				if err == nil {
					if directory, e := managedCatalog.Members(view.State); e == nil {
						if directory.HistoricalMemberKey([32]byte(key)) && !directory.ReplicationKey([32]byte(key)) {
							return mydcp.Peer{}, false
						}
						for _, entry := range directory.Entries {
							if entry.CurrentPeer().Key == actor {
								member = directory.MemberKey([32]byte(key))
								replicate := directory.ReplicationKey([32]byte(key))
								// Retained historic proof keys never fall through into
								// the generic ephemeral User TLS admission below.
								if membership.FullMember(entry) && !replicate {
									return mydcp.Peer{}, false
								}
								peer = mydcp.Peer{ID: entry.Peer.ID, Endpoint: entry.Peer.Endpoint, Policy: mydcp.Policy{Key: key, Replicate: replicate, Member: member, Snapshot: replicate, Respond: true, Read: member, Report: member}}
								break
							}
						}
					}
				}
				if installation.Join != nil && installation.Root.Installed.Index == 0 && (err != nil || view.RaftIndex < installation.Join.MinimumIndex) && !member {
					if seed, ok := peers[key]; ok {
						peer = seed
					}
				}

				if err == nil {
					rights, _, _, known := view.State.Principal(actor)
					allowed = known && rights != 0
					if packetPolicy && member && r.networkEnabled {

						directory, memberErr := managedCatalog.Members(view.State)
						peer.Tunnel = memberErr == nil && directory.WorkKey(r.Identity.Public) && directory.WorkKey([32]byte(key)) && (managedTunnelGrant(view.State, r.Identity.Public, [32]byte(key), managedCatalog) || managedCatalog.RouteTransportAllowed(view.State, r.Identity.Public, [32]byte(key)))

					}
				}
			}
			if allowed {
				peer.Manage = true
				peer.Read = true
			}

			peer.Manage = false
			peer.Read = member

			// Public user-auth admission proves only the ephemeral TLS key. The
			// User-purpose adapter verifies registered credentials/session grants.
			peer.UserAuth = true
			if engine := r.Engine(); engine != nil {
				peer.UserAuth = engine.ModuleEnabled()
			}
			return peer, member || peer.Replicate || allowed || peer.UserAuth
		})
	}
	policy := desired.Policy{Cluster: clusterID, Owners: map[string][32]byte{}}
	for _, p := range peers {
		pub := [32]byte(p.Key)
		policy.Owners[desired.Owner(clusterID, pub)] = pub
	}
	r.policy, r.owner = policy, desired.Owner(clusterID, self.Public)
	r.Mesh, err = mydcp.NewTransportWithPurposeLookup(self, clusterID, lookupPurpose)
	if err != nil {
		return nil, err
	}
	if err = r.Mesh.EnableDiscovery(c.Node.ID); err != nil {
		return nil, err
	}
	if err = r.Mesh.Listen(c.Node.Listen); err != nil {
		return nil, err
	}
	resolve := func(id raft.ServerID, address raft.ServerAddress) (mydcp.Peer, bool) {

		if engine := r.Engine(); engine != nil {
			if view, err := engine.Read(context.Background(), false); err == nil {
				if directory, err := managedCatalog.Members(view.State); err == nil {
					if entry, found := directory.Entry(string(id)); found && entry.Peer.Endpoint == string(address) {
						full, _ := identity.ParseKey(entry.CurrentPeer().Key)
						return lookupPurpose(mydcp.Identity(full), mydcp.Raft)
					}
				}
			}
		}
		if installation.Join != nil && installation.Root.Installed.Index == 0 {
			if seed, found := byID[string(id)]; found && seed.Endpoint == string(address) {
				peer, ok := lookupPurpose(seed.Key, mydcp.Raft)
				return peer, ok && peer.ID == string(id) && (peer.Member || peer.Replicate)
			}
		}
		return mydcp.Peer{}, false
	}
	manifestID := control.ManagedManifest(installation.Root.Cluster, installation.Admin, installation.Genesis)
	options := cluster.Options{ID: c.Node.ID, Root: c.Node.StateDir, Admin: c.Common.Admin, Cluster: clusterID, Mesh: r.Mesh, Resolve: resolve, Servers: servers, Manifest: manifestID, Validate: policy.Validate, ReadModule: r.readModule}
	options.Prepared = func(engine *cluster.Engine) {
		// Publish the verified durable directory before the SDK starts peer
		// traffic; old static seeds must not revive a removed managed member.
		r.mu.Lock()
		r.engine = engine
		r.mu.Unlock()
	}

	options.Bootstrap = installation.Root.Intent == "init" && installation.Root.Installed.Index == 0
	options.TrackConfiguration = true
	options.IdentityTransitions = lifecycle.OwnIdentityTransitions(installation.Root.Keys)

	if err = r.openGit(c); err != nil {
		return nil, err
	}
	if err = r.openVaults(c); err != nil {
		return nil, err
	}

	if err = r.openVaultApprovals(c.Node.StateDir); err != nil {
		return nil, err
	}

	catalog := managedCatalog
	for key, peer := range peers {
		if peer.Member {
			catalog.Issuers = append(catalog.Issuers, [32]byte(key))
		}
	}
	options.ModuleID, options.Reduce = catalog.ID(), catalog.Reduce
	options.AdmitModule = catalog.AdmitModule
	options.AdmitMutation = catalog.AdmitAppMutation
	options.AdmitModulePatch = catalog.AdmitAppPatch
	options.AllowMutationUpgrade = true
	options.AllowPatchUpgrade = true
	options.CommandModule = r.appCommand
	options.Validate = catalog.ValidateManaged
	r.controlPolicy = catalog

	options.EventProjection = catalog.ProjectEvents

	options.NodeCLIAllowed = catalog.NodeCLIAllowed
	engine, err := cluster.Open(options)
	if err != nil {
		return nil, err
	}
	r.mu.Lock()
	r.engine = engine
	r.mu.Unlock()

	if err = r.serveAppInputFetch(); err != nil {
		return nil, err
	}

	nativeConfig := c

	nativeConfig.Node.StateDir = bootstrap.NativeOwnerPath(original, installation, self.Public)
	for _, transition := range installation.Root.Keys {
		for _, old := range [][32]byte{transition.Proof.Old, transition.Proof.New} {
			r.policy.Owners[desired.Owner(clusterID, old)] = old
		}
	}

	r.nativeRoot = nativeConfig.Node.StateDir
	if err = r.openModules(nativeConfig, peers); err != nil {
		return nil, err
	}

	if err = r.openHistoricalOwners(c, original, installation, peers); err != nil {
		return nil, err
	}
	if err = r.openNodeShell(c.Node.ID, original.Node.StateDir); err != nil {
		return nil, err
	}
	if err = r.openServiceCalls(c); err != nil {
		return nil, err
	}
	if err = r.serveCheckerArtifacts(); err != nil {
		return nil, err
	}
	if err = r.serveCheckerProbes(); err != nil {
		return nil, err
	}
	if err = r.serveVolumeTransfers(); err != nil {
		return nil, err
	}

	if err = engine.ServeManagement(); err != nil {
		return nil, err
	}
	{
		if p := c.Credentials; p != nil {
			r.credentials, err = credentials.OpenLocal(p.Profile, p.Address, p.Mount, p.Namespace, p.CAFile, p.TokenFile)
			if err != nil {
				return nil, err
			}
		}
		service := userauth.Service{Engine: engine, Mesh: r.Mesh, Self: self, Policy: catalog, Credentials: r.credentials, Enabled: engine.ModuleEnabledAt}

		service.NodeShellLifetime = r.ctx
		service.NodeShellOpen = func(ctx context.Context, id string) (userauth.NodeShellStream, error) {
			return r.OpenNodeShell(ctx, id)
		}
		service.NodeDrainPlanner = r.nodeDrainPlan
		service.NodeForceProbe = r.nodeForceProbe
		service.NodeDiagnostics = r.nodeDiagnostics
		service.VaultWriter = r.writeVault
		service.VaultApprover = r.approveVault
		service.CertificateWriter = r.writeCertificate
		service.IngressObserver = r.readIngresses
		service.ServiceCaller = r.callService
		service.ServiceCallLimiter = &r.serviceCallLimit
		service.CDProber = r.probeCD
		service.ContainerObserver = r.containerObservation
		service.ExternalRegistryProber = r.externalRegistryProbe
		service.ImageResolver = r.resolveImage
		service.RegistryCatalog = r.registryCatalogue
		service.RegistryPrune = r.registryPrune
		service.ImageBuildDraft = r.imageBuildDraft
		service.ImageBuildGit = r.saveImageBuildGit
		service.ImageBuildTransfer = r.imageBuildTransfer
		service.ImageBuildSource = r.checkImageBuildSource
		service.ImageBuildContent = r.imageBuildContent
		service.ImageBuildCaches = r.imageBuildCacheInventory
		service.ImageBuildCache = r.imageBuildCache
		service.ImageBuildLogs = r.imageBuildLogs
		service.ImageContent = r.openImageContent
		service.ImageBuildBaseContent = r.openImageBuildBaseContent
		service.EventReader = r.readEvents
		service.ImageCachePlanner = r.imageCachePlan
		service.ContainerPlanner = r.containerSessionPlan
		service.ContainerLifetime = r.ctx
		service.ContainerRunner = r.runContainerSession
		service.ContainerExecObserver = r.containerExecStatus
		service.VolumeFiles = r.runVolumeFile
		service.VolumeObserver = r.volumeUsage
		service.VolumeSourceObserver = r.volumeBackupSource
		service.VolumeMoveObserver = r.volumeMoveRecipe
		service.NodeStorageObserver = r.nodeStorageSpace
		service.NodeObservations = r.nodeObservations
		service.NetworkObserver = r.networkClosureRead
		service.DNSObserver = r.networkDNSRead
		service.LifecycleSourceReader = r.readLifecycleSource
		service.CheckerSources = checkerSourceBackend{r}

		if err = service.Serve(); err != nil {
			return nil, err
		}
	}

	if err = r.serveCertificateMaterial(); err != nil {
		return nil, err
	}
	if err = r.serveMembership(); err != nil {
		return nil, err
	}
	r.wg.Add(1)
	go r.memberLoop()
	r.wg.Add(1)
	go r.deliverySourceLoop()

	ok = true
	return r, nil
}
func (r *Runtime) Engine() *cluster.Engine { r.mu.RLock(); defer r.mu.RUnlock(); return r.engine }
func (r *Runtime) Close() error {
	r.closeOnce.Do(func() {
		started := time.Now()
		phase := func(name string) {
			log.Printf("runtime shutdown: stage=%s elapsed=%s", name, time.Since(started))
		}
		phase("cancel")
		if r.cancel != nil {
			r.cancel()
		}
		if r.Mesh != nil && !r.historicalOwner {
			phase("unix-admission")
			// Stop local producers before waiting for modules/consensus. Keep
			// MYDCP peer paths alive for their existing retirement/closure.
			r.closeErr = errors.Join(r.closeErr, r.Mesh.CloseUnix())
		}
		for _, owner := range r.nativeOwners {
			if owner.cancel != nil {
				owner.cancel()
			}
		}
		phase("node-shells")
		r.closeNodeShells()
		phase("workers")
		r.wg.Wait()
		for _, owner := range r.nativeOwners {
			r.closeErr = errors.Join(r.closeErr, owner.Close())
		}
		r.closeErr = errors.Join(r.closeErr, r.imageBuildShutdownError)
		phase("registry-owners")
		r.closeErr = errors.Join(r.closeErr, r.closeRegistryOwners(context.Background()))
		phase("input-lock")
		r.inputLife.Lock()
		defer r.inputLife.Unlock()
		phase("vault-approval-lock")
		r.vaultApprovalLife.Lock()
		defer r.vaultApprovalLife.Unlock()
		phase("module-lock")
		r.life.Lock()
		r.closed = true
		r.imageBuildMu.Lock()
		r.closeErr = errors.Join(r.closeErr, r.imageBuildTree.Close())
		r.imageBuildTree = nil
		r.imageBuildMu.Unlock()
		r.logPages.Clear()
		if r.ingress != nil {
			phase("ingress")
			r.closeErr = errors.Join(r.closeErr, r.ingress.Close())
		}
		if r.dns != nil {
			phase("dns")
			r.closeErr = errors.Join(r.closeErr, r.dns.Close())
		}
		if r.tunnel != nil {
			phase("tunnel")
			r.closeErr = errors.Join(r.closeErr, r.tunnel.Close())
		}
		phase("routes")
		r.routeMu.Lock()
		if r.routeDriver != nil {
			r.closeErr = errors.Join(r.closeErr, r.routeDriver.Close())
		}
		r.routeMu.Unlock()
		if r.workload != nil {
			phase("workload")
			r.closeErr = errors.Join(r.closeErr, r.workload.Close())
		}
		if r.backupArtifacts != nil {
			phase("backup-artifacts")
			if r.volumeRestores != nil {
				r.closeErr = errors.Join(r.closeErr, r.volumeRestores.Close())
			}
			r.closeErr = errors.Join(r.closeErr, r.backupArtifacts.Close())
		}
		if r.activations != nil {
			phase("activations")
			r.closeErr = errors.Join(r.closeErr, r.activations.Close())
		}
		if r.nativeVolumes != nil {
			phase("native-volumes")
			r.closeErr = errors.Join(r.closeErr, r.nativeVolumes.Close())
		}
		if r.fixedVolumes != nil {
			phase("fixed-volumes")
			r.closeErr = errors.Join(r.closeErr, r.fixedVolumes.Close())
		}
		if r.nodeRoots != nil {
			phase("node-roots")
			r.closeErr = errors.Join(r.closeErr, r.nodeRoots.Close())
		}
		if r.projections != nil {
			phase("projections")
			r.closeErr = errors.Join(r.closeErr, r.projections.Close())
		}
		if r.network != nil {
			phase("network")
			r.closeErr = errors.Join(r.closeErr, r.network.Close())
		}
		if r.docker != nil {
			phase("docker-compiler")
			if r.checkerCompiler != nil {
				ctx, stop := context.WithTimeout(context.Background(), 30*time.Second)
				r.closeErr = errors.Join(r.closeErr, r.checkerCompiler.Shutdown(ctx))
				stop()
				r.closeErr = errors.Join(r.closeErr, r.checkerCompiler.Close())
			}
			r.closeErr = errors.Join(r.closeErr, r.docker.Close())
		}
		if r.reports != nil {
			phase("checker-reports")
			if r.checkerSources != nil {
				r.closeErr = errors.Join(r.closeErr, r.checkerSources.Close())
			}
			r.closeErr = errors.Join(r.closeErr, r.reports.Close())
		}
		phase("vault-backends")
		if !r.historicalOwner {
			for _, backend := range r.vaultBackends {
				if backend.writer != nil {
					r.closeErr = errors.Join(r.closeErr, backend.writer.Close())
				}
				backend.provider.Close()
			}
		}
		if r.vaultApprovals != nil {
			r.closeErr = errors.Join(r.closeErr, r.vaultApprovals.Close())
		}
		r.life.Unlock()
		if e := r.Engine(); e != nil && !r.historicalOwner {
			phase("consensus")
			r.closeErr = errors.Join(r.closeErr, e.Close())
		}
		if r.Mesh != nil && !r.historicalOwner {
			phase("peer-transport")
			if err := r.Mesh.Close(); r.closeErr == nil {
				r.closeErr = err
			}
		}
		if r.credentials != nil && !r.historicalOwner {
			phase("credentials")
			r.credentials.Close()
		}
		phase("complete")
	})
	return r.closeErr
}
