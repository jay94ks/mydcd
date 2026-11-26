// SPDX-License-Identifier: Apache-2.0

import { Navigate, Route, Routes, useLocation } from 'react-router-dom';
import { useAuth } from './auth/session';
import { AppShell } from './layout/AppShell';
import { LoginPage } from './pages/Login';
import { DashboardPage } from './pages/Dashboard';
import { AccountPage } from './pages/Account';
import { ServersPage, ConsensusPage } from './pages/Servers';
import { ServerDetailPage } from './pages/ServerDetail';
import { NodeShellListPage } from './pages/NodeShell';
import { TenantsPage, TenantDetailPage } from './pages/Tenants';
import { UsersPage } from './pages/Users';
import { DeployedAppsPage, ArchivedAppsPage } from './pages/Deploy';
import { DeployNewPage } from './pages/DeployNew';
import { AppContainerPage } from './pages/AppContainer';
import { AppDetailPage } from './pages/AppDetail';
import { IncidentPolicyPage, IncidentsPage } from './pages/Incidents';
import { IncidentGuidePage } from './pages/IncidentGuide';
import { IncidentHooksPage } from './pages/IncidentHooks';
import { NetworkRoutesPage, NetworksPage, VolumesPage } from './pages/Shared';
import { VaultPage } from './pages/Vault';
import { LifecyclePage } from './pages/Lifecycle';
import { NetworkChangePage } from './pages/NetworkChange';
import { ImagesPage } from './pages/Images';
import { StandalonePage } from './pages/Standalone';
import { StandaloneNewPage } from './pages/StandaloneNew';
import { OpsResourcesPage } from './pages/OpsTabs';
import { OpsChangesPage } from './pages/OpsChanges';
import { OperationsPage } from './pages/Operations';
import { NotificationsPage, NotifyPrefsPage } from './pages/Notifications';
import { WebSettingsPage } from './pages/WebSettings';
import { AuditPage } from './pages/Audit';
import { Placeholder } from './pages/Placeholder';
import { IngressPage } from './pages/Ingress';
import { IngressDetailPage } from './pages/IngressDetail';
import { DomainsPage } from './pages/Domains';
import { DomainDetailPage } from './pages/DomainDetail';
import { CertsPage } from './pages/Certs';
import { CertDetailPage } from './pages/CertDetail';
import { AiSettingsPage } from './pages/AiSettings';
import { AiMcpPage } from './pages/AiMcp';
import { CoordinatorListPage, CoordinatorPage } from './pages/CoordinatorFull';
import { MoreGroupPage, MorePage } from './mobile/More';
import { MKeySetupPage } from './mobile/MLogin';

function RequireAuth({ children }: { children: JSX.Element }) {
  const { session, loading } = useAuth();
  const loc = useLocation();
  if (loading) return null;
  if (!session) return <Navigate to="/login" replace state={{ from: loc.pathname + loc.search }} />;
  return children;
}

export function App() {
  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route
        path="/login/key"
        element={
          <RequireAuth>
            <MKeySetupPage />
          </RequireAuth>
        }
      />
      <Route
        element={
          <RequireAuth>
            <AppShell />
          </RequireAuth>
        }
      >
        <Route index element={<DashboardPage />} />
        <Route path="account" element={<AccountPage />} />
        <Route path="account/notify" element={<NotifyPrefsPage />} />
        <Route path="notifications" element={<NotificationsPage />} />
        <Route path="coordinator" element={<CoordinatorPage />} />
        <Route path="coordinator/list" element={<CoordinatorListPage />} />
        <Route path="more" element={<MorePage />} />
        <Route path="more/:group" element={<MoreGroupPage />} />

        <Route path="servers" element={<ServersPage />} />
        <Route path="servers/consensus" element={<ConsensusPage />} />
        <Route path="servers/:id/*" element={<ServerDetailPage />} />
        <Route path="node-shell" element={<NodeShellListPage />} />

        <Route path="deploy" element={<DeployedAppsPage />} />
        <Route path="deploy/new/*" element={<DeployNewPage />} />
        <Route path="deploy/archived" element={<ArchivedAppsPage />} />
        <Route path="deploy/apps/:tenant/:app/c/:service/:instance/*" element={<AppContainerPage />} />
        <Route path="deploy/apps/:tenant/:app/*" element={<AppDetailPage />} />

        <Route path="standalone" element={<StandalonePage />} />
        <Route path="standalone/new" element={<StandaloneNewPage />} />

        <Route path="images/*" element={<ImagesPage />} />
        <Route path="incidents" element={<IncidentsPage />} />
        <Route path="incidents/policy" element={<IncidentPolicyPage />} />
        <Route path="incidents/guide" element={<IncidentGuidePage />} />
        <Route path="incidents/hooks" element={<IncidentHooksPage />} />
        <Route path="incidents/:id" element={<IncidentsPage />} />

        <Route path="shared/networks" element={<NetworksPage />} />
        <Route path="shared/networks/routes" element={<NetworkRoutesPage />} />
        <Route path="shared/networks/:name/change" element={<NetworkChangePage />} />
        <Route path="shared/ingress" element={<IngressPage />} />
        <Route path="shared/ingress/:tenant/:app" element={<IngressDetailPage />} />
        <Route path="shared/volumes" element={<VolumesPage />} />
        <Route path="shared/vault" element={<VaultPage />} />
        <Route path="shared/lifecycle" element={<LifecyclePage />} />

        <Route path="system/tenants" element={<TenantsPage />} />
        <Route path="system/tenants/:id/*" element={<TenantDetailPage />} />
        <Route path="system/domains" element={<DomainsPage />} />
        <Route path="system/domains/certs" element={<CertsPage />} />
        <Route path="system/domains/certs/:name" element={<CertDetailPage />} />
        <Route path="system/domains/:domain/*" element={<DomainDetailPage />} />
        <Route path="system/users" element={<UsersPage />} />
        <Route path="system/ops" element={<OperationsPage />} />
        <Route path="system/ops/changes" element={<OpsChangesPage />} />
        <Route path="system/ops/cluster" element={<Navigate to="/system/ops/changes" replace />} />
        <Route path="system/ops/resources" element={<OpsResourcesPage />} />
        <Route path="system/ops/web" element={<AuditPage />} />
        <Route path="system/ai" element={<AiSettingsPage />} />
        <Route path="system/ai/mcp" element={<AiMcpPage />} />
        <Route path="system/web" element={<WebSettingsPage />} />
        <Route path="system/audit" element={<Navigate to="/system/ops/web" replace />} />
        <Route path="*" element={<Placeholder title="없는 화면" what="주소를 확인해 주세요." />} />
      </Route>
    </Routes>
  );
}
