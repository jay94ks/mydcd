// SPDX-License-Identifier: Apache-2.0

import { useTenantRole } from '../auth/session';
import { Badge, PageHeader } from '../components/ui';
import { Routes, Route, useLocation } from 'react-router-dom';
import { ImageCatalog, ImageListActions, ImageListTab, MImageList, useImageCount } from './ImageList';
import { usePhone } from '../lib/viewport';
import { useReadOnlyTop } from '../mobile/ReadOnly';
import { Tabs } from '../components/Tabs';
import { NoTenant } from './Deploy';
import { RegistryTab } from './Registry';
import { TrustTab } from './ImageTrust';
import { ExternalRegisterButton, ExternalTab } from './ExternalRegistries';
import { BuildNewMenu, BuildsTab } from './ImageBuilds';
import { ImageUploadPage } from './ImageTools';
import { MBuildsTab, MExternalTab, MRegistryTab, MTrustTab } from './MImageTabs';

/** 휴대폰 이미지 목록 머리 (UI-M11 ③) */
function MImagesTop({ tenant }: { tenant?: string }) {
  useReadOnlyTop('이미지 관리', tenant ? `작업 공간 ${tenant} 전용` : undefined, '올리기·태그·지우기·빌드는 넓은 화면에서', [tenant]);
  return null;
}

export function ImagesPage() {
  const { tenant } = useTenantRole();
  const phone = usePhone();
  const path = useLocation().pathname.replace(/\/$/, '');
  const list = path === '/images';
  const upload = path === '/images/upload';
  const external = path === '/images/external';
  const builds = path.startsWith('/images/builds');
  const buildIds = path === '/images/builds/cache' ? 'UI-87' : path === '/images/builds' ? 'UI-85' : 'UI-86';
  return (
    <ImageCatalog>
      <PageHeader
        title="이미지 관리"
        ids={list ? 'UI-84 · UI-8A' : upload ? 'UI-88' : external ? 'UI-83' : builds ? buildIds : 'UI-60 · UI-80 · UI-82'}
        actions={
          tenant && !phone ? (
            <>
              <Badge tone="un">작업 공간 {tenant} 전용</Badge>
              {list && <ImageListActions />}
              {external && <ExternalRegisterButton />}
              {path === '/images/builds' && <BuildNewMenu />}
            </>
          ) : undefined
        }
      />
      {!tenant ? (
        <NoTenant />
      ) : (
        <>
          <ImageTabs />
          <Routes>
            <Route index element={phone ? <><MImagesTop tenant={tenant} /><MImageList /></> : <ImageListTab />} />
            <Route path="upload" element={<ImageUploadPage />} />
            <Route path="registry" element={phone ? <MRegistryTab /> : <RegistryTab />} />
            <Route path="trust" element={phone ? <MTrustTab /> : <TrustTab />} />
            <Route path="external" element={phone ? <MExternalTab /> : <ExternalTab />} />
            {phone && <Route path="builds" element={<MBuildsTab />} />}
            {phone && <Route path="builds/cache" element={<MBuildsTab />} />}
            <Route path="builds/*" element={<BuildsTab />} />
          </Routes>
        </>
      )}
    </ImageCatalog>
  );
}

function ImageTabs() {
  const path = useLocation().pathname.replace(/\/$/, '');
  const n = useImageCount();
  return (
    <Tabs
      label="이미지 관리 탭"
      items={[
        { to: '/images', active: path === '/images/upload', label: n === undefined ? '이미지 목록' : `이미지 목록 (${n})` },
        { to: '/images/registry', label: '내장 저장소' },
        { to: '/images/external', label: '외부 저장소' },
        { to: '/images/builds', label: '빌드' },
        { to: '/images/trust', label: '신뢰 출처' },
      ]}
    />
  );
}
