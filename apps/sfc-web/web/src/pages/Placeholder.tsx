// SPDX-License-Identifier: Apache-2.0

import { HelpBox, PageHeader } from '../components/ui';
import { Empty } from '../components/states';

/** 아직 구현하지 않은 화면. 가짜 Ready를 만들지 않고 무엇이 남았는지 보인다. */
export function Placeholder({ title, ids, what, stage, req }: { title: string; ids?: string; what: string; stage?: string; req?: string }) {
  return (
    <>
      <PageHeader title={title} ids={ids} />
      <HelpBox>{what}</HelpBox>
      <Empty kind="scope" title={stage ? `${stage}에서 제공합니다` : '이 화면은 아직 만들고 있습니다'}>
        {req ? `sfcd 기능 ${req}가 들어온 뒤 실제 연동합니다.` : '디자인 캔버스의 화면을 따라 다음 PR에서 이어 만듭니다.'}
      </Empty>
    </>
  );
}
