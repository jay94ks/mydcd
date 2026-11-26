## 미게시 생성 archive의 회수

draft freeze/Git 보관으로 준비·채택된 원 archive에 공유 upload가 없고, 최신 quorum의
context/policy revision 증가 또는 context 삭제로 원 게시가 불가능해진 경우 owner가
회수한다. 현재 게시 가능한 archive는 시계상 만료만으로 삭제하지 않는다. 공유 upload가
이미 있으면 그 원 scope를 대조하고 기존 version/job 참조·owner 보고 경로로 정산한다.
다른 scope의 ID 충돌이나 현재 상태보다 앞선 로컬 plan은 추정해서 지우지 않는다.

원 source metadata를 유지하며 기존 native archive header에 원 artifact 지문·설정/
snapshot 좌표·archive pin의 실제 borrow 여부와 정확한 lease를 저장한다. 준비 파일은
원 inode 그대로 기존 Spool namespace에 rename/fsync하고, 기존 Reclaim의 삭제 intent·
unlink/fsync를 수행한다. 이 과정에서 ZIP을 복사·재작성하거나 seal·공유 upload·새
사용자 작업을 합성하지 않는다. 원 파일의 의도 전 부재/교체·열린 reader는 보호한다.

실제 삭제 뒤 Returning을 기록하고 descriptor 종료·원 pin Return 뒤 Returned를
정산한다. archive pin을 아직 빌리지 않았다면 원 draft/Git stage pin으로 기존 Spool을
열어 정리하며 새 pin을 만들지 않는다. 반환 기록 미정산은 실제 pin이 없어도 tenant
종료 점검에 남는다. 원 source/결과 metadata와 다른 archive는 보존하고, 삭제 완료한
native header가 전체 draft/Git stage의 후속 종료 근거가 된다.

같은 owner 순환 pass에서 context당 최대4건을 처리하며 원 evidence cursor로 다음
대상에 진행한다. 보호·완료 행 때문에 뒤의 원 자료가 계속 제외되지 않도록 순환한다.
이 연결은 RQ6 마지막 실행 검증 전이다.

