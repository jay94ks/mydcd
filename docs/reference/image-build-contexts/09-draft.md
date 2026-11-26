## 종료된 draft 데이터 수명 회수

일반 context/policy 설정 변경은 편집 파일의 수명을 끝내지 않는다. context 삭제 또는
삭제 후 재생성으로 더 높은 데이터 Generation이 확정된 경우에만 owner가 원 draft
디렉터리를 회수한다. 최신 quorum 상태의 fence를 원 native anchor에 적용하며 현재
데이터보다 앞선 로컬 기록·다른 root/owner·교체 inode·열린 draft는 삭제하지 않는다.

같은 observations DB에 원 scope·lease와 삭제 의도를 보존한 뒤 원 namespace를
unlink/fsync하고 Removed/Returning을 기록한다. 실제 descriptor 종료와 정확한 원
RootManager Return 뒤 Returned를 정산한다. 삭제 또는 반환 뒤 기록 실패는 같은
의도로 재개하며 옛 디렉터리를 다시 생성하거나 새 pin을 빌리지 않는다. 반환 기록이
미정산이면 실제 lease가 이미 반환됐어도 tenant 종료 점검은 대기 상태로 센다.

편집 의도·원 결과·freeze metadata는 남기며 재생성한 현재 데이터는 건드리지 않는다.
이미 Spool의 별도 namespace에 채택된 archive는 이 디렉터리 삭제로 제거하지 않는다.
준비된 archive가 아직 인계되지 않았거나 원 header의 인계가 미완료면 전체 디렉터리
삭제를 보류한다. 먼저 archive의 독립 수명에서 원 inode와 참조를 정산해야 한다.
그 archive와 Git stage의 참조/본문 회수는 위 독립 정산을 따른다. 이 연결은 RQ6 마지막 실행
검증 전이며, 모든 입력 자료의 회수 완료를 뜻하지 않는다.

