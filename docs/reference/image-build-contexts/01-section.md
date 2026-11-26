## 대상과 권한

자동 만료는 owner의 서명 관측을 Raft에 확정한 뒤 수행한다. 공개 upload row의 optional `ExpiredAt`·`ReclaimedAt`은 공유 만료와 실제 회수 완료를 구분한다. closed/expired만으로 저장 예산이나 원 root dependency가 반환되지 않는다. 보존 version은 기본 보호하며 명시 `delete-build-version {Tenant,ID:[32]}`의 Expected는 그 version의 Number다. 삭제 수락 후에도 실제 bytes/원 pin 종료와 owner closure가 보고돼야 회수가 완료된다. 원 version metadata·사용자 승인·삭제/회수 근거는 tombstone으로 보존한다.

tenant별 ManageRegistry가 정책·컨텍스트·업로드를 관리한다. 실제 node/root 선택은 현재 설치 멤버·tenant의 노드 권한과 등록 root의 tenant ACL/attestation을 함께 확인한다. Volume 관리 권한을 부여하는 기능이 아니다. 등록 root의 전체 Reference를 사용하며 임의 호스트 경로는 받을 수 없다. Secret 값은 등록하지 않고 Vault mount 참조만 저장한다. `Arguments`는 공개 값이며 비밀 인자는 `Secrets` 참조로 분리한다. Git 주소에 username/password·query/fragment를 넣지 않는다.

일반 metadata 조회는 현재 tenant Read 또는 ManageRegistry가 필요하다. 업로드 목록·누락 진행 조회와 part/consume/abort는 원 creator의 안정적인 사용자 ID에 한정된다. 다른 관리자도 남의 upload를 소비하지 않는다. 정책/컨텍스트와 upload ID는 클러스터 프로필·tenant 범위에 속하며 Linux user의 로컬 등록이 아니다.

