## 유지·관리 규칙

- 자원 종류·소유 주체·허용 입력·이름 해석·삭제/보존 정책을 추가하거나 변경하면 해당 구현과 같은 작업에서 이 표를 갱신한다. 설계 검토 시에도 정의 주체와 실제 실행 주체를 구분한다.
- parser·관리 API·CLI·CD·예시와 관련 명세를 같은 경계에 맞춘다. 미지원 관리 action이나 native 연결을 문서 예시만으로 지원된 것으로 표시하지 않는다.
- 소유권 계약이 바뀌면 MILESTONES.md에 영향받는 남은 구현/검증을 반영한다. 원 artifact/서명/ID·DB·Unknown·미반환 참조는 보존하며 새 입력 규칙으로 과거 작업을 재해석하지 않는다.
- 이 문서에는 현재 자원 분류와 규칙만 둔다. 변경 이유·작업/검증 결과는 HISTORY.md, 원 근거는 검증 기록에 남긴다.

### lifecycle 캐시의 회수 주체

source/module/compiled bytes는 node SourceStore의 소유다. tenant named 등록·앱의 accepted Use·build 참조와 원 업로드 hold가 수명을 고정한다. 등록 tombstone·앱 종료와 byte 삭제를 분리하고, current quorum fence·로컬 미정산 run/exec/control/compiler·stream join을 확인한 node collector만 원문/module 값과 compiled 바이너리를 자동 회수한다. 원 서명 Fact·빌드/수집 영수증·진단·원 operation/sequence와 consumed upload floor는 회수하지 않는다. app은 빌린 tenant 등록을 지우지 않는다. 불명/legacy 업로드는 보존한다. bbolt의 회수 페이지는 DB가 재사용하며 파일 크기의 즉시 축소와 구분한다. 구체적 보존·quota·eviction/복구 계약은 D6 캐시 자동 회수를 따른다.

CD 앱의 명시 Volume 이관 계획은 원 Inventory의 tenant/app/deployment grouping을 유지한다. 계획 조회에서 optional Deployment를 생략하면 원 값을 사용하며 명시적으로 다른 grouping을 지정하여 원 소유권이나 승인 범위를 바꿀 수 없다.

관리 DNS의 배치 허가 철회는 선언 정책의 삭제/변경이 아니라 현재 owner serving의 종료다. 원 DNS source·망·앱 보존 데이터와 원 종료 증거를 유지한다. 배치 허가 복원 뒤에도 전체 원 owner 정산 전에는 같은 disabled lifetime을 다시 열지 않는다. 상세 경계는 CIDR/IPAM·DNS를 따른다.

부분 CD 전환의 retirement는 대상 Task/inputs의 Binding만 반환한다. 비대상 Task의 원 Source·세대/revision·현재 객체/claim이 일치하면 기존 Secret usage·Volume consumer와 함께 보존한다. 전체 app down에는 이 예외를 적용하지 않고 모든 앱 Binding 반환을 요구한다. 원 서명/인가·참조의 권위와 원 종료 증명은 기존 Binding 계약을 따른다.

Task 부분 교체의 주소 수명은 그 Task의 원 정적 allocation에 한정한다. closed Task도 AddressRetirement의 fence·기존 DNS/query/TTL 정산·원 owner 종료 서명과 반환이 끝나기 전까지 retirement 원 증명을 유지한다. 공유 Bridge/망과 비대상 Task의 주소·소비 참조를 함께 반환하지 않는다. orphan hold는 새 Task의 할당 허가가 아니다.

동일 앱의 lifecycle 프로그램은 현재 정책/source/provider 검사를 통과하고 정책 revision 외 모든 내용 및 원 이력이 동일할 때만 원 accepted 참조를 유지한다. 다른 앱/tenant/principal의 참조를 차용하거나 실제 정책 변경을 동일 설정으로 취급하지 않는다. 컨테이너 용량은 기존의 정확한 task goal·예약·의존 참조 검사로만 재사용하며 이 조건을 완화하지 않는다.

CD source/controller 보고의 대상은 원 CD revision·fetch ticket/upload·현재 선택이다. `app-delivery` Target의 과거 Apps root를 허용해도 현재 권한·회원·정책·epoch와 그 대상 자체의 CAS/서명을 검사한다. 다른 앱의 관측 root를 소유권으로 사용하지 않으며 과거 Target 없는 보고를 자동 변환하지 않는다.

새 CD 보고의 optional signed Target은 source의 고정 ticket/input 또는 controller의 실행 의도에 귀속한다. 현재 권한을 다시 확인하며 같은 artifact/intent의 CAS/readiness rebase와 수락은 원 operation/서명을 보존하는 한 FSM 변경이다. health/fetch bookkeeping이 새 권위나 새 자원을 만들지 않으며 Target=nil인 원 보고를 자동 변환하지 않는다.

검사 프로그램의 동일 정책 복구 연속성은 활성 Execution뿐 아니라 이미 승인된 CD update/recovery 전환의 고정 계획에도 적용한다. positive retirement 뒤 Execution이 없어도 이 accepted recipe를 원 소유 참조로 사용한다. 미승인 queued 후보와 Down을 새 실행의 승인으로 삼지 않으며 현재 정책/source/provider 검사는 먼저 수행한다.

새 Binding/컴파일 job의 정책 admission은 저장된 원 정책과 현재 활성 정책의 전체 설정을 비교한다. revision 순서만 달라진 동일 설정 복구라면 원 recipe·Use·build ID/bytes를 보존하며 예약/계획/전송할 수 있다. 설정 변경·비활성·없는 역사적 정책은 허용하지 않는다. current source·사용자/노드/provider·parent·quota와 실제 빌드/실행 검사는 별도로 유지한다.

### 앱 종료의 원 명령 재전송 허가

원 내부 명령의 재전송 허가는 해당 앱의 기존 Inventory/Retirement에 속한다. 현재 tenant Deploy cleanup 관리자만 명시 `resume-app-retirement` 관리 변경으로 원 Key/Phase/Command 지문·retirement·Inventory CAS를 고정하여 만든다. 담당 daemon은 현재 원 종료 권한을 다시 확인하고 허가를 한 번 소비한다. 새 DB/worker/앱 자원이나 native 제어 권한을 만들지 않는다. 명령/원 Unknown/ledger epoch와 실제 종료·Volume/Binding pin을 보존하며 늦은 원 결과는 재전송보다 먼저 수집한다. 앱 선언·CD·관리 명령이 허가를 자동 갱신하지 않는다.

