## Lifecycle 편집기 source 메시지

User purpose8 `lifecycle-source-stage`/`lifecycle-module-stage`는 `{Tenant,Node?,CheckerSource,CheckerUpload,CheckerModule?}` header→kind2 continue→기존 kind4 순차 body→EOF를 사용한다. 원 길이/digest/EOF·현재 ManageServices/provider quorum permit과 upload hold 뒤 resolver·SDK 타입을 검사하여 `Reply.LifecycleStage`의 SourceFact 또는 줄/열 Diagnostics를 반환한다. 사용자 init/Check는 실행하지 않는다. body 없는 recover는 명시 원 provider/descriptor/token만 조회한다. User `lifecycle-source`는 `{Tenant,LifecycleSource:{Name,Revision,Offset}}`에 대한24KiB 원 byte page `{Tenant,Name,Revision,Offset,Total,Next,Digest,Data}`를 반환한다. 원 provider는 member 전용 `lifecycle-source-version-owner`와 current quorum `lifecycle-source-version-permit`으로 연결한다. [형식·검사·읽기/복구 계약](../../reference/lifecycle-sources.md)을 따른다.

설치 신원 교체 후 lifecycle source/version·checker artifact/cache의 peer routing은 원 fact/use/job의 owner를 기존 resource-owner lineage로 현재 member에 연결한다. wire의 원 `SourceFact`/`Consumer`/provider/cache recipe/BuildIntent/closure는 바꾸지 않고 현재 member만 관리·artifact 연결과 보고 봉투를 인증한다. `CheckerBuildPermit.Owner`는 원 job owner이고 현재 호출키로 덮어쓰지 않는다. 원 upload recover는 해당 물리 노드의 정확한 기존 descriptor/token hold를 읽으며 새 hold를 생성하지 않는다. 새 editor는 현재 owner로만 서명하고 같은 token을 과거 namespace에서 현재 namespace로 재배정하지 않는다. 과거 키 archive는 현재 TLS/issuer/명령 lookup으로 fallback하지 않는다.

설치 신원 교체 뒤 CertificateMaterial의 원 Source/Consumer와 Version.Sealer는 원 참조로 보존한다. 실제 peer는 현재 멤버 키로 인증하며, quorum의 기존 resource-owner 관계와 exact source generation/revision·version digest로 소비를 제한한다. 원 sealer의 Material provider 경로는 현재 peer를 사용한다. 로컬 version key는 해당 owner의 원 DB/identity seed로만 열고 ciphertext/receipt를 새 request/version으로 바꾸지 않는다. 과거 TLS/issuer/관리 인증 fallback은 허용하지 않는다.

설치 신원 교체 후 Engine은 로컬 설치 Root의 전체 이중 서명 키 이력을 검증하고, 마지막 키가 현재 TLS 키와 일치할 때 최초 키로 원 DB binding을 대조한다. DB binding의 나머지 cluster/node/admin/module/정책 필드는 그대로 검사하며 binding 부재나 불일치는 거부한다. 원 binding을 새 키로 덮어쓰거나 구키 TLS 권한을 복원하지 않는다. 대상의 로컬 FSM이 아직 Prepared여도 원 quorum activation으로 확정된 설치 selector와 이력으로 같은 DB를 재개할 수 있다.

같은 DB 재개 후 설치 구성 확인은 로컬 member 이력이 설치 selector의 exact proof/activation index 이력에 도달할 때까지 기존 context 안에서 기다린다. 정확한 과거 prefix만 recovering이며 다른 origin/proof/index는 거부한다. Root의 command revision과 topology revision은 서로 비교하지 않는다.

Raft SDK 구성은 ID/주소/voter를 기록하고 노드 키는 별도 member 이력에서 결정한다. SDK 구성 번호가 그대로인 다른 노드의 키 교체에서는 ID/voter가 완전히 같고 원 키가 검증된 현재 member lineage로 이어질 때만 원 설치 기록의 키를 역사적 근거로 보존한다. 현재 TLS/명령/issuer 권한은 항상 현재 member 키로 판단하며 역사적 설치 기록에서 구키 인증을 복원하지 않는다.

Ingress 관리의 User `ingresses` 조회에는 Part=`gateways|history`, signed Change에는 `set-node-gateways|set-ingress-balance|drain-ingress|undrain-ingress`가 있다. 네트워크와 Unix 모두 동일한 현재 사용자·원 operation·Raft/record CAS를 사용한다. gateway 주소 검사는 현재 owner가 원 user/request/이전·다음 설정에 결합해 서명한 관측이며 Raft reducer가 OS 주소를 직접 조회하지 않는다. 공개 메시지/입력·적용 revision과 이력 형식은 [Unix API](../../reference/unix-sockets/25-ingress.md)·[Ingress 운영](../../reference/ingress-management.md#gateway분배drain-변경과-공개-이력)을 따른다.
