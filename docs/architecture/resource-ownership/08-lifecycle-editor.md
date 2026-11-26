## Lifecycle editor 원본·임시 입력

| 자원 | 정의·변경 주체 | 소비·수명 |
|---|---|---|
| source/locked module ZIP | 현재 tenant ManageServices 사용자, 허용된 provider | 기존 SourceStore·원 upload hold/cache GC; source diagnostics만 있을 때 root fact를 발급하지 않음 |
| 등록 named source version | 기존 put-lifecycle-script 관리 변경·Raft Catalog CAS | 앱/빌드가 정확 revision을 참조; source-read는 nondeleted 원 provider 바이트만 읽고 사본/새 버전 생성 없음 |
| editor 진단 | 선택 provider의 기존 resolver와 compiled-in SDK/whitelist type metadata | 요청별 유한 공개 줄/열·메시지; 사용자 init/Check 실행·Secret/host 경로 출력 없음 |

[원본 API](../../reference/lifecycle-sources.md)를 따른다.

설치 키 교체 시 lifecycle source/version·upload hold·checker artifact/cache·미정산 compiler job은 원 owner namespace와 서명·ID를 유지한다. 현재 노드가 기존 resource-owner adapter로 그 원 자료를 소비하고 현재 보고 봉투를 서명한다. 원 cache namespace는 새 compiler 작업을 배치하지 않으며, 원 builder 종료 proof만 해당 job을 정산한다. named-script use의 정확한 원 version/provider도 node activity에 포함하여 다른 노드의 소비자가 보존한 source pin을 drain/remove 계산에서 누락하지 않는다. 현재 신원과 원 자료 소유권은 별도이며 새 TLS/issuer/명령 인증은 현재 멤버 키만 사용한다.

현재·이전 lifecycle cache namespace는 같은 논리 노드의 기존 tenant cache 예산과 source/module·compiled·준비 metadata 한도를 합산한다. 키 교체나 이전 adapter의 종료로 사용량을 초기화하지 않으며 실제 회수로 반환된 자료만 예산에서 제외한다. 어느 namespace의 저장 결과가 불명하면 복구 전 신규 할당을 허용하지 않는다. 원 upload hold·게시 이력의 보존과 정확한 원 자료 복구는 유지한다.

설치 신원 교체로 certificate holder의 원 암호화 namespace를 바꾸지 않는다. 원 version key·미정산 입력 request·receipt는 원 native DB/identity seed에 남고, 현재 노드가 기존 resource-owner adapter와 현재 권한으로 정확한 원 version/request를 읽는다. 원 ingress consumer/source 참조와 certificate sealer를 현재 인증키로 덮어쓰지 않는다. Material 통신과 새 인증서 입력·만료 보고는 현재 키로 수행하며 과거 namespace에는 새 입력을 만들지 않는다.
