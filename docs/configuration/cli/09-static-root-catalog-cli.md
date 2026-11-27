## 기존 static root의 catalog 활성화 CLI

모든 voter에 같은 정책 gate 지원 빌드를 배치한 뒤 원 bootstrap node-admin의 `auth: node` 프로필로 최신 quorum을 조회한다. 조회 성공 하나를 전체 voter의 빌드 일치 증거로 해석하지 않는다. `--local`·tenant/user 선택·과거 profile archive는 사용하지 않는다. `catalog-policy show`는 현재 원 admin epoch와 고정 source/target manifest·policy ID·활성 여부를 표시한다. Configuration에는 원 SDK 구성 index·applied floor와 해당 full-key/endpoint/voter 목록을 표시하며 CLI가 현재 quorum 읽기 floor와 구조를 확인한다. 다른 노드의 설치/가입 ACK를 뜻하지 않는다.

```sh
sfcli --config node-admin.yaml catalog-policy show
sfcli --config node-admin.yaml catalog-policy prepare --request enable-user-catalog-1 > catalog-activation.json
sfcli --config node-admin.yaml submit catalog-activation.json
sfcli --config node-admin.yaml result catalog-activation.json
```

`prepare`는 원 서명 command만 출력하며 자동 제출하지 않는다. Unknown이면 같은 파일을 보존하고 원 결과부터 조회한다. 이미 활성 상태에서 새 activation을 준비하지 않는다. 초기 user 등록은 활성화 뒤 기존 `enroll-admin`으로 별도 수행하고 이후 `auth: user` 프로필로 login한다. 설정 플래그 변경으로 기존 DB를 초기화하거나 native source·journal·pin을 다시 만들지 않는다. static→managed 전체 이행은 별도 E6 조건이다.

### managed 이행의 원 계획·노드 준비

원 catalog가 활성화된 static cluster의 node-admin 프로필로 계획을 고정한다. genesis는 실제 구성에 설치된 기존 voter ID다. 계획과 각 원 노드의 public certificate를 보관한다.

```sh
sfcli --config node-admin.yaml catalog-policy plan-managed --genesis node-a --request retain-original > adoption-plan.json
# 이행·재시작할 해당 원 노드에서 daemon을 정지한 뒤 실행
sfcd --config original-static-node.yaml adopt --plan adoption-plan.json > node-adoption.json
```

`plan-managed`는 최신 quorum·원 admin epoch·source manifest/policy·native index/order/peer/floor와 원 operation의 서명 계획만 출력한다. `adopt`는 원 root/키/DB와 실제 설치 구성을 readonly 확인한 뒤 원 node의 로컬 준비 intent와 서명 사실만 보관한다. 실행 중 root·다른 계획·누락/뒤처진 source·다른 cluster/신원은 오류다. 같은 계획의 재실행은 원 사실을 반환한다. 이 준비는 shared 활성화/Ready와 구분한다. source voter는 준비 뒤 원 static 설정으로 재개한 다음 원 관리자 프로필에서 다음 artifact를 보존·제출한다.

```sh
sfcli --config node-admin.yaml catalog-policy prepare-managed --plan adoption-plan.json --source node-adoption.json > managed-activation.json
sfcli --config node-admin.yaml submit managed-activation.json
# 확정된 source daemon은 managed 재시작 필요를 알리고 정지한다.
# 각 node에서 원 prefix 설치/정지 뒤 같은 계획으로 local adopt를 재사용/복구한다.
sfcd --config original-static-node.yaml adopt --plan adoption-plan.json
sfcd --config managed-node.yaml run
sfcli --config node-admin.yaml result managed-activation.json
```

전환 지원 빌드를 모든 voter에 먼저 배치한다. native 구성 index/bytes가 바뀐 계획은 거부하며 Unknown이면 원 artifact를 유지하고 결과부터 조회한다. 로컬 committed marker가 없는 managed 기동은 원 static runtime으로 prefix를 먼저 설치하라는 오류를 낸다. managed 설정은 같은 ID/listen/identity/state 경로를 사용한다. 전환 뒤 원 nonmember node-admin은 자기 exact 원 command의 result만 조회하며 get/새 submit·tenant/member 권한을 물려받지 않는다. 수락과 원 DB 재시작 뒤의 committed marker·현재 정책 조회를 구분한다.

<a id="후속-사용자-로그인tenant-선택"></a>

