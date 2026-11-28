# 사용 설명서

제품은 노드에서 실행하는 `sfcd`와 관리 명령 도구 `sfcli`로 구성된다. [모듈 설명](../architecture/modules.md)과 [실행·설정/명령 문법](../configuration/cli.md)을 함께 참조한다.

클러스터를 처음 구축하려면 [Quick-start](../quick.md)의 단일 노드·3노드·실행 중 추가/제거 절차를 따른다. 새 빌드로 바꿀 때는 [업그레이드](upgrade.md)를 따른다.

## 사용 순서

| 순서 | 작업 | 참고 |
|---|---|---|
| 1 | 노드 신원·상태 경로를 준비하고 새 클러스터 생성 또는 기존 클러스터 가입을 선택 | [CLI·node 명령](../configuration/cli.md), [cluster 동작](../mechanisms/cluster.md) |
| 2 | Linux user의 CLI 저장소에 cluster를 등록하고 node 공개키를 확인 | [CLI 프로필과 인증](../mechanisms/cli-identity.md) |
| 3 | `sfcli login`으로 계정을 선택하고 관리할 tenant를 등록/선택 | [CLI·설정](../configuration/cli/05-section.md) |
| 4 | tenant 관리 명령으로 이름 있는 망·Secret·Volume 등 앱이 빌릴 자원을 준비 | [자원표](../architecture/resource-ownership.md), [입력 경계](../architecture/app-and-cluster-spec.md) |
| 5 | 노드 배치와 이름 기반 자원 참조를 담은 `app.yaml`을 계획·적용하고 원 operation을 조회 | [배포 명령](../configuration/cli.md), [앱/lifecycle](../mechanisms/workloads.md) |
| 6 | 변경·중단·종료 시 원 요청의 결과와 실제 native 종료/참조 반환을 확인 | [원 요청과 결과](../algorithms/consensus-and-requests.md), [reconcile](../algorithms/reconciliation.md) |

샘플의 cluster ID·키·endpoint·node 이름·이미지 값은 실제 환경 값으로 바꾼다. [configs/](../../configs/)는 설정 예시, [docs/examples/](../examples/README.md)는 자원/앱 선언 예시다. 예제 파일을 읽는 것과 현재 환경에서 자원 생성·권한 승인을 수행하는 것은 별도 단계다.
