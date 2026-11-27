# Tenant에 허용된 저장 경로 조회

`tenant-storage`는 특정 tenant에서 사용할 수 있는 node 저장 root의 읽기 전용 조회다. 현재 사용자에게 그 tenant의 `ManageVolumes` 또는 `ManageRegistry` 권한이 있어야 한다. viewer·Read 전용 credential은 거부하며, 시스템 관리자도 현재 session의 해당 권한 범위를 충족해야 한다. 기존 시스템 관리자 `node-storage`·`node-storage-space`의 권한과 전체 root/실제 용량 조회는 바꾸지 않는다.

```sh
sfcli --tenant shop manage tenant-storage --node node-b
sfcli --tenant shop manage tenant-storage --node node-b --after CURSOR
sfcli --tenant shop node storage list
```

첫 명령은 한 페이지를 출력한다. `TenantStorageNext`가 있으면 같은 tenant/node 선택에서 `--after`로 이어 읽는다. 저장 정책·사용자/tenant 권한·멤버십·epoch가 바뀌면 과거 cursor는 `conflict`로 거부되므로 처음부터 다시 읽는다. 기본 프로필의 tenant 선택 규칙은 다른 tenant 관리 명령과 같다. 이 명령은 root 등록·OS 디렉터리 생성·용량 예약·빌더 기동을 하지 않는다.

Unix TLS와 QUIC User purpose8의 요청은 다음 필드만 받는다.

```json
{"Schema":1,"Method":"tenant-storage","Tenant":"shop","Node":"node-b","After":"","Nonce":[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1]}
```

실제 Nonce는 요청마다 난수로 만든다. Node·After는 선택 사항이고 Tenant는 필수다. 다른 업무 selector·NodeStorage selection·Secret·operation을 혼합하지 않는다. 기존 User Envelope의 Session/현재 연결 proof·digest·쓰기 EOF·응답/EOF 계약을 사용한다.

Reply에는 다음 공개 필드가 있다.

| 필드 | 내용 |
|---|---|
| `TenantStorage` | 최대8개의 허용 root 행 |
| `TenantStorageNext` | 다음 페이지의 opaque cursor, 없으면 마지막 |
| `TenantStorageViewIndex` | 같은 committed 조회 상태의 Raft index |
| `NodeStorageRootRevision` | `control/node-storage`의 root revision |
| `NodeStorageRevision` | 저장 경로 catalog revision |

각 행은 `Node,ID,Generation,Revision,Draining,Allowed,Root`를 가진다. `Root`는 `nodestorage.Reference{Cluster,Node,Key,ID,Generation,Path}` 전체이며, Cluster·Key는 기존 Go `[32]byte`의 JSON 숫자 배열이다. 해당 tenant가 허용된 root의 실제 경로와 node 공개키는 반환한다. 다른 tenant의 목록/ACL·root·경로, node filesystem attestation·설치 개인키는 반환하지 않는다.

서버는 root의 Tenants ACL, tenant의 현재 AllowedNodes, 현재 설치 멤버/공개키와 사용자의 현재 role·credential scope를 같은 상태에서 검사한다. 다른 tenant 전용 root나 현재 tenant에 배정되지 않은 node는 목록에 나오지 않는다. `Allowed:true`는 조회 시 tenant ACL에 포함됐다는 의미다. Draining 행도 상태 확인을 위해 반환할 수 있으며 새 실행 허가를 뜻하지 않는다.

빌드 정책을 작성할 때 선택한 행의 `Root`를 그대로 `set-image-build-policy`의 `Spec.Nodes[].Root`로 사용한다. `{Node,ID}`만으로 서버가 임의 경로·최신 generation을 채우는 축약 입력은 추가하지 않는다. 실제 변경은 기존 사용자 signed operation·정확한 CAS·현재 ManageRegistry 권한·`CanBuild`·원 root generation/path/key·등록 attestation·work member fence를 다시 검사한다. 조회 이후 root의 tenant ACL이나 node 배정이 회수되거나 Draining이 되면 원 참조를 새 정책에 저장할 수 없다. 다른 경로/키로 고친 참조도 거부한다. root 조회 성공을 빌드 시작·저장 공간 예약·향후 성공으로 표시하지 않는다.
