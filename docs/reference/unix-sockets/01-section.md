## 끝점 목록

member Management `image-build-automatic-git-report`는 원 Automatic 사용자 정의·SavedGit/시작 시각/의도 지문을 확인해 기존 Raft의 archive/version/job·Secret 참조를 원자 수락한다. 사용자 메시지나 새 로그인으로 노드 보고를 위장하지 않는다. [보고 포맷·수명](../image-build-contexts/17-git.md)을 따른다.

Automatic Git 컨텍스트의 결과는 기존 User `image-builds Part:contexts`의 optional `GitObservation`으로 읽는다. 내부 member Management `image-build-git-observation-report`의 원 정의/owner 서명·Result·관측 CAS/전역 CAS와 공개 필드는 [자동 관측 명세](../image-build-contexts/16-git.md)를 따른다. 사용자 끝점에 노드 관측 입력 권한을 추가하지 않는다.

User `check-build-context` Params `{Tenant,Query:{ID}}`와 응답 `Data`는 [등록 Git source 확인](../image-build-contexts/03-user.md)을 사용한다. 설치된 owner의 같은 credential profile/HTTPS fetch 경계이며 임의 URL/자격을 요청에 실어 보내지 않는다. owner relay도 기존 member SFCP Management `image-build-source-owner` 안에 둔다.

빌드 upload의 자동 만료와 물리 회수는 클라이언트 socket EOF가 아니라 기존 member owner report로 정산한다. User `image-builds`의 upload row는 optional `ExpiredAt`/`ReclaimedAt`으로 두 단계를 구분한다. version 명시 삭제 action과 owner report의 [포맷/권한](../image-build-contexts/01-section.md)을 따른다.

ZIP 조각 전송은 같은 User 목적8의 typed method `build-zip-transfer`(응답 `Data`)를 사용한다. 원 signed begin/UploadScope의 optional `ChunkBytes`는 생략/0인 기존24KiB 또는32768인32KiB만 받으며 원 Scope의 Hash·서명·offset(`Index * PartSize`)에 고정한다. 새 CLI begin만 현재 Session(Approval 포함) JSON≤8KiB에서32768을 고르고 더 큰 Session은0을 쓴다. 원 begin/journal 재개는 그 크기를 유지한다. Unix/QUIC와 member owner/permit의 기존128KiB frame 상한은 바꾸지 않는다. creator의 raw part proof·owner/quorum·고정 scope/CAS와 영수증 포맷, optional `Record`의 사용자 서명과 owner 보고 확정(`Recorded`/`UploadRevision`), CLI `build context upload`는 [빌드 컨텍스트 API](../image-build-contexts/05-zip.md)를 따른다. 임의 파일 쓰기나 node CLI 관리 권한을 여는 끝점이 아니다.

User purpose8의 typed method `image-builds`의 Params와 응답 `Data`는 [빌드 컨텍스트 API](../image-build-contexts.md)의 메시지/selector/포맷을 사용한다. tenant Read/ManageRegistry의 공개 metadata와 creator 전용 upload 진행을 구분한다. 정책/컨텍스트 정의 및 owner part/seal fact 수락은 같은 UserOperation 코어의 `control/image-builds` namespace이며 ZIP bytes를 관리 변경에 넣지 않는다. 실제 stage/build 연결 범위도 해당 명세에 표시한다. version row의 optional Commit과 관리 publish-build-git의 Saved/Expected/원 creator 서명은 같은 API의 [Git 게시 형식](../image-build-contexts/14-git-archive.md)을 따른다.

| 끝점 | 소유/방향 | 프로토콜 | 역할 |
|---|---|---|---|
| `unix:///run/sfcdp.sock` | sfcd가 listen, sfc가 connect | TLS 1.3 이상 + SFCP + 아래 record Contract1 | 로컬 사용자 인증·조회·관리·보호 입력 |
| `unix:///<사용자 지정 절대 경로>` | 해당 노드의 sfcd | 위 관리 끝점과 동일 | `node.management_socket`으로 지정한 로컬 관리 주소 |
| `unix:///var/run/docker.sock` | Docker Engine이 listen, Sfc의 Docker SDK가 connect | Docker Engine HTTP API | 컨테이너·망·Volume·exec 등 실제 Docker 효과 |

Docker 소켓은 Sfc의 외부 의존 서비스다. Seafield Cluster 관리 클라이언트는 `/run/sfcdp.sock`의 TLS/SFCP를 구현하고, Docker SDK는 별도의 Docker API를 사용한다. Sfc의 node 간 Raft·Snapshot·터널 데이터는 QUIC의 SFCP 경계를 사용한다.

