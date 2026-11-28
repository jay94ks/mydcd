# purpose 지도

스트림의 첫 frame이 purpose를 정하고, transport는 아래 표 하나(`internal/sfcp/purposes.go`의 `purposes`)로 frame 해석, 허용, 동시 스트림 한도, handler 수명, Unix 허용을 판단한다. 새 purpose는 상수 하나와 표 한 줄을 더하는 것으로 생긴다.

아래 표는 코드 표를 그대로 옮긴 것이다. `TestPurposeMapDocMatchesTable`이 두 표가 같은지 확인한다. 표를 바꾸면 `SFCP_WRITE_DOCS=1 go test -run TestPurposeMapDocMatchesTable ./internal/sfcp/`로 이 칸을 다시 쓴다.

- **동시 스트림**: 이 노드가 그 purpose를 한 번에 처리하는 스트림 수, 괄호는 한 키당 몫. `한도 없음`은 permit을 쓰지 않고 handler가 스스로 자원을 묶는다(Topic).
- **Unix**: 로컬 관리 소켓에서도 받는다.
- **오래 열림**: handler가 30초 해석 기한 대신 transport 수명을 받고, 자기 기한을 직접 묶는다. Unix에서는 그 대화가 연결 하나를 혼자 쓴다.

<!-- purposes:begin -->
| # | 이름 | 모양 | kind (본문 한도) | 동시 스트림 (peer당) | Unix | 오래 열림 |
|---|---|---|---|---|---|---|
| 1 | handshake | handshake | 1 (4KiB), 2 (4KiB), 3 (4KiB), 4 (4KiB) | – | ○ |  |
| 2 | management | unary | 1 (128KiB), 2 (128KiB), 3 (128KiB), 16 (128KiB) | 16 (8) |  |  |
| 3 | raft | unary | 1 (256KiB), 2 (256KiB) | 32 (16) |  |  |
| 4 | snapshot | bulk | 1 (4KiB), 4 (131136B), 8 (128B) | 2 |  |  |
| 5 | observation | report | 2 (2KiB), 16 (64KiB), 18 (64KiB), 19 (64KiB) | 8 (4) |  |  |
| 6 | packet | datagram | 1 (65663B), 2 (65663B) | – |  |  |
| 7 | path-control | unary | 1 (4KiB), 2 (4KiB) | 8 |  |  |
| 8 | user | unary | 1 (128KiB), 2 (128KiB), 3 (128KiB), 4 (24640B) | 16 | ○ |  |
| 9 | membership | unary | 1 (128KiB), 2 (128KiB) | 8 |  |  |
| 10 | secret-input | unary | 1 (64KiB), 2 (64KiB) | 8 | ○ |  |
| 11 | secret-fetch | sensitive | 1 (128KiB), 2 (128KiB) | 4 |  |  |
| 12 | volume-transfer | bulk | 1 (32KiB), 4 (131136B), 6 (128B), 7 (64B), 8 (128B) | 1 |  | ○ |
| 13 | checker-artifact | bulk | 1 (32KiB), 2 (24KiB), 4 (24640B), 6 (128B), 7 (128B), 8 (128B) | 2 |  | ○ |
| 14 | checker-probe | bulk | 1 (128KiB), 2 (2KiB), 4 (24640B), 6 (128B), 7 (128B), 8 (128B) | 2 |  | ○ |
| 15 | container-session | duplex | 1 (128KiB), 2 (128KiB), 3 (128KiB), 5 (128KiB) | 8 | ○ | ○ |
| 16 | image-content | bulk | 1 (128KiB), 2 (128KiB), 3 (128KiB), 4 (24640B), 16 (128KiB), 17 (128KiB) | 2 | ○ | ○ |
| 17 | certificate-material | sensitive | 1 (64KiB), 2 (64KiB) | 2 |  |  |
| 18 | volume-file | bulk | 1 (128KiB), 2 (128KiB), 3 (128KiB), 4 (24640B) | 2 | ○ | ○ |
| 19 | node-shell | duplex | 1 (128KiB), 2 (128KiB), 3 (128KiB), 5 (128KiB) | 64 | ○ | ○ |
| 20 | cluster-backup | bulk | 1 (128KiB), 2 (128KiB), 3 (128KiB), 4 (24640B) | 1 | ○ | ○ |
| 21 | vault-value | sensitive | 1 (192KiB), 2 (192KiB) | 4 |  |  |
| 22 | change-watch | duplex | 1 (128KiB), 2 (128KiB) | 32 | ○ | ○ |
| 24 | volume-fs | unary | 1 (136KiB), 2 (136KiB) | 64 (16) |  |  |
| 26 | topic | duplex | 1 (65600B), 2 (1KiB), 7 (65600B), 16 (65600B), 17 (65600B), 18 (65600B), 19 (64B), 20 (64B) | 한도 없음 |  | ○ |
<!-- purposes:end -->

## purpose마다

| # | 쓰는 곳 | 보내는 쪽(정책) | 비고 |
|---|---|---|---|
| 1 handshake | `authenticate.go`, `discovery.go` | 인증 전만 | 1 hello, 2 proof, 3·4 공개 신원 확인(최초 등록 전 discovery). 확장 tag 129 = 기능 목록 |
| 2 management | `cluster/management.go`, 노드 method 등록표 | Manage(1), Respond(2), Member(3 relay), Read(16 read) | 노드 서명 봉투 |
| 3 raft | `cluster/transport.go` | Member 또는 Replicate | 로그·snapshot 형식과 상관없는 전송 인코딩 |
| 4 snapshot | `cluster/transport.go` | (Member 또는 Replicate) 그리고 Snapshot | metadata 1 → 조각 4 → installed 8 |
| 5 observation | `app/reports.go`, `app/diagnostic_events.go`, `app/app_renewal.go` | Report, Respond(2 ACK) | [보고](05-reports.md) |
| 6 packet | `network/plane.go` | Tunnel | DATAGRAM. 1 IP, 2 route IP |
| 7 path-control | `path_control.go` | Member 그리고 Tunnel | |
| 8 user | `userauth` | UserAuth(1), Respond(2), Member(3 relay, 4 조각) | 사용자 method. 기능별 규칙은 [rules/](../sfcp.md#기능별-규칙) |
| 9 membership | `app/join_transport.go` | Member 또는 Replicate | 가입 |
| 10 secret-input | `userauth/secret.go` | UserAuth, Respond | [Secret 보호 입력](rules/06-secret.md) |
| 11 secret-fetch | `app/app_input_fetch.go` | Member | [원격 앱 입력](rules/14-secretfetch.md) |
| 12 volume-transfer | `app/volume_move_transfer.go` | Member | 128KiB 조각. 1 → 4 → 7 → 6 → 8 |
| 13 checker-artifact | `app/checker_artifacts.go` | Member | |
| 14 checker-probe | `app/checker_remote_provider.go` | Member | 양쪽이 조각과 끝을 보낸다 |
| 15 container-session | `userauth/container_session.go` | UserAuth, Respond, Member | |
| 16 image-content | `userauth/image_content.go` | UserAuth, Respond, Member(16 source read, 17 엔진 read) | |
| 17 certificate-material | `app/certificate_store.go` | Member | |
| 18 volume-file | `userauth/volume_files.go` | UserAuth, Respond, Member | [Volume 파일](rules/30-volume.md) |
| 19 node-shell | `userauth/node_shell.go` | UserAuth, Respond, Member | [노드 shell](rules/24-shell-purpose19.md) |
| 20 cluster-backup | `userauth/cluster_backup.go` | UserAuth, Respond, Member | |
| 21 vault-value | `app/vault_builtin.go` | Member(handler가 voter 확인) | [VaultValue](rules/32-vault-value.md) |
| 22 change-watch | `userauth/change_watch.go` | UserAuth, Respond | [변경 watch](../../reference/change-watch.md) |
| 24 volume-fs | `volumeshare` | Member(handler가 consumer binding 확인) | 연산 하나가 스트림 하나, 데이터는 확장 tag 128 |
| 26 topic | `internal/sfcp/topics.go` | Member(handler가 가족 ACL 확인) | [Topic 채널](05-reports.md#topic-채널) |

23은 비어 있다. 25는 경유 세션(Transit, 0.1.1)용으로 예약돼 있어 이 빌드에서는 모르는 purpose로 거절된다.
