## 허용 메시지와 payload

Unix 관리 listener의 업무 목적은 **User=8**, **SecretInput=10**, **ContainerSession=15**, **ImageContent=16**, **VolumeFile=18**, **NodeShell=19**다. node 관리 명령도 사용자 관리 API를 통해 처리한다. node 간 `Management=2`, Raft, Snapshot, Observation, Packet, PathControl, Membership, SecretFetch, VolumeTransfer, CheckerArtifact, CheckerProbe, CertificateMaterial을 이 listener에 직접 dispatch하지 않는다. relay 수신도 Unix 로컬 관리 요청으로 허용하지 않는다.

| purpose/kind | 필수 TLV | body 한도 |
|---|---|---|
| User / 1 요청 | tag1 Envelope JSON, tag2 그 JSON의 SHA-256 32바이트 | 128KiB |
| User / 2 응답 | tag1 Reply JSON, tag2 **원 요청** Envelope JSON의 SHA-256 | 128KiB |
| User / 4 입력 조각 | tag1 offset u64 LE, tag2 data, tag3 원 header digest32 | 24KiB+64바이트 |
| SecretInput / 1 요청 | tag1 SecretRequest를 감싼 Envelope JSON, tag2 그 Envelope의 digest32 | 64KiB |
| SecretInput / 2 응답 | tag1 응답 JSON, tag2 원 요청 digest32 | 64KiB |
| ContainerSession / 1 요청, 2 응답 | tag1 Envelope/SessionReply JSON, tag2 원 요청 Envelope digest32 | 128KiB |
| ContainerSession / 5 record | tag1 SessionRecord JSON, tag2 원 Intent digest32 | 128KiB |
| ImageContent / 1 요청, 2 응답 | tag1 Envelope/ContentReply JSON, tag2 원 요청 Envelope digest32 | 128KiB |
| ImageContent / 4 data | tag1 offset u64 LE, tag2 data, tag3 원 요청 Envelope digest32 | 24KiB+64바이트 |
| VolumeFile / 1 요청, 2 응답 | tag1 Envelope/reply JSON, tag2 원 요청 Envelope digest32 | 128KiB |
| VolumeFile / 4 data | tag1 offset u64 LE, tag2 data, tag3 원 header digest32 | 24KiB+64바이트 |
| NodeShell / 1 요청, 2 응답 | tag1 Envelope/NodeShellReply JSON, tag2 원 요청 Envelope digest32 | 128KiB |
| NodeShell / 5 record | tag1 NodeShellRecord JSON, tag2 NodeShellRequest Body의 SHA-256 | 128KiB |

User kind4는 해당 업로드/큰 계획 입력 handler가 정의한 순서와 EOF 안에서만 사용한다. 모든 일반 조회/관리 요청이 여러 frame을 받는다는 뜻은 아니다. 서버는 handler 뒤의 추가 입력을 검사하고 정상 EOF 외의 여분 바이트를 거부한다.

