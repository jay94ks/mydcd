## Managed 가입 directory 경계

User method `members`는 현재 ManageCluster 권한을 요구한다. `After`는 node ID cursor이며 한 응답에 최대8개 Entries와 MembersRootRevision/MembersNext를 반환한다. 다른 목록 method의 After 허용 여부와 cursor 형식은 각 handler 계약을 따른다. 여러 페이지의 일관성은 동일 root revision으로 확인한다. `invite-node`/`promote-node` UserOperation의 CAS는 `control/members` root를 선택하며 기존 UserOperation 바이트 구조/서명 domain과 schema1은 유지한다. CLI node 명령은 가입 directory와 runtime lifecycle의 조회·변경 대상을 구분한다.

현재 lookup의 Replicate는 Raft/Snapshot와 자기 가입/ACK용 Membership 목적만 허용한다. Snapshot은 별도 Snapshot 허가도 요구하고 User kind3/Management relay·Observation·PathControl/Packet은 Member/기존 목적 권한을 그대로 요구한다. Public UserAuth와 Replicate를 합쳐도 relay/투표/관리 권한이 생기지 않는다. 실제 가입/설치 ACK는 D5.14 완료 근거의 Membership handler에 연결한다.


Membership=9의 kind1 요청/kind2 응답은 required TLV1 정규 JSON·TLV2 SHA-256을 사용하고128KiB body/동시8 stream을 제한한다. kind1은 현재 Member/Replicate, kind2는 그 권한과 Respond가 필요하며 UserAuth만으로는 접근하지 못한다. method는 join/install/status이고 Schema/Node/JoinID·설치 시 대상 ACK를 포함한다. 수신한 TLS key가 현재 승인 target key와 같아야 자기 가입/설치 요청을 처리한다. 현재 control의 전달 서명과 대상 ACK 서명을 구분하며 타 대상/cluster/서명 위조를 거부한다.

User method node-invitation은 Node를 지정하고 현재 ManageCluster를 요구한다. 현재 leader control이 cluster/admin/genesis·source/target peer·Join ID·승인 revision/실제 MinimumIndex를 서명한다. 소비자는 별도 외부 cluster/control pin으로 검증한다. 초기 복제 seed는 그 prefix까지 제한하며 이후 current directory가 peer/issuer 권위를 갖는다. wire header/schema와 기존 purpose 번호는1/1–8을 유지한다.

가입 응답은 Code/현재 Entry를 반환하며 SDK 호출 성공만으로 Joined를 표시하지 않는다. 실제 native configuration/log/Snapshot과 local 설치 checkpoint를 확인하고 첫 송신 전 저장한 원 ACK를 과반수에 확정한 뒤 정상 admission을 연다. Unknown은 원 작업/ACK를 유지하며 자동 재제출하지 않는다. 같은 DB의 명시 join/run 재개는 원 effect 조회/정산을 사용한다.


