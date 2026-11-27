## Volume transfer 경계

D2 이관 설계의 source artifact 게시와 전용 VolumeTransfer=12 reliable stream을 연결한다. 현재 원 작업/전체 peer·고정 artifact/기한을 검사하며 Snapshot·관리·Packet을 파일 복사용으로 재해석하지 않는다. 수신은 같은 private artifact root/A2 journal의 원 파일·offset/prefix 내구 저장과 같은 DB 재개를 사용한다. 실제 비활성 native 복원/owner CAS는 같은 이관의 관리 경계에 연결하며, 앱 writer/SQL·전체 crash/제어 트래픽 장애 조합은 남아 있다. 자체 schema는1이며 필수 목적을 지원하지 않는 peer는 거부한다. Vault 외부 HTTPS 공급과 Seafield Cluster node 간 제어/이관은 서로 다른 신뢰 경계다.

VolumeTransfer는 현재 Member만 사용하며 Replicate·일반 사용자/관리 읽기·0-RTT·DATAGRAM·다른 목적 stream을 허용하지 않는다. parsing은 기존30초/64 slot을 유지하고 승인 후 dedicated handler1개·128KiB 조각/비행2개·송신8MiB/s를 사용한다. source는 원 Job/전체 target key·현재 quorum 허가/Manifest·불변 ExpiresAt을 검사하고 각 창/최종 응답 전에 다시 허가를 확인한다. stream 전체는 원 plan 기한, 각 frame I/O는 최대30초와 남은 plan 기한 중 작은 값이다. 일반 RPC의30초 전체 제한은 유지한다. source Runtime 종료는 handler context/FD/원 artifact worker도 중단/회수한다.

재개 요청은 같은 Job binding/artifact·원 Offset/Prefix SHA256을 사용한다. source는 실제 원 파일의 해당 prefix를 대조하고 source의 A3 파일 참조를 잡은 채 전송한다. chunk digest는 요청/offset/data에 결합하며 별도 hash chain이 아니다. `VolumeSink.WriteChunk`는 파일/offset을 내구 sync한 뒤에만 새 offset을 반환해야 하며, 그 뒤 wire ACK를 보낸다. 마지막 verified ACK는 전체 profile/digest/완료 sync를 담당하는 Finish 성공 뒤에만 보낸다. 네트워크 쓰기/부분 ACK로 target native/SQL Ready를 만들지 않는다. source의 불명 stream 참조는 재개 또는 exclusive worker 정산 후 명시 취소까지 보존하며 remote target 예약은 source 정산만으로 반환하지 않는다. 기존 QUIC 경계와 source-only 경계의 sink는 시험 어댑터다. 실제 receiver 경계는 현재 target member의 quorum 허가·제품 파일/offset sync 실패/ACK 부재·같은 A2 DB/inode 재개·전체 profile/완료 sync를 검증했다. target reconciler는 native 미설치 member에서 직접 호출했으며 실제 비활성 Volume/SQL 복원은 이 결과에 포함하지 않는다.


수신은 원 Job과 source 서명 Manifest에 local A2 intent/디렉터리 inode checkpoint를 묶는다. 최초 archive는 exclusive/no-follow로 만들고 진행 파일의 device/inode·offset/prefix를 보존한다. 재개는 원 prefix를 읽고 file/metadata/directory를 재-sync한 뒤 해당 offset만 요청한다. data sync→progress sync/원자 rename→directory sync 전 ACK를 금지한다. 미확정 tail은 같은 조각과 일치하는 바이트만 인정하고 부족분을 append하며 truncate/다른 inode 채택을 하지 않는다. 완성 뒤 idle controller는 큰 파일을 매 tick 다시 hash/sync하지 않으며 다음 native 소비자가 원 파일/A3를 검증해야 한다. cleanup은 실제 local worker/소유 파일 정산이며 shared target 예약/native 종료 proof를 대신하지 않는다.


앱 경로의 source quiesce는 target 서명 preparation(원 Binding/NativeReady·empty/no-writer/space/protocol 관측) 뒤에만 허가한다. quiesce는 원 accepted 앱 operation/plan과 Deploy cleanup 범위를 검사하고 기존 Inventory retirement를 사용한다. Volume/App 두 checkpoint를 같은 typed transaction으로 게시하며 새로운 down 서명을 만들지 않는다. 기존 retirement·retained source 증거 전에는 source archive reader를 취득하지 않는다. 전송 완료 뒤 native 소비자는 같은 파일/A3·원 staging consumer로 실제 cold 복원/검증을 수행한다. target 서명 copied 보고의 CopyProof/정확한 NativeReady·artifact 반환을 같은 Raft/root/Volume CAS로 검사한 뒤 Verified로 진행한다. 이때 source는 exclusive 전송 worker/파일/reader만 정산할 수 있다. `commit-volume-move`는 원 owner revision·target NativeReady와 현재 accepted scope/기한·Verified/reader0을 검사해 registry Native/용량과 owner를 같은 변경으로 확정한다. 별도 파일 프로토콜·소유권 상태를 만들지 않으며 writer 활성은 다음 Arm/Task 경계다. 전송/앱 소비의 상세 경계는 이관 계약을 따른다.


<a id="후속-secret-보호-입력과-승인"></a>

