# 대화 모양

purpose마다 모양이 하나다([purpose 지도](02-purposes.md)의 "모양" 칸). 모양은 대화가 어떻게 흘러가는지를 정하고, 허용 판단은 kind마다 따로 한다.

## unary

요청(kind 1) 하나, 응답(kind 2) 하나. 보내는 쪽은 요청 뒤 쓰기를 닫고, 응답은 요청 digest를 되돌린다. `Session.Call`이 이 모양이다. Management, Raft, PathControl, User, Membership, SecretInput, VolumeFS가 쓴다.

- relay(kind 3)는 다른 member가 원 요청을 바꾸지 않고 대신 전달하는 것이다. 받는 쪽은 원 서명과 원 actor의 현재 권한을 다시 검사한다. relay 권한이 원 명령을 허가하지 않는다.
- `Call`은 재시도하지 않는다. 보내기 전 실패(NotSent)와 보낸 뒤 실패를 호출자에게 구분해 돌려준다. 보낸 뒤 응답을 잃으면 결과는 Unknown이고, 원 request ID로 결과를 다시 묻는다.

## sensitive

unary와 같은 흐름에 비밀 바이트가 실린다. 양쪽이 쓴 뒤 버퍼를 지우고, 쓰기 닫기와 EOF를 확인한다. 로그·journal·Raft에는 값을 남기지 않는다. SecretFetch, CertificateMaterial, VaultValue가 쓴다.

## bulk

요청 → 순서 있는 조각 → 끝 → ACK.

- 요청(kind 1)의 SHA-256이 대화의 binding이다. 모든 조각·끝·ACK가 binding을 싣는다.
- 조각(kind 4) = `offset u64 | data | binding`. 크기는 VolumeTransfer 128KiB, 나머지 24KiB다.
- 끝(kind 6) = 전체 길이와 digest. 선언한 크기를 넘으면 받는 쪽이 끊는다.
- 저장 ACK(7)는 받는 쪽이 내구 저장했을 때만, 최종 ACK(8)는 전체 digest가 맞을 때만 보낸다.
- 이어 받기는 없다. 끊기면 새 대화로 처음부터 한다.

Snapshot, VolumeTransfer, CheckerArtifact, CheckerProbe, ImageContent, VolumeFile, ClusterBackup과 User의 조각 입력이 쓴다.

## duplex

요청 하나로 열고, 그 뒤 양쪽이 순서 있는 record(kind 5) 또는 purpose 고유 kind를 주고받는다. 연결이 이어지는 동안 열려 있고, handler가 자기 기한과 idle 한도를 묶는다. ContainerSession, NodeShell, ChangeWatch, Topic이 쓴다.

## report

보고 frame 하나(kind 16+, 종류마다 kind가 다르다)와 ACK(kind 2). 한 frame에 같은 종류의 항목을 64KiB까지 묶을 수 있고, ACK는 항목마다 받음·거절을 돌려준다. [보고](05-reports.md)에 자세히 있다.

## datagram

Packet(purpose 6)만 쓴다. QUIC DATAGRAM 하나에 frame 하나, request ID는 0이다. 순서·도착을 보장하지 않는다.

## Unix에서

Unix 관리 연결은 한 번에 대화 하나다. 한 로그인의 짧은 대화들은 연결 하나를 차례로 쓰고, "오래 열림" purpose의 대화는 연결 하나를 혼자 쓴다. 진행 중인 대화가 취소되면 record 경계를 이어 갈 수 없어서 그 연결이 닫힌다. 그때 아직 보내지 않은 대화는 새 연결로 한 번 다시 연다.
