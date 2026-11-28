## 이관 대상의 비공개 입력 준비

원 app-target 이관의 prepare-inputs는 기존 volume-move-permit의 current member/latest quorum read다. 원 target 또는 고정 Blueprint의 실제 소비/망 owner node만 요청하며 응답은 원 job과 공개 read-set/command index만 전달한다. leaf/profile/입력·node별 자원 확인 목록은 같은 최소 index·job/read-set이 반영된 로컬 replica에서 재구성해 관리 프레임의 크기를 늘리지 않는다. read-set은 현재 native source와 모듈/Ingress 확인 입력을 포함하고 Secret이 없는 노드도 서명 대상에 포함한다.

volume-move-inputs-observe는 Latest=false로 실제 소비 node에 직접 전달하는 member-only readback이며 원 target caller만 허용한다. 소비 node가 자신의 최신 permit을 얻은 뒤 기존 SecretFetch에 optional Move selector·최소 index/read-set을 고정해 자신의 leaf만 읽는다. Move와 Task Binding selector 혼입·다른 node의 leaf·stale read-set/최소 index·미승인/회수는 거부한다. provider는 기존 조회 전후 app-input-read-permit·비공개 응답/바이트 한도를 그대로 사용한다. 일반 user relay/Unix socket·별도 TCP/HTTP 경로로 값을 운반하지 않는다.

관측 응답은 schema1·원 Selection/job digest/read-set/실제 consumer key/시점과 해당 node 서명뿐이다. target은 모든 필요한 node의 서명/30초 신선도와 마지막 current read-set을 확인하고 TargetPreparation의 optional Inputs/InputsAt에 가장 이른 시점을 결합한다. 새 준비 보고와 source quiesce 모두 현재 read-set/30초 신선도를 검사한다. optional nil은 과거 schema1 원 bytes/정산만 보존하며 새 app-target source 중지 허가가 아니다. 이 관측은 원 소비자의 실제 merge/파일 구성과 해당 owner의 native 망/DNS·모듈·TLS/TCP/HTTP3 UDP 확인이다. 확인용 소켓은 즉시 닫으며 관측 시점은 망 확인 시작 전부터 계산한다. 새 Task/Binding 세대·내구 게시/Start 허가·지속적인 OS 포트 독점이나 미래 Ready를 만들지 않는다. Secret 원문/원문 hash·설치 URL/token은 관리 응답/Raft/Snapshot에 싣지 않는다.

