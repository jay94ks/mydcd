## Ingress 관측·Raft 차단과 CertificateMaterial

User purpose8에 `ingresses`, `certificates` 읽기를 추가한다. 둘 다 typed method다. `ingresses`는 `Params:{Node,Tenant,App,Key,Part,After,Offset}`, 인증서 읽기는 `Params:{ID,After}`이고 Request에 다른 업무 필드를 두지 않는다. 응답은 Reply.Data(IngressPage / `{Page,RootRevision}`)에 공개 결과만 넣는다. [Ingress 메시지·페이지](../../reference/ingress-management.md)와 [인증서 공개 정보](../../reference/certificate-store.md)를 따른다.

ingresses의 `IngressPage.BlockRevision`은 현재 정책 book의 목표 revision이다. `RootRevision`(저장 root CAS)·블록별 `Revision`과 다른 단위이며 실제 설치와 비교하지 않는다. owner snapshot은 실제 설치 차단 정책의 `Runtime.BlockRevision`도 반환한다. 해제된 목표 ID의 부재만으로 적용을 증명하지 않으며 원 해제 revision까지의 실제 설치를 확인한다. 이 node-local 관측을 현재 Raft 목표/실행 승인과 혼합하지 않는다.

ingresses의 owner snapshot은 호스트별 `Runtime.Certificates`와 현재 권한으로 필터한 `Nodes.Gateways.Listeners`의 공유 listener/host binding도 포함한다. 인증서와 gateway binding은 `Params.Offset`으로 각각 최대4개씩 이어 읽으며 원 TLS material/key를 관측에 포함하지 않는다. gateway의 전역 거부/unmatched 계수는 tenant 범위에 공개하지 않는다.

SecretInput purpose10의 `Mode:certificate` Body는 `Schema:1,Nonce,ID,Mode,Certificate:{Request,Recover,Chain,Key}`다. ID=Request이며 Realm은 비어 있고 다른 Secret selector/values/password/origin과 배타적이다. Chain/Key는 각각8KiB 이하의 PEM bytes(JSON base64)이고 frame Body 최대64KiB를 유지한다. 인증된 현재 사용자와 현재 put-certificate 권한을 검사한 뒤 sealed receipt만 Reply.Certificate로 반환한다. 최초 입력은 WorkKey 노드, 원 receipt의 Recover는 현재 MemberKey인 원 sealer에서 처리한다. 입력 배열과 원 frame/body는 사용 후 지운다. DB/I/O 또는 응답 유실은 unknown이며 FD 재전송을 허용하는 denied로 바꾸지 않는다.

`CertificateMaterial=17`은 현재 설치 member 간 유한 stream이다. kind1 요청/kind2 응답 모두 tag1 JSON bytes, tag2 tag1의 SHA-256:32이며 전체 Body 상한64KiB, 전송 owner 동시성2다. 사용자/Unix·relay·early data·datagram은 허용하지 않는다. 답하는 쪽은 마스터 키를 가진 현재 voter뿐이다. 요청 body는 셋 중 하나다. `{Read: CertificateMaterialRead{Schema:2}}`는 cluster/인증서 ID/receipt digest·consumer·실제 ingress ObjectRef·host에 고정한다(그 host에 지금 연결된 인증서만). `{Seal: SealRequest{Schema:1,Cluster,Member,ID,Leaf,At,Proof}}`는 아직 목록에 없는 업로드의 키를 요청하며, Proof는 인증서 비공개 키의 서명이다. `{Master:{Schema:1,Cluster,Voter,At}}`는 현재 voter가 마스터 키를 요청한다. 응답은 `Schema:1,Certificate:<receipt digest32 | 인증서 ID | 0>,Key:<32 bytes>`다. 현재 권한/참조를 송수신 전후 재검사하며, 받은 쪽은 인증서 키를 메모리에만 두고 마스터 키만 자기 identity로 봉인해 저장한다. 이 JSON은 공개 User Reply·Raft 명령·이벤트가 아니다.

member Management `ingress-observe`는 원 사용자 Session/IngressQuery를 보존해 실제 owner의 현재 mapping·최근 지표·block 적용을 조회한다. 설치 member라는 사실만으로 다른 tenant의 사용자 권한을 만들지 않는다. typed `ingress-block/ingress-unblock/ingress-block-extend/set-ingress-host-policy`와 `put/delete/disable-certificate`는 기존 사용자 승인·Raft/CAS·원 operation 경계를 사용한다. member `certificate-expiry-report`는 현재 voter가 관측한 시각/서명이며 결정적 reducer는 그 고정 입력만 소비한다.


