### SecretInput과 Vault write permit

User의 public `vault-write-plan`은 Tenant와 같은 Realm·ID·선택 Object/Profile/Kind/Keys를 받는다. current session/realm manager·원 actor 또는 system admin을 검사하고 같은 Tree.PlanWrite/PrepareWrite 코어로 대상 provider/CAS를 도출한다. 응답 schema1은 현재 root/tree revision·write epoch·원 request/object/write/서명 fact·current member/profile의 optional Receiver다. 원 write 조회는 새 효과를 만들지 않으며 ID가 없으면 Write=nil을 반환한다. private 값/비밀번호는 이 조회나 member relay에 포함하지 않는다. CLI는 이 quorum 응답으로만 response-only receiver pin을 얻어 직접 SecretInput을 사용하고 저장된 profile/node 권한을 바꾸지 않는다.

member Management의 `app-native-permit`은 현재 exact Source(key/generation/revision)에 결합한 managed TUN Goal도 지원한다. Kind=tunnel은 현재 owner/앱/권한·확정 원 결과·Bridge refs를 검사하고 native Spec SHA/MaxConsumers와 optional PacketLimits를 반환한다. node/tenant 큐 예산의 min이 양수이고 QueueBytes>=MTU+120이어야 한다. 별도 TUN/RPC 경로나 runtime/packet Ready를 만드는 응답이 아니며 관리 quorum은 기존 Latest 경로를 유지한다. 실제 managed path/plane 연결은 현재 TUN 범위를 따른다.

현재5시험의 SecretInput=10은 kind1 요청/kind2 응답만 지원한다. frame64KiB·동시8·early data/DATAGRAM/relay kind 금지이며 현재 UserAuth와 응답 Respond 허가를 구분한다. body는 session-bound Envelope 안의 SecretRequest(Schema/Realm/ID/Mode/Nonce/선택 Values)다. 일반 User/Management payload와 혼용하지 않는다. 현재 execute 값은 합계16KiB/128키이며 recover에는 Values를 보내지 않는다. 민감 원문은 node writer에게 직접 전송하고 다른 control에 redirect/relay하지 않는다.

writer는 public Management `vault-write-permit`를 Latest=true로 원 caller/current member와 함께 조회한다. 입력은 현재 Session/Realm/원 ID/execute 또는 recover/고정 At이며 시각은 edge에서30초 범위를 검사한다. leader는 current session/realm 권한·원 actor 또는 system admin·실제 member/profile/역할·원 source/operation 상태를 검사한다. 응답은 Cluster/Realm/원 WriteRecord/current Observer의 public metadata다. local 설치의 realm/profile/역할/HTTPS 경계와 다시 대조한 뒤 기존 native A2를 sync한다.

execute의 새 provider 호출은 원 Dispatched에 한하며 native Unknown 뒤 같은 요청을 보내도 ReadOriginal만 수행한다. recover의 부재/거부/timeout은 Unknown으로 남는다. 원 SDK receipt를 확인한 owner의 signed WriteObservation만 응답하며 shared Observe/별도 Publish CAS를 자동 완료로 추정하지 않는다. 원격 owner 호출·Group 승인·앱 Binding도 원 요청과 현재 permit을 사용하며 리더 변경으로 provider 쓰기를 새로 발급하지 않는다. public Vault 조회는 반복 native spec을 제외한 compact write 상태·최대8항목/112KiB·원 root CAS/정렬 cursor를 사용한다.


