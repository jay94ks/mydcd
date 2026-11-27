# 클러스터 인증서 보관함

보관함은 외부 HTTP/HTTPS 게이트웨이와 HTTP/3의 인증서를 공급하는 클러스터 자원이다. ACME 발급·DNS 검증·갱신 예약은 웹 앱이 담당한다. 내장 registry도 authority 호스트로 이 보관함의 인증서를 쓴다. 서버 로컬 인증서 파일 설정은 없다. 내부 서비스 mTLS나 임의 TCP/UDP TLS 종료를 위한 보관함은 아니다.

## 관리와 보호 입력

시스템 관리자 계정으로 [sfcli certificate](../cli/certificate.md) 명령을 사용한다. 계정 credential의 허용 동작 목록은 역할에 추가되는 제한이며, 자동 갱신 계정에는 `put-certificate`만 허용할 수 있다. 웹 자동 작업 계정이 HTTP-01 응답기 주소도 채우게 하려면 `set-acme-responder`를 함께 허용한다([웹 API](web-api/23-ui-57-59.md#http-01-응답기-주소-sfcd-설정-웹이-채움)). tenant 관리자는 보관함을 관리하거나 공개 정보를 조회할 수 없다.

인증서에는 이름이 없다. ID는 leaf DER의 SHA-256이며, 보관함의 항목은 ID로 정렬해 최대 256개다. 관리 동작은 `put-certificate {Certificate}`, `delete-certificate {ID}`, `disable-certificate {ID}` 셋이고 모두 `Expected`가 0이다. 같은 ID의 put, 연결된 인증서의 delete, 이미 끊은 인증서의 disable은 `ConditionFailed`다. CLI와 웹은 put 전에 ID를 조회해 이미 있으면 보내지 않는다. 연결과 상태(`연결됨`·`미연결`·`파기 대기`)는 저장하지 않고 지금의 목록·도메인·시각에서 계산한다. 규칙은 [CLI 문서](../cli/certificate.md#호스트와-연결)와 같다.

체인과 비공개 키는 각각 최대 8KiB의 PEM이다. 입력 시 체인이 leaf부터 서명으로 이어지는지, 실제 키/leaf 일치, 호스트 이름(DNS·IP SAN, 없으면 CN), 키 형식(ECDSA P-256·P-384, RSA 2048비트 이상), NotBefore/NotAfter를 검사한다. 비공개 키는 명령행 문자열이나 app.yaml/cluster.yaml에 넣지 않는다.

CLI는 작업 ID·보호 입력을 받을 서버를 공개 intent로 먼저 저장하고, 전송 직전에 dispatched를 내구화한다. 전송 뒤 오류나 응답 유실이 있으면 같은 `--id`로 다시 실행한다. 그때는 키를 다시 보내지 않고 원 서버에 보관된 같은 봉인 receipt만 조회한 뒤, 이미 서명한 관리 작업을 이어 보낸다. 원 서버가 공급하지 못하면 오류로 남는다. receipt의 `UploadedAt`부터 120초 안에 게시해야 하며, 원 서버는 600초 안에 게시되지 않은 준비 기록을 지운다.

## 도메인 목록

보관함은 클러스터에 등록한 도메인 목록(최대 128개)도 가진다. 이름은 소문자 A-label이며 와일드카드·한 단어·공개 접미사는 받지 않는다. IP 주소는 정규형으로 받아 그 주소 하나만 덮는다. 시스템 관리자가 [sfcli domain](../cli/domain.md)으로 `add-domain`/`remove-domain`을 보내며, 둘 다 보관함 전체 revision으로 CAS한다. 목록은 `certificates` 첫 페이지의 `Domains`로 읽는다. 같은 보관함에 ACME HTTP-01 응답기 주소(`ACMEResponder{Address, SetBy, SetAt}`, `set-acme-responder`, [sfcli domain acme-responder](../cli/domain.md#acme-http-01-응답기))도 두며 첫 페이지에 함께 온다. remove는 인증서 링크가 있어도 거절하지 않는다. 인증서는 이 목록 안의 호스트에만 연결된다(설계).

## 공개 정보

`certificates` 조회(`CertificateQuery{ID, After}`)의 공개 행은 `Metadata{ID, Hosts, Algorithm, Issuer, Serial, NotBefore, NotAfter, UploadedBy, UploadedAt}`, `State`, `Links[{Host, Family, ID}]`, `DisabledBy`, `DisabledAt`이다. `Serial`은 소문자 16진수다. 비공개 키 원문과 복호화 키는 어느 공개 응답에도 포함하지 않는다. 복호화 키나 비공개 키를 내보내는 조회는 없다.

페이지는 최대 32행이고 `Revision`과 `Next`를 가진다. CLI는 같은 보관함 revision에서 모든 페이지를 이어 읽는다. cursor는 그 revision에 고정되며 변경 후에는 `conflict`를 반환한다. `ID`를 주면 그 인증서 한 행과 공개 체인 PEM(`Chain`)을 돌려주고, 없는 ID는 빈 페이지다.

Raft의 공개 게시 receipt는 `Schema(2), Cluster, Metadata, Chain, SealedKey, KeyID, Sealer, Request, Signature`를 가진다. `SealedKey`는 인증서 비공개 키의 인증된 ciphertext이다. 원 sealer가 서명하고, 최종 사용자 operation은 그 receipt와 원 request ID를 다시 서명한다. 보호 입력 자체는 UserOperation이나 조회 request에 포함되지 않는다. 보관함 형식은 Schema 2이며 이전 형식은 읽지 않는다.

## 마스터 키와 봉인

클러스터 인증서 마스터 키(32바이트)는 cluster init 때 첫 voter가 만든다. 마스터 키는 현재 voter의 로컬 native 저장소에만 있고, 각 voter의 설치 identity seed로 봉인한다. Raft에는 넣지 않는다. 승격이 커밋된 voter는 다른 현재 voter에게 전용 SFCP `CertificateMaterial`로 받는다. 주는 쪽과 받는 쪽은 그 시점의 커밋된 멤버 목록에서 서로 voter인지 확인한다. 강등이 끝나 voter가 아닌 노드와 제거된 노드는 마스터 키를 지운다. 승격·강등이 진행 중이거나 멤버 목록을 읽지 못하면 지우지 않는다. 수동으로 공통 키 파일을 모든 서버에 복사하는 운영 전제는 없다.

인증서마다 키를 유도한다: `K = HKDF-SHA256(마스터 키, salt = 인증서 ID, info = "sfc/certificate/v1")`. 비공개 키 PEM은 `K`로 AES-256-GCM 암호화하고, AAD는 클러스터 ID와 인증서 ID다. 암호문(`SealedKey`, nonce가 앞에 붙음)은 Raft의 인증서 목록에 공개 체인과 함께 있으므로, 올린 노드가 사라져도 인증서를 쓸 수 있다. receipt의 `KeyID`는 `K`의 SHA-256이다.

보호 입력은 현재 WorkKey 멤버 어디서나 받는다. voter면 `K`를 직접 유도한다. voter가 아니면 voter에게 `Seal` 요청을 보낸다. 이 요청에는 leaf와, 인증서 비공개 키로 서명한 소유 증명(클러스터·요청 노드·ID·시각, ECDSA 또는 RSA-PSS)이 들어간다. voter는 leaf의 SHA-256이 ID인지, 증명이 맞는지, 요청 노드가 연결한 WorkKey 멤버인지, 시각이 60초 안인지 확인하고 `K`를 준다. 요청 노드는 이미 비공개 키를 가지고 있으므로 `K`로 새로 알게 되는 것은 없다. 입력 노드는 `K`를 저장하지 않고, 공개 receipt만 복구용으로 native에 둔다.

ingress 노드는 voter면 `K`를 직접 유도한다. 아니면 현재 voter에게 `Read`(`CertificateMaterialRead`)로 요청한다. voter는 그 노드가 지금 서빙하는 확정 ingress의 호스트에 그 인증서가 연결돼 있을 때만 `K`를 준다. 입력·출력 전 현재 멤버십과 연결을 검사하고, 응답 직전에 자기가 아직 voter인지 다시 본다. ingress 노드는 푼 키를 메모리에만 둔다. 사용자 Secret의 grant나 일반 관리 메시지로 이 경계를 우회하지 않는다. voter에게 닿지 못하면 새 적재는 오류가 되고, gateway는 이전의 유효한 인증서를 유지하며 성공이나 Ready를 합성하지 않는다.

마스터 키 교체(새 `info` 판)는 아직 없다.

## 참조·만료와 동적 적용

앱은 인증서 이름을 쓰지 않는다. `tls: true`인 수신 주소가 SNI 호스트로 고른다. 선택은 정확한 SAN을 우선하고 다음으로 한 label의 `*.` SAN을 선택하며, 호스트·키 계열마다 연결된 인증서 하나를 쓴다. ECDSA를 먼저, RSA는 클라이언트가 ECDSA를 지원하지 않을 때 고른다. 인증서를 올려도 앱을 재배포하지 않는다.

보관함 delete는 연결된 인증서를 거절한다. `disable`은 연결을 모두 떼고, 떨어진 호스트는 남은 인증서 가운데 가장 나은 것에 다시 연결된다. 앱 down이 보관함 인증서를 지우지 않는다. 적재 실패는 이전의 유효한 인증서를 유지하고 관측에 실패를 남긴다. 이전 인증서도 만료되면 새 TLS 접속을 거부한다.

만료 판정의 시각은 외부 관측 입력이다. 현재 control voter의 서명된 만료 보고를 기존 Raft FSM에 적용하여 만료된 인증서를 현재 상태에서 제거하고(연결은 다시 계산된다) 시스템 작업 기록을 남긴다. 각 노드도 만료/확정 삭제 fence를 확인해 자기 DB의 인증서 키와 준비 receipt payload를 제거한다. 상태 부재나 timeout만으로 미게시 자료를 삭제하지 않으며, 미게시 준비 기록은 게시 기한(600초)이 지나거나 만료될 때 지운다. 과거 Raft 로그를 임의 수정하지 않는다. 이미 열린 TLS 연결을 강제로 끊는 동작은 추가하지 않는다.

관측과 SNI/공유 게이트웨이 동작은 [SFCP](../protocol/sfcp.md)와 [Unix 소켓 API](unix-sockets.md)의 동일 인증 경계를 따른다.

사용자 `ingresses`의 `Runtime.Certificates`에서도 호스트별 실제 적재 인증서 ID·만료·적재 시각·오류를 읽는다. 공유 listener/host 관측의 권한·cursor는 [ingress 조회 계약](ingress-management.md)을 따른다.

설치 노드 키를 교체해도 기존 인증서의 sealer·digest·봉인 ciphertext·signed receipt와 미정산 입력 request, 그리고 마스터 키 envelope는 원 owner DB에 보존한다. 현재 노드는 설치 이력의 정확한 원 namespace에서 원 sealing identity로만 그 envelope를 연다. 현재 키를 옛 암호문의 sealing key로 사용하거나 원 receipt를 새 ID로 재작성하지 않는다. 원 request의 복구는 현재 사용자 권한과 현재 노드 신원으로 실행하며, 원 request가 없거나 여러 namespace에서 충돌하면 새 입력을 생성하지 않고 실패한다.

Material 전송과 ingress 소비는 현재 TLS 멤버 키만 인증한다. 기존 ingress의 Source/Consumer가 원 owner를 가리키는 경우 기존 resource-owner 연결과 정확한 source generation/revision을 함께 검사한다. 원 sealer의 경로도 현재 peer로 해석한다. 읽기 전후 현재 권한·원 receipt digest·연결을 재검사하며, 과거 sealer 개인키는 원 native envelope를 여는 데만 쓰고 현재 TLS/issuer/관리 명령의 fallback이 되지 않는다.
