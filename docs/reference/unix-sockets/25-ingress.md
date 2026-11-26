## Ingress와 인증서 메시지

Unix TLS의 User purpose8은 `ingresses`, `certificates`를 받는다. 네트워크 MYDCP와 같은 현재 계정/credential·tenant/node 권한과 원 operation을 사용한다.

| 요청 Method | 전용 Request 필드 | Reply 필드 |
|---|---|---|
| `ingresses` | `Tenant, Ingress:{Node,Tenant,App,Key,Part,After,Offset}` | `Ingress:{Schema:1,Index,Epoch,RootRevision,Mappings,Nodes,Blocks,HostPolicies,Next}` |
| `certificates` | `Certificate:{ID?,After?}` | `CertificatePage:{Revision,Certificates,Chain?,Domains?,Next}` |

다른 업무 selector와 혼합하지 않으며 `After`는 전용 객체 안에 둔다. mapping/지표 상세는 [Ingress 운영](../ingress-management.md), 공개 인증서 metadata와 cursor는 [인증서 보관함](../certificate-store.md)을 따른다. 응답에 원 사용자 grant·비공개 키를 넣지 않는다. `whoami`는 기존 root revision들과 함께 `IngressRootRevision`, `CertificatesRootRevision`을 반환해 새 typed operation의 root CAS를 고정한다.

User `ingresses`의 Part에는 `gateways`, `history`도 있다. gateways는 Node를 필수로 지정한 시스템 조회이며 `NodeGateways:[{Node,Source,Revision,AppliedRevision,Configuration,Error?}]`를 반환한다. history는 tenant/app/node·현재 권한을 검사한 `History:[{At,Actor,Action,Request,Tenant,App,Node,Route,Gateway,Detail,Previous}]`와 `Next`를 반환한다. 원 Session·서명 원문은 이 공개 행에 포함하지 않는다.

같은 User `submit/result/resume`의 Change.Action은 `set-node-gateways`(Node,External?,Local?,SDK가 붙이는 Evidence), `set-ingress-balance`(Tenant,App,Route,Balance), `drain-ingress/undrain-ingress`(Tenant,App,Node?,DrainSeconds?)를 지원한다. gateway는 현재 system-admin·owner preflight, 나머지는 현재 tenant Network 관리 권한·record CAS와 원 operation을 유지한다. payload와 세부 필드는 [Ingress 운영](../ingress-management.md#gateway분배drain-변경과-공개-이력)을 따른다. frame/record/EOF 규격은 기존 User purpose8과 같다.

`Ingress.BlockRevision`은 현재 차단 정책 book의 목표 revision이고 `Ingress.Mappings[].Runtime.BlockRevision`은 owner가 실제 설치한 같은 단위의 revision이다. 저장 root CAS인 `Ingress.RootRevision`이나 블록별 `Revision`과 비교하지 않는다. 확정 해제 뒤 Runtime이 유효하면 목표 이상은 적용됨, 미만은 대기이며 Runtime 부재/관측 오류는 관측 불가다. 목표에서 제거된 ID가 필터되어 보이지 않아도 이 값이 원 해제 revision에 도달하기 전에는 해제 적용 완료가 아니다. 노드별 실제 관측과 Raft 목표를 구분한다.

`Ingress.Mappings[].Runtime.Certificates`의 호스트별 인증서 ID(`Fingerprint`)·만료·적재 오류도 같은 상세 offset으로4개씩 읽는다. `Ingress.Nodes[].Gateways`의 공개 `Listeners`에는 현재 사용자에게 보이는 공유 listener/host binding만 최대4개씩 넣고 `BindingsTotal,Offset,Next`를 제공한다. 이 Next도 원 조회의 `Ingress.Offset`으로 이어 읽으며 전역 source 거부/unmatched 계수는 시스템 관리자에게만 제공한다.

인증서 입력은 기존 SecretInput purpose10/kind1 Envelope와 같은 Session/연결 proof/digest/쓰기 EOF를 사용한다. Body의 고정 형식은 다음과 같다.

```json
{"Schema":1,"Realm":"","ID":"upload-1","Mode":"certificate","Nonce":[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1],"Certificate":{"Request":"upload-1","Recover":false,"Chain":"<PEM chain bytes base64>","Key":"<PEM private key bytes base64>"}}
```

`Nonce`와 digest32는 Go `[32]byte`의 기존 숫자 배열 JSON 형식이다. 실제 Nonce는 매 요청마다 난수로 생성한다. Chain/Key의 `[]byte`만 JSON base64다. ID=Request, Realm empty이며 Values/Target/Password/Origin/Selection은 없다. Chain/Key 각각8KiB, 기존64KiB frame 상한을 유지한다. kind2 Reply.Certificate는 원 sealer가 서명한 공개 chain/봉인 ciphertext receipt만 반환한다. 오류 Code는 `conflict`, `denied`, `unknown`을 구분하고 원문 오류/비밀을 반환하지 않는다. Recover=true에는 PEM/key가 없으며 같은 원 sealer의 동일 receipt만 조회한다.

최종 `put-certificate`는 이 receipt를 기존 UserOperation으로 서명해 Raft에서 확정한다. `delete-certificate`, `disable-certificate`(payload `{ID}`), `ingress-block`, `ingress-unblock`, `ingress-block-extend`, `set-ingress-host-policy`도 User의 기존 apply/result/resume를 사용한다. SecretInput 성공만으로 관리 게시 완료를 뜻하지 않는다.

node 간 비공개 version key 전송 `CertificateMaterial=17`은 이 Unix listener에 노출하지 않는다. 전용 member kind1/2·64KiB·현재 ingress 소비 참조/권한·EOF 계약은 [MYDCP](../../protocol/mydcp/28-ingress-raft-certificatematerial.md)에서 규정한다.


