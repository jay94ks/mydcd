## 메시지 교환 순서

일반 요청은 `C:User/1 → C:EOF → S:User/2 → S:EOF`다. 개인키 로그인은 같은 TLS 연결에서 `challenge/Ticket` 교환을 끝낸 뒤 `login(Ticket,Proof)/Session` 교환을 수행한다. password/token도 `credential-challenge` 뒤 `credential-login` 순서다.

큰 계획/source/module stage는 아래와 같이 **요청 EOF 전에 응답을 먼저 읽는다**. 모든 frame은 같은 request ID이고 digest TLV는 최초 Envelope에 고정한다.

```text
client                                 server
User/1 (AppInput 또는 CheckerSource/Module descriptor) →
                                     ← User/2 Code=continue
User/4 offset=0, data, headerDigest    →
User/4 offset=이전 끝, data, 동일digest → ...
EOF record                            →
                                     ← User/2 최종 Reply (또는 AppPlan Part=0,1,...)
                                     ← EOF record
```

kind4의 조각은 최대24KiB, offset은 u64 LE이며 누락·중복·역순·과대 입력·hash 불일치·여분 frame을 거부한다. 일반 앱 문서는 최대4MiB, checker source는256KiB, module ZIP은64MiB이며 source-envelope는 별도 [입력 예산](../../../internal/userauth/app_source_input.go)을 따른다. 응답 계획은 **kind4가 아니라 kind2 Reply.AppPlan.Data**에 최대24KiB씩 담는다. 마지막 part 뒤 길이/digest/응답 EOF를 모두 검사한다. recover는 저장된 원 사실 조회이므로 stage의 원문 전송 순서를 반복하지 않는다.

