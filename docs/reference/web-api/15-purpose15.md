## 컨테이너 스트림 (purpose15)

### 로그 따라가기 · top/stats 감시 (SSE)

`GET /t/{t}/apps/{app}/stream?kind=logs|top|stats&service=&instance=&tail=&stdout=&stderr=&interval=`

- `EventSource`로 연다(쿠키 인증, GET이라 `X-SFC-Web` 불필요). `tail` 0..10000(0이나 없음은 지난 줄 없이 지금부터 새 줄만. sfcd에는 1줄·since=지금으로 보낸다), `interval` 1s..1m(top/stats, 기본 5s).
- 이벤트: `target`(실제 대상 컨테이너), `stdout`·`stderr`(`{type, sequence, data(base64), text(UTF-8이면)}`), `sample`(`{type, sample}`), `output-eof`, 끝에 `end` 또는 `error`(`{code}`: `target-changed`면 다시 열기, `closed`·`disconnected`는 연결 끊김). 서버 ping은 SSE 주석(`: ping`).
- 브라우저가 닫으면 스트림을 취소한다. 조회 스트림이라 남는 효과는 없다. 30초 주기 감시 규칙의 대상이 아니다(서버가 밀어 줌).

### 터미널 (WebSocket)

`GET /t/{t}/apps/{app}/exec?opId=<uuid>&service=&instance=&cmd=<argv0>&cmd=<argv1>…&tty=1&stdin=1&rows=&cols=`

- `Origin`이 같은 호스트여야 한다(없거나 다르면 403 `csrf`). TTY면 rows/cols 필수.
- 서명한 exec intent를 작업 기록 `opId`(`action:"exec"`, `requestId:"exec-<opId>"`, 처음 state `running`)로 **저장한 뒤** 연다.
- 브라우저 → 서버(텍스트 JSON): `{type:"stdin",data:<base64>}`, `{type:"close-stdin"}`, `{type:"resize",rows,cols}`, `{type:"cancel"}`(입출력만 끝냄, 프로세스를 죽이지 않음).
- 서버 → 브라우저: 위 스트림 레코드 JSON(`receipt`·`stdout`·`stderr`·`output-eof`), 끝에 `{type:"end"}` 또는 `{type:"error",code}`. 끝난 receipt가 오면 op는 `applied`(종료 코드 ≠ 0이면 `errorCode:"exit-N"`).
- **끊긴 뒤**: 프로세스는 계속 돈다. `POST /ops/{opId}/result`가 exec `status`를 읽어 `{op, exec}`를 돌려준다. 같은 opId로 다시 연결하면 같은 원 intent를 다시 열어 receipt만 받고 끝난다(재실행 없음, intent는 서명 뒤 30초 안에만 열린다). `resume`은 409 `exec`.

