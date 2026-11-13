# API 참조

[설치·토큰 발급](USAGE.md#api-인증과-실행) · [지원 범위](PARITY.md)

## 권한

| scope | 허용 기능 |
| --- | --- |
| `status:read` | 상태 조회 |
| `rooms:read` | 채팅방 목록·참여자 ID·명단 상태 |
| `messages:read` | 메시지·검색·누락 상태·첨부 메타데이터·SSE |
| `messages:write` | 일반 텍스트 발송·발송 상태 조회 |
| `friends:read` | 친구·차단 목록과 메시지 응답의 발신자 이름 |
| `attachments:read` | 이미지·파일 내용 다운로드. `messages:read`도 필요 |

방을 제한하려면 `--all-rooms` 대신 `--room ROOM_ID`를 사용합니다. `friends:read`는 계정 전체 친구 목록에 접근하므로 방 제한 토큰과 함께 발급할 수 없습니다. `messages:read`만 가진 토큰에는 발신자 ID를 제공하지만 친구 이름은 `null`로 반환합니다.

## 경로와 조회

모든 경로는 `Authorization: Bearer <API_TOKEN>` 헤더를 요구합니다. 아래 `API_TOKEN`은 카카오 로그인 토큰이 아닌, 별도로 발급한 API 토큰입니다. 예제 ID와 메시지는 모두 합성 데이터입니다.

| 경로 | 용도 |
| --- | --- |
| `GET /v1/status` | 기능·데이터 출처·구현 상태 |
| `GET /v1/rooms` | 접근 가능한 방 목록 |
| `GET /v1/messages` | 전체 접근 가능 방의 메시지 필터 조회 |
| `GET /v1/rooms/{room_id}/messages` | 특정 방의 메시지 필터 조회 |
| `GET /v1/rooms/{room_id}/messages/{message_id}` | 메시지 한 건 조회 |
| `POST /v1/rooms/{room_id}/messages` | 일반 텍스트 발송 |
| `GET /v1/rooms/{room_id}/outgoing/{request_id}` | 발송 결과 확인 |
| `GET /v1/rooms/{room_id}/messages/{message_id}/attachments` | 첨부파일 목록 |
| `GET /v1/rooms/{room_id}/messages/{message_id}/attachments/{index}/content` | 첨부파일 다운로드 |
| `GET /v1/search?q=...` | 본문 검색. `q` 필수 |
| `GET /v1/friends` | 친구·과거 발신자 이름과 관계 정보 |
| `GET /v1/blocked-users` | 차단한 사용자·채널 목록 |
| `GET /v1/rooms/{room_id}/members` | 참여자 정보와 명단 확인 상태 |
| `GET /v1/rooms/{room_id}/gaps` | 수집 구간과 누락 상태 |
| `GET /v1/attachments` | 이미지·파일 메타데이터 |
| `GET /v1/events` | 메시지 변경 메타데이터 SSE |

메시지 목록과 검색은 아래 매개변수를 조합할 수 있습니다.

| 매개변수 | 설명 |
| --- | --- |
| `room_id` | 방 ID. 생략하면 토큰에 허용된 모든 방 |
| `sender_id` | 발신자 사용자 ID. 친구 목록의 `user_id`와 연결 |
| `from_ms`, `to_ms` | Unix epoch 밀리초. 양 끝 포함 |
| `q` | 본문 부분 문자열. 목록에서 선택, `/v1/search`에서는 필수 |
| `limit` | 페이지 크기. 기본 50, 1~200 |
| `cursor` | 직전 응답의 `next_cursor` |

```sh
# 특정 방에서 특정 사람이 보낸 메시지를 시간 범위로 조회
curl -fsS -G 'http://127.0.0.1:8787/v1/messages' \
  -H "Authorization: Bearer $API_TOKEN" \
  --data-urlencode 'room_id=demo-room' \
  --data-urlencode 'sender_id=demo-friend' \
  --data-urlencode 'from_ms=1700000000000' \
  --data-urlencode 'to_ms=1700086400000' \
  --data-urlencode 'limit=100'

# 접근 가능한 모든 방에서 검색
curl -fsS -G 'http://127.0.0.1:8787/v1/search' \
  -H "Authorization: Bearer $API_TOKEN" \
  --data-urlencode 'q=회의'

# 친구 목록과 메시지 한 건
curl -fsS 'http://127.0.0.1:8787/v1/friends?limit=100' \
  -H "Authorization: Bearer $API_TOKEN"
curl -fsS 'http://127.0.0.1:8787/v1/rooms/demo-room/messages/demo-message' \
  -H "Authorization: Bearer $API_TOKEN"
```

메시지 목록 응답 형태:

```json
{
  "items": [
    {
      "room_id": "demo-room",
      "message_id": "demo-message",
      "revision": 1,
      "sent_at_ms": 1700000000000,
      "sender_id": "demo-friend",
      "sender_name": "예제 친구",
      "sender_name_source": "kakao_profile",
      "sender_name_observed_at_ms": 1700000001000,
      "body": "회의 시간을 확인해 주세요.",
      "source": "offline_import",
      "source_local_pk": null
    }
  ],
  "next_cursor": null
}
```

친구 이름으로 찾으려면 `/v1/friends`를 페이지 끝까지 읽어 해당 `user_id`를 찾은 뒤 `sender_id` 조건으로 메시지를 조회하세요. `q`는 발신자 이름이 아니라 메시지 본문을 검색합니다.

ID는 문자열입니다. JavaScript의 정수 정밀도 범위를 넘을 수 있으므로 숫자로 변환하지 마세요. 시간은 밀리초 숫자입니다. 시간·방 ID·메시지 ID 기준 오름차순으로 읽으며 `next_cursor=null`이면 현재 결과 끝입니다. 다음 페이지에도 동일한 필터를 전달해야 합니다. 계정·경로·필터가 다른 커서는 거부합니다. 페이지 사이의 데이터 변경을 고정하는 snapshot pagination은 아닙니다.

본문 검색은 대소문자를 구분하는 Unicode 부분 문자열 검색입니다. FTS5 trigram으로 후보를 찾고 원문 조건을 다시 검사합니다. 짧은 검색어는 최대 2초 예산의 스캔을 사용합니다. 형태소·유사도·정규표현식 검색은 제공하지 않습니다. 삭제된 메시지는 일반 조회 결과에서 제외합니다.

SSE 소비 예:

```sh
curl -N 'http://127.0.0.1:8787/v1/events' \
  -H "Authorization: Bearer $API_TOKEN" \
  -H 'Last-Event-ID: 0'
```

`message_changed` 이벤트에는 `room_id`, `message_id`, 변경 종류·revision·출처가 포함되며 본문은 없습니다. `id`를 저장하고 재연결 시 `Last-Event-ID`로 전달합니다. 변경 알림 후 단건 조회로 현재 내용을 가져옵니다. 삭제 이벤트 뒤 단건 조회는 404가 될 수 있습니다. SSE는 수집기가 DB에 반영한 변경 알림입니다.

계정·방 제한은 페이지 크기 적용 전에 검사합니다. 토큰당 분당 120회, 동시 일반 요청 32개, 동시 SSE 연결 8개로 제한합니다. 400은 잘못된 조건, 401은 인증 실패, 403은 권한 부족, 404는 없는/삭제된 리소스, 409는 상태·중복 키 충돌, 429는 요청 제한, 503은 연결·설정 준비 대기 또는 조회 시간 초과입니다. 제한이나 DB 처리 오류는 JSON 오류로 반환되며 재시도 시에는 간격을 두세요.

## 누락 수집 상태

`GET /v1/rooms/{room_id}/gaps`는 `messages:read` 권한으로 방의 누락 재조회 상태를 반환합니다. `recovery_cursor`는 수집 위치, `target`은 관측한 목표 위치, `pending`은 해당 구간의 재조회 대기 여부입니다. `missing_predecessors`에는 로컬에서 앞선 메시지를 찾지 못한 연결이 표시되며, 결과가 잘렸는지는 `missing_predecessors_truncated`로 확인합니다.

범위는 수집 시작 경계 이후(`scope=since_collection_boundary`)입니다. `history_complete=false`이며, `pending=false`나 빈 누락 목록이 과거 전체 기록의 완전성을 보증하지 않습니다.

## 참여자 명단

일반 1:1·그룹 채팅의 참여자 명단을 갱신합니다. 오픈채팅은 수신·조회로 확인한 방별 프로필을 제공하며 전체 명단을 자동 열거하지 않습니다. 비밀채팅 전체 명단은 미지원입니다. 빈 응답으로 기존 명단을 지우지 않습니다.

`GET /v1/rooms/{room_id}/members`는 과거에 확인한 신원도 반환합니다. `membership`은 확인된 현재 참여자 `active`, 현재 명단에서 제외된 과거 신원 `inactive`, 현재 참여 여부가 불확실한 `observed`로 구분합니다. 이름 조회에는 `friends:read`가 필요하며 이름을 확보하지 못한 참여자는 ID와 `null` 이름을 반환합니다.

`coverage.complete`는 마지막으로 확인한 전체 명단의 유효 여부입니다. 입·퇴장 알림과 재접속 시 무효화하고 다시 조회합니다. `active_count`는 저장된 활성 명단의 건수, `observed_count`는 이름 정보를 확보한 신원 건수, `reported_active_count`는 방 정보의 서버 건수, `as_of_ms`는 명단 상태 확인 시점입니다. `complete=false`이면 `active_count`를 현재 전체 인원수로 사용하지 마세요. 페이지 조회는 고정 snapshot이 아닙니다.

`observed_read_message_id`는 수신한 읽음 알림에서 관측된 위치이며 메시지 수집 커서와 별개입니다. 오픈채팅 이름은 방 링크에 속한 프로필만 사용합니다. 연락처나 일반 친구 이름으로 대체하지 않으며, 해당 프로필이 없으면 `null`입니다.

친구 목록의 `favorite`은 확인한 즐겨찾기 상태이며 미확인 상태는 `null`입니다. 즐겨찾기 변경 알림을 받으면 해당 친구만 다시 조회하고, 실패하면 5분 뒤 재시도합니다.

## 차단 목록과 친구 상태

`GET /v1/blocked-users`는 `friends:read` 권한의 계정 전체 토큰으로 조회합니다. `limit`·`cursor` 페이지 조회를 지원하며 사용자 ID, 채널 여부(`is_channel`), 프로필 차단 여부(`profile_block`), 확인된 이름을 반환합니다. 사람·채널 각각의 `coverage.complete`는 전체 차단 목록을 수신했는지 나타냅니다. 미확인 상태의 목록은 완전한 목록이 아닙니다.

`/v1/friends`의 `is_blocked`는 확인된 차단 상태, `profile_block`는 차단 항목의 프로필 차단 상태입니다. `is_blocked=null`은 해당 범주의 전체 목록이 아직 없어 차단 여부가 불확실하다는 뜻입니다. 친구 관계 필드 `relation`·`is_friend`는 마지막 친구 목록 응답 기준으로 유지됩니다. 차단 해제를 친구 복원으로 추정하지 않습니다.

차단 사용자 이름은 확인된 신원 정보를 사용하며 메시지·과거 이름은 삭제하지 않습니다. 차단 목록 조회만으로 추천·친구 관계가 모두 최신 상태임을 보증하지 않습니다.

## 첨부파일

`/v1/attachments`는 메시지와 같은 방·발신자·기간·cursor 필터를 지원하지만 본문 검색 `q`는 지원하지 않습니다. 목록과 메시지별 `/attachments`는 메타데이터만 읽으며 `messages:read` 권한을 사용합니다. 목록의 `index`를 `/attachments/{index}/content`에 지정하면 내용을 내려받습니다. 내용 조회에는 `attachments:read`도 필요합니다.

이미지·파일·썸네일을 미리 내려받거나 디스크에 캐시하지 않습니다. 일부 파일은 수집기가 실행 중이어야 다운로드할 수 있습니다. 지원하지 않는 자료는 `available=false`와 사유로 표시됩니다. `available=true`도 서버의 파일 보존을 보증하지 않습니다.

한 API 프로세스에서 동시 다운로드는 2개, 파일 크기는 512MiB, 전송 시간은 최대 10분으로 제한합니다. 중간 오류·삭제·토큰 회수 때 스트림이 종료될 수 있으므로 호출자는 응답 본문을 끝까지 정상 수신했는지 확인해야 합니다.

## 텍스트 발송

일반 1:1·그룹 채팅의 텍스트를 전송합니다. 수집기가 연결되어 있어야 하며, 기존 조회 토큰에는 발송 권한이 추가되지 않습니다. 발송용 토큰을 별도로 발급합니다.

```sh
./target/release/kakao-rust --data-dir "$KAKAO_DATA_DIR" token issue \
  --label sender --session-account --room ROOM_ID \
  --scope messages:write --expires-in 3600
```

논리적으로 같은 발송에는 항상 같은 `Idempotency-Key`를 사용합니다. 통신 오류로 응답을 받지 못해도 새 키를 만들지 마세요.

```sh
curl -fsS -X POST 'http://127.0.0.1:8787/v1/rooms/ROOM_ID/messages' \
  -H "Authorization: Bearer $SEND_TOKEN" \
  -H 'Content-Type: application/json' \
  -H 'Idempotency-Key: example-send-001' \
  --data '{"text":"안녕하세요"}'
```

HTTP 202는 접수됐다는 뜻입니다. 응답의 `request_id`로 결과를 조회합니다. 같은 토큰·키·방·본문으로 POST를 반복하면 기존 요청을 반환하며, 같은 키에 다른 본문이나 토큰을 사용하면 409를 반환합니다.

```sh
curl -fsS 'http://127.0.0.1:8787/v1/rooms/ROOM_ID/outgoing/REQUEST_ID' \
  -H "Authorization: Bearer $SEND_TOKEN"
```

| 상태 | 의미 |
| --- | --- |
| `queued` | 전송 대기 또는 허용된 재연결 재시도 대기 |
| `dispatching` | 서버에 요청 중 |
| `sent` | 성공 응답 또는 본인 메시지 수신으로 서버 메시지 ID 확인 |
| `rejected` | 서버가 거절. `server_status`에 응답 코드 제공 |
| `cancelled` | 실제 전송 전에 만료·권한 변경·수집기 재시작 등으로 취소 |
| `unknown` | 전송 시도 후 결과 미확정. 자동으로 새 요청을 만들면 중복될 수 있음 |

`sent`이면 `message_id`로 기존 단건 조회 API를 사용할 수 있습니다. 메시지 내용 조회에는 `messages:read`가 별도로 필요합니다. 상태 응답에는 메시지 본문과 인증정보를 포함하지 않습니다.

지원 본문은 공백만으로 이루어지지 않은 UTF-16 3999단위 이하 텍스트입니다. 줄바꿈과 탭은 허용하며 다른 제어 문자는 거부합니다. 이미지·파일·답장·스레드·오픈채팅·비밀채팅 발송은 지원하지 않습니다. 서버 키워드 효과가 필요한 문구도 거부합니다. 서버 설정 갱신 대기나 연결 부재는 503으로 반환합니다.

처음 접수한 요청은 60초 동안 유효하며, 전송 직전에 토큰 만료·회수·방 제한을 다시 검사합니다. 전송 이력이 있는 요청은 상태 조회로 확인하세요. 서버 거절이나 시간 초과는 무조건 재전송하지 않습니다. 프로세스 재시작 시 미전송 요청은 취소하고, 전송 이력이 있으면 결과 미확정으로 보존합니다. 동일 키의 API 요청 중복 방지와 네트워크의 정확히 한 번 전달 보장은 서로 다릅니다.

발송은 수집기가 실행 중일 때 처리하며 방 열기·읽음 표시를 수행하지 않습니다. 발송 결과는 기존 메시지 조회 API로도 확인할 수 있습니다.
