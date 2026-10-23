# Control-plane API contract — design v0

Same-origin HTTPS JSON API `/api/v1`; обязательная admin session кроме bootstrap/login и минимального liveness без секретов. Методы ниже — проект интерфейса, endpoints еще не существуют. Все mutation: CSRF/origin checks, requestId, optimistic revision; никаких секретов в query string. Ответ ошибки `{code,message,fieldErrors?,requestId}`; значения secret полей не возвращать.

| Operation | Method/path | Результат |
|---|---|---|
| Login/logout | POST /session, DELETE /session | Secure cookie; generic invalid credentials, rate limit |
| Bootstrap | POST /bootstrap | только authorized local bootstrap channel, одноразовый token; атомарное закрытие после admin creation |
| Read/edit nodes | GET/POST /nodes; GET/PATCH/DELETE /nodes/{id} | GET secret fields = presence only; PATCH expectedRevision; DELETE dependency conflict 409 |
| Validate | POST /revisions/{id}/validate | report + capability version; не apply |
| Apply | POST /revisions/{id}/apply | 202 operationId; conflict 409; invalid 422 |
| Operation/status | GET /operations/{id}; GET /state | actual phase, draft/active IDs, readiness, redacted failure |
| Stop | POST /runtime/stop | stopped-guarded, не release protection |
| Release protection | POST /runtime/release-protection | отдельный expiring confirmation token bound to current state, повторная проверка авторизации |
| Subscriptions/rule sources | GET/POST/PATCH /subscriptions, /rule-sources (item path for PATCH) | settings with redacted URL; no implicit fetch |
| Update source | POST /subscriptions/{id}/refresh; POST /rule-sources/{id}/refresh | 202 job; busy 409; never apply |
| Rules | GET/POST /rules; PATCH/DELETE /rules/{id} | draft mutation, conflict warnings, references validated |
| Backup | POST /backups | encrypted download, passphrase request body not logged; bounded memory |
| Restore | POST /restores | authenticated bounded upload -> draft revision; no apply |
| Diagnostics | POST /diagnostics/export | allowlisted nonsecret artifact |

Typed secret update: unchanged / replace(value) / clear; masked placeholder не является новым значением. Inactive value сохраняется, compiler не использует. Revision-changing операции фиксируют actor/audit без секретов. Unauthorized 401, forbidden 403, stale revision/busy/dependency 409, limits 413, semantic/syntax validation 422. Invalid JSON request 400. Чтение ошибки не должно возвращать raw source body.

## UI contract
Отдельные состояния Unsaved / Saved draft / Invalid / Active / Applying / Rolling back / Degraded guarded. «Сохранить» никогда не вызывает Apply. Показывать active references при delete conflict. Подписочный editor предупреждает о замене правок. HTTP/TLS exception/downgrade имеют видимые разные предупреждения. Никаких обещаний success до terminal operation state. Доступность: keyboard flow, labels, non-color errors, reduced motion. Точные endpoints/schema закрепляются machine-readable schema перед параллельной работой UI/backend; изменения schema требуют 03 review.


## Source URL security — D-061
При вводе userinfo в URL извлечь credentials в SecretRef до persistence/ответа/audit; raw request body не логировать. Per-source LAN allowlist изменяется только администратором явно, не импортированным источником. Forbidden address classes имеют приоритет над allowlist. Проверять разрешение на каждом фактическом соединении/redirect; непроверяемый remote proxy resolve дает безопасный отказ, не direct retry. UI объясняет причину без секретного URL.
