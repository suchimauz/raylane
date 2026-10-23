# Control-plane API contract — design v0

Same-origin HTTPS JSON API `/api/v1`; обязательная admin session кроме bootstrap/login и минимального liveness без секретов. Методы ниже — проект интерфейса, endpoints еще не существуют. Все mutation: CSRF/origin checks, requestId; никаких секретов в query string. Ответ ошибки `{code,message,fieldErrors?,requestId}`; значения secret полей не возвращать.

Optimistic-revision guard применяется к mutation состояния существующей сущности, не ко всем mutation подряд. Точный operation-class table (D3):

| Operation class | Guard | Операции |
|---|---|---|
| Entity mutation (существующая сущность) | Required client `expectedRevision`; mismatch -> 409 | PATCH/DELETE на /nodes/{id}, /rules/{id}, /subscriptions/{id}, /rule-sources/{id} |
| Refresh | Required client `expectedRevision` на revision настроек источника; mismatch -> 409. Дополнительно server-side `capturedRevision` commit-check на captured revision (mismatch -> candidate rejected) | POST /subscriptions/{id}/refresh, /rule-sources/{id}/refresh |
| Create | No prior revision to guard; absence цели + uniqueness ключа транзакционно; duplicate -> 409, никогда overwrite | POST /nodes, /rules, /subscriptions, /rule-sources |
| Immutable-revision | No optimistic guard (revision immutable после создания) | POST /revisions/{id}/validate |
| Generation-bound runtime | `expectedGeneration` body; mismatch -> 409 | POST /runtime/stop, POST /runtime/release-protection |
| Auth/session | Session token + CSRF/origin, не revision | POST/DELETE /session, POST /bootstrap |

`expectedRevision` на refresh привязан к `revision` (settings revision) источника. Для RuleSetSource это новый `revision` (settings), НЕ `draftVersion`/`activeVersion` (content versions).

| Operation | Method/path | Результат |
|---|---|---|
| Login/logout | POST /session, DELETE /session | Secure cookie; generic invalid credentials, rate limit |
| Bootstrap | POST /bootstrap | только authorized local bootstrap channel, одноразовый token; атомарное закрытие после admin creation |
| Read/edit nodes | GET/POST /nodes; GET/PATCH/DELETE /nodes/{id} | GET secret fields = presence only; PATCH expectedRevision; DELETE dependency conflict 409 |
| Validate | POST /revisions/{id}/validate | report + capability version; не apply |
| Apply | POST /revisions/{id}/apply | 202 operationId; conflict 409; invalid 422 |
| Operation/status | GET /operations/{id}; GET /state | actual phase, draft/active IDs, readiness, redacted failure |
| Stop | POST /runtime/stop | stopped-guarded, не release protection |
| Release protection | POST /runtime/release-protection | отдельный expiring confirmation token bound to current state, повторная проверка авторизации. Token issuance/registration — helper operation (D6); helper сам проверяет binding к generation/protection state, freshness и single use |
| Subscriptions/rule sources | GET/POST/PATCH /subscriptions, /rule-sources (item path for PATCH) | settings with redacted URL; no implicit fetch |
| Update source | POST /subscriptions/{id}/refresh; POST /rule-sources/{id}/refresh | 202 job; busy 409; never apply; client `expectedRevision` (settings revision) required, server `capturedRevision` commit-check |
| Rules | GET/POST /rules; PATCH/DELETE /rules/{id} | draft mutation, conflict warnings, references validated |
| Backup | POST /backups | encrypted download, passphrase request body not logged; bounded memory |
| Restore | POST /restores | authenticated bounded upload -> draft revision; no apply |
| Diagnostics | POST /diagnostics/export | allowlisted nonsecret artifact |

Typed secret update: unchanged / replace(value) / clear; masked placeholder не является новым значением. Зарезервированное значение `__RAYLANE_SECRET_UNCHANGED_V1__` означает «оставить поле без изменений» и не принимается как новый секрет: точный match отвергается (422, fieldError) и никогда не сохраняется и не возвращается; отвергается ТОЛЬКО точный match — любые другие строки, включая похожие на маску, остаются легитимными значениями. Inactive value сохраняется, compiler не использует. Revision-changing операции фиксируют actor/audit без секретов. Unauthorized 401, forbidden 403, stale revision/busy/dependency 409, limits 413, semantic/syntax validation 422. Invalid JSON request 400. Чтение ошибки не должно возвращать raw source body.

## UI contract
Отдельные состояния Unsaved / Saved draft / Invalid / Active / Applying / Rolling back / Degraded guarded. «Сохранить» никогда не вызывает Apply. Показывать active references при delete conflict. Подписочный editor предупреждает о замене правок. HTTP/TLS exception/downgrade имеют видимые разные предупреждения. Никаких обещаний success до terminal operation state. Доступность: keyboard flow, labels, non-color errors, reduced motion. Точные endpoints/schema закрепляются machine-readable schema перед параллельной работой UI/backend; изменения schema требуют 03 review.

Unsaved-edit preservation (D5): открытая страница сохраняет unsaved editor state в page RAM через expiry, re-login и control-plane restart, включая введённые secret-поля; reauthenticate перед save, re-fetch revision, разрешать конфликты, не перезаписывать. Не очищать editor молча на 401/expiry/restart; не replay mutation автоматически. Никакого localStorage/sessionStorage/IndexedDB/cache/cookie/log/analytics/service-worker для edit или secret data. Clear retained secret input только после подтверждённого save, explicit discard или destruction страницы. Честно документированные ограничения (потеря неизбежна, UI предупреждает и предлагает save-to-draft): browser restart, tab crash, explicit navigation. Expiry НЕ ослабляется ради preservation.


## Source URL security — D-061
При вводе userinfo в URL извлечь credentials в SecretRef до persistence/ответа/audit; raw request body не логировать. Per-source LAN allowlist (поле `lanAllowlistCIDRs` на Subscription и RuleSetSource) изменяется только администратором явно, не импортированным источником.

Forbidden address classes имеют приоритет над allowlist для КАЖДОГО resolution, фактического соединения и redirect, для IPv4 и IPv6 (включая IPv4-mapped IPv6 эквиваленты). Forbidden classes: loopback (127.0.0.0/8, ::1), link-local (169.254.0.0/16, fe80::/10), multicast (224.0.0.0/4, ff00::/8), unspecified (0.0.0.0, ::), metadata/link-local metadata (169.254.169.254, fd00:ec2::254), IPv4-mapped IPv6 (::ffff:0:0/96). Порядок оценки: forbidden class -> allowlist membership -> остальная политика. Forbidden-class отказ называет класс, не «не в allowlist»; причины различны. Redirects переоцениваются; каждый hop проверяется. Явно учитывать смешанные A/AAAA результаты и безопасное destination pinning/проверку соединения; remote proxy resolution, который не может это гарантировать, даёт безопасный отказ (fail closed), не direct retry. Сохранять management/local exclusions. UI объясняет причину без секретного URL.
