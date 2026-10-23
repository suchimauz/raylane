# Phase 1 — концептуальная модель данных

Проект, не миграция. UUID для локальной идентичности; секреты только SecretRef. Конфликт не перезаписывает чужое изменение. Optimistic-revision guard применяется к mutation состояния существующей сущности (PATCH/DELETE): такая mutation требует client expectedRevision, конфликт -> 409. Создание новой сущности guard не требует (нет прежнего состояния; защита - absence цели и уникальность ключа транзакционно). Refresh требует client expectedRevision на revision настроек источника плюс серверный commit-check capturedRevision (см. ниже). Immutable-revision операции и generation-bound runtime операции имеют собственные guard. Подробный operation-class table - в contracts/control-plane.md.

| Entity | Поля / связи | Инварианты |
|---|---|---|
| Node | id, protocol, label, activeFields, inactiveFields, unknownFieldsEncrypted, sourceId?, sourceKey?, revision, validation | protocol выбранный; неизвестное сохраняется без исполнения; JSON syntax gate до записи; секреты refs |
| Subscription | id, URL secret ref, accessMode, serviceRouteRef?, TLS exception, UA, filter, schedule, revision, lanAllowlistCIDRs | Auto без примененного маршрута запрещает загрузку; источник не задает локальный ID. `lanAllowlistCIDRs` - per-source LAN CIDR allowlist; редактируется только администратором, не импортируемым содержимым (D-061) |
| SourceBinding | sourceId, sourceStableId?, fingerprintVersion, keyedFingerprint, nodeId, missingSince? | уникальность внутри источника, неоднозначность отклоняет весь candidate. Create сам по себе uniqueness-guard не требует; уникальность keyedFingerprint проверяется при reconciliation, где источник известен |
| RuleSetSource | id, chosenURL, fetchPolicy, schedule, revision, draftVersion, activeVersion, lanAllowlistCIDRs | источник явно выбран; пустой/ошибочный candidate не заменяет набор. `revision` - settings revision (optimistic-concurrency guard); `draftVersion`/`activeVersion` - content versions загруженного набора. Client `expectedRevision` на PATCH/DELETE/refresh всегда привязан к `revision`, никогда к `draftVersion`/`activeVersion`. `lanAllowlistCIDRs` - per-source LAN CIDR allowlist; редактируется только администратором, не импортируемым содержимым (D-061) |
| DestinationRule | id, kind block/direct/proxy, matcher domain/IP/CIDR/setRef, outboundRef?, revision | фиксированный приоритет FR-020; ссылки защищены; конфликты видимы |
| ConfigRevision | id, parentId, canonicalDocument, secretRefs, validationReportId, createdBy | immutable; never stores plaintext secrets; active и draft различаются |
| ValidationReport | id, revisionId, capabilityProfileId, status, errors/warnings, evidence | invalid блокирует apply; NOT_RUN не PASS; ошибки редактированы |
| ActiveState | revisionId, manifestHash, generation, readiness, appliedAt | меняется только после apply readiness, не при save |
| ApplyJournal | id, previousActive, candidate, state, helperOperationId, lastError | durable progress, crash reconciliation, один apply |
| UpdateJob | id, sourceId, capturedRevision, status, counters, errorCode | один running/source; commit только при совпадении server-side `capturedRevision`. `capturedRevision` - серверный commit-check (останавливает commit поверх изменения, сделанного после старта job), отличный от client `expectedRevision` на сам запрос refresh |
| Secret | id, ciphertext, nonce, keyVersion, purpose | key отдельно; purpose binding; значения не API read |
| Admin / Session | id, passwordHash, sessionTokenHash, created/expires, bootstrapConsumed | одна роль; session revocation, CSRF/origin, bootstrap одноразовый. Unsaved-edit preservation (D5): открытая страница сохраняет unsaved editor state в page RAM через expiry/re-login/control-plane restart, включая введённые secret-поля; без browser storage/логов; см. UI contract |
| AuditEvent | id, actor, operation, targetId, revision, result | без URL tokens/secret values/полных конфигов |
| BackupEnvelope | version, KDF metadata, salt, AEAD metadata, encrypted payload | отдельная passphrase; authenticated envelope; restore -> draft. Self-contained encrypted export (D4): payload несёт достаточный конфиг и значения секретов для восстановления на чистую цель, включая encrypted-quarantined поля. Restore пересоздаёт записи secret-store под целевым ключом и remapит ссылки в той же транзакции, что и новый draft. Не содержит master key, sessions, admin credentials, release/bootstrap tokens, raw audit logs или passphrase |

## Состояния
Node: valid-draft / invalid-draft; missing-from-source — отдельный признак, не автоматическое удаление. Active membership хранится в ActiveState snapshot, а не mutable-флаге самого узла.
Update: queued → fetching → parsing → reconciling → committed либо rejected/failed. Никаких частичных записей; refresh отсутствующих полей и появление новых узлов одной транзакцией. Конфликт revision отклоняет candidate, не теряет ручные изменения.
Apply: queued → validating → guarding → preparing → switching → verifying → active. Ошибка после guarding → rolling-back → restored либо degraded-guarded. При crash незавершенный journal сначала reconciled; не снимать gate по одному исчезновению процесса.
Stop: active → stopping-guarded → stopped-guarded. release-protection — отдельная авторизованная подтвержденная операция; не часть Stop.
Readiness: management-ready отдельно от DNS-ready/engine-ready/classification-ready. Новые соединения затронутых клиентов допускаются только по утвержденной политике readiness, без догадок по наличию PID.

## Валидаторы
По каждому протоколу schema/capability profile закрепляет supported fields, отсутствующее/пустое, defaults, зависимости, URI/YAML mapping. WireGuard Reserved 0/3 bytes проверяется по целевому release; snapshot reference не заменяет release gate. Chain graph: отсутствие dangling refs, cycles и лишних слоев. Domain/IP matching нормализуется документированно; не выполнять regex/YAML tags из неподдержанных форматов.

## Удаление и восстановление
Проверять references текущего draft и immutable active; transaction защищает гонку delete/apply. Secret cleanup только после отсутствия всех живых revision/backup-retention refs согласно отдельной retention policy. Restore не перезаписывает active; шифрование/формат проверяются до создания нового draft. Схема хранения, migrations и retention durations требуют security review до реализации.
