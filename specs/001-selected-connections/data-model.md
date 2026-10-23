# Phase 1 — концептуальная модель данных

Проект, не миграция. UUID для локальной идентичности; секреты только SecretRef. Все mutation требуют expectedRevision, конфликт не перезаписывает чужое изменение.

| Entity | Поля / связи | Инварианты |
|---|---|---|
| Node | id, protocol, label, activeFields, inactiveFields, unknownFieldsEncrypted, sourceId?, sourceKey?, revision, validation | protocol выбранный; неизвестное сохраняется без исполнения; JSON syntax gate до записи; секреты refs |
| Subscription | id, URL secret ref, accessMode, serviceRouteRef?, TLS exception, UA, filter, schedule, revision | Auto без примененного маршрута запрещает загрузку; источник не задает локальный ID |
| SourceBinding | sourceId, sourceStableId?, fingerprintVersion, keyedFingerprint, nodeId, missingSince? | уникальность внутри источника, неоднозначность отклоняет весь candidate |
| RuleSetSource | id, chosenURL, fetchPolicy, schedule, draftVersion, activeVersion | источник явно выбран; пустой/ошибочный candidate не заменяет набор |
| DestinationRule | id, kind block/direct/proxy, matcher domain/IP/CIDR/setRef, outboundRef?, revision | фиксированный приоритет FR-020; ссылки защищены; конфликты видимы |
| ConfigRevision | id, parentId, canonicalDocument, secretRefs, validationReportId, createdBy | immutable; never stores plaintext secrets; active и draft различаются |
| ValidationReport | id, revisionId, capabilityProfileId, status, errors/warnings, evidence | invalid блокирует apply; NOT_RUN не PASS; ошибки редактированы |
| ActiveState | revisionId, manifestHash, generation, readiness, appliedAt | меняется только после apply readiness, не при save |
| ApplyJournal | id, previousActive, candidate, state, helperOperationId, lastError | durable progress, crash reconciliation, один apply |
| UpdateJob | id, sourceId, capturedRevision, status, counters, errorCode | один running/source; commit только при совпадении capturedRevision |
| Secret | id, ciphertext, nonce, keyVersion, purpose | key отдельно; purpose binding; значения не API read |
| Admin / Session | id, passwordHash, sessionTokenHash, created/expires, bootstrapConsumed | одна роль; session revocation, CSRF/origin, bootstrap одноразовый |
| AuditEvent | id, actor, operation, targetId, revision, result | без URL tokens/secret values/полных конфигов |
| BackupEnvelope | version, KDF metadata, salt, AEAD metadata, encrypted payload | отдельная passphrase; authenticated envelope; restore -> draft |

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
