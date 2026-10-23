# Privileged helper contract — design v0

Локальный Unix socket, проверка peer credentials, отдельный user/group; недоступен браузеру или TCP LAN. Не general-purpose shell executor. Envelope: protocolVersion, operationId, expectedGeneration, command, payloadHash. Idempotency по operationId+payloadHash, другой payload с тем же ID отклоняется.

Команды: Inspect, ValidateManifest, PrepareGeneration, EngageGuard, ActivateGeneration, VerifyGeneration, RestoreGeneration, StopGuarded, ReleaseProtection. Payload — типизированный manifest из разрешенных объектов: generation ID, listener ports, approved interfaces, canonical destination sets, policy refs, engine/DNS artifacts hashes. Только helper-owned paths; запрет traversal/symlink escape и arbitrary executable/environment/command text. Xray config компилируется сервером, но helper повторно проверяет профиль и допустимые пути/порты; не доверяет API как root.

## Apply protocol
1. Контроллер сохраняет immutable candidate/journal и запускает validation, включая engine config check без применения.
2. Helper закрывает затронутый new-flow gate, сохраняя management/local exclusions; подтверждает durable guard generation.
3. Подготавливает ресурсы поколения; не переписывает активные файлы in-place. Проводит readiness DNS/engine/classification, не только PID check.
4. Переключает kernel batch в пределах атомарности nft transaction; вся операция разных процессов не атомарна. Подтверждает generation после проверки.
5. Контроллер фиксирует active revision только по подтвержденному результату. Crash между подтверждением и DB commit восстанавливается Inspect+journal.
6. Ошибка: вернуть previous generation; при неудаче degraded-guarded. Отсутствие UI/Xray не снимает guard. StopGuarded оставляет защиту. ReleaseProtection требует bound confirmation и audit; повторная операция безопасна.

## Ownership / recovery
Helper управляет только собственными namespace/table/resources, не flush ruleset. Уникальные mark/table allocations проверяются preflight, не копировать 999/255 наугад. Конфликт окружения — ошибка до изменения. nft/system process ошибки не маскируются под success. Persistent recovery manifest содержит hashes/IDs, не открытые секреты; root-owned engine artifacts имеют минимальные права. Recovery при boot восстанавливает gate до разрешения обслуживаемого транзита; конкретный service ordering проверяется изолированно.

## Required negative tests
Недопустимый peer, version mismatch, stale generation, duplicate operation с другим hash, oversized input, path traversal/symlink, неподдержанный interface/port, hostile compiler artifact; остановка API/helper/engine на каждом шаге, full disk и corrupt journal, timeout, rollback failure. Helper crash не доказывает сохранение kernel gate — проверить. IPv6 enable без доказанного профиля отклоняется, не частично применяется.
