# Quickstart validation guide — planned, NOT RUN

Это сценарии будущей проверки, не инструкция менять текущую LAN. Продуктового кода/бинарников пока нет; команды будущих тестов нельзя считать существующими. Полностью runnable quickstart блокируется G1 и реализацией тестовых entrypoints. Сейчас можно проверить лишь документы.

## Сейчас: проверка артефактов без сети
```sh
SPECIFY_FEATURE_DIRECTORY=specs/001-selected-connections .specify/scripts/bash/check-prerequisites.sh --json --paths-only
git diff --check
```
Ожидается корректный feature path и отсутствие whitespace errors. Это НЕ проверка продукта.

## После разрешения реализации и G1
Prerequisites: закрепленные Go/Node/Xray/dnsmasq/nft/iproute2 versions, синтетические fixtures, disposable Linux VM для network tests. Никаких production secrets/subscriptions и маршрутов текущей машины. 02 создает следующие test entrypoints, 04 проверяет их независимо:
```sh
go test ./...
go test -race ./...
npm --prefix web ci
npm --prefix web run test -- --run
npm --prefix web run test:e2e
```
До появления go.mod/web/package-lock и scripts эти команды — контракт будущего quickstart, не факт запуска. Для namespace tests нужен отдельный runner внутри disposable VM, его точная команда добавляется после реализации; не выполнять arbitrary root script на рабочей машине.

## Обязательные сценарии
| Сценарий | Данные/действие | Ожидание |
|---|---|---|
| US-01 | по одному синтетическому узлу всех протоколов, неверный JSON, несовместимый TLS/transport | no silent correction, invalid draft/no apply, syntax error no save |
| US-02 | save inactive fields, active dependency delete, explicit apply | save не меняет active, dependency 409, operation phase правдив |
| US-03 | rename/change/duplicate/missing source fields, corrupted/empty source | reconciliation FR-022, atomic reject, protected refs |
| US-04 | proxy outage, TLS failure, HTTP redirect cross-origin | no direct fallback, warning, no forwarded credentials |
| US-05 | synthetic router/client/Ubuntu/WAN namespaces | no loop, correct reply, direct/proxy classification, IPv6 profile separately |
| FR-020 | DNS/classification unready; stop | новые затронутые потоки закрыты, management доступен, stop guarded |
| FR-021 | bad apply, failed rollback, encrypted backup/restore | last-good attempt либо degraded-guarded, restore только draft |
| FR-023 | update race, missed schedule, size/redirect/time limit | single-flight, bounded rejection, unchanged active |
| Security | CSRF, auth, helper peer/path attack, redaction canaries | отказ без выполнения, секреты отсутствуют в evidence |

Нагрузка: baseline 20 synthetic clients, 1000 nodes, 10 sources; stress parser до 10 000/source. 04 сохраняет latency percentiles, throughput, CPU/RSS, время failure detection/recovery и окружение. Не назначать SLA задним числом; если ресурсов недостаточно, 01/03 обсуждают корректировку цели, не скрывают измерения.

## Evidence и приемка
Каждый прогон привязан к commit, versions, конфигурации стенда и scenario ID; redacted log, exit code, expected/actual, PASS/FAIL/NOT_RUN. Сырые пакеты/ключи/подписки не коммитить. Данные стенда только в ignored local storage. 03 review и независимый 04 report обязательны. Реальный LAN smoke и отключение Ubuntu — только по отдельному подтверждению пользователя после успешной изоляции. Исходные состояния/план ручного восстановления подготовить до такого теста.
