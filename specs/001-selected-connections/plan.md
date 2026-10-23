# Implementation Plan: Raylane selected connections and LAN

**Status:** DRAFT TECHNICAL PLAN / REVIEW REQUIRED. Spec Kit Phase 0 выполнена как консолидация исследования; Phase 1 — проект контрактов. Version/network gates ниже остаются блокерами runnable baseline, а не скрыто «решенными» неизвестными.
**Spec:** [spec.md](spec.md). Feature 001-selected-connections; текущая Git-ветка main, отдельная ветка не создавалась. Пользователь разрешил составить plan с учетом существующих агентов 01–05, не запуск реализации.

## Summary
Самостоятельная Ubuntu-панель: Go control-plane + ограниченный privileged helper, React/TypeScript UI, SQLite, отдельные Xray и dnsmasq. Immutable drafts/active snapshots, безопасное применение с journal/rollback, отдельно живущая защита от direct bypass. nftables/TPROXY — выбранная база проектирования, один NIC проверяется прежде реализации полной сетевой интеграции. Все решения/альтернативы и ограничения — [research.md](research.md).

## Technical Context
- Language: Go backend/helper, TypeScript UI. Точные supported release pins блокируются gate G1, не оставлены на «latest».
- Dependencies: Xray (один движок), dnsmasq с nftset, nftables/iproute2, React, SQLite driver, проверенные crypto/парсеры. Production Xray release еще не выбран; snapshots только исследовательские.
- Storage: SQLite single-host, WAL/transactions, отдельный secret key; immutable manifests и recovery journal в служебном каталоге.
- Testing: Go unit/fuzz/race, frontend unit/component и Playwright E2E; изолированные Linux namespaces для dataplane; отдельный реальный Ubuntu стенд только после разрешения.
- Platform: первичный целевой стенд Ubuntu 24.04 LTS amd64, systemd. ARM/другие ОС не объявлены поддержанными.
- Type: самостоятельное web application + local privileged service, не Hyper plugin.
- Performance: фиксируем latency/throughput, CPU/RSS и time-to-recovery; baseline 20 синтетических клиентов/1000 узлов/10 источников, stress до parser limit 10 000/source. Это тестовые нагрузки плана, не SLA; принять/скорректировать по измерениям до release.
- Constraints: один NIC, внешний роутер вручную, no automatic proxy fallback, management preserved, secrets redacted, no runtime edits now.

## Constitution Check — до и после дизайна
- PASS: разрешение plan получено текущим сообщением пользователя; tasks/implement/оркестратор не запускались. Предыдущие запреты относятся к самовольному переходу, не отменяют это явное разрешение.
- PASS: нет API/LuCI/SSH-интеграции продукта; ручная инструкция роутера отдельно.
- PASS: референс привязан к commits, product decisions не переписаны архитектурой; новые technical choices помечены proposal/review.
- PASS: UI использует согласованные accessibility/reduced-motion принципы; визуальная реализация/прототип пока не создаются. До UI-кода повторное чтение установленного Apple Design skill обязательно.
- PASS: приватные адреса, роли с runtime IDs и секреты в публичный план не включены. Роли указаны номерами; точные agent IDs разрешаются discovery при запуске, не hard-code.
- CONDITIONAL: безопасность/сеть/версии требуют G1–G4; документальный PASS не означает runtime-ready.

## Project Structure — предлагаемые пути, еще не созданный код
```text
cmd/raylane/                  # API/control plane
cmd/raylane-net/              # restricted helper
internal/domain/             # immutable model, validation, reconciliation
internal/store/              # SQLite, migrations, encrypted secrets
internal/importer/           # URI/YAML, limits, fingerprints
internal/compiler/           # engine/DNS/network manifests
internal/control/            # update/apply state machines
internal/api/                # auth, HTTPS API, redaction
internal/netagent/           # privileged operations and recovery
web/                         # React UI
contracts/                   # implementation schemas after approval
packaging/                   # systemd/package manifests
tests/                       # synthetic tests
  fixtures/                  # synthetic only
  contract/
  integration/
  network/
```
Документы этой feature: plan.md, research.md, data-model.md, contracts/control-plane.md, contracts/network-agent.md, quickstart.md. tasks.md не создается этим этапом.

## Gates и порядок этапов
**G0 — согласование технического плана:** пользователь/ревью подтверждают базу и границы; неожиданные требования возвращаются в spec.
**G1 — reproducible baseline:** 05 собирает release/capability/license matrix Xray, Go/Node/dependencies; 03 проверяет. 01 фиксирует versions/checksums. Без этого нет обещания runnable quickstart или готовности Phase 0 к реализации.
**G2 — сеть одного NIC:** доказать в изолированной среде IPv4 direct SNAT-return, TPROXY, DNS readiness, no-loop/no-bypass, management. IPv6 отдельно; незакрытый IPv6 блокирует полную приемку FR-020, не вычеркивается из scope.
**G3 — security contracts:** 03 проверяет helper attack surface, bootstrap/session, fetch SSRF, secrets/backup, crash consistency. 04 готовит отрицательные проверки.
**G4 — acceptance evidence:** каждый принятый FR имеет тест/свидетельство, failure tests и recovery. Непройденный gate блокирует acceptance.

Последовательность будущих implementation increments (не task dispatch):
1. Версии, схемы и skeleton без привилегий; тестовая инфраструктура.
2. Domain/store/auth/secrets; UI каркас и редактор с save/validate, без сети.
3. Импорт/подписки/списки и reconciliation; независимая проверка транзакций.
4. Compiler manifests и isolated network spike для G2; helper/gate lifecycle.
5. Apply/rollback/backup и полноценные UI состояния.
6. End-to-end/нагрузка/security review, package и ручная инструкция; реальная сеть только по разрешению.
Последовательность может уточняться tasks, но зависимость сетевого выполнения от G2/G3 сохраняется. Изолированный spike также не запускается сейчас.

## Существующие агенты 01–05
| Агент | Ответственность | Запрещенная подмена |
|---|---|---|
| 01 — Оркестратор | зависимости tasks, ограниченный dispatch, integration/merge queue, tracking gates | не объявлять PASS по словам исполнителя; не менять scope |
| 02 — Разработчик | реализация scoped задач, unit tests, migrations, docs и воспроизводимые команды | не принимать собственную работу вместо 03/04; не трогать реальную сеть |
| 03 — Технический ревьюер | независимый diff/architecture/security review, проверка контрактов и отказов | не подтверждать невыполненные тесты; блокировать риск, не замалчивать |
| 04 — Тестировщик | acceptance/negative/regression, независимое воспроизведение, evidence и NOT_RUN | не подменять real result предположением или успешной сборкой |
| 05 — Исследователь | release/capability, mapping полей, сеть/протоколы, источники и неизвестные | не внедрять незаявленные функции и не менять решения пользователя |

**Передача:** 01 → 05 при неизвестном контракте → 03 review исследования → 02 implementation → 03 diff review → 04 verification → 01 интеграция. Если тесты требуют изменений, обратно 02, затем повторно 03/04. 03 и 04 могут работать параллельно только по неизменному commit. 05 может параллельно исследовать независимый будущий блок. Один writer на область; контракты меняются отдельным review, не одновременно несколькими агентами.

Каждая будущая task packet содержит ID, FR/US, immutable base commit, allowed paths, preconditions, acceptance, команды проверки, запреты/секреты, stop conditions и формат результата. Результат: commit/diff, выполненные команды и exit codes, redacted evidence, PASS/FAIL/NOT_RUN, риски. Без evidence задача не Done. Подтверждение 03/04 не разрешает push, live deployment или сетевые изменения без человека.

Существующие чаты не пересоздавать. Их роли найдены через agent.search в workspace Raylane; перед dispatch заново проверить соответствие номера/заголовка/workspace. Текущий план не посылал им сообщений и не запускал задания.

## Completion / Complexity Tracking
Phase 1 artifacts подготовлены как проект. Никаких новых продуктовых вопросов; technical plan требует ревью, G1/G2/G3 имеют явные условия закрытия. Не объявлять Phase 0 полностью resolved: exact releases и network proof еще не получены. Добавленная сложность helper оправдана изоляцией root и сохранением gate после смерти UI/engine; backend-root и один общий процесс отвергнуты. Следующий разрешаемый шаг после review — speckit.tasks, затем speckit.analyze; implement только отдельно.
