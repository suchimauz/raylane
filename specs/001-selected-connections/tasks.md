# Tasks: Raylane — 001-selected-connections

Статус: реализация явно разрешена пользователем и начата. T001 принят как исследовательский результат; T002 принят как инертный сборочный каркас после независимых 03/04 проверок. T003 принят как синтетический корпус fixtures, без заявления о проверке поведения продукта. Остальные задачи не завершены. Evidence: [T001 acceptance](../../docs/verification/T001-acceptance.md), [T002 acceptance](../../docs/verification/T002-acceptance.md), [T003 acceptance](../../docs/verification/T003-acceptance.md). G1 runnable и G2–G4 остаются OPEN. План: plan.md, spec.md, data-model.md, contracts/*.md. Порядок ниже технический, не присвоенные пользователю бизнес-приоритеты.

## Общий контракт выполнения
01 выдает пакет с base commit, FR/US, allowed paths, зависимостями и критериями. 02 — основной writer; 05 — source/capability research; 03 — независимый review; 04 — тесты/evidence. Если явно не указано иное, владелец 02; 01 не отмечает Done без 03 review + 04 evidence. Возможные test-first failures фиксируются; инфраструктурный сбой не считается доказательством failing acceptance test. Секреты/сырые дампы — вне Git; нет live network/push/deploy без отдельного подтверждения. Все пути ниже будущие, не существующий код. [P] означает разные файлы после выполненных prerequisites, не разрешение двум агентам править одну область.

## Phase 1 — Setup / G1
- [x] T001 Закрепить release/capability/license matrix и provenance выбранного Xray source baseline, Go/Node/dnsmasq/nft и crypto/parser dependencies в packaging/versions.lock и docs/engineering/capabilities.md; 05 собирает, 03 проверяет. G1: никакого latest или неподтвержденного checksum, нет обещания binary trust по одному tag.
- [x] T002 После T001 создать Go modules, cmd/raylane/main.go, cmd/raylane-net/main.go, web/package.json и lockfiles для Go/React/SQLite; без root/network side effects, build обоих бинарников и UI воспроизводим.
- [x] T003 [P] После T002 создать tests/fixtures/README.md и синтетические fixtures всех протоколов/ошибок; 04 задает секретные canaries и expected semantic outcomes из spec, не реальные подписки.
- [ ] T004 [P] После T002 настроить unit/race/frontend/contract CI в .github/workflows/verify.yml и docs/engineering/testing.md; network runner только opt-in disposable VM, не host root.

## Phase 2 — Foundational
- [ ] T005 Зафиксировать machine-readable API/helper schemas в contracts/openapi.yaml и contracts/helper.schema.json по feature contracts; 03 проверяет отсутствие arbitrary shell/path и secret-read; prerequisites T001.
- [ ] T006 После T002/T005 реализовать revision/entity/validation envelopes в internal/domain/ и SQLite migrations в internal/store/; immutable active/draft, transaction и optimistic revision tests в internal/store/store_test.go.
- [ ] T007 После T006 реализовать SecretRef/AEAD/key access в internal/store/secrets.go и redaction allowlist в internal/api/redaction.go; negative tests на утечку canaries, key permissions и corrupt ciphertext; 03 security review.
- [ ] T008 После T005/T007 реализовать local bootstrap, Argon2id, sessions/CSRF/rate limits/LAN HTTPS configuration в internal/api/auth/ и tests/integration/auth_test.go; FR-019/021, нет общих паролей и открытого LAN bootstrap.
- [ ] T009 После T005/T008 создать UI shell со статусами draft/active/error, keyboard/reduced-motion в web/src/app/; перед кодом прочитать Apple Design skill, не считать наличие UI разрешением сети.

## Phase 3 — US-01: узлы и проверка
Независимая приемка: создание/сохранение всех выбранных узлов, неизвестные/несовместимые поля и неверный JSON без применения сети. FR-001–009/018/019, SC-001/006.
- [ ] T010 [P] [US1] После T003/T005 подготовить table-driven negative/positive validation tests в tests/contract/nodes_test.go; 04 сверяет synthetic fixtures с capability matrix, NOT_RUN отделен от PASS.
- [ ] T011 [US1] После T006/T007/T010 реализовать schemas/default-presence/inactive/unknown fields и chain graph в internal/domain/nodes/; все поля FR-002–008, никакого silent correction или secret leak.
- [ ] T012 [US1] После T011 реализовать revision-aware node CRUD/validation в internal/api/nodes.go; references из draft/active блокируют delete, синтаксическая JSON ошибка не меняет сохраненное.
- [ ] T013 [US1] После T009/T012 реализовать редакторы четырех протоколов в web/src/features/nodes/ и web/tests/nodes.spec.ts; отличать collapsed от inactive, пароль/PSK скрыт, compatibility errors видимы.

## Phase 4 — US-02: сохраненное/активное, применение
Независимая приемка сначала с fake helper, затем с G2 runner. FR-009/010/021, SC-002/004. Никакое stub PASS не выдается за сетевую приемку.
- [ ] T014 [US2] После T006/T011 реализовать immutable compiler artifacts и capability validators в internal/compiler/ и tests/contract/compiler_test.go; validation Xray config отдельная операция, не применение.
- [ ] T015 [US2] После T005/T007/T014 реализовать constrained Unix-socket helper/preflight/idempotency в internal/netagent/ и tests/contract/helper_test.go; peer credentials, own resources, stale generation/path attacks. Fake adapter по умолчанию.
- [ ] T016 [US2] После T006/T014/T015 реализовать durable apply journal/reconciliation/rollback controller в internal/control/apply.go; crash/failure injection на каждом шаге в tests/integration/apply_test.go, active обновляется только после acknowledgement/readiness.
- [ ] T017 [US2] После T008/T016 реализовать apply/status/stop-guarded/release-protection API и UI в internal/api/runtime.go и web/src/features/runtime/; bound expiring confirmation для release, отсутствие silent fallback.
- [ ] T018 [US2] После T007/T008/T016 реализовать encrypted backup/restore-to-draft и diagnostics allowlist в internal/control/backup.go и tests/integration/backup_test.go; plaintext/passphrase не persist, limits/authentication до restore.

## Phase 5 — US-03: импорт и reconciliation
Независимая приемка без внешней сети: fixture source candidate→atomic commit/reject, активное состояние неизменно. FR-011–013/022, SC-003/004/006.
- [ ] T019 [P] [US3] После T003/T005 подготовить URI/YAML equivalence, damaged/empty/unknown/unsupported cases в tests/contract/import_test.go; 04 проверяет различия parse failure и semantic invalidity.
- [ ] T020 [US3] После T011/T019 реализовать bounded URI/Base64/YAML parsers в internal/importer/; без tags execution/providers fetch; unknown fields encrypted, supported field mapping exhaustive по profile.
- [ ] T021 [US3] После T006/T020 реализовать source identity/fingerprint versioning/duplicate rejection и absent-field reset в internal/control/reconcile.go; rename preserves ID, changes without source ID -> new node, disappearing references protected.
- [ ] T022 [US3] После T021 реализовать filters/global inheritance и atomic import commit в internal/control/import.go; matcher contract и нулевые результаты покрыты tests/integration/subscription_update_test.go.
- [ ] T023 [US3] После T009/T022 реализовать subscription/import editor и отчеты в internal/api/import.go и web/src/features/subscriptions/; предупредить о замене ручных правок, secrets absent from errors.

## Phase 6 — US-04: загрузчик и расписание
Независимая приемка: controlled HTTP/TLS/proxy fixtures, никакого real endpoint. FR-014/015/022/023, SC-005/006.
- [ ] T024 [US4] После T007/T020 реализовать access modes/Auto service route и bounded fetch/redirect/SSRF policy в internal/control/fetch.go; contracts for DNS rebinding/proxy-resolved destination fail-closed, explicit per-source TLS exception; FR-024/D-061: URL credentials extraction, per-source LAN allowlist, absolute forbidden address classes.
- [ ] T025 [P] [US4] После T005/T003 реализовать fixture proxy/HTTP servers и leakage tests в tests/integration/fetch_test.go; 04 проверяет Proxy outage, downgrade reporting, cross-origin credential stripping, size/deadline limits, URL credential redaction, per-source LAN allowlist и запрещенные адреса даже поверх allowlist (FR-024).
- [ ] T026 [US4] После T006/T021/T024 реализовать single-flight scheduler с явной timezone, boot marker, coalescing missed runs и bounded retries в internal/control/scheduler.go и tests/integration/scheduler_test.go.
- [ ] T027 [US4] После T023/T024/T026 реализовать download controls/warnings/UA presets, progress и busy response в web/src/features/subscriptions/download.tsx и internal/api/updates.go; автоматические режимы default off, success не apply.

## Phase 7 — US-05: LAN и guard / G2
Независимая приемка: изолированные router/client/Ubuntu/WAN namespaces, два IP-профиля; production LAN не используется. FR-016/017/020/023, SC-005/007.
- [ ] T028 [US5] После T001/T014 описать воспроизводимые IPv4 flat-LAN SNAT и IPv6 transit-VLAN профили в tests/network/topology.md и docs/engineering/network-profile.md; 05 подтверждает original destination/return path/kernel prerequisites по источникам, 03 review до запуска.
- [ ] T029 [US5] После T028/T015 создать disposable-VM namespace runner в tests/network/runner/ с cleanup/audit и tests/network/no_loop_test.go; 04 выполняет только после отдельной авторизации выполнения, доказывает маршруты/marks/conntrack, не правит host routes.
- [ ] T030 [US5] После T014/T028 реализовать nftables manifest/compiler и backend adapter в internal/netagent/nft/; atomic own-table batches, mark collision rejection, management exemptions, explicit rule priority; tests/contract/network_manifest_test.go.
- [ ] T031 [US5] После T022/T024/T030 реализовать rule-source validation/draft generation и dnsmasq adapter в internal/compiler/dns/ и internal/control/rules.go; explicit resolvers/sources, generation-bound sets/TTL/readiness, IPv6 filtering independent.
- [ ] T032 [US5] После T029/T030/T031/T016 реализовать live adapter lifecycle в internal/netagent/lifecycle.go; startup/stop guarded, DNS unready new-flow block, upstream failure without bypass, rollback/degraded; 04 проверяет tests/network/failure_matrix_test.go.
- [ ] T033 [US5] После T009/T031/T032 реализовать rules/readiness/IPv6/conflict UI и API в web/src/features/rules/ и internal/api/rules.go; IPv6 unavailable profile отклоняется с причиной, не silently partial, ограничения скрытого домена видимы.
- [ ] T034 [US5] После T032 подготовить docs/operations/router-manual.md и docs/operations/recovery.md для двух профилей; 04 проверяет управление при остановке/полном отказе в стенде, 03 review последствий manual bypass, без адресов частного окружения.

## Phase 8 — cross-cutting verification / release gate
- [ ] T035 После T013/T017/T018/T023/T027/T033 выполнить independent E2E/accessibility/security regressions в tests/e2e/ и docs/verification/e2e.md; 04 evidence на immutable commit, 03 review угроз/auth/helper/exports.
- [ ] T036 После T032/T035 измерить baseline/stress нагрузки плана и recovery в tests/network/performance/ и docs/verification/performance.md; 04 пишет actual metrics, failures и ограничения, не выдуманный SLA.
- [ ] T037 После T001/T034/T035/T036 подготовить systemd ordering/package/upgrade artifacts в packaging/ и точные runnable команды feature quickstart.md; 02 воспроизводит чистую disposable install, 03/04 verify gate-before-transit и secret permissions.
- [ ] T038 После T037 свести FR-001–024→tests→evidence в docs/verification/acceptance.md; 01 проверяет независимые 03/04 заключения и все gates, статус NOT_RUN блокирует соответствующую приемку. Live LAN/push/deploy не входят в это разрешение.

## Зависимости и ограничение параллелизма
Setup → foundation → US-01. Затем US-02 fake-helper и US-03 могут планироваться раздельно, но общий domain/schema не правится параллельно. US-04 зависит от parser/reconciliation; US-05 от compiler/helper/loader. Полный US-02 apply acceptance зависит от US-05 G2. T025 может идти параллельно T024: отдельные tests vs implementation, общий контракт предварительно заморожен. T010/T019 fixture tests независимы после prerequisites. Один 02 не становится несколькими разработчиками из-за [P]; 04 работает в своем worktree, 03 review readonly immutable commit. 05 исследует будущую задачу, не исправляет одновременно реализацию 02.

Примеры: US-01 — 04 T010, затем 02 T011; US-02 — 03 review T015 параллельно 04 injection tests на том же commit; US-03 — 04 T019 пока 05 проверяет следующий mapping, без shared edits; US-04 — T024/T025; US-05 — 05 source evidence T028, затем 04 isolated runner, 02 adapter только после согласованного профиля. Это conditional concurrency, не запуск сейчас.

## Incremental strategy
Первый демонстрируемый срез: T001–T013, редактор/валидация без сети, не полноценный релиз и не замена полного scope. Далее drafts/import/fetch, затем доказанная сетевая интеграция и recovery. Каждая история проверяется независимо на fixtures/adapters; полный релиз требует всех пяти историй и G1–G4. Нет внедрения в реальную LAN ради демонстрации MVP.
