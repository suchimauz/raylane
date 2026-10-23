> **UPDATE — A04 partially resolved by the T005 foundation batch (D4, D5).**
> Backup: alternative **A — self-contained encrypted export** is chosen (D4);
> persistent backup metadata/pinning (B) is declined; cleanup stays OFF. The
> envelope carries configuration AND secret values for restore to a clean
> target; restore is draft-only and atomic. Session constants are unchanged
> (idle 900 s, absolute 43200 s, re-login after restart); unsaved-edit
> preservation is RAM-only and is a UI implementation gate (D5). The
> PROPOSED limiter constants and activity allowlist remain open where not
> fixed by D5. Authoritative rationale: `docs/engineering/foundation-decisions.md`.

# A04 — security-contract proposal (r3: scoped session-policy consent)

**Частичный пользовательский consent; остальные defaults PROPOSED. A04 OPEN.** Researcher 05; 2026-10-23.
Corrections to target `427a9de4a72af848dacb3496a466c83da1e46ec5`.
Assignment/research base исходного предложения: `5774d00`; HEAD до правок:
`427a9de`. Фактический parent нового commit сообщается после commit.
Scope: FR-019/021, US2; Admin/Session/Secret/ConfigRevision; analysis A04;
research R-05/R-06; control-plane/network-agent contracts. Это предложение,
не изменение архитектуры, schema, contracts, tasks или кода. Сеть: 0.
Никакие sessions/secrets/GC не созданы и не запущены.

## 0. Источник и точный scope согласия

Consent source: пользовательский input `in9a75e5c3028a907d`, ответ
`accept-session-policy-preserve-edits`; передан оркестратором 01 в задании
T005-A04-consent-record. Correction target/base: `d0ae30a` (HEAD проверен).
Это запись полученного согласия, не самостоятельная приемка Researcher.

**USER-ACCEPTED только:** session idle 15 min, polling/read не продлевают idle;
absolute 12 h; re-login после control-plane restart; допустимость ограничения
НОВОГО login под LAN DoS. Точные limiter constants, activity allowlist и остальные
технические детали остаются PROPOSED, не превращаются в согласованные defaults.

**Обязательное условие UX:** потеря НЕСОХРАНЕННЫХ правок НЕ разрешена. До реализации
UI должен быть определен и проверен механизм сохранения/восстановления правок при
expiry, re-login и restart. Данный consent НЕ выбирает механизм и НЕ разрешает
автоматическое хранение секретов в localStorage, browser storage или журналах.
Не ослаблять expiry/auth ради сохранения правок; secret handling остается FR-019/021.

Consent НЕ выбирает backup A/B, НЕ разрешает automatic deletion, не вводит новую
архитектуру, features или UI knobs. Backup-live schema/GC остаются BLOCKED.

## 1. Fixed technical constants — статус указан ниже, остальные PROPOSED

Новых admin UI knobs/settings нет. Значения фиксируются в security contract
только после review/решения 01. Для фиксированного параметра min=max=default;
изменение — новая согласованная версия контракта, не пользовательская настройка.
Это не обещание производительности и не результат испытаний.

| ID | Параметр / единицы | Default = min = max | Граница и rationale |
|---|---|---|---|
| P1 | Session idle, s | 900 | USER-ACCEPTED: 15 min, polling/read не продлевают. Точный activity allowlist §2 PROPOSED; UX preservation обязателен (§0). |
| P2 | Session absolute, s | 43 200 | USER-ACCEPTED: 12 h absolute. Детали enforcement остаются PROPOSED; UX preservation обязателен (§0). |
| P3 | Session token entropy, bits | 128 | CSPRNG random token; в БД SHA-256 hash, cookie Secure/HttpOnly/SameSite=Strict; без plaintext/logging. |
| P4 | Bootstrap TTL, s | 600 | Локальная issuance ДО появления admin; одноразовый random token; TTL не настройка существующего admin. |
| P5 | Release confirmation TTL, s | 120 | Random token, bound к session + ActiveState generation + protection state; одноразовый. |
| P6 | Login admission | 5 attempts/IP burst; refill 1/60 s; max 2 concurrent password verifications; max 1 waiting request | Только per-source admission и глобальное ограничение работы; НЕТ account-wide unauthenticated lockout. Подробнее §4. |
| P7 | Secret payload deletion | OFF | Нет разрешения на cleanup. Reachability/tx алгоритм §5 — только design proposal; backup semantics не решены → затронутые schema/GC BLOCKED. |
| P8 | Revision/draft retention deletion | OFF | Никаких 30-day compactions; все revision/draft сохраняются до отдельного продуктового решения. |
| P9 | Audit retention deletion | OFF | Никакого six-month удаления/stubs вместо history. Audit сохраняется до отдельного продуктового решения. |
| P10 | Expired auth-record sweep, s | 60 | Только истекшие session/confirmation/bootstrap token records, не audit/revisions/secrets. Expiry проверяется на запросе независимо от sweep. |

OFF — reason nonconfigurable: удаление history/backup требует отдельного решения,
не технического duration default. Это НЕ разрешение на бесконтрольный silent disk
growth: backpressure/management path — §7. Согласия на P8/P9 сейчас не запрашиваем.

## 2. Session activity contract (P1–P3)

Server-side route classification, default **NO_ACTIVITY**. Клиентский header
«human action» не принимается как доказательство. Activity только при всех условиях:
1. session валидна ДО выполнения операции;
2. CSRF/origin и authorization успешны;
3. это allowlisted явная mutation черновика либо пользовательская команда
   apply/stop/backup-export/restore/release-confirmation в существующем API;
4. команда принята сервером (успешный commit или 202 с durable operation id).
В этом случае idle deadline обновляется в той же транзакционной границе принятия
команды, с cap по absolute deadline. Конкретный route allowlist должен войти в T005
contract; новые API endpoints этим не добавляются.

GET/HEAD/OPTIONS не activity. В частности `/operations` (включая `/operations/{id}`),
`/state`, liveness, фоновые refresh/status requests никогда не продлевают idle;
ошибки 4xx/5xx/CSRF failure также не activity. Простое чтение/долгое редактирование
без сохранения не продлевает session; после expiry нужен login, не скрытый heartbeat.
Это НЕ согласие на потерю несохраненных правок: защита правок должна быть определена
до UI, без автоматического plaintext-secret persistence (§0). Login создает новую
session, а не оживляет старую.

Valid iff not revoked AND now < idle_deadline AND now < absolute_deadline;
равенство deadline уже expired. Request проверяется до приема команды. Команда,
принятая до expiry, может завершиться после него под своим journal/in-flight pins;
последующее чтение результата требует действующей session.

Expired/revoked/invalid → одинаковый generic 401 и очистка cookie. Revocation
проверяется на каждом запросе без кеш-окна. Parallel sessions разрешены независимо;
logout затрагивает текущую; password change атомарно отзывает остальные и ротирует
текущую без продления ее absolute lifetime. Session rotation отзывает старый token
и связанные confirmation tokens; новые права/сроки этим не создаются.

## 3. Clock, restart, bootstrap, confirmation

### Clock/restart — fail-closed, persistent
В процессе durations используют monotonic clock и wall UTC deadline: истечение
по ЛЮБОМУ из двух часов завершает session; forward wall jump за deadline не отменяется
последующим backward jump. Persistent security wall-clock high-water mark обновляется
в SQLite при принятии auth activity/issuance и checkpoint раз в 60 s. Не допускается
уменьшение watermark; clock write failure → auth mutation отказ, не продление trust.
Backward jump >300 s относительно persistent watermark/наблюдаемого в процессе
максимума отзывает sessions и ephemeral tokens, пишет redacted audit; при меньшем
откате effective wall time = max(observed wall, watermark), а monotonic lifetime не
увеличивается. Запрет новых issuance при недостоверном времени до его исправления.

USER-ACCEPTED: после control-plane restart требуется re-login; несохраненные правки
должны быть защищены (§0). PROPOSED enforcement: при КАЖДОМ service restart старые
sessions/bootstrap/confirmation tokens инвалидны;
отмена фиксируется до открытия auth API, idle/absolute не восстанавливаются «с нуля».
Это консервативный пересмотр исходного предложения о persist-through-restart:
persistent watermark нужен и после restart, чтобы откат часов не обходил policy.
Если запись revocation/clock state невозможна, auth API fail-closed; management
liveness доступен без секретов. Bootstrap после admin creation НЕ открывается.
DB/snapshot restore: до открытия auth middleware отозвать старые auth tokens;
если это нельзя гарантировать — auth API BLOCKED, не считать старые cookie валидными.
Это не новая remote recovery функция; корректный login после исправления storage/time
остается штатным путем. Не обещать HTTP login при физически неработающей БД.

### Bootstrap (P4)
До admin локальная консоль/защищенный local channel выдает random 128-bit token
на 600 s, сервер хранит hash. Новая локальная issuance отзывает предыдущий token.
Endpoint доступен только по принятому authorized local channel (не LAN HTTP).
Consume token + insert admin + permanent bootstrapConsumed — одна SQLite transaction.
Два конкурентных запроса: ровно один победитель. Expired token требует новой локальной
issuance; после admin creation повторная issuance запрещена, включая restart.
Local bootstrap НЕ способ password recovery существующего admin.

### Release protection (P5)
Однозначно **CSPRNG random 128-bit token**, не «HMAC или random»; хранится hash и
binding tuple (session id, ActiveState.generation, protection state, expiry, used).
Не добавляем password re-entry как согласованное продуктовое требование: действующая
авторизация повторно проверяется при выдаче и использовании, как в contract.
При consume атомарно повторно проверить session, deadlines, generation, protection
state и unused flag; отметить used и durable принятие release operation.
Проверка актуального generation/protection state также обязательна на helper boundary,
чтобы очередь не дала снять уже изменившуюся защиту. Changed generation (даже если
revision id прежний), logout/rotation/revocation/restart/expiry → token недействителен.
Replay → отказ без второго эффекта; stale state → authenticated 409; expiry/invalid
→ согласуемый contract error, не новый публичный HTTP-код. Дублирование delivery уже
принятой operation допустимо только идемпотентно по journal id, не повторным consume.
Guard самопроизвольно не снимается при ошибках storage/time/auth.

## 4. P6: anti-bruteforce без account-wide unauthenticated lockout

Удален исходный account-wide 5 failures → lockout: атакующий не должен иметь
возможность навсегда блокировать единственного admin неверными паролями.
Per-IP token bucket из P6 применяется ДО password hash; адрес — фактический peer,
не произвольный X-Forwarded-For. IP bucket не продлевает ban на каждом rejected
request: refill идет независимо от атакующего. Хранилище buckets bounded: 1 024
entries, неистекшие entries не вытесняются для обхода лимита; overflow новых peers
получает краткий generic busy. Idle entries удаляются после полного refill.
Глобальный concurrency cap/очередь ограничивают CPU/memory, не создают persistent
account-disabled flag. При исчерпании очереди fail-fast generic retry response без
достоверного account-existence сигнала. Неверный username проходит эквивалентный
password-hash путь после admission, без вывода credentials в audit.

Established valid sessions, authenticated management operations и liveness НЕ
попадают в unauthenticated login limiter. Login с отдельного peer не наследует
чужой IP bucket. Общий NAT peer может мешать admin на том же IP; распределенный
flood может исчерпать bounded global capacity. Абсолютной login availability под
LAN DoS НЕ обещаем. USER-ACCEPTED: ограничение НОВОГО login под LAN DoS допустимо;
это НЕ acceptance точных P6 чисел или доказательство availability действующей session.
Остаточные technical risks остаются для 03/01, не «local console все решает».
Нужны tests: отсутствие account lockout, refill несмотря на flood, доступ действующей
session, bounded CPU/queue, возможность нового login после прекращения flood.
Локальная консоль — диагностика/исправление storage/time и разрешенное service
administration, НЕ новый bypass/password-reset/remote recovery endpoint.

## 5. Reachability и cleanup: порядок, ограничения, BLOCKED часть

Сейчас P7/P8/P9 OFF. Даже будущая cleanup policy НИКОГДА не может удалять payload,
достижимый из active, current draft, retained revision, in-flight apply/export/restore,
rollback/reconciliation journal, previous-good revision или выбранных backup-live refs.
Достижимость — по immutable snapshot/revision graph, а не ненадежному отдельно
обновляемому refcount. AuditEvent содержит ids/result без секретов; по 03 audit stub
не live SecretRef, НО это не разрешение стирать исходный revision ради stub.

Если cleanup позже разрешен: candidate enumeration не дает права удаления. В одной
SQLite write transaction повторно проверить ВСЕ roots, удалить только unreachable
payload и записать redacted audit. Writer, pin insertion, restore-draft commit и
cleanup сериализованы тем же write-lock discipline. Если GC выиграл раньше, новый
reference creation проверяет payload existence и отказывает целиком, никогда не
создает dangling ref. Если writer первым закрепил ref — GC его сохраняет.

Crash до commit → полная rollback transaction (payload И audit); после commit →
оба эффекта durable. Исходное «crash между delete и audit → re-collect» было неточно:
при единой транзакции ни частичного delete, ни audit gap нет. In-flight pins нельзя
снимать по timeout/PID. Restart сначала reconciles journal; incomplete apply/rollback
не объявляется failed автоматически с освобождением refs. Неясность → pins сохранены,
cleanup BLOCKED, management path/guard остаются по R-05.

## 6. Backup-live: две альтернативы, НЕ архитектурное решение

Уже принято: FR-021 требует encrypted backup с отдельной passphrase, ключ не рядом;
restore проверяет envelope и создает draft БЕЗ apply. R-06/data-model дают BackupEnvelope,
Secret и запрет cleanup при live revision/backup-retention refs; **BackupMetadata
сущность в принятом data-model не объявлена**. Из этого нельзя вывести существующий
каталог экспортов/его expiry или разрешение удалить backup files.

| | A — self-contained encrypted export | B — persistent backup metadata/pinning |
|---|---|---|
| Payload | Все нужные snapshot config и secret values внутри AEAD envelope; SecretRef IDs экспортера не являются обязательной restore-зависимостью | Backup зарегистрирован, persistent metadata содержит roots/pinning до явного снятия регистрации |
| Pins | Export capture + transient in-flight pin атомарны; pins сохраняются на весь read/encrypt/export operation и recovery. После доказанного complete/abort/reconciliation — снять pins, completed export не зависит от live SecretRef | Те же in-flight pins, плюс persistent backup-related roots; удаление регистрации требует отдельного policy и согласования потери защиты |
| Restore | Проверить envelope/passphrase, импортировать секреты под новыми локальными refs и создать draft одной логической commit-границей. После успеха draft — live root | Нужно определить переносимость/поведение при потере исходной БД и metadata; одной ссылки на live SecretRef недостаточно для FR-021 backup с секретами |
| Tradeoff | Меньше постоянных зависимостей и сущностей; loss exporter DB не должен мешать restore. Требуется доказать completeness secret closure | Управляемый backup catalog/history, но новая schema/registration lifecycle; рост retention и риск вечных pins |

**Рекомендация, не решение:** A лучше соответствует переносимой резервной копии с
секретами и уже принятому BackupEnvelope, без новой постоянной сущности. Но сам факт
self-contained payload и точное завершение export необходимо закрепить архитектором
в backup contract: encrypted envelope сам по себе не доказывает полноту payload.
B требует Chief Architect до введения metadata/schema, плюс отдельного продукта
решения о lifecycle/удалении history/backup. Ни A, ни B здесь не реализуются.
До выбора 01/архитектора затронутые backup-live schema/SecretRef GC **BLOCKED**;
консервативно сохранять refs. Нельзя превратить незарегистрированный export в тайную
зависимость от исходного хранилища. Backup FILE deletion остается вне scope.

## 7. Retention OFF: disk-full/backpressure и management path

P8/P9 OFF не означает silent unlimited growth: нужны redacted storage-health warnings
и bounded admission (PROPOSED reserve floor 64 MiB free filesystem bytes для новых
revision/export/restore mutations). При free <64 MiB — не принимать новые такие
операции, не менять active/draft; ранее принятые journal operations reconciled.
Это admission watermark, не доказанная физическая reservation: совместный filesystem
может заполниться между check и write. ENOSPC/SQLITE_FULL/IO error всегда обработать
transactionally, без success response при недоказанном commit. Никакого auto-GC,
удаления audit/history/backups ради места или fail-open release protection.

Если audit/journal нельзя durable записать, отказать mutation и release-protection;
не продолжать «без audit». Read-only management/state/liveness сохранять где storage
позволяет; новые login требуют durable session state и при full storage могут
отказать. Existing authenticated management reads не требуют audit write per read.
При полном отказе БД нельзя обещать web management: локальная диагностика и явное
освобождение места оператором вне этого scope; guard остается, active snapshot не
стирается. Стенд должен доказать этот degraded path; эти меры не разрешают cleanup.

## 8. Negative-test vectors — expected, все NOT_RUN

Tests отсутствуют в baseline; ниже acceptance vectors для будущих T005/T007/T008,
не команды к несуществующим файлам и не результаты выполнения.

| # | Input / interleaving | Expected |
|---|---|---|
| 1 | Login t0; принята allowlisted save на t0+899 s | Idle переносится на +900 s, absolute остается t0+43 200 s; ошибка save не переносит |
| 2 | Activity каждые 60 s до absolute boundary | На t0+43 200 s 401 независимо от активности; equality expired |
| 3 | Logout/reuse, parallel sessions, password change/rotation | Старый cookie 401; независимая session живет до отзыва; password change отзывает остальные и старый current token, current absolute не растет |
| 4 | Forward jump за deadline / backward >300 s / малый rollback | Forward expires; большой backward отзывает tokens и блокирует issuance при недостоверном времени; малый rollback не продлевает monotonic lifetime |
| 5 | Expired bootstrap / remote channel / two concurrent consumes / restart после admin creation | Отказ/отказ/ровно один admin и один consume; bootstrap навсегда закрыт после admin |
| 6 | Confirmation replay / same revision reapply с новой generation / logout / queued stale release | Не более одного эффекта; новая generation инвалидирует token даже при том же revision; helper отказывает stale state |
| 7 | Future GC против draft reference insertion | Writer first → payload pinned; GC first → writer отказывает, dangling ref не создается; сейчас GC OFF |
| 8 | Crash между delete/audit/commit будущего GC; crash apply с pins | До commit оба эффекта rolled back, после оба durable; unresolved journal сохраняет pins до reconciliation |
| 9 | Лимит P6 и неправильный username/password | Bounded CPU/queue, generic response без account-existence oracle; secret values отсутствуют в audit |
| 10 | Restore validated backup одновременно с cleanup candidate | Imported secret+draft atomic; нет промежуточного dangling ref, active не меняется; backup ambiguity не обходится |
| 11 | Только GET /operations/{id}, /state, liveness каждые 5 s после login | Idle истекает через 900 s; polling не оживляет session; fake human-activity header игнорируется |
| 12 | Атакующий циклически шлет ошибки в single-admin account | Нет account-wide lockout; отдельный peer допускается при свободной capacity; established management reads работают; local console не выдается за bypass; после flood/refill login восстанавливается, ошибки generic |
| 13 | Export capture одновременно с будущим secret deletion | Capture/pin под write lock: pin first → GC сохраняет; GC first → export fails до принятия snapshot; выбранная A/B policy определяет момент освобождения, не таймер |
| 14 | Persist watermark → restart → rollback clocks / старые cookies/tokens | Старые auth tokens инвалидны; persisted watermark проверен до auth issuance; write failure fail-closed; bootstrap не открывается заново |
| 15 | <64 MiB / ENOSPC между check и commit / audit write fails | Backpressure, mutation не объявлена успешной, active/draft сохранены transactionally, guard остается; no destructive cleanup |
| 16 | DB snapshot restore с прежними session tokens и clock state | До открытия auth старые tokens revoked; если revocation нельзя durable гарантировать, auth BLOCKED; restore конфигурации остается draft-only |

## 9. Disposition review 03 (target 427a9de)

Исходный report использует P1–P10, section notes и missing vectors 11–14, а не
отдельные H/M finding IDs; ниже сохраняются именно эти идентификаторы.

| ID | Disposition |
|---|---|
| P1 M | REVISED §2: server-side allowlist accepted explicit mutations only; polling/reads/errors не activity; vectors 1/11 |
| P2 L | REVISED: fixed absolute 12h, без 7d UI bound/knob; tests 2/3 |
| P3 L / §2.3 random ambiguity | REVISED: все токены random 128-bit, SHA-256 stored; HMAC alternative удалена |
| P4 L | REVISED: local issuance ДО admin, 600s fixed; permanent bootstrapConsumed atomic; vector 5 |
| P5 L | REVISED: session+generation+protection state, one-use; consume/helper recheck; vector 6 |
| P6 M | REVISED §4: no account-wide unauthenticated lockout; per-peer bucket + bounded global concurrency; остаточный NAT/distributed DoS явно не скрыт; vectors 9/12 |
| P7 backup-live | BLOCKED decision §6: A/B альтернативы; новая BackupMetadata не вводится; affected schema/GC запрещены до решения |
| P8 H | WITHDRAWN: 30d draft compaction default и UI knob удалены; retention deletion OFF |
| P9 H | WITHDRAWN: six-month audit deletion и UI knob удалены; OFF, product consent сейчас не запрашиваем |
| P10 | RETAINED fixed 60s auth-record sweep; не GC данных/истории |
| §2 clock persistence | REVISED §3: persistent high-water mark, restart revoke before auth, snapshot rollback tests 4/14/16 |
| §2.4 crash semantics | CORRECTED §5: transaction rollback vs durable commit, никаких частичных delete/audit gap; journal pins не снимаются по факту crash |
| Vector 7 audit stub | 03 подтверждает отсутствие SecretRef в AuditEvent; это принято как пояснение, но compaction/stub replacement больше НЕ предлагается |
| Missing vectors 11–14 | ADDED §8 ровно с этими номерами; disk-full negative дополнительно 15; snapshot restore 16 |
| Configurable settings surface | WITHDRAWN: только fixed PROPOSED constants, никакого admin UI/settings расширения |

## 10. Remaining decision points / routing

1. Chief Architect/01: выбрать A или B backup-live semantics; A рекомендована, не
   принята. До этого затронутые schema/GC BLOCKED, а не A04 Done.
2. 03/01: принять/скорректировать proposed activity allowlist, auth restart revocation,
   P6 admission constants и disk-pressure floor. Это security-contract review,
   не согласование новой UI настройки или recovery-функции.
3. Distributed login-flood availability/NAT tradeoff требует проверки и acceptance;
   bounded admission не доказывает гарантированной доступности нового login.
4. History/backup deletion policy отдельно не расширяем и не запрашиваем сейчас:
   P7/P8/P9 OFF. Если понадобится — отдельное продуктово-архитектурное решение.

## 11. Evidence and checks

Локальные источники: `.hyper/tmp/t005/T005-A04-review-REPORT.md` (03, target 427a9de),
`specs/001-selected-connections/research.md` R-05/R-06,
`data-model.md` Admin/Session/Secret/ConfigRevision/AuditEvent/BackupEnvelope и
«Удаление и восстановление», contracts/control-plane.md и network-agent.md,
spec FR-019/021. Не выдаем чужие review checks за собственные runtime tests.

| command | exitCode | executedAt UTC | artifactPath / result |
|---|---|---|---|
| git log --oneline -3; git status --porcelain; git show -s --format='%H parent %P' HEAD | 0 | 2026-10-23 (начало revision turn; точное время не фиксировалось) | tool output: HEAD 427a9de, clean; parent 5774d00 |
| sed -n '30,110p' .hyper/tmp/t005/T005-A04-review-REPORT.md | 0 | 2026-10-23 (точное время не фиксировалось) | review findings/vectors, local stdout |
| cat specs/001-selected-connections/contracts/control-plane.md; cat specs/001-selected-connections/data-model.md; date -u +%FT%TZ | 0 | 2026-10-23T19:59:28Z | local stdout, source semantics checked |
| runtime/unit/security/GC/session tests | NOT_RUN | — | proposal only; no implementation fixtures/commands established here |

Post-edit diff-check, staged-scope check и immutable commit/parent приводятся в
completion report после исполнения. Эта запись не предсказывает их результат.

## 12. Consent-record disposition

T005-A04-consent-record: записан input ID и точный scope (§0); P1/P2 policy,
restart re-login и допустимость ограничения нового login под LAN DoS отмечены
USER-ACCEPTED. Все остальные defaults/mechanics остаются PROPOSED; blanket-статус
«все PROPOSED» заменен только в пределах согласия. UX preservation — обязательное
условие до UI; механизм не выбран и не реализован. Backup A/B не выбран,
automatic deletion не разрешена, backup-live schema/GC BLOCKED.

Дополнительная будущая проверка (NOT_RUN): несохраненные правки переживают expiry,
re-login и control-plane restart без неразрешенного secret persistence/утечки и без
обхода auth; при отсутствии согласованного механизма затронутая UI реализация BLOCKED.
Это acceptance requirement, не создание нового endpoint или browser storage feature.

**A04 OPEN; APPROVED/Done не присваивается.** USER-ACCEPTED только scope §0;
остальные параметры PROPOSED; readiness, clock recovery, disk-full behavior,
race safety и защита несохраненных правок пока не испытаны.
