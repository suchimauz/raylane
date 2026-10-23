# Spec Kit Analyze — document-only, implementation NOT RUN

Проверены spec.md, plan.md, research.md, data-model.md, contracts/, quickstart.md, tasks.md и constitution. prerequisites с --require-tasks --include-tasks успешно определил feature. Hooks отсутствуют. Анализ не меняет требования и не запускает задачи; этот отчет — единственный выход этапа анализа.

## Findings
| ID | Severity | Место | Наблюдение | Действие до реализации |
|---|---|---|---|---|
| A01 | HIGH | research R-07 vs FR-014/023 | Предложены запрет credentials-in-URL и особые ограничения LAN источников; это дополнительные пользовательски видимые ограничения, прямо не принятые D-060 | Не считать их утвержденным scope. Согласовать либо переработать контракт загрузчика так, чтобы защита SSRF не молча исключала разрешенные источники. T024 блокируется до решения |
| A02 | HIGH | plan G1/research R-01 | Точный dependency/release provenance еще не закреплен; source tag сам по себе не security assurance | T001 — обязательный предшественник runnable baseline. Plan остается conditional; не объявлять все research unknowns resolved |
| A03 | HIGH | plan IPv6 profile vs FR-020 | VLAN — выбранный технический путь с дополнительной precondition инфраструктуры, но работоспособность не доказана | T028–T029 должны подтвердить профиль. Невозможность VLAN на целевом окружении требует alternative design, не удаления IPv6. Полная приемка блокируется |
| A04 | MEDIUM | data-model retention / R-06 | Retention policy и session expiry описаны без конкретных длительностей | В T005/T007/T008 закрепить bounded defaults в схемах/security contract, покрыть expired-session/secret retention tests до реализации соответствующих операций |
| A05 | MEDIUM | tasks T001,T028,T038 | Часть задач шире одного короткого агентного изменения | 01 при реализации должен выдавать bounded subtasks в рамках тех же IDs/base commits, не смешивать research/implementation/acceptance в один PASS |
| A06 | LOW | spec scenario order | Нет утвержденных бизнес-приоритетов историй | Использован технический порядок зависимостей и первый demonstrable slice, не выдуманы P1/P2 как выбор пользователя |
| A07 | LOW | quickstart | Продуктовые команды еще не исполнимы, явно помечены planned | T037 обязан заменить их проверенным clean-install guide; отсутствие runtime сейчас не скрывать |

## Coverage — все 23 FR имеют будущие задачи
| FR | Tasks |
|---|---|
| 001–008 | T001,T010–T014 |
| 009–010 | T006,T011–T017 |
| 011–013 | T019–T023 |
| 014–015 | T024–T027 |
| 016–017 | T028–T034,T037 |
| 018 | T009,T013,T017,T023,T027,T033,T035 |
| 019 | T007–T008,T018,T025,T035 |
| 020 | T028–T034,T035 |
| 021 | T008,T015–T018,T032,T035,T037 |
| 022 | T021,T024–T027 |
| 023 | T022,T024–T027,T031,T035 |

SC-001→T001/T010/T014, SC-002→T016/T022/T027, SC-003→T019–T023, SC-004→T011/T012/T021, SC-005→T025/T029/T032, SC-006→T007/T018/T025/T035, SC-007→T034/T037. Покрытие означает наличие назначенной проверки, не ее успешное выполнение.

## Формат и зависимости
38 уникальных unchecked задач: setup 4, foundation 5, US1 4, US2 5, US3 5, US4 4, US5 7, final 4. Story labels добавлены в checklist строки; пути конкретны. Зависимости указывают на более ранние tasks, кроме явно указанной полной сетевой приемки US2 после US5, которая не блокирует разработку fake-helper US2. Нет циклического требования «реальный apply для создания helper». Один implementation writer; parallel markers не запускают агентов.

## Constitution / agent governance
Нарушений действующих разрешений выполненными действиями не найдено: текущее действие только документы; 01–05 не запускались. Требование независимого review/evidence отражено в будущих task packets. Scope не должен расширяться через security proposal A01 без решения. Секреты/частные адреса не добавлены. Нельзя обходить G1–G4 для ускорения релиза.

## Result
**Документы plan/tasks/analyze подготовлены; IMPLEMENTATION HOLD.** 0 CRITICAL, 3 HIGH, 2 MEDIUM, 2 LOW. Высокие пункты не скрыты: A01 требует согласования/корректировки контракта, A02/A03 — явные проверочные gates до соответствующего выполнения/приемки. Нет разрешения на запуск команды, продуктовый код, privileged tests, live deployment или push. Рекомендуемый следующий шаг — закрыть A01 и технические параметры A04 в документах; затем отдельное разрешение на controlled implementation с gate T001/T028–T029, не объявляя готовой сетевую архитектуру заранее.
