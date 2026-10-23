# Phase 0 — технические решения плана

Статус: DESIGN PROPOSAL, без запуска кода и сети. Основание: spec FR-001–023, D-058–060 и статические исследования в docs/discovery. Продуктовые требования не изменяются. Выборы ниже — решения предлагаемого технического плана, не результаты испытаний.

## R-01 — стек и границы runtime
**Decision:** самостоятельный Go control-plane и небольшой Go privileged helper; React/TypeScript UI, SQLite для одного экземпляра приложения; Xray как отдельный процесс. Hyper/Bun/Postgres — среда работы агентов, НЕ обязательная зависимость Raylane. Linux systemd — целевой менеджер служб. Базовая ОС для первого стенда Ubuntu 24.04 LTS amd64; совместимость других версий не обещается до проверки.
**Rationale:** HTTP/control-plane и привилегированную часть можно разделить по пользователям/сокетам; SQLite достаточно для single-host single-admin, не требует отдельного сервиса. Go предоставляет типизированные модели, тесты и управляемые бинарники; UI отделен от привилегий.
**Alternatives:** Bun/TS backend уменьшает число языков, но требует отдельного решения privileged worker; весь backend под root отвергнут; Postgres избыточен для выбранной топологии; Python допустим технически, но не дает преимущества единому статически собираемому helper.
**Version gate:** production-версия Xray и точные Go/Node/dependency pins НЕ установлены исследованием snapshots. До первого runnable baseline 05 выбирает поддерживаемые releases с лицензиями/checksums и capability matrix, 03 проверяет, 01 фиксирует lock/manifests. Не ставить latest и не выдавать исследовательский commit за стабильный релиз. Это блокер завершения технического baseline, не скрытый default.

## R-02 — модель сети
**Decision:** проектировать nftables + TPROXY + policy routing, не TUN. Разделить dataplane gate, DNS-классификатор и Xray; direct-классифицированный трафик обходит Xray на уровне kernel forwarding, proxy — transparent listener. IPv6 отдельный выключенный переключатель по FR-020.
**Rationale:** максимально близко к прочитанной nft-ветке PassWall; direct может жить при отказе Xray. Default direct допускается только после готовности классификации, не при пустых/невалидных наборах.
**Alternatives:** весь direct через Xray связывает direct-доступ с жизнью движка; REDIRECT TCP требует отдельного UDP/IPv6 пути; TUN не является исследованным listener protocol=tunnel.
**Unproven gate:** доменная классификация при shared IP/DoH и неизвестном имени имеет согласованные ограничения. Не обещать точную доменную идентификацию любого IP-потока. На startup/DNS failure затронутые новые соединения закрываются до readiness; устаревший last-known set не считается автоматически готовым.

## R-03 — один NIC и внешний роутер
**Decision:** эталонный IPv4 стенд использует исключение адреса Ubuntu из policy route роутера и SNAT direct-forwarding на Ubuntu к ее LAN-адресу, чтобы возвращаемый трафик не классифицировался повторно по IP клиента. Это проектный кандидат ручной инструкции, не выполненная настройка. Proxy upstream также идет с адреса Ubuntu. Проверить conntrack/asymmetry/rp_filter/ICMP redirects; не менять sysctl вслепую.
**Alternatives:** VLAN разделяет пути, но требует оборудования/изменения топологии; source-only policy без SNAT/различения второго прохода создает риск петли; метка Linux не переносится на другую машину.
**Gate:** синтетический namespace-стенд должен доказать прямой/обратный пути. Для IPv6 нельзя механически переносить SNAT/NAT66: профиль маршрутов/исключений должен быть отдельно доказан. Пока доказательства нет, IPv6 enable отклоняется с причиной, не включается частично; это временный implementation gate, не удаление требования IPv6 из scope. До закрытия IPv6 gate релиз полного scope не принимается.

## R-04 — DNS и готовые списки
**Decision:** отдельный dnsmasq экземпляр с проверенной nftset-поддержкой, local direct resolver и локальный proxy DNS forwarder через Xray. Ни прямой публичный DNS, ни URL списков не зашиты как доверенные defaults. Resolver endpoints администратор задает явно; readiness требует валидной настройки. Списки компилируются из проверенного черновика в версионированный snapshot; DNS-ответы наполняют sets этого поколения. UI показывает источник/поколение/готовность.
**Rationale:** соответствует прочитанной dnsmasq-ветке PassWall. DNS клиентов к роутеру требует отдельной ручной forwarding/DHCP-инструкции, не покрывается WAN policy сам по себе.
**Alternatives:** SmartDNS/ChinaDNS-NG — альтернативы референса, не нужны все одновременно; один sniffing не решает скрытые домены. Backend adapter позволяет заменить resolver позднее без изменения доменной модели.
**Gate:** проверить фактическую семантику TTL/кэша и shared-IP overlap до сетевой приемки; отдельно IPv6 filter и TPROXY. DNS failure закрывает затронутую новую сессию; local management остается доступным.

## R-05 — сохранение, применение, восстановление
**Decision:** immutable revision, SQLite-транзакция сохранения, optimistic concurrency по revision; применение сериализовано. Сначала snapshot/validation, затем protective gate, подготовка resolver/engine, атомарная загрузка nft batch там, где возможна, health/readiness, запись active revision. Межпроцессная операция НЕ объявляется атомарной: durable journal и reconciliation после crash.
**Rationale:** нельзя копировать stop PassWall, удаляющий защиту. Helper хранит последний active/gate manifest вне жизненного цикла Web UI/Xray. Неудача вызывает возврат последней рабочей версии; ошибка возврата оставляет gate закрытым и управление доступным.
**Alternatives:** немедленное применение каждого поля нарушает spec; rollback только в памяти не переживает crash. Отдельное действие release-protection имеет подтверждение, audit и предупреждение.

## R-06 — безопасность
**Decision:** LAN HTTPS, same-origin UI/API, одна admin role. Первичная настройка через локальную консоль и одноразовый короткоживущий токен, доступ к bootstrap только loopback/защищенный локальный канал. Password hashing Argon2id через проверенную библиотеку, серверные sessions с Secure/HttpOnly/SameSite cookie, CSRF/origin checks, idle/absolute expiry, rate limits. Пароль/токен не выводятся в журналы. HTTP bootstrap не публикуется в LAN.
**Secrets:** отдельный root/service-readable master key, AEAD secret store; ключ не в БД/экспорте. Копия шифруется отдельной вводимой пользователем passphrase с версионированным KDF/envelope; passphrase не хранится, утрата предупреждается. Диагностический экспорт allowlist, не blacklist. Backup restore проверяет формат/размер/version и создает draft.
**Privilege:** Web UI/API без root; Unix socket к helper с peer-credentials и строго типизированными операциями, без arbitrary shell, arbitrary paths и JSON Xray от клиента напрямую. Helper принимает скомпилированный/проверенный manifest ограниченного формата и контролирует свои каталоги/ресурсы.

## R-07 — загрузки и идентичность
**Decision:** single-flight per source, bounded parser/fetch worker, immutable candidate и транзакционный commit. Стабильный source ID имеет приоритет; иначе fingerprint canonical protocol+endpoint+transport/security/auth params, без имени и локальных параметров. Использовать keyed digest для секретосодержащих полей; не публиковать fingerprint или credentials. Точный список полей версионируется по протоколу, смена версии требует migration/reconciliation preview, не автоматической потери ссылок.
**Proposed baseline limits:** загрузка 10 MiB после decompression, 60 s общий deadline, 10 s connect, 5 redirects, максимум 2 повтора только временных transport/5xx ошибок, один выполняемый update/source. JSON/YAML nesting ≤32, 10 000 узлов/источник. 4xx, parse/TLS errors без автоматического insecure retry. Значения — технические параметры плана для проверки нагрузкой, не обещание производительности.
**URL security:** только http/https, запрет credentials-in-URL для новых URL, секреты через отдельные поля. Проверять каждый redirect, не копировать auth/cookies на другой origin, reject metadata/link-local/loopback destinations; явно разрешаемые администратором LAN sources проверяются отдельным allowlist, защита от DNS rebinding должна учитывать фактический endpoint/proxy DNS. Если выбранный proxy не позволяет гарантировать policy, отказ, не обход. Не добавлять внешние источники без явного выбора.

## R-08 — работа существующих агентов
**Decision:** 01 orchestration, 02 implementation, 03 independent technical/security review, 04 independent tests/evidence, 05 research/capability contracts. Номера/роли подтверждены runtime discovery, агенты idle на момент подготовки. Их не запускали и контекст не изменяли. Детальный порядок в plan; tasks.md создается отдельно через speckit.tasks.
**Rationale:** один implementation writer снижает конфликты; 03/04 не заменяются самооценкой 02. Исследование 05 закрывает version/network gates, не меняет product requirements самостоятельно.


## Самостоятельное уточнение baseline перед tasks
Локальный git describe/tag --points-at подтвердил v26.10.21 на исследованном Xray commit 1b1647cd9ddf0abc34b981d4611fc03bcac1ca74; go.mod содержит go 1.27. Этот source baseline выбран для воспроизводимого первого компилятора. Release provenance и бинарные checksums не проверены: packaging gate обязателен. Выбор Go 1.27 family, Node 22 LTS family и React 19 family определяет совместимость архитектуры; exact patch locks создаются до первого runnable baseline и проверяются независимо. Не записывать выдуманные hashes/versions в план.

IPv6 path design: отдельный logical transit VLAN через тот же NIC, ручной router policy по ingress клиента с исключением return transit. Это избегает требования NAT66; доступность подходящего switch/router — проверяемая precondition. IPv6 gate включает этот профиль; если не поддержан, нужна корректировка профиля или явное ограничение развертывания, а не молчаливое снятие защиты. Архитектурная гипотеза выбрана, но подтверждение остается за изолированным тестом.

Команда 01–05 используется только при реализации. До нее текущий агент готовит документы самостоятельно; задачи gate в tasks — будущие задания, не dispatch сейчас.
