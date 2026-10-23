# Xray: transparent inbound и границы маршрутизации

Статический анализ snapshot 1b1647cd9ddf0abc34b981d4611fc03bcac1ca74, не выбранного production-релиза. База: https://github.com/XTLS/Xray-core/tree/1b1647cd9ddf0abc34b981d4611fc03bcac1ca74 . Код не запускался; runtime NOT_RUN.

## Имена и исходное назначение
- infra/conf/xray.go:29 регистрирует `tunnel` как DokodemoConfig. Поэтому protocol=tunnel в исследованном PassWall не означает TUN device, а является конфигурационным именем обработчика dokodemo.
- infra/conf/xray.go:207 связывает FollowRedirect с ReceiveOriginalDestination; app/proxyman/inbound/always.go:102–109 включает получение original destination, задавая Redirect, если Tproxy еще не выбран.
- app/proxyman/inbound/worker.go:69–78 различает TCP Redirect (tcp.GetOriginalDestination) и TProxy (conn.LocalAddr). Следовательно, подмена destination NAT до transparent listener должна оцениваться совместно с выбранным режимом; нельзя механически заменить TPROXY на обычный DNAT и ожидать того же original destination.
- proxy/dokodemo/dokodemo.go:113–139 берет валидный Target из outbound context при FollowRedirect; без валидного назначения возвращает ошибку. Этот inbound не восстанавливает магически домен из IP.

## UDP и привилегии
transport/internet/sockopt_linux.go:212–224 устанавливает IP_TRANSPARENT для включенного Tproxy; для UDP original destination пытается включить IPV6_RECVORIGDSTADDR и IP_RECVORIGDSTADDR, возвращая ошибку, если обе операции не удались. transport/internet/udp/hub_linux.go:13–30 извлекает адрес/порт из IPv4/IPv6 ancillary data. Это поддержка в коде, не доказательство достаточных прав или модулей конкретной Ubuntu.

proxy/dokodemo/dokodemo.go:160–201 при overridden destination использует FakeUDP, привязанный к адресу назначения, для ответа клиенту; передает mark из sockopt. Обычный UDP writer применяется при отсутствии overridden destination. Следовательно, обратный transparent UDP-путь требует отдельной проверки source address, маршрута, прав и conntrack, а не только успешного входящего пакета. Потребность в IP_TRANSPARENT не означает необходимость выдавать root всей Web UI; минимальные привилегии сетевого процесса проектируются отдельно.

## Отсутствующий маршрут, отсутствующий outbound и недоступный сервер — три разных случая
app/dispatcher/default.go:443–517:
1. Forced outbound tag отсутствует → закрыть/прервать link и вернуть управление.
2. Router вернул tag, но handler отсутствует → закрыть/прервать link. В коде явно запрещен переход на default в этом случае.
3. PickRoute вернул ошибку (включая отсутствие совпадения) → если handler не выбран, взять default handler. Если default отсутствует — закрыть link.
4. Выбранный handler получает Dispatch. В прочитанной функции нет повторного выбора direct после сбоя upstream; полный failure-контракт протокольного outbound этим не доказан.

Следствие: нельзя обобщать «любая ошибка маршрутизации блокирует поток». Ошибка выбора маршрута может перейти к default. При direct-default нужен контроль корректности/готовности правил и классификации, а не надежда на отсутствие handler. И наоборот, отсутствие выбранного outbound не следует описывать как автоматический прямой fallback.

## Порядок Xray routing
app/router/router.go:201–232 обходит rules по порядку и возвращает первое совпавшее. Для IpOnDemand может подключить DNS context до прохода; для IpIfNonMatch повторяет проход после DNS при наличии домена и разрешенном resolve. SkipDNSResolve защищает от определенного цикла DNS. Это не универсальная защита всех bootstrap-петель внешнего DNS/роутера.

Следствие для генерации: завершающее широкое direct-правило, совпавшее на первом проходе, не оставляет этап «ни одно правило не совпало» для IPIfNonMatch. Нельзя обещать, что IP-правила всегда будут проверены по разрешенному домену только из-за выбора этой стратегии. Нужно проверять конкретную последовательность и наличие sniffed domain/исходного IP.

## Что проверять до утверждения генератора
- TCP original destination отдельно для REDIRECT и TPROXY, UDP ancillary destination и ответы IPv4/IPv6.
- Ошибки socket options/прав не маскируются под успешно работающий listener.
- Совпадение домена, IP, обоих, отсутствие домена, shared IP, зашифрованный ClientHello/неподдержанный sniffing.
- Первый match, catch-all default и взаимодействие с IPIfNonMatch.
- Ошибка PickRoute, отсутствующий outbound tag, недоступный upstream — отдельные сценарии.
- При пустой/неготовой классификации выбранные proxy-направления не должны незаметно уходить в direct. Как это обеспечить при недоступном DNS — еще задача архитектуры, не доказанное свойство PassWall/Xray.

Вывод: engine предоставляет transparent TCP/UDP-механизмы и предсказуемые отдельные ветки ошибок, но сам по себе не обеспечивает всю LAN-политику отказа. Firewall/DNS/readiness и жизненный цикл конфигурации остаются частью контракта Raylane.
