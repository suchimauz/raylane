# Первичный обзор PassWall

UNDER_RESEARCH. Исследован только структурный обзор, не полный каталог полей. Установленная у пользователя версия неизвестна. PassWall2 не исследован и не смешивается с PassWall.

Источник: commit 409d28cc7d7d2d806039bf03f7ebf4724c03ea99; Makefile указывает 26.10.22, release 2. Это версия исследуемого снимка, НЕ установленная версия пользователя.

[Меню и маршруты LuCI](https://github.com/Openwrt-Passwall/openwrt-passwall/blob/409d28cc7d7d2d806039bf03f7ebf4724c03ea99/luci-app-passwall/luasrc/controller/passwall.lua) подтверждают разделы: основные настройки, узлы, подписки, прочие настройки, балансировка (при наличии haproxy), обновления компонентов, управление правилами/списки правил, контроль доступа, журналы, серверная часть. В global.lua подтверждены вкладки Main, DNS, Proxy, log, FAQ, Maintain.

| Область | Исходник для углубленного исследования |
|---|---|
| Основные настройки, DNS, режимы проксирования, журнал | [исходник](https://github.com/Openwrt-Passwall/openwrt-passwall/blob/409d28cc7d7d2d806039bf03f7ebf4724c03ea99/luci-app-passwall/luasrc/model/cbi/passwall/client/global.lua) |
| Узлы и поля узлов | [исходник](https://github.com/Openwrt-Passwall/openwrt-passwall/blob/409d28cc7d7d2d806039bf03f7ebf4724c03ea99/luci-app-passwall/luasrc/model/cbi/passwall/client/node_config.lua) |
| Подписки | [исходник](https://github.com/Openwrt-Passwall/openwrt-passwall/blob/409d28cc7d7d2d806039bf03f7ebf4724c03ea99/luci-app-passwall/root/usr/share/passwall/subscribe.lua) |
| Маршрутизация и разделение трафика | [исходник](https://github.com/Openwrt-Passwall/openwrt-passwall/blob/409d28cc7d7d2d806039bf03f7ebf4724c03ea99/luci-app-passwall/luasrc/model/cbi/passwall/client/shunt_rules.lua) |
| Контроль доступа | [исходник](https://github.com/Openwrt-Passwall/openwrt-passwall/blob/409d28cc7d7d2d806039bf03f7ebf4724c03ea99/luci-app-passwall/luasrc/model/cbi/passwall/client/acl_config.lua) |
| Балансировка HAProxy | [исходник](https://github.com/Openwrt-Passwall/openwrt-passwall/blob/409d28cc7d7d2d806039bf03f7ebf4724c03ea99/luci-app-passwall/root/usr/share/passwall/haproxy.lua) |
| Автопереключение SOCKS | [исходник](https://github.com/Openwrt-Passwall/openwrt-passwall/blob/409d28cc7d7d2d806039bf03f7ebf4724c03ea99/luci-app-passwall/root/usr/share/passwall/socks_auto_switch.sh) |
| Генератор Xray | [исходник](https://github.com/Openwrt-Passwall/openwrt-passwall/blob/409d28cc7d7d2d806039bf03f7ebf4724c03ea99/luci-app-passwall/luasrc/passwall/util_xray.lua) |
| Сетевая интеграция | [исходник](https://github.com/Openwrt-Passwall/openwrt-passwall/blob/409d28cc7d7d2d806039bf03f7ebf4724c03ea99/luci-app-passwall/root/usr/share/passwall/nftables.sh) |
| Запуск и системная интеграция | [исходник](https://github.com/Openwrt-Passwall/openwrt-passwall/blob/409d28cc7d7d2d806039bf03f7ebf4724c03ea99/luci-app-passwall/root/usr/share/passwall/app.sh) |

[Makefile](https://github.com/Openwrt-Passwall/openwrt-passwall/blob/409d28cc7d7d2d806039bf03f7ebf4724c03ea99/luci-app-passwall/Makefile) показывает зависимости от Lua, UCI, LuCI, dnsmasq-full, chinadns-ng, ip-full и прочих компонентов. В root/usr/share/passwall есть iptables.sh, nftables.sh, 0_default_config и DNS helpers. Наличие файла не доказывает семантику всех его настроек.

## Переносимость — предварительная оценка
Семантика узлов и правил потенциально переносима; точные поля еще исследуются. UCI/LuCI и init/firewall/DNS-интеграция OpenWrt требуют отдельной реализации для Ubuntu. Нельзя запускать shell-скрипты PassWall на Ubuntu как готовое решение. Лицензирование кода проверить перед любым заимствованием: Makefile указывает GPLv3.

## PROPOSED: порядок
Версия → узлы и используемые протоколы → подписки → маршрутизация и режимы → DNS → группы/переключение/балансировка → ACL и вспомогательные функции → Ubuntu networking и отказы → стек и UI → критерии приемки. Сетевые ограничения уточнять параллельно при выборе функций.

## Установленная версия — проверено по SSH тестового роутера
По явному разрешению пользователя выполнено только чтение списка пакетов и /etc/openwrt_release:
- luci-app-passwall: 25.12.19-r1 (PassWall, не PassWall2).
- xray-core: 25.12.8-r1.
- OpenWrt: 24.10.4, r28959-29397011cc, target mediatek/mt7622.
Настройки, секреты и подписки не читались; изменений на роутере нет.
Предыдущий обзор commit 409d28cc7d7d2d806039bf03f7ebf4724c03ea99 относится к более новой версии и не подтверждает наличие ее функций в установленной 25.12.19-r1. Следующий шаг: установить соответствие установленного пакета исходникам/commit; не считать номер версии доказательством отсутствия патчей сборки.

## Актуализация области исследования
CONFIRMED пользователем: исследовать современный официальный PassWall без обязательной привязки к установленной версии. Используем уже зафиксированный commit 409d28cc7d7d2d806039bf03f7ebf4724c03ea99 (26.10.22, release 2). Поиск точного commit установленного пакета больше не блокирует исследование. Преимущества новых возможностей требуют проверки и согласования; роутер не обновляем.

## Узлы: первый проход по форме Xray
Источник: тот же фиксированный commit 409d28cc7d7d2d806039bf03f7ebf4724c03ea99, luci-app-passwall/luasrc/model/cbi/passwall/client/node_config.lua и client/type/2_xray.lua, строки 1–61.
- node_config.lua содержит общие remarks и group, а типы загружает из client/type/. Группа здесь — именованная организация узлов, не доказательство балансировки.
- Форма Xray доступна при api.finded_com("xray"). Предлагает socks, http, vmess, vless, shadowsocks, trojan, wireguard, hysteria2, masque.
- _balancing, _shunt, _iface — специальные режимы узлов (балансировка, разделение трафика, интерфейс), а не протоколы подключения к серверу.
- В util_xray.lua найдены отдельные ветви обработки WireGuard, Hysteria2 и MASQUE. Наличие опции в форме не доказывает поддержку любой версией Xray; совместимость версий и полная генерация еще UNDER_RESEARCH.
- TLS/REALITY и транспорт следует исследовать отдельно от протокола; перечень полей еще не завершен.
OPEN_QUESTION: какие протоколы и сочетания транспорта/защиты пользователь хочет сохранить. Ни один не утвержден и не исключен.

## Сверка с исходниками Xray-core (без запуска)
Снимок официального Xray: 1b1647cd9ddf0abc34b981d4611fc03bcac1ca74, https://github.com/XTLS/Xray-core/tree/1b1647cd9ddf0abc34b981d4611fc03bcac1ca74 . Это исследовательский HEAD, не утвержденная production-версия и не подтвержденный стабильный релиз.
- infra/conf/transport_internet.go:48–132 подтверждает streamSettings.method, приоритет method над network, default tcp. REALITY допускает только RAW/TCP, XHTTP и gRPC; WS и HTTPUpgrade отвергаются. В форме выбранного PassWall переключатель REALITY для них показывается. Это подтвержденное несовпадение UI/engine, не основание молча менять поведение продукта.
- infra/conf/vless.go:245–340 подтверждает сокращенные settings.address/port/id/encryption/flow; ID проходит uuid.ParseString, разрешенные flow: пустое, Vision, Vision-udp443. encryption имеет расширенный формат mlkem768x25519plus; полный валидатор еще исследовать.
- infra/conf/socks.go:76–143 и http.go:58–132 подтверждают сокращенные settings.user/pass. Учетная запись создается только при непустом user: пароль без имени сам по себе не включает авторизацию.
- proxy/socks/client.go:87 использует socks5Version; это SOCKS5 outbound, не доказательство поддержки SOCKS4 outbound.
- infra/conf/wireguard.go:17–132: allowedIPs при отсутствии → 0.0.0.0/0 и ::0/0; MTU 0 → 1420; reserved допускает только 0 или 3 байта; noKernelTun поддерживается. Отсутствующее address имеет fallback engine; не превращать его в желаемый default продукта.
- Отдельный PassWall type=Socks (client/type/0_socks.lua) зависит от ipt2socks, имеет address/port/username/password и не является формой Xray/SOCKS. Перенос на Xray — отдельное соответствие реализации, а не копирование зависимости ipt2socks.

Все выводы — статический анализ. Сборка, runtime-тесты, обращения к прокси-серверам и изменение сети не выполнялись. Обязательная дальнейшая работа: полный совместимый version matrix engine, импорт/экспорт узлов, обработка скрытых значений LuCI, chained outbound, DNS bootstrap и проверки целостности.

## Подписки — обзор формы, до выбора функций пользователем
Источник: [node_subscribe_config.lua](https://github.com/Openwrt-Passwall/openwrt-passwall/blob/409d28cc7d7d2d806039bf03f7ebf4724c03ea99/luci-app-passwall/luasrc/model/cbi/passwall/client/node_subscribe_config.lua), прочитан целиком. Реализация загрузки/парсинга subscribe.lua пока не прочитана целиком: ниже именно UI и обработчики сохранения.
- Имя подписки обязательно, trim, уникальность без учета регистра, имя default запрещено. Переименование меняет group связанных узлов и node_group балансировщиков/_urltest. Это связь подписки с группировкой, а не просто подпись.
- URL: обязательный TextValue, удаляются пробельные и нулевые символы. Из самого TextValue нельзя заключать поддержку нескольких URL. Ссылки подписки могут содержать секреты.
- Настройки DNS адресов импортируемых узлов: Auto/TCP/UDP/DoH; стратегия IPv4/IPv6. Не путать с DNS-загрузкой самой подписки.
- allowInsecure: default 0, пояснение обещает пропуск проверки сертификата, если ссылка узла не содержит параметр. В ранее прочитанной Xray-форме/генераторе эквивалент не найден: это открытый вопрос, не обещанная возможность Xray.
- Фильтры: выключены; discard; keep; discard с приоритетом keep; keep с приоритетом discard; наследовать глобальное (default 5). Семантика сопоставления и регистра требует чтения parser.
- Выбор движка по типам узлов наследует глобальный, варианты зависят от установленных компонентов. Для Hysteria2/Xray форма подписки проверяет Xray >=26.1.13; это не выбор версии для нашего приложения.
- Обновление при первой автоматической загрузке PassWall после boot (default 0); расписание выключено/по дням недели/ежедневно/интервал. Время default 0:00 с timehhmm, интервал 1–24 часа, default 2.
- Получение URL: Auto/Direct/Proxy, default Auto. User-Agent — свободное поле с вариантами, default passwall.
- Цепочки подписки: выключено/preproxy/landing/interface. Кандидаты — обычные узлы Xray/sing-box без цепочки, add_mode !=2 (по описанию ручные или импортированные, не подписочные). Ограничение одним слоем.
- Перед сохранением удаляется md5. Что именно означает этот кеш и когда пересоздаются узлы — еще исследовать.

Все возможности подписок пока UNDER_RESEARCH/OPEN_QUESTION, не CONFIRMED. Автообновление требует Ubuntu-реализации расписания, не переноса OpenWrt cron/init-скриптов. Никакая реальная подписка не запрашивалась.

## Загрузка подписок: Auto/Proxy и проверка TLS
Источники фиксированного PW commit: root/usr/share/passwall/subscribe.lua:1796–1841 и luasrc/passwall/api.lua:343–386. curl выбирает curl_direct/curl_proxy/curl_auto. Proxy использует GLOBAL_SOCKS_server с socks5h, без direct fallback в самой функции. Auto: при localhost_proxy=1 (fallback 1) вызывает curl_base; иначе curl_logic пытается Proxy, затем Direct при ошибке/отсутствии прокси. Поэтому Auto не равен просто «если движок работает, всегда прокси» и зависит от системной интеграции PassWall; перенос этой зависимости на Ubuntu требует отдельного решения.
В subscribe.lua передается -fskL: флаг -k отключает проверку TLS-сертификата источника подписки. Это отдельная TLS-проверка от VLESS tls-полей. Перенос небезопасного поведения не утвержден. Вопрос вынести пользователю, рекомендовать обязательную проверку сертификата. Обнаружение статическое; реальные URL не запрашивались.
