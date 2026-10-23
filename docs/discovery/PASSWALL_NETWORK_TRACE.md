# PassWall: трассировка сетевого пути и IPv6

Статический анализ официального snapshot 409d28cc7d7d2d806039bf03f7ebf4724c03ea99. Никакие скрипты не запускались, сеть не менялась. Ниже факты референса, НЕ новые решения продукта. Отмененная карточка IPv6 не является выбором пользователя.

База ссылок: https://github.com/Openwrt-Passwall/openwrt-passwall/tree/409d28cc7d7d2d806039bf03f7ebf4724c03ea99/luci-app-passwall . Пути ниже относительно этой директории.

## 1. UI → переменные запуска
- luasrc/model/cbi/passwall/client/other.lua:125–151: при доступности модулей форма предлагает TCP REDIRECT/TPROXY; IPv6 TProxy — отдельный флаг, default=0, с experimental-предупреждением. При IPv6 TProxy форма предлагает только TCP TPROXY. Это ограничение формы, не доказательство принудительной нормализации любого импортированного UCI.
- root/usr/share/passwall/app.sh:1838–1881: TCP_PROXY_WAY читается с fallback redirect, PROXY_IPV6 — из ipv6_tproxy с fallback 0. FILTER_PROXY_IPV6 отдельно читается из filter_proxy_ipv6 с fallback 0. Следовательно, выключение IPv6 TProxy само по себе не включает DNS-фильтрацию IPv6.
- Там же: CLIENT_PROXY и LOCALHOST_PROXY раздельны, оба с fallback 1. Уже выбранное исключение обычного трафика Ubuntu (D-057) отличается от fallback localhost_proxy референса, но соответствует наличию отдельного управления этой областью.

## 2. Firewall → policy routing → Xray
Ветка nftables, root/usr/share/passwall/nftables.sh:
- :46: FWMARK=0x50535731. :138–145: TPROXY/TPROXY6 ставят эту метку и направляют пакет на локальный порт (для IPv6 `tproxy ip6 to :port`).
- :162–166: отдельные prerouting hooks для NAT и mangle. Это не один лишь default route на машину: перехват требует правил firewall и принимающего transparent listener.
- :1226–1227: IPv4 policy rule по метке, таблица 999, local route через lo.
- :1230–1245: IPv6-цепочки исключают LAN6, VPS6, reply direction; OUTPUT также учитывает block/direct sets и пропускает mark с младшим байтом 0xff.
- :1265–1273: только при PROXY_IPV6=1 подключаются IPv6 prerouting/output chains, исключается WAN6, добавляются `ip -6 rule ... table 999 priority 999` и `ip -6 route add local ::/0 dev lo table 999`.
- Это не равнозначно запрету всех IPv6-пакетов при выключенном флаге. Вывод ограничен этой веткой: IPv6 TProxy jump и policy route не включаются. Остальные firewall/DNS-правила нужно учитывать отдельно.

Генератор luasrc/passwall/util_xray.lua:1649–1687:
- В ЭТОМ snapshot inbound называется `tunnel`, а не автоматически предполагаемый по старым версиям `dokodemo-door`.
- followRedirect=true; отдельные tcp_redir/udp_redir на redir_port. TCP получает выбранный tcp_proxy_way; UDP сохраняет tproxy.
- Sniffing включается условно: override_dest либо shunt; HTTP/TLS/QUIC, routeOnly и FakeDNS зависят от параметров. Нельзя считать распознавание домена включенным/надежным для любого потока.
- :166–169 обычный outbound sockopt содержит mark=255, что связано с исключением 0xff в OUTPUT. Это не та же метка, что FWMARK для доставки inbound.

## 3. DNS-фильтр IPv6 — другая функция
- luasrc/model/cbi/passwall/client/global.lua:222–223 и acl_config.lua:332–333: отдельный filter_proxy_ipv6, default=0.
- app.sh:1875–1881: direct и remote query strategy изначально UseIP; FILTER_PROXY_IPV6=1 меняет REMOTE_DNS_QUERY_STRATEGY на UseIPv4 и задает DNSMASQ_FILTER_PROXY_IPV6.
- Разные DNS-ветки дополнительно меняют DNSMASQ_FILTER_PROXY_IPV6 (например :657,741,1158,1201). Полная цепочка dnsmasq/chinadns-ng/smartdns/Xray еще не прочитана; нельзя объявлять эти две строки универсальным способом блокировки AAAA.
- Ограничение DNS-ответов само по себе не доказывает отсутствие обхода через literal IPv6, кэш или сторонний DoH. Это граница механизма, не результат сетевого теста.

## 4. Что это означает для Ubuntu с одним NIC
PassWall устанавливает эти правила на самом OpenWrt-роутере. Raylane будет на отдельной машине: доставка пакетов от роутера и обратный путь — дополнительная часть схемы, которой не заменяет копирование скрипта. Сохранение IPv6-переключателя как возможности референса можно оценивать лишь вместе с IPv6-доставкой трафика на Ubuntu; выключение IPv6 на всех устройствах не следует из устройства PassWall.

Технический кандидат для исследования — Linux nftables + policy routing + transparent Xray listener по образцу этой ветки. Это НЕ выбор реализации. Перед переносом нужны анализ конфликтов меток/таблиц, привилегий, исключений upstream, IPv6 next-hop/RA и обратного пути, без переноса UCI/ubus/fw4-зависимостей как зависимостей продукта. Нельзя копировать фиксированные mark/table 999 без проверки окружения.

## 5. Следующее чтение, без продуктовой анкеты
1. Проследить DNS-ветки и наполнение IPv4/IPv6 sets из доменных списков.
2. Проследить порядок direct/proxy/block и fallback на уровне firewall и shunt Xray.
3. Разобрать запуск/остановку/аварийный выход: наличие правил при остановленном Xray и соответствие D-055. Не считать поведение штатного stop доказательством поведения при crash.
4. Сопоставить зависимости OpenWrt с Linux-механизмами и представить схему одного NIC с явно обозначенными непроверенными местами.

Результат: установлена связка UI → config → nftables/policy routing → Xray inbound и отдельно начальная ветка DNS IPv6. Полное исследование сетевого пути еще не завершено; runtime NOT_RUN.
