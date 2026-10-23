# Каталог настроек

UNDER_RESEARCH. Выбраны VLESS, SOCKS, HTTP-прокси и WireGuard. Ниже сохранен статический каталог; runtime-проверки и набор расширенных возможностей еще не согласованы.

Для каждого выбранного поля фиксировать: оригинальное имя и UI label; назначение; тип; значения; UI default и фактический runtime fallback отдельно; валидацию UI и backend; условия видимости; зависимости; обработку пустого/отсутствующего значения; путь генерации Xray либо влияние на внешний процесс/firewall/DNS; переносимость Ubuntu; согласованные отклонения; commit, файл и строки источника; статус и нерешенные вопросы. Не все поля обязаны попадать непосредственно в JSON Xray.

## VLESS — первый проход: идентификация, TLS/REALITY (UNDER_RESEARCH)
Источник формы: https://github.com/Openwrt-Passwall/openwrt-passwall/blob/409d28cc7d7d2d806039bf03f7ebf4724c03ea99/luci-app-passwall/luasrc/model/cbi/passwall/client/type/2_xray.lua#L245-L575
Генератор: https://github.com/Openwrt-Passwall/openwrt-passwall/blob/409d28cc7d7d2d806039bf03f7ebf4724c03ea99/luci-app-passwall/luasrc/passwall/util_xray.lua#L109-L202
Таблица фиксирует прочитанные объявления, не законченный контракт. «Не задан» означает отсутствие явного default/validator в данном фрагменте; общие CBI и engine-правила еще проверить. Выбор VLESS не означает утверждение всех транспортов.

| Поле (оригинальная подпись) | Тип / значения / default | Условие и проверка | Назначение / генерация |
|---|---|---|---|
| address (Address (Support Domain Name)) | строка; default не задан | обычный узел; явного datatype нет | Адрес сервера; генератор приводит к lowercase |
| port (Port) | строковое поле порта; default не задан | datatype=port | Порт сервера; полный mapping еще проверить |
| uuid (ID) | скрываемая строка; default не задан | vmess/vless; явной UUID-валидации здесь нет | Идентификатор доступа, обращаться как с секретом; mapping еще проверить |
| encryption (Encrypt Method (encryption)) | строка; default none | VLESS; trim, пустое → none | Не закрытый enum: нельзя самовольно ограничить только none |
| flow (flow) | список: пустое, xtls-rprx-vision, xtls-rprx-vision-udp443; default пустое | VLESS | Режим потока; совместимость с transport/security еще проверить |
| tls (TLS) | flag; default 0 | VLESS и ряд других протоколов | При 1 generator задает stream_security=tls |
| reality (REALITY) | flag; default 0 | tls=true и raw/ws/grpc/httpupgrade/xhttp | При 1 generator заменяет security на reality; текст рекомендует VLESS-TCP-XTLS-Vision, но UI не ограничивается им |
| alpn (alpn) | default, h3, h2, h3,h2, http/1.1, h2,http/1.1, h3,h2,http/1.1; default=default | tls=true,reality=false для VLESS | Протоколы TLS; mapping еще исследуется |
| tls_serverName (SNI Domain) | строка; default не задан | tls=true | TLS/REALITY serverName |
| tls_pinSHA256 (TLS Chain Fingerprint (SHA256)) | строка; default не задан | tls=true,reality=false | tlsSettings.pinnedPeerCertSha256 через api.sha256_sb_xray; отсутствующее/пустое → пустая строка |
| tls_CertByName (TLS Certificate Name (CertName)) | строка; default не задан | tls=true,reality=false | verifyPeerCertByName, fallback пустая строка |
| tls_certificate (TLS Certificate (PEM)) | flag; default 0 | tls=true,reality=false | Включает пользовательский сертификат проверки |
| tls_certificate_pem | многострочный текст; default пустое | tls_certificate=true; trim, нормализация CR/LF, пробелов вокруг переводов строк и повторных переводов | Сохраняет escaped newline; генератор восстанавливает строки, certificates.certificate и usage=verify |
| ech (ECH) | flag; default 0 | tls=true,reality=false | Включает echConfigList |
| ech_config (ECH Config) | многострочный текст; default пустое | ech=true; удаляет CR/LF, trim | tlsSettings.echConfigList |
| reality_publicKey (Public Key) | строка; default не задан | tls=true,reality=true | realitySettings.publicKey |
| reality_shortId (Short Id) | строка; default не задан | tls=true,reality=true | realitySettings.shortId, fallback пустая строка |
| reality_spiderX (Spider X) | строка; placeholder /, не explicit default | tls=true,reality=true | realitySettings.spiderX; отсутствующее → /; пустое в Lua не равнозначно отсутствующему |
| utls (uTLS) | flag; default 0 | tls=true,reality=false | Включает fingerprint для TLS |
| fingerprint (Finger Print) | chrome/firefox/edge/safari/360/qq/ios/android/random/randomized/unsafe; default chrome | tls+utls либо tls+reality | TLS: только при включенном utls и непустом значении; REALITY: fallback chrome |
| cipherSuites (Cipher Suites) | строка со списком через :; default не задан | tls=true,reality=false | tlsSettings.cipherSuites |
| use_mldsa65Verify (ML-DSA-65) | flag; default 0 | tls=true,reality=true | Включает mldsa65Verify |
| reality_mldsa65Verify (ML-DSA-65 Public key) | многострочный текст; default пустое | use_mldsa65Verify=true; убрать CR/LF, trim | realitySettings.mldsa65Verify |
| transport (Transport) | raw/mkcp/ws/grpc/httpupgrade/xhttp; явный default не задан | VLESS и другие | В прочитанном генераторе streamSettings.method=node.transport; не подменять автоматически на network по памяти, проверить версию Xray |

### Переносимость и оставшиеся проверки
Поля описывают узел/движок и не требуют OpenWrt API, но возможность конкретных значений на Ubuntu зависит от версии Xray, а не только ОС. Нужны полный mapping VLESS settings, общая обработка CBI (включая удаление скрытых значений), runtime defaults, совместимость engine, все транспортные поля, mux/XUDP, socket options и дополнительные настройки. Не считать видимость опции доказательством допустимости комбинации в Xray. Не ужесточать молча слабую валидацию PassWall; изменения безопасности обсуждать явно.

## Транспорт VLESS — продолжение первого прохода
Источник UI: client/type/2_xray.lua, строки 599–758; генерация: util_xray.lua, строки 202–275, 300–324. Все пути относительно luci-app-passwall/luasrc в зафиксированном commit выше. Ниже отсутствие explicit default отмечено «—»; placeholder не равен default. Типы Value/DynamicList отражают LuCI, а не утвержденную модель backend.

| Поля / оригинальные подписи | Тип, значения, default, validation | Видимость | Генерация / существенные детали |
|---|---|---|---|
| tcp_guise / Camouflage Type | список none/http; default — | raw | rawSettings.header.type; при none header не создается |
| tcp_guise_http_host / HTTP Host | DynamicList, default — | tcp_guise=http | header.request.headers.Host; общий CBI удаляет дубликаты |
| tcp_guise_http_path / HTTP Path | DynamicList, placeholder / | tcp_guise=http | Каждый пустой путь → /; отсутствующий список → {/} |
| mkcp_guise / Camouflage Type | none/srtp/utp/wechat-video/dtls/wireguard/dns; default — | mkcp | finalmask.udp, mkcp-legacy; wechat-video преобразуется в wechat. wireguard здесь маскировка, не WG-туннель |
| mkcp_domain / Camouflage Domain | Value, default — | mkcp_guise=dns | settings.value DNS-маскировки |
| mkcp_mtu / KCP MTU | Value, uinteger, default 1350 | mkcp | kcpSettings.mtu, fallback 1350 |
| mkcp_seed / KCP Seed | Value, default — | mkcp | finalmask.udp: дополнительный mkcp-legacy, settings.value при непустом seed |
| ws_host / WebSocket Host | Value, default — | ws | wsSettings.host |
| ws_path / WebSocket Path | Value, placeholder / | ws | wsSettings.path; отсутствующее → / |
| ws_heartbeatPeriod / HeartbeatPeriod(second) | Value, integer, default — | ws | heartbeatPeriod=tonumber, нечисловое → nil |
| grpc_serviceName / ServiceName | Value, default — | grpc | grpcSettings.serviceName |
| grpc_mode / gRPC Transfer mode | gun/multi; default — | grpc | multiMode=true только для multi |
| grpc_health_check / Health check | Flag, explicit default — | grpc | Управляет видимостью; генератор читает дочерние поля напрямую, не этот flag |
| grpc_idle_timeout / Idle timeout | Value, default 10; datatype не указан | grpc_health_check=true | idle_timeout: числовое значение минимум 10; нечисловой непустой ввод потенциально приводит к сравнению nil с числом — проверить безопасным тестом позже |
| grpc_health_check_timeout / Health check timeout | Value, default 20 | grpc_health_check=true | health_check_timeout=tonumber |
| grpc_permit_without_stream / Permit without stream | Flag, default 0 | grpc_health_check=true | true только при строке 1 |
| grpc_initial_windows_size / Initial Windows Size | Value, default 0 | grpc | initial_windows_size числовое; отсутствующее → 0 |
| httpupgrade_host / HttpUpgrade Host | Value, default — | httpupgrade | httpupgradeSettings.host |
| httpupgrade_path / HttpUpgrade Path | Value, placeholder / | httpupgrade | httpupgradeSettings.path; отсутствующее → / |
| xhttp_mode / XHTTP Mode | auto/packet-up/stream-up/stream-one; default auto | xhttp | xhttpSettings.mode, fallback auto |
| xhttp_host / XHTTP Host | Value, default — | xhttp | xhttpSettings.host |
| xhttp_path / XHTTP Path | Value, placeholder / | xhttp | xhttpSettings.path; отсутствующее → / |
| use_xhttp_extra / XHTTP Extra | Flag, default 0 | xhttp | UI-переключатель; generator читает xhttp_extra напрямую |
| xhttp_extra | TextValue, json, 10 строк | use_xhttp_extra=true | Нормализация пробелов/переводов, JSON validation; хранение base64. Generator берет parsed.extra либо весь parsed. Это не полное копирование внешнего XHttpObject: верхние mode/path/host по этому пути не применяются |
| download_address (служебное, не отдельное поле UI) | строка, извлекается при записи extra | extra.downloadSettings.address либо downloadSettings.address | Удаление внешних квадратных скобок; отсутствующее → удаление поля. Сетевое использование еще исследовать |
| user_agent / User-Agent | Value, default пустое; свободная строка плюс готовые chrome/firefox/safari/edge/golang/curl значения | tcp_guise=http либо ws/httpupgrade/xhttp/grpc; также masque | RAW/WS/HTTPUpgrade: header; gRPC: user_agent; XHTTP: extra.headers.User-Agent, если нет User-Agent или user-agent в JSON |

KCP generator также задает без UI-полей в этом блоке: tti=50, uplinkCapacity=12, downlinkCapacity=100, cwndMultiplier=1, maxSendingWindow=2097152. WS generator поддерживает ws_maxEarlyData и ws_earlyDataHeaderName, хотя в прочитанной форме их нет: требуется проверить импорт подписок и обратную совместимость. Нельзя считать каталог UI полным каталогом входных настроек.

## Дополнительные поля и ограничения
Источник UI: client/type/2_xray.lua, строки 757–938. Генератор: util_xray.lua, строки 160–182, 400–529.

| Поля | Тип / default / условие | Преобразование / незакрытый вопрос |
|---|---|---|
| mux (Mux) | Flag; explicit default —; для VLESS raw/ws/grpc/httpupgrade; также SOCKS/HTTP | mux.enabled=(mux==1). Наличие в UI не подтверждает пригодность Mux для произвольного внешнего HTTP/SOCKS-сервера |
| mux_concurrency | Value; -1; mux=true | tonumber, fallback -1 при отсутствии |
| xudp_concurrency | Value; 8; mux=true | xudpConcurrency; fallback 8 при отсутствии |
| use_finalmask | Flag; 0; VLESS/WireGuard и другие, не SOCKS/HTTP | Управляет видимостью FinalMask |
| finalmask | TextValue/json; use_finalmask=true; base64 storage | Валидный JSON заменяет автоматически собранный finalmask целиком, а не дополняет. Generator не проверяет use_finalmask напрямую |
| tcp_fast_open | Flag; 0 | sockopt.tcpFastOpen; только значение 1 создает true |
| tcpMptcp | Flag; 0 | sockopt.tcpMptcp; нужно исследовать поддержку Linux и сервера |
| domain_resolver | список пустое (Auto)/tcp/udp/https | DNS именно адреса узла, не политика всего пользовательского DNS |
| domain_resolver_dns | Value, or(ipaddr,ipaddrport); default 114.114.114.114; при tcp/udp | Generator собирает отдельный DNS server и full:домен; разбор IPv6 через split(':') требует проверки |
| domain_resolver_dns_https | Value; default https://120.53.53.53/dns-query; при https | parseDoH; bootstrap доменов выделяется отдельно; UI не задает datatype в данном блоке |
| domain_strategy | список пустое/UseIPv4v6/UseIPv6v4/UseIPv4/UseIPv6; default пустое; happy_eyeballs=false | sockopt.domainStrategy=node.domain_strategy or UseIP: отсутствующее и пустая строка различаются в Lua |
| happy_eyeballs | Flag; 0 | sockopt.happyEyeballs: TryDelayMs=250, PrioritizeIPv6=false, Interleave=1, MaxConcurrentTry=4 |
| chain_proxy | список пустое/1/3/2 для обычного узла | Выключено/предварительный узел/выходной интерфейс/конечный узел; mapping вне gen_outbound еще исследовать |
| preproxy_node | ListValue; chain_proxy=1,hysteria2_realms=false | Исключает текущий узел, shunt/iface; пояснение обещает один слой; реальную защиту циклов проверить |
| outbound_iface | Value с вариантами устройств; chain_proxy=3 | Имена Linux-интерфейсов; нельзя переносить OpenWrt enumeration как API приложения |
| to_node | ListValue; chain_proxy=2,hysteria2_realms=false | Только normal_list, кроме самого себя; один слой по UI |

Служебный sockopt.mark=255 жестко задан PassWall. Его нельзя автоматически утверждать для Ubuntu: нужна собственная согласованная схема маркировки/обхода петель. Для WireGuard перечисленные общие поля видны, но обычный streamSettings/sockopt-блок не создается по одному лишь protocol=wireguard; видимость и действие расходятся. Требуется трассировка полного pipeline.

## SOCKS и HTTP — поля выбранных типов внутри Xray
Источник формы: client/type/2_xray.lua:245–268,432–575,757–938; генератор: util_xray.lua:144–146,417–449.
Общие remarks/group/type — node_config.lua. address/port — сервер и порт. username (Username) — Value, password (Password) — скрываемый Value, explicit defaults/дополнительные validators отсутствуют в этих объявлениях; генератор передает settings.user/settings.pass. Пустая авторизация и частично заполненная пара должны проверяться на согласованной версии Xray, не додумываться.
HTTP имеет переключатель TLS и общие TLS-поля; при stream_security=tls генератор принудительно задает transport=raw. У SOCKS нет TLS-переключателя в этой Xray-форме. Версия SOCKS здесь не выбирается. Нужна сверка Xray, прежде чем утверждать поддержку SOCKS4/4a/5. Отдельный тип PassWall SOCKS из 0_socks.lua еще не исследован; не смешивать его с Xray/SOCKS. Локальный HTTP/SOCKS inbound пользователь не утверждал.

## WireGuard — поля узла Xray
Источник формы: client/type/2_xray.lua:576–598, общие поля выше. Генератор util_xray.lua:118–131,417–471.

| Поле / оригинальная подпись | Тип/default/validation в UI | Генерация |
|---|---|---|
| address / Address (Support Domain Name), port / Port | Общие Value, port datatype | peers[1].endpoint=address..':'..port; IPv6-скобки требуют проверки |
| wireguard_public_key / Public Key | Value, explicit default и validator — | peers[1].publicKey |
| wireguard_secret_key / Private Key | Value, password=true в этом объявлении отсутствует | settings.secretKey; секрет, не записывать в исследовательские документы |
| wireguard_preSharedKey / Pre shared key | Value, explicit default/validator — | peers[1].preSharedKey; секрет |
| wireguard_local_address / Local Address | DynamicList, explicit default/validator — | settings.address; общий CBI удаляет дубликаты |
| wireguard_mtu / MTU | Value; default 1420; datatype не указан | settings.mtu=tonumber |
| wireguard_reserved / Reserved | Value; десятичные через запятую или base64 по описанию | Decimal/base64 преобразование в массив; ограничения длины/байтов еще проверить |
| wireguard_keepAlive / Keep Alive | Value; default 0; datatype не указан | peers[1].keepAlive=tonumber |

Генератор создает одного peer и выставляет noKernelTun=true. Это реализация outbound внутри Xray, не настройка wg-quick/системного VPN-интерфейса. Пользовательский FinalMask добавляется отдельно в streamSettings. Возможность импорта полноценного WireGuard-конфига и нескольких peers не утверждена. Ubuntu-переносимость определяется поддержкой target Xray; системные маршруты не следует выводить из наличия этих полей.

## Общая обработка формы (api.lua:1716–1827)
set_type_cbi сохраняет UI-префикс xray_ отдельно от config_option: в хранилище обычно пишется имя без префикса. DynamicList/MultiValue дедуплицируются. write/remove действуют только если выбран соответствующий type. deplist2json добавляет type=Xray к условиям и преобразует ссылки на поля. При удалении используется config_option либо rewrite_option. Точный момент удаления скрытого поля зависит от LuCI CBI — пока UNDER_RESEARCH, поэтому нельзя объявлять отключенный UI-флаг надежным gate для сохраненного JSON.

## VLESS: уточненное преобразование в outbound settings
settings.id=uuid; settings.encryption — непустое encryption либо none. settings.flow включается только для VLESS, если tls=1 ИЛИ непустое encryption не равно none, и flow непустой. UI при этом показывает flow для любого VLESS. ALPN, если не default, разбивается по запятой и добавляется только в tlsSettings, не realitySettings. Новые форматы settings.address/port/id и streamSettings.method должны сверяться с исходниками конкретного Xray, не со старой схемой по памяти.

## Результаты проверки по Xray
См. PASSWALL_RESEARCH.md: Xray commit 1b1647cd9ddf0abc34b981d4611fc03bcac1ca74, infra/conf/{transport_internet,vless,socks,http,wireguard}.go и proxy/socks/client.go.
Закрытые вопросы: streamSettings.method допустим в этом snapshot; SOCKS outbound использует SOCKS5; user/pass авторизация появляется только при непустом user; WireGuard reserved — 0 либо 3 байта; engine принимает сокращенную схему VLESS. REALITY+WS/HTTPUpgrade в этом Xray недопустимы несмотря на UI PassWall.
Не смешивать эту проверку с гарантией поддержки в релизном Xray пользователя. Ни production-версия engine, ни политика обработки неверных комбинаций еще не утверждены.

## Общие поля и полная трассировка chains
node_config.lua:35–60: remarks (Node Remarks), Value, default перевод строки Remarks, rmempty=false; group (Group Name), Value, default пустое. group обрезается trim; пустое/default без учета регистра удаляет значение; совпадающая без учета регистра существующая группа использует существующее написание. type — выбор движка, список зависит от установленных компонентов; доступный Xray назначается default лишь если default еще не задан. remarks/group — метаданные, group сам по себе не балансировка. tags могут включать remarks; не хранить секреты в названиях.
util_xray.lua:1258–1346: chain=1 добавляет предварительный outbound и текущему sockopt.dialerProxy=его tag, если отсутствует _flag_proxy_tag; balancing preproxy может использовать loopback. chain=2 добавляет конечный outbound и задает его dialerProxy на текущий, возвращает tag конечного; для не-Xray конечного узла создается локальный tunnel inbound и routing rule. chain=3 выставляет sockopt.interface только если streamSettings.sockopt уже есть. Отсутствующий iface/preproxy не превращать в обещанный успешный маршрут. Гарантии обхода циклов и cross-engine fallback требуют отдельного исследования.

## Импорт VLESS: отдельные defaults и нормализация
Источник: root/usr/share/passwall/subscribe.lua:1255–1420, тот же PW commit. Импорт НЕ равен значениям формы:
- Нет port → 443; нет type → tcp, для Xray tcp преобразуется в raw; kcp→mkcp; h2/http→xhttp stream-one.
- uuid и remarks URL-decode; IPv6 bracket endpoint отдельно разбирается.
- RAW headerType default none; KCP headerType default none; gRPC serviceName имеет приоритет над path, mode default gun; XHTTP mode default auto.
- encryption default none; flow копируется; flow при отсутствующем/пустом security включает tls при импорте. Это отличается от ручной формы с default tls=0.
- security=tls/reality включает tls; SNI берется из непустого sni, иначе host; fp включает utls; pcs→tls_pinSHA256, vcn→tls_CertByName, ech→ech_config, pbk/sid/spx/pqv→REALITY поля.
- extra и fm сохраняются base64, включают соответствующие флаги; tfo→tcp_fast_open. tls_allowInsecure может сохраняться, но mapping в прочитанном генераторе отсутствует.
- legacy quic_guise/key/security сохраняются парсером без соответствующей новой UI-опции. Трактовать как совместимость для проверки, не как подтвержденную поддержку.

Полный сырой инвентарь NODE_FIELD_INVENTORY.md сохраняет точные типы, подписи, values, defaults, depends, validators и write/remove handlers всех объявлений обычной формы (включая поля других протоколов как контекст). Совместно с таблицами выше это каталог источника, а не утверждение, что все runtime-эффекты проверены. Пробелы имеют явные записи CONNECTION_GAPS.md.

### Проверка значения Vision-udp443
Источник: https://github.com/XTLS/Xray-core/blob/1b1647cd9ddf0abc34b981d4611fc03bcac1ca74/proxy/vless/outbound/outbound.go#L246-L275 . Для xtls-rprx-vision-udp443 устанавливается allowUDP443=true и flow нормализуется к Vision; обычный Vision отклоняет RequestCommandUDP с портом 443. Это не подтверждает поддержку UDP всей сетевой цепочкой. D-011 сохраняет все три значения flow; D-010 требует TLS/REALITY даже при выключенном flow.

## Подписки: точная логика фильтров (D-031)
Источник: https://github.com/Openwrt-Passwall/openwrt-passwall/blob/409d28cc7d7d2d806039bf03f7ebf4724c03ea99/luci-app-passwall/root/usr/share/passwall/subscribe.lua#L64-L130 . split_filter_keywords делит строки списка по символу |, убирает точные дубликаты, не выполняет trim в этой функции. match_filter_keywords использует буквальную подстроку (find(...,1,true)), без regex и без нормализации регистра в matcher. Для окончательной оценки регистра входного имени проверить вызовы matcher. Режим 5, отсутствующий или неизвестный режим наследует глобальный; глобальный fallback mode=0.
Пусть D — совпадение discard, K — keep. Отбрасывание: mode1=D; mode2=not K; mode3=D and not K; mode4=D or not K; mode0=false. Следовательно, при совпадении обоих mode3 сохраняет, mode4 отбрасывает; при отсутствии обоих mode3 сохраняет, mode4 отбрасывает. Пустой keep в mode2/4 отбрасывает все. Политика Raylane для нулевой выборки еще не согласована. Это статический анализ, не результат выполненных тестов.
