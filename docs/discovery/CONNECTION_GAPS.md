# Несовместимости, пробелы и открытые решения

Статус: черновик для обсуждения. Полный инвентарь объявлений не равен полностью испытанному runtime-контракту. Никакие тесты движка или сети на этом этапе не запускались.

## Подтвержденные статическим анализом расхождения
| ID | Факт | Источники | Последствие / решение |
|---|---|---|---|
| G-01 | PassWall показывает REALITY при ws/httpupgrade; Xray отклоняет их | PW type/2_xray.lua:440–446; XR infra/conf/transport_internet.go:117–120 | OPEN_QUESTION: предупреждать/блокировать; не обещать поддержку |
| G-02 | flow виден для любого VLESS, но generator передает его лишь при tls=1 либо encryption != none | PW 2_xray.lua:338–343; util_xray.lua:421–424 | Зафиксировать отличие сохраненного и эффективного значения |
| G-03 | password без user не создает авторизацию HTTP/SOCKS | XR infra/conf/{http,socks}.go, Build | Решить UX-валидацию без молчаливой подстановки |
| G-04 | XHTTP Extra/FinalMask generator читает по наличию данных, а не по флагу UI | PW util_xray.lua:260–275,408–414 | Проверить очищение скрытых полей LuCI; импорт может обходить UI |
| G-05 | FinalMask полностью заменяет автоматически построенный объект | PW util_xray.lua:408–414 | Не реализовывать как merge |
| G-06 | gRPC idle timeout использует tonumber и сравнение без проверки успешности | PW util_xray.lua:242 | Потенциальная ошибка генератора при нечисловой строке; это анализ, не выполненный тест |
| G-07 | В форме WireGuard нет password=true для secret/preSharedKey | PW 2_xray.lua:579–583 | PROPOSED: маскировать секреты; согласовать отличие UX |
| G-08 | WireGuard reserved допускает только 0 или 3 байта в Xray, UI ограничение не задает | XR infra/conf/wireguard.go:120–122; PW 2_xray.lua:592 | Нужна явная модель validation |
| G-09 | Импорт VLESS сохраняет tls_allowInsecure; прочитанный Xray generator не передает его | PW subscribe.lua:1400–1401; util_xray.lua TLS block | Не обещать bypass сертификата; исследовать итоговый cleanup и engine policy |
| G-10 | Import допускает legacy quic-поля, которых нет в новой форме транспорта | PW subscribe.lua:1342–1346 | Не считать импорт успешным до проверки engine |
| G-11 | Generic SOCKS PassWall зависит от ipt2socks, Xray SOCKS — отдельная реализация | PW type/0_socks.lua и type/2_xray.lua | Выбор пользователя SOCKS не определяет перенос ipt2socks |
| G-12 | Некоторые общие поля видны WireGuard, но обычный sockopt-блок создается не для protocol=wireguard | PW util_xray.lua:166,456–465 | Не гарантировать действие TFO/MPTCP/Happy Eyeballs на WG |

PW = https://github.com/Openwrt-Passwall/openwrt-passwall/tree/409d28cc7d7d2d806039bf03f7ebf4724c03ea99/luci-app-passwall . Пути UI относительно luasrc/model/cbi/passwall/client; util_xray.lua — luasrc/passwall; subscribe.lua — root/usr/share/passwall.
XR = https://github.com/XTLS/Xray-core/tree/1b1647cd9ddf0abc34b981d4611fc03bcac1ca74 .

## Открытые продуктовые решения (не подменять предположениями)
1. Все ли транспорты VLESS нужны: raw, mkcp, ws, grpc, httpupgrade, xhttp? Какие security/flow сочетания?
2. Нужны ли произвольные XHTTP Extra/FinalMask, ECH, ML-DSA-65, Mux/XUDP, цепочки и интерфейсный выход?
3. Ручной ввод, одиночный импорт/экспорт, подписки: что включить? WireGuard .conf и несколько peers не утверждены.
4. Прямая совместимость с недопустимыми настройками PassWall или понятная блокировка до применения? Улучшенная валидация требует согласования.
5. Как хранить/редактировать скрытые поля при смене режима? Сохранять для возврата или удалять, как может делать CBI?
6. Какая стабильная версия Xray является целью, как обновлять и фиксировать capability profile?
7. Входящий TCP/UDP, DNS, IPv6, failure policy, откат и восстановление — сетевой этап не завершен.
8. Backend/frontend, хранение, права, authentication панели, критерии производительности и границы UI еще не выбраны.

## Технические исследования, НЕ требующие решения пользователя
- Точное поведение удаления/валидации LuCI CBI: в исследуемом репозитории PassWall нет полной реализации зависимости luci.cbi; нужен отдельно привязанный исходник LuCI, не догадки.
- Полные engine validators для каждого TLS/REALITY/транспорта и runtime-проверки безопасности; выбранный Xray HEAD не равен проверенному релизу.
- Импорт/экспорт и восстановление неявных полей: найдено, но не доказана полнота всех форматов и их round-trip.
- IPv6 endpoint WireGuard и отдельный DNS resolver: исследовать разбор адресов и bootstrap, не запускать сетевые изменения.
- Сохранение/удаление ссылок chain и защита от циклов, ошибка отсутствующего узла.

Эти пункты не блокируют обсуждение черновика, но блокируют утверждение полной исполнимой спецификации. Приемка текущего этапа — документальная; runtime acceptance в будущем отдельно.
