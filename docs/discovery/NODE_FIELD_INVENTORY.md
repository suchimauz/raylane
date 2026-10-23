# Инвентарь полей узлов

UNDER_RESEARCH. Полный сырой инвентарь обычной Xray-формы, общих полей и Socks. Условные поля иных протоколов не означают включение их в продукт. Нормализованная семантика — SETTINGS_REFERENCE.md. Сохранены defaults, datatype, depends и обработчики. Комментарии с невалидным UTF-8 в оригинальном 0_socks.lua заменены символом замены, исполняемые объявления не изменены. Специальные узлы балансировки/shunt/iface вне этого каталога; chain-поля включены.

## node_config.lua: `remarks`

[Источник 35–38](https://github.com/Openwrt-Passwall/openwrt-passwall/blob/409d28cc7d7d2d806039bf03f7ebf4724c03ea99/luci-app-passwall/luasrc/model/cbi/passwall/client/node_config.lua#L35-L38)

```lua
o = s:option(Value, "remarks", translate("Node Remarks"))
o.default = translate("Remarks")
o.rmempty = false

```

## node_config.lua: `group`

[Источник 39–60](https://github.com/Openwrt-Passwall/openwrt-passwall/blob/409d28cc7d7d2d806039bf03f7ebf4724c03ea99/luci-app-passwall/luasrc/model/cbi/passwall/client/node_config.lua#L39-L60)

```lua
o = s:option(Value, "group", translate("Group Name"))
o.default = ""
o:value("", translate("default"))
for k, v in pairs(groups) do
	o:value(k)
end
o.write = function(self, section, value)
	value = api.trim(value)
	local lower = value:lower()

	if lower == "" or lower == "default" then
		return m:del(section, self.option)
	end

	for _, v in ipairs(self.keylist or {}) do
		if v:lower() == lower then
			return m:set(section, self.option, v)
		end
	end
	m:set(section, self.option, value)
end

```

## type/2_xray.lua: `address`

[Источник 247–248](https://github.com/Openwrt-Passwall/openwrt-passwall/blob/409d28cc7d7d2d806039bf03f7ebf4724c03ea99/luci-app-passwall/luasrc/model/cbi/passwall/client/type/2_xray.lua#L247-L248)

```lua
o = s:option(Value, "address", translate("Address (Support Domain Name)"))

```

## type/2_xray.lua: `port`

[Источник 249–251](https://github.com/Openwrt-Passwall/openwrt-passwall/blob/409d28cc7d7d2d806039bf03f7ebf4724c03ea99/luci-app-passwall/luasrc/model/cbi/passwall/client/type/2_xray.lua#L249-L251)

```lua
o = s:option(Value, "port", translate("Port"))
o.datatype = "port"

```

## type/2_xray.lua: `uuid`

[Источник 252–256](https://github.com/Openwrt-Passwall/openwrt-passwall/blob/409d28cc7d7d2d806039bf03f7ebf4724c03ea99/luci-app-passwall/luasrc/model/cbi/passwall/client/type/2_xray.lua#L252-L256)

```lua
o = s:option(Value, "uuid", translate("ID"))
o.password = true
o:depends({ protocol = "vmess" })
o:depends({ protocol = "vless" })

```

## type/2_xray.lua: `username`

[Источник 257–261](https://github.com/Openwrt-Passwall/openwrt-passwall/blob/409d28cc7d7d2d806039bf03f7ebf4724c03ea99/luci-app-passwall/luasrc/model/cbi/passwall/client/type/2_xray.lua#L257-L261)

```lua
o = s:option(Value, "username", translate("Username"))
o:depends({ protocol = "http" })
o:depends({ protocol = "socks" })
o:depends({ protocol = "masque" })

```

## type/2_xray.lua: `password`

[Источник 262–270](https://github.com/Openwrt-Passwall/openwrt-passwall/blob/409d28cc7d7d2d806039bf03f7ebf4724c03ea99/luci-app-passwall/luasrc/model/cbi/passwall/client/type/2_xray.lua#L262-L270)

```lua
o = s:option(Value, "password", translate("Password"))
o.password = true
o:depends({ protocol = "http" })
o:depends({ protocol = "socks" })
o:depends({ protocol = "shadowsocks" })
o:depends({ protocol = "trojan" })
o:depends({ protocol = "masque" })

-- [[ MASQUE ]] --
```

## type/2_xray.lua: `masque_warp`

[Источник 271–290](https://github.com/Openwrt-Passwall/openwrt-passwall/blob/409d28cc7d7d2d806039bf03f7ebf4724c03ea99/luci-app-passwall/luasrc/model/cbi/passwall/client/type/2_xray.lua#L271-L290)

```lua
o = s:option(Flag, "masque_warp", "WARP")
o.default = "0"
o:depends({ protocol = "masque" })

for _, field in ipairs({
	{ "masque_warp_private_key", translate("WARP Device Private Key") },
	{ "masque_warp_public_key", translate("WARP Endpoint Public Key") }
}) do
	o = s:option(TextValue, field[1], field[2])
	o.rows = 3
	o.wrap = "off"
	o:depends({ protocol = "masque", masque_warp = "1" })
	o.cfgvalue = function(self, section)
		return (m:get(section, self.config_option) or ""):gsub("\\n", "\n")
	end
	o.validate = function(self, value)
		return api.trim(value):gsub("\r\n?", "\n"):gsub("\n", "\\n")
	end
end

```

## type/2_xray.lua: `masque_warp_address`

[Источник 291–293](https://github.com/Openwrt-Passwall/openwrt-passwall/blob/409d28cc7d7d2d806039bf03f7ebf4724c03ea99/luci-app-passwall/luasrc/model/cbi/passwall/client/type/2_xray.lua#L291-L293)

```lua
o = s:option(DynamicList, "masque_warp_address", "WARP " .. translate("Local Address"))
o:depends({ protocol = "masque", masque_warp = "1" })

```

## type/2_xray.lua: `masque_path`

[Источник 294–296](https://github.com/Openwrt-Passwall/openwrt-passwall/blob/409d28cc7d7d2d806039bf03f7ebf4724c03ea99/luci-app-passwall/luasrc/model/cbi/passwall/client/type/2_xray.lua#L294-L296)

```lua
o = s:option(Value, "masque_path", translate("MASQUE Path"))
o:depends({ protocol = "masque" })

```

## type/2_xray.lua: `masque_headers`

[Источник 297–319](https://github.com/Openwrt-Passwall/openwrt-passwall/blob/409d28cc7d7d2d806039bf03f7ebf4724c03ea99/luci-app-passwall/luasrc/model/cbi/passwall/client/type/2_xray.lua#L297-L319)

```lua
o = s:option(TextValue, "masque_headers", translate("Custom HTTP Headers"))
o.rows = 5
o.wrap = "off"
o:depends({ protocol = "masque" })
o.cfgvalue = function(self, section)
	return (m:get(section, "masque_headers") or ""):gsub("\\n", "\n")
end
o.validate = function(self, value)
	value = api.trim(value):gsub("\r\n", "\n"):gsub("\r", "\n")
	local headers = {}
	for line in value:gmatch("[^\n]+") do
		if api.trim(line) ~= "" then
			local key = line:match("^%s*([^:]+):")
			key = key and api.trim(key):lower()
			if not key or not key:match("^[!#$%%&'*+%.%^_`|~%w%-]+$") or headers[key] or key == "host" or key == "capsule-protocol" then
				return nil, translate("Not true format, please re-enter!") .. " (" .. line .. ")"
			end
			headers[key] = true
		end
	end
	return value:gsub("\n", "\\n")
end

```

## type/2_xray.lua: `security`

[Источник 320–323](https://github.com/Openwrt-Passwall/openwrt-passwall/blob/409d28cc7d7d2d806039bf03f7ebf4724c03ea99/luci-app-passwall/luasrc/model/cbi/passwall/client/type/2_xray.lua#L320-L323)

```lua
o = s:option(ListValue, "security", translate("Encrypt Method"))
for a, t in ipairs(security_list) do o:value(t) end
o:depends({ protocol = "vmess" })

```

## type/2_xray.lua: `encryption`

[Источник 324–332](https://github.com/Openwrt-Passwall/openwrt-passwall/blob/409d28cc7d7d2d806039bf03f7ebf4724c03ea99/luci-app-passwall/luasrc/model/cbi/passwall/client/type/2_xray.lua#L324-L332)

```lua
o = s:option(Value, "encryption", translate("Encrypt Method") .. " (encryption)")
o.default = "none"
o.placeholder = "none"
o:depends({ protocol = "vless" })
o.validate = function(self, value)
	value = api.trim(value)
	return (value == "" and "none" or value)
end

```

## type/2_xray.lua: `ss_method`

[Источник 333–337](https://github.com/Openwrt-Passwall/openwrt-passwall/blob/409d28cc7d7d2d806039bf03f7ebf4724c03ea99/luci-app-passwall/luasrc/model/cbi/passwall/client/type/2_xray.lua#L333-L337)

```lua
o = s:option(ListValue, "ss_method", translate("Encrypt Method"))
o.rewrite_option = "method"
for a, t in ipairs(ss_method_list) do o:value(t) end
o:depends({ protocol = "shadowsocks" })

```

## type/2_xray.lua: `flow`

[Источник 338–345](https://github.com/Openwrt-Passwall/openwrt-passwall/blob/409d28cc7d7d2d806039bf03f7ebf4724c03ea99/luci-app-passwall/luasrc/model/cbi/passwall/client/type/2_xray.lua#L338-L345)

```lua
o = s:option(ListValue, "flow", translate("flow"))
o.default = ""
o:value("", translate("Disable"))
o:value("xtls-rprx-vision")
o:value("xtls-rprx-vision-udp443")
o:depends({ protocol = "vless" })

---- [[hysteria2]]
```

## type/2_xray.lua: `hysteria2_hop`

[Источник 346–349](https://github.com/Openwrt-Passwall/openwrt-passwall/blob/409d28cc7d7d2d806039bf03f7ebf4724c03ea99/luci-app-passwall/luasrc/model/cbi/passwall/client/type/2_xray.lua#L346-L349)

```lua
o = s:option(Value, "hysteria2_hop", translate("Port hopping range"))
o.description = translate("Format as 1000:2000 or 1000-2000 Multiple groups are separated by commas (,).")
o:depends({ protocol = "hysteria2", hysteria2_realms = false })

```

## type/2_xray.lua: `hysteria2_hop_interval`

[Источник 350–355](https://github.com/Openwrt-Passwall/openwrt-passwall/blob/409d28cc7d7d2d806039bf03f7ebf4724c03ea99/luci-app-passwall/luasrc/model/cbi/passwall/client/type/2_xray.lua#L350-L355)

```lua
o = s:option(Value, "hysteria2_hop_interval", translate("Hop Interval(second)"), translate("Supports a fixed value or a random range (e.g., 30, 5-30), minimum 5."))
o.datatype = "or(uinteger,portrange)"
o.placeholder = "30"
o.default = "30"
o:depends({ protocol = "hysteria2", hysteria2_realms = false })

```

## type/2_xray.lua: `hysteria2_realms`

[Источник 356–359](https://github.com/Openwrt-Passwall/openwrt-passwall/blob/409d28cc7d7d2d806039bf03f7ebf4724c03ea99/luci-app-passwall/luasrc/model/cbi/passwall/client/type/2_xray.lua#L356-L359)

```lua
o = s:option(Flag, "hysteria2_realms", translate("Realms"))
o.default = "0"
o:depends({ protocol = "hysteria2"})

```

## type/2_xray.lua: `hysteria2_realm_url`

[Источник 360–368](https://github.com/Openwrt-Passwall/openwrt-passwall/blob/409d28cc7d7d2d806039bf03f7ebf4724c03ea99/luci-app-passwall/luasrc/model/cbi/passwall/client/type/2_xray.lua#L360-L368)

```lua
o = s:option(Value, "hysteria2_realm_url", translate("Realm URL"), translate("Example:") .. "realm://public@realm.hy2.io/your-realm-name")
o:depends({ hysteria2_realms = "1" })
o.validate = function(self, value)
	value = api.trim(value)
	local realm = api.parse_realm_uri(value)
	if realm then return value end
	return nil, translate("Invalid Realm URL.")
end

```

## type/2_xray.lua: `hysteria2_realm_stun`

[Источник 369–372](https://github.com/Openwrt-Passwall/openwrt-passwall/blob/409d28cc7d7d2d806039bf03f7ebf4724c03ea99/luci-app-passwall/luasrc/model/cbi/passwall/client/type/2_xray.lua#L369-L372)

```lua
o = s:option(DynamicList, "hysteria2_realm_stun", translate("Realm STUN"))
o.default = { "stun.sip.us:3478", "stun.nextcloud.com:3478", "global.stun.twilio.com:3478" }
o:depends({ hysteria2_realms = "1" })

```

## type/2_xray.lua: `hysteria2_realm_upnp`

[Источник 373–376](https://github.com/Openwrt-Passwall/openwrt-passwall/blob/409d28cc7d7d2d806039bf03f7ebf4724c03ea99/luci-app-passwall/luasrc/model/cbi/passwall/client/type/2_xray.lua#L373-L376)

```lua
o = s:option(Flag, "hysteria2_realm_upnp", translate("Enable") .. " UPnP/NAT-PMP", translate("Enable UPnP/NAT-PMP port mapping on your gateway to improve hole punching success."))
o.default = "0"
o:depends({ hysteria2_realms = "1" })

```

## type/2_xray.lua: `hysteria2_auth_password`

[Источник 377–380](https://github.com/Openwrt-Passwall/openwrt-passwall/blob/409d28cc7d7d2d806039bf03f7ebf4724c03ea99/luci-app-passwall/luasrc/model/cbi/passwall/client/type/2_xray.lua#L377-L380)

```lua
o = s:option(Value, "hysteria2_auth_password", translate("Auth Password"))
o.password = true
o:depends({ protocol = "hysteria2"})

```

## type/2_xray.lua: `hysteria2_obfs_type`

[Источник 381–386](https://github.com/Openwrt-Passwall/openwrt-passwall/blob/409d28cc7d7d2d806039bf03f7ebf4724c03ea99/luci-app-passwall/luasrc/model/cbi/passwall/client/type/2_xray.lua#L381-L386)

```lua
o = s:option(ListValue, "hysteria2_obfs_type", translate("Obfs Type"))
o:value("", translate("Disable"))
o:value("salamander")
o:value("gecko")
o:depends({ protocol = "hysteria2" })

```

## type/2_xray.lua: `hysteria2_obfs_password`

[Источник 387–390](https://github.com/Openwrt-Passwall/openwrt-passwall/blob/409d28cc7d7d2d806039bf03f7ebf4724c03ea99/luci-app-passwall/luasrc/model/cbi/passwall/client/type/2_xray.lua#L387-L390)

```lua
o = s:option(Value, "hysteria2_obfs_password", translate("Obfs Password"))
o:depends({ hysteria2_obfs_type = "salamander" })
o:depends({ hysteria2_obfs_type = "gecko" })

```

## type/2_xray.lua: `hysteria2_obfs_MinPacketSize`

[Источник 391–396](https://github.com/Openwrt-Passwall/openwrt-passwall/blob/409d28cc7d7d2d806039bf03f7ebf4724c03ea99/luci-app-passwall/luasrc/model/cbi/passwall/client/type/2_xray.lua#L391-L396)

```lua
o = s:option(Value, "hysteria2_obfs_MinPacketSize", translate("Gecko Packet Size (min)"))
o.datatype = "uinteger"
o.placeholder = "512"
o.default = "512"
o:depends({ hysteria2_obfs_type = "gecko" })

```

## type/2_xray.lua: `hysteria2_obfs_MaxPacketSize`

[Источник 397–402](https://github.com/Openwrt-Passwall/openwrt-passwall/blob/409d28cc7d7d2d806039bf03f7ebf4724c03ea99/luci-app-passwall/luasrc/model/cbi/passwall/client/type/2_xray.lua#L397-L402)

```lua
o = s:option(Value, "hysteria2_obfs_MaxPacketSize", translate("Gecko Packet Size (max)"))
o.datatype = "uinteger"
o.placeholder = "1200"
o.default = "1200"
o:depends({ hysteria2_obfs_type = "gecko" })

```

## type/2_xray.lua: `hysteria2_up_mbps`

[Источник 403–405](https://github.com/Openwrt-Passwall/openwrt-passwall/blob/409d28cc7d7d2d806039bf03f7ebf4724c03ea99/luci-app-passwall/luasrc/model/cbi/passwall/client/type/2_xray.lua#L403-L405)

```lua
o = s:option(Value, "hysteria2_up_mbps", translate("Max upload Mbps"))
o:depends({ protocol = "hysteria2" })

```

## type/2_xray.lua: `hysteria2_down_mbps`

[Источник 406–408](https://github.com/Openwrt-Passwall/openwrt-passwall/blob/409d28cc7d7d2d806039bf03f7ebf4724c03ea99/luci-app-passwall/luasrc/model/cbi/passwall/client/type/2_xray.lua#L406-L408)

```lua
o = s:option(Value, "hysteria2_down_mbps", translate("Max download Mbps"))
o:depends({ protocol = "hysteria2" })

```

## type/2_xray.lua: `hysteria2_stream_recv_win`

[Источник 409–413](https://github.com/Openwrt-Passwall/openwrt-passwall/blob/409d28cc7d7d2d806039bf03f7ebf4724c03ea99/luci-app-passwall/luasrc/model/cbi/passwall/client/type/2_xray.lua#L409-L413)

```lua
o = s:option(Value, "hysteria2_stream_recv_win", translate("QUIC stream receive window") .. " (MB)")
o.datatype = "range(1,1000)"
o.placeholder = "8"
o:depends({ protocol = "hysteria2" })

```

## type/2_xray.lua: `hysteria2_conn_recv_win`

[Источник 414–418](https://github.com/Openwrt-Passwall/openwrt-passwall/blob/409d28cc7d7d2d806039bf03f7ebf4724c03ea99/luci-app-passwall/luasrc/model/cbi/passwall/client/type/2_xray.lua#L414-L418)

```lua
o = s:option(Value, "hysteria2_conn_recv_win", translate("QUIC connection receive window") .. " (MB)")
o.datatype = "range(1,1000)"
o.placeholder = "20"
o:depends({ protocol = "hysteria2" })

```

## type/2_xray.lua: `hysteria2_idle_timeout`

[Источник 419–422](https://github.com/Openwrt-Passwall/openwrt-passwall/blob/409d28cc7d7d2d806039bf03f7ebf4724c03ea99/luci-app-passwall/luasrc/model/cbi/passwall/client/type/2_xray.lua#L419-L422)

```lua
o = s:option(Value, "hysteria2_idle_timeout", translate("Idle Timeout"), translate("Units:seconds") .. " (4~120)")
o.datatype = "range(4,120)"
o:depends({ protocol = "hysteria2"})

```

## type/2_xray.lua: `hysteria2_keep_alive_period`

[Источник 423–426](https://github.com/Openwrt-Passwall/openwrt-passwall/blob/409d28cc7d7d2d806039bf03f7ebf4724c03ea99/luci-app-passwall/luasrc/model/cbi/passwall/client/type/2_xray.lua#L423-L426)

```lua
o = s:option(Value, "hysteria2_keep_alive_period", translate("QUIC KeepAlive interval"), translate("Units:seconds") .. " (2~60)")
o.datatype = "range(2,60)"
o:depends({ protocol = "hysteria2"})

```

## type/2_xray.lua: `hysteria2_disable_mtu_discovery`

[Источник 427–431](https://github.com/Openwrt-Passwall/openwrt-passwall/blob/409d28cc7d7d2d806039bf03f7ebf4724c03ea99/luci-app-passwall/luasrc/model/cbi/passwall/client/type/2_xray.lua#L427-L431)

```lua
o = s:option(Flag, "hysteria2_disable_mtu_discovery", translate("Disable MTU detection"))
o.default = "0"
o:depends({ protocol = "hysteria2"})
---- [[hysteria2 end]]

```

## type/2_xray.lua: `tls`

[Источник 432–439](https://github.com/Openwrt-Passwall/openwrt-passwall/blob/409d28cc7d7d2d806039bf03f7ebf4724c03ea99/luci-app-passwall/luasrc/model/cbi/passwall/client/type/2_xray.lua#L432-L439)

```lua
o = s:option(Flag, "tls", translate("TLS"))
o.default = 0
o:depends({ protocol = "vmess" })
o:depends({ protocol = "vless" })
o:depends({ protocol = "http" })
o:depends({ protocol = "trojan" })
o:depends({ protocol = "shadowsocks" })

```

## type/2_xray.lua: `reality`

[Источник 440–447](https://github.com/Openwrt-Passwall/openwrt-passwall/blob/409d28cc7d7d2d806039bf03f7ebf4724c03ea99/luci-app-passwall/luasrc/model/cbi/passwall/client/type/2_xray.lua#L440-L447)

```lua
o = s:option(Flag, "reality", translate("REALITY"), translate("Only recommend to use with VLESS-TCP-XTLS-Vision."))
o.default = 0
o:depends({ tls = true, transport = "raw" })
o:depends({ tls = true, transport = "ws" })
o:depends({ tls = true, transport = "grpc" })
o:depends({ tls = true, transport = "httpupgrade" })
o:depends({ tls = true, transport = "xhttp" })

```

## type/2_xray.lua: `alpn`

[Источник 448–464](https://github.com/Openwrt-Passwall/openwrt-passwall/blob/409d28cc7d7d2d806039bf03f7ebf4724c03ea99/luci-app-passwall/luasrc/model/cbi/passwall/client/type/2_xray.lua#L448-L464)

```lua
o = s:option(ListValue, "alpn", translate("alpn"))
o.default = "default"
o:value("default", translate("Default"))
o:value("h3")
o:value("h2")
o:value("h3,h2")
o:value("http/1.1")
o:value("h2,http/1.1")
o:value("h3,h2,http/1.1")
o:depends({ tls = true, reality = false })
o:depends({ protocol = "masque" })

-- o = s:option(Value, "minversion", translate("minversion"))
-- o.default = "1.3"
-- o:value("1.3")
-- o:depends({ tls = true })

```

## type/2_xray.lua: `tls_serverName`

[Источник 465–469](https://github.com/Openwrt-Passwall/openwrt-passwall/blob/409d28cc7d7d2d806039bf03f7ebf4724c03ea99/luci-app-passwall/luasrc/model/cbi/passwall/client/type/2_xray.lua#L465-L469)

```lua
o = s:option(Value, "tls_serverName", "SNI " .. translate("Domain"))
o:depends({ tls = true })
o:depends({ protocol = "hysteria2" })
o:depends({ protocol = "masque" })

```

## type/2_xray.lua: `tls_pinSHA256`

[Источник 470–476](https://github.com/Openwrt-Passwall/openwrt-passwall/blob/409d28cc7d7d2d806039bf03f7ebf4724c03ea99/luci-app-passwall/luasrc/model/cbi/passwall/client/type/2_xray.lua#L470-L476)

```lua
o = s:option(Value, "tls_pinSHA256", translate("TLS Chain Fingerprint (SHA256)"))
o:depends({ tls = true, reality = false })
o:depends({ protocol = "hysteria2" })
o:depends({ protocol = "masque" })
o.description = translate("Once set, connects only when the server’s chain fingerprint matches.") ..
		string.format("<a href='javascript:void(0)' onclick='javascript:fetchCertSha256(this)'>%s</a>", "→ " .. translate("Fetch Manually"))

```

## type/2_xray.lua: `tls_CertByName`

[Источник 477–481](https://github.com/Openwrt-Passwall/openwrt-passwall/blob/409d28cc7d7d2d806039bf03f7ebf4724c03ea99/luci-app-passwall/luasrc/model/cbi/passwall/client/type/2_xray.lua#L477-L481)

```lua
o = s:option(Value, "tls_CertByName", translate("TLS Certificate Name (CertName)"), translate("TLS is used to verify the leaf certificate name."))
o:depends({ tls = true, reality = false })
o:depends({ protocol = "hysteria2" })
o:depends({ protocol = "masque" })

```

## type/2_xray.lua: `tls_certificate`

[Источник 482–487](https://github.com/Openwrt-Passwall/openwrt-passwall/blob/409d28cc7d7d2d806039bf03f7ebf4724c03ea99/luci-app-passwall/luasrc/model/cbi/passwall/client/type/2_xray.lua#L482-L487)

```lua
o = s:option(Flag, "tls_certificate", translate("TLS Certificate (PEM)"))
o.default = "0"
o:depends({ tls = true, reality = false })
o:depends({ protocol = "hysteria2" })
o:depends({ protocol = "masque" })

```

## type/2_xray.lua: `tls_certificate_pem`

[Источник 488–500](https://github.com/Openwrt-Passwall/openwrt-passwall/blob/409d28cc7d7d2d806039bf03f7ebf4724c03ea99/luci-app-passwall/luasrc/model/cbi/passwall/client/type/2_xray.lua#L488-L500)

```lua
o = s:option(TextValue, "tls_certificate_pem", "　", translate("Full certificate (chain), PEM format."))
o.default = ""
o.rows = 5
o.wrap = "off"
o:depends({ tls_certificate = true })
o.cfgvalue = function(self, section)
	return (m:get(section, "tls_certificate_pem") or ""):gsub("\\n", "\n")
end
o.validate = function(self, value)
	value = api.trim(value):gsub("\r\n", "\n"):gsub("\r", "\n"):gsub("[ \t]*\n[ \t]*", "\n"):gsub("\n+", "\n")
	return value:gsub("\n", "\\n")
end

```

## type/2_xray.lua: `ech`

[Источник 501–506](https://github.com/Openwrt-Passwall/openwrt-passwall/blob/409d28cc7d7d2d806039bf03f7ebf4724c03ea99/luci-app-passwall/luasrc/model/cbi/passwall/client/type/2_xray.lua#L501-L506)

```lua
o = s:option(Flag, "ech", translate("ECH"))
o.default = "0"
o:depends({ tls = true, reality = false })
o:depends({ protocol = "hysteria2", hysteria2_realms = false })
o:depends({ protocol = "masque" })

```

## type/2_xray.lua: `ech_config`

[Источник 507–516](https://github.com/Openwrt-Passwall/openwrt-passwall/blob/409d28cc7d7d2d806039bf03f7ebf4724c03ea99/luci-app-passwall/luasrc/model/cbi/passwall/client/type/2_xray.lua#L507-L516)

```lua
o = s:option(TextValue, "ech_config", translate("ECH Config"))
o.default = ""
o.rows = 5
o.wrap = "soft"
o:depends({ ech = true })
o.validate = function(self, value)
	return api.trim(value:gsub("[\r\n]", ""))
end

-- [[ REALITY部分 ]] --
```

## type/2_xray.lua: `reality_publicKey`

[Источник 517–519](https://github.com/Openwrt-Passwall/openwrt-passwall/blob/409d28cc7d7d2d806039bf03f7ebf4724c03ea99/luci-app-passwall/luasrc/model/cbi/passwall/client/type/2_xray.lua#L517-L519)

```lua
o = s:option(Value, "reality_publicKey", translate("Public Key"))
o:depends({ tls = true, reality = true })

```

## type/2_xray.lua: `reality_shortId`

[Источник 520–522](https://github.com/Openwrt-Passwall/openwrt-passwall/blob/409d28cc7d7d2d806039bf03f7ebf4724c03ea99/luci-app-passwall/luasrc/model/cbi/passwall/client/type/2_xray.lua#L520-L522)

```lua
o = s:option(Value, "reality_shortId", translate("Short Id"))
o:depends({ tls = true, reality = true })

```

## type/2_xray.lua: `reality_spiderX`

[Источник 523–526](https://github.com/Openwrt-Passwall/openwrt-passwall/blob/409d28cc7d7d2d806039bf03f7ebf4724c03ea99/luci-app-passwall/luasrc/model/cbi/passwall/client/type/2_xray.lua#L523-L526)

```lua
o = s:option(Value, "reality_spiderX", translate("Spider X"))
o.placeholder = "/"
o:depends({ tls = true, reality = true })

```

## type/2_xray.lua: `utls`

[Источник 527–530](https://github.com/Openwrt-Passwall/openwrt-passwall/blob/409d28cc7d7d2d806039bf03f7ebf4724c03ea99/luci-app-passwall/luasrc/model/cbi/passwall/client/type/2_xray.lua#L527-L530)

```lua
o = s:option(Flag, "utls", translate("uTLS"))
o.default = "0"
o:depends({ tls = true, reality = false })

```

## type/2_xray.lua: `fingerprint`

[Источник 531–546](https://github.com/Openwrt-Passwall/openwrt-passwall/blob/409d28cc7d7d2d806039bf03f7ebf4724c03ea99/luci-app-passwall/luasrc/model/cbi/passwall/client/type/2_xray.lua#L531-L546)

```lua
o = s:option(ListValue, "fingerprint", translate("Finger Print"))
o:value("chrome")
o:value("firefox")
o:value("edge")
o:value("safari")
o:value("360")
o:value("qq")
o:value("ios")
o:value("android")
o:value("random")
o:value("randomized")
o:value("unsafe")
o.default = "chrome"
o:depends({ tls = true, utls = true })
o:depends({ tls = true, reality = true })

```

## type/2_xray.lua: `cipherSuites`

[Источник 547–550](https://github.com/Openwrt-Passwall/openwrt-passwall/blob/409d28cc7d7d2d806039bf03f7ebf4724c03ea99/luci-app-passwall/luasrc/model/cbi/passwall/client/type/2_xray.lua#L547-L550)

```lua
o = s:option(Value, "cipherSuites", translate("Cipher Suites"), '<a href="https://go.dev/src/crypto/tls/cipher_suites.go#L44" target="_blank">***</a>' .. " " .. translate("Configures the list of supported cipher suites, separated by :"))
o:depends({ tls = true, reality = false })
o:depends({ protocol = "masque" })

```

## type/2_xray.lua: `use_mldsa65Verify`

[Источник 551–554](https://github.com/Openwrt-Passwall/openwrt-passwall/blob/409d28cc7d7d2d806039bf03f7ebf4724c03ea99/luci-app-passwall/luasrc/model/cbi/passwall/client/type/2_xray.lua#L551-L554)

```lua
o = s:option(Flag, "use_mldsa65Verify", translate("ML-DSA-65"))
o.default = "0"
o:depends({ tls = true, reality = true })

```

## type/2_xray.lua: `reality_mldsa65Verify`

[Источник 555–563](https://github.com/Openwrt-Passwall/openwrt-passwall/blob/409d28cc7d7d2d806039bf03f7ebf4724c03ea99/luci-app-passwall/luasrc/model/cbi/passwall/client/type/2_xray.lua#L555-L563)

```lua
o = s:option(TextValue, "reality_mldsa65Verify", "ML-DSA-65 " .. translate("Public key"))
o.default = ""
o.rows = 5
o.wrap = "soft"
o:depends({ use_mldsa65Verify = true })
o.validate = function(self, value)
	return api.trim(value:gsub("[\r\n]", ""))
end

```

## type/2_xray.lua: `transport`

[Источник 564–575](https://github.com/Openwrt-Passwall/openwrt-passwall/blob/409d28cc7d7d2d806039bf03f7ebf4724c03ea99/luci-app-passwall/luasrc/model/cbi/passwall/client/type/2_xray.lua#L564-L575)

```lua
o = s:option(ListValue, "transport", translate("Transport"))
o:value("raw", "RAW (TCP)")
o:value("mkcp", "mKCP")
o:value("ws", "WebSocket")
o:value("grpc", "gRPC")
o:value("httpupgrade", "HttpUpgrade")
o:value("xhttp", "XHTTP")
o:depends({ protocol = "vmess" })
o:depends({ protocol = "vless" })
o:depends({ protocol = "shadowsocks" })
o:depends({ protocol = "trojan" })

```

## type/2_xray.lua: `wireguard_public_key`

[Источник 576–578](https://github.com/Openwrt-Passwall/openwrt-passwall/blob/409d28cc7d7d2d806039bf03f7ebf4724c03ea99/luci-app-passwall/luasrc/model/cbi/passwall/client/type/2_xray.lua#L576-L578)

```lua
o = s:option(Value, "wireguard_public_key", translate("Public Key"))
o:depends({ protocol = "wireguard" })

```

## type/2_xray.lua: `wireguard_secret_key`

[Источник 579–581](https://github.com/Openwrt-Passwall/openwrt-passwall/blob/409d28cc7d7d2d806039bf03f7ebf4724c03ea99/luci-app-passwall/luasrc/model/cbi/passwall/client/type/2_xray.lua#L579-L581)

```lua
o = s:option(Value, "wireguard_secret_key", translate("Private Key"))
o:depends({ protocol = "wireguard" })

```

## type/2_xray.lua: `wireguard_preSharedKey`

[Источник 582–584](https://github.com/Openwrt-Passwall/openwrt-passwall/blob/409d28cc7d7d2d806039bf03f7ebf4724c03ea99/luci-app-passwall/luasrc/model/cbi/passwall/client/type/2_xray.lua#L582-L584)

```lua
o = s:option(Value, "wireguard_preSharedKey", translate("Pre shared key"))
o:depends({ protocol = "wireguard" })

```

## type/2_xray.lua: `wireguard_local_address`

[Источник 585–587](https://github.com/Openwrt-Passwall/openwrt-passwall/blob/409d28cc7d7d2d806039bf03f7ebf4724c03ea99/luci-app-passwall/luasrc/model/cbi/passwall/client/type/2_xray.lua#L585-L587)

```lua
o = s:option(DynamicList, "wireguard_local_address", translate("Local Address"))
o:depends({ protocol = "wireguard" })

```

## type/2_xray.lua: `wireguard_mtu`

[Источник 588–591](https://github.com/Openwrt-Passwall/openwrt-passwall/blob/409d28cc7d7d2d806039bf03f7ebf4724c03ea99/luci-app-passwall/luasrc/model/cbi/passwall/client/type/2_xray.lua#L588-L591)

```lua
o = s:option(Value, "wireguard_mtu", translate("MTU"))
o.default = "1420"
o:depends({ protocol = "wireguard" })

```

## type/2_xray.lua: `wireguard_reserved`

[Источник 592–594](https://github.com/Openwrt-Passwall/openwrt-passwall/blob/409d28cc7d7d2d806039bf03f7ebf4724c03ea99/luci-app-passwall/luasrc/model/cbi/passwall/client/type/2_xray.lua#L592-L594)

```lua
o = s:option(Value, "wireguard_reserved", translate("Reserved"), translate("Decimal numbers separated by \",\" or Base64-encoded strings."))
o:depends({ protocol = "wireguard" })

```

## type/2_xray.lua: `wireguard_keepAlive`

[Источник 595–601](https://github.com/Openwrt-Passwall/openwrt-passwall/blob/409d28cc7d7d2d806039bf03f7ebf4724c03ea99/luci-app-passwall/luasrc/model/cbi/passwall/client/type/2_xray.lua#L595-L601)

```lua
o = s:option(Value, "wireguard_keepAlive", translate("Keep Alive"))
o.default = "0"
o:depends({ protocol = "wireguard" })

-- [[ RAW部分 ]]--

-- TCP伪装
```

## type/2_xray.lua: `tcp_guise`

[Источник 602–607](https://github.com/Openwrt-Passwall/openwrt-passwall/blob/409d28cc7d7d2d806039bf03f7ebf4724c03ea99/luci-app-passwall/luasrc/model/cbi/passwall/client/type/2_xray.lua#L602-L607)

```lua
o = s:option(ListValue, "tcp_guise", translate("Camouflage Type"))
o:value("none", "none")
o:value("http", "http")
o:depends({ transport = "raw" })

-- HTTP域名
```

## type/2_xray.lua: `tcp_guise_http_host`

[Источник 608–611](https://github.com/Openwrt-Passwall/openwrt-passwall/blob/409d28cc7d7d2d806039bf03f7ebf4724c03ea99/luci-app-passwall/luasrc/model/cbi/passwall/client/type/2_xray.lua#L608-L611)

```lua
o = s:option(DynamicList, "tcp_guise_http_host", translate("HTTP Host"))
o:depends({ tcp_guise = "http" })

-- HTTP路径
```

## type/2_xray.lua: `tcp_guise_http_path`

[Источник 612–617](https://github.com/Openwrt-Passwall/openwrt-passwall/blob/409d28cc7d7d2d806039bf03f7ebf4724c03ea99/luci-app-passwall/luasrc/model/cbi/passwall/client/type/2_xray.lua#L612-L617)

```lua
o = s:option(DynamicList, "tcp_guise_http_path", translate("HTTP Path"))
o.placeholder = "/"
o:depends({ tcp_guise = "http" })

-- [[ mKCP部分 ]]--

```

## type/2_xray.lua: `mkcp_guise`

[Источник 618–621](https://github.com/Openwrt-Passwall/openwrt-passwall/blob/409d28cc7d7d2d806039bf03f7ebf4724c03ea99/luci-app-passwall/luasrc/model/cbi/passwall/client/type/2_xray.lua#L618-L621)

```lua
o = s:option(ListValue, "mkcp_guise", translate("Camouflage Type"), translate('<br />none: default, no masquerade, data sent is packets with no characteristics.<br />srtp: disguised as an SRTP packet, it will be recognized as video call data (such as FaceTime).<br />utp: packets disguised as uTP will be recognized as bittorrent downloaded data.<br />wechat-video: packets disguised as WeChat video calls.<br />dtls: disguised as DTLS 1.2 packet.<br />wireguard: disguised as a WireGuard packet. (not really WireGuard protocol)<br />dns: Disguising traffic as DNS requests.'))
for a, t in ipairs(header_type_list) do o:value(t) end
o:depends({ transport = "mkcp" })

```

## type/2_xray.lua: `mkcp_domain`

[Источник 622–624](https://github.com/Openwrt-Passwall/openwrt-passwall/blob/409d28cc7d7d2d806039bf03f7ebf4724c03ea99/luci-app-passwall/luasrc/model/cbi/passwall/client/type/2_xray.lua#L622-L624)

```lua
o = s:option(Value, "mkcp_domain", translate("Camouflage Domain"), translate("Use it together with the DNS disguised type. You can fill in any domain."))
o:depends({ mkcp_guise = "dns" })

```

## type/2_xray.lua: `mkcp_mtu`

[Источник 625–629](https://github.com/Openwrt-Passwall/openwrt-passwall/blob/409d28cc7d7d2d806039bf03f7ebf4724c03ea99/luci-app-passwall/luasrc/model/cbi/passwall/client/type/2_xray.lua#L625-L629)

```lua
o = s:option(Value, "mkcp_mtu", translate("KCP MTU"))
o.datatype = "uinteger"
o.default = 1350
o:depends({ transport = "mkcp" })

```

## type/2_xray.lua: `mkcp_seed`

[Источник 630–633](https://github.com/Openwrt-Passwall/openwrt-passwall/blob/409d28cc7d7d2d806039bf03f7ebf4724c03ea99/luci-app-passwall/luasrc/model/cbi/passwall/client/type/2_xray.lua#L630-L633)

```lua
o = s:option(Value, "mkcp_seed", translate("KCP Seed"))
o:depends({ transport = "mkcp" })

-- [[ WebSocket部分 ]]--
```

## type/2_xray.lua: `ws_host`

[Источник 634–636](https://github.com/Openwrt-Passwall/openwrt-passwall/blob/409d28cc7d7d2d806039bf03f7ebf4724c03ea99/luci-app-passwall/luasrc/model/cbi/passwall/client/type/2_xray.lua#L634-L636)

```lua
o = s:option(Value, "ws_host", translate("WebSocket Host"))
o:depends({ transport = "ws" })

```

## type/2_xray.lua: `ws_path`

[Источник 637–640](https://github.com/Openwrt-Passwall/openwrt-passwall/blob/409d28cc7d7d2d806039bf03f7ebf4724c03ea99/luci-app-passwall/luasrc/model/cbi/passwall/client/type/2_xray.lua#L637-L640)

```lua
o = s:option(Value, "ws_path", translate("WebSocket Path"))
o.placeholder = "/"
o:depends({ transport = "ws" })

```

## type/2_xray.lua: `ws_heartbeatPeriod`

[Источник 641–645](https://github.com/Openwrt-Passwall/openwrt-passwall/blob/409d28cc7d7d2d806039bf03f7ebf4724c03ea99/luci-app-passwall/luasrc/model/cbi/passwall/client/type/2_xray.lua#L641-L645)

```lua
o = s:option(Value, "ws_heartbeatPeriod", translate("HeartbeatPeriod(second)"))
o.datatype = "integer"
o:depends({ transport = "ws" })

-- [[ gRPC部分 ]]--
```

## type/2_xray.lua: `grpc_serviceName`

[Источник 646–648](https://github.com/Openwrt-Passwall/openwrt-passwall/blob/409d28cc7d7d2d806039bf03f7ebf4724c03ea99/luci-app-passwall/luasrc/model/cbi/passwall/client/type/2_xray.lua#L646-L648)

```lua
o = s:option(Value, "grpc_serviceName", "ServiceName")
o:depends({ transport = "grpc" })

```

## type/2_xray.lua: `grpc_mode`

[Источник 649–653](https://github.com/Openwrt-Passwall/openwrt-passwall/blob/409d28cc7d7d2d806039bf03f7ebf4724c03ea99/luci-app-passwall/luasrc/model/cbi/passwall/client/type/2_xray.lua#L649-L653)

```lua
o = s:option(ListValue, "grpc_mode", "gRPC " .. translate("Transfer mode"))
o:value("gun")
o:value("multi")
o:depends({ transport = "grpc" })

```

## type/2_xray.lua: `grpc_health_check`

[Источник 654–656](https://github.com/Openwrt-Passwall/openwrt-passwall/blob/409d28cc7d7d2d806039bf03f7ebf4724c03ea99/luci-app-passwall/luasrc/model/cbi/passwall/client/type/2_xray.lua#L654-L656)

```lua
o = s:option(Flag, "grpc_health_check", translate("Health check"))
o:depends({ transport = "grpc" })

```

## type/2_xray.lua: `grpc_idle_timeout`

[Источник 657–660](https://github.com/Openwrt-Passwall/openwrt-passwall/blob/409d28cc7d7d2d806039bf03f7ebf4724c03ea99/luci-app-passwall/luasrc/model/cbi/passwall/client/type/2_xray.lua#L657-L660)

```lua
o = s:option(Value, "grpc_idle_timeout", translate("Idle timeout"))
o.default = "10"
o:depends({ grpc_health_check = true })

```

## type/2_xray.lua: `grpc_health_check_timeout`

[Источник 661–664](https://github.com/Openwrt-Passwall/openwrt-passwall/blob/409d28cc7d7d2d806039bf03f7ebf4724c03ea99/luci-app-passwall/luasrc/model/cbi/passwall/client/type/2_xray.lua#L661-L664)

```lua
o = s:option(Value, "grpc_health_check_timeout", translate("Health check timeout"))
o.default = "20"
o:depends({ grpc_health_check = true })

```

## type/2_xray.lua: `grpc_permit_without_stream`

[Источник 665–668](https://github.com/Openwrt-Passwall/openwrt-passwall/blob/409d28cc7d7d2d806039bf03f7ebf4724c03ea99/luci-app-passwall/luasrc/model/cbi/passwall/client/type/2_xray.lua#L665-L668)

```lua
o = s:option(Flag, "grpc_permit_without_stream", translate("Permit without stream"))
o.default = "0"
o:depends({ grpc_health_check = true })

```

## type/2_xray.lua: `grpc_initial_windows_size`

[Источник 669–673](https://github.com/Openwrt-Passwall/openwrt-passwall/blob/409d28cc7d7d2d806039bf03f7ebf4724c03ea99/luci-app-passwall/luasrc/model/cbi/passwall/client/type/2_xray.lua#L669-L673)

```lua
o = s:option(Value, "grpc_initial_windows_size", translate("Initial Windows Size"))
o.default = "0"
o:depends({ transport = "grpc" })

-- [[ HttpUpgrade部分 ]]--
```

## type/2_xray.lua: `httpupgrade_host`

[Источник 674–676](https://github.com/Openwrt-Passwall/openwrt-passwall/blob/409d28cc7d7d2d806039bf03f7ebf4724c03ea99/luci-app-passwall/luasrc/model/cbi/passwall/client/type/2_xray.lua#L674-L676)

```lua
o = s:option(Value, "httpupgrade_host", translate("HttpUpgrade Host"))
o:depends({ transport = "httpupgrade" })

```

## type/2_xray.lua: `httpupgrade_path`

[Источник 677–681](https://github.com/Openwrt-Passwall/openwrt-passwall/blob/409d28cc7d7d2d806039bf03f7ebf4724c03ea99/luci-app-passwall/luasrc/model/cbi/passwall/client/type/2_xray.lua#L677-L681)

```lua
o = s:option(Value, "httpupgrade_path", translate("HttpUpgrade Path"))
o.placeholder = "/"
o:depends({ transport = "httpupgrade" })

-- [[ XHTTP部分 ]]--
```

## type/2_xray.lua: `xhttp_mode`

[Источник 682–689](https://github.com/Openwrt-Passwall/openwrt-passwall/blob/409d28cc7d7d2d806039bf03f7ebf4724c03ea99/luci-app-passwall/luasrc/model/cbi/passwall/client/type/2_xray.lua#L682-L689)

```lua
o = s:option(ListValue, "xhttp_mode", "XHTTP " .. translate("Mode"))
o:depends({ transport = "xhttp" })
o.default = "auto"
o:value("auto")
o:value("packet-up")
o:value("stream-up")
o:value("stream-one")

```

## type/2_xray.lua: `xhttp_host`

[Источник 690–692](https://github.com/Openwrt-Passwall/openwrt-passwall/blob/409d28cc7d7d2d806039bf03f7ebf4724c03ea99/luci-app-passwall/luasrc/model/cbi/passwall/client/type/2_xray.lua#L690-L692)

```lua
o = s:option(Value, "xhttp_host", translate("XHTTP Host"))
o:depends({ transport = "xhttp" })

```

## type/2_xray.lua: `xhttp_path`

[Источник 693–696](https://github.com/Openwrt-Passwall/openwrt-passwall/blob/409d28cc7d7d2d806039bf03f7ebf4724c03ea99/luci-app-passwall/luasrc/model/cbi/passwall/client/type/2_xray.lua#L693-L696)

```lua
o = s:option(Value, "xhttp_path", translate("XHTTP Path"))
o.placeholder = "/"
o:depends({ transport = "xhttp" })

```

## type/2_xray.lua: `use_xhttp_extra`

[Источник 697–700](https://github.com/Openwrt-Passwall/openwrt-passwall/blob/409d28cc7d7d2d806039bf03f7ebf4724c03ea99/luci-app-passwall/luasrc/model/cbi/passwall/client/type/2_xray.lua#L697-L700)

```lua
o = s:option(Flag, "use_xhttp_extra", translate("XHTTP Extra"))
o.default = "0"
o:depends({ transport = "xhttp" })

```

## type/2_xray.lua: `xhttp_extra`

[Источник 701–740](https://github.com/Openwrt-Passwall/openwrt-passwall/blob/409d28cc7d7d2d806039bf03f7ebf4724c03ea99/luci-app-passwall/luasrc/model/cbi/passwall/client/type/2_xray.lua#L701-L740)

```lua
o = s:option(TextValue, "xhttp_extra", "　", translate("An XHttpObject in JSON format, used for sharing."))
o:depends({ use_xhttp_extra = true })
o.rows = 10
o.wrap = "off"
o.datatype = "json"
local o_validate = o.validate
o.validate = function(self, value)
	value = api.trim(value):gsub("\r\n", "\n"):gsub("^[ \t]*\n", ""):gsub("\n[ \t]*$", ""):gsub("\n[ \t]*\n", "\n")
	local v = o_validate(self, value)
	if v then return v end
	return nil, "XHTTP Extra " .. translate("Must be JSON text!")
end
o.cfgvalue = function(self, section, value)
	local raw = m:get(section, "xhttp_extra")
	if raw then
		return api.base64Decode(raw)
	end
end
o.write = function(self, section, value)
	m:set(section, "xhttp_extra", api.base64Encode(value) or "")
	local success, data = pcall(api.jsonc.parse, value)
	if success and data then
		local address = (data.extra and data.extra.downloadSettings and data.extra.downloadSettings.address)
			or (data.downloadSettings and data.downloadSettings.address)
		if address and address ~= "" then
			address = address:gsub("^%[", ""):gsub("%]$", "")
			m:set(section, "download_address", address)
		else
			m:del(section, "download_address")
		end
	else
		m:del(section, "download_address")
	end
end
o.remove = function(self, section, value)
	m:del(section, "xhttp_extra")
	m:del(section, "download_address")
end

-- [[ User-Agent ]]--
```

## type/2_xray.lua: `user_agent`

[Источник 741–757](https://github.com/Openwrt-Passwall/openwrt-passwall/blob/409d28cc7d7d2d806039bf03f7ebf4724c03ea99/luci-app-passwall/luasrc/model/cbi/passwall/client/type/2_xray.lua#L741-L757)

```lua
o = s:option(Value, "user_agent", translate("User-Agent"))
o.default = ""
o:value("", translate("default"))
o:value("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.131 Safari/537.36", "chrome")
o:value("Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:90.0) Gecko/20100101 Firefox/90.0", "firefox")
o:value("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15", "safari")
o:value("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 Edg/91.0.864.70", "edge")
o:value("Go-http-client/1.1", "golang")
o:value("curl/7.68.0", "curl")
o:depends({ tcp_guise = "http" })
o:depends({ transport = "ws" })
o:depends({ transport = "httpupgrade" })
o:depends({ transport = "xhttp" })
o:depends({ transport = "grpc" })
o:depends({ protocol = "masque" })

-- [[ Mux.Cool ]]--
```

## type/2_xray.lua: `mux`

[Источник 758–768](https://github.com/Openwrt-Passwall/openwrt-passwall/blob/409d28cc7d7d2d806039bf03f7ebf4724c03ea99/luci-app-passwall/luasrc/model/cbi/passwall/client/type/2_xray.lua#L758-L768)

```lua
o = s:option(Flag, "mux", "Mux", translate("Enable Mux.Cool"))
o:depends({ protocol = "vmess" })
o:depends({ protocol = "vless", transport = "raw" })
o:depends({ protocol = "vless", transport = "ws" })
o:depends({ protocol = "vless", transport = "grpc" })
o:depends({ protocol = "vless", transport = "httpupgrade" })
o:depends({ protocol = "http" })
o:depends({ protocol = "socks" })
o:depends({ protocol = "shadowsocks" })
o:depends({ protocol = "trojan" })

```

## type/2_xray.lua: `mux_concurrency`

[Источник 769–772](https://github.com/Openwrt-Passwall/openwrt-passwall/blob/409d28cc7d7d2d806039bf03f7ebf4724c03ea99/luci-app-passwall/luasrc/model/cbi/passwall/client/type/2_xray.lua#L769-L772)

```lua
o = s:option(Value, "mux_concurrency", translate("Mux concurrency"))
o.default = -1
o:depends({ mux = true })

```

## type/2_xray.lua: `xudp_concurrency`

[Источник 773–777](https://github.com/Openwrt-Passwall/openwrt-passwall/blob/409d28cc7d7d2d806039bf03f7ebf4724c03ea99/luci-app-passwall/luasrc/model/cbi/passwall/client/type/2_xray.lua#L773-L777)

```lua
o = s:option(Value, "xudp_concurrency", translate("XUDP Mux concurrency"))
o.default = 8
o:depends({ mux = true })

--[[FinalMask]]
```

## type/2_xray.lua: `use_finalmask`

[Источник 778–787](https://github.com/Openwrt-Passwall/openwrt-passwall/blob/409d28cc7d7d2d806039bf03f7ebf4724c03ea99/luci-app-passwall/luasrc/model/cbi/passwall/client/type/2_xray.lua#L778-L787)

```lua
o = s:option(Flag, "use_finalmask", "FinalMask")
o.default = "0"
o:depends({ protocol = "vmess" })
o:depends({ protocol = "vless" })
o:depends({ protocol = "trojan" })
o:depends({ protocol = "shadowsocks" })
o:depends({ protocol = "wireguard" })
o:depends({ protocol = "hysteria2", hysteria2_realms = false })
o:depends({ protocol = "masque" })

```

## type/2_xray.lua: `finalmask`

[Источник 788–812](https://github.com/Openwrt-Passwall/openwrt-passwall/blob/409d28cc7d7d2d806039bf03f7ebf4724c03ea99/luci-app-passwall/luasrc/model/cbi/passwall/client/type/2_xray.lua#L788-L812)

```lua
o = s:option(TextValue, "finalmask", "　")
o:depends({ use_finalmask = true })
o.rows = 10
o.wrap = "off"
o.description = translate("An FinalMaskObject in JSON format, used for sharing.") .. "<br>" ..
		translate("Custom finalmask overrides mkcp, hysteria2, fragment, noise, and related settings.")
o.datatype = "json"
local o_validate = o.validate
o.validate = function(self, value)
	value = api.trim(value):gsub("\r\n", "\n"):gsub("^[ \t]*\n", ""):gsub("\n[ \t]*$", ""):gsub("\n[ \t]*\n", "\n")
	local v = o_validate(self, value)
	if v then return v end
	return nil, "FinalMask " .. translate("Must be JSON text!")
end
o.cfgvalue = function(self, section, value)
	local raw = m:get(section, "finalmask")
	if raw then
		return api.base64Decode(raw)
	end
end
o.write = function(self, section, value)
	m:set(section, "finalmask", api.base64Encode(value) or "")
end

--[[Fast Open]]
```

## type/2_xray.lua: `tcp_fast_open`

[Источник 813–816](https://github.com/Openwrt-Passwall/openwrt-passwall/blob/409d28cc7d7d2d806039bf03f7ebf4724c03ea99/luci-app-passwall/luasrc/model/cbi/passwall/client/type/2_xray.lua#L813-L816)

```lua
o = s:option(Flag, "tcp_fast_open", "TCP " .. translate("Fast Open"), translate("Need node support required"))
o.default = 0

--[[tcpMptcp]]
```

## type/2_xray.lua: `tcpMptcp`

[Источник 817–819](https://github.com/Openwrt-Passwall/openwrt-passwall/blob/409d28cc7d7d2d806039bf03f7ebf4724c03ea99/luci-app-passwall/luasrc/model/cbi/passwall/client/type/2_xray.lua#L817-L819)

```lua
o = s:option(Flag, "tcpMptcp", "tcpMptcp", translate("Enable Multipath TCP, need to be enabled in both server and client configuration."))
o.default = 0

```

## type/2_xray.lua: `domain_resolver`

[Источник 820–827](https://github.com/Openwrt-Passwall/openwrt-passwall/blob/409d28cc7d7d2d806039bf03f7ebf4724c03ea99/luci-app-passwall/luasrc/model/cbi/passwall/client/type/2_xray.lua#L820-L827)

```lua
o = s:option(ListValue, "domain_resolver", translate("Domain DNS Resolve"))
o.description = translate("If the node address is a domain name, this DNS will be used for resolution.") .. "<br>" .. string.format('<font color="red">%s</font>',
		translate("Note: For node-specific DNS only. Keep Auto to avoid extra overhead."))
o:value("", translate("Auto"))
o:value("tcp", "TCP")
o:value("udp", "UDP")
o:value("https", "DoH")

```

## type/2_xray.lua: `domain_resolver_dns`

[Источник 828–835](https://github.com/Openwrt-Passwall/openwrt-passwall/blob/409d28cc7d7d2d806039bf03f7ebf4724c03ea99/luci-app-passwall/luasrc/model/cbi/passwall/client/type/2_xray.lua#L828-L835)

```lua
o = s:option(Value, "domain_resolver_dns", "DNS")
o.datatype = "or(ipaddr,ipaddrport)"
o:value("114.114.114.114")
o:value("223.5.5.5:53")
o.default = o.keylist[1]
o:depends({ domain_resolver = "tcp" })
o:depends({ domain_resolver = "udp" })

```

## type/2_xray.lua: `domain_resolver_dns_https`

[Источник 836–841](https://github.com/Openwrt-Passwall/openwrt-passwall/blob/409d28cc7d7d2d806039bf03f7ebf4724c03ea99/luci-app-passwall/luasrc/model/cbi/passwall/client/type/2_xray.lua#L836-L841)

```lua
o = s:option(Value, "domain_resolver_dns_https", "DNS")
o:value("https://120.53.53.53/dns-query", "DNSPod")
o:value("https://223.5.5.5/dns-query", "AliDNS")
o.default = o.keylist[1]
o:depends({ domain_resolver = "https" })

```

## type/2_xray.lua: `domain_strategy`

[Источник 842–849](https://github.com/Openwrt-Passwall/openwrt-passwall/blob/409d28cc7d7d2d806039bf03f7ebf4724c03ea99/luci-app-passwall/luasrc/model/cbi/passwall/client/type/2_xray.lua#L842-L849)

```lua
o = s:option(ListValue, "domain_strategy", translate("Domain Strategy"), translate("If is domain name, The requested domain name will be resolved to IP before connect."))
o.default = ""
o:value("", translate("Auto"))
o:value("UseIPv4v6", translate("Prefer IPv4"))
o:value("UseIPv6v4", translate("Prefer IPv6"))
o:value("UseIPv4", translate("IPv4 Only"))
o:value("UseIPv6", translate("IPv6 Only"))

```

## type/2_xray.lua: `happy_eyeballs`

[Источник 850–936](https://github.com/Openwrt-Passwall/openwrt-passwall/blob/409d28cc7d7d2d806039bf03f7ebf4724c03ea99/luci-app-passwall/luasrc/model/cbi/passwall/client/type/2_xray.lua#L850-L936)

```lua
o = s:option(Flag, "happy_eyeballs", translate("Enable Happy Eyeballs"), translate("Attempts IPv4 and IPv6 simultaneously; automatically uses the faster connection."))
o.default = 0

local protocols = s.fields["protocol"].keylist
if #protocols > 0 then
	for i, v in ipairs(protocols) do
		if not v:find("^_") then
			local depends_condition = { protocol = v }
			if v == "hysteria2" then
				depends_condition["hysteria2_realms"] = false
			end
			s.fields["address"]:depends(depends_condition)
			s.fields["port"]:depends(depends_condition)
			s.fields["domain_resolver"]:depends(depends_condition)
			s.fields["happy_eyeballs"]:depends(depends_condition)

			local strategy_depends = api.clone(depends_condition)
			strategy_depends["happy_eyeballs"] = false
			s.fields["domain_strategy"]:depends(strategy_depends)

			if v ~= "hysteria2" then
				s.fields["tcp_fast_open"]:depends({ protocol = v })
				s.fields["tcpMptcp"]:depends({ protocol = v })
			end
		end
	end
end
end
-- [[ Normal single node End ]]

if not load_shunt_options then
	o = s:option(ListValue, "chain_proxy", translate("Chain Proxy"))
	o:value("", translate("Close(Not use)"))
	if not (load_iface_options or load_balancing_options) then
		-- Special node cannot be use pre-proxy.
		o:value("1", translate("Preproxy Node"))
		o:value("3", translate("Outbound Interface"))
	end
	o:value("2", translate("Landing Node"))

	o1 = s:option(ListValue, "preproxy_node", translate("Preproxy Node"), translate("Only support a layer of proxy."))
	o1:depends({ chain_proxy = "1", hysteria2_realms = false })
	o1.template = m:template_path("/cbi/nodes_listvalue")
	o1.group = {}

	o3 = s:option(Value, "outbound_iface", translate("Outbound Interface"))
	o3:depends({ chain_proxy = "3" })
	o3:value("", translate("All"))
	for _, d in ipairs(netdev_list) do
		o3:value(d.name, d.label)
	end

	o2 = s:option(ListValue, "to_node", translate("Landing Node"), translate("Only support a layer of proxy."))
	o2:depends({ chain_proxy = "2", hysteria2_realms = false })
	o2.template = m:template_path("/cbi/nodes_listvalue")
	o2.group = {}

	for k1, v1 in pairs(node_list) do
		if k1 ~= "shunt_list" and k1 ~= "iface_list" then
			for i, v in ipairs(v1) do
				if v.id ~= s.section then
					o1:value(v.id, v.remark)
					o1.group[#o1.group+1] = (v.group and v.group ~= "") and v.group or translate("default")
					if k1 == "normal_list" then
						-- Landing Node not support use special node.
						o2:value(v.id, v.remark)
						o2.group[#o2.group+1] = (v.group and v.group ~= "") and v.group or translate("default")
					end
				end
			end
		end
	end
end

api.type_cbi_section(s1, s)

if load_shunt_options then
	local current_node = m:get(arg[1]) or {}
	local shunt_lua = loadfile("/usr/lib/lua/luci/model/cbi/passwall/client/include/shunt_options.lua")
	setfenv(shunt_lua, getfenv(1))(m, s1, {
		node = {
			[".name"] = s.section,
			type = type_name,
		},
		node_list = node_list,
	})
end
```

## type/0_socks.lua: `del_protocol`

[Источник 21–24](https://github.com/Openwrt-Passwall/openwrt-passwall/blob/409d28cc7d7d2d806039bf03f7ebf4724c03ea99/luci-app-passwall/luasrc/model/cbi/passwall/client/type/0_socks.lua#L21-L24)

```lua
o = s:option(ListValue, "del_protocol", "��") --ʼ�����أ�����ɾ�� protocol
o:depends({ __hide = "1" })
o.rewrite_option = "protocol"

```

## type/0_socks.lua: `address`

[Источник 25–26](https://github.com/Openwrt-Passwall/openwrt-passwall/blob/409d28cc7d7d2d806039bf03f7ebf4724c03ea99/luci-app-passwall/luasrc/model/cbi/passwall/client/type/0_socks.lua#L25-L26)

```lua
o = s:option(Value, "address", translate("Address (Support Domain Name)"))

```

## type/0_socks.lua: `port`

[Источник 27–29](https://github.com/Openwrt-Passwall/openwrt-passwall/blob/409d28cc7d7d2d806039bf03f7ebf4724c03ea99/luci-app-passwall/luasrc/model/cbi/passwall/client/type/0_socks.lua#L27-L29)

```lua
o = s:option(Value, "port", translate("Port"))
o.datatype = "port"

```

## type/0_socks.lua: `username`

[Источник 30–31](https://github.com/Openwrt-Passwall/openwrt-passwall/blob/409d28cc7d7d2d806039bf03f7ebf4724c03ea99/luci-app-passwall/luasrc/model/cbi/passwall/client/type/0_socks.lua#L30-L31)

```lua
o = s:option(Value, "username", translate("Username"))

```

## type/0_socks.lua: `password`

[Источник 32–34](https://github.com/Openwrt-Passwall/openwrt-passwall/blob/409d28cc7d7d2d806039bf03f7ebf4724c03ea99/luci-app-passwall/luasrc/model/cbi/passwall/client/type/0_socks.lua#L32-L34)

```lua
o = s:option(Value, "password", translate("Password"))
o.password = true

```

## Дополнение: вложенные chain-поля и построение вариантов

Первичная механическая выборка пропустила объявления с отступом; полный блок добавлен после проверки покрытия. [Источник](https://github.com/Openwrt-Passwall/openwrt-passwall/blob/409d28cc7d7d2d806039bf03f7ebf4724c03ea99/luci-app-passwall/luasrc/model/cbi/passwall/client/type/2_xray.lua#L882-L936). Поля: `chain_proxy`, `preproxy_node`, `outbound_iface`, `to_node`.

```lua
	o:value("", translate("Close(Not use)"))
	if not (load_iface_options or load_balancing_options) then
		-- Special node cannot be use pre-proxy.
		o:value("1", translate("Preproxy Node"))
		o:value("3", translate("Outbound Interface"))
	end
	o:value("2", translate("Landing Node"))

	o1 = s:option(ListValue, "preproxy_node", translate("Preproxy Node"), translate("Only support a layer of proxy."))
	o1:depends({ chain_proxy = "1", hysteria2_realms = false })
	o1.template = m:template_path("/cbi/nodes_listvalue")
	o1.group = {}

	o3 = s:option(Value, "outbound_iface", translate("Outbound Interface"))
	o3:depends({ chain_proxy = "3" })
	o3:value("", translate("All"))
	for _, d in ipairs(netdev_list) do
		o3:value(d.name, d.label)
	end

	o2 = s:option(ListValue, "to_node", translate("Landing Node"), translate("Only support a layer of proxy."))
	o2:depends({ chain_proxy = "2", hysteria2_realms = false })
	o2.template = m:template_path("/cbi/nodes_listvalue")
	o2.group = {}

	for k1, v1 in pairs(node_list) do
		if k1 ~= "shunt_list" and k1 ~= "iface_list" then
			for i, v in ipairs(v1) do
				if v.id ~= s.section then
					o1:value(v.id, v.remark)
					o1.group[#o1.group+1] = (v.group and v.group ~= "") and v.group or translate("default")
					if k1 == "normal_list" then
						-- Landing Node not support use special node.
						o2:value(v.id, v.remark)
						o2.group[#o2.group+1] = (v.group and v.group ~= "") and v.group or translate("default")
					end
				end
			end
		end
	end
end

api.type_cbi_section(s1, s)

if load_shunt_options then
	local current_node = m:get(arg[1]) or {}
	local shunt_lua = loadfile("/usr/lib/lua/luci/model/cbi/passwall/client/include/shunt_options.lua")
	setfenv(shunt_lua, getfenv(1))(m, s1, {
		node = {
			[".name"] = s.section,
			type = type_name,
		},
		node_list = node_list,
	})
end
```
