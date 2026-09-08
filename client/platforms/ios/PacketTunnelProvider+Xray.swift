import Darwin
import Foundation
import HevSocks5Tunnel
import NetworkExtension

enum XrayErrors: Error {
    case noXrayConfig
    case xrayConfigIsWrong
    case cantSaveXrayConfig
    case cantParseListenAndPort
    case cantAcquireLocalPort
    case cantSaveHevSocksConfig
    case cantRegisterSocketProtection
    // AVPN (этап D3): жизненный цикл xray-сессии — поколение/сессия TunnelRuntimeSession.
    case supersededSession
    case callbackSlotBusy
    case xrayCoreStartFailed
    case socketProtectionFailed
    case tun2socksExited
}

extension Constants {
    static let cachesDirectory: URL = {
        if let cachesDirectoryURL = FileManager.default.urls(for: .cachesDirectory,
                                                             in: .userDomainMask).first {
            return cachesDirectoryURL
        } else {
            fatalError("Unable to retrieve caches directory.")
        }
    }()
}

// AVPN (этап D3): контекст protect-колбэка ядра Xray. Сырой указатель на этот объект уходит в C
// (ctx у LibXraySetSockCallback); владеет им xraySocketCallbackRegistry провайдера, отпускается
// только после LibXraySetSockCallback(nil, nil) (XraySocketCallbackTeardown). Забор (fence)
// отсекает поздние колбэки вытесненной сессии: они не трогают сокет и не роняют новую сессию.
final class XraySocketCallbackContext {
    weak var provider: PacketTunnelProvider?
    let identity: XraySocketCallbackIdentity
    private let fence: XraySocketCallbackFence

    init(provider: PacketTunnelProvider, identity: XraySocketCallbackIdentity) {
        self.provider = provider
        self.identity = identity
        fence = XraySocketCallbackFence(identity: identity)
    }

    func invoke(fd: uintptr_t) -> Int32 {
        guard let provider else { return 0 }
        let runtime = provider.xrayRuntimeSession.snapshot()
        guard fence.accepts(currentGeneration: runtime.generation,
                            currentSessionId: runtime.sessionId) else { return 0 }
        return provider.protectXraySocket(fd: fd, identity: identity) ? 1 : 0
    }

    func deactivate(expected: XraySocketCallbackIdentity) -> Bool {
        guard fence.deactivate(expected: expected) else { return false }
        provider = nil
        return true
    }
}

extension PacketTunnelProvider {
    /// TCP port chosen by the OS on IPv6 loopback (::1), matching inbound listen address.
    private func acquireFreeLocalPort() throws -> Int {
        let fd = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP)
        guard fd != -1 else {
            throw XrayErrors.cantAcquireLocalPort
        }
        defer { close(fd) }
        var reuse: Int32 = 1
        _ = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, socklen_t(MemoryLayout<Int32>.size))
        var addr = sockaddr_in6()
        addr.sin6_len = UInt8(MemoryLayout<sockaddr_in6>.size)
        addr.sin6_family = sa_family_t(AF_INET6)
        addr.sin6_port = in_port_t(0).bigEndian
        addr.sin6_addr = in6addr_loopback
        addr.sin6_scope_id = 0
        let bindResult = withUnsafePointer(to: &addr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { p in
                bind(fd, p, socklen_t(MemoryLayout<sockaddr_in6>.size))
            }
        }
        guard bindResult == 0 else {
            throw XrayErrors.cantAcquireLocalPort
        }
        var bound = sockaddr_in6()
        var len = socklen_t(MemoryLayout<sockaddr_in6>.size)
        let gr = withUnsafeMutablePointer(to: &bound) { p in
            p.withMemoryRebound(to: sockaddr.self, capacity: 1) { bp in
                getsockname(fd, bp, &len)
            }
        }
        guard gr == 0 else {
            throw XrayErrors.cantAcquireLocalPort
        }
        return Int(bound.sin6_port.byteSwapped)
    }

    // AVPN (IPv6-волна 2026-09-08): xray-путь ОБЯЗАН забирать `::/0` — ровно как AWG-путь.
    //
    // ЗАЧЕМ. Туннель v4-only (адрес 198.18.0.1, egress ноды — v4). Раньше здесь стояло
    // `ipv6Enabled = false` и `settings.ipv6Settings = nil`, то есть NE не заявлял v6 ВООБЩЕ:
    // на dual-stack сети (домашний Wi-Fi с IPv6 у провайдера) система оставляла v6 на физическом
    // интерфейсе, и весь AAAA-трафик — Google/YouTube/Meta/Cloudflare — уходил МИМО туннеля с
    // настоящим адресом пользователя. Это классическая IPv6-утечка, ровно то, от чего защищает
    // решение #8 контракта. AWG-путь (PacketTunnelSettingsGenerator) её не имеет: у него
    // `ipv6Settings` заявлены всегда, а адресов v6 нет — см. ниже, почему это и есть защита.
    //
    // КАК. `NEIPv6Settings` с ПУСТЫМ списком адресов + default-маршрут: v6 объявлен «нашим»,
    // маршрут ведёт в туннель, но источника v6 у интерфейса нет ⇒ ядро отказывает уже на
    // `connect()` за 0.0с, пакет не покидает устройство. Happy Eyeballs (RFC 8305) мгновенно
    // уходит на IPv4 — dual-stack адресаты не замечают ничего. Цена честная и осознанная:
    // адресат ТОЛЬКО с IPv6 при включённом VPN недостижим (см. CONNECT-INVARIANTS §24).
    // ❌ НЕ выдавать сюда ULA-заглушку (`fd..::1/64`, как делает desktop-демон): с источником
    // пакет уйдёт в tun2socks, у которого v6 не настроен, и вместо мгновенного отказа получится
    // чёрная дыра с таймаутом — медленно и без объяснения.
    //
    // Kill-switch `features.xray_ipv6_capture` (default TRUE): false = прежнее поведение
    // (v6 не заявляем). Ключ отсутствует (стейл-конфиг OS-init старта) ⇒ ЗАХВАТЫВАЕМ: дефолт
    // выбран по безопасности, а не по «как было» — утечка адреса хуже недоступного v6-only хоста.
    private func applyXrayIPv6Policy(_ xrayConfig: XrayConfig,
                                     settings: NEPacketTunnelNetworkSettings) {
        guard (xrayConfig.ipv6Capture ?? 1) != 0 else {
            settings.ipv6Settings = nil
            xrayLog(.info, message: "Tribe IPv6 (xray): capture OFF (kill-switch) — v6 stays off-tunnel")
            return
        }

        let ipv6Settings = NEIPv6Settings(addresses: [], networkPrefixLengths: [])
        ipv6Settings.includedRoutes = [NEIPv6Route.default()]
        settings.ipv6Settings = ipv6Settings
        xrayLog(.info, message: "Tribe IPv6 (xray): capture ON — ::/0 into the tunnel, no v6 source")
    }

    private func applyXraySplitTunnel(_ xrayConfig: XrayConfig,
                                      settings: NEPacketTunnelNetworkSettings) {
        guard let splitTunnelType = xrayConfig.splitTunnelType else {
            return
        }

        guard let splitTunnelSites = xrayConfig.splitTunnelSites else {
            xrayLog(.error, message: "Split tunnel sites are not set")
            return
        }

        if splitTunnelType == 1 {
            var ipv4IncludedRoutes = [NEIPv4Route]()

            for allowedIPString in splitTunnelSites {
                if let allowedIP = IPv4RouteSpec(cidr: allowedIPString) {
                    ipv4IncludedRoutes.append(NEIPv4Route(
                        destinationAddress: allowedIP.destinationAddress,
                        subnetMask: allowedIP.subnetMask))
                }
            }

            settings.ipv4Settings?.includedRoutes = ipv4IncludedRoutes
            // AVPN (IPv6-волна 2026-09-08): v6-половина того же списка. Без неё include-режим
            // оставлял бы `::/0` захваченным целиком — асимметрия с v4 и с AWG-путём.
            settings.ipv6Settings?.includedRoutes = Self.ipv6Routes(from: splitTunnelSites)
        } else if splitTunnelType == 2 {
            var ipv4ExcludedRoutes = [NEIPv4Route]()

            for excludedIPString in splitTunnelSites {
                if let excludedIP = IPv4RouteSpec(cidr: excludedIPString) {
                    ipv4ExcludedRoutes.append(NEIPv4Route(
                        destinationAddress: excludedIP.destinationAddress,
                        subnetMask: excludedIP.subnetMask))
                }
            }

            settings.ipv4Settings?.excludedRoutes = ipv4ExcludedRoutes
            // AVPN (IPv6-волна 2026-09-08): RU-split кормится 8628 v4 + 2174 v6 префиксами
            // (`ru_prefixes.h`). До захвата `::/0` v6-половина была бессмысленна (v6 и так шёл
            // мимо туннеля), теперь она ОБЯЗАТЕЛЬНА: иначе рунет по AAAA уедет в туннель и
            // «Доступ к сайтам РФ» на dual-stack операторе перестанет работать — ровно тот же
            // баг, что чинил CONNECT-INVARIANTS §14.2 для AWG-пути.
            settings.ipv6Settings?.excludedRoutes = Self.ipv6Routes(from: splitTunnelSites)
        }
    }

    // Обе половины сплита фильтруют один и тот же список: v4-строки отсеет IPv6RouteSpec,
    // v6-строки — IPv4RouteSpec. Кормить NEIPv6Route развёрнутым CIDR из ru_prefixes.h нельзя,
    // ему нужен канон RFC 5952 и сетевой адрес префикса.
    private static func ipv6Routes(from cidrs: [String]) -> [NEIPv6Route] {
        cidrs.compactMap { cidr in
            guard let spec = IPv6RouteSpec(cidr: cidr) else { return nil }
            return NEIPv6Route(destinationAddress: spec.destinationAddress,
                               networkPrefixLength: NSNumber(value: spec.networkPrefixLength))
        }
    }

    // AVPN (этап D3): preservingCounters = true — рестарт по смене сети внутри той же NE-сессии
    // (PacketTunnelProvider.handle(networkChange:)): кумулятив rx/tx сохраняется, поколение
    // колбэков обновляется. Первый старт из startTunnel — false (свежая сессия).
    func startXray(preservingCounters: Bool = false,
                   completionHandler: @escaping (Error?) -> Void) {

        // Xray configuration
        guard let protocolConfiguration = self.protocolConfiguration as? NETunnelProviderProtocol,
              let providerConfiguration = protocolConfiguration.providerConfiguration,
              let configData = providerConfiguration[Constants.xrayConfigKey] as? Data else {
            xrayLog(.error, message: "Can't get xray configuration")
            completionHandler(XrayErrors.noXrayConfig)
            return
        }

        // AVPN (этап D3): новое поколение runtime-сессии — все висящие колбэки прежнего старта
        // (setTunnelNetworkSettings, tun2socks) становятся стейл и игнорируются.
        let sessionGeneration = xrayRuntimeSession.beginSession(protocolName: "xray",
                                                                preservingCounters: preservingCounters)
        // Счётчики protect живут ровно одну сессию ядра — иначе «сколько дозвонов привязано»
        // смешивает прошлый и текущий старт.
        xrayProtectCounters.reset()
        guard let callbackIdentity = XraySocketCallbackIdentity(
            generation: sessionGeneration,
            sessionId: xrayRuntimeSession.snapshot().sessionId) else {
            completionHandler(XrayErrors.supersededSession)
            return
        }
        // Стейл-счётчики прошлого запуска hev в этом же процессе NE не должны стать «трафиком»
        // новой сессии: перебазируем аккумулятор на текущее сырое значение (сброс при старте
        // движка аккумулятор переживёт как reset, дельта 0).
        xrayRuntimeSession.rebase(readHevTrafficSample(), generation: sessionGeneration)

        func fail(_ error: Error) {
            _ = xrayRuntimeSession.fail(generation: sessionGeneration)
            completionHandler(error)
        }

        // Tunnel settings
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "254.1.1.1")
        settings.mtu = 9000

        settings.ipv4Settings = {
            let settings = NEIPv4Settings(addresses: ["198.18.0.1"], subnetMasks: ["255.255.0.0"])
            settings.includedRoutes = [NEIPv4Route.default()]
            return settings
        }()
        // ipv6Settings — НЕ здесь: политика захвата v6 приходит в конфиге (xray_ipv6_capture),
        // а он декодируется ниже. См. applyXrayIPv6Policy().

        do {
            let xrayConfig = try JSONDecoder().decode(XrayConfig.self,
                                                      from: configData)

            var dnsArray = [String]()
            if let dns1 = xrayConfig.dns1 {
                dnsArray.append(dns1)
            }
            if let dns2 = xrayConfig.dns2 {
                dnsArray.append(dns2)
            }

            settings.dnsSettings = !dnsArray.isEmpty
            ? NEDNSSettings(servers: dnsArray)
            : NEDNSSettings(servers: ["1.1.1.1"])
            applyXrayIPv6Policy(xrayConfig, settings: settings)
            applyXraySplitTunnel(xrayConfig, settings: settings)

            // AVPN backend-first (Task 6): cache the network-change reconnect debounce for this tunnel
            // session (used by scheduleNetworkChangeHandling in PacketTunnelProvider.swift). Fallback
            // 1.0s matches the pre-Task-6 literal byte-for-byte when the key is absent.
            xrayNetworkChangeDebounceSeconds = xrayConfig.networkChangeDebounceMs.map { Double($0) / 1000.0 } ?? 1.0
            // AVPN seamless roaming: рестарт ядра только при смене аплинка (kill-switch
            // xray_restart_on_path_loss=1 возвращает рестарт на любую смену пути).
            xrayRestartOnPathLoss = (xrayConfig.restartOnPathLoss ?? 0) != 0
            xrayAppliedUplinkSignature = currentUplinkSignature()
            xrayLog(.info, message: "Tribe roaming (xray): restartOnPathLoss=\(xrayRestartOnPathLoss) uplink=\(xrayAppliedUplinkSignature ?? "-")")

            let xrayConfigData = xrayConfig.config.data(using: .utf8)

            guard let xrayConfigData else {
                xrayLog(.error, message: "Can't encode config to data")
                fail(XrayErrors.xrayConfigIsWrong)
                return
            }

            let jsonDict = try JSONSerialization.jsonObject(with: xrayConfigData,
                                                            options: []) as? [String: Any]

            guard var jsonDict else {
                xrayLog(.error, message: "Can't parse address and port for hevSocks")
                fail(XrayErrors.cantParseListenAndPort)
                return
            }

            let port = try acquireFreeLocalPort()
            let address = "::1"

            // Extract existing SOCKS5 credentials or generate new ones per session.
            let socksCredentials = ensureInboundAuth(jsonDict: &jsonDict, port: port, address: address)

            // AVPN (девайс-разбор 2026-09-02): без файла ядро пишет в stderr NE — то есть в никуда,
            // и REALITY-ошибки/отказы дозвона не видит никто. Кладём лог рядом с конфигом и
            // отдаём его хвост в статус (см. xrayCoreLogTail).
            attachCoreLogSink(jsonDict: &jsonDict)

            let updatedData = try JSONSerialization.data(withJSONObject: jsonDict, options: [])

            setTunnelNetworkSettings(settings) { [weak self] error in
                guard let self else {
                    completionHandler(XrayErrors.supersededSession)
                    return
                }
                // AVPN (этап D3): стоп/рестарт успел сменить поколение — этот старт стейл.
                guard self.xrayRuntimeSession.isCurrent(generation: sessionGeneration) else {
                    completionHandler(XrayErrors.supersededSession)
                    return
                }
                if let error {
                    fail(error)
                    return
                }

                self.updateActiveInterfaceIndexForCurrentPath()

                // Launch xray (protect-колбэк взводится ДО старта ядра — внутри setupAndStartXray)
                self.setupAndStartXray(configData: updatedData,
                                       callbackIdentity: callbackIdentity) { xrayError in
                    if let xrayError {
                        fail(xrayError)
                        return
                    }

                    // Launch hevSocks
                    self.setupAndRunTun2socks(configData: updatedData,
                                              address: address,
                                              port: port,
                                              username: socksCredentials.username,
                                              password: socksCredentials.password,
                                              connectTimeoutMs: xrayConfig.connectTimeoutMs,
                                              readWriteTimeoutMs: xrayConfig.readWriteTimeoutMs,
                                              callbackIdentity: callbackIdentity,
                                              completionHandler: completionHandler)
                }
            }
        } catch {
            fail(error)
            return
        }
    }

    func stopXray(completionHandler: () -> Void) {
        // AVPN (этап D3): снапшот/инвалидация поколения и нативное закрытие — под тем же gate'ом,
        // что оба плеча старта: поздний старт либо целиком успевает раньше и гасится здесь, либо
        // видит новое поколение до того, как тронуть process-global движки.
        let cleared: Bool = xrayNativeLifecycleGate.withExclusive {
            let active = xrayRuntimeSession.snapshot()
            let identity = XraySocketCallbackIdentity(generation: active.generation,
                                                      sessionId: active.sessionId)
            let stopGeneration = xrayRuntimeSession.beginStop()
            Socks5Tunnel.quit()
            let done: Bool
            if let identity, xraySocketCallbackRegistry.value(for: identity) != nil {
                done = retireXrayCallback(identity: identity, stopCore: true)
            } else {
                // Контекст не взведён (старт не дошёл до регистрации) — легаси-порядок:
                // закрыть ядро, очистить слот. StopXray без запущенного ядра = успех.
                let coreStopped = XrayNativeCStringResult.consume(LibXrayStopXray())
                let drained = XrayNativeCStringResult.consume(LibXraySetSockCallback(nil, nil))
                done = coreStopped && drained
            }
            _ = xrayRuntimeSession.transition(to: done ? .stopped : .failed,
                                              generation: stopGeneration)
            return done
        }
        if !cleared {
            xrayLog(.error, message: "Can't clear Xray socket protection callback")
        }
        completionHandler()
    }

    // AVPN (этап D3): ответ на {"action":"status"} для xray-пути — раньше NE отвечал nil и
    // приложение (IosController::checkStatus) не видело rx/tx, HealthLoop был слеп.
    // Источник — счётчики tun-интерфейса hev-socks5-tunnel (hev_socks5_tunnel_stats, API 2.6.5+):
    // hev rx = записано в tun (пришло от ноды, download) = rx_bytes контракта; hev tx = прочитано
    // из tun (уходит к ноде, upload) = tx_bytes. Кумулятив с подъёма туннеля (§17.1), строки.
    // last_handshake_time_sec = null: у xray нет рукопожатия, 0 = «неизвестно» по контракту.
    func handleXrayStatusMessage(completionHandler: ((Data?) -> Void)? = nil) {
        guard let completionHandler else { return }
        let snapshot = xrayRuntimeSession.snapshot()
        if snapshot.state == .running {
            _ = xrayRuntimeSession.record(readHevTrafficSample(), generation: snapshot.generation)
        }
        let protectStats = xrayProtectCounters.snapshot()
        var core: [String: Any] = [
            "engine": "xray",
            "tun2socks": "hev-socks5-tunnel",
            "active_interface_index": activeIfaceIdx,
            // Имя интерфейса отличает «привязались к Wi-Fi» от «привязались к своему utun» —
            // по одному индексу это неразличимо (девайс-разбор 2026-09-02).
            "active_interface_name": activeIfaceName,
            "protect_bound": protectStats.bound,
            "protect_unbound": protectStats.unbound,
            "protect_rejected": protectStats.rejected
        ]
        // Хвост лога самого ядра: REALITY-ошибки и отказы дозвона видны только там.
        if let tail = xrayCoreLogTail(), !tail.isEmpty {
            core["core_log_tail"] = tail
        }
        // Причина последнего отказа старта ядра — в тот же статус-ответ: приложение кладёт её
        // в лог и диагностику, поэтому «вечное подключение» перестаёт быть безымянным.
        if let failure = lastXrayStartFailure {
            core["last_start_failure"] = failure
        }
        let response = xrayRuntimeSession.payload(core: core)
        completionHandler(try? JSONSerialization.data(withJSONObject: response, options: []))
    }

    private func readHevTrafficSample() -> TunnelTrafficSample {
        var txPackets = 0
        var txBytes = 0
        var rxPackets = 0
        var rxBytes = 0
        hev_socks5_tunnel_stats(&txPackets, &txBytes, &rxPackets, &rxBytes)
        return TunnelTrafficSample(
            rxBytes: UInt64(max(0, rxBytes)),
            txBytes: UInt64(max(0, txBytes)),
            rxPackets: UInt64(max(0, rxPackets)),
            txPackets: UInt64(max(0, txPackets))
        )
    }

    // AVPN (этап D3): защита сокета ядра Xray от петли через собственный utun — привязка к
    // физическому интерфейсу (IP_BOUND_IF / IPV6_BOUND_IF). Первый провал ТЕРМИНАЛЕН:
    // незащищённый dial ушёл бы в туннель и молча «завис» бы коннект — честнее уронить NE
    // (приложение увидит Disconnected/Error и уйдёт в failover по своим правилам).
    func protectXraySocket(fd: uintptr_t, identity: XraySocketCallbackIdentity) -> Bool {
        let interfaceIndex = activeIfaceIdx
        if interfaceIndex == 0 {
            // Индекс физического интерфейса ещё не известен (путь сети не успел обновиться к
            // первому дозвону ядра). ВАЖНО (девайс-разбор 2026-09-02): наш диалер сделан
            // fail-closed (патч 0004 к xray-core: отказ колбэка ОТМЕНЯЕТ дозвон, апстрим же
            // просто логирует и звонит дальше). Поэтому «не знаю интерфейс» = «навсегда ни
            // одного TCP» = вечное «Подключение…». Разрешаем непривязанный дозвон: маршрут по
            // умолчанию у NE-процесса и так идёт мимо своего туннеля.
            xrayProtectCounters.countUnbound()
            xrayLog(.info, message: "Xray socket dial allowed unbound: active interface is unknown yet")
            return true
        }

        var boundInterface = interfaceIndex
        let ipv4 = setsockopt(Int32(fd), IPPROTO_IP, IP_BOUND_IF, &boundInterface,
                              socklen_t(MemoryLayout<UInt32>.size))
        let ipv6 = setsockopt(Int32(fd), IPPROTO_IPV6, IPV6_BOUND_IF, &boundInterface,
                              socklen_t(MemoryLayout<UInt32>.size))
        let protected = (ipv4 == 0 || ipv6 == 0)
        if protected {
            xrayProtectCounters.countBound()
        } else {
            // Индекс известен, а привязка не удалась — это настоящий отказ: незащищённый
            // сокет ушёл бы в собственный туннель. Гасим ровно один раз.
            xrayProtectCounters.countRejected()
            xraySocketProtectionFailed(identity: identity)
        }
        return protected
    }

    /// Путь файла лога ядра Xray (внутри каталога кешей NE, рядом с config.json).
    static var xrayCoreLogURL: URL {
        Constants.cachesDirectory.appendingPathComponent("xray-core.log", isDirectory: false)
    }

    /// Подмешивает в конфиг ядра запись лога в файл. Уровень warning: ошибки дозвона и REALITY
    /// видны, а болтовни на каждый пакет нет. Файл пересоздаётся на каждый старт — он живёт
    /// ровно одну сессию и не растёт бесконечно.
    func attachCoreLogSink(jsonDict: inout [String: Any]) {
        let url = Self.xrayCoreLogURL
        try? FileManager.default.removeItem(at: url)
        FileManager.default.createFile(atPath: url.path, contents: nil)
        var log = (jsonDict["log"] as? [String: Any]) ?? [:]
        // AVPN (diag 2026-09-03): ошибки дозвона/Reality Xray пишет на уровне info — при warning
        // core_log_tail приходил пустым и «нет трафика» было безымянным. info ловит причину.
        log["loglevel"] = "info"
        log["error"] = url.path
        jsonDict["log"] = log
    }

    /// Последние строки лога ядра для статус-ответа (ограничены, чтобы не раздувать IPC).
    func xrayCoreLogTail(maxBytes: Int = 16384, maxLines: Int = 80) -> String? {
        let url = Self.xrayCoreLogURL
        guard let handle = try? FileHandle(forReadingFrom: url) else { return nil }
        defer { try? handle.close() }
        let size = (try? handle.seekToEnd()) ?? 0
        let offset = size > UInt64(maxBytes) ? size - UInt64(maxBytes) : 0
        try? handle.seek(toOffset: offset)
        guard let data = try? handle.readToEnd(), let text = String(data: data, encoding: .utf8) else {
            return nil
        }
        let lines = text.split(separator: "\n", omittingEmptySubsequences: true).suffix(maxLines)
        return lines.isEmpty ? nil : lines.joined(separator: "\n")
    }

    private func xraySocketProtectionFailed(identity: XraySocketCallbackIdentity) {
        // fail(generation:) даёт true только первому провалу текущего поколения — гасим ровно раз.
        guard xrayRuntimeSession.fail(generation: identity.generation) else { return }
        xrayLog(.error, message: "Xray socket protection failed (iface=\(activeIfaceIdx)); cancelling tunnel")
        DispatchQueue.global().async { [weak self] in
            self?.cancelTunnelWithError(XrayErrors.socketProtectionFailed)
        }
    }

    // Точный teardown колбэка: [stopCore] -> LibXraySetSockCallback(nil, nil) (синхронный
    // drain) -> снять контекст из реестра. false = слот остаётся взведённым (fail-closed).
    @discardableResult
    private func retireXrayCallback(identity: XraySocketCallbackIdentity, stopCore: Bool) -> Bool {
        XraySocketCallbackTeardown.execute(
            stopCore: { stopCore ? XrayNativeCStringResult.consume(LibXrayStopXray()) : true },
            drain: { XrayNativeCStringResult.consume(LibXraySetSockCallback(nil, nil)) },
            retireContext: {
                guard let context = xraySocketCallbackRegistry.value(for: identity),
                      context.deactivate(expected: identity) else { return false }
                return xraySocketCallbackRegistry.remove(identity: identity) === context
            })
    }

    private struct SocksCredentials {
        let username: String
        let password: String
    }

    private func indexOfSocksInbound(in inboundsArray: [[String: Any]]) -> Int? {
        for (i, inbound) in inboundsArray.enumerated() {
            guard let proto = inbound["protocol"] as? String else { continue }
            if proto.caseInsensitiveCompare("socks") == .orderedSame {
                return i
            }
        }
        return nil
    }

    // Returns existing SOCKS5 credentials from the inbound config, or generates and injects
    // new random ones. Also sets port and address on the socks inbound entry.
    private func ensureInboundAuth(jsonDict: inout [String: Any], port: Int, address: String) -> SocksCredentials {
        var inboundsArray = jsonDict["inbounds"] as? [[String: Any]] ?? []

        if let socksIdx = indexOfSocksInbound(in: inboundsArray) {
            var inbound = inboundsArray[socksIdx]
            inbound["port"] = port
            inbound["listen"] = address

            var settings = inbound["settings"] as? [String: Any] ?? [:]
            if let accounts = settings["accounts"] as? [[String: Any]],
               let first = accounts.first,
               let user = first["user"] as? String, !user.isEmpty,
               let pass = first["pass"] as? String, !pass.isEmpty {
                // Re-use existing credentials, but always enforce auth mode in case the
                // imported config had accounts but auth: "noauth" (or no auth field).
                settings["auth"] = "password"
                inbound["settings"] = settings
                inboundsArray[socksIdx] = inbound
                jsonDict["inbounds"] = inboundsArray
                return SocksCredentials(username: user, password: pass)
            }

            // Generate new random credentials for this session
            let user = UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased().prefix(16)
            let pass = UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased()
            settings["auth"] = "password"
            settings["accounts"] = [["user": String(user), "pass": pass]]
            inbound["settings"] = settings
            inboundsArray[socksIdx] = inbound
            jsonDict["inbounds"] = inboundsArray
            return SocksCredentials(username: String(user), password: pass)
        }

        // Fallback: no socks inbound — generate credentials but can't inject
        let user = UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased().prefix(16)
        let pass = UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased()
        return SocksCredentials(username: String(user), password: pass)
    }

    private func setupAndStartXray(configData: Data,
                                   callbackIdentity: XraySocketCallbackIdentity,
                                   completionHandler: @escaping (Error?) -> Void) {
        let path = Constants.cachesDirectory.appendingPathComponent("config.json", isDirectory: false).path
        guard FileManager.default.createFile(atPath: path, contents: configData) else {
            xrayLog(.error, message: "Can't save xray configuration")
            completionHandler(XrayErrors.cantSaveXrayConfig)
            return
        }

        updateActiveInterfaceIndexForCurrentPath()

        // AVPN (этап D3): порядок под gate'ом — контекст в реестр -> LibXraySetSockCallback ->
        // LibXrayRunXray. Колбэк взведён ДО первого сокета ядра; провал любого шага откатывает
        // предыдущие (слот не остаётся взведённым на мёртвую сессию).
        let context = XraySocketCallbackContext(provider: self, identity: callbackIdentity)
        let startError: Error? = xrayNativeLifecycleGate.withExclusive {
            guard xrayRuntimeSession.isCurrent(generation: callbackIdentity.generation) else {
                return XrayErrors.supersededSession
            }
            guard xraySocketCallbackRegistry.install(context, identity: callbackIdentity) else {
                xrayLog(.error, message: "Xray socket protection slot is still held by a previous session")
                return XrayErrors.callbackSlotBusy
            }
            let ctx = Unmanaged.passUnretained(context).toOpaque()
            let cb: libxray_sockcallback = { (fd, ctx) in
                guard let ctx = ctx else { return 0 }
                return Unmanaged<XraySocketCallbackContext>.fromOpaque(ctx).takeUnretainedValue().invoke(fd: fd)
            }
            if let reason = XrayNativeCStringResult.message(LibXraySetSockCallback(cb, ctx)) {
                // Колбэк не взведён — контекст можно снять без drain'а.
                _ = context.deactivate(expected: callbackIdentity)
                _ = xraySocketCallbackRegistry.remove(identity: callbackIdentity)
                xrayLog(.error, message: "Can't register Xray socket protection callback: \(reason)")
                lastXrayStartFailure = reason
                return XrayErrors.cantRegisterSocketProtection
            }
            // Конвенция libxray (сверено с вендоренным nodep.WrapError и с Android-биндингом
            // Xray.kt): при успехе возвращается ПУСТАЯ строка, любая непустая = ошибка старта.
            // Поэтому guard строгий: мёртвое ядро не должно выглядеть «Подключено» — hev поднимется
            // и поверх мёртвого socks, а tun2socksExited в этом случае не срабатывает.
            // Причину запоминаем ДО возврата: она уезжает в статус-ответ (last_start_failure) и
            // дальше в лог/диагностику приложения — «вечное подключение» больше не безымянно.
            if let reason = XrayNativeCStringResult.message(LibXrayRunXray(nil, path, Int64.max)) {
                xrayLog(.error, message: "Xray core start failed: \(reason)")
                lastXrayStartFailure = reason
                // Слот колбэка очищаем ТОЛЬКО через drain (колбэк уже взведён), ядро не гасим.
                _ = retireXrayCallback(identity: callbackIdentity, stopCore: false)
                return XrayErrors.xrayCoreStartFailed
            }
            return nil
        }

        if let startError {
            completionHandler(startError)
            return
        }
        completionHandler(nil)
        xrayLog(.info, message: "Xray started; socket protection callback is armed")
    }

    private func setupAndRunTun2socks(configData: Data,
                                      address: String,
                                      port: Int,
                                      username: String,
                                      password: String,
                                      connectTimeoutMs: Int?,
                                      readWriteTimeoutMs: Int?,
                                      callbackIdentity: XraySocketCallbackIdentity,
                                      completionHandler: @escaping (Error?) -> Void) {
        let sessionGeneration = callbackIdentity.generation
        // AVPN backend-first (Task 6): server-tunable via XrayConfig.connectTimeoutMs/readWriteTimeoutMs
        // (TuningStore numbers.xray_connect_timeout_ms/xray_rw_timeout_ms). Fallbacks are byte-for-byte
        // the pre-Task-6 literals. task-stack-size/limit-nofile intentionally left untouched.
        let connectTimeout = connectTimeoutMs ?? 5000
        let readWriteTimeout = readWriteTimeoutMs ?? 60000
        let config = """
        tunnel:
          mtu: 9000
        socks5:
          port: \(port)
          address: \(address)
          username: \(username)
          password: \(password)
          udp: 'udp'
        misc:
          task-stack-size: 20480
          connect-timeout: \(connectTimeout)
          read-write-timeout: \(readWriteTimeout)
          log-file: stderr
          log-level: error
          limit-nofile: 65535
        """

        let configurationFilePath = Constants.cachesDirectory.appendingPathComponent("config.yml", isDirectory: false).path
        guard FileManager.default.createFile(atPath: configurationFilePath, contents: config.data(using: .utf8)!) else {
            xrayLog(.info, message: "Cant save hevSocks configuration")
            // Откат под тем же gate'ом, что и старт: нативные LibXray-вызовы наружу из него не выходят.
            xrayNativeLifecycleGate.withExclusive {
                _ = retireXrayCallback(identity: callbackIdentity, stopCore: true)
            }
            completionHandler(XrayErrors.cantSaveHevSocksConfig)
            return
        }

        // AVPN (этап D3): старт tun2socks — под gate'ом с перепроверкой поколения: стоп между
        // готовностью ядра и стартом hev не может быть догнан поздним адаптером.
        let accepted: Bool = xrayNativeLifecycleGate.withExclusive {
            guard xrayRuntimeSession.isCurrent(generation: sessionGeneration),
                  xrayRuntimeSession.transition(to: .running, generation: sessionGeneration) else {
                return false
            }
            DispatchQueue.global().async { [weak self] in
                xrayLog(.info, message: "Hev socks started")
                completionHandler(nil)
                let exitCode = Socks5Tunnel.run(withConfig: configurationFilePath)
                self?.handleTun2socksExit(exitCode, generation: sessionGeneration)
            }
            return true
        }
        guard accepted else {
            xrayNativeLifecycleGate.withExclusive {
                _ = retireXrayCallback(identity: callbackIdentity, stopCore: true)
            }
            completionHandler(XrayErrors.supersededSession)
            return
        }
    }

    // AVPN (этап D3): hev_socks5_tunnel_main вернулся. Штатный стоп уже сменил поколение
    // (beginStop) — молча выходим; выход при живом поколении = мёртвый data-plane при
    // «подключённом» NE — гасим туннель честно, а не ждём DEAD от HealthLoop.
    private func handleTun2socksExit(_ exitCode: Int32, generation: UInt64) {
        guard xrayRuntimeSession.fail(generation: generation) else { return }
        xrayLog(.error, message: "Hev socks exited unexpectedly (rc=\(exitCode)); cancelling tunnel")
        cancelTunnelWithError(XrayErrors.tun2socksExited)
    }
}
