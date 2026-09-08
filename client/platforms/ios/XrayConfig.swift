import Foundation

// AVPN backend-first (Task 6): server-tunable tun2socks timeouts + network-change reconnect debounce.
// All three are optional — absent key (old GUI-built config, or server default not seeded) decodes to
// nil, and callers fall back to the pre-Task-6 literals, so behavior is byte-for-byte unchanged for any
// config that doesn't carry these keys. Seeded from TuningStore in ios_controller.mm::setupXray()/
// setupSSXray() (client/core/serviceEngine/TuningStore.h, numbers.xray_connect_timeout_ms /
// xray_rw_timeout_ms / network_change_debounce_ms).
struct XrayConfig: Decodable {
    let dns1: String?
    let dns2: String?
    let splitTunnelType: Int?
    let splitTunnelSites: [String]?
    let config: String
    let connectTimeoutMs: Int?
    let readWriteTimeoutMs: Int?
    let networkChangeDebounceMs: Int?
    // AVPN seamless roaming (2026-09-03): 1 = старое поведение (рестарт ядра на любую значимую
    // смену пути, включая «пропал и вернулся тот же Wi-Fi»); 0/nil = рестарт ТОЛЬКО при смене
    // физического аплинка (Wi-Fi <-> сотовая), потеря и возврат того же интерфейса ядро не трогают.
    let restartOnPathLoss: Int?
    // AVPN (IPv6-волна 2026-09-08): 0 = НЕ заявлять v6 в туннеле (прежнее поведение,
    // kill-switch features.xray_ipv6_capture=false); 1/nil = забирать `::/0` в туннель без
    // v6-источника, чтобы v6 не утекал мимо VPN. nil трактуется как ЗАХВАТ — см.
    // applyXrayIPv6Policy() в PacketTunnelProvider+Xray.swift.
    let ipv6Capture: Int?

    private enum CodingKeys: String, CodingKey {
        case dns1
        case dns2
        case splitTunnelType
        case splitTunnelSites
        case config
        case connectTimeoutMs = "xray_connect_timeout_ms"
        case readWriteTimeoutMs = "xray_rw_timeout_ms"
        case networkChangeDebounceMs = "network_change_debounce_ms"
        case restartOnPathLoss = "xray_restart_on_path_loss"
        case ipv6Capture = "xray_ipv6_capture"
    }
}
