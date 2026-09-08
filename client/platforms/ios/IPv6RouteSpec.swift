import Foundation
import Network

// AVPN (IPv6-волна 2026-09-08): v6-близнец IPv4RouteSpec.
//
// NEIPv6Route, как и NEIPv4Route, требует СЕТЕВОЙ адрес префикса (не произвольный хост внутри
// него) и не принимает ни v4-строку, ни scope (`%en0`) — маршрут не имеет интерфейсной области.
// Держим преобразование в одном тестируемом месте: v6-половина RU-split на xray-пути NE кормится
// теми же 2174 префиксами `ru_prefixes.h`, что и AWG-путь, а они приходят в РАЗВЁРНУТОЙ форме
// (`2001:0640:0000:...:0000/32`) — NEIPv6Route ждёт канон RFC 5952.
struct IPv6RouteSpec: Equatable {
    let destinationAddress: String
    let networkPrefixLength: Int

    init?(cidr: String) {
        let parts = cidr.split(separator: "/", omittingEmptySubsequences: false)
        guard parts.count == 2,
              !parts[0].contains("%"),
              let address = IPv6Address(String(parts[0])),
              let prefixLength = Int(parts[1]),
              prefixLength >= 0, prefixLength <= 128 else {
            return nil
        }

        var bytes = [UInt8](address.rawValue)
        guard bytes.count == 16 else { return nil }
        for index in 0..<16 {
            let bitsKept = prefixLength - index * 8
            if bitsKept >= 8 { continue }
            bytes[index] = bitsKept <= 0
                ? 0
                : bytes[index] & UInt8(truncatingIfNeeded: 0xFF << (8 - bitsKept))
        }

        guard let network = IPv6Address(Data(bytes)) else { return nil }
        destinationAddress = "\(network)"
        networkPrefixLength = prefixLength
    }
}
