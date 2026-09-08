#pragma once
// AVPN (IPv6-волна 2026-09-08): «есть ли ГЛОБАЛЬНЫЙ IPv6 у самой сети пользователя, мимо
// туннеля». Чистая логика без I/O — юнит tests/ipv6_presence_check.cpp; срез интерфейсов
// собирает вызывающий (AvpnEngineQml::detectLanIpv6 через QNetworkInterface).
//
// ЗАЧЕМ. Туннель у нас v4-only: клиент забирает `::/0` и роняет его без v6-источника
// (CONNECT-INVARIANTS §24). Для человека на сети БЕЗ IPv6 это ничего не меняет и говорить не о
// чем; на сети С IPv6 — единственное объяснение, почему v6-only адресат вдруг недостижим.
// Поэтому Доктор произносит фразу про IPv6 ровно тогда, когда она несёт смысл.
//
// ❌ НЕ считать «сетью пользователя» адреса на туннельных интерфейсах: десктоп-демон вешает на
// utun ULA-заглушку `fd58:baa6:dead::1`, а v6-egress-профиль (когда он появится) повесит туда
// НАСТОЯЩИЙ глобальный адрес — и Доктор начнёт рапортовать о своём же туннеле как о сети.

#include <QHostAddress>
#include <QList>
#include <QPair>
#include <QString>

namespace avpn {

// Глобальный юникаст IPv6 = 2000::/3. Всё остальное (ULA fc00::/7, link-local fe80::/10,
// loopback, multicast, unspecified, любой v4) — НЕ признак «интернет доступен по v6».
inline bool isGlobalUnicastV6(const QString &addr)
{
    if (addr.isEmpty())
        return false;
    // QHostAddress не принимает scope-суффикс (`%en0`) — QNetworkInterface его отдаёт.
    const QString bare = addr.section(QLatin1Char('%'), 0, 0);
    const QHostAddress host(bare);
    if (host.protocol() != QAbstractSocket::IPv6Protocol)
        return false;
    const Q_IPV6ADDR raw = host.toIPv6Address();
    return (raw[0] & 0xE0) == 0x20;
}

// Туннельные интерфейсы по имени. Список намеренно широкий: чужой VPN на устройстве — тоже не
// «сеть пользователя». `wlan0` не должен попасть под `wg` — сравниваем префикс с цифрой/концом.
inline bool isTunnelIfaceName(const QString &name)
{
    if (name.isEmpty())
        return false;
    const QString n = name.toLower();
    static const char *const kPrefixes[] = {"utun", "tun", "tap", "ppp", "ipsec", "wg", "gpd"};
    for (const char *p : kPrefixes) {
        const QString prefix = QString::fromLatin1(p);
        if (!n.startsWith(prefix))
            continue;
        if (n.size() == prefix.size())
            return true;
        const QChar next = n.at(prefix.size());
        if (next.isDigit())
            return true;
    }
    return false;
}

// Срез (имя интерфейса, адрес) -> 1 у сети есть глобальный v6 мимо туннеля, иначе 0.
// Возвращаем int, а не bool: у вызывающего есть третье состояние -1 «не проверяли» (сторож
// стадии Доктора успел сработать), и оно едет в отчёт как отсутствие поля.
inline int hasOffTunnelGlobalV6(const QList<QPair<QString, QString>> &ifaceAddrs)
{
    for (const auto &pair : ifaceAddrs) {
        if (isTunnelIfaceName(pair.first))
            continue;
        if (isGlobalUnicastV6(pair.second))
            return 1;
    }
    return 0;
}

} // namespace avpn
