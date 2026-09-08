// AVPN (IPv6-волна 2026-09-08): юнит чистой логики Ipv6Presence.h — «есть ли у САМОЙ СЕТИ
// пользователя глобальный IPv6, мимо туннеля». Ответ нужен Доктору: только на такой сети
// формулировка «IPv6 отключён на время VPN» несёт смысл. Запуск: tests/build_ipv6_presence.sh.
#include "../Ipv6Presence.h"

#include <cstdio>

static int g_fail = 0;
#define CHECK(cond, msg)                                                     \
    do {                                                                     \
        if (!(cond)) { std::printf("FAIL: %s\n", msg); ++g_fail; }           \
        else         { std::printf("ok:   %s\n", msg); }                     \
    } while (0)

int main()
{
    using namespace avpn;

    // --- классификация адреса: глобальный юникаст = 2000::/3 и только он
    CHECK(isGlobalUnicastV6(QStringLiteral("2a02:8071:6480:df00::1")),
          "v6: адрес провайдера — глобальный");
    CHECK(isGlobalUnicastV6(QStringLiteral("2001:640::")),
          "v6: 2001::/16 — глобальный");
    CHECK(!isGlobalUnicastV6(QStringLiteral("fd58:baa6:dead::1")),
          "v6: ULA-заглушка десктоп-демона НЕ глобальный (иначе Доктор соврёт про свой же туннель)");
    CHECK(!isGlobalUnicastV6(QStringLiteral("fe80::e0e7:c128:978b:7d9a")),
          "v6: link-local не глобальный");
    CHECK(!isGlobalUnicastV6(QStringLiteral("::1")), "v6: loopback не глобальный");
    CHECK(!isGlobalUnicastV6(QStringLiteral("::")), "v6: unspecified не глобальный");
    CHECK(!isGlobalUnicastV6(QStringLiteral("ff02::1")), "v6: multicast не глобальный");
    CHECK(!isGlobalUnicastV6(QStringLiteral("192.168.1.10")), "v6: v4-адрес не глобальный v6");
    CHECK(!isGlobalUnicastV6(QString()), "v6: пустая строка не адрес");
    CHECK(!isGlobalUnicastV6(QStringLiteral("не адрес")), "v6: мусор не адрес");
    CHECK(isGlobalUnicastV6(QStringLiteral("2a02:8071:6480:df00::1%en0")),
          "v6: scope-суффикс интерфейса не мешает классификации");

    // --- имена туннельных интерфейсов: их адреса НЕ считаются «сетью пользователя»
    CHECK(isTunnelIfaceName(QStringLiteral("utun5")), "iface: utun — туннель");
    CHECK(isTunnelIfaceName(QStringLiteral("tun0")), "iface: tun — туннель");
    CHECK(isTunnelIfaceName(QStringLiteral("wg0")), "iface: wg — туннель");
    CHECK(isTunnelIfaceName(QStringLiteral("ipsec1")), "iface: ipsec — туннель");
    CHECK(isTunnelIfaceName(QStringLiteral("ppp0")), "iface: ppp — туннель");
    CHECK(isTunnelIfaceName(QStringLiteral("TUN2")), "iface: регистр не важен");
    CHECK(!isTunnelIfaceName(QStringLiteral("en0")), "iface: en0 — физический");
    CHECK(!isTunnelIfaceName(QStringLiteral("pdp_ip0")), "iface: сотовый — физический");
    CHECK(!isTunnelIfaceName(QStringLiteral("wlan0")), "iface: wlan0 — физический (не путать с wg)");
    CHECK(!isTunnelIfaceName(QString()), "iface: пустое имя — не туннель");

    // --- сводный вердикт по срезу интерфейсов
    using Pairs = QList<QPair<QString, QString>>;
    CHECK(hasOffTunnelGlobalV6(Pairs{}) == 0,
          "срез: пусто -> 0 (v6 у сети нет)");
    CHECK(hasOffTunnelGlobalV6(Pairs{{QStringLiteral("en0"), QStringLiteral("192.168.1.10")},
                                     {QStringLiteral("en0"), QStringLiteral("fe80::1")}}) == 0,
          "срез: только v4 + link-local -> 0");
    CHECK(hasOffTunnelGlobalV6(Pairs{{QStringLiteral("en0"), QStringLiteral("2a02:8071::5")}}) == 1,
          "срез: глобальный v6 на физическом интерфейсе -> 1");
    CHECK(hasOffTunnelGlobalV6(Pairs{{QStringLiteral("utun5"), QStringLiteral("2a02:8071::5")}}) == 0,
          "срез: глобальный v6 ТОЛЬКО на туннеле -> 0 (это наш адрес, не сеть пользователя)");
    CHECK(hasOffTunnelGlobalV6(Pairs{{QStringLiteral("utun5"), QStringLiteral("fd58:baa6:dead::1")},
                                     {QStringLiteral("en0"), QStringLiteral("2a02:8071::5")}}) == 1,
          "срез: туннель с ULA + физический с глобальным -> 1 (реальный кейс macOS)");

    if (g_fail) { std::printf(">>> ПРОВАЛОВ: %d\n", g_fail); return 1; }
    std::printf(">>> ipv6_presence_check: все проверки зелёные\n");
    return 0;
}
