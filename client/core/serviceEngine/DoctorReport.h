#pragma once
// AVPN (Доктор, 2026-07-17): чистая логика диагностики — вердикты стадий, сборка JSON-отчёта
// и человеческое резюме. БЕЗ I/O и Qt-сети: всё тестируется юнитом (tests/doctor_report_check.cpp).
// Оркестрация (фазы/таймеры/пробы/подъём туннеля) — в AvpnEngineQml.
//
// АКТИВНАЯ модель (v2): Доктор САМ поднимает VPN и тестирует РЕАЛЬНУЮ работу через туннель
// (не пассивно смотрит на выключенный VPN). Стадии: подключение (поднять+проверить данные) →
// серверы (где/качество) → сервисы (WhatsApp/TG/YT/IG через туннель) → скорость (бенч через туннель).
// Спека: tribe-front docs/superpowers/specs/2026-07-17-doctor-v1-design.md.

#include <QJsonArray>
#include <QJsonObject>
#include <QString>
#include <QStringList>

#include <algorithm>

namespace doctor {

// Статус стадии для UI и отчёта.
enum StageStatus { Skip = -1, Ok = 0, Warn = 1, Bad = 2 };

struct StageResult {
    QString id;              // connect|servers|services|speed
    int status = Ok;         // StageStatus
    QString note;            // короткая человеческая строка для UI
    QJsonObject data;        // сырые факты стадии (в отчёт)
};

// numbers.diag_stage_timeout_ms: кламп 5с..60с (сторож фазы; стадия дольше — гасится с честным
// вердиктом, диагностика продолжается).
inline int clampStageTimeoutMs(double v)
{
    if (v != v || v <= 0)      // NaN/нет ключа
        return 25000;
    if (v < 5000)  return 5000;
    if (v > 60000) return 60000;
    return int(v);
}

// Стадия 0 (D-3): СЕТЬ КЛИЕНТА — до подъёма туннеля. Captive-портал (отель/аэропорт),
// тип сети + поколение сотовой (3G сам по себе медленный — не вина VPN), metered/roaming,
// форс-прогон дифф-проб «белых списков» (валиден ТОЛЬКО при опущенном туннеле — пробы через
// туннель врут, тогда wlForced = -1).
//   captive: -1 не проверялось | 0 нет | 1 портал (generate_204 вернул редирект/чужое тело);
//   cellGen: "5g"/"lte"/"3g"/"2g"/"" (пусто = неизвестно/не сотовая);
//   metered/roaming: -1 неизвестно | 0 | 1;
//   wlForced: -1 не гонялись | 0 сеть нормальная | 1 сигнатура «белых списков»;
//   lanIpv6:  -1 не проверяли | 0 у сети нет глобального v6 | 1 есть (Ipv6Presence.h).
//
// IPv6 (волна 2026-09-08): туннель v4-only забирает `::/0` и роняет его без v6-источника
// (CONNECT-INVARIANTS §24) — адресат ТОЛЬКО с IPv6 при включённом VPN недостижим, и системная
// ошибка («Operation not permitted») об этом не говорит НИЧЕГО. Доктор — то место, куда человек
// приходит за причиной, поэтому строку произносим здесь. Правила: (а) только когда у сети
// реально есть глобальный v6 — иначе фраза пугает без повода; (б) статус стадии НЕ портим,
// это осознанная политика, а не поломка; (в) вердикты captive/«белые списки» важнее — там note
// занят настоящей проблемой.
inline StageResult networkStage(int captive, const QString &netType, const QString &cellGen,
                                int metered, int roaming, int wlForced,
                                const QString &carrier = QString(), int lanIpv6 = -1)
{
    StageResult r; r.id = QStringLiteral("network");
    if (captive >= 0) r.data.insert(QStringLiteral("captive"), captive == 1);
    if (!netType.isEmpty()) r.data.insert(QStringLiteral("net_type"), netType);
    if (!cellGen.isEmpty()) r.data.insert(QStringLiteral("cellular_gen"), cellGen);
    if (!carrier.isEmpty()) r.data.insert(QStringLiteral("carrier"), carrier); // MCC-MNC / ручной
    if (metered >= 0) r.data.insert(QStringLiteral("metered"), metered == 1);
    if (roaming >= 0) r.data.insert(QStringLiteral("roaming"), roaming == 1);
    if (wlForced >= 0) r.data.insert(QStringLiteral("wl_forced"), wlForced == 1);
    if (lanIpv6 >= 0)  r.data.insert(QStringLiteral("ipv6_lan"), lanIpv6 == 1);

    const QString netRu = netType == QLatin1String("cellular")
            ? (cellGen.isEmpty() ? QStringLiteral("сотовая")
                                 : QStringLiteral("сотовая %1").arg(cellGen.toUpper()))
            : netType == QLatin1String("wifi")     ? QStringLiteral("Wi-Fi")
            : netType == QLatin1String("ethernet") ? QStringLiteral("проводная")
                                                   : QString();
    if (captive == 1) {
        r.status = Bad;
        r.note = QStringLiteral("Сеть требует входа — откройте браузер и залогиньтесь");
        return r;
    }
    if (wlForced == 1) {
        r.status = Bad;
        r.note = QStringLiteral("Оператор ограничивает интернет («белые списки»)");
        return r;
    }
    const bool slowGen = cellGen == QLatin1String("2g") || cellGen == QLatin1String("3g");
    if (slowGen) {
        r.status = Warn;
        r.note = QStringLiteral("Сеть %1 — медленно само по себе, не из-за VPN")
                     .arg(cellGen.toUpper());
        return r;
    }
    r.status = Ok;
    r.note = netRu.isEmpty() ? QStringLiteral("Сеть доступна")
                             : QStringLiteral("Сеть: %1").arg(netRu);
    if (roaming == 1)
        r.note += QStringLiteral(" (роуминг)");
    if (lanIpv6 == 1)
        r.note += QStringLiteral(" · IPv6 отключён на время VPN");
    return r;
}

// Стадия 1: ПОДКЛЮЧЕНИЕ (активная). Доктор поднял VPN (или он уже был поднят) и проверил,
// идут ли данные через туннель (проба + рост rx). Ловит «зелёный, но мёртвый» (S4-blackhole).
//   couldConnect — туннель поднялся до connected (или уже был);
//   dataFlows    — проба через туннель дошла (первый байт получен) ИЛИ rx подрос;
//   handshakeAgeSec — возраст последнего WG-handshake (для отчёта).
inline StageResult connectStage(bool couldConnect, bool dataFlows, qint64 handshakeAgeSec)
{
    StageResult r; r.id = QStringLiteral("connect");
    r.data.insert(QStringLiteral("could_connect"), couldConnect);
    r.data.insert(QStringLiteral("data_flows"), dataFlows);
    r.data.insert(QStringLiteral("handshake_age_sec"), double(handshakeAgeSec));
    if (!couldConnect) {
        r.status = Bad;
        r.note = QStringLiteral("Не удалось подключиться к VPN");
    } else if (!dataFlows) {
        r.status = Bad;
        r.note = QStringLiteral("Подключено, но данные не проходят");
    } else {
        r.status = Ok;
        r.note = QStringLiteral("VPN подключён — интернет работает");
    }
    return r;
}

// ISO-3166 alpha-2 → русское название страны (наш пул нод). Фолбэк — код заглавными.
inline QString countryNameRu(const QString &code)
{
    const QString cc = code.trimmed().toUpper();
    static const QHash<QString, QString> t{
        {QStringLiteral("LV"), QStringLiteral("Латвия")},
        {QStringLiteral("FI"), QStringLiteral("Финляндия")},
        {QStringLiteral("NL"), QStringLiteral("Нидерланды")},
        {QStringLiteral("DE"), QStringLiteral("Германия")},
        {QStringLiteral("US"), QStringLiteral("США")},
        {QStringLiteral("GB"), QStringLiteral("Великобритания")},
        {QStringLiteral("FR"), QStringLiteral("Франция")},
        {QStringLiteral("SE"), QStringLiteral("Швеция")},
        {QStringLiteral("PL"), QStringLiteral("Польша")},
        {QStringLiteral("RU"), QStringLiteral("Россия")},
        {QStringLiteral("TR"), QStringLiteral("Турция")},
        {QStringLiteral("CH"), QStringLiteral("Швейцария")},
        {QStringLiteral("AT"), QStringLiteral("Австрия")},
        {QStringLiteral("CA"), QStringLiteral("Канада")},
        {QStringLiteral("JP"), QStringLiteral("Япония")},
        {QStringLiteral("SG"), QStringLiteral("Сингапур")},
        {QStringLiteral("HK"), QStringLiteral("Гонконг")},
        {QStringLiteral("ES"), QStringLiteral("Испания")},
        {QStringLiteral("IT"), QStringLiteral("Италия")},
        {QStringLiteral("EE"), QStringLiteral("Эстония")},
        {QStringLiteral("LT"), QStringLiteral("Литва")},
        {QStringLiteral("NO"), QStringLiteral("Норвегия")},
        {QStringLiteral("DK"), QStringLiteral("Дания")},
        {QStringLiteral("CZ"), QStringLiteral("Чехия")},
    };
    const auto it = t.constFind(cc);
    return it != t.constEnd() ? it.value() : cc;
}

// Стадия 2: СЕРВЕРЫ. На каком сервере сидим и его отклик (live RTT через туннель / app-layer).
//   displayName — человекочитаемое имя («Латвия»); countryCode — ISO для флага в UI;
//   rttMs — отклик текущего сервера (<0 = не измерен);
//   warnMs — порог жёлтого (server-driven numbers.doctor_rtt_warn_ms; пересмотр владельца
//   2026-07-21: 470 мс до Латвии — не повод желтить, «до секунды можно зелёную»).
inline StageResult serverStage(const QString &displayName, const QString &countryCode, int rttMs,
                               int warnMs = 800)
{
    StageResult r; r.id = QStringLiteral("servers");
    if (!displayName.isEmpty()) r.data.insert(QStringLiteral("region"), displayName);
    if (!countryCode.isEmpty()) r.data.insert(QStringLiteral("country_code"), countryCode.toUpper());
    r.data.insert(QStringLiteral("rtt_ms"), rttMs);
    const QString where = displayName.isEmpty() ? QStringLiteral("Сервер")
                                                : QStringLiteral("Сервер: %1").arg(displayName);
    if (rttMs < 0) {
        r.status = Ok;
        r.note = where;
    } else if (rttMs >= warnMs) {
        r.status = Warn;
        r.note = QStringLiteral("%1 — далеко (~%2 мс)").arg(where).arg(rttMs);
    } else {
        r.status = Ok;
        r.note = QStringLiteral("%1 · ~%2 мс").arg(where).arg(rttMs);
    }
    return r;
}

// Стадия 3: СЕРВИСЫ через туннель. works/total + список недоступных (blocked). Плюс опц.
// whitelist-факт (на сотовой): whitelistActive поднимает вердикт до Bad с понятной причиной.
inline StageResult servicesStage(int works, int total, const QStringList &blocked,
                                 bool whitelistApplicable, bool whitelistActive)
{
    StageResult r; r.id = QStringLiteral("services");
    r.data.insert(QStringLiteral("works"), works);
    r.data.insert(QStringLiteral("total"), total);
    if (!blocked.isEmpty())
        r.data.insert(QStringLiteral("blocked"), QJsonArray::fromStringList(blocked));
    if (whitelistApplicable)
        r.data.insert(QStringLiteral("whitelist_active"), whitelistActive);

    if (whitelistActive) {
        r.status = Bad;
        r.note = QStringLiteral("Оператор ограничивает интернет («белые списки»)");
        return r;
    }
    if (total <= 0) {
        r.status = Skip;
        r.note = QStringLiteral("Сервисы не проверены");
    } else if (!blocked.isEmpty()) {
        r.status = Bad;
        r.note = QStringLiteral("Недоступно: %1").arg(blocked.join(QStringLiteral(", ")));
    } else {
        r.status = Ok;
        r.note = QStringLiteral("Мессенджеры и видео работают");
    }
    return r;
}

// D-3 п.18: вердикт «коллапс» по посекундному профилю download — сигнатура ТСПУ-троттлинга
// «первые секунды летит, потом душат». Среднее за замер это маскирует. Правило: пик первых
// 3 секунд >= 8 Мбит/с, дальше (без последней, возможно неполной, корзины) в среднем <= 25%
// пика И < 5 Мбит/с; профиль не короче 6 секунд.
inline bool speedCollapsed(const QList<double> &mbitPerSec)
{
    if (mbitPerSec.size() < 6) return false;
    double head = 0;
    for (int i = 0; i < 3; ++i) head = std::max(head, mbitPerSec.at(i));
    if (head < 8.0) return false;
    double tailSum = 0; int tailN = 0;
    for (int i = 3; i < mbitPerSec.size() - 1; ++i) { tailSum += mbitPerSec.at(i); ++tailN; }
    if (tailN < 2) return false;
    const double tailAvg = tailSum / tailN;
    return tailAvg <= head * 0.25 && tailAvg < 5.0;
}

// Стадия 4: СКОРОСТЬ (бенч через туннель). Пороги согласованы с BenchAnalysis
// (kLowGoodputMbit=5, bufferbloat = loaded/idle > 2.5 при idle>0).
// D-3: collapsed — вердикт speedCollapsed() по посекундному профилю (ТСПУ-сигнатура);
// directMbit — контрольный замер МИМО туннеля к RU-endpoint (<0 = не мерялся): различает
// «душат VPN» (напрямую быстро, через туннель коллапс) от «сеть сама слабая».
inline StageResult speedStage(double downMbit, int idleRttMs, int loadedRttMs,
                              bool collapsed = false, double directMbit = -1)
{
    StageResult r; r.id = QStringLiteral("speed");
    r.data.insert(QStringLiteral("down_mbit"), downMbit);
    r.data.insert(QStringLiteral("idle_rtt_ms"), idleRttMs);
    r.data.insert(QStringLiteral("loaded_rtt_ms"), loadedRttMs);
    if (collapsed) r.data.insert(QStringLiteral("collapsed"), true);
    if (directMbit >= 0) r.data.insert(QStringLiteral("direct_mbit"), directMbit);
    if (downMbit < 0) {         // стадия не мерялась (обрыв/таймаут)
        r.status = Skip;
        r.note = QStringLiteral("Замер скорости не выполнен");
        return r;
    }
    if (collapsed) {
        r.status = Bad;
        r.note = directMbit >= 8.0
            ? QStringLiteral("Скорость VPN обрезается после первых секунд (напрямую сеть быстрая)")
            : QStringLiteral("Скорость обрывается после первых секунд — похоже на ограничение оператора");
        return r;
    }
    const bool slow = downMbit < 5.0;
    if (slow && directMbit >= 0 && directMbit < 5.0) {
        r.status = Warn;
        r.note = QStringLiteral("Сеть медленная и без VPN (%1 Мбит/с) — дело не в VPN")
                     .arg(QString::number(directMbit, 'f', 1));
        return r;
    }
    // «Пухнет» — только при БОЛИ в абсолюте: loaded RTT >= 400мс (звонок разваливается)
    // И росте от покоя. Относительный порог сам по себе ложно ругал сотовые сети
    // (idle 40 -> loaded 120 = ratio 3 при отличных 30+ Мбит — это норма LTE, не проблема).
    const bool bloat = idleRttMs > 0 && loadedRttMs >= 400
                       && double(loadedRttMs) / double(idleRttMs) > 2.5;
    if (slow && bloat) {
        r.status = Bad;
        r.note = QStringLiteral("Скорость низкая, задержка под нагрузкой растёт");
    } else if (slow) {
        r.status = Warn;
        r.note = QStringLiteral("Скорость ниже комфортной (%1 Мбит/с)")
                     .arg(QString::number(downMbit, 'f', 1));
    } else if (bloat) {
        r.status = Warn;
        r.note = QStringLiteral("Канал «пухнет» под нагрузкой (%1 Мбит/с)")
                     .arg(QString::number(downMbit, 'f', 1));
    } else {
        r.status = Ok;
        r.note = QStringLiteral("Скорость в порядке: %1 Мбит/с")
                     .arg(QString::number(downMbit, 'f', 1));
    }
    return r;
}

// Стадия 4a (опциональная): ДОСТУП К САЙТАМ РФ (РФ-сплит). Пробы RU-корпуса (server-driven
// lists.rusplit_watch, фолбэк rusentinel::defaultWatch — Яндекс/Ozon/WB/Госуслуги) текущим
// путём — сплит обязан вести их напрямую. names/oks — параллельные списки проверенных сайтов.
// enabled=false — тумблер «Доступ к сайтам РФ» выключен: честный Skip с причиной (раньше фаза
// молча пропускалась и поддержка не видела, что сплит у клиента не включён вовсе).
inline StageResult ruSplitStage(const QStringList &names, const QList<bool> &oks,
                                bool enabled = true)
{
    StageResult r; r.id = QStringLiteral("rusplit");
    if (!enabled) {
        r.status = Skip;
        r.data.insert(QStringLiteral("enabled"), false);
        r.note = QStringLiteral("«Доступ к сайтам РФ» выключен — не проверялся");
        return r;
    }
    QStringList bad;
    int ok = 0;
    for (int i = 0; i < names.size() && i < oks.size(); ++i) {
        if (oks.at(i)) ++ok;
        else bad.append(names.at(i));
    }
    r.data.insert(QStringLiteral("ok"), ok);
    r.data.insert(QStringLiteral("total"), names.size());
    if (!bad.isEmpty()) r.data.insert(QStringLiteral("failed"), QJsonArray::fromStringList(bad));
    if (names.isEmpty()) {
        r.status = Skip;
        r.note = QStringLiteral("Сайты РФ не проверялись");
    } else if (bad.isEmpty()) {
        r.status = Ok;
        r.note = QStringLiteral("Сайты РФ открываются напрямую");
    } else if (ok > 0) {
        r.status = Warn;
        r.note = QStringLiteral("Не открылись: %1").arg(bad.join(QStringLiteral(", ")));
    } else {
        r.status = Bad;
        r.note = QStringLiteral("Сайты РФ недоступны — проблема с «Доступом к сайтам РФ»");
    }
    return r;
}

// Стадия 5 (опциональная): ДРУГИЕ СЕРВЕРЫ. Запускается только при проблеме на текущей ноде —
// различает «нода сломана» (альтернатива работает → переключаем) от «сеть/оператор»
// (все недоступны). names/oks — параллельные списки проверенных альтернатив; details —
// per-нода факты (обе пробы/handshake/rx/RTT) для честного разбора «там работает» постфактум.
// verdict per-нода: 0=мертва (обе пробы мимо), 1=нестабильна (одна проба, задержанный blackhole),
// 2=жива (обе пробы прошли). good = verdict>=2 (стабильная), иначе в bad.
inline StageResult altNodesStage(const QStringList &names, const QList<bool> &oks,
                                 const QString &switchedTo,
                                 const QJsonArray &details = {})
{
    StageResult r; r.id = QStringLiteral("altnodes");
    QStringList good, bad, shaky;
    for (int i = 0; i < names.size() && i < oks.size(); ++i)
        (oks.at(i) ? good : bad).append(names.at(i));
    // details несут per-нода verdict — из них вытаскиваем «нестабильные» (одна проба из двух).
    for (const QJsonValue &v : details) {
        const QJsonObject d = v.toObject();
        if (d.value(QStringLiteral("verdict")).toInt() == 1) {
            const QString nm = d.value(QStringLiteral("name")).toString();
            if (!nm.isEmpty()) shaky.append(nm);
        }
    }
    r.data.insert(QStringLiteral("checked"), names.size());
    if (!good.isEmpty()) r.data.insert(QStringLiteral("good"), QJsonArray::fromStringList(good));
    if (!bad.isEmpty())  r.data.insert(QStringLiteral("bad"), QJsonArray::fromStringList(bad));
    if (!shaky.isEmpty()) r.data.insert(QStringLiteral("unstable"), QJsonArray::fromStringList(shaky));
    if (!details.isEmpty()) r.data.insert(QStringLiteral("details"), details);
    if (!switchedTo.isEmpty()) r.data.insert(QStringLiteral("switched_to"), switchedTo);
    if (names.isEmpty()) {
        r.status = Skip;
        r.note = QStringLiteral("Другие серверы не проверялись");
    } else if (!switchedTo.isEmpty()) {
        r.status = Ok;
        r.note = QStringLiteral("Переключил на %1 — там работает").arg(switchedTo);
    } else if (!good.isEmpty()) {
        r.status = Ok;
        r.note = QStringLiteral("Работает: %1").arg(good.join(QStringLiteral(", ")));
    } else if (!shaky.isEmpty()) {
        r.status = Warn;
        r.note = QStringLiteral("Нестабильно: %1 — данные пропадают через ~%2 c после подключения")
                     .arg(shaky.join(QStringLiteral(", "))).arg(20);
    } else {
        r.status = Bad;
        r.note = QStringLiteral("Другие серверы тоже недоступны — похоже, дело в вашей сети");
    }
    return r;
}

// Есть ли реальная проблема (Bad/Warn). Skip — не проблема, но и не «всё ок».
inline bool hasProblem(const QList<StageResult> &stages)
{
    for (const auto &s : stages)
        if (s.status == Warn || s.status == Bad) return true;
    return false;
}

// Главная человеческая строка для финала попапа: худшая стадия; при отсутствии проблем —
// с оговоркой, если часть проверок пропущена (Skip) — не врём «всё работает» вслепую.
inline QString humanSummary(const QList<StageResult> &stages)
{
    const StageResult *worst = nullptr;
    bool anySkip = false, anyOk = false;
    for (const auto &s : stages) {
        if (s.status == Skip) { anySkip = true; continue; }
        if (s.status == Ok) anyOk = true;
        if (!worst || s.status > worst->status) worst = &s;
    }
    if (worst && (worst->status == Warn || worst->status == Bad))
        return worst->note;
    if (!anyOk)
        return QStringLiteral("Диагностика выполнена");
    if (anySkip)
        return QStringLiteral("Основное работает — часть проверок не завершилась");
    return QStringLiteral("Всё работает — VPN подключён, интернет доступен");
}

// Человекочитаемое резюме для МЕНЕДЖЕРА поддержки (текст-сообщение в тред: сырой diag.log
// оператору бесполезен — ему нужны выводы). Маркеры статуса словами, без эмодзи (правило проекта).
inline QString humanReport(const QList<StageResult> &stages, const QString &netType,
                           const QString &tz)
{
    auto mark = [](int st) -> QString {
        switch (st) {
        case Ok:   return QStringLiteral("[ok]");
        case Warn: return QStringLiteral("[!]");
        case Bad:  return QStringLiteral("[x]");
        default:   return QStringLiteral("[-]");
        }
    };
    QString out = QStringLiteral("Диагностика Tribe VPN\n");
    for (const auto &s : stages)
        out += mark(s.status) + QStringLiteral(" ") + s.note + QStringLiteral("\n");
    out += QStringLiteral("Итог: ") + humanSummary(stages) + QStringLiteral("\n");
    QStringList ctx;
    if (!netType.isEmpty() && netType != QLatin1String("unknown"))
        ctx << (netType == QLatin1String("cellular") ? QStringLiteral("сеть: сотовая")
              : netType == QLatin1String("wifi")     ? QStringLiteral("сеть: Wi-Fi")
                                                     : QStringLiteral("сеть: ") + netType);
    if (!tz.isEmpty())
        ctx << QStringLiteral("tz: ") + tz;
    if (!ctx.isEmpty())
        out += ctx.join(QStringLiteral(" · "));
    return out.trimmed();
}

// Итоговый JSON-отчёт (уходит в /v1/bench/report и в секцию diag.log).
// PII нет by construction: стадии кладут только агрегаты (loc/colo, регион, статусы).
inline QJsonObject buildReport(const QList<StageResult> &stages, const QJsonObject &extra)
{
    QJsonObject o;
    o.insert(QStringLiteral("type"), QStringLiteral("doctor"));
    o.insert(QStringLiteral("schema"), 4);   // v4 (волна UX 07-22): RU-корпус GET<500, full-режим,
                                             // порог RTT server-driven, ручной net_type/оператор
    QJsonArray arr;
    for (const auto &s : stages) {
        QJsonObject so = s.data;
        so.insert(QStringLiteral("id"), s.id);
        so.insert(QStringLiteral("status"), s.status);
        so.insert(QStringLiteral("note"), s.note);
        arr.append(so);
    }
    o.insert(QStringLiteral("stages"), arr);
    o.insert(QStringLiteral("summary"), humanSummary(stages));
    if (!extra.isEmpty())
        o.insert(QStringLiteral("extra"), extra);
    return o;
}

} // namespace doctor
