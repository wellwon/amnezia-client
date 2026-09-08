// AVPN (Доктор v2, активная модель): юнит чистой логики DoctorReport.h — вердикты стадий,
// клампы, humanSummary, сборка отчёта. Запуск: tests/build_doctor_check.sh (только QtCore).
#include "../DoctorReport.h"

#include <QJsonDocument>
#include <cstdio>

static int g_fail = 0;
#define CHECK(cond, msg)                                                     \
    do {                                                                     \
        if (!(cond)) { std::printf("FAIL: %s\n", msg); ++g_fail; }           \
        else         { std::printf("ok:   %s\n", msg); }                     \
    } while (0)

int main()
{
    using namespace doctor;

    // клампы таймаута стадии
    CHECK(clampStageTimeoutMs(0) == 25000, "timeout: нет ключа -> дефолт 25с");
    CHECK(clampStageTimeoutMs(100) == 5000, "timeout: низ клампится в 5с");
    CHECK(clampStageTimeoutMs(999999) == 60000, "timeout: верх клампится в 60с");
    CHECK(clampStageTimeoutMs(30000) == 30000, "timeout: валидный проходит");

    // стадия подключения (активная)
    CHECK(connectStage(false, false, -1).status == Bad,
          "connect: не поднялся -> Bad «не удалось подключиться»");
    CHECK(connectStage(true, false, 200).status == Bad,
          "connect: поднят, но данные не идут -> Bad (зелёный-но-мёртвый)");
    CHECK(connectStage(true, true, 10).status == Ok,
          "connect: поднят + данные идут -> Ok");

    // стадия серверов
    CHECK(serverStage(QStringLiteral("Финляндия"), QStringLiteral("FI"), 28).status == Ok,
          "servers: близкий сервер -> Ok");
    CHECK(serverStage(QStringLiteral("США"), QStringLiteral("US"), 450).status == Ok,
          "servers: 450 мс при дефолтном пороге 800 -> Ok (пересмотр владельца 07-21)");
    CHECK(serverStage(QStringLiteral("США"), QStringLiteral("US"), 900).status == Warn,
          "servers: RTT>=800 (дефолт) -> Warn (далеко)");
    CHECK(serverStage(QStringLiteral("США"), QStringLiteral("US"), 450, 400).status == Warn,
          "servers: порог server-driven — 450 при warnMs=400 -> Warn");
    CHECK(serverStage({}, {}, -1).status == Ok,
          "servers: без региона/RTT -> Ok (нейтрально)");
    CHECK(serverStage(QStringLiteral("Латвия"), QStringLiteral("LV"), 28).note.contains(QStringLiteral("Латвия")),
          "servers: регион попадает в текст");

    // стадия сервисов
    CHECK(servicesStage(4, 4, {}, false, false).status == Ok,
          "services: все works -> Ok");
    CHECK(servicesStage(3, 4, {QStringLiteral("WhatsApp")}, false, false).status == Bad,
          "services: один заблокирован -> Bad с названием");
    CHECK(servicesStage(3, 4, {QStringLiteral("WhatsApp")}, false, false)
              .note.contains(QStringLiteral("WhatsApp")),
          "services: имя заблокированного в тексте");
    CHECK(servicesStage(0, 0, {}, false, false).status == Skip,
          "services: ничего не измерено -> Skip");
    CHECK(servicesStage(2, 4, {}, true, true).status == Bad,
          "services: whitelist активен -> Bad (оператор ограничивает)");
    CHECK(servicesStage(4, 4, {}, true, false).status == Ok,
          "services: whitelist применим, но не активен -> Ok");

    // D-3: стадия сети (network) — captive/поколение/белые списки
    CHECK(networkStage(1, QStringLiteral("wifi"), {}, -1, -1, -1).status == Bad,
          "network: captive-портал -> Bad «залогиньтесь»");
    CHECK(networkStage(0, QStringLiteral("cellular"), QStringLiteral("lte"), -1, -1, 1).status == Bad,
          "network: форс-пробы дали whitelist -> Bad");
    CHECK(networkStage(0, QStringLiteral("cellular"), QStringLiteral("3g"), -1, -1, 0).status == Warn,
          "network: 3G -> Warn «медленно само по себе»");
    CHECK(networkStage(0, QStringLiteral("cellular"), QStringLiteral("lte"), 1, 0, 0).status == Ok,
          "network: LTE без captive/wl -> Ok");
    CHECK(networkStage(0, QStringLiteral("cellular"), QStringLiteral("lte"), -1, 1, 0)
              .note.contains(QStringLiteral("роуминг")),
          "network: роуминг попадает в текст");
    CHECK(networkStage(-1, QStringLiteral("wifi"), {}, -1, -1, -1).status == Ok,
          "network: Wi-Fi, captive не проверялся -> Ok (без вранья)");
    CHECK(!networkStage(-1, {}, {}, -1, -1, -1).data.contains(QStringLiteral("captive")),
          "network: непроверенные поля не пишутся в data");

    // IPv6-волна 2026-09-08: туннель v4-only забирает ::/0 — на сети С глобальным v6 это
    // единственное объяснение «v6-only адресат недостижим». Говорим ТОЛЬКО когда есть о чём.
    {
        const StageResult withV6 = networkStage(0, QStringLiteral("wifi"), {}, -1, -1, 0, {}, 1);
        CHECK(withV6.note.contains(QStringLiteral("IPv6")),
              "network: сеть с глобальным v6 -> в note объяснение про IPv6");
        CHECK(withV6.status == Ok,
              "network: IPv6 выключен туннелем — это НЕ проблема сети, статус остаётся Ok");
        CHECK(withV6.data.value(QStringLiteral("ipv6_lan")).toBool() == true,
              "network: факт v6 у сети едет в отчёт поддержки");
        CHECK(withV6.note.contains(QStringLiteral("Wi-Fi")),
              "network: прежний текст про тип сети не потерян");

        const StageResult noV6 = networkStage(0, QStringLiteral("wifi"), {}, -1, -1, 0, {}, 0);
        CHECK(!noV6.note.contains(QStringLiteral("IPv6")),
              "network: сеть без v6 -> ни слова про IPv6 (незачем пугать)");
        CHECK(noV6.data.value(QStringLiteral("ipv6_lan")).toBool() == false,
              "network: проверено и v6 нет -> false в отчёт");

        const StageResult unknownV6 = networkStage(0, QStringLiteral("wifi"), {}, -1, -1, 0, {}, -1);
        CHECK(!unknownV6.note.contains(QStringLiteral("IPv6")),
              "network: не проверяли -> молчим");
        CHECK(!unknownV6.data.contains(QStringLiteral("ipv6_lan")),
              "network: не проверяли -> поля в отчёте нет (честно)");

        CHECK(networkStage(1, QStringLiteral("wifi"), {}, -1, -1, -1, {}, 1)
                  .note.contains(QStringLiteral("браузер")),
              "network: captive-портал важнее IPv6 — вердикт стадии не подменяется");
        CHECK(networkStage(0, QStringLiteral("cellular"), QStringLiteral("lte"), -1, -1, 1, {}, 1)
                  .note.contains(QStringLiteral("белые списки")),
              "network: «белые списки» важнее IPv6");
    }

    // D-3: коллапс посекундного профиля (ТСПУ-сигнатура)
    const QList<double> flat{20, 21, 19, 20, 22, 20, 21, 20};
    const QList<double> tspu{25, 24, 20, 2.0, 1.5, 1.0, 0.8, 0.5};
    const QList<double> slowAll{2, 2.5, 2, 1.8, 2.2, 2, 2.1};
    CHECK(!speedCollapsed(flat), "collapse: ровный профиль -> нет");
    CHECK(speedCollapsed(tspu), "collapse: летит-потом-душат -> да");
    CHECK(!speedCollapsed(slowAll), "collapse: медленно с самого начала -> нет (не ТСПУ)");
    CHECK(!speedCollapsed({25, 24, 20, 2.0}), "collapse: профиль короче 6с -> нет");
    CHECK(!speedCollapsed({25, 24, 20, 10, 9, 8, 7, 6}), "collapse: плавное снижение -> нет");

    // D-3: speedStage с коллапсом и A/B direct
    CHECK(speedStage(6.0, 40, 60, true, -1).status == Bad,
          "speed: коллапс -> Bad независимо от среднего");
    CHECK(speedStage(6.0, 40, 60, true, 30.0).note.contains(QStringLiteral("напрямую")),
          "speed: коллапс + direct быстрый -> текст про «напрямую быстрая»");
    CHECK(speedStage(3.0, 40, 60, false, 2.5).status == Warn,
          "speed: медленно и без VPN -> Warn «дело не в VPN»");
    CHECK(speedStage(3.0, 40, 60, false, 2.5).note.contains(QStringLiteral("не в VPN")),
          "speed: текст «дело не в VPN» присутствует");
    CHECK(speedStage(48.0, 40, 60, false, -1).status == Ok,
          "speed: direct не мерялся -> поведение прежнее");
    CHECK(!speedStage(48.0, 40, 60).data.contains(QStringLiteral("direct_mbit")),
          "speed: без direct замера поле не пишется");

    // стадия скорости
    CHECK(speedStage(-1, 0, 0).status == Skip, "speed: не мерялась -> Skip");
    CHECK(speedStage(48.0, 40, 60).status == Ok, "speed: быстро без блоата -> Ok");
    CHECK(speedStage(2.0, 40, 60).status == Warn, "speed: медленно -> Warn");
    CHECK(speedStage(2.0, 40, 400).status == Bad, "speed: медленно + bufferbloat -> Bad");
    CHECK(speedStage(48.0, 40, 400).status == Warn, "speed: только bufferbloat -> Warn");

    // humanSummary: худшая стадия побеждает; Skip не участвует
    {
        QList<StageResult> st;
        st << connectStage(true, true, 10)                      // Ok
           << servicesStage(0, 0, {}, false, false)             // Skip
           << speedStage(2.0, 40, 400);                         // Bad
        CHECK(humanSummary(st) == speedStage(2.0, 40, 400).note,
              "summary: строка = худшая стадия (Bad скорости)");
    }
    {
        QList<StageResult> st;
        st << connectStage(true, true, 10);
        CHECK(humanSummary(st).contains(QStringLiteral("Всё работает")),
              "summary: всё Ok -> «всё работает»");
    }
    {
        QList<StageResult> st;
        st << servicesStage(0, 0, {}, false, false);   // только Skip
        CHECK(humanSummary(st) == QStringLiteral("Диагностика выполнена"),
              "summary: только Skip -> нейтральная строка");
    }

    // страны и человекочитаемое резюме для менеджера
    CHECK(countryNameRu(QStringLiteral("lv")) == QStringLiteral("Латвия"),
          "country: lv -> Латвия (регистронезависимо)");
    CHECK(countryNameRu(QStringLiteral("ZZ")) == QStringLiteral("ZZ"),
          "country: неизвестный код -> код заглавными");
    {
        QList<StageResult> st;
        st << connectStage(true, true, 10)
           << serverStage(QStringLiteral("Латвия"), QStringLiteral("LV"), 28);
        CHECK(!hasProblem(st), "hasProblem: всё Ok -> false");
        st << servicesStage(3, 4, {QStringLiteral("WhatsApp")}, false, false);
        CHECK(hasProblem(st), "hasProblem: есть Bad -> true");
        const QString rep = humanReport(st, QStringLiteral("wifi"), QStringLiteral("Europe/Riga"));
        CHECK(rep.contains(QStringLiteral("[x]")) && rep.contains(QStringLiteral("WhatsApp")),
              "humanReport: маркер и имя сервиса на месте");
        CHECK(rep.contains(QStringLiteral("Wi-Fi")), "humanReport: тип сети словами");
    }
    {
        QList<StageResult> st;
        st << connectStage(true, true, 10) << speedStage(-1, 0, 0);   // Ok + Skip
        CHECK(humanSummary(st).contains(QStringLiteral("часть проверок")),
              "summary: Ok+Skip -> честная оговорка, не «всё работает»");
    }

    // фикс «канал пухнет» на сотовой: относительный рост при МАЛОМ абсолюте — НЕ блоат
    CHECK(speedStage(30.0, 40, 120).status == Ok,
          "speed: 30 Мбит, idle 40 -> loaded 120 (ratio 3, но < 400мс) -> Ok, НЕ «пухнет»");
    CHECK(speedStage(30.0, 100, 450).status == Warn,
          "speed: loaded 450мс при росте — честный Warn «пухнет»");

    // стадия других серверов
    CHECK(altNodesStage({}, {}, {}).status == Skip, "alt: не проверялись -> Skip");
    CHECK(altNodesStage({QStringLiteral("Финляндия")}, {true}, QStringLiteral("Финляндия")).status == Ok,
          "alt: рабочая найдена -> Ok «переключил»");
    CHECK(altNodesStage({QStringLiteral("Финляндия")}, {true}, QStringLiteral("Финляндия"))
              .note.contains(QStringLiteral("Финляндия")),
          "alt: имя ноды в тексте");
    CHECK(altNodesStage({QStringLiteral("A"), QStringLiteral("B")}, {false, false}, {}).status == Bad,
          "alt: все мертвы -> Bad «дело в вашей сети»");

    // стадия РФ-сплита
    CHECK(ruSplitStage({}, {}).status == Skip, "rusplit: не проверялись -> Skip");
    CHECK(ruSplitStage({QStringLiteral("Яндекс"), QStringLiteral("VK")}, {true, true}).status == Ok,
          "rusplit: все открылись -> Ok");
    CHECK(ruSplitStage({QStringLiteral("Яндекс"), QStringLiteral("Аэрофлот")}, {true, false}).status == Warn,
          "rusplit: часть не открылась -> Warn с именами");
    CHECK(ruSplitStage({QStringLiteral("Яндекс"), QStringLiteral("Аэрофлот")}, {true, false})
              .note.contains(QStringLiteral("Аэрофлот")),
          "rusplit: имя упавшего сайта в тексте");
    CHECK(ruSplitStage({QStringLiteral("Яндекс")}, {false}).status == Bad,
          "rusplit: всё мертво -> Bad «проблема с Доступом к РФ»");
    CHECK(ruSplitStage({}, {}, /*enabled=*/false).status == Skip,
          "rusplit: тумблер выключен -> Skip (не Bad)");
    CHECK(ruSplitStage({}, {}, /*enabled=*/false).note.contains(QStringLiteral("выключен")),
          "rusplit: причина Skip — «выключен» видна поддержке");

    // сборка отчёта
    {
        QList<StageResult> st;
        st << connectStage(true, true, 10) << speedStage(48.0, 40, 60);
        QJsonObject extra; extra.insert(QStringLiteral("app_ver"), QStringLiteral("test"));
        const QJsonObject rep = buildReport(st, extra);
        CHECK(rep.value(QStringLiteral("type")).toString() == QLatin1String("doctor"),
              "report: type=doctor");
        CHECK(rep.value(QStringLiteral("schema")).toInt() == 4, "report: schema=4 (волна UX 07-22)");
        CHECK(rep.value(QStringLiteral("stages")).toArray().size() == 2, "report: 2 стадии");
        CHECK(rep.value(QStringLiteral("stages")).toArray().at(0).toObject()
                  .value(QStringLiteral("id")).toString() == QLatin1String("connect"),
              "report: id стадии на месте");
        CHECK(!rep.value(QStringLiteral("summary")).toString().isEmpty(), "report: summary не пуст");
        CHECK(rep.value(QStringLiteral("extra")).toObject()
                  .value(QStringLiteral("app_ver")).toString() == QLatin1String("test"),
              "report: extra прокинут");
        const QByteArray raw = QJsonDocument(rep).toJson();
        CHECK(!raw.contains("private_key") && !raw.contains("\"ip\""),
              "report: нет ключей и IP");
    }

    if (g_fail) { std::printf(">>> ПРОВАЛОВ: %d\n", g_fail); return 1; }
    std::printf(">>> doctor_report_check: все проверки зелёные\n");
    return 0;
}
