#include "AvpnEngineQml.h"

#ifdef Q_OS_ANDROID
#include "platforms/android/android_controller.h" // AVPN: адопт снапшота статуса (рассинхрон после фона)
#endif

#include "core/repositories/secureAppSettingsRepository.h"
#include "core/utils/errorStrings.h" // AVPN: errorString(ErrorCode) → текст для error()
#include "vpnConnection.h"
#include "Enrollment.h" // AVPN: authToken() → Enrollment::loadToken()
#include "SubscriptionParser.h" // AVPN (оплата): refreshSubscription() — device-часы для шапки/CTA
#include "SubscriptionRequest.h"
#include "Identity.h"   // AVPN: localDeviceId() → installation-UUID (раздел «Устройства» всегда показывает ID)
#include "IdentityAnchor.h" // AVPN (анти-фрод): Keychain-якорь identity — restore на старте (переустановка)
#include "DeviceFingerprint.h" // AVPN (anti-farm): якорь железа в async-enroll (паритет с Enrollment::enroll)
#include "DeviceModel.h" // AVPN: нативные имя/ОС текущего устройства (раздел «Устройства»)
#include "QualityProbe.h" // AVPN (реальные палочки): app-layer RTT-проба через туннель
#include "ServiceProbe.h" // AVPN (чипы доступности): проба Telegram/YouTube через туннель
#include "ServiceProbeTargets.h" // AVPN (чипы): вшитые цели + мерж серверного probe_targets (не замещать!)
#include "ConnectTunables.h" // AVPN: клампованные пороги коннекта + связка watchdog>handshake (ревью 2026-07-11)
#include "NodeRanking.h"  // AVPN (выбор по скорости): RTT→палочки + сортировка «быстрые внизу»
#include "NodeRotation.h" // AVPN (Task 10 финал): isSupportedProto — xray-ноды мимо свипа/выбора
#include "RttProbeIcmp.h" // AVPN (выбор по скорости): прямой ICMP-замер RTT до нод off-tunnel
#include "BenchAnalysis.h" // AVPN (панель администратора): вердикты + A/B-сравнение замеров
#include "Ipv6Presence.h" // AVPN (IPv6-волна): есть ли у сети глобальный v6 мимо туннеля (Доктор)
#ifdef Q_OS_IOS
#include "platforms/ios/AvpnDiagnostics.h" // AVPN backend-first (2026-07-10): crash-diag следует за edge-walk базой
#endif
#include "BenchRunner.h"  // AVPN (панель администратора): in-app бенч соединения
#include "BootstrapRetry.h" // AVPN: политика ретраев тихого bootstrap (бэкофф → вечный медленный цикл)
#include "ConfigStore.h" // AVPN remote-config (T6): compareVersions/UpdateVerdict + APP_VERSION (version.h)
#include "BypassListService.h" // AVPN server-driven АнтиВПН (Task 10): серверные bypass-списки + BypassListStore
#include "WhitelistDetector.h" // AVPN (белые списки): детект РКН-режима «работает только whitelist»
#include "CrashGuard.h" // AVPN (CR-1): свой краш-репортинг (sentinel+сигналы) -> type:"crash" в /v1/bench/report
#include "TribeNetInfo.h" // AVPN (Доктор D-3): поколение сотовой/metered/roaming для стадии network
#include "RuSplitSentinel.h" // AVPN (Доктор D-3 п.26): фоновый дозор RU-сайтов при вкл. сплите
#include "TuningStore.h" // AVPN backend-first (T8): потокобезопасный снапшот numbers/features/lists
#include "AnnounceGate.h" // AVPN (announce-quiet): тихое окно попапов объявлений после онбординга
#include "SubscriptionGate.h" // AVPN (sub-grace): «подписка истекла и грейс прошёл» → управляемый stop
#include "TribeDiagReport.h" // AVPN (diag-report, Task 4 bff-3): единый диагностический отчёт для чата поддержки
#include "logger.h" // AVPN (diag-report): Logger::userLogsFilePath() — хвост лога приложения в отчёт

#include <algorithm> // AVPN (панель администратора): сортировка строк свипа
#include "AvpnIntentBridge.h" // AVPN (Task E): консьюмер «намерений» App Intent авто-паузы → pause/resume
#include "AvpnShareBridge.h" // AVPN: нативный share sheet (рефералка/перенос)
#include "core/utils/qrCodeUtils.h" // AVPN: QR для ссылки переноса (makeQrCode)
#include "AvpnPushBridge.h" // AVPN (Task 9): device token → /v1/devices/push-token; markAllRead → /v1/notifications/read
#include "ru_prefixes.h"          // AVPN RU-direct: весь рунет CIDR для split-tunnel (applyRuBypassSplit)
#include "CidrCarve.h"            // AVPN RU-direct: carve-out IP API из сева (control plane всегда в туннеле)
#include "BypassSeedStamp.h"      // AVPN: стамп входов сева АнтиВПН — скип пересева 10k CIDR при неизменных входах
#include <QHostInfo>              // AVPN RU-direct: async-резолв хоста API для carve-out
#include "LegalDocs.h"            // AVPN in-app Legal: URL/кэш/валидация Privacy/Terms
#include <QDir>                   // AVPN in-app Legal: каталог кэша
#include <QImage>                 // AVPN: QR → PNG для share-листа переноса (shareTextWithQr)
#include <QFile>                  // AVPN in-app Legal: чтение кэша
#include <QLocalSocket>           // AVPN (BUG-6): стартовая проба статуса root-демона (macOS)
#include <QSaveFile>              // AVPN in-app Legal: атомарная запись кэша
#include <QStandardPaths>         // AVPN in-app Legal: AppDataLocation
#ifdef Q_OS_IOS
#include <chrono>   // AVPN: предохранитель watchdog при выходе (см. конструктор)
#include <thread>
#include <unistd.h> // ::_exit
#endif
#include "core/utils/routeModes.h" // AVPN RU-direct: amnezia::RouteMode::VpnAllExceptSites
#include <QMap>                    // AVPN RU-direct: bulk addVpnSites

#include <QCoreApplication> // AVPN (Task 9): applicationVersion() → app_version в push-token
#include <QGuiApplication>  // AVPN (store-flow E): applicationStateChanged → foreground-рефреш подписки
#include <QDateTime>
#include <QLocale>
#include <QJsonDocument> // AVPN (панель администратора): сериализация результата бенча

#include <QNetworkInformation> // AVPN (авто-A/B): тип сети (Wi-Fi/сотовая) в extra{} бенча
#include <QNetworkInterface>   // AVPN (IPv6-волна): срез адресов для detectLanIpv6()
#include <QSysInfo>      // AVPN (панель администратора): platform в extra{} бенча
#include <QTimeZone>     // AVPN (панель администратора): tz в extra{} — физлокация vs egress
#include "ui/controllers/systemController.h" // AVPN (панель администратора): saveReportFile → файл/шэр отчёта
#include <QSettings> // AVPN (Task 7): чтение тумблера AvpnSettings/autoPauseRu (общий стор с QML Settings)
#include <QVariantList>
#include <QScopedValueRollback> // AVPN (краш-фикс): RAII-флаг m_inSyncNetCall вокруг вложенного QEventLoop
// AVPN (Devices+Account): синхронные REST-вызовы к control plane, как fetchSubscription.
#include "NetAwait.h" // AVPN: awaitReply() — ожидание с таймаутом (анти-фриз GUI)

#if defined(Q_OS_MACOS) && !defined(MACOS_NE)
// AVPN (P-ANN, macOS): регистрация бейджа дока (platforms/macos/AvpnDockBadge.mm).
extern "C" void AvpnDockBadge_install();
#endif
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QUrl>
#include <QUrlQuery> // AVPN (P-ANN): query-параметры GET /v1/announcements

#if defined(Q_OS_MACOS) && !defined(MACOS_NE)
#include "MacServiceInstaller.h" // AVPN (macOS desktop): авто-установка root-демона из вшитого pkg (ноль терминала)
#include <QThread>
#include "core/utils/ipcClient.h" // AVPN (wake-реконнект): подписка на wakeup/networkChanged реплики демона

#endif

namespace avpn {

// Ключ платформы для карт версий (определение — ниже, рядом с self-update).
static QString avpnPlatformKey();


// AVPN awg31-xray-v1: маппер технических ошибок движка (no_transport/unsupported_proto) в человеческий
// текст — определён рядом с humanPinError ниже по файлу, нужен раньше (guardedStart).
static QString humanEngineError(const QString &technical);

// AVPN (CR-1): tee лог-строк в кольцо CrashGuard поверх текущего message-handler (chain —
// апстрим-логгер работает как раньше). Ставится один раз из конструктора движка.
namespace {
QtMessageHandler g_crashPrevHandler = nullptr;
void crashLogTeeHandler(QtMsgType t, const QMessageLogContext &c, const QString &m)
{
    CrashGuard::instance().appendLogLine(m);
    if (g_crashPrevHandler)
        g_crashPrevHandler(t, c, m);
}
void installCrashLogTee()
{
    static bool done = false;
    if (done) return;
    done = true;
    g_crashPrevHandler = qInstallMessageHandler(crashLogTeeHandler);
}
} // namespace

AvpnEngineQml::AvpnEngineQml(VpnConnection *conn, SecureAppSettingsRepository *store,
                             QNetworkAccessManager *nam, QObject *parent)
    : QObject(parent), m_tunnel(conn, this), m_store(store), m_nam(nam), m_conn(conn)
{
    // AVPN (анти-фрод, DEVICE-FIRST-SPEC §4): восстановить identity из Keychain ДО первого
    // использования (переустановка на iOS стирает QSettings → без этого новый триал и потеря
    // оплаченных дней). Один блокирующий Keychain-раунд ~мс со сторожем; не-Apple — no-op.
    IdentityAnchor::syncAtStartup();

    // dev/E2E: переопределение control plane (напр. http://127.0.0.1:48480 — локальный бэкенд)
    const QByteArray envUrl = qgetenv("AVPN_API_URL");
    if (!envUrl.isEmpty())
        m_baseUrl = QString::fromUtf8(envUrl);

    // AVPN RU-direct carve-out (2026-07-05): узнать актуальные IP хоста API, чтобы сев байпаса
    // их исключил (см. applyRuBypassSplit). Async (QHostInfo не блокирует GUI); провал резолва
    // не страшен — в севе всегда есть вкомпиленный фолбэк-IP. Ре-сев на живом туннеле произойдёт
    // при следующем reconcile/up() и подхватит m_apiHostIps.
    // AVPN (watchdog 0x8BADF00D, креш build 53, 2026-07-05): при выходе ~QGuiApplication ждёт
    // QThreadPool::waitForDone (Qt-внутренний пул QHostInfo), а застрявший в блокированной сети
    // DNS-lookup не завершается → iOS убивает процесс за 5с как «Failed to terminate gracefully».
    // Предохранитель: на aboutToQuit синхронно флашим настройки и взводим detached-поток, который
    // через 2с (внутри 5с watchdog) завершает процесс штатно, если teardown не успел сам.
    // Overlay: наш файл, апстрим main.cpp/amneziaApplication.cpp не трогаем.
#ifdef Q_OS_IOS
    connect(QCoreApplication::instance(), &QCoreApplication::aboutToQuit, this, [] {
        { QSettings s; s.sync(); }
        std::thread([] {
            std::this_thread::sleep_for(std::chrono::seconds(2));
            ::_exit(0);
        }).detach();
    });
#endif

    const QString apiHost = QUrl(m_baseUrl).host();
    if (!apiHost.isEmpty() && QHostAddress(apiHost).isNull()) { // literal-IP резолвить не надо
        QHostInfo::lookupHost(apiHost, this, [this](const QHostInfo &info) {
            if (info.error() == QHostInfo::NoError && !info.addresses().isEmpty())
                m_apiHostIps = info.addresses();
        });
    }

    m_engine.setTunnel(&m_tunnel);
    m_tunnel.setStore(store); // AVPN RU-direct: гейт сплита по фактической ноде — в up() (T2)

    // AVPN (выбор по скорости): прямой ICMP-пробер RTT до нод (off-tunnel). Кроссплатформенный за швом
    // IRttProbe; Windows — graceful-стаб (нет измерения → health-фолбэк). Запуск — из probeNodeRtt().
    m_rttProbe = new RttProbeIcmp(this);
    // AVPN (Доктор D-3 п.3): отдельный ICMP-инстанс для пробы ЧЕРЕЗ туннель — m_rttProbe
    // гейтится «connected⇒cancel» (off-tunnel семантика), делить нельзя.
    m_docPing = new RttProbeIcmp(this);

    // AVPN (панель администратора): in-app бенч соединения. Запуск ТОЛЬКО вручную (startBench из QML),
    // коннект-путь не трогает; результат — schema:1 (сводится с Mac-замерами tools/connect-bench).
    m_bench = new BenchRunner(m_nam, this);
    connect(m_bench, &BenchRunner::stageChanged, this, [this](const QString &st) {
        m_benchStage = st;
        emit benchChanged();
    });
    // сторож фаз свипа нод + продвижение фазовой машины по каждому changed() (queued: не входить
    // в reconcile-стек синхронно)
    m_sweepGuard.setSingleShot(true);
    connect(&m_sweepGuard, &QTimer::timeout, this, [this] { sweepGuardFired(); });
    connect(this, &AvpnEngineQml::changed, this, [this] { sweepAdvance(); }, Qt::QueuedConnection);
    // AVPN (авто-A/B байпаса): та же схема — сторож фазы + queued-продвижение по changed()
    m_abGuard.setSingleShot(true);
    connect(&m_abGuard, &QTimer::timeout, this, [this] { abGuardFired(); });
    connect(this, &AvpnEngineQml::changed, this, [this] { abAdvance(); }, Qt::QueuedConnection);

    m_ccGuard.setSingleShot(true); // AVPN bench v5 (connect{}): тот же каркас, что свип/A/B
    connect(&m_ccGuard, &QTimer::timeout, this, [this] { ccGuardFired(); });
    connect(this, &AvpnEngineQml::changed, this, [this] { ccAdvance(); }, Qt::QueuedConnection);

    // AVPN bench v5.2 (мастер «Полный тест»): дирижёр слушает завершения готовых машин.
    m_ftGuard.setSingleShot(true);
    connect(&m_ftGuard, &QTimer::timeout, this, [this] { ftStepDone(m_ftPhase, false); });
    connect(this, &AvpnEngineQml::ccFinished, this, [this] { ftStepDone(FtPhase::Cc, true); });
    connect(this, &AvpnEngineQml::abFinished, this, [this] { ftStepDone(FtPhase::Ab, true); });
    connect(this, &AvpnEngineQml::sweepFinished, this, [this] { ftStepDone(FtPhase::Sweep, true); });
    connect(this, &AvpnEngineQml::benchFinished, this, [this] {
        if (m_ftPhase == FtPhase::BenchAmnezia || m_ftPhase == FtPhase::BenchBaseline)
            ftStepDone(m_ftPhase, true);
    });
    // AVPN (Доктор v2): сторож стадии + добор lite-бенча + тик процента Speed + продвижение
    // фазы Connect по changed() (туннель поднялся/упал — queued, не входим в reconcile-стек).
    m_docGuard.setSingleShot(true);
    connect(&m_docGuard, &QTimer::timeout, this, [this] { docGuardFired(); });
    connect(this, &AvpnEngineQml::changed, this, [this] {
        if (m_docConnecting && (m_docPhase == DoctorPhase::Connect
                                || m_docPhase == DoctorPhase::AltNodes))
            docConnectAdvance();
    }, Qt::QueuedConnection);
    connect(m_bench, &BenchRunner::finished, this, [this](const QJsonObject &result) {
        if (m_docPhase != DoctorPhase::Speed || !m_docBenchStarted)
            return;
        m_docBenchStarted = false;
        m_docBenchFull = result; // полный замер (dns/tls/http/ping/…) уходит в extra отчёта
        const QJsonObject thr = result.value(QStringLiteral("throughput")).toObject();
        const QJsonObject nq  = result.value(QStringLiteral("network_quality")).toObject();
        const double down = thr.value(QStringLiteral("down_mbit")).isDouble()
                                ? thr.value(QStringLiteral("down_mbit")).toDouble() : -1.0;
        // D-3 п.18: посекундный профиль -> вердикт «коллапс» (ТСПУ-сигнатура)
        QList<double> prof;
        const QJsonArray profArr = thr.value(QStringLiteral("down_mbit_per_sec")).toArray();
        prof.reserve(profArr.size());
        for (const QJsonValue &v : profArr)
            prof.append(v.toDouble());
        const bool collapsed = doctor::speedCollapsed(prof);
        // D-3 п.19: при подозрении — контрольный замер МИМО туннеля (внутри docDirectSpeed),
        // иначе сразу вердикт
        docDirectSpeed(down,
                       int(nq.value(QStringLiteral("base_rtt_ms")).toDouble(0)),
                       int(nq.value(QStringLiteral("loaded_rtt_ms")).toDouble(0)), collapsed);
    });
    connect(this, &AvpnEngineQml::benchChanged, this, [this] {
        if (m_docPhase == DoctorPhase::Speed && m_docBenchStarted) {
            m_docPercent = 68 + int(28.0 * benchStageFrac());
            emit doctorChanged();
        }
    });

    // ── AVPN (CR-1): краш-репортинг — install СНАЧАЛА классифицирует прошлый запуск,
    // затем пишет свежий sentinel и ставит сигнал-хендлеры. Отчёты прошлых крашей уходят
    // тихо в /v1/bench/report (kill-switch features.crash_report). Спека:
    // tribe-front specs/2026-07-17-observability-crash-telemetry-design.md §1.
    {
        QString ver = QCoreApplication::applicationVersion();
        CrashGuard::instance().install(
            QStandardPaths::writableLocation(QStandardPaths::AppDataLocation)
                + QStringLiteral("/crash"),
            ver, QSysInfo::productType(), QSysInfo::productVersion());
        auto *hb = new QTimer(this);
        hb->setInterval(30000);
        connect(hb, &QTimer::timeout, this, [] { CrashGuard::instance().heartbeat(); });
        hb->start();
        // штатный выход != dirty_exit
        connect(qApp, &QCoreApplication::aboutToQuit, this,
                [] { CrashGuard::instance().markCleanExit(); });
        // лог-хвост: tee поверх ТЕКУЩЕГО message-handler (chain; апстрим-логгер не трогаем)
        installCrashLogTee();
        // отправка pending прошлых запусков: тихо, когда сеть скорее всего поднялась
        QTimer::singleShot(12000, this, [this] { crashFlushPending(); });
        QTimer::singleShot(120000, this, [this] { crashFlushPending(); });
    }
    // BUG-7: недоставленные отчёты прошлых запусков — дослать, когда сеть скорее всего есть
    QTimer::singleShot(25000, this, [this] { outboxFlush(); });
    // ── AVPN (Доктор D-3 п.26): RU-split-дозорный — сам замечает «сайт РФ не открывается»
    // и шлёт rusplit_fail (только на смене состояния, 1/сутки на target, kill-switch
    // rusplit_sentinel). Приватность: только наш вахт-лист, браузинг юзера не трогаем.
    m_ruSentinel = new RuSplitSentinel(
        m_nam,
        [this](const QJsonObject &o) {
            // S-5 (разбор 2026-07-24): без build отчёт не привязать к версии
            // (ингест берёт app_ver из тела, тело его не несло).
            QJsonObject withBuild = o;
            withBuild.insert(QStringLiteral("build"),
                             QCoreApplication::applicationVersion().section(QLatin1Char('.'), -1));
            uploadReport(QString::fromUtf8(
                             QJsonDocument(withBuild).toJson(QJsonDocument::Compact)),
                         /*quiet=*/true);
        },
        [this] { return benchExtra().value(QStringLiteral("net_type")).toString(); },
        [] {
            QSettings st;
            return st.value(QStringLiteral("AvpnBypass/masterOn"), false).toBool();
        },
        this);
    connect(this, &AvpnEngineQml::changed, this, [this] {
        const QString st = state();
        if (m_ruSentinel)
            m_ruSentinel->onTunnelStateChanged(st);
        if (m_docPhase == DoctorPhase::Idle) // во время Доктора фаза "doctor" приоритетнее
            CrashGuard::instance().setPhase(st == QLatin1String("connected") ? "connected"
                                            : st == QLatin1String("disconnected") ? "idle"
                                                                                  : "connecting");
        // BUG-7: фронт connected = сеть вернулась → дослать outbox (10с на устаканивание)
        const bool nowConnected = (st == QLatin1String("connected"));
        if (nowConnected && !m_outboxWasConnected)
            QTimer::singleShot(10000, this, [this] { outboxFlush(); });
        m_outboxWasConnected = nowConnected;
    }, Qt::QueuedConnection);

    // прогресс-бар мастера: пересчитывать на каждом тике под-машин (v5.4)
    auto ftTick = [this] { if (ftRunning()) ftUpdatePercent(); };
    connect(this, &AvpnEngineQml::benchChanged, this, ftTick);
    connect(this, &AvpnEngineQml::abChanged, this, ftTick);
    connect(this, &AvpnEngineQml::sweepChanged, this, ftTick);
    connect(this, &AvpnEngineQml::ccChanged, this, ftTick);
    // фаза Connect0 (мастер сам подключает) продвигается по changed()
    connect(this, &AvpnEngineQml::changed, this, [this] {
        if (m_ftPhase != FtPhase::Connect0)
            return;
        if (state() == QLatin1String("connected"))
            ftStepDone(FtPhase::Connect0, true);
        else if (state() == QLatin1String("error"))
            ftStepDone(FtPhase::Connect0, false);
    }, Qt::QueuedConnection);

    connect(m_bench, &BenchRunner::finished, this, [this](const QJsonObject &result) {
        m_benchRunning = false;
        emit benchChanged();

        // свип нод: результат забирает фазовая машина (в историю меток не пишем, наружу не эмитим)
        if (m_sweepPhase == SweepPhase::Bench) {
            m_sweepGuard.stop();
            m_sweepResults.append(result);
            QTimer::singleShot(0, this, [this, e = m_sweepEpoch] { if (e == m_sweepEpoch) sweepNextNode(); });
            return;
        }

        // история: последний замер каждой метки (для A/B между запусками)
        const QString label = result.value(QStringLiteral("label")).toString();
        const QString json = QString::fromUtf8(QJsonDocument(result).toJson(QJsonDocument::Compact));
        QSettings().setValue(QStringLiteral("AvpnBench/last_%1").arg(label), json);

        // авто-A/B байпаса: замер забирает фазовая машина (история выше УЖЕ записана — полный
        // отчёт собирает last_<label>); в UI не эмитим — по завершении пары придёт abFinished
        if (m_abPhase == AbPhase::BenchA || m_abPhase == AbPhase::BenchB) {
            abOnBenchDone(result);
            return;
        }

        QVariantMap s; // плоская сводка для мини-таблицы в UI
        s.insert(QStringLiteral("label"), result.value(QStringLiteral("label")).toString());
        s.insert(QStringLiteral("dns_ms"), result.value(QStringLiteral("dns")).toObject().value(QStringLiteral("median_ms")).toVariant());
        const QJsonObject http = result.value(QStringLiteral("http")).toObject();
        s.insert(QStringLiteral("ttfb_ms"), http.value(QStringLiteral("median_ttfb_ms")).toVariant());
        s.insert(QStringLiteral("total_ms"), http.value(QStringLiteral("median_total_ms")).toVariant());
        s.insert(QStringLiteral("failures"), http.value(QStringLiteral("failures")).toInt());
        const QJsonObject thr = result.value(QStringLiteral("throughput")).toObject();
        s.insert(QStringLiteral("down_mbit"), thr.value(QStringLiteral("down_mbit")).toDouble());
        s.insert(QStringLiteral("up_mbit"), thr.value(QStringLiteral("up_mbit")).toDouble());
        const QJsonObject nq = result.value(QStringLiteral("network_quality")).toObject();
        s.insert(QStringLiteral("base_rtt_ms"), nq.value(QStringLiteral("base_rtt_ms")).toVariant());
        s.insert(QStringLiteral("loaded_rtt_ms"), nq.value(QStringLiteral("loaded_rtt_ms")).toVariant());
        const QJsonObject eg = result.value(QStringLiteral("network")).toObject().value(QStringLiteral("egress")).toObject();
        s.insert(QStringLiteral("egress"), QStringLiteral("%1/%2").arg(eg.value(QStringLiteral("loc")).toString(QStringLiteral("-")),
                                                                       eg.value(QStringLiteral("cf_colo")).toString(QStringLiteral("-"))));
        // вердикты замера (BenchAnalysis) — тексты в UI
        QStringList verdictTexts;
        for (const QJsonValue &v : result.value(QStringLiteral("verdicts")).toArray())
            verdictTexts << v.toObject().value(QStringLiteral("text")).toString();
        s.insert(QStringLiteral("verdicts"), verdictTexts);
        // A/B против истории: существенные ухудшения текущего замера относительно эталонов.
        auto loadPrev = [this](const char *lbl) {
            const QString j = benchLastJson(QLatin1String(lbl));
            return j.isEmpty() ? QJsonObject() : QJsonDocument::fromJson(j.toUtf8()).object();
        };
        auto sigList = [](const QJsonObject &cmp) {
            QStringList out;
            for (const QJsonValue &v : cmp.value(QStringLiteral("significant")).toArray())
                out << v.toString();
            return out;
        };
        if (label != QLatin1String("baseline")) {
            const QJsonObject base = loadPrev("baseline");
            if (!base.isEmpty())
                s.insert(QStringLiteral("vs_baseline"), sigList(bench::compare(base, result)));
        }
        // главная пара методики: tribe-bypass-off ↔ amnezia (одинаковый full-tunnel, та же нода)
        if (label == QLatin1String("amnezia")) {
            const QJsonObject tribe = loadPrev("tribe-bypass-off");
            if (!tribe.isEmpty())
                s.insert(QStringLiteral("tribe_vs_amnezia"), sigList(bench::compare(result, tribe)));
        } else if (label == QLatin1String("tribe-bypass-off")) {
            const QJsonObject amn = loadPrev("amnezia");
            if (!amn.isEmpty())
                s.insert(QStringLiteral("tribe_vs_amnezia"), sigList(bench::compare(amn, result)));
        }
        emit benchFinished(s, QString::fromUtf8(QJsonDocument(result).toJson(QJsonDocument::Compact)));
    });

    // health-loop driver: периодический tick (3–5с).
    m_healthTimer.setInterval(4000);
    connect(&m_healthTimer, &QTimer::timeout, this, &AvpnEngineQml::onTick);

    // AVPN backend-first: фоновый LKG-рефреш подписки (H-3 бэклога). Коннект здесь, старт —
    // из configApplied (интервал приходит с сервера; до первого applied — не тикает).
    connect(&m_subRefreshTimer, &QTimer::timeout, this, &AvpnEngineQml::refreshSubscription);

    // AVPN (реальные палочки): app-layer RTT-проба ЧЕРЕЗ туннель. AWG UDP-only ⇒ ICMP/TCP-пинг до
    // эндпоинта пуст; реальный RTT даёт крошечный HTTPS-запрос к generate_204 через поднятый full-tunnel.
    // Эндпоинты по приоритету: свой бэкенд-пинг (тот же путь, что и control plane) → публичный фолбэк.
    // Поток RTT → m_signal (EWMA+гистерезис) → liveBars 0..5. Запуск — из onTick(), когда Connected.
    m_probe = new QualityProbe(m_nam, this);
    m_probe->setEndpoints({m_baseUrl + QStringLiteral("/v1/ping"),
                           QStringLiteral("https://connectivitycheck.gstatic.com/generate_204")});
    connect(m_probe, &QualityProbe::result, this, [this](int rttMs, bool reachable) {
        m_liveBars = m_signal.feed(rttMs, reachable);
        m_liveRtt = m_signal.smoothedRtt();
        m_liveReachable = reachable;
        // AVPN (красные палочки): различаем «ещё мерю» (m_liveDead=false → плейсхолдер 1 зелёная)
        // и «связь подтверждённо мертва» (m_liveDead=true → 0 зелёных + все красные). Один таймаут
        // в «мертво» НЕ роняем — ждём kLiveDeadStreak неудач подряд (анти-фликер на транзиентном дропе).
        if (reachable) {
            m_liveFailStreak = 0;
            m_liveDead = false;
        } else {
            // AVPN backend-first (final review R-2): пол 1 — 0/минус латчили бы m_liveDead=true мгновенно.
            const int deadStreak = qMax(1,
                (int) TuningStore::numberOr(QStringLiteral("live_dead_streak"), kLiveDeadStreak));
            if (++m_liveFailStreak >= deadStreak)
                m_liveDead = true;
        }
        emit liveQualityChanged();
        // AVPN awg31-xray-v1: для xray та же живая проба — вторая половина DEAD-критерия (у xray нет
        // handshake): N провалов подряд (xray_probe_fail_cycles) → движок уводит на другой транспорт
        // той же локации (двухфазный свитч, как health-DEAD). awg — no-op внутри. Сигнал приходит с
        // верха цикла событий (async-ответ QNetworkReply), не из-под Selector::pick.
        if (m_engine.feedProbeResult(reachable)) {
            persistTransportHistory();
            emit changed();
        } else if (surrenderIfDataPlaneDead()) {
            persistTransportHistory(); // AVPN (ревью волны, MAJOR-1): кап провалов исчерпан → честный OFF
        }
    });

    // AVPN (чипы доступности): проба «работает ли сервис через ЭТУ ноду» — с устройства через туннель
    // (бэкенд знать не может: доступность = f(юзер,сеть,регион,нода,время)). Все три меряются РЕАЛЬНОЙ
    // работоспособностью, а не reachability (иначе ложно-зелёный при DPI-троттлинге):
    //   • Telegram — login-free MTProto-handshake к seed-DC-IP (resPQ ⇒ дата-плейн жив);
    //   • YouTube/Instagram — GOODPUT: качаем ~128 КБ с реального душимого CDN (googlevideo/cdninstagram)
    //     и меряем kbit/s (RU-троттл ~128 кбит/с ⇒ slow; норм ⇒ works; путь срезан ⇒ blocked). См. ServiceProbe.h.
    {
        // Единый источник целей (seed-DC Telegram, fallback-SNI goodput) — avpn::defaultServiceProbeConfigs()
        // (ServiceProbeTargets.h): те же дефолты — база мержа applyRemoteProbeTargets, не расходятся.
        const QList<ServiceProbeConfig> cfgs = avpn::defaultServiceProbeConfigs();
        m_svcProbe = new ServiceProbe(m_nam, this);
        // AVPN backend-first (Task 4): m_svcCfgsAll — полный (нефильтрованный) список; rebuildServiceChips()
        // применяет lists.service_chips_disabled и заполняет И m_svcProbe (что пробится), И m_serviceStatus
        // (сидирует чипы state=-1 «неизвестно» в порядке cfgs — UI рисует их сразу). Пустой disabled-список
        // (default здесь — до первого /v1/config) => фильтр не убирает ничего, поведение как раньше.
        m_svcCfgsAll = cfgs;
        rebuildServiceChips();
        connect(m_svcProbe, &ServiceProbe::result, this,
                [this](const QString &key, int state, int rttMs) {
                    // rttMs для goodput-сервисов несёт метрику качества (kbit/s или TTFB), для telegram — RTT мс.
                    static const char *stName[] = {"blocked", "slow", "works"};
                    auto nameOf = [](int s) { return (s >= 0 && s <= 2) ? stName[s] : "unknown"; };
                    // AVPN чипы v2 (2026-07-12, анти-флап): сырой вердикт НЕ пишется в UI напрямую —
                    // через гистерезис (ChipLogic::chipHystStep): ухудшение показывается только после
                    // chip_confirm_n согласных прогонов ПОДРЯД (между ними — быстрая пере-проба ниже),
                    // восстановление — с первого успешного, unknown не понижает известное.
                    const int confirmN = qBound(1, int(avpn::TuningStore::numberOr(
                            QStringLiteral("chip_confirm_n"), 2.0)), 5);
                    const avpn::ChipHystStep stp =
                            avpn::chipHystStep(m_chipHyst.value(key), state, confirmN);
                    m_chipHyst.insert(key, stp.next);
                    qInfo("[AVPN svc] %s raw=%s shown=%s metric=%d%s",
                          key.toUtf8().constData(), nameOf(state), nameOf(stp.next.shown), rttMs,
                          stp.wantConfirm ? " (confirm pending)" : "");
                    for (int i = 0; i < m_serviceStatus.size(); ++i) {
                        QVariantMap m = m_serviceStatus.at(i).toMap();
                        if (m.value(QStringLiteral("key")).toString() == key) {
                            m[QStringLiteral("state")] = stp.next.shown;
                            m[QStringLiteral("rttMs")] = rttMs;
                            m[QStringLiteral("stale")] = false; // свежий вердикт ЭТОЙ ноды
                            m_serviceStatus[i] = m;
                            break;
                        }
                    }
                    emit serviceStatusChanged();
                    // Быстрое подтверждение ухудшения (вместо ожидания 3-мин self-heal): пере-проба
                    // одного сервиса через chip_confirm_ms. Бюджет 3 на серию — защита от шторма
                    // «ухудшился→отскочил→ухудшился» (сброс бюджета в probeServices).
                    if (stp.wantConfirm && m_chipConfirms.value(key, 0) < 3) {
                        m_chipConfirms.insert(key, m_chipConfirms.value(key, 0) + 1);
                        const int confirmMs = qBound(1000, int(avpn::TuningStore::numberOr(
                                QStringLiteral("chip_confirm_ms"), 8000.0)), 600000);
                        QTimer::singleShot(confirmMs, this, [this, key]() {
                            if (m_svcProbe && this->state() == QLatin1String("connected"))
                                m_svcProbe->probeOne(key);
                        });
                    }
                    // AVPN (анти-«вечно серый», 2026-07-03): Unknown (state=-1) = «не смогли измерить»
                    // (транзиент сразу после коннекта: маршруты/DNS не осели) — один авто-ретрай через
                    // 20с (per-key, per-connect: m_svcRetried сбрасывается в probeServices). Blocked
                    // сюда больше не входит — его перепроверяет confirm-цикл гистерезиса выше.
                    if (state == -1 && !m_svcRetried.contains(key)) {
                        m_svcRetried.insert(key);
                        // Server-driven (backend-first, Task 3): svc_probe_retry_ms, фолбэк 20с (прежнее).
                        // AVPN backend-first (final review R-3): клампим — 0/минус ретраил бы мгновенно
                        // (антипаттерн), сверху потолок 10 мин.
                        const int retryMs = qBound(1000, int(avpn::TuningStore::numberOr(
                                QStringLiteral("svc_probe_retry_ms"), 20000.0)), 600000);
                        QTimer::singleShot(retryMs, this, [this, key]() {
                            if (m_svcProbe && this->state() == QLatin1String("connected"))
                                m_svcProbe->probeOne(key);
                        });
                    }
                });
    }

    // AVPN remote-config (T6): вшитый публичный ключ (prod, key id k1) + дефолтные edges (baked —
    // обязателен по контракту ConfigService — фолбэк, если LKG-кеш ещё пуст на первом запуске).
    // ПОСЛЕ блока m_svcProbe (выше) НАРОЧНО: ConfigService::start() может синхронно эмитить
    // configApplied прямо из этого вызова (LKG-кеш готов мгновенно, без сети) → applyRemoteProbeTargets
    // должен застать УЖЕ созданный m_svcProbe, иначе серверный оверрайд probe-целей на холодном
    // офлайн-старте молча потерялся бы до следующего живого /v1/config (m_apiHostIps/carve-out эту
    // гонку не разделяют — они читаются из applyRuBypassSplit() в guardedStart(), намного позже ctor).
    // Remote-config signing key: prod by default; dev key only when a dev/E2E backend is pinned
    // via AVPN_API_URL (same env var read above for m_baseUrl override — keeps endpoint and key
    // selection consistent: dev endpoint ⇒ dev key, prod endpoint ⇒ prod key).
    const bool devApi = !qgetenv("AVPN_API_URL").isEmpty();
    const QString kConfigPubKeyHex = devApi
        ? QStringLiteral("95da1bd9062653d9c185c3ca5cae995516a8e353abccd3cf98cd12cd2f3a075a")
        : QStringLiteral("67bddcb248215a35ee2d8c2145ce415071ba02c5bcf888e35cc4491957aac78f");
    static const QStringList kBakedEdges{QStringLiteral("https://api.tribevpn.com"),
                                         QStringLiteral("https://vpn.wellwon.hk")};
    m_configSvc = new avpn::ConfigService(m_nam, m_baseUrl, kConfigPubKeyHex, kBakedEdges, this);
    connect(m_configSvc, &avpn::ConfigService::configApplied, this,
            [this](const avpn::RemoteConfig &c) {
                avpn::TuningStore::set(c.numbers, c.features, c.lists, c.urls); // AVPN backend-first (T19)
                // AVPN backend-first (T10): health-tick — server-tunable (numbers.health_tick_ms),
                // фолбэк 4000мс. setInterval на живом QTimer безопасен (Qt перезапускает с новым
                // интервалом, ничего не останавливаем/не стартуем).
                m_healthTimer.setInterval(avpn::healthTickMsTuned()); // кламп 1с..60с (0 с бэка = spin-loop)
                // AVPN backend-first: фоновый LKG-рефреш подписки по серверному интервалу
                // (H-3 бэклога). qBound — защита от абсурда: 10 мин..7 суток.
                const int refreshMs = qBound(600, c.subscriptionRefreshIntervalS, 7 * 24 * 3600) * 1000;
                // Periodic config checks must not postpone subscription refresh forever.
                if (!m_subRefreshTimer.isActive() || m_subRefreshTimer.interval() != refreshMs)
                    m_subRefreshTimer.start(refreshMs);
                m_remoteCfg = c;
                // AVPN (diag-report, Task 4 bff-3): timestamp применения конфига → возраст в отчёте.
                m_lastConfigAppliedEpoch = QDateTime::currentSecsSinceEpoch();
                // AVPN backend-first (T19): down/up speed-URL бенча — urls.bench_speed_down_url/
                // bench_speed_up_url с сервера, фолбэк = вкомпиленные литералы (BenchRunner ctor).
                if (m_bench)
                    m_bench->setSpeedUrls(
                        configUrl(QStringLiteral("bench_speed_down_url"),
                                  QStringLiteral("https://speed.cloudflare.com/__down?bytes=26214400")),
                        configUrl(QStringLiteral("bench_speed_up_url"),
                                  QStringLiteral("https://speed.cloudflare.com/__up")));
                // force-update вердикт: платформенная ветка — ЕДИНСТВЕННОЕ платформо-специфичное
                // место здесь (PLATFORM-SCOPING: serviceEngine общий, ветка строго под #ifdef Q_OS_*).
                const QString appVer = QStringLiteral(APP_VERSION);
                const QString plat = avpnPlatformKey();
                const avpn::UpdateVerdict v = avpn::compareVersions(
                    appVer, c.minAppVersion.value(plat), c.recommendedVersion.value(plat));
                m_updateState = (v == avpn::UpdateVerdict::Block) ? 2
                              : (v == avpn::UpdateVerdict::Recommend) ? 1 : 0;
                applyRemoteProbeTargets(c); // переопределить probe-цели, если пришли с сервера
                refreshQualityEndpoints();  // AVPN (T16): urls.quality_probe_url мог смениться
                emit changed();
            });
    connect(m_configSvc, &avpn::ConfigService::activeEdgeChanged, this,
            [this](const QString &base) {
                m_baseUrl = base;              // control plane переключился на живой вход (edge-walk)
                refreshQualityEndpoints();     // AVPN (T16): живые палочки — новый /v1/ping-хост
                rebuildApiCarveOut();          // новый хост — в carve-out (async резолв + reapply)
                emit apiBaseChanged(base);     // AVPN backend-first: сателлиты (чат поддержки) следуют за edge
#ifdef Q_OS_IOS
                AvpnDiagnostics_setBase(m_baseUrl.toUtf8().constData());
#endif
                emit changed();
            });

    // AVPN server-driven АнтиВПН (Task 10): сервис серверных bypass-списков (/v1/bypass-lists —
    // ru_cidrs/bypass_extra/cn_liauto_cidrs/split_dns, подпись+LKG). Тот же m_nam/kConfigPubKeyHex,
    // что у ConfigService — dev-эндпоинт ⇒ dev-ключ, prod ⇒ prod-ключ. baseUrl берём из
    // m_configSvc->activeBaseUrl() (НЕ из m_baseUrl напрямую): ConfigService уже создан и
    // поднял персистнутый edge на конструкции; activeEdgeChanged эмитится только при СМЕНЕ
    // edge, а не на холодном старте — если бы тут стоял m_baseUrl (ещё primary), а прод уже
    // персистнул рабочий edge с прошлой сессии, bypass-фетч бил бы в заблокированный primary
    // до первой смены edge (которая при живом primary может не наступить вовсе).
    // Kill-switch remote_bypass_lists реализован ВНУТРИ сервиса (onRemoteConfigApplied: при
    // флаге=false → пустой invalid снапшот в BypassListStore + фетч на паузу) ⇒ точки чтения
    // (applyRuBypassSplit / VpnConnectionTunnelControl) проверяют только bl.valid.
    // Порядок: создаём m_bypassListSvc и подключаем оба connect'а ДО m_configSvc->start() —
    // ConfigService::start() может синхронно эмитнуть configApplied на тёплом LKG-старте
    // (без сети), и если бы connect стоял после start(), это первое персистнутое состояние
    // флага remote_bypass_lists терялось бы: офлайн-сеанс мог целиком прожить со стейл-LKG
    // BypassListService вместо актуального флага. Реордер закрывает это окно: оба connect'а
    // гарантированно ловят даже синхронный первый configApplied. m_bypassListSvc->start()
    // (loadLkg + fetch) остаётся ПОСЛЕ m_configSvc->start() — сам старт не участвует в гонке.
    m_bypassListSvc = new avpn::BypassListService(m_nam, m_configSvc->activeBaseUrl(), kConfigPubKeyHex, this);
    connect(m_configSvc, &avpn::ConfigService::configApplied,
            m_bypassListSvc, &avpn::BypassListService::onRemoteConfigApplied);
    connect(m_configSvc, &avpn::ConfigService::activeEdgeChanged,
            m_bypassListSvc, &avpn::BypassListService::setBaseUrl);

    m_configSvc->start();
    m_bypassListSvc->start();

    // AVPN (Task 7): таймер авто-паузы «для покупок». Одноразовый: истёк → бездействие → resume.
    m_pauseTimer.setSingleShot(true);
    connect(&m_pauseTimer, &QTimer::timeout, this, &AvpnEngineQml::onPauseTimeout);

    // AVPN (reconcile-машина): единый сторож. Если терминальный колбэк туннеля (Connected/Disconnected)
    // не прилетит за таймаут (iOS NE иногда не рапортует чистый Disconnected) — разблокируем машину,
    // чтобы отложенный старт/стоп не залип навсегда. Один таймер (не накапливаем singleShot, как раньше).
    m_watchdog.setSingleShot(true);
    m_watchdog.setInterval(15000); // > 12с iOS handshake-timeout, чтобы не прерывать нормальный connect.
                                   // NB (аудит N9): для app-инициированных стартов именно ЭТОТ сторож
                                   // ограничивает ожидание (~1 handshake-таймаут); политика «3 таймаута»
                                   // в ios_controller работает для OS-инициированных стартов (интент/Настройки).
    connect(&m_watchdog, &QTimer::timeout, this, &AvpnEngineQml::onWatchdog);

    // AVPN (Task E): консьюмер «намерений» фонового iOS App Intent (Task 8). Интент в фоне уже
    // реально опустил/поднял туннель и записал флаг в App Group; при выходе в foreground натив-слой
    // (QtAppDelegate.mm → Avpn_consumeIntentFlags → AvpnIntentController.mm) эмитит сигналы моста.
    // Здесь согласуем СВОЁ состояние: pause → pauseForShopping (m_paused + гасим failover),
    // resume → resumeFromPause. На desktop мост молчит (Avpn_consumeIntentFlags — no-op).
    connect(avpn::AvpnIntentBridge::instance(), &avpn::AvpnIntentBridge::pauseRequested,
            this, [this]() { pauseForShopping(); });
    connect(avpn::AvpnIntentBridge::instance(), &avpn::AvpnIntentBridge::resumeRequested,
            this, &AvpnEngineQml::resumeFromPause);

    // AVPN (Task 9 — APNs): мост пушей. Натив (AvpnPushController.mm) кладёт device token + окружение в
    // мост; здесь, получив deviceTokenReady, шлём токен на бэк авторизованно (Bearer subscription_token).
    // На desktop мост молчит (нет натив-регистратора). markAllRead из QML → readRequested → сброс
    // серверного счётчика. Singleton-мост, как AvpnIntentBridge.
    connect(avpn::AvpnPushBridge::instance(), &avpn::AvpnPushBridge::deviceTokenReady,
            this, [this](const QString &token, const QString &platform, const QString &environment) {
                // AVPN (FCM 2026-07-13): платформа токена сквозная — бэк по ней выбирает
                // провайдера (ios→apns, android→fcm, POST /v1/devices/push-token).
                m_pushPlatform = platform;
                registerPushToken(token, environment);
            });
    connect(avpn::AvpnPushBridge::instance(), &avpn::AvpnPushBridge::readRequested,
            this, &AvpnEngineQml::markNotificationsRead);
    // AVPN (read per-элемент): изменён read-статус / удалён элемент → синк на сервер ТОЛЬКО его.
    connect(avpn::AvpnPushBridge::instance(), &avpn::AvpnPushBridge::readItemRequested,
            this, &AvpnEngineQml::markNotificationReadById);
    connect(avpn::AvpnPushBridge::instance(), &avpn::AvpnPushBridge::deleteItemRequested,
            this, &AvpnEngineQml::deleteNotificationById);
    // AVPN (P-ANN): пуш «объявление» → немедленный рефреш списка (попап всплывает сразу).
    connect(avpn::AvpnPushBridge::instance(), &avpn::AvpnPushBridge::announcementPushReceived,
            this, &AvpnEngineQml::refreshAnnouncements);

#if defined(Q_OS_MACOS) && !defined(MACOS_NE)
    // AVPN (P-ANN, macOS): бейдж непрочитанных на иконке дока — питается unreadCount моста
    // (aps.badge на десктоп не приходит). Реализация — platforms/macos/AvpnDockBadge.mm.
    AvpnDockBadge_install();
#endif

    // AVPN (Task 9): разрешение на пуши спрашиваем ОДИН раз — после первого успешного коннекта (UX:
    // контекстный запрос). Persist, чтобы не пытаться при каждом коннекте (iOS и так дедупит промпт).
    {
        QSettings s;
        m_pushPermissionAsked = s.value(QStringLiteral("AvpnPush/permissionAsked"), false).toBool();
    }
    loadAnnouncementsLkg(); // AVPN (P-ANN): объявления из LKG до сети (fetch заменит после bootstrap)

    // реактивный failover + правдивый статус: реальное состояние туннеля. // AVPN
    if (m_conn) {
        connect(m_conn, &VpnConnection::connectionStateChanged,
                this, &AvpnEngineQml::onConnectionStateChanged, Qt::QueuedConnection);
        // AVPN: протокол-уровневые ошибки (ErrorCode) идут отдельным сигналом — раньше терялись.
        connect(m_conn, &VpnConnection::vpnProtocolError,
                this, &AvpnEngineQml::onVpnProtocolError, Qt::QueuedConnection);
    }

#ifdef Q_OS_ANDROID
    // AVPN (рассинхрон после фона, 2026-07-07): Android-активити при возврате из фона ре-байндится к
    // сервису и получает СНАПШОТ статуса (REQUEST_STATUS -> STATUS -> JNI onStatus -> сырой сигнал
    // status). До фикса цепочка была дырявой дважды: (1) апстрим слал фейковый Disconnected на каждый
    // onStop (убрано в AmneziaActivity -- состояние больше не «забывается» в фоне), (2) restore-сигнал
    // initConnectionState шёл в ванильный UI-контроллер МИМО VpnConnection/движка. Теперь движок
    // слушает СЫРОЙ AndroidController::status и адоптит ТОЛЬКО РАСХОЖДЕНИЕ факта с нашим состоянием:
    //  - факт Connected, мы «не connected» -> вернуть намерение + adoptTunnelConnected (воскреситель;
    //    покрывает холодный старт при живом туннеле и восстановление после РЕАЛЬНОГО обрыва байндинга
    //    -- те пути всё ещё шлют фейковый Disconnected);
    //  - факт Disconnected, мы «connected» -> честный Disconnected (туннель погас, пока были в фоне);
    //  - состояния согласованы -> НИЧЕГО (никаких пере-проб/вспышек при обычном возврате из фона).
    // Промежуточные снапшоты (Connecting/...) не трогаем -- терминал прилетит обычным путём.
    connect(AndroidController::instance(), &AndroidController::status, this,
            [this](AndroidController::ConnectionState st) {
                const bool thinkConnected = (state() == QLatin1String("connected"));
                if (st == AndroidController::ConnectionState::CONNECTED && !thinkConnected) {
                    m_wantConnected = true;
                    m_engine.adoptTunnelConnected();
                    onConnectionStateChanged(Vpn::Connected);
                } else if (st == AndroidController::ConnectionState::DISCONNECTED && thinkConnected) {
                    onConnectionStateChanged(Vpn::Disconnected);
                }
            },
            Qt::QueuedConnection);
#endif

    // AVPN (Task 11): тихий bootstrap при создании движка — наполнить подписку ДО первого Connect,
    // чтобы бейдж ГБ/дней/subActive был живой сразу. Дефер через singleShot(0): bootstrap() делает
    // синхронный сетевой вызов (QEventLoop), поэтому не блокируем конструктор/инициализацию UI —
    // отдаём управление циклу событий. КРАШ-ФИКС: singleShot(0) слишком рано — bootstrap крутит
    // вложенный QEventLoop, и если он сработает во время загрузки/показа QML, вложенный цикл
    // прокручивает чужие события (таймеры/фокус) на недостроенном дереве → re-entrancy SIGSEGV
    // (QQuickItem::setFocus). 1200мс гарантируют, что окно показано и loop простаивает (как при
    // пользовательском start()). Идемпотентно (m_bootstrapped). // AVPN
    QTimer::singleShot(1200, this, &AvpnEngineQml::bootstrap);

#if defined(Q_OS_MACOS) && !defined(MACOS_NE)
    // AVPN (BUG-6, адопция при перезапуске GUI): демон держит туннель через выход GUI — спросить
    // его статус на старте и адоптировать живой туннель (см. probeDaemonTunnelOnStartup). 1500мс:
    // после показа окна; чисто async (QLocalSocket), вложенных QEventLoop нет — конфликт с
    // bootstrap(1200мс) исключён.
    QTimer::singleShot(1500, this, &AvpnEngineQml::probeDaemonTunnelOnStartup);
#endif

    // AVPN (LKG, C-7): мгновенный бейдж/пул из последнего удачного ответа /v1/subscription —
    // холодный старт не мигает «∞» и список серверов не пустой, пока сетевой bootstrap в пути.
    // Чистый парс без сети/QEventLoop — из конструктора безопасно. Источник правды — сервер:
    // успешный фетч перезапишет данные (loadSubscription снимет lkgStale). emit не нужен —
    // QML-биндинги читают Q_PROPERTY при первом создании, т.е. уже ПОСЛЕ этой строки.
    {
        const QByteArray lkg = Enrollment::loadLkgSubscription();
        QString lkgErr;
        if (!lkg.isEmpty() && !m_engine.loadSubscriptionFromLkg(lkg, lkgErr))
            qWarning() << "avpn: lkg subscription cache unusable:" << lkgErr; // не фатально: bootstrap догрузит
    }
    // AVPN awg31-xray-v1 (спека §2.3): локальные настройки транспорта — ручной режим
    // (avpn/transportMode: auto|awg|xray, незнакомое = auto) и история транспортов по парам
    // локация×proto (avpn/transportHistory, JSON; клампы внутри TransportHistory::fromJson —
    // битое/стейл значение не портит выбор). Без сети/QEventLoop — из конструктора безопасно.
    {
        QSettings s;
        m_engine.setTransportMode(avpn::transportModeFromString(
            s.value(QStringLiteral("avpn/transportMode"), QStringLiteral("auto")).toString()));
        m_engine.loadTransportHistory(s.value(QStringLiteral("avpn/transportHistory")).toByteArray());
    }

    // AVPN (фикс «на сотовой ∞ навсегда»): единый member-таймер ретрая bootstrap (вместо
    // одноразовых singleShot) — kickBootstrap() может его поджать при появлении сети/foreground.
    m_bootstrapRetryTimer.setSingleShot(true);
    connect(&m_bootstrapRetryTimer, &QTimer::timeout, this, &AvpnEngineQml::tryBootstrapSubscription);

    // AVPN (фикс «на сотовой ∞ навсегда»): появление сети / смена Wi-Fi↔сотовая → поджать ретрай.
    // ТОЛЬКО ускоряет фетч подписки, когда она ещё не загружена (kickBootstrap — no-op после
    // успеха); туннель/коннект/выбор ноды НЕ трогает — хождение между роутерами с поднятым VPN
    // сюда не попадает. loadDefaultBackend идемпотентен (второй вызов в benchExtra — ок).
    // AVPN (store-flow E, 2026-07-09): foreground-рефреш подписки НА УРОВНЕ ДВИЖКА. Раньше жил
    // только в PageConnectTribe (Connections на Qt.application), а вкладки существуют ПО ОДНОЙ
    // (goToTabBarPageUrl = clear+replace) → вернулся из браузера после оплаты на вкладке
    // Поддержка/Настройки — рефреша НЕ было, бейдж/золотая CTA стейл до захода на главную.
    // Движок живёт всегда → покрывает все страницы и платформы. Троттл 30с (как у QML-пути;
    // QML-путь в PageConnectTribe оставлен — он же дёргает kickBootstrap/refreshAccount; лишний
    // параллельный GET /v1/subscription в момент резюма дёшев и безвреден). Async, no-op без токена.
    if (auto *guiApp = qobject_cast<QGuiApplication *>(QCoreApplication::instance())) {
        connect(guiApp, &QGuiApplication::applicationStateChanged, this,
                [this](Qt::ApplicationState st) {
                    if (st != Qt::ApplicationActive)
                        return;
                    // AVPN (белые списки): foreground-триггер детектора — ДО троттла рефреша
                    // (детектор дебаунсит сам; в активном режиме это немедленная exit-проба).
                    if (m_whitelistDetector)
                        m_whitelistDetector->noteForeground();
                    const qint64 now = QDateTime::currentMSecsSinceEpoch();
                    if (now - m_lastFgRefreshMs < 30000)
                        return;
                    m_lastFgRefreshMs = now;
                    refreshSubscription();
                });
    }

    if (QNetworkInformation::loadDefaultBackend()) {
        if (auto *ni = QNetworkInformation::instance()) {
            connect(ni, &QNetworkInformation::reachabilityChanged, this,
                    [this](QNetworkInformation::Reachability r) {
                        if (r == QNetworkInformation::Reachability::Online) {
                            kickBootstrap();
#if defined(Q_OS_MACOS) && !defined(MACOS_NE)
                            // AVPN (wake-реконнект): сеть вернулась после сна — ретрай нашего
                            // wake-рестарта (кап внутри wakeKick). 1.5с — DHCP/DNS доседают.
                            if (m_wakeRestartPending)
                                QTimer::singleShot(1500, this, [this]() { wakeKick(); });
#endif
                        }
                    });
            connect(ni, &QNetworkInformation::transportMediumChanged, this,
                    [this](QNetworkInformation::TransportMedium) { kickBootstrap(); });
        }
    }

    // AVPN (белые списки, спека 2026-07-12): детектор дифф-проб «РКН-whitelist на сотовой».
    // Только мобилки (PLATFORM-SCOPING): на десктопе сотовая — экзотика, гейт снимем позже.
    // m_nam — общий QNAM движка: при опущенном туннеле (единственное состояние, когда детектор
    // пробует — гейт tunnelIdle) запросы идут напрямую по сотовой сети. Создаётся ПОСЛЕ
    // loadDefaultBackend — детектору нужен живой QNetworkInformation::instance().
#if defined(Q_OS_IOS) || defined(Q_OS_ANDROID)
    m_whitelistDetector = new avpn::WhitelistDetector(
        m_nam, [this]() { return state() == QStringLiteral("disconnected"); }, this);
    connect(m_whitelistDetector, &avpn::WhitelistDetector::activeChanged, this, [this](bool on) {
        if (on) {
            m_whitelistEpisodeStartMs = QDateTime::currentMSecsSinceEpoch();
        } else {
            // Эпизод кончился — в локальную очередь телеметрии (кап 10 FIFO; шлём при первом
            // успешном контакте с control plane — в момент эпизода сеть мертва по определению).
            if (m_whitelistEpisodeStartMs > 0) {
                QSettings st;
                QJsonArray arr = QJsonDocument::fromJson(
                    st.value(QStringLiteral("Whitelist/episodes")).toByteArray()).array();
                QJsonObject ep;
                ep.insert(QStringLiteral("started_at"), double(m_whitelistEpisodeStartMs / 1000));
                ep.insert(QStringLiteral("ended_at"),
                          double(QDateTime::currentMSecsSinceEpoch() / 1000));
                ep.insert(QStringLiteral("net_type"), QStringLiteral("cellular"));
                arr.append(ep);
                while (arr.size() > 10)
                    arr.removeFirst();
                st.setValue(QStringLiteral("Whitelist/episodes"),
                            QJsonDocument(arr).toJson(QJsonDocument::Compact));
                st.sync();
                m_whitelistEpisodeStartMs = 0;
                m_whitelistEpisodesSent = false; // свежий эпизод — разрешить отправку
            }
            if (m_whitelistAcked) {
                m_whitelistAcked = false;   // новый эпизод покажет попап снова
                emit whitelistAckedChanged();
            }
            kickBootstrap();                // сеть вернулась — немедленно к нормальному циклу
        }
        emit whitelistModeChanged();
    });
    // Второй источник сигналов control plane — фетчи /v1/config (bootstrap-цепочка — первый).
    if (m_configSvc) {
        connect(m_configSvc, &avpn::ConfigService::transportFailed, m_whitelistDetector,
                &avpn::WhitelistDetector::noteControlPlaneFailure);
        connect(m_configSvc, &avpn::ConfigService::transportOk, m_whitelistDetector,
                &avpn::WhitelistDetector::noteControlPlaneOk);
    }
#endif
}

// AVPN remote-config (T6): фичефлаг/URL из последнего применённого /v1/config (LKG на старте,
// свежий — после первого успешного fetch). Ключ отсутствует на сервере → def.
bool AvpnEngineQml::featureEnabled(const QString &key, bool def) const
{
    return avpn::featureFlag(m_remoteCfg, key, def);
}

QString AvpnEngineQml::configUrl(const QString &key, const QString &def) const
{
    return m_remoteCfg.urls.value(key, def);
}

// AVPN remote-config (T6): магазинная ссылка для баннера апдейта/CTA — urls.store_ios/store_android
// с сервера (можно поменять без ребилда, напр. сменить регион стора), фолбэк вшитый.
// AVPN (реш. владельца 2026-09-02): «Обновить» на десктопном macOS ставит новую версию сама.
// URL образа — server-driven (urls.macos_dmg_url) с вкомпиленным фолбэком; хост-гард и все проверки
// подписи/нотаризации/версии — внутри SelfUpdate (там же причина отказа человеческим текстом).
// Ключ платформы для карт min_app_version/recommended_version. ЕДИНСТВЕННОЕ платформо-специфичное
// место в этом файле (PLATFORM-SCOPING: serviceEngine общий, ветка строго под #ifdef Q_OS_*).
static QString avpnPlatformKey()
{
#if defined(Q_OS_IOS)
    return QStringLiteral("ios");
#elif defined(Q_OS_ANDROID)
    return QStringLiteral("android");
#elif defined(Q_OS_MACOS)
    return QStringLiteral("macos");
#elif defined(Q_OS_WIN)
    return QStringLiteral("windows");
#else
    return QStringLiteral("linux");
#endif
}

QString AvpnEngineQml::appVersion() const
{
    const QStringList parts = QStringLiteral(APP_VERSION).split(QLatin1Char('.'));
    return parts.mid(0, 3).join(QLatin1Char('.'));
}

QString AvpnEngineQml::availableVersion() const
{
    const QString plat = avpnPlatformKey();
    const QString rec = m_remoteCfg.recommendedVersion.value(plat);
    return rec.isEmpty() ? m_remoteCfg.minAppVersion.value(plat) : rec;
}

void AvpnEngineQml::startSelfUpdate()
{
    if (!avpn::SelfUpdate::isSupported()) {
        emit selfUpdateFailed(tr("Обновление внутри приложения тут недоступно"));
        return;
    }
    if (!m_selfUpdate) {
        m_selfUpdate = new avpn::SelfUpdate(this);
        connect(m_selfUpdate, &avpn::SelfUpdate::progress, this,
                [this](const QString &t) { emit selfUpdateProgress(t); });
        connect(m_selfUpdate, &avpn::SelfUpdate::failed, this,
                [this](const QString &r) { emit selfUpdateFailed(r); });
        // installed(): образ проверен и подготовлен; финишер (nohup, скрипт SelfUpdate) ЖДЁТ
        // выхода нашего процесса (до 30 с), затем подменяет бандл и запускает новую версию.
        // Выйти обязаны МЫ: под живым процессом подмена + `open -a` новую копию не запускают —
        // LaunchServices лишь активирует старый инстанс (проверено 2026-09-04, MAC-29), и человек
        // оставался на старой версии до ручного перезапуска. Экрану даём показать «Готово,
        // перезапускаем…», затем штатный quit (aboutToQuit флашит настройки; живой туннель
        // остаётся у демона и адоптируется новой копией, §19).
        connect(m_selfUpdate, &avpn::SelfUpdate::installed, this, [this]() {
            emit selfUpdateInstalled();
            qInfo() << "[selfupdate] installed — quitting so the finisher can relaunch the new version";
            QTimer::singleShot(1500, qApp, &QCoreApplication::quit);
        });
    }
    // Маркетинговая версия (первые три компонента APP_VERSION) — нижняя граница: образ со
    // старой/равной версией скрипт не поставит.
    const QStringList parts = QStringLiteral(APP_VERSION).split(QLatin1Char('.'));
    const QString marketing = parts.mid(0, 3).join(QLatin1Char('.'));
    m_selfUpdate->start(configUrl(QStringLiteral("macos_dmg_url"), avpn::SelfUpdate::defaultDmgUrl()),
                        marketing);
}

QString AvpnEngineQml::storeUrl() const
{
#if defined(Q_OS_ANDROID)
    return m_remoteCfg.urls.value(QStringLiteral("store_android"),
        QStringLiteral("https://play.google.com/store/apps/details?id=com.tribevpn.client"));
#else
    return m_remoteCfg.urls.value(QStringLiteral("store_ios"),
        QStringLiteral("https://apps.apple.com/app/id6778394015"));
#endif
}

// AVPN remote-config (T6): вынесенный API/edge-хост carve-out (см. .h) — применяет вырез к
// КОНКРЕТНОМУ сев-набору sites. Вызывается ВНУТРИ applyRuBypassSplit РОВНО там же, где раньше
// был инлайн-блок — behaviour-preserving extraction, поведение на исходном месте не меняется.
// AVPN: ЕДИНЫЙ источник carve-IP control plane — и для фактического выреза (rebuildApiCarveOut),
// и для стампа сева (bypassSeedStamp). Ревью 2026-07-10: раньше стамп собирал этот же список
// вручную — добавление carve-IP в одном месте без другого дало бы «seed unchanged — skip» при
// реально изменившемся севе (стале-маршрут для control plane = инцидент 2026-07-05).
QStringList AvpnEngineQml::apiCarveIps() const
{
    QStringList ips{QStringLiteral("159.194.214.36")}; // вкомпиленный фолбэк (Beget, api.tribevpn.com)
    for (const QHostAddress &ip : std::as_const(m_apiHostIps))
        ips << ip.toString();
    return ips;
}

void AvpnEngineQml::rebuildApiCarveOut(QMap<QString, QStringList> &sites) const
{
    // AVPN carve-out (инцидент 2026-07-05): api.tribevpn.com хостится на Beget (RU) и накрывается
    // ru_prefixes (159.194.208.0/20) → control plane уходил мимо туннеля, где его режет оператор:
    // пустое приложение без подписки/нод, а WG-туннель при этом жив. Исключаем IP API из сева
    // (дихотомическое разбиение накрывающих CIDR без /32 — остальной рунет по-прежнему direct).
    // Вкомпиленный фолбэк + актуальные IP из async-резолва — единый список apiCarveIps().
    const QStringList ips = apiCarveIps();
    for (const QString &ip : ips)
        carveOutIpFromSites(sites, QHostAddress(ip));
}

// AVPN remote-config (T6): «новый активный edge — в carve-out». Резолвит host(m_baseUrl) (уже
// переключён вызывающим activeEdgeChanged-обработчиком) в m_apiHostIps (async QHostInfo, тот же
// паттерн, что в конструкторе для исходного m_baseUrl; накопительно — не теряем IP предыдущих
// edge, лишний carve-out безвреден) и передёргивает сплит через reapplyBypass(). reapplyBypass()
// — единственный штатный способ докатить сев до ЖИВОГО туннеля (см. setBypassMasterOn и др.):
// на живом коннекте reconcile сделает stop→start, а guardedStart() пересеет applyRuBypassSplit()
// (который зовёт rebuildApiCarveOut(sites) выше) уже со свежим m_apiHostIps. Офлайн → no-op
// (reapplyBypass сам гейтит по m_wantConnected) — свежий сев подхватится на следующем Connect.
void AvpnEngineQml::rebuildApiCarveOut()
{
    const QString host = QUrl(m_baseUrl).host();
    if (host.isEmpty() || !QHostAddress(host).isNull()) { // пусто или уже literal-IP — резолвить не надо
        reapplyBypass();
        return;
    }
    QHostInfo::lookupHost(host, this, [this](const QHostInfo &info) {
        if (info.error() == QHostInfo::NoError) {
            for (const QHostAddress &ip : info.addresses())
                if (!m_apiHostIps.contains(ip))
                    m_apiHostIps.append(ip);
        }
        reapplyBypass();
    });
}

// AVPN remote-config (T6): сервер может переопределить цели проб чипов (probeTargets из
// /v1/config) — напр. сменить seed-хост без ребилда. МЕРЖ с вшитыми дефолтами, НЕ замещение:
// семантика, kind-гейт (только явные "mtproto"/"goodput"/"https"; "tcp" = данные арбитра — игнор)
// и multi-seed-группировка — в avpn::mergeRemoteProbeTargets (ServiceProbeTargets.h, там же
// разбор инцидента 2026-07-11 «Telegram красный / Instagram серый» и TDD-контракт).
void AvpnEngineQml::applyRemoteProbeTargets(const avpn::RemoteConfig &cfg)
{
    if (!m_svcProbe)
        return;
    // AVPN backend-first (Task 4 + мерж ci-build 9ad41a45): серверные probe-цели МЕРЖАТСЯ с вшитыми
    // дефолтами (avpn::mergeRemoteProbeTargets — kind-гейт, multi-seed-группировка), НЕ замещают их.
    // Результат мержа кладётся в m_svcCfgsAll (полный нефильтрованный набор); rebuildServiceChips()
    // применит lists.service_chips_disabled к смерженному набору и пересоберёт m_svcProbe->setServices
    // + m_serviceStatus (иначе дрейф чипов при remote override). Пустой disabled-список → фильтр
    // прозрачен, поведение байт-в-байт как в 9ad41a45.
    m_svcCfgsAll = avpn::mergeRemoteProbeTargets(avpn::defaultServiceProbeConfigs(), cfg.probeTargets);
    rebuildServiceChips();
}

// AVPN backend-first (T16): цели QualityProbe (живые палочки) следуют за edge-walk и
// urls.quality_probe_url. Свой бэкенд-пинг всегда первый приоритет; публичный generate_204 —
// фолбэк-литерал байт-в-байт как в конструкторном сиде, если сервер URL не прислал.
void AvpnEngineQml::refreshQualityEndpoints()
{
    if (!m_probe)
        return;
    m_probe->setEndpoints({m_baseUrl + QStringLiteral("/v1/ping"),
                           configUrl(QStringLiteral("quality_probe_url"),
                                     QStringLiteral("https://connectivitycheck.gstatic.com/generate_204"))});
}

// AVPN backend-first (Task 4): пер-сервисный kill-switch чипов доступности (lists.service_chips_disabled).
// Отфильтровывает m_svcCfgsAll (полный набор — ctor-дефолт telegram/youtube/instagram ЛИБО remote
// probeTargets из applyRemoteProbeTargets) по серверному списку отключённых ключей:
//   · m_svcProbe получает ТОЛЬКО включённые cfgs → probeAll()/probeOne() физически не пробуют
//     отключённый сервис (не тратят трафик через туннель);
//   · m_serviceStatus ПЕРЕСТРАИВАЕТСЯ ЦЕЛИКОМ (не мержится point-wise) под тот же набор → отключённый
//     чип пропадает из UI (QML TribeServiceChips дата-driven от serviceStatus, правок не требует).
// Уже известные состояния (works/slow/blocked/rttMs) сохраняются по key для сервисов, оставшихся
// включёнными — повторный вызов не сбрасывает их обратно в «неизвестно».
// Пустой/отсутствующий список (TuningStore::listOr «пусто=фолбэк») → фильтр не убирает ничего,
// поведение байт-в-байт как до задачи.
void AvpnEngineQml::rebuildServiceChips()
{
    if (!m_svcProbe)
        return;

    const QStringList disabled =
            avpn::TuningStore::listOr(QStringLiteral("service_chips_disabled"), {});
    QList<ServiceProbeConfig> enabled;
    enabled.reserve(m_svcCfgsAll.size());
    for (const ServiceProbeConfig &c : std::as_const(m_svcCfgsAll)) {
        if (!disabled.contains(c.key))
            enabled.append(c);
    }
    m_svcProbe->setServices(enabled);

    auto labelOf = [](const QString &k) {
        if (k == QLatin1String("telegram"))  return QStringLiteral("Telegram");
        if (k == QLatin1String("youtube"))   return QStringLiteral("YouTube");
        if (k == QLatin1String("instagram")) return QStringLiteral("Instagram");
        if (k == QLatin1String("whatsapp"))  return QStringLiteral("WhatsApp"); // AVPN (Доктор v1)
        return k;
    };
    QHash<QString, QVariantMap> prevByKey;
    for (const QVariant &v : std::as_const(m_serviceStatus)) {
        const QVariantMap m = v.toMap();
        prevByKey.insert(m.value(QStringLiteral("key")).toString(), m);
    }
    QVariantList next;
    next.reserve(enabled.size());
    for (const ServiceProbeConfig &c : std::as_const(enabled)) {
        const auto it = prevByKey.constFind(c.key);
        if (it != prevByKey.constEnd()) {
            next.append(it.value()); // сохраняем известный state/rttMs для уже пробитого сервиса
        } else {
            QVariantMap m;
            m[QStringLiteral("key")] = c.key;
            m[QStringLiteral("label")] = labelOf(c.key);
            m[QStringLiteral("state")] = -1;
            m[QStringLiteral("rttMs")] = -1;
            m[QStringLiteral("stale")] = false; // v2: приглушение QML читает этот флаг
            next.append(m);
        }
    }
    if (next != m_serviceStatus) {
        m_serviceStatus = next;
        emit serviceStatusChanged();
    }
}

// AVPN BUG-13 (2026-07-30): чипы → «не проверено» (синий), гистерезис и бюджеты серии — с нуля.
// Зовётся на входе в connected: вердикты прошлой ноды/сессии к новому туннелю отношения не имеют,
// а показывать их как текущие (особенно красный) — врать пользователю.
void AvpnEngineQml::resetServiceChipsToUnknown()
{
    if (m_svcProbe)
        m_svcProbe->invalidate(); // in-flight результаты прошлой серии не должны дописаться
    m_chipHyst.clear();
    m_chipConfirms.clear();

    bool changed = false;
    for (int i = 0; i < m_serviceStatus.size(); ++i) {
        QVariantMap m = m_serviceStatus.at(i).toMap();
        if (m.value(QStringLiteral("state"), -1).toInt() != -1
            || m.value(QStringLiteral("rttMs"), -1).toInt() != -1
            || m.value(QStringLiteral("stale"), false).toBool()) {
            m[QStringLiteral("state")] = -1;
            m[QStringLiteral("rttMs")] = -1;
            m[QStringLiteral("stale")] = false;
            m_serviceStatus[i] = m;
            changed = true;
        }
    }
    if (changed)
        emit serviceStatusChanged();
}

QString AvpnEngineQml::state() const
{
    // AVPN (Task 7): «paused» — наша надстройка над фазами движка (туннель реально down, ждём
    // авто-возврат). Перекрывает disconnected, чтобы UI отличал паузу-для-покупок от обычного стопа.
    if (m_paused)
        return QStringLiteral("paused");
    return debugSnapshot().value(QStringLiteral("state")).toString();
}

// AVPN (белые списки): активный РКН-режим whitelist (детектор жив только на iOS/Android).
bool AvpnEngineQml::whitelistMode() const
{
    return m_whitelistDetector && m_whitelistDetector->active();
}

void AvpnEngineQml::setWhitelistAcked(bool on)
{
    if (m_whitelistAcked == on)
        return;
    m_whitelistAcked = on;
    emit whitelistAckedChanged();
}

// AVPN: текущее устройство — нативная маркетинговая модель/ОС (DeviceModel.h). Перекрывают
// невнятный backend-label (часто «macos») в разделе «Устройства».
QString AvpnEngineQml::thisDeviceName() const { return avpn::deviceMarketingName(); }
QString AvpnEngineQml::thisDeviceOs() const { return avpn::deviceOsName(); }

// AVPN: статус подписки (Task 3) — единый источник debugSnapshot() (как state()).
qlonglong AvpnEngineQml::trafficUsed() const
{
    return debugSnapshot().value(QStringLiteral("trafficUsed")).toLongLong();
}

qlonglong AvpnEngineQml::trafficLimit() const
{
    return debugSnapshot().value(QStringLiteral("trafficLimit")).toLongLong();
}

// AVPN: JWT подписки из защищённого стора — для редиректа в кабинет с авторизацией.
QString AvpnEngineQml::authToken() const
{
    return Enrollment::loadToken();
}

bool AvpnEngineQml::subActive() const
{
    return debugSnapshot().value(QStringLiteral("subStatus")).toString() == QLatin1String("active");
}

// AVPN (баг 2026-07-10 «вечная загрузка без подписки»): достоверное «подписки нет» = снапшот
// degraded (бэк ставит его ТОЛЬКО по состоянию устройства: expired/over-quota/без tunnel_ip)
// И пул пуст. active+пустой пул (все ноды в дренаже у подписанного) сюда не попадает; до
// первого распарсенного тела subStatus пуст → false («ещё грузится», не CTA).
bool AvpnEngineQml::subMissing() const
{
    return debugSnapshot().value(QStringLiteral("subStatus")).toString() == QLatin1String("degraded")
           && !m_engine.hasSubscription();
}

QString AvpnEngineQml::localDeviceId() const
{
    // installation-UUID из secure-store — стабильный, генерится на первом запуске, тот же уходит
    // на backend при enroll (=> совпадает с devices.device_id). Доступен всегда, без сети.
    return Identity::deviceId(m_store);
}

int AvpnEngineQml::daysLeft() const
{
    const QString iso = debugSnapshot().value(QStringLiteral("expiresAt")).toString();
    if (iso.isEmpty())
        return -1; // бессрочно / неизвестно
    const QDateTime exp = QDateTime::fromString(iso, Qt::ISODate);
    if (!exp.isValid())
        return -1;
    const qint64 secs = QDateTime::currentDateTimeUtc().secsTo(exp.toUTC());
    // AVPN: округление ВВЕРХ (ceil), а не вниз — чтобы совпадало с админкой/бэкендом: «осталось
    // 6 дней 18 часов» = «7 дней» (раньше floor давал 6, юзер видел рассинхрон с выданными 7).
    return secs <= 0 ? 0 : static_cast<int>((secs + 86399) / 86400);
}

QString AvpnEngineQml::subExpiresAt() const
{
    return debugSnapshot().value(QStringLiteral("expiresAt")).toString();
}

// AVPN: текущий сервер для карточки Connect. Показываем ноду ТОЛЬКО когда реально подключены/
// переключаемся; до коннекта и после стопа hasNode=false → карточка показывает «Умный выбор сервера»
// (умный выбор происходит в момент connect, выбранная нода видна уже подключённой). Без fallback на
// pool.first() — иначе в простое показывалась «Польша».
QVariantMap AvpnEngineQml::currentNode() const
{
    const DebugSnapshot s = m_engine.debugSnapshot();
    const QString pinned = m_engine.pinnedNodeId();
    const bool connectedNow = (s.state == QLatin1String("connected"));
    // Какой узел показывать на карточке Connect:
    //  • ПОДКЛЮЧЕНЫ → реальный текущий узел (s.currentNodeId) — честно даже если failover увёл
    //    с закреплённого;
    //  • закреплён вручную И НЕ подключены (переключаемся/оффлайн) → закреплённый узел СРАЗУ
    //    (оптимистично): тап по Латвии в пикере мгновенно показывает Латвию + орб «подключаюсь»,
    //    а не висит на старой Польше 1–3 c до нового рукопожатия (жалоба 2026-07-20). Орб
    //    отражает реальное состояние отдельно — обмана нет;
    //  • авто-switching без pin → пока старый узел;
    //  • иначе → ничего (hasNode=false) → карточка «Умный выбор сервера».
    QString showId;
    // AVPN awg31-xray-v1: в verifying туннель поднят на реальной ноде — показываем её (как connected).
    if ((connectedNow || s.state == QLatin1String("verifying")) && !s.currentNodeId.isEmpty())
        showId = s.currentNodeId;
    else if (!pinned.isEmpty())
        showId = pinned;
    else if (s.state == QLatin1String("switching") && !s.currentNodeId.isEmpty())
        showId = s.currentNodeId;
    const NodeDebugRow *pick = nullptr;
    if (!showId.isEmpty()) {
        for (const NodeDebugRow &r : s.pool)
            if (r.nodeId == showId) { pick = &r; break; }
    }
    QVariantMap node;
    node["nodeId"]    = pick ? pick->nodeId : QString();
    node["region"]    = pick ? pick->region : QString();
    node["name"]      = pick ? pick->name : QString();
    node["countryCode"] = pick ? pick->countryCode : QString(); // AVPN: для флага-эмодзи
    node["endpoint"]  = pick ? pick->endpoint : QString();
    node["ip"]        = pick ? pick->endpoint.section(QLatin1Char(':'), 0, 0) : QString();
    // AVPN awg31-xray-v1: транспорт показанного узла — бейдж «Amnezia v3.1»/«Xray» на карточке
    // Connect. Даём из currentNode (а не сканом nodePool в QML): nodePool пересобирает и ранжирует
    // весь снапшот на КАЖДЫЙ changed() (тик ~4с) — биндинг главного экрана этого не стоит.
    node["proto"]        = pick ? pick->proto : QString();
    node["protoVersion"] = pick ? pick->protoVersion : QString(); // "2"/"3"/"3.1"; xray — пусто
    node["connected"] = (s.state == QLatin1String("connected"));
    node["hasNode"]   = (pick != nullptr);
    // AVPN: бейдж «auto» — показываем ТОЛЬКО когда подключены в авто-режиме (узел выбрал движок, pin
    // пуст). При ручном выборе (pin задан) бейджа нет. pinned — что показанный узел закреплён вручную.
    node["pinned"]    = (!pinned.isEmpty() && pick && pick->nodeId == pinned);
    node["auto"]      = (s.state == QLatin1String("connected") && pinned.isEmpty());
    return node;
}

// AVPN: весь пул нод для страницы «Серверы» / шторки выбора.
// Обогащаем измеренным RTT (m_nodeRtt) → measuredRttMs + measuredBars (0..5; -1 = не мерили), затем
// сортируем «быстрые ВНИЗУ» (неизмеренные сверху). Без измерений порядок не меняется (все rtt=-1 ⇒
// rankFastestAtBottom стабилен) и палочки берутся из health, как и раньше (поведение идентично).
QVariantList AvpnEngineQml::nodePool() const
{
    QVariantList pool = debugSnapshot().value(QStringLiteral("pool")).toList();

    QHash<QString, QVariantMap> byId;
    QList<RankRow> rows;
    rows.reserve(pool.size());
    for (const QVariant &v : pool) {
        QVariantMap n = v.toMap();
        const QString id = n.value(QStringLiteral("nodeId")).toString();
        const int rtt = m_nodeRtt.value(id, -1);
        n[QStringLiteral("measuredRttMs")] = rtt;
        n[QStringLiteral("measuredBars")] = (rtt >= 0) ? barsForNode(rtt) : -1;
        byId.insert(id, n);
        rows.append({ id, rtt });
    }

    rows = rankFastestAtBottom(rows);
    QVariantList out;
    out.reserve(rows.size());
    for (const RankRow &r : rows)
        out.append(byId.value(r.nodeId));
    return out;
}

// AVPN (выбор по скорости): прямой ICMP-замер RTT до всех живых нод (off-tunnel). См. заголовок.
void AvpnEngineQml::probeNodeRtt()
{
    if (!m_rttProbe)
        return;
    // Через поднятый туннель замер к чужим нодам идёт ВНУТРИ туннеля (смазан) — держим кэш, не мерим.
    // AVPN awg31-xray-v1: в verifying туннель тоже поднят (xray ждёт пробу) — тот же гейт.
    if (state() == QLatin1String("connected") || state() == QLatin1String("verifying")) {
        m_rttProbe->cancel();
        return;
    }
    const QVariantList pool = debugSnapshot().value(QStringLiteral("pool")).toList();
    QList<RttTarget> targets;
    for (const QVariant &v : pool) {
        const QVariantMap n = v.toMap();
        if (!n.value(QStringLiteral("alive")).toBool())
            continue; // мёртвые по backend-данным не пингуем
        const QString id = n.value(QStringLiteral("nodeId")).toString();
        const QString host = n.value(QStringLiteral("ip")).toString(); // host без порта (см. debugSnapshot)
        if (id.isEmpty() || host.isEmpty())
            continue;
        targets.append({ id, host, 0 });
    }
    if (targets.isEmpty())
        return;

    m_rttProbe->probeAll(
        targets, 1500,
        [this](const QString &nodeId, int rttMs) {
            m_nodeRtt.insert(nodeId, rttMs);
            m_engine.setMeasuredRtt(m_nodeRtt); // AVPN: авто-выбор «быстрейший» берёт RTT отсюда (pickByMeasuredRtt)
            emit changed(); // шторка пересортируется + палочки обновятся по мере прихода пингов
        },
        []() {});
}

void AvpnEngineQml::onTick()
{
    // AVPN seamless roaming (CONNECT-INVARIANTS §23.8): с awg-apple tribe.4 iOS-движок при потере
    // пути НЕ гасится, поэтому в офлайне tx растёт (ретраи handshake), rx стоит, handshake стареет —
    // через 180 с это выглядело бы как DEAD → failover на другую ноду ещё ДО возврата сети (раньше
    // апстрим паузил устройство и статистики просто не было). Пока ОС говорит «сети нет» — health
    // не кормим и обнуляем выборку: DEAD = вердикт о туннеле при живой сети, не об офлайне.
    // kill-switch features.health_pause_offline (default ВКЛ).
    if (avpn::TuningStore::flag(QStringLiteral("health_pause_offline"), true)) {
        if (auto *ni = QNetworkInformation::instance();
            ni && ni->reachability() == QNetworkInformation::Reachability::Disconnected) {
            m_engine.resetHealthSampling();
            return;
        }
    }
    if (m_engine.tick(QDateTime::currentSecsSinceEpoch())) {
        persistTransportHistory(); // AVPN awg31-xray-v1: DEAD записан в историю транспорта
        emit changed(); // произошёл свитч
    } else if (surrenderIfDataPlaneDead()) {
        persistTransportHistory(); // AVPN (ревью волны, MAJOR-1): провал записан, дальше — честный OFF
        return;
    }

    // AVPN (реальные палочки): пока соединение активно — мерим RTT через туннель (async, без nested loop).
    // measure() сам игнорит повторный запуск, пока предыдущий в полёте. На не-connected — не мерим
    // и держим бары на 0 (hard-gate сбросит при следующем reachable=false, см. ниже onConnectionStateChanged).
    if (m_probe && avpn::TuningStore::flag(QStringLiteral("live_rtt")) && state() == QLatin1String("connected"))
        m_probe->measure();

    // AVPN (#35 живой трафик): пока подключены — каждый N-й тик (~20с при N=5, server-tunable
    // numbers.traffic_sync_ticks) освежаем счётчики.
    // ⚠️ ДВОЕ ЧАСОВ: берём /v1/subscription (ЧАСЫ УСТРОЙСТВА — их продлевает оплата), НЕ /v1/account
    // (часы аккаунта: на оплаченном устройстве затирали 36 дн./100ГБ триальными числами аккаунта).
    // refreshSubscription пишет traffic/expires в снапшот + emit changed() → бейдж живой.
    if (state() == QLatin1String("connected")) {
        if (++m_trafficSyncTicks
            >= int(avpn::TuningStore::numberOr(QStringLiteral("traffic_sync_ticks"), 5))) {
            m_trafficSyncTicks = 0;
            refreshSubscription();
        }
        // AVPN (sub-grace): подписка истекла и грейс (+N ч) прошёл → управляемое отключение.
        // ПОСЛЕ блока refreshSubscription: тот как раз освежает expiresAt снапшота (async),
        // так что решение принимается по максимально свежим данным, какие есть локально.
        enforceSubscriptionGrace();
    } else {
        m_trafficSyncTicks = 0; // сброс, чтобы первый ре-синк после коннекта был через полный интервал
    }
}

// AVPN (sub-grace): движок сам гасит активный туннель, когда «подписка истекла И грейс прошёл».
// Консервативно by design: пустой/невалидный expiresAt НИКОГДА не рвёт (SubscriptionGate);
// kill-switch features.subscription_grace_enforce (default TRUE — бэк может прислать false и
// выключить всё поведение без релиза); грейс server-tunable (numbers.subscription_grace_hours,
// фолбэк 24 ч, кламп >=1). Остановка — ТЕМ ЖЕ путём, что пользовательский stop(): намерение OFF
// (m_wantConnected=false внутри stop() — иначе reconcile поднял бы туннель обратно) + reconcile()
// (CONNECT-INVARIANTS §2: туннель трогает только reconcile, новых путей teardown не изобретаем).
// Гард m_graceStopInFlight: ровно ОДИН вход, пока идёт остановка (без него залипший в connected
// снапшот при op-in-flight звал бы stop() каждый тик). Сбрасывается явным start().
void AvpnEngineQml::enforceSubscriptionGrace()
{
    if (!avpn::TuningStore::flag(QStringLiteral("subscription_grace_enforce")))
        return; // kill-switch: бэк выключил принудительное отключение целиком
    if (m_graceStopInFlight)
        return; // остановка уже инициирована — не входим повторно
    const QString iso = debugSnapshot().value(QStringLiteral("expiresAt")).toString();
    const int graceHours = avpn::SubscriptionGate::graceHoursTuned();
    if (!avpn::SubscriptionGate::graceExpired(iso, graceHours, QDateTime::currentDateTimeUtc()))
        return;
    m_graceStopInFlight = true;
    m_subEnforcedStop = true;
    qInfo("[AVPN subgate] sub grace expired -> enforced stop (expiresAt=%s, graceHours=%d)",
          qPrintable(iso), graceHours);
    stop(); // тот же путь, что пользовательское выключение: намерение OFF + reconcile + changed()
    emit subscriptionEnforcedStop();
}

void AvpnEngineQml::probeServices()
{
    // AVPN backend-first (T11): kill-switch — гасит и авто-запуск, и ручной тап из UI (осознанно:
    // выключенный флаг должен глушить ВЕСЬ трафик проб, не только фоновый).
    if (!avpn::TuningStore::flag(QStringLiteral("service_probes")))
        return;
    // AVPN backend-first (Task 4): пер-сервисный kill-switch — подхватываем СВЕЖИЙ
    // lists.service_chips_disabled на КАЖДОМ прогоне (живой цикл: сервер выключил сервис ПОСЛЕ того,
    // как чип уже в m_serviceStatus → следующий probeServices() уберёт его без отдельного хука на
    // configApplied). Только при активном туннеле: иначе мерили бы доступность «мимо VPN» (не наша
    // цель — нам нужно «работает ли сервис ЧЕРЕЗ эту ноду»). On-connect (авто) + по тапу из UI; НЕ
    // поллинг (батарея).
    rebuildServiceChips();
    m_svcRetried.clear(); // новая серия → каждый сервис снова имеет право на один авто-ретрай Unknown
    m_chipConfirms.clear(); // и на свежий бюджет confirm-переппроб гистерезиса (v2)
    if (m_svcProbe && state() == QLatin1String("connected")) {
        // Инвалидация перед стартом (v2): застрявшая in-flight серия (напр. долгий goodput при
        // смене ноды) не блокирует новую и не дописывает старые вердикты. Гистерезис НЕ сбрасываем —
        // self-heal каждые 3 мин обязан проходить через него (иначе гистерезис бессмыслен).
        m_svcProbe->invalidate();
        m_svcProbe->probeAll();
    }
}

// AVPN (панель администратора): контекст замера. Пишем ФАКТЫ конфигурации из QSettings (не метки!) —
// иначе замер невозможно интерпретировать постфактум (реальный случай: 4 замера с метками
// baseline/bypass-on/off/amnezia оказались одним и тем же путём — метки врали, extra молчал).
QJsonObject AvpnEngineQml::benchExtra() const
{
    QJsonObject extra;
    extra.insert(QStringLiteral("platform"), QSysInfo::productType());
    extra.insert(QStringLiteral("app_ver"), QCoreApplication::applicationVersion());
    extra.insert(QStringLiteral("tunnel_state"), state());
    extra.insert(QStringLiteral("node_id"), debugSnapshot().value(QStringLiteral("currentNodeId")).toString());
    QSettings s;
    extra.insert(QStringLiteral("bypass_on"), s.value(QStringLiteral("AvpnBypass/masterOn"), true).toBool());
    extra.insert(QStringLiteral("liauto_on"), s.value(QStringLiteral("AvpnBypass/liAutoOn"), true).toBool());
    extra.insert(QStringLiteral("dns_mask_on"), s.value(QStringLiteral("AvpnBypass/dnsMaskOn"), true).toBool());
    // системная таймзона = где ФИЗИЧЕСКИ устройство (egress loc в network{} — где выход туннеля).
    // Без неё отчёты из разных стран несравнимы: провал RU-direct за границей — норма, в РФ — баг.
    extra.insert(QStringLiteral("tz"), QString::fromUtf8(QTimeZone::systemTimeZoneId()));
    // bench v5 (tunnel.config): фактический конфиг НАШЕГО туннеля — только когда поднят именно он
    // (baseline/amnezia меряют чужой путь — наш последний конфиг там был бы враньём). Санитизирован
    // by construction (AwgConfigBuilder::reportSummary). Даёт A/B с ванилью diff mtu/dns/awg в отчёте.
    // AVPN awg31-xray-v1 (§2.3 «отчёт содержит proto и результат probe»): транспорт текущей ноды,
    // ручной режим, итог верификации xray (probe через туннель: ok/ms) и стрик провалов живой пробы.
    {
        QJsonObject tr;
        tr.insert(QStringLiteral("proto"), m_engine.currentNodeProto());
        tr.insert(QStringLiteral("mode"), avpn::transportModeToString(m_engine.transportMode()));
        tr.insert(QStringLiteral("location"), m_engine.currentLocation());
        tr.insert(QStringLiteral("verifying"), m_engine.isVerifying());
        if (m_lastVerifyOk >= 0) {
            tr.insert(QStringLiteral("verify_ok"), m_lastVerifyOk == 1);
            tr.insert(QStringLiteral("verify_ms"), double(m_lastVerifyMs));
            tr.insert(QStringLiteral("verify_attempts"), m_verifyAttempts);
            // AVPN (ревью волны, MAJOR-3): было ли доказательство rx ЧЕРЕЗ туннель (false =
            // источник статистики молчал, верификацию приняли с оговоркой).
            tr.insert(QStringLiteral("verify_rx_proof"), m_lastVerifyRxProof);
        }
        tr.insert(QStringLiteral("probe_fail_streak"), m_liveFailStreak);
        // AVPN (ревью волны, MAJOR-1): подряд идущие провалы data-plane за сессию — паттерн
        // «оператор × сеть × сколько кандидатов не пропустили трафик» ищется по bench_reports.
        tr.insert(QStringLiteral("dataplane_fail_streak"), m_engine.dataPlaneFailStreak());
        tr.insert(QStringLiteral("probe_reachable"), m_liveReachable);
        extra.insert(QStringLiteral("transport"), tr);
    }
    if (state() == QLatin1String("connected")) {
        const QJsonObject tc = m_tunnel.lastConfigReport();
        if (!tc.isEmpty())
            extra.insert(QStringLiteral("tunnel_config"), tc);
        // v5.2 (обогащение): готовые живые сигналы клиента — чипы сервисов (goodput/троттл),
        // сглаженный RTT-бар и off-tunnel RTT-кэш нод (изоляция «нода vs провайдер»: сравнить
        // node_rtt_cache текущей ноды с base_rtt_ms через туннель = чистый оверхед туннеля).
        if (m_liveRtt > 0) {
            QJsonObject lq;
            lq.insert(QStringLiteral("rtt_ms"), m_liveRtt);
            lq.insert(QStringLiteral("bars"), m_liveBars);
            extra.insert(QStringLiteral("live_quality"), lq);
        }
        if (!m_serviceStatus.isEmpty())
            extra.insert(QStringLiteral("services"), QJsonArray::fromVariantList(m_serviceStatus));
        if (!m_nodeRtt.isEmpty()) {
            QJsonObject rtts;
            for (auto it = m_nodeRtt.constBegin(); it != m_nodeRtt.constEnd(); ++it)
                if (it.value() > 0)
                    rtts.insert(it.key(), it.value());
            if (!rtts.isEmpty())
                extra.insert(QStringLiteral("node_rtt_cache"), rtts);
        }
    }
    // тип сети: Wi-Fi и сотовая несравнимы между собой — без этого поля два замера не сопоставить
    static const bool niLoaded = QNetworkInformation::loadDefaultBackend();
    if (niLoaded) {
        if (auto *ni = QNetworkInformation::instance()) {
            switch (ni->transportMedium()) {
            case QNetworkInformation::TransportMedium::Ethernet:  extra.insert(QStringLiteral("net_type"), QStringLiteral("ethernet")); break;
            case QNetworkInformation::TransportMedium::WiFi:      extra.insert(QStringLiteral("net_type"), QStringLiteral("wifi")); break;
            case QNetworkInformation::TransportMedium::Cellular:  extra.insert(QStringLiteral("net_type"), QStringLiteral("cellular")); break;
            default: break; // unknown/bluetooth — не пишем, чтобы не врать
            }
        }
    }
    // Волна UX Доктора 07-22: iOS на сотовой отдаёт Unknown из QNetworkInformation («сеть
    // доступна» вместо «сотовая» — жалоба владельца). Деривация из CoreTelephony: поколение
    // сотовой непусто ⇒ мы на сотовой (работает и под VPN). Последний фолбэк — ручной выбор
    // в интро Доктора (не персистится: сеть могла смениться между запусками).
    if (!extra.contains(QStringLiteral("net_type"))) {
        if (!avpn::cellularGeneration().isEmpty())
            extra.insert(QStringLiteral("net_type"), QStringLiteral("cellular"));
        else if (!m_diagNetManual.isEmpty())
            extra.insert(QStringLiteral("net_type"), m_diagNetManual);
    }
    // AVPN (BUG-4 auto-heal): сколько раз за запуск heal ребайндил сокет — в каждый отчёт
    // (паттерн «оператор×нода×heal помог/нет» ищется по bench_reports без релиза).
    if (m_engine.rebindHealTotal() > 0)
        extra.insert(QStringLiteral("rebind_heals"), m_engine.rebindHealTotal());
    // AVPN (Доктор): оператор для паттернов «оператор X режет ноду Y». Приоритет — ручной выбор
    // пользователя (QSettings, единственный путь на iOS 16+, где API оператора закрыт), иначе
    // обезличенный авто-код MCC-MNC. Пусто → поле не пишем (Wi-Fi/десктоп/недоступно).
    QSettings carrierSettings;
    const QString carrierManual = carrierSettings.value(QStringLiteral("AvpnDiag/carrier")).toString();
    const QString carrier = !carrierManual.isEmpty() ? carrierManual : avpn::carrierCode();
    if (!carrier.isEmpty())
        extra.insert(QStringLiteral("carrier"), carrier);
    return extra;
}

// AVPN (панель администратора): in-app бенч. Валиден в ЛЮБОМ состоянии туннеля (baseline = VPN off;
// замер ванильной Amnezia = её NE-туннель системный). extra фиксирует контекст запуска в результат.
// Гард методики: baseline/amnezia — замеры ЧУЖОГО пути, при поднятом Tribe-туннеле они бессмысленны
// (реальный случай: «baseline» с tunnel_state=connected обесценил всю серию). Пустая метка →
// авто-метка по факту: подключены — tribe-bypass-on/off из настроек, отключены — manual.
// v5.5: IP эндпоинта ТЕКУЩЕЙ ноды для ICMP-цели "node-endpoint" (host-route ⇒ off-tunnel);
// пусто, если не подключены — тогда цель не добавляется.
static QString currentNodeEndpointIp(const QVariantMap &node)
{
    return node.value(QStringLiteral("connected")).toBool()
        ? node.value(QStringLiteral("ip")).toString() : QString();
}

void AvpnEngineQml::startBench(const QString &label)
{
    if (m_benchRunning || sweepRunning() || abRunning() || doctorRunning() || !m_bench)
        return;
    const bool connected = (state() == QLatin1String("connected"));
    QString effLabel = label;
    if ((effLabel == QLatin1String("baseline") || effLabel == QLatin1String("amnezia")) && connected) {
        emit error(tr("Метка «%1» — замер БЕЗ нашего туннеля. Сначала отключи Tribe VPN.").arg(effLabel));
        return;
    }
    if (effLabel.isEmpty())
        effLabel = connected
            ? bypassLabel(QSettings().value(QStringLiteral("AvpnBypass/masterOn"), true).toBool())
            : QStringLiteral("manual");
    m_benchRunning = true;
    m_benchStage = QStringLiteral("start");
    emit benchChanged();
    m_bench->start(effLabel, benchExtra(), /*lite=*/false, currentNodeEndpointIp(currentNode()));
}

void AvpnEngineQml::cancelBench()
{
    if (!m_bench)
        return;
    m_bench->cancel();
    m_benchRunning = false;
    m_benchStage.clear();
    emit benchChanged();
}

// ── AVPN (панель администратора): авто-свип нод ────────────────────────────────────────────────
// Фазовая машина поверх ПУБЛИЧНЫХ переходов движка: switchToNode() (pin + guardedStop) → start() →
// wait connected → lite-бенч → следующая нода → восстановление исходного pin/подключения.
// Продвижение — из sweepAdvance() (по сигналу changed, queued) и sweepGuardFired() (сторож фазы).
// Инварианты коннекта не трогаем: НИКАКИХ прямых up()/down(), только те же вызовы, что жмёт юзер.

static const int kSweepGuardDownMs = 25000;  // стоп туннеля обязан завершиться быстро
static const int kSweepGuardUpMs = 75000;    // connect: enroll+handshake на медленной сети
static const int kSweepGuardBenchMs = 120000;

// display-имя ноды для прогресса/строк отчёта (из пула снапшота)
QString AvpnEngineQml::sweepNodeLabel(const QString &nodeId) const
{
    const QVariantList pool = debugSnapshot().value(QStringLiteral("pool")).toList();
    for (const QVariant &v : pool) {
        const QVariantMap n = v.toMap();
        if (n.value(QStringLiteral("nodeId")).toString() == nodeId) {
            const QString name = n.value(QStringLiteral("name")).toString();
            return name.isEmpty() ? n.value(QStringLiteral("region")).toString() : name;
        }
    }
    return nodeId;
}

void AvpnEngineQml::startNodeSweep()
{
    if (sweepRunning() || m_benchRunning || abRunning() || doctorRunning() || !m_bench)
        return;
    // очередь: ВСЕ ноды пула (вкл. RU — это тест, не авто-выбор; §14.3 касается выбора, не замера).
    // Task 10 финал: КРОМЕ неподдерживаемых протоколов (xray, ...) — switchToNode к ним невозможен,
    // каждая такая нода лишь выжигала бы сторожа фазы (до 25с) впустую.
    m_sweepQueue.clear();
    const QVariantList pool = debugSnapshot().value(QStringLiteral("pool")).toList();
    for (const QVariant &v : pool) {
        const QVariantMap n = v.toMap();
        if (!avpn::isSupportedProto(n.value(QStringLiteral("proto")).toString()))
            continue;
        m_sweepQueue << n.value(QStringLiteral("nodeId")).toString();
    }
    m_sweepQueue.removeAll(QString());
    if (m_sweepQueue.isEmpty()) {
        emit error(tr("Свип: пул нод пуст — обнови подписку"));
        return;
    }
    ++m_sweepEpoch;
    m_sweepIdx = -1;
    m_sweepResults = QJsonArray();
    m_sweepOrigPin = m_engine.pinnedNodeId();
    m_sweepOrigConnected = (state() == QLatin1String("connected"));
    sweepNextNode();
}

void AvpnEngineQml::cancelNodeSweep()
{
    if (!sweepRunning())
        return;
    ++m_sweepEpoch;
    m_sweepGuard.stop();
    if (m_benchRunning)
        cancelBench();
    m_sweepPhase = SweepPhase::Idle;
    m_sweepProgress.clear();
    emit sweepChanged();
    // вернуть исходное состояние (без ожиданий — юзер прервал; восстановление цели достаточно)
    if (m_sweepOrigPin.isEmpty()) selectAuto(); else switchToNode(m_sweepOrigPin);
    if (m_sweepOrigConnected)
        start();
}

void AvpnEngineQml::sweepEnterPhase(SweepPhase ph, int guardMs)
{
    m_sweepPhase = ph;
    m_sweepGuard.start(guardMs);
    emit sweepChanged();
}

void AvpnEngineQml::sweepNextNode()
{
    ++m_sweepIdx;
    if (m_sweepIdx >= m_sweepQueue.size()) {
        sweepBeginRestore();
        return;
    }
    const QString id = m_sweepQueue.at(m_sweepIdx);
    m_sweepProgress = QStringLiteral("%1/%2 · %3").arg(m_sweepIdx + 1).arg(m_sweepQueue.size())
                          .arg(sweepNodeLabel(id));
    switchToNode(id);                        // pin + намерение OFF (guardedStop, если были online)
    sweepEnterPhase(SweepPhase::WaitDown, kSweepGuardDownMs);
    // возможно, уже disconnected (no-op reconcile) — проверим отложенно, не дожидаясь changed
    QTimer::singleShot(0, this, [this, e = m_sweepEpoch] { if (e == m_sweepEpoch) sweepAdvance(); });
}

void AvpnEngineQml::sweepAdvance()
{
    const QString st = state();
    switch (m_sweepPhase) {
    case SweepPhase::Idle:
        return;
    case SweepPhase::WaitDown:
        if (st == QLatin1String("disconnected") || st == QLatin1String("error")) {
            m_sweepConnT.start();
            start();                          // коннект к запиненной ноде
            sweepEnterPhase(SweepPhase::WaitUp, kSweepGuardUpMs);
        }
        return;
    case SweepPhase::WaitUp:
        if (st == QLatin1String("connected")) {
            m_sweepGuard.stop();
            sweepStartBench();
        } else if (st == QLatin1String("error")) {
            sweepNodeFailed(QStringLiteral("connect-error"));
        }
        return;
    case SweepPhase::Bench:
        return; // продвижение придёт из benchFinished-лямбды
    case SweepPhase::RestoreWaitDown:
        if (st == QLatin1String("disconnected") || st == QLatin1String("error")) {
            if (m_sweepOrigConnected) {
                start();
                sweepEnterPhase(SweepPhase::RestoreWaitUp, kSweepGuardUpMs);
            } else {
                sweepFinish();
            }
        }
        return;
    case SweepPhase::RestoreWaitUp:
        if (st == QLatin1String("connected") || st == QLatin1String("error"))
            sweepFinish();
        return;
    }
}

void AvpnEngineQml::sweepStartBench()
{
    const QString id = m_sweepQueue.at(m_sweepIdx);
    const QString actual = debugSnapshot().value(QStringLiteral("currentNodeId")).toString();
    QJsonObject extra = benchExtra(); // общий контекст (факты конфигурации, сеть) + пер-нодные поля
    extra.insert(QStringLiteral("node_label"), sweepNodeLabel(id));
    extra.insert(QStringLiteral("connect_ms"), double(m_sweepConnT.elapsed()));
    if (actual != id) // движок мог failover'нуться — честно фиксируем (замер не той ноды)
        extra.insert(QStringLiteral("failover_from"), id);
    m_benchRunning = true;
    m_benchStage = QStringLiteral("start");
    emit benchChanged();
    sweepEnterPhase(SweepPhase::Bench, kSweepGuardBenchMs);
    m_bench->start(QStringLiteral("node-%1").arg(id), extra, /*lite=*/true,
                   currentNodeEndpointIp(currentNode()));
}

void AvpnEngineQml::sweepNodeFailed(const QString &reason)
{
    m_sweepGuard.stop();
    QJsonObject r;
    r.insert(QStringLiteral("label"), QStringLiteral("node-%1").arg(m_sweepQueue.value(m_sweepIdx)));
    r.insert(QStringLiteral("extra"), QJsonObject{
        { QStringLiteral("node_id"), m_sweepQueue.value(m_sweepIdx) },
        { QStringLiteral("node_label"), sweepNodeLabel(m_sweepQueue.value(m_sweepIdx)) },
    });
    r.insert(QStringLiteral("error"), reason);
    m_sweepResults.append(r);
    if (m_benchRunning)
        cancelBench();
    stop(); // не оставляем полуподнятый туннель перед следующей нодой
    QTimer::singleShot(0, this, [this, e = m_sweepEpoch] { if (e == m_sweepEpoch) sweepNextNode(); });
}

void AvpnEngineQml::sweepGuardFired()
{
    switch (m_sweepPhase) {
    case SweepPhase::Idle: return;
    case SweepPhase::WaitDown:  sweepNodeFailed(QStringLiteral("stop-timeout")); return;
    case SweepPhase::WaitUp:    sweepNodeFailed(QStringLiteral("connect-timeout")); return;
    case SweepPhase::Bench:     sweepNodeFailed(QStringLiteral("bench-timeout")); return;
    case SweepPhase::RestoreWaitDown:
    case SweepPhase::RestoreWaitUp:
        sweepFinish(); // восстановление зависло — отдаём отчёт, юзер увидит состояние на орбе
        return;
    }
}

void AvpnEngineQml::sweepBeginRestore()
{
    m_sweepProgress = tr("восстановление…");
    if (m_sweepOrigPin.isEmpty()) selectAuto(); else switchToNode(m_sweepOrigPin);
    sweepEnterPhase(SweepPhase::RestoreWaitDown, kSweepGuardDownMs);
    QTimer::singleShot(0, this, [this, e = m_sweepEpoch] { if (e == m_sweepEpoch) sweepAdvance(); });
}

void AvpnEngineQml::sweepFinish()
{
    m_sweepGuard.stop();
    m_sweepPhase = SweepPhase::Idle;
    m_sweepProgress.clear();

    // строки отчёта: выжимка per node, лучшие сверху (по скорости, ошибки — вниз)
    struct Row { QVariantMap m; double down; bool ok; };
    QList<Row> rows;
    for (const QJsonValue &v : m_sweepResults) {
        const QJsonObject r = v.toObject();
        const QJsonObject extra = r.value(QStringLiteral("extra")).toObject();
        QVariantMap m;
        m.insert(QStringLiteral("node_id"), extra.value(QStringLiteral("node_id")).toString());
        m.insert(QStringLiteral("label"), extra.value(QStringLiteral("node_label")).toString());
        const bool ok = !r.contains(QStringLiteral("error"));
        m.insert(QStringLiteral("ok"), ok);
        if (!ok) {
            m.insert(QStringLiteral("verdict"), r.value(QStringLiteral("error")).toString());
            rows.append({ m, -1, false });
            continue;
        }
        m.insert(QStringLiteral("connect_ms"), extra.value(QStringLiteral("connect_ms")).toDouble());
        m.insert(QStringLiteral("ttfb_ms"), r.value(QStringLiteral("http")).toObject().value(QStringLiteral("median_ttfb_ms")).toDouble(-1));
        const double down = r.value(QStringLiteral("throughput")).toObject().value(QStringLiteral("down_mbit")).toDouble();
        m.insert(QStringLiteral("down_mbit"), down);
        m.insert(QStringLiteral("base_rtt_ms"), r.value(QStringLiteral("network_quality")).toObject().value(QStringLiteral("base_rtt_ms")).toDouble(-1));
        m.insert(QStringLiteral("loaded_rtt_ms"), r.value(QStringLiteral("network_quality")).toObject().value(QStringLiteral("loaded_rtt_ms")).toDouble(-1));
        QString verdict = extra.contains(QStringLiteral("failover_from")) ? QStringLiteral("failover! ") : QString();
        const QJsonArray vs = r.value(QStringLiteral("verdicts")).toArray();
        verdict += vs.isEmpty() ? QStringLiteral("ok")
                                : vs.first().toObject().value(QStringLiteral("code")).toString()
                                      + (vs.size() > 1 ? QStringLiteral(" +%1").arg(vs.size() - 1) : QString());
        m.insert(QStringLiteral("verdict"), verdict);
        rows.append({ m, down, true });
    }
    std::sort(rows.begin(), rows.end(), [](const Row &a, const Row &b) {
        if (a.ok != b.ok) return a.ok;
        return a.down > b.down;
    });
    QVariantList outRows;
    for (const Row &r : rows) outRows << r.m;

    QJsonObject report;
    report.insert(QStringLiteral("schema"), 1);
    report.insert(QStringLiteral("type"), QStringLiteral("node-sweep"));
    report.insert(QStringLiteral("ts"), QDateTime::currentDateTime().toString(QStringLiteral("yyyyMMdd-HHmmss")));
    report.insert(QStringLiteral("nodes"), m_sweepResults);
    const QString json = QString::fromUtf8(QJsonDocument(report).toJson(QJsonDocument::Compact));
    QSettings().setValue(QStringLiteral("AvpnBench/last_node-sweep"), json);

    emit sweepChanged();
    emit sweepFinished(outRows, json);
}

// ── AVPN (панель администратора): авто-A/B байпаса ─────────────────────────────────────────────
// Одна кнопка при подключённом Tribe: full-бенч на ТЕКУЩЕМ тумблере → setBypassMasterOn(!x)
// (reconcile штатно передёргивает туннель — БЕЗ прямых up/down, CONNECT-INVARIANTS не трогаем) →
// второй full-бенч → возврат тумблера + реконнект → отчёт type:"ab-bypass" (пара + compare +
// длительности реконнектов). Метки выводятся из фактического состояния настроек.

static const int kAbGuardBenchMs = 240000; // full-бенч ~2 мин + запас на медленной сети

void AvpnEngineQml::startBypassAb()
{
    if (abRunning() || m_benchRunning || sweepRunning() || doctorRunning() || !m_bench)
        return;
    if (state() != QLatin1String("connected")) {
        emit error(tr("Авто-A/B байпаса: сначала подключи Tribe VPN"));
        return;
    }
    ++m_abEpoch;
    m_abOrigOn = QSettings().value(QStringLiteral("AvpnBypass/masterOn"), true).toBool();
    m_abOrigLiAuto = QSettings().value(QStringLiteral("AvpnBypass/liAutoOn"), true).toBool();
    m_abFirst = QJsonObject();
    m_abSecond = QJsonObject();
    m_abSwitchMs = m_abRestoreMs = -1;
    abStartBench(/*second=*/false);
}

void AvpnEngineQml::cancelBypassAb()
{
    if (!abRunning())
        return;
    ++m_abEpoch;
    m_abGuard.stop();
    if (m_benchRunning)
        cancelBench();
    // вернуть исходный тумблер, если успели переключить (реконнект доделает reconcile)
    {
        QSettings st; // v5.5: вернуть liAuto тихо ДО реконсиляции master
        if (st.value(QStringLiteral("AvpnBypass/liAutoOn"), true).toBool() != m_abOrigLiAuto) {
            st.setValue(QStringLiteral("AvpnBypass/liAutoOn"), m_abOrigLiAuto);
            st.sync();
        }
    }
    if (QSettings().value(QStringLiteral("AvpnBypass/masterOn"), true).toBool() != m_abOrigOn)
        setBypassMasterOn(m_abOrigOn);
    m_abPhase = AbPhase::Idle;
    m_abProgress.clear();
    emit abChanged();
}

void AvpnEngineQml::abEnterPhase(AbPhase ph, int guardMs)
{
    m_abPhase = ph;
    m_abGuard.start(guardMs);
    emit abChanged();
}

void AvpnEngineQml::abStartBench(bool second)
{
    const bool on = QSettings().value(QStringLiteral("AvpnBypass/masterOn"), true).toBool();
    m_abProgress = tr("замер %1/2 · байпас %2").arg(second ? 2 : 1).arg(on ? tr("ВКЛ") : tr("ВЫКЛ"));
    m_benchRunning = true;
    m_benchStage = QStringLiteral("start");
    emit benchChanged();
    abEnterPhase(second ? AbPhase::BenchB : AbPhase::BenchA, kAbGuardBenchMs);
    m_bench->start(bypassLabel(on), benchExtra(), /*lite=*/false, currentNodeEndpointIp(currentNode()));
}

// benchFinished при фазе BenchA/BenchB (история last_<label> уже записана вызывающей лямбдой)
void AvpnEngineQml::abOnBenchDone(const QJsonObject &result)
{
    m_abGuard.stop();
    const bool wasFirst = (m_abPhase == AbPhase::BenchA);
    (wasFirst ? m_abFirst : m_abSecond) = result;
    m_abProgress = wasFirst ? tr("переключение байпаса и реконнект…")
                            : tr("возврат настроек и реконнект…");
    m_abConnT.start();
    // синхронная запись тумблера + штатный передёрг туннеля (reapplyBypass → reconcile)
    // v5.5 (Li Auto гейт): off-фаза = ЧИСТЫЙ full-tunnel — гасим и liAutoOn, иначе split_on
    // остаётся из-за Li Auto default-ON и «bypass-off» несравним с ванилью (реальный отчёт).
    // Пишем тихо (setValue+sync): реконсиляцию/реконнект делает следующий setBypassMasterOn.
    {
        const bool targetMaster = wasFirst ? !m_abOrigOn : m_abOrigOn;
        QSettings st;
        st.setValue(QStringLiteral("AvpnBypass/liAutoOn"), targetMaster ? m_abOrigLiAuto : false);
        st.sync();
        setBypassMasterOn(targetMaster);
    }
    abEnterPhase(wasFirst ? AbPhase::WaitDown : AbPhase::RestoreDown, kSweepGuardDownMs);
    QTimer::singleShot(0, this, [this, e = m_abEpoch] { if (e == m_abEpoch) abAdvance(); });
}

void AvpnEngineQml::abAdvance()
{
    const QString st = state();
    switch (m_abPhase) {
    case AbPhase::Idle:
    case AbPhase::BenchA:
    case AbPhase::BenchB:
        return; // продвижение придёт из abOnBenchDone
    case AbPhase::WaitDown:
    case AbPhase::RestoreDown:
        // reconcile передёргивает сам; «вниз» мы можем не застать (queued-снапшоты) — фактом начала
        // передёрга считаем ЛЮБОЕ не-connected состояние. Залипший connected отловит сторож фазы.
        if (st == QLatin1String("error")) {
            abFail(QStringLiteral("reconnect-error"));
        } else if (st != QLatin1String("connected")) {
            abEnterPhase(m_abPhase == AbPhase::WaitDown ? AbPhase::WaitUp : AbPhase::RestoreUp,
                         kSweepGuardUpMs);
        }
        return;
    case AbPhase::WaitUp:
        if (st == QLatin1String("connected")) {
            m_abGuard.stop();
            m_abSwitchMs = double(m_abConnT.elapsed());
            abStartBench(/*second=*/true);
        } else if (st == QLatin1String("error")) {
            abFail(QStringLiteral("reconnect-error"));
        }
        return;
    case AbPhase::RestoreUp:
        if (st == QLatin1String("connected")) {
            m_abRestoreMs = double(m_abConnT.elapsed());
            abFinish();
        } else if (st == QLatin1String("error")) {
            abFinish(); // пара уже собрана — отчёт отдаём, состояние юзер увидит на орбе
        }
        return;
    }
}

void AvpnEngineQml::abGuardFired()
{
    switch (m_abPhase) {
    case AbPhase::Idle:
        return;
    case AbPhase::BenchA:
    case AbPhase::BenchB:
        abFail(QStringLiteral("bench-timeout"));
        return;
    case AbPhase::WaitDown:
    case AbPhase::WaitUp:
        abFail(QStringLiteral("reconnect-timeout"));
        return;
    case AbPhase::RestoreDown:
    case AbPhase::RestoreUp:
        abFinish(); // восстановление зависло — отчёт всё равно отдаём
        return;
    }
}

void AvpnEngineQml::abFail(const QString &reason)
{
    m_abGuard.stop();
    ++m_abEpoch;
    if (m_benchRunning)
        cancelBench();
    {
        QSettings st; // v5.5: вернуть liAuto тихо ДО реконсиляции master
        if (st.value(QStringLiteral("AvpnBypass/liAutoOn"), true).toBool() != m_abOrigLiAuto) {
            st.setValue(QStringLiteral("AvpnBypass/liAutoOn"), m_abOrigLiAuto);
            st.sync();
        }
    }
    if (QSettings().value(QStringLiteral("AvpnBypass/masterOn"), true).toBool() != m_abOrigOn)
        setBypassMasterOn(m_abOrigOn);
    m_abPhase = AbPhase::Idle;
    m_abProgress.clear();
    emit abChanged();
    emit error(tr("Авто-A/B прерван: %1. Тумблер байпаса возвращён.").arg(reason));
}

void AvpnEngineQml::abFinish()
{
    m_abGuard.stop();
    m_abPhase = AbPhase::Idle;
    m_abProgress.clear();

    // раскладываем пару по фактическим меткам (первый замер шёл на исходном тумблере)
    const QJsonObject &onRun = m_abOrigOn ? m_abFirst : m_abSecond;
    const QJsonObject &offRun = m_abOrigOn ? m_abSecond : m_abFirst;

    QJsonObject report;
    report.insert(QStringLiteral("schema"), 1);
    report.insert(QStringLiteral("type"), QStringLiteral("ab-bypass"));
    report.insert(QStringLiteral("ts"), QDateTime::currentDateTime().toString(QStringLiteral("yyyyMMdd-HHmmss")));
    report.insert(QStringLiteral("orig_bypass_on"), m_abOrigOn);
    if (m_abSwitchMs >= 0) report.insert(QStringLiteral("reconnect_switch_ms"), m_abSwitchMs);
    if (m_abRestoreMs >= 0) report.insert(QStringLiteral("reconnect_restore_ms"), m_abRestoreMs);
    QJsonObject runs;
    runs.insert(QStringLiteral("tribe-bypass-on"), onRun);
    runs.insert(QStringLiteral("tribe-bypass-off"), offRun);
    report.insert(QStringLiteral("runs"), runs);
    // «цена байпаса»: on относительно off (b относительно a в bench::compare)
    const QJsonObject cost = bench::compare(offRun, onRun);
    report.insert(QStringLiteral("bypass_cost"), cost);

    const QString json = QString::fromUtf8(QJsonDocument(report).toJson(QJsonDocument::Compact));
    QSettings().setValue(QStringLiteral("AvpnBench/last_ab-bypass"), json);

    // плоская сводка для UI: пара ключевых метрик + существенные ухудшения
    auto flat = [](const QJsonObject &r) {
        QVariantMap m;
        const QJsonObject http = r.value(QStringLiteral("http")).toObject();
        m.insert(QStringLiteral("ttfb_ms"), http.value(QStringLiteral("median_ttfb_ms")).toVariant());
        m.insert(QStringLiteral("failures"), http.value(QStringLiteral("failures")).toInt());
        const QJsonObject thr = r.value(QStringLiteral("throughput")).toObject();
        m.insert(QStringLiteral("down_mbit"), thr.value(QStringLiteral("down_mbit")).toVariant());
        m.insert(QStringLiteral("up_mbit"), thr.value(QStringLiteral("up_mbit")).toVariant());
        const QJsonObject nq = r.value(QStringLiteral("network_quality")).toObject();
        m.insert(QStringLiteral("base_rtt_ms"), nq.value(QStringLiteral("base_rtt_ms")).toVariant());
        return m;
    };
    QStringList costTexts;
    for (const QJsonValue &v : cost.value(QStringLiteral("significant")).toArray())
        costTexts << v.toString();
    QVariantMap summary;
    summary.insert(QStringLiteral("on"), flat(onRun));
    summary.insert(QStringLiteral("off"), flat(offRun));
    summary.insert(QStringLiteral("cost"), costTexts);
    if (m_abSwitchMs >= 0) summary.insert(QStringLiteral("reconnect_ms"), m_abSwitchMs);

    emit abChanged();
    emit abFinished(summary, json);
}

// ── AVPN bench v5 (connect{}): «Тест коннекта» ────────────────────────────────────────────────
// Меряет САМ коннект (v1–v4 мерили путь после): kCcCycles циклов stop→wait down→start→wait
// connected→handshake→first byte. Только публичные переходы (CONNECT-INVARIANTS не трогаем);
// исторические баги этого класса: «2-й коннект = Network Error» (ios reconnect), залипание
// Connect, медленные сторожа — здесь видны как фейл/тайминг конкретной фазы конкретного цикла.
static const int kCcGuardVerifyMs = 15000;  // HEAD 204 через свежеподнятый туннель
static const int kCcHsPollMs = 500;         // шаг полла handshake
static const int kCcHsPollMax = 20;         // 10с: handshake не свежий → пишем null (desktop не отдаёт)

void AvpnEngineQml::startConnectCycle()
{
    if (ccRunning() || m_benchRunning || sweepRunning() || abRunning() || doctorRunning())
        return;
    if (state() != QLatin1String("connected")) {
        emit error(tr("Тест коннекта: сначала подключи Tribe VPN"));
        return;
    }
    ++m_ccEpoch;
    m_ccCycle = 0;
    m_ccCycles = QJsonArray();
    m_ccCur = QJsonObject();
    m_ccProgress = tr("цикл 1/%1 · отключение…").arg(kCcCycles);
    m_ccT.start();
    stop(); // публичный переход; факт «вниз» ждём по changed()
    ccEnterPhase(CcPhase::Down, 25000);
}

void AvpnEngineQml::cancelConnectCycle()
{
    if (!ccRunning())
        return;
    ++m_ccEpoch;
    m_ccGuard.stop();
    const bool wasDown = (m_ccPhase == CcPhase::Down);
    m_ccPhase = CcPhase::Idle;
    m_ccProgress.clear();
    emit ccChanged();
    if (wasDown || state() != QLatin1String("connected"))
        start(); // не бросаем юзера отключённым посреди цикла
}

void AvpnEngineQml::ccEnterPhase(CcPhase ph, int guardMs)
{
    m_ccPhase = ph;
    m_ccGuard.start(guardMs);
    emit ccChanged();
}

void AvpnEngineQml::ccAdvance()
{
    const QString st = state();
    switch (m_ccPhase) {
    case CcPhase::Idle:
    case CcPhase::Handshake: // продвигается поллом ccPollHandshake
    case CcPhase::Verify:    // продвигается колбэком HEAD в ccVerify
        return;
    case CcPhase::Down:
        if (st == QLatin1String("error")) {
            m_ccCur.insert(QStringLiteral("error"), QStringLiteral("teardown-error"));
            ccNextCycle();
        } else if (st == QLatin1String("disconnected")) {
            // ждём именно disconnected (не «любой не-connected»): реальные данные iOS — «любой»
            // давал teardown_ms=2 (первый же changed), метрика врала. Плюс 1с успокоения NE перед
            // start — не гоним новый up() поверх недоехавшего teardown (класс m_pendingStart).
            m_ccCur.insert(QStringLiteral("teardown_ms"), double(m_ccT.elapsed()));
            m_ccGuard.stop();
            m_ccProgress = tr("цикл %1/%2 · подключение…").arg(m_ccCycle + 1).arg(kCcCycles);
            const int epoch = m_ccEpoch;
            QTimer::singleShot(1000, this, [this, epoch] {
                if (epoch != m_ccEpoch || m_ccPhase != CcPhase::Down)
                    return;
                m_ccT.start();
                start();
                ccEnterPhase(CcPhase::Up, kSweepGuardUpMs);
            });
        }
        return;
    case CcPhase::Up:
        if (st == QLatin1String("connected")) {
            m_ccGuard.stop();
            m_ccCur.insert(QStringLiteral("connect_ms"), double(m_ccT.elapsed()));
            m_ccConnEpochSec = QDateTime::currentSecsSinceEpoch();
            m_ccHsPolls = 0;
            m_ccProgress = tr("цикл %1/%2 · рукопожатие…").arg(m_ccCycle + 1).arg(kCcCycles);
            m_ccT.start();
            ccEnterPhase(CcPhase::Handshake, (kCcHsPollMax + 4) * kCcHsPollMs);
            ccPollHandshake();
        } else if (st == QLatin1String("error")) {
            m_ccCur.insert(QStringLiteral("error"), QStringLiteral("connect-error"));
            ccNextCycle();
        }
        return;
    }
}

// handshake: iOS/Android отдают latestHandshakeEpoch (UAPI/GoBackend), desktop-демон — нет (см.
// VpnConnectionTunnelControl::readStats). Свежий (после момента коннекта) эпох → handshake_ms;
// за kCcHsPollMax поллов не дождались → null (не факт проблемы: desktop просто не отдаёт).
void AvpnEngineQml::ccPollHandshake()
{
    if (m_ccPhase != CcPhase::Handshake)
        return;
    const int epoch = m_ccEpoch;
    const TunnelStats s = m_tunnel.readStats();
    if (s.valid && s.latestHandshakeEpoch >= m_ccConnEpochSec - 3) {
        m_ccCur.insert(QStringLiteral("handshake_ms"), double(m_ccT.elapsed()));
        ccVerify();
        return;
    }
    if (++m_ccHsPolls >= kCcHsPollMax) {
        ccVerify(); // handshake_ms не пишем (null в анализе) — идём проверять данные напрямую
        return;
    }
    QTimer::singleShot(kCcHsPollMs, this, [this, epoch] {
        if (epoch == m_ccEpoch)
            ccPollHandshake();
    });
}

// Правда data-plane: HEAD generate_204 через свежий туннель (first_byte_ms) + вырос ли rx.
// «connected + first byte не прошёл» = класс S4-blackhole («подключено, данных нет»).
void AvpnEngineQml::ccVerify()
{
    m_ccProgress = tr("цикл %1/%2 · проверка данных…").arg(m_ccCycle + 1).arg(kCcCycles);
    ccEnterPhase(CcPhase::Verify, kCcGuardVerifyMs);
    const int epoch = m_ccEpoch;
    const qint64 rxBefore = m_tunnel.readStats().rxBytes;
    QNetworkRequest req{QUrl(QStringLiteral("https://connectivitycheck.gstatic.com/generate_204"))};
    req.setTransferTimeout(kCcGuardVerifyMs - 2000);
    m_ccT.start();
    QNetworkReply *r = m_nam->head(req);
    connect(r, &QNetworkReply::finished, this, [this, r, epoch, rxBefore] {
        r->deleteLater();
        if (epoch != m_ccEpoch)
            return;
        m_ccGuard.stop();
        const int code = r->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        const bool ok = (r->error() == QNetworkReply::NoError && (code == 204 || code == 200));
        if (ok)
            m_ccCur.insert(QStringLiteral("first_byte_ms"), double(m_ccT.elapsed()));
        m_ccCur.insert(QStringLiteral("verify_ok"), ok);
        // rx-счётчики обновляются платформой с лагом (реальные данные iOS: чтение сразу после
        // ответа = rx_grew:false при живом трафике) — читаем отложенно
        QTimer::singleShot(1200, this, [this, epoch, rxBefore] {
            if (epoch != m_ccEpoch)
                return;
            const qint64 rxAfter = m_tunnel.readStats().rxBytes;
            if (rxAfter > 0 || rxBefore > 0) // счётчики живы только там, где платформа их отдаёт
                m_ccCur.insert(QStringLiteral("rx_grew"), rxAfter > rxBefore);
            ccNextCycle();
        });
    });
}

void AvpnEngineQml::ccNextCycle()
{
    m_ccGuard.stop();
    m_ccCycles.append(m_ccCur);
    m_ccCur = QJsonObject();
    ++m_ccCycle;
    if (m_ccCycle >= kCcCycles || state() == QLatin1String("error")) {
        ccFinish();
        return;
    }
    m_ccProgress = tr("цикл %1/%2 · отключение…").arg(m_ccCycle + 1).arg(kCcCycles);
    m_ccT.start();
    stop();
    ccEnterPhase(CcPhase::Down, 25000);
}

void AvpnEngineQml::ccGuardFired()
{
    switch (m_ccPhase) {
    case CcPhase::Idle:
        return;
    case CcPhase::Down:
        m_ccCur.insert(QStringLiteral("error"), QStringLiteral("teardown-timeout"));
        break;
    case CcPhase::Up:
        m_ccCur.insert(QStringLiteral("error"), QStringLiteral("connect-timeout"));
        break;
    case CcPhase::Handshake:
        break; // поллы сами уходят в verify; сторож здесь — чистая подстраховка
    case CcPhase::Verify:
        m_ccCur.insert(QStringLiteral("verify_ok"), false);
        m_ccCur.insert(QStringLiteral("error"), QStringLiteral("verify-timeout"));
        break;
    }
    ccNextCycle(); // тайм-аут фазы = данные цикла (это и есть находка), НЕ смерть теста
}

void AvpnEngineQml::ccFail(const QString &reason)
{
    ++m_ccEpoch;
    m_ccGuard.stop();
    m_ccPhase = CcPhase::Idle;
    m_ccProgress.clear();
    emit ccChanged();
    emit error(tr("Тест коннекта прерван: %1").arg(reason));
}

void AvpnEngineQml::ccFinish()
{
    m_ccGuard.stop();
    m_ccPhase = CcPhase::Idle;
    m_ccProgress.clear();

    QVector<double> conn, teardown, firstByte;
    int okCycles = 0;
    for (const QJsonValue &v : m_ccCycles) {
        const QJsonObject c = v.toObject();
        if (c.value(QStringLiteral("connect_ms")).isDouble())
            conn.append(c.value(QStringLiteral("connect_ms")).toDouble());
        if (c.value(QStringLiteral("teardown_ms")).isDouble())
            teardown.append(c.value(QStringLiteral("teardown_ms")).toDouble());
        if (c.value(QStringLiteral("first_byte_ms")).isDouble())
            firstByte.append(c.value(QStringLiteral("first_byte_ms")).toDouble());
        if (c.value(QStringLiteral("verify_ok")).toBool())
            ++okCycles;
    }
    auto num = [](double v) { return v < 0 ? QJsonValue(QJsonValue::Null) : QJsonValue(v); };
    QJsonObject report;
    report.insert(QStringLiteral("schema"), 2);
    report.insert(QStringLiteral("type"), QStringLiteral("connect-cycle"));
    report.insert(QStringLiteral("ts"), QDateTime::currentDateTime().toString(QStringLiteral("yyyyMMdd-HHmmss")));
    report.insert(QStringLiteral("cycles"), m_ccCycles);
    report.insert(QStringLiteral("ok_cycles"), okCycles);
    report.insert(QStringLiteral("median_connect_ms"), num(avpn::BenchRunner::median(conn)));
    report.insert(QStringLiteral("median_teardown_ms"), num(avpn::BenchRunner::median(teardown)));
    report.insert(QStringLiteral("median_first_byte_ms"), num(avpn::BenchRunner::median(firstByte)));
    report.insert(QStringLiteral("extra"), benchExtra());

    QVariantMap summary;
    summary.insert(QStringLiteral("cycles"), int(m_ccCycles.size()));
    summary.insert(QStringLiteral("ok_cycles"), okCycles);
    summary.insert(QStringLiteral("median_connect_ms"), report.value(QStringLiteral("median_connect_ms")).toVariant());
    summary.insert(QStringLiteral("median_teardown_ms"), report.value(QStringLiteral("median_teardown_ms")).toVariant());
    summary.insert(QStringLiteral("median_first_byte_ms"), report.value(QStringLiteral("median_first_byte_ms")).toVariant());

    const QString json = QString::fromUtf8(QJsonDocument(report).toJson(QJsonDocument::Compact));
    // история — попадает в единый полный отчёт (buildFullReport), как свип и A/B
    QSettings().setValue(QStringLiteral("AvpnBench/last_connect-cycle"), json);
    emit ccChanged();
    emit ccFinished(summary, json);
}

// ── AVPN bench v5.3: отправка отчёта на control plane ─────────────────────────────────────────
// POST /v1/bench/report (Bearer-токен устройства, тело = отчёт как есть; PII в отчётах нет by
// construction — IP не пишутся ещё на сборке). Сервер копит по device_id — анализ с прода без
// пересылки файлов руками. Бэк-эндпоинт — greenfield (handoff BENCH-REPORT-BACKEND-HANDOFF.md):
// до его выката честно говорим «сервер ещё не принимает отчёты».
void AvpnEngineQml::uploadReport(const QString &json, bool quiet, const QString &outboxFile)
{
    if (json.isEmpty())
        return;
    // AVPN backend-first (T11): kill-switch глушит ТОЛЬКО авто-отправку (quiet); ручную кнопку не
    // трогаем — юзер сам увидит честный отказ бэка, если тот не готов принимать отчёты.
    if (quiet && !avpn::TuningStore::flag(QStringLiteral("bench_report_upload")))
        return;
    if (json.size() > 3 * 1024 * 1024) { // защита от абсурда; реальный мега-отчёт ~200–600 КБ
        emit reportUploadDone(false, tr("Отчёт слишком большой для отправки"));
        return;
    }
    const QString token = authToken();
    if (!m_nam || token.isEmpty()) {
        // BUG-7: до enroll'а токена нет (холодный старт без сети) — отчёт в outbox, не в мусор.
        if (outboxFile.isEmpty())
            outboxEnqueue(json);
        if (!quiet)
            emit reportUploadDone(false, tr("Нет токена устройства — отправка недоступна"));
        return;
    }
    QNetworkRequest req{QUrl(m_baseUrl + QStringLiteral("/v1/bench/report"))};
    req.setHeader(QNetworkRequest::ContentTypeHeader, QStringLiteral("application/json"));
    req.setRawHeader(QByteArrayLiteral("Authorization"), QByteArrayLiteral("Bearer ") + token.toUtf8());
    QNetworkReply *reply = m_nam->post(req, json.toUtf8());
    armTimeout(reply);
    connect(reply, &QNetworkReply::finished, this, [this, reply, quiet, json, outboxFile]() {
        reply->deleteLater();
        const int code = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        if (code >= 200 && code < 300) {
            if (!outboxFile.isEmpty())
                QFile::remove(outboxFile); // отложенный отчёт доехал
            m_lastUploadStatus = tr("Отправлен на сервер ✓ (%1)")
                                     .arg(QDateTime::currentDateTime().toString(QStringLiteral("HH:mm")));
            emit ftChanged();
            emit reportUploadDone(true, tr("Отчёт отправлен разработчику ✓"));
        }
        else if (code == 404 || code == 405) {
            // бэк ещё без эндпоинта: авто-отправка молчит (иначе ныла бы каждый прогон);
            // терминально — из outbox тоже убираем (ретрай бессмыслен до обновления бэка)
            if (!outboxFile.isEmpty())
                QFile::remove(outboxFile);
            m_lastUploadStatus = tr("Не отправлен: сервер не принимает — сохрани файлом");
            emit ftChanged();
            if (!quiet)
                emit reportUploadDone(false, tr("Сервер ещё не принимает отчёты — сохрани файлом"));
        } else if (code == 401 || code == 403) {
            if (!outboxFile.isEmpty())
                QFile::remove(outboxFile); // авторизация не появится сама — не копим
            emit reportUploadDone(false, tr("Нет авторизации для отправки (%1)").arg(code));
        } else {
            // BUG-7: сеть (code 0) или 5xx — ретраибельно. Свежий отчёт кладём в outbox
            // (доедет после восстановления/перезапуска); отложенный остаётся лежать.
            if (outboxFile.isEmpty() && (code == 0 || code >= 500))
                outboxEnqueue(json);
            m_lastUploadStatus = tr("Не отправлен (%1) — сохрани файлом").arg(code > 0 ? QString::number(code) : tr("сеть"));
            emit ftChanged();
            emit reportUploadDone(false, code > 0 ? tr("Сервер отклонил отчёт (%1)").arg(code)
                                                  : tr("Сеть недоступна — отчёт будет дослан позже"));
        }
    });
}

// ── BUG-7 (2026-07-24): персистентный outbox отчётов ─────────────────────────────────────────
// Диагностику чаще всего шлют В МОМЕНТ сетевой беды (control plane за мёртвым туннелем) —
// fire-and-forget терял самые ценные отчёты. Файлы <AppData>/report-outbox/<msecs>.json;
// flush: старт (+25с), фронт connected (+10с). Кап 20 файлов (старые вытесняются).
// Kill-switch features.report_outbox (default ON).
static QString reportOutboxDir()
{
    const QString dir = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation)
                        + QStringLiteral("/report-outbox");
    QDir().mkpath(dir);
    return dir;
}

void AvpnEngineQml::outboxEnqueue(const QString &json)
{
    if (!featureEnabled(QStringLiteral("report_outbox"), true))
        return;
    QDir d(reportOutboxDir());
    QStringList old = d.entryList({QStringLiteral("*.json")}, QDir::Files, QDir::Name);
    while (old.size() >= 20) // кап: свежее ценнее давнего
        QFile::remove(d.filePath(old.takeFirst()));
    QFile f(d.filePath(QStringLiteral("%1.json")
                           .arg(QDateTime::currentMSecsSinceEpoch(), 15, 10, QLatin1Char('0'))));
    if (f.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        f.write(json.toUtf8());
        f.close();
    }
}

void AvpnEngineQml::outboxFlush()
{
    if (!featureEnabled(QStringLiteral("report_outbox"), true))
        return;
    QDir d(reportOutboxDir());
    const QStringList files = d.entryList({QStringLiteral("*.json")}, QDir::Files, QDir::Name);
    for (const QString &name : files) {
        const QString path = d.filePath(name);
        QFile f(path);
        if (!f.open(QIODevice::ReadOnly)) {
            QFile::remove(path);
            continue;
        }
        const QString json = QString::fromUtf8(f.readAll());
        f.close();
        if (json.isEmpty()) {
            QFile::remove(path);
            continue;
        }
        uploadReport(json, /*quiet=*/true, /*outboxFile=*/path);
    }
}

// ── AVPN bench v5.2: мастер «Полный тест» ─────────────────────────────────────────────────────
// Дирижёр: этап 1 сам (connect0 → тест коннекта → авто-A/B → свип), два ручных гейта
// (Amnezia / baseline-скип), финал = мега-отчёт одним JSON. Измерительной логики НЕТ —
// только последовательность, ожидание *Finished и сторожа. Ошибка шага НЕ роняет мастер:
// шаг пишется error в methodology, идём дальше (частичный отчёт ценнее прерванного).
static const int kFtGuardConnectMs = 90000;   // connect0: enroll+подключение
static const int kFtGuardCcMs      = 5 * 60000;
static const int kFtGuardAbMs      = 12 * 60000;
static const int kFtGuardSweepMs   = 15 * 60000;
static const int kFtGuardBenchMs   = 5 * 60000;

QString AvpnEngineQml::lastFullTestJson() const
{
    return QSettings().value(QStringLiteral("AvpnBench/last_full_test")).toString();
}

// Доля прогресса текущего бенча по его стадии (порядок = конвейер BenchRunner; веса ~длительности:
// down/up — самые долгие). Грубая, но живая — юзеру важно видеть движение, не точность.
double AvpnEngineQml::benchStageFrac() const
{
    static const struct { const char *st; double frac; } kMap[] = {
        {"start", 0.02}, {"dns", 0.08}, {"tls", 0.16}, {"http", 0.30}, {"ping", 0.45},
        {"split", 0.55}, {"dns_duel", 0.58}, {"mtu", 0.60}, {"rtt", 0.68}, {"down", 0.80},
        {"up", 0.95}, {"done", 1.0},
    };
    for (const auto &m : kMap)
        if (m_benchStage == QLatin1String(m.st))
            return m.frac;
    return 0.0;
}

// Взвешенная шкала мастера: этап 1 (сам) ≈ 0–86, ручные шаги и финальные бенчи — хвост.
void AvpnEngineQml::ftUpdatePercent()
{
    double p = 0;
    switch (m_ftPhase) {
    case FtPhase::Idle:          p = m_ftPercent; break; // не дёргаем после финиша
    case FtPhase::Connect0:      p = 2; break;
    case FtPhase::Cc:            p = 4 + std::min(m_ccCycle, kCcCycles) * (12.0 / kCcCycles); break;
    case FtPhase::Ab:
        switch (m_abPhase) {
        case AbPhase::Idle:
        case AbPhase::BenchA:    p = 18 + benchStageFrac() * 20; break;
        case AbPhase::WaitDown:
        case AbPhase::WaitUp:    p = 40; break;
        case AbPhase::BenchB:    p = 43 + benchStageFrac() * 17; break;
        case AbPhase::RestoreDown:
        case AbPhase::RestoreUp: p = 61; break;
        }
        break;
    case FtPhase::Sweep:
        p = 62 + (m_sweepQueue.isEmpty() ? 0.0
                  : (std::max(m_sweepIdx, 0) + benchStageFrac()) * (24.0 / m_sweepQueue.size()));
        p = std::min(p, 86.0);
        break;
    case FtPhase::WaitAmnezia:   p = 86; break;
    case FtPhase::BenchAmnezia:  p = 87 + benchStageFrac() * 8; break;
    case FtPhase::WaitBaseline:  p = 95; break;
    case FtPhase::BenchBaseline: p = 95 + benchStageFrac() * 5; break;
    }
    const int np = std::clamp(int(p), 0, 100);
    if (np != m_ftPercent) {
        m_ftPercent = np;
        emit ftChanged();
    }
}

QString AvpnEngineQml::ftStage() const
{
    switch (m_ftPhase) {
    case FtPhase::Idle:          return QString();
    case FtPhase::Connect0:      return QStringLiteral("connect0");
    case FtPhase::Cc:            return QStringLiteral("cc");
    case FtPhase::Ab:            return QStringLiteral("ab");
    case FtPhase::Sweep:         return QStringLiteral("sweep");
    case FtPhase::WaitAmnezia:   return QStringLiteral("wait-amnezia");
    case FtPhase::BenchAmnezia:  return QStringLiteral("bench-amnezia");
    case FtPhase::WaitBaseline:  return QStringLiteral("wait-baseline");
    case FtPhase::BenchBaseline: return QStringLiteral("bench-baseline");
    }
    return QString();
}

void AvpnEngineQml::ftEnter(FtPhase ph, int guardMs)
{
    m_ftPhase = ph;
    m_ftGuard.stop();
    if (guardMs > 0)
        m_ftGuard.start(guardMs);
    ftUpdatePercent();
    emit ftChanged();
}

void AvpnEngineQml::ftRecord(const char *step, const char *status)
{
    QJsonObject s;
    s.insert(QStringLiteral("step"), QLatin1String(step));
    s.insert(QStringLiteral("status"), QLatin1String(status));
    s.insert(QStringLiteral("ts"), QDateTime::currentDateTime().toString(QStringLiteral("yyyyMMdd-HHmmss")));
    m_ftSteps.append(s);
}

void AvpnEngineQml::startFullTest()
{
    if (ftRunning() || m_benchRunning || sweepRunning() || abRunning() || ccRunning() || doctorRunning())
        return;
    ++m_ftEpoch;
    m_ftSteps = QJsonArray();
    m_ftPercent = 0;
    ftRecord("full-test", "started");
    if (state() == QLatin1String("connected")) {
        probeServices(); // v5.5: чипы (goodput/троттл) греются заранее — к A/B попадут в extra живыми
        m_ftProgress = tr("этап 1/3 · тест коннекта…");
        ftEnter(FtPhase::Cc, kFtGuardCcMs);
        startConnectCycle();
    } else {
        m_ftProgress = tr("этап 1/3 · подключаю Tribe…");
        ftEnter(FtPhase::Connect0, kFtGuardConnectMs);
        start();
    }
}

void AvpnEngineQml::cancelFullTest()
{
    if (!ftRunning())
        return;
    ++m_ftEpoch;
    m_ftGuard.stop();
    // отменить активную под-машину (каждая сама возвращает тумблеры/состояние)
    if (ccRunning()) cancelConnectCycle();
    if (abRunning()) cancelBypassAb();
    if (sweepRunning()) cancelNodeSweep();
    if (m_benchRunning) cancelBench();
    ftRecord("full-test", "cancelled");
    m_ftPhase = FtPhase::Idle;
    m_ftProgress.clear();
    m_ftPercent = 0;
    emit ftChanged();
}

// Продвижение: завершился шаг donePhase (ok/сторож). Ошибка шага не прерывает мастер.
void AvpnEngineQml::ftStepDone(FtPhase donePhase, bool ok)
{
    if (m_ftPhase != donePhase || m_ftPhase == FtPhase::Idle)
        return;
    m_ftGuard.stop();
    // Сторож добил шаг → ОТМЕНИТЬ зависшую под-машину, иначе она живёт параллельно со следующим
    // шагом (реальный прогон 2026-07-06: свип завис на мёртвой Польше, сторож увёл мастер на
    // ручной шаг Amnezia, а свип продолжал реконнектить наш туннель под ногами у юзера).
    if (!ok) {
        switch (donePhase) {
        case FtPhase::Cc:            if (ccRunning()) cancelConnectCycle(); break;
        case FtPhase::Ab:            if (abRunning()) cancelBypassAb(); break;
        case FtPhase::Sweep:         if (sweepRunning()) cancelNodeSweep(); break;
        case FtPhase::BenchAmnezia:
        case FtPhase::BenchBaseline: if (m_benchRunning) cancelBench(); break;
        default: break;
        }
    }
    const int epoch = m_ftEpoch;
    switch (donePhase) {
    case FtPhase::Idle:
        return;
    case FtPhase::Connect0:
        ftRecord("connect0", ok ? "ok" : "error");
        if (!ok) { // подключиться не смогли — этап 1 невозможен, уходим сразу на ручные шаги
            m_ftProgress = tr("этап 2/3 · включи Amnezia и нажми «Продолжить»");
            ftEnter(FtPhase::WaitAmnezia);
            return;
        }
        probeServices(); // v5.5: греем чипы сразу после подключения
        m_ftProgress = tr("этап 1/3 · тест коннекта…");
        ftEnter(FtPhase::Cc, kFtGuardCcMs);
        startConnectCycle();
        return;
    case FtPhase::Cc:
        ftRecord("connect-cycle", ok ? "ok" : "error");
        m_ftProgress = tr("этап 1/3 · авто-A/B байпаса…");
        ftEnter(FtPhase::Ab, kFtGuardAbMs);
        // A/B требует connected; после cc мы connected (последняя фаза — verify)
        QTimer::singleShot(500, this, [this, epoch] {
            if (epoch == m_ftEpoch && m_ftPhase == FtPhase::Ab)
                startBypassAb();
        });
        return;
    case FtPhase::Ab:
        ftRecord("ab-bypass", ok ? "ok" : "error");
        m_ftProgress = tr("этап 1/3 · свип всех нод…");
        ftEnter(FtPhase::Sweep, kFtGuardSweepMs);
        QTimer::singleShot(500, this, [this, epoch] {
            if (epoch == m_ftEpoch && m_ftPhase == FtPhase::Sweep)
                startNodeSweep();
        });
        return;
    case FtPhase::Sweep:
        ftRecord("node-sweep", ok ? "ok" : "error");
        // ручной шаг: сами опускаем наш туннель, юзеру остаётся включить Amnezia
        m_ftProgress = tr("этап 2/3 · включи Amnezia (наш ключ) и нажми «Продолжить»");
        stop();
        ftEnter(FtPhase::WaitAmnezia);
        return;
    case FtPhase::WaitAmnezia:
    case FtPhase::WaitBaseline:
        return; // продвигаются только fullTestContinue/fullTestSkip
    case FtPhase::BenchAmnezia:
        ftRecord("bench-amnezia", ok ? "ok" : "error");
        m_ftProgress = tr("этап 3/3 · выключи ВСЕ VPN и нажми «Продолжить» (или пропусти)");
        ftEnter(FtPhase::WaitBaseline);
        return;
    case FtPhase::BenchBaseline:
        ftRecord("bench-baseline", ok ? "ok" : "error");
        ftFinish();
        return;
    }
}

void AvpnEngineQml::fullTestContinue()
{
    if (m_ftPhase == FtPhase::WaitAmnezia) {
        if (state() == QLatin1String("connected")) // наш ещё поднят — гейт (QML тоже дизейблит)
            return;
        m_ftProgress = tr("этап 2/3 · замер через Amnezia…");
        ftEnter(FtPhase::BenchAmnezia, kFtGuardBenchMs);
        startBench(QStringLiteral("amnezia"));
    } else if (m_ftPhase == FtPhase::WaitBaseline) {
        if (state() == QLatin1String("connected"))
            return;
        m_ftProgress = tr("этап 3/3 · замер без VPN (baseline)…");
        ftEnter(FtPhase::BenchBaseline, kFtGuardBenchMs);
        startBench(QStringLiteral("baseline"));
    }
}

void AvpnEngineQml::fullTestSkip()
{
    if (m_ftPhase != FtPhase::WaitBaseline)
        return;
    ftRecord("bench-baseline", "skipped");
    ftFinish();
}

// Мега-отчёт мастера: buildFullReport (метки+сравнения+свип+cc+A/B) + methodology (шаги/время/
// пропуски — видно, что серия снята одной сессией) + summary (выжимка ВСЕХ вердиктов всех секций —
// анализ начинается с одного блока) + гард методики baseline-suspect (egress baseline == стране
// ноды amnezia-замера ⇒ «похоже, VPN не был выключен» — человеческая ошибка ручного шага).
QString AvpnEngineQml::assembleMegaReport() const
{
    QJsonObject rep = QJsonDocument::fromJson(buildFullReport().toUtf8()).object();
    if (rep.isEmpty()) {
        rep.insert(QStringLiteral("schema"), 2);
        rep.insert(QStringLiteral("type"), QStringLiteral("full-report"));
    }
    QJsonObject meth;
    meth.insert(QStringLiteral("wizard"), true);
    meth.insert(QStringLiteral("steps"), m_ftSteps);
    rep.insert(QStringLiteral("methodology"), meth);

    QJsonArray sum;
    auto addVerdicts = [&sum](const QString &section, const QJsonObject &run) {
        for (const QJsonValue &v : run.value(QStringLiteral("verdicts")).toArray()) {
            QJsonObject o = v.toObject();
            o.insert(QStringLiteral("section"), section);
            sum.append(o);
        }
    };
    const QJsonObject runs = rep.value(QStringLiteral("runs")).toObject();
    for (auto it = runs.constBegin(); it != runs.constEnd(); ++it)
        addVerdicts(it.key(), it.value().toObject());
    const QJsonArray sweepNodes = rep.value(QStringLiteral("node_sweep")).toObject()
                                     .value(QStringLiteral("nodes")).toArray();
    for (const QJsonValue &n : sweepNodes)
        addVerdicts(QStringLiteral("sweep:%1").arg(n.toObject().value(QStringLiteral("label")).toString()),
                    n.toObject());
    const QJsonObject cc = rep.value(QStringLiteral("connect_cycle")).toObject();
    if (!cc.isEmpty()) {
        const int okC = cc.value(QStringLiteral("ok_cycles")).toInt();
        const int allC = cc.value(QStringLiteral("cycles")).toArray().size();
        if (allC > 0 && okC < allC) {
            QJsonObject o = bench::mkVerdict("connect-cycle-failures", "bad",
                tr("Тест коннекта: успешно %1 из %2 циклов").arg(okC).arg(allC));
            o.insert(QStringLiteral("section"), QStringLiteral("connect_cycle"));
            sum.append(o);
        }
    }
    // baseline-suspect: страна egress baseline == стране egress amnezia-замера → VPN не выключали
    const QString baseLoc = runs.value(QStringLiteral("baseline")).toObject()
                                .value(QStringLiteral("network")).toObject()
                                .value(QStringLiteral("egress")).toObject()
                                .value(QStringLiteral("loc")).toString();
    const QString amnLoc = runs.value(QStringLiteral("amnezia")).toObject()
                               .value(QStringLiteral("network")).toObject()
                               .value(QStringLiteral("egress")).toObject()
                               .value(QStringLiteral("loc")).toString();
    const bool baselineSuspect = !baseLoc.isEmpty() && !amnLoc.isEmpty() && baseLoc == amnLoc;
    if (baselineSuspect) {
        QJsonObject o = bench::mkVerdict("baseline-suspect", "warn",
            tr("baseline и amnezia видят один egress (%1) — похоже, VPN не был выключен при baseline-замере").arg(baseLoc));
        o.insert(QStringLiteral("section"), QStringLiteral("methodology"));
        sum.append(o);
    }
    // build 62 (цензура-детект): хост молчит в baseline (без VPN) и открывается через туннель →
    // явный диагноз «оператор блокирует X». Нога «через VPN» = bypass-off (полный туннель);
    // фолбэк bypass-on — внутри bench::censorship() RU-корпус тогда пропускается (шёл мимо туннеля).
    // Гейт: baseline не под подозрением (иначе baseline врёт и сравнение бессмысленно).
    if (!baselineSuspect) {
        QJsonObject vpnRun = runs.value(QStringLiteral("tribe-bypass-off")).toObject();
        if (vpnRun.isEmpty())
            vpnRun = runs.value(QStringLiteral("tribe-bypass-on")).toObject();
        const QJsonArray cens = bench::censorship(runs.value(QStringLiteral("baseline")).toObject(), vpnRun);
        for (const QJsonValue &v : cens) {
            QJsonObject o = v.toObject();
            o.insert(QStringLiteral("section"), QStringLiteral("baseline"));
            sum.append(o);
        }
    }
    rep.insert(QStringLiteral("summary"), sum);
    return QString::fromUtf8(QJsonDocument(rep).toJson(QJsonDocument::Compact));
}

void AvpnEngineQml::ftFinish()
{
    m_ftGuard.stop();
    ftRecord("full-test", "finished");
    m_ftPhase = FtPhase::Idle;
    m_ftProgress.clear();
    m_ftPercent = 100;
    const QString json = assembleMegaReport();
    // v5.4: мега-отчёт живёт в QSettings — переживает навигацию/перезапуск («не сбрасывается»),
    // и уходит на сервер САМ (quiet: пока бэк не принимает — без нытья тостом, только успех/сеть)
    QSettings().setValue(QStringLiteral("AvpnBench/last_full_test"), json);
    emit ftChanged();
    emit ftFinished(json);
    uploadReport(json, /*quiet=*/true);
}

// история замеров (QSettings AvpnBench/last_<label>) — для A/B между запусками
QString AvpnEngineQml::benchLastJson(const QString &label) const
{
    return QSettings().value(QStringLiteral("AvpnBench/last_%1").arg(label)).toString();
}

// AVPN (авто-A/B): сводный отчёт всех собранных меток одним JSON — вместо пересылки 4 файлов.
// compares: baseline↔off (цена туннеля), off↔on (цена байпаса), amnezia↔off (Tribe vs ванилла).
QString AvpnEngineQml::buildFullReport() const
{
    static const char *const kLabels[] = { "baseline", "tribe-bypass-on", "tribe-bypass-off", "amnezia" };
    QJsonObject runs;
    for (const char *l : kLabels) {
        const QString j = benchLastJson(QLatin1String(l));
        if (!j.isEmpty())
            runs.insert(QLatin1String(l), QJsonDocument::fromJson(j.toUtf8()).object());
    }
    QJsonObject report;
    report.insert(QStringLiteral("schema"), 1);
    report.insert(QStringLiteral("type"), QStringLiteral("full-report"));
    report.insert(QStringLiteral("ts"), QDateTime::currentDateTime().toString(QStringLiteral("yyyyMMdd-HHmmss")));
    report.insert(QStringLiteral("runs"), runs);
    QJsonObject compares; // bench::compare(a,b) = «b относительно a», significant = ухудшения b
    auto add = [&](const char *name, const char *a, const char *b) {
        if (runs.contains(QLatin1String(a)) && runs.contains(QLatin1String(b)))
            compares.insert(QLatin1String(name),
                            bench::compare(runs.value(QLatin1String(a)).toObject(),
                                           runs.value(QLatin1String(b)).toObject()));
    };
    add("tunnel_cost_off_vs_baseline", "baseline", "tribe-bypass-off");
    add("bypass_cost_on_vs_off", "tribe-bypass-off", "tribe-bypass-on");
    add("tribe_off_vs_amnezia", "amnezia", "tribe-bypass-off");
    report.insert(QStringLiteral("compares"), compares);
    // v5.1 «всё-в-одном» (реальный фидбек: «неудобно каждый отчёт отдельным файлом»): вклеиваем
    // последние свип нод / тест коннекта / авто-A/B — один файл покрывает все шаги методики.
    auto attach = [&report](const char *section, const char *key) {
        const QString j = QSettings().value(QStringLiteral("AvpnBench/last_%1").arg(QLatin1String(key))).toString();
        if (!j.isEmpty())
            report.insert(QLatin1String(section), QJsonDocument::fromJson(j.toUtf8()).object());
    };
    attach("node_sweep", "node-sweep");
    attach("connect_cycle", "connect-cycle");
    attach("ab_bypass", "ab-bypass");
    // пусто только если совсем нечего отдавать (раньше требовали ≥2 метки — свип/коннект пропадали)
    if (runs.isEmpty() && !report.contains(QStringLiteral("node_sweep"))
        && !report.contains(QStringLiteral("connect_cycle"))
        && !report.contains(QStringLiteral("ab_bypass")))
        return {};
    return QString::fromUtf8(QJsonDocument(report).toJson(QJsonDocument::Compact));
}

// Сохранение отчёта файлом — весь платформенный веер уже в SystemController::saveFile (upstream:
// desktop = запись по пути, iOS = temp + share sheet файла, Android = SAF). Здесь только мост в QML.
bool AvpnEngineQml::saveReportFile(const QString &fileName, const QString &json) const
{
    if (fileName.isEmpty() || json.isEmpty())
        return false;
    return SystemController::saveFile(fileName, json);
}

// метка → ts последнего замера (для карточки «собрано N/4»; свежесть видна по датам)
QVariantMap AvpnEngineQml::benchHistoryInfo() const
{
    static const char *const kLabels[] = { "baseline", "tribe-bypass-on", "tribe-bypass-off", "amnezia" };
    QVariantMap out;
    for (const char *l : kLabels) {
        const QString j = benchLastJson(QLatin1String(l));
        if (j.isEmpty())
            continue;
        out.insert(QLatin1String(l),
                   QJsonDocument::fromJson(j.toUtf8()).object().value(QStringLiteral("ts")).toString());
    }
    return out;
}

void AvpnEngineQml::clearBenchHistory()
{
    QSettings s;
    s.beginGroup(QStringLiteral("AvpnBench"));
    s.remove(QString());
    s.endGroup();
}

void AvpnEngineQml::onConnectionStateChanged(Vpn::ConnectionState s) // AVPN
{
    m_lastTunnelState = s; // AVPN: кэш реального состояния туннеля (для отложенного start() при смене узла)
    // Правдивый статус: маппим РЕАЛЬНОЕ состояние VpnConnection в фазу движка. up() лишь ставит
    // туннель в очередь (async) и НЕ объявляет Connected — переход прилетает сюда.
    switch (s) {
    case Vpn::Connected:
        // AVPN (BUG-6, адопция живого туннеля): onTunnelConnected() поднимает Connected только из
        // фаз подъёма; false = факт «туннель жив» пришёл, когда движок в терминале и это НЕ наша
        // операция — туннель пережил перезапуск GUI (iOS: NE после смахивания, initialize() эмитит
        // Connected; desktop: демон держит туннель, факт приходит из стартовой пробы). Раньше факт
        // игнорировался (UI «выключен»), а ближайший reconcile ГАСИЛ живой туннель (wantConnected
        // false → guardedStop). Адопт по образцу Android §13a: намерение ПЕРЕД воскрешением —
        // иначе reconcile погасит. §13 цел: это не авто-коннект из OFF, а факт живого СВОЕГО
        // туннеля (iOS-обсервер фильтрует чужие сессии; Android-путь сюда же — идемпотентен).
        // Kill-switch: features.adopt_live_tunnel (default ON).
        // AVPN awg31-xray-v1: повторный Connected в фазе Verifying (iOS Reconnecting→Connected при
        // смене сети) — НЕ адопт (движок и так знает свой туннель), а перезапуск верификации ниже.
        if (!m_engine.onTunnelConnected()
            && !m_engine.isVerifying()
            && m_op == Op::None
            && avpn::TuningStore::flag(QStringLiteral("adopt_live_tunnel"))) {
            m_wantConnected = true;
            m_engine.adoptTunnelConnected();
        }
#if defined(Q_OS_MACOS) && !defined(MACOS_NE)
        // AVPN (wake-реконнект): успешный подъём закрывает wake-операцию (если шла) и заново
        // перехватывает wakeup/networkChanged — createProtocolConnections на КАЖДОМ connectToVpn
        // переподключает ванильный rep→reconnectToVpn, срезать надо после каждого коннекта.
        m_wakeRestartPending = false;
        m_wakeTries = 0;
        hookDaemonWakeSignals();
#endif
        if (m_rttProbe)
            m_rttProbe->cancel(); // подключились → off-tunnel ICMP больше не нужен (был бы внутри туннеля)
        // AVPN awg31-xray-v1 (инвариант волны §4.3): xray поднят платформой → движок в Verifying —
        // «Подключено» и все его эффекты (пуши/чипы/живой RTT/история) ТОЛЬКО после первой удачной
        // пробы через туннель (startXrayVerification → finishVerify → onTunnelUpEffects). awg — сразу.
        if (m_engine.isVerifying())
            startXrayVerification();
        else
            onTunnelUpEffects();
        break;
    case Vpn::Error:
        // AVPN awg31-xray-v1: провал подъёма (наш start в полёте) — в локальную историю транспорта
        // (EWMA успеха по паре локация×proto: следующий выбор демоутит транспорт после 2+ провалов).
        if (m_op == Op::Starting && m_engine.recordTransportOutcome(false))
            persistTransportHistory();
        ++m_verifyEpoch; // стейл-ответы верификации xray выбрасываются
        // AVPN (анти-авто-коннект): РАНЬШЕ обрыв из Connected → notifyConnectionLost() → реактивный
        // авто-failover (реконнект). Это давало НЕЖЕЛАТЕЛЬНЫЙ авто-коннект, когда туннель гасит ВНЕШНЕ
        // (другой VPN / iOS / пользователь снял VPN): приложение тут же переподнимало туннель, «воюя»
        // с другим VPN и самоподключаясь при входе в приложение. Теперь как обычное VPN-приложение:
        // фиксируем факт, НЕ реконнектим сами. (Failover по РЕАЛЬНОЙ смерти ноды остаётся в health-loop
        // tick — onTick→m_engine.tick, см. §анти-авто-коннект ниже + CONNECT-INVARIANTS §13.)
        m_engine.onTunnelError();
        break;
    case Vpn::Disconnected:
        // onTunnelDisconnected САМ продолжит НАМЕРЕННЫЙ свитч ноды (Switching+pendingSwitch → up());
        // если это не свитч — просто «отключено». БЕЗ реактивного failover на внешний обрыв (см. Error).
        ++m_verifyEpoch; // AVPN awg31-xray-v1: верификация xray старой сессии отменена
        m_engine.onTunnelDisconnected();
        break;
    case Vpn::Reconnecting:
        // Промежуточное iOS-Reconnecting: НЕ инициируем свитч/реконнект — дождёмся терминала.
        break;
    default: // Unknown/Preparing/Connecting/Disconnecting — промежуточные, фазу движка не трогаем.
        break;
    }

    // AVPN (анти-авто-коннект на внешний обрыв): если туннель ушёл в Disconnected/Error, и при этом мы
    // НЕ ведём свою операцию (m_op==None: не наш start/stop) и движок НЕ в намеренном свитче/коннекте
    // (switching/connecting/selecting), значит туннель погас ВНЕШНЕ (другой VPN / iOS / пользователь).
    // Снимаем намерение, чтобы reconcile() НЕ поднял туннель заново — подключение только вручную.
    if (s == Vpn::Disconnected || s == Vpn::Error) {
        const QString est = m_engine.debugSnapshot().state; // DebugSnapshot-структура (поле, не QVariantMap)
        const bool weAreOperating = (m_op != Op::None); // наш guardedStart/guardedStop в полёте
        const bool engineSwitching = (est == QLatin1String("switching")
                                   || est == QLatin1String("connecting")
                                   || est == QLatin1String("selecting"));
        if (!weAreOperating && !engineSwitching)
            m_wantConnected = false;
    }

    // AVPN (reconcile-машина): терминальное состояние снимает op-in-flight и разрешает следующий шаг;
    // промежуточные (Connecting/Disconnecting/Reconnecting/Preparing) держим «занято» (UI «подбираем…»).
    {
        const bool terminal = (s == Vpn::Connected || s == Vpn::Disconnected
                               || s == Vpn::Error || s == Vpn::Unknown);
        if (terminal) {
            const Op finished = m_op;
            m_op = Op::None;
            m_opInFlight = false;
            m_busy = false;
            m_watchdog.stop();
            if (s == Vpn::Connected)
                m_startAttempts = 0;                 // успех — счётчик попыток сброшен
            else if (s == Vpn::Error && finished == Op::Starting)
                ++m_startAttempts;                   // connect не удался — считаем попытку (анти-зацикливание)
        } else {
            m_busy = true;                           // идёт переход — занято
        }
        // AVPN awg31-xray-v1: xray поднят, но ещё не подтверждён пробой — орб остаётся «занят»
        // (спиннер «Подключаемся…»/«Проверяем трафик…»), stopping=false (намерение = онлайн).
        if (m_engine.isVerifying())
            m_busy = true;
        // AVPN awg31-xray-v1 (reseed, инвариант §4.4): терминал → отложенное тело пула применяем
        // с верха цикла событий (никогда из стека колбэка туннеля / Selector::pick).
        if (terminal && (s == Vpn::Disconnected || s == Vpn::Error) && m_engine.hasPendingReseed())
            QTimer::singleShot(0, this, [this]() { applyPendingReseed(); });
    }
    persistTransportHistory(); // AVPN awg31-xray-v1: no-op, если движок ничего не записал

    // AVPN (реальные палочки): туннель не в Connected → гасим живые палочки (кэш RTT не должен
    // маскировать обрыв). При следующем Connected проба пере-сидирует SignalQuality с нуля.
    if (state() != QLatin1String("connected")
        && (m_liveBars != 0 || m_liveReachable || m_liveRtt >= 0 || m_liveDead || m_liveFailStreak)) {
        m_signal.reset();
        m_liveBars = 0;
        m_liveRtt = -1;
        m_liveReachable = false;
        m_liveDead = false;        // обрыв/смена ноды → «мертво» снимаем, при новом Connected мерим заново
        m_liveFailStreak = 0;
        emit liveQualityChanged();

        // AVPN чипы v2 (2026-07-12): обрыв/смена ноды → НЕ гасим чипы в серый (источник «то цветные,
        // то серые» на каждом транзиенте iOS Reconnecting), а помечаем последний вердикт stale —
        // QML приглушает чип до первого свежего результата новой ноды. In-flight серию инвалидируем
        // (вердикт старой ноды не должен дописаться в чипы новой), гистерезис сбрасываем (первый
        // вердикт новой ноды принимается сразу — нода могла смениться, старая история не сравнима).
        if (m_svcProbe)
            m_svcProbe->invalidate();
        m_chipHyst.clear();
        m_chipConfirms.clear();
        bool anyFresh = false;
        for (int i = 0; i < m_serviceStatus.size(); ++i) {
            QVariantMap m = m_serviceStatus.at(i).toMap();
            if (!m.value(QStringLiteral("stale"), false).toBool()) {
                m[QStringLiteral("stale")] = true;
                m_serviceStatus[i] = m;
                anyFresh = true;
            }
        }
        if (anyFresh)
            emit serviceStatusChanged();
    }

    emit changed();

    // AVPN: довести факт до намерения — поднять отложенный старт после Disconnected (смена ноды) или
    // погасить туннель, если намерение изменилось. ОТКЛАДЫВАЕМ через singleShot(0): этот слот вызван из
    // сигнала VpnConnection (возможно — изнутри вложенного QEventLoop сетевого вызова); прямой reconcile()
    // → guardedStart мог бы повторно войти в обработку поверх текущего стека → re-entrancy/abort. Деферим
    // на верх цикла событий. No-op, если op в полёте / состояние промежуточное.
    QTimer::singleShot(0, this, [this]() { reconcile(); });
}

void AvpnEngineQml::onVpnProtocolError(amnezia::ErrorCode code) // AVPN
{
    // Протокол-уровневая ошибка раньше терялась (сигнал не был подключён). Surface наружу в error().
    // AVPN (анти-авто-коннект): больше НЕ зовём notifyConnectionLost() (реактивный failover/реконнект) —
    // фиксируем факт ошибки; подключение только вручную. См. onConnectionStateChanged выше.
    m_engine.onTunnelError();
    // AVPN (фикс залипания): ошибка ОБЯЗАНА снять op-in-flight (раньше не трогала m_pendingStart →
    // следующий start() мгновенно return → орб залипал навсегда). Теперь машина разблокируется.
    const Op finished = m_op;
    m_op = Op::None;
    m_opInFlight = false;
    m_busy = false;
    m_watchdog.stop();
    if (finished == Op::Starting)
        ++m_startAttempts;
    // AVPN: на iOS «InternalError» (код 101) — ЛОЖНЫЙ: m_vpnProtocol там всегда null (туннель ведёт
    // IosController, это норма), а VpnConnection::lastError() из-за этого отдаёт InternalError. Не пугаем
    // им пользователя (он лез тостом при смене сервера/rotateNext). Реальные ошибки показываем.
    if (code != amnezia::ErrorCode::InternalError)
        emit error(errorString(code));
    emit changed();
    // AVPN (аудит N6, §3): только отложенно — слот вызван из сигнала VpnConnection; при живом вложенном
    // цикле (awaitReply в redeemCode/kickDevice) queued-события доставляются ВНУТРЬ него → re-entrancy.
    QTimer::singleShot(0, this, [this]() { reconcile(); });
}

void AvpnEngineQml::bootstrap() // AVPN: Task 11 — живой бейдж (ГБ/дней/subActive) ДО первого Connect.
{
    // Дедуп: не стартуем вторую цепочку, если уже успешно прогрузились ИЛИ ретраи в полёте
    // (защита от повторного вызова из QML Component.onCompleted нескольких экранов + дефер-вызова
    // из конструктора). m_bootstrapped теперь ставится ТОЛЬКО при успехе → после исчерпания ретраев
    // повторный заход (навигация/Connect) снова разрешён.
    if (m_bootstrapped || m_bootstrapInFlight)
        return;
    m_bootstrapInFlight = true;
    m_bootstrapRetries = 0;

    // Ключи клиента (zero-knowledge) — для enroll и последующего connect; ошибка не фатальна для бейджа.
    QString err;
    if (m_engine.identityEnsureKeys(m_store, err))
        m_tunnel.setClientKeys(m_engine.clientKeys());

    // Тихая прогрузка подписки БЕЗ подъёма туннеля, С РЕТРАЕМ при транзиентном сетевом сбое (см. ниже).
    tryBootstrapSubscription();

    // AVPN (Task 9): если первичный авто-enroll создал subscription_token, а device token уже пришёл
    // из APNs ДО enroll — флашим отложенный push-токен (дедуп защитит от повтора). authToken() пуст →
    // registerPushToken снова тихо отложит до следующего коннекта/ротации.
    flushPendingPushToken();
}

// AVPN: тихий фетч подписки на холодном старте С САМОВОССТАНОВЛЕНИЕМ. Корень бага «после обновления нет
// нод»: одиночный фетч на первом запуске падал транзиентно (сеть/DNS/TLS/NE ещё не прогреты сразу после
// апдейта) → пул пустой до ручного перезапуска ( retry отсутствовал; 401-самохил в ensureSubscription
// сетевые сбои не покрывает). Решение: переарм с бэкоффом 2/4/8/16/30с, затем ВЕЧНЫЙ медленный цикл 60с
// (BootstrapRetry.h), тихо (без error()). Раньше после 5 попыток сдавались навсегда — на сотовой с
// холодным радио первое 60с-окно проваливалось целиком и «∞»/пустой пул жили до перезапуска приложения.
// Ускорение извне — kickBootstrap() (появление сети/foreground) поджимает m_bootstrapRetryTimer.
// АСИНХРОННО (2026-07-07): раньше здесь был m_engine.bootstrap → awaitReply (вложенный QEventLoop,
// до 4с блокировки главного потока НА КАЖДУЮ попытку). С вечным ретраем это недопустимо — перешли
// на armTimeout-цепочку (kNetTimeoutMs 15с: не блокирует UI, и сотовой с холодным радио хватает).
// Успех → m_bootstrapped=true (дедуп), пул наполнен, RTT-проба.
void AvpnEngineQml::tryBootstrapSubscription()
{
    if (m_bootstrapped)
        return;
    const QString token = Enrollment::loadToken();
    if (token.isEmpty()) {
        bootstrapEnrollAsync(/*reEnrolled=*/false); // первый вход: POST /v1/trial → GET /v1/subscription
        return;
    }
    bootstrapFetchAsync(token, /*tokenFromStore=*/true, /*reEnrolled=*/false);
}

// AVPN: async-энролл для bootstrap-цепочки. Повторяет side-эффекты Enrollment::enroll (saveToken,
// clearPendingReferral, Keychain-якорь через saveToken) через те же чистые хелперы, но БЕЗ awaitReply.
void AvpnEngineQml::bootstrapEnrollAsync(bool reEnrolled)
{
    if (!m_nam) { onBootstrapAttemptFailed(); return; }
    QString err;
    if (!m_engine.identityEnsureKeys(m_store, err)) { onBootstrapAttemptFailed(); return; }
    m_tunnel.setClientKeys(m_engine.clientKeys());

    const QByteArray body = Enrollment::buildTrialBody(
        m_engine.identity().publicKey(), Identity::deviceId(m_store), Enrollment::detectPlatform(),
        deviceMarketingName(), Enrollment::loadPendingReferral(),
        DeviceFingerprint::get()); // AVPN (anti-farm, 7eb3467a): паритет с sync-enroll — якорь железа и тут
    QNetworkRequest req{QUrl(m_baseUrl + QStringLiteral("/v1/trial"))};
    req.setHeader(QNetworkRequest::ContentTypeHeader, QByteArrayLiteral("application/json"));

    QNetworkReply *reply = m_nam->post(req, body);
    armTimeout(reply);
    connect(reply, &QNetworkReply::finished, this, [this, reply, reEnrolled]() {
        reply->deleteLater();
        const int code = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        const bool netErr = (reply->error() != QNetworkReply::NoError);
        const auto outcome = Enrollment::classifyFetch(code, netErr);
        // AVPN (белые списки): любой дошедший HTTP-статус = control plane достижим; транспортный
        // фейл (code==0) — сигнал детектору (порог 2 фейлов подряд запускает раунд проб).
        if (m_whitelistDetector) {
            if (code > 0) m_whitelistDetector->noteControlPlaneOk();
            else if (netErr) m_whitelistDetector->noteControlPlaneFailure();
        }
        if (outcome == FetchOutcome::Transferred) { stopBootstrapTerminal(); return; } // 410: триал не выдаётся
        if (outcome != FetchOutcome::Ok) { onBootstrapAttemptFailed(); return; }
        TrialResponse tr;
        QString perr;
        if (!Enrollment::parseTrialResponse(reply->readAll(), tr, perr)) { onBootstrapAttemptFailed(); return; }
        Enrollment::saveToken(tr.subscriptionToken);
        Enrollment::clearPendingReferral(); // реферал атрибутирован на бэке (first-touch)
        emit changed();                     // authToken появился → зависимые биндинги оживут
        // AVPN (Task 9): device token из APNs мог прийти ДО enroll — теперь authToken есть, флашим.
        flushPendingPushToken();
        bootstrapFetchAsync(tr.subscriptionToken, /*tokenFromStore=*/false, reEnrolled);
    });
}

// AVPN: async GET /v1/subscription для bootstrap-цепочки. Исходы — через те же чистые решатели
// (classifyFetch/decideAuthRecovery, покрыты auth_heal_check), что и синхронный ensureSubscription.
void AvpnEngineQml::bootstrapFetchAsync(const QString &token, bool tokenFromStore, bool reEnrolled)
{
    if (!m_nam) { onBootstrapAttemptFailed(); return; }
    QNetworkRequest req{versionedSubscriptionUrl(
        m_baseUrl, QCoreApplication::applicationVersion())};
    req.setRawHeader(QByteArrayLiteral("Authorization"),
                     QByteArrayLiteral("Bearer ") + token.toUtf8());

    QNetworkReply *reply = m_nam->get(req);
    armTimeout(reply);
    connect(reply, &QNetworkReply::finished, this, [this, reply, tokenFromStore, reEnrolled]() {
        reply->deleteLater();
        const int code = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        const bool netErr = (reply->error() != QNetworkReply::NoError);
        const auto outcome = Enrollment::classifyFetch(code, netErr);
        // AVPN (белые списки): паритет с enroll-путём — HTTP-ответ гасит подозрение, транспортный
        // фейл копит стрик детектора.
        if (m_whitelistDetector) {
            if (code > 0) m_whitelistDetector->noteControlPlaneOk();
            else if (netErr) m_whitelistDetector->noteControlPlaneFailure();
        }
        if (outcome == FetchOutcome::Ok) {
            finishBootstrapSuccess(reply->readAll());
            return;
        }
        if (outcome == FetchOutcome::Transferred) { // 410: подписка уехала — терминально, НЕ ре-энроллим
            if (!m_transferredAway) { m_transferredAway = true; emit changed(); }
            stopBootstrapTerminal();
            return;
        }
        if (Enrollment::decideAuthRecovery(outcome, tokenFromStore, reEnrolled)
            == AuthRecoveryAction::ReEnrollThenRetry) {
            Enrollment::clearToken();               // стейл-токен (ротация secret на бэке) — выкинуть
            bootstrapEnrollAsync(/*reEnrolled=*/true); // один ре-энролл + повторный fetch, без петли
            return;
        }
        if (outcome == FetchOutcome::Unauthorized) { // свежий токен 401 / уже лечили — ретрай не поможет
            stopBootstrapTerminal();
            return;
        }
        onBootstrapAttemptFailed(); // сеть/5xx/429 — транзиентно, вечный ретрай добьёт
    });
}

// AVPN: успех bootstrap-цепочки — единая точка (парс + LKG-персист + пробы + оживление UI).
void AvpnEngineQml::finishBootstrapSuccess(const QByteArray &body)
{
    QString err;
    const bool parseOk = m_engine.loadSubscription(body, err);
    // AVPN (баг 2026-07-10 «начисленный триал не подхватился без перезахода»): исход 200-тела
    // решает чистый decideBootstrapBody (BootstrapRetry.h, покрыт bootstrap_retry_check). Бэк для
    // устройства без подписки отдаёт 200 со status=degraded и nodes:[] — раньше такое тело
    // ЗАЩЁЛКИВАЛО m_bootstrapped=true и навсегда глушило ретрай (kickBootstrap — no-op по защёлке,
    // refreshSubscription пул не наполняет) → начисленная позже подписка жила только после
    // рестарта процесса. Теперь пустой пул = «подписки ещё нет»: стейт применяем (degraded —
    // авторитетная правда, m_subMissingSeen поднимает CTA в UI), но цикл продолжаем — начисление
    // подхватится ближайшим ретраем (≤60с) или kickBootstrap (foreground/сеть).
    switch (avpn::decideBootstrapBody(parseOk, m_engine.hasSubscription())) {
    case avpn::BootstrapBodyAction::RetryTransient:
        onBootstrapAttemptFailed(); // битое тело не затирает LKG-пул и не останавливает ретрай
        return;
    case avpn::BootstrapBodyAction::KeepPollingEmptyPool:
        // Валидное 200-тело (пусть и с пустым пулом) — общие с latch-путём эффекты обязаны
        // случиться и здесь (ревью 2026-07-10): LKG = честный стейт; transferredAway снят
        // (тело валидно = не 410, иначе UI показывал бы «перенесена» вместо CTA после
        // ре-энролла с непровиженным пулом); push-токен флашим (дедуп внутри) — иначе
        // no-sub устройство не получит пуш «подписка активирована».
        Enrollment::saveLkgSubscription(body);
        if (m_transferredAway) { m_transferredAway = false; }
        flushPendingPushToken();
        emit changed(); // daysLeft/traffic/subMissing обновятся; защёлку НЕ ставим, таймер жив
        onBootstrapAttemptFailed();
        return;
    case avpn::BootstrapBodyAction::LatchSuccess:
        break;
    }
    Enrollment::saveLkgSubscription(body); // AVPN (LKG): персистим ТОЛЬКО валидное тело
    if (m_transferredAway) { m_transferredAway = false; } // подписка снова валидна (новый ключ/энролл)
    m_bootstrapped = true;
    m_bootstrapInFlight = false;
    m_bootstrapRetries = 0;
    m_bootstrapRetryTimer.stop();
    emit changed(); // подписка наполнена → Q_PROPERTY (daysLeft/traffic*/subActive/nodePool) обновятся
    probeNodeRtt(); // AVPN (выбор по скорости): тёплый off-tunnel ICMP при старте (туннель опущен) —
                    // чтобы ПЕРВЫЙ «Авто (быстрейший)» уже выбирал по реальному RTT, а не по weight.
    flushPendingPushToken(); // токен точно есть — дедуп внутри защитит от повтора
    refreshAnnouncements();  // AVPN (P-ANN): токен есть → подтянуть актуальные объявления
    flushWhitelistEpisodes(); // AVPN (белые списки): сеть жива — отдать накопленные эпизоды
}

// AVPN (белые списки, спека §7): отправка очереди whitelist-эпизодов после восстановления
// сети. Одна попытка за сессию (m_whitelistEpisodesSent; сброс при новом эпизоде): бэк может
// быть без эндпоинта (handoff WHITELIST-EPISODES-BACKEND-HANDOFF.md) — 404 молчим, очередь
// капнута 10 и не растёт. 2xx -> очередь очищена.
void AvpnEngineQml::flushWhitelistEpisodes()
{
    if (m_whitelistEpisodesSent || !m_nam)
        return;
    QSettings st;
    const QByteArray raw = st.value(QStringLiteral("Whitelist/episodes")).toByteArray();
    const QJsonArray arr = QJsonDocument::fromJson(raw).array();
    if (arr.isEmpty())
        return;
    const QString token = authToken();
    if (token.isEmpty())
        return;
    m_whitelistEpisodesSent = true; // одна попытка за сессию, независимо от исхода
    QJsonObject body;
    body.insert(QStringLiteral("episodes"), arr);
    QNetworkRequest req{QUrl(m_baseUrl + QStringLiteral("/v1/telemetry/net-episodes"))};
    req.setHeader(QNetworkRequest::ContentTypeHeader, QStringLiteral("application/json"));
    req.setRawHeader(QByteArrayLiteral("Authorization"), QByteArrayLiteral("Bearer ") + token.toUtf8());
    QNetworkReply *reply = m_nam->post(req, QJsonDocument(body).toJson(QJsonDocument::Compact));
    armTimeout(reply);
    connect(reply, &QNetworkReply::finished, this, [this, reply, raw]() {
        reply->deleteLater();
        const int code = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        if (code >= 200 && code < 300) {
            // Ревью: чистим ТОЛЬКО если очередь не изменилась за время полёта — иначе
            // сотрём эпизод, завершившийся между отправкой и ответом (уйдёт следующей сессией).
            QSettings s;
            if (s.value(QStringLiteral("Whitelist/episodes")).toByteArray() == raw) {
                s.remove(QStringLiteral("Whitelist/episodes"));
                s.sync();
            }
        }
        // 404 (бэк ещё без эндпоинта) / прочее — молчим, очередь останется на следующую сессию
    });
}

// AVPN: провал попытки — тихо переарм: быстрый бэкофф → вечный медленный цикл (никогда не сдаёмся).
void AvpnEngineQml::onBootstrapAttemptFailed()
{
    int delayMs = nextBootstrapDelayMs(m_bootstrapRetries);
    // AVPN (белые списки): в активном режиме сеть мертва для нас ФИЗИЧЕСКИ — растянуть цикл
    // (60с -> ~240с), не жечь батарею/радио. Выход из режима зовёт kickBootstrap() ->
    // немедленный фетч, юзер задержки не видит.
    if (m_whitelistDetector && m_whitelistDetector->active())
        delayMs *= qBound(1, int(avpn::TuningStore::numberOr(
                              QStringLiteral("whitelist_retry_stretch"), 4)), 20);
    m_bootstrapRetryTimer.start(delayMs);
    ++m_bootstrapRetries;
}

// AVPN: терминальный исход (410 transferred / невосстановимый 401) — вечный ретрай тут ВРЕДЕН
// (долбил бы бэк каждые 60с заведомо мёртвым запросом). Отпускаем цепочку: следующий заход
// (навигация/kick/Connect/redeem нового ключа) сможет попробовать заново с чистого листа.
void AvpnEngineQml::stopBootstrapTerminal()
{
    m_bootstrapInFlight = false;
    m_bootstrapRetries = 0;
    m_bootstrapRetryTimer.stop();
}

// AVPN (фикс «на сотовой ∞ навсегда»): поджать ретрай bootstrap — сеть появилась/сменилась или
// приложение вышло из фона. СТРОГО про фетч подписки: после успешного bootstrap это no-op, туннель/
// коннект/выбор ноды не трогает (безопасно звать сколь угодно часто). Фетч НЕ запускаем синхронно
// из сигнала: сетевые транзишены/резюм — худший момент для вложенного QEventLoop на главном потоке
// (iOS watchdog, см. NetAwait.h) + сети нужно время устаканиться. Вместо этого взводим таймер.
void AvpnEngineQml::kickBootstrap()
{
    static constexpr int kKickDelayMs = 1200; // как стартовый дефер bootstrap: окно показано, сеть осела
    if (m_bootstrapped)
        return;
    if (!m_bootstrapInFlight) {
        // Цепочка ещё не стартовала (ранний сигнал до дефер-вызова из конструктора) — bootstrap()
        // сам идемпотентен, лишний вызов схлопнется.
        QTimer::singleShot(kKickDelayMs, this, &AvpnEngineQml::bootstrap);
        return;
    }
    // Ретрай спит (до 60с в медленном цикле) — поджать. Если сработает раньше kKickDelayMs сам, не трогаем.
    if (m_bootstrapRetryTimer.isActive() && m_bootstrapRetryTimer.remainingTime() > kKickDelayMs)
        m_bootstrapRetryTimer.start(kKickDelayMs);
}

void AvpnEngineQml::start()
{
    // AVPN (Task 7): явный start() выходит из паузы (пользователь сам поднял VPN).
    m_pauseTimer.stop();
    m_paused = false;
    m_wasConnected = false;
    // AVPN (sub-grace): явный старт снимает состояние «отключено из-за истечения подписки» —
    // и флаг UI, и гард однократности (если подписка всё ещё истекшая, гейт отработает заново).
    m_subEnforcedStop = false;
    m_graceStopInFlight = false;
    // Намерение: хотим быть онлайн (к авто/закреплённой ноде). Факт догонит reconcile() из терминала.
    m_wantConnected = true;
    m_startAttempts = 0;        // ручной запуск — свежая серия попыток
    reconcile();
    // reconcile мог ранне-выйти (op-in-flight) без эмита — а направление (stopping) уже сменилось;
    // UI должен увидеть его сразу, не дожидаясь терминального колбэка. // AVPN
    emit changed();
}

void AvpnEngineQml::stop()
{
    // AVPN (Task 7): явный stop() отменяет ожидающую авто-паузу (пользователь сам выключил VPN).
    m_pauseTimer.stop();
    m_paused = false;
    m_wasConnected = false;
    // Намерение: хотим быть офлайн. reconcile() опустит туннель, если он поднят.
    m_wantConnected = false;
    m_needsRestart = false;
    m_startAttempts = 0;
    reconcile();
    // как в start(): направление (stopping) сменилось сразу, даже если reconcile ранне-вышел
    // (отмена недоехавшего коннекта) — эмитим, чтобы орб мгновенно перестал показывать Connecting. // AVPN
    emit changed();
}

// AVPN (reconcile-машина): ЕДИНСТВЕННАЯ точка, поднимающая/опускающая туннель. Действует ТОЛЬКО из
// терминального состояния (.connected/.disconnected/.error) — никогда не up()/down() поверх перехода
// (back-to-back давало iOS «Operation Cancelled»/«Network error»). Смена ноды: connected + needsRestart
// → guardedStop(); затем на пришедшем Disconnected reconcile() сам поднимет цель (pinned/auto). Зовётся
// из start/stop/switchToNode/rotateNext/selectAuto/reprobe и из onConnectionStateChanged/onWatchdog.
void AvpnEngineQml::reconcile()
{
    if (m_paused)
        return;          // во время авто-паузы туннель ведёт pause-логика — не вмешиваемся
    if (m_opInFlight)
        return;          // операция в полёте — ждём терминального колбэка (debounce, анти-шторм)
    // AVPN (ревью 2026-07-11, гонка «двойной up»): движок ведёт СВОЙ внутренний двухфазный свитч
    // (failover onDead → requestSwitch → down() → на Disconnected continuePendingSwitch → up()),
    // state=Switching держится до Connected/Error. Терминальный Disconnected от down() уже снял
    // m_opInFlight → отложенный reconcile() влезал guardedStart-ом ПОВЕРХ поставленного в очередь
    // up(): второй connectToVpn back-to-back (iOS «Operation Cancelled»), причём второй connect()
    // мог выбрать даже только что признанную DEAD ноду. Из Switching движок выходит ТОЛЬКО через
    // колбэки туннеля (Connected/Error) — каждый снова ставит singleShot(0, reconcile), так что
    // гейт машину не подвешивает.
    if (m_engine.state() == avpn::EngineState::Switching)
        return;

    const Vpn::ConnectionState s = m_lastTunnelState;
    const bool connected = (s == Vpn::Connected);
    // Error/Unknown/Disconnected = «можно действовать» (туннель де-факто не поднят). Error трактуем так
    // же, как Disconnected, иначе после ошибки teardown машина залипла бы (старый баг).
    const bool actionable = (s == Vpn::Disconnected || s == Vpn::Unknown || s == Vpn::Error);
    if (!connected && !actionable)
        return;          // промежуточное (Connecting/Disconnecting/Reconnecting/Preparing) — ждём

    if (m_wantConnected) {
        if (connected) {
            if (m_needsRestart) {        // надо переехать на другую ноду → сначала чистый teardown
                m_needsRestart = false;
                guardedStop();
            }
            // connected && !needsRestart → уже где надо
        } else {                         // офлайн, а хотим онлайн → поднимаем выбранную/авто ноду
            if (m_startAttempts >= 3) {  // постоянный провал connect — не зацикливаемся (ошибка уже показана)
                m_wantConnected = false;
                m_startAttempts = 0;
                return;
            }
            guardedStart();
        }
    } else {                             // хотим офлайн
        if (connected)
            guardedStop();
        // офлайн → уже отключены
    }
}

// AVPN: поднять туннель. startFlow = enroll→GET /v1/subscription→connect()→up() (async). Помечаем
// op-in-flight + сторож; m_busy держим до прихода Connected (UI «подбираем…»).
void AvpnEngineQml::guardedStart()
{
#if defined(Q_OS_MACOS) && !defined(MACOS_NE)
    // AVPN (BUG-6): реальный старт создаст протокол — дальше stop идёт штатным путём.
    m_adoptedNoProto = false;
#endif
    // AVPN (краш-фикс iOS, анти-реэнтрантность): startFlow ниже крутит вложенный QEventLoop на главном
    // потоке. Если guardedStart переисполнен ИЗ этого цикла (queued onConnectionStateChanged очищает
    // m_opInFlight, затем отложенный reconcile→guardedStart прилетает внутри того же loop.exec()),
    // второй вход застекал бы ещё один loop.exec() → re-entrancy → abort() (см. комментарий ниже + NetAwait.h).
    // Деферим на верх цикла событий — намерение не теряется, повтор отработает после раскрутки стека.
    if (m_inSyncNetCall) {
        QTimer::singleShot(0, this, [this]() { guardedStart(); });
        return;
    }
#if defined(Q_OS_MACOS) && !defined(MACOS_NE)
    // AVPN: другой активный VPN (чужой full-tunnel/демон) дерётся за маршрут → «крутится, не
    // подключается». Предупреждаем (не блокируем — на случай ложного срабатывания).
    {
        const QString foreign = avpn::macForeignVpnName();
        if (!foreign.isEmpty())
            emit vpnConflict(foreign);
    }
    // AVPN (ноль терминала): на macOS туннель поднимает root-демон Tribe-service. Ставим/обновляем из
    // ВШИТОГО tarball одним системным промптом пароля (MacServiceInstaller). Триггер: демон не запущен
    // ЛИБО устарел (macServiceOutdated: хэш бинарей вшитого ≠ установленного). Без апдейт-триггера
    // правки логики демона (split-DNS и т.п.) не доезжали бы до юзеров с уже стоящим демоном.
    // Актуальный запущенный демон → мгновенный выход, путь коннекта НЕ меняется.
    //
    // AVPN (beachball-фикс 2026-07-21): установка БОЛЬШЕ НЕ блокирует GUI-поток. Раньше пароль +
    // распаковка tarball + msleep-ожидание демона (до ~5с) жили прямо здесь — окно «висело» с
    // радужным курсором на всё время ввода пароля. Теперь: подтверждение — на главном потоке
    // (macInstallServiceConfirm, display dialog качает события), привилегированная установка +
    // ожидание живого демона — в фоновом QThread (nested QEventLoop нет — CONNECT-INVARIANTS
    // соблюдён), а UI показывает svcInstalling («Устанавливаем службу VPN…»). Продолжение старта —
    // finishSvcInstall → reconcile(): намерение (m_wantConnected) всё это время взведено.
    if (m_svcInstallInFlight)
        return;                       // установка уже идёт — reconcile дождётся finishSvcInstall
    const bool needInstall = !avpn::macServiceInstalled() || avpn::macServiceOutdated();
    if (!avpn::macServiceRunning() || needInstall) {
        if (needInstall) {
            QString cerr;
            if (!avpn::macInstallServiceConfirm(&cerr)) {
                // Пользователь отменил — снимаем намерение (иначе ближайший reconcile переспросит).
                m_wantConnected = false;
                ++m_startAttempts;
                emit error(cerr.isEmpty() ? tr("Установка службы VPN отменена") : cerr);
                emit changed();
                return;
            }
        }
        m_svcInstallInFlight = true;
        m_svcInstalling = true;
        m_busy = true;               // орб — спиннер; текст даёт svcInstalling
        emit changed();
        QThread *worker = QThread::create([this, needInstall]() {
            QString ierr;
            bool ok = true;
            if (needInstall) {
                ok = avpn::macInstallServiceRun(&ierr); // пароль + tarball + bootstrap + ожидание демона
            } else {
                // Демон установлен, но не бежит (рестарт/kill) — даём launchd до ~5с поднять его;
                // старт продолжаем в любом случае (паритет с прежним поведением: up() сам упадёт
                // честной ошибкой, если демона так и нет).
                for (int i = 0; i < 16 && !avpn::macServiceRunning(); ++i)
                    QThread::msleep(300);
            }
            QMetaObject::invokeMethod(this, [this, ok, ierr]() { finishSvcInstall(ok, ierr); },
                                      Qt::QueuedConnection);
        });
        connect(worker, &QThread::finished, worker, &QObject::deleteLater);
        worker->start();
        return;                       // продолжение старта — из finishSvcInstall (queued)
    }
#endif

    m_op = Op::Starting;
    m_opInFlight = true;
    m_busy = true;
    m_needsRestart = false;   // свежий старт всегда поднимает целевую (pin/auto) ноду — рестарт не нужен
    // AVPN backend-first (final review MF-2): свежее значение сторожа на каждый взвод (server-driven,
    // без ребилда); setInterval конструктора (15000) остаётся вкомпиленным дефолтом.
    // Пол связан с handshake-бюджетом (ConnectTunables.h): watchdog ВСЕГДА > handshake_timeout,
    // иначе сторож рвёт штатный медленный коннект (ревью 2026-07-11).
    m_watchdog.setInterval(avpn::reconcileWatchdogMsTuned());
    m_watchdog.start();
    emit changed();

    QString err;
    if (m_engine.identityEnsureKeys(m_store, err))
        m_tunnel.setClientKeys(m_engine.clientKeys());

    // AVPN RU-direct: засеять split-tunnel (рунет CIDR мимо туннеля) ДО подъёма — конфиг должен быть готов
    // к appendSplitTunnelingConfig, который читает routeMode/vpnSites из репозитория при openConnection.
    applyRuBypassSplit();

    // AVPN (КОРНЕВОЙ фикс зависания UI + краша на 2-м коннекте): если подписка УЖЕ загружена
    // (bootstrap при старте или прошлый connect) — поднимаем туннель ЛОКАЛЬНО через m_engine.connect(),
    // БЕЗ синхронного сетевого startFlow. startFlow крутит ВЛОЖЕННЫЙ QEventLoop на ГЛАВНОМ потоке
    // (enroll + GET /v1/subscription); на 2-м коннекте, когда летят сигналы дисконнекта, это давало
    // повторный вход вложенного цикла → «Hang UIKit-runloop» (по логам устройства) → abort(). В Amnezia
    // кнопка коннекта в сеть НЕ ходит — конфиг уже готов, она только поднимает туннель. Делаем так же.
    // AVPN (краш-фикс): startFlow() входит во вложенный QEventLoop (awaitReply). Держим m_inSyncNetCall
    // на время вызова, чтобы переисполнение guardedStart из этого цикла отложилось (см. гард выше), а не
    // застекало второй loop.exec(). QScopedValueRollback гарантирует сброс даже при исключении.
    bool ok;
    {
        QScopedValueRollback<bool> syncGuard(m_inSyncNetCall, true);
        ok = m_engine.hasSubscription() ? m_engine.connect(err)
                                        : m_engine.startFlow(m_nam, m_baseUrl, m_store, err);
    }
    if (!ok) {
        // Подъём не удался ДО туннеля (терминального колбэка не будет) — снимаем op-in-flight, считаем
        // попытку, показываем ошибку. Авто-ретрай не запускаем; орб станет «Connect».
        m_op = Op::None;
        m_opInFlight = false;
        m_busy = false;
        m_watchdog.stop();
        ++m_startAttempts;
        emit error(humanEngineError(err)); // AVPN awg31-xray-v1: no_transport/unsupported_proto → человеческий текст
        emit changed();
        return;
    }
    m_healthTimer.start();
    // up() в очереди — реальный Connecting→Connected/Error прилетит в onConnectionStateChanged, где
    // op-in-flight снимется. m_busy остаётся true до тех пор.
    emit changed();
}

// AVPN: опустить туннель. requestStop() гасит фазу/failover ДО down() (иначе прилетевший Disconnected
// переподнял бы ноду); реальный Disconnected снимет op-in-flight и reconcile поднимет цель при смене.
#if defined(Q_OS_MACOS) && !defined(MACOS_NE)
// AVPN (beachball-фикс): финиш фоновой установки root-демона. Главный поток (queued из worker).
void AvpnEngineQml::finishSvcInstall(bool ok, const QString &err)
{
    m_svcInstallInFlight = false;
    m_svcInstalling = false;
    m_busy = false;              // guardedStart сам вернёт busy, если старт продолжится
    if (!ok) {
        ++m_startAttempts;
        emit error(err.isEmpty() ? tr("Не удалось установить службу VPN") : err);
        emit changed();
        return;
    }
    emit changed();
    // Намерение всё это время было взведено; если пользователь за время установки передумал
    // (нажал «Отключить»), reconcile честно останется no-op. Иначе — штатный guardedStart,
    // теперь по быстрому пути (демон запущен и актуален).
    reconcile();
}

// ---- AVPN macOS wake-реконнект (спека 2026-07-17-macos-wake-reconnect-design.md) --------------
// Корень «закрыл крышку — утром OFF»: демон туннель через ночь ДЕРЖИТ, а на wakeup ванильный
// reconnectToVpn рвал его stop()+start() в ещё не готовую сеть; 20с-сторож (§16) форсил
// Disconnected, §13 снимал намерение (путь мимо guardedStart, m_op==None) → reconcile не поднимал.
// Фикс: wake — НАША операция. §13/§16 не трогаем (внешние обрывы ведут себя как раньше).

void AvpnEngineQml::hookDaemonWakeSignals()
{
    // Kill-switch: features.wake_restart=false — ванильное поведение (подписки не срезаем).
    if (!avpn::TuningStore::flag(QStringLiteral("wake_restart")))
        return;
    // На Connected демон гарантированно жив → waitForSource внутри withInterface мгновенен.
    IpcClient::withInterface([this](QSharedPointer<IpcInterfaceReplica> rep) {
        // Срез ванильного пути БЕЗ правки апстрима: снимаем все подписки rep→VpnConnection
        // (createProtocolConnections их к тому же копит дубликатами на каждый connectToVpn).
        // Окно между connectToVpn и Connected безопасно: reconnectToVpn игнорирует не-Connected.
        QObject::disconnect(rep.data(), &IpcInterfaceReplica::wakeup, m_conn, nullptr);
        QObject::disconnect(rep.data(), &IpcInterfaceReplica::networkChanged, m_conn, nullptr);
        // Наши обработчики (UniqueConnection — на каждом Connected хук повторяется).
        connect(rep.data(), &IpcInterfaceReplica::wakeup, this, &AvpnEngineQml::onDaemonWakeup,
                Qt::ConnectionType(Qt::QueuedConnection | Qt::UniqueConnection));
        connect(rep.data(), &IpcInterfaceReplica::networkChanged, this,
                &AvpnEngineQml::onDaemonNetworkChanged,
                Qt::ConnectionType(Qt::QueuedConnection | Qt::UniqueConnection));
    });
}

void AvpnEngineQml::onDaemonWakeup()         { daemonWakeEvent("wakeup"); }
void AvpnEngineQml::onDaemonNetworkChanged() { daemonWakeEvent("networkChanged"); }

void AvpnEngineQml::daemonWakeEvent(const char *why)
{
    // Kill-switch мог флипнуться уже ПОСЛЕ среза ванильных подписок — честно возвращаем ваниль.
    if (!avpn::TuningStore::flag(QStringLiteral("wake_restart"))) {
        m_conn->reconnectToVpn();
        return;
    }
    if (!m_wantConnected)
        return;                                  // намерения нет — спека §2.1 шаг 1
    if (m_lastTunnelState != Vpn::Connected)
        return;                                  // туннель не поднят — рвать/чинить нечего
    // Ночные дельты rx/tx не должны дать ложный onDead первым же health-tick (спека §2.2).
    m_engine.resetHealthSampling();
    if (m_wakeProbing)
        return;                                  // wakeup+networkChanged летят пачкой — одна проба
    m_wakeProbing = true;
    m_wakeProbeAttempt = 0;                      // новый цикл проб — счётчик повторов с нуля
    qInfo() << "[wake]" << why << "— probing tunnel liveness";
    // Сети после сна нужно время (реассоциация Wi-Fi, DHCP) — пробуем чуть отложенно.
    QTimer::singleShot(2500, this, [this]() { wakeLivenessProbe(); });
}

void AvpnEngineQml::wakeLivenessProbe()
{
    if (!m_wantConnected || m_lastTunnelState != Vpn::Connected) {
        m_wakeProbing = false;                   // состояние уехало, пока ждали — не вмешиваемся
        m_wakeProbeAttempt = 0;
        return;
    }
    // Сначала проверка живости, потом рестарт (спека §2.1 шаг 2): HEAD generate_204 ЧЕРЕЗ туннель
    // (full-tunnel — весь трафик в нём). Успех = туннель пережил сон сам (как у ванили его держал
    // демон) → НИЧЕГО не делаем. Async + transferTimeout — никакого nested QEventLoop (§1).
    QNetworkRequest req{QUrl(QStringLiteral("https://connectivitycheck.gstatic.com/generate_204"))};
    req.setTransferTimeout(4000);
    QNetworkReply *r = m_nam->head(req);
    connect(r, &QNetworkReply::finished, this, [this, r]() {
        r->deleteLater();
        m_wakeProbing = false;
        const int code = r->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        const bool alive = (r->error() == QNetworkReply::NoError && (code == 204 || code == 200));
        if (alive) {
            m_wakeRestartPending = false;
            m_wakeTries = 0;
            m_wakeProbeAttempt = 0;
            qInfo() << "[wake] tunnel alive — nothing to do";
            return;
        }
        if (!m_wantConnected || m_lastTunnelState != Vpn::Connected)
            return;                              // за время пробы состояние уехало
        // AVPN seamless roaming (§23.9): смена BSSID на mesh — секундный провал радио; одна
        // неудачная проба через 2.5 с = ещё не «мёртв». Повторяем пробу (кап
        // numbers.wake_probe_retries, 0 = как раньше) с шагом 4 с и только потом рестарт.
        if (m_wakeProbeAttempt < avpn::wakeProbeRetriesTuned()) {
            ++m_wakeProbeAttempt;
            m_wakeProbing = true;
            qInfo() << "[wake] probe failed — retry" << m_wakeProbeAttempt << "before restart";
            QTimer::singleShot(4000, this, [this]() { wakeLivenessProbe(); });
            return;
        }
        m_wakeProbeAttempt = 0;
        // Мёртв → штатный рестарт ЧЕРЕЗ reconcile (спека §2.1 шаг 3, паттерн pinAndReconcile):
        // m_needsRestart → guardedStop→Disconnected→guardedStart; m_op взведён → §13-гард
        // weAreOperating держит намерение; сторож — движковый клампованный, не жёсткие 20с.
        qInfo() << "[wake] tunnel dead after sleep — restarting (our operation)";
        m_wakeRestartPending = true;
        m_wakeTries = 1;
        m_startAttempts = 0;                     // wake-попытки меряем своим капом
        m_needsRestart = true;
        reconcile();
    });
}

void AvpnEngineQml::wakeKick()
{
    if (!m_wakeRestartPending)
        return;
    if (m_lastTunnelState == Vpn::Connected) {   // уже поднялись (сами или предыдущим ретраем)
        m_wakeRestartPending = false;
        m_wakeTries = 0;
        return;
    }
    if (m_wakeTries >= avpn::wakeRestartMaxTriesTuned()) {
        // Усталость = внешние обстоятельства — честный OFF, подключение вручную (дух §13).
        qInfo() << "[wake] restart tries exhausted — honest OFF";
        m_wakeRestartPending = false;
        return;
    }
    ++m_wakeTries;
    qInfo() << "[wake] network is back — retry" << m_wakeTries;
    // Намерение восстанавливаем: неудача СОБСТВЕННОГО wake-рестарта ≠ «пользователь выключил»
    // (спека §2.1 шаг 4). Это не авто-коннект §13 — операция началась с живого туннеля до сна.
    m_wantConnected = true;
    m_startAttempts = 0;
    reconcile();
}

// AVPN (BUG-6): путь к сокету демона — тот же, что у LocalSocketController (initializeInternal).
static QString avpnDaemonSocketPath()
{
    const QString primary = QStringLiteral("/var/run/avpn/daemon.socket");
    return QFile::exists(primary) ? primary : QStringLiteral("/tmp/avpn.socket");
}

// AVPN (BUG-6, адопция при перезапуске GUI): демон переживает выход GUI и держит туннель, но
// до клика Connect протокол не существует и статус демона никто не спрашивает — GUI показывал
// «выключено», а reconcile мог погасить живой туннель. Лёгкая async-проба (без nested loop,
// NetAwait-доктрина): connect → {"type":"status"} → connected==true → адопт через общий
// choke-point onConnectionStateChanged(Connected) (там же встанет hookDaemonWakeSignals §18).
void AvpnEngineQml::probeDaemonTunnelOnStartup()
{
    if (!avpn::TuningStore::flag(QStringLiteral("adopt_live_tunnel")))
        return;
    if (m_op != Op::None || m_lastTunnelState == Vpn::Connected)
        return; // уже оперируем/подключены — пробе нечего чинить
    auto *sock = new QLocalSocket(this);
    auto *guard = new QTimer(sock);
    guard->setSingleShot(true);
    connect(guard, &QTimer::timeout, sock, &QObject::deleteLater); // демона нет/молчит — тихо уходим
    connect(sock, &QLocalSocket::connected, sock, [sock]() {
        sock->write(QJsonDocument(QJsonObject{ { QStringLiteral("type"), QStringLiteral("status") } })
                        .toJson(QJsonDocument::Compact));
        sock->write("\n");
        sock->flush();
    });
    connect(sock, &QLocalSocket::readyRead, sock, [this, sock]() {
        while (sock->canReadLine()) {
            const QJsonObject o = QJsonDocument::fromJson(sock->readLine()).object();
            if (o.value(QStringLiteral("type")).toString() != QLatin1String("status"))
                continue;
            if (o.value(QStringLiteral("connected")).toBool()
                && m_op == Op::None && m_lastTunnelState != Vpn::Connected) {
                qInfo() << "[adopt] daemon holds a live tunnel — adopting (GUI restart)";
                m_adoptedNoProto = true;
                // AVPN (независимое ревью волны, MINOR-4): если демон держит xray, статистику
                // адоптированной сессии никто не поллит (m_lastUpProto пуст) — HealthLoop слеп.
                m_tunnel.adoptXrayIfRunning();
                onConnectionStateChanged(Vpn::Connected); // адопт внутри (BUG-6 ветка Connected)
            }
            sock->deleteLater();
            return;
        }
    });
    connect(sock, &QLocalSocket::errorOccurred, sock, [sock](QLocalSocket::LocalSocketError) {
        sock->deleteLater(); // демон не установлен/не поднят — штатно, адоптить нечего
    });
    guard->start(3000);
    sock->connectToServer(avpnDaemonSocketPath());
}

// AVPN (BUG-6): выключение адоптированного туннеля. Протокола нет (эту GUI-сессию не коннектили),
// m_tunnel.down() дойдёт до VpnConnection с null-протоколом (ноль-оп для демона) — гасим демона
// напрямую его же командой протокола. Иначе пользователь не может выключить VPN (зеркало §13a).
void AvpnEngineQml::daemonDirectDeactivate()
{
    auto *sock = new QLocalSocket(this);
    auto *guard = new QTimer(sock);
    guard->setSingleShot(true);
    connect(guard, &QTimer::timeout, sock, &QObject::deleteLater);
    connect(sock, &QLocalSocket::connected, sock, [sock]() {
        sock->write(QJsonDocument(QJsonObject{ { QStringLiteral("type"), QStringLiteral("deactivate") } })
                        .toJson(QJsonDocument::Compact));
        sock->write("\n");
        sock->flush();
        QTimer::singleShot(300, sock, &QObject::deleteLater); // байты ушли — сокет больше не нужен
    });
    connect(sock, &QLocalSocket::errorOccurred, sock, [sock](QLocalSocket::LocalSocketError) {
        sock->deleteLater();
    });
    guard->start(3000);
    sock->connectToServer(avpnDaemonSocketPath());
}
#endif

void AvpnEngineQml::guardedStop()
{
    ++m_verifyEpoch; // AVPN awg31-xray-v1: стоп отменяет верификацию xray (стейл-ответ выбросится)
    m_op = Op::Stopping;
    m_opInFlight = true;
    m_busy = true;
    // AVPN backend-first (final review MF-2): свежее значение сторожа на каждый взвод (см. guardedStart).
    // Пол связан с handshake-бюджетом (ConnectTunables.h): watchdog ВСЕГДА > handshake_timeout,
    // иначе сторож рвёт штатный медленный коннект (ревью 2026-07-11).
    m_watchdog.setInterval(avpn::reconcileWatchdogMsTuned());
    m_watchdog.start();
    m_healthTimer.stop();
    m_engine.requestStop();
    m_tunnel.down();
#if defined(Q_OS_MACOS) && !defined(MACOS_NE)
    // AVPN (BUG-6): туннель был адоптирован без протокола этой GUI-сессии — down() демона не
    // достигнет (null-протокол), гасим напрямую. Терминальный Disconnected приедет ретрансляцией
    // демона? Нет — соединения-слушателя тоже нет, поэтому полагаемся на m_tunnel.down()-путь
    // (null-протокол шлёт синхронный Disconnected) + факт деактивации демона этой командой.
    if (m_adoptedNoProto) {
        m_adoptedNoProto = false;
        daemonDirectDeactivate();
    }
#endif
    emit changed();
}

// AVPN: сторож reconcile — терминальный колбэк не пришёл за таймаут (iOS NE иногда «молчит» при
// teardown или connect завис). Разблокируем машину, чтобы не залипнуть навсегда.
void AvpnEngineQml::onWatchdog()
{
    if (!m_opInFlight)
        return;
    const Op finished = m_op;
    m_op = Op::None;
    m_opInFlight = false;
    m_busy = false;
    if (finished == Op::Stopping) {
        // teardown не отрапортовал чистым Disconnected → считаем опущенным, отложенный старт пойдёт.
        m_lastTunnelState = Vpn::Disconnected;
        emit changed();
        reconcile();
    } else if (finished == Op::Starting && m_lastTunnelState != Vpn::Connected) {
        // connect завис без терминала → принудительный teardown (→ Disconnected → reconcile ретрайнет
        // с учётом анти-зацикливания m_startAttempts, либо остановится, если попытки исчерпаны).
        ++m_startAttempts;
        m_healthTimer.stop();
        m_engine.requestStop();
        m_tunnel.down();
        // AVPN (белые списки): коннект не поднялся по watchdog — триггер раунда проб. Детектор
        // сам проверит гейты (Cellular + туннель опущен + дебаунс); teardown выше уже запущен.
        if (m_whitelistDetector)
            m_whitelistDetector->noteConnectFailure();
        emit changed();
    } else {
        emit changed();
        reconcile();
    }
}

void AvpnEngineQml::reprobe()
{
    // AVPN: re-pick авто-ноды через единый reconcile (не дёргаем m_engine.connect() напрямую — это
    // обходило бы стейт-машину и давало back-to-back up()). Снимаем pin; если онлайн — перевыбираем.
    m_engine.clearPin();
    const QString st = debugSnapshot().value(QStringLiteral("state")).toString();
    if (avpn::isTunnelUpStateName(st)) { // AVPN awg31-xray-v1: verifying = туннель поднят
        m_wantConnected = true;
        m_needsRestart = true;   // переподнять на свежевыбранной авто-ноде
        m_startAttempts = 0;
    }
    emit changed();
    reconcile();
}

void AvpnEngineQml::manualSwitch()
{
    if (m_engine.notifyConnectionLost())
        emit changed();
}

void AvpnEngineQml::resetLkg()
{
    Enrollment::clearToken(); // AVPN: SecureQSettings-backed
    emit changed();
}

// AVPN (Task 10 финал): setPinnedNode отдаёт ТЕХНИЧЕСКУЮ строку (английская, с nodeId/proto) —
// её место в логе, не в тосте. Человеческий текст — здесь, на границе фасада: маппим по
// стабильному префиксу движка; неизвестные причины сворачиваем в общий текст (детали в лог).
static QString humanPinError(const QString &technical)
{
    qWarning() << "avpn: setPinnedNode failed:" << technical;
    if (technical.startsWith(QLatin1String("unsupported_proto")))
        return AvpnEngineQml::tr("Сервер недоступен в этой версии приложения — обновите приложение");
    // AVPN awg31-xray-v1: ручной режим транспорта отфильтровал локацию/пул.
    if (technical.startsWith(QLatin1String("no_transport")))
        return AvpnEngineQml::tr("У этого сервера нет выбранного транспорта — переключите режим на «Авто»");
    return AvpnEngineQml::tr("Не удалось выбрать сервер — обновите список серверов");
}

// AVPN awg31-xray-v1: тот же маппер для ошибок connect() (guardedStart): стабильные префиксы движка
// → человеческий текст; всё прочее — как пришло (те же строки, что и раньше).
static QString humanEngineError(const QString &technical)
{
    if (technical.startsWith(QLatin1String("no_transport")))
        return AvpnEngineQml::tr("У этого сервера нет выбранного транспорта — переключите режим на «Авто»");
    if (technical.startsWith(QLatin1String("unsupported_proto")))
        return AvpnEngineQml::tr("Сервер недоступен в этой версии приложения — обновите приложение");
    return technical;
}

// AVPN (live-node picker): «Выбрать» сервер из шторки. Модель «выбор = задать цель, коннект —
// ВРУЧНУЮ кнопкой Connect» (по требованию пользователя): НЕ коннектим автоматически. setPinnedNode
// закрепляет узел; если сейчас онлайн — опускаем туннель (намерение «офлайн»), чтобы орб стал OFF и
// показал выбранную ноду. Пользователь подключается сам — это надёжный COLD-connect на закреплённую
// ноду (он не ловит iOS-гонку «старт поверх teardown», в отличие от авто-switch на подключённом).
// Шторка закрывается в QML (sheet.close()).
void AvpnEngineQml::switchToNode(const QString &nodeId)
{
    QString err;
    if (!m_engine.setPinnedNode(nodeId, err)) {
        emit error(humanPinError(err));
        return;
    }
    // Намерение: офлайн. Если онлайн — reconcile сделает guardedStop (орб OFF); офлайн — no-op.
    // Цель (pin) запомнена → следующий ручной Connect поднимет именно её.
    m_wantConnected = false;
    m_needsRestart = false;
    m_startAttempts = 0;
    reconcile();
    emit changed();
}

// AVPN (server picker, спека 2026-07-10): тап по стране на странице выбора = пин + мгновенный
// реконнект (решение пользователя; CONNECT-INVARIANTS §4 обновлён этой волной). Реконнект — ТОЛЬКО
// через reconcile с m_needsRestart (stop→Disconnected→start, тот же iOS-safe путь, что rotateNext);
// НИКОГДА прямой up() поверх teardown. Офлайн — только цель (cold-connect кнопкой Connect).
// Kill-switch: features.picker_instant_reconnect=false (/v1/config, operator-editable) откатывает
// на старую семантику switchToNode без релиза в стор (вкомпиленный фолбэк = true).
void AvpnEngineQml::pinAndReconnect(const QString &nodeId)
{
    if (!featureEnabled(QStringLiteral("picker_instant_reconnect"), true)) {
        switchToNode(nodeId);
        return;
    }
    QString err;
    if (!m_engine.setPinnedNode(nodeId, err)) {
        emit error(humanPinError(err));
        return;
    }
    const QString st = debugSnapshot().value(QStringLiteral("state")).toString();
    if (avpn::isTunnelUpStateName(st)) { // AVPN awg31-xray-v1: verifying = туннель поднят
        m_wantConnected = true;
        m_needsRestart = true;   // reconcile: stop→Disconnected→start на закреплённой ноде
        m_startAttempts = 0;
    } else {
        m_wantConnected = false; // офлайн: только цель, туннель не стартуем
        m_needsRestart = false;
        m_startAttempts = 0;
    }
    emit changed();
    reconcile();
}

// AVPN (live-node picker): «Авто (быстрейший)» в шторке — СИММЕТРИЧНО ручному выбору узла (switchToNode):
// снимаем закрепление И уводим намерение в OFF. Пользователь жал «Авто» на ПОДКЛЮЧЁННОМ узле (напр.
// Poland) и ждёт, что главный экран ВЫЙДЕТ из «подключено к Польше» в состояние «авто — можно подключиться»
// (а НЕ останется висеть на старом узле — это была жалоба). reconcile сделает чистый guardedStop (орб OFF);
// карточка станет «Умный выбор сервера», следующий РУЧНОЙ Connect поднимет быстрейший по скорингу/weight.
// Модель «выбор = задать цель, коннект — кнопкой»: НЕ реконнектим автоматически (без back-to-back up()).
void AvpnEngineQml::selectAuto()
{
    m_engine.clearPin();
    m_wantConnected = false;
    m_needsRestart = false;
    m_startAttempts = 0;
    reconcile();        // онлайн → guardedStop (орб OFF); оффлайн → no-op
    emit changed();
}

// AVPN (live-node picker): кнопка «Обновить подключение» — round-robin на следующую живую ноду через
// единый reconcile (не дёргаем m_engine.rotateNext() напрямую — он имел свой контур свитча, конфликтуя
// с reconcile). Берём следующую живую ноду (чистый nextLiveNodeId, без side-effects), закрепляем как
// цель и просим переключиться: reconcile сделает stop→Disconnected→start на ней (iOS-safe).
void AvpnEngineQml::rotateNext()
{
    const QString next = m_engine.nextLiveNodeId();
    if (next.isEmpty()) {
        emit error(tr("Недостаточно живых серверов для переключения"));
        return;
    }
    QString err;
    if (!m_engine.setPinnedNode(next, err)) {
        emit error(humanPinError(err));
        return;
    }
    m_wantConnected = true;
    m_needsRestart = true;
    m_startAttempts = 0;
    emit changed();
    reconcile();
}

// ---- AVPN awg31-xray-v1 (спека 2026-09-01 §2.3): транспорты, verifying, история, reseed ----------

QString AvpnEngineQml::transportMode() const
{
    return avpn::transportModeToString(m_engine.transportMode());
}

bool AvpnEngineQml::verifying() const
{
    return m_engine.isVerifying();
}

QString AvpnEngineQml::activeProto() const
{
    return m_engine.currentNodeProto();
}

void AvpnEngineQml::setTransportMode(const QString &mode)
{
    const avpn::TransportMode m = avpn::transportModeFromString(mode);
    if (m == avpn::TransportMode::Xray && !avpn::isSupportedProto(QStringLiteral("xray"))) {
        // Платформа/kill-switch xray_client: режим честно отклоняем, настройку не портим.
        emit error(tr("Xray недоступен в этой версии приложения"));
        return;
    }
    if (m == m_engine.transportMode())
        return;
    m_engine.setTransportMode(m);
    QSettings s;
    s.setValue(QStringLiteral("avpn/transportMode"), avpn::transportModeToString(m));
    s.sync();
    // Поднятый/поднимающийся туннель на транспорте, который новому режиму не соответствует, —
    // переподнять ЧЕРЕЗ reconcile+m_needsRestart (stop→Disconnected→start), никогда прямой up()
    // поверх teardown (CONNECT-INVARIANTS §2/§4). Авто: текущий транспорт всегда допустим — не трогаем.
    const QString st = debugSnapshot().value(QStringLiteral("state")).toString();
    const bool up = avpn::isTunnelUpStateName(st);
    const QString cur = m_engine.currentNodeProto();
    const bool mismatch = (m == avpn::TransportMode::Awg && avpn::isXrayProto(cur))
                          || (m == avpn::TransportMode::Xray && !cur.isEmpty() && !avpn::isXrayProto(cur));
    if (up && mismatch) {
        m_wantConnected = true;
        m_needsRestart = true;
        m_startAttempts = 0;
        reconcile();
    }
    emit changed();
}

void AvpnEngineQml::persistTransportHistory()
{
    if (!m_engine.transportHistoryDirty())
        return;
    QSettings s;
    s.setValue(QStringLiteral("avpn/transportHistory"), m_engine.transportHistoryJson());
    m_engine.clearTransportHistoryDirty();
}

// Побочные эффекты реального «Подключено» — единая точка для awg (Vpn::Connected) и xray (после verify).
void AvpnEngineQml::onTunnelUpEffects()
{
    // AVPN awg31-xray-v1: исход подъёма в локальную историю транспорта (время до реального трафика);
    // xray уже записал движок в verifySucceeded (повтор — no-op).
    m_engine.recordTransportOutcome(true);
    persistTransportHistory();
    // AVPN (Task 9): контекстный запрос разрешения на пуши — в момент очевидной ценности (VPN
    // поднялся), а не на холодном старте. Один раз за установку (persist). Мост дёрнет натив
    // (UNUserNotificationCenter + registerForRemoteNotifications); на desktop — no-op.
    if (!m_pushPermissionAsked) {
        m_pushPermissionAsked = true;
        QSettings().setValue(QStringLiteral("AvpnPush/permissionAsked"), true);
        avpn::AvpnPushBridge::instance()->requestAuthorization();
    }
    // AVPN (Task 9): к моменту Connected subscription_token уже создан (start/bootstrap → enroll).
    // Если device token пришёл из APNs ДО enroll, registerPushToken его отложил (authToken был пуст) —
    // флашим здесь. Дедуп по fingerprint пропустит повтор, если токен уже отправлен (redeem/bootstrap).
    flushPendingPushToken();
    // AVPN: чипы доступности + скорость после поднятия. Чипы youtube/instagram теперь GOODPUT (качают
    // ~128 КБ каждый) — дороже по трафику и дольше (до ~20с при троттле), поэтому ОДНА проба за коннект
    // (~1.5с — DNS/маршруты через свежий туннель уже осели; раньше давало HostNotFound → ложный «заблок»).
    // Дальше — только по тапу «перепроверить» (см. UI), НЕ поллинг: goodput каждые N секунд = лишний трафик.
    // Скорость (RTT-палочки) — через ~1.8с, дальше по каденсу onTick (4с, лёгкий generate_204).
    // AVPN BUG-13 (2026-07-30): на входе в connected обнуляем чипы в «не проверено» (синий).
    // Раньше вердикты прошлой сессии оставались висеть (помеченные stale, но ТОГО ЖЕ цвета),
    // и после подключения пользователь видел красные бейджи живых сервисов, пока не дойдёт
    // первая проба — жалоба «включаю VPN, все бейджи красные, через полминуты зеленеют».
    // Нейтральный синий честен: проверка ещё не проводилась. На транзиентах (обрыв без нового
    // connected) поведение прежнее — stale-приглушение, чипы не мигают.
    resetServiceChipsToUnknown();
    QTimer::singleShot(1500, this, &AvpnEngineQml::probeServices);
    QTimer::singleShot(1800, this, [this]() {
        if (m_probe && avpn::TuningStore::flag(QStringLiteral("live_rtt"))
            && state() == QLatin1String("connected"))
            m_probe->measure();
    });
}

// Фаза Verifying (xray): «Подключено» — только после DNS+HTTPS через туннель (инвариант волны §4.3).
void AvpnEngineQml::startXrayVerification()
{
    const int epoch = ++m_verifyEpoch;
    m_verifyClock.start();
    m_verifyAttempts = 0;
    m_lastVerifyRxProof = false;
    m_busy = true;
    qInfo() << "[avpn xray] tunnel up on" << m_engine.currentNodeId() << "— verifying data-plane";
    // Маршруты/DNS через свежий tun2socks оседают не мгновенно — первая попытка чуть отложенно.
    QTimer::singleShot(800, this, [this, epoch]() { verifyAttempt(epoch); });
}

void AvpnEngineQml::verifyAttempt(int epoch)
{
    if (epoch != m_verifyEpoch || !m_engine.isVerifying() || m_lastTunnelState != Vpn::Connected)
        return; // состояние уехало (стоп/обрыв/смена) — серия отменена
    const int budget = avpn::xrayVerifyTimeoutMsTuned();
    const qint64 elapsed = m_verifyClock.elapsed();
    if (elapsed >= budget) {
        finishVerify(epoch, false);
        return;
    }
    ++m_verifyAttempts;
    // Та же цель, что у живых палочек (urls.quality_probe_url, фолбэк generate_204). HEAD, без кэша.
    // Async + transferTimeout — никакого nested QEventLoop (§1).
    QNetworkRequest req{QUrl(configUrl(QStringLiteral("quality_probe_url"),
                                       QStringLiteral("https://connectivitycheck.gstatic.com/generate_204")))};
    req.setAttribute(QNetworkRequest::CacheLoadControlAttribute, QNetworkRequest::AlwaysNetwork);
    const qint64 remaining = budget - elapsed;
    req.setTransferTimeout(int(remaining < 1500 ? 1500 : (remaining > 4000 ? 4000 : remaining)));
    QNetworkReply *r = m_nam->head(req);
    connect(r, &QNetworkReply::finished, this, [this, r, epoch]() {
        r->deleteLater();
        if (epoch != m_verifyEpoch || !m_engine.isVerifying())
            return;
        const int code = r->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        const bool ok = (r->error() == QNetworkReply::NoError && (code == 204 || code == 200));
        // AVPN (независимое ревью волны, MAJOR-3; инвариант §22.5): 204/200 доказывает ИНТЕРНЕТ,
        // а не туннель — если tun2socks/маршруты не встали, проба ушла НАПРЯМУЮ мимо xray. Второе
        // условие — реальный rx через туннель (счётчики уже поллятся: macOS — IPC xrayRuntimeStatus,
        // iOS — bytesChanged NE). rx==0 при живом источнике = «доказательства ещё нет» (§17.1:
        // 0 = неизвестно) → ждём следующей попытки; источника нет вовсе → принимаем с оговоркой.
        const avpn::TunnelStats st = m_tunnel.readStats();
        switch (avpn::verifyStepFor(ok, st.valid, st.rxBytes)) {
        case avpn::VerifyStep::Confirmed:
            m_lastVerifyRxProof = true;
            finishVerify(epoch, true);
            return;
        case avpn::VerifyStep::AcceptedWithoutStats:
            qWarning() << "[avpn xray] probe ok, but tunnel stats are unavailable — accepting without rx proof";
            m_lastVerifyRxProof = false;
            finishVerify(epoch, true);
            return;
        case avpn::VerifyStep::KeepTrying:
            break;
        }
        if (m_verifyClock.elapsed() >= avpn::xrayVerifyTimeoutMsTuned()) {
            finishVerify(epoch, false);
            return;
        }
        QTimer::singleShot(1200, this, [this, epoch]() { verifyAttempt(epoch); });
    });
}

void AvpnEngineQml::finishVerify(int epoch, bool ok)
{
    if (epoch != m_verifyEpoch || !m_engine.isVerifying())
        return;
    m_lastVerifyMs = m_verifyClock.elapsed();
    m_lastVerifyOk = ok ? 1 : 0;
    if (ok) {
        qInfo() << "[avpn xray] data-plane verified in" << m_lastVerifyMs << "ms, attempts"
                << m_verifyAttempts << "rx-proof" << m_lastVerifyRxProof;
        m_engine.verifySucceeded();
        m_busy = false;
        onTunnelUpEffects();
        emit changed();
        return;
    }
    qWarning() << "[avpn xray] data-plane NOT verified after" << m_lastVerifyMs << "ms — failover";
    // Движок: история (провал) + другой транспорт той же локации через двухфазный свитч
    // (down → Disconnected → up), потом соседняя локация; кандидатов нет → Error при поднятом
    // туннеле — гасим честно через reconcile (намерение OFF), как внешний провал.
    m_engine.verifyFailed();
    persistTransportHistory();
    // AVPN (независимое ревью волны, MAJOR-1): исчерпан кап подряд идущих провалов data-plane —
    // отдельный текст (дело не в конкретном сервере, а в сети/ТСПУ), намерение снимается там же.
    if (!surrenderIfDataPlaneDead() && m_engine.state() == avpn::EngineState::Error) {
        emit error(tr("Сервер не пропускает трафик — попробуйте другой сервер"));
        m_wantConnected = false;
        m_needsRestart = false;
    }
    m_busy = m_engine.state() == avpn::EngineState::Switching;
    emit changed();
    QTimer::singleShot(0, this, [this]() { reconcile(); });
}

// AVPN (независимое ревью волны, MAJOR-1): движок сдался — data-plane мёртв на всех перепробованных
// узлах подряд (captive portal, ТСПУ, сеть без интернета). До этой правки цикл up → verifying →
// verifyFailed → down → up крутился вечно, и пользователь не видел ни ошибки, ни причины. Теперь:
// честный текст + снятие намерения (§13 — поднимает туннель только пользователь) + гашение через
// reconcile (§2, монополия на туннель). Идемпотентно: requestStop() внутри guardedStop() обнуляет
// счётчик, так что второй раз ветка не сработает.
bool AvpnEngineQml::surrenderIfDataPlaneDead()
{
    if (!m_engine.dataPlaneExhausted() || m_engine.state() != avpn::EngineState::Error)
        return false;
    if (!m_wantConnected)
        return false; // намерение уже снято (стоп/пауза) — гасить и жаловаться нечего
    qWarning() << "[avpn] data-plane dead on every candidate — giving up (streak"
               << m_engine.dataPlaneFailStreak() << ")";
    emit error(tr("Трафик не проходит ни через один сервер — проверьте сеть и попробуйте снова"));
    m_wantConnected = false;
    m_needsRestart = false;
    m_busy = false;
    emit changed();
    QTimer::singleShot(0, this, [this]() { reconcile(); });
    return true;
}

// Reseed пула по pool_revision (см. refreshSubscription). Вызывается ТОЛЬКО с верха цикла событий.
void AvpnEngineQml::applyReseed(const avpn::Subscription &sub)
{
    if (m_inSyncNetCall) {
        // Внутри вложенного QEventLoop sync-вызова (redeem/startFlow → Selector::pick) — ещё раз позже.
        QTimer::singleShot(50, this, [this, sub]() { applyReseed(sub); });
        return;
    }
    if (!featureEnabled(QStringLiteral("subscription_reseed_pool"), false))
        return; // kill-switch мог флипнуться, пока ждали
    const avpn::ReseedResult r = m_engine.reseedPool(sub);
    switch (r) {
    case avpn::ReseedResult::Applied: {
        // RTT-кэш фасада синхронизируем с движком (исчезнувшие узлы обрезаны там).
        m_nodeRtt = m_engine.measuredRtt();
        qInfo() << "[avpn reseed] pool revision" << m_engine.poolRevision() << "applied";
        emit changed();     // nodePool/currentNode пересчитаются (пикер, карточка)
        probeNodeRtt();     // новые узлы без замера — тёплый off-tunnel RTT (no-op при поднятом туннеле)
        break;
    }
    case avpn::ReseedResult::Deferred:
        qInfo() << "[avpn reseed] pool revision" << sub.poolRevision << "deferred until terminal";
        break;
    case avpn::ReseedResult::Rejected:
        break;
    }
}

void AvpnEngineQml::applyPendingReseed()
{
    if (m_inSyncNetCall) {
        QTimer::singleShot(50, this, [this]() { applyPendingReseed(); });
        return;
    }
    if (!m_engine.hasPendingReseed())
        return;
    if (!m_engine.applyPendingReseed())
        return; // не терминал (уже снова поднимаемся) — применим на следующем терминале
    m_nodeRtt = m_engine.measuredRtt();
    qInfo() << "[avpn reseed] pending pool revision" << m_engine.poolRevision() << "applied";
    emit changed();
    probeNodeRtt();
}

// AVPN (live-node picker): пере-зачитать подписку/health и обновить nodePool. Тихий no-op при провале
// (оффлайн/нет токена) — как bootstrap, не пугаем пользователя ошибкой при простом обновлении списка.
void AvpnEngineQml::refreshPool()
{
    QString err;
    if (m_engine.bootstrap(m_nam, m_baseUrl, m_store, err)) {
        emit changed(); // nodePool/health обновлены → шторка перерисуется
        probeNodeRtt(); // AVPN (выбор по скорости): тёплый прямой замер RTT (no-op при connected)
    }
    // при провале — тихо (silent fail)
}

// AVPN (Task C): вход/восстановление по коду доступа (POST /v1/code/redeem). Синхронно (как enroll).
void AvpnEngineQml::redeemCode(const QString &code, const QString &evictDeviceId)
{
    if (m_busy)
        return;
    const QString trimmed = code.trimmed();
    if (trimmed.isEmpty()) {
        emit error(tr("Введите код доступа"));
        return;
    }

    m_busy = true;
    emit changed();

    avpn::CodeRedeemResponse resp;
    QVariantList devices;
    QString err;
    const avpn::CodeRedeemResult res =
        Enrollment::redeemCode(m_nam, m_baseUrl, m_engine.identity(), m_store,
                               trimmed, evictDeviceId, resp, devices, err);

    m_busy = false;

    switch (res) {
    case avpn::CodeRedeemResult::Ok:
        // РОТАЦИЯ токена уже сделана внутри Enrollment::redeemCode (saveToken). Перечитываем подписку
        // под НОВЫМ токеном — напрямую через движок (QML-фасадный bootstrap() идемпотентен и не сработал
        // бы повторно). Провал re-fetch не критичен: лимиты подтянутся при следующем bootstrap/start.
        m_engine.bootstrap(m_nam, m_baseUrl, m_store, err);
        // AVPN (Task 9): subscription_token ротирован → старый push token на сервере отвязан.
        // Пере-регистрируем известный device token под новым токеном (fingerprint сменился → не дедупнется).
        if (!m_pushToken.isEmpty())
            registerPushToken(m_pushToken, m_pushEnv);
        emit changed(); // daysLeft/traffic*/subActive/nodePool/authToken обновятся
        break;
    case avpn::CodeRedeemResult::BadCode:
        emit error(tr("Неверный код доступа"));
        emit changed();
        break;
    case avpn::CodeRedeemResult::SeatLimit:
        // Мест нет — UI покажет devices[] для выбора кого отключить (повторный redeemCode с evictDeviceId
        // или DELETE /v1/devices/{id}). Не пишем error(), чтобы не дублировать модалкой выбора.
        emit seatLimitReached(devices);
        emit changed();
        break;
    case avpn::CodeRedeemResult::FingerprintMismatch:
        // Rehome-гейт (403): не error() — QML показывает специальное сообщение + кнопку в поддержку.
        emit fingerprintMismatch();
        emit changed();
        break;
    case avpn::CodeRedeemResult::Failed:
    default:
        emit error(err.isEmpty() ? tr("Не удалось активировать код") : err);
        emit changed();
        break;
    }
}

// AVPN (Task 13): принять перенос «как SIM» (POST /v1/transfer/redeem). Зовётся мостом диплинка
// (AvpnDeepLinkBridge) по tribe://transfer?t=… . Синхронно (как redeemCode).
void AvpnEngineQml::redeemTransfer(const QString &transferToken)
{
    // AVPN backend-first-3 (Task 6): kill-switch (features.transfer, default TRUE) — единая
    // воронка для deep-link/Universal Link/QR-скан/ввод в поле (все сходятся сюда через
    // AvpnDeepLinkBridge → coreController). Бэкенд может погасить перенос без релиза.
    if (!avpn::TuningStore::flag(QStringLiteral("transfer"))) {
        emit error(tr("Перенос временно недоступен"));
        return;
    }
    const QString trimmed = transferToken.trimmed();
    if (trimmed.isEmpty()) {
        emit error(tr("Пустая ссылка переноса"));
        return;
    }
    // Дедуп: iOS-сканер может отдать один QR несколько раз подряд (эмит на каждый кадр), плюс
    // возможен дубль скана/ссылки руками. Повторный redeem УЖЕ принятого токена дал бы 401 →
    // тост «Ссылка недействительна» ПОВЕРХ экрана успеха. Токен одноразовый — второй заход глушим.
    if (!m_lastRedeemedToken.isEmpty() && trimmed == m_lastRedeemedToken)
        return;
    if (m_busy) {
        // Холодный старт по диплинку: движок ещё занят bootstrap'ом. Раньше токен МОЛЧА терялся
        // («приложение открылось, а подписка не поменялась») — откладываем и ретраим до ~15 с.
        if (m_pendingRedeemToken == trimmed)
            return; // ретрай этого токена уже запланирован — второй таймер не плодим
        if (m_pendingRedeemAttempts < 20) {
            ++m_pendingRedeemAttempts;
            m_pendingRedeemToken = trimmed;
            QTimer::singleShot(750, this, [this, trimmed]() {
                m_pendingRedeemToken.clear();
                redeemTransfer(trimmed);
            });
        } else {
            m_pendingRedeemAttempts = 0;
            emit error(tr("Не удалось принять перенос — откройте ссылку ещё раз"));
        }
        return;
    }
    m_pendingRedeemAttempts = 0;

    m_busy = true;
    emit changed();

    avpn::TransferRedeemResponse resp;
    QString err;
    const avpn::TransferRedeemResult res =
        Enrollment::redeemTransfer(m_nam, m_baseUrl, m_engine.identity(), m_store,
                                   trimmed, resp, err);

    m_busy = false;

    switch (res) {
    case avpn::TransferRedeemResult::Ok:
        m_lastRedeemedToken = trimmed; // дедуп повторных сканов того же QR (см. вход)
        // РОТАЦИЯ токена уже сделана внутри Enrollment::redeemTransfer (saveToken). Перечитываем
        // подписку под НОВЫМ токеном напрямую через движок (QML-фасадный bootstrap() идемпотентен).
        m_engine.bootstrap(m_nam, m_baseUrl, m_store, err);
        // AVPN (Task 9): токен ротирован переносом → пере-регистрируем push token под новым.
        if (!m_pushToken.isEmpty())
            registerPushToken(m_pushToken, m_pushEnv);
        emit transferRedeemed();
        emit changed(); // daysLeft/traffic*/subActive/nodePool/authToken обновятся
        break;
    case avpn::TransferRedeemResult::BadToken:
        emit error(tr("Ссылка переноса недействительна или истекла"));
        emit changed();
        break;
    case avpn::TransferRedeemResult::FingerprintMismatch:
        // Rehome-гейт (403): специальный UX (не error) — см. onFingerprintMismatch в QML.
        emit fingerprintMismatch();
        emit changed();
        break;
    case avpn::TransferRedeemResult::SeatLimit:
        emit error(tr("Достигнут лимит устройств"));
        emit changed();
        break;
    case avpn::TransferRedeemResult::Failed:
    default:
        emit error(err.isEmpty() ? tr("Не удалось принять перенос") : err);
        emit changed();
        break;
    }
}

// AVPN (Task 13): выпустить перенос с ЭТОГО устройства (POST /v1/transfer, Bearer authToken).
// 401 лечим как fetchSubscription (decideAuthRecovery): один ре-энролл + ретрай — раньше
// стейл-JWT давал сырую ошибку «transfer unauthorized (token)» до перезапуска приложения.
// 410 (после переноса) — законное терминальное состояние: взводим transferredAway, не ошибку.
QVariantMap AvpnEngineQml::createTransfer()
{
    QVariantMap result;
    // AVPN backend-first-3 (Task 6): kill-switch (features.transfer, default TRUE) — симметрично
    // redeemTransfer. Пустая мапа + тост, QML createTransfer() уже трактует пустой deep_link как
    // «onError уже показал тост» (см. PageAccountTribe.qml).
    if (!avpn::TuningStore::flag(QStringLiteral("transfer"))) {
        emit error(tr("Перенос временно недоступен"));
        return result;
    }
    if (m_busy)
        return result;

    m_busy = true;
    emit changed();

    avpn::TransferMintResponse resp;
    QString err;
    avpn::FetchOutcome outcome = avpn::FetchOutcome::NetworkError;
    bool ok = Enrollment::createTransfer(m_nam, m_baseUrl, authToken(), resp, err, &outcome);

    if (!ok
        && Enrollment::decideAuthRecovery(outcome, /*tokenFromStore*/ true, /*alreadyReEnrolled*/ false)
                   == avpn::AuthRecoveryAction::ReEnrollThenRetry) {
        // БЕЗ clearToken: enroll при успехе сам перезапишет токен (saveToken), а при провале
        // (сеть/429) старый токен обязан ОСТАТЬСЯ — иначе после рестарта устройство в лимбе
        // (пустой токен → refreshSubscription молчит → даже 410 «перенесено» не доедет до UI).
        avpn::TrialResponse trial;
        QString enrollErr;
        avpn::FetchOutcome enrollOutcome = avpn::FetchOutcome::NetworkError;
        if (Enrollment::enroll(m_nam, m_baseUrl, m_engine.identity(), m_store, trial, enrollErr,
                               &enrollOutcome)) {
            // device_id идемпотентен на бэке: ре-энролл вернул токен ТОГО ЖЕ аккаунта — ретраим минт.
            ok = Enrollment::createTransfer(m_nam, m_baseUrl, authToken(), resp, err, &outcome);
        } else if (enrollOutcome == avpn::FetchOutcome::Transferred) {
            outcome = avpn::FetchOutcome::Transferred; // перенесённому устройству триал не положен
        }
    }

    m_busy = false;

    if (!ok && outcome == avpn::FetchOutcome::Transferred) {
        if (!m_transferredAway) m_transferredAway = true;
        emit changed(); // UI покажет состояние «Подписка перенесена» вместо тоста ошибки
        return result;
    }
    emit changed();

    if (!ok) {
        emit error(err.isEmpty() ? tr("Не удалось создать перенос") : err);
        return result;
    }
    result.insert(QStringLiteral("transfer_token"), resp.transferToken);
    result.insert(QStringLiteral("deep_link"), resp.deepLink);
    // опциональные (бэк по TRANSFER-KEYS-BACKEND-HANDOFF; пусто/0 пока не докатил)
    result.insert(QStringLiteral("web_link"), resp.webLink);
    result.insert(QStringLiteral("expires_in_s"), resp.expiresInS);
    return result;
}

// AVPN (grant-ключи): активация TRIBE-XXXX-XXXX-XXXX (промо/подарок/компенсация) на текущий аккаунт.
// Токен НЕ ротируется; успех = мапа с начислением, UI показывает «+N дней». Бэк — по handoff §3.B2.
QVariantMap AvpnEngineQml::redeemGrantKey(const QString &key)
{
    QVariantMap result;
    if (m_busy)
        return result;

    m_busy = true;
    emit changed();

    avpn::GrantKeyResponse resp;
    QString err;
    const auto res = Enrollment::redeemGrantKey(m_nam, m_baseUrl, authToken(), key, resp, err);

    m_busy = false;
    emit changed();

    if (res != GrantKeyResult::Ok) {
        QString msg;
        switch (res) {
        case GrantKeyResult::NotFound:    msg = tr("Ключ не найден — проверьте ввод"); break;
        case GrantKeyResult::AlreadyUsed: msg = tr("Этот ключ уже использован"); break;
        case GrantKeyResult::Expired:     msg = tr("Ключ истёк или отозван"); break;
        default: msg = err.isEmpty() ? tr("Не удалось активировать ключ") : err; break;
        }
        emit error(msg);
        return result;
    }

    result.insert(QStringLiteral("granted_days"), resp.grantedDays);
    result.insert(QStringLiteral("granted_gib"), resp.grantedGib);
    result.insert(QStringLiteral("plan"), resp.plan);
    result.insert(QStringLiteral("new_expiry"), resp.newExpiry);
    refreshSubscription(); // async данные-only: шапка (дни/ГБ) обновится, туннель не трогаем
    return result;
}

// AVPN: системный share sheet для текста/ссылки — см. AvpnShareBridge (iOS/Android), desktop → false.
bool AvpnEngineQml::shareText(const QString &text) const
{
    return AvpnShare::shareText(text);
}

// AVPN: share ссылки ВМЕСТЕ с QR-картинкой (перенос подписки: получатель может тапнуть ссылку
// ИЛИ отсканировать картинку с другого экрана). Рендерим qrcodegen-матрицу в PNG (12 px/модуль,
// quiet zone 4 модуля — читается камерой с запасом) в files-dir — на Android его покрывает
// FileProvider qtprovider (см. AvpnShareBridge). false → QML-fallback (shareText → копирование).
bool AvpnEngineQml::shareTextWithQr(const QString &text, const QString &qrPayload) const
{
    if (qrPayload.isEmpty())
        return AvpnShare::shareText(text);
    try {
        const qrcodegen::QrCode qr = qrcodegen::QrCode::encodeText(qrPayload.toUtf8().constData(),
                                                                   qrcodegen::QrCode::Ecc::MEDIUM);
        constexpr int kScale = 12, kBorder = 4;
        const int size = (qr.getSize() + 2 * kBorder) * kScale;
        QImage img(size, size, QImage::Format_RGB32);
        img.fill(Qt::white);
        for (int y = 0; y < qr.getSize(); ++y)
            for (int x = 0; x < qr.getSize(); ++x)
                if (qr.getModule(x, y))
                    for (int dy = 0; dy < kScale; ++dy)
                        for (int dx = 0; dx < kScale; ++dx)
                            img.setPixel((x + kBorder) * kScale + dx, (y + kBorder) * kScale + dy,
                                         qRgb(0, 0, 0));

        const QString dir = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
        QDir().mkpath(dir);
        const QString path = dir + QStringLiteral("/tribe-transfer-qr.png");
        if (!img.save(path, "PNG"))
            return AvpnShare::shareText(text);
        return AvpnShare::shareTextWithImage(text, path);
    } catch (...) {
        return AvpnShare::shareText(text); // payload не влез в QR — хотя бы ссылка
    }
}

// AVPN: QR для ссылки переноса — СЫРАЯ строка в QR (НЕ generateQrCodeImageSeries: тот заворачивает
// в амнезиевский чанк-конверт magic+base64 для импорта конфигов — системная камера его не поймёт).
// border=2 модуля — quiet zone для считывания. Data-URI SVG (чёрный на белом) для Image.source.
QString AvpnEngineQml::makeQrCode(const QString &text) const
{
    if (text.isEmpty())
        return QString();
    try {
        const qrcodegen::QrCode qr = qrcodegen::QrCode::encodeText(text.toUtf8().constData(),
                                                                   qrcodegen::QrCode::Ecc::MEDIUM);
        return qrCodeUtils::svgToBase64(QString::fromStdString(qrcodegen::toSvgString(qr, 2)));
    } catch (...) {
        return QString(); // слишком длинно/не влезло — QML покажет плейсхолдер
    }
}

// AVPN (Task 7): тумблер #6 — читаем из ТОГО ЖЕ стора, что QML Settings{category:"AvpnSettings"}.
// QtCore.Settings без своего fileName использует default-конструируемый QSettings (org/app из
// QCoreApplication, выставленные ORGANIZATION_NAME/APPLICATION_NAME в main.cpp) → ключ совпадает.
bool AvpnEngineQml::autoPauseEnabled() const
{
    QSettings s; // org/app берутся из QCoreApplication (как у QML Settings)
    // Дефолт true — совпадает с `property bool autoPauseRu: true` в PageAccountTribe.qml.
    return s.value(QStringLiteral("AvpnSettings/autoPauseRu"), true).toBool();
}

// AVPN RU-direct: сев split-tunnel под единый тумблер «Доступ к сайтам РФ» (AvpnBypass/masterOn, default
// ON). Зовётся из guardedStart ПЕРЕД коннектом → конфиг готов к appendSplitTunnelingConfig. Сеет ВЕСЬ рунет
// CIDR в режим VpnAllExceptSites → рунет мимо туннеля (реальный РФ-IP). Домены отсекает сам движок,
// потому кормим ТОЛЬКО CIDR из ru_prefixes.h: v4 проходит checkIpSubnetFormat везде; v6 — isIpv6Cidr
// на iOS/Android (десктоп-демон v6-сплит не умеет, там v6 отсеется — см. appendSplitTunnelingConfig).
// Пустой список движок сам роняет в VpnAllSites (защита от блэкхола). Сев = РЕКОНСИЛЯЦИЯ
// (replaceVpnSites, полная замена): merge-only addVpnSites копил стейл-CIDR прошлых регенераций
// ru_prefixes навсегда (аудит; инвариант №3 vpn-bypass/README «apply = реконсиляция»). Список
// полностью наш — ручные сайты amnezia-UI затираются осознанно (в Tribe-навигации экрана нет).
// Кросс-платформенно (iOS excludeRoutes / Android excludeRoute / macOS десктоп-маршруты).
// OFF → активное ВЫКЛ флага.
void AvpnEngineQml::applyRuBypassSplit()
{
    if (!m_store)
        return;
    // AVPN win-note (2026-07-07): Windows-путь сева (router_win.cpp routeAddList) доведён до
    // инварианта «apply = реконсиляция»: идемпотентный посев + persist на диск + уборка сирот на
    // старте сервиса + дебаунс RouteMonitor (инцидент: 8646 маршрутов-сирот после краша сервиса).
    using amnezia::RouteMode;
    QSettings s;
    const bool masterOn = s.value(QStringLiteral("AvpnBypass/masterOn"), true).toBool();
    // AVPN (китайские сервисы, 2026-07-03): второй независимый тумблер «Li Auto» (default ВКЛ). Оба тумблера
    // сеют в один и тот же split-набор (RouteMode::VpnAllExceptSites) — оси не конфликтуют, список объединяется.
    const bool liAutoOn = s.value(QStringLiteral("AvpnBypass/liAutoOn"), true).toBool();
    // AVPN server-driven АнтиВПН (Task 10): списки с /v1/bypass-lists (подпись+LKG); вкомпиленные
    // массивы ниже — фолбэк (офлайн/первый запуск/kill-switch). Kill-switch remote_bypass_lists
    // гасится ВНУТРИ BypassListService (пустой invalid снапшот) ⇒ здесь достаточно bl.valid.
    const avpn::BypassLists bl = avpn::BypassListStore::get();
    const bool useRemote = bl.valid;
    // AVPN (T2, аудит 2026-07-02): здесь — только СЕВ списка (и активное ВЫКЛ, если ОБА тумблера OFF,
    // иначе прежний seed продолжил бы исключать трафик). Вкл/выкл сплита под РФ-ноду решается ПО
    // ФАКТИЧЕСКОЙ ноде в VpnConnectionTunnelControl::up() (покрывает failover/авто-RU-fallback/мёртвый
    // RU-pin — прежний гейт по pinnedNodeIsRu() тут расходился с реальностью, когда нода ≠ pin).
    if (!masterOn && !liAutoOn) {
        m_store->setSitesSplitTunnelingEnabled(false);
        // Страховка (ревью A5): пока сплит выключен, стор могли мутировать в обход этой функции —
        // сбрасываем стамп, чтобы ре-ВКЛ гарантированно пересеял (цена — один сев на переключение).
        m_lastBypassSeedStamp.clear();
        return;
    }
    m_store->setRouteMode(RouteMode::VpnAllExceptSites);
    m_store->setSitesSplitTunnelingEnabled(true);
    // AVPN (тормоза коннекта, 2026-07-10): сев ~10801 CIDR (QMap + carve по всем ключам + полная
    // запись в QSettings/plist) на GUI-потоке — на КАЖДОМ guardedStart/реконнекте/failover, при
    // неизменных входах (список обновляется раз в 6ч, тумблеры — руками). Стамп входов
    // (BypassSeedStamp.h, покрыт bypass_seed_check) совпал с прошлым севом этого процесса →
    // содержимое sites в сторе уже ровно такое → пропускаем сев целиком. Смена тумблера/версии
    // списка/carve-IP (async-резолв edge) меняет стамп → честный пересев. Стамп живёт только в
    // памяти процесса — первый сев после запуска всегда выполняется (стор мог меняться извне).
    // Оба-OFF выше чистят стамп (страховка от мутаций стора при выключенном сплите) — ре-ВКЛ
    // всегда пересеет. Carve-IP — из apiCarveIps(), ЕДИНОГО источника с rebuildApiCarveOut.
    const QString seedStamp =
            avpn::bypassSeedStamp(masterOn, liAutoOn, useRemote, bl.version, apiCarveIps());
    if (seedStamp == m_lastBypassSeedStamp) {
        qInfo("[AVPN bypass] seed unchanged — skip (v=%d)", useRemote ? bl.version : -1);
        return;
    }
    QMap<QString, QStringList> sites; // AVPN: формат значений апстрима f73697d3 (QStringList IP), CIDR = единственный элемент
    // AVPN Task 10 (per-group fallback): та же политика, что у парсера split_dns — "пусто =
    // нет override". Сервер может курировать любую из групп (ru_cidrs/bypass_extra/cn_liauto),
    // но если конкретная группа в валидном снапшоте пуста, это НЕ значит "выключить группу" —
    // это значит "сервер её не переопределяет", и группа падает на вкомпиленный дефолт. Раньше
    // useRemote гасил bypassExtra/liAuto целиком одним пустым полем на сервере (даже при живом
    // вкомпиленном фолбэке) — Госуслуги-carve и LiAuto молча исчезали. usedRemote* ниже — per-group
    // источник для лога (см. qInfo в конце функции).
    bool usedRemoteRu = false, usedRemoteExtra = false, usedRemoteLiAuto = false;
    if (masterOn) {
        // AVPN Task 10: рунет CIDR — серверный (bl.ruCidrs) при валидном снапшоте, иначе вкомпиленный.
        usedRemoteRu = useRemote;
        const QStringList ru = useRemote ? bl.ruCidrs : avpn::ruPrefixes();
        for (const QString &cidr : ru)
            sites.insert(cidr, {cidr});   // key=CIDR (checkIpSubnetFormat пройдёт), value=[CIDR]

        // AVPN RU-direct: foreign-эндпоинты, которые РФ-приложения дёргают для гео/анти-фрод проверок и которые
        // ПАЛЯТ загран-IP → гоним их тоже direct (residential РФ-IP), иначе приложение видит «VPN». Найдено
        // ЗАХВАТОМ (rvi0/PKTAP, 2026-07-01): процесс Gosuslugi через туннель ходит ТОЛЬКО в эти два, оба отвечают
        // (видят наш выход). Узкие /24 — не весь Google/Level3. Расширять по мере находок из захватов др. РФ-прил.
        // ⚠️ НЕ добавлять сюда CIDR, куда резолвятся эндпоинты НАШИХ проб (ServiceProbe/QualityProbe):
        // 216.239.38.0/24 уже накрывал youtubei.googleapis.com (216.239.38.223) → резолв YouTube-пробы уходил
        // мимо туннеля через РФ и таймаутился → «вечно серый чип» (2026-07-03; проба ушла на www.youtube.com).
        static const char *const kBypassExtra[] = {
            "216.239.38.0/24", // Google (QUIC 443) — Госуслуги attestation/Firebase-класс
            "8.6.112.0/24",    // Level3 (TLS 443)  — Госуслуги телеметрия/анти-фрод (POST ~1.5КБ)
        };
        // AVPN Task 10: foreign-эндпоинты — серверные (bl.bypassExtra) при валидном снапшоте И
        // непустые (сервер может курировать список, но пусто = "нет override", НЕ "выключить
        // Госуслуги-carve" — иначе пустое поле на сервере молча гасило бы вкомпиленный дефолт).
        // Массив выше остаётся вкомпиленным фолбэком на офлайн/первый запуск/kill-switch/пустой ответ.
        QStringList extraFallback;
        for (const char *cidr : kBypassExtra)
            extraFallback << QString::fromLatin1(cidr);
        usedRemoteExtra = useRemote && !bl.bypassExtra.isEmpty();
        const QStringList bypassExtra = usedRemoteExtra ? bl.bypassExtra : extraFallback;
        for (const QString &cidr : bypassExtra)
            sites.insert(cidr, {cidr});
    }

    // AVPN (китайские сервисы, 2026-07-03): узкие /24 серверов Li Auto (理想汽车, app com.chehejia.oc.m01) →
    // direct через РФ-IP. Из-за границы команды управления авто не проходят; с прямого РФ-IP работают.
    // Харвест «глазами РФ» (Google DoH + EDNS РФ-операторов), проверено стабильным для 6 операторов и на
    // пересечение с never-bypass — docs/amnezia-fork/CN-SERVICES-HARVEST.md. Только IPv4-CIDR (checkIpSubnetFormat).
    // Все /24 — на carrier-IDC/Baidu самого Li Auto, НЕ общий CDN (побочки на чужие сервисы нет: китайская
    // инфра из РФ и так direct). Хост команд api-app.lixiang.com за GSLB Baidu — при протухании регенерить
    // (см. gen-скрипт в HARVEST-доке). НЕ брать announced-префикс целиком (там /18–/23 carrier — пол-Китая).
    if (liAutoOn) {
        static const char *const kLiAutoCidrs[] = {
            "175.12.90.0/24",   // api-app.lixiang.com — КОМАНДЫ АВТО (CT Centralsouth AS151823)
            "183.60.227.0/24",  // api-app.lixiang.com — КОМАНДЫ АВТО (CHINANET Guangdong IDC AS134763)
            "103.103.244.0/24", // id.lixiang.com + account.lixiang.com — ЛОГИН/SSO (AS151373, РФ-вид)
            "180.76.97.0/24",   // api.lixiang.com — general API (Baidu AS38365)
            "106.13.244.0/23",  // likey-open/mindgpt/manage.chehejia.com — open-API apisix (CHINANET-IDC-BJ AS23724)
            "106.12.251.0/24",  // ssai-apis.chehejia.com — AI/ASR API (CHINANET Nanjing AS134756)
            "114.111.24.0/24",  // lianshan.lixiang.com / mindgpt — apisix gw (CT Hebei AS140903)
            "193.118.54.0/24",  // account.lixiang.com — заграничный GSLB-edge логина, запасной (Zenlayer AS21859)
        };
        // AVPN Task 10: Li Auto CIDR — серверные (bl.cnLiAutoCidrs) при валидном снапшоте И
        // непустые (та же политика "пусто = нет override" — сервер может курировать список Li Auto,
        // но пустое поле не должно молча гасить вкомпиленный дефолт при живом фолбэке).
        // Массив выше — вкомпиленный фолбэк на офлайн/первый запуск/kill-switch/пустой ответ.
        QStringList liAutoFallback;
        for (const char *cidr : kLiAutoCidrs)
            liAutoFallback << QString::fromLatin1(cidr);
        usedRemoteLiAuto = useRemote && !bl.cnLiAutoCidrs.isEmpty();
        const QStringList liAuto = usedRemoteLiAuto ? bl.cnLiAutoCidrs : liAutoFallback;
        for (const QString &cidr : liAuto)
            sites.insert(cidr, {cidr});
    }

    // AVPN carve-out (инцидент 2026-07-05, вынесено в T6 — rebuildApiCarveOut(sites) выше в файле):
    // api.tribevpn.com хостится на Beget (RU) и накрывается ru_prefixes (159.194.208.0/20) →
    // control plane уходил мимо туннеля, где его режет оператор. Исключаем IP API/активного edge
    // из сева ЗДЕСЬ ЖЕ, где раньше был инлайн-блок (behaviour-preserving — тот же порядок операций
    // над тем же `sites`, тот же вызов carveOutIpFromSites, просто вынесен в метод).
    rebuildApiCarveOut(sites);

    // AVPN Task 10 (per-group fallback): источник — ПО ГРУППАМ, не одним общим useRemote — с тех пор
    // как пустая группа на сервере падает на вкомпиленный дефолт, а не на пустой список (см. выше).
    // ru/extra/liauto=1 → взят серверный снапшот для этой группы, =0 → вкомпиленный фолбэк.
    qInfo("[AVPN bypass] seed source cidrs=%d (master=%d liauto=%d) remote{ru=%d extra=%d liauto=%d} v=%d",
          int(sites.size()), masterOn ? 1 : 0, liAutoOn ? 1 : 0,
          usedRemoteRu ? 1 : 0, usedRemoteExtra ? 1 : 0, usedRemoteLiAuto ? 1 : 0,
          useRemote ? bl.version : -1);

    m_store->replaceVpnSites(RouteMode::VpnAllExceptSites, sites); // AVPN: реконсиляция, не merge
    m_lastBypassSeedStamp = seedStamp; // сев доехал до стора — только теперь входы можно считать применёнными
}

// AVPN RU-direct: применить смену тумблера «АвтоVPN» на живом туннеле. Если намерение — быть онлайн
// (подключены/подключаемся), передёргиваем через reconcile-машину: needsRestart → guardedStop → на
// пришедшем Disconnected reconcile сам поднимет заново (applyRuBypassSplit пересеет новый сплит-конфиг).
// Без back-to-back down+up (CONNECT-INVARIANTS). Офлайн → no-op (применится при следующем Connect).
// AVPN RU-direct (фикс «тумблер на лету не применяется», 2026-07-02): QML Settings (QtCore) пишет в
// QSettings с батч-задержкой ~500 мс (settingsWriteDelay в qqmlsettings), а NE-туннель на iOS гасится
// быстрее → applyRuBypassSplit (guardedStart) и DNS-гейт в up() читали СТАРЫЙ masterOn и поднимали
// туннель со старым сплит-конфигом. Симптом: тумблер на подключённом VPN → реконнект есть, сплит нет;
// ручной stop→toggle→start работал (запись успевала флашнуться). Пишем СИНХРОННО до передёрга —
// движок не должен зависеть от дебаунса UI-стора.
void AvpnEngineQml::setBypassMasterOn(bool on)
{
    QSettings s;
    s.setValue(QStringLiteral("AvpnBypass/masterOn"), on);
    s.sync();
    reapplyBypass();
}

// AVPN (звонки): «RU-DNS маскировка» — гейт Яндекс-DNS-подмены (читается в
// VpnConnectionTunnelControl::up). Синхронная запись + передёрг туннеля, как setBypassMasterOn.
bool AvpnEngineQml::bypassDnsMaskOn() const
{
    return QSettings().value(QStringLiteral("AvpnBypass/dnsMaskOn"), true).toBool();
}

void AvpnEngineQml::setBypassDnsMaskOn(bool on)
{
    QSettings s;
    s.setValue(QStringLiteral("AvpnBypass/dnsMaskOn"), on);
    s.sync();
    reapplyBypass();
}

// AVPN (китайские сервисы): «Li Auto» — узкие /24 серверов Li Auto мимо туннеля (default ВКЛ).
// Синхронная запись + передёрг туннеля, как setBypassMasterOn (QML Settings лагает ~500 мс).
bool AvpnEngineQml::bypassLiAutoOn() const
{
    return QSettings().value(QStringLiteral("AvpnBypass/liAutoOn"), true).toBool();
}

void AvpnEngineQml::setBypassLiAutoOn(bool on)
{
    QSettings s;
    s.setValue(QStringLiteral("AvpnBypass/liAutoOn"), on);
    s.sync();
    reapplyBypass();
}

// AVPN split-DNS форвардер: синхронная запись (грабля QML Settings ~500мс) + штатная реконсиляция
// (смена DNS-механики требует передёрга туннеля — reapplyBypass сам решит needsRestart).
bool AvpnEngineQml::bypassDnsFwdOn() const
{
    return QSettings().value(QStringLiteral("AvpnBypass/dnsFwd"), true).toBool();
}

void AvpnEngineQml::setBypassDnsFwdOn(bool on)
{
    QSettings s;
    s.setValue(QStringLiteral("AvpnBypass/dnsFwd"), on);
    s.sync();
    reapplyBypass();
}

void AvpnEngineQml::reapplyBypass()
{
    if (!m_wantConnected)
        return;
    m_needsRestart = true;
    reconcile();
    emit changed();
}

// AVPN (Task 7): пауза туннеля «для покупок». Будет дёргаться iOS App Intent (Task 8).
// Семантика бездействия БЕЗ foreground-API: ставим одноразовый таймер на `seconds`; если за это
// время пользователь не вернул туннель руками (resumeFromPause) и не остановил VPN — считаем, что
// он «не трогал» → авто-поднимаем обратно. Это и есть «бездействие → вернулись».
void AvpnEngineQml::pauseForShopping(int seconds)
{
    // Тумблер управляет лишь АВТО-триггером со стороны системы. Ручной/intent-вызов работает всегда —
    // если бы мы блокировали по autoPauseEnabled(), кнопка «пауза для покупок» молча не сработала бы.
    // (Авто-инициатор на стороне iOS-интента сам проверит тумблер перед вызовом — Task 8.)

    if (m_paused) {
        // Уже на паузе — продлеваем окно (пользователь «ещё не закончил покупки»).
        m_pauseTimer.start(qMax(1, seconds) * 1000);
        return;
    }

    // AVPN (аудит N7): не роняем туннель ПОВЕРХ незавершённой операции — down() поверх поднимающегося
    // = iOS-churn (§2). Пауза в момент перехода бессмысленна (туннель ещё/уже не несёт трафик) — игнор.
    if (m_opInFlight)
        return;

    // Запоминаем, был ли активный туннель: только тогда есть смысл поднимать его обратно по таймауту.
    // Если VPN и так не был поднят — пауза вырождается в no-op подъёма (просто ничего не роняем).
    // AVPN (независимое ревью волны, MINOR-7): фаза verifying — туннель ПОДНЯТ (xray ждёт первой
    // пробы). Без неё пауза для покупок считала xray-сессию «не поднятой» и после паузы туннель
    // не возвращался. Единый предикат — avpn::isTunnelUpStateName (DebugSnapshot.h).
    const QString st = debugSnapshot().value(QStringLiteral("state")).toString();
    m_wasConnected = avpn::isTunnelUpStateName(st);

    m_paused = true;
    // Реально опускаем туннель: на паузе utun-детект ДОЛЖЕН показывать туннель опущенным (трафик
    // покупки идёт мимо VPN). AVPN (аудит N7): через guardedStop() — та же последовательность
    // (healthTimer.stop + requestStop + down), но с Op::Stopping/opInFlight/watchdog, т.е. внутри
    // reconcile-машины; на пришедшем Disconnected reconcile no-op по гейту m_paused.
    guardedStop();

    m_pauseTimer.start(qMax(1, seconds) * 1000);
    emit changed();
}

// AVPN (Task 7): ручной выход из паузы — поднять туннель сразу, не дожидаясь таймера.
void AvpnEngineQml::resumeFromPause()
{
    if (!m_paused)
        return;
    m_pauseTimer.stop();
    m_paused = false;
    // Поднимаем туннель обратно только если до паузы он был активен. Иначе — просто снимаем флаг.
    if (m_wasConnected)
        start(); // enroll→subscription→connect (идемпотентно по busy); поднимет лучшую ноду
    m_wasConnected = false;
    emit changed();
}

// AVPN (Task 7): таймер паузы истёк → бездействие → возвращаемся (поднимаем туннель обратно).
void AvpnEngineQml::onPauseTimeout()
{
    resumeFromPause();
}

// AVPN (Devices+Account): GET /v1/devices АСИНХРОННО → property `devices` + devicesChanged().
// Контракт отдаёт ГОЛЫЙ JSON-массив DeviceInfo (не обёртку {devices:[…]}, как в 409-теле redeem).
// Bearer = authToken() (subscription_token). Нет токена / 401 / сеть / таймаут → пустой список.
// КРИТИЧНО: БЕЗ вложенного QEventLoop — зовётся из QML-таймера (settingsLoadTimer); nested loop
// на GUI-потоке прокручивал чужие события и при destroy объекта в его теле → re-entrancy краш
// («Object destroyed while one of its QML signal handlers is in progress / nested event loop»).
void AvpnEngineQml::refreshDevices()
{
    const QString token = authToken();
    if (!m_nam || token.isEmpty()) {
        if (!m_devices.isEmpty()) { m_devices.clear(); emit devicesChanged(); }
        return;
    }

    QNetworkRequest req{QUrl(m_baseUrl + QStringLiteral("/v1/devices"))};
    req.setRawHeader(QByteArrayLiteral("Authorization"),
                     QByteArrayLiteral("Bearer ") + token.toUtf8());

    QNetworkReply *reply = m_nam->get(req);
    armTimeout(reply); // жёсткий таймаут без nested loop (abort → finished с code==0)
    connect(reply, &QNetworkReply::finished, this, [this, reply]() {
        reply->deleteLater();
        const int code = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        QVariantList list;
        if (code >= 200 && code < 300) {
            const QJsonDocument doc = QJsonDocument::fromJson(reply->readAll());
            if (doc.isArray()) {
                for (const QJsonValue &v : doc.array()) {
                    const QJsonObject d = v.toObject();
                    QVariantMap m;
                    m.insert(QStringLiteral("device_id"), d.value(QStringLiteral("device_id")).toString());
                    // AVPN: device_uuid (install-UUID = localDeviceId) — публичный «ID устройства»
                    // для UI и операций extend/delete; device_id (PK) deprecated. Контракт LIVE.
                    m.insert(QStringLiteral("device_uuid"), d.value(QStringLiteral("device_uuid")).toString());
                    m.insert(QStringLiteral("platform"), d.value(QStringLiteral("platform")).toString());
                    m.insert(QStringLiteral("label"), d.value(QStringLiteral("label")).toString());
                    m.insert(QStringLiteral("last_seen"), d.value(QStringLiteral("last_seen")).toString());
                    m.insert(QStringLiteral("is_current"), d.value(QStringLiteral("is_current")).toBool());
                    list.append(m);
                }
            }
        }
        // 401/сеть/таймаут → пустой список (как в синхронной версии). Эмитим всегда, чтобы UI
        // мог снять «загрузку» и забиндиться на актуальное значение.
        m_devices = list;
        emit devicesChanged();
    });
}

// AVPN (Devices+Account): DELETE /v1/devices/{id} → кик устройства (его токен убит, peer снят на
// каждой ноде). 204 → true + emit changed() (UI перечитает listDevices()). 401/404/сеть → false +
// emit error. Account-scoped: чужой/несуществующий id отдаёт 404 (BOLA-защита бэка).
bool AvpnEngineQml::kickDevice(const QString &deviceId)
{
    const QString id = deviceId.trimmed();
    if (id.isEmpty()) {
        emit error(tr("Не указано устройство"));
        return false;
    }
    const QString token = authToken();
    if (!m_nam || token.isEmpty()) {
        emit error(tr("Нет авторизации"));
        return false;
    }

    QNetworkRequest req{QUrl(m_baseUrl + QStringLiteral("/v1/devices/")
                            + QString::fromUtf8(QUrl::toPercentEncoding(id)))};
    req.setRawHeader(QByteArrayLiteral("Authorization"),
                     QByteArrayLiteral("Bearer ") + token.toUtf8());

    QNetworkReply *reply = m_nam->deleteResource(req);
    awaitReply(reply); // AVPN: было QEventLoop без таймаута → фриз при зависшем бэке

    const int code = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
    const QNetworkReply::NetworkError netErr = reply->error();
    const QString netErrStr = reply->errorString();
    reply->deleteLater();

    if (netErr != QNetworkReply::NoError && code == 0) {
        emit error(tr("Сеть недоступна: %1").arg(netErrStr));
        return false;
    }
    if (code == 401) {
        emit error(tr("Сессия истекла"));
        return false;
    }
    if (code == 404) {
        emit error(tr("Устройство не найдено"));
        return false;
    }
    if (code < 200 || code >= 300) {
        emit error(tr("Не удалось отключить устройство (HTTP %1)").arg(code));
        return false;
    }
    emit changed(); // UI перечитает список устройств
    return true;
}

// AVPN (Devices+Account): GET /v1/account АСИНХРОННО → property `account` + accountChanged().
// Bearer = authToken(). Нет токена / 401 / сеть / таймаут → пустая мапа (UI покажет дефолты).
// Формат: {account_id, status, expires_at?, traffic_limit, traffic_used}. БЕЗ nested loop
// (как refreshDevices — зовётся из QML-таймера, nested loop = re-entrancy краш).
void AvpnEngineQml::refreshAccount()
{
    const QString token = authToken();
    if (!m_nam || token.isEmpty()) {
        if (!m_account.isEmpty()) { m_account.clear(); emit accountChanged(); }
        return;
    }

    QNetworkRequest req{QUrl(m_baseUrl + QStringLiteral("/v1/account"))};
    req.setRawHeader(QByteArrayLiteral("Authorization"),
                     QByteArrayLiteral("Bearer ") + token.toUtf8());

    QNetworkReply *reply = m_nam->get(req);
    armTimeout(reply);
    connect(reply, &QNetworkReply::finished, this, [this, reply]() {
        reply->deleteLater();
        const int code = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        // AVPN remote-config (T6, edge-walk): та же классификация транспорт-vs-приложение, что
        // ConfigService::fetchConfig — 0/5xx = проблема ИМЕННО этого edge → повод шагнуть на другой;
        // любой иной ответ (даже 401/403/410) ДОКАЗЫВАЕТ, что edge жив — НЕ считаем сетевой ошибкой.
        if (m_configSvc) {
            if (code == 0 || code >= 500)
                m_configSvc->reportNetworkFailure();
            else
                m_configSvc->reportNetworkSuccess();
        }
        // AVPN (белые списки, ревью finding 2): у детектора классификация иная, чем у edge-walk —
        // ЛЮБОЙ дошедший HTTP-статус (вкл. 5xx) = control plane достижим, фейл только code==0.
        if (m_whitelistDetector) {
            if (code > 0) m_whitelistDetector->noteControlPlaneOk();
            else m_whitelistDetector->noteControlPlaneFailure();
        }
        // AVPN (перенос «как SIM»): 410 transferred — см. refreshSubscription (тот же флаг).
        if (code == 410 && !m_transferredAway) { m_transferredAway = true; emit changed(); }
        QVariantMap result;
        if (code >= 200 && code < 300) {
            const QJsonDocument doc = QJsonDocument::fromJson(reply->readAll());
            if (doc.isObject()) {
                const QJsonObject o = doc.object();
                result.insert(QStringLiteral("account_id"), o.value(QStringLiteral("account_id")).toString());
                result.insert(QStringLiteral("status"), o.value(QStringLiteral("status")).toString());
                result.insert(QStringLiteral("expires_at"), o.value(QStringLiteral("expires_at")).toString());
                result.insert(QStringLiteral("traffic_limit"),
                              static_cast<qlonglong>(o.value(QStringLiteral("traffic_limit")).toDouble()));
                result.insert(QStringLiteral("traffic_used"),
                              static_cast<qlonglong>(o.value(QStringLiteral("traffic_used")).toDouble()));
                // AVPN (admin-гейт): devices.is_admin с бэка. Отсутствие ключа/оффлайн/401 →
                // пустая мапа → isAdminDevice()==false — панель администратора скрыта.
                result.insert(QStringLiteral("is_admin"), o.value(QStringLiteral("is_admin")).toBool());
                // AVPN (короткий ID, канон 2026-07-21): порядковый числовой Account.id —
                // ЕГО показываем юзеру (шапка чата, карточка «Статус доступа»); длинный
                // hex account_id — технический (копия/перенос). 0/нет поля = старый бэк →
                // UI падает на фолбэк (первые 8 hex).
                result.insert(QStringLiteral("account_number"),
                              o.value(QStringLiteral("account_number")).toInt(0));
                // AVPN (плашка группы, group-aware волна): операторская группа аккаунта —
                // бейдж карточки показывает её имя вместо Премиум/Пробный/Истекла.
                // null/нет поля → ключ не пишем, UI рисует обычный бейдж.
                const QJsonValue gv = o.value(QStringLiteral("group"));
                if (gv.isObject()) {
                    const QJsonObject g = gv.toObject();
                    QVariantMap gm;
                    gm.insert(QStringLiteral("name"), g.value(QStringLiteral("name")).toString());
                    gm.insert(QStringLiteral("color"), g.value(QStringLiteral("color")).toString());
                    gm.insert(QStringLiteral("unlimited"),
                              g.value(QStringLiteral("unlimited")).toBool());
                    result.insert(QStringLiteral("group"), gm);
                }
            }
        }
        m_account = result;
        emit accountChanged();
        // AVPN (оплата, ДВОЕ ЧАСОВ): числа /v1/account — ЧАСЫ АККАУНТА, а платёж продлевает ЧАСЫ
        // УСТРОЙСТВА (apply_paid → device.expires_at/traffic; account.status/expires не трогает).
        // Прежний merge updateSubscriptionTraffic(/v1/account) ЗАТИРАЛ device-часы шапки аккаунт-
        // часами: на оплаченном устройстве бейдж флипался «36 дн./100ГБ → триальные». Живой бейдж
        // теперь кормит refreshSubscription() (device-часы); сюда merge НЕ возвращать.
        // property account (account_id для саппорта, списки в Настройках) остаётся как есть.
    });
}

// AVPN (i18n): язык приложения для переключателя в Tribe-настройках. Свои enum/модели не заводим —
// пишем локаль напрямую в SecureAppSettingsRepository (тот же инстанс, что у coreController);
// его сигнал appLanguageChanged запускает штатную цепочку ретрансляции апстрима.
QString AvpnEngineQml::appLang() const
{
    return m_store ? m_store->getAppLanguage().name().split(QLatin1Char('_')).first()
                   : QStringLiteral("ru");
}

void AvpnEngineQml::setAppLang(const QString &lang)
{
    if (!m_store || appLang() == lang)
        return;
    m_store->setAppLanguage(QLocale(lang));
    emit appLangChanged();
    // AVPN backend-first-3 (Task 7): incidentText/hotTexts — функции от appLang (localizedOr).
    // Их NOTIFY = changed, appLangChanged его не покрывает — эмитим явно, иначе баннер/CTA
    // остаются на старом языке до следующего configApplied.
    emit changed();
}

// AVPN backend-first-3 (Task 7): server-driven hot-тексты CTA оплаты. Ключи фиксированы
// (контракт с PageConnectTribe.qml), значение — localizedOr("<key>", appLang(), "") по цепочке
// _<lang> → _en → base. Пустые НЕ кладём в map: в QML `hotTexts["key"]` даёт undefined →
// falsy → срабатывает вкомпиленный qsTr-фолбэк (byte-for-byte прежний текст).
QVariantMap AvpnEngineQml::hotTexts() const
{
    static const QString kCtaKeys[] = { QStringLiteral("cta_renew_traffic"),
                                        QStringLiteral("cta_renew_access"),
                                        QStringLiteral("cta_how_traffic"),
                                        QStringLiteral("cta_how_access") };
    QVariantMap out;
    const QString lang = appLang();
    for (const QString &key : kCtaKeys) {
        const QString v = avpn::TuningStore::localizedOr(key, lang, QString());
        if (!v.isEmpty())
            out.insert(key, v);
    }
    return out;
}

// AVPN (оплата, ДВОЕ ЧАСОВ): лёгкий рефетч GET /v1/subscription — ЧАСЫ УСТРОЙСТВА (их продлевает
// платёж) для бейджа ГБ/дней и CTA «Обновить ключ». Обновляет ТОЛЬКО traffic/expires снапшота
// (updateSubscriptionTraffic) — пул нод/туннель/стейт-машину НЕ трогает (CONNECT-INVARIANTS:
// никакой реконфигурации на лету). АСИНХРОННО (armTimeout, без nested loop). Зовётся: (а) возврат
// в foreground — после оплаты в кабинете приедет новый expires_at и CTA погаснет сам; (б) тик #35.
void AvpnEngineQml::refreshSubscription()
{
    const QString token = authToken();
    if (!m_nam || token.isEmpty())
        return;

    QNetworkRequest req{versionedSubscriptionUrl(
        m_baseUrl, QCoreApplication::applicationVersion())};
    req.setRawHeader(QByteArrayLiteral("Authorization"),
                     QByteArrayLiteral("Bearer ") + token.toUtf8());

    QNetworkReply *reply = m_nam->get(req);
    armTimeout(reply);
    connect(reply, &QNetworkReply::finished, this, [this, reply]() {
        reply->deleteLater();
        const int code = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        // AVPN remote-config (T6, edge-walk): см. идентичный блок в refreshAccount() выше по файлу.
        if (m_configSvc) {
            if (code == 0 || code >= 500)
                m_configSvc->reportNetworkFailure();
            else
                m_configSvc->reportNetworkSuccess();
        }
        // AVPN (белые списки, ревью finding 2): паритет с refreshAccount — детектору свой сигнал.
        if (m_whitelistDetector) {
            if (code > 0) m_whitelistDetector->noteControlPlaneOk();
            else m_whitelistDetector->noteControlPlaneFailure();
        }
        // AVPN (перенос «как SIM»): 410 transferred — подписка уехала на другое устройство.
        // Взводим терминальный флаг для UI («Подписка перенесена»); НЕ ре-энроллим.
        if (code == 410) {
            if (!m_transferredAway) { m_transferredAway = true; emit changed(); }
            return;
        }
        if (code < 200 || code >= 300)
            return; // 401/сеть/таймаут → тихо; данные обновятся при следующем connect/bootstrap
        if (m_transferredAway) { m_transferredAway = false; emit changed(); } // подписка снова валидна (новый ключ/энролл)
        const QByteArray body = reply->readAll();
        Subscription sub;
        QString err;
        if (!SubscriptionParser::parse(body, sub, err))
            return; // битый ответ не затирает валидные числа
        m_engine.updateSubscriptionTraffic(sub.trafficUsed, sub.trafficLimit, sub.expiresAt);
        // AVPN (LKG, HARDENING-BACKLOG H-3): каждый удачный фетч освежает дисковый кэш — после
        // долгой фоновой жизни холодный старт покажет свежие цифры, а не данные последнего bootstrap.
        // Тело уже валидно (parse выше); m_pool этот путь трогает ТОЛЬКО через reseed ниже.
        Enrollment::saveLkgSubscription(body);
        emit changed(); // daysLeft/traffic*/subExpired в QML пересчитаются
        // AVPN awg31-xray-v1 (спека §2.3, инвариант §4.4): reseed пула на живом приложении по смене
        // pool_revision. Три опоры: kill-switch features.subscription_reseed_pool (default ВЫКЛ —
        // включает бэк), ревизия > 0 (старый бэк/LKG без поля — не трогаем), непустой пул (пустое/
        // degraded-тело пул не затирает). Применение — с верха цикла событий (QTimer::singleShot(0)):
        // этот колбэк может прийти изнутри вложенного QEventLoop sync-вызова (redeem/startFlow),
        // а движок мог быть в Selector::pick. Терминал/неизменная текущая нода решает сам движок.
        if (featureEnabled(QStringLiteral("subscription_reseed_pool"), false)
            && sub.poolRevision > 0 && !sub.nodes.isEmpty()
            && sub.poolRevision != m_engine.poolRevision()) {
            QTimer::singleShot(0, this, [this, sub]() { applyReseed(sub); });
        }
    });
}

// AVPN (#37 рефералы): GET /v1/referral → {code, link, invited, days_earned, gb_earned,
// days_per_friend, gb_per_friend, invitee_days} (openapi 0.9.0). Тот же async-паттерн,
// что refreshAccount (без вложенного QEventLoop). Код привязывается к устройству при первом вызове
// (issued lazily) — поэтому бонус-дни от установки друга падают на ЭТО устройство.
void AvpnEngineQml::refreshReferral()
{
    const QString token = authToken();
    if (!m_nam || token.isEmpty()) {
        if (!m_referral.isEmpty()) { m_referral.clear(); emit referralChanged(); }
        return;
    }

    QNetworkRequest req{QUrl(m_baseUrl + QStringLiteral("/v1/referral"))};
    req.setRawHeader(QByteArrayLiteral("Authorization"),
                     QByteArrayLiteral("Bearer ") + token.toUtf8());

    QNetworkReply *reply = m_nam->get(req);
    armTimeout(reply);
    connect(reply, &QNetworkReply::finished, this, [this, reply]() {
        reply->deleteLater();
        const int code = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        QVariantMap result;
        if (code >= 200 && code < 300) {
            const QJsonDocument doc = QJsonDocument::fromJson(reply->readAll());
            if (doc.isObject()) {
                const QJsonObject o = doc.object();
                result.insert(QStringLiteral("code"), o.value(QStringLiteral("code")).toString());
                result.insert(QStringLiteral("link"), o.value(QStringLiteral("link")).toString());
                result.insert(QStringLiteral("invited"),
                              static_cast<int>(o.value(QStringLiteral("invited")).toDouble()));
                result.insert(QStringLiteral("days_earned"),
                              static_cast<int>(o.value(QStringLiteral("days_earned")).toDouble()));
                result.insert(QStringLiteral("gb_earned"),
                              static_cast<int>(o.value(QStringLiteral("gb_earned")).toDouble()));
                // Server-driven размер оффера — пробрасываем ТОЛЬКО если бэк прислал (QML по
                // undefined откатывается на вкомпиленный фолбэк — старые бэки без полей).
                for (const char *key : { "days_per_friend", "gb_per_friend", "invitee_days" }) {
                    const QString k = QString::fromLatin1(key);
                    if (o.contains(k))
                        result.insert(k, static_cast<int>(o.value(k).toDouble()));
                }
            }
        }
        // 401/сеть/таймаут → пустая мапа (баннер покажет дефолтный оффер). Эмитим всегда.
        m_referral = result;
        emit referralChanged();
    });
}

// ---------------------------------------------------------------------------
// AVPN (объявления P-ANN): server-driven важные сообщения — попап поверх главного
// экрана + карточки колокольчика. Контент настраивается в админке; новые
// объявления НЕ требуют обновления приложения. Спека: tribe-front
// docs/superpowers/specs/2026-07-09-announcements-design.md.
// ---------------------------------------------------------------------------

namespace {
QString announcePlatform()
{
#if defined(Q_OS_IOS)
    return QStringLiteral("ios");
#elif defined(Q_OS_ANDROID)
    return QStringLiteral("android");
#elif defined(Q_OS_MACOS)
    return QStringLiteral("macos");
#elif defined(Q_OS_WIN)
    return QStringLiteral("windows");
#else
    return QStringLiteral("linux");
#endif
}
} // namespace

// AVPN (announce-quiet): отметка «онбординг пройден» — якорь тихого окна попапов.
// Синхронный QSettings (грабля 500мс QML-Settings: quiet-проверка идёт уже через 900мс).
// Идемпотентно: НЕ сдвигаем отметку, если уже стоит (повторные onRequestStart/дев-сбросы
// онбординга не продлевают тишину).
void AvpnEngineQml::markOnboardingDone()
{
    QSettings s;
    const QString key = QStringLiteral("AvpnAnnounce/onboardDoneAt");
    if (s.value(key, 0).toLongLong() > 0)
        return;
    s.setValue(key, QDateTime::currentSecsSinceEpoch());
    s.sync();
}

// AVPN (announce-quiet): попапы объявлений сейчас молчат? Kill-switch первой строкой
// (default TRUE — бэк может прислать false и вернуть старое поведение без релиза);
// размер окна server-tunable (кап 7 суток в AnnounceGate::quietMinTuned). Глушится только
// автопоказ попапа — бейдж колокольчика, лента и пуши работают как раньше.
bool AvpnEngineQml::announcementsQuietNow() const
{
    if (!avpn::TuningStore::flag(QStringLiteral("announce_onboarding_quiet")))
        return false;
    const qint64 doneAt = QSettings().value(QStringLiteral("AvpnAnnounce/onboardDoneAt"), 0).toLongLong();
    return avpn::AnnounceGate::quietActive(doneAt, avpn::AnnounceGate::quietMinTuned(),
                                           QDateTime::currentSecsSinceEpoch());
}

// LKG-персист текущего списка (мгновенный показ до сети при следующем старте — паттерн
// saveLkgSubscription). Синхронный QSettings::sync — движок владеет записью, не QML.
void AvpnEngineQml::persistAnnouncementsLkg()
{
    QSettings s;
    s.setValue(QStringLiteral("AvpnAnnounce/lkg"),
               QString::fromUtf8(QJsonDocument(QJsonArray::fromVariantList(m_announcements))
                                     .toJson(QJsonDocument::Compact)));
    s.sync();
}

void AvpnEngineQml::loadAnnouncementsLkg()
{
    QSettings s;
    const QByteArray raw = s.value(QStringLiteral("AvpnAnnounce/lkg")).toString().toUtf8();
    if (raw.isEmpty())
        return;
    const QJsonDocument doc = QJsonDocument::fromJson(raw);
    if (!doc.isArray())
        return;
    QVariantList items;
    for (const QJsonValue &v : doc.array()) {
        const QVariantMap item = v.toObject().toVariantMap();
        // Прочитанное после сохранения LKG отфильтровываем на загрузке.
        if (!announcementRead(item.value(QStringLiteral("id")).toInt()))
            items.append(item);
    }
    if (!items.isEmpty()) {
        m_announcements = items;
        emit announcementsChanged();
    }
}

void AvpnEngineQml::refreshAnnouncements()
{
    const QString token = authToken();
    if (!m_nam || token.isEmpty())
        return; // без токена не ходим; LKG уже показан, bootstrap дотянет позже

    QUrl url(m_baseUrl + QStringLiteral("/v1/announcements"));
    QUrlQuery q;
    q.addQueryItem(QStringLiteral("platform"), announcePlatform());
    q.addQueryItem(QStringLiteral("lang"), appLang());
    q.addQueryItem(QStringLiteral("app_version"), QCoreApplication::applicationVersion());
    url.setQuery(q);
    QNetworkRequest req{url};
    req.setRawHeader(QByteArrayLiteral("Authorization"),
                     QByteArrayLiteral("Bearer ") + token.toUtf8());

    QNetworkReply *reply = m_nam->get(req);
    armTimeout(reply);
    connect(reply, &QNetworkReply::finished, this, [this, reply]() {
        reply->deleteLater();
        const int code = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        if (code < 200 || code >= 300)
            return; // сеть/401 → тихо, текущий список (LKG) не трогаем
        const QJsonDocument doc = QJsonDocument::fromJson(reply->readAll());
        if (!doc.isObject())
            return;
        QVariantList items;
        const QJsonArray arr = doc.object().value(QStringLiteral("items")).toArray();
        for (const QJsonValue &v : arr) {
            const QVariantMap item = v.toObject().toVariantMap();
            // Серверный фильтр уже исключает прочитанные ЭТИМ устройством; локальный дубль —
            // страховка от гонки «read-ack ещё не долетел, а fetch уже вернул старый список».
            if (!announcementRead(item.value(QStringLiteral("id")).toInt()))
                items.append(item);
        }
        m_announcements = items;
        persistAnnouncementsLkg();
        emit announcementsChanged();
    });
}

bool AvpnEngineQml::announcementRead(int id) const
{
    QSettings s;
    return s.value(QStringLiteral("AvpnAnnounce/read_%1").arg(id), false).toBool();
}

void AvpnEngineQml::ackAnnouncement(int id, const QString &event, const QString &buttonId)
{
    if (id <= 0)
        return;
    if (event == QLatin1String("shown")) {
        if (m_announceShownAcked.contains(id))
            return; // один shown-ack на объявление за сессию
        m_announceShownAcked.insert(id);
    }
    if (event == QLatin1String("read")) {
        // Локальный дубль серверного read_at — СИНХРОННО (движок, не QML Settings):
        // попап не должен всплыть повторно даже офлайн/до следующего fetch.
        {
            QSettings s;
            s.setValue(QStringLiteral("AvpnAnnounce/read_%1").arg(id), true);
            s.sync();
        }
        QVariantList rest;
        for (const QVariant &v : std::as_const(m_announcements))
            if (v.toMap().value(QStringLiteral("id")).toInt() != id)
                rest.append(v);
        if (rest.size() != m_announcements.size()) {
            m_announcements = rest;
            persistAnnouncementsLkg();
            emit announcementsChanged();
        }
    }

    const QString token = authToken();
    if (!m_nam || token.isEmpty())
        return; // локальный read уже сохранён; серверная квитанция догонит при следующем показе
    QNetworkRequest req{QUrl(m_baseUrl + QStringLiteral("/v1/announcements/%1/ack").arg(id))};
    req.setRawHeader(QByteArrayLiteral("Authorization"),
                     QByteArrayLiteral("Bearer ") + token.toUtf8());
    req.setHeader(QNetworkRequest::ContentTypeHeader, QStringLiteral("application/json"));
    QJsonObject body{{QStringLiteral("event"), event}};
    if (!buttonId.isEmpty())
        body.insert(QStringLiteral("button_id"), buttonId);
    QNetworkReply *reply = m_nam->post(req, QJsonDocument(body).toJson(QJsonDocument::Compact));
    armTimeout(reply);
    connect(reply, &QNetworkReply::finished, reply, &QNetworkReply::deleteLater); // fire-and-forget
}

// AVPN (оплата): POST /v1/cabinet/web-link (Bearer, тело пустое) → { url: "…?wl=<token>", expires_in }.
// Тот же async-паттерн, что refreshReferral (armTimeout, без вложенного QEventLoop). Сигнал
// cabinetLinkReady эмитится на ЛЮБОМ исходе: успех → url бэка как есть (устройство вшито в wl-токен,
// бэк PR #257), провал → fallback https://tribevpn.com/account. device_uuid в URL не дописываем.
void AvpnEngineQml::requestCabinetLink(const QString &intent)
{
    // intent → query-параметр (реш. 2026-07-03): "renew" (золотая CTA) — кабинет сразу выдвигает шит
    // тарифов; пусто («Управлять подпиской») — чистый ЛК. lang = язык приложения → кабинет открывается
    // на нём же (i18n ЛК, 2026-07-07). Дописываем к ЛЮБОМУ исходу (и к fallback). Захват по значению:
    // лямбда живёт дольше вызова (async-коллбэк ниже).
    const QString lang = appLang();
    const auto withIntent = [intent, lang](const QString &url) {
        QString out = url;
        const auto add = [&out](const QString &kv) {
            out += (out.contains(QLatin1Char('?')) ? QLatin1Char('&') : QLatin1Char('?'));
            out += kv;
        };
        if (!intent.isEmpty())
            add(QStringLiteral("intent=") + QString::fromLatin1(QUrl::toPercentEncoding(intent)));
        if (!lang.isEmpty())
            add(QStringLiteral("lang=") + lang);
        return out;
    };
    // ПРИВАТНОСТЬ: URL кабинета идёт БЕЗ device_uuid — устройство вшито в сам wl-токен
    // (бэк PR #257: кабинет берёт цель авто-продления из wl-сессии), а fallback без wl
    // кабинет всё равно не аутентифицирует. Стабильный install-id в query засветился бы
    // в access-логах зря (docs/amnezia-fork/WEBLINK-DEVICE-BINDING-HANDOFF.md).
    // Домен фолбэка — cabinetUrl() (server-driven urls.cabinet через TuningStore, 0a6c1408), НЕ
    // литерал: та же канон-точка, что уже читают PageConnectTribe/PageAccountTribe напрямую.
    const QString fallback = withIntent(cabinetUrl());
    const QString token = authToken();
    if (!m_nam || token.isEmpty()) {
        emit cabinetLinkReady(fallback);
        return;
    }

    QNetworkRequest req{QUrl(m_baseUrl + QStringLiteral("/v1/cabinet/web-link"))};
    req.setRawHeader(QByteArrayLiteral("Authorization"),
                     QByteArrayLiteral("Bearer ") + token.toUtf8());

    QNetworkReply *reply = m_nam->post(req, QByteArray());
    armTimeout(reply); // жёсткий таймаут без nested loop
    connect(reply, &QNetworkReply::finished, this, [this, reply, fallback, withIntent]() {
        reply->deleteLater();
        const int code = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        QString url = fallback;
        if (code >= 200 && code < 300) {
            WebLinkResponse wl;
            QString err;
            if (Enrollment::parseWebLinkResponse(reply->readAll(), wl, err))
                url = withIntent(wl.url);
        }
        emit cabinetLinkReady(url);
    });
}

// AVPN (Task 9 — APNs): POST /v1/devices/push-token (Bearer = subscription_token). АСИНХРОННО (как
// refreshAccount — без вложенного QEventLoop: зовётся из сигнала моста на GUI-потоке). body
// {token, platform:"ios", environment, app_version}. Нет токена подписки / сеть / таймаут → тихо
// (повторится при следующем коннекте или ротации токена). Дедуп: один POST на пару (token,env) за сессию.
void AvpnEngineQml::registerPushToken(const QString &token, const QString &environment)
{
    if (token.isEmpty())
        return;
    // Запоминаем последний токен/окружение для ПЕРЕ-регистрации после ротации subscription_token.
    m_pushToken = token;
    m_pushEnv = environment;

    const QString auth = authToken();
    if (!m_nam || auth.isEmpty())
        return; // ещё не enrolled — зарегистрируем, когда появится subscription_token (коннект/redeem)

    // Дедуп: не дёргаем бэк повторно тем же токеном+окружением под тем же subscription_token.
    const QString fingerprint = token + QLatin1Char('|') + environment + QLatin1Char('|') + auth;
    if (m_pushTokenSent == fingerprint)
        return;

    QJsonObject body;
    body.insert(QStringLiteral("token"), token);
    // Платформа из моста (deviceTokenReady); пусто = легаси-путь iOS (до FCM-волны).
    body.insert(QStringLiteral("platform"),
                m_pushPlatform.isEmpty() ? QStringLiteral("ios") : m_pushPlatform);
    if (!environment.isEmpty())
        body.insert(QStringLiteral("environment"), environment);
    const QString ver = QCoreApplication::applicationVersion();
    if (!ver.isEmpty())
        body.insert(QStringLiteral("app_version"), ver);
    // AVPN (P-ANN): язык UI — кормит таргетинг объявлений/пушей на бэке.
    if (!appLang().isEmpty())
        body.insert(QStringLiteral("lang"), appLang());

    QNetworkRequest req{QUrl(m_baseUrl + QStringLiteral("/v1/devices/push-token"))};
    req.setHeader(QNetworkRequest::ContentTypeHeader, QByteArrayLiteral("application/json"));
    req.setRawHeader(QByteArrayLiteral("Authorization"),
                     QByteArrayLiteral("Bearer ") + auth.toUtf8());

    QNetworkReply *reply = m_nam->post(req, QJsonDocument(body).toJson(QJsonDocument::Compact));
    armTimeout(reply); // жёсткий таймаут без nested loop
    connect(reply, &QNetworkReply::finished, this, [this, reply, fingerprint]() {
        reply->deleteLater();
        const int code = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        if (code >= 200 && code < 300)
            m_pushTokenSent = fingerprint; // успех → больше не дублируем
        // 401/сеть/таймаут → НЕ помечаем отправленным: повторим при ротации/реконнекте. Тихо (фоновая
        // best-effort регистрация не должна показывать пользователю ошибку).
    });
}

// DEV TOOL (TEMPORARY — remove with backend routers/devtools.py): POST /v1/dev/reset-trial
// (Bearer = subscription_token, пустое тело). Заводской сброс триала ЭТОГО аккаунта; при успехе
// перечитываем account+подписку, чтобы шапка (дни/трафик) обновилась. 404 = флаг выключен на сервере.
// Изолировано: один метод + один пункт в настройках; удаляется вместе с бэкенд-роутером devtools.
void AvpnEngineQml::resetTrialDev()
{
    const QString auth = authToken();
    if (!m_nam || auth.isEmpty()) {
        emit error(tr("Сначала войдите или подключитесь"));
        return;
    }
    QNetworkRequest req{QUrl(m_baseUrl + QStringLiteral("/v1/dev/reset-trial"))};
    req.setHeader(QNetworkRequest::ContentTypeHeader, QByteArrayLiteral("application/json"));
    req.setRawHeader(QByteArrayLiteral("Authorization"),
                     QByteArrayLiteral("Bearer ") + auth.toUtf8());

    QNetworkReply *reply = m_nam->post(req, QByteArrayLiteral("{}"));
    armTimeout(reply);
    connect(reply, &QNetworkReply::finished, this, [this, reply]() {
        reply->deleteLater();
        const int code = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        if (code >= 200 && code < 300) {
            refreshAccount(); // обновить property account (дни/трафик)
            // AVPN (фикс ревью 2026-07-07): фасадный bootstrap() идемпотентен (m_bootstrapped
            // после первого успеха) — прямой вызов был вечным no-op, бейдж после сброса не
            // обновлялся. Принудительно перезапускаем async-цепочку под новым состоянием бэка.
            m_bootstrapped = false;
            m_bootstrapInFlight = false;
            m_bootstrapRetryTimer.stop();
            bootstrap();      // перечитать подписку (async-цепочка)
            emit changed();
        } else if (code == 404) {
            emit error(tr("Сброс триала выключен на сервере"));
        } else {
            emit error(tr("Не удалось сбросить триал (код %1)").arg(code));
        }
    });
}

// AVPN (Task 9 — APNs): флаш отложенного push-токена после появления subscription_token. Закрывает
// гэп первичного авто-enroll: device token пришёл из APNs ДО enroll (registerPushToken запомнил
// m_pushToken, но не отправил, т.к. authToken был пуст). После успешного bootstrap/enroll subscription_token
// уже есть → отправляем. Дедуп по fingerprint (token|env|auth) защищает от лишнего POST, если токен
// уже ушёл по redeem-пути. No-op при пустом push-токене (desktop / разрешение не выдано).
void AvpnEngineQml::flushPendingPushToken()
{
    if (m_pushToken.isEmpty())
        return;
    registerPushToken(m_pushToken, m_pushEnv);
}

// AVPN (Task 9 — APNs): POST /v1/notifications/read (Bearer) — обнулить серверный счётчик непрочитанных.
// Без тела. АСИНХРОННО, тихо (фоновое действие). Вызывается по AvpnPushBridge::readRequested
// (QML: AvpnPush.markAllRead()). Локальный бейдж иконки уже снят натив-clearer'ом в мосте.
void AvpnEngineQml::markNotificationsRead()
{
    const QString auth = authToken();
    if (!m_nam || auth.isEmpty())
        return;

    QNetworkRequest req{QUrl(m_baseUrl + QStringLiteral("/v1/notifications/read"))};
    req.setRawHeader(QByteArrayLiteral("Authorization"),
                     QByteArrayLiteral("Bearer ") + auth.toUtf8());

    QNetworkReply *reply = m_nam->post(req, QByteArray());
    armTimeout(reply);
    connect(reply, &QNetworkReply::finished, this, [reply]() { reply->deleteLater(); });
}

// AVPN (read per-элемент): POST /v1/notifications/read {"ids":[id],"read":read} — read-статус
// ОДНОГО уведомления в обе стороны (бэк пересчитывает unread_count по остатку). Вызывается по
// readItemRequested моста (деталь открыта / свайп-тоггл). АСИНХРОННО, тихо: офлайн-провал не
// страшен — локальный флаг уже сохранён, серверный догонит следующий mark.
void AvpnEngineQml::markNotificationReadById(qlonglong id, bool read)
{
    const QString auth = authToken();
    if (!m_nam || auth.isEmpty() || id <= 0)
        return;

    QNetworkRequest req{QUrl(m_baseUrl + QStringLiteral("/v1/notifications/read"))};
    req.setRawHeader(QByteArrayLiteral("Authorization"),
                     QByteArrayLiteral("Bearer ") + auth.toUtf8());
    req.setHeader(QNetworkRequest::ContentTypeHeader, QStringLiteral("application/json"));

    const QByteArray body = QJsonDocument(QJsonObject{
        {QStringLiteral("ids"), QJsonArray{static_cast<double>(id)}},
        {QStringLiteral("read"), read}}).toJson(QJsonDocument::Compact);
    QNetworkReply *reply = m_nam->post(req, body);
    armTimeout(reply);
    connect(reply, &QNetworkReply::finished, this, [reply]() { reply->deleteLater(); });
}

// AVPN (свайп «Удалить»): POST /v1/notifications/delete {"ids":[id]} — удалить строку на бэке
// (unread_count пересчитает бэк). АСИНХРОННО, тихо; локально элемент уже убран мостом.
void AvpnEngineQml::deleteNotificationById(qlonglong id)
{
    const QString auth = authToken();
    if (!m_nam || auth.isEmpty() || id <= 0)
        return;

    QNetworkRequest req{QUrl(m_baseUrl + QStringLiteral("/v1/notifications/delete"))};
    req.setRawHeader(QByteArrayLiteral("Authorization"),
                     QByteArrayLiteral("Bearer ") + auth.toUtf8());
    req.setHeader(QNetworkRequest::ContentTypeHeader, QStringLiteral("application/json"));

    const QByteArray body = QJsonDocument(QJsonObject{
        {QStringLiteral("ids"), QJsonArray{static_cast<double>(id)}}}).toJson(QJsonDocument::Compact);
    QNetworkReply *reply = m_nam->post(req, body);
    armTimeout(reply);
    connect(reply, &QNetworkReply::finished, this, [reply]() { reply->deleteLater(); });
}

// AVPN (центр уведомлений, серверная история): GET /v1/notifications?limit=50 → мост setServerItems.
// См. коммент в .h (фикс «строка в БД есть, центр пуст» — история доезжает и без доставленного пуша).
void AvpnEngineQml::refreshNotifications()
{
    const QString auth = authToken();
    if (!m_nam || auth.isEmpty())
        return; // не enrolled — серверной истории всё равно нет; локальная лента остаётся
    QNetworkRequest req{QUrl(m_baseUrl + QStringLiteral("/v1/notifications?limit=50"))};
    req.setRawHeader(QByteArrayLiteral("Authorization"),
                     QByteArrayLiteral("Bearer ") + auth.toUtf8());
    QNetworkReply *reply = m_nam->get(req);
    armTimeout(reply);
    connect(reply, &QNetworkReply::finished, this, [reply]() {
        reply->deleteLater();
        const int code = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        if (code < 200 || code >= 300)
            return; // офлайн/401 → локальная лента живёт, ничего не затираем
        const QJsonDocument doc = QJsonDocument::fromJson(reply->readAll());
        if (!doc.isArray())
            return;
        QVariantList items;
        for (const QJsonValue &v : doc.array()) {
            const QJsonObject o = v.toObject();
            const QString title = o.value(QStringLiteral("title")).toString();
            const QString body = o.value(QStringLiteral("body")).toString();
            if (title.isEmpty() && body.isEmpty())
                continue;
            QVariantMap item;
            // Серверный id строки — ключ поэлементного mark-read (markItemRead в мосте).
            item[QStringLiteral("id")] = static_cast<qlonglong>(o.value(QStringLiteral("id")).toDouble());
            item[QStringLiteral("title")] = title;
            item[QStringLiteral("body")] = body;
            // Эталон 2026-07-12: сегодня/вчера — HH:mm, раньше — «10 июл»; плюс секция-группа
            // (Сегодня/Вчера/Ранее) и полная дата для детальной страницы.
            const QDateTime dt = QDateTime::fromString(o.value(QStringLiteral("created_at")).toString(),
                                                       Qt::ISODate).toLocalTime();
            const QDate today = QDate::currentDate();
            const QLocale loc;
            if (!dt.isValid()) {
                item[QStringLiteral("time")] = QString();
                item[QStringLiteral("group")] = QStringLiteral("earlier");
                item[QStringLiteral("dateFull")] = QString();
            } else if (dt.date() == today) {
                item[QStringLiteral("time")] = dt.toString(QStringLiteral("HH:mm"));
                item[QStringLiteral("group")] = QStringLiteral("today");
                item[QStringLiteral("dateFull")] =
                    tr("Сегодня в %1").arg(dt.toString(QStringLiteral("HH:mm")));
            } else if (dt.date() == today.addDays(-1)) {
                item[QStringLiteral("time")] = dt.toString(QStringLiteral("HH:mm"));
                item[QStringLiteral("group")] = QStringLiteral("yesterday");
                item[QStringLiteral("dateFull")] =
                    tr("Вчера в %1").arg(dt.toString(QStringLiteral("HH:mm")));
            } else {
                item[QStringLiteral("time")] = loc.toString(dt.date(), QStringLiteral("d MMM"));
                item[QStringLiteral("group")] = QStringLiteral("earlier");
                item[QStringLiteral("dateFull")] =
                    tr("%1 в %2").arg(loc.toString(dt.date(), QStringLiteral("d MMMM")),
                                      dt.toString(QStringLiteral("HH:mm")));
            }
            item[QStringLiteral("read")] = o.value(QStringLiteral("read")).toBool();
            // Контракт NotificationOut: неизвестный тип = generic-строка title+body, НЕ скрывать
            // (делегат QML стилизует только известные kind, остальным даёт общий вид).
            const QString type = o.value(QStringLiteral("type")).toString();
            item[QStringLiteral("type")] = type.isEmpty() ? QStringLiteral("generic") : type;
            item[QStringLiteral("days")] = static_cast<int>(o.value(QStringLiteral("days")).toDouble());
            items.append(item);
        }
        avpn::AvpnPushBridge::instance()->setServerItems(items);
    });
}

QVariantMap AvpnEngineQml::debugSnapshot() const
{
    const DebugSnapshot s = m_engine.debugSnapshot();
    QVariantMap m;
    m["state"] = s.state;
    m["currentNodeId"] = s.currentNodeId;
    m["latestHandshakeAgeSec"] = static_cast<qlonglong>(s.latestHandshakeAgeSec);
    m["rxBytes"] = static_cast<qlonglong>(s.rxBytes);
    m["txBytes"] = static_cast<qlonglong>(s.txBytes);
    m["subStatus"] = s.subStatus;
    m["lkgStale"] = s.lkgStale;
    m["trafficUsed"] = static_cast<qlonglong>(s.trafficUsed);
    m["trafficLimit"] = static_cast<qlonglong>(s.trafficLimit);
    m["expiresAt"] = s.expiresAt; // AVPN: для daysLeft()
    // AVPN awg31-xray-v1: транспорт текущей ноды / ручной режим / фаза verifying / ревизия пула.
    m["activeProto"] = s.activeProto;
    m["transportMode"] = s.transportMode;
    m["verifying"] = s.verifying;
    m["poolRevision"] = static_cast<qlonglong>(s.poolRevision);
    m["reseedPending"] = s.reseedPending;

    QVariantList pool;
    for (const NodeDebugRow &r : s.pool) {
        QVariantMap n;
        n["nodeId"] = r.nodeId;
        n["region"] = r.region;
        n["name"] = r.name;                                          // AVPN: имя сервера (опц.)
        n["countryCode"] = r.countryCode;                            // AVPN: ISO-3166 alpha-2 → флаг-эмодзи

        n["endpoint"] = r.endpoint;                                   // AVPN: реальный host:port
        n["ip"] = r.endpoint.section(QLatin1Char(':'), 0, 0);         // AVPN: только host для показа
        n["scoreMs"] = r.scoreMs;
        n["healthy"] = r.healthy;
        // AVPN (live-node picker): обогащённые поля для шторки выбора сервера (weight/health/alive/current).
        n["weight"] = r.weight;
        n["health"] = r.healthAgg;  // 0..1 агрегат backend-health → 0..4 бара в UI
        n["alive"] = r.alive;       // жив по backend-данным (фильтр «только живые» в шторке)
        n["current"] = r.current;   // == текущая нода → акцент #7CA2D0 + галка
        n["reason"] = r.reason;
        // AVPN (Task 10 финал): протокол ноды — QML-пикер и админ-свип скипают неподдерживаемые
        // (xray, ...): коннект к ним невозможен, тап/свип упирался бы в сторожа. Пусто = awg.
        n["proto"] = r.proto;
        n["protoVersion"] = r.protoVersion; // AVPN AWG 3.0/3.1: "1"/"2"/"3"/"3.1" → метка «Amnezia vN» в пикере; xray — пусто
        n["manualOnly"] = r.manualOnly; // AVPN (Доктор): manual/RU скипаются в авто-очередях
        // AVPN awg31-xray-v1 (§2.3, пикер «локации × транспорты»): группировка строк по location
        // (host_id, фолбэк country_code+region), бейджи транспортов локации (transports: порядок =
        // transport_rank), активный транспорт локации (activeProto = proto текущей ноды, если она из
        // этой локации), серверный ранг ноды и поддерживается ли её proto этим клиентом
        // (transportSupported=false → строка серая «недоступно в этой версии»).
        n["hostId"] = r.hostId;
        n["location"] = r.location;
        n["transports"] = r.transports;
        n["activeProto"] = r.activeProto;
        n["transportRank"] = r.transportRank;
        n["transportSupported"] = r.transportSupported;
        pool.append(n);
    }
    m["pool"] = pool;

    QVariantList log;
    for (const QString &l : s.switchLog)
        log.append(l);
    m["switchLog"] = log;
    return m;
}

// AVPN (diag-report, Task 4 bff-3): полный диагностический отчёт — юзер отправляет его в чат
// поддержки. Снапшот движка (уже обогащён RTT-кэшем/proto/grace в ServiceEngine::debugSnapshot) +
// версия серверных bypass-списков (движок BypassListService не знает — сеем здесь) + bypassMasterOn
// (QSettings в QML-домене, как applyRuBypassSplit) + хвост лога приложения. Сборка/кламп — в
// header-only TribeDiagReport (покрыт tests/test_diag_report.cpp).
QString AvpnEngineQml::buildDiagReport() const
{
    avpn::DebugSnapshot s = m_engine.debugSnapshot();
    if (m_bypassListSvc)
        s.bypassListVersion = m_bypassListSvc->lkgVersion();

    avpn::DiagMeta meta;
    meta.appVersion = QCoreApplication::applicationVersion(); // tribe_version — как в bench-отчёте (benchExtra)
    meta.platform = QSysInfo::productType() + QLatin1Char(' ') + QSysInfo::productVersion();
    meta.lang = appLang();
    meta.configAppliedAgeSec = (m_lastConfigAppliedEpoch > 0)
        ? (QDateTime::currentSecsSinceEpoch() - m_lastConfigAppliedEpoch)
        : -1; // конфиг ещё не применялся → ключ опускается

    const bool bypassOn =
        QSettings().value(QStringLiteral("AvpnBypass/masterOn"), true).toBool();
    const QString logTail = avpn::TribeDiagReport::readLogTail(Logger::userLogsFilePath());
    return avpn::TribeDiagReport::build(s, bypassOn, logTail, meta);
}

// ── AVPN in-app Legal (Privacy/Terms) ────────────────────────────────────────
// PageLegalTribe: qrc-снапшот → legalDocCached() поверх → legalDocFetch() тихо
// обновляет. Кэш: AppDataLocation/legal/<doc>.<lang>.md. Ошибки сети молчаливые.

static QString legalCacheDir()
{
    return QStandardPaths::writableLocation(QStandardPaths::AppDataLocation)
           + QStringLiteral("/legal");
}

QString AvpnEngineQml::legalDocCached(const QString &doc, const QString &lang) const
{
    if (!LegalDocs::isValidDoc(doc) || !LegalDocs::isValidLang(lang))
        return {};
    // 1) дисковый кэш прошлого fetch; 2) qrc-снапшот из сборки. Читаем здесь, а не XHR
    // из QML: XMLHttpRequest к file:/qrc: по умолчанию ЗАПРЕЩЁН (QML_XHR_ALLOW_FILE_READ),
    // в проде qrc-фоллбек обязан работать без env-хаков.
    const QString name = LegalDocs::cacheFileName(doc, lang);
    for (const QString &path : { legalCacheDir() + QLatin1Char('/') + name,
                                 QStringLiteral(":/ui/qml/Tribe/legal/") + name }) {
        QFile f(path);
        if (!f.open(QIODevice::ReadOnly))
            continue;
        const QByteArray body = f.readAll();
        if (LegalDocs::looksLikeMarkdown(body))
            return QString::fromUtf8(body);
    }
    return {};
}

void AvpnEngineQml::legalDocFetch(const QString &doc, const QString &lang)
{
    if (!m_nam || !LegalDocs::isValidDoc(doc) || !LegalDocs::isValidLang(lang))
        return;
    // без дедупа запросов: страница дёргает fetch один раз на открытие, ответы идемпотентны
    QNetworkRequest req{QUrl(LegalDocs::url(doc, lang, configUrl(QStringLiteral("legal_base"), QStringLiteral("https://tribevpn.com/legal"))))};
    QNetworkReply *reply = m_nam->get(req);
    armTimeout(reply); // жёсткий таймаут без nested loop (abort → finished с code==0)
    connect(reply, &QNetworkReply::finished, this, [this, reply, doc, lang]() {
        reply->deleteLater();
        const int code = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        if (code != 200)
            return; // тихо: остаёмся на кэше/снапшоте
        const QByteArray body = reply->readAll();
        if (!LegalDocs::looksLikeMarkdown(body))
            return; // captive portal / страница ошибки — кэш не портим
        QDir().mkpath(legalCacheDir());
        QSaveFile f(legalCacheDir() + QLatin1Char('/') + LegalDocs::cacheFileName(doc, lang));
        if (f.open(QIODevice::WriteOnly)) {
            f.write(body);
            f.commit();
        }
        emit legalDocReady(doc, lang, QString::fromUtf8(body));
    });
}

// ── AVPN (Доктор v1, 2026-07-17): пользовательская диагностика ─────────────────────────────
// Канон машин (enum+epoch+guard) + дирижёр поверх готовых блоков: rx/tx-дельты снапшота,
// off-tunnel RTT (probeNodeRtt/кеш m_nodeRtt), reach-кворум + cdn-cgi/trace (только loc,
// IP отброшен), вердикт WhitelistDetector, lite-бенч. Вердикты стадий — чистый DoctorReport.h
// (юнит tests/doctor_report_check.cpp). Спека: specs/2026-07-17-doctor-v1-design.md.

void AvpnEngineQml::startDoctor(bool full)
{
    if (doctorRunning())
        return;
    if (!featureEnabled(QStringLiteral("diag_v2"), true))
        return; // kill-switch: бэк может выключить фичу без релиза
    // взаимоисключение с бенч-машинами: доктор делит BenchRunner и туннельные переходы
    if (m_benchRunning || sweepRunning() || abRunning() || ccRunning() || ftRunning())
        return;
    ++m_docEpoch;
    m_docFull = full && featureEnabled(QStringLiteral("doctor_full"), true);
    m_docStages.clear();
    m_docReport = QJsonObject();
    m_docBenchFull = QJsonObject();
    m_docSummary.clear();
    m_docBenchStarted = false;
    m_docConnecting = false;
    m_docWasConnected = (state() == QLatin1String("connected"));
    // D-3: сброс партиалов новых стадий
    m_docNetCaptive = -1;
    m_docNetWl = -1;
    m_docNetPending = 0;
    m_docTunIcmpMs = -1;
    m_docEpMs = -1; m_docEpBig = -1; m_docEpTried = false;          // D-6
    m_docAltEpMs = -1; m_docAltEpBig = -1; m_docAltEpTried = false; // D-6
    m_docSpeedDown = -1;
    m_docSpeedIdle = 0;
    m_docSpeedLoaded = 0;
    m_docSpeedCollapsed = false;
    CrashGuard::instance().setPhase("doctor");
    docStartNetwork();
}

// D-3: стадия 0 — сеть клиента ДО подъёма туннеля. Captive + сигналы платформы + форс-прогон
// дифф-проб белых списков. При уже поднятом туннеле captive/whitelist не валидны (пробы пойдут
// через VPN) — честные "-1", собираем только сигналы.
void AvpnEngineQml::docStartNetwork()
{
    docEnter(DoctorPhase::Network);
    const bool tunnelUp = m_docWasConnected;
    if (!tunnelUp) {
        // captive-детект: generate_204 МИМО туннеля; редирект/200 = портал подменяет ответы
        ++m_docNetPending;
        QNetworkRequest req{QUrl(QStringLiteral("https://connectivitycheck.gstatic.com/generate_204"))};
        req.setTransferTimeout(5000);
        req.setAttribute(QNetworkRequest::CacheLoadControlAttribute, QNetworkRequest::AlwaysNetwork);
        req.setAttribute(QNetworkRequest::RedirectPolicyAttribute, QNetworkRequest::ManualRedirectPolicy);
        QNetworkReply *rep = m_nam->head(req);
        connect(rep, &QNetworkReply::finished, this, [this, rep, e = m_docEpoch] {
            rep->deleteLater();
            if (e != m_docEpoch || m_docPhase != DoctorPhase::Network) return;
            const int code = rep->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
            if (code == 204)                    m_docNetCaptive = 0;
            else if (code >= 200 && code < 400) m_docNetCaptive = 1; // портал перехватил
            // сетевой фейл -> остаётся -1: «нет сети» != captive (не врём)
            docNetMaybeDone();
        });
        // форс-раунд белых списков (только мобилки+сотовая+опущенный туннель — гейты внутри)
        if (m_whitelistDetector) {
            const bool started = m_whitelistDetector->runRoundNow(
                [this, e = m_docEpoch](WlVerdict v, bool /*marginal*/) {
                    if (e != m_docEpoch || m_docPhase != DoctorPhase::Network) return;
                    m_docNetWl = (v == WlVerdict::Candidate) ? 1
                               : (v == WlVerdict::Normal || v == WlVerdict::SocialOnly) ? 0 : -1;
                    docNetMaybeDone();
                });
            if (started)
                ++m_docNetPending;
        }
    }
    if (m_docNetPending == 0)
        docNetMaybeDone();
}

int AvpnEngineQml::detectLanIpv6() const
{
    // Kill-switch: бэкенд может убрать фразу про IPv6 из Доктора без релиза.
    if (!avpn::TuningStore::flag(QStringLiteral("ipv6_notice"), true))
        return -1;

    QList<QPair<QString, QString>> snapshot;
    const auto ifaces = QNetworkInterface::allInterfaces();
    for (const QNetworkInterface &iface : ifaces) {
        const auto flags = iface.flags();
        // Погашенный или loopback-интерфейс — не «сеть пользователя».
        if (!flags.testFlag(QNetworkInterface::IsUp)
            || !flags.testFlag(QNetworkInterface::IsRunning)
            || flags.testFlag(QNetworkInterface::IsLoopBack))
            continue;
        const auto entries = iface.addressEntries();
        for (const QNetworkAddressEntry &entry : entries)
            snapshot.append({iface.name(), entry.ip().toString()});
    }
    return avpn::hasOffTunnelGlobalV6(snapshot);
}

void AvpnEngineQml::docNetMaybeDone()
{
    if (m_docNetPending > 0 && --m_docNetPending > 0)
        return; // ждём вторую параллельную пробу
    docStageDone(doctor::networkStage(
        m_docNetCaptive, benchExtra().value(QStringLiteral("net_type")).toString(),
        avpn::cellularGeneration(), avpn::meteredState(), avpn::roamingState(), m_docNetWl,
        benchExtra().value(QStringLiteral("carrier")).toString(), detectLanIpv6()));
}

void AvpnEngineQml::docStartConnect()
{
    docEnter(DoctorPhase::Connect);
    if (m_docWasConnected) {
        // VPN уже поднят — сразу проверяем, идут ли данные через туннель. Сторож ОБЯЗАТЕЛЕН:
        // у QNetworkReply нет таймаута общей длительности (урок NetAwait.h), а docEnter для
        // Connect guard не ставит — без него зависшая проба вешала Доктора навсегда (ревью v2 #1).
        m_docRx0 = m_tunnel.readStats().rxBytes;
        m_docGuard.start(15000);
        QTimer::singleShot(300, this, [this, e = m_docEpoch] {
            if (e == m_docEpoch && m_docPhase == DoctorPhase::Connect) docVerifyDataplane();
        });
    } else {
        // АКТИВНО: поднимаем VPN (авто-выбор лучшего по measuredRtt внутри start) и ждём connected
        m_docConnecting = true;
        m_docSawProgress = false;
        start();
        // сторож фазы Connect отдельный — подъём может занять дольше стандартной стадии
        m_docGuard.start(45000);
        // вдруг уже перескочило в connected до подписки — толкнём проверку
        QTimer::singleShot(0, this, [this, e = m_docEpoch] {
            if (e == m_docEpoch && m_docConnecting) docConnectAdvance();
        });
    }
}

void AvpnEngineQml::cancelDoctor()
{
    if (!doctorRunning())
        return;
    ++m_docEpoch; // стейл-колбэки всех стадий отбрасываются
    m_docGuard.stop();
    // отмена посреди перебора альтернатив — вернуть исходный выбор (fire-and-forget)
    if (m_docPhase == DoctorPhase::AltNodes) {
        if (!m_docOrigPin.isEmpty())
            pinAndReconnect(m_docOrigPin);
        else if (!m_docOrigNode.isEmpty())
            pinAndReconnect(m_docOrigNode);
    }
    m_docConnecting = false;
    if (m_docBenchStarted) {
        m_bench->cancel(); // после cancel сигналов НЕ будет — флаг бенча гасим сами
        m_docBenchStarted = false;
        m_benchRunning = false;
        emit benchChanged();
    }
    m_docPhase = DoctorPhase::Idle;
    CrashGuard::instance().setPhase(state() == QLatin1String("connected") ? "connected" : "idle");
    emit doctorChanged();
}

void AvpnEngineQml::docEnter(DoctorPhase ph)
{
    m_docPhase = ph;
    // базовый процент стадии (Speed дотикивает по benchStageFrac в проводке конструктора)
    switch (ph) {
    case DoctorPhase::Network:  m_docPercent = 3;  break;
    case DoctorPhase::Connect:  m_docPercent = 8;  break;
    case DoctorPhase::Servers:  m_docPercent = 36; break;
    case DoctorPhase::Services: m_docPercent = 46; break;
    case DoctorPhase::RuSplit:  m_docPercent = 58; break;
    case DoctorPhase::Speed:    m_docPercent = 66; break;
    case DoctorPhase::AltNodes: m_docPercent = 88; break;
    case DoctorPhase::Send:     m_docPercent = 97; break;
    case DoctorPhase::Idle:     break;
    }
    // сторож: server-tunable с клампом. Бенч-стадии нужен свой запас — numbers.doctor_speed_guard_ms
    // (жалоба владельца «иногда скорость проверяется очень долго»: было 60с намертво, теперь 45с
    // по умолчанию и рычаг у бэка). Фазы Connect и AltNodes ведут сторожа сами — НЕ перетираем.
    if (ph != DoctorPhase::Connect && ph != DoctorPhase::AltNodes) {
        const int base = doctor::clampStageTimeoutMs(
            TuningStore::numberOr(QStringLiteral("diag_stage_timeout_ms"), 0));
        const int spd = qBound(20000, int(TuningStore::numberOr(
                                   QStringLiteral("doctor_speed_guard_ms"), 45000.0)), 90000);
        m_docGuard.start(ph == DoctorPhase::Speed ? spd : base);
    }
    emit doctorChanged();
}

void AvpnEngineQml::docConnectAdvance()
{
    if (!m_docConnecting)
        return;
    // AltNodes: ждём подъёма на альтернативе (после pinAndReconnect)
    if (m_docPhase == DoctorPhase::AltNodes) {
        const QString st = state();
        if (st == QLatin1String("connected")) {
            m_docConnecting = false;
            m_docAltRx0 = m_tunnel.readStats().rxBytes; // база для «данные идут» (рост rx)
            m_docAltProbe1 = false; m_docAltIcmpMs = -1; m_docAltHsSec = -1;
            m_docAltEpMs = -1; m_docAltEpBig = -1; m_docAltEpTried = false; // D-6
            // сторож накрывает обе пробы: 800мс прогрев + проба1 + re-probe-гэп + проба2
            const int gap = qBound(3000, int(avpn::TuningStore::numberOr(
                                       QStringLiteral("doctor_alt_reprobe_ms"), 12000.0)), 30000);
            m_docGuard.start(gap + 16000);
            QTimer::singleShot(800, this, [this, e = m_docEpoch] {
                if (e == m_docEpoch && m_docPhase == DoctorPhase::AltNodes) docAltVerify();
            });
        } else if (st == QLatin1String("error")
                   || (st == QLatin1String("disconnected") && m_docSawProgress)) {
            m_docConnecting = false;
            m_docGuard.stop();
            m_docAltProbe1 = false; // альтернатива не поднялась — обе пробы «мимо»
            docAltRecord(/*probe2=*/false);
        } else if (st != QLatin1String("disconnected")) {
            m_docSawProgress = true;
        }
        return;
    }
    if (m_docPhase != DoctorPhase::Connect)
        return;
    const QString st = state();
    if (st == QLatin1String("connected")) {
        m_docConnecting = false;
        m_docRx0 = m_tunnel.readStats().rxBytes;
        // сторож ПЕРЕВЗВОДИМ на пробу данных (не гасим: зависший reply без него вешал бы фазу)
        m_docGuard.start(15000);
        // дать data-plane секунду прогреться перед пробой
        QTimer::singleShot(1000, this, [this, e = m_docEpoch] {
            if (e == m_docEpoch && m_docPhase == DoctorPhase::Connect) docVerifyDataplane();
        });
    } else if (st == QLatin1String("error")
               || (st == QLatin1String("disconnected") && m_docSawProgress)) {
        // error — коннект не удался; disconnected ПОСЛЕ начала подъёма — туннель остановили
        // извне (виджет/App Intent/grace-энфорс): честный вердикт сразу, не ждать 45с сторожа
        // (ревью v2 #3). Стартовый disconnected (start() ещё не перевёл машину) — НЕ провал.
        m_docConnecting = false;
        m_docGuard.stop();
        docStageDone(doctor::connectStage(/*couldConnect=*/false, false, -1));
    } else if (st != QLatin1String("disconnected")) {
        m_docSawProgress = true; // connecting/switching/selecting — подъём реально начался
    }
}

// D-6 (блок-профиль эндпоинта): запуск проб до IP ТЕКУЩЕЙ ноды МИМО туннеля — host-route WG
// выводит пакеты к эндпоинту в физический интерфейс даже при full-tunnel. Вместе с handshake/rx
// стадии различает ПРИЧИНУ смерти ноды у оператора: IP-блэкхол (echo мимо) vs фильтр по размеру
// пакета (маленький ок, большой DF-echo ~1400Б дропнут — профиль ТСПУ/DPI) vs верхние слои
// (оба ок, а 204 мимо). Возвращает IP для цели "ep" в общий probeAll вызывающего (пусто = не
// пробуем); большой echo уходит тут же отдельным сокетом (probeMtuOne самодостаточна, состояние
// probeAll не трогает). bigSink(ok) зовётся ТОЛЬКО для IPv4-литерала (probeMtuOne не резолвит
// хосты; не звался = «не мерили», не ложное «дропнут»). false при payload>MTU интерфейса =
// локальный EMSGSIZE — тоже честное «не проходит» (дефолт 1372+28=1400 < реальных MTU).
// Гейт features.doctor_ep_probe; размер — numbers.doctor_ep_big_payload (REMOTE-TUNING §1).
QString AvpnEngineQml::docEpProbeStart(std::function<void(bool)> bigSink)
{
    if (!m_docPing || !featureEnabled(QStringLiteral("doctor_ep_probe"), true))
        return QString();
    const QString epIp = currentNodeEndpointIp(currentNode());
    if (epIp.isEmpty())
        return QString();
    const QHostAddress lit(epIp);
    if (!lit.isNull() && lit.protocol() == QAbstractSocket::IPv4Protocol) {
        const int payload = qBound(200, int(avpn::TuningStore::numberOr(
                                       QStringLiteral("doctor_ep_big_payload"), 1372.0)), 1400);
        m_docPing->probeMtuOne(epIp, payload, 4000, std::move(bigSink));
    }
    return epIp;
}

void AvpnEngineQml::docVerifyDataplane()
{
    // проба generate_204 ЧЕРЕЗ туннель: первый байт получен ⇒ данные идут; параллельно смотрим
    // рост rx (сигнатура S4-blackhole: handshake есть, но rx стоит).
    const qint64 hsAge = debugSnapshot().value(QStringLiteral("latestHandshakeAgeSec")).toLongLong();
    // D-3 п.3: ICMP к 1.1.1.1 ЧЕРЕЗ туннель (default-route) — fire-and-collect, отдельный
    // инстанс (m_rttProbe гейтится connected⇒cancel). L3-жив != L7-жив: различает «туннель
    // доводит пакеты» от «HTTPS зарезан за нодой». Windows — стаб, результат просто не пишется.
    m_docTunIcmpMs = -1;
    m_docEpMs = -1; m_docEpBig = -1;
    const QString epIp = docEpProbeStart([this, e = m_docEpoch](bool ok) {
        if (e == m_docEpoch) m_docEpBig = ok ? 1 : 0;
    });
    m_docEpTried = !epIp.isEmpty();
    if (m_docPing) {
        QList<avpn::RttTarget> targets{{QStringLiteral("tunnel"), QStringLiteral("1.1.1.1"), 0}};
        if (!epIp.isEmpty())
            targets.append({QStringLiteral("ep"), epIp, 0});
        m_docPing->probeAll(targets, 3000,
            [this, e = m_docEpoch](const QString &id, int rttMs) {
                if (e != m_docEpoch || rttMs < 0) return;
                if (id == QLatin1String("ep")) {
                    if (m_docEpMs < 0 || rttMs < m_docEpMs) m_docEpMs = rttMs;
                } else if (m_docTunIcmpMs < 0 || rttMs < m_docTunIcmpMs) {
                    m_docTunIcmpMs = rttMs;
                }
            },
            [] {});
    }
    QNetworkRequest req{QUrl(QStringLiteral("https://connectivitycheck.gstatic.com/generate_204"))};
    req.setTransferTimeout(6000);
    req.setAttribute(QNetworkRequest::CacheLoadControlAttribute, QNetworkRequest::AlwaysNetwork);
    QNetworkReply *rep = m_nam->head(req);
    connect(rep, &QNetworkReply::finished, this, [this, rep, hsAge, e = m_docEpoch] {
        rep->deleteLater();
        if (e != m_docEpoch || m_docPhase != DoctorPhase::Connect) return;
        const int code = rep->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        const bool httpOk = rep->error() == QNetworkReply::NoError && code > 0;
        const qint64 rxNow = m_tunnel.readStats().rxBytes;
        const bool rxGrew = rxNow > m_docRx0;
        doctor::StageResult r = doctor::connectStage(/*couldConnect=*/true, httpOk || rxGrew, hsAge);
        if (m_docTunIcmpMs >= 0)
            r.data.insert(QStringLiteral("tunnel_icmp_ms"), m_docTunIcmpMs);
        if (m_docEpTried) { // D-6: блок-профиль эндпоинта текущей ноды (docEpProbeStart)
            r.data.insert(QStringLiteral("ep_icmp_ms"), m_docEpMs); // -1 = IP молчит мимо туннеля
            if (m_docEpBig != -1)
                r.data.insert(QStringLiteral("ep_icmp_big"), m_docEpBig == 1);
        }
        docStageDone(r);
    });
}

void AvpnEngineQml::docStageDone(const doctor::StageResult &r)
{
    m_docGuard.stop();
    m_docStages.append(r);
    emit doctorChanged();
    const DoctorPhase donePh = m_docPhase;
    QTimer::singleShot(0, this, [this, e = m_docEpoch, donePh] {
        if (e != m_docEpoch)
            return;
        switch (donePh) {
        case DoctorPhase::Network:  docStartConnect();  break;
        case DoctorPhase::Connect:  docStartServers();  break;
        case DoctorPhase::Servers:  docStartServices(); break;
        case DoctorPhase::Services: docStartRuSplit();  break; // при вкл. сплите — RU-корпус
        case DoctorPhase::RuSplit:  docStartSpeed();    break;
        case DoctorPhase::Speed:    docStartAltNodes(); break; // при проблеме — до 2 альтернатив
        case DoctorPhase::AltNodes: docFinish();        break;
        default: break;
        }
    });
}

void AvpnEngineQml::docGuardFired()
{
    // стадия не уложилась в сторож: честный частичный вердикт, диагностика продолжается
    switch (m_docPhase) {
    case DoctorPhase::Network:
        // собираем что успели (незавершённые пробы останутся -1 — честно)
        m_docNetPending = 0;
        docStageDone(doctor::networkStage(
            m_docNetCaptive, benchExtra().value(QStringLiteral("net_type")).toString(),
            avpn::cellularGeneration(), avpn::meteredState(), avpn::roamingState(), m_docNetWl,
            benchExtra().value(QStringLiteral("carrier")).toString(), detectLanIpv6()));
        break;
    case DoctorPhase::Connect: {
        // сторож: либо не поднялись (45с), либо зависла проба данных (15с) — вердикт по факту
        m_docConnecting = false;
        const bool up = (state() == QLatin1String("connected"));
        docStageDone(doctor::connectStage(/*couldConnect=*/up, /*dataFlows=*/false,
            up ? debugSnapshot().value(QStringLiteral("latestHandshakeAgeSec")).toLongLong() : -1));
        break;
    }
    case DoctorPhase::Servers: {
        const QVariantMap cur = currentNode();
        QString nm = cur.value(QStringLiteral("name")).toString();
        const QString cc = cur.value(QStringLiteral("countryCode")).toString();
        if (nm.isEmpty()) nm = doctor::countryNameRu(cc);
        docStageDone(doctor::serverStage(nm, cc, -1));
        break;
    }
    case DoctorPhase::Services:
        docStageDone(doctor::servicesStage(0, 0, {}, false, false));
        break;
    case DoctorPhase::Speed:
        if (m_docBenchStarted) { // сторож добил бенч: cancel молчалив — флаг гасим сами
            m_bench->cancel();
            m_docBenchStarted = false;
            m_benchRunning = false;
            emit benchChanged();
            docStageDone(doctor::speedStage(-1, 0, 0));
        } else {
            // бенч УСПЕЛ, завис A/B-замер мимо туннеля — не терять реальный результат бенча
            docStageDone(doctor::speedStage(m_docSpeedDown, m_docSpeedIdle, m_docSpeedLoaded,
                                            m_docSpeedCollapsed, -1));
        }
        break;
    case DoctorPhase::RuSplit:
        // не все пробы успели — вердикт по собранному (m_docRuOks предзаполнен false по индексам)
        docStageDone(doctor::ruSplitStage(m_docRuNames, m_docRuOks));
        break;
    case DoctorPhase::AltNodes:
        // подъём/проба альтернативы не уложились в сторож. Если проба 1 уже прошла (зависла
        // проба 2) — это нестабильная нода (одна проба), не мёртвая: docAltRecord с probe2=false.
        m_docConnecting = false;
        docAltRecord(/*probe2=*/false);
        break;
    case DoctorPhase::Send:
        docFinish();
        break;
    case DoctorPhase::Idle:
        break;
    }
}

void AvpnEngineQml::docStartServers()
{
    docEnter(DoctorPhase::Servers);
    // туннель поднят (фаза Connect его подняла/подтвердила) — показываем текущий сервер и его
    // live-отклик (app-layer RTT через туннель; off-tunnel ICMP при connected смазан, §11).
    QTimer::singleShot(500, this, [this, e = m_docEpoch] {
        if (e != m_docEpoch || m_docPhase != DoctorPhase::Servers) return;
        const QVariantMap cur = currentNode();
        QString nm = cur.value(QStringLiteral("name")).toString();
        const QString cc = cur.value(QStringLiteral("countryCode")).toString();
        if (nm.isEmpty()) nm = doctor::countryNameRu(cc); // «lv» → «Латвия» + флаг по cc в UI
        const int rtt = liveReachable() ? liveRttMs() : -1;
        // порог жёлтого server-driven (пересмотр владельца: до ~секунды — зелёный)
        const int warnMs = qBound(300, int(avpn::TuningStore::numberOr(
                                      QStringLiteral("doctor_rtt_warn_ms"), 800.0)), 3000);
        docStageDone(doctor::serverStage(nm, cc, rtt, warnMs));
    });
}

void AvpnEngineQml::docStartServices()
{
    docEnter(DoctorPhase::Services);
    // Туннель не поднят (Connect провалился) — probeServices() тихо no-op'нется, а
    // m_serviceStatus хранит СТАРЫЕ вердикты прошлой сессии: читать их = ложное
    // «мессенджеры работают» рядом с «не удалось подключиться» (ревью v2 #2). Честный Skip.
    if (state() != QLatin1String("connected")) {
        docStageDone(doctor::servicesStage(0, 0, {}, false, false));
        return;
    }
    // РЕАЛЬНАЯ проверка сервисов ЧЕРЕЗ туннель: WhatsApp/Telegram/YouTube/Instagram (те же
    // чипы, что на главном экране). Запускаем пробу и ждём заполнения m_serviceStatus.
    probeServices();
    QTimer::singleShot(9000, this, [this, e = m_docEpoch] {
        if (e != m_docEpoch || m_docPhase != DoctorPhase::Services) return;
        int works = 0, total = 0;
        QStringList blocked;
        for (const QVariant &v : std::as_const(m_serviceStatus)) {
            const QVariantMap m = v.toMap();
            const int stt = m.value(QStringLiteral("state")).toInt();
            const QString label = m.value(QStringLiteral("label")).toString();
            if (stt < 0) continue; // unknown/не измерено — не считаем ни за, ни против
            ++total;
            if (stt == 0)      blocked.append(label);  // Blocked
            else if (stt >= 2) ++works;                // Works (Slow не блок, но и не «недоступно»)
        }
        const QString net = benchExtra().value(QStringLiteral("net_type")).toString();
        const bool wlApplicable = (m_whitelistDetector != nullptr) && net == QLatin1String("cellular");
        const bool wlActive = m_whitelistDetector && m_whitelistDetector->active();
        docStageDone(doctor::servicesStage(works, total, blocked, wlApplicable, wlActive));
    });
}

void AvpnEngineQml::docStartSpeed()
{
    docEnter(DoctorPhase::Speed);
    if (m_benchRunning) { // гонка с админ-панелью — честный Skip, не второй бенч
        docStageDone(doctor::speedStage(-1, 0, 0));
        return;
    }
    m_docBenchStarted = true;
    m_benchRunning = true;
    m_benchStage = QStringLiteral("start"); // benchStageFrac() тикает процент Speed-стадии
    emit benchChanged();
    const bool lite = TuningStore::numberOr(QStringLiteral("diag_bench_lite"), 1) != 0;
    m_bench->start(QStringLiteral("doctor"), benchExtra(), lite,
                   currentNodeEndpointIp(currentNode()));
}

// D-3 п.19: A/B — тот же класс замера МИМО туннеля. На мобилках off-tunnel HTTP возможен
// только маршрутом байпаса (RU-endpoint при включённом «Доступе к РФ»), поэтому гейты:
// подозрение (коллапс/медленно) + server-driven urls.diag_ru_speed_url задан (пустой
// фолбэк = стадия без A/B, бэк включает без релиза) + сплит включён. Кап: 8с транспортом.
void AvpnEngineQml::docDirectSpeed(double down, int idle, int loaded, bool collapsed)
{
    m_docSpeedDown = down; // партиалы: сторож фазы не должен терять готовый бенч
    m_docSpeedIdle = idle;
    m_docSpeedLoaded = loaded;
    m_docSpeedCollapsed = collapsed;
    const bool suspicious = collapsed || (down >= 0 && down < 5.0);
    const QString url = configUrl(QStringLiteral("diag_ru_speed_url"), QString());
    bool masterOn = false;
    {
        QSettings st;
        masterOn = st.value(QStringLiteral("AvpnBypass/masterOn"), false).toBool();
    }
    if (!suspicious || url.isEmpty() || !masterOn) {
        docStageDone(doctor::speedStage(down, idle, loaded, collapsed, -1));
        return;
    }
    m_docGuard.start(15000); // свой сторож на контрольный замер (Speed-сторож мог истечь)
    QNetworkRequest req{QUrl(url)};
    req.setTransferTimeout(8000);
    req.setAttribute(QNetworkRequest::CacheLoadControlAttribute, QNetworkRequest::AlwaysNetwork);
    auto *t = new QElapsedTimer();
    t->start();
    QNetworkReply *rep = m_nam->get(req);
    auto bytes = std::make_shared<qint64>(0);
    connect(rep, &QNetworkReply::readyRead, this, [rep, bytes] {
        *bytes += rep->readAll().size();
        if (*bytes > 6 * 1024 * 1024)
            rep->abort(); // кап трафика: 6 МБ хватает для оценки, замер закончит finished
    });
    connect(rep, &QNetworkReply::finished, this,
            [this, rep, t, bytes, down, idle, loaded, collapsed, e = m_docEpoch] {
        rep->deleteLater();
        const qint64 ms = t->elapsed();
        delete t;
        if (e != m_docEpoch || m_docPhase != DoctorPhase::Speed) return;
        // abort после капа — валидный замер; настоящий фейл = байтов почти нет
        const double direct = (*bytes > 64 * 1024 && ms > 300)
                                  ? avpn::BenchRunner::mbit(*bytes, ms) : -1.0;
        docStageDone(doctor::speedStage(down, idle, loaded, collapsed, direct));
    });
}

void AvpnEngineQml::docStartRuSplit()
{
    docEnter(DoctorPhase::RuSplit);
    // Выключенный «Доступ к сайтам РФ» — честный Skip с причиной (раньше фаза молча
    // пропускалась, и поддержка не видела, что сплит у клиента вовсе не включён).
    bool masterOn = false;
    {
        QSettings st;
        masterOn = st.value(QStringLiteral("AvpnBypass/masterOn"), false).toBool();
    }
    if (!masterOn) {
        docStageDone(doctor::ruSplitStage({}, {}, /*enabled=*/false));
        return;
    }
    // Корпус server-driven — ЕДИНЫЙ ключ lists.rusplit_watch с дозорным RuSplitSentinel
    // (фолбэк rusentinel::defaultWatch: Яндекс/Ozon/Wildberries/Госуслуги, "Имя|URL").
    // BUG-5 (2026-07-22): было HEAD + требование error()==NoError — бот-защита VK/Аэрофлота
    // отвечает 418/403 на HEAD ⇒ вечное ложное «Не открылись» в КАЖДОМ отчёте на любой сети.
    // Теперь GET (обрываем после заголовков — тело не тянем) + успех = ЛЮБОЙ HTTP-код <500
    // (семантика rusentinel::classifyProbe: ответ дошёл ⇒ маршрут до сайта работает).
    const QStringList raw =
        TuningStore::listOr(QStringLiteral("rusplit_watch"), rusentinel::defaultWatch());
    m_docRuNames.clear(); m_docRuOks.clear();
    m_docRuPending = 0;
    QStringList urls;
    for (const QString &entry : raw) {
        QString name, url;
        if (!rusentinel::parseWatchEntry(entry, name, url))
            continue;
        m_docRuNames.append(name);
        m_docRuOks.append(false); // предзаполнение по индексам (параллельные колбэки)
        urls.append(url);
    }
    if (m_docRuNames.isEmpty()) {
        docStageDone(doctor::ruSplitStage({}, {}));
        return;
    }
    for (int i = 0; i < urls.size(); ++i) {
        ++m_docRuPending;
        QNetworkRequest req{QUrl(urls.at(i))};
        req.setTransferTimeout(6000);
        req.setAttribute(QNetworkRequest::CacheLoadControlAttribute, QNetworkRequest::AlwaysNetwork);
        req.setAttribute(QNetworkRequest::RedirectPolicyAttribute, QNetworkRequest::ManualRedirectPolicy);
        QNetworkReply *rep = m_nam->get(req);
        auto code = std::make_shared<int>(0);
        connect(rep, &QNetworkReply::metaDataChanged, this, [rep, code] {
            if (*code > 0)
                return;
            *code = rep->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
            if (*code > 0)
                rep->abort(); // заголовков достаточно для вердикта — трафик не жжём
        });
        connect(rep, &QNetworkReply::finished, this, [this, rep, code, i, e = m_docEpoch] {
            rep->deleteLater();
            if (e != m_docEpoch || m_docPhase != DoctorPhase::RuSplit) return;
            int c = *code;
            if (c <= 0)
                c = rep->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
            if (i < m_docRuOks.size())
                m_docRuOks[i] = (c > 0 && c < 500);
            if (--m_docRuPending <= 0)
                docStageDone(doctor::ruSplitStage(m_docRuNames, m_docRuOks));
        });
    }
}

void AvpnEngineQml::docStartAltNodes()
{
    // Триггер (быстрый режим): только при реальной проблеме на текущей ноде И наличии
    // альтернатив. Различает «нода сломана» (альтернатива работает → остаёмся на ней) от
    // «сеть/оператор» (все мертвы → честный вердикт + возврат исходного выбора).
    // Полный режим (m_docFull): обзор ВСЕХ кандидатов независимо от проблемы — без ранней
    // остановки на первой рабочей; в конце пересадка только если проблема БЫЛА.
    m_docAltHadProblem = doctor::hasProblem(m_docStages);
    if (!m_docFull && !m_docAltHadProblem) {
        docFinish();
        return;
    }
    const QVariantMap cur = currentNode();
    const QString curId = cur.value(QStringLiteral("nodeId")).toString();
    // очередь: живые поддерживаемые ноды, отсортированные по измеренному RTT (кеш), != текущей
    QList<QPair<int, QVariantMap>> cand;
    const QVariantList pool = debugSnapshot().value(QStringLiteral("pool")).toList();
    for (const QVariant &v : pool) {
        const QVariantMap n = v.toMap();
        if (!n.value(QStringLiteral("alive")).toBool()) continue;
        const QString id = n.value(QStringLiteral("nodeId")).toString();
        if (id.isEmpty() || id == curId) continue;
        if (!avpn::isSupportedProto(n.value(QStringLiteral("proto")).toString())) continue;
        // manual_only/RU (§14.3) — вне авто-выбора ВЕЗДЕ: иначе Доктор проверял бы RU-ноду и,
        // пройди её проба, пересадил бы пользователя на RU-egress (реальный случай 2026-07-20).
        if (n.value(QStringLiteral("manualOnly")).toBool()) continue;
        // Канон владельца (полная диагностика): RU-нода ВСЕГДА в исключениях — ремень поверх
        // manual_only на случай, если флаг у RU-ноды когда-нибудь снимут на бэке.
        if (n.value(QStringLiteral("countryCode")).toString()
                .compare(QStringLiteral("RU"), Qt::CaseInsensitive) == 0) continue;
        const int rtt = m_nodeRtt.value(id, 99999);
        cand.append({rtt, n});
    }
    std::sort(cand.begin(), cand.end(),
              [](const auto &a, const auto &b) { return a.first < b.first; });
    m_docAltQueue.clear(); m_docAltNames.clear(); m_docAltOks.clear();
    m_docAltDetails.clear(); m_docAltCand.clear();
    m_docAltIdx = -1;
    // Быстрый режим: до 3 самых быстрых альтернатив (doctor_alt_max). Полный: все кандидаты
    // (кап doctor_full_max — предохранитель от гигантского пула). Каждую держим и пробуем
    // ДВАЖДЫ (сразу + после ~keepalive) — ловит «handshake есть, данные пропали через 20с».
    const int altMax = m_docFull
        ? qBound(3, int(avpn::TuningStore::numberOr(
                      QStringLiteral("doctor_full_max"), 12.0)), 20)
        : qBound(1, int(avpn::TuningStore::numberOr(
                      QStringLiteral("doctor_alt_max"), 3.0)), 5);
    for (const auto &c : cand) {
        if (m_docAltQueue.size() >= altMax) break;
        const QString id = c.second.value(QStringLiteral("nodeId")).toString();
        m_docAltQueue.append(id);
        QString nm = c.second.value(QStringLiteral("name")).toString();
        const QString cc = c.second.value(QStringLiteral("countryCode")).toString();
        if (nm.isEmpty())
            nm = doctor::countryNameRu(cc);
        m_docAltNames.append(nm);
        QVariantMap meta;
        meta.insert(QStringLiteral("name"), nm);
        meta.insert(QStringLiteral("cc"), cc);
        meta.insert(QStringLiteral("nodeId"), id);
        meta.insert(QStringLiteral("rtt_ms"), c.first < 99999 ? c.first : -1);
        m_docAltCand.append(meta);
    }
    if (m_docAltQueue.isEmpty()) {
        docFinish();
        return;
    }
    m_docOrigNode = curId;
    m_docOrigPin = m_engine.pinnedNodeId();
    docEnter(DoctorPhase::AltNodes);
    docAltNext();
}

void AvpnEngineQml::docAltNext()
{
    // Быстрый режим: предыдущая альтернатива оказалась СТАБИЛЬНОЙ (обе пробы) → остаёмся на
    // ней (юзеру сразу хорошо), дальше не перебираем. Нестабильная (одна проба из двух =
    // задержанный blackhole) НЕ считается рабочей — перебираем дальше, ищем по-настоящему
    // живую. Полный режим ранней остановки НЕ делает — обзор всех кандидатов до конца.
    if (!m_docFull
        && m_docAltIdx >= 0 && m_docAltIdx < m_docAltOks.size() && m_docAltOks.at(m_docAltIdx)) {
        docStageDone(doctor::altNodesStage(
            m_docAltNames.mid(0, m_docAltIdx + 1), m_docAltOks,
            /*switchedTo=*/m_docAltNames.at(m_docAltIdx),
            QJsonArray::fromVariantList(m_docAltDetails)));
        return;
    }
    ++m_docAltIdx;
    if (m_docAltIdx >= m_docAltQueue.size()) {
        // Конец очереди. Пересадка ТОЛЬКО если проблема была (в полном режиме сюда доходим
        // всегда — обзор без проблемы не должен молча менять сервер пользователю): сначала
        // лучшая стабильная (полный режим), потом нестабильная (хоть что-то), иначе — возврат
        // исходного выбора. Fire-and-forget.
        int bestStable = -1;
        for (int i = 0; i < m_docAltOks.size(); ++i)
            if (m_docAltOks.at(i)) { bestStable = i; break; } // первый = самый быстрый по RTT
        int bestShaky = -1;
        for (int i = 0; i < m_docAltDetails.size(); ++i)
            if (m_docAltDetails.at(i).toMap().value(QStringLiteral("verdict")).toInt() == 1) {
                bestShaky = i; break;
            }
        QString switchedTo;
        if (m_docAltHadProblem && bestStable >= 0 && bestStable < m_docAltQueue.size()) {
            pinAndReconnect(m_docAltQueue.at(bestStable));
            switchedTo = m_docAltNames.value(bestStable);
        } else if (m_docAltHadProblem && bestShaky >= 0 && bestShaky < m_docAltQueue.size()) {
            pinAndReconnect(m_docAltQueue.at(bestShaky));
            switchedTo = m_docAltNames.value(bestShaky);
        } else if (!m_docOrigPin.isEmpty()) {
            pinAndReconnect(m_docOrigPin);
        } else if (!m_docOrigNode.isEmpty()) {
            pinAndReconnect(m_docOrigNode);
        }
        docStageDone(doctor::altNodesStage(m_docAltNames, m_docAltOks, switchedTo,
                                           QJsonArray::fromVariantList(m_docAltDetails)));
        return;
    }
    // полный обзор долгий — прогресс тикает по числу пройденных нод (70..96%)
    if (m_docFull && !m_docAltQueue.isEmpty())
        m_docPercent = 70 + (26 * m_docAltIdx) / m_docAltQueue.size();
    m_docConnecting = true;
    m_docSawProgress = false;
    m_docGuard.start(40000); // подъём альтернативы
    emit doctorChanged();    // note текущей стадии в UI обновится (docStage прежний)
    pinAndReconnect(m_docAltQueue.at(m_docAltIdx)); // stop→start на выбранную (путь пикера)
}

// Проба 1 сразу после connected: HEAD 204 + ICMP через туннель + возраст handshake. Результат
// НЕ финализируем — планируем пробу 2 после ~keepalive (задержанный blackhole S4/ТСПУ виден
// только тогда: handshake жив, data-плейн умирает через ~20-28с).
void AvpnEngineQml::docAltVerify()
{
    m_docAltHsSec = debugSnapshot().value(QStringLiteral("latestHandshakeAgeSec")).toLongLong();
    // D-6: блок-профиль эндпоинта альтернативы — мы к ней подключены, host-route активен
    const QString epIp = docEpProbeStart([this, e = m_docEpoch](bool ok) {
        if (e == m_docEpoch) m_docAltEpBig = ok ? 1 : 0;
    });
    m_docAltEpTried = !epIp.isEmpty();
    if (m_docPing) {
        QList<avpn::RttTarget> targets{{QStringLiteral("tunnel"), QStringLiteral("1.1.1.1"), 0}};
        if (!epIp.isEmpty())
            targets.append({QStringLiteral("ep"), epIp, 0});
        m_docPing->probeAll(targets, 3000,
            [this, e = m_docEpoch](const QString &id, int rttMs) {
                if (e != m_docEpoch || rttMs < 0) return;
                if (id == QLatin1String("ep")) {
                    if (m_docAltEpMs < 0 || rttMs < m_docAltEpMs) m_docAltEpMs = rttMs;
                } else if (m_docAltIcmpMs < 0 || rttMs < m_docAltIcmpMs) {
                    m_docAltIcmpMs = rttMs;
                }
            },
            [] {});
    }
    QNetworkRequest req{QUrl(QStringLiteral("https://connectivitycheck.gstatic.com/generate_204"))};
    req.setTransferTimeout(6000);
    req.setAttribute(QNetworkRequest::CacheLoadControlAttribute, QNetworkRequest::AlwaysNetwork);
    QNetworkReply *rep = m_nam->head(req);
    connect(rep, &QNetworkReply::finished, this, [this, rep, e = m_docEpoch] {
        rep->deleteLater();
        if (e != m_docEpoch || m_docPhase != DoctorPhase::AltNodes) return;
        const int code = rep->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        m_docAltProbe1 = rep->error() == QNetworkReply::NoError && code > 0;
        const int gap = qBound(3000, int(avpn::TuningStore::numberOr(
                                   QStringLiteral("doctor_alt_reprobe_ms"), 12000.0)), 30000);
        QTimer::singleShot(gap, this, [this, e = m_docEpoch] {
            if (e == m_docEpoch && m_docPhase == DoctorPhase::AltNodes) docAltVerify2();
        });
    });
}

// Проба 2 (после гэпа): второй HEAD 204. verdict сводит обе.
void AvpnEngineQml::docAltVerify2()
{
    QNetworkRequest req{QUrl(QStringLiteral("https://connectivitycheck.gstatic.com/generate_204"))};
    req.setTransferTimeout(6000);
    req.setAttribute(QNetworkRequest::CacheLoadControlAttribute, QNetworkRequest::AlwaysNetwork);
    QNetworkReply *rep = m_nam->head(req);
    connect(rep, &QNetworkReply::finished, this, [this, rep, e = m_docEpoch] {
        rep->deleteLater();
        if (e != m_docEpoch || m_docPhase != DoctorPhase::AltNodes) return;
        const int code = rep->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        docAltRecord(/*probe2=*/rep->error() == QNetworkReply::NoError && code > 0);
    });
}

// Свести обе пробы в per-нода деталь. verdict: 2=обе прошли (стабильна), 1=одна (нестабильна,
// задержанный blackhole), 0=обе мимо (мертва). m_docAltOks[idx] = стабильна (для switch-логики).
void AvpnEngineQml::docAltRecord(bool probe2)
{
    m_docGuard.stop();
    const qint64 rxNow = m_tunnel.readStats().rxBytes;
    const bool rxGrew = rxNow > m_docAltRx0;
    const int hits = (m_docAltProbe1 ? 1 : 0) + (probe2 ? 1 : 0);
    const int verdict = hits >= 2 ? 2 : (hits == 1 ? 1 : 0);
    QVariantMap d = (m_docAltIdx >= 0 && m_docAltIdx < m_docAltCand.size())
                        ? m_docAltCand.at(m_docAltIdx).toMap() : QVariantMap{};
    d.insert(QStringLiteral("probe1"), m_docAltProbe1);
    d.insert(QStringLiteral("probe2"), probe2);
    d.insert(QStringLiteral("rx_grew"), rxGrew);
    d.insert(QStringLiteral("handshake_sec"), double(m_docAltHsSec));
    if (m_docAltIcmpMs >= 0) d.insert(QStringLiteral("tunnel_icmp_ms"), m_docAltIcmpMs);
    if (m_docAltEpTried) { // D-6: блок-профиль эндпоинта (docEpProbeStart)
        d.insert(QStringLiteral("ep_icmp_ms"), m_docAltEpMs); // -1 = IP молчит мимо туннеля
        if (m_docAltEpBig != -1)
            d.insert(QStringLiteral("ep_icmp_big"), m_docAltEpBig == 1);
    }
    d.insert(QStringLiteral("verdict"), verdict);
    m_docAltDetails.append(d);
    m_docAltOks.append(verdict >= 2); // РАБОЧАЯ только если стабильна (обе пробы)
    docAltNext();
}

void AvpnEngineQml::docFinish()
{
    docEnter(DoctorPhase::Send);
    {
        QJsonObject extra = benchExtra();
        extra.insert(QStringLiteral("doctor_mode"),
                     m_docFull ? QStringLiteral("full") : QStringLiteral("quick"));
        if (!m_docBenchFull.isEmpty()) // полный lite-бенч: разложение dns/tls/http/ping для анализа
            extra.insert(QStringLiteral("bench"), m_docBenchFull);
        // CR-1: локальный счётчик аварийных смертей на мобилках (dirty_exit там не шлётся
        // отдельным отчётом — ОС штатно убивает фон; но в контексте Доктора он информативен)
        const int dirty = CrashGuard::instance().dirtyExitCount();
        if (dirty > 0) {
            extra.insert(QStringLiteral("dirty_exits_since_last"), dirty);
            CrashGuard::instance().resetDirtyExitCount();
        }
        m_docReport = doctor::buildReport(m_docStages, extra);
    }
    m_docSummary = m_docReport.value(QStringLiteral("summary")).toString();
    m_docHasProblem = doctor::hasProblem(m_docStages);
    // Анонимный отчёт на control plane ВСЕГДА (наш анализ /v1/bench/report — все прогоны,
    // и удачные, и проблемные, для улучшения пула). В ТРЕД поддержки шлёт QML — и ТОЛЬКО
    // при проблеме (нет сбоев ⇒ не дёргаем поддержку и не пишем «ожидайте ответа»).
    if (featureEnabled(QStringLiteral("diag_upload"), true))
        uploadReport(QString::fromUtf8(
                         QJsonDocument(m_docReport).toJson(QJsonDocument::Compact)),
                     /*quiet=*/true);
    m_docGuard.stop();
    m_docPhase = DoctorPhase::Idle;
    m_docPercent = 100;
    CrashGuard::instance().setPhase(state() == QLatin1String("connected") ? "connected" : "idle");
    emit doctorChanged();
    emit doctorFinished();
}

// CR-1: отправить накопленные краш-отчёты прошлых запусков. Best-effort + оптимистичный
// markSent (дубликаты в телеметрии хуже редкой потери — отчёт уже классифицирован локально).
void AvpnEngineQml::crashFlushPending()
{
    if (!featureEnabled(QStringLiteral("crash_report"), true))
        return; // kill-switch: бэк глушит поток без релиза
    const QList<QJsonObject> pend = CrashGuard::instance().takePendingReports();
    for (QJsonObject r : pend) {
        const QString id = r.take(QStringLiteral("_pending_id")).toString();
        if (id.isEmpty())
            continue;
        uploadReport(QString::fromUtf8(QJsonDocument(r).toJson(QJsonDocument::Compact)),
                     /*quiet=*/true);
        CrashGuard::instance().markSent(id);
    }
}

QString AvpnEngineQml::doctorReportJson() const
{
    if (m_docReport.isEmpty())
        return {};
    return QString::fromUtf8(QJsonDocument(m_docReport).toJson(QJsonDocument::Compact));
}

// AVPN (Доктор): ручной оператор — QSettings AvpnDiag/carrier (benchExtra отдаёт ему приоритет
// над авто MCC-MNC). На iOS 16+ Apple закрыл CTCarrier → это единственный способ узнать оператора.
void AvpnEngineQml::setDiagCarrier(const QString &code)
{
    QSettings s;
    if (code.isEmpty())
        s.remove(QStringLiteral("AvpnDiag/carrier"));
    else
        s.setValue(QStringLiteral("AvpnDiag/carrier"), code);
    s.sync();
    emit changed();
}

QString AvpnEngineQml::diagCarrier() const
{
    const QString manual = QSettings().value(QStringLiteral("AvpnDiag/carrier")).toString();
    return manual.isEmpty() ? avpn::carrierCode() : manual;
}

QString AvpnEngineQml::diagCarrierAuto() const
{
    return avpn::carrierCode();
}

// AVPN (волна UX Доктора 07-22): авто-тип сети для интро-шагов. БЕЗ ручного фолбэка — по нему
// интро решает, задавать ли вопрос «какой у вас интернет» (авто знает → не спрашиваем).
QString AvpnEngineQml::doctorNetType() const
{
    static const bool niLoaded = QNetworkInformation::loadDefaultBackend();
    if (niLoaded) {
        if (auto *ni = QNetworkInformation::instance()) {
            switch (ni->transportMedium()) {
            case QNetworkInformation::TransportMedium::Ethernet: return QStringLiteral("ethernet");
            case QNetworkInformation::TransportMedium::WiFi:     return QStringLiteral("wifi");
            case QNetworkInformation::TransportMedium::Cellular: return QStringLiteral("cellular");
            default: break;
            }
        }
    }
    // iOS на сотовой: Qt отдаёт Unknown, CoreTelephony знает (работает и под VPN)
    if (!avpn::cellularGeneration().isEmpty())
        return QStringLiteral("cellular");
    return {};
}

// Ручной тип сети из интро. НЕ персистится (сеть меняется между запусками) — живёт до
// перезапуска приложения; benchExtra берёт его только когда авто-детект промолчал.
void AvpnEngineQml::setDiagNetType(const QString &t)
{
    const QString v = (t == QLatin1String("wifi") || t == QLatin1String("cellular"))
                          ? t : QString();
    if (m_diagNetManual == v)
        return;
    m_diagNetManual = v;
    emit changed();
}

// Операторы РФ для плашки интро (server-driven lists.doctor_operators, формат "MCC-MNC|Имя").
// Фолбэк — актуальные операторы 2026: большая четвёрка + заметные MVNO (Т-Мобайл экс-Тинькофф,
// СберМобайл, МОТИВ, Ростелеком). "other" = «Другой»: ценность выбора — категория для паттернов
// «оператор X режет ноду Y», точный MNC не обязателен.
QVariantList AvpnEngineQml::diagOperators() const
{
    static const QStringList def{
        QStringLiteral("250-01|МТС"),
        QStringLiteral("250-02|МегаФон"),
        QStringLiteral("250-99|Билайн"),
        QStringLiteral("250-20|T2"),
        QStringLiteral("250-11|Yota"),
        QStringLiteral("250-62|Т-Мобайл"),
        QStringLiteral("250-40|СберМобайл"),
        QStringLiteral("250-35|МОТИВ"),
        QStringLiteral("250-39|Ростелеком"),
        QStringLiteral("other|Другой"),
    };
    QVariantList out;
    const QStringList raw = TuningStore::listOr(QStringLiteral("doctor_operators"), def);
    for (const QString &e : raw) {
        const int sep = e.indexOf(QLatin1Char('|'));
        if (sep <= 0)
            continue;
        QVariantMap m;
        m.insert(QStringLiteral("code"), e.left(sep).trimmed());
        m.insert(QStringLiteral("name"), e.mid(sep + 1).trimmed());
        out.append(m);
    }
    return out;
}

QString AvpnEngineQml::doctorHumanReport() const
{
    // Читаемое резюме для менеджера поддержки: текст-СООБЩЕНИЕ в тред (сырой diag.log
    // оператору бесполезен — вложение остаётся для разработчика).
    const QJsonObject extra = benchExtra();
    return doctor::humanReport(m_docStages,
                               extra.value(QStringLiteral("net_type")).toString(),
                               extra.value(QStringLiteral("tz")).toString());
}

QString AvpnEngineQml::doctorDiagText() const
{
    QString txt = buildDiagReport();
    const QString json = doctorReportJson();
    if (!json.isEmpty())
        txt += QStringLiteral("\n=== DOCTOR v1 ===\n") + json + QStringLiteral("\n");
    return txt;
}

QString AvpnEngineQml::doctorStage() const
{
    switch (m_docPhase) {
    case DoctorPhase::Network:  return QStringLiteral("network");
    case DoctorPhase::Connect:  return QStringLiteral("connect");
    case DoctorPhase::Servers:  return QStringLiteral("servers");
    case DoctorPhase::Services: return QStringLiteral("services");
    case DoctorPhase::RuSplit:  return QStringLiteral("rusplit");
    case DoctorPhase::Speed:    return QStringLiteral("speed");
    case DoctorPhase::AltNodes: return QStringLiteral("altnodes");
    case DoctorPhase::Send:     return QStringLiteral("send");
    case DoctorPhase::Idle:     break;
    }
    return {};
}

QVariantList AvpnEngineQml::doctorStages() const
{
    QVariantList out;
    for (const auto &s : m_docStages) {
        QVariantMap m;
        m.insert(QStringLiteral("id"), s.id);
        m.insert(QStringLiteral("status"), s.status);
        m.insert(QStringLiteral("note"), s.note);
        // серверная стадия несёт country_code/region/rtt — попап рисует «Сервер: [флаг] Страна · мс»
        const QString cc = s.data.value(QStringLiteral("country_code")).toString();
        if (!cc.isEmpty()) {
            m.insert(QStringLiteral("countryCode"), cc);
            m.insert(QStringLiteral("region"), s.data.value(QStringLiteral("region")).toString());
            m.insert(QStringLiteral("rttMs"), s.data.value(QStringLiteral("rtt_ms")).toInt(-1));
        }
        // волна UX 07-22: факты текущей ноды (вкладка «текущий сервер» в финале попапа)
        if (s.id == QLatin1String("connect")) {
            m.insert(QStringLiteral("dataFlows"),
                     s.data.value(QStringLiteral("data_flows")).toBool());
            if (s.data.contains(QStringLiteral("tunnel_icmp_ms")))
                m.insert(QStringLiteral("tunnelIcmpMs"),
                         s.data.value(QStringLiteral("tunnel_icmp_ms")).toInt(-1));
            if (s.data.contains(QStringLiteral("ep_icmp_ms")))
                m.insert(QStringLiteral("epIcmpMs"),
                         s.data.value(QStringLiteral("ep_icmp_ms")).toInt(-1));
            if (s.data.contains(QStringLiteral("ep_icmp_big")))
                m.insert(QStringLiteral("epIcmpBig"),
                         s.data.value(QStringLiteral("ep_icmp_big")).toBool());
        }
        // per-нода факты обзора альтернатив — вкладки по серверам в финале попапа
        if (s.id == QLatin1String("altnodes") && s.data.contains(QStringLiteral("details")))
            m.insert(QStringLiteral("details"),
                     s.data.value(QStringLiteral("details")).toArray().toVariantList());
        out.append(m);
    }
    return out;
}

} // namespace avpn
