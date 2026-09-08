// AVPN serviceEngine — тонкий QObject-фасад движка для QML (context property "AvpnEngine").
// Владеет ServiceEngine + VpnConnectionTunnelControl; гоняет health-tick (QTimer) и слушает
// VpnConnection::connectionStateChanged (реактивный failover). Конвертит DebugSnapshot → QVariantMap
// для PageDiagnostics.qml. Overlay: апстрим не трогаем, только публичные API форка. [IN-FORK build]
#pragma once

#include "ConfigService.h" // AVPN remote-config (T5/T6): ConfigService + RemoteConfig (featureEnabled/configUrl/updateState)
#include "ServiceEngine.h"
#include "ServiceProbe.h"    // AVPN backend-first (Task 4): ServiceProbeConfig — m_svcCfgsAll (kill-switch чипов)
#include "SignalQuality.h"   // AVPN: RTT→0..5 баров (EWMA+гистерезис)
#include "SelfUpdate.h"      // AVPN (2026-09-02): установка обновления внутри приложения (macOS)
#include "TuningStore.h"     // AVPN backend-first (T10): probeServicesIntervalMs inline-геттер
#include "VpnConnectionTunnelControl.h"

#include "core/protocols/vpnProtocol.h" // AVPN: Vpn::ConnectionState
#include "core/utils/errorCodes.h"      // AVPN: amnezia::ErrorCode

#include <QElapsedTimer> // AVPN (панель администратора): connect_ms в свипе нод
#include <QHash>
#include <QHostAddress> // AVPN RU-direct carve-out: IP API вне байпаса
#include <QJsonArray>    // AVPN (панель администратора): результаты свипа
#include <QMap>          // AVPN remote-config (T6): sites-карта в rebuildApiCarveOut(sites)
#include <QObject>
#include <QSet>
#include <QString>
#include <QTimer>
#include <QVariantList>
#include <QVariantMap>

#include <functional> // AVPN (Доктор D-6): sink большого DF-echo блок-профиля эндпоинта

#include "DoctorReport.h" // AVPN (Доктор v1): чистые вердикты стадий диагностики (юнит-покрыты)

class VpnConnection;
class SecureAppSettingsRepository;
class QNetworkAccessManager;

namespace avpn {

class QualityProbe; // AVPN: app-layer RTT-проба через туннель (QualityProbe.h)
class ServiceProbe; // AVPN: проба доступности сервисов (Telegram/YouTube) через туннель (ServiceProbe.h)
class IRttProbe;    // AVPN (выбор по скорости): прямой RTT до нод off-tunnel (IRttProbe.h / RttProbeIcmp)
class BenchRunner;  // AVPN (панель администратора): in-app бенч соединения (BenchRunner.h)
class BypassListService; // AVPN server-driven АнтиВПН (Task 10): серверные bypass-списки (BypassListService.h)
class WhitelistDetector; // AVPN (белые списки): детект РКН-режима «работает только whitelist» (WhitelistDetector.h)
class RuSplitSentinel;   // AVPN (Доктор D-3 п.26): фоновый дозор RU-сайтов при вкл. сплите (RuSplitSentinel.h)

class AvpnEngineQml : public QObject {
    Q_OBJECT
    Q_PROPERTY(QString state READ state NOTIFY changed)
    Q_PROPERTY(bool busy READ busy NOTIFY changed)
    // AVPN: направление активного перехода — движок занят ОПУСКАНИЕМ туннеля (намерение = офлайн).
    // Источник правды для «не показывать Connecting… при выключении»: живёт в движке (не в странице),
    // поэтому переживает пересоздание страницы и покрывает ВСЕ пути teardown (орб/шторка/отмена коннекта).
    Q_PROPERTY(bool stopping READ stopping NOTIFY changed)
    // AVPN (macOS, beachball-фикс 2026-07-21): идёт установка root-демона Tribe-service (фоновый
    // поток, GUI живой) — QML показывает «Устанавливаем службу VPN…» вместо «Подбираем сервер…».
    // На остальных платформах всегда false.
    Q_PROPERTY(bool svcInstalling READ svcInstalling NOTIFY changed)
    // AVPN awg31-xray-v1 (спека 2026-09-01 §2.3): ручной режим транспорта "auto"|"awg"|"xray"
    // (локальная настройка QSettings avpn/transportMode; setTransportMode), фаза verifying
    // (xray поднят, ждём первую удачную пробу через туннель — UI «Проверяем трафик…», орб ещё не
    // «подключено») и транспорт текущей ноды ("awg"/"xray"; пусто = не подключены) для бейджа.
    Q_PROPERTY(QString transportMode READ transportMode NOTIFY changed)
    Q_PROPERTY(bool verifying READ verifying NOTIFY changed)
    Q_PROPERTY(QString activeProto READ activeProto NOTIFY changed)
    // AVPN: статус подписки для бейджа Connect (читается из загруженной Subscription через движок).
    Q_PROPERTY(int daysLeft READ daysLeft NOTIFY changed)
    // AVPN (group-aware, 2026-07-21): ISO-дата конца подписки из /v1/subscription (device-часы,
    // бэк учитывает группу). Для UI-дат — ТОЛЬКО она; account.expires_at (аккаунт-часы) для
    // дат не использовать: рассинхрон «361 дн. · до <прошлогодняя дата>» у членов групп.
    // Пусто = бессрочно/ещё не загружено (daysLeft тогда -1).
    Q_PROPERTY(QString subExpiresAt READ subExpiresAt NOTIFY changed)
    Q_PROPERTY(qlonglong trafficUsed READ trafficUsed NOTIFY changed)
    Q_PROPERTY(qlonglong trafficLimit READ trafficLimit NOTIFY changed)
    Q_PROPERTY(bool subActive READ subActive NOTIFY changed)
    // AVPN (перенос «как SIM»): бэк ответил 410 transferred на /v1/subscription|/v1/account —
    // подписка УЕХАЛА на другое устройство. Терминально до ре-энролла/нового ключа; self-heal
    // НЕ ре-энроллит (Enrollment::decideAuthRecovery). UI показывает «Подписка перенесена».
    Q_PROPERTY(bool transferredAway READ transferredAway NOTIFY changed)
    // AVPN (баг 2026-07-10 «вечная загрузка без подписки»): бэк авторитетно ответил 200 со
    // status=degraded и nodes:[] — подписки у устройства НЕТ (не «ещё грузится»). UI по этому
    // флагу показывает золотую CTA вместо бесконечного «Локации загружаются…». Выводится из
    // снапшота (degraded + пустой пул), без липкого стейта (ревью: sticky-флаг давал ложную CTA
    // платящему юзеру при транзиентно пустом пуле со status=active — все ноды в дренаже).
    Q_PROPERTY(bool subMissing READ subMissing NOTIFY changed)
    // AVPN (белые списки, спека 2026-07-12): РКН-режим «работает только whitelist» на сотовой —
    // детект дифф-пробами (control мертвы ВСЕ + >=2 whitelist живы, вкл. маркетплейс). UI кажет
    // центрированный попап «подключитесь к Wi-Fi» вместо вечного Connecting (subMissing этот
    // случай не покрывает — тело от бэка не приходит). Механизм общий, активация — iOS/Android.
    Q_PROPERTY(bool whitelistMode READ whitelistMode NOTIFY whitelistModeChanged)
    // «Понятно» нажато для ТЕКУЩЕГО эпизода (сессионное): false = попап виден. Сбрасывается
    // при новом эпизоде И при тапе коннекта в активном режиме (PageConnectTribe) -> попап снова.
    Q_PROPERTY(bool whitelistAcked READ whitelistAcked NOTIFY whitelistAckedChanged)
    // AVPN (sub-grace): движок САМ погасил туннель — «подписка истекла и грейс (+N ч,
    // numbers.subscription_grace_hours) прошёл» (enforceSubscriptionGrace из onTick). UI отличает
    // это от ручного выключения (подпись «Доступ приостановлен…» вместо «Отключено»).
    // Сбрасывается при следующем явном start().
    Q_PROPERTY(bool subEnforcedStop READ subEnforcedStop NOTIFY changed)
    // AVPN: JWT подписки — для авторизованного редиректа в кабинет (кнопка «Обновить ключ»).
    Q_PROPERTY(QString authToken READ authToken NOTIFY changed)
    // AVPN: реальные серверы (вместо хардкода). currentNode = {region,endpoint,ip,connected,hasNode};
    // nodePool = список нод [{nodeId,region,endpoint,...}] из живой подписки.
    Q_PROPERTY(QVariantMap currentNode READ currentNode NOTIFY changed)
    Q_PROPERTY(QVariantList nodePool READ nodePool NOTIFY changed)
    // AVPN (live-node picker): Pro-гейт-заглушка. Сейчас всегда true (trial выбирает уже сейчас);
    // позже выбор сервера гейтится этим одним флагом. CONSTANT — значение не меняется в рантайме.
    Q_PROPERTY(bool proSelectionEnabled READ proSelectionEnabled CONSTANT)
    // AVPN (store-flow, 2026-07-09): сборка для сторов (-DTRIBE_STORE_BUILD=ON, cmake/avpn.cmake).
    // true → в UI НЕТ прямых платёжных переходов: «Управлять подпиской» скрыта, золотая CTA ведёт
    // на карточку «Активировать ключ» + чат поддержки (полиси Google Play Payments / Apple §3.1.1).
    // CONSTANT by design: compile-time, НЕ рантайм-флаг (переключение после ревью = cloaking).
    Q_PROPERTY(bool storeBuild READ storeBuild CONSTANT)
    // AVPN: имя/ОС ТЕКУЩЕГО устройства, добытые НАТИВНО (DeviceModel.h: IOKit на macOS, sysctl+таблица
    // на iOS). Перекрывают невнятный backend-label (часто = платформа «macos»). CONSTANT — не меняется.
    Q_PROPERTY(QString thisDeviceName READ thisDeviceName CONSTANT)
    Q_PROPERTY(QString thisDeviceOs READ thisDeviceOs CONSTANT)
    // AVPN (анти-фриз/анти-краш): устройства и статус аккаунта грузятся АСИНХРОННО (без вложенного
    // QEventLoop на GUI-потоке). UI биндится на эти property; refreshDevices()/refreshAccount() лишь
    // запускают фоновый GET, результат прилетает через devicesChanged()/accountChanged().
    Q_PROPERTY(QVariantList devices READ devices NOTIFY devicesChanged)
    Q_PROPERTY(QVariantMap account READ account NOTIFY accountChanged)
    // AVPN (admin-гейт): серверный флаг devices.is_admin из /v1/account — «Панель администратора»
    // видна ТОЛЬКО помеченным устройствам. Оффлайн/401/нет ключа → m_account пуста → false.
    Q_PROPERTY(bool isAdminDevice READ isAdminDevice NOTIFY accountChanged)
    // AVPN (i18n): язык приложения "ru"/"en"/"es" для переключателя в Tribe-настройках.
    // Хранение/цепочка ретрансляции — апстримные (SecureAppSettingsRepository::setAppLanguage →
    // appLanguageChanged → LanguageUiController → CoreController::updateTranslator → retranslate).
    Q_PROPERTY(QString appLang READ appLang NOTIFY appLangChanged)
    // AVPN (рефералы #37): GET /v1/referral → {code, link, invited, days_earned} для баннера «Поделиться».
    Q_PROPERTY(QVariantMap referral READ referral NOTIFY referralChanged)
    // AVPN (объявления P-ANN): активные server-driven объявления для этого устройства.
    // Элемент: {id:int, kind:"popup"|"inbox_only", title, body, image_url, buttons:[{id,label,action,value}]}.
    // Контент приходит уже в языке устройства; прочитанные локально/на сервере сюда не попадают.
    Q_PROPERTY(QVariantList announcements READ announcements NOTIFY announcementsChanged)
    // AVPN (Task 7): туннель на «авто-паузе для покупок» (реально down, ждём авто-возврат). // AVPN
    Q_PROPERTY(bool paused READ paused NOTIFY changed)
    // AVPN (реальные палочки): живое качество ТЕКУЩЕГО соединения, измеренное app-layer RTT-пробой
    // ЧЕРЕЗ туннель (TCP-пинг до AWG-UDP-порта не достукивается; per-node RTT остальных нод off-tunnel
    // меряет RttProbeIcmp, см. probeNodeRtt). liveBars 0..5 (EWMA+гистерезис),
    // liveRttMs — сглаженный RTT (−1 = ещё не мерили/нет связи), liveReachable — дошла ли проба.
    Q_PROPERTY(int liveRttMs READ liveRttMs NOTIFY liveQualityChanged)
    Q_PROPERTY(int liveBars READ liveBars NOTIFY liveQualityChanged)
    Q_PROPERTY(bool liveReachable READ liveReachable NOTIFY liveQualityChanged)
    // AVPN (красные палочки): true ТОЛЬКО когда проба подтверждённо не доходит (kLiveDeadStreak подряд) —
    // отличает «ещё мерю / только подключились» от «связь мертва». UI рисует 0 зелёных + все красные.
    Q_PROPERTY(bool liveDead READ liveDead NOTIFY liveQualityChanged)
    // AVPN (чипы доступности): статус сервисов через ЭТУ ноду. Список [{key,label,state,rttMs}],
    // state: -1 неизв / 0 заблок / 1 медленно(троттл) / 2 работает. Замер — с устройства через туннель.
    Q_PROPERTY(QVariantList serviceStatus READ serviceStatus NOTIFY serviceStatusChanged)
    // AVPN (панель администратора): in-app бенч соединения (BenchRunner; схема результата =
    // tools/connect-bench репо tribe-front, сводится общим summarize.sh). Меряет ТЕКУЩИЙ путь
    // (NE-туннель системный ⇒ подходит и для замера ванильной Amnezia). Итог — сигнал benchFinished.
    Q_PROPERTY(bool benchRunning READ benchRunning NOTIFY benchChanged)
    Q_PROPERTY(QString benchStage READ benchStage NOTIFY benchChanged)
    // AVPN (панель администратора): авто-свип ВСЕХ нод — на каждой: pin→connect (замер connect_ms)→
    // lite-бенч→next; в конце восстановление исходного pin/подключения. Итог — сигнал sweepFinished.
    Q_PROPERTY(bool sweepRunning READ sweepRunning NOTIFY sweepChanged)
    Q_PROPERTY(QString sweepProgress READ sweepProgress NOTIFY sweepChanged)
    // AVPN (панель администратора, авто-A/B): при подключённом Tribe одна кнопка сама меряет пару
    // bypass-on↔bypass-off: full-бенч на текущем тумблере → setBypassMasterOn(!x) (reconcile сам
    // передёргивает туннель) → второй бенч → возврат тумблера. Метки выводятся из ФАКТИЧЕСКОГО
    // состояния настроек — ошибиться меткой невозможно. Итог — abFinished (type:"ab-bypass").
    Q_PROPERTY(bool abRunning READ abRunning NOTIFY abChanged)
    Q_PROPERTY(QString abProgress READ abProgress NOTIFY abChanged)
    // AVPN (bench v5, connect{}): «Тест коннекта» — N циклов disconnect→connect→verify ТОЛЬКО
    // публичными переходами (stop()/start(), фактические состояния по changed()). Меряет сам
    // КОННЕКТ (v1-v4 меряли путь после): teardown_ms/connect_ms/handshake_ms/first_byte_ms +
    // verify (данные реально ходят). Итог — ccFinished (type:"connect-cycle").
    Q_PROPERTY(bool ccRunning READ ccRunning NOTIFY ccChanged)
    Q_PROPERTY(QString ccProgress READ ccProgress NOTIFY ccChanged)
    // AVPN (bench v5.2, мастер «Полный тест»): дирижёр поверх готовых машин — этап 1 сам
    // (коннект-цикл → авто-A/B → свип нод), два ручных гейта (Amnezia / baseline, второй скипается),
    // финал = единый мега-отчёт (ftFinished). ftStage — для карточки мастера в QML:
    // "connect0|cc|ab|sweep|wait-amnezia|bench-amnezia|wait-baseline|bench-baseline".
    Q_PROPERTY(bool ftRunning READ ftRunning NOTIFY ftChanged)
    Q_PROPERTY(QString ftStage READ ftStage NOTIFY ftChanged)
    Q_PROPERTY(QString ftProgress READ ftProgress NOTIFY ftChanged)
    // v5.4: прогресс мастера 0..100 (взвешенные этапы + доля стадии текущего бенча) — для
    // прогресс-бара; и последний мега-отчёт (живёт в движке+QSettings — переживает навигацию
    // и перезапуск, «тест не сбрасывается»).
    Q_PROPERTY(int ftPercent READ ftPercent NOTIFY ftChanged)
    Q_PROPERTY(QString lastFullTestJson READ lastFullTestJson NOTIFY ftChanged)
    // v5.5: судьба последней отправки отчёта на сервер («Отправлен ✓ (HH:mm)» / причина) — видно
    // в финальной карточке мастера, а не только мимолётным тостом.
    Q_PROPERTY(QString uploadStatus READ uploadStatus NOTIFY ftChanged)
    // AVPN (Доктор v1): попап диагностики — статус машины/стадия/процент/список стадий/резюме.
    Q_PROPERTY(bool doctorRunning READ doctorRunning NOTIFY doctorChanged)
    Q_PROPERTY(QString doctorStage READ doctorStage NOTIFY doctorChanged)
    Q_PROPERTY(int doctorPercent READ doctorPercent NOTIFY doctorChanged)
    Q_PROPERTY(QVariantList doctorStages READ doctorStages NOTIFY doctorChanged)
    Q_PROPERTY(QString doctorSummary READ doctorSummary NOTIFY doctorChanged)
    Q_PROPERTY(bool doctorHasProblem READ doctorHasProblem NOTIFY doctorChanged)
    // AVPN remote-config (T6): вердикт force-update (0 Ok/1 Recommend/2 Block, из ConfigService::configApplied)
    // + магазинная ссылка (urls.store_ios/store_android с сервера, фолбэк вшитый) — баннер апдейта/CTA.
    Q_PROPERTY(int updateState READ updateState NOTIFY changed)
    // AVPN (реш. владельца 2026-09-02): экран обновления обязан называть ОБЕ версии — «было → стало».
    // Без них сообщение «доступна новая версия» неотличимо от старого/ошибочного, и человек не
    // понимает, обновился он уже или нет.
    Q_PROPERTY(QString appVersion READ appVersion CONSTANT)
    Q_PROPERTY(QString availableVersion READ availableVersion NOTIFY changed)
    Q_PROPERTY(QString storeUrl READ storeUrl NOTIFY changed)
    // AVPN (реш. владельца 2026-09-02): на десктопном macOS кнопка «Обновить» ставит новую версию
    // сама (скачивание нашего dmg + проверка подписи/нотаризации/версии). На остальных платформах
    // false — UI открывает страницу загрузки/стор, как раньше.
    Q_PROPERTY(bool canSelfUpdate READ canSelfUpdate CONSTANT)
    // AVPN backend-first (T10): интервал авто-self-heal чипов сервисов (PageConnectTribe.qml) —
    // server-tunable (numbers.probe_services_interval_ms), фолбэк вкомпиленные 180000мс (3 мин).
    Q_PROPERTY(int probeServicesIntervalMs READ probeServicesIntervalMs NOTIFY changed)
    // AVPN backend-first (Task 9): реф-вкладка — kill-switch (features.referral, default TRUE —
    // отсутствие ключа НЕ прячет вкладку). TribeBottomNav.qml прячет её при !referralEnabled.
    Q_PROPERTY(bool referralEnabled READ referralEnabled NOTIFY changed)
    // AVPN backend-first (Task 9): домен веб-кабинета (urls.cabinet) — CTA «Продлить»/«Аккаунт»
    // (PageConnectTribe/PageAccountTribe), фолбэк вкомпиленный https://tribevpn.com/account.
    Q_PROPERTY(QString cabinetUrl READ cabinetUrl NOTIFY changed)
    // AVPN backend-first (Task 9): поллинг «перенос принят» (PageAccountTribe) — server-tunable
    // (numbers.transfer_poll_ms), фолбэк 4000мс, клампы 1с..10мин.
    Q_PROPERTY(int transferPollMs READ transferPollMs NOTIFY changed)
    // AVPN backend-first-3 (Task 8): троттл авто-refresh подписки на возврат приложения в фон/
    // foreground (PageConnectTribe.qml, Qt.application.onStateChanged) — server-tunable
    // (numbers.fg_refresh_throttle_ms), фолбэк 30000мс, клампы 1с..10мин.
    Q_PROPERTY(int fgRefreshThrottleMs READ fgRefreshThrottleMs NOTIFY changed)
    // AVPN backend-first (Task 9): ретрай-поллинг рефералки (PageReferralTribe) — server-tunable
    // (numbers.referral_retry_ms), фолбэк 6000мс, клампы 1с..10мин.
    Q_PROPERTY(int referralRetryMs READ referralRetryMs NOTIFY changed)
    // AVPN (diag, Task 5 bff-3): отправка диагностики в чат поддержки — kill-switch
    // (features.support_diag, default TRUE). PageSupportTribe прячет пункт меню при false;
    // сам sendDiagReport гейтится и в C++ (TribeSupportChat).
    Q_PROPERTY(bool supportDiagEnabled READ supportDiagEnabled NOTIFY changed)
    // AVPN backend-first-3 (Task 6): перенос подписки «как SIM» — kill-switch (features.transfer,
    // default TRUE — без сервера/на старом конфиге поведение не меняется). PageAccountTribe прячет
    // карточку «Перенос на новое устройство» при false; redeemTransfer/createTransfer гейтятся
    // тем же флагом в C++ (единая воронка: deep-link tribe://transfer, Universal Link, QR-скан,
    // ввод в поле — все сходятся в redeemTransfer через AvpnDeepLinkBridge → coreController).
    Q_PROPERTY(bool transferEnabled READ transferEnabled NOTIFY changed)
    // AVPN backend-first-3 (Task 7): incident-баннер из подписанного /v1/config — единственный
    // анонимно-достижимый канал оповещения (пуш/чат требуют enrollment). Текст локализованный
    // (strings.incident_text_<lang> → _en → base через TuningStore::localizedOr), пусто = баннера
    // нет; incident_url опционален (тап → браузер). PageConnectTribe встраивает баннер в якорную
    // цепочку updateBanner → incidentBanner → autoVpnCard. Пересчёт: configApplied и setAppLang
    // эмитят changed().
    Q_PROPERTY(QString incidentText READ incidentText NOTIFY changed)
    Q_PROPERTY(QString incidentUrl READ incidentUrl NOTIFY changed)
    // AVPN backend-first-3 (Task 7): server-driven CTA-тексты оплаты — map по ключам
    // cta_renew_traffic/cta_renew_access/cta_how_traffic/cta_how_access (localizedOr; пустые НЕ
    // кладём — QML фолбэчит на вкомпиленный qsTr-литерал). PATCH client_urls меняет CTA без релиза.
    Q_PROPERTY(QVariantMap hotTexts READ hotTexts NOTIFY changed)
    // AVPN backend-first-3 (Task 9): server-driven состав/порядок бренд-плиток онбординга
    // (lists.onboarding_brand_tiles). PageOnboardingTribe.qml держит вкомпиленный реестр
    // tileDefs (ключи-слаги — "whatsapp"/"telegram"/…); сервер может ТОЛЬКО выбрать подмножество
    // и порядок ИЗ ЭТИХ ключей (неизвестный ключ скипается на QML-стороне, новые глифы требуют
    // релиза). Пусто/отсутствие ключа → фолбэк на вкомпиленный порядок (listOr «пусто=фолбэк»).
    Q_PROPERTY(QStringList onboardingBrandTiles READ onboardingBrandTiles NOTIFY changed)
public:
    AvpnEngineQml(VpnConnection *conn, SecureAppSettingsRepository *store,
                  QNetworkAccessManager *nam, QObject *parent = nullptr);

    QString state() const;
    bool busy() const { return m_busy; }
    // busy при намерении «офлайн» = идёт teardown (вкл. отмену недоехавшего коннекта). // AVPN
    bool stopping() const { return m_busy && !m_wantConnected; }
    // AVPN (macOS): идёт фоновая установка root-демона (см. Q_PROPERTY выше). Прочие ОС — false.
    bool svcInstalling() const { return m_svcInstalling; }
    // AVPN awg31-xray-v1: см. Q_PROPERTY transportMode/verifying/activeProto выше.
    QString transportMode() const;
    bool verifying() const;
    QString activeProto() const;
    // Переключатель «Авто / Amnezia / Xray» пикера (mode: "auto"|"awg"|"xray"; kill-switch не
    // нужен — локальная настройка). Режим "xray" при неподдерживаемом xray (платформа/kill-switch
    // xray_client) отклоняется с тостом. На поднятом туннеле, чей транспорт новому режиму не
    // соответствует, — реконнект ТОЛЬКО через reconcile+m_needsRestart (как pinAndReconnect).
    Q_INVOKABLE void setTransportMode(const QString &mode);

    // AVPN: статус подписки (Task 3). daysLeft<0 = бессрочно/неизвестно; trafficLimit==0 = безлимит.
    int daysLeft() const;
    QString subExpiresAt() const;
    qlonglong trafficUsed() const;
    qlonglong trafficLimit() const;
    bool subActive() const;
    bool transferredAway() const { return m_transferredAway; }
    // AVPN: «подписки нет» достоверно — снапшот говорит degraded (бэк ставит его ТОЛЬКО по
    // состоянию устройства: expired/over-quota/без tunnel_ip) И пул пуст. active+пустой пул
    // (все ноды в дренаже у подписанного юзера) сюда НЕ попадает. Без липкого члена — правда
    // пересчитывается из текущего снапшота на каждом changed().
    bool subMissing() const;
    // AVPN (белые списки): см. Q_PROPERTY whitelistMode/whitelistAcked выше.
    bool whitelistMode() const;
    bool whitelistAcked() const { return m_whitelistAcked; }
    Q_INVOKABLE void setWhitelistAcked(bool on);
    // AVPN (sub-grace): см. Q_PROPERTY subEnforcedStop выше.
    bool subEnforcedStop() const { return m_subEnforcedStop; }
    QString authToken() const;  // AVPN: JWT из защищённого стора (Enrollment::loadToken)

    // AVPN: реальные серверы для UI (карточка Connect + страница Серверы).
    QVariantMap currentNode() const;
    QVariantList nodePool() const;
    // AVPN (live-node picker): Pro-гейт-заглушка — выбор сервера доступен (сейчас всегда true).
    bool proSelectionEnabled() const { return true; }
    // AVPN (store-flow): compile-time флаг store-сборки (см. Q_PROPERTY storeBuild выше).
    bool storeBuild() const
    {
#ifdef TRIBE_STORE_BUILD
        return true;
#else
        return false;
#endif
    }

    // AVPN: текущее устройство (нативно). Реализация в .cpp — DeviceModel.h тянет Apple-фреймворки,
    // держим их вне этого заголовка (его инклудят многие TU).
    QString thisDeviceName() const;
    QString thisDeviceOs() const;

    // AVPN: кэш последнего async-ответа /v1/devices и /v1/account (для биндинга в QML).
    QVariantList devices() const { return m_devices; }
    QVariantMap account() const { return m_account; }
    // AVPN (admin-гейт): пустая мапа / отсутствие ключа → QVariant().toBool() == false.
    bool isAdminDevice() const { return m_account.value(QStringLiteral("is_admin")).toBool(); }

    // AVPN (i18n): текущий язык ("ru"/"en"/"es" — префикс локали) и смена из QML.
    QString appLang() const;
    Q_INVOKABLE void setAppLang(const QString &lang);
    QVariantMap referral() const { return m_referral; }   // AVPN (#37): кэш GET /v1/referral
    QVariantList announcements() const { return m_announcements; } // AVPN (P-ANN): кэш /v1/announcements

    // Control plane base URL (BACKEND §2). Можно переопределить из настроек.
    void setBaseUrl(const QString &url) { m_baseUrl = url; }
    // AVPN backend-first (2026-07-10): текущий активный edge-хост control plane — для сателлитов
    // вроде TribeSupportChat, которым нужен тот же хост, что у движка (см. apiBaseChanged).
    QString apiBase() const { return m_baseUrl; }

    // AVPN remote-config (T6, server-driven — без ребилда): фичефлаги/URL из /v1/config (ConfigService).
    // featureEnabled/configUrl читают ПОСЛЕДНИЙ применённый конфиг (LKG на старте, свежий после fetch).
    Q_INVOKABLE bool    featureEnabled(const QString &key, bool def = false) const;
    Q_INVOKABLE QString configUrl(const QString &key, const QString &def) const;
    int     updateState() const { return m_updateState; }
    QString storeUrl() const;
    bool canSelfUpdate() const { return avpn::SelfUpdate::isSupported(); }
    // Маркетинговая версия приложения (первые три компонента APP_VERSION, без номера сборки).
    QString appVersion() const;
    // Версия, которую предлагает control plane для ЭТОЙ платформы (recommended_version, при его
    // отсутствии — min_app_version). Пусто = сервер ничего не предлагает.
    QString availableVersion() const;
    // Запускает установку обновления (idempotent: повторный вызов во время установки — no-op).
    Q_INVOKABLE void startSelfUpdate();

    // AVPN backend-first (T10): интервал авто-self-heal чипов сервисов — см. Q_PROPERTY выше.
    int probeServicesIntervalMs() const
    { return int(avpn::TuningStore::numberOr(QStringLiteral("probe_services_interval_ms"), 180000)); }

    // AVPN backend-first (Task 9): реф-вкладка/кабинет-URL/поллинг — см. Q_PROPERTY выше.
    bool referralEnabled() const { return avpn::TuningStore::flag(QStringLiteral("referral")); }
    // AVPN (diag, Task 5 bff-3): kill-switch отправки диагностики — см. Q_PROPERTY выше.
    bool supportDiagEnabled() const { return avpn::TuningStore::flag(QStringLiteral("support_diag")); }
    // AVPN backend-first-3 (Task 6): kill-switch переноса подписки — см. Q_PROPERTY выше.
    bool transferEnabled() const { return avpn::TuningStore::flag(QStringLiteral("transfer")); }
    QString cabinetUrl() const
    {
        return avpn::TuningStore::stringOr(QStringLiteral("cabinet"),
                                            QStringLiteral("https://tribevpn.com/account"));
    }
    // AVPN backend-first-3 (Task 7): incident-баннер + hot-тексты CTA — см. Q_PROPERTY выше.
    // Дефолты пустые НАМЕРЕННО: пусто = «инцидента нет», баннер скрыт / CTA на qsTr-фолбэке.
    QString incidentText() const
    {
        return avpn::TuningStore::localizedOr(QStringLiteral("incident_text"), appLang(),
                                              QString());
    }
    QString incidentUrl() const
    {
        return avpn::TuningStore::stringOr(QStringLiteral("incident_url"), QString());
    }
    QVariantMap hotTexts() const;   // .cpp: localizedOr по 4 CTA-ключам, пустые не кладём
    int transferPollMs() const
    {
        return qBound(1000, int(avpn::TuningStore::numberOr(QStringLiteral("transfer_poll_ms"), 4000)),
                      600000);
    }
    int referralRetryMs() const
    {
        return qBound(1000, int(avpn::TuningStore::numberOr(QStringLiteral("referral_retry_ms"), 6000)),
                      600000);
    }
    // AVPN backend-first-3 (Task 8): fg-refresh троттл — см. Q_PROPERTY выше.
    int fgRefreshThrottleMs() const
    {
        return qBound(1000, int(avpn::TuningStore::numberOr(QStringLiteral("fg_refresh_throttle_ms"), 30000)),
                      600000);
    }
    // AVPN backend-first-3 (Task 9): бренд-плитки онбординга — см. Q_PROPERTY выше.
    QStringList onboardingBrandTiles() const
    { return avpn::TuningStore::listOr(QStringLiteral("onboarding_brand_tiles"), {}); }

    // --- QML API (для PageHomeTribe / PageDiagnostics) ---
    Q_INVOKABLE QVariantMap debugSnapshot() const;  // форма = DebugSnapshot.h / PageDiagnostics

    // AVPN (diag-report, Task 4 bff-3): полный диагностический text/plain отчёт для чата поддержки —
    // JSON-снапшот (версия/платформа/состояние/подписка/пул с RTT/switchLog/байпас) + хвост лога
    // приложения (<= 256 КБ). Секретов нет by construction (инвариант DebugSnapshot); итог <= 2 МБ - 4 КБ.
    Q_INVOKABLE QString buildDiagReport() const;

    // AVPN (панель администратора): запустить/прервать in-app бенч. label — метка методики
    // (baseline / tribe-bypass-on / tribe-bypass-off / amnezia). Один прогон ~1.5–2 мин, ~40 МБ трафика.
    Q_INVOKABLE void startBench(const QString &label);
    Q_INVOKABLE void cancelBench();
    bool benchRunning() const { return m_benchRunning; }
    QString benchStage() const { return m_benchStage; }

    // AVPN (панель администратора): авто-свип нод (~40-60 с и ~10 МБ на ноду). Фазовая машина поверх
    // ПУБЛИЧНЫХ переходов движка (switchToNode→start→stop — те же, что жмёт юзер из шторки;
    // CONNECT-INVARIANTS не трогаем: никаких back-to-back up, ожидание реальных состояний по changed()
    // + сторожа на фазу). После свипа восстанавливается исходное состояние (pin/авто + подключение).
    Q_INVOKABLE void startNodeSweep();
    Q_INVOKABLE void cancelNodeSweep();
    bool sweepRunning() const { return m_sweepPhase != SweepPhase::Idle; }
    QString sweepProgress() const { return m_sweepProgress; }

    // AVPN (панель администратора, авто-A/B байпаса): 2 full-бенча + 2 реконнекта (~90 МБ, ~5 мин).
    // Только при подключённом Tribe; фазовая машина поверх ПУБЛИЧНЫХ переходов (как свип нод).
    Q_INVOKABLE void startBypassAb();
    Q_INVOKABLE void cancelBypassAb();
    bool abRunning() const { return m_abPhase != AbPhase::Idle; }
    QString abProgress() const { return m_abProgress; }

    // AVPN (bench v5, connect{}): «Тест коннекта» — N циклов stop→start→verify (см. Q_PROPERTY выше).
    Q_INVOKABLE void startConnectCycle();
    Q_INVOKABLE void cancelConnectCycle();
    bool ccRunning() const { return m_ccPhase != CcPhase::Idle; }
    QString ccProgress() const { return m_ccProgress; }

    // AVPN (bench v5.3): отправка отчёта на control plane — POST /v1/bench/report (Bearer, JSON
    // как есть; отчёты без PII by construction). Копятся в БД по устройствам — анализ с прода.
    // Итог — сигнал reportUploadDone(ok, message); 404/405 = «бэк ещё не принимает» (endpoint в
    // handoff BENCH-REPORT-BACKEND-HANDOFF.md). v5.4: зовётся АВТОМАТОМ по завершении мастера
    // (quiet=true: «сервер не принимает» не ноет тостом каждый прогон — только успех/сеть).
    Q_INVOKABLE void uploadReport(const QString &json, bool quiet = false,
                                  const QString &outboxFile = QString());

    // AVPN (bench v5.2): мастер «Полный тест». fullTestContinue — подтверждение ручного шага
    // (гейт: наш туннель disconnected), fullTestSkip — пропустить baseline-шаг.
    Q_INVOKABLE void startFullTest();
    Q_INVOKABLE void cancelFullTest();
    Q_INVOKABLE void fullTestContinue();
    Q_INVOKABLE void fullTestSkip();
    bool ftRunning() const { return m_ftPhase != FtPhase::Idle; }
    QString ftStage() const;
    QString ftProgress() const { return m_ftProgress; }
    int ftPercent() const { return m_ftPercent; }
    QString lastFullTestJson() const;
    QString uploadStatus() const { return m_lastUploadStatus; }

    // AVPN (Доктор v1, 2026-07-17): пользовательская диагностика «У меня не работает» —
    // фазовая машина поверх готовых блоков (RTT-кеш/пробы, reach-кворум, WhitelistDetector,
    // lite-бенч). Спека: specs/2026-07-17-doctor-v1-design.md. Kill-switch features.diag_v2.
    // Отчёт: doctorReportJson() → uploadReport (quiet) сам; текст в тред поддержки шлёт QML
    // (TribeSupport.sendDiagReport(doctorDiagText()) — чат принадлежит своему слою).
    // full=true — «Полная диагностика» (волна UX 07-22): обзор ВСЕХ живых нод пула (кроме RU и
    // manual_only) вместо «до 3 при проблеме»; kill-switch features.doctor_full.
    Q_INVOKABLE void startDoctor(bool full = false);
    Q_INVOKABLE void cancelDoctor();
    Q_INVOKABLE QString doctorReportJson() const;  // итоговый JSON type:"doctor" (после finish)
    Q_INVOKABLE QString doctorHumanReport() const; // читаемое резюме для менеджера (текст в тред)
    Q_INVOKABLE QString doctorDiagText() const;    // buildDiagReport() + секция DOCTOR (файл-вложение)
    // AVPN (Доктор): ручной оператор — единственный путь на iOS 16+ (Apple закрыл CTCarrier).
    // Пусто = сбросить (вернуться к авто MCC-MNC). Читается в benchExtra (QSettings AvpnDiag/carrier).
    Q_INVOKABLE void setDiagCarrier(const QString &code);
    Q_INVOKABLE QString diagCarrier() const;        // текущий (ручной приоритетнее авто)
    Q_INVOKABLE QString diagCarrierAuto() const;     // авто MCC-MNC ("" если недоступно)
    // AVPN (волна UX Доктора 07-22): интро-шаги. Авто-тип сети ("wifi"/"cellular"/"ethernet"/"" =
    // неизвестно) — по нему интро решает, спрашивать ли «какой у вас интернет». Ручной выбор НЕ
    // персистится (сеть меняется между запусками) — benchExtra берёт его последним фолбэком.
    Q_INVOKABLE QString doctorNetType() const;
    Q_INVOKABLE void setDiagNetType(const QString &t);
    // Операторы РФ для плашки интро (server-driven lists.doctor_operators "MCC-MNC|Имя").
    Q_INVOKABLE QVariantList diagOperators() const;
    bool doctorRunning() const { return m_docPhase != DoctorPhase::Idle; }
    QString doctorStage() const;                   // connect|servers|services|speed|send
    int doctorPercent() const { return m_docPercent; }
    QVariantList doctorStages() const;             // [{id,status,note,country_code}] для попапа
    QString doctorSummary() const { return m_docSummary; }
    bool doctorHasProblem() const { return m_docHasProblem; } // есть Bad/Warn → слать в поддержку

    // AVPN (панель администратора): история последних замеров по меткам (QSettings AvpnBench/*) —
    // A/B-сравнение работает между запусками (baseline утром, amnezia вечером). Пусто = не мерили.
    Q_INVOKABLE QString benchLastJson(const QString &label) const;
    Q_INVOKABLE void clearBenchHistory();
    // AVPN (авто-A/B): сводный отчёт всех собранных меток (baseline/on/off/amnezia) одним JSON
    // (type:"full-report": замеры + парные сравнения). "" пока собрано <2 меток.
    Q_INVOKABLE QString buildFullReport() const;
    Q_INVOKABLE QVariantMap benchHistoryInfo() const; // метка → ts последнего замера (карточка «N/4»)
    // Сохранить JSON-отчёт бенча файлом: desktop — путь из SystemController.getFileName (QML-диалог),
    // iOS — временный файл + нативный share sheet ФАЙЛОМ, Android — SAF (создание документа).
    Q_INVOKABLE bool saveReportFile(const QString &fileName, const QString &json) const;
    Q_INVOKABLE void bootstrap();                    // AVPN: тихая прогрузка подписки при старте (Task 11; без connect)
    Q_INVOKABLE void kickBootstrap();                // AVPN: поджать ретрай bootstrap (сеть появилась/foreground). No-op когда подписка загружена; туннель НЕ трогает
    Q_INVOKABLE void start();                        // «одна кнопка»: enroll→subscription→connect (async)
    Q_INVOKABLE void stop();
    Q_INVOKABLE void reprobe();                      // повторный выбор ноды (re-pick)
    Q_INVOKABLE void manualSwitch();                 // принудительный свитч (как DEAD)
    Q_INVOKABLE void resetLkg();                     // очистить кэш токена/подписки (re-enroll при start)

    // AVPN (live-node picker): ручной выбор сервера из шторки + кнопка «Обновить подключение».
    //  switchToNode(nodeId) — «Закрепить» выбранную ноду (переключиться/подключиться к ней).
    //  rotateNext()         — round-robin на следующую живую ноду (кнопка «Обновить подключение»).
    //  refreshPool()        — пере-зачитать подписку/health и обновить nodePool (NOTIFY changed).
    Q_INVOKABLE void switchToNode(const QString &nodeId);
    // AVPN (server picker 2026-07-10): пин + мгновенный реконнект при онлайне (страница выбора).
    // Kill-switch features.picker_instant_reconnect=false → старая семантика switchToNode.
    Q_INVOKABLE void pinAndReconnect(const QString &nodeId);
    Q_INVOKABLE void selectAuto();   // AVPN: «Авто (быстрейший)» — авто-режим без реконнекта (снять pin)
    Q_INVOKABLE void rotateNext();
    Q_INVOKABLE void refreshPool();

    // AVPN: ЛОКАЛЬНЫЙ device_id (installation-UUID из secure-store) — тот же, что уходит на backend
    // при enroll. Доступен ВСЕГДА, без сети/подписки → раздел «Устройства» показывает ID всегда.
    Q_INVOKABLE QString localDeviceId() const;

    // AVPN (Task C): вход/восстановление по коду доступа (POST /v1/code/redeem). Синхронно.
    // 200 → РОТАЦИЯ токена (Enrollment::saveToken) → re-fetch подписки → emit changed().
    // 401 → emit error («неверный код»). 409 → emit seatLimitReached(devices[]) (UI-выбор кого отключить).
    // evictDeviceId — backend-id из devices[] для 1-seat «перенести сюда» (пусто = обычный redeem).
    Q_INVOKABLE void redeemCode(const QString &code, const QString &evictDeviceId = QString());

    // AVPN (grant-ключи): активировать промо/подарочный/компенсационный ключ TRIBE-XXXX-XXXX-XXXX
    // (POST /v1/key/redeem, Bearer; токен НЕ ротируется — начисление на текущий аккаунт). Синхронно.
    // Возвращает {granted_days, granted_gib, plan, new_expiry}; пустая мапа + emit error при провале.
    // Диспатч формата ввода (transfer-ссылка / TRIBE-… / access-code) делает QML (PageAccountTribe).
    Q_INVOKABLE QVariantMap redeemGrantKey(const QString &key);

    // AVPN (Task 13): принять перенос «как SIM» на ЭТО устройство (POST /v1/transfer/redeem). Зовётся
    // мостом диплинка (AvpnDeepLinkBridge) при tribe://transfer?t=… . 200 → РОТАЦИЯ токена внутри
    // Enrollment::redeemTransfer (saveToken) → re-fetch подписки → emit transferRedeemed()+changed().
    // 401 → error («ссылка переноса недействительна»). 409 → error («достигнут лимит устройств»).
    Q_INVOKABLE void redeemTransfer(const QString &transferToken);

    // AVPN (Task 13): выпустить перенос с ЭТОГО устройства (POST /v1/transfer, Bearer authToken).
    // Возвращает { transfer_token, deep_link } для рендера QR/копирования в UI. Пустая мапа при ошибке
    // (+ emit error). Синхронно (QEventLoop).
    Q_INVOKABLE QVariantMap createTransfer();

    // AVPN: системный share sheet для текста/ссылки (рефералка, перенос). iOS = UIActivityViewController
    // (non-blocking), Android = ACTION_SEND chooser, desktop = false → QML-fallback (copy + тост).
    Q_INVOKABLE bool shareText(const QString &text) const;
    // AVPN: share ссылки + QR-картинки одним шитом (перенос). qrPayload = та же ссылка в QR (PNG).
    // false → у платформы нет натив-шита / рендер не удался → QML-fallback (копирование + тост).
    Q_INVOKABLE bool shareTextWithQr(const QString &text, const QString &qrPayload) const;

    // AVPN: QR-картинка для СЫРОЙ строки (ссылка переноса) — data:image/svg;base64,… для Image.source.
    // Кодирует текст как есть (qrcodegen), БЕЗ амнезиевского чанк-конверта — читается системной камерой.
    // Пустая строка при ошибке кодирования.
    Q_INVOKABLE QString makeQrCode(const QString &text) const;

    // AVPN (Task 7): авто-пауза «для покупок». Опускает туннель (m_tunnel.down(), state→Paused) на
    // время покупки в РФ-приложении и АВТО-ВОЗВРАЩАЕТ его через `seconds` секунд бездействия
    // (нет foreground-API → «истёк таймер паузы» = «пользователь не дёргал → возвращаемся»).
    // Будет вызываться iOS App Intent (Task 8). Если тумблер AvpnSettings/autoPauseRu выключен —
    // intent-пауза всё равно отрабатывает (ручной вызов), просто без авто-триггера со стороны системы.
    Q_INVOKABLE void pauseForShopping(int seconds = 90);
    // AVPN: ручной выход из паузы (поднять туннель сразу, не дожидаясь таймера).
    Q_INVOKABLE void resumeFromPause();

    // AVPN (Task: Devices+Account): управление устройствами аккаунта и его статусом. Все три —
    // синхронные (QEventLoop как fetchSubscription), Bearer = authToken() (subscription_token).
    // 401/сеть → пустой результат (+ emit error для kick); UI обновляет список по changed().

    // GET /v1/devices (АСИНХРОННО) → наполняет property `devices` [{device_id, platform, label,
    // last_seen, is_current}] и эмитит devicesChanged(). Нет токена / 401 / сеть / таймаут → пустой
    // список. БЕЗ вложенного QEventLoop: зовётся из QML-таймера, nested loop здесь = re-entrancy краш.
    Q_INVOKABLE void refreshDevices();

    // DELETE /v1/devices/{id} → true при 204 (токен устройства убит, peer снят на всех нодах).
    // false при 401/404/сети (+ emit error). При успехе emit changed() (UI перечитает список).
    Q_INVOKABLE bool kickDevice(const QString &deviceId);

    // GET /v1/account (АСИНХРОННО) → наполняет property `account` {account_id, status, expires_at,
    // traffic_limit, traffic_used} и эмитит accountChanged(). Нет токена / 401 / сеть → пустая мапа.
    // ⚠️ ДВОЕ ЧАСОВ: это ЧАСЫ АККАУНТА (справочно, для саппорта/списков) — в снапшот подписки НЕ пишутся.
    Q_INVOKABLE void refreshAccount();

    // AVPN (оплата, ДВОЕ ЧАСОВ): лёгкий рефетч /v1/subscription — ЧАСЫ УСТРОЙСТВА (их продлевает
    // платёж) для бейджа ГБ/дней и CTA. Данные-only: пул/туннель не трогает (CONNECT-INVARIANTS).
    // Зовётся при возврате в foreground (после оплаты в кабинете) и тиком живого трафика (#35).
    Q_INVOKABLE void refreshSubscription();

    // DEV TOOL (TEMPORARY — remove with backend routers/devtools.py): factory-reset
    // THIS account's trial via POST /v1/dev/reset-trial (Bearer = subscription_token).
    // 2xx → refreshAccount()+bootstrap() so the header (daysLeft/traffic) updates;
    // 404 (server flag off)/401/net → emit error(). Isolated: one method, one QML row.
    Q_INVOKABLE void resetTrialDev();

    // AVPN (#37 рефералы): GET /v1/referral (АСИНХРОННО, Bearer) → property `referral`
    // {code, link, invited, days_earned} + emit referralChanged(). 401/сеть → пустая мапа.
    Q_INVOKABLE void refreshReferral();

    // AVPN (объявления P-ANN): GET /v1/announcements?platform=&lang=&app_version= (АСИНХРОННО,
    // Bearer, armTimeout — без nested loop). Успех → property announcements + LKG-персист
    // (AvpnAnnounce/lkg, мгновенный показ до сети при следующем старте); ошибка/401 → тихо,
    // текущий список НЕ затирается. Вызовы: finishBootstrapSuccess, foreground-хук QML,
    // пуш type=announcement (мост).
    Q_INVOKABLE void refreshAnnouncements();
    // Квитанция объявления: event = "shown" | "read" | "clicked" (+buttonId). Fire-and-forget
    // POST /v1/announcements/{id}/ack. "read" дополнительно персистится ЛОКАЛЬНО (синхронный
    // QSettings — грабля 500мс QML-Settings) и убирает объявление из announcements — попап не
    // мигает повторно офлайн. "shown" дедупится за сессию. Кнопка-действие (не "later"):
    // QML шлёт clicked, затем read.
    Q_INVOKABLE void ackAnnouncement(int id, const QString &event, const QString &buttonId = QString());
    Q_INVOKABLE bool announcementRead(int id) const; // локальный дубль серверного read_at
    // AVPN (announce-quiet): онбординг завершён («Приступим») — движок пишет отметку времени
    // (AvpnAnnounce/onboardDoneAt, синхронный QSettings — грабля 500мс QML-Settings) для
    // «тихого окна» попапов. Идемпотентно: повторный вызов НЕ сдвигает отметку.
    Q_INVOKABLE void markOnboardingDone();
    // AVPN (announce-quiet): true = popup-объявления сейчас молчат (N минут после онбординга,
    // numbers.announce_onboarding_quiet_min, кап 7 суток; kill-switch
    // features.announce_onboarding_quiet — false выключает окно целиком). Глушится ТОЛЬКО
    // автопоказ попапа в PageStart.maybeShowAnnouncement — бейдж/лента/пуши живут.
    Q_INVOKABLE bool announcementsQuietNow() const;

    // AVPN (оплата): «Управлять подпиской» — минт одноразовой ссылки авто-логина в web-кабинет
    // (POST /v1/cabinet/web-link, Bearer = authToken()). АСИНХРОННО (armTimeout, без nested loop).
    // Ответ ВСЕГДА приходит сигналом cabinetLinkReady(url): успех → url бэка (?wl=…, single-use,
    // TTL ~90с) + device_uuid; любая ошибка (нет токена/401/429/сеть/таймаут) → fallback
    // https://tribevpn.com/account + device_uuid (юзер войдёт сам). Минтим строго в момент тапа,
    // НЕ кэшируем. В приложении НЕТ цен/оплаты (Apple §3.1.1) — только открытие внешнего браузера.
    // intent (реш. 2026-07-03): "renew" — золотая CTA «Обновить ключ» на главной → кабинет сразу
    // выдвигает шит тарифов; пусто — «Управлять подпиской» в Настройках → чистый ЛК (шит тарифов
    // только по кнопке «Продлить» ВНУТРИ кабинета). Параметр уходит в URL как &intent=…, читает web.
    Q_INVOKABLE void requestCabinetLink(const QString &intent = QString());

    // AVPN (Task 9 — APNs): зарегистрировать push device token на бэке (POST /v1/devices/push-token,
    // Bearer = authToken()). body {token, platform:"ios", environment, app_version}. АСИНХРОННО (как
    // refreshAccount, без nested loop). environment: "sandbox"|"production" (TestFlight/Debug vs App
    // Store). Нет токена подписки / сеть → тихий no-op (повторится при ротации токена/реконнекте).
    // Обычно зовётся не из QML, а из движка по сигналу AvpnPushBridge::deviceTokenReady.
    Q_INVOKABLE void registerPushToken(const QString &token, const QString &environment);

    // AVPN (Task 9 — APNs): флаш отложенного push-токена ПОСЛЕ появления subscription_token.
    // Сценарий гэпа: APNs отдал device token ДО первичного авто-enroll (authToken пуст →
    // registerPushToken запомнил m_pushToken, но НЕ отправил). После успешного bootstrap/enroll
    // (Connected) subscription_token уже есть → дёргаем registerPushToken повторно; дедуп по
    // fingerprint (token|env|auth) пропустит лишний POST, если он уже ушёл (redeem-пути). No-op,
    // если push-токен пуст (desktop / разрешение не выдано).
    void flushPendingPushToken();

    // AVPN (Task 9 — APNs): отметить уведомления прочитанными на сервере (POST /v1/notifications/read,
    // Bearer). Обнуляет серверный счётчик непрочитанных → следующий пуш придёт с низким aps.badge.
    // Связан с AvpnPushBridge::readRequested (QML зовёт AvpnPush.markAllRead()). АСИНХРОННО.
    Q_INVOKABLE void markNotificationsRead();
    // AVPN (read per-элемент): POST /v1/notifications/read {"ids":[id],"read":read} — read-статус
    // одного уведомления в обе стороны. Связан с AvpnPushBridge::readItemRequested. АСИНХРОННО.
    void markNotificationReadById(qlonglong id, bool read);
    // AVPN (свайп «Удалить»): POST /v1/notifications/delete {"ids":[id]}. АСИНХРОННО.
    void deleteNotificationById(qlonglong id);
    // AVPN (центр уведомлений, серверная история): GET /v1/notifications?limit=50 (Bearer) →
    // AvpnPushBridge::setServerItems (замещение локальной ленты). Зовётся QML при открытии центра
    // (баг 2026-07-10: строка type=announcement была в БД, но пуш не дошёл → центр пуст; теперь
    // история доезжает без пуша — сервер = источник правды, контракт NotificationOut: неизвестный
    // тип рендерится generic-строкой, НЕ скрывается). АСИНХРОННО (armTimeout, без nested loop).
    Q_INVOKABLE void refreshNotifications();
    // AVPN: читается тумблером #6 — отражает текущую фазу «на паузе» для UI.
    bool paused() const { return m_paused; }
    // AVPN (реальные палочки): живое качество текущего соединения.
    int liveRttMs() const { return m_liveRtt; }
    int liveBars() const { return m_liveBars; }
    bool liveReachable() const { return m_liveReachable; }
    bool liveDead() const { return m_liveDead; }
    // AVPN (чипы доступности): текущий статус сервисов (кэш последней пробы).
    QVariantList serviceStatus() const { return m_serviceStatus; }
    // Запустить пробу сервисов через туннель (on-connect авто + по тапу из UI). No-op, если не Connected.
    Q_INVOKABLE void probeServices();
    // AVPN (выбор по скорости): прямой ICMP-замер RTT до ВСЕХ живых нод (off-tunnel). Зовётся при
    // открытии шторки выбора сервера. No-op при connected (через туннель замер смазан — держим кэш) и
    // если пул пуст. Каждый ответ → m_nodeRtt[nodeId] + emit changed() (шторка пересортируется/обновит
    // палочки вживую по мере прихода пингов). Неизмеренные/недостижимые → -1 (фолбэк на health в UI).
    Q_INVOKABLE void probeNodeRtt();
    // AVPN backend-first-3 (Task 11): RTT(мс)→палочки 0..5 для QML-списков (PageLocationsTribe) —
    // канон avpn::SignalQuality::barsForRtt (RttBands::fromTuning(), server-tunable rtt_bar*_ms),
    // чтобы список серверов и «живая» проба (m_signal) не расходились в порогах.
    Q_INVOKABLE int barsForRtt(int rttMs) const { return avpn::SignalQuality::barsForRtt(rttMs); }
    // AVPN (Task 7): состояние тумблера #6 (AvpnSettings/autoPauseRu) — для авто-инициатора (iOS
    // App Intent / Shortcuts, Task 8): проверить ПЕРЕД авто-вызовом pauseForShopping. Ручной/intent
    // вызов pauseForShopping работает независимо от этого флага.
    Q_INVOKABLE bool autoPauseEnabled() const;

    // AVPN RU-direct: тумблер «АвтоVPN» (AvpnBypass/masterOn) сменился на главном экране. Если хотим быть
    // онлайн — безопасно передёрнуть туннель через reconcile-машину (needsRestart), чтобы применился новый
    // split-конфиг (applyRuBypassSplit пересеет в guardedStart). Офлайн → применится при следующем Connect.
    Q_INVOKABLE void reapplyBypass();
    // AVPN RU-direct: ЕДИНСТВЕННО правильный вход тумблера из QML — синхронно пишет masterOn в QSettings
    // и передёргивает (reapplyBypass). ❌ НЕ полагаться на запись через QML Settings + голый reapplyBypass():
    // QML-стор флашится с батч-задержкой ~500 мс, туннель гасится быстрее → guardedStart читал СТАРОЕ
    // значение и поднимал туннель без сплита («переподключился, а сплит не активен»).
    Q_INVOKABLE void setBypassMasterOn(bool on);

    // AVPN (звонки, 2026-07-03): саб-опция «RU-DNS маскировка» (AvpnBypass/dnsMaskOn, default ВКЛ).
    // OFF ⇒ DNS = бэкендовский 1.1.1.1 через туннель (честный гео для звонков/CDN), маршрутный
    // RU-байпас сохраняется. Тот же синхронный паттерн, что setBypassMasterOn (QML Settings лагает).
    Q_INVOKABLE bool bypassDnsMaskOn() const;
    Q_INVOKABLE void setBypassDnsMaskOn(bool on);

    // AVPN (китайские сервисы, 2026-07-03): тумблер «Li Auto» (AvpnBypass/liAutoOn, default ВКЛ).
    // ВКЛ ⇒ узкие /24 серверов Li Auto (команды авто api-app.lixiang.com + логин id/account.lixiang.com
    // + API-шлюзы) идут МИМО туннеля через residential РФ-IP: из-за границы команды управления авто не
    // проходят, а с прямого РФ-IP работают. Независим от masterOn (RU-байпас) — сплит включается, если
    // включён ЛЮБОЙ из тумблеров. Тот же синхронный паттерн, что setBypassMasterOn (QML Settings лагает).
    Q_INVOKABLE bool bypassLiAutoOn() const;
    Q_INVOKABLE void setBypassLiAutoOn(bool on);

    // AVPN split-DNS форвардер (iOS, эксперимент; дизайн SPLIT-DNS-FORWARDER-DESIGN.md):
    // AvpnBypass/dnsFwd, default ON (реш. 2026-07-06 после замеров FI: DNS 19мс vs 38, TTFB −12%).
    // При ON тумблер «RU-DNS маскировка» игнорируется (но живёт в UI).
    Q_INVOKABLE bool bypassDnsFwdOn() const;
    Q_INVOKABLE void setBypassDnsFwdOn(bool on);

    // AVPN in-app Legal (Privacy/Terms, PageLegalTribe): кэш с диска + тихий fetch
    // tribevpn.com/legal/<doc>.<lang>.md (LegalDocs.h). Ошибки сети молчаливые:
    // страница живёт на кэше/qrc-снапшоте. doc ∈ privacy|terms, lang ∈ ru|en.
    Q_INVOKABLE QString legalDocCached(const QString &doc, const QString &lang) const;
    Q_INVOKABLE void legalDocFetch(const QString &doc, const QString &lang);

signals:
    // AVPN (2026-09-02): ход установки обновления — стадия для экрана обновления и причина отказа.
    void selfUpdateProgress(const QString &text);
    void selfUpdateFailed(const QString &reason);
    void selfUpdateInstalled();
    void changed();
    void error(const QString &message);
    // AVPN (macOS): на старте коннекта обнаружен другой активный VPN (чужой full-tunnel/демон) →
    // конфликт маршрутов («крутится, не подключается»). UI показывает уведомление «отключите другой VPN».
    void vpnConflict(const QString &name);
    // AVPN (Task C): redeem вернул 409 (мест нет) — devices[] для UI-выбора кого отключить
    // (DELETE /v1/devices/{id} или повторный redeemCode(code, evictDeviceId)). Каждый элемент —
    // QVariantMap {deviceId, platform, label, lastSeen, isCurrent}.
    void seatLimitReached(const QVariantList &devices);
    // AVPN (Task 13): перенос «как SIM» успешно принят на это устройство (токен уже ротирован,
    // подписка перечитана). UI может показать тост/перейти на Connect.
    void transferRedeemed();
    // AVPN (device_fingerprint): redeem/transfer вернул 403 «device fingerprint mismatch» —
    // rehome-гейт бэка: устройство заштамповано другим якорем железа (защита от угона по утёкшему
    // device_id). UI: «привязано к другому аккаунту — обратитесь в поддержку», БЕЗ ретраев и БЕЗ
    // чистки локального стейта (текущая подписка устройства цела).
    void fingerprintMismatch();
    // AVPN: async-ответ /v1/devices и /v1/account готов (property devices/account обновлены).
    void devicesChanged();
    void accountChanged();
    void whitelistModeChanged();  // AVPN (белые списки): вход/выход РКН-режима whitelist
    void whitelistAckedChanged(); // AVPN (белые списки): «Понятно» нажато/сброшено
    void appLangChanged();   // AVPN (i18n): сменили язык через setAppLang
    void referralChanged();   // AVPN (#37): async-ответ /v1/referral готов (property referral обновлена)
    void announcementsChanged(); // AVPN (P-ANN): property announcements обновлена (fetch/LKG/read)
    // AVPN (оплата): готова ссылка web-кабинета (см. requestCabinetLink). Эмитится ВСЕГДА (успех или
    // fallback) — QML-кнопка не залипнет в loading. Открывать ТОЛЬКО во внешнем браузере
    // (Qt.openUrlExternally), НЕ в webview (Apple §3.1.1).
    void cabinetLinkReady(const QString &url);
    // AVPN in-app Legal: свежий markdown скачан и закэширован (после legalDocFetch)
    void legalDocReady(const QString &doc, const QString &lang, const QString &text);
    // AVPN (реальные палочки): прилетел новый замер качества (liveBars/liveRttMs/liveReachable).
    void liveQualityChanged();
    // AVPN (чипы доступности): обновился статус сервисов (serviceStatus).
    void serviceStatusChanged();
    // AVPN (панель администратора): смена состояния бенча (benchRunning/benchStage).
    void benchChanged();
    // AVPN (панель администратора): бенч завершён. summary — плоская мапа для мини-таблицы в UI
    // (+ vs_baseline/vs_amnezia при наличии истории), json — полный результат (schema:1, компактный).
    void benchFinished(const QVariantMap &summary, const QString &json);
    // AVPN (панель администратора): смена состояния свипа нод (sweepRunning/sweepProgress).
    void sweepChanged();
    // AVPN (панель администратора): свип завершён. rows — [{node_id,label,connect_ms,ttfb_ms,down_mbit,
    // base_rtt_ms,loaded_rtt_ms,verdict,ok}] отсортированные (лучшие сверху), json — полный отчёт.
    void sweepFinished(const QVariantList &rows, const QString &json);
    // AVPN (авто-A/B байпаса): смена состояния (abRunning/abProgress).
    void abChanged();
    // AVPN (авто-A/B байпаса): пара замеров готова. summary — {on:{...}, off:{...}, cost:[тексты],
    // reconnect_ms}; json — полный отчёт (type:"ab-bypass": оба замера + compare).
    void abFinished(const QVariantMap &summary, const QString &json);
    // AVPN (bench v5, connect{}): смена состояния теста коннекта (ccRunning/ccProgress).
    void ccChanged();
    // AVPN (bench v5.2, мастер): смена состояния/этапа мастера.
    void ftChanged();
    // AVPN (bench v5.2, мастер): полный тест завершён — единый мега-отчёт (все секции + methodology
    // + summary). UI сразу предлагает сохранить файлом.
    void ftFinished(const QString &json);
    // AVPN (Доктор v1): прогресс/стадии попапа + финал (отчёт готов, можно слать в чат).
    void doctorChanged();
    void doctorFinished();
    // AVPN (bench v5.3): итог отправки отчёта на сервер (message — готовый текст для тоста).
    void reportUploadDone(bool ok, const QString &message);
    // AVPN (bench v5, connect{}): циклы завершены. summary — {cycles, ok_cycles, median_connect_ms,
    // median_teardown_ms, median_first_byte_ms}; json — полный отчёт (type:"connect-cycle").
    void ccFinished(const QVariantMap &summary, const QString &json);
    // AVPN backend-first (2026-07-10): control plane переключился на живой edge (edge-walk) —
    // сателлиты (TribeSupportChat) следуют за новым хостом вместо застревания на мёртвом.
    void apiBaseChanged(const QString &base);
    // AVPN (sub-grace): движок инициировал управляемое отключение «подписка истекла и грейс
    // прошёл» (см. enforceSubscriptionGrace). Парный флаг — Q_PROPERTY subEnforcedStop.
    void subscriptionEnforcedStop();

private slots:
    void onTick();
    // AVPN: правдивый статус — реальное состояние VpnConnection (не маска успеха up()).
    void onConnectionStateChanged(Vpn::ConnectionState state);
    // AVPN: протокол-уровневые ошибки туннеля (ErrorCode) — наружу в error().
    void onVpnProtocolError(amnezia::ErrorCode code);
    // AVPN (Task 7): таймер паузы истёк → бездействие → поднять туннель обратно.
    void onPauseTimeout();
    // AVPN (reconcile-машина): терминальный колбэк туннеля не пришёл за таймаут → разблокировать.
    void onWatchdog();

private:
    // AVPN (reconcile-машина смены ноды): единый контур «намерение vs факт». ВСЕ подъёмы/опускания
    // туннеля идут ТОЛЬКО из терминального состояния (.connected/.disconnected/.error); смена ноды =
    // stop → дождаться Disconnected → start (никогда не up() поверх незакрытой iOS-NE-сессии). Это
    // убирает «подбираем сервер»→«Network Error» и залипания. См. memory tribe-server-switch-fix.
    void reconcile();      // привести факт (m_lastTunnelState) к намерению (m_wantConnected + pin)
    void guardedStart();   // поднять туннель (startFlow→connect→up): op-in-flight + сторож
    void guardedStop();    // опустить туннель (requestStop+down): op-in-flight + сторож
    // AVPN awg31-xray-v1 (спека §2.3):
    //  onTunnelUpEffects()     — побочные эффекты реального «Подключено» (пуши, чипы, живой RTT,
    //                            история транспорта); awg — сразу на Vpn::Connected, xray — после verify.
    //  startXrayVerification() — фаза Verifying: HEAD generate_204 ЧЕРЕЗ туннель, повторы каждые
    //                            ~1.2с в бюджете xray_verify_timeout_ms (кламп ConnectTunables.h);
    //                            async, без nested QEventLoop (§1). Успех → verifySucceeded →
    //                            эффекты; провал → verifyFailed → движок уводит на другой транспорт
    //                            той же локации (двухфазный свитч), нет кандидатов → честный OFF.
    //  persistTransportHistory()— QSettings avpn/transportHistory, только когда движок пометил dirty.
    //  applyReseed()/applyPendingReseed() — reseed пула по pool_revision (refreshSubscription →
    //                            QTimer::singleShot(0), никогда из-под Selector::pick / sync-вызова).
    void onTunnelUpEffects();
    void startXrayVerification();
    void verifyAttempt(int epoch);
    void finishVerify(int epoch, bool ok);
    // AVPN (независимое ревью волны, MAJOR-1): движок исчерпал кап подряд идущих провалов
    // data-plane (ServiceEngine::dataPlaneExhausted) — показать честную ошибку, снять намерение
    // (§13) и погасить туннель через reconcile (§2). true = сдались этим вызовом.
    bool surrenderIfDataPlaneDead();
    void persistTransportHistory();
    void applyReseed(const avpn::Subscription &sub);
    void applyPendingReseed();
#if defined(Q_OS_MACOS) && !defined(MACOS_NE)
    // AVPN (beachball-фикс): финиш фоновой установки root-демона (главный поток, queued из worker).
    // ok → reconcile() продолжает старт (намерение живо); fail → error + счёт попытки.
    void finishSvcInstall(bool ok, const QString &err);

    // AVPN (macOS wake-реконнект, спека 2026-07-17-macos-wake-reconnect-design.md): «закрыл крышку —
    // утром VPN off». Wake — НАША операция, а не внешний обрыв: демон туннель через ночь держит,
    // рвал его ванильный reconnectToVpn (stop+start в неготовую сеть) + наш 20с-сторож + §13.
    // Перехват: на каждом Connected срезаем ванильные подписки rep→VpnConnection (hook) и слушаем
    // wakeup/networkChanged сами; сначала проверка живости (HEAD generate_204 через туннель),
    // рестарт — только если туннель реально мёртв, и ТОЛЬКО через reconcile (m_needsRestart:
    // m_op взведён → §13-гард weAreOperating держит намерение). Ретраи — по reachabilityChanged,
    // кап wakeRestartMaxTriesTuned. Kill-switch features.wake_restart (false = ваниль).
    void hookDaemonWakeSignals();     // подписка + срез ванильного пути (зов: onConnectionStateChanged/Connected)
    void onDaemonWakeup();            // сигнал wakeup реплики демона (queued)
    void onDaemonNetworkChanged();    // сигнал networkChanged реплики (та же обработка)
    void daemonWakeEvent(const char *why);
    void wakeLivenessProbe();         // async HEAD через туннель; мёртв → needsRestart+reconcile
    void wakeKick();                  // ретрай подъёма по появлению сети (кап tries)
    // AVPN (BUG-6, адопция при перезапуске GUI): демон держит туннель после выхода GUI, но на
    // холодном старте протокол (LocalSocketController) не создаётся до клика Connect — факт
    // «connected» демона никто не спрашивает. Стартовая проба: свой QLocalSocket → {"type":"status"}
    // → connected==true → адопт (намерение + adoptTunnelConnected + onConnectionStateChanged).
    // m_adoptedNoProto: туннель адоптирован БЕЗ живого протокола — пользовательский stop обязан
    // гасить демона напрямую ({"type":"deactivate"}), иначе выключение станет ноль-оп (§13a-зеркало).
    void probeDaemonTunnelOnStartup();
    void daemonDirectDeactivate();
    bool m_adoptedNoProto = false;
#endif
    // AVPN (sub-grace): из onTick при connected — «подписка истекла и грейс прошёл» → управляемый
    // stop() (тот же путь, что пользовательский: намерение OFF + reconcile) + subscriptionEnforcedStop().
    void enforceSubscriptionGrace();

    // AVPN: холодный bootstrap подписки С РЕТРАЕМ, полностью АСИНХРОННЫЙ (armTimeout, БЕЗ вложенного
    // QEventLoop на GUI-потоке — тот же паттерн, что refreshDevices/refreshAccount). Цепочка:
    // tryBootstrapSubscription → (нет токена? bootstrapEnrollAsync) → bootstrapFetchAsync →
    // finishBootstrapSuccess | onBootstrapAttemptFailed (переарм m_bootstrapRetryTimer, вечный цикл).
    // 401-самохил (стейл-токен из стора): clearToken → bootstrapEnrollAsync → повторный fetch РОВНО
    // один раз (та же логика Enrollment::decideAuthRecovery, что в синхронном ensureSubscription).
    // Терминальные исходы (410 transferred; 401 на свежем токене) ОСТАНАВЛИВАЮТ цепочку — вечный
    // ретрай только для транзиентного (сеть/HTTP 5xx/429).
    void tryBootstrapSubscription();
    void bootstrapEnrollAsync(bool reEnrolled);                    // POST /v1/trial (async)
    void bootstrapFetchAsync(const QString &token, bool tokenFromStore, bool reEnrolled); // GET /v1/subscription (async)
    void finishBootstrapSuccess(const QByteArray &body);           // парс + LKG + probeNodeRtt + changed()
    void flushWhitelistEpisodes(); // AVPN (белые списки): отправка очереди эпизодов после восстановления сети
    void onBootstrapAttemptFailed();                               // переарм таймера (BootstrapRetry.h)
    void stopBootstrapTerminal();                                  // 410/невосстановимый 401 — цепочку не переармируем

    // AVPN RU-direct (единый «Доступ к сайтам РФ», флаг AvpnBypass/masterOn, default ON): перед коннектом
    // сеет split-tunnel репозиторий — routeMode=VpnAllExceptSites + весь рунет CIDR (ru_prefixes.h) →
    // рунет идёт МИМО туннеля через реальный residential РФ-IP (бьёт датацентр-детект Госуслуг/Кинопоиска;
    // Ozon-приложение — реальный IP телефона). Кросс-платформенно (iOS excludeRoutes / macOS маршруты).
    // OFF → не трогаем (юзер сам рулит с экрана «Защита»). DNS=Яндекс ставится в VpnConnectionTunnelControl.
    void applyRuBypassSplit();

    // AVPN remote-config (T6): carve-out API/edge-хоста из RU-bypass CIDR — тот же инвариант, что
    // carveOutIpFromSites в applyRuBypassSplit (control plane ВСЕГДА в туннеле), но переиспользуемый:
    //  · rebuildApiCarveOut(sites) — применяет вырез к конкретному сев-набору; вызывается ВНУТРИ
    //    applyRuBypassSplit РОВНО там же, где раньше был инлайн-блок (behaviour-preserving extraction).
    //  · rebuildApiCarveOut() — вызывается из ConfigService::activeEdgeChanged: резолвит НОВЫЙ активный
    //    edge-хост в m_apiHostIps (async QHostInfo, тот же паттерн, что в конструкторе для исходного
    //    m_baseUrl) и передёргивает сплит через reapplyBypass(), чтобы следующий пересев (внутри
    //    applyRuBypassSplit → rebuildApiCarveOut(sites)) унёс с собой и свежий carve-out. Офлайн/ещё
    //    не резолвлено → применится на следующем Connect, как везде в RU-direct (см. reapplyBypass()).
    void rebuildApiCarveOut(QMap<QString, QStringList> &sites) const;
    void rebuildApiCarveOut();
    // ЕДИНЫЙ список carve-IP (вкомпиленный фолбэк + m_apiHostIps) — для выреза И для стампа сева
    // (bypassSeedStamp): один источник исключает дрейф «carve изменился, а стамп не заметил».
    QStringList apiCarveIps() const;

    // AVPN remote-config (T6): если сервер прислал probeTargets — переопределить m_svcProbe маппингом
    // ProbeTarget→ServiceProbeConfig (telegram→Mtproto, youtube/instagram→Goodput); иначе НЕ трогаем
    // вшитые дефолты из конструктора (см. AvpnEngineQml.cpp:278-292).
    void applyRemoteProbeTargets(const avpn::RemoteConfig &cfg);

    // AVPN backend-first (T16): цели QualityProbe (живые палочки) следуют за edge-walk (m_baseUrl)
    // и urls.quality_probe_url; вызывается из activeEdgeChanged и configApplied. Конструкторный
    // setEndpoints (AvpnEngineQml.cpp:268-269) — только сид до первого вызова.
    void refreshQualityEndpoints();

    // AVPN backend-first (Task 4): пер-сервисный kill-switch чипов (lists.service_chips_disabled).
    // Фильтрует m_svcCfgsAll (полный список — ctor-дефолт или remote probeTargets из
    // applyRemoteProbeTargets) → отключённые ключи НЕ попадают в m_svcProbe (не пробятся, не тратят
    // трафик) И не попадают в m_serviceStatus (чип пропадает из UI — QML дата-driven, без правок).
    // Пустой/отсутствующий список → фильтр не убирает ничего (TuningStore::listOr «пусто=фолбэк»),
    // поведение байт-в-байт как до задачи. Существующие состояния (works/slow/blocked) сохраняются
    // по key для сервисов, оставшихся включёнными — список ПЕРЕСТРАИВАЕТСЯ целиком, не мержится point-wise.
    // Вызывается из ctor (сид), applyRemoteProbeTargets (сервер сменил цели) и probeServices() (каждый
    // прогон подхватывает свежий disabled-список — живой цикл без отдельного хука на configApplied).
    void rebuildServiceChips();
    // AVPN BUG-13 (2026-07-30): сбросить все чипы в «не проверено» (state=-1, синий) — зовётся
    // на входе в connected, чтобы вердикты прошлой сессии не выдавались за текущие.
    void resetServiceChipsToUnknown();

    ServiceEngine               m_engine;
    VpnConnectionTunnelControl  m_tunnel;     // живёт здесь, отдаётся движку
    SecureAppSettingsRepository *m_store = nullptr;
    QNetworkAccessManager       *m_nam = nullptr;
    VpnConnection               *m_conn = nullptr;
    QTimer                       m_healthTimer;
    // AVPN backend-first (H-3 бэклога): фоновый LKG-рефреш подписки по серверному интервалу
    // (numbers.subscription_refresh_interval_s из /v1/config). Периодический, не singleShot;
    // старт — из configApplied (не в конструкторе, интервал ещё неизвестен).
    QTimer                       m_subRefreshTimer;
    // AVPN (реальные палочки): app-layer RTT-проба через туннель + сглаживание в 0..5 баров.
    QualityProbe                *m_probe = nullptr;   // создаётся в конструкторе (владелец — this)
    SignalQuality                m_signal;            // EWMA+гистерезис (чистая логика, протестирована)
    int                          m_liveRtt = -1;      // сглаженный RTT, мс (−1 = нет данных)
    int                          m_liveBars = 0;      // 0..5
    bool                         m_liveReachable = false;
    bool                         m_liveDead = false;     // проба подтверждённо не доходит → 0 зелёных + все красные
    int                          m_liveFailStreak = 0;   // неуспешных проб подряд (анти-фликер до «мертво»)
    static constexpr int         kLiveDeadStreak = 2;    // фолбэк; серверный оверрайд numbers.live_dead_streak (TuningStore)
    // AVPN (чипы доступности): проба сервисов через туннель + кэш статусов для QML.
    ServiceProbe                *m_svcProbe = nullptr;
    QVariantList                 m_serviceStatus;     // [{key,label,state,rttMs}] — обновляется по месту
    // AVPN backend-first (Task 4): ПОЛНЫЙ (нефильтрованный) список сервисов — источник правды для
    // rebuildServiceChips(); ctor-дефолт (telegram/youtube/instagram) либо замещён applyRemoteProbeTargets.
    QList<ServiceProbeConfig>    m_svcCfgsAll;
    QSet<QString>                m_svcRetried;        // ключи, уже получившие авто-ретрай Unknown (сброс на probeServices)
    // AVPN чипы v2 (2026-07-12, анти-флап): гистерезис показа per-key (ChipLogic::chipHystStep —
    // ухудшение после N подряд + быстрая пере-проба, восстановление сразу) + бюджет confirm-переппроб
    // на серию. Сбрасываются на транзиенте туннеля (нода могла смениться — первый вердикт новой ноды
    // принимается сразу) и НЕ сбрасываются на self-heal (иначе гистерезис бессмыслен).
    QHash<QString, avpn::ChipHyst> m_chipHyst;
    QHash<QString, int>          m_chipConfirms;      // key → потрачено confirm-переппроб этой серии
    // AVPN (выбор по скорости): прямой RTT до нод (off-tunnel) + кэш измерений по nodeId.
    IRttProbe                   *m_rttProbe = nullptr; // владелец — this (QObject-parent)
    QHash<QString, int>          m_nodeRtt;            // nodeId → измеренный RTT мс (−1/нет = неизвестно)
    // AVPN (панель администратора): in-app бенч (создаётся в конструкторе, владелец — this).
    BenchRunner                 *m_bench = nullptr;
    bool                         m_benchRunning = false;
    QString                      m_benchStage;
    // AVPN (панель администратора): фазовая машина авто-свипа нод. Продвигается ТОЛЬКО из
    // sweepAdvance() (по changed()) и sweepGuardFired() (сторож фазы) — реентерабельность исключена
    // отложенным продвижением (singleShot(0)); m_sweepEpoch отбрасывает стейл-колбэки.
    enum class SweepPhase { Idle, WaitDown, WaitUp, Bench, RestoreWaitDown, RestoreWaitUp };
    SweepPhase                   m_sweepPhase = SweepPhase::Idle;
    int                          m_sweepEpoch = 0;
    int                          m_sweepIdx = 0;
    QStringList                  m_sweepQueue;        // nodeId в порядке обхода
    QJsonArray                   m_sweepResults;      // полные lite-результаты + ошибки per node
    QString                      m_sweepProgress;     // «2/5 · POLAND» для UI
    QString                      m_sweepOrigPin;      // исходный pin ("" = авто)
    bool                         m_sweepOrigConnected = false;
    QElapsedTimer                m_sweepConnT;        // замер connect_ms текущей ноды
    QTimer                       m_sweepGuard;        // сторож текущей фазы

    // AVPN (авто-A/B байпаса): фазовая машина «бенч A → toggle+реконнект → бенч B → возврат».
    // Тот же каркас, что свип: продвижение из abAdvance() (queued по changed()) + сторож фазы;
    // m_abEpoch отбрасывает стейл. Реконнект делаем НЕ сами — setBypassMasterOn → reapplyBypass →
    // reconcile (needsRestart) передёргивает туннель штатно; мы только ждём фактических состояний.
    enum class AbPhase { Idle, BenchA, WaitDown, WaitUp, BenchB, RestoreDown, RestoreUp };
    AbPhase                      m_abPhase = AbPhase::Idle;
    int                          m_abEpoch = 0;
    bool                         m_abOrigOn = true;    // исходный AvpnBypass/masterOn (вернём в конце)
    bool                         m_abOrigLiAuto = true; // v5.5: исходный liAutoOn — off-фаза A/B гасит
                                                        // и его (иначе «bypass-off» ≠ ваниль: split_on
                                                        // остаётся из-за Li Auto default-ON)
    QJsonObject                  m_abFirst, m_abSecond; // замер 1 (исходный тумблер) и 2 (инверсный)
    double                       m_abSwitchMs = -1, m_abRestoreMs = -1; // длительность реконнектов
    QElapsedTimer                m_abConnT;
    QTimer                       m_abGuard;
    QString                      m_abProgress;

    void abEnterPhase(AbPhase ph, int guardMs);
    void abOnBenchDone(const QJsonObject &result); // benchFinished при фазе BenchA/BenchB
    void abAdvance();
    void abGuardFired();
    void abStartBench(bool second);
    void abFail(const QString &reason); // прервать, вернуть исходный тумблер, error() наружу
    void abFinish();

    // AVPN (bench v5, connect{}): «Тест коннекта» — N циклов stop→wait down→start→wait connected→
    // →handshake (poll readStats, где платформа отдаёт)→first byte (HEAD 204)→next. Тот же каркас,
    // что свип/A/B: продвижение по changed() (queued) + сторож фазы + эпоха против стейла.
    // Настройки/тумблеры НЕ трогаем; тест заканчивается подключённым (последняя фаза — Verify).
    enum class CcPhase { Idle, Down, Up, Handshake, Verify };
    CcPhase       m_ccPhase = CcPhase::Idle;
    int           m_ccEpoch = 0;
    int           m_ccCycle = 0;                    // текущий цикл (0-based)
    static constexpr int kCcCycles = 3;
    QJsonArray    m_ccCycles;                       // [{teardown_ms,connect_ms,handshake_ms,first_byte_ms,verify_ok,error?}]
    QJsonObject   m_ccCur;                          // собираемый цикл
    QElapsedTimer m_ccT;                            // таймер текущей фазы
    qint64        m_ccConnEpochSec = 0;             // момент подключения (гейт свежести handshake)
    int           m_ccHsPolls = 0;                  // счётчик поллов handshake (сторож по числу)
    QTimer        m_ccGuard;
    QString       m_ccProgress;
    void ccEnterPhase(CcPhase ph, int guardMs);
    void ccAdvance();
    void ccGuardFired();
    void ccPollHandshake();
    void ccVerify();          // HEAD generate_204 через туннель + rx-рост (data-plane правда)
    void ccNextCycle();       // зафиксировать m_ccCur и перейти к следующему циклу/финишу
    void ccFail(const QString &reason);
    void ccFinish();

    // AVPN (bench v5.2): мастер «Полный тест» — дирижёр. НЕ содержит измерительной логики:
    // последовательно зовёт готовые машины и ждёт их *Finished (подключено в конструкторе);
    // зависший шаг добивает сторож (шаг помечается error, мастер идёт дальше — частичный отчёт
    // ценнее прерванного). Ручные фазы Wait* сторожа не имеют (юзер может отойти).
    enum class FtPhase { Idle, Connect0, Cc, Ab, Sweep, WaitAmnezia, BenchAmnezia,
                         WaitBaseline, BenchBaseline };
    FtPhase     m_ftPhase = FtPhase::Idle;
    int         m_ftEpoch = 0;
    QJsonArray  m_ftSteps;      // methodology: [{step, ts, status}]
    QString     m_ftProgress;
    int         m_ftPercent = 0;
    QString     m_lastUploadStatus; // v5.5: итог последней отправки на сервер
    QTimer      m_ftGuard;
    void ftUpdatePercent();     // из ftEnter + changed-сигналов под-машин (пока ftRunning)
    double benchStageFrac() const; // доля прогресса текущего бенча по m_benchStage (0..1)
    void ftEnter(FtPhase ph, int guardMs = 0); // 0 = без сторожа (ручные фазы)
    void ftRecord(const char *step, const char *status);
    void ftStepDone(FtPhase donePhase, bool ok); // продвижение по *Finished/сторожу
    void ftFinish();
    QString assembleMegaReport() const; // buildFullReport + methodology + summary (+baseline-suspect)
    QJsonObject benchExtra() const;     // контекст замера: факты конфигурации + тип сети

    // AVPN (Доктор v2, активная): пользовательская диагностика — канон машин (enum+epoch+guard),
    // дирижёр поверх готовых блоков. Доктор САМ поднимает VPN и проверяет РЕАЛЬНУЮ работу через
    // туннель (Connect поднимает туннель если выключен → ждёт connected → проба данных; Services
    // гоняет чипы WhatsApp/TG/YT/IG через туннель; Speed — бенч через туннель). Сторож фазы
    // (clampStageTimeoutMs) гасит зависшую стадию честным вердиктом и идёт дальше — частичный
    // отчёт ценнее прерванного (урок ftStepDone). Спека: 2026-07-17-doctor-v1-design.md.
    // AltNodes — опциональная фаза: при проблеме на текущей ноде проверяем до 2 лучших
    // альтернатив (переключение + проба данных) — различает «нода сломана» от «сеть/оператор»;
    // рабочая альтернатива найдена → ОСТАЁМСЯ на ней (активная модель: юзеру сразу хорошо).
    // RuSplit — опциональная фаза: при включённом «Доступе к сайтам РФ» пробы RU-корпуса
    // (Яндекс/VK/Аэрофлот) — сплит обязан вести их напрямую (кейс владельца с аэрофлотом).
    // Network (D-3) — ПЕРВАЯ стадия, до подъёма туннеля: captive-детект (generate_204 ->
    // редирект/чужое тело = портал), сигналы платформы (поколение сотовой/metered/roaming)
    // и форс-прогон дифф-проб «белых списков» (валиден только при опущенном туннеле).
    enum class DoctorPhase { Idle, Network, Connect, Servers, Services, RuSplit, Speed, AltNodes, Send };
    DoctorPhase m_docPhase = DoctorPhase::Idle;
    int         m_docEpoch = 0;
    QTimer      m_docGuard;
    QList<doctor::StageResult> m_docStages;
    int         m_docPercent = 0;
    QString     m_docSummary;
    bool        m_docHasProblem = false; // финал: есть Bad/Warn (слать в тред поддержки)
    QJsonObject m_docReport;          // итог buildReport (живёт до следующего запуска)
    QJsonObject m_docBenchFull;       // полный JSON lite-бенча Speed-стадии (в extra отчёта)
    qint64      m_docRx0 = 0;         // срез rx для проверки «данные идут»
    bool        m_docWasConnected = false; // VPN был поднят ДО теста (не опускать в конце)
    bool        m_docConnecting = false;   // фаза Connect ждёт connected по changed()
    bool        m_docSawProgress = false;  // видели connecting/selecting: disconnected ПОСЛЕ
                                           // этого = остановили извне (а не «ещё не стартовали»)
    bool        m_docBenchStarted = false; // Speed-стадию запустил доктор (для cancel)
    QStringList m_docAltQueue;        // nodeId альтернатив на проверку (до 3, самые быстрые по RTT)
    int         m_docAltIdx = -1;     // текущая альтернатива (-1 = не начали)
    QStringList m_docAltNames;        // человеческие имена проверенных
    QList<bool> m_docAltOks;          // итог per-альтернатива (стабильна = обе пробы прошли)
    QVariantList m_docAltDetails;     // per-нода факты: name/cc/handshake/rx/rtt/обе пробы/verdict
    QVariantList m_docAltCand;        // очередь-кандидаты (nodeId+name+cc) для деталей
    qint64      m_docAltRx0 = 0;      // rx на момент connected альтернативы (рост = данные идут)
    int         m_docAltIcmpMs = -1;  // ICMP 1.1.1.1 через туннель на альтернативе
    qint64      m_docAltHsSec = -1;   // возраст handshake на альтернативе
    bool        m_docAltProbe1 = false; // результат первой пробы (до re-probe)
    QString     m_docOrigNode;        // nodeId на момент старта AltNodes (для возврата)
    QString     m_docOrigPin;         // исходный pin (пуст = был авто-режим)
    bool        m_docFull = false;    // «Полная диагностика»: обзор всех нод (кроме RU/manual_only)
    bool        m_docAltHadProblem = false; // была ли проблема ДО обзора альтернатив (решает пересадку)
    QString     m_diagNetManual;      // ручной тип сети из интро (не персистится)
    void docEnter(DoctorPhase ph);    // фаза + сторож + процент + doctorChanged
    QStringList m_docRuNames;         // RU-корпус: имена проверяемых сайтов
    QList<bool> m_docRuOks;           // результаты (порядок = m_docRuNames)
    int         m_docRuPending = 0;
    // D-3: стадия Network + ICMP-через-туннель + A/B-замер мимо туннеля
    int  m_docNetCaptive = -1;        // -1 не проверялось / 0 нет / 1 портал
    int  m_docNetWl = -1;             // форс-раунд белых списков: -1 не гонялся / 0 норм / 1 сигнатура
    int  m_docNetPending = 0;         // незавершённые async-пробы стадии Network
    int  m_docTunIcmpMs = -1;         // ICMP 1.1.1.1 ЧЕРЕЗ туннель (fire-and-collect в Connect)
    IRttProbe *m_docPing = nullptr;   // отдельный инстанс (m_rttProbe гейтится connected⇒cancel)
    // D-6 (блок-профиль эндпоинта): ICMP до IP ТЕКУЩЕЙ ноды МИМО туннеля (host-route WG) —
    // различает причину смерти ноды у оператора: IP-блэкхол / фильтр по размеру / верхние слои
    int  m_docEpMs = -1;              // Connect: маленький echo до эндпоинта, -1 = нет ответа
    int  m_docEpBig = -1;             // Connect: большой DF-echo, -1 не мерили / 0 дроп / 1 ок
    bool m_docEpTried = false;
    int  m_docAltEpMs = -1;           // то же для текущей альтернативы перебора
    int  m_docAltEpBig = -1;
    bool m_docAltEpTried = false;
    QString docEpProbeStart(std::function<void(bool)> bigSink); // -> IP цели "ep" ("" = пропуск)
    double m_docSpeedDown = -1;       // партиалы Speed на время A/B-замера (сторож не теряет бенч)
    int    m_docSpeedIdle = 0, m_docSpeedLoaded = 0;
    bool   m_docSpeedCollapsed = false;
    void docStartNetwork();           // captive + сигналы + форс-whitelist (первая стадия)
    void docNetMaybeDone();           // сведение параллельных проб Network -> networkStage
    // AVPN (IPv6-волна 2026-09-08): -1 не проверяли | 0 нет | 1 у САМОЙ СЕТИ есть глобальный
    // IPv6 (мимо туннеля). Срез QNetworkInterface -> чистая Ipv6Presence.h::hasOffTunnelGlobalV6.
    // Гейт features.ipv6_notice (kill-switch, default true): false -> всегда -1, Доктор молчит.
    int  detectLanIpv6() const;
    void docStartConnect();           // вход фазы Connect (вынесен из startDoctor)
    void docDirectSpeed(double down, int idle, int loaded, bool collapsed); // A/B мимо туннеля
    void crashFlushPending();         // CR-1: отправка pending краш-отчётов (kill-switch crash_report)
    // BUG-7: персистентный outbox /v1/bench/report — отчёт, не ушедший из-за сети
    // (мёртвый туннель!), доезжает после восстановления/перезапуска.
    void outboxEnqueue(const QString &json);
    void outboxFlush();
    bool m_outboxWasConnected = false; // фронт connected → отложенный flush
    void docStartRuSplit();           // пробы RU-корпуса (или сразу Speed при выкл. сплите)
    void docStartAltNodes();          // собрать очередь альтернатив (или сразу Send)
    void docAltNext();                // переключиться на следующую альтернативу
    void docAltVerify();              // проба 1 данных на альтернативе (сразу после connected)
    void docAltVerify2();             // проба 2 (после ~keepalive) — ловит задержанный blackhole
    void docAltRecord(bool probe2);   // свести обе пробы в per-нода деталь -> docAltNext
    void docStageDone(const doctor::StageResult &r); // записать стадию и перейти к следующей
    void docGuardFired();             // стадия не уложилась в сторож -> вердикт и дальше
    void docConnectAdvance();         // реакция на changed() в фазе Connect (поднялся/упал туннель)
    void docVerifyDataplane();        // проба generate_204 через туннель + рост rx -> connectStage
    void docStartServers();
    void docStartServices();
    void docStartSpeed();
    void docFinish();                 // buildReport + upload(quiet) + doctorFinished
    static QString bypassLabel(bool on)
    { return on ? QStringLiteral("tribe-bypass-on") : QStringLiteral("tribe-bypass-off"); }

    QString sweepNodeLabel(const QString &nodeId) const; // display-имя из пула снапшота
    void sweepEnterPhase(SweepPhase ph, int guardMs);
    void sweepAdvance();       // реакция на changed(): проверка достижения целевого состояния фазы
    void sweepGuardFired();    // фаза не завершилась за сторож — зафиксировать ошибку и дальше
    void sweepNextNode();      // pin следующей ноды (или переход к восстановлению)
    void sweepStartBench();    // lite-бенч на подключённой ноде
    void sweepNodeFailed(const QString &reason);
    void sweepBeginRestore();
    void sweepFinish();        // сборка отчёта + emit sweepFinished + сброс в Idle
    QString                      m_baseUrl = QStringLiteral("https://api.tribevpn.com");
    // AVPN remote-config (T6): оркестратор /v1/config+/v1/edges (fetch/ed25519-verify/LKG/edge-walk,
    // см. ConfigService.h) + снапшот последнего применённого конфига (featureEnabled/configUrl/
    // storeUrl читают отсюда) + вердикт force-update (см. updateState()).
    avpn::ConfigService          *m_configSvc = nullptr;
    avpn::SelfUpdate *m_selfUpdate = nullptr;  // AVPN: установка обновления (macOS desktop)
    // AVPN server-driven АнтиВПН (Task 10): оркестратор /v1/bypass-lists (подписанный fetch/LKG/
    // анти-downgrade). Kill-switch remote_bypass_lists — ВНУТРИ сервиса (onRemoteConfigApplied):
    // при флаге=false кладёт пустой invalid снапшот в BypassListStore и ставит фетч на паузу.
    // Точки чтения (applyRuBypassSplit / VpnConnectionTunnelControl) проверяют только bl.valid.
    avpn::BypassListService      *m_bypassListSvc = nullptr;
    avpn::RemoteConfig            m_remoteCfg;
    // AVPN (diag-report, Task 4 bff-3): epoch последнего configApplied (ConfigService) —
    // в отчёте отдаём возраст; 0 = ещё не применялся (ключ в JSON опускается).
    qint64                        m_lastConfigAppliedEpoch = 0;
    int                           m_updateState = 0; // 0 Ok / 1 Recommend / 2 Block
    // AVPN RU-direct carve-out (2026-07-05): актуальные IP хоста API (async QHostInfo из
    // конструктора; T6 — дополняется резолвом НОВОГО edge-хоста при activeEdgeChanged, см.
    // rebuildApiCarveOut()). Сев applyRuBypassSplit исключает их (+ вкомпиленный фолбэк) из
    // байпаса — control plane всегда через туннель, см. CidrCarve.h.
    QList<QHostAddress>          m_apiHostIps;
    QString                      m_lastBypassSeedStamp; // AVPN: стамп последнего доехавшего сева АнтиВПН (BypassSeedStamp.h) — скип пересева при неизменных входах
    bool                         m_busy = false;
    // AVPN (macOS, beachball-фикс): установка root-демона идёт в фоновом потоке; флаг гейтит
    // повторный вход guardedStart (reconcile может тикать во время установки) и питает свойство
    // svcInstalling. На не-macOS всегда false.
    bool                         m_svcInstalling = false;
    bool                         m_svcInstallInFlight = false;
    // AVPN (macOS wake-реконнект): состояние wake-операции. wakeProbing — дедуп пробы живости
    // (wakeup+networkChanged летят пачкой); wakeRestartPending — наш рестарт в полёте, ретраи по
    // reachabilityChanged восстанавливают намерение (это НЕ авто-коннект §13 — операция наша);
    // wakeTries — счётчик против капа wakeRestartMaxTriesTuned. Не-macOS: не используются.
    bool                         m_wakeProbing = false;
    int                          m_wakeProbeAttempt = 0;   // AVPN seamless roaming: повторы пробы до рестарта
    bool                         m_wakeRestartPending = false;
    int                          m_wakeTries = 0;
    bool                         m_transferredAway = false; // AVPN: 410 transferred (подписка уехала на другое устройство)
    int                          m_pendingRedeemAttempts = 0; // AVPN: ретраи redeemTransfer, пока движок занят bootstrap'ом (холодный старт по диплинку)
    QString                      m_pendingRedeemToken;        // AVPN: токен с уже запланированным busy-ретраем (второй таймер не плодим)
    QString                      m_lastRedeemedToken;         // AVPN: успешно принятый токен — дедуп повторных сканов того же QR (иначе 401-тост поверх успеха)
    // AVPN (reconcile-машина смены ноды): намерение vs факт + защита от гонок/шторма. См. reconcile().
    Vpn::ConnectionState         m_lastTunnelState = Vpn::Unknown; // ФАКТ: реальное состояние туннеля
    int                          m_trafficSyncTicks = 0;           // AVPN (#35): счётчик health-тиков для ре-синка /v1/account (каждый 5-й ≈20с)
    bool                         m_wantConnected = false;          // НАМЕРЕНИЕ: туннель должен быть поднят
    bool                         m_needsRestart  = false;          // цель сменилась на подключённом → stop→start
    // AVPN awg31-xray-v1: верификация xray (см. startXrayVerification): epoch гейтит стейл-ответы
    // (сменился туннель/стоп → ответ старой серии выбрасывается), clock — бюджет, ms/ok — факты
    // последней верификации для отчётов бенча/диагностики (benchExtra.transport).
    int                          m_verifyEpoch = 0;
    QElapsedTimer                m_verifyClock;
    int                          m_verifyAttempts = 0;
    qint64                       m_lastVerifyMs = -1;
    int                          m_lastVerifyOk = -1;              // -1 не было, 0 провал, 1 успех
    // AVPN (независимое ревью волны, MAJOR-3): было ли у последней успешной верификации
    // доказательство rx ЧЕРЕЗ туннель (false = источник статистики молчал, приняли с оговоркой).
    bool                         m_lastVerifyRxProof = false;
    bool                         m_opInFlight    = false;          // start/stop в полёте — ждём терминального
    bool                         m_inSyncNetCall = false;          // AVPN (краш-фикс): внутри вложенного
                                                                   // QEventLoop (awaitReply) → запрет повторного
                                                                   // входа guardedStart. НЕ сбрасывается сменой
                                                                   // состояния (в отличие от m_opInFlight) — иначе
                                                                   // reconcile внутри цикла застекал бы 2-й loop.exec
    int                          m_startAttempts = 0;              // подряд неудачных connect — анти-зацикливание
    // AVPN (sub-grace): флаг для UI «движок сам погасил туннель по истечению подписки» (Q_PROPERTY
    // subEnforcedStop) + гард однократности, пока идёт остановка. Оба сбрасывает явный start().
    bool                         m_subEnforcedStop = false;
    bool                         m_graceStopInFlight = false;
    enum class Op { None, Starting, Stopping };
    Op                           m_op = Op::None;                  // что сейчас в полёте (для обработки терминала)
    QTimer                       m_watchdog;                       // единый сторож (НЕ накапливаем singleShot)
    bool                         m_bootstrapped = false; // AVPN: bootstrap() УСПЕШНО выполнен (Task 11)
    qint64                       m_lastFgRefreshMs = 0;  // AVPN (store-flow E): троттл engine-level foreground-рефреша подписки (30с)
    bool                         m_bootstrapInFlight = false; // AVPN: цепочка ретраев идёт (дедуп QML-вызовов)
    int                          m_bootstrapRetries = 0;      // AVPN: счётчик попыток фетча подписки (бэкофф → вечный медленный цикл, BootstrapRetry.h)
    QTimer                       m_bootstrapRetryTimer;       // AVPN: единый таймер ретрая (member, НЕ singleShot-фабрика) — kickBootstrap() может его поджать
    WhitelistDetector           *m_whitelistDetector = nullptr; // AVPN (белые списки): nullptr на десктопе (гейт платформ)
    RuSplitSentinel             *m_ruSentinel = nullptr; // AVPN (D-3 п.26): дозор RU-сайтов (все платформы)
    bool                         m_whitelistAcked = false;      // AVPN (белые списки): «Понятно» текущего эпизода
    qint64                       m_whitelistEpisodeStartMs = 0; // AVPN (белые списки): старт активного эпизода (для телеметрии)
    bool                         m_whitelistEpisodesSent = false; // AVPN (белые списки): одна попытка отправки за сессию
    // AVPN (Task 7): авто-пауза «для покупок».
    QTimer                       m_pauseTimer;           // singleShot: истёк → бездействие → resume
    bool                         m_paused = false;       // туннель реально down, ждём авто-возврат
    bool                         m_wasConnected = false; // был ли активный туннель ДО паузы (нужно ли поднимать)
    // AVPN: кэш последних async-ответов /v1/devices и /v1/account (см. refreshDevices/refreshAccount).
    QVariantList                 m_devices;
    QVariantMap                  m_account;
    QVariantMap                  m_referral;   // AVPN (#37): кэш GET /v1/referral {code,link,invited,days_earned}
    QVariantList                 m_announcements;       // AVPN (P-ANN): активные объявления (fetch/LKG)
    QSet<int>                    m_announceShownAcked;  // AVPN (P-ANN): дедуп shown-ack за сессию
    void loadAnnouncementsLkg();                        // AVPN (P-ANN): LKG из QSettings при старте
    void persistAnnouncementsLkg();                     // AVPN (P-ANN): персист текущего списка
    // AVPN (Task 9 — APNs): последний device token/окружение от AvpnPushBridge — для ПЕРЕ-регистрации
    // после ротации subscription_token (redeemCode/redeemTransfer: старый токен на сервере сброшен).
    QString                      m_pushToken;
    QString                      m_pushEnv;
    QString                      m_pushPlatform; // "ios"|"android" из deviceTokenReady (пусто = легаси iOS)
    // AVPN (Task 9): запрос разрешения на пуши — один раз, после первого успешного коннекта (persist).
    bool                         m_pushPermissionAsked = false;
    // AVPN (Task 9): один device token-POST за сессию на пару (token,env) — без дублей на каждый коннект.
    QString                      m_pushTokenSent;
};

} // namespace avpn
