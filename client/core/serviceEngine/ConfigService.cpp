// client/core/serviceEngine/ConfigService.cpp
#include "ConfigService.h"

#include "ConfigStore.h"
#include "Ed25519Verify.h"
#include "EdgeWalk.h"
#include "NetAwait.h"

#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>

namespace avpn {

ConfigService::ConfigService(QNetworkAccessManager *nam, const QString &baseUrl,
                             const QString &pubKeyHex, const QStringList &bakedEdges,
                             QObject *parent)
    : QObject(parent), m_nam(nam), m_pubKeyHex(pubKeyHex), m_bakedEdges(bakedEdges), m_refreshTimer(this)
{
    m_activeBase = ConfigStore::activeEdge(baseUrl.isEmpty() && !bakedEdges.isEmpty()
                                               ? bakedEdges.first()
                                               : baseUrl);
#if defined(Q_OS_MACOS) && !defined(MACOS_NE)
    // macOS часто работает неделями без выхода: обновления должны обнаруживаться
    // и в уже открытом приложении. После сна Qt доставит просроченный timeout.
    m_refreshTimer.setObjectName(QStringLiteral("macosConfigRefresh"));
    m_refreshTimer.setInterval(15 * 60 * 1000);
    connect(&m_refreshTimer, &QTimer::timeout, this, &ConfigService::fetchConfig);
#endif
}

void ConfigService::start()
{
    // 1) LKG из кеша — мгновенно, без сети.
    const QByteArray lkg = ConfigStore::loadConfig();
    if (!lkg.isEmpty()) {
        RemoteConfig c;
        QString err;
        if (parseConfig(lkg, c, err)) {
            m_config = c;
            emit configApplied(m_config);
        }
    }
    // 2) свежий фетч (async).
    fetchConfig();
    fetchEdges();
#if defined(Q_OS_MACOS) && !defined(MACOS_NE)
    m_refreshTimer.start();
#endif
}

int ConfigService::failThreshold() const
{
    const int t = static_cast<int>(numberOr(m_config, QStringLiteral("edge_fail_threshold"), 3));
    return t < 1 ? 1 : t;
}

void ConfigService::fetchConfig()
{
    if (!m_nam || m_configInFlight)
        return;
    m_configInFlight = true;
    QNetworkRequest req{QUrl(m_activeBase + QStringLiteral("/v1/config"))};
    QNetworkReply *reply = m_nam->get(req);
    armTimeout(reply);
    connect(reply, &QNetworkReply::finished, this, [this, reply]() {
        m_configInFlight = false;
        reply->deleteLater();
        const int code = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        // Только транспортный сбой = проблема ЭТОГО входа → повод шагнуть на другой edge:
        // code==0 (abort/timeout из armTimeout, либо сокет не подключился) или 5xx (серверная авария).
        // Ревью 2026-07-12 (finding 2): для ДЕТЕКТОРА белых списков классификация ДРУГАЯ —
        // любой дошедший HTTP-статус (вкл. 5xx: бэк упал, но сеть жива) = transportOk;
        // транспортный фейл только code==0. Иначе обычный 5xx-инцидент бэка кормил детектор.
        if (code == 0 || code >= 500) {
            if (code == 0)
                emit transportFailed();
            else
                emit transportOk();
            reportNetworkFailure();
            return;
        }
        emit transportOk();
        // Любой иной non-2xx (401/403/410/404/4xx) ДОКАЗЫВАЕТ, что edge достижим — ответ пришёл с
        // прикладного слоя. Проблема НЕ в маршруте (это авторизация/подписка/путь), уходить с
        // рабочего входа нельзя → сбрасываем стрик, тело не применяем.
        if (code < 200 || code >= 300) {
            reportNetworkSuccess();
            return;
        }
        reportNetworkSuccess();
        const QByteArray body = reply->readAll();
        const QByteArray sig = reply->rawHeader(QByteArrayLiteral("X-Tribe-Sig"));
        applyBody(body, sig);
    });
}

void ConfigService::fetchEdges()
{
    if (!m_nam)
        return;
    QNetworkRequest req{QUrl(m_activeBase + QStringLiteral("/v1/edges"))};
    QNetworkReply *reply = m_nam->get(req);
    armTimeout(reply);
    connect(reply, &QNetworkReply::finished, this, [this, reply]() {
        reply->deleteLater();
        const int code = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        if (code < 200 || code >= 300)
            return; // edges — вспомогательный; primary всё равно вшит
        const QByteArray body = reply->readAll();
        const QByteArray sig = reply->rawHeader(QByteArrayLiteral("X-Tribe-Sig"));
        if (!verifyDetached(m_pubKeyHex, body, sig))
            return; // не доверяем неподписанному списку зеркал
        RemoteConfig tmp;
        QString err;
        // /v1/edges — то же тело-форма {edges:[...], ttl_s}; переиспользуем парсер (edges field).
        if (parseConfig(body, tmp, err) && !tmp.edges.isEmpty())
            ConfigStore::saveEdges(tmp.edges);
    });
}

void ConfigService::applyBody(const QByteArray &body, const QByteArray &sigB64)
{
    if (!verifyDetached(m_pubKeyHex, body, sigB64))
        return; // подпись не прошла → игнор, остаёмся на кеше/дефолтах
    RemoteConfig c;
    QString err;
    if (!parseConfig(body, c, err))
        return;
    m_config = c;
    ConfigStore::saveConfig(body);
    if (!c.edges.isEmpty())
        ConfigStore::saveEdges(c.edges);
    emit configApplied(m_config);
}

// ВНИМАНИЕ: report* — семантика EDGE-WALK («этот вход плох», 5xx тоже повод шагнуть).
// Сигналы transportFailed/transportOk для детектора белых списков здесь НЕ эмитятся
// (ревью 2026-07-12, finding 2): у детектора иная классификация (5xx = сеть жива) —
// эмиссии стоят по местам, где известен code (fetchConfig выше; движковые фетчи зовут
// noteControlPlane* напрямую).
void ConfigService::reportNetworkSuccess()
{
    m_failStreak = 0;
}

void ConfigService::reportNetworkFailure()
{
    if (++m_failStreak < failThreshold())
        return;
    m_failStreak = 0;
    const QStringList cands = edgeCandidates(ConfigStore::loadEdges(), m_bakedEdges);
    const QString next = nextEdge(cands, m_activeBase);
    if (next == m_activeBase)
        return;
    m_activeBase = next;
    ConfigStore::setActiveEdge(next);
    emit activeEdgeChanged(next);
    fetchConfig(); // немедленно пробуем новый вход
}

} // namespace avpn
