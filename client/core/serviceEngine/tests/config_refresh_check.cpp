// Real ConfigService + loopback HTTP server. Storage and signature verification are
// isolated fixtures; Ed25519 itself has a separate regression suite.
#define AVPN_CONFIGSTORE_TEST
#include <QByteArray>
#include <QStringList>
namespace avpn {
class ConfigStore {
public:
    static QByteArray loadConfig() { return {}; }
    static void saveConfig(const QByteArray &) {}
    static QStringList loadEdges() { return {}; }
    static void saveEdges(const QStringList &) {}
    static QString activeEdge(const QString &value) { return value; }
    static void setActiveEdge(const QString &) {}
};
bool verifyDetached(const QString &, const QByteArray &, const QByteArray &sig)
{
    return sig == "fixture-signature";
}
}
#include "../ConfigService.cpp"
#include <QTcpServer>
#include <QTcpSocket>
#include <QTest>

class ConfigRefreshTest : public QObject {
    Q_OBJECT
private slots:
    void refreshesWithoutApplicationRestart()
    {
        runScenario(false);
    }
    void doesNotOverlapSlowRequests()
    {
        runScenario(true);
    }
private:
    void runScenario(bool hold)
    {
        QTcpServer server;
        QVERIFY(server.listen(QHostAddress::LocalHost));
        int requests = 0;
        QString version = "5.1.82";
        connect(&server, &QTcpServer::newConnection, this, [&]() {
            while (auto *socket = server.nextPendingConnection()) {
                connect(socket, &QTcpSocket::disconnected, socket, &QObject::deleteLater);
                connect(socket, &QTcpSocket::readyRead, socket, [&, socket]() {
                    const QByteArray request = socket->readAll();
                    const bool config = request.startsWith("GET /v1/config ");
                    if (config) {
                        ++requests;
                        if (hold)
                            return;
                    }
                    const QByteArray body = config
                        ? QString("{\"recommended_version\":{\"macos\":\"%1\"}}").arg(version).toUtf8()
                        : QByteArray("{}");
                    socket->write("HTTP/1.1 200 OK\r\nConnection: close\r\nX-Tribe-Sig: fixture-signature\r\nContent-Length: "
                                  + QByteArray::number(body.size()) + "\r\n\r\n" + body);
                    socket->disconnectFromHost();
                });
            }
        });
        QNetworkAccessManager network;
        const QString base = QString("http://127.0.0.1:%1").arg(server.serverPort());
        avpn::ConfigService service(&network, base, "fixture-key", {base});
        service.start();
        auto *timer = service.findChild<QTimer *>("macosConfigRefresh");
        QVERIFY(timer);
        QCOMPARE(timer->interval(), 15 * 60 * 1000);
        QVERIFY(timer->isActive());
        QTRY_COMPARE(requests, 1);
        if (hold) {
            timer->setInterval(20);
            QTest::qWait(100);
            QCOMPARE(requests, 1);
        } else {
            QTRY_COMPARE(service.config().recommendedVersion.value("macos"), QString("5.1.82"));
            version = "5.1.83";
            timer->setInterval(20);
            QTRY_COMPARE(service.config().recommendedVersion.value("macos"), version);
            QVERIFY(requests >= 2);
        }
    }
};
QTEST_GUILESS_MAIN(ConfigRefreshTest)
#include "config_refresh_check.moc"
