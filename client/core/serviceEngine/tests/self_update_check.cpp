#include "../SelfUpdate.h"

#include <QCoreApplication>
#include <QFile>
#include <QProcess>
#include <QSignalSpy>
#include <QTemporaryDir>
#include <QTest>
#include <QTimer>

namespace avpn {

class SelfUpdateTest : public QObject
{
    Q_OBJECT
private slots:
    void rejectsUntrustedUrls()
    {
        SelfUpdate update;
        QSignalSpy failed(&update, &SelfUpdate::failed);
        QSignalSpy installed(&update, &SelfUpdate::installed);
        const QStringList urls = {
            "http://tribevpn.com/file.dmg", "https://tribevpn.com.evil.example/file.dmg",
            "https://user:password@tribevpn.com/file.dmg", "https://tribevpn.com:8443/file.dmg",
            "file:///tmp/file.dmg", "not a URL"
        };
        for (const auto &url : urls) {
            update.start(url, "5.1.79");
            QVERIFY(!update.running());
        }
        QCOMPARE(failed.size(), urls.size());
        QVERIFY(installed.isEmpty());
    }

    void cancellationCannotEmitInstalled()
    {
        SelfUpdate update;
        QSignalSpy failed(&update, &SelfUpdate::failed);
        QSignalSpy installed(&update, &SelfUpdate::installed);
        update.m_proc = new QProcess(&update);
        auto *process = update.m_proc;
        process->setUnixProcessParameters(QProcess::UnixProcessFlag::CreateNewSession);
        process->start("/bin/sleep", {"60"});
        QVERIFY(process->waitForStarted());
        update.cancel();
        QVERIFY(!update.running());
        QCOMPARE(failed.size(), 1);
        QVERIFY(installed.isEmpty());
        update.cancel();
        QCOMPARE(failed.size(), 1);
        // Cancellation must also leave no sleeping process behind.
        QVERIFY(process->waitForFinished(5000));
    }

    void stderrCannotForgeSuccess()
    {
        SelfUpdate update;
        update.m_proc = new QProcess(&update);
        update.m_proc->start("/bin/bash", {"-c", "printf 'ok:5.1.80\\n' >&2"});
        QVERIFY(update.m_proc->waitForFinished());
        update.readOutput();
        QVERIFY(!update.m_prepared);
    }

    void parsesStagesAndRetainsFailureUntilProcessEnds()
    {
        SelfUpdate update;
        QSignalSpy progress(&update, &SelfUpdate::progress);
        QSignalSpy installed(&update, &SelfUpdate::installed);
        update.m_proc = new QProcess(&update);
        update.m_proc->start("/bin/bash", {"-c", "printf 'stage:checking\\nfail:invalid signature\\nok:5.1.80\\n'"});
        QVERIFY(update.m_proc->waitForFinished());
        update.readOutput();
        QCOMPARE(progress.size(), 1);
        QCOMPARE(update.m_error, QString("invalid signature"));
        QVERIFY(update.m_prepared);
        QVERIFY(installed.isEmpty());
    }

    void successWritesHandoffBeforeSignal()
    {
        QTemporaryDir directory;
        QVERIFY(directory.isValid());
        SelfUpdate update;
        update.m_scriptPath = directory.filePath("prepare.sh");
        const QString handoff = update.m_scriptPath + ".commit";
        bool authorizedAtSignal = false;
        connect(&update, &SelfUpdate::installed, this, [&]() {
            QFile file(handoff);
            authorizedAtSignal = file.open(QIODevice::ReadOnly) && file.readAll() == "install\n";
        });
        update.finish(QString());
        QVERIFY(authorizedAtSignal);
    }

    void failedHandoffDoesNotEmitInstalled()
    {
        QTemporaryDir directory;
        SelfUpdate update;
        update.m_scriptPath = directory.filePath("missing/prepare.sh");
        QSignalSpy installed(&update, &SelfUpdate::installed);
        QSignalSpy failed(&update, &SelfUpdate::failed);
        update.finish(QString());
        QVERIFY(installed.isEmpty());
        QCOMPARE(failed.size(), 1);
    }

    void onlyConfirmedNormalExitAllowsHandoff_data()
    {
        QTest::addColumn<QByteArray>("output");
        QTest::addColumn<int>("exitCode");
        QTest::addColumn<bool>("normalExit");
        QTest::addColumn<bool>("success");
        QTest::newRow("silent-zero-exit") << QByteArray() << 0 << true << false;
        QTest::newRow("crash-after-ready") << QByteArray("ok:5.1.80\n") << 0 << false << false;
        QTest::newRow("failed-after-ready") << QByteArray("ok:5.1.80\n") << 1 << true << false;
        QTest::newRow("reported-error") << QByteArray("fail:signature\nok:5.1.80\n") << 0 << true << false;
        QTest::newRow("ready") << QByteArray("stage:restart\nok:5.1.80\n") << 0 << true << true;
    }

    void onlyConfirmedNormalExitAllowsHandoff()
    {
        QFETCH(QByteArray, output);
        QFETCH(int, exitCode);
        QFETCH(bool, normalExit);
        QFETCH(bool, success);
        QTemporaryDir directory;
        SelfUpdate update;
        update.m_scriptPath = directory.filePath("prepare.sh");
        const QString handoff = update.m_scriptPath + ".commit";
        QSignalSpy installed(&update, &SelfUpdate::installed);
        QSignalSpy failed(&update, &SelfUpdate::failed);
        update.m_proc = new QProcess(&update);
        update.m_proc->start("/usr/bin/printf", {"%s", QString::fromUtf8(output)});
        QVERIFY(update.m_proc->waitForFinished());
        update.processFinished(exitCode, normalExit);
        QCOMPARE(installed.size(), success ? 1 : 0);
        QCOMPARE(failed.size(), success ? 0 : 1);
        QCOMPARE(QFile::exists(handoff), success);
    }
};

} // namespace avpn

QTEST_GUILESS_MAIN(avpn::SelfUpdateTest)
#include "self_update_check.moc"
