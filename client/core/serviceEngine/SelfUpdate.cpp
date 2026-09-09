// AVPN (реш. владельца 2026-09-02): установка обновления внутри приложения на десктопном macOS.
// Логика установки живёт в шелл-скрипте, который пишется во временный файл на время работы:
// так её видно целиком одним куском (аудит), и она не требует изменений бандла/CMake-инсталла.
//
// Скрипт печатает строки вида "stage:<текст>" (прогресс) и "fail:<причина>" (отказ). Любой отказ —
// терминальный: приложение НЕ устанавливается, пользователю показывается причина.

#include "SelfUpdate.h"

#include <QCoreApplication>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QDebug>
// QProcess есть не на всех наших платформах: в iOS-сборке Qt его нет вовсе, поэтому
// реализация установки компилируется только под десктопным macOS (PLATFORM-SCOPING.md).
#if defined(Q_OS_MACOS) && !defined(MACOS_NE)
#define AVPN_SELFUPDATE_IMPL 1
#include <QProcess>
#include <QProcessEnvironment>
#include <signal.h>
#endif
#include <QSaveFile>
#include <QTemporaryFile>
#include <QTimer>
#include <QUrl>

namespace avpn {

namespace {

// Наш Team ID и bundle id — жёстко вкомпилены: они не данные, а часть доверия (backend-first §5).
constexpr const char *kTeamId = "Q7DVH5MCWF";
constexpr const char *kBundleId = "hk.wellwon.vpn";
constexpr const char *kDefaultDmgUrl = "https://tribevpn.com/dl/TribeVPN.dmg";
constexpr const char *kAllowedHostSuffix = "tribevpn.com";

// $1 URL, $2 версия, $3 Team ID, $4 bundle id, $5 установленный app,
// $6 PID приложения, $7 файл разрешения замены, $8 каталог журнала.
// Каждый шаг печатает стадию; любой провал печатает fail: и выходит с ненулевым кодом.
constexpr const char *kScript = R"SH(#!/bin/bash
set -u
set -o pipefail
umask 077

url="$1"; cur="$2"; team="$3"; bid="$4"
app_dst="$5"; parent="$6"; commit="$7"
tmp="$(mktemp -d /tmp/tribe-update.XXXXXX)" || { echo "fail:Не удалось подготовить папку для загрузки"; exit 1; }
mnt=""
transaction=""
runner_pid=""

fail() { echo "fail:$1"; exit 1; }

cleanup() {
  [ -n "$runner_pid" ] && kill "$runner_pid" 2>/dev/null
  [ -n "$mnt" ] && hdiutil detach "$mnt" -quiet >/dev/null 2>&1
  [ -n "$transaction" ] && rm -rf -- "$transaction"
  rm -rf -- "$tmp"
}
trap cleanup EXIT
trap 'exit 1' TERM INT HUP

# Обновляем именно запущенную установленную копию. DMG/App Translocation/read-only —
# явный отказ до загрузки; установка из образа выполняется пользователем в Applications.
case "$app_dst" in
  /Volumes/*|*/AppTranslocation/*) fail "Перенесите Tribe VPN в папку «Программы» и запустите оттуда" ;;
esac
if [ ! -d "$app_dst/Contents" ] || [ -L "$app_dst" ] || [ ! -w "$(dirname "$app_dst")" ]; then
  fail "Нет прав на замену приложения. Перенесите Tribe VPN в папку «Программы»"
fi

log_dir="$8"
mkdir -p "$log_dir" || fail "Не удалось создать журнал обновления"
log="$log_dir/self-update.log"
exec 2>>"$log"
date >&2

echo "stage:Скачиваем обновление"
# Не следуем редиректам: URL уже проверен C++, Location может вести на чужой домен.
http_code="$(curl -q -fsS --proto '=https' --tlsv1.2 --retry 3 --retry-delay 2 \
        --connect-timeout 30 --max-time 900 --retry-max-time 900 \
        -w '%{http_code}' -o "$tmp/Tribe.dmg" "$url")"
if [ "$?" -ne 0 ] || [ "$http_code" != 200 ]; then
  echo "fail:Не удалось скачать обновление. Проверьте соединение."
  exit 1
fi

echo "stage:Проверяем подпись"
mnt="$(hdiutil attach "$tmp/Tribe.dmg" -nobrowse -readonly -mountrandom /tmp 2>/dev/null \
      | awk -F'\t' '/\/tmp\//{print $NF}' | tail -1)"
if [ -z "$mnt" ] || [ ! -d "$mnt" ]; then
  echo "fail:Образ обновления повреждён"
  exit 1
fi

app_src="$(/usr/bin/find "$mnt" -maxdepth 1 -name '*.app' -print -quit)"
if [ -z "$app_src" ]; then
  echo "fail:В образе нет приложения"
  exit 1
fi

# Подпись нашей командой разработки.
if ! codesign --verify --deep --strict \
    -R="anchor apple generic and certificate leaf[subject.OU] = \"$team\" and identifier \"$bid\"" \
    "$app_src" >/dev/null; then
  echo "fail:Подпись обновления не прошла проверку"
  exit 1
fi
got_team="$(codesign -dv "$app_src" 2>&1 | awk -F= '/TeamIdentifier/{print $2}')"
if [ "$got_team" != "$team" ]; then
  echo "fail:Обновление подписано не нами"
  exit 1
fi
got_bid="$(/usr/libexec/PlistBuddy -c 'Print CFBundleIdentifier' "$app_src/Contents/Info.plist" 2>/dev/null)"
if [ "$got_bid" != "$bid" ]; then
  echo "fail:В образе другое приложение"
  exit 1
fi

# Системный codesign проверяет нотарификацию без Xcode/Command Line Tools.
# stapler — инструмент разработчика, его нельзя требовать на компьютере пользователя.
if ! codesign --verify --check-notarization -R=notarized "$app_src" >/dev/null; then
  echo "fail:Обновление не заверено Apple"
  exit 1
fi

new_ver="$(/usr/libexec/PlistBuddy -c 'Print CFBundleShortVersionString' "$app_src/Contents/Info.plist" 2>/dev/null)"
if ! [[ "$new_ver" =~ ^[0-9]+(\.[0-9]+){1,3}$ ]]; then
  echo "fail:В образе не указана версия"
  exit 1
fi
# Строго новее текущей: сравниваем как версии, не как строки.
newest="$(printf '%s\n%s\n' "$cur" "$new_ver" | sort -V | tail -1)"
if [ "$new_ver" = "$cur" ] || [ "$newest" != "$new_ver" ]; then
  echo "fail:В образе не более новая версия"
  exit 1
fi

echo "stage:Устанавливаем"
# Подготовка на том же томе: после quit нужны только rename, а не долгое копирование
# в живой destination. Уникальная резервная копия не затирает предыдущий неудачный откат.
transaction="$(mktemp -d "$(dirname "$app_dst")/.tribe-update.XXXXXX")" \
  || fail "Не удалось подготовить установку в папке приложения"
staged="$transaction/staged.app"
if ! ditto "$app_src" "$staged" >/dev/null 2>&1; then
  echo "fail:Не удалось подготовить установку"
  exit 1
fi
if ! codesign --verify --deep --strict "$staged" >/dev/null; then
  fail "Копия обновления не прошла проверку"
fi
hdiutil detach "$mnt" -quiet || fail "Не удалось закрыть образ обновления"
mnt=""

# Замена и перезапуск — уже после выхода приложения: отдельный процесс переживает наш quit.
runner="$tmp/finish.sh"
cat > "$runner" <<'INNER'
#!/bin/bash
set -u
umask 077
staged="$1"; dst="$2"; parent="$3"; tmp="$4"; transaction="$5"; commit="$6"
backup="$transaction/previous.app"
fail() {
  echo "Update failed: $1" >&2
  # После quit нет окна Qt, поэтому ошибка остаётся в журнале и системном диалоге.
  /usr/bin/osascript - "$1" <<'APPLESCRIPT'
on run argv
  display alert "Не удалось обновить Tribe VPN" message (item 1 of argv) as warning
end run
APPLESCRIPT
  exit 1
}
touch "$tmp/ready" || exit 1
# Ждём выхода приложения (до 30 секунд), затем меняем бандл.
for _ in $(seq 1 60); do
  kill -0 "$parent" 2>/dev/null || break
  sleep 0.5
done
if kill -0 "$parent" 2>/dev/null; then
  rm -f -- "$commit"
  rm -rf -- "$transaction" "$tmp"
  fail "Приложение не завершилось. Закройте Tribe VPN и повторите обновление."
fi
# Выход/отмена/сбой приложения до подтверждённого handoff — никогда не установка.
if [ ! -f "$commit" ]; then
  rm -rf -- "$transaction" "$tmp"
  exit 1
fi
rm -f -- "$commit"
if ! mv -- "$dst" "$backup"; then
  open -n "$dst"
  rm -rf -- "$transaction" "$tmp"
  fail "Не удалось заменить приложение. Прежняя версия сохранена."
fi
if ! mv -- "$staged" "$dst"; then
  mv -- "$backup" "$dst" || fail "Не удалось восстановить приложение. Резервная копия: $backup"
  open -n "$dst"
  rm -rf -- "$transaction" "$tmp"
  fail "Не удалось установить обновление. Прежняя версия восстановлена."
fi
if ! open -n "$dst"; then
  # Сохраняем обе копии, если откат тоже не удался.
  mv -- "$dst" "$staged" && mv -- "$backup" "$dst" \
    || fail "Не удалось восстановить приложение. Резервная копия: $backup"
  open -n "$dst"
  rm -rf -- "$transaction" "$tmp"
  fail "Не удалось запустить обновление. Прежняя версия восстановлена."
fi
echo "Update handed to LaunchServices: $dst" >&2
rm -rf -- "$transaction" "$tmp"
INNER
chmod +x "$runner" || fail "Не удалось подготовить перезапуск"

# Закрываем stdin и оба канала QProcess; проверяем запуск до того, как просить GUI выйти.
nohup /bin/bash "$runner" "$staged" "$app_dst" "$parent" "$tmp" "$transaction" "$commit" \
  </dev/null >>"$log" 2>&1 &
runner_pid=$!
disown 2>/dev/null || true
for _ in $(seq 1 50); do
  [ -f "$tmp/ready" ] && break
  kill -0 "$runner_pid" 2>/dev/null || fail "Не удалось запустить перезапуск приложения"
  sleep 0.1
done
[ -f "$tmp/ready" ] || fail "Не удалось подготовить перезапуск приложения"
trap - EXIT

echo "stage:Перезапускаем приложение"
echo "ok:$new_ver"
exit 0
)SH";

} // namespace

SelfUpdate::SelfUpdate(QObject *parent) : QObject(parent), m_timeout(new QTimer(this))
{
    m_timeout->setSingleShot(true);
    connect(m_timeout, &QTimer::timeout, this, [this]() {
        finish(tr("Обновление заняло слишком много времени. Попробуйте ещё раз."));
    });
}

SelfUpdate::~SelfUpdate()
{
    if (!m_scriptPath.isEmpty())
        QFile::remove(m_scriptPath);
}

bool SelfUpdate::isSupported()
{
#if defined(Q_OS_MACOS) && !defined(MACOS_NE)
    return true;
#else
    return false;
#endif
}

QString SelfUpdate::defaultDmgUrl()
{
    return QString::fromLatin1(kDefaultDmgUrl);
}

bool SelfUpdate::running() const
{
    return m_proc != nullptr;
}

void SelfUpdate::start(const QString &dmgUrl, const QString &currentVersion)
{
    if (!isSupported()) {
        emit failed(tr("Обновление внутри приложения тут недоступно"));
        return;
    }
    if (m_proc)   // повторный клик — не плодим второй загрузчик
        return;

    // Хост-гард: даже если конфиг подписан, URL обязан вести на наш домен по https.
    const QUrl url(dmgUrl.isEmpty() ? defaultDmgUrl() : dmgUrl);
    const bool hostOk = url.scheme() == QLatin1String("https")
                        && (url.host() == QLatin1String(kAllowedHostSuffix)
                            || url.host().endsWith(QLatin1String(".") + QLatin1String(kAllowedHostSuffix)));
    if (!url.isValid() || !hostOk || !url.userInfo().isEmpty()
        || (url.port() != -1 && url.port() != 443)) {
        emit failed(tr("Адрес обновления не прошёл проверку"));
        return;
    }

    // Скрипт кладём во временный файл на время установки (0700) и удаляем за собой.
    QTemporaryFile script(QDir::tempPath() + QStringLiteral("/tribe-update-XXXXXX.sh"));
    if (!script.open()) {
        emit failed(tr("Не удалось подготовить обновление"));
        return;
    }
    if (script.write(kScript) != qint64(qstrlen(kScript)) || !script.flush()
        || !script.setPermissions(QFile::ReadOwner | QFile::WriteOwner | QFile::ExeOwner)) {
        emit failed(tr("Не удалось сохранить установщик обновления"));
        return;
    }
    script.setAutoRemove(false);
    m_scriptPath = script.fileName();
    script.close();
    m_error.clear();
    m_prepared = false;

#ifdef AVPN_SELFUPDATE_IMPL
    const QDir executableDir(QCoreApplication::applicationDirPath());
    const QString appPath = QDir::cleanPath(executableDir.absoluteFilePath(QStringLiteral("../..")));
    if (!appPath.endsWith(QLatin1String(".app"))
        || !QFileInfo::exists(appPath + QStringLiteral("/Contents/Info.plist"))) {
        finish(tr("Запустите установленное приложение из папки «Программы»"));
        return;
    }
    m_proc = new QProcess(this);
    m_proc->setUnixProcessParameters(QProcess::UnixProcessFlag::CreateNewSession);
    // Протокол стадий — только stdout. stderr утилит не может подделать ok:/fail:.
    m_proc->setProcessChannelMode(QProcess::SeparateChannels);
    auto environment = QProcessEnvironment::systemEnvironment();
    environment.insert(QStringLiteral("PATH"), QStringLiteral("/usr/bin:/bin:/usr/sbin:/sbin"));
    m_proc->setProcessEnvironment(environment);

    connect(m_proc, &QProcess::readyReadStandardOutput, this, &SelfUpdate::readOutput);
    connect(m_proc, &QProcess::readyReadStandardError, this, [this]() {
        if (m_proc)
            qWarning().noquote() << "[selfupdate]" << QString::fromUtf8(m_proc->readAllStandardError());
    });
    connect(m_proc, &QProcess::errorOccurred, this,
            [this](QProcess::ProcessError error) {
                if (error == QProcess::FailedToStart)
                    finish(tr("Не удалось запустить обновление"));
            });
    connect(m_proc, QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished), this,
            [this](int code, QProcess::ExitStatus status) {
                processFinished(code, status == QProcess::NormalExit);
            });

    m_timeout->start(20 * 60 * 1000);
    m_proc->start(QStringLiteral("/bin/bash"),
                  { m_scriptPath, url.toString(QUrl::FullyEncoded), currentVersion,
                    QString::fromLatin1(kTeamId), QString::fromLatin1(kBundleId), appPath,
                    QString::number(QCoreApplication::applicationPid()),
                    m_scriptPath + QStringLiteral(".commit"),
                    QDir::homePath() + QStringLiteral("/Library/Logs/Tribe VPN") });
#else
    Q_UNUSED(currentVersion)
#endif
}

void SelfUpdate::cancel()
{
    if (!m_proc)
        return;
    finish(tr("Обновление отменено"));
}

void SelfUpdate::readOutput()
{
#ifdef AVPN_SELFUPDATE_IMPL
    while (m_proc && m_proc->canReadLine()) {
        const QString line = QString::fromUtf8(m_proc->readLine()).trimmed();
        if (line.startsWith(QLatin1String("stage:")))
            emit progress(line.mid(6));
        else if (line.startsWith(QLatin1String("fail:")))
            m_error = line.mid(5);
        else if (line.startsWith(QLatin1String("ok:")) && line.size() > 3)
            m_prepared = true;
    }
#endif
}

void SelfUpdate::processFinished(int code, bool normalExit)
{
    readOutput();
    if (!m_proc) // обработчик progress мог отменить установку
        return;
    if (!m_error.isEmpty())
        finish(m_error);
    else if (!normalExit || code != 0 || !m_prepared)
        finish(tr("Обновление не подготовлено. Попробуйте ещё раз."));
    else
        finish(QString());
}

void SelfUpdate::finish(const QString &reason)
{
    m_timeout->stop();
    QString error = reason;
    if (error.isEmpty()) {
        // Финишер меняет файлы только после этого разрешения И выхода нашего PID.
        // Отмена/аварийный выход до передачи управления не приведут к установке позже.
        QSaveFile commit(m_scriptPath + QStringLiteral(".commit"));
        if (!commit.open(QIODevice::WriteOnly)
            || commit.write("install\n") != 8 || !commit.commit())
            error = tr("Не удалось передать установку процессу перезапуска");
    }
    if (!m_scriptPath.isEmpty()) {
        QFile::remove(m_scriptPath);
        m_scriptPath.clear();
    }
    if (m_proc) {
#ifdef AVPN_SELFUPDATE_IMPL
        m_proc->disconnect(this);
        if (m_proc->state() != QProcess::NotRunning) {
            // TERM даёт shell выполнить cleanup; kill — только если он не завершился.
            const qint64 pid = m_proc->processId();
            if (pid > 0)
                ::kill(-pid_t(pid), SIGTERM); // включая curl/hdiutil и ещё не принятый финишер
            else
                m_proc->terminate();
            QTimer::singleShot(3000, m_proc, [pid, process = m_proc]() {
                if (pid > 0)
                    ::kill(-pid_t(pid), SIGKILL);
                process->kill();
            });
            connect(m_proc, QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished),
                    m_proc, &QObject::deleteLater);
        } else {
            m_proc->deleteLater();
        }
#endif
        m_proc = nullptr;
    }
    if (error.isEmpty())
        emit installed();
    else
        emit failed(error);
}

} // namespace avpn
