#pragma once
// AVPN (реш. владельца 2026-09-02): обновление приложения ВНУТРИ приложения на десктопном macOS.
// Кнопка «Обновить» на экране обновления не открывает браузер, а сама скачивает наш .dmg с /dl/,
// ПРОВЕРЯЕТ подпись и нотаризацию, заменяет запущенный установленный .app и перезапускает приложение
// (выход из приложения — на стороне AvpnEngineQml по installed(): финишер ждёт именно его).
//
// Инварианты (нарушение любого = не устанавливать, честная ошибка пользователю):
//   1. Скачиваем только по https и только с хоста, пришедшего из подписанного /v1/config
//      (urls.macos_dmg_url) либо с вкомпиленного фолбэка. Никаких редиректов на другой хост.
//   2. Устанавливаем только бандл с нашим Team ID и нашим bundle id, прошедший codesign --verify
//      и системную проверку нотарификации codesign (без зависимости от Xcode).
//   3. Версия в образе обязана быть СТРОГО выше текущей (не даём откатить на старую).
//   4. Ничего не делаем от root: замена идёт правами пользователя; нет прав на папку приложения —
//      честная ошибка с предложением перенести приложение в «Программы».
//   5. Ни одного nested QEventLoop на GUI-потоке (CONNECT-INVARIANTS §1): весь процесс — QProcess
//      с сигналами, прогресс уходит наверх строками.
//
// Платформа: только Q_OS_MACOS && !MACOS_NE. На остальных isSupported() == false, и UI открывает
// страницу загрузки, как раньше.

#include <QObject>
#include <QString>

QT_BEGIN_NAMESPACE
class QProcess;
class QTimer;
QT_END_NAMESPACE

namespace avpn {

class SelfUpdate : public QObject
{
    Q_OBJECT
public:
    explicit SelfUpdate(QObject *parent = nullptr);
    ~SelfUpdate() override;

    // Сборка умеет обновлять себя сама (десктопный macOS). Проверяется на этапе компиляции.
    static bool isSupported();

    // Хост, с которого разрешено качать образ, и путь по умолчанию.
    static QString defaultDmgUrl();

    // true, если процесс уже идёт (повторный клик — no-op, а не второй загрузчик).
    bool running() const;

    // dmgUrl — из TuningStore/urls (фолбэк defaultDmgUrl()); currentVersion — версия приложения
    // ("5.1.69"), она же нижняя граница: образ со старшей версией установится, с равной/младшей нет.
    void start(const QString &dmgUrl, const QString &currentVersion);

    void cancel();

signals:
    // Человеческая стадия для UI («Скачиваем…», «Проверяем подпись…», «Устанавливаем…»).
    void progress(const QString &text);
    // Установка не удалась; reason уже готов к показу пользователю (без путей и внутренностей).
    void failed(const QString &reason);
    // Образ проверен, финишер готов: приложение должно выйти, чтобы разрешить замену.
    // Это подтверждение передачи установки, а не успешного запуска новой версии.
    void installed();

private:
    friend class SelfUpdateTest;
    void finish(const QString &reason);   // reason пустой = успех
    void readOutput();
    void processFinished(int code, bool normalExit);

    QProcess *m_proc = nullptr;
    QTimer *m_timeout = nullptr;
    QString m_error;
    bool m_prepared = false;
    QString m_scriptPath;                 // временный файл со скриптом установки (удаляем за собой)
};

} // namespace avpn
