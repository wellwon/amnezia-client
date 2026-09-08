#!/bin/bash
# AVPN (волна AWG 3.1 + Xray, этап D3): автономная проверка Apple-слоя xray-пути NE.
#
# Шаг 1 (всегда, ~5с, без устройства и без Xcode-проекта): хостовый Swift-тест изолированных
# Foundation-only файлов — TunnelRuntimeStatus.swift (аккумулятор rx/tx, поколения сессии,
# payload runtime status v1) и XraySocketCallbackLifecycle.swift (слот protect-колбэка,
# забор поздних колбэков, точный teardown, gate нативных старт/стоп).
#
# Шаг 2 (опционально, --ne): компиляция реальной цели Network Extension под iphoneos —
# единственный способ проверить PacketTunnelProvider+Xray.swift целиком (libxray, hev,
# NetworkExtension). Требует настроенной папки сборки iOS (по умолчанию deploy/build,
# создаётся обычным configure-циклом iOS). Полный архив НЕ запускается.
#
# Использование:
#   bash client/platforms/ios/tests/run_ios_swift_checks.sh            # только хостовый тест
#   bash client/platforms/ios/tests/run_ios_swift_checks.sh --ne       # + сборка цели NE
#   IOS_BUILD_DIR=~/my-ios-build bash .../run_ios_swift_checks.sh --ne
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IOS_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$IOS_DIR/../../.." && pwd)"
IOS_BUILD_DIR="${IOS_BUILD_DIR:-$REPO_ROOT/deploy/build}"
WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

echo "== 1/2 хостовый Swift-тест (macOS SDK) =="
xcrun --sdk macosx swiftc -Onone -parse-as-library \
    -o "$WORK_DIR/xray_lifecycle_tests" \
    "$IOS_DIR/TunnelRuntimeStatus.swift" \
    "$IOS_DIR/XraySocketCallbackLifecycle.swift" \
    "$IOS_DIR/IPv4RouteSpec.swift" \
    "$IOS_DIR/IPv6RouteSpec.swift" \
    "$SCRIPT_DIR/XraySocketCallbackLifecycleTests.swift"
"$WORK_DIR/xray_lifecycle_tests"

if [[ "${1:-}" != "--ne" ]]; then
    echo "== 2/2 сборка цели NE пропущена (запусти с --ne) =="
    exit 0
fi

if [[ ! -f "$IOS_BUILD_DIR/AmneziaVPN.xcodeproj/project.pbxproj" ]]; then
    echo "СТОП: нет настроенной сборки iOS в $IOS_BUILD_DIR — нечего собирать." >&2
    echo "Настрой её обычным configure-циклом iOS или задай IOS_BUILD_DIR." >&2
    exit 1
fi

echo "== 2/2 регенерация xcodeproj + сборка цели networkextension (iphoneos) =="
# Регенерация обязательна: новые .swift из client/ios/networkextension/CMakeLists.txt
# в стейл-проекте отсутствуют и молча не попадают в компиляцию.
(cd "$IOS_BUILD_DIR" && PATH="$HOME/Library/Python/3.13/bin:$PATH" cmake . >/dev/null)
# Битый симлинк .appex от прошлого архива (DerivedData удалена) роняет MkDir цели.
APPEX="$IOS_BUILD_DIR/client/ios/networkextension/Release-iphoneos/AmneziaVPNNetworkExtension.appex"
if [[ -L "$APPEX" && ! -e "$APPEX" ]]; then
    rm -f "$APPEX"
fi
xcodebuild -project "$IOS_BUILD_DIR/AmneziaVPN.xcodeproj" \
    -target networkextension -configuration Release \
    -destination 'generic/platform=iOS' \
    CODE_SIGNING_ALLOWED=NO CODE_SIGNING_REQUIRED=NO \
    ENABLE_DEBUG_DYLIB=NO ENABLE_PREVIEWS=NO build
