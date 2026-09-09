#!/bin/bash
set -euo pipefail
QT="${QT_ROOT:-/Users/macbookpro/Qt/6.10.2/macos}"
HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="$(mktemp -d /tmp/tribe-config-refresh.XXXXXX)"
trap 'rm -rf -- "$OUT"' EXIT
"$QT/libexec/moc" -f"$HERE/../ConfigService.h" "$HERE/../ConfigService.h" -o "$OUT/moc_ConfigService.cpp"
"$QT/libexec/moc" "$HERE/config_refresh_check.cpp" -o "$OUT/config_refresh_check.moc"
clang++ -std=c++17 -fPIC -include arm_acle.h \
  -I"$QT/include" -I"$QT/lib/QtCore.framework/Headers" -I"$QT/lib/QtNetwork.framework/Headers" \
  -I"$QT/lib/QtTest.framework/Headers" -I"$OUT" -F"$QT/lib" \
  "$HERE/config_refresh_check.cpp" "$OUT/moc_ConfigService.cpp" \
  -framework QtCore -framework QtNetwork -framework QtTest -framework Foundation \
  -Wl,-rpath,"$QT/lib" -o "$OUT/config_refresh_check"
WW_TEST=1 WW_TEST_ID=config-refresh "$OUT/config_refresh_check"
