#!/bin/bash
# Isolated QtCore/QtTest build; does not build or run the VPN app or touch its installation.
set -euo pipefail
QT="${QT_ROOT:-/Users/macbookpro/Qt/6.10.2/macos}"
HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="$(mktemp -d /tmp/tribe-self-update-qt.XXXXXX)"
trap 'rm -rf -- "$OUT"' EXIT
"$QT/libexec/moc" -f"$HERE/../SelfUpdate.h" "$HERE/../SelfUpdate.h" -o "$OUT/moc_SelfUpdate.cpp"
"$QT/libexec/moc" "$HERE/self_update_check.cpp" -o "$OUT/self_update_check.moc"
clang++ -std=c++17 -fPIC -include arm_acle.h \
  -I"$QT/include" -I"$QT/lib/QtCore.framework/Headers" -I"$QT/lib/QtTest.framework/Headers" \
  -I"$OUT" -F"$QT/lib" \
  "$HERE/../SelfUpdate.cpp" "$OUT/moc_SelfUpdate.cpp" "$HERE/self_update_check.cpp" \
  -framework QtCore -framework QtTest -framework Foundation \
  -Wl,-rpath,"$QT/lib" -o "$OUT/self_update_check"
WW_TEST=1 WW_TEST_ID=self-update-qt "$OUT/self_update_check"
# The implementation must also remain compilable when the macOS desktop branch is disabled.
clang++ -std=c++17 -fPIC -include arm_acle.h -DMACOS_NE -fsyntax-only \
  -I"$QT/include" -I"$QT/lib/QtCore.framework/Headers" -F"$QT/lib" "$HERE/../SelfUpdate.cpp"
