#!/bin/bash
# bundle-daemon-qt.sh — делает root-демон Tribe-service самодостаточным:
# вшивает транзитивное замыкание его не-системных зависимостей (Qt + openssl)
# в <daemon_dir>/Frameworks и переписывает rpath на @loader_path/Frameworks,
# убирая dev-пути (~/Qt, ~/.conan2). После этого демон запускается на машине БЕЗ Qt.
#
# Использование: bundle-daemon-qt.sh /путь/к/service/server   (каталог с Tribe-service)
# Источники фреймворков: уже развёрнутый TribeVPN.app/Contents/Frameworks (macdeployqt),
# затем ~/Qt/<ver>/macos/lib, затем conan-каталог из текущего rpath бинаря.
set -euo pipefail

SRVDIR="${1:?укажи каталог с Tribe-service}"
DAEMON="$SRVDIR/Tribe-service"
[ -x "$DAEMON" ] || { echo "нет $DAEMON"; exit 1; }

APP_FW="$SRVDIR/../../client/TribeVPN.app/Contents/Frameworks"
QT_LIB="$HOME/Qt/6.10.2/macos/lib"
FW="$SRVDIR/Frameworks"
rm -rf "$FW"; mkdir -p "$FW"

# conan-каталоги из текущих rpath бинаря (для libssl/libcrypto)
CONAN_DIRS=$(otool -l "$DAEMON" | awk '/LC_RPATH/{f=1} f&&/path/{print $2; f=0}' | grep -E "conan2|/p/lib" || true)

# Найти исходник зависимости по её @rpath-имени (framework path или dylib).
find_src() {
  local dep="$1"               # напр. QtCore.framework/Versions/A/QtCore  или  libssl.3.dylib
  case "$dep" in
    *.framework/*)
      local fwname="${dep%%.framework/*}.framework"   # QtCore.framework
      for base in "$APP_FW" "$QT_LIB"; do
        [ -d "$base/$fwname" ] && { echo "$base/$fwname"; return; }
      done ;;
    *)
      local b="$(basename "$dep")"
      [ -f "$APP_FW/$b" ] && { echo "$APP_FW/$b"; return; }
      for d in $CONAN_DIRS "$QT_LIB"; do
        [ -f "$d/$b" ] && { echo "$d/$b"; return; }
      done ;;
  esac
  return 1
}

declare -A DONE
queue=()

enqueue_deps() {  # вытащить @rpath-зависимости из бинаря, добавить в очередь
  local bin="$1"
  while read -r dep; do
    [ -z "$dep" ] && continue
    queue+=("${dep#@rpath/}")
  done < <(otool -L "$bin" | awk '/@rpath\//{print $1}')
}

enqueue_deps "$DAEMON"

while [ ${#queue[@]} -gt 0 ]; do
  dep="${queue[0]}"; queue=("${queue[@]:1}")
  [ -n "${DONE[$dep]:-}" ] && continue
  DONE[$dep]=1
  src="$(find_src "$dep")" || { echo "  ⚠️ НЕ НАЙДЕН источник: $dep"; continue; }
  case "$dep" in
    *.framework/*)
      fwname="${dep%%.framework/*}.framework"
      if [ ! -d "$FW/$fwname" ]; then
        cp -aR "$src" "$FW/$fwname"
        echo "  + $fwname"
        enqueue_deps "$FW/$fwname/Versions/A/${fwname%.framework}"
      fi ;;
    *)
      b="$(basename "$dep")"
      if [ ! -f "$FW/$b" ]; then
        cp -aL "$src" "$FW/$b"; chmod u+w "$FW/$b"
        echo "  + $b"
        enqueue_deps "$FW/$b"
      fi ;;
  esac
done

# rpath демона: убрать dev-пути, добавить относительный @loader_path/Frameworks
for rp in $(otool -l "$DAEMON" | awk '/LC_RPATH/{f=1} f&&/path/{print $2; f=0}'); do
  install_name_tool -delete_rpath "$rp" "$DAEMON" 2>/dev/null || true
done
install_name_tool -add_rpath "@loader_path/Frameworks" "$DAEMON"

echo "=== Готово. Вшито в $FW: ==="
ls "$FW"
echo "=== rpath демона теперь: ==="
otool -l "$DAEMON" | awk '/LC_RPATH/{f=1} f&&/path/{print "  ",$2; f=0}'
