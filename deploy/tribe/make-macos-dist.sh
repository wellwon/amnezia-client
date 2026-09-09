#!/bin/bash
# make-macos-dist.sh — собрать раздаваемый macOS-дистрибутив Tribe VPN (демон-модель, ноль терминала).
# Предполагает, что app+демон УЖЕ собраны (cmake) в deploy/build-macos-desktop.
# Делает: Qt в app+демон → подпись Developer ID+runtime → daemon.pkg → вшивает pkg в app →
#         подпись app (entitlements) → [нотаризация] → dmg → [нотаризация dmg].
#
# Конечный пользователь: открыл dmg → перетащил в Applications → запустил → Connect →
# ОДИН системный промпт пароля (ставит демон) → подключено. Терминал НЕ нужен.
#
# Использование:
#   make-macos-dist.sh sign           # только подписать app с вшитым pkg (без dmg/нотаризации) — для теста
#   make-macos-dist.sh dmg            # + собрать dmg, без нотаризации
#   make-macos-dist.sh notarize       # + нотаризовать app и dmg (нужен keychain-профиль AC_NOTARY)
set -euo pipefail
STAGE="${1:-sign}"

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
BUILD="${TRIBE_RELEASE_BUILD:-$REPO/deploy/build-macos-desktop}"
APP="$BUILD/client/TribeVPN.app"
SRV="$BUILD/service/server"
QTBIN="$HOME/Qt/6.10.2/macos/bin"
DEVID="Developer ID Application: WellWon Limited (Q7DVH5MCWF)"
ENTS="$REPO/deploy/tribe/tribe-app.entitlements"
DIST="${TRIBE_RELEASE_DIST:-$HOME/avpn-build/dist}"; DMG="$DIST/Tribe VPN.dmg"
SIGN=(codesign --force --options runtime --timestamp --sign "$DEVID")
# Нотаризация ПРЯМЫМИ ключами (НЕ keychain-профиль AC_NOTARY: он спонтанно пропадал из
# кичейна — см. memory tribe-notary-keychain-flake; прямые аргументы не зависят от кичейна)
NOTARY_KEY=(--key "$HOME/.appstoreconnect/private_keys/AuthKey_BSDJAT949V.p8" --key-id BSDJAT949V --issuer 1fb2a58a-ce3b-470a-bfed-afa87c463e8a)

[ -d "$APP" ] || { echo "нет $APP — сначала cmake build"; exit 1; }

echo "=== 0. Чистка хвостов прошлых сборок (stale pkg/Helpers/tarball) ==="
rm -f  "$APP/Contents/Resources/Tribe-service.pkg"
rm -f  "$APP/Contents/Resources/tribe-svc.tar.gz" "$APP/Contents/Resources/tribe-svc-install.sh"
rm -rf "$APP/Contents/Helpers"

echo "=== 1. Qt в app (macdeployqt) ==="
"$QTBIN/macdeployqt" "$APP" -qmldir="$REPO/client/ui/qml"

echo "=== 2. Qt в демон (самодостаточность) ==="
bash "$REPO/deploy/tribe/bundle-daemon-qt.sh" "$SRV" >/dev/null

echo "=== 3. Подпись демона: Developer ID + hardened runtime + timestamp (inside-out) ==="
find "$SRV/Frameworks" -type f \( -name '*.dylib' -o -path '*/Versions/A/Qt*' \) -print0 \
  | while IFS= read -r -d '' f; do "${SIGN[@]}" "$f"; done
"${SIGN[@]}" "$SRV/amneziawg-go"
"${SIGN[@]}" "$SRV/Tribe-service"

echo "=== 4. Payload-tarball (подписанный демон) → Contents/Resources (непрозрачный ресурс) ==="
# Бинари уже подписаны Developer ID+runtime (шаг 3). Tarball codesign пломбирует как ресурс,
# нотаризация внутрь tar НЕ лезет → нет «unsigned nested code». Скрипт на установке распакует в /Library.
ST="$(mktemp -d)"
cp -f  "$SRV/Tribe-service" "$ST/Tribe-service"
cp -f  "$SRV/amneziawg-go"  "$ST/amneziawg-go"
cp -aR "$SRV/Frameworks"    "$ST/Frameworks"
mkdir -p "$ST/pf"; cp -f "$REPO/deploy/data/macos/pf/tribe."*.conf "$REPO/deploy/data/macos/pf/tribe.conf" "$ST/pf/"
# AVPN: маркер версии демона = хэш бинарей (меняется ⟺ меняется демон). Кладём В tarball (установщик
# перенесёт в /Library/.../VERSION) И в ресурс app (приложение сверяет с установленным → авто-
# переустановка при апдейте, ноль терминала). См. MacServiceInstaller::macServiceOutdated.
# AVPN 2026-09-04: хэш считаем по бинарям БЕЗ подписи. Подпись (шаг 3) несёт timestamp-токен,
# из-за чего маркер менялся КАЖДУЮ сборку при неизменённом демоне, и каждое обновление приложения
# спрашивало пароль на переустановку службы (MAC-23/24). Снятая подпись даёт одинаковые байты
# и для Developer-ID-, и для ad-hoc-подписанного бинаря (проверено 2026-09-04).
HT="$(mktemp -d)"
cp -f "$SRV/Tribe-service" "$HT/Tribe-service"; cp -f "$SRV/amneziawg-go" "$HT/amneziawg-go"
codesign --remove-signature "$HT/Tribe-service"; codesign --remove-signature "$HT/amneziawg-go"
DVER="$(cat "$HT/Tribe-service" "$HT/amneziawg-go" | shasum -a 256 | cut -c1-16)"
rm -rf "$HT"
echo "$DVER" > "$ST/VERSION"
echo "$DVER" > "$APP/Contents/Resources/tribe-svc.version"
echo "  daemon version: $DVER"
( cd "$ST" && COPYFILE_DISABLE=1 tar czf "$APP/Contents/Resources/tribe-svc.tar.gz" Tribe-service amneziawg-go Frameworks pf VERSION )
rm -rf "$ST"
cp -f "$REPO/deploy/tribe/tribe-svc-install.sh" "$APP/Contents/Resources/tribe-svc-install.sh"
chmod +x "$APP/Contents/Resources/tribe-svc-install.sh"
echo "  tarball: $(ls -la "$APP/Contents/Resources/tribe-svc.tar.gz" | awk '{print $5}') байт"

echo "=== 5/6. Подпись app: фреймворки/плагины inside-out + app c entitlements ==="
find "$APP/Contents/Frameworks" -type f \( -name '*.dylib' -o -path '*/Versions/*/Qt*' \) -print0 \
  | while IFS= read -r -d '' f; do "${SIGN[@]}" "$f" 2>/dev/null; done
find "$APP/Contents/PlugIns" -type f -name '*.dylib' -print0 \
  | while IFS= read -r -d '' f; do "${SIGN[@]}" "$f" 2>/dev/null; done
codesign --force --options runtime --timestamp --entitlements "$ENTS" --sign "$DEVID" "$APP"
codesign --verify --deep --strict --verbose=1 "$APP" && echo "  ✅ подпись app валидна"

[ "$STAGE" = sign ] && { echo "=== ГОТОВО (sign) — app: $APP ==="; exit 0; }

if [ "$STAGE" = notarize ]; then
  echo "=== 7. Нотаризация app ==="
  ZIP_DIR="$(mktemp -d /tmp/TribeVPN-notarize.XXXXXX)"
  ZIP="$ZIP_DIR/app.zip"
  ditto -c -k --keepParent "$APP" "$ZIP"
  xcrun notarytool submit "$ZIP" "${NOTARY_KEY[@]}" --wait
  xcrun stapler staple "$APP"
  rm -rf -- "$ZIP_DIR"
fi

echo "=== 8. dmg (фирменный layout через dmgbuild; staging чистый — НЕ create-dmg: он путал наш app со stale в dist/) ==="
# Оформление (фон/иконки/стрелка) — deploy/tribe/dmg/{settings.py,background.tiff};
# менять layout ТОЛЬКО здесь, ДО codesign dmg: после нотаризации образ трогать нельзя.
python3 -c "import dmgbuild" 2>/dev/null || { echo "нет dmgbuild: pip3 install --user --break-system-packages dmgbuild"; exit 1; }
mkdir -p "$DIST"; rm -rf "$DMG" "$DIST/Tribe VPN.app"
DMGROOT="$(mktemp -d)/dmg"; mkdir -p "$DMGROOT"
cp -R "$APP" "$DMGROOT/Tribe VPN.app"          # переименовываем копию для красивого drag-install
python3 -m dmgbuild -s "$REPO/deploy/tribe/dmg/settings.py" \
  -D app="$DMGROOT/Tribe VPN.app" "Tribe VPN" "$DMG"
rm -rf "$(dirname "$DMGROOT")"
codesign --force --timestamp --sign "$DEVID" "$DMG"

if [ "$STAGE" = notarize ]; then
  echo "=== 9. Нотаризация dmg ==="
  # КРИТИЧНО: смонтированный dmg ВЕШАЕТ pre-submission checks notarytool намертво
  # (висит на «initiating connection», submission ID не приходит). Перед сабмитом —
  # отмонтировать ВСЕ инстансы образа (Finder/прошлый прогон могли смонтировать).
  for dev in $(hdiutil info | grep -A30 "Tribe VPN.dmg" | grep -oE "/dev/disk[0-9]+" | sort -u); do
    hdiutil detach "$dev" -force 2>/dev/null || true
  done
  xcrun notarytool submit "$DMG" "${NOTARY_KEY[@]}" --wait
  xcrun stapler staple "$DMG"
  codesign -v -R=notarized --verbose=1 "$DMG" && echo "  ✅ dmg notarized (codesign -R=notarized exit0)"
  spctl -a -t open --context context:primary-signature -vv "$DMG" || true
fi
echo "=== ГОТОВО: $DMG ==="
ls -la "$DMG"
