# AVPN/Tribe — СОБСТВЕННАЯ система версий приложения. ЕДИНЫЙ ИСТОЧНИК ПРАВДЫ ДЛЯ ВСЕХ ПЛАТФОРМ.
# Перекрывает upstream Amnezia (set(AMNEZIAVPN_VERSION ...) в CMakeLists.txt) — чтобы при
# `git merge upstream` версия НИКОГДА не откатывалась на 4.9.x (родная версия Amnezia).
#
# ── TRIBE_VERSION: МАЖОР.МИНОР.ПАТЧ.BUILD (4 части) ──────────────────────────────────────────
#   МАЖОР.МИНОР.ПАТЧ — marketing-версия, идёт ВО ВСЕ платформы из одного значения:
#       • iOS    → CFBundleShortVersionString / MARKETING_VERSION  (client/cmake/ios.cmake)
#       • macOS  → MACOSX_BUNDLE_SHORT_VERSION_STRING                (client/cmake/macos.cmake; NE-вариант откачен)
#       • Android→ versionName  (= APP_MAJOR_VERSION)               (client/cmake/android.cmake)
#       • Windows→ APP_MAJOR_VERSION (FILEVERSION/инсталлятор)
#   BUILD           — CFBundleVersion (iOS/macOS), монотонно растёт. Для Android номер сборки —
#                     отдельный TRIBE_ANDROID_VERSION_CODE (целое, своя нумерация Google Play).
#
# ── ПРАВИЛА (см. memory tribe-ios-versioning-rule; doc docs/amnezia-fork/VERSIONING.md) ───────
#   • версия только РАСТЁТ; обязана быть > 4.9.2 (история app-record hk.wellwon.vpn, app 6778394015);
#   • схема 5.x (монотонно): 5.0.0 → … → 5.0.9 → 5.1.0 → … → 5.1.7 → …; НИКОГДА не 4.9.x и НИКОГДА не 2.4.x
#     (2.4.x < 4.9.x = откат → Apple отклоняет, апдейты не доходят — уже ломалось на 2.4.1);
#   • iOS/macOS build-number (BUILD) > последнего залитого в TestFlight (последний — см. верх
#     docs/amnezia-fork/CHANGELOG.md или `python3 ~/avpn-build/asc_list_builds.py`; число тут НЕ дублируем);
#   • Android versionCode > последнего залитого в Google Play (отдельная монотонная нумерация).
#
# БАМПИТЬ — ТОЛЬКО ЗДЕСЬ (две строки ниже). Больше нигде, ни для одной платформы, трогать не нужно.
set(TRIBE_VERSION 5.1.82.111)
set(TRIBE_ANDROID_VERSION_CODE 2169)
