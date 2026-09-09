# macOS self-update regression checks

Run from the client repository:

```sh
bash client/core/serviceEngine/tests/build_self_update.sh
WW_TEST=1 WW_TEST_ID=self-update python3 -B -m unittest discover \
  -s client/core/serviceEngine/tests -p test_self_update.py -v
```

The Qt runner compiles the real `SelfUpdate.cpp` with QtCore/QtTest, exercises URL
validation, cancellation, stdout/stderr separation, exit-status handling and the
handoff marker. It also compiles the implementation with `MACOS_NE` defined to
check the platform guard. Set `QT_ROOT` to use another installed Qt kit.

The Python suite extracts the embedded production shell script and runs it against
temporary app fixtures. Network, mount, signature and LaunchServices commands are
stubbed; PlistBuddy and file-system operations use local fixtures. It covers live
parent/exit/timeout, cancellation before handoff, successful replacement, download
and verification failures, failed replacement, failed launch and failed rollback.
It does not alter `/Applications`, launch the VPN, use its settings or access keys.

## Installation contract

Preparation copies the verified app to a private directory on the destination
volume. The detached finisher acknowledges readiness. Only an explicit `ok:` plus
a normal zero exit permits C++ to atomically create the handoff marker and emit
`installed()`. `AvpnEngineQml` then requests application shutdown.

The finisher requires both the marker and termination of the supplied application
PID. A 30-second shutdown timeout leaves the old app untouched. Replacement uses
renames, with a unique backup; a failed rename or LaunchServices request restores
the old app where possible. If restoration fails, the backup is retained and its
path is shown in the error dialog. Normal completion and successful rollback clean
up temporary app copies. Errors after application exit are written to
`~/Library/Logs/Tribe VPN/self-update.log` and shown in a system alert.

Signature verification uses the system `codesign` with the compiled Team ID and
bundle identifier, plus a separate `notarized` requirement. It does not invoke
Xcode's `stapler`. See Apple's [code-signing requirements documentation](https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/RequirementLang/RequirementLang.html)
and [notarization verification guidance](https://developer.apple.com/forums/topics/code-signing-topic?sortBy=boosts&sortOrder=ASC).

## Remaining release acceptance

These checks validate the installer and controller, not the startup health of a
newly signed VPN release. A successful `open -n` means LaunchServices accepted the
launch; it does not prove the new UI or VPN connection stayed healthy. Before
publishing a release, exercise a signed/notarized DMG update in an isolated macOS
instance and confirm version, settings and connection recovery after relaunch.

The changes are source-only until included in a new signed/notarized release.
An already running 5.1.78 still uses its old updater and needs a one-time manual
restart or installation to acquire the fixed updater.
