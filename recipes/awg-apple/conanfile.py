from conan import ConanFile
from conan.errors import ConanInvalidConfiguration
from conan.tools.layout import basic_layout
from conan.tools.files import (
    apply_conandata_patches,
    collect_libs,
    copy,
    export_conandata_patches,
    get,
    patch,
)
from conan.tools.apple import is_apple_os
from conan.tools.env import Environment
from conan.tools.gnu import AutotoolsToolchain, Autotools

import os

class AwgApple(ConanFile):
    name = "awg-apple"
    # AVPN: official v3.1.4 contains the AWG 3.1 parser fix.  The package
    # suffix is deliberate: it also carries the small, reviewable Tribe
    # split-DNS/warmup/rebind patch from the old fork.
    version = "3.1.4-tribe.5"
    settings = "os", "arch", "compiler"

    _upstream_version = "3.1.4"

    def export_sources(self):
        export_conandata_patches(self)
        # Tribe seamless roaming: pure policy/watchdog logic + its executable unit test travel
        # with the recipe (tribe.4). The .swift is copied next to WireGuardAdapter.swift in
        # build(); the test is a build gate (see build()).
        copy(self, "*.swift", src=os.path.join(self.recipe_folder, "tribe"),
             dst=os.path.join(self.export_sources_folder, "tribe"))
        copy(self, "*", src=os.path.join(self.recipe_folder, "tests"),
             dst=os.path.join(self.export_sources_folder, "tests"))
        # Both mobile adapters bind the same pinned Xray core. Reuse its reviewed error-
        # propagation delta, but copy it into this recipe's immutable exported sources.
        copy(
            self,
            "0004-xray-core-controller-errors.patch",
            src=os.path.join(self.recipe_folder, "..", "amnezia-libxray", "patches"),
            dst=os.path.join(self.export_sources_folder, "patches"),
        )

    @property
    def _goarch(self):
        arch_map = {
            "armv8": "arm64",
            "x86_64": "x86_64",
        }
        archs = str(self.settings.arch).split("|")
        return " ".join(arch_map.get(arch, arch) for arch in archs)

    def configure(self):
        self.settings.rm_safe("compiler.libcxx")
        self.settings.rm_safe("compiler.cppstd")

    def layout(self):
        basic_layout(self, build_folder=os.path.join(self.folders.source, "Sources/WireGuardKitGo"))

    def build_requirements(self):
        self.tool_requires("go/1.26.0")

    def validate(self):
        if not is_apple_os(self):
            raise ConanInvalidConfiguration(
                f"{self.name} v{self.version} does not support {self.settings.os}"
            )

    def source(self):
        # AVPN: source is immutable official upstream; local behavior is
        # applied from conandata.yml instead of relying on a mutable fork.
        get(self, f"https://github.com/amnezia-vpn/amneziawg-apple/archive/refs/tags/v{self._upstream_version}.zip",
            sha256="09d7b760d18232fdf121ed2286b2f171b501dc31137e5e7d557c1ee3a99ef772", strip_root=True
        )

    def generate(self):
        tc = AutotoolsToolchain(self)
        sdk = str(self.settings.get_safe("os.sdk", "macosx"))
        tc.make_args = [
            f"ARCHS={self._goarch}",
            f"PLATFORM_NAME={sdk}"
        ]
        deployment_target = self.settings.get_safe("os.version")
        if not deployment_target:
            raise ConanInvalidConfiguration(
                f"{self.name} requires an explicit Apple deployment target"
            )
        target_flags = {
            "iphoneos": ("miphoneos-version-min", "IPHONEOS_DEPLOYMENT_TARGET"),
            "macosx": ("mmacosx-version-min", "MACOSX_DEPLOYMENT_TARGET"),
        }
        if sdk not in target_flags:
            raise ConanInvalidConfiguration(
                f"{self.name} does not support Apple SDK {sdk!r}"
            )
        flag_name, environment_name = target_flags[sdk]
        tc.make_args.extend([
            f"DEPLOYMENT_TARGET_CLANG_FLAG_NAME={flag_name}",
            f"DEPLOYMENT_TARGET_CLANG_ENV_NAME={environment_name}",
            f"{environment_name}={deployment_target}",
        ])
        tc.generate()

    def build(self):
        apply_conandata_patches(self)
        # Tribe seamless roaming (tribe.4): the adapter patch 0003 references TribeRoaming.swift;
        # gate the package on its unit test first (plain swiftc, host toolchain), then ship the
        # file alongside the adapter so the NE target compiles it from AWG_APPLE_SOURCE_DIR.
        self.run("sh " + os.path.join(self.source_folder, "tests", "run_tribe_roaming_tests.sh"))
        copy(self, "TribeRoaming.swift", src=os.path.join(self.source_folder, "tribe"),
             dst=os.path.join(self.source_folder, "Sources", "WireGuardKit"))
        go_path = os.path.join(self.build_folder, ".tribe-go-path")
        go_cache = os.path.join(self.build_folder, ".tribe-go-cache")
        prep_env = Environment()
        prep_env.define("GOPATH", go_path)
        prep_env.define("GOCACHE", go_cache)
        prep_env.define("GOFLAGS", "")
        with prep_env.vars(self).apply():
            # AVPN: upstream wrapper is unchanged; ship the verified AWG fixes
            # for DisableCookies under load and UDP-window padding on every platform.
            self.run("go mod edit -require=github.com/amnezia-vpn/amneziawg-go/v3@v3.1.20260828")
            self.run("go mod tidy")
            self.run("go mod vendor")
        patch(
            self,
            base_path=os.path.join(self.build_folder, "vendor", "github.com", "xtls", "xray-core"),
            patch_file=os.path.join(self.source_folder, "patches", "0004-xray-core-controller-errors.patch"),
        )
        vendor_env = Environment()
        vendor_env.define("GOPATH", go_path)
        vendor_env.define("GOCACHE", go_cache)
        # Define rather than append: a builder-level GOFLAGS=-mod=mod must never bypass the
        # reviewed vendored core patch in either tests or the final c-archive.
        vendor_env.define("GOFLAGS", "-mod=vendor -trimpath -buildvcs=false")
        with vendor_env.vars(self).apply():
            self.run(
                "go test -count=1 -run '^TestTribeExternalControllerErrorsArePropagated$' "
                "github.com/xtls/xray-core/transport/internet"
            )
            # Exercise the actual singleton callback slot and its RWMutex drain receipt before
            # producing any Apple archive.
            self.run(
                "go test -tags tribe_callback_test -count=1 "
                "-run '^TestTribeXraySockCallbackSlot' "
                "api-xray.go api-xray_testhelper.go api-xray_callback_test.go"
            )
            autotools = Autotools(self)
            autotools.make()
            autotools.make("version-header")

    def package(self):
        copy(self, "wireguard.h", src=self.build_folder, dst=os.path.join(self.package_folder, "include"))
        # WireGuardKitC.h includes key.h and x25519.h by name; package the
        # complete public C header set so Swift bridging headers are hermetic.
        copy(self, "*.h", src=os.path.join(self.source_folder, "Sources", "WireGuardKitC"),
             dst=os.path.join(self.package_folder, "include"))
        copy(self, "*.h", src=os.path.join(self.build_folder, "out"), dst=os.path.join(self.package_folder, "include"))
        copy(self, "*.a", src=os.path.join(self.build_folder, "out"), dst=os.path.join(self.package_folder, "lib"))
        # AVPN: the app/NE compile Swift and x25519 directly.  Ship the exact
        # patched sources alongside the archive so CMake cannot silently use
        # the stale git submodule with a different parser/ABI.  WireGuardKitGo is
        # also this recipe's in-source build directory; never package its transient
        # `.tmp` Go toolchain/module cache or generated `out` tree as source input.
        copy(self, "*", src=os.path.join(self.source_folder, "Sources"),
             dst=os.path.join(self.package_folder, "src", "Sources"),
             excludes=("WireGuardKitGo/.tmp/*", "WireGuardKitGo/out/*",
                       "WireGuardKitGo/vendor/*"))

    def package_info(self):
        self.cpp_info.set_property("cmake_target_name", "amnezia::awg-apple")
        self.cpp_info.libs = collect_libs(self)
        self.cpp_info.set_property("cmake_extra_variables", {
            "AWG_APPLE_SOURCE_DIR": os.path.join(self.package_folder, "src", "Sources"),
            "AWG_APPLE_ADAPTER_VERSION": self.version,
            "AWG_APPLE_UPSTREAM_VERSION": self._upstream_version,
            "AWG_APPLE_SOURCE_COMMIT": "811f5c8213e6b257e9520fff713ec4d22086e9ac",
            "AWG_APPLE_AWG_CORE_VERSION": "3.1.20260828",
            "AWG_APPLE_XRAY_ADAPTER_VERSION": "1.0.3",
            "AWG_APPLE_XRAY_SOURCE_COMMIT": "e8cc06d7427251fa549093e7cc32c28b0f5fbafa",
            "AWG_APPLE_XRAY_CORE_VERSION": "1.260728.0",
            "AWG_APPLE_XRAY_SOCKET_ABI": "awg-apple-libxray-c-v2-protect-result",
            "AWG_APPLE_ENGINE_CAPABILITIES": "awg.random_trailers;awg.disable_cookies",
            # Tribe seamless roaming (patch 0003 + TribeRoaming.swift): the NE CMake target
            # compiles TribeRoaming.swift only when the package declares it.
            "AWG_APPLE_TRIBE_ROAMING": "1",
        })
