from conan import ConanFile
from conan.tools.cmake import cmake_layout, CMake, CMakeToolchain
from conan.tools.files import copy, load, patch, replace_in_file
from conan.errors import ConanInvalidConfiguration
from conan.tools.scm import Git

import os
import platform
import hashlib

class AwgAndroid(ConanFile):
    name = "awg-android"
    version = "3.1.20260814-tribe.1"
    _upstream_version = "3.1.20260814"
    settings = "os", "arch", "build_type", "compiler"

    # AVPN: tags in this repository have moved before.  Verify both the
    # wrapper commit and the Go module it embeds, instead of trusting a tag.
    _AWG_ANDROID_COMMIT = "5c16489e2cd9ed3a0a7a27c7445bba5238132f86"
    _AWG_GO_V3_REQ = (
        "github.com/amnezia-vpn/amneziawg-go/v3 v3.1.20260828"
    )
    _PROTECTED_START_SOURCE_SHA256 = (
        "30e870eb2f670e6faee25c253c03d103a697622f4944033ce044a6d593f2d7c6"
    )
    _PROTECTED_START_JNI_PATCH_SHA256 = (
        "e923de05300bd80a7c001fcdb5f6aee7e3542db4eb5761fa8b2a86cf6fb7d353"
    )

    exports_sources = "files/*", "patches/*"

    @staticmethod
    def _file_sha256(path):
        digest = hashlib.sha256()
        with open(path, "rb") as source:
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()

    @property
    def _upstream_root(self):
        # exports_sources are materialized in source_folder before source().
        # Keep the immutable upstream checkout separate so the clone target is
        # empty and the local overlay/patch inputs remain auditable.
        return os.path.join(self.source_folder, "upstream")

    def configure(self):
        self.settings.rm_safe("compiler.libcxx")
        self.settings.rm_safe("compiler.cppstd")

    def layout(self):
        cmake_layout(self)

    def build_requirements(self):
        self.tool_requires("cmake/[>=3.4.1 <4]")

    def validate(self):
        if self.settings.os != "Android":
            raise ConanInvalidConfiguration(f"{self.name} v{self.version} does not support {self.settings.os}")

    def source(self):
        git = Git(self)
        git.clone(
            url="https://github.com/amnezia-vpn/amneziawg-android.git",
            target="upstream",
            args=["--recurse-submodules", "--branch", f"v{self._upstream_version}"]
        )
        actual_commit = Git(self, folder=self._upstream_root).get_commit().strip()
        if actual_commit != self._AWG_ANDROID_COMMIT:
            raise ConanInvalidConfiguration(
                "awg-android: tag v{} resolved to {}, expected immutable {}"
                .format(self.version, actual_commit, self._AWG_ANDROID_COMMIT)
            )
        # AVPN: retain the immutable JNI wrapper and upgrade only its Go core.
        go_dir = os.path.join(self._upstream_root, "tunnel", "tools", "libwg-go")
        for filename in ("go.mod", "go.sum"):
            replace_in_file(self, os.path.join(go_dir, filename),
                "github.com/amnezia-vpn/amneziawg-go/v3 v3.1.20260814",
                self._AWG_GO_V3_REQ, strict=True)
        replace_in_file(self, os.path.join(go_dir, "go.sum"),
            "h1:l2AhBD+sFycU8Im81n/bZORMxW7fWtlZJEuJ4Hh0+z0=",
            "h1:D8d8gGvwXcTxUIsE4z6F6vjy4/VZddu95vMNtOygh1c=", strict=True)

    def generate(self):
        tc = CMakeToolchain(self)
        tc.variables["GRADLE_USER_HOME"] = os.path.join(self.build_folder, "gradle_user_home")
        tc.variables["CMAKE_LIBRARY_OUTPUT_DIRECTORY"] = os.path.join(self.build_folder, "out")
        # not to warn in case of strtok() usage
        tc.extra_cflags = ["-Wno-deprecated-declarations"]
        tc.generate()

    # AVPN: гвард версии amneziawg-go внутри обёртки. История: (1) S4 keepalive-паддинг чинится
    # только >=0.2.18 — CONNECT-INVARIANTS §14.1; (2) апстрим ПЕРЕДВИГАЛ тег обёртки v2.0.1
    # (2026-06-12: внутри 0.2.16 -> 0.2.18), а conan снапшотит источники — кеш тихо собирал
    # старый движок во все APK. Поэтому содержимому тега не доверяем и валидируем go.mod явно.
    def _check_awg_go_v3(self):
        d = os.path.join(self._upstream_root, "tunnel", "tools", "libwg-go")
        gomod = load(self, os.path.join(d, "go.mod"))
        if self._AWG_GO_V3_REQ not in gomod:
            raise ConanInvalidConfiguration(
                "awg-android: go.mod без amneziawg-go/v3 — conan затянул СТАРЫЙ снапшот тега "
                "(2.0-эра, тег обёртки передвинут?). Очисти кеш: "
                "conan remove 'awg-android/*' -c и пересобери; сверь go.mod тега на GitHub")
        gosum = load(self, os.path.join(d, "go.sum"))
        if self._AWG_GO_V3_REQ not in gosum:
            raise ConanInvalidConfiguration(
                "awg-android: go.sum без строк amneziawg-go/v3 — снапшот источников "
                "не соответствует go.mod, пересобери с чистым кешем")

    def _patch_sources(self):
        self._check_awg_go_v3()
        source_overlay = os.path.join(
            self.export_sources_folder, "files", "protected-start.go"
        )
        jni_patch = os.path.join(
            self.export_sources_folder, "patches", "0001-protected-start-jni.patch"
        )
        if self._file_sha256(source_overlay) != self._PROTECTED_START_SOURCE_SHA256:
            raise ConanInvalidConfiguration(
                "awg-android: protected-start.go digest mismatch"
            )
        if self._file_sha256(jni_patch) != self._PROTECTED_START_JNI_PATCH_SHA256:
            raise ConanInvalidConfiguration(
                "awg-android: protected-start JNI patch digest mismatch"
            )
        patch(self, base_path=self._upstream_root, patch_file=jni_patch)
        copy(
            self,
            "protected-start.go",
            src=os.path.dirname(source_overlay),
            dst=os.path.join(
                self._upstream_root, "tunnel", "tools", "libwg-go"
            ),
        )
        if platform.system() == 'Darwin':
            replace_in_file(self,
                os.path.join(self._upstream_root, "tunnel", "tools", "libwg-go", "Makefile"),
                'flock "$@.lock" -c \' \\\n',
                "",
            )
            replace_in_file(self,
                os.path.join(self._upstream_root, "tunnel", "tools", "libwg-go", "Makefile"),
                'mv "$@.tmp" "$@"\'',
                'mv "$@.tmp" "$@"',
            )
            replace_in_file(self,
                os.path.join(self._upstream_root, "tunnel", "tools", "libwg-go", "Makefile"),
                'touch "$@"\'',
                'touch "$@"',
            )
            replace_in_file(self,
                os.path.join(self._upstream_root, "tunnel", "tools", "libwg-go", "Makefile"),
                'sha256sum -c',
                'shasum -a 256 -c'
            )

    def build(self):
        self._patch_sources()
        cmake = CMake(self)
        cmake.configure(build_script_folder=os.path.join(self._upstream_root, "tunnel", "tools"))
        cmake.build(target=["libwg-go.so", "libwg.so", "libwg-quick.so"])

    def package(self):
        copy(self, "libwg-go.h", src=os.path.join(self.build_folder, "out"), dst=os.path.join(self.package_folder, "include"))
        copy(self, "libwg-go.so", src=os.path.join(self.build_folder, "out"), dst=os.path.join(self.package_folder, "lib"))
        copy(self, "libwg.so", src=os.path.join(self.build_folder, "out"), dst=os.path.join(self.package_folder, "bin"))
        copy(self, "libwg-quick.so", src=os.path.join(self.build_folder, "out"), dst=os.path.join(self.package_folder, "bin"))

    def package_info(self):
        self.cpp_info.set_property("cmake_target_name", "amnezia::awg-android")
        self.cpp_info.libs = [ "wg-go" ]
        self.cpp_info.set_property("cmake_extra_variables", {
            "AMNEZIA_ANDROID_LIBWG_PATH": os.path.join(self.package_folder, "bin", "libwg.so"),
            "AMNEZIA_ANDROID_LIBWG_QUICK_PATH": os.path.join(self.package_folder, "bin", "libwg-quick.so"),
            "AWG_ANDROID_ADAPTER_VERSION": self.version,
            "AWG_ANDROID_SOURCE_COMMIT": self._AWG_ANDROID_COMMIT,
            "AWG_ANDROID_UAPI_ABI": "awg-android-jni-uapi-v3.1-protected-start.1",
        })
