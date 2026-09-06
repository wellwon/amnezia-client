from conan import ConanFile
from conan.errors import ConanInvalidConfiguration
from conan.tools.layout import basic_layout
from conan.tools.files import get, chdir, save
from conan.tools.apple import XCRun
from conan.tools.gnu import Autotools, AutotoolsToolchain
from conan.tools.apple import is_apple_os
from conan.tools.apple.apple import _to_apple_arch
from conan.tools.env import Environment

import os
import shlex


class AwgGo(ConanFile):
    name = "awg-go"
    version = "3.1.20260828"
    package_type = "application"
    settings = "os", "arch"

    _binary_name = "amneziawg-go"

    _arch_map = {
        "x86": "386",
        "x86_64": "amd64",
        "armv8": "arm64"
    }

    @property
    def _goos(self):
        return {
            "Linux": "linux",
            "Macos": "darwin",
            "Windows": "windows"
        }.get(str(self.settings.os))

    @property
    def _archs(self):
        return str(self.settings.arch).split("|")
    
    @property
    def _is_multiarch(self):
        return len(self._archs) > 1

    def layout(self):
        basic_layout(self, build_folder=".")

    def build_requirements(self):
        self.tool_requires("go/1.26.0")

    def validate(self):
        if not self._goos or not all(arch in self._arch_map for arch in self._archs):
            raise ConanInvalidConfiguration(
                f"{self.name} v{self.version} does not support {self.settings.os} {self.settings.arch}"
            )
        
        if self._is_multiarch and not is_apple_os(self):
            raise ConanInvalidConfiguration(
                f"{self.name} v{self.version} does not support multiarch builds"
            )

    def source(self):
        get(self, f"https://github.com/amnezia-vpn/amneziawg-go/archive/refs/tags/v{self.version}.zip",
            sha256="7adedd3ea97cf63f365f3610667817da4e8979fea996dc131d0b5693b40954e0", strip_root=True
        )

    def generate(self):
        tc = AutotoolsToolchain(self)
        tc.apple_arch_flag = None
        env = tc.environment()
        env.define("GOPATH", os.path.join(self.build_folder, "gopath"))
        env.define("GOMODCACHE", os.path.join(self.build_folder, "gopath", "pkg", "mod"))
        env.define("GOCACHE", os.path.join(self.build_folder, "gocache"))
        env.define("GOTELEMETRY", "off")
        # Reproducible release binaries must not retain Conan's per-user Go
        # toolchain/module cache paths or a volatile linker build id.
        env.define("GOFLAGS", "-trimpath -buildvcs=false -ldflags=-buildid=")
        env.define("GOOS", self._goos)
        self._ldflags = tc.ldflags
        self._cflags = tc.cflags
        tc.generate(env)

    def build(self):
        # GitHub release archives intentionally contain no .git directory.  Upstream's
        # Makefile therefore cannot derive the release tag with `git describe` and silently
        # keeps the stale version.go shipped in the archive (v3.1.20260814 currently reports
        # 0.0.20250522).  Runtime identity must describe the bytes we actually package, so make
        # the immutable Conan version authoritative before invoking the upstream build.
        save(
            self,
            os.path.join(self.source_folder, "version.go"),
            f'package main\n\nconst Version = "{self.version}"\n',
        )
        with chdir(self, self.source_folder):
            for arch in self._archs:
                goarch = self._arch_map.get(arch)

                ldflags = list(self._ldflags)
                cflags = list(self._cflags)
                if is_apple_os(self):
                    ldflags.append(f"-arch {_to_apple_arch(arch)}")
                    cflags.append(f"-arch {_to_apple_arch(arch)}")
                    for build_root in (self.source_folder, self.build_folder):
                        cflags.extend([
                            f"-ffile-prefix-map={build_root}=.",
                            f"-fdebug-prefix-map={build_root}=.",
                            f"-fmacro-prefix-map={build_root}=.",
                        ])

                env = Environment()
                env.define("GOARCH", goarch)
                env.define("CGO_LDFLAGS", " ".join(ldflags))
                env.define("CGO_CFLAGS", " ".join(cflags))
                with env.vars(self).apply():
                    at = Autotools(self)
                    at.make()
                    if self._is_multiarch:
                        os.rename(
                            os.path.join(self.source_folder, self._binary_name),
                            os.path.join(self.source_folder, f"{self._binary_name}-{arch}")
                        )

            if is_apple_os(self) and self._is_multiarch:
                lipo = XCRun(self).find("lipo")
                output = os.path.join(self.build_folder, self._binary_name)
                binaries = [os.path.join(self.build_folder, f"{self._binary_name}-{arch}") for arch in self._archs]
                self.run("{} -create -output {} {}".format(
                    shlex.quote(lipo),
                    shlex.quote(output),
                    shlex.join(binaries)
                ))

    def package(self):
        with chdir(self, self.source_folder):
            at = Autotools(self)
            at.make("install", args=[
                f"BINDIR={self.package_folder}",
            ])

    def package_info(self):
        self.cpp_info.exe = True
        self.cpp_info.location = os.path.join(self.package_folder, self._binary_name)
        self.cpp_info.set_property("cmake_target_name", "amnezia::awg-go")
        self.cpp_info.set_property("cmake_extra_variables", {
            "AWG_GO_ENGINE_VERSION": self.version,
            "AWG_GO_SOURCE_COMMIT": "1b86b2ae0e493e7ea93f8c1a0f0cb6735b1551f1",
            "AWG_GO_UAPI_ABI": "awg-uapi-v3.1",
        })
