# SPDX-License-Identifier: 0BSD
"""Build script for the optional compiled accelerator.

The _fast extension is built when a C compiler is available. If the
compiler or Cython is missing the package still installs, with the
pure-Python codec as the only backend.
"""

import sys
from pathlib import Path

from setuptools import Extension, setup
from setuptools._distutils.errors import (
    CCompilerError,
    DistutilsExecError,
    DistutilsPlatformError,
)
from setuptools.command.build_ext import build_ext


class OptionalBuildExt(build_ext):
    """Build extensions but downgrade failures to a pure-Python install."""

    def run(self):
        try:
            super().run()
        except (DistutilsPlatformError, FileNotFoundError) as e:
            print(f"cborx: skipping extension build: {e}", file=sys.stderr)
            self.extensions = []

    def build_extension(self, ext):
        try:
            super().build_extension(ext)
        except (
            CCompilerError,
            DistutilsExecError,
            DistutilsPlatformError,
            ValueError,
            OSError,
        ) as e:
            print(
                f"cborx: _fast extension failed, using pure Python: {e}",
                file=sys.stderr,
            )


def _extensions():
    pyx = "src/cborx/_fast.pyx"
    try:
        from Cython.Build import cythonize
    except ImportError:
        c_source = str(Path(pyx).with_suffix(".c"))
        if Path(c_source).exists():
            return [Extension("cborx._fast", [c_source])]
        return []
    return cythonize(
        [Extension("cborx._fast", [pyx])],
        compiler_directives={"language_level": "3"},
    )


setup(
    ext_modules=_extensions(),
    cmdclass={"build_ext": OptionalBuildExt},
)
