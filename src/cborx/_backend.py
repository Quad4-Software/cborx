# SPDX-License-Identifier: 0BSD
"""Optional compiled backend selection.

The accelerator is imported when available unless CBORX_DISABLE_FAST
is set. Tests and embedders can force the pure-Python path either with
the environment variable or by setting this module's fast attribute to
None.

The extension is CPython-only. On PyPy the cpyext emulation layer makes
native calls slower than the JIT-compiled pure path, so the fallback is
the right backend there.
"""

import os
import sys
from typing import Any

fast: Any = None
if sys.implementation.name == "cpython" and not os.environ.get("CBORX_DISABLE_FAST"):
    try:
        from . import (  # type: ignore[attr-defined]
            _fast,  # ty: ignore[unresolved-import]
        )
    except ImportError:
        pass
    else:
        fast = _fast
