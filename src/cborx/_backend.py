# SPDX-License-Identifier: 0BSD
"""Optional compiled backend selection.

The accelerator is imported when available unless CBORX_DISABLE_FAST
is set. Tests and embedders can force the pure-Python path either with
the environment variable or by setting this module's fast attribute to
None.
"""

import os
from typing import Any

fast: Any = None
if not os.environ.get("CBORX_DISABLE_FAST"):
    try:
        from . import (  # type: ignore[attr-defined]
            _fast,  # ty: ignore[unresolved-import]
        )
    except ImportError:
        pass
    else:
        fast = _fast
