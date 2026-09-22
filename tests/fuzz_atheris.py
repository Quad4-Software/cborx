# SPDX-License-Identifier: 0BSD
"""Coverage-guided differential fuzz harness for Atheris.

The fuzzer mutates CBOR input and decodes it with both backends. A
crash, a non-CBORDecodeError exception, or any divergence between the
compiled and pure decoders is a bug: libFuzzer writes the input to a
crash artifact in the working directory.

Run locally:

    python setup.py build_ext --inplace
    uv run --with atheris python tests/fuzz_atheris.py corpus -max_total_time=60
"""

import sys
from pathlib import Path
from typing import Any

import atheris  # ty: ignore[unresolved-import]

sys.path.insert(0, str(Path(__file__).parent))  # for util.py
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

with atheris.instrument_imports():
    import cborx
    from cborx import CBORDecodeError, _backend
    from util import (  # type: ignore[import-not-found]  # ty: ignore[unresolved-import]
        same,
    )

_OPTIONS = [
    {},
    {"canonical": True},
    {"allow_indefinite": False},
    {"duplicate_keys": "error"},
    {"max_depth": 8},
]


def _decode_both(data: bytes, opts: dict[str, Any]) -> None:
    """Decode with each backend; any divergence is a bug."""
    fast = _backend.fast
    results: list[tuple[Any, CBORDecodeError | None]] = []
    for backend in (fast, None):
        _backend.fast = backend
        try:
            results.append((cborx.loads(data, **opts), None))
        except CBORDecodeError as e:
            results.append((None, e))
        finally:
            _backend.fast = fast
    (fast_val, fast_err), (pure_val, pure_err) = results
    if (fast_err is None) != (pure_err is None):
        raise RuntimeError(
            f"backend divergence: fast_err={fast_err!r} pure_err={pure_err!r} "
            f"input={data.hex()}"
        )
    if fast_err is not None and (
        type(fast_err) is not type(pure_err) or str(fast_err) != str(pure_err)
    ):
        raise RuntimeError(
            f"error divergence: fast={fast_err!r} pure={pure_err!r} input={data.hex()}"
        )
    if fast_err is None and not same(fast_val, pure_val):
        raise RuntimeError(
            f"value divergence: fast={fast_val!r} pure={pure_val!r} input={data.hex()}"
        )


def _target(data: bytes) -> None:
    fdp = atheris.FuzzedDataProvider(data)
    opts = _OPTIONS[fdp.ConsumeIntInRange(0, len(_OPTIONS) - 1)]
    payload = fdp.ConsumeBytes(fdp.remaining_bytes())
    _decode_both(payload, opts)


if __name__ == "__main__":
    atheris.Setup(sys.argv, _target)
    atheris.Fuzz()
