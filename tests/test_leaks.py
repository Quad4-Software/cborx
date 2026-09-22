# SPDX-License-Identifier: 0BSD
"""Allocation-leak smoke tests.

These catch reference-counting bugs in the compiled backend, which
leak rather than crash. Each loop is measured after a warmup so freelists,
interned strings and type caches are already warm: a correct codec
returns memory to a steady state.
"""

import gc
import sys
from contextlib import suppress
from typing import Any

import pytest

from cborx import CBORDecodeError, dumps, loads

_IS_CPYTHON = sys.implementation.name == "cpython"

_PAYLOAD = {
    "id": 42,
    "name": "device-alpha",
    "tags": ["sensor", "outdoor", "v2"],
    "meta": {"fw": "1.4.2", "uptime": 86400, "floats": [1.5, -0.0, 3.25]},
    "blob": bytes(range(64)),
}

# Inputs that exercise error and unwind paths, where reference
# counting mistakes hide.
_MALFORMED = [
    b"\xa1\x61",
    b"\x9b\xff\xff\xff\xff\xff\xff\xff\xff\x01",
    bytes.fromhex(
        "a6646e7473201bffffffffffffffff3bffffffffffffffff"
        "c24940000000000000000066666c6f61747385fb0000000000"
        "000000bb80000000000000006265404200ff"
    ),
]

_WARMUP = 500
_ITERATIONS = 5000
# A small positive delta is allowed for one-off allocations such as
# lazily created exception internals. Unbounded growth is a leak.
_SLACK = 64


def _blocks() -> int:
    gc.collect()
    return sys.getallocatedblocks()


def _assert_stable(fn: Any) -> None:
    for _ in range(_WARMUP):
        fn()
    before = _blocks()
    for _ in range(_ITERATIONS):
        fn()
    after = _blocks()
    assert after - before < _SLACK, f"allocated blocks grew {before} -> {after}"


@pytest.mark.skipif(not _IS_CPYTHON, reason="getallocatedblocks is CPython-only")
def test_decode_no_leak() -> None:
    wire = dumps(_PAYLOAD)
    _assert_stable(lambda: loads(wire))


@pytest.mark.skipif(not _IS_CPYTHON, reason="getallocatedblocks is CPython-only")
def test_encode_no_leak() -> None:
    _assert_stable(lambda: dumps(_PAYLOAD))


@pytest.mark.skipif(not _IS_CPYTHON, reason="getallocatedblocks is CPython-only")
def test_decode_error_no_leak() -> None:
    def attempt(wire: bytes) -> None:
        with suppress(CBORDecodeError):
            loads(wire)

    for wire in _MALFORMED:
        _assert_stable(lambda w=wire: attempt(w))
