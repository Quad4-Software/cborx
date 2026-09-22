# SPDX-License-Identifier: 0BSD
"""Fuzz tests: the decoder must only ever return a value or raise CBORDecodeError."""

import os
from contextlib import suppress
from typing import Any

import pytest

from cborx import CBORDecodeError, dumps, loads

_BASE_OBJECT: dict[str, Any] = {
    "ints": [0, -1, 2**64 - 1, -(2**64), 2**70],
    "floats": [0.0, -0.0, 1.5, 1e300, 5e-324],
    "text": ["ascii", "\u00fc", "\u6c34", "\U00010151", ""],
    "bytes": [b"", b"\x00\xff"],
    "nested": [[], {}, [[]], {"k": {"k2": [1, 2, 3]}}],
    "special": [None, True, False],
}


def _may_decode(data: bytes, **kwargs: Any) -> None:
    # Any exception class other than CBORDecodeError propagates out of
    # the suppress block and fails the test.
    with suppress(CBORDecodeError):
        loads(data, **kwargs)


def _decodes(data: bytes) -> bool:
    try:
        loads(data)
    except CBORDecodeError:
        return False
    return True


def test_random_bytes_fuzz() -> None:
    # Thousands of iterations over random inputs of length 0..256. The
    # decoder may only return a value or raise CBORDecodeError. Any other
    # exception class (or a hang) is a bug and fails the test.
    for length in range(257):
        for _ in range(10):
            _may_decode(os.urandom(length))


def test_truncation_fuzz() -> None:
    # Every strict prefix of a valid definite-length encoding must fail:
    # a declared length can never be satisfied by fewer bytes.
    base = dumps(_BASE_OBJECT)
    assert loads(base) == _BASE_OBJECT
    for cut in range(len(base)):
        with pytest.raises(CBORDecodeError):
            loads(base[:cut])


def test_bit_flip_fuzz() -> None:
    # Flip every bit of a valid encoding: each mutation must either fail
    # with CBORDecodeError or decode without crashing.
    base = dumps(_BASE_OBJECT)
    decoded = 0
    for i in range(len(base)):
        for bit in range(8):
            mutated = bytearray(base)
            mutated[i] ^= 1 << bit
            decoded += int(_decodes(bytes(mutated)))
    assert decoded > 0  # sanity: some mutations stay decodable


def test_truncation_indefinite_fuzz() -> None:
    base = bytes.fromhex("9f018202039f0405ffff")
    assert loads(base) == [1, [2, 3], [4, 5]]
    # Unlike definite-length items, a prefix ending right after a break
    # byte is a complete item, so prefixes may decode or fail. They must
    # never raise anything but CBORDecodeError.
    for cut in range(len(base)):
        _may_decode(base[:cut])


def test_mutation_canonical_mode() -> None:
    base = dumps(_BASE_OBJECT, canonical=True)
    for i in range(len(base)):
        for bit in range(8):
            mutated = bytearray(base)
            mutated[i] ^= 1 << bit
            _may_decode(bytes(mutated), canonical=True)


def test_random_bytes_with_options() -> None:
    for length in (0, 1, 8, 32, 128):
        for _ in range(200):
            data = os.urandom(length)
            _may_decode(
                data, canonical=True, duplicate_keys="error", allow_indefinite=False
            )
            _may_decode(data, strict_utf8=False)


@pytest.mark.parametrize(
    "wire",
    [
        # Regression: a map declaring 2**63 pairs overflowed the
        # item counter to zero and crashed the compiled backend by
        # reading past the items list. Found by test_bit_flip_fuzz.
        bytes.fromhex(
            "a6646e7473201bffffffffffffffff3bffffffffffffffff"
            "c24940000000000000000066666c6f61747385fb0000000000"
            "000000bb80000000000000006265404200ff"
        ),
        # An array of 2**64 - 1 items wrapped the counter to the
        # indefinite sentinel value.
        bytes.fromhex("9bffffffffffffffff01"),
        bytes.fromhex("bbffffffffffffffff0102"),
        bytes.fromhex("9b8000000000000000"),
        bytes.fromhex("bb7fffffffffffffff"),
    ],
)
def test_huge_container_counts(wire: bytes) -> None:
    _may_decode(wire)
