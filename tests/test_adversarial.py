# SPDX-License-Identifier: 0BSD
"""Handcrafted hostile inputs: the decoder is an attack surface."""

import math

import pytest

from cborx import CBORDecodeError, CBORSimpleValue, dumps, loads, undefined
from tests.util import depth


def _evil(hexs: str) -> bytes:
    return bytes.fromhex(hexs)


EVIL: list[bytes] = [
    b"",
    b"\xff",  # break with nothing open
    _evil("9f"),  # indefinite array, no break, EOF
    _evil("bf"),  # indefinite map, no break, EOF
    _evil("5f"),  # indefinite bytes, no break, EOF
    _evil("7f"),  # indefinite text, no break, EOF
    _evil("9f01"),  # indefinite array truncated mid-items
    _evil("bf0102"),  # indefinite map truncated (even items, no break)
    _evil("82ff"),  # break inside definite array (as first item)
    _evil("8201ff"),  # break inside definite array (as second item)
    _evil("a101ff"),  # break inside definite map
    _evil("1c"),  # reserved additional information 28
    _evil("1d"),  # reserved 29
    _evil("1e"),  # reserved 30
    _evil("3c"),
    _evil("5c"),
    _evil("7c"),
    _evil("9c"),
    _evil("bc"),
    _evil("dc"),
    _evil("fc"),
    _evil("fd"),
    _evil("fe"),
    _evil("1f"),  # "indefinite" integer
    _evil("3f"),  # "indefinite" negint
    _evil("df"),  # "indefinite" tag
    _evil("18"),  # truncated argument bytes
    _evil("1900"),
    _evil("1a000000"),
    _evil("1b00000000000000"),
    _evil("5bffffffffffffffff"),  # byte string claiming 2^64-1 on empty input
    _evil("5bffffffffffffffff" + "00" * 8),  # still far short of the claim
    _evil("7bffffffffffffffff"),  # text string claiming 2^64-1
    _evil("9bffffffffffffffff"),  # array claiming 2^64-1 items
    _evil("bbffffffffffffffff"),  # map claiming 2^64-1 pairs
    _evil("4401"),  # declared byte string length exceeds remaining input
    _evil("63ff"),  # declared text length exceeds remaining input
    _evil("5f41"),  # indefinite byte string truncated inside a chunk
    _evil("5f00ff"),  # integer chunk inside indefinite byte string
    _evil("5f5f40ffff"),  # nested indefinite chunk inside indefinite bytes
    _evil("7f40ff"),  # byte string chunk inside indefinite text string
    _evil("bf010203ff"),  # odd item count in indefinite map
    _evil("61ff"),  # invalid UTF-8 in text string
    _evil("62c080"),  # overlong (invalid) UTF-8
    _evil("c1" + "60"),  # tag 1 wrapping a non-number
    _evil("c000"),  # tag 0 wrapping a non-string
    _evil("c06178"),  # tag 0 wrapping unparseable text
    _evil("c200"),  # tag 2 wrapping a non-bytes value
    _evil("c300"),  # tag 3 wrapping a non-bytes value
    _evil("d82000"),  # tag 32 wrapping a non-string
    _evil("d903ec60"),  # tag 1004 wrapping a non-integer
    _evil("d903ec1b00000002540be400"),  # tag 1004 day count out of range
    _evil("a1810102"),  # unhashable (array) map key
    _evil("f8"),  # truncated simple value
    _evil("f9ff"),  # truncated float16
    _evil("faffffff"),  # truncated float32
    _evil("fbffffffffffffff"),  # truncated float64
]


@pytest.mark.parametrize("data", EVIL)
def test_evil_inputs_raise_decode_error(data: bytes) -> None:
    with pytest.raises(CBORDecodeError):
        loads(data)


def test_nesting_bomb_bounded_by_max_depth() -> None:
    bomb = b"\x81" * 10000 + b"\x00"
    with pytest.raises(CBORDecodeError):
        loads(bomb)


def test_deep_nesting_decodes_iteratively() -> None:
    # Well past the Python recursion limit, must not crash the interpreter.
    levels = 5000
    data = b"\x81" * levels + b"\x00"
    result = loads(data, max_depth=levels + 10)
    assert depth(result) == levels + 1


def test_tag_nesting_bomb() -> None:
    bomb = b"\xc2" * 10000 + b"\x40"
    with pytest.raises(CBORDecodeError):
        loads(bomb)


def test_indefinite_nesting_bomb() -> None:
    with pytest.raises(CBORDecodeError):
        loads(b"\x9f" * 500)


def test_map_nesting_bomb() -> None:
    # Each map has one pair and the next map is the value.
    bomb = (b"\xa1\x00") * 500 + b"\x00"
    with pytest.raises(CBORDecodeError):
        loads(bomb)


def test_mixed_nesting_bomb() -> None:
    bomb = (b"\x81" + b"\xa1\x00") * 5000 + b"\x00"
    with pytest.raises(CBORDecodeError):
        loads(bomb)


def test_map_claim_huge_count_on_tiny_input() -> None:
    # Claims 2^64-1 pairs but the input ends immediately.
    with pytest.raises(CBORDecodeError):
        loads(_evil("bbffffffffffffffff") + b"\x01\x02")


def test_huge_bignum_bounded_by_input() -> None:
    # Tag 2 with a declared byte length exceeding the input fails fast.
    with pytest.raises(CBORDecodeError):
        loads(_evil("c25bffffffffffffffff"))
    # A legitimate large bignum still works.
    big = 2**8000 + 7
    assert loads(dumps(big)) == big
    assert loads(dumps(-big)) == -big


@pytest.mark.parametrize(
    "hexs",
    [
        "1800",  # 0 encoded with a one-byte argument
        "1817",  # 23 encoded with a one-byte argument
        "190018",  # 24 encoded with a two-byte argument
        "1a0000ffff",  # 65535 encoded with a four-byte argument
        "1b00000000ffffffff",  # 2^32-1 encoded with an eight-byte argument
        "3817",  # -24 encoded non-minimally (arg 23 fits inline)
        "5801ff",  # byte string length 1 encoded non-minimally
    ],
)
def test_nonminimal_integers_lax(hexs: str) -> None:
    loads(bytes.fromhex(hexs))  # must not raise in lax mode


@pytest.mark.parametrize(
    "hexs",
    [
        "1800",
        "1817",
        "190018",
        "1a0000ffff",
        "1b00000000ffffffff",
        "3817",
        "5801ff",
    ],
)
def test_nonminimal_integers_rejected_in_canonical_mode(hexs: str) -> None:
    with pytest.raises(CBORDecodeError):
        loads(bytes.fromhex(hexs), canonical=True)


def test_nonminimal_simple_value() -> None:
    assert loads(b"\xf8\x00") is not None  # lax: extended encoding of simple(0)
    with pytest.raises(CBORDecodeError):
        loads(b"\xf8\x00", canonical=True)


def test_nonshortest_float_rejected_in_canonical_mode() -> None:
    # 1.5 as double is valid but not preferred.
    assert loads(bytes.fromhex("fb3ff8000000000000")) == 1.5
    with pytest.raises(CBORDecodeError):
        loads(bytes.fromhex("fb3ff8000000000000"), canonical=True)
    # 1.5 as single is also not preferred (half suffices).
    with pytest.raises(CBORDecodeError):
        loads(bytes.fromhex("fa3fc00000"), canonical=True)


def test_unsorted_map_keys_rejected_in_canonical_mode() -> None:
    # {2: "b", 1: "a"}: single-byte keys out of lexicographic order.
    bad = _evil("a2026162016161")
    assert loads(bad) == {2: "b", 1: "a"}
    with pytest.raises(CBORDecodeError):
        loads(bad, canonical=True)
    # "a" (2 bytes) before 1 (1 byte): length-first ordering violated.
    bad2 = _evil("a26161020102")
    with pytest.raises(CBORDecodeError):
        loads(bad2, canonical=True)


def test_indefinite_rejected_in_canonical_mode() -> None:
    with pytest.raises(CBORDecodeError):
        loads(b"\x9f\x01\xff", canonical=True)


def test_indefinite_rejected_when_disallowed() -> None:
    assert loads(b"\x9f\x01\xff") == [1]
    with pytest.raises(CBORDecodeError):
        loads(b"\x9f\x01\xff", allow_indefinite=False)
    with pytest.raises(CBORDecodeError):
        loads(b"\x5f\x40\xff", allow_indefinite=False)


def test_duplicate_keys() -> None:
    data = _evil("a201020103")
    assert loads(data) == {1: 3}
    assert loads(data, duplicate_keys="last") == {1: 3}
    assert loads(data, duplicate_keys="first") == {1: 2}
    with pytest.raises(CBORDecodeError):
        loads(data, duplicate_keys="error")


def test_duplicate_keys_bool_int_collision() -> None:
    # true and 1 are the same dict key in Python.
    with pytest.raises(CBORDecodeError):
        loads(_evil("a2f5010102"), duplicate_keys="error")


def test_invalid_utf8() -> None:
    with pytest.raises(CBORDecodeError):
        loads(b"\x61\xff")
    assert loads(b"\x61\xff", strict_utf8=False) == "\ufffd"


def test_trailing_garbage() -> None:
    with pytest.raises(CBORDecodeError):
        loads(b"\x00\x00")
    assert loads(b"\x00\x00", allow_trailing=True) == 0


def test_break_without_indefinite() -> None:
    with pytest.raises(CBORDecodeError):
        loads(b"\xff")
    with pytest.raises(CBORDecodeError):
        loads(b"\x01\xff")
    assert loads(b"\x01\xff", allow_trailing=True) == 1


def test_extreme_integers() -> None:
    values = [
        2**64 - 1,
        -(2**64),
        -(2**64) - 1,
        2**64,
        2**128,
        -(2**128),
        18446744073709551615,
        -18446744073709551616,
    ]
    for value in values:
        assert loads(dumps(value)) == value


def test_float16_subnormal_and_inf_nan() -> None:
    assert loads(bytes.fromhex("f90001")) == 5.960464477539063e-8
    assert loads(bytes.fromhex("f97c00")) == math.inf
    assert loads(bytes.fromhex("f9fc00")) == -math.inf
    result = loads(bytes.fromhex("f97e00"))
    assert isinstance(result, float)
    assert math.isnan(result)
    # Quiet NaN round-trips through the canonical shortest form.
    again = loads(dumps(result, canonical=True))
    assert isinstance(again, float)
    assert math.isnan(again)


def test_simple_value_boundary() -> None:
    assert loads(b"\xe0") == CBORSimpleValue(0)
    assert loads(b"\xf7") is undefined


def test_extended_simple_named_values() -> None:
    # Lax mode: named simple values in extended form decode to the names.
    assert loads(b"\xf8\x14") is False
    assert loads(b"\xf8\x15") is True
    assert loads(b"\xf8\x16") is None
    assert loads(b"\xf8\x17") is undefined
    assert loads(b"\xf8\x20") == CBORSimpleValue(32)
