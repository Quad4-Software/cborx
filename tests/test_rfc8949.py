# SPDX-License-Identifier: 0BSD
"""RFC 8949 Appendix A test vectors."""

import math
from datetime import datetime, timezone
from typing import Any

import pytest

from cborx import CBORSimpleValue, CBORTag, dumps, loads, undefined

_UTC = timezone.utc
_RANGE_1_25 = "".join(f"{i:02x}" for i in range(1, 24)) + "18181819"

# Every decode vector from RFC 8949 Appendix A: hex -> expected value.
DECODE_VECTORS: list[tuple[str, Any]] = [
    ("00", 0),
    ("01", 1),
    ("0a", 10),
    ("17", 23),
    ("1818", 24),
    ("1819", 25),
    ("1864", 100),
    ("1903e8", 1000),
    ("1a000f4240", 1000000),
    ("1b000000e8d4a51000", 1000000000000),
    ("1bffffffffffffffff", 18446744073709551615),
    ("c249010000000000000000", 18446744073709551616),
    ("3bffffffffffffffff", -18446744073709551616),
    ("c349010000000000000000", -18446744073709551617),
    ("20", -1),
    ("29", -10),
    ("3863", -100),
    ("3903e7", -1000),
    ("f90000", 0.0),
    ("f98000", -0.0),
    ("f93c00", 1.0),
    ("fb3ff199999999999a", 1.1),
    ("f93e00", 1.5),
    ("f97bff", 65504.0),
    ("fa47c35000", 100000.0),
    ("fa7f7fffff", 3.4028234663852886e38),
    ("fb7e37e43c8800759c", 1.0e300),
    ("f90001", 5.960464477539063e-8),
    ("f90400", 0.00006103515625),
    ("f9c400", -4.0),
    ("fbc010666666666666", -4.1),
    ("f97c00", math.inf),
    ("f97e00", math.nan),
    ("f9fc00", -math.inf),
    ("fa7f800000", math.inf),
    ("fa7fc00000", math.nan),
    ("faff800000", -math.inf),
    ("fb7ff0000000000000", math.inf),
    ("fb7ff8000000000000", math.nan),
    ("fbfff0000000000000", -math.inf),
    ("f4", False),
    ("f5", True),
    ("f6", None),
    ("f7", undefined),
    ("f0", CBORSimpleValue(16)),
    ("f8ff", CBORSimpleValue(255)),
    (
        "c074323031332d30332d32315432303a30343a30305a",
        datetime(2013, 3, 21, 20, 4, 0, tzinfo=_UTC),
    ),
    ("c11a514b67b0", datetime(2013, 3, 21, 20, 4, 0, tzinfo=_UTC)),
    ("c1fb41d452d9ec200000", datetime(2013, 3, 21, 20, 4, 0, 500000, tzinfo=_UTC)),
    ("d74401020304", CBORTag(23, b"\x01\x02\x03\x04")),
    ("d818456449455446", CBORTag(24, b"dIETF")),
    ("d82076687474703a2f2f7777772e6578616d706c652e636f6d", "http://www.example.com"),
    ("40", b""),
    ("4401020304", b"\x01\x02\x03\x04"),
    ("60", ""),
    ("6161", "a"),
    ("6449455446", "IETF"),
    ("62225c", '"\\'),
    ("62c3bc", "\u00fc"),
    ("63e6b0b4", "\u6c34"),
    ("64f0908591", "\U00010151"),
    ("80", []),
    ("83010203", [1, 2, 3]),
    ("8301820203820405", [1, [2, 3], [4, 5]]),
    ("9819" + _RANGE_1_25, list(range(1, 26))),
    ("a0", {}),
    ("a201020304", {1: 2, 3: 4}),
    ("a2018202030405", {1: [2, 3], 4: 5}),
    ("a26161016162820203", {"a": 1, "b": [2, 3]}),
    ("826161a161626163", ["a", {"b": "c"}]),
    (
        "a56161614161626142616361436164614461656145",
        {"a": "A", "b": "B", "c": "C", "d": "D", "e": "E"},
    ),
    ("5f42010243030405ff", b"\x01\x02\x03\x04\x05"),
    ("7f657374726561646d696e67ff", "streaming"),
    ("9fff", []),
    ("9f018202039f0405ffff", [1, [2, 3], [4, 5]]),
    ("9f01820203820405ff", [1, [2, 3], [4, 5]]),
    ("83018202039f0405ff", [1, [2, 3], [4, 5]]),
    ("83019f0203ff820405", [1, [2, 3], [4, 5]]),
    ("9f" + _RANGE_1_25 + "ff", list(range(1, 26))),
    ("bf61610161629f0203ffff", {"a": 1, "b": [2, 3]}),
    ("826161bf61626163ff", ["a", {"b": "c"}]),
    ("bf6346756ef563416d7421ff", {"Fun": True, "Amt": -2}),
]


@pytest.mark.parametrize(("hexs", "expected"), DECODE_VECTORS)
def test_decode_vector(hexs: str, expected: Any) -> None:
    result = loads(bytes.fromhex(hexs))
    if isinstance(expected, float) and math.isnan(expected):
        assert isinstance(result, float)
        assert math.isnan(result)
    else:
        assert result == expected
        if isinstance(expected, float):
            # distinguish -0.0 from 0.0
            assert math.copysign(1.0, result) == math.copysign(1.0, expected)


# Preferred-serialization encodings: obj -> canonical hex.
ENCODE_VECTORS: list[tuple[Any, str]] = [
    (0, "00"),
    (1, "01"),
    (10, "0a"),
    (23, "17"),
    (24, "1818"),
    (25, "1819"),
    (100, "1864"),
    (1000, "1903e8"),
    (1000000, "1a000f4240"),
    (1000000000000, "1b000000e8d4a51000"),
    (18446744073709551615, "1bffffffffffffffff"),
    (18446744073709551616, "c249010000000000000000"),
    (-18446744073709551616, "3bffffffffffffffff"),
    (-18446744073709551617, "c349010000000000000000"),
    (-1, "20"),
    (-10, "29"),
    (-100, "3863"),
    (-1000, "3903e7"),
    (0.0, "f90000"),
    (-0.0, "f98000"),
    (1.0, "f93c00"),
    (1.1, "fb3ff199999999999a"),
    (1.5, "f93e00"),
    (65504.0, "f97bff"),
    (100000.0, "fa47c35000"),
    (3.4028234663852886e38, "fa7f7fffff"),
    (1.0e300, "fb7e37e43c8800759c"),
    (5.960464477539063e-8, "f90001"),
    (0.00006103515625, "f90400"),
    (-4.0, "f9c400"),
    (-4.1, "fbc010666666666666"),
    (math.inf, "f97c00"),
    (math.nan, "f97e00"),
    (-math.inf, "f9fc00"),
    (False, "f4"),
    (True, "f5"),
    (None, "f6"),
    (undefined, "f7"),
    (CBORSimpleValue(16), "f0"),
    (CBORSimpleValue(255), "f8ff"),
    (
        datetime(2013, 3, 21, 20, 4, 0, tzinfo=_UTC),
        "c074323031332d30332d32315432303a30343a30305a",
    ),
    (CBORTag(23, b"\x01\x02\x03\x04"), "d74401020304"),
    (CBORTag(24, b"dIETF"), "d818456449455446"),
    (
        CBORTag(32, "http://www.example.com"),
        "d82076687474703a2f2f7777772e6578616d706c652e636f6d",
    ),
    (b"", "40"),
    (b"\x01\x02\x03\x04", "4401020304"),
    ("", "60"),
    ("a", "6161"),
    ("IETF", "6449455446"),
    ('"\\', "62225c"),
    ("\u00fc", "62c3bc"),
    ("\u6c34", "63e6b0b4"),
    ("\U00010151", "64f0908591"),
    ([], "80"),
    ([1, 2, 3], "83010203"),
    ([1, [2, 3], [4, 5]], "8301820203820405"),
    (list(range(1, 26)), "9819" + _RANGE_1_25),
    ({}, "a0"),
    ({1: 2, 3: 4}, "a201020304"),
    ({1: [2, 3], 4: 5}, "a2018202030405"),
    ({"a": 1, "b": [2, 3]}, "a26161016162820203"),
    (["a", {"b": "c"}], "826161a161626163"),
    (
        {"a": "A", "b": "B", "c": "C", "d": "D", "e": "E"},
        "a56161614161626142616361436164614461656145",
    ),
]


@pytest.mark.parametrize(("obj", "hexs"), ENCODE_VECTORS)
def test_encode_vector(obj: Any, hexs: str) -> None:
    assert dumps(obj, canonical=True) == bytes.fromhex(hexs)


def test_encode_epoch_int() -> None:
    dt = datetime(2013, 3, 21, 20, 4, 0, tzinfo=_UTC)
    assert dumps(dt, datetime_as_timestamp=True) == bytes.fromhex("c11a514b67b0")


def test_encode_epoch_float() -> None:
    dt = datetime(2013, 3, 21, 20, 4, 0, 500000, tzinfo=_UTC)
    assert dumps(dt, datetime_as_timestamp=True) == bytes.fromhex(
        "c1fb41d452d9ec200000"
    )


def test_self_describe_cbor_passthrough() -> None:
    # Tag 55799 wraps an item and is transparent to the application.
    assert loads(bytes.fromhex("d9d9f7") + dumps([1, 2])) == [1, 2]
