# SPDX-License-Identifier: 0BSD
"""Backend parity: the compiled fast path must match pure Python.

The compiled backend is exercised by the whole suite when present.
These tests pin equivalence between the two implementations on the
same inputs, and keep the pure-Python path covered even when the
extension is installed.
"""

import io
import math
from datetime import date, datetime, timezone
from typing import Any

import pytest

import cborx
from cborx import _backend
from cborx.decoder import CBORDecoder
from cborx.encoder import CBOREncoder

have_fast = _backend.fast is not None
skip_no_fast = pytest.mark.skipif(not have_fast, reason="no compiled backend")

# fmt: off
VALUES: list[Any] = [
    0, 1, 23, 24, 255, 256, 65535, 65536, 2**32, 2**64 - 1,
    -1, -24, -25, -256, -(2**63), 2**70, -(2**70),
    0.0, -0.0, 1.5, -1.5, 3.14159, 1e300, 5e-324,
    float("inf"), float("-inf"), float("nan"),
    b"", b"x", b"\x00\xff" * 40,
    "", "ascii", "héllo wörld", "𝕊𝕋𝕄", "\U0001f600",  # noqa: RUF001
    True, False, None,
    [], [1, "a", b"b", 2.5, None, True],
    {}, {"a": 1, "b": [1, 2], 3: "c"},
    cborx.CBORTag(0, "2024-01-01T00:00:00Z"),
    cborx.CBORTag(1, 1700000000),
    cborx.CBORTag(42, [1, 2]),
    cborx.CBORSimpleValue(0),
    cborx.CBORSimpleValue(255),
    cborx.undefined,
    datetime(2024, 6, 1, 12, 30, 45, tzinfo=timezone.utc),
    datetime(2024, 6, 1, 12, 30, 45),  # noqa: DTZ001
    date(2024, 6, 1),
    [[[["deep"]]]],
    {str(i): i for i in range(30)},
]
# fmt: on

WIRES = [
    bytes.fromhex(h)
    for h in (
        "9f0182020382030405ff",
        "bf61610161629f0203ff",
        "5f4201024103ff",
        "7f61616162ff",
        "c074323031332d30332d32315432303a30343a30305a",
        "c11a514b67b0",
        "d81e00",
        "f8ff",
        "e0",
        "a26161016162820203",
    )
]

MALFORMED = [
    b"",
    b"\x1c",
    b"\x1d",
    b"\x1e",
    b"\x1f",
    b"\x3f",
    b"\x41",
    b"\x61",
    b"\x81",
    b"\xa1\x61",
    b"\x9f\x01",
    b"\xff",
    b"\xf8\x1f",
    b"\xf8",
    b"\xf9\x7e",
    b"\x82\x01",
    b"\xa1\x01",
]


def _pure_dumps(obj: Any, **kwargs: Any) -> bytes:
    enc = CBOREncoder(io.BytesIO(), **kwargs)
    buf = bytearray()
    enc._write_item(obj, buf, 0)
    return bytes(buf)


def _pure_decode(data: Any, **kwargs: Any) -> Any:
    saved = _backend.fast
    _backend.fast = None
    try:
        return CBORDecoder(**kwargs).decode(data)
    finally:
        _backend.fast = saved


@pytest.mark.parametrize("obj", VALUES, ids=repr)
@pytest.mark.parametrize("canonical", [False, True])
@skip_no_fast
def test_encode_parity(obj: Any, canonical: bool) -> None:
    assert cborx.dumps(obj, canonical=canonical) == _pure_dumps(
        obj, canonical=canonical
    )


@pytest.mark.parametrize("obj", VALUES, ids=repr)
@skip_no_fast
def test_encode_parity_indefinite(obj: Any) -> None:
    assert cborx.dumps(obj, indefinite=True) == _pure_dumps(obj, indefinite=True)


@pytest.mark.parametrize("obj", VALUES, ids=repr)
@skip_no_fast
def test_roundtrip_parity(obj: Any) -> None:
    encoded = cborx.dumps(obj)
    fast_val = cborx.loads(encoded)
    pure_val = _pure_decode(encoded)
    assert _same(fast_val, pure_val), (fast_val, pure_val)


@pytest.mark.parametrize("wire", WIRES + MALFORMED)
@skip_no_fast
def test_decode_parity(wire: bytes) -> None:
    try:
        fast_val = cborx.loads(wire)
        fast_err = None
    except cborx.CBORDecodeError as e:
        fast_val, fast_err = None, e
    try:
        pure_val = _pure_decode(wire)
        pure_err = None
    except cborx.CBORDecodeError as e:
        pure_val, pure_err = None, e
    assert (fast_err is None) == (pure_err is None), wire.hex()
    if fast_err is None:
        assert _same(fast_val, pure_val)
    else:
        assert type(fast_err) is type(pure_err)
        assert str(fast_err) == str(pure_err)


@skip_no_fast
def test_decode_options_parity() -> None:
    wire = cborx.dumps({"b": 1, "a": 2})
    option_sets: tuple[dict[str, Any], ...] = (
        {"canonical": True},
        {"duplicate_keys": "first"},
        {"duplicate_keys": "error"},
        {"allow_indefinite": False},
        {"strict_utf8": False},
        {"max_depth": 2},
        {"tag_hook": lambda dec, tag: ("T", tag.tag, tag.value)},
    )
    for kwargs in option_sets:
        for data in (wire, b"\x9f\x01\x02\xff", b"\xc8\x01", b"\xff"):
            try:
                fast_val = cborx.loads(data, **kwargs)
                fast_err = None
            except Exception as e:  # noqa: BLE001
                fast_val, fast_err = None, e
            try:
                pure_val = _pure_decode(data, **kwargs)
                pure_err = None
            except Exception as e:  # noqa: BLE001
                pure_val, pure_err = None, e
            assert (fast_err is None) == (pure_err is None), (kwargs, data.hex())
            if fast_err is None:
                assert _same(fast_val, pure_val)
            else:
                assert type(fast_err) is type(pure_err), (kwargs, data.hex())
                assert str(fast_err) == str(pure_err), (kwargs, data.hex())


@skip_no_fast
def test_decode_pos_and_trailing_parity() -> None:
    data = cborx.dumps([1]) + cborx.dumps([2])
    assert cborx.loads(data, allow_trailing=True) == [1]
    saved = _backend.fast
    _backend.fast = None
    try:
        assert CBORDecoder().decode(data, allow_trailing=True) == [1]
    finally:
        _backend.fast = saved
    assert CBORDecoder().decode_item(data, 2) == ([2], 4)
    with pytest.raises(cborx.CBORDecodeError):
        cborx.loads(data)
    with pytest.raises(cborx.CBORDecodeError):
        CBORDecoder().decode_item(data, -1)
    saved = _backend.fast
    _backend.fast = None
    try:
        with pytest.raises(cborx.CBORDecodeError):
            CBORDecoder().decode_item(data, -1)
    finally:
        _backend.fast = saved


def _same(a: Any, b: Any) -> bool:
    if isinstance(a, float) and isinstance(b, float):
        if math.isnan(a) and math.isnan(b):
            return True
        return a == b and math.copysign(1.0, a) == math.copysign(1.0, b)
    if isinstance(a, dict) and isinstance(b, dict):
        if len(a) != len(b):
            return False
        unmatched = list(b.items())
        for ka, va in a.items():
            for i, (kb, vb) in enumerate(unmatched):
                if _same(ka, kb) and _same(va, vb):
                    unmatched.pop(i)
                    break
            else:
                return False
        return True
    if isinstance(a, (list, tuple)) and isinstance(b, (list, tuple)):
        return len(a) == len(b) and all(_same(x, y) for x, y in zip(a, b, strict=True))
    return a == b and type(a) is type(b)
