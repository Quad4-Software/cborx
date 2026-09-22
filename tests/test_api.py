# SPDX-License-Identifier: 0BSD
"""API surface, options, hooks, edge cases and metamorphic checks."""

import copy
import io
import math
from datetime import date, datetime, timedelta, timezone
from typing import Any, cast

import pytest

from cborx import (
    CBORDecodeError,
    CBORDecoder,
    CBOREncodeError,
    CBOREncoder,
    CBORError,
    CBORSimpleValue,
    CBORTag,
    DuplicateMode,
    UndefinedType,
    dump,
    dumps,
    load,
    loads,
    undefined,
)
from tests.util import same


def test_dump_and_load_file_objects() -> None:
    fp = io.BytesIO()
    dump({"a": [1, 2, 3]}, fp)
    assert fp.getvalue() == dumps({"a": [1, 2, 3]})
    fp.seek(0)
    assert load(fp) == {"a": [1, 2, 3]}


def test_load_reads_first_item_only() -> None:
    fp = io.BytesIO(dumps(1) + dumps(2))
    assert load(fp) == 1


def test_loads_accepts_buffer_types() -> None:
    data = dumps([1, "a"])
    assert loads(data) == [1, "a"]
    assert loads(bytearray(data)) == [1, "a"]
    assert loads(memoryview(data)) == [1, "a"]


def test_encoder_decoder_classes() -> None:
    fp = io.BytesIO()
    CBOREncoder(fp).encode([1, 2])
    assert CBORDecoder().decode(fp.getvalue()) == [1, 2]


def test_decode_item_returns_consumed_position() -> None:
    data = dumps(1) + dumps(2)
    value, pos = CBORDecoder().decode_item(data)
    assert (value, pos) == (1, 1)


def test_tag_hook_receives_decoder_and_tag() -> None:
    seen: list[CBORTag] = []

    def hook(decoder: CBORDecoder, tag: CBORTag) -> str:
        assert isinstance(decoder, CBORDecoder)
        seen.append(tag)
        return "hooked"

    assert loads(bytes.fromhex("d82a01"), tag_hook=hook) == "hooked"  # tag 42
    assert seen == [CBORTag(42, 1)]


def test_tag_hook_overrides_builtin_semantics() -> None:
    # With a hook installed even tag 0 goes through the hook.
    result = loads(
        bytes.fromhex("c074323031332d30332d32315432303a30343a30305a"),
        tag_hook=lambda dec, tag: ("tag", tag.tag, tag.value),
    )
    assert result == ("tag", 0, "2013-03-21T20:04:00Z")


def test_unhandled_tag_decodes_to_cbtag() -> None:
    assert loads(bytes.fromhex("d8ff6161")) == CBORTag(255, "a")


def test_default_callback_return_substitute() -> None:
    class Odd:
        pass

    def default(encoder: CBOREncoder, obj: Any) -> Any:
        if isinstance(obj, Odd):
            return {"odd": True}
        return None

    assert dumps(Odd(), default=default) == dumps({"odd": True})


def test_default_callback_writes_via_encoder() -> None:
    class Odd:
        pass

    def default(encoder: CBOREncoder, obj: Any) -> None:
        if isinstance(obj, Odd):
            encoder.encode(CBORTag(9999, "odd"))

    assert loads(dumps(Odd(), default=default)) == CBORTag(9999, "odd")


def test_default_callback_identity_guard() -> None:
    class Odd:
        pass

    with pytest.raises(CBOREncodeError):
        dumps(Odd(), default=lambda encoder, obj: obj)


def test_default_callback_silent_none_rejected() -> None:
    class Odd:
        pass

    # A default that neither writes nor returns a substitute would
    # silently corrupt the stream (the map loses its value).
    with pytest.raises(CBOREncodeError, match="emitted nothing"):
        dumps({"k": Odd()}, default=lambda encoder, obj: None)


def test_default_callback_write_and_return_rejected() -> None:
    class Odd:
        pass

    def default(encoder: CBOREncoder, obj: Any) -> Any:
        encoder.encode(0)
        return 1

    with pytest.raises(CBOREncodeError, match="both wrote"):
        dumps(Odd(), default=default)


def test_unencodable_type_raises() -> None:
    class Odd:
        pass

    with pytest.raises(CBOREncodeError):
        dumps(Odd())
    with pytest.raises(CBOREncodeError):
        dumps(object())


def test_max_depth_validation() -> None:
    with pytest.raises(ValueError, match="max_depth"):
        CBORDecoder(max_depth=0)
    with pytest.raises(ValueError, match="duplicate_keys"):
        CBORDecoder(duplicate_keys=cast(DuplicateMode, "bogus"))


def test_encode_depth_limit() -> None:
    nested: Any = 0
    for _ in range(300):
        nested = [nested]
    with pytest.raises(CBOREncodeError):
        dumps(nested)
    assert loads(dumps(nested, max_depth=400), max_depth=400) == nested


def test_encode_recursion_guard(monkeypatch: pytest.MonkeyPatch) -> None:
    # With max_depth above the interpreter recursion limit the encoder
    # fails with CBOREncodeError instead of crashing the interpreter.
    import cborx._backend as backend

    nested: Any = 0
    for _ in range(1500):
        nested = [nested]
    monkeypatch.setattr(backend, "fast", None)
    with pytest.raises(CBOREncodeError):
        dumps(nested, max_depth=10**6)
    monkeypatch.undo()

    if backend.fast is None:
        pytest.skip("no compiled backend")
    # The compiled path encodes 1500-deep natively and must still fail
    # safely, without a crash, past its internal C stack cap.
    assert loads(dumps(nested, max_depth=10**6), max_depth=10**6) == nested
    for _ in range(10000):
        nested = [nested]
    with pytest.raises(CBOREncodeError):
        dumps(nested, max_depth=10**6)


def test_undefined_sentinel() -> None:
    assert repr(undefined) == "undefined"
    assert not undefined
    assert undefined == UndefinedType()
    assert copy.copy(undefined) is undefined
    assert copy.deepcopy(undefined) is undefined
    assert loads(dumps(undefined)) is undefined
    # Any UndefinedType instance encodes as 0xf7, not only the sentinel.
    assert dumps(UndefinedType()) == b"\xf7"


def test_simple_value_encode_errors() -> None:
    bad_values: list[Any] = [-1, 256, 24, 25, 31, True, "x"]
    for bad in bad_values:
        with pytest.raises(CBOREncodeError):
            dumps(CBORSimpleValue(bad))
    assert dumps(CBORSimpleValue(0)) == b"\xe0"
    assert dumps(CBORSimpleValue(20)) == b"\xf4"  # encodes as false
    assert dumps(CBORSimpleValue(100)) == b"\xf8\x64"


def test_cbtag_encode_validation() -> None:
    with pytest.raises(CBOREncodeError):
        dumps(CBORTag(-1, 0))
    with pytest.raises(CBOREncodeError):
        dumps(CBORTag(1 << 70, 0))
    with pytest.raises(CBOREncodeError):
        dumps(CBORTag(True, 0))
    assert dumps(CBORTag(0, 0)) == b"\xc0\x00"


def test_lone_surrogate_rejected() -> None:
    with pytest.raises(CBOREncodeError):
        dumps("lone\ud800surrogate")


def test_map_with_non_string_keys() -> None:
    decoded = loads(dumps({1: "one", b"k": 2, 3.5: None}))
    assert decoded == {1: "one", b"k": 2, 3.5: None}
    # A tuple key encodes as an array, which decodes to an unhashable
    # list, so the decode side fails cleanly.
    with pytest.raises(CBORDecodeError):
        loads(dumps({(1,): "x"}))


def test_tuple_encodes_as_array() -> None:
    assert dumps((1, 2)) == b"\x82\x01\x02"
    assert loads(dumps((1, 2))) == [1, 2]


def test_bytearray_and_memoryview_encode() -> None:
    assert dumps(bytearray(b"\x01\x02")) == b"\x42\x01\x02"
    assert dumps(memoryview(b"\x01\x02")) == b"\x42\x01\x02"


def test_float_is_not_encoded_as_int() -> None:
    assert dumps(1.0)[0] == 0xFB
    assert dumps(1.0, canonical=True) == bytes.fromhex("f93c00")
    assert loads(dumps(1.0)) == 1.0
    assert isinstance(loads(dumps(1.0)), float)


def test_negative_zero_distinction() -> None:
    assert dumps(-0.0) != dumps(0.0)
    neg = loads(dumps(-0.0))
    assert neg == 0.0
    assert math.copysign(1.0, neg) == -1.0


def test_datetime_as_timestamp_naive_is_utc() -> None:
    dt = datetime(2021, 6, 1, 12, 0, 0)  # noqa: DTZ001  # naive on purpose
    encoded = dumps(dt, datetime_as_timestamp=True)
    assert loads(encoded) == dt.replace(tzinfo=timezone.utc)


def test_date_encodes_as_tag_1004() -> None:
    # RFC 8943: tag 1004 wraps an RFC 3339 full-date text string.
    assert dumps(date(1970, 1, 2)) == bytes.fromhex("d903ec6a313937302d30312d3032")
    assert loads(bytes.fromhex("d903ec6a313937302d30312d3032")) == date(1970, 1, 2)
    assert loads(dumps(date(1960, 5, 4))) == date(1960, 5, 4)


def test_date_decodes_legacy_and_epoch_forms() -> None:
    # cborx 0.1.1 emitted tag 1004 with an integer day count. Keep
    # accepting that form. Tag 100 is the RFC 8943 epoch-based date.
    assert loads(bytes.fromhex("d903ec01")) == date(1970, 1, 2)
    assert loads(bytes.fromhex("d86401")) == date(1970, 1, 2)


def test_uri_tag_decodes_to_str() -> None:
    # Documented choice: tag 32 decodes to a plain str.
    data = dumps(CBORTag(32, "https://quad4.io"))
    assert loads(data) == "https://quad4.io"


def test_canonical_map_key_ordering() -> None:
    # Canonical order is by encoded key bytes: shorter first, then
    # lexicographic. "a" encodes to two bytes, 1 to one byte, so the
    # integer key sorts first regardless of insertion order.
    a = dumps({"a": 1, 1: 2}, canonical=True)
    b = dumps({1: 2, "a": 1}, canonical=True)
    assert a == b == bytes.fromhex("a20102616101")


def test_canonical_output_is_stable() -> None:
    obj = {"z": [1, 2], "a": {"y": True, "x": None}, 10: "ten"}
    first = dumps(obj, canonical=True)
    assert first == dumps(loads(first), canonical=True)
    assert loads(first, canonical=True) is not None


def test_metamorphic_decode_encode_decode() -> None:
    obj = [1, {"a": [b"\x00", "x", None]}, -2.5, True]
    v1 = loads(dumps(obj, canonical=True), canonical=True)
    v2 = loads(dumps(v1, canonical=True), canonical=True)
    assert same(v1, v2)
    assert dumps(v1, canonical=True) == dumps(v2, canonical=True)


def test_mutation_invariance() -> None:
    # Re-marshaling a decoded object does not disturb the original.
    obj = {"k": [1, 2, {"n": 3}]}
    decoded = loads(dumps(obj))
    snapshot = copy.deepcopy(decoded)
    loads(dumps(decoded))
    assert decoded == snapshot


def test_error_hierarchy() -> None:
    assert issubclass(CBOREncodeError, CBORError)
    assert issubclass(CBORDecodeError, CBORError)
    with pytest.raises(CBORError):
        dumps(object())
    with pytest.raises(CBORError):
        loads(b"\xff")


def test_bignum_minimal_form() -> None:
    # 2**64 is the smallest int that needs the bignum tag.
    assert dumps(2**64 - 1) == bytes.fromhex("1bffffffffffffffff")
    assert dumps(2**64) == bytes.fromhex("c249010000000000000000")
    assert dumps(-(2**64)) == bytes.fromhex("3bffffffffffffffff")
    assert dumps(-(2**64) - 1) == bytes.fromhex("c349010000000000000000")


def test_epoch_tag_rejects_bad_values() -> None:
    with pytest.raises(CBORDecodeError):
        loads(bytes.fromhex("c11bffffffffffffffff"))  # absurd timestamp
    with pytest.raises(CBORDecodeError):
        loads(bytes.fromhex("c1f5"))  # tag 1 wrapping true


def test_empty_and_nested_empty_containers() -> None:
    obj = {"e": [], "m": {}, "n": [[], [{}], {"x": []}]}
    assert loads(dumps(obj)) == obj
    assert loads(dumps(obj, canonical=True), canonical=True) == obj


def test_decoder_strict_validation() -> None:
    assert CBORDecoder(max_depth=1).decode(b"\x00") == 0
    assert CBORDecoder(max_depth=1).decode(b"\x81\x00") == [0]
    with pytest.raises(CBORDecodeError):
        CBORDecoder(max_depth=1).decode(b"\x81\x81\x00")


def test_tag_wrapping_containers() -> None:
    obj = CBORTag(5000, {"deep": [CBORTag(5001, [1, 2])]})
    assert loads(dumps(obj)) == obj


def test_timedelta_not_builtin() -> None:
    # timedelta has no CBOR mapping: needs a default callback.
    with pytest.raises(CBOREncodeError):
        dumps(timedelta(days=1))
    out = dumps(timedelta(days=1), default=lambda enc, obj: obj.days)
    assert loads(out) == 1


def test_bool_not_confused_with_int() -> None:
    assert dumps(True) == b"\xf5"
    assert dumps(1) == b"\x01"
    assert loads(b"\xf5") is True


def test_indefinite_encoding() -> None:
    assert dumps(b"\x01\x02", indefinite=True) == bytes.fromhex("5f420102ff")
    assert dumps("ab", indefinite=True) == bytes.fromhex("7f626162ff")
    assert dumps([1, 2], indefinite=True) == bytes.fromhex("9f0102ff")
    assert dumps({"a": 1}, indefinite=True) == bytes.fromhex("bf7f6161ff01ff")
    obj = {"k": [b"\x00", "x"], "n": []}
    encoded = dumps(obj, indefinite=True)
    assert encoded[0] == 0xBF
    assert encoded[-1] == 0xFF
    assert loads(encoded) == obj
    with pytest.raises(ValueError, match="mutually exclusive"):
        dumps(obj, canonical=True, indefinite=True)
    with pytest.raises(CBORDecodeError):
        loads(encoded, canonical=True)


class _Int(int):
    __slots__ = ()


class _Str(str):
    __slots__ = ()


class _Float(float):
    __slots__ = ()


class _Bytes(bytes):
    __slots__ = ()


class _UInt(int):
    __slots__ = ()


class _List(list[Any]):
    pass


class _Dict(dict[Any, Any]):
    pass


class _DateTime(datetime):
    pass


class _Date(date):
    pass


class _Tag(CBORTag):
    pass


class _Simple(CBORSimpleValue):
    pass


class _Undef(UndefinedType):
    pass


def test_builtin_subclasses_encode_like_base() -> None:
    obj = {
        _Str("k"): [
            _Int(5),
            _Float(1.5),
            _Bytes(b"b"),
            _UInt(1),
            _List([1]),
            _Dict({"x": 2}),
            _DateTime(2024, 1, 2, 3, 4, 5, tzinfo=timezone.utc),
            _Date(2024, 1, 2),
            _Tag(1, 0),
            _Simple(33),
            _Undef(),
        ]
    }
    assert dumps(obj) == dumps(
        {
            "k": [
                5,
                1.5,
                b"b",
                1,
                [1],
                {"x": 2},
                datetime(2024, 1, 2, 3, 4, 5, tzinfo=timezone.utc),
                date(2024, 1, 2),
                CBORTag(1, 0),
                CBORSimpleValue(33),
                undefined,
            ]
        }
    )


def test_encode_recursion_limit_maps_to_encode_error() -> None:
    deep: Any = []
    for _ in range(5000):
        deep = [deep]
    enc = CBOREncoder(io.BytesIO(), max_depth=100000)
    with pytest.raises(CBOREncodeError, match="too deep"):
        enc.encode(deep)
    with pytest.raises(CBOREncodeError, match="too deep"):
        dumps(deep, max_depth=100000)


def test_canonical_map_with_many_keys() -> None:
    obj = {f"k{i:02d}": i for i in range(30)}
    encoded = dumps(obj, canonical=True)
    # 30 entries: the map header itself needs a multi-byte length.
    assert encoded[0] == 0xB8
    assert loads(encoded, canonical=True) == obj


def test_small_simple_values_decode() -> None:
    for v in range(20):
        assert loads(bytes((0xE0 | v,))) == CBORSimpleValue(v)
    assert loads(b"\xf8\x20") == CBORSimpleValue(32)
    assert loads(b"\xf8\x14") is False
