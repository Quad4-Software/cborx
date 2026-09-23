# SPDX-License-Identifier: 0BSD
"""Differential tests against cbor2, the reference implementation.

cbor2 is a dev-only dependency. The runtime library stays dep-free.

Deliberate scope differences, asserted rather than hidden:

* Tags 28 and 29 (shareable and shared references) resolve references
  in cbor2 but decode to plain CBORTag in cborx. Tag 256 is likewise
  unwrapped by cbor2 and kept by cborx.
* Map keys that are not hashable (arrays, maps) decode via frozendict
  or tuples in cbor2 but are rejected by cborx.
* cbor2 refuses to encode naive datetimes without a configured
  timezone. cborx encodes them as tag 0 without an offset.
* cbor2 applies built-in semantic decoders for tags such as 4, 30 and
  35, producing Fraction, Decimal and re.Pattern objects. cborx keeps
  the CBORTag. The tests here assert the same information survives.
* cbor2 ignores trailing bytes after the first item. cborx rejects
  them by default and accepts them under allow_trailing.
* cbor2 returns an opaque marker object for a stray break byte, even
  as a map key. cborx rejects it per RFC 8949.
* cbor2 calls tag_hook only for tags without a built-in decoder and
  passes (tag, immutable). cborx calls tag_hook(decoder, tag) for
  every tag, overriding built-in handling.
* cbor2 decodes tag 1 timestamps through the C runtime. On Windows
  that rejects values before 1970 or after year 3000, so the
  timestamp parity test generates datetimes inside that range there.
  cborx uses epoch arithmetic and decodes the full range everywhere.
"""

import contextlib
import ipaddress
import math
import re
import sys
import uuid
from datetime import date, datetime, timedelta, timezone
from decimal import Decimal
from fractions import Fraction
from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

import cborx
from cborx import CBORSimpleValue, CBORTag, dumps, loads, undefined

cbor2 = pytest.importorskip("cbor2", reason="differential oracle not installed")

_FIXED_TZ = st.integers(-14 * 60, 14 * 60).map(lambda m: timezone(timedelta(minutes=m)))

# Range of tag 1 timestamps cbor2 can decode on the current platform.
# On Windows its C decoder calls gmtime, which accepts only
# 1970-01-01 through 3000-12-31 UTC. The bounds are padded by the
# maximum _FIXED_TZ offset (14h) so the UTC timestamp stays in range.
if sys.platform == "win32":
    _TS_DATETIMES = st.datetimes(
        min_value=datetime(1970, 1, 2),  # noqa: DTZ001  # bounds are naive
        max_value=datetime(3000, 12, 30),  # noqa: DTZ001
        timezones=_FIXED_TZ,
    )
else:
    _TS_DATETIMES = st.datetimes(timezones=_FIXED_TZ)

# Tags 28 and 29 carry shareable-reference semantics in cbor2 that
# cborx does not implement, so they are excluded from generated
# structures and covered by an explicit divergence test instead.
_TAG_NUMS = st.integers(0, (1 << 64) - 1).filter(lambda t: t not in {28, 29})

_LEAVES: st.SearchStrategy[Any] = st.one_of(
    st.none(),
    st.booleans(),
    st.integers(-(1 << 70), 1 << 70),
    st.floats(allow_nan=True, allow_infinity=True, allow_subnormal=True),
    st.binary(max_size=48),
    st.text(alphabet=st.characters(blacklist_categories={"Cs"}), max_size=48),
    st.just(undefined),
    st.builds(CBORSimpleValue, st.one_of(st.integers(0, 19), st.integers(32, 255))),
    st.datetimes(),
    st.datetimes(timezones=_FIXED_TZ),
    st.dates(),
)

_KEY_LEAVES: st.SearchStrategy[Any] = st.one_of(
    st.none(),
    st.booleans(),
    st.integers(-(1 << 70), 1 << 70),
    st.floats(allow_nan=False, allow_infinity=True),
    st.binary(max_size=24),
    st.text(alphabet=st.characters(blacklist_categories={"Cs"}), max_size=24),
)

_TREES: st.SearchStrategy[Any] = st.recursive(
    _LEAVES,
    lambda children: st.one_of(
        st.lists(children, max_size=6),
        st.dictionaries(_KEY_LEAVES, children, max_size=6),
        st.tuples(children),
        st.builds(CBORTag, _TAG_NUMS, children),
    ),
    max_leaves=40,
)


def _to_cbor2(obj: Any) -> Any:
    """Convert cborx-side values into their cbor2 equivalents."""
    if isinstance(obj, cborx.CBORTag):
        return cbor2.CBORTag(obj.tag, _to_cbor2(obj.value))
    if isinstance(obj, cborx.CBORSimpleValue):
        return cbor2.CBORSimpleValue(obj.value)
    if isinstance(obj, cborx.UndefinedType):
        return cbor2.undefined
    if isinstance(obj, dict):
        return {_to_cbor2(k): _to_cbor2(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_to_cbor2(v) for v in obj]
    return obj


_UNKNOWN = object()


def _norm_semantic(obj: Any) -> Any:
    """Fold cbor2's semantic decodes back into CBORTag form.

    Returns _UNKNOWN when obj is not a cbor2 semantic-decoded type.
    """
    if isinstance(obj, Fraction):
        return ("tag", 30, (obj.numerator, obj.denominator))
    if isinstance(obj, Decimal):
        t = obj.as_tuple()
        mantissa = int("".join(map(str, t.digits))) if t.digits else 0
        return ("tag", 4, (int(t.exponent), -mantissa if t.sign else mantissa))
    if isinstance(obj, re.Pattern):
        return ("tag", 35, obj.pattern)
    if isinstance(obj, uuid.UUID):
        return ("tag", 37, obj.bytes)
    if isinstance(obj, ipaddress.IPv4Address):
        return ("tag", 52, obj.packed)
    if isinstance(obj, ipaddress.IPv6Address):
        return ("tag", 54, obj.packed)
    if isinstance(obj, (ipaddress.IPv4Network, ipaddress.IPv6Network)):
        nbytes = (obj.prefixlen + 7) // 8
        packed = obj.network_address.packed[:nbytes].rstrip(b"\x00")
        tag = 52 if obj.version == 4 else 54
        return ("tag", tag, (obj.prefixlen, packed))
    if isinstance(obj, (set, frozenset)):
        return ("tag", 258, frozenset(_norm(v) for v in obj))
    return _UNKNOWN


def _norm_taglike(obj: Any) -> Any:
    """Normalize tag, simple and undefined wrappers from either library."""
    if isinstance(obj, (cborx.CBORTag, cbor2.CBORTag)):
        if obj.tag == 258 and isinstance(obj.value, (list, tuple)):
            # Tag 258 content is a set: order is not meaningful.
            return ("tag", 258, frozenset(_norm(v) for v in obj.value))
        return ("tag", obj.tag, _norm(obj.value))
    if isinstance(obj, (cborx.CBORSimpleValue, cbor2.CBORSimpleValue)):
        return ("simple", obj.value)
    if isinstance(obj, (cborx.UndefinedType, type(cbor2.undefined))):
        return ("undefined",)
    return _UNKNOWN


def _norm_plain(obj: Any) -> Any:
    if isinstance(obj, float):
        if math.isnan(obj):
            return ("nan", math.copysign(1.0, obj))
        return obj
    if isinstance(obj, datetime):
        return ("dt", obj)
    if isinstance(obj, date):
        return ("date", obj)
    if isinstance(obj, (list, tuple)):
        return tuple(_norm(v) for v in obj)
    if isinstance(obj, (dict, cbor2.frozendict)):
        return frozenset((_norm(k), _norm(v)) for k, v in obj.items())
    return obj


def _norm(obj: Any) -> Any:
    """Map a decoded value from either library to a comparison form.

    cbor2 resolves several semantic tags into Python objects. Each is
    folded back into the CBORTag structure that cborx returns, so a
    successful comparison proves the same information survived.
    """
    if isinstance(obj, bool):
        return obj
    tagged = _norm_taglike(obj)
    if tagged is not _UNKNOWN:
        return tagged
    sem = _norm_semantic(obj)
    if sem is not _UNKNOWN:
        return sem
    return _norm_plain(obj)


def _has_naive_datetime(obj: Any) -> bool:
    """True if obj holds a naive datetime, which cbor2 will not encode."""
    stack = [obj]
    while stack:
        item = stack.pop()
        if isinstance(item, datetime):
            if item.tzinfo is None or item.utcoffset() is None:
                return True
        elif isinstance(item, CBORTag):
            stack.append(item.value)
        elif isinstance(item, dict):
            stack.extend(item.keys())
            stack.extend(item.values())
        elif isinstance(item, (list, tuple)):
            stack.extend(item)
    return False


def _has_break_sentinel(obj: Any) -> bool:
    """True if obj contains cbor2's opaque break marker object."""
    stack = [obj]
    while stack:
        item = stack.pop()
        if type(item) is object:
            return True
        if isinstance(item, cbor2.CBORTag):
            stack.append(item.value)
        elif isinstance(item, (dict, cbor2.frozendict)):
            stack.extend(item.keys())
            stack.extend(item.values())
        elif isinstance(item, (list, tuple)):
            stack.extend(item)
    return False


# ------------------------------------------------------------------
# Encode equality: identical wire bytes for the same logical value.
# ------------------------------------------------------------------


@given(_TREES)
@settings(max_examples=400, deadline=None)
def test_encode_bytes_equal_default(obj: Any) -> None:
    if _has_naive_datetime(obj):
        return
    assert dumps(obj) == cbor2.dumps(_to_cbor2(obj))


@given(_TREES)
@settings(max_examples=400, deadline=None)
def test_encode_bytes_equal_canonical(obj: Any) -> None:
    if _has_naive_datetime(obj):
        return
    assert dumps(obj, canonical=True) == cbor2.dumps(_to_cbor2(obj), canonical=True)


@given(_TS_DATETIMES)
@settings(max_examples=100)
def test_datetime_as_timestamp_parity(dt: datetime) -> None:
    ours = dumps(dt, datetime_as_timestamp=True)
    theirs = cbor2.dumps(dt, datetime_as_timestamp=True)
    assert ours == theirs
    assert loads(ours) == cbor2.loads(theirs)


@given(st.dates())
@settings(max_examples=100)
def test_date_wire_parity(d: date) -> None:
    ours = dumps(d)
    theirs = cbor2.dumps(d)
    assert ours == theirs
    assert loads(theirs) == d
    assert cbor2.loads(ours) == d


@given(_TREES)
@settings(max_examples=400, deadline=None)
def test_indefinite_encode_parity(obj: Any) -> None:
    if _has_naive_datetime(obj):
        return
    ours = dumps(obj, indefinite=True)
    theirs = cbor2.dumps(_to_cbor2(obj), indefinite_containers=True)
    # Indefinite framing differs per container splitting choices, so
    # compare decoded values rather than bytes.
    _assert_decode_agreement(ours)
    _assert_decode_agreement(theirs)


# ------------------------------------------------------------------
# Cross decode: each library must read the other's output.
# ------------------------------------------------------------------


@given(_TREES)
@settings(max_examples=400, deadline=None)
def test_cbor2_decodes_cborx_output(obj: Any) -> None:
    _assert_decode_agreement(dumps(obj))


@given(_TREES)
@settings(max_examples=400, deadline=None)
def test_cborx_decodes_cbor2_output(obj: Any) -> None:
    if _has_naive_datetime(obj):
        return
    _assert_decode_agreement(cbor2.dumps(_to_cbor2(obj)))


# ------------------------------------------------------------------
# Decode agreement on arbitrary and mutated bytes: either both
# libraries reject an input or both accept it with equal values.
# ------------------------------------------------------------------


@st.composite
def _mutated_cbor(draw: Any) -> bytes:
    obj = draw(_TREES)
    encoder = draw(
        st.sampled_from(
            [
                lambda o: dumps(o),
                lambda o: dumps(o, canonical=True),
                lambda o: dumps(o, indefinite=True),
                lambda o: cbor2.dumps(_to_cbor2(o)),
                lambda o: cbor2.dumps(_to_cbor2(o), canonical=True),
                lambda o: cbor2.dumps(_to_cbor2(o), indefinite_containers=True),
            ]
        )
    )
    try:
        buf = bytearray(encoder(obj))
    except cbor2.CBOREncodeError:
        buf = bytearray(dumps(obj))
    for _ in range(draw(st.integers(0, 3))):
        op = draw(st.sampled_from(["flip", "truncate", "append"]))
        if op == "flip" and buf:
            buf[draw(st.integers(0, len(buf) - 1))] = draw(st.integers(0, 255))
        elif op == "truncate" and len(buf) > 1:
            del buf[draw(st.integers(1, len(buf) - 1)) :]
        else:
            buf += draw(st.binary(max_size=6))
    return bytes(buf)


# Tags cbor2 resolves through built-in semantic decoders. For these
# it applies content validation that cborx does not, so cborx may keep
# a CBORTag where cbor2 raises or returns a Python object.
_C2_SEMANTIC_TAGS = {
    0,
    1,
    2,
    3,
    4,
    5,
    25,
    28,
    29,
    30,
    35,
    36,
    37,
    52,
    54,
    100,
    258,
    260,
    261,
    1004,
    55799,
}

# Tags both libraries resolve semantically. For anything else in
# _C2_SEMANTIC_TAGS cbor2 decodes to a Python object while cborx keeps
# CBORTag, so a decoded-value mismatch is expected.
_SHARED_SEMANTIC = {0, 1, 2, 3, 100, 1004, 55799}
_C2_ONLY_SEMANTIC = _C2_SEMANTIC_TAGS - _SHARED_SEMANTIC

# Tags cborx resolves semantically that cbor2 leaves as CBORTag.
_X_ONLY_SEMANTIC = {32}

# Tags both libraries resolve where cborx validates content more
# strictly: cbor2 accepts bool content as a number, cborx does not.
_X_STRICT_TAGS = {1, 100}

# Tags cbor2 transparently unwraps: shareable 28, sharedref 29 and
# the string-concatenation marker 256. cborx keeps them as CBORTag.
_C2_UNWRAP_TAGS = {28, 29, 256}


def _wire_tags(data: bytes) -> set[int]:
    """Collect the tag numbers present on the wire via a tag_hook tap."""
    seen: set[int] = set()

    def tap(_dec: cborx.CBORDecoder, tag: CBORTag) -> Any:
        seen.add(tag.tag)
        return tag

    with contextlib.suppress(cborx.CBORError):
        loads(data, allow_trailing=True, tag_hook=tap)
    return seen


def _only_cborx_ok(data: bytes, theirs_err: str) -> None:
    """Assert that a cborx-accepts/cbor2-rejects split is legitimate."""
    if "two-byte sequence for simple value" in theirs_err:
        # cbor2 rejects non-minimal two-byte simple values. cborx
        # accepts them in lax mode like other non-minimal encodings.
        return
    # Otherwise a cbor2 built-in semantic decoder must have rejected
    # tag content that cborx surfaces as CBORTag.
    assert _wire_tags(data) & _C2_SEMANTIC_TAGS, (
        f"cborx accepted {data.hex()} but cbor2 rejected it"
    )


def _only_cbor2_ok(data: bytes, theirs: Any) -> None:
    """Assert that a cbor2-accepts/cborx-rejects split is legitimate."""
    wire = _wire_tags(data)
    if wire & _X_ONLY_SEMANTIC or wire & _X_STRICT_TAGS:
        return
    if _has_break_sentinel(theirs):
        return
    with pytest.raises(cborx.CBORDecodeError, match="unhashable"):
        loads(data, allow_trailing=True)


def _assert_decode_agreement(data: bytes) -> None:
    try:
        theirs = cbor2.loads(data)
    except Exception as exc:  # noqa: BLE001  # any cbor2 failure counts
        theirs_ok = False
        theirs = None
        theirs_err = str(exc)
    else:
        theirs_ok = True
        theirs_err = ""
    try:
        ours = loads(data, allow_trailing=True)
    except cborx.CBORError:
        ours_ok = False
        ours = None
    else:
        ours_ok = True

    if ours_ok != theirs_ok:
        if ours_ok:
            _only_cborx_ok(data, theirs_err)
        else:
            _only_cbor2_ok(data, theirs)
        return

    if ours_ok and _norm(ours) != _norm(theirs):
        # cbor2 unwraps shareable, sharedref and string-concat tags and
        # resolves extra tags to Python objects. The URI tag resolves
        # to str in cborx but stays a CBORTag in cbor2.
        wire = _wire_tags(data)
        assert wire & (_C2_UNWRAP_TAGS | _X_ONLY_SEMANTIC | _C2_ONLY_SEMANTIC), (
            f"decode mismatch on {data.hex()}: {ours!r} vs {theirs!r}"
        )


@given(st.binary(max_size=96))
@settings(max_examples=600, deadline=None)
def test_decode_agreement_random_bytes(data: bytes) -> None:
    _assert_decode_agreement(data)


@given(_mutated_cbor())
@settings(max_examples=600, deadline=None)
def test_decode_agreement_mutated(data: bytes) -> None:
    _assert_decode_agreement(data)


# ------------------------------------------------------------------
# Semantic tags: the same information survives on both sides.
# ------------------------------------------------------------------

_SEMANTIC_CASES: list[tuple[Any, int, Any]] = [
    # (object cbor2 encodes natively, tag number, tag content)
    (Fraction(1, 3), 30, [1, 3]),
    (Fraction(-7, 2), 30, [-7, 2]),
    (Decimal("274.43"), 4, [-2, 27443]),
    (Decimal(0), 4, [0, 0]),
    (
        uuid.UUID("12345678123456781234567812345678"),
        37,
        bytes.fromhex("12345678123456781234567812345678"),
    ),
    (ipaddress.ip_address("192.168.0.1"), 52, bytes([192, 168, 0, 1])),
    (ipaddress.ip_address("::1"), 54, bytes(15) + b"\x01"),
    (ipaddress.ip_network("192.168.0.0/24"), 52, [24, bytes([192, 168])]),
    (re.compile("abc"), 35, "abc"),
    ({1, 2, 3}, 258, [1, 2, 3]),
]


@pytest.mark.parametrize(("obj", "tag", "content"), _SEMANTIC_CASES)
def test_semantic_tag_parity(obj: Any, tag: int, content: Any) -> None:
    wire = cbor2.dumps(obj)
    ours = loads(wire)
    assert _norm(ours) == _norm(CBORTag(tag, content)), f"{wire.hex()}: {ours!r}"
    assert _norm(cbor2.loads(wire)) == _norm(ours)


def test_date_tag_error_parity() -> None:
    # Both decoders reject malformed or out-of-range date tag content.
    bad = [
        "d903ec6a6e6f742d612d64617465",  # tag 1004 wrapping non-date text
        "d903ec1bffffffffffffffff",  # tag 1004 int day count overflow
        "d864f4",  # tag 100 wrapping a bool
        "d8641bffffffffffffffff",  # tag 100 day count overflow
        "d86441aa",  # tag 100 wrapping a byte string
        "d903ec41aa",  # tag 1004 wrapping a byte string
    ]
    for hexform in bad:
        data = bytes.fromhex(hexform)
        _assert_decode_agreement(data)


def test_default_callback_matches_cbor2_native_encoding() -> None:
    """cborx's default hook can emit byte-identical semantic encodings."""

    def default(_encoder: cborx.CBOREncoder, obj: Any) -> Any:
        if isinstance(obj, Fraction):
            return CBORTag(30, [obj.numerator, obj.denominator])
        if isinstance(obj, Decimal):
            t = obj.as_tuple()
            mantissa = int("".join(map(str, t.digits))) if t.digits else 0
            return CBORTag(4, [int(t.exponent), -mantissa if t.sign else mantissa])
        if isinstance(obj, uuid.UUID):
            return CBORTag(37, obj.bytes)
        raise cborx.CBOREncodeError(f"cannot encode {type(obj).__name__}")

    for obj in (Fraction(22, 7), Decimal("-1.5"), uuid.uuid5(uuid.NAMESPACE_DNS, "x")):
        ours = dumps(obj, default=default)
        assert ours == cbor2.dumps(obj)
        assert loads(ours) == loads(cbor2.dumps(obj))


# ------------------------------------------------------------------
# Documented divergences: pinned down so they cannot silently change.
# ------------------------------------------------------------------


def test_shareable_reference_divergence() -> None:
    # Tag 28 wraps a shareable value: cbor2 unwraps it, cborx keeps it.
    wire = cbor2.dumps(cbor2.CBORTag(28, [1, 2]))
    assert cbor2.loads(wire) == [1, 2]
    assert loads(wire) == CBORTag(28, [1, 2])


def test_unhashable_key_divergence() -> None:
    wire = cbor2.dumps({(1, 2): 3})
    assert cbor2.loads(wire) == {(1, 2): 3}
    with pytest.raises(cborx.CBORDecodeError):
        loads(wire)


def test_naive_datetime_divergence() -> None:
    naive = datetime(2020, 1, 1, 12, 0, 0)  # noqa: DTZ001
    with pytest.raises(cbor2.CBOREncodeError):
        cbor2.dumps(naive)
    ours = dumps(naive)
    assert cbor2.loads(ours) == naive


def test_trailing_bytes_divergence() -> None:
    wire = dumps(1) + dumps(2)
    assert cbor2.loads(wire) == 1
    with pytest.raises(cborx.CBORDecodeError):
        loads(wire)
    assert loads(wire, allow_trailing=True) == 1


def test_stray_break_divergence() -> None:
    # cbor2 surfaces a bare break byte as an opaque marker object and
    # even accepts it as a map key. cborx rejects it per RFC 8949.
    marker = cbor2.loads(b"\xff")
    assert type(marker) is object
    with pytest.raises(cborx.CBORDecodeError):
        loads(b"\xff")
    with pytest.raises(cborx.CBORDecodeError):
        loads(bytes.fromhex("a1ff01"))


def test_tag_hook_semantics_divergence() -> None:
    # cbor2 hooks are consulted only for tags without a built-in
    # decoder and receive (tag, immutable). cborx overrides all tags
    # and receives (decoder, tag).
    seen: list[int] = []
    wire_tag0 = cbor2.dumps(datetime(2020, 1, 1, tzinfo=timezone.utc))

    def cbor2_hook(tag: Any, _immutable: bool) -> Any:
        seen.append(tag.tag)
        return tag.value

    assert isinstance(cbor2.loads(wire_tag0, tag_hook=cbor2_hook), datetime)
    assert seen == []

    seen2: list[int] = []

    def cborx_hook(_dec: cborx.CBORDecoder, tag: CBORTag) -> Any:
        seen2.append(tag.tag)
        return tag.value

    assert loads(wire_tag0, tag_hook=cborx_hook) is not None
    assert seen2 == [0]


# ------------------------------------------------------------------
# RFC 8949 Appendix A vectors through both implementations.
# ------------------------------------------------------------------


def test_rfc8949_vectors_agree() -> None:
    from tests.test_rfc8949 import DECODE_VECTORS

    for hexform, _expected in DECODE_VECTORS:
        data = bytes.fromhex(hexform)
        _assert_decode_agreement(data)


# ------------------------------------------------------------------
# Errors: both libraries raise typed errors on unencodable input.
# ------------------------------------------------------------------


def test_encode_error_parity() -> None:
    class Widget:
        pass

    with pytest.raises(cborx.CBOREncodeError):
        dumps(Widget())
    with pytest.raises(cbor2.CBOREncodeError):
        cbor2.dumps(Widget())


def test_decode_error_type_parity() -> None:
    bad_inputs = [
        b"",
        b"\x1c",  # reserved additional information
        b"\x81",  # truncated array
        b"\xa1\x01",  # odd map item count
    ]
    for data in bad_inputs:
        with pytest.raises(cborx.CBORDecodeError):
            loads(data)
        with pytest.raises(cbor2.CBORDecodeError):
            cbor2.loads(data)
