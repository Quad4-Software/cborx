# SPDX-License-Identifier: 0BSD
"""Property-based round-trip tests."""

from datetime import date, datetime, timedelta, timezone
from typing import Any

from hypothesis import given, settings
from hypothesis import strategies as st

from cborx import CBORSimpleValue, CBORTag, dumps, loads, undefined
from tests.util import same

_BUILTIN_TAGS = {0, 1, 2, 3, 32, 1004, 55799}

# Fixed-offset timezones only: zoneinfo datetimes near DST gaps have
# surprising equality semantics in CPython itself, unrelated to CBOR.
_FIXED_TZ = st.integers(-14 * 60, 14 * 60).map(lambda m: timezone(timedelta(minutes=m)))

_SCALARS: st.SearchStrategy[Any] = st.one_of(
    st.none(),
    st.booleans(),
    st.integers(),
    st.floats(allow_nan=True, allow_infinity=True, allow_subnormal=True),
    st.binary(max_size=64),
    st.text(alphabet=st.characters(blacklist_categories={"Cs"}), max_size=64),
    st.just(undefined),
    st.builds(CBORSimpleValue, st.one_of(st.integers(0, 19), st.integers(32, 255))),
    st.datetimes(),
    st.datetimes(timezones=_FIXED_TZ),
    st.dates(),
)

_NONBUILTIN_TAG = st.integers(0, (1 << 64) - 1).filter(lambda t: t not in _BUILTIN_TAGS)

# Scalars usable as map keys (hashable).
_KEYS = _SCALARS

_TREES: st.SearchStrategy[Any] = st.recursive(
    _SCALARS,
    lambda children: st.one_of(
        st.lists(children, max_size=8),
        st.dictionaries(_KEYS, children, max_size=8),
        st.builds(CBORTag, _NONBUILTIN_TAG, children),
    ),
    max_leaves=48,
)

# Trees that never touch semantic tags, for byte-level fixpoint checks.
_PLAIN_SCALARS = st.one_of(
    st.none(),
    st.booleans(),
    st.integers(),
    st.floats(allow_nan=True, allow_infinity=True),
    st.binary(max_size=32),
    st.text(alphabet=st.characters(blacklist_categories={"Cs"}), max_size=32),
)

_PLAIN_TREES: st.SearchStrategy[Any] = st.recursive(
    _PLAIN_SCALARS,
    lambda children: st.one_of(
        st.lists(children, max_size=6),
        st.dictionaries(_PLAIN_SCALARS, children, max_size=6),
        st.builds(CBORTag, _NONBUILTIN_TAG, children),
    ),
    max_leaves=32,
)


@given(_TREES)
@settings(max_examples=400, deadline=None)
def test_round_trip(obj: Any) -> None:
    assert same(loads(dumps(obj)), obj)


@given(_TREES)
@settings(max_examples=400, deadline=None)
def test_canonical_round_trip(obj: Any) -> None:
    encoded = dumps(obj, canonical=True)
    # Canonical output must satisfy strict canonical decoding.
    decoded = loads(encoded, canonical=True)
    assert same(decoded, obj)
    # Re-encoding the decoded value is a value-level fixpoint.
    assert same(loads(dumps(decoded, canonical=True)), decoded)


@given(_PLAIN_TREES)
@settings(max_examples=300, deadline=None)
def test_canonical_byte_fixpoint(obj: Any) -> None:
    first = dumps(obj, canonical=True)
    second = dumps(loads(first), canonical=True)
    assert first == second


@given(st.lists(st.integers(), max_size=12))
def test_canonical_int_vectors(values: list[int]) -> None:
    for value in values:
        assert loads(dumps(value, canonical=True), canonical=True) == value


def test_special_floats_round_trip() -> None:
    specials: list[float] = [
        0.0,
        -0.0,
        1.0,
        -1.0,
        5e-324,  # smallest float64 subnormal
        2.2250738585072014e-308,  # smallest float64 normal
        1.7976931348623157e308,  # largest float64
        5.960464477539063e-8,  # smallest float16 subnormal
        65504.0,  # largest float16
        3.4028234663852886e38,  # largest float32
        6.103515625e-05,
        -4.1,
    ]
    for value in specials:
        for canonical in (False, True):
            result = loads(dumps(value, canonical=canonical))
            assert isinstance(result, float)
            assert result == value
            assert result.hex() == float(value).hex()


def test_integral_float_stays_float() -> None:
    for value in (1.0, -100.0, 2.0**64):
        result = loads(dumps(value))
        assert isinstance(result, float)
        assert result == value


def test_datetime_variants_round_trip() -> None:
    values = [
        datetime(2020, 1, 1),  # noqa: DTZ001  # naive on purpose
        datetime(2020, 1, 1, 12, 30, 45, 123456),  # noqa: DTZ001
        datetime(2013, 3, 21, 20, 4, 0, tzinfo=timezone.utc),
        date(1970, 1, 1),
        date(1, 1, 1),
        date(9999, 12, 31),
        date(1969, 12, 31),
    ]
    for value in values:
        assert loads(dumps(value)) == value
