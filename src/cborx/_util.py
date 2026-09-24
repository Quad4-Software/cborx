# SPDX-License-Identifier: 0BSD
"""Shared internal helpers."""

import math
import struct
from typing import Any

from .exceptions import CBORDecodeError
from .types import CBORTag


def _nan_bearing(value: Any) -> bool:
    """True for map keys whose __eq__ never reports equality.

    float NaN, or a CBORTag chain ending in NaN. Such keys must be
    deduplicated by their encoded bytes instead: Python equality cannot
    detect a duplicate NaN key.
    """
    while isinstance(value, CBORTag):
        value = value.value
    return type(value) is float and math.isnan(value)


def _dedup_nan_keys(
    items: list[Any], nan_keys: list[tuple[int, bytes]], mode: str
) -> list[Any]:
    """Drop or reject duplicate NaN-bearing key pairs in items.

    nan_keys holds (items index, encoded key bytes) for each key where
    _nan_bearing was true. Two such keys are duplicates iff their wire
    encodings are byte-identical. mode is "last", "first" or "error".
    """
    groups: dict[bytes, list[int]] = {}
    for idx, raw in nan_keys:
        groups.setdefault(raw, []).append(idx)
    drop: set[int] = set()
    for idxs in groups.values():
        if len(idxs) < 2:
            continue
        if mode == "error":
            raise CBORDecodeError(f"duplicate map key {items[idxs[0]]!r}")
        keep = idxs[0] if mode == "first" else idxs[-1]
        for idx in idxs:
            if idx != keep:
                drop.add(idx)
                drop.add(idx + 1)
    if not drop:
        return items
    return [v for i, v in enumerate(items) if i not in drop]


def float_min_ai(value: float) -> int:
    """Return the smallest float additional-info width preserving a value.

    The result is one of the CBOR additional information values 25
    (half), 26 (single) or 27 (double). NaN maps to 25, the preferred
    encoding 0xf97e00.
    """
    if math.isnan(value):
        return 25
    if _fits(">e", value):
        return 25
    if _fits(">f", value):
        return 26
    return 27


def _fits(fmt: str, value: float) -> bool:
    """True if value survives a round trip through format fmt."""
    try:
        return bool(struct.unpack(fmt, struct.pack(fmt, value))[0] == value)
    except OverflowError:
        return False
