# SPDX-License-Identifier: 0BSD
"""Shared internal helpers."""

import math
import struct


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
