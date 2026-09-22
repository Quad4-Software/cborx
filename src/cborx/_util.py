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
    try:
        if struct.unpack(">e", struct.pack(">e", value))[0] == value:
            return 25
    except OverflowError:
        pass
    try:
        if struct.unpack(">f", struct.pack(">f", value))[0] == value:
            return 26
    except OverflowError:
        pass
    return 27
