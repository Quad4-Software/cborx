# SPDX-License-Identifier: 0BSD
"""Shared helpers for the cborx test suite."""

import math
from typing import Any

from cborx import CBORTag


def same(a: Any, b: Any) -> bool:
    """Structural equality that treats NaN as equal to NaN."""
    if isinstance(a, float) and isinstance(b, float):
        if math.isnan(a) or math.isnan(b):
            return (
                math.isnan(a)
                and math.isnan(b)
                and math.copysign(1.0, a) == math.copysign(1.0, b)
            )
        return a == b and math.copysign(1.0, a) == math.copysign(1.0, b)
    if isinstance(a, CBORTag) and isinstance(b, CBORTag):
        return a.tag == b.tag and same(a.value, b.value)
    if isinstance(a, list) and isinstance(b, list):
        return len(a) == len(b) and all(same(x, y) for x, y in zip(a, b, strict=True))
    if isinstance(a, dict) and isinstance(b, dict):
        if len(a) != len(b):
            return False
        for key, value in a.items():
            matches = [bk for bk in b if same(key, bk)]
            if len(matches) != 1 or not same(value, b[matches[0]]):
                return False
        return True
    if type(a) is not type(b):
        return False
    return bool(a == b)


def depth(value: Any) -> int:
    """Iteratively measure the nesting depth of a decoded structure."""
    deepest = 0
    stack: list[tuple[Any, int]] = [(value, 1)]
    while stack:
        item, level = stack.pop()
        deepest = max(deepest, level)
        if isinstance(item, (list, tuple)):
            stack.extend((child, level + 1) for child in item)
        elif isinstance(item, dict):
            stack.extend((child, level + 1) for pair in item.items() for child in pair)
        elif isinstance(item, CBORTag):
            stack.append((item.value, level + 1))
    return deepest
