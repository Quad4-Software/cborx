# SPDX-License-Identifier: 0BSD
"""Smoke tests mirroring the README examples."""

import cborx


def test_readme_usage() -> None:
    data = cborx.dumps({"a": [1, 2, 3], "b": None})
    assert cborx.loads(data) == {"a": [1, 2, 3], "b": None}

    canonical = cborx.dumps({"b": 1, "a": 2}, canonical=True)
    assert cborx.loads(canonical) == {"a": 2, "b": 1}

    cborx.loads(data, canonical=False, duplicate_keys="error", max_depth=100)

    result = cborx.loads(
        b"\xd8\x2a\x01", tag_hook=lambda decoder, tag: (tag.tag, tag.value)
    )
    assert result == (42, 1)
    assert cborx.loads(cborx.dumps(cborx.CBORTag(42, "x"))) == cborx.CBORTag(42, "x")

    out = cborx.dumps(
        object(), default=lambda encoder, obj: {"type": type(obj).__name__}
    )
    assert cborx.loads(out) == {"type": "object"}

    assert cborx.loads(b"\xf7") is cborx.undefined
    assert cborx.loads(b"\xf0") == cborx.CBORSimpleValue(16)
