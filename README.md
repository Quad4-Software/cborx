# cborx

[![CI](https://github.com/Quad4-Software/cborx/actions/workflows/ci.yml/badge.svg)](https://github.com/Quad4-Software/cborx/actions/workflows/ci.yml)
[![CodeQL](https://github.com/Quad4-Software/cborx/actions/workflows/codeql.yml/badge.svg)](https://github.com/Quad4-Software/cborx/actions/workflows/codeql.yml)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/Quad4-Software/cborx/badge)](https://securityscorecards.dev/viewer/?uri=github.com/Quad4-Software/cborx)
[![PyPI](https://img.shields.io/pypi/v/cborx)](https://pypi.org/project/cborx/)
[![License: 0BSD](https://img.shields.io/badge/license-0BSD-blue)](LICENSE)

CBOR (RFC 8949) encoder/decoder for Python. Zero runtime dependencies.

A hardened, fully typed replacement for cbor2. Wheels ship an optional
Cython accelerator that outperforms cbor2's native extension on encode
and most decode workloads, and every install falls back to a portable
pure-Python implementation with identical behavior. The accelerator
is CPython-only, declares free-threading support, and stays off PyPy,
where the JIT-optimized pure path is the right backend. The decoder is
iterative, bounds every claimed length against the remaining input,
and enforces a configurable nesting limit, so hostile input fails fast
instead of exhausting memory or the call stack.

## Install

```sh
pip install cborx
```

## Usage

```python
import cborx

data = cborx.dumps({"a": [1, 2, 3], "b": None})
assert cborx.loads(data) == {"a": [1, 2, 3], "b": None}

# Deterministic encoding: shortest-form integers and floats, map keys
# sorted by encoded key bytes (RFC 8949 section 4.2).
canonical = cborx.dumps({"b": 1, "a": 2}, canonical=True)

# Strict canonical validation on decode, duplicate-key policy, depth
# and indefinite-length controls.
cborx.loads(data, canonical=True, duplicate_keys="error", max_depth=100)

# Unhandled semantic tags round-trip as CBORTag. A tag_hook overrides
# all built-in tag handling.
cborx.loads(b"\xd8\x2a\x01", tag_hook=lambda decoder, tag: (tag.tag, tag.value))
assert cborx.loads(cborx.dumps(cborx.CBORTag(42, "x"))) == cborx.CBORTag(42, "x")

# A default callback handles otherwise unencodable objects, like cbor2.
cborx.dumps(object(), default=lambda encoder, obj: {"type": type(obj).__name__})

# Simple values and the undefined sentinel.
assert cborx.loads(b"\xf7") is cborx.undefined
assert cborx.loads(b"\xf0") == cborx.CBORSimpleValue(16)
```

Built-in semantic tags: 0 (ISO 8601 datetime), 1 (epoch datetime),
2/3 (bignum integers beyond the 64-bit range), 32 (URI, decoded to a
plain str since Python has no URI scalar), 1004 (calendar date) and
55799 (self-described CBOR, passed through). All other tags decode to
CBORTag. See RFC 8949: https://www.rfc-editor.org/rfc/rfc8949

## Development

```sh
uv sync --group dev
make check
```

License: 0BSD. Quad4 Software, https://quad4.io
