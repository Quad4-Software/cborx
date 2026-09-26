# cborx

CBOR (RFC 8949) encoder/decoder for Python. Zero runtime dependencies.

A hardened, fully typed replacement for cbor2. Wheels ship an optional
Cython accelerator that outperforms cbor2's native extension on encode
and most decode workloads, and every install falls back to a portable
pure-Python implementation with identical behavior. The accelerator is
CPython-only, declares free-threading support, and stays off PyPy, where
the JIT-optimized pure path is the right backend.

## Features

- Full RFC 8949 data model: all major types, simple values, bignums,
  half/float/double precision floats.
- Deterministic encoding per RFC 8949 section 4.2: shortest-form
  integers and floats, definite lengths, map keys sorted by encoded
  key bytes.
- Optional strict canonical validation on decode, plus a configurable
  duplicate-key policy.
- Semantic tag support with built-in handling for tags 0, 1, 2, 3, 32,
  1004 and 55799, and a `tag_hook` that overrides everything.
- Hardened iterative decoder: nesting depth is bounded by `max_depth`,
  never by the Python call stack, and every claimed length is checked
  against the remaining input before allocation.
- `py.typed` marker, strict mypy coverage, and a test suite that
  differentiates both backends against cbor2 and the RFC 8949 appendix
  test vectors.

## Install

```sh
pip install cborx
```

The compiled accelerator ships in the wheels for supported platforms.
Installs from source fall back to pure Python when a Cython toolchain
is not available, and `CBORX_DISABLE_FAST=1` forces the pure backend
on any install.

## Quick start

```python
import cborx

data = cborx.dumps({"a": [1, 2, 3], "b": None})
assert cborx.loads(data) == {"a": [1, 2, 3], "b": None}
```

Deterministic encoding is one flag away:

```python
canonical = cborx.dumps({"b": 1, "a": 2}, canonical=True)
```

See [Usage](usage.md) for the full option set and [API reference](api.md)
for signatures.
