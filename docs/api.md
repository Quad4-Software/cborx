# API reference

Everything below is exported from the `cborx` package root.

```python
import cborx
```

## Module functions

### dumps

```python
cborx.dumps(
    obj,
    *,
    canonical: bool = False,
    indefinite: bool = False,
    datetime_as_timestamp: bool = False,
    default: DefaultCallback | None = None,
    max_depth: int = 200,
) -> bytes
```

Encode `obj` to CBOR and return the bytes. See
[Usage](usage.md#options) for the option semantics. Raises
`CBOREncodeError` on unencodable objects or excessive depth.

### dump

```python
cborx.dump(obj, fp, *, ...same options as dumps...) -> None
```

Encode `obj` to CBOR and write it to the binary file-like object `fp`.

### loads

```python
cborx.loads(
    data,
    *,
    tag_hook: TagHook | None = None,
    strict_utf8: bool = True,
    max_depth: int = 200,
    allow_indefinite: bool = True,
    canonical: bool = False,
    duplicate_keys: DuplicateMode = "last",
    allow_trailing: bool = False,
) -> Any
```

Decode a single CBOR data item from `bytes`, `bytearray` or
`memoryview`. Raises `CBORDecodeError` on malformed input and, unless
`allow_trailing` is set, on trailing bytes.

### load

```python
cborx.load(fp, *, ...same options as loads except allow_trailing...) -> Any
```

Read a binary file-like object to end and decode the first data item.
Trailing bytes are ignored, matching single-item stream semantics.

## Classes

### CBOREncoder

```python
CBOREncoder(fp, *, canonical=False, indefinite=False,
            datetime_as_timestamp=False, default=None, max_depth=200)
```

Streaming encoder writing to `fp`. `encode(obj)` writes one data item;
call it repeatedly to produce a CBOR sequence.

### CBORDecoder

```python
CBORDecoder(*, tag_hook=None, strict_utf8=True, max_depth=200,
            allow_indefinite=True, canonical=False,
            duplicate_keys="last")
```

Reusable decoder. `decode(data, *, allow_trailing=False)` decodes a
single item. Decoding is iterative with an explicit work stack, so
nesting depth is bounded by `max_depth` and never by the Python call
stack.

### CBORTag

```python
CBORTag(tag: int, value: Any)
```

A semantic tag wrapping a value. Immutable and hashable. Attributes:
`tag`, `value`.

### CBORSimpleValue

```python
CBORSimpleValue(value: int)
```

An unassigned simple value. Immutable and hashable. Attribute: `value`.
Values 20-23 decode to built-ins and 24-31 are reserved, so instances
carry the other assigned or unassigned simple values.

### UndefinedType / undefined

`undefined` is the singleton of `UndefinedType` representing CBOR simple
value 23. Falsy, hashable, and identity-stable across copies.

## Type aliases

- `TagHook`: `Callable[[CBORDecoder, CBORTag], Any]`
- `DuplicateMode`: `Literal["last", "first", "error"]`
- `DefaultCallback`: `Callable[[CBOREncoder, Any], Any]`

## Exceptions

- `CBORError`: base class for all cborx errors.
- `CBOREncodeError`: raised when an object cannot be encoded.
- `CBORDecodeError`: raised when input bytes cannot be decoded.
