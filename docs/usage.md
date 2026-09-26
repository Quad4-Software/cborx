# Usage

## Encoding

`dumps` encodes a Python object to `bytes`, `dump` writes to a binary
file-like object.

```python
import cborx

data = cborx.dumps({"a": [1, 2, 3], "b": None})

with open("out.cbor", "wb") as fp:
    cborx.dump({"a": 1}, fp)
```

Supported value types: `None`, `bool`, `int` (arbitrary precision,
encoded with tags 2 and 3 beyond the 64-bit range), `float`, `bytes`,
`bytearray`, `memoryview`, `str`, `list`, `tuple`, `dict`,
`datetime.datetime`, `datetime.date`, `CBORTag`, `CBORSimpleValue` and
the `undefined` sentinel.

### Options

| Option | Default | Effect |
| --- | --- | --- |
| `canonical` | `False` | Deterministic encoding per RFC 8949 section 4.2: shortest-form integers, shortest preserving floats, definite lengths, map keys sorted by encoded key bytes (shorter first, then lexicographic). |
| `indefinite` | `False` | Emit indefinite-length byte strings, text strings, arrays and maps. Mutually exclusive with `canonical`. |
| `datetime_as_timestamp` | `False` | Encode `datetime` as tag 1 (seconds since epoch, naive treated as UTC) instead of tag 0 (ISO 8601 text). |
| `default` | `None` | Callback for otherwise unencodable objects. |
| `max_depth` | `200` | Maximum nesting depth. Exceeding it raises `CBOREncodeError`. |

### The default callback

Like cbor2, a `default` callback handles objects with no built-in
encoding. It may either call `encoder.encode(substitute)` or return a
substitute object.

```python
cborx.dumps(
    object(),
    default=lambda encoder, obj: {"type": type(obj).__name__},
)
```

A callback that both writes and returns a value raises
`CBOREncodeError`, as does one that returns the object it was given.

## Decoding

`loads` decodes a single data item from `bytes`, `bytearray` or
`memoryview`. `load` reads a binary file-like object to end and decodes
the first item.

```python
value = cborx.loads(b"\xa1aa\x01")  # {"a": 1}
value = cborx.load(open("out.cbor", "rb"))
```

### Options

| Option | Default | Effect |
| --- | --- | --- |
| `tag_hook` | `None` | Called for every decoded tag; the return value replaces the item. Overrides all built-in tag handling. |
| `strict_utf8` | `True` | Reject malformed UTF-8 in text strings. When `False`, invalid sequences decode with replacement characters. |
| `max_depth` | `200` | Maximum nesting depth. Exceeding it raises `CBORDecodeError`. |
| `allow_indefinite` | `True` | Accept indefinite-length items. |
| `canonical` | `False` | Enforce RFC 8949 preferred serialization: non-minimal integers, non-shortest floats, indefinite lengths and unsorted map keys are rejected. |
| `duplicate_keys` | `"last"` | `"last"` keeps the last value, `"first"` keeps the first, `"error"` raises `CBORDecodeError`. |
| `allow_trailing` | `False` | Permit bytes after the first complete data item. |

`load` always allows trailing bytes, matching single-item stream
semantics.

### Custom tag handling

```python
cborx.loads(
    b"\xd8\x2a\x01",
    tag_hook=lambda decoder, tag: (tag.tag, tag.value),
)
# -> (42, 1)
```

## Long-lived encoders and decoders

For repeated calls with non-default options, construct `CBOREncoder` or
`CBORDecoder` once and reuse it. `loads` itself caches a shared decoder
when all options are defaults.
