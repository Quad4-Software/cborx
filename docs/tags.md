# Semantic tags

CBOR semantic tags (major type 6) annotate a value with additional
meaning. cborx handles the common tags natively and exposes the rest
through `CBORTag`.

## Built-in tags

| Tag | Meaning | Decodes to | Encoded from |
| --- | --- | --- | --- |
| 0 | ISO 8601 datetime text | `datetime` | `datetime` (default) |
| 1 | Epoch timestamp | `datetime` | `datetime` with `datetime_as_timestamp=True` |
| 2 | Positive bignum | `int` | `int` beyond the 64-bit range |
| 3 | Negative bignum | `int` | `int` beyond the 64-bit range |
| 32 | URI | `str` | via `CBORTag(32, ...)` |
| 1004 | Calendar date | `datetime.date` | `datetime.date` |
| 55799 | Self-described CBOR | inner value | via `CBORTag(55799, ...)` |

Tag 32 decodes to a plain `str` since Python has no URI scalar. Tag
55799 passes through to its inner value on decode.

## Unhandled tags

Every other tag decodes to a `CBORTag`, and encoding a `CBORTag` writes
the tag header followed by the encoded value, so unhandled tags
round-trip losslessly:

```python
assert cborx.loads(cborx.dumps(cborx.CBORTag(42, "x"))) == cborx.CBORTag(42, "x")
```

`CBORTag` instances are immutable and hashable.

## Overriding tag handling

A `tag_hook` is called for every decoded tag and overrides all built-in
handling, including the tags in the table above:

```python
import cborx

value = cborx.loads(
    b"\xd8\x2a\x01",
    tag_hook=lambda decoder, tag: (tag.tag, tag.value),
)
assert value == (42, 1)
```

## Simple values

Simple values 20, 21, 22 and 23 decode to `False`, `True`, `None` and
`undefined` and are never wrapped. Other unassigned simple values decode
to `CBORSimpleValue`. Values 24 through 31 are reserved by RFC 8949 and
the encoder rejects them.

```python
assert cborx.loads(b"\xf7") is cborx.undefined
assert cborx.loads(b"\xf0") == cborx.CBORSimpleValue(16)
```

`undefined` is a singleton: it survives `copy`, `deepcopy` and identity
comparison, and is falsy.
