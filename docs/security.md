# Security

cborx is designed to be safe on hostile input. The decoder fails fast
on malformed or adversarial data instead of exhausting memory or the
call stack.

## Decoder hardening

- **Iterative decoding.** Containers are processed on an explicit work
  stack, so nesting depth is bounded by `max_depth` (default 200) and
  never by the Python call stack. Deeply nested input raises
  `CBORDecodeError` rather than `RecursionError`.
- **Length bounds.** Every claimed array, map, string and byte-string
  length is checked against the remaining input before allocation, so a
  header advertising 4 GiB of items in a 12-byte buffer is rejected
  immediately.
- **Size accounting.** Aggregate sizes are tracked so that many small
  items cannot sum to a memory exhaustion attack.
- **No trailing data by default.** `loads` rejects inputs with bytes
  left over after the first item; opt in with `allow_trailing=True`
  when decoding from a stream.

## Stricter modes

For protocols that require deterministic bytes, `canonical=True` on
decode enforces RFC 8949 preferred serialization: non-minimal integers,
non-shortest floats, indefinite lengths and unsorted map keys are all
rejected.

`duplicate_keys="error"` rejects maps with repeated keys, which some
specifications require and which otherwise silently keep the last value.

## Testing posture

The test suite runs both backends through the RFC 8949 appendix test
vectors, property-based round-trip tests with Hypothesis, differential
tests against cbor2, and a dedicated adversarial suite covering
truncated inputs, oversize length claims, duplicate keys, NaN keys and
deep nesting. CI also runs a guided fuzzing job (Atheris) on the pure
backend.

Report vulnerabilities to security@quad4.io. Do not open public issues
for security reports.
