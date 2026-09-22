# SPDX-License-Identifier: 0BSD
"""CBOR encoder (RFC 8949)."""

import io
import math
import struct
from collections.abc import Callable
from datetime import date, datetime, timezone
from typing import Any, BinaryIO

from . import _backend
from ._util import float_min_ai
from .exceptions import CBOREncodeError
from .types import CBORSimpleValue, CBORTag, UndefinedType, undefined

_UINT64_MAX = (1 << 64) - 1
_EPOCH_DATE = date(1970, 1, 1)
_PACK_F16 = struct.Struct(">Be")
_PACK_F32 = struct.Struct(">Bf")
_PACK_F64 = struct.Struct(">Bd")

DefaultCallback = Callable[["CBOREncoder", Any], Any]
"""Called for objects with no built-in encoding.

The callback may either call encoder.encode(substitute) or return a
substitute object, which is then encoded in place of the original.
"""


def _to_bignum(value: int) -> bytes:
    return value.to_bytes((value.bit_length() + 7) // 8, "big")


class CBOREncoder:
    """Encode Python objects to a binary stream as CBOR."""

    def __init__(
        self,
        fp: BinaryIO,
        *,
        canonical: bool = False,
        indefinite: bool = False,
        datetime_as_timestamp: bool = False,
        default: DefaultCallback | None = None,
        max_depth: int = 200,
    ) -> None:
        if canonical and indefinite:
            raise ValueError("canonical and indefinite encoding are mutually exclusive")
        self._fp = fp
        self._canonical = canonical
        self._indefinite = indefinite
        self._datetime_as_timestamp = datetime_as_timestamp
        self._default = default
        self._max_depth = max_depth
        self._active: bytearray | None = None

    def encode(self, obj: Any) -> None:
        """Write obj to the stream as a single CBOR data item."""
        active = self._active
        if active is not None:
            # Nested call from a default callback: append in place so the
            # substituted bytes land at the correct position.
            self._write_item(obj, active, 0)
            return
        fast = _backend.fast
        try:
            if fast is not None:
                self._fp.write(fast.encode(self, obj))
                return
            buf = bytearray()
            self._write_item(obj, buf, 0)
        except RecursionError as e:
            raise CBOREncodeError("object graph too deep to encode") from e
        self._fp.write(buf)

    def _write_item(self, obj: Any, buf: bytearray, depth: int) -> None:  # noqa: C901
        if depth > self._max_depth:
            raise CBOREncodeError("maximum container depth exceeded")
        t = type(obj)
        # Exact-type checks cover the common cases cheaply. The
        # isinstance fallbacks below handle subclasses.
        if t is int:
            self._write_int(obj, buf)
        elif t is str:
            self._write_text(obj, buf)
        elif t is float:
            self._write_float(obj, buf)
        elif t is bytes:
            self._write_bytes(obj, buf)
        elif t is bool:
            buf.append(0xF5 if obj else 0xF4)
        elif t is list or t is tuple:
            self._write_array(obj, buf, depth)
        elif t is dict:
            self._write_map(obj, buf, depth)
        elif obj is None:
            buf.append(0xF6)
        elif t is UndefinedType or obj is undefined:
            buf.append(0xF7)
        elif t is CBORTag:
            self._write_tag(obj, buf, depth)
        elif t is CBORSimpleValue:
            self._write_simple(obj, buf)
        elif t is datetime:
            self._write_datetime(obj, buf, depth)
        elif t is date:
            self._write_date(obj, buf, depth)
        elif isinstance(obj, int):
            self._write_int(obj, buf)
        elif isinstance(obj, float):
            self._write_float(obj, buf)
        elif isinstance(obj, str):
            self._write_text(obj, buf)
        elif isinstance(obj, (bytes, bytearray, memoryview)):
            self._write_bytes(bytes(obj), buf)
        elif isinstance(obj, CBORTag):
            self._write_tag(obj, buf, depth)
        elif isinstance(obj, CBORSimpleValue):
            self._write_simple(obj, buf)
        elif isinstance(obj, UndefinedType):
            buf.append(0xF7)
        elif isinstance(obj, datetime):
            self._write_datetime(obj, buf, depth)
        elif isinstance(obj, date):
            self._write_date(obj, buf, depth)
        elif isinstance(obj, (list, tuple)):
            self._write_array(obj, buf, depth)
        elif isinstance(obj, dict):
            self._write_map(obj, buf, depth)
        else:
            self._write_default(obj, buf, depth)

    @staticmethod
    def _write_head(buf: bytearray, major: int, arg: int) -> None:
        if arg < 0 or arg > _UINT64_MAX:
            raise CBOREncodeError(f"argument {arg} out of range for CBOR header")
        base = major << 5
        if arg < 24:
            buf.append(base | arg)
        elif arg <= 0xFF:
            buf += bytes((base | 24, arg))
        elif arg <= 0xFFFF:
            buf.append(base | 25)
            buf += arg.to_bytes(2, "big")
        elif arg <= 0xFFFFFFFF:
            buf.append(base | 26)
            buf += arg.to_bytes(4, "big")
        else:
            buf.append(base | 27)
            buf += arg.to_bytes(8, "big")

    def _write_int(self, n: int, buf: bytearray) -> None:
        if 0 <= n < 24:
            buf.append(n)
            return
        if -24 <= n < 0:
            buf.append(0x20 | (-1 - n))
            return
        if n >= 0:
            if n <= _UINT64_MAX:
                self._write_head(buf, 0, n)
            else:
                self._write_head(buf, 6, 2)
                self._write_bytes(_to_bignum(n), buf)
        else:
            magnitude = -1 - n
            if magnitude <= _UINT64_MAX:
                self._write_head(buf, 1, magnitude)
            else:
                self._write_head(buf, 6, 3)
                self._write_bytes(_to_bignum(magnitude), buf)

    def _write_float(self, value: float, buf: bytearray) -> None:
        # NaN is always the RFC 8949 preferred form 0xf97e00: sign and
        # payload bits do not survive a float round trip anyway.
        # Non-canonical output uses float64 otherwise, except that
        # infinity uses float16 for compatibility with cbor2.
        if math.isnan(value):
            buf += b"\xf9\x7e\x00"
            return
        if self._canonical:
            ai = float_min_ai(value)
        elif math.isinf(value):
            ai = 25
        else:
            ai = 27
        if ai == 25:
            buf += _PACK_F16.pack(0xF9, value)
        elif ai == 26:
            buf += _PACK_F32.pack(0xFA, value)
        else:
            buf += _PACK_F64.pack(0xFB, value)

    def _write_text(self, s: str, buf: bytearray) -> None:
        try:
            raw = s.encode("utf-8")
        except UnicodeEncodeError as e:
            raise CBOREncodeError("text string contains lone surrogates") from e
        n = len(raw)
        if self._indefinite:
            buf.append(0x7F)
            self._write_head(buf, 3, n)
            buf += raw
            buf.append(0xFF)
            return
        if n < 24:
            buf.append(0x60 | n)
        else:
            self._write_head(buf, 3, n)
        buf += raw

    def _write_bytes(self, raw: bytes, buf: bytearray) -> None:
        n = len(raw)
        if self._indefinite:
            buf.append(0x5F)
            self._write_head(buf, 2, n)
            buf += raw
            buf.append(0xFF)
            return
        if n < 24:
            buf.append(0x40 | n)
        else:
            self._write_head(buf, 2, n)
        buf += raw

    def _write_tag(self, obj: CBORTag, buf: bytearray, depth: int) -> None:
        if isinstance(obj.tag, bool) or not isinstance(obj.tag, int):
            raise CBOREncodeError("CBORTag tag must be an integer")
        self._write_head(buf, 6, obj.tag)
        self._write_item(obj.value, buf, depth + 1)

    @staticmethod
    def _write_simple(obj: CBORSimpleValue, buf: bytearray) -> None:
        value = obj.value
        if (
            isinstance(value, bool)
            or not isinstance(value, int)
            or not 0 <= value <= 0xFF
        ):
            raise CBOREncodeError(f"simple value {value!r} out of range 0..255")
        if 24 <= value <= 31:
            raise CBOREncodeError(f"simple value {value} is reserved")
        if value < 24:
            buf.append(0xE0 | value)
        else:
            buf += bytes((0xF8, value))

    def _write_datetime(self, obj: datetime, buf: bytearray, depth: int) -> None:
        if self._datetime_as_timestamp:
            aware = obj if obj.tzinfo is not None else obj.replace(tzinfo=timezone.utc)
            timestamp = float(aware.timestamp())
            self._write_head(buf, 6, 1)
            self._write_item(
                int(timestamp) if timestamp.is_integer() else timestamp, buf, depth + 1
            )
            return
        text = obj.isoformat()
        if text.endswith("+00:00"):
            text = text[:-6] + "Z"
        self._write_head(buf, 6, 0)
        self._write_item(text, buf, depth + 1)

    def _write_date(self, obj: date, buf: bytearray, depth: int) -> None:
        # RFC 8943 calendar date: tag 1004 wrapping an RFC 3339 date string.
        self._write_head(buf, 6, 1004)
        self._write_item(obj.isoformat(), buf, depth + 1)

    def _write_array(
        self, obj: list[Any] | tuple[Any, ...], buf: bytearray, depth: int
    ) -> None:
        write_item = self._write_item
        child = depth + 1
        if self._indefinite:
            buf.append(0x9F)
            for item in obj:
                write_item(item, buf, child)
            buf.append(0xFF)
            return
        n = len(obj)
        if n < 24:
            buf.append(0x80 | n)
        else:
            self._write_head(buf, 4, n)
        for item in obj:
            write_item(item, buf, child)

    def _write_map(self, obj: dict[Any, Any], buf: bytearray, depth: int) -> None:
        write_item = self._write_item
        child = depth + 1
        if self._indefinite:
            buf.append(0xBF)
            for key, value in obj.items():
                write_item(key, buf, child)
                write_item(value, buf, child)
            buf.append(0xFF)
            return
        n = len(obj)
        if n < 24:
            buf.append(0xA0 | n)
        else:
            self._write_head(buf, 5, n)
        if self._canonical:
            pairs = [(self._key_bytes(key, depth), value) for key, value in obj.items()]
            pairs.sort(key=lambda pair: (len(pair[0]), pair[0]))
            for key_bytes, value in pairs:
                buf += key_bytes
                write_item(value, buf, child)
        else:
            for key, value in obj.items():
                write_item(key, buf, child)
                write_item(value, buf, child)

    def _key_bytes(self, key: Any, depth: int) -> bytes:
        buf = bytearray()
        self._write_item(key, buf, depth + 1)
        return bytes(buf)

    def _write_default(self, obj: Any, buf: bytearray, depth: int) -> None:
        if self._default is None:
            raise CBOREncodeError(f"cannot encode object of type {type(obj).__name__}")
        before = len(buf)
        prev = self._active
        self._active = buf
        try:
            substitute = self._default(self, obj)
        finally:
            self._active = prev
        wrote = len(buf) != before
        if substitute is None:
            if not wrote:
                # Emitting nothing would silently corrupt the stream (a
                # map would lose its value).
                raise CBOREncodeError(
                    f"default callback emitted nothing for {type(obj).__name__}"
                )
            return
        if wrote:
            raise CBOREncodeError(
                "default callback both wrote via encode() and returned a value"
            )
        if substitute is obj:
            raise CBOREncodeError("default callback returned the object it was given")
        self._write_item(substitute, buf, depth + 1)


def dumps(
    obj: Any,
    *,
    canonical: bool = False,
    indefinite: bool = False,
    datetime_as_timestamp: bool = False,
    default: DefaultCallback | None = None,
    max_depth: int = 200,
) -> bytes:
    """Encode obj to CBOR and return the bytes.

    canonical selects deterministic encoding per RFC 8949 section 4.2:
    shortest-form integers, shortest preserving floats, definite lengths
    and map keys sorted by encoded key bytes (shorter first, then
    lexicographic). indefinite emits indefinite-length byte strings,
    text strings, arrays and maps instead of definite ones. It cannot
    be combined with canonical. datetime_as_timestamp encodes datetime
    as tag 1 (seconds since epoch, naive treated as UTC) instead of
    tag 0 (ISO 8601 text). default handles otherwise unencodable
    objects.
    """
    enc = CBOREncoder(
        io.BytesIO(),
        canonical=canonical,
        indefinite=indefinite,
        datetime_as_timestamp=datetime_as_timestamp,
        default=default,
        max_depth=max_depth,
    )
    fast = _backend.fast
    try:
        if fast is not None:
            result: bytes = fast.encode(enc, obj)
            return result
        buf = bytearray()
        enc._write_item(obj, buf, 0)
        return bytes(buf)
    except RecursionError as e:
        raise CBOREncodeError("object graph too deep to encode") from e


def dump(
    obj: Any,
    fp: BinaryIO,
    *,
    canonical: bool = False,
    indefinite: bool = False,
    datetime_as_timestamp: bool = False,
    default: DefaultCallback | None = None,
    max_depth: int = 200,
) -> None:
    """Encode obj to CBOR and write it to a binary file-like object."""
    CBOREncoder(
        fp,
        canonical=canonical,
        indefinite=indefinite,
        datetime_as_timestamp=datetime_as_timestamp,
        default=default,
        max_depth=max_depth,
    ).encode(obj)
