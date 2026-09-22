# SPDX-License-Identifier: 0BSD
"""Hardened iterative CBOR decoder (RFC 8949)."""

import struct
from collections.abc import Callable
from datetime import date, datetime, timedelta, timezone
from functools import partial
from typing import Any, BinaryIO, Literal

from . import _backend
from ._util import float_min_ai
from .exceptions import CBORDecodeError
from .types import CBORSimpleValue, CBORTag, undefined

TagHook = Callable[["CBORDecoder", CBORTag], Any]
"""Called for every decoded tag when provided.

Receives the decoder and a CBORTag. The return value replaces the item.
When a tag_hook is set it overrides all built-in semantic tag handling.
"""

DuplicateMode = Literal["last", "first", "error"]

_MISSING = object()
_ARR, _MAP, _TAG = 0, 1, 2

_U16 = struct.Struct(">H")
_U32 = struct.Struct(">I")
_U64 = struct.Struct(">Q")
_F16 = struct.Struct(">e")
_F32 = struct.Struct(">f")
_F64 = struct.Struct(">d")

_ARG_UNPACK: dict[int, struct.Struct] = {2: _U16, 4: _U32, 8: _U64}
_FLOAT_UNPACK: dict[int, struct.Struct] = {25: _F16, 26: _F32, 27: _F64}
_FLOAT_SIZES = {25: 2, 26: 4, 27: 8}
_MINIMAL_ARG = {1: 24, 2: 0x100, 4: 0x10000, 8: 0x100000000}
_EPOCH_DATE = date(1970, 1, 1)


class _Frame:
    """One open container or tag on the decode work stack."""

    __slots__ = ("items", "kind", "prev_key", "remaining", "start", "tag")

    def __init__(self, kind: int, remaining: int, start: int, tag: int = 0) -> None:
        self.kind = kind
        self.remaining = remaining  # -1 means indefinite length
        self.items: list[Any] = []
        self.tag = tag
        self.start = start
        self.prev_key: bytes | None = None


class CBORDecoder:
    """Decode CBOR data items.

    Decoding is iterative with an explicit work stack: nesting depth is
    bounded by max_depth and never by the Python call stack.
    """

    def __init__(
        self,
        *,
        tag_hook: TagHook | None = None,
        strict_utf8: bool = True,
        max_depth: int = 200,
        allow_indefinite: bool = True,
        canonical: bool = False,
        duplicate_keys: DuplicateMode = "last",
    ) -> None:
        if max_depth < 1:
            raise ValueError("max_depth must be at least 1")
        if duplicate_keys not in ("last", "first", "error"):
            raise ValueError(f"invalid duplicate_keys mode {duplicate_keys!r}")
        self._tag_hook = tag_hook
        self._utf8_errors = "strict" if strict_utf8 else "replace"
        self._max_depth = max_depth
        self._allow_indefinite = allow_indefinite
        self._canonical = canonical
        self._duplicate_keys = duplicate_keys
        # Packed for the compiled backend so it reads one attribute.
        self._cfg = (
            canonical,
            allow_indefinite,
            min(max_depth, 2147483647),
            {"last": 0, "first": 1, "error": 2}[duplicate_keys],
            strict_utf8,
        )

    def decode(
        self, data: bytes | bytearray | memoryview, *, allow_trailing: bool = False
    ) -> Any:
        """Decode a single data item from data.

        Raises CBORDecodeError on trailing bytes unless allow_trailing is
        set.
        """
        value, pos = self.decode_item(data, 0)
        if not allow_trailing and pos != len(data):
            raise CBORDecodeError(f"trailing data at offset {pos}")
        return value

    def decode_item(  # noqa: C901
        self, data: bytes | bytearray | memoryview, pos: int = 0
    ) -> tuple[Any, int]:
        """Decode one data item starting at pos and return (value, new pos)."""
        if _backend.fast is not None:
            result: tuple[Any, int] = _backend.fast.decode_item(self, data, pos)
            return result
        if pos < 0:
            raise CBORDecodeError("unexpected end of input")
        if not isinstance(data, bytes):
            data = bytes(data)
        n = len(data)
        frames: list[_Frame] = []
        read_one = self._read_one
        read_arg = self._read_arg
        canonical = self._canonical
        utf8_errors = self._utf8_errors
        value: Any = _MISSING
        start = end = pos
        while True:
            if value is _MISSING:
                start = pos
                # Inline the dominant forms so common scalars and short
                # strings skip the _read_one call entirely.
                if pos >= n:
                    raise CBORDecodeError("unexpected end of input")
                head = data[pos]
                if head < 0x18:
                    pos += 1
                    end = pos
                    value = head
                elif 0x20 <= head < 0x38:
                    pos += 1
                    end = pos
                    value = -1 - (head & 0x1F)
                elif 0x40 <= head < 0x58:
                    arg = head & 0x1F
                    pos += 1
                    if arg > n - pos:
                        raise CBORDecodeError(
                            f"declared length {arg} exceeds {n - pos} "
                            f"remaining bytes at offset {start}"
                        )
                    value = data[pos : pos + arg]
                    pos += arg
                    end = pos
                elif 0x60 <= head < 0x78:
                    arg = head & 0x1F
                    pos += 1
                    if arg > n - pos:
                        raise CBORDecodeError(
                            f"declared length {arg} exceeds {n - pos} "
                            f"remaining bytes at offset {start}"
                        )
                    try:
                        value = data[pos : pos + arg].decode("utf-8", utf8_errors)
                    except UnicodeDecodeError as e:
                        raise CBORDecodeError("invalid UTF-8 in text string") from e
                    pos += arg
                    end = pos
                elif head < 0x1C:
                    pos += 1
                    value, pos = read_arg(data, pos, n, head)
                    end = pos
                elif 0x38 <= head < 0x3C:
                    pos += 1
                    arg, pos = read_arg(data, pos, n, head & 0x1F)
                    end = pos
                    value = -1 - arg
                elif head == 0xF4:
                    pos += 1
                    end = pos
                    value = False
                elif head == 0xF5:
                    pos += 1
                    end = pos
                    value = True
                elif head == 0xF6:
                    pos += 1
                    end = pos
                    value = None
                elif head == 0xF7:
                    pos += 1
                    end = pos
                    value = undefined
                else:
                    value, end = read_one(data, pos, n, frames)
                    pos = end
                    if value is _MISSING:
                        continue  # a container or tag frame was pushed
            while value is not _MISSING:
                if not frames:
                    return value, end
                frame = frames[-1]
                if frame.kind == _TAG:
                    frames.pop()
                    value = self._apply_tag(frame.tag, value)
                    start = frame.start
                    continue
                if canonical and frame.kind == _MAP and not len(frame.items) % 2:
                    self._check_key_order(data, frame, start, end)
                frame.items.append(value)
                if frame.remaining > 0:
                    frame.remaining -= 1
                if frame.remaining == 0:
                    frames.pop()
                    value = self._finish(frame)
                    start = frame.start
                    continue
                value = _MISSING

    @staticmethod
    def _check_key_order(data: bytes, frame: _Frame, start: int, end: int) -> None:
        key = data[start:end]
        prev = frame.prev_key
        if prev is not None and (len(key), key) <= (len(prev), prev):
            raise CBORDecodeError("map keys are not in canonical order")
        frame.prev_key = key

    def _read_one(
        self, data: bytes, pos: int, n: int, frames: list[_Frame]
    ) -> tuple[Any, int]:
        """Read one item and return (value or _MISSING, end).

        Only called for heads outside the decode_item fast path, so
        major types 0 and 1 and ai 20..23 cannot reach this point.
        """
        start = pos
        head = data[pos]
        pos += 1
        major = head >> 5
        ai = head & 0x1F
        if ai == 0x1F:
            return self._read_indefinite(data, pos, n, start, major, frames)
        if ai > 0x1B:
            raise CBORDecodeError(
                f"reserved additional information {ai} at offset {start}"
            )
        if major == 7:
            return self._read_simple_or_float(data, pos, n, start, ai)
        arg, pos = self._read_arg(data, pos, n, ai)
        if major == 2 or major == 3:
            return self._read_string(data, pos, n, start, major, arg)
        return self._open_container(pos, start, major, arg, frames)

    def _read_indefinite(
        self,
        data: bytes,
        pos: int,
        n: int,
        start: int,
        major: int,
        frames: list[_Frame],
    ) -> tuple[Any, int]:
        if major == 7:
            # Break byte: only valid closing an indefinite container.
            if frames and frames[-1].remaining == -1:
                frame = frames.pop()
                if frame.kind == _MAP and len(frame.items) % 2 != 0:
                    raise CBORDecodeError("indefinite-length map has an odd item count")
                return self._finish(frame), pos
            raise CBORDecodeError(
                f"break byte outside indefinite-length item at offset {start}"
            )
        if major in (0, 1, 6):
            raise CBORDecodeError(
                f"indefinite length not allowed for major type {major} "
                f"at offset {start}"
            )
        if not self._allow_indefinite:
            raise CBORDecodeError(
                f"indefinite-length item not permitted at offset {start}"
            )
        if self._canonical:
            raise CBORDecodeError(
                f"indefinite-length item is not canonical at offset {start}"
            )
        if major in (2, 3):
            return self._read_indef_string(data, pos, n, start, major)
        if len(frames) >= self._max_depth:
            raise CBORDecodeError(
                f"maximum depth {self._max_depth} exceeded at offset {start}"
            )
        frames.append(_Frame(_ARR if major == 4 else _MAP, -1, start))
        return _MISSING, pos

    def _read_arg(self, data: bytes, pos: int, n: int, ai: int) -> tuple[int, int]:
        if ai < 24:
            return ai, pos
        nbytes = 1 << (ai - 24)  # ai 24..27 gives 1, 2, 4, 8
        if pos + nbytes > n:
            raise CBORDecodeError("truncated integer argument")
        if nbytes == 1:
            arg = data[pos]
        else:
            arg = _ARG_UNPACK[nbytes].unpack_from(data, pos)[0]
        pos += nbytes
        if self._canonical and arg < _MINIMAL_ARG[nbytes]:
            raise CBORDecodeError("non-minimal integer encoding")
        return arg, pos

    def _read_string(
        self, data: bytes, pos: int, n: int, start: int, major: int, arg: int
    ) -> tuple[Any, int]:
        # Check the declared length against remaining input before
        # touching it, so a forged huge length fails cheaply.
        if arg > n - pos:
            raise CBORDecodeError(
                f"declared length {arg} exceeds {n - pos} "
                f"remaining bytes at offset {start}"
            )
        raw = data[pos : pos + arg]
        pos += arg
        if major == 2:
            return raw, pos
        try:
            return raw.decode("utf-8", self._utf8_errors), pos
        except UnicodeDecodeError as e:
            raise CBORDecodeError("invalid UTF-8 in text string") from e

    def _read_indef_string(
        self, data: bytes, pos: int, n: int, start: int, major: int
    ) -> tuple[Any, int]:
        parts: list[bytes] = []
        while True:
            if pos >= n:
                raise CBORDecodeError("unterminated indefinite-length string")
            head = data[pos]
            pos += 1
            if head == 0xFF:
                break
            if head >> 5 != major:
                raise CBORDecodeError("wrong chunk type in indefinite-length string")
            ai = head & 0x1F
            if ai >= 28:
                raise CBORDecodeError(
                    "invalid chunk header in indefinite-length string"
                )
            arg, pos = self._read_arg(data, pos, n, ai)
            if arg > n - pos:
                raise CBORDecodeError("declared chunk length exceeds remaining input")
            parts.append(data[pos : pos + arg])
            pos += arg
        if major == 2:
            return b"".join(parts), pos
        # Each chunk must be well-formed UTF-8 on its own: a split
        # sequence across a chunk boundary is invalid.
        return "".join(self._decode_text(chunk) for chunk in parts), pos

    def _read_simple_or_float(  # noqa: C901
        self, data: bytes, pos: int, n: int, start: int, ai: int
    ) -> tuple[Any, int]:
        if ai < 20:
            return CBORSimpleValue(ai), pos
        if ai < 24:
            # decode_item handles heads 0xF4..0xF7 inline. These only
            # matter if this helper is ever called directly.
            return (False, True, None, undefined)[ai - 20], pos  # pragma: no cover
        if ai == 24:
            if pos >= n:
                raise CBORDecodeError("truncated simple value")
            value = data[pos]
            pos += 1
            if self._canonical and value < 24:
                raise CBORDecodeError("non-minimal simple value encoding")
            if 24 <= value <= 31:
                raise CBORDecodeError("reserved simple value")
            if value == 20:
                return False, pos
            if value == 21:
                return True, pos
            if value == 22:
                return None, pos
            if value == 23:
                return undefined, pos
            return CBORSimpleValue(value), pos
        nbytes = _FLOAT_SIZES[ai]
        if pos + nbytes > n:
            raise CBORDecodeError("truncated float")
        fval = float(_FLOAT_UNPACK[ai].unpack_from(data, pos)[0])
        pos += nbytes
        if self._canonical and float_min_ai(fval) != ai:
            raise CBORDecodeError("float is not in shortest form")
        return fval, pos

    def _open_container(
        self, pos: int, start: int, major: int, arg: int, frames: list[_Frame]
    ) -> tuple[Any, int]:
        # The claimed length only sizes the item budget, so nothing is
        # allocated up front, so forged counts fail at end of input.
        if major == 4:
            if arg == 0:
                return [], pos
            if len(frames) >= self._max_depth:
                raise CBORDecodeError(
                    f"maximum depth {self._max_depth} exceeded at offset {start}"
                )
            frames.append(_Frame(_ARR, arg, start))
        elif major == 5:
            if arg == 0:
                return {}, pos
            if len(frames) >= self._max_depth:
                raise CBORDecodeError(
                    f"maximum depth {self._max_depth} exceeded at offset {start}"
                )
            frames.append(_Frame(_MAP, arg * 2, start))
        else:  # major == 6, tag: arg is the tag number, needs one item
            if len(frames) >= self._max_depth:
                raise CBORDecodeError(
                    f"maximum depth {self._max_depth} exceeded at offset {start}"
                )
            frames.append(_Frame(_TAG, 1, start, arg))
        return _MISSING, pos

    def _decode_text(self, raw: bytes) -> str:
        try:
            return raw.decode("utf-8", self._utf8_errors)
        except UnicodeDecodeError as e:
            raise CBORDecodeError("invalid UTF-8 in text string") from e

    def _finish(self, frame: _Frame) -> Any:
        if frame.kind == _ARR:
            return frame.items
        items = frame.items
        result: dict[Any, Any] = {}
        try:
            if self._duplicate_keys == "error":
                for i in range(0, len(items), 2):
                    key = items[i]
                    if key in result:
                        raise CBORDecodeError(f"duplicate map key {key!r}")
                    result[key] = items[i + 1]
            elif self._duplicate_keys == "first":
                for i in range(0, len(items), 2):
                    result.setdefault(items[i], items[i + 1])
            else:
                for i in range(0, len(items), 2):
                    result[items[i]] = items[i + 1]
        except TypeError as e:
            raise CBORDecodeError("unhashable map key") from e
        return result

    def _apply_tag(self, tag: int, value: Any) -> Any:
        if self._tag_hook is not None:
            return self._tag_hook(self, CBORTag(tag, value))
        if tag == 32:
            # URI: returned as a plain str, since Python has no URI scalar type.
            if not isinstance(value, str):
                raise CBORDecodeError("tag 32 (URI) must wrap a text string")
            return value
        if tag == 55799:
            # Self-described CBOR: pass the enclosed item through.
            return value
        handler = _TAG_DECODERS.get(tag)
        if handler is not None:
            return handler(value)
        return CBORTag(tag, value)


def _decode_datetime(value: Any) -> datetime:
    if not isinstance(value, str):
        raise CBORDecodeError("tag 0 must wrap a text string")
    text = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        return datetime.fromisoformat(text)
    except ValueError as e:
        raise CBORDecodeError(f"malformed tag 0 datetime string {value!r}") from e


def _decode_epoch(value: Any) -> datetime:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise CBORDecodeError("tag 1 must wrap a number")
    try:
        return datetime.fromtimestamp(value, tz=timezone.utc)
    except (OverflowError, OSError, ValueError) as e:
        raise CBORDecodeError(f"tag 1 timestamp {value!r} out of range") from e


def _decode_bignum(value: Any, *, negative: bool) -> int:
    if not isinstance(value, bytes):
        raise CBORDecodeError("bignum tag must wrap a byte string")
    magnitude = int.from_bytes(value, "big")
    return -1 - magnitude if negative else magnitude


def _decode_tag_date(value: Any) -> date:
    if isinstance(value, str):
        try:
            return date.fromisoformat(value)
        except ValueError as e:
            raise CBORDecodeError(f"malformed tag 1004 date string {value!r}") from e
    if isinstance(value, bool) or not isinstance(value, int):
        raise CBORDecodeError("tag 1004 must wrap a text string")
    try:
        return _EPOCH_DATE + timedelta(days=value)
    except OverflowError as e:
        raise CBORDecodeError(f"tag 1004 day count {value} out of range") from e


def _decode_epoch_date(value: Any) -> date:
    if isinstance(value, bool) or not isinstance(value, int):
        raise CBORDecodeError("tag 100 must wrap an integer day count")
    try:
        return _EPOCH_DATE + timedelta(days=value)
    except OverflowError as e:
        raise CBORDecodeError(f"tag 100 day count {value} out of range") from e


_TAG_DECODERS: dict[int, Callable[[Any], Any]] = {
    0: _decode_datetime,
    1: _decode_epoch,
    2: partial(_decode_bignum, negative=False),
    3: partial(_decode_bignum, negative=True),
    100: _decode_epoch_date,
    1004: _decode_tag_date,
}


_DEFAULT_DECODER: "CBORDecoder | None" = None


def loads(
    data: bytes | bytearray | memoryview,
    *,
    tag_hook: TagHook | None = None,
    strict_utf8: bool = True,
    max_depth: int = 200,
    allow_indefinite: bool = True,
    canonical: bool = False,
    duplicate_keys: DuplicateMode = "last",
    allow_trailing: bool = False,
) -> Any:
    """Decode a single CBOR data item from data.

    canonical=True enforces RFC 8949 preferred serialization: non-minimal
    integers, non-shortest floats, indefinite lengths and unsorted map
    keys are rejected. duplicate_keys selects "last" (keep the last
    value), "first" or "error" handling for repeated map keys.
    """
    global _DEFAULT_DECODER
    if (
        tag_hook is None
        and strict_utf8
        and max_depth == 200
        and allow_indefinite
        and not canonical
        and duplicate_keys == "last"
    ):
        # Decoders hold no per-call state, so a shared instance is safe.
        dec = _DEFAULT_DECODER
        if dec is None:
            dec = _DEFAULT_DECODER = CBORDecoder()
    else:
        dec = CBORDecoder(
            tag_hook=tag_hook,
            strict_utf8=strict_utf8,
            max_depth=max_depth,
            allow_indefinite=allow_indefinite,
            canonical=canonical,
            duplicate_keys=duplicate_keys,
        )
    return dec.decode(data, allow_trailing=allow_trailing)


def load(
    fp: BinaryIO,
    *,
    tag_hook: TagHook | None = None,
    strict_utf8: bool = True,
    max_depth: int = 200,
    allow_indefinite: bool = True,
    canonical: bool = False,
    duplicate_keys: DuplicateMode = "last",
) -> Any:
    """Decode one CBOR data item from a binary file-like object.

    The stream is read to end. The first data item is decoded and any
    remaining bytes are ignored, matching single-item stream semantics.
    """
    return loads(
        fp.read(),
        tag_hook=tag_hook,
        strict_utf8=strict_utf8,
        max_depth=max_depth,
        allow_indefinite=allow_indefinite,
        canonical=canonical,
        duplicate_keys=duplicate_keys,
        allow_trailing=True,
    )
