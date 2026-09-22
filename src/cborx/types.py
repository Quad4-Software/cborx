# SPDX-License-Identifier: 0BSD
"""Public value types for the CBOR codec."""

from typing import Any


class CBORTag:
    """A CBOR semantic tag (major type 6) wrapping a value.

    Tags without built-in handling decode to CBORTag. Encoding a CBORTag
    writes the tag header followed by the encoded value. Instances are
    immutable.
    """

    __slots__ = ("tag", "value")

    tag: int
    value: Any

    def __init__(self, tag: int, value: Any) -> None:
        object.__setattr__(self, "tag", tag)
        object.__setattr__(self, "value", value)

    def __setattr__(self, name: str, value: Any) -> None:
        raise AttributeError(f"{type(self).__name__} is immutable")

    def __delattr__(self, name: str) -> None:
        raise AttributeError(f"{type(self).__name__} is immutable")

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, CBORTag):
            return NotImplemented
        return self.tag == other.tag and self.value == other.value

    def __hash__(self) -> int:
        return hash((self.tag, self.value))

    def __repr__(self) -> str:
        return f"CBORTag(tag={self.tag!r}, value={self.value!r})"

    def __getstate__(self) -> tuple[int, Any]:
        return self.tag, self.value

    def __setstate__(self, state: tuple[int, Any]) -> None:
        object.__setattr__(self, "tag", state[0])
        object.__setattr__(self, "value", state[1])


class CBORSimpleValue:
    """An unassigned CBOR simple value (major type 7).

    Values 20, 21, 22 and 23 are the named simple values false, true, null
    and undefined and are never wrapped: decoding yields False, True, None
    and undefined instead. Values 24 through 31 are reserved by RFC 8949
    and are rejected by the encoder. Instances are immutable.
    """

    __slots__ = ("value",)

    value: int

    def __init__(self, value: int) -> None:
        object.__setattr__(self, "value", value)

    def __setattr__(self, name: str, value: Any) -> None:
        raise AttributeError(f"{type(self).__name__} is immutable")

    def __delattr__(self, name: str) -> None:
        raise AttributeError(f"{type(self).__name__} is immutable")

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, CBORSimpleValue):
            return NotImplemented
        return self.value == other.value

    def __hash__(self) -> int:
        return hash(self.value)

    def __repr__(self) -> str:
        return f"CBORSimpleValue(value={self.value!r})"

    def __getstate__(self) -> int:
        return self.value

    def __setstate__(self, state: int) -> None:
        object.__setattr__(self, "value", state)


class UndefinedType:
    """Type of the undefined sentinel."""

    __slots__ = ()

    def __repr__(self) -> str:
        return "undefined"

    def __bool__(self) -> bool:
        return False

    def __eq__(self, other: object) -> bool:
        return isinstance(other, UndefinedType)

    def __hash__(self) -> int:
        return hash(UndefinedType)

    def __copy__(self) -> "UndefinedType":
        return self

    def __deepcopy__(self, memo: dict[int, Any]) -> "UndefinedType":
        return self


undefined = UndefinedType()
"""Sentinel for the CBOR simple value undefined (0xf7)."""
