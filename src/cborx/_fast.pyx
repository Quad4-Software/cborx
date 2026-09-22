# SPDX-License-Identifier: 0BSD
# cython: language_level=3, boundscheck=False, wraparound=False
"""Optional compiled fast paths for the CBOR codec.

The pure-Python encoder and decoder remain the reference
implementation. This accelerator handles the hot scalar and container
paths at C level and delegates tags, dates, default callbacks and
indefinite-length strings back to the Python classes, so every option
keeps identical semantics.
"""

from cpython.bytearray cimport PyByteArray_AS_STRING, PyByteArray_GET_SIZE
from cpython.bytes cimport (
    PyBytes_AS_STRING,
    PyBytes_CheckExact,
    PyBytes_FromStringAndSize,
    PyBytes_GET_SIZE,
)
from cpython.dict cimport (
    PyDict_CheckExact,
    PyDict_New,
    PyDict_Next,
    PyDict_Size,
)
from cpython.float cimport PyFloat_AS_DOUBLE, PyFloat_CheckExact, PyFloat_FromDouble
from cpython.list cimport (
    PyList_Append,
    PyList_CheckExact,
    PyList_GET_ITEM,
    PyList_GET_SIZE,
    PyList_New,
)
from cpython.long cimport (
    PyLong_AsLongLongAndOverflow,
    PyLong_CheckExact,
    PyLong_FromLongLong,
    PyLong_FromUnsignedLongLong,
)
from cpython.mem cimport PyMem_Free, PyMem_Realloc
from cpython.ref cimport PyObject
from cpython.tuple cimport PyTuple_CheckExact, PyTuple_GET_ITEM, PyTuple_GET_SIZE
from cpython.unicode cimport (
    PyUnicode_AsUTF8AndSize,
    PyUnicode_CheckExact,
    PyUnicode_DecodeUTF8,
)
from libc.math cimport isinf, isnan
from libc.stdint cimport uint64_t
from libc.string cimport memcpy

# PyFloat_Pack/Unpack only became public API in 3.11. On 3.10
# libpython exports them under the internal _Py names, which the
# local shim header aliases.
cdef extern from "_fastshim.h":
    int PyFloat_Pack2(double x, char *p, int le)
    int PyFloat_Pack4(double x, char *p, int le)
    int PyFloat_Pack8(double x, char *p, int le)
    double PyFloat_Unpack2(const char *p, int le)
    double PyFloat_Unpack4(const char *p, int le)
    double PyFloat_Unpack8(const char *p, int le)

from cborx._util import float_min_ai
from cborx.exceptions import CBORDecodeError, CBOREncodeError
from cborx.types import CBORSimpleValue, undefined

cdef int _CANON = 1
cdef int _INDEF = 2
cdef int _DEPTH_CAP = 4000  # beyond this, encode recurses in Python
cdef object _MISSING = object()


cdef class _Arena:
    cdef char *buf
    cdef Py_ssize_t used
    cdef Py_ssize_t cap

    def __cinit__(self):
        self.buf = NULL
        self.used = 0
        self.cap = 0

    def __dealloc__(self):
        PyMem_Free(self.buf)

    cdef int reserve(self, Py_ssize_t extra) except -1:
        cdef Py_ssize_t cap
        cdef char *p
        if self.used + extra > self.cap:
            cap = self.cap * 2 if self.cap else 512
            if cap < self.used + extra:
                cap = self.used + extra
            p = <char *>PyMem_Realloc(self.buf, <size_t>cap)
            if p == NULL:
                raise MemoryError()
            self.buf = p
            self.cap = cap
        return 0

    cdef int byte(self, unsigned char b) except -1:
        if self.used >= self.cap:
            self.reserve(1)
        self.buf[self.used] = <char>b
        self.used += 1
        return 0

    cdef int write(self, const char *src, Py_ssize_t n) except -1:
        if n > 0:
            self.reserve(n)
            memcpy(self.buf + self.used, src, <size_t>n)
            self.used += n
        return 0


cdef int _head(_Arena a, unsigned int major, uint64_t arg) except -1:
    cdef unsigned char base = <unsigned char>(major << 5)
    if arg < 24:
        return a.byte(base | <unsigned char>arg)
    if arg <= 0xFF:
        a.byte(base | 24)
        return a.byte(<unsigned char>arg)
    if arg <= 0xFFFF:
        a.byte(base | 25)
        a.byte(<unsigned char>(arg >> 8))
        return a.byte(<unsigned char>arg)
    if arg <= 0xFFFFFFFF:
        a.byte(base | 26)
        a.byte(<unsigned char>(arg >> 24))
        a.byte(<unsigned char>(arg >> 16))
        a.byte(<unsigned char>(arg >> 8))
        return a.byte(<unsigned char>arg)
    a.byte(base | 27)
    a.byte(<unsigned char>(arg >> 56))
    a.byte(<unsigned char>(arg >> 48))
    a.byte(<unsigned char>(arg >> 40))
    a.byte(<unsigned char>(arg >> 32))
    a.byte(<unsigned char>(arg >> 24))
    a.byte(<unsigned char>(arg >> 16))
    a.byte(<unsigned char>(arg >> 8))
    return a.byte(<unsigned char>arg)


cdef int _delegate(object enc, object obj, _Arena a, int depth) except -1:
    """Encode an uncommon object through the Python code path."""
    cdef object tmp = bytearray()
    enc._write_item(obj, tmp, depth)
    return a.write(PyByteArray_AS_STRING(tmp), PyByteArray_GET_SIZE(tmp))


cdef int _write(object enc, object obj, _Arena a, int depth,
                int max_depth, int flags) except -1:  # noqa: C901
    cdef Py_ssize_t n, i, ppos, dsize, mark
    cdef long long ll
    cdef int overflow = 0
    cdef int ai
    cdef double d
    cdef const char *s
    cdef char fbuf[8]
    cdef object tmp, item, pairs, pair
    cdef PyObject *k
    cdef PyObject *v

    if depth > max_depth:
        raise CBOREncodeError("maximum container depth exceeded")
    if depth > _DEPTH_CAP:
        # Beyond this point C recursion could exhaust the call stack,
        # so the deep tail runs through the Python path which maps
        # RecursionError to CBOREncodeError.
        return _delegate(enc, obj, a, depth)

    if PyLong_CheckExact(obj):
        ll = PyLong_AsLongLongAndOverflow(obj, &overflow)
        if overflow == 0:
            if ll >= 0:
                if ll < 24:
                    return a.byte(<unsigned char>ll)
                return _head(a, 0, <uint64_t>ll)
            if ll >= -24:
                return a.byte(<unsigned char>(0x20 | (-1 - ll)))
            return _head(a, 1, <uint64_t>(-(ll + 1)))
        # Out of int64 range: the Python path emits a bignum tag.
        return _delegate(enc, obj, a, depth)

    if PyUnicode_CheckExact(obj):
        try:
            s = PyUnicode_AsUTF8AndSize(obj, &n)
        except UnicodeEncodeError as e:
            raise CBOREncodeError(
                "text string contains lone surrogates") from e
        if flags & _INDEF:
            a.byte(0x7F)
            _head(a, 3, <uint64_t>n)
            a.write(s, n)
            return a.byte(0xFF)
        if n < 24:
            a.byte(0x60 | <unsigned char>n)
        else:
            _head(a, 3, <uint64_t>n)
        return a.write(s, n)

    if PyFloat_CheckExact(obj):
        d = PyFloat_AS_DOUBLE(obj)
        # NaN always uses the preferred form 0xf97e00. Non-canonical
        # mode uses float64 except for infinity, which uses float16.
        if isnan(d):
            a.byte(0xF9)
            a.byte(0x7E)
            return a.byte(0x00)
        if flags & _CANON:
            ai = float_min_ai(d)
        elif isinf(d):
            ai = 25
        else:
            ai = 27
        if ai == 25:
            a.byte(0xF9)
            if PyFloat_Pack2(d, fbuf, 0) < 0:
                return _delegate(enc, obj, a, depth)
            return a.write(fbuf, 2)
        if ai == 26:
            a.byte(0xFA)
            if PyFloat_Pack4(d, fbuf, 0) < 0:
                return _delegate(enc, obj, a, depth)
            return a.write(fbuf, 4)
        a.byte(0xFB)
        PyFloat_Pack8(d, fbuf, 0)
        return a.write(fbuf, 8)

    if PyBytes_CheckExact(obj):
        n = PyBytes_GET_SIZE(obj)
        s = PyBytes_AS_STRING(obj)
        if flags & _INDEF:
            a.byte(0x5F)
            _head(a, 2, <uint64_t>n)
            a.write(s, n)
            return a.byte(0xFF)
        if n < 24:
            a.byte(0x40 | <unsigned char>n)
        else:
            _head(a, 2, <uint64_t>n)
        return a.write(s, n)

    if obj is True:
        return a.byte(0xF5)
    if obj is False:
        return a.byte(0xF4)
    if obj is None:
        return a.byte(0xF6)

    if PyList_CheckExact(obj) or PyTuple_CheckExact(obj):
        n = (PyList_GET_SIZE(obj) if PyList_CheckExact(obj)
             else PyTuple_GET_SIZE(obj))
        if flags & _INDEF:
            a.byte(0x9F)
            for i in range(n):
                item = <object>(PyList_GET_ITEM(obj, i)
                                if PyList_CheckExact(obj)
                                else PyTuple_GET_ITEM(obj, i))
                _write(enc, item, a, depth + 1, max_depth, flags)
            return a.byte(0xFF)
        if n < 24:
            a.byte(0x80 | <unsigned char>n)
        else:
            _head(a, 4, <uint64_t>n)
        for i in range(n):
            item = <object>(PyList_GET_ITEM(obj, i)
                            if PyList_CheckExact(obj)
                            else PyTuple_GET_ITEM(obj, i))
            _write(enc, item, a, depth + 1, max_depth, flags)
        return 0

    if PyDict_CheckExact(obj):
        dsize = PyDict_Size(obj)
        if dsize < 0:
            return -1
        if flags & _INDEF:
            a.byte(0xBF)
        elif flags & _CANON:
            if dsize < 24:
                a.byte(0xA0 | <unsigned char>dsize)
            else:
                _head(a, 5, <uint64_t>dsize)
        elif dsize < 24:
            a.byte(0xA0 | <unsigned char>dsize)
        else:
            _head(a, 5, <uint64_t>dsize)
        if flags & _CANON:
            # Encode each key into the arena, slice it out, then emit
            # pairs in (length, bytes) order.
            pairs = []
            ppos = 0
            while PyDict_Next(obj, &ppos, &k, &v):
                if PyDict_Size(obj) != dsize:
                    raise RuntimeError("dictionary changed size during iteration")
                item = <object>k
                tmp = <object>v
                mark = a.used
                _write(enc, item, a, depth + 1, max_depth, flags)
                pairs.append((a.used - mark,
                              PyBytes_FromStringAndSize(a.buf + mark,
                                                        a.used - mark),
                              tmp))
                a.used = mark
            pairs.sort()
            for pair in pairs:
                a.write(PyBytes_AS_STRING(pair[1]), PyBytes_GET_SIZE(pair[1]))
                _write(enc, pair[2], a, depth + 1, max_depth, flags)
            return 0
        ppos = 0
        while PyDict_Next(obj, &ppos, &k, &v):
            if PyDict_Size(obj) != dsize:
                raise RuntimeError("dictionary changed size during iteration")
            item = <object>k
            tmp = <object>v
            _write(enc, item, a, depth + 1, max_depth, flags)
            _write(enc, tmp, a, depth + 1, max_depth, flags)
        if flags & _INDEF:
            return a.byte(0xFF)
        return 0

    # Tags, simple values, undefined, dates, subclasses and unknown
    # types all take the Python path, including the default callback.
    return _delegate(enc, obj, a, depth)


def encode(object enc, object obj):
    """Encode obj and return the bytes.

    enc is a CBOREncoder supplying the options and the Python fallback
    for uncommon objects.
    """
    cdef _Arena a = _Arena()
    cdef int flags = 0
    cdef int max_depth = (enc._max_depth if enc._max_depth < 2147483647
                          else 2147483647)
    if enc._canonical:
        flags |= _CANON
    if enc._indefinite:
        flags |= _INDEF
    _write(enc, obj, a, 0, max_depth, flags)
    return PyBytes_FromStringAndSize(a.buf, a.used)


cdef class _FFrame:
    """One open container or tag on the decode work stack."""

    cdef int kind  # 0 array, 1 map, 2 tag
    cdef long long remaining  # -1 means indefinite length
    cdef Py_ssize_t start
    cdef uint64_t tag
    cdef list items
    cdef object prev_key
    cdef _FFrame parent

    def __cinit__(self, int kind, long long remaining, Py_ssize_t start,
                  uint64_t tag=0, parent=None):
        self.kind = kind
        self.remaining = remaining
        self.start = start
        self.tag = tag
        self.items = []
        self.prev_key = None
        self.parent = parent


cdef object _finish(_FFrame f, int dupmode):
    cdef list items = f.items
    cdef Py_ssize_t i, m = PyList_GET_SIZE(items)
    cdef object result, key
    if f.kind == 0:
        return items
    result = PyDict_New()
    try:
        if dupmode == 2:
            for i in range(0, m, 2):
                key = items[i]
                if key in result:
                    raise CBORDecodeError(f"duplicate map key {key!r}")
                result[key] = items[i + 1]
        elif dupmode == 1:
            for i in range(0, m, 2):
                result.setdefault(items[i], items[i + 1])
        else:
            for i in range(0, m, 2):
                result[items[i]] = items[i + 1]
    except TypeError as e:
        raise CBORDecodeError("unhashable map key") from e
    return result


def decode_item(object dec, object data, Py_ssize_t pos):  # noqa: C901
    """Decode one item from data at pos and return (value, new pos).

    dec is a CBORDecoder supplying the options and the Python helpers
    for tags and indefinite-length strings.
    """
    cdef const unsigned char *b
    cdef Py_ssize_t n, start, i, m
    cdef unsigned int head, major, ai
    cdef uint64_t arg
    cdef int canonical, allow_indef, max_depth, dupmode
    cdef object value, key, prev
    cdef _FFrame frame, top
    cdef int depth
    cdef double d
    cdef object apply_tag = None
    cdef object read_indef = None
    cdef const char *errstr
    cdef tuple cfg = dec._cfg

    if cfg[4]:
        errstr = "strict"
    else:
        errstr = "replace"
    if not PyBytes_CheckExact(data):
        data = bytes(data)
    b = <const unsigned char *>PyBytes_AS_STRING(data)
    n = PyBytes_GET_SIZE(data)
    canonical = 1 if cfg[0] else 0
    allow_indef = 1 if cfg[1] else 0
    max_depth = cfg[2]
    dupmode = cfg[3]
    if pos < 0:
        raise CBORDecodeError("unexpected end of input")

    depth = 0
    frame = None
    value = _MISSING
    start = pos
    while True:
        if value is _MISSING:
            start = pos
            if pos >= n:
                raise CBORDecodeError("unexpected end of input")
            head = b[pos]
            pos += 1
            major = head >> 5
            ai = head & 0x1F
            if ai == 0x1F:
                # Indefinite-length forms and the break byte.
                if major == 7:
                    if frame is not None and frame.remaining == -1:
                        top = frame
                        frame = top.parent
                        depth -= 1
                        if top.kind == 1 and PyList_GET_SIZE(top.items) % 2:
                            raise CBORDecodeError(
                                "indefinite-length map has an odd item count")
                        value = _finish(top, dupmode)
                        start = top.start
                    else:
                        raise CBORDecodeError(
                            "break byte outside indefinite-length item "
                            f"at offset {start}")
                elif major in (0, 1, 6):
                    raise CBORDecodeError(
                        f"indefinite length not allowed for major type "
                        f"{major} at offset {start}")
                elif not allow_indef:
                    raise CBORDecodeError(
                        f"indefinite-length item not permitted "
                        f"at offset {start}")
                elif canonical:
                    raise CBORDecodeError(
                        f"indefinite-length item is not canonical "
                        f"at offset {start}")
                elif major in (2, 3):
                    if read_indef is None:
                        read_indef = dec._read_indef_string
                    value, pos = read_indef(data, pos, n, start, major)
                else:
                    if depth >= max_depth:
                        raise CBORDecodeError(
                            f"maximum depth {max_depth} exceeded "
                            f"at offset {start}")
                    frame = _FFrame(0 if major == 4 else 1, -1, start,
                                    parent=frame)
                    depth += 1
                    continue
            elif ai > 0x1B:
                raise CBORDecodeError(
                    f"reserved additional information {ai} "
                    f"at offset {start}")
            elif major == 7:
                if ai < 20:
                    value = CBORSimpleValue(ai)
                elif ai == 20:
                    value = False
                elif ai == 21:
                    value = True
                elif ai == 22:
                    value = None
                elif ai == 23:
                    value = undefined
                elif ai == 24:
                    if pos >= n:
                        raise CBORDecodeError("truncated simple value")
                    arg = b[pos]
                    pos += 1
                    if canonical and arg < 24:
                        raise CBORDecodeError(
                            "non-minimal simple value encoding")
                    if 24 <= arg <= 31:
                        raise CBORDecodeError("reserved simple value")
                    if arg == 20:
                        value = False
                    elif arg == 21:
                        value = True
                    elif arg == 22:
                        value = None
                    elif arg == 23:
                        value = undefined
                    else:
                        value = CBORSimpleValue(arg)
                else:
                    m = 2 if ai == 25 else (4 if ai == 26 else 8)
                    if pos + m > n:
                        raise CBORDecodeError("truncated float")
                    if ai == 25:
                        d = PyFloat_Unpack2(<const char *>b + pos, 0)
                    elif ai == 26:
                        d = PyFloat_Unpack4(<const char *>b + pos, 0)
                    else:
                        d = PyFloat_Unpack8(<const char *>b + pos, 0)
                    pos += m
                    if canonical and float_min_ai(d) != ai:
                        raise CBORDecodeError(
                            "float is not in shortest form")
                    value = PyFloat_FromDouble(d)
            else:
                # Definite-length item with an integer argument.
                if ai < 24:
                    arg = ai
                else:
                    m = 1 << (ai - 24)
                    if pos + m > n:
                        raise CBORDecodeError("truncated integer argument")
                    arg = 0
                    for i in range(m):
                        arg = (arg << 8) | b[pos + i]
                    pos += m
                    if canonical and arg < _min_arg(m):
                        raise CBORDecodeError("non-minimal integer encoding")
                if major == 0:
                    value = PyLong_FromUnsignedLongLong(arg)
                elif major == 1:
                    if arg <= 0x7FFFFFFFFFFFFFFF:
                        value = PyLong_FromLongLong(-1 - <long long>arg)
                    else:
                        value = -1 - PyLong_FromUnsignedLongLong(arg)
                elif major == 2:
                    if arg > <uint64_t>(n - pos):
                        raise CBORDecodeError(
                            f"declared length {arg} exceeds {n - pos} "
                            f"remaining bytes at offset {start}")
                    value = PyBytes_FromStringAndSize(
                        <const char *>b + pos, <Py_ssize_t>arg)
                    pos += <Py_ssize_t>arg
                elif major == 3:
                    if arg > <uint64_t>(n - pos):
                        raise CBORDecodeError(
                            f"declared length {arg} exceeds {n - pos} "
                            f"remaining bytes at offset {start}")
                    try:
                        value = PyUnicode_DecodeUTF8(
                            <const char *>b + pos, <Py_ssize_t>arg, errstr)
                    except UnicodeDecodeError as e:
                        raise CBORDecodeError(
                            "invalid UTF-8 in text string") from e
                    pos += <Py_ssize_t>arg
                elif major == 4:
                    if arg == 0:
                        value = []
                    elif depth >= max_depth:
                        raise CBORDecodeError(
                            f"maximum depth {max_depth} exceeded "
                            f"at offset {start}")
                    else:
                        # Each item needs at least one byte, so a count
                        # beyond the input left can never complete.
                        # Clamp instead of storing arg raw: 2**63 and
                        # up would wrap long long into the indefinite
                        # sentinel. Clamped to n - pos + 1 the counter
                        # can never reach zero and decoding fails at
                        # the same offset as the pure path.
                        if arg > <uint64_t>(n - pos):
                            arg = <uint64_t>(n - pos) + 1
                        frame = _FFrame(0, <long long>arg, start,
                                        parent=frame)
                        depth += 1
                        continue
                elif major == 5:
                    if arg == 0:
                        value = {}
                    elif depth >= max_depth:
                        raise CBORDecodeError(
                            f"maximum depth {max_depth} exceeded "
                            f"at offset {start}")
                    else:
                        # Pairs need at least two bytes. Clamping the
                        # doubled item count keeps arg * 2 inside long
                        # long while still never reaching zero.
                        if arg > <uint64_t>(n - pos) // 2:
                            arg = (<uint64_t>(n - pos) // 2) + 1
                        frame = _FFrame(1, <long long>(arg * 2), start,
                                        parent=frame)
                        depth += 1
                        continue
                else:
                    if depth >= max_depth:
                        raise CBORDecodeError(
                            f"maximum depth {max_depth} exceeded "
                            f"at offset {start}")
                    frame = _FFrame(2, 1, start, arg, parent=frame)
                    depth += 1
                    continue
        while value is not _MISSING:
            if frame is None:
                return value, pos
            if frame.kind == 2:
                top = frame
                frame = top.parent
                depth -= 1
                if apply_tag is None:
                    apply_tag = dec._apply_tag
                value = apply_tag(top.tag, value)
                start = top.start
                continue
            if canonical and frame.kind == 1 and not len(frame.items) % 2:
                key = data[start:pos]
                prev = frame.prev_key
                if prev is not None and (len(key), key) <= (len(prev), prev):
                    raise CBORDecodeError("map keys are not in canonical order")
                frame.prev_key = key
            PyList_Append(frame.items, value)
            if frame.remaining > 0:
                frame.remaining -= 1
            if frame.remaining == 0:
                top = frame
                frame = top.parent
                depth -= 1
                value = _finish(top, dupmode)
                start = top.start
                continue
            value = _MISSING


cdef inline uint64_t _min_arg(Py_ssize_t nbytes):
    if nbytes == 1:
        return 24
    if nbytes == 2:
        return 0x100
    if nbytes == 4:
        return 0x10000
    return 0x100000000
