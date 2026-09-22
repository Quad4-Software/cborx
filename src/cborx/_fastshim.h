/* SPDX-License-Identifier: 0BSD */
/* PyFloat_Pack/Unpack became public API in CPython 3.11. On earlier
   versions libpython exports them only under the internal _Py names.
   The declarations below mirror pycore_floatobject.h so they are
   legal whether or not that header was already included. */
#ifndef CBORX_FASTSHIM_H
#define CBORX_FASTSHIM_H
#include <Python.h>
#if PY_VERSION_HEX < 0x030B0000
int _PyFloat_Pack2(double x, unsigned char *p, int le);
int _PyFloat_Pack4(double x, unsigned char *p, int le);
int _PyFloat_Pack8(double x, unsigned char *p, int le);
double _PyFloat_Unpack2(const unsigned char *p, int le);
double _PyFloat_Unpack4(const unsigned char *p, int le);
double _PyFloat_Unpack8(const unsigned char *p, int le);
#define PyFloat_Pack2(x, p, le) _PyFloat_Pack2((x), (unsigned char *)(p), (le))
#define PyFloat_Pack4(x, p, le) _PyFloat_Pack4((x), (unsigned char *)(p), (le))
#define PyFloat_Pack8(x, p, le) _PyFloat_Pack8((x), (unsigned char *)(p), (le))
#define PyFloat_Unpack2(p, le) _PyFloat_Unpack2((const unsigned char *)(p), (le))
#define PyFloat_Unpack4(p, le) _PyFloat_Unpack4((const unsigned char *)(p), (le))
#define PyFloat_Unpack8(p, le) _PyFloat_Unpack8((const unsigned char *)(p), (le))
#endif
#endif
