#ifndef aegis256x4_avx512vl_H
#define aegis256x4_avx512vl_H

#include "../common/common.h"
#include "implementations.h"

#ifdef HAVE_VAESINTRIN_H
extern struct aegis256x4_implementation aegis256x4_avx512vl_implementation;
#endif

#endif