#if defined(__aarch32__) || defined(__aarch64__) // ArmV8 CRC32 acceleration

// Copyright 2017 The CRC32C Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file. See the AUTHORS file for names of contributors.


// In a separate source file to allow this accelerated CRC32C function to be
// compiled with the appropriate compiler flags to enable ARM NEON CRC32C
// instructions.

// This implementation is based on https://github.com/google/leveldb/pull/490.

#include <cstddef>
#include <cstdint>

#include <arm_acle.h>
#include <arm_neon.h>

#define KBYTES 1032
#define SEGMENTBYTES 256

// compute 8bytes for each segment parallelly
#define CRC32C32BYTES(P, IND)                                             \
  do {                                                                    \
    crc1 = __crc32cd(                                                     \
        crc1, *((const uint64_t *)(P) + (SEGMENTBYTES / 8) * 1 + (IND))); \
    crc2 = __crc32cd(                                                     \
        crc2, *((const uint64_t *)(P) + (SEGMENTBYTES / 8) * 2 + (IND))); \
    crc3 = __crc32cd(                                                     \
        crc3, *((const uint64_t *)(P) + (SEGMENTBYTES / 8) * 3 + (IND))); \
    crc0 = __crc32cd(                                                     \
        crc0, *((const uint64_t *)(P) + (SEGMENTBYTES / 8) * 0 + (IND))); \
  } while (0);

// compute 8*8 bytes for each segment parallelly
#define CRC32C256BYTES(P, IND)      \
  do {                              \
    CRC32C32BYTES((P), (IND)*8 + 0) \
    CRC32C32BYTES((P), (IND)*8 + 1) \
    CRC32C32BYTES((P), (IND)*8 + 2) \
    CRC32C32BYTES((P), (IND)*8 + 3) \
    CRC32C32BYTES((P), (IND)*8 + 4) \
    CRC32C32BYTES((P), (IND)*8 + 5) \
    CRC32C32BYTES((P), (IND)*8 + 6) \
    CRC32C32BYTES((P), (IND)*8 + 7) \
  } while (0);

// compute 4*8*8 bytes for each segment parallelly
#define CRC32C1024BYTES(P)   \
  do {                       \
    CRC32C256BYTES((P), 0)   \
    CRC32C256BYTES((P), 1)   \
    CRC32C256BYTES((P), 2)   \
    CRC32C256BYTES((P), 3)   \
    (P) += 4 * SEGMENTBYTES; \
  } while (0)

namespace leveldb {
namespace port {
uint32_t AcceleratedCRC32C(uint32_t crc, const char* buf, size_t length)
{
  //int64_t length = size;
  uint32_t crc0, crc1, crc2, crc3;
  uint64_t t0, t1, t2;

  // k0=CRC(x^(3*SEGMENTBYTES*8)), k1=CRC(x^(2*SEGMENTBYTES*8)),
  // k2=CRC(x^(SEGMENTBYTES*8))
  const poly64_t k0 = 0x8d96551c, k1 = 0xbd6f81f8, k2 = 0xdcb17aa4;
  static constexpr const uint32_t kCRC32Xor = static_cast<uint32_t>(0xffffffffU);

  crc = crc ^ kCRC32Xor;
  const uint8_t *p = reinterpret_cast<const uint8_t *>(buf);

  while (length >= KBYTES) {
    crc0 = crc;
    crc1 = 0;
    crc2 = 0;
    crc3 = 0;

    // Process 1024 bytes in parallel.
    CRC32C1024BYTES(p);

    // Merge the 4 partial CRC32C values.
    t2 = (uint64_t)vmull_p64(crc2, k2);
    t1 = (uint64_t)vmull_p64(crc1, k1);
    t0 = (uint64_t)vmull_p64(crc0, k0);
    crc = __crc32cd(crc3, *(uint64_t *)p);
    p += sizeof(uint64_t);
    crc ^= __crc32cd(0, t2);
    crc ^= __crc32cd(0, t1);
    crc ^= __crc32cd(0, t0);

    length -= KBYTES;
  }

  while (length >= 8) {
    crc = __crc32cd(crc, *(uint64_t *)p);
    p += 8;
    length -= 8;
  }

  if (length & 4) {
    crc = __crc32cw(crc, *(uint32_t *)p);
    p += 4;
  }

  if (length & 2) {
    crc = __crc32ch(crc, *(uint16_t *)p);
    p += 2;
  }

  if (length & 1) {
    crc = __crc32cb(crc, *p);
  }

  return crc ^ kCRC32Xor;
}

}  // namespace port
}  // namespace leveldb

#else // Default Intel SSE implementation

// Copyright 2016 The LevelDB Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file. See the AUTHORS file for names of contributors.
//
// A portable implementation of crc32c, optimized to handle
// four bytes at a time.
//
// In a separate source file to allow this accelerated CRC32C function to be
// compiled with the appropriate compiler flags to enable x86 SSE 4.2
// instructions.

#include <stdint.h>
#include <string.h>
#include "port/port.h"

#if defined(LEVELDB_PLATFORM_POSIX_SSE)

#if defined(_MSC_VER)
#include <intrin.h>
#elif defined(__GNUC__) && defined(__SSE4_2__)
#include <nmmintrin.h>
#endif

#endif  // defined(LEVELDB_PLATFORM_POSIX_SSE)

namespace leveldb {
namespace port {

#if defined(LEVELDB_PLATFORM_POSIX_SSE)

// Used to fetch a naturally-aligned 32-bit word in little endian byte-order
static inline uint32_t LE_LOAD32(const uint8_t *p) {
  // SSE is x86 only, so ensured that |p| is always little-endian.
  uint32_t word;
  memcpy(&word, p, sizeof(word));
  return word;
}

#if defined(_M_X64) || defined(__x86_64__)  // LE_LOAD64 is only used on x64.

// Used to fetch a naturally-aligned 64-bit word in little endian byte-order
static inline uint64_t LE_LOAD64(const uint8_t *p) {
  uint64_t dword;
  memcpy(&dword, p, sizeof(dword));
  return dword;
}

#endif  // defined(_M_X64) || defined(__x86_64__)

#endif  // defined(LEVELDB_PLATFORM_POSIX_SSE)

// For further improvements see Intel publication at:
// http://download.intel.com/design/intarch/papers/323405.pdf
uint32_t AcceleratedCRC32C(uint32_t crc, const char* buf, size_t size) {
#if !defined(LEVELDB_PLATFORM_POSIX_SSE)
  return 0;
#else

  const uint8_t *p = reinterpret_cast<const uint8_t *>(buf);
  const uint8_t *e = p + size;
  uint32_t l = crc ^ 0xffffffffu;

#define STEP1 do {                              \
    l = _mm_crc32_u8(l, *p++);                  \
} while (0)
#define STEP4 do {                              \
    l = _mm_crc32_u32(l, LE_LOAD32(p));         \
    p += 4;                                     \
} while (0)
#define STEP8 do {                              \
    l = _mm_crc32_u64(l, LE_LOAD64(p));         \
    p += 8;                                     \
} while (0)

  if (size > 16) {
    // Process unaligned bytes
    for (unsigned int i = reinterpret_cast<uintptr_t>(p) % 8; i; --i) {
      STEP1;
    }

    // _mm_crc32_u64 is only available on x64.
#if defined(_M_X64) || defined(__x86_64__)
    // Process 8 bytes at a time
    while ((e-p) >= 8) {
      STEP8;
    }
    // Process 4 bytes at a time
    if ((e-p) >= 4) {
      STEP4;
    }
#else  // !(defined(_M_X64) || defined(__x86_64__))
    // Process 4 bytes at a time
    while ((e-p) >= 4) {
      STEP4;
    }
#endif  // defined(_M_X64) || defined(__x86_64__)
  }
  // Process the last few bytes
  while (p != e) {
    STEP1;
  }
#undef STEP8
#undef STEP4
#undef STEP1
  return l ^ 0xffffffffu;
#endif  // defined(LEVELDB_PLATFORM_POSIX_SSE)
}

}  // namespace port
}  // namespace leveldb

#endif // defined(__aarch32__) || defined(__aarch64__)
