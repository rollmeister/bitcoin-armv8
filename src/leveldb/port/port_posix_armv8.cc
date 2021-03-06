/* Based on https://github.com/ceph/ceph/blob/master/src/common/crc32c_aarch64.c */

// Copyright 2017 The CRC32C Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file. See the AUTHORS file for names of contributors.


// In a separate source file to allow this accelerated CRC32C function to be
// compiled with the appropriate compiler flags to enable ARM NEON CRC32C
// instructions.

// This implementation is based on https://github.com/google/leveldb/pull/490.

#include <cstddef>
#include <cstdint>
#include <stdio.h>

#include <arm_acle.h>
#include <arm_neon.h>

#define KBYTES 1032
#define SEGMENTBYTES 256

#define PREF4X64L1(PREF_OFFSET, ITR) \
	__asm__("PRFM PLDL1KEEP, [%x[v],%[c]]"::[v]"r"(buf), [c]"I"((PREF_OFFSET) + ((ITR) + 0)*64));\
	__asm__("PRFM PLDL1KEEP, [%x[v],%[c]]"::[v]"r"(buf), [c]"I"((PREF_OFFSET) + ((ITR) + 1)*64));\
	__asm__("PRFM PLDL1KEEP, [%x[v],%[c]]"::[v]"r"(buf), [c]"I"((PREF_OFFSET) + ((ITR) + 2)*64));\
	__asm__("PRFM PLDL1KEEP, [%x[v],%[c]]"::[v]"r"(buf), [c]"I"((PREF_OFFSET) + ((ITR) + 3)*64));

#define PREF1KL1(PREF_OFFSET) \
	PREF4X64L1((PREF_OFFSET), 0) \
	PREF4X64L1((PREF_OFFSET), 4) \
	PREF4X64L1((PREF_OFFSET), 8) \
	PREF4X64L1((PREF_OFFSET), 12)

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
#if !defined(__aarch64__) && !defined(__aarch32__)
  return 0;
#endif

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
    PREF1KL1(1024);

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
