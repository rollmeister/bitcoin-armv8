// Copyright (c) 2014-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <crypto/sha256.h>
#include <crypto/common.h>


#if defined(__aarch32__) || defined(__aarch64__)
#include <arm_neon.h>
#endif

#include <assert.h>
#include <string.h>
#include <atomic>

#if defined(__x86_64__) || defined(__amd64__) || defined(__i386__)
#if defined(USE_ASM)
#include <cpuid.h>
namespace sha256_sse4
{
void Transform(uint32_t* s, const unsigned char* chunk, size_t blocks);
}
#endif
#endif

namespace sha256d64_sse41
{
void Transform_4way(unsigned char* out, const unsigned char* in);
}

namespace sha256d64_avx2
{
void Transform_8way(unsigned char* out, const unsigned char* in);
}

namespace sha256d64_shani
{
void Transform_2way(unsigned char* out, const unsigned char* in);
}

namespace sha256_shani
{
void Transform(uint32_t* s, const unsigned char* chunk, size_t blocks);
}

#if defined(__aarch32__) || defined(__aarch64__)
namespace sha256_armv8 {

alignas(16) static const uint32x4x2_t init = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};

alignas(16) static const uint32_t K[192] = {
	/* transform 1 */
	0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,
	0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
	0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,
	0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
	0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,
	0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
	0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,
	0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
	0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,
	0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
	0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,
	0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
	0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,
	0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
	0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,
	0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2,
	/* transform 2 */
	0xc28a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,
	0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
	0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,
	0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf374,
	0x649b69c1,0xf0fe4786,0x0fe1edc6,0x240cf254,
	0x4fe9346f,0x6cc984be,0x61b9411e,0x16f988fa,
	0xf2c65152,0xa88e5a6d,0xb019fc65,0xb9d99ec7,
	0x9a1231c3,0xe70eeaa0,0xfdb1232b,0xc7353eb0,
	0x3069bad5,0xcb976d5f,0x5a0f118f,0xdc1eeefd,
	0x0a35b689,0xde0b7a04,0x58f4ca9d,0xe15d5b16,
	0x007f3e86,0x37088980,0xa507ea32,0x6fab9537,
	0x17406110,0x0d8cd6f1,0xcdaa3b6d,0xc0bbbe37,
	0x83613bda,0xdb48a363,0x0b02e931,0x6fd15ca7,
	0x521afaca,0x31338431,0x6ed41a95,0x6d437890,
	0xc39c91f2,0x9eccabbd,0xb5c9a0e6,0x532fb63c,
	0xd2c741c6,0x07237ea3,0xa4954b68,0x4c191d76,
	/* transform 3 */
	0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,
	0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
	0x5807aa98,0x12835b01,0x243185be,0x550c7dc3,
	0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf274,
	0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,
	0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
	0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,
	0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
	0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,
	0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
	0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,
	0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
	0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,
	0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
	0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,
	0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

// This is a port of Intel's _mm_set_epi64x taken from an Android library
static inline __attribute__((always_inline)) uint32x4_t _mm_set_epi64x(const uint64_t a, const uint64_t b)
{
    return vreinterpretq_u32_u64(vcombine_u64(vcreate_u64(b), vcreate_u64(a)));
}


/** Initialize SHA-256 state. */
void inline Initialize(uint32_t* s)
{
    vst1q_u32(&s[0], sha256_armv8::init.val[0]);
    vst1q_u32(&s[4], sha256_armv8::init.val[1]);
}

// Neon version of bswap32 for aarch64. Customised to process 32bytes.
void inline WriteBE32Neon32bytes(unsigned char* ptr, uint32_t* x)
{
    alignas(16) uint8x16_t *dst = reinterpret_cast<uint8x16_t*>(ptr);
    *dst++ = vrev32q_u8(vreinterpretq_u32_u8(vld1q_u32(x)));
    *dst = vrev32q_u8(vreinterpretq_u32_u8(vld1q_u32(x + 4)));
}

// Perform a number of SHA-256 transformations via ArmV8 extensions, processing 64-byte chunks.
inline void Transform(uint32_t* s, const unsigned char* chunk, size_t blocks)
{
    alignas(16) uint32x4_t STATE0, STATE1, ABEF_SAVE, CDGH_SAVE;
    alignas(16) uint32x4_t MSG0, MSG1, MSG2, MSG3;
    alignas(16) uint32x4_t TMP0, TMP2;

    // Load state
    STATE0 = vld1q_u32(&s[0]);
    STATE1 = vld1q_u32(&s[4]);

    alignas(16) const uint8x16_t* input32 = reinterpret_cast<const uint8x16_t*>(chunk);

        while (blocks--)
        {
        // Backup current state
        ABEF_SAVE = STATE0;
        CDGH_SAVE = STATE1;

        // Load and Convert input chunk to Big Endian
        MSG0 = vreinterpretq_u32_u8(vrev32q_u8(*input32++));
        MSG1 = vreinterpretq_u32_u8(vrev32q_u8(*input32++));
        MSG2 = vreinterpretq_u32_u8(vrev32q_u8(*input32++));
        MSG3 = vreinterpretq_u32_u8(vrev32q_u8(*input32++));

	// Original implemenation preloaded message and constant addition which was 1-3% slower.
	// Now included as first step in quad round code saving one Q Neon register
        // "TMP0 = vaddq_u32(MSG0, vld1q_u32(&K[0]));"

        // Rounds 1-4
        TMP0 = vaddq_u32(MSG0, vld1q_u32(&K[0]));
        TMP2 = STATE0;
        MSG0 = vsha256su0q_u32(MSG0, MSG1);
        STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
        STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP0);
        MSG0 = vsha256su1q_u32(MSG0, MSG2, MSG3);

        // Rounds 5-8
        TMP0 = vaddq_u32(MSG1, vld1q_u32(&K[4]));
        TMP2 = STATE0;
        MSG1 = vsha256su0q_u32(MSG1, MSG2);
        STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
        STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP0);
        MSG1 = vsha256su1q_u32(MSG1, MSG3, MSG0);

        // Rounds 9-12
        TMP0 = vaddq_u32(MSG2, vld1q_u32(&K[8]));
        TMP2 = STATE0;
        MSG2 = vsha256su0q_u32(MSG2, MSG3);
        STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
        STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP0);
        MSG2 = vsha256su1q_u32(MSG2, MSG0, MSG1);

        // Rounds 13-16
        TMP0 = vaddq_u32(MSG3, vld1q_u32(&K[12]));
        TMP2 = STATE0;
        MSG3 = vsha256su0q_u32(MSG3, MSG0);
        STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
        STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP0);
        MSG3 = vsha256su1q_u32(MSG3, MSG1, MSG2);

        // Rounds 17-20
        TMP0 = vaddq_u32(MSG0, vld1q_u32(&K[16]));
        TMP2 = STATE0;
        MSG0 = vsha256su0q_u32(MSG0, MSG1);
        STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
        STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP0);
        MSG0 = vsha256su1q_u32(MSG0, MSG2, MSG3);

        // Rounds 21-24
        TMP0 = vaddq_u32(MSG1, vld1q_u32(&K[20]));
        TMP2 = STATE0;
        MSG1 = vsha256su0q_u32(MSG1, MSG2);
        STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
        STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP0);
        MSG1 = vsha256su1q_u32(MSG1, MSG3, MSG0);

        // Rounds 25-28
        TMP0 = vaddq_u32(MSG2, vld1q_u32(&K[24]));
        TMP2 = STATE0;
        MSG2 = vsha256su0q_u32(MSG2, MSG3);
        STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
        STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP0);
        MSG2 = vsha256su1q_u32(MSG2, MSG0, MSG1);

        // Rounds 29-32
        TMP0 = vaddq_u32(MSG3, vld1q_u32(&K[28]));
        TMP2 = STATE0;
        MSG3 = vsha256su0q_u32(MSG3, MSG0);
        STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
        STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP0);
        MSG3 = vsha256su1q_u32(MSG3, MSG1, MSG2);

        // Rounds 33-36
        TMP0 = vaddq_u32(MSG0, vld1q_u32(&K[32]));
        TMP2 = STATE0;
        MSG0 = vsha256su0q_u32(MSG0, MSG1);
        STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
        STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP0);
        MSG0 = vsha256su1q_u32(MSG0, MSG2, MSG3);

        // Rounds 37-40
        TMP0 = vaddq_u32(MSG1, vld1q_u32(&K[36]));
        TMP2 = STATE0;
        MSG1 = vsha256su0q_u32(MSG1, MSG2);
        STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
        STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP0);
        MSG1 = vsha256su1q_u32(MSG1, MSG3, MSG0);

        // Rounds 41-44
        TMP0 = vaddq_u32(MSG2, vld1q_u32(&K[40]));
        TMP2 = STATE0;
        MSG2 = vsha256su0q_u32(MSG2, MSG3);
        STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
        STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP0);
        MSG2 = vsha256su1q_u32(MSG2, MSG0, MSG1);

        // Rounds 45-48
        TMP0 = vaddq_u32(MSG3, vld1q_u32(&K[44]));
        TMP2 = STATE0;
        MSG3 = vsha256su0q_u32(MSG3, MSG0);
        STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
        STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP0);
        MSG3 = vsha256su1q_u32(MSG3, MSG1, MSG2);

        // Rounds 49-52
        TMP0 = vaddq_u32(MSG0, vld1q_u32(&K[48]));
        TMP2 = STATE0;
        STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
        STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP0);

        // Rounds 53-56
        TMP0 = vaddq_u32(MSG1, vld1q_u32(&K[52]));
        TMP2 = STATE0;
        STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
        STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP0);

        // Rounds 57-60
        TMP0 = vaddq_u32(MSG2, vld1q_u32(&K[56]));
        TMP2 = STATE0;
        STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
        STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP0);

        // Rounds 61-64
        TMP0 = vaddq_u32(MSG3, vld1q_u32(&K[60]));
        TMP2 = STATE0;
        STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
        STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP0);

        // Update state
        STATE0 = vaddq_u32(STATE0, ABEF_SAVE);
        STATE1 = vaddq_u32(STATE1, CDGH_SAVE);
        }

    // Save final state
    vst1q_u32(&s[0], STATE0);
    vst1q_u32(&s[4], STATE1);
}


// Broken implementation for armv8
inline void TransformD64(unsigned char* out, const unsigned char* in)
{


#define Rx(T0, T1, K, W0, W1, W2, W3)      \
	W0 = vsha256su0q_u32( W0, W1 );    \
	d2 = d0;                           \
	T1 = vaddq_u32(W1, K); 		   \
	d0 = vsha256hq_u32( d0, d1, T0 );  \
	d1 = vsha256h2q_u32( d1, d2, T0 ); \
	W0 = vsha256su1q_u32( W0, W2, W3 );

#define Rx1(T0, T1, K, W0, W1, W2, W3)      \
	W0 = vsha256su0q_u32( W0, W1 );    \
	d2 = d0;                           \
	T1 = K; 		   \
	d0 = vsha256hq_u32( d0, d1, T0 );  \
	d1 = vsha256h2q_u32( d1, d2, T0 ); \
	W0 = vsha256su1q_u32( W0, W2, W3 );

#define Ry(T0, T1, K, W1)                  \
	d2 = d0;                           \
	T1 = vaddq_u32(W1, K); 		   \
	d0 = vsha256hq_u32( d0, d1, T0 );  \
	d1 = vsha256h2q_u32( d1, d2, T0 );

#define Rz(T0)                             \
	d2 = d0;                       	   \
	d0 = vsha256hq_u32( d0, d1, T0 );  \
	d1 = vsha256h2q_u32( d1, d2, T0 );

#define Ry2(T0, T1, K)			   \
	d2 = d0;                           \
	T1 = K; 		   \
	d0 = vsha256hq_u32( d0, d1, T0 );  \
	d1 = vsha256h2q_u32( d1, d2, T0 );

	alignas(16) uint32x4_t s0, s1;

	alignas(16) uint32x4_t w0, w1, w2, w3;

	alignas(16) uint32x4_t d0, d1, d2;

	alignas(16) uint32x4_t t0, t1;

	s0 = sha256_armv8::init.val[0];
	s1 = sha256_armv8::init.val[1];

	alignas(16) const uint8x16_t* data = reinterpret_cast<const uint8x16_t*>(in);

	w0 = vreinterpretq_u32_u8(vrev32q_u8(*data++));
	w1 = vreinterpretq_u32_u8(vrev32q_u8(*data++));
	w2 = vreinterpretq_u32_u8(vrev32q_u8(*data++));
	w3 = vreinterpretq_u32_u8(vrev32q_u8(*data++));

	alignas(16) const uint32x4_t* k = reinterpret_cast<const uint32x4_t*>(K);

	t0 = w0 + k[0];

	d0 = s0;
	d1 = s1;

	Rx(t0, t1, k[1], w0, w1, w2, w3);
	Rx(t1, t0, k[2], w1, w2, w3, w0);
	Rx(t0, t1, k[3], w2, w3, w0, w1);
	Rx(t1, t0, k[4], w3, w0, w1, w2);
	Rx(t0, t1, k[5], w0, w1, w2, w3);
	Rx(t1, t0, k[6], w1, w2, w3, w0);
	Rx(t0, t1, k[7], w2, w3, w0, w1);
	Rx(t1, t0, k[8], w3, w0, w1, w2);
	Rx(t0, t1, k[9], w0, w1, w2, w3);
	Rx(t1, t0, k[10], w1, w2, w3, w0);
	Rx(t0, t1, k[11], w2, w3, w0, w1);
	Rx(t1, t0, k[12], w3, w0, w1, w2);
	Ry(t0, t1, k[13], w1);
	Ry(t1, t0, k[14], w2);
	Ry(t0, t1, k[15], w3);
	Rz(t1);

	s0  += d0;
	s1  += d1;

		//transform 2 

	d0 = s0;
	d1 = s1;

	Rz(k[16]);
	Rz(k[17]);
	Rz(k[18]);
	Rz(k[19]);
	Rz(k[20]);
	Rz(k[21]);
	Rz(k[22]);
	Rz(k[23]);
	Rz(k[24]);
	Rz(k[25]);
	Rz(k[26]);
	Rz(k[27]);
	Rz(k[28]);
	Rz(k[29]);
	Rz(k[30]);
	Rz(k[31]);


	w0 = d0 + s0;
	w1 = d1 + s1;

// everything works up until transform 3

	d0 = sha256_armv8::init.val[0];
	d1 = sha256_armv8::init.val[1];

	t0 = w0 + k[32];

	Rx(t0, t1, k[33], w0, w1, w2, w3);
	Rx1(t1, t0, k[34], w1, w2, w3, w0);
	// Intel _mm_set_epi64x intrinsic port taken from an Android library
	w2 = _mm_set_epi64x(0x0ull, 0x80000000ull);
	Ry2(t0, t1, k[35]);
	w3 = _mm_set_epi64x(0x10000000000ull, 0x0ull);
	Ry(t1, t0, k[36], w3);
	Rx(t0, t1, k[37], w0, w1, w2, w3);
	Rx(t1, t0, k[38], w1, w2, w3, w0);
	Rx(t0, t1, k[39], w2, w3, w0, w1);
	Rx(t1, t0, k[40], w3, w0, w1, w2);
	Rx(t0, t1, k[41], w0, w1, w2, w3);
	Rx(t1, t0, k[42], w1, w2, w3, w0);
	Rx(t0, t1, k[43], w2, w3, w0, w1);
	Rx(t1, t0, k[44], w3, w0, w1, w2);
	Ry(t0, t1, k[45], w1);
	Ry(t1, t0, k[46], w2);
	Ry(t0, t1, k[47], w3);
	Rz(t1);

	d0 += sha256_armv8::init.val[0];
	d1 += sha256_armv8::init.val[1];

	alignas(16) uint8x16_t *dst = reinterpret_cast<uint8x16_t*>(out);

	*dst++ = vrev32q_u8(vreinterpretq_u8_u32(d0));
	*dst++ = vrev32q_u8(vreinterpretq_u8_u32(d1));
}

/* BROKEN
// Perform a sha256d midstate transformation via ArmV8 extensions, skipping message sigmas.
inline void TransformMidstate(uint32_t* s)
{
    alignas(16) uint32x4_t STATE0, STATE1;
    alignas(16) uint32x4_t TMP0, TMP2;

    // Load state
    STATE0 = vld1q_u32(&s[0]);
    STATE1 = vld1q_u32(&s[4]);

        // Rounds 1-4
        TMP0 = vld1q_u32(&K[0]);
        TMP2 = STATE0;
        STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
        STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP0);

        // Rounds 5-8
        TMP0 = vld1q_u32(&K[4]);
        TMP2 = STATE0;
        STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
        STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP0);

        // Rounds 9-12
        TMP0 = vld1q_u32(&K[8]);
        TMP2 = STATE0;
        STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
        STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP0);

        // Rounds 13-16
        TMP0 = vld1q_u32(&K[12]);
        TMP2 = STATE0;
        STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
        STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP0);

        // Rounds 17-20
        TMP0 = vld1q_u32(&K[16]);
        TMP2 = STATE0;
        STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
        STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP0);

        // Rounds 21-24
        TMP0 = vld1q_u32(&K[20]);
        TMP2 = STATE0;
        STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
        STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP0);

        // Rounds 25-28
        TMP0 = vld1q_u32(&K[24]);
        TMP2 = STATE0;
        STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
        STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP0);

        // Rounds 29-32
        TMP0 = vld1q_u32(&K[28]);
        TMP2 = STATE0;
        STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
        STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP0);

        // Rounds 33-36
        TMP0 = vld1q_u32(&K[32]);
        TMP2 = STATE0;
        STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
        STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP0);

        // Rounds 37-40
        TMP0 = vld1q_u32(&K[36]);
        TMP2 = STATE0;
        STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
        STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP0);

        // Rounds 41-44
        TMP0 = vld1q_u32(&K[40]);
        TMP2 = STATE0;
        STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
        STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP0);

        // Rounds 45-48
        TMP0 = vld1q_u32(&K[44]);
        TMP2 = STATE0;
        STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
        STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP0);

        // Rounds 49-52
        TMP0 = vld1q_u32(&K[48]);
        TMP2 = STATE0;
        STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
        STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP0);

        // Rounds 53-56
        TMP0 = vld1q_u32(&K[52]);
        TMP2 = STATE0;
        STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
        STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP0);

        // Rounds 57-60
        TMP0 = vld1q_u32(&K[56]);
        TMP2 = STATE0;
        STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
        STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP0);

        // Rounds 61-64
        TMP0 = vld1q_u32(&K[60]);
        TMP2 = STATE0;
        STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
        STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP0);

        // Update state
        STATE0 = vaddq_u32(STATE0, vld1q_u32(&s[0]));
        STATE1 = vaddq_u32(STATE1, vld1q_u32(&s[1]));

    // Save final state
    vst1q_u32(&s[0], STATE0);
    vst1q_u32(&s[4], STATE1);
}*/

typedef void (*TransformType)(uint32_t*, const unsigned char*, size_t);
typedef void (*TransformD64Type)(unsigned char*, const unsigned char*);

template<TransformType tr>
void inline TransformD64Wrapper(unsigned char* out, const unsigned char* in)
{
    alignas(16) uint32_t s[8];
    alignas(16) static const unsigned char padding1[64] = {
      0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      0,    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      0,    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      0,    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0
    };
    alignas(16) unsigned char buffer2[64] = {
      0,    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      0,    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      0,    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0
    };

    sha256_armv8::Initialize(s);
    tr(s, in, 1);
    //sha256_armv8::TransformMidstate(s); 
    tr(s, padding1, 1);
    sha256_armv8::WriteBE32Neon32bytes(buffer2, s);
    sha256_armv8::Initialize(s);
    tr(s, buffer2, 1);
    sha256_armv8::WriteBE32Neon32bytes(out, s);
}

} // namespace sha256_armv8
#endif

// Internal implementation code.
namespace
{
/// Internal SHA-256 implementation.
namespace sha256
{

uint32_t inline Ch(uint32_t x, uint32_t y, uint32_t z) { return z ^ (x & (y ^ z)); }
uint32_t inline Maj(uint32_t x, uint32_t y, uint32_t z) { return (x & y) | (z & (x | y)); }
uint32_t inline Sigma0(uint32_t x) { return (x >> 2 | x << 30) ^ (x >> 13 | x << 19) ^ (x >> 22 | x << 10); }
uint32_t inline Sigma1(uint32_t x) { return (x >> 6 | x << 26) ^ (x >> 11 | x << 21) ^ (x >> 25 | x << 7); }
uint32_t inline sigma0(uint32_t x) { return (x >> 7 | x << 25) ^ (x >> 18 | x << 14) ^ (x >> 3); }
uint32_t inline sigma1(uint32_t x) { return (x >> 17 | x << 15) ^ (x >> 19 | x << 13) ^ (x >> 10); }

/** One round of SHA-256. */
void inline Round(uint32_t a, uint32_t b, uint32_t c, uint32_t& d, uint32_t e, uint32_t f, uint32_t g, uint32_t& h, uint32_t k)
{
    uint32_t t1 = h + Sigma1(e) + Ch(e, f, g) + k;
    uint32_t t2 = Sigma0(a) + Maj(a, b, c);
    d += t1;
    h = t1 + t2;
}

/** Initialize SHA-256 state. */
void inline Initialize(uint32_t* s)
{
    s[0] = 0x6a09e667ul;
    s[1] = 0xbb67ae85ul;
    s[2] = 0x3c6ef372ul;
    s[3] = 0xa54ff53aul;
    s[4] = 0x510e527ful;
    s[5] = 0x9b05688cul;
    s[6] = 0x1f83d9abul;
    s[7] = 0x5be0cd19ul;
}

/** Perform a number of SHA-256 transformations, processing 64-byte chunks. */
void inline Transform(uint32_t* s, const unsigned char* chunk, size_t blocks)
{
    while (blocks--) {
      uint32_t a = s[0], b = s[1], c = s[2], d = s[3], e = s[4], f = s[5], g = s[6], h = s[7];
      uint32_t w0, w1, w2, w3, w4, w5, w6, w7, w8, w9, w10, w11, w12, w13, w14, w15;

      Round(a, b, c, d, e, f, g, h, 0x428a2f98 + (w0 = ReadBE32(chunk + 0)));
      Round(h, a, b, c, d, e, f, g, 0x71374491 + (w1 = ReadBE32(chunk + 4)));
      Round(g, h, a, b, c, d, e, f, 0xb5c0fbcf + (w2 = ReadBE32(chunk + 8)));
      Round(f, g, h, a, b, c, d, e, 0xe9b5dba5 + (w3 = ReadBE32(chunk + 12)));
      Round(e, f, g, h, a, b, c, d, 0x3956c25b + (w4 = ReadBE32(chunk + 16)));
      Round(d, e, f, g, h, a, b, c, 0x59f111f1 + (w5 = ReadBE32(chunk + 20)));
      Round(c, d, e, f, g, h, a, b, 0x923f82a4 + (w6 = ReadBE32(chunk + 24)));
      Round(b, c, d, e, f, g, h, a, 0xab1c5ed5 + (w7 = ReadBE32(chunk + 28)));
      Round(a, b, c, d, e, f, g, h, 0xd807aa98 + (w8 = ReadBE32(chunk + 32)));
      Round(h, a, b, c, d, e, f, g, 0x12835b01 + (w9 = ReadBE32(chunk + 36)));
      Round(g, h, a, b, c, d, e, f, 0x243185be + (w10 = ReadBE32(chunk + 40)));
      Round(f, g, h, a, b, c, d, e, 0x550c7dc3 + (w11 = ReadBE32(chunk + 44)));
      Round(e, f, g, h, a, b, c, d, 0x72be5d74 + (w12 = ReadBE32(chunk + 48)));
      Round(d, e, f, g, h, a, b, c, 0x80deb1fe + (w13 = ReadBE32(chunk + 52)));
      Round(c, d, e, f, g, h, a, b, 0x9bdc06a7 + (w14 = ReadBE32(chunk + 56)));
      Round(b, c, d, e, f, g, h, a, 0xc19bf174 + (w15 = ReadBE32(chunk + 60)));

      Round(a, b, c, d, e, f, g, h, 0xe49b69c1 + (w0 += sigma1(w14) + w9 + sigma0(w1)));
      Round(h, a, b, c, d, e, f, g, 0xefbe4786 + (w1 += sigma1(w15) + w10 + sigma0(w2)));
      Round(g, h, a, b, c, d, e, f, 0x0fc19dc6 + (w2 += sigma1(w0) + w11 + sigma0(w3)));
      Round(f, g, h, a, b, c, d, e, 0x240ca1cc + (w3 += sigma1(w1) + w12 + sigma0(w4)));
      Round(e, f, g, h, a, b, c, d, 0x2de92c6f + (w4 += sigma1(w2) + w13 + sigma0(w5)));
      Round(d, e, f, g, h, a, b, c, 0x4a7484aa + (w5 += sigma1(w3) + w14 + sigma0(w6)));
      Round(c, d, e, f, g, h, a, b, 0x5cb0a9dc + (w6 += sigma1(w4) + w15 + sigma0(w7)));
      Round(b, c, d, e, f, g, h, a, 0x76f988da + (w7 += sigma1(w5) + w0 + sigma0(w8)));
      Round(a, b, c, d, e, f, g, h, 0x983e5152 + (w8 += sigma1(w6) + w1 + sigma0(w9)));
      Round(h, a, b, c, d, e, f, g, 0xa831c66d + (w9 += sigma1(w7) + w2 + sigma0(w10)));
      Round(g, h, a, b, c, d, e, f, 0xb00327c8 + (w10 += sigma1(w8) + w3 + sigma0(w11)));
      Round(f, g, h, a, b, c, d, e, 0xbf597fc7 + (w11 += sigma1(w9) + w4 + sigma0(w12)));
      Round(e, f, g, h, a, b, c, d, 0xc6e00bf3 + (w12 += sigma1(w10) + w5 + sigma0(w13)));
      Round(d, e, f, g, h, a, b, c, 0xd5a79147 + (w13 += sigma1(w11) + w6 + sigma0(w14)));
      Round(c, d, e, f, g, h, a, b, 0x06ca6351 + (w14 += sigma1(w12) + w7 + sigma0(w15)));
      Round(b, c, d, e, f, g, h, a, 0x14292967 + (w15 += sigma1(w13) + w8 + sigma0(w0)));

      Round(a, b, c, d, e, f, g, h, 0x27b70a85 + (w0 += sigma1(w14) + w9 + sigma0(w1)));
      Round(h, a, b, c, d, e, f, g, 0x2e1b2138 + (w1 += sigma1(w15) + w10 + sigma0(w2)));
      Round(g, h, a, b, c, d, e, f, 0x4d2c6dfc + (w2 += sigma1(w0) + w11 + sigma0(w3)));
      Round(f, g, h, a, b, c, d, e, 0x53380d13 + (w3 += sigma1(w1) + w12 + sigma0(w4)));
      Round(e, f, g, h, a, b, c, d, 0x650a7354 + (w4 += sigma1(w2) + w13 + sigma0(w5)));
      Round(d, e, f, g, h, a, b, c, 0x766a0abb + (w5 += sigma1(w3) + w14 + sigma0(w6)));
      Round(c, d, e, f, g, h, a, b, 0x81c2c92e + (w6 += sigma1(w4) + w15 + sigma0(w7)));
      Round(b, c, d, e, f, g, h, a, 0x92722c85 + (w7 += sigma1(w5) + w0 + sigma0(w8)));
      Round(a, b, c, d, e, f, g, h, 0xa2bfe8a1 + (w8 += sigma1(w6) + w1 + sigma0(w9)));
      Round(h, a, b, c, d, e, f, g, 0xa81a664b + (w9 += sigma1(w7) + w2 + sigma0(w10)));
      Round(g, h, a, b, c, d, e, f, 0xc24b8b70 + (w10 += sigma1(w8) + w3 + sigma0(w11)));
      Round(f, g, h, a, b, c, d, e, 0xc76c51a3 + (w11 += sigma1(w9) + w4 + sigma0(w12)));
      Round(e, f, g, h, a, b, c, d, 0xd192e819 + (w12 += sigma1(w10) + w5 + sigma0(w13)));
      Round(d, e, f, g, h, a, b, c, 0xd6990624 + (w13 += sigma1(w11) + w6 + sigma0(w14)));
      Round(c, d, e, f, g, h, a, b, 0xf40e3585 + (w14 += sigma1(w12) + w7 + sigma0(w15)));
      Round(b, c, d, e, f, g, h, a, 0x106aa070 + (w15 += sigma1(w13) + w8 + sigma0(w0)));

      Round(a, b, c, d, e, f, g, h, 0x19a4c116 + (w0 += sigma1(w14) + w9 + sigma0(w1)));
      Round(h, a, b, c, d, e, f, g, 0x1e376c08 + (w1 += sigma1(w15) + w10 + sigma0(w2)));
      Round(g, h, a, b, c, d, e, f, 0x2748774c + (w2 += sigma1(w0) + w11 + sigma0(w3)));
      Round(f, g, h, a, b, c, d, e, 0x34b0bcb5 + (w3 += sigma1(w1) + w12 + sigma0(w4)));
      Round(e, f, g, h, a, b, c, d, 0x391c0cb3 + (w4 += sigma1(w2) + w13 + sigma0(w5)));
      Round(d, e, f, g, h, a, b, c, 0x4ed8aa4a + (w5 += sigma1(w3) + w14 + sigma0(w6)));
      Round(c, d, e, f, g, h, a, b, 0x5b9cca4f + (w6 += sigma1(w4) + w15 + sigma0(w7)));
      Round(b, c, d, e, f, g, h, a, 0x682e6ff3 + (w7 += sigma1(w5) + w0 + sigma0(w8)));
      Round(a, b, c, d, e, f, g, h, 0x748f82ee + (w8 += sigma1(w6) + w1 + sigma0(w9)));
      Round(h, a, b, c, d, e, f, g, 0x78a5636f + (w9 += sigma1(w7) + w2 + sigma0(w10)));
      Round(g, h, a, b, c, d, e, f, 0x84c87814 + (w10 += sigma1(w8) + w3 + sigma0(w11)));
      Round(f, g, h, a, b, c, d, e, 0x8cc70208 + (w11 += sigma1(w9) + w4 + sigma0(w12)));
      Round(e, f, g, h, a, b, c, d, 0x90befffa + (w12 += sigma1(w10) + w5 + sigma0(w13)));
      Round(d, e, f, g, h, a, b, c, 0xa4506ceb + (w13 += sigma1(w11) + w6 + sigma0(w14)));
      Round(c, d, e, f, g, h, a, b, 0xbef9a3f7 + (w14 + sigma1(w12) + w7 + sigma0(w15)));
      Round(b, c, d, e, f, g, h, a, 0xc67178f2 + (w15 + sigma1(w13) + w8 + sigma0(w0)));

      s[0] += a;
      s[1] += b;
      s[2] += c;
      s[3] += d;
      s[4] += e;
      s[5] += f;
      s[6] += g;
      s[7] += h;
      chunk += 64;
    }
}

void inline TransformD64(unsigned char* out, const unsigned char* in)
{
    // Transform 1
    uint32_t a = 0x6a09e667ul;
    uint32_t b = 0xbb67ae85ul;
    uint32_t c = 0x3c6ef372ul;
    uint32_t d = 0xa54ff53aul;
    uint32_t e = 0x510e527ful;
    uint32_t f = 0x9b05688cul;
    uint32_t g = 0x1f83d9abul;
    uint32_t h = 0x5be0cd19ul;

    uint32_t w0, w1, w2, w3, w4, w5, w6, w7, w8, w9, w10, w11, w12, w13, w14, w15;

    Round(a, b, c, d, e, f, g, h, 0x428a2f98ul + (w0 = ReadBE32(in + 0)));
    Round(h, a, b, c, d, e, f, g, 0x71374491ul + (w1 = ReadBE32(in + 4)));
    Round(g, h, a, b, c, d, e, f, 0xb5c0fbcful + (w2 = ReadBE32(in + 8)));
    Round(f, g, h, a, b, c, d, e, 0xe9b5dba5ul + (w3 = ReadBE32(in + 12)));
    Round(e, f, g, h, a, b, c, d, 0x3956c25bul + (w4 = ReadBE32(in + 16)));
    Round(d, e, f, g, h, a, b, c, 0x59f111f1ul + (w5 = ReadBE32(in + 20)));
    Round(c, d, e, f, g, h, a, b, 0x923f82a4ul + (w6 = ReadBE32(in + 24)));
    Round(b, c, d, e, f, g, h, a, 0xab1c5ed5ul + (w7 = ReadBE32(in + 28)));
    Round(a, b, c, d, e, f, g, h, 0xd807aa98ul + (w8 = ReadBE32(in + 32)));
    Round(h, a, b, c, d, e, f, g, 0x12835b01ul + (w9 = ReadBE32(in + 36)));
    Round(g, h, a, b, c, d, e, f, 0x243185beul + (w10 = ReadBE32(in + 40)));
    Round(f, g, h, a, b, c, d, e, 0x550c7dc3ul + (w11 = ReadBE32(in + 44)));
    Round(e, f, g, h, a, b, c, d, 0x72be5d74ul + (w12 = ReadBE32(in + 48)));
    Round(d, e, f, g, h, a, b, c, 0x80deb1feul + (w13 = ReadBE32(in + 52)));
    Round(c, d, e, f, g, h, a, b, 0x9bdc06a7ul + (w14 = ReadBE32(in + 56)));
    Round(b, c, d, e, f, g, h, a, 0xc19bf174ul + (w15 = ReadBE32(in + 60)));
    Round(a, b, c, d, e, f, g, h, 0xe49b69c1ul + (w0 += sigma1(w14) + w9 + sigma0(w1)));
    Round(h, a, b, c, d, e, f, g, 0xefbe4786ul + (w1 += sigma1(w15) + w10 + sigma0(w2)));
    Round(g, h, a, b, c, d, e, f, 0x0fc19dc6ul + (w2 += sigma1(w0) + w11 + sigma0(w3)));
    Round(f, g, h, a, b, c, d, e, 0x240ca1ccul + (w3 += sigma1(w1) + w12 + sigma0(w4)));
    Round(e, f, g, h, a, b, c, d, 0x2de92c6ful + (w4 += sigma1(w2) + w13 + sigma0(w5)));
    Round(d, e, f, g, h, a, b, c, 0x4a7484aaul + (w5 += sigma1(w3) + w14 + sigma0(w6)));
    Round(c, d, e, f, g, h, a, b, 0x5cb0a9dcul + (w6 += sigma1(w4) + w15 + sigma0(w7)));
    Round(b, c, d, e, f, g, h, a, 0x76f988daul + (w7 += sigma1(w5) + w0 + sigma0(w8)));
    Round(a, b, c, d, e, f, g, h, 0x983e5152ul + (w8 += sigma1(w6) + w1 + sigma0(w9)));
    Round(h, a, b, c, d, e, f, g, 0xa831c66dul + (w9 += sigma1(w7) + w2 + sigma0(w10)));
    Round(g, h, a, b, c, d, e, f, 0xb00327c8ul + (w10 += sigma1(w8) + w3 + sigma0(w11)));
    Round(f, g, h, a, b, c, d, e, 0xbf597fc7ul + (w11 += sigma1(w9) + w4 + sigma0(w12)));
    Round(e, f, g, h, a, b, c, d, 0xc6e00bf3ul + (w12 += sigma1(w10) + w5 + sigma0(w13)));
    Round(d, e, f, g, h, a, b, c, 0xd5a79147ul + (w13 += sigma1(w11) + w6 + sigma0(w14)));
    Round(c, d, e, f, g, h, a, b, 0x06ca6351ul + (w14 += sigma1(w12) + w7 + sigma0(w15)));
    Round(b, c, d, e, f, g, h, a, 0x14292967ul + (w15 += sigma1(w13) + w8 + sigma0(w0)));
    Round(a, b, c, d, e, f, g, h, 0x27b70a85ul + (w0 += sigma1(w14) + w9 + sigma0(w1)));
    Round(h, a, b, c, d, e, f, g, 0x2e1b2138ul + (w1 += sigma1(w15) + w10 + sigma0(w2)));
    Round(g, h, a, b, c, d, e, f, 0x4d2c6dfcul + (w2 += sigma1(w0) + w11 + sigma0(w3)));
    Round(f, g, h, a, b, c, d, e, 0x53380d13ul + (w3 += sigma1(w1) + w12 + sigma0(w4)));
    Round(e, f, g, h, a, b, c, d, 0x650a7354ul + (w4 += sigma1(w2) + w13 + sigma0(w5)));
    Round(d, e, f, g, h, a, b, c, 0x766a0abbul + (w5 += sigma1(w3) + w14 + sigma0(w6)));
    Round(c, d, e, f, g, h, a, b, 0x81c2c92eul + (w6 += sigma1(w4) + w15 + sigma0(w7)));
    Round(b, c, d, e, f, g, h, a, 0x92722c85ul + (w7 += sigma1(w5) + w0 + sigma0(w8)));
    Round(a, b, c, d, e, f, g, h, 0xa2bfe8a1ul + (w8 += sigma1(w6) + w1 + sigma0(w9)));
    Round(h, a, b, c, d, e, f, g, 0xa81a664bul + (w9 += sigma1(w7) + w2 + sigma0(w10)));
    Round(g, h, a, b, c, d, e, f, 0xc24b8b70ul + (w10 += sigma1(w8) + w3 + sigma0(w11)));
    Round(f, g, h, a, b, c, d, e, 0xc76c51a3ul + (w11 += sigma1(w9) + w4 + sigma0(w12)));
    Round(e, f, g, h, a, b, c, d, 0xd192e819ul + (w12 += sigma1(w10) + w5 + sigma0(w13)));
    Round(d, e, f, g, h, a, b, c, 0xd6990624ul + (w13 += sigma1(w11) + w6 + sigma0(w14)));
    Round(c, d, e, f, g, h, a, b, 0xf40e3585ul + (w14 += sigma1(w12) + w7 + sigma0(w15)));
    Round(b, c, d, e, f, g, h, a, 0x106aa070ul + (w15 += sigma1(w13) + w8 + sigma0(w0)));
    Round(a, b, c, d, e, f, g, h, 0x19a4c116ul + (w0 += sigma1(w14) + w9 + sigma0(w1)));
    Round(h, a, b, c, d, e, f, g, 0x1e376c08ul + (w1 += sigma1(w15) + w10 + sigma0(w2)));
    Round(g, h, a, b, c, d, e, f, 0x2748774cul + (w2 += sigma1(w0) + w11 + sigma0(w3)));
    Round(f, g, h, a, b, c, d, e, 0x34b0bcb5ul + (w3 += sigma1(w1) + w12 + sigma0(w4)));
    Round(e, f, g, h, a, b, c, d, 0x391c0cb3ul + (w4 += sigma1(w2) + w13 + sigma0(w5)));
    Round(d, e, f, g, h, a, b, c, 0x4ed8aa4aul + (w5 += sigma1(w3) + w14 + sigma0(w6)));
    Round(c, d, e, f, g, h, a, b, 0x5b9cca4ful + (w6 += sigma1(w4) + w15 + sigma0(w7)));
    Round(b, c, d, e, f, g, h, a, 0x682e6ff3ul + (w7 += sigma1(w5) + w0 + sigma0(w8)));
    Round(a, b, c, d, e, f, g, h, 0x748f82eeul + (w8 += sigma1(w6) + w1 + sigma0(w9)));
    Round(h, a, b, c, d, e, f, g, 0x78a5636ful + (w9 += sigma1(w7) + w2 + sigma0(w10)));
    Round(g, h, a, b, c, d, e, f, 0x84c87814ul + (w10 += sigma1(w8) + w3 + sigma0(w11)));
    Round(f, g, h, a, b, c, d, e, 0x8cc70208ul + (w11 += sigma1(w9) + w4 + sigma0(w12)));
    Round(e, f, g, h, a, b, c, d, 0x90befffaul + (w12 += sigma1(w10) + w5 + sigma0(w13)));
    Round(d, e, f, g, h, a, b, c, 0xa4506cebul + (w13 += sigma1(w11) + w6 + sigma0(w14)));
    Round(c, d, e, f, g, h, a, b, 0xbef9a3f7ul + (w14 + sigma1(w12) + w7 + sigma0(w15)));
    Round(b, c, d, e, f, g, h, a, 0xc67178f2ul + (w15 + sigma1(w13) + w8 + sigma0(w0)));

    a += 0x6a09e667ul;
    b += 0xbb67ae85ul;
    c += 0x3c6ef372ul;
    d += 0xa54ff53aul;
    e += 0x510e527ful;
    f += 0x9b05688cul;
    g += 0x1f83d9abul;
    h += 0x5be0cd19ul;

    uint32_t t0 = a, t1 = b, t2 = c, t3 = d, t4 = e, t5 = f, t6 = g, t7 = h;

    // Transform 2
    Round(a, b, c, d, e, f, g, h, 0xc28a2f98ul);
    Round(h, a, b, c, d, e, f, g, 0x71374491ul);
    Round(g, h, a, b, c, d, e, f, 0xb5c0fbcful);
    Round(f, g, h, a, b, c, d, e, 0xe9b5dba5ul);
    Round(e, f, g, h, a, b, c, d, 0x3956c25bul);
    Round(d, e, f, g, h, a, b, c, 0x59f111f1ul);
    Round(c, d, e, f, g, h, a, b, 0x923f82a4ul);
    Round(b, c, d, e, f, g, h, a, 0xab1c5ed5ul);
    Round(a, b, c, d, e, f, g, h, 0xd807aa98ul);
    Round(h, a, b, c, d, e, f, g, 0x12835b01ul);
    Round(g, h, a, b, c, d, e, f, 0x243185beul);
    Round(f, g, h, a, b, c, d, e, 0x550c7dc3ul);
    Round(e, f, g, h, a, b, c, d, 0x72be5d74ul);
    Round(d, e, f, g, h, a, b, c, 0x80deb1feul);
    Round(c, d, e, f, g, h, a, b, 0x9bdc06a7ul);
    Round(b, c, d, e, f, g, h, a, 0xc19bf374ul);
    Round(a, b, c, d, e, f, g, h, 0x649b69c1ul);
    Round(h, a, b, c, d, e, f, g, 0xf0fe4786ul);
    Round(g, h, a, b, c, d, e, f, 0x0fe1edc6ul);
    Round(f, g, h, a, b, c, d, e, 0x240cf254ul);
    Round(e, f, g, h, a, b, c, d, 0x4fe9346ful);
    Round(d, e, f, g, h, a, b, c, 0x6cc984beul);
    Round(c, d, e, f, g, h, a, b, 0x61b9411eul);
    Round(b, c, d, e, f, g, h, a, 0x16f988faul);
    Round(a, b, c, d, e, f, g, h, 0xf2c65152ul);
    Round(h, a, b, c, d, e, f, g, 0xa88e5a6dul);
    Round(g, h, a, b, c, d, e, f, 0xb019fc65ul);
    Round(f, g, h, a, b, c, d, e, 0xb9d99ec7ul);
    Round(e, f, g, h, a, b, c, d, 0x9a1231c3ul);
    Round(d, e, f, g, h, a, b, c, 0xe70eeaa0ul);
    Round(c, d, e, f, g, h, a, b, 0xfdb1232bul);
    Round(b, c, d, e, f, g, h, a, 0xc7353eb0ul);
    Round(a, b, c, d, e, f, g, h, 0x3069bad5ul);
    Round(h, a, b, c, d, e, f, g, 0xcb976d5ful);
    Round(g, h, a, b, c, d, e, f, 0x5a0f118ful);
    Round(f, g, h, a, b, c, d, e, 0xdc1eeefdul);
    Round(e, f, g, h, a, b, c, d, 0x0a35b689ul);
    Round(d, e, f, g, h, a, b, c, 0xde0b7a04ul);
    Round(c, d, e, f, g, h, a, b, 0x58f4ca9dul);
    Round(b, c, d, e, f, g, h, a, 0xe15d5b16ul);
    Round(a, b, c, d, e, f, g, h, 0x007f3e86ul);
    Round(h, a, b, c, d, e, f, g, 0x37088980ul);
    Round(g, h, a, b, c, d, e, f, 0xa507ea32ul);
    Round(f, g, h, a, b, c, d, e, 0x6fab9537ul);
    Round(e, f, g, h, a, b, c, d, 0x17406110ul);
    Round(d, e, f, g, h, a, b, c, 0x0d8cd6f1ul);
    Round(c, d, e, f, g, h, a, b, 0xcdaa3b6dul);
    Round(b, c, d, e, f, g, h, a, 0xc0bbbe37ul);
    Round(a, b, c, d, e, f, g, h, 0x83613bdaul);
    Round(h, a, b, c, d, e, f, g, 0xdb48a363ul);
    Round(g, h, a, b, c, d, e, f, 0x0b02e931ul);
    Round(f, g, h, a, b, c, d, e, 0x6fd15ca7ul);
    Round(e, f, g, h, a, b, c, d, 0x521afacaul);
    Round(d, e, f, g, h, a, b, c, 0x31338431ul);
    Round(c, d, e, f, g, h, a, b, 0x6ed41a95ul);
    Round(b, c, d, e, f, g, h, a, 0x6d437890ul);
    Round(a, b, c, d, e, f, g, h, 0xc39c91f2ul);
    Round(h, a, b, c, d, e, f, g, 0x9eccabbdul);
    Round(g, h, a, b, c, d, e, f, 0xb5c9a0e6ul);
    Round(f, g, h, a, b, c, d, e, 0x532fb63cul);
    Round(e, f, g, h, a, b, c, d, 0xd2c741c6ul);
    Round(d, e, f, g, h, a, b, c, 0x07237ea3ul);
    Round(c, d, e, f, g, h, a, b, 0xa4954b68ul);
    Round(b, c, d, e, f, g, h, a, 0x4c191d76ul);

    w0 = t0 + a;
    w1 = t1 + b;
    w2 = t2 + c;
    w3 = t3 + d;
    w4 = t4 + e;
    w5 = t5 + f;
    w6 = t6 + g;
    w7 = t7 + h;

    // Transform 3
    a = 0x6a09e667ul;
    b = 0xbb67ae85ul;
    c = 0x3c6ef372ul;
    d = 0xa54ff53aul;
    e = 0x510e527ful;
    f = 0x9b05688cul;
    g = 0x1f83d9abul;
    h = 0x5be0cd19ul;

    Round(a, b, c, d, e, f, g, h, 0x428a2f98ul + w0);
    Round(h, a, b, c, d, e, f, g, 0x71374491ul + w1);
    Round(g, h, a, b, c, d, e, f, 0xb5c0fbcful + w2);
    Round(f, g, h, a, b, c, d, e, 0xe9b5dba5ul + w3);
    Round(e, f, g, h, a, b, c, d, 0x3956c25bul + w4);
    Round(d, e, f, g, h, a, b, c, 0x59f111f1ul + w5);
    Round(c, d, e, f, g, h, a, b, 0x923f82a4ul + w6);
    Round(b, c, d, e, f, g, h, a, 0xab1c5ed5ul + w7);
    Round(a, b, c, d, e, f, g, h, 0x5807aa98ul);
    Round(h, a, b, c, d, e, f, g, 0x12835b01ul);
    Round(g, h, a, b, c, d, e, f, 0x243185beul);
    Round(f, g, h, a, b, c, d, e, 0x550c7dc3ul);
    Round(e, f, g, h, a, b, c, d, 0x72be5d74ul);
    Round(d, e, f, g, h, a, b, c, 0x80deb1feul);
    Round(c, d, e, f, g, h, a, b, 0x9bdc06a7ul);
    Round(b, c, d, e, f, g, h, a, 0xc19bf274ul);
    Round(a, b, c, d, e, f, g, h, 0xe49b69c1ul + (w0 += sigma0(w1)));
    Round(h, a, b, c, d, e, f, g, 0xefbe4786ul + (w1 += 0xa00000ul + sigma0(w2)));
    Round(g, h, a, b, c, d, e, f, 0x0fc19dc6ul + (w2 += sigma1(w0) + sigma0(w3)));
    Round(f, g, h, a, b, c, d, e, 0x240ca1ccul + (w3 += sigma1(w1) + sigma0(w4)));
    Round(e, f, g, h, a, b, c, d, 0x2de92c6ful + (w4 += sigma1(w2) + sigma0(w5)));
    Round(d, e, f, g, h, a, b, c, 0x4a7484aaul + (w5 += sigma1(w3) + sigma0(w6)));
    Round(c, d, e, f, g, h, a, b, 0x5cb0a9dcul + (w6 += sigma1(w4) + 0x100ul + sigma0(w7)));
    Round(b, c, d, e, f, g, h, a, 0x76f988daul + (w7 += sigma1(w5) + w0 + 0x11002000ul));
    Round(a, b, c, d, e, f, g, h, 0x983e5152ul + (w8 = 0x80000000ul + sigma1(w6) + w1));
    Round(h, a, b, c, d, e, f, g, 0xa831c66dul + (w9 = sigma1(w7) + w2));
    Round(g, h, a, b, c, d, e, f, 0xb00327c8ul + (w10 = sigma1(w8) + w3));
    Round(f, g, h, a, b, c, d, e, 0xbf597fc7ul + (w11 = sigma1(w9) + w4));
    Round(e, f, g, h, a, b, c, d, 0xc6e00bf3ul + (w12 = sigma1(w10) + w5));
    Round(d, e, f, g, h, a, b, c, 0xd5a79147ul + (w13 = sigma1(w11) + w6));
    Round(c, d, e, f, g, h, a, b, 0x06ca6351ul + (w14 = sigma1(w12) + w7 + 0x400022ul));
    Round(b, c, d, e, f, g, h, a, 0x14292967ul + (w15 = 0x100ul + sigma1(w13) + w8 + sigma0(w0)));
    Round(a, b, c, d, e, f, g, h, 0x27b70a85ul + (w0 += sigma1(w14) + w9 + sigma0(w1)));
    Round(h, a, b, c, d, e, f, g, 0x2e1b2138ul + (w1 += sigma1(w15) + w10 + sigma0(w2)));
    Round(g, h, a, b, c, d, e, f, 0x4d2c6dfcul + (w2 += sigma1(w0) + w11 + sigma0(w3)));
    Round(f, g, h, a, b, c, d, e, 0x53380d13ul + (w3 += sigma1(w1) + w12 + sigma0(w4)));
    Round(e, f, g, h, a, b, c, d, 0x650a7354ul + (w4 += sigma1(w2) + w13 + sigma0(w5)));
    Round(d, e, f, g, h, a, b, c, 0x766a0abbul + (w5 += sigma1(w3) + w14 + sigma0(w6)));
    Round(c, d, e, f, g, h, a, b, 0x81c2c92eul + (w6 += sigma1(w4) + w15 + sigma0(w7)));
    Round(b, c, d, e, f, g, h, a, 0x92722c85ul + (w7 += sigma1(w5) + w0 + sigma0(w8)));
    Round(a, b, c, d, e, f, g, h, 0xa2bfe8a1ul + (w8 += sigma1(w6) + w1 + sigma0(w9)));
    Round(h, a, b, c, d, e, f, g, 0xa81a664bul + (w9 += sigma1(w7) + w2 + sigma0(w10)));
    Round(g, h, a, b, c, d, e, f, 0xc24b8b70ul + (w10 += sigma1(w8) + w3 + sigma0(w11)));
    Round(f, g, h, a, b, c, d, e, 0xc76c51a3ul + (w11 += sigma1(w9) + w4 + sigma0(w12)));
    Round(e, f, g, h, a, b, c, d, 0xd192e819ul + (w12 += sigma1(w10) + w5 + sigma0(w13)));
    Round(d, e, f, g, h, a, b, c, 0xd6990624ul + (w13 += sigma1(w11) + w6 + sigma0(w14)));
    Round(c, d, e, f, g, h, a, b, 0xf40e3585ul + (w14 += sigma1(w12) + w7 + sigma0(w15)));
    Round(b, c, d, e, f, g, h, a, 0x106aa070ul + (w15 += sigma1(w13) + w8 + sigma0(w0)));
    Round(a, b, c, d, e, f, g, h, 0x19a4c116ul + (w0 += sigma1(w14) + w9 + sigma0(w1)));
    Round(h, a, b, c, d, e, f, g, 0x1e376c08ul + (w1 += sigma1(w15) + w10 + sigma0(w2)));
    Round(g, h, a, b, c, d, e, f, 0x2748774cul + (w2 += sigma1(w0) + w11 + sigma0(w3)));
    Round(f, g, h, a, b, c, d, e, 0x34b0bcb5ul + (w3 += sigma1(w1) + w12 + sigma0(w4)));
    Round(e, f, g, h, a, b, c, d, 0x391c0cb3ul + (w4 += sigma1(w2) + w13 + sigma0(w5)));
    Round(d, e, f, g, h, a, b, c, 0x4ed8aa4aul + (w5 += sigma1(w3) + w14 + sigma0(w6)));
    Round(c, d, e, f, g, h, a, b, 0x5b9cca4ful + (w6 += sigma1(w4) + w15 + sigma0(w7)));
    Round(b, c, d, e, f, g, h, a, 0x682e6ff3ul + (w7 += sigma1(w5) + w0 + sigma0(w8)));
    Round(a, b, c, d, e, f, g, h, 0x748f82eeul + (w8 += sigma1(w6) + w1 + sigma0(w9)));
    Round(h, a, b, c, d, e, f, g, 0x78a5636ful + (w9 += sigma1(w7) + w2 + sigma0(w10)));
    Round(g, h, a, b, c, d, e, f, 0x84c87814ul + (w10 += sigma1(w8) + w3 + sigma0(w11)));
    Round(f, g, h, a, b, c, d, e, 0x8cc70208ul + (w11 += sigma1(w9) + w4 + sigma0(w12)));
    Round(e, f, g, h, a, b, c, d, 0x90befffaul + (w12 += sigma1(w10) + w5 + sigma0(w13)));
    Round(d, e, f, g, h, a, b, c, 0xa4506cebul + (w13 += sigma1(w11) + w6 + sigma0(w14)));
    Round(c, d, e, f, g, h, a, b, 0xbef9a3f7ul + (w14 + sigma1(w12) + w7 + sigma0(w15)));
    Round(b, c, d, e, f, g, h, a, 0xc67178f2ul + (w15 + sigma1(w13) + w8 + sigma0(w0)));

    // Output
    WriteBE32(out + 0, a + 0x6a09e667ul);
    WriteBE32(out + 4, b + 0xbb67ae85ul);
    WriteBE32(out + 8, c + 0x3c6ef372ul);
    WriteBE32(out + 12, d + 0xa54ff53aul);
    WriteBE32(out + 16, e + 0x510e527ful);
    WriteBE32(out + 20, f + 0x9b05688cul);
    WriteBE32(out + 24, g + 0x1f83d9abul);
    WriteBE32(out + 28, h + 0x5be0cd19ul);

}
} // namespace sha256

typedef void (*TransformType)(uint32_t*, const unsigned char*, size_t);
typedef void (*TransformD64Type)(unsigned char*, const unsigned char*);

template<TransformType tr>
void inline TransformD64Wrapper(unsigned char* out, const unsigned char* in)
{
    alignas(16) uint32_t s[8];
    alignas(16) static const unsigned char padding1[64] = {
      0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      0,    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      0,    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      0,    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0
    };
    alignas(16) unsigned char buffer2[64] = {
      0,    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      0,    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      0,    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0
    };
    sha256::Initialize(s);
    tr(s, in, 1);
    tr(s, padding1, 1);
    WriteBE32(buffer2 + 0, s[0]);
    WriteBE32(buffer2 + 4, s[1]);
    WriteBE32(buffer2 + 8, s[2]);
    WriteBE32(buffer2 + 12, s[3]);
    WriteBE32(buffer2 + 16, s[4]);
    WriteBE32(buffer2 + 20, s[5]);
    WriteBE32(buffer2 + 24, s[6]);
    WriteBE32(buffer2 + 28, s[7]);
    sha256::Initialize(s);
    tr(s, buffer2, 1);
    WriteBE32(out + 0, s[0]);
    WriteBE32(out + 4, s[1]);
    WriteBE32(out + 8, s[2]);
    WriteBE32(out + 12, s[3]);
    WriteBE32(out + 16, s[4]);
    WriteBE32(out + 20, s[5]);
    WriteBE32(out + 24, s[6]);
    WriteBE32(out + 28, s[7]);
}

TransformType Transform = sha256::Transform;
TransformD64Type TransformD64 = sha256::TransformD64;
TransformD64Type TransformD64_2way = nullptr;
TransformD64Type TransformD64_4way = nullptr;
TransformD64Type TransformD64_8way = nullptr;

bool SelfTest() {

    // Input state (equal to the initial SHA256 state)
    alignas(16) static const uint32_t init[8] = {
      0x6a09e667ul, 0xbb67ae85ul, 0x3c6ef372ul, 0xa54ff53aul, 0x510e527ful, 0x9b05688cul, 0x1f83d9abul, 0x5be0cd19ul
    };
    // Some random input data to test with
    alignas(16) static const unsigned char data[641] = "-" // Intentionally not aligned
      "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do "
      "eiusmod tempor incididunt ut labore et dolore magna aliqua. Et m"
      "olestie ac feugiat sed lectus vestibulum mattis ullamcorper. Mor"
      "bi blandit cursus risus at ultrices mi tempus imperdiet nulla. N"
      "unc congue nisi vita suscipit tellus mauris. Imperdiet proin fer"
      "mentum leo vel orci. Massa tempor nec feugiat nisl pretium fusce"
      " id velit. Telus in metus vulputate eu scelerisque felis. Mi tem"
      "pus imperdiet nulla malesuada pellentesque. Tristique magna sit.";
    // Expected output state for hashing the i*64 first input bytes above (excluding SHA256 padding).
    alignas(16) static const uint32_t result[9][8] = {
      {0x6a09e667ul, 0xbb67ae85ul, 0x3c6ef372ul, 0xa54ff53aul, 0x510e527ful, 0x9b05688cul, 0x1f83d9abul, 0x5be0cd19ul},
      {0x91f8ec6bul, 0x4da10fe3ul, 0x1c9c292cul, 0x45e18185ul, 0x435cc111ul, 0x3ca26f09ul, 0xeb954caeul, 0x402a7069ul},
      {0xcabea5acul, 0x374fb97cul, 0x182ad996ul, 0x7bd69cbful, 0x450ff900ul, 0xc1d2be8aul, 0x6a41d505ul, 0xe6212dc3ul},
      {0xbcff09d6ul, 0x3e76f36eul, 0x3ecb2501ul, 0x78866e97ul, 0xe1c1e2fdul, 0x32f4eafful, 0x8aa6c4e5ul, 0xdfc024bcul},
      {0xa08c5d94ul, 0x0a862f93ul, 0x6b7f2f40ul, 0x8f9fae76ul, 0x6d40439ful, 0x79dcee0cul, 0x3e39ff3aul, 0xdc3bdbb1ul},
      {0x216a0895ul, 0x9f1a3662ul, 0xe99946f9ul, 0x87ba4364ul, 0x0fb5db2cul, 0x12bed3d3ul, 0x6689c0c7ul, 0x292f1b04ul},
      {0xca3067f8ul, 0xbc8c2656ul, 0x37cb7e0dul, 0x9b6b8b0ful, 0x46dc380bul, 0xf1287f57ul, 0xc42e4b23ul, 0x3fefe94dul},
      {0x3e4c4039ul, 0xbb6fca8cul, 0x6f27d2f7ul, 0x301e44a4ul, 0x8352ba14ul, 0x5769ce37ul, 0x48a1155ful, 0xc0e1c4c6ul},
      {0xfe2fa9ddul, 0x69d0862bul, 0x1ae0db23ul, 0x471f9244ul, 0xf55c0145ul, 0xc30f9c3bul, 0x40a84ea0ul, 0x5b8a266cul},
    };
    // Expected output for each of the individual 8 64-byte messages under full double SHA256 (including padding).
    alignas(16) static const unsigned char result_d64[256] = {
      0x09, 0x3a, 0xc4, 0xd0, 0x0f, 0xf7, 0x57, 0xe1, 0x72, 0x85, 0x79, 0x42, 0xfe, 0xe7, 0xe0, 0xa0,
      0xfc, 0x52, 0xd7, 0xdb, 0x07, 0x63, 0x45, 0xfb, 0x53, 0x14, 0x7d, 0x17, 0x22, 0x86, 0xf0, 0x52,
      0x48, 0xb6, 0x11, 0x9e, 0x6e, 0x48, 0x81, 0x6d, 0xcc, 0x57, 0x1f, 0xb2, 0x97, 0xa8, 0xd5, 0x25,
      0x9b, 0x82, 0xaa, 0x89, 0xe2, 0xfd, 0x2d, 0x56, 0xe8, 0x28, 0x83, 0x0b, 0xe2, 0xfa, 0x53, 0xb7,
      0xd6, 0x6b, 0x07, 0x85, 0x83, 0xb0, 0x10, 0xa2, 0xf5, 0x51, 0x3c, 0xf9, 0x60, 0x03, 0xab, 0x45,
      0x6c, 0x15, 0x6e, 0xef, 0xb5, 0xac, 0x3e, 0x6c, 0xdf, 0xb4, 0x92, 0x22, 0x2d, 0xce, 0xbf, 0x3e,
      0xe9, 0xe5, 0xf6, 0x29, 0x0e, 0x01, 0x4f, 0xd2, 0xd4, 0x45, 0x65, 0xb3, 0xbb, 0xf2, 0x4c, 0x16,
      0x37, 0x50, 0x3c, 0x6e, 0x49, 0x8c, 0x5a, 0x89, 0x2b, 0x1b, 0xab, 0xc4, 0x37, 0xd1, 0x46, 0xe9,
      0x3d, 0x0e, 0x85, 0xa2, 0x50, 0x73, 0xa1, 0x5e, 0x54, 0x37, 0xd7, 0x94, 0x17, 0x56, 0xc2, 0xd8,
      0xe5, 0x9f, 0xed, 0x4e, 0xae, 0x15, 0x42, 0x06, 0x0d, 0x74, 0x74, 0x5e, 0x24, 0x30, 0xce, 0xd1,
      0x9e, 0x50, 0xa3, 0x9a, 0xb8, 0xf0, 0x4a, 0x57, 0x69, 0x78, 0x67, 0x12, 0x84, 0x58, 0xbe, 0xc7,
      0x36, 0xaa, 0xee, 0x7c, 0x64, 0xa3, 0x76, 0xec, 0xff, 0x55, 0x41, 0x00, 0x2a, 0x44, 0x68, 0x4d,
      0xb6, 0x53, 0x9e, 0x1c, 0x95, 0xb7, 0xca, 0xdc, 0x7f, 0x7d, 0x74, 0x27, 0x5c, 0x8e, 0xa6, 0x84,
      0xb5, 0xac, 0x87, 0xa9, 0xf3, 0xff, 0x75, 0xf2, 0x34, 0xcd, 0x1a, 0x3b, 0x82, 0x2c, 0x2b, 0x4e,
      0x6a, 0x46, 0x30, 0xa6, 0x89, 0x86, 0x23, 0xac, 0xf8, 0xa5, 0x15, 0xe9, 0x0a, 0xaa, 0x1e, 0x9a,
      0xd7, 0x93, 0x6b, 0x28, 0xe4, 0x3b, 0xfd, 0x59, 0xc6, 0xed, 0x7c, 0x5f, 0xa5, 0x41, 0xcb, 0x51
    };


    // Test Transform() for 0 through 8 transformations.
    for (size_t i = 0; i <= 8; ++i) {
      alignas(16) uint32_t state[8];
      std::copy(init, init + 8, state);
      Transform(state, data + 1, i);
      if (!std::equal(state, state + 8, result[i])) { printf("SHA256 Transform test failed\n"); return false; }
    }

    // Test TransformD64
    alignas(16) unsigned char out[32];
    TransformD64(out, data + 1);
    if (!std::equal(out, out + 32, result_d64)) { printf("SHA256D Transform64 test failed\n"); return false; }

    // Test TransformD64_2way, if available.
    if (TransformD64_2way) {
      alignas(16) unsigned char out[64];
      TransformD64_2way(out, data + 1);
      if (!std::equal(out, out + 64, result_d64)) return false;
    }

    // Test TransformD64_4way, if available.
    if (TransformD64_4way) {
      alignas(16) unsigned char out[128];
      TransformD64_4way(out, data + 1);
      if (!std::equal(out, out + 128, result_d64)) return false;
    }

    // Test TransformD64_8way, if available.
    if (TransformD64_8way) {
      alignas(16) unsigned char out[256];
      TransformD64_8way(out, data + 1);
      if (!std::equal(out, out + 256, result_d64)) return false;
    }

    return true;
}

#if defined(USE_ASM) && (defined(__x86_64__) || defined(__amd64__) || defined(__i386__))
// We can't use cpuid.h's __get_cpuid as it does not support subleafs.
void inline cpuid(uint32_t leaf, uint32_t subleaf, uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d)
{
#ifdef __GNUC__
    __cpuid_count(leaf, subleaf, a, b, c, d);
#else
  __asm__ ("cpuid" : "=a"(a), "=b"(b), "=c"(c), "=d"(d) : "0"(leaf), "2"(subleaf));
#endif
}

/** Check whether the OS has enabled AVX registers. */
bool AVXEnabled()
{
    uint32_t a, d;
    __asm__("xgetbv" : "=a"(a), "=d"(d) : "c"(0));
    return (a & 6) == 6;
}
#endif
} // namespace


std::string SHA256AutoDetect()
{
    std::string ret = "standard";
#if defined(USE_ASM) && (defined(__x86_64__) || defined(__amd64__) || defined(__i386__))
    bool have_sse4 = false;
    bool have_xsave = false;
    bool have_avx = false;
    bool have_avx2 = false;
    bool have_shani = false;
    bool enabled_avx = false;

    (void)AVXEnabled;
    (void)have_sse4;
    (void)have_avx;
    (void)have_xsave;
    (void)have_avx2;
    (void)have_shani;
    (void)enabled_avx;

    uint32_t eax, ebx, ecx, edx;
    cpuid(1, 0, eax, ebx, ecx, edx);
    have_sse4 = (ecx >> 19) & 1;
    have_xsave = (ecx >> 27) & 1;
    have_avx = (ecx >> 28) & 1;
    if (have_xsave && have_avx) {
      enabled_avx = AVXEnabled();
    }
    if (have_sse4) {
      cpuid(7, 0, eax, ebx, ecx, edx);
      have_avx2 = (ebx >> 5) & 1;
      have_shani = (ebx >> 29) & 1;
    }

#if defined(ENABLE_SHANI) && !defined(BUILD_BITCOIN_INTERNAL)
    if (have_shani) {
      Transform = sha256_shani::Transform;
      TransformD64 = TransformD64Wrapper<sha256_shani::Transform>;
      TransformD64_2way = sha256d64_shani::Transform_2way;
      ret = "shani(1way,2way)";
      have_sse4 = false; // Disable SSE4/AVX2;
      have_avx2 = false;
    }
#endif

    if (have_sse4) {
#if defined(__x86_64__) || defined(__amd64__)
      Transform = sha256_sse4::Transform;
      TransformD64 = TransformD64Wrapper<sha256_sse4::Transform>;
      ret = "sse4(1way)";
#endif
#if defined(ENABLE_SSE41) && !defined(BUILD_BITCOIN_INTERNAL)
      TransformD64_4way = sha256d64_sse41::Transform_4way;
      ret += ",sse41(4way)";
#endif
    }

#if defined(ENABLE_AVX2) && !defined(BUILD_BITCOIN_INTERNAL)
    if (have_avx2 && have_avx && enabled_avx) {
      TransformD64_8way = sha256d64_avx2::Transform_8way;
      ret += ",avx2(8way)";
    }
#endif
#endif

#if defined(__aarch32__) || defined(__aarch64__)
    // Assign default sha256 transform to armv8 implementation
    Transform = sha256_armv8::Transform;
    // Route default sha256d through TransformD64Wrapper and armv8 sha256 transform
    TransformD64 = sha256_armv8::TransformD64Wrapper<sha256_armv8::Transform>;
    ret = "ArmV8 sha2 extensions";
#endif

    assert(SelfTest());
    return ret;
}

////// SHA-256

CSHA256::CSHA256() : bytes(0)
{
    sha256::Initialize(s);
}

CSHA256& CSHA256::Write(const unsigned char* data, size_t len)
{
    const unsigned char* end = data + len;
    size_t bufsize = bytes % 64;
    if (bufsize && bufsize + len >= 64) {
      // Fill the buffer, and process it.
      memcpy(buf + bufsize, data, 64 - bufsize);
      bytes += 64 - bufsize;
      data += 64 - bufsize;
      Transform(s, buf, 1);
      bufsize = 0;
    }
    if (end - data >= 64) {
      size_t blocks = (end - data) / 64;
      Transform(s, data, blocks);
      data += 64 * blocks;
      bytes += 64 * blocks;
    }
    if (end > data) {
      // Fill the buffer with what remains.
      memcpy(buf + bufsize, data, end - data);
      bytes += end - data;
    }
    return *this;
}

void CSHA256::Finalize(unsigned char hash[OUTPUT_SIZE])
{
    alignas(16) static const unsigned char pad[64] = {0x80};
    alignas(16) unsigned char sizedesc[8];
    WriteBE64(sizedesc, bytes << 3);
    Write(pad, 1 + ((119 - (bytes % 64)) % 64));
    Write(sizedesc, 8);
#if defined(__aarch32__) || defined(__aarch64__)
    sha256_armv8::WriteBE32Neon32bytes(hash, s);
#else
    WriteBE32(hash, s[0]);
    WriteBE32(hash + 4, s[1]);
    WriteBE32(hash + 8, s[2]);
    WriteBE32(hash + 12, s[3]);
    WriteBE32(hash + 16, s[4]);
    WriteBE32(hash + 20, s[5]);
    WriteBE32(hash + 24, s[6]);
    WriteBE32(hash + 28, s[7]);
#endif
}

CSHA256& CSHA256::Reset()
{
    bytes = 0;
    sha256::Initialize(s);
    return *this;
}

void SHA256D64(unsigned char* out, const unsigned char* in, size_t blocks)
{
    if (TransformD64_8way) {
      while (blocks >= 8) {
        TransformD64_8way(out, in);
        out += 256;
        in += 512;
        blocks -= 8;
      }
    }
    if (TransformD64_4way) {
      while (blocks >= 4) {
        TransformD64_4way(out, in);
        out += 128;
        in += 256;
        blocks -= 4;
      }
    }
    if (TransformD64_2way) {
      while (blocks >= 2) {
        TransformD64_2way(out, in);
        out += 64;
        in += 128;
        blocks -= 2;
      }
    }
    while (blocks) {
      TransformD64(out, in);
      out += 32;
      in += 64;
      --blocks;
    }
}
