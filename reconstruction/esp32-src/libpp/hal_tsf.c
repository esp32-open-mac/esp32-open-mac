/* ===== hal_tsf.o : reconstructed from libpp.a (ESP32, Xtensa, esp-2022r1) =====
 * Toolchain: xtensa-esp32-elf (GCC 11.2.0 crosstool-NG esp-2022r1).
 * ABI: args a2..a7, return a2 (all functions take a2..a7, return int32_t).
 * memw barriers preserved as MEMW(). MMIO as REG32/REG16/REG8(addr).
 * Calls with unknown arg counts are modeled with 4 live args (a2..a5);
 * a2..a7 are clobbered across calls (windowed-ABI approximation).
 * Sections: .text.hal_disable_nan_tsf, .text.hal_disable_softap_tsf, .text.hal_disable_sta_tsf, .text.hal_enable_nan_tsf, .text.hal_enable_sta_tsf
 * Undefined refs (0): 
 */
#include <stdint.h>
#define REG32(a) (*(volatile uint32_t *)(a))
#define REG16(a) (*(volatile uint16_t *)(a))
#define REG8(a)  (*(volatile uint8_t *)(a))
#define MEM32(a) (*(volatile uint32_t *)(a))
#define MEM16(a) (*(volatile uint16_t *)(a))
#define MEM8(a)  (*(volatile uint8_t *)(a))
#define MEMW() __asm__ volatile("memw" ::: "memory")

/* pool[hal_enable_sta_tsf]: +0x0=0x3FF75020 */
/* pool[hal_disable_sta_tsf]: +0x0=0x3FF75020, +0x4=0x67FFFFFF */
/* pool[hal_enable_nan_tsf]: +0x0=0x3FF75098 */
/* pool[hal_disable_nan_tsf]: +0x0=0x3FF75098, +0x4=0x67FFFFFF */
/* pool[hal_disable_softap_tsf]: +0x0=0x3FF7505C, +0x4=0x3DFFFFFF */

/* hal_enable_sta_tsf @ hal_tsf.o 00000004 size 29B bind GLOBAL
 * Calls: none | Data refs: none
 *   MMIO: 0x3FF75020
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t hal_enable_sta_tsf(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.hal_enable_sta_tsf; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a10 = 0x3FF75020; /* 0007: l32r a10, 0 <hal_enable_sta_tsf-0x4> (3ff75020 <hal_disable_nan_tsf+0x3ff75018>) */ /* MMIO base */ @0x0
  a9 = 0xFFFFFFF3; /* 000a: movi.n a9, -13 */
  a9 = 0x98000000; /* 000c: slli a9, a9, 27 */
  MEMW(); /* 000f: memw  */
  a8 = REG32(0x3FF75020); /* 0012: l32i.n a8, a10, 0 */ /* MMIO read: base 0x3FF75020+0 */
  a8 = a8 | a9; /* 0014: or a8, a8, a9 */
  MEMW(); /* 0017: memw  */
  REG32(0x3FF75020) = a8; /* 001a: s32i.n a8, a10, 0 */ /* MMIO write: base 0x3FF75020+0 */
  MEMW(); /* 001c: memw  */
  return (int32_t)a2; /* 001f: retw.n  */
}

/* hal_disable_sta_tsf @ hal_tsf.o 00000008 size 27B bind GLOBAL
 * Calls: none | Data refs: none
 *   MMIO: 0x3FF75020
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t hal_disable_sta_tsf(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.hal_disable_sta_tsf; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_8:;
  /* 0008: entry a1, 32 */
  a9 = 0x3FF75020; /* 000b: l32r a9, 0 <hal_disable_sta_tsf-0x8> (3ff75020 <hal_disable_sta_tsf+0x3ff75018>) */ /* MMIO base */ @0x0
  a10 = 0x67FFFFFF; /* 000e: l32r a10, 4 <hal_disable_sta_tsf-0x4> (67ffffff <hal_disable_sta_tsf+0x67fffff7>) */ @0x4
  MEMW(); /* 0011: memw  */
  a8 = REG32(0x3FF75020); /* 0014: l32i.n a8, a9, 0 */ /* MMIO read: base 0x3FF75020+0 */
  a8 = a8 & a10; /* 0016: and a8, a8, a10 */
  MEMW(); /* 0019: memw  */
  REG32(0x3FF75020) = a8; /* 001c: s32i.n a8, a9, 0 */ /* MMIO write: base 0x3FF75020+0 */
  MEMW(); /* 001e: memw  */
  return (int32_t)a2; /* 0021: retw.n  */
}

/* hal_enable_nan_tsf @ hal_tsf.o 00000004 size 29B bind GLOBAL
 * Calls: none | Data refs: none
 *   MMIO: 0x3FF75098
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t hal_enable_nan_tsf(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.hal_enable_nan_tsf; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a10 = 0x3FF75098; /* 0007: l32r a10, 0 <hal_enable_nan_tsf-0x4> (3ff75098 <hal_disable_nan_tsf+0x3ff75090>) */ /* MMIO base */ @0x0
  a9 = 0xFFFFFFF3; /* 000a: movi.n a9, -13 */
  a9 = 0x98000000; /* 000c: slli a9, a9, 27 */
  MEMW(); /* 000f: memw  */
  a8 = REG32(0x3FF75098); /* 0012: l32i.n a8, a10, 0 */ /* MMIO read: base 0x3FF75098+0 */
  a8 = a8 | a9; /* 0014: or a8, a8, a9 */
  MEMW(); /* 0017: memw  */
  REG32(0x3FF75098) = a8; /* 001a: s32i.n a8, a10, 0 */ /* MMIO write: base 0x3FF75098+0 */
  MEMW(); /* 001c: memw  */
  return (int32_t)a2; /* 001f: retw.n  */
}

/* hal_disable_nan_tsf @ hal_tsf.o 00000008 size 27B bind GLOBAL
 * Calls: none | Data refs: none
 *   MMIO: 0x3FF75098
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t hal_disable_nan_tsf(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.hal_disable_nan_tsf; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_8:;
  /* 0008: entry a1, 32 */
  a9 = 0x3FF75098; /* 000b: l32r a9, 0 <hal_disable_nan_tsf-0x8> (3ff75098 <hal_disable_nan_tsf+0x3ff75090>) */ /* MMIO base */ @0x0
  a10 = 0x67FFFFFF; /* 000e: l32r a10, 4 <hal_disable_nan_tsf-0x4> (67ffffff <hal_disable_nan_tsf+0x67fffff7>) */ @0x4
  MEMW(); /* 0011: memw  */
  a8 = REG32(0x3FF75098); /* 0014: l32i.n a8, a9, 0 */ /* MMIO read: base 0x3FF75098+0 */
  a8 = a8 & a10; /* 0016: and a8, a8, a10 */
  MEMW(); /* 0019: memw  */
  REG32(0x3FF75098) = a8; /* 001c: s32i.n a8, a9, 0 */ /* MMIO write: base 0x3FF75098+0 */
  MEMW(); /* 001e: memw  */
  return (int32_t)a2; /* 0021: retw.n  */
}

/* hal_disable_softap_tsf @ hal_tsf.o 00000008 size 27B bind GLOBAL
 * Calls: none | Data refs: none
 *   MMIO: 0x3FF7505C
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t hal_disable_softap_tsf(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.hal_disable_softap_tsf; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_8:;
  /* 0008: entry a1, 32 */
  a9 = 0x3FF7505C; /* 000b: l32r a9, 0 <hal_disable_softap_tsf-0x8> (3ff7505c <hal_disable_softap_tsf+0x3ff75054>) */ /* MMIO base */ @0x0
  a10 = 0x3DFFFFFF; /* 000e: l32r a10, 4 <hal_disable_softap_tsf-0x4> (3dffffff <hal_disable_softap_tsf+0x3dfffff7>) */ @0x4
  MEMW(); /* 0011: memw  */
  a8 = REG32(0x3FF7505C); /* 0014: l32i.n a8, a9, 0 */ /* MMIO read: base 0x3FF7505C+0 */
  a8 = a8 & a10; /* 0016: and a8, a8, a10 */
  MEMW(); /* 0019: memw  */
  REG32(0x3FF7505C) = a8; /* 001c: s32i.n a8, a9, 0 */ /* MMIO write: base 0x3FF7505C+0 */
  MEMW(); /* 001e: memw  */
  return (int32_t)a2; /* 0021: retw.n  */
}

