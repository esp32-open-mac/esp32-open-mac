/* ===== hal_sniffer.o : reconstructed from libpp.a (ESP32, Xtensa, esp-2022r1) =====
 * Toolchain: xtensa-esp32-elf (GCC 11.2.0 crosstool-NG esp-2022r1).
 * ABI: args a2..a7, return a2 (all functions take a2..a7, return int32_t).
 * memw barriers preserved as MEMW(). MMIO as REG32/REG16/REG8(addr).
 * Calls with unknown arg counts are modeled with 4 live args (a2..a5);
 * a2..a7 are clobbered across calls (windowed-ABI approximation).
 * Sections: .text.hal_sniffer_disable, .text.hal_sniffer_enable, .text.hal_sniffer_rx_clr_statistics, .text.hal_sniffer_rx_set_promis
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

/* pool[hal_sniffer_enable]: +0x0=0x3FF730E4 */
/* pool[hal_sniffer_disable]: +0x0=0x3FF730E4, +0x4=0xFFFF7FFF */
/* pool[hal_sniffer_rx_set_promis]: +0x0=0x3FF73C40, +0x4=0x3FF73104, +0x8=0x3FF730F8, +0xc=0x3FF730FC */
/* pool[hal_sniffer_rx_clr_statistics]: +0x0=0x3FF73D7C, +0x4=0x7FFFFFFF */

/* hal_sniffer_enable @ hal_sniffer.o 00000004 size 135B bind GLOBAL
 * Calls: none | Data refs: none
 *   MMIO: 0x3FF730E4
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: medium - 53 instr, 0 branches, calls resolved */
int32_t hal_sniffer_enable(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.hal_sniffer_enable; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a8 = 0x3FF730E4; /* 0007: l32r a8, 0 <hal_sniffer_enable-0x4> (3ff730e4 <hal_sniffer_rx_set_promis+0x3ff730d4>) */ /* MMIO base */ @0x0
  a10 = 0x1; /* 000a: movi.n a10, 1 */
  a10 = 0x8000; /* 000c: slli a10, a10, 15 */
  MEMW(); /* 000f: memw  */
  a9 = REG32(0x3FF730E4); /* 0012: l32i.n a9, a8, 0 */ /* MMIO read: base 0x3FF730E4+0 */
  a9 = a9 | a10; /* 0014: or a9, a9, a10 */
  a10 = 0xFFFFFFFE; /* 0017: movi.n a10, -2 */
  MEMW(); /* 0019: memw  */
  REG32(0x3FF730E4) = a9; /* 001c: s32i.n a9, a8, 0 */ /* MMIO write: base 0x3FF730E4+0 */
  MEMW(); /* 001e: memw  */
  a9 = REG32(0x3FF730E4); /* 0021: l32i.n a9, a8, 0 */ /* MMIO read: base 0x3FF730E4+0 */
  a9 = a9 & a10; /* 0023: and a9, a9, a10 */
  a10 = 0xFFFFFFFD; /* 0026: movi.n a10, -3 */
  MEMW(); /* 0028: memw  */
  REG32(0x3FF730E4) = a9; /* 002b: s32i.n a9, a8, 0 */ /* MMIO write: base 0x3FF730E4+0 */
  MEMW(); /* 002d: memw  */
  a9 = REG32(0x3FF730E4); /* 0030: l32i.n a9, a8, 0 */ /* MMIO read: base 0x3FF730E4+0 */
  a9 = a9 & a10; /* 0032: and a9, a9, a10 */
  a10 = 0xFFFFFFFB; /* 0035: movi.n a10, -5 */
  MEMW(); /* 0037: memw  */
  REG32(0x3FF730E4) = a9; /* 003a: s32i.n a9, a8, 0 */ /* MMIO write: base 0x3FF730E4+0 */
  MEMW(); /* 003c: memw  */
  a9 = REG32(0x3FF730E4); /* 003f: l32i.n a9, a8, 0 */ /* MMIO read: base 0x3FF730E4+0 */
  a9 = a9 & a10; /* 0041: and a9, a9, a10 */
  a10 = 0xFFFFFFF7; /* 0044: movi.n a10, -9 */
  MEMW(); /* 0046: memw  */
  REG32(0x3FF730E4) = a9; /* 0049: s32i.n a9, a8, 0 */ /* MMIO write: base 0x3FF730E4+0 */
  MEMW(); /* 004b: memw  */
  a9 = REG32(0x3FF730E4); /* 004e: l32i.n a9, a8, 0 */ /* MMIO read: base 0x3FF730E4+0 */
  a9 = a9 & a10; /* 0050: and a9, a9, a10 */
  a10 = 0x20; /* 0053: movi.n a10, 32 */
  MEMW(); /* 0055: memw  */
  REG32(0x3FF730E4) = a9; /* 0058: s32i.n a9, a8, 0 */ /* MMIO write: base 0x3FF730E4+0 */
  MEMW(); /* 005a: memw  */
  a9 = REG32(0x3FF730E4); /* 005d: l32i.n a9, a8, 0 */ /* MMIO read: base 0x3FF730E4+0 */
  a9 = a9 | a10; /* 005f: or a9, a9, a10 */
  a10 = 0x40; /* 0062: movi.n a10, 64 */
  MEMW(); /* 0064: memw  */
  REG32(0x3FF730E4) = a9; /* 0067: s32i.n a9, a8, 0 */ /* MMIO write: base 0x3FF730E4+0 */
  MEMW(); /* 0069: memw  */
  a9 = REG32(0x3FF730E4); /* 006c: l32i.n a9, a8, 0 */ /* MMIO read: base 0x3FF730E4+0 */
  a9 = a9 | a10; /* 006e: or a9, a9, a10 */
  a10 = 0x80; /* 0071: movi a10, 128 */
  MEMW(); /* 0074: memw  */
  REG32(0x3FF730E4) = a9; /* 0077: s32i.n a9, a8, 0 */ /* MMIO write: base 0x3FF730E4+0 */
  MEMW(); /* 0079: memw  */
  a9 = REG32(0x3FF730E4); /* 007c: l32i.n a9, a8, 0 */ /* MMIO read: base 0x3FF730E4+0 */
  a9 = a9 | a10; /* 007e: or a9, a9, a10 */
  MEMW(); /* 0081: memw  */
  REG32(0x3FF730E4) = a9; /* 0084: s32i.n a9, a8, 0 */ /* MMIO write: base 0x3FF730E4+0 */
  MEMW(); /* 0086: memw  */
  return (int32_t)a2; /* 0089: retw.n  */
}

/* hal_sniffer_disable @ hal_sniffer.o 00000008 size 135B bind GLOBAL
 * Calls: none | Data refs: none
 *   MMIO: 0x3FF730E4
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: medium - 52 instr, 0 branches, calls resolved */
int32_t hal_sniffer_disable(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.hal_sniffer_disable; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_8:;
  /* 0008: entry a1, 32 */
  a8 = 0x3FF730E4; /* 000b: l32r a8, 0 <hal_sniffer_disable-0x8> (3ff730e4 <hal_sniffer_rx_set_promis+0x3ff730d4>) */ /* MMIO base */ @0x0
  a10 = 0xFFFF7FFF; /* 000e: l32r a10, 4 <hal_sniffer_disable-0x4> (ffff7fff <hal_sniffer_rx_set_promis+0xffff7fef>) */ @0x4
  MEMW(); /* 0011: memw  */
  a9 = REG32(0x3FF730E4); /* 0014: l32i.n a9, a8, 0 */ /* MMIO read: base 0x3FF730E4+0 */
  a9 = a9 & a10; /* 0016: and a9, a9, a10 */
  a10 = 0x1; /* 0019: movi.n a10, 1 */
  MEMW(); /* 001b: memw  */
  REG32(0x3FF730E4) = a9; /* 001e: s32i.n a9, a8, 0 */ /* MMIO write: base 0x3FF730E4+0 */
  MEMW(); /* 0020: memw  */
  a9 = REG32(0x3FF730E4); /* 0023: l32i.n a9, a8, 0 */ /* MMIO read: base 0x3FF730E4+0 */
  a9 = a9 | a10; /* 0025: or a9, a9, a10 */
  a10 = 0x2; /* 0028: movi.n a10, 2 */
  MEMW(); /* 002a: memw  */
  REG32(0x3FF730E4) = a9; /* 002d: s32i.n a9, a8, 0 */ /* MMIO write: base 0x3FF730E4+0 */
  MEMW(); /* 002f: memw  */
  a9 = REG32(0x3FF730E4); /* 0032: l32i.n a9, a8, 0 */ /* MMIO read: base 0x3FF730E4+0 */
  a9 = a9 | a10; /* 0034: or a9, a9, a10 */
  a10 = 0x4; /* 0037: movi.n a10, 4 */
  MEMW(); /* 0039: memw  */
  REG32(0x3FF730E4) = a9; /* 003c: s32i.n a9, a8, 0 */ /* MMIO write: base 0x3FF730E4+0 */
  MEMW(); /* 003e: memw  */
  a9 = REG32(0x3FF730E4); /* 0041: l32i.n a9, a8, 0 */ /* MMIO read: base 0x3FF730E4+0 */
  a9 = a9 | a10; /* 0043: or a9, a9, a10 */
  a10 = 0x8; /* 0046: movi.n a10, 8 */
  MEMW(); /* 0048: memw  */
  REG32(0x3FF730E4) = a9; /* 004b: s32i.n a9, a8, 0 */ /* MMIO write: base 0x3FF730E4+0 */
  MEMW(); /* 004d: memw  */
  a9 = REG32(0x3FF730E4); /* 0050: l32i.n a9, a8, 0 */ /* MMIO read: base 0x3FF730E4+0 */
  a9 = a9 | a10; /* 0052: or a9, a9, a10 */
  a10 = 0xFFFFFFDF; /* 0055: movi a10, -33 */
  MEMW(); /* 0058: memw  */
  REG32(0x3FF730E4) = a9; /* 005b: s32i.n a9, a8, 0 */ /* MMIO write: base 0x3FF730E4+0 */
  MEMW(); /* 005d: memw  */
  a9 = REG32(0x3FF730E4); /* 0060: l32i.n a9, a8, 0 */ /* MMIO read: base 0x3FF730E4+0 */
  a9 = a9 & a10; /* 0062: and a9, a9, a10 */
  a10 = 0xFFFFFFBF; /* 0065: movi a10, -65 */
  MEMW(); /* 0068: memw  */
  REG32(0x3FF730E4) = a9; /* 006b: s32i.n a9, a8, 0 */ /* MMIO write: base 0x3FF730E4+0 */
  MEMW(); /* 006d: memw  */
  a9 = REG32(0x3FF730E4); /* 0070: l32i.n a9, a8, 0 */ /* MMIO read: base 0x3FF730E4+0 */
  a9 = a9 & a10; /* 0072: and a9, a9, a10 */
  a10 = 0xFFFFFF7F; /* 0075: movi a10, -129 */
  MEMW(); /* 0078: memw  */
  REG32(0x3FF730E4) = a9; /* 007b: s32i.n a9, a8, 0 */ /* MMIO write: base 0x3FF730E4+0 */
  MEMW(); /* 007d: memw  */
  a9 = REG32(0x3FF730E4); /* 0080: l32i.n a9, a8, 0 */ /* MMIO read: base 0x3FF730E4+0 */
  a9 = a9 & a10; /* 0082: and a9, a9, a10 */
  MEMW(); /* 0085: memw  */
  REG32(0x3FF730E4) = a9; /* 0088: s32i.n a9, a8, 0 */ /* MMIO write: base 0x3FF730E4+0 */
  MEMW(); /* 008a: memw  */
  return (int32_t)a2; /* 008d: retw.n  */
}

/* hal_sniffer_rx_set_promis @ hal_sniffer.o 00000010 size 182B bind GLOBAL
 * Calls: none | Data refs: none
 *   MMIO: 0x3FF73C40, 0x3FF73104, 0x3FF730F8, 0x3FF730FC
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: medium - 72 instr, 7 branches, calls resolved */
int32_t hal_sniffer_rx_set_promis(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.hal_sniffer_rx_set_promis; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_10:;
  /* 0010: entry a1, 32 */
  a3 = (a3 >> 0) & 0xFF; /* 0013: extui a3, a3, 0, 8 */
  if (a2 == 0) goto L_20; /* 0016: beqz.n a2, 20 <hal_sniffer_rx_set_promis+0x10> */
  if (a2 == 1) goto L_35; /* 0018: beqi a2, 1, 35 <hal_sniffer_rx_set_promis+0x25> */
  goto L_c1; /* 001b: j c1 <hal_sniffer_rx_set_promis+0xb1> */
  /* 001e: .byte 00 */
  /* 001f: .byte 00 */
L_20:;
  a8 = 0x3FF73C40; /* 0020: l32r a8, 0 <hal_sniffer_rx_set_promis-0x10> (3ff73c40 <hal_sniffer_rx_set_promis+0x3ff73c30>) */ /* MMIO base */ @0x0
  a4 = 0xFFFFFFFB; /* 0023: movi.n a4, -5 */
  MEMW(); /* 0025: memw  */
  a9 = REG32(0x3FF73C40); /* 0028: l32i.n a9, a8, 0 */ /* MMIO read: base 0x3FF73C40+0 */
  a4 = a9 & a4; /* 002a: and a4, a9, a4 */
  if (a3 == 0) goto L_bc; /* 002d: beqz a3, bc <hal_sniffer_rx_set_promis+0xac> */
  a4 = 0x4; /* 0030: movi.n a4, 4 */
  goto L_b9; /* 0032: j b9 <hal_sniffer_rx_set_promis+0xa9> */
L_35:;
  a8 = 0x3FF73104; /* 0035: l32r a8, 4 <hal_sniffer_rx_set_promis-0xc> (3ff73104 <hal_sniffer_rx_set_promis+0x3ff730f4>) */ /* MMIO base */ @0x4
  MEMW(); /* 0038: memw  */
  a9 = REG32(0x3FF73104); /* 003b: l32i.n a9, a8, 0 */ /* MMIO read: base 0x3FF73104+0 */
  a9 = (a9 >> 0) & 0xFFFF; /* 003d: extui a9, a9, 0, 16 */
  MEMW(); /* 0040: memw  */
  REG32(0x3FF73104) = a9; /* 0043: s32i.n a9, a8, 0 */ /* MMIO write: base 0x3FF73104+0 */
  if (a3 == 0) goto L_7d; /* 0045: beqz.n a3, 7d <hal_sniffer_rx_set_promis+0x6d> */
  MEMW(); /* 0047: memw  */
  a9 = REG32(0x3FF73104); /* 004a: l32i.n a9, a8, 0 */ /* MMIO read: base 0x3FF73104+0 */
  a9 = a9 | a4; /* 004c: or a9, a9, a4 */
  MEMW(); /* 004f: memw  */
  REG32(0x3FF73104) = a9; /* 0052: s32i.n a9, a8, 0 */ /* MMIO write: base 0x3FF73104+0 */
  a9 = 0x3FF730F8; /* 0054: l32r a9, 8 <hal_sniffer_rx_set_promis-0x8> (3ff730f8 <hal_sniffer_rx_set_promis+0x3ff730e8>) */ /* MMIO base */ @0x8
  MEMW(); /* 0057: memw  */
  a8 = REG32(0x3FF730F8); /* 005a: l32i.n a8, a9, 0 */ /* MMIO read: base 0x3FF730F8+0 */
  a8 = a8 | a4; /* 005c: or a8, a8, a4 */
  MEMW(); /* 005f: memw  */
  REG32(0x3FF730F8) = a8; /* 0062: s32i.n a8, a9, 0 */ /* MMIO write: base 0x3FF730F8+0 */
  a9 = 0x3FF730FC; /* 0064: l32r a9, c <hal_sniffer_rx_set_promis-0x4> (3ff730fc <hal_sniffer_rx_set_promis+0x3ff730ec>) */ /* MMIO base */ @0xC
  MEMW(); /* 0067: memw  */
  a8 = REG32(0x3FF730FC); /* 006a: l32i.n a8, a9, 0 */ /* MMIO read: base 0x3FF730FC+0 */
  a8 = a8 | a4; /* 006c: or a8, a8, a4 */
  MEMW(); /* 006f: memw  */
  REG32(0x3FF730FC) = a8; /* 0072: s32i.n a8, a9, 0 */ /* MMIO write: base 0x3FF730FC+0 */
  MEMW(); /* 0074: memw  */
  goto L_c1; /* 0077: j c1 <hal_sniffer_rx_set_promis+0xb1> */
  /* 007a: .byte 00 */
  /* 007b: .byte 00 */
  /* 007c: .byte 00 */
L_7d:;
  a9 = 0x3FF730F8; /* 007d: l32r a9, 8 <hal_sniffer_rx_set_promis-0x8> (3ff730f8 <hal_sniffer_rx_set_promis+0x3ff730e8>) */ /* MMIO base */ @0x8
  a8 = 0xFFFFFFFF; /* 0080: movi.n a8, -1 */
  a4 = 0xFFFFFFFB; /* 0082: xor a4, a8, a4 */
  MEMW(); /* 0085: memw  */
  a10 = REG32(0x3FF730F8); /* 0088: l32i.n a10, a9, 0 */ /* MMIO read: base 0x3FF730F8+0 */
  a10 = a10 & a4; /* 008a: and a10, a10, a4 */
  a8 = 0x3FF730FC; /* 008d: l32r a8, c <hal_sniffer_rx_set_promis-0x4> (3ff730fc <hal_sniffer_rx_set_promis+0x3ff730ec>) */ /* MMIO base */ @0xC
  MEMW(); /* 0090: memw  */
  REG32(0x3FF730F8) = a10; /* 0093: s32i.n a10, a9, 0 */ /* MMIO write: base 0x3FF730F8+0 */
  MEMW(); /* 0095: memw  */
  a2 = REG32(0x3FF730FC); /* 0098: l32i.n a2, a8, 0 */ /* MMIO read: base 0x3FF730FC+0 */
  a4 = a4 & a2; /* 009a: and a4, a4, a2 */
  MEMW(); /* 009d: memw  */
  REG32(0x3FF730FC) = a4; /* 00a0: s32i.n a4, a8, 0 */ /* MMIO write: base 0x3FF730FC+0 */
  a4 = 0x5; /* 00a2: movi.n a4, 5 */
  a4 = 0x5000000; /* 00a4: slli a4, a4, 24 */
  MEMW(); /* 00a7: memw  */
  a10 = REG32(0x3FF730F8); /* 00aa: l32i.n a10, a9, 0 */ /* MMIO read: base 0x3FF730F8+0 */
  a10 = a10 | a4; /* 00ac: or a10, a10, a4 */
  MEMW(); /* 00af: memw  */
  REG32(0x3FF730F8) = a10; /* 00b2: s32i.n a10, a9, 0 */ /* MMIO write: base 0x3FF730F8+0 */
  MEMW(); /* 00b4: memw  */
  a9 = REG32(0x3FF730FC); /* 00b7: l32i.n a9, a8, 0 */ /* MMIO read: base 0x3FF730FC+0 */
L_b9:;
  a4 = a9 | a4; /* 00b9: or a4, a9, a4 */
L_bc:;
  MEMW(); /* 00bc: memw  */
  REG32(0x3FF730FC) = a4; /* 00bf: s32i.n a4, a8, 0 */ /* MMIO write: base 0x3FF730FC+0 */
L_c1:;
  MEMW(); /* 00c1: memw  */
  return (int32_t)a2; /* 00c4: retw.n  */
}

/* hal_sniffer_rx_clr_statistics @ hal_sniffer.o 00000008 size 45B bind GLOBAL
 * Calls: none | Data refs: none
 *   MMIO: 0x3FF73D7C
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t hal_sniffer_rx_clr_statistics(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.hal_sniffer_rx_clr_statistics; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_8:;
  /* 0008: entry a1, 32 */
  a8 = 0x3FF73D7C; /* 000b: l32r a8, 0 <hal_sniffer_rx_clr_statistics-0x8> (3ff73d7c <hal_sniffer_rx_set_promis+0x3ff73d6c>) */ /* MMIO base */ @0x0
  a10 = 0xFFFFFFFF; /* 000e: movi.n a10, -1 */
  a10 = 0x80000000; /* 0010: slli a10, a10, 31 */
  MEMW(); /* 0013: memw  */
  a9 = REG32(0x3FF73D7C); /* 0016: l32i.n a9, a8, 0 */ /* MMIO read: base 0x3FF73D7C+0 */
  a9 = a9 | a10; /* 0018: or a9, a9, a10 */
  MEMW(); /* 001b: memw  */
  REG32(0x3FF73D7C) = a9; /* 001e: s32i.n a9, a8, 0 */ /* MMIO write: base 0x3FF73D7C+0 */
  MEMW(); /* 0020: memw  */
  a9 = REG32(0x3FF73D7C); /* 0023: l32i.n a9, a8, 0 */ /* MMIO read: base 0x3FF73D7C+0 */
  a10 = 0x7FFFFFFF; /* 0025: l32r a10, 4 <hal_sniffer_rx_clr_statistics-0x4> (7fffffff <hal_sniffer_rx_set_promis+0x7fffffef>) */ @0x4
  a9 = a9 & a10; /* 0028: and a9, a9, a10 */
  MEMW(); /* 002b: memw  */
  REG32(0x3FF73D7C) = a9; /* 002e: s32i.n a9, a8, 0 */ /* MMIO write: base 0x3FF73D7C+0 */
  MEMW(); /* 0030: memw  */
  return (int32_t)a2; /* 0033: retw.n  */
}

