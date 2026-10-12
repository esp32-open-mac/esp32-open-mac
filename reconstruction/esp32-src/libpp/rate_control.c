/* ===== rate_control.o : reconstructed from libpp.a (ESP32, Xtensa, esp-2022r1) =====
 * Toolchain: xtensa-esp32-elf (GCC 11.2.0 crosstool-NG esp-2022r1).
 * ABI: args a2..a7, return a2 (all functions take a2..a7, return int32_t).
 * memw barriers preserved as MEMW(). MMIO as REG32/REG16/REG8(addr).
 * Calls with unknown arg counts are modeled with 4 live args (a2..a5);
 * a2..a7 are clobbered across calls (windowed-ABI approximation).
 * Sections: .text.RC_GetAckRate, .text.RC_GetAckTime, .text.RC_GetBlockAckTime, .text.RC_GetCtsTime, .text.RC_GetDuration, .text.RC_GetRtsRate, .text.RC_SetBasicRate
 * Undefined refs (0): 

 * RATE CONTROL ALGORITHM (recovered from disasm + .rodata.our_controls):
 * - Rate index space: legacy rates 0..7 (CCK/OFDM per 802.11b/g), HT/MCS rates
 *   >= 8 selected via separate MCS table region (rodata offset 0x100+).
 * - Per-rate entry: 8 bytes: [+0 u32 duration factor][+4 u16 ack-time us]
 *   [+6 u8 ack-rate idx][+7 u8 flags]. RC_GetAckRate/RC_GetRtsRate return
 *   entry[rate & 0xFF].ack_rate (byte +6); RC_GetAckTime returns
 *   entry[ack_rate].ack_time (u16 +4) -- i.e. ACK time is looked up through
 *   the ACK rate, not the TX rate directly.
 * - RC_GetDuration(rate, len_bits, ...): len_bits = len<<3 (+22 for MCS rates,
 *   covering SERVICE/tail); fixed-point multiply of len_bits by the u32 rate
 *   factor emulated with 9/18-bit split 32x32->64 emulation (extui/mull ladder
 *   + shifts 9/18), small-len fast path when len_bits > 0x3FFF; legacy rates
 *   round up to 4 us (mask ~3). No per-STA state lives here: this object is
 *   pure arithmetic over the shared our_controls table; per-STA retry/probe
 *   state (if any) lives in the net80211/lmac layer that calls these helpers.
 * - RC_SetBasicRate is a no-op stub (returns 0).
 * - RC_GetCtsTime/RC_GetBlockAckTime: SIFS select (10 vs 16 us by rate class),
 *   preamble+PLCP select (0x120/192/96 by modulation class: CCK-short/long vs
 *   OFDM; MCS branch adds BAR+moving-avg term), then + RC_GetDuration(...)+30.

 * .rodata.our_controls decoded (first 16 legacy entries, 8B each):
 * idx | dur_factor | ack_us | ackrate | b7
 *   0 | 0x00040000 |   314 |   0 | 0x00
 *   1 | 0x00020000 |   258 |   5 | 0x00
 *   2 | 0x0000BA2E |   223 |   6 | 0x00
 *   3 | 0x00005D17 |   213 |   7 | 0x00
 *   4 | 0x00040000 |   314 |   4 | 0x00
 *   5 | 0x00020000 |   162 |   5 | 0x00
 *   6 | 0x0000BA2E |   127 |   6 | 0x00
 *   7 | 0x00005D17 |   117 |   7 | 0x00
 *   8 | 0x00001555 |    44 |   9 | 0x00
 *   9 | 0x00002AAA |    44 |   9 | 0x00
 *  10 | 0x00005555 |    48 |  10 | 0x00
 *  11 | 0x0000AAAA |    60 |  11 | 0x00
 *  12 | 0x000012F6 |    44 |   9 | 0x00
 *  13 | 0x00001C71 |    44 |   9 | 0x00
 *  14 | 0x000038E3 |    48 |  10 | 0x00
 *  15 | 0x000071C7 |    60 |  11 | 0x00
 */
#include <stdint.h>
#define REG32(a) (*(volatile uint32_t *)(a))
#define REG16(a) (*(volatile uint16_t *)(a))
#define REG8(a)  (*(volatile uint8_t *)(a))
#define MEM32(a) (*(volatile uint32_t *)(a))
#define MEM16(a) (*(volatile uint16_t *)(a))
#define MEM8(a)  (*(volatile uint8_t *)(a))
#define MEMW() __asm__ volatile("memw" ::: "memory")

extern uint32_t rodata_our_controls; /* .rodata.our_controls */

/* pool[RC_GetDuration]: +0x0=0x00000000, +0x4=0x00003FFF, +0x8=0x0003FFFF */
/* pool[RC_GetAckRate]: +0x0=0x00000000(.rodata.our_controls) */
/* pool[RC_GetRtsRate]: +0x0=0x00000000(.rodata.our_controls) */
/* pool[RC_GetAckTime]: +0x0=0x00000000(.rodata.our_controls) */
/* pool[RC_GetCtsTime]: +0x0=0x0000000C(.text.RC_GetDuration) */
/* pool[RC_GetBlockAckTime]: +0x0=0x00000000(.rodata.our_controls), +0x4=0x0000000C(.text.RC_GetDuration) */

/* RC_SetBasicRate @ rate_control.o 00000000 size 7B bind GLOBAL
 * Calls: none | Data refs: none
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t RC_SetBasicRate(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.RC_SetBasicRate; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_0:;
  /* 0000: entry a1, 32 */
  a2 = 0x0; /* 0003: movi.n a2, 0 */
  return (int32_t)a2; /* 0005: retw.n  */
}

/* RC_GetAckRate @ rate_control.o 00000004 size 17B bind GLOBAL
 * Calls: none | Data refs: .rodata.our_controls
 *   MMIO: none
 *   funcdb v3: 0 call(s), 1 ref(s); disasm: 0 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t RC_GetAckRate(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.RC_GetAckRate; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a8 = (uint32_t)&lit_rodata_our_controls; /* 0007: l32r a8, 0 <RC_GetAckRate-0x4> (0 <RC_GetAckRate-0x4>) */ /* literal @0x0: .rodata.our_controls */
  a2 = (a2 >> 0) & 0xFF; /* 000a: extui a2, a2, 0, 8 */
  a2 = (a2 << 8) + a8; /* 000d: addx8 a2, a2, a8 */
  a2 = MEM8(a2 + 6); /* 0010: l8ui a2, a2, 6 */
  return (int32_t)a2; /* 0013: retw.n  */
}

/* RC_GetRtsRate @ rate_control.o 00000004 size 17B bind GLOBAL
 * Calls: none | Data refs: .rodata.our_controls
 *   MMIO: none
 *   funcdb v3: 0 call(s), 1 ref(s); disasm: 0 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t RC_GetRtsRate(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.RC_GetRtsRate; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a8 = (uint32_t)&lit_rodata_our_controls; /* 0007: l32r a8, 0 <RC_GetRtsRate-0x4> (0 <RC_GetRtsRate-0x4>) */ /* literal @0x0: .rodata.our_controls */
  a2 = (a2 >> 0) & 0xFF; /* 000a: extui a2, a2, 0, 8 */
  a2 = (a2 << 8) + a8; /* 000d: addx8 a2, a2, a8 */
  a2 = MEM8(a2 + 6); /* 0010: l8ui a2, a2, 6 */
  return (int32_t)a2; /* 0013: retw.n  */
}

/* RC_GetAckTime @ rate_control.o 00000004 size 23B bind GLOBAL
 * Calls: none | Data refs: .rodata.our_controls
 *   MMIO: none
 *   funcdb v3: 0 call(s), 1 ref(s); disasm: 0 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t RC_GetAckTime(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.RC_GetAckTime; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a9 = (uint32_t)&lit_rodata_our_controls; /* 0007: l32r a9, 0 <RC_GetAckTime-0x4> (0 <RC_GetAckTime-0x4>) */ /* literal @0x0: .rodata.our_controls */
  a2 = (a2 >> 0) & 0xFF; /* 000a: extui a2, a2, 0, 8 */
  a2 = (a2 << 8) + a9; /* 000d: addx8 a2, a2, a9 */
  a8 = MEM8(a2 + 6); /* 0010: l8ui a8, a2, 6 */
  a8 = (a8 << 8) + a9; /* 0013: addx8 a8, a8, a9 */
  a2 = MEM16(a8 + 4); /* 0016: l16ui a2, a8, 4 */
  return (int32_t)a2; /* 0019: retw.n  */
}

/* RC_GetCtsTime @ rate_control.o 00000004 size 73B bind GLOBAL
 * Calls: .text.RC_GetDuration[got] | Data refs: .text.RC_GetDuration
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 1 call(s), 1 data ref(s)
 * Fidelity: medium - 27 instr, 5 branches, calls resolved */
int32_t RC_GetCtsTime(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.RC_GetCtsTime; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a10 = (a2 >> 0) & 0xFF; /* 0007: extui a10, a2, 0, 8 */
  a11 = (a3 >> 0) & 0xFFFF; /* 000a: extui a11, a3, 0, 16 */
  a4 = (a4 >> 0) & 0xFFFF; /* 000d: extui a4, a4, 0, 16 */
  a8 = 0xA; /* 0010: movi.n a8, 10 */
  if (a10 < 8) goto L_18; /* 0012: bltui a10, 8, 18 <RC_GetCtsTime+0x14> */
  a8 = 0x10; /* 0015: movi a8, 16 */
L_18:;
  a9 = a10 + (-41); /* 0018: addi a9, a10, -41 */
  a9 = (a9 >> 0) & 0xFF; /* 001b: extui a9, a9, 0, 8 */
  a5 = 0x120; /* 001e: movi a5, 0x120 */
  if (a9 < 2) goto L_39; /* 0021: bltui a9, 2, 39 <RC_GetCtsTime+0x35> */
  a5 = 0xC0; /* 0024: movi a5, 192 */
  if (a10 < 5) goto L_39; /* 0027: bltui a10, 5, 39 <RC_GetCtsTime+0x35> */
  a5 = 0x60; /* 002a: movi a5, 96 */
  if (a10 < 8) goto L_39; /* 002d: bltui a10, 8, 39 <RC_GetCtsTime+0x35> */
  a9 = 0xF; /* 0030: movi.n a9, 15 */
  a5 = 0x24; /* 0032: movi.n a5, 36 */
  if (a9 < a10) goto L_39; /* 0034: bltu a9, a10, 39 <RC_GetCtsTime+0x35> */
  a5 = 0x14; /* 0037: movi.n a5, 20 */
L_39:;
  a8 = a8 + a4; /* 0039: add.n a8, a8, a4 */
  a4 = (a8 >> 0) & 0xFFFF; /* 003b: extui a4, a8, 0, 16 */
  a5 = a5 + a4; /* 003e: add.n a5, a5, a4 */
  a8 = (uint32_t)&RC_GetDuration; /* 0040: l32r a8, 0 <RC_GetCtsTime-0x4> (c <RC_GetCtsTime+0x8>) */ /* literal: GOT slot for .text.RC_GetDuration */
  RC_GetDuration(a2, a3, a4, a5); /* call via literal slot */ /* 0043: callx8 a8 */
  a5 = a10 + a5; /* 0046: add.n a5, a10, a5 */
  a2 = (a5 >> 0) & 0xFFFF; /* 0048: extui a2, a5, 0, 16 */
  return (int32_t)a2; /* 004b: retw.n  */
}

/* RC_GetBlockAckTime @ rate_control.o 00000008 size 74B bind GLOBAL
 * Calls: .text.RC_GetDuration[got] | Data refs: .rodata.our_controls, .text.RC_GetDuration
 *   MMIO: none
 *   funcdb v3: 0 call(s), 1 ref(s); disasm: 1 call(s), 2 data ref(s)
 * Fidelity: medium - 27 instr, 5 branches, calls resolved */
int32_t RC_GetBlockAckTime(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.RC_GetBlockAckTime; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_8:;
  /* 0008: entry a1, 32 */
  a3 = (uint32_t)&lit_rodata_our_controls; /* 000b: l32r a3, 0 <RC_GetBlockAckTime-0x8> (0 <RC_GetBlockAckTime-0x8>) */ /* literal @0x0: .rodata.our_controls */
  a2 = (a2 >> 0) & 0xFF; /* 000e: extui a2, a2, 0, 8 */
  a2 = (a2 << 8) + a3; /* 0011: addx8 a2, a2, a3 */
  a10 = MEM8(a2 + 6); /* 0014: l8ui a10, a2, 6 */
  a2 = 0xA; /* 0017: movi a2, 10 */
  if (a10 < 8) goto L_20; /* 001a: bltui a10, 8, 20 <RC_GetBlockAckTime+0x18> */
  a2 = 0x10; /* 001d: movi a2, 16 */
L_20:;
  a8 = a10 + (-41); /* 0020: addi a8, a10, -41 */
  a8 = (a8 >> 0) & 0xFF; /* 0023: extui a8, a8, 0, 8 */
  a3 = 0x120; /* 0026: movi a3, 0x120 */
  if (a8 < 2) goto L_41; /* 0029: bltui a8, 2, 41 <RC_GetBlockAckTime+0x39> */
  a3 = 0xC0; /* 002c: movi a3, 192 */
  if (a10 < 5) goto L_41; /* 002f: bltui a10, 5, 41 <RC_GetBlockAckTime+0x39> */
  a3 = 0x60; /* 0032: movi a3, 96 */
  if (a10 < 8) goto L_41; /* 0035: bltui a10, 8, 41 <RC_GetBlockAckTime+0x39> */
  a8 = 0xF; /* 0038: movi.n a8, 15 */
  a3 = 0x24; /* 003a: movi.n a3, 36 */
  if (a8 < a10) goto L_41; /* 003c: bltu a8, a10, 41 <RC_GetBlockAckTime+0x39> */
  a3 = 0x14; /* 003f: movi.n a3, 20 */
L_41:;
  a11 = 0x1E; /* 0041: movi.n a11, 30 */
  a8 = (uint32_t)&RC_GetDuration; /* 0043: l32r a8, 4 <RC_GetBlockAckTime-0x4> (c <RC_GetBlockAckTime+0x4>) */ /* literal: GOT slot for .text.RC_GetDuration */
  RC_GetDuration(a2, a3, a4, a5); /* call via literal slot */ /* 0046: callx8 a8 */
  a10 = a10 + a3; /* 0049: add.n a10, a10, a3 */
  a2 = a2 + a10; /* 004b: add.n a2, a2, a10 */
  a2 = (a2 >> 0) & 0xFFFF; /* 004d: extui a2, a2, 0, 16 */
  return (int32_t)a2; /* 0050: retw.n  */
}

/* RC_GetDuration @ rate_control.o 00000000 size 117B bind LOCAL
 * Calls: none | Data refs: none
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
static int32_t RC_GetDuration(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.RC_GetDuration; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
  /* 0000: .word 0x00000000 (literal pool) */
  /* 0004: .word 0x00003fff (literal pool) */
  /* 0008: .word 0x0003ffff (literal pool) */
  /* 000c: entry a1, 32 */
  a3 = a3 << (3 & 31); /* 000f: slli a3, a3, 3 */
  if (a2 < 8) goto L_18; /* 0012: bltui a2, 8, 18 <.text.RC_GetDuration+0x18> */
  a3 = a3 + (22); /* 0015: addi a3, a3, 22 */
L_18:;
  a8 = 0x0; /* 0018: l32r a8, 0 <.text.RC_GetDuration> (0 <.text.RC_GetDuration>) */ @0x0
  a8 = (a2 << 8) + a8; /* 001b: addx8 a8, a2, a8 */
  a9 = 0x3FFF; /* 001e: l32r a9, 4 <.text.RC_GetDuration+0x4> (3fff <RC_GetBlockAckTime+0x3ff7>) */ @0x4
  a8 = MEM32(a8 + 0); /* 0021: l32i.n a8, a8, 0 */
  if (a9 < a3) goto L_35; /* 0023: bltu a9, a3, 35 <.text.RC_GetDuration+0x35> */
  a3 = (uint32_t)((uint64_t)a3 * a8); /* 0026: mull a3, a3, a8 */
  a8 = 0x3FFFF; /* 0029: l32r a8, 8 <.text.RC_GetDuration+0x8> (3ffff <RC_GetBlockAckTime+0x3fff7>) */ @0x8
  a3 = a3 + a8; /* 002c: add.n a3, a3, a8 */
  a3 = (a3 >> 18) & 0x3FFF; /* 002e: extui a3, a3, 18, 14 */
  goto L_5e; /* 0031: j 5e <.text.RC_GetDuration+0x5e> */
  /* 0034: .byte 00 */
L_35:;
  a10 = (a3 >> 0) & 0x1FF; /* 0035: extui a10, a3, 0, 9 */
  a9 = 0x1FF; /* 0038: extui a9, a8, 0, 9 */
  a3 = a3 >> (9 & 31); /* 003b: srli a3, a3, 9 */
  a8 = 0x1FF; /* 003e: extui a8, a8, 9, 16 */
  a11 = (uint32_t)((uint64_t)a3 * a8); /* 0041: mull a11, a3, a8 */
  a3 = (uint32_t)((uint64_t)a9 * a3); /* 0044: mull a3, a9, a3 */
  a8 = (uint32_t)((uint64_t)a10 * a8); /* 0047: mull a8, a10, a8 */
  a9 = (uint32_t)((uint64_t)a9 * a10); /* 004a: mull a9, a9, a10 */
  a3 = a3 + a8; /* 004d: add.n a3, a3, a8 */
  a3 = a3 << (9 & 31); /* 004f: slli a3, a3, 9 */
  a8 = 0x3FFFF; /* 0052: l32r a8, 8 <.text.RC_GetDuration+0x8> (3ffff <RC_GetBlockAckTime+0x3fff7>) */ @0x8
  a3 = a3 + a9; /* 0055: add.n a3, a3, a9 */
  a3 = a3 + a8; /* 0057: add.n a3, a3, a8 */
  a3 = (int32_t)a3 >> (18 & 31); /* 0059: srai a3, a3, 18 */
  a3 = a3 + a11; /* 005c: add.n a3, a3, a11 */
L_5e:;
  if (a2 < 8) goto L_68; /* 005e: bltui a2, 8, 68 <.text.RC_GetDuration+0x68> */
  a3 = a3 + (3); /* 0061: addi.n a3, a3, 3 */
  a2 = 0xFFFFFFFC; /* 0063: movi.n a2, -4 */
  a3 = a3 & a2; /* 0065: and a3, a3, a2 */
L_68:;
  a2 = (a3 >> 0) & 0xFFFF; /* 0068: extui a2, a3, 0, 16 */
  return (int32_t)a2; /* 006b: retw.n  */
}

