/* ===== hal_mac_tx.o : reconstructed from libpp.a (ESP32, Xtensa, esp-2022r1) =====
 * Toolchain: xtensa-esp32-elf (GCC 11.2.0 crosstool-NG esp-2022r1).
 * ABI: args a2..a7, return a2 (all functions take a2..a7, return int32_t).
 * memw barriers preserved as MEMW(). MMIO as REG32/REG16/REG8(addr).
 * Calls with unknown arg counts are modeled with 4 live args (a2..a5);
 * a2..a7 are clobbered across calls (windowed-ABI approximation).
 * Sections: .text.hal_attenna_init, .text.hal_mac_clr_txq_state, .text.hal_mac_get_txq_pmd, .text.hal_mac_get_txq_state, .text.hal_mac_rate_autoack_init, .text.mac_tx_set_htsig, .text.mac_tx_set_plcp1, .text.mac_tx_set_plcp2, .wifi0iram.4
 * Undefined refs (1): wifi_log

 * DESCRIPTOR RING HANDLING (observed):
 * - TX: per-queue state words hal_mac_get_txq_state (queue select in a2:
 *   0 -> word bits[10:0], 1 -> bits[26:16], 2 -> low nibble) and
 *   hal_mac_clr_txq_state (mask/OR update of the same words); PMD snapshot
 *   hal_mac_get_txq_pmd splits one status word into bytes [24:31]->[3],
 *   [8:15]->[1], [16:23]->[2] with bit24-gated fixup; PLCP words built in
 *   mac_tx_set_plcp1/plcp2/htsig and pushed with memw barriers.
 * - RX: end-state byte hal_mac_rx_get_end_state, last-descriptor pointer
 *   hal_mac_rx_get_last_dscr, reload flag bit0 hal_mac_rx_{is,set}_dscr_reload,
 *   6-word end-info snapshot hal_mac_rx_get_end_info.

 */
#include <stdint.h>
#define REG32(a) (*(volatile uint32_t *)(a))
#define REG16(a) (*(volatile uint16_t *)(a))
#define REG8(a)  (*(volatile uint8_t *)(a))
#define MEM32(a) (*(volatile uint32_t *)(a))
#define MEM16(a) (*(volatile uint16_t *)(a))
#define MEM8(a)  (*(volatile uint8_t *)(a))
#define MEMW() __asm__ volatile("memw" ::: "memory")

extern uint32_t rodata_wlog_warning_2; /* .rodata_wlog_warning.2 */
extern int32_t wifi_log();
extern uint32_t rodata_func_0; /* .rodata.__func__$0 */
extern uint32_t rodata_wlog_warning_3; /* .rodata_wlog_warning.3 */

/* pool[mac_tx_set_plcp1]: +0x0=0x3FF74258 */
/* pool[mac_tx_set_plcp2]: +0x0=0x00000000(.rodata_wlog_warning.2), +0x10=0x00000000(wifi_log), +0x4=0x00000000(.rodata.__func__$0), +0x8=0x00000000(.rodata_wlog_warning.3), +0x14=0x00000000(wifi_log), +0xc=0x3FF7425C */
/* pool[mac_tx_set_htsig]: +0x0=0xFF0000FF, +0x4=0x00FFFFFF, +0x8=0x3FF74260, +0xc=0xFFF3FFFF, +0x10=0x3FF74264 */
/* pool[hal_mac_tx_is_cbw40]: +0x0=0x3FF74270 */
/* pool[hal_mac_get_txq_state]: +0x0=0x3FF73CC0, +0x4=0x3FF73CC8 */
/* pool[hal_mac_clr_txq_state]: +0x0=0x3FF73CBC, +0x4=0xF800FFFF, +0x8=0x3FF73CC4 */
/* pool[hal_mac_get_txq_pmd]: +0x0=0x3FF74270 */
/* pool[hal_attenna_init]: +0x0=0x3FF7425C, +0x4=0x3FF73284 */
/* pool[hal_mac_rate_autoack_init]: +0x0=0x3FF73404, +0x4=0x3FF73400, +0x8=0x3FF7340C, +0xc=0x03020100, +0x10=0x3FF73408, +0x14=0x07060500, +0x1c=0x0B0B0B0B, +0x18=0x3FF73414, +0x20=0x3FF73410, +0x24=0x3FF7341C, +0x28=0x090B0B0B, +0x2c=0x3FF73418, +0x30=0x09090909 */

/* mac_tx_set_plcp1 @ hal_mac_tx.o 00000004 size 125B bind GLOBAL
 * Calls: none | Data refs: none
 *   MMIO: none
 *   FP/data literals (loaded, never dereferenced - NOT MMIO): 0x3FF74258
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: medium - 46 instr, 4 branches, calls resolved */
int32_t mac_tx_set_plcp1(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.mac_tx_set_plcp1; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a12 = MEM32(a2 + 0); /* 0007: l32i.n a12, a2, 0 */
  a10 = 0xF; /* 0009: movi.n a10, 15 */
  a8 = 0x1; /* 000b: movi.n a8, 1 */
  a9 = MEM32(a12 + 44); /* 000d: l32i.n a9, a12, 44 */
  a13 = MEM8(a9 + 12); /* 000f: l8ui a13, a9, 12 */
  a11 = a13 + (-16); /* 0012: addi a11, a13, -16 */
  a11 = (a11 >> 0) & 0xFF; /* 0015: extui a11, a11, 0, 8 */
  a14 = MEM32(a9 + 0); /* 0018: l32i.n a14, a9, 0 */
  if (a10 >= a11) goto L_20; /* 001a: bgeu a10, a11, 20 <mac_tx_set_plcp1+0x1c> */
  a8 = 0x0; /* 001d: movi a8, 0 */
L_20:;
  a8 = 0x0; /* 0020: slli a8, a8, 9 */
  a15 = 0x1F; /* 0023: movi.n a15, 31 */
  a10 = MEM8(a9 + 16); /* 0025: l8ui a10, a9, 16 */
  a10 = a10 + a10; /* 0028: add.n a10, a10, a10 */
  a8 = a8 | a10; /* 002a: or a8, a8, a10 */
  a8 = a8 << (16 & 31); /* 002d: slli a8, a8, 16 */
  a10 = a13 & a15; /* 0030: and a10, a13, a15 */
  if (a15 >= a13) goto L_39; /* 0033: bgeu a15, a13, 39 <mac_tx_set_plcp1+0x35> */
  a10 = a11 & a15; /* 0036: and a10, a11, a15 */
L_39:;
  a10 = a10 << (12 & 31); /* 0039: slli a10, a10, 12 */
  a8 = a8 | a10; /* 003c: or a8, a8, a10 */
  if (!((a14 >> 14) & 1)) goto L_50; /* 003f: bbci a14, 14, 50 <mac_tx_set_plcp1+0x4c> */
  a9 = MEM32(a9 + 8); /* 0042: l32i.n a9, a9, 8 */
  if (!((a9 >> 15) & 1)) goto L_50; /* 0044: bbci a9, 15, 50 <mac_tx_set_plcp1+0x4c> */
  a9 = 0x1; /* 0047: movi a9, 1 */
  a9 = 0x10000000; /* 004a: slli a9, a9, 28 */
  a8 = a8 | a9; /* 004d: or a8, a8, a9 */
L_50:;
  a10 = MEM16(a12 + 20); /* 0050: l16ui a10, a12, 20 */
  a9 = MEM16(a12 + 22); /* 0053: l16ui a9, a12, 22 */
  a9 = a9 + a10; /* 0056: add.n a9, a9, a10 */
  a10 = 0xFFFFFFFF; /* 0058: movi.n a10, -1 */
  a10 = 0xFFFFF000; /* 005a: slli a10, a10, 12 */
  a9 = (a9 >> 0) & 0xFFF; /* 005d: extui a9, a9, 0, 12 */
  a10 = a8 & a10; /* 0060: and a10, a8, a10 */
  a8 = a10 | a9; /* 0063: or a8, a10, a9 */
  a9 = MEM8(a2 + 4); /* 0066: l8ui a9, a2, 4 */
  a2 = a9 << (4 & 31); /* 0069: slli a2, a9, 4 */
  a9 = a9 - a2; /* 006c: sub a9, a9, a2 */
  a2 = 0x3FF74258; /* 006f: l32r a2, 0 <mac_tx_set_plcp1-0x4> (3ff74258 <hal_mac_rate_autoack_init+0x3ff74224>) */ /* MMIO base */ @0x0
  a9 = (a9 << 4) + a2; /* 0072: addx4 a9, a9, a2 */
  a2 = 0x0; /* 0075: movi.n a2, 0 */
  MEMW(); /* 0077: memw  */
  MEM32(a9 + 0) = a8; /* 007a: s32i.n a8, a9, 0 */
  MEMW(); /* 007c: memw  */
  return (int32_t)a2; /* 007f: retw.n  */
}

/* mac_tx_set_plcp2 @ hal_mac_tx.o 00000018 size 128B bind GLOBAL
 * Calls: wifi_log | Data refs: .rodata.__func__$0, .rodata_wlog_warning.2, .rodata_wlog_warning.3, wifi_log
 *   MMIO: none
 *   FP/data literals (loaded, never dereferenced - NOT MMIO): 0x3FF7425C
 *   funcdb v3: 1 call(s), 4 ref(s); disasm: 2 call(s), 4 data ref(s)
 * Fidelity: medium - 49 instr, 2 branches, calls resolved */
int32_t mac_tx_set_plcp2(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.mac_tx_set_plcp2; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_18:;
  /* 0018: entry a1, 48 */
  a15 = MEM32(a2 + 0); /* 001b: l32i.n a15, a2, 0 */
  a9 = 0x7; /* 001d: movi.n a9, 7 */
  a8 = 0xF; /* 001f: movi.n a8, 15 */
  a9 = 0xE000; /* 0021: slli a9, a9, 13 */
  a8 = 0xF000; /* 0024: slli a8, a8, 12 */
  a11 = MEM32(a15 + 44); /* 0027: l32i.n a11, a15, 44 */
  a14 = MEM32(a11 + 16); /* 0029: l32i.n a14, a11, 16 */
  a10 = a14 & a9; /* 002b: and a10, a14, a9 */
  a8 = a14 & a8; /* 002e: and a8, a14, a8 */
  if (a10 == 0) goto L_68; /* 0031: beqz.n a10, 68 <mac_tx_set_plcp2+0x50> */
  a13 = (uint32_t)&lit_rodata_wlog_warning_2; /* 0033: l32r a13, 0 <mac_tx_set_plcp2-0x18> (0 <mac_tx_set_plcp2-0x18>) */ /* literal @0x0: .rodata_wlog_warning.2 */
  a14 = (a14 >> 12) & 0xF; /* 0036: extui a14, a14, 12, 4 */
  a12 = 0x2; /* 0039: movi.n a12, 2 */
  a10 = 0x6; /* 003b: movi.n a10, 6 */
  MEM32(a1 + 0) = a11; /* 003d: s32i.n a11, a1, 0 */
  a11 = 0x40; /* 003f: movi.n a11, 64 */
  MEMW(); /* 0041: memw  */
  a8 = (uint32_t)&wifi_log; /* 0044: l32r a8, 10 <mac_tx_set_plcp2-0x8> (0 <mac_tx_set_plcp2-0x18>) */ /* literal: GOT slot for wifi_log */
  wifi_log(a2, a3, a4, a5); /* call via literal slot */ /* 0047: callx8 a8 */
  a11 = 0x1; /* 004a: movi.n a11, 1 */
  a15 = 0x9F; /* 004c: movi a15, 159 */
  a14 = (uint32_t)&lit_rodata_func_0; /* 004f: l32r a14, 4 <mac_tx_set_plcp2-0x14> (0 <mac_tx_set_plcp2-0x18>) */ /* literal @0x4: .rodata.__func__$0 */
  a12 = 0x2; /* 0052: movi a12, 2 */
  a11 = 0x2000; /* 0055: slli a11, a11, 13 */
  a10 = 0x6; /* 0058: movi a10, 6 */
  a13 = (uint32_t)&lit_rodata_wlog_warning_3; /* 005b: l32r a13, 8 <mac_tx_set_plcp2-0x10> (0 <mac_tx_set_plcp2-0x18>) */ /* literal @0x8: .rodata_wlog_warning.3 */
  a8 = (uint32_t)&wifi_log; /* 005e: l32r a8, 14 <mac_tx_set_plcp2-0x4> (0 <mac_tx_set_plcp2-0x18>) */ /* literal: GOT slot for wifi_log */
  wifi_log(a2, a3, a4, a5); /* call via literal slot */ /* 0061: callx8 a8 */
  goto L_91; /* 0064: j 91 <mac_tx_set_plcp2+0x79> */
  /* 0067: .byte 00 */
L_68:;
  a9 = a8 + ((0xfffff000) << 8); /* 0068: addmi a9, a8, 0xfffff000 */
  a8 = 0x1; /* 006b: movi.n a8, 1 */
  if (a9 != 0) a8 = a10; /* 006d: movnez a8, a10, a9 */
  a8 = a8 << (4 & 31); /* 0070: slli a8, a8, 4 */
  a9 = 0x20; /* 0073: movi.n a9, 32 */
  a8 = a8 | a9; /* 0075: or a8, a8, a9 */
  a9 = 0x30; /* 0078: movi.n a9, 48 */
  a8 = a8 & a9; /* 007a: and a8, a8, a9 */
  a9 = MEM8(a2 + 4); /* 007d: l8ui a9, a2, 4 */
  a2 = a9 << (4 & 31); /* 0080: slli a2, a9, 4 */
  a9 = a9 - a2; /* 0083: sub a9, a9, a2 */
  a2 = 0x3FF7425C; /* 0086: l32r a2, c <mac_tx_set_plcp2-0xc> (3ff7425c <hal_mac_rate_autoack_init+0x3ff74228>) */ /* MMIO base */ @0xC
  a9 = (a9 << 4) + a2; /* 0089: addx4 a9, a9, a2 */
  MEMW(); /* 008c: memw  */
  MEM32(a9 + 0) = a8; /* 008f: s32i.n a8, a9, 0 */
L_91:;
  a2 = 0x0; /* 0091: movi.n a2, 0 */
  MEMW(); /* 0093: memw  */
  return (int32_t)a2; /* 0096: retw.n  */
}

/* mac_tx_set_htsig @ hal_mac_tx.o 00000014 size 293B bind GLOBAL
 * Calls: none | Data refs: none
 *   MMIO: none
 *   FP/data literals (loaded, never dereferenced - NOT MMIO): 0x3FF74260, 0x3FF74264
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: medium - 106 instr, 11 branches, calls resolved */
int32_t mac_tx_set_htsig(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.mac_tx_set_htsig; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_14:;
  /* 0014: entry a1, 48 */
  a8 = MEM32(a2 + 0); /* 0017: l32i.n a8, a2, 0 */
  a4 = 0xF; /* 0019: movi.n a4, 15 */
  a11 = MEM32(a8 + 44); /* 001b: l32i.n a11, a8, 44 */
  a13 = MEM8(a11 + 12); /* 001d: l8ui a13, a11, 12 */
  a9 = a13 + (-16); /* 0020: addi a9, a13, -16 */
  a9 = (a9 >> 0) & 0xFF; /* 0023: extui a9, a9, 0, 8 */
  if (a4 >= a9) goto L_2c; /* 0026: bgeu a4, a9, 2c <mac_tx_set_htsig+0x18> */
  goto L_132; /* 0029: j 132 <mac_tx_set_htsig+0x11e> */
L_2c:;
  a9 = MEM32(a8 + 36); /* 002c: l32i.n a9, a8, 36 */
  a10 = MEM32(a11 + 16); /* 002e: l32i a10, a11, 16 */
  a10 = (a10 >> 20) & 0xF; /* 0031: extui a10, a10, 20, 4 */
  a4 = MEM32(a11 + 0); /* 0034: l32i a4, a11, 0 */
  a14 = (a4 >> 22) & 0x1; /* 0037: extui a14, a4, 22, 1 */
  a12 = MEM16(a8 + 22); /* 003a: l16ui a12, a8, 22 */
  a15 = MEM16(a8 + 20); /* 003d: l16ui a15, a8, 20 */
  a8 = 0x0; /* 0040: movi.n a8, 0 */
  if (a9 == a8) goto L_54; /* 0042: beq a9, a8, 54 <mac_tx_set_htsig+0x40> */
  a9 = MEM8(a9 + 130); /* 0045: l8ui a9, a9, 130 */
  a9 = a9 + (-4); /* 0048: addi a9, a9, -4 */
  a9 = (a9 >> 0) & 0xFF; /* 004b: extui a9, a9, 0, 8 */
  if (a9 >= 2) goto L_54; /* 004e: bgeui a9, 2, 54 <mac_tx_set_htsig+0x40> */
  a8 = 0x80; /* 0051: movi a8, 128 */
L_54:;
  if (!((a4 >> 14) & 1)) goto L_62; /* 0054: bbci a4, 14, 62 <mac_tx_set_htsig+0x4e> */
  a4 = MEM32(a11 + 8); /* 0057: l32i.n a4, a11, 8 */
  if (!((a4 >> 15) & 1)) goto L_62; /* 0059: bbci a4, 15, 62 <mac_tx_set_htsig+0x4e> */
  a4 = 0x80; /* 005c: movi a4, 128 */
  a8 = 0x80; /* 005f: or a8, a8, a4 */
L_62:;
  a11 = 0xFFFFFF80; /* 0062: movi a11, -128 */
  a9 = (a13 >> 0) & 0x7; /* 0065: extui a9, a13, 0, 3 */
  a11 = 0x80; /* 0068: and a11, a8, a11 */
  a12 = a12 + a15; /* 006b: add.n a12, a12, a15 */
  a8 = a11 | a9; /* 006d: or a8, a11, a9 */
  a9 = (a12 >> 0) & 0xFFFF; /* 0070: extui a9, a12, 0, 16 */
  a11 = a9 | a9; /* 0073: or a11, a9, a9 */
  if (a14 == 0) goto L_84; /* 0076: beqz.n a14, 84 <mac_tx_set_htsig+0x70> */
  a11 = (a10 << 2) + a10; /* 0078: addx2 a11, a10, a10 */
  a11 = a11 << (4 & 31); /* 007b: slli a11, a11, 4 */
  a11 = a3 + a11; /* 007e: add a11, a3, a11 */
  a11 = MEM16(a11 + 68); /* 0081: l16ui a11, a11, 68 */
L_84:;
  a11 = a11 << (8 & 31); /* 0084: slli a11, a11, 8 */
  a4 = 0x7; /* 0087: movi.n a4, 7 */
  a15 = 0xFF0000FF; /* 0089: l32r a15, 0 <mac_tx_set_htsig-0x14> (ff0000ff <hal_mac_rate_autoack_init+0xff0000cb>) */ @0x0
  a8 = a8 & a15; /* 008c: and a8, a8, a15 */
  a8 = a8 | a11; /* 008f: or a8, a8, a11 */
  a11 = a14 << (3 & 31); /* 0092: slli a11, a14, 3 */
  a11 = a11 | a4; /* 0095: or a11, a11, a4 */
  a4 = 0x17; /* 0098: movi.n a4, 23 */
  a15 = 0x1; /* 009a: movi.n a15, 1 */
  if (a4 < a13) goto L_a1; /* 009c: bltu a4, a13, a1 <mac_tx_set_htsig+0x8d> */
  a15 = 0x0; /* 009f: movi.n a15, 0 */
L_a1:;
  a13 = (a8 >> 24) & 0xFF; /* 00a1: extui a13, a8, 24, 8 */
  a15 = 0x0; /* 00a4: slli a15, a15, 7 */
  a4 = 0x70; /* 00a7: movi a4, 112 */
  a13 = a13 & a4; /* 00aa: and a13, a13, a4 */
  a11 = a11 | a15; /* 00ad: or a11, a11, a15 */
  a11 = a11 | a13; /* 00b0: or a11, a11, a13 */
  a13 = 0xFFFFFF; /* 00b3: l32r a13, 4 <mac_tx_set_htsig-0x10> (ffffff <hal_mac_rate_autoack_init+0xffffcb>) */ @0x4
  a11 = a11 << (24 & 31); /* 00b6: slli a11, a11, 24 */
  a8 = a8 & a13; /* 00b9: and a8, a8, a13 */
  a8 = a8 | a11; /* 00bc: or a8, a8, a11 */
  a13 = MEM8(a2 + 4); /* 00bf: l8ui a13, a2, 4 */
  a2 = a13 << (4 & 31); /* 00c2: slli a2, a13, 4 */
  a13 = a13 - a2; /* 00c5: sub a13, a13, a2 */
  a11 = a13 << (2 & 31); /* 00c8: slli a11, a13, 2 */
  a2 = 0x3FF74260; /* 00cb: l32r a2, 8 <mac_tx_set_htsig-0xc> (3ff74260 <hal_mac_rate_autoack_init+0x3ff7422c>) */ /* MMIO base */ @0x8
  a13 = (a13 << 4) + a2; /* 00ce: addx4 a13, a13, a2 */
  a2 = 0x0; /* 00d1: movi.n a2, 0 */
  MEMW(); /* 00d3: memw  */
  MEM32(a13 + 0) = a8; /* 00d6: s32i.n a8, a13, 0 */
  MEM16(a1 + 0) = a2; /* 00d8: s16i a2, a1, 0 */
  MEMW(); /* 00db: memw  */
  if (a14 == 0) goto L_120; /* 00de: beqz.n a14, 120 <mac_tx_set_htsig+0x10c> */
  a10 = (a10 << 2) + a10; /* 00e0: addx2 a10, a10, a10 */
  a10 = a10 << (4 & 31); /* 00e3: slli a10, a10, 4 */
  a3 = a3 + a10; /* 00e6: add.n a3, a3, a10 */
  a8 = MEM8(a3 + 65); /* 00e8: l8ui a8, a3, 65 */
  a2 = 0xC; /* 00eb: movi.n a2, 12 */
  a8 = a8 << (2 & 31); /* 00ed: slli a8, a8, 2 */
  a8 = a8 & a2; /* 00f0: and a8, a8, a2 */
  a2 = MEM8(a3 + 64); /* 00f3: l8ui a2, a3, 64 */
  a2 = (a2 >> 0) & 0x3; /* 00f6: extui a2, a2, 0, 2 */
  a8 = a8 | a2; /* 00f9: or a8, a8, a2 */
  a8 = (a8 >> 0) & 0xF; /* 00fc: extui a8, a8, 0, 4 */
  a2 = MEM32(a3 + 68); /* 00ff: l32i a2, a3, 68 */
  a8 = a8 << (16 & 31); /* 0102: slli a8, a8, 16 */
  a8 = a9 | a8; /* 0105: or a8, a9, a8 */
  if (a2 != a12) goto L_128; /* 0108: bne a2, a12, 128 <mac_tx_set_htsig+0x114> */
  a2 = 0xFFF3FFFF; /* 010b: l32r a2, c <mac_tx_set_htsig-0x8> (fff3ffff <hal_mac_rate_autoack_init+0xfff3ffcb>) */ @0xC
  a8 = a8 & a2; /* 010e: and a8, a8, a2 */
  a2 = 0x1; /* 0111: movi.n a2, 1 */
  a2 = 0x40000; /* 0113: slli a2, a2, 18 */
  a8 = a8 | a2; /* 0116: or a8, a8, a2 */
  MEMW(); /* 0119: memw  */
  goto L_128; /* 011c: j 128 <mac_tx_set_htsig+0x114> */
  /* 011f: .byte 00 */
L_120:;
  a2 = 0x5; /* 0120: movi.n a2, 5 */
  a2 = 0x50000; /* 0122: slli a2, a2, 16 */
  a8 = a9 | a2; /* 0125: or a8, a9, a2 */
L_128:;
  a2 = 0x3FF74264; /* 0128: l32r a2, 10 <mac_tx_set_htsig-0x4> (3ff74264 <hal_mac_rate_autoack_init+0x3ff74230>) */ /* MMIO base */ @0x10
  a11 = a11 + a2; /* 012b: add.n a11, a11, a2 */
  MEMW(); /* 012d: memw  */
  MEM32(a11 + 0) = a8; /* 0130: s32i.n a8, a11, 0 */
L_132:;
  a2 = 0x0; /* 0132: movi.n a2, 0 */
  MEMW(); /* 0134: memw  */
  return (int32_t)a2; /* 0137: retw.n  */
}

/* hal_mac_tx_is_cbw40 @ hal_mac_tx.o 00000004 size 28B bind GLOBAL
 * Calls: none | Data refs: none
 *   MMIO: none
 *   FP/data literals (loaded, never dereferenced - NOT MMIO): 0x3FF74270
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t hal_mac_tx_is_cbw40(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .wifi0iram.4; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a2 = (a2 >> 0) & 0xFF; /* 0007: extui a2, a2, 0, 8 */
  a8 = a2 << (4 & 31); /* 000a: slli a8, a2, 4 */
  a2 = a2 - a8; /* 000d: sub a2, a2, a8 */
  a8 = 0x3FF74270; /* 0010: l32r a8, 0 <hal_mac_tx_is_cbw40-0x4> (3ff74270 <hal_mac_rate_autoack_init+0x3ff7423c>) */ /* MMIO base */ @0x0
  a2 = (a2 << 4) + a8; /* 0013: addx4 a2, a2, a8 */
  MEMW(); /* 0016: memw  */
  a2 = MEM32(a2 + 0); /* 0019: l32i.n a2, a2, 0 */
  a2 = (a2 >> 25) & 0x1; /* 001b: extui a2, a2, 25, 1 */
  return (int32_t)a2; /* 001e: retw.n  */
}

/* hal_mac_get_txq_state @ hal_mac_tx.o 00000008 size 60B bind GLOBAL
 * Calls: none | Data refs: none
 *   MMIO: 0x3FF73CC0, 0x3FF73CC8
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: medium - 24 instr, 5 branches, calls resolved */
int32_t hal_mac_get_txq_state(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.hal_mac_get_txq_state; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_8:;
  /* 0008: entry a1, 32 */
  if (a2 == 1) goto L_24; /* 000b: beqi a2, 1, 24 <hal_mac_get_txq_state+0x1c> */
  if (a2 == 2) goto L_35; /* 000e: beqi a2, 2, 35 <hal_mac_get_txq_state+0x2d> */
  a8 = 0x0; /* 0011: movi.n a8, 0 */
  if (a2 != a8) goto L_40; /* 0013: bne a2, a8, 40 <hal_mac_get_txq_state+0x38> */
  a2 = 0x3FF73CC0; /* 0016: l32r a2, 0 <hal_mac_get_txq_state-0x8> (3ff73cc0 <hal_mac_rate_autoack_init+0x3ff73c8c>) */ /* MMIO base */ @0x0
  MEMW(); /* 0019: memw  */
  a8 = REG32(0x3FF73CC0); /* 001c: l32i.n a8, a2, 0 */ /* MMIO read: base 0x3FF73CC0+0 */
  a8 = (a8 >> 0) & 0x7FF; /* 001e: extui a8, a8, 0, 11 */
  goto L_40; /* 0021: j 40 <hal_mac_get_txq_state+0x38> */
L_24:;
  a2 = 0x3FF73CC0; /* 0024: l32r a2, 0 <hal_mac_get_txq_state-0x8> (3ff73cc0 <hal_mac_rate_autoack_init+0x3ff73c8c>) */ /* MMIO base */ @0x0
  MEMW(); /* 0027: memw  */
  a8 = REG32(0x3FF73CC0); /* 002a: l32i.n a8, a2, 0 */ /* MMIO read: base 0x3FF73CC0+0 */
  a8 = (a8 >> 16) & 0x7FF; /* 002c: extui a8, a8, 16, 11 */
  goto L_40; /* 002f: j 40 <hal_mac_get_txq_state+0x38> */
  /* 0032: .byte 00 */
  /* 0033: .byte 00 */
  /* 0034: .byte 00 */
L_35:;
  a2 = 0x3FF73CC8; /* 0035: l32r a2, 4 <hal_mac_get_txq_state-0x4> (3ff73cc8 <hal_mac_rate_autoack_init+0x3ff73c94>) */ /* MMIO base */ @0x4
  MEMW(); /* 0038: memw  */
  a8 = REG32(0x3FF73CC8); /* 003b: l32i.n a8, a2, 0 */ /* MMIO read: base 0x3FF73CC8+0 */
  a8 = (a8 >> 0) & 0xF; /* 003d: extui a8, a8, 0, 4 */
L_40:;
  a2 = a8; /* 0040: mov.n a2, a8 */
  return (int32_t)a2; /* 0042: retw.n  */
}

/* hal_mac_clr_txq_state @ hal_mac_tx.o 0000000c size 95B bind GLOBAL
 * Calls: none | Data refs: none
 *   MMIO: 0x3FF73CBC, 0x3FF73CC4
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: medium - 34 instr, 5 branches, calls resolved */
int32_t hal_mac_clr_txq_state(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.hal_mac_clr_txq_state; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_c:;
  /* 000c: entry a1, 32 */
  if (a2 == 1) goto L_2c; /* 000f: beqi a2, 1, 2c <hal_mac_clr_txq_state+0x20> */
  if (a2 == 2) goto L_54; /* 0012: beqi a2, 2, 54 <hal_mac_clr_txq_state+0x48> */
  if (a2 != 0) goto L_64; /* 0015: bnez a2, 64 <hal_mac_clr_txq_state+0x58> */
  a2 = 0x3FF73CBC; /* 0018: l32r a2, 0 <hal_mac_clr_txq_state-0xc> (3ff73cbc <hal_mac_rate_autoack_init+0x3ff73c88>) */ /* MMIO base */ @0x0
  a9 = 0xFFFFF800; /* 001b: movi a9, 0xfffff800 */
  a3 = (a3 >> 0) & 0x7FF; /* 001e: extui a3, a3, 0, 11 */
  MEMW(); /* 0021: memw  */
  a8 = REG32(0x3FF73CBC); /* 0024: l32i.n a8, a2, 0 */ /* MMIO read: base 0x3FF73CBC+0 */
  a8 = a8 & a9; /* 0026: and a8, a8, a9 */
  goto L_5c; /* 0029: j 5c <hal_mac_clr_txq_state+0x50> */
L_2c:;
  a2 = 0x3FF73CBC; /* 002c: l32r a2, 0 <hal_mac_clr_txq_state-0xc> (3ff73cbc <hal_mac_rate_autoack_init+0x3ff73c88>) */ /* MMIO base */ @0x0
  a9 = 0x7FF; /* 002f: movi a9, 0x7ff */
  a9 = 0x7FF0000; /* 0032: slli a9, a9, 16 */
  a3 = a3 << (16 & 31); /* 0035: slli a3, a3, 16 */
  a3 = a3 & a9; /* 0038: and a3, a3, a9 */
  MEMW(); /* 003b: memw  */
  a8 = REG32(0x3FF73CBC); /* 003e: l32i.n a8, a2, 0 */ /* MMIO read: base 0x3FF73CBC+0 */
  a9 = 0xF800FFFF; /* 0040: l32r a9, 4 <hal_mac_clr_txq_state-0x8> (f800ffff <hal_mac_rate_autoack_init+0xf800ffcb>) */ @0x4
  a8 = a8 & a9; /* 0043: and a8, a8, a9 */
  a3 = a3 | a8; /* 0046: or a3, a3, a8 */
  MEMW(); /* 0049: memw  */
  REG32(0x3FF73CBC) = a3; /* 004c: s32i.n a3, a2, 0 */ /* MMIO write: base 0x3FF73CBC+0 */
  MEMW(); /* 004e: memw  */
  goto L_64; /* 0051: j 64 <hal_mac_clr_txq_state+0x58> */
L_54:;
  a2 = 0x3FF73CC4; /* 0054: l32r a2, 8 <hal_mac_clr_txq_state-0x4> (3ff73cc4 <hal_mac_rate_autoack_init+0x3ff73c90>) */ /* MMIO base */ @0x8
  MEMW(); /* 0057: memw  */
  a8 = REG32(0x3FF73CC4); /* 005a: l32i.n a8, a2, 0 */ /* MMIO read: base 0x3FF73CC4+0 */
L_5c:;
  a8 = a8 | a3; /* 005c: or a8, a8, a3 */
  MEMW(); /* 005f: memw  */
  REG32(0x3FF73CC4) = a8; /* 0062: s32i.n a8, a2, 0 */ /* MMIO write: base 0x3FF73CC4+0 */
L_64:;
  a2 = 0x0; /* 0064: movi.n a2, 0 */
  MEMW(); /* 0066: memw  */
  return (int32_t)a2; /* 0069: retw.n  */
}

/* hal_mac_get_txq_pmd @ hal_mac_tx.o 00000004 size 69B bind GLOBAL
 * Calls: none | Data refs: none
 *   MMIO: none
 *   FP/data literals (loaded, never dereferenced - NOT MMIO): 0x3FF74270
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t hal_mac_get_txq_pmd(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.hal_mac_get_txq_pmd; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 48 */
  a2 = (a2 >> 0) & 0xFF; /* 0007: extui a2, a2, 0, 8 */
  a8 = a2 << (4 & 31); /* 000a: slli a8, a2, 4 */
  a2 = a2 - a8; /* 000d: sub a2, a2, a8 */
  a8 = 0x3FF74270; /* 0010: l32r a8, 0 <hal_mac_get_txq_pmd-0x4> (3ff74270 <hal_mac_rate_autoack_init+0x3ff7423c>) */ /* MMIO base */ @0x0
  a2 = (a2 << 4) + a8; /* 0013: addx4 a2, a2, a8 */
  MEMW(); /* 0016: memw  */
  a8 = MEM32(a2 + 0); /* 0019: l32i.n a8, a2, 0 */
  a2 = (a8 >> 24) & 0xFF; /* 001b: extui a2, a8, 24, 8 */
  a10 = (a8 >> 8) & 0xFF; /* 001e: extui a10, a8, 8, 8 */
  a9 = (a8 >> 16) & 0xFF; /* 0021: extui a9, a8, 16, 8 */
  MEM8(a3 + 3) = a2; /* 0024: s8i a2, a3, 3 */
  a2 = 0x7F; /* 0027: movi a2, 127 */
  MEM8(a3 + 0) = a8; /* 002a: s8i a8, a3, 0 */
  MEM8(a3 + 1) = a10; /* 002d: s8i a10, a3, 1 */
  MEM8(a3 + 2) = a9; /* 0030: s8i a9, a3, 2 */
  MEMW(); /* 0033: memw  */
  if (!((a8 >> 24) & 1)) goto L_3c; /* 0036: bbci a8, 24, 3c <hal_mac_get_txq_pmd+0x38> */
  a2 = a9 | a9; /* 0039: or a2, a9, a9 */
L_3c:;
  MEM8(a3 + 2) = a2; /* 003c: s8i a2, a3, 2 */
  MEMW(); /* 003f: memw  */
  a2 = 0x0; /* 0042: movi.n a2, 0 */
  MEMW(); /* 0044: memw  */
  return (int32_t)a2; /* 0047: retw.n  */
}

/* hal_attenna_init @ hal_mac_tx.o 00000008 size 122B bind GLOBAL
 * Calls: none | Data refs: none
 *   MMIO: 0x3FF7425C, 0x3FF73284
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: medium - 47 instr, 2 branches, calls resolved */
int32_t hal_attenna_init(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.hal_attenna_init; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_8:;
  /* 0008: entry a1, 32 */
  a8 = 0x3FF7425C; /* 000b: l32r a8, 0 <hal_attenna_init-0x8> (3ff7425c <hal_mac_rate_autoack_init+0x3ff74228>) */ /* MMIO base */ @0x0
  a11 = 0xFFFFFFF8; /* 000e: movi.n a11, -8 */
  a9 = 0x8; /* 0010: movi.n a9, 8 */
  /* 0012: loop a9, 25 <hal_attenna_init+0x1d> */ /* loop a9 times, end L_25; body shown single-pass */
  a8 = 0x3FF74220; /* 0015: addi a8, a8, -60 */
  MEMW(); /* 0018: memw  */
  a10 = REG32(0x3FF7425C); /* 001b: l32i.n a10, a8, 60 */ /* MMIO read: base 0x3FF74220+60 */
  a10 = a10 & a11; /* 001d: and a10, a10, a11 */
  MEMW(); /* 0020: memw  */
  REG32(0x3FF7425C) = a10; /* 0023: s32i.n a10, a8, 60 */ /* MMIO write: base 0x3FF74220+60 */
L_25:;
  a13 = 0xFFFFFFF7; /* 0025: movi.n a13, -9 */
  a11 = 0x20; /* 0027: movi.n a11, 32 */
  a12 = 0xFFFFFFEF; /* 0029: movi.n a12, -17 */
  a8 = 0x3FF7425C; /* 002b: l32r a8, 0 <hal_attenna_init-0x8> (3ff7425c <hal_mac_rate_autoack_init+0x3ff74228>) */ /* MMIO base */ @0x0
  a9 = 0x8; /* 002e: movi a9, 8 */
  /* 0031: loop a9, 5e <hal_attenna_init+0x56> */ /* loop a9 times, end L_5e; body shown single-pass */
  a8 = 0x3FF74220; /* 0034: addi a8, a8, -60 */
  MEMW(); /* 0037: memw  */
  a10 = REG32(0x3FF7425C); /* 003a: l32i.n a10, a8, 60 */ /* MMIO read: base 0x3FF74220+60 */
  a10 = a10 & a13; /* 003c: and a10, a10, a13 */
  MEMW(); /* 003f: memw  */
  REG32(0x3FF7425C) = a10; /* 0042: s32i.n a10, a8, 60 */ /* MMIO write: base 0x3FF74220+60 */
  MEMW(); /* 0044: memw  */
  a10 = REG32(0x3FF7425C); /* 0047: l32i.n a10, a8, 60 */ /* MMIO read: base 0x3FF74220+60 */
  a10 = a10 | a11; /* 0049: or a10, a10, a11 */
  MEMW(); /* 004c: memw  */
  REG32(0x3FF7425C) = a10; /* 004f: s32i.n a10, a8, 60 */ /* MMIO write: base 0x3FF74220+60 */
  MEMW(); /* 0051: memw  */
  a10 = REG32(0x3FF7425C); /* 0054: l32i.n a10, a8, 60 */ /* MMIO read: base 0x3FF74220+60 */
  a10 = a10 & a12; /* 0056: and a10, a10, a12 */
  MEMW(); /* 0059: memw  */
  REG32(0x3FF7425C) = a10; /* 005c: s32i.n a10, a8, 60 */ /* MMIO write: base 0x3FF74220+60 */
L_5e:;
  a10 = 0xFFFFFFF8; /* 005e: movi.n a10, -8 */
  a8 = 0x3FF73284; /* 0060: l32r a8, 4 <hal_attenna_init-0x4> (3ff73284 <hal_mac_rate_autoack_init+0x3ff73250>) */ /* MMIO base */ @0x4
  MEMW(); /* 0063: memw  */
  a9 = REG32(0x3FF73284); /* 0066: l32i.n a9, a8, 0 */ /* MMIO read: base 0x3FF73284+0 */
  a9 = a9 & a10; /* 0068: and a9, a9, a10 */
  MEMW(); /* 006b: memw  */
  REG32(0x3FF73284) = a9; /* 006e: s32i.n a9, a8, 0 */ /* MMIO write: base 0x3FF73284+0 */
  MEMW(); /* 0070: memw  */
  a9 = REG32(0x3FF73284); /* 0073: l32i.n a9, a8, 0 */ /* MMIO read: base 0x3FF73284+0 */
  a9 = a9 | a11; /* 0075: or a9, a9, a11 */
  MEMW(); /* 0078: memw  */
  REG32(0x3FF73284) = a9; /* 007b: s32i.n a9, a8, 0 */ /* MMIO write: base 0x3FF73284+0 */
  MEMW(); /* 007d: memw  */
  return (int32_t)a2; /* 0080: retw.n  */
}

/* hal_mac_rate_autoack_init @ hal_mac_tx.o 00000034 size 89B bind GLOBAL
 * Calls: none | Data refs: none
 *   MMIO: 0x3FF73404, 0x3FF73400, 0x3FF7340C, 0x3FF73408, 0x3FF73414, 0x3FF73410, 0x3FF7341C, 0x3FF73418
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t hal_mac_rate_autoack_init(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.hal_mac_rate_autoack_init; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_34:;
  /* 0034: entry a1, 32 */
  a9 = 0x3FF73404; /* 0037: l32r a9, 0 <hal_mac_rate_autoack_init-0x34> (3ff73404 <hal_mac_rate_autoack_init+0x3ff733d0>) */ /* MMIO base */ @0x0
  a8 = 0x0; /* 003a: movi.n a8, 0 */
  MEMW(); /* 003c: memw  */
  REG32(0x3FF73404) = a8; /* 003f: s32i.n a8, a9, 0 */ /* MMIO write: base 0x3FF73404+0 */
  a9 = 0x3FF73400; /* 0041: l32r a9, 4 <hal_mac_rate_autoack_init-0x30> (3ff73400 <hal_mac_rate_autoack_init+0x3ff733cc>) */ /* MMIO base */ @0x4
  MEMW(); /* 0044: memw  */
  REG32(0x3FF73400) = a8; /* 0047: s32i.n a8, a9, 0 */ /* MMIO write: base 0x3FF73400+0 */
  a8 = 0x3FF7340C; /* 0049: l32r a8, 8 <hal_mac_rate_autoack_init-0x2c> (3ff7340c <hal_mac_rate_autoack_init+0x3ff733d8>) */ /* MMIO base */ @0x8
  a9 = 0x3020100; /* 004c: l32r a9, c <hal_mac_rate_autoack_init-0x28> (3020100 <hal_mac_rate_autoack_init+0x30200cc>) */ @0xC
  MEMW(); /* 004f: memw  */
  REG32(0x3FF7340C) = a9; /* 0052: s32i.n a9, a8, 0 */ /* MMIO write: base 0x3FF7340C+0 */
  a8 = 0x3FF73408; /* 0054: l32r a8, 10 <hal_mac_rate_autoack_init-0x24> (3ff73408 <hal_mac_rate_autoack_init+0x3ff733d4>) */ /* MMIO base */ @0x10
  a9 = 0x7060500; /* 0057: l32r a9, 14 <hal_mac_rate_autoack_init-0x20> (7060500 <hal_mac_rate_autoack_init+0x70604cc>) */ @0x14
  MEMW(); /* 005a: memw  */
  REG32(0x3FF73408) = a9; /* 005d: s32i.n a9, a8, 0 */ /* MMIO write: base 0x3FF73408+0 */
  a8 = 0xB0B0B0B; /* 005f: l32r a8, 1c <hal_mac_rate_autoack_init-0x18> (b0b0b0b <hal_mac_rate_autoack_init+0xb0b0ad7>) */ @0x1C
  a9 = 0x3FF73414; /* 0062: l32r a9, 18 <hal_mac_rate_autoack_init-0x1c> (3ff73414 <hal_mac_rate_autoack_init+0x3ff733e0>) */ /* MMIO base */ @0x18
  MEMW(); /* 0065: memw  */
  REG32(0x3FF73414) = a8; /* 0068: s32i.n a8, a9, 0 */ /* MMIO write: base 0x3FF73414+0 */
  a9 = 0x3FF73410; /* 006a: l32r a9, 20 <hal_mac_rate_autoack_init-0x14> (3ff73410 <hal_mac_rate_autoack_init+0x3ff733dc>) */ /* MMIO base */ @0x20
  MEMW(); /* 006d: memw  */
  REG32(0x3FF73410) = a8; /* 0070: s32i.n a8, a9, 0 */ /* MMIO write: base 0x3FF73410+0 */
  a8 = 0x3FF7341C; /* 0072: l32r a8, 24 <hal_mac_rate_autoack_init-0x10> (3ff7341c <hal_mac_rate_autoack_init+0x3ff733e8>) */ /* MMIO base */ @0x24
  a9 = 0x90B0B0B; /* 0075: l32r a9, 28 <hal_mac_rate_autoack_init-0xc> (90b0b0b <hal_mac_rate_autoack_init+0x90b0ad7>) */ @0x28
  MEMW(); /* 0078: memw  */
  REG32(0x3FF7341C) = a9; /* 007b: s32i.n a9, a8, 0 */ /* MMIO write: base 0x3FF7341C+0 */
  a8 = 0x3FF73418; /* 007d: l32r a8, 2c <hal_mac_rate_autoack_init-0x8> (3ff73418 <hal_mac_rate_autoack_init+0x3ff733e4>) */ /* MMIO base */ @0x2C
  a9 = 0x9090909; /* 0080: l32r a9, 30 <hal_mac_rate_autoack_init-0x4> (9090909 <hal_mac_rate_autoack_init+0x90908d5>) */ @0x30
  MEMW(); /* 0083: memw  */
  REG32(0x3FF73418) = a9; /* 0086: s32i.n a9, a8, 0 */ /* MMIO write: base 0x3FF73418+0 */
  MEMW(); /* 0088: memw  */
  return (int32_t)a2; /* 008b: retw.n  */
}

