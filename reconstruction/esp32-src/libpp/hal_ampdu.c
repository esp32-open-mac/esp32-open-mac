/* ===== hal_ampdu.o : reconstructed from libpp.a (ESP32, Xtensa, esp-2022r1) =====
 * Toolchain: xtensa-esp32-elf (GCC 11.2.0 crosstool-NG esp-2022r1).
 * ABI: args a2..a7, return a2 (all functions take a2..a7, return int32_t).
 * memw barriers preserved as MEMW(). MMIO as REG32/REG16/REG8(addr).
 * Calls with unknown arg counts are modeled with 4 live args (a2..a5);
 * a2..a7 are clobbered across calls (windowed-ABI approximation).
 * Sections: .text.hal_agreement_add_rx_ba, .text.hal_agreement_clr_rx_ba, .text.hal_agreement_del_rx_ba, .text.hal_ba_session_restore, .text.hal_ba_session_restore_by_hw_index, .text.hal_ba_session_store
 * Undefined refs (1): wifi_log
 */
#include <stdint.h>
#define REG32(a) (*(volatile uint32_t *)(a))
#define REG16(a) (*(volatile uint16_t *)(a))
#define REG8(a)  (*(volatile uint8_t *)(a))
#define MEM32(a) (*(volatile uint32_t *)(a))
#define MEM16(a) (*(volatile uint16_t *)(a))
#define MEM8(a)  (*(volatile uint8_t *)(a))
#define MEMW() __asm__ volatile("memw" ::: "memory")

extern uint32_t rodata_wlog_info_2; /* .rodata_wlog_info.2 */
extern int32_t wifi_log();
extern uint32_t rodata_wlog_info_3; /* .rodata_wlog_info.3 */
extern uint32_t rodata_wlog_info_4; /* .rodata_wlog_info.4 */

/* pool[hal_agreement_add_rx_ba]: +0x0=0x00000000(.rodata_wlog_info.2), +0x24=0x00000000(wifi_log), +0x4=0x3FF73258, +0x8=0x3FF73254, +0xc=0x3FF7325C, +0x10=0x3FF73250, +0x14=0x7FFFFFFF, +0x18=0x01FFB993, +0x1c=0x3FF73264, +0x20=0xC0000005 */
/* pool[hal_agreement_clr_rx_ba]: +0x0=0x00000000(.rodata_wlog_info.3), +0x18=0x00000000(wifi_log), +0x4=0x3FF73250, +0x8=0x3FF7325C, +0xc=0x01FFB993, +0x10=0x3FF73264, +0x14=0xC0000005 */
/* pool[hal_agreement_del_rx_ba]: +0x0=0x3FF73250, +0x4=0x00000000(.rodata_wlog_info.4), +0x14=0x00000000(wifi_log), +0x8=0x7FFFFFFF, +0xc=0x01FFB993, +0x10=0x3FF73264 */
/* pool[hal_ba_session_store]: +0x0=0x3FF73250 */
/* pool[hal_ba_session_restore]: +0x0=0x3FF73250, +0x4=0x7FFFFFFF */
/* pool[hal_ba_session_restore_by_hw_index]: +0x0=0x3FF73250, +0x4=0x7FFFFFFF, +0x8=0x01FFB993, +0xc=0x3FF73264, +0x10=0x3FF7325C */

/* hal_agreement_add_rx_ba @ hal_ampdu.o 00000028 size 260B bind GLOBAL
 * Calls: wifi_log | Data refs: .rodata_wlog_info.2, wifi_log
 *   MMIO: none
 *   FP/data literals (loaded, never dereferenced - NOT MMIO): 0x3FF73258, 0x3FF73254, 0x3FF7325C, 0x3FF73250, 0x3FF73264
 *   funcdb v3: 1 call(s), 2 ref(s); disasm: 1 call(s), 2 data ref(s)
 * Fidelity: medium - 95 instr, 0 branches, calls resolved */
int32_t hal_agreement_add_rx_ba(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.hal_agreement_add_rx_ba; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_28:;
  /* 0028: entry a1, 80 */
  a5 = (a5 >> 0) & 0xFF; /* 002b: extui a5, a5, 0, 8 */
  a6 = (a6 >> 0) & 0xFFFF; /* 002e: extui a6, a6, 0, 16 */
  a7 = (a7 >> 0) & 0xFF; /* 0031: extui a7, a7, 0, 8 */
  MEM32(a1 + 32) = a7; /* 0034: s32i.n a7, a1, 32 */
  a2 = (a2 >> 0) & 0xFF; /* 0036: extui a2, a2, 0, 8 */
  a3 = (a3 >> 0) & 0xFF; /* 0039: extui a3, a3, 0, 8 */
  a11 = 0x1; /* 003c: movi.n a11, 1 */
  a15 = a3; /* 003e: mov.n a15, a3 */
  MEM32(a1 + 28) = a6; /* 0040: s32i.n a6, a1, 28 */
  a14 = a2; /* 0042: mov.n a14, a2 */
  a10 = 0x5; /* 0044: movi.n a10, 5 */
  a12 = 0x3; /* 0046: movi.n a12, 3 */
  a11 = 0x2000; /* 0048: slli a11, a11, 13 */
  MEM32(a1 + 24) = a5; /* 004b: s32i.n a5, a1, 24 */
  a3 = a3 << (16 & 31); /* 004d: slli a3, a3, 16 */
  a7 = a7 << (13 & 31); /* 0050: slli a7, a7, 13 */
  a6 = (a6 >> 0) & 0xFFF; /* 0053: extui a6, a6, 0, 12 */
  a8 = MEM8(a4 + 5); /* 0056: l8ui a8, a4, 5 */
  MEM32(a1 + 20) = a8; /* 0059: s32i.n a8, a1, 20 */
  a8 = MEM8(a4 + 4); /* 005b: l8ui a8, a4, 4 */
  MEM32(a1 + 16) = a8; /* 005e: s32i.n a8, a1, 16 */
  a8 = MEM8(a4 + 3); /* 0060: l8ui a8, a4, 3 */
  MEM32(a1 + 12) = a8; /* 0063: s32i.n a8, a1, 12 */
  a8 = MEM8(a4 + 2); /* 0065: l8ui a8, a4, 2 */
  MEM32(a1 + 8) = a8; /* 0068: s32i.n a8, a1, 8 */
  a8 = MEM8(a4 + 1); /* 006a: l8ui a8, a4, 1 */
  MEM32(a1 + 4) = a8; /* 006d: s32i.n a8, a1, 4 */
  a8 = MEM8(a4 + 0); /* 006f: l8ui a8, a4, 0 */
  a13 = (uint32_t)&lit_rodata_wlog_info_2; /* 0072: l32r a13, 0 <hal_agreement_add_rx_ba-0x28> (0 <hal_agreement_add_rx_ba-0x28>) */ /* literal @0x0: .rodata_wlog_info.2 */
  MEM32(a1 + 0) = a8; /* 0075: s32i.n a8, a1, 0 */
  MEMW(); /* 0077: memw  */
  a8 = (uint32_t)&wifi_log; /* 007a: l32r a8, 24 <hal_agreement_add_rx_ba-0x4> (0 <hal_agreement_add_rx_ba-0x28>) */ /* literal: GOT slot for wifi_log */
  wifi_log(a2, a3, a4, a5); /* call via literal slot */ /* 007d: callx8 a8 */
  a9 = MEM8(a4 + 1); /* 0080: l8ui a9, a4, 1 */
  a9 = a9 << (8 & 31); /* 0083: slli a9, a9, 8 */
  a8 = MEM8(a4 + 0); /* 0086: l8ui a8, a4, 0 */
  a9 = a9 | a8; /* 0089: or a9, a9, a8 */
  a8 = MEM8(a4 + 2); /* 008c: l8ui a8, a4, 2 */
  a8 = a8 << (16 & 31); /* 008f: slli a8, a8, 16 */
  a8 = a8 | a9; /* 0092: or a8, a8, a9 */
  a9 = MEM8(a4 + 3); /* 0095: l8ui a9, a4, 3 */
  a9 = a9 << (24 & 31); /* 0098: slli a9, a9, 24 */
  a9 = a9 | a8; /* 009b: or a9, a9, a8 */
  a8 = a2 << (5 & 31); /* 009e: slli a8, a2, 5 */
  a10 = 0x3FF73258; /* 00a1: l32r a10, 4 <hal_agreement_add_rx_ba-0x24> (3ff73258 <hal_agreement_add_rx_ba+0x3ff73230>) */ /* MMIO base */ @0x4
  a10 = a10 - a8; /* 00a4: sub a10, a10, a8 */
  MEMW(); /* 00a7: memw  */
  MEM32(a10 + 0) = a9; /* 00aa: s32i.n a9, a10, 0 */
  a9 = 0x3; /* 00ac: movi.n a9, 3 */
  a9 = 0x30000; /* 00ae: slli a9, a9, 16 */
  a3 = a3 & a9; /* 00b1: and a3, a3, a9 */
  a9 = MEM8(a4 + 4); /* 00b4: l8ui a9, a4, 4 */
  a4 = MEM8(a4 + 5); /* 00b7: l8ui a4, a4, 5 */
  a4 = a4 << (8 & 31); /* 00ba: slli a4, a4, 8 */
  a4 = a4 | a9; /* 00bd: or a4, a4, a9 */
  a3 = a3 | a4; /* 00c0: or a3, a3, a4 */
  a4 = 0x3FF73254; /* 00c3: l32r a4, 8 <hal_agreement_add_rx_ba-0x20> (3ff73254 <hal_agreement_add_rx_ba+0x3ff7322c>) */ /* MMIO base */ @0x8
  a4 = a4 - a8; /* 00c6: sub a4, a4, a8 */
  MEMW(); /* 00c9: memw  */
  MEM32(a4 + 0) = a3; /* 00cc: s32i.n a3, a4, 0 */
  a3 = 0x7F; /* 00ce: movi a3, 127 */
  a3 = 0xFE000; /* 00d1: slli a3, a3, 13 */
  a7 = a7 & a3; /* 00d4: and a7, a7, a3 */
  a7 = a7 | a6; /* 00d7: or a7, a7, a6 */
  a3 = 0x3FF7325C; /* 00da: l32r a3, c <hal_agreement_add_rx_ba-0x1c> (3ff7325c <hal_agreement_add_rx_ba+0x3ff73234>) */ /* MMIO base */ @0xC
  a3 = a3 - a8; /* 00dd: sub a3, a3, a8 */
  MEMW(); /* 00e0: memw  */
  MEM32(a3 + 0) = a7; /* 00e3: s32i.n a7, a3, 0 */
  a3 = 0x3FF73250; /* 00e5: l32r a3, 10 <hal_agreement_add_rx_ba-0x18> (3ff73250 <hal_agreement_add_rx_ba+0x3ff73228>) */ /* MMIO base */ @0x10
  a3 = a3 - a8; /* 00e8: sub a3, a3, a8 */
  MEMW(); /* 00eb: memw  */
  a4 = MEM32(a3 + 0); /* 00ee: l32i.n a4, a3, 0 */
  a6 = 0x7FFFFFFF; /* 00f0: l32r a6, 14 <hal_agreement_add_rx_ba-0x14> (7fffffff <hal_agreement_add_rx_ba+0x7fffffd7>) */ @0x14
  a4 = a4 & a6; /* 00f3: and a4, a4, a6 */
  a6 = 0x0; /* 00f6: movi.n a6, 0 */
  MEMW(); /* 00f8: memw  */
  MEM32(a3 + 0) = a4; /* 00fb: s32i.n a4, a3, 0 */
  a4 = 0x1FFB993; /* 00fd: l32r a4, 18 <hal_agreement_add_rx_ba-0x10> (1ffb993 <hal_agreement_add_rx_ba+0x1ffb96b>) */ @0x18
  a4 = a4 - a2; /* 0100: sub a4, a4, a2 */
  a4 = a4 << (5 & 31); /* 0103: slli a4, a4, 5 */
  a2 = 0x3FF73264; /* 0106: l32r a2, 1c <hal_agreement_add_rx_ba-0xc> (3ff73264 <hal_agreement_add_rx_ba+0x3ff7323c>) */ /* MMIO base */ @0x1C
  a2 = a2 - a8; /* 0109: sub a2, a2, a8 */
  MEMW(); /* 010c: memw  */
  MEM32(a4 + 0) = a6; /* 010f: s32i.n a6, a4, 0 */
  a4 = a5 << (12 & 31); /* 0111: slli a4, a5, 12 */
  a4 = (a4 >> 0) & 0xFFFF; /* 0114: extui a4, a4, 0, 16 */
  MEMW(); /* 0117: memw  */
  MEM32(a2 + 0) = a6; /* 011a: s32i.n a6, a2, 0 */
  a2 = 0xC0000005; /* 011c: l32r a2, 20 <hal_agreement_add_rx_ba-0x8> (c0000005 <hal_agreement_add_rx_ba+0xbfffffdd>) */ @0x20
  a4 = a4 | a2; /* 011f: or a4, a4, a2 */
  MEMW(); /* 0122: memw  */
  MEM32(a3 + 0) = a4; /* 0125: s32i.n a4, a3, 0 */
  MEMW(); /* 0127: memw  */
  return (int32_t)a2; /* 012a: retw.n  */
}

/* hal_agreement_clr_rx_ba @ hal_ampdu.o 0000001c size 138B bind GLOBAL
 * Calls: wifi_log | Data refs: .rodata_wlog_info.3, wifi_log
 *   MMIO: none
 *   FP/data literals (loaded, never dereferenced - NOT MMIO): 0x3FF73250, 0x3FF7325C, 0x3FF73264
 *   funcdb v3: 1 call(s), 2 ref(s); disasm: 1 call(s), 2 data ref(s)
 * Fidelity: medium - 50 instr, 0 branches, calls resolved */
int32_t hal_agreement_clr_rx_ba(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.hal_agreement_clr_rx_ba; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_1c:;
  /* 001c: entry a1, 48 */
  a2 = (a2 >> 0) & 0xFF; /* 001f: extui a2, a2, 0, 8 */
  a3 = (a3 >> 0) & 0xFF; /* 0022: extui a3, a3, 0, 8 */
  a4 = (a4 >> 0) & 0xFFFF; /* 0025: extui a4, a4, 0, 16 */
  a5 = (a5 >> 0) & 0xFF; /* 0028: extui a5, a5, 0, 8 */
  a13 = (uint32_t)&lit_rodata_wlog_info_3; /* 002b: l32r a13, 0 <hal_agreement_clr_rx_ba-0x1c> (0 <hal_agreement_clr_rx_ba-0x1c>) */ /* literal @0x0: .rodata_wlog_info.3 */
  a11 = 0x1; /* 002e: movi.n a11, 1 */
  a15 = a3; /* 0030: mov.n a15, a3 */
  a14 = a2; /* 0032: mov.n a14, a2 */
  a11 = 0x2000; /* 0034: slli a11, a11, 13 */
  MEM32(a1 + 4) = a5; /* 0037: s32i.n a5, a1, 4 */
  a10 = 0x5; /* 0039: movi.n a10, 5 */
  a12 = 0x3; /* 003b: movi a12, 3 */
  a5 = a5 << (13 & 31); /* 003e: slli a5, a5, 13 */
  a3 = a3 << (12 & 31); /* 0041: slli a3, a3, 12 */
  MEM32(a1 + 0) = a4; /* 0044: s32i a4, a1, 0 */
  MEMW(); /* 0047: memw  */
  a8 = (uint32_t)&wifi_log; /* 004a: l32r a8, 18 <hal_agreement_clr_rx_ba-0x4> (0 <hal_agreement_clr_rx_ba-0x1c>) */ /* literal: GOT slot for wifi_log */
  wifi_log(a2, a3, a4, a5); /* call via literal slot */ /* 004d: callx8 a8 */
  a11 = 0x7F; /* 0050: movi a11, 127 */
  a11 = 0xFE000; /* 0053: slli a11, a11, 13 */
  a4 = (a4 >> 0) & 0xFFF; /* 0056: extui a4, a4, 0, 12 */
  a8 = 0x3FF73250; /* 0059: l32r a8, 4 <hal_agreement_clr_rx_ba-0x18> (3ff73250 <hal_agreement_add_rx_ba+0x3ff73228>) */ /* MMIO base */ @0x4
  a5 = a5 & a11; /* 005c: and a5, a5, a11 */
  a10 = a2 << (5 & 31); /* 005f: slli a10, a2, 5 */
  a5 = a5 | a4; /* 0062: or a5, a5, a4 */
  a9 = 0x0; /* 0065: movi.n a9, 0 */
  a4 = 0x3FF7325C; /* 0067: l32r a4, 8 <hal_agreement_clr_rx_ba-0x14> (3ff7325c <hal_agreement_add_rx_ba+0x3ff73234>) */ /* MMIO base */ @0x8
  a8 = a8 - a10; /* 006a: sub a8, a8, a10 */
  a4 = a4 - a10; /* 006d: sub a4, a4, a10 */
  a3 = (a3 >> 0) & 0xFFFF; /* 0070: extui a3, a3, 0, 16 */
  MEMW(); /* 0073: memw  */
  MEM32(a8 + 0) = a9; /* 0076: s32i.n a9, a8, 0 */
  MEMW(); /* 0078: memw  */
  MEM32(a4 + 0) = a5; /* 007b: s32i.n a5, a4, 0 */
  a5 = 0x1FFB993; /* 007d: l32r a5, c <hal_agreement_clr_rx_ba-0x10> (1ffb993 <hal_agreement_add_rx_ba+0x1ffb96b>) */ @0xC
  a5 = a5 - a2; /* 0080: sub a5, a5, a2 */
  a5 = a5 << (5 & 31); /* 0083: slli a5, a5, 5 */
  a2 = 0x3FF73264; /* 0086: l32r a2, 10 <hal_agreement_clr_rx_ba-0xc> (3ff73264 <hal_agreement_add_rx_ba+0x3ff7323c>) */ /* MMIO base */ @0x10
  a2 = a2 - a10; /* 0089: sub a2, a2, a10 */
  MEMW(); /* 008c: memw  */
  MEM32(a5 + 0) = a9; /* 008f: s32i.n a9, a5, 0 */
  MEMW(); /* 0091: memw  */
  MEM32(a2 + 0) = a9; /* 0094: s32i.n a9, a2, 0 */
  a2 = 0xC0000005; /* 0096: l32r a2, 14 <hal_agreement_clr_rx_ba-0x8> (c0000005 <hal_agreement_add_rx_ba+0xbfffffdd>) */ @0x14
  a3 = a3 | a2; /* 0099: or a3, a3, a2 */
  MEMW(); /* 009c: memw  */
  MEM32(a8 + 0) = a3; /* 009f: s32i.n a3, a8, 0 */
  MEMW(); /* 00a1: memw  */
  return (int32_t)a2; /* 00a4: retw.n  */
}

/* hal_agreement_del_rx_ba @ hal_ampdu.o 00000018 size 115B bind GLOBAL
 * Calls: wifi_log | Data refs: .rodata_wlog_info.4, wifi_log
 *   MMIO: none
 *   FP/data literals (loaded, never dereferenced - NOT MMIO): 0x3FF73250, 0x3FF73264
 *   funcdb v3: 1 call(s), 2 ref(s); disasm: 1 call(s), 2 data ref(s)
 * Fidelity: medium - 43 instr, 0 branches, calls resolved */
int32_t hal_agreement_del_rx_ba(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.hal_agreement_del_rx_ba; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_18:;
  /* 0018: entry a1, 32 */
  a4 = (a2 >> 0) & 0xFF; /* 001b: extui a4, a2, 0, 8 */
  a3 = 0x3FF73250; /* 001e: l32r a3, 0 <hal_agreement_del_rx_ba-0x18> (3ff73250 <hal_agreement_add_rx_ba+0x3ff73228>) */ /* MMIO base */ @0x0
  a2 = a4 << (5 & 31); /* 0021: slli a2, a4, 5 */
  a3 = a3 - a2; /* 0024: sub a3, a3, a2 */
  a11 = 0x1; /* 0027: movi.n a11, 1 */
  a14 = a4; /* 0029: mov.n a14, a4 */
  MEMW(); /* 002b: memw  */
  a15 = MEM32(a3 + 0); /* 002e: l32i.n a15, a3, 0 */
  a12 = 0x3; /* 0030: movi.n a12, 3 */
  a15 = (a15 >> 12) & 0xF; /* 0032: extui a15, a15, 12, 4 */
  a11 = 0x2000; /* 0035: slli a11, a11, 13 */
  a10 = 0x5; /* 0038: movi a10, 5 */
  a13 = (uint32_t)&lit_rodata_wlog_info_4; /* 003b: l32r a13, 4 <hal_agreement_del_rx_ba-0x14> (0 <hal_agreement_del_rx_ba-0x18>) */ /* literal @0x4: .rodata_wlog_info.4 */
  a8 = (uint32_t)&wifi_log; /* 003e: l32r a8, 14 <hal_agreement_del_rx_ba-0x4> (0 <hal_agreement_del_rx_ba-0x18>) */ /* literal: GOT slot for wifi_log */
  wifi_log(a2, a3, a4, a5); /* call via literal slot */ /* 0041: callx8 a8 */
  MEMW(); /* 0044: memw  */
  a8 = MEM32(a3 + 0); /* 0047: l32i.n a8, a3, 0 */
  a9 = 0x7FFFFFFF; /* 0049: l32r a9, 8 <hal_agreement_del_rx_ba-0x10> (7fffffff <hal_agreement_add_rx_ba+0x7fffffd7>) */ @0x8
  a8 = a8 & a9; /* 004c: and a8, a8, a9 */
  a14 = 0x1FFB993; /* 004f: l32r a14, c <hal_agreement_del_rx_ba-0xc> (1ffb993 <hal_agreement_add_rx_ba+0x1ffb96b>) */ @0xC
  a14 = a14 - a4; /* 0052: sub a14, a14, a4 */
  a14 = a14 << (5 & 31); /* 0055: slli a14, a14, 5 */
  a9 = 0x3FF73264; /* 0058: l32r a9, 10 <hal_agreement_del_rx_ba-0x8> (3ff73264 <hal_agreement_add_rx_ba+0x3ff7323c>) */ /* MMIO base */ @0x10
  a2 = a9 - a2; /* 005b: sub a2, a9, a2 */
  a9 = 0xFFFFFFFF; /* 005e: movi.n a9, -1 */
  a9 = 0x80000000; /* 0060: slli a9, a9, 31 */
  MEMW(); /* 0063: memw  */
  MEM32(a3 + 0) = a8; /* 0066: s32i.n a8, a3, 0 */
  a8 = 0x0; /* 0068: movi.n a8, 0 */
  MEMW(); /* 006a: memw  */
  MEM32(a14 + 0) = a8; /* 006d: s32i.n a8, a14, 0 */
  MEMW(); /* 006f: memw  */
  MEM32(a2 + 0) = a8; /* 0072: s32i.n a8, a2, 0 */
  MEMW(); /* 0074: memw  */
  a2 = MEM32(a3 + 0); /* 0077: l32i.n a2, a3, 0 */
  a2 = a2 | a9; /* 0079: or a2, a2, a9 */
  MEMW(); /* 007c: memw  */
  MEM32(a3 + 0) = a2; /* 007f: s32i.n a2, a3, 0 */
  MEMW(); /* 0081: memw  */
  MEM32(a3 + 0) = a8; /* 0084: s32i.n a8, a3, 0 */
  MEMW(); /* 0086: memw  */
  return (int32_t)a2; /* 0089: retw.n  */
}

/* hal_ba_session_store @ hal_ampdu.o 00000004 size 62B bind GLOBAL
 * Calls: none | Data refs: none
 *   MMIO: 0x3FF73250, 0x3FF7325C, 0x3FF73268, 0x3FF7326C
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t hal_ba_session_store(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.hal_ba_session_store; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a8 = 0x3FF73250; /* 0007: l32r a8, 0 <hal_ba_session_store-0x4> (3ff73250 <hal_agreement_add_rx_ba+0x3ff73228>) */ /* MMIO base */ @0x0
  a9 = 0x0; /* 000a: movi.n a9, 0 */
  a10 = 0x8; /* 000c: movi.n a10, 8 */
  /* 000e: loop a10, 3d <hal_ba_session_store+0x39> */ /* loop a10 times, end L_3d; body shown single-pass */
  MEMW(); /* 0011: memw  */
  a11 = REG32(0x3FF73250); /* 0014: l32i.n a11, a8, 0 */ /* MMIO read: base 0x3FF73250+0 */
  /* 0016: bgez a11, 38 <hal_ba_session_store+0x34> */ /* UNMODELED branch */
  a12 = a2 + a9; /* 0019: add.n a12, a2, a9 */
  MEMW(); /* 001b: memw  */
  a11 = REG32(0x3FF7325C); /* 001e: l32i.n a11, a8, 12 */ /* MMIO read: base 0x3FF73250+12 */
  a11 = (a11 >> 20) & 0xFFF; /* 0020: extui a11, a11, 20, 12 */
  MEM32(a12 + 0) = a11; /* 0023: s32i.n a11, a12, 0 */
  a11 = a3 + a9; /* 0025: add.n a11, a3, a9 */
  MEMW(); /* 0027: memw  */
  a12 = REG32(0x3FF73268); /* 002a: l32i.n a12, a8, 24 */ /* MMIO read: base 0x3FF73250+24 */
  MEM32(a11 + 0) = a12; /* 002c: s32i.n a12, a11, 0 */
  a11 = a4 + a9; /* 002e: add.n a11, a4, a9 */
  MEMW(); /* 0030: memw  */
  a12 = REG32(0x3FF7326C); /* 0033: l32i.n a12, a8, 28 */ /* MMIO read: base 0x3FF73250+28 */
  MEM32(a11 + 0) = a12; /* 0035: s32i a12, a11, 0 */
L_38:;
  a8 = 0x3FF73230; /* 0038: addi a8, a8, -32 */
  a9 = 0x4; /* 003b: addi.n a9, a9, 4 */
L_3d:;
  MEMW(); /* 003d: memw  */
  return (int32_t)a2; /* 0040: retw.n  */
}

/* hal_ba_session_restore @ hal_ampdu.o 00000008 size 111B bind GLOBAL
 * Calls: none | Data refs: none
 *   MMIO: 0x3FF73250, 0x3FF7325C, 0x3FF73260, 0x3FF73264
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: medium - 44 instr, 2 branches, calls resolved */
int32_t hal_ba_session_restore(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.hal_ba_session_restore; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_8:;
  /* 0008: entry a1, 32 */
  a8 = 0x3FF73250; /* 000b: l32r a8, 0 <hal_ba_session_restore-0x8> (3ff73250 <hal_agreement_add_rx_ba+0x3ff73228>) */ /* MMIO base */ @0x0
  a9 = 0x0; /* 000e: movi.n a9, 0 */
  a11 = 0x8; /* 0010: movi.n a11, 8 */
  a13 = 0x7FFFFFFF; /* 0012: l32r a13, 4 <hal_ba_session_restore-0x4> (7fffffff <hal_agreement_add_rx_ba+0x7fffffd7>) */ @0x4
  /* 0015: loop a11, 72 <hal_ba_session_restore+0x6a> */ /* loop a11 times, end L_72; body shown single-pass */
  MEMW(); /* 0018: memw  */
  a10 = REG32(0x3FF73250); /* 001b: l32i.n a10, a8, 0 */ /* MMIO read: base 0x3FF73250+0 */
  /* 001d: bgez a10, 6d <hal_ba_session_restore+0x65> */ /* UNMODELED branch */
  a14 = 0xFFFFFFFF; /* 0020: movi.n a14, -1 */
  a14 = 0xFFFFF000; /* 0022: slli a14, a14, 12 */
  MEMW(); /* 0025: memw  */
  a10 = REG32(0x3FF73250); /* 0028: l32i.n a10, a8, 0 */ /* MMIO read: base 0x3FF73250+0 */
  a10 = a10 & a13; /* 002a: and a10, a10, a13 */
  MEMW(); /* 002d: memw  */
  REG32(0x3FF73250) = a10; /* 0030: s32i.n a10, a8, 0 */ /* MMIO write: base 0x3FF73250+0 */
  a10 = a2 + a9; /* 0032: add.n a10, a2, a9 */
  MEMW(); /* 0034: memw  */
  a12 = REG32(0x3FF7325C); /* 0037: l32i.n a12, a8, 12 */ /* MMIO read: base 0x3FF73250+12 */
  a12 = a12 & a14; /* 0039: and a12, a12, a14 */
  a10 = MEM32(a10 + 0); /* 003c: l32i.n a10, a10, 0 */
  a10 = (a10 >> 0) & 0xFFF; /* 003e: extui a10, a10, 0, 12 */
  a10 = a10 | a12; /* 0041: or a10, a10, a12 */
  a12 = 0xFFFFFFFF; /* 0044: movi.n a12, -1 */
  MEMW(); /* 0046: memw  */
  REG32(0x3FF7325C) = a10; /* 0049: s32i.n a10, a8, 12 */ /* MMIO write: base 0x3FF73250+12 */
  a10 = a3 + a9; /* 004b: add.n a10, a3, a9 */
  a12 = 0x80000000; /* 004d: slli a12, a12, 31 */
  a10 = MEM32(a10 + 0); /* 0050: l32i.n a10, a10, 0 */
  MEMW(); /* 0052: memw  */
  REG32(0x3FF73260) = a10; /* 0055: s32i.n a10, a8, 16 */ /* MMIO write: base 0x3FF73250+16 */
  a10 = a4 + a9; /* 0057: add.n a10, a4, a9 */
  a10 = MEM32(a10 + 0); /* 0059: l32i.n a10, a10, 0 */
  MEMW(); /* 005b: memw  */
  REG32(0x3FF73264) = a10; /* 005e: s32i.n a10, a8, 20 */ /* MMIO write: base 0x3FF73250+20 */
  MEMW(); /* 0060: memw  */
  a10 = REG32(0x3FF73250); /* 0063: l32i.n a10, a8, 0 */ /* MMIO read: base 0x3FF73250+0 */
  a10 = a10 | a12; /* 0065: or a10, a10, a12 */
  MEMW(); /* 0068: memw  */
  REG32(0x3FF73250) = a10; /* 006b: s32i.n a10, a8, 0 */ /* MMIO write: base 0x3FF73250+0 */
L_6d:;
  a8 = 0x3FF73230; /* 006d: addi a8, a8, -32 */
  a9 = 0x4; /* 0070: addi.n a9, a9, 4 */
L_72:;
  MEMW(); /* 0072: memw  */
  return (int32_t)a2; /* 0075: retw.n  */
}

/* hal_ba_session_restore_by_hw_index @ hal_ampdu.o 00000014 size 134B bind GLOBAL
 * Calls: none | Data refs: none
 *   MMIO: none
 *   FP/data literals (loaded, never dereferenced - NOT MMIO): 0x3FF73250, 0x3FF73264, 0x3FF7325C
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: medium - 50 instr, 1 branches, calls resolved */
int32_t hal_ba_session_restore_by_hw_index(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.hal_ba_session_restore_by_hw_index; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_14:;
  /* 0014: entry a1, 32 */
  a11 = (a2 >> 0) & 0xFF; /* 0017: extui a11, a2, 0, 8 */
  a8 = 0x3FF73250; /* 001a: l32r a8, 0 <hal_ba_session_restore_by_hw_index-0x14> (3ff73250 <hal_agreement_add_rx_ba+0x3ff73228>) */ /* MMIO base */ @0x0
  a10 = a11 << (5 & 31); /* 001d: slli a10, a11, 5 */
  a8 = a8 - a10; /* 0020: sub a8, a8, a10 */
  a2 = a11; /* 0023: mov.n a2, a11 */
  MEMW(); /* 0025: memw  */
  a9 = MEM32(a8 + 0); /* 0028: l32i.n a9, a8, 0 */
  /* 002a: bgez a9, 95 <hal_ba_session_restore_by_hw_index+0x81> */ /* UNMODELED branch */
  a4 = (a11 << 4) + a4; /* 002d: addx4 a4, a11, a4 */
  a5 = (a11 << 4) + a5; /* 0030: addx4 a5, a11, a5 */
  MEMW(); /* 0033: memw  */
  a9 = MEM32(a8 + 0); /* 0036: l32i.n a9, a8, 0 */
  a2 = (a11 << 4) + a3; /* 0038: addx4 a2, a11, a3 */
  a12 = 0x7FFFFFFF; /* 003b: l32r a12, 4 <hal_ba_session_restore_by_hw_index-0x10> (7fffffff <hal_agreement_add_rx_ba+0x7fffffd7>) */ @0x4
  a9 = a9 & a12; /* 003e: and a9, a9, a12 */
  MEMW(); /* 0041: memw  */
  MEM32(a8 + 0) = a9; /* 0044: s32i.n a9, a8, 0 */
  a9 = 0x1FFB993; /* 0046: l32r a9, 8 <hal_ba_session_restore_by_hw_index-0xc> (1ffb993 <hal_agreement_add_rx_ba+0x1ffb96b>) */ @0x8
  a9 = a9 - a11; /* 0049: sub a9, a9, a11 */
  a9 = a9 << (5 & 31); /* 004c: slli a9, a9, 5 */
  a11 = 0xFFFFFFFF; /* 004f: movi.n a11, -1 */
  a4 = MEM32(a4 + 0); /* 0051: l32i.n a4, a4, 0 */
  a11 = 0xFFFFF000; /* 0053: slli a11, a11, 12 */
  MEMW(); /* 0056: memw  */
  MEM32(a9 + 0) = a4; /* 0059: s32i.n a4, a9, 0 */
  a9 = 0x3FF73264; /* 005b: l32r a9, c <hal_ba_session_restore_by_hw_index-0x8> (3ff73264 <hal_agreement_add_rx_ba+0x3ff7323c>) */ /* MMIO base */ @0xC
  a9 = a9 - a10; /* 005e: sub a9, a9, a10 */
  a4 = MEM32(a5 + 0); /* 0061: l32i.n a4, a5, 0 */
  MEMW(); /* 0063: memw  */
  MEM32(a9 + 0) = a4; /* 0066: s32i.n a4, a9, 0 */
  a9 = 0x3FF7325C; /* 0068: l32r a9, 10 <hal_ba_session_restore_by_hw_index-0x4> (3ff7325c <hal_agreement_add_rx_ba+0x3ff73234>) */ /* MMIO base */ @0x10
  a9 = a9 - a10; /* 006b: sub a9, a9, a10 */
  MEMW(); /* 006e: memw  */
  a10 = MEM32(a9 + 0); /* 0071: l32i.n a10, a9, 0 */
  a10 = a10 & a11; /* 0073: and a10, a10, a11 */
  a2 = MEM32(a2 + 0); /* 0076: l32i.n a2, a2, 0 */
  a2 = (a2 >> 0) & 0xFFF; /* 0078: extui a2, a2, 0, 12 */
  a2 = a2 | a10; /* 007b: or a2, a2, a10 */
  MEMW(); /* 007e: memw  */
  MEM32(a9 + 0) = a2; /* 0081: s32i.n a2, a9, 0 */
  a9 = 0xFFFFFFFF; /* 0083: movi.n a9, -1 */
  a9 = 0x80000000; /* 0085: slli a9, a9, 31 */
  MEMW(); /* 0088: memw  */
  a2 = MEM32(a8 + 0); /* 008b: l32i.n a2, a8, 0 */
  a2 = a2 | a9; /* 008d: or a2, a2, a9 */
  MEMW(); /* 0090: memw  */
  MEM32(a8 + 0) = a2; /* 0093: s32i.n a2, a8, 0 */
L_95:;
  MEMW(); /* 0095: memw  */
  return (int32_t)a2; /* 0098: retw.n  */
}

