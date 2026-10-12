/* ===== hal_crypto.o : reconstructed from libpp.a (ESP32, Xtensa, esp-2022r1) =====
 * Toolchain: xtensa-esp32-elf (GCC 11.2.0 crosstool-NG esp-2022r1).
 * ABI: args a2..a7, return a2 (all functions take a2..a7, return int32_t).
 * memw barriers preserved as MEMW(). MMIO as REG32/REG16/REG8(addr).
 * Calls with unknown arg counts are modeled with 4 live args (a2..a5);
 * a2..a7 are clobbered across calls (windowed-ABI approximation).
 * Sections: .text.hal_crypto_clr_key_entry, .text.hal_crypto_disable, .text.hal_crypto_enable, .text.hal_crypto_get_key_entry, .text.hal_crypto_get_using_key_idx, .text.hal_crypto_init, .text.hal_crypto_is_key_valid, .text.hal_crypto_mgmt_rx_enabled, .text.hal_crypto_set_key_entry
 * Undefined refs (5): free, g_osi_funcs_p, memcpy, memset, wifi_log
 */
#include <stdint.h>
#define REG32(a) (*(volatile uint32_t *)(a))
#define REG16(a) (*(volatile uint16_t *)(a))
#define REG8(a)  (*(volatile uint8_t *)(a))
#define MEM32(a) (*(volatile uint32_t *)(a))
#define MEM16(a) (*(volatile uint16_t *)(a))
#define MEM8(a)  (*(volatile uint8_t *)(a))
#define MEMW() __asm__ volatile("memw" ::: "memory")

extern int32_t g_osi_funcs_p();
extern int32_t memset();
extern int32_t memcpy();
extern uint32_t rodata_func_1; /* .rodata.__func__$1 */
extern uint32_t rodata_wlog_warning_2; /* .rodata_wlog_warning.2 */
extern uint32_t rodata_wlog_warning_3; /* .rodata_wlog_warning.3 */
extern int32_t wifi_log();
extern int32_t free();
extern uint32_t rodata_func_0; /* .rodata.__func__$0 */
extern uint32_t rodata_wlog_warning_4; /* .rodata_wlog_warning.4 */

/* pool[hal_crypto_clr_key_entry]: +0x0=0x3FF73814, +0x4=0x3FF74400, +0x8=0x3FF74404, +0xc=0x3FF74408, +0x10=0x3FF7440C, +0x14=0x3FF74410, +0x18=0x3FF74414, +0x1c=0x3FF74418, +0x20=0x3FF7441C, +0x24=0x3FF74420, +0x28=0x3FF74424 */
/* pool[hal_crypto_get_using_key_idx]: +0x0=0x3FF7442C */
/* pool[hal_crypto_set_key_entry]: +0x0=0x00000000(g_osi_funcs_p), +0x24=0x00000000(memset), +0x28=0x00000000(memcpy), +0x4=0x00000000(.rodata.__func__$1), +0x8=0x00000000(.rodata_wlog_warning.2), +0xc=0x00000000(.rodata_wlog_warning.3), +0x2c=0x00000000(wifi_log), +0x10=0x00003C1F, +0x14=0x3FF74400, +0x18=0x3FF74404, +0x1c=0x3FF73814, +0x20=0x3FF74408, +0x30=0x00000000(memcpy), +0x34=0x00000000(free) */
/* pool[hal_crypto_is_key_valid]: +0x0=0x3FF73814 */
/* pool[hal_crypto_get_key_entry]: +0x0=0x00000000(.rodata.__func__$0), +0x4=0x00000000(.rodata_wlog_warning.4), +0x14=0x00000000(wifi_log), +0x8=0x3FF74400, +0xc=0x3FF74404, +0x10=0x3FF74408, +0x18=0x00000000(memcpy) */
/* pool[hal_crypto_init]: +0x4=0x00030000, +0x0=0x3FF73800, +0x8=0x3FF73804, +0xc=0x3FF73808, +0x10=0x3FF7380C, +0x14=0x3FF73810 */
/* pool[hal_crypto_mgmt_rx_enabled]: +0x4=0x3FF73800, +0x0=0x3FF73804 */
/* pool[hal_crypto_enable]: +0x0=0x3FF73800, +0x4=0x3FF73804, +0x8=0x3FF73808, +0x10=0x10010103, +0xc=0x00010103, +0x14=0x3FF73810, +0x18=0x00FFFF00, +0x1c=0x3FFFFFFF, +0x20=0xFF0000FF */
/* pool[hal_crypto_disable]: +0x0=0x3FF73800, +0x8=0x3FF73804, +0x4=0x00030000, +0xc=0x3FF73814 */

/* hal_crypto_clr_key_entry @ hal_crypto.o 0000002c size 147B bind GLOBAL
 * Calls: none | Data refs: none
 *   MMIO: 0x3FF73814
 *   FP/data literals (loaded, never dereferenced - NOT MMIO): 0x3FF74400, 0x3FF74404, 0x3FF74408, 0x3FF7440C, 0x3FF74410, 0x3FF74414, 0x3FF74418, 0x3FF7441C, 0x3FF74420, 0x3FF74424
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: medium - 54 instr, 0 branches, calls resolved */
int32_t hal_crypto_clr_key_entry(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.hal_crypto_clr_key_entry; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_2c:;
  /* 002c: entry a1, 32 */
  a9 = 0x3FF73814; /* 002f: l32r a9, 0 <hal_crypto_clr_key_entry-0x2c> (3ff73814 <hal_crypto_set_key_entry+0x3ff737dc>) */ /* MMIO base */ @0x0
  a8 = 0xFFFFFFFE; /* 0032: movi.n a8, -2 */
  /* 0034: ssl a2 */ /* UNMODELED: a2 clobbered */
  /* 0037: src a8, a8, a8 */ /* UNMODELED: a8 clobbered */
  a2 = (a2 << 4) + a2; /* 003a: addx4 a2, a2, a2 */
  MEMW(); /* 003d: memw  */
  a10 = REG32(0x3FF73814); /* 0040: l32i.n a10, a9, 0 */ /* MMIO read: base 0x3FF73814+0 */
  a8 = a8 & a10; /* 0042: and a8, a8, a10 */
  MEMW(); /* 0045: memw  */
  REG32(0x3FF73814) = a8; /* 0048: s32i.n a8, a9, 0 */ /* MMIO write: base 0x3FF73814+0 */
  a8 = 0x0; /* 004a: movi.n a8, 0 */
  a9 = 0x3FF74400; /* 004c: l32r a9, 4 <hal_crypto_clr_key_entry-0x28> (3ff74400 <hal_crypto_set_key_entry+0x3ff743c8>) */ /* MMIO base */ @0x4
  a9 = (a2 << 8) + a9; /* 004f: addx8 a9, a2, a9 */
  MEMW(); /* 0052: memw  */
  MEM32(a9 + 0) = a8; /* 0055: s32i.n a8, a9, 0 */
  a9 = 0x3FF74404; /* 0057: l32r a9, 8 <hal_crypto_clr_key_entry-0x24> (3ff74404 <hal_crypto_set_key_entry+0x3ff743cc>) */ /* MMIO base */ @0x8
  a9 = (a2 << 8) + a9; /* 005a: addx8 a9, a2, a9 */
  MEMW(); /* 005d: memw  */
  MEM32(a9 + 0) = a8; /* 0060: s32i.n a8, a9, 0 */
  a9 = 0x3FF74408; /* 0062: l32r a9, c <hal_crypto_clr_key_entry-0x20> (3ff74408 <hal_crypto_set_key_entry+0x3ff743d0>) */ /* MMIO base */ @0xC
  a9 = (a2 << 8) + a9; /* 0065: addx8 a9, a2, a9 */
  MEMW(); /* 0068: memw  */
  MEM32(a9 + 0) = a8; /* 006b: s32i.n a8, a9, 0 */
  a9 = 0x3FF7440C; /* 006d: l32r a9, 10 <hal_crypto_clr_key_entry-0x1c> (3ff7440c <hal_crypto_set_key_entry+0x3ff743d4>) */ /* MMIO base */ @0x10
  a9 = (a2 << 8) + a9; /* 0070: addx8 a9, a2, a9 */
  MEMW(); /* 0073: memw  */
  MEM32(a9 + 0) = a8; /* 0076: s32i.n a8, a9, 0 */
  a9 = 0x3FF74410; /* 0078: l32r a9, 14 <hal_crypto_clr_key_entry-0x18> (3ff74410 <hal_crypto_set_key_entry+0x3ff743d8>) */ /* MMIO base */ @0x14
  a9 = (a2 << 8) + a9; /* 007b: addx8 a9, a2, a9 */
  MEMW(); /* 007e: memw  */
  MEM32(a9 + 0) = a8; /* 0081: s32i.n a8, a9, 0 */
  a9 = 0x3FF74414; /* 0083: l32r a9, 18 <hal_crypto_clr_key_entry-0x14> (3ff74414 <hal_crypto_set_key_entry+0x3ff743dc>) */ /* MMIO base */ @0x18
  a9 = (a2 << 8) + a9; /* 0086: addx8 a9, a2, a9 */
  MEMW(); /* 0089: memw  */
  MEM32(a9 + 0) = a8; /* 008c: s32i.n a8, a9, 0 */
  a9 = 0x3FF74418; /* 008e: l32r a9, 1c <hal_crypto_clr_key_entry-0x10> (3ff74418 <hal_crypto_set_key_entry+0x3ff743e0>) */ /* MMIO base */ @0x1C
  a9 = (a2 << 8) + a9; /* 0091: addx8 a9, a2, a9 */
  MEMW(); /* 0094: memw  */
  MEM32(a9 + 0) = a8; /* 0097: s32i.n a8, a9, 0 */
  a9 = 0x3FF7441C; /* 0099: l32r a9, 20 <hal_crypto_clr_key_entry-0xc> (3ff7441c <hal_crypto_set_key_entry+0x3ff743e4>) */ /* MMIO base */ @0x20
  a9 = (a2 << 8) + a9; /* 009c: addx8 a9, a2, a9 */
  MEMW(); /* 009f: memw  */
  MEM32(a9 + 0) = a8; /* 00a2: s32i.n a8, a9, 0 */
  a9 = 0x3FF74420; /* 00a4: l32r a9, 24 <hal_crypto_clr_key_entry-0x8> (3ff74420 <hal_crypto_set_key_entry+0x3ff743e8>) */ /* MMIO base */ @0x24
  a9 = (a2 << 8) + a9; /* 00a7: addx8 a9, a2, a9 */
  MEMW(); /* 00aa: memw  */
  MEM32(a9 + 0) = a8; /* 00ad: s32i.n a8, a9, 0 */
  a9 = 0x3FF74424; /* 00af: l32r a9, 28 <hal_crypto_clr_key_entry-0x4> (3ff74424 <hal_crypto_set_key_entry+0x3ff743ec>) */ /* MMIO base */ @0x28
  a2 = (a2 << 8) + a9; /* 00b2: addx8 a2, a2, a9 */
  MEMW(); /* 00b5: memw  */
  MEM32(a2 + 0) = a8; /* 00b8: s32i.n a8, a2, 0 */
  MEMW(); /* 00ba: memw  */
  return (int32_t)a2; /* 00bd: retw.n  */
}

/* hal_crypto_get_using_key_idx @ hal_crypto.o 00000004 size 16B bind GLOBAL
 * Calls: none | Data refs: none
 *   MMIO: 0x3FF7442C
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t hal_crypto_get_using_key_idx(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.hal_crypto_get_using_key_idx; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a2 = 0x3FF7442C; /* 0007: l32r a2, 0 <hal_crypto_get_using_key_idx-0x4> (3ff7442c <hal_crypto_set_key_entry+0x3ff743f4>) */ /* MMIO base */ @0x0
  MEMW(); /* 000a: memw  */
  a2 = REG32(0x3FF7442C); /* 000d: l32i.n a2, a2, 0 */ /* MMIO read: base 0x3FF7442C+0 */
  a2 = (a2 >> 30) & 0x3; /* 000f: extui a2, a2, 30, 2 */
  return (int32_t)a2; /* 0012: retw.n  */
}

/* hal_crypto_set_key_entry @ hal_crypto.o 00000038 size 330B bind GLOBAL
 * Calls: free, memcpy, memset, wifi_log, g_osi_funcs_p[got] | Data refs: .rodata.__func__$1, .rodata_wlog_warning.2, .rodata_wlog_warning.3, free, g_osi_funcs_p, memcpy, memset, wifi_log
 *   MMIO: 0x3FF73814
 *   FP/data literals (loaded, never dereferenced - NOT MMIO): 0x3FF74400, 0x3FF74404, 0x3FF74408
 *   funcdb v3: 4 call(s), 8 ref(s); disasm: 6 call(s), 8 data ref(s)
 * Fidelity: medium - 122 instr, 10 branches, calls resolved */
int32_t hal_crypto_set_key_entry(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.hal_crypto_set_key_entry; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_38:;
  /* 0038: entry a1, 48 */
  a7 = 0xFFFFFFFC; /* 003b: movi.n a7, -4 */
  a6 = a4 + (3); /* 003d: addi.n a6, a4, 3 */
  a6 = a6 & a7; /* 003f: and a6, a6, a7 */
  a7 = (a3 >> 0) & 0x3; /* 0042: extui a7, a3, 0, 2 */
  if (a7 == 0) goto L_81; /* 0045: beqz.n a7, 81 <hal_crypto_set_key_entry+0x49> */
  a7 = (uint32_t)&g_osi_funcs_p; /* 0047: l32r a7, 0 <hal_crypto_set_key_entry-0x38> (0 <hal_crypto_set_key_entry-0x38>) */ /* literal @0x0: g_osi_funcs_p */
  a10 = a6; /* 004a: mov.n a10, a6 */
  a7 = MEM32(a7 + 0); /* 004c: l32i.n a7, a7, 0 */
  a7 = MEM32(a7 + 364); /* 004e: l32i a7, a7, 0x16c */
  g_osi_funcs_p(a2, a3, a4, a5); /* call via literal slot */ /* 0051: callx8 a7 */
  a7 = a10; /* 0054: mov.n a7, a10 */
  if (a10 == 0) goto L_74; /* 0056: beqz.n a10, 74 <hal_crypto_set_key_entry+0x3c> */
  a12 = a6; /* 0058: mov.n a12, a6 */
  a11 = 0x0; /* 005a: movi.n a11, 0 */
  a8 = (uint32_t)&memset; /* 005c: l32r a8, 24 <hal_crypto_set_key_entry-0x14> (0 <hal_crypto_set_key_entry-0x38>) */ /* literal: GOT slot for memset */
  memset(a2, a3, a4, a5); /* call via literal slot */ /* 005f: callx8 a8 */
  a12 = a4; /* 0062: mov.n a12, a4 */
  a11 = a3 | a3; /* 0064: or a11, a3, a3 */
  a10 = a7 | a7; /* 0067: or a10, a7, a7 */
  a8 = (uint32_t)&memcpy; /* 006a: l32r a8, 28 <hal_crypto_set_key_entry-0x10> (0 <hal_crypto_set_key_entry-0x38>) */ /* literal: GOT slot for memcpy */
  memcpy(a2, a3, a4, a5); /* call via literal slot */ /* 006d: callx8 a8 */
  goto L_83; /* 0070: j 83 <hal_crypto_set_key_entry+0x4b> */
  /* 0073: .byte 00 */
L_74:;
  a14 = (uint32_t)&lit_rodata_func_1; /* 0074: l32r a14, 4 <hal_crypto_set_key_entry-0x34> (0 <hal_crypto_set_key_entry-0x38>) */ /* literal @0x4: .rodata.__func__$1 */
  a15 = 0x81; /* 0077: movi a15, 129 */
  a13 = (uint32_t)&lit_rodata_wlog_warning_2; /* 007a: l32r a13, 8 <hal_crypto_set_key_entry-0x30> (0 <hal_crypto_set_key_entry-0x38>) */ /* literal @0x8: .rodata_wlog_warning.2 */
  goto L_91; /* 007d: j 91 <hal_crypto_set_key_entry+0x59> */
  /* 0080: .byte 00 */
L_81:;
  a7 = a3; /* 0081: mov.n a7, a3 */
L_83:;
  a4 = (a7 >> 0) & 0x3; /* 0083: extui a4, a7, 0, 2 */
  if (a4 == 0) goto L_a0; /* 0086: beqz.n a4, a0 <hal_crypto_set_key_entry+0x68> */
  a14 = (uint32_t)&lit_rodata_func_1; /* 0088: l32r a14, 4 <hal_crypto_set_key_entry-0x34> (0 <hal_crypto_set_key_entry-0x38>) */ /* literal @0x4: .rodata.__func__$1 */
  a15 = 0x85; /* 008b: movi a15, 133 */
  a13 = (uint32_t)&lit_rodata_wlog_warning_3; /* 008e: l32r a13, c <hal_crypto_set_key_entry-0x2c> (0 <hal_crypto_set_key_entry-0x38>) */ /* literal @0xC: .rodata_wlog_warning.3 */
L_91:;
  a11 = 0x1; /* 0091: movi.n a11, 1 */
  a12 = 0x2; /* 0093: movi.n a12, 2 */
  a11 = 0x2000; /* 0095: slli a11, a11, 13 */
  a10 = 0x6; /* 0098: movi.n a10, 6 */
  a8 = (uint32_t)&wifi_log; /* 009a: l32r a8, 2c <hal_crypto_set_key_entry-0xc> (0 <hal_crypto_set_key_entry-0x38>) */ /* literal: GOT slot for wifi_log */
  wifi_log(a2, a3, a4, a5); /* call via literal slot */ /* 009d: callx8 a8 */
L_a0:;
  a4 = 0x0; /* 00a0: movi.n a4, 0 */
  MEM16(a1 + 0) = a4; /* 00a2: s16i a4, a1, 0 */
  MEMW(); /* 00a5: memw  */
  a11 = MEM8(a5 + 6); /* 00a8: l8ui a11, a5, 6 */
  a11 = a11 << (24 & 31); /* 00ab: slli a11, a11, 24 */
  a8 = MEM8(a5 + 5); /* 00ae: l8ui a8, a5, 5 */
  a8 = a8 << (16 & 31); /* 00b1: slli a8, a8, 16 */
  a11 = a11 + a8; /* 00b4: add.n a11, a11, a8 */
  a8 = MEM8(a5 + 4); /* 00b6: l8ui a8, a5, 4 */
  a8 = a8 << (8 & 31); /* 00b9: slli a8, a8, 8 */
  a11 = a11 + a8; /* 00bc: add.n a11, a11, a8 */
  a9 = MEM8(a5 + 8); /* 00be: l8ui a9, a5, 8 */
  a9 = a9 << (8 & 31); /* 00c1: slli a9, a9, 8 */
  a8 = MEM8(a5 + 7); /* 00c4: l8ui a8, a5, 7 */
  a8 = a8 + a9; /* 00c7: add.n a8, a8, a9 */
  a8 = (a8 >> 0) & 0xFFFF; /* 00c9: extui a8, a8, 0, 16 */
  a4 = MEM8(a5 + 3); /* 00cc: l8ui a4, a5, 3 */
  a11 = a11 + a4; /* 00cf: add.n a11, a11, a4 */
  a9 = MEM8(a5 + 1); /* 00d1: l8ui a9, a5, 1 */
  if (a9 != 5) goto L_e0; /* 00d4: bnei a9, 5, e0 <hal_crypto_set_key_entry+0xa8> */
  a9 = a9 << (16 & 31); /* 00d7: slli a9, a9, 16 */
  MEMW(); /* 00da: memw  */
  goto L_e6; /* 00dd: j e6 <hal_crypto_set_key_entry+0xae> */
L_e0:;
  a9 = (a9 >> 0) & 0x7; /* 00e0: extui a9, a9, 0, 3 */
  a9 = a9 << (18 & 31); /* 00e3: slli a9, a9, 18 */
L_e6:;
  a8 = a8 | a9; /* 00e6: or a8, a8, a9 */
  a9 = 0x7; /* 00e9: movi.n a9, 7 */
  a9 = 0x1C0000; /* 00eb: slli a9, a9, 18 */
  a12 = 0x1; /* 00ee: movi.n a12, 1 */
  a9 = a8 & a9; /* 00f0: and a9, a8, a9 */
  a12 = 0x40000; /* 00f3: slli a12, a12, 18 */
  a10 = 0x7; /* 00f6: movi a10, 7 */
  if (a9 == a12) goto L_104; /* 00f9: beq a9, a12, 104 <hal_crypto_set_key_entry+0xcc> */
  a10 = 0x3; /* 00fc: movi.n a10, 3 */
  if (a2 >= 4) goto L_104; /* 00fe: bgei a2, 4, 104 <hal_crypto_set_key_entry+0xcc> */
  a10 = 0x6; /* 0101: movi a10, 6 */
L_104:;
  a9 = MEM8(a5 + 0); /* 0104: l8ui a9, a5, 0 */
  a10 = 0xC0; /* 0107: slli a10, a10, 5 */
  a9 = (a9 >> 0) & 0x3; /* 010a: extui a9, a9, 0, 2 */
  a9 = a9 << (8 & 31); /* 010d: slli a9, a9, 8 */
  a9 = a9 | a10; /* 0110: or a9, a9, a10 */
  a5 = MEM8(a5 + 2); /* 0113: l8ui a5, a5, 2 */
  a12 = a6; /* 0116: mov.n a12, a6 */
  a5 = a5 << (14 & 31); /* 0118: slli a5, a5, 14 */
  a9 = a9 | a5; /* 011b: or a9, a9, a5 */
  a5 = (a8 >> 16) & 0xFFFF; /* 011e: extui a5, a8, 16, 16 */
  a4 = 0x3C1F; /* 0121: l32r a4, 10 <hal_crypto_set_key_entry-0x28> (3c1f <hal_crypto_set_key_entry+0x3be7>) */ @0x10
  a8 = (a8 >> 0) & 0xFFFF; /* 0124: extui a8, a8, 0, 16 */
  a5 = a5 & a4; /* 0127: and a5, a5, a4 */
  a9 = a9 | a5; /* 012a: or a9, a9, a5 */
  a9 = a9 << (16 & 31); /* 012d: slli a9, a9, 16 */
  a5 = 0x3FF74400; /* 0130: l32r a5, 14 <hal_crypto_set_key_entry-0x24> (3ff74400 <hal_crypto_set_key_entry+0x3ff743c8>) */ /* MMIO base */ @0x14
  a8 = a8 | a9; /* 0133: or a8, a8, a9 */
  a9 = (a2 << 4) + a2; /* 0136: addx4 a9, a2, a2 */
  a5 = (a9 << 8) + a5; /* 0139: addx8 a5, a9, a5 */
  MEMW(); /* 013c: memw  */
  MEM32(a5 + 0) = a11; /* 013f: s32i.n a11, a5, 0 */
  a11 = a7; /* 0141: mov.n a11, a7 */
  a5 = 0x3FF74404; /* 0143: l32r a5, 18 <hal_crypto_set_key_entry-0x20> (3ff74404 <hal_crypto_set_key_entry+0x3ff743cc>) */ /* MMIO base */ @0x18
  a5 = (a9 << 8) + a5; /* 0146: addx8 a5, a9, a5 */
  MEMW(); /* 0149: memw  */
  MEM32(a5 + 0) = a8; /* 014c: s32i.n a8, a5, 0 */
  a5 = 0x1; /* 014e: movi.n a5, 1 */
  /* 0150: ssl a2 */ /* UNMODELED: a2 clobbered */
  /* 0153: sll a5, a5 */ /* UNMODELED: a5 clobbered */
  a8 = 0x3FF73814; /* 0156: l32r a8, 1c <hal_crypto_set_key_entry-0x1c> (3ff73814 <hal_crypto_set_key_entry+0x3ff737dc>) */ /* MMIO base */ @0x1C
  MEMW(); /* 0159: memw  */
  a4 = REG32(0x3FF73814); /* 015c: l32i.n a4, a8, 0 */ /* MMIO read: base 0x3FF73814+0 */
  a5 = a5 | a4; /* 015e: or a5, a5, a4 */
  a10 = 0x3FF74408; /* 0161: l32r a10, 20 <hal_crypto_set_key_entry-0x18> (3ff74408 <hal_crypto_set_key_entry+0x3ff743d0>) */ /* MMIO base */ @0x20
  a10 = (a9 << 8) + a10; /* 0164: addx8 a10, a9, a10 */
  MEMW(); /* 0167: memw  */
  REG32(0x3FF73814) = a5; /* 016a: s32i.n a5, a8, 0 */ /* MMIO write: base 0x3FF73814+0 */
  MEMW(); /* 016c: memw  */
  a8 = (uint32_t)&memcpy; /* 016f: l32r a8, 30 <hal_crypto_set_key_entry-0x8> (0 <hal_crypto_set_key_entry-0x38>) */ /* literal: GOT slot for memcpy */
  memcpy(a2, a3, a4, a5); /* call via literal slot */ /* 0172: callx8 a8 */
  if (a7 == a3) goto L_180; /* 0175: beq a7, a3, 180 <hal_crypto_set_key_entry+0x148> */
  a10 = a7; /* 0178: mov.n a10, a7 */
  a8 = (uint32_t)&free; /* 017a: l32r a8, 34 <hal_crypto_set_key_entry-0x4> (0 <hal_crypto_set_key_entry-0x38>) */ /* literal: GOT slot for free */
  free(a2, a3, a4, a5); /* call via literal slot */ /* 017d: callx8 a8 */
L_180:;
  return (int32_t)a2; /* 0180: retw.n  */
}

/* hal_crypto_is_key_valid @ hal_crypto.o 00000004 size 29B bind GLOBAL
 * Calls: none | Data refs: none
 *   MMIO: 0x3FF73814
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t hal_crypto_is_key_valid(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.hal_crypto_is_key_valid; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a8 = 0x3FF73814; /* 0007: l32r a8, 0 <hal_crypto_is_key_valid-0x4> (3ff73814 <hal_crypto_set_key_entry+0x3ff737dc>) */ /* MMIO base */ @0x0
  MEMW(); /* 000a: memw  */
  a9 = REG32(0x3FF73814); /* 000d: l32i.n a9, a8, 0 */ /* MMIO read: base 0x3FF73814+0 */
  a8 = 0x1; /* 000f: movi.n a8, 1 */
  /* 0011: ssl a2 */ /* UNMODELED: a2 clobbered */
  /* 0014: sll a2, a8 */ /* UNMODELED: a2 clobbered */
  a9 = a2 & a9; /* 0017: and a9, a2, a9 */
  a2 = 0x0; /* 001a: movi.n a2, 0 */
  if (a9 != 0) a2 = a8; /* 001c: movnez a2, a8, a9 */
  return (int32_t)a2; /* 001f: retw.n  */
}

/* hal_crypto_get_key_entry @ hal_crypto.o 0000001c size 155B bind GLOBAL
 * Calls: memcpy, wifi_log | Data refs: .rodata.__func__$0, .rodata_wlog_warning.4, memcpy, wifi_log
 *   MMIO: none
 *   FP/data literals (loaded, never dereferenced - NOT MMIO): 0x3FF74400, 0x3FF74404, 0x3FF74408
 *   funcdb v3: 2 call(s), 4 ref(s); disasm: 2 call(s), 4 data ref(s)
 * Fidelity: medium - 57 instr, 2 branches, calls resolved */
int32_t hal_crypto_get_key_entry(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.hal_crypto_get_key_entry; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_1c:;
  /* 001c: entry a1, 48 */
  a8 = (a3 >> 0) & 0x3; /* 001f: extui a8, a3, 0, 2 */
  if (a8 == 0) goto L_3c; /* 0022: beqz.n a8, 3c <hal_crypto_get_key_entry+0x20> */
  a11 = 0x1; /* 0024: movi.n a11, 1 */
  a14 = (uint32_t)&lit_rodata_func_0; /* 0026: l32r a14, 0 <hal_crypto_get_key_entry-0x1c> (0 <hal_crypto_get_key_entry-0x1c>) */ /* literal @0x0: .rodata.__func__$0 */
  a15 = 0xC8; /* 0029: movi a15, 200 */
  a12 = 0x2; /* 002c: movi.n a12, 2 */
  a11 = 0x2000; /* 002e: slli a11, a11, 13 */
  a10 = 0x6; /* 0031: movi.n a10, 6 */
  a13 = (uint32_t)&lit_rodata_wlog_warning_4; /* 0033: l32r a13, 4 <hal_crypto_get_key_entry-0x18> (0 <hal_crypto_get_key_entry-0x1c>) */ /* literal @0x4: .rodata_wlog_warning.4 */
  a8 = (uint32_t)&wifi_log; /* 0036: l32r a8, 14 <hal_crypto_get_key_entry-0x8> (0 <hal_crypto_get_key_entry-0x1c>) */ /* literal: GOT slot for wifi_log */
  wifi_log(a2, a3, a4, a5); /* call via literal slot */ /* 0039: callx8 a8 */
L_3c:;
  a2 = (a2 << 4) + a2; /* 003c: addx4 a2, a2, a2 */
  a10 = a2 << (3 & 31); /* 003f: slli a10, a2, 3 */
  a8 = 0x3FF74400; /* 0042: l32r a8, 8 <hal_crypto_get_key_entry-0x14> (3ff74400 <hal_crypto_set_key_entry+0x3ff743c8>) */ /* MMIO base */ @0x8
  a8 = (a2 << 8) + a8; /* 0045: addx8 a8, a2, a8 */
  a9 = MEM32(a8 + 0); /* 0048: l32i.n a9, a8, 0 */
  a14 = (a9 >> 8) & 0xFF; /* 004a: extui a14, a9, 8, 8 */
  a13 = (a9 >> 16) & 0xFF; /* 004d: extui a13, a9, 16, 8 */
  a12 = (a9 >> 24) & 0xFF; /* 0050: extui a12, a9, 24, 8 */
  a8 = 0x3FF74404; /* 0053: l32r a8, c <hal_crypto_get_key_entry-0x10> (3ff74404 <hal_crypto_set_key_entry+0x3ff743cc>) */ /* MMIO base */ @0xC
  a2 = (a2 << 8) + a8; /* 0056: addx8 a2, a2, a8 */
  a2 = MEM32(a2 + 0); /* 0059: l32i.n a2, a2, 0 */
  a8 = (a2 >> 24) & 0x3; /* 005b: extui a8, a2, 24, 2 */
  a11 = (a2 >> 8) & 0xFF; /* 005e: extui a11, a2, 8, 8 */
  MEM8(a5 + 0) = a8; /* 0061: s8i a8, a5, 0 */
  a8 = (a2 >> 30) & 0x3; /* 0064: extui a8, a2, 30, 2 */
  MEM8(a5 + 2) = a8; /* 0067: s8i a8, a5, 2 */
  a8 = 0x1F; /* 006a: movi.n a8, 31 */
  a8 = 0x1F0000; /* 006c: slli a8, a8, 16 */
  a8 = a2 & a8; /* 006f: and a8, a2, a8 */
  MEM32(a1 + 4) = a9; /* 0072: s32i.n a9, a1, 4 */
  MEM8(a5 + 3) = a9; /* 0074: s8i a9, a5, 3 */
  a9 = 0x5; /* 0077: movi.n a9, 5 */
  a9 = 0x50000; /* 0079: slli a9, a9, 16 */
  MEM8(a5 + 8) = a11; /* 007c: s8i a11, a5, 8 */
  a11 = 0x5; /* 007f: movi.n a11, 5 */
  MEM32(a1 + 0) = a2; /* 0081: s32i.n a2, a1, 0 */
  MEM8(a5 + 4) = a14; /* 0083: s8i a14, a5, 4 */
  MEM8(a5 + 5) = a13; /* 0086: s8i a13, a5, 5 */
  MEM8(a5 + 6) = a12; /* 0089: s8i a12, a5, 6 */
  MEM8(a5 + 7) = a2; /* 008c: s8i a2, a5, 7 */
  MEMW(); /* 008f: memw  */
  if (a8 == a9) goto L_98; /* 0092: beq a8, a9, 98 <hal_crypto_get_key_entry+0x7c> */
  a11 = (a2 >> 18) & 0x7; /* 0095: extui a11, a2, 18, 3 */
L_98:;
  a4 = a4 + (3); /* 0098: addi.n a4, a4, 3 */
  a12 = 0xFFFFFFFC; /* 009a: movi.n a12, -4 */
  MEM8(a5 + 1) = a11; /* 009c: s8i a11, a5, 1 */
  MEMW(); /* 009f: memw  */
  a12 = a4 & a12; /* 00a2: and a12, a4, a12 */
  a11 = 0x3FF74408; /* 00a5: l32r a11, 10 <hal_crypto_get_key_entry-0xc> (3ff74408 <hal_crypto_set_key_entry+0x3ff743d0>) */ /* MMIO base */ @0x10
  a11 = a10 + a11; /* 00a8: add.n a11, a10, a11 */
  a10 = a3; /* 00aa: mov.n a10, a3 */
  MEMW(); /* 00ac: memw  */
  a8 = (uint32_t)&memcpy; /* 00af: l32r a8, 18 <hal_crypto_get_key_entry-0x4> (0 <hal_crypto_get_key_entry-0x1c>) */ /* literal: GOT slot for memcpy */
  memcpy(a2, a3, a4, a5); /* call via literal slot */ /* 00b2: callx8 a8 */
  return (int32_t)a2; /* 00b5: retw.n  */
}

/* hal_crypto_init @ hal_crypto.o 00000018 size 53B bind GLOBAL
 * Calls: none | Data refs: none
 *   MMIO: 0x3FF73800, 0x3FF73804, 0x3FF73808, 0x3FF7380C, 0x3FF73810
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t hal_crypto_init(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.hal_crypto_init; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_18:;
  /* 0018: entry a1, 32 */
  a8 = 0x30000; /* 001b: l32r a8, 4 <hal_crypto_init-0x14> (30000 <hal_crypto_set_key_entry+0x2ffc8>) */ @0x4
  a9 = 0x3FF73800; /* 001e: l32r a9, 0 <hal_crypto_init-0x18> (3ff73800 <hal_crypto_set_key_entry+0x3ff737c8>) */ /* MMIO base */ @0x0
  MEMW(); /* 0021: memw  */
  REG32(0x3FF73800) = a8; /* 0024: s32i.n a8, a9, 0 */ /* MMIO write: base 0x3FF73800+0 */
  a9 = 0x3FF73804; /* 0026: l32r a9, 8 <hal_crypto_init-0x10> (3ff73804 <hal_crypto_set_key_entry+0x3ff737cc>) */ /* MMIO base */ @0x8
  MEMW(); /* 0029: memw  */
  REG32(0x3FF73804) = a8; /* 002c: s32i.n a8, a9, 0 */ /* MMIO write: base 0x3FF73804+0 */
  a8 = 0x0; /* 002e: movi.n a8, 0 */
  a9 = 0x3FF73808; /* 0030: l32r a9, c <hal_crypto_init-0xc> (3ff73808 <hal_crypto_set_key_entry+0x3ff737d0>) */ /* MMIO base */ @0xC
  MEMW(); /* 0033: memw  */
  REG32(0x3FF73808) = a8; /* 0036: s32i.n a8, a9, 0 */ /* MMIO write: base 0x3FF73808+0 */
  a9 = 0x3FF7380C; /* 0038: l32r a9, 10 <hal_crypto_init-0x8> (3ff7380c <hal_crypto_set_key_entry+0x3ff737d4>) */ /* MMIO base */ @0x10
  MEMW(); /* 003b: memw  */
  REG32(0x3FF7380C) = a8; /* 003e: s32i.n a8, a9, 0 */ /* MMIO write: base 0x3FF7380C+0 */
  a9 = 0x3FF73810; /* 0040: l32r a9, 14 <hal_crypto_init-0x4> (3ff73810 <hal_crypto_set_key_entry+0x3ff737d8>) */ /* MMIO base */ @0x14
  MEMW(); /* 0043: memw  */
  REG32(0x3FF73810) = a8; /* 0046: s32i.n a8, a9, 0 */ /* MMIO write: base 0x3FF73810+0 */
  MEMW(); /* 0048: memw  */
  return (int32_t)a2; /* 004b: retw.n  */
}

/* hal_crypto_mgmt_rx_enabled @ hal_crypto.o 00000008 size 25B bind GLOBAL
 * Calls: none | Data refs: none
 *   MMIO: 0x3FF73804
 *   FP/data literals (loaded, never dereferenced - NOT MMIO): 0x3FF73800
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t hal_crypto_mgmt_rx_enabled(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.hal_crypto_mgmt_rx_enabled; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_8:;
  /* 0008: entry a1, 32 */
  a2 = (a2 >> 0) & 0xFF; /* 000b: extui a2, a2, 0, 8 */
  a8 = 0x3FF73800; /* 000e: l32r a8, 4 <hal_crypto_mgmt_rx_enabled-0x4> (3ff73800 <hal_crypto_set_key_entry+0x3ff737c8>) */ /* MMIO base */ @0x4
  if (a2 != 1) goto L_17; /* 0011: bnei a2, 1, 17 <hal_crypto_mgmt_rx_enabled+0xf> */
  a8 = 0x3FF73804; /* 0014: l32r a8, 0 <hal_crypto_mgmt_rx_enabled-0x8> (3ff73804 <hal_crypto_set_key_entry+0x3ff737cc>) */ /* MMIO base */ @0x0
L_17:;
  MEMW(); /* 0017: memw  */
  a2 = REG32(0x3FF73804); /* 001a: l32i.n a2, a8, 0 */ /* MMIO read: base 0x3FF73804+0 */
  a2 = (a2 >> 17) & 0x1; /* 001c: extui a2, a2, 17, 1 */
  return (int32_t)a2; /* 001f: retw.n  */
}

/* hal_crypto_enable @ hal_crypto.o 00000024 size 152B bind GLOBAL
 * Calls: none | Data refs: none
 *   MMIO: 0x3FF73808, 0x3FF73810
 *   FP/data literals (loaded, never dereferenced - NOT MMIO): 0x3FF73800, 0x3FF73804, 0x3FFFFFFF
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: medium - 55 instr, 8 branches, calls resolved */
int32_t hal_crypto_enable(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.hal_crypto_enable; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_24:;
  /* 0024: entry a1, 32 */
  a2 = (a2 >> 0) & 0xFF; /* 0027: extui a2, a2, 0, 8 */
  a8 = 0x3FF73800; /* 002a: l32r a8, 0 <hal_crypto_enable-0x24> (3ff73800 <hal_crypto_set_key_entry+0x3ff737c8>) */ /* MMIO base */ @0x0
  a3 = (a3 >> 0) & 0xFF; /* 002d: extui a3, a3, 0, 8 */
  a4 = (a4 >> 0) & 0xFF; /* 0030: extui a4, a4, 0, 8 */
  a5 = (a5 >> 0) & 0xFF; /* 0033: extui a5, a5, 0, 8 */
  if (a2 == 0) goto L_48; /* 0036: beqz a2, 48 <hal_crypto_enable+0x24> */
  a8 = 0x3FF73804; /* 0039: l32r a8, 4 <hal_crypto_enable-0x20> (3ff73804 <hal_crypto_set_key_entry+0x3ff737cc>) */ /* MMIO base */ @0x4
  if (a2 == 1) goto L_48; /* 003c: beqi a2, 1, 48 <hal_crypto_enable+0x24> */
  a8 = 0x3FF73800; /* 003f: l32r a8, 0 <hal_crypto_enable-0x24> (3ff73800 <hal_crypto_set_key_entry+0x3ff737c8>) */ /* MMIO base */ @0x0
  if (a2 != 2) goto L_48; /* 0042: bnei a2, 2, 48 <hal_crypto_enable+0x24> */
  a8 = 0x3FF73808; /* 0045: l32r a8, 8 <hal_crypto_enable-0x1c> (3ff73808 <hal_crypto_set_key_entry+0x3ff737d0>) */ /* MMIO base */ @0x8
L_48:;
  a10 = 0xFFFFFFFB; /* 0048: movi.n a10, -5 */
  a10 = a3 & a10; /* 004a: and a10, a3, a10 */
  a9 = 0x10010103; /* 004d: l32r a9, 10 <hal_crypto_enable-0x14> (10010103 <hal_crypto_set_key_entry+0x100100cb>) */ @0x10
  if (a10 == 1) goto L_56; /* 0050: beqi a10, 1, 56 <hal_crypto_enable+0x32> */
  a9 = 0x10103; /* 0053: l32r a9, c <hal_crypto_enable-0x18> (10103 <hal_crypto_set_key_entry+0x100cb>) */ @0xC
L_56:;
  if (a4 == 0) goto L_60; /* 0056: beqz.n a4, 60 <hal_crypto_enable+0x3c> */
  a10 = 0x1; /* 0058: movi.n a10, 1 */
  a10 = 0x20000; /* 005a: slli a10, a10, 17 */
  a9 = 0x30103; /* 005d: or a9, a9, a10 */
L_60:;
  if (a5 == 0) goto L_68; /* 0060: beqz.n a5, 68 <hal_crypto_enable+0x44> */
  a2 = 0x200; /* 0062: movi a2, 0x200 */
  a9 = 0x30303; /* 0065: or a9, a9, a2 */
L_68:;
  MEMW(); /* 0068: memw  */
  REG32(0x3FF73808) = a9; /* 006b: s32i.n a9, a8, 0 */ /* MMIO write: base 0x3FF73808+0 */
  a9 = 0x3FF73810; /* 006d: l32r a9, 14 <hal_crypto_enable-0x10> (3ff73810 <hal_crypto_set_key_entry+0x3ff737d8>) */ /* MMIO base */ @0x14
  MEMW(); /* 0070: memw  */
  a10 = REG32(0x3FF73810); /* 0073: l32i.n a10, a9, 0 */ /* MMIO read: base 0x3FF73810+0 */
  if (a3 != 4) goto L_9c; /* 0075: bnei a3, 4, 9c <hal_crypto_enable+0x78> */
  a2 = 0xFFFF00; /* 0078: l32r a2, 18 <hal_crypto_enable-0xc> (ffff00 <hal_crypto_set_key_entry+0xfffec8>) */ @0x18
  a10 = a10 | a2; /* 007b: or a10, a10, a2 */
  MEMW(); /* 007e: memw  */
  REG32(0x3FF73810) = a10; /* 0081: s32i.n a10, a9, 0 */ /* MMIO write: base 0x3FF73810+0 */
  a10 = 0xFFFFFFFF; /* 0083: movi.n a10, -1 */
  a10 = 0x80000000; /* 0085: slli a10, a10, 31 */
  MEMW(); /* 0088: memw  */
  a9 = REG32(0x3FF73808); /* 008b: l32i.n a9, a8, 0 */ /* MMIO read: base 0x3FF73808+0 */
  a2 = 0x3FFFFFFF; /* 008d: l32r a2, 1c <hal_crypto_enable-0x8> (3fffffff <hal_crypto_set_key_entry+0x3fffffc7>) */ /* MMIO base */ @0x1C
  a9 = a9 & a2; /* 0090: and a9, a9, a2 */
  a9 = a9 | a10; /* 0093: or a9, a9, a10 */
  MEMW(); /* 0096: memw  */
  goto L_b2; /* 0099: j b2 <hal_crypto_enable+0x8e> */
L_9c:;
  a2 = 0xFF0000FF; /* 009c: l32r a2, 20 <hal_crypto_enable-0x4> (ff0000ff <hal_crypto_set_key_entry+0xff0000c7>) */ @0x20
  a10 = 0x80000000; /* 009f: and a10, a10, a2 */
  MEMW(); /* 00a2: memw  */
  MEM32(a9 + 0) = a10; /* 00a5: s32i.n a10, a9, 0 */
  MEMW(); /* 00a7: memw  */
  a9 = REG32(0x3FF73808); /* 00aa: l32i.n a9, a8, 0 */ /* MMIO read: base 0x3FF73808+0 */
  a2 = 0x3FFFFFFF; /* 00ac: l32r a2, 1c <hal_crypto_enable-0x8> (3fffffff <hal_crypto_set_key_entry+0x3fffffc7>) */ /* MMIO base */ @0x1C
  a9 = a9 & a2; /* 00af: and a9, a9, a2 */
L_b2:;
  MEMW(); /* 00b2: memw  */
  REG32(0x3FF73808) = a9; /* 00b5: s32i.n a9, a8, 0 */ /* MMIO write: base 0x3FF73808+0 */
  MEMW(); /* 00b7: memw  */
  return (int32_t)a2; /* 00ba: retw.n  */
}

/* hal_crypto_disable @ hal_crypto.o 00000010 size 56B bind GLOBAL
 * Calls: none | Data refs: none
 *   MMIO: 0x3FF73804, 0x3FF73814
 *   FP/data literals (loaded, never dereferenced - NOT MMIO): 0x3FF73800
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t hal_crypto_disable(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.hal_crypto_disable; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_10:;
  /* 0010: entry a1, 32 */
  a2 = (a2 >> 0) & 0xFF; /* 0013: extui a2, a2, 0, 8 */
  if (a2 != 0) goto L_20; /* 0016: bnez.n a2, 20 <hal_crypto_disable+0x10> */
  a2 = 0x3FF73800; /* 0018: l32r a2, 0 <hal_crypto_disable-0x10> (3ff73800 <hal_crypto_set_key_entry+0x3ff737c8>) */ /* MMIO base */ @0x0
  goto L_26; /* 001b: j 26 <hal_crypto_disable+0x16> */
  /* 001e: .byte 00 */
  /* 001f: .byte 00 */
L_20:;
  if (a2 != 1) goto L_2e; /* 0020: bnei a2, 1, 2e <hal_crypto_disable+0x1e> */
  a2 = 0x3FF73804; /* 0023: l32r a2, 8 <hal_crypto_disable-0x8> (3ff73804 <hal_crypto_set_key_entry+0x3ff737cc>) */ /* MMIO base */ @0x8
L_26:;
  a8 = 0x30000; /* 0026: l32r a8, 4 <hal_crypto_disable-0xc> (30000 <hal_crypto_set_key_entry+0x2ffc8>) */ @0x4
  MEMW(); /* 0029: memw  */
  REG32(0x3FF73804) = a8; /* 002c: s32i.n a8, a2, 0 */ /* MMIO write: base 0x3FF73804+0 */
L_2e:;
  a8 = 0xFFFFFFFF; /* 002e: movi.n a8, -1 */
  a8 = a8 ^ a3; /* 0030: xor a8, a8, a3 */
  a9 = 0x3FF73814; /* 0033: l32r a9, c <hal_crypto_disable-0x4> (3ff73814 <hal_crypto_set_key_entry+0x3ff737dc>) */ /* MMIO base */ @0xC
  MEMW(); /* 0036: memw  */
  a2 = REG32(0x3FF73814); /* 0039: l32i.n a2, a9, 0 */ /* MMIO read: base 0x3FF73814+0 */
  a8 = a8 & a2; /* 003b: and a8, a8, a2 */
  MEMW(); /* 003e: memw  */
  REG32(0x3FF73814) = a8; /* 0041: s32i.n a8, a9, 0 */ /* MMIO write: base 0x3FF73814+0 */
  MEMW(); /* 0043: memw  */
  return (int32_t)a2; /* 0046: retw.n  */
}

