/* ===== esf_buf.o : reconstructed from libpp.a (ESP32, Xtensa, esp-2022r1) =====
 * Toolchain: xtensa-esp32-elf (GCC 11.2.0 crosstool-NG esp-2022r1).
 * ABI: args a2..a7, return a2 (all functions take a2..a7, return int32_t).
 * memw barriers preserved as MEMW(). MMIO as REG32/REG16/REG8(addr).
 * Calls with unknown arg counts are modeled with 4 live args (a2..a5);
 * a2..a7 are clobbered across calls (windowed-ABI approximation).
 * Sections: .text.esf_buf_alloc_default_handler, .text.esf_buf_alloc_dynamic_default_handler, .text.esf_buf_free_static, .text.esf_buf_recycle_default_handler, .text.esf_buf_setdown, .text.esf_buf_setup, .text.esf_buf_setup_for_mesh, .text.esf_buf_setup_static, .text.esf_buf_statis_dump, .wifiextrairam.4, .wifirxiram.8, .wifislprxiram.6
 * Undefined refs (8): config_is_cache_tx_buf_enabled, g_lmac_cnt, g_osi_funcs_p, g_wifi_global_lock, g_wifi_menuconfig, memcpy, memset, wifi_log
 */
#include <stdint.h>
#define REG32(a) (*(volatile uint32_t *)(a))
#define REG16(a) (*(volatile uint16_t *)(a))
#define REG8(a)  (*(volatile uint8_t *)(a))
#define MEM32(a) (*(volatile uint32_t *)(a))
#define MEM16(a) (*(volatile uint16_t *)(a))
#define MEM8(a)  (*(volatile uint8_t *)(a))
#define MEMW() __asm__ volatile("memw" ::: "memory")

extern uint32_t rodata_wlog_error_3; /* .rodata_wlog_error.3 */
extern int32_t wifi_log();
extern int32_t g_osi_funcs_p();
extern uint32_t g_wifi_global_lock; /* g_wifi_global_lock */
extern int32_t g_lmac_cnt();
extern int32_t memset();
extern int32_t memcpy();
extern uint32_t rodata_wlog_error_5; /* .rodata_wlog_error.5 */
extern int32_t rodata();
extern int32_t g_wifi_menuconfig();
uint32_t g_eb_list_desc; /* defined here (.bss/.data); was: g_eb_list_desc */
extern uint32_t rodata_wlog_error_7; /* .rodata_wlog_error.7 */
extern uint32_t rodata_wlog_warning_9; /* .rodata_wlog_warning.9 */
extern int32_t eb_txdesc_space();
extern int32_t eb_space();
extern uint32_t rodata_wlog_info_10; /* .rodata_wlog_info.10 */
extern uint32_t rodata_wlog_info_11; /* .rodata_wlog_info.11 */
extern uint32_t rodata_wlog_info_12; /* .rodata_wlog_info.12 */
extern uint32_t rodata_wlog_info_13; /* .rodata_wlog_info.13 */
extern uint32_t rodata_wlog_info_14; /* .rodata_wlog_info.14 */
extern uint32_t rodata_wlog_info_15; /* .rodata_wlog_info.15 */
extern int32_t config_is_cache_tx_buf_enabled();
extern uint32_t rodata_wlog_info_16; /* .rodata_wlog_info.16 */
extern uint32_t rodata_wlog_info_17; /* .rodata_wlog_info.17 */
extern uint32_t rodata_esf_buf_statis_dump_str1_1; /* .rodata.esf_buf_statis_dump.str1.1 */
extern uint32_t rodata_wlog_info_18; /* .rodata_wlog_info.18 */
extern uint32_t rodata_wlog_info_19; /* .rodata_wlog_info.19 */

/* pool[esf_buf_alloc_dynamic_default_handler]: +0x0=0x00000000(.rodata_wlog_error.3), +0x4=0x00000000(wifi_log) */
/* pool[esf_buf_alloc_dynamic]: +0x4=0x00000000(g_osi_funcs_p), +0x0=0x00000000(g_wifi_global_lock), +0x8=0x00000000(g_lmac_cnt), +0x14=0x00000000(esf_buf_alloc_dynamic_default_handler), +0x18=0x00000000(memset), +0x1c=0x00000000(memset), +0xc=0x00000FFB, +0x10=0xDEADBEEF, +0x20=0x00000000(memcpy) */
/* pool[esf_buf_alloc_default_handler]: +0x0=0x00000000(.rodata_wlog_error.5), +0x4=0x00000000(wifi_log) */
/* pool[esf_buf_alloc]: +0x0=0x00000000(.rodata), +0x4=0x00000000(g_wifi_menuconfig), +0xc=0x00000000(g_osi_funcs_p), +0x8=0x00000000(g_wifi_global_lock), +0x10=0x00000000(g_eb_list_desc), +0x14=0x00000000(g_lmac_cnt), +0x18=0x00000000(memcpy), +0x1c=0x00000000(esf_buf_alloc_dynamic), +0x20=0x00000000(esf_buf_alloc_default_handler) */
/* pool[esf_buf_recycle_default_handler]: +0x0=0x00000000(.rodata_wlog_error.7), +0x4=0x00000000(wifi_log) */
/* pool[esf_buf_recycle]: +0x0=0x00000024(.rodata), +0x4=0x00000000(g_wifi_menuconfig), +0x18=0x00000000(memset), +0xc=0x00000000(g_osi_funcs_p), +0x8=0x00000000(g_wifi_global_lock), +0x10=0x00000000(g_eb_list_desc), +0x14=0x00000000(g_lmac_cnt), +0x1c=0x00000000(esf_buf_recycle_default_handler) */
/* pool[esf_buf_setup_for_mesh]: +0x0=0x00000000(g_eb_list_desc) */
/* pool[esf_buf_setup_static]: +0x0=0x00000000(g_eb_list_desc), +0x8=0x00000000(esf_buf_alloc_dynamic), +0x4=0x00000000(.rodata_wlog_warning.9), +0xc=0x00000000(wifi_log), +0x10=0x00000000(esf_buf_recycle) */
/* pool[esf_buf_free_static]: +0x0=0x00000000(g_eb_list_desc), +0x8=0x00000000(g_osi_funcs_p), +0x4=0x00000000(g_wifi_global_lock), +0xc=0x00000000(memset), +0x10=0x00000000(memset) */
/* pool[esf_buf_setdown]: +0x0=0x00000000(esf_buf_free_static) */
/* pool[esf_buf_setup]: +0x4=0x00000000(eb_txdesc_space), +0x2c=0x00000000(memset), +0x0=0x00000000(eb_space), +0x30=0x00000000(memset), +0x8=0x00000000(g_wifi_menuconfig), +0xc=0x00000000(g_eb_list_desc), +0x10=0x00000000(.rodata_wlog_info.10), +0x34=0x00000000(wifi_log), +0x38=0x00000000(esf_buf_setup_static), +0x14=0x00000000(.rodata_wlog_info.11), +0x18=0x00000000(.rodata_wlog_info.12), +0x3c=0x00000000(wifi_log), +0x1c=0x00000000(.rodata_wlog_info.13), +0x40=0x00000000(wifi_log), +0x44=0x00000000(esf_buf_setup_static), +0x20=0x00000000(.rodata_wlog_info.14), +0x24=0x00000000(.rodata_wlog_info.15), +0x48=0x00000000(wifi_log), +0x4c=0x00000000(config_is_cache_tx_buf_enabled), +0x50=0x00000000(esf_buf_setup_static), +0x28=0x00000000(.rodata_wlog_info.16), +0x54=0x00000000(wifi_log), +0x58=0x00000000(esf_buf_recycle), +0x5c=0x00000000(esf_buf_setdown) */
/* pool[esf_buf_statis_dump]: +0x0=0x00000000(.rodata_wlog_info.17), +0x30=0x00000000(wifi_log), +0x10=0x00000006(.rodata.esf_buf_statis_dump.str1.1), +0x14=0x0000000F(.rodata.esf_buf_statis_dump.str1.1), +0x18=0x00000017(.rodata.esf_buf_statis_dump.str1.1), +0x1c=0x00000022(.rodata.esf_buf_statis_dump.str1.1), +0x20=0x0000002E(.rodata.esf_buf_statis_dump.str1.1), +0x4=0x00000000(.rodata.esf_buf_statis_dump.str1.1), +0x8=0x00000004(.rodata.esf_buf_statis_dump.str1.1), +0xc=0x00000000(.rodata_wlog_info.18), +0x34=0x00000000(wifi_log), +0x28=0x00000000(g_lmac_cnt), +0x24=0x00000000(g_eb_list_desc), +0x2c=0x00000000(.rodata_wlog_info.19), +0x38=0x00000000(wifi_log) */

/* esf_buf_alloc_dynamic_default_handler @ esf_buf.o 00000008 size 25B bind GLOBAL
 * Calls: wifi_log | Data refs: .rodata_wlog_error.3, wifi_log
 *   MMIO: none
 *   funcdb v3: 1 call(s), 2 ref(s); disasm: 1 call(s), 2 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t esf_buf_alloc_dynamic_default_handler(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.esf_buf_alloc_dynamic_default_handler; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_8:;
  /* 0008: entry a1, 32 */
  a13 = (uint32_t)&lit_rodata_wlog_error_3; /* 000b: l32r a13, 0 <esf_buf_alloc_dynamic_default_handler-0x8> (0 <esf_buf_alloc_dynamic_default_handler-0x8>) */ /* literal @0x0: .rodata_wlog_error.3 */
  a14 = a2; /* 000e: mov.n a14, a2 */
  a12 = 0x1; /* 0010: movi.n a12, 1 */
  a11 = 0x400; /* 0012: movi a11, 0x400 */
  a10 = 0x6; /* 0015: movi.n a10, 6 */
  a8 = (uint32_t)&wifi_log; /* 0017: l32r a8, 4 <esf_buf_alloc_dynamic_default_handler-0x4> (0 <esf_buf_alloc_dynamic_default_handler-0x8>) */ /* literal: GOT slot for wifi_log */
  wifi_log(a2, a3, a4, a5); /* call via literal slot */ /* 001a: callx8 a8 */
  a2 = 0x0; /* 001d: movi.n a2, 0 */
  return (int32_t)a2; /* 001f: retw.n  */
}

/* esf_buf_alloc_dynamic @ esf_buf.o 00000024 size 452B bind GLOBAL
 * Calls: g_osi_funcs_p[got], g_osi_funcs_p[got], esf_buf_alloc_dynamic_default_handler[got], memset[got], memset[got], memcpy[got] | Data refs: g_osi_funcs_p, g_wifi_global_lock, g_lmac_cnt, esf_buf_alloc_dynamic_default_handler, memset, memcpy
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 6 call(s), 6 data ref(s)
 * Fidelity: medium - 179 instr, 17 branches, 3 indirect; flow + direct calls mapped, GOT-indirects enumerated (verified against section disasm) */
int32_t esf_buf_alloc_dynamic(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .wifiextrairam.4; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_24:;
  /* 0024: entry a1, 48 */
  a5 = MEM16(a2 + 16); /* 0027: l16ui a5, a2, 16 */
  a6 = MEM8(a2 + 8); /* 002a: l8ui a6, a2, 8 */
  a7 = MEM8(a2 + 12); /* 002d: l8ui a7, a2, 12 */
  if (a5 == 0) goto L_94; /* 0030: beqz a5, 94 <esf_buf_alloc_dynamic+0x70> */
  a5 = (uint32_t)&g_osi_funcs_p; /* 0033: l32r a5, 4 <esf_buf_alloc_dynamic-0x20> (0 <esf_buf_alloc_dynamic-0x24>) */ /* literal @0x4: g_osi_funcs_p */
  a9 = (uint32_t)&g_wifi_global_lock; /* 0036: l32r a9, 0 <esf_buf_alloc_dynamic-0x24> (0 <esf_buf_alloc_dynamic-0x24>) */ /* literal @0x0: g_wifi_global_lock */
  a8 = MEM32(a5 + 0); /* 0039: l32i.n a8, a5, 0 */
  a10 = MEM32(a9 + 0); /* 003b: l32i.n a10, a9, 0 */
  a8 = MEM32(a8 + 84); /* 003d: l32i a8, a8, 84 */
  MEM32(a1 + 4) = a9; /* 0040: s32i.n a9, a1, 4 */
  MEMW(); /* 0042: memw  */
  ((int32_t(*)())a8)(a2, a3, a4, a5); /* 0045: callx8 a8 */ /* indirect */
  a8 = MEM16(a2 + 14); /* 0048: l16ui a8, a2, 14 */
  a12 = MEM16(a2 + 16); /* 004b: l16ui a12, a2, 16 */
  a10 = MEM32(a5 + 0); /* 004e: l32i.n a10, a5, 0 */
  a5 = a6 + a6; /* 0050: add.n a5, a6, a6 */
  a11 = (uint32_t)&g_lmac_cnt; /* 0052: l32r a11, 8 <esf_buf_alloc_dynamic-0x1c> (0 <esf_buf_alloc_dynamic-0x24>) */ /* literal @0x8: g_lmac_cnt */
  a9 = MEM32(a1 + 4); /* 0055: l32i.n a9, a1, 4 */
  if (a8 < a12) goto L_76; /* 0057: bltu a8, a12, 76 <esf_buf_alloc_dynamic+0x52> */
  a5 = a5 + a6; /* 005a: add.n a5, a5, a6 */
  a5 = (a5 << 4) + a11; /* 005c: addx4 a5, a5, a11 */
  a2 = MEM16(a5 + 10); /* 005f: l16ui a2, a5, 10 */
  a2 = a2 + (1); /* 0062: addi.n a2, a2, 1 */
  MEM16(a5 + 10) = a2; /* 0064: s16i a2, a5, 10 */
  MEMW(); /* 0067: memw  */
  a2 = MEM32(a10 + 88); /* 006a: l32i a2, a10, 88 */
  a10 = MEM32(a9 + 0); /* 006d: l32i.n a10, a9, 0 */
  MEMW(); /* 006f: memw  */
  goto L_1dc; /* 0072: j 1dc <esf_buf_alloc_dynamic+0x1b8> */
  /* 0075: .byte 00 */
L_76:;
  a5 = a5 + a6; /* 0076: add.n a5, a5, a6 */
  a5 = (a5 << 4) + a11; /* 0078: addx4 a5, a5, a11 */
  a8 = a8 + (1); /* 007b: addi.n a8, a8, 1 */
  MEM16(a2 + 14) = a8; /* 007d: s16i a8, a2, 14 */
  MEMW(); /* 0080: memw  */
  a8 = MEM32(a5 + 0); /* 0083: l32i.n a8, a5, 0 */
  a8 = a8 + (1); /* 0085: addi.n a8, a8, 1 */
  MEM32(a5 + 0) = a8; /* 0087: s32i.n a8, a5, 0 */
  a5 = MEM32(a10 + 88); /* 0089: l32i a5, a10, 88 */
  a10 = MEM32(a9 + 0); /* 008c: l32i.n a10, a9, 0 */
  MEMW(); /* 008e: memw  */
  ((int32_t(*)())a5)(a2, a3, a4, a5); /* 0091: callx8 a5 */ /* indirect */
L_94:;
  if (a6 >= 5) goto L_9c; /* 0094: bgeui a6, 5, 9c <esf_buf_alloc_dynamic+0x78> */
  if (a6 == 0) goto L_cd; /* 0097: beqz.n a6, cd <esf_buf_alloc_dynamic+0xa9> */
  goto L_aa; /* 0099: j aa <esf_buf_alloc_dynamic+0x86> */
L_9c:;
  a5 = a6 + (-7); /* 009c: addi a5, a6, -7 */
  a5 = (a5 >> 0) & 0xFF; /* 009f: extui a5, a5, 0, 8 */
  if (a5 < 3) goto L_b8; /* 00a2: bltui a5, 3, b8 <esf_buf_alloc_dynamic+0x94> */
  goto L_cd; /* 00a5: j cd <esf_buf_alloc_dynamic+0xa9> */
  /* 00a8: .byte 00 */
  /* 00a9: .byte 00 */
L_aa:;
  a5 = (uint32_t)&g_osi_funcs_p; /* 00aa: l32r a5, 4 <esf_buf_alloc_dynamic-0x20> (0 <esf_buf_alloc_dynamic-0x24>) */ /* literal @0x4: g_osi_funcs_p */
  a10 = a3 + (96); /* 00ad: addi a10, a3, 96 */
  a5 = MEM32(a5 + 0); /* 00b0: l32i.n a5, a5, 0 */
  a5 = MEM32(a5 + 348); /* 00b2: l32i a5, a5, 0x15c */
  goto L_c3; /* 00b5: j c3 <esf_buf_alloc_dynamic+0x9f> */
L_b8:;
  a5 = (uint32_t)&g_osi_funcs_p; /* 00b8: l32r a5, 4 <esf_buf_alloc_dynamic-0x20> (0 <esf_buf_alloc_dynamic-0x24>) */ /* literal @0x4: g_osi_funcs_p */
  a10 = a3 + (96); /* 00bb: addi a10, a3, 96 */
  a5 = MEM32(a5 + 0); /* 00be: l32i.n a5, a5, 0 */
  a5 = MEM32(a5 + 364); /* 00c0: l32i a5, a5, 0x16c */
L_c3:;
  a10 = a10 + a7; /* 00c3: add.n a10, a10, a7 */
  g_osi_funcs_p(a2, a3, a4, a5); /* call via literal slot */ /* 00c5: callx8 a5 */
  goto L_d5; /* 00c8: j d5 <esf_buf_alloc_dynamic+0xb1> */
  /* 00cb: .byte 00 */
  /* 00cc: .byte 00 */
L_cd:;
  a10 = a6; /* 00cd: mov.n a10, a6 */
  a8 = (uint32_t)&esf_buf_alloc_dynamic_default_handler; /* 00cf: l32r a8, 14 <esf_buf_alloc_dynamic-0x10> (0 <esf_buf_alloc_dynamic-0x24>) */ /* literal: GOT slot for esf_buf_alloc_dynamic_default_handler */
  esf_buf_alloc_dynamic_default_handler(a2, a3, a4, a5); /* call via literal slot */ /* 00d2: callx8 a8 */
L_d5:;
  a5 = a10; /* 00d5: mov.n a5, a10 */
  if (a10 == 0) goto L_190; /* 00d7: beqz a10, 190 <esf_buf_alloc_dynamic+0x16c> */
  a12 = 0x5C; /* 00da: movi.n a12, 92 */
  a11 = 0x0; /* 00dc: movi.n a11, 0 */
  a8 = (uint32_t)&memset; /* 00de: l32r a8, 18 <esf_buf_alloc_dynamic-0xc> (0 <esf_buf_alloc_dynamic-0x24>) */ /* literal: GOT slot for memset */
  memset(a2, a3, a4, a5); /* call via literal slot */ /* 00e1: callx8 a8 */
  a8 = a5 + (60); /* 00e4: addi a8, a5, 60 */
  a13 = a5 + (48); /* 00e7: addi a13, a5, 48 */
  MEM32(a5 + 44) = a8; /* 00ea: s32i.n a8, a5, 44 */
  a8 = a5 + (92); /* 00ec: addi a8, a5, 92 */
  a12 = a7; /* 00ef: mov.n a12, a7 */
  a11 = 0x0; /* 00f1: movi.n a11, 0 */
  a10 = a8; /* 00f3: mov.n a10, a8 */
  MEM32(a5 + 4) = a13; /* 00f5: s32i.n a13, a5, 4 */
  MEM32(a5 + 16) = a8; /* 00f7: s32i.n a8, a5, 16 */
  MEM32(a1 + 0) = a13; /* 00f9: s32i.n a13, a1, 0 */
  MEM32(a1 + 4) = a5; /* 00fb: s32i.n a5, a1, 4 */
  MEMW(); /* 00fd: memw  */
  a8 = (uint32_t)&memset; /* 0100: l32r a8, 1c <esf_buf_alloc_dynamic-0x8> (0 <esf_buf_alloc_dynamic-0x24>) */ /* literal: GOT slot for memset */
  memset(a2, a3, a4, a5); /* call via literal slot */ /* 0103: callx8 a8 */
  a8 = a10; /* 0106: mov.n a8, a10 */
  a10 = 0x1; /* 0108: movi.n a10, 1 */
  a11 = (a3 >> 0) & 0xFFFF; /* 010a: extui a11, a3, 0, 16 */
  a2 = MEM32(a2 + 4); /* 010d: l32i.n a2, a2, 4 */
  a13 = MEM32(a1 + 0); /* 010f: l32i.n a13, a1, 0 */
  MEM32(a5 + 60) = a2; /* 0111: s32i.n a2, a5, 60 */
  a2 = MEM32(a5 + 64); /* 0113: l32i a2, a5, 64 */
  MEM16(a5 + 12) = a10; /* 0116: s16i a10, a5, 12 */
  MEMW(); /* 0119: memw  */
  a10 = 0xF; /* 011c: movi.n a10, 15 */
  a2 = a2 | a10; /* 011e: or a2, a2, a10 */
  a10 = a8 + a7; /* 0121: add.n a10, a8, a7 */
  a12 = 0xFFB; /* 0123: l32r a12, c <esf_buf_alloc_dynamic-0x18> (ffb <esf_buf_setup+0xf9b>) */ @0xC
  MEM32(a5 + 64) = a2; /* 0126: s32i a2, a5, 64 */
  a2 = a7 + a3; /* 0129: add.n a2, a7, a3 */
  MEM32(a5 + 8) = a13; /* 012b: s32i.n a13, a5, 8 */
  MEM32(a5 + 52) = a10; /* 012d: s32i.n a10, a5, 52 */
  a9 = MEM32(a1 + 4); /* 012f: l32i.n a9, a1, 4 */
  if (a12 >= a2) goto L_14d; /* 0131: bgeu a12, a2, 14d <esf_buf_alloc_dynamic+0x129> */
  a7 = 0xFFFFFFFF; /* 0134: movi.n a7, -1 */
  a7 = 0xFFFFF000; /* 0136: slli a7, a7, 12 */
  MEMW(); /* 0139: memw  */
  a2 = MEM32(a5 + 48); /* 013c: l32i.n a2, a5, 48 */
  a2 = a2 & a7; /* 013e: and a2, a2, a7 */
  a7 = 0x3FF; /* 0141: movi a7, 0x3ff */
  a7 = 0xFFC; /* 0144: slli a7, a7, 2 */
  MEMW(); /* 0147: memw  */
  goto L_166; /* 014a: j 166 <esf_buf_alloc_dynamic+0x142> */
L_14d:;
  a8 = a8 + a2; /* 014d: add.n a8, a8, a2 */
  a2 = 0xDEADBEEF; /* 014f: l32r a2, 10 <esf_buf_alloc_dynamic-0x14> (deadbeef <esf_buf_setup+0xdeadbe8f>) */ @0x10
  a7 = a11 + a7; /* 0152: add.n a7, a11, a7 */
  a7 = (a7 >> 0) & 0xFFF; /* 0154: extui a7, a7, 0, 12 */
  MEM32(a8 + 0) = a2; /* 0157: s32i.n a2, a8, 0 */
  a8 = 0xFFFFFFFF; /* 0159: movi.n a8, -1 */
  a8 = 0xFFFFF000; /* 015b: slli a8, a8, 12 */
  MEMW(); /* 015e: memw  */
  a2 = MEM32(a5 + 48); /* 0161: l32i.n a2, a5, 48 */
  a2 = a2 & a8; /* 0163: and a2, a2, a8 */
L_166:;
  a2 = a2 | a7; /* 0166: or a2, a2, a7 */
  MEMW(); /* 0169: memw  */
  MEM32(a5 + 48) = a2; /* 016c: s32i.n a2, a5, 48 */
  MEM16(a5 + 22) = a11; /* 016e: s16i a11, a5, 22 */
  MEM8(a5 + 26) = a6; /* 0171: s8i a6, a5, 26 */
  MEMW(); /* 0174: memw  */
  if (a4 == 0) goto L_1e4; /* 0177: beqz a4, 1e4 <esf_buf_alloc_dynamic+0x1c0> */
  a12 = a3; /* 017a: mov.n a12, a3 */
  a11 = a4; /* 017c: mov.n a11, a4 */
  MEM32(a1 + 4) = a9; /* 017e: s32i.n a9, a1, 4 */
  MEMW(); /* 0180: memw  */
  a8 = (uint32_t)&memcpy; /* 0183: l32r a8, 20 <esf_buf_alloc_dynamic-0x4> (0 <esf_buf_alloc_dynamic-0x24>) */ /* literal: GOT slot for memcpy */
  memcpy(a2, a3, a4, a5); /* call via literal slot */ /* 0186: callx8 a8 */
  a9 = MEM32(a1 + 4); /* 0189: l32i.n a9, a1, 4 */
  goto L_1e4; /* 018b: j 1e4 <esf_buf_alloc_dynamic+0x1c0> */
  /* 018e: .byte 00 */
  /* 018f: .byte 00 */
L_190:;
  a3 = MEM16(a2 + 16); /* 0190: l16ui a3, a2, 16 */
  a9 = 0x0; /* 0193: movi.n a9, 0 */
  if (a3 == a9) goto L_1e4; /* 0195: beq a3, a9, 1e4 <esf_buf_alloc_dynamic+0x1c0> */
  a7 = (uint32_t)&g_osi_funcs_p; /* 0198: l32r a7, 4 <esf_buf_alloc_dynamic-0x20> (0 <esf_buf_alloc_dynamic-0x24>) */ /* literal @0x4: g_osi_funcs_p */
  a4 = (uint32_t)&g_wifi_global_lock; /* 019b: l32r a4, 0 <esf_buf_alloc_dynamic-0x24> (0 <esf_buf_alloc_dynamic-0x24>) */ /* literal @0x0: g_wifi_global_lock */
  a3 = MEM32(a7 + 0); /* 019e: l32i.n a3, a7, 0 */
  a10 = MEM32(a4 + 0); /* 01a0: l32i.n a10, a4, 0 */
  a3 = MEM32(a3 + 84); /* 01a2: l32i a3, a3, 84 */
  ((int32_t(*)())a3)(a2, a3, a4, a5); /* 01a5: callx8 a3 */ /* indirect */
  a3 = a6 + a6; /* 01a8: add.n a3, a6, a6 */
  a5 = MEM16(a2 + 14); /* 01aa: l16ui a5, a2, 14 */
  a8 = (uint32_t)&g_lmac_cnt; /* 01ad: l32r a8, 8 <esf_buf_alloc_dynamic-0x1c> (0 <esf_buf_alloc_dynamic-0x24>) */ /* literal @0x8: g_lmac_cnt */
  if (a5 == 0) goto L_1c5; /* 01b0: beqz.n a5, 1c5 <esf_buf_alloc_dynamic+0x1a1> */
  a5 = a5 + (-1); /* 01b2: addi.n a5, a5, -1 */
  MEM16(a2 + 14) = a5; /* 01b4: s16i a5, a2, 14 */
  MEMW(); /* 01b7: memw  */
  a2 = a3 + a6; /* 01ba: add.n a2, a3, a6 */
  a2 = (a2 << 4) + a8; /* 01bc: addx4 a2, a2, a8 */
  a5 = MEM32(a2 + 0); /* 01bf: l32i.n a5, a2, 0 */
  a5 = a5 + (1); /* 01c1: addi.n a5, a5, 1 */
  MEM32(a2 + 0) = a5; /* 01c3: s32i.n a5, a2, 0 */
L_1c5:;
  a3 = a3 + a6; /* 01c5: add.n a3, a3, a6 */
  a3 = (a3 << 4) + a8; /* 01c7: addx4 a3, a3, a8 */
  a2 = MEM16(a3 + 8); /* 01ca: l16ui a2, a3, 8 */
  a2 = a2 + (1); /* 01cd: addi.n a2, a2, 1 */
  MEM16(a3 + 8) = a2; /* 01cf: s16i a2, a3, 8 */
  MEMW(); /* 01d2: memw  */
  a2 = MEM32(a7 + 0); /* 01d5: l32i.n a2, a7, 0 */
  a10 = MEM32(a4 + 0); /* 01d7: l32i.n a10, a4, 0 */
  a2 = MEM32(a2 + 88); /* 01d9: l32i a2, a2, 88 */
L_1dc:;
  MEMW(); /* 01dc: memw  */
  ((int32_t(*)())a2)(a2, a3, a4, a5); /* 01df: callx8 a2 */ /* indirect */
  a9 = 0x0; /* 01e2: movi.n a9, 0 */
L_1e4:;
  a2 = 0x0; /* 01e4: mov.n a2, a9 */
  return (int32_t)a2; /* 01e6: retw.n  */
}

/* esf_buf_alloc_default_handler @ esf_buf.o 00000008 size 25B bind GLOBAL
 * Calls: wifi_log | Data refs: .rodata_wlog_error.5, wifi_log
 *   MMIO: none
 *   funcdb v3: 1 call(s), 2 ref(s); disasm: 1 call(s), 2 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t esf_buf_alloc_default_handler(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.esf_buf_alloc_default_handler; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_8:;
  /* 0008: entry a1, 32 */
  a13 = (uint32_t)&lit_rodata_wlog_error_5; /* 000b: l32r a13, 0 <esf_buf_alloc_default_handler-0x8> (0 <esf_buf_alloc_default_handler-0x8>) */ /* literal @0x0: .rodata_wlog_error.5 */
  a14 = a2; /* 000e: mov.n a14, a2 */
  a12 = 0x1; /* 0010: movi.n a12, 1 */
  a11 = 0x400; /* 0012: movi a11, 0x400 */
  a10 = 0x6; /* 0015: movi.n a10, 6 */
  a8 = (uint32_t)&wifi_log; /* 0017: l32r a8, 4 <esf_buf_alloc_default_handler-0x4> (0 <esf_buf_alloc_default_handler-0x8>) */ /* literal: GOT slot for wifi_log */
  wifi_log(a2, a3, a4, a5); /* call via literal slot */ /* 001a: callx8 a8 */
  a2 = 0x0; /* 001d: movi.n a2, 0 */
  return (int32_t)a2; /* 001f: retw.n  */
}

/* esf_buf_alloc @ esf_buf.o 00000024 size 314B bind GLOBAL
 * Calls: g_wifi_menuconfig[got], g_osi_funcs_p[got], memcpy[got], esf_buf_alloc_dynamic[got], esf_buf_alloc_default_handler[got] | Data refs: .rodata, g_wifi_menuconfig, g_osi_funcs_p, g_wifi_global_lock, g_eb_list_desc, g_lmac_cnt, memcpy, esf_buf_alloc_dynamic, esf_buf_alloc_default_handler
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 5 call(s), 9 data ref(s)
 * Fidelity: low - 125 instr, 14 branches, 2 indirect; jx computed tail dispatch at +0x3b (movi 8/bgeu at +0x2d, l32r .rodata at +0x33 + addx4 at +0x36, jx a2); per-type case targets structural - need rodata case decode to raise */
int32_t esf_buf_alloc(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .wifislprxiram.6; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_24:;
  /* 0024: entry a1, 48 */
  a6 = a2; /* 0027: mov.n a6, a2 */
  a5 = 0x8; /* 0029: movi.n a5, 8 */
  a2 = a3 + (-1); /* 002b: addi.n a2, a3, -1 */
  if (a5 >= a2) goto L_33; /* 002d: bgeu a5, a2, 33 <esf_buf_alloc+0xf> */
  goto L_149; /* 0030: j 149 <esf_buf_alloc+0x125> */
L_33:;
  a5 = (uint32_t)&lit_rodata; /* 0033: l32r a5, 0 <esf_buf_alloc-0x24> (0 <esf_buf_alloc-0x24>) */ /* literal @0x0: .rodata */
  a2 = (a2 << 4) + a5; /* 0036: addx4 a2, a2, a5 */
  a2 = MEM32(a2 + 0); /* 0039: l32i.n a2, a2, 0 */
  /* 003b: jx a2 */ /* jx a2: computed tail jump; modeled as return */
  return (int32_t)a2;
  a2 = (uint32_t)&g_wifi_menuconfig; /* 003e: l32r a2, 4 <esf_buf_alloc-0x20> (0 <esf_buf_alloc-0x24>) */ /* literal @0x4: g_wifi_menuconfig */
  a2 = MEM32(a2 + 8); /* 0041: l32i.n a2, a2, 8 */
  goto L_4d; /* 0043: j 4d <esf_buf_alloc+0x29> */
  /* 0046: .byte 00 */
  a2 = (uint32_t)&g_wifi_menuconfig; /* 0047: l32r a2, 4 <esf_buf_alloc-0x20> (0 <esf_buf_alloc-0x24>) */ /* literal @0x4: g_wifi_menuconfig */
  a2 = MEM32(a2 + 84); /* 004a: l32i a2, a2, 84 */
L_4d:;
  if (a2 != 0) goto L_131; /* 004d: bnez a2, 131 <esf_buf_alloc+0x10d> */
L_50:;
  a5 = a3 << (2 & 31); /* 0050: slli a5, a3, 2 */
  a8 = (uint32_t)&g_osi_funcs_p; /* 0053: l32r a8, c <esf_buf_alloc-0x18> (0 <esf_buf_alloc-0x24>) */ /* literal @0xC: g_osi_funcs_p */
  a11 = (uint32_t)&g_wifi_global_lock; /* 0056: l32r a11, 8 <esf_buf_alloc-0x1c> (0 <esf_buf_alloc-0x24>) */ /* literal @0x8: g_wifi_global_lock */
  a2 = MEM32(a8 + 0); /* 0059: l32i.n a2, a8, 0 */
  a10 = MEM32(a11 + 0); /* 005b: l32i a10, a11, 0 */
  a2 = MEM32(a2 + 84); /* 005e: l32i a2, a2, 84 */
  MEM32(a1 + 4) = a8; /* 0061: s32i.n a8, a1, 4 */
  MEM32(a1 + 0) = a11; /* 0063: s32i a11, a1, 0 */
  MEMW(); /* 0066: memw  */
  g_wifi_menuconfig(a2, a3, a4, a5); /* call via literal slot */ /* 0069: callx8 a2 */
  a9 = (a3 << 4) + a3; /* 006c: addx4 a9, a3, a3 */
  a2 = (uint32_t)&g_eb_list_desc; /* 006f: l32r a2, 10 <esf_buf_alloc-0x14> (0 <esf_buf_alloc-0x24>) */ /* literal @0x10: g_eb_list_desc */
  a7 = (a9 << 4) + a2; /* 0072: addx4 a7, a9, a2 */
  a8 = MEM32(a1 + 4); /* 0075: l32i.n a8, a1, 4 */
  a2 = MEM32(a7 + 0); /* 0077: l32i.n a2, a7, 0 */
  a10 = MEM32(a8 + 0); /* 0079: l32i.n a10, a8, 0 */
  a12 = (uint32_t)&g_lmac_cnt; /* 007b: l32r a12, 14 <esf_buf_alloc-0x10> (0 <esf_buf_alloc-0x24>) */ /* literal @0x14: g_lmac_cnt */
  a11 = MEM32(a1 + 0); /* 007e: l32i.n a11, a1, 0 */
  if (a2 == 0) goto L_b5; /* 0080: beqz.n a2, b5 <esf_buf_alloc+0x91> */
  a8 = MEM32(a2 + 40); /* 0082: l32i.n a8, a2, 40 */
  MEM32(a7 + 0) = a8; /* 0084: s32i.n a8, a7, 0 */
  a8 = 0x0; /* 0086: movi.n a8, 0 */
  MEM32(a2 + 40) = a8; /* 0088: s32i.n a8, a2, 40 */
  a8 = (a3 << 2) + a3; /* 008a: addx2 a8, a3, a3 */
  a8 = (a8 << 4) + a12; /* 008d: addx4 a8, a8, a12 */
  a12 = MEM32(a8 + 0); /* 0090: l32i.n a12, a8, 0 */
  a12 = a12 + (1); /* 0092: addi.n a12, a12, 1 */
  MEM32(a8 + 0) = a12; /* 0094: s32i.n a12, a8, 0 */
  a8 = MEM32(a10 + 88); /* 0096: l32i a8, a10, 88 */
  a10 = MEM32(a11 + 0); /* 0099: l32i.n a10, a11, 0 */
  MEMW(); /* 009b: memw  */
  ((int32_t(*)())a8)(a2, a3, a4, a5); /* 009e: callx8 a8 */ /* indirect */
  a8 = (a4 >> 0) & 0xFFFF; /* 00a1: extui a8, a4, 0, 16 */
  a10 = MEM32(a2 + 4); /* 00a4: l32i.n a10, a2, 4 */
  MEM16(a2 + 22) = a8; /* 00a6: s16i a8, a2, 22 */
  MEMW(); /* 00a9: memw  */
  if (a10 != 0) goto L_d8; /* 00ac: bnez.n a10, d8 <esf_buf_alloc+0xb4> */
  MEMW(); /* 00ae: memw  */
  goto L_fb; /* 00b1: j fb <esf_buf_alloc+0xd7> */
  /* 00b4: .byte 00 */
L_b5:;
  a3 = MEM8(a7 + 8); /* 00b5: l8ui a3, a7, 8 */
  a3 = (a3 << 2) + a3; /* 00b8: addx2 a3, a3, a3 */
  a3 = (a3 << 4) + a12; /* 00bb: addx4 a3, a3, a12 */
  a4 = MEM16(a3 + 10); /* 00be: l16ui a4, a3, 10 */
  a4 = a4 + (1); /* 00c1: addi.n a4, a4, 1 */
  MEM16(a3 + 10) = a4; /* 00c3: s16i a4, a3, 10 */
  MEMW(); /* 00c6: memw  */
  a3 = MEM32(a10 + 88); /* 00c9: l32i a3, a10, 88 */
  a10 = MEM32(a11 + 0); /* 00cc: l32i.n a10, a11, 0 */
  MEMW(); /* 00ce: memw  */
  ((int32_t(*)())a3)(a2, a3, a4, a5); /* 00d1: callx8 a3 */ /* indirect */
  goto L_15c; /* 00d4: j 15c <esf_buf_alloc+0x138> */
  /* 00d7: .byte 00 */
L_d8:;
  a11 = MEM8(a7 + 12); /* 00d8: l8ui a11, a7, 12 */
  a8 = a8 + a11; /* 00db: add.n a8, a8, a11 */
  a8 = (a8 >> 0) & 0xFFF; /* 00dd: extui a8, a8, 0, 12 */
  a9 = MEM32(a2 + 16); /* 00e0: l32i.n a9, a2, 16 */
  a9 = a9 + a11; /* 00e2: add.n a9, a9, a11 */
  a11 = 0xFFFFFFFF; /* 00e4: movi.n a11, -1 */
  a11 = 0xFFFFF000; /* 00e6: slli a11, a11, 12 */
  MEM32(a10 + 4) = a9; /* 00e9: s32i.n a9, a10, 4 */
  MEMW(); /* 00eb: memw  */
  a9 = MEM32(a10 + 0); /* 00ee: l32i.n a9, a10, 0 */
  a9 = a9 & a11; /* 00f0: and a9, a9, a11 */
  a8 = a9 | a8; /* 00f3: or a8, a9, a8 */
  MEMW(); /* 00f6: memw  */
  MEM32(a10 + 0) = a8; /* 00f9: s32i.n a8, a10, 0 */
L_fb:;
  if (a6 == 0) goto L_10c; /* 00fb: beqz.n a6, 10c <esf_buf_alloc+0xe8> */
  a12 = a4; /* 00fd: mov.n a12, a4 */
  a11 = a6; /* 00ff: mov.n a11, a6 */
  a10 = MEM32(a10 + 4); /* 0101: l32i.n a10, a10, 4 */
  MEMW(); /* 0103: memw  */
  a8 = (uint32_t)&memcpy; /* 0106: l32r a8, 18 <esf_buf_alloc-0xc> (0 <esf_buf_alloc-0x24>) */ /* literal: GOT slot for memcpy */
  memcpy(a2, a3, a4, a5); /* call via literal slot */ /* 0109: callx8 a8 */
L_10c:;
  a5 = a5 + a3; /* 010c: add.n a5, a5, a3 */
  a3 = (uint32_t)&g_eb_list_desc; /* 010e: l32r a3, 10 <esf_buf_alloc-0x14> (0 <esf_buf_alloc-0x24>) */ /* literal @0x10: g_eb_list_desc */
  a5 = (a5 << 4) + a3; /* 0111: addx4 a5, a5, a3 */
  a4 = MEM32(a2 + 44); /* 0114: l32i.n a4, a2, 44 */
  a5 = MEM32(a5 + 4); /* 0116: l32i.n a5, a5, 4 */
  a3 = MEM32(a4 + 0); /* 0118: l32i.n a3, a4, 0 */
  a3 = a3 | a5; /* 011a: or a3, a3, a5 */
  a5 = 0xF; /* 011d: movi.n a5, 15 */
  MEM32(a4 + 0) = a3; /* 011f: s32i.n a3, a4, 0 */
  a3 = MEM32(a4 + 4); /* 0121: l32i.n a3, a4, 4 */
  a3 = a3 | a5; /* 0123: or a3, a3, a5 */
  MEM32(a4 + 4) = a3; /* 0126: s32i.n a3, a4, 4 */
  MEMW(); /* 0128: memw  */
  goto L_15c; /* 012b: j 15c <esf_buf_alloc+0x138> */
  /* 012e: .byte 00 */
  /* 012f: .byte 00 */
  /* 0130: .byte 00 */
L_131:;
  a10 = (uint32_t)&g_eb_list_desc; /* 0131: l32r a10, 10 <esf_buf_alloc-0x14> (0 <esf_buf_alloc-0x24>) */ /* literal @0x10: g_eb_list_desc */
  a3 = (a3 << 4) + a3; /* 0134: addx4 a3, a3, a3 */
  a12 = a6; /* 0137: mov.n a12, a6 */
  a11 = a4; /* 0139: mov.n a11, a4 */
  a10 = (a3 << 4) + a10; /* 013b: addx4 a10, a3, a10 */
  a8 = (uint32_t)&esf_buf_alloc_dynamic; /* 013e: l32r a8, 1c <esf_buf_alloc-0x8> (0 <esf_buf_alloc-0x24>) */ /* literal: GOT slot for esf_buf_alloc_dynamic */
  esf_buf_alloc_dynamic(a2, a3, a4, a5); /* call via literal slot */ /* 0141: callx8 a8 */
  a2 = a10; /* 0144: mov.n a2, a10 */
  goto L_15c; /* 0146: j 15c <esf_buf_alloc+0x138> */
L_149:;
  a10 = a3; /* 0149: mov.n a10, a3 */
  a8 = (uint32_t)&esf_buf_alloc_default_handler; /* 014b: l32r a8, 20 <esf_buf_alloc-0x4> (0 <esf_buf_alloc-0x24>) */ /* literal: GOT slot for esf_buf_alloc_default_handler */
  esf_buf_alloc_default_handler(a2, a3, a4, a5); /* call via literal slot */ /* 014e: callx8 a8 */
  if (a10 == 1) goto L_131; /* 0151: beqi a10, 1, 131 <esf_buf_alloc+0x10d> */
  if (a10 != 2) goto L_15a; /* 0154: bnei a10, 2, 15a <esf_buf_alloc+0x136> */
  goto L_50; /* 0157: j 50 <esf_buf_alloc+0x2c> */
L_15a:;
  a2 = 0x0; /* 015a: movi.n a2, 0 */
L_15c:;
  return (int32_t)a2; /* 015c: retw.n  */
}

/* esf_buf_recycle_default_handler @ esf_buf.o 00000008 size 26B bind GLOBAL
 * Calls: wifi_log | Data refs: .rodata_wlog_error.7, wifi_log
 *   MMIO: none
 *   funcdb v3: 1 call(s), 2 ref(s); disasm: 1 call(s), 2 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t esf_buf_recycle_default_handler(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.esf_buf_recycle_default_handler; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_8:;
  /* 0008: entry a1, 32 */
  a13 = (uint32_t)&lit_rodata_wlog_error_7; /* 000b: l32r a13, 0 <esf_buf_recycle_default_handler-0x8> (0 <esf_buf_recycle_default_handler-0x8>) */ /* literal @0x0: .rodata_wlog_error.7 */
  a14 = (a2 >> 0) & 0xFF; /* 000e: extui a14, a2, 0, 8 */
  a12 = 0x1; /* 0011: movi.n a12, 1 */
  a11 = 0x400; /* 0013: movi a11, 0x400 */
  a10 = 0x6; /* 0016: movi.n a10, 6 */
  a8 = (uint32_t)&wifi_log; /* 0018: l32r a8, 4 <esf_buf_recycle_default_handler-0x4> (0 <esf_buf_recycle_default_handler-0x8>) */ /* literal: GOT slot for wifi_log */
  wifi_log(a2, a3, a4, a5); /* call via literal slot */ /* 001b: callx8 a8 */
  a2 = 0x0; /* 001e: movi.n a2, 0 */
  return (int32_t)a2; /* 0020: retw.n  */
}

/* esf_buf_recycle @ esf_buf.o 00000020 size 238B bind GLOBAL
 * Calls: .rodata[tail], memset[got], g_wifi_menuconfig[got], g_wifi_menuconfig[got], g_osi_funcs_p[got], g_lmac_cnt[got], esf_buf_recycle_default_handler[got] | Data refs: .rodata, g_wifi_menuconfig, memset, g_osi_funcs_p, g_wifi_global_lock, g_eb_list_desc, g_lmac_cnt, esf_buf_recycle_default_handler
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 7 call(s), 8 data ref(s)
 * Fidelity: low - 89 instr, 12 branches, jx tail dispatch on eb-type (bounds-checked, rodata table + (idx<<4) load at +0x39); GOT-indirect free paths mapped - need per-type rodata case decode to raise */
int32_t esf_buf_recycle(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .wifirxiram.8; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_20:;
  /* 0020: entry a1, 32 */
  if (a2 == 0) goto L_10c; /* 0023: beqz a2, 10c <esf_buf_recycle+0xec> */
  a3 = MEM8(a2 + 26); /* 0026: l8ui a3, a2, 26 */
  a4 = 0x8; /* 0029: movi.n a4, 8 */
  a8 = a3 + (-1); /* 002b: addi.n a8, a3, -1 */
  a8 = (a8 >> 0) & 0xFF; /* 002d: extui a8, a8, 0, 8 */
  if (a4 >= a8) goto L_36; /* 0030: bgeu a4, a8, 36 <esf_buf_recycle+0x16> */
  goto L_fb; /* 0033: j fb <esf_buf_recycle+0xdb> */
L_36:;
  a4 = (uint32_t)&lit_rodata; /* 0036: l32r a4, 0 <esf_buf_recycle-0x20> (24 <esf_buf_recycle+0x4>) */ /* literal @0x0: .rodata */
  a8 = (a8 << 4) + a4; /* 0039: addx4 a8, a8, a4 */
  a4 = MEM32(a8 + 0); /* 003c: l32i.n a4, a8, 0 */
  return lit_rodata(a2, a3, a4, a5); /* tail jump */ /* 003e: jx a4 */
  a4 = (uint32_t)&g_wifi_menuconfig; /* 0041: l32r a4, 4 <esf_buf_recycle-0x1c> (0 <esf_buf_recycle-0x20>) */ /* literal @0x4: g_wifi_menuconfig */
  a4 = MEM32(a4 + 8); /* 0044: l32i.n a4, a4, 8 */
  goto L_4f; /* 0046: j 4f <esf_buf_recycle+0x2f> */
  a4 = (uint32_t)&g_wifi_menuconfig; /* 0049: l32r a4, 4 <esf_buf_recycle-0x1c> (0 <esf_buf_recycle-0x20>) */ /* literal @0x4: g_wifi_menuconfig */
  a4 = MEM32(a4 + 84); /* 004c: l32i a4, a4, 84 */
L_4f:;
  if (a4 != 0) goto L_a4; /* 004f: bnez a4, a4 <esf_buf_recycle+0x84> */
L_52:;
  a12 = 0x20; /* 0052: movi.n a12, 32 */
  a11 = 0x0; /* 0054: movi.n a11, 0 */
  a4 = 0x0; /* 0056: movi.n a4, 0 */
  a10 = MEM32(a2 + 44); /* 0058: l32i.n a10, a2, 44 */
  a8 = (uint32_t)&memset; /* 005a: l32r a8, 18 <esf_buf_recycle-0x8> (0 <esf_buf_recycle-0x20>) */ /* literal: GOT slot for memset */
  memset(a2, a3, a4, a5); /* call via literal slot */ /* 005d: callx8 a8 */
  a6 = (uint32_t)&g_osi_funcs_p; /* 0060: l32r a6, c <esf_buf_recycle-0x14> (0 <esf_buf_recycle-0x20>) */ /* literal @0xC: g_osi_funcs_p */
  a5 = (uint32_t)&g_wifi_global_lock; /* 0063: l32r a5, 8 <esf_buf_recycle-0x18> (0 <esf_buf_recycle-0x20>) */ /* literal @0x8: g_wifi_global_lock */
  MEM16(a2 + 20) = a4; /* 0066: s16i a4, a2, 20 */
  MEMW(); /* 0069: memw  */
  a4 = MEM32(a6 + 0); /* 006c: l32i.n a4, a6, 0 */
  a10 = MEM32(a5 + 0); /* 006e: l32i.n a10, a5, 0 */
  a4 = MEM32(a4 + 84); /* 0070: l32i a4, a4, 84 */
  MEMW(); /* 0073: memw  */
  g_wifi_menuconfig(a2, a3, a4, a5); /* call via literal slot */ /* 0076: callx8 a4 */
  a4 = (a3 << 4) + a3; /* 0079: addx4 a4, a3, a3 */
  a3 = (a3 << 2) + a3; /* 007c: addx2 a3, a3, a3 */
  a8 = (uint32_t)&g_eb_list_desc; /* 007f: l32r a8, 10 <esf_buf_recycle-0x10> (0 <esf_buf_recycle-0x20>) */ /* literal @0x10: g_eb_list_desc */
  a4 = (a4 << 4) + a8; /* 0082: addx4 a4, a4, a8 */
  a8 = MEM32(a4 + 0); /* 0085: l32i.n a8, a4, 0 */
  MEM32(a2 + 40) = a8; /* 0087: s32i.n a8, a2, 40 */
  MEM32(a4 + 0) = a2; /* 0089: s32i.n a2, a4, 0 */
  a2 = (uint32_t)&g_lmac_cnt; /* 008b: l32r a2, 14 <esf_buf_recycle-0xc> (0 <esf_buf_recycle-0x20>) */ /* literal @0x14: g_lmac_cnt */
  a3 = (a3 << 4) + a2; /* 008e: addx4 a3, a3, a2 */
  a2 = MEM32(a3 + 4); /* 0091: l32i.n a2, a3, 4 */
  a2 = a2 + (1); /* 0093: addi.n a2, a2, 1 */
  MEM32(a3 + 4) = a2; /* 0095: s32i.n a2, a3, 4 */
  a2 = MEM32(a6 + 0); /* 0097: l32i.n a2, a6, 0 */
  a10 = MEM32(a5 + 0); /* 0099: l32i.n a10, a5, 0 */
  a2 = MEM32(a2 + 88); /* 009b: l32i a2, a2, 88 */
  MEMW(); /* 009e: memw  */
  goto L_f2; /* 00a1: j f2 <esf_buf_recycle+0xd2> */
L_a4:;
  a5 = (uint32_t)&g_osi_funcs_p; /* 00a4: l32r a5, c <esf_buf_recycle-0x14> (0 <esf_buf_recycle-0x20>) */ /* literal @0xC: g_osi_funcs_p */
  a10 = a2; /* 00a7: mov.n a10, a2 */
  a2 = (a3 << 4) + a3; /* 00a9: addx4 a2, a3, a3 */
  a4 = MEM32(a5 + 0); /* 00ac: l32i.n a4, a5, 0 */
  a4 = MEM32(a4 + 176); /* 00ae: l32i a4, a4, 176 */
  ((int32_t(*)())a4)(a2, a3, a4, a5); /* 00b1: callx8 a4 */ /* indirect */
  a4 = (uint32_t)&g_eb_list_desc; /* 00b4: l32r a4, 10 <esf_buf_recycle-0x10> (0 <esf_buf_recycle-0x20>) */ /* literal @0x10: g_eb_list_desc */
  a2 = (a2 << 4) + a4; /* 00b7: addx4 a2, a2, a4 */
  a4 = MEM16(a2 + 16); /* 00ba: l16ui a4, a2, 16 */
  if (a4 == 0) goto L_10c; /* 00bd: beqz a4, 10c <esf_buf_recycle+0xec> */
  a4 = (uint32_t)&g_wifi_global_lock; /* 00c0: l32r a4, 8 <esf_buf_recycle-0x18> (0 <esf_buf_recycle-0x20>) */ /* literal @0x8: g_wifi_global_lock */
  a6 = MEM32(a5 + 0); /* 00c3: l32i.n a6, a5, 0 */
  a10 = MEM32(a4 + 0); /* 00c5: l32i.n a10, a4, 0 */
  a6 = MEM32(a6 + 84); /* 00c7: l32i a6, a6, 84 */
  g_osi_funcs_p(a2, a3, a4, a5); /* call via literal slot */ /* 00ca: callx8 a6 */
  a8 = MEM16(a2 + 14); /* 00cd: l16ui a8, a2, 14 */
  if (a8 == 0) goto L_dc; /* 00d0: beqz a8, dc <esf_buf_recycle+0xbc> */
  a8 = a8 + (-1); /* 00d3: addi a8, a8, -1 */
  MEM16(a2 + 14) = a8; /* 00d6: s16i a8, a2, 14 */
  MEMW(); /* 00d9: memw  */
L_dc:;
  a3 = (a3 << 2) + a3; /* 00dc: addx2 a3, a3, a3 */
  a2 = (uint32_t)&g_lmac_cnt; /* 00df: l32r a2, 14 <esf_buf_recycle-0xc> (0 <esf_buf_recycle-0x20>) */ /* literal @0x14: g_lmac_cnt */
  a3 = (a3 << 4) + a2; /* 00e2: addx4 a3, a3, a2 */
  a2 = MEM32(a3 + 4); /* 00e5: l32i.n a2, a3, 4 */
  a2 = a2 + (1); /* 00e7: addi.n a2, a2, 1 */
  MEM32(a3 + 4) = a2; /* 00e9: s32i.n a2, a3, 4 */
  a2 = MEM32(a5 + 0); /* 00eb: l32i.n a2, a5, 0 */
  a10 = MEM32(a4 + 0); /* 00ed: l32i.n a10, a4, 0 */
  a2 = MEM32(a2 + 88); /* 00ef: l32i a2, a2, 88 */
L_f2:;
  MEMW(); /* 00f2: memw  */
  ((int32_t(*)())a2)(a2, a3, a4, a5); /* 00f5: callx8 a2 */ /* indirect */
  goto L_10c; /* 00f8: j 10c <esf_buf_recycle+0xec> */
L_fb:;
  a10 = a3; /* 00fb: mov.n a10, a3 */
  a8 = (uint32_t)&esf_buf_recycle_default_handler; /* 00fd: l32r a8, 1c <esf_buf_recycle-0x4> (0 <esf_buf_recycle-0x20>) */ /* literal: GOT slot for esf_buf_recycle_default_handler */
  esf_buf_recycle_default_handler(a2, a3, a4, a5); /* call via literal slot */ /* 0100: callx8 a8 */
  if (a10 == 1) goto L_a4; /* 0103: beqi a10, 1, a4 <esf_buf_recycle+0x84> */
  if (a10 != 2) goto L_10c; /* 0106: bnei a10, 2, 10c <esf_buf_recycle+0xec> */
  goto L_52; /* 0109: j 52 <esf_buf_recycle+0x32> */
L_10c:;
  return (int32_t)a2; /* 010c: retw.n  */
}

/* esf_buf_setup_for_mesh @ esf_buf.o 00000004 size 30B bind GLOBAL
 * Calls: none | Data refs: g_eb_list_desc
 *   MMIO: none
 *   funcdb v3: 0 call(s), 1 ref(s); disasm: 0 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t esf_buf_setup_for_mesh(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.esf_buf_setup_for_mesh; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a8 = (uint32_t)&g_eb_list_desc; /* 0007: l32r a8, 0 <esf_buf_setup_for_mesh-0x4> (0 <esf_buf_setup_for_mesh-0x4>) */ /* literal @0x0: g_eb_list_desc */
  a9 = 0x40; /* 000a: movi.n a9, 64 */
  a10 = 0x80; /* 000c: movi a10, 128 */
  a2 = 0x0; /* 000f: movi.n a2, 0 */
  MEM16(a8 + 96) = a9; /* 0011: s16i a9, a8, 96 */
  MEM16(a8 + 76) = a10; /* 0014: s16i a10, a8, 76 */
  MEM16(a8 + 56) = a9; /* 0017: s16i a9, a8, 56 */
  MEMW(); /* 001a: memw  */
  MEMW(); /* 001d: memw  */
  return (int32_t)a2; /* 0020: retw.n  */
}

/* esf_buf_setup_static @ esf_buf.o 00000014 size 81B bind GLOBAL
 * Calls: esf_buf_alloc_dynamic, esf_buf_recycle, wifi_log | Data refs: .rodata_wlog_warning.9, esf_buf_alloc_dynamic, esf_buf_recycle, g_eb_list_desc, wifi_log
 *   MMIO: none
 *   funcdb v3: 3 call(s), 5 ref(s); disasm: 3 call(s), 5 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t esf_buf_setup_static(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.esf_buf_setup_static; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_14:;
  /* 0014: entry a1, 32 */
  a6 = (uint32_t)&g_eb_list_desc; /* 0017: l32r a6, 0 <esf_buf_setup_static-0x14> (0 <esf_buf_setup_static-0x14>) */ /* literal @0x0: g_eb_list_desc */
  a5 = (a2 << 4) + a2; /* 001a: addx4 a5, a2, a2 */
  a5 = (a5 << 4) + a6; /* 001d: addx4 a5, a5, a6 */
  a6 = 0x0; /* 0020: movi.n a6, 0 */
  MEM16(a5 + 10) = a3; /* 0022: s16i a3, a5, 10 */
  MEMW(); /* 0025: memw  */
  MEMW(); /* 0028: memw  */
  goto L_5e; /* 002b: j 5e <esf_buf_setup_static+0x4a> */
L_2e:;
  a12 = 0x0; /* 002e: mov.n a12, a6 */
  a11 = a4; /* 0030: mov.n a11, a4 */
  a10 = a5; /* 0032: mov.n a10, a5 */
  a3 = a3 + (-1); /* 0034: addi.n a3, a3, -1 */
  a8 = (uint32_t)&esf_buf_alloc_dynamic; /* 0036: l32r a8, 8 <esf_buf_setup_static-0xc> (0 <esf_buf_setup_static-0x14>) */ /* literal: GOT slot for esf_buf_alloc_dynamic */
  esf_buf_alloc_dynamic(a2, a3, a4, a5); /* call via literal slot */ /* 0039: callx8 a8 */
  if (a10 != 0) goto L_58; /* 003c: bnez.n a10, 58 <esf_buf_setup_static+0x44> */
  a13 = (uint32_t)&lit_rodata_wlog_warning_9; /* 003e: l32r a13, 4 <esf_buf_setup_static-0x10> (0 <esf_buf_setup_static-0x14>) */ /* literal @0x4: .rodata_wlog_warning.9 */
  a14 = a2; /* 0041: mov.n a14, a2 */
  a12 = 0x2; /* 0043: movi.n a12, 2 */
  a11 = 0x400; /* 0045: movi a11, 0x400 */
  a10 = 0x1; /* 0048: movi.n a10, 1 */
  a8 = (uint32_t)&wifi_log; /* 004a: l32r a8, c <esf_buf_setup_static-0x8> (0 <esf_buf_setup_static-0x14>) */ /* literal: GOT slot for wifi_log */
  wifi_log(a2, a3, a4, a5); /* call via literal slot */ /* 004d: callx8 a8 */
  a3 = 0x101; /* 0050: movi a3, 0x101 */
  goto L_61; /* 0053: j 61 <esf_buf_setup_static+0x4d> */
  /* 0056: .byte 00 */
  /* 0057: .byte 00 */
L_58:;
  a8 = (uint32_t)&esf_buf_recycle; /* 0058: l32r a8, 10 <esf_buf_setup_static-0x4> (0 <esf_buf_setup_static-0x14>) */ /* literal: GOT slot for esf_buf_recycle */
  esf_buf_recycle(a2, a3, a4, a5); /* call via literal slot */ /* 005b: callx8 a8 */
L_5e:;
  if (a3 != 0) goto L_2e; /* 005e: bnez a3, 2e <esf_buf_setup_static+0x1a> */
L_61:;
  a2 = a3; /* 0061: mov.n a2, a3 */
  return (int32_t)a2; /* 0063: retw.n  */
}

/* esf_buf_free_static @ esf_buf.o 00000014 size 146B bind GLOBAL
 * Calls: memset, g_osi_funcs_p[got] | Data refs: g_eb_list_desc, g_osi_funcs_p, g_wifi_global_lock, memset
 *   MMIO: none
 *   funcdb v3: 1 call(s), 4 ref(s); disasm: 3 call(s), 4 data ref(s)
 * Fidelity: medium - 59 instr, 7 branches, 3 indirect; flow + direct calls mapped, GOT-indirects enumerated */
int32_t esf_buf_free_static(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.esf_buf_free_static; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_14:;
  /* 0014: entry a1, 32 */
  a3 = 0x9; /* 0017: movi.n a3, 9 */
  if (a3 >= a2) goto L_1f; /* 0019: bge a3, a2, 1f <esf_buf_free_static+0xb> */
  goto L_a4; /* 001c: j a4 <esf_buf_free_static+0x90> */
L_1f:;
  a4 = (uint32_t)&g_eb_list_desc; /* 001f: l32r a4, 0 <esf_buf_free_static-0x14> (0 <esf_buf_free_static-0x14>) */ /* literal @0x0: g_eb_list_desc */
  a3 = (a2 << 4) + a2; /* 0022: addx4 a3, a2, a2 */
  a5 = a3 << (2 & 31); /* 0025: slli a5, a3, 2 */
  a6 = 0x0; /* 0028: movi.n a6, 0 */
  a3 = (a3 << 4) + a4; /* 002a: addx4 a3, a3, a4 */
  MEM16(a3 + 14) = a6; /* 002d: s16i a6, a3, 14 */
  MEMW(); /* 0030: memw  */
L_33:;
  a6 = (uint32_t)&g_osi_funcs_p; /* 0033: l32r a6, 8 <esf_buf_free_static-0xc> (0 <esf_buf_free_static-0x14>) */ /* literal @0x8: g_osi_funcs_p */
  a4 = (uint32_t)&g_wifi_global_lock; /* 0036: l32r a4, 4 <esf_buf_free_static-0x10> (0 <esf_buf_free_static-0x14>) */ /* literal @0x4: g_wifi_global_lock */
  a3 = MEM32(a6 + 0); /* 0039: l32i a3, a6, 0 */
  a10 = MEM32(a4 + 0); /* 003c: l32i a10, a4, 0 */
  a3 = MEM32(a3 + 84); /* 003f: l32i a3, a3, 84 */
  MEMW(); /* 0042: memw  */
  ((int32_t(*)())a3)(a2, a3, a4, a5); /* 0045: callx8 a3 */ /* indirect */
  a3 = (uint32_t)&g_eb_list_desc; /* 0048: l32r a3, 0 <esf_buf_free_static-0x14> (0 <esf_buf_free_static-0x14>) */ /* literal @0x0: g_eb_list_desc */
  a7 = a3 + a5; /* 004b: add.n a7, a3, a5 */
  a3 = MEM32(a7 + 0); /* 004d: l32i.n a3, a7, 0 */
  a9 = MEM32(a6 + 0); /* 004f: l32i.n a9, a6, 0 */
  if (a3 != 0) goto L_61; /* 0051: bnez.n a3, 61 <esf_buf_free_static+0x4d> */
  a2 = MEM32(a9 + 88); /* 0053: l32i a2, a9, 88 */
  a10 = MEM32(a4 + 0); /* 0056: l32i a10, a4, 0 */
  ((int32_t(*)())a2)(a2, a3, a4, a5); /* 0059: callx8 a2 */ /* indirect */
  goto L_a4; /* 005c: j a4 <esf_buf_free_static+0x90> */
  /* 005f: .byte 00 */
  /* 0060: .byte 00 */
L_61:;
  a10 = MEM32(a3 + 40); /* 0061: l32i.n a10, a3, 40 */
  a9 = MEM32(a9 + 88); /* 0063: l32i a9, a9, 88 */
  MEM32(a7 + 0) = a10; /* 0066: s32i.n a10, a7, 0 */
  a7 = 0x0; /* 0068: movi.n a7, 0 */
  a10 = MEM32(a4 + 0); /* 006a: l32i.n a10, a4, 0 */
  MEM32(a3 + 40) = a7; /* 006c: s32i a7, a3, 40 */
  MEMW(); /* 006f: memw  */
  ((int32_t(*)())a9)(a2, a3, a4, a5); /* 0072: callx8 a9 */ /* indirect */
  if (a2 != 5) goto L_96; /* 0075: bnei a2, 5, 96 <esf_buf_free_static+0x82> */
  a11 = a7; /* 0078: mov.n a11, a7 */
  a12 = 0x20; /* 007a: movi.n a12, 32 */
  a10 = MEM32(a3 + 44); /* 007c: l32i.n a10, a3, 44 */
  a8 = (uint32_t)&memset; /* 007e: l32r a8, c <esf_buf_free_static-0x8> (0 <esf_buf_free_static-0x14>) */ /* literal: GOT slot for memset */
  memset(a2, a3, a4, a5); /* call via literal slot */ /* 0081: callx8 a8 */
  a12 = 0x30; /* 0084: movi.n a12, 48 */
  a11 = a7; /* 0086: mov.n a11, a7 */
  a10 = a3; /* 0088: mov.n a10, a3 */
  a8 = (uint32_t)&memset; /* 008a: l32r a8, 10 <esf_buf_free_static-0x4> (0 <esf_buf_free_static-0x14>) */ /* literal: GOT slot for memset */
  memset(a2, a3, a4, a5); /* call via literal slot */ /* 008d: callx8 a8 */
  goto L_33; /* 0090: j 33 <esf_buf_free_static+0x1f> */
  /* 0093: .byte 00 */
  /* 0094: .byte 00 */
  /* 0095: .byte 00 */
L_96:;
  a6 = MEM32(a6 + 0); /* 0096: l32i.n a6, a6, 0 */
  a10 = a3; /* 0098: mov.n a10, a3 */
  a6 = MEM32(a6 + 176); /* 009a: l32i a6, a6, 176 */
  g_osi_funcs_p(a2, a3, a4, a5); /* call via literal slot */ /* 009d: callx8 a6 */
  goto L_33; /* 00a0: j 33 <esf_buf_free_static+0x1f> */
  /* 00a3: .byte 00 */
L_a4:;
  return (int32_t)a2; /* 00a4: retw.n  */
}

/* esf_buf_setdown @ esf_buf.o 00000004 size 21B bind GLOBAL
 * Calls: esf_buf_free_static | Data refs: esf_buf_free_static
 *   MMIO: none
 *   funcdb v3: 1 call(s), 1 ref(s); disasm: 1 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t esf_buf_setdown(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.esf_buf_setdown; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a2 = 0x1; /* 0007: movi a2, 1 */
L_a:;
  a10 = 0x1; /* 000a: mov.n a10, a2 */
  a2 = 0x2; /* 000c: addi.n a2, a2, 1 */
  a8 = (uint32_t)&esf_buf_free_static; /* 000e: l32r a8, 0 <esf_buf_setdown-0x4> (0 <esf_buf_setdown-0x4>) */ /* literal: GOT slot for esf_buf_free_static */
  esf_buf_free_static(a2, a3, a4, a5); /* call via literal slot */ /* 0011: callx8 a8 */
  if (a2 != 10) goto L_a; /* 0014: bnei a2, 10, a <esf_buf_setdown+0x6> */
  return (int32_t)a2; /* 0017: retw.n  */
}

/* esf_buf_setup @ esf_buf.o 00000060 size 370B bind GLOBAL
 * Calls: config_is_cache_tx_buf_enabled, esf_buf_recycle, esf_buf_setdown, esf_buf_setup_static, memset, wifi_log | Data refs: .rodata_wlog_info.10, .rodata_wlog_info.11, .rodata_wlog_info.12, .rodata_wlog_info.13, .rodata_wlog_info.14, .rodata_wlog_info.15, .rodata_wlog_info.16, config_is_cache_tx_buf_enabled, eb_space, eb_txdesc_space, esf_buf_recycle, esf_buf_setdown, esf_buf_setup_static, g_eb_list_desc, g_wifi_menuconfig, memset, wifi_log
 *   MMIO: none
 *   funcdb v3: 6 call(s), 17 ref(s); disasm: 13 call(s), 17 data ref(s)
 * Fidelity: medium - 143 instr, 16 branches, calls resolved */
int32_t esf_buf_setup(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.esf_buf_setup; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_60:;
  /* 0060: entry a1, 48 */
  a6 = (uint32_t)&eb_txdesc_space; /* 0063: l32r a6, 4 <esf_buf_setup-0x5c> (0 <esf_buf_setup-0x60>) */ /* literal @0x4: eb_txdesc_space */
  a12 = 0x80; /* 0066: movi a12, 128 */
  a11 = 0x0; /* 0069: movi.n a11, 0 */
  a10 = a6 | a6; /* 006b: or a10, a6, a6 */
  a8 = (uint32_t)&memset; /* 006e: l32r a8, 2c <esf_buf_setup-0x34> (0 <esf_buf_setup-0x60>) */ /* literal: GOT slot for memset */
  memset(a2, a3, a4, a5); /* call via literal slot */ /* 0071: callx8 a8 */
  a5 = (uint32_t)&eb_space; /* 0074: l32r a5, 0 <esf_buf_setup-0x60> (0 <esf_buf_setup-0x60>) */ /* literal @0x0: eb_space */
  a12 = 0xC0; /* 0077: movi a12, 192 */
  a11 = 0x0; /* 007a: movi.n a11, 0 */
  a10 = a5; /* 007c: mov.n a10, a5 */
  a8 = (uint32_t)&memset; /* 007e: l32r a8, 30 <esf_buf_setup-0x30> (0 <esf_buf_setup-0x60>) */ /* literal: GOT slot for memset */
  memset(a2, a3, a4, a5); /* call via literal slot */ /* 0081: callx8 a8 */
  a3 = (uint32_t)&g_wifi_menuconfig; /* 0084: l32r a3, 8 <esf_buf_setup-0x58> (0 <esf_buf_setup-0x60>) */ /* literal @0x8: g_wifi_menuconfig */
  a14 = MEM16(a3 + 4); /* 0087: l16ui a14, a3, 4 */
  if (a14 != 0) goto L_8e; /* 008a: bnez.n a14, 8e <esf_buf_setup+0x2e> */
  a14 = 0x40; /* 008c: movi.n a14, 64 */
L_8e:;
  a11 = 0x1; /* 008e: movi.n a11, 1 */
  a4 = (uint32_t)&g_eb_list_desc; /* 0090: l32r a4, c <esf_buf_setup-0x54> (0 <esf_buf_setup-0x60>) */ /* literal @0xC: g_eb_list_desc */
  a12 = 0x3; /* 0093: movi.n a12, 3 */
  a10 = 0x6; /* 0095: movi.n a10, 6 */
  a13 = (uint32_t)&lit_rodata_wlog_info_10; /* 0097: l32r a13, 10 <esf_buf_setup-0x50> (0 <esf_buf_setup-0x60>) */ /* literal @0x10: .rodata_wlog_info.10 */
  MEM16(a4 + 156) = a14; /* 009a: s16i a14, a4, 156 */
  MEMW(); /* 009d: memw  */
  MEMW(); /* 00a0: memw  */
  a8 = (uint32_t)&wifi_log; /* 00a3: l32r a8, 34 <esf_buf_setup-0x2c> (0 <esf_buf_setup-0x60>) */ /* literal: GOT slot for wifi_log */
  wifi_log(a2, a3, a4, a5); /* call via literal slot */ /* 00a6: callx8 a8 */
  a8 = MEM32(a3 + 84); /* 00a9: l32i a8, a3, 84 */
  a11 = MEM16(a3 + 88); /* 00ac: l16ui a11, a3, 88 */
  if (a8 != 0) goto L_d5; /* 00af: bnez.n a8, d5 <esf_buf_setup+0x75> */
  if (a11 != 0) goto L_b5; /* 00b1: bnez.n a11, b5 <esf_buf_setup+0x55> */
  a11 = 0xA; /* 00b3: movi.n a11, 10 */
L_b5:;
  a12 = 0x1F4; /* 00b5: movi a12, 0x1f4 */
  MEM16(a4 + 176) = a11; /* 00b8: s16i a11, a4, 176 */
  MEMW(); /* 00bb: memw  */
  a10 = 0x8; /* 00be: movi.n a10, 8 */
  MEMW(); /* 00c0: memw  */
  a8 = (uint32_t)&esf_buf_setup_static; /* 00c3: l32r a8, 38 <esf_buf_setup-0x28> (0 <esf_buf_setup-0x60>) */ /* literal: GOT slot for esf_buf_setup_static */
  esf_buf_setup_static(a2, a3, a4, a5); /* call via literal slot */ /* 00c6: callx8 a8 */
  if (a10 != 0) goto L_1c1; /* 00c9: bnez a10, 1c1 <esf_buf_setup+0x161> */
  a14 = MEM16(a4 + 176); /* 00cc: l16ui a14, a4, 176 */
  a13 = (uint32_t)&lit_rodata_wlog_info_11; /* 00cf: l32r a13, 14 <esf_buf_setup-0x4c> (0 <esf_buf_setup-0x60>) */ /* literal @0x14: .rodata_wlog_info.11 */
  goto L_e6; /* 00d2: j e6 <esf_buf_setup+0x86> */
L_d5:;
  a14 = 0xA; /* 00d5: mov.n a14, a11 */
  if (a11 != 0) goto L_dd; /* 00d7: bnez a11, dd <esf_buf_setup+0x7d> */
  a14 = 0xA; /* 00da: movi a14, 10 */
L_dd:;
  a13 = (uint32_t)&lit_rodata_wlog_info_12; /* 00dd: l32r a13, 18 <esf_buf_setup-0x48> (0 <esf_buf_setup-0x60>) */ /* literal @0x18: .rodata_wlog_info.12 */
  MEM16(a4 + 176) = a14; /* 00e0: s16i a14, a4, 176 */
  MEMW(); /* 00e3: memw  */
L_e6:;
  a12 = 0x3; /* 00e6: movi.n a12, 3 */
  a11 = 0x1; /* 00e8: movi.n a11, 1 */
  a10 = 0x6; /* 00ea: movi.n a10, 6 */
  MEMW(); /* 00ec: memw  */
  a8 = (uint32_t)&wifi_log; /* 00ef: l32r a8, 3c <esf_buf_setup-0x24> (0 <esf_buf_setup-0x60>) */ /* literal: GOT slot for wifi_log */
  wifi_log(a2, a3, a4, a5); /* call via literal slot */ /* 00f2: callx8 a8 */
  a14 = MEM16(a3 + 60); /* 00f5: l16ui a14, a3, 60 */
  if (a14 != 0) goto L_fd; /* 00f8: bnez.n a14, fd <esf_buf_setup+0x9d> */
  a14 = 0x20; /* 00fa: movi a14, 32 */
L_fd:;
  a12 = 0x3; /* 00fd: movi.n a12, 3 */
  a13 = (uint32_t)&lit_rodata_wlog_info_13; /* 00ff: l32r a13, 1c <esf_buf_setup-0x44> (0 <esf_buf_setup-0x60>) */ /* literal @0x1C: .rodata_wlog_info.13 */
  a11 = 0x1; /* 0102: movi.n a11, 1 */
  a10 = 0x6; /* 0104: movi.n a10, 6 */
  MEM16(a4 + 76) = a14; /* 0106: s16i a14, a4, 76 */
  MEMW(); /* 0109: memw  */
  MEMW(); /* 010c: memw  */
  a8 = (uint32_t)&wifi_log; /* 010f: l32r a8, 40 <esf_buf_setup-0x20> (0 <esf_buf_setup-0x60>) */ /* literal: GOT slot for wifi_log */
  wifi_log(a2, a3, a4, a5); /* call via literal slot */ /* 0112: callx8 a8 */
  a8 = MEM32(a3 + 8); /* 0115: l32i.n a8, a3, 8 */
  if (a8 != 0) goto L_149; /* 0117: bnez.n a8, 149 <esf_buf_setup+0xe9> */
  a8 = MEM16(a3 + 12); /* 0119: l16ui a8, a3, 12 */
  if (a8 != 0) goto L_120; /* 011c: bnez.n a8, 120 <esf_buf_setup+0xc0> */
  a8 = 0x20; /* 011e: movi.n a8, 32 */
L_120:;
  a12 = 0x640; /* 0120: movi a12, 0x640 */
  MEM16(a4 + 36) = a8; /* 0123: s16i a8, a4, 36 */
  MEMW(); /* 0126: memw  */
  a11 = a2; /* 0129: mov.n a11, a2 */
  a10 = 0x1; /* 012b: movi.n a10, 1 */
  a8 = MEM8(a4 + 32); /* 012d: l8ui a8, a4, 32 */
  a12 = a12 - a8; /* 0130: sub a12, a12, a8 */
  MEMW(); /* 0133: memw  */
  a8 = (uint32_t)&esf_buf_setup_static; /* 0136: l32r a8, 44 <esf_buf_setup-0x1c> (0 <esf_buf_setup-0x60>) */ /* literal: GOT slot for esf_buf_setup_static */
  esf_buf_setup_static(a2, a3, a4, a5); /* call via literal slot */ /* 0139: callx8 a8 */
  a14 = a2; /* 013c: mov.n a14, a2 */
  a13 = (uint32_t)&lit_rodata_wlog_info_14; /* 013e: l32r a13, 20 <esf_buf_setup-0x40> (0 <esf_buf_setup-0x60>) */ /* literal @0x20: .rodata_wlog_info.14 */
  if (a10 == 0) goto L_159; /* 0141: beqz.n a10, 159 <esf_buf_setup+0xf9> */
  goto L_1c1; /* 0143: j 1c1 <esf_buf_setup+0x161> */
  /* 0146: .byte 00 */
  /* 0147: .byte 00 */
  /* 0148: .byte 00 */
L_149:;
  a14 = MEM16(a3 + 16); /* 0149: l16ui a14, a3, 16 */
  if (a14 != 0) goto L_150; /* 014c: bnez.n a14, 150 <esf_buf_setup+0xf0> */
  a14 = 0x20; /* 014e: movi.n a14, 32 */
L_150:;
  a13 = (uint32_t)&lit_rodata_wlog_info_15; /* 0150: l32r a13, 24 <esf_buf_setup-0x3c> (0 <esf_buf_setup-0x60>) */ /* literal @0x24: .rodata_wlog_info.15 */
  MEM16(a4 + 36) = a14; /* 0153: s16i a14, a4, 36 */
  MEMW(); /* 0156: memw  */
L_159:;
  a12 = 0x3; /* 0159: movi.n a12, 3 */
  a11 = 0x1; /* 015b: movi.n a11, 1 */
  a10 = 0x6; /* 015d: movi.n a10, 6 */
  MEMW(); /* 015f: memw  */
  a8 = (uint32_t)&wifi_log; /* 0162: l32r a8, 48 <esf_buf_setup-0x18> (0 <esf_buf_setup-0x60>) */ /* literal: GOT slot for wifi_log */
  wifi_log(a2, a3, a4, a5); /* call via literal slot */ /* 0165: callx8 a8 */
  a8 = (uint32_t)&config_is_cache_tx_buf_enabled; /* 0168: l32r a8, 4c <esf_buf_setup-0x14> (0 <esf_buf_setup-0x60>) */ /* literal: GOT slot for config_is_cache_tx_buf_enabled */
  config_is_cache_tx_buf_enabled(a2, a3, a4, a5); /* call via literal slot */ /* 016b: callx8 a8 */
  if (a10 == 0) goto L_198; /* 016e: beqz.n a10, 198 <esf_buf_setup+0x138> */
  a2 = MEM8(a4 + 192); /* 0170: l8ui a2, a4, 192 */
  a12 = 0x640; /* 0173: movi a12, 0x640 */
  a12 = a12 - a2; /* 0176: sub a12, a12, a2 */
  a10 = 0x9; /* 0179: movi.n a10, 9 */
  a11 = MEM32(a3 + 20); /* 017b: l32i a11, a3, 20 */
  a8 = (uint32_t)&esf_buf_setup_static; /* 017e: l32r a8, 50 <esf_buf_setup-0x10> (0 <esf_buf_setup-0x60>) */ /* literal: GOT slot for esf_buf_setup_static */
  esf_buf_setup_static(a2, a3, a4, a5); /* call via literal slot */ /* 0181: callx8 a8 */
  if (a10 != 0) goto L_1c1; /* 0184: bnez.n a10, 1c1 <esf_buf_setup+0x161> */
  a12 = 0x3; /* 0186: movi.n a12, 3 */
  a14 = MEM32(a3 + 20); /* 0188: l32i.n a14, a3, 20 */
  a11 = 0x1; /* 018a: movi.n a11, 1 */
  a10 = 0x6; /* 018c: movi a10, 6 */
  a13 = (uint32_t)&lit_rodata_wlog_info_16; /* 018f: l32r a13, 28 <esf_buf_setup-0x38> (0 <esf_buf_setup-0x60>) */ /* literal @0x28: .rodata_wlog_info.16 */
  a8 = (uint32_t)&wifi_log; /* 0192: l32r a8, 54 <esf_buf_setup-0xc> (0 <esf_buf_setup-0x60>) */ /* literal: GOT slot for wifi_log */
  wifi_log(a2, a3, a4, a5); /* call via literal slot */ /* 0195: callx8 a8 */
L_198:;
  a2 = 0x0; /* 0198: movi.n a2, 0 */
  a3 = 0x5; /* 019a: movi.n a3, 5 */
L_19c:;
  a4 = a6 + a2; /* 019c: add.n a4, a6, a2 */
  MEM32(a5 + 44) = a4; /* 019e: s32i.n a4, a5, 44 */
  a10 = a5; /* 01a0: mov.n a10, a5 */
  a2 = 0x20; /* 01a2: addi a2, a2, 32 */
  MEM8(a5 + 26) = a3; /* 01a5: s8i a3, a5, 26 */
  MEMW(); /* 01a8: memw  */
  MEMW(); /* 01ab: memw  */
  a8 = (uint32_t)&esf_buf_recycle; /* 01ae: l32r a8, 58 <esf_buf_setup-0x8> (0 <esf_buf_setup-0x60>) */ /* literal: GOT slot for esf_buf_recycle */
  esf_buf_recycle(a2, a3, a4, a5); /* call via literal slot */ /* 01b1: callx8 a8 */
  a5 = a5 + (48); /* 01b4: addi a5, a5, 48 */
  if (a2 != 128) goto L_19c; /* 01b7: bnei a2, 128, 19c <esf_buf_setup+0x13c> */
  a10 = 0x0; /* 01ba: movi.n a10, 0 */
  goto L_1ce; /* 01bc: j 1ce <esf_buf_setup+0x16e> */
  /* 01bf: .byte 00 */
  /* 01c0: .byte 00 */
L_1c1:;
  MEM32(a1 + 0) = a10; /* 01c1: s32i.n a10, a1, 0 */
  MEMW(); /* 01c3: memw  */
  a8 = (uint32_t)&esf_buf_setdown; /* 01c6: l32r a8, 5c <esf_buf_setup-0x4> (0 <esf_buf_setup-0x60>) */ /* literal: GOT slot for esf_buf_setdown */
  esf_buf_setdown(a2, a3, a4, a5); /* call via literal slot */ /* 01c9: callx8 a8 */
  a10 = MEM32(a1 + 0); /* 01cc: l32i.n a10, a1, 0 */
L_1ce:;
  a2 = a10; /* 01ce: mov.n a2, a10 */
  return (int32_t)a2; /* 01d0: retw.n  */
}

/* esf_buf_statis_dump @ esf_buf.o 0000003c size 141B bind GLOBAL
 * Calls: wifi_log | Data refs: .rodata.esf_buf_statis_dump.str1.1, .rodata_wlog_info.17, .rodata_wlog_info.18, .rodata_wlog_info.19, g_eb_list_desc, g_lmac_cnt, wifi_log
 *   MMIO: none
 *   funcdb v3: 1 call(s), 7 ref(s); disasm: 3 call(s), 7 data ref(s)
 * Fidelity: medium - 52 instr, 1 branches, calls resolved */
int32_t esf_buf_statis_dump(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.esf_buf_statis_dump; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_3c:;
  /* 003c: entry a1, 64 */
  a13 = (uint32_t)&lit_rodata_wlog_info_17; /* 003f: l32r a13, 0 <esf_buf_statis_dump-0x3c> (0 <esf_buf_statis_dump-0x3c>) */ /* literal @0x0: .rodata_wlog_info.17 */
  a12 = 0x3; /* 0042: movi a12, 3 */
  a11 = 0x400; /* 0045: movi a11, 0x400 */
  a10 = 0x1; /* 0048: movi.n a10, 1 */
  a8 = (uint32_t)&wifi_log; /* 004a: l32r a8, 30 <esf_buf_statis_dump-0xc> (0 <esf_buf_statis_dump-0x3c>) */ /* literal: GOT slot for wifi_log */
  wifi_log(a2, a3, a4, a5); /* call via literal slot */ /* 004d: callx8 a8 */
  a2 = (uint32_t)&lit_rodata_esf_buf_statis_dump_str1_1; /* 0050: l32r a2, 10 <esf_buf_statis_dump-0x2c> (6 <esf_buf_statis_dump-0x36>) */ /* literal @0x10: .rodata.esf_buf_statis_dump.str1.1 */
  a12 = 0x3; /* 0053: movi.n a12, 3 */
  a11 = 0x400; /* 0055: movi a11, 0x400 */
  a10 = 0x1; /* 0058: movi.n a10, 1 */
  MEM32(a1 + 16) = a2; /* 005a: s32i.n a2, a1, 16 */
  a2 = (uint32_t)&lit_rodata_esf_buf_statis_dump_str1_1; /* 005c: l32r a2, 14 <esf_buf_statis_dump-0x28> (f <esf_buf_statis_dump-0x2d>) */ /* literal @0x14: .rodata.esf_buf_statis_dump.str1.1 */
  MEM32(a1 + 12) = a2; /* 005f: s32i.n a2, a1, 12 */
  a2 = (uint32_t)&lit_rodata_esf_buf_statis_dump_str1_1; /* 0061: l32r a2, 18 <esf_buf_statis_dump-0x24> (17 <esf_buf_statis_dump-0x25>) */ /* literal @0x18: .rodata.esf_buf_statis_dump.str1.1 */
  MEM32(a1 + 8) = a2; /* 0064: s32i a2, a1, 8 */
  a2 = (uint32_t)&lit_rodata_esf_buf_statis_dump_str1_1; /* 0067: l32r a2, 1c <esf_buf_statis_dump-0x20> (22 <esf_buf_statis_dump-0x1a>) */ /* literal @0x1C: .rodata.esf_buf_statis_dump.str1.1 */
  MEM32(a1 + 4) = a2; /* 006a: s32i.n a2, a1, 4 */
  a2 = (uint32_t)&lit_rodata_esf_buf_statis_dump_str1_1; /* 006c: l32r a2, 20 <esf_buf_statis_dump-0x1c> (2e <esf_buf_statis_dump-0xe>) */ /* literal @0x20: .rodata.esf_buf_statis_dump.str1.1 */
  a15 = (uint32_t)&lit_rodata_esf_buf_statis_dump_str1_1; /* 006f: l32r a15, 4 <esf_buf_statis_dump-0x38> (0 <esf_buf_statis_dump-0x3c>) */ /* literal @0x4: .rodata.esf_buf_statis_dump.str1.1 */
  a14 = (uint32_t)&lit_rodata_esf_buf_statis_dump_str1_1; /* 0072: l32r a14, 8 <esf_buf_statis_dump-0x34> (4 <esf_buf_statis_dump-0x38>) */ /* literal @0x8: .rodata.esf_buf_statis_dump.str1.1 */
  a13 = (uint32_t)&lit_rodata_wlog_info_18; /* 0075: l32r a13, c <esf_buf_statis_dump-0x30> (0 <esf_buf_statis_dump-0x3c>) */ /* literal @0xC: .rodata_wlog_info.18 */
  MEM32(a1 + 0) = a2; /* 0078: s32i a2, a1, 0 */
  MEMW(); /* 007b: memw  */
  a8 = (uint32_t)&wifi_log; /* 007e: l32r a8, 34 <esf_buf_statis_dump-0x8> (0 <esf_buf_statis_dump-0x3c>) */ /* literal: GOT slot for wifi_log */
  wifi_log(a2, a3, a4, a5); /* call via literal slot */ /* 0081: callx8 a8 */
  a2 = (uint32_t)&g_lmac_cnt; /* 0084: l32r a2, 28 <esf_buf_statis_dump-0x14> (0 <esf_buf_statis_dump-0x3c>) */ /* literal @0x28: g_lmac_cnt */
  a4 = a2 + (108); /* 0087: addi a4, a2, 108 */
  a3 = (uint32_t)&g_eb_list_desc; /* 008a: l32r a3, 24 <esf_buf_statis_dump-0x18> (0 <esf_buf_statis_dump-0x3c>) */ /* literal @0x24: g_eb_list_desc */
L_8d:;
  a12 = 0x3; /* 008d: movi.n a12, 3 */
  a11 = 0x400; /* 008f: movi a11, 0x400 */
  a10 = 0x1; /* 0092: movi.n a10, 1 */
  a2 = a2 + (12); /* 0094: addi.n a2, a2, 12 */
  a8 = MEM16(a2 + 8); /* 0096: l16ui a8, a2, 8 */
  a3 = a3 + (20); /* 0099: addi a3, a3, 20 */
  a15 = MEM16(a3 + 16); /* 009c: l16ui a15, a3, 16 */
  a14 = MEM8(a3 + 8); /* 009f: l8ui a14, a3, 8 */
  MEM32(a1 + 16) = a8; /* 00a2: s32i.n a8, a1, 16 */
  a8 = MEM16(a2 + 10); /* 00a4: l16ui a8, a2, 10 */
  MEM32(a1 + 12) = a8; /* 00a7: s32i.n a8, a1, 12 */
  a8 = MEM32(a2 + 4); /* 00a9: l32i.n a8, a2, 4 */
  MEM32(a1 + 8) = a8; /* 00ab: s32i.n a8, a1, 8 */
  a8 = MEM32(a2 + 0); /* 00ad: l32i.n a8, a2, 0 */
  MEM32(a1 + 4) = a8; /* 00af: s32i a8, a1, 4 */
  a8 = MEM16(a3 + 14); /* 00b2: l16ui a8, a3, 14 */
  a13 = (uint32_t)&lit_rodata_wlog_info_19; /* 00b5: l32r a13, 2c <esf_buf_statis_dump-0x10> (0 <esf_buf_statis_dump-0x3c>) */ /* literal @0x2C: .rodata_wlog_info.19 */
  MEM32(a1 + 0) = a8; /* 00b8: s32i a8, a1, 0 */
  MEMW(); /* 00bb: memw  */
  a8 = (uint32_t)&wifi_log; /* 00be: l32r a8, 38 <esf_buf_statis_dump-0x4> (0 <esf_buf_statis_dump-0x3c>) */ /* literal: GOT slot for wifi_log */
  wifi_log(a2, a3, a4, a5); /* call via literal slot */ /* 00c1: callx8 a8 */
  if (a2 != a4) goto L_8d; /* 00c4: bne a2, a4, 8d <esf_buf_statis_dump+0x51> */
  return (int32_t)a2; /* 00c7: retw.n  */
}

