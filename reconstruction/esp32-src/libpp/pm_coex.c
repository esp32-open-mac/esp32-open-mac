/* ===== pm_coex.o : reconstructed from libpp.a (ESP32, Xtensa, esp-2022r1) =====
 * Toolchain: xtensa-esp32-elf (GCC 11.2.0 crosstool-NG esp-2022r1).
 * ABI: args a2..a7, return a2 (all functions take a2..a7, return int32_t).
 * memw barriers preserved as MEMW(). MMIO as REG32/REG16/REG8(addr).
 * Calls with unknown arg counts are modeled with 4 live args (a2..a5);
 * a2..a7 are clobbered across calls (windowed-ABI approximation).
 * Sections: .iram1.2, .text.pm_coex_customized_wifi_time_slice, .text.pm_coex_pwr_configure, .text.pm_coex_recalculate_wifi_time_slice, .text.pm_coex_reconnect_policy, .text.pm_coex_set_reconnect_policy, .text.pm_coex_update_wifi_time_slice_state, .wifislprxiram.4, .wifislprxiram.5
 * Undefined refs (9): __umoddi3, g_mesh_init_ps_type, g_mesh_is_root, g_mesh_is_started, g_osi_funcs_p, g_pm, g_pm_cfg, g_wifi_mac_time_delta, wifi_log
 */
#include <stdint.h>
#define REG32(a) (*(volatile uint32_t *)(a))
#define REG16(a) (*(volatile uint16_t *)(a))
#define REG8(a)  (*(volatile uint8_t *)(a))
#define MEM32(a) (*(volatile uint32_t *)(a))
#define MEM16(a) (*(volatile uint16_t *)(a))
#define MEM8(a)  (*(volatile uint8_t *)(a))
#define MEMW() __asm__ volatile("memw" ::: "memory")

extern int32_t g_pm();
extern int32_t g_osi_funcs_p();
extern uint32_t rodata_wlog_info_3; /* .rodata_wlog_info.3 */
extern int32_t wifi_log();
extern uint32_t g_mesh_is_started; /* g_mesh_is_started */
extern uint32_t g_mesh_is_root; /* g_mesh_is_root */
extern int32_t g_mesh_init_ps_type();
extern uint32_t g_wifi_mac_time_delta; /* g_wifi_mac_time_delta */
extern uint32_t g_pm_cfg; /* g_pm_cfg */
extern int32_t umoddi3();
extern uint32_t rodata_pm_coex_recalculate_wifi_time_slice_str1_1; /* .rodata.pm_coex_recalculate_wifi_time_slice.str1.1 */
extern uint32_t rodata_wlog_error_6; /* .rodata_wlog_error.6 */

/* pool[pm_coex_reconnect_policy]: +0x0=0x00000000(g_pm) */
/* pool[pm_coex_set_reconnect_policy]: +0x0=0x00000000(g_osi_funcs_p), +0x4=0x00000000(g_pm), +0x8=0x00000000(.rodata_wlog_info.3), +0xc=0x00000000(wifi_log) */
/* pool[pm_coex_schm_overall_period_get]: +0x0=0x00000000(g_osi_funcs_p) */
/* pool[pm_get_null_max_tx_time]: +0x4=0x00000000(g_osi_funcs_p), +0x0=0x00000000(g_pm), +0x8=0x00FFFF00, +0xc=0x00000000(g_mesh_is_started), +0x10=0x00000000(g_mesh_is_root), +0x14=0x00000000(g_mesh_init_ps_type), +0x18=0x3FF73C00, +0x1c=0x00000000(g_wifi_mac_time_delta), +0x20=0x00000000(pm_coex_schm_overall_period_get) */
/* pool[pm_coex_pwr_update]: +0x0=0x00000000(g_pm), +0xc=0x00000000(g_pm+0x100), +0x4=0x00000000(g_pm_cfg), +0x8=0x00000000(g_osi_funcs_p) */
/* pool[pm_coex_pwr_configure]: +0x0=0x00000000(g_pm_cfg), +0x4=0x00000000(pm_coex_pwr_update) */
/* pool[pm_coex_recalculate_wifi_time_slice]: +0x0=0x00000000(g_osi_funcs_p), +0x4=0x00000000(g_pm), +0x28=0x00000000(pm_coex_schm_overall_period_get), +0x8=0x00000000(g_mesh_is_started), +0xc=0x00000000(g_mesh_is_root), +0x10=0x00000000(g_mesh_init_ps_type), +0x14=0x3FF73C00, +0x18=0x00000000(g_wifi_mac_time_delta), +0x2c=0x00000000(__umoddi3), +0x1c=0x00000000(.rodata.pm_coex_recalculate_wifi_time_slice.str1.1), +0x20=0x00000000(.rodata_wlog_error.6), +0x30=0x00000000(wifi_log), +0x34=0x00000000(pm_coex_schm_overall_period_get), +0x24=0x00000000(g_pm+0xf4) */
/* pool[pm_coex_update_wifi_time_slice_state]: +0xc=0x00000000(pm_coex_recalculate_wifi_time_slice), +0x0=0x00000000(g_osi_funcs_p), +0x4=0x00000000(g_pm), +0x8=0x00001387 */
/* pool[pm_coex_customized_wifi_time_slice]: +0x0=0x00000000(g_pm), +0x8=0x00000000(g_osi_funcs_p), +0x4=0x00000000(g_pm+0xf4) */

/* pm_coex_reconnect_policy @ pm_coex.o 00000004 size 22B bind GLOBAL
 * Calls: none | Data refs: g_pm
 *   MMIO: none
 *   funcdb v3: 0 call(s), 1 ref(s); disasm: 0 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t pm_coex_reconnect_policy(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pm_coex_reconnect_policy; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a2 = (uint32_t)&g_pm; /* 0007: l32r a2, 0 <pm_coex_reconnect_policy-0x4> (0 <pm_coex_reconnect_policy-0x4>) */ /* literal @0x0: g_pm */
  a8 = 0x1; /* 000a: movi.n a8, 1 */
  a2 = a2 + ((0x100) << 8); /* 000c: addmi a2, a2, 0x100 */
  a2 = MEM8(a2 + 201); /* 000f: l8ui a2, a2, 201 */
  a2 = a2 ^ a8; /* 0012: xor a2, a2, a8 */
  a2 = (a2 >> 0) & 0xFF; /* 0015: extui a2, a2, 0, 8 */
  return (int32_t)a2; /* 0018: retw.n  */
}

/* pm_coex_set_reconnect_policy @ pm_coex.o 00000010 size 54B bind GLOBAL
 * Calls: wifi_log | Data refs: .rodata_wlog_info.3, g_osi_funcs_p, g_pm, wifi_log
 *   MMIO: none
 *   funcdb v3: 1 call(s), 4 ref(s); disasm: 1 call(s), 4 data ref(s)
 * Fidelity: medium - 20 instr, 1 branches, calls resolved */
int32_t pm_coex_set_reconnect_policy(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pm_coex_set_reconnect_policy; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_10:;
  /* 0010: entry a1, 32 */
  a8 = (uint32_t)&g_osi_funcs_p; /* 0013: l32r a8, 0 <pm_coex_set_reconnect_policy-0x10> (0 <pm_coex_set_reconnect_policy-0x10>) */ /* literal @0x0: g_osi_funcs_p */
  a8 = MEM32(a8 + 0); /* 0016: l32i.n a8, a8, 0 */
  a10 = MEM32(a8 + 404); /* 0018: l32i a10, a8, 0x194 */
  ((int32_t(*)())a10)(a2, a3, a4, a5); /* 001b: callx8 a10 */ /* indirect */
  if (a10 == 0) goto L_44; /* 001e: beqz.n a10, 44 <pm_coex_set_reconnect_policy+0x34> */
  a11 = 0x1; /* 0020: movi.n a11, 1 */
  a8 = (uint32_t)&g_pm; /* 0022: l32r a8, 4 <pm_coex_set_reconnect_policy-0xc> (0 <pm_coex_set_reconnect_policy-0x10>) */ /* literal @0x4: g_pm */
  a9 = 0x0; /* 0025: movi.n a9, 0 */
  a8 = a8 + ((0x100) << 8); /* 0027: addmi a8, a8, 0x100 */
  a12 = 0x3; /* 002a: movi.n a12, 3 */
  a11 = 0x1000; /* 002c: slli a11, a11, 12 */
  a13 = (uint32_t)&lit_rodata_wlog_info_3; /* 002f: l32r a13, 8 <pm_coex_set_reconnect_policy-0x8> (0 <pm_coex_set_reconnect_policy-0x10>) */ /* literal @0x8: .rodata_wlog_info.3 */
  a10 = 0x6; /* 0032: movi a10, 6 */
  MEM8(a8 + 201) = a9; /* 0035: s8i a9, a8, 201 */
  MEMW(); /* 0038: memw  */
  MEMW(); /* 003b: memw  */
  a8 = (uint32_t)&wifi_log; /* 003e: l32r a8, c <pm_coex_set_reconnect_policy-0x4> (0 <pm_coex_set_reconnect_policy-0x10>) */ /* literal: GOT slot for wifi_log */
  wifi_log(a2, a3, a4, a5); /* call via literal slot */ /* 0041: callx8 a8 */
L_44:;
  return (int32_t)a2; /* 0044: retw.n  */
}

/* pm_coex_schm_overall_period_get @ pm_coex.o 00000004 size 32B bind GLOBAL
 * Calls: none | Data refs: g_osi_funcs_p
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 1 data ref(s)
 * Fidelity: medium - 12 instr, 0 branches, calls resolved */
int32_t pm_coex_schm_overall_period_get(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .wifislprxiram.4; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a3 = (uint32_t)&g_osi_funcs_p; /* 0007: l32r a3, 0 <pm_coex_schm_overall_period_get-0x4> (0 <pm_coex_schm_overall_period_get-0x4>) */ /* literal @0x0: g_osi_funcs_p */
  a2 = MEM32(a3 + 0); /* 000a: l32i.n a2, a3, 0 */
  a10 = MEM32(a2 + 448); /* 000c: l32i a10, a2, 0x1c0 */
  ((int32_t(*)())a10)(a2, a3, a4, a5); /* 000f: callx8 a10 */ /* indirect */
  a2 = a10; /* 0012: mov.n a2, a10 */
  a3 = MEM32(a3 + 0); /* 0014: l32i.n a3, a3, 0 */
  a10 = MEM32(a3 + 472); /* 0016: l32i a10, a3, 0x1d8 */
  ((int32_t(*)())a10)(a2, a3, a4, a5); /* 0019: callx8 a10 */ /* indirect */
  /* 001c: maxu a2, a2, a10 */ /* UNMODELED: a2 clobbered */
  a2 = (a2 >> 0) & 0xFF; /* 001f: extui a2, a2, 0, 8 */
  return (int32_t)a2; /* 0022: retw.n  */
}

/* pm_get_null_max_tx_time @ pm_coex.o 00000024 size 168B bind GLOBAL
 * Calls: pm_coex_schm_overall_period_get[got] | Data refs: g_osi_funcs_p, g_pm, g_mesh_is_started, g_mesh_is_root, g_mesh_init_ps_type, g_wifi_mac_time_delta, pm_coex_schm_overall_period_get
 *   MMIO: 0x3FF73C00
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 1 call(s), 7 data ref(s)
 * Fidelity: medium - 62 instr, 11 branches, 3 indirect; flow + direct calls mapped, GOT-indirects enumerated */
int32_t pm_get_null_max_tx_time(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .iram1.2; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_24:;
  /* 0024: entry a1, 32 */
  a4 = (uint32_t)&g_osi_funcs_p; /* 0027: l32r a4, 4 <pm_get_null_max_tx_time-0x20> (0 <pm_get_null_max_tx_time-0x24>) */ /* literal @0x4: g_osi_funcs_p */
  a6 = (a2 >> 0) & 0xFF; /* 002a: extui a6, a2, 0, 8 */
  a8 = MEM32(a4 + 0); /* 002d: l32i a8, a4, 0 */
  a5 = (uint32_t)&g_pm; /* 0030: l32r a5, 0 <pm_get_null_max_tx_time-0x24> (0 <pm_get_null_max_tx_time-0x24>) */ /* literal @0x0: g_pm */
  a10 = MEM32(a8 + 404); /* 0033: l32i a10, a8, 0x194 */
  a2 = MEM32(a5 + 44); /* 0036: l32i a2, a5, 44 */
  ((int32_t(*)())a10)(a2, a3, a4, a5); /* 0039: callx8 a10 */ /* indirect */
  if (a10 == 0) goto L_ca; /* 003c: beqz a10, ca <pm_get_null_max_tx_time+0xa6> */
  a8 = 0xFFFF00; /* 003f: l32r a8, 8 <pm_get_null_max_tx_time-0x1c> (ffff00 <pm_coex_recalculate_wifi_time_slice+0xfffec8>) */ @0x8
  a9 = MEM32(a5 + 12); /* 0042: l32i.n a9, a5, 12 */
  a9 = a9 & a8; /* 0044: and a9, a9, a8 */
  a8 = 0x101; /* 0047: movi a8, 0x101 */
  a8 = 0x10100; /* 004a: slli a8, a8, 8 */
  if (a9 != a8) goto L_ca; /* 004d: bne a9, a8, ca <pm_get_null_max_tx_time+0xa6> */
  if (a6 == 0) goto L_68; /* 0050: beqz.n a6, 68 <pm_get_null_max_tx_time+0x44> */
  a2 = a5 + ((0x200) << 8); /* 0052: addmi a2, a5, 0x200 */
  a3 = MEM8(a2 + 31); /* 0055: l8ui a3, a2, 31 */
  a2 = 0x271; /* 0058: movi a2, 0x271 */
  a2 = 0x1388; /* 005b: slli a2, a2, 3 */
  if (a3 != 0) goto L_ca; /* 005e: bnez a3, ca <pm_get_null_max_tx_time+0xa6> */
  a2 = MEM32(a5 + 432); /* 0061: l32i a2, a5, 0x1b0 */
  goto L_ca; /* 0064: j ca <pm_get_null_max_tx_time+0xa6> */
  /* 0067: .byte 00 */
L_68:;
  a2 = (uint32_t)&g_mesh_is_started; /* 0068: l32r a2, c <pm_get_null_max_tx_time-0x18> (0 <pm_get_null_max_tx_time-0x24>) */ /* literal @0xC: g_mesh_is_started */
  a2 = MEM8(a2 + 0); /* 006b: l8ui a2, a2, 0 */
  if (a2 == 0) goto L_91; /* 006e: beqz.n a2, 91 <pm_get_null_max_tx_time+0x6d> */
  a2 = (uint32_t)&g_mesh_is_root; /* 0070: l32r a2, 10 <pm_get_null_max_tx_time-0x14> (0 <pm_get_null_max_tx_time-0x24>) */ /* literal @0x10: g_mesh_is_root */
  MEMW(); /* 0073: memw  */
  a2 = MEM8(a2 + 0); /* 0076: l8ui a2, a2, 0 */
  a2 = (a2 >> 0) & 0xFF; /* 0079: extui a2, a2, 0, 8 */
  if (a2 != 0) goto L_91; /* 007c: bnez.n a2, 91 <pm_get_null_max_tx_time+0x6d> */
  a2 = (uint32_t)&g_mesh_init_ps_type; /* 007e: l32r a2, 14 <pm_get_null_max_tx_time-0x10> (0 <pm_get_null_max_tx_time-0x24>) */ /* literal @0x14: g_mesh_init_ps_type */
  a2 = MEM32(a2 + 0); /* 0081: l32i.n a2, a2, 0 */
  if (a2 == 0) goto L_91; /* 0083: beqz.n a2, 91 <pm_get_null_max_tx_time+0x6d> */
  a2 = MEM32(a4 + 0); /* 0085: l32i.n a2, a4, 0 */
  a10 = MEM32(a2 + 272); /* 0087: l32i a10, a2, 0x110 */
  ((int32_t(*)())a10)(a2, a3, a4, a5); /* 008a: callx8 a10 */ /* indirect */
  goto L_a0; /* 008d: j a0 <pm_get_null_max_tx_time+0x7c> */
  /* 0090: .byte 00 */
L_91:;
  a2 = 0x3FF73C00; /* 0091: l32r a2, 18 <pm_get_null_max_tx_time-0xc> (3ff73c00 <pm_coex_recalculate_wifi_time_slice+0x3ff73bc8>) */ /* MMIO base */ @0x18
  a8 = (uint32_t)&g_wifi_mac_time_delta; /* 0094: l32r a8, 1c <pm_get_null_max_tx_time-0x8> (0 <pm_get_null_max_tx_time-0x24>) */ /* literal @0x1C: g_wifi_mac_time_delta */
  MEMW(); /* 0097: memw  */
  a2 = REG32(0x3FF73C00); /* 009a: l32i.n a2, a2, 0 */ /* MMIO read: base 0x3FF73C00+0 */
  a8 = MEM32(a8 + 0); /* 009c: l32i.n a8, a8, 0 */
  a10 = a2 + a8; /* 009e: add.n a10, a2, a8 */
L_a0:;
  a2 = a10 - a3; /* 00a0: sub a2, a10, a3 */
  a8 = (uint32_t)&pm_coex_schm_overall_period_get; /* 00a3: l32r a8, 20 <pm_get_null_max_tx_time-0x4> (0 <pm_get_null_max_tx_time-0x24>) */ /* literal: GOT slot for pm_coex_schm_overall_period_get */
  pm_coex_schm_overall_period_get(a2, a3, a4, a5); /* call via literal slot */ /* 00a6: callx8 a8 */
  a3 = MEM32(a5 + 44); /* 00a9: l32i.n a3, a5, 44 */
  a3 = (uint32_t)((uint64_t)a10 * a3); /* 00ab: mull a3, a10, a3 */
  a4 = MEM32(a4 + 0); /* 00ae: l32i.n a4, a4, 0 */
  a8 = MEM32(a5 + 432); /* 00b0: l32i a8, a5, 0x1b0 */
  a3 = a3 - a8; /* 00b3: sub a3, a3, a8 */
  a10 = MEM32(a4 + 272); /* 00b6: l32i a10, a4, 0x110 */
  ((int32_t(*)())a10)(a2, a3, a4, a5); /* 00b9: callx8 a10 */ /* indirect */
  a8 = MEM32(a5 + 104); /* 00bc: l32i a8, a5, 104 */
  if (a2 >= a3) goto L_ca; /* 00bf: bgeu a2, a3, ca <pm_get_null_max_tx_time+0xa6> */
  if (a10 >= a8) goto L_ca; /* 00c2: bgeu a10, a8, ca <pm_get_null_max_tx_time+0xa6> */
  a8 = a8 + a2; /* 00c5: add.n a8, a8, a2 */
  a2 = a8 - a10; /* 00c7: sub a2, a8, a10 */
L_ca:;
  return (int32_t)a2; /* 00ca: retw.n  */
}

/* pm_coex_pwr_update @ pm_coex.o 00000010 size 115B bind GLOBAL
 * Calls: g_osi_funcs_p[got], g_osi_funcs_p[got] | Data refs: g_pm, g_pm_cfg, g_osi_funcs_p
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 2 call(s), 3 data ref(s)
 * Fidelity: medium - 44 instr, 9 branches, calls resolved */
int32_t pm_coex_pwr_update(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .wifislprxiram.5; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_10:;
  /* 0010: entry a1, 32 */
  a8 = (uint32_t)&g_pm; /* 0013: l32r a8, 0 <pm_coex_pwr_update-0x10> (0 <pm_coex_pwr_update-0x10>) */ /* literal @0x0: g_pm */
  a9 = MEM32(a8 + 36); /* 0016: l32i.n a9, a8, 36 */
  a10 = (uint32_t)&g_pm; /* 0018: l32r a10, c <pm_coex_pwr_update-0x4> (0 <pm_coex_pwr_update-0x10>) */ /* literal @0xC: g_pm */
  if (a9 != 0) goto L_29; /* 001b: bnez.n a9, 29 <pm_coex_pwr_update+0x19> */
  MEM8(a10 + 213) = a9; /* 001d: s8i a9, a10, 213 */
  MEMW(); /* 0020: memw  */
  MEMW(); /* 0023: memw  */
  goto L_74; /* 0026: j 74 <pm_coex_pwr_update+0x64> */
L_29:;
  a11 = MEM8(a8 + 13); /* 0029: l8ui a11, a8, 13 */
  if (a11 != 0) goto L_3c; /* 002c: bnez.n a11, 3c <pm_coex_pwr_update+0x2c> */
  MEM8(a10 + 213) = a11; /* 002e: s8i a11, a10, 213 */
  MEMW(); /* 0031: memw  */
  MEMW(); /* 0034: memw  */
  goto L_74; /* 0037: j 74 <pm_coex_pwr_update+0x64> */
  /* 003a: .byte 00 */
  /* 003b: .byte 00 */
L_3c:;
  a11 = (uint32_t)&g_pm_cfg; /* 003c: l32r a11, 4 <pm_coex_pwr_update-0xc> (0 <pm_coex_pwr_update-0x10>) */ /* literal @0x4: g_pm_cfg */
  a11 = MEM8(a11 + 50); /* 003f: l8ui a11, a11, 50 */
  MEM8(a10 + 213) = a11; /* 0042: s8i a11, a10, 213 */
  MEMW(); /* 0045: memw  */
  if (a11 == 0) goto L_74; /* 0048: beqz.n a11, 74 <pm_coex_pwr_update+0x64> */
  if (a9 != 2) goto L_60; /* 004a: bnei a9, 2, 60 <pm_coex_pwr_update+0x50> */
  a9 = (uint32_t)&g_osi_funcs_p; /* 004d: l32r a9, 8 <pm_coex_pwr_update-0x8> (0 <pm_coex_pwr_update-0x10>) */ /* literal @0x8: g_osi_funcs_p */
  a9 = MEM32(a9 + 0); /* 0050: l32i.n a9, a9, 0 */
  a10 = MEM8(a8 + 32); /* 0052: l8ui a10, a8, 32 */
  a9 = MEM32(a9 + 468); /* 0055: l32i a9, a9, 0x1d4 */
  MEMW(); /* 0058: memw  */
  goto L_6e; /* 005b: j 6e <pm_coex_pwr_update+0x5e> */
  /* 005e: .byte 00 */
  /* 005f: .byte 00 */
L_60:;
  if (a9 != 1) goto L_81; /* 0060: bnei a9, 1, 81 <pm_coex_pwr_update+0x71> */
  a9 = (uint32_t)&g_osi_funcs_p; /* 0063: l32r a9, 8 <pm_coex_pwr_update-0x8> (0 <pm_coex_pwr_update-0x10>) */ /* literal @0x8: g_osi_funcs_p */
  a9 = MEM32(a9 + 0); /* 0066: l32i.n a9, a9, 0 */
  a10 = MEM8(a8 + 11); /* 0068: l8ui a10, a8, 11 */
  a9 = MEM32(a9 + 468); /* 006b: l32i a9, a9, 0x1d4 */
L_6e:;
  g_osi_funcs_p(a2, a3, a4, a5); /* call via literal slot */ /* 006e: callx8 a9 */
  goto L_81; /* 0071: j 81 <pm_coex_pwr_update+0x71> */
L_74:;
  a8 = (uint32_t)&g_osi_funcs_p; /* 0074: l32r a8, 8 <pm_coex_pwr_update-0x8> (0 <pm_coex_pwr_update-0x10>) */ /* literal @0x8: g_osi_funcs_p */
  a10 = 0x1; /* 0077: movi.n a10, 1 */
  a8 = MEM32(a8 + 0); /* 0079: l32i.n a8, a8, 0 */
  a8 = MEM32(a8 + 468); /* 007b: l32i a8, a8, 0x1d4 */
  g_osi_funcs_p(a2, a3, a4, a5); /* call via literal slot */ /* 007e: callx8 a8 */
L_81:;
  return (int32_t)a2; /* 0081: retw.n  */
}

/* pm_coex_pwr_configure @ pm_coex.o 00000008 size 23B bind GLOBAL
 * Calls: pm_coex_pwr_update | Data refs: g_pm_cfg, pm_coex_pwr_update
 *   MMIO: none
 *   funcdb v3: 1 call(s), 2 ref(s); disasm: 1 call(s), 2 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t pm_coex_pwr_configure(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pm_coex_pwr_configure; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_8:;
  /* 0008: entry a1, 32 */
  a8 = (uint32_t)&g_pm_cfg; /* 000b: l32r a8, 0 <pm_coex_pwr_configure-0x8> (0 <pm_coex_pwr_configure-0x8>) */ /* literal @0x0: g_pm_cfg */
  MEM8(a8 + 50) = a2; /* 000e: s8i a2, a8, 50 */
  MEMW(); /* 0011: memw  */
  MEMW(); /* 0014: memw  */
  a8 = (uint32_t)&pm_coex_pwr_update; /* 0017: l32r a8, 4 <pm_coex_pwr_configure-0x4> (0 <pm_coex_pwr_configure-0x8>) */ /* literal: GOT slot for pm_coex_pwr_update */
  pm_coex_pwr_update(a2, a3, a4, a5); /* call via literal slot */ /* 001a: callx8 a8 */
  return (int32_t)a2; /* 001d: retw.n  */
}

/* pm_coex_recalculate_wifi_time_slice @ pm_coex.o 00000038 size 469B bind GLOBAL
 * Calls: __umoddi3, pm_coex_schm_overall_period_get, wifi_log, g_mesh_init_ps_type[got] | Data refs: .rodata.pm_coex_recalculate_wifi_time_slice.str1.1, .rodata_wlog_error.6, __umoddi3, g_mesh_init_ps_type, g_mesh_is_root, g_mesh_is_started, g_osi_funcs_p, g_pm, g_wifi_mac_time_delta, pm_coex_schm_overall_period_get, wifi_log
 *   MMIO: 0x3FF73C00
 *   funcdb v3: 3 call(s), 11 ref(s); disasm: 6 call(s), 11 data ref(s)
 * Fidelity: low - 177 instr, 24 branches, 7 indirect; call-sequence + MMIO skeleton */
int32_t pm_coex_recalculate_wifi_time_slice(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pm_coex_recalculate_wifi_time_slice; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_38:;
  /* 0038: entry a1, 48 */
  a6 = (uint32_t)&g_osi_funcs_p; /* 003b: l32r a6, 0 <pm_coex_recalculate_wifi_time_slice-0x38> (0 <pm_coex_recalculate_wifi_time_slice-0x38>) */ /* literal @0x0: g_osi_funcs_p */
  a4 = (a4 >> 0) & 0xFF; /* 003e: extui a4, a4, 0, 8 */
  a5 = MEM32(a6 + 0); /* 0041: l32i.n a5, a6, 0 */
  a10 = MEM32(a5 + 404); /* 0043: l32i a10, a5, 0x194 */
  ((int32_t(*)())a10)(a2, a3, a4, a5); /* 0046: callx8 a10 */ /* indirect */
  if (a10 == 0) goto L_208; /* 0049: beqz a10, 208 <pm_coex_recalculate_wifi_time_slice+0x1d0> */
  a5 = (uint32_t)&g_pm; /* 004c: l32r a5, 4 <pm_coex_recalculate_wifi_time_slice-0x34> (0 <pm_coex_recalculate_wifi_time_slice-0x38>) */ /* literal @0x4: g_pm */
  if (a4 != 0) goto L_79; /* 004f: bnez.n a4, 79 <pm_coex_recalculate_wifi_time_slice+0x41> */
  a7 = 0x1; /* 0051: movi.n a7, 1 */
  a10 = MEM32(a5 + 96); /* 0053: l32i a10, a5, 96 */
  a8 = MEM32(a5 + 432); /* 0056: l32i a8, a5, 0x1b0 */
  a8 = a10 + a8; /* 0059: add.n a8, a10, a8 */
  a9 = MEM32(a5 + 100); /* 005b: l32i a9, a5, 100 */
  a11 = MEM32(a5 + 436); /* 005e: l32i a11, a5, 0x1b4 */
  if (a8 < a10) goto L_66; /* 0061: bltu a8, a10, 66 <pm_coex_recalculate_wifi_time_slice+0x2e> */
  a7 = a4; /* 0064: mov.n a7, a4 */
L_66:;
  a9 = a9 + a11; /* 0066: add.n a9, a9, a11 */
  a7 = a7 + a9; /* 0068: add.n a7, a7, a9 */
  if (a3 >= a7) goto L_70; /* 006a: bgeu a3, a7, 70 <pm_coex_recalculate_wifi_time_slice+0x38> */
  goto L_208; /* 006d: j 208 <pm_coex_recalculate_wifi_time_slice+0x1d0> */
L_70:;
  if (a7 != a3) goto L_79; /* 0070: bne a7, a3, 79 <pm_coex_recalculate_wifi_time_slice+0x41> */
  if (a2 >= a8) goto L_79; /* 0073: bgeu a2, a8, 79 <pm_coex_recalculate_wifi_time_slice+0x41> */
  goto L_208; /* 0076: j 208 <pm_coex_recalculate_wifi_time_slice+0x1d0> */
L_79:;
  a8 = (uint32_t)&pm_coex_schm_overall_period_get; /* 0079: l32r a8, 28 <pm_coex_recalculate_wifi_time_slice-0x10> (0 <pm_coex_recalculate_wifi_time_slice-0x38>) */ /* literal: GOT slot for pm_coex_schm_overall_period_get */
  pm_coex_schm_overall_period_get(a2, a3, a4, a5); /* call via literal slot */ /* 007c: callx8 a8 */
  a7 = MEM32(a6 + 0); /* 007f: l32i.n a7, a6, 0 */
  a4 = a10; /* 0081: mov.n a4, a10 */
  a10 = MEM32(a7 + 444); /* 0083: l32i a10, a7, 0x1bc */
  ((int32_t(*)())a10)(a2, a3, a4, a5); /* 0086: callx8 a10 */ /* indirect */
  a10 = (uint32_t)((uint64_t)a4 * a10); /* 0089: mull a10, a4, a10 */
  a7 = (uint32_t)&g_mesh_is_started; /* 008c: l32r a7, 8 <pm_coex_recalculate_wifi_time_slice-0x30> (0 <pm_coex_recalculate_wifi_time_slice-0x38>) */ /* literal @0x8: g_mesh_is_started */
  a10 = (a10 << 4) + a10; /* 008f: addx4 a10, a10, a10 */
  a10 = (a10 << 4) + a10; /* 0092: addx4 a10, a10, a10 */
  a4 = a10 << (2 & 31); /* 0095: slli a4, a10, 2 */
  a7 = MEM8(a7 + 0); /* 0098: l8ui a7, a7, 0 */
  if (a7 == 0) goto L_c1; /* 009b: beqz.n a7, c1 <pm_coex_recalculate_wifi_time_slice+0x89> */
  a7 = (uint32_t)&g_mesh_is_root; /* 009d: l32r a7, c <pm_coex_recalculate_wifi_time_slice-0x2c> (0 <pm_coex_recalculate_wifi_time_slice-0x38>) */ /* literal @0xC: g_mesh_is_root */
  MEMW(); /* 00a0: memw  */
  a7 = MEM8(a7 + 0); /* 00a3: l8ui a7, a7, 0 */
  a7 = (a7 >> 0) & 0xFF; /* 00a6: extui a7, a7, 0, 8 */
  if (a7 != 0) goto L_c1; /* 00a9: bnez.n a7, c1 <pm_coex_recalculate_wifi_time_slice+0x89> */
  a7 = (uint32_t)&g_mesh_init_ps_type; /* 00ab: l32r a7, 10 <pm_coex_recalculate_wifi_time_slice-0x28> (0 <pm_coex_recalculate_wifi_time_slice-0x38>) */ /* literal @0x10: g_mesh_init_ps_type */
  a7 = MEM32(a7 + 0); /* 00ae: l32i.n a7, a7, 0 */
  if (a7 == 0) goto L_c1; /* 00b0: beqz.n a7, c1 <pm_coex_recalculate_wifi_time_slice+0x89> */
  a7 = MEM32(a6 + 0); /* 00b2: l32i.n a7, a6, 0 */
  a10 = MEM32(a7 + 272); /* 00b4: l32i a10, a7, 0x110 */
  ((int32_t(*)())a10)(a2, a3, a4, a5); /* 00b7: callx8 a10 */ /* indirect */
  a7 = a10; /* 00ba: mov.n a7, a10 */
  goto L_d0; /* 00bc: j d0 <pm_coex_recalculate_wifi_time_slice+0x98> */
  /* 00bf: .byte 00 */
  /* 00c0: .byte 00 */
L_c1:;
  a7 = 0x3FF73C00; /* 00c1: l32r a7, 14 <pm_coex_recalculate_wifi_time_slice-0x24> (3ff73c00 <pm_coex_recalculate_wifi_time_slice+0x3ff73bc8>) */ /* MMIO base */ @0x14
  a8 = (uint32_t)&g_wifi_mac_time_delta; /* 00c4: l32r a8, 18 <pm_coex_recalculate_wifi_time_slice-0x20> (0 <pm_coex_recalculate_wifi_time_slice-0x38>) */ /* literal @0x18: g_wifi_mac_time_delta */
  MEMW(); /* 00c7: memw  */
  a7 = REG32(0x3FF73C00); /* 00ca: l32i.n a7, a7, 0 */ /* MMIO read: base 0x3FF73C00+0 */
  a8 = MEM32(a8 + 0); /* 00cc: l32i.n a8, a8, 0 */
  a7 = a7 + a8; /* 00ce: add.n a7, a7, a8 */
L_d0:;
  a11 = 0x1; /* 00d0: movi.n a11, 1 */
  a10 = MEM32(a5 + 80); /* 00d2: l32i a10, a5, 80 */
  a10 = a7 - a10; /* 00d5: sub a10, a7, a10 */
  a8 = MEM32(a5 + 84); /* 00d8: l32i a8, a5, 84 */
  if (a7 < a10) goto L_e0; /* 00db: bltu a7, a10, e0 <pm_coex_recalculate_wifi_time_slice+0xa8> */
  a11 = 0x0; /* 00de: movi.n a11, 0 */
L_e0:;
  a8 = -a8; /* 00e0: neg a8, a8 */
  a12 = a4; /* 00e3: mov.n a12, a4 */
  a13 = 0x0; /* 00e5: movi.n a13, 0 */
  a11 = a8 - a11; /* 00e7: sub a11, a8, a11 */
  a8 = (uint32_t)&umoddi3; /* 00ea: l32r a8, 2c <pm_coex_recalculate_wifi_time_slice-0xc> (0 <pm_coex_recalculate_wifi_time_slice-0x38>) */ /* literal: GOT slot for __umoddi3 */
  umoddi3(a2, a3, a4, a5); /* call via literal slot */ /* 00ed: callx8 a8 */
  a8 = MEM32(a6 + 0); /* 00f0: l32i.n a8, a6, 0 */
  a7 = a10; /* 00f2: mov.n a7, a10 */
  a10 = 0x0; /* 00f4: movi.n a10, 0 */
  a4 = a11; /* 00f6: mov.n a4, a11 */
  a8 = MEM32(a8 + 476); /* 00f8: l32i a8, a8, 0x1dc */
  umoddi3(a2, a3, a4, a5); /* call via literal slot */ /* 00fb: callx8 a8 */
  a8 = 0x0; /* 00fe: mov.n a8, a10 */
  if (a10 != 0) goto L_11d; /* 0100: bnez.n a10, 11d <pm_coex_recalculate_wifi_time_slice+0xe5> */
  a12 = 0x1; /* 0102: movi.n a12, 1 */
  a14 = (uint32_t)&lit_rodata_pm_coex_recalculate_wifi_time_slice_str1_1; /* 0104: l32r a14, 1c <pm_coex_recalculate_wifi_time_slice-0x1c> (0 <pm_coex_recalculate_wifi_time_slice-0x38>) */ /* literal @0x1C: .rodata.pm_coex_recalculate_wifi_time_slice.str1.1 */
  a15 = 0x59; /* 0107: movi.n a15, 89 */
  a11 = 0x1000; /* 0109: slli a11, a12, 12 */
  a10 = 0x6; /* 010c: movi a10, 6 */
  a13 = (uint32_t)&lit_rodata_wlog_error_6; /* 010f: l32r a13, 20 <pm_coex_recalculate_wifi_time_slice-0x18> (0 <pm_coex_recalculate_wifi_time_slice-0x38>) */ /* literal @0x20: .rodata_wlog_error.6 */
  a8 = (uint32_t)&wifi_log; /* 0112: l32r a8, 30 <pm_coex_recalculate_wifi_time_slice-0x8> (0 <pm_coex_recalculate_wifi_time_slice-0x38>) */ /* literal: GOT slot for wifi_log */
  wifi_log(a2, a3, a4, a5); /* call via literal slot */ /* 0115: callx8 a8 */
L_118:;
  goto L_118; /* 0118: j 118 <pm_coex_recalculate_wifi_time_slice+0xe0> */
  /* 011b: .byte 00 */
  /* 011c: .byte 00 */
L_11d:;
  a9 = MEM32(a6 + 0); /* 011d: l32i.n a9, a6, 0 */
  a7 = a2 - a7; /* 011f: sub a7, a2, a7 */
  a10 = MEM32(a9 + 448); /* 0122: l32i a10, a9, 0x1c0 */
  MEM32(a1 + 4) = a8; /* 0125: s32i.n a8, a1, 4 */
  MEMW(); /* 0127: memw  */
  ((int32_t(*)())a10)(a2, a3, a4, a5); /* 012a: callx8 a10 */ /* indirect */
  a9 = a10; /* 012d: mov.n a9, a10 */
  a10 = MEM32(a6 + 0); /* 012f: l32i.n a10, a6, 0 */
  a10 = MEM32(a10 + 444); /* 0131: l32i a10, a10, 0x1bc */
  MEM32(a1 + 0) = a9; /* 0134: s32i.n a9, a1, 0 */
  MEMW(); /* 0136: memw  */
  ((int32_t(*)())a10)(a2, a3, a4, a5); /* 0139: callx8 a10 */ /* indirect */
  a8 = MEM32(a1 + 4); /* 013c: l32i.n a8, a1, 4 */
  a8 = MEM8(a8 + 0); /* 013e: l8ui a8, a8, 0 */
  a8 = (uint32_t)((uint64_t)a8 * a10); /* 0141: mull a8, a8, a10 */
  a9 = MEM32(a1 + 0); /* 0144: l32i.n a9, a1, 0 */
  a8 = (uint32_t)((uint64_t)a8 * a9); /* 0146: mull a8, a8, a9 */
  a9 = 0x1; /* 0149: movi.n a9, 1 */
  if (a2 < a7) goto L_151; /* 014b: bltu a2, a7, 151 <pm_coex_recalculate_wifi_time_slice+0x119> */
  a9 = 0x0; /* 014e: movi a9, 0 */
L_151:;
  a4 = a3 - a4; /* 0151: sub a4, a3, a4 */
  a4 = a4 - a9; /* 0154: sub a4, a4, a9 */
  a9 = a7 + a8; /* 0157: add.n a9, a7, a8 */
  a11 = 0x1; /* 0159: movi a11, 1 */
  if (a9 < a7) goto L_162; /* 015c: bltu a9, a7, 162 <pm_coex_recalculate_wifi_time_slice+0x12a> */
  a11 = 0x0; /* 015f: movi a11, 0 */
L_162:;
  a11 = a11 + a4; /* 0162: add.n a11, a11, a4 */
  a7 = MEM8(a5 + 13); /* 0164: l8ui a7, a5, 13 */
  a4 = 0x3E8; /* 0167: movi a4, 0x3e8 */
  MEM32(a5 + 96) = a9; /* 016a: s32i a9, a5, 96 */
  MEM32(a5 + 100) = a11; /* 016d: s32i a11, a5, 100 */
  if (a7 == 0) goto L_174; /* 0170: beqz.n a7, 174 <pm_coex_recalculate_wifi_time_slice+0x13c> */
  a4 = MEM32(a5 + 56); /* 0172: l32i.n a4, a5, 56 */
L_174:;
  a4 = a9 - a4; /* 0174: sub a4, a9, a4 */
  a7 = 0x1; /* 0177: movi a7, 1 */
  if (a9 < a4) goto L_180; /* 017a: bltu a9, a4, 180 <pm_coex_recalculate_wifi_time_slice+0x148> */
  a7 = 0x0; /* 017d: movi a7, 0 */
L_180:;
  a11 = a11 - a7; /* 0180: sub a11, a11, a7 */
  MEM32(a5 + 104) = a4; /* 0183: s32i a4, a5, 104 */
  MEM32(a5 + 108) = a11; /* 0186: s32i a11, a5, 108 */
  MEM32(a1 + 4) = a8; /* 0189: s32i.n a8, a1, 4 */
  MEMW(); /* 018b: memw  */
  a8 = (uint32_t)&pm_coex_schm_overall_period_get; /* 018e: l32r a8, 34 <pm_coex_recalculate_wifi_time_slice-0x4> (0 <pm_coex_recalculate_wifi_time_slice-0x38>) */ /* literal: GOT slot for pm_coex_schm_overall_period_get */
  pm_coex_schm_overall_period_get(a2, a3, a4, a5); /* call via literal slot */ /* 0191: callx8 a8 */
  a4 = a10 | a10; /* 0194: or a4, a10, a10 */
  a7 = MEM32(a6 + 0); /* 0197: l32i a7, a6, 0 */
  a10 = MEM32(a7 + 444); /* 019a: l32i a10, a7, 0x1bc */
  ((int32_t(*)())a10)(a2, a3, a4, a5); /* 019d: callx8 a10 */ /* indirect */
  a10 = (uint32_t)((uint64_t)a4 * a10); /* 01a0: mull a10, a4, a10 */
  a4 = 0x1; /* 01a3: movi.n a4, 1 */
  a8 = MEM32(a1 + 4); /* 01a5: l32i.n a8, a1, 4 */
  a10 = (a10 << 4) + a10; /* 01a7: addx4 a10, a10, a10 */
  a10 = (a10 << 4) + a10; /* 01aa: addx4 a10, a10, a10 */
  a7 = a10 << (2 & 31); /* 01ad: slli a7, a10, 2 */
  a10 = a8 - (a10 << 4) /* verify order vs disasm */; /* 01b0: subx4 a10, a10, a8 */
  if (a7 < a10) goto L_1b8; /* 01b3: bltu a7, a10, 1b8 <pm_coex_recalculate_wifi_time_slice+0x180> */
  a4 = 0x0; /* 01b6: movi.n a4, 0 */
L_1b8:;
  a7 = MEM32(a6 + 0); /* 01b8: l32i.n a7, a6, 0 */
  a4 = 0x0; /* 01ba: neg a4, a4 */
  MEM32(a5 + 436) = a4; /* 01bd: s32i a4, a5, 0x1b4 */
  a4 = (uint32_t)&g_pm; /* 01c0: l32r a4, 24 <pm_coex_recalculate_wifi_time_slice-0x14> (0 <pm_coex_recalculate_wifi_time_slice-0x38>) */ /* literal @0x24: g_pm */
  a7 = MEM32(a7 + 236); /* 01c3: l32i a7, a7, 236 */
  MEM32(a5 + 432) = a10; /* 01c6: s32i a10, a5, 0x1b0 */
  a10 = a4; /* 01c9: mov.n a10, a4 */
  MEMW(); /* 01cb: memw  */
  ((int32_t(*)())a7)(a2, a3, a4, a5); /* 01ce: callx8 a7 */ /* indirect */
  a7 = MEM32(a5 + 108); /* 01d1: l32i a7, a5, 108 */
  a11 = MEM32(a5 + 104); /* 01d4: l32i a11, a5, 104 */
  if (a3 < a7) goto L_1e0; /* 01d7: bltu a3, a7, 1e0 <pm_coex_recalculate_wifi_time_slice+0x1a8> */
  if (a7 != a3) goto L_200; /* 01da: bne a7, a3, 200 <pm_coex_recalculate_wifi_time_slice+0x1c8> */
  if (a2 >= a11) goto L_200; /* 01dd: bgeu a2, a11, 200 <pm_coex_recalculate_wifi_time_slice+0x1c8> */
L_1e0:;
  a3 = 0x1; /* 01e0: movi.n a3, 1 */
  MEM8(a5 + 24) = a3; /* 01e2: s8i a3, a5, 24 */
  MEMW(); /* 01e5: memw  */
  a12 = 0x0; /* 01e8: movi.n a12, 0 */
  a11 = a11 - a2; /* 01ea: sub a11, a11, a2 */
  a10 = a4 | a4; /* 01ed: or a10, a4, a4 */
  a3 = MEM32(a6 + 0); /* 01f0: l32i a3, a6, 0 */
  a3 = MEM32(a3 + 248); /* 01f3: l32i a3, a3, 248 */
  MEMW(); /* 01f6: memw  */
  ((int32_t(*)())a3)(a2, a3, a4, a5); /* 01f9: callx8 a3 */ /* indirect */
  goto L_208; /* 01fc: j 208 <pm_coex_recalculate_wifi_time_slice+0x1d0> */
  /* 01ff: .byte 00 */
L_200:;
  a2 = 0x0; /* 0200: movi.n a2, 0 */
  MEM8(a5 + 24) = a2; /* 0202: s8i a2, a5, 24 */
  MEMW(); /* 0205: memw  */
L_208:;
  MEMW(); /* 0208: memw  */
  return (int32_t)a2; /* 020b: retw.n  */
}

/* pm_coex_update_wifi_time_slice_state @ pm_coex.o 00000010 size 148B bind GLOBAL
 * Calls: pm_coex_recalculate_wifi_time_slice | Data refs: g_osi_funcs_p, g_pm, pm_coex_recalculate_wifi_time_slice
 *   MMIO: none
 *   funcdb v3: 1 call(s), 3 ref(s); disasm: 1 call(s), 3 data ref(s)
 * Fidelity: medium - 53 instr, 14 branches, 3 indirect; flow + direct calls mapped, GOT-indirects enumerated */
int32_t pm_coex_update_wifi_time_slice_state(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pm_coex_update_wifi_time_slice_state; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_10:;
  /* 0010: entry a1, 32 */
  a12 = (a4 >> 0) & 0xFF; /* 0013: extui a12, a4, 0, 8 */
  a10 = a2; /* 0016: mov.n a10, a2 */
  a11 = a3 | a3; /* 0018: or a11, a3, a3 */
  a8 = (uint32_t)&pm_coex_recalculate_wifi_time_slice; /* 001b: l32r a8, c <pm_coex_update_wifi_time_slice_state-0x4> (0 <pm_coex_update_wifi_time_slice_state-0x10>) */ /* literal: GOT slot for pm_coex_recalculate_wifi_time_slice */
  pm_coex_recalculate_wifi_time_slice(a2, a3, a4, a5); /* call via literal slot */ /* 001e: callx8 a8 */
  a4 = (uint32_t)&g_osi_funcs_p; /* 0021: l32r a4, 0 <pm_coex_update_wifi_time_slice_state-0x10> (0 <pm_coex_update_wifi_time_slice_state-0x10>) */ /* literal @0x0: g_osi_funcs_p */
  a8 = MEM32(a4 + 0); /* 0024: l32i.n a8, a4, 0 */
  a10 = MEM32(a8 + 404); /* 0026: l32i a10, a8, 0x194 */
  ((int32_t(*)())a10)(a2, a3, a4, a5); /* 0029: callx8 a10 */ /* indirect */
  a8 = (uint32_t)&g_pm; /* 002c: l32r a8, 4 <pm_coex_update_wifi_time_slice_state-0xc> (0 <pm_coex_update_wifi_time_slice_state-0x10>) */ /* literal @0x4: g_pm */
  if (a10 == 0) goto L_82; /* 002f: beqz a10, 82 <pm_coex_update_wifi_time_slice_state+0x72> */
  a9 = MEM32(a8 + 108); /* 0032: l32i a9, a8, 108 */
  a10 = MEM32(a8 + 104); /* 0035: l32i a10, a8, 104 */
  if (a3 < a9) goto L_41; /* 0038: bltu a3, a9, 41 <pm_coex_update_wifi_time_slice_state+0x31> */
  if (a9 != a3) goto L_98; /* 003b: bne a9, a3, 98 <pm_coex_update_wifi_time_slice_state+0x88> */
  if (a2 >= a10) goto L_98; /* 003e: bgeu a2, a10, 98 <pm_coex_update_wifi_time_slice_state+0x88> */
L_41:;
  a11 = a10 - a2; /* 0041: sub a11, a10, a2 */
  a12 = 0x1; /* 0044: movi a12, 1 */
  if (a10 < a11) goto L_4d; /* 0047: bltu a10, a11, 4d <pm_coex_update_wifi_time_slice_state+0x3d> */
  a12 = 0x0; /* 004a: movi a12, 0 */
L_4d:;
  a9 = a9 - a3; /* 004d: sub a9, a9, a3 */
  if (a9 != a12) goto L_59; /* 0050: bne a9, a12, 59 <pm_coex_update_wifi_time_slice_state+0x49> */
  a3 = 0x1387; /* 0053: l32r a3, 8 <pm_coex_update_wifi_time_slice_state-0x8> (1387 <pm_coex_recalculate_wifi_time_slice+0x134f>) */ @0x8
  if (a3 >= a11) goto L_98; /* 0056: bgeu a3, a11, 98 <pm_coex_update_wifi_time_slice_state+0x88> */
L_59:;
  a3 = a8 + ((0x200) << 8); /* 0059: addmi a3, a8, 0x200 */
  a3 = MEM8(a3 + 31); /* 005c: l8ui a3, a3, 31 */
  if (a3 == 0) goto L_82; /* 005f: beqz.n a3, 82 <pm_coex_update_wifi_time_slice_state+0x72> */
  a11 = MEM32(a8 + 572); /* 0061: l32i a11, a8, 0x23c */
  a3 = MEM32(a8 + 568); /* 0064: l32i a3, a8, 0x238 */
  if (a11 != 0) goto L_6d; /* 0067: bnez a11, 6d <pm_coex_update_wifi_time_slice_state+0x5d> */
  if (a2 >= a3) goto L_98; /* 006a: bgeu a2, a3, 98 <pm_coex_update_wifi_time_slice_state+0x88> */
L_6d:;
  a9 = a3 - a2; /* 006d: sub a9, a3, a2 */
  a10 = 0x1; /* 0070: movi a10, 1 */
  if (a3 < a9) goto L_79; /* 0073: bltu a3, a9, 79 <pm_coex_update_wifi_time_slice_state+0x69> */
  a10 = 0x0; /* 0076: movi a10, 0 */
L_79:;
  if (a11 != a10) goto L_82; /* 0079: bne a11, a10, 82 <pm_coex_update_wifi_time_slice_state+0x72> */
  a3 = 0x1387; /* 007c: l32r a3, 8 <pm_coex_update_wifi_time_slice_state-0x8> (1387 <pm_coex_recalculate_wifi_time_slice+0x134f>) */ @0x8
  if (a3 >= a9) goto L_98; /* 007f: bgeu a3, a9, 98 <pm_coex_update_wifi_time_slice_state+0x88> */
L_82:;
  a11 = 0x0; /* 0082: movi.n a11, 0 */
  a10 = 0x1; /* 0084: movi.n a10, 1 */
  a3 = MEM32(a4 + 0); /* 0086: l32i.n a3, a4, 0 */
  a12 = MEM32(a8 + 96); /* 0088: l32i a12, a8, 96 */
  a12 = a12 - a2; /* 008b: sub a12, a12, a2 */
  a3 = MEM32(a3 + 412); /* 008e: l32i a3, a3, 0x19c */
  ((int32_t(*)())a3)(a2, a3, a4, a5); /* 0091: callx8 a3 */ /* indirect */
  goto L_a2; /* 0094: j a2 <pm_coex_update_wifi_time_slice_state+0x92> */
  /* 0097: .byte 00 */
L_98:;
  a2 = MEM32(a4 + 0); /* 0098: l32i.n a2, a4, 0 */
  a10 = 0x1; /* 009a: movi.n a10, 1 */
  a2 = MEM32(a2 + 416); /* 009c: l32i a2, a2, 0x1a0 */
  ((int32_t(*)())a2)(a2, a3, a4, a5); /* 009f: callx8 a2 */ /* indirect */
L_a2:;
  return (int32_t)a2; /* 00a2: retw.n  */
}

/* pm_coex_customized_wifi_time_slice @ pm_coex.o 0000000c size 118B bind GLOBAL
 * Calls: g_pm[got] | Data refs: g_osi_funcs_p, g_pm
 *   MMIO: none
 *   funcdb v3: 0 call(s), 2 ref(s); disasm: 1 call(s), 2 data ref(s)
 * Fidelity: medium - 45 instr, 3 branches, calls resolved */
int32_t pm_coex_customized_wifi_time_slice(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pm_coex_customized_wifi_time_slice; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_c:;
  /* 000c: entry a1, 32 */
  a6 = (uint32_t)&g_pm; /* 000f: l32r a6, 0 <pm_coex_customized_wifi_time_slice-0xc> (0 <pm_coex_customized_wifi_time_slice-0xc>) */ /* literal @0x0: g_pm */
  a8 = 0x1; /* 0012: movi.n a8, 1 */
  a10 = a2 + a4; /* 0014: add.n a10, a2, a4 */
  MEM8(a6 + 24) = a8; /* 0016: s8i a8, a6, 24 */
  MEMW(); /* 0019: memw  */
  a8 = 0x1; /* 001c: movi.n a8, 1 */
  if (a10 < a2) goto L_24; /* 001e: bltu a10, a2, 24 <pm_coex_customized_wifi_time_slice+0x18> */
  a8 = 0x0; /* 0021: movi a8, 0 */
L_24:;
  a3 = a3 + a5; /* 0024: add.n a3, a3, a5 */
  a8 = a8 + a3; /* 0026: add.n a8, a8, a3 */
  a3 = MEM8(a6 + 13); /* 0028: l8ui a3, a6, 13 */
  a9 = 0x3E8; /* 002b: movi a9, 0x3e8 */
  MEM32(a6 + 96) = a10; /* 002e: s32i a10, a6, 96 */
  MEM32(a6 + 100) = a8; /* 0031: s32i a8, a6, 100 */
  if (a3 == 0) goto L_38; /* 0034: beqz.n a3, 38 <pm_coex_customized_wifi_time_slice+0x2c> */
  a9 = MEM32(a6 + 56); /* 0036: l32i.n a9, a6, 56 */
L_38:;
  a9 = a10 - a9; /* 0038: sub a9, a10, a9 */
  a3 = 0x1; /* 003b: movi a3, 1 */
  if (a10 < a9) goto L_44; /* 003e: bltu a10, a9, 44 <pm_coex_customized_wifi_time_slice+0x38> */
  a3 = 0x0; /* 0041: movi a3, 0 */
L_44:;
  a8 = a8 - a3; /* 0044: sub a8, a8, a3 */
  a3 = (uint32_t)&g_osi_funcs_p; /* 0047: l32r a3, 8 <pm_coex_customized_wifi_time_slice-0x4> (0 <pm_coex_customized_wifi_time_slice-0xc>) */ /* literal @0x8: g_osi_funcs_p */
  MEM32(a6 + 108) = a8; /* 004a: s32i a8, a6, 108 */
  a8 = MEM32(a3 + 0); /* 004d: l32i.n a8, a3, 0 */
  a5 = (uint32_t)&g_pm; /* 004f: l32r a5, 4 <pm_coex_customized_wifi_time_slice-0x8> (0 <pm_coex_customized_wifi_time_slice-0xc>) */ /* literal @0x4: g_pm */
  a10 = a5; /* 0052: mov.n a10, a5 */
  a8 = MEM32(a8 + 236); /* 0054: l32i a8, a8, 236 */
  MEM32(a6 + 104) = a9; /* 0057: s32i a9, a6, 104 */
  MEMW(); /* 005a: memw  */
  ((int32_t(*)())a8)(a2, a3, a4, a5); /* 005d: callx8 a8 */ /* indirect */
  a10 = a5; /* 0060: mov.n a10, a5 */
  a12 = 0x0; /* 0062: movi.n a12, 0 */
  a11 = MEM32(a6 + 104); /* 0064: l32i a11, a6, 104 */
  a11 = a11 - a2; /* 0067: sub a11, a11, a2 */
  a6 = MEM32(a3 + 0); /* 006a: l32i.n a6, a3, 0 */
  a6 = MEM32(a6 + 248); /* 006c: l32i a6, a6, 248 */
  g_pm(a2, a3, a4, a5); /* call via literal slot */ /* 006f: callx8 a6 */
  a12 = a4; /* 0072: mov.n a12, a4 */
  a11 = 0x0; /* 0074: movi.n a11, 0 */
  a2 = MEM32(a3 + 0); /* 0076: l32i.n a2, a3, 0 */
  a10 = 0x1; /* 0078: movi.n a10, 1 */
  a2 = MEM32(a2 + 412); /* 007a: l32i a2, a2, 0x19c */
  ((int32_t(*)())a2)(a2, a3, a4, a5); /* 007d: callx8 a2 */ /* indirect */
  return (int32_t)a2; /* 0080: retw.n  */
}

