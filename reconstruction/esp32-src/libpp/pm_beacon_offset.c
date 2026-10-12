/* ===== pm_beacon_offset.o : reconstructed from libpp.a (ESP32, Xtensa, esp-2022r1) =====
 * Toolchain: xtensa-esp32-elf (GCC 11.2.0 crosstool-NG esp-2022r1).
 * ABI: args a2..a7, return a2 (all functions take a2..a7, return int32_t).
 * memw barriers preserved as MEMW(). MMIO as REG32/REG16/REG8(addr).
 * Calls with unknown arg counts are modeled with 4 live args (a2..a5);
 * a2..a7 are clobbered across calls (windowed-ABI approximation).
 * Sections: .text.empty_func_p_pconfg_r_void, .text.empty_func_p_ptsf_u32_r_void, .text.empty_func_p_pvoid_r_void, .text.empty_func_p_u32_r_void, .text.empty_func_p_u8_r_void, .text.empty_func_p_u8_u8_float_float_pparams_r_void, .text.empty_func_p_u8_u8_pu16_pfloat_r_void, .text.empty_func_p_void_r_bool, .text.empty_func_p_void_r_float, .text.empty_func_p_void_r_void, .text.pm_beacon_offset_add_loss_counter, .text.pm_beacon_offset_add_total_counter, .text.pm_beacon_offset_check, .text.pm_beacon_offset_configure, .text.pm_beacon_offset_deinit, .text.pm_beacon_offset_funcs_empty_init, .text.pm_beacon_offset_funcs_init, .text.pm_beacon_offset_get_rx_beacon_success_rate, .text.pm_beacon_offset_init, .text.pm_beacon_offset_resample_timeout, .text.pm_beacon_offset_resample_timeout_process, .text.pm_beacon_offset_set_rx_beacon_standard, .text.pm_funcs_deinit, .text.pm_funcs_init, .wifislpiram.11, .wifislpiram.12, .wifislpiram.2, .wifislpiram.3, .wifislpiram.4, .wifislpiram.9, .wifislprxiram.10, .wifislprxiram.6
 * Undefined refs (21): __adddf3, __divsf3, __extendsfdf2, __floatsidf, __floatunsidf, __muldf3, __subdf3, __truncdfsf2, g_mesh_init_ps_type, g_mesh_is_root, g_mesh_is_started, g_osi_funcs_p, g_pm, g_pm_cfg, g_wifi_mac_time_delta, memcpy, memset, pm_on_sample_beacon, pp_timer_process, wifi_event_post, wifi_log
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
extern int32_t divsf3();
extern int32_t extendsfdf2();
extern int32_t muldf3();
extern int32_t truncdfsf2();
uint32_t s_pm_beacon_offset; /* defined here (.bss/.data); was: s_pm_beacon_offset */
extern int32_t floatsidf();
extern int32_t adddf3();
extern int32_t subdf3();
uint32_t s_pm_beacon_offset_config; /* defined here (.bss/.data); was: s_pm_beacon_offset_config */
extern uint32_t rodata_wlog_error_5; /* .rodata_wlog_error.5 */
extern int32_t wifi_log();
extern int32_t memset();
extern int32_t floatunsidf();
extern int32_t memcpy();
extern uint32_t g_pm_cfg; /* g_pm_cfg */
extern int32_t g_osi_funcs_p();
extern uint32_t bss_prev_last_tbtt_time_1; /* .bss.prev_last_tbtt_time$1 (verify defined-here with nm) */
extern uint32_t g_mesh_is_started; /* g_mesh_is_started */
extern uint32_t g_mesh_is_root; /* g_mesh_is_root */
extern uint32_t g_mesh_init_ps_type; /* g_mesh_init_ps_type */
extern uint32_t g_wifi_mac_time_delta; /* g_wifi_mac_time_delta */
extern uint32_t bss_total_tbtt_count_0; /* .bss.total_tbtt_count$0 (verify defined-here with nm) */
extern uint32_t rodata_wlog_info_13; /* .rodata_wlog_info.13 */
extern uint32_t rodata_wlog_info_14; /* .rodata_wlog_info.14 */
extern uint32_t rodata_wlog_info_7; /* .rodata_wlog_info.7 */
extern uint32_t rodata_wlog_error_8; /* .rodata_wlog_error.8 */
extern int32_t pm_on_sample_beacon();
extern int32_t wifi_event_post();
extern uint32_t rodata_wlog_debug_15; /* .rodata_wlog_debug.15 */
extern uint32_t rodata_wlog_debug_16; /* .rodata_wlog_debug.16 */
extern uint32_t rodata_pm_beacon_offset_check_str1_1; /* .rodata.pm_beacon_offset_check.str1.1 */
extern uint32_t rodata_wlog_info_17; /* .rodata_wlog_info.17 */
extern uint32_t rodata_wlog_debug_18; /* .rodata_wlog_debug.18 */
extern int32_t pp_timer_process();
uint32_t ptr_beacon_offset_funcs; /* defined here (.bss/.data); was: ptr_beacon_offset_funcs */
extern uint32_t rodata_wlog_error_20; /* .rodata_wlog_error.20 */

/* pool[pm_beacon_offset_get_average]: +0x4=0x00000000(g_pm), +0x8=0x447A0000, +0x20=0x00000000(__divsf3), +0x24=0x00000000(__extendsfdf2), +0xc=0xD2F1A9FC, +0x10=0x3FF0624D, +0x28=0x00000000(__muldf3), +0x2c=0x00000000(__truncdfsf2), +0x0=0x00000000, +0x14=0x00000000(s_pm_beacon_offset), +0x30=0x00000000(__floatsidf), +0x18=0x00000000, +0x1c=0x3FE00000, +0x34=0x00000000(__adddf3), +0x38=0x00000000(__muldf3), +0x3c=0x00000000(__extendsfdf2), +0x40=0x00000000(__adddf3), +0x44=0x00000000(__truncdfsf2), +0x48=0x00000000(__divsf3), +0x4c=0x00000000(__extendsfdf2), +0x50=0x00000000(__floatsidf), +0x54=0x00000000(__muldf3), +0x58=0x00000000(__subdf3), +0x5c=0x00000000(__truncdfsf2) */
/* pool[pm_beacon_offset_get_expect]: +0x4=0x00000000, +0x1c=0x00000000(pm_beacon_offset_get_average), +0x8=0x00000000(s_pm_beacon_offset_config), +0x20=0x00000000(__divsf3), +0x0=0x3F800000, +0xc=0x00000000(g_pm), +0x10=0x447A0000, +0x24=0x00000000(__divsf3), +0x28=0x00000000(__extendsfdf2), +0x2c=0x00000000(__extendsfdf2), +0x14=0xD2F1A9FC, +0x18=0x3FF0624D, +0x30=0x00000000(__muldf3), +0x34=0x00000000(__adddf3), +0x38=0x00000000(__truncdfsf2), +0x3c=0x00000000(__extendsfdf2), +0x40=0x00000000(__muldf3), +0x44=0x00000000(__truncdfsf2), +0x48=0x00000000(__divsf3), +0x4c=0x00000000(__divsf3) */
/* pool[pm_beacon_offset_is_sampling]: +0x0=0x00000000(s_pm_beacon_offset) */
/* pool[pm_beacon_offset_is_enabled]: +0x0=0x00000000(s_pm_beacon_offset_config) */
/* pool[pm_beacon_offset_get_rx_beacon_success_rate]: +0x0=0x00000000(s_pm_beacon_offset), +0x4=0x00000000(__divsf3) */
/* pool[pm_beacon_offset_add_total_counter]: +0x0=0x00000000(s_pm_beacon_offset) */
/* pool[pm_beacon_offset_add_loss_counter]: +0x0=0x00000000(s_pm_beacon_offset) */
/* pool[empty_func_p_void_r_float]: +0x0=0x00000000 */
/* pool[pm_beacon_offset_get_params]: +0x4=0x00000000(g_pm), +0x0=0x00000000, +0x30=0x00000000(pm_beacon_offset_get_average), +0x8=0x00000000(s_pm_beacon_offset_config), +0xc=0x00000000(.rodata_wlog_error.5), +0x34=0x00000000(wifi_log), +0x38=0x00000000(memset), +0x3c=0x00000000(__divsf3), +0x40=0x00000000(__floatunsidf), +0x10=0xD2F1A9FC, +0x14=0x3FF0624D, +0x44=0x00000000(__muldf3), +0x48=0x00000000(__truncdfsf2), +0x4c=0x00000000(__divsf3), +0x50=0x00000000(memcpy), +0x54=0x00000000(pm_beacon_offset_get_expect), +0x58=0x00000000(memcpy), +0x18=0x00000000(s_pm_beacon_offset), +0x1c=0x42C80000, +0x20=0x00000000(g_pm_cfg), +0x2c=0x00000000(g_osi_funcs_p), +0x24=0x0036EE80, +0x28=0x00000000(s_pm_beacon_offset+0x10), +0x5c=0x00000000(memcpy) */
/* pool[pm_beacon_offset_sample]: +0x0=0x00000000(s_pm_beacon_offset), +0x4=0x00000000(g_pm), +0x8=0x00000000(.bss.prev_last_tbtt_time$1), +0xc=0x00000000(g_mesh_is_started), +0x10=0x00000000(g_mesh_is_root), +0x14=0x00000000(g_mesh_init_ps_type), +0x18=0x00000000(g_osi_funcs_p), +0x1c=0x3FF73C00, +0x20=0x00000000(g_wifi_mac_time_delta), +0x24=0x00000000(.bss.total_tbtt_count$0), +0x28=0x00000000(pm_beacon_offset_get_params) */
/* pool[pm_beacon_offset_configure]: +0x0=0x00000000(s_pm_beacon_offset_config), +0x8=0x42C80000, +0xc=0x00000000(__divsf3), +0x10=0x00000000(__extendsfdf2), +0x14=0x00000000(__divsf3), +0x18=0x00000000(__extendsfdf2), +0x4=0x00000000(.rodata_wlog_info.13), +0x1c=0x00000000(wifi_log) */
/* pool[pm_beacon_offset_set_rx_beacon_standard]: +0x0=0x00000000(s_pm_beacon_offset_config), +0x4=0x42C80000, +0xc=0x00000000(__divsf3), +0x10=0x00000000(__extendsfdf2), +0x14=0x00000000(__divsf3), +0x18=0x00000000(__extendsfdf2), +0x8=0x00000000(.rodata_wlog_info.14), +0x1c=0x00000000(wifi_log) */
/* pool[pm_beacon_offset_reset]: +0x0=0x00000000(s_pm_beacon_offset), +0x8=0x00000000(g_pm_cfg), +0x4=0x00000000(g_pm), +0xc=0x00000000(g_osi_funcs_p), +0x10=0x00000000(s_pm_beacon_offset+0x28), +0x14=0x00000000(memset) */
/* pool[pm_beacon_offset_init]: +0xc=0x00000000(pm_beacon_offset_reset), +0x8=0x00000000(g_osi_funcs_p), +0x0=0x00000004(.text.pm_beacon_offset_resample_timeout), +0x4=0x00000000(s_pm_beacon_offset+0x10) */
/* pool[pm_beacon_offset_deinit]: +0x4=0x00000000(g_osi_funcs_p), +0x0=0x00000000(s_pm_beacon_offset+0x10), +0x8=0x00000000(pm_beacon_offset_reset) */
/* pool[pm_beacon_offset_sample_start]: +0x0=0x00000000(s_pm_beacon_offset), +0x4=0x00000000(s_pm_beacon_offset_config), +0x1c=0x00000000(pm_beacon_offset_reset), +0x8=0x00000000(g_pm), +0xc=0x00000000(.rodata_wlog_info.7), +0x20=0x00000000(wifi_log), +0x10=0x00000000(g_osi_funcs_p), +0x14=0x00000000(.rodata_wlog_error.8), +0x24=0x00000000(memset), +0x18=0x00000000(s_pm_beacon_offset+0x10) */
/* pool[pm_beacon_offset_resample_timeout_process]: +0x0=0x00000000(pm_on_sample_beacon) */
/* pool[pm_beacon_offset_check]: +0x8=0x00000000(s_pm_beacon_offset_config), +0xc=0x00000000(s_pm_beacon_offset), +0x10=0x00000000(g_pm), +0x2c=0x00000000(pm_beacon_offset_get_rx_beacon_success_rate), +0x14=0x3F000000, +0x30=0x00000000(wifi_event_post), +0x18=0x42C80000, +0x34=0x00000000(__divsf3), +0x38=0x00000000(__extendsfdf2), +0x1c=0x00000000(.rodata_wlog_debug.15), +0x3c=0x00000000(wifi_log), +0x20=0x00000000(.rodata_wlog_debug.16), +0x40=0x00000000(wifi_log), +0x0=0x00000000(.rodata.pm_beacon_offset_check.str1.1), +0x4=0x00000009(.rodata.pm_beacon_offset_check.str1.1), +0x44=0x00000000(__extendsfdf2), +0x48=0x00000000(__extendsfdf2), +0x24=0x00000000(.rodata_wlog_info.17), +0x4c=0x00000000(wifi_log), +0x50=0x00000000(__extendsfdf2), +0x54=0x00000000(__extendsfdf2), +0x58=0x00000000(__extendsfdf2), +0x28=0x00000000(.rodata_wlog_debug.18), +0x5c=0x00000000(wifi_log) */
/* pool[pm_beacon_offset_resample_timeout]: +0x0=0x00000000 */
/* pool[pm_beacon_offset_funcs_init]: +0x0=0x00000000(ptr_beacon_offset_funcs), +0x4=0x00000000(pm_beacon_offset_sample_start), +0x8=0x00000000(pm_beacon_offset_sample), +0xc=0x00000000(pm_beacon_offset_reset), +0x10=0x00000000(pm_beacon_offset_is_sampling), +0x14=0x00000000(pm_beacon_offset_is_enabled), +0x18=0x00000000(pm_beacon_offset_configure), +0x1c=0x00000000(pm_beacon_offset_resample_timeout_process), +0x20=0x00000000(pm_beacon_offset_set_rx_beacon_standard), +0x24=0x00000000(pm_beacon_offset_get_rx_beacon_success_rate), +0x28=0x00000000(pm_beacon_offset_add_total_counter), +0x2c=0x00000000(pm_beacon_offset_add_loss_counter), +0x30=0x00000000(pm_beacon_offset_check), +0x34=0x00000000(pm_beacon_offset_init), +0x38=0x00000000(pm_beacon_offset_deinit), +0x3c=0x00000000(pm_beacon_offset_get_average), +0x40=0x00000000(pm_beacon_offset_get_expect), +0x44=0x00000000(pm_beacon_offset_get_params) */
/* pool[pm_beacon_offset_funcs_empty_init]: +0x0=0x00000000(ptr_beacon_offset_funcs), +0xc=0x00000000(empty_func_p_void_r_bool), +0x10=0x00000000(empty_func_p_pconfg_r_void), +0x14=0x00000000(empty_func_p_pvoid_r_void), +0x4=0x00000000(empty_func_p_void_r_void), +0x18=0x00000000(empty_func_p_u8_r_void), +0x1c=0x00000000(empty_func_p_void_r_float), +0x24=0x00000000(empty_func_p_u8_u8_pu16_pfloat_r_void), +0x8=0x00000000(empty_func_p_u32_r_void), +0x20=0x00000000(empty_func_p_ptsf_u32_r_void), +0x28=0x00000000(empty_func_p_u8_u8_float_float_pparams_r_void) */
/* pool[pm_funcs_init]: +0x0=0x00000000(g_osi_funcs_p), +0x4=0x00000000(ptr_beacon_offset_funcs), +0x8=0x00000000(.rodata_wlog_error.20), +0xc=0x00000000(wifi_log), +0x10=0x00000000(pm_beacon_offset_funcs_init) */
/* pool[pm_funcs_deinit]: +0x0=0x00000000(ptr_beacon_offset_funcs), +0x4=0x00000000(g_osi_funcs_p) */

/* pm_beacon_offset_get_average @ pm_beacon_offset.o 00000060 size 317B bind GLOBAL
 * Calls: __divsf3[got], __extendsfdf2[got], __muldf3[got], __truncdfsf2[got], __floatsidf[got], __adddf3[got], __muldf3[got], __extendsfdf2[got], __adddf3[got], __truncdfsf2[got], __divsf3[got], __extendsfdf2[got], __floatsidf[got], __muldf3[got], __subdf3[got], __truncdfsf2[got] | Data refs: g_pm, __divsf3, __extendsfdf2, __muldf3, __truncdfsf2, s_pm_beacon_offset, __floatsidf, __adddf3, __subdf3
 *   MMIO: none
 *   FP/data literals (loaded, never dereferenced - NOT MMIO): 0x3FF0624D, 0x3FE00000
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 16 call(s), 9 data ref(s)
 * Fidelity: medium - 117 instr, 6 branches, calls resolved */
int32_t pm_beacon_offset_get_average(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .wifislpiram.2; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_60:;
  /* 0060: entry a1, 64 */
  a7 = (uint32_t)&g_pm; /* 0063: l32r a7, 4 <pm_beacon_offset_get_average-0x5c> (0 <pm_beacon_offset_get_average-0x60>) */ /* literal @0x4: g_pm */
  a6 = (a3 >> 0) & 0xFF; /* 0066: extui a6, a3, 0, 8 */
  a2 = (a2 >> 0) & 0xFF; /* 0069: extui a2, a2, 0, 8 */
  a3 = MEM32(a7 + 464); /* 006c: l32i a3, a7, 0x1d0 */
  /* 006f: ufloat.s f0, a3, 0 */
  /* 0072: rfr a10, f0 */ /* UNMODELED: a10 clobbered */
  a11 = 0x447A0000; /* 0075: l32r a11, 8 <pm_beacon_offset_get_average-0x58> (447a0000 <pm_beacon_offset_get_average+0x4479ffa0>) */ @0x8
  a8 = (uint32_t)&divsf3; /* 0078: l32r a8, 20 <pm_beacon_offset_get_average-0x40> (0 <pm_beacon_offset_get_average-0x60>) */ /* literal: GOT slot for __divsf3 */
  divsf3(a2, a3, a4, a5); /* call via literal slot */ /* 007b: callx8 a8 */
  a3 = a10; /* 007e: mov.n a3, a10 */
  a7 = MEM32(a7 + 44); /* 0080: l32i.n a7, a7, 44 */
  a7 = a7 >> (10 & 31); /* 0082: srli a7, a7, 10 */
  /* 0085: float.s f1, a7, 0 */
  /* 0088: rfr a10, f1 */ /* UNMODELED: a10 clobbered */
  a8 = (uint32_t)&extendsfdf2; /* 008b: l32r a8, 24 <pm_beacon_offset_get_average-0x3c> (0 <pm_beacon_offset_get_average-0x60>) */ /* literal: GOT slot for __extendsfdf2 */
  extendsfdf2(a2, a3, a4, a5); /* call via literal slot */ /* 008e: callx8 a8 */
  a12 = 0xD2F1A9FC; /* 0091: l32r a12, c <pm_beacon_offset_get_average-0x54> (d2f1a9fc <pm_beacon_offset_get_average+0xd2f1a99c>) */ @0xC
  a13 = 0x3FF0624D; /* 0094: l32r a13, 10 <pm_beacon_offset_get_average-0x50> (3ff0624d <pm_beacon_offset_get_average+0x3ff061ed>) */ /* MMIO base */ @0x10
  a8 = (uint32_t)&muldf3; /* 0097: l32r a8, 28 <pm_beacon_offset_get_average-0x38> (0 <pm_beacon_offset_get_average-0x60>) */ /* literal: GOT slot for __muldf3 */
  muldf3(a2, a3, a4, a5); /* call via literal slot */ /* 009a: callx8 a8 */
  a8 = (uint32_t)&truncdfsf2; /* 009d: l32r a8, 2c <pm_beacon_offset_get_average-0x34> (0 <pm_beacon_offset_get_average-0x60>) */ /* literal: GOT slot for __truncdfsf2 */
  truncdfsf2(a2, a3, a4, a5); /* call via literal slot */ /* 00a0: callx8 a8 */
  a8 = 0x0; /* 00a3: l32r a8, 0 <pm_beacon_offset_get_average-0x60> (0 <pm_beacon_offset_get_average-0x60>) */ @0x0
  /* 00a6: wfr f0, a8 */
  a7 = (uint32_t)&s_pm_beacon_offset; /* 00a9: l32r a7, 14 <pm_beacon_offset_get_average-0x4c> (0 <pm_beacon_offset_get_average-0x60>) */ /* literal @0x14: s_pm_beacon_offset */
  MEM32(a1 + 0) = a10; /* 00ac: s32i.n a10, a1, 0 */
  a15 = MEM32(a7 + 4); /* 00ae: l32i.n a15, a7, 4 */
  a7 = a2; /* 00b0: mov.n a7, a2 */
  MEMW(); /* 00b2: memw  */
  goto L_13c; /* 00b5: j 13c <pm_beacon_offset_get_average+0xdc> */
  /* 00b8: .byte 00 */
L_b9:;
  a9 = (a7 << 2) + a15; /* 00b9: addx2 a9, a7, a15 */
  a14 = MEM16(a9 + 0); /* 00bc: l16ui a14, a9, 0 */
  if (a14 == 0) goto L_13a; /* 00bf: beqz a14, 13a <pm_beacon_offset_get_average+0xda> */
  a8 = a14 + a8; /* 00c2: add.n a8, a14, a8 */
  a10 = a7; /* 00c4: mov.n a10, a7 */
  MEM16(a4 + 0) = a8; /* 00c6: s16i a8, a4, 0 */
  MEMW(); /* 00c9: memw  */
  MEM32(a1 + 20) = a14; /* 00cc: s32i.n a14, a1, 20 */
  MEM32(a1 + 12) = a15; /* 00ce: s32i a15, a1, 12 */
  /* 00d1: ssi f0, a1, 16 */
  MEMW(); /* 00d4: memw  */
  a8 = (uint32_t)&floatsidf; /* 00d7: l32r a8, 30 <pm_beacon_offset_get_average-0x30> (0 <pm_beacon_offset_get_average-0x60>) */ /* literal: GOT slot for __floatsidf */
  floatsidf(a2, a3, a4, a5); /* call via literal slot */ /* 00da: callx8 a8 */
  a12 = 0x0; /* 00dd: l32r a12, 18 <pm_beacon_offset_get_average-0x48> (0 <pm_beacon_offset_get_average-0x60>) */ @0x18
  a13 = 0x3FE00000; /* 00e0: l32r a13, 1c <pm_beacon_offset_get_average-0x44> (3fe00000 <pm_beacon_offset_get_average+0x3fdfffa0>) */ /* MMIO base */ @0x1C
  a8 = (uint32_t)&adddf3; /* 00e3: l32r a8, 34 <pm_beacon_offset_get_average-0x2c> (0 <pm_beacon_offset_get_average-0x60>) */ /* literal: GOT slot for __adddf3 */
  adddf3(a2, a3, a4, a5); /* call via literal slot */ /* 00e6: callx8 a8 */
  a12 = 0xD2F1A9FC; /* 00e9: l32r a12, c <pm_beacon_offset_get_average-0x54> (d2f1a9fc <pm_beacon_offset_get_average+0xd2f1a99c>) */ @0xC
  a13 = 0x3FF0624D; /* 00ec: l32r a13, 10 <pm_beacon_offset_get_average-0x50> (3ff0624d <pm_beacon_offset_get_average+0x3ff061ed>) */ /* MMIO base */ @0x10
  a8 = (uint32_t)&muldf3; /* 00ef: l32r a8, 38 <pm_beacon_offset_get_average-0x28> (0 <pm_beacon_offset_get_average-0x60>) */ /* literal: GOT slot for __muldf3 */
  muldf3(a2, a3, a4, a5); /* call via literal slot */ /* 00f2: callx8 a8 */
  a8 = a10; /* 00f5: mov.n a8, a10 */
  a10 = a3; /* 00f7: mov.n a10, a3 */
  MEM32(a1 + 4) = a8; /* 00f9: s32i.n a8, a1, 4 */
  MEM32(a1 + 8) = a11; /* 00fb: s32i.n a11, a1, 8 */
  MEMW(); /* 00fd: memw  */
  a8 = (uint32_t)&extendsfdf2; /* 0100: l32r a8, 3c <pm_beacon_offset_get_average-0x24> (0 <pm_beacon_offset_get_average-0x60>) */ /* literal: GOT slot for __extendsfdf2 */
  extendsfdf2(a2, a3, a4, a5); /* call via literal slot */ /* 0103: callx8 a8 */
  a12 = a10; /* 0106: mov.n a12, a10 */
  a13 = 0x447A0000; /* 0108: mov.n a13, a11 */
  a8 = MEM32(a1 + 4); /* 010a: l32i.n a8, a1, 4 */
  a10 = a8; /* 010c: mov.n a10, a8 */
  a9 = MEM32(a1 + 8); /* 010e: l32i.n a9, a1, 8 */
  a11 = a9; /* 0110: mov.n a11, a9 */
  a8 = (uint32_t)&adddf3; /* 0112: l32r a8, 40 <pm_beacon_offset_get_average-0x20> (0 <pm_beacon_offset_get_average-0x60>) */ /* literal: GOT slot for __adddf3 */
  adddf3(a2, a3, a4, a5); /* call via literal slot */ /* 0115: callx8 a8 */
  a8 = (uint32_t)&truncdfsf2; /* 0118: l32r a8, 44 <pm_beacon_offset_get_average-0x1c> (0 <pm_beacon_offset_get_average-0x60>) */ /* literal: GOT slot for __truncdfsf2 */
  truncdfsf2(a2, a3, a4, a5); /* call via literal slot */ /* 011b: callx8 a8 */
  /* 011e: lsi f2, a1, 0 */
  /* 0121: wfr f1, a10 */
  /* 0124: olt.s b0, f2, f1 */
  a14 = MEM32(a1 + 20); /* 0127: l32i.n a14, a1, 20 */
  a15 = MEM32(a1 + 12); /* 0129: l32i.n a15, a1, 12 */
  /* 012b: lsi f0, a1, 16 */
  if (!FP_b0) goto L_134; /* 012e: bf b0, 134 <pm_beacon_offset_get_average+0xd4> */
  /* 0131: mov.s f1, f2 */
L_134:;
  /* 0134: float.s f2, a14, 0 */
  /* 0137: madd.s f0, f2, f1 */
L_13a:;
  a7 = a7 + (1); /* 013a: addi.n a7, a7, 1 */
L_13c:;
  a9 = (a7 >> 0) & 0xFF; /* 013c: extui a9, a7, 0, 8 */
  a8 = MEM16(a4 + 0); /* 013f: l16ui a8, a4, 0 */
  if (a9 >= a6) goto L_148; /* 0142: bgeu a9, a6, 148 <pm_beacon_offset_get_average+0xe8> */
  goto L_b9; /* 0145: j b9 <pm_beacon_offset_get_average+0x59> */
L_148:;
  if (a8 == 0) goto L_198; /* 0148: beqz a8, 198 <pm_beacon_offset_get_average+0x138> */
  /* 014b: float.s f1, a8, 0 */
  /* 014e: rfr a10, f0 */ /* UNMODELED: a10 clobbered */
  /* 0151: rfr a11, f1 */ /* UNMODELED: a11 clobbered */
  a8 = (uint32_t)&divsf3; /* 0154: l32r a8, 48 <pm_beacon_offset_get_average-0x18> (0 <pm_beacon_offset_get_average-0x60>) */ /* literal: GOT slot for __divsf3 */
  divsf3(a2, a3, a4, a5); /* call via literal slot */ /* 0157: callx8 a8 */
  a8 = (uint32_t)&extendsfdf2; /* 015a: l32r a8, 4c <pm_beacon_offset_get_average-0x14> (0 <pm_beacon_offset_get_average-0x60>) */ /* literal: GOT slot for __extendsfdf2 */
  extendsfdf2(a2, a3, a4, a5); /* call via literal slot */ /* 015d: callx8 a8 */
  a8 = a10; /* 0160: mov.n a8, a10 */
  a10 = a2; /* 0162: mov.n a10, a2 */
  MEM32(a1 + 4) = a8; /* 0164: s32i.n a8, a1, 4 */
  MEM32(a1 + 8) = a11; /* 0166: s32i.n a11, a1, 8 */
  MEMW(); /* 0168: memw  */
  a8 = (uint32_t)&floatsidf; /* 016b: l32r a8, 50 <pm_beacon_offset_get_average-0x10> (0 <pm_beacon_offset_get_average-0x60>) */ /* literal: GOT slot for __floatsidf */
  floatsidf(a2, a3, a4, a5); /* call via literal slot */ /* 016e: callx8 a8 */
  a12 = 0xD2F1A9FC; /* 0171: l32r a12, c <pm_beacon_offset_get_average-0x54> (d2f1a9fc <pm_beacon_offset_get_average+0xd2f1a99c>) */ @0xC
  a13 = 0x3FF0624D; /* 0174: l32r a13, 10 <pm_beacon_offset_get_average-0x50> (3ff0624d <pm_beacon_offset_get_average+0x3ff061ed>) */ /* MMIO base */ @0x10
  a8 = (uint32_t)&muldf3; /* 0177: l32r a8, 54 <pm_beacon_offset_get_average-0xc> (0 <pm_beacon_offset_get_average-0x60>) */ /* literal: GOT slot for __muldf3 */
  muldf3(a2, a3, a4, a5); /* call via literal slot */ /* 017a: callx8 a8 */
  a12 = a10; /* 017d: mov.n a12, a10 */
  a13 = a11; /* 017f: mov.n a13, a11 */
  a8 = MEM32(a1 + 4); /* 0181: l32i.n a8, a1, 4 */
  a10 = a8; /* 0183: mov.n a10, a8 */
  a9 = MEM32(a1 + 8); /* 0185: l32i a9, a1, 8 */
  a11 = a9; /* 0188: mov.n a11, a9 */
  a8 = (uint32_t)&subdf3; /* 018a: l32r a8, 58 <pm_beacon_offset_get_average-0x8> (0 <pm_beacon_offset_get_average-0x60>) */ /* literal: GOT slot for __subdf3 */
  subdf3(a2, a3, a4, a5); /* call via literal slot */ /* 018d: callx8 a8 */
  a8 = (uint32_t)&truncdfsf2; /* 0190: l32r a8, 5c <pm_beacon_offset_get_average-0x4> (0 <pm_beacon_offset_get_average-0x60>) */ /* literal: GOT slot for __truncdfsf2 */
  truncdfsf2(a2, a3, a4, a5); /* call via literal slot */ /* 0193: callx8 a8 */
  MEM32(a5 + 0) = a10; /* 0196: s32i.n a10, a5, 0 */
L_198:;
  MEMW(); /* 0198: memw  */
  return (int32_t)a2; /* 019b: retw.n  */
}

/* pm_beacon_offset_get_expect @ pm_beacon_offset.o 00000050 size 409B bind GLOBAL
 * Calls: pm_beacon_offset_get_average[got], __divsf3[got], __divsf3[got], __extendsfdf2[got], __extendsfdf2[got], __muldf3[got], __adddf3[got], __truncdfsf2[got], __extendsfdf2[got], __muldf3[got], __truncdfsf2[got], __divsf3[got], __divsf3[got] | Data refs: pm_beacon_offset_get_average, s_pm_beacon_offset_config, __divsf3, g_pm, __extendsfdf2, __muldf3, __adddf3, __truncdfsf2
 *   MMIO: none
 *   FP/data literals (loaded, never dereferenced - NOT MMIO): 0x3F800000, 0x3FF0624D
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 13 call(s), 8 data ref(s)
 * Fidelity: medium - 143 instr, 7 branches, calls resolved */
int32_t pm_beacon_offset_get_expect(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .wifislpiram.3; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_50:;
  /* 0050: entry a1, 80 */
  a4 = 0x0; /* 0053: movi.n a4, 0 */
  /* 0055: lsi f0, a6, 20 */
  a2 = (a2 >> 0) & 0xFF; /* 0058: extui a2, a2, 0, 8 */
  a3 = (a3 >> 0) & 0xFF; /* 005b: extui a3, a3, 0, 8 */
  a10 = a2; /* 005e: mov.n a10, a2 */
  a13 = a1; /* 0060: mov.n a13, a1 */
  MEM16(a1 + 4) = a4; /* 0062: s16i a4, a1, 4 */
  MEMW(); /* 0065: memw  */
  a12 = a1 + (4); /* 0068: addi.n a12, a1, 4 */
  a11 = a3 | a3; /* 006a: or a11, a3, a3 */
  a4 = 0x0; /* 006d: l32r a4, 4 <pm_beacon_offset_get_expect-0x4c> (0 <pm_beacon_offset_get_expect-0x50>) */ @0x4
  MEM32(a1 + 16) = a5; /* 0070: s32i a5, a1, 16 */
  MEM32(a1 + 0) = a4; /* 0073: s32i a4, a1, 0 */
  /* 0076: ssi f0, a1, 20 */
  MEMW(); /* 0079: memw  */
  a8 = (uint32_t)&pm_beacon_offset_get_average; /* 007c: l32r a8, 1c <pm_beacon_offset_get_expect-0x34> (0 <pm_beacon_offset_get_expect-0x50>) */ /* literal: GOT slot for pm_beacon_offset_get_average */
  pm_beacon_offset_get_average(a2, a3, a4, a5); /* call via literal slot */ /* 007f: callx8 a8 */
  a10 = a4; /* 0082: mov.n a10, a4 */
  a7 = MEM16(a1 + 4); /* 0084: l16ui a7, a1, 4 */
  if (a7 == 0) goto L_1e2; /* 0087: beqz a7, 1e2 <pm_beacon_offset_get_expect+0x192> */
  /* 008a: ufloat.s f4, a7, 0 */
  a3 = a3 - a2; /* 008d: sub a3, a3, a2 */
  a4 = (uint32_t)&s_pm_beacon_offset_config; /* 0090: l32r a4, 8 <pm_beacon_offset_get_expect-0x48> (0 <pm_beacon_offset_get_expect-0x50>) */ /* literal @0x8: s_pm_beacon_offset_config */
  /* 0093: rfr a10, f4 */ /* UNMODELED: a10 clobbered */
  a3 = (a3 >> 0) & 0xFF; /* 0096: extui a3, a3, 0, 8 */
  a4 = MEM16(a4 + 0); /* 0099: l16ui a4, a4, 0 */
  /* 009c: ufloat.s f1, a4, 0 */
  /* 009f: rfr a11, f1 */ /* UNMODELED: a11 clobbered */
  a8 = (uint32_t)&divsf3; /* 00a2: l32r a8, 20 <pm_beacon_offset_get_expect-0x30> (0 <pm_beacon_offset_get_expect-0x50>) */ /* literal: GOT slot for __divsf3 */
  divsf3(a2, a3, a4, a5); /* call via literal slot */ /* 00a5: callx8 a8 */
  /* 00a8: lsi f0, a1, 16 */
  /* 00ab: wfr f5, a10 */
  /* 00ae: mul.s f5, f5, f0 */
  a4 = 0x3F800000; /* 00b1: l32r a4, 0 <pm_beacon_offset_get_expect-0x50> (3f800000 <pm_beacon_offset_get_params+0x3f7fffa0>) */ /* MMIO base */ @0x0
  /* 00b4: wfr f1, a4 */
  /* 00b7: olt.s b0, f5, f1 */
  /* 00ba: ssi f5, a1, 16 */
  /* 00bd: lsi f2, a1, 0 */
  if (FP_b0) goto L_c6; /* 00c0: bt b0, c6 <pm_beacon_offset_get_expect+0x76> */
  goto L_1b8; /* 00c3: j 1b8 <pm_beacon_offset_get_expect+0x168> */
L_c6:;
  a8 = (uint32_t)&g_pm; /* 00c6: l32r a8, c <pm_beacon_offset_get_expect-0x44> (0 <pm_beacon_offset_get_expect-0x50>) */ /* literal @0xC: g_pm */
  a4 = MEM32(a8 + 464); /* 00c9: l32i a4, a8, 0x1d0 */
  /* 00cc: ufloat.s f0, a4, 0 */
  /* 00cf: rfr a10, f0 */ /* UNMODELED: a10 clobbered */
  a11 = 0x447A0000; /* 00d2: l32r a11, 10 <pm_beacon_offset_get_expect-0x40> (447a0000 <pm_beacon_offset_get_params+0x4479ffa0>) */ @0x10
  MEM32(a1 + 32) = a8; /* 00d5: s32i.n a8, a1, 32 */
  /* 00d7: ssi f1, a1, 28 */
  /* 00da: ssi f2, a1, 36 */
  MEMW(); /* 00dd: memw  */
  a8 = (uint32_t)&divsf3; /* 00e0: l32r a8, 24 <pm_beacon_offset_get_expect-0x2c> (0 <pm_beacon_offset_get_expect-0x50>) */ /* literal: GOT slot for __divsf3 */
  divsf3(a2, a3, a4, a5); /* call via literal slot */ /* 00e3: callx8 a8 */
  a8 = (uint32_t)&extendsfdf2; /* 00e6: l32r a8, 28 <pm_beacon_offset_get_expect-0x28> (0 <pm_beacon_offset_get_expect-0x50>) */ /* literal: GOT slot for __extendsfdf2 */
  extendsfdf2(a2, a3, a4, a5); /* call via literal slot */ /* 00e9: callx8 a8 */
  /* 00ec: ufloat.s f4, a3, 0 */
  a4 = a10; /* 00ef: mov.n a4, a10 */
  /* 00f1: rfr a10, f4 */ /* UNMODELED: a10 clobbered */
  a5 = 0x447A0000; /* 00f4: mov.n a5, a11 */
  a8 = (uint32_t)&extendsfdf2; /* 00f6: l32r a8, 2c <pm_beacon_offset_get_expect-0x24> (0 <pm_beacon_offset_get_expect-0x50>) */ /* literal: GOT slot for __extendsfdf2 */
  extendsfdf2(a2, a3, a4, a5); /* call via literal slot */ /* 00f9: callx8 a8 */
  a12 = 0xD2F1A9FC; /* 00fc: l32r a12, 14 <pm_beacon_offset_get_expect-0x3c> (d2f1a9fc <pm_beacon_offset_get_params+0xd2f1a99c>) */ @0x14
  a13 = 0x3FF0624D; /* 00ff: l32r a13, 18 <pm_beacon_offset_get_expect-0x38> (3ff0624d <pm_beacon_offset_get_params+0x3ff061ed>) */ /* MMIO base */ @0x18
  a8 = (uint32_t)&muldf3; /* 0102: l32r a8, 30 <pm_beacon_offset_get_expect-0x20> (0 <pm_beacon_offset_get_expect-0x50>) */ /* literal: GOT slot for __muldf3 */
  muldf3(a2, a3, a4, a5); /* call via literal slot */ /* 0105: callx8 a8 */
  a12 = a10; /* 0108: mov.n a12, a10 */
  a13 = 0x447A0000; /* 010a: or a13, a11, a11 */
  a10 = a4 | a4; /* 010d: or a10, a4, a4 */
  a11 = a5; /* 0110: mov.n a11, a5 */
  a8 = (uint32_t)&adddf3; /* 0112: l32r a8, 34 <pm_beacon_offset_get_expect-0x1c> (0 <pm_beacon_offset_get_expect-0x50>) */ /* literal: GOT slot for __adddf3 */
  adddf3(a2, a3, a4, a5); /* call via literal slot */ /* 0115: callx8 a8 */
  a8 = (uint32_t)&truncdfsf2; /* 0118: l32r a8, 38 <pm_beacon_offset_get_expect-0x18> (0 <pm_beacon_offset_get_expect-0x50>) */ /* literal: GOT slot for __truncdfsf2 */
  truncdfsf2(a2, a3, a4, a5); /* call via literal slot */ /* 011b: callx8 a8 */
  /* 011e: float.s f0, a2, 0 */
  /* 0121: lsi f5, a1, 20 */
  /* 0124: wfr f3, a10 */
  /* 0127: sub.s f5, f5, f0 */
  /* 012a: ssi f3, a1, 24 */
  /* 012d: rfr a10, f5 */ /* UNMODELED: a10 clobbered */
  MEMW(); /* 0130: memw  */
  a8 = (uint32_t)&extendsfdf2; /* 0133: l32r a8, 3c <pm_beacon_offset_get_expect-0x14> (0 <pm_beacon_offset_get_expect-0x50>) */ /* literal: GOT slot for __extendsfdf2 */
  extendsfdf2(a2, a3, a4, a5); /* call via literal slot */ /* 0136: callx8 a8 */
  a12 = 0xD2F1A9FC; /* 0139: l32r a12, 14 <pm_beacon_offset_get_expect-0x3c> (d2f1a9fc <pm_beacon_offset_get_params+0xd2f1a99c>) */ @0x14
  a13 = 0x3FF0624D; /* 013c: l32r a13, 18 <pm_beacon_offset_get_expect-0x38> (3ff0624d <pm_beacon_offset_get_params+0x3ff061ed>) */ /* MMIO base */ @0x18
  a8 = (uint32_t)&muldf3; /* 013f: l32r a8, 40 <pm_beacon_offset_get_expect-0x10> (0 <pm_beacon_offset_get_expect-0x50>) */ /* literal: GOT slot for __muldf3 */
  muldf3(a2, a3, a4, a5); /* call via literal slot */ /* 0142: callx8 a8 */
  a8 = (uint32_t)&truncdfsf2; /* 0145: l32r a8, 44 <pm_beacon_offset_get_expect-0xc> (0 <pm_beacon_offset_get_expect-0x50>) */ /* literal: GOT slot for __truncdfsf2 */
  truncdfsf2(a2, a3, a4, a5); /* call via literal slot */ /* 0148: callx8 a8 */
  /* 014b: wfr f0, a10 */
  /* 014e: lsi f3, a1, 24 */
  /* 0151: olt.s b0, f0, f3 */
  a8 = MEM32(a1 + 32); /* 0154: l32i.n a8, a1, 32 */
  /* 0156: lsi f1, a1, 28 */
  /* 0159: lsi f2, a1, 36 */
  if (!FP_b0) goto L_162; /* 015c: bf b0, 162 <pm_beacon_offset_get_expect+0x112> */
  /* 015f: wfr f3, a10 */
L_162:;
  a4 = 0x0; /* 0162: movi.n a4, 0 */
  /* 0164: mov.s f4, f1 */
  /* 0167: lsi f5, a1, 16 */
  /* 016a: sub.s f0, f1, f5 */
  a5 = MEM16(a8 + 386); /* 016d: l16si a5, a8, 0x182 */
  goto L_17c; /* 0170: j 17c <pm_beacon_offset_get_expect+0x12c> */
  /* 0173: .byte 00 */
L_174:;
  a4 = 0x1; /* 0174: addi.n a4, a4, 1 */
  a4 = 0x1; /* 0176: sext a4, a4, 15 */
  /* 0179: mov.s f4, f6 */
L_17c:;
  /* 017c: mul.s f6, f0, f4 */
  if (a4 < a5) goto L_174; /* 017f: blt a4, a5, 174 <pm_beacon_offset_get_expect+0x124> */
  /* 0182: lsi f5, a6, 24 */
  /* 0185: sub.s f1, f1, f6 */
  /* 0188: sub.s f5, f5, f2 */
  /* 018b: sub.s f0, f2, f3 */
  /* 018e: mul.s f1, f1, f3 */
  a11 = MEM32(a1 + 16); /* 0191: l32i.n a11, a1, 16 */
  /* 0193: madd.s f0, f5, f4 */
  /* 0196: rfr a10, f1 */ /* UNMODELED: a10 clobbered */
  /* 0199: ssi f0, a1, 24 */
  /* 019c: ssi f2, a1, 36 */
  MEMW(); /* 019f: memw  */
  a8 = (uint32_t)&divsf3; /* 01a2: l32r a8, 48 <pm_beacon_offset_get_expect-0x8> (0 <pm_beacon_offset_get_expect-0x50>) */ /* literal: GOT slot for __divsf3 */
  divsf3(a2, a3, a4, a5); /* call via literal slot */ /* 01a5: callx8 a8 */
  /* 01a8: wfr f1, a10 */
  /* 01ab: lsi f0, a1, 24 */
  /* 01ae: add.s f0, f1, f0 */
  /* 01b1: lsi f2, a1, 36 */
  goto L_1bb; /* 01b4: j 1bb <pm_beacon_offset_get_expect+0x16b> */
  /* 01b7: .byte 00 */
L_1b8:;
  /* 01b8: mov.s f0, f2 */
L_1bb:;
  /* 01bb: lsi f4, a1, 16 */
  /* 01be: rfr a10, f0 */ /* UNMODELED: a10 clobbered */
  /* 01c1: rfr a11, f4 */ /* UNMODELED: a11 clobbered */
  /* 01c4: ssi f0, a6, 0 */
  /* 01c7: ssi f4, a6, 4 */
  /* 01ca: ssi f2, a6, 8 */
  MEM8(a6 + 16) = a2; /* 01cd: s8i a2, a6, 16 */
  MEM8(a6 + 17) = a3; /* 01d0: s8i a3, a6, 17 */
  MEM16(a6 + 18) = a7; /* 01d3: s16i a7, a6, 18 */
  MEMW(); /* 01d6: memw  */
  MEMW(); /* 01d9: memw  */
  a8 = (uint32_t)&divsf3; /* 01dc: l32r a8, 4c <pm_beacon_offset_get_expect-0x4> (0 <pm_beacon_offset_get_expect-0x50>) */ /* literal: GOT slot for __divsf3 */
  divsf3(a2, a3, a4, a5); /* call via literal slot */ /* 01df: callx8 a8 */
L_1e2:;
  MEM32(a6 + 28) = a10; /* 01e2: s32i.n a10, a6, 28 */
  MEMW(); /* 01e4: memw  */
  return (int32_t)a2; /* 01e7: retw.n  */
}

/* pm_beacon_offset_is_sampling @ pm_beacon_offset.o 00000004 size 18B bind GLOBAL
 * Calls: none | Data refs: s_pm_beacon_offset
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t pm_beacon_offset_is_sampling(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .wifislpiram.11; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a2 = (uint32_t)&s_pm_beacon_offset; /* 0007: l32r a2, 0 <pm_beacon_offset_is_sampling-0x4> (0 <pm_beacon_offset_is_sampling-0x4>) */ /* literal @0x0: s_pm_beacon_offset */
  a8 = 0x0; /* 000a: movi.n a8, 0 */
  a9 = MEM16(a2 + 0); /* 000c: l16ui a9, a2, 0 */
  a2 = 0x1; /* 000f: movi.n a2, 1 */
  if (a9 == 0) a2 = a8; /* 0011: moveqz a2, a8, a9 */
  return (int32_t)a2; /* 0014: retw.n  */
}

/* pm_beacon_offset_is_enabled @ pm_beacon_offset.o 00000004 size 18B bind GLOBAL
 * Calls: none | Data refs: s_pm_beacon_offset_config
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t pm_beacon_offset_is_enabled(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .wifislpiram.12; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a2 = (uint32_t)&s_pm_beacon_offset_config; /* 0007: l32r a2, 0 <pm_beacon_offset_is_enabled-0x4> (0 <pm_beacon_offset_is_enabled-0x4>) */ /* literal @0x0: s_pm_beacon_offset_config */
  a8 = 0x0; /* 000a: movi.n a8, 0 */
  a9 = MEM16(a2 + 0); /* 000c: l16ui a9, a2, 0 */
  a2 = 0x1; /* 000f: movi.n a2, 1 */
  if (a9 == 0) a2 = a8; /* 0011: moveqz a2, a8, a9 */
  return (int32_t)a2; /* 0014: retw.n  */
}

/* pm_beacon_offset_get_rx_beacon_success_rate @ pm_beacon_offset.o 00000008 size 36B bind GLOBAL
 * Calls: __divsf3 | Data refs: __divsf3, s_pm_beacon_offset
 *   MMIO: none
 *   funcdb v3: 1 call(s), 2 ref(s); disasm: 1 call(s), 2 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t pm_beacon_offset_get_rx_beacon_success_rate(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pm_beacon_offset_get_rx_beacon_success_rate; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_8:;
  /* 0008: entry a1, 32 */
  a8 = (uint32_t)&s_pm_beacon_offset; /* 000b: l32r a8, 0 <pm_beacon_offset_get_rx_beacon_success_rate-0x8> (0 <pm_beacon_offset_get_rx_beacon_success_rate-0x8>) */ /* literal @0x0: s_pm_beacon_offset */
  a9 = MEM32(a8 + 8); /* 000e: l32i.n a9, a8, 8 */
  /* 0010: ufloat.s f0, a9, 0 */
  /* 0013: rfr a11, f0 */ /* UNMODELED: a11 clobbered */
  a8 = MEM32(a8 + 12); /* 0016: l32i a8, a8, 12 */
  a8 = a9 - a8; /* 0019: sub a8, a9, a8 */
  /* 001c: ufloat.s f0, a8, 0 */
  /* 001f: rfr a10, f0 */ /* UNMODELED: a10 clobbered */
  a8 = (uint32_t)&divsf3; /* 0022: l32r a8, 4 <pm_beacon_offset_get_rx_beacon_success_rate-0x4> (0 <pm_beacon_offset_get_rx_beacon_success_rate-0x8>) */ /* literal: GOT slot for __divsf3 */
  divsf3(a2, a3, a4, a5); /* call via literal slot */ /* 0025: callx8 a8 */
  a2 = a10; /* 0028: mov.n a2, a10 */
  return (int32_t)a2; /* 002a: retw.n  */
}

/* pm_beacon_offset_add_total_counter @ pm_beacon_offset.o 00000004 size 17B bind GLOBAL
 * Calls: none | Data refs: s_pm_beacon_offset
 *   MMIO: none
 *   funcdb v3: 0 call(s), 1 ref(s); disasm: 0 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t pm_beacon_offset_add_total_counter(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pm_beacon_offset_add_total_counter; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a9 = (uint32_t)&s_pm_beacon_offset; /* 0007: l32r a9, 0 <pm_beacon_offset_add_total_counter-0x4> (0 <pm_beacon_offset_add_total_counter-0x4>) */ /* literal @0x0: s_pm_beacon_offset */
  a8 = MEM32(a9 + 8); /* 000a: l32i.n a8, a9, 8 */
  a8 = a8 + (1); /* 000c: addi.n a8, a8, 1 */
  MEM32(a9 + 8) = a8; /* 000e: s32i.n a8, a9, 8 */
  MEMW(); /* 0010: memw  */
  return (int32_t)a2; /* 0013: retw.n  */
}

/* pm_beacon_offset_add_loss_counter @ pm_beacon_offset.o 00000004 size 17B bind GLOBAL
 * Calls: none | Data refs: s_pm_beacon_offset
 *   MMIO: none
 *   funcdb v3: 0 call(s), 1 ref(s); disasm: 0 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t pm_beacon_offset_add_loss_counter(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pm_beacon_offset_add_loss_counter; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a9 = (uint32_t)&s_pm_beacon_offset; /* 0007: l32r a9, 0 <pm_beacon_offset_add_loss_counter-0x4> (0 <pm_beacon_offset_add_loss_counter-0x4>) */ /* literal @0x0: s_pm_beacon_offset */
  a8 = MEM32(a9 + 12); /* 000a: l32i.n a8, a9, 12 */
  a8 = a8 + (1); /* 000c: addi.n a8, a8, 1 */
  MEM32(a9 + 12) = a8; /* 000e: s32i.n a8, a9, 12 */
  MEMW(); /* 0010: memw  */
  return (int32_t)a2; /* 0013: retw.n  */
}

/* empty_func_p_void_r_void @ pm_beacon_offset.o 00000000 size 5B bind GLOBAL
 * Calls: none | Data refs: none
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t empty_func_p_void_r_void(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.empty_func_p_void_r_void; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_0:;
  /* 0000: entry a1, 32 */
  return (int32_t)a2; /* 0003: retw.n  */
}

/* empty_func_p_u32_r_void @ pm_beacon_offset.o 00000000 size 5B bind GLOBAL
 * Calls: none | Data refs: none
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t empty_func_p_u32_r_void(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.empty_func_p_u32_r_void; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_0:;
  /* 0000: entry a1, 32 */
  return (int32_t)a2; /* 0003: retw.n  */
}

/* empty_func_p_void_r_bool @ pm_beacon_offset.o 00000000 size 7B bind GLOBAL
 * Calls: none | Data refs: none
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t empty_func_p_void_r_bool(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.empty_func_p_void_r_bool; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_0:;
  /* 0000: entry a1, 32 */
  a2 = 0x0; /* 0003: movi.n a2, 0 */
  return (int32_t)a2; /* 0005: retw.n  */
}

/* empty_func_p_pconfg_r_void @ pm_beacon_offset.o 00000000 size 5B bind GLOBAL
 * Calls: none | Data refs: none
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t empty_func_p_pconfg_r_void(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.empty_func_p_pconfg_r_void; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_0:;
  /* 0000: entry a1, 32 */
  return (int32_t)a2; /* 0003: retw.n  */
}

/* empty_func_p_u8_r_void @ pm_beacon_offset.o 00000000 size 5B bind GLOBAL
 * Calls: none | Data refs: none
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t empty_func_p_u8_r_void(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.empty_func_p_u8_r_void; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_0:;
  /* 0000: entry a1, 32 */
  return (int32_t)a2; /* 0003: retw.n  */
}

/* empty_func_p_void_r_float @ pm_beacon_offset.o 00000004 size 8B bind GLOBAL
 * Calls: none | Data refs: none
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t empty_func_p_void_r_float(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.empty_func_p_void_r_float; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a2 = 0x0; /* 0007: l32r a2, 0 <empty_func_p_void_r_float-0x4> (0 <empty_func_p_void_r_float-0x4>) */ @0x0
  return (int32_t)a2; /* 000a: retw.n  */
}

/* empty_func_p_ptsf_u32_r_void @ pm_beacon_offset.o 00000000 size 5B bind GLOBAL
 * Calls: none | Data refs: none
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t empty_func_p_ptsf_u32_r_void(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.empty_func_p_ptsf_u32_r_void; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_0:;
  /* 0000: entry a1, 32 */
  return (int32_t)a2; /* 0003: retw.n  */
}

/* empty_func_p_u8_u8_pu16_pfloat_r_void @ pm_beacon_offset.o 00000000 size 5B bind GLOBAL
 * Calls: none | Data refs: none
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t empty_func_p_u8_u8_pu16_pfloat_r_void(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.empty_func_p_u8_u8_pu16_pfloat_r_void; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_0:;
  /* 0000: entry a1, 32 */
  return (int32_t)a2; /* 0003: retw.n  */
}

/* empty_func_p_u8_u8_float_float_pparams_r_void @ pm_beacon_offset.o 00000000 size 5B bind GLOBAL
 * Calls: none | Data refs: none
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t empty_func_p_u8_u8_float_float_pparams_r_void(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.empty_func_p_u8_u8_float_float_pparams_r_void; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_0:;
  /* 0000: entry a1, 32 */
  return (int32_t)a2; /* 0003: retw.n  */
}

/* pm_beacon_offset_get_params @ pm_beacon_offset.o 00000060 size 587B bind GLOBAL
 * Calls: pm_beacon_offset_get_average[got], wifi_log[got], memset[got], __divsf3[got], __floatunsidf[got], __muldf3[got], __truncdfsf2[got], __divsf3[got], memcpy[got], pm_beacon_offset_get_expect[got], memcpy[got], g_osi_funcs_p[got], memcpy[got] | Data refs: g_pm, pm_beacon_offset_get_average, s_pm_beacon_offset_config, .rodata_wlog_error.5, wifi_log, memset, __divsf3, __floatunsidf, __muldf3, __truncdfsf2, memcpy, pm_beacon_offset_get_expect, s_pm_beacon_offset, g_pm_cfg, g_osi_funcs_p
 *   MMIO: none
 *   FP/data literals (loaded, never dereferenced - NOT MMIO): 0x3FF0624D
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 13 call(s), 15 data ref(s)
 * Fidelity: medium - 207 instr, 15 branches, 0 indirect; flow + direct calls mapped, GOT-indirects enumerated (verified against section disasm) */
int32_t pm_beacon_offset_get_params(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .wifislpiram.4; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_60:;
  /* 0060: entry a1, 160 */
  a3 = (uint32_t)&g_pm; /* 0063: l32r a3, 4 <pm_beacon_offset_get_params-0x5c> (0 <pm_beacon_offset_get_params-0x60>) */ /* literal @0x4: g_pm */
  a6 = a2; /* 0066: mov.n a6, a2 */
  a5 = 0x0; /* 0068: movi.n a5, 0 */
  a13 = a1 + (80); /* 006a: addi a13, a1, 80 */
  a12 = a1 + (84); /* 006d: addi a12, a1, 84 */
  a2 = 0x0; /* 0070: l32r a2, 0 <pm_beacon_offset_get_params-0x60> (0 <pm_beacon_offset_get_params-0x60>) */ @0x0
  a10 = 0x0; /* 0073: movi.n a10, 0 */
  a4 = MEM32(a3 + 44); /* 0075: l32i.n a4, a3, 44 */
  MEM32(a1 + 80) = a2; /* 0077: s32i a2, a1, 80 */
  a2 = a4 >> (10 & 31); /* 007a: srli a2, a4, 10 */
  a4 = (a4 >> 10) & 0xFF; /* 007d: extui a4, a4, 10, 8 */
  a11 = a4; /* 0080: mov.n a11, a4 */
  MEM16(a1 + 84) = a5; /* 0082: s16i a5, a1, 84 */
  MEMW(); /* 0085: memw  */
  MEMW(); /* 0088: memw  */
  a8 = (uint32_t)&pm_beacon_offset_get_average; /* 008b: l32r a8, 30 <pm_beacon_offset_get_params-0x30> (0 <pm_beacon_offset_get_params-0x60>) */ /* literal: GOT slot for pm_beacon_offset_get_average */
  pm_beacon_offset_get_average(a2, a3, a4, a5); /* call via literal slot */ /* 008e: callx8 a8 */
  a5 = (uint32_t)&s_pm_beacon_offset_config; /* 0091: l32r a5, 8 <pm_beacon_offset_get_params-0x58> (0 <pm_beacon_offset_get_params-0x60>) */ /* literal @0x8: s_pm_beacon_offset_config */
  a15 = MEM16(a1 + 84); /* 0094: l16ui a15, a1, 84 */
  a5 = MEM16(a5 + 0); /* 0097: l16ui a5, a5, 0 */
  if (a5 != a15) goto L_a0; /* 009a: bne a5, a15, a0 <pm_beacon_offset_get_params+0x40> */
  if (a6 >= a5) goto L_bc; /* 009d: bgeu a6, a5, bc <pm_beacon_offset_get_params+0x5c> */
L_a0:;
  a12 = 0x1; /* 00a0: movi.n a12, 1 */
  a13 = (uint32_t)&lit_rodata_wlog_error_5; /* 00a2: l32r a13, c <pm_beacon_offset_get_params-0x54> (0 <pm_beacon_offset_get_params-0x60>) */ /* literal @0xC: .rodata_wlog_error.5 */
  a14 = a5; /* 00a5: mov.n a14, a5 */
  a11 = 0x1000; /* 00a7: slli a11, a12, 12 */
  a10 = 0x6; /* 00aa: movi.n a10, 6 */
  MEM32(a1 + 0) = a6; /* 00ac: s32i a6, a1, 0 */
  MEMW(); /* 00af: memw  */
  a8 = (uint32_t)&wifi_log; /* 00b2: l32r a8, 34 <pm_beacon_offset_get_params-0x2c> (0 <pm_beacon_offset_get_params-0x60>) */ /* literal: GOT slot for wifi_log */
  wifi_log(a2, a3, a4, a5); /* call via literal slot */ /* 00b5: callx8 a8 */
  goto L_2a6; /* 00b8: j 2a6 <pm_beacon_offset_get_params+0x246> */
  /* 00bb: .byte 00 */
L_bc:;
  a8 = (a2 >> 0) & 0xFF; /* 00bc: extui a8, a2, 0, 8 */
  a12 = 0x20; /* 00bf: movi a12, 32 */
  a11 = 0x0; /* 00c2: movi a11, 0 */
  a10 = a1 + (48); /* 00c5: addi a10, a1, 48 */
  MEM32(a1 + 100) = a8; /* 00c8: s32i a8, a1, 100 */
  MEMW(); /* 00cb: memw  */
  a8 = (uint32_t)&memset; /* 00ce: l32r a8, 38 <pm_beacon_offset_get_params-0x28> (0 <pm_beacon_offset_get_params-0x60>) */ /* literal: GOT slot for memset */
  memset(a2, a3, a4, a5); /* call via literal slot */ /* 00d1: callx8 a8 */
  /* 00d4: ufloat.s f1, a5, 0 */
  /* 00d7: ufloat.s f0, a6, 0 */
  /* 00da: rfr a10, f1 */ /* UNMODELED: a10 clobbered */
  /* 00dd: rfr a11, f0 */ /* UNMODELED: a11 clobbered */
  a8 = (uint32_t)&divsf3; /* 00e0: l32r a8, 3c <pm_beacon_offset_get_params-0x24> (0 <pm_beacon_offset_get_params-0x60>) */ /* literal: GOT slot for __divsf3 */
  divsf3(a2, a3, a4, a5); /* call via literal slot */ /* 00e3: callx8 a8 */
  a6 = a10; /* 00e6: mov.n a6, a10 */
  a10 = a2 | a2; /* 00e8: or a10, a2, a2 */
  a8 = (uint32_t)&floatunsidf; /* 00eb: l32r a8, 40 <pm_beacon_offset_get_params-0x20> (0 <pm_beacon_offset_get_params-0x60>) */ /* literal: GOT slot for __floatunsidf */
  floatunsidf(a2, a3, a4, a5); /* call via literal slot */ /* 00ee: callx8 a8 */
  a12 = 0xD2F1A9FC; /* 00f1: l32r a12, 10 <pm_beacon_offset_get_params-0x50> (d2f1a9fc <pm_beacon_offset_get_params+0xd2f1a99c>) */ @0x10
  a13 = 0x3FF0624D; /* 00f4: l32r a13, 14 <pm_beacon_offset_get_params-0x4c> (3ff0624d <pm_beacon_offset_get_params+0x3ff061ed>) */ /* MMIO base */ @0x14
  a8 = (uint32_t)&muldf3; /* 00f7: l32r a8, 44 <pm_beacon_offset_get_params-0x1c> (0 <pm_beacon_offset_get_params-0x60>) */ /* literal: GOT slot for __muldf3 */
  muldf3(a2, a3, a4, a5); /* call via literal slot */ /* 00fa: callx8 a8 */
  a8 = (uint32_t)&truncdfsf2; /* 00fd: l32r a8, 48 <pm_beacon_offset_get_params-0x18> (0 <pm_beacon_offset_get_params-0x60>) */ /* literal: GOT slot for __truncdfsf2 */
  truncdfsf2(a2, a3, a4, a5); /* call via literal slot */ /* 0100: callx8 a8 */
  /* 0103: wfr f3, a10 */
  /* 0106: lsi f2, a1, 80 */
  a11 = a6; /* 0109: mov.n a11, a6 */
  /* 010b: sub.s f0, f2, f3 */
  /* 010e: ssi f2, a1, 96 */
  /* 0111: ssi f0, a1, 120 */
  MEM32(a1 + 68) = a10; /* 0114: s32i a10, a1, 68 */
  MEMW(); /* 0117: memw  */
  a8 = (uint32_t)&divsf3; /* 011a: l32r a8, 4c <pm_beacon_offset_get_params-0x14> (0 <pm_beacon_offset_get_params-0x60>) */ /* literal: GOT slot for __divsf3 */
  divsf3(a2, a3, a4, a5); /* call via literal slot */ /* 011d: callx8 a8 */
  /* 0120: wfr f1, a10 */
  a12 = 0x20; /* 0123: movi.n a12, 32 */
  a11 = a1 + (48); /* 0125: addi a11, a1, 48 */
  /* 0128: lsi f0, a1, 120 */
  a10 = a1 + (16); /* 012b: addi a10, a1, 16 */
  /* 012e: add.s f0, f0, f1 */
  /* 0131: ssi f0, a1, 72 */
  MEMW(); /* 0134: memw  */
  a8 = (uint32_t)&memcpy; /* 0137: l32r a8, 50 <pm_beacon_offset_get_params-0x10> (0 <pm_beacon_offset_get_params-0x60>) */ /* literal: GOT slot for memcpy */
  memcpy(a2, a3, a4, a5); /* call via literal slot */ /* 013a: callx8 a8 */
  a5 = MEM32(a1 + 100); /* 013d: l32i a5, a1, 100 */
  a2 = a5 + (-1); /* 0140: addi.n a2, a5, -1 */
  a2 = (a2 >> 0) & 0xFF; /* 0142: extui a2, a2, 0, 8 */
  a5 = 0x0; /* 0145: movi.n a5, 0 */
  a8 = 0x0; /* 0147: l32r a8, 0 <pm_beacon_offset_get_params-0x60> (0 <pm_beacon_offset_get_params-0x60>) */ @0x0
  a2 = a4 - a2; /* 014a: sub a2, a4, a2 */
  /* 014d: wfr f0, a8 */
  a9 = 0x0; /* 0150: mov.n a9, a5 */
  /* 0152: wfr f1, a8 */
  a15 = 0x0; /* 0155: mov.n a15, a5 */
L_157:;
  a8 = a4 - a2; /* 0157: sub a8, a4, a2 */
  a7 = 0x0; /* 015a: movi.n a7, 0 */
  MEM32(a1 + 104) = a8; /* 015c: s32i a8, a1, 104 */
  MEMW(); /* 015f: memw  */
  goto L_1df; /* 0162: j 1df <pm_beacon_offset_get_params+0x17f> */
L_165:;
  a8 = MEM32(a1 + 100); /* 0165: l32i a8, a1, 100 */
  a14 = a1 + (48); /* 0168: addi a14, a1, 48 */
  a11 = a8 - a7; /* 016b: sub a11, a8, a7 */
  a13 = a6; /* 016e: mov.n a13, a6 */
  a11 = (a11 >> 0) & 0xFF; /* 0170: extui a11, a11, 0, 8 */
  a12 = MEM32(a1 + 96); /* 0173: l32i a12, a1, 96 */
  a10 = MEM32(a1 + 104); /* 0176: l32i a10, a1, 104 */
  MEM32(a1 + 116) = a9; /* 0179: s32i a9, a1, 116 */
  MEM32(a1 + 108) = a15; /* 017c: s32i a15, a1, 108 */
  /* 017f: ssi f0, a1, 120 */
  /* 0182: ssi f1, a1, 112 */
  MEMW(); /* 0185: memw  */
  a8 = (uint32_t)&pm_beacon_offset_get_expect; /* 0188: l32r a8, 54 <pm_beacon_offset_get_params-0xc> (0 <pm_beacon_offset_get_params-0x60>) */ /* literal: GOT slot for pm_beacon_offset_get_expect */
  pm_beacon_offset_get_expect(a2, a3, a4, a5); /* call via literal slot */ /* 018b: callx8 a8 */
  a8 = 0x0; /* 018e: l32r a8, 0 <pm_beacon_offset_get_params-0x60> (0 <pm_beacon_offset_get_params-0x60>) */ @0x0
  /* 0191: wfr f3, a8 */
  /* 0194: lsi f2, a1, 76 */
  /* 0197: oeq.s b0, f2, f3 */
  a9 = MEM32(a1 + 116); /* 019a: l32i a9, a1, 116 */
  a15 = MEM32(a1 + 108); /* 019d: l32i a15, a1, 108 */
  /* 01a0: lsi f0, a1, 120 */
  /* 01a3: lsi f1, a1, 112 */
  if (FP_b0) goto L_1da; /* 01a6: bt b0, 1da <pm_beacon_offset_get_params+0x17a> */
  /* 01a9: ole.s b0, f2, f0 */
  if (FP_b0) goto L_1b5; /* 01ac: bt b0, 1b5 <pm_beacon_offset_get_params+0x155> */
  /* 01af: oeq.s b0, f0, f3 */
  if (!FP_b0) goto L_1da; /* 01b2: bf b0, 1da <pm_beacon_offset_get_params+0x17a> */
L_1b5:;
  a12 = 0x20; /* 01b5: movi.n a12, 32 */
  a11 = a1 + (48); /* 01b7: addi a11, a1, 48 */
  a10 = a1 + (16); /* 01ba: addi a10, a1, 16 */
  /* 01bd: ssi f2, a1, 108 */
  MEMW(); /* 01c0: memw  */
  a8 = (uint32_t)&memcpy; /* 01c3: l32r a8, 58 <pm_beacon_offset_get_params-0x8> (0 <pm_beacon_offset_get_params-0x60>) */ /* literal: GOT slot for memcpy */
  memcpy(a2, a3, a4, a5); /* call via literal slot */ /* 01c6: callx8 a8 */
  a15 = 0x1; /* 01c9: movi.n a15, 1 */
  /* 01cb: lsi f2, a1, 108 */
  /* 01ce: mov.s f0, f2 */
  /* 01d1: lsi f1, a1, 52 */
  a9 = MEM8(a1 + 64); /* 01d4: l8ui a9, a1, 64 */
  a5 = MEM8(a1 + 65); /* 01d7: l8ui a5, a1, 65 */
L_1da:;
  a8 = a7 + (1); /* 01da: addi.n a8, a7, 1 */
  a7 = (a8 >> 0) & 0xFF; /* 01dc: extui a7, a8, 0, 8 */
L_1df:;
  if (a7 < a2) goto L_165; /* 01df: blt a7, a2, 165 <pm_beacon_offset_get_params+0x105> */
  if (a4 == a2) goto L_1ea; /* 01e2: beq a4, a2, 1ea <pm_beacon_offset_get_params+0x18a> */
  a2 = a2 + (1); /* 01e5: addi.n a2, a2, 1 */
  goto L_157; /* 01e7: j 157 <pm_beacon_offset_get_params+0xf7> */
L_1ea:;
  a4 = (uint32_t)&s_pm_beacon_offset; /* 01ea: l32r a4, 18 <pm_beacon_offset_get_params-0x48> (0 <pm_beacon_offset_get_params-0x60>) */ /* literal @0x18: s_pm_beacon_offset */
  if (a15 == 0) goto L_274; /* 01ed: beqz a15, 274 <pm_beacon_offset_get_params+0x214> */
  a2 = a9 << (10 & 31); /* 01f0: slli a2, a9, 10 */
  a8 = 0xFF; /* 01f3: movi a8, 255 */
  a7 = a3 + ((0x100) << 8); /* 01f6: addmi a7, a3, 0x100 */
  MEM32(a3 + 460) = a2; /* 01f9: s32i a2, a3, 0x1cc */
  a2 = MEM32(a3 + 464); /* 01fc: l32i a2, a3, 0x1d0 */
  a2 = a2 >> (10 & 31); /* 01ff: srli a2, a2, 10 */
  a2 = a2 + (1); /* 0202: addi.n a2, a2, 1 */
  a2 = a2 + a5; /* 0204: add.n a2, a2, a5 */
  /* 0206: minu a2, a2, a8 */ /* UNMODELED: a2 clobbered */
  MEM8(a7 + 124) = a2; /* 0209: s8i a2, a7, 124 */
  MEMW(); /* 020c: memw  */
  a8 = 0x1; /* 020f: movi.n a8, 1 */
  a2 = 0x42C80000; /* 0211: l32r a2, 1c <pm_beacon_offset_get_params-0x44> (42c80000 <pm_beacon_offset_get_params+0x42c7ffa0>) */ @0x1C
  /* 0214: wfr f3, a2 */
  /* 0217: mul.s f2, f1, f3 */
  a7 = (uint32_t)&s_pm_beacon_offset_config; /* 021a: l32r a7, 8 <pm_beacon_offset_get_params-0x58> (0 <pm_beacon_offset_get_params-0x60>) */ /* literal @0x8: s_pm_beacon_offset_config */
  /* 021d: utrunc.s a2, f2, 0 */ /* UNMODELED: a2 clobbered */
  a2 = (a2 >> 0) & 0xFF; /* 0220: extui a2, a2, 0, 8 */
  a10 = MEM8(a7 + 3); /* 0223: l8ui a10, a7, 3 */
  MEM8(a4 + 73) = a8; /* 0226: s8i a8, a4, 73 */
  MEMW(); /* 0229: memw  */
  if (a2 >= a10) goto L_27a; /* 022c: bgeu a2, a10, 27a <pm_beacon_offset_get_params+0x21a> */
  a3 = a3 + ((0x200) << 8); /* 022f: addmi a3, a3, 0x200 */
  a2 = MEM8(a7 + 2); /* 0232: l8ui a2, a7, 2 */
  MEM8(a3 + 28) = a8; /* 0235: s8i a8, a3, 28 */
  MEMW(); /* 0238: memw  */
  if (a2 == 0) goto L_27a; /* 023b: beqz.n a2, 27a <pm_beacon_offset_get_params+0x21a> */
  a3 = (uint32_t)&g_pm_cfg; /* 023d: l32r a3, 20 <pm_beacon_offset_get_params-0x40> (0 <pm_beacon_offset_get_params-0x60>) */ /* literal @0x20: g_pm_cfg */
  a3 = MEM8(a3 + 51); /* 0240: l8ui a3, a3, 51 */
  if (a3 != 1) goto L_27a; /* 0243: bnei a3, 1, 27a <pm_beacon_offset_get_params+0x21a> */
  a12 = 0x0; /* 0246: movi.n a12, 0 */
  a3 = (uint32_t)&g_osi_funcs_p; /* 0248: l32r a3, 2c <pm_beacon_offset_get_params-0x34> (0 <pm_beacon_offset_get_params-0x60>) */ /* literal @0x2C: g_osi_funcs_p */
  a11 = 0x36EE80; /* 024b: l32r a11, 24 <pm_beacon_offset_get_params-0x3c> (36ee80 <pm_beacon_offset_get_params+0x36ee20>) */ @0x24
  a11 = (uint32_t)((uint64_t)a2 * a11); /* 024e: mull a11, a2, a11 */
  a3 = MEM32(a3 + 0); /* 0251: l32i.n a3, a3, 0 */
  a10 = (uint32_t)&s_pm_beacon_offset; /* 0253: l32r a10, 28 <pm_beacon_offset_get_params-0x38> (0 <pm_beacon_offset_get_params-0x60>) */ /* literal @0x28: s_pm_beacon_offset */
  a3 = MEM32(a3 + 232); /* 0256: l32i a3, a3, 232 */
  MEM32(a1 + 116) = a9; /* 0259: s32i a9, a1, 116 */
  /* 025c: ssi f0, a1, 120 */
  /* 025f: ssi f1, a1, 112 */
  MEMW(); /* 0262: memw  */
  g_osi_funcs_p(a2, a3, a4, a5); /* call via literal slot */ /* 0265: callx8 a3 */
  a9 = MEM32(a1 + 116); /* 0268: l32i a9, a1, 116 */
  /* 026b: lsi f0, a1, 120 */
  /* 026e: lsi f1, a1, 112 */
  goto L_27a; /* 0271: j 27a <pm_beacon_offset_get_params+0x21a> */
L_274:;
  MEM8(a4 + 73) = a15; /* 0274: s8i a15, a4, 73 */
  MEMW(); /* 0277: memw  */
L_27a:;
  a3 = 0x2; /* 027a: movi.n a3, 2 */
  a12 = 0x20; /* 027c: movi.n a12, 32 */
  a11 = a1 + (16); /* 027e: addi a11, a1, 16 */
  a10 = a4 + (40); /* 0281: addi a10, a4, 40 */
  a2 = MEM32(a4 + 36); /* 0284: l32i.n a2, a4, 36 */
  a2 = a2 | a3; /* 0286: or a2, a2, a3 */
  MEM32(a4 + 36) = a2; /* 0289: s32i a2, a4, 36 */
  /* 028c: ssi f1, a1, 20 */
  MEM8(a1 + 32) = a9; /* 028f: s8i a9, a1, 32 */
  MEM8(a1 + 33) = a5; /* 0292: s8i a5, a1, 33 */
  MEMW(); /* 0295: memw  */
  /* 0298: ssi f0, a1, 44 */
  MEMW(); /* 029b: memw  */
  a8 = (uint32_t)&memcpy; /* 029e: l32r a8, 5c <pm_beacon_offset_get_params-0x4> (0 <pm_beacon_offset_get_params-0x60>) */ /* literal: GOT slot for memcpy */
  memcpy(a2, a3, a4, a5); /* call via literal slot */ /* 02a1: callx8 a8 */
  MEM32(a4 + 52) = a6; /* 02a4: s32i.n a6, a4, 52 */
L_2a6:;
  MEMW(); /* 02a6: memw  */
  return (int32_t)a2; /* 02a9: retw.n  */
}

/* pm_beacon_offset_sample @ pm_beacon_offset.o 0000002c size 201B bind GLOBAL
 * Calls: pm_beacon_offset_get_params[got], g_osi_funcs_p[got] | Data refs: s_pm_beacon_offset, g_pm, .bss.prev_last_tbtt_time$1, g_mesh_is_started, g_mesh_is_root, g_mesh_init_ps_type, g_osi_funcs_p, g_wifi_mac_time_delta, .bss.total_tbtt_count$0, pm_beacon_offset_get_params
 *   MMIO: 0x3FF73C00
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 2 call(s), 10 data ref(s)
 * Fidelity: medium - 77 instr, 9 branches, calls resolved */
int32_t pm_beacon_offset_sample(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .wifislpiram.9; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_2c:;
  /* 002c: entry a1, 32 */
  a3 = (uint32_t)&s_pm_beacon_offset; /* 002f: l32r a3, 0 <pm_beacon_offset_sample-0x2c> (0 <pm_beacon_offset_sample-0x2c>) */ /* literal @0x0: s_pm_beacon_offset */
  a4 = MEM16(a3 + 0); /* 0032: l16ui a4, a3, 0 */
  if (a4 == 0) goto L_f0; /* 0035: beqz a4, f0 <pm_beacon_offset_sample+0xc4> */
  a4 = (uint32_t)&g_pm; /* 0038: l32r a4, 4 <pm_beacon_offset_sample-0x28> (0 <pm_beacon_offset_sample-0x2c>) */ /* literal @0x4: g_pm */
  a8 = MEM32(a4 + 80); /* 003b: l32i a8, a4, 80 */
  a9 = MEM32(a4 + 84); /* 003e: l32i a9, a4, 84 */
  a5 = a8 | a9; /* 0041: or a5, a8, a9 */
  if (a5 == 0) goto L_f0; /* 0044: beqz a5, f0 <pm_beacon_offset_sample+0xc4> */
  a5 = (uint32_t)&bss_prev_last_tbtt_time_1; /* 0047: l32r a5, 8 <pm_beacon_offset_sample-0x24> (0 <pm_beacon_offset_sample-0x2c>) */ /* literal @0x8: .bss.prev_last_tbtt_time$1 */
  a10 = MEM32(a5 + 0); /* 004a: l32i.n a10, a5, 0 */
  if (a8 != a10) goto L_52; /* 004c: bne a8, a10, 52 <pm_beacon_offset_sample+0x26> */
  if (a9 == 0) goto L_f0; /* 004f: beqz a9, f0 <pm_beacon_offset_sample+0xc4> */
L_52:;
  a9 = 0x1; /* 0052: movi.n a9, 1 */
  MEM32(a5 + 0) = a8; /* 0054: s32i.n a8, a5, 0 */
  a8 = MEM32(a3 + 36); /* 0056: l32i.n a8, a3, 36 */
  a8 = a8 | a9; /* 0058: or a8, a8, a9 */
  MEM32(a3 + 36) = a8; /* 005b: s32i.n a8, a3, 36 */
  a8 = (uint32_t)&g_mesh_is_started; /* 005d: l32r a8, c <pm_beacon_offset_sample-0x20> (0 <pm_beacon_offset_sample-0x2c>) */ /* literal @0xC: g_mesh_is_started */
  a8 = MEM8(a8 + 0); /* 0060: l8ui a8, a8, 0 */
  if (a8 == 0) goto L_8c; /* 0063: beqz.n a8, 8c <pm_beacon_offset_sample+0x60> */
  a8 = (uint32_t)&g_mesh_is_root; /* 0065: l32r a8, 10 <pm_beacon_offset_sample-0x1c> (0 <pm_beacon_offset_sample-0x2c>) */ /* literal @0x10: g_mesh_is_root */
  MEMW(); /* 0068: memw  */
  a8 = MEM8(a8 + 0); /* 006b: l8ui a8, a8, 0 */
  a8 = (a8 >> 0) & 0xFF; /* 006e: extui a8, a8, 0, 8 */
  if (a8 != 0) goto L_8c; /* 0071: bnez.n a8, 8c <pm_beacon_offset_sample+0x60> */
  a8 = (uint32_t)&g_mesh_init_ps_type; /* 0073: l32r a8, 14 <pm_beacon_offset_sample-0x18> (0 <pm_beacon_offset_sample-0x2c>) */ /* literal @0x14: g_mesh_init_ps_type */
  a8 = MEM32(a8 + 0); /* 0076: l32i.n a8, a8, 0 */
  if (a8 == 0) goto L_8c; /* 0078: beqz.n a8, 8c <pm_beacon_offset_sample+0x60> */
  a8 = (uint32_t)&g_osi_funcs_p; /* 007a: l32r a8, 18 <pm_beacon_offset_sample-0x14> (0 <pm_beacon_offset_sample-0x2c>) */ /* literal @0x18: g_osi_funcs_p */
  a8 = MEM32(a8 + 0); /* 007d: l32i.n a8, a8, 0 */
  a10 = MEM32(a8 + 272); /* 007f: l32i a10, a8, 0x110 */
  MEMW(); /* 0082: memw  */
  ((int32_t(*)())a10)(a2, a3, a4, a5); /* 0085: callx8 a10 */ /* indirect */
  goto L_9b; /* 0088: j 9b <pm_beacon_offset_sample+0x6f> */
  /* 008b: .byte 00 */
L_8c:;
  a8 = 0x3FF73C00; /* 008c: l32r a8, 1c <pm_beacon_offset_sample-0x10> (3ff73c00 <pm_beacon_offset_get_params+0x3ff73ba0>) */ /* MMIO base */ @0x1C
  MEMW(); /* 008f: memw  */
  a10 = REG32(0x3FF73C00); /* 0092: l32i.n a10, a8, 0 */ /* MMIO read: base 0x3FF73C00+0 */
  a8 = (uint32_t)&g_wifi_mac_time_delta; /* 0094: l32r a8, 20 <pm_beacon_offset_sample-0xc> (0 <pm_beacon_offset_sample-0x2c>) */ /* literal @0x20: g_wifi_mac_time_delta */
  a8 = MEM32(a8 + 0); /* 0097: l32i.n a8, a8, 0 */
  a10 = a10 + a8; /* 0099: add.n a10, a10, a8 */
L_9b:;
  a2 = a2 >> (10 & 31); /* 009b: srli a2, a2, 10 */
  a5 = MEM32(a5 + 0); /* 009e: l32i.n a5, a5, 0 */
  a10 = a10 - a5; /* 00a0: sub a10, a10, a5 */
  a4 = MEM32(a4 + 44); /* 00a3: l32i.n a4, a4, 44 */
  /* 00a5: quou a10, a10, a4 */ /* UNMODELED: a10 clobbered */
  a4 = (uint32_t)&bss_total_tbtt_count_0; /* 00a8: l32r a4, 24 <pm_beacon_offset_sample-0x8> (0 <pm_beacon_offset_sample-0x2c>) */ /* literal @0x24: .bss.total_tbtt_count$0 */
  a5 = MEM32(a3 + 4); /* 00ab: l32i.n a5, a3, 4 */
  a2 = (a2 << 2) + a5; /* 00ad: addx2 a2, a2, a5 */
  a8 = MEM32(a4 + 0); /* 00b0: l32i.n a8, a4, 0 */
  a8 = a8 + (1); /* 00b2: addi.n a8, a8, 1 */
  a10 = a10 + a8; /* 00b4: add.n a10, a10, a8 */
  a8 = MEM16(a2 + 0); /* 00b6: l16ui a8, a2, 0 */
  a8 = a8 + (1); /* 00b9: addi.n a8, a8, 1 */
  MEM16(a2 + 0) = a8; /* 00bb: s16i a8, a2, 0 */
  MEMW(); /* 00be: memw  */
  a2 = MEM16(a3 + 0); /* 00c1: l16ui a2, a3, 0 */
  a2 = a2 + (-1); /* 00c4: addi.n a2, a2, -1 */
  a2 = (a2 >> 0) & 0xFFFF; /* 00c6: extui a2, a2, 0, 16 */
  MEM32(a4 + 0) = a10; /* 00c9: s32i.n a10, a4, 0 */
  MEM16(a3 + 0) = a2; /* 00cb: s16i a2, a3, 0 */
  MEMW(); /* 00ce: memw  */
  if (a2 != 0) goto L_f0; /* 00d1: bnez.n a2, f0 <pm_beacon_offset_sample+0xc4> */
  MEMW(); /* 00d3: memw  */
  a8 = (uint32_t)&pm_beacon_offset_get_params; /* 00d6: l32r a8, 28 <pm_beacon_offset_sample-0x4> (0 <pm_beacon_offset_sample-0x2c>) */ /* literal: GOT slot for pm_beacon_offset_get_params */
  pm_beacon_offset_get_params(a2, a3, a4, a5); /* call via literal slot */ /* 00d9: callx8 a8 */
  MEM32(a4 + 0) = a2; /* 00dc: s32i.n a2, a4, 0 */
  a4 = (uint32_t)&g_osi_funcs_p; /* 00de: l32r a4, 18 <pm_beacon_offset_sample-0x14> (0 <pm_beacon_offset_sample-0x2c>) */ /* literal @0x18: g_osi_funcs_p */
  a4 = MEM32(a4 + 0); /* 00e1: l32i.n a4, a4, 0 */
  a10 = MEM32(a3 + 4); /* 00e3: l32i.n a10, a3, 4 */
  a4 = MEM32(a4 + 176); /* 00e5: l32i a4, a4, 176 */
  MEMW(); /* 00e8: memw  */
  g_osi_funcs_p(a2, a3, a4, a5); /* call via literal slot */ /* 00eb: callx8 a4 */
  MEM32(a3 + 4) = a2; /* 00ee: s32i.n a2, a3, 4 */
L_f0:;
  MEMW(); /* 00f0: memw  */
  return (int32_t)a2; /* 00f3: retw.n  */
}

/* pm_beacon_offset_configure @ pm_beacon_offset.o 00000020 size 126B bind GLOBAL
 * Calls: __divsf3, __extendsfdf2, wifi_log | Data refs: .rodata_wlog_info.13, __divsf3, __extendsfdf2, s_pm_beacon_offset_config, wifi_log
 *   MMIO: none
 *   funcdb v3: 3 call(s), 5 ref(s); disasm: 5 call(s), 5 data ref(s)
 * Fidelity: medium - 45 instr, 1 branches, calls resolved */
int32_t pm_beacon_offset_configure(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pm_beacon_offset_configure; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_20:;
  /* 0020: entry a1, 48 */
  a3 = MEM16(a2 + 0); /* 0023: l16ui a3, a2, 0 */
  a8 = (uint32_t)&s_pm_beacon_offset_config; /* 0026: l32r a8, 0 <pm_beacon_offset_configure-0x20> (0 <pm_beacon_offset_configure-0x20>) */ /* literal @0x0: s_pm_beacon_offset_config */
  MEM16(a8 + 0) = a3; /* 0029: s16i a3, a8, 0 */
  MEMW(); /* 002c: memw  */
  if (a3 == 0) goto L_9c; /* 002f: beqz a3, 9c <pm_beacon_offset_configure+0x7c> */
  a9 = MEM8(a2 + 4); /* 0032: l8ui a9, a2, 4 */
  /* 0035: ufloat.s f0, a9, 0 */
  /* 0038: rfr a10, f0 */ /* UNMODELED: a10 clobbered */
  a4 = MEM8(a2 + 2); /* 003b: l8ui a4, a2, 2 */
  a5 = MEM8(a2 + 3); /* 003e: l8ui a5, a2, 3 */
  a2 = 0x1; /* 0041: movi.n a2, 1 */
  a2 = 0x1000; /* 0043: slli a2, a2, 12 */
  a11 = 0x42C80000; /* 0046: l32r a11, 8 <pm_beacon_offset_configure-0x18> (42c80000 <pm_beacon_offset_get_params+0x42c7ffa0>) */ @0x8
  MEM8(a8 + 2) = a4; /* 0049: s8i a4, a8, 2 */
  MEM8(a8 + 3) = a5; /* 004c: s8i a5, a8, 3 */
  MEM8(a8 + 4) = a9; /* 004f: s8i a9, a8, 4 */
  MEMW(); /* 0052: memw  */
  MEMW(); /* 0055: memw  */
  a8 = (uint32_t)&divsf3; /* 0058: l32r a8, c <pm_beacon_offset_configure-0x14> (0 <pm_beacon_offset_configure-0x20>) */ /* literal: GOT slot for __divsf3 */
  divsf3(a2, a3, a4, a5); /* call via literal slot */ /* 005b: callx8 a8 */
  a8 = (uint32_t)&extendsfdf2; /* 005e: l32r a8, 10 <pm_beacon_offset_configure-0x10> (0 <pm_beacon_offset_configure-0x20>) */ /* literal: GOT slot for __extendsfdf2 */
  extendsfdf2(a2, a3, a4, a5); /* call via literal slot */ /* 0061: callx8 a8 */
  /* 0064: ufloat.s f0, a5, 0 */
  MEM32(a1 + 12) = a11; /* 0067: s32i a11, a1, 12 */
  a11 = 0x42C80000; /* 006a: l32r a11, 8 <pm_beacon_offset_configure-0x18> (42c80000 <pm_beacon_offset_get_params+0x42c7ffa0>) */ @0x8
  MEM32(a1 + 8) = a10; /* 006d: s32i a10, a1, 8 */
  /* 0070: rfr a10, f0 */ /* UNMODELED: a10 clobbered */
  MEMW(); /* 0073: memw  */
  a8 = (uint32_t)&divsf3; /* 0076: l32r a8, 14 <pm_beacon_offset_configure-0xc> (0 <pm_beacon_offset_configure-0x20>) */ /* literal: GOT slot for __divsf3 */
  divsf3(a2, a3, a4, a5); /* call via literal slot */ /* 0079: callx8 a8 */
  a8 = (uint32_t)&extendsfdf2; /* 007c: l32r a8, 18 <pm_beacon_offset_configure-0x8> (0 <pm_beacon_offset_configure-0x20>) */ /* literal: GOT slot for __extendsfdf2 */
  extendsfdf2(a2, a3, a4, a5); /* call via literal slot */ /* 007f: callx8 a8 */
  a15 = a4; /* 0082: mov.n a15, a4 */
  a13 = (uint32_t)&lit_rodata_wlog_info_13; /* 0084: l32r a13, 4 <pm_beacon_offset_configure-0x1c> (0 <pm_beacon_offset_configure-0x20>) */ /* literal @0x4: .rodata_wlog_info.13 */
  a14 = a3; /* 0087: mov.n a14, a3 */
  a12 = 0x3; /* 0089: movi.n a12, 3 */
  MEM32(a1 + 0) = a10; /* 008b: s32i.n a10, a1, 0 */
  a10 = 0x6; /* 008d: movi.n a10, 6 */
  MEM32(a1 + 4) = a11; /* 008f: s32i.n a11, a1, 4 */
  a11 = a2; /* 0091: mov.n a11, a2 */
  MEMW(); /* 0093: memw  */
  a8 = (uint32_t)&wifi_log; /* 0096: l32r a8, 1c <pm_beacon_offset_configure-0x4> (0 <pm_beacon_offset_configure-0x20>) */ /* literal: GOT slot for wifi_log */
  wifi_log(a2, a3, a4, a5); /* call via literal slot */ /* 0099: callx8 a8 */
L_9c:;
  return (int32_t)a2; /* 009c: retw.n  */
}

/* pm_beacon_offset_set_rx_beacon_standard @ pm_beacon_offset.o 00000020 size 107B bind GLOBAL
 * Calls: __divsf3, __extendsfdf2, wifi_log | Data refs: .rodata_wlog_info.14, __divsf3, __extendsfdf2, s_pm_beacon_offset_config, wifi_log
 *   MMIO: none
 *   funcdb v3: 3 call(s), 5 ref(s); disasm: 5 call(s), 5 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t pm_beacon_offset_set_rx_beacon_standard(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pm_beacon_offset_set_rx_beacon_standard; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_20:;
  /* 0020: entry a1, 64 */
  a4 = (uint32_t)&s_pm_beacon_offset_config; /* 0023: l32r a4, 0 <pm_beacon_offset_set_rx_beacon_standard-0x20> (0 <pm_beacon_offset_set_rx_beacon_standard-0x20>) */ /* literal @0x0: s_pm_beacon_offset_config */
  a2 = (a2 >> 0) & 0xFF; /* 0026: extui a2, a2, 0, 8 */
  a3 = MEM8(a4 + 3); /* 0029: l8ui a3, a4, 3 */
  /* 002c: ufloat.s f0, a3, 0 */
  a3 = 0x1; /* 002f: movi.n a3, 1 */
  /* 0031: rfr a10, f0 */ /* UNMODELED: a10 clobbered */
  a11 = 0x42C80000; /* 0034: l32r a11, 4 <pm_beacon_offset_set_rx_beacon_standard-0x1c> (42c80000 <pm_beacon_offset_get_params+0x42c7ffa0>) */ @0x4
  a3 = 0x1000; /* 0037: slli a3, a3, 12 */
  a8 = (uint32_t)&divsf3; /* 003a: l32r a8, c <pm_beacon_offset_set_rx_beacon_standard-0x14> (0 <pm_beacon_offset_set_rx_beacon_standard-0x20>) */ /* literal: GOT slot for __divsf3 */
  divsf3(a2, a3, a4, a5); /* call via literal slot */ /* 003d: callx8 a8 */
  a8 = (uint32_t)&extendsfdf2; /* 0040: l32r a8, 10 <pm_beacon_offset_set_rx_beacon_standard-0x10> (0 <pm_beacon_offset_set_rx_beacon_standard-0x20>) */ /* literal: GOT slot for __extendsfdf2 */
  extendsfdf2(a2, a3, a4, a5); /* call via literal slot */ /* 0043: callx8 a8 */
  /* 0046: ufloat.s f0, a2, 0 */
  a15 = 0x42C80000; /* 0049: mov.n a15, a11 */
  a11 = 0x42C80000; /* 004b: l32r a11, 4 <pm_beacon_offset_set_rx_beacon_standard-0x1c> (42c80000 <pm_beacon_offset_get_params+0x42c7ffa0>) */ @0x4
  a14 = a10; /* 004e: mov.n a14, a10 */
  /* 0050: rfr a10, f0 */ /* UNMODELED: a10 clobbered */
  MEM32(a1 + 16) = a14; /* 0053: s32i.n a14, a1, 16 */
  MEM32(a1 + 20) = a15; /* 0055: s32i.n a15, a1, 20 */
  MEMW(); /* 0057: memw  */
  a8 = (uint32_t)&divsf3; /* 005a: l32r a8, 14 <pm_beacon_offset_set_rx_beacon_standard-0xc> (0 <pm_beacon_offset_set_rx_beacon_standard-0x20>) */ /* literal: GOT slot for __divsf3 */
  divsf3(a2, a3, a4, a5); /* call via literal slot */ /* 005d: callx8 a8 */
  a8 = (uint32_t)&extendsfdf2; /* 0060: l32r a8, 18 <pm_beacon_offset_set_rx_beacon_standard-0x8> (0 <pm_beacon_offset_set_rx_beacon_standard-0x20>) */ /* literal: GOT slot for __extendsfdf2 */
  extendsfdf2(a2, a3, a4, a5); /* call via literal slot */ /* 0063: callx8 a8 */
  a12 = 0x3; /* 0066: movi.n a12, 3 */
  a14 = MEM32(a1 + 16); /* 0068: l32i.n a14, a1, 16 */
  a15 = MEM32(a1 + 20); /* 006a: l32i.n a15, a1, 20 */
  a13 = (uint32_t)&lit_rodata_wlog_info_14; /* 006c: l32r a13, 8 <pm_beacon_offset_set_rx_beacon_standard-0x18> (0 <pm_beacon_offset_set_rx_beacon_standard-0x20>) */ /* literal @0x8: .rodata_wlog_info.14 */
  MEM32(a1 + 0) = a10; /* 006f: s32i.n a10, a1, 0 */
  a10 = 0x6; /* 0071: movi.n a10, 6 */
  MEM32(a1 + 4) = a11; /* 0073: s32i.n a11, a1, 4 */
  a11 = a3; /* 0075: mov.n a11, a3 */
  MEMW(); /* 0077: memw  */
  a8 = (uint32_t)&wifi_log; /* 007a: l32r a8, 1c <pm_beacon_offset_set_rx_beacon_standard-0x4> (0 <pm_beacon_offset_set_rx_beacon_standard-0x20>) */ /* literal: GOT slot for wifi_log */
  wifi_log(a2, a3, a4, a5); /* call via literal slot */ /* 007d: callx8 a8 */
  MEM8(a4 + 3) = a2; /* 0080: s8i a2, a4, 3 */
  MEMW(); /* 0083: memw  */
  MEMW(); /* 0086: memw  */
  return (int32_t)a2; /* 0089: retw.n  */
}

/* pm_beacon_offset_reset @ pm_beacon_offset.o 00000018 size 98B bind GLOBAL
 * Calls: g_osi_funcs_p[got], memset[got] | Data refs: s_pm_beacon_offset, g_pm_cfg, g_pm, g_osi_funcs_p, memset
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 2 call(s), 5 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t pm_beacon_offset_reset(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .wifislprxiram.10; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_18:;
  /* 0018: entry a1, 32 */
  a2 = (uint32_t)&s_pm_beacon_offset; /* 001b: l32r a2, 0 <pm_beacon_offset_reset-0x18> (0 <pm_beacon_offset_reset-0x18>) */ /* literal @0x0: s_pm_beacon_offset */
  a3 = 0x0; /* 001e: movi.n a3, 0 */
  a4 = 0x0; /* 0020: movi.n a4, 0 */
  a9 = (uint32_t)&g_pm_cfg; /* 0022: l32r a9, 8 <pm_beacon_offset_reset-0x10> (0 <pm_beacon_offset_reset-0x18>) */ /* literal @0x8: g_pm_cfg */
  MEM16(a2 + 0) = a3; /* 0025: s16i a3, a2, 0 */
  MEMW(); /* 0028: memw  */
  a3 = (uint32_t)&g_pm; /* 002b: l32r a3, 4 <pm_beacon_offset_reset-0x14> (0 <pm_beacon_offset_reset-0x18>) */ /* literal @0x4: g_pm */
  a8 = a3 + ((0x100) << 8); /* 002e: addmi a8, a3, 0x100 */
  a9 = MEM8(a9 + 37); /* 0031: l8ui a9, a9, 37 */
  a10 = MEM32(a2 + 4); /* 0034: l32i.n a10, a2, 4 */
  MEM32(a3 + 460) = a4; /* 0036: s32i a4, a3, 0x1cc */
  MEM8(a8 + 124) = a9; /* 0039: s8i a9, a8, 124 */
  MEMW(); /* 003c: memw  */
  if (a10 == a4) goto L_52; /* 003f: beq a10, a4, 52 <pm_beacon_offset_reset+0x3a> */
  a8 = (uint32_t)&g_osi_funcs_p; /* 0042: l32r a8, c <pm_beacon_offset_reset-0xc> (0 <pm_beacon_offset_reset-0x18>) */ /* literal @0xC: g_osi_funcs_p */
  a8 = MEM32(a8 + 0); /* 0045: l32i.n a8, a8, 0 */
  a8 = MEM32(a8 + 176); /* 0047: l32i a8, a8, 176 */
  MEMW(); /* 004a: memw  */
  g_osi_funcs_p(a2, a3, a4, a5); /* call via literal slot */ /* 004d: callx8 a8 */
  MEM32(a2 + 4) = a4; /* 0050: s32i.n a4, a2, 4 */
L_52:;
  a4 = 0x0; /* 0052: movi.n a4, 0 */
  a12 = 0x20; /* 0054: movi.n a12, 32 */
  a11 = 0x0; /* 0056: mov.n a11, a4 */
  a3 = a3 + ((0x200) << 8); /* 0058: addmi a3, a3, 0x200 */
  a10 = (uint32_t)&s_pm_beacon_offset; /* 005b: l32r a10, 10 <pm_beacon_offset_reset-0x8> (0 <pm_beacon_offset_reset-0x18>) */ /* literal @0x10: s_pm_beacon_offset */
  MEM32(a2 + 8) = a4; /* 005e: s32i.n a4, a2, 8 */
  MEM32(a2 + 12) = a4; /* 0060: s32i a4, a2, 12 */
  MEMW(); /* 0063: memw  */
  a8 = (uint32_t)&memset; /* 0066: l32r a8, 14 <pm_beacon_offset_reset-0x4> (0 <pm_beacon_offset_reset-0x18>) */ /* literal: GOT slot for memset */
  memset(a2, a3, a4, a5); /* call via literal slot */ /* 0069: callx8 a8 */
  MEM16(a2 + 72) = a4; /* 006c: s16i a4, a2, 72 */
  MEM8(a3 + 28) = a4; /* 006f: s8i a4, a3, 28 */
  MEMW(); /* 0072: memw  */
  MEMW(); /* 0075: memw  */
  return (int32_t)a2; /* 0078: retw.n  */
}

/* pm_beacon_offset_init @ pm_beacon_offset.o 00000010 size 30B bind GLOBAL
 * Calls: pm_beacon_offset_reset, g_osi_funcs_p[got] | Data refs: g_osi_funcs_p, pm_beacon_offset_reset, s_pm_beacon_offset, .text.pm_beacon_offset_resample_timeout
 *   MMIO: none
 *   funcdb v3: 1 call(s), 3 ref(s); disasm: 2 call(s), 4 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t pm_beacon_offset_init(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pm_beacon_offset_init; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_10:;
  /* 0010: entry a1, 32 */
  a8 = (uint32_t)&pm_beacon_offset_reset; /* 0013: l32r a8, c <pm_beacon_offset_init-0x4> (0 <pm_beacon_offset_init-0x10>) */ /* literal: GOT slot for pm_beacon_offset_reset */
  pm_beacon_offset_reset(a2, a3, a4, a5); /* call via literal slot */ /* 0016: callx8 a8 */
  a8 = (uint32_t)&g_osi_funcs_p; /* 0019: l32r a8, 8 <pm_beacon_offset_init-0x8> (0 <pm_beacon_offset_init-0x10>) */ /* literal @0x8: g_osi_funcs_p */
  a12 = 0x0; /* 001c: movi.n a12, 0 */
  a8 = MEM32(a8 + 0); /* 001e: l32i.n a8, a8, 0 */
  a11 = (uint32_t)&pm_beacon_offset_resample_timeout; /* 0020: l32r a11, 0 <pm_beacon_offset_init-0x10> (4 <pm_beacon_offset_init-0xc>) */ /* literal @0x0: .text.pm_beacon_offset_resample_timeout */
  a8 = MEM32(a8 + 244); /* 0023: l32i a8, a8, 244 */
  a10 = (uint32_t)&s_pm_beacon_offset; /* 0026: l32r a10, 4 <pm_beacon_offset_init-0xc> (0 <pm_beacon_offset_init-0x10>) */ /* literal @0x4: s_pm_beacon_offset */
  g_osi_funcs_p(a2, a3, a4, a5); /* call via literal slot */ /* 0029: callx8 a8 */
  return (int32_t)a2; /* 002c: retw.n  */
}

/* pm_beacon_offset_deinit @ pm_beacon_offset.o 0000000c size 40B bind GLOBAL
 * Calls: pm_beacon_offset_reset, g_osi_funcs_p[got] | Data refs: g_osi_funcs_p, pm_beacon_offset_reset, s_pm_beacon_offset
 *   MMIO: none
 *   funcdb v3: 1 call(s), 3 ref(s); disasm: 2 call(s), 3 data ref(s)
 * Fidelity: medium - 14 instr, 0 branches, calls resolved */
int32_t pm_beacon_offset_deinit(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pm_beacon_offset_deinit; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_c:;
  /* 000c: entry a1, 32 */
  a3 = (uint32_t)&g_osi_funcs_p; /* 000f: l32r a3, 4 <pm_beacon_offset_deinit-0x8> (0 <pm_beacon_offset_deinit-0xc>) */ /* literal @0x4: g_osi_funcs_p */
  a8 = MEM32(a3 + 0); /* 0012: l32i a8, a3, 0 */
  a2 = (uint32_t)&s_pm_beacon_offset; /* 0015: l32r a2, 0 <pm_beacon_offset_deinit-0xc> (0 <pm_beacon_offset_deinit-0xc>) */ /* literal @0x0: s_pm_beacon_offset */
  a10 = a2; /* 0018: mov.n a10, a2 */
  a8 = MEM32(a8 + 236); /* 001a: l32i a8, a8, 236 */
  ((int32_t(*)())a8)(a2, a3, a4, a5); /* 001d: callx8 a8 */ /* indirect */
  a10 = a2 | a2; /* 0020: or a10, a2, a2 */
  a3 = MEM32(a3 + 0); /* 0023: l32i a3, a3, 0 */
  a3 = MEM32(a3 + 240); /* 0026: l32i a3, a3, 240 */
  g_osi_funcs_p(a2, a3, a4, a5); /* call via literal slot */ /* 0029: callx8 a3 */
  a8 = (uint32_t)&pm_beacon_offset_reset; /* 002c: l32r a8, 8 <pm_beacon_offset_deinit-0x4> (0 <pm_beacon_offset_deinit-0xc>) */ /* literal: GOT slot for pm_beacon_offset_reset */
  pm_beacon_offset_reset(a2, a3, a4, a5); /* call via literal slot */ /* 002f: callx8 a8 */
  return (int32_t)a2; /* 0032: retw.n  */
}

/* pm_beacon_offset_sample_start @ pm_beacon_offset.o 00000028 size 130B bind GLOBAL
 * Calls: pm_beacon_offset_reset[got], wifi_log[got], wifi_log[got], memset[got], g_pm[got] | Data refs: s_pm_beacon_offset, s_pm_beacon_offset_config, pm_beacon_offset_reset, g_pm, .rodata_wlog_info.7, wifi_log, g_osi_funcs_p, .rodata_wlog_error.8, memset
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 5 call(s), 9 data ref(s)
 * Fidelity: medium - 48 instr, 5 branches, calls resolved */
int32_t pm_beacon_offset_sample_start(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .wifislprxiram.6; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_28:;
  /* 0028: entry a1, 32 */
  a3 = (uint32_t)&s_pm_beacon_offset; /* 002b: l32r a3, 0 <pm_beacon_offset_sample_start-0x28> (0 <pm_beacon_offset_sample_start-0x28>) */ /* literal @0x0: s_pm_beacon_offset */
  a5 = MEM16(a3 + 0); /* 002e: l16ui a5, a3, 0 */
  if (a5 != 0) goto L_a8; /* 0031: bnez a5, a8 <pm_beacon_offset_sample_start+0x80> */
  a4 = (uint32_t)&s_pm_beacon_offset_config; /* 0034: l32r a4, 4 <pm_beacon_offset_sample_start-0x24> (0 <pm_beacon_offset_sample_start-0x28>) */ /* literal @0x4: s_pm_beacon_offset_config */
  a2 = MEM16(a4 + 0); /* 0037: l16ui a2, a4, 0 */
  if (a2 == 0) goto L_a8; /* 003a: beqz a2, a8 <pm_beacon_offset_sample_start+0x80> */
  a8 = (uint32_t)&pm_beacon_offset_reset; /* 003d: l32r a8, 1c <pm_beacon_offset_sample_start-0xc> (0 <pm_beacon_offset_sample_start-0x28>) */ /* literal: GOT slot for pm_beacon_offset_reset */
  pm_beacon_offset_reset(a2, a3, a4, a5); /* call via literal slot */ /* 0040: callx8 a8 */
  a6 = 0xFF; /* 0043: movi a6, 255 */
  a2 = (uint32_t)&g_pm; /* 0046: l32r a2, 8 <pm_beacon_offset_sample_start-0x20> (0 <pm_beacon_offset_sample_start-0x28>) */ /* literal @0x8: g_pm */
  a2 = MEM32(a2 + 44); /* 0049: l32i.n a2, a2, 44 */
  a2 = a2 >> (10 & 31); /* 004b: srli a2, a2, 10 */
  if (a6 >= a2) goto L_69; /* 004e: bgeu a6, a2, 69 <pm_beacon_offset_sample_start+0x41> */
  a12 = 0x3; /* 0051: movi.n a12, 3 */
  a13 = (uint32_t)&lit_rodata_wlog_info_7; /* 0053: l32r a13, c <pm_beacon_offset_sample_start-0x1c> (0 <pm_beacon_offset_sample_start-0x28>) */ /* literal @0xC: .rodata_wlog_info.7 */
L_56:;
  a11 = 0x1; /* 0056: movi.n a11, 1 */
  a11 = 0x1000; /* 0058: slli a11, a11, 12 */
  a10 = 0x6; /* 005b: movi a10, 6 */
  a8 = (uint32_t)&wifi_log; /* 005e: l32r a8, 20 <pm_beacon_offset_sample_start-0x8> (0 <pm_beacon_offset_sample_start-0x28>) */ /* literal: GOT slot for wifi_log */
  wifi_log(a2, a3, a4, a5); /* call via literal slot */ /* 0061: callx8 a8 */
  goto L_a8; /* 0064: j a8 <pm_beacon_offset_sample_start+0x80> */
  /* 0067: .byte 00 */
  /* 0068: .byte 00 */
L_69:;
  a6 = (uint32_t)&g_osi_funcs_p; /* 0069: l32r a6, 10 <pm_beacon_offset_sample_start-0x18> (0 <pm_beacon_offset_sample_start-0x28>) */ /* literal @0x10: g_osi_funcs_p */
  a2 = a2 + a2; /* 006c: add.n a2, a2, a2 */
  a10 = a2; /* 006e: mov.n a10, a2 */
  a8 = MEM32(a6 + 0); /* 0070: l32i a8, a6, 0 */
  a8 = MEM32(a8 + 172); /* 0073: l32i a8, a8, 172 */
  wifi_log(a2, a3, a4, a5); /* call via literal slot */ /* 0076: callx8 a8 */
  a12 = 0x1; /* 0079: movi.n a12, 1 */
  MEM32(a3 + 4) = a10; /* 007b: s32i.n a10, a3, 4 */
  a13 = (uint32_t)&lit_rodata_wlog_error_8; /* 007d: l32r a13, 14 <pm_beacon_offset_sample_start-0x14> (0 <pm_beacon_offset_sample_start-0x28>) */ /* literal @0x14: .rodata_wlog_error.8 */
  if (a10 == 0) goto L_56; /* 0080: beqz a10, 56 <pm_beacon_offset_sample_start+0x2e> */
  a12 = a2; /* 0083: mov.n a12, a2 */
  a11 = a5 | a5; /* 0085: or a11, a5, a5 */
  MEMW(); /* 0088: memw  */
  a8 = (uint32_t)&memset; /* 008b: l32r a8, 24 <pm_beacon_offset_sample_start-0x4> (0 <pm_beacon_offset_sample_start-0x28>) */ /* literal: GOT slot for memset */
  memset(a2, a3, a4, a5); /* call via literal slot */ /* 008e: callx8 a8 */
  a2 = MEM16(a4 + 0); /* 0091: l16ui a2, a4, 0 */
  MEM16(a3 + 0) = a2; /* 0094: s16i a2, a3, 0 */
  MEMW(); /* 0097: memw  */
  a2 = MEM32(a6 + 0); /* 009a: l32i.n a2, a6, 0 */
  a10 = (uint32_t)&s_pm_beacon_offset; /* 009c: l32r a10, 18 <pm_beacon_offset_sample_start-0x10> (0 <pm_beacon_offset_sample_start-0x28>) */ /* literal @0x18: s_pm_beacon_offset */
  a2 = MEM32(a2 + 236); /* 009f: l32i a2, a2, 236 */
  MEMW(); /* 00a2: memw  */
  ((int32_t(*)())a2)(a2, a3, a4, a5); /* 00a5: callx8 a2 */ /* indirect */
L_a8:;
  return (int32_t)a2; /* 00a8: retw.n  */
}

/* pm_beacon_offset_resample_timeout_process @ pm_beacon_offset.o 00000004 size 11B bind GLOBAL
 * Calls: pm_on_sample_beacon | Data refs: pm_on_sample_beacon
 *   MMIO: none
 *   funcdb v3: 1 call(s), 1 ref(s); disasm: 1 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t pm_beacon_offset_resample_timeout_process(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pm_beacon_offset_resample_timeout_process; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a8 = (uint32_t)&pm_on_sample_beacon; /* 0007: l32r a8, 0 <pm_beacon_offset_resample_timeout_process-0x4> (0 <pm_beacon_offset_resample_timeout_process-0x4>) */ /* literal: GOT slot for pm_on_sample_beacon */
  pm_on_sample_beacon(a2, a3, a4, a5); /* call via literal slot */ /* 000a: callx8 a8 */
  return (int32_t)a2; /* 000d: retw.n  */
}

/* pm_beacon_offset_check @ pm_beacon_offset.o 00000060 size 453B bind GLOBAL
 * Calls: __divsf3, __extendsfdf2, pm_beacon_offset_get_rx_beacon_success_rate, wifi_event_post, wifi_log | Data refs: .rodata.pm_beacon_offset_check.str1.1, .rodata_wlog_debug.15, .rodata_wlog_debug.16, .rodata_wlog_debug.18, .rodata_wlog_info.17, __divsf3, __extendsfdf2, g_pm, pm_beacon_offset_get_rx_beacon_success_rate, s_pm_beacon_offset, s_pm_beacon_offset_config, wifi_event_post, wifi_log
 *   MMIO: none
 *   FP/data literals (loaded, never dereferenced - NOT MMIO): 0x3F000000
 *   funcdb v3: 5 call(s), 13 ref(s); disasm: 13 call(s), 13 data ref(s)
 * Fidelity: medium - 173 instr, 15 branches, 0 indirect; flow + direct calls mapped, GOT-indirects enumerated (verified against section disasm) */
int32_t pm_beacon_offset_check(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pm_beacon_offset_check; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_60:;
  /* 0060: entry a1, 96 */
  a5 = (uint32_t)&s_pm_beacon_offset_config; /* 0063: l32r a5, 8 <pm_beacon_offset_check-0x58> (0 <pm_beacon_offset_check-0x60>) */ /* literal @0x8: s_pm_beacon_offset_config */
  a9 = MEM16(a5 + 0); /* 0066: l16ui a9, a5, 0 */
  if (a9 == 0) goto L_220; /* 0069: beqz a9, 220 <pm_beacon_offset_check+0x1c0> */
  a4 = (uint32_t)&s_pm_beacon_offset; /* 006c: l32r a4, c <pm_beacon_offset_check-0x54> (0 <pm_beacon_offset_check-0x60>) */ /* literal @0xC: s_pm_beacon_offset */
  a8 = MEM8(a4 + 73); /* 006f: l8ui a8, a4, 73 */
  if (a8 == 0) goto L_129; /* 0072: beqz a8, 129 <pm_beacon_offset_check+0xc9> */
  a8 = (uint32_t)&g_pm; /* 0075: l32r a8, 10 <pm_beacon_offset_check-0x50> (0 <pm_beacon_offset_check-0x60>) */ /* literal @0x10: g_pm */
  a8 = MEM16(a8 + 386); /* 0078: l16si a8, a8, 0x182 */
  a8 = (uint32_t)((uint64_t)a8 * a9); /* 007b: mull a8, a8, a9 */
  a9 = MEM32(a4 + 8); /* 007e: l32i.n a9, a4, 8 */
  if (a9 >= a8) goto L_86; /* 0080: bgeu a9, a8, 86 <pm_beacon_offset_check+0x26> */
  goto L_129; /* 0083: j 129 <pm_beacon_offset_check+0xc9> */
L_86:;
  a8 = (uint32_t)&pm_beacon_offset_get_rx_beacon_success_rate; /* 0086: l32r a8, 2c <pm_beacon_offset_check-0x34> (0 <pm_beacon_offset_check-0x60>) */ /* literal: GOT slot for pm_beacon_offset_get_rx_beacon_success_rate */
  pm_beacon_offset_get_rx_beacon_success_rate(a2, a3, a4, a5); /* call via literal slot */ /* 0089: callx8 a8 */
  /* 008c: wfr f0, a10 */
  a6 = 0x3F000000; /* 008f: l32r a6, 14 <pm_beacon_offset_check-0x4c> (3f000000 <pm_beacon_offset_check+0x3effffa0>) */ /* MMIO base */ @0x14
  /* 0092: wfr f3, a6 */
  /* 0095: lsi f1, a4, 44 */
  /* 0098: mul.s f2, f1, f3 */
  /* 009b: olt.s b0, f2, f0 */
  if (FP_b0) goto L_c1; /* 009e: bt b0, c1 <pm_beacon_offset_check+0x61> */
L_a1:;
  a5 = 0x0; /* 00a1: movi.n a5, 0 */
  a12 = 0x4; /* 00a3: movi.n a12, 4 */
  a11 = a1 + (32); /* 00a5: addi a11, a1, 32 */
  a10 = 0x2E; /* 00a8: movi.n a10, 46 */
  MEM8(a4 + 72) = a5; /* 00aa: s8i a5, a4, 72 */
  MEMW(); /* 00ad: memw  */
  /* 00b0: ssi f0, a1, 32 */
  MEMW(); /* 00b3: memw  */
  a8 = (uint32_t)&wifi_event_post; /* 00b6: l32r a8, 30 <pm_beacon_offset_check-0x30> (0 <pm_beacon_offset_check-0x60>) */ /* literal: GOT slot for wifi_event_post */
  wifi_event_post(a2, a3, a4, a5); /* call via literal slot */ /* 00b9: callx8 a8 */
  goto L_122; /* 00bc: j 122 <pm_beacon_offset_check+0xc2> */
  /* 00bf: .byte 00 */
  /* 00c0: .byte 00 */
L_c1:;
  a5 = MEM8(a5 + 4); /* 00c1: l8ui a5, a5, 4 */
  /* 00c4: ufloat.s f2, a5, 0 */
  /* 00c7: rfr a10, f2 */ /* UNMODELED: a10 clobbered */
  a11 = 0x42C80000; /* 00ca: l32r a11, 18 <pm_beacon_offset_check-0x48> (42c80000 <pm_beacon_offset_check+0x42c7ffa0>) */ @0x18
  /* 00cd: ssi f0, a1, 52 */
  /* 00d0: ssi f1, a1, 48 */
  MEMW(); /* 00d3: memw  */
  a8 = (uint32_t)&divsf3; /* 00d6: l32r a8, 34 <pm_beacon_offset_check-0x2c> (0 <pm_beacon_offset_check-0x60>) */ /* literal: GOT slot for __divsf3 */
  divsf3(a2, a3, a4, a5); /* call via literal slot */ /* 00d9: callx8 a8 */
  /* 00dc: wfr f3, a10 */
  /* 00df: lsi f1, a1, 48 */
  /* 00e2: sub.s f1, f1, f3 */
  /* 00e5: lsi f0, a1, 52 */
  /* 00e8: olt.s b0, f1, f0 */
  if (FP_b0) goto L_11a; /* 00eb: bt b0, 11a <pm_beacon_offset_check+0xba> */
  a5 = MEM8(a4 + 72); /* 00ee: l8ui a5, a4, 72 */
  if (a5 != 0) goto L_a1; /* 00f1: bnez a5, a1 <pm_beacon_offset_check+0x41> */
  /* 00f4: rfr a10, f0 */ /* UNMODELED: a10 clobbered */
  a8 = (uint32_t)&extendsfdf2; /* 00f7: l32r a8, 38 <pm_beacon_offset_check-0x28> (0 <pm_beacon_offset_check-0x60>) */ /* literal: GOT slot for __extendsfdf2 */
  extendsfdf2(a2, a3, a4, a5); /* call via literal slot */ /* 00fa: callx8 a8 */
  a15 = 0x42C80000; /* 00fd: mov.n a15, a11 */
  a13 = (uint32_t)&lit_rodata_wlog_debug_15; /* 00ff: l32r a13, 1c <pm_beacon_offset_check-0x44> (0 <pm_beacon_offset_check-0x60>) */ /* literal @0x1C: .rodata_wlog_debug.15 */
  a11 = 0x1; /* 0102: movi.n a11, 1 */
  a14 = a10; /* 0104: mov.n a14, a10 */
  a12 = 0x4; /* 0106: movi.n a12, 4 */
  a11 = 0x1000; /* 0108: slli a11, a11, 12 */
  a10 = 0x6; /* 010b: movi a10, 6 */
  a8 = (uint32_t)&wifi_log; /* 010e: l32r a8, 3c <pm_beacon_offset_check-0x24> (0 <pm_beacon_offset_check-0x60>) */ /* literal: GOT slot for wifi_log */
  wifi_log(a2, a3, a4, a5); /* call via literal slot */ /* 0111: callx8 a8 */
  a5 = 0x1; /* 0114: movi.n a5, 1 */
  goto L_11c; /* 0116: j 11c <pm_beacon_offset_check+0xbc> */
  /* 0119: .byte 00 */
L_11a:;
  a5 = 0x0; /* 011a: movi.n a5, 0 */
L_11c:;
  MEM8(a4 + 72) = a5; /* 011c: s8i a5, a4, 72 */
  MEMW(); /* 011f: memw  */
L_122:;
  a5 = 0x0; /* 0122: movi.n a5, 0 */
  MEM32(a4 + 12) = a5; /* 0124: s32i.n a5, a4, 12 */
  MEM32(a4 + 8) = a5; /* 0126: s32i a5, a4, 8 */
L_129:;
  a5 = MEM32(a4 + 36); /* 0129: l32i.n a5, a4, 36 */
  if (!((a5 >> 0) & 1)) goto L_16a; /* 012b: bbci a5, 0, 16a <pm_beacon_offset_check+0x10a> */
  a14 = a2; /* 012e: mov.n a14, a2 */
  a15 = a2; /* 0130: mov.n a15, a2 */
  if (a2 == 0) goto L_138; /* 0132: beqz.n a2, 138 <pm_beacon_offset_check+0xd8> */
  a14 = MEM32(a2 + 0); /* 0134: l32i.n a14, a2, 0 */
  a15 = MEM32(a2 + 4); /* 0136: l32i.n a15, a2, 4 */
L_138:;
  a11 = 0x1; /* 0138: movi.n a11, 1 */
  a11 = 0x1000; /* 013a: slli a11, a11, 12 */
  a5 = (uint32_t)&g_pm; /* 013d: l32r a5, 10 <pm_beacon_offset_check-0x50> (0 <pm_beacon_offset_check-0x60>) */ /* literal @0x10: g_pm */
  a2 = MEM32(a5 + 80); /* 0140: l32i a2, a5, 80 */
  a2 = a3 - a2; /* 0143: sub a2, a3, a2 */
  a8 = MEM32(a5 + 84); /* 0146: l32i a8, a5, 84 */
  a5 = 0x1; /* 0149: movi.n a5, 1 */
  if (a3 < a2) goto L_150; /* 014b: bltu a3, a2, 150 <pm_beacon_offset_check+0xf0> */
  a5 = 0x0; /* 014e: movi.n a5, 0 */
L_150:;
  a8 = -a8; /* 0150: neg a8, a8 */
  a8 = a8 - a5; /* 0153: sub a8, a8, a5 */
  a13 = (uint32_t)&lit_rodata_wlog_debug_16; /* 0156: l32r a13, 20 <pm_beacon_offset_check-0x40> (0 <pm_beacon_offset_check-0x60>) */ /* literal @0x20: .rodata_wlog_debug.16 */
  a12 = 0x4; /* 0159: movi.n a12, 4 */
  a10 = 0x6; /* 015b: movi.n a10, 6 */
  MEM32(a1 + 0) = a2; /* 015d: s32i.n a2, a1, 0 */
  MEM32(a1 + 4) = a8; /* 015f: s32i.n a8, a1, 4 */
  MEMW(); /* 0161: memw  */
  a8 = (uint32_t)&wifi_log; /* 0164: l32r a8, 40 <pm_beacon_offset_check-0x20> (0 <pm_beacon_offset_check-0x60>) */ /* literal: GOT slot for wifi_log */
  wifi_log(a2, a3, a4, a5); /* call via literal slot */ /* 0167: callx8 a8 */
L_16a:;
  a2 = MEM32(a4 + 36); /* 016a: l32i.n a2, a4, 36 */
  if ((a2 >> 1) & 1) goto L_172; /* 016c: bbsi a2, 1, 172 <pm_beacon_offset_check+0x112> */
  goto L_21c; /* 016f: j 21c <pm_beacon_offset_check+0x1bc> */
L_172:;
  a2 = MEM8(a4 + 73); /* 0172: l8ui a2, a4, 73 */
  a5 = (uint32_t)&lit_rodata_pm_beacon_offset_check_str1_1; /* 0175: l32r a5, 0 <pm_beacon_offset_check-0x60> (0 <pm_beacon_offset_check-0x60>) */ /* literal @0x0: .rodata.pm_beacon_offset_check.str1.1 */
  if (a2 != 0) goto L_17d; /* 0178: bnez.n a2, 17d <pm_beacon_offset_check+0x11d> */
  a5 = (uint32_t)&lit_rodata_pm_beacon_offset_check_str1_1; /* 017a: l32r a5, 4 <pm_beacon_offset_check-0x5c> (9 <pm_beacon_offset_check-0x57>) */ /* literal @0x4: .rodata.pm_beacon_offset_check.str1.1 */
L_17d:;
  a2 = 0x1; /* 017d: movi.n a2, 1 */
  a2 = 0x1000; /* 017f: slli a2, a2, 12 */
  a3 = (uint32_t)&g_pm; /* 0182: l32r a3, 10 <pm_beacon_offset_check-0x50> (0 <pm_beacon_offset_check-0x60>) */ /* literal @0x10: g_pm */
  a8 = MEM32(a3 + 464); /* 0185: l32i a8, a3, 0x1d0 */
  MEM32(a1 + 24) = a8; /* 0188: s32i.n a8, a1, 24 */
  a10 = MEM32(a4 + 44); /* 018a: l32i.n a10, a4, 44 */
  MEMW(); /* 018c: memw  */
  a8 = (uint32_t)&extendsfdf2; /* 018f: l32r a8, 44 <pm_beacon_offset_check-0x1c> (0 <pm_beacon_offset_check-0x60>) */ /* literal: GOT slot for __extendsfdf2 */
  extendsfdf2(a2, a3, a4, a5); /* call via literal slot */ /* 0192: callx8 a8 */
  MEM32(a1 + 16) = a10; /* 0195: s32i.n a10, a1, 16 */
  MEM32(a1 + 20) = a11; /* 0197: s32i.n a11, a1, 20 */
  a10 = MEM32(a4 + 52); /* 0199: l32i.n a10, a4, 52 */
  MEMW(); /* 019b: memw  */
  a8 = (uint32_t)&extendsfdf2; /* 019e: l32r a8, 48 <pm_beacon_offset_check-0x18> (0 <pm_beacon_offset_check-0x60>) */ /* literal: GOT slot for __extendsfdf2 */
  extendsfdf2(a2, a3, a4, a5); /* call via literal slot */ /* 01a1: callx8 a8 */
  a8 = a3 + ((0x100) << 8); /* 01a4: addmi a8, a3, 0x100 */
  a12 = 0x3; /* 01a7: movi.n a12, 3 */
  MEM32(a1 + 8) = a10; /* 01a9: s32i.n a10, a1, 8 */
  a14 = a5; /* 01ab: mov.n a14, a5 */
  a10 = 0x6; /* 01ad: movi.n a10, 6 */
  MEM32(a1 + 12) = a11; /* 01af: s32i.n a11, a1, 12 */
  a11 = a2; /* 01b1: mov.n a11, a2 */
  a8 = MEM8(a8 + 124); /* 01b3: l8ui a8, a8, 124 */
  a8 = a8 << (10 & 31); /* 01b6: slli a8, a8, 10 */
  MEM32(a1 + 0) = a8; /* 01b9: s32i.n a8, a1, 0 */
  a15 = MEM32(a3 + 460); /* 01bb: l32i a15, a3, 0x1cc */
  a13 = (uint32_t)&lit_rodata_wlog_info_17; /* 01be: l32r a13, 24 <pm_beacon_offset_check-0x3c> (0 <pm_beacon_offset_check-0x60>) */ /* literal @0x24: .rodata_wlog_info.17 */
  MEMW(); /* 01c1: memw  */
  a8 = (uint32_t)&wifi_log; /* 01c4: l32r a8, 4c <pm_beacon_offset_check-0x14> (0 <pm_beacon_offset_check-0x60>) */ /* literal: GOT slot for wifi_log */
  wifi_log(a2, a3, a4, a5); /* call via literal slot */ /* 01c7: callx8 a8 */
  a10 = MEM32(a4 + 40); /* 01ca: l32i.n a10, a4, 40 */
  a8 = (uint32_t)&extendsfdf2; /* 01cc: l32r a8, 50 <pm_beacon_offset_check-0x10> (0 <pm_beacon_offset_check-0x60>) */ /* literal: GOT slot for __extendsfdf2 */
  extendsfdf2(a2, a3, a4, a5); /* call via literal slot */ /* 01cf: callx8 a8 */
  a14 = a10; /* 01d2: mov.n a14, a10 */
  a3 = MEM16(a4 + 58); /* 01d4: l16ui a3, a4, 58 */
  MEM32(a1 + 24) = a3; /* 01d7: s32i.n a3, a1, 24 */
  a3 = MEM8(a4 + 57); /* 01d9: l8ui a3, a4, 57 */
  MEM32(a1 + 20) = a3; /* 01dc: s32i.n a3, a1, 20 */
  a3 = MEM8(a4 + 56); /* 01de: l8ui a3, a4, 56 */
  MEM32(a1 + 16) = a3; /* 01e1: s32i.n a3, a1, 16 */
  a10 = MEM32(a4 + 48); /* 01e3: l32i.n a10, a4, 48 */
  MEM32(a1 + 48) = a14; /* 01e5: s32i.n a14, a1, 48 */
  MEM32(a1 + 52) = a11; /* 01e7: s32i.n a11, a1, 52 */
  MEMW(); /* 01e9: memw  */
  a8 = (uint32_t)&extendsfdf2; /* 01ec: l32r a8, 54 <pm_beacon_offset_check-0xc> (0 <pm_beacon_offset_check-0x60>) */ /* literal: GOT slot for __extendsfdf2 */
  extendsfdf2(a2, a3, a4, a5); /* call via literal slot */ /* 01ef: callx8 a8 */
  MEM32(a1 + 8) = a10; /* 01f2: s32i.n a10, a1, 8 */
  MEM32(a1 + 12) = a11; /* 01f4: s32i.n a11, a1, 12 */
  a10 = MEM32(a4 + 68); /* 01f6: l32i a10, a4, 68 */
  MEMW(); /* 01f9: memw  */
  a8 = (uint32_t)&extendsfdf2; /* 01fc: l32r a8, 58 <pm_beacon_offset_check-0x8> (0 <pm_beacon_offset_check-0x60>) */ /* literal: GOT slot for __extendsfdf2 */
  extendsfdf2(a2, a3, a4, a5); /* call via literal slot */ /* 01ff: callx8 a8 */
  a12 = 0x4; /* 0202: movi.n a12, 4 */
  a14 = MEM32(a1 + 48); /* 0204: l32i.n a14, a1, 48 */
  a15 = MEM32(a1 + 52); /* 0206: l32i.n a15, a1, 52 */
  a13 = (uint32_t)&lit_rodata_wlog_debug_18; /* 0208: l32r a13, 28 <pm_beacon_offset_check-0x38> (0 <pm_beacon_offset_check-0x60>) */ /* literal @0x28: .rodata_wlog_debug.18 */
  MEM32(a1 + 0) = a10; /* 020b: s32i.n a10, a1, 0 */
  a10 = 0x6; /* 020d: movi.n a10, 6 */
  MEM32(a1 + 4) = a11; /* 020f: s32i.n a11, a1, 4 */
  a11 = a2; /* 0211: mov.n a11, a2 */
  MEMW(); /* 0213: memw  */
  a8 = (uint32_t)&wifi_log; /* 0216: l32r a8, 5c <pm_beacon_offset_check-0x4> (0 <pm_beacon_offset_check-0x60>) */ /* literal: GOT slot for wifi_log */
  wifi_log(a2, a3, a4, a5); /* call via literal slot */ /* 0219: callx8 a8 */
L_21c:;
  a2 = 0x0; /* 021c: movi.n a2, 0 */
  MEM32(a4 + 36) = a2; /* 021e: s32i.n a2, a4, 36 */
L_220:;
  MEMW(); /* 0220: memw  */
  return (int32_t)a2; /* 0223: retw.n  */
}

/* empty_func_p_pvoid_r_void @ pm_beacon_offset.o 00000000 size 5B bind GLOBAL
 * Calls: none | Data refs: none
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t empty_func_p_pvoid_r_void(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.empty_func_p_pvoid_r_void; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_0:;
  /* 0000: entry a1, 32 */
  return (int32_t)a2; /* 0003: retw.n  */
}

/* pm_beacon_offset_funcs_empty_init @ pm_beacon_offset.o 0000002c size 78B bind GLOBAL
 * Calls: none | Data refs: empty_func_p_pconfg_r_void, empty_func_p_ptsf_u32_r_void, empty_func_p_pvoid_r_void, empty_func_p_u32_r_void, empty_func_p_u8_r_void, empty_func_p_u8_u8_float_float_pparams_r_void, empty_func_p_u8_u8_pu16_pfloat_r_void, empty_func_p_void_r_bool, empty_func_p_void_r_float, empty_func_p_void_r_void, ptr_beacon_offset_funcs
 *   MMIO: none
 *   funcdb v3: 0 call(s), 11 ref(s); disasm: 0 call(s), 11 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t pm_beacon_offset_funcs_empty_init(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pm_beacon_offset_funcs_empty_init; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_2c:;
  /* 002c: entry a1, 32 */
  a8 = (uint32_t)&ptr_beacon_offset_funcs; /* 002f: l32r a8, 0 <pm_beacon_offset_funcs_empty_init-0x2c> (0 <pm_beacon_offset_funcs_empty_init-0x2c>) */ /* literal @0x0: ptr_beacon_offset_funcs */
  a11 = (uint32_t)&empty_func_p_void_r_bool; /* 0032: l32r a11, c <pm_beacon_offset_funcs_empty_init-0x20> (0 <pm_beacon_offset_funcs_empty_init-0x2c>) */ /* literal @0xC: empty_func_p_void_r_bool */
  a8 = MEM32(a8 + 0); /* 0035: l32i.n a8, a8, 0 */
  MEM32(a8 + 12) = a11; /* 0037: s32i.n a11, a8, 12 */
  MEM32(a8 + 16) = a11; /* 0039: s32i.n a11, a8, 16 */
  a11 = (uint32_t)&empty_func_p_pconfg_r_void; /* 003b: l32r a11, 10 <pm_beacon_offset_funcs_empty_init-0x1c> (0 <pm_beacon_offset_funcs_empty_init-0x2c>) */ /* literal @0x10: empty_func_p_pconfg_r_void */
  MEM32(a8 + 20) = a11; /* 003e: s32i.n a11, a8, 20 */
  a11 = (uint32_t)&empty_func_p_pvoid_r_void; /* 0040: l32r a11, 14 <pm_beacon_offset_funcs_empty_init-0x18> (0 <pm_beacon_offset_funcs_empty_init-0x2c>) */ /* literal @0x14: empty_func_p_pvoid_r_void */
  a9 = (uint32_t)&empty_func_p_void_r_void; /* 0043: l32r a9, 4 <pm_beacon_offset_funcs_empty_init-0x28> (0 <pm_beacon_offset_funcs_empty_init-0x2c>) */ /* literal @0x4: empty_func_p_void_r_void */
  MEM32(a8 + 24) = a11; /* 0046: s32i.n a11, a8, 24 */
  a11 = (uint32_t)&empty_func_p_u8_r_void; /* 0048: l32r a11, 18 <pm_beacon_offset_funcs_empty_init-0x14> (0 <pm_beacon_offset_funcs_empty_init-0x2c>) */ /* literal @0x18: empty_func_p_u8_r_void */
  MEM32(a8 + 0) = a9; /* 004b: s32i.n a9, a8, 0 */
  MEM32(a8 + 8) = a9; /* 004d: s32i.n a9, a8, 8 */
  MEM32(a8 + 28) = a11; /* 004f: s32i.n a11, a8, 28 */
  MEM32(a8 + 36) = a9; /* 0051: s32i.n a9, a8, 36 */
  a11 = (uint32_t)&empty_func_p_void_r_float; /* 0053: l32r a11, 1c <pm_beacon_offset_funcs_empty_init-0x10> (0 <pm_beacon_offset_funcs_empty_init-0x2c>) */ /* literal @0x1C: empty_func_p_void_r_float */
  MEM32(a8 + 40) = a9; /* 0056: s32i.n a9, a8, 40 */
  MEM32(a8 + 48) = a9; /* 0058: s32i.n a9, a8, 48 */
  MEM32(a8 + 52) = a9; /* 005a: s32i.n a9, a8, 52 */
  a9 = (uint32_t)&empty_func_p_u8_u8_pu16_pfloat_r_void; /* 005c: l32r a9, 24 <pm_beacon_offset_funcs_empty_init-0x8> (0 <pm_beacon_offset_funcs_empty_init-0x2c>) */ /* literal @0x24: empty_func_p_u8_u8_pu16_pfloat_r_void */
  a10 = (uint32_t)&empty_func_p_u32_r_void; /* 005f: l32r a10, 8 <pm_beacon_offset_funcs_empty_init-0x24> (0 <pm_beacon_offset_funcs_empty_init-0x2c>) */ /* literal @0x8: empty_func_p_u32_r_void */
  MEM32(a8 + 32) = a11; /* 0062: s32i.n a11, a8, 32 */
  MEM32(a8 + 56) = a9; /* 0064: s32i.n a9, a8, 56 */
  a11 = (uint32_t)&empty_func_p_ptsf_u32_r_void; /* 0066: l32r a11, 20 <pm_beacon_offset_funcs_empty_init-0xc> (0 <pm_beacon_offset_funcs_empty_init-0x2c>) */ /* literal @0x20: empty_func_p_ptsf_u32_r_void */
  a9 = (uint32_t)&empty_func_p_u8_u8_float_float_pparams_r_void; /* 0069: l32r a9, 28 <pm_beacon_offset_funcs_empty_init-0x4> (0 <pm_beacon_offset_funcs_empty_init-0x2c>) */ /* literal @0x28: empty_func_p_u8_u8_float_float_pparams_r_void */
  MEM32(a8 + 4) = a10; /* 006c: s32i.n a10, a8, 4 */
  MEM32(a8 + 44) = a11; /* 006e: s32i.n a11, a8, 44 */
  MEM32(a8 + 60) = a9; /* 0070: s32i.n a9, a8, 60 */
  MEM32(a8 + 64) = a10; /* 0072: s32i a10, a8, 64 */
  MEMW(); /* 0075: memw  */
  return (int32_t)a2; /* 0078: retw.n  */
}

/* pm_funcs_init @ pm_beacon_offset.o 00000014 size 62B bind GLOBAL
 * Calls: pm_beacon_offset_funcs_init, wifi_log, g_osi_funcs_p[got] | Data refs: .rodata_wlog_error.20, g_osi_funcs_p, pm_beacon_offset_funcs_init, ptr_beacon_offset_funcs, wifi_log
 *   MMIO: none
 *   funcdb v3: 2 call(s), 5 ref(s); disasm: 3 call(s), 5 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t pm_funcs_init(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pm_funcs_init; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_14:;
  /* 0014: entry a1, 32 */
  a2 = (uint32_t)&g_osi_funcs_p; /* 0017: l32r a2, 0 <pm_funcs_init-0x14> (0 <pm_funcs_init-0x14>) */ /* literal @0x0: g_osi_funcs_p */
  a11 = 0x44; /* 001a: movi.n a11, 68 */
  a10 = 0x1; /* 001c: movi a10, 1 */
  a2 = MEM32(a2 + 0); /* 001f: l32i a2, a2, 0 */
  a2 = MEM32(a2 + 356); /* 0022: l32i a2, a2, 0x164 */
  g_osi_funcs_p(a2, a3, a4, a5); /* call via literal slot */ /* 0025: callx8 a2 */
  a2 = (uint32_t)&ptr_beacon_offset_funcs; /* 0028: l32r a2, 4 <pm_funcs_init-0x10> (0 <pm_funcs_init-0x14>) */ /* literal @0x4: ptr_beacon_offset_funcs */
  MEM32(a2 + 0) = a10; /* 002b: s32i.n a10, a2, 0 */
  if (a10 != 0) goto L_48; /* 002d: bnez.n a10, 48 <pm_funcs_init+0x34> */
  a12 = 0x1; /* 002f: movi.n a12, 1 */
  a11 = 0x1; /* 0031: mov.n a11, a12 */
  a10 = 0x6; /* 0033: movi.n a10, 6 */
  a13 = (uint32_t)&lit_rodata_wlog_error_20; /* 0035: l32r a13, 8 <pm_funcs_init-0xc> (0 <pm_funcs_init-0x14>) */ /* literal @0x8: .rodata_wlog_error.20 */
  a2 = 0x101; /* 0038: movi a2, 0x101 */
  MEMW(); /* 003b: memw  */
  a8 = (uint32_t)&wifi_log; /* 003e: l32r a8, c <pm_funcs_init-0x8> (0 <pm_funcs_init-0x14>) */ /* literal: GOT slot for wifi_log */
  wifi_log(a2, a3, a4, a5); /* call via literal slot */ /* 0041: callx8 a8 */
  goto L_50; /* 0044: j 50 <pm_funcs_init+0x3c> */
  /* 0047: .byte 00 */
L_48:;
  a8 = (uint32_t)&pm_beacon_offset_funcs_init; /* 0048: l32r a8, 10 <pm_funcs_init-0x4> (0 <pm_funcs_init-0x14>) */ /* literal: GOT slot for pm_beacon_offset_funcs_init */
  pm_beacon_offset_funcs_init(a2, a3, a4, a5); /* call via literal slot */ /* 004b: callx8 a8 */
  a2 = 0x0; /* 004e: movi.n a2, 0 */
L_50:;
  return (int32_t)a2; /* 0050: retw.n  */
}

/* pm_funcs_deinit @ pm_beacon_offset.o 00000008 size 32B bind GLOBAL
 * Calls: g_osi_funcs_p[got] | Data refs: g_osi_funcs_p, ptr_beacon_offset_funcs
 *   MMIO: none
 *   funcdb v3: 0 call(s), 2 ref(s); disasm: 1 call(s), 2 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t pm_funcs_deinit(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pm_funcs_deinit; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_8:;
  /* 0008: entry a1, 32 */
  a2 = (uint32_t)&ptr_beacon_offset_funcs; /* 000b: l32r a2, 0 <pm_funcs_deinit-0x8> (0 <pm_funcs_deinit-0x8>) */ /* literal @0x0: ptr_beacon_offset_funcs */
  a10 = MEM32(a2 + 0); /* 000e: l32i.n a10, a2, 0 */
  if (a10 == 0) goto L_21; /* 0010: beqz.n a10, 21 <pm_funcs_deinit+0x19> */
  a8 = (uint32_t)&g_osi_funcs_p; /* 0012: l32r a8, 4 <pm_funcs_deinit-0x4> (0 <pm_funcs_deinit-0x8>) */ /* literal @0x4: g_osi_funcs_p */
  a8 = MEM32(a8 + 0); /* 0015: l32i.n a8, a8, 0 */
  a8 = MEM32(a8 + 176); /* 0017: l32i a8, a8, 176 */
  g_osi_funcs_p(a2, a3, a4, a5); /* call via literal slot */ /* 001a: callx8 a8 */
  a8 = 0x0; /* 001d: movi.n a8, 0 */
  MEM32(a2 + 0) = a8; /* 001f: s32i.n a8, a2, 0 */
L_21:;
  a2 = 0x0; /* 0021: movi.n a2, 0 */
  MEMW(); /* 0023: memw  */
  return (int32_t)a2; /* 0026: retw.n  */
}

/* pm_beacon_offset_resample_timeout @ pm_beacon_offset.o 00000000 size 21B bind LOCAL
 * Calls: pp_timer_process[got] | Data refs: pp_timer_process
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 1 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
static int32_t pm_beacon_offset_resample_timeout(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pm_beacon_offset_resample_timeout; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
  /* 0000: .word 0x00000000 (literal pool) */
  /* 0004: entry a1, 32 */
  a11 = 0x0; /* 0007: movi.n a11, 0 */
  a10 = 0xC; /* 0009: movi.n a10, 12 */
  a8 = (uint32_t)&pp_timer_process; /* 000b: l32r a8, 0 <.text.pm_beacon_offset_resample_timeout> (0 <.text.pm_beacon_offset_resample_timeout>) */ /* literal: GOT slot for pp_timer_process */
  pp_timer_process(a2, a3, a4, a5); /* call via literal slot */ /* 000e: callx8 a8 */
  return (int32_t)a2; /* 0011: retw.n  */
}

/* pm_beacon_offset_funcs_init @ pm_beacon_offset.o 00000048 size 117B bind LOCAL
 * Calls: none | Data refs: ptr_beacon_offset_funcs, pm_beacon_offset_sample_start, pm_beacon_offset_sample, pm_beacon_offset_reset, pm_beacon_offset_is_sampling, pm_beacon_offset_is_enabled, pm_beacon_offset_configure, pm_beacon_offset_resample_timeout_process, pm_beacon_offset_set_rx_beacon_standard, pm_beacon_offset_get_rx_beacon_success_rate, pm_beacon_offset_add_total_counter, pm_beacon_offset_add_loss_counter, pm_beacon_offset_check, pm_beacon_offset_init, pm_beacon_offset_deinit, pm_beacon_offset_get_average, pm_beacon_offset_get_expect, pm_beacon_offset_get_params
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 18 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
static int32_t pm_beacon_offset_funcs_init(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pm_beacon_offset_funcs_init; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_48:;
  /* 0048: entry a1, 32 */
  a8 = (uint32_t)&ptr_beacon_offset_funcs; /* 004b: l32r a8, 0 <pm_beacon_offset_funcs_init-0x48> (0 <pm_beacon_offset_funcs_init-0x48>) */ /* literal @0x0: ptr_beacon_offset_funcs */
  a9 = (uint32_t)&pm_beacon_offset_sample_start; /* 004e: l32r a9, 4 <pm_beacon_offset_funcs_init-0x44> (0 <pm_beacon_offset_funcs_init-0x48>) */ /* literal @0x4: pm_beacon_offset_sample_start */
  a8 = MEM32(a8 + 0); /* 0051: l32i.n a8, a8, 0 */
  MEM32(a8 + 0) = a9; /* 0053: s32i.n a9, a8, 0 */
  a9 = (uint32_t)&pm_beacon_offset_sample; /* 0055: l32r a9, 8 <pm_beacon_offset_funcs_init-0x40> (0 <pm_beacon_offset_funcs_init-0x48>) */ /* literal @0x8: pm_beacon_offset_sample */
  MEM32(a8 + 4) = a9; /* 0058: s32i.n a9, a8, 4 */
  a9 = (uint32_t)&pm_beacon_offset_reset; /* 005a: l32r a9, c <pm_beacon_offset_funcs_init-0x3c> (0 <pm_beacon_offset_funcs_init-0x48>) */ /* literal @0xC: pm_beacon_offset_reset */
  MEM32(a8 + 8) = a9; /* 005d: s32i.n a9, a8, 8 */
  a9 = (uint32_t)&pm_beacon_offset_is_sampling; /* 005f: l32r a9, 10 <pm_beacon_offset_funcs_init-0x38> (0 <pm_beacon_offset_funcs_init-0x48>) */ /* literal @0x10: pm_beacon_offset_is_sampling */
  MEM32(a8 + 12) = a9; /* 0062: s32i.n a9, a8, 12 */
  a9 = (uint32_t)&pm_beacon_offset_is_enabled; /* 0064: l32r a9, 14 <pm_beacon_offset_funcs_init-0x34> (0 <pm_beacon_offset_funcs_init-0x48>) */ /* literal @0x14: pm_beacon_offset_is_enabled */
  MEM32(a8 + 16) = a9; /* 0067: s32i.n a9, a8, 16 */
  a9 = (uint32_t)&pm_beacon_offset_configure; /* 0069: l32r a9, 18 <pm_beacon_offset_funcs_init-0x30> (0 <pm_beacon_offset_funcs_init-0x48>) */ /* literal @0x18: pm_beacon_offset_configure */
  MEM32(a8 + 20) = a9; /* 006c: s32i.n a9, a8, 20 */
  a9 = (uint32_t)&pm_beacon_offset_resample_timeout_process; /* 006e: l32r a9, 1c <pm_beacon_offset_funcs_init-0x2c> (0 <pm_beacon_offset_funcs_init-0x48>) */ /* literal @0x1C: pm_beacon_offset_resample_timeout_process */
  MEM32(a8 + 24) = a9; /* 0071: s32i.n a9, a8, 24 */
  a9 = (uint32_t)&pm_beacon_offset_set_rx_beacon_standard; /* 0073: l32r a9, 20 <pm_beacon_offset_funcs_init-0x28> (0 <pm_beacon_offset_funcs_init-0x48>) */ /* literal @0x20: pm_beacon_offset_set_rx_beacon_standard */
  MEM32(a8 + 28) = a9; /* 0076: s32i.n a9, a8, 28 */
  a9 = (uint32_t)&pm_beacon_offset_get_rx_beacon_success_rate; /* 0078: l32r a9, 24 <pm_beacon_offset_funcs_init-0x24> (0 <pm_beacon_offset_funcs_init-0x48>) */ /* literal @0x24: pm_beacon_offset_get_rx_beacon_success_rate */
  MEM32(a8 + 32) = a9; /* 007b: s32i.n a9, a8, 32 */
  a9 = (uint32_t)&pm_beacon_offset_add_total_counter; /* 007d: l32r a9, 28 <pm_beacon_offset_funcs_init-0x20> (0 <pm_beacon_offset_funcs_init-0x48>) */ /* literal @0x28: pm_beacon_offset_add_total_counter */
  MEM32(a8 + 36) = a9; /* 0080: s32i.n a9, a8, 36 */
  a9 = (uint32_t)&pm_beacon_offset_add_loss_counter; /* 0082: l32r a9, 2c <pm_beacon_offset_funcs_init-0x1c> (0 <pm_beacon_offset_funcs_init-0x48>) */ /* literal @0x2C: pm_beacon_offset_add_loss_counter */
  MEM32(a8 + 40) = a9; /* 0085: s32i.n a9, a8, 40 */
  a9 = (uint32_t)&pm_beacon_offset_check; /* 0087: l32r a9, 30 <pm_beacon_offset_funcs_init-0x18> (0 <pm_beacon_offset_funcs_init-0x48>) */ /* literal @0x30: pm_beacon_offset_check */
  MEM32(a8 + 44) = a9; /* 008a: s32i.n a9, a8, 44 */
  a9 = (uint32_t)&pm_beacon_offset_init; /* 008c: l32r a9, 34 <pm_beacon_offset_funcs_init-0x14> (0 <pm_beacon_offset_funcs_init-0x48>) */ /* literal @0x34: pm_beacon_offset_init */
  MEM32(a8 + 48) = a9; /* 008f: s32i.n a9, a8, 48 */
  a9 = (uint32_t)&pm_beacon_offset_deinit; /* 0091: l32r a9, 38 <pm_beacon_offset_funcs_init-0x10> (0 <pm_beacon_offset_funcs_init-0x48>) */ /* literal @0x38: pm_beacon_offset_deinit */
  MEM32(a8 + 52) = a9; /* 0094: s32i.n a9, a8, 52 */
  a9 = (uint32_t)&pm_beacon_offset_get_average; /* 0096: l32r a9, 3c <pm_beacon_offset_funcs_init-0xc> (0 <pm_beacon_offset_funcs_init-0x48>) */ /* literal @0x3C: pm_beacon_offset_get_average */
  MEM32(a8 + 56) = a9; /* 0099: s32i.n a9, a8, 56 */
  a9 = (uint32_t)&pm_beacon_offset_get_expect; /* 009b: l32r a9, 40 <pm_beacon_offset_funcs_init-0x8> (0 <pm_beacon_offset_funcs_init-0x48>) */ /* literal @0x40: pm_beacon_offset_get_expect */
  MEM32(a8 + 60) = a9; /* 009e: s32i.n a9, a8, 60 */
  a9 = (uint32_t)&pm_beacon_offset_get_params; /* 00a0: l32r a9, 44 <pm_beacon_offset_funcs_init-0x4> (0 <pm_beacon_offset_funcs_init-0x48>) */ /* literal @0x44: pm_beacon_offset_get_params */
  MEM32(a8 + 64) = a9; /* 00a3: s32i a9, a8, 64 */
  MEMW(); /* 00a6: memw  */
  return (int32_t)a2; /* 00a9: retw.n  */
}

