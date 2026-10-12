/* ===== pp_debug.o : reconstructed from libpp.a (ESP32, Xtensa, esp-2022r1) =====
 * Toolchain: xtensa-esp32-elf (GCC 11.2.0 crosstool-NG esp-2022r1).
 * ABI: args a2..a7, return a2 (all functions take a2..a7, return int32_t).
 * memw barriers preserved as MEMW(). MMIO as REG32/REG16/REG8(addr).
 * Calls with unknown arg counts are modeled with 4 live args (a2..a5);
 * a2..a7 are clobbered across calls (windowed-ABI approximation).
 * Sections: .iram1.3, .iram1.4, .text.dbg_ebuf_loc_show, .text.dbg_his_lmac_eb_show, .text.dbg_his_lmac_event_show, .text.dbg_his_lmac_int_show, .text.dbg_his_lmac_rx_show, .text.dbg_his_lmac_tx_show, .text.dbg_lmac_diag_statis_dump, .text.dbg_lmac_hw_statis_dump, .text.dbg_lmac_init, .text.dbg_lmac_ps_statis_dump, .text.dbg_lmac_ps_statis_reset, .text.dbg_lmac_rxtx_statis_dump, .text.dbg_lmac_statis_dump, .text.dbg_perf_path_set, .text.dbg_perf_path_show, .text.dbg_perf_throughput_cal, .text.wifi_gpio_debug_max_event_get
 * Undefined refs (11): __divsf3, __extendsfdf2, __floatundisf, esf_buf_statis_dump, g_mesh_init_ps_type, g_mesh_is_root, g_mesh_is_started, g_osi_funcs_p, g_wifi_mac_time_delta, memset, wifi_log
 */
#include <stdint.h>
#define REG32(a) (*(volatile uint32_t *)(a))
#define REG16(a) (*(volatile uint16_t *)(a))
#define REG8(a)  (*(volatile uint8_t *)(a))
#define MEM32(a) (*(volatile uint32_t *)(a))
#define MEM16(a) (*(volatile uint16_t *)(a))
#define MEM8(a)  (*(volatile uint8_t *)(a))
#define MEMW() __asm__ volatile("memw" ::: "memory")

extern int32_t dram1_2();
extern uint32_t rodata_wlog_info_5; /* .rodata_wlog_info.5 */
extern int32_t wifi_log();
extern uint32_t rodata_wlog_info_6; /* .rodata_wlog_info.6 */
extern uint32_t rodata_dbg_lmac_rxtx_statis_dump_str1_1; /* .rodata.dbg_lmac_rxtx_statis_dump.str1.1 */
extern uint32_t rodata_wlog_info_7; /* .rodata_wlog_info.7 */
uint32_t g_lmac_cnt; /* defined here (.bss/.data); was: g_lmac_cnt */
extern uint32_t rodata_wlog_info_8; /* .rodata_wlog_info.8 */
extern uint32_t rodata_wlog_info_9; /* .rodata_wlog_info.9 */
extern uint32_t rodata_wlog_info_10; /* .rodata_wlog_info.10 */
extern uint32_t rodata_wlog_info_11; /* .rodata_wlog_info.11 */
extern uint32_t rodata_wlog_info_12; /* .rodata_wlog_info.12 */
extern uint32_t rodata_wlog_info_13; /* .rodata_wlog_info.13 */
extern uint32_t rodata_wlog_info_14; /* .rodata_wlog_info.14 */
extern uint32_t rodata_wlog_info_15; /* .rodata_wlog_info.15 */
extern uint32_t rodata_wlog_info_16; /* .rodata_wlog_info.16 */
extern uint32_t rodata_wlog_info_17; /* .rodata_wlog_info.17 */
extern uint32_t rodata_wlog_info_18; /* .rodata_wlog_info.18 */
extern uint32_t rodata_dbg_lmac_hw_statis_dump_str1_1; /* .rodata.dbg_lmac_hw_statis_dump.str1.1 */
extern uint32_t rodata_wlog_info_19; /* .rodata_wlog_info.19 */
extern uint32_t rodata_wlog_info_20; /* .rodata_wlog_info.20 */
extern uint32_t rodata_wlog_info_21; /* .rodata_wlog_info.21 */
extern uint32_t rodata_wlog_info_22; /* .rodata_wlog_info.22 */
extern uint32_t rodata_wlog_info_23; /* .rodata_wlog_info.23 */
extern uint32_t rodata_wlog_info_24; /* .rodata_wlog_info.24 */
extern uint32_t rodata_wlog_info_25; /* .rodata_wlog_info.25 */
extern uint32_t rodata_wlog_info_26; /* .rodata_wlog_info.26 */
extern uint32_t rodata_dbg_lmac_diag_statis_dump_str1_1; /* .rodata.dbg_lmac_diag_statis_dump.str1.1 */
extern uint32_t rodata_wlog_info_27; /* .rodata_wlog_info.27 */
extern uint32_t rodata_wlog_info_28; /* .rodata_wlog_info.28 */
extern uint32_t rodata_wlog_info_29; /* .rodata_wlog_info.29 */
extern uint32_t rodata_wlog_info_30; /* .rodata_wlog_info.30 */
extern uint32_t rodata_wlog_info_31; /* .rodata_wlog_info.31 */
extern uint32_t rodata_wlog_info_32; /* .rodata_wlog_info.32 */
extern uint32_t rodata_dbg_lmac_ps_statis_dump_str1_1; /* .rodata.dbg_lmac_ps_statis_dump.str1.1 */
extern uint32_t rodata_wlog_info_33; /* .rodata_wlog_info.33 */
uint32_t g_pm_cnt; /* defined here (.bss/.data); was: g_pm_cnt */
extern int32_t floatundisf();
extern int32_t divsf3();
extern int32_t extendsfdf2();
extern uint32_t rodata_wlog_info_34; /* .rodata_wlog_info.34 */
extern int32_t memset();
extern int32_t esf_buf_statis_dump();
extern uint32_t g_mesh_is_started; /* g_mesh_is_started */
extern uint32_t g_mesh_is_root; /* g_mesh_is_root */
extern uint32_t g_mesh_init_ps_type; /* g_mesh_init_ps_type */
extern uint32_t g_osi_funcs_p; /* g_osi_funcs_p */
extern uint32_t g_wifi_mac_time_delta; /* g_wifi_mac_time_delta */
extern uint32_t bss_s_total; /* .bss.s_total (verify defined-here with nm) */
extern uint32_t bss_s_t_old; /* .bss.s_t_old (verify defined-here with nm) */
extern uint32_t rodata_wlog_info_35; /* .rodata_wlog_info.35 */

/* pool[wifi_gpio_debug]: +0x0=0x00000000(.dram1.2) */
/* pool[wifi_set_gpio_debug_cb]: +0x0=0x00000000(.dram1.2) */
/* pool[dbg_lmac_rxtx_statis_dump]: +0x0=0x00000000(.rodata_wlog_info.5), +0x7c=0x00000000(wifi_log), +0x4=0x00000000(.rodata_wlog_info.6), +0x80=0x00000000(wifi_log), +0x14=0x0000000B(.rodata.dbg_lmac_rxtx_statis_dump.str1.1), +0x18=0x0000000E(.rodata.dbg_lmac_rxtx_statis_dump.str1.1), +0x1c=0x00000012(.rodata.dbg_lmac_rxtx_statis_dump.str1.1), +0x8=0x00000000(.rodata.dbg_lmac_rxtx_statis_dump.str1.1), +0xc=0x00000004(.rodata.dbg_lmac_rxtx_statis_dump.str1.1), +0x10=0x00000000(.rodata_wlog_info.7), +0x84=0x00000000(wifi_log), +0x20=0x00000000(g_lmac_cnt), +0x24=0x00000000(.rodata_wlog_info.8), +0x88=0x00000000(wifi_log), +0x28=0x00000000(.rodata_wlog_info.9), +0x8c=0x00000000(wifi_log), +0x2c=0x00000000(.rodata_wlog_info.10), +0x90=0x00000000(wifi_log), +0x3c=0x00000021(.rodata.dbg_lmac_rxtx_statis_dump.str1.1), +0x40=0x00000026(.rodata.dbg_lmac_rxtx_statis_dump.str1.1), +0x44=0x0000002B(.rodata.dbg_lmac_rxtx_statis_dump.str1.1), +0x30=0x00000016(.rodata.dbg_lmac_rxtx_statis_dump.str1.1), +0x34=0x0000001B(.rodata.dbg_lmac_rxtx_statis_dump.str1.1), +0x38=0x00000000(.rodata_wlog_info.11), +0x94=0x00000000(wifi_log), +0x48=0x00000000(.rodata_wlog_info.12), +0x98=0x00000000(wifi_log), +0x4c=0x00000000(.rodata_wlog_info.13), +0x9c=0x00000000(wifi_log), +0x50=0x00000000(.rodata_wlog_info.14), +0xa0=0x00000000(wifi_log), +0x60=0x0000003E(.rodata.dbg_lmac_rxtx_statis_dump.str1.1), +0x64=0x00000045(.rodata.dbg_lmac_rxtx_statis_dump.str1.1), +0x54=0x00000030(.rodata.dbg_lmac_rxtx_statis_dump.str1.1), +0x58=0x00000037(.rodata.dbg_lmac_rxtx_statis_dump.str1.1), +0x5c=0x00000000(.rodata_wlog_info.15), +0xa4=0x00000000(wifi_log), +0x68=0x3FF732CC, +0x6c=0x3FF732D0, +0x74=0x3FF732DC, +0x70=0x3FF732AC, +0x78=0x00000000(.rodata_wlog_info.16), +0xa8=0x00000000(wifi_log) */
/* pool[dbg_lmac_hw_statis_dump]: +0x0=0x00000000(.rodata_wlog_info.17), +0xe8=0x00000000(wifi_log), +0x4=0x00000000(.rodata_wlog_info.18), +0xec=0x00000000(wifi_log), +0x14=0x00000011(.rodata.dbg_lmac_hw_statis_dump.str1.1), +0x18=0x0000001A(.rodata.dbg_lmac_hw_statis_dump.str1.1), +0x1c=0x00000021(.rodata.dbg_lmac_hw_statis_dump.str1.1), +0x20=0x0000002A(.rodata.dbg_lmac_hw_statis_dump.str1.1), +0x24=0x0000002F(.rodata.dbg_lmac_hw_statis_dump.str1.1), +0x28=0x00000036(.rodata.dbg_lmac_hw_statis_dump.str1.1), +0x8=0x00000000(.rodata.dbg_lmac_hw_statis_dump.str1.1), +0xc=0x00000009(.rodata.dbg_lmac_hw_statis_dump.str1.1), +0x10=0x00000000(.rodata_wlog_info.19), +0xf0=0x00000000(wifi_log), +0x2c=0x3FF73094, +0x30=0x3FF7328C, +0x38=0x3FF73294, +0x3c=0x3FF73298, +0x34=0x3FF73290, +0x40=0x3FF7329C, +0x44=0x3FF732A0, +0x48=0x3FF732A4, +0x4c=0x00000000(.rodata_wlog_info.20), +0xf4=0x00000000(wifi_log), +0x5c=0x0000004B(.rodata.dbg_lmac_hw_statis_dump.str1.1), +0x60=0x00000054(.rodata.dbg_lmac_hw_statis_dump.str1.1), +0x64=0x0000005C(.rodata.dbg_lmac_hw_statis_dump.str1.1), +0x68=0x00000064(.rodata.dbg_lmac_hw_statis_dump.str1.1), +0x6c=0x0000006C(.rodata.dbg_lmac_hw_statis_dump.str1.1), +0x70=0x00000073(.rodata.dbg_lmac_hw_statis_dump.str1.1), +0x50=0x0000003E(.rodata.dbg_lmac_hw_statis_dump.str1.1), +0x54=0x00000045(.rodata.dbg_lmac_hw_statis_dump.str1.1), +0x58=0x00000000(.rodata_wlog_info.21), +0xf8=0x00000000(wifi_log), +0x74=0x3FF732A8, +0x78=0x3FF732B0, +0x80=0x3FF732B8, +0x84=0x3FF732BC, +0x7c=0x3FF732B4, +0x88=0x3FF732C0, +0x8c=0x3FF732C4, +0x90=0x3FF732C8, +0x94=0x00000000(.rodata_wlog_info.22), +0xfc=0x00000000(wifi_log), +0xa4=0x0000008B(.rodata.dbg_lmac_hw_statis_dump.str1.1), +0xa8=0x00000091(.rodata.dbg_lmac_hw_statis_dump.str1.1), +0xac=0x00000098(.rodata.dbg_lmac_hw_statis_dump.str1.1), +0xb0=0x000000A0(.rodata.dbg_lmac_hw_statis_dump.str1.1), +0xb4=0x000000A6(.rodata.dbg_lmac_hw_statis_dump.str1.1), +0xb8=0x000000AC(.rodata.dbg_lmac_hw_statis_dump.str1.1), +0xbc=0x000000B2(.rodata.dbg_lmac_hw_statis_dump.str1.1), +0x98=0x0000007B(.rodata.dbg_lmac_hw_statis_dump.str1.1), +0x9c=0x00000082(.rodata.dbg_lmac_hw_statis_dump.str1.1), +0xa0=0x00000000(.rodata_wlog_info.23), +0x100=0x00000000(wifi_log), +0xc0=0x3FF732E0, +0xc4=0x3FF732D8, +0xc8=0x3FF73D58, +0xcc=0x3FF73D5C, +0xd0=0x3FF73D60, +0xd4=0x3FF73D64, +0xd8=0x3FF73D68, +0xdc=0x3FF73D6C, +0xe0=0x3FF73D70, +0xe4=0x00000000(.rodata_wlog_info.24), +0x104=0x00000000(wifi_log) */
/* pool[dbg_lmac_diag_statis_dump]: +0x0=0x00000000(.rodata_wlog_info.25), +0x80=0x00000000(wifi_log), +0x4=0x00000000(.rodata_wlog_info.26), +0x84=0x00000000(wifi_log), +0x14=0x0000000C(.rodata.dbg_lmac_diag_statis_dump.str1.1), +0x18=0x00000012(.rodata.dbg_lmac_diag_statis_dump.str1.1), +0x1c=0x00000018(.rodata.dbg_lmac_diag_statis_dump.str1.1), +0x20=0x0000001E(.rodata.dbg_lmac_diag_statis_dump.str1.1), +0x24=0x00000024(.rodata.dbg_lmac_diag_statis_dump.str1.1), +0x8=0x00000000(.rodata.dbg_lmac_diag_statis_dump.str1.1), +0xc=0x00000006(.rodata.dbg_lmac_diag_statis_dump.str1.1), +0x10=0x00000000(.rodata_wlog_info.27), +0x88=0x00000000(wifi_log), +0x28=0x3FF73DAC, +0x2c=0x3FF73DB0, +0x34=0x3FF73DB8, +0x38=0x3FF732F0, +0x30=0x3FF73DB4, +0x3c=0x3FF732F4, +0x40=0x3FF732F8, +0x44=0x00000000(.rodata_wlog_info.28), +0x8c=0x00000000(wifi_log), +0x54=0x00000036(.rodata.dbg_lmac_diag_statis_dump.str1.1), +0x58=0x0000003E(.rodata.dbg_lmac_diag_statis_dump.str1.1), +0x5c=0x00000045(.rodata.dbg_lmac_diag_statis_dump.str1.1), +0x60=0x0000004C(.rodata.dbg_lmac_diag_statis_dump.str1.1), +0x48=0x0000002A(.rodata.dbg_lmac_diag_statis_dump.str1.1), +0x4c=0x00000030(.rodata.dbg_lmac_diag_statis_dump.str1.1), +0x50=0x00000000(.rodata_wlog_info.29), +0x90=0x00000000(wifi_log), +0x64=0x3FF732FC, +0x68=0x3FF73424, +0x70=0x3FF7342C, +0x74=0x3FF73430, +0x6c=0x3FF73428, +0x78=0x3FF73DBC, +0x7c=0x00000000(.rodata_wlog_info.30), +0x94=0x00000000(wifi_log) */
/* pool[dbg_lmac_ps_statis_dump]: +0x0=0x00000000(.rodata_wlog_info.31), +0x58=0x00000000(wifi_log), +0x4=0x00000000(.rodata_wlog_info.32), +0x5c=0x00000000(wifi_log), +0x14=0x0000000C(.rodata.dbg_lmac_ps_statis_dump.str1.1), +0x18=0x00000014(.rodata.dbg_lmac_ps_statis_dump.str1.1), +0x1c=0x0000001B(.rodata.dbg_lmac_ps_statis_dump.str1.1), +0x20=0x00000021(.rodata.dbg_lmac_ps_statis_dump.str1.1), +0x24=0x00000028(.rodata.dbg_lmac_ps_statis_dump.str1.1), +0x28=0x0000002D(.rodata.dbg_lmac_ps_statis_dump.str1.1), +0x2c=0x00000033(.rodata.dbg_lmac_ps_statis_dump.str1.1), +0x30=0x0000003A(.rodata.dbg_lmac_ps_statis_dump.str1.1), +0x34=0x00000040(.rodata.dbg_lmac_ps_statis_dump.str1.1), +0x38=0x00000046(.rodata.dbg_lmac_ps_statis_dump.str1.1), +0x3c=0x0000004D(.rodata.dbg_lmac_ps_statis_dump.str1.1), +0x40=0x00000053(.rodata.dbg_lmac_ps_statis_dump.str1.1), +0x44=0x0000005B(.rodata.dbg_lmac_ps_statis_dump.str1.1), +0x48=0x00000063(.rodata.dbg_lmac_ps_statis_dump.str1.1), +0x8=0x00000000(.rodata.dbg_lmac_ps_statis_dump.str1.1), +0xc=0x00000007(.rodata.dbg_lmac_ps_statis_dump.str1.1), +0x10=0x00000000(.rodata_wlog_info.33), +0x60=0x00000000(wifi_log), +0x4c=0x00000000(g_pm_cnt), +0x64=0x00000000(__floatundisf), +0x54=0x42C80000, +0x68=0x00000000(__floatundisf), +0x6c=0x00000000(__divsf3), +0x70=0x00000000(__extendsfdf2), +0x50=0x00000000(.rodata_wlog_info.34), +0x74=0x00000000(wifi_log) */
/* pool[dbg_lmac_ps_statis_reset]: +0x0=0x00000000(g_pm_cnt), +0x4=0x00000000(memset) */
/* pool[dbg_lmac_statis_dump]: +0x0=0x00000000(esf_buf_statis_dump), +0x4=0x00000000(dbg_lmac_rxtx_statis_dump), +0x8=0x00000000(dbg_lmac_hw_statis_dump), +0xc=0x00000000(dbg_lmac_diag_statis_dump), +0x10=0x00000000(dbg_lmac_ps_statis_dump) */
/* pool[dbg_perf_throughput_cal]: +0x0=0x00000000(g_mesh_is_started), +0x4=0x00000000(g_mesh_is_root), +0x8=0x00000000(g_mesh_init_ps_type), +0xc=0x00000000(g_osi_funcs_p), +0x10=0x3FF73C00, +0x14=0x00000000(g_wifi_mac_time_delta), +0x18=0x00000000(.bss.s_total), +0x1c=0x00000000(.bss.s_t_old), +0x20=0x007A11FF, +0x24=0x00000000(.rodata_wlog_info.35), +0x28=0x00000000(wifi_log) */

/* wifi_gpio_debug @ pp_debug.o 00000004 size 19B bind GLOBAL
 * Calls: .dram1.2[got] | Data refs: .dram1.2
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 1 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t wifi_gpio_debug(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .iram1.3; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a8 = (uint32_t)&dram1_2; /* 0007: l32r a8, 0 <wifi_gpio_debug-0x4> (0 <wifi_gpio_debug-0x4>) */ /* literal @0x0: .dram1.2 */
  a10 = a2; /* 000a: mov.n a10, a2 */
  a11 = a3; /* 000c: mov.n a11, a3 */
  a8 = MEM32(a8 + 0); /* 000e: l32i.n a8, a8, 0 */
  if (a8 == 0) goto L_15; /* 0010: beqz.n a8, 15 <wifi_gpio_debug+0x11> */
  dram1_2(a2, a3, a4, a5); /* call via literal slot */ /* 0012: callx8 a8 */
L_15:;
  return (int32_t)a2; /* 0015: retw.n  */
}

/* wifi_set_gpio_debug_cb @ pp_debug.o 00000004 size 17B bind GLOBAL
 * Calls: none | Data refs: .dram1.2
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t wifi_set_gpio_debug_cb(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .iram1.4; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  if (a2 == 0) goto L_10; /* 0007: beqz a2, 10 <wifi_set_gpio_debug_cb+0xc> */
  a8 = (uint32_t)&dram1_2; /* 000a: l32r a8, 0 <wifi_set_gpio_debug_cb-0x4> (0 <wifi_set_gpio_debug_cb-0x4>) */ /* literal @0x0: .dram1.2 */
  MEM32(a8 + 0) = a2; /* 000d: s32i a2, a8, 0 */
L_10:;
  MEMW(); /* 0010: memw  */
  return (int32_t)a2; /* 0013: retw.n  */
}

/* wifi_gpio_debug_max_event_get @ pp_debug.o 00000000 size 7B bind GLOBAL
 * Calls: none | Data refs: none
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t wifi_gpio_debug_max_event_get(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.wifi_gpio_debug_max_event_get; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_0:;
  /* 0000: entry a1, 32 */
  a2 = 0x12; /* 0003: movi.n a2, 18 */
  return (int32_t)a2; /* 0005: retw.n  */
}

/* dbg_lmac_rxtx_statis_dump @ pp_debug.o 000000ac size 370B bind GLOBAL
 * Calls: wifi_log | Data refs: .rodata.dbg_lmac_rxtx_statis_dump.str1.1, .rodata_wlog_info.10, .rodata_wlog_info.11, .rodata_wlog_info.12, .rodata_wlog_info.13, .rodata_wlog_info.14, .rodata_wlog_info.15, .rodata_wlog_info.16, .rodata_wlog_info.5, .rodata_wlog_info.6, .rodata_wlog_info.7, .rodata_wlog_info.8, .rodata_wlog_info.9, g_lmac_cnt, wifi_log
 *   MMIO: 0x3FF732CC, 0x3FF732D0, 0x3FF732DC, 0x3FF732AC
 *   funcdb v3: 1 call(s), 15 ref(s); disasm: 12 call(s), 15 data ref(s)
 * Fidelity: medium - 142 instr, 1 branches, calls resolved */
int32_t dbg_lmac_rxtx_statis_dump(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.dbg_lmac_rxtx_statis_dump; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_ac:;
  /* 00ac: entry a1, 48 */
  a2 = 0x1; /* 00af: movi.n a2, 1 */
  a2 = 0x80000; /* 00b1: slli a2, a2, 19 */
  a13 = (uint32_t)&lit_rodata_wlog_info_5; /* 00b4: l32r a13, 0 <dbg_lmac_rxtx_statis_dump-0xac> (0 <dbg_lmac_rxtx_statis_dump-0xac>) */ /* literal @0x0: .rodata_wlog_info.5 */
  a12 = 0x3; /* 00b7: movi.n a12, 3 */
  a11 = 0x80000; /* 00b9: or a11, a2, a2 */
  a10 = 0x6; /* 00bc: movi a10, 6 */
  a8 = (uint32_t)&wifi_log; /* 00bf: l32r a8, 7c <dbg_lmac_rxtx_statis_dump-0x30> (0 <dbg_lmac_rxtx_statis_dump-0xac>) */ /* literal: GOT slot for wifi_log */
  wifi_log(a2, a3, a4, a5); /* call via literal slot */ /* 00c2: callx8 a8 */
  a13 = (uint32_t)&lit_rodata_wlog_info_6; /* 00c5: l32r a13, 4 <dbg_lmac_rxtx_statis_dump-0xa8> (0 <dbg_lmac_rxtx_statis_dump-0xac>) */ /* literal @0x4: .rodata_wlog_info.6 */
  a12 = 0x3; /* 00c8: movi.n a12, 3 */
  a11 = a2; /* 00ca: mov.n a11, a2 */
  a10 = 0x6; /* 00cc: movi.n a10, 6 */
  a8 = (uint32_t)&wifi_log; /* 00ce: l32r a8, 80 <dbg_lmac_rxtx_statis_dump-0x2c> (0 <dbg_lmac_rxtx_statis_dump-0xac>) */ /* literal: GOT slot for wifi_log */
  wifi_log(a2, a3, a4, a5); /* call via literal slot */ /* 00d1: callx8 a8 */
  a3 = (uint32_t)&lit_rodata_dbg_lmac_rxtx_statis_dump_str1_1; /* 00d4: l32r a3, 14 <dbg_lmac_rxtx_statis_dump-0x98> (b <dbg_lmac_rxtx_statis_dump-0xa1>) */ /* literal @0x14: .rodata.dbg_lmac_rxtx_statis_dump.str1.1 */
  a12 = 0x3; /* 00d7: movi.n a12, 3 */
  a11 = a2; /* 00d9: mov.n a11, a2 */
  a10 = 0x6; /* 00db: movi.n a10, 6 */
  a5 = 0x0; /* 00dd: movi.n a5, 0 */
  MEM32(a1 + 8) = a3; /* 00df: s32i.n a3, a1, 8 */
  a3 = (uint32_t)&lit_rodata_dbg_lmac_rxtx_statis_dump_str1_1; /* 00e1: l32r a3, 18 <dbg_lmac_rxtx_statis_dump-0x94> (e <dbg_lmac_rxtx_statis_dump-0x9e>) */ /* literal @0x18: .rodata.dbg_lmac_rxtx_statis_dump.str1.1 */
  MEM32(a1 + 4) = a3; /* 00e4: s32i.n a3, a1, 4 */
  a3 = (uint32_t)&lit_rodata_dbg_lmac_rxtx_statis_dump_str1_1; /* 00e6: l32r a3, 1c <dbg_lmac_rxtx_statis_dump-0x90> (12 <dbg_lmac_rxtx_statis_dump-0x9a>) */ /* literal @0x1C: .rodata.dbg_lmac_rxtx_statis_dump.str1.1 */
  a15 = (uint32_t)&lit_rodata_dbg_lmac_rxtx_statis_dump_str1_1; /* 00e9: l32r a15, 8 <dbg_lmac_rxtx_statis_dump-0xa4> (0 <dbg_lmac_rxtx_statis_dump-0xac>) */ /* literal @0x8: .rodata.dbg_lmac_rxtx_statis_dump.str1.1 */
  a14 = (uint32_t)&lit_rodata_dbg_lmac_rxtx_statis_dump_str1_1; /* 00ec: l32r a14, c <dbg_lmac_rxtx_statis_dump-0xa0> (4 <dbg_lmac_rxtx_statis_dump-0xa8>) */ /* literal @0xC: .rodata.dbg_lmac_rxtx_statis_dump.str1.1 */
  a13 = (uint32_t)&lit_rodata_wlog_info_7; /* 00ef: l32r a13, 10 <dbg_lmac_rxtx_statis_dump-0x9c> (0 <dbg_lmac_rxtx_statis_dump-0xac>) */ /* literal @0x10: .rodata_wlog_info.7 */
  MEM32(a1 + 0) = a3; /* 00f2: s32i.n a3, a1, 0 */
  MEMW(); /* 00f4: memw  */
  a8 = (uint32_t)&wifi_log; /* 00f7: l32r a8, 84 <dbg_lmac_rxtx_statis_dump-0x28> (0 <dbg_lmac_rxtx_statis_dump-0xac>) */ /* literal: GOT slot for wifi_log */
  wifi_log(a2, a3, a4, a5); /* call via literal slot */ /* 00fa: callx8 a8 */
  a3 = (uint32_t)&g_lmac_cnt; /* 00fd: l32r a3, 20 <dbg_lmac_rxtx_statis_dump-0x8c> (0 <dbg_lmac_rxtx_statis_dump-0xac>) */ /* literal @0x20: g_lmac_cnt */
  a4 = a3; /* 0100: mov.n a4, a3 */
L_102:;
  a2 = 0x1; /* 0102: movi.n a2, 1 */
  a2 = 0x80000; /* 0104: slli a2, a2, 19 */
  a8 = MEM8(a3 + 127); /* 0107: l8ui a8, a3, 127 */
  a12 = 0x3; /* 010a: movi.n a12, 3 */
  a11 = 0x80000; /* 010c: mov.n a11, a2 */
  a10 = 0x6; /* 010e: movi.n a10, 6 */
  a5 = a5 + (1); /* 0110: addi.n a5, a5, 1 */
  a15 = MEM8(a3 + 124); /* 0112: l8ui a15, a3, 124 */
  a3 = a3 + (8); /* 0115: addi.n a3, a3, 8 */
  MEM32(a1 + 8) = a8; /* 0117: s32i a8, a1, 8 */
  a8 = MEM8(a3 + 118); /* 011a: l8ui a8, a3, 118 */
  MEM32(a1 + 4) = a8; /* 011d: s32i a8, a1, 4 */
  a8 = MEM8(a3 + 117); /* 0120: l8ui a8, a3, 117 */
  MEM32(a1 + 0) = a8; /* 0123: s32i.n a8, a1, 0 */
  a14 = MEM32(a3 + 112); /* 0125: l32i a14, a3, 112 */
  a13 = (uint32_t)&lit_rodata_wlog_info_8; /* 0128: l32r a13, 24 <dbg_lmac_rxtx_statis_dump-0x88> (0 <dbg_lmac_rxtx_statis_dump-0xac>) */ /* literal @0x24: .rodata_wlog_info.8 */
  MEMW(); /* 012b: memw  */
  a8 = (uint32_t)&wifi_log; /* 012e: l32r a8, 88 <dbg_lmac_rxtx_statis_dump-0x24> (0 <dbg_lmac_rxtx_statis_dump-0xac>) */ /* literal: GOT slot for wifi_log */
  wifi_log(a2, a3, a4, a5); /* call via literal slot */ /* 0131: callx8 a8 */
  if (a5 != 5) goto L_102; /* 0134: bnei a5, 5, 102 <dbg_lmac_rxtx_statis_dump+0x56> */
  a11 = a2; /* 0137: mov.n a11, a2 */
  a13 = (uint32_t)&lit_rodata_wlog_info_9; /* 0139: l32r a13, 28 <dbg_lmac_rxtx_statis_dump-0x84> (0 <dbg_lmac_rxtx_statis_dump-0xac>) */ /* literal @0x28: .rodata_wlog_info.9 */
  a12 = 0x3; /* 013c: movi.n a12, 3 */
  a10 = 0x6; /* 013e: movi.n a10, 6 */
  a8 = (uint32_t)&wifi_log; /* 0140: l32r a8, 8c <dbg_lmac_rxtx_statis_dump-0x20> (0 <dbg_lmac_rxtx_statis_dump-0xac>) */ /* literal: GOT slot for wifi_log */
  wifi_log(a2, a3, a4, a5); /* call via literal slot */ /* 0143: callx8 a8 */
  a11 = a2; /* 0146: mov.n a11, a2 */
  a13 = (uint32_t)&lit_rodata_wlog_info_10; /* 0148: l32r a13, 2c <dbg_lmac_rxtx_statis_dump-0x80> (0 <dbg_lmac_rxtx_statis_dump-0xac>) */ /* literal @0x2C: .rodata_wlog_info.10 */
  a12 = 0x3; /* 014b: movi.n a12, 3 */
  a10 = 0x6; /* 014d: movi a10, 6 */
  a8 = (uint32_t)&wifi_log; /* 0150: l32r a8, 90 <dbg_lmac_rxtx_statis_dump-0x1c> (0 <dbg_lmac_rxtx_statis_dump-0xac>) */ /* literal: GOT slot for wifi_log */
  wifi_log(a2, a3, a4, a5); /* call via literal slot */ /* 0153: callx8 a8 */
  a11 = a2; /* 0156: mov.n a11, a2 */
  a3 = (uint32_t)&lit_rodata_dbg_lmac_rxtx_statis_dump_str1_1; /* 0158: l32r a3, 3c <dbg_lmac_rxtx_statis_dump-0x70> (21 <dbg_lmac_rxtx_statis_dump-0x8b>) */ /* literal @0x3C: .rodata.dbg_lmac_rxtx_statis_dump.str1.1 */
  a12 = 0x3; /* 015b: movi.n a12, 3 */
  a10 = 0x6; /* 015d: movi.n a10, 6 */
  MEM32(a1 + 8) = a3; /* 015f: s32i.n a3, a1, 8 */
  a3 = (uint32_t)&lit_rodata_dbg_lmac_rxtx_statis_dump_str1_1; /* 0161: l32r a3, 40 <dbg_lmac_rxtx_statis_dump-0x6c> (26 <dbg_lmac_rxtx_statis_dump-0x86>) */ /* literal @0x40: .rodata.dbg_lmac_rxtx_statis_dump.str1.1 */
  MEM32(a1 + 4) = a3; /* 0164: s32i.n a3, a1, 4 */
  a3 = (uint32_t)&lit_rodata_dbg_lmac_rxtx_statis_dump_str1_1; /* 0166: l32r a3, 44 <dbg_lmac_rxtx_statis_dump-0x68> (2b <dbg_lmac_rxtx_statis_dump-0x81>) */ /* literal @0x44: .rodata.dbg_lmac_rxtx_statis_dump.str1.1 */
  a15 = (uint32_t)&lit_rodata_dbg_lmac_rxtx_statis_dump_str1_1; /* 0169: l32r a15, 30 <dbg_lmac_rxtx_statis_dump-0x7c> (16 <dbg_lmac_rxtx_statis_dump-0x96>) */ /* literal @0x30: .rodata.dbg_lmac_rxtx_statis_dump.str1.1 */
  a14 = (uint32_t)&lit_rodata_dbg_lmac_rxtx_statis_dump_str1_1; /* 016c: l32r a14, 34 <dbg_lmac_rxtx_statis_dump-0x78> (1b <dbg_lmac_rxtx_statis_dump-0x91>) */ /* literal @0x34: .rodata.dbg_lmac_rxtx_statis_dump.str1.1 */
  a13 = (uint32_t)&lit_rodata_wlog_info_11; /* 016f: l32r a13, 38 <dbg_lmac_rxtx_statis_dump-0x74> (0 <dbg_lmac_rxtx_statis_dump-0xac>) */ /* literal @0x38: .rodata_wlog_info.11 */
  MEM32(a1 + 0) = a3; /* 0172: s32i.n a3, a1, 0 */
  MEMW(); /* 0174: memw  */
  a8 = (uint32_t)&wifi_log; /* 0177: l32r a8, 94 <dbg_lmac_rxtx_statis_dump-0x18> (0 <dbg_lmac_rxtx_statis_dump-0xac>) */ /* literal: GOT slot for wifi_log */
  wifi_log(a2, a3, a4, a5); /* call via literal slot */ /* 017a: callx8 a8 */
  a11 = a2; /* 017d: mov.n a11, a2 */
  a12 = 0x3; /* 017f: movi.n a12, 3 */
  a10 = 0x6; /* 0181: movi.n a10, 6 */
  a3 = MEM16(a4 + 176); /* 0183: l16ui a3, a4, 176 */
  MEM32(a1 + 8) = a3; /* 0186: s32i.n a3, a1, 8 */
  a3 = MEM32(a4 + 172); /* 0188: l32i a3, a4, 172 */
  MEM32(a1 + 4) = a3; /* 018b: s32i a3, a1, 4 */
  a3 = MEM32(a4 + 168); /* 018e: l32i a3, a4, 168 */
  MEM32(a1 + 0) = a3; /* 0191: s32i a3, a1, 0 */
  a15 = MEM32(a4 + 164); /* 0194: l32i a15, a4, 164 */
  a14 = MEM32(a4 + 160); /* 0197: l32i a14, a4, 160 */
  a13 = (uint32_t)&lit_rodata_wlog_info_12; /* 019a: l32r a13, 48 <dbg_lmac_rxtx_statis_dump-0x64> (0 <dbg_lmac_rxtx_statis_dump-0xac>) */ /* literal @0x48: .rodata_wlog_info.12 */
  MEMW(); /* 019d: memw  */
  a8 = (uint32_t)&wifi_log; /* 01a0: l32r a8, 98 <dbg_lmac_rxtx_statis_dump-0x14> (0 <dbg_lmac_rxtx_statis_dump-0xac>) */ /* literal: GOT slot for wifi_log */
  wifi_log(a2, a3, a4, a5); /* call via literal slot */ /* 01a3: callx8 a8 */
  a11 = a2; /* 01a6: mov.n a11, a2 */
  a12 = 0x3; /* 01a8: movi.n a12, 3 */
  a13 = (uint32_t)&lit_rodata_wlog_info_13; /* 01aa: l32r a13, 4c <dbg_lmac_rxtx_statis_dump-0x60> (0 <dbg_lmac_rxtx_statis_dump-0xac>) */ /* literal @0x4C: .rodata_wlog_info.13 */
  a10 = 0x6; /* 01ad: movi.n a10, 6 */
  a8 = (uint32_t)&wifi_log; /* 01af: l32r a8, 9c <dbg_lmac_rxtx_statis_dump-0x10> (0 <dbg_lmac_rxtx_statis_dump-0xac>) */ /* literal: GOT slot for wifi_log */
  wifi_log(a2, a3, a4, a5); /* call via literal slot */ /* 01b2: callx8 a8 */
  a11 = a2; /* 01b5: mov.n a11, a2 */
  a12 = 0x3; /* 01b7: movi.n a12, 3 */
  a13 = (uint32_t)&lit_rodata_wlog_info_14; /* 01b9: l32r a13, 50 <dbg_lmac_rxtx_statis_dump-0x5c> (0 <dbg_lmac_rxtx_statis_dump-0xac>) */ /* literal @0x50: .rodata_wlog_info.14 */
  a10 = 0x6; /* 01bc: movi.n a10, 6 */
  a8 = (uint32_t)&wifi_log; /* 01be: l32r a8, a0 <dbg_lmac_rxtx_statis_dump-0xc> (0 <dbg_lmac_rxtx_statis_dump-0xac>) */ /* literal: GOT slot for wifi_log */
  wifi_log(a2, a3, a4, a5); /* call via literal slot */ /* 01c1: callx8 a8 */
  a11 = a2; /* 01c4: mov.n a11, a2 */
  a12 = 0x3; /* 01c6: movi.n a12, 3 */
  a3 = (uint32_t)&lit_rodata_dbg_lmac_rxtx_statis_dump_str1_1; /* 01c8: l32r a3, 60 <dbg_lmac_rxtx_statis_dump-0x4c> (3e <dbg_lmac_rxtx_statis_dump-0x6e>) */ /* literal @0x60: .rodata.dbg_lmac_rxtx_statis_dump.str1.1 */
  a10 = 0x6; /* 01cb: movi.n a10, 6 */
  MEM32(a1 + 4) = a3; /* 01cd: s32i.n a3, a1, 4 */
  a3 = (uint32_t)&lit_rodata_dbg_lmac_rxtx_statis_dump_str1_1; /* 01cf: l32r a3, 64 <dbg_lmac_rxtx_statis_dump-0x48> (45 <dbg_lmac_rxtx_statis_dump-0x67>) */ /* literal @0x64: .rodata.dbg_lmac_rxtx_statis_dump.str1.1 */
  a15 = (uint32_t)&lit_rodata_dbg_lmac_rxtx_statis_dump_str1_1; /* 01d2: l32r a15, 54 <dbg_lmac_rxtx_statis_dump-0x58> (30 <dbg_lmac_rxtx_statis_dump-0x7c>) */ /* literal @0x54: .rodata.dbg_lmac_rxtx_statis_dump.str1.1 */
  a14 = (uint32_t)&lit_rodata_dbg_lmac_rxtx_statis_dump_str1_1; /* 01d5: l32r a14, 58 <dbg_lmac_rxtx_statis_dump-0x54> (37 <dbg_lmac_rxtx_statis_dump-0x75>) */ /* literal @0x58: .rodata.dbg_lmac_rxtx_statis_dump.str1.1 */
  a13 = (uint32_t)&lit_rodata_wlog_info_15; /* 01d8: l32r a13, 5c <dbg_lmac_rxtx_statis_dump-0x50> (0 <dbg_lmac_rxtx_statis_dump-0xac>) */ /* literal @0x5C: .rodata_wlog_info.15 */
  MEM32(a1 + 0) = a3; /* 01db: s32i.n a3, a1, 0 */
  MEMW(); /* 01dd: memw  */
  a8 = (uint32_t)&wifi_log; /* 01e0: l32r a8, a4 <dbg_lmac_rxtx_statis_dump-0x8> (0 <dbg_lmac_rxtx_statis_dump-0xac>) */ /* literal: GOT slot for wifi_log */
  wifi_log(a2, a3, a4, a5); /* call via literal slot */ /* 01e3: callx8 a8 */
  a12 = 0x3; /* 01e6: movi.n a12, 3 */
  a11 = a2; /* 01e8: mov.n a11, a2 */
  a10 = 0x6; /* 01ea: movi.n a10, 6 */
  a3 = 0x3FF732CC; /* 01ec: l32r a3, 68 <dbg_lmac_rxtx_statis_dump-0x44> (3ff732cc <dbg_lmac_hw_statis_dump+0x3ff731c4>) */ /* MMIO base */ @0x68
  MEMW(); /* 01ef: memw  */
  a14 = REG32(0x3FF732CC); /* 01f2: l32i.n a14, a3, 0 */ /* MMIO read: base 0x3FF732CC+0 */
  a3 = 0x3FF732D0; /* 01f4: l32r a3, 6c <dbg_lmac_rxtx_statis_dump-0x40> (3ff732d0 <dbg_lmac_hw_statis_dump+0x3ff731c8>) */ /* MMIO base */ @0x6C
  a4 = 0x3FF732DC; /* 01f7: l32r a4, 74 <dbg_lmac_rxtx_statis_dump-0x38> (3ff732dc <dbg_lmac_hw_statis_dump+0x3ff731d4>) */ /* MMIO base */ @0x74
  MEMW(); /* 01fa: memw  */
  a15 = REG32(0x3FF732D0); /* 01fd: l32i.n a15, a3, 0 */ /* MMIO read: base 0x3FF732D0+0 */
  a3 = 0x3FF732AC; /* 01ff: l32r a3, 70 <dbg_lmac_rxtx_statis_dump-0x3c> (3ff732ac <dbg_lmac_hw_statis_dump+0x3ff731a4>) */ /* MMIO base */ @0x70
  MEMW(); /* 0202: memw  */
  a3 = REG32(0x3FF732AC); /* 0205: l32i.n a3, a3, 0 */ /* MMIO read: base 0x3FF732AC+0 */
  MEMW(); /* 0207: memw  */
  a4 = REG32(0x3FF732DC); /* 020a: l32i.n a4, a4, 0 */ /* MMIO read: base 0x3FF732DC+0 */
  a13 = (uint32_t)&lit_rodata_wlog_info_16; /* 020c: l32r a13, 78 <dbg_lmac_rxtx_statis_dump-0x34> (0 <dbg_lmac_rxtx_statis_dump-0xac>) */ /* literal @0x78: .rodata_wlog_info.16 */
  MEM32(a1 + 4) = a4; /* 020f: s32i.n a4, a1, 4 */
  MEM32(a1 + 0) = a3; /* 0211: s32i.n a3, a1, 0 */
  MEMW(); /* 0213: memw  */
  a8 = (uint32_t)&wifi_log; /* 0216: l32r a8, a8 <dbg_lmac_rxtx_statis_dump-0x4> (0 <dbg_lmac_rxtx_statis_dump-0xac>) */ /* literal: GOT slot for wifi_log */
  wifi_log(a2, a3, a4, a5); /* call via literal slot */ /* 0219: callx8 a8 */
  return (int32_t)a2; /* 021c: retw.n  */
}

/* dbg_lmac_hw_statis_dump @ pp_debug.o 00000108 size 503B bind GLOBAL
 * Calls: wifi_log | Data refs: .rodata.dbg_lmac_hw_statis_dump.str1.1, .rodata_wlog_info.17, .rodata_wlog_info.18, .rodata_wlog_info.19, .rodata_wlog_info.20, .rodata_wlog_info.21, .rodata_wlog_info.22, .rodata_wlog_info.23, .rodata_wlog_info.24, wifi_log
 *   MMIO: 0x3FF73094, 0x3FF7328C, 0x3FF73294, 0x3FF73298, 0x3FF73290, 0x3FF7329C, 0x3FF732A0, 0x3FF732A4, 0x3FF732A8, 0x3FF732B0, 0x3FF732B8, 0x3FF732BC, 0x3FF732B4, 0x3FF732C0, 0x3FF732C4, 0x3FF732C8, 0x3FF732E0, 0x3FF732D8, 0x3FF73D58, 0x3FF73D5C, 0x3FF73D60, 0x3FF73D64, 0x3FF73D68, 0x3FF73D6C, 0x3FF73D70
 *   funcdb v3: 1 call(s), 10 ref(s); disasm: 8 call(s), 10 data ref(s)
 * Fidelity: low - 196 instr, 0 branches, 0 indirect; call-sequence + MMIO skeleton */
int32_t dbg_lmac_hw_statis_dump(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.dbg_lmac_hw_statis_dump; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_108:;
  /* 0108: entry a1, 64 */
  a2 = 0x1; /* 010b: movi.n a2, 1 */
  a2 = 0x80000; /* 010d: slli a2, a2, 19 */
  a13 = (uint32_t)&lit_rodata_wlog_info_17; /* 0110: l32r a13, 0 <dbg_lmac_hw_statis_dump-0x108> (0 <dbg_lmac_hw_statis_dump-0x108>) */ /* literal @0x0: .rodata_wlog_info.17 */
  a11 = 0x80000; /* 0113: mov.n a11, a2 */
  a12 = 0x3; /* 0115: movi a12, 3 */
  a10 = 0x6; /* 0118: movi a10, 6 */
  a8 = (uint32_t)&wifi_log; /* 011b: l32r a8, e8 <dbg_lmac_hw_statis_dump-0x20> (0 <dbg_lmac_hw_statis_dump-0x108>) */ /* literal: GOT slot for wifi_log */
  wifi_log(a2, a3, a4, a5); /* call via literal slot */ /* 011e: callx8 a8 */
  a13 = (uint32_t)&lit_rodata_wlog_info_18; /* 0121: l32r a13, 4 <dbg_lmac_hw_statis_dump-0x104> (0 <dbg_lmac_hw_statis_dump-0x108>) */ /* literal @0x4: .rodata_wlog_info.18 */
  a11 = a2; /* 0124: mov.n a11, a2 */
  a12 = 0x3; /* 0126: movi.n a12, 3 */
  a10 = 0x6; /* 0128: movi.n a10, 6 */
  a8 = (uint32_t)&wifi_log; /* 012a: l32r a8, ec <dbg_lmac_hw_statis_dump-0x1c> (0 <dbg_lmac_hw_statis_dump-0x108>) */ /* literal: GOT slot for wifi_log */
  wifi_log(a2, a3, a4, a5); /* call via literal slot */ /* 012d: callx8 a8 */
  a3 = (uint32_t)&lit_rodata_dbg_lmac_hw_statis_dump_str1_1; /* 0130: l32r a3, 14 <dbg_lmac_hw_statis_dump-0xf4> (11 <dbg_lmac_hw_statis_dump-0xf7>) */ /* literal @0x14: .rodata.dbg_lmac_hw_statis_dump.str1.1 */
  a11 = a2; /* 0133: mov.n a11, a2 */
  a12 = 0x3; /* 0135: movi.n a12, 3 */
  a10 = 0x6; /* 0137: movi.n a10, 6 */
  MEM32(a1 + 20) = a3; /* 0139: s32i.n a3, a1, 20 */
  a3 = (uint32_t)&lit_rodata_dbg_lmac_hw_statis_dump_str1_1; /* 013b: l32r a3, 18 <dbg_lmac_hw_statis_dump-0xf0> (1a <dbg_lmac_hw_statis_dump-0xee>) */ /* literal @0x18: .rodata.dbg_lmac_hw_statis_dump.str1.1 */
  MEM32(a1 + 16) = a3; /* 013e: s32i.n a3, a1, 16 */
  a3 = (uint32_t)&lit_rodata_dbg_lmac_hw_statis_dump_str1_1; /* 0140: l32r a3, 1c <dbg_lmac_hw_statis_dump-0xec> (21 <dbg_lmac_hw_statis_dump-0xe7>) */ /* literal @0x1C: .rodata.dbg_lmac_hw_statis_dump.str1.1 */
  MEM32(a1 + 12) = a3; /* 0143: s32i.n a3, a1, 12 */
  a3 = (uint32_t)&lit_rodata_dbg_lmac_hw_statis_dump_str1_1; /* 0145: l32r a3, 20 <dbg_lmac_hw_statis_dump-0xe8> (2a <dbg_lmac_hw_statis_dump-0xde>) */ /* literal @0x20: .rodata.dbg_lmac_hw_statis_dump.str1.1 */
  MEM32(a1 + 8) = a3; /* 0148: s32i a3, a1, 8 */
  a3 = (uint32_t)&lit_rodata_dbg_lmac_hw_statis_dump_str1_1; /* 014b: l32r a3, 24 <dbg_lmac_hw_statis_dump-0xe4> (2f <dbg_lmac_hw_statis_dump-0xd9>) */ /* literal @0x24: .rodata.dbg_lmac_hw_statis_dump.str1.1 */
  MEM32(a1 + 4) = a3; /* 014e: s32i a3, a1, 4 */
  a3 = (uint32_t)&lit_rodata_dbg_lmac_hw_statis_dump_str1_1; /* 0151: l32r a3, 28 <dbg_lmac_hw_statis_dump-0xe0> (36 <dbg_lmac_hw_statis_dump-0xd2>) */ /* literal @0x28: .rodata.dbg_lmac_hw_statis_dump.str1.1 */
  a15 = (uint32_t)&lit_rodata_dbg_lmac_hw_statis_dump_str1_1; /* 0154: l32r a15, 8 <dbg_lmac_hw_statis_dump-0x100> (0 <dbg_lmac_hw_statis_dump-0x108>) */ /* literal @0x8: .rodata.dbg_lmac_hw_statis_dump.str1.1 */
  a14 = (uint32_t)&lit_rodata_dbg_lmac_hw_statis_dump_str1_1; /* 0157: l32r a14, c <dbg_lmac_hw_statis_dump-0xfc> (9 <dbg_lmac_hw_statis_dump-0xff>) */ /* literal @0xC: .rodata.dbg_lmac_hw_statis_dump.str1.1 */
  a13 = (uint32_t)&lit_rodata_wlog_info_19; /* 015a: l32r a13, 10 <dbg_lmac_hw_statis_dump-0xf8> (0 <dbg_lmac_hw_statis_dump-0x108>) */ /* literal @0x10: .rodata_wlog_info.19 */
  MEM32(a1 + 0) = a3; /* 015d: s32i.n a3, a1, 0 */
  MEMW(); /* 015f: memw  */
  a8 = (uint32_t)&wifi_log; /* 0162: l32r a8, f0 <dbg_lmac_hw_statis_dump-0x18> (0 <dbg_lmac_hw_statis_dump-0x108>) */ /* literal: GOT slot for wifi_log */
  wifi_log(a2, a3, a4, a5); /* call via literal slot */ /* 0165: callx8 a8 */
  a3 = 0x3FF73094; /* 0168: l32r a3, 2c <dbg_lmac_hw_statis_dump-0xdc> (3ff73094 <dbg_lmac_hw_statis_dump+0x3ff72f8c>) */ /* MMIO base */ @0x2C
  MEMW(); /* 016b: memw  */
  a14 = REG32(0x3FF73094); /* 016e: l32i.n a14, a3, 0 */ /* MMIO read: base 0x3FF73094+0 */
  a3 = 0x3FF7328C; /* 0170: l32r a3, 30 <dbg_lmac_hw_statis_dump-0xd8> (3ff7328c <dbg_lmac_hw_statis_dump+0x3ff73184>) */ /* MMIO base */ @0x30
  a8 = 0x3FF73294; /* 0173: l32r a8, 38 <dbg_lmac_hw_statis_dump-0xd0> (3ff73294 <dbg_lmac_hw_statis_dump+0x3ff7318c>) */ /* MMIO base */ @0x38
  MEMW(); /* 0176: memw  */
  a15 = REG32(0x3FF7328C); /* 0179: l32i.n a15, a3, 0 */ /* MMIO read: base 0x3FF7328C+0 */
  a9 = 0x3FF73298; /* 017b: l32r a9, 3c <dbg_lmac_hw_statis_dump-0xcc> (3ff73298 <dbg_lmac_hw_statis_dump+0x3ff73190>) */ /* MMIO base */ @0x3C
  a3 = 0x3FF73290; /* 017e: l32r a3, 34 <dbg_lmac_hw_statis_dump-0xd4> (3ff73290 <dbg_lmac_hw_statis_dump+0x3ff73188>) */ /* MMIO base */ @0x34
  a10 = 0x3FF7329C; /* 0181: l32r a10, 40 <dbg_lmac_hw_statis_dump-0xc8> (3ff7329c <dbg_lmac_hw_statis_dump+0x3ff73194>) */ /* MMIO base */ @0x40
  a11 = 0x3FF732A0; /* 0184: l32r a11, 44 <dbg_lmac_hw_statis_dump-0xc4> (3ff732a0 <dbg_lmac_hw_statis_dump+0x3ff73198>) */ /* MMIO base */ @0x44
  a12 = 0x3FF732A4; /* 0187: l32r a12, 48 <dbg_lmac_hw_statis_dump-0xc0> (3ff732a4 <dbg_lmac_hw_statis_dump+0x3ff7319c>) */ /* MMIO base */ @0x48
  MEMW(); /* 018a: memw  */
  a3 = REG32(0x3FF73290); /* 018d: l32i.n a3, a3, 0 */ /* MMIO read: base 0x3FF73290+0 */
  MEMW(); /* 018f: memw  */
  a8 = REG32(0x3FF73294); /* 0192: l32i.n a8, a8, 0 */ /* MMIO read: base 0x3FF73294+0 */
  MEMW(); /* 0194: memw  */
  a9 = REG32(0x3FF73298); /* 0197: l32i.n a9, a9, 0 */ /* MMIO read: base 0x3FF73298+0 */
  MEMW(); /* 0199: memw  */
  a10 = REG32(0x3FF7329C); /* 019c: l32i.n a10, a10, 0 */ /* MMIO read: base 0x3FF7329C+0 */
  MEMW(); /* 019e: memw  */
  a11 = REG32(0x3FF732A0); /* 01a1: l32i.n a11, a11, 0 */ /* MMIO read: base 0x3FF732A0+0 */
  MEMW(); /* 01a3: memw  */
  a12 = REG32(0x3FF732A4); /* 01a6: l32i.n a12, a12, 0 */ /* MMIO read: base 0x3FF732A4+0 */
  a13 = (uint32_t)&lit_rodata_wlog_info_20; /* 01a8: l32r a13, 4c <dbg_lmac_hw_statis_dump-0xbc> (0 <dbg_lmac_hw_statis_dump-0x108>) */ /* literal @0x4C: .rodata_wlog_info.20 */
  MEM32(a1 + 8) = a9; /* 01ab: s32i.n a9, a1, 8 */
  MEM32(a1 + 4) = a8; /* 01ad: s32i.n a8, a1, 4 */
  MEM32(a1 + 20) = a12; /* 01af: s32i.n a12, a1, 20 */
  a12 = 0x3; /* 01b1: movi.n a12, 3 */
  MEM32(a1 + 16) = a11; /* 01b3: s32i.n a11, a1, 16 */
  a11 = a2; /* 01b5: mov.n a11, a2 */
  MEM32(a1 + 12) = a10; /* 01b7: s32i.n a10, a1, 12 */
  a10 = 0x6; /* 01b9: movi.n a10, 6 */
  MEM32(a1 + 0) = a3; /* 01bb: s32i.n a3, a1, 0 */
  MEMW(); /* 01bd: memw  */
  a8 = (uint32_t)&wifi_log; /* 01c0: l32r a8, f4 <dbg_lmac_hw_statis_dump-0x14> (0 <dbg_lmac_hw_statis_dump-0x108>) */ /* literal: GOT slot for wifi_log */
  wifi_log(a2, a3, a4, a5); /* call via literal slot */ /* 01c3: callx8 a8 */
  a11 = a2; /* 01c6: mov.n a11, a2 */
  a12 = 0x3; /* 01c8: movi.n a12, 3 */
  a10 = 0x6; /* 01ca: movi.n a10, 6 */
  a3 = (uint32_t)&lit_rodata_dbg_lmac_hw_statis_dump_str1_1; /* 01cc: l32r a3, 5c <dbg_lmac_hw_statis_dump-0xac> (4b <dbg_lmac_hw_statis_dump-0xbd>) */ /* literal @0x5C: .rodata.dbg_lmac_hw_statis_dump.str1.1 */
  MEM32(a1 + 20) = a3; /* 01cf: s32i.n a3, a1, 20 */
  a3 = (uint32_t)&lit_rodata_dbg_lmac_hw_statis_dump_str1_1; /* 01d1: l32r a3, 60 <dbg_lmac_hw_statis_dump-0xa8> (54 <dbg_lmac_hw_statis_dump-0xb4>) */ /* literal @0x60: .rodata.dbg_lmac_hw_statis_dump.str1.1 */
  MEM32(a1 + 16) = a3; /* 01d4: s32i.n a3, a1, 16 */
  a3 = (uint32_t)&lit_rodata_dbg_lmac_hw_statis_dump_str1_1; /* 01d6: l32r a3, 64 <dbg_lmac_hw_statis_dump-0xa4> (5c <dbg_lmac_hw_statis_dump-0xac>) */ /* literal @0x64: .rodata.dbg_lmac_hw_statis_dump.str1.1 */
  MEM32(a1 + 12) = a3; /* 01d9: s32i.n a3, a1, 12 */
  a3 = (uint32_t)&lit_rodata_dbg_lmac_hw_statis_dump_str1_1; /* 01db: l32r a3, 68 <dbg_lmac_hw_statis_dump-0xa0> (64 <dbg_lmac_hw_statis_dump-0xa4>) */ /* literal @0x68: .rodata.dbg_lmac_hw_statis_dump.str1.1 */
  MEM32(a1 + 8) = a3; /* 01de: s32i.n a3, a1, 8 */
  a3 = (uint32_t)&lit_rodata_dbg_lmac_hw_statis_dump_str1_1; /* 01e0: l32r a3, 6c <dbg_lmac_hw_statis_dump-0x9c> (6c <dbg_lmac_hw_statis_dump-0x9c>) */ /* literal @0x6C: .rodata.dbg_lmac_hw_statis_dump.str1.1 */
  MEM32(a1 + 4) = a3; /* 01e3: s32i.n a3, a1, 4 */
  a3 = (uint32_t)&lit_rodata_dbg_lmac_hw_statis_dump_str1_1; /* 01e5: l32r a3, 70 <dbg_lmac_hw_statis_dump-0x98> (73 <dbg_lmac_hw_statis_dump-0x95>) */ /* literal @0x70: .rodata.dbg_lmac_hw_statis_dump.str1.1 */
  a15 = (uint32_t)&lit_rodata_dbg_lmac_hw_statis_dump_str1_1; /* 01e8: l32r a15, 50 <dbg_lmac_hw_statis_dump-0xb8> (3e <dbg_lmac_hw_statis_dump-0xca>) */ /* literal @0x50: .rodata.dbg_lmac_hw_statis_dump.str1.1 */
  a14 = (uint32_t)&lit_rodata_dbg_lmac_hw_statis_dump_str1_1; /* 01eb: l32r a14, 54 <dbg_lmac_hw_statis_dump-0xb4> (45 <dbg_lmac_hw_statis_dump-0xc3>) */ /* literal @0x54: .rodata.dbg_lmac_hw_statis_dump.str1.1 */
  a13 = (uint32_t)&lit_rodata_wlog_info_21; /* 01ee: l32r a13, 58 <dbg_lmac_hw_statis_dump-0xb0> (0 <dbg_lmac_hw_statis_dump-0x108>) */ /* literal @0x58: .rodata_wlog_info.21 */
  MEM32(a1 + 0) = a3; /* 01f1: s32i.n a3, a1, 0 */
  MEMW(); /* 01f3: memw  */
  a8 = (uint32_t)&wifi_log; /* 01f6: l32r a8, f8 <dbg_lmac_hw_statis_dump-0x10> (0 <dbg_lmac_hw_statis_dump-0x108>) */ /* literal: GOT slot for wifi_log */
  wifi_log(a2, a3, a4, a5); /* call via literal slot */ /* 01f9: callx8 a8 */
  a3 = 0x3FF732A8; /* 01fc: l32r a3, 74 <dbg_lmac_hw_statis_dump-0x94> (3ff732a8 <dbg_lmac_hw_statis_dump+0x3ff731a0>) */ /* MMIO base */ @0x74
  MEMW(); /* 01ff: memw  */
  a14 = REG32(0x3FF732A8); /* 0202: l32i.n a14, a3, 0 */ /* MMIO read: base 0x3FF732A8+0 */
  a3 = 0x3FF732B0; /* 0204: l32r a3, 78 <dbg_lmac_hw_statis_dump-0x90> (3ff732b0 <dbg_lmac_hw_statis_dump+0x3ff731a8>) */ /* MMIO base */ @0x78
  a8 = 0x3FF732B8; /* 0207: l32r a8, 80 <dbg_lmac_hw_statis_dump-0x88> (3ff732b8 <dbg_lmac_hw_statis_dump+0x3ff731b0>) */ /* MMIO base */ @0x80
  MEMW(); /* 020a: memw  */
  a15 = REG32(0x3FF732B0); /* 020d: l32i.n a15, a3, 0 */ /* MMIO read: base 0x3FF732B0+0 */
  a9 = 0x3FF732BC; /* 020f: l32r a9, 84 <dbg_lmac_hw_statis_dump-0x84> (3ff732bc <dbg_lmac_hw_statis_dump+0x3ff731b4>) */ /* MMIO base */ @0x84
  a3 = 0x3FF732B4; /* 0212: l32r a3, 7c <dbg_lmac_hw_statis_dump-0x8c> (3ff732b4 <dbg_lmac_hw_statis_dump+0x3ff731ac>) */ /* MMIO base */ @0x7C
  a10 = 0x3FF732C0; /* 0215: l32r a10, 88 <dbg_lmac_hw_statis_dump-0x80> (3ff732c0 <dbg_lmac_hw_statis_dump+0x3ff731b8>) */ /* MMIO base */ @0x88
  a11 = 0x3FF732C4; /* 0218: l32r a11, 8c <dbg_lmac_hw_statis_dump-0x7c> (3ff732c4 <dbg_lmac_hw_statis_dump+0x3ff731bc>) */ /* MMIO base */ @0x8C
  a12 = 0x3FF732C8; /* 021b: l32r a12, 90 <dbg_lmac_hw_statis_dump-0x78> (3ff732c8 <dbg_lmac_hw_statis_dump+0x3ff731c0>) */ /* MMIO base */ @0x90
  MEMW(); /* 021e: memw  */
  a3 = REG32(0x3FF732B4); /* 0221: l32i.n a3, a3, 0 */ /* MMIO read: base 0x3FF732B4+0 */
  MEMW(); /* 0223: memw  */
  a8 = REG32(0x3FF732B8); /* 0226: l32i.n a8, a8, 0 */ /* MMIO read: base 0x3FF732B8+0 */
  MEMW(); /* 0228: memw  */
  a9 = REG32(0x3FF732BC); /* 022b: l32i.n a9, a9, 0 */ /* MMIO read: base 0x3FF732BC+0 */
  MEMW(); /* 022d: memw  */
  a10 = REG32(0x3FF732C0); /* 0230: l32i.n a10, a10, 0 */ /* MMIO read: base 0x3FF732C0+0 */
  MEMW(); /* 0232: memw  */
  a11 = REG32(0x3FF732C4); /* 0235: l32i.n a11, a11, 0 */ /* MMIO read: base 0x3FF732C4+0 */
  MEMW(); /* 0237: memw  */
  a12 = REG32(0x3FF732C8); /* 023a: l32i.n a12, a12, 0 */ /* MMIO read: base 0x3FF732C8+0 */
  a13 = (uint32_t)&lit_rodata_wlog_info_22; /* 023c: l32r a13, 94 <dbg_lmac_hw_statis_dump-0x74> (0 <dbg_lmac_hw_statis_dump-0x108>) */ /* literal @0x94: .rodata_wlog_info.22 */
  MEM32(a1 + 8) = a9; /* 023f: s32i.n a9, a1, 8 */
  MEM32(a1 + 4) = a8; /* 0241: s32i.n a8, a1, 4 */
  MEM32(a1 + 20) = a12; /* 0243: s32i.n a12, a1, 20 */
  a12 = 0x3; /* 0245: movi.n a12, 3 */
  MEM32(a1 + 16) = a11; /* 0247: s32i.n a11, a1, 16 */
  a11 = a2; /* 0249: mov.n a11, a2 */
  MEM32(a1 + 12) = a10; /* 024b: s32i.n a10, a1, 12 */
  a10 = 0x6; /* 024d: movi.n a10, 6 */
  MEM32(a1 + 0) = a3; /* 024f: s32i.n a3, a1, 0 */
  MEMW(); /* 0251: memw  */
  a8 = (uint32_t)&wifi_log; /* 0254: l32r a8, fc <dbg_lmac_hw_statis_dump-0xc> (0 <dbg_lmac_hw_statis_dump-0x108>) */ /* literal: GOT slot for wifi_log */
  wifi_log(a2, a3, a4, a5); /* call via literal slot */ /* 0257: callx8 a8 */
  a11 = a2; /* 025a: mov.n a11, a2 */
  a12 = 0x3; /* 025c: movi.n a12, 3 */
  a10 = 0x6; /* 025e: movi.n a10, 6 */
  a3 = (uint32_t)&lit_rodata_dbg_lmac_hw_statis_dump_str1_1; /* 0260: l32r a3, a4 <dbg_lmac_hw_statis_dump-0x64> (8b <dbg_lmac_hw_statis_dump-0x7d>) */ /* literal @0xA4: .rodata.dbg_lmac_hw_statis_dump.str1.1 */
  MEM32(a1 + 24) = a3; /* 0263: s32i.n a3, a1, 24 */
  a3 = (uint32_t)&lit_rodata_dbg_lmac_hw_statis_dump_str1_1; /* 0265: l32r a3, a8 <dbg_lmac_hw_statis_dump-0x60> (91 <dbg_lmac_hw_statis_dump-0x77>) */ /* literal @0xA8: .rodata.dbg_lmac_hw_statis_dump.str1.1 */
  MEM32(a1 + 20) = a3; /* 0268: s32i.n a3, a1, 20 */
  a3 = (uint32_t)&lit_rodata_dbg_lmac_hw_statis_dump_str1_1; /* 026a: l32r a3, ac <dbg_lmac_hw_statis_dump-0x5c> (98 <dbg_lmac_hw_statis_dump-0x70>) */ /* literal @0xAC: .rodata.dbg_lmac_hw_statis_dump.str1.1 */
  MEM32(a1 + 16) = a3; /* 026d: s32i.n a3, a1, 16 */
  a3 = (uint32_t)&lit_rodata_dbg_lmac_hw_statis_dump_str1_1; /* 026f: l32r a3, b0 <dbg_lmac_hw_statis_dump-0x58> (a0 <dbg_lmac_hw_statis_dump-0x68>) */ /* literal @0xB0: .rodata.dbg_lmac_hw_statis_dump.str1.1 */
  MEM32(a1 + 12) = a3; /* 0272: s32i.n a3, a1, 12 */
  a3 = (uint32_t)&lit_rodata_dbg_lmac_hw_statis_dump_str1_1; /* 0274: l32r a3, b4 <dbg_lmac_hw_statis_dump-0x54> (a6 <dbg_lmac_hw_statis_dump-0x62>) */ /* literal @0xB4: .rodata.dbg_lmac_hw_statis_dump.str1.1 */
  MEM32(a1 + 8) = a3; /* 0277: s32i.n a3, a1, 8 */
  a3 = (uint32_t)&lit_rodata_dbg_lmac_hw_statis_dump_str1_1; /* 0279: l32r a3, b8 <dbg_lmac_hw_statis_dump-0x50> (ac <dbg_lmac_hw_statis_dump-0x5c>) */ /* literal @0xB8: .rodata.dbg_lmac_hw_statis_dump.str1.1 */
  MEM32(a1 + 4) = a3; /* 027c: s32i.n a3, a1, 4 */
  a3 = (uint32_t)&lit_rodata_dbg_lmac_hw_statis_dump_str1_1; /* 027e: l32r a3, bc <dbg_lmac_hw_statis_dump-0x4c> (b2 <dbg_lmac_hw_statis_dump-0x56>) */ /* literal @0xBC: .rodata.dbg_lmac_hw_statis_dump.str1.1 */
  a15 = (uint32_t)&lit_rodata_dbg_lmac_hw_statis_dump_str1_1; /* 0281: l32r a15, 98 <dbg_lmac_hw_statis_dump-0x70> (7b <dbg_lmac_hw_statis_dump-0x8d>) */ /* literal @0x98: .rodata.dbg_lmac_hw_statis_dump.str1.1 */
  a14 = (uint32_t)&lit_rodata_dbg_lmac_hw_statis_dump_str1_1; /* 0284: l32r a14, 9c <dbg_lmac_hw_statis_dump-0x6c> (82 <dbg_lmac_hw_statis_dump-0x86>) */ /* literal @0x9C: .rodata.dbg_lmac_hw_statis_dump.str1.1 */
  a13 = (uint32_t)&lit_rodata_wlog_info_23; /* 0287: l32r a13, a0 <dbg_lmac_hw_statis_dump-0x68> (0 <dbg_lmac_hw_statis_dump-0x108>) */ /* literal @0xA0: .rodata_wlog_info.23 */
  MEM32(a1 + 0) = a3; /* 028a: s32i.n a3, a1, 0 */
  MEMW(); /* 028c: memw  */
  a8 = (uint32_t)&wifi_log; /* 028f: l32r a8, 100 <dbg_lmac_hw_statis_dump-0x8> (0 <dbg_lmac_hw_statis_dump-0x108>) */ /* literal: GOT slot for wifi_log */
  wifi_log(a2, a3, a4, a5); /* call via literal slot */ /* 0292: callx8 a8 */
  a3 = 0x3FF732E0; /* 0295: l32r a3, c0 <dbg_lmac_hw_statis_dump-0x48> (3ff732e0 <dbg_lmac_hw_statis_dump+0x3ff731d8>) */ /* MMIO base */ @0xC0
  MEMW(); /* 0298: memw  */
  a14 = REG32(0x3FF732E0); /* 029b: l32i.n a14, a3, 0 */ /* MMIO read: base 0x3FF732E0+0 */
  a3 = 0x3FF732D8; /* 029d: l32r a3, c4 <dbg_lmac_hw_statis_dump-0x44> (3ff732d8 <dbg_lmac_hw_statis_dump+0x3ff731d0>) */ /* MMIO base */ @0xC4
  MEMW(); /* 02a0: memw  */
  a15 = REG32(0x3FF732D8); /* 02a3: l32i.n a15, a3, 0 */ /* MMIO read: base 0x3FF732D8+0 */
  a3 = 0x3FF73D58; /* 02a5: l32r a3, c8 <dbg_lmac_hw_statis_dump-0x40> (3ff73d58 <dbg_lmac_hw_statis_dump+0x3ff73c50>) */ /* MMIO base */ @0xC8
  MEMW(); /* 02a8: memw  */
  a8 = REG32(0x3FF73D58); /* 02ab: l32i.n a8, a3, 0 */ /* MMIO read: base 0x3FF73D58+0 */
  a3 = 0x3FF73D5C; /* 02ad: l32r a3, cc <dbg_lmac_hw_statis_dump-0x3c> (3ff73d5c <dbg_lmac_hw_statis_dump+0x3ff73c54>) */ /* MMIO base */ @0xCC
  MEMW(); /* 02b0: memw  */
  a9 = REG32(0x3FF73D5C); /* 02b3: l32i.n a9, a3, 0 */ /* MMIO read: base 0x3FF73D5C+0 */
  a3 = 0x3FF73D60; /* 02b5: l32r a3, d0 <dbg_lmac_hw_statis_dump-0x38> (3ff73d60 <dbg_lmac_hw_statis_dump+0x3ff73c58>) */ /* MMIO base */ @0xD0
  MEMW(); /* 02b8: memw  */
  a10 = REG32(0x3FF73D60); /* 02bb: l32i.n a10, a3, 0 */ /* MMIO read: base 0x3FF73D60+0 */
  a3 = 0x3FF73D64; /* 02bd: l32r a3, d4 <dbg_lmac_hw_statis_dump-0x34> (3ff73d64 <dbg_lmac_hw_statis_dump+0x3ff73c5c>) */ /* MMIO base */ @0xD4
  MEMW(); /* 02c0: memw  */
  a11 = REG32(0x3FF73D64); /* 02c3: l32i.n a11, a3, 0 */ /* MMIO read: base 0x3FF73D64+0 */
  a3 = 0x3FF73D68; /* 02c5: l32r a3, d8 <dbg_lmac_hw_statis_dump-0x30> (3ff73d68 <dbg_lmac_hw_statis_dump+0x3ff73c60>) */ /* MMIO base */ @0xD8
  MEMW(); /* 02c8: memw  */
  a12 = REG32(0x3FF73D68); /* 02cb: l32i.n a12, a3, 0 */ /* MMIO read: base 0x3FF73D68+0 */
  a3 = 0x3FF73D6C; /* 02cd: l32r a3, dc <dbg_lmac_hw_statis_dump-0x2c> (3ff73d6c <dbg_lmac_hw_statis_dump+0x3ff73c64>) */ /* MMIO base */ @0xDC
  MEMW(); /* 02d0: memw  */
  a13 = REG32(0x3FF73D6C); /* 02d3: l32i.n a13, a3, 0 */ /* MMIO read: base 0x3FF73D6C+0 */
  a3 = 0x3FF73D70; /* 02d5: l32r a3, e0 <dbg_lmac_hw_statis_dump-0x28> (3ff73d70 <dbg_lmac_hw_statis_dump+0x3ff73c68>) */ /* MMIO base */ @0xE0
  MEMW(); /* 02d8: memw  */
  a3 = REG32(0x3FF73D70); /* 02db: l32i.n a3, a3, 0 */ /* MMIO read: base 0x3FF73D70+0 */
  MEM32(a1 + 20) = a13; /* 02dd: s32i.n a13, a1, 20 */
  a13 = (uint32_t)&lit_rodata_wlog_info_24; /* 02df: l32r a13, e4 <dbg_lmac_hw_statis_dump-0x24> (0 <dbg_lmac_hw_statis_dump-0x108>) */ /* literal @0xE4: .rodata_wlog_info.24 */
  MEM32(a1 + 16) = a12; /* 02e2: s32i.n a12, a1, 16 */
  a12 = 0x3; /* 02e4: movi.n a12, 3 */
  MEM32(a1 + 12) = a11; /* 02e6: s32i.n a11, a1, 12 */
  a11 = a2; /* 02e8: mov.n a11, a2 */
  MEM32(a1 + 8) = a10; /* 02ea: s32i.n a10, a1, 8 */
  a10 = 0x6; /* 02ec: movi.n a10, 6 */
  MEM32(a1 + 4) = a9; /* 02ee: s32i.n a9, a1, 4 */
  MEM32(a1 + 0) = a8; /* 02f0: s32i.n a8, a1, 0 */
  MEM32(a1 + 24) = a3; /* 02f2: s32i.n a3, a1, 24 */
  MEMW(); /* 02f4: memw  */
  a8 = (uint32_t)&wifi_log; /* 02f7: l32r a8, 104 <dbg_lmac_hw_statis_dump-0x4> (0 <dbg_lmac_hw_statis_dump-0x108>) */ /* literal: GOT slot for wifi_log */
  wifi_log(a2, a3, a4, a5); /* call via literal slot */ /* 02fa: callx8 a8 */
  return (int32_t)a2; /* 02fd: retw.n  */
}

/* dbg_lmac_diag_statis_dump @ pp_debug.o 00000098 size 294B bind GLOBAL
 * Calls: wifi_log | Data refs: .rodata.dbg_lmac_diag_statis_dump.str1.1, .rodata_wlog_info.25, .rodata_wlog_info.26, .rodata_wlog_info.27, .rodata_wlog_info.28, .rodata_wlog_info.29, .rodata_wlog_info.30, wifi_log
 *   MMIO: 0x3FF73DAC, 0x3FF73DB0, 0x3FF73DB8, 0x3FF732F0, 0x3FF73DB4, 0x3FF732F4, 0x3FF732F8, 0x3FF732FC, 0x3FF73424, 0x3FF7342C, 0x3FF73430, 0x3FF73428, 0x3FF73DBC
 *   funcdb v3: 1 call(s), 8 ref(s); disasm: 6 call(s), 8 data ref(s)
 * Fidelity: medium - 114 instr, 0 branches, calls resolved */
int32_t dbg_lmac_diag_statis_dump(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.dbg_lmac_diag_statis_dump; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_98:;
  /* 0098: entry a1, 64 */
  a2 = 0x1; /* 009b: movi.n a2, 1 */
  a2 = 0x80000; /* 009d: slli a2, a2, 19 */
  a13 = (uint32_t)&lit_rodata_wlog_info_25; /* 00a0: l32r a13, 0 <dbg_lmac_diag_statis_dump-0x98> (0 <dbg_lmac_diag_statis_dump-0x98>) */ /* literal @0x0: .rodata_wlog_info.25 */
  a11 = 0x80000; /* 00a3: mov.n a11, a2 */
  a12 = 0x3; /* 00a5: movi a12, 3 */
  a10 = 0x6; /* 00a8: movi a10, 6 */
  a8 = (uint32_t)&wifi_log; /* 00ab: l32r a8, 80 <dbg_lmac_diag_statis_dump-0x18> (0 <dbg_lmac_diag_statis_dump-0x98>) */ /* literal: GOT slot for wifi_log */
  wifi_log(a2, a3, a4, a5); /* call via literal slot */ /* 00ae: callx8 a8 */
  a13 = (uint32_t)&lit_rodata_wlog_info_26; /* 00b1: l32r a13, 4 <dbg_lmac_diag_statis_dump-0x94> (0 <dbg_lmac_diag_statis_dump-0x98>) */ /* literal @0x4: .rodata_wlog_info.26 */
  a11 = a2; /* 00b4: mov.n a11, a2 */
  a12 = 0x3; /* 00b6: movi.n a12, 3 */
  a10 = 0x6; /* 00b8: movi.n a10, 6 */
  a8 = (uint32_t)&wifi_log; /* 00ba: l32r a8, 84 <dbg_lmac_diag_statis_dump-0x14> (0 <dbg_lmac_diag_statis_dump-0x98>) */ /* literal: GOT slot for wifi_log */
  wifi_log(a2, a3, a4, a5); /* call via literal slot */ /* 00bd: callx8 a8 */
  a8 = (uint32_t)&lit_rodata_dbg_lmac_diag_statis_dump_str1_1; /* 00c0: l32r a8, 14 <dbg_lmac_diag_statis_dump-0x84> (c <dbg_lmac_diag_statis_dump-0x8c>) */ /* literal @0x14: .rodata.dbg_lmac_diag_statis_dump.str1.1 */
  a11 = a2; /* 00c3: mov.n a11, a2 */
  a12 = 0x3; /* 00c5: movi.n a12, 3 */
  a10 = 0x6; /* 00c7: movi.n a10, 6 */
  MEM32(a1 + 16) = a8; /* 00c9: s32i.n a8, a1, 16 */
  a8 = (uint32_t)&lit_rodata_dbg_lmac_diag_statis_dump_str1_1; /* 00cb: l32r a8, 18 <dbg_lmac_diag_statis_dump-0x80> (12 <dbg_lmac_diag_statis_dump-0x86>) */ /* literal @0x18: .rodata.dbg_lmac_diag_statis_dump.str1.1 */
  MEM32(a1 + 12) = a8; /* 00ce: s32i.n a8, a1, 12 */
  a8 = (uint32_t)&lit_rodata_dbg_lmac_diag_statis_dump_str1_1; /* 00d0: l32r a8, 1c <dbg_lmac_diag_statis_dump-0x7c> (18 <dbg_lmac_diag_statis_dump-0x80>) */ /* literal @0x1C: .rodata.dbg_lmac_diag_statis_dump.str1.1 */
  MEM32(a1 + 8) = a8; /* 00d3: s32i.n a8, a1, 8 */
  a8 = (uint32_t)&lit_rodata_dbg_lmac_diag_statis_dump_str1_1; /* 00d5: l32r a8, 20 <dbg_lmac_diag_statis_dump-0x78> (1e <dbg_lmac_diag_statis_dump-0x7a>) */ /* literal @0x20: .rodata.dbg_lmac_diag_statis_dump.str1.1 */
  MEM32(a1 + 4) = a8; /* 00d8: s32i.n a8, a1, 4 */
  a8 = (uint32_t)&lit_rodata_dbg_lmac_diag_statis_dump_str1_1; /* 00da: l32r a8, 24 <dbg_lmac_diag_statis_dump-0x74> (24 <dbg_lmac_diag_statis_dump-0x74>) */ /* literal @0x24: .rodata.dbg_lmac_diag_statis_dump.str1.1 */
  a15 = (uint32_t)&lit_rodata_dbg_lmac_diag_statis_dump_str1_1; /* 00dd: l32r a15, 8 <dbg_lmac_diag_statis_dump-0x90> (0 <dbg_lmac_diag_statis_dump-0x98>) */ /* literal @0x8: .rodata.dbg_lmac_diag_statis_dump.str1.1 */
  a14 = (uint32_t)&lit_rodata_dbg_lmac_diag_statis_dump_str1_1; /* 00e0: l32r a14, c <dbg_lmac_diag_statis_dump-0x8c> (6 <dbg_lmac_diag_statis_dump-0x92>) */ /* literal @0xC: .rodata.dbg_lmac_diag_statis_dump.str1.1 */
  a13 = (uint32_t)&lit_rodata_wlog_info_27; /* 00e3: l32r a13, 10 <dbg_lmac_diag_statis_dump-0x88> (0 <dbg_lmac_diag_statis_dump-0x98>) */ /* literal @0x10: .rodata_wlog_info.27 */
  MEM32(a1 + 0) = a8; /* 00e6: s32i.n a8, a1, 0 */
  MEMW(); /* 00e8: memw  */
  a8 = (uint32_t)&wifi_log; /* 00eb: l32r a8, 88 <dbg_lmac_diag_statis_dump-0x10> (0 <dbg_lmac_diag_statis_dump-0x98>) */ /* literal: GOT slot for wifi_log */
  wifi_log(a2, a3, a4, a5); /* call via literal slot */ /* 00ee: callx8 a8 */
  a8 = 0x3FF73DAC; /* 00f1: l32r a8, 28 <dbg_lmac_diag_statis_dump-0x70> (3ff73dac <dbg_lmac_hw_statis_dump+0x3ff73ca4>) */ /* MMIO base */ @0x28
  MEMW(); /* 00f4: memw  */
  a14 = REG32(0x3FF73DAC); /* 00f7: l32i.n a14, a8, 0 */ /* MMIO read: base 0x3FF73DAC+0 */
  a8 = 0x3FF73DB0; /* 00f9: l32r a8, 2c <dbg_lmac_diag_statis_dump-0x6c> (3ff73db0 <dbg_lmac_hw_statis_dump+0x3ff73ca8>) */ /* MMIO base */ @0x2C
  a9 = 0x3FF73DB8; /* 00fc: l32r a9, 34 <dbg_lmac_diag_statis_dump-0x64> (3ff73db8 <dbg_lmac_hw_statis_dump+0x3ff73cb0>) */ /* MMIO base */ @0x34
  MEMW(); /* 00ff: memw  */
  a15 = REG32(0x3FF73DB0); /* 0102: l32i.n a15, a8, 0 */ /* MMIO read: base 0x3FF73DB0+0 */
  a10 = 0x3FF732F0; /* 0104: l32r a10, 38 <dbg_lmac_diag_statis_dump-0x60> (3ff732f0 <dbg_lmac_hw_statis_dump+0x3ff731e8>) */ /* MMIO base */ @0x38
  a8 = 0x3FF73DB4; /* 0107: l32r a8, 30 <dbg_lmac_diag_statis_dump-0x68> (3ff73db4 <dbg_lmac_hw_statis_dump+0x3ff73cac>) */ /* MMIO base */ @0x30
  a11 = 0x3FF732F4; /* 010a: l32r a11, 3c <dbg_lmac_diag_statis_dump-0x5c> (3ff732f4 <dbg_lmac_hw_statis_dump+0x3ff731ec>) */ /* MMIO base */ @0x3C
  a12 = 0x3FF732F8; /* 010d: l32r a12, 40 <dbg_lmac_diag_statis_dump-0x58> (3ff732f8 <dbg_lmac_hw_statis_dump+0x3ff731f0>) */ /* MMIO base */ @0x40
  MEMW(); /* 0110: memw  */
  a8 = REG32(0x3FF73DB4); /* 0113: l32i.n a8, a8, 0 */ /* MMIO read: base 0x3FF73DB4+0 */
  MEMW(); /* 0115: memw  */
  a9 = REG32(0x3FF73DB8); /* 0118: l32i.n a9, a9, 0 */ /* MMIO read: base 0x3FF73DB8+0 */
  MEMW(); /* 011a: memw  */
  a10 = REG32(0x3FF732F0); /* 011d: l32i.n a10, a10, 0 */ /* MMIO read: base 0x3FF732F0+0 */
  MEMW(); /* 011f: memw  */
  a11 = REG32(0x3FF732F4); /* 0122: l32i.n a11, a11, 0 */ /* MMIO read: base 0x3FF732F4+0 */
  MEMW(); /* 0124: memw  */
  a12 = REG32(0x3FF732F8); /* 0127: l32i.n a12, a12, 0 */ /* MMIO read: base 0x3FF732F8+0 */
  a13 = (uint32_t)&lit_rodata_wlog_info_28; /* 0129: l32r a13, 44 <dbg_lmac_diag_statis_dump-0x54> (0 <dbg_lmac_diag_statis_dump-0x98>) */ /* literal @0x44: .rodata_wlog_info.28 */
  MEM32(a1 + 4) = a9; /* 012c: s32i.n a9, a1, 4 */
  MEM32(a1 + 16) = a12; /* 012e: s32i.n a12, a1, 16 */
  a12 = 0x3; /* 0130: movi.n a12, 3 */
  MEM32(a1 + 12) = a11; /* 0132: s32i.n a11, a1, 12 */
  a11 = a2; /* 0134: mov.n a11, a2 */
  MEM32(a1 + 8) = a10; /* 0136: s32i.n a10, a1, 8 */
  a10 = 0x6; /* 0138: movi.n a10, 6 */
  MEM32(a1 + 0) = a8; /* 013a: s32i a8, a1, 0 */
  MEMW(); /* 013d: memw  */
  a8 = (uint32_t)&wifi_log; /* 0140: l32r a8, 8c <dbg_lmac_diag_statis_dump-0xc> (0 <dbg_lmac_diag_statis_dump-0x98>) */ /* literal: GOT slot for wifi_log */
  wifi_log(a2, a3, a4, a5); /* call via literal slot */ /* 0143: callx8 a8 */
  a11 = a2; /* 0146: mov.n a11, a2 */
  a12 = 0x3; /* 0148: movi.n a12, 3 */
  a10 = 0x6; /* 014a: movi.n a10, 6 */
  a8 = (uint32_t)&lit_rodata_dbg_lmac_diag_statis_dump_str1_1; /* 014c: l32r a8, 54 <dbg_lmac_diag_statis_dump-0x44> (36 <dbg_lmac_diag_statis_dump-0x62>) */ /* literal @0x54: .rodata.dbg_lmac_diag_statis_dump.str1.1 */
  MEM32(a1 + 12) = a8; /* 014f: s32i.n a8, a1, 12 */
  a8 = (uint32_t)&lit_rodata_dbg_lmac_diag_statis_dump_str1_1; /* 0151: l32r a8, 58 <dbg_lmac_diag_statis_dump-0x40> (3e <dbg_lmac_diag_statis_dump-0x5a>) */ /* literal @0x58: .rodata.dbg_lmac_diag_statis_dump.str1.1 */
  MEM32(a1 + 8) = a8; /* 0154: s32i.n a8, a1, 8 */
  a8 = (uint32_t)&lit_rodata_dbg_lmac_diag_statis_dump_str1_1; /* 0156: l32r a8, 5c <dbg_lmac_diag_statis_dump-0x3c> (45 <dbg_lmac_diag_statis_dump-0x53>) */ /* literal @0x5C: .rodata.dbg_lmac_diag_statis_dump.str1.1 */
  MEM32(a1 + 4) = a8; /* 0159: s32i.n a8, a1, 4 */
  a8 = (uint32_t)&lit_rodata_dbg_lmac_diag_statis_dump_str1_1; /* 015b: l32r a8, 60 <dbg_lmac_diag_statis_dump-0x38> (4c <dbg_lmac_diag_statis_dump-0x4c>) */ /* literal @0x60: .rodata.dbg_lmac_diag_statis_dump.str1.1 */
  a15 = (uint32_t)&lit_rodata_dbg_lmac_diag_statis_dump_str1_1; /* 015e: l32r a15, 48 <dbg_lmac_diag_statis_dump-0x50> (2a <dbg_lmac_diag_statis_dump-0x6e>) */ /* literal @0x48: .rodata.dbg_lmac_diag_statis_dump.str1.1 */
  a14 = (uint32_t)&lit_rodata_dbg_lmac_diag_statis_dump_str1_1; /* 0161: l32r a14, 4c <dbg_lmac_diag_statis_dump-0x4c> (30 <dbg_lmac_diag_statis_dump-0x68>) */ /* literal @0x4C: .rodata.dbg_lmac_diag_statis_dump.str1.1 */
  a13 = (uint32_t)&lit_rodata_wlog_info_29; /* 0164: l32r a13, 50 <dbg_lmac_diag_statis_dump-0x48> (0 <dbg_lmac_diag_statis_dump-0x98>) */ /* literal @0x50: .rodata_wlog_info.29 */
  MEM32(a1 + 0) = a8; /* 0167: s32i.n a8, a1, 0 */
  MEMW(); /* 0169: memw  */
  a8 = (uint32_t)&wifi_log; /* 016c: l32r a8, 90 <dbg_lmac_diag_statis_dump-0x8> (0 <dbg_lmac_diag_statis_dump-0x98>) */ /* literal: GOT slot for wifi_log */
  wifi_log(a2, a3, a4, a5); /* call via literal slot */ /* 016f: callx8 a8 */
  a12 = 0x3; /* 0172: movi.n a12, 3 */
  a8 = 0x3FF732FC; /* 0174: l32r a8, 64 <dbg_lmac_diag_statis_dump-0x34> (3ff732fc <dbg_lmac_hw_statis_dump+0x3ff731f4>) */ /* MMIO base */ @0x64
  MEMW(); /* 0177: memw  */
  a14 = REG32(0x3FF732FC); /* 017a: l32i.n a14, a8, 0 */ /* MMIO read: base 0x3FF732FC+0 */
  a8 = 0x3FF73424; /* 017c: l32r a8, 68 <dbg_lmac_diag_statis_dump-0x30> (3ff73424 <dbg_lmac_hw_statis_dump+0x3ff7331c>) */ /* MMIO base */ @0x68
  a9 = 0x3FF7342C; /* 017f: l32r a9, 70 <dbg_lmac_diag_statis_dump-0x28> (3ff7342c <dbg_lmac_hw_statis_dump+0x3ff73324>) */ /* MMIO base */ @0x70
  MEMW(); /* 0182: memw  */
  a15 = REG32(0x3FF73424); /* 0185: l32i.n a15, a8, 0 */ /* MMIO read: base 0x3FF73424+0 */
  a10 = 0x3FF73430; /* 0187: l32r a10, 74 <dbg_lmac_diag_statis_dump-0x24> (3ff73430 <dbg_lmac_hw_statis_dump+0x3ff73328>) */ /* MMIO base */ @0x74
  a8 = 0x3FF73428; /* 018a: l32r a8, 6c <dbg_lmac_diag_statis_dump-0x2c> (3ff73428 <dbg_lmac_hw_statis_dump+0x3ff73320>) */ /* MMIO base */ @0x6C
  a11 = 0x3FF73DBC; /* 018d: l32r a11, 78 <dbg_lmac_diag_statis_dump-0x20> (3ff73dbc <dbg_lmac_hw_statis_dump+0x3ff73cb4>) */ /* MMIO base */ @0x78
  MEMW(); /* 0190: memw  */
  a8 = REG32(0x3FF73428); /* 0193: l32i.n a8, a8, 0 */ /* MMIO read: base 0x3FF73428+0 */
  MEMW(); /* 0195: memw  */
  a9 = REG32(0x3FF7342C); /* 0198: l32i.n a9, a9, 0 */ /* MMIO read: base 0x3FF7342C+0 */
  MEMW(); /* 019a: memw  */
  a10 = REG32(0x3FF73430); /* 019d: l32i.n a10, a10, 0 */ /* MMIO read: base 0x3FF73430+0 */
  MEMW(); /* 019f: memw  */
  a11 = REG32(0x3FF73DBC); /* 01a2: l32i.n a11, a11, 0 */ /* MMIO read: base 0x3FF73DBC+0 */
  a13 = (uint32_t)&lit_rodata_wlog_info_30; /* 01a4: l32r a13, 7c <dbg_lmac_diag_statis_dump-0x1c> (0 <dbg_lmac_diag_statis_dump-0x98>) */ /* literal @0x7C: .rodata_wlog_info.30 */
  MEM32(a1 + 12) = a11; /* 01a7: s32i.n a11, a1, 12 */
  a11 = a2; /* 01a9: mov.n a11, a2 */
  MEM32(a1 + 8) = a10; /* 01ab: s32i.n a10, a1, 8 */
  a10 = 0x6; /* 01ad: movi.n a10, 6 */
  MEM32(a1 + 4) = a9; /* 01af: s32i.n a9, a1, 4 */
  MEM32(a1 + 0) = a8; /* 01b1: s32i.n a8, a1, 0 */
  MEMW(); /* 01b3: memw  */
  a8 = (uint32_t)&wifi_log; /* 01b6: l32r a8, 94 <dbg_lmac_diag_statis_dump-0x4> (0 <dbg_lmac_diag_statis_dump-0x98>) */ /* literal: GOT slot for wifi_log */
  wifi_log(a2, a3, a4, a5); /* call via literal slot */ /* 01b9: callx8 a8 */
  return (int32_t)a2; /* 01bc: retw.n  */
}

/* dbg_lmac_ps_statis_dump @ pp_debug.o 00000078 size 279B bind GLOBAL
 * Calls: __divsf3, __extendsfdf2, __floatundisf, wifi_log | Data refs: .rodata.dbg_lmac_ps_statis_dump.str1.1, .rodata_wlog_info.31, .rodata_wlog_info.32, .rodata_wlog_info.33, .rodata_wlog_info.34, __divsf3, __extendsfdf2, __floatundisf, g_pm_cnt, wifi_log
 *   MMIO: none
 *   funcdb v3: 4 call(s), 10 ref(s); disasm: 8 call(s), 10 data ref(s)
 * Fidelity: medium - 112 instr, 0 branches, calls resolved */
int32_t dbg_lmac_ps_statis_dump(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.dbg_lmac_ps_statis_dump; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_78:;
  /* 0078: entry a1, 112 */
  a3 = 0x1; /* 007b: movi.n a3, 1 */
  a3 = 0x80000; /* 007d: slli a3, a3, 19 */
  a13 = (uint32_t)&lit_rodata_wlog_info_31; /* 0080: l32r a13, 0 <dbg_lmac_ps_statis_dump-0x78> (0 <dbg_lmac_ps_statis_dump-0x78>) */ /* literal @0x0: .rodata_wlog_info.31 */
  a11 = 0x80000; /* 0083: mov.n a11, a3 */
  a12 = 0x3; /* 0085: movi a12, 3 */
  a10 = 0x6; /* 0088: movi a10, 6 */
  a8 = (uint32_t)&wifi_log; /* 008b: l32r a8, 58 <dbg_lmac_ps_statis_dump-0x20> (0 <dbg_lmac_ps_statis_dump-0x78>) */ /* literal: GOT slot for wifi_log */
  wifi_log(a2, a3, a4, a5); /* call via literal slot */ /* 008e: callx8 a8 */
  a13 = (uint32_t)&lit_rodata_wlog_info_32; /* 0091: l32r a13, 4 <dbg_lmac_ps_statis_dump-0x74> (0 <dbg_lmac_ps_statis_dump-0x78>) */ /* literal @0x4: .rodata_wlog_info.32 */
  a11 = a3; /* 0094: mov.n a11, a3 */
  a12 = 0x3; /* 0096: movi.n a12, 3 */
  a10 = 0x6; /* 0098: movi.n a10, 6 */
  a8 = (uint32_t)&wifi_log; /* 009a: l32r a8, 5c <dbg_lmac_ps_statis_dump-0x1c> (0 <dbg_lmac_ps_statis_dump-0x78>) */ /* literal: GOT slot for wifi_log */
  wifi_log(a2, a3, a4, a5); /* call via literal slot */ /* 009d: callx8 a8 */
  a2 = (uint32_t)&lit_rodata_dbg_lmac_ps_statis_dump_str1_1; /* 00a0: l32r a2, 14 <dbg_lmac_ps_statis_dump-0x64> (c <dbg_lmac_ps_statis_dump-0x6c>) */ /* literal @0x14: .rodata.dbg_lmac_ps_statis_dump.str1.1 */
  a12 = 0x3; /* 00a3: movi.n a12, 3 */
  a11 = a3; /* 00a5: mov.n a11, a3 */
  a10 = 0x6; /* 00a7: movi.n a10, 6 */
  MEM32(a1 + 52) = a2; /* 00a9: s32i.n a2, a1, 52 */
  a2 = (uint32_t)&lit_rodata_dbg_lmac_ps_statis_dump_str1_1; /* 00ab: l32r a2, 18 <dbg_lmac_ps_statis_dump-0x60> (14 <dbg_lmac_ps_statis_dump-0x64>) */ /* literal @0x18: .rodata.dbg_lmac_ps_statis_dump.str1.1 */
  MEM32(a1 + 48) = a2; /* 00ae: s32i.n a2, a1, 48 */
  a2 = (uint32_t)&lit_rodata_dbg_lmac_ps_statis_dump_str1_1; /* 00b0: l32r a2, 1c <dbg_lmac_ps_statis_dump-0x5c> (1b <dbg_lmac_ps_statis_dump-0x5d>) */ /* literal @0x1C: .rodata.dbg_lmac_ps_statis_dump.str1.1 */
  MEM32(a1 + 44) = a2; /* 00b3: s32i.n a2, a1, 44 */
  a2 = (uint32_t)&lit_rodata_dbg_lmac_ps_statis_dump_str1_1; /* 00b5: l32r a2, 20 <dbg_lmac_ps_statis_dump-0x58> (21 <dbg_lmac_ps_statis_dump-0x57>) */ /* literal @0x20: .rodata.dbg_lmac_ps_statis_dump.str1.1 */
  MEM32(a1 + 40) = a2; /* 00b8: s32i.n a2, a1, 40 */
  a2 = (uint32_t)&lit_rodata_dbg_lmac_ps_statis_dump_str1_1; /* 00ba: l32r a2, 24 <dbg_lmac_ps_statis_dump-0x54> (28 <dbg_lmac_ps_statis_dump-0x50>) */ /* literal @0x24: .rodata.dbg_lmac_ps_statis_dump.str1.1 */
  MEM32(a1 + 36) = a2; /* 00bd: s32i.n a2, a1, 36 */
  a2 = (uint32_t)&lit_rodata_dbg_lmac_ps_statis_dump_str1_1; /* 00bf: l32r a2, 28 <dbg_lmac_ps_statis_dump-0x50> (2d <dbg_lmac_ps_statis_dump-0x4b>) */ /* literal @0x28: .rodata.dbg_lmac_ps_statis_dump.str1.1 */
  MEM32(a1 + 32) = a2; /* 00c2: s32i.n a2, a1, 32 */
  a2 = (uint32_t)&lit_rodata_dbg_lmac_ps_statis_dump_str1_1; /* 00c4: l32r a2, 2c <dbg_lmac_ps_statis_dump-0x4c> (33 <dbg_lmac_ps_statis_dump-0x45>) */ /* literal @0x2C: .rodata.dbg_lmac_ps_statis_dump.str1.1 */
  MEM32(a1 + 28) = a2; /* 00c7: s32i.n a2, a1, 28 */
  a2 = (uint32_t)&lit_rodata_dbg_lmac_ps_statis_dump_str1_1; /* 00c9: l32r a2, 30 <dbg_lmac_ps_statis_dump-0x48> (3a <dbg_lmac_ps_statis_dump-0x3e>) */ /* literal @0x30: .rodata.dbg_lmac_ps_statis_dump.str1.1 */
  MEM32(a1 + 24) = a2; /* 00cc: s32i.n a2, a1, 24 */
  a2 = (uint32_t)&lit_rodata_dbg_lmac_ps_statis_dump_str1_1; /* 00ce: l32r a2, 34 <dbg_lmac_ps_statis_dump-0x44> (40 <dbg_lmac_ps_statis_dump-0x38>) */ /* literal @0x34: .rodata.dbg_lmac_ps_statis_dump.str1.1 */
  MEM32(a1 + 20) = a2; /* 00d1: s32i.n a2, a1, 20 */
  a2 = (uint32_t)&lit_rodata_dbg_lmac_ps_statis_dump_str1_1; /* 00d3: l32r a2, 38 <dbg_lmac_ps_statis_dump-0x40> (46 <dbg_lmac_ps_statis_dump-0x32>) */ /* literal @0x38: .rodata.dbg_lmac_ps_statis_dump.str1.1 */
  MEM32(a1 + 16) = a2; /* 00d6: s32i.n a2, a1, 16 */
  a2 = (uint32_t)&lit_rodata_dbg_lmac_ps_statis_dump_str1_1; /* 00d8: l32r a2, 3c <dbg_lmac_ps_statis_dump-0x3c> (4d <dbg_lmac_ps_statis_dump-0x2b>) */ /* literal @0x3C: .rodata.dbg_lmac_ps_statis_dump.str1.1 */
  MEM32(a1 + 12) = a2; /* 00db: s32i.n a2, a1, 12 */
  a2 = (uint32_t)&lit_rodata_dbg_lmac_ps_statis_dump_str1_1; /* 00dd: l32r a2, 40 <dbg_lmac_ps_statis_dump-0x38> (53 <dbg_lmac_ps_statis_dump-0x25>) */ /* literal @0x40: .rodata.dbg_lmac_ps_statis_dump.str1.1 */
  MEM32(a1 + 8) = a2; /* 00e0: s32i a2, a1, 8 */
  a2 = (uint32_t)&lit_rodata_dbg_lmac_ps_statis_dump_str1_1; /* 00e3: l32r a2, 44 <dbg_lmac_ps_statis_dump-0x34> (5b <dbg_lmac_ps_statis_dump-0x1d>) */ /* literal @0x44: .rodata.dbg_lmac_ps_statis_dump.str1.1 */
  MEM32(a1 + 4) = a2; /* 00e6: s32i a2, a1, 4 */
  a2 = (uint32_t)&lit_rodata_dbg_lmac_ps_statis_dump_str1_1; /* 00e9: l32r a2, 48 <dbg_lmac_ps_statis_dump-0x30> (63 <dbg_lmac_ps_statis_dump-0x15>) */ /* literal @0x48: .rodata.dbg_lmac_ps_statis_dump.str1.1 */
  a15 = (uint32_t)&lit_rodata_dbg_lmac_ps_statis_dump_str1_1; /* 00ec: l32r a15, 8 <dbg_lmac_ps_statis_dump-0x70> (0 <dbg_lmac_ps_statis_dump-0x78>) */ /* literal @0x8: .rodata.dbg_lmac_ps_statis_dump.str1.1 */
  a14 = (uint32_t)&lit_rodata_dbg_lmac_ps_statis_dump_str1_1; /* 00ef: l32r a14, c <dbg_lmac_ps_statis_dump-0x6c> (7 <dbg_lmac_ps_statis_dump-0x71>) */ /* literal @0xC: .rodata.dbg_lmac_ps_statis_dump.str1.1 */
  a13 = (uint32_t)&lit_rodata_wlog_info_33; /* 00f2: l32r a13, 10 <dbg_lmac_ps_statis_dump-0x68> (0 <dbg_lmac_ps_statis_dump-0x78>) */ /* literal @0x10: .rodata_wlog_info.33 */
  MEM32(a1 + 0) = a2; /* 00f5: s32i a2, a1, 0 */
  MEMW(); /* 00f8: memw  */
  a8 = (uint32_t)&wifi_log; /* 00fb: l32r a8, 60 <dbg_lmac_ps_statis_dump-0x18> (0 <dbg_lmac_ps_statis_dump-0x78>) */ /* literal: GOT slot for wifi_log */
  wifi_log(a2, a3, a4, a5); /* call via literal slot */ /* 00fe: callx8 a8 */
  a2 = (uint32_t)&g_pm_cnt; /* 0101: l32r a2, 4c <dbg_lmac_ps_statis_dump-0x2c> (0 <dbg_lmac_ps_statis_dump-0x78>) */ /* literal @0x4C: g_pm_cnt */
  a4 = MEM32(a2 + 48); /* 0104: l32i.n a4, a2, 48 */
  a10 = a4; /* 0106: mov.n a10, a4 */
  a11 = MEM32(a2 + 52); /* 0108: l32i.n a11, a2, 52 */
  a8 = (uint32_t)&floatundisf; /* 010a: l32r a8, 64 <dbg_lmac_ps_statis_dump-0x14> (0 <dbg_lmac_ps_statis_dump-0x78>) */ /* literal: GOT slot for __floatundisf */
  floatundisf(a2, a3, a4, a5); /* call via literal slot */ /* 010d: callx8 a8 */
  /* 0110: wfr f0, a10 */
  a8 = 0x42C80000; /* 0113: l32r a8, 54 <dbg_lmac_ps_statis_dump-0x24> (42c80000 <dbg_lmac_hw_statis_dump+0x42c7fef8>) */ @0x54
  /* 0116: wfr f1, a8 */
  /* 0119: mul.s f0, f0, f1 */
  a5 = MEM32(a2 + 64); /* 011c: l32i a5, a2, 64 */
  a10 = a5; /* 011f: mov.n a10, a5 */
  a6 = MEM32(a2 + 68); /* 0121: l32i a6, a2, 68 */
  a11 = a6; /* 0124: mov.n a11, a6 */
  /* 0126: ssi f0, a1, 64 */
  MEMW(); /* 0129: memw  */
  a8 = (uint32_t)&floatundisf; /* 012c: l32r a8, 68 <dbg_lmac_ps_statis_dump-0x10> (0 <dbg_lmac_ps_statis_dump-0x78>) */ /* literal: GOT slot for __floatundisf */
  floatundisf(a2, a3, a4, a5); /* call via literal slot */ /* 012f: callx8 a8 */
  a11 = a10; /* 0132: mov.n a11, a10 */
  a10 = MEM32(a1 + 64); /* 0134: l32i a10, a1, 64 */
  a8 = (uint32_t)&divsf3; /* 0137: l32r a8, 6c <dbg_lmac_ps_statis_dump-0xc> (0 <dbg_lmac_ps_statis_dump-0x78>) */ /* literal: GOT slot for __divsf3 */
  divsf3(a2, a3, a4, a5); /* call via literal slot */ /* 013a: callx8 a8 */
  a8 = (uint32_t)&extendsfdf2; /* 013d: l32r a8, 70 <dbg_lmac_ps_statis_dump-0x8> (0 <dbg_lmac_ps_statis_dump-0x78>) */ /* literal: GOT slot for __extendsfdf2 */
  extendsfdf2(a2, a3, a4, a5); /* call via literal slot */ /* 0140: callx8 a8 */
  a12 = 0x3; /* 0143: movi.n a12, 3 */
  MEM32(a1 + 56) = a10; /* 0145: s32i.n a10, a1, 56 */
  a10 = 0x6; /* 0147: movi.n a10, 6 */
  MEM32(a1 + 60) = a11; /* 0149: s32i.n a11, a1, 60 */
  a11 = a3; /* 014b: mov.n a11, a3 */
  MEM32(a1 + 48) = a5; /* 014d: s32i.n a5, a1, 48 */
  a5 = MEM32(a2 + 56); /* 014f: l32i.n a5, a2, 56 */
  MEM32(a1 + 40) = a4; /* 0151: s32i.n a4, a1, 40 */
  MEM32(a1 + 44) = a5; /* 0153: s32i.n a5, a1, 44 */
  a4 = MEM32(a2 + 44); /* 0155: l32i.n a4, a2, 44 */
  MEM32(a1 + 36) = a4; /* 0157: s32i.n a4, a1, 36 */
  a4 = MEM32(a2 + 40); /* 0159: l32i.n a4, a2, 40 */
  MEM32(a1 + 32) = a4; /* 015b: s32i.n a4, a1, 32 */
  a4 = MEM32(a2 + 36); /* 015d: l32i.n a4, a2, 36 */
  MEM32(a1 + 28) = a4; /* 015f: s32i.n a4, a1, 28 */
  a4 = MEM32(a2 + 32); /* 0161: l32i.n a4, a2, 32 */
  MEM32(a1 + 24) = a4; /* 0163: s32i.n a4, a1, 24 */
  a4 = MEM32(a2 + 28); /* 0165: l32i.n a4, a2, 28 */
  MEM32(a1 + 20) = a4; /* 0167: s32i.n a4, a1, 20 */
  a4 = MEM32(a2 + 24); /* 0169: l32i.n a4, a2, 24 */
  MEM32(a1 + 16) = a4; /* 016b: s32i.n a4, a1, 16 */
  a4 = MEM32(a2 + 20); /* 016d: l32i.n a4, a2, 20 */
  MEM32(a1 + 12) = a4; /* 016f: s32i.n a4, a1, 12 */
  a4 = MEM32(a2 + 16); /* 0171: l32i.n a4, a2, 16 */
  MEM32(a1 + 8) = a4; /* 0173: s32i.n a4, a1, 8 */
  a4 = MEM32(a2 + 12); /* 0175: l32i.n a4, a2, 12 */
  MEM32(a1 + 4) = a4; /* 0177: s32i.n a4, a1, 4 */
  a4 = MEM32(a2 + 8); /* 0179: l32i.n a4, a2, 8 */
  MEM32(a1 + 0) = a4; /* 017b: s32i.n a4, a1, 0 */
  a15 = MEM32(a2 + 4); /* 017d: l32i.n a15, a2, 4 */
  a14 = MEM32(a2 + 0); /* 017f: l32i.n a14, a2, 0 */
  a13 = (uint32_t)&lit_rodata_wlog_info_34; /* 0181: l32r a13, 50 <dbg_lmac_ps_statis_dump-0x28> (0 <dbg_lmac_ps_statis_dump-0x78>) */ /* literal @0x50: .rodata_wlog_info.34 */
  MEMW(); /* 0184: memw  */
  a8 = (uint32_t)&wifi_log; /* 0187: l32r a8, 74 <dbg_lmac_ps_statis_dump-0x4> (0 <dbg_lmac_ps_statis_dump-0x78>) */ /* literal: GOT slot for wifi_log */
  wifi_log(a2, a3, a4, a5); /* call via literal slot */ /* 018a: callx8 a8 */
  return (int32_t)a2; /* 018d: retw.n  */
}

/* dbg_lmac_ps_statis_reset @ pp_debug.o 00000008 size 18B bind GLOBAL
 * Calls: memset | Data refs: g_pm_cnt, memset
 *   MMIO: none
 *   funcdb v3: 1 call(s), 2 ref(s); disasm: 1 call(s), 2 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t dbg_lmac_ps_statis_reset(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.dbg_lmac_ps_statis_reset; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_8:;
  /* 0008: entry a1, 32 */
  a10 = (uint32_t)&g_pm_cnt; /* 000b: l32r a10, 0 <dbg_lmac_ps_statis_reset-0x8> (0 <dbg_lmac_ps_statis_reset-0x8>) */ /* literal @0x0: g_pm_cnt */
  a12 = 0x48; /* 000e: movi.n a12, 72 */
  a11 = 0x0; /* 0010: movi.n a11, 0 */
  a8 = (uint32_t)&memset; /* 0012: l32r a8, 4 <dbg_lmac_ps_statis_reset-0x4> (0 <dbg_lmac_ps_statis_reset-0x8>) */ /* literal: GOT slot for memset */
  memset(a2, a3, a4, a5); /* call via literal slot */ /* 0015: callx8 a8 */
  return (int32_t)a2; /* 0018: retw.n  */
}

/* dbg_lmac_statis_dump @ pp_debug.o 00000014 size 50B bind GLOBAL
 * Calls: dbg_lmac_diag_statis_dump, dbg_lmac_hw_statis_dump, dbg_lmac_ps_statis_dump, dbg_lmac_rxtx_statis_dump, esf_buf_statis_dump | Data refs: dbg_lmac_diag_statis_dump, dbg_lmac_hw_statis_dump, dbg_lmac_ps_statis_dump, dbg_lmac_rxtx_statis_dump, esf_buf_statis_dump
 *   MMIO: none
 *   funcdb v3: 5 call(s), 5 ref(s); disasm: 5 call(s), 5 data ref(s)
 * Fidelity: medium - 17 instr, 5 branches, calls resolved */
int32_t dbg_lmac_statis_dump(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.dbg_lmac_statis_dump; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_14:;
  /* 0014: entry a1, 32 */
  if (!((a2 >> 0) & 1)) goto L_20; /* 0017: bbci a2, 0, 20 <dbg_lmac_statis_dump+0xc> */
  a8 = (uint32_t)&esf_buf_statis_dump; /* 001a: l32r a8, 0 <dbg_lmac_statis_dump-0x14> (0 <dbg_lmac_statis_dump-0x14>) */ /* literal: GOT slot for esf_buf_statis_dump */
  esf_buf_statis_dump(a2, a3, a4, a5); /* call via literal slot */ /* 001d: callx8 a8 */
L_20:;
  if (!((a2 >> 1) & 1)) goto L_29; /* 0020: bbci a2, 1, 29 <dbg_lmac_statis_dump+0x15> */
  a8 = (uint32_t)&dbg_lmac_rxtx_statis_dump; /* 0023: l32r a8, 4 <dbg_lmac_statis_dump-0x10> (0 <dbg_lmac_statis_dump-0x14>) */ /* literal: GOT slot for dbg_lmac_rxtx_statis_dump */
  dbg_lmac_rxtx_statis_dump(a2, a3, a4, a5); /* call via literal slot */ /* 0026: callx8 a8 */
L_29:;
  if (!((a2 >> 2) & 1)) goto L_32; /* 0029: bbci a2, 2, 32 <dbg_lmac_statis_dump+0x1e> */
  a8 = (uint32_t)&dbg_lmac_hw_statis_dump; /* 002c: l32r a8, 8 <dbg_lmac_statis_dump-0xc> (0 <dbg_lmac_statis_dump-0x14>) */ /* literal: GOT slot for dbg_lmac_hw_statis_dump */
  dbg_lmac_hw_statis_dump(a2, a3, a4, a5); /* call via literal slot */ /* 002f: callx8 a8 */
L_32:;
  if (!((a2 >> 3) & 1)) goto L_3b; /* 0032: bbci a2, 3, 3b <dbg_lmac_statis_dump+0x27> */
  a8 = (uint32_t)&dbg_lmac_diag_statis_dump; /* 0035: l32r a8, c <dbg_lmac_statis_dump-0x8> (0 <dbg_lmac_statis_dump-0x14>) */ /* literal: GOT slot for dbg_lmac_diag_statis_dump */
  dbg_lmac_diag_statis_dump(a2, a3, a4, a5); /* call via literal slot */ /* 0038: callx8 a8 */
L_3b:;
  if (!((a2 >> 4) & 1)) goto L_44; /* 003b: bbci a2, 4, 44 <dbg_lmac_statis_dump+0x30> */
  a8 = (uint32_t)&dbg_lmac_ps_statis_dump; /* 003e: l32r a8, 10 <dbg_lmac_statis_dump-0x4> (0 <dbg_lmac_statis_dump-0x14>) */ /* literal: GOT slot for dbg_lmac_ps_statis_dump */
  dbg_lmac_ps_statis_dump(a2, a3, a4, a5); /* call via literal slot */ /* 0041: callx8 a8 */
L_44:;
  return (int32_t)a2; /* 0044: retw.n  */
}

/* dbg_his_lmac_eb_show @ pp_debug.o 00000000 size 5B bind GLOBAL
 * Calls: none | Data refs: none
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t dbg_his_lmac_eb_show(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.dbg_his_lmac_eb_show; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_0:;
  /* 0000: entry a1, 32 */
  return (int32_t)a2; /* 0003: retw.n  */
}

/* dbg_his_lmac_event_show @ pp_debug.o 00000000 size 5B bind GLOBAL
 * Calls: none | Data refs: none
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t dbg_his_lmac_event_show(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.dbg_his_lmac_event_show; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_0:;
  /* 0000: entry a1, 32 */
  return (int32_t)a2; /* 0003: retw.n  */
}

/* dbg_his_lmac_int_show @ pp_debug.o 00000000 size 5B bind GLOBAL
 * Calls: none | Data refs: none
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t dbg_his_lmac_int_show(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.dbg_his_lmac_int_show; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_0:;
  /* 0000: entry a1, 32 */
  return (int32_t)a2; /* 0003: retw.n  */
}

/* dbg_his_lmac_rx_show @ pp_debug.o 00000000 size 5B bind GLOBAL
 * Calls: none | Data refs: none
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t dbg_his_lmac_rx_show(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.dbg_his_lmac_rx_show; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_0:;
  /* 0000: entry a1, 32 */
  return (int32_t)a2; /* 0003: retw.n  */
}

/* dbg_his_lmac_tx_show @ pp_debug.o 00000000 size 5B bind GLOBAL
 * Calls: none | Data refs: none
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t dbg_his_lmac_tx_show(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.dbg_his_lmac_tx_show; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_0:;
  /* 0000: entry a1, 32 */
  return (int32_t)a2; /* 0003: retw.n  */
}

/* dbg_ebuf_loc_show @ pp_debug.o 00000000 size 5B bind GLOBAL
 * Calls: none | Data refs: none
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t dbg_ebuf_loc_show(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.dbg_ebuf_loc_show; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_0:;
  /* 0000: entry a1, 32 */
  return (int32_t)a2; /* 0003: retw.n  */
}

/* dbg_perf_path_show @ pp_debug.o 00000000 size 5B bind GLOBAL
 * Calls: none | Data refs: none
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t dbg_perf_path_show(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.dbg_perf_path_show; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_0:;
  /* 0000: entry a1, 32 */
  return (int32_t)a2; /* 0003: retw.n  */
}

/* dbg_perf_path_set @ pp_debug.o 00000000 size 5B bind GLOBAL
 * Calls: none | Data refs: none
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t dbg_perf_path_set(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.dbg_perf_path_set; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_0:;
  /* 0000: entry a1, 32 */
  return (int32_t)a2; /* 0003: retw.n  */
}

/* dbg_perf_throughput_cal @ pp_debug.o 0000002c size 117B bind GLOBAL
 * Calls: wifi_log | Data refs: .bss.s_t_old, .bss.s_total, .rodata_wlog_info.35, g_mesh_init_ps_type, g_mesh_is_root, g_mesh_is_started, g_osi_funcs_p, g_wifi_mac_time_delta, wifi_log
 *   MMIO: 0x3FF73C00
 *   funcdb v3: 1 call(s), 9 ref(s); disasm: 1 call(s), 9 data ref(s)
 * Fidelity: medium - 45 instr, 5 branches, calls resolved */
int32_t dbg_perf_throughput_cal(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.dbg_perf_throughput_cal; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_2c:;
  /* 002c: entry a1, 32 */
  a3 = (uint32_t)&g_mesh_is_started; /* 002f: l32r a3, 0 <dbg_perf_throughput_cal-0x2c> (0 <dbg_perf_throughput_cal-0x2c>) */ /* literal @0x0: g_mesh_is_started */
  a3 = MEM8(a3 + 0); /* 0032: l8ui a3, a3, 0 */
  if (a3 == 0) goto L_5c; /* 0035: beqz.n a3, 5c <dbg_perf_throughput_cal+0x30> */
  a3 = (uint32_t)&g_mesh_is_root; /* 0037: l32r a3, 4 <dbg_perf_throughput_cal-0x28> (0 <dbg_perf_throughput_cal-0x2c>) */ /* literal @0x4: g_mesh_is_root */
  MEMW(); /* 003a: memw  */
  a3 = MEM8(a3 + 0); /* 003d: l8ui a3, a3, 0 */
  a3 = (a3 >> 0) & 0xFF; /* 0040: extui a3, a3, 0, 8 */
  if (a3 != 0) goto L_5c; /* 0043: bnez.n a3, 5c <dbg_perf_throughput_cal+0x30> */
  a3 = (uint32_t)&g_mesh_init_ps_type; /* 0045: l32r a3, 8 <dbg_perf_throughput_cal-0x24> (0 <dbg_perf_throughput_cal-0x2c>) */ /* literal @0x8: g_mesh_init_ps_type */
  a3 = MEM32(a3 + 0); /* 0048: l32i.n a3, a3, 0 */
  if (a3 == 0) goto L_5c; /* 004a: beqz.n a3, 5c <dbg_perf_throughput_cal+0x30> */
  a3 = (uint32_t)&g_osi_funcs_p; /* 004c: l32r a3, c <dbg_perf_throughput_cal-0x20> (0 <dbg_perf_throughput_cal-0x2c>) */ /* literal @0xC: g_osi_funcs_p */
  a3 = MEM32(a3 + 0); /* 004f: l32i a3, a3, 0 */
  a10 = MEM32(a3 + 272); /* 0052: l32i a10, a3, 0x110 */
  ((int32_t(*)())a10)(a2, a3, a4, a5); /* 0055: callx8 a10 */ /* indirect */
  goto L_6b; /* 0058: j 6b <dbg_perf_throughput_cal+0x3f> */
  /* 005b: .byte 00 */
L_5c:;
  a3 = 0x3FF73C00; /* 005c: l32r a3, 10 <dbg_perf_throughput_cal-0x1c> (3ff73c00 <dbg_lmac_hw_statis_dump+0x3ff73af8>) */ /* MMIO base */ @0x10
  MEMW(); /* 005f: memw  */
  a10 = REG32(0x3FF73C00); /* 0062: l32i.n a10, a3, 0 */ /* MMIO read: base 0x3FF73C00+0 */
  a3 = (uint32_t)&g_wifi_mac_time_delta; /* 0064: l32r a3, 14 <dbg_perf_throughput_cal-0x18> (0 <dbg_perf_throughput_cal-0x2c>) */ /* literal @0x14: g_wifi_mac_time_delta */
  a3 = MEM32(a3 + 0); /* 0067: l32i.n a3, a3, 0 */
  a10 = a10 + a3; /* 0069: add.n a10, a10, a3 */
L_6b:;
  a3 = (uint32_t)&bss_s_total; /* 006b: l32r a3, 18 <dbg_perf_throughput_cal-0x14> (0 <dbg_perf_throughput_cal-0x2c>) */ /* literal @0x18: .bss.s_total */
  a8 = MEM32(a3 + 0); /* 006e: l32i.n a8, a3, 0 */
  a14 = a2 + a8; /* 0070: add.n a14, a2, a8 */
  a8 = (uint32_t)&bss_s_t_old; /* 0072: l32r a8, 1c <dbg_perf_throughput_cal-0x10> (0 <dbg_perf_throughput_cal-0x2c>) */ /* literal @0x1C: .bss.s_t_old */
  a2 = MEM32(a8 + 0); /* 0075: l32i.n a2, a8, 0 */
  a2 = a10 - a2; /* 0077: sub a2, a10, a2 */
  a9 = 0x7A11FF; /* 007a: l32r a9, 20 <dbg_perf_throughput_cal-0xc> (7a11ff <dbg_lmac_hw_statis_dump+0x7a10f7>) */ @0x20
  MEM32(a3 + 0) = a14; /* 007d: s32i.n a14, a3, 0 */
  if (a9 >= a2) goto L_9c; /* 007f: bgeu a9, a2, 9c <dbg_perf_throughput_cal+0x70> */
  a12 = 0x3; /* 0082: movi.n a12, 3 */
  a11 = 0x1; /* 0084: movi.n a11, 1 */
  a2 = 0x0; /* 0086: movi.n a2, 0 */
  a13 = (uint32_t)&lit_rodata_wlog_info_35; /* 0088: l32r a13, 24 <dbg_perf_throughput_cal-0x8> (0 <dbg_perf_throughput_cal-0x2c>) */ /* literal @0x24: .rodata_wlog_info.35 */
  MEM32(a8 + 0) = a10; /* 008b: s32i a10, a8, 0 */
  a10 = 0x6; /* 008e: movi a10, 6 */
  MEMW(); /* 0091: memw  */
  a8 = (uint32_t)&wifi_log; /* 0094: l32r a8, 28 <dbg_perf_throughput_cal-0x4> (0 <dbg_perf_throughput_cal-0x2c>) */ /* literal: GOT slot for wifi_log */
  wifi_log(a2, a3, a4, a5); /* call via literal slot */ /* 0097: callx8 a8 */
  MEM32(a3 + 0) = a2; /* 009a: s32i.n a2, a3, 0 */
L_9c:;
  MEMW(); /* 009c: memw  */
  return (int32_t)a2; /* 009f: retw.n  */
}

/* dbg_lmac_init @ pp_debug.o 00000000 size 5B bind GLOBAL
 * Calls: none | Data refs: none
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t dbg_lmac_init(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.dbg_lmac_init; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_0:;
  /* 0000: entry a1, 32 */
  return (int32_t)a2; /* 0003: retw.n  */
}

