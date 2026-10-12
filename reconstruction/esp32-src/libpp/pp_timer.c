/* ===== pp_timer.o : reconstructed from libpp.a (ESP32, Xtensa, esp-2022r1) =====
 * Toolchain: xtensa-esp32-elf (GCC 11.2.0 crosstool-NG esp-2022r1).
 * ABI: args a2..a7, return a2 (all functions take a2..a7, return int32_t).
 * memw barriers preserved as MEMW(). MMIO as REG32/REG16/REG8(addr).
 * Calls with unknown arg counts are modeled with 4 live args (a2..a5);
 * a2..a7 are clobbered across calls (windowed-ABI approximation).
 * Sections: .text.pp_timer_active, .text.pp_timer_beacon_monitor, .text.pp_timer_beacon_monitor_tbtt, .text.pp_timer_coex_restart, .text.pp_timer_coex_slice, .text.pp_timer_connectionless_wake_interval, .text.pp_timer_connectionless_wake_window, .text.pp_timer_disconnected_sleep_delay, .text.pp_timer_dream, .text.pp_timer_keep_alive, .text.pp_timer_noise_check, .text.pp_timer_process, .text.pp_timer_register_post_cb, .text.pp_timer_resample, .text.pp_timer_sleep_delay, .wifislpiram.2, .wifislpiram.3
 * Undefined refs (16): g_osi_funcs_p, pm_active_timeout_process, pm_beacon_monitor_tbtt_timeout_process, pm_beacon_monitor_timeout_process, pm_coex_restart_timeout_process, pm_coex_slice_timeout_process, pm_connectionless_wake_interval_timeout_process, pm_connectionless_wake_window_timeout_process, pm_disconnected_sleep_delay_timeout_process, pm_dream_timeout_process, pm_keep_alive_timeout_process, pm_noise_check_process, pm_sleep_delay_timeout_process, pm_tbtt_process, ptr_beacon_offset_funcs, wifi_log
 */
#include <stdint.h>
#define REG32(a) (*(volatile uint32_t *)(a))
#define REG16(a) (*(volatile uint16_t *)(a))
#define REG8(a)  (*(volatile uint8_t *)(a))
#define MEM32(a) (*(volatile uint32_t *)(a))
#define MEM16(a) (*(volatile uint16_t *)(a))
#define MEM8(a)  (*(volatile uint8_t *)(a))
#define MEMW() __asm__ volatile("memw" ::: "memory")

extern int32_t pm_coex_restart_timeout_process();
extern int32_t pm_keep_alive_timeout_process();
extern int32_t pm_beacon_monitor_tbtt_timeout_process();
extern int32_t pm_beacon_monitor_timeout_process();
extern int32_t pm_connectionless_wake_window_timeout_process();
extern int32_t pm_connectionless_wake_interval_timeout_process();
extern int32_t pm_disconnected_sleep_delay_timeout_process();
extern int32_t pm_sleep_delay_timeout_process();
extern int32_t pm_coex_slice_timeout_process();
extern int32_t pm_active_timeout_process();
extern int32_t pm_dream_timeout_process();
extern int32_t pm_tbtt_process();
extern int32_t pm_noise_check_process();
extern uint32_t rodata_wlog_warning_4; /* .rodata_wlog_warning.4 */
extern int32_t wifi_log();
uint32_t g_pp_timer_info; /* defined here (.bss/.data); was: g_pp_timer_info */
extern uint32_t rodata_wlog_warning_5; /* .rodata_wlog_warning.5 */
extern int32_t g_osi_funcs_p();
extern int32_t bss_s_timer_post();

/* pool[pp_timer_resample]: +0x0=0x00000000 */
/* pool[pp_timer_coex_restart]: +0x0=0x00000000 */
/* pool[pp_timer_keep_alive]: +0x0=0x00000000 */
/* pool[pp_timer_beacon_monitor_tbtt]: +0x0=0x00000000 */
/* pool[pp_timer_beacon_monitor]: +0x0=0x00000000 */
/* pool[pp_timer_connectionless_wake_window]: +0x0=0x00000000 */
/* pool[pp_timer_connectionless_wake_interval]: +0x0=0x00000000 */
/* pool[pp_timer_disconnected_sleep_delay]: +0x0=0x00000000 */
/* pool[pp_timer_sleep_delay]: +0x0=0x00000000 */
/* pool[pp_timer_coex_slice]: +0x0=0x00000000 */
/* pool[pp_timer_active]: +0x0=0x00000000 */
/* pool[pp_timer_dream]: +0x0=0x00000000 */
/* pool[pp_timer_tbtt]: +0x0=0x00000000 */
/* pool[pp_timer_noise_check]: +0x0=0x00000000 */
/* pool[pp_timer_do_process]: +0x0=0x00000000(.rodata_wlog_warning.4), +0x10=0x00000000(wifi_log), +0x4=0x00000000(g_pp_timer_info), +0x8=0x00000000(.rodata_wlog_warning.5), +0x14=0x00000000(wifi_log), +0xc=0x00000000(g_osi_funcs_p) */
/* pool[pp_timer_register_post_cb]: +0x0=0x00000000(.bss.s_timer_post) */
/* pool[pp_timer_process]: +0x0=0x00000000(.bss.s_timer_post) */

/* pp_timer_do_process @ pp_timer.o 00000018 size 146B bind GLOBAL
 * Calls: wifi_log[got], wifi_log[got], g_osi_funcs_p[got], g_osi_funcs_p[got] | Data refs: .rodata_wlog_warning.4, wifi_log, g_pp_timer_info, .rodata_wlog_warning.5, g_osi_funcs_p
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 4 call(s), 5 data ref(s)
 * Fidelity: medium - 57 instr, 10 branches, calls resolved */
int32_t pp_timer_do_process(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .wifislpiram.3; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_18:;
  /* 0018: entry a1, 32 */
  if (a2 != 0) goto L_34; /* 001b: bnez.n a2, 34 <pp_timer_do_process+0x1c> */
  a13 = (uint32_t)&lit_rodata_wlog_warning_4; /* 001d: l32r a13, 0 <pp_timer_do_process-0x18> (0 <pp_timer_do_process-0x18>) */ /* literal @0x0: .rodata_wlog_warning.4 */
  a11 = 0x1; /* 0020: movi.n a11, 1 */
  a12 = 0x2; /* 0022: movi.n a12, 2 */
  a11 = 0x800; /* 0024: slli a11, a11, 11 */
  a10 = 0x6; /* 0027: movi a10, 6 */
  a8 = (uint32_t)&wifi_log; /* 002a: l32r a8, 10 <pp_timer_do_process-0x8> (0 <pp_timer_do_process-0x18>) */ /* literal: GOT slot for wifi_log */
  wifi_log(a2, a3, a4, a5); /* call via literal slot */ /* 002d: callx8 a8 */
  goto L_a8; /* 0030: j a8 <pp_timer_do_process+0x90> */
  /* 0033: .byte 00 */
L_34:;
  a12 = MEM8(a2 + 0); /* 0034: l8ui a12, a2, 0 */
  a9 = (uint32_t)&g_pp_timer_info; /* 0037: l32r a9, 4 <pp_timer_do_process-0x14> (0 <pp_timer_do_process-0x18>) */ /* literal @0x4: g_pp_timer_info */
  a8 = (a12 << 8) + a9; /* 003a: addx8 a8, a12, a9 */
  a8 = MEM8(a8 + 0); /* 003d: l8ui a8, a8, 0 */
  if (a8 == a12) goto L_5c; /* 0040: beq a8, a12, 5c <pp_timer_do_process+0x44> */
  a11 = a9; /* 0043: mov.n a11, a9 */
  a8 = 0x0; /* 0045: movi.n a8, 0 */
  a10 = 0xE; /* 0047: movi.n a10, 14 */
  /* 0049: loop a10, 59 <pp_timer_do_process+0x41> */ /* loop a10 times, end L_59; body shown single-pass */
  a13 = MEM8(a11 + 0); /* 004c: l8ui a13, a11, 0 */
  if (a13 == a12) goto L_61; /* 004f: beq a13, a12, 61 <pp_timer_do_process+0x49> */
  a8 = 0x1; /* 0052: addi.n a8, a8, 1 */
  a8 = 0x1; /* 0054: extui a8, a8, 0, 8 */
  a11 = a11 + (8); /* 0057: addi.n a11, a11, 8 */
L_59:;
  goto L_70; /* 0059: j 70 <pp_timer_do_process+0x58> */
L_5c:;
  a10 = 0xD; /* 005c: movi.n a10, 13 */
  if (a10 < a8) goto L_70; /* 005e: bltu a10, a8, 70 <pp_timer_do_process+0x58> */
L_61:;
  a8 = (a8 << 8) + a9; /* 0061: addx8 a8, a8, a9 */
  a8 = MEM32(a8 + 4); /* 0064: l32i.n a8, a8, 4 */
  if (a8 == 0) goto L_99; /* 0066: beqz.n a8, 99 <pp_timer_do_process+0x81> */
  a10 = a2; /* 0068: mov.n a10, a2 */
  ((int32_t(*)())a8)(a2, a3, a4, a5); /* 006a: callx8 a8 */ /* indirect */
  goto L_99; /* 006d: j 99 <pp_timer_do_process+0x81> */
L_70:;
  a13 = (uint32_t)&lit_rodata_wlog_warning_5; /* 0070: l32r a13, 8 <pp_timer_do_process-0x10> (0 <pp_timer_do_process-0x18>) */ /* literal @0x8: .rodata_wlog_warning.5 */
  a11 = 0x1; /* 0073: movi a11, 1 */
  a12 = 0x2; /* 0076: movi a12, 2 */
  a11 = 0x800; /* 0079: slli a11, a11, 11 */
  a10 = 0x6; /* 007c: movi a10, 6 */
  a8 = (uint32_t)&wifi_log; /* 007f: l32r a8, 14 <pp_timer_do_process-0x4> (0 <pp_timer_do_process-0x18>) */ /* literal: GOT slot for wifi_log */
  wifi_log(a2, a3, a4, a5); /* call via literal slot */ /* 0082: callx8 a8 */
  a8 = (uint32_t)&g_osi_funcs_p; /* 0085: l32r a8, c <pp_timer_do_process-0xc> (0 <pp_timer_do_process-0x18>) */ /* literal @0xC: g_osi_funcs_p */
  a10 = a2; /* 0088: mov.n a10, a2 */
  a2 = 0x0; /* 008a: movi.n a2, 0 */
  a8 = MEM32(a8 + 0); /* 008c: l32i.n a8, a8, 0 */
  a8 = MEM32(a8 + 176); /* 008e: l32i a8, a8, 176 */
  g_osi_funcs_p(a2, a3, a4, a5); /* call via literal slot */ /* 0091: callx8 a8 */
  goto L_a8; /* 0094: j a8 <pp_timer_do_process+0x90> */
  /* 0097: .byte 00 */
  /* 0098: .byte 00 */
L_99:;
  a8 = (uint32_t)&g_osi_funcs_p; /* 0099: l32r a8, c <pp_timer_do_process-0xc> (0 <pp_timer_do_process-0x18>) */ /* literal @0xC: g_osi_funcs_p */
  a10 = a2; /* 009c: mov.n a10, a2 */
  a2 = 0x1; /* 009e: movi.n a2, 1 */
  a8 = MEM32(a8 + 0); /* 00a0: l32i.n a8, a8, 0 */
  a8 = MEM32(a8 + 176); /* 00a2: l32i a8, a8, 176 */
  g_osi_funcs_p(a2, a3, a4, a5); /* call via literal slot */ /* 00a5: callx8 a8 */
L_a8:;
  return (int32_t)a2; /* 00a8: retw.n  */
}

/* pp_timer_register_post_cb @ pp_timer.o 00000004 size 15B bind GLOBAL
 * Calls: none | Data refs: .bss.s_timer_post
 *   MMIO: none
 *   funcdb v3: 0 call(s), 1 ref(s); disasm: 0 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t pp_timer_register_post_cb(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pp_timer_register_post_cb; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a8 = (uint32_t)&bss_s_timer_post; /* 0007: l32r a8, 0 <pp_timer_register_post_cb-0x4> (0 <pp_timer_register_post_cb-0x4>) */ /* literal @0x0: .bss.s_timer_post */
  MEM32(a8 + 0) = a2; /* 000a: s32i.n a2, a8, 0 */
  a2 = 0x0; /* 000c: movi.n a2, 0 */
  MEMW(); /* 000e: memw  */
  return (int32_t)a2; /* 0011: retw.n  */
}

/* pp_timer_process @ pp_timer.o 00000004 size 26B bind GLOBAL
 * Calls: .bss.s_timer_post[got] | Data refs: .bss.s_timer_post
 *   MMIO: none
 *   funcdb v3: 0 call(s), 1 ref(s); disasm: 1 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t pp_timer_process(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pp_timer_process; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a8 = (uint32_t)&bss_s_timer_post; /* 0007: l32r a8, 0 <pp_timer_process-0x4> (0 <pp_timer_process-0x4>) */ /* literal @0x0: .bss.s_timer_post */
  a12 = a3; /* 000a: mov.n a12, a3 */
  a11 = (a2 >> 0) & 0xFF; /* 000c: extui a11, a2, 0, 8 */
  a10 = 0xFFFFFFFF; /* 000f: movi.n a10, -1 */
  a8 = MEM32(a8 + 0); /* 0011: l32i.n a8, a8, 0 */
  if (a8 == 0) goto L_1a; /* 0013: beqz.n a8, 1a <pp_timer_process+0x16> */
  a10 = 0x8; /* 0015: movi.n a10, 8 */
  bss_s_timer_post(a2, a3, a4, a5); /* call via literal slot */ /* 0017: callx8 a8 */
L_1a:;
  a2 = 0x8; /* 001a: mov.n a2, a10 */
  return (int32_t)a2; /* 001c: retw.n  */
}

/* pp_timer_resample @ pp_timer.o 00000000 size 30B bind LOCAL
 * Calls: none | Data refs: none
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: medium - 9 instr, 1 branches, calls resolved */
static int32_t pp_timer_resample(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pp_timer_resample; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
  /* 0000: .word 0x00000000 (literal pool) */
  /* 0004: entry a1, 32 */
  a8 = 0x0; /* 0007: l32r a8, 0 <.text.pp_timer_resample> (0 <.text.pp_timer_resample>) */ @0x0
  a8 = MEM32(a8 + 0); /* 000a: l32i.n a8, a8, 0 */
  a8 = MEM32(a8 + 24); /* 000c: l32i.n a8, a8, 24 */
  if (a8 == 0) goto L_15; /* 000e: beqz.n a8, 15 <.text.pp_timer_resample+0x15> */
  a10 = MEM32(a2 + 4); /* 0010: l32i.n a10, a2, 4 */
  ((int32_t(*)())a8)(a2, a3, a4, a5); /* 0012: callx8 a8 */ /* indirect */
L_15:;
  a2 = 0x1; /* 0015: movi.n a2, 1 */
  return (int32_t)a2; /* 0017: retw.n  */
}

/* pp_timer_coex_restart @ pp_timer.o 00000000 size 21B bind LOCAL
 * Calls: pm_coex_restart_timeout_process[got] | Data refs: pm_coex_restart_timeout_process
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 1 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
static int32_t pp_timer_coex_restart(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pp_timer_coex_restart; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
  /* 0000: .word 0x00000000 (literal pool) */
  /* 0004: entry a1, 32 */
  a10 = MEM32(a2 + 4); /* 0007: l32i.n a10, a2, 4 */
  a2 = 0x1; /* 0009: movi.n a2, 1 */
  a8 = (uint32_t)&pm_coex_restart_timeout_process; /* 000b: l32r a8, 0 <.text.pp_timer_coex_restart> (0 <.text.pp_timer_coex_restart>) */ /* literal: GOT slot for pm_coex_restart_timeout_process */
  pm_coex_restart_timeout_process(a2, a3, a4, a5); /* call via literal slot */ /* 000e: callx8 a8 */
  return (int32_t)a2; /* 0011: retw.n  */
}

/* pp_timer_keep_alive @ pp_timer.o 00000000 size 21B bind LOCAL
 * Calls: pm_keep_alive_timeout_process[got] | Data refs: pm_keep_alive_timeout_process
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 1 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
static int32_t pp_timer_keep_alive(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pp_timer_keep_alive; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
  /* 0000: .word 0x00000000 (literal pool) */
  /* 0004: entry a1, 32 */
  a10 = MEM32(a2 + 4); /* 0007: l32i.n a10, a2, 4 */
  a2 = 0x1; /* 0009: movi.n a2, 1 */
  a8 = (uint32_t)&pm_keep_alive_timeout_process; /* 000b: l32r a8, 0 <.text.pp_timer_keep_alive> (0 <.text.pp_timer_keep_alive>) */ /* literal: GOT slot for pm_keep_alive_timeout_process */
  pm_keep_alive_timeout_process(a2, a3, a4, a5); /* call via literal slot */ /* 000e: callx8 a8 */
  return (int32_t)a2; /* 0011: retw.n  */
}

/* pp_timer_beacon_monitor_tbtt @ pp_timer.o 00000000 size 21B bind LOCAL
 * Calls: pm_beacon_monitor_tbtt_timeout_process[got] | Data refs: pm_beacon_monitor_tbtt_timeout_process
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 1 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
static int32_t pp_timer_beacon_monitor_tbtt(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pp_timer_beacon_monitor_tbtt; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
  /* 0000: .word 0x00000000 (literal pool) */
  /* 0004: entry a1, 32 */
  a10 = MEM32(a2 + 4); /* 0007: l32i.n a10, a2, 4 */
  a2 = 0x1; /* 0009: movi.n a2, 1 */
  a8 = (uint32_t)&pm_beacon_monitor_tbtt_timeout_process; /* 000b: l32r a8, 0 <.text.pp_timer_beacon_monitor_tbtt> (0 <.text.pp_timer_beacon_monitor_tbtt>) */ /* literal: GOT slot for pm_beacon_monitor_tbtt_timeout_process */
  pm_beacon_monitor_tbtt_timeout_process(a2, a3, a4, a5); /* call via literal slot */ /* 000e: callx8 a8 */
  return (int32_t)a2; /* 0011: retw.n  */
}

/* pp_timer_beacon_monitor @ pp_timer.o 00000000 size 21B bind LOCAL
 * Calls: pm_beacon_monitor_timeout_process[got] | Data refs: pm_beacon_monitor_timeout_process
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 1 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
static int32_t pp_timer_beacon_monitor(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pp_timer_beacon_monitor; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
  /* 0000: .word 0x00000000 (literal pool) */
  /* 0004: entry a1, 32 */
  a10 = MEM32(a2 + 4); /* 0007: l32i.n a10, a2, 4 */
  a2 = 0x1; /* 0009: movi.n a2, 1 */
  a8 = (uint32_t)&pm_beacon_monitor_timeout_process; /* 000b: l32r a8, 0 <.text.pp_timer_beacon_monitor> (0 <.text.pp_timer_beacon_monitor>) */ /* literal: GOT slot for pm_beacon_monitor_timeout_process */
  pm_beacon_monitor_timeout_process(a2, a3, a4, a5); /* call via literal slot */ /* 000e: callx8 a8 */
  return (int32_t)a2; /* 0011: retw.n  */
}

/* pp_timer_connectionless_wake_window @ pp_timer.o 00000000 size 21B bind LOCAL
 * Calls: pm_connectionless_wake_window_timeout_process[got] | Data refs: pm_connectionless_wake_window_timeout_process
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 1 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
static int32_t pp_timer_connectionless_wake_window(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pp_timer_connectionless_wake_window; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
  /* 0000: .word 0x00000000 (literal pool) */
  /* 0004: entry a1, 32 */
  a10 = MEM32(a2 + 4); /* 0007: l32i.n a10, a2, 4 */
  a2 = 0x1; /* 0009: movi.n a2, 1 */
  a8 = (uint32_t)&pm_connectionless_wake_window_timeout_process; /* 000b: l32r a8, 0 <.text.pp_timer_connectionless_wake_window> (0 <.text.pp_timer_connectionless_wake_window>) */ /* literal: GOT slot for pm_connectionless_wake_window_timeout_process */
  pm_connectionless_wake_window_timeout_process(a2, a3, a4, a5); /* call via literal slot */ /* 000e: callx8 a8 */
  return (int32_t)a2; /* 0011: retw.n  */
}

/* pp_timer_connectionless_wake_interval @ pp_timer.o 00000000 size 21B bind LOCAL
 * Calls: pm_connectionless_wake_interval_timeout_process[got] | Data refs: pm_connectionless_wake_interval_timeout_process
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 1 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
static int32_t pp_timer_connectionless_wake_interval(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pp_timer_connectionless_wake_interval; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
  /* 0000: .word 0x00000000 (literal pool) */
  /* 0004: entry a1, 32 */
  a10 = MEM32(a2 + 4); /* 0007: l32i.n a10, a2, 4 */
  a2 = 0x1; /* 0009: movi.n a2, 1 */
  a8 = (uint32_t)&pm_connectionless_wake_interval_timeout_process; /* 000b: l32r a8, 0 <.text.pp_timer_connectionless_wake_interval> (0 <.text.pp_timer_connectionless_wake_interval>) */ /* literal: GOT slot for pm_connectionless_wake_interval_timeout_process */
  pm_connectionless_wake_interval_timeout_process(a2, a3, a4, a5); /* call via literal slot */ /* 000e: callx8 a8 */
  return (int32_t)a2; /* 0011: retw.n  */
}

/* pp_timer_disconnected_sleep_delay @ pp_timer.o 00000000 size 21B bind LOCAL
 * Calls: pm_disconnected_sleep_delay_timeout_process[got] | Data refs: pm_disconnected_sleep_delay_timeout_process
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 1 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
static int32_t pp_timer_disconnected_sleep_delay(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pp_timer_disconnected_sleep_delay; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
  /* 0000: .word 0x00000000 (literal pool) */
  /* 0004: entry a1, 32 */
  a10 = MEM32(a2 + 4); /* 0007: l32i.n a10, a2, 4 */
  a2 = 0x1; /* 0009: movi.n a2, 1 */
  a8 = (uint32_t)&pm_disconnected_sleep_delay_timeout_process; /* 000b: l32r a8, 0 <.text.pp_timer_disconnected_sleep_delay> (0 <.text.pp_timer_disconnected_sleep_delay>) */ /* literal: GOT slot for pm_disconnected_sleep_delay_timeout_process */
  pm_disconnected_sleep_delay_timeout_process(a2, a3, a4, a5); /* call via literal slot */ /* 000e: callx8 a8 */
  return (int32_t)a2; /* 0011: retw.n  */
}

/* pp_timer_sleep_delay @ pp_timer.o 00000000 size 21B bind LOCAL
 * Calls: pm_sleep_delay_timeout_process[got] | Data refs: pm_sleep_delay_timeout_process
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 1 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
static int32_t pp_timer_sleep_delay(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pp_timer_sleep_delay; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
  /* 0000: .word 0x00000000 (literal pool) */
  /* 0004: entry a1, 32 */
  a10 = MEM32(a2 + 4); /* 0007: l32i.n a10, a2, 4 */
  a2 = 0x1; /* 0009: movi.n a2, 1 */
  a8 = (uint32_t)&pm_sleep_delay_timeout_process; /* 000b: l32r a8, 0 <.text.pp_timer_sleep_delay> (0 <.text.pp_timer_sleep_delay>) */ /* literal: GOT slot for pm_sleep_delay_timeout_process */
  pm_sleep_delay_timeout_process(a2, a3, a4, a5); /* call via literal slot */ /* 000e: callx8 a8 */
  return (int32_t)a2; /* 0011: retw.n  */
}

/* pp_timer_coex_slice @ pp_timer.o 00000000 size 21B bind LOCAL
 * Calls: pm_coex_slice_timeout_process[got] | Data refs: pm_coex_slice_timeout_process
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 1 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
static int32_t pp_timer_coex_slice(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pp_timer_coex_slice; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
  /* 0000: .word 0x00000000 (literal pool) */
  /* 0004: entry a1, 32 */
  a10 = MEM32(a2 + 4); /* 0007: l32i.n a10, a2, 4 */
  a2 = 0x1; /* 0009: movi.n a2, 1 */
  a8 = (uint32_t)&pm_coex_slice_timeout_process; /* 000b: l32r a8, 0 <.text.pp_timer_coex_slice> (0 <.text.pp_timer_coex_slice>) */ /* literal: GOT slot for pm_coex_slice_timeout_process */
  pm_coex_slice_timeout_process(a2, a3, a4, a5); /* call via literal slot */ /* 000e: callx8 a8 */
  return (int32_t)a2; /* 0011: retw.n  */
}

/* pp_timer_active @ pp_timer.o 00000000 size 21B bind LOCAL
 * Calls: pm_active_timeout_process[got] | Data refs: pm_active_timeout_process
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 1 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
static int32_t pp_timer_active(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pp_timer_active; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
  /* 0000: .word 0x00000000 (literal pool) */
  /* 0004: entry a1, 32 */
  a10 = MEM32(a2 + 4); /* 0007: l32i.n a10, a2, 4 */
  a2 = 0x1; /* 0009: movi.n a2, 1 */
  a8 = (uint32_t)&pm_active_timeout_process; /* 000b: l32r a8, 0 <.text.pp_timer_active> (0 <.text.pp_timer_active>) */ /* literal: GOT slot for pm_active_timeout_process */
  pm_active_timeout_process(a2, a3, a4, a5); /* call via literal slot */ /* 000e: callx8 a8 */
  return (int32_t)a2; /* 0011: retw.n  */
}

/* pp_timer_dream @ pp_timer.o 00000000 size 21B bind LOCAL
 * Calls: pm_dream_timeout_process[got] | Data refs: pm_dream_timeout_process
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 1 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
static int32_t pp_timer_dream(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pp_timer_dream; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
  /* 0000: .word 0x00000000 (literal pool) */
  /* 0004: entry a1, 32 */
  a10 = MEM32(a2 + 4); /* 0007: l32i.n a10, a2, 4 */
  a2 = 0x1; /* 0009: movi.n a2, 1 */
  a8 = (uint32_t)&pm_dream_timeout_process; /* 000b: l32r a8, 0 <.text.pp_timer_dream> (0 <.text.pp_timer_dream>) */ /* literal: GOT slot for pm_dream_timeout_process */
  pm_dream_timeout_process(a2, a3, a4, a5); /* call via literal slot */ /* 000e: callx8 a8 */
  return (int32_t)a2; /* 0011: retw.n  */
}

/* pp_timer_tbtt @ pp_timer.o 00000000 size 21B bind LOCAL
 * Calls: pm_tbtt_process[got] | Data refs: pm_tbtt_process
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 1 call(s), 1 data ref(s)
 *   NOTE: C name `pp_timer_tbtt` inferred from .wifislpiram.2 (no symtab symbol; see object header)
 * Fidelity: high - straight-line / few branches, all refs resolved */
static int32_t pp_timer_tbtt(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .wifislpiram.2; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
  /* 0000: .word 0x00000000 (literal pool) */
  /* 0004: entry a1, 32 */
  a10 = MEM32(a2 + 4); /* 0007: l32i.n a10, a2, 4 */
  a2 = 0x1; /* 0009: movi.n a2, 1 */
  a8 = (uint32_t)&pm_tbtt_process; /* 000b: l32r a8, 0 <.wifislpiram.2> (0 <.wifislpiram.2>) */ /* literal: GOT slot for pm_tbtt_process */
  pm_tbtt_process(a2, a3, a4, a5); /* call via literal slot */ /* 000e: callx8 a8 */
  return (int32_t)a2; /* 0011: retw.n  */
}

/* pp_timer_noise_check @ pp_timer.o 00000000 size 21B bind LOCAL
 * Calls: pm_noise_check_process[got] | Data refs: pm_noise_check_process
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 1 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
static int32_t pp_timer_noise_check(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pp_timer_noise_check; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
  /* 0000: .word 0x00000000 (literal pool) */
  /* 0004: entry a1, 32 */
  a10 = MEM32(a2 + 4); /* 0007: l32i.n a10, a2, 4 */
  a2 = 0x1; /* 0009: movi.n a2, 1 */
  a8 = (uint32_t)&pm_noise_check_process; /* 000b: l32r a8, 0 <.text.pp_timer_noise_check> (0 <.text.pp_timer_noise_check>) */ /* literal: GOT slot for pm_noise_check_process */
  pm_noise_check_process(a2, a3, a4, a5); /* call via literal slot */ /* 000e: callx8 a8 */
  return (int32_t)a2; /* 0011: retw.n  */
}

