/* libmesh.a mesh_sleep.o --- reconstructed C (offline).
 * Role: power-save: sleep/wake, beacon/TBTT processing, null-data handling.
 * Object file: 10552 bytes on disk; 9/9 functions reconstructed, ~1099 code bytes.
 * Method: xtensa-esp32-elf-objdump -d/-s + readelf -rW/-sW + funcdb_libmesh.json v3
 * (calls/refs edges). Control flow preserved 1:1 via labels+gotos; regs a0-a15
 * are u32 locals; window rotation flattened. Direct calls come from
 * R_XTENSA_ASM_EXPAND relocs (ground truth); leftover indirect sites are
 * attributed in order from funcdb-v3 calls and marked funcdb-attributed;
 * literal-pool-only inferences contradicting funcdb-v3 were demoted (see
 * corrections). No logic invented; see Fidelity tags. */
#include <stdint.h>
#include <stddef.h>
typedef uint8_t u8; typedef uint16_t u16; typedef uint32_t u32;
typedef int8_t i8; typedef int16_t i16; typedef int32_t i32;
#define LD32(p) (*(volatile u32*)(uintptr_t)(p))
#define LD16U(p) (*(volatile u16*)(uintptr_t)(p))
#define LD16S(p) (*(volatile i16*)(uintptr_t)(p))
#define LD8U(p) (*(volatile u8*)(uintptr_t)(p))
#define ST32(p,v) (*(volatile u32*)(uintptr_t)(p) = (u32)(v))
#define ST16(p,v) (*(volatile u16*)(uintptr_t)(p) = (u16)(v))
#define ST8(p,v) (*(volatile u8*)(uintptr_t)(p) = (u8)(v))
#define LD32F(p) u2f(LD32(p))
#define ST32F(p,v) ST32((p), f2u(v))
#define SRC_FUNNEL(x,y) (0u) /* SAR-dependent funnel shift; value untracked */
static float u2f(u32 v){ float f; __builtin_memcpy(&f,&v,4); return f; }
static u32 f2u(float f){ u32 v; __builtin_memcpy(&v,&f,4); return v; }
extern u32 g_mesh_dfs_compensation_ms; /* undefined data (reloc-referenced) */
extern u32 g_mesh_is_root; /* undefined data (reloc-referenced) */
extern u32 g_osi_funcs_p; /* undefined data (reloc-referenced) */
extern u32 mesh_ps_keep_cnx; /* undefined data (reloc-referenced) */
extern u32 __divdi3(); /* undefined func (args unknown, returns u32) */
extern u32 esp_mesh_get_running_active_duty_cycle(); /* undefined func (args unknown, returns u32) */
extern u32 esp_mesh_sync_interface_tsf(); /* defined in another libmesh.a object */
extern u32 hal_get_tsf_time(); /* undefined func (args unknown, returns u32) */
extern u32 ieee80211_hostap_send_beacon_process(); /* undefined func (args unknown, returns u32) */
extern u32 pm_check_state(); /* undefined func (args unknown, returns u32) */
extern u32 pm_go_to_sleep(); /* undefined func (args unknown, returns u32) */
extern u32 pm_go_to_wake(); /* undefined func (args unknown, returns u32) */
extern u32 pm_is_dream(); /* undefined func (args unknown, returns u32) */
extern u32 pm_is_open(); /* undefined func (args unknown, returns u32) */
extern u32 pm_is_sleeping(); /* undefined func (args unknown, returns u32) */
extern u32 pm_is_waked(); /* undefined func (args unknown, returns u32) */
extern u32 pm_send_nullfunc(); /* undefined func (args unknown, returns u32) */
extern u32 pm_stop(); /* undefined func (args unknown, returns u32) */
extern u32 pm_tx_null_data_done_process(); /* undefined func (args unknown, returns u32) */
extern u32 ppCheckTxQIdle(); /* undefined func (args unknown, returns u32) */
extern u32 wifi_log(); /* undefined func (args unknown, returns u32) */
static const u8 RODATA__rodata_wlog_info_2[] = { 0x28, 0x74, 0x62, 0x74, 0x74, 0x29, 0x6e, 0x65, 0x77, 0x20, 0x64, 0x75, 0x74, 0x79, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x74, 0x73, 0x66, 0x20, 0x6f, 0x66, 0x66, 0x73, 0x65, 0x74, 0x3a, 0x25, 0x6c, 0x6c, 0x64, 0x75, 0x73 }; /* .rodata_wlog_info.2 (36 bytes) */
static const u8 RODATA__rodata_wlog_info_4[] = { 0x28, 0x72, 0x78, 0x20, 0x62, 0x65, 0x61, 0x63, 0x6f, 0x6e, 0x29, 0x6e, 0x65, 0x77, 0x20, 0x64, 0x75, 0x74, 0x79, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x74, 0x73, 0x66, 0x20, 0x6f, 0x66, 0x66, 0x73, 0x65, 0x74, 0x3a, 0x25, 0x6c, 0x6c, 0x64, 0x75, 0x73, 0x28, 0x25, 0x64 }; /* .rodata_wlog_info.4 (44 bytes) */
static const u8 RODATA__rodata_wlog_warning_3[] = { 0x28, 0x2d, 0x3e, 0x73, 0x6c, 0x65, 0x65, 0x70, 0x29, 0x62, 0x75, 0x73, 0x79, 0x2c, 0x20, 0x77, 0x61, 0x6b, 0x65, 0x64, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x64, 0x72, 0x65, 0x61, 0x6d, 0x3a, 0x25, 0x64, 0x2c, 0x20, 0x73, 0x6c, 0x65, 0x65, 0x70, 0x3a, 0x25, 0x64, 0x00 }; /* .rodata_wlog_warning.3 (44 bytes) strings: [0x0]="(->sleep)busy, waked:%d, dream:%d, sleep:%d" */
static u8 LOCAL__bss_rx_bcn_count_0[0x4]; /* stand-in for .bss.rx_bcn_count$0 (same-object static; real size/type unknown; sized to cover observed +0x0 refs) */
static u8 LOCAL__bss_s_mesh_is_awake_duty[0x4]; /* stand-in for .bss.s_mesh_is_awake_duty (same-object static; real size/type unknown; sized to cover observed +0x0 refs) */
static u8 LOCAL__bss_s_mesh_next_awake_tbtt[0x4]; /* stand-in for .bss.s_mesh_next_awake_tbtt (same-object static; real size/type unknown; sized to cover observed +0x0 refs) */
static u8 LOCAL__bss_send_null_cnt_1[0x4]; /* stand-in for .bss.send_null_cnt$1 (same-object static; real size/type unknown; sized to cover observed +0x0 refs) */
static u8 LOCAL__data_s_mesh_active_duty_cycle[0x4]; /* stand-in for .data.s_mesh_active_duty_cycle (same-object static; real size/type unknown; sized to cover observed +0x0 refs) */

/* esp_mesh_is_start_pm_now @ mesh_sleep.o 00000010 size 71B bind GLOBAL
 * Calls: pm_is_open, esp_mesh_get_running_active_duty_cycle | Data refs: g_mesh_is_root, .bss.rx_bcn_count$0
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=2, refs=4); reloc-direct=2, funcdb-attributed=0, unknown-indirect=0 */
u32 esp_mesh_is_start_pm_now(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a8, a9;
  /* 0010: entry a1, 32 (frame 32 bytes) */
  a2 = (u32)&g_mesh_is_root + 0x0;  /* 0013: l32r -> global */
  __asm__ volatile("" ::: "memory");  /* 0016: memw */
  a2 = LD8U(a2 + 0x0);  /* 0019 */
  a2 = (a2 >> 8) & 0x1;  /* 001c: extui width 1 */
  if (a2 == 0) goto L_0024;  /* 001f: beqz.n a2, 24 <esp_mesh_is_start_pm_now+0x14> */
  L_0021: goto L_0050;  /* 0021: j */
  L_0024: a8 = (u32)&pm_is_open + 0x0;  /* 0024: l32r -> global */
  a2 = pm_is_open(a2, a3, a4, a5, a6, a7);  /* 0027: callx a8 via reloc-expand */
  a2 = a10;  /* 002a */
  if (a10 != 0) goto L_0050;  /* 002c: bnez.n a10, 50 <esp_mesh_is_start_pm_now+0x40> */
  L_002e: a8 = (u32)&esp_mesh_get_running_active_duty_cycle + 0x0;  /* 002e: l32r -> global */
  a2 = esp_mesh_get_running_active_duty_cycle(a2, a3, a4, a5, a6, a7);  /* 0031: callx a8 via reloc-expand */
  a8 = 100;  /* 0034 */
  if (a10 == a8) goto L_0052;  /* 0037: beq a10, a8, 52 <esp_mesh_is_start_pm_now+0x42> */
  L_003a: a9 = (u32)&LOCAL__bss_rx_bcn_count_0 + 0x0;  /* 003a: l32r -> .bss.rx_bcn_count$0 (same-object static) */
  a10 = 24;  /* 003d */
  a8 = LD32(a9 + 0x0);  /* 003f */
  a8 = a8 + (1);  /* 0041 */
  if ((i32)a10 < (i32)a8) goto L_004e;  /* 0043: blt a10, a8, 4e <esp_mesh_is_start_pm_now+0x3e> */
  L_0046: ST32(a9 + 0x0, a8);  /* 0046 */
  __asm__ volatile("" ::: "memory");  /* 0048: memw */
  goto L_0052;  /* 004b: j */
  L_004e: ST32(a9 + 0x0, a2);  /* 004e */
  L_0050: a2 = 1;  /* 0050 */
  L_0052: __asm__ volatile("" ::: "memory");  /* 0052: memw */
  return a2;  /* 0055: retw.n */
}


/* esp_mesh_pm_go_to_sleep @ mesh_sleep.o 00000004 size 56B bind GLOBAL
 * Calls: pm_tx_null_data_done_process | Data refs: none
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=1, refs=1); reloc-direct=1, funcdb-attributed=0, unknown-indirect=0 */
u32 esp_mesh_pm_go_to_sleep(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a8;
  /* 0004: entry a1, 32 (frame 32 bytes) */
  a2 = (a2 >> 8) & 0x1;  /* 0007: extui width 1 */
  a8 = 1;  /* 000a */
  if (a2 == 0) goto L_0020;  /* 000c: beqz.n a2, 20 <esp_mesh_pm_go_to_sleep+0x1c> */
  L_000e: ST8(a3 + 0x0, a8);  /* 000e */
  a2 = 0;  /* 0011 */
  ST8(a4 + 0x0, a2);  /* 0013 */
  __asm__ volatile("" ::: "memory");  /* 0016: memw */
  __asm__ volatile("" ::: "memory");  /* 0019: memw */
  goto L_0029;  /* 001c: j */
  L_0020: ST8(a4 + 0x0, a8);  /* 0020 */
  ST8(a3 + 0x0, a2);  /* 0023 */
  __asm__ volatile("" ::: "memory");  /* 0026: memw */
  L_0029: a12 = 0;  /* 0029 */
  a11 = a12;  /* 002b */
  a10 = 1;  /* 002d */
  __asm__ volatile("" ::: "memory");  /* 002f: memw */
  a8 = (u32)&pm_tx_null_data_done_process + 0x0;  /* 0032: l32r -> global */
  a2 = pm_tx_null_data_done_process(a2, a3, a4, a5, a6, a7);  /* 0035: callx a8 via reloc-expand */
  a2 = 0;  /* 0038 */
  return a2;  /* 003a: retw.n */
}


/* esp_mesh_pm_go_to_wake @ mesh_sleep.o 00000004 size 56B bind GLOBAL
 * Calls: pm_tx_null_data_done_process | Data refs: none
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=1, refs=1); reloc-direct=1, funcdb-attributed=0, unknown-indirect=0 */
u32 esp_mesh_pm_go_to_wake(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a8;
  /* 0004: entry a1, 32 (frame 32 bytes) */
  a2 = (a2 >> 8) & 0x1;  /* 0007: extui width 1 */
  a8 = 1;  /* 000a */
  if (a2 == 0) goto L_0020;  /* 000c: beqz.n a2, 20 <esp_mesh_pm_go_to_wake+0x1c> */
  L_000e: ST8(a3 + 0x0, a8);  /* 000e */
  a2 = 0;  /* 0011 */
  ST8(a4 + 0x0, a2);  /* 0013 */
  __asm__ volatile("" ::: "memory");  /* 0016: memw */
  __asm__ volatile("" ::: "memory");  /* 0019: memw */
  goto L_0029;  /* 001c: j */
  L_0020: ST8(a4 + 0x0, a8);  /* 0020 */
  ST8(a3 + 0x0, a2);  /* 0023 */
  __asm__ volatile("" ::: "memory");  /* 0026: memw */
  L_0029: a12 = 0;  /* 0029 */
  a11 = a12;  /* 002b */
  a10 = a12;  /* 002d */
  __asm__ volatile("" ::: "memory");  /* 002f: memw */
  a8 = (u32)&pm_tx_null_data_done_process + 0x0;  /* 0032: l32r -> global */
  a2 = pm_tx_null_data_done_process(a2, a3, a4, a5, a6, a7);  /* 0035: callx a8 via reloc-expand */
  a2 = 0;  /* 0038 */
  return a2;  /* 003a: retw.n */
}


/* esp_mesh_pm_rx_beacon_process @ mesh_sleep.o 00000044 size 288B bind GLOBAL
 * Calls: esp_mesh_get_running_active_duty_cycle, hal_get_tsf_time, wifi_log, mesh_pm_tbtt_start, __divdi3, pm_is_open, pm_send_nullfunc | indirect[2]: mem[a3+0x110] | Data refs: .data.s_mesh_active_duty_cycle, .rodata_wlog_info.4, g_mesh_dfs_compensation_ms, .bss.s_mesh_next_awake_tbtt, .bss.s_mesh_is_awake_duty, mesh_ps_keep_cnx, g_osi_funcs_p
 * Fidelity: medium - 2 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=7, refs=14); reloc-direct=7, funcdb-attributed=0, unknown-indirect=2 */
u32 esp_mesh_pm_rx_beacon_process(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a8, a9;
  /* 0044: entry a1, 64 (frame 64 bytes) */
  a8 = (u32)&esp_mesh_get_running_active_duty_cycle + 0x0;  /* 0047: l32r -> global */
  a2 = esp_mesh_get_running_active_duty_cycle(a2, a3, a4, a5, a6, a7);  /* 004a: callx a8 via reloc-expand */
  a6 = (u32)&LOCAL__data_s_mesh_active_duty_cycle + 0x0;  /* 004d: l32r -> .data.s_mesh_active_duty_cycle (same-object static) */
  a7 = a10;  /* 0050 */
  a3 = LD32(a6 + 0x0);  /* 0052 */
  if (a3 == a10) goto L_00a6;  /* 0054: beq a3, a10, a6 <esp_mesh_pm_rx_beacon_process+0x62> */
  L_0057: ST32(a6 + 0x0, a10);  /* 0057 */
  a10 = 0;  /* 0059 */
  __asm__ volatile("" ::: "memory");  /* 005b: memw */
  a8 = (u32)&hal_get_tsf_time + 0x0;  /* 005e: l32r -> global */
  a2 = hal_get_tsf_time(a2, a3, a4, a5, a6, a7);  /* 0061: callx a8 via reloc-expand */
  a9 = a10;  /* 0064 */
  a10 = 1;  /* 0066 */
  ST32(a1 + 0x10, a9);  /* 0068 */
  a3 = a11;  /* 006a */
  __asm__ volatile("" ::: "memory");  /* 006c: memw */
  a8 = (u32)&hal_get_tsf_time + 0x0;  /* 006f: l32r -> global */
  a2 = hal_get_tsf_time(a2, a3, a4, a5, a6, a7);  /* 0072: callx a8 via reloc-expand */
  a8 = 1;  /* 0075 */
  a8 = a8 << 12;  /* 0077 */
  a9 = LD32(a1 + 0x10);  /* 007a */
  a10 = a9 - a10;  /* 007c: sub */
  ST32(a1 + 0x8, a4);  /* 007f */
  a4 = 1;  /* 0081 */
  if (a9 < a10) goto L_0088;  /* 0083: bltu a9, a10, 88 <esp_mesh_pm_rx_beacon_process+0x44> */
  L_0086: a4 = 0;  /* 0086 */
  L_0088: a3 = a3 - a11;  /* 0088: sub */
  a3 = a3 - a4;  /* 008b: sub */
  a13 = (u32)(RODATA__rodata_wlog_info_4 + 0x0);  /* 008e: l32r -> .rodata_wlog_info.4 */
  a14 = a7;  /* 0091 */
  a12 = 3;  /* 0093 */
  a11 = a8;  /* 0095 */
  ST32(a1 + 0x0, a10);  /* 0097 */
  a10 = 6;  /* 0099 */
  ST32(a1 + 0x4, a3);  /* 009b */
  __asm__ volatile("" ::: "memory");  /* 009d: memw */
  a8 = (u32)&wifi_log + 0x0;  /* 00a0: l32r -> global */
  a2 = wifi_log(a2, a3, a4, a5, a6, a7);  /* 00a3: callx a8 via reloc-expand */
  L_00a6: a4 = 0;  /* 00a6 */
  a10 = a2;  /* 00a8 */
  a8 = LD32(a6 + 0x0);  /* 00aa */
  a8 = a2 * a8;  /* 00ac */
  a9 = 0x51eb851fu;  /* 00af: l32r = 1374389535 */
  a9 = (u32)(((u64)a8 * a9) >> 32);  /* 00b2: mulsh */
  a8 = (i32)a8 >> 31;  /* 00b5 */
  a9 = (i32)a9 >> 5;  /* 00b8 */
  a3 = (u32)&g_mesh_dfs_compensation_ms + 0x0;  /* 00bb: l32r -> global */
  a9 = a9 - a8;  /* 00be: sub */
  a3 = LD32(a3 + 0x0);  /* 00c1 */
  a8 = a3 << 5;  /* 00c3 */
  a8 = a8 - a3;  /* 00c6: sub */
  a8 = a8 + (a3 << 2);  /* 00c9 */
  a3 = a2 - a9;  /* 00cc: sub */
  a8 = a8 + (a3 << 3);  /* 00cf */
  a3 = (u32)&LOCAL__bss_s_mesh_next_awake_tbtt + 0x0;  /* 00d2: l32r -> .bss.s_mesh_next_awake_tbtt (same-object static) */
  a8 = ((i32)a8 > (i32)a4) ? a8 : a4;  /* 00d5: max */
  ST32(a3 + 0x0, a8);  /* 00d8 */
  a3 = (u32)&LOCAL__bss_s_mesh_is_awake_duty + 0x0;  /* 00da: l32r -> .bss.s_mesh_is_awake_duty (same-object static) */
  ST32(a5 + 0x0, a9);  /* 00dd */
  a5 = 1;  /* 00df */
  ST8(a3 + 0x0, a5);  /* 00e1 */
  __asm__ volatile("" ::: "memory");  /* 00e4: memw */
  __asm__ volatile("" ::: "memory");  /* 00e7: memw */
  a8 = (u32)&mesh_pm_tbtt_start;  /* 00ea: l32r -> func addr */
  a2 = mesh_pm_tbtt_start(a2, a3, a4, a5, a6, a7);  /* 00ed: callx a8 via reloc-expand */
  a2 = (u32)&mesh_ps_keep_cnx + 0x0;  /* 00f0: l32r -> global */
  a5 = LD32(a2 + 0x4);  /* 00f3 */
  a3 = LD32(a2 + 0x0);  /* 00f5 */
  a3 = a3 | a5;  /* 00f7 */
  a5 = a4;  /* 00fa */
  if (a3 == a4) goto L_0130;  /* 00fc: beq a3, a4, 130 <esp_mesh_pm_rx_beacon_process+0xec> */
  L_00ff: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 00ff: l32r -> global */
  a5 = 1;  /* 0102 */
  a3 = LD32(a3 + 0x0);  /* 0104 */
  a10 = LD32(a3 + 0x110);  /* 0107 */
  /* 010a: INDIRECT callx a10 <- mem[a3+0x110]; result unknown */ a2 = 0;
  a3 = LD32(a2 + 0x0);  /* 010d */
  a3 = a10 - a3;  /* 010f: sub */
  a6 = LD32(a2 + 0x4);  /* 0112 */
  if (a10 < a3) goto L_0119;  /* 0114: bltu a10, a3, 119 <esp_mesh_pm_rx_beacon_process+0xd5> */
  L_0117: a5 = a4;  /* 0117 */
  L_0119: a11 = a11 - a6;  /* 0119: sub */
  a11 = a11 - a5;  /* 011c: sub */
  a12 = 0x3e8;  /* 011f */
  a13 = 0;  /* 0122 */
  a10 = a3;  /* 0125: mov */
  a8 = (u32)&__divdi3 + 0x0;  /* 0128: l32r -> global */
  a2 = __divdi3(a2, a3, a4, a5, a6, a7);  /* 012b: callx a8 via reloc-expand */
  a5 = a10;  /* 012e */
  L_0130: a8 = (u32)&pm_is_open + 0x0;  /* 0130: l32r -> global */
  a2 = pm_is_open(a2, a3, a4, a5, a6, a7);  /* 0133: callx a8 via reloc-expand */
  a3 = a10;  /* 0136 */
  a11 = a10;  /* 0138 */
  if (a10 == 0) goto L_014a;  /* 013a: beqz a10, 14a <esp_mesh_pm_rx_beacon_process+0x106> */
  L_013d: a3 = (u32)&g_osi_funcs_p + 0x0;  /* 013d: l32r -> global */
  a3 = LD32(a3 + 0x0);  /* 0140 */
  a10 = LD32(a3 + 0x110);  /* 0142 */
  /* 0145: INDIRECT callx a10 <- mem[a3+0x110]; result unknown */ a2 = 0;
  a3 = a10;  /* 0148 */
  L_014a: ST32(a2 + 0x0, a3);  /* 014a */
  ST32(a2 + 0x4, a11);  /* 014c */
  a2 = 0x00002edfu;  /* 014e: l32r = 11999 */
  if ((i32)a2 >= (i32)a5) goto L_0160;  /* 0151: bge a2, a5, 160 <esp_mesh_pm_rx_beacon_process+0x11c> */
  L_0154: a10 = 0;  /* 0154 */
  __asm__ volatile("" ::: "memory");  /* 0157: memw */
  a8 = (u32)&pm_send_nullfunc + 0x0;  /* 015a: l32r -> global */
  a2 = pm_send_nullfunc(a2, a3, a4, a5, a6, a7);  /* 015d: callx a8 via reloc-expand */
  L_0160: a2 = 0;  /* 0160 */
  return a2;  /* 0162: retw.n */
}


/* esp_mesh_pm_tbtt_timeout_process @ mesh_sleep.o 0000005c size 388B bind GLOBAL
 * Calls: ppCheckTxQIdle, esp_mesh_get_running_active_duty_cycle, hal_get_tsf_time, wifi_log, __divdi3, pm_go_to_wake, ieee80211_hostap_send_beacon_process, mesh_pm_tbtt_start, pm_go_to_sleep, pm_is_waked, pm_is_dream, pm_is_sleeping | indirect[2]: mem[a8+0x110]; mem[a2+0x110] | Data refs: .bss.s_mesh_is_awake_duty, .bss.s_mesh_next_awake_tbtt, .data.s_mesh_active_duty_cycle, .rodata_wlog_info.2, mesh_ps_keep_cnx, g_osi_funcs_p, g_mesh_dfs_compensation_ms, .rodata_wlog_warning.3
 * Fidelity: medium - 2 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=12, refs=20); reloc-direct=12, funcdb-attributed=0, unknown-indirect=2 */
u32 esp_mesh_pm_tbtt_timeout_process(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a14, a15, a8, a9;
  float F8;
  /* 005c: entry a1, 64 (frame 64 bytes) */
  a3 = (u32)&LOCAL__bss_s_mesh_is_awake_duty + 0x0;  /* 005f: l32r -> .bss.s_mesh_is_awake_duty (same-object static) */
  a6 = LD8U(a3 + 0x0);  /* 0062 */
  if (a6 == 0) goto L_0088;  /* 0065: beqz.n a6, 88 <esp_mesh_pm_tbtt_timeout_process+0x2c> */
  L_0067: a10 = 1;  /* 0067 */
  a6 = (u32)&LOCAL__bss_s_mesh_next_awake_tbtt + 0x0;  /* 0069: l32r -> .bss.s_mesh_next_awake_tbtt (same-object static) */
  a2 = LD32(a6 + 0x0);  /* 006c */
  ST32(a4 + 0x0, a2);  /* 006e */
  a2 = 0;  /* 0070 */
  ST8(a3 + 0x0, a2);  /* 0072 */
  __asm__ volatile("" ::: "memory");  /* 0075: memw */
  __asm__ volatile("" ::: "memory");  /* 0078: memw */
  a8 = (u32)&ppCheckTxQIdle + 0x0;  /* 007b: l32r -> global */
  a2 = ppCheckTxQIdle(a2, a3, a4, a5, a6, a7);  /* 007e: callx a8 via reloc-expand */
  if (a10 == 0) goto L_01a0;  /* 0081: beqz a10, 1a0 <esp_mesh_pm_tbtt_timeout_process+0x144> */
  L_0084: goto L_01ab;  /* 0084: j */
  L_0088: a8 = (u32)&esp_mesh_get_running_active_duty_cycle + 0x0;  /* 0088: l32r -> global */
  a2 = esp_mesh_get_running_active_duty_cycle(a2, a3, a4, a5, a6, a7);  /* 008b: callx a8 via reloc-expand */
  a7 = (u32)&LOCAL__data_s_mesh_active_duty_cycle + 0x0;  /* 008e: l32r -> .data.s_mesh_active_duty_cycle (same-object static) */
  a3 = a10;  /* 0091 */
  a5 = LD32(a7 + 0x0);  /* 0093 */
  if (a5 == a10) goto L_00e9;  /* 0095: beq a5, a10, e9 <esp_mesh_pm_tbtt_timeout_process+0x8d> */
  L_0098: ST32(a7 + 0x0, a10);  /* 0098 */
  a10 = a6;  /* 009a */
  __asm__ volatile("" ::: "memory");  /* 009c: memw */
  a8 = (u32)&hal_get_tsf_time + 0x0;  /* 009f: l32r -> global */
  a2 = hal_get_tsf_time(a2, a3, a4, a5, a6, a7);  /* 00a2: callx a8 via reloc-expand */
  a13 = a10;  /* 00a5 */
  a10 = 1;  /* 00a7 */
  ST32(a1 + 0x10, a13);  /* 00a9 */
  a5 = a11;  /* 00ab */
  __asm__ volatile("" ::: "memory");  /* 00ad: memw */
  a8 = (u32)&hal_get_tsf_time + 0x0;  /* 00b0: l32r -> global */
  a2 = hal_get_tsf_time(a2, a3, a4, a5, a6, a7);  /* 00b3: callx a8 via reloc-expand */
  a8 = 1;  /* 00b6 */
  a8 = a8 << 12;  /* 00b8 */
  a13 = LD32(a1 + 0x10);  /* 00bb */
  a12 = 1;  /* 00bd */
  a10 = a13 - a10;  /* 00c0: sub */
  if (a13 < a10) goto L_00c8;  /* 00c3: bltu a13, a10, c8 <esp_mesh_pm_tbtt_timeout_process+0x6c> */
  L_00c6: a12 = a6;  /* 00c6 */
  L_00c8: a5 = a5 - a11;  /* 00c8: sub */
  a5 = a5 - a12;  /* 00cb: sub */
  a13 = (u32)(RODATA__rodata_wlog_info_2 + 0x0);  /* 00ce: l32r -> .rodata_wlog_info.2 */
  a14 = a3;  /* 00d1 */
  a12 = 3;  /* 00d3 */
  a11 = a8;  /* 00d5 */
  ST32(a1 + 0x0, a10);  /* 00d7 */
  a10 = 6;  /* 00da */
  ST32(a1 + 0x4, a5);  /* 00dd */
  __asm__ volatile("" ::: "memory");  /* 00e0: memw */
  a8 = (u32)&wifi_log + 0x0;  /* 00e3: l32r -> global */
  a2 = wifi_log(a2, a3, a4, a5, a6, a7);  /* 00e6: callx a8 via reloc-expand */
  L_00e9: a3 = (u32)&mesh_ps_keep_cnx + 0x0;  /* 00e9: l32r -> global */
  a5 = LD32(a3 + 0x4);  /* 00ec */
  a8 = LD32(a3 + 0x0);  /* 00ee */
  a8 = a8 | a5;  /* 00f0 */
  a5 = (u32)&g_osi_funcs_p + 0x0;  /* 00f3: l32r -> global */
  if (a8 != 0) goto L_0110;  /* 00f6: bnez.n a8, 110 <esp_mesh_pm_tbtt_timeout_process+0xb4> */
  L_00f8: a7 = LD32(a7 + 0x0);  /* 00f8 */
  a7 = a2 * a7;  /* 00fa */
  a8 = 0x51eb851fu;  /* 00fd: l32r = 1374389535 */
  a8 = (u32)(((u64)a7 * a8) >> 32);  /* 0100: mulsh */
  a7 = (i32)a7 >> 31;  /* 0103 */
  a8 = (i32)a8 >> 5;  /* 0106 */
  a8 = a8 - a7;  /* 0109: sub */
  goto L_0146;  /* 010c: j */
  L_0110: a8 = LD32(a5 + 0x0);  /* 0110 */
  a10 = LD32(a8 + 0x110);  /* 0112 */
  /* 0115: INDIRECT callx a10 <- mem[a8+0x110]; result unknown */ a2 = 0;
  a9 = a10;  /* 0118 */
  a8 = 1;  /* 011a */
  a10 = LD32(a3 + 0x0);  /* 011c */
  a10 = a9 - a10;  /* 011e: sub */
  a12 = LD32(a3 + 0x4);  /* 0121 */
  if (a9 < a10) goto L_0128;  /* 0123: bltu a9, a10, 128 <esp_mesh_pm_tbtt_timeout_process+0xcc> */
  L_0126: a8 = 0;  /* 0126 */
  L_0128: a11 = a11 - a12;  /* 0128: sub */
  a11 = a11 - a8;  /* 012b: sub */
  a12 = 0x3e8;  /* 012e */
  a13 = 0;  /* 0131 */
  a8 = (u32)&__divdi3 + 0x0;  /* 0133: l32r -> global */
  a2 = __divdi3(a2, a3, a4, a5, a6, a7);  /* 0136: callx a8 via reloc-expand */
  a8 = (i32)a2 >> 10;  /* 0139 */
  a10 = a10 / a8;  /* 013c: quos */
  a8 = 30;  /* 013f */
  if ((i32)a8 >= (i32)a10) goto L_00f8;  /* 0141: bge a8, a10, f8 <esp_mesh_pm_tbtt_timeout_process+0x9c> */
  L_0144: a8 = 0;  /* 0144 */
  L_0146: a7 = (u32)&g_mesh_dfs_compensation_ms + 0x0;  /* 0146: l32r -> global */
  a10 = 1;  /* 0149 */
  a7 = LD32(a7 + 0x0);  /* 014b */
  a9 = a7 << 5;  /* 014d */
  a9 = a9 - a7;  /* 0150: sub */
  a9 = a9 + (a7 << 2);  /* 0153 */
  a7 = a2 - a8;  /* 0156: sub */
  a6 = (u32)&LOCAL__bss_s_mesh_next_awake_tbtt + 0x0;  /* 0159: l32r -> .bss.s_mesh_next_awake_tbtt (same-object static) */
  a9 = a9 + (a7 << 3);  /* 015c */
  a7 = 0;  /* 015f */
  a9 = ((i32)a9 > (i32)a7) ? a9 : a7;  /* 0161: max */
  a11 = a7;  /* 0164 */
  ST32(a6 + 0x0, a9);  /* 0166 */
  a6 = (u32)&LOCAL__bss_s_mesh_is_awake_duty + 0x0;  /* 0168: l32r -> .bss.s_mesh_is_awake_duty (same-object static) */
  ST32(a4 + 0x0, a8);  /* 016b */
  a4 = 1;  /* 016d */
  ST8(a6 + 0x0, a4);  /* 016f */
  __asm__ volatile("" ::: "memory");  /* 0172: memw */
  __asm__ volatile("" ::: "memory");  /* 0175: memw */
  a8 = (u32)&pm_go_to_wake + 0x0;  /* 0178: l32r -> global */
  a2 = pm_go_to_wake(a2, a3, a4, a5, a6, a7);  /* 017b: callx a8 via reloc-expand */
  a10 = a7;  /* 017e */
  a8 = (u32)&ieee80211_hostap_send_beacon_process + 0x0;  /* 0180: l32r -> global */
  a2 = ieee80211_hostap_send_beacon_process(a2, a3, a4, a5, a6, a7);  /* 0183: callx a8 via reloc-expand */
  a10 = a2;  /* 0186 */
  a8 = (u32)&mesh_pm_tbtt_start;  /* 0188: l32r -> func addr */
  a2 = mesh_pm_tbtt_start(a2, a3, a4, a5, a6, a7);  /* 018b: callx a8 via reloc-expand */
  a2 = LD32(a5 + 0x0);  /* 018e */
  a10 = LD32(a2 + 0x110);  /* 0190 */
  /* 0193: INDIRECT callx a10 <- mem[a2+0x110]; result unknown */ a2 = 0;
  ST32(a3 + 0x20, a10);  /* 0196 */
  ST32(a3 + 0x24, a11);  /* 0198 */
  __asm__ volatile("" ::: "memory");  /* 019a: memw */
  goto L_01dc;  /* 019d: j */
  L_01a0: a8 = (u32)&pm_go_to_sleep + 0x0;  /* 01a0: l32r -> global */
  a2 = pm_go_to_sleep(a2, a3, a4, a5, a6, a7);  /* 01a3: callx a8 via reloc-expand */
  goto L_01dc;  /* 01a6: j */
  L_01ab: a8 = (u32)&pm_is_waked + 0x0;  /* 01ab: l32r -> global */
  a2 = pm_is_waked(a2, a3, a4, a5, a6, a7);  /* 01ae: callx a8 via reloc-expand */
  a2 = a10;  /* 01b1 */
  a8 = (u32)&pm_is_dream + 0x0;  /* 01b3: l32r -> global */
  a2 = pm_is_dream(a2, a3, a4, a5, a6, a7);  /* 01b6: callx a8 via reloc-expand */
  a3 = a10;  /* 01b9 */
  a8 = (u32)&pm_is_sleeping + 0x0;  /* 01bb: l32r -> global */
  a2 = pm_is_sleeping(a2, a3, a4, a5, a6, a7);  /* 01be: callx a8 via reloc-expand */
  a11 = 1;  /* 01c1 */
  a13 = (u32)(RODATA__rodata_wlog_warning_3 + 0x0);  /* 01c3: -> "(->sleep)busy, waked:%d, dream:%d, sleep:%d" */
  a15 = a3;  /* 01c6 */
  a14 = a2;  /* 01c8 */
  a12 = 2;  /* 01ca */
  a11 = a11 << 12;  /* 01cc */
  ST32(a1 + 0x0, a10);  /* 01cf */
  a10 = 1;  /* 01d1 */
  __asm__ volatile("" ::: "memory");  /* 01d3: memw */
  a8 = (u32)&wifi_log + 0x0;  /* 01d6: l32r -> global */
  a2 = wifi_log(a2, a3, a4, a5, a6, a7);  /* 01d9: callx a8 via reloc-expand */
  L_01dc: a2 = 0;  /* 01dc */
  return a2;  /* 01de: retw.n */
}


/* esp_mesh_pm_tx_data_process @ mesh_sleep.o 00000008 size 41B bind GLOBAL
 * Calls: pm_check_state, pm_is_waked | Data refs: none
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=2, refs=2); reloc-direct=2, funcdb-attributed=0, unknown-indirect=0 */
u32 esp_mesh_pm_tx_data_process(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a8;
  /* 0008: entry a1, 32 (frame 32 bytes) */
  a8 = (u32)&pm_check_state + 0x0;  /* 000b: l32r -> global */
  a2 = pm_check_state(a2, a3, a4, a5, a6, a7);  /* 000e: callx a8 via reloc-expand */
  if (a10 != 0) goto L_0019;  /* 0011: bnez a10, 19 <esp_mesh_pm_tx_data_process+0x11> */
  L_0014: a8 = 0;  /* 0014 */
  goto L_0024;  /* 0016: j */
  L_0019: a8 = (u32)&pm_is_waked + 0x0;  /* 0019: l32r -> global */
  a2 = pm_is_waked(a2, a3, a4, a5, a6, a7);  /* 001c: callx a8 via reloc-expand */
  if (a10 != 0) goto L_0014;  /* 001f: bnez a10, 14 <esp_mesh_pm_tx_data_process+0xc> */
  L_0022: a8 = 1;  /* 0022 */
  L_0024: ST8(a2 + 0x0, a8);  /* 0024 */
  __asm__ volatile("" ::: "memory");  /* 0027: memw */
  a2 = 0;  /* 002a */
  __asm__ volatile("" ::: "memory");  /* 002c: memw */
  return a2;  /* 002f: retw.n */
}


/* esp_mesh_pm_tx_null_process @ mesh_sleep.o 0000000c size 81B bind GLOBAL
 * Calls: pm_stop | indirect[1]: mem[a4+0x110] | Data refs: mesh_ps_keep_cnx, g_osi_funcs_p
 * Fidelity: medium - 1 indirect call site(s) via register (OSI/func-table); flow + direct calls mapped
 * Edges: funcdb-v3 (calls=1, refs=3); reloc-direct=1, funcdb-attributed=0, unknown-indirect=1 */
u32 esp_mesh_pm_tx_null_process(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a8, a9;
  /* 000c: entry a1, 32 (frame 32 bytes) */
  if (a3 != 1) goto L_0032;  /* 000f: bnei a3, 1, 32 <esp_mesh_pm_tx_null_process+0x26> */
  L_0012: a2 = (u32)&mesh_ps_keep_cnx + 0x0;  /* 0012: l32r -> global */
  a4 = 0;  /* 0015 */
  ST32(a2 + 0x18, a4);  /* 0017 */
  a4 = (u32)&g_osi_funcs_p + 0x0;  /* 0019: l32r -> global */
  a4 = LD32(a4 + 0x0);  /* 001c */
  a10 = LD32(a4 + 0x110);  /* 001f */
  __asm__ volatile("" ::: "memory");  /* 0022: memw */
  /* 0025: INDIRECT callx a10 <- mem[a4+0x110]; result unknown */ a2 = 0;
  ST32(a2 + 0x10, a10);  /* 0028 */
  ST32(a2 + 0x14, a11);  /* 002a */
  __asm__ volatile("" ::: "memory");  /* 002c: memw */
  goto L_0059;  /* 002f: j */
  L_0032: a2 = 15;  /* 0032 */
  if ((i32)a2 >= (i32)a4) goto L_0059;  /* 0034: bge a2, a4, 59 <esp_mesh_pm_tx_null_process+0x4d> */
  L_0037: a9 = (u32)&mesh_ps_keep_cnx + 0x0;  /* 0037: l32r -> global */
  a2 = 23;  /* 003a */
  a8 = LD32(a9 + 0x18);  /* 003c */
  a8 = a8 + (1);  /* 003e */
  if ((i32)a2 < (i32)a8) goto L_004c;  /* 0040: blt a2, a8, 4c <esp_mesh_pm_tx_null_process+0x40> */
  L_0043: ST32(a9 + 0x18, a8);  /* 0043 */
  __asm__ volatile("" ::: "memory");  /* 0045: memw */
  goto L_0059;  /* 0048: j */
  L_004c: a10 = 0;  /* 004c */
  ST32(a9 + 0x18, a10);  /* 004e */
  __asm__ volatile("" ::: "memory");  /* 0050: memw */
  a8 = (u32)&pm_stop + 0x0;  /* 0053: l32r -> global */
  a2 = pm_stop(a2, a3, a4, a5, a6, a7);  /* 0056: callx a8 via reloc-expand */
  L_0059: a2 = 0;  /* 0059 */
  return a2;  /* 005b: retw.n */
}


/* mesh_pm_set_null @ mesh_sleep.o 00000000 size 42B bind GLOBAL
 * Calls: none | Data refs: none
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=0, refs=0); reloc-direct=0, funcdb-attributed=0, unknown-indirect=0 */
u32 mesh_pm_set_null(u32 a2, u32 a3, u32 a4) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a8;
  /* 0000: entry a1, 32 (frame 32 bytes) */
  a2 = (a2 >> 8) & 0x1;  /* 0003: extui width 1 */
  a8 = 1;  /* 0006 */
  if (a2 == 0) goto L_001c;  /* 0008: beqz.n a2, 1c <mesh_pm_set_null+0x1c> */
  L_000a: ST8(a3 + 0x0, a8);  /* 000a */
  a2 = 0;  /* 000d */
  ST8(a4 + 0x0, a2);  /* 000f */
  __asm__ volatile("" ::: "memory");  /* 0012: memw */
  __asm__ volatile("" ::: "memory");  /* 0015: memw */
  goto L_0025;  /* 0018: j */
  L_001c: ST8(a4 + 0x0, a8);  /* 001c */
  ST8(a3 + 0x0, a2);  /* 001f */
  __asm__ volatile("" ::: "memory");  /* 0022: memw */
  L_0025: __asm__ volatile("" ::: "memory");  /* 0025: memw */
  return a2;  /* 0028: retw.n */
}


/* mesh_pm_tbtt_start @ mesh_sleep.o 00000018 size 76B bind GLOBAL
 * Calls: pm_send_nullfunc, esp_mesh_sync_interface_tsf | Data refs: .bss.send_null_cnt$1
 * Fidelity: high - small leaf; control flow, calls and constants fully mapped
 * Edges: funcdb-v3 (calls=2, refs=3); reloc-direct=2, funcdb-attributed=0, unknown-indirect=0 */
u32 mesh_pm_tbtt_start(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) {
  u32 a1 = 0; /* stack pointer on entry (spill offsets preserved) */
  u32 a10, a11, a12, a13, a8, a9;
  /* 0018: entry a1, 32 (frame 32 bytes) */
  a10 = (u32)&LOCAL__bss_send_null_cnt_1 + 0x0;  /* 001b: l32r -> .bss.send_null_cnt$1 (same-object static) */
  a9 = LD32(a10 + 0x0);  /* 001e */
  a9 = a9 + (1);  /* 0020 */
  a8 = 0xcccccccdu;  /* 0022: l32r = -858993459 */
  a8 = a9 * a8;  /* 0025 */
  a3 = 0x19999990u;  /* 0028: l32r = 429496720 */
  a8 = a8 + a3;  /* 002b */
  /* 002d: ssai 4 (SAR/shift-amount, summarized) */
  a8 = SRC_FUNNEL(a8, a8);  /* 0030: src (funnel shift via SAR, untracked) */
  a3 = 0x03333332u;  /* 0033: l32r = 53687090 */
  if (a3 >= a8) goto L_0042;  /* 0036: bgeu a3, a8, 42 <mesh_pm_tbtt_start+0x2a> */
  L_0039: ST32(a10 + 0x0, a9);  /* 0039 */
  __asm__ volatile("" ::: "memory");  /* 003b: memw */
  goto L_0060;  /* 003e: j */
  L_0042: a3 = 0;  /* 0042 */
  ST32(a10 + 0x0, a3);  /* 0044 */
  a10 = a3;  /* 0046 */
  __asm__ volatile("" ::: "memory");  /* 0048: memw */
  a8 = (u32)&pm_send_nullfunc + 0x0;  /* 004b: l32r -> global */
  a2 = pm_send_nullfunc(a2, a3, a4, a5, a6, a7);  /* 004e: callx a8 via reloc-expand */
  a13 = 1;  /* 0051 */
  a12 = a3;  /* 0053 */
  a11 = a13;  /* 0055 */
  a10 = (i32)a2 >> 10;  /* 0057 */
  a8 = (u32)&esp_mesh_sync_interface_tsf + 0x0;  /* 005a: l32r -> global */
  a2 = esp_mesh_sync_interface_tsf(a2, a3, a4, a5, a6, a7);  /* 005d: callx a8 via reloc-expand */
  L_0060: a2 = 0;  /* 0060 */
  return a2;  /* 0062: retw.n */
}

