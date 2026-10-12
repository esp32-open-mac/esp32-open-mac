/* ieee80211_ets.o - reconstructed control-path C (offline, from objdump -d -r).
 * 2 code sections recovered. Fidelity per function below.
 * Conventions: args a2..a7 (Xtensa windowed ABI); outgoing call args
 * traced as a10..; u32 used for pointers/regs; opaque_* marks unrecovered.
 */
#include <stdint.h>
typedef unsigned char u8; typedef unsigned short u16; typedef unsigned int u32;
static u32 opaque_result, last_call_result;
/* ---- externals (U symbols + literal refs) ---- */
extern u32 rodata_wlog_info_2; /* .rodata_wlog_info.2 */
extern u32 rodata_wlog_warning_3; /* .rodata_wlog_warning.3 */
extern u32 g_beacon_eb; /* g_beacon_eb */
extern u32 g_beacon_idx; /* g_beacon_idx */
extern u32 g_wifi_menuconfig; /* g_wifi_menuconfig */
extern u32 ic_ebuf_alloc(); /* ic_ebuf_alloc */
extern u32 roundup2(); /* roundup2 */
extern u32 wifi_log(); /* wifi_log */

/* ROLE: frame allocators: ieee80211_getmgtframe (roundup2 size class
 * 64/256/259?, ic_ebuf_alloc, links mbuf chain, stores len@+22) and
 * ieee80211_getbcnframe (g_beacon_eb[idx] fast path, menuconfig+56 size floor
 * max(...,0x2f0), else alloc + wifi_log).
 */
/* ---- literal-rooted access patterns (offsets observed; layout NOT confirmed) ----
 * g_beacon_eb: u32+4
 * g_beacon_idx: u8+0, u32+0
 * g_wifi_menuconfig: u32+56
 * ret@2d: u32+4
/* ---- funcdb-v2 cross-check (calls[] vs section relocs; disasm is ground truth) ----
 * confirmed funcdb edges: 4; rejected funcdb-only (no exact reloc in
 * callee section; caller-side .rela.text.<f> prefix-collision artifacts): 0;
 * disasm-only edges kept (static-local callees + funcdb relsec:null gaps): 0;
 */
/* ==== functions of ieee80211_ets.o ==== */

/* ieee80211_getmgtframe @ ieee80211_ets.o 0x00000008 size 63B bind GLOBAL
 * Calls: roundup2, ic_ebuf_alloc | Data refs: none
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 ieee80211_getmgtframe(u32 a2, u32 a3, u32 a4)
{
    /* frame: entry a1,32; 26 insns, 3 cond-branches, 0 loops, 0 jumps */
    /* immediates: 4, 0x100, 64, 2, 3, 0 */
    /* first predicate: bltu a8, a10, 26 <ieee80211_getmgtframe+0x1e> (condition opaque) */
    /* mem ld32: base=(ret@2d) off=4 */
    /* mem ld32: base=(*(ret@2d+4)) off=4 */
    /* mem st32: base=(?) off=0 */
    /* mem st16: base=(ret@2d) off=22 */
    /* site +0x12: roundup2(?, 4) */
    roundup2(?, 4);
    /* site +0x2d: ic_ebuf_alloc(0, 3, ret@12) */
    ic_ebuf_alloc(0, 3, ret@12);
    return last_call_result; /* opaque */
}

/* ieee80211_getbcnframe @ ieee80211_ets.o 0x00000020 size 106B bind GLOBAL
 * Calls: wifi_log, ic_ebuf_alloc, wifi_log | Data refs: g_beacon_eb, g_beacon_idx, g_wifi_menuconfig, .rodata_wlog_info.2, .rodata_wlog_warning.3
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 ieee80211_getbcnframe(u32 a2, u32 a3, u32 a4, u32 a6, u32 a7)
{
    /* frame: entry a1,32; 43 insns, 2 cond-branches, 0 loops, 1 jumps */
    /* immediates: 1, 3, 0x2f0, 4, 2, 64 */
    /* first predicate: bnez.n a2, 61 <ieee80211_getbcnframe+0x41> (condition opaque) */
    /* mem ld8: base=(lit:g_beacon_idx) off=0 */
    /* mem ld32: base=(*(g_beacon_idx+0)) off=0 */
    /* mem ld32: base=(lit:g_wifi_menuconfig) off=56 */
    /* mem ld32: base=(ret@5a) off=4 */
    /* mem ld32: base=(*(g_beacon_eb+4)) off=4 */
    /* mem st32: base=(?) off=0 */
    /* mem st16: base=(ret@5a) off=22 */
    /* site +0x4e: wifi_log(1, 1, 3, lit:.rodata_wlog_info.2, *(g_wifi_menuconfig+56)) */
    wifi_log(1, 1, 3, lit:.rodata_wlog_info.2, *(g_wifi_menuconfig+56));
    /* site +0x5a: ic_ebuf_alloc(*(*(g_beacon_idx+0)+0), 4, ?, lit:.rodata_wlog_info.2, *(g_wifi_menuconfig+56)) */
    ic_ebuf_alloc(*(*(g_beacon_idx+0)+0), 4, ?, lit:.rodata_wlog_info.2, *(g_wifi_menuconfig+56));
    /* site +0x85: wifi_log(1, 64, 2, lit:.rodata_wlog_warning.3, *(g_beacon_eb+4)) */
    wifi_log(1, 64, 2, lit:.rodata_wlog_warning.3, *(g_beacon_eb+4));
    return opaque_result; /* full dataflow not recovered */
}
