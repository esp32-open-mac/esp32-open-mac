/* ieee80211_debug.o - reconstructed control-path C (offline, from objdump -d -r).
 * 3 code sections recovered. Fidelity per function below.
 * Conventions: args a2..a7 (Xtensa windowed ABI); outgoing call args
 * traced as a10..; u32 used for pointers/regs; opaque_* marks unrecovered.
 */
#include <stdint.h>
typedef unsigned char u8; typedef unsigned short u16; typedef unsigned int u32;
static u32 opaque_result, last_call_result;
/* ---- externals (U symbols + literal refs) ---- */
extern u32 rodata; /* .rodata */
extern u32 rodata_dbg_hmac_rxtx_statis_dump_str1_1; /* .rodata.dbg_hmac_rxtx_statis_dump.str1.1 */
extern u32 rodata_wifi_log_str1_1; /* .rodata.wifi_log.str1.1 */
extern u32 rodata_wlog_info_10; /* .rodata_wlog_info.10 */
extern u32 rodata_wlog_info_11; /* .rodata_wlog_info.11 */
extern u32 rodata_wlog_info_12; /* .rodata_wlog_info.12 */
extern u32 rodata_wlog_info_13; /* .rodata_wlog_info.13 */
extern u32 rodata_wlog_info_14; /* .rodata_wlog_info.14 */
extern u32 rodata_wlog_info_2; /* .rodata_wlog_info.2 */
extern u32 rodata_wlog_info_3; /* .rodata_wlog_info.3 */
extern u32 rodata_wlog_info_4; /* .rodata_wlog_info.4 */
extern u32 rodata_wlog_info_5; /* .rodata_wlog_info.5 */
extern u32 rodata_wlog_info_6; /* .rodata_wlog_info.6 */
extern u32 rodata_wlog_info_7; /* .rodata_wlog_info.7 */
extern u32 rodata_wlog_info_8; /* .rodata_wlog_info.8 */
extern u32 rodata_wlog_info_9; /* .rodata_wlog_info.9 */
extern u32 g_hmac_cnt; /* g_hmac_cnt */
extern u32 g_log_level; /* g_log_level */
extern u32 g_osi_funcs_p; /* g_osi_funcs_p */
extern u32 memcpy(); /* memcpy */

/* ROLE: logging: wifi_log (level/mod-gated via g_osi_funcs_p) and
 * hmac stat dumps. All format strings live in .rodata_wlog_*.
 */
/* ---- literal-rooted access patterns (offsets observed; layout NOT confirmed) ----
 * g_hmac_cnt: u32+0, u32+4, u16+8, u16+10, u16+12, u8+14, u8+15, u8+16, u8+17, u16+18, u32+20, u32+24, u16+28, u16+30 (+15 more)
 * g_log_level: u32+0
 * g_osi_funcs_p: u32+0, u32+0
/* ---- funcdb-v2 cross-check (calls[] vs section relocs; disasm is ground truth) ----
 * confirmed funcdb edges: 3; rejected funcdb-only (no exact reloc in
 * callee section; caller-side .rela.text.<f> prefix-collision artifacts): 0;
 * disasm-only edges kept (static-local callees + funcdb relsec:null gaps): 0;
 */
/* ==== functions of ieee80211_debug.o ==== */

/* wifi_log @ ieee80211_debug.o 0x00000024 size 156B bind GLOBAL
 * Calls: memcpy, indirect(a10), indirect(a6), indirect(a8), indirect(a3) | Data refs: .rodata, g_osi_funcs_p, g_log_level, .rodata.wifi_log.str1.1
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 wifi_log(u32 a3, u32 a4, u32 a5, u32 a6, u32 a7)
{
    /* frame: entry a1,112; 59 insns, 3 cond-branches, 0 loops, 0 jumps */
    /* immediates: 7, 0, 16 */
    /* first predicate: beqz a2, be <wifi_log+0x9a> (condition opaque) */
    /* mem st32: base=(?) off=64 */
    /* mem st32: base=(?) off=68 */
    /* mem st8: base=(?) off=35 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=0x154 */
    /* mem ld32: base=(lit:g_log_level) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=0x158 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=0x150 */
    /* mem ld8: base=(&memcpy()) off=0 */
    /* mem st32: base=(?) off=0 */
    /* ... +7 more memops */
    /* site +0x3e: memcpy((?+28), lit:.rodata, 7) */
    memcpy((?+28), lit:.rodata, 7);
    /* site +0x6f: indirect call via a10 (base *(*(g_osi_funcs_p+0)+0x158)); args: *(*(g_osi_funcs_p+0)+0x158), lit:.rodata, 7 */
    opaque_indirect_a10();
    /* site +0x8a: indirect call via a6 (base *(*(g_osi_funcs_p+0)+0x150)); args: ?, lit:.rodata.wifi_log.str1.1, lit:.rodata, *(&memcpy()+0), ret@6f */
    opaque_indirect_a6();
    /* site +0xa9: indirect call via a8 (base *(.rodata+0x154)); args: ?, lit:.rodata.wifi_log.str1.1, ?, (?+80), (?+48) */
    opaque_indirect_a8();
    /* site +0xbb: indirect call via a3 (base *(g_osi_funcs_p+0x150)); args: ?, lit:.rodata.wifi_log.str1.1, lit:.rodata, lit:.rodata, (?+48) */
    opaque_indirect_a3();
    return opaque_result; /* full dataflow not recovered */
}

/* dbg_hmac_rxtx_statis_dump @ ieee80211_debug.o 0x000000c0 size 471B bind GLOBAL
 * Calls: wifi_log, wifi_log, wifi_log, wifi_log, wifi_log, wifi_log, wifi_log, wifi_log, wifi_log, wifi_log, wifi_log, wifi_log, wifi_log | Data refs: .rodata_wlog_info.2, .rodata_wlog_info.3, .rodata.dbg_hmac_rxtx_statis_dump.str1.1, .rodata_wlog_info.4, g_hmac_cnt, .rodata_wlog_info.5, .rodata_wlog_info.6, .rodata_wlog_info.7, .rodata_wlog_info.8, .rodata_wlog_info.9, .rodata_wlog_info.10, .rodata_wlog_info.11, .rodata_wlog_info.12, .rodata_wlog_info.13, .rodata_wlog_info.14
 * Fidelity: medium - 185 insns, 0 branches, 0 loops; branchy but loop-free, call sequence mapped (verified against section disasm; predicates opaque) */
u32 dbg_hmac_rxtx_statis_dump(u32 a2, u32 a5, u32 a6, u32 a7)
{
    /* frame: entry a1,64; 185 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* immediates: 1, 3 */
    /* mem st32: base=(?) off=12 */
    /* mem st32: base=(?) off=8 */
    /* mem st32: base=(?) off=4 */
    /* mem st32: base=(?) off=0 */
    /* mem ld16: base=(lit:g_hmac_cnt) off=12 */
    /* mem st32: base=(?) off=12 */
    /* mem ld16: base=(lit:g_hmac_cnt) off=10 */
    /* mem st32: base=(?) off=8 */
    /* mem ld16: base=(lit:g_hmac_cnt) off=8 */
    /* mem st32: base=(?) off=4 */
    /* ... +57 more memops */
    /* site +0xd6: wifi_log(1, (1 slli 19), 3, lit:.rodata_wlog_info.2) */
    wifi_log(1, (1 slli 19), 3, lit:.rodata_wlog_info.2);
    /* site +0xe5: wifi_log(1, (1 slli 19), 3, lit:.rodata_wlog_info.3) */
    wifi_log(1, (1 slli 19), 3, lit:.rodata_wlog_info.3);
    /* site +0x113: wifi_log(1, (1 slli 19), 3, lit:.rodata_wlog_info.4, lit:.rodata_wlog_info.2) */
    wifi_log(1, (1 slli 19), 3, lit:.rodata_wlog_info.4, lit:.rodata_wlog_info.2);
    /* site +0x143: wifi_log(1, (1 slli 19), 3, lit:.rodata_wlog_info.5, lit:.rodata_wlog_info.2) */
    wifi_log(1, (1 slli 19), 3, lit:.rodata_wlog_info.5, lit:.rodata_wlog_info.2);
    /* site +0x16f: wifi_log(1, (1 slli 19), 3, lit:.rodata_wlog_info.6, lit:.rodata_wlog_info.2) */
    wifi_log(1, (1 slli 19), 3, lit:.rodata_wlog_info.6, lit:.rodata_wlog_info.2);
    /* site +0x17e: wifi_log(1, (1 slli 19), 3, lit:.rodata_wlog_info.7, lit:.rodata_wlog_info.2) */
    wifi_log(1, (1 slli 19), 3, lit:.rodata_wlog_info.7, lit:.rodata_wlog_info.2);
    /* site +0x1aa: wifi_log(1, (1 slli 19), 3, lit:.rodata_wlog_info.8, lit:.rodata_wlog_info.2) */
    wifi_log(1, (1 slli 19), 3, lit:.rodata_wlog_info.8, lit:.rodata_wlog_info.2);
    /* site +0x1d6: wifi_log(1, (1 slli 19), 3, lit:.rodata_wlog_info.9, lit:.rodata_wlog_info.2) */
    wifi_log(1, (1 slli 19), 3, lit:.rodata_wlog_info.9, lit:.rodata_wlog_info.2);
    /* site +0x203: wifi_log(1, (1 slli 19), 3, lit:.rodata_wlog_info.10, lit:.rodata_wlog_info.2) */
    wifi_log(1, (1 slli 19), 3, lit:.rodata_wlog_info.10, lit:.rodata_wlog_info.2);
    /* site +0x212: wifi_log(1, (1 slli 19), 3, lit:.rodata_wlog_info.11, lit:.rodata_wlog_info.2) */
    wifi_log(1, (1 slli 19), 3, lit:.rodata_wlog_info.11, lit:.rodata_wlog_info.2);
    /* site +0x221: wifi_log(1, (1 slli 19), 3, lit:.rodata_wlog_info.12, lit:.rodata_wlog_info.2) */
    wifi_log(1, (1 slli 19), 3, lit:.rodata_wlog_info.12, lit:.rodata_wlog_info.2);
    /* site +0x259: wifi_log(1, (1 slli 19), 3, lit:.rodata_wlog_info.13, lit:.rodata_wlog_info.2) */
    wifi_log(1, (1 slli 19), 3, lit:.rodata_wlog_info.13, lit:.rodata_wlog_info.2);
    /* site +0x292: wifi_log(1, (1 slli 19), 3, lit:.rodata_wlog_info.14, *(g_hmac_cnt+44)) */
    wifi_log(1, (1 slli 19), 3, lit:.rodata_wlog_info.14, *(g_hmac_cnt+44));
    return opaque_result; /* full dataflow not recovered */
}

/* dbg_hmac_statis_dump @ ieee80211_debug.o 0x00000004 size 14B bind GLOBAL
 * Calls: dbg_hmac_rxtx_statis_dump | Data refs: none
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 dbg_hmac_statis_dump(u32 a2)
{
    /* frame: entry a1,32; 5 insns, 1 cond-branches, 0 loops, 0 jumps */
    /* first predicate: bbci a2, 1, 10 <dbg_hmac_statis_dump+0xc> (condition opaque) */
    /* site +0xd: dbg_hmac_rxtx_statis_dump(/* no traced args */) */
    dbg_hmac_rxtx_statis_dump(/* no traced args */);
    return opaque_result; /* full dataflow not recovered */
}
