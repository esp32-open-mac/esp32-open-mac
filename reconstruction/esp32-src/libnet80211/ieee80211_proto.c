/* ieee80211_proto.o - reconstructed control-path C (offline, from objdump -d -r).
 * 7 code sections recovered. Fidelity per function below.
 * Conventions: args a2..a7 (Xtensa windowed ABI); outgoing call args
 * traced as a10..; u32 used for pointers/regs; opaque_* marks unrecovered.
 */
#include <stdint.h>
typedef unsigned char u8; typedef unsigned short u16; typedef unsigned int u32;
static u32 opaque_result, last_call_result;
/* ---- externals (U symbols + literal refs) ---- */
extern u32 rodata_rates_0; /* .rodata.rates$0 */
extern u32 rodata_wlog_debug_2; /* .rodata_wlog_debug.2 */
extern u32 g_ic; /* g_ic */
extern u32 g_wifi_improve_contention_ability; /* g_wifi_improve_contention_ability */
extern u32 ic_register_tx_cb(); /* ic_register_tx_cb */
extern u32 ic_set_ac_param(); /* ic_set_ac_param */
extern u32 ieee80211_sta_new_state(); /* ieee80211_sta_new_state */
extern u32 ieee80211_tx_mgt_cb; /* ieee80211_tx_mgt_cb */
extern u32 memcpy(); /* memcpy */
extern u32 wifi_log(); /* wifi_log */

/* ROLE: tiny protocol helpers: ieee80211_gettid (TID from QoS ctl),
 * erp rateset check, mlme_connect_bss, proto_attach, short-slot, WME params.
 */
/* ---- literal-rooted access patterns (offsets observed; layout NOT confirmed) ----
 * g_ic: u32+16
 * g_wifi_improve_contention_ability: u8+0
/* ---- funcdb-v2 cross-check (calls[] vs section relocs; disasm is ground truth) ----
 * confirmed funcdb edges: 5; rejected funcdb-only (no exact reloc in
 * callee section; caller-side .rela.text.<f> prefix-collision artifacts): 0;
 * disasm-only edges kept (static-local callees + funcdb relsec:null gaps): 0;
 */
/* ==== functions of ieee80211_proto.o ==== */

/* ieee80211_proto_attach @ ieee80211_proto.o 0x00000008 size 35B bind GLOBAL
 * Calls: ic_register_tx_cb | Data refs: ieee80211_tx_mgt_cb
 * Fidelity: high - straight-line, fully mapped (14 insns) */
u32 ieee80211_proto_attach(u32 a2)
{
    /* frame: entry a1,32; 14 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* immediates: 1, 0, 2 */
    /* mem ld32: base=(?) off=28 */
    /* mem st32: base=(?) off=12 */
    /* mem st32: base=(?) off=28 */
    /* site +0x26: ic_register_tx_cb(lit:ieee80211_tx_mgt_cb, 2, 0) */
    ic_register_tx_cb(lit:ieee80211_tx_mgt_cb, 2, 0);
    return opaque_result; /* full dataflow not recovered */
}

/* ieee80211_gettid @ ieee80211_proto.o 0x00000000 size 54B bind GLOBAL
 * Calls: none | Data refs: none
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 ieee80211_gettid(u32 a2)
{
    /* frame: entry a1,32; 19 insns, 3 cond-branches, 0 loops, 1 jumps */
    /* immediates: 12, 17, -116, 136, 16 */
    /* first predicate: bnone a9, a10, 32 <ieee80211_gettid+0x32> (condition opaque) */
    /* mem ld8: base=(?) off=0 */
    /* mem ld8: base=(?) off=1 */
    /* mem ld8: base=(?) off=30 */
    /* mem ld8: base=(?) off=24 */
    return *(?+24);
}

/* ieee80211_set_shortslottime @ ieee80211_proto.o 0x00000000 size 27B bind GLOBAL
 * Calls: none | Data refs: none
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 ieee80211_set_shortslottime(u32 a2, u32 a3)
{
    /* frame: entry a1,32; 10 insns, 1 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0xfffffbff, 0x400 */
    /* first predicate: beqz a3, 14 <ieee80211_set_shortslottime+0x14> (condition opaque) */
    /* mem ld32: base=(?) off=28 */
    /* mem st32: base=(?) off=28 */
    return opaque_result; /* full dataflow not recovered */
}

/* ieee80211_iserp_rateset @ ieee80211_proto.o 0x00000004 size 74B bind GLOBAL
 * Calls: none | Data refs: .rodata.rates$0
 * Fidelity: medium - branchy but loop-free, call sequence mapped */
u32 ieee80211_iserp_rateset(u32 a2)
{
    /* frame: entry a1,32; 29 insns, 5 cond-branches, 0 loops, 4 jumps */
    /* immediates: 0, 1 */
    /* first predicate: bgeui a11, 7, 40 <ieee80211_iserp_rateset+0x3c> (condition opaque) */
    /* mem ld8: base=(?) off=0 */
    /* mem ld8: base=(0) off=1 */
    /* mem ld32: base=((lit:.rodata.rates$0+4)) off=0 */
    return 0;
}

/* ieee80211_wme_initparams @ ieee80211_proto.o 0x00000000 size 5B bind GLOBAL
 * Calls: none | Data refs: none
 * Fidelity: high - straight-line, fully mapped (2 insns) */
u32 ieee80211_wme_initparams(void)
{
    /* frame: entry a1,32; 2 insns, 0 cond-branches, 0 loops, 0 jumps */
    return opaque_result; /* full dataflow not recovered */
}

/* ieee80211_wme_updateparams @ ieee80211_proto.o 0x0000000c size 67B bind GLOBAL
 * Calls: ic_set_ac_param, ic_set_ac_param | Data refs: g_wifi_improve_contention_ability
 * Fidelity: medium - branchy but loop-free, call sequence mapped */
u32 ieee80211_wme_updateparams(u32 a3)
{
    /* frame: entry a1,32; 26 insns, 4 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0, 2, 0x5e0, 3 */
    /* first predicate: beqz.n a11, 2d <ieee80211_wme_updateparams+0x21> (condition opaque) */
    /* mem ld8: base=((?+3)) off=0 */
    /* mem ld8: base=((?+3)) off=1 */
    /* mem ld8: base=((?+3)) off=2 */
    /* mem ld8: base=((?+3)) off=3 */
    /* mem ld8: base=(lit:g_wifi_improve_contention_ability) off=0 */
    /* site +0x2a: ic_set_ac_param(0, *((?+3)+0), *((?+3)+1), *((?+3)+2), *((?+3)+3)) */
    ic_set_ac_param(0, *((?+3)+0), *((?+3)+1), *((?+3)+2), *((?+3)+3));
    /* site +0x4a: ic_set_ac_param(2, 2, 2, 3, 0x5e0) */
    ic_set_ac_param(2, 2, 2, 3, 0x5e0);
    return opaque_result; /* full dataflow not recovered */
}

/* ieee80211_mlme_connect_bss @ ieee80211_proto.o 0x00000014 size 78B bind GLOBAL
 * Calls: memcpy, wifi_log, ieee80211_sta_new_state | Data refs: g_ic, .rodata_wlog_debug.2
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 ieee80211_mlme_connect_bss(u32 a2, u32 a3, u32 a4, u32 a5)
{
    /* frame: entry a1,32; 30 insns, 1 cond-branches, 0 loops, 0 jumps */
    /* immediates: 156, 6, 4, 1, 176, 2, 3 */
    /* first predicate: bnez.n a4, 58 <ieee80211_mlme_connect_bss+0x44> (condition opaque) */
    /* mem ld32: base=(lit:g_ic) off=16 */
    /* mem st32: base=(*(g_ic+16)) off=228 */
    /* site +0x35: memcpy(156, (?+4), 6) */
    memcpy(156, (?+4), 6);
    /* site +0x49: wifi_log(1, 4, 4, lit:.rodata_wlog_debug.2) */
    wifi_log(1, 4, 4, lit:.rodata_wlog_debug.2);
    /* site +0x5d: ieee80211_sta_new_state(lit:g_ic, 3, (? slli 5), lit:.rodata_wlog_debug.2) */
    ieee80211_sta_new_state(lit:g_ic, 3, (? slli 5), lit:.rodata_wlog_debug.2);
    return opaque_result; /* full dataflow not recovered */
}
