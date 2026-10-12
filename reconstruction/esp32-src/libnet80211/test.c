/* test.o - reconstructed control-path C (offline, from objdump -d -r).
 * 2 code sections recovered. Fidelity per function below.
 * Conventions: args a2..a7 (Xtensa windowed ABI); outgoing call args
 * traced as a10..; u32 used for pointers/regs; opaque_* marks unrecovered.
 */
#include <stdint.h>
typedef unsigned char u8; typedef unsigned short u16; typedef unsigned int u32;
static u32 opaque_result, last_call_result;
/* ---- externals (U symbols + literal refs) ---- */
extern u32 rodata_wlog_warning_2; /* .rodata_wlog_warning.2 */
extern u32 rodata_wlog_warning_3; /* .rodata_wlog_warning.3 */
extern u32 rodata_wlog_warning_4; /* .rodata_wlog_warning.4 */
extern u32 cnx_node_search(); /* cnx_node_search */
extern u32 g_ic; /* g_ic */
extern u32 ieee80211_ampdu_request(); /* ieee80211_ampdu_request */
extern u32 wifi_log(); /* wifi_log */

/* ROLE: test hooks: esp_test_{sta,ap}_create_addba validate the node/BA
 * state (g_ic+16/+20 lists, +228/+0x244 entries, bit2 of +44 clear) then call
 * ieee80211_ampdu_request, else wifi_log; return 0.
 */
/* ---- literal-rooted access patterns (offsets observed; layout NOT confirmed) ----
 * g_ic: u32+16, u32+16, u32+20, u16+0x244
/* ---- funcdb-v2 cross-check (calls[] vs section relocs; disasm is ground truth) ----
 * confirmed funcdb edges: 5; rejected funcdb-only (no exact reloc in
 * callee section; caller-side .rela.text.<f> prefix-collision artifacts): 0;
 * disasm-only edges kept (static-local callees + funcdb relsec:null gaps): 0;
 */
/* ==== functions of test.o ==== */

/* esp_test_sta_create_addba @ test.o 0x00000010 size 72B bind GLOBAL
 * Calls: ieee80211_ampdu_request, wifi_log | Data refs: g_ic, .rodata_wlog_warning.2
 * Fidelity: medium - branchy but loop-free, call sequence mapped */
u32 esp_test_sta_create_addba(u32 a2)
{
    /* frame: entry a1,32; 28 insns, 5 cond-branches, 0 loops, 1 jumps */
    /* immediates: -1, 2, 64, 1, 0 */
    /* first predicate: beqz.n a9, 54 <esp_test_sta_create_addba+0x44> (condition opaque) */
    /* mem ld32: base=(lit:g_ic) off=16 */
    /* mem ld32: base=(*(g_ic+16)) off=228 */
    /* mem ld32: base=(-1) off=0x244 */
    /* mem ld16: base=(*(g_ic+0x244)) off=44 */
    /* site +0x3a: ieee80211_ampdu_request(*(*(g_ic+16)+228)) */
    ieee80211_ampdu_request(*(*(g_ic+16)+228));
    /* site +0x4f: wifi_log(1, 64, 2, lit:.rodata_wlog_warning.2) */
    wifi_log(1, 64, 2, lit:.rodata_wlog_warning.2);
    return 0;
}

/* esp_test_ap_create_addba @ test.o 0x0000001c size 158B bind GLOBAL
 * Calls: cnx_node_search, wifi_log, ieee80211_ampdu_request, wifi_log | Data refs: g_ic, .rodata_wlog_warning.3, .rodata_wlog_warning.4
 * Fidelity: medium - branchy but loop-free, call sequence mapped (verified: section R_XTENSA_ASM_EXPAND + funcdb v3 agree; predicates opaque) */
u32 esp_test_ap_create_addba(u32 a2, u32 a3)
{
    /* frame: entry a1,64; 61 insns, 5 cond-branches, 0 loops, 2 jumps */
    /* immediates: -1, 2, 64, 1, 0 */
    /* first predicate: beqz a9, b6 <esp_test_ap_create_addba+0x9a> (condition opaque) */
    /* mem ld32: base=(lit:g_ic) off=20 */
    /* mem st32: base=(?) off=16 */
    /* mem ld8: base=(?) off=5 */
    /* mem st32: base=(?) off=12 */
    /* mem ld8: base=(?) off=4 */
    /* mem st32: base=(?) off=8 */
    /* mem ld8: base=(?) off=3 */
    /* mem st32: base=(?) off=4 */
    /* mem ld8: base=(?) off=2 */
    /* mem st32: base=(?) off=0 */
    /* ... +16 more memops */
    /* site +0x2e: cnx_node_search(/* no traced args */) */
    cnx_node_search(/* no traced args */);
    /* site +0x5e: wifi_log(1, 64, 2, lit:.rodata_wlog_warning.3, *(?+0)) */
    wifi_log(1, 64, 2, lit:.rodata_wlog_warning.3, *(?+0));
    /* site +0x7f: ieee80211_ampdu_request(ret@5e, 64, 2, lit:.rodata_wlog_warning.3, *(?+0)) */
    ieee80211_ampdu_request(ret@5e, 64, 2, lit:.rodata_wlog_warning.3, *(?+0));
    /* site +0xb1: wifi_log(1, 64, 2, lit:.rodata_wlog_warning.4, *(?+0)) */
    wifi_log(1, 64, 2, lit:.rodata_wlog_warning.4, *(?+0));
    return 0;
}
