/* ieee80211_rfid.o - reconstructed control-path C (offline, from objdump -d -r).
 * 6 code sections recovered. Fidelity per function below.
 * Conventions: args a2..a7 (Xtensa windowed ABI); outgoing call args
 * traced as a10..; u32 used for pointers/regs; opaque_* marks unrecovered.
 */
#include <stdint.h>
typedef unsigned char u8; typedef unsigned short u16; typedef unsigned int u32;
static u32 opaque_result, last_call_result;
/* ---- externals (U symbols + literal refs) ---- */
extern u32 g_ic; /* g_ic */
extern u32 g_wifi_nvs; /* g_wifi_nvs */

/* ROLE: RFID location callbacks: single callback slot at g_ic+0x1c4.
 * register/unregister write the slot (NULL on unregister/reset + memw);
 * ieee80211_rfid_locp_recv dispatches slot(arg) if bit0 of *(arg+4) set and
 * slot != NULL. recv_open validates mode byte *(g_wifi_nvs[0]+0) ranges.
 */
/* ---- literal-rooted access patterns (offsets observed; layout NOT confirmed) ----
 * g_ic: u32+452
 * g_wifi_nvs: u32+0, u8+0
/* ---- funcdb-v2 cross-check (calls[] vs section relocs; disasm is ground truth) ----
 * confirmed funcdb edges: 0; rejected funcdb-only (no exact reloc in
 * callee section; caller-side .rela.text.<f> prefix-collision artifacts): 0;
 * disasm-only edges kept (static-local callees + funcdb relsec:null gaps): 0;
 */
/* ==== functions of ieee80211_rfid.o ==== */

/* ieee80211_rfid_locp_recv_open @ ieee80211_rfid.o 0x00000004 size 34B bind GLOBAL
 * Calls: none | Data refs: g_wifi_nvs
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 ieee80211_rfid_locp_recv_open(u32 a2)
{
    /* frame: entry a1,32; 12 insns, 2 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0, 1 */
    /* first predicate: bgeui a8, 5, 24 <ieee80211_rfid_locp_recv_open+0x20> (condition opaque) */
    /* mem ld32: base=(lit:g_wifi_nvs) off=0 */
    /* mem ld8: base=(*(g_wifi_nvs+0)) off=0 */
    return opaque_result; /* full dataflow not recovered */
}

/* ieee80211_rfid_locp_recv_close @ ieee80211_rfid.o 0x00000000 size 5B bind GLOBAL
 * Calls: none | Data refs: none
 * Fidelity: high - straight-line, fully mapped (2 insns) */
u32 ieee80211_rfid_locp_recv_close(void)
{
    /* frame: entry a1,32; 2 insns, 0 cond-branches, 0 loops, 0 jumps */
    return opaque_result; /* full dataflow not recovered */
}

/* ieee80211_rfid_locp_recv_reset @ ieee80211_rfid.o 0x00000004 size 16B bind GLOBAL
 * Calls: none | Data refs: g_ic
 * Fidelity: high - straight-line, fully mapped (6 insns) */
u32 ieee80211_rfid_locp_recv_reset(void)
{
    /* frame: entry a1,32; 6 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0 */
    /* mem st32: base=(lit:g_ic) off=0x1c4 */
    return opaque_result; /* full dataflow not recovered */
}

/* ieee80211_rfid_locp_recv @ ieee80211_rfid.o 0x00000004 size 28B bind GLOBAL
 * Calls: indirect(a8) | Data refs: g_ic
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 ieee80211_rfid_locp_recv(u32 a2, u32 a3, u32 a4)
{
    /* frame: entry a1,32; 11 insns, 2 cond-branches, 0 loops, 0 jumps */
    /* first predicate: bbci a8, 0, 1e <ieee80211_rfid_locp_recv+0x1a> (condition opaque) */
    /* mem ld8: base=(?) off=4 */
    /* mem ld32: base=(lit:g_ic) off=0x1c4 */
    /* site +0x1b: indirect call via a8 (base *(g_ic+0x1c4)); args: /* no traced args */ */
    opaque_indirect_a8();
    return opaque_result; /* full dataflow not recovered */
}

/* register_ieee80211_rfid_locp_recv_cb @ ieee80211_rfid.o 0x00000004 size 23B bind GLOBAL
 * Calls: none | Data refs: g_ic
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 register_ieee80211_rfid_locp_recv_cb(u32 a2)
{
    /* frame: entry a1,32; 9 insns, 1 cond-branches, 0 loops, 0 jumps */
    /* immediates: -1, 0 */
    /* first predicate: beqz.n a2, 14 <register_ieee80211_rfid_locp_recv_cb+0x10> (condition opaque) */
    /* mem st32: base=(lit:g_ic) off=0x1c4 */
    return 0;
}

/* unregister_ieee80211_rfid_locp_recv_cb @ ieee80211_rfid.o 0x00000004 size 16B bind GLOBAL
 * Calls: none | Data refs: g_ic
 * Fidelity: high - straight-line, fully mapped (6 insns) */
u32 unregister_ieee80211_rfid_locp_recv_cb(void)
{
    /* frame: entry a1,32; 6 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0 */
    /* mem st32: base=(lit:g_ic) off=0x1c4 */
    return opaque_result; /* full dataflow not recovered */
}
