/* ieee80211_ie_vendor.o - reconstructed control-path C (offline, from objdump -d -r).
 * 8 code sections recovered. Fidelity per function below.
 * Conventions: args a2..a7 (Xtensa windowed ABI); outgoing call args
 * traced as a10..; u32 used for pointers/regs; opaque_* marks unrecovered.
 */
#include <stdint.h>
typedef unsigned char u8; typedef unsigned short u16; typedef unsigned int u32;
static u32 opaque_result, last_call_result;
/* ---- externals (U symbols + literal refs) ---- */
extern u32 g_espnow_user_oui; /* g_espnow_user_oui */
extern u32 g_mesh_init_ps_type; /* g_mesh_init_ps_type */
extern u32 memcpy(); /* memcpy */

/* ROLE: vendor-IE builders (ESP OUI): head/freq-annon/manufacturer/
 * mesh-group/espnow(+head)/simple-pair/ssid appenders. memcpy-based.
 */
/* ---- literal-rooted access patterns (offsets observed; layout NOT confirmed) ----
 * g_espnow_user_oui: u8+0, u8+1, u8+2
 * g_mesh_init_ps_type: u32+0
/* ---- funcdb-v2 cross-check (calls[] vs section relocs; disasm is ground truth) ----
 * confirmed funcdb edges: 5; rejected funcdb-only (no exact reloc in
 * callee section; caller-side .rela.text.<f> prefix-collision artifacts): 0;
 * disasm-only edges kept (static-local callees + funcdb relsec:null gaps): 0;
 */
/* ==== functions of ieee80211_ie_vendor.o ==== */

/* ieee80211_add_ie_vendor_esp_head @ ieee80211_ie_vendor.o 0x00000004 size 58B bind GLOBAL
 * Calls: none | Data refs: g_espnow_user_oui
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 ieee80211_add_ie_vendor_esp_head(u32 a2, u32 a3, u32 a4, u32 a5)
{
    /* frame: entry a1,32; 20 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* immediates: -35 */
    /* mem st8: base=(?) off=0 */
    /* mem st8: base=(?) off=1 */
    /* mem ld8: base=(lit:g_espnow_user_oui) off=0 */
    /* mem ld8: base=(lit:g_espnow_user_oui) off=1 */
    /* mem st8: base=(?) off=2 */
    /* mem ld8: base=(lit:g_espnow_user_oui) off=2 */
    /* mem st8: base=(?) off=5 */
    /* mem st8: base=(?) off=3 */
    /* mem st8: base=(?) off=4 */
    /* mem st8: base=(?) off=6 */
    return opaque_result; /* full dataflow not recovered */
}

/* ieee80211_add_ie_vendor_esp_now_head @ ieee80211_ie_vendor.o 0x00000004 size 70B bind GLOBAL
 * Calls: none | Data refs: g_espnow_user_oui
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 ieee80211_add_ie_vendor_esp_now_head(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6)
{
    /* frame: entry a1,32; 24 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* immediates: -35 */
    /* mem st8: base=(?) off=0 */
    /* mem st8: base=(?) off=1 */
    /* mem ld8: base=(lit:g_espnow_user_oui) off=0 */
    /* mem ld8: base=(lit:g_espnow_user_oui) off=1 */
    /* mem st8: base=(?) off=2 */
    /* mem ld8: base=(lit:g_espnow_user_oui) off=2 */
    /* mem st8: base=(?) off=5 */
    /* mem st8: base=(?) off=3 */
    /* mem st8: base=(?) off=4 */
    /* mem st8: base=(?) off=6 */
    return opaque_result; /* full dataflow not recovered */
}

/* ieee80211_add_ie_vendor_esp_mesh_group @ ieee80211_ie_vendor.o 0x00000008 size 76B bind GLOBAL
 * Calls: memcpy | Data refs: g_espnow_user_oui
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 ieee80211_add_ie_vendor_esp_mesh_group(u32 a2, u32 a3, u32 a4)
{
    /* frame: entry a1,32; 28 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* immediates: -35, 12, 6, 2, 1 */
    /* mem st8: base=(?) off=0 */
    /* mem st8: base=(?) off=1 */
    /* mem ld8: base=(lit:g_espnow_user_oui) off=0 */
    /* mem ld8: base=(lit:g_espnow_user_oui) off=1 */
    /* mem st8: base=(?) off=2 */
    /* mem ld8: base=(lit:g_espnow_user_oui) off=2 */
    /* mem st8: base=(?) off=4 */
    /* mem st8: base=(?) off=5 */
    /* mem st8: base=(?) off=3 */
    /* mem st8: base=(?) off=6 */
    /* ... +1 more memops */
    /* site +0x4d: memcpy((?+8), ?, 6) */
    memcpy((?+8), ?, 6);
    return opaque_result; /* full dataflow not recovered */
}

/* ieee80211_add_ie_vendor_esp_simple_pair @ ieee80211_ie_vendor.o 0x00000008 size 90B bind GLOBAL
 * Calls: memcpy | Data refs: g_espnow_user_oui
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 ieee80211_add_ie_vendor_esp_simple_pair(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7)
{
    /* frame: entry a1,32; 33 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* immediates: -35, 5, 1 */
    /* mem ld8: base=(?) off=32 */
    /* mem st8: base=(?) off=0 */
    /* mem st8: base=(?) off=1 */
    /* mem ld8: base=(lit:g_espnow_user_oui) off=0 */
    /* mem ld8: base=(lit:g_espnow_user_oui) off=1 */
    /* mem st8: base=(?) off=2 */
    /* mem ld8: base=(lit:g_espnow_user_oui) off=2 */
    /* mem st8: base=(?) off=4 */
    /* mem st8: base=(?) off=5 */
    /* mem st8: base=(?) off=3 */
    /* ... +5 more memops */
    /* site +0x5b: memcpy((?+11), ?, *(?+32)) */
    memcpy((?+11), ?, *(?+32));
    return opaque_result; /* full dataflow not recovered */
}

/* ieee80211_add_ie_vendor_esp_freq_annon @ ieee80211_ie_vendor.o 0x00000004 size 76B bind GLOBAL
 * Calls: none | Data refs: g_espnow_user_oui
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 ieee80211_add_ie_vendor_esp_freq_annon(u32 a2, u32 a3, u32 a4, u32 a5)
{
    /* frame: entry a1,32; 27 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* immediates: -35, 9, 3, 1 */
    /* mem st8: base=(?) off=0 */
    /* mem st8: base=(?) off=1 */
    /* mem ld8: base=(lit:g_espnow_user_oui) off=0 */
    /* mem ld8: base=(lit:g_espnow_user_oui) off=1 */
    /* mem st8: base=(?) off=2 */
    /* mem ld8: base=(lit:g_espnow_user_oui) off=2 */
    /* mem st8: base=(?) off=4 */
    /* mem st8: base=(?) off=5 */
    /* mem st8: base=(?) off=9 */
    /* mem st8: base=(?) off=3 */
    /* ... +4 more memops */
    return opaque_result; /* full dataflow not recovered */
}

/* ieee80211_add_ie_vendor_esp_now @ ieee80211_ie_vendor.o 0x00000008 size 111B bind GLOBAL
 * Calls: memcpy | Data refs: g_espnow_user_oui
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 ieee80211_add_ie_vendor_esp_now(u32 a2, u32 a3, u32 a4, u32 a5)
{
    /* frame: entry a1,32; 41 insns, 2 cond-branches, 0 loops, 0 jumps */
    /* immediates: 250, -35, 4, 1, 0, 2 */
    /* first predicate: blt a5, a4, 49 <ieee80211_add_ie_vendor_esp_now+0x41> (condition opaque) */
    /* mem st8: base=(?) off=0 */
    /* mem st8: base=(?) off=1 */
    /* mem ld8: base=(lit:g_espnow_user_oui) off=0 */
    /* mem ld8: base=(lit:g_espnow_user_oui) off=1 */
    /* mem st8: base=(?) off=2 */
    /* mem ld8: base=(lit:g_espnow_user_oui) off=2 */
    /* mem st8: base=(?) off=4 */
    /* mem st8: base=(?) off=5 */
    /* mem st8: base=(?) off=3 */
    /* mem st8: base=(?) off=6 */
    /* site +0x63: memcpy((?+7)) */
    memcpy((?+7));
    return opaque_result; /* full dataflow not recovered */
}

/* ieee80211_add_ie_vendor_esp_ssid @ ieee80211_ie_vendor.o 0x0000000c size 96B bind GLOBAL
 * Calls: memcpy | Data refs: g_mesh_init_ps_type, g_espnow_user_oui
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 ieee80211_add_ie_vendor_esp_ssid(u32 a2, u32 a3, u32 a4)
{
    /* frame: entry a1,32; 36 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* immediates: 1, 2, -35, 0, 6 */
    /* mem ld32: base=(lit:g_mesh_init_ps_type) off=0 */
    /* mem st8: base=(?) off=0 */
    /* mem st8: base=(?) off=1 */
    /* mem ld8: base=(lit:g_espnow_user_oui) off=0 */
    /* mem ld8: base=(lit:g_espnow_user_oui) off=1 */
    /* mem st8: base=(?) off=2 */
    /* mem ld8: base=(lit:g_espnow_user_oui) off=2 */
    /* mem st8: base=(?) off=6 */
    /* mem st8: base=(?) off=4 */
    /* mem st8: base=(?) off=3 */
    /* ... +3 more memops */
    /* site +0x63: memcpy((?+9)) */
    memcpy((?+9));
    return opaque_result; /* full dataflow not recovered */
}

/* ieee80211_add_ie_vendor_esp_manufacturer @ ieee80211_ie_vendor.o 0x00000008 size 107B bind GLOBAL
 * Calls: memcpy | Data refs: g_espnow_user_oui
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 ieee80211_add_ie_vendor_esp_manufacturer(u32 a2, u32 a3, u32 a4, u32 a5)
{
    /* frame: entry a1,32; 39 insns, 2 cond-branches, 0 loops, 0 jumps */
    /* immediates: -35, 1 */
    /* first predicate: beqz.n a5, 6d <ieee80211_add_ie_vendor_esp_manufacturer+0x65> (condition opaque) */
    /* mem st8: base=(?) off=1 */
    /* mem st8: base=(?) off=0 */
    /* mem ld8: base=(lit:g_espnow_user_oui) off=0 */
    /* mem ld8: base=(lit:g_espnow_user_oui) off=1 */
    /* mem st8: base=(?) off=2 */
    /* mem ld8: base=(lit:g_espnow_user_oui) off=2 */
    /* mem st8: base=(?) off=4 */
    /* mem st8: base=(?) off=3 */
    /* mem st8: base=(?) off=5 */
    /* mem st8: base=(?) off=6 */
    /* ... +6 more memops */
    /* site +0x6a: memcpy((?+10), ?, ?, *(g_espnow_user_oui+0)) */
    memcpy((?+10), ?, ?, *(g_espnow_user_oui+0));
    return opaque_result; /* full dataflow not recovered */
}
