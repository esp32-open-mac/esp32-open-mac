/* ieee80211.o - reconstructed control-path C (offline, from objdump -d -r).
 * 30 code sections recovered. Fidelity per function below.
 * Conventions: args a2..a7 (Xtensa windowed ABI); outgoing call args
 * traced as a10..; u32 used for pointers/regs; opaque_* marks unrecovered.
 */
#include <stdint.h>
typedef unsigned char u8; typedef unsigned short u16; typedef unsigned int u32;
static u32 opaque_result, last_call_result;
/* ---- externals (U symbols + literal refs) ---- */
extern u32 rodata_band2str_str1_1; /* .rodata.band2str.str1.1 */
extern u32 rodata_ieee80211_send_sa_query_str1_1; /* .rodata.ieee80211_send_sa_query.str1.1 */
extern u32 rodata_wifi_create_nan_str1_1; /* .rodata.wifi_create_nan.str1.1 */
extern u32 rodata_wifi_mode_set; /* .rodata.wifi_mode_set */
extern u32 rodata_wlog_error_7; /* .rodata_wlog_error.7 */
extern u32 rodata_wlog_info_3; /* .rodata_wlog_info.3 */
extern u32 rodata_wlog_info_4; /* .rodata_wlog_info.4 */
extern u32 rodata_wlog_info_5; /* .rodata_wlog_info.5 */
extern u32 rodata_wlog_info_6; /* .rodata_wlog_info.6 */
extern u32 rodata_wlog_info_8; /* .rodata_wlog_info.8 */
extern u32 rodata_wlog_info_9; /* .rodata_wlog_info.9 */
extern u32 rodata_wlog_warning_10; /* .rodata_wlog_warning.10 */
extern u32 rodata_wlog_warning_2; /* .rodata_wlog_warning.2 */
extern u32 text_ieee80211_recv_sa_query_req; /* .text.ieee80211_recv_sa_query_req */
extern u32 text_ieee80211_recv_sa_query_resp; /* .text.ieee80211_recv_sa_query_resp */
extern u32 text_ieee80211_send_sa_query_req; /* .text.ieee80211_send_sa_query_req */
extern u32 text_ieee80211_send_sa_query_resp; /* .text.ieee80211_send_sa_query_resp */
extern u32 ap_rx_cb; /* ap_rx_cb */
extern u32 chm_get_current_band(); /* chm_get_current_band */
extern u32 cnx_clear_blacklist(); /* cnx_clear_blacklist */
extern u32 cnx_remove_all_rc(); /* cnx_remove_all_rc */
extern u32 g_ic; /* g_ic */
extern u32 g_ic_0xa0; /* g_ic+0xa0 */
extern u32 g_osi_funcs_p; /* g_osi_funcs_p */
extern u32 g_wifi_global_lock; /* g_wifi_global_lock */
extern u32 g_wifi_nvs; /* g_wifi_nvs */
extern u32 hostap_del_mac_info_from_list(); /* hostap_del_mac_info_from_list */
extern u32 hostap_query_mac_in_list(); /* hostap_query_mac_in_list */
extern u32 ic_ebuf_recycle_rx(); /* ic_ebuf_recycle_rx */
extern u32 ic_register_michael_mic_failure_cb(); /* ic_register_michael_mic_failure_cb */
extern u32 ic_register_rx_cb(); /* ic_register_rx_cb */
extern u32 ic_register_tx_cb(); /* ic_register_tx_cb */
extern u32 ic_set_interface(); /* ic_set_interface */
extern u32 ieee80211_action_vendor_spec_attach(); /* ieee80211_action_vendor_spec_attach */
extern u32 ieee80211_crypto_attach(); /* ieee80211_crypto_attach */
extern u32 ieee80211_free_beacon_eb(); /* ieee80211_free_beacon_eb */
extern u32 ieee80211_freedom_inside_cb; /* ieee80211_freedom_inside_cb */
extern u32 ieee80211_get_robustmgtframe(); /* ieee80211_get_robustmgtframe */
extern u32 ieee80211_ht_attach(); /* ieee80211_ht_attach */
extern u32 ieee80211_ht_deattach(); /* ieee80211_ht_deattach */
extern u32 ieee80211_mgmt_output(); /* ieee80211_mgmt_output */
extern u32 ieee80211_phy_deinit(); /* ieee80211_phy_deinit */
extern u32 ieee80211_phy_init(); /* ieee80211_phy_init */
extern u32 ieee80211_proto_attach(); /* ieee80211_proto_attach */
extern u32 ieee80211_recv_action_register(); /* ieee80211_recv_action_register */
extern u32 ieee80211_rfid_locp_recv_reset(); /* ieee80211_rfid_locp_recv_reset */
extern u32 ieee80211_scan_attach(); /* ieee80211_scan_attach */
extern u32 ieee80211_scan_deattach(); /* ieee80211_scan_deattach */
extern u32 ieee80211_send_action(); /* ieee80211_send_action */
extern u32 ieee80211_send_action_register(); /* ieee80211_send_action_register */
extern u32 ieee80211_set_tx_desc(); /* ieee80211_set_tx_desc */
extern u32 memcmp(); /* memcmp */
extern u32 memcpy(); /* memcpy */
extern u32 memset(); /* memset */
extern u32 nan_rx_cb; /* nan_rx_cb */
extern u32 net80211_funcs; /* net80211_funcs */
extern u32 pp_unregister_tx_cb(); /* pp_unregister_tx_cb */
extern u32 sta_michael_mic_failure; /* sta_michael_mic_failure */
extern u32 sta_rx_cb; /* sta_rx_cb */
extern u32 wifi_log(); /* wifi_log */

/* ROLE: net80211 core attach/detach: ieee80211_ifattach/ifdetach,
 * wifi_create_sta/softap / wifi_destroy_*, wifi_mode_set, PMF setup,
 * element finders (ieee80211_find_ie/elem*), freedom (sniffer) hooks.
 */
/* ---- literal-rooted access patterns (offsets observed; layout NOT confirmed) ----
 * .rodata.wifi_mode_set: u32+0
 * .rodata_wlog_info.9: u32+0, u32+0
 * ?: u8+0, u32+4, u32+44, u8+44
 * g_ic: u32+0, u32+0, u32+16, u32+16, u32+20, u32+20, u32+448, u32+672, u32+0x2a0
 * g_osi_funcs_p: u32+0, u32+0
 * g_wifi_global_lock: u32+0
 * g_wifi_nvs: u32+0, u8+0
 * net80211_funcs: u32+0, u32+0
 * ret@45: u32+44
/* ---- funcdb-v2 cross-check (calls[] vs section relocs; disasm is ground truth) ----
 * confirmed funcdb edges: 60; rejected funcdb-only (no exact reloc in
 * callee section; caller-side .rela.text.<f> prefix-collision artifacts): 0;
 * disasm-only edges kept (static-local callees + funcdb relsec:null gaps): 15;
 */
/* ==== functions of ieee80211.o ==== */

/* ieee80211_send_sa_query @ ieee80211.o 0x00000024 size 199B bind LOCAL
 * Calls: ieee80211_get_robustmgtframe, wifi_log, ieee80211_set_tx_desc, ieee80211_mgmt_output, wifi_log | Data refs: .rodata.ieee80211_send_sa_query.str1.1, .rodata_wlog_error.7, .rodata_wlog_info.8
 * Fidelity: low - 65 insns, 3 branches, 0 loops; skeleton only */
u32 ieee80211_send_sa_query(u32 a2, u32 a3, u32 a4)
{
    /* frame: entry a1,48; 65 insns, 3 cond-branches, 0 loops, 1 jumps */
    /* immediates: 4, 24, 1, 64, 0, 7, 8, 208, 3 */
    /* first predicate: bnez.n a10, 4d <.text.ieee80211_send_sa_query+0x4d> (condition opaque) */
    /* mem ld32: base=(ret@45) off=44 */
    /* mem ld32: base=(*(ret@45+44)) off=0 */
    /* mem st32: base=(*(ret@45+44)) off=0 */
    /* mem st16: base=(ret@32) off=20 */
    /* mem ld32: base=(?) off=0 */
    /* mem st8: base=(*(?+0)) off=2 */
    /* mem st8: base=(*(?+0)) off=3 */
    /* mem st8: base=(*(?+0)) off=0 */
    /* mem st8: base=(*(?+0)) off=1 */
    /* mem st16: base=(ret@32) off=22 */
    /* ... +3 more memops */
    /* site +0x32: ieee80211_get_robustmgtframe(?, 24, 4) */
    ieee80211_get_robustmgtframe(?, 24, 4);
    /* site +0x45: wifi_log(1, 64, 1, lit:.rodata.ieee80211_send_sa_query.str1.1) */
    wifi_log(1, 64, 1, lit:.rodata.ieee80211_send_sa_query.str1.1);
    /* site +0x8b: ieee80211_set_tx_desc(1, ret@32, 7, 0, 0) */
    ieee80211_set_tx_desc(1, ret@32, 7, 0, 0);
    /* site +0x99: ieee80211_mgmt_output(1, ret@32, 208, 0, 0) */
    ieee80211_mgmt_output(1, ret@32, 208, 0, 0);
    /* site +0xc2: wifi_log(1, 64, 3, lit:.rodata.ieee80211_send_sa_query.str1.1, lit:.rodata.ieee80211_send_sa_query.str1.1) */
    wifi_log(1, 64, 3, lit:.rodata.ieee80211_send_sa_query.str1.1, lit:.rodata.ieee80211_send_sa_query.str1.1);
    return last_call_result; /* opaque */
}

/* ieee80211_send_sa_query_resp @ ieee80211.o 0x00000004 size 40B bind LOCAL
 * Calls: ieee80211_send_sa_query | Data refs: none
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 ieee80211_send_sa_query_resp(u32 a2, u32 a5)
{
    /* frame: entry a1,32; 14 insns, 2 cond-branches, 0 loops, 0 jumps */
    /* immediates: -1, 1 */
    /* first predicate: beqz.n a9, 26 <.text.ieee80211_send_sa_query_resp+0x26> (condition opaque) */
    /* mem ld8: base=((?+131072)) off=251 */
    /* mem ld32: base=(?) off=12 */
    /* mem ld16: base=(?) off=0 */
    /* site +0x21: ieee80211_send_sa_query(?, 1, *(?+0)) */
    ieee80211_send_sa_query(?, 1, *(?+0));
    return last_call_result; /* opaque */
}

/* ieee80211_send_sa_query_req @ ieee80211.o 0x00000004 size 40B bind LOCAL
 * Calls: ieee80211_send_sa_query | Data refs: none
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 ieee80211_send_sa_query_req(u32 a2, u32 a5)
{
    /* frame: entry a1,32; 14 insns, 2 cond-branches, 0 loops, 0 jumps */
    /* immediates: -1, 0 */
    /* first predicate: beqz.n a9, 26 <.text.ieee80211_send_sa_query_req+0x26> (condition opaque) */
    /* mem ld8: base=((?+131072)) off=251 */
    /* mem ld32: base=(?) off=12 */
    /* mem ld16: base=(?) off=0 */
    /* site +0x21: ieee80211_send_sa_query(?, 0, *(?+0)) */
    ieee80211_send_sa_query(?, 0, *(?+0));
    return last_call_result; /* opaque */
}

/* ieee80211_recv_sa_query_req @ ieee80211.o 0x00000004 size 40B bind LOCAL
 * Calls: ieee80211_send_action | Data refs: none
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 ieee80211_recv_sa_query_req(u32 a2, u32 a4)
{
    /* frame: entry a1,32; 15 insns, 2 cond-branches, 0 loops, 0 jumps */
    /* immediates: -1, 1, 8 */
    /* first predicate: beqz.n a9, 26 <.text.ieee80211_recv_sa_query_req+0x26> (condition opaque) */
    /* mem ld8: base=((?+131072)) off=251 */
    /* mem ld32: base=(?) off=12 */
    /* site +0x21: ieee80211_send_action(?, 8, 1, (?+2)) */
    ieee80211_send_action(?, 8, 1, (?+2));
    return last_call_result; /* opaque */
}

/* ieee80211_recv_sa_query_resp @ ieee80211.o 0x0000001c size 258B bind LOCAL
 * Calls: wifi_log, indirect(a8), indirect(a8), indirect(a8), indirect(a4), wifi_log, hostap_query_mac_in_list, hostap_del_mac_info_from_list | Data refs: .rodata_wlog_info.9, g_osi_funcs_p, .rodata_wlog_warning.10
 * Fidelity: low - 87 insns, 6 branches, 0 loops; skeleton only */
u32 ieee80211_recv_sa_query_resp(u32 a2, u32 a4)
{
    /* frame: entry a1,64; 87 insns, 6 cond-branches, 0 loops, 3 jumps */
    /* immediates: -1, 0, 3, 64, 1, 0x304, 0x318, 2 */
    /* first predicate: beqz a8, 100 <.text.ieee80211_recv_sa_query_resp+0x100> (condition opaque) */
    /* mem ld8: base=((?+131072)) off=251 */
    /* mem ld32: base=(?) off=12 */
    /* mem ld8: base=((?+131072)) off=252 */
    /* mem ld8: base=(?) off=3 */
    /* mem ld8: base=(?) off=2 */
    /* mem ld32: base=(?) off=0x300 */
    /* mem ld16: base=((?+131072)) off=254 */
    /* mem ld32: base=(lit:.rodata_wlog_info.9) off=0 */
    /* mem ld32: base=(*(.rodata_wlog_info.9+0)) off=236 */
    /* mem ld32: base=(lit:.rodata_wlog_info.9) off=0 */
    /* ... +19 more memops */
    /* site +0x69: wifi_log(1, 64, 3, lit:.rodata_wlog_info.9, (*(?+3) slli 8)) */
    wifi_log(1, 64, 3, lit:.rodata_wlog_info.9, (*(?+3) slli 8));
    /* site +0x7b: indirect call via a8 (base *(*(.rodata_wlog_info.9+0)+236)); args: 0x304, 64, 3, lit:.rodata_wlog_info.9, (*(?+3) slli 8) */
    opaque_indirect_a8();
    /* site +0x8d: indirect call via a8 (base *(*(.rodata_wlog_info.9+0)+240)); args: 0x304, 64, 3, lit:.rodata_wlog_info.9, (*(?+3) slli 8) */
    opaque_indirect_a8();
    /* site +0x97: indirect call via a8 (base *(*(.rodata_wlog_info.9+0)+236)); args: 0x318, 64, 3, lit:.rodata_wlog_info.9, (*(?+3) slli 8) */
    opaque_indirect_a8();
    /* site +0xa2: indirect call via a4 (base *(.rodata_wlog_info.9+240)); args: 0x318, 64, 3, lit:.rodata_wlog_info.9, (*(?+3) slli 8) */
    opaque_indirect_a4();
    /* site +0xd5: wifi_log(1, 64, 2, lit:.rodata_wlog_info.9, *((?+4)+0)) */
    wifi_log(1, 64, 2, lit:.rodata_wlog_info.9, *((?+4)+0));
    /* site +0xed: hostap_query_mac_in_list((?+4), 1, 2, lit:.rodata_wlog_info.9, *((?+4)+0)) */
    hostap_query_mac_in_list((?+4), 1, 2, lit:.rodata_wlog_info.9, *((?+4)+0));
    /* site +0xfd: hostap_del_mac_info_from_list((?+4), 1, 2, lit:.rodata_wlog_info.9, *((?+4)+0)) */
    hostap_del_mac_info_from_list((?+4), 1, 2, lit:.rodata_wlog_info.9, *((?+4)+0));
    return opaque_result; /* full dataflow not recovered */
}

/* band2str @ ieee80211.o 0x00000014 size 38B bind GLOBAL
 * Calls: wifi_log | Data refs: .rodata.band2str.str1.1, .rodata_wlog_warning.2
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 band2str(u32 a2)
{
    /* frame: entry a1,32; 14 insns, 2 cond-branches, 0 loops, 0 jumps */
    /* immediates: 2, 4, 1 */
    /* first predicate: beqi a14, 1, 38 <band2str+0x24> (condition opaque) */
    /* site +0x32: wifi_log(1, 4, 2, lit:.rodata_wlog_warning.2) */
    wifi_log(1, 4, 2, lit:.rodata_wlog_warning.2);
    return opaque_result; /* full dataflow not recovered */
}

/* ieee80211_rate_ref_init @ ieee80211.o 0x00000004 size 30B bind GLOBAL
 * Calls: none | Data refs: g_ic
 * Fidelity: high - straight-line, fully mapped (11 insns) */
u32 ieee80211_rate_ref_init(void)
{
    /* frame: entry a1,32; 11 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* immediates: 1, 0 */
    /* mem st8: base=((lit:g_ic+65536)) off=213 */
    /* mem st8: base=((lit:g_ic+65536)) off=214 */
    /* mem st8: base=((lit:g_ic+65536)) off=216 */
    return opaque_result; /* full dataflow not recovered */
}

/* ieee80211_get_tx_info_from_eb @ ieee80211.o 0x00000000 size 69B bind GLOBAL
 * Calls: none | Data refs: none
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 ieee80211_get_tx_info_from_eb(u32 a2, u32 a3)
{
    /* frame: entry a1,32; 29 insns, 1 cond-branches, 0 loops, 0 jumps */
    /* immediates: 1, 0 */
    /* first predicate: bbci a2, 18, 38 <ieee80211_get_tx_info_from_eb+0x38> (condition opaque) */
    /* mem ld32: base=(?) off=44 */
    /* mem ld32: base=(*(?+44)) off=16 */
    /* mem st32: base=(?) off=8 */
    /* mem ld16: base=(?) off=22 */
    /* mem st8: base=(?) off=16 */
    /* mem ld32: base=(?) off=4 */
    /* mem ld8: base=(*(?+44)) off=19 */
    /* mem ld32: base=(*(?+4)) off=4 */
    /* mem ld8: base=(*(?+44)) off=12 */
    /* mem st32: base=(?) off=20 */
    /* ... +5 more memops */
    return opaque_result; /* full dataflow not recovered */
}

/* ieee80211_freedom_inside_cb @ ieee80211.o 0x0000000c size 43B bind GLOBAL
 * Calls: memset, ieee80211_get_tx_info_from_eb, indirect(a3) | Data refs: g_ic
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 ieee80211_freedom_inside_cb(u32 a2, u32 a3)
{
    /* frame: entry a1,64; 16 insns, 1 cond-branches, 0 loops, 0 jumps */
    /* immediates: 28, 0 */
    /* first predicate: beqz.n a3, 35 <ieee80211_freedom_inside_cb+0x29> (condition opaque) */
    /* mem ld32: base=(lit:g_ic) off=0x1c0 */
    /* site +0x1a: memset(?, 0, 28) */
    memset(?, 0, 28);
    /* site +0x2d: ieee80211_get_tx_info_from_eb(?, 0, 28) */
    ieee80211_get_tx_info_from_eb(?, 0, 28);
    /* site +0x32: indirect call via a3 (base *(g_ic+0x1c0)); args: ?, 0, 28 */
    opaque_indirect_a3();
    return opaque_result; /* full dataflow not recovered */
}

/* ieee80211_freedom_init @ ieee80211.o 0x0000000c size 27B bind GLOBAL
 * Calls: ic_register_tx_cb | Data refs: g_ic, ieee80211_freedom_inside_cb
 * Fidelity: high - straight-line, fully mapped (10 insns) */
u32 ieee80211_freedom_init(void)
{
    /* frame: entry a1,32; 10 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0, 8 */
    /* mem st32: base=(lit:g_ic) off=0x1c0 */
    /* site +0x22: ic_register_tx_cb(lit:ieee80211_freedom_inside_cb, 8, 0) */
    ic_register_tx_cb(lit:ieee80211_freedom_inside_cb, 8, 0);
    return opaque_result; /* full dataflow not recovered */
}

/* ieee80211_freedom_deinit @ ieee80211.o 0x00000008 size 24B bind GLOBAL
 * Calls: pp_unregister_tx_cb | Data refs: g_ic
 * Fidelity: high - straight-line, fully mapped (9 insns) */
u32 ieee80211_freedom_deinit(void)
{
    /* frame: entry a1,32; 9 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0, 8 */
    /* mem st32: base=(lit:g_ic) off=0x1c0 */
    /* site +0x1b: pp_unregister_tx_cb(8) */
    pp_unregister_tx_cb(8);
    return opaque_result; /* full dataflow not recovered */
}

/* ieee80211_user_ie_init @ ieee80211.o 0x0000000c size 61B bind GLOBAL
 * Calls: memset | Data refs: g_ic, g_ic+0xa0
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 ieee80211_user_ie_init(u32 a3)
{
    /* frame: entry a1,32; 21 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0, 40 */
    /* mem st32: base=(lit:g_ic) off=136 */
    /* mem st32: base=(lit:g_ic) off=140 */
    /* mem st32: base=(lit:g_ic) off=144 */
    /* mem st32: base=(lit:g_ic) off=148 */
    /* mem st32: base=(lit:g_ic) off=152 */
    /* mem st32: base=(lit:g_ic) off=156 */
    /* mem st32: base=(lit:g_ic) off=200 */
    /* mem st32: base=(lit:g_ic) off=204 */
    /* mem st32: base=(lit:g_ic) off=0x2c0 */
    /* mem st32: base=(lit:g_ic) off=0x2c4 */
    /* site +0x35: memset(lit:g_ic+0xa0, ?, 40) */
    memset(lit:g_ic+0xa0, ?, 40);
    return opaque_result; /* full dataflow not recovered */
}

/* ieee80211_ifattach @ ieee80211.o 0x00000034 size 210B bind GLOBAL
 * Calls: ieee80211_phy_init, ieee80211_crypto_attach, ieee80211_proto_attach, ieee80211_phy_init, ieee80211_ht_attach, ieee80211_ht_attach, ieee80211_rate_ref_init, ieee80211_scan_attach, ieee80211_action_vendor_spec_attach, ieee80211_user_ie_init, ieee80211_freedom_init, ieee80211_rfid_locp_recv_reset | Data refs: g_ic
 * Fidelity: low - 75 insns, 8 branches, 0 loops; skeleton only */
u32 ieee80211_ifattach(u32 a3)
{
    /* frame: entry a1,32; 75 insns, 8 cond-branches, 0 loops, 4 jumps */
    /* immediates: 0, 1, 100 */
    /* first predicate: bnez.n a4, 46 <ieee80211_ifattach+0x12> (condition opaque) */
    /* mem ld32: base=(lit:g_ic) off=16 */
    /* mem ld32: base=(lit:g_ic) off=20 */
    /* mem st32: base=(*(g_ic+16)) off=0x158 */
    /* mem ld8: base=((lit:g_ic+131072)) off=176 */
    /* mem st16: base=(lit:g_ic) off=32 */
    /* mem st32: base=(*(g_ic+20)) off=0x158 */
    /* mem ld8: base=((lit:g_ic+131072)) off=174 */
    /* mem ld8: base=((lit:g_ic+131072)) off=176 */
    /* mem ld8: base=((lit:g_ic+131072)) off=174 */
    /* mem st32: base=(lit:g_ic) off=116 */
    /* ... +2 more memops */
    /* site +0x5d: ieee80211_phy_init(?, 1, *((lit:g_ic+131072)+176)) */
    ieee80211_phy_init(?, 1, *((lit:g_ic+131072)+176));
    /* site +0x79: ieee80211_crypto_attach(lit:g_ic, 1, *((lit:g_ic+131072)+176)) */
    ieee80211_crypto_attach(lit:g_ic, 1, *((lit:g_ic+131072)+176));
    /* site +0x81: ieee80211_proto_attach(lit:g_ic, 1, *((lit:g_ic+131072)+176)) */
    ieee80211_proto_attach(lit:g_ic, 1, *((lit:g_ic+131072)+176));
    /* site +0x9e: ieee80211_phy_init(*(g_ic+20), 1, *((lit:g_ic+131072)+174)) */
    ieee80211_phy_init(*(g_ic+20), 1, *((lit:g_ic+131072)+174));
    /* site +0xb6: ieee80211_ht_attach(*(g_ic+16), 1, *((lit:g_ic+131072)+174)) */
    ieee80211_ht_attach(*(g_ic+16), 1, *((lit:g_ic+131072)+174));
    /* site +0xc9: ieee80211_ht_attach(*(g_ic+20), 1, *((lit:g_ic+131072)+174)) */
    ieee80211_ht_attach(*(g_ic+20), 1, *((lit:g_ic+131072)+174));
    /* site +0xcf: ieee80211_rate_ref_init(ret@c9, 1, *((lit:g_ic+131072)+174)) */
    ieee80211_rate_ref_init(ret@c9, 1, *((lit:g_ic+131072)+174));
    /* site +0xd7: ieee80211_scan_attach(lit:g_ic, 1, *((lit:g_ic+131072)+174)) */
    ieee80211_scan_attach(lit:g_ic, 1, *((lit:g_ic+131072)+174));
    /* site +0xdd: ieee80211_action_vendor_spec_attach(ret@d7, 1, *((lit:g_ic+131072)+174)) */
    ieee80211_action_vendor_spec_attach(ret@d7, 1, *((lit:g_ic+131072)+174));
    /* site +0xf1: ieee80211_user_ie_init(ret@dd, 1, *((lit:g_ic+131072)+174)) */
    ieee80211_user_ie_init(ret@dd, 1, *((lit:g_ic+131072)+174));
    /* site +0xf7: ieee80211_freedom_init(ret@f1, 1, *((lit:g_ic+131072)+174)) */
    ieee80211_freedom_init(ret@f1, 1, *((lit:g_ic+131072)+174));
    /* site +0xfd: ieee80211_rfid_locp_recv_reset(ret@f7, 1, *((lit:g_ic+131072)+174)) */
    ieee80211_rfid_locp_recv_reset(ret@f7, 1, *((lit:g_ic+131072)+174));
    return 0;
}

/* ieee80211_ifdetach @ ieee80211.o 0x0000000c size 25B bind GLOBAL
 * Calls: ieee80211_freedom_deinit, ieee80211_scan_deattach, ieee80211_phy_deinit | Data refs: none
 * Fidelity: high - straight-line, fully mapped (9 insns) */
u32 ieee80211_ifdetach(void)
{
    /* frame: entry a1,32; 9 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0 */
    /* site +0x12: ieee80211_freedom_deinit(/* no traced args */) */
    ieee80211_freedom_deinit(/* no traced args */);
    /* site +0x18: ieee80211_scan_deattach(ret@12) */
    ieee80211_scan_deattach(ret@12);
    /* site +0x1e: ieee80211_phy_deinit(ret@18) */
    ieee80211_phy_deinit(ret@18);
    return 0;
}

/* wifi_create_nan @ ieee80211.o 0x0000002c size 252B bind GLOBAL
 * Calls: indirect(a2), indirect(a2), memcpy, ieee80211_phy_init, ieee80211_ht_attach, ic_register_rx_cb, indirect(a5), ic_set_interface | Data refs: g_ic, g_osi_funcs_p, .rodata.wifi_create_nan.str1.1, nan_rx_cb
 * Fidelity: low - 72 insns, 4 branches, 0 loops; skeleton only (weak) */
u32 wifi_create_nan(u32 a4, u32 a5)
{
    /* frame: entry a1,32; 72 insns, 4 cond-branches, 0 loops, 2 jumps */
    /* immediates: 0x250, 0x101, 3, 0x3d0, 6, 1, 2, 0 */
    /* first predicate: bnez a2, ec <wifi_create_nan+0xc0> (condition opaque) */
    /* mem ld32: base=(lit:g_ic) off=0x2a0 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=0x178 */
    /* mem st32: base=(lit:g_ic) off=0x2a0 */
    /* mem st32: base=(ret@43) off=0x14c */
    /* mem st8: base=((ret@43+65536)) off=104 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=0x178 */
    /* mem st32: base=(ret@43) off=0x240 */
    /* mem ld8: base=((ret@43+65536)) off=104 */
    /* ... +11 more memops */
    /* site +0x43: indirect call via a2 (base *(*(g_osi_funcs_p+0)+0x178)); args: 0x250 */
    opaque_indirect_a2();
    /* site +0x6b: indirect call via a2 (base *(*(g_osi_funcs_p+0)+0x178)); args: 0x3d0 */
    opaque_indirect_a2();
    /* site +0x85: memcpy((ret@6b+4), lit:.rodata.wifi_create_nan.str1.1, 6) */
    memcpy((ret@6b+4), lit:.rodata.wifi_create_nan.str1.1, 6);
    /* site +0x92: ieee80211_phy_init(ret@43, 1, *((ret@43+65536)+104)) */
    ieee80211_phy_init(ret@43, 1, *((ret@43+65536)+104));
    /* site +0xa1: ieee80211_ht_attach(ret@92, 1, *((ret@43+65536)+104)) */
    ieee80211_ht_attach(ret@92, 1, *((ret@43+65536)+104));
    /* site +0xcd: ic_register_rx_cb(lit:nan_rx_cb, 2, *((ret@43+65536)+104)) */
    ic_register_rx_cb(lit:nan_rx_cb, 2, *((ret@43+65536)+104));
    /* site +0xdd: indirect call via a5 (base *(g_ic+176)); args: ret@43, 2, *((ret@43+65536)+104) */
    opaque_indirect_a5();
    /* site +0xf5: ic_set_interface(2, *(g_ic+0x2a0), *((ret@43+65536)+104)) */
    ic_set_interface(2, *(g_ic+0x2a0), *((ret@43+65536)+104));
    return 0;
}

/* wifi_destroy_nan @ ieee80211.o 0x00000018 size 102B bind GLOBAL
 * Calls: indirect(a5), indirect(a8), cnx_clear_blacklist, indirect(a6), indirect(a2), ic_register_rx_cb, ic_set_interface | Data refs: g_ic, g_wifi_global_lock, g_osi_funcs_p
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 wifi_destroy_nan(u32 a2, u32 a3, u32 a6)
{
    /* frame: entry a1,32; 36 insns, 1 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0, 2 */
    /* first predicate: beqz a4, 71 <wifi_destroy_nan+0x59> (condition opaque) */
    /* mem ld32: base=(lit:g_ic) off=0x2a0 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(lit:g_wifi_global_lock) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=84 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(lit:g_wifi_global_lock) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=88 */
    /* mem st32: base=(lit:g_ic) off=0x2a0 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_ic+0x2a0)) off=0x240 */
    /* ... +4 more memops */
    /* site +0x33: indirect call via a5 (base *(*(g_osi_funcs_p+0)+84)); args: *(g_wifi_global_lock+0) */
    opaque_indirect_a5();
    /* site +0x45: indirect call via a8 (base *(*(g_osi_funcs_p+0)+88)); args: *(g_wifi_global_lock+0) */
    opaque_indirect_a8();
    /* site +0x4b: cnx_clear_blacklist(ret@45) */
    cnx_clear_blacklist(ret@45);
    /* site +0x57: indirect call via a6 (base *(g_wifi_global_lock+176)); args: *(*(g_ic+0x2a0)+0x240) */
    opaque_indirect_a6();
    /* site +0x63: indirect call via a2 (base *(g_osi_funcs_p+176)); args: ret@57 */
    opaque_indirect_a2();
    /* site +0x6e: ic_register_rx_cb(ret@63, 2) */
    ic_register_rx_cb(ret@63, 2);
    /* site +0x79: ic_set_interface(2, *(g_ic+0x2a0)) */
    ic_set_interface(2, *(g_ic+0x2a0));
    return opaque_result; /* full dataflow not recovered */
}

/* wifi_destroy_softap @ ieee80211.o 0x0000001c size 112B bind GLOBAL
 * Calls: ieee80211_ht_deattach, indirect(a5), indirect(a8), indirect(a6), indirect(a3), ic_register_rx_cb, ic_set_interface, ieee80211_free_beacon_eb | Data refs: g_ic, g_wifi_global_lock, g_osi_funcs_p
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 wifi_destroy_softap(u32 a4, u32 a6)
{
    /* frame: entry a1,32; 42 insns, 2 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0, 1 */
    /* first predicate: beqz a2, 7a <wifi_destroy_softap+0x5e> (condition opaque) */
    /* mem ld32: base=(lit:g_ic) off=20 */
    /* mem ld8: base=((*(g_ic+20)+65536)) off=104 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(lit:g_wifi_global_lock) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=84 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(lit:g_wifi_global_lock) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=88 */
    /* mem st32: base=(lit:g_ic) off=20 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* ... +5 more memops */
    /* site +0x35: ieee80211_ht_deattach(*(g_ic+20)) */
    ieee80211_ht_deattach(*(g_ic+20));
    /* site +0x45: indirect call via a5 (base *(*(g_osi_funcs_p+0)+84)); args: *(g_wifi_global_lock+0) */
    opaque_indirect_a5();
    /* site +0x56: indirect call via a8 (base *(*(g_osi_funcs_p+0)+88)); args: *(g_wifi_global_lock+0) */
    opaque_indirect_a8();
    /* site +0x61: indirect call via a6 (base *(g_wifi_global_lock+176)); args: *(*(g_ic+20)+236) */
    opaque_indirect_a6();
    /* site +0x6d: indirect call via a3 (base *(g_osi_funcs_p+176)); args: ret@61 */
    opaque_indirect_a3();
    /* site +0x77: ic_register_rx_cb(0, 1) */
    ic_register_rx_cb(0, 1);
    /* site +0x81: ic_set_interface(1, *(g_ic+20)) */
    ic_set_interface(1, *(g_ic+20));
    /* site +0x87: ieee80211_free_beacon_eb(ret@81, *(g_ic+20)) */
    ieee80211_free_beacon_eb(ret@81, *(g_ic+20));
    return opaque_result; /* full dataflow not recovered */
}

/* wifi_destroy_sta @ ieee80211.o 0x00000020 size 118B bind GLOBAL
 * Calls: ieee80211_ht_deattach, indirect(a5), indirect(a8), indirect(a6), indirect(a3), cnx_clear_blacklist, cnx_remove_all_rc, ic_register_rx_cb, ic_set_interface | Data refs: g_ic, g_wifi_global_lock, g_osi_funcs_p
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 wifi_destroy_sta(u32 a4, u32 a6)
{
    /* frame: entry a1,32; 44 insns, 2 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0 */
    /* first predicate: beqz a2, 8a <wifi_destroy_sta+0x6a> (condition opaque) */
    /* mem ld32: base=(lit:g_ic) off=16 */
    /* mem ld8: base=((*(g_ic+16)+65536)) off=104 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(lit:g_wifi_global_lock) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=84 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(lit:g_wifi_global_lock) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=88 */
    /* mem st32: base=(lit:g_ic) off=16 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* ... +5 more memops */
    /* site +0x39: ieee80211_ht_deattach(*(g_ic+16)) */
    ieee80211_ht_deattach(*(g_ic+16));
    /* site +0x49: indirect call via a5 (base *(*(g_osi_funcs_p+0)+84)); args: *(g_wifi_global_lock+0) */
    opaque_indirect_a5();
    /* site +0x5a: indirect call via a8 (base *(*(g_osi_funcs_p+0)+88)); args: *(g_wifi_global_lock+0) */
    opaque_indirect_a8();
    /* site +0x65: indirect call via a6 (base *(g_wifi_global_lock+176)); args: *(*(g_ic+16)+232) */
    opaque_indirect_a6();
    /* site +0x71: indirect call via a3 (base *(g_osi_funcs_p+176)); args: ret@65 */
    opaque_indirect_a3();
    /* site +0x77: cnx_clear_blacklist(ret@71) */
    cnx_clear_blacklist(ret@71);
    /* site +0x7d: cnx_remove_all_rc(ret@77) */
    cnx_remove_all_rc(ret@77);
    /* site +0x87: ic_register_rx_cb(0, 0) */
    ic_register_rx_cb(0, 0);
    /* site +0x91: ic_set_interface(0, *(g_ic+16)) */
    ic_set_interface(0, *(g_ic+16));
    return opaque_result; /* full dataflow not recovered */
}

/* wifi_recycle_rx_pkt @ ieee80211.o 0x00000004 size 14B bind GLOBAL
 * Calls: ic_ebuf_recycle_rx | Data refs: none
 * Fidelity: high - straight-line, fully mapped (5 insns) */
u32 wifi_recycle_rx_pkt(u32 a2)
{
    /* frame: entry a1,32; 5 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* site +0xd: ic_ebuf_recycle_rx(/* no traced args */) */
    ic_ebuf_recycle_rx(/* no traced args */);
    return opaque_result; /* full dataflow not recovered */
}

/* ieee80211_find_elem_match @ ieee80211.o 0x00000004 size 76B bind GLOBAL
 * Calls: memcmp | Data refs: none
 * Fidelity: medium - branchy but loop-free, call sequence mapped */
u32 ieee80211_find_elem_match(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7)
{
    /* frame: entry a1,48; 31 insns, 5 cond-branches, 0 loops, 1 jumps */
    /* immediates: 0 */
    /* first predicate: bne a8, a13, 3a <ieee80211_find_elem_match+0x36> (condition opaque) */
    /* mem ld8: base=(?) off=0 */
    /* mem st32: base=(?) off=0 */
    /* mem st32: base=(?) off=4 */
    /* mem st32: base=(?) off=8 */
    /* mem ld32: base=(?) off=0 */
    /* mem ld32: base=(?) off=4 */
    /* mem ld32: base=(?) off=8 */
    /* mem ld8: base=(?) off=1 */
    /* site +0x2e: memcmp(/* no traced args */) */
    memcmp(/* no traced args */);
    return 0;
}

/* ieee80211_find_ie_match @ ieee80211.o 0x00000004 size 31B bind GLOBAL
 * Calls: ieee80211_find_elem_match | Data refs: none
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 ieee80211_find_ie_match(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7)
{
    /* frame: entry a1,32; 13 insns, 1 cond-branches, 0 loops, 0 jumps */
    /* first predicate: beqz.n a7, 19 <ieee80211_find_ie_match+0x15> (condition opaque) */
    /* site +0x1c: ieee80211_find_elem_match(/* no traced args */) */
    ieee80211_find_elem_match(/* no traced args */);
    return last_call_result; /* opaque */
}

/* ieee80211_find_elem @ ieee80211.o 0x00000004 size 26B bind GLOBAL
 * Calls: ieee80211_find_elem_match | Data refs: none
 * Fidelity: high - straight-line, fully mapped (11 insns) */
u32 ieee80211_find_elem(u32 a2, u32 a3, u32 a4)
{
    /* frame: entry a1,32; 11 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0 */
    /* site +0x17: ieee80211_find_elem_match(?, ?, ?, 0, 0) */
    ieee80211_find_elem_match(?, ?, ?, 0, 0);
    return last_call_result; /* opaque */
}

/* ieee80211_find_ext_elem @ ieee80211.o 0x00000004 size 36B bind GLOBAL
 * Calls: ieee80211_find_elem_match | Data refs: none
 * Fidelity: high - straight-line, fully mapped (14 insns) */
u32 ieee80211_find_ext_elem(u32 a2, u32 a3, u32 a4)
{
    /* frame: entry a1,48; 14 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0, 1, 255 */
    /* mem st8: base=(?) off=0 */
    /* site +0x21: ieee80211_find_elem_match(255, ?, ?, ?, 1) */
    ieee80211_find_elem_match(255, ?, ?, ?, 1);
    return last_call_result; /* opaque */
}

/* ieee80211_find_ie @ ieee80211.o 0x00000004 size 20B bind GLOBAL
 * Calls: ieee80211_find_elem | Data refs: none
 * Fidelity: high - straight-line, fully mapped (8 insns) */
u32 ieee80211_find_ie(u32 a2, u32 a3, u32 a4)
{
    /* frame: entry a1,32; 8 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* site +0x11: ieee80211_find_elem(/* no traced args */) */
    ieee80211_find_elem(/* no traced args */);
    return last_call_result; /* opaque */
}

/* ieee80211_find_ext_ie @ ieee80211.o 0x00000004 size 20B bind GLOBAL
 * Calls: ieee80211_find_ext_elem | Data refs: none
 * Fidelity: high - straight-line, fully mapped (8 insns) */
u32 ieee80211_find_ext_ie(u32 a2, u32 a3, u32 a4)
{
    /* frame: entry a1,32; 8 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* site +0x11: ieee80211_find_ext_elem(/* no traced args */) */
    ieee80211_find_ext_elem(/* no traced args */);
    return last_call_result; /* opaque */
}

/* ieee80211_setup_pmf @ ieee80211.o 0x00000020 size 58B bind GLOBAL
 * Calls: ieee80211_recv_action_register, ieee80211_recv_action_register, ieee80211_send_action_register, ieee80211_send_action_register | Data refs: .text.ieee80211_recv_sa_query_req, .text.ieee80211_recv_sa_query_resp, .text.ieee80211_send_sa_query_req, .text.ieee80211_send_sa_query_resp
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 ieee80211_setup_pmf(void)
{
    /* frame: entry a1,32; 22 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0, 8, 1 */
    /* site +0x2d: ieee80211_recv_action_register(8, 0, lit:.text.ieee80211_recv_sa_query_req) */
    ieee80211_recv_action_register(8, 0, lit:.text.ieee80211_recv_sa_query_req);
    /* site +0x3a: ieee80211_recv_action_register(8, 1, lit:.text.ieee80211_recv_sa_query_resp) */
    ieee80211_recv_action_register(8, 1, lit:.text.ieee80211_recv_sa_query_resp);
    /* site +0x47: ieee80211_send_action_register(8, 0, lit:.text.ieee80211_send_sa_query_req) */
    ieee80211_send_action_register(8, 0, lit:.text.ieee80211_send_sa_query_req);
    /* site +0x55: ieee80211_send_action_register(8, 1, lit:.text.ieee80211_send_sa_query_resp) */
    ieee80211_send_action_register(8, 1, lit:.text.ieee80211_send_sa_query_resp);
    return opaque_result; /* full dataflow not recovered */
}

/* wifi_create_softap @ ieee80211.o 0x00000030 size 250B bind GLOBAL
 * Calls: indirect(a2), indirect(a7), chm_get_current_band, memcpy, ieee80211_phy_init, ieee80211_ht_attach, ic_register_rx_cb, ieee80211_setup_pmf, indirect(a5), ic_set_interface | Data refs: g_ic, g_osi_funcs_p, g_wifi_nvs, .rodata.wifi_create_nan.str1.1, ap_rx_cb
 * Fidelity: low - 89 insns, 5 branches, 0 loops; skeleton only */
u32 wifi_create_softap(u32 a4, u32 a5, u32 a6)
{
    /* frame: entry a1,32; 89 insns, 5 cond-branches, 0 loops, 3 jumps */
    /* immediates: 0x250, 0x101, 1, 0x3d0, 6, 0 */
    /* first predicate: bnez a2, 11c <wifi_create_softap+0xec> (condition opaque) */
    /* mem ld32: base=(lit:g_ic) off=20 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=0x178 */
    /* mem ld32: base=(lit:g_wifi_nvs) off=0 */
    /* mem st32: base=(ret@47) off=0x14c */
    /* mem ld8: base=((*(g_wifi_nvs+0)+196608)) off=250 */
    /* mem st8: base=((lit:g_ic+131072)) off=174 */
    /* mem st8: base=((ret@47+65536)) off=104 */
    /* mem ld16: base=((*(g_wifi_nvs+0)+327680)) off=66 */
    /* mem st16: base=((ret@47+131072)) off=58 */
    /* ... +16 more memops */
    /* site +0x47: indirect call via a2 (base *(*(g_osi_funcs_p+0)+0x178)); args: 0x250 */
    opaque_indirect_a2();
    /* site +0x8d: indirect call via a7 (base *(*(g_osi_funcs_p+0)+0x178)); args: 0x3d0 */
    opaque_indirect_a7();
    /* site +0x99: chm_get_current_band(ret@8d) */
    chm_get_current_band(ret@8d);
    /* site +0xcd: memcpy((*(ret@47+236)+4), lit:.rodata.wifi_create_nan.str1.1, 6) */
    memcpy((*(ret@47+236)+4), lit:.rodata.wifi_create_nan.str1.1, 6);
    /* site +0xe2: ieee80211_phy_init(ret@47, lit:.rodata.wifi_create_nan.str1.1, *((lit:g_ic+131072)+175)) */
    ieee80211_phy_init(ret@47, lit:.rodata.wifi_create_nan.str1.1, *((lit:g_ic+131072)+175));
    /* site +0xee: ieee80211_ht_attach(ret@e2, lit:.rodata.wifi_create_nan.str1.1, *((lit:g_ic+131072)+175)) */
    ieee80211_ht_attach(ret@e2, lit:.rodata.wifi_create_nan.str1.1, *((lit:g_ic+131072)+175));
    /* site +0xf9: ic_register_rx_cb(lit:ap_rx_cb, 1, *((lit:g_ic+131072)+175)) */
    ic_register_rx_cb(lit:ap_rx_cb, 1, *((lit:g_ic+131072)+175));
    /* site +0xff: ieee80211_setup_pmf(ret@f9, 1, *((lit:g_ic+131072)+175)) */
    ieee80211_setup_pmf(ret@f9, 1, *((lit:g_ic+131072)+175));
    /* site +0x10d: indirect call via a5 (base *(g_osi_funcs_p+176)); args: ret@47, 1, *((lit:g_ic+131072)+175) */
    opaque_indirect_a5();
    /* site +0x123: ic_set_interface(1, *(g_ic+20), *((lit:g_ic+131072)+175)) */
    ic_set_interface(1, *(g_ic+20), *((lit:g_ic+131072)+175));
    return 0;
}

/* wifi_create_sta @ ieee80211.o 0x00000038 size 254B bind GLOBAL
 * Calls: indirect(a2), indirect(a7), chm_get_current_band, memcpy, ieee80211_phy_init, ieee80211_ht_attach, ic_register_rx_cb, ic_register_michael_mic_failure_cb, ieee80211_setup_pmf, indirect(a5), ic_set_interface | Data refs: g_ic, g_osi_funcs_p, g_wifi_nvs, .rodata.wifi_create_nan.str1.1, sta_rx_cb, sta_michael_mic_failure
 * Fidelity: low - 90 insns, 5 branches, 0 loops; skeleton only */
u32 wifi_create_sta(u32 a4, u32 a5)
{
    /* frame: entry a1,32; 90 insns, 5 cond-branches, 0 loops, 3 jumps */
    /* immediates: 0x250, 0x101, 0x3d0, 6, 0 */
    /* first predicate: bnez a6, 128 <wifi_create_sta+0xf0> (condition opaque) */
    /* mem ld32: base=(lit:g_ic) off=16 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=0x178 */
    /* mem st32: base=(ret@4e) off=0x14c */
    /* mem st32: base=(ret@4e) off=152 */
    /* mem ld32: base=(lit:g_wifi_nvs) off=0 */
    /* mem ld8: base=(*(g_wifi_nvs+0)) off=156 */
    /* mem st8: base=((lit:g_ic+131072)) off=176 */
    /* mem st8: base=((ret@4e+65536)) off=104 */
    /* mem ld16: base=((*(g_wifi_nvs+0)+262144)) off=166 */
    /* ... +17 more memops */
    /* site +0x4e: indirect call via a2 (base *(*(g_osi_funcs_p+0)+0x178)); args: 0x250 */
    opaque_indirect_a2();
    /* site +0x92: indirect call via a7 (base *(*(g_osi_funcs_p+0)+0x178)); args: 0x3d0 */
    opaque_indirect_a7();
    /* site +0x9e: chm_get_current_band(ret@92) */
    chm_get_current_band(ret@92);
    /* site +0xd1: memcpy((*(ret@4e+232)+4), lit:.rodata.wifi_create_nan.str1.1, 6) */
    memcpy((*(ret@4e+232)+4), lit:.rodata.wifi_create_nan.str1.1, 6);
    /* site +0xde: ieee80211_phy_init(ret@4e, lit:.rodata.wifi_create_nan.str1.1, *((lit:g_ic+131072)+177)) */
    ieee80211_phy_init(ret@4e, lit:.rodata.wifi_create_nan.str1.1, *((lit:g_ic+131072)+177));
    /* site +0xf2: ieee80211_ht_attach(ret@de, lit:.rodata.wifi_create_nan.str1.1, *((lit:g_ic+131072)+177)) */
    ieee80211_ht_attach(ret@de, lit:.rodata.wifi_create_nan.str1.1, *((lit:g_ic+131072)+177));
    /* site +0xfd: ic_register_rx_cb(lit:sta_rx_cb, 0, *((lit:g_ic+131072)+177)) */
    ic_register_rx_cb(lit:sta_rx_cb, 0, *((lit:g_ic+131072)+177));
    /* site +0x106: ic_register_michael_mic_failure_cb(lit:sta_michael_mic_failure, 0, *((lit:g_ic+131072)+177)) */
    ic_register_michael_mic_failure_cb(lit:sta_michael_mic_failure, 0, *((lit:g_ic+131072)+177));
    /* site +0x10c: ieee80211_setup_pmf(ret@106, 0, *((lit:g_ic+131072)+177)) */
    ieee80211_setup_pmf(ret@106, 0, *((lit:g_ic+131072)+177));
    /* site +0x119: indirect call via a5 (base *(g_osi_funcs_p+176)); args: ret@4e, 0, *((lit:g_ic+131072)+177) */
    opaque_indirect_a5();
    /* site +0x12f: ic_set_interface(0, *(g_ic+16), *((lit:g_ic+131072)+177)) */
    ic_set_interface(0, *(g_ic+16), *((lit:g_ic+131072)+177));
    return 0;
}

/* wifi_mode_set @ ieee80211.o 0x0000004c size 379B bind GLOBAL
 * Calls: wifi_log, wifi_destroy_sta, indirect(a2), wifi_destroy_nan, wifi_create_sta, wifi_destroy_nan, indirect(a2), indirect(a10), wifi_destroy_nan, wifi_destroy_sta, wifi_log, wifi_create_nan, wifi_destroy_sta, indirect(a3), wifi_log, wifi_log | Data refs: .rodata.wifi_mode_set, .rodata_wlog_info.3, net80211_funcs, g_ic, .rodata_wlog_info.5, .rodata_wlog_info.4, .rodata_wlog_info.6
 * Fidelity: low - 139 insns, 12 branches, 0 loops; skeleton only */
u32 wifi_mode_set(u32 a2)
{
    /* frame: entry a1,80; 139 insns, 12 cond-branches, 0 loops, 8 jumps */
    /* immediates: 0x102, 1, 3, 0 */
    /* first predicate: bltui a3, 5, 5a <wifi_mode_set+0xe> (condition opaque) */
    /* mem ld32: base=(lit:.rodata.wifi_mode_set) off=0 */
    /* mem ld32: base=(lit:net80211_funcs) off=0 */
    /* mem ld32: base=(*(net80211_funcs+0)) off=8 */
    /* mem ld32: base=(lit:net80211_funcs) off=0 */
    /* mem ld32: base=(*(net80211_funcs+0)) off=8 */
    /* mem ld32: base=(lit:net80211_funcs) off=0 */
    /* mem ld32: base=(*(net80211_funcs+0)) off=4 */
    /* mem ld8: base=((lit:g_ic+131072)) off=17 */
    /* mem ld8: base=((lit:g_ic+131072)) off=13 */
    /* mem ld8: base=((lit:g_ic+131072)) off=12 */
    /* ... +41 more memops */
    /* site +0x71: wifi_log(1, 1, 3, lit:.rodata_wlog_info.3) */
    wifi_log(1, 1, 3, lit:.rodata_wlog_info.3);
    /* site +0x77: wifi_destroy_sta(ret@71, 1, 3, lit:.rodata_wlog_info.3) */
    wifi_destroy_sta(ret@71, 1, 3, lit:.rodata_wlog_info.3);
    /* site +0x85: indirect call via a2 (base *(net80211_funcs+8)); args: ret@77, 1, 3, lit:.rodata_wlog_info.3 */
    opaque_indirect_a2();
    /* site +0x8b: wifi_destroy_nan(ret@85, 1, 3, lit:.rodata_wlog_info.3) */
    wifi_destroy_nan(ret@85, 1, 3, lit:.rodata_wlog_info.3);
    /* site +0x96: wifi_create_sta(ret@8b, 1, 3, lit:.rodata_wlog_info.3) */
    wifi_create_sta(ret@8b, 1, 3, lit:.rodata_wlog_info.3);
    /* site +0xa1: wifi_destroy_nan(ret@96, 1, 3, lit:.rodata_wlog_info.3) */
    wifi_destroy_nan(ret@96, 1, 3, lit:.rodata_wlog_info.3);
    /* site +0xb1: indirect call via a2 (base *(net80211_funcs+8)); args: ret@a1, 1, 3, lit:.rodata_wlog_info.3 */
    opaque_indirect_a2();
    /* site +0xc6: indirect call via a10 (base *(net80211_funcs+4)); args: *(net80211_funcs+4), 1, 3, lit:.rodata_wlog_info.3 */
    opaque_indirect_a10();
    /* site +0xd1: wifi_destroy_nan(ret@c6, 1, 3, lit:.rodata_wlog_info.3) */
    wifi_destroy_nan(ret@c6, 1, 3, lit:.rodata_wlog_info.3);
    /* site +0xda: wifi_destroy_sta(ret@d1, 1, 3, lit:.rodata_wlog_info.3) */
    wifi_destroy_sta(ret@d1, 1, 3, lit:.rodata_wlog_info.3);
    /* site +0x10d: wifi_log(1, 1, 3, lit:.rodata_wlog_info.5, *(g_ic+12)) */
    wifi_log(1, 1, 3, lit:.rodata_wlog_info.5, *(g_ic+12));
    /* site +0x116: wifi_create_nan(ret@10d, 1, 3, lit:.rodata_wlog_info.5, *(g_ic+12)) */
    wifi_create_nan(ret@10d, 1, 3, lit:.rodata_wlog_info.5, *(g_ic+12));
    /* site +0x121: wifi_destroy_sta(ret@116, 1, 3, lit:.rodata_wlog_info.5, *(g_ic+12)) */
    wifi_destroy_sta(ret@116, 1, 3, lit:.rodata_wlog_info.5, *(g_ic+12));
    /* site +0x12e: indirect call via a3 (base *(net80211_funcs+8)); args: ret@121, 1, 3, lit:.rodata_wlog_info.5, *(g_ic+12) */
    opaque_indirect_a3();
    /* site +0x16d: wifi_log(1, 1, 3, lit:.rodata_wlog_info.4, *(g_ic+18)) */
    wifi_log(1, 1, 3, lit:.rodata_wlog_info.4, *(g_ic+18));
    /* site +0x1c2: wifi_log(1, 1, *(g_ic+21), lit:.rodata_wlog_info.6, *(g_ic+18)) */
    wifi_log(1, 1, *(g_ic+21), lit:.rodata_wlog_info.6, *(g_ic+18));
    return 0;
}

/* ieee80211_is_robust_mgmt_frm @ ieee80211.o 0x00000004 size 64B bind GLOBAL
 * Calls: none | Data refs: none
 * Fidelity: medium - branchy but loop-free, call sequence mapped */
u32 ieee80211_is_robust_mgmt_frm(u32 a2, u32 a3)
{
    /* frame: entry a1,32; 24 insns, 4 cond-branches, 0 loops, 1 jumps */
    /* immediates: -160, -33, 1, 208, 0, 22 */
    /* first predicate: bnone a9, a10, 40 <ieee80211_is_robust_mgmt_frm+0x3c> (condition opaque) */
    return 1;
}
