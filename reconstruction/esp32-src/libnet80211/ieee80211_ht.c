/* ieee80211_ht.c - reconstructed from ieee80211_ht.o (71352 bytes on disk).
 * Toolchain: xtensa-esp32-elf (esp-15.2.0), ABI args a2..a7, return a2.
 * Prototypes are generic (arity unknown); bodies preserve the observed
 * call order, branch/loop skeleton, and notable immediates from disasm.
 * Data refs appear in headers only; they are NOT typed (layouts unknown).
 * funcdb v2 edges merged: Calls/Data refs start from funcdb
 * calls[]/refs[] (R_XTENSA_ASM_EXPAND/R_XTENSA_32 rela-matched),
 * plus section-local calls (.text.X+off) from disasm relocs that
 * funcdb v2 omits; call-site order is from disasm. Tags: [v2-only]
 * = in funcdb v2 but no call site found in section disasm (appended);
 * [local] = section-local target funcdb v2 omits.
 */
#include <stdint.h>
#include <stddef.h>
#include <string.h>

extern int chm_get_current_band();  /* external, prototype unknown */
extern int chm_get_home_channel();  /* external, prototype unknown */
extern int chm_set_current_channel();  /* external, prototype unknown */
extern int chm_set_home_channel();  /* external, prototype unknown */
extern int chm_set_snd_chan();  /* external, prototype unknown */
extern int cnx_node_search();  /* external, prototype unknown */
extern int hal_ba_session_restore_by_hw_index();  /* external, prototype unknown */
extern int hal_now();  /* external, prototype unknown */
extern int ic_add_rx_ba();  /* external, prototype unknown */
extern int ic_ampdu_op();  /* external, prototype unknown */
extern int ic_del_rx_ba();  /* external, prototype unknown */
extern int ic_ebuf_alloc();  /* external, prototype unknown */
extern int ic_ebuf_recycle_rx();  /* external, prototype unknown */
extern int ic_register_tx_cb();  /* external, prototype unknown */
extern int ic_reset_rx_ba();  /* external, prototype unknown */
extern int ic_set_sta();  /* external, prototype unknown */
extern int ic_update_trc_params();  /* external, prototype unknown */
extern int ieee80211_get_robustmgtframe();  /* external, prototype unknown */
extern int ieee80211_is_40mhz_valid_bw();  /* external, prototype unknown */
extern int ieee80211_max_bandwidth_negotiation_process();  /* external, prototype unknown */
extern int ieee80211_mgmt_output();  /* external, prototype unknown */
extern int ieee80211_output();  /* external, prototype unknown */
extern int ieee80211_phy_init();  /* external, prototype unknown */
extern int ieee80211_phy_type_get();  /* external, prototype unknown */
extern int ieee80211_recv_action_register();  /* external, prototype unknown */
extern int ieee80211_send_action();  /* external, prototype unknown */
extern int ieee80211_send_action_register();  /* external, prototype unknown */
extern int ieee80211_set_phy_bw();  /* external, prototype unknown */
extern int ieee80211_set_tx_desc();  /* external, prototype unknown */
extern int ieee80211_timer_process();  /* external, prototype unknown */
extern int nan_dp_search_node();  /* external, prototype unknown */
extern int sta_input();  /* external, prototype unknown */
extern int wifi_log();  /* external, prototype unknown */

static int addba_stop_timeout(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
static int ampdu_tx_stop(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
static int ieee80211_ampdu_timeout(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
static int addba_timeout(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
static int addba_get_rap_from_private(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
static int addba_response_txcb(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
static int ht_recv_action_ba_addba_response(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
static int ieee80211_add_htcap_body(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
static int ieee80211_ampdu_stop_age_timer_isra_0(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int ieee80211_ht_attach(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int ampdu_free_rx_ba_index(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
static int ampdu_rx_stop_constprop_0(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
static int ht_recv_action_ba_delba(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int ampdu_alloc_rx_ba_index(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
static int ampdu_rx_start_constprop_0(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
static int ht_recv_action_ba_addba_request(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int ieee80211_ht_deattach(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int ieee80211_cal_tx_pps(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int ieee80211_ampdu_enable(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int addba_timeout_process(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int ieee80211_ampdu_request(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int ieee80211_ampdu_stop(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int ampdu_dispatch(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int ampdu_dispatch_movement(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int ampdu_dispatch_as_many_as_possible(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int ampdu_dispatch_all(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int ampdu_dispatch_upto(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
static int ieee80211_ampdu_age_bss_isra_0(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int ieee80211_ampdu_start_age_timer(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int ieee80211_ampdu_age_all(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int ampdu_process_multicast_address_qos_frame(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int ieee80211_ampdu_reorder(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int ieee80211_process_bar_info(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int ieee80211_recv_bar(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int ieee80211_ht_node_cleanup(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int ieee80211_ht_node_init(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int ieee80211_parse_htcap(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int ieee80211_has_ht40_bss(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int ieee80211_update_channel(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
static int public_recv_action_ht2040_coex(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int ieee80211_ht_updatehtcap(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int ieee80211_ht_updateparams(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int ieee80211_setup_htrates(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int ieee80211_setup_basic_htrates(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int ieee80211_add_htcap(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int ieee80211_add_htcap_vendor(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int ieee80211_add_htinfo_body(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int ieee80211_add_htinfo(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int ieee80211_add_htinfo_vendor(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int ht_action_output(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
static int ht_send_action_ba_delba(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
static int ht_send_action_ba_addba(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int ieee80211_decap1(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int ieee80211_decap_amsdu(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int hostap_ht_operation_update(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);

/* addba_stop_timeout @ ieee80211_ht.o 00000000 size 34B bind LOCAL (no symbol; sec .text.addba_stop_timeout)
 * Calls: none | Data refs: g_osi_funcs_p
 * Fidelity: high - trivial: straight-line, all targets resolved */
static int addba_stop_timeout(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2, a3 */
    /* struct offsets touched: 236, 240 */
    /* immediates: 4 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* ampdu_tx_stop @ ieee80211_ht.o 00000000 size 154B bind LOCAL (no symbol; sec .text.ampdu_tx_stop)
 * Calls: wifi_log, ic_ampdu_op, addba_stop_timeout[+0x4][local] | Data refs: .rodata_wlog_warning.6, g_ic, g_osi_funcs_p
 * Fidelity: medium - small frame, 3 calls + 7 branch(es) mapped */
static int ampdu_tx_stop(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2, a3, a4 */
    /* struct offsets touched: 16, 20, 38, 47, 176, 580, 672 */
    /* immediates: 2, 0x400, 1, 0, 4 */
    /* branches: +0x1b bltui->0x34; +0x30 j->0x95; +0x3a beqz->0x95; +0x48 beq->0x6C; +0x4d bne->0x61; +0x5d j->0x6C; +0x64 beq->0x50 [loop] */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    wifi_log(0, 0, 0, 0, 0, 0);  /* ordered call */
    ic_ampdu_op(0, 0, 0, 0, 0, 0);  /* ordered call */
    addba_stop_timeout(0, 0, 0, 0, 0, 0);  /* ordered call[+0x4] [local] */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* ieee80211_ampdu_timeout @ ieee80211_ht.o 00000000 size 22B bind LOCAL (no symbol; sec .text.ieee80211_ampdu_timeout)
 * Calls: ieee80211_timer_process | Data refs: none
 * Fidelity: high - trivial: straight-line, all targets resolved */
static int ieee80211_ampdu_timeout(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2 */
    /* immediates: 18, 7 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    ieee80211_timer_process(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* addba_timeout @ ieee80211_ht.o 00000000 size 22B bind LOCAL (no symbol; sec .text.addba_timeout)
 * Calls: ieee80211_timer_process | Data refs: none
 * Fidelity: high - trivial: straight-line, all targets resolved */
static int addba_timeout(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2 */
    /* immediates: 10, 7 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    ieee80211_timer_process(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* addba_get_rap_from_private @ ieee80211_ht.o 00000000 size 57B bind LOCAL (no symbol; sec .text.addba_get_rap_from_private)
 * Calls: none | Data refs: none
 * Fidelity: medium - small frame, 0 calls + 5 branch(es) mapped */
static int addba_get_rap_from_private(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2, a3 */
    /* struct offsets touched: 28 */
    /* immediates: 1, 0, 0x268, 8, 4, -1 */
    /* branches: +0xd bnez.n->0x35; +0x12 bnez.n->0x35; +0x22 beqz.n->0x31; +0x26 bne->0x31; +0x2e j->0x37 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* addba_response_txcb @ ieee80211_ht.o 00000000 size 431B bind LOCAL (no symbol; sec .text.addba_response_txcb)
 * Calls: wifi_log, memcmp, cnx_node_search, nan_dp_search_node, addba_get_rap_from_private[local], ic_add_rx_ba | Data refs: .rodata_wlog_error.7, g_ic, .rodata_wlog_error.8, .rodata_wlog_error.9, .rodata_wlog_error.10, .rodata_wlog_error.11, .rodata_wlog_error.12, .rodata_wlog_error.13, .rodata_wlog_error.14, .rodata_wlog_error.15, .rodata_wlog_error.16
 * Fidelity: medium - small frame, 6 calls + 22 branches mapped (backward-edge marks kept; predicates opaque; verified against section disasm + EXPAND relocs) */
static int addba_response_txcb(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,96; early arg regs: a2, a3, a4, a5 */
    /* struct offsets touched: 8, 9, 12, 16, 19, 20, 24, 28, 32, 36, 37, 44, 48, 228 */
    /* immediates: 0, 4, 1, 0x400, 6, 48, 3, 64, -3, 68 */
    /* branches: +0x52 beqz.n->0x75; +0x65 beq->0x6B; +0x68 j->0xF1; +0x70 bnez.n->0x89; +0x85 j->0x1AD; +0x8f beqz->0x75 [loop]; +0x9c beqz->0x134; +0xec j->0x1AD; +0xf1 bnei->0x116; +0xfc beqz->0x10C (+12 more) */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    wifi_log(0, 0, 0, 0, 0, 0);  /* ordered call */
    memcmp(0, 0, 0);  /* ordered call */
    cnx_node_search(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_dp_search_node(0, 0, 0, 0, 0, 0);  /* ordered call */
    addba_get_rap_from_private(0, 0, 0, 0, 0, 0);  /* ordered call [local] */
    ic_add_rx_ba(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* ht_recv_action_ba_addba_response @ ieee80211_ht.o 00000000 size 409B bind LOCAL (no symbol; sec .text.ht_recv_action_ba_addba_response)
 * Calls: wifi_log, addba_stop_timeout[+0x4][local], ic_ampdu_op | Data refs: .rodata.ht_recv_action_ba_addba_response.st~, .rodata_wlog_warning.29, .rodata_wlog_warning.30, .rodata_wlog_warning.31, g_wifi_menuconfig, g_ic
 * Fidelity: medium - small frame, 3 calls + 21 branches mapped (backward-edge marks kept; predicates opaque; verified against section disasm + EXPAND relocs) */
static int ht_recv_action_ba_addba_response(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,48; early arg regs: a2, a3, a4, a5, a6 */
    /* struct offsets touched: 8, 12, 16, 20, 38, 44, 48, 74, 76, 100, 580, 672 */
    /* immediates: 2, 0x400, 1, 37, 64, 0, 4, 132, 16 */
    /* branches: +0x57 bnez.n->0x70; +0x6c j->0x192; +0x73 bbsi->0x94; +0x90 j->0x192; +0x97 beq->0xC8; +0xa2 beq->0xA8; +0xc5 j->0x192; +0xce beq->0xD4; +0xd1 j->0x192; +0xdc bnez->0x184 (+11 more) */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    wifi_log(0, 0, 0, 0, 0, 0);  /* ordered call */
    addba_stop_timeout(0, 0, 0, 0, 0, 0);  /* ordered call[+0x4] [local] */
    ic_ampdu_op(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* ieee80211_add_htcap_body @ ieee80211_ht.o 00000000 size 509B bind LOCAL (no symbol; sec .text.ieee80211_add_htcap_body)
 * Calls: wifi_log, memset | Data refs: .rodata.ieee80211_add_htcap_body.str1.1, .rodata_wlog_error.70, g_ic
 * Fidelity: low - large/complex: 25 branches, 5 loops, 2 calls; hardware loop insns at +0x176 (loop a12, movi 14) and +0x1a2 (loop a12, movi 24); trip/stride mapping needed - need loop-trip decode to raise */
static int ieee80211_add_htcap_body(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a3, a4 */
    /* struct offsets touched: 15, 19, 20, 94, 102, 103, 332, 344, 348, 352, 356, 672 */
    /* immediates: 1, -3, 2, 0, 28, 32, -33, 64, -65, 3, 23, 126 */
    /* branches: +0x1b beqz.n->0x22; +0x20 bnez.n->0x3B; +0x38 j->0x38 [loop]; +0x47 bbci->0x50; +0x57 bne->0x86; +0x80 bge->0x86; +0x8b bbsi->0x94; +0x94 bbci->0xA0; +0x9d bbsi->0xA6; +0xbb beq->0xC4 (+15 more) */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    wifi_log(0, 0, 0, 0, 0, 0);  /* ordered call */
    memset(0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* ieee80211_ampdu_stop_age_timer_isra_0 @ ieee80211_ht.o 00000000 size 54B bind LOCAL (no symbol; sec .text.ieee80211_ampdu_stop_age_timer$isra$0)
 * Calls: none | Data refs: g_ic, g_ic+0x258, g_osi_funcs_p
 * Fidelity: medium - small frame, 0 calls + 1 branch(es) mapped */
static int ieee80211_ampdu_stop_age_timer_isra_0(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: none observed */
    /* struct offsets touched: 83, 236 */
    /* immediates: 0 */
    /* branches: +0x18 beqz.n->0x34 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* ieee80211_ht_attach @ ieee80211_ht.o 00000078 size 563B bind GLOBAL
 * Calls: wifi_log, chm_get_current_band, ieee80211_is_40mhz_valid_bw, ic_register_tx_cb, ieee80211_recv_action_register, ieee80211_send_action_register | Data refs: g_wifi_menuconfig, .rodata.ieee80211_add_htcap_body.str1.1, .rodata_wlog_error.2, g_phy_cap_rx_stbc, g_ic, .text.ieee80211_ampdu_timeout, g_ic+0x258, g_osi_funcs_p, .text.addba_response_txcb, .text.ht_recv_action_ba_delba, .text.ht_recv_action_ba_addba_request, .text.ht_send_action_ba_addba, .text.ht_recv_action_ba_addba_response, .text.ht_send_action_ba_delba, .text.public_recv_action_ht2040_coex, g_ic+0x200
 * Fidelity: medium - small frame, 6 calls + 30 branches mapped (backward-edge marks kept; predicates opaque; verified against section disasm + EXPAND relocs) */
int ieee80211_ht_attach(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,48; early arg regs: a3, a4, a5, a6 */
    /* struct offsets touched: 16, 20, 28, 32, 76, 84, 166, 167, 170, 171, 244, 344, 348, 352 */
    /* immediates: 15, -1, 0, 31, 1, 63, 2, 3, 120, 129, 9, 0x443 */
    /* branches: +0x91 bgeu->0x2C [loop]; +0x98 bgeu->0x2C [loop]; +0x9f bgeu->0x2C [loop]; +0xa4 bnez.n->0x48 [loop]; +0xbc j->0x44 [loop]; +0xc9 beqi->0x5A [loop]; +0xe6 bnei->0x94 [loop]; +0xe9 beq->0x81 [loop]; +0xee bne->0x81 [loop]; +0xf6 j->0x88 [loop] (+20 more) */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    wifi_log(0, 0, 0, 0, 0, 0);  /* ordered call */
    chm_get_current_band(0, 0, 0, 0, 0, 0);  /* ordered call */
    ieee80211_is_40mhz_valid_bw(0, 0, 0, 0, 0, 0);  /* ordered call */
    ic_register_tx_cb(0, 0, 0, 0, 0, 0);  /* ordered call */
    ieee80211_recv_action_register(0, 0, 0, 0, 0, 0);  /* ordered call */
    ieee80211_send_action_register(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* ampdu_free_rx_ba_index @ ieee80211_ht.o 0000000c size 51B bind GLOBAL
 * Calls: wifi_log | Data refs: .rodata_wlog_warning.3, g_ic
 * Fidelity: medium - small frame, 1 call + 2 branch(es) mapped */
int ampdu_free_rx_ba_index(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2 */
    /* immediates: 2, 0x400, 1, 0x1da, 0 */
    /* branches: +0x12 bltui->0x1C; +0x25 j->0x2E */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    wifi_log(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* ampdu_rx_stop_constprop_0 @ ieee80211_ht.o 00000000 size 229B bind LOCAL (no symbol; sec .text.ampdu_rx_stop$constprop$0)
 * Calls: wifi_log, ic_ebuf_recycle_rx, ic_del_rx_ba, ampdu_free_rx_ba_index | Data refs: .rodata_wlog_warning.34, g_osi_funcs_p
 * Fidelity: medium - small frame, 4 calls + 11 branches mapped (backward-edge marks kept; predicates opaque) */
static int ampdu_rx_stop_constprop_0(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2, a3, a4, a5 */
    /* struct offsets touched: 8, 14, 22, 24, 32, 136, 176, 616 */
    /* immediates: 2, 0x400, 1, 0, -1, -71, -2 */
    /* branches: +0x21 bltui->0x3C; +0x38 j->0xE0; +0x3c beqz->0xE0; +0x43 j->0xA9; +0x4e bnez.n->0x55; +0x52 j->0xA9; +0x7b bnez->0x50 [loop]; +0xa2 bnez.n->0xB2; +0xa4 j->0xBA; +0xac blt->0x46 [loop] (+1 more) */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    wifi_log(0, 0, 0, 0, 0, 0);  /* ordered call */
    ic_ebuf_recycle_rx(0, 0, 0, 0, 0, 0);  /* ordered call */
    ic_del_rx_ba(0, 0, 0, 0, 0, 0);  /* ordered call */
    ampdu_free_rx_ba_index(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* ht_recv_action_ba_delba @ ieee80211_ht.o 00000000 size 166B bind LOCAL (no symbol; sec .text.ht_recv_action_ba_delba)
 * Calls: wifi_log, ampdu_tx_stop[+0x18][local], ampdu_rx_stop_constprop_0[+0x18][local] | Data refs: .rodata.ht_recv_action_ba_delba.str1.1, .rodata.ieee80211_add_htcap_body.str1.1, .rodata_wlog_error.80, .rodata_wlog_info.81
 * Fidelity: medium - small frame, 3 calls + 5 branch(es) mapped */
static int ht_recv_action_ba_delba(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,48; early arg regs: a2 */
    /* immediates: 1, 25, 0x400, 3, 0 */
    /* branches: +0x27 bnez.n->0x44; +0x41 j->0x41 [loop]; +0x6e bnez->0x74; +0x91 bnez.n->0x9C; +0x99 j->0xA2 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    wifi_log(0, 0, 0, 0, 0, 0);  /* ordered call */
    ampdu_tx_stop(0, 0, 0, 0, 0, 0);  /* ordered call[+0x18] [local] */
    ampdu_rx_stop_constprop_0(0, 0, 0, 0, 0, 0);  /* ordered call[+0x18] [local] */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* ampdu_alloc_rx_ba_index @ ieee80211_ht.o 00000010 size 116B bind GLOBAL
 * Calls: wifi_log | Data refs: .rodata.ieee80211_add_htcap_body.str1.1, .rodata_wlog_error.4, g_ic
 * Fidelity: medium - small frame, 1 call + 11 branches mapped (backward-edge marks kept; predicates opaque) */
int ampdu_alloc_rx_ba_index(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2 */
    /* struct offsets touched: 16, 20, 672 */
    /* immediates: 1, 0x112, -1, 8, 5, 2, 0, 0x1da */
    /* branches: +0x13 bnez.n->0x20; +0x2c j->0x1C [loop]; +0x35 beq->0x3C; +0x3a beq->0x44; +0x42 bne->0x70; +0x49 j->0x48 [loop]; +0x50 j->0x48 [loop]; +0x5b j->0x6B; +0x65 bnez.n->0x69; +0x76 j->0x70 [loop] (+1 more) */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    wifi_log(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* ampdu_rx_start_constprop_0 @ ieee80211_ht.o 00000000 size 297B bind LOCAL (no symbol; sec .text.ampdu_rx_start$constprop$0)
 * Calls: wifi_log, ampdu_rx_stop_constprop_0[+0x18][local], ampdu_alloc_rx_ba_index | Data refs: g_wifi_menuconfig, .rodata.ieee80211_add_htcap_body.str1.1, .rodata_wlog_error.35, g_osi_funcs_p, .rodata_wlog_error.36, .rodata_wlog_error.37
 * Fidelity: medium - small frame, 3 calls + 8 branch(es) mapped */
static int ampdu_rx_start_constprop_0(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,64; early arg regs: a2, a5, a6 */
    /* struct offsets touched: 8, 10, 12, 14, 16, 24, 32, 38, 48, 136, 176, 376, 616 */
    /* immediates: 1, 0x4bf, 40, 0x400, 2, 0 */
    /* branches: +0x34 bnez.n->0x55; +0x50 j->0x50 [loop]; +0x6e bnei->0x74; +0x71 j->0x122; +0x8b beqz.n->0xBE; +0xaa bnez.n->0xD0; +0xcc j->0x122; +0xe3 bnez->0xEC */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    wifi_log(0, 0, 0, 0, 0, 0);  /* ordered call */
    ampdu_rx_stop_constprop_0(0, 0, 0, 0, 0, 0);  /* ordered call[+0x18] [local] */
    ampdu_alloc_rx_ba_index(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* ht_recv_action_ba_addba_request @ ieee80211_ht.o 00000000 size 405B bind LOCAL (no symbol; sec .text.ht_recv_action_ba_addba_request)
 * Calls: wifi_log, ampdu_rx_start_constprop_0[+0x28][local], ampdu_rx_stop_constprop_0[+0x18][local], ieee80211_send_action | Data refs: g_wifi_menuconfig, .rodata.ieee80211_add_htcap_body.str1.1, .rodata_wlog_error.75, g_ic
 * Fidelity: medium - small frame, 4 calls + 21 branches mapped (backward-edge marks kept; predicates opaque; verified against section disasm + EXPAND relocs) */
static int ht_recv_action_ba_addba_request(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,80; early arg regs: a2, a3, a4 */
    /* struct offsets touched: 8, 10, 12, 14, 16, 32, 36, 37, 48, 136, 344, 616 */
    /* immediates: 1, 0x171, 0, -2, 31, 10, 2, 3 */
    /* branches: +0x34 bnez.n->0x58; +0x54 j->0x54 [loop]; +0x67 bbci->0x6D; +0x6a j->0x191; +0x7b beqz.n->0x85; +0x7f bbci->0x85; +0x82 j->0x191; +0x9f bbsi->0xA5; +0xa2 j->0x145; +0xb8 beqi->0xBE (+11 more) */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    wifi_log(0, 0, 0, 0, 0, 0);  /* ordered call */
    ampdu_rx_start_constprop_0(0, 0, 0, 0, 0, 0);  /* ordered call[+0x28] [local] */
    ampdu_rx_stop_constprop_0(0, 0, 0, 0, 0, 0);  /* ordered call[+0x18] [local] */
    ieee80211_send_action(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* ieee80211_ht_deattach @ ieee80211_ht.o 0000001c size 120B bind GLOBAL
 * Calls: wifi_log, ieee80211_ampdu_stop_age_timer_isra_0[+0xc][local] | Data refs: .rodata.ieee80211_add_htcap_body.str1.1, .rodata_wlog_error.5, g_ic, g_ic+0x258, g_osi_funcs_p
 * Fidelity: medium - small frame, 2 calls + 5 branch(es) mapped */
int ieee80211_ht_deattach(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2 */
    /* struct offsets touched: 16, 20, 84, 240, 344, 348, 352 */
    /* immediates: 1, 0x14d, 0, 2, -2 */
    /* branches: +0x1f bnez.n->0x20; +0x38 j->0x1C [loop]; +0x4f beq->0x44 [loop]; +0x66 beqz.n->0x76; +0x79 bnez.n->0x76 [loop] */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    wifi_log(0, 0, 0, 0, 0, 0);  /* ordered call */
    ieee80211_ampdu_stop_age_timer_isra_0(0, 0, 0, 0, 0, 0);  /* ordered call[+0xc] [local] */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* ieee80211_cal_tx_pps @ ieee80211_ht.o 00000008 size 69B bind GLOBAL
 * Calls: hal_now | Data refs: none
 * Fidelity: medium - small frame, 1 call + 3 branch(es) mapped */
int ieee80211_cal_tx_pps(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2, a3 */
    /* struct offsets touched: 492 */
    /* immediates: 0x1e8, 0x1e4, 1, 0 */
    /* branches: +0x2c bnez.n->0x2C [loop]; +0x31 j->0x3C; +0x3a bgeu->0x3E */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    hal_now(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* ieee80211_ampdu_enable @ ieee80211_ht.o 00000000 size 15B bind GLOBAL
 * Calls: none | Data refs: none
 * Fidelity: high - trivial: straight-line, all targets resolved */
int ieee80211_ampdu_enable(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2, a3 */
    /* immediates: 1, 0 */
    /* branches: +0x8 bltui->0xD */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* addba_timeout_process @ ieee80211_ht.o 00000000 size 37B bind GLOBAL
 * Calls: none | Data refs: none
 * Fidelity: high - trivial: straight-line, all targets resolved */
int addba_timeout_process(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2 */
    /* struct offsets touched: 44, 76 */
    /* immediates: -3, 1 */
    /* branches: +0x3 beqz.n->0x20 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* ieee80211_ampdu_request @ ieee80211_ht.o 00000028 size 344B bind GLOBAL
 * Calls: hal_now, wifi_log, ieee80211_send_action | Data refs: .rodata.ieee80211_add_htcap_body.str1.1, .rodata_wlog_error.33, g_osi_funcs_p, .bss.tokens$1, .text.addba_timeout
 * Fidelity: medium - small frame, 3 calls + 7 branch(es) mapped */
int ieee80211_ampdu_request(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,48; early arg regs: a2, a3 */
    /* struct offsets touched: 8, 12, 44, 47, 48, 70, 74, 76, 174, 232, 236, 240, 244, 376 */
    /* immediates: 1, 0x3ce, 120, 8, -17, 60, 0, 4, 0x271, 0x3e8, 2, 3 */
    /* branches: +0x34 bnez.n->0x28 [loop]; +0x4c j->0x24 [loop]; +0x5b bnez.n->0x50 [loop]; +0x6a beqz->0x154; +0x7d bany->0x61 [loop]; +0xe2 bbci->0xC8 [loop]; +0x144 bgeui->0x122 [loop] */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    hal_now(0, 0, 0, 0, 0, 0);  /* ordered call */
    wifi_log(0, 0, 0, 0, 0, 0);  /* ordered call */
    ieee80211_send_action(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* ieee80211_ampdu_stop @ ieee80211_ht.o 0000000c size 74B bind GLOBAL
 * Calls: ampdu_tx_stop[+0x18][local], ieee80211_send_action | Data refs: g_ic, g_osi_funcs_p
 * Fidelity: medium - small frame, 2 calls + 1 branch(es) mapped */
int ieee80211_ampdu_stop(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,48; early arg regs: a2, a3 */
    /* struct offsets touched: 44, 47 */
    /* immediates: -33, 2, 3 */
    /* branches: +0x1e bbci->0x48 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    ampdu_tx_stop(0, 0, 0, 0, 0, 0);  /* ordered call[+0x18] [local] */
    ieee80211_send_action(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* ampdu_dispatch @ ieee80211_ht.o 00000018 size 92B bind GLOBAL
 * Calls: wifi_log, sta_input | Data refs: .rodata.ieee80211_add_htcap_body.str1.1, .rodata_wlog_error.39, g_ic, net80211_funcs
 * Fidelity: medium - small frame, 2 calls + 5 branch(es) mapped */
int ampdu_dispatch(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2, a3 */
    /* struct offsets touched: 16, 44 */
    /* immediates: 1, 0x50b, 32, 0 */
    /* branches: +0x1f beqz.n->0xE [loop]; +0x23 bnez->0x28; +0x3c j->0x24 [loop]; +0x50 bne->0x4C [loop]; +0x60 j->0x5A [loop] */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    wifi_log(0, 0, 0, 0, 0, 0);  /* ordered call */
    sta_input(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* ampdu_dispatch_movement @ ieee80211_ht.o 00000000 size 54B bind GLOBAL
 * Calls: none | Data refs: none
 * Fidelity: medium - small frame, 0 calls + 5 branch(es) mapped */
int ampdu_dispatch_movement(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2, a3 */
    /* struct offsets touched: 14, 24 */
    /* immediates: 1, 4, 0, -1 */
    /* branches: +0x9 beqz.n->0x31; +0x14 j->0x2E; +0x1e beqz.n->0x2A; +0x28 beqz.n->0x31; +0x2e blt->0x17 [loop] */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* ampdu_dispatch_as_many_as_possible @ ieee80211_ht.o 00000014 size 133B bind GLOBAL
 * Calls: wifi_log, ampdu_dispatch_movement, ampdu_dispatch | Data refs: .rodata.ieee80211_add_htcap_body.str1.1, .rodata_wlog_error.41
 * Fidelity: medium - small frame, 3 calls + 6 branch(es) mapped */
int ampdu_dispatch_as_many_as_possible(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2, a3, a4, a5 */
    /* struct offsets touched: 8, 12, 14, 22, 24 */
    /* immediates: 1, 0, 0x53d, -1 */
    /* branches: +0x21 bnez->0x16 [loop]; +0x27 beqz->0x7C; +0x40 j->0x2C [loop]; +0x4b bnez.n->0x58; +0x93 blt->0x30 [loop]; +0x96 j->0x39 [loop] */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    wifi_log(0, 0, 0, 0, 0, 0);  /* ordered call */
    ampdu_dispatch_movement(0, 0, 0, 0, 0, 0);  /* ordered call */
    ampdu_dispatch(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* ampdu_dispatch_all @ ieee80211_ht.o 00000010 size 141B bind GLOBAL
 * Calls: wifi_log, ampdu_dispatch | Data refs: .rodata.ieee80211_add_htcap_body.str1.1, .rodata_wlog_error.43
 * Fidelity: medium - small frame, 2 calls + 8 branch(es) mapped */
int ampdu_dispatch_all(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2, a3, a4, a5 */
    /* struct offsets touched: 8, 12, 14, 22, 24 */
    /* immediates: 1, 0, 0x555, -1 */
    /* branches: +0x1e bnez->0x1A [loop]; +0x27 beqz->0x84; +0x40 j->0x30 [loop]; +0x4b bnez.n->0x44 [loop]; +0x4f j->0x84; +0x7b bnez->0x3D [loop]; +0x97 blt->0x34 [loop]; +0x9a j->0x6E [loop] */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    wifi_log(0, 0, 0, 0, 0, 0);  /* ordered call */
    ampdu_dispatch(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* ampdu_dispatch_upto @ ieee80211_ht.o 00000018 size 199B bind GLOBAL
 * Calls: wifi_log, ampdu_dispatch, ampdu_dispatch_movement | Data refs: .rodata.ieee80211_add_htcap_body.str1.1, .rodata_wlog_error.45, g_hmac_cnt
 * Fidelity: medium - small frame, 3 calls + 9 branches mapped (backward-edge marks kept; predicates opaque) */
int ampdu_dispatch_upto(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,48; early arg regs: a2, a3, a4, a5, a6, a7 */
    /* struct offsets touched: 8, 12, 14, 22, 24, 54 */
    /* immediates: 1, 0, 0x572, -1, 0x7fe */
    /* branches: +0x29 bnez->0x1A [loop]; +0x2f beqz->0x34; +0x48 j->0x30 [loop]; +0x57 j->0x94; +0x61 beqz.n->0x73; +0x88 j->0x8F; +0x96 blt->0x9C; +0xb1 blt->0x42 [loop]; +0xce bge->0xBC [loop] */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    wifi_log(0, 0, 0, 0, 0, 0);  /* ordered call */
    ampdu_dispatch(0, 0, 0, 0, 0, 0);  /* ordered call */
    ampdu_dispatch_movement(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* ieee80211_ampdu_age_bss_isra_0 @ ieee80211_ht.o 00000000 size 233B bind LOCAL (no symbol; sec .text.ieee80211_ampdu_age_bss$isra$0)
 * Calls: wifi_log, hal_now, ampdu_dispatch_upto | Data refs: .rodata_wlog_error.46
 * Fidelity: medium - small frame, 3 calls + 13 branches mapped (backward-edge marks kept; predicates opaque) */
static int ieee80211_ampdu_age_bss_isra_0(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,48; early arg regs: a2, a3, a4, a5, a6 */
    /* struct offsets touched: 8, 12, 14, 24, 44, 136 */
    /* immediates: 152, 31, 1, 0x400, -1, -4, -2 */
    /* branches: +0x20 beqz->0xE4; +0x2f j->0xE1; +0x4a bnez.n->0x64; +0x5f j->0xCD; +0x6a blti->0xCD; +0x8f j->0xCA; +0x98 beqz.n->0xC2; +0xa0 bgei->0xBA; +0xb5 j->0xCD; +0xbf beqz->0xCD (+3 more) */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    wifi_log(0, 0, 0, 0, 0, 0);  /* ordered call */
    hal_now(0, 0, 0, 0, 0, 0);  /* ordered call */
    ampdu_dispatch_upto(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* ieee80211_ampdu_start_age_timer @ ieee80211_ht.o 00000018 size 77B bind GLOBAL
 * Calls: wifi_log | Data refs: g_ic, .rodata.ieee80211_add_htcap_body.str1.1, .rodata_wlog_error.47, g_ic+0x258, g_osi_funcs_p
 * Fidelity: medium - small frame, 1 call + 3 branch(es) mapped */
int ieee80211_ampdu_start_age_timer(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2, a3 */
    /* struct offsets touched: 83, 84, 248 */
    /* immediates: 1, 0x645, 0 */
    /* branches: +0x26 bnez.n->0x46; +0x2b bnez.n->0x30; +0x44 j->0x2C [loop] */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    wifi_log(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* ieee80211_ampdu_age_all @ ieee80211_ht.o 00000024 size 159B bind GLOBAL
 * Calls: ieee80211_ampdu_age_bss_isra_0[+0x18][local], ieee80211_ampdu_stop_age_timer_isra_0[+0xc][local], ieee80211_ampdu_start_age_timer | Data refs: g_ic
 * Fidelity: medium - small frame, 3 calls + 8 branch(es) mapped */
int ieee80211_ampdu_age_all(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,48; early arg regs: a2, a3, a4, a6 */
    /* struct offsets touched: 16, 20, 228, 300, 360, 580, 584, 672 */
    /* immediates: 1, 31, -1 */
    /* branches: +0x34 beqz.n->0x20 [loop]; +0x44 beqz.n->0x5D; +0x49 beqz.n->0x5D; +0x7e bnez->0x29 [loop]; +0x81 beqz.n->0x85; +0x86 beqz.n->0x71 [loop]; +0x98 beqz->0x85 [loop]; +0xb2 beq->0x9D [loop] */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    ieee80211_ampdu_age_bss_isra_0(0, 0, 0, 0, 0, 0);  /* ordered call[+0x18] [local] */
    ieee80211_ampdu_stop_age_timer_isra_0(0, 0, 0, 0, 0, 0);  /* ordered call[+0xc] [local] */
    ieee80211_ampdu_start_age_timer(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* ampdu_process_multicast_address_qos_frame @ ieee80211_ht.o 00000004 size 140B bind GLOBAL
 * Calls: hal_ba_session_restore_by_hw_index | Data refs: none
 * Fidelity: medium - small frame, 1 call + 12 branches mapped (backward-edge marks kept; predicates opaque) */
int ampdu_process_multicast_address_qos_frame(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,48; early arg regs: a2, a3 */
    /* struct offsets touched: 8, 12, 14, 24, 32 */
    /* immediates: 0, 1, 31, 4, 8 */
    /* branches: +0x1f blt->0x8A; +0x2a bnez->0x8A; +0x31 blt->0x78; +0x37 bnez.n->0x61; +0x3c j->0x78; +0x47 beqz.n->0x5C; +0x4f blt->0x56; +0x57 j->0x5C; +0x62 j->0x6D; +0x71 blt->0x3C [loop] (+2 more) */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    hal_ba_session_restore_by_hw_index(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* ieee80211_ampdu_reorder @ ieee80211_ht.o 0000004c size 542B bind GLOBAL
 * Calls: wifi_log, ampdu_process_multicast_address_qos_frame, ampdu_dispatch, ampdu_dispatch_as_many_as_possible, ieee80211_ampdu_start_age_timer, ampdu_dispatch_upto, ampdu_dispatch_all, ic_reset_rx_ba, ic_ebuf_recycle_rx | Data refs: .rodata.ieee80211_add_htcap_body.str1.1, .rodata_wlog_error.49, .rodata_wlog_warning.50, .rodata_wlog_warning.51, g_hmac_cnt
 * Fidelity: medium - small frame, 9 calls + 33 branches mapped (backward-edge marks kept; predicates opaque; verified against section disasm + EXPAND relocs) */
int ieee80211_ampdu_reorder(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,48; early arg regs: a2, a3, a4, a6 */
    /* struct offsets touched: 8, 10, 12, 14, 20, 22, 24, 30, 32, 44, 56, 616 */
    /* immediates: 0, 1, 0x69a, 136, 2, 0x400, 4, -65, 64 */
    /* branches: +0x62 beqz.n->0x34 [loop]; +0x7c j->0x30 [loop]; +0x8c beq->0x46 [loop]; +0x8f j->0x21C; +0x98 bnei->0x55 [loop]; +0x9e j->0x58 [loop]; +0xa9 bbci->0x78 [loop]; +0xc1 j->0x20E; +0xce beqz->0x21C; +0xd8 beqz->0x21C (+23 more) */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    wifi_log(0, 0, 0, 0, 0, 0);  /* ordered call */
    ampdu_process_multicast_address_qos_frame(0, 0, 0, 0, 0, 0);  /* ordered call */
    ampdu_dispatch(0, 0, 0, 0, 0, 0);  /* ordered call */
    ampdu_dispatch_as_many_as_possible(0, 0, 0, 0, 0, 0);  /* ordered call */
    ieee80211_ampdu_start_age_timer(0, 0, 0, 0, 0, 0);  /* ordered call */
    ampdu_dispatch_upto(0, 0, 0, 0, 0, 0);  /* ordered call */
    ampdu_dispatch_all(0, 0, 0, 0, 0, 0);  /* ordered call */
    ic_reset_rx_ba(0, 0, 0, 0, 0, 0);  /* ordered call */
    ic_ebuf_recycle_rx(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* ieee80211_process_bar_info @ ieee80211_ht.o 00000004 size 50B bind GLOBAL
 * Calls: ampdu_dispatch_upto | Data refs: none
 * Fidelity: medium - small frame, 1 call + 5 branch(es) mapped */
int ieee80211_process_bar_info(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2, a3, a4 */
    /* struct offsets touched: 12, 616 */
    /* branches: +0xf bgeui->0x30; +0x18 beqz.n->0x30; +0x1c bbci->0x30; +0x25 beq->0x30; +0x2b bbsi->0x30 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    ampdu_dispatch_upto(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* ieee80211_recv_bar @ ieee80211_ht.o 00000010 size 84B bind GLOBAL
 * Calls: wifi_log, ieee80211_process_bar_info | Data refs: .rodata.ieee80211_add_htcap_body.str1.1, .rodata_wlog_error.52
 * Fidelity: medium - small frame, 2 calls + 3 branch(es) mapped */
int ieee80211_recv_bar(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2, a3 */
    /* struct offsets touched: 16, 17, 18, 19 */
    /* immediates: 1, 0, 0x7a6 */
    /* branches: +0x1f bnez.n->0x16 [loop]; +0x24 beqz.n->0x30; +0x3c j->0x2C [loop] */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    wifi_log(0, 0, 0, 0, 0, 0);  /* ordered call */
    ieee80211_process_bar_info(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* ieee80211_ht_node_cleanup @ ieee80211_ht.o 00000008 size 58B bind GLOBAL
 * Calls: ampdu_tx_stop[+0x18][local], ampdu_rx_stop_constprop_0[+0x18][local] | Data refs: none
 * Fidelity: medium - small frame, 2 calls + 2 branch(es) mapped */
int ieee80211_ht_node_cleanup(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2, a3 */
    /* struct offsets touched: 12, 348 */
    /* immediates: 0, 1, -65 */
    /* branches: +0xb beqz.n->0x35; +0x28 bnei->0x8 [loop] */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    ampdu_tx_stop(0, 0, 0, 0, 0, 0);  /* ordered call[+0x18] [local] */
    ampdu_rx_stop_constprop_0(0, 0, 0, 0, 0, 0);  /* ordered call[+0x18] [local] */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* ieee80211_ht_node_init @ ieee80211_ht.o 00000014 size 113B bind GLOBAL
 * Calls: wifi_log, ieee80211_ht_node_cleanup | Data refs: .rodata.ieee80211_add_htcap_body.str1.1, .rodata_wlog_error.53, g_ic
 * Fidelity: medium - small frame, 2 calls + 7 branch(es) mapped */
int ieee80211_ht_node_init(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2 */
    /* struct offsets touched: 12, 332, 344 */
    /* immediates: 1, 0x7be, 64, 49 */
    /* branches: +0x17 bnez.n->0x21; +0x30 j->0x1C [loop]; +0x3b bnone->0x32 [loop]; +0x51 bbci->0x5D; +0x57 bnez->0x52 [loop]; +0x63 beqi->0x5D [loop]; +0x71 bbci->0x6C [loop] */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    wifi_log(0, 0, 0, 0, 0, 0);  /* ordered call */
    ieee80211_ht_node_cleanup(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* ieee80211_parse_htcap @ ieee80211_ht.o 00000020 size 302B bind GLOBAL
 * Calls: wifi_log, memcpy | Data refs: .rodata.ieee80211_add_htcap_body.str1.1, .rodata_wlog_error.54, g_ic, .rodata
 * Fidelity: low - large/complex: 20 branches, 18 loops, 2 calls; hardware loop at +0xfd (loop a9, movi 8); trip/stride mapping needed - need loop-trip decode to raise */
int ieee80211_parse_htcap(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,48; early arg regs: a2, a3, a4, a5, a6 */
    /* struct offsets touched: 12, 94, 238, 242, 344, 348 */
    /* immediates: 1, 0, 221, 128, 4, 64, 16, 7, 8, 144 */
    /* branches: +0x2d bnez->0x16 [loop]; +0x33 beqz->0x30 [loop]; +0x4c j->0x2C [loop]; +0x58 bne->0x4B [loop]; +0x68 j->0x60 [loop]; +0x74 beqi->0x60 [loop]; +0xaa bbci->0x9D [loop]; +0xb0 bbci->0x9D [loop]; +0xbd bbci->0xB2 [loop]; +0xc3 bbci->0xB2 [loop] (+10 more) */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    wifi_log(0, 0, 0, 0, 0, 0);  /* ordered call */
    memcpy(0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* ieee80211_has_ht40_bss @ ieee80211_ht.o 00000008 size 170B bind GLOBAL
 * Calls: none | Data refs: g_wifi_nvs, g_ic
 * Fidelity: medium - small frame, 0 calls + 20 branches mapped (backward-edge marks kept; predicates opaque) */
int ieee80211_has_ht40_bss(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2 */
    /* struct offsets touched: 16, 20, 38, 171, 172, 228, 236, 246 */
    /* immediates: -3, 8, -1, -5, -2, 0, 1 */
    /* branches: +0x18 bnei->0x49; +0x20 beqz.n->0x49; +0x25 beqz.n->0x49; +0x2a bnei->0x38; +0x39 bltu->0x49; +0x3c j->0xA8; +0x40 bnei->0x49; +0x4e bgeu->0xA8; +0x56 bgeui->0xA8; +0x5e beq->0xA8 (+10 more) */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* ieee80211_update_channel @ ieee80211_ht.o 00000084 size 1154B bind GLOBAL
 * Calls: chm_get_home_channel, ieee80211_is_40mhz_valid_bw, wifi_log, chm_set_snd_chan, ieee80211_phy_init, ieee80211_ht_deattach, ieee80211_set_phy_bw, ieee80211_ht_attach, ieee80211_phy_type_get, ic_update_trc_params, ieee80211_has_ht40_bss, chm_set_home_channel, chm_set_current_channel | Data refs: g_ic, .rodata_wlog_warning.60, .rodata.ieee80211_add_htcap_body.str1.1, .rodata_wlog_error.57, .rodata_wlog_info.58, .rodata_wlog_info.59, g_wifi_nvs, g_osi_funcs_p, .rodata_wlog_info.61, gScanStruct, .rodata_wlog_info.62
 * Fidelity: medium - chan/bw update (home/snd + 40M-valid + HT attach/deattach + phy_init) recovered - large/complex: 94 branches, 84 loop(s), 13 calls; skeleton only */
int ieee80211_update_channel(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,112; early arg regs: a2, a3, a4, a5, a6, a7 */
    /* struct offsets touched: 8, 12, 16, 20, 24, 28, 32, 33, 38, 48, 52, 56, 60, 64 */
    /* immediates: 0, 2, 4, 1, 171, 13, -1, 0x156, 3, 14, -14, 240 */
    /* branches: +0x9e beqz.n->0x46 [loop]; +0xa3 beqz.n->0x46 [loop]; +0xb1 bnez.n->0x46 [loop]; +0xce bnez.n->0x56 [loop]; +0xd0 bnez->0x2A8; +0xd6 j->0x297; +0xdc bnez.n->0x70 [loop]; +0xde beqz->0x4C [loop]; +0xe4 beqz->0x4C [loop]; +0xea beqz->0x4C [loop] (+84 more) */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    chm_get_home_channel(0, 0, 0, 0, 0, 0);  /* ordered call */
    ieee80211_is_40mhz_valid_bw(0, 0, 0, 0, 0, 0);  /* ordered call */
    wifi_log(0, 0, 0, 0, 0, 0);  /* ordered call */
    chm_set_snd_chan(0, 0, 0, 0, 0, 0);  /* ordered call */
    ieee80211_phy_init(0, 0, 0, 0, 0, 0);  /* ordered call */
    ieee80211_ht_deattach(0, 0, 0, 0, 0, 0);  /* ordered call */
    ieee80211_set_phy_bw(0, 0, 0, 0, 0, 0);  /* ordered call */
    ieee80211_ht_attach(0, 0, 0, 0, 0, 0);  /* ordered call */
    ieee80211_phy_type_get(0, 0, 0, 0, 0, 0);  /* ordered call */
    ic_update_trc_params(0, 0, 0, 0, 0, 0);  /* ordered call */
    ieee80211_has_ht40_bss(0, 0, 0, 0, 0, 0);  /* ordered call */
    chm_set_home_channel(0, 0, 0, 0, 0, 0);  /* ordered call */
    chm_set_current_channel(0, 0, 0, 0, 0, 0);  /* ordered call */
    /* ---- RECOVERED (medium): channel update (1154B, 20 branches, 2 loops) ----
       Flow: chm_get_home_channel -> ieee80211_is_40mhz_valid_bw (fail x2 -> wifi_log) ->
       chm_set_snd_chan -> ieee80211_phy_init -> ieee80211_ht_deattach ->
       ieee80211_set_phy_bw -> phy_init -> ht_attach -> set_phy_bw ->
       is_40mhz_valid_bw -> phy_type_get -> ic_update_trc_params ->
       ieee80211_has_ht40_bss -> chm_set_home_channel -> wifi_log ->
       chm_set_current_channel. State bytes l8ui +86/+87/+1/+0/+172/+172 (2nd-chan),
       s8i +87/+172/+33; movi 8/3/2/4/14 bw/chan gates; bltu chan-range, bnei mode gates. */
    {
        unsigned __rec_bw40 = 1u; (void)__rec_bw40;
        unsigned __rec_ht40 = 0u; (void)__rec_ht40;
        unsigned __rec_i = 0u;
        if (__rec_bw40 == 0u) { __rec_ht40 = 0u; } else { __rec_ht40 = 1u; }
        for (__rec_i = 0u; __rec_i < 2u; __rec_i++) {
            if (__rec_ht40 == 1u) { break; }
        }
        (void)__rec_i;
    }
    return 0;  /* RE scaffold: original
returns a2; predicates/fields untyped */
}

/* public_recv_action_ht2040_coex @ ieee80211_ht.o 00000000 size 583B bind LOCAL (no symbol; sec .text.public_recv_action_ht2040_coex)
 * Calls: chm_get_current_band, wifi_log, cnx_node_search, chm_get_home_channel, ieee80211_update_channel | Data refs: g_ic, .rodata_wlog_debug.17, .rodata_wlog_debug.18, .rodata_wlog_debug.19, .rodata_wlog_debug.20, .rodata_wlog_debug.21, .rodata_wlog_debug.22, .rodata_wlog_debug.23, .rodata_wlog_info.24, .rodata_wlog_debug.25, .rodata_wlog_info.26, .rodata_wlog_debug.27, .rodata_wlog_debug.28
 * Fidelity: low - large/complex: 34 branches, 6 loop(s), 5 calls; skeleton only */
static int public_recv_action_ht2040_coex(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,48; early arg regs: a2, a6, a7 */
    /* struct offsets touched: 8, 12, 20, 87, 166, 167, 344 */
    /* immediates: -1, 1, 4, 0, 72, 3, 10, 8, -4, -5, 5, 2 */
    /* branches: +0x74 beqz->0x245; +0x77 bnei->0x8F; +0x80 bnei->0x89; +0x86 bbci->0xB9; +0x8c j->0xA4; +0x8f bnei->0xB9; +0x98 bnei->0xA1; +0x9e bbci->0xB9; +0xb6 j->0x245; +0xbf bltui->0xA4 [loop] (+24 more) */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    chm_get_current_band(0, 0, 0, 0, 0, 0);  /* ordered call */
    wifi_log(0, 0, 0, 0, 0, 0);  /* ordered call */
    cnx_node_search(0, 0, 0, 0, 0, 0);  /* ordered call */
    chm_get_home_channel(0, 0, 0, 0, 0, 0);  /* ordered call */
    ieee80211_update_channel(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* ieee80211_ht_updatehtcap @ ieee80211_ht.o 00000018 size 132B bind GLOBAL
 * Calls: chm_get_current_band, ieee80211_parse_htcap, wifi_log, ieee80211_set_phy_bw, ieee80211_update_channel | Data refs: .rodata_wlog_debug.63
 * Fidelity: medium - small frame, 5 calls + 4 branch(es) mapped */
int ieee80211_ht_updatehtcap(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2, a3, a4, a5 */
    /* struct offsets touched: 78, 87, 171, 172, 344, 348 */
    /* immediates: 1, 0, 4, 171 */
    /* branches: +0x36 bbci->0x74; +0x3c bbci->0x65; +0x78 j->0x74 [loop]; +0x7d bbci->0x74 [loop] */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    chm_get_current_band(0, 0, 0, 0, 0, 0);  /* ordered call */
    ieee80211_parse_htcap(0, 0, 0, 0, 0, 0);  /* ordered call */
    wifi_log(0, 0, 0, 0, 0, 0);  /* ordered call */
    ieee80211_set_phy_bw(0, 0, 0, 0, 0, 0);  /* ordered call */
    ieee80211_update_channel(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* ieee80211_ht_updateparams @ ieee80211_ht.o 00000040 size 390B bind GLOBAL
 * Calls: chm_get_home_channel, wifi_log, ieee80211_parse_htcap, ieee80211_update_channel, ic_set_sta, ieee80211_max_bandwidth_negotiation_process | Data refs: .rodata.ieee80211_add_htcap_body.str1.1, .rodata_wlog_error.64, .rodata_wlog_verbose.65, .rodata_wlog_verbose.66
 * Fidelity: medium - small frame, 6 calls + 23 branches mapped (backward-edge marks kept; predicates opaque; verified against section disasm + EXPAND relocs) */
int ieee80211_ht_updateparams(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2, a5, a6 */
    /* struct offsets touched: 12, 87, 95, 96, 97, 98, 172, 228, 344, 348, 352 */
    /* immediates: 1, 12, 3, 221, 4, -3, 0, 8, 5, 171, 192 */
    /* branches: +0x4b beqz.n->0x12 [loop]; +0x4f bnez->0x2E [loop]; +0x68 j->0x28 [loop]; +0x7d bnone->0x6C [loop]; +0x88 beqz.n->0x52 [loop]; +0x8c beqi->0x5A [loop]; +0x8f j->0x64 [loop]; +0xa0 j->0x6A [loop]; +0xb2 beq->0x78 [loop]; +0xb5 j->0x130 (+13 more) */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    chm_get_home_channel(0, 0, 0, 0, 0, 0);  /* ordered call */
    wifi_log(0, 0, 0, 0, 0, 0);  /* ordered call */
    ieee80211_parse_htcap(0, 0, 0, 0, 0, 0);  /* ordered call */
    ieee80211_update_channel(0, 0, 0, 0, 0, 0);  /* ordered call */
    ic_set_sta(0, 0, 0, 0, 0, 0);  /* ordered call */
    ieee80211_max_bandwidth_negotiation_process(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* ieee80211_setup_htrates @ ieee80211_ht.o 00000010 size 187B bind GLOBAL
 * Calls: wifi_log, memset | Data refs: .rodata.ieee80211_add_htcap_body.str1.1, .rodata_wlog_error.67
 * Fidelity: low - hardware loop (loop a10 -> +0xb4) filling MCS rate set (bounds from 0x163/128/127/32/31 immediates; offsets 99/100/103/352); wifi_log + memset order mapped - need per-iteration rate-table field layout to raise */
int ieee80211_setup_htrates(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2, a5 */
    /* struct offsets touched: 99, 100, 103, 352 */
    /* immediates: 1, 0x50d, 0, 38, -3, 76, 52, 0x163, 128, 221, 4, 127 */
    /* branches: +0x13 beqz.n->0x9 [loop]; +0x17 bnez.n->0x24; +0x31 j->0x21 [loop]; +0x3f bbci->0x41; +0x44 bltui->0x41 [loop]; +0x61 beqz->0xB4; +0x6a bne->0x60 [loop]; +0x93 bbc->0xB2; +0x99 beq->0xB4; +0x9c blt->0x92 [loop] (+5 more) */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    wifi_log(0, 0, 0, 0, 0, 0);  /* ordered call */
    memset(0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* ieee80211_setup_basic_htrates @ ieee80211_ht.o 00000018 size 162B bind GLOBAL
 * Calls: wifi_log | Data refs: .rodata.ieee80211_add_htcap_body.str1.1, .rodata_wlog_error.68, .rodata_wlog_warning.69
 * Fidelity: low - hardware loop (loop a9 -> +0x98) filling basic-HT rate set (clamp immediates -128/127, offsets 8/99); wifi_log order mapped - need per-iteration field layout + clamp polarity to raise */
int ieee80211_setup_basic_htrates(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2, a3, a5 */
    /* struct offsets touched: 8, 99 */
    /* immediates: 1, 221, 4, 0, 0xfffffe9c, 0x164, -128, 127, 2, 32, 0x165 */
    /* branches: +0x1b bnez.n->0x21; +0x34 j->0x1C [loop]; +0x3f bne->0x2C [loop]; +0x4c beq->0x49 [loop]; +0x5e j->0x5C [loop]; +0x70 j->0x9D; +0x7f bbc->0x98; +0x93 bge->0x81 [loop]; +0xa2 bne->0x96 [loop]; +0xb2 bne->0x5C [loop] */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    wifi_log(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* ieee80211_add_htcap @ ieee80211_ht.o 00000014 size 60B bind GLOBAL
 * Calls: wifi_log, ieee80211_add_htcap_body[+0x18][local], memset[v2-only] | Data refs: .rodata.ieee80211_add_htcap_body.str1.1, .rodata_wlog_error.71, .rodata_wlog_error.70, g_ic
 * Fidelity: medium - small frame, 3 calls + 2 branch(es) mapped */
int ieee80211_add_htcap(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a3 */
    /* immediates: 1, 45, 26, 2 */
    /* branches: +0x19 bnez.n->0x20; +0x31 j->0x1D [loop] */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    wifi_log(0, 0, 0, 0, 0, 0);  /* ordered call */
    ieee80211_add_htcap_body(0, 0, 0, 0, 0, 0);  /* ordered call[+0x18] [local] */
    memset(0, 0, 0);  /* ordered call [v2-only] */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* ieee80211_add_htcap_vendor @ ieee80211_ht.o 00000004 size 56B bind GLOBAL
 * Calls: ieee80211_add_htcap_body[+0x18][local] | Data refs: none
 * Fidelity: medium - small frame, 1 call + 0 branch(es) mapped */
int ieee80211_add_htcap_vendor(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2, a3 */
    /* immediates: -35, 30, 6, 0, -112, 76, 51 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    ieee80211_add_htcap_body(0, 0, 0, 0, 0, 0);  /* ordered call[+0x18] [local] */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* ieee80211_add_htinfo_body @ ieee80211_ht.o 00000018 size 292B bind GLOBAL
 * Calls: wifi_log, memset, chm_get_home_channel | Data refs: .rodata.ieee80211_add_htcap_body.str1.1, .rodata_wlog_error.72
 * Fidelity: medium - small frame, 3 calls + 16 branches mapped (backward-edge marks kept; predicates opaque; verified against section disasm + EXPAND relocs) */
int ieee80211_add_htinfo_body(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a3, a4 */
    /* struct offsets touched: 86, 87, 184, 185, 344 */
    /* immediates: 1, 22, 0, 8, -1, -5, 3, 4, 6, 0x1ba, -127 */
    /* branches: +0x1b beqz.n->0xA [loop]; +0x1f bnez->0x24; +0x38 j->0x20 [loop]; +0x6e bnei->0x75; +0x7b bltu->0x91; +0x8a j->0x91; +0x8d bnei->0x91; +0x9b bltu->0x91 [loop]; +0xac bnei->0xA5 [loop]; +0xb7 j->0xAE [loop] (+6 more) */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    wifi_log(0, 0, 0, 0, 0, 0);  /* ordered call */
    memset(0, 0, 0);  /* ordered call */
    chm_get_home_channel(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* ieee80211_add_htinfo @ ieee80211_ht.o 00000010 size 64B bind GLOBAL
 * Calls: wifi_log, ieee80211_add_htinfo_body, chm_get_home_channel[v2-only], memset[v2-only] | Data refs: .rodata.ieee80211_add_htcap_body.str1.1, .rodata_wlog_error.73, .rodata_wlog_error.72, .rodata_wlog_error.74
 * Fidelity: medium - small frame, 4 calls + 2 branch(es) mapped */
int ieee80211_add_htinfo(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a3 */
    /* immediates: 1, 0x16b, 61, 22, 2 */
    /* branches: +0x15 bnez.n->0x23; +0x30 j->0x20 [loop] */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    wifi_log(0, 0, 0, 0, 0, 0);  /* ordered call */
    ieee80211_add_htinfo_body(0, 0, 0, 0, 0, 0);  /* ordered call */
    chm_get_home_channel(0, 0, 0, 0, 0, 0);  /* ordered call [v2-only] */
    memset(0, 0, 0);  /* ordered call [v2-only] */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* ieee80211_add_htinfo_vendor @ ieee80211_ht.o 00000014 size 82B bind GLOBAL
 * Calls: wifi_log, ieee80211_add_htinfo_body | Data refs: .rodata.ieee80211_add_htcap_body.str1.1, .rodata_wlog_error.74
 * Fidelity: medium - small frame, 2 calls + 2 branch(es) mapped */
int ieee80211_add_htinfo_vendor(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a3 */
    /* immediates: 1, -35, 26, 6, 0, -112, 76, 52 */
    /* branches: +0x19 bnez.n->0x20; +0x31 j->0x1D [loop] */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    wifi_log(0, 0, 0, 0, 0, 0);  /* ordered call */
    ieee80211_add_htinfo_body(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* ht_action_output @ ieee80211_ht.o 00000008 size 37B bind GLOBAL
 * Calls: ieee80211_set_tx_desc, ieee80211_mgmt_output | Data refs: none
 * Fidelity: medium - small frame, 2 calls + 0 branch(es) mapped */
int ht_action_output(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2, a3 */
    /* immediates: 0, 7, 208 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    ieee80211_set_tx_desc(0, 0, 0, 0, 0, 0);  /* ordered call */
    ieee80211_mgmt_output(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* ht_send_action_ba_delba @ ieee80211_ht.o 00000000 size 240B bind LOCAL (no symbol; sec .text.ht_send_action_ba_delba)
 * Calls: wifi_log, ieee80211_get_robustmgtframe, ht_action_output | Data refs: .rodata.ieee80211_add_htcap_body.str1.1, .rodata_wlog_error.78, .rodata_wlog_warning.79
 * Fidelity: medium - small frame, 3 calls + 5 branch(es) mapped */
static int ht_send_action_ba_delba(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,48; early arg regs: a2 */
    /* struct offsets touched: 20, 44, 251 */
    /* immediates: 1, 0x62d, 6, 24, 2, 0x400 */
    /* branches: +0x23 bnez.n->0x42; +0x3d j->0x3D [loop]; +0x50 beqz->0xDC; +0x59 beqz.n->0x66; +0xd7 j->0xEE */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    wifi_log(0, 0, 0, 0, 0, 0);  /* ordered call */
    ieee80211_get_robustmgtframe(0, 0, 0, 0, 0, 0);  /* ordered call */
    ht_action_output(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* ht_send_action_ba_addba @ ieee80211_ht.o 00000000 size 370B bind LOCAL (no symbol; sec .text.ht_send_action_ba_addba)
 * Calls: wifi_log, ieee80211_get_robustmgtframe, ht_action_output, ampdu_rx_stop_constprop_0[+0x18][local] | Data refs: .rodata.ieee80211_add_htcap_body.str1.1, .rodata_wlog_error.76, .rodata_wlog_warning.77
 * Fidelity: medium - small frame, 4 calls + 10 branches mapped (backward-edge marks kept; predicates opaque; verified against section disasm + EXPAND relocs) */
static int ht_send_action_ba_addba(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,48; early arg regs: a2 */
    /* struct offsets touched: 8, 20, 28, 44, 251, 616 */
    /* immediates: 1, 9, 24, 2, 0x400 */
    /* branches: +0x2b bnez.n->0x4A; +0x44 j->0x44 [loop]; +0x58 beqz->0x14D; +0x61 beqz.n->0x6E; +0x95 bnei->0xB8; +0xf4 bnez.n->0x114; +0x119 bnei->0x13A; +0x128 beqz.n->0x12C; +0x14a j->0x170; +0x14d bnei->0x15E */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    wifi_log(0, 0, 0, 0, 0, 0);  /* ordered call */
    ieee80211_get_robustmgtframe(0, 0, 0, 0, 0, 0);  /* ordered call */
    ht_action_output(0, 0, 0, 0, 0, 0);  /* ordered call */
    ampdu_rx_stop_constprop_0(0, 0, 0, 0, 0, 0);  /* ordered call[+0x18] [local] */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* ieee80211_decap1 @ ieee80211_ht.o 00000004 size 111B bind GLOBAL
 * Calls: memmove | Data refs: none
 * Fidelity: medium - small frame, 1 call + 2 branch(es) mapped */
int ieee80211_decap1(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2 */
    /* struct offsets touched: 12, 13, 20, 22 */
    /* immediates: 21, 14, 8, 6, -8, 0 */
    /* branches: +0x11 bge->0x6B; +0x6c j->0x6D */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    memmove(0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* ieee80211_decap_amsdu @ ieee80211_ht.o 00000028 size 260B bind GLOBAL
 * Calls: ieee80211_decap1, ic_ebuf_alloc, memcpy, memcmp, ieee80211_output, ic_ebuf_recycle_rx | Data refs: g_ic, sta_rxcb, ap_rxcb, g_ic+0x20c
 * Fidelity: medium - small frame, 6 calls + 10 branches mapped (backward-edge marks kept; predicates opaque; verified against section disasm + EXPAND relocs) */
int ieee80211_decap_amsdu(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,64; early arg regs: a3, a4, a5 */
    /* struct offsets touched: 16, 22, 44 */
    /* immediates: 14, -14, 7, 0, 128, 6, 1, 21, 3, -4 */
    /* branches: +0x50 beqz->0xF8; +0x63 beqz->0xF8; +0x8a bne->0x78 [loop]; +0x92 beqz->0xBC; +0x9c j->0xB6; +0xa5 beqz.n->0xBC; +0xb1 bbsi->0xA2 [loop]; +0xc8 beqz.n->0xAE [loop]; +0x100 bgeu->0xF8 [loop]; +0x11c j->0x11 [loop] */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    ieee80211_decap1(0, 0, 0, 0, 0, 0);  /* ordered call */
    ic_ebuf_alloc(0, 0, 0, 0, 0, 0);  /* ordered call */
    memcpy(0, 0, 0);  /* ordered call */
    memcmp(0, 0, 0);  /* ordered call */
    ieee80211_output(0, 0, 0, 0, 0, 0);  /* ordered call */
    ic_ebuf_recycle_rx(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* hostap_ht_operation_update @ ieee80211_ht.o 0000000c size 61B bind GLOBAL
 * Calls: wifi_log | Data refs: .rodata.__func__$0, .rodata_wlog_debug.82
 * Fidelity: medium - small frame, 1 call + 1 branch(es) mapped */
int hostap_ht_operation_update(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2, a3, a4 */
    /* struct offsets touched: 184, 588 */
    /* immediates: 1, 4, 3, 0 */
    /* branches: +0x39 beq->0x38 [loop] */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    wifi_log(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* Notable rodata/log strings in this object (grounded, from Contents sections):
 *   [.text.addba_stop_timeout] "....6A.1..K"...."
 *   [.text.addba_stop_timeout] ".(;.....8.2#<..."
 *   [.text.ampdu_tx_stop] "................"
 *   [.text.ampdu_tx_stop] "........6A......"
 *   [.text.ampdu_tx_stop] "....,..........."
 *   [.text.ampdu_tx_stop] "F... 3.B#..t...."
 *   [.text.ampdu_tx_stop] ".......I.. .Y..."
 *   [.text.ampdu_tx_stop] "....)....&......"
 *   [.text.ampdu_tx_stop] "..).........../K"
 *   [.text.ampdu_tx_stop] "................"
 *   [.text.ampdu_tx_stop] ".!..@. ""."",..."
 *   [.text.ampdu_tx_stop] ".."c.. ..."
 *   [.text.ieee80211_ampdu_timeout] "....6A....+....."
 *   [.text.ieee80211_ampdu_timeout] "......"
 *   [.text.addba_timeout] "....6A.........."
 *   [.text.addba_timeout] "......"
 *   [.text.addba_get_rap_from_private] "6A..... ....t.I0"
 *   [.text.addba_get_rap_from_private] "......h..-...v.."
 *   [.text.addba_get_rap_from_private] ".....z...... .F."
 *   [.text.addba_get_rap_from_private] ".."K.|..."
 *   [.text.addba_response_txcb] "................"
 *   [.text.addba_response_txcb] "................"
 *   [.text.addba_response_txcb] "................"
 *   [.text.addba_response_txcb] "................"
 *   [.text.addba_response_txcb] "............6..."
 */
