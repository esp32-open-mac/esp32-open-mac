/* ieee80211_nan_common.c - reconstructed from ieee80211_nan_common.o (45328 bytes on disk).
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

extern int chm_is_at_home_channel();  /* external, prototype unknown */
extern int chm_set_current_channel();  /* external, prototype unknown */
extern int chm_set_home_channel();  /* external, prototype unknown */
extern int cnx_rc_update_rssi();  /* external, prototype unknown */
extern int hal_disable_nan_tsf();  /* external, prototype unknown */
extern int hal_enable_nan_tsf();  /* external, prototype unknown */
extern int hal_mac_tsf_get_time();  /* external, prototype unknown */
extern int hal_mac_tsf_reset();  /* external, prototype unknown */
extern int hal_mac_tsf_set_time();  /* external, prototype unknown */
extern int hal_now();  /* external, prototype unknown */
extern int ic_ebuf_recycle_rx();  /* external, prototype unknown */
extern int ic_ebuf_recycle_tx();  /* external, prototype unknown */
extern int ic_get_G6M_sched();  /* external, prototype unknown */
extern int ic_get_random();  /* external, prototype unknown */
extern int ic_interface_enabled();  /* external, prototype unknown */
extern int ic_register_nan_callbacks();  /* external, prototype unknown */
extern int ic_register_tx_cb();  /* external, prototype unknown */
extern int ic_set_trc();  /* external, prototype unknown */
extern int ic_set_vif();  /* external, prototype unknown */
extern int ic_tx_pkt();  /* external, prototype unknown */
extern int ieee80211_ampdu_reorder();  /* external, prototype unknown */
extern int ieee80211_ccmp_decrypt();  /* external, prototype unknown */
extern int ieee80211_ccmp_encrypt();  /* external, prototype unknown */
extern int ieee80211_crypto_bip_encrypt_with_key();  /* external, prototype unknown */
extern int ieee80211_crypto_bip_verify_with_key();  /* external, prototype unknown */
extern int ieee80211_crypto_decap();  /* external, prototype unknown */
extern int ieee80211_decap();  /* external, prototype unknown */
extern int ieee80211_empty_txq();  /* external, prototype unknown */
extern int ieee80211_get_robustmgtframe();  /* external, prototype unknown */
extern int ieee80211_getmgtframe();  /* external, prototype unknown */
extern int ieee80211_phy_type_get();  /* external, prototype unknown */
extern int ieee80211_recv_action();  /* external, prototype unknown */
extern int ieee80211_regdomain_get_country();  /* external, prototype unknown */
extern int ieee80211_send_setup();  /* external, prototype unknown */
extern int ieee80211_set_tx_desc();  /* external, prototype unknown */
extern int ieee80211w_get_active_bigtk_key_id();  /* external, prototype unknown */
extern int ieee80211w_get_active_igtk_key_id();  /* external, prototype unknown */
extern int ieee80211w_get_bigtk_from_keyidx();  /* external, prototype unknown */
extern int ieee80211w_get_igtk_from_keyidx();  /* external, prototype unknown */
extern int nan_clear_all_integrity_keys();  /* external, prototype unknown */
extern int nan_dp_deinit();  /* external, prototype unknown */
extern int nan_dp_has_active_datapath();  /* external, prototype unknown */
extern int nan_dp_init();  /* external, prototype unknown */
extern int nan_dp_log_rx();  /* external, prototype unknown */
extern int nan_dp_search_node();  /* external, prototype unknown */
extern int nan_dp_update_ndi();  /* external, prototype unknown */
extern int nan_fill_dynamic_attr();  /* external, prototype unknown */
extern int nan_get_peer_bigtk();  /* external, prototype unknown */
extern int nan_get_peer_igtk();  /* external, prototype unknown */
extern int nan_naf_txcb();  /* external, prototype unknown */
extern int nan_ndp_start_inactivity_timer();  /* external, prototype unknown */
extern int nan_nulldata_txcb();  /* external, prototype unknown */
extern int nan_rx_naf();  /* external, prototype unknown */
extern int nan_rx_sdf();  /* external, prototype unknown */
extern int nan_schedule_disc_bcn();  /* external, prototype unknown */
extern int nan_sdf_txcb();  /* external, prototype unknown */
extern int nan_services_deinit();  /* external, prototype unknown */
extern int nan_services_init();  /* external, prototype unknown */
extern int nan_sm_deinit();  /* external, prototype unknown */
extern int nan_sm_handle_event();  /* external, prototype unknown */
extern int nan_sm_init();  /* external, prototype unknown */
extern int nan_sm_start();  /* external, prototype unknown */
extern int nan_sm_stop();  /* external, prototype unknown */
extern int wifi_event_post();  /* external, prototype unknown */
extern int wifi_log();  /* external, prototype unknown */

int nan_mgmt_txcb(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_get_random_word(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_get_random_byte(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_get_tsf(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_update_tsf(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_is_in_dw(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
static int nan_is_pkt_in_valid_slot(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_action_frames_queued(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_flush_action_q(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_get_clust_id(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_disc_enable_rx(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_disc_disable_rx(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int wifi_nan_reg_rxcb(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_set_update_sdf_pending(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_fill_country_code_attr(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_set_trc(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_set_nm_tk_key(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_get_nm_tk_key(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_transmit_bcn(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_is_pmf_enabled(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_alloc_beacon(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_alloc_sdf(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_alloc_action(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_post_event(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_transmit_action(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_tx_action_frame(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_tx_queued_action_frames(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_start(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_stop(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_set_config_local(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_get_config_local(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_call_service_match_cb(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_call_replied_cb(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_call_receive_cb(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_call_ndp_indication_cb(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_call_ndp_confirm_cb(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_call_ndp_terminated_cb(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_call_action_txdone_cb(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_call_ndp_response_indication_cb(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int esp_nan_internal_register_secure_dp_funcs(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_call_pasn_receive_cb(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_input(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_rx_cb(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_register_callbacks(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);

/* nan_mgmt_txcb @ ieee80211_nan_common.o 00000018 size 149B bind GLOBAL
 * Calls: nan_nulldata_txcb, nan_schedule_disc_bcn, nan_sdf_txcb, nan_naf_txcb | Data refs: g_ic, s_ni
 * Fidelity: low - large/complex: 14 branches, 6 loop(s), 4 calls; skeleton only */
int nan_mgmt_txcb(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2 */
    /* struct offsets touched: 8, 16, 32, 33, 44, 672 */
    /* immediates: 3, 1, 12, -16, 100, 208, 125 */
    /* branches: +0x23 beqz->0x93; +0x37 bne->0x93; +0x4c bnei->0x44 [loop]; +0x4f bnei->0x44 [loop]; +0x58 j->0x93; +0x5c bnez->0x93; +0x5f bnei->0x68; +0x71 bne->0x93; +0x7d j->0x93; +0x83 bne->0x93 (+4 more) */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    nan_nulldata_txcb(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_schedule_disc_bcn(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_sdf_txcb(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_naf_txcb(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_get_random_word @ ieee80211_nan_common.o 00000004 size 13B bind GLOBAL
 * Calls: ic_get_random | Data refs: none
 * Fidelity: high - trivial: straight-line, all targets resolved */
int nan_get_random_word(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    ic_get_random(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_get_random_byte @ ieee80211_nan_common.o 00000004 size 14B bind GLOBAL
 * Calls: ic_get_random | Data refs: none
 * Fidelity: high - trivial: straight-line, all targets resolved */
int nan_get_random_byte(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    ic_get_random(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_get_tsf @ ieee80211_nan_common.o 00000004 size 18B bind GLOBAL
 * Calls: hal_mac_tsf_get_time | Data refs: none
 * Fidelity: high - trivial: straight-line, all targets resolved */
int nan_get_tsf(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2, a3 */
    /* immediates: 2 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    hal_mac_tsf_get_time(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_update_tsf @ ieee80211_nan_common.o 00000008 size 32B bind GLOBAL
 * Calls: hal_mac_tsf_reset, hal_mac_tsf_set_time | Data refs: none
 * Fidelity: medium - small frame, 2 calls + 2 branch(es) mapped */
int nan_update_tsf(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2, a3 */
    /* immediates: 2 */
    /* branches: +0x14 bnez.n->0x18; +0x1c j->0x1E */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    hal_mac_tsf_reset(0, 0, 0, 0, 0, 0);  /* ordered call */
    hal_mac_tsf_set_time(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_is_in_dw @ ieee80211_nan_common.o 00000004 size 26B bind GLOBAL
 * Calls: nan_get_tsf | Data refs: none
 * Fidelity: high - trivial: straight-line, all targets resolved */
int nan_is_in_dw(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2 */
    /* immediates: 31, 1, 0 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    nan_get_tsf(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_is_pkt_in_valid_slot @ ieee80211_nan_common.o 00000000 size 32B bind LOCAL (no symbol; sec .text.nan_is_pkt_in_valid_slot)
 * Calls: nan_is_in_dw | Data refs: s_ni
 * Fidelity: high - trivial: straight-line, all targets resolved */
static int nan_is_pkt_in_valid_slot(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2 */
    /* struct offsets touched: 312 */
    /* immediates: 1 */
    /* branches: +0x13 bne->0x1C */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    nan_is_in_dw(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_action_frames_queued @ ieee80211_nan_common.o 00000004 size 17B bind GLOBAL
 * Calls: none | Data refs: action_q
 * Fidelity: high - trivial: straight-line, all targets resolved */
int nan_action_frames_queued(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2 */
    /* immediates: 0, 1 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_flush_action_q @ ieee80211_nan_common.o 00000008 size 42B bind GLOBAL
 * Calls: ic_ebuf_recycle_tx | Data refs: action_q
 * Fidelity: medium - small frame, 1 call + 4 branch(es) mapped */
int nan_flush_action_q(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2, a3 */
    /* struct offsets touched: 40 */
    /* immediates: 0 */
    /* branches: +0x10 beqz.n->0x28; +0x16 beqz.n->0x28; +0x1c bnez.n->0x19 [loop]; +0x2c j->0xC [loop] */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    ic_ebuf_recycle_tx(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_get_clust_id @ ieee80211_nan_common.o 00000004 size 8B bind GLOBAL
 * Calls: none | Data refs: s_ni+0x130, s_ni
 * Fidelity: high - trivial: straight-line, all targets resolved */
int nan_get_clust_id(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_disc_enable_rx @ ieee80211_nan_common.o 00000004 size 19B bind GLOBAL
 * Calls: none | Data refs: .bss.s_nan_rx_enabled
 * Fidelity: high - trivial: straight-line, all targets resolved */
int nan_disc_enable_rx(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: none observed */
    /* immediates: 1 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_disc_disable_rx @ ieee80211_nan_common.o 00000004 size 19B bind GLOBAL
 * Calls: none | Data refs: .bss.s_nan_rx_enabled
 * Fidelity: high - trivial: straight-line, all targets resolved */
int nan_disc_disable_rx(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: none observed */
    /* immediates: 0 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* wifi_nan_reg_rxcb @ ieee80211_nan_common.o 00000004 size 13B bind GLOBAL
 * Calls: none | Data refs: ndp_rxcb
 * Fidelity: high - trivial: straight-line, all targets resolved */
int wifi_nan_reg_rxcb(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_set_update_sdf_pending @ ieee80211_nan_common.o 00000004 size 20B bind GLOBAL
 * Calls: none | Data refs: s_ni
 * Fidelity: high - trivial: straight-line, all targets resolved */
int nan_set_update_sdf_pending(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2 */
    /* struct offsets touched: 88 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_fill_country_code_attr @ ieee80211_nan_common.o 00000010 size 75B bind GLOBAL
 * Calls: ieee80211_regdomain_get_country, memcmp | Data refs: .rodata.nan_fill_country_code_attr.str1.1
 * Fidelity: medium - small frame, 2 calls + 1 branch(es) mapped */
int nan_fill_country_code_attr(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2, a3 */
    /* immediates: 2, 11, 0, 3, 5 */
    /* branches: +0x40 bnez.n->0x35 [loop] */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    ieee80211_regdomain_get_country(0, 0, 0, 0, 0, 0);  /* ordered call */
    memcmp(0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_set_trc @ ieee80211_nan_common.o 0000000c size 126B bind GLOBAL
 * Calls: memset, ieee80211_phy_type_get, ic_set_trc | Data refs: none
 * Fidelity: medium - small frame, 3 calls + 2 branch(es) mapped */
int nan_set_trc(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,64; early arg regs: a2, a3 */
    /* struct offsets touched: 8, 10, 12, 16, 20, 24, 25, 26, 38, 94, 164, 239, 243 */
    /* immediates: 28, 0, 4, 2, 131 */
    /* branches: +0x20 beqz->0x7C; +0x25 beqz->0x7C */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    memset(0, 0, 0);  /* ordered call */
    ieee80211_phy_type_get(0, 0, 0, 0, 0, 0);  /* ordered call */
    ic_set_trc(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_set_nm_tk_key @ ieee80211_nan_common.o 00000008 size 32B bind GLOBAL
 * Calls: none | Data refs: s_ni, g_osi_funcs_p
 * Fidelity: high - trivial: straight-line, all targets resolved */
int nan_set_nm_tk_key(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2, a3 */
    /* struct offsets touched: 176, 372 */
    /* branches: +0x11 beqz->0x18 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_get_nm_tk_key @ ieee80211_nan_common.o 00000004 size 11B bind GLOBAL
 * Calls: none | Data refs: s_ni
 * Fidelity: high - trivial: straight-line, all targets resolved */
int nan_get_nm_tk_key(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2 */
    /* struct offsets touched: 372 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_transmit_bcn @ ieee80211_nan_common.o 00000050 size 335B bind GLOBAL
 * Calls: nan_fill_dynamic_attr, hal_now, ieee80211w_get_active_bigtk_key_id, ieee80211w_get_bigtk_from_keyidx, ieee80211_crypto_bip_encrypt_with_key, wifi_log, chm_is_at_home_channel, ic_tx_pkt | Data refs: .rodata_wlog_error.14, s_ni, .rodata_wlog_error.15, .rodata_wlog_error.16, .rodata_wlog_error.17
 * Fidelity: low - large/complex: 11 branches, 9 loop(s), 8 calls; skeleton only */
int nan_transmit_bcn(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2, a3, a4, a5 */
    /* struct offsets touched: 20, 22, 24, 44, 89, 206 */
    /* immediates: 4, 1, 44, 2, 9, -1 */
    /* branches: +0x56 beqz->0x140; +0x67 bbci->0x1D [loop]; +0x6d bbci->0x23 [loop]; +0x70 j->0x14D; +0x7c beqz->0x35 [loop]; +0xbf beq->0x9E [loop]; +0xcc beqz.n->0x9E [loop]; +0xdc beqz.n->0x9E [loop]; +0x15e beqz.n->0x13D [loop]; +0x168 bnei->0x14D [loop] (+1 more) */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    nan_fill_dynamic_attr(0, 0, 0, 0, 0, 0);  /* ordered call */
    hal_now(0, 0, 0, 0, 0, 0);  /* ordered call */
    ieee80211w_get_active_bigtk_key_id(0, 0, 0, 0, 0, 0);  /* ordered call */
    ieee80211w_get_bigtk_from_keyidx(0, 0, 0, 0, 0, 0);  /* ordered call */
    ieee80211_crypto_bip_encrypt_with_key(0, 0, 0, 0, 0, 0);  /* ordered call */
    wifi_log(0, 0, 0, 0, 0, 0);  /* ordered call */
    chm_is_at_home_channel(0, 0, 0, 0, 0, 0);  /* ordered call */
    ic_tx_pkt(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_is_pmf_enabled @ ieee80211_nan_common.o 00000004 size 28B bind GLOBAL
 * Calls: none | Data refs: g_ic
 * Fidelity: high - trivial: straight-line, all targets resolved */
int nan_is_pmf_enabled(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2 */
    /* struct offsets touched: 251, 576, 672 */
    /* immediates: 0 */
    /* branches: +0xf beq->0x1A; +0x15 beq->0x1A */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_alloc_beacon @ ieee80211_nan_common.o 00000038 size 191B bind GLOBAL
 * Calls: wifi_log, ieee80211_getmgtframe, memset, ieee80211_send_setup, ieee80211_set_tx_desc, ic_get_G6M_sched | Data refs: .rodata.nan_alloc_beacon.str1.1, .rodata_wlog_error.18, .rodata_wlog_error.19, g_ic, ieee80211_ethbroadcast
 * Fidelity: medium - small frame, 6 calls + 5 branch(es) mapped */
int nan_alloc_beacon(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,64; early arg regs: a2, a4 */
    /* struct offsets touched: 12, 16, 20, 24, 28, 36, 44 */
    /* immediates: 1, 0x29b, 24, 62, 0, 16, 128, 7, 11, 0x200 */
    /* branches: +0x3d beqz->0xE [loop]; +0x43 bnez->0x28 [loop]; +0x5c j->0x24 [loop]; +0x6e bnez.n->0x4C [loop]; +0x80 j->0xBA */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    wifi_log(0, 0, 0, 0, 0, 0);  /* ordered call */
    ieee80211_getmgtframe(0, 0, 0, 0, 0, 0);  /* ordered call */
    memset(0, 0, 0);  /* ordered call */
    ieee80211_send_setup(0, 0, 0, 0, 0, 0);  /* ordered call */
    ieee80211_set_tx_desc(0, 0, 0, 0, 0, 0);  /* ordered call */
    ic_get_G6M_sched(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_alloc_sdf @ ieee80211_nan_common.o 00000040 size 341B bind GLOBAL
 * Calls: wifi_log, ieee80211w_get_active_igtk_key_id, ieee80211_getmgtframe, ieee80211_get_robustmgtframe, memset, ieee80211_send_setup, ieee80211_set_tx_desc, ic_get_G6M_sched | Data refs: g_ic, .rodata.nan_alloc_beacon.str1.1, .rodata_wlog_error.21, .rodata_wlog_error.22
 * Fidelity: low - large/complex: 12 branches, 11 loop(s), 8 calls; skeleton only */
int nan_alloc_sdf(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,80; early arg regs: a4, a5, a6, a7 */
    /* struct offsets touched: 12, 16, 20, 22, 28, 32, 36, 44, 536, 576, 672 */
    /* immediates: 1, 0x2d0, 6, 2, 24, 0, -18, 16, 208, 11, 7 */
    /* branches: +0x53 beqz.n->0x19 [loop]; +0x57 bnez.n->0x39 [loop]; +0x74 j->0x34 [loop]; +0x7e bbci->0x68 [loop]; +0x8e beq->0x54 [loop]; +0xa4 j->0x9C [loop]; +0xa8 beqz.n->0x82 [loop]; +0xbf j->0x9C [loop]; +0xdc bnez.n->0xB4 [loop]; +0xf0 j->0x14E (+2 more) */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    wifi_log(0, 0, 0, 0, 0, 0);  /* ordered call */
    ieee80211w_get_active_igtk_key_id(0, 0, 0, 0, 0, 0);  /* ordered call */
    ieee80211_getmgtframe(0, 0, 0, 0, 0, 0);  /* ordered call */
    ieee80211_get_robustmgtframe(0, 0, 0, 0, 0, 0);  /* ordered call */
    memset(0, 0, 0);  /* ordered call */
    ieee80211_send_setup(0, 0, 0, 0, 0, 0);  /* ordered call */
    ieee80211_set_tx_desc(0, 0, 0, 0, 0, 0);  /* ordered call */
    ic_get_G6M_sched(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_alloc_action @ ieee80211_nan_common.o 00000034 size 275B bind GLOBAL
 * Calls: wifi_log, ieee80211_get_robustmgtframe, ieee80211_getmgtframe, memset, ieee80211_send_setup, ieee80211_set_tx_desc, ic_get_G6M_sched | Data refs: g_ic, .rodata.nan_alloc_beacon.str1.1, .rodata_wlog_error.23, .rodata_wlog_error.24
 * Fidelity: medium - small frame, 7 calls + 8 branch(es) mapped */
int nan_alloc_action(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,80; early arg regs: a2, a6, a7 */
    /* struct offsets touched: 12, 16, 20, 22, 24, 28, 32, 36, 44, 576, 672 */
    /* immediates: 1, 0x31b, 7, 24, 0, 16, 208, 11, 0x200 */
    /* branches: +0x45 beqz->0x1A [loop]; +0x4b bnez->0x35 [loop]; +0x64 j->0x30 [loop]; +0x6b beqz.n->0x68 [loop]; +0x84 bnez.n->0x82 [loop]; +0x98 j->0x10E; +0xb1 bnez.n->0x8E [loop]; +0xb3 j->0x52 [loop] */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    wifi_log(0, 0, 0, 0, 0, 0);  /* ordered call */
    ieee80211_get_robustmgtframe(0, 0, 0, 0, 0, 0);  /* ordered call */
    ieee80211_getmgtframe(0, 0, 0, 0, 0, 0);  /* ordered call */
    memset(0, 0, 0);  /* ordered call */
    ieee80211_send_setup(0, 0, 0, 0, 0, 0);  /* ordered call */
    ieee80211_set_tx_desc(0, 0, 0, 0, 0, 0);  /* ordered call */
    ic_get_G6M_sched(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_post_event @ ieee80211_nan_common.o 00000004 size 18B bind GLOBAL
 * Calls: wifi_event_post | Data refs: none
 * Fidelity: high - trivial: straight-line, all targets resolved */
int nan_post_event(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2, a3, a4 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    wifi_event_post(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_transmit_action @ ieee80211_nan_common.o 0000004c size 410B bind GLOBAL
 * Calls: hal_now, memmove, ieee80211_ccmp_encrypt, ieee80211w_get_active_igtk_key_id, ieee80211w_get_igtk_from_keyidx, ieee80211_crypto_bip_encrypt_with_key, wifi_log, chm_is_at_home_channel, ic_tx_pkt | Data refs: g_ic, s_ni, .rodata_wlog_error.25, .rodata_wlog_error.26, .rodata_wlog_error.27
 * Fidelity: low - large/complex: 16 branches, 12 loop(s), 9 calls; skeleton only */
int nan_transmit_action(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2, a3, a4, a5 */
    /* struct offsets touched: 20, 22, 24, 44, 160, 206, 372, 576, 672 */
    /* immediates: 4, 1, -2, -65, 8, -8, 2, 18, 76, -18, 9, -1 */
    /* branches: +0x63 bbci->0x1C [loop]; +0x8b bbci->0x9C; +0x98 bnez.n->0x8C [loop]; +0xd4 j->0x9C [loop]; +0xdd bnei->0x9C [loop]; +0xee bbsi->0x10C; +0xf3 bbci->0xAC [loop]; +0xfb bbci->0x10C; +0x10b beq->0x10C; +0x118 beqz.n->0x10C [loop] (+6 more) */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    hal_now(0, 0, 0, 0, 0, 0);  /* ordered call */
    memmove(0, 0, 0);  /* ordered call */
    ieee80211_ccmp_encrypt(0, 0, 0, 0, 0, 0);  /* ordered call */
    ieee80211w_get_active_igtk_key_id(0, 0, 0, 0, 0, 0);  /* ordered call */
    ieee80211w_get_igtk_from_keyidx(0, 0, 0, 0, 0, 0);  /* ordered call */
    ieee80211_crypto_bip_encrypt_with_key(0, 0, 0, 0, 0, 0);  /* ordered call */
    wifi_log(0, 0, 0, 0, 0, 0);  /* ordered call */
    chm_is_at_home_channel(0, 0, 0, 0, 0, 0);  /* ordered call */
    ic_tx_pkt(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_tx_action_frame @ ieee80211_nan_common.o 0000001c size 70B bind GLOBAL
 * Calls: nan_is_in_dw, nan_transmit_action, wifi_log | Data refs: .rodata_wlog_debug.2, .rodata_wlog_debug.3, action_q
 * Fidelity: medium - small frame, 3 calls + 3 branch(es) mapped */
int nan_tx_action_frame(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2 */
    /* struct offsets touched: 40 */
    /* immediates: 4, 1, 0, 40 */
    /* branches: +0x25 beqz.n->0x1E [loop]; +0x35 bnez.n->0x24 [loop]; +0x37 j->0x41 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    nan_is_in_dw(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_transmit_action(0, 0, 0, 0, 0, 0);  /* ordered call */
    wifi_log(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_tx_queued_action_frames @ ieee80211_nan_common.o 00000018 size 89B bind GLOBAL
 * Calls: nan_is_in_dw, wifi_log, nan_transmit_action | Data refs: action_q, .rodata_wlog_debug.4
 * Fidelity: medium - small frame, 3 calls + 7 branch(es) mapped */
int nan_tx_queued_action_frames(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2, a3, a4 */
    /* struct offsets touched: 40 */
    /* immediates: 0, 4, 1, 40 */
    /* branches: +0x22 beq->0x54; +0x2b bnez.n->0x28 [loop]; +0x3d j->0x54; +0x42 beqz.n->0x54; +0x48 bnez.n->0x34 [loop]; +0x59 beqz->0xD [loop]; +0x61 bnez->0x52 [loop] */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    nan_is_in_dw(0, 0, 0, 0, 0, 0);  /* ordered call */
    wifi_log(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_transmit_action(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_start @ ieee80211_nan_common.o 0000004c size 267B bind GLOBAL
 * Calls: ic_set_vif, ic_register_tx_cb, ic_register_nan_callbacks, memset, hal_enable_nan_tsf, chm_set_home_channel, chm_set_current_channel, nan_sm_start, nan_services_init, nan_dp_init | Data refs: g_ic, g_nan_started, g_ic+0x218, nan_mgmt_txcb, .text.nan_is_pkt_in_valid_slot, action_q, s_ni
 * Fidelity: medium - small frame, 10 calls + 3 branch(es) mapped */
int nan_start(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2, a3, a4 */
    /* struct offsets touched: 12, 53, 55, 58, 86, 87, 208, 312, 320, 576, 672 */
    /* immediates: 0, 2, 1, 9, 174, 36, -16, 210, 18, 246, -1, 0x156 */
    /* branches: +0x58 beqz->0x109; +0x80 beqz->0xF8; +0x115 beqz.n->0xF8 [loop] */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    ic_set_vif(0, 0, 0, 0, 0, 0);  /* ordered call */
    ic_register_tx_cb(0, 0, 0, 0, 0, 0);  /* ordered call */
    ic_register_nan_callbacks(0, 0, 0, 0, 0, 0);  /* ordered call */
    memset(0, 0, 0);  /* ordered call */
    hal_enable_nan_tsf(0, 0, 0, 0, 0, 0);  /* ordered call */
    chm_set_home_channel(0, 0, 0, 0, 0, 0);  /* ordered call */
    chm_set_current_channel(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_sm_start(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_services_init(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_dp_init(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_stop @ ieee80211_nan_common.o 00000044 size 170B bind GLOBAL
 * Calls: wifi_log, ieee80211_empty_txq, nan_dp_deinit, nan_services_deinit, nan_clear_all_integrity_keys, nan_sm_stop, nan_sm_deinit, nan_flush_action_q, hal_disable_nan_tsf, nan_set_nm_tk_key, ic_set_vif, wifi_event_post | Data refs: g_ic, g_nan_started, .rodata_wlog_error.28, s_ni
 * Fidelity: medium - small frame, 12 calls + 2 branch(es) mapped */
int nan_stop(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2, a3 */
    /* struct offsets touched: 12, 164, 168, 576, 672 */
    /* immediates: 0, 1, 2, -17, 36 */
    /* branches: +0x58 bnez.n->0x2C [loop]; +0x6d j->0xA6 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    wifi_log(0, 0, 0, 0, 0, 0);  /* ordered call */
    ieee80211_empty_txq(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_dp_deinit(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_services_deinit(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_clear_all_integrity_keys(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_sm_stop(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_sm_deinit(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_flush_action_q(0, 0, 0, 0, 0, 0);  /* ordered call */
    hal_disable_nan_tsf(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_set_nm_tk_key(0, 0, 0, 0, 0, 0);  /* ordered call */
    ic_set_vif(0, 0, 0, 0, 0, 0);  /* ordered call */
    wifi_event_post(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_set_config_local @ ieee80211_nan_common.o 0000004c size 290B bind GLOBAL
 * Calls: wifi_log, memset, nan_dp_update_ndi, nan_sm_init, ic_interface_enabled, chm_set_home_channel, chm_set_current_channel, nan_sm_start | Data refs: g_ic, s_ni, .rodata_wlog_error.29, s_ni+0xd0, g_ic+0x21b, g_osi_funcs_p, g_ic+0x218, .rodata_wlog_info.30, g_ic+0x200
 * Fidelity: medium - small frame, 8 calls + 6 branch(es) mapped */
int nan_set_config_local(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,48; early arg regs: a2, a3, a4 */
    /* struct offsets touched: 8, 9, 12, 24, 25, 26, 27, 28, 29, 86, 87, 208, 209, 210 */
    /* immediates: 1, 0x103, 10, 5, 120, 3, -2, 2, 0, 0x156 */
    /* branches: +0x5a beqz.n->0x29 [loop]; +0x70 j->0x120; +0x95 bnez.n->0x4D [loop]; +0xa2 bnez->0x5C [loop]; +0xc6 bnez.n->0xB0 [loop]; +0x13a beq->0x120 [loop] */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    wifi_log(0, 0, 0, 0, 0, 0);  /* ordered call */
    memset(0, 0, 0);  /* ordered call */
    nan_dp_update_ndi(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_sm_init(0, 0, 0, 0, 0, 0);  /* ordered call */
    ic_interface_enabled(0, 0, 0, 0, 0, 0);  /* ordered call */
    chm_set_home_channel(0, 0, 0, 0, 0, 0);  /* ordered call */
    chm_set_current_channel(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_sm_start(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_get_config_local @ ieee80211_nan_common.o 00000008 size 26B bind GLOBAL
 * Calls: memcpy | Data refs: s_ni+0xd0, s_ni
 * Fidelity: high - trivial: straight-line, all targets resolved */
int nan_get_config_local(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2 */
    /* immediates: 0x102, 10, 0 */
    /* branches: +0x10 beqz.n->0x18 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    memcpy(0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_call_service_match_cb @ ieee80211_nan_common.o 0000000c size 128B bind GLOBAL
 * Calls: memset, memcpy | Data refs: s_nan_cb
 * Fidelity: medium - small frame, 2 calls + 3 branch(es) mapped */
int nan_call_service_match_cb(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,80; early arg regs: a2, a3, a5 */
    /* struct offsets touched: 8, 12, 20, 22, 24, 26, 28, 32, 36, 120, 328, 332 */
    /* immediates: 36, 0, 4, 1, 6, 0x150 */
    /* branches: +0x17 beqz->0x7E; +0x1a beqz->0x7E; +0x1d bgeui->0x7E */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    memset(0, 0, 0);  /* ordered call */
    memcpy(0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_call_replied_cb @ ieee80211_nan_common.o 0000000c size 99B bind GLOBAL
 * Calls: memset, memcpy | Data refs: s_nan_cb
 * Fidelity: medium - small frame, 2 calls + 3 branch(es) mapped */
int nan_call_replied_cb(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,80; early arg regs: a2, a3, a4, a5 */
    /* struct offsets touched: 12, 20, 22, 24, 32, 36, 328, 332 */
    /* immediates: 36, 0, 4, 1, 6 */
    /* branches: +0x1a beqz->0x61; +0x1d beqz->0x61; +0x20 bgeui->0x61 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    memset(0, 0, 0);  /* ordered call */
    memcpy(0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_call_receive_cb @ ieee80211_nan_common.o 0000000c size 108B bind GLOBAL
 * Calls: memset, memcpy | Data refs: s_nan_cb
 * Fidelity: medium - small frame, 2 calls + 3 branch(es) mapped */
int nan_call_receive_cb(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,80; early arg regs: a2, a3, a6, a7 */
    /* struct offsets touched: 8, 12, 20, 22, 24, 28, 32, 328, 332 */
    /* immediates: 36, 0, 4, 1, 6 */
    /* branches: +0x1a beqz->0x6A; +0x1d beqz->0x6A; +0x20 bgeui->0x6A */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    memset(0, 0, 0);  /* ordered call */
    memcpy(0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_call_ndp_indication_cb @ ieee80211_nan_common.o 00000018 size 120B bind GLOBAL
 * Calls: memset, memcpy, wifi_log | Data refs: s_nan_cb, .rodata_wlog_debug.31
 * Fidelity: medium - small frame, 3 calls + 1 branch(es) mapped */
int nan_call_ndp_indication_cb(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,80; early arg regs: a2, a3, a7 */
    /* struct offsets touched: 12, 16, 20, 32, 80 */
    /* immediates: 12, 0, 6, 1, 7, 4 */
    /* branches: +0x29 beqz->0x76 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    memset(0, 0, 0);  /* ordered call */
    memcpy(0, 0, 0);  /* ordered call */
    wifi_log(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_call_ndp_confirm_cb @ ieee80211_nan_common.o 00000010 size 103B bind GLOBAL
 * Calls: memset, memcpy | Data refs: s_nan_cb
 * Fidelity: medium - small frame, 2 calls + 1 branch(es) mapped */
int nan_call_ndp_confirm_cb(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,80; early arg regs: a2, a3, a7 */
    /* struct offsets touched: 16, 20, 32, 36, 80, 84 */
    /* immediates: 12, 0, 6, 1, 7 */
    /* branches: +0x23 beqz->0x65 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    memset(0, 0, 0);  /* ordered call */
    memcpy(0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_call_ndp_terminated_cb @ ieee80211_nan_common.o 00000004 size 23B bind GLOBAL
 * Calls: none | Data refs: s_nan_cb
 * Fidelity: high - trivial: straight-line, all targets resolved */
int nan_call_ndp_terminated_cb(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2, a3, a4 */
    /* struct offsets touched: 20 */
    /* branches: +0x14 beqz.n->0x15 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_call_action_txdone_cb @ ieee80211_nan_common.o 00000004 size 20B bind GLOBAL
 * Calls: none | Data refs: s_nan_cb
 * Fidelity: high - trivial: straight-line, all targets resolved */
int nan_call_action_txdone_cb(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2, a3 */
    /* struct offsets touched: 24 */
    /* branches: +0x11 beqz.n->0x12 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_call_ndp_response_indication_cb @ ieee80211_nan_common.o 00000010 size 67B bind GLOBAL
 * Calls: memset, memcpy | Data refs: s_nan_cb
 * Fidelity: medium - small frame, 2 calls + 1 branch(es) mapped */
int nan_call_ndp_response_indication_cb(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,64; early arg regs: a2, a3, a5 */
    /* struct offsets touched: 28 */
    /* immediates: 12, 0, 6, 1, 7 */
    /* branches: +0x1b beqz.n->0x41 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    memset(0, 0, 0);  /* ordered call */
    memcpy(0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* esp_nan_internal_register_secure_dp_funcs @ ieee80211_nan_common.o 00000004 size 15B bind GLOBAL
 * Calls: none | Data refs: g_nan_secure_dp_funcs
 * Fidelity: high - trivial: straight-line, all targets resolved */
int esp_nan_internal_register_secure_dp_funcs(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2 */
    /* immediates: 0 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_call_pasn_receive_cb @ ieee80211_nan_common.o 00000004 size 26B bind GLOBAL
 * Calls: none | Data refs: s_nan_cb
 * Fidelity: high - trivial: straight-line, all targets resolved */
int nan_call_pasn_receive_cb(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2, a3, a4, a5 */
    /* struct offsets touched: 32 */
    /* branches: +0x16 beqz->0x18 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_input @ ieee80211_nan_common.o 000000dc size 1340B bind GLOBAL
 * Calls: nan_dp_search_node, hal_now, cnx_rc_update_rssi, nan_ndp_start_inactivity_timer, ieee80211_ampdu_reorder, nan_dp_has_active_datapath, ieee80211_crypto_decap, nan_dp_log_rx, ieee80211_decap, memcmp, nan_get_peer_bigtk, ieee80211_crypto_bip_verify_with_key, nan_sm_handle_event, ieee80211_ccmp_decrypt, wifi_log, nan_get_peer_igtk, nan_rx_sdf, nan_rx_naf, ieee80211_recv_action, nan_call_pasn_receive_cb, ic_ebuf_recycle_rx | Data refs: g_ic, .bss.s_nan_rx_enabled, ndp_rxcb, NAN_STANDARD_BSSID, s_ni, NAN_STANDARD_OUI, .rodata_wlog_debug.5, .rodata_wlog_error.6, .rodata_wlog_error.7, .rodata_wlog_debug.8, .rodata_wlog_error.9, .rodata_wlog_debug.10, NAN_ACTION_OUI, .rodata_wlog_debug.11, .rodata_wlog_debug.12, .rodata_wlog_error.13, NAN_NETWORK_ID
 * Fidelity: low - large/complex: 101 branches, 73 loop(s), 21 calls; skeleton only */
int nan_input(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,96; early arg regs: a2, a4, a5, a6 */
    /* struct offsets touched: 8, 10, 11, 12, 13, 14, 15, 16, 20, 22, 24, 25, 26, 28 */
    /* immediates: 24, -116, -3, 30, 136, 2, 0, 4, -4, 12, 10, 1 */
    /* branches: +0x107 bbci->0x55 [loop]; +0x11a bne->0x44 [loop]; +0x122 blt->0x4C [loop]; +0x125 j->0x134; +0x12d j->0x134; +0x143 bne->0x6C [loop]; +0x148 bgez->0x71 [loop]; +0x16e beqz->0x504; +0x177 beqz->0x504; +0x188 beqz.n->0xE8 [loop] (+91 more) */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    nan_dp_search_node(0, 0, 0, 0, 0, 0);  /* ordered call */
    hal_now(0, 0, 0, 0, 0, 0);  /* ordered call */
    cnx_rc_update_rssi(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_ndp_start_inactivity_timer(0, 0, 0, 0, 0, 0);  /* ordered call */
    ieee80211_ampdu_reorder(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_dp_has_active_datapath(0, 0, 0, 0, 0, 0);  /* ordered call */
    ieee80211_crypto_decap(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_dp_log_rx(0, 0, 0, 0, 0, 0);  /* ordered call */
    ieee80211_decap(0, 0, 0, 0, 0, 0);  /* ordered call */
    memcmp(0, 0, 0);  /* ordered call */
    nan_get_peer_bigtk(0, 0, 0, 0, 0, 0);  /* ordered call */
    ieee80211_crypto_bip_verify_with_key(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_sm_handle_event(0, 0, 0, 0, 0, 0);  /* ordered call */
    ieee80211_ccmp_decrypt(0, 0, 0, 0, 0, 0);  /* ordered call */
    wifi_log(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_get_peer_igtk(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_rx_sdf(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_rx_naf(0, 0, 0, 0, 0, 0);  /* ordered call */
    ieee80211_recv_action(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_call_pasn_receive_cb(0, 0, 0, 0, 0, 0);  /* ordered call */
    ic_ebuf_recycle_rx(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_rx_cb @ ieee80211_nan_common.o 00000004 size 20B bind GLOBAL
 * Calls: nan_input | Data refs: none
 * Fidelity: high - trivial: straight-line, all targets resolved */
int nan_rx_cb(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2, a3, a4 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    nan_input(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_register_callbacks @ ieee80211_nan_common.o 0000000c size 32B bind GLOBAL
 * Calls: memcpy, memset | Data refs: s_nan_cb
 * Fidelity: medium - small frame, 2 calls + 2 branch(es) mapped */
int nan_register_callbacks(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2 */
    /* immediates: 52 */
    /* branches: +0x17 beqz->0x18; +0x20 j->0x1E [loop] */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    memcpy(0, 0, 0);  /* ordered call */
    memset(0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* Notable rodata/log strings in this object (grounded, from Contents sections):
 *   [.text.nan_mgmt_txcb] "................"
 *   [.text.nan_mgmt_txcb] "........6A......"
 *   [.text.nan_mgmt_txcb] ".(..H..8......L."
 *   [.text.nan_mgmt_txcb] ".........p....|."
 *   [.text.nan_mgmt_txcb] ".(..........f..f"
 *   [.text.nan_mgmt_txcb] "............V..f"
 *   [.text.nan_mgmt_txcb] "....!..... .. .."
 *   [.text.nan_mgmt_txcb] "d..6............"
 *   [.text.nan_mgmt_txcb] ".....$.,..d.8..."
 *   [.text.nan_mgmt_txcb] "}..d.X.........."
 *   [.text.nan_mgmt_txcb] "..F.........."
 *   [.text.nan_get_random_word] "....6A.......-.."
 *   [.text.nan_get_random_byte] "....6A........ t"
 *   [.text.nan_get_tsf] "....6A.........."
 *   [.text.nan_get_tsf] "-.=..."
 *   [.text.nan_update_tsf] "........6A.0. .."
 *   [.text.nan_update_tsf] "...*............"
 *   [.text.nan_update_tsf] "........"
 *   [.text.nan_is_in_dw] "....6A........."
 *   [.text.nan_is_in_dw] "..........(..."
 *   [.text.nan_is_pkt_in_valid_slot] "........6A......"
 *   [.text.nan_is_pkt_in_valid_slot] ".(N'........-..."
 *   [.text.nan_action_frames_queued] "....6A.!........"
 *   [.text.nan_action_frames_queued] ".(..."
 *   [.text.nan_flush_action_q] "........6A.!..8."
 */
