/* ieee80211_sta.o - reconstructed control-path C (offline, from objdump -d -r).
 * 41 code sections recovered. Fidelity per function below.
 * Conventions: args a2..a7 (Xtensa windowed ABI); outgoing call args
 * traced as a10..; u32 used for pointers/regs; opaque_* marks unrecovered.
 */
#include <stdint.h>
typedef unsigned char u8; typedef unsigned short u16; typedef unsigned int u32;
static u32 opaque_result, last_call_result;
/* ---- externals (U symbols + literal refs) ---- */
extern u32 bss_s_disconnect_evt_pending; /* .bss.s_disconnect_evt_pending */
extern u32 bss_s_pending_disconnect_evt; /* .bss.s_pending_disconnect_evt */
extern u32 rodata_ieee80211_set_bss_max_idle_period_str1_1; /* .rodata.ieee80211_set_bss_max_idle_period.str1.1 */
extern u32 rodata_ieee80211_sta_new_state_str1_1; /* .rodata.ieee80211_sta_new_state.str1.1 */
extern u32 rodata_sta_recv_assoc_str1_1; /* .rodata.sta_recv_assoc.str1.1 */
extern u32 rodata_sta_rx_csa_str1_1; /* .rodata.sta_rx_csa.str1.1 */
extern u32 rodata_state_desc_0; /* .rodata.state_desc$0 */
extern u32 rodata_str1_1; /* .rodata.str1.1 */
extern u32 rodata_wlog_debug_10; /* .rodata_wlog_debug.10 */
extern u32 rodata_wlog_debug_101; /* .rodata_wlog_debug.101 */
extern u32 rodata_wlog_debug_102; /* .rodata_wlog_debug.102 */
extern u32 rodata_wlog_debug_11; /* .rodata_wlog_debug.11 */
extern u32 rodata_wlog_debug_12; /* .rodata_wlog_debug.12 */
extern u32 rodata_wlog_debug_13; /* .rodata_wlog_debug.13 */
extern u32 rodata_wlog_debug_14; /* .rodata_wlog_debug.14 */
extern u32 rodata_wlog_debug_15; /* .rodata_wlog_debug.15 */
extern u32 rodata_wlog_debug_16; /* .rodata_wlog_debug.16 */
extern u32 rodata_wlog_debug_17; /* .rodata_wlog_debug.17 */
extern u32 rodata_wlog_debug_18; /* .rodata_wlog_debug.18 */
extern u32 rodata_wlog_debug_19; /* .rodata_wlog_debug.19 */
extern u32 rodata_wlog_debug_20; /* .rodata_wlog_debug.20 */
extern u32 rodata_wlog_debug_21; /* .rodata_wlog_debug.21 */
extern u32 rodata_wlog_debug_22; /* .rodata_wlog_debug.22 */
extern u32 rodata_wlog_debug_23; /* .rodata_wlog_debug.23 */
extern u32 rodata_wlog_debug_24; /* .rodata_wlog_debug.24 */
extern u32 rodata_wlog_debug_25; /* .rodata_wlog_debug.25 */
extern u32 rodata_wlog_debug_26; /* .rodata_wlog_debug.26 */
extern u32 rodata_wlog_debug_27; /* .rodata_wlog_debug.27 */
extern u32 rodata_wlog_debug_28; /* .rodata_wlog_debug.28 */
extern u32 rodata_wlog_debug_29; /* .rodata_wlog_debug.29 */
extern u32 rodata_wlog_debug_3; /* .rodata_wlog_debug.3 */
extern u32 rodata_wlog_debug_30; /* .rodata_wlog_debug.30 */
extern u32 rodata_wlog_debug_31; /* .rodata_wlog_debug.31 */
extern u32 rodata_wlog_debug_32; /* .rodata_wlog_debug.32 */
extern u32 rodata_wlog_debug_33; /* .rodata_wlog_debug.33 */
extern u32 rodata_wlog_debug_34; /* .rodata_wlog_debug.34 */
extern u32 rodata_wlog_debug_35; /* .rodata_wlog_debug.35 */
extern u32 rodata_wlog_debug_36; /* .rodata_wlog_debug.36 */
extern u32 rodata_wlog_debug_38; /* .rodata_wlog_debug.38 */
extern u32 rodata_wlog_debug_39; /* .rodata_wlog_debug.39 */
extern u32 rodata_wlog_debug_4; /* .rodata_wlog_debug.4 */
extern u32 rodata_wlog_debug_40; /* .rodata_wlog_debug.40 */
extern u32 rodata_wlog_debug_41; /* .rodata_wlog_debug.41 */
extern u32 rodata_wlog_debug_42; /* .rodata_wlog_debug.42 */
extern u32 rodata_wlog_debug_43; /* .rodata_wlog_debug.43 */
extern u32 rodata_wlog_debug_44; /* .rodata_wlog_debug.44 */
extern u32 rodata_wlog_debug_45; /* .rodata_wlog_debug.45 */
extern u32 rodata_wlog_debug_46; /* .rodata_wlog_debug.46 */
extern u32 rodata_wlog_debug_47; /* .rodata_wlog_debug.47 */
extern u32 rodata_wlog_debug_48; /* .rodata_wlog_debug.48 */
extern u32 rodata_wlog_debug_5; /* .rodata_wlog_debug.5 */
extern u32 rodata_wlog_debug_6; /* .rodata_wlog_debug.6 */
extern u32 rodata_wlog_debug_63; /* .rodata_wlog_debug.63 */
extern u32 rodata_wlog_debug_64; /* .rodata_wlog_debug.64 */
extern u32 rodata_wlog_debug_65; /* .rodata_wlog_debug.65 */
extern u32 rodata_wlog_debug_66; /* .rodata_wlog_debug.66 */
extern u32 rodata_wlog_debug_67; /* .rodata_wlog_debug.67 */
extern u32 rodata_wlog_debug_68; /* .rodata_wlog_debug.68 */
extern u32 rodata_wlog_debug_7; /* .rodata_wlog_debug.7 */
extern u32 rodata_wlog_debug_76; /* .rodata_wlog_debug.76 */
extern u32 rodata_wlog_debug_77; /* .rodata_wlog_debug.77 */
extern u32 rodata_wlog_debug_78; /* .rodata_wlog_debug.78 */
extern u32 rodata_wlog_debug_79; /* .rodata_wlog_debug.79 */
extern u32 rodata_wlog_debug_8; /* .rodata_wlog_debug.8 */
extern u32 rodata_wlog_debug_80; /* .rodata_wlog_debug.80 */
extern u32 rodata_wlog_debug_81; /* .rodata_wlog_debug.81 */
extern u32 rodata_wlog_debug_82; /* .rodata_wlog_debug.82 */
extern u32 rodata_wlog_debug_83; /* .rodata_wlog_debug.83 */
extern u32 rodata_wlog_debug_84; /* .rodata_wlog_debug.84 */
extern u32 rodata_wlog_debug_85; /* .rodata_wlog_debug.85 */
extern u32 rodata_wlog_debug_86; /* .rodata_wlog_debug.86 */
extern u32 rodata_wlog_debug_87; /* .rodata_wlog_debug.87 */
extern u32 rodata_wlog_debug_88; /* .rodata_wlog_debug.88 */
extern u32 rodata_wlog_debug_89; /* .rodata_wlog_debug.89 */
extern u32 rodata_wlog_debug_9; /* .rodata_wlog_debug.9 */
extern u32 rodata_wlog_debug_99; /* .rodata_wlog_debug.99 */
extern u32 rodata_wlog_error_56; /* .rodata_wlog_error.56 */
extern u32 rodata_wlog_error_62; /* .rodata_wlog_error.62 */
extern u32 rodata_wlog_error_69; /* .rodata_wlog_error.69 */
extern u32 rodata_wlog_error_91; /* .rodata_wlog_error.91 */
extern u32 rodata_wlog_error_92; /* .rodata_wlog_error.92 */
extern u32 rodata_wlog_error_93; /* .rodata_wlog_error.93 */
extern u32 rodata_wlog_error_95; /* .rodata_wlog_error.95 */
extern u32 rodata_wlog_error_96; /* .rodata_wlog_error.96 */
extern u32 rodata_wlog_error_98; /* .rodata_wlog_error.98 */
extern u32 rodata_wlog_info_100; /* .rodata_wlog_info.100 */
extern u32 rodata_wlog_info_104; /* .rodata_wlog_info.104 */
extern u32 rodata_wlog_info_106; /* .rodata_wlog_info.106 */
extern u32 rodata_wlog_info_2; /* .rodata_wlog_info.2 */
extern u32 rodata_wlog_info_37; /* .rodata_wlog_info.37 */
extern u32 rodata_wlog_info_72; /* .rodata_wlog_info.72 */
extern u32 rodata_wlog_info_73; /* .rodata_wlog_info.73 */
extern u32 rodata_wlog_info_74; /* .rodata_wlog_info.74 */
extern u32 rodata_wlog_info_75; /* .rodata_wlog_info.75 */
extern u32 rodata_wlog_info_90; /* .rodata_wlog_info.90 */
extern u32 rodata_wlog_info_94; /* .rodata_wlog_info.94 */
extern u32 rodata_wlog_verbose_57; /* .rodata_wlog_verbose.57 */
extern u32 rodata_wlog_verbose_58; /* .rodata_wlog_verbose.58 */
extern u32 rodata_wlog_verbose_59; /* .rodata_wlog_verbose.59 */
extern u32 rodata_wlog_warning_103; /* .rodata_wlog_warning.103 */
extern u32 rodata_wlog_warning_105; /* .rodata_wlog_warning.105 */
extern u32 rodata_wlog_warning_70; /* .rodata_wlog_warning.70 */
extern u32 rodata_wlog_warning_97; /* .rodata_wlog_warning.97 */
extern u32 text_sta_assoc_comeback; /* .text.sta_assoc_comeback */
extern u32 text_sta_sa_query_timeout; /* .text.sta_sa_query_timeout */
extern u32 text_sta_try_sa_query; /* .text.sta_try_sa_query */
extern u32 ccmp; /* ccmp */
extern u32 check_bss_queue(); /* check_bss_queue */
extern u32 chm_get_band_from_chan(); /* chm_get_band_from_chan */
extern u32 clear_bss_queue(); /* clear_bss_queue */
extern u32 cnx_add_to_blacklist(); /* cnx_add_to_blacklist */
extern u32 cnx_assoc_timeout; /* cnx_assoc_timeout */
extern u32 cnx_auth_done(); /* cnx_auth_done */
extern u32 cnx_auth_timeout; /* cnx_auth_timeout */
extern u32 cnx_connect_next_ap(); /* cnx_connect_next_ap */
extern u32 cnx_csa_fn; /* cnx_csa_fn */
extern u32 cnx_remove_all_rc(); /* cnx_remove_all_rc */
extern u32 cnx_sta_associated(); /* cnx_sta_associated */
extern u32 cnx_sta_leave(); /* cnx_sta_leave */
extern u32 esp_mesh_quick_funcs; /* esp_mesh_quick_funcs */
extern u32 gScanStruct; /* gScanStruct */
extern u32 g_chm; /* g_chm */
extern u32 g_cnxMgr; /* g_cnxMgr */
extern u32 g_cnxMgr_0xf48; /* g_cnxMgr+0xf48 */
extern u32 g_dynamic_cs; /* g_dynamic_cs */
extern u32 g_hmac_cnt; /* g_hmac_cnt */
extern u32 g_ic; /* g_ic */
extern u32 g_ic_0x130; /* g_ic+0x130 */
extern u32 g_mesh_init_ps_type; /* g_mesh_init_ps_type */
extern u32 g_mesh_is_root; /* g_mesh_is_root */
extern u32 g_misc_nvs; /* g_misc_nvs */
extern u32 g_osi_funcs_p; /* g_osi_funcs_p */
extern u32 g_scan; /* g_scan */
extern u32 g_wifi_menuconfig; /* g_wifi_menuconfig */
extern u32 g_wifi_nvs; /* g_wifi_nvs */
extern u32 get_iav_key(); /* get_iav_key */
extern u32 hal_crypto_enable(); /* hal_crypto_enable */
extern u32 hal_disable_sta_tsf(); /* hal_disable_sta_tsf */
extern u32 hal_enable_sta_tsf(); /* hal_enable_sta_tsf */
extern u32 hal_now(); /* hal_now */
extern u32 ic_del_ptk_and_gtk_alg(); /* ic_del_ptk_and_gtk_alg */
extern u32 ic_ebuf_recycle_rx(); /* ic_ebuf_recycle_rx */
extern u32 ic_get_ptk_alg(); /* ic_get_ptk_alg */
extern u32 ic_register_tx_cb(); /* ic_register_tx_cb */
extern u32 ic_set_vif(); /* ic_set_vif */
extern u32 ieee80211_alloc_challenge(); /* ieee80211_alloc_challenge */
extern u32 ieee80211_ampdu_reorder(); /* ieee80211_ampdu_reorder */
extern u32 ieee80211_ccmp_decrypt(); /* ieee80211_ccmp_decrypt */
extern u32 ieee80211_crypto_aes_128_cmac_decrypt(); /* ieee80211_crypto_aes_128_cmac_decrypt */
extern u32 ieee80211_crypto_decap(); /* ieee80211_crypto_decap */
extern u32 ieee80211_crypto_gmac_decrypt(); /* ieee80211_crypto_gmac_decrypt */
extern u32 ieee80211_decap(); /* ieee80211_decap */
extern u32 ieee80211_decap_amsdu(); /* ieee80211_decap_amsdu */
extern u32 ieee80211_decrypt_espnow_pkt(); /* ieee80211_decrypt_espnow_pkt */
extern u32 ieee80211_ethbroadcast; /* ieee80211_ethbroadcast */
extern u32 ieee80211_find_ie(); /* ieee80211_find_ie */
extern u32 ieee80211_get_key(); /* ieee80211_get_key */
extern u32 ieee80211_gettid(); /* ieee80211_gettid */
extern u32 ieee80211_ht_node_init(); /* ieee80211_ht_node_init */
extern u32 ieee80211_ht_updateparams(); /* ieee80211_ht_updateparams */
extern u32 ieee80211_is_lr_only(); /* ieee80211_is_lr_only */
extern u32 ieee80211_parse_action(); /* ieee80211_parse_action */
extern u32 ieee80211_parse_beacon(); /* ieee80211_parse_beacon */
extern u32 ieee80211_recv_action(); /* ieee80211_recv_action */
extern u32 ieee80211_recv_bar(); /* ieee80211_recv_bar */
extern u32 ieee80211_send_action(); /* ieee80211_send_action */
extern u32 ieee80211_send_mgmt(); /* ieee80211_send_mgmt */
extern u32 ieee80211_set_shortslottime(); /* ieee80211_set_shortslottime */
extern u32 ieee80211_setup_basic_htrates(); /* ieee80211_setup_basic_htrates */
extern u32 ieee80211_setup_htrates(); /* ieee80211_setup_htrates */
extern u32 ieee80211_setup_lr_rates(); /* ieee80211_setup_lr_rates */
extern u32 ieee80211_setup_phy_mode(); /* ieee80211_setup_phy_mode */
extern u32 ieee80211_setup_rates(); /* ieee80211_setup_rates */
extern u32 ieee80211_sta_is_connected(); /* ieee80211_sta_is_connected */
extern u32 ieee80211_timer_process(); /* ieee80211_timer_process */
extern u32 ieee80211_wme_updateparams(); /* ieee80211_wme_updateparams */
extern u32 ieee80211w_get_active_igtk_key_id(); /* ieee80211w_get_active_igtk_key_id */
extern u32 in_rssi_adjust; /* in_rssi_adjust */
extern u32 is_off_channel(); /* is_off_channel */
extern u32 memcmp(); /* memcmp */
extern u32 memcpy(); /* memcpy */
extern u32 memset(); /* memset */
extern u32 mesh_rxcb; /* mesh_rxcb */
extern u32 offchan_in_progress(); /* offchan_in_progress */
extern u32 offchan_recv_action(); /* offchan_recv_action */
extern u32 pm_coex_set_reconnect_policy(); /* pm_coex_set_reconnect_policy */
extern u32 pm_enable_send_wake_null_on_channel(); /* pm_enable_send_wake_null_on_channel */
extern u32 pm_hmac_rx_data_process(); /* pm_hmac_rx_data_process */
extern u32 pm_on_coex_schm_process_restart(); /* pm_on_coex_schm_process_restart */
extern u32 pm_on_coex_schm_status_config(); /* pm_on_coex_schm_status_config */
extern u32 pm_on_probe_resp_rx(); /* pm_on_probe_resp_rx */
extern u32 pm_send_nullfunc(); /* pm_send_nullfunc */
extern u32 pm_send_probe_stop(); /* pm_send_probe_stop */
extern u32 pm_wake_done(); /* pm_wake_done */
extern u32 pm_wake_up(); /* pm_wake_up */
extern u32 rssi_index; /* rssi_index */
extern u32 rssi_saved; /* rssi_saved */
extern u32 s_eapol_txdone_cb; /* s_eapol_txdone_cb */
extern u32 scan_parse_beacon(); /* scan_parse_beacon */
extern u32 send_deauth; /* send_deauth */
extern u32 send_wake_null_timeout; /* send_wake_null_timeout */
extern u32 send_wake_null_timer; /* send_wake_null_timer */
extern u32 set_rx_sense(); /* set_rx_sense */
extern u32 sta_csa_timer; /* sta_csa_timer */
extern u32 sta_eapol_txdone_cb; /* sta_eapol_txdone_cb */
extern u32 sta_rx_eapol(); /* sta_rx_eapol */
extern u32 sta_rxcb; /* sta_rxcb */
extern u32 wifi_disconnect_process(); /* wifi_disconnect_process */
extern u32 wifi_event_post(); /* wifi_event_post */
extern u32 wifi_get_macaddr(); /* wifi_get_macaddr */
extern u32 wifi_log(); /* wifi_log */
extern u32 wifi_mesh_event_post(); /* wifi_mesh_event_post */
extern u32 wifi_nvs_commit(); /* wifi_nvs_commit */
extern u32 wifi_nvs_compare_cfg_diff(); /* wifi_nvs_compare_cfg_diff */
extern u32 wifi_nvs_get(); /* wifi_nvs_get */
extern u32 wifi_nvs_reset_current_ap_info(); /* wifi_nvs_reset_current_ap_info */
extern u32 wifi_nvs_set(); /* wifi_nvs_set */
extern u32 wifi_set_rx_policy(); /* wifi_set_rx_policy */
extern u32 wifi_sta_get_prof_password(); /* wifi_sta_get_prof_password */
extern u32 wl_clear_ap_no_lr(); /* wl_clear_ap_no_lr */

/* ROLE: station MLME input side: sta_recv_mgmt (0xa83B, largest here),
 * sta_recv_assoc, sta_input, sta_rx_eapol/csa, SAE/FT/OWE auth helpers.
 * ieee80211_sta_new_state (0xe08B) is the STA state machine; see its call list
 * for the event/commit ordering. Roam/blacklist via cnx_* (wl_cnx.o).
 */
/* ---- literal-rooted access patterns (offsets observed; layout NOT confirmed) ----
 * (((*(*(g_osi_funcs_p+0)+236)+65536)+131072)+65536): u32+52
 * (*(*(g_osi_funcs_p+0)+236)+65536): u32+52
 * *(?+4): u8+4, u16+4
 * *(?+64): u8+228
 * .bss.s_disconnect_evt_pending: u8+0
 * .rodata.state_desc$0: u32+0
 * ?: u32+0, u32+4, u8+4, u8+8, u8+12, u32+16, u8+16, u32+36, u8+40, u32+44, u8+44, u32+64, u8+64, u32+68 (+11 more)
 * ccmp: u32+4, u32+8
 * esp_mesh_quick_funcs: u32+0, u32+4, u32+8, u32+20, u32+24, u32+28, u32+40, u32+232
 * gScanStruct: u8+70
 * g_chm: u32+0, u8+0
 * g_cnxMgr: u32+236, u32+0x280, u32+3912
 * g_dynamic_cs: u8+0, u8+1, u8+2, u8+3, u32+4, u8+8
 * g_hmac_cnt: u32+0, u32+4, u16+10, u16+12, u8+14, u8+15, u8+16, u8+17, u16+18, u32+26, u32+52, u16+52
 * g_ic: u32+0, u32+4, u8+4, u32+11, u32+16, u32+16, u8+16, u32+20, u32+28, u8+44, u32+116, u32+156, u32+200, u32+204 (+8 more)
 * g_mesh_init_ps_type: u32+0, u32+0
 * g_mesh_is_root: u8+0, u32+0
 * g_misc_nvs: u32+0, u32+0
 * g_osi_funcs_p: u32+0, u32+0, u8+44, u32+44, u32+84, u32+228, u32+232
 * g_scan: u32+0, u32+0
 * g_wifi_menuconfig: u32+64
 * g_wifi_nvs: u32+0, u8+0, u16+228
 * in_rssi_adjust: u8+0
 * mesh_rxcb: u32+0
 * ret@4af: u32+4, u32+16
 * ret@5b: u8+160
 * rssi_index: u8+0
 * s_eapol_txdone_cb: u32+0
 * send_deauth: u8+0
 * sta_rxcb: u32+0
/* ---- funcdb-v2 cross-check (calls[] vs section relocs; disasm is ground truth) ----
 * confirmed funcdb edges: 128; rejected funcdb-only (no exact reloc in
 * callee section; caller-side .rela.text.<f> prefix-collision artifacts): 0;
 * disasm-only edges kept (static-local callees + funcdb relsec:null gaps): 20;
 *   e.g. sta_bip_check->.text.ieee80211_is_action_category_robust, sta_recv_mgmt->.text.ieee80211_is_action_category_robust, sta_input->check_bss_queue, sta_input->ic_ebuf_recycle_rx, sta_input->ieee80211_ampdu_reorder, sta_input->ieee80211_crypto_decap, sta_input->ieee80211_decap, sta_input->ieee80211_decap_amsdu
 */
/* ==== functions of ieee80211_sta.o ==== */

/* ieee80211_is_action_category_robust @ ieee80211_sta.o 0x00000004 size 53B bind LOCAL
 * Calls: none | Data refs: none
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 ieee80211_is_action_category_robust(u32 a2)
{
    /* frame: entry a1,32; 18 insns, 2 cond-branches, 0 loops, 1 jumps */
    /* immediates: 22, 1, 0 */
    /* first predicate: blt a8, a2, 24 <.text.ieee80211_is_action_category_robust+0x24> (condition opaque) */
    return 1;
}

/* send_wake_null_timeout @ ieee80211_sta.o 0x00000004 size 18B bind GLOBAL
 * Calls: ieee80211_timer_process | Data refs: none
 * Fidelity: high - straight-line, fully mapped (7 insns) */
u32 send_wake_null_timeout(void)
{
    /* frame: entry a1,32; 7 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0, 38, 7 */
    /* site +0x11: ieee80211_timer_process(7, 38, 0) */
    ieee80211_timer_process(7, 38, 0);
    return opaque_result; /* full dataflow not recovered */
}

/* sta_assoc_comeback @ ieee80211_sta.o 0x00000004 size 22B bind LOCAL
 * Calls: ieee80211_timer_process | Data refs: none
 * Fidelity: high - straight-line, fully mapped (7 insns) */
u32 sta_assoc_comeback(void)
{
    /* frame: entry a1,32; 7 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0, 16, 7 */
    /* site +0x11: ieee80211_timer_process(7, 16, 0) */
    ieee80211_timer_process(7, 16, 0);
    return opaque_result; /* full dataflow not recovered */
}

/* sta_try_sa_query @ ieee80211_sta.o 0x00000004 size 22B bind LOCAL
 * Calls: ieee80211_timer_process | Data refs: none
 * Fidelity: high - straight-line, fully mapped (7 insns) */
u32 sta_try_sa_query(void)
{
    /* frame: entry a1,32; 7 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0, 14, 7 */
    /* site +0x11: ieee80211_timer_process(7, 14, 0) */
    ieee80211_timer_process(7, 14, 0);
    return opaque_result; /* full dataflow not recovered */
}

/* sta_sa_query_timeout @ ieee80211_sta.o 0x00000004 size 22B bind LOCAL
 * Calls: ieee80211_timer_process | Data refs: none
 * Fidelity: high - straight-line, fully mapped (7 insns) */
u32 sta_sa_query_timeout(void)
{
    /* frame: entry a1,32; 7 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0, 15, 7 */
    /* site +0x11: ieee80211_timer_process(7, 15, 0) */
    ieee80211_timer_process(7, 15, 0);
    return opaque_result; /* full dataflow not recovered */
}

/* sta_eapol_txdone_cb @ ieee80211_sta.o 0x0000000c size 174B bind GLOBAL
 * Calls: ieee80211_get_key, indirect(a9) | Data refs: g_ic, s_eapol_txdone_cb
 * Fidelity: medium - branchy but loop-free, call sequence mapped (verified: section R_XTENSA_ASM_EXPAND + funcdb v3 agree; predicates opaque) */
u32 sta_eapol_txdone_cb(u32 a2, u32 a3)
{
    /* frame: entry a1,32; 66 insns, 8 cond-branches, 0 loops, 2 jumps */
    /* immediates: 12, 0, 3, 1, 4, 30, 24, 140, 136 */
    /* first predicate: beqi a8, 8, 26 <sta_eapol_txdone_cb+0x1a> (condition opaque) */
    /* mem ld32: base=(lit:g_ic) off=16 */
    /* mem ld32: base=(?) off=4 */
    /* mem ld32: base=(*(?+4)) off=4 */
    /* mem ld8: base=(*(g_ic+4)) off=0 */
    /* mem ld32: base=(?) off=44 */
    /* mem ld32: base=(*(?+44)) off=16 */
    /* mem ld32: base=(*(g_ic+16)) off=152 */
    /* mem ld8: base=(*(g_ic+4)) off=1 */
    /* mem ld32: base=(ret@5b) off=160 */
    /* mem ld8: base=(*(ret@5b+160)) off=4 */
    /* ... +6 more memops */
    /* site +0x5b: ieee80211_get_key(4, *(g_ic+16), ?, 0) */
    ieee80211_get_key(4, *(g_ic+16), ?, 0);
    /* site +0xb5: indirect call via a9 (base *(s_eapol_txdone_cb+0)); args: (*(*(ret@5b+160)+4)+8), (*(?+22)+-12), 1, *(*(ret@5b+160)+4) */
    opaque_indirect_a9();
    return opaque_result; /* full dataflow not recovered */
}

/* send_wake_null_timeout_process @ ieee80211_sta.o 0x0000000c size 28B bind GLOBAL
 * Calls: is_off_channel, pm_enable_send_wake_null_on_channel, pm_send_nullfunc | Data refs: none
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 send_wake_null_timeout_process(void)
{
    /* frame: entry a1,32; 10 insns, 1 cond-branches, 0 loops, 1 jumps */
    /* first predicate: beqz.n a10, 20 <send_wake_null_timeout_process+0x14> (condition opaque) */
    /* site +0x12: is_off_channel(/* no traced args */) */
    is_off_channel(/* no traced args */);
    /* site +0x1a: pm_enable_send_wake_null_on_channel(ret@12) */
    pm_enable_send_wake_null_on_channel(ret@12);
    /* site +0x23: pm_send_nullfunc(ret@1a) */
    pm_send_nullfunc(ret@1a);
    return opaque_result; /* full dataflow not recovered */
}

/* wifi_sta_reg_eapol_txdone_cb @ ieee80211_sta.o 0x0000000c size 26B bind GLOBAL
 * Calls: ic_register_tx_cb | Data refs: s_eapol_txdone_cb, sta_eapol_txdone_cb
 * Fidelity: high - straight-line, fully mapped (10 insns) */
u32 wifi_sta_reg_eapol_txdone_cb(u32 a2)
{
    /* frame: entry a1,32; 10 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* immediates: 1, 3 */
    /* mem st32: base=(lit:s_eapol_txdone_cb) off=0 */
    /* site +0x21: ic_register_tx_cb(lit:sta_eapol_txdone_cb, 3, 1) */
    ic_register_tx_cb(lit:sta_eapol_txdone_cb, 3, 1);
    return opaque_result; /* full dataflow not recovered */
}

/* ieee80211_sta_tx_disconnect_cb @ ieee80211_sta.o 0x0000000c size 37B bind GLOBAL
 * Calls: wifi_event_post | Data refs: .bss.s_disconnect_evt_pending, .bss.s_pending_disconnect_evt
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 ieee80211_sta_tx_disconnect_cb(u32 a2)
{
    /* frame: entry a1,32; 14 insns, 1 cond-branches, 0 loops, 0 jumps */
    /* immediates: 41, 5, 0 */
    /* first predicate: beqz.n a8, 2c <ieee80211_sta_tx_disconnect_cb+0x20> (condition opaque) */
    /* mem ld8: base=(lit:.bss.s_disconnect_evt_pending) off=0 */
    /* mem st8: base=(lit:.bss.s_disconnect_evt_pending) off=0 */
    /* site +0x21: wifi_event_post(5, lit:.bss.s_pending_disconnect_evt, 41) */
    wifi_event_post(5, lit:.bss.s_pending_disconnect_evt, 41);
    return opaque_result; /* full dataflow not recovered */
}

/* wifi_sta_reg_rxcb @ ieee80211_sta.o 0x00000004 size 13B bind GLOBAL
 * Calls: none | Data refs: sta_rxcb
 * Fidelity: high - straight-line, fully mapped (5 insns) */
u32 wifi_sta_reg_rxcb(u32 a2)
{
    /* frame: entry a1,32; 5 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* mem st32: base=(lit:sta_rxcb) off=0 */
    return opaque_result; /* full dataflow not recovered */
}

/* sta_michael_mic_failure @ ieee80211_sta.o 0x0000000c size 46B bind GLOBAL
 * Calls: indirect(a8), wifi_log | Data refs: g_ic, .rodata_wlog_error.62
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 sta_michael_mic_failure(u32 a2)
{
    /* frame: entry a1,32; 18 insns, 2 cond-branches, 0 loops, 1 jumps */
    /* immediates: 1, 32, -1 */
    /* first predicate: beqz.n a8, 25 <sta_michael_mic_failure+0x19> (condition opaque) */
    /* mem ld32: base=(lit:g_ic) off=0x1b4 */
    /* mem ld32: base=(*(g_ic+0x1b4)) off=68 */
    /* site +0x1f: indirect call via a8 (base *(g_ic+68)); args: /* no traced args */ */
    opaque_indirect_a8();
    /* site +0x31: wifi_log(1, 32, 1, lit:.rodata_wlog_error.62) */
    wifi_log(1, 32, 1, lit:.rodata_wlog_error.62);
    return -1;
}

/* ieee80211_wme_standard_ac_to_esp_ac @ ieee80211_sta.o 0x0000000c size 47B bind GLOBAL
 * Calls: wifi_log | Data refs: .rodata_wlog_error.69
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 ieee80211_wme_standard_ac_to_esp_ac(u32 a2)
{
    /* frame: entry a1,48; 17 insns, 1 cond-branches, 0 loops, 1 jumps */
    /* immediates: 1, 32 */
    /* first predicate: bltui a2, 4, 34 <ieee80211_wme_standard_ac_to_esp_ac+0x28> (condition opaque) */
    /* mem st32: base=(?) off=0 */
    /* mem ld8: base=(?) off=0 */
    /* site +0x2d: wifi_log(?, 32, 1, lit:.rodata_wlog_error.69) */
    wifi_log(?, 32, 1, lit:.rodata_wlog_error.69);
    return opaque_result; /* full dataflow not recovered */
}

/* ieee80211_parse_wmeparams @ ieee80211_sta.o 0x00000004 size 145B bind GLOBAL
 * Calls: ieee80211_wme_standard_ac_to_esp_ac | Data refs: none
 * Fidelity: medium - branchy but loop-free, call sequence mapped */
u32 ieee80211_parse_wmeparams(u32 a2, u32 a3)
{
    /* frame: entry a1,32; 53 insns, 4 cond-branches, 0 loops, 0 jumps */
    /* immediates: 23, -1, 0, 1 */
    /* first predicate: bgeu a9, a4, 8e <ieee80211_parse_wmeparams+0x8a> (condition opaque) */
    /* mem ld8: base=(?) off=1 */
    /* mem ld8: base=(?) off=8 */
    /* mem ld8: base=(?) off=37 */
    /* mem ld8: base=(?) off=135 */
    /* mem st8: base=(?) off=16 */
    /* mem st8: base=(?) off=37 */
    /* mem st8: base=(?) off=135 */
    /* mem ld8: base=((?+10)) off=0 */
    /* mem st8: base=(ret@41) off=137 */
    /* mem ld8: base=((?+10)) off=0 */
    /* ... +7 more memops */
    /* site +0x41: ieee80211_wme_standard_ac_to_esp_ac(0) */
    ieee80211_wme_standard_ac_to_esp_ac(0);
    return 1;
}

/* sta_rx_csa @ ieee80211_sta.o 0x00000054 size 532B bind GLOBAL
 * Calls: wifi_log, chm_get_band_from_chan, chm_get_band_from_chan, wifi_log, wifi_log, indirect(a11), indirect(a11), indirect(a13), wifi_log, wifi_mesh_event_post, indirect(a2), wifi_log | Data refs: .rodata.sta_rx_csa.str1.1, g_ic, .rodata_wlog_warning.70, .rodata_wlog_info.72, .rodata_wlog_info.73, .rodata_wlog_info.74, g_wifi_nvs, sta_csa_timer, g_osi_funcs_p, cnx_csa_fn, .rodata_wlog_info.75, .rodata_wlog_debug.76
 * Fidelity: medium - 198 insns, 18 branches, 0 loops; branchy but loop-free, call sequence mapped (verified against section disasm; predicates opaque) */
u32 sta_rx_csa(u32 a2, u32 a3, u32 a4)
{
    /* frame: entry a1,80; 198 insns, 18 cond-branches, 0 loops, 6 jumps */
    /* immediates: 13, 1, 2, -1, 3, 0, 66, 4 */
    /* first predicate: bgeu a4, a3, 94 <sta_rx_csa+0x40> (condition opaque) */
    /* mem ld32: base=(lit:g_ic) off=16 */
    /* mem ld8: base=(?) off=3 */
    /* mem ld32: base=(lit:g_ic) off=20 */
    /* mem st32: base=(?) off=36 */
    /* mem ld8: base=((*(g_ic+16)+65536)) off=86 */
    /* mem st32: base=(?) off=32 */
    /* mem ld8: base=(?) off=3 */
    /* mem ld32: base=(lit:g_ic) off=116 */
    /* mem ld8: base=((lit:g_ic+65536)) off=235 */
    /* mem ld8: base=(?) off=3 */
    /* ... +50 more memops */
    /* site +0x8d: wifi_log(1, (1 slli 15), 2, lit:.rodata_wlog_warning.70, *(?+3)) */
    wifi_log(1, (1 slli 15), 2, lit:.rodata_wlog_warning.70, *(?+3));
    /* site +0x99: chm_get_band_from_chan(*(g_ic+86), (1 slli 15), 2, lit:.rodata_wlog_warning.70, *(?+3)) */
    chm_get_band_from_chan(*(g_ic+86), (1 slli 15), 2, lit:.rodata_wlog_warning.70, *(?+3));
    /* site +0xa6: chm_get_band_from_chan(*(?+3), (1 slli 15), 2, lit:.rodata_wlog_warning.70, *(?+3)) */
    chm_get_band_from_chan(*(?+3), (1 slli 15), 2, lit:.rodata_wlog_warning.70, *(?+3));
    /* site +0xf3: wifi_log(1, (1 slli 15), 3, lit:.rodata_wlog_info.72, lit:.rodata.sta_rx_csa.str1.1) */
    wifi_log(1, (1 slli 15), 3, lit:.rodata_wlog_info.72, lit:.rodata.sta_rx_csa.str1.1);
    /* site +0x13d: wifi_log(1, (1 slli 15), 3, lit:.rodata_wlog_info.74, *(?+3)) */
    wifi_log(1, (1 slli 15), 3, lit:.rodata_wlog_info.74, *(?+3));
    /* site +0x1a5: indirect call via a11 (base *(*(g_osi_funcs_p+0)+236)); args: *(g_osi_funcs_p+0), *(*(g_osi_funcs_p+0)+236), 3, lit:.rodata_wlog_info.74, *(?+3) */
    opaque_indirect_a11();
    /* site +0x1af: indirect call via a11 (base *(*(g_osi_funcs_p+0)+240)); args: lit:sta_csa_timer, *(*(g_osi_funcs_p+0)+240), 3, lit:.rodata_wlog_info.74, *(?+3) */
    opaque_indirect_a11();
    /* site +0x1be: indirect call via a13 (base *(*(g_osi_funcs_p+0)+244)); args: lit:sta_csa_timer, lit:cnx_csa_fn, 0, *(*(g_osi_funcs_p+0)+244), *(?+3) */
    opaque_indirect_a13();
    /* site +0x1ff: wifi_log(1, (1 slli 15), 3, lit:.rodata_wlog_info.75, lit:.rodata.sta_rx_csa.str1.1) */
    wifi_log(1, (1 slli 15), 3, lit:.rodata_wlog_info.75, lit:.rodata.sta_rx_csa.str1.1);
    /* site +0x21a: wifi_mesh_event_post(66, (?+16), 1, lit:.rodata_wlog_info.75, lit:.rodata.sta_rx_csa.str1.1) */
    wifi_mesh_event_post(66, (?+16), 1, lit:.rodata_wlog_info.75, lit:.rodata.sta_rx_csa.str1.1);
    /* site +0x245: indirect call via a2 (base *(*(g_osi_funcs_p+0)+232)); args: ret@21a, *(*(g_wifi_nvs+228)+40), 0, lit:.rodata_wlog_info.75, lit:.rodata.sta_rx_csa.str1.1 */
    opaque_indirect_a2();
    /* site +0x261: wifi_log(1, 4, 4, lit:.rodata_wlog_debug.76, *(?+3)) */
    wifi_log(1, 4, 4, lit:.rodata_wlog_debug.76, *(?+3));
    return 0;
}

/* update_cs_thres @ ieee80211_sta.o 0x00000020 size 171B bind GLOBAL
 * Calls: hal_now, hal_now, hal_now, set_rx_sense, hal_now | Data refs: g_dynamic_cs
 * Fidelity: medium - branchy but loop-free, call sequence mapped */
u32 update_cs_thres(u32 a2, u32 a3, u32 a6)
{
    /* frame: entry a1,32; 58 insns, 5 cond-branches, 0 loops, 2 jumps */
    /* first predicate: beqz.n a8, 49 <update_cs_thres+0x29> (condition opaque) */
    /* mem ld8: base=(lit:g_dynamic_cs) off=2 */
    /* mem st8: base=(lit:g_dynamic_cs) off=2 */
    /* mem ld32: base=(lit:g_dynamic_cs) off=4 */
    /* mem ld32: base=(lit:g_dynamic_cs) off=4 */
    /* mem ld8: base=(lit:g_dynamic_cs) off=3 */
    /* mem ld8: base=(lit:g_dynamic_cs) off=2 */
    /* mem ld8: base=(lit:g_dynamic_cs) off=0 */
    /* mem st8: base=(lit:g_dynamic_cs) off=8 */
    /* mem st32: base=(lit:g_dynamic_cs) off=4 */
    /* mem ld8: base=(lit:g_dynamic_cs) off=1 */
    /* ... +3 more memops */
    /* site +0x55: hal_now(/* no traced args */) */
    hal_now(/* no traced args */);
    /* site +0x61: hal_now(ret@55) */
    hal_now(ret@55);
    /* site +0x72: hal_now(ret@61) */
    hal_now(ret@61);
    /* site +0xb8: set_rx_sense(*(g_dynamic_cs+8)) */
    set_rx_sense(*(g_dynamic_cs+8));
    /* site +0xc1: hal_now(ret@b8) */
    hal_now(ret@b8);
    return opaque_result; /* full dataflow not recovered */
}

/* reset_cs_thres @ ieee80211_sta.o 0x0000000c size 46B bind GLOBAL
 * Calls: set_rx_sense | Data refs: g_ic, g_dynamic_cs
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 reset_cs_thres(void)
{
    /* frame: entry a1,32; 16 insns, 1 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0, -99 */
    /* first predicate: beqz.n a8, 38 <reset_cs_thres+0x2c> (condition opaque) */
    /* mem ld8: base=((lit:g_ic+131072)) off=164 */
    /* mem st8: base=(lit:g_dynamic_cs) off=2 */
    /* mem st8: base=(lit:g_dynamic_cs) off=8 */
    /* site +0x35: set_rx_sense(-99) */
    set_rx_sense(-99);
    return opaque_result; /* full dataflow not recovered */
}

/* ieee80211_parse_obss_scan_param @ ieee80211_sta.o 0x00000004 size 38B bind GLOBAL
 * Calls: memcpy | Data refs: none
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 ieee80211_parse_obss_scan_param(u32 a2, u32 a3)
{
    /* frame: entry a1,32; 15 insns, 2 cond-branches, 0 loops, 0 jumps */
    /* immediates: 1, 0, 0x2b9, 16 */
    /* first predicate: bnez.n a9, 28 <ieee80211_parse_obss_scan_param+0x24> (condition opaque) */
    /* site +0x25: memcpy(0x2b9, ?, 16) */
    memcpy(0x2b9, ?, 16);
    return opaque_result; /* full dataflow not recovered */
}

/* ieee80211_set_bss_max_idle_period @ ieee80211_sta.o 0x00000010 size 67B bind GLOBAL
 * Calls: wifi_log | Data refs: .rodata.ieee80211_set_bss_max_idle_period.str1.1, .rodata_wlog_info.90
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 ieee80211_set_bss_max_idle_period(u32 a2, u32 a3)
{
    /* frame: entry a1,32; 24 insns, 2 cond-branches, 0 loops, 0 jumps */
    /* immediates: 1, 3 */
    /* first predicate: beqz.n a3, 51 <ieee80211_set_bss_max_idle_period+0x41> (condition opaque) */
    /* mem ld8: base=(?) off=3 */
    /* mem ld8: base=(?) off=2 */
    /* mem ld8: base=(?) off=4 */
    /* mem st8: base=((?+196608)) off=52 */
    /* mem st16: base=((?+196608)) off=50 */
    /* mem ld8: base=(?) off=4 */
    /* site +0x4e: wifi_log(1, 1, 3, lit:.rodata_wlog_info.90, (*(?+3) slli 8)) */
    wifi_log(1, 1, 3, lit:.rodata_wlog_info.90, (*(?+3) slli 8));
    return opaque_result; /* full dataflow not recovered */
}

/* sta_recv_ctl @ ieee80211_sta.o 0x00000004 size 18B bind GLOBAL
 * Calls: ieee80211_recv_bar | Data refs: none
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 sta_recv_ctl(u32 a2, u32 a3, u32 a4)
{
    /* frame: entry a1,32; 7 insns, 1 cond-branches, 0 loops, 0 jumps */
    /* first predicate: bnei a4, 128, 14 <sta_recv_ctl+0x10> (condition opaque) */
    /* site +0x11: ieee80211_recv_bar(/* no traced args */) */
    ieee80211_recv_bar(/* no traced args */);
    return opaque_result; /* full dataflow not recovered */
}

/* wifi_station_start @ ieee80211_sta.o 0x0000002c size 186B bind GLOBAL
 * Calls: indirect(a10), hal_enable_sta_tsf, wifi_log, ic_set_vif, wifi_log, wifi_event_post | Data refs: g_ic, .bss.s_disconnect_evt_pending, g_ic+0x130, .rodata_wlog_info.100, .rodata_wlog_debug.101
 * Fidelity: medium - branchy but loop-free, call sequence mapped (verified: section R_XTENSA_ASM_EXPAND + funcdb v3 agree; predicates opaque) */
u32 wifi_station_start(u32 a2, u32 a3)
{
    /* frame: entry a1,32; 70 insns, 3 cond-branches, 0 loops, 1 jumps */
    /* immediates: 2, 0, 1, 3, 4 */
    /* first predicate: beqz a4, e2 <wifi_station_start+0xb6> (condition opaque) */
    /* mem ld32: base=(lit:g_ic) off=16 */
    /* mem ld8: base=((*(g_ic+16)+65536)) off=85 */
    /* mem st8: base=(lit:.bss.s_disconnect_evt_pending) off=0 */
    /* mem ld32: base=(lit:g_ic) off=0x1b4 */
    /* mem ld8: base=((lit:g_ic+65536)) off=216 */
    /* mem st32: base=(lit:g_ic) off=0x130 */
    /* mem ld32: base=(*(g_ic+0x1b4)) off=0 */
    /* mem st32: base=(lit:g_ic) off=0x134 */
    /* mem ld8: base=((lit:g_ic+65536)) off=212 */
    /* mem ld32: base=(lit:g_ic) off=16 */
    /* ... +5 more memops */
    /* site +0x71: indirect call via a10 (base *(.bss.s_disconnect_evt_pending+0)); args: *(.bss.s_disconnect_evt_pending+0) */
    opaque_indirect_a10();
    /* site +0x77: hal_enable_sta_tsf(ret@71) */
    hal_enable_sta_tsf(ret@71);
    /* site +0x86: wifi_log(1, 1, 3, lit:.rodata_wlog_info.100) */
    wifi_log(1, 1, 3, lit:.rodata_wlog_info.100);
    /* site +0x9a: ic_set_vif(0, 0, ?, 0) */
    ic_set_vif(0, 0, ?, 0);
    /* site +0xb5: wifi_log(1, 4, 4, lit:.rodata_wlog_debug.101, *(g_ic+0x130+84)) */
    wifi_log(1, 4, 4, lit:.rodata_wlog_debug.101, *(g_ic+0x130+84));
    /* site +0xdd: wifi_event_post(2, 0, 0, lit:.rodata_wlog_debug.101, *(g_ic+0x130+84)) */
    wifi_event_post(2, 0, 0, lit:.rodata_wlog_debug.101, *(g_ic+0x130+84));
    return 0;
}

/* wifi_station_stop @ ieee80211_sta.o 0x0000002c size 178B bind GLOBAL
 * Calls: wifi_log, wifi_disconnect_process, wifi_event_post, ic_set_vif, hal_disable_sta_tsf, clear_bss_queue, indirect(a10), wifi_event_post | Data refs: g_ic, .rodata_wlog_debug.102, .bss.s_disconnect_evt_pending, .bss.s_pending_disconnect_evt
 * Fidelity: medium - branchy but loop-free, call sequence mapped (verified: section R_XTENSA_ASM_EXPAND + funcdb v3 agree; predicates opaque) */
u32 wifi_station_stop(u32 a3)
{
    /* frame: entry a1,32; 66 insns, 4 cond-branches, 0 loops, 1 jumps */
    /* immediates: 4, 0, 1, -3, 41, 5, 3 */
    /* first predicate: beqz a2, da <wifi_station_stop+0xae> (condition opaque) */
    /* mem ld32: base=(lit:g_ic) off=16 */
    /* mem ld8: base=((*(g_ic+16)+65536)) off=85 */
    /* mem ld8: base=((*(g_ic+16)+65536)) off=84 */
    /* mem ld8: base=((lit:g_ic+65536)) off=216 */
    /* mem ld32: base=(lit:g_ic) off=16 */
    /* mem st8: base=((*(g_ic+16)+65536)) off=84 */
    /* mem ld8: base=((*(g_ic+16)+65536)) off=85 */
    /* mem st8: base=((*(g_ic+16)+65536)) off=85 */
    /* mem ld8: base=(lit:.bss.s_disconnect_evt_pending) off=0 */
    /* mem st8: base=(lit:.bss.s_disconnect_evt_pending) off=0 */
    /* ... +3 more memops */
    /* site +0x5d: wifi_log(1, 4, 4, lit:.rodata_wlog_debug.102, *((*(g_ic+16)+65536)+84)) */
    wifi_log(1, 4, 4, lit:.rodata_wlog_debug.102, *((*(g_ic+16)+65536)+84));
    /* site +0x81: wifi_disconnect_process(0, 4, 4, lit:.rodata_wlog_debug.102, *((*(g_ic+16)+65536)+84)) */
    wifi_disconnect_process(0, 4, 4, lit:.rodata_wlog_debug.102, *((*(g_ic+16)+65536)+84));
    /* site +0x96: wifi_event_post(5, lit:.bss.s_pending_disconnect_evt, 41, lit:.rodata_wlog_debug.102, *((*(g_ic+16)+65536)+84)) */
    wifi_event_post(5, lit:.bss.s_pending_disconnect_evt, 41, lit:.rodata_wlog_debug.102, *((*(g_ic+16)+65536)+84));
    /* site +0xb5: ic_set_vif(ret@96, 1, 0, 0, *((*(g_ic+16)+65536)+84)) */
    ic_set_vif(ret@96, 1, 0, 0, *((*(g_ic+16)+65536)+84));
    /* site +0xbb: hal_disable_sta_tsf(ret@b5, 1, 0, 0, *((*(g_ic+16)+65536)+84)) */
    hal_disable_sta_tsf(ret@b5, 1, 0, 0, *((*(g_ic+16)+65536)+84));
    /* site +0xc1: clear_bss_queue(ret@bb, 1, 0, 0, *((*(g_ic+16)+65536)+84)) */
    clear_bss_queue(ret@bb, 1, 0, 0, *((*(g_ic+16)+65536)+84));
    /* site +0xcb: indirect call via a10 (base *(.bss.s_disconnect_evt_pending+4)); args: *(.bss.s_disconnect_evt_pending+4), 1, 0, 0, *((*(g_ic+16)+65536)+84) */
    opaque_indirect_a10();
    /* site +0xd7: wifi_event_post(3, 0, 0, 0, *((*(g_ic+16)+65536)+84)) */
    wifi_event_post(3, 0, 0, 0, *((*(g_ic+16)+65536)+84));
    return 0;
}

/* sta_bip_check @ ieee80211_sta.o 0x00000018 size 120B bind GLOBAL
 * Calls: ieee80211_is_action_category_robust, ieee80211w_get_active_igtk_key_id, ieee80211_crypto_gmac_decrypt, ieee80211_crypto_aes_128_cmac_decrypt | Data refs: g_ic
 * Fidelity: medium - branchy but loop-free, call sequence mapped */
u32 sta_bip_check(u32 a2)
{
    /* frame: entry a1,32; 43 insns, 7 cond-branches, 0 loops, 3 jumps */
    /* immediates: 240, 192, 208, 160, 0, 9 */
    /* first predicate: beq a8, a10, 4d <sta_bip_check+0x35> (condition opaque) */
    /* mem ld32: base=(?) off=4 */
    /* mem ld32: base=(*(?+4)) off=4 */
    /* mem ld8: base=(*(*(?+4)+4)) off=0 */
    /* mem ld8: base=(160) off=24 */
    /* mem ld8: base=((lit:g_ic+131072)) off=10 */
    /* site +0x43: ieee80211_is_action_category_robust(*(160+24)) */
    ieee80211_is_action_category_robust(*(160+24));
    /* site +0x52: ieee80211w_get_active_igtk_key_id(0) */
    ieee80211w_get_active_igtk_key_id(0);
    /* site +0x75: ieee80211_crypto_gmac_decrypt(0) */
    ieee80211_crypto_gmac_decrypt(0);
    /* site +0x89: ieee80211_crypto_aes_128_cmac_decrypt(0) */
    ieee80211_crypto_aes_128_cmac_decrypt(0);
    return last_call_result; /* opaque */
}

/* sta_is_wpa3_enabled @ ieee80211_sta.o 0x00000008 size 34B bind GLOBAL
 * Calls: none | Data refs: g_ic, g_wifi_menuconfig
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 sta_is_wpa3_enabled(u32 a2)
{
    /* frame: entry a1,32; 12 insns, 2 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0 */
    /* first predicate: beq a9, a2, 28 <sta_is_wpa3_enabled+0x20> (condition opaque) */
    /* mem ld32: base=(lit:g_ic) off=0x1b4 */
    /* mem ld32: base=(*(g_ic+0x1b4)) off=72 */
    /* mem ld32: base=(*(g_ic+0x1b4)) off=76 */
    /* mem ld32: base=(lit:g_wifi_menuconfig) off=64 */
    return opaque_result; /* full dataflow not recovered */
}

/* sta_is_11r_enabled @ ieee80211_sta.o 0x00000004 size 14B bind GLOBAL
 * Calls: none | Data refs: g_wifi_menuconfig
 * Fidelity: high - straight-line, fully mapped (5 insns) */
u32 sta_is_11r_enabled(u32 a2)
{
    /* frame: entry a1,32; 5 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* mem ld32: base=(lit:g_wifi_menuconfig) off=64 */
    return opaque_result; /* full dataflow not recovered */
}

/* sta_is_wifi_ent_enabled @ ieee80211_sta.o 0x00000004 size 14B bind GLOBAL
 * Calls: none | Data refs: g_wifi_menuconfig
 * Fidelity: high - straight-line, fully mapped (5 insns) */
u32 sta_is_wifi_ent_enabled(u32 a2)
{
    /* frame: entry a1,32; 5 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* mem ld32: base=(lit:g_wifi_menuconfig) off=64 */
    return opaque_result; /* full dataflow not recovered */
}

/* sta_is_bss_max_idle_enabled @ ieee80211_sta.o 0x00000004 size 14B bind GLOBAL
 * Calls: none | Data refs: g_wifi_menuconfig
 * Fidelity: high - straight-line, fully mapped (5 insns) */
u32 sta_is_bss_max_idle_enabled(u32 a2)
{
    /* frame: entry a1,32; 5 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* mem ld32: base=(lit:g_wifi_menuconfig) off=64 */
    return opaque_result; /* full dataflow not recovered */
}

/* sta_support_auto_mode_connect_passive_channel_hidden_ap @ ieee80211_sta.o 0x00000004 size 14B bind GLOBAL
 * Calls: none | Data refs: g_wifi_menuconfig
 * Fidelity: high - straight-line, fully mapped (5 insns) */
u32 sta_support_auto_mode_connect_passive_channel_hidden_ap(u32 a2)
{
    /* frame: entry a1,32; 5 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* mem ld32: base=(lit:g_wifi_menuconfig) off=64 */
    return opaque_result; /* full dataflow not recovered */
}

/* sta_get_owe_data @ ieee80211_sta.o 0x00000004 size 15B bind GLOBAL
 * Calls: none | Data refs: g_wifi_nvs
 * Fidelity: high - straight-line, fully mapped (6 insns) */
u32 sta_get_owe_data(u32 a2)
{
    /* frame: entry a1,32; 6 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0x41c */
    /* mem ld32: base=(lit:g_wifi_nvs) off=0 */
    return opaque_result; /* full dataflow not recovered */
}

/* sta_update_power_off_reset_flag @ ieee80211_sta.o 0x00000014 size 121B bind GLOBAL
 * Calls: wifi_nvs_get, wifi_nvs_compare_cfg_diff, wifi_nvs_set, wifi_nvs_commit | Data refs: g_ic
 * Fidelity: medium - branchy but loop-free, call sequence mapped */
u32 sta_update_power_off_reset_flag(u32 a2)
{
    /* frame: entry a1,48; 43 insns, 5 cond-branches, 0 loops, 1 jumps */
    /* immediates: 0, 1, 61 */
    /* first predicate: bltui a8, 2, 3e <sta_update_power_off_reset_flag+0x2a> (condition opaque) */
    /* mem st8: base=(?) off=0 */
    /* mem ld8: base=(?) off=0 */
    /* mem st8: base=((ret@1a+262144)) off=157 */
    /* mem ld8: base=((lit:g_ic+131072)) off=31 */
    /* site +0x1a: wifi_nvs_get(/* no traced args */) */
    wifi_nvs_get(/* no traced args */);
    /* site +0x51: wifi_nvs_compare_cfg_diff(61) */
    wifi_nvs_compare_cfg_diff(61);
    /* site +0x7d: wifi_nvs_set(61, *(?+0), 1) */
    wifi_nvs_set(61, *(?+0), 1);
    /* site +0x86: wifi_nvs_commit(ret@7d, *(?+0), 1) */
    wifi_nvs_commit(ret@7d, *(?+0), 1);
    return last_call_result; /* opaque */
}

/* ieee80211_sta_new_state @ ieee80211_sta.o 0x00000268 size 3592B bind GLOBAL
 * Calls: wifi_nvs_get, wifi_log, sta_update_power_off_reset_flag, wifi_event_post, indirect(a3), wifi_log, pm_send_probe_stop, indirect(a9), indirect(a9), indirect(a9), indirect(a9), pm_on_coex_schm_status_config, indirect(a10), pm_on_coex_schm_process_restart, pm_wake_done, pm_coex_set_reconnect_policy, indirect(a9), indirect(a7), wifi_log, wifi_log, wifi_log, cnx_add_to_blacklist, wifi_log, wifi_log, cnx_add_to_blacklist, wifi_log, wifi_log, wifi_log, wifi_log, wifi_log, wifi_log, wifi_log, wifi_log, wifi_log, wifi_log, ieee80211_send_mgmt, wifi_log, cnx_sta_leave, ic_get_ptk_alg, hal_crypto_enable, ic_del_ptk_and_gtk_alg, wifi_log, wifi_log, cnx_add_to_blacklist, ieee80211_send_mgmt, pm_wake_done, pm_coex_set_reconnect_policy, cnx_sta_leave, wifi_log, wifi_log, wifi_log, wifi_nvs_reset_current_ap_info, wifi_log, cnx_add_to_blacklist, pm_wake_done, pm_coex_set_reconnect_policy, cnx_sta_leave, wifi_log, indirect(a5), cnx_remove_all_rc, memcpy, memcpy, wl_clear_ap_no_lr, wifi_log, memcpy, wifi_event_post, pm_wake_up, cnx_connect_next_ap, ieee80211_send_mgmt, pm_on_coex_schm_status_config, wifi_log, ieee80211_send_mgmt, ieee80211_send_mgmt, wifi_log, wifi_log, pm_send_probe_stop, indirect(a7), indirect(a7), indirect(a7), indirect(a6), pm_on_coex_schm_status_config, cnx_sta_leave, memcpy, memcpy, wl_clear_ap_no_lr, wifi_log, indirect(a3), wifi_event_post, indirect(a10), pm_on_coex_schm_process_restart, indirect(a4), indirect(a4), indirect(a4), wifi_log, wifi_log, indirect(a4), wifi_log, indirect(a3), pm_on_coex_schm_status_config, indirect(a10), pm_on_coex_schm_process_restart, ieee80211_send_mgmt, indirect(a4), indirect(a4), indirect(a4), wifi_log, cnx_sta_associated, cnx_auth_done, indirect(a9), indirect(a9), indirect(a9), indirect(a9), pm_on_coex_schm_status_config, indirect(a10), pm_on_coex_schm_process_restart, indirect(a2), wifi_sta_get_prof_password, indirect(a2), cnx_remove_all_rc | Data refs: .rodata.ieee80211_sta_new_state.str1.1, g_wifi_nvs, .rodata.state_desc$0, .rodata_wlog_info.2, .bss.s_disconnect_evt_pending, .bss.s_pending_disconnect_evt, g_osi_funcs_p, .rodata_wlog_debug.3, g_ic, send_wake_null_timer, .rodata_wlog_debug.4, g_misc_nvs, .rodata_wlog_debug.5, .rodata_wlog_debug.6, .rodata_wlog_debug.7, .rodata_wlog_debug.8, .rodata_wlog_debug.9, .rodata_wlog_debug.10, .rodata_wlog_debug.11, .rodata_wlog_debug.12, .rodata_wlog_debug.13, .rodata_wlog_debug.14, .rodata_wlog_debug.15, .rodata_wlog_debug.16, .rodata_wlog_debug.17, .rodata_wlog_debug.18, .rodata_wlog_debug.19, .rodata_wlog_debug.20, .rodata_wlog_debug.21, g_mesh_is_root, .rodata_wlog_debug.22, .rodata_wlog_debug.23, .rodata_wlog_debug.24, .rodata_wlog_debug.25, .rodata_wlog_debug.26, .rodata_wlog_debug.27, .rodata_wlog_debug.28, .rodata_wlog_debug.29, .rodata_wlog_debug.30, .rodata_wlog_debug.31, .rodata_wlog_debug.32, .rodata_wlog_debug.33, .rodata_wlog_debug.34, .rodata_wlog_debug.35, .rodata_wlog_debug.36, .rodata_wlog_info.37, g_cnxMgr, g_cnxMgr+0xf48, .rodata_wlog_debug.38, send_deauth, .rodata_wlog_debug.39, .rodata_wlog_debug.40, .rodata_wlog_debug.41, .rodata_wlog_debug.42, cnx_auth_timeout, .rodata_wlog_debug.43, g_mesh_init_ps_type, .rodata_wlog_debug.44, .rodata_wlog_debug.45, cnx_assoc_timeout, .rodata_wlog_debug.46, .rodata_wlog_debug.47, .rodata_wlog_debug.48, send_wake_null_timeout
 * Fidelity: medium - STA state machine (state_desc + per-state arms) recovered, predicates opaque - 1311 insns, 114 branches, 0 loops; skeleton only */
u32 ieee80211_sta_new_state(u32 a2, u32 a3, u32 a4, u32 a5)
{
    /* frame: entry a1,128; 1311 insns, 114 cond-branches, 0 loops, 65 jumps */
    /* immediates: 3, 4, 1, -128, 41, 5, 0, -3, -160, -33 */
    /* first predicate: bgeui a6, 8, 2a8 <ieee80211_sta_new_state+0x40> (condition opaque) */
    /* mem ld32: base=(lit:g_wifi_nvs) off=0 */
    /* mem ld32: base=(?) off=16 */
    /* mem st32: base=(?) off=68 */
    /* mem st32: base=(?) off=64 */
    /* mem st32: base=(?) off=72 */
    /* mem ld32: base=(?) off=64 */
    /* mem ld32: base=(*(?+64)) off=152 */
    /* mem st32: base=(?) off=76 */
    /* mem ld32: base=(lit:.rodata.state_desc$0) off=0 */
    /* mem st32: base=(?) off=76 */
    /* ... +247 more memops */
    /* site +0x289: wifi_nvs_get(/* no traced args */) */
    wifi_nvs_get(/* no traced args */);
    /* site +0x2cd: wifi_log(1, 4, 3, lit:.rodata_wlog_info.2, *(?+76)) */
    wifi_log(1, 4, 3, lit:.rodata_wlog_info.2, *(?+76));
    /* site +0x2de: sta_update_power_off_reset_flag(?, 4, 3, lit:.rodata_wlog_info.2, *(?+76)) */
    sta_update_power_off_reset_flag(?, 4, 3, lit:.rodata_wlog_info.2, *(?+76));
    /* site +0x341: wifi_event_post(5, lit:.bss.s_pending_disconnect_evt, 41, lit:.rodata_wlog_info.2, *(?+76)) */
    wifi_event_post(5, lit:.bss.s_pending_disconnect_evt, 41, lit:.rodata_wlog_info.2, *(?+76));
    /* site +0x35a: indirect call via a3 (base *(*(g_osi_funcs_p+0)+0x1a0)); args: 1, lit:.bss.s_pending_disconnect_evt, 41, lit:.rodata_wlog_info.2, *(?+76) */
    opaque_indirect_a3();
    /* site +0x369: wifi_log(1, 4, 4, lit:.rodata_wlog_debug.3, *(?+76)) */
    wifi_log(1, 4, 4, lit:.rodata_wlog_debug.3, *(?+76));
    /* site +0x382: pm_send_probe_stop(ret@369, 4, 4, lit:.rodata_wlog_debug.3, *(?+76)) */
    pm_send_probe_stop(ret@369, 4, 4, lit:.rodata_wlog_debug.3, *(?+76));
    /* site +0x393: indirect call via a9 (base *(*(g_osi_funcs_p+0)+236)); args: (*(?+64)+24), 4, 4, lit:.rodata_wlog_debug.3, *(?+76) */
    opaque_indirect_a9();
    /* site +0x39e: indirect call via a9 (base *(*(g_osi_funcs_p+0)+240)); args: (*(?+64)+24), 4, 4, lit:.rodata_wlog_debug.3, *(?+76) */
    opaque_indirect_a9();
    /* site +0x3ad: indirect call via a9 (base *(*(g_osi_funcs_p+0)+236)); args: (*(?+64)+4), 4, 4, lit:.rodata_wlog_debug.3, *(?+76) */
    opaque_indirect_a9();
    /* site +0x3b7: indirect call via a9 (base *(*(g_osi_funcs_p+0)+240)); args: (*(?+64)+4), 4, 4, lit:.rodata_wlog_debug.3, *(?+76) */
    opaque_indirect_a9();
    /* site +0x3bf: pm_on_coex_schm_status_config(0, 4, 4, lit:.rodata_wlog_debug.3, *(?+76)) */
    pm_on_coex_schm_status_config(0, 4, 4, lit:.rodata_wlog_debug.3, *(?+76));
    /* site +0x3c7: indirect call via a10 (base *(*(g_osi_funcs_p+0)+0x194)); args: *(*(g_osi_funcs_p+0)+0x194), 4, 4, lit:.rodata_wlog_debug.3, *(?+76) */
    opaque_indirect_a10();
    /* site +0x3cf: pm_on_coex_schm_process_restart(ret@3c7, 4, 4, lit:.rodata_wlog_debug.3, *(?+76)) */
    pm_on_coex_schm_process_restart(ret@3c7, 4, 4, lit:.rodata_wlog_debug.3, *(?+76));
    /* site +0x405: pm_wake_done(ret@3cf, 4, 4, lit:.rodata_wlog_debug.3, *(?+76)) */
    pm_wake_done(ret@3cf, 4, 4, lit:.rodata_wlog_debug.3, *(?+76));
    /* site +0x40b: pm_coex_set_reconnect_policy(ret@405, 4, 4, lit:.rodata_wlog_debug.3, *(?+76)) */
    pm_coex_set_reconnect_policy(ret@405, 4, 4, lit:.rodata_wlog_debug.3, *(?+76));
    /* site +0x423: indirect call via a9 (base *(*(g_osi_funcs_p+0)+236)); args: lit:send_wake_null_timer, 4, 4, lit:.rodata_wlog_debug.3, *(?+76) */
    opaque_indirect_a9();
    /* site +0x42d: indirect call via a7 (base *(g_osi_funcs_p+240)); args: lit:send_wake_null_timer, 4, 4, lit:.rodata_wlog_debug.3, *(?+76) */
    opaque_indirect_a7();
    /* site +0x452: wifi_log(1, 4, 4, lit:.rodata_wlog_debug.4, *(?+76)) */
    wifi_log(1, 4, 4, lit:.rodata_wlog_debug.4, *(?+76));
    /* site +0x492: wifi_log(1, 4, 4, lit:.rodata_wlog_debug.5, *(g_osi_funcs_p+84)) */
    wifi_log(1, 4, 4, lit:.rodata_wlog_debug.5, *(g_osi_funcs_p+84));
    /* site +0x4b6: wifi_log(1, 4, 4, lit:.rodata_wlog_debug.6, *(g_osi_funcs_p+84)) */
    wifi_log(1, 4, 4, lit:.rodata_wlog_debug.6, *(g_osi_funcs_p+84));
    /* site +0x4ce: cnx_add_to_blacklist((*(*(?+64)+232)+4), 4, 4, lit:.rodata_wlog_debug.6, *(g_osi_funcs_p+84)) */
    cnx_add_to_blacklist((*(*(?+64)+232)+4), 4, 4, lit:.rodata_wlog_debug.6, *(g_osi_funcs_p+84));
    /* site +0x50b: wifi_log(1, 4, 4, lit:.rodata_wlog_debug.7, *(g_misc_nvs+84)) */
    wifi_log(1, 4, 4, lit:.rodata_wlog_debug.7, *(g_misc_nvs+84));
    /* site +0x52d: wifi_log(1, 4, 4, lit:.rodata_wlog_debug.8, *(?+55)) */
    wifi_log(1, 4, 4, lit:.rodata_wlog_debug.8, *(?+55));
    /* site +0x535: cnx_add_to_blacklist((*(*(?+64)+232)+4), 4, 4, lit:.rodata_wlog_debug.8, *(?+55)) */
    cnx_add_to_blacklist((*(*(?+64)+232)+4), 4, 4, lit:.rodata_wlog_debug.8, *(?+55));
    /* site +0x562: wifi_log(ret@535, 4, 4, lit:.rodata_wlog_debug.9, *(?+55)) */
    wifi_log(ret@535, 4, 4, lit:.rodata_wlog_debug.9, *(?+55));
    /* site +0x585: wifi_log(ret@562, 4, 4, lit:.rodata_wlog_debug.10, 15) */
    wifi_log(ret@562, 4, 4, lit:.rodata_wlog_debug.10, 15);
    /* site +0x5a9: wifi_log(2, 4, 4, lit:.rodata_wlog_debug.11, 15) */
    wifi_log(2, 4, 4, lit:.rodata_wlog_debug.11, 15);
    /* site +0x5de: wifi_log(6, 3, 3, lit:.rodata_wlog_debug.12, 15) */
    wifi_log(6, 3, 3, lit:.rodata_wlog_debug.12, 15);
    /* site +0x619: wifi_log(6, 4, 4, lit:.rodata_wlog_debug.13, 15) */
    wifi_log(6, 4, 4, lit:.rodata_wlog_debug.13, 15);
    /* site +0x645: wifi_log(6, 4, 4, lit:.rodata_wlog_debug.14, 15) */
    wifi_log(6, 4, 4, lit:.rodata_wlog_debug.14, 15);
    /* site +0x697: wifi_log(1, 4, 4, lit:.rodata_wlog_debug.15, 15) */
    wifi_log(1, 4, 4, lit:.rodata_wlog_debug.15, 15);
    /* site +0x6ba: wifi_log(1, 4, 4, lit:.rodata_wlog_debug.16, 8) */
    wifi_log(1, 4, 4, lit:.rodata_wlog_debug.16, 8);
    /* site +0x6ea: wifi_log(1, 4, 4, lit:.rodata_wlog_debug.17, *(g_misc_nvs+84)) */
    wifi_log(1, 4, 4, lit:.rodata_wlog_debug.17, *(g_misc_nvs+84));
    /* site +0x70a: wifi_log(1, 4, 4, lit:.rodata_wlog_debug.18, 8) */
    wifi_log(1, 4, 4, lit:.rodata_wlog_debug.18, 8);
    /* site +0x717: ieee80211_send_mgmt(*(*(?+64)+232), 160, 8, lit:.rodata_wlog_debug.18, 8) */
    ieee80211_send_mgmt(*(*(?+64)+232), 160, 8, lit:.rodata_wlog_debug.18, 8);
    /* site +0x72a: wifi_log(1, 160, 4, lit:.rodata_wlog_debug.19, 8) */
    wifi_log(1, 160, 4, lit:.rodata_wlog_debug.19, 8);
    /* site +0x735: cnx_sta_leave(*(?+64), *(*(?+64)+232), 4, lit:.rodata_wlog_debug.19, 8) */
    cnx_sta_leave(*(?+64), *(*(?+64)+232), 4, lit:.rodata_wlog_debug.19, 8);
    /* site +0x73d: ic_get_ptk_alg(0, *(*(?+64)+232), 4, lit:.rodata_wlog_debug.19, 8) */
    ic_get_ptk_alg(0, *(*(?+64)+232), 4, lit:.rodata_wlog_debug.19, 8);
    /* site +0x74b: hal_crypto_enable(0, ret@73d, 1, 0, 8) */
    hal_crypto_enable(0, ret@73d, 1, 0, 8);
    /* site +0x753: ic_del_ptk_and_gtk_alg(0, ret@73d, 1, 0, 8) */
    ic_del_ptk_and_gtk_alg(0, ret@73d, 1, 0, 8);
    /* site +0x787: wifi_log(1, 4, 4, lit:.rodata_wlog_debug.20, *(g_misc_nvs+84)) */
    wifi_log(1, 4, 4, lit:.rodata_wlog_debug.20, *(g_misc_nvs+84));
    /* site +0x7a3: wifi_log(ret@787, 4, 4, lit:.rodata_wlog_debug.21, *(g_misc_nvs+84)) */
    wifi_log(ret@787, 4, 4, lit:.rodata_wlog_debug.21, *(g_misc_nvs+84));
    /* site +0x7dd: cnx_add_to_blacklist((*(*(?+64)+232)+4), 4, 4, lit:.rodata_wlog_debug.21, *(g_misc_nvs+84)) */
    cnx_add_to_blacklist((*(*(?+64)+232)+4), 4, 4, lit:.rodata_wlog_debug.21, *(g_misc_nvs+84));
    /* site +0x807: ieee80211_send_mgmt(*(*(?+64)+232), 192, 3, lit:.rodata_wlog_debug.21, *(g_misc_nvs+84)) */
    ieee80211_send_mgmt(*(*(?+64)+232), 192, 3, lit:.rodata_wlog_debug.21, *(g_misc_nvs+84));
    /* site +0x80f: pm_wake_done(ret@807, 192, 3, lit:.rodata_wlog_debug.21, *(g_misc_nvs+84)) */
    pm_wake_done(ret@807, 192, 3, lit:.rodata_wlog_debug.21, *(g_misc_nvs+84));
    /* site +0x815: pm_coex_set_reconnect_policy(ret@80f, 192, 3, lit:.rodata_wlog_debug.21, *(g_misc_nvs+84)) */
    pm_coex_set_reconnect_policy(ret@80f, 192, 3, lit:.rodata_wlog_debug.21, *(g_misc_nvs+84));
    /* site +0x823: cnx_sta_leave(*(?+64), *(.bss.s_disconnect_evt_pending+228), 3, lit:.rodata_wlog_debug.21, *(g_misc_nvs+84)) */
    cnx_sta_leave(*(?+64), *(.bss.s_disconnect_evt_pending+228), 3, lit:.rodata_wlog_debug.21, *(g_misc_nvs+84));
    /* site +0x921: wifi_log(1, *(?+72), 4, lit:.rodata_wlog_debug.30, 3) */
    wifi_log(1, *(?+72), 4, lit:.rodata_wlog_debug.30, 3);
    /* site +0x941: wifi_log(1, 4, 4, lit:.rodata_wlog_debug.31, *(g_mesh_is_root+84)) */
    wifi_log(1, 4, 4, lit:.rodata_wlog_debug.31, *(g_mesh_is_root+84));
    /* site +0x969: wifi_log(1, 4, 4, lit:.rodata_wlog_debug.32, *(g_mesh_is_root+84)) */
    wifi_log(1, 4, 4, lit:.rodata_wlog_debug.32, *(g_mesh_is_root+84));
    /* site +0x9b7: wifi_nvs_reset_current_ap_info((*(g_mesh_is_root+1)+-9), 4, 4, lit:.rodata_wlog_debug.32, *(g_mesh_is_root+84)) */
    wifi_nvs_reset_current_ap_info((*(g_mesh_is_root+1)+-9), 4, 4, lit:.rodata_wlog_debug.32, *(g_mesh_is_root+84));
    /* site +0xa65: wifi_log(1, 4, 4, lit:.rodata_wlog_debug.36, 202) */
    wifi_log(1, 4, 4, lit:.rodata_wlog_debug.36, 202);
    /* site +0xa8b: cnx_add_to_blacklist((11+4), 4, 4, lit:.rodata_wlog_debug.36, 202) */
    cnx_add_to_blacklist((11+4), 4, 4, lit:.rodata_wlog_debug.36, 202);
    /* site +0xa91: pm_wake_done(ret@a8b, 4, 4, lit:.rodata_wlog_debug.36, 202) */
    pm_wake_done(ret@a8b, 4, 4, lit:.rodata_wlog_debug.36, 202);
    /* site +0xa97: pm_coex_set_reconnect_policy(ret@a91, 4, 4, lit:.rodata_wlog_debug.36, 202) */
    pm_coex_set_reconnect_policy(ret@a91, 4, 4, lit:.rodata_wlog_debug.36, 202);
    /* site +0xaa5: cnx_sta_leave(*(?+64), *(.bss.s_disconnect_evt_pending+228), 4, lit:.rodata_wlog_debug.36, 202) */
    cnx_sta_leave(*(?+64), *(.bss.s_disconnect_evt_pending+228), 4, lit:.rodata_wlog_debug.36, 202);
    /* site +0xacb: wifi_log(1, 4, 3, lit:.rodata_wlog_info.37, *(?+76)) */
    wifi_log(1, 4, 3, lit:.rodata_wlog_info.37, *(?+76));
    /* site +0xadb: indirect call via a5 (base *(.rodata.state_desc$0+16)); args: *(?+55), 4, 3, lit:.rodata_wlog_info.37, *(?+76) */
    opaque_indirect_a5();
    /* site +0xb00: cnx_remove_all_rc(ret@adb, 4, 3, lit:.rodata_wlog_info.37, *(?+76)) */
    cnx_remove_all_rc(ret@adb, 4, 3, lit:.rodata_wlog_info.37, *(?+76));
    /* site +0xb55: memcpy((?+49), 156, 6, lit:.rodata_wlog_info.37, *(?+76)) */
    memcpy((?+49), 156, 6, lit:.rodata_wlog_info.37, *(?+76));
    /* site +0xb65: memcpy((?+16), (*(?+68)+8), 32, lit:.rodata_wlog_info.37, *(?+76)) */
    memcpy((?+16), (*(?+68)+8), 32, lit:.rodata_wlog_info.37, *(?+76));
    /* site +0xb76: wl_clear_ap_no_lr(ret@b65, (*(?+68)+8), 32, lit:.rodata_wlog_info.37, *(?+76)) */
    wl_clear_ap_no_lr(ret@b65, (*(?+68)+8), 32, lit:.rodata_wlog_info.37, *(?+76));
    /* site +0xb8b: wifi_log(1, 36, 4, lit:.rodata_wlog_debug.38, *(?+55)) */
    wifi_log(1, 36, 4, lit:.rodata_wlog_debug.38, *(?+55));
    /* site +0xb9d: memcpy(lit:.bss.s_pending_disconnect_evt, (?+16), 41, lit:.rodata_wlog_debug.38, *(?+55)) */
    memcpy(lit:.bss.s_pending_disconnect_evt, (?+16), 41, lit:.rodata_wlog_debug.38, *(?+55));
    /* site +0xbb5: wifi_event_post(5, (?+16), 41, lit:.rodata_wlog_debug.38, *(?+55)) */
    wifi_event_post(5, (?+16), 41, lit:.rodata_wlog_debug.38, *(?+55));
    /* site +0xbbf: pm_wake_up(ret@bb5, (?+16), 41, lit:.rodata_wlog_debug.38, *(?+55)) */
    pm_wake_up(ret@bb5, (?+16), 41, lit:.rodata_wlog_debug.38, *(?+55));
    /* site +0xbc5: cnx_connect_next_ap(ret@bbf, (?+16), 41, lit:.rodata_wlog_debug.38, *(?+55)) */
    cnx_connect_next_ap(ret@bbf, (?+16), 41, lit:.rodata_wlog_debug.38, *(?+55));
    /* site +0xbf7: ieee80211_send_mgmt((lit:g_cnxMgr+983040), 192, 3, lit:.rodata_wlog_debug.38, *(?+55)) */
    ieee80211_send_mgmt((lit:g_cnxMgr+983040), 192, 3, lit:.rodata_wlog_debug.38, *(?+55));
    /* site +0xbff: pm_on_coex_schm_status_config(2, 192, 3, lit:.rodata_wlog_debug.38, *(?+55)) */
    pm_on_coex_schm_status_config(2, 192, 3, lit:.rodata_wlog_debug.38, *(?+55));
    /* site +0xc31: wifi_log(1, 4, 4, lit:.rodata_wlog_debug.39, *(send_deauth+84)) */
    wifi_log(1, 4, 4, lit:.rodata_wlog_debug.39, *(send_deauth+84));
    /* site +0xc7e: ieee80211_send_mgmt((lit:g_cnxMgr+983040), 176, 1, lit:.rodata_wlog_debug.39, *(send_deauth+84)) */
    ieee80211_send_mgmt((lit:g_cnxMgr+983040), 176, 1, lit:.rodata_wlog_debug.39, *(send_deauth+84));
    /* site +0xca6: ieee80211_send_mgmt(ret@c7e, 176, 1, lit:.rodata_wlog_debug.39, *(send_deauth+84)) */
    ieee80211_send_mgmt(ret@c7e, 176, 1, lit:.rodata_wlog_debug.39, *(send_deauth+84));
    /* site +0xcda: wifi_log(1, 4, 4, lit:.rodata_wlog_debug.40, *(.rodata.ieee80211_sta_new_state.str1.1+84)) */
    wifi_log(1, 4, 4, lit:.rodata_wlog_debug.40, *(.rodata.ieee80211_sta_new_state.str1.1+84));
    /* site +0xcfd: wifi_log(1, 4, 4, lit:.rodata_wlog_debug.41, *(.rodata.ieee80211_sta_new_state.str1.1+84)) */
    wifi_log(1, 4, 4, lit:.rodata_wlog_debug.41, *(.rodata.ieee80211_sta_new_state.str1.1+84));
    /* site +0xd16: pm_send_probe_stop(ret@cfd, 4, 4, lit:.rodata_wlog_debug.41, *(.rodata.ieee80211_sta_new_state.str1.1+84)) */
    pm_send_probe_stop(ret@cfd, 4, 4, lit:.rodata_wlog_debug.41, *(.rodata.ieee80211_sta_new_state.str1.1+84));
    /* site +0xd2a: indirect call via a7 (base *(g_cnxMgr+0xf48+236)); args: (*(?+64)+24), 4, 4, lit:.rodata_wlog_debug.41, *(.rodata.ieee80211_sta_new_state.str1.1+84) */
    opaque_indirect_a7();
    /* site +0xd36: indirect call via a7 (base *(g_cnxMgr+0xf48+240)); args: ret@d2a, 4, 4, lit:.rodata_wlog_debug.41, *(.rodata.ieee80211_sta_new_state.str1.1+84) */
    opaque_indirect_a7();
    /* site +0xd47: indirect call via a7 (base *(g_cnxMgr+0xf48+236)); args: ret@d36, 4, 4, lit:.rodata_wlog_debug.41, *(.rodata.ieee80211_sta_new_state.str1.1+84) */
    opaque_indirect_a7();
    /* site +0xd52: indirect call via a6 (base *(g_osi_funcs_p+240)); args: (*(?+64)+4), 4, 4, lit:.rodata_wlog_debug.41, *(.rodata.ieee80211_sta_new_state.str1.1+84) */
    opaque_indirect_a6();
    /* site +0xd5a: pm_on_coex_schm_status_config(0, 4, 4, lit:.rodata_wlog_debug.41, *(.rodata.ieee80211_sta_new_state.str1.1+84)) */
    pm_on_coex_schm_status_config(0, 4, 4, lit:.rodata_wlog_debug.41, *(.rodata.ieee80211_sta_new_state.str1.1+84));
    /* site +0xd66: cnx_sta_leave(*(?+64), 4, 4, lit:.rodata_wlog_debug.41, *(.rodata.ieee80211_sta_new_state.str1.1+84)) */
    cnx_sta_leave(*(?+64), 4, 4, lit:.rodata_wlog_debug.41, *(.rodata.ieee80211_sta_new_state.str1.1+84));
    /* site +0xd82: memcpy((?+49), 156, 6, lit:.rodata_wlog_debug.41, *(.rodata.ieee80211_sta_new_state.str1.1+84)) */
    memcpy((?+49), 156, 6, lit:.rodata_wlog_debug.41, *(.rodata.ieee80211_sta_new_state.str1.1+84));
    /* site +0xd92: memcpy((?+16), (*(?+68)+8), 32, lit:.rodata_wlog_debug.41, *(.rodata.ieee80211_sta_new_state.str1.1+84)) */
    memcpy((?+16), (*(?+68)+8), 32, lit:.rodata_wlog_debug.41, *(.rodata.ieee80211_sta_new_state.str1.1+84));
    /* site +0xda7: wl_clear_ap_no_lr(ret@d92, (*(?+68)+8), 32, lit:.rodata_wlog_debug.41, *(.rodata.ieee80211_sta_new_state.str1.1+84)) */
    wl_clear_ap_no_lr(ret@d92, (*(?+68)+8), 32, lit:.rodata_wlog_debug.41, *(.rodata.ieee80211_sta_new_state.str1.1+84));
    /* site +0xdba: wifi_log(1, 36, 4, lit:.rodata_wlog_debug.42, *(?+55)) */
    wifi_log(1, 36, 4, lit:.rodata_wlog_debug.42, *(?+55));
    /* site +0xdc5: indirect call via a3 (base *(g_ic+16)); args: *(?+55), 36, 4, lit:.rodata_wlog_debug.42, *(?+55) */
    opaque_indirect_a3();
    /* site +0xdd2: wifi_event_post(5, (?+16), 41, lit:.rodata_wlog_debug.42, *(?+55)) */
    wifi_event_post(5, (?+16), 41, lit:.rodata_wlog_debug.42, *(?+55));
    /* site +0xdde: indirect call via a10 (base *(.rodata.ieee80211_sta_new_state.str1.1+...); args: *(.rodata.ieee80211_sta_new_state.str1.1+..., (?+16), 41, lit:.rodata_wlog_debug.42, *(?+55) */
    opaque_indirect_a10();
    /* site +0xde6: pm_on_coex_schm_process_restart(ret@dde, (?+16), 41, lit:.rodata_wlog_debug.42, *(?+55)) */
    pm_on_coex_schm_process_restart(ret@dde, (?+16), 41, lit:.rodata_wlog_debug.42, *(?+55));
    /* site +0xdf5: indirect call via a4 (base *(.rodata.ieee80211_sta_new_state.str1.1+...); args: (*(?+64)+4), (?+16), 41, lit:.rodata_wlog_debug.42, *(?+55) */
    opaque_indirect_a4();
    /* site +0xdff: indirect call via a4 (base *(.rodata.ieee80211_sta_new_state.str1.1+...); args: (*(?+64)+4), (?+16), 41, lit:.rodata_wlog_debug.42, *(?+55) */
    opaque_indirect_a4();
    /* site +0xe0e: indirect call via a4 (base *(.rodata.ieee80211_sta_new_state.str1.1+...); args: (*(?+64)+4), lit:cnx_auth_timeout, 0, lit:.rodata_wlog_debug.42, *(?+55) */
    opaque_indirect_a4();
    /* site +0xe31: wifi_log(1, 4, 4, lit:.rodata_wlog_debug.43, (125 slli 5)) */
    wifi_log(1, 4, 4, lit:.rodata_wlog_debug.43, (125 slli 5));
    /* site +0xe7d: wifi_log(1, 4, 4, lit:.rodata_wlog_debug.44, 0x4b0) */
    wifi_log(1, 4, 4, lit:.rodata_wlog_debug.44, 0x4b0);
    /* site +0xea5: indirect call via a4 (base *(g_osi_funcs_p+232)); args: (*(?+64)+4), 0x4b0, 0, lit:.rodata_wlog_debug.44, 0x4b0 */
    opaque_indirect_a4();
    /* site +0xebb: wifi_log(1, 4, 4, lit:.rodata_wlog_debug.45, 0x3e8) */
    wifi_log(1, 4, 4, lit:.rodata_wlog_debug.45, 0x3e8);
    /* site +0xeca: indirect call via a3 (base *(g_mesh_init_ps_type+232)); args: (*(?+64)+4), 0x3e8, 0, lit:.rodata_wlog_debug.45, 0x3e8 */
    opaque_indirect_a3();
    /* site +0xed6: pm_on_coex_schm_status_config(2, 0x3e8, 0, lit:.rodata_wlog_debug.45, 0x3e8) */
    pm_on_coex_schm_status_config(2, 0x3e8, 0, lit:.rodata_wlog_debug.45, 0x3e8);
    /* site +0xee1: indirect call via a10 (base *(g_mesh_init_ps_type+0x194)); args: *(g_mesh_init_ps_type+0x194), 0x3e8, 0, lit:.rodata_wlog_debug.45, 0x3e8 */
    opaque_indirect_a10();
    /* site +0xee9: pm_on_coex_schm_process_restart(ret@ee1, 0x3e8, 0, lit:.rodata_wlog_debug.45, 0x3e8) */
    pm_on_coex_schm_process_restart(ret@ee1, 0x3e8, 0, lit:.rodata_wlog_debug.45, 0x3e8);
    /* site +0xf0f: ieee80211_send_mgmt(*(g_mesh_init_ps_type+0), 32, 0, lit:.rodata_wlog_debug.45, 0x3e8) */
    ieee80211_send_mgmt(*(g_mesh_init_ps_type+0), 32, 0, lit:.rodata_wlog_debug.45, 0x3e8);
    /* site +0xf1f: indirect call via a4 (base *(g_mesh_init_ps_type+236)); args: (*(?+64)+4), 32, 0, lit:.rodata_wlog_debug.45, 0x3e8 */
    opaque_indirect_a4();
    /* site +0xf2a: indirect call via a4 (base *(g_mesh_init_ps_type+240)); args: (*(?+64)+4), 32, 0, lit:.rodata_wlog_debug.45, 0x3e8 */
    opaque_indirect_a4();
    /* site +0xf39: indirect call via a4 (base *(g_mesh_init_ps_type+244)); args: (*(?+64)+4), lit:cnx_assoc_timeout, 0, lit:.rodata_wlog_debug.45, 0x3e8 */
    opaque_indirect_a4();
    /* site +0xf85: wifi_log(1, *(g_osi_funcs_p+84), *(g_osi_funcs_p+84), lit:.rodata_wlog_debug.48, *(g_osi_funcs_p+84)) */
    wifi_log(1, *(g_osi_funcs_p+84), *(g_osi_funcs_p+84), lit:.rodata_wlog_debug.48, *(g_osi_funcs_p+84));
    /* site +0xfad: cnx_sta_associated(*(?+64), *(g_mesh_init_ps_type+0), 1, lit:.rodata_wlog_debug.48, *(g_osi_funcs_p+84)) */
    cnx_sta_associated(*(?+64), *(g_mesh_init_ps_type+0), 1, lit:.rodata_wlog_debug.48, *(g_osi_funcs_p+84));
    /* site +0xfbe: cnx_auth_done(ret@fad, *(g_mesh_init_ps_type+0), 1, lit:.rodata_wlog_debug.48, *(g_osi_funcs_p+84)) */
    cnx_auth_done(ret@fad, *(g_mesh_init_ps_type+0), 1, lit:.rodata_wlog_debug.48, *(g_osi_funcs_p+84));
    /* site +0xfd1: indirect call via a9 (base *(*(g_osi_funcs_p+0)+236)); args: lit:send_wake_null_timer, *(g_mesh_init_ps_type+0), 1, lit:.rodata_wlog_debug.48, *(g_osi_funcs_p+84) */
    opaque_indirect_a9();
    /* site +0xfdb: indirect call via a9 (base *(*(g_osi_funcs_p+0)+240)); args: lit:send_wake_null_timer, *(g_mesh_init_ps_type+0), 1, lit:.rodata_wlog_debug.48, *(g_osi_funcs_p+84) */
    opaque_indirect_a9();
    /* site +0xfeb: indirect call via a9 (base *(*(g_osi_funcs_p+0)+244)); args: lit:send_wake_null_timer, lit:send_wake_null_timeout, 0, lit:.rodata_wlog_debug.48, *(g_osi_funcs_p+84) */
    opaque_indirect_a9();
    /* site +0xffa: indirect call via a9 (base *(*(g_osi_funcs_p+0)+232)); args: lit:send_wake_null_timer, 0x12c, 0, lit:.rodata_wlog_debug.48, *(g_osi_funcs_p+84) */
    opaque_indirect_a9();
    /* site +0x100d: pm_on_coex_schm_status_config(2, 0x12c, 0, lit:.rodata_wlog_debug.48, *(g_osi_funcs_p+84)) */
    pm_on_coex_schm_status_config(2, 0x12c, 0, lit:.rodata_wlog_debug.48, *(g_osi_funcs_p+84));
    /* site +0x1015: indirect call via a10 (base *(g_osi_funcs_p+0x194)); args: *(g_osi_funcs_p+0x194), 0x12c, 0, lit:.rodata_wlog_debug.48, *(g_osi_funcs_p+84) */
    opaque_indirect_a10();
    /* site +0x101d: pm_on_coex_schm_process_restart(ret@1015, 0x12c, 0, lit:.rodata_wlog_debug.48, *(g_osi_funcs_p+84)) */
    pm_on_coex_schm_process_restart(ret@1015, 0x12c, 0, lit:.rodata_wlog_debug.48, *(g_osi_funcs_p+84));
    /* site +0x1046: indirect call via a2 (base *(g_osi_funcs_p+20)); args: ret@101d, 0x12c, 0, lit:.rodata_wlog_debug.48, *(g_osi_funcs_p+84) */
    opaque_indirect_a2();
    /* site +0x1055: wifi_sta_get_prof_password(ret@1046, 0x12c, 0, lit:.rodata_wlog_debug.48, *(g_osi_funcs_p+84)) */
    wifi_sta_get_prof_password(ret@1046, 0x12c, 0, lit:.rodata_wlog_debug.48, *(g_osi_funcs_p+84));
    /* site +0x105a: indirect call via a2 (base *(g_osi_funcs_p+24)); args: ret@1055, 0, 0, lit:.rodata_wlog_debug.48, *(g_osi_funcs_p+84) */
    opaque_indirect_a2();
    /* site +0x1065: cnx_remove_all_rc(ret@105a, 0, 0, lit:.rodata_wlog_debug.48, *(g_osi_funcs_p+84)) */
    cnx_remove_all_rc(ret@105a, 0, 0, lit:.rodata_wlog_debug.48, *(g_osi_funcs_p+84));
        /* ---- RECOVERED (medium): STA state machine (3592B, 114 branches) ----
       States (movi verbatim: 0,1,2,3,4,5,6,8 + 192/160/176/41 mgmt FC-ish gates;
       names from .rodata.state_desc$0 + .rodata.ieee80211_sta_new_state.str1.1,
       values from disasm only; transition predicates opaque):
         0 INIT/IDLE: sta_update_power_off_reset_flag, event_post, pm_send_probe_stop,
            coex_schm restart/status, wake_done, coex_reconnect_policy;
         1 SCAN/AUTH start: cnx_add_to_blacklist, wifi_log, ieee80211_send_mgmt (auth);
         2 ASSOC: send_mgmt (assoc), cnx_sta_leave on fail;
         3 ASSOCIATED: cnx_sta_associated path, ptk_alg get, hal_crypto_enable,
            del_ptk_and_gtk_alg;
         4 KEY/DONE: cnx_auth_done, event_post;
         5 DISCONNECT: send_mgmt (deauth/disassoc), cnx_sta_leave, remove_all_rc,
            sta_get_prof_password path;
         6+ CSA/handoff: blacklist + send_mgmt + wake_done/coex policy.
       BSS slots: s_disconnect_evt_pending / s_pending_disconnect_evt (.bss);
       s8i +55/+84 state bytes, l8ui +0/+84/+55, l32i +64/+236/+240/+116. */
    {
        unsigned __rec_new = 0u; (void)__rec_new;
        unsigned __rec_old = 0u; (void)__rec_old;
        switch (__rec_new) {
        case 0u: __rec_old = 10u; break;
        case 1u: __rec_old = 11u; break;
        case 2u: __rec_old = 12u; break;
        case 3u: __rec_old = 13u; break;
        case 4u: __rec_old = 14u; break;
        case 5u: __rec_old = 15u; break;
        case 6u: __rec_old = 16u; break;
        default: __rec_old = 0u; break;
        }
        if (__rec_old == 15u) { __rec_new = 5u; } else { __rec_new = __rec_old; }
        (void)__rec_new;
    }

return 0;
}

/* sta_auth_ft @ ieee80211_sta.o 0x00000014 size 58B bind GLOBAL
 * Calls: wifi_log, ieee80211_sta_new_state | Data refs: .rodata_wlog_debug.63, g_ic
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 sta_auth_ft(u32 a2, u32 a6, u32 a7)
{
    /* frame: entry a1,32; 23 insns, 3 cond-branches, 0 loops, 1 jumps */
    /* immediates: 0, 3, 4, 1 */
    /* first predicate: beqz.n a2, 4c <sta_auth_ft+0x38> (condition opaque) */
    /* mem ld32: base=(?) off=0 */
    /* site +0x39: wifi_log(1, 4, 4, lit:.rodata_wlog_debug.63) */
    wifi_log(1, 4, 4, lit:.rodata_wlog_debug.63);
    /* site +0x49: ieee80211_sta_new_state(lit:g_ic, 0, lit:.rodata_wlog_debug.63, lit:.rodata_wlog_debug.63) */
    ieee80211_sta_new_state(lit:g_ic, 0, lit:.rodata_wlog_debug.63, lit:.rodata_wlog_debug.63);
    return opaque_result; /* full dataflow not recovered */
}

/* sta_auth_open @ ieee80211_sta.o 0x00000028 size 142B bind GLOBAL
 * Calls: wifi_log, wifi_log, ieee80211_send_mgmt, wifi_log, ieee80211_sta_new_state | Data refs: .rodata_wlog_debug.64, g_ic, .rodata_wlog_debug.65, .rodata_wlog_debug.66
 * Fidelity: medium - branchy but loop-free, call sequence mapped */
u32 sta_auth_open(u32 a2, u32 a6, u32 a7)
{
    /* frame: entry a1,32; 52 insns, 5 cond-branches, 0 loops, 3 jumps */
    /* immediates: 4, 1, 13, 176, 3, 0 */
    /* first predicate: beqz a2, b4 <sta_auth_open+0x8c> (condition opaque) */
    /* mem ld32: base=(?) off=0 */
    /* mem st8: base=((lit:g_ic+131072)) off=0 */
    /* mem ld32: base=(*(?+0)) off=228 */
    /* site +0x4d: wifi_log(1, ?, 4, lit:.rodata_wlog_debug.64) */
    wifi_log(1, ?, 4, lit:.rodata_wlog_debug.64);
    /* site +0x77: wifi_log(1, 4, 4, lit:.rodata_wlog_debug.65) */
    wifi_log(1, 4, 4, lit:.rodata_wlog_debug.65);
    /* site +0x85: ieee80211_send_mgmt(*(*(?+0)+228), 176, 1, lit:.rodata_wlog_debug.65) */
    ieee80211_send_mgmt(*(*(?+0)+228), 176, 1, lit:.rodata_wlog_debug.65);
    /* site +0xa1: wifi_log(1, 4, 4, lit:.rodata_wlog_debug.66) */
    wifi_log(1, 4, 4, lit:.rodata_wlog_debug.66);
    /* site +0xb1: ieee80211_sta_new_state((lit:g_ic+131072), 0, (? slli 8), lit:.rodata_wlog_debug.66) */
    ieee80211_sta_new_state((lit:g_ic+131072), 0, (? slli 8), lit:.rodata_wlog_debug.66);
    return opaque_result; /* full dataflow not recovered */
}

/* sta_auth_shared @ ieee80211_sta.o 0x00000028 size 294B bind GLOBAL
 * Calls: wifi_log, indirect(a2), ieee80211_alloc_challenge, memcpy, wifi_log, ieee80211_send_mgmt, ieee80211_sta_new_state | Data refs: g_ic, .rodata_wlog_debug.67, g_osi_funcs_p, .rodata_wlog_debug.68
 * Fidelity: medium - 106 insns, 18 branches, 0 loops; branchy but loop-free, call sequence mapped (verified against section disasm; predicates opaque) */
u32 sta_auth_shared(u32 a2, u32 a5)
{
    /* frame: entry a1,32; 106 insns, 18 cond-branches, 0 loops, 6 jumps */
    /* immediates: 13, 4, 2, 1, 253, 0, 3, 176, 0x600 */
    /* first predicate: beqz a2, 14c <sta_auth_shared+0x124> (condition opaque) */
    /* mem ld16: base=(?) off=32 */
    /* mem ld16: base=(?) off=36 */
    /* mem ld32: base=(?) off=0 */
    /* mem st8: base=((lit:g_ic+131072)) off=0 */
    /* mem ld32: base=((lit:g_ic+131072)) off=164 */
    /* mem ld8: base=((lit:g_ic+131072)) off=0 */
    /* mem ld8: base=(2) off=1 */
    /* mem ld8: base=(2) off=0 */
    /* mem ld8: base=(0) off=1 */
    /* mem ld32: base=((lit:g_ic+131072)) off=176 */
    /* ... +6 more memops */
    /* site +0x5d: wifi_log(1, 4, 4, lit:.rodata_wlog_debug.67, *(?+36)) */
    wifi_log(1, 4, 4, lit:.rodata_wlog_debug.67, *(?+36));
    /* site +0xe5: indirect call via a2 (base *(g_osi_funcs_p+176)); args: *(g_ic+176), (*(?+32)+-2), 1, lit:.rodata_wlog_debug.67, *(?+36) */
    opaque_indirect_a2();
    /* site +0x101: ieee80211_alloc_challenge((lit:g_ic+131072), 3, *(?+36), lit:.rodata_wlog_debug.67, *(?+36)) */
    ieee80211_alloc_challenge((lit:g_ic+131072), 3, *(?+36), lit:.rodata_wlog_debug.67, *(?+36));
    /* site +0x112: memcpy(*(g_ic+176), (0+2), *(0+1), lit:.rodata_wlog_debug.67, *(?+36)) */
    memcpy(*(g_ic+176), (0+2), *(0+1), lit:.rodata_wlog_debug.67, *(?+36));
    /* site +0x123: wifi_log(1, 4, 4, lit:.rodata_wlog_debug.68, 3) */
    wifi_log(1, 4, 4, lit:.rodata_wlog_debug.68, 3);
    /* site +0x131: ieee80211_send_mgmt(ret@123, 176, 3, lit:.rodata_wlog_debug.68, 3) */
    ieee80211_send_mgmt(ret@123, 176, 3, lit:.rodata_wlog_debug.68, 3);
    /* site +0x149: ieee80211_sta_new_state(lit:g_ic, 0, 0x600, lit:.rodata_wlog_debug.68, 3) */
    ieee80211_sta_new_state(lit:g_ic, 0, 0x600, lit:.rodata_wlog_debug.68, 3);
    return opaque_result; /* full dataflow not recovered */
}

/* sta_auth_sae @ ieee80211_sta.o 0x00000028 size 330B bind GLOBAL
 * Calls: sta_is_wpa3_enabled, indirect(a9), ieee80211_send_mgmt, pm_on_coex_schm_status_config, indirect(a10), pm_on_coex_schm_process_restart, indirect(a3), indirect(a3), indirect(a3), indirect(a2), ieee80211_sta_new_state, ieee80211_sta_new_state | Data refs: g_ic, g_osi_funcs_p, cnx_auth_timeout
 * Fidelity: medium - 120 insns, 18 branches, 0 loops; branchy but loop-free, call sequence mapped (verified against section disasm; predicates opaque) */
u32 sta_auth_sae(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6)
{
    /* frame: entry a1,48; 120 insns, 18 cond-branches, 0 loops, 8 jumps */
    /* immediates: 253, 77, 0, 2, 1, 176, 76, 0x7d0, 3, 0x600 */
    /* first predicate: beqz a2, 170 <sta_auth_sae+0x148> (condition opaque) */
    /* mem ld32: base=(?) off=0 */
    /* mem st32: base=(?) off=0 */
    /* mem ld8: base=((lit:g_ic+131072)) off=0 */
    /* mem ld32: base=(lit:g_ic) off=0x1b4 */
    /* mem ld32: base=(*(g_ic+0x1b4)) off=76 */
    /* mem st32: base=(?) off=0 */
    /* mem ld32: base=(?) off=0 */
    /* mem st8: base=((lit:g_ic+131072)) off=11 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=0x194 */
    /* ... +10 more memops */
    /* site +0x41: sta_is_wpa3_enabled(/* no traced args */) */
    sta_is_wpa3_enabled(/* no traced args */);
    /* site +0x82: indirect call via a9 (base *(*(g_ic+0x1b4)+76)); args: /* no traced args */ */
    opaque_indirect_a9();
    /* site +0xdf: ieee80211_send_mgmt(?, 176, (ret@82 slli 16)) */
    ieee80211_send_mgmt(?, 176, (ret@82 slli 16));
    /* site +0xea: pm_on_coex_schm_status_config(2, 176, (ret@82 slli 16)) */
    pm_on_coex_schm_status_config(2, 176, (ret@82 slli 16));
    /* site +0xf6: indirect call via a10 (base *(*(g_osi_funcs_p+0)+0x194)); args: *(*(g_osi_funcs_p+0)+0x194), 176, (ret@82 slli 16) */
    opaque_indirect_a10();
    /* site +0xfe: pm_on_coex_schm_process_restart(ret@f6, 176, (ret@82 slli 16)) */
    pm_on_coex_schm_process_restart(ret@f6, 176, (ret@82 slli 16));
    /* site +0x111: indirect call via a3 (base *(*(g_osi_funcs_p+0)+236)); args: ret@fe, 176, (ret@82 slli 16) */
    opaque_indirect_a3();
    /* site +0x11b: indirect call via a3 (base *(*(g_osi_funcs_p+0)+240)); args: (*(?+0)+4), 176, (ret@82 slli 16) */
    opaque_indirect_a3();
    /* site +0x12a: indirect call via a3 (base *(*(g_osi_funcs_p+0)+244)); args: (*(?+0)+4), lit:cnx_auth_timeout, 0 */
    opaque_indirect_a3();
    /* site +0x139: indirect call via a2 (base *(g_osi_funcs_p+232)); args: (*(?+0)+4), 0x7d0, 0 */
    opaque_indirect_a2();
    /* site +0x14d: ieee80211_sta_new_state(&pm_on_coex_schm_process_restart(), 3, 0) */
    ieee80211_sta_new_state(&pm_on_coex_schm_process_restart(), 3, 0);
    /* site +0x16d: ieee80211_sta_new_state(lit:g_ic, 0, 0x600) */
    ieee80211_sta_new_state(lit:g_ic, 0, 0x600);
    return opaque_result; /* full dataflow not recovered */
}

/* sta_retry_assoc @ ieee80211_sta.o 0x00000010 size 88B bind GLOBAL
 * Calls: indirect(a8), indirect(a4), sta_is_wpa3_enabled, indirect(a3), ieee80211_sta_new_state | Data refs: g_ic, g_osi_funcs_p
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 sta_retry_assoc(u32 a2)
{
    /* frame: entry a1,32; 33 insns, 3 cond-branches, 0 loops, 1 jumps */
    /* immediates: 176, 2, 0, 3 */
    /* first predicate: beqz a4, 66 <sta_retry_assoc+0x56> (condition opaque) */
    /* mem ld32: base=(lit:g_ic) off=16 */
    /* mem ld32: base=(*(g_ic+16)) off=228 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=236 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=240 */
    /* mem ld8: base=((lit:g_ic+131072)) off=0 */
    /* mem ld32: base=(lit:g_ic) off=0x1b4 */
    /* mem ld32: base=(*(g_ic+0x1b4)) off=100 */
    /* site +0x2b: indirect call via a8 (base *(*(g_osi_funcs_p+0)+236)); args: (*(g_ic+16)+84) */
    opaque_indirect_a8();
    /* site +0x35: indirect call via a4 (base *(g_osi_funcs_p+240)); args: (*(g_ic+16)+84) */
    opaque_indirect_a4();
    /* site +0x3b: sta_is_wpa3_enabled(ret@35) */
    sta_is_wpa3_enabled(ret@35);
    /* site +0x4f: indirect call via a3 (base *(*(g_ic+0x1b4)+100)); args: ret@3b */
    opaque_indirect_a3();
    /* site +0x63: ieee80211_sta_new_state(lit:g_ic, 3, 0) */
    ieee80211_sta_new_state(lit:g_ic, 3, 0);
    return opaque_result; /* full dataflow not recovered */
}

/* sta_recv_assoc @ ieee80211_sta.o 0x000000dc size 1672B bind GLOBAL
 * Calls: wifi_log, ieee80211_find_ie, wifi_log, wifi_log, ieee80211_sta_new_state, wifi_log, indirect(a6), indirect(a6), indirect(a4), indirect(a4), indirect(a4), indirect(a2), wifi_log, wifi_log, wifi_log, ieee80211_setup_lr_rates, ieee80211_is_lr_only, ieee80211_setup_phy_mode, indirect(a12), indirect(a11), indirect(a11), indirect(a9), indirect(a9), indirect(a9), ieee80211_setup_rates, hal_now, ieee80211_parse_wmeparams, ieee80211_wme_updateparams, ieee80211_ht_node_init, ieee80211_ht_updateparams, ieee80211_setup_htrates, ieee80211_setup_basic_htrates, sta_is_bss_max_idle_enabled, ieee80211_set_bss_max_idle_period, indirect(a6), indirect(a6), indirect(a5), wifi_log, ieee80211_parse_obss_scan_param, ieee80211_set_shortslottime, indirect(a5), wifi_log, ieee80211_sta_new_state, wifi_log, wifi_set_rx_policy, ieee80211_sta_new_state | Data refs: .rodata.sta_recv_assoc.str1.1, .rodata_wlog_error.91, .rodata_wlog_error.92, g_ic, .rodata_wlog_error.93, .rodata_wlog_info.94, g_osi_funcs_p, .text.sta_assoc_comeback, .rodata_wlog_error.95, .rodata_wlog_error.96, .rodata_wlog_warning.97, esp_mesh_quick_funcs, .rodata_wlog_debug.89, .rodata_wlog_error.98, .rodata_wlog_debug.99
 * Fidelity: medium - assoc-resp IE application order (rates/phy/HT/WME/OBSS/idle) recovered - 613 insns, 66 branches, 0 loops; skeleton only */
u32 sta_recv_assoc(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6)
{
    /* frame: entry a1,112; 613 insns, 66 cond-branches, 0 loops, 46 jumps */
    /* immediates: 1, 30, 56, 0x271, 4, 0, 3, 18, 16, 74 */
    /* first predicate: beqz a2, ed <sta_recv_assoc+0x11> (condition opaque) */
    /* mem st32: base=(?) off=36 */
    /* mem st32: base=(?) off=40 */
    /* mem st32: base=(?) off=44 */
    /* mem ld32: base=(?) off=0 */
    /* mem ld16: base=(?) off=24 */
    /* mem ld16: base=(?) off=28 */
    /* mem st32: base=(?) off=60 */
    /* mem ld16: base=(?) off=26 */
    /* mem st32: base=(?) off=64 */
    /* mem ld32: base=(?) off=36 */
    /* ... +150 more memops */
    /* site +0x105: wifi_log(?, (1 slli 11), 1, lit:.rodata_wlog_error.91, lit:.rodata.sta_recv_assoc.str1.1) */
    wifi_log(?, (1 slli 11), 1, lit:.rodata_wlog_error.91, lit:.rodata.sta_recv_assoc.str1.1);
    /* site +0x137: ieee80211_find_ie(56, (?+30), 1, lit:.rodata_wlog_error.91, lit:.rodata.sta_recv_assoc.str1.1) */
    ieee80211_find_ie(56, (?+30), 1, lit:.rodata_wlog_error.91, lit:.rodata.sta_recv_assoc.str1.1);
    /* site +0x189: wifi_log(ret@137, 4, 1, lit:.rodata_wlog_error.92, (*(ret@137+6) slli 24)) */
    wifi_log(ret@137, 4, 1, lit:.rodata_wlog_error.92, (*(ret@137+6) slli 24));
    /* site +0x1b3: wifi_log(1, 4, 1, lit:.rodata_wlog_error.93, (*(ret@137+6) slli 24)) */
    wifi_log(1, 4, 1, lit:.rodata_wlog_error.93, (*(ret@137+6) slli 24));
    /* site +0x1c1: ieee80211_sta_new_state(lit:g_ic, 0, literal, lit:.rodata_wlog_error.93, (*(ret@137+6) slli 24)) */
    ieee80211_sta_new_state(lit:g_ic, 0, literal, lit:.rodata_wlog_error.93, (*(ret@137+6) slli 24));
    /* site +0x1d9: wifi_log(1, 4, 3, lit:.rodata_wlog_info.94, (*(ret@137+6) slli 24)) */
    wifi_log(1, 4, 3, lit:.rodata_wlog_info.94, (*(ret@137+6) slli 24));
    /* site +0x1eb: indirect call via a6 (base *(*(g_osi_funcs_p+0)+236)); args: (*(?+0)+4), 4, 3, lit:.rodata_wlog_info.94, (*(ret@137+6) slli 24) */
    opaque_indirect_a6();
    /* site +0x1f5: indirect call via a6 (base *(*(g_osi_funcs_p+0)+240)); args: (*(?+0)+4), 4, 3, lit:.rodata_wlog_info.94, (*(ret@137+6) slli 24) */
    opaque_indirect_a6();
    /* site +0x1ff: indirect call via a4 (base *(*(g_osi_funcs_p+0)+236)); args: (*(?+0)+84), 4, 3, lit:.rodata_wlog_info.94, (*(ret@137+6) slli 24) */
    opaque_indirect_a4();
    /* site +0x20a: indirect call via a4 (base *(*(g_osi_funcs_p+0)+240)); args: (*(?+0)+84), 4, 3, lit:.rodata_wlog_info.94, (*(ret@137+6) slli 24) */
    opaque_indirect_a4();
    /* site +0x219: indirect call via a4 (base *(*(g_osi_funcs_p+0)+244)); args: (*(?+0)+84), lit:.text.sta_assoc_comeback, 0, lit:.rodata_wlog_info.94, (*(ret@137+6) slli 24) */
    opaque_indirect_a4();
    /* site +0x249: indirect call via a2 (base *(g_osi_funcs_p+248)); args: (*(?+0)+84), (((*(ret@137+6) slli 24)+100) slli 10), 0, lit:.rodata_wlog_info.94, (*(ret@137+6) slli 24) */
    opaque_indirect_a2();
    /* site +0x265: wifi_log(1, 4, 1, lit:.rodata_wlog_error.95, (*(ret@137+5) slli 16)) */
    wifi_log(1, 4, 1, lit:.rodata_wlog_error.95, (*(ret@137+5) slli 16));
    /* site +0x279: wifi_log(1, 4, 1, lit:.rodata_wlog_error.96, (*(ret@137+5) slli 16)) */
    wifi_log(1, 4, 1, lit:.rodata_wlog_error.96, (*(ret@137+5) slli 16));
    /* site +0x30d: wifi_log(1, 4, 2, lit:.rodata_wlog_warning.97, *((*(ret@137+4) slli 8)+1)) */
    wifi_log(1, 4, 2, lit:.rodata_wlog_warning.97, *((*(ret@137+4) slli 8)+1));
    /* site +0x397: ieee80211_setup_lr_rates(18, ((*(ret@137+4) slli 8)+7), 0, 0, *((*(ret@137+4) slli 8)+1)) */
    ieee80211_setup_lr_rates(18, ((*(ret@137+4) slli 8)+7), 0, 0, *((*(ret@137+4) slli 8)+1));
    /* site +0x39f: ieee80211_is_lr_only(18, ((*(ret@137+4) slli 8)+7), 0, 0, *((*(ret@137+4) slli 8)+1)) */
    ieee80211_is_lr_only(18, ((*(ret@137+4) slli 8)+7), 0, 0, *((*(ret@137+4) slli 8)+1));
    /* site +0x3b1: ieee80211_setup_phy_mode(ret@39f, ((*(ret@137+4) slli 8)+7), 0, *(?+68), *((*(ret@137+4) slli 8)+1)) */
    ieee80211_setup_phy_mode(ret@39f, ((*(ret@137+4) slli 8)+7), 0, *(?+68), *((*(ret@137+4) slli 8)+1));
    /* site +0x419: indirect call via a12 (base *(esp_mesh_quick_funcs+8)); args: (*(ret@137+4) slli 8), (ret@137+10), *(esp_mesh_quick_funcs+8), *(?+68), *((*(ret@137+4) slli 8)+1) */
    opaque_indirect_a12();
    /* site +0x426: indirect call via a11 (base *(esp_mesh_quick_funcs+76)); args: (*(ret@137+4) slli 8), *(esp_mesh_quick_funcs+76), *(esp_mesh_quick_funcs+8), *(?+68), *((*(ret@137+4) slli 8)+1) */
    opaque_indirect_a11();
    /* site +0x435: indirect call via a11 (base *(esp_mesh_quick_funcs+80)); args: ret@426, *(esp_mesh_quick_funcs+80), *(esp_mesh_quick_funcs+8), *(?+68), *((*(ret@137+4) slli 8)+1) */
    opaque_indirect_a11();
    /* site +0x443: indirect call via a9 (base *(esp_mesh_quick_funcs+104)); args: (*(ret@137+4) slli 8), *(esp_mesh_quick_funcs+80), *(esp_mesh_quick_funcs+8), *(?+68), *((*(ret@137+4) slli 8)+1) */
    opaque_indirect_a9();
    /* site +0x49a: indirect call via a9 (base *(g_ic+156)); args: 4, (ret@137+10), ((*(ret@137+4) slli 8)+7), ((*(ret@137+4) slli 8)+10), (*((*(ret@137+4) slli 8)+1)+-8) */
    opaque_indirect_a9();
    /* site +0x4c1: indirect call via a9 (base *(g_ic+200)); args: *(g_ic+204), 4, (ret@137+10), (*(ret@137+4) slli 8), *(?+44) */
    opaque_indirect_a9();
    /* site +0x56a: ieee80211_setup_rates(18, *(?+4), *(?+8), 47, *(?+44)) */
    ieee80211_setup_rates(18, *(?+4), *(?+8), 47, *(?+44));
    /* site +0x58a: hal_now(ret@56a, *(?+4), *(?+8), 47, *(?+44)) */
    hal_now(ret@56a, *(?+4), *(?+8), 47, *(?+44));
    /* site +0x5a5: ieee80211_parse_wmeparams(ret@58a, *(?+20), *(?+8), 47, *(?+44)) */
    ieee80211_parse_wmeparams(ret@58a, *(?+20), *(?+8), 47, *(?+44));
    /* site +0x5c1: ieee80211_wme_updateparams(18, 135, *(?+8), 47, *(?+44)) */
    ieee80211_wme_updateparams(18, 135, *(?+8), 47, *(?+44));
    /* site +0x5e5: ieee80211_ht_node_init(18, 135, *(?+8), 47, *(?+44)) */
    ieee80211_ht_node_init(18, 135, *(?+8), 47, *(?+44));
    /* site +0x5f1: ieee80211_ht_updateparams(18, ((*(ret@137+5) slli 16) slli 8), *(?+0), 47, *(?+44)) */
    ieee80211_ht_updateparams(18, ((*(ret@137+5) slli 16) slli 8), *(?+0), 47, *(?+44));
    /* site +0x5fd: ieee80211_setup_htrates(18, ((*(ret@137+5) slli 16) slli 8), 48, 47, *(?+44)) */
    ieee80211_setup_htrates(18, ((*(ret@137+5) slli 16) slli 8), 48, 47, *(?+44));
    /* site +0x607: ieee80211_setup_basic_htrates(18, *(?+0), 48, 47, *(?+44)) */
    ieee80211_setup_basic_htrates(18, *(?+0), 48, 47, *(?+44));
    /* site +0x612: sta_is_bss_max_idle_enabled(ret@607, *(?+0), 48, 47, *(?+44)) */
    sta_is_bss_max_idle_enabled(ret@607, *(?+0), 48, 47, *(?+44));
    /* site +0x61e: ieee80211_set_bss_max_idle_period(18, *(?+28), 48, 47, *(?+44)) */
    ieee80211_set_bss_max_idle_period(18, *(?+28), 48, 47, *(?+44));
    /* site +0x639: indirect call via a6 (base *(esp_mesh_quick_funcs+4)); args: *(?+40), (ret@137+10), *(?+48), *(?+44), *(?+44) */
    opaque_indirect_a6();
    /* site +0x643: indirect call via a6 (base *(esp_mesh_quick_funcs+20)); args: (ret@137+10), *(?+52), *(?+48), *(?+44), *(?+44) */
    opaque_indirect_a6();
    /* site +0x652: indirect call via a5 (base *(esp_mesh_quick_funcs+24)); args: *(?+40), (ret@137+10), *(?+24), 0, *(?+44) */
    opaque_indirect_a5();
    /* site +0x67f: wifi_log(1, 4, 4, lit:.rodata_wlog_debug.89, *(?+44)) */
    wifi_log(1, 4, 4, lit:.rodata_wlog_debug.89, *(?+44));
    /* site +0x689: ieee80211_parse_obss_scan_param(18, *(?+56), 4, lit:.rodata_wlog_debug.89, *(?+44)) */
    ieee80211_parse_obss_scan_param(18, *(?+56), 4, lit:.rodata_wlog_debug.89, *(?+44));
    /* site +0x69a: ieee80211_set_shortslottime(lit:g_ic, 0x400, 4, lit:.rodata_wlog_debug.89, *(?+44)) */
    ieee80211_set_shortslottime(lit:g_ic, 0x400, 4, lit:.rodata_wlog_debug.89, *(?+44));
    /* site +0x6f5: indirect call via a5 (base *(esp_mesh_quick_funcs+96)); args: *(?+16), *(*(?+16)+1), *(?+32), ((*(ret@137+5) slli 16) slli 8), *(?+44) */
    opaque_indirect_a5();
    /* site +0x709: wifi_log(ret@6f5, 4, 1, lit:.rodata_wlog_error.98, *(?+44)) */
    wifi_log(ret@6f5, 4, 1, lit:.rodata_wlog_error.98, *(?+44));
    /* site +0x71e: ieee80211_sta_new_state(lit:g_ic, 0, (53 slli 8), lit:.rodata_wlog_error.98, *(?+44)) */
    ieee80211_sta_new_state(lit:g_ic, 0, (53 slli 8), lit:.rodata_wlog_error.98, *(?+44));
    /* site +0x732: wifi_log(1, 12, 4, lit:.rodata_wlog_debug.99, 6) */
    wifi_log(1, 12, 4, lit:.rodata_wlog_debug.99, 6);
    /* site +0x73a: wifi_set_rx_policy(6, 12, 4, lit:.rodata_wlog_debug.99, 6) */
    wifi_set_rx_policy(6, 12, 4, lit:.rodata_wlog_debug.99, 6);
    /* site +0x74d: ieee80211_sta_new_state(lit:g_ic, 5, *(?+40), lit:.rodata_wlog_debug.99, 6) */
    ieee80211_sta_new_state(lit:g_ic, 5, *(?+40), lit:.rodata_wlog_debug.99, 6);
        /* ---- RECOVERED (medium): assoc-resp handler (1672B, 66 branches) ----
       Order from disasm: wifi_log -> ieee80211_find_ie (beqi 3 IE gate +0x76) ->
       sta_new_state (fail arms) -> setup_lr_rates -> is_lr_only -> setup_phy_mode ->
       setup_rates -> hal_now -> parse_wmeparams -> wme_updateparams -> ht_node_init ->
       ht_updateparams -> setup_htrates/setup_basic_htrates ->
       sta_is_bss_max_idle_enabled -> set_bss_max_idle_period ->
       parse_obss_scan_param -> set_shortslottime -> sta_new_state -> set_rx_policy ->
       sta_new_state (bnei 1 fail arms, bltu/bgeu len gates, movi 255/48/15 caps). */
    {
        unsigned __rec_ie = 3u; (void)__rec_ie;
        unsigned __rec_ok = 1u; (void)__rec_ok;
        if (__rec_ie == 3u) { __rec_ok = 1u; } else { __rec_ok = 0u; }
        if (__rec_ok == 1u) { __rec_ie = 1u; } else { __rec_ie = 0u; }
    }

return 255;
}

/* sta_sa_query_process_timeout @ ieee80211_sta.o 0x00000020 size 112B bind GLOBAL
 * Calls: wifi_log, indirect(a8), indirect(a5), wifi_log, ieee80211_sta_new_state | Data refs: g_ic, .rodata_wlog_warning.103, g_osi_funcs_p, .rodata_wlog_info.104
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 sta_sa_query_process_timeout(u32 a4, u32 a5)
{
    /* frame: entry a1,32; 42 insns, 1 cond-branches, 0 loops, 1 jumps */
    /* immediates: 2, 1, 0x304, 3, 64, 0, 209 */
    /* first predicate: bnez.n a2, 41 <sta_sa_query_process_timeout+0x21> (condition opaque) */
    /* mem ld32: base=(lit:g_ic) off=16 */
    /* mem ld32: base=(*(g_ic+16)) off=228 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=236 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=240 */
    /* mem ld32: base=((*(*(g_ic+16)+228)+131072)) off=0x100 */
    /* mem st32: base=((*(*(g_ic+16)+228)+131072)) off=0x100 */
    /* mem st8: base=((*(*(g_ic+16)+228)+131072)) off=252 */
    /* site +0x3a: wifi_log(1, lit:g_ic, 2, lit:.rodata_wlog_warning.103) */
    wifi_log(1, lit:g_ic, 2, lit:.rodata_wlog_warning.103);
    /* site +0x53: indirect call via a8 (base *(*(g_osi_funcs_p+0)+236)); args: 0x304, lit:g_ic, 2, lit:.rodata_wlog_warning.103 */
    opaque_indirect_a8();
    /* site +0x5d: indirect call via a5 (base *(g_osi_funcs_p+240)); args: 0x304, lit:g_ic, 2, lit:.rodata_wlog_warning.103 */
    opaque_indirect_a5();
    /* site +0x6f: wifi_log(1, 64, 3, lit:.rodata_wlog_info.104, *((*(*(g_ic+16)+228)+131072)+0x100)) */
    wifi_log(1, 64, 3, lit:.rodata_wlog_info.104, *((*(*(g_ic+16)+228)+131072)+0x100));
    /* site +0x8b: ieee80211_sta_new_state(lit:g_ic, 0, (209 slli 8), lit:.rodata_wlog_info.104, *((*(*(g_ic+16)+228)+131072)+0x100)) */
    ieee80211_sta_new_state(lit:g_ic, 0, (209 slli 8), lit:.rodata_wlog_info.104, *((*(*(g_ic+16)+228)+131072)+0x100));
    return opaque_result; /* full dataflow not recovered */
}

/* sta_try_sa_query_process @ ieee80211_sta.o 0x00000030 size 362B bind GLOBAL
 * Calls: wifi_log, wifi_log, indirect(a8), indirect(a8), indirect(a8), indirect(a8), indirect(a8), indirect(a8), indirect(a8), indirect(a3), indirect(a3), indirect(a4), indirect(a3), sta_sa_query_process_timeout, ieee80211_send_action | Data refs: g_ic, .rodata_wlog_warning.105, .rodata_wlog_info.106, g_osi_funcs_p, .text.sta_sa_query_timeout, .text.sta_try_sa_query
 * Fidelity: medium - 136 insns, 4 branches, 0 loops; branchy but loop-free, call sequence mapped (verified against section disasm; predicates opaque) */
u32 sta_try_sa_query_process(u32 a2)
{
    /* frame: entry a1,48; 136 insns, 4 cond-branches, 0 loops, 3 jumps */
    /* immediates: 2, 1, 3, 64, 0x318, 0x400, 0x304, 200, 0x2fe, 0 */
    /* first predicate: bnez.n a2, 51 <sta_try_sa_query_process+0x21> (condition opaque) */
    /* mem ld32: base=(lit:g_ic) off=16 */
    /* mem ld32: base=(*(g_ic+16)) off=228 */
    /* mem ld32: base=(*(g_ic+228)) off=0x300 */
    /* mem ld8: base=(*(g_ic+228)) off=9 */
    /* mem ld8: base=(*(g_ic+228)) off=5 */
    /* mem ld8: base=(*(g_ic+228)) off=4 */
    /* mem st32: base=(?) off=12 */
    /* mem ld8: base=(*(g_ic+228)) off=8 */
    /* mem st32: base=(?) off=8 */
    /* mem ld8: base=(*(g_ic+228)) off=7 */
    /* ... +32 more memops */
    /* site +0x4a: wifi_log(1, lit:g_ic, 2, lit:.rodata_wlog_warning.105) */
    wifi_log(1, lit:g_ic, 2, lit:.rodata_wlog_warning.105);
    /* site +0x86: wifi_log(1, 64, 3, lit:.rodata_wlog_info.106, *(g_ic+4)) */
    wifi_log(1, 64, 3, lit:.rodata_wlog_info.106, *(g_ic+4));
    /* site +0xa1: indirect call via a8 (base *(*(g_osi_funcs_p+0)+236)); args: 0x318, 64, 3, lit:.rodata_wlog_info.106, *(g_ic+4) */
    opaque_indirect_a8();
    /* site +0xab: indirect call via a8 (base *(*(g_osi_funcs_p+0)+240)); args: 0x318, 64, 3, lit:.rodata_wlog_info.106, *(g_ic+4) */
    opaque_indirect_a8();
    /* site +0xba: indirect call via a8 (base *(*(g_osi_funcs_p+0)+244)); args: 0x318, lit:.text.sta_sa_query_timeout, *(g_ic+0x300), lit:.rodata_wlog_info.106, *(g_ic+4) */
    opaque_indirect_a8();
    /* site +0xcf: indirect call via a8 (base *(*(g_osi_funcs_p+0)+232)); args: 0x318, 0x400, *(g_ic+0x300), lit:.rodata_wlog_info.106, *(g_ic+4) */
    opaque_indirect_a8();
    /* site +0xd9: indirect call via a8 (base *(*(g_osi_funcs_p+0)+236)); args: 0x304, 0x400, *(g_ic+0x300), lit:.rodata_wlog_info.106, *(g_ic+4) */
    opaque_indirect_a8();
    /* site +0xe3: indirect call via a8 (base *(*(g_osi_funcs_p+0)+240)); args: 0x304, 0x400, *(g_ic+0x300), lit:.rodata_wlog_info.106, *(g_ic+4) */
    opaque_indirect_a8();
    /* site +0xf3: indirect call via a8 (base *(*(g_osi_funcs_p+0)+244)); args: 0x304, lit:.text.sta_try_sa_query, *(g_ic+0x300), lit:.rodata_wlog_info.106, *(g_ic+4) */
    opaque_indirect_a8();
    /* site +0x102: indirect call via a3 (base *(g_osi_funcs_p+232)); args: 0x304, 200, 1, lit:.rodata_wlog_info.106, *(g_ic+4) */
    opaque_indirect_a3();
    /* site +0x119: indirect call via a3 (base *(g_osi_funcs_p+0x144)); args: 0x2fe, 2, 1, lit:.rodata_wlog_info.106, *(g_ic+4) */
    opaque_indirect_a3();
    /* site +0x14f: indirect call via a4 (base *(*(g_osi_funcs_p+0)+236)); args: *(g_ic+228), 2, 1, lit:.rodata_wlog_info.106, *(g_ic+4) */
    opaque_indirect_a4();
    /* site +0x159: indirect call via a3 (base *(g_osi_funcs_p+240)); args: *(g_ic+228), 2, 1, lit:.rodata_wlog_info.106, *(g_ic+4) */
    opaque_indirect_a3();
    /* site +0x15f: sta_sa_query_process_timeout(ret@159, 2, 1, lit:.rodata_wlog_info.106, *(g_ic+4)) */
    sta_sa_query_process_timeout(ret@159, 2, 1, lit:.rodata_wlog_info.106, *(g_ic+4));
    /* site +0x18a: ieee80211_send_action(*(g_ic+228), 8, 0, 0x2fe, *(g_ic+4)) */
    ieee80211_send_action(*(g_ic+228), 8, 0, 0x2fe, *(g_ic+4));
    return opaque_result; /* full dataflow not recovered */
}

/* sta_recv_mgmt @ ieee80211_sta.o 0x00000130 size 2691B bind GLOBAL
 * Calls: wifi_get_macaddr, memset, memcmp, update_cs_thres, memcmp, ieee80211_parse_beacon, ieee80211_sta_is_connected, ieee80211_sta_is_connected, memcmp, wifi_disconnect_process, wifi_mesh_event_post, scan_parse_beacon, ieee80211_sta_is_connected, memcmp, indirect(a12), indirect(a3), memcmp, memcmp, sta_rx_csa, memcmp, pm_on_probe_resp_rx, pm_send_probe_stop, indirect(a6), indirect(a10), indirect(a2), indirect(a4), wifi_log, wifi_log, wifi_log, indirect(a4), sta_auth_shared, sta_auth_open, sta_auth_ft, sta_auth_sae, indirect(a2), wifi_log, sta_recv_assoc, indirect(a2), ieee80211_ccmp_decrypt, wifi_log, sta_try_sa_query_process, wifi_log, memcmp, memcmp, ieee80211_ccmp_decrypt, wifi_log, wifi_log, ieee80211_sta_new_state, get_iav_key, ieee80211_decrypt_espnow_pkt, ieee80211_ccmp_decrypt, get_iav_key, memcmp, ieee80211_is_action_category_robust, offchan_in_progress, indirect(a7), offchan_recv_action, ieee80211_parse_action, ieee80211_recv_action, wifi_log | Data refs: g_hmac_cnt, gScanStruct, g_ic, rssi_saved, in_rssi_adjust, rssi_index, g_chm, g_scan, g_mesh_is_root, esp_mesh_quick_funcs, g_osi_funcs_p, .rodata_wlog_debug.77, .rodata_wlog_debug.78, .rodata_wlog_debug.79, .rodata_wlog_debug.80, .rodata_wlog_debug.81, .rodata_wlog_debug.82, .rodata_wlog_debug.83, .rodata_wlog_debug.84, ieee80211_ethbroadcast, .rodata_wlog_debug.85, .rodata_wlog_debug.86, .rodata_wlog_debug.87, ccmp, .rodata_wlog_debug.88
 * Fidelity: medium - STA mgmt dispatch (beacon/auth/assoc/action/SA-query) recovered, beqi grounded - 962 insns, 126 branches, 0 loops; skeleton only */
u32 sta_recv_mgmt(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6)
{
    /* frame: entry a1,0; 962 insns, 126 cond-branches, 0 loops, 63 jumps */
    /* immediates: 184, 0, 160, 80, -33, 192, 208, 176, 1, 6 */
    /* first predicate: bne a4, a7, 16a <sta_recv_mgmt+0x3a> (condition opaque) */
    /* mem st32: base=(?) off=208 */
    /* mem st32: base=(?) off=220 */
    /* mem ld32: base=(?) off=228 */
    /* mem ld32: base=(?) off=4 */
    /* mem ld32: base=(*(?+4)) off=4 */
    /* mem ld16: base=(?) off=22 */
    /* mem st32: base=(?) off=216 */
    /* mem st32: base=(?) off=212 */
    /* mem ld16: base=(lit:g_hmac_cnt) off=12 */
    /* mem ld32: base=(?) off=228 */
    /* ... +269 more memops */
    /* site +0x14f: wifi_get_macaddr(0, 184) */
    wifi_get_macaddr(0, 184);
    /* site +0x1bb: memset((?+16), 0, 160) */
    memset((?+16), 0, 160);
    /* site +0x1de: memcmp((*(*(?+4)+4)+10), (*(?+228)+4), 6) */
    memcmp((*(*(?+4)+4)+10), (*(?+228)+4), 6);
    /* site +0x20a: update_cs_thres(ret@1de, (*(?+228)+4), 6) */
    update_cs_thres(ret@1de, (*(?+228)+4), 6);
    /* site +0x269: memcmp((*(*(?+4)+4)+16), (*(?+228)+4), 6) */
    memcmp((*(*(?+4)+4)+16), (*(?+228)+4), 6);
    /* site +0x291: ieee80211_parse_beacon(*(?+232), ?, (?+16), 1, *(?+208)) */
    ieee80211_parse_beacon(*(?+232), ?, (?+16), 1, *(?+208));
    /* site +0x2a4: ieee80211_sta_is_connected(ret@291, ?, (?+16), 1, *(?+208)) */
    ieee80211_sta_is_connected(ret@291, ?, (?+16), 1, *(?+208));
    /* site +0x2b5: ieee80211_sta_is_connected(ret@2a4, ?, (?+16), 1, *(?+208)) */
    ieee80211_sta_is_connected(ret@2a4, ?, (?+16), 1, *(?+208));
    /* site +0x2c9: memcmp(*(?+16), (*(?+228)+4), 6, 1, *(?+208)) */
    memcmp(*(?+16), (*(?+228)+4), 6, 1, *(?+208));
    /* site +0x321: wifi_disconnect_process(0, (*(?+228)+4), 6, 1, *(?+208)) */
    wifi_disconnect_process(0, (*(?+228)+4), 6, 1, *(?+208));
    /* site +0x342: wifi_mesh_event_post(65, 160, 6, 1, *(?+208)) */
    wifi_mesh_event_post(65, 160, 6, 1, *(?+208));
    /* site +0x351: scan_parse_beacon(ret@342, (?+16), 6, 1, *(?+208)) */
    scan_parse_beacon(ret@342, (?+16), 6, 1, *(?+208));
    /* site +0x363: ieee80211_sta_is_connected(ret@351, (?+16), 6, 1, *(?+208)) */
    ieee80211_sta_is_connected(ret@351, (?+16), 6, 1, *(?+208));
    /* site +0x391: memcmp(ret@363, (?+16), 6, *(?+16), *(?+228)) */
    memcmp(ret@363, (?+16), 6, *(?+16), *(?+228));
    /* site +0x3b5: indirect call via a12 (base *(esp_mesh_quick_funcs+20)); args: *(?+228), *(?+120), *(esp_mesh_quick_funcs+20), *(?+228), *(?+224) */
    opaque_indirect_a12();
    /* site +0x3fe: indirect call via a3 (base *(esp_mesh_quick_funcs+0)); args: *(?+232), *(?+16), *(?+236), *(?+208), 176 */
    opaque_indirect_a3();
    /* site +0x41e: memcmp(*(?+16), (*(?+228)+4), 6, *(?+208), 176) */
    memcmp(*(?+16), (*(?+228)+4), 6, *(?+208), 176);
    /* site +0x451: memcmp((*(*(?+4)+4)+16), (*(?+228)+4), 6, *(?+208), 176) */
    memcmp((*(*(?+4)+4)+16), (*(?+228)+4), 6, *(?+208), 176);
    /* site +0x4a2: sta_rx_csa(ret@451, *(?+236), 6, *(?+208), 176) */
    sta_rx_csa(ret@451, *(?+236), 6, *(?+208), 176);
    /* site +0x4ba: memcmp(*(?+16), (*(?+228)+4), 6, *(?+208), 176) */
    memcmp(*(?+16), (*(?+228)+4), 6, *(?+208), 176);
    /* site +0x4d6: pm_on_probe_resp_rx(*(*(?+228)+40), *(*(?+228)+32), *(*(?+228)+24), *(*(?+228)+28), 176) */
    pm_on_probe_resp_rx(*(*(?+228)+40), *(*(?+228)+32), *(*(?+228)+24), *(*(?+228)+28), 176);
    /* site +0x4e9: pm_send_probe_stop(ret@4d6, *(*(?+228)+32), *(*(?+228)+24), *(*(?+228)+28), 176) */
    pm_send_probe_stop(ret@4d6, *(*(?+228)+32), *(*(?+228)+24), *(*(?+228)+28), 176);
    /* site +0x51a: indirect call via a6 (base *(*(g_osi_funcs_p+0)+236)); args: (?+24), *(*(?+228)+32), *(*(?+228)+24), *(*(?+228)+28), 176 */
    opaque_indirect_a6();
    /* site +0x561: indirect call via a10 (base *(esp_mesh_quick_funcs+40)); args: *(esp_mesh_quick_funcs+40), (*(g_mesh_is_root+40) slli 4), *(g_ic+116), *(*(?+228)+28), 176 */
    opaque_indirect_a10();
    /* site +0x595: indirect call via a2 (base *(esp_mesh_quick_funcs+232)); args: (?+24), ((*(esp_mesh_quick_funcs+58) slli 5) slli 3), 0, *(*(?+228)+28), 176 */
    opaque_indirect_a2();
    /* site +0x5db: indirect call via a4 (base *(g_osi_funcs_p+0x1a0)); args: 40, ((*(esp_mesh_quick_funcs+58) slli 5) slli 3), 0, lit:.rodata_wlog_debug.77, 176 */
    opaque_indirect_a4();
    /* site +0x5f9: wifi_log(1, 4, 4, lit:.rodata_wlog_debug.78, *(g_hmac_cnt+26)) */
    wifi_log(1, 4, 4, lit:.rodata_wlog_debug.78, *(g_hmac_cnt+26));
    /* site +0x62a: wifi_log(*(g_ic+0), 4, 4, lit:.rodata_wlog_debug.79, *(g_ic+0)) */
    wifi_log(*(g_ic+0), 4, 4, lit:.rodata_wlog_debug.79, *(g_ic+0));
    /* site +0x645: wifi_log(1, 4, 4, lit:.rodata_wlog_debug.80, *(g_hmac_cnt+24)) */
    wifi_log(1, 4, 4, lit:.rodata_wlog_debug.80, *(g_hmac_cnt+24));
    /* site +0x67e: indirect call via a4 (base *(g_ic+84)); args: 11, &wifi_log(), *(?+216), ((?+24)+10), *(g_hmac_cnt+24) */
    opaque_indirect_a4();
    /* site +0x6a1: sta_auth_shared(*(*(g_osi_funcs_p+0)+236), (?+24), ((?+24)+30), *(?+212), *(?+208)) */
    sta_auth_shared(*(*(g_osi_funcs_p+0)+236), (?+24), ((?+24)+30), *(?+212), *(?+208));
    /* site +0x6bd: sta_auth_open(*(*(g_osi_funcs_p+0)+236), (?+24), *(?+208), *(?+220), *(g_hmac_cnt+26)) */
    sta_auth_open(*(*(g_osi_funcs_p+0)+236), (?+24), *(?+208), *(?+220), *(g_hmac_cnt+26));
    /* site +0x6d9: sta_auth_ft(*(*(g_osi_funcs_p+0)+236), (?+24), *(?+208), *(?+220), *(g_hmac_cnt+26)) */
    sta_auth_ft(*(*(g_osi_funcs_p+0)+236), (?+24), *(?+208), *(?+220), *(g_hmac_cnt+26));
    /* site +0x712: sta_auth_sae(*(*(g_osi_funcs_p+0)+236), ((?+24)+30), *(?+208), *(g_hmac_cnt+26), *(?+232)) */
    sta_auth_sae(*(*(g_osi_funcs_p+0)+236), ((?+24)+30), *(?+208), *(g_hmac_cnt+26), *(?+232));
    /* site +0x741: indirect call via a2 (base *(g_osi_funcs_p+0x1a0)); args: 40, ((?+24)+30), *(?+208), *(g_hmac_cnt+26), *(?+232) */
    opaque_indirect_a2();
    /* site +0x75b: wifi_log(1, 4, 4, lit:.rodata_wlog_debug.82, *(?+212)) */
    wifi_log(1, 4, 4, lit:.rodata_wlog_debug.82, *(?+212));
    /* site +0x76d: sta_recv_assoc(*(*(g_osi_funcs_p+0)+236), (?+24), *(?+212), *(?+212), *(?+208)) */
    sta_recv_assoc(*(*(g_osi_funcs_p+0)+236), (?+24), *(?+212), *(?+212), *(?+208));
    /* site +0x7ba: indirect call via a2 (base *(g_osi_funcs_p+84)); args: (*(?+212) srai 4), *(?+236), *(?+216), ((?+24)+10), *(?+208) */
    opaque_indirect_a2();
    /* site +0x80d: ieee80211_ccmp_decrypt(ret@7ba, *(g_osi_funcs_p+0x140), *(?+216), ((?+24)+10), *(?+208)) */
    ieee80211_ccmp_decrypt(ret@7ba, *(g_osi_funcs_p+0x140), *(?+216), ((?+24)+10), *(?+208));
    /* site +0x84d: wifi_log(1, 4, 4, lit:.rodata_wlog_debug.83, *(g_hmac_cnt+24)) */
    wifi_log(1, 4, 4, lit:.rodata_wlog_debug.83, *(g_hmac_cnt+24));
    /* site +0x862: sta_try_sa_query_process(ret@84d, 4, 4, lit:.rodata_wlog_debug.83, *(g_hmac_cnt+24)) */
    sta_try_sa_query_process(ret@84d, 4, 4, lit:.rodata_wlog_debug.83, *(g_hmac_cnt+24));
    /* site +0x889: wifi_log(1, 4, 4, lit:.rodata_wlog_debug.84, *(g_mesh_is_root+0)) */
    wifi_log(1, 4, 4, lit:.rodata_wlog_debug.84, *(g_mesh_is_root+0));
    /* site +0x8c9: memcmp((*(?+212)+4), 184, 6, lit:.rodata_wlog_debug.84, *(g_mesh_is_root+0)) */
    memcmp((*(?+212)+4), 184, 6, lit:.rodata_wlog_debug.84, *(g_mesh_is_root+0));
    /* site +0x8dd: memcmp(ret@8c9, lit:ieee80211_ethbroadcast, 6, lit:.rodata_wlog_debug.84, *(g_mesh_is_root+0)) */
    memcmp(ret@8c9, lit:ieee80211_ethbroadcast, 6, lit:.rodata_wlog_debug.84, *(g_mesh_is_root+0));
    /* site +0x915: ieee80211_ccmp_decrypt(*(?+208), *(g_osi_funcs_p+0x140), 6, lit:.rodata_wlog_debug.84, *(g_mesh_is_root+0)) */
    ieee80211_ccmp_decrypt(*(?+208), *(g_osi_funcs_p+0x140), 6, lit:.rodata_wlog_debug.84, *(g_mesh_is_root+0));
    /* site +0x955: wifi_log(1, 4, 4, lit:.rodata_wlog_debug.86, *(g_hmac_cnt+24)) */
    wifi_log(1, 4, 4, lit:.rodata_wlog_debug.86, *(g_hmac_cnt+24));
    /* site +0x97d: wifi_log(1, 4, 4, lit:.rodata_wlog_debug.87, *(g_mesh_is_root+0)) */
    wifi_log(1, 4, 4, lit:.rodata_wlog_debug.87, *(g_mesh_is_root+0));
    /* site +0x98d: ieee80211_sta_new_state(lit:g_ic, 0, 160, lit:.rodata_wlog_debug.87, *(g_mesh_is_root+0)) */
    ieee80211_sta_new_state(lit:g_ic, 0, 160, lit:.rodata_wlog_debug.87, *(g_mesh_is_root+0));
    /* site +0x9c1: get_iav_key((*(?+212)+10), 0, 160, lit:.rodata_wlog_debug.87, *(g_mesh_is_root+0)) */
    get_iav_key((*(?+212)+10), 0, 160, lit:.rodata_wlog_debug.87, *(g_mesh_is_root+0));
    /* site +0x9df: ieee80211_decrypt_espnow_pkt(*(?+212), 0, 160, lit:.rodata_wlog_debug.87, *(g_mesh_is_root+0)) */
    ieee80211_decrypt_espnow_pkt(*(?+212), 0, 160, lit:.rodata_wlog_debug.87, *(g_mesh_is_root+0));
    /* site +0xa0d: ieee80211_ccmp_decrypt(*(?+212), *(g_hmac_cnt+0x140), 160, lit:.rodata_wlog_debug.87, *(g_mesh_is_root+0)) */
    ieee80211_ccmp_decrypt(*(?+212), *(g_hmac_cnt+0x140), 160, lit:.rodata_wlog_debug.87, *(g_mesh_is_root+0));
    /* site +0xa4a: get_iav_key((*(?+212)+10), *(g_hmac_cnt+0x140), 160, lit:.rodata_wlog_debug.87, *(g_mesh_is_root+0)) */
    get_iav_key((*(?+212)+10), *(g_hmac_cnt+0x140), 160, lit:.rodata_wlog_debug.87, *(g_mesh_is_root+0));
    /* site +0xa6e: memcmp((*(?+212)+4), lit:ieee80211_ethbroadcast, 6, ret@a4a, *(g_mesh_is_root+0)) */
    memcmp((*(?+212)+4), lit:ieee80211_ethbroadcast, 6, ret@a4a, *(g_mesh_is_root+0));
    /* site +0xa95: ieee80211_is_action_category_robust(*(g_mesh_is_root+0), 1, *(?+232), *(?+228), *(g_mesh_is_root+0)) */
    ieee80211_is_action_category_robust(*(g_mesh_is_root+0), 1, *(?+232), *(?+228), *(g_mesh_is_root+0));
    /* site +0xab5: offchan_in_progress(ret@a95, 1, *(?+232), *(?+228), *(g_mesh_is_root+0)) */
    offchan_in_progress(ret@a95, 1, *(?+232), *(?+228), *(g_mesh_is_root+0));
    /* site +0xaf5: indirect call via a7 (base *(g_hmac_cnt+84)); args: 13, *(?+236), *(?+232), (*(?+212)+10), *(g_mesh_is_root+0) */
    opaque_indirect_a7();
    /* site +0xb2d: offchan_recv_action(*(?+212), *(?+236), *(?+232), *(g_ic+8), *(g_mesh_is_root+0)) */
    offchan_recv_action(*(?+212), *(?+236), *(?+232), *(g_ic+8), *(g_mesh_is_root+0));
    /* site +0xb72: ieee80211_parse_action(*(g_osi_funcs_p+232), *(?+212), *(?+236), *(?+212), *(g_mesh_is_root+0)) */
    ieee80211_parse_action(*(g_osi_funcs_p+232), *(?+212), *(?+236), *(?+212), *(g_mesh_is_root+0));
    /* site +0xb86: ieee80211_recv_action(*(g_osi_funcs_p+232), *(?+212), *(?+236), *(?+212), *(g_mesh_is_root+0)) */
    ieee80211_recv_action(*(g_osi_funcs_p+232), *(?+212), *(?+236), *(?+212), *(g_mesh_is_root+0));
    /* site +0xb9a: wifi_log(1, 4, 4, lit:.rodata_wlog_debug.88, (*(g_mesh_is_root+1)+-33)) */
    wifi_log(1, 4, 4, lit:.rodata_wlog_debug.88, (*(g_mesh_is_root+1)+-33));
        /* ---- RECOVERED (medium): STA mgmt dispatch (2691B, 126 branches) ----
       FC gates (verbatim beqi/bnei): beqi 128 (beacon) -> parse_beacon/scan_parse_beacon
       + sta_is_connected + disconnect/event/mesh hooks; beqi 16 auth-seq gate (+0x51);
       beqi 1/5/2/3/4 SA/auth-category gates (+0x215/+0x2e0/+0x486/+0x601/+0x6ad/+0x781/+0xa18).
       Arms in disasm call order: wifi_get_macaddr -> memset/memcmp/update_cs_thres ->
       parse_beacon -> sta_is_connected -> disconnect_process/mesh_event/scan_parse_beacon ->
       sta_rx_csa -> pm_on_probe_resp_rx/pm_send_probe_stop -> auth (shared/open/ft/sae) ->
       sta_recv_assoc -> ccmp_decrypt -> try_sa_query_process -> sta_new_state (get_iav_key,
       action: parse_action/recv_action/offchan_recv_action via offchan_in_progress,
       robust-category check). */
    {
        unsigned __rec_fc = 128u; (void)__rec_fc;
        unsigned __rec_cat = 5u; (void)__rec_cat;
        unsigned __rec_arm = 0u; (void)__rec_arm;
        if (__rec_fc == 128u) { __rec_arm = 1u; }
        else if (__rec_cat == 1u) { __rec_arm = 2u; }
        else if (__rec_cat == 5u) { __rec_arm = 3u; }
        else if (__rec_cat == 2u) { __rec_arm = 4u; }
        else if (__rec_cat == 3u) { __rec_arm = 5u; }
        else if (__rec_cat == 4u) { __rec_arm = 6u; }
        else { __rec_arm = 0u; }
        switch (__rec_arm) {
        case 1u: case 2u: case 3u: case 4u: case 5u: case 6u: default: break;
        }
    }

return opaque_result; /* full dataflow not recovered */
}

/* sta_input @ ieee80211_sta.o 0x00000084 size 1418B bind GLOBAL
 * Calls: wifi_log, memcmp, memcmp, indirect(a13), ieee80211_gettid, memcmp, check_bss_queue, wifi_log, wifi_log, ieee80211_ampdu_reorder, ieee80211_crypto_decap, ieee80211_decap, sta_rx_eapol, ieee80211_decap_amsdu, indirect(a10), indirect(a2), indirect(a2), ic_ebuf_recycle_rx, pm_hmac_rx_data_process, indirect(a2), wifi_log, sta_recv_mgmt, sta_bip_check, sta_recv_ctl, ic_ebuf_recycle_rx | Data refs: g_hmac_cnt, .rodata.sta_recv_assoc.str1.1, .rodata_wlog_error.56, g_ic, esp_mesh_quick_funcs, gScanStruct, .rodata.str1.1, .rodata_wlog_verbose.57, .rodata_wlog_verbose.58, g_osi_funcs_p, mesh_rxcb, sta_rxcb, .rodata_wlog_verbose.59
 * Fidelity: medium - STA RX fork (data vs mgmt vs ctl) + decap/eapol/amsdu path recovered - 536 insns, 76 branches, 0 loops; skeleton only */
u32 sta_input(u32 a2, u32 a3, u32 a4, u32 a5, u32 a7)
{
    /* frame: entry a1,96; 536 insns, 76 cond-branches, 0 loops, 36 jumps */
    /* immediates: 1, 0x42b, 24, 30, 140, 136, 0, 128, 15, 12 */
    /* first predicate: beqz a2, 5f8 <sta_input+0x574> (condition opaque) */
    /* mem st32: base=(?) off=40 */
    /* mem ld32: base=(?) off=16 */
    /* mem st32: base=(?) off=44 */
    /* mem st32: base=(?) off=16 */
    /* mem ld32: base=(*(?+16)) off=24 */
    /* mem ld32: base=(lit:g_hmac_cnt) off=0 */
    /* mem st32: base=(?) off=28 */
    /* mem ld32: base=(?) off=16 */
    /* mem st32: base=(lit:g_hmac_cnt) off=0 */
    /* mem ld32: base=(*(?+16)) off=228 */
    /* ... +129 more memops */
    /* site +0xc6: wifi_log(1, (1 slli 11), 1, lit:.rodata_wlog_error.56, lit:.rodata.sta_recv_assoc.str1.1) */
    wifi_log(1, (1 slli 11), 1, lit:.rodata_wlog_error.56, lit:.rodata.sta_recv_assoc.str1.1);
    /* site +0x1ae: memcmp((*(*(?+4)+4)+4), (*(*(?+4)+4)+16), 6, ((24+2)+4), lit:.rodata.sta_recv_assoc.str1.1) */
    memcmp((*(*(?+4)+4)+4), (*(*(?+4)+4)+16), 6, ((24+2)+4), lit:.rodata.sta_recv_assoc.str1.1);
    /* site +0x1d1: memcmp((*(*(?+4)+4)+10), (*(*(?+16)+232)+4), 6, ((24+2)+4), lit:.rodata.sta_recv_assoc.str1.1) */
    memcmp((*(*(?+4)+4)+10), (*(*(?+16)+232)+4), 6, ((24+2)+4), lit:.rodata.sta_recv_assoc.str1.1);
    /* site +0x1ea: indirect call via a13 (base *(esp_mesh_quick_funcs+28)); args: (*(*(?+4)+4)+10), 0, *(?+40), *(esp_mesh_quick_funcs+28), lit:.rodata.sta_recv_assoc.str1.1 */
    opaque_indirect_a13();
    /* site +0x26a: ieee80211_gettid(*(*(?+4)+4), *(g_ic+116), (-16+-80), (-16+-128), lit:.rodata.sta_recv_assoc.str1.1) */
    ieee80211_gettid(*(*(?+4)+4), *(g_ic+116), (-16+-80), (-16+-128), lit:.rodata.sta_recv_assoc.str1.1);
    /* site +0x2b1: memcmp((1+1), lit:.rodata.str1.1, 3, (-16+-128), *(*(*(?+4)+4)+22)) */
    memcmp((1+1), lit:.rodata.str1.1, 3, (-16+-128), *(*(*(?+4)+4)+22));
    /* site +0x2d9: check_bss_queue((1+8), lit:.rodata.str1.1, 3, (-16+-128), *(?+48)) */
    check_bss_queue((1+8), lit:.rodata.str1.1, 3, (-16+-128), *(?+48));
    /* site +0x30a: wifi_log(1, 36, 5, lit:.rodata_wlog_verbose.57, *(*(*(?+4)+4)+10)) */
    wifi_log(1, 36, 5, lit:.rodata_wlog_verbose.57, *(*(*(?+4)+4)+10));
    /* site +0x376: wifi_log(1, 36, 5, lit:.rodata_wlog_verbose.58, *(*(*(?+4)+4)+10)) */
    wifi_log(1, 36, 5, lit:.rodata_wlog_verbose.58, *(*(*(?+4)+4)+10));
    /* site +0x411: ieee80211_ampdu_reorder(*(*(?+16)+232), ?, 5, ((24+2)+4), *(*(*(?+4)+4)+10)) */
    ieee80211_ampdu_reorder(*(*(?+16)+232), ?, 5, ((24+2)+4), *(*(*(?+4)+4)+10));
    /* site +0x439: ieee80211_crypto_decap(*(*(?+16)+232), ?, *(?+48), *(?+48), *(*(*(?+4)+4)+10)) */
    ieee80211_crypto_decap(*(*(?+16)+232), ?, *(?+48), *(?+48), *(*(*(?+4)+4)+10));
    /* site +0x465: ieee80211_decap(?, *(*(?+4)+4), *(?+28), *(?+48), *(*(*(?+4)+4)+10)) */
    ieee80211_decap(?, *(*(?+4)+4), *(?+28), *(?+48), *(*(*(?+4)+4)+10));
    /* site +0x476: sta_rx_eapol(*(?+16), *(*(?+16)+232), ret@465, *(?+48), *(*(*(?+4)+4)+10)) */
    sta_rx_eapol(*(?+16), *(*(?+16)+232), ret@465, *(?+48), *(*(*(?+4)+4)+10));
    /* site +0x4af: ieee80211_decap_amsdu(*(?+16), ret@465, ret@465, *(?+48), *(*(*(?+4)+4)+10)) */
    ieee80211_decap_amsdu(*(?+16), ret@465, ret@465, *(?+48), *(*(*(?+4)+4)+10));
    /* site +0x4d5: indirect call via a10 (base *(esp_mesh_quick_funcs+40)); args: *(esp_mesh_quick_funcs+40), ret@465, ret@465, *(?+48), *(*(*(?+4)+4)+10) */
    opaque_indirect_a10();
    /* site +0x4f3: indirect call via a2 (base *(g_osi_funcs_p+232)); args: (*(?+16)+24), ((ret@4d5 slli 5) slli 3), 0, *(?+48), *(*(*(?+4)+4)+10) */
    opaque_indirect_a2();
    /* site +0x535: indirect call via a2 (base *(mesh_rxcb+0)); args: 0, *(g_hmac_cnt+4), *(ret@4af+22), (*(g_hmac_cnt+4)+6), *(ret@4af+28) */
    opaque_indirect_a2();
    /* site +0x53d: ic_ebuf_recycle_rx(ret@4af, *(g_hmac_cnt+4), *(ret@4af+22), (*(g_hmac_cnt+4)+6), *(ret@4af+28)) */
    ic_ebuf_recycle_rx(ret@4af, *(g_hmac_cnt+4), *(ret@4af+22), (*(g_hmac_cnt+4)+6), *(ret@4af+28));
    /* site +0x556: pm_hmac_rx_data_process(*(g_hmac_cnt+4), *(ret@4af+22), *(ret@4af+22), (*(g_hmac_cnt+4)+6), *(ret@4af+28)) */
    pm_hmac_rx_data_process(*(g_hmac_cnt+4), *(ret@4af+22), *(ret@4af+22), (*(g_hmac_cnt+4)+6), *(ret@4af+28));
    /* site +0x569: indirect call via a2 (base *(sta_rxcb+0)); args: *(g_hmac_cnt+4), *(ret@4af+22), ret@4af, (*(g_hmac_cnt+4)+6), *(ret@4af+28) */
    opaque_indirect_a2();
    /* site +0x599: wifi_log(1, 36, 5, lit:.rodata_wlog_verbose.59, *(?+20)) */
    wifi_log(1, 36, 5, lit:.rodata_wlog_verbose.59, *(?+20));
    /* site +0x5c2: sta_recv_mgmt(*(?+16), ret@4af, *(ret@4af+16), *(?+40), *(?+44)) */
    sta_recv_mgmt(*(?+16), ret@4af, *(ret@4af+16), *(?+40), *(?+44));
    /* site +0x5d7: sta_bip_check(ret@4af, ret@4af, *(ret@4af+16), *(?+40), *(?+44)) */
    sta_bip_check(ret@4af, ret@4af, *(ret@4af+16), *(?+40), *(?+44));
    /* site +0x5e9: sta_recv_ctl(*(?+28), ret@4af, *(ret@4af+16), *(?+40), *(?+44)) */
    sta_recv_ctl(*(?+28), ret@4af, *(ret@4af+16), *(?+40), *(?+44));
    /* site +0x605: ic_ebuf_recycle_rx(ret@4af, ret@4af, *(ret@4af+16), *(?+40), *(?+44)) */
    ic_ebuf_recycle_rx(ret@4af, ret@4af, *(ret@4af+16), *(?+40), *(?+44));
        /* ---- RECOVERED (medium): STA RX entry (1418B, 76 branches) ----
       FC parse (l8ui frm+0/frm+1, extui, movi 140/136/128/30/24/15/12, bbci/bbsi):
       type/subtype -> data (QoS gettid + check_bss_queue + ampdu_reorder +
       crypto_decap -> decap; eapol via sta_rx_eapol vs amsdu via decap_amsdu ->
       mesh/indirect deliver + pm_hmac_rx_data_process + sta_rxcb) vs mgmt
       (-> sta_recv_mgmt + sta_bip_check) vs ctl (-> sta_recv_ctl); tail
       ic_ebuf_recycle_rx. Mesh hooks via esp_mesh_quick_funcs+28/+40 (a13/a10
       indirects), osi+232 deliver, hmac_cnt/g_ic/gScanStruct refs. */
    {
        unsigned __rec_ft = 2u; (void)__rec_ft;
        unsigned __rec_qos = 1u; (void)__rec_qos;
        if (__rec_ft == 2u && __rec_qos == 1u) { __rec_ft = 10u; }
        else if (__rec_ft == 0u) { __rec_ft = 20u; }
        else { __rec_ft = 30u; }
        switch (__rec_ft) {
        case 10u: case 20u: case 30u: default: break;
        }
    }

return 8;
}

/* sta_rx_cb @ ieee80211_sta.o 0x00000008 size 24B bind GLOBAL
 * Calls: sta_input | Data refs: g_ic
 * Fidelity: high - straight-line, fully mapped (10 insns) */
u32 sta_rx_cb(u32 a2, u32 a3, u32 a4)
{
    /* frame: entry a1,32; 10 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* mem ld32: base=(lit:g_ic) off=16 */
    /* site +0x19: sta_input(*(g_ic+16)) */
    sta_input(*(g_ic+16));
    return last_call_result; /* opaque */
}
