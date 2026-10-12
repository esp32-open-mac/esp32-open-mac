/* wl_cnx.o - reconstructed control-path C (offline, from objdump -d -r).
 * 78 code sections recovered. Fidelity per function below.
 * Conventions: args a2..a7 (Xtensa windowed ABI); outgoing call args
 * traced as a10..; u32 used for pointers/regs; opaque_* marks unrecovered.
 */
#include <stdint.h>
typedef unsigned char u8; typedef unsigned short u16; typedef unsigned int u32;
static u32 opaque_result, last_call_result;
/* ---- externals (U symbols + literal refs) ---- */
extern u32 bss_cnx_csa_timer; /* .bss.cnx_csa_timer */
extern u32 bss_is_connected_sync; /* .bss.is_connected_sync */
extern u32 bss_s_csa_timer_bss; /* .bss.s_csa_timer_bss */
extern u32 bss_s_sta_last_start_txseq; /* .bss.s_sta_last_start_txseq */
extern u32 data_join_deny_flag; /* .data.join_deny_flag */
extern u32 rodata_CSWTCH_289; /* .rodata.CSWTCH$289 */
extern u32 rodata_cnx_auth_done; /* .rodata.cnx_auth_done */
extern u32 rodata_cnx_auth_done_str1_1; /* .rodata.cnx_auth_done.str1.1 */
extern u32 rodata_cnx_connect_to_bss_str1_1; /* .rodata.cnx_connect_to_bss.str1.1 */
extern u32 rodata_cnx_node_join_str1_1; /* .rodata.cnx_node_join.str1.1 */
extern u32 rodata_cnx_sta_scan_cmd_str1_1; /* .rodata.cnx_sta_scan_cmd.str1.1 */
extern u32 rodata_wlog_debug_10; /* .rodata_wlog_debug.10 */
extern u32 rodata_wlog_debug_100; /* .rodata_wlog_debug.100 */
extern u32 rodata_wlog_debug_101; /* .rodata_wlog_debug.101 */
extern u32 rodata_wlog_debug_102; /* .rodata_wlog_debug.102 */
extern u32 rodata_wlog_debug_104; /* .rodata_wlog_debug.104 */
extern u32 rodata_wlog_debug_106; /* .rodata_wlog_debug.106 */
extern u32 rodata_wlog_debug_107; /* .rodata_wlog_debug.107 */
extern u32 rodata_wlog_debug_11; /* .rodata_wlog_debug.11 */
extern u32 rodata_wlog_debug_111; /* .rodata_wlog_debug.111 */
extern u32 rodata_wlog_debug_112; /* .rodata_wlog_debug.112 */
extern u32 rodata_wlog_debug_14; /* .rodata_wlog_debug.14 */
extern u32 rodata_wlog_debug_15; /* .rodata_wlog_debug.15 */
extern u32 rodata_wlog_debug_16; /* .rodata_wlog_debug.16 */
extern u32 rodata_wlog_debug_19; /* .rodata_wlog_debug.19 */
extern u32 rodata_wlog_debug_20; /* .rodata_wlog_debug.20 */
extern u32 rodata_wlog_debug_21; /* .rodata_wlog_debug.21 */
extern u32 rodata_wlog_debug_22; /* .rodata_wlog_debug.22 */
extern u32 rodata_wlog_debug_23; /* .rodata_wlog_debug.23 */
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
extern u32 rodata_wlog_debug_37; /* .rodata_wlog_debug.37 */
extern u32 rodata_wlog_debug_39; /* .rodata_wlog_debug.39 */
extern u32 rodata_wlog_debug_4; /* .rodata_wlog_debug.4 */
extern u32 rodata_wlog_debug_40; /* .rodata_wlog_debug.40 */
extern u32 rodata_wlog_debug_41; /* .rodata_wlog_debug.41 */
extern u32 rodata_wlog_debug_42; /* .rodata_wlog_debug.42 */
extern u32 rodata_wlog_debug_43; /* .rodata_wlog_debug.43 */
extern u32 rodata_wlog_debug_45; /* .rodata_wlog_debug.45 */
extern u32 rodata_wlog_debug_47; /* .rodata_wlog_debug.47 */
extern u32 rodata_wlog_debug_48; /* .rodata_wlog_debug.48 */
extern u32 rodata_wlog_debug_49; /* .rodata_wlog_debug.49 */
extern u32 rodata_wlog_debug_5; /* .rodata_wlog_debug.5 */
extern u32 rodata_wlog_debug_52; /* .rodata_wlog_debug.52 */
extern u32 rodata_wlog_debug_53; /* .rodata_wlog_debug.53 */
extern u32 rodata_wlog_debug_54; /* .rodata_wlog_debug.54 */
extern u32 rodata_wlog_debug_55; /* .rodata_wlog_debug.55 */
extern u32 rodata_wlog_debug_57; /* .rodata_wlog_debug.57 */
extern u32 rodata_wlog_debug_58; /* .rodata_wlog_debug.58 */
extern u32 rodata_wlog_debug_59; /* .rodata_wlog_debug.59 */
extern u32 rodata_wlog_debug_6; /* .rodata_wlog_debug.6 */
extern u32 rodata_wlog_debug_60; /* .rodata_wlog_debug.60 */
extern u32 rodata_wlog_debug_61; /* .rodata_wlog_debug.61 */
extern u32 rodata_wlog_debug_62; /* .rodata_wlog_debug.62 */
extern u32 rodata_wlog_debug_66; /* .rodata_wlog_debug.66 */
extern u32 rodata_wlog_debug_67; /* .rodata_wlog_debug.67 */
extern u32 rodata_wlog_debug_68; /* .rodata_wlog_debug.68 */
extern u32 rodata_wlog_debug_7; /* .rodata_wlog_debug.7 */
extern u32 rodata_wlog_debug_70; /* .rodata_wlog_debug.70 */
extern u32 rodata_wlog_debug_71; /* .rodata_wlog_debug.71 */
extern u32 rodata_wlog_debug_72; /* .rodata_wlog_debug.72 */
extern u32 rodata_wlog_debug_73; /* .rodata_wlog_debug.73 */
extern u32 rodata_wlog_debug_74; /* .rodata_wlog_debug.74 */
extern u32 rodata_wlog_debug_75; /* .rodata_wlog_debug.75 */
extern u32 rodata_wlog_debug_77; /* .rodata_wlog_debug.77 */
extern u32 rodata_wlog_debug_78; /* .rodata_wlog_debug.78 */
extern u32 rodata_wlog_debug_79; /* .rodata_wlog_debug.79 */
extern u32 rodata_wlog_debug_8; /* .rodata_wlog_debug.8 */
extern u32 rodata_wlog_debug_82; /* .rodata_wlog_debug.82 */
extern u32 rodata_wlog_debug_83; /* .rodata_wlog_debug.83 */
extern u32 rodata_wlog_debug_84; /* .rodata_wlog_debug.84 */
extern u32 rodata_wlog_debug_85; /* .rodata_wlog_debug.85 */
extern u32 rodata_wlog_debug_86; /* .rodata_wlog_debug.86 */
extern u32 rodata_wlog_debug_87; /* .rodata_wlog_debug.87 */
extern u32 rodata_wlog_debug_9; /* .rodata_wlog_debug.9 */
extern u32 rodata_wlog_debug_96; /* .rodata_wlog_debug.96 */
extern u32 rodata_wlog_debug_99; /* .rodata_wlog_debug.99 */
extern u32 rodata_wlog_error_12; /* .rodata_wlog_error.12 */
extern u32 rodata_wlog_error_18; /* .rodata_wlog_error.18 */
extern u32 rodata_wlog_error_44; /* .rodata_wlog_error.44 */
extern u32 rodata_wlog_error_56; /* .rodata_wlog_error.56 */
extern u32 rodata_wlog_error_64; /* .rodata_wlog_error.64 */
extern u32 rodata_wlog_error_92; /* .rodata_wlog_error.92 */
extern u32 rodata_wlog_error_95; /* .rodata_wlog_error.95 */
extern u32 rodata_wlog_info_103; /* .rodata_wlog_info.103 */
extern u32 rodata_wlog_info_105; /* .rodata_wlog_info.105 */
extern u32 rodata_wlog_info_109; /* .rodata_wlog_info.109 */
extern u32 rodata_wlog_info_110; /* .rodata_wlog_info.110 */
extern u32 rodata_wlog_info_13; /* .rodata_wlog_info.13 */
extern u32 rodata_wlog_info_46; /* .rodata_wlog_info.46 */
extern u32 rodata_wlog_info_50; /* .rodata_wlog_info.50 */
extern u32 rodata_wlog_info_51; /* .rodata_wlog_info.51 */
extern u32 rodata_wlog_info_80; /* .rodata_wlog_info.80 */
extern u32 rodata_wlog_info_81; /* .rodata_wlog_info.81 */
extern u32 rodata_wlog_info_93; /* .rodata_wlog_info.93 */
extern u32 rodata_wlog_info_94; /* .rodata_wlog_info.94 */
extern u32 rodata_wlog_info_97; /* .rodata_wlog_info.97 */
extern u32 rodata_wlog_info_98; /* .rodata_wlog_info.98 */
extern u32 rodata_wlog_verbose_38; /* .rodata_wlog_verbose.38 */
extern u32 rodata_wlog_verbose_63; /* .rodata_wlog_verbose.63 */
extern u32 rodata_wlog_verbose_65; /* .rodata_wlog_verbose.65 */
extern u32 rodata_wlog_verbose_76; /* .rodata_wlog_verbose.76 */
extern u32 rodata_wlog_warning_108; /* .rodata_wlog_warning.108 */
extern u32 rodata_wlog_warning_17; /* .rodata_wlog_warning.17 */
extern u32 rodata_wlog_warning_24; /* .rodata_wlog_warning.24 */
extern u32 rodata_wlog_warning_25; /* .rodata_wlog_warning.25 */
extern u32 rodata_wlog_warning_26; /* .rodata_wlog_warning.26 */
extern u32 rodata_wlog_warning_69; /* .rodata_wlog_warning.69 */
extern u32 text_cnx_beacon_timeout; /* .text.cnx_beacon_timeout */
extern u32 text_cnx_probe_rc_tx_cb; /* .text.cnx_probe_rc_tx_cb */
extern u32 text_mgd_probe_send_timeout; /* .text.mgd_probe_send_timeout */
extern u32 ap_no_lr; /* ap_no_lr */
extern u32 check_bss_queue(); /* check_bss_queue */
extern u32 chm_acquire_lock(); /* chm_acquire_lock */
extern u32 chm_check_channel_is_valid(); /* chm_check_channel_is_valid */
extern u32 chm_get_band_from_chan(); /* chm_get_band_from_chan */
extern u32 chm_get_chan_info(); /* chm_get_chan_info */
extern u32 chm_get_current_band(); /* chm_get_current_band */
extern u32 chm_get_current_channel(); /* chm_get_current_channel */
extern u32 chm_release_lock(); /* chm_release_lock */
extern u32 chm_return_home_channel(); /* chm_return_home_channel */
extern u32 chm_start_op(); /* chm_start_op */
extern u32 clear_bss_queue(); /* clear_bss_queue */
extern u32 clear_ic_key(); /* clear_ic_key */
extern u32 cnx_connect_next_ap_timeout; /* cnx_connect_next_ap_timeout */
extern u32 cnx_csa_fn; /* cnx_csa_fn */
extern u32 cnx_get_authtype_strength(); /* cnx_get_authtype_strength */
extern u32 cnx_handshake_timeout; /* cnx_handshake_timeout */
extern u32 cnx_obss_scan_done_cb; /* cnx_obss_scan_done_cb */
extern u32 cnx_obss_scan_timeout; /* cnx_obss_scan_timeout */
extern u32 cnx_sta_connect_led_timer_cb; /* cnx_sta_connect_led_timer_cb */
extern u32 cnx_start_handoff_cb; /* cnx_start_handoff_cb */
extern u32 esp_mesh_quick_funcs; /* esp_mesh_quick_funcs */
extern u32 gScanStruct; /* gScanStruct */
extern u32 g_authmode_incompatible; /* g_authmode_incompatible */
extern u32 g_authmode_threshold_failure; /* g_authmode_threshold_failure */
extern u32 g_cnxMgr; /* g_cnxMgr */
extern u32 g_cnxMgr_0x8; /* g_cnxMgr+0x8 */
extern u32 g_cnxMgr_0xf00; /* g_cnxMgr+0xf00 */
extern u32 g_cnxMgr_0xf48; /* g_cnxMgr+0xf48 */
extern u32 g_cnxMgr_0xf74; /* g_cnxMgr+0xf74 */
extern u32 g_cnx_probe_rc_list_cb; /* g_cnx_probe_rc_list_cb */
extern u32 g_ic; /* g_ic */
extern u32 g_ic_0x100; /* g_ic+0x100 */
extern u32 g_ic_0x130; /* g_ic+0x130 */
extern u32 g_ic_0x1e8; /* g_ic+0x1e8 */
extern u32 g_ic_0x1f0; /* g_ic+0x1f0 */
extern u32 g_ic_0x200; /* g_ic+0x200 */
extern u32 g_in_blacklist_flag; /* g_in_blacklist_flag */
extern u32 g_mesh_init_ps_type; /* g_mesh_init_ps_type */
extern u32 g_mesh_is_root; /* g_mesh_is_root */
extern u32 g_mesh_self_organized; /* g_mesh_self_organized */
extern u32 g_misc_nvs; /* g_misc_nvs */
extern u32 g_osi_funcs_p; /* g_osi_funcs_p */
extern u32 g_rssi_threshold_failure; /* g_rssi_threshold_failure */
extern u32 g_scan; /* g_scan */
extern u32 g_sta_connected_flag; /* g_sta_connected_flag */
extern u32 g_wifi_global_lock; /* g_wifi_global_lock */
extern u32 g_wifi_menuconfig; /* g_wifi_menuconfig */
extern u32 g_wifi_nvs; /* g_wifi_nvs */
extern u32 hal_get_tsf_time(); /* hal_get_tsf_time */
extern u32 hal_now(); /* hal_now */
extern u32 hostap_del_mac_info_from_list(); /* hostap_del_mac_info_from_list */
extern u32 hostap_ht_operation_update(); /* hostap_ht_operation_update */
extern u32 ic_del_key(); /* ic_del_key */
extern u32 ic_del_key_all(); /* ic_del_key_all */
extern u32 ic_del_ptk_and_gtk_alg(); /* ic_del_ptk_and_gtk_alg */
extern u32 ic_get_next_bcnoffset(); /* ic_get_next_bcnoffset */
extern u32 ic_register_tx_cb(); /* ic_register_tx_cb */
extern u32 ic_set_trc(); /* ic_set_trc */
extern u32 ieee80211_adjust_2nd_chan(); /* ieee80211_adjust_2nd_chan */
extern u32 ieee80211_amsdu_negotiate(); /* ieee80211_amsdu_negotiate */
extern u32 ieee80211_cipher_name(); /* ieee80211_cipher_name */
extern u32 ieee80211_ethbroadcast; /* ieee80211_ethbroadcast */
extern u32 ieee80211_getmgtframe(); /* ieee80211_getmgtframe */
extern u32 ieee80211_ht_node_cleanup(); /* ieee80211_ht_node_cleanup */
extern u32 ieee80211_ht_updateparams(); /* ieee80211_ht_updateparams */
extern u32 ieee80211_is_40mhz_valid_bw(); /* ieee80211_is_40mhz_valid_bw */
extern u32 ieee80211_is_ht_cipher(); /* ieee80211_is_ht_cipher */
extern u32 ieee80211_mgmt_output(); /* ieee80211_mgmt_output */
extern u32 ieee80211_mlme_connect_bss(); /* ieee80211_mlme_connect_bss */
extern u32 ieee80211_parse_obss_scan_param(); /* ieee80211_parse_obss_scan_param */
extern u32 ieee80211_parse_wmeparams(); /* ieee80211_parse_wmeparams */
extern u32 ieee80211_phy_mode_show(); /* ieee80211_phy_mode_show */
extern u32 ieee80211_phy_type_get(); /* ieee80211_phy_type_get */
extern u32 ieee80211_pwrsave_node_cleanup(); /* ieee80211_pwrsave_node_cleanup */
extern u32 ieee80211_regdomain_chan_in_range(); /* ieee80211_regdomain_chan_in_range */
extern u32 ieee80211_regdomain_min_chan(); /* ieee80211_regdomain_min_chan */
extern u32 ieee80211_regdomain_update_in_connect(); /* ieee80211_regdomain_update_in_connect */
extern u32 ieee80211_send_mgmt(); /* ieee80211_send_mgmt */
extern u32 ieee80211_send_probereq(); /* ieee80211_send_probereq */
extern u32 ieee80211_set_max_rate(); /* ieee80211_set_max_rate */
extern u32 ieee80211_set_phy_bw(); /* ieee80211_set_phy_bw */
extern u32 ieee80211_set_shortslottime(); /* ieee80211_set_shortslottime */
extern u32 ieee80211_set_tim(); /* ieee80211_set_tim */
extern u32 ieee80211_set_tx_desc(); /* ieee80211_set_tx_desc */
extern u32 ieee80211_setup_phy_mode(); /* ieee80211_setup_phy_mode */
extern u32 ieee80211_setup_rates(); /* ieee80211_setup_rates */
extern u32 ieee80211_setup_rateset(); /* ieee80211_setup_rateset */
extern u32 ieee80211_sta_is_connected(); /* ieee80211_sta_is_connected */
extern u32 ieee80211_sta_new_state(); /* ieee80211_sta_new_state */
extern u32 ieee80211_timer_process(); /* ieee80211_timer_process */
extern u32 ieee80211_update_channel(); /* ieee80211_update_channel */
extern u32 ieee80211_update_phy_country(); /* ieee80211_update_phy_country */
extern u32 ieee80211_wme_updateparams(); /* ieee80211_wme_updateparams */
extern u32 memcmp(); /* memcmp */
extern u32 memcpy(); /* memcpy */
extern u32 memmove(); /* memmove */
extern u32 memset(); /* memset */
extern u32 pm_coex_set_reconnect_policy(); /* pm_coex_set_reconnect_policy */
extern u32 pm_disable_keep_alive_timer(); /* pm_disable_keep_alive_timer */
extern u32 pm_enable_keep_alive_timer(); /* pm_enable_keep_alive_timer */
extern u32 pm_is_open(); /* pm_is_open */
extern u32 pm_on_coex_schm_process_restart(); /* pm_on_coex_schm_process_restart */
extern u32 pm_on_coex_schm_status_config(); /* pm_on_coex_schm_status_config */
extern u32 pm_send_probe_start(); /* pm_send_probe_start */
extern u32 pm_send_probe_stop(); /* pm_send_probe_stop */
extern u32 pm_set_bss_max_idle(); /* pm_set_bss_max_idle */
extern u32 pm_start(); /* pm_start */
extern u32 pm_stop(); /* pm_stop */
extern u32 pm_wake_done(); /* pm_wake_done */
extern u32 ppInstallKey(); /* ppInstallKey */
extern u32 scan_add_bssid(); /* scan_add_bssid */
extern u32 scan_add_probe_ssid(); /* scan_add_probe_ssid */
extern u32 scan_bitmap_to_channel_list(); /* scan_bitmap_to_channel_list */
extern u32 scan_build_chan_list(); /* scan_build_chan_list */
extern u32 scan_cancel(); /* scan_cancel */
extern u32 scan_get_type(); /* scan_get_type */
extern u32 scan_prefer_chan(); /* scan_prefer_chan */
extern u32 scan_remove_bssid(); /* scan_remove_bssid */
extern u32 scan_remove_probe_ssid(); /* scan_remove_probe_ssid */
extern u32 scan_set_act_duration(); /* scan_set_act_duration */
extern u32 scan_set_current_scan_times(); /* scan_set_current_scan_times */
extern u32 scan_set_desChan(); /* scan_set_desChan */
extern u32 scan_set_pas_duration(); /* scan_set_pas_duration */
extern u32 scan_start(); /* scan_start */
extern u32 scan_update_scan_history(); /* scan_update_scan_history */
extern u32 sta_con_timer; /* sta_con_timer */
extern u32 sta_csa_timer; /* sta_csa_timer */
extern u32 sta_get_owe_data(); /* sta_get_owe_data */
extern u32 strlen(); /* strlen */
extern u32 wifi_event_post(); /* wifi_event_post */
extern u32 wifi_get_macaddr(); /* wifi_get_macaddr */
extern u32 wifi_log(); /* wifi_log */
extern u32 wifi_mesh_event_post(); /* wifi_mesh_event_post */
extern u32 wifi_nvs_commit(); /* wifi_nvs_commit */
extern u32 wifi_nvs_get(); /* wifi_nvs_get */
extern u32 wifi_nvs_set(); /* wifi_nvs_set */
extern u32 wifi_set_rx_policy(); /* wifi_set_rx_policy */
extern u32 wifi_sta_get_prof_password(); /* wifi_sta_get_prof_password */
extern u32 wifi_station_save_ap_channel(); /* wifi_station_save_ap_channel */
extern u32 wifi_wpa2_is_started(); /* wifi_wpa2_is_started */
extern u32 wifi_wps_is_started(); /* wifi_wps_is_started */

/* ROLE: station/AP connection manager (cnx_*): blacklist, roam-cache (rc),
 * BSS/node alloc, assoc/auth sequencing, OBSS scan, CSA/handoff.
 * g_cnxMgr is the manager root; channel ops go through chm_* (chm_get_chan_info,
 * chm_start_op, chm_get_current_channel); beacons/timeouts re-enter via
 * *_timeout_process handlers posted to the WiFi task.
 */
/* ---- literal-rooted access patterns (offsets observed; layout NOT confirmed) ----
 * (*(g_wifi_nvs+0)+262144): u8+170
 * *(?+0): u8+0, u32+52
 * *(g_ic+16): u32+228, u16+228, u8+228
 * *(g_ic+20): u32+0
 * *(g_osi_funcs_p+0): u32+244
 * .bss.is_connected_sync: u8+0
 * .bss.s_csa_timer_bss: u32+0
 * .bss.s_sta_last_start_txseq: u16+0
 * .data.join_deny_flag: u8+0
 * 0x3d0: u32+8, u8+8
 * ?: u8+0, u32+0, u32+4, u32+8, u8+24, u8+44, u32+44, u8+52, u8+60, u8+80, u8+132, u32+140, u8+152, u8+156 (+3 more)
 * ap_no_lr: u8+0
 * esp_mesh_quick_funcs: u32+12, u32+116, u32+144
 * gScanStruct: u8+70
 * g_cnxMgr: u32+0, u8+0, u8+0, u32+0, u32+4, u32+12, u32+16, u16+16, u32+20, u32+88, u8+96, u32+116, u8+174, u32+688 (+2 more)
 * g_cnx_probe_rc_list_cb: u32+0, u32+0
 * g_ic: u32+0, u8+0, u32+0, u8+0, u32+16, u32+16, u8+16, u32+20, u32+20, u16+100, u32+100, u32+116, u32+228, u32+232 (+27 more)
 * g_mesh_init_ps_type: u32+0
 * g_mesh_is_root: u8+0
 * g_mesh_self_organized: u8+0
 * g_misc_nvs: u32+0, u32+0
 * g_osi_funcs_p: u32+0, u32+0, u32+8, u32+52, u32+176, u32+232
 * g_scan: u32+0
 * g_wifi_global_lock: u32+0
 * g_wifi_menuconfig: u8+97
 * g_wifi_nvs: u32+0, u8+0, u32+0, u8+72, u32+116
 * ret@189: u8+4
/* ---- funcdb-v2 cross-check (calls[] vs section relocs; disasm is ground truth) ----
 * confirmed funcdb edges: 203; rejected funcdb-only (no exact reloc in
 * callee section; caller-side .rela.text.<f> prefix-collision artifacts): 0;
 * disasm-only edges kept (static-local callees + funcdb relsec:null gaps): 81;
 *   e.g. cnx_csa_fn_process->.text.cnx_connect_to_bss, cnx_do_handoff_internal->.text.cnx_connect_to_bss, cnx_bss_alloc->.text.cnx_cal_rc_util, cnx_connect_next_ap_timeout_process->.text.cnx_do_handoff, cnx_start_handoff_cb->.text.cnx_do_handoff, cnx_sta_connect_cmd->.text.cnx_choose_rc, cnx_sta_connect_cmd->.text.cnx_do_handoff
 */
/* ==== functions of wl_cnx.o ==== */

/* cnx_sta_connect_led_timer_cb @ wl_cnx.o 0x00000004 size 31B bind GLOBAL
 * Calls: none | Data refs: g_ic
 * Fidelity: high - straight-line, fully mapped (11 insns) */
u32 cnx_sta_connect_led_timer_cb(void)
{
    /* frame: entry a1,32; 11 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* immediates: -1 */
    /* mem ld8: base=((lit:g_ic+131072)) off=36 */
    /* mem st8: base=((lit:g_ic+131072)) off=36 */
    return opaque_result; /* full dataflow not recovered */
}

/* cnx_cal_rc_util @ wl_cnx.o 0x00000004 size 84B bind LOCAL
 * Calls: none | Data refs: g_cnxMgr
 * Fidelity: medium - branchy but loop-free, call sequence mapped */
u32 cnx_cal_rc_util(u32 a2)
{
    /* frame: entry a1,32; 30 insns, 8 cond-branches, 0 loops, 1 jumps */
    /* immediates: 2 */
    /* first predicate: beqz.n a8, 32 <.text.cnx_cal_rc_util+0x32> (condition opaque) */
    /* mem ld8: base=((lit:g_cnxMgr+983040)) off=93 */
    /* mem ld8: base=(?) off=167 */
    /* mem ld8: base=(?) off=164 */
    /* mem ld8: base=(?) off=164 */
    /* mem ld8: base=(?) off=165 */
    /* mem ld8: base=(?) off=170 */
    return opaque_result; /* full dataflow not recovered */
}

/* cnx_get_next_rc @ wl_cnx.o 0x00000008 size 70B bind LOCAL
 * Calls: chm_get_chan_info | Data refs: g_cnxMgr
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 cnx_get_next_rc(u32 a3)
{
    /* frame: entry a1,32; 22 insns, 2 cond-branches, 0 loops, 1 jumps */
    /* immediates: 0x3d0, 0 */
    /* first predicate: bbci a8, 9, 44 <.text.cnx_get_next_rc+0x44> (condition opaque) */
    /* mem ld32: base=(0x3d0) off=8 */
    /* mem st8: base=(?) off=95 */
    /* mem ld8: base=(*(0x3d0+8)) off=171 */
    /* mem ld32: base=(ret@2e) off=8 */
    /* mem ld8: base=((lit:g_cnxMgr+983040)) off=95 */
    /* mem ld8: base=((lit:g_cnxMgr+983040)) off=94 */
    /* site +0x2e: chm_get_chan_info(*(*(0x3d0+8)+171)) */
    chm_get_chan_info(*(*(0x3d0+8)+171));
    return 0;
}

/* cnx_probe_rc @ wl_cnx.o 0x00000018 size 119B bind LOCAL
 * Calls: chm_get_current_channel, wifi_get_macaddr, chm_start_op, ieee80211_send_probereq | Data refs: g_wifi_nvs, .text.cnx_probe_rc
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 cnx_probe_rc(u32 a2, u32 a3)
{
    /* frame: entry a1,64; 36 insns, 1 cond-branches, 0 loops, 1 jumps */
    /* immediates: 0, 171 */
    /* first predicate: beq a9, a8, 58 <.text.cnx_probe_rc+0x58> (condition opaque) */
    /* mem ld32: base=(lit:g_wifi_nvs) off=0 */
    /* mem ld8: base=(?) off=171 */
    /* mem ld8: base=(ret@23) off=0 */
    /* mem ld8: base=(*(g_wifi_nvs+0)) off=4 */
    /* mem st32: base=(?) off=4 */
    /* mem st32: base=(?) off=0 */
    /* site +0x23: chm_get_current_channel(/* no traced args */) */
    chm_get_current_channel(/* no traced args */);
    /* site +0x31: wifi_get_macaddr(0, (?+16)) */
    wifi_get_macaddr(0, (?+16));
    /* site +0x51: chm_start_op(171, 0, 0, lit:g_wifi_nvs, 0) */
    chm_start_op(171, 0, 0, lit:g_wifi_nvs, 0);
    /* site +0x72: ieee80211_send_probereq(?, (?+16), (?+4), (?+4), (*(g_wifi_nvs+0)+8)) */
    ieee80211_send_probereq(?, (?+16), (?+4), (?+4), (*(g_wifi_nvs+0)+8));
    return opaque_result; /* full dataflow not recovered */
}

/* cnx_traverse_rc_lis_done @ wl_cnx.o 0x00000010 size 67B bind LOCAL
 * Calls: chm_return_home_channel, chm_release_lock, indirect(a2) | Data refs: g_cnx_probe_rc_list_cb, g_cnxMgr
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 cnx_traverse_rc_lis_done(u32 a2, u32 a3)
{
    /* frame: entry a1,32; 19 insns, 1 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0 */
    /* first predicate: beqz.n a2, 41 <.text.cnx_traverse_rc_lis_done+0x41> (condition opaque) */
    /* mem ld32: base=(lit:g_cnx_probe_rc_list_cb) off=0 */
    /* mem st8: base=((lit:g_cnx_probe_rc_list_cb+983040)) off=95 */
    /* mem ld32: base=(*(g_cnx_probe_rc_list_cb+0)) off=0 */
    /* site +0x2d: chm_return_home_channel(/* no traced args */) */
    chm_return_home_channel(/* no traced args */);
    /* site +0x33: chm_release_lock(ret@2d) */
    chm_release_lock(ret@2d);
    /* site +0x3e: indirect call via a2 (base *(g_cnx_probe_rc_list_cb+0)); args: 0 */
    opaque_indirect_a2();
    return opaque_result; /* full dataflow not recovered */
}

/* cnx_connect_next_ap_timeout @ wl_cnx.o 0x00000004 size 18B bind GLOBAL
 * Calls: ieee80211_timer_process | Data refs: none
 * Fidelity: high - straight-line, fully mapped (7 insns) */
u32 cnx_connect_next_ap_timeout(void)
{
    /* frame: entry a1,32; 7 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0, 37, 7 */
    /* site +0x11: ieee80211_timer_process(7, 37, 0) */
    ieee80211_timer_process(7, 37, 0);
    return opaque_result; /* full dataflow not recovered */
}

/* cnx_handshake_timeout @ wl_cnx.o 0x00000004 size 18B bind GLOBAL
 * Calls: ieee80211_timer_process | Data refs: none
 * Fidelity: high - straight-line, fully mapped (7 insns) */
u32 cnx_handshake_timeout(void)
{
    /* frame: entry a1,32; 7 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0, 6, 7 */
    /* site +0x11: ieee80211_timer_process(7, 6, 0) */
    ieee80211_timer_process(7, 6, 0);
    return opaque_result; /* full dataflow not recovered */
}

/* cnx_csa_fn @ wl_cnx.o 0x00000004 size 20B bind GLOBAL
 * Calls: ieee80211_timer_process | Data refs: none
 * Fidelity: high - straight-line, fully mapped (8 insns) */
u32 cnx_csa_fn(u32 a2)
{
    /* frame: entry a1,32; 8 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* immediates: 3, 7, 1 */
    /* site +0x11: ieee80211_timer_process(7, 3) */
    ieee80211_timer_process(7, 3);
    return 1;
}

/* mgd_probe_send_timeout @ wl_cnx.o 0x00000004 size 22B bind LOCAL
 * Calls: ieee80211_timer_process | Data refs: none
 * Fidelity: high - straight-line, fully mapped (7 insns) */
u32 mgd_probe_send_timeout(void)
{
    /* frame: entry a1,32; 7 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0, 4, 7 */
    /* site +0x11: ieee80211_timer_process(7, 4, 0) */
    ieee80211_timer_process(7, 4, 0);
    return opaque_result; /* full dataflow not recovered */
}

/* cnx_beacon_timeout @ wl_cnx.o 0x00000004 size 22B bind LOCAL
 * Calls: ieee80211_timer_process | Data refs: none
 * Fidelity: high - straight-line, fully mapped (7 insns) */
u32 cnx_beacon_timeout(void)
{
    /* frame: entry a1,32; 7 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0, 5, 7 */
    /* site +0x11: ieee80211_timer_process(7, 5, 0) */
    ieee80211_timer_process(7, 5, 0);
    return opaque_result; /* full dataflow not recovered */
}

/* cnx_connect_op @ wl_cnx.o 0x00000060 size 531B bind LOCAL
 * Calls: chm_release_lock, ieee80211_cipher_name, wifi_log, ic_del_key, ic_del_key, ic_del_key, ic_del_key, ic_del_ptk_and_gtk_alg, clear_ic_key, clear_ic_key, clear_ic_key, clear_ic_key, wifi_log, indirect(a3), ppInstallKey, ppInstallKey, ppInstallKey, ppInstallKey, scan_get_type, ieee80211_mlme_connect_bss | Data refs: g_ic, .rodata_wlog_debug.59, .rodata_wlog_debug.60, g_ic+0x1f0, g_cnxMgr
 * Fidelity: low - 168 insns, 10 branches, 0 loops; skeleton only */
u32 cnx_connect_op(u32 a2, u32 a3, u32 a7)
{
    /* frame: entry a1,80; 168 insns, 10 cond-branches, 0 loops, 3 jumps */
    /* immediates: 0, 4, 1, 5, -1, 8, 13 */
    /* first predicate: bnez a3, 211 <.text.cnx_connect_op+0x211> (condition opaque) */
    /* mem st32: base=(?) off=16 */
    /* mem st32: base=(?) off=20 */
    /* mem ld8: base=((lit:g_ic+131072)) off=2 */
    /* mem ld8: base=((lit:g_ic+131072)) off=1 */
    /* mem st32: base=(?) off=0 */
    /* mem ld8: base=((?+65536)) off=52 */
    /* mem ld8: base=((lit:g_ic+131072)) off=1 */
    /* mem ld32: base=(lit:g_ic) off=0x280 */
    /* mem ld32: base=(*(g_ic+0x280)) off=16 */
    /* mem st8: base=((?+65536)) off=53 */
    /* ... +24 more memops */
    /* site +0x71: chm_release_lock(/* no traced args */) */
    chm_release_lock(/* no traced args */);
    /* site +0x83: ieee80211_cipher_name(*((lit:g_ic+131072)+2)) */
    ieee80211_cipher_name(*((lit:g_ic+131072)+2));
    /* site +0x9e: wifi_log(1, ?, 4, lit:g_ic) */
    wifi_log(1, ?, 4, lit:g_ic);
    /* site +0xa9: ic_del_key(?, ?, 4, lit:g_ic) */
    ic_del_key(?, ?, 4, lit:g_ic);
    /* site +0xb1: ic_del_key(1, ?, 4, lit:g_ic) */
    ic_del_key(1, ?, 4, lit:g_ic);
    /* site +0xb9: ic_del_key(4, ?, 4, lit:g_ic) */
    ic_del_key(4, ?, 4, lit:g_ic);
    /* site +0xc1: ic_del_key(5, ?, 4, lit:g_ic) */
    ic_del_key(5, ?, 4, lit:g_ic);
    /* site +0xc9: ic_del_ptk_and_gtk_alg(?, ?, 4, lit:g_ic) */
    ic_del_ptk_and_gtk_alg(?, ?, 4, lit:g_ic);
    /* site +0xd5: clear_ic_key(*((?+65536)+52), ?, 4, lit:g_ic) */
    clear_ic_key(*((?+65536)+52), ?, 4, lit:g_ic);
    /* site +0xdd: clear_ic_key(?, ?, 4, lit:g_ic) */
    clear_ic_key(?, ?, 4, lit:g_ic);
    /* site +0xe5: clear_ic_key(1, ?, 4, lit:g_ic) */
    clear_ic_key(1, ?, 4, lit:g_ic);
    /* site +0xed: clear_ic_key(5, ?, 4, lit:g_ic) */
    clear_ic_key(5, ?, 4, lit:g_ic);
    /* site +0x102: wifi_log(1, 4, 4, lit:g_ic) */
    wifi_log(1, 4, 4, lit:g_ic);
    /* site +0x111: indirect call via a3 (base *(*(g_ic+0x280)+16)); args: (?+4), 4, 4, lit:g_ic */
    opaque_indirect_a3();
    /* site +0x157: ppInstallKey(*((lit:g_ic+131072)+1), (?+4), -1, *((lit:g_ic+131072)+1), (?+16)) */
    ppInstallKey(*((lit:g_ic+131072)+1), (?+4), -1, *((lit:g_ic+131072)+1), (?+16));
    /* site +0x176: ppInstallKey(*((lit:g_ic+131072)+1), (?+4), *((lit:g_ic+131072)+1), *((lit:g_ic+131072)+1), (?+16)) */
    ppInstallKey(*((lit:g_ic+131072)+1), (?+4), *((lit:g_ic+131072)+1), *((lit:g_ic+131072)+1), (?+16));
    /* site +0x1af: ppInstallKey(5, (?+4), (?+4), *((lit:g_ic+131072)+1), (?+16)) */
    ppInstallKey(5, (?+4), (?+4), *((lit:g_ic+131072)+1), (?+16));
    /* site +0x1d2: ppInstallKey(5, (?+4), *((lit:g_ic+131072)+1), *((lit:g_ic+131072)+1), (?+16)) */
    ppInstallKey(5, (?+4), *((lit:g_ic+131072)+1), *((lit:g_ic+131072)+1), (?+16));
    /* site +0x1e1: scan_get_type(ret@1d2, (?+4), *((lit:g_ic+131072)+1), *((lit:g_ic+131072)+1), (?+16)) */
    scan_get_type(ret@1d2, (?+4), *((lit:g_ic+131072)+1), *((lit:g_ic+131072)+1), (?+16));
    /* site +0x20e: ieee80211_mlme_connect_bss(?, 1, 1, *((lit:g_ic+131072)+1), (?+16)) */
    ieee80211_mlme_connect_bss(?, 1, 1, *((lit:g_ic+131072)+1), (?+16));
    return opaque_result; /* full dataflow not recovered */
}

/* update_ic_params_using_bss$part$0 @ wl_cnx.o 0x00000004 size 40B bind LOCAL
 * Calls: none | Data refs: g_ic
 * Fidelity: high - straight-line, fully mapped (13 insns) */
u32 update_ic_params_using_bss_part_0(void)
{
    /* frame: entry a1,32; 13 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0 */
    /* mem st16: base=((lit:g_ic+131072)) off=0 */
    /* mem st8: base=((lit:g_ic+131072)) off=2 */
    /* mem st8: base=((lit:g_ic+131072)) off=4 */
    /* mem st16: base=((lit:g_ic+131072)) off=156 */
    /* mem st32: base=(lit:g_ic) off=0x208 */
    return opaque_result; /* full dataflow not recovered */
}

/* ieee80211_cnx_attach @ wl_cnx.o 0x00000014 size 62B bind GLOBAL
 * Calls: memset, ic_register_tx_cb | Data refs: g_cnxMgr, g_ic, .text.cnx_probe_rc_tx_cb
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 ieee80211_cnx_attach(void)
{
    /* frame: entry a1,32; 23 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0x1f1, 0, 1, 2, 15 */
    /* mem st32: base=(lit:g_ic) off=0 */
    /* mem st32: base=(ret@29) off=0 */
    /* mem st8: base=((ret@29+983040)) off=93 */
    /* site +0x29: memset(?, 0, (0x1f1 slli 3)) */
    memset(?, 0, (0x1f1 slli 3));
    /* site +0x4d: ic_register_tx_cb(lit:.text.cnx_probe_rc_tx_cb, 0, 1) */
    ic_register_tx_cb(lit:.text.cnx_probe_rc_tx_cb, 0, 1);
    return opaque_result; /* full dataflow not recovered */
}

/* _cnx_start_connect_without_scan @ wl_cnx.o 0x00000014 size 85B bind GLOBAL
 * Calls: wifi_log | Data refs: g_ic, .rodata_wlog_debug.3, g_cnxMgr, gScanStruct
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 cnx_start_connect_without_scan(u32 a2)
{
    /* frame: entry a1,32; 32 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* immediates: 1, 4, -65, 16, 2 */
    /* mem ld32: base=(lit:g_ic) off=16 */
    /* mem ld8: base=((*(g_ic+16)+65536)) off=84 */
    /* mem ld32: base=(lit:g_ic) off=16 */
    /* mem st8: base=((*(g_ic+16)+65536)) off=84 */
    /* mem ld32: base=(*(g_ic+16)) off=164 */
    /* mem st32: base=(*(g_ic+16)) off=164 */
    /* mem ld32: base=(lit:g_cnxMgr) off=0 */
    /* mem st32: base=(lit:g_cnxMgr) off=0 */
    /* mem st8: base=(lit:gScanStruct) off=68 */
    /* site +0x31: wifi_log(1, 4, 4, lit:.rodata_wlog_debug.3, *((*(g_ic+16)+65536)+84)) */
    wifi_log(1, 4, 4, lit:.rodata_wlog_debug.3, *((*(g_ic+16)+65536)+84));
    return opaque_result; /* full dataflow not recovered */
}

/* cnx_can_do_obss_scan @ wl_cnx.o 0x00000020 size 104B bind GLOBAL
 * Calls: wifi_log, wifi_log, wifi_log | Data refs: g_ic, .rodata_wlog_debug.5, .rodata_wlog_debug.6, .rodata_wlog_debug.7, .rodata_wlog_debug.8
 * Fidelity: medium - branchy but loop-free, call sequence mapped */
u32 cnx_can_do_obss_scan(u32 a3)
{
    /* frame: entry a1,32; 40 insns, 4 cond-branches, 0 loops, 3 jumps */
    /* immediates: 4, 8, 1, 0 */
    /* first predicate: bnez.n a3, 44 <cnx_can_do_obss_scan+0x24> (condition opaque) */
    /* mem ld32: base=(lit:g_ic) off=16 */
    /* mem ld32: base=(lit:g_ic) off=0x248 */
    /* mem ld32: base=(*(g_ic+16)) off=152 */
    /* mem ld32: base=(*(g_ic+16)) off=228 */
    /* site +0x3d: wifi_log(1, 8, 4, lit:.rodata_wlog_debug.5) */
    wifi_log(1, 8, 4, lit:.rodata_wlog_debug.5);
    /* site +0x65: wifi_log(1, 8, 4, lit:.rodata_wlog_debug.7, *(*(g_ic+16)+152)) */
    wifi_log(1, 8, 4, lit:.rodata_wlog_debug.7, *(*(g_ic+16)+152));
    /* site +0x7f: wifi_log(1, 8, 4, lit:.rodata_wlog_debug.8, *(*(g_ic+16)+152)) */
    wifi_log(1, 8, 4, lit:.rodata_wlog_debug.8, *(*(g_ic+16)+152));
    return *(*(g_ic+16)+228);
}

/* cnx_obss_scan @ wl_cnx.o 0x00000038 size 126B bind GLOBAL
 * Calls: cnx_can_do_obss_scan, scan_cancel, scan_remove_probe_ssid, scan_add_probe_ssid, scan_remove_bssid, scan_set_act_duration, scan_start, wifi_log, wifi_log | Data refs: g_ic+0x130, cnx_obss_scan_done_cb, .rodata_wlog_debug.14, .rodata_wlog_debug.15, .rodata_wlog_debug.16
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 cnx_obss_scan(u32 a5)
{
    /* frame: entry a1,32; 47 insns, 2 cond-branches, 0 loops, 1 jumps */
    /* immediates: 0, 2, 1, 120, 0x10f, 4, 8, -1 */
    /* first predicate: beqz a10, a5 <cnx_obss_scan+0x6d> (condition opaque) */
    /* site +0x3e: cnx_can_do_obss_scan(/* no traced args */) */
    cnx_can_do_obss_scan(/* no traced args */);
    /* site +0x49: scan_cancel(ret@3e) */
    scan_cancel(ret@3e);
    /* site +0x51: scan_remove_probe_ssid(0) */
    scan_remove_probe_ssid(0);
    /* site +0x61: scan_add_probe_ssid(1, ?, 0, 2) */
    scan_add_probe_ssid(1, ?, 0, 2);
    /* site +0x67: scan_remove_bssid(ret@61, ?, 0, 2) */
    scan_remove_bssid(ret@61, ?, 0, 2);
    /* site +0x72: scan_set_act_duration(0, 120, 0, 2) */
    scan_set_act_duration(0, 120, 0, 2);
    /* site +0x83: scan_start(0x10f, 0, lit:cnx_obss_scan_done_cb, lit:g_ic+0x130) */
    scan_start(0x10f, 0, lit:cnx_obss_scan_done_cb, lit:g_ic+0x130);
    /* site +0x9b: wifi_log(1, 8, 4, lit:.rodata_wlog_debug.14, ret@83) */
    wifi_log(1, 8, 4, lit:.rodata_wlog_debug.14, ret@83);
    /* site +0xb1: wifi_log(1, 8, 4, lit:.rodata_wlog_debug.16, ret@83) */
    wifi_log(1, 8, 4, lit:.rodata_wlog_debug.16, ret@83);
    return -1;
}

/* cnx_obss_scan_timeout @ wl_cnx.o 0x00000024 size 88B bind GLOBAL
 * Calls: wifi_log, wifi_log, wifi_log, cnx_obss_scan | Data refs: g_ic, .rodata_wlog_debug.100, .rodata_wlog_debug.101, .rodata_wlog_debug.102, .rodata_wlog_info.103
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 cnx_obss_scan_timeout(void)
{
    /* frame: entry a1,32; 32 insns, 3 cond-branches, 0 loops, 2 jumps */
    /* immediates: 4, 8, 1, 3 */
    /* first predicate: beqz.n a8, 54 <cnx_obss_scan_timeout+0x30> (condition opaque) */
    /* mem ld32: base=(lit:g_ic) off=16 */
    /* mem ld32: base=(*(g_ic+16)) off=152 */
    /* mem ld32: base=(&wifi_log()) off=228 */
    /* site +0x45: wifi_log(1, 8, 4, lit:.rodata_wlog_debug.101, *(g_ic+152)) */
    wifi_log(1, 8, 4, lit:.rodata_wlog_debug.101, *(g_ic+152));
    /* site +0x5d: wifi_log(1, 8, 4, lit:.rodata_wlog_debug.102, *(g_ic+152)) */
    wifi_log(1, 8, 4, lit:.rodata_wlog_debug.102, *(g_ic+152));
    /* site +0x71: wifi_log(1, 1, 3, lit:.rodata_wlog_info.103, *(g_ic+152)) */
    wifi_log(1, 1, 3, lit:.rodata_wlog_info.103, *(g_ic+152));
    /* site +0x77: cnx_obss_scan(ret@71, 1, 3, lit:.rodata_wlog_info.103, *(g_ic+152)) */
    cnx_obss_scan(ret@71, 1, 3, lit:.rodata_wlog_info.103, *(g_ic+152));
    return opaque_result; /* full dataflow not recovered */
}

/* cnx_sta_scan_cmd @ wl_cnx.o 0x000000c8 size 774B bind GLOBAL
 * Calls: wifi_log, wifi_log, scan_cancel, scan_remove_probe_ssid, scan_add_probe_ssid, scan_remove_bssid, wifi_log, scan_prefer_chan, ieee80211_regdomain_chan_in_range, ieee80211_regdomain_min_chan, scan_build_chan_list, wifi_log, wifi_log, strlen, scan_add_probe_ssid, wifi_log, scan_add_bssid, scan_remove_bssid, chm_check_channel_is_valid, scan_set_desChan, scan_bitmap_to_channel_list, wifi_log, indirect(a10), wifi_log, wifi_log, scan_set_current_scan_times, wifi_log, scan_prefer_chan, ieee80211_regdomain_chan_in_range, ieee80211_regdomain_min_chan, scan_build_chan_list, scan_start | Data refs: .rodata.cnx_sta_scan_cmd.str1.1, g_ic, .rodata_wlog_warning.17, .rodata_wlog_error.18, gScanStruct, g_scan, .rodata_wlog_debug.19, g_wifi_nvs, .rodata_wlog_debug.20, .rodata_wlog_debug.21, .rodata_wlog_debug.22, .rodata_wlog_debug.23, g_osi_funcs_p, .rodata_wlog_warning.24, .rodata_wlog_warning.25, .rodata_wlog_warning.26
 * Fidelity: low - 294 insns, 29 branches, 0 loops; skeleton only */
u32 cnx_sta_scan_cmd(u32 a2, u32 a3, u32 a4, u32 a6)
{
    /* frame: entry a1,64; 294 insns, 29 cond-branches, 0 loops, 10 jumps */
    /* immediates: 2, 8, 1, -1, 0, 120, 4, 3, 0x10f, 0xfffffe98 */
    /* first predicate: beqz.n a5, ee <cnx_sta_scan_cmd+0x26> (condition opaque) */
    /* mem ld32: base=(lit:g_ic) off=16 */
    /* mem ld8: base=((*(g_ic+16)+65536)) off=84 */
    /* mem st8: base=(lit:gScanStruct) off=71 */
    /* mem ld32: base=(lit:g_scan) off=0 */
    /* mem st8: base=(*(g_scan+0)) off=163 */
    /* mem st8: base=((*(g_scan+0)+65536)) off=26 */
    /* mem st8: base=((*(g_scan+0)+65536)) off=25 */
    /* mem ld32: base=(lit:g_wifi_nvs) off=0 */
    /* mem ld32: base=((*(g_wifi_nvs+0)+327680)) off=200 */
    /* mem ld32: base=(ret@189) off=0 */
    /* ... +52 more memops */
    /* site +0xe5: wifi_log(*((*(g_ic+16)+65536)+84), 8, 2, lit:.rodata_wlog_warning.17) */
    wifi_log(*((*(g_ic+16)+65536)+84), 8, 2, lit:.rodata_wlog_warning.17);
    /* site +0xfa: wifi_log(1, 8, 1, lit:.rodata_wlog_error.18) */
    wifi_log(1, 8, 1, lit:.rodata_wlog_error.18);
    /* site +0x107: scan_cancel(-1, 8, 1, lit:.rodata_wlog_error.18) */
    scan_cancel(-1, 8, 1, lit:.rodata_wlog_error.18);
    /* site +0x11d: scan_remove_probe_ssid(0, 8, 1, lit:.rodata_wlog_error.18) */
    scan_remove_probe_ssid(0, 8, 1, lit:.rodata_wlog_error.18);
    /* site +0x131: scan_add_probe_ssid(1, ?, ?, 2) */
    scan_add_probe_ssid(1, ?, ?, 2);
    /* site +0x137: scan_remove_bssid(ret@131, ?, ?, 2) */
    scan_remove_bssid(ret@131, ?, ?, 2);
    /* site +0x161: wifi_log(1, 8, 4, lit:.rodata_wlog_debug.19, 120) */
    wifi_log(1, 8, 4, lit:.rodata_wlog_debug.19, 120);
    /* site +0x169: scan_prefer_chan(?, 8, 4, lit:.rodata_wlog_debug.19, 120) */
    scan_prefer_chan(?, 8, 4, lit:.rodata_wlog_debug.19, 120);
    /* site +0x171: ieee80211_regdomain_chan_in_range(ret@169, 8, 4, lit:.rodata_wlog_debug.19, 120) */
    ieee80211_regdomain_chan_in_range(ret@169, 8, 4, lit:.rodata_wlog_debug.19, 120);
    /* site +0x189: ieee80211_regdomain_min_chan(1, 8, 4, lit:.rodata_wlog_debug.19, 120) */
    ieee80211_regdomain_min_chan(1, 8, 4, lit:.rodata_wlog_debug.19, 120);
    /* site +0x199: scan_build_chan_list((1 slli 17), 8, 4, lit:.rodata_wlog_debug.19, 120) */
    scan_build_chan_list((1 slli 17), 8, 4, lit:.rodata_wlog_debug.19, 120);
    /* site +0x1df: wifi_log(1, 8, 4, lit:.rodata_wlog_debug.20, lit:.rodata.cnx_sta_scan_cmd.str1.1) */
    wifi_log(1, 8, 4, lit:.rodata_wlog_debug.20, lit:.rodata.cnx_sta_scan_cmd.str1.1);
    /* site +0x1f1: wifi_log(1, 8, 4, lit:.rodata_wlog_debug.21, *(ret@189+28)) */
    wifi_log(1, 8, 4, lit:.rodata_wlog_debug.21, *(ret@189+28));
    /* site +0x1fd: strlen(*(ret@189+0), 8, 4, lit:.rodata_wlog_debug.21, *(ret@189+28)) */
    strlen(*(ret@189+0), 8, 4, lit:.rodata_wlog_debug.21, *(ret@189+28));
    /* site +0x217: scan_add_probe_ssid(1, *(ret@189+0), *(ret@189+0), 2, *(ret@189+28)) */
    scan_add_probe_ssid(1, *(ret@189+0), *(ret@189+0), 2, *(ret@189+28));
    /* site +0x247: wifi_log(1, 8, 4, lit:.rodata_wlog_debug.22, *(.rodata.cnx_sta_scan_cmd.str1.1+0)) */
    wifi_log(1, 8, 4, lit:.rodata_wlog_debug.22, *(.rodata.cnx_sta_scan_cmd.str1.1+0));
    /* site +0x24f: scan_add_bssid(*(ret@189+4), 8, 4, lit:.rodata_wlog_debug.22, *(.rodata.cnx_sta_scan_cmd.str1.1+0)) */
    scan_add_bssid(*(ret@189+4), 8, 4, lit:.rodata_wlog_debug.22, *(.rodata.cnx_sta_scan_cmd.str1.1+0));
    /* site +0x258: scan_remove_bssid(ret@24f, 8, 4, lit:.rodata_wlog_debug.22, *(.rodata.cnx_sta_scan_cmd.str1.1+0)) */
    scan_remove_bssid(ret@24f, 8, 4, lit:.rodata_wlog_debug.22, *(.rodata.cnx_sta_scan_cmd.str1.1+0));
    /* site +0x26f: chm_check_channel_is_valid(*(ret@189+32), *(ret@189+36), 4, lit:.rodata_wlog_debug.22, *(.rodata.cnx_sta_scan_cmd.str1.1+0)) */
    chm_check_channel_is_valid(*(ret@189+32), *(ret@189+36), 4, lit:.rodata_wlog_debug.22, *(.rodata.cnx_sta_scan_cmd.str1.1+0));
    /* site +0x27e: scan_set_desChan(*(ret@189+8), *(ret@189+36), 4, lit:.rodata_wlog_debug.22, *(.rodata.cnx_sta_scan_cmd.str1.1+0)) */
    scan_set_desChan(*(ret@189+8), *(ret@189+36), 4, lit:.rodata_wlog_debug.22, *(.rodata.cnx_sta_scan_cmd.str1.1+0));
    /* site +0x295: scan_bitmap_to_channel_list(ret@27e, *(ret@189+36), 4, lit:.rodata_wlog_debug.22, *(.rodata.cnx_sta_scan_cmd.str1.1+0)) */
    scan_bitmap_to_channel_list(ret@27e, *(ret@189+36), 4, lit:.rodata_wlog_debug.22, *(.rodata.cnx_sta_scan_cmd.str1.1+0));
    /* site +0x2ae: wifi_log(1, 8, 4, lit:.rodata_wlog_debug.23, *(.rodata.cnx_sta_scan_cmd.str1.1+0)) */
    wifi_log(1, 8, 4, lit:.rodata_wlog_debug.23, *(.rodata.cnx_sta_scan_cmd.str1.1+0));
    /* site +0x2e5: indirect call via a10 (base *(g_osi_funcs_p+0x194)); args: *(g_osi_funcs_p+0x194), 8, 4, lit:.rodata_wlog_debug.23, *(.rodata.cnx_sta_scan_cmd.str1.1+0) */
    opaque_indirect_a10();
    /* site +0x31b: wifi_log(1, 8, 2, lit:.rodata_wlog_warning.24, *(.rodata.cnx_sta_scan_cmd.str1.1+0)) */
    wifi_log(1, 8, 2, lit:.rodata_wlog_warning.24, *(.rodata.cnx_sta_scan_cmd.str1.1+0));
    /* site +0x34a: wifi_log(*(ret@189+12), 8, 2, lit:.rodata_wlog_warning.25, *(.rodata.cnx_sta_scan_cmd.str1.1+0)) */
    wifi_log(*(ret@189+12), 8, 2, lit:.rodata_wlog_warning.25, *(.rodata.cnx_sta_scan_cmd.str1.1+0));
    /* site +0x359: scan_set_current_scan_times(*(ret@189+16), *(ret@189+20), *(ret@189+24), *(ret@189+28), *(.rodata.cnx_sta_scan_cmd.str1.1+0)) */
    scan_set_current_scan_times(*(ret@189+16), *(ret@189+20), *(ret@189+24), *(ret@189+28), *(.rodata.cnx_sta_scan_cmd.str1.1+0));
    /* site +0x379: wifi_log(1, 8, 2, lit:.rodata_wlog_warning.26, *(.rodata.cnx_sta_scan_cmd.str1.1+0)) */
    wifi_log(1, 8, 2, lit:.rodata_wlog_warning.26, *(.rodata.cnx_sta_scan_cmd.str1.1+0));
    /* site +0x389: scan_prefer_chan(*(ret@189+0), 8, 2, lit:.rodata_wlog_warning.26, *(.rodata.cnx_sta_scan_cmd.str1.1+0)) */
    scan_prefer_chan(*(ret@189+0), 8, 2, lit:.rodata_wlog_warning.26, *(.rodata.cnx_sta_scan_cmd.str1.1+0));
    /* site +0x391: ieee80211_regdomain_chan_in_range(ret@389, 8, 2, lit:.rodata_wlog_warning.26, *(.rodata.cnx_sta_scan_cmd.str1.1+0)) */
    ieee80211_regdomain_chan_in_range(ret@389, 8, 2, lit:.rodata_wlog_warning.26, *(.rodata.cnx_sta_scan_cmd.str1.1+0));
    /* site +0x3a9: ieee80211_regdomain_min_chan(1, 8, 2, lit:.rodata_wlog_warning.26, *(.rodata.cnx_sta_scan_cmd.str1.1+0)) */
    ieee80211_regdomain_min_chan(1, 8, 2, lit:.rodata_wlog_warning.26, *(.rodata.cnx_sta_scan_cmd.str1.1+0));
    /* site +0x3b9: scan_build_chan_list((1 slli 17), 8, 2, lit:.rodata_wlog_warning.26, *(.rodata.cnx_sta_scan_cmd.str1.1+0)) */
    scan_build_chan_list((1 slli 17), 8, 2, lit:.rodata_wlog_warning.26, *(.rodata.cnx_sta_scan_cmd.str1.1+0));
    /* site +0x3c7: scan_start(0x10f, 3, ?, ?, *(.rodata.cnx_sta_scan_cmd.str1.1+0)) */
    scan_start(0x10f, 3, ?, ?, *(.rodata.cnx_sta_scan_cmd.str1.1+0));
    return last_call_result; /* opaque */
}

/* cnx_connect_next_ap @ wl_cnx.o 0x00000020 size 137B bind GLOBAL
 * Calls: indirect(a8), indirect(a8), indirect(a8), indirect(a3), wifi_log | Data refs: g_ic, g_mesh_is_root, g_cnxMgr, g_cnxMgr+0xf74, g_osi_funcs_p, cnx_connect_next_ap_timeout, .rodata_wlog_debug.29
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 cnx_connect_next_ap(u32 a3, u32 a4)
{
    /* frame: entry a1,32; 52 insns, 3 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0, 1, 4 */
    /* first predicate: beqz.n a2, 3a <cnx_connect_next_ap+0x1a> (condition opaque) */
    /* mem ld32: base=(lit:g_ic) off=116 */
    /* mem ld8: base=(lit:g_mesh_is_root) off=0 */
    /* mem ld8: base=((lit:g_cnxMgr+983040)) off=94 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=236 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=240 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=244 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* ... +5 more memops */
    /* site +0x53: indirect call via a8 (base *(*(g_osi_funcs_p+0)+236)); args: lit:g_cnxMgr+0xf74 */
    opaque_indirect_a8();
    /* site +0x5e: indirect call via a8 (base *(*(g_osi_funcs_p+0)+240)); args: lit:g_cnxMgr+0xf74 */
    opaque_indirect_a8();
    /* site +0x6d: indirect call via a8 (base *(*(g_osi_funcs_p+0)+244)); args: lit:g_cnxMgr+0xf74, lit:cnx_connect_next_ap_timeout, 0 */
    opaque_indirect_a8();
    /* site +0x7b: indirect call via a3 (base *(g_osi_funcs_p+232)); args: lit:g_cnxMgr+0xf74, 0, 0 */
    opaque_indirect_a3();
    /* site +0x96: wifi_log(1, 4, 4, lit:.rodata_wlog_debug.29, *(g_cnxMgr+0xf74+84)) */
    wifi_log(1, 4, 4, lit:.rodata_wlog_debug.29, *(g_cnxMgr+0xf74+84));
    return opaque_result; /* full dataflow not recovered */
}

/* cnx_auth_timeout @ wl_cnx.o 0x00000004 size 18B bind GLOBAL
 * Calls: ieee80211_timer_process | Data refs: none
 * Fidelity: high - straight-line, fully mapped (7 insns) */
u32 cnx_auth_timeout(void)
{
    /* frame: entry a1,32; 7 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0, 11, 7 */
    /* site +0x11: ieee80211_timer_process(7, 11, 0) */
    ieee80211_timer_process(7, 11, 0);
    return opaque_result; /* full dataflow not recovered */
}

/* cnx_auth_timeout_process @ wl_cnx.o 0x00000010 size 36B bind GLOBAL
 * Calls: wifi_log, ieee80211_sta_new_state | Data refs: .rodata_wlog_debug.30, g_ic
 * Fidelity: high - straight-line, fully mapped (13 insns) */
u32 cnx_auth_timeout_process(void)
{
    /* frame: entry a1,32; 13 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* immediates: 4, 1, 0x200, 0 */
    /* site +0x21: wifi_log(1, ?, 4, lit:.rodata_wlog_debug.30) */
    wifi_log(1, ?, 4, lit:.rodata_wlog_debug.30);
    /* site +0x2f: ieee80211_sta_new_state(lit:g_ic, 0, 0x200, lit:.rodata_wlog_debug.30) */
    ieee80211_sta_new_state(lit:g_ic, 0, 0x200, lit:.rodata_wlog_debug.30);
    return opaque_result; /* full dataflow not recovered */
}

/* cnx_assoc_timeout @ wl_cnx.o 0x00000004 size 18B bind GLOBAL
 * Calls: ieee80211_timer_process | Data refs: none
 * Fidelity: high - straight-line, fully mapped (7 insns) */
u32 cnx_assoc_timeout(void)
{
    /* frame: entry a1,32; 7 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0, 13, 7 */
    /* site +0x11: ieee80211_timer_process(7, 13, 0) */
    ieee80211_timer_process(7, 13, 0);
    return opaque_result; /* full dataflow not recovered */
}

/* cnx_assoc_timeout_process @ wl_cnx.o 0x00000010 size 36B bind GLOBAL
 * Calls: wifi_log, ieee80211_sta_new_state | Data refs: .rodata_wlog_debug.31, g_ic
 * Fidelity: high - straight-line, fully mapped (13 insns) */
u32 cnx_assoc_timeout_process(void)
{
    /* frame: entry a1,32; 13 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* immediates: 4, 1, 0x400, 0 */
    /* site +0x21: wifi_log(1, ?, 4, lit:.rodata_wlog_debug.31) */
    wifi_log(1, ?, 4, lit:.rodata_wlog_debug.31);
    /* site +0x2f: ieee80211_sta_new_state(lit:g_ic, 0, 0x400, lit:.rodata_wlog_debug.31) */
    ieee80211_sta_new_state(lit:g_ic, 0, 0x400, lit:.rodata_wlog_debug.31);
    return opaque_result; /* full dataflow not recovered */
}

/* cnx_handshake_timeout_process @ wl_cnx.o 0x00000014 size 74B bind GLOBAL
 * Calls: hal_now, wifi_log, indirect(a8), ieee80211_sta_new_state | Data refs: .rodata_wlog_debug.32, g_ic
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 cnx_handshake_timeout_process(u32 a2)
{
    /* frame: entry a1,32; 28 insns, 3 cond-branches, 0 loops, 0 jumps */
    /* immediates: 4, 1, 0, 51 */
    /* first predicate: bnei a8, 1, 4d <cnx_handshake_timeout_process+0x39> (condition opaque) */
    /* mem ld32: base=(lit:g_ic) off=0x24c */
    /* mem st32: base=(lit:g_ic) off=0x24c */
    /* mem ld32: base=(lit:g_ic) off=0x1b8 */
    /* mem ld32: base=(*(g_ic+0x1b8)) off=16 */
    /* site +0x1a: hal_now(/* no traced args */) */
    hal_now(/* no traced args */);
    /* site +0x2d: wifi_log(1, 4, 4, lit:.rodata_wlog_debug.32) */
    wifi_log(1, 4, 4, lit:.rodata_wlog_debug.32);
    /* site +0x4a: indirect call via a8 (base *(*(g_ic+0x1b8)+16)); args: ret@2d, 4, 4, lit:.rodata_wlog_debug.32 */
    opaque_indirect_a8();
    /* site +0x59: ieee80211_sta_new_state(lit:g_ic, 0, (51 slli 10), lit:.rodata_wlog_debug.32) */
    ieee80211_sta_new_state(lit:g_ic, 0, (51 slli 10), lit:.rodata_wlog_debug.32);
    return opaque_result; /* full dataflow not recovered */
}

/* wl_is_ap_no_lr @ wl_cnx.o 0x00000004 size 11B bind GLOBAL
 * Calls: none | Data refs: ap_no_lr
 * Fidelity: high - straight-line, fully mapped (4 insns) */
u32 wl_is_ap_no_lr(void)
{
    /* frame: entry a1,32; 4 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* mem ld8: base=(lit:ap_no_lr) off=0 */
    return opaque_result; /* full dataflow not recovered */
}

/* wl_clear_ap_no_lr @ wl_cnx.o 0x00000004 size 19B bind GLOBAL
 * Calls: none | Data refs: ap_no_lr
 * Fidelity: high - straight-line, fully mapped (7 insns) */
u32 wl_clear_ap_no_lr(void)
{
    /* frame: entry a1,32; 7 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0 */
    /* mem st8: base=(lit:ap_no_lr) off=0 */
    return opaque_result; /* full dataflow not recovered */
}

/* cnx_csa_cancel_pending_connect @ wl_cnx.o 0x0000000c size 34B bind GLOBAL
 * Calls: wifi_log | Data refs: .bss.s_csa_timer_bss, .rodata_wlog_debug.49
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 cnx_csa_cancel_pending_connect(u32 a2)
{
    /* frame: entry a1,32; 14 insns, 1 cond-branches, 0 loops, 0 jumps */
    /* immediates: 4, 1, 0 */
    /* first predicate: beqz.n a8, 29 <cnx_csa_cancel_pending_connect+0x1d> (condition opaque) */
    /* mem ld32: base=(lit:.bss.s_csa_timer_bss) off=0 */
    /* mem st32: base=(lit:.bss.s_csa_timer_bss) off=0 */
    /* site +0x22: wifi_log(1, 4, 4, lit:.rodata_wlog_debug.49) */
    wifi_log(1, 4, 4, lit:.rodata_wlog_debug.49);
    return opaque_result; /* full dataflow not recovered */
}

/* cnx_softap_csa @ wl_cnx.o 0x00000044 size 369B bind GLOBAL
 * Calls: chm_get_band_from_chan, chm_get_band_from_chan, wifi_log, wifi_log, wifi_mesh_event_post, indirect(a5), indirect(a5), indirect(a5), ic_get_next_bcnoffset, indirect(a5), ic_get_next_bcnoffset, wifi_log | Data refs: g_ic, g_wifi_nvs, .rodata_wlog_info.50, .rodata_wlog_info.51, .bss.s_csa_timer_bss, .bss.cnx_csa_timer, g_osi_funcs_p, cnx_csa_fn, .rodata_wlog_debug.52
 * Fidelity: low - 138 insns, 9 branches, 0 loops; skeleton only */
u32 cnx_softap_csa(u32 a3, u32 a6, u32 a7)
{
    /* frame: entry a1,80; 138 insns, 9 cond-branches, 0 loops, 1 jumps */
    /* immediates: -1, 0, 1, 3, 4, 15, 66 */
    /* first predicate: bnez.n a8, 58 <cnx_softap_csa+0x14> (condition opaque) */
    /* mem ld32: base=(lit:g_ic) off=20 */
    /* mem st32: base=(?) off=32 */
    /* mem ld32: base=(lit:g_wifi_nvs) off=0 */
    /* mem ld8: base=(*(g_wifi_nvs+0)) off=0 */
    /* mem ld8: base=((lit:g_ic+65536)) off=234 */
    /* mem ld8: base=((lit:g_ic+65536)) off=235 */
    /* mem ld8: base=(-1) off=0 */
    /* mem ld8: base=((*(g_ic+20)+65536)) off=86 */
    /* mem ld8: base=(-1) off=0 */
    /* mem st32: base=(?) off=36 */
    /* ... +33 more memops */
    /* site +0x9f: chm_get_band_from_chan(*((*(g_ic+20)+65536)+86), *(-1+0), 0, (*(-1+0)+-14)) */
    chm_get_band_from_chan(*((*(g_ic+20)+65536)+86), *(-1+0), 0, (*(-1+0)+-14));
    /* site +0xaf: chm_get_band_from_chan(*(-1+0), *(-1+0), 0, (*(-1+0)+-14)) */
    chm_get_band_from_chan(*(-1+0), *(-1+0), 0, (*(-1+0)+-14));
    /* site +0xc9: wifi_log(1, 4, 3, lit:.rodata_wlog_info.50, *((*(g_ic+20)+65536)+86)) */
    wifi_log(1, 4, 3, lit:.rodata_wlog_info.50, *((*(g_ic+20)+65536)+86));
    /* site +0x105: wifi_log(1, (1 slli 15), 3, lit:.rodata_wlog_info.51, *(-1+0)) */
    wifi_log(1, (1 slli 15), 3, lit:.rodata_wlog_info.51, *(-1+0));
    /* site +0x11e: wifi_mesh_event_post(66, (?+16), 1, lit:.rodata_wlog_info.51, *(-1+0)) */
    wifi_mesh_event_post(66, (?+16), 1, lit:.rodata_wlog_info.51, *(-1+0));
    /* site +0x15d: indirect call via a5 (base *(.bss.s_csa_timer_bss+236)); args: lit:.bss.cnx_csa_timer, (?+16), 1, lit:.rodata_wlog_info.51, *(-1+0) */
    opaque_indirect_a5();
    /* site +0x167: indirect call via a5 (base *(.bss.s_csa_timer_bss+240)); args: lit:.bss.cnx_csa_timer, (?+16), 1, lit:.rodata_wlog_info.51, *(-1+0) */
    opaque_indirect_a5();
    /* site +0x176: indirect call via a5 (base *(.bss.s_csa_timer_bss+244)); args: lit:.bss.cnx_csa_timer, lit:cnx_csa_fn, 0, lit:.rodata_wlog_info.51, *(-1+0) */
    opaque_indirect_a5();
    /* site +0x189: ic_get_next_bcnoffset(ret@176, lit:cnx_csa_fn, 0, lit:.rodata_wlog_info.51, *(-1+0)) */
    ic_get_next_bcnoffset(ret@176, lit:cnx_csa_fn, 0, lit:.rodata_wlog_info.51, *(-1+0));
    /* site +0x195: indirect call via a5 (base *(g_osi_funcs_p+232)); args: lit:.bss.cnx_csa_timer, lit:cnx_csa_fn, 0, lit:.rodata_wlog_info.51, *(-1+0) */
    opaque_indirect_a5();
    /* site +0x19b: ic_get_next_bcnoffset(ret@195, lit:cnx_csa_fn, 0, lit:.rodata_wlog_info.51, *(-1+0)) */
    ic_get_next_bcnoffset(ret@195, lit:cnx_csa_fn, 0, lit:.rodata_wlog_info.51, *(-1+0));
    /* site +0x1ae: wifi_log(1, 4, 4, lit:.rodata_wlog_debug.52, (*((lit:g_ic+65536)+236)+1)) */
    wifi_log(1, 4, 4, lit:.rodata_wlog_debug.52, (*((lit:g_ic+65536)+236)+1));
    return 0;
}

/* cnx_connect_to_bss @ wl_cnx.o 0x00000074 size 676B bind LOCAL
 * Calls: chm_get_current_channel, wifi_log, wifi_log, pm_wake_done, wifi_log, wifi_set_rx_policy, cnx_softap_csa, wifi_log, wifi_log, indirect(a8), ieee80211_update_channel, indirect(a2), hal_now, chm_acquire_lock, wifi_log, chm_start_op, cnx_connect_op | Data refs: g_cnxMgr, g_ic, g_mesh_is_root, g_mesh_self_organized, .rodata_wlog_debug.53, .rodata_wlog_debug.54, .rodata_wlog_debug.55, .rodata.cnx_connect_to_bss.str1.1, .rodata_wlog_error.56, .rodata_wlog_debug.57, g_osi_funcs_p, .rodata_wlog_debug.58
 * Fidelity: low - 213 insns, 19 branches, 0 loops; skeleton only */
u32 cnx_connect_to_bss(u32 a2, u32 a4, u32 a5)
{
    /* frame: entry a1,64; 213 insns, 19 cond-branches, 0 loops, 6 jumps */
    /* immediates: 255, 4, 1, 0x140, 5, 0, 12, 171, 0x4a7, 8 */
    /* first predicate: beqz.n a9, b8 <.text.cnx_connect_to_bss+0xb8> (condition opaque) */
    /* mem ld32: base=(lit:g_cnxMgr) off=16 */
    /* mem ld32: base=((lit:g_cnxMgr+983040)) off=96 */
    /* mem st32: base=(?) off=16 */
    /* mem ld32: base=(lit:g_cnxMgr) off=20 */
    /* mem ld32: base=(lit:g_cnxMgr) off=116 */
    /* mem ld8: base=(lit:g_cnxMgr) off=0 */
    /* mem ld8: base=(lit:g_cnxMgr) off=0 */
    /* mem ld8: base=(?) off=171 */
    /* mem ld8: base=(?) off=172 */
    /* mem ld8: base=(ret@91) off=0 */
    /* ... +29 more memops */
    /* site +0x91: chm_get_current_channel(/* no traced args */) */
    chm_get_current_channel(/* no traced args */);
    /* site +0xe1: wifi_log(1, 4, 4, lit:g_cnxMgr) */
    wifi_log(1, 4, 4, lit:g_cnxMgr);
    /* site +0x11a: wifi_log(1, 4, 4, lit:g_cnxMgr, *((*(g_cnxMgr+16)+65536)+84)) */
    wifi_log(1, 4, 4, lit:g_cnxMgr, *((*(g_cnxMgr+16)+65536)+84));
    /* site +0x12e: pm_wake_done(ret@11a, 4, 4, lit:g_cnxMgr, *((*(g_cnxMgr+16)+65536)+84)) */
    pm_wake_done(ret@11a, 4, 4, lit:g_cnxMgr, *((*(g_cnxMgr+16)+65536)+84));
    /* site +0x14a: wifi_log(1, 12, 4, lit:g_cnxMgr, 5) */
    wifi_log(1, 12, 4, lit:g_cnxMgr, 5);
    /* site +0x155: wifi_set_rx_policy(5, 12, 4, lit:g_cnxMgr, 5) */
    wifi_set_rx_policy(5, 12, 4, lit:g_cnxMgr, 5);
    /* site +0x161: cnx_softap_csa(171, 5, 4, lit:g_cnxMgr, 5) */
    cnx_softap_csa(171, 5, 4, lit:g_cnxMgr, 5);
    /* site +0x1ba: wifi_log(1, (1 slli 11), 1, lit:g_cnxMgr, lit:g_cnxMgr) */
    wifi_log(1, (1 slli 11), 1, lit:g_cnxMgr, lit:g_cnxMgr);
    /* site +0x216: wifi_log(1, 4, 4, lit:g_cnxMgr, ret@1ba) */
    wifi_log(1, 4, 4, lit:g_cnxMgr, ret@1ba);
    /* site +0x22f: indirect call via a8 (base *(*(g_cnxMgr+0)+0x19c)); args: 1, 0, lit:g_cnxMgr, lit:g_cnxMgr, ret@1ba */
    opaque_indirect_a8();
    /* site +0x237: ieee80211_update_channel(171, 0, lit:g_cnxMgr, lit:g_cnxMgr, ret@1ba) */
    ieee80211_update_channel(171, 0, lit:g_cnxMgr, lit:g_cnxMgr, ret@1ba);
    /* site +0x241: indirect call via a2 (base *(*(g_cnxMgr+0)+0x1a0)); args: 1, 0, lit:g_cnxMgr, lit:g_cnxMgr, ret@1ba */
    opaque_indirect_a2();
    /* site +0x247: hal_now(ret@241, 0, lit:g_cnxMgr, lit:g_cnxMgr, ret@1ba) */
    hal_now(ret@241, 0, lit:g_cnxMgr, lit:g_cnxMgr, ret@1ba);
    /* site +0x265: chm_acquire_lock(3, lit:g_cnxMgr, 5, lit:g_cnxMgr, ret@1ba) */
    chm_acquire_lock(3, lit:g_cnxMgr, 5, lit:g_cnxMgr, ret@1ba);
    /* site +0x276: wifi_log(1, 4, 4, lit:g_cnxMgr, ret@1ba) */
    wifi_log(1, 4, 4, lit:g_cnxMgr, ret@1ba);
    /* site +0x28d: chm_start_op(171, 1, 1, lit:g_cnxMgr, 1) */
    chm_start_op(171, 1, 1, lit:g_cnxMgr, 1);
    /* site +0x29b: cnx_connect_op(5, 0, 1, lit:g_cnxMgr, 1) */
    cnx_connect_op(5, 0, 1, lit:g_cnxMgr, 1);
    return 2;
}

/* cnx_csa_fn_process @ wl_cnx.o 0x00000044 size 268B bind GLOBAL
 * Calls: wifi_log, wifi_log, wifi_log, ieee80211_update_channel, cnx_connect_to_bss, wifi_station_save_ap_channel, wifi_nvs_get, wifi_nvs_set, ieee80211_adjust_2nd_chan, wifi_nvs_commit | Data refs: g_ic, .rodata_wlog_info.46, .rodata_wlog_debug.47, .rodata_wlog_debug.48, g_ic+0x1e8, .bss.s_csa_timer_bss, g_wifi_nvs
 * Fidelity: low - 97 insns, 9 branches, 0 loops; skeleton only */
u32 cnx_csa_fn_process(u32 a2)
{
    /* frame: entry a1,32; 97 insns, 9 cond-branches, 0 loops, 2 jumps */
    /* immediates: 3, 4, 1, 0, 26 */
    /* first predicate: beqz.n a5, 9c <cnx_csa_fn_process+0x58> (condition opaque) */
    /* mem ld32: base=(lit:g_ic) off=16 */
    /* mem ld8: base=((lit:g_ic+65536)) off=232 */
    /* mem ld32: base=(lit:g_ic) off=20 */
    /* mem ld32: base=(*(g_ic+16)) off=228 */
    /* mem ld8: base=((lit:g_ic+65536)) off=233 */
    /* mem st8: base=(*(*(g_ic+16)+228)) off=172 */
    /* mem st8: base=((*(g_ic+16)+65536)) off=87 */
    /* mem ld8: base=((lit:g_ic+65536)) off=232 */
    /* mem st8: base=(*(*(g_ic+16)+228)) off=171 */
    /* mem st8: base=((*(g_ic+16)+65536)) off=86 */
    /* ... +14 more memops */
    /* site +0x61: wifi_log(1, 4, 3, lit:.rodata_wlog_info.46, *((lit:g_ic+65536)+232)) */
    wifi_log(1, 4, 3, lit:.rodata_wlog_info.46, *((lit:g_ic+65536)+232));
    /* site +0x99: wifi_log(1, (3 slli 14), 4, lit:.rodata_wlog_debug.47, *((lit:g_ic+65536)+232)) */
    wifi_log(1, (3 slli 14), 4, lit:.rodata_wlog_debug.47, *((lit:g_ic+65536)+232));
    /* site +0xbd: wifi_log(1, (3 slli 14), 4, lit:.rodata_wlog_debug.48, *((*(g_ic+20)+65536)+86)) */
    wifi_log(1, (3 slli 14), 4, lit:.rodata_wlog_debug.48, *((*(g_ic+20)+65536)+86));
    /* site +0xc6: ieee80211_update_channel(lit:g_ic+0x1e8, (3 slli 14), 4, lit:.rodata_wlog_debug.48, *((*(g_ic+20)+65536)+86)) */
    ieee80211_update_channel(lit:g_ic+0x1e8, (3 slli 14), 4, lit:.rodata_wlog_debug.48, *((*(g_ic+20)+65536)+86));
    /* site +0xd5: cnx_connect_to_bss(*(.bss.s_csa_timer_bss+0), (3 slli 14), 4, lit:.rodata_wlog_debug.48, *((*(g_ic+20)+65536)+86)) */
    cnx_connect_to_bss(*(.bss.s_csa_timer_bss+0), (3 slli 14), 4, lit:.rodata_wlog_debug.48, *((*(g_ic+20)+65536)+86));
    /* site +0xf6: wifi_station_save_ap_channel(*((lit:g_ic+65536)+232), (3 slli 14), 4, lit:.rodata_wlog_debug.48, *((*(g_ic+20)+65536)+86)) */
    wifi_station_save_ap_channel(*((lit:g_ic+65536)+232), (3 slli 14), 4, lit:.rodata_wlog_debug.48, *((*(g_ic+20)+65536)+86));
    /* site +0x107: wifi_nvs_get(ret@f6, (3 slli 14), 4, lit:.rodata_wlog_debug.48, *((*(g_ic+20)+65536)+86)) */
    wifi_nvs_get(ret@f6, (3 slli 14), 4, lit:.rodata_wlog_debug.48, *((*(g_ic+20)+65536)+86));
    /* site +0x12b: wifi_nvs_set(26, *((lit:g_ic+65536)+232), 0, lit:.rodata_wlog_debug.48, *((*(g_ic+20)+65536)+86)) */
    wifi_nvs_set(26, *((lit:g_ic+65536)+232), 0, lit:.rodata_wlog_debug.48, *((*(g_ic+20)+65536)+86));
    /* site +0x137: ieee80211_adjust_2nd_chan(ret@12b, *((lit:g_ic+65536)+232), 0, lit:.rodata_wlog_debug.48, *((*(g_ic+20)+65536)+86)) */
    ieee80211_adjust_2nd_chan(ret@12b, *((lit:g_ic+65536)+232), 0, lit:.rodata_wlog_debug.48, *((*(g_ic+20)+65536)+86));
    /* site +0x146: wifi_nvs_commit(ret@137, *((lit:g_ic+65536)+232), 0, lit:.rodata_wlog_debug.48, *((*(g_ic+20)+65536)+86)) */
    wifi_nvs_commit(ret@137, *((lit:g_ic+65536)+232), 0, lit:.rodata_wlog_debug.48, *((*(g_ic+20)+65536)+86));
    return last_call_result; /* opaque */
}

/* cnx_bss_init @ wl_cnx.o 0x00000028 size 208B bind GLOBAL
 * Calls: wifi_log, memset, indirect(a10), indirect(a10), wifi_log | Data refs: .rodata_wlog_error.64, g_wifi_menuconfig, g_ic, g_osi_funcs_p, .bss.s_sta_last_start_txseq, g_wifi_nvs, .rodata_wlog_verbose.65
 * Fidelity: low - 76 insns, 5 branches, 0 loops; skeleton only */
u32 cnx_bss_init(u32 a2, u32 a3, u32 a6)
{
    /* frame: entry a1,32; 76 insns, 5 cond-branches, 0 loops, 2 jumps */
    /* immediates: 1, 4, 0x3d0, 0, 246, 210, 174, -16, 5 */
    /* first predicate: bnez.n a2, 40 <cnx_bss_init+0x18> (condition opaque) */
    /* mem st32: base=(?) off=0 */
    /* mem ld8: base=(lit:g_wifi_menuconfig) off=97 */
    /* mem ld32: base=(lit:g_ic) off=116 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=188 */
    /* mem st16: base=(174) off=36 */
    /* mem st16: base=(174) off=0 */
    /* mem st8: base=(246) off=0 */
    /* mem ld16: base=(lit:.bss.s_sta_last_start_txseq) off=0 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* ... +6 more memops */
    /* site +0x39: wifi_log(1, 4, 1, lit:.rodata_wlog_error.64) */
    wifi_log(1, 4, 1, lit:.rodata_wlog_error.64);
    /* site +0x4a: memset(?, 0, 0x3d0, lit:.rodata_wlog_error.64) */
    memset(?, 0, 0x3d0, lit:.rodata_wlog_error.64);
    /* site +0x81: indirect call via a10 (base *(g_osi_funcs_p+188)); args: *(g_osi_funcs_p+188), 0, 0x3d0, lit:.rodata_wlog_error.64 */
    opaque_indirect_a10();
    /* site +0xb1: indirect call via a10 (base *(g_osi_funcs_p+0x14c)); args: *(g_osi_funcs_p+0x14c), 0, 0x3d0, lit:.rodata_wlog_error.64 */
    opaque_indirect_a10();
    /* site +0xf3: wifi_log(1, 4, 5, lit:.rodata_wlog_verbose.65, *(g_wifi_nvs+116)) */
    wifi_log(1, 4, 5, lit:.rodata_wlog_verbose.65, *(g_wifi_nvs+116));
    return opaque_result; /* full dataflow not recovered */
}

/* cnx_check_bssid_in_blacklist @ wl_cnx.o 0x00000008 size 45B bind GLOBAL
 * Calls: memcmp | Data refs: g_cnxMgr
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 cnx_check_bssid_in_blacklist(u32 a2, u32 a3)
{
    /* frame: entry a1,32; 18 insns, 2 cond-branches, 0 loops, 2 jumps */
    /* immediates: 6, 1 */
    /* first predicate: beqz.n a10, 31 <cnx_check_bssid_in_blacklist+0x29> (condition opaque) */
    /* mem ld32: base=((lit:g_cnxMgr+983040)) off=88 */
    /* mem ld32: base=(*(g_cnxMgr+88)) off=8 */
    /* site +0x22: memcmp(?, *(g_cnxMgr+88), 6) */
    memcmp(?, *(g_cnxMgr+88), 6);
    return 1;
}

/* cnx_remove_from_blacklist @ wl_cnx.o 0x00000014 size 142B bind GLOBAL
 * Calls: wifi_log, memcmp, indirect(a2) | Data refs: .rodata_wlog_debug.67, g_cnxMgr, g_osi_funcs_p
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 cnx_remove_from_blacklist(u32 a2, u32 a3)
{
    /* frame: entry a1,64; 54 insns, 3 cond-branches, 0 loops, 3 jumps */
    /* immediates: 4, 1, 0, 6 */
    /* first predicate: bnez.n a10, 99 <cnx_remove_from_blacklist+0x85> (condition opaque) */
    /* mem ld8: base=((lit:g_cnxMgr+983040)) off=92 */
    /* mem st32: base=(?) off=16 */
    /* mem ld8: base=(?) off=5 */
    /* mem st32: base=(?) off=12 */
    /* mem ld8: base=(?) off=4 */
    /* mem st32: base=(?) off=8 */
    /* mem ld8: base=(?) off=3 */
    /* mem st32: base=(?) off=4 */
    /* mem ld8: base=(?) off=2 */
    /* mem st32: base=(?) off=0 */
    /* ... +10 more memops */
    /* site +0x51: wifi_log(1, 4, 4, lit:.rodata_wlog_debug.67, *(?+0)) */
    wifi_log(1, 4, 4, lit:.rodata_wlog_debug.67, *(?+0));
    /* site +0x63: memcmp(?, *(g_cnxMgr+88), 6, lit:.rodata_wlog_debug.67, *(?+0)) */
    memcmp(?, *(g_cnxMgr+88), 6, lit:.rodata_wlog_debug.67, *(?+0));
    /* site +0x85: indirect call via a2 (base *(g_osi_funcs_p+176)); args: *(g_cnxMgr+88), *(g_cnxMgr+88), 6, lit:.rodata_wlog_debug.67, *(?+0) */
    opaque_indirect_a2();
    return opaque_result; /* full dataflow not recovered */
}

/* cnx_add_to_blacklist @ wl_cnx.o 0x00000028 size 180B bind GLOBAL
 * Calls: wifi_log, indirect(a4), wifi_log, memcpy, cnx_check_bssid_in_blacklist, wifi_log, indirect(a2) | Data refs: .rodata_wlog_debug.68, g_cnxMgr, g_osi_funcs_p, .rodata_wlog_warning.69, .rodata_wlog_debug.70
 * Fidelity: low - 69 insns, 3 branches, 0 loops; skeleton only */
u32 cnx_add_to_blacklist(u32 a2, u32 a3, u32 a5)
{
    /* frame: entry a1,64; 69 insns, 3 cond-branches, 0 loops, 3 jumps */
    /* immediates: 4, 1, 12, 2, 0, 6 */
    /* first predicate: bnez.n a10, 88 <cnx_add_to_blacklist+0x60> (condition opaque) */
    /* mem ld8: base=((lit:g_cnxMgr+983040)) off=92 */
    /* mem st32: base=(?) off=16 */
    /* mem ld8: base=(?) off=5 */
    /* mem st32: base=(?) off=12 */
    /* mem ld8: base=(?) off=4 */
    /* mem st32: base=(?) off=8 */
    /* mem ld8: base=(?) off=3 */
    /* mem st32: base=(?) off=4 */
    /* mem ld8: base=(?) off=2 */
    /* mem st32: base=(?) off=0 */
    /* ... +12 more memops */
    /* site +0x5f: wifi_log(1, 4, 4, lit:.rodata_wlog_debug.68, *(?+0)) */
    wifi_log(1, 4, 4, lit:.rodata_wlog_debug.68, *(?+0));
    /* site +0x6d: indirect call via a4 (base *(*(g_osi_funcs_p+0)+0x16c)); args: 12, 4, 4, lit:.rodata_wlog_debug.68, *(?+0) */
    opaque_indirect_a4();
    /* site +0x81: wifi_log(1, 4, 2, lit:.rodata_wlog_warning.69, *(?+0)) */
    wifi_log(1, 4, 2, lit:.rodata_wlog_warning.69, *(?+0));
    /* site +0x91: memcpy(ret@81, ?, 6, lit:.rodata_wlog_warning.69, *(?+0)) */
    memcpy(ret@81, ?, 6, lit:.rodata_wlog_warning.69, *(?+0));
    /* site +0xa6: cnx_check_bssid_in_blacklist(?, ?, 6, lit:.rodata_wlog_warning.69, *(?+0)) */
    cnx_check_bssid_in_blacklist(?, ?, 6, lit:.rodata_wlog_warning.69, *(?+0));
    /* site +0xcd: wifi_log(1, 4, 4, lit:.rodata_wlog_debug.70, *(?+0)) */
    wifi_log(1, 4, 4, lit:.rodata_wlog_debug.70, *(?+0));
    /* site +0xd7: indirect call via a2 (base *(*(g_osi_funcs_p+0)+176)); args: ret@6d, 4, 4, lit:.rodata_wlog_debug.70, *(?+0) */
    opaque_indirect_a2();
    return opaque_result; /* full dataflow not recovered */
}

/* cnx_clear_blacklist @ wl_cnx.o 0x00000018 size 129B bind GLOBAL
 * Calls: wifi_log, memset, indirect(a9) | Data refs: .rodata_wlog_debug.71, g_cnxMgr, g_osi_funcs_p, g_cnxMgr+0xf48
 * Fidelity: medium - branchy but loop-free, call sequence mapped */
u32 cnx_clear_blacklist(u32 a2, u32 a3)
{
    /* frame: entry a1,32; 47 insns, 4 cond-branches, 0 loops, 2 jumps */
    /* immediates: 4, 1, 12, 0 */
    /* first predicate: beqz.n a8, 69 <cnx_clear_blacklist+0x51> (condition opaque) */
    /* mem ld32: base=((lit:g_cnxMgr+983040)) off=88 */
    /* mem ld32: base=((lit:g_cnxMgr+983040)) off=88 */
    /* mem ld32: base=(*(g_cnxMgr+88)) off=8 */
    /* mem st32: base=((lit:g_cnxMgr+983040)) off=88 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=176 */
    /* mem ld8: base=((lit:g_cnxMgr+983040)) off=92 */
    /* mem st8: base=((lit:g_cnxMgr+983040)) off=92 */
    /* mem ld32: base=((lit:g_cnxMgr+983040)) off=88 */
    /* mem ld8: base=((lit:g_cnxMgr+983040)) off=94 */
    /* ... +3 more memops */
    /* site +0x29: wifi_log(1, ?, 4, lit:.rodata_wlog_debug.71) */
    wifi_log(1, ?, 4, lit:.rodata_wlog_debug.71);
    /* site +0x51: memset(*(g_cnxMgr+88), 0, 12, lit:.rodata_wlog_debug.71) */
    memset(*(g_cnxMgr+88), 0, 12, lit:.rodata_wlog_debug.71);
    /* site +0x59: indirect call via a9 (base *(*(g_osi_funcs_p+0)+176)); args: ret@51, 0, 12, lit:.rodata_wlog_debug.71 */
    opaque_indirect_a9();
    return opaque_result; /* full dataflow not recovered */
}

/* cnx_rc_search @ wl_cnx.o 0x0000000c size 56B bind GLOBAL
 * Calls: memcmp | Data refs: g_cnxMgr, g_cnxMgr+0xf48
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 cnx_rc_search(u32 a2, u32 a3, u32 a4)
{
    /* frame: entry a1,32; 23 insns, 3 cond-branches, 0 loops, 1 jumps */
    /* immediates: 6, 0 */
    /* first predicate: beqz.n a2, 36 <cnx_rc_search+0x2a> (condition opaque) */
    /* mem ld8: base=((lit:g_cnxMgr+983040)) off=94 */
    /* mem ld32: base=(lit:g_cnxMgr+0xf48) off=0 */
    /* site +0x31: memcmp((*(g_cnxMgr+0xf48+0)+4), ?, 6) */
    memcmp((*(g_cnxMgr+0xf48+0)+4), ?, 6);
    return 0;
}

/* cnx_do_handoff_internal @ wl_cnx.o 0x0000001c size 168B bind GLOBAL
 * Calls: cnx_rc_search, wifi_log, wifi_log, cnx_connect_to_bss | Data refs: .rodata_wlog_error.44, .rodata_wlog_debug.45, g_cnxMgr
 * Fidelity: low - 63 insns, 3 branches, 0 loops; skeleton only */
u32 cnx_do_handoff_internal(u32 a2)
{
    /* frame: entry a1,48; 63 insns, 3 cond-branches, 0 loops, 2 jumps */
    /* immediates: 1, 5, 4, -17, 0x140 */
    /* first predicate: bnez.n a10, 60 <cnx_do_handoff_internal+0x44> (condition opaque) */
    /* mem ld8: base=(?) off=5 */
    /* mem st32: base=(?) off=12 */
    /* mem ld8: base=(?) off=4 */
    /* mem st32: base=(?) off=8 */
    /* mem ld8: base=(?) off=3 */
    /* mem st32: base=(?) off=4 */
    /* mem ld8: base=(?) off=2 */
    /* mem st32: base=(?) off=0 */
    /* mem ld8: base=(?) off=1 */
    /* mem ld8: base=(?) off=0 */
    /* ... +14 more memops */
    /* site +0x25: cnx_rc_search(/* no traced args */) */
    cnx_rc_search(/* no traced args */);
    /* site +0x59: wifi_log(1, 5, 1, lit:.rodata_wlog_error.44, *(?+0)) */
    wifi_log(1, 5, 1, lit:.rodata_wlog_error.44, *(?+0));
    /* site +0x89: wifi_log(1, 5, 4, lit:.rodata_wlog_debug.45, *(ret@59+4)) */
    wifi_log(1, 5, 4, lit:.rodata_wlog_debug.45, *(ret@59+4));
    /* site +0x91: cnx_connect_to_bss(*(?+2), 5, 4, lit:.rodata_wlog_debug.45, *(ret@59+4)) */
    cnx_connect_to_bss(*(?+2), 5, 4, lit:.rodata_wlog_debug.45, *(ret@59+4));
    return last_call_result; /* opaque */
}

/* cnx_validate_owe_bss @ wl_cnx.o 0x00000024 size 150B bind GLOBAL
 * Calls: sta_get_owe_data, memcmp, memcmp, cnx_rc_search, wifi_log, check_bss_queue | Data refs: g_ic, g_wifi_nvs, .rodata_wlog_debug.61
 * Fidelity: medium - branchy but loop-free, call sequence mapped */
u32 cnx_validate_owe_bss(u32 a4)
{
    /* frame: entry a1,32; 55 insns, 8 cond-branches, 0 loops, 3 jumps */
    /* immediates: 1, 6, 0, 15, 4 */
    /* first predicate: bnez.n a3, 41 <cnx_validate_owe_bss+0x1d> (condition opaque) */
    /* mem ld8: base=((lit:g_ic+196608)) off=2 */
    /* mem ld32: base=(lit:g_wifi_nvs) off=0 */
    /* mem ld8: base=((*(g_wifi_nvs+0)+262144)) off=21 */
    /* mem ld8: base=((lit:g_ic+131072)) off=1 */
    /* mem ld8: base=((*(g_wifi_nvs+0)+196608)) off=95 */
    /* site +0x2a: sta_get_owe_data(/* no traced args */) */
    sta_get_owe_data(/* no traced args */);
    /* site +0x5e: memcmp(ret@2a, (ret@2a+72), 6) */
    memcmp(ret@2a, (ret@2a+72), 6);
    /* site +0x6d: memcmp((1+4), (ret@2a+78), 6) */
    memcmp((1+4), (ret@2a+78), 6);
    /* site +0x8e: cnx_rc_search((ret@2a+72), (ret@2a+78), 6) */
    cnx_rc_search((ret@2a+72), (ret@2a+78), 6);
    /* site +0x9f: wifi_log(1, 4, 4, lit:.rodata_wlog_debug.61) */
    wifi_log(1, 4, 4, lit:.rodata_wlog_debug.61);
    /* site +0xae: check_bss_queue((ret@2a+78), 4, 4, lit:.rodata_wlog_debug.61) */
    check_bss_queue((ret@2a+78), 4, 4, lit:.rodata_wlog_debug.61);
    return 0;
}

/* cnx_add_rc @ wl_cnx.o 0x00000008 size 146B bind GLOBAL
 * Calls: none | Data refs: g_cnxMgr, g_cnxMgr+0xf48
 * Fidelity: medium - branchy but loop-free, call sequence mapped */
u32 cnx_add_rc(u32 a2)
{
    /* frame: entry a1,32; 55 insns, 6 cond-branches, 0 loops, 4 jumps */
    /* immediates: 255, 0x3d0, 0, 0x3cf */
    /* first predicate: bgeui a8, 4, 95 <cnx_add_rc+0x8d> (condition opaque) */
    /* mem ld8: base=((lit:g_cnxMgr+983040)) off=94 */
    /* mem st32: base=(0x3d0) off=8 */
    /* mem ld8: base=(?) off=171 */
    /* mem ld32: base=(lit:g_cnxMgr+0xf48) off=0 */
    /* mem ld8: base=(*(g_cnxMgr+0xf48+0)) off=171 */
    /* mem ld32: base=(?) off=8 */
    /* mem st32: base=(?) off=8 */
    /* mem st32: base=(0x3d0) off=8 */
    /* mem st32: base=((0+1)) off=8 */
    /* mem st8: base=((lit:g_cnxMgr+983040)) off=94 */
    return 0;
}

/* cnx_remove_all_rc @ wl_cnx.o 0x00000018 size 196B bind GLOBAL
 * Calls: wifi_log, indirect(a3), indirect(a8), indirect(a8), memset | Data refs: .rodata_wlog_debug.72, .bss.s_csa_timer_bss, g_cnxMgr, g_osi_funcs_p
 * Fidelity: low - 74 insns, 5 branches, 0 loops; skeleton only */
u32 cnx_remove_all_rc(u32 a2, u32 a4, u32 a5)
{
    /* frame: entry a1,32; 74 insns, 5 cond-branches, 0 loops, 2 jumps */
    /* immediates: 4, 1, 0, 0x3d0 */
    /* first predicate: beqz.n a3, 38 <cnx_remove_all_rc+0x20> (condition opaque) */
    /* mem ld32: base=(lit:.bss.s_csa_timer_bss) off=0 */
    /* mem st32: base=(lit:.bss.s_csa_timer_bss) off=0 */
    /* mem ld32: base=(0x3d0) off=8 */
    /* mem ld32: base=(*(0x3d0+8)) off=0x338 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=176 */
    /* mem ld32: base=(0x3d0) off=8 */
    /* mem ld32: base=(*(g_osi_funcs_p+8)) off=0x3b8 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=176 */
    /* ... +12 more memops */
    /* site +0x29: wifi_log(1, ?, 4, lit:.rodata_wlog_debug.72) */
    wifi_log(1, ?, 4, lit:.rodata_wlog_debug.72);
    /* site +0x5d: indirect call via a3 (base *(g_osi_funcs_p+176)); args: *(*(0x3d0+8)+0x338), ?, 4, lit:.rodata_wlog_debug.72 */
    opaque_indirect_a3();
    /* site +0x77: indirect call via a8 (base *(g_osi_funcs_p+176)); args: *(*(g_osi_funcs_p+8)+0x3b8), ?, 4, lit:.rodata_wlog_debug.72 */
    opaque_indirect_a8();
    /* site +0x9b: indirect call via a8 (base *(g_osi_funcs_p+176)); args: *(g_osi_funcs_p+0x3bc), ?, 4, lit:.rodata_wlog_debug.72 */
    opaque_indirect_a8();
    /* site +0xb9: memset(*(g_osi_funcs_p+8), 0, 0x3d0, lit:.rodata_wlog_debug.72) */
    memset(*(g_osi_funcs_p+8), 0, 0x3d0, lit:.rodata_wlog_debug.72);
    return opaque_result; /* full dataflow not recovered */
}

/* cnx_remove_rc @ wl_cnx.o 0x00000020 size 229B bind GLOBAL
 * Calls: wifi_log, indirect(a7), indirect(a7), indirect(a7), memset, memmove | Data refs: .rodata_wlog_debug.73, .bss.s_csa_timer_bss, g_cnxMgr, g_cnxMgr+0xf48, g_osi_funcs_p
 * Fidelity: low - 86 insns, 7 branches, 0 loops; skeleton only */
u32 cnx_remove_rc(u32 a2, u32 a5, u32 a7)
{
    /* frame: entry a1,48; 86 insns, 7 cond-branches, 0 loops, 3 jumps */
    /* immediates: 4, 1, 0, 0x3d0, 0x3d3, 0x3d2 */
    /* first predicate: bne a4, a2, 5c <cnx_remove_rc+0x3c> (condition opaque) */
    /* mem ld8: base=(?) off=9 */
    /* mem st32: base=(?) off=12 */
    /* mem ld8: base=(?) off=8 */
    /* mem st32: base=(?) off=8 */
    /* mem ld8: base=(?) off=7 */
    /* mem st32: base=(?) off=4 */
    /* mem ld8: base=(?) off=6 */
    /* mem st32: base=(?) off=0 */
    /* mem ld8: base=(?) off=5 */
    /* mem ld8: base=(?) off=4 */
    /* ... +16 more memops */
    /* site +0x4d: wifi_log(1, 4, 4, lit:.rodata_wlog_debug.73, *(?+4)) */
    wifi_log(1, 4, 4, lit:.rodata_wlog_debug.73, *(?+4));
    /* site +0x86: indirect call via a7 (base *(g_osi_funcs_p+176)); args: *(?+0x338), 4, 4, lit:.rodata_wlog_debug.73, *(?+4) */
    opaque_indirect_a7();
    /* site +0x96: indirect call via a7 (base *(g_osi_funcs_p+176)); args: *(?+0x3b8), 4, 4, lit:.rodata_wlog_debug.73, *(?+4) */
    opaque_indirect_a7();
    /* site +0xa6: indirect call via a7 (base *(g_osi_funcs_p+176)); args: *(?+0x3bc), 4, 4, lit:.rodata_wlog_debug.73, *(?+4) */
    opaque_indirect_a7();
    /* site +0xb6: memset(?, 0, 0x3d0, lit:.rodata_wlog_debug.73, *(?+4)) */
    memset(?, 0, 0x3d0, lit:.rodata_wlog_debug.73, *(?+4));
    /* site +0xf2: memmove(0x3d2, 0x3d3, (0 slli 2), lit:.rodata_wlog_debug.73, *(?+4)) */
    memmove(0x3d2, 0x3d3, (0 slli 2), lit:.rodata_wlog_debug.73, *(?+4));
    return opaque_result; /* full dataflow not recovered */
}

/* cnx_bss_alloc @ wl_cnx.o 0x00000044 size 332B bind GLOBAL
 * Calls: hal_now, hal_now, cnx_cal_rc_util, cnx_get_authtype_strength, cnx_get_authtype_strength, cnx_remove_rc, cnx_get_authtype_strength, cnx_get_authtype_strength, memcmp, wifi_log | Data refs: g_cnxMgr+0x8, g_cnxMgr, g_wifi_nvs, .rodata_wlog_debug.66, g_cnxMgr+0xf00
 * Fidelity: low - 122 insns, 17 branches, 0 loops; skeleton only */
u32 cnx_bss_alloc(u32 a2, u32 a3, u32 a4)
{
    /* frame: entry a1,48; 122 insns, 17 cond-branches, 0 loops, 4 jumps */
    /* immediates: 0, 0x28b, 0x3d0, 147, 6, 4, 1 */
    /* first predicate: bnez.n a14, 99 <cnx_bss_alloc+0x55> (condition opaque) */
    /* mem st32: base=(?) off=4 */
    /* mem st32: base=(?) off=8 */
    /* mem st32: base=(?) off=12 */
    /* mem ld32: base=(lit:g_cnxMgr) off=0x2b0 */
    /* mem st32: base=(?) off=0 */
    /* mem ld32: base=(((0 slli 4) slli 4)) off=12 */
    /* mem ld32: base=(lit:g_cnxMgr+0x8) off=0x2a8 */
    /* mem ld16: base=(((0 slli 4) slli 4)) off=16 */
    /* mem ld32: base=(lit:g_cnxMgr+0xf00) off=96 */
    /* mem ld32: base=(lit:g_wifi_nvs) off=0 */
    /* ... +18 more memops */
    /* site +0x5a: hal_now(/* no traced args */) */
    hal_now(/* no traced args */);
    /* site +0x76: hal_now(ret@5a) */
    hal_now(ret@5a);
    /* site +0xbd: cnx_cal_rc_util(lit:g_cnxMgr+0x8, *(g_cnxMgr+0x8+0x2a8), ?, ?, *(((0 slli 4) slli 4)+12)) */
    cnx_cal_rc_util(lit:g_cnxMgr+0x8, *(g_cnxMgr+0x8+0x2a8), ?, ?, *(((0 slli 4) slli 4)+12));
    /* site +0xdb: cnx_get_authtype_strength(*(0x28b+0), *(g_cnxMgr+0x8+0x2a8), ?, ?, *(((0 slli 4) slli 4)+12)) */
    cnx_get_authtype_strength(*(0x28b+0), *(g_cnxMgr+0x8+0x2a8), ?, ?, *(((0 slli 4) slli 4)+12));
    /* site +0xea: cnx_get_authtype_strength(*((lit:g_cnxMgr+0x8+131072)+139), *(g_cnxMgr+0x8+0x2a8), ?, ?, *(((0 slli 4) slli 4)+12)) */
    cnx_get_authtype_strength(*((lit:g_cnxMgr+0x8+131072)+139), *(g_cnxMgr+0x8+0x2a8), ?, ?, *(((0 slli 4) slli 4)+12));
    /* site +0x11d: cnx_remove_rc(lit:g_cnxMgr+0x8, *(g_cnxMgr+0x8+0x2a8), ?, ?, *(((0 slli 4) slli 4)+12)) */
    cnx_remove_rc(lit:g_cnxMgr+0x8, *(g_cnxMgr+0x8+0x2a8), ?, ?, *(((0 slli 4) slli 4)+12));
    /* site +0x146: cnx_get_authtype_strength(*(?+12), *(g_cnxMgr+0x8+0x2a8), ?, ?, *(((0 slli 4) slli 4)+12)) */
    cnx_get_authtype_strength(*(?+12), *(g_cnxMgr+0x8+0x2a8), ?, ?, *(((0 slli 4) slli 4)+12));
    /* site +0x151: cnx_get_authtype_strength(*(g_cnxMgr+0xf00+139), *(g_cnxMgr+0x8+0x2a8), ?, ?, *(((0 slli 4) slli 4)+12)) */
    cnx_get_authtype_strength(*(g_cnxMgr+0xf00+139), *(g_cnxMgr+0x8+0x2a8), ?, ?, *(((0 slli 4) slli 4)+12));
    /* site +0x176: memcmp(147, *(?+4), 6, ?, *(((0 slli 4) slli 4)+12)) */
    memcmp(147, *(?+4), 6, ?, *(((0 slli 4) slli 4)+12));
    /* site +0x189: wifi_log(1, *(?+4), 4, lit:.rodata_wlog_debug.66, *(((0 slli 4) slli 4)+12)) */
    wifi_log(1, *(?+4), 4, lit:.rodata_wlog_debug.66, *(((0 slli 4) slli 4)+12));
    return 0;
}

/* cnx_remove_rc_except @ wl_cnx.o 0x00000018 size 156B bind GLOBAL
 * Calls: wifi_log, indirect(a5), memset | Data refs: .rodata_wlog_debug.74, .bss.s_csa_timer_bss, g_cnxMgr, g_osi_funcs_p
 * Fidelity: medium - branchy but loop-free, call sequence mapped */
u32 cnx_remove_rc_except(u32 a2)
{
    /* frame: entry a1,48; 59 insns, 5 cond-branches, 0 loops, 1 jumps */
    /* immediates: 4, 1, 0, 0x3d0 */
    /* first predicate: beqz.n a4, 56 <cnx_remove_rc_except+0x3e> (condition opaque) */
    /* mem ld8: base=(?) off=9 */
    /* mem st32: base=(?) off=12 */
    /* mem ld8: base=(?) off=8 */
    /* mem st32: base=(?) off=8 */
    /* mem ld8: base=(?) off=7 */
    /* mem st32: base=(?) off=4 */
    /* mem ld8: base=(?) off=6 */
    /* mem ld8: base=(?) off=5 */
    /* mem ld8: base=(?) off=4 */
    /* mem st32: base=(?) off=0 */
    /* ... +11 more memops */
    /* site +0x45: wifi_log(1, 4, 4, lit:.rodata_wlog_debug.74, *(?+4)) */
    wifi_log(1, 4, 4, lit:.rodata_wlog_debug.74, *(?+4));
    /* site +0x7d: indirect call via a5 (base *(g_osi_funcs_p+176)); args: *(*(0x3d0+8)+0x338), 4, 4, lit:.rodata_wlog_debug.74, *(?+4) */
    opaque_indirect_a5();
    /* site +0x8f: memset(*(g_osi_funcs_p+8), 0, 0x3d0, lit:.rodata_wlog_debug.74, *(?+4)) */
    memset(*(g_osi_funcs_p+8), 0, 0x3d0, lit:.rodata_wlog_debug.74, *(?+4));
    return opaque_result; /* full dataflow not recovered */
}

/* cnx_choose_rc @ wl_cnx.o 0x00000054 size 642B bind LOCAL
 * Calls: wifi_sta_get_prof_password, wifi_wpa2_is_started, wifi_wps_is_started, cnx_cal_rc_util, cnx_validate_owe_bss, memcmp, memcmp, cnx_get_authtype_strength, cnx_get_authtype_strength, wifi_log, scan_update_scan_history, scan_update_scan_history, cnx_remove_rc_except, cnx_clear_blacklist, wifi_log | Data refs: g_wifi_nvs, g_cnxMgr+0xf48, g_ic, g_cnxMgr, .rodata_wlog_debug.62, .rodata_wlog_verbose.63
 * Fidelity: low - 208 insns, 25 branches, 0 loops; skeleton only */
u32 cnx_choose_rc(u32 a4)
{
    /* frame: entry a1,64; 208 insns, 25 cond-branches, 0 loops, 9 jumps */
    /* immediates: 0, 1, 0xfffff880, 0xfffff881, -5, 147, 6, 4, 5 */
    /* first predicate: beqz.n a2, 6d <.text.cnx_choose_rc+0x6d> (condition opaque) */
    /* mem ld8: base=(ret@5a) off=0 */
    /* mem st32: base=(?) off=4 */
    /* mem st32: base=(?) off=4 */
    /* mem ld32: base=(lit:g_wifi_nvs) off=0 */
    /* mem ld8: base=((*(g_wifi_nvs+0)+196608)) off=93 */
    /* mem ld32: base=(?) off=4 */
    /* mem st32: base=(?) off=12 */
    /* mem st32: base=(?) off=16 */
    /* mem st32: base=(?) off=0 */
    /* mem st32: base=(?) off=8 */
    /* ... +43 more memops */
    /* site +0x5a: wifi_sta_get_prof_password(/* no traced args */) */
    wifi_sta_get_prof_password(/* no traced args */);
    /* site +0x70: wifi_wpa2_is_started(ret@5a) */
    wifi_wpa2_is_started(ret@5a);
    /* site +0x79: wifi_wps_is_started(ret@70) */
    wifi_wps_is_started(ret@70);
    /* site +0xc2: cnx_cal_rc_util(*(*(?+8)+0)) */
    cnx_cal_rc_util(*(*(?+8)+0));
    /* site +0xe3: cnx_validate_owe_bss(*(*(?+8)+0), *((*(*(?+8)+0)+196608)+196)) */
    cnx_validate_owe_bss(*(*(?+8)+0), *((*(*(?+8)+0)+196608)+196));
    /* site +0x12d: memcmp(*(g_wifi_nvs+0), (*(*(?+8)+0)+4), 6, 147, 1) */
    memcmp(*(g_wifi_nvs+0), (*(*(?+8)+0)+4), 6, 147, 1);
    /* site +0x14e: memcmp(*(g_wifi_nvs+0), (*(*(?+8)+0)+4), 6, 147, 147) */
    memcmp(*(g_wifi_nvs+0), (*(*(?+8)+0)+4), 6, 147, 147);
    /* site +0x167: cnx_get_authtype_strength(*(g_wifi_nvs+139), (*(*(?+8)+0)+4), 6, 147, 147) */
    cnx_get_authtype_strength(*(g_wifi_nvs+139), (*(*(?+8)+0)+4), 6, 147, 147);
    /* site +0x17a: cnx_get_authtype_strength(*(g_wifi_nvs+139), ret@167, 6, 147, 147) */
    cnx_get_authtype_strength(*(g_wifi_nvs+139), ret@167, 6, 147, 147);
    /* site +0x1c9: wifi_log(1, 4, 4, lit:g_wifi_nvs, 147) */
    wifi_log(1, 4, 4, lit:g_wifi_nvs, 147);
    /* site +0x215: scan_update_scan_history((*(g_wifi_nvs+0)+8), *(g_wifi_nvs+171), *(g_wifi_nvs+4), *((*(*(?+0)+0)+131072)+248), 147) */
    scan_update_scan_history((*(g_wifi_nvs+0)+8), *(g_wifi_nvs+171), *(g_wifi_nvs+4), *((*(*(?+0)+0)+131072)+248), 147);
    /* site +0x25a: scan_update_scan_history((ret@215+8), *(g_wifi_nvs+171), *(g_wifi_nvs+4), *((*(g_wifi_nvs+72)+131072)+248), 147) */
    scan_update_scan_history((ret@215+8), *(g_wifi_nvs+171), *(g_wifi_nvs+4), *((*(g_wifi_nvs+72)+131072)+248), 147);
    /* site +0x263: cnx_remove_rc_except(*(g_wifi_nvs+72), *(g_wifi_nvs+171), *(g_wifi_nvs+4), *((*(g_wifi_nvs+72)+131072)+248), 147) */
    cnx_remove_rc_except(*(g_wifi_nvs+72), *(g_wifi_nvs+171), *(g_wifi_nvs+4), *((*(g_wifi_nvs+72)+131072)+248), 147);
    /* site +0x269: cnx_clear_blacklist(ret@263, *(g_wifi_nvs+171), *(g_wifi_nvs+4), *((*(g_wifi_nvs+72)+131072)+248), 147) */
    cnx_clear_blacklist(ret@263, *(g_wifi_nvs+171), *(g_wifi_nvs+4), *((*(g_wifi_nvs+72)+131072)+248), 147);
    /* site +0x27b: wifi_log(1, 4, 5, lit:g_wifi_nvs, 147) */
    wifi_log(1, 4, 5, lit:g_wifi_nvs, 147);
    return (0+1);
}

/* cnx_do_handoff @ wl_cnx.o 0x000000b4 size 992B bind LOCAL
 * Calls: cnx_choose_rc, wifi_sta_get_prof_password, wifi_sta_get_prof_password, wifi_log, wifi_log, wifi_log, cnx_add_to_blacklist, cnx_remove_rc, wifi_log, cnx_choose_rc, indirect(a5), update_ic_params_using_bss_part_0, wifi_log, indirect(a2), memset, memcpy, wifi_log, wifi_event_post, pm_coex_set_reconnect_policy, wifi_log, wifi_log, wifi_log, indirect(a3), indirect(a3), pm_on_coex_schm_status_config, indirect(a10), pm_on_coex_schm_process_restart, pm_wake_done, cnx_add_to_blacklist, cnx_remove_rc, cnx_remove_all_rc, cnx_clear_blacklist | Data refs: g_ic, g_cnxMgr, .rodata_wlog_debug.36, .rodata_wlog_debug.37, .rodata_wlog_verbose.38, ap_no_lr, .rodata_wlog_debug.39, .rodata_wlog_debug.40, g_in_blacklist_flag, g_rssi_threshold_failure, g_authmode_threshold_failure, g_authmode_incompatible, g_wifi_nvs, .rodata_wlog_debug.35, .rodata_wlog_debug.41, .rodata_wlog_debug.42, .rodata_wlog_debug.43, g_osi_funcs_p
 * Fidelity: low - 294 insns, 18 branches, 0 loops; skeleton only */
u32 cnx_do_handoff(u32 a3, u32 a4)
{
    /* frame: entry a1,112; 294 insns, 18 cond-branches, 0 loops, 11 jumps */
    /* immediates: 16, 0, 1, 111, 110, 4, 5, 3, 205, 212 */
    /* first predicate: beqz a3, 258 <.text.cnx_do_handoff+0x258> (condition opaque) */
    /* mem ld32: base=(lit:g_ic) off=0 */
    /* mem st32: base=(lit:g_ic) off=0 */
    /* mem ld32: base=(lit:g_ic) off=16 */
    /* mem ld32: base=(lit:g_ic) off=116 */
    /* mem ld8: base=(ret@df) off=0 */
    /* mem ld8: base=((ret@ce+131072)) off=139 */
    /* mem ld8: base=(ret@fb) off=0 */
    /* mem ld8: base=((ret@ce+131072)) off=139 */
    /* mem ld8: base=((ret@ce+131072)) off=139 */
    /* mem ld8: base=(ret@ce) off=9 */
    /* ... +68 more memops */
    /* site +0xce: cnx_choose_rc(/* no traced args */) */
    cnx_choose_rc(/* no traced args */);
    /* site +0xdf: wifi_sta_get_prof_password(ret@ce) */
    wifi_sta_get_prof_password(ret@ce);
    /* site +0xfb: wifi_sta_get_prof_password(ret@df) */
    wifi_sta_get_prof_password(ret@df);
    /* site +0x155: wifi_log(1, 5, 4, lit:g_ic, *(ret@ce+4)) */
    wifi_log(1, 5, 4, lit:g_ic, *(ret@ce+4));
    /* site +0x1bd: wifi_log(ret@155, 4, 4, lit:g_ic, *(g_ic+84)) */
    wifi_log(ret@155, 4, 4, lit:g_ic, *(g_ic+84));
    /* site +0x1fe: wifi_log(1, 4, 5, lit:g_ic, *(ret@ce+4)) */
    wifi_log(1, 4, 5, lit:g_ic, *(ret@ce+4));
    /* site +0x222: cnx_add_to_blacklist(ret@1fe, 4, 5, lit:g_ic, *(ret@ce+4)) */
    cnx_add_to_blacklist(ret@1fe, 4, 5, lit:g_ic, *(ret@ce+4));
    /* site +0x22a: cnx_remove_rc(ret@ce, 4, 5, lit:g_ic, *(ret@ce+4)) */
    cnx_remove_rc(ret@ce, 4, 5, lit:g_ic, *(ret@ce+4));
    /* site +0x239: wifi_log(1, 4, 4, lit:g_ic, *(ret@ce+4)) */
    wifi_log(1, 4, 4, lit:g_ic, *(ret@ce+4));
    /* site +0x23f: cnx_choose_rc(ret@239, 4, 4, lit:g_ic, *(ret@ce+4)) */
    cnx_choose_rc(ret@239, 4, 4, lit:g_ic, *(ret@ce+4));
    /* site +0x24d: indirect call via a5 (base *(g_ic+8)); args: (ret@ce+4), 4, 4, lit:g_ic, *(ret@ce+4) */
    opaque_indirect_a5();
    /* site +0x262: update_ic_params_using_bss_part_0(ret@24d, 4, 4, lit:g_ic, *(ret@ce+4)) */
    update_ic_params_using_bss_part_0(ret@24d, 4, 4, lit:g_ic, *(ret@ce+4));
    /* site +0x27b: wifi_log(1, 4, 4, lit:g_ic, *(g_ic+84)) */
    wifi_log(1, 4, 4, lit:g_ic, *(g_ic+84));
    /* site +0x2cb: indirect call via a2 (base *(g_ic+16)); args: 210, 4, 4, lit:g_ic, *(g_ic+84) */
    opaque_indirect_a2();
    /* site +0x2e6: memset((?+65), 0, 6, lit:g_ic, *(g_ic+84)) */
    memset((?+65), 0, 6, lit:g_ic, *(g_ic+84));
    /* site +0x2f2: memcpy(ret@2e6, (*(g_ic+0)+8), 32, lit:g_ic, *(g_ic+84)) */
    memcpy(ret@2e6, (*(g_ic+0)+8), 32, lit:g_ic, *(g_ic+84));
    /* site +0x312: wifi_log(1, 5, 4, lit:g_ic, 210) */
    wifi_log(1, 5, 4, lit:g_ic, 210);
    /* site +0x321: wifi_event_post(5, (?+32), 41, lit:g_ic, 210) */
    wifi_event_post(5, (?+32), 41, lit:g_ic, 210);
    /* site +0x327: pm_coex_set_reconnect_policy(ret@321, (?+32), 41, lit:g_ic, 210) */
    pm_coex_set_reconnect_policy(ret@321, (?+32), 41, lit:g_ic, 210);
    /* site +0x341: wifi_log(1, 5, 4, lit:g_ic, 210) */
    wifi_log(1, 5, 4, lit:g_ic, 210);
    /* site +0x357: wifi_log(1, 5, 4, lit:g_ic, 210) */
    wifi_log(1, 5, 4, lit:g_ic, 210);
    /* site +0x366: wifi_log(1, 4, 4, lit:g_ic, 210) */
    wifi_log(1, 4, 4, lit:g_ic, 210);
    /* site +0x375: indirect call via a3 (base *(g_ic+236)); args: (*(g_ic+16)+4), 4, 4, lit:g_ic, 210 */
    opaque_indirect_a3();
    /* site +0x37f: indirect call via a3 (base *(g_ic+240)); args: (*(g_ic+16)+4), 4, 4, lit:g_ic, 210 */
    opaque_indirect_a3();
    /* site +0x387: pm_on_coex_schm_status_config(0, 4, 4, lit:g_ic, 210) */
    pm_on_coex_schm_status_config(0, 4, 4, lit:g_ic, 210);
    /* site +0x38f: indirect call via a10 (base *(g_ic+0x194)); args: *(g_ic+0x194), 4, 4, lit:g_ic, 210 */
    opaque_indirect_a10();
    /* site +0x397: pm_on_coex_schm_process_restart(ret@38f, 4, 4, lit:g_ic, 210) */
    pm_on_coex_schm_process_restart(ret@38f, 4, 4, lit:g_ic, 210);
    /* site +0x39d: pm_wake_done(ret@397, 4, 4, lit:g_ic, 210) */
    pm_wake_done(ret@397, 4, 4, lit:g_ic, 210);
    /* site +0x3b1: cnx_add_to_blacklist((*(g_ic+0)+4), 4, 4, lit:g_ic, 210) */
    cnx_add_to_blacklist((*(g_ic+0)+4), 4, 4, lit:g_ic, 210);
    /* site +0x3b9: cnx_remove_rc(*(g_ic+0), 4, 4, lit:g_ic, 210) */
    cnx_remove_rc(*(g_ic+0), 4, 4, lit:g_ic, 210);
    /* site +0x3c4: cnx_remove_all_rc(ret@3b9, 4, 4, lit:g_ic, 210) */
    cnx_remove_all_rc(ret@3b9, 4, 4, lit:g_ic, 210);
    /* site +0x3cd: cnx_clear_blacklist(ret@3c4, 4, 4, lit:g_ic, 210) */
    cnx_clear_blacklist(ret@3c4, 4, 4, lit:g_ic, 210);
    return 0;
}

/* cnx_connect_next_ap_timeout_process @ wl_cnx.o 0x0000000c size 28B bind GLOBAL
 * Calls: wifi_log, cnx_do_handoff | Data refs: .rodata_wlog_debug.28
 * Fidelity: high - straight-line, fully mapped (10 insns) */
u32 cnx_connect_next_ap_timeout_process(void)
{
    /* frame: entry a1,32; 10 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* immediates: 4, 1 */
    /* site +0x1d: wifi_log(1, ?, 4, lit:.rodata_wlog_debug.28) */
    wifi_log(1, ?, 4, lit:.rodata_wlog_debug.28);
    /* site +0x23: cnx_do_handoff(ret@1d, ?, 4, lit:.rodata_wlog_debug.28) */
    cnx_do_handoff(ret@1d, ?, 4, lit:.rodata_wlog_debug.28);
    return opaque_result; /* full dataflow not recovered */
}

/* cnx_start_handoff_cb @ wl_cnx.o 0x00000024 size 98B bind GLOBAL
 * Calls: wifi_log, cnx_do_handoff, pm_wake_done, pm_wake_done, wifi_log, wifi_event_post | Data refs: .rodata_wlog_debug.33, g_ic, .rodata_wlog_debug.34
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 cnx_start_handoff_cb(u32 a3)
{
    /* frame: entry a1,80; 37 insns, 3 cond-branches, 0 loops, 1 jumps */
    /* immediates: 4, 1, 106, 41, 5 */
    /* first predicate: bnez.n a3, 4c <cnx_start_handoff_cb+0x28> (condition opaque) */
    /* mem ld32: base=(lit:g_ic) off=116 */
    /* mem st8: base=(?) off=39 */
    /* site +0x35: wifi_log(1, 4, 4, lit:.rodata_wlog_debug.33) */
    wifi_log(1, 4, 4, lit:.rodata_wlog_debug.33);
    /* site +0x3d: cnx_do_handoff(ret@35, 4, 4, lit:.rodata_wlog_debug.33) */
    cnx_do_handoff(ret@35, 4, 4, lit:.rodata_wlog_debug.33);
    /* site +0x46: pm_wake_done(ret@3d, 4, 4, lit:.rodata_wlog_debug.33) */
    pm_wake_done(ret@3d, 4, 4, lit:.rodata_wlog_debug.33);
    /* site +0x4f: pm_wake_done(ret@46, 4, 4, lit:.rodata_wlog_debug.33) */
    pm_wake_done(ret@46, 4, 4, lit:.rodata_wlog_debug.33);
    /* site +0x75: wifi_log(1, 4, 4, lit:.rodata_wlog_debug.34, 106) */
    wifi_log(1, 4, 4, lit:.rodata_wlog_debug.34, 106);
    /* site +0x81: wifi_event_post(5, ?, 41, lit:.rodata_wlog_debug.34, 106) */
    wifi_event_post(5, ?, 41, lit:.rodata_wlog_debug.34, 106);
    return opaque_result; /* full dataflow not recovered */
}

/* cnx_sta_connect_cmd @ wl_cnx.o 0x00000098 size 622B bind GLOBAL
 * Calls: wifi_log, cnx_choose_rc, memcmp, cnx_start_connect_without_scan, cnx_do_handoff, cnx_remove_rc, scan_remove_probe_ssid, indirect(a9), indirect(a9), indirect(a9), indirect(a2), scan_remove_bssid, scan_set_desChan, scan_add_probe_ssid, ieee80211_regdomain_chan_in_range, scan_prefer_chan, ieee80211_regdomain_chan_in_range, ieee80211_regdomain_min_chan, scan_build_chan_list, wifi_log, scan_cancel, scan_set_pas_duration, scan_set_act_duration, cnx_remove_all_rc, scan_start | Data refs: g_wifi_nvs, g_ic, .rodata_wlog_debug.4, g_mesh_is_root, g_mesh_self_organized, gScanStruct, g_cnxMgr, g_in_blacklist_flag, g_authmode_incompatible, g_authmode_threshold_failure, g_rssi_threshold_failure, sta_con_timer, g_osi_funcs_p, cnx_sta_connect_led_timer_cb, .rodata_wlog_debug.27, cnx_start_handoff_cb
 * Fidelity: low - 227 insns, 20 branches, 0 loops; skeleton only */
u32 cnx_sta_connect_cmd(u32 a2, u32 a4, u32 a5)
{
    /* frame: entry a1,48; 227 insns, 20 cond-branches, 0 loops, 5 jumps */
    /* immediates: 0, 4, 5, 1, 147, 6, 50, 0x50f, 33, 3 */
    /* first predicate: beqz a2, 151 <cnx_sta_connect_cmd+0xb9> (condition opaque) */
    /* mem st8: base=((lit:g_ic+196608)) off=1 */
    /* mem st8: base=((lit:g_ic+196608)) off=2 */
    /* mem ld32: base=(lit:g_wifi_nvs) off=0 */
    /* mem ld32: base=(lit:g_ic) off=116 */
    /* mem ld8: base=(lit:g_mesh_is_root) off=0 */
    /* mem ld8: base=(lit:g_mesh_self_organized) off=0 */
    /* mem ld8: base=(lit:gScanStruct) off=70 */
    /* mem ld32: base=(*(g_wifi_nvs+0)) off=4 */
    /* mem ld32: base=(lit:g_wifi_nvs) off=0 */
    /* mem ld8: base=(*(g_wifi_nvs+0)) off=146 */
    /* ... +39 more memops */
    /* site +0xc5: wifi_log(1, 5, 4, lit:.rodata_wlog_debug.4) */
    wifi_log(1, 5, 4, lit:.rodata_wlog_debug.4);
    /* site +0x103: cnx_choose_rc(ret@c5, 5, 4, lit:.rodata_wlog_debug.4) */
    cnx_choose_rc(ret@c5, 5, 4, lit:.rodata_wlog_debug.4);
    /* site +0x11e: memcmp(147, (ret@103+4), 6, lit:.rodata_wlog_debug.4) */
    memcmp(147, (ret@103+4), 6, lit:.rodata_wlog_debug.4);
    /* site +0x12f: cnx_start_connect_without_scan(ret@11e, (ret@103+4), 6, lit:.rodata_wlog_debug.4) */
    cnx_start_connect_without_scan(ret@11e, (ret@103+4), 6, lit:.rodata_wlog_debug.4);
    /* site +0x135: cnx_do_handoff(ret@12f, (ret@103+4), 6, lit:.rodata_wlog_debug.4) */
    cnx_do_handoff(ret@12f, (ret@103+4), 6, lit:.rodata_wlog_debug.4);
    /* site +0x142: cnx_remove_rc(ret@135, (ret@103+4), 6, lit:.rodata_wlog_debug.4) */
    cnx_remove_rc(ret@135, (ret@103+4), 6, lit:.rodata_wlog_debug.4);
    /* site +0x159: scan_remove_probe_ssid(1, (ret@103+4), 6, lit:.rodata_wlog_debug.4) */
    scan_remove_probe_ssid(1, (ret@103+4), 6, lit:.rodata_wlog_debug.4);
    /* site +0x1a5: indirect call via a9 (base *(*(g_osi_funcs_p+0)+236)); args: lit:sta_con_timer, (ret@103+4), 6, lit:.rodata_wlog_debug.4 */
    opaque_indirect_a9();
    /* site +0x1af: indirect call via a9 (base *(*(g_osi_funcs_p+0)+240)); args: lit:sta_con_timer, (ret@103+4), 6, lit:.rodata_wlog_debug.4 */
    opaque_indirect_a9();
    /* site +0x1be: indirect call via a9 (base *(*(g_osi_funcs_p+0)+244)); args: lit:sta_con_timer, lit:cnx_sta_connect_led_timer_cb, 0, lit:.rodata_wlog_debug.4 */
    opaque_indirect_a9();
    /* site +0x1ce: indirect call via a2 (base *(g_osi_funcs_p+232)); args: lit:sta_con_timer, 50, *(?+0), lit:.rodata_wlog_debug.4 */
    opaque_indirect_a2();
    /* site +0x1d4: scan_remove_bssid(ret@1ce, 50, *(?+0), lit:.rodata_wlog_debug.4) */
    scan_remove_bssid(ret@1ce, 50, *(?+0), lit:.rodata_wlog_debug.4);
    /* site +0x1e6: scan_set_desChan(ret@1d4, 50, *(?+0), lit:.rodata_wlog_debug.4) */
    scan_set_desChan(ret@1d4, 50, *(?+0), lit:.rodata_wlog_debug.4);
    /* site +0x20d: scan_add_probe_ssid(*(g_cnxMgr+4), (*(g_wifi_nvs+0)+8), *(*(g_wifi_nvs+0)+4), 1) */
    scan_add_probe_ssid(*(g_cnxMgr+4), (*(g_wifi_nvs+0)+8), *(*(g_wifi_nvs+0)+4), 1);
    /* site +0x21b: ieee80211_regdomain_chan_in_range(*(*(g_wifi_nvs+0)+144), (*(g_wifi_nvs+0)+8), *(*(g_wifi_nvs+0)+4), 1) */
    ieee80211_regdomain_chan_in_range(*(*(g_wifi_nvs+0)+144), (*(g_wifi_nvs+0)+8), *(*(g_wifi_nvs+0)+4), 1);
    /* site +0x22f: scan_prefer_chan(*(g_osi_funcs_p+144), (*(g_wifi_nvs+0)+8), *(*(g_wifi_nvs+0)+4), 1) */
    scan_prefer_chan(*(g_osi_funcs_p+144), (*(g_wifi_nvs+0)+8), *(*(g_wifi_nvs+0)+4), 1);
    /* site +0x239: ieee80211_regdomain_chan_in_range(ret@22f, (*(g_wifi_nvs+0)+8), *(*(g_wifi_nvs+0)+4), 1) */
    ieee80211_regdomain_chan_in_range(ret@22f, (*(g_wifi_nvs+0)+8), *(*(g_wifi_nvs+0)+4), 1);
    /* site +0x24f: ieee80211_regdomain_min_chan(1, (*(g_wifi_nvs+0)+8), *(*(g_wifi_nvs+0)+4), 1) */
    ieee80211_regdomain_min_chan(1, (*(g_wifi_nvs+0)+8), *(*(g_wifi_nvs+0)+4), 1);
    /* site +0x25f: scan_build_chan_list((1 slli 17), ret@22f, *(*(g_wifi_nvs+0)+4), 1) */
    scan_build_chan_list((1 slli 17), ret@22f, *(*(g_wifi_nvs+0)+4), 1);
    /* site +0x27a: wifi_log(1, 4, 4, lit:.rodata_wlog_debug.27, *(g_osi_funcs_p+84)) */
    wifi_log(1, 4, 4, lit:.rodata_wlog_debug.27, *(g_osi_funcs_p+84));
    /* site +0x2a5: scan_cancel(ret@27a, 4, 4, lit:.rodata_wlog_debug.27, *(g_osi_funcs_p+84)) */
    scan_cancel(ret@27a, 4, 4, lit:.rodata_wlog_debug.27, *(g_osi_funcs_p+84));
    /* site +0x2d9: scan_set_pas_duration(0x5dc, 4, 4, lit:.rodata_wlog_debug.27, *(g_osi_funcs_p+84)) */
    scan_set_pas_duration(0x5dc, 4, 4, lit:.rodata_wlog_debug.27, *(g_osi_funcs_p+84));
    /* site +0x2ea: scan_set_act_duration(0, 120, 4, lit:.rodata_wlog_debug.27, *(g_osi_funcs_p+84)) */
    scan_set_act_duration(0, 120, 4, lit:.rodata_wlog_debug.27, *(g_osi_funcs_p+84));
    /* site +0x2f0: cnx_remove_all_rc(ret@2ea, 120, 4, lit:.rodata_wlog_debug.27, *(g_osi_funcs_p+84)) */
    cnx_remove_all_rc(ret@2ea, 120, 4, lit:.rodata_wlog_debug.27, *(g_osi_funcs_p+84));
    /* site +0x2ff: scan_start((33 slli 10), 2, lit:cnx_start_handoff_cb, 0, *(g_osi_funcs_p+84)) */
    scan_start((33 slli 10), 2, lit:cnx_start_handoff_cb, 0, *(g_osi_funcs_p+84));
    return 0;
}

/* cnx_rc_update_rssi @ wl_cnx.o 0x00000004 size 116B bind GLOBAL
 * Calls: none | Data refs: g_ic
 * Fidelity: medium - branchy but loop-free, call sequence mapped */
u32 cnx_rc_update_rssi(u32 a2, u32 a3, u32 a4)
{
    /* frame: entry a1,32; 41 insns, 4 cond-branches, 0 loops, 2 jumps */
    /* first predicate: beqz.n a4, 34 <cnx_rc_update_rssi+0x30> (condition opaque) */
    /* mem st8: base=(?) off=166 */
    /* mem ld8: base=(?) off=164 */
    /* mem ld8: base=(?) off=165 */
    /* mem st8: base=(?) off=165 */
    /* mem st8: base=(?) off=164 */
    /* mem st8: base=(lit:g_ic) off=253 */
    return opaque_result; /* full dataflow not recovered */
}

/* cnx_rc_update_state_metric @ wl_cnx.o 0x00000008 size 103B bind GLOBAL
 * Calls: cnx_remove_rc | Data refs: g_cnxMgr
 * Fidelity: medium - branchy but loop-free, call sequence mapped */
u32 cnx_rc_update_state_metric(u32 a2, u32 a3, u32 a4)
{
    /* frame: entry a1,32; 38 insns, 6 cond-branches, 0 loops, 2 jumps */
    /* immediates: 0, 10, 15, 1 */
    /* first predicate: bnei a4, 1, 18 <cnx_rc_update_state_metric+0x10> (condition opaque) */
    /* mem ld8: base=(?) off=167 */
    /* mem st8: base=(?) off=167 */
    /* mem ld8: base=(?) off=167 */
    /* mem st8: base=(?) off=167 */
    /* mem ld32: base=((lit:g_cnxMgr+983040)) off=96 */
    /* mem ld8: base=(?) off=167 */
    /* mem st8: base=(?) off=167 */
    /* site +0x6a: cnx_remove_rc(?, 0, *(g_cnxMgr+96)) */
    cnx_remove_rc(?, 0, *(g_cnxMgr+96));
    return opaque_result; /* full dataflow not recovered */
}

/* cnx_probe_rc_tx_cb @ wl_cnx.o 0x00000014 size 110B bind LOCAL
 * Calls: cnx_rc_search, cnx_rc_update_state_metric, cnx_get_next_rc, cnx_probe_rc, cnx_traverse_rc_lis_done | Data refs: none
 * Fidelity: medium - branchy but loop-free, call sequence mapped */
u32 cnx_probe_rc_tx_cb(u32 a2)
{
    /* frame: entry a1,32; 33 insns, 4 cond-branches, 0 loops, 2 jumps */
    /* immediates: 5, 1, -3, 0 */
    /* first predicate: bbci a2, 18, 24 <.text.cnx_probe_rc_tx_cb+0x24> (condition opaque) */
    /* mem ld32: base=(?) off=44 */
    /* mem ld32: base=(?) off=4 */
    /* mem ld32: base=(*(?+4)) off=4 */
    /* mem ld32: base=(*(?+44)) off=0 */
    /* mem ld8: base=(*(?+44)) off=19 */
    /* mem st8: base=(ret@2a) off=169 */
    /* site +0x2a: cnx_rc_search(((*(*(?+4)+4)+4)+16)) */
    cnx_rc_search(((*(*(?+4)+4)+4)+16));
    /* site +0x4d: cnx_rc_update_state_metric(ret@2a, -3, 1) */
    cnx_rc_update_state_metric(ret@2a, -3, 1);
    /* site +0x53: cnx_get_next_rc(ret@4d, -3, 1) */
    cnx_get_next_rc(ret@4d, -3, 1);
    /* site +0x5d: cnx_probe_rc(ret@53, 0, 1) */
    cnx_probe_rc(ret@53, 0, 1);
    /* site +0x69: cnx_traverse_rc_lis_done(ret@5d, ret@5d, 1) */
    cnx_traverse_rc_lis_done(ret@5d, ret@5d, 1);
    return opaque_result; /* full dataflow not recovered */
}

/* cnx_rc_update_age @ wl_cnx.o 0x00000000 size 27B bind GLOBAL
 * Calls: none | Data refs: none
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 cnx_rc_update_age(u32 a2, u32 a3, u32 a4)
{
    /* frame: entry a1,32; 10 insns, 2 cond-branches, 0 loops, 1 jumps */
    /* first predicate: bnez.n a4, 8 <cnx_rc_update_age+0x8> (condition opaque) */
    /* mem ld8: base=(?) off=169 */
    /* mem st8: base=(?) off=169 */
    return opaque_result; /* full dataflow not recovered */
}

/* cnx_update_bss @ wl_cnx.o 0x00000008 size 34B bind GLOBAL
 * Calls: memcpy, ieee80211_setup_rateset | Data refs: none
 * Fidelity: high - straight-line, fully mapped (13 insns) */
u32 cnx_update_bss(u32 a2, u32 a3, u32 a4)
{
    /* frame: entry a1,32; 13 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* immediates: 6, 15 */
    /* mem ld32: base=(?) off=44 */
    /* mem ld32: base=(?) off=40 */
    /* site +0x16: memcpy((?+4), (?+16), 6) */
    memcpy((?+4), (?+16), 6);
    /* site +0x25: ieee80211_setup_rateset((?+115), *(?+40), *(?+44), 15) */
    ieee80211_setup_rateset((?+115), *(?+40), *(?+44), 15);
    return opaque_result; /* full dataflow not recovered */
}

/* esp_mesh_get_tsf_time @ wl_cnx.o 0x00000004 size 18B bind GLOBAL
 * Calls: hal_get_tsf_time | Data refs: none
 * Fidelity: high - straight-line, fully mapped (7 insns) */
u32 esp_mesh_get_tsf_time(void)
{
    /* frame: entry a1,32; 7 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0 */
    /* site +0xd: hal_get_tsf_time(0) */
    hal_get_tsf_time(0);
    return last_call_result; /* opaque */
}

/* ieee80211_max_bandwidth_negotiation_process @ wl_cnx.o 0x00000014 size 470B bind GLOBAL
 * Calls: ieee80211_is_40mhz_valid_bw | Data refs: g_ic, g_wifi_nvs, g_ic+0x200
 * Fidelity: low - 165 insns, 31 branches, 0 loops; skeleton only */
u32 ieee80211_max_bandwidth_negotiation_process(u32 a2, u32 a5, u32 a6)
{
    /* frame: entry a1,32; 165 insns, 31 cond-branches, 0 loops, 26 jumps */
    /* immediates: 14, 1, 0, 2, 9 */
    /* first predicate: beq a4, a3, 24 <ieee80211_max_bandwidth_negotiation_process+0x10> (condition opaque) */
    /* mem ld32: base=(?) off=0 */
    /* mem ld32: base=(lit:g_ic) off=16 */
    /* mem ld32: base=(lit:g_wifi_nvs) off=0 */
    /* mem ld8: base=(?) off=171 */
    /* mem ld8: base=((*(g_wifi_nvs+0)+262144)) off=170 */
    /* mem ld8: base=(*((*(g_wifi_nvs+0)+262144)+170)) off=169 */
    /* mem ld32: base=(*(?+0)) off=0x158 */
    /* mem ld32: base=(*(?+0)) off=0x158 */
    /* mem st32: base=(*(?+0)) off=0x158 */
    /* mem ld32: base=(lit:g_ic) off=16 */
    /* ... +33 more memops */
    /* site +0x61: ieee80211_is_40mhz_valid_bw(*(?+171), 14) */
    ieee80211_is_40mhz_valid_bw(*(?+171), 14);
    return opaque_result; /* full dataflow not recovered */
}

/* send_ap_probe @ wl_cnx.o 0x00000020 size 158B bind GLOBAL
 * Calls: wifi_get_macaddr, pm_send_probe_start, ieee80211_send_probereq, pm_send_probe_stop, indirect(a4), indirect(a2) | Data refs: g_ic, g_wifi_nvs, ieee80211_ethbroadcast, g_osi_funcs_p
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 send_ap_probe(u32 a2, u32 a4)
{
    /* frame: entry a1,64; 59 insns, 3 cond-branches, 0 loops, 2 jumps */
    /* immediates: 0, 5, 0x1f4 */
    /* first predicate: bnez.n a3, 50 <send_ap_probe+0x30> (condition opaque) */
    /* mem ld32: base=(lit:g_ic) off=16 */
    /* mem ld32: base=(*(g_ic+16)) off=228 */
    /* mem ld32: base=(lit:g_wifi_nvs) off=0 */
    /* mem ld32: base=(lit:g_ic) off=16 */
    /* mem st8: base=(*(g_ic+16)) off=148 */
    /* mem ld32: base=(lit:g_ic) off=16 */
    /* mem ld8: base=(*(g_ic+16)) off=148 */
    /* mem ld32: base=(5) off=4 */
    /* mem st32: base=(?) off=4 */
    /* mem st32: base=(?) off=0 */
    /* ... +8 more memops */
    /* site +0x39: wifi_get_macaddr(0, (?+16)) */
    wifi_get_macaddr(0, (?+16));
    /* site +0x53: pm_send_probe_start(ret@39, (?+16)) */
    pm_send_probe_start(ret@39, (?+16));
    /* site +0x7d: ieee80211_send_probereq(*(g_ic+16), (?+16), (*(g_ic+16)+4), (*(g_ic+16)+4), (5+8)) */
    ieee80211_send_probereq(*(g_ic+16), (?+16), (*(g_ic+16)+4), (*(g_ic+16)+4), (5+8));
    /* site +0x85: pm_send_probe_stop(ret@7d, (?+16), (*(g_ic+16)+4), (*(g_ic+16)+4), (5+8)) */
    pm_send_probe_stop(ret@7d, (?+16), (*(g_ic+16)+4), (*(g_ic+16)+4), (5+8));
    /* site +0xa7: indirect call via a4 (base *(g_wifi_nvs+236)); args: (*(g_ic+16)+24), (?+16), (*(g_ic+16)+4), (*(g_ic+16)+4), (5+8) */
    opaque_indirect_a4();
    /* site +0xb9: indirect call via a2 (base *(g_ic+232)); args: (*(g_ic+16)+24), 0x1f4, 0, (*(g_ic+16)+4), (5+8) */
    opaque_indirect_a2();
    return opaque_result; /* full dataflow not recovered */
}

/* mgd_probe_send_timeout_process @ wl_cnx.o 0x00000038 size 274B bind GLOBAL
 * Calls: indirect(a8), indirect(a8), indirect(a8), indirect(a2), indirect(a8), indirect(a2), send_ap_probe, indirect(a8), indirect(a3), pm_send_probe_stop, wifi_log, ieee80211_sta_new_state, wifi_log, wifi_log | Data refs: g_ic, g_osi_funcs_p, .text.cnx_beacon_timeout, .text.mgd_probe_send_timeout, .rodata_wlog_info.81, gScanStruct, .rodata_wlog_debug.82, .rodata_wlog_debug.83
 * Fidelity: low - 102 insns, 3 branches, 0 loops; skeleton only */
u32 mgd_probe_send_timeout_process(u32 a2, u32 a3)
{
    /* frame: entry a1,32; 102 insns, 3 cond-branches, 0 loops, 3 jumps */
    /* immediates: 0, 3, 4, 1, 25 */
    /* first predicate: bnez a4, 99 <mgd_probe_send_timeout_process+0x61> (condition opaque) */
    /* mem ld32: base=(lit:g_ic) off=16 */
    /* mem ld8: base=((*(g_ic+16)+24)) off=124 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=236 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(lit:g_ic) off=16 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=240 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(lit:g_ic) off=16 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=244 */
    /* ... +18 more memops */
    /* site +0x52: indirect call via a8 (base *(*(g_osi_funcs_p+0)+236)); args: (*(g_ic+16)+24) */
    opaque_indirect_a8();
    /* site +0x5f: indirect call via a8 (base *(*(g_osi_funcs_p+0)+240)); args: (*(g_ic+16)+24) */
    opaque_indirect_a8();
    /* site +0x71: indirect call via a8 (base *(*(g_osi_funcs_p+0)+244)); args: (*(g_ic+16)+24), lit:.text.cnx_beacon_timeout, *((*(g_ic+16)+24)+124) */
    opaque_indirect_a8();
    /* site +0x92: indirect call via a2 (base *(g_ic+232)); args: (*(g_ic+16)+24), ((*(g_ic+58) slli 5) slli 2), *((*(g_ic+16)+24)+124) */
    opaque_indirect_a2();
    /* site +0x9f: indirect call via a8 (base *(*(*(g_osi_funcs_p+0)+244)+240)); args: ret@92, ((*(g_ic+58) slli 5) slli 2), *((*(g_ic+16)+24)+124) */
    opaque_indirect_a8();
    /* site +0xb1: indirect call via a2 (base *(g_ic+244)); args: (*(g_ic+16)+24), lit:.text.mgd_probe_send_timeout, 0 */
    opaque_indirect_a2();
    /* site +0xb7: send_ap_probe(ret@b1, lit:.text.mgd_probe_send_timeout, 0) */
    send_ap_probe(ret@b1, lit:.text.mgd_probe_send_timeout, 0);
    /* site +0xbd: indirect call via a8 (base &send_ap_probe()); args: ret@b7, lit:.text.mgd_probe_send_timeout, 0 */
    opaque_indirect_a8();
    /* site +0xd1: indirect call via a3 (base *(g_osi_funcs_p+244)); args: (*(g_ic+16)+24), lit:.text.cnx_beacon_timeout, 0 */
    opaque_indirect_a3();
    /* site +0xd7: pm_send_probe_stop(ret@d1, lit:.text.cnx_beacon_timeout, 0) */
    pm_send_probe_stop(ret@d1, lit:.text.cnx_beacon_timeout, 0);
    /* site +0xe6: wifi_log(1, 4, 3, lit:.rodata_wlog_info.81) */
    wifi_log(1, 4, 3, lit:.rodata_wlog_info.81);
    /* site +0xf5: ieee80211_sta_new_state(*(g_ic+244), 0, (25 slli 11), lit:.rodata_wlog_info.81) */
    ieee80211_sta_new_state(*(g_ic+244), 0, (25 slli 11), lit:.rodata_wlog_info.81);
    /* site +0x11b: wifi_log(1, 4, 4, lit:.rodata_wlog_debug.82, *((*(g_ic+16)+65536)+84)) */
    wifi_log(1, 4, 4, lit:.rodata_wlog_debug.82, *((*(g_ic+16)+65536)+84));
    /* site +0x137: wifi_log(1, 4, 4, lit:.rodata_wlog_debug.83, *(&wifi_log()+84)) */
    wifi_log(1, 4, 4, lit:.rodata_wlog_debug.83, *(&wifi_log()+84));
    return opaque_result; /* full dataflow not recovered */
}

/* cnx_node_alloc @ wl_cnx.o 0x00000018 size 211B bind GLOBAL
 * Calls: indirect(a8), cnx_bss_init, ic_del_key, indirect(a11), memcpy | Data refs: g_ic, g_wifi_nvs, g_osi_funcs_p
 * Fidelity: low - 76 insns, 4 branches, 0 loops; skeleton only */
u32 cnx_node_alloc(u32 a2, u32 a3, u32 a6)
{
    /* frame: entry a1,48; 76 insns, 4 cond-branches, 0 loops, 5 jumps */
    /* immediates: 1, 0x3d0, 0, 6 */
    /* first predicate: bnez a5, d9 <cnx_node_alloc+0xc1> (condition opaque) */
    /* mem ld32: base=(lit:g_ic) off=20 */
    /* mem ld32: base=(lit:g_wifi_nvs) off=0 */
    /* mem ld8: base=((*(g_wifi_nvs+0)+196608)) off=246 */
    /* mem ld32: base=(?) off=236 */
    /* mem st32: base=(?) off=0 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=0x178 */
    /* mem st32: base=(?) off=236 */
    /* mem st8: base=((0+65536)) off=52 */
    /* mem ld32: base=(*(g_ic+20)) off=0x140 */
    /* ... +11 more memops */
    /* site +0x49: indirect call via a8 (base *(*(g_osi_funcs_p+0)+0x178)); args: 0x3d0 */
    opaque_indirect_a8();
    /* site +0x62: cnx_bss_init(ret@49, *(g_ic+20)) */
    cnx_bss_init(ret@49, *(g_ic+20));
    /* site +0x86: ic_del_key((1+7), *(*(g_ic+20)+0x140)) */
    ic_del_key((1+7), *(*(g_ic+20)+0x140));
    /* site +0x9d: indirect call via a11 (base *(*(g_osi_funcs_p+0)+176)); args: *(*(g_osi_funcs_p+52)+0x140), *(*(g_osi_funcs_p+0)+176) */
    opaque_indirect_a11();
    /* site +0xc5: memcpy((*(?+236)+4), ?, 6) */
    memcpy((*(?+236)+4), ?, 6);
    return 0;
}

/* cnx_node_remove @ wl_cnx.o 0x00000030 size 389B bind GLOBAL
 * Calls: indirect(a6), ic_del_key, indirect(a11), ieee80211_pwrsave_node_cleanup, ieee80211_ht_node_cleanup, chm_get_current_band, ieee80211_set_phy_bw, ieee80211_update_channel, hostap_ht_operation_update, indirect(a5), indirect(a2), indirect(a2) | Data refs: g_ic, g_wifi_nvs, g_osi_funcs_p, g_wifi_global_lock
 * Fidelity: low - 123 insns, 10 branches, 0 loops; skeleton only (weak) */
u32 cnx_node_remove(u32 a2, u32 a4, u32 a5, u32 a7)
{
    /* frame: entry a1,48; 123 insns, 10 cond-branches, 0 loops, 5 jumps */
    /* immediates: 1, 0, 64, 2, 0x156, -2 */
    /* first predicate: beq a8, a2, 55 <cnx_node_remove+0x25> (condition opaque) */
    /* mem ld32: base=(lit:g_wifi_nvs) off=0 */
    /* mem ld8: base=((*(g_wifi_nvs+0)+196608)) off=246 */
    /* mem ld32: base=(lit:g_ic) off=20 */
    /* mem ld32: base=(?) off=236 */
    /* mem ld32: base=(lit:g_ic) off=0x1b4 */
    /* mem ld32: base=(*(g_ic+0x1b4)) off=40 */
    /* mem ld8: base=((?+65536)) off=52 */
    /* mem st32: base=(?) off=0 */
    /* mem ld32: base=(?) off=0 */
    /* mem ld8: base=(*(?+0)) off=52 */
    /* ... +28 more memops */
    /* site +0x5e: indirect call via a6 (base *(*(g_ic+0x1b4)+40)); args: (?+4) */
    opaque_indirect_a6();
    /* site +0x6f: ic_del_key(*((?+65536)+52)) */
    ic_del_key(*((?+65536)+52));
    /* site +0x87: indirect call via a11 (base *(*(g_osi_funcs_p+0)+176)); args: *(*(*(?+0)+52)+0x140), *(*(g_osi_funcs_p+0)+176) */
    opaque_indirect_a11();
    /* site +0xa1: ieee80211_pwrsave_node_cleanup(?, *(*(g_osi_funcs_p+0)+176)) */
    ieee80211_pwrsave_node_cleanup(?, *(*(g_osi_funcs_p+0)+176));
    /* site +0xc9: ieee80211_ht_node_cleanup(?, *(*(g_osi_funcs_p+0)+176)) */
    ieee80211_ht_node_cleanup(?, *(*(g_osi_funcs_p+0)+176));
    /* site +0x106: chm_get_current_band(*((?+196608)+182), *(*(g_osi_funcs_p+0)+176)) */
    chm_get_current_band(*((?+196608)+182), *(*(g_osi_funcs_p+0)+176));
    /* site +0x112: ieee80211_set_phy_bw(1, 2, ret@106) */
    ieee80211_set_phy_bw(1, 2, ret@106);
    /* site +0x11d: ieee80211_update_channel(0x156, 2, ret@106) */
    ieee80211_update_channel(0x156, 2, ret@106);
    /* site +0x125: hostap_ht_operation_update(*(g_ic+20), 2, ret@106) */
    hostap_ht_operation_update(*(g_ic+20), 2, ret@106);
    /* site +0x141: indirect call via a5 (base *(g_ic+176)); args: ?, 2, ret@106 */
    opaque_indirect_a5();
    /* site +0x14e: indirect call via a2 (base *(*(g_osi_funcs_p+0)+84)); args: *(g_wifi_global_lock+0), 2, ret@106 */
    opaque_indirect_a2();
    /* site +0x171: indirect call via a2 (base *(*(g_osi_funcs_p+0)+88)); args: *(g_wifi_global_lock+0), 2, ret@106 */
    opaque_indirect_a2();
    return opaque_result; /* full dataflow not recovered */
}

/* cnx_is_any_node_connected @ wl_cnx.o 0x00000008 size 56B bind GLOBAL
 * Calls: none | Data refs: g_ic, g_wifi_nvs
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 cnx_is_any_node_connected(u32 a2)
{
    /* frame: entry a1,32; 23 insns, 3 cond-branches, 0 loops, 2 jumps */
    /* immediates: 240, 1, 0 */
    /* first predicate: beqz.n a8, 3e <cnx_is_any_node_connected+0x36> (condition opaque) */
    /* mem ld32: base=(lit:g_ic) off=20 */
    /* mem ld32: base=(lit:g_wifi_nvs) off=0 */
    /* mem ld8: base=((*(g_wifi_nvs+0)+196608)) off=246 */
    /* mem ld32: base=(((*(g_ic+20)+4)+-4)) off=0 */
    return 1;
}

/* cnx_is_any_node_connecting @ wl_cnx.o 0x00000008 size 58B bind GLOBAL
 * Calls: none | Data refs: g_ic, g_wifi_nvs
 * Fidelity: medium - branchy but loop-free, call sequence mapped */
u32 cnx_is_any_node_connecting(u32 a2)
{
    /* frame: entry a1,32; 24 insns, 4 cond-branches, 0 loops, 2 jumps */
    /* immediates: 240, 1, 0 */
    /* first predicate: beqz.n a8, 40 <cnx_is_any_node_connecting+0x38> (condition opaque) */
    /* mem ld32: base=(lit:g_ic) off=20 */
    /* mem ld32: base=(lit:g_wifi_nvs) off=0 */
    /* mem ld8: base=((*(g_wifi_nvs+0)+196608)) off=246 */
    /* mem ld32: base=(*(g_ic+20)) off=0 */
    /* mem ld32: base=(*(*(g_ic+20)+0)) off=12 */
    return 1;
}

/* wifi_softap_staconnected_event_policy @ wl_cnx.o 0x00000004 size 61B bind GLOBAL
 * Calls: none | Data refs: .data.join_deny_flag
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 wifi_softap_staconnected_event_policy(u32 a2)
{
    /* frame: entry a1,32; 22 insns, 2 cond-branches, 0 loops, 1 jumps */
    /* immediates: 4, 0, -5, 1 */
    /* first predicate: bnei a8, 1, 24 <wifi_softap_staconnected_event_policy+0x20> (condition opaque) */
    /* mem ld8: base=(lit:.data.join_deny_flag) off=0 */
    /* mem st8: base=(lit:.data.join_deny_flag) off=0 */
    /* mem ld8: base=(lit:.data.join_deny_flag) off=0 */
    /* mem st8: base=(lit:.data.join_deny_flag) off=0 */
    return 1;
}

/* wifi_softap_toomany_deny @ wl_cnx.o 0x00000008 size 46B bind GLOBAL
 * Calls: none | Data refs: g_wifi_nvs, .data.join_deny_flag
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 wifi_softap_toomany_deny(u32 a2)
{
    /* frame: entry a1,32; 17 insns, 2 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0, 2, 1 */
    /* first predicate: bgeui a8, 2, 31 <wifi_softap_toomany_deny+0x29> (condition opaque) */
    /* mem ld32: base=(lit:g_wifi_nvs) off=0 */
    /* mem ld8: base=(*(g_wifi_nvs+0)) off=0 */
    /* mem ld8: base=(lit:.data.join_deny_flag) off=0 */
    /* mem st8: base=(lit:.data.join_deny_flag) off=0 */
    return 1;
}

/* cnx_sta_pm @ wl_cnx.o 0x00000014 size 78B bind GLOBAL
 * Calls: pm_start, pm_set_bss_max_idle, pm_enable_keep_alive_timer, pm_stop, pm_disable_keep_alive_timer | Data refs: none
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 cnx_sta_pm(u32 a2, u32 a3)
{
    /* frame: entry a1,48; 28 insns, 1 cond-branches, 0 loops, 1 jumps */
    /* immediates: 0 */
    /* first predicate: beqz.n a10, 54 <cnx_sta_pm+0x40> (condition opaque) */
    /* mem ld32: base=(?) off=24 */
    /* mem ld32: base=(?) off=28 */
    /* mem ld16: base=(?) off=38 */
    /* mem st32: base=(?) off=0 */
    /* mem st32: base=(?) off=4 */
    /* mem ld32: base=(?) off=32 */
    /* mem ld16: base=(?) off=40 */
    /* mem ld16: base=((?+196608)) off=50 */
    /* site +0x3d: pm_start(0, *(?+38), (?+4), *(?+40), *(?+32)) */
    pm_start(0, *(?+38), (?+4), *(?+40), *(?+32));
    /* site +0x46: pm_set_bss_max_idle(*((?+196608)+50), *(?+38), (?+4), *(?+40), *(?+32)) */
    pm_set_bss_max_idle(*((?+196608)+50), *(?+38), (?+4), *(?+40), *(?+32));
    /* site +0x4c: pm_enable_keep_alive_timer(ret@46, *(?+38), (?+4), *(?+40), *(?+32)) */
    pm_enable_keep_alive_timer(ret@46, *(?+38), (?+4), *(?+40), *(?+32));
    /* site +0x57: pm_stop(ret@4c, *(?+38), (?+4), *(?+40), *(?+32)) */
    pm_stop(ret@4c, *(?+38), (?+4), *(?+40), *(?+32));
    /* site +0x5d: pm_disable_keep_alive_timer(ret@57, *(?+38), (?+4), *(?+40), *(?+32)) */
    pm_disable_keep_alive_timer(ret@57, *(?+38), (?+4), *(?+40), *(?+32));
    return opaque_result; /* full dataflow not recovered */
}

/* cnx_update_bss_more @ wl_cnx.o 0x0000007c size 1139B bind GLOBAL
 * Calls: indirect(a4), indirect(a6), indirect(a4), indirect(a6), memcpy, indirect(a4), memcpy, memset, indirect(a9), indirect(a8), indirect(a9), memcpy, indirect(a8), indirect(a9), indirect(a8), indirect(a9), memcpy, indirect(a8), memcpy, memset, memcpy, ieee80211_sta_is_connected, indirect(a8), indirect(a10), cnx_sta_pm, ieee80211_set_shortslottime, ieee80211_parse_wmeparams, ieee80211_wme_updateparams, memset, hal_now, ieee80211_setup_rates, ieee80211_is_ht_cipher, ieee80211_setup_phy_mode, ieee80211_ht_updateparams, ieee80211_update_channel, ieee80211_regdomain_update_in_connect, ieee80211_set_max_rate, ieee80211_parse_obss_scan_param | Data refs: g_cnxMgr, g_ic, g_wifi_nvs, g_mesh_init_ps_type, esp_mesh_quick_funcs, g_osi_funcs_p, .bss.is_connected_sync, g_ic+0x200
 * Fidelity: low - 412 insns, 46 branches, 0 loops; skeleton only */
u32 cnx_update_bss_more(u32 a2, u32 a3, u32 a4)
{
    /* frame: entry a1,48; 412 insns, 46 cond-branches, 0 loops, 11 jumps */
    /* immediates: 1, 0, 0x12c, 0x3e8, 62, 0x33e, 15, 64, 8, 0x400 */
    /* first predicate: beqz a4, ac <cnx_update_bss_more+0x30> (condition opaque) */
    /* mem st32: base=(?) off=4 */
    /* mem ld32: base=((lit:g_cnxMgr+983040)) off=96 */
    /* mem st32: base=(?) off=0 */
    /* mem ld32: base=(?) off=80 */
    /* mem st8: base=((?+196608)) off=181 */
    /* mem ld32: base=(lit:g_ic) off=116 */
    /* mem ld32: base=(lit:g_wifi_nvs) off=0 */
    /* mem ld16: base=(?) off=10 */
    /* mem ld16: base=((*(g_wifi_nvs+0)+196608)) off=248 */
    /* mem ld32: base=(lit:g_ic) off=16 */
    /* ... +141 more memops */
    /* site +0xf2: indirect call via a4 (base *(esp_mesh_quick_funcs+12)); args: *(?+40) */
    opaque_indirect_a4();
    /* site +0x135: indirect call via a6 (base *(*(g_osi_funcs_p+0)+176)); args: *(?+0x338) */
    opaque_indirect_a6();
    /* site +0x145: indirect call via a4 (base *(g_osi_funcs_p+0x16c)); args: (*(*(?+132)+1)+2) */
    opaque_indirect_a4();
    /* site +0x156: indirect call via a6 (base *(g_osi_funcs_p+0x16c)); args: (*(g_osi_funcs_p+0x16c)+2) */
    opaque_indirect_a6();
    /* site +0x16d: memcpy(*(?+0x338), *(?+132), (*(*(?+132)+1)+2)) */
    memcpy(*(?+0x338), *(?+132), (*(*(?+132)+1)+2));
    /* site +0x17f: indirect call via a4 (base *(g_osi_funcs_p+176)); args: ret@16d, *(?+132), (*(*(?+132)+1)+2) */
    opaque_indirect_a4();
    /* site +0x1b1: memcpy(0x33e, *(?+60), (*(*(?+60)+1)+2)) */
    memcpy(0x33e, *(?+60), (*(*(?+60)+1)+2));
    /* site +0x1cd: memset(0x33e, 0, 64) */
    memset(0x33e, 0, 64);
    /* site +0x1fb: indirect call via a9 (base *(*(g_osi_funcs_p+0)+176)); args: *(?+0x3b8), 0, 64 */
    opaque_indirect_a9();
    /* site +0x20d: indirect call via a8 (base *(g_osi_funcs_p+0x16c)); args: (*(*(?+152)+1)+2), 0, 64 */
    opaque_indirect_a8();
    /* site +0x21e: indirect call via a9 (base *(g_osi_funcs_p+0x16c)); args: (*(g_osi_funcs_p+0x16c)+2), 0, 64 */
    opaque_indirect_a9();
    /* site +0x235: memcpy(*(?+0x3b8), *(?+152), (*(*(?+152)+1)+2)) */
    memcpy(*(?+0x3b8), *(?+152), (*(*(?+152)+1)+2));
    /* site +0x246: indirect call via a8 (base *(g_osi_funcs_p+176)); args: ret@235, *(?+152), (*(*(?+152)+1)+2) */
    opaque_indirect_a8();
    /* site +0x26f: indirect call via a9 (base *(g_osi_funcs_p+176)); args: *(?+0x3bc), *(?+152), (*(*(?+152)+1)+2) */
    opaque_indirect_a9();
    /* site +0x281: indirect call via a8 (base *(g_osi_funcs_p+0x16c)); args: (*(g_osi_funcs_p+1)+2), *(?+152), (*(*(?+152)+1)+2) */
    opaque_indirect_a8();
    /* site +0x292: indirect call via a9 (base *(g_osi_funcs_p+0x16c)); args: (*(g_osi_funcs_p+0x16c)+2), *(?+152), (*(*(?+152)+1)+2) */
    opaque_indirect_a9();
    /* site +0x2a9: memcpy(*(?+0x3bc), *(?+156), (*(*(?+156)+1)+2)) */
    memcpy(*(?+0x3bc), *(?+156), (*(*(?+156)+1)+2));
    /* site +0x2bb: indirect call via a8 (base *(g_osi_funcs_p+176)); args: ret@2a9, *(?+156), (*(*(?+156)+1)+2) */
    opaque_indirect_a8();
    /* site +0x2e5: memcpy((?+51), *(?+52), (*(*(?+52)+1)+2)) */
    memcpy((?+51), *(?+52), (*(*(?+52)+1)+2));
    /* site +0x2f3: memset(ret@2e5, 0, 64) */
    memset(ret@2e5, 0, 64);
    /* site +0x37e: memcpy((?+24), *(?+28), 8, *(g_ic+0x200+156)) */
    memcpy((?+24), *(?+28), 8, *(g_ic+0x200+156));
    /* site +0x38a: ieee80211_sta_is_connected(ret@37e, *(?+28), 8, *(g_ic+0x200+156)) */
    ieee80211_sta_is_connected(ret@37e, *(?+28), 8, *(g_ic+0x200+156));
    /* site +0x3a5: indirect call via a8 (base *(esp_mesh_quick_funcs+116)); args: *(?+40), *(.bss.is_connected_sync+0), 1, 0 */
    opaque_indirect_a8();
    /* site +0x3bb: indirect call via a10 (base *(esp_mesh_quick_funcs+144)); args: *(esp_mesh_quick_funcs+144), *(.bss.is_connected_sync+0), 1, 0 */
    opaque_indirect_a10();
    /* site +0x3c9: cnx_sta_pm(1, *(.bss.is_connected_sync+0), 1, 0) */
    cnx_sta_pm(1, *(.bss.is_connected_sync+0), 1, 0);
    /* site +0x3e9: ieee80211_set_shortslottime(ret@3c9, 0x400, 1, 0) */
    ieee80211_set_shortslottime(ret@3c9, 0x400, 1, 0);
    /* site +0x415: ieee80211_parse_wmeparams(?, *(?+64), 1, 0) */
    ieee80211_parse_wmeparams(?, *(?+64), 1, 0);
    /* site +0x431: ieee80211_wme_updateparams(ret@415, 135, 1, 0) */
    ieee80211_wme_updateparams(ret@415, 135, 1, 0);
    /* site +0x449: memset(135, 0, 29, 0) */
    memset(135, 0, 29, 0);
    /* site +0x44f: hal_now(ret@449, 0, 29, 0) */
    hal_now(ret@449, 0, 29, 0);
    /* site +0x463: ieee80211_setup_rates(?, *(?+40), *(?+44), 0) */
    ieee80211_setup_rates(?, *(?+40), *(?+44), 0);
    /* site +0x471: ieee80211_is_ht_cipher(0, *(?+40), *(?+44), 0) */
    ieee80211_is_ht_cipher(0, *(?+40), *(?+44), 0);
    /* site +0x47b: ieee80211_setup_phy_mode(?, ret@471, *(?+44), 0) */
    ieee80211_setup_phy_mode(?, ret@471, *(?+44), 0);
    /* site +0x495: ieee80211_ht_updateparams(?, *(?+68), *(?+72), 0) */
    ieee80211_ht_updateparams(?, *(?+68), *(?+72), 0);
    /* site +0x4c5: ieee80211_update_channel(171, *(?+68), *(?+72), 0) */
    ieee80211_update_channel(171, *(?+68), *(?+72), 0);
    /* site +0x4cf: ieee80211_regdomain_update_in_connect(?, *(?+32), *(?+72), 0) */
    ieee80211_regdomain_update_in_connect(?, *(?+32), *(?+72), 0);
    /* site +0x4d7: ieee80211_set_max_rate(?, *(?+32), *(?+72), 0) */
    ieee80211_set_max_rate(?, *(?+32), *(?+72), 0);
    /* site +0x4ea: ieee80211_parse_obss_scan_param(?, *(?+116), *(?+72), 0) */
    ieee80211_parse_obss_scan_param(?, *(?+116), *(?+72), 0);
    return opaque_result; /* full dataflow not recovered */
}

/* cnx_beacon_timeout_process @ wl_cnx.o 0x00000034 size 160B bind GLOBAL
 * Calls: wifi_log, wifi_log, wifi_event_post, pm_is_open, cnx_sta_pm, indirect(a8), indirect(a2), send_ap_probe | Data refs: g_ic, .rodata_wlog_debug.79, .rodata_wlog_info.80, g_mesh_is_root, g_mesh_init_ps_type, g_osi_funcs_p, .text.mgd_probe_send_timeout
 * Fidelity: medium - branchy but loop-free, call sequence mapped */
u32 cnx_beacon_timeout_process(u32 a3)
{
    /* frame: entry a1,32; 60 insns, 5 cond-branches, 0 loops, 1 jumps */
    /* immediates: 4, 8, 1, 3, 21, 0 */
    /* first predicate: beqz.n a2, 55 <cnx_beacon_timeout_process+0x21> (condition opaque) */
    /* mem ld32: base=(lit:g_ic) off=16 */
    /* mem ld8: base=(*(g_ic+16)) off=148 */
    /* mem ld32: base=(lit:g_ic) off=116 */
    /* mem ld8: base=(lit:g_mesh_is_root) off=0 */
    /* mem ld32: base=(lit:g_mesh_init_ps_type) off=0 */
    /* mem ld32: base=(lit:g_ic) off=16 */
    /* mem st8: base=((*(g_ic+16)+24)) off=124 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=240 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* ... +2 more memops */
    /* site +0x4d: wifi_log(1, 8, 4, lit:.rodata_wlog_debug.79) */
    wifi_log(1, 8, 4, lit:.rodata_wlog_debug.79);
    /* site +0x62: wifi_log(1, 4, 3, lit:.rodata_wlog_info.80) */
    wifi_log(1, 4, 3, lit:.rodata_wlog_info.80);
    /* site +0x6e: wifi_event_post(21, *(*(g_ic+16)+148), *(*(g_ic+16)+148), lit:.rodata_wlog_info.80) */
    wifi_event_post(21, *(*(g_ic+16)+148), *(*(g_ic+16)+148), lit:.rodata_wlog_info.80);
    /* site +0x8e: pm_is_open(ret@6e, *(*(g_ic+16)+148), *(*(g_ic+16)+148), lit:.rodata_wlog_info.80) */
    pm_is_open(ret@6e, *(*(g_ic+16)+148), *(*(g_ic+16)+148), lit:.rodata_wlog_info.80);
    /* site +0x9a: cnx_sta_pm(*(g_mesh_is_root+0), *(g_mesh_is_root+0), *(*(g_ic+16)+148), lit:.rodata_wlog_info.80) */
    cnx_sta_pm(*(g_mesh_is_root+0), *(g_mesh_is_root+0), *(*(g_ic+16)+148), lit:.rodata_wlog_info.80);
    /* site +0xb7: indirect call via a8 (base *(g_mesh_init_ps_type+240)); args: (*(g_ic+16)+24), *(g_mesh_is_root+0), *(*(g_ic+16)+148), lit:.rodata_wlog_info.80 */
    opaque_indirect_a8();
    /* site +0xc9: indirect call via a2 (base *(g_osi_funcs_p+244)); args: (*(g_ic+16)+24), lit:.text.mgd_probe_send_timeout, 0, lit:.rodata_wlog_info.80 */
    opaque_indirect_a2();
    /* site +0xcf: send_ap_probe(ret@c9, lit:.text.mgd_probe_send_timeout, 0, lit:.rodata_wlog_info.80) */
    send_ap_probe(ret@c9, lit:.text.mgd_probe_send_timeout, 0, lit:.rodata_wlog_info.80);
    return opaque_result; /* full dataflow not recovered */
}

/* ic_set_sta @ wl_cnx.o 0x00000018 size 216B bind GLOBAL
 * Calls: ieee80211_phy_type_get, memset, ic_set_trc, indirect(a3), indirect(a2) | Data refs: g_wifi_global_lock, g_osi_funcs_p, g_ic+0x100
 * Fidelity: low - 79 insns, 6 branches, 0 loops; skeleton only */
u32 ic_set_sta(u32 a2, u32 a3)
{
    /* frame: entry a1,80; 79 insns, 6 cond-branches, 0 loops, 1 jumps */
    /* immediates: 1, 28, 0, 131 */
    /* first predicate: beqz a3, ee <ic_set_sta+0xd6> (condition opaque) */
    /* mem ld32: base=(?) off=0 */
    /* mem ld32: base=(*(?+0)) off=0x14c */
    /* mem ld16: base=(?) off=38 */
    /* mem st32: base=(?) off=32 */
    /* mem st16: base=(?) off=10 */
    /* mem ld8: base=(?) off=164 */
    /* mem st32: base=(?) off=16 */
    /* mem st32: base=(?) off=20 */
    /* mem ld32: base=(?) off=32 */
    /* mem ld8: base=((?+65536)) off=94 */
    /* ... +20 more memops */
    /* site +0x47: ieee80211_phy_type_get(/* no traced args */) */
    ieee80211_phy_type_get(/* no traced args */);
    /* site +0x55: memset(?, 0, 28) */
    memset(?, 0, 28);
    /* site +0xa6: ic_set_trc(?, 0, 28) */
    ic_set_trc(?, 0, 28);
    /* site +0xb9: indirect call via a3 (base *(*(g_osi_funcs_p+0)+84)); args: *(g_wifi_global_lock+0), 0, 28 */
    opaque_indirect_a3();
    /* site +0xeb: indirect call via a2 (base *(*(g_osi_funcs_p+0)+88)); args: *(g_wifi_global_lock+0), 0, 28 */
    opaque_indirect_a2();
    return opaque_result; /* full dataflow not recovered */
}

/* cnx_sta_leave @ wl_cnx.o 0x00000090 size 694B bind GLOBAL
 * Calls: ic_set_sta, cnx_sta_pm, wifi_log, indirect(a6), indirect(a6), indirect(a6), indirect(a6), indirect(a7), indirect(a7), indirect(a7), indirect(a7), indirect(a7), indirect(a7), indirect(a7), indirect(a7), indirect(a6), indirect(a6), ieee80211_ht_node_cleanup, cnx_rc_update_state_metric, memcmp, wifi_log, indirect(a8), cnx_remove_from_blacklist, cnx_remove_rc, wifi_log, ic_del_key_all, clear_ic_key, clear_ic_key, clear_ic_key, indirect(a3), indirect(a2), ieee80211_update_phy_country, ieee80211_update_channel, wifi_log, wifi_set_rx_policy | Data refs: .rodata_wlog_debug.75, .bss.cnx_csa_timer, g_osi_funcs_p, sta_csa_timer, g_ic, ieee80211_ethbroadcast, g_cnxMgr, .bss.is_connected_sync, g_mesh_is_root, g_mesh_self_organized, g_wifi_nvs, .rodata_wlog_verbose.76, .rodata_wlog_debug.77, g_sta_connected_flag, g_wifi_global_lock, ap_no_lr, .rodata_wlog_debug.78
 * Fidelity: low - 258 insns, 17 branches, 0 loops; skeleton only */
u32 cnx_sta_leave(u32 a2, u32 a3, u32 a5)
{
    /* frame: entry a1,48; 258 insns, 17 cond-branches, 0 loops, 1 jumps */
    /* immediates: 0, 4, 1, 0x304, 0x318, 0x2cc, 13, 2, -3, -7 */
    /* first predicate: beqz.n a4, ad <cnx_sta_leave+0x1d> (condition opaque) */
    /* mem ld16: base=(?) off=38 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=236 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=240 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=236 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=240 */
    /* mem st8: base=((lit:g_ic+65536)) off=235 */
    /* ... +59 more memops */
    /* site +0x9f: ic_set_sta(0) */
    ic_set_sta(0);
    /* site +0xaa: cnx_sta_pm(0) */
    cnx_sta_pm(0);
    /* site +0xb9: wifi_log(1, 4, 4, lit:.rodata_wlog_debug.75) */
    wifi_log(1, 4, 4, lit:.rodata_wlog_debug.75);
    /* site +0xcb: indirect call via a6 (base *(*(g_osi_funcs_p+0)+236)); args: lit:.bss.cnx_csa_timer, 4, 4, lit:.rodata_wlog_debug.75 */
    opaque_indirect_a6();
    /* site +0xd6: indirect call via a6 (base *(*(g_osi_funcs_p+0)+240)); args: lit:.bss.cnx_csa_timer, 4, 4, lit:.rodata_wlog_debug.75 */
    opaque_indirect_a6();
    /* site +0xe3: indirect call via a6 (base *(*(g_osi_funcs_p+0)+236)); args: lit:sta_csa_timer, 4, 4, lit:.rodata_wlog_debug.75 */
    opaque_indirect_a6();
    /* site +0xed: indirect call via a6 (base *(*(g_osi_funcs_p+0)+240)); args: lit:sta_csa_timer, 4, 4, lit:.rodata_wlog_debug.75 */
    opaque_indirect_a6();
    /* site +0x10b: indirect call via a7 (base *(*(g_osi_funcs_p+0)+236)); args: 0x304, 4, 4, lit:.rodata_wlog_debug.75 */
    opaque_indirect_a7();
    /* site +0x11b: indirect call via a7 (base *(*(g_osi_funcs_p+0)+240)); args: 0x304, 4, 4, lit:.rodata_wlog_debug.75 */
    opaque_indirect_a7();
    /* site +0x127: indirect call via a7 (base *(*(g_osi_funcs_p+0)+236)); args: ret@11b, 4, 4, lit:.rodata_wlog_debug.75 */
    opaque_indirect_a7();
    /* site +0x137: indirect call via a7 (base *(*(g_osi_funcs_p+0)+240)); args: 0x318, 4, 4, lit:.rodata_wlog_debug.75 */
    opaque_indirect_a7();
    /* site +0x141: indirect call via a7 (base *(*(g_osi_funcs_p+0)+236)); args: 0x2cc, 4, 4, lit:.rodata_wlog_debug.75 */
    opaque_indirect_a7();
    /* site +0x14f: indirect call via a7 (base *(*(g_osi_funcs_p+0)+240)); args: 0x2cc, 4, 4, lit:.rodata_wlog_debug.75 */
    opaque_indirect_a7();
    /* site +0x15b: indirect call via a7 (base *(*(g_osi_funcs_p+0)+236)); args: ret@14f, 4, 4, lit:.rodata_wlog_debug.75 */
    opaque_indirect_a7();
    /* site +0x166: indirect call via a7 (base *(*(g_osi_funcs_p+0)+240)); args: (?+84), 4, 4, lit:.rodata_wlog_debug.75 */
    opaque_indirect_a7();
    /* site +0x183: indirect call via a6 (base *(*(g_ic+0x1b8)+16)); args: ret@166, 4, 4, lit:.rodata_wlog_debug.75 */
    opaque_indirect_a6();
    /* site +0x19a: indirect call via a6 (base *(*(g_ic+0x280)+16)); args: lit:ieee80211_ethbroadcast, 4, 4, lit:.rodata_wlog_debug.75 */
    opaque_indirect_a6();
    /* site +0x1a2: ieee80211_ht_node_cleanup(?, 4, 4, lit:.rodata_wlog_debug.75) */
    ieee80211_ht_node_cleanup(?, 4, 4, lit:.rodata_wlog_debug.75);
    /* site +0x1c9: cnx_rc_update_state_metric(?, -7, 1, lit:.rodata_wlog_debug.75) */
    cnx_rc_update_state_metric(?, -7, 1, lit:.rodata_wlog_debug.75);
    /* site +0x219: memcmp(147, (?+4), 6, lit:.rodata_wlog_debug.75) */
    memcmp(147, (?+4), 6, lit:.rodata_wlog_debug.75);
    /* site +0x237: wifi_log(1, 4, 5, lit:.rodata_wlog_verbose.76, *((?+196608)+60)) */
    wifi_log(1, 4, 5, lit:.rodata_wlog_verbose.76, *((?+196608)+60));
    /* site +0x25d: indirect call via a8 (base *(g_wifi_nvs+100)); args: ret@237, 4, 5, lit:.rodata_wlog_verbose.76, *((?+196608)+60) */
    opaque_indirect_a8();
    /* site +0x265: cnx_remove_from_blacklist((?+4), 4, 5, lit:.rodata_wlog_verbose.76, *((?+196608)+60)) */
    cnx_remove_from_blacklist((?+4), 4, 5, lit:.rodata_wlog_verbose.76, *((?+196608)+60));
    /* site +0x27d: cnx_remove_rc(?, 4, 5, lit:.rodata_wlog_verbose.76, *((?+196608)+60)) */
    cnx_remove_rc(?, 4, 5, lit:.rodata_wlog_verbose.76, *((?+196608)+60));
    /* site +0x2ab: wifi_log(1, 4, 4, lit:.rodata_wlog_debug.77, *((*(g_ic+16)+65536)+84)) */
    wifi_log(1, 4, 4, lit:.rodata_wlog_debug.77, *((*(g_ic+16)+65536)+84));
    /* site +0x2c6: ic_del_key_all(0, *(g_ic+0x1c8), 4, lit:.rodata_wlog_debug.77, *((*(g_ic+16)+65536)+84)) */
    ic_del_key_all(0, *(g_ic+0x1c8), 4, lit:.rodata_wlog_debug.77, *((*(g_ic+16)+65536)+84));
    /* site +0x2ce: clear_ic_key(4, *(g_ic+0x1c8), 4, lit:.rodata_wlog_debug.77, *((*(g_ic+16)+65536)+84)) */
    clear_ic_key(4, *(g_ic+0x1c8), 4, lit:.rodata_wlog_debug.77, *((*(g_ic+16)+65536)+84));
    /* site +0x2d6: clear_ic_key(0, *(g_ic+0x1c8), 4, lit:.rodata_wlog_debug.77, *((*(g_ic+16)+65536)+84)) */
    clear_ic_key(0, *(g_ic+0x1c8), 4, lit:.rodata_wlog_debug.77, *((*(g_ic+16)+65536)+84));
    /* site +0x2de: clear_ic_key(1, *(g_ic+0x1c8), 4, lit:.rodata_wlog_debug.77, *((*(g_ic+16)+65536)+84)) */
    clear_ic_key(1, *(g_ic+0x1c8), 4, lit:.rodata_wlog_debug.77, *((*(g_ic+16)+65536)+84));
    /* site +0x2fb: indirect call via a3 (base *(g_sta_connected_flag+84)); args: *(g_wifi_global_lock+0), *(g_ic+0x1c8), 4, lit:.rodata_wlog_debug.77, *((*(g_ic+16)+65536)+84) */
    opaque_indirect_a3();
    /* site +0x30d: indirect call via a2 (base *(*(g_osi_funcs_p+0)+88)); args: *(g_wifi_global_lock+0), *(g_ic+0x1c8), 4, lit:.rodata_wlog_debug.77, *((*(g_ic+16)+65536)+84) */
    opaque_indirect_a2();
    /* site +0x313: ieee80211_update_phy_country(ret@30d, *(g_ic+0x1c8), 4, lit:.rodata_wlog_debug.77, *((*(g_ic+16)+65536)+84)) */
    ieee80211_update_phy_country(ret@30d, *(g_ic+0x1c8), 4, lit:.rodata_wlog_debug.77, *((*(g_ic+16)+65536)+84));
    /* site +0x31b: ieee80211_update_channel(0, *(g_ic+0x1c8), 4, lit:.rodata_wlog_debug.77, *((*(g_ic+16)+65536)+84)) */
    ieee80211_update_channel(0, *(g_ic+0x1c8), 4, lit:.rodata_wlog_debug.77, *((*(g_ic+16)+65536)+84));
    /* site +0x339: wifi_log(1, 12, 4, lit:.rodata_wlog_debug.78, 7) */
    wifi_log(1, 12, 4, lit:.rodata_wlog_debug.78, 7);
    /* site +0x341: wifi_set_rx_policy(7, 12, 4, lit:.rodata_wlog_debug.78, 7) */
    wifi_set_rx_policy(7, 12, 4, lit:.rodata_wlog_debug.78, 7);
    return opaque_result; /* full dataflow not recovered */
}

/* cnx_sta_associated @ wl_cnx.o 0x0000003c size 348B bind GLOBAL
 * Calls: ic_set_sta, indirect(a5), indirect(a5), indirect(a5), indirect(a5), indirect(a4), indirect(a4), indirect(a4), wifi_log, indirect(a3), indirect(a10), wifi_log, wifi_log, indirect(a3), indirect(a10), wifi_log, indirect(a3) | Data refs: g_osi_funcs_p, .text.cnx_beacon_timeout, cnx_handshake_timeout, g_misc_nvs, .rodata_wlog_debug.84, g_ic, .rodata_wlog_debug.85, .rodata_wlog_debug.86, .rodata_wlog_debug.87
 * Fidelity: low - 131 insns, 10 branches, 0 loops; skeleton only */
u32 cnx_sta_associated(u32 a2, u32 a3)
{
    /* frame: entry a1,32; 131 insns, 10 cond-branches, 0 loops, 3 jumps */
    /* immediates: 1, 0, 4, 0x271, 13, 0x3e8, 0x753 */
    /* first predicate: beqz.n a6, f7 <cnx_sta_associated+0xbb> (condition opaque) */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=236 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=240 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=244 */
    /* mem ld16: base=((?+131072)) off=58 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=232 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* ... +23 more memops */
    /* site +0x46: ic_set_sta(1) */
    ic_set_sta(1);
    /* site +0x57: indirect call via a5 (base *(*(g_osi_funcs_p+0)+236)); args: (?+24) */
    opaque_indirect_a5();
    /* site +0x62: indirect call via a5 (base *(*(g_osi_funcs_p+0)+240)); args: (?+24) */
    opaque_indirect_a5();
    /* site +0x71: indirect call via a5 (base *(*(g_osi_funcs_p+0)+244)); args: (?+24), lit:.text.cnx_beacon_timeout, 0 */
    opaque_indirect_a5();
    /* site +0x91: indirect call via a5 (base *(*(g_osi_funcs_p+0)+232)); args: (?+24), ((*((?+131072)+58) slli 5) slli 3), 0 */
    opaque_indirect_a5();
    /* site +0x9b: indirect call via a4 (base *(*(g_osi_funcs_p+0)+236)); args: (?+4), ((*((?+131072)+58) slli 5) slli 3), 0 */
    opaque_indirect_a4();
    /* site +0xa6: indirect call via a4 (base *(*(g_osi_funcs_p+0)+240)); args: (?+4), ((*((?+131072)+58) slli 5) slli 3), 0 */
    opaque_indirect_a4();
    /* site +0xb5: indirect call via a4 (base *(*(g_osi_funcs_p+0)+244)); args: (?+4), lit:cnx_handshake_timeout, 0 */
    opaque_indirect_a4();
    /* site +0xd5: wifi_log(1, 4, 4, lit:.rodata_wlog_debug.84) */
    wifi_log(1, 4, 4, lit:.rodata_wlog_debug.84);
    /* site +0xe9: indirect call via a3 (base *(g_osi_funcs_p+232)); args: (?+4), (0x271 slli 5), 0, lit:.rodata_wlog_debug.84 */
    opaque_indirect_a3();
    /* site +0x11d: indirect call via a10 (base *(*(g_ic+0x1b8)+12)); args: *(*(g_ic+0x1b8)+12), (0x271 slli 5), 0, lit:.rodata_wlog_debug.84 */
    opaque_indirect_a10();
    /* site +0x131: wifi_log(1, 4, 4, lit:.rodata_wlog_debug.85) */
    wifi_log(1, 4, 4, lit:.rodata_wlog_debug.85);
    /* site +0x14d: wifi_log(1, 4, 4, lit:.rodata_wlog_debug.86) */
    wifi_log(1, 4, 4, lit:.rodata_wlog_debug.86);
    /* site +0x161: indirect call via a3 (base *(g_osi_funcs_p+232)); args: ret@14d, (0x753 slli 4), 4, lit:.rodata_wlog_debug.86 */
    opaque_indirect_a3();
    /* site +0x16d: indirect call via a10 (base *(*(g_ic+0x1b8)+4)); args: *(*(g_ic+0x1b8)+4), (0x753 slli 4), 4, lit:.rodata_wlog_debug.86 */
    opaque_indirect_a10();
    /* site +0x181: wifi_log(1, 4, 4, lit:.rodata_wlog_debug.87) */
    wifi_log(1, 4, 4, lit:.rodata_wlog_debug.87);
    /* site +0x193: indirect call via a3 (base *(g_osi_funcs_p+232)); args: *(g_ic+0x1b8), (0x271 slli 4), 0, lit:.rodata_wlog_debug.87 */
    opaque_indirect_a3();
    return opaque_result; /* full dataflow not recovered */
}

/* cnx_node_leave @ wl_cnx.o 0x00000054 size 618B bind GLOBAL
 * Calls: wifi_log, indirect(a6), indirect(a6), hostap_del_mac_info_from_list, hostap_del_mac_info_from_list, hostap_del_mac_info_from_list, indirect(a8), indirect(a8), indirect(a8), indirect(a3), wifi_log, wifi_log, memcpy, wifi_event_post, memcpy, wifi_event_post, ieee80211_set_tim, ic_set_sta, ieee80211_update_channel, cnx_node_remove | Data refs: .rodata.cnx_connect_to_bss.str1.1, .rodata_wlog_error.92, g_osi_funcs_p, .rodata_wlog_info.93, .rodata_wlog_info.94, g_ic
 * Fidelity: low - 201 insns, 13 branches, 0 loops; skeleton only (weak) */
u32 cnx_node_leave(u32 a2, u32 a3)
{
    /* frame: entry a1,80; 201 insns, 13 cond-branches, 0 loops, 4 jumps */
    /* immediates: 1, 0x13c, 2, 3, 0, 0x304, 0x318, 4, 6, 10 */
    /* first predicate: beqz.n a2, 5e <cnx_node_leave+0xa> (condition opaque) */
    /* mem ld32: base=(?) off=0 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=236 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=240 */
    /* mem ld32: base=(*(?+0)) off=236 */
    /* mem ld8: base=((?+131072)) off=251 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=236 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* ... +53 more memops */
    /* site +0x71: wifi_log(1, (1 slli 11), 1, lit:.rodata_wlog_error.92, lit:.rodata.cnx_connect_to_bss.str1.1) */
    wifi_log(1, (1 slli 11), 1, lit:.rodata_wlog_error.92, lit:.rodata.cnx_connect_to_bss.str1.1);
    /* site +0x87: indirect call via a6 (base *(*(g_osi_funcs_p+0)+236)); args: 0x13c, (1 slli 11), 1, lit:.rodata_wlog_error.92, lit:.rodata.cnx_connect_to_bss.str1.1 */
    opaque_indirect_a6();
    /* site +0x92: indirect call via a6 (base *(*(g_osi_funcs_p+0)+240)); args: 0x13c, (1 slli 11), 1, lit:.rodata_wlog_error.92, lit:.rodata.cnx_connect_to_bss.str1.1 */
    opaque_indirect_a6();
    /* site +0xa7: hostap_del_mac_info_from_list((?+4), 2, 1, lit:.rodata_wlog_error.92, lit:.rodata.cnx_connect_to_bss.str1.1) */
    hostap_del_mac_info_from_list((?+4), 2, 1, lit:.rodata_wlog_error.92, lit:.rodata.cnx_connect_to_bss.str1.1);
    /* site +0xb1: hostap_del_mac_info_from_list((?+4), 3, 1, lit:.rodata_wlog_error.92, lit:.rodata.cnx_connect_to_bss.str1.1) */
    hostap_del_mac_info_from_list((?+4), 3, 1, lit:.rodata_wlog_error.92, lit:.rodata.cnx_connect_to_bss.str1.1);
    /* site +0xbe: hostap_del_mac_info_from_list((?+4), 0, 1, lit:.rodata_wlog_error.92, lit:.rodata.cnx_connect_to_bss.str1.1) */
    hostap_del_mac_info_from_list((?+4), 0, 1, lit:.rodata_wlog_error.92, lit:.rodata.cnx_connect_to_bss.str1.1);
    /* site +0xd2: indirect call via a8 (base *(*(g_osi_funcs_p+0)+236)); args: 0x304, 0, 1, lit:.rodata_wlog_error.92, lit:.rodata.cnx_connect_to_bss.str1.1 */
    opaque_indirect_a8();
    /* site +0xe1: indirect call via a8 (base *(*(g_osi_funcs_p+0)+240)); args: 0x304, 0, 1, lit:.rodata_wlog_error.92, lit:.rodata.cnx_connect_to_bss.str1.1 */
    opaque_indirect_a8();
    /* site +0xeb: indirect call via a8 (base *(*(g_osi_funcs_p+0)+236)); args: 0x318, 0, 1, lit:.rodata_wlog_error.92, lit:.rodata.cnx_connect_to_bss.str1.1 */
    opaque_indirect_a8();
    /* site +0xf5: indirect call via a3 (base *(g_osi_funcs_p+240)); args: 0x318, 0, 1, lit:.rodata_wlog_error.92, lit:.rodata.cnx_connect_to_bss.str1.1 */
    opaque_indirect_a3();
    /* site +0x139: wifi_log(1, 4, 3, lit:.rodata_wlog_info.93, *(?+4)) */
    wifi_log(1, 4, 3, lit:.rodata_wlog_info.93, *(?+4));
    /* site +0x15a: wifi_log(1, 4, 3, lit:.rodata_wlog_info.94, *(?+4)) */
    wifi_log(1, 4, 3, lit:.rodata_wlog_info.94, *(?+4));
    /* site +0x176: memcpy((?+32), (?+4), 6, lit:.rodata_wlog_info.94, *(?+4)) */
    memcpy((?+32), (?+4), 6, lit:.rodata_wlog_info.94, *(?+4));
    /* site +0x1a5: wifi_event_post(15, (?+32), 10, lit:.rodata_wlog_info.94, *(?+4)) */
    wifi_event_post(15, (?+32), 10, lit:.rodata_wlog_info.94, *(?+4));
    /* site +0x1df: memcpy((?+32), (?+4), 6, lit:.rodata_wlog_info.94, *(?+4)) */
    memcpy((?+32), (?+4), 6, lit:.rodata_wlog_info.94, *(?+4));
    /* site +0x20b: wifi_event_post(15, (?+32), 10, lit:.rodata_wlog_info.94, *(?+4)) */
    wifi_event_post(15, (?+32), 10, lit:.rodata_wlog_info.94, *(?+4));
    /* site +0x21b: ieee80211_set_tim(ret@20b, 0, 10, lit:.rodata_wlog_info.94, *(?+4)) */
    ieee80211_set_tim(ret@20b, 0, 10, lit:.rodata_wlog_info.94, *(?+4));
    /* site +0x226: ic_set_sta(0, ?, 10, lit:.rodata_wlog_info.94, *(?+4)) */
    ic_set_sta(0, ?, 10, lit:.rodata_wlog_info.94, *(?+4));
    /* site +0x25d: ieee80211_update_channel(0, ?, 10, lit:.rodata_wlog_info.94, *(?+4)) */
    ieee80211_update_channel(0, ?, 10, lit:.rodata_wlog_info.94, *(?+4));
    /* site +0x265: cnx_node_remove(?, ?, 10, lit:.rodata_wlog_info.94, *(?+4)) */
    cnx_node_remove(?, ?, 10, lit:.rodata_wlog_info.94, *(?+4));
    return opaque_result; /* full dataflow not recovered */
}

/* cnx_node_join @ wl_cnx.o 0x00000080 size 806B bind GLOBAL
 * Calls: wifi_log, wifi_log, memcmp, ieee80211_send_mgmt, wifi_log, wifi_log, memcpy, wifi_mesh_event_post, memcpy, wifi_event_post, indirect(a3), indirect(a3), ieee80211_amsdu_negotiate, wifi_log, ieee80211_send_mgmt, ieee80211_send_mgmt, cnx_node_leave, ic_set_sta, ieee80211_phy_mode_show | Data refs: .rodata.cnx_node_join.str1.1, .rodata.cnx_connect_to_bss.str1.1, .rodata_wlog_error.95, .rodata_wlog_debug.96, ieee80211_ethbroadcast, g_wifi_nvs, .rodata_wlog_info.97, .rodata_wlog_info.98, .data.join_deny_flag, g_ic, .rodata_wlog_debug.99
 * Fidelity: low - 293 insns, 17 branches, 0 loops; skeleton only */
u32 cnx_node_join(u32 a2, u32 a3, u32 a6, u32 a7)
{
    /* frame: entry a1,128; 293 insns, 17 cond-branches, 0 loops, 10 jumps */
    /* immediates: 0, 1, 4, 6, 17, 3, 11, 68, 8, 14 */
    /* first predicate: beqz.n a2, 94 <cnx_node_join+0x14> (condition opaque) */
    /* mem st8: base=(?) off=79 */
    /* mem st8: base=(?) off=78 */
    /* mem ld32: base=(?) off=0 */
    /* mem ld32: base=(lit:g_wifi_nvs) off=0 */
    /* mem ld8: base=((*(g_wifi_nvs+0)+196608)) off=246 */
    /* mem ld32: base=(?) off=236 */
    /* mem st32: base=(?) off=24 */
    /* mem st32: base=(?) off=20 */
    /* mem st32: base=(?) off=16 */
    /* mem st32: base=(?) off=12 */
    /* ... +80 more memops */
    /* site +0xaa: wifi_log(1, (1 slli 11), 1, lit:.rodata_wlog_error.95, lit:.rodata.cnx_connect_to_bss.str1.1) */
    wifi_log(1, (1 slli 11), 1, lit:.rodata_wlog_error.95, lit:.rodata.cnx_connect_to_bss.str1.1);
    /* site +0xc2: wifi_log(1, 4, 4, lit:.rodata_wlog_debug.96, lit:.rodata.cnx_connect_to_bss.str1.1) */
    wifi_log(1, 4, 4, lit:.rodata_wlog_debug.96, lit:.rodata.cnx_connect_to_bss.str1.1);
    /* site +0xd1: memcmp((?+4), lit:ieee80211_ethbroadcast, 6, lit:.rodata_wlog_debug.96, lit:.rodata.cnx_connect_to_bss.str1.1) */
    memcmp((?+4), lit:ieee80211_ethbroadcast, 6, lit:.rodata_wlog_debug.96, lit:.rodata.cnx_connect_to_bss.str1.1);
    /* site +0xf1: ieee80211_send_mgmt(ret@d1, ?, 17, lit:.rodata_wlog_debug.96, lit:.rodata.cnx_connect_to_bss.str1.1) */
    ieee80211_send_mgmt(ret@d1, ?, 17, lit:.rodata_wlog_debug.96, lit:.rodata.cnx_connect_to_bss.str1.1);
    /* site +0x101: wifi_log(1, 4, 3, lit:.rodata_wlog_info.97, lit:.rodata.cnx_connect_to_bss.str1.1) */
    wifi_log(1, 4, 3, lit:.rodata_wlog_info.97, lit:.rodata.cnx_connect_to_bss.str1.1);
    /* site +0x145: wifi_log(1, 4, 3, lit:.rodata_wlog_info.98, lit:.rodata.cnx_connect_to_bss.str1.1) */
    wifi_log(1, 4, 3, lit:.rodata_wlog_info.98, lit:.rodata.cnx_connect_to_bss.str1.1);
    /* site +0x186: memcpy((?+32), (?+4), 6, lit:.rodata_wlog_info.98, lit:.rodata.cnx_connect_to_bss.str1.1) */
    memcpy((?+32), (?+4), 6, lit:.rodata_wlog_info.98, lit:.rodata.cnx_connect_to_bss.str1.1);
    /* site +0x1b1: wifi_mesh_event_post(68, (?+32), 11, lit:.rodata_wlog_info.98, lit:.rodata.cnx_connect_to_bss.str1.1) */
    wifi_mesh_event_post(68, (?+32), 11, lit:.rodata_wlog_info.98, lit:.rodata.cnx_connect_to_bss.str1.1);
    /* site +0x1e3: memcpy((?+32), (?+4), 6, lit:.rodata_wlog_info.98, lit:.rodata.cnx_connect_to_bss.str1.1) */
    memcpy((?+32), (?+4), 6, lit:.rodata_wlog_info.98, lit:.rodata.cnx_connect_to_bss.str1.1);
    /* site +0x1fd: wifi_event_post(14, (?+32), 8, lit:.rodata_wlog_info.98, lit:.rodata.cnx_connect_to_bss.str1.1) */
    wifi_event_post(14, (?+32), 8, lit:.rodata_wlog_info.98, lit:.rodata.cnx_connect_to_bss.str1.1);
    /* site +0x285: indirect call via a3 (base *(*(g_ic+0x1b4)+36)); args: (?+32), (?+32), 8, lit:.rodata_wlog_info.98, lit:.rodata.cnx_connect_to_bss.str1.1 */
    opaque_indirect_a3();
    /* site +0x2ab: indirect call via a3 (base *(*(g_ic+0x1b4)+52)); args: *(?+0x130), (?+79), (?+78), lit:.rodata_wlog_info.98, lit:.rodata.cnx_connect_to_bss.str1.1 */
    opaque_indirect_a3();
    /* site +0x2b9: ieee80211_amsdu_negotiate(?, *(?+79), *(?+78), lit:.rodata_wlog_info.98, lit:.rodata.cnx_connect_to_bss.str1.1) */
    ieee80211_amsdu_negotiate(?, *(?+79), *(?+78), lit:.rodata_wlog_info.98, lit:.rodata.cnx_connect_to_bss.str1.1);
    /* site +0x2d2: wifi_log(1, 4, 4, lit:.rodata_wlog_debug.99, lit:.rodata.cnx_connect_to_bss.str1.1) */
    wifi_log(1, 4, 4, lit:.rodata_wlog_debug.99, lit:.rodata.cnx_connect_to_bss.str1.1);
    /* site +0x2ea: ieee80211_send_mgmt(?, *(*(g_ic+0x1b4)+52), *(?+80), lit:.rodata_wlog_debug.99, lit:.rodata.cnx_connect_to_bss.str1.1) */
    ieee80211_send_mgmt(?, *(*(g_ic+0x1b4)+52), *(?+80), lit:.rodata_wlog_debug.99, lit:.rodata.cnx_connect_to_bss.str1.1);
    /* site +0x32b: ieee80211_send_mgmt((*(0+236)+131072), (*((*(0+236)+131072)+250)+-1), 17, lit:.rodata_wlog_debug.99, lit:.rodata.cnx_connect_to_bss.str1.1) */
    ieee80211_send_mgmt((*(0+236)+131072), (*((*(0+236)+131072)+250)+-1), 17, lit:.rodata_wlog_debug.99, lit:.rodata.cnx_connect_to_bss.str1.1);
    /* site +0x333: cnx_node_leave((*(0+236)+131072), (*((*(0+236)+131072)+250)+-1), 17, lit:.rodata_wlog_debug.99, lit:.rodata.cnx_connect_to_bss.str1.1) */
    cnx_node_leave((*(0+236)+131072), (*((*(0+236)+131072)+250)+-1), 17, lit:.rodata_wlog_debug.99, lit:.rodata.cnx_connect_to_bss.str1.1);
    /* site +0x366: ic_set_sta(1, (*(0+236)+131072), 17, lit:.rodata_wlog_debug.99, lit:.rodata.cnx_connect_to_bss.str1.1) */
    ic_set_sta(1, (*(0+236)+131072), 17, lit:.rodata_wlog_debug.99, lit:.rodata.cnx_connect_to_bss.str1.1);
    /* site +0x379: ieee80211_phy_mode_show((*(0+236)+131072), (?+72), 17, lit:.rodata_wlog_debug.99, lit:.rodata.cnx_connect_to_bss.str1.1) */
    ieee80211_phy_mode_show((*(0+236)+131072), (?+72), 17, lit:.rodata_wlog_debug.99, lit:.rodata.cnx_connect_to_bss.str1.1);
    return opaque_result; /* full dataflow not recovered */
}

/* cnx_start_obss_scan @ wl_cnx.o 0x00000028 size 208B bind GLOBAL
 * Calls: cnx_can_do_obss_scan, indirect(a8), wifi_log, wifi_log, indirect(a2), wifi_log | Data refs: g_ic, cnx_obss_scan_timeout, g_osi_funcs_p, .rodata_wlog_debug.104, .rodata_wlog_info.105, .rodata_wlog_debug.106
 * Fidelity: low - 75 insns, 2 branches, 0 loops; skeleton only */
u32 cnx_start_obss_scan(u32 a2, u32 a4)
{
    /* frame: entry a1,32; 75 insns, 2 cond-branches, 0 loops, 1 jumps */
    /* immediates: 0x2cc, 0, 0x2bf, 120, 4, 8, 1, 3 */
    /* first predicate: beqz a10, e5 <cnx_start_obss_scan+0xbd> (condition opaque) */
    /* mem ld32: base=(lit:g_ic) off=16 */
    /* mem ld32: base=(*(g_ic+16)) off=228 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=244 */
    /* mem st32: base=(*(g_ic+228)) off=0x2e0 */
    /* mem st32: base=(*(g_ic+228)) off=0x2e4 */
    /* mem ld32: base=(*(g_ic+228)) off=0x2c0 */
    /* mem ld32: base=(*(g_ic+228)) off=0x2bc */
    /* mem st8: base=(0x2bf) off=0 */
    /* mem st8: base=(0x2bf) off=1 */
    /* ... +6 more memops */
    /* site +0x2e: cnx_can_do_obss_scan(/* no traced args */) */
    cnx_can_do_obss_scan(/* no traced args */);
    /* site +0x5a: indirect call via a8 (base *(*(g_osi_funcs_p+0)+244)); args: 0x2cc, lit:cnx_obss_scan_timeout, 0 */
    opaque_indirect_a8();
    /* site +0x92: wifi_log(1, 8, 4, lit:.rodata_wlog_debug.104) */
    wifi_log(1, 8, 4, lit:.rodata_wlog_debug.104);
    /* site +0xb3: wifi_log(1, 1, 3, lit:.rodata_wlog_info.105, *(g_ic+0x2bc)) */
    wifi_log(1, 1, 3, lit:.rodata_wlog_info.105, *(g_ic+0x2bc));
    /* site +0xdd: indirect call via a2 (base *(g_ic+232)); args: 0x2cc, (((*(g_ic+0x2c0) slli 8) slli 5) slli 3), 0, lit:.rodata_wlog_info.105, *(g_ic+0x2bc) */
    opaque_indirect_a2();
    /* site +0xf1: wifi_log(1, 8, 4, lit:.rodata_wlog_debug.106, *(g_ic+0x2bc)) */
    wifi_log(1, 8, 4, lit:.rodata_wlog_debug.106, *(g_ic+0x2bc));
    return 0;
}

/* cnx_obss_scan_done_cb @ wl_cnx.o 0x0000003c size 297B bind GLOBAL
 * Calls: clear_bss_queue, cnx_can_do_obss_scan, wifi_log, ieee80211_getmgtframe, wifi_log, wifi_log, ieee80211_set_tx_desc, ieee80211_mgmt_output, cnx_start_obss_scan | Data refs: g_ic, .rodata_wlog_debug.9, .rodata_wlog_debug.10, .rodata_wlog_debug.11, .rodata_wlog_error.12, .rodata_wlog_info.13
 * Fidelity: low - 114 insns, 8 branches, 1 loops; skeleton only */
u32 cnx_obss_scan_done_cb(void)
{
    /* frame: entry a1,64; 114 insns, 8 cond-branches, 1 loops, 3 jumps */
    /* immediates: 0, 4, 8, 1, 32, 24, 72, 73, 3, 7 */
    /* first predicate: beqz.n a10, 94 <cnx_obss_scan_done_cb+0x58> (condition opaque) */
    /* mem st32: base=(?) off=16 */
    /* mem ld32: base=(lit:g_ic) off=16 */
    /* mem ld32: base=(*(g_ic+16)) off=228 */
    /* mem ld32: base=(*(g_ic+228)) off=0x2e0 */
    /* mem ld32: base=(*(g_ic+228)) off=0x2e4 */
    /* mem st32: base=(*(g_ic+228)) off=0x2e4 */
    /* mem ld32: base=(?) off=16 */
    /* mem st8: base=(*(?+16)) off=0 */
    /* mem st8: base=(*(?+16)) off=2 */
    /* mem st8: base=(*(?+16)) off=1 */
    /* ... +11 more memops */
    /* site +0x45: clear_bss_queue(/* no traced args */) */
    clear_bss_queue(/* no traced args */);
    /* site +0x59: cnx_can_do_obss_scan(ret@45) */
    cnx_can_do_obss_scan(ret@45);
    /* site +0x6d: wifi_log(1, 8, 4, lit:.rodata_wlog_debug.10) */
    wifi_log(1, 8, 4, lit:.rodata_wlog_debug.10);
    /* site +0xb6: ieee80211_getmgtframe((?+16), 24, ((0+1)+8), lit:.rodata_wlog_debug.11) */
    ieee80211_getmgtframe((?+16), 24, ((0+1)+8), lit:.rodata_wlog_debug.11);
    /* site +0xc9: wifi_log(1, 8, 1, lit:.rodata_wlog_error.12) */
    wifi_log(1, 8, 1, lit:.rodata_wlog_error.12);
    /* site +0x13d: wifi_log(1, 8, 3, lit:.rodata_wlog_info.13, 24) */
    wifi_log(1, 8, 3, lit:.rodata_wlog_info.13, 24);
    /* site +0x14d: ieee80211_set_tx_desc(*(g_ic+228), ret@b6, 7, 0, 0) */
    ieee80211_set_tx_desc(*(g_ic+228), ret@b6, 7, 0, 0);
    /* site +0x15a: ieee80211_mgmt_output(*(g_ic+228), ret@b6, 208, 0, 0) */
    ieee80211_mgmt_output(*(g_ic+228), ret@b6, 208, 0, 0);
    /* site +0x160: cnx_start_obss_scan(ret@15a, ret@b6, 208, 0, 0) */
    cnx_start_obss_scan(ret@15a, ret@b6, 208, 0, 0);
    return opaque_result; /* full dataflow not recovered */
}

/* cnx_stop_obss_scan @ wl_cnx.o 0x00000008 size 46B bind GLOBAL
 * Calls: indirect(a8), indirect(a3) | Data refs: g_ic, g_osi_funcs_p
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 cnx_stop_obss_scan(u32 a2)
{
    /* frame: entry a1,32; 18 insns, 1 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0x2cc, 0 */
    /* first predicate: beqz.n a2, 32 <cnx_stop_obss_scan+0x2a> (condition opaque) */
    /* mem ld32: base=(lit:g_ic) off=16 */
    /* mem ld32: base=(*(g_ic+16)) off=228 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=236 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=240 */
    /* site +0x25: indirect call via a8 (base *(*(g_osi_funcs_p+0)+236)); args: /* no traced args */ */
    opaque_indirect_a8();
    /* site +0x2f: indirect call via a3 (base *(g_osi_funcs_p+240)); args: *(g_ic+228) */
    opaque_indirect_a3();
    return 0;
}

/* cnx_auth_done @ wl_cnx.o 0x00000124 size 1181B bind GLOBAL
 * Calls: memset, sta_get_owe_data, memcmp, sta_get_owe_data, wifi_log, wifi_nvs_set, wifi_nvs_commit, wifi_log, ieee80211_phy_mode_show, memcpy, wifi_log, ieee80211_cipher_name, ieee80211_cipher_name, wifi_log, cnx_remove_rc_except, cnx_clear_blacklist, indirect(a11), indirect(a11), pm_on_coex_schm_status_config, indirect(a10), pm_on_coex_schm_process_restart, memcpy, wifi_station_save_ap_channel, cnx_sta_pm, pm_wake_done, memcpy, memcpy, memcpy, indirect(a4), wifi_log, wifi_event_post, wifi_log, cnx_start_obss_scan | Data refs: .rodata.cnx_node_join.str1.1, .rodata.cnx_auth_done.str1.1, .rodata.cnx_sta_scan_cmd.str1.1, g_ic, g_wifi_nvs, g_cnxMgr, .rodata_wlog_debug.107, .rodata_wlog_warning.108, .rodata_wlog_info.109, .rodata.CSWTCH$289, .rodata.cnx_auth_done, .rodata_wlog_info.110, g_misc_nvs, g_osi_funcs_p, g_sta_connected_flag, g_mesh_init_ps_type, .rodata_wlog_debug.111, .rodata_wlog_debug.112
 * Fidelity: low - 432 insns, 32 branches, 0 loops; skeleton only */
u32 cnx_auth_done(u32 a3, u32 a5)
{
    /* frame: entry a1,176; 432 insns, 32 cond-branches, 0 loops, 32 jumps */
    /* immediates: 48, 0, 6, 4, 1, 46, 2, 32, 3, 17 */
    /* first predicate: beqz a2, 1c4 <cnx_auth_done+0xa0> (condition opaque) */
    /* mem ld32: base=(lit:g_wifi_nvs) off=0 */
    /* mem ld32: base=((lit:g_cnxMgr+983040)) off=96 */
    /* mem ld32: base=(lit:g_ic) off=16 */
    /* mem ld8: base=((*(g_wifi_nvs+0)+262144)) off=21 */
    /* mem ld32: base=(lit:g_wifi_nvs) off=0 */
    /* mem ld8: base=((*(g_wifi_nvs+0)+196608)) off=95 */
    /* mem ld32: base=(*(g_ic+16)) off=228 */
    /* mem ld8: base=(ret@183) off=84 */
    /* mem ld8: base=(ret@183) off=85 */
    /* mem ld8: base=((lit:g_ic+131072)) off=31 */
    /* ... +97 more memops */
    /* site +0x149: memset((?+32), 0, 48) */
    memset((?+32), 0, 48);
    /* site +0x155: sta_get_owe_data(ret@149, 0, 48) */
    sta_get_owe_data(ret@149, 0, 48);
    /* site +0x176: memcmp((ret@155+72), (*(*(g_ic+16)+228)+4), 6) */
    memcmp((ret@155+72), (*(*(g_ic+16)+228)+4), 6);
    /* site +0x183: sta_get_owe_data(ret@176, (*(*(g_ic+16)+228)+4), 6) */
    sta_get_owe_data(ret@176, (*(*(g_ic+16)+228)+4), 6);
    /* site +0x19e: wifi_log(1, 4, 4, lit:.rodata_wlog_debug.107) */
    wifi_log(1, 4, 4, lit:.rodata_wlog_debug.107);
    /* site +0x1b9: wifi_nvs_set(46, ret@19e, ret@176, lit:.rodata_wlog_debug.107) */
    wifi_nvs_set(46, ret@19e, ret@176, lit:.rodata_wlog_debug.107);
    /* site +0x1c1: wifi_nvs_commit(ret@1b9, ret@19e, ret@176, lit:.rodata_wlog_debug.107) */
    wifi_nvs_commit(ret@1b9, ret@19e, ret@176, lit:.rodata_wlog_debug.107);
    /* site +0x1e5: wifi_log(1, 4, 2, lit:.rodata_wlog_warning.108) */
    wifi_log(1, 4, 2, lit:.rodata_wlog_warning.108);
    /* site +0x1fd: ieee80211_phy_mode_show(*(*(g_ic+16)+228), (?+113), 2, lit:.rodata_wlog_warning.108) */
    ieee80211_phy_mode_show(*(*(g_ic+16)+228), (?+113), 2, lit:.rodata_wlog_warning.108);
    /* site +0x215: memcpy((?+80), (ret@155+4), 32, lit:.rodata_wlog_warning.108) */
    memcpy((?+80), (ret@155+4), 32, lit:.rodata_wlog_warning.108);
    /* site +0x26d: wifi_log(1, 4, 3, lit:.rodata_wlog_info.109, (?+80)) */
    wifi_log(1, 4, 3, lit:.rodata_wlog_info.109, (?+80));
    /* site +0x382: ieee80211_cipher_name(*((lit:g_ic+131072)+2), 4, 3, lit:.rodata_wlog_info.109, lit:.rodata.cnx_node_join.str1.1) */
    ieee80211_cipher_name(*((lit:g_ic+131072)+2), 4, 3, lit:.rodata_wlog_info.109, lit:.rodata.cnx_node_join.str1.1);
    /* site +0x393: ieee80211_cipher_name(*((lit:g_ic+131072)+4), 4, 3, lit:.rodata_wlog_info.109, lit:.rodata.cnx_node_join.str1.1) */
    ieee80211_cipher_name(*((lit:g_ic+131072)+4), 4, 3, lit:.rodata_wlog_info.109, lit:.rodata.cnx_node_join.str1.1);
    /* site +0x3c1: wifi_log(1, 4, 3, lit:.rodata_wlog_info.110, *(?+132)) */
    wifi_log(1, 4, 3, lit:.rodata_wlog_info.110, *(?+132));
    /* site +0x3c9: cnx_remove_rc_except(*(g_cnxMgr+96), 4, 3, lit:.rodata_wlog_info.110, *(?+132)) */
    cnx_remove_rc_except(*(g_cnxMgr+96), 4, 3, lit:.rodata_wlog_info.110, *(?+132));
    /* site +0x3cf: cnx_clear_blacklist(ret@3c9, 4, 3, lit:.rodata_wlog_info.110, *(?+132)) */
    cnx_clear_blacklist(ret@3c9, 4, 3, lit:.rodata_wlog_info.110, *(?+132));
    /* site +0x3f6: indirect call via a11 (base *(*(g_osi_funcs_p+0)+236)); args: (*(g_ic+16)+4), *(*(g_osi_funcs_p+0)+236), 3, lit:.rodata_wlog_info.110, *(?+132) */
    opaque_indirect_a11();
    /* site +0x406: indirect call via a11 (base *(*(g_osi_funcs_p+0)+240)); args: *(?+136), *(*(g_osi_funcs_p+0)+240), 3, lit:.rodata_wlog_info.110, *(?+132) */
    opaque_indirect_a11();
    /* site +0x40e: pm_on_coex_schm_status_config(0, *(*(g_osi_funcs_p+0)+240), 3, lit:.rodata_wlog_info.110, *(?+132)) */
    pm_on_coex_schm_status_config(0, *(*(g_osi_funcs_p+0)+240), 3, lit:.rodata_wlog_info.110, *(?+132));
    /* site +0x419: indirect call via a10 (base *(g_misc_nvs+0x194)); args: *(g_misc_nvs+0x194), *(*(g_osi_funcs_p+0)+240), 3, lit:.rodata_wlog_info.110, *(?+132) */
    opaque_indirect_a10();
    /* site +0x421: pm_on_coex_schm_process_restart(ret@419, *(*(g_osi_funcs_p+0)+240), 3, lit:.rodata_wlog_info.110, *(?+132)) */
    pm_on_coex_schm_process_restart(ret@419, *(*(g_osi_funcs_p+0)+240), 3, lit:.rodata_wlog_info.110, *(?+132));
    /* site +0x43d: memcpy(147, (*(*(g_ic+16)+228)+4), 6, lit:.rodata_wlog_info.110, *(?+132)) */
    memcpy(147, (*(*(g_ic+16)+228)+4), 6, lit:.rodata_wlog_info.110, *(?+132));
    /* site +0x449: wifi_station_save_ap_channel(*(g_misc_nvs+171), (*(*(g_ic+16)+228)+4), 6, lit:.rodata_wlog_info.110, *(?+132)) */
    wifi_station_save_ap_channel(*(g_misc_nvs+171), (*(*(g_ic+16)+228)+4), 6, lit:.rodata_wlog_info.110, *(?+132));
    /* site +0x485: cnx_sta_pm(1, *(g_cnxMgr+96), 6, lit:.rodata_wlog_info.110, *(?+132)) */
    cnx_sta_pm(1, *(g_cnxMgr+96), 6, lit:.rodata_wlog_info.110, *(?+132));
    /* site +0x48b: pm_wake_done(ret@485, *(g_cnxMgr+96), 6, lit:.rodata_wlog_info.110, *(?+132)) */
    pm_wake_done(ret@485, *(g_cnxMgr+96), 6, lit:.rodata_wlog_info.110, *(?+132));
    /* site +0x49a: memcpy(ret@48b, (ret@155+4), 32, lit:.rodata_wlog_info.110, *(?+132)) */
    memcpy(ret@48b, (ret@155+4), 32, lit:.rodata_wlog_info.110, *(?+132));
    /* site +0x4b5: memcpy((?+65), 156, 6, lit:.rodata_wlog_info.110, *(?+132)) */
    memcpy((?+65), 156, 6, lit:.rodata_wlog_info.110, *(?+132));
    /* site +0x547: memcpy(0x380, (ret@155+4), 32, lit:.rodata_wlog_info.110, *(?+132)) */
    memcpy(0x380, (ret@155+4), 32, lit:.rodata_wlog_info.110, *(?+132));
    /* site +0x566: indirect call via a4 (base *(*(g_ic+0x1b4)+12)); args: (*(g_cnxMgr+96)+4), (ret@155+4), 32, lit:.rodata_wlog_info.110, *(?+132) */
    opaque_indirect_a4();
    /* site +0x575: wifi_log(1, 4, 4, lit:.rodata_wlog_debug.111, *(?+132)) */
    wifi_log(1, 4, 4, lit:.rodata_wlog_debug.111, *(?+132));
    /* site +0x582: wifi_event_post(4, (?+32), 48, lit:.rodata_wlog_debug.111, *(?+132)) */
    wifi_event_post(4, (?+32), 48, lit:.rodata_wlog_debug.111, *(?+132));
    /* site +0x59b: wifi_log(1, 4, 4, lit:.rodata_wlog_debug.112, *((*(g_ic+16)+65536)+84)) */
    wifi_log(1, 4, 4, lit:.rodata_wlog_debug.112, *((*(g_ic+16)+65536)+84));
    /* site +0x5ba: cnx_start_obss_scan(ret@59b, 4, 4, lit:.rodata_wlog_debug.112, *((*(g_ic+16)+65536)+84)) */
    cnx_start_obss_scan(ret@59b, 4, 4, lit:.rodata_wlog_debug.112, *((*(g_ic+16)+65536)+84));
    return 1;
}

/* sta_reset_beacon_timeout @ wl_cnx.o 0x00000008 size 74B bind GLOBAL
 * Calls: indirect(a8), indirect(a2) | Data refs: g_ic, g_osi_funcs_p
 * Fidelity: medium - branchy but loop-free, call sequence mapped */
u32 sta_reset_beacon_timeout(u32 a2, u32 a5)
{
    /* frame: entry a1,32; 28 insns, 4 cond-branches, 0 loops, 0 jumps */
    /* first predicate: beqz.n a2, 50 <sta_reset_beacon_timeout+0x48> (condition opaque) */
    /* mem ld32: base=(lit:g_ic) off=16 */
    /* mem ld32: base=(*(g_ic+16)) off=228 */
    /* mem ld32: base=(*(g_ic+16)) off=152 */
    /* mem ld8: base=(*(g_ic+16)) off=148 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=236 */
    /* mem ld16: base=((*(g_ic+16)+131072)) off=58 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=232 */
    /* site +0x32: indirect call via a8 (base *(*(g_osi_funcs_p+0)+236)); args: (*(g_ic+16)+24) */
    opaque_indirect_a8();
    /* site +0x4d: indirect call via a2 (base *(g_ic+232)); args: (*(g_ic+16)+24), ((*(g_ic+58) slli 5) slli 3), *(g_ic+148) */
    opaque_indirect_a2();
    return opaque_result; /* full dataflow not recovered */
}

/* ieee80211_get_nvs_sta_inactive_time @ wl_cnx.o 0x00000004 size 16B bind GLOBAL
 * Calls: none | Data refs: g_wifi_nvs
 * Fidelity: high - straight-line, fully mapped (6 insns) */
u32 ieee80211_get_nvs_sta_inactive_time(void)
{
    /* frame: entry a1,32; 6 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* mem ld32: base=(lit:g_wifi_nvs) off=0 */
    /* mem ld16: base=((*(g_wifi_nvs+0)+262144)) off=166 */
    return opaque_result; /* full dataflow not recovered */
}

/* sta_get_beacon_timeout @ wl_cnx.o 0x00000008 size 45B bind GLOBAL
 * Calls: none | Data refs: g_ic, g_wifi_nvs
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 sta_get_beacon_timeout(u32 a2)
{
    /* frame: entry a1,32; 16 insns, 3 cond-branches, 0 loops, 1 jumps */
    /* first predicate: beqz.n a8, 28 <sta_get_beacon_timeout+0x20> (condition opaque) */
    /* mem ld32: base=(lit:g_ic) off=16 */
    /* mem ld32: base=(*(g_ic+16)) off=228 */
    /* mem ld32: base=(*(g_ic+16)) off=152 */
    /* mem ld16: base=((*(g_ic+16)+131072)) off=58 */
    /* mem ld32: base=(lit:g_wifi_nvs) off=0 */
    /* mem ld16: base=((*(g_wifi_nvs+0)+262144)) off=166 */
    return opaque_result; /* full dataflow not recovered */
}
