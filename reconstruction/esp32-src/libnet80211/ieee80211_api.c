/* ieee80211_api.o - reconstructed control-path C (offline, from objdump -d -r).
 * 236 code sections recovered. Fidelity per function below.
 * Conventions: args a2..a7 (Xtensa windowed ABI); outgoing call args
 * traced as a10..; u32 used for pointers/regs; opaque_* marks unrecovered.
 */
#include <stdint.h>
typedef unsigned char u8; typedef unsigned short u16; typedef unsigned int u32;
static u32 opaque_result, last_call_result;
/* ---- externals (U symbols + literal refs) ---- */
extern u32 bss_old_scan_id_2; /* .bss.old_scan_id$2 */
extern u32 bss_s_mesh_fetch_num; /* .bss.s_mesh_fetch_num */
extern u32 bss_s_mesh_sort_bss; /* .bss.s_mesh_sort_bss */
extern u32 bss_s_mesh_sort_num; /* .bss.s_mesh_sort_num */
extern u32 bss_sort_bss_1; /* .bss.sort_bss$1 */
extern u32 bss_token_0; /* .bss.token$0 */
extern u32 data_s_wifi_init_state; /* .data.s_wifi_init_state */
extern u32 rodata_CSWTCH_548; /* .rodata.CSWTCH$548 */
extern u32 rodata_esp_wifi_init_internal_str1_1; /* .rodata.esp_wifi_init_internal.str1.1 */
extern u32 rodata_esp_wifi_internal_crypto_funcs_md5_check_str1_1; /* .rodata.esp_wifi_internal_crypto_funcs_md5_check.str1.1 */
extern u32 rodata_esp_wifi_internal_esp_wifi_he_md5_check_str1_1; /* .rodata.esp_wifi_internal_esp_wifi_he_md5_check.str1.1 */
extern u32 rodata_esp_wifi_internal_esp_wifi_md5_check_str1_1; /* .rodata.esp_wifi_internal_esp_wifi_md5_check.str1.1 */
extern u32 rodata_esp_wifi_internal_osi_funcs_md5_check_str1_1; /* .rodata.esp_wifi_internal_osi_funcs_md5_check.str1.1 */
extern u32 rodata_esp_wifi_internal_wifi_he_type_md5_check_str1_1; /* .rodata.esp_wifi_internal_wifi_he_type_md5_check.str1.1 */
extern u32 rodata_esp_wifi_internal_wifi_type_md5_check_str1_1; /* .rodata.esp_wifi_internal_wifi_type_md5_check.str1.1 */
extern u32 rodata_esp_wifi_nan_load_saved_creds_str1_1; /* .rodata.esp_wifi_nan_load_saved_creds.str1.1 */
extern u32 rodata_esp_wifi_set_protocol; /* .rodata.esp_wifi_set_protocol */
extern u32 rodata_wifi_get_user_ie; /* .rodata.wifi_get_user_ie */
extern u32 rodata_wifi_osi_funcs_register_str1_1; /* .rodata.wifi_osi_funcs_register.str1.1 */
extern u32 rodata_wlog_error_11; /* .rodata_wlog_error.11 */
extern u32 rodata_wlog_error_12; /* .rodata_wlog_error.12 */
extern u32 rodata_wlog_error_13; /* .rodata_wlog_error.13 */
extern u32 rodata_wlog_error_15; /* .rodata_wlog_error.15 */
extern u32 rodata_wlog_error_18; /* .rodata_wlog_error.18 */
extern u32 rodata_wlog_error_19; /* .rodata_wlog_error.19 */
extern u32 rodata_wlog_error_23; /* .rodata_wlog_error.23 */
extern u32 rodata_wlog_error_24; /* .rodata_wlog_error.24 */
extern u32 rodata_wlog_error_25; /* .rodata_wlog_error.25 */
extern u32 rodata_wlog_error_26; /* .rodata_wlog_error.26 */
extern u32 rodata_wlog_error_30; /* .rodata_wlog_error.30 */
extern u32 rodata_wlog_error_31; /* .rodata_wlog_error.31 */
extern u32 rodata_wlog_error_5; /* .rodata_wlog_error.5 */
extern u32 rodata_wlog_error_55; /* .rodata_wlog_error.55 */
extern u32 rodata_wlog_error_56; /* .rodata_wlog_error.56 */
extern u32 rodata_wlog_error_57; /* .rodata_wlog_error.57 */
extern u32 rodata_wlog_error_58; /* .rodata_wlog_error.58 */
extern u32 rodata_wlog_error_59; /* .rodata_wlog_error.59 */
extern u32 rodata_wlog_error_60; /* .rodata_wlog_error.60 */
extern u32 rodata_wlog_error_61; /* .rodata_wlog_error.61 */
extern u32 rodata_wlog_error_71; /* .rodata_wlog_error.71 */
extern u32 rodata_wlog_error_72; /* .rodata_wlog_error.72 */
extern u32 rodata_wlog_error_73; /* .rodata_wlog_error.73 */
extern u32 rodata_wlog_error_8; /* .rodata_wlog_error.8 */
extern u32 rodata_wlog_info_34; /* .rodata_wlog_info.34 */
extern u32 rodata_wlog_info_35; /* .rodata_wlog_info.35 */
extern u32 rodata_wlog_info_36; /* .rodata_wlog_info.36 */
extern u32 rodata_wlog_info_37; /* .rodata_wlog_info.37 */
extern u32 rodata_wlog_info_63; /* .rodata_wlog_info.63 */
extern u32 rodata_wlog_info_65; /* .rodata_wlog_info.65 */
extern u32 rodata_wlog_info_66; /* .rodata_wlog_info.66 */
extern u32 rodata_wlog_info_67; /* .rodata_wlog_info.67 */
extern u32 rodata_wlog_info_70; /* .rodata_wlog_info.70 */
extern u32 rodata_wlog_verbose_21; /* .rodata_wlog_verbose.21 */
extern u32 rodata_wlog_verbose_22; /* .rodata_wlog_verbose.22 */
extern u32 rodata_wlog_warning_10; /* .rodata_wlog_warning.10 */
extern u32 rodata_wlog_warning_16; /* .rodata_wlog_warning.16 */
extern u32 rodata_wlog_warning_17; /* .rodata_wlog_warning.17 */
extern u32 rodata_wlog_warning_20; /* .rodata_wlog_warning.20 */
extern u32 rodata_wlog_warning_32; /* .rodata_wlog_warning.32 */
extern u32 rodata_wlog_warning_33; /* .rodata_wlog_warning.33 */
extern u32 rodata_wlog_warning_38; /* .rodata_wlog_warning.38 */
extern u32 rodata_wlog_warning_39; /* .rodata_wlog_warning.39 */
extern u32 rodata_wlog_warning_4; /* .rodata_wlog_warning.4 */
extern u32 rodata_wlog_warning_40; /* .rodata_wlog_warning.40 */
extern u32 rodata_wlog_warning_41; /* .rodata_wlog_warning.41 */
extern u32 rodata_wlog_warning_42; /* .rodata_wlog_warning.42 */
extern u32 rodata_wlog_warning_43; /* .rodata_wlog_warning.43 */
extern u32 rodata_wlog_warning_44; /* .rodata_wlog_warning.44 */
extern u32 rodata_wlog_warning_45; /* .rodata_wlog_warning.45 */
extern u32 rodata_wlog_warning_46; /* .rodata_wlog_warning.46 */
extern u32 rodata_wlog_warning_47; /* .rodata_wlog_warning.47 */
extern u32 rodata_wlog_warning_48; /* .rodata_wlog_warning.48 */
extern u32 rodata_wlog_warning_49; /* .rodata_wlog_warning.49 */
extern u32 rodata_wlog_warning_50; /* .rodata_wlog_warning.50 */
extern u32 rodata_wlog_warning_51; /* .rodata_wlog_warning.51 */
extern u32 rodata_wlog_warning_52; /* .rodata_wlog_warning.52 */
extern u32 rodata_wlog_warning_53; /* .rodata_wlog_warning.53 */
extern u32 rodata_wlog_warning_54; /* .rodata_wlog_warning.54 */
extern u32 rodata_wlog_warning_6; /* .rodata_wlog_warning.6 */
extern u32 rodata_wlog_warning_64; /* .rodata_wlog_warning.64 */
extern u32 rodata_wlog_warning_68; /* .rodata_wlog_warning.68 */
extern u32 rodata_wlog_warning_69; /* .rodata_wlog_warning.69 */
extern u32 rodata_wlog_warning_7; /* .rodata_wlog_warning.7 */
extern u32 rodata_wlog_warning_9; /* .rodata_wlog_warning.9 */
extern u32 WIFI_EVENT; /* WIFI_EVENT */
extern u32 WIFI_MESH_EVENT; /* WIFI_MESH_EVENT */
extern u32 chip_v7_set_chan_misc(); /* chip_v7_set_chan_misc */
extern u32 chm_get_current_band(); /* chm_get_current_band */
extern u32 chm_get_current_channel(); /* chm_get_current_channel */
extern u32 chm_get_snd_chan_mode(); /* chm_get_snd_chan_mode */
extern u32 current_task_is_wifi_task(); /* current_task_is_wifi_task */
extern u32 dbg_hmac_statis_dump(); /* dbg_hmac_statis_dump */
extern u32 dbg_lmac_statis_dump(); /* dbg_lmac_statis_dump */
extern u32 esp_mesh_ps_duty; /* esp_mesh_ps_duty */
extern u32 esp_mesh_quick_funcs; /* esp_mesh_quick_funcs */
extern u32 esp_wifi_ap_get_sta_aid_local; /* esp_wifi_ap_get_sta_aid_local */
extern u32 esp_wifi_band_get_config_channel_local; /* esp_wifi_band_get_config_channel_local */
extern u32 esp_wifi_deauthenticate_internal(); /* esp_wifi_deauthenticate_internal */
extern u32 esp_wifi_ftm_end_session_local; /* esp_wifi_ftm_end_session_local */
extern u32 esp_wifi_ftm_get_report_local; /* esp_wifi_ftm_get_report_local */
extern u32 esp_wifi_ftm_resp_set_offset_local; /* esp_wifi_ftm_resp_set_offset_local */
extern u32 esp_wifi_get_config_channel_local; /* esp_wifi_get_config_channel_local */
extern u32 esp_wifi_get_inactive_time_local; /* esp_wifi_get_inactive_time_local */
extern u32 esp_wifi_get_negotiated_bw_local; /* esp_wifi_get_negotiated_bw_local */
extern u32 esp_wifi_get_negotiated_channel_local; /* esp_wifi_get_negotiated_channel_local */
extern u32 esp_wifi_internal_reg_netstack_buf_cb_local; /* esp_wifi_internal_reg_netstack_buf_cb_local */
extern u32 esp_wifi_send_deauth_local; /* esp_wifi_send_deauth_local */
extern u32 esp_wifi_set_inactive_time_local; /* esp_wifi_set_inactive_time_local */
extern u32 esp_wifi_sta_get_aid_local; /* esp_wifi_sta_get_aid_local */
extern u32 esp_wifi_sta_get_negotiated_phymode_local; /* esp_wifi_sta_get_negotiated_phymode_local */
extern u32 free_bss_info(); /* free_bss_info */
extern u32 g_chm; /* g_chm */
extern u32 g_esp_wifi_he_md5; /* g_esp_wifi_he_md5 */
extern u32 g_esp_wifi_md5; /* g_esp_wifi_md5 */
extern u32 g_ic; /* g_ic */
extern u32 g_ic_0x130; /* g_ic+0x130 */
extern u32 g_ic_0x88; /* g_ic+0x88 */
extern u32 g_intr_lock_mux; /* g_intr_lock_mux */
extern u32 g_log_level; /* g_log_level */
extern u32 g_log_mod; /* g_log_mod */
extern u32 g_mesh_init_ps_type; /* g_mesh_init_ps_type */
extern u32 g_mesh_is_root; /* g_mesh_is_root */
extern u32 g_mesh_is_started; /* g_mesh_is_started */
extern u32 g_mesh_root_conflicts_allowed; /* g_mesh_root_conflicts_allowed */
extern u32 g_mesh_topology; /* g_mesh_topology */
extern u32 g_osi_funcs_p; /* g_osi_funcs_p */
extern u32 g_wifi_crypto_funcs_md5; /* g_wifi_crypto_funcs_md5 */
extern u32 g_wifi_event_mask; /* g_wifi_event_mask */
extern u32 g_wifi_global_lock; /* g_wifi_global_lock */
extern u32 g_wifi_he_type_md5; /* g_wifi_he_type_md5 */
extern u32 g_wifi_improve_contention_ability; /* g_wifi_improve_contention_ability */
extern u32 g_wifi_mac_time_delta; /* g_wifi_mac_time_delta */
extern u32 g_wifi_menuconfig; /* g_wifi_menuconfig */
extern u32 g_wifi_nvs; /* g_wifi_nvs */
extern u32 g_wifi_osi_funcs_md5; /* g_wifi_osi_funcs_md5 */
extern u32 g_wifi_type_md5; /* g_wifi_type_md5 */
extern u32 hostap_input; /* hostap_input */
extern u32 ic_beacon_monitor_configure(); /* ic_beacon_monitor_configure */
extern u32 ic_beacon_offset_configure(); /* ic_beacon_offset_configure */
extern u32 ic_beacon_offset_set_rx_beacon_standard(); /* ic_beacon_offset_set_rx_beacon_standard */
extern u32 ic_create_wifi_task(); /* ic_create_wifi_task */
extern u32 ic_delete_wifi_task(); /* ic_delete_wifi_task */
extern u32 ic_get_fix_rate(); /* ic_get_fix_rate */
extern u32 ic_get_promis_ctrl_filter(); /* ic_get_promis_ctrl_filter */
extern u32 ic_get_promis_filter(); /* ic_get_promis_filter */
extern u32 ic_register_csi_rx_cb(); /* ic_register_csi_rx_cb */
extern u32 ic_register_pp_tx_done_cb(); /* ic_register_pp_tx_done_cb */
extern u32 ic_register_promis_rx_cb(); /* ic_register_promis_rx_cb */
extern u32 ic_set_80211_tx_rate(); /* ic_set_80211_tx_rate */
extern u32 ic_set_80211_tx_rate_config(); /* ic_set_80211_tx_rate_config */
extern u32 ic_set_bar_rate(); /* ic_set_bar_rate */
extern u32 ic_set_keep_alive_time(); /* ic_set_keep_alive_time */
extern u32 ic_set_sleep_min_active_time(); /* ic_set_sleep_min_active_time */
extern u32 ic_set_sleep_wait_broadcast_data_time(); /* ic_set_sleep_wait_broadcast_data_time */
extern u32 ic_trc_update_def_rate(); /* ic_trc_update_def_rate */
extern u32 ic_update_light_sleep_default_params(); /* ic_update_light_sleep_default_params */
extern u32 ic_update_modem_sleep_default_params(); /* ic_update_modem_sleep_default_params */
extern u32 ieee80211_add_ie_vendor_esp_head(); /* ieee80211_add_ie_vendor_esp_head */
extern u32 ieee80211_ethbroadcast; /* ieee80211_ethbroadcast */
extern u32 ieee80211_ioctl(); /* ieee80211_ioctl */
extern u32 ieee80211_ioctl_deinit(); /* ieee80211_ioctl_deinit */
extern u32 ieee80211_ioctl_init(); /* ieee80211_ioctl_init */
extern u32 ieee80211_reg_netstack_buf_cb(); /* ieee80211_reg_netstack_buf_cb */
extern u32 ieee80211_regdomain_ap_min_chan(); /* ieee80211_regdomain_ap_min_chan */
extern u32 ieee80211_regdomain_chan_num(); /* ieee80211_regdomain_chan_num */
extern u32 ieee80211_regdomain_check_ap_channel(); /* ieee80211_regdomain_check_ap_channel */
extern u32 ieee80211_regdomain_check_channel(); /* ieee80211_regdomain_check_channel */
extern u32 ieee80211_regdomain_get_country_info(); /* ieee80211_regdomain_get_country_info */
extern u32 ieee80211_regdomain_policy(); /* ieee80211_regdomain_policy */
extern u32 ieee80211_register_hostap_timer(); /* ieee80211_register_hostap_timer */
extern u32 mac_list_lock; /* mac_list_lock */
extern u32 map_assoc_expire; /* map_assoc_expire */
extern u32 memcmp(); /* memcmp */
extern u32 memcpy(); /* memcpy */
extern u32 memmove(); /* memmove */
extern u32 memset(); /* memset */
extern u32 mesh_rxcb; /* mesh_rxcb */
extern u32 misc_nvs_deinit(); /* misc_nvs_deinit */
extern u32 misc_nvs_init(); /* misc_nvs_init */
extern u32 nan_get_config_local(); /* nan_get_config_local */
extern u32 net80211_funcs; /* net80211_funcs */
extern u32 net80211_printf(); /* net80211_printf */
extern u32 phy_get_most_tpw(); /* phy_get_most_tpw */
extern u32 pm_funcs_deinit(); /* pm_funcs_deinit */
extern u32 pm_funcs_init(); /* pm_funcs_init */
extern u32 pm_get_sleep_type(); /* pm_get_sleep_type */
extern u32 puts(); /* puts */
extern u32 register_chipv7_phy_init_param(); /* register_chipv7_phy_init_param */
extern u32 reset_cs_thres(); /* reset_cs_thres */
extern u32 s_ni; /* s_ni */
extern u32 s_wifi_api_lock; /* s_wifi_api_lock */
extern u32 s_wifi_stop_in_progress; /* s_wifi_stop_in_progress */
extern u32 scan_get_apnum(); /* scan_get_apnum */
extern u32 scan_get_scan_id(); /* scan_get_scan_id */
extern u32 scan_set_scan_id(); /* scan_set_scan_id */
extern u32 strlen(); /* strlen */
extern u32 strncmp(); /* strncmp */
extern u32 wifi_ap_remove_sta_node_process; /* wifi_ap_remove_sta_node_process */
extern u32 wifi_clear_ap_list_process; /* wifi_clear_ap_list_process */
extern u32 wifi_coex_pwr_process; /* wifi_coex_pwr_process */
extern u32 wifi_configure_wake_interval_process; /* wifi_configure_wake_interval_process */
extern u32 wifi_configure_wake_window_process; /* wifi_configure_wake_window_process */
extern u32 wifi_connect_process; /* wifi_connect_process */
extern u32 wifi_create_softap; /* wifi_create_softap */
extern u32 wifi_csi_set_config; /* wifi_csi_set_config */
extern u32 wifi_deauth_sta_process; /* wifi_deauth_sta_process */
extern u32 wifi_deinit_process; /* wifi_deinit_process */
extern u32 wifi_destroy_softap; /* wifi_destroy_softap */
extern u32 wifi_disable_pmf_config_process; /* wifi_disable_pmf_config_process */
extern u32 wifi_disconnect_process; /* wifi_disconnect_process */
extern u32 wifi_force_wakeup_process; /* wifi_force_wakeup_process */
extern u32 wifi_get_ap_info_process; /* wifi_get_ap_info_process */
extern u32 wifi_get_ap_list_process; /* wifi_get_ap_list_process */
extern u32 wifi_get_ap_record_process; /* wifi_get_ap_record_process */
extern u32 wifi_get_bw_process; /* wifi_get_bw_process */
extern u32 wifi_get_channel_process; /* wifi_get_channel_process */
extern u32 wifi_get_country; /* wifi_get_country */
extern u32 wifi_get_home_channel_process; /* wifi_get_home_channel_process */
extern u32 wifi_get_macaddr(); /* wifi_get_macaddr */
extern u32 wifi_get_protocol_process; /* wifi_get_protocol_process */
extern u32 wifi_get_protocols_process; /* wifi_get_protocols_process */
extern u32 wifi_get_scan_params_process; /* wifi_get_scan_params_process */
extern u32 wifi_get_sta_list_process; /* wifi_get_sta_list_process */
extern u32 wifi_get_tsf_time_process(); /* wifi_get_tsf_time_process */
extern u32 wifi_init_process; /* wifi_init_process */
extern u32 wifi_internal_ioctl_process; /* wifi_internal_ioctl_process */
extern u32 wifi_ipc_process; /* wifi_ipc_process */
extern u32 wifi_log(); /* wifi_log */
extern u32 wifi_menuconfig_init(); /* wifi_menuconfig_init */
extern u32 wifi_mesh_act_duty_signaling_process; /* wifi_mesh_act_duty_signaling_process */
extern u32 wifi_mesh_assoc_expire_set_progress; /* wifi_mesh_assoc_expire_set_progress */
extern u32 wifi_mesh_ie_crypto_funcs_set_progress; /* wifi_mesh_ie_crypto_funcs_set_progress */
extern u32 wifi_mesh_ie_crypto_key_set_progress; /* wifi_mesh_ie_crypto_key_set_progress */
extern u32 wifi_mesh_ie_deinit_progress; /* wifi_mesh_ie_deinit_progress */
extern u32 wifi_mesh_ie_get_progress; /* wifi_mesh_ie_get_progress */
extern u32 wifi_mesh_ie_init_progress; /* wifi_mesh_ie_init_progress */
extern u32 wifi_mesh_ie_set_progress; /* wifi_mesh_ie_set_progress */
extern u32 wifi_mesh_is_roots_found_progress; /* wifi_mesh_is_roots_found_progress */
extern u32 wifi_mesh_parent_candidate_clear_progress; /* wifi_mesh_parent_candidate_clear_progress */
extern u32 wifi_mesh_parent_candidate_get_progress; /* wifi_mesh_parent_candidate_get_progress */
extern u32 wifi_mesh_parent_candidate_set_progress; /* wifi_mesh_parent_candidate_set_progress */
extern u32 wifi_mesh_parent_monitor_get_progress; /* wifi_mesh_parent_monitor_get_progress */
extern u32 wifi_mesh_parent_monitor_set_progress; /* wifi_mesh_parent_monitor_set_progress */
extern u32 wifi_mesh_ps_duty_cycle_get_process; /* wifi_mesh_ps_duty_cycle_get_process */
extern u32 wifi_mesh_ps_duty_cycle_set_process; /* wifi_mesh_ps_duty_cycle_set_process */
extern u32 wifi_mesh_ps_duty_ext_get_process; /* wifi_mesh_ps_duty_ext_get_process */
extern u32 wifi_mesh_root_conflicts_set_progress; /* wifi_mesh_root_conflicts_set_progress */
extern u32 wifi_mesh_roots_ie_get_progress; /* wifi_mesh_roots_ie_get_progress */
extern u32 wifi_mesh_roots_ie_set_progress; /* wifi_mesh_roots_ie_set_progress */
extern u32 wifi_mesh_router_bssid_get_progress; /* wifi_mesh_router_bssid_get_progress */
extern u32 wifi_mesh_router_bssid_set_progress; /* wifi_mesh_router_bssid_set_progress */
extern u32 wifi_mesh_rssi_threshold_get_progress; /* wifi_mesh_rssi_threshold_get_progress */
extern u32 wifi_mesh_rssi_threshold_set_progress; /* wifi_mesh_rssi_threshold_set_progress */
extern u32 wifi_mesh_set_beacon_interval_progress; /* wifi_mesh_set_beacon_interval_progress */
extern u32 wifi_mesh_sta_disassoc_progress; /* wifi_mesh_sta_disassoc_progress */
extern u32 wifi_mesh_switch_channel_progress; /* wifi_mesh_switch_channel_progress */
extern u32 wifi_nan_config_process; /* wifi_nan_config_process */
extern u32 wifi_nan_followup_process; /* wifi_nan_followup_process */
extern u32 wifi_nan_publish_process; /* wifi_nan_publish_process */
extern u32 wifi_nan_subscribe_process; /* wifi_nan_subscribe_process */
extern u32 wifi_ndp_end_process; /* wifi_ndp_end_process */
extern u32 wifi_ndp_req_process; /* wifi_ndp_req_process */
extern u32 wifi_ndp_resp_process; /* wifi_ndp_resp_process */
extern u32 wifi_nvs_commit(); /* wifi_nvs_commit */
extern u32 wifi_nvs_get(); /* wifi_nvs_get */
extern u32 wifi_nvs_set(); /* wifi_nvs_set */
extern u32 wifi_offchan_cancel_process; /* wifi_offchan_cancel_process */
extern u32 wifi_on_coex_schm_phase_process; /* wifi_on_coex_schm_phase_process */
extern u32 wifi_on_coex_start_process; /* wifi_on_coex_start_process */
extern u32 wifi_restart_process; /* wifi_restart_process */
extern u32 wifi_restore_process; /* wifi_restore_process */
extern u32 wifi_sample_beacon_process; /* wifi_sample_beacon_process */
extern u32 wifi_scan_start_process; /* wifi_scan_start_process */
extern u32 wifi_scan_stop_process; /* wifi_scan_stop_process */
extern u32 wifi_set_auto_connect_process; /* wifi_set_auto_connect_process */
extern u32 wifi_set_band_mode_process; /* wifi_set_band_mode_process */
extern u32 wifi_set_band_process; /* wifi_set_band_process */
extern u32 wifi_set_bw_process; /* wifi_set_bw_process */
extern u32 wifi_set_channel_process; /* wifi_set_channel_process */
extern u32 wifi_set_config_process; /* wifi_set_config_process */
extern u32 wifi_set_country; /* wifi_set_country */
extern u32 wifi_set_csi; /* wifi_set_csi */
extern u32 wifi_set_default_ssid(); /* wifi_set_default_ssid */
extern u32 wifi_set_dynamic_cs_process; /* wifi_set_dynamic_cs_process */
extern u32 wifi_set_event_mask; /* wifi_set_event_mask */
extern u32 wifi_set_fix_rate_process; /* wifi_set_fix_rate_process */
extern u32 wifi_set_home_channel_process; /* wifi_set_home_channel_process */
extern u32 wifi_set_log_mod_process; /* wifi_set_log_mod_process */
extern u32 wifi_set_mac_process; /* wifi_set_mac_process */
extern u32 wifi_set_max_tpw; /* wifi_set_max_tpw */
extern u32 wifi_set_mode_process; /* wifi_set_mode_process */
extern u32 wifi_set_promis_ctrl_filter_process; /* wifi_set_promis_ctrl_filter_process */
extern u32 wifi_set_promis_filter_process; /* wifi_set_promis_filter_process */
extern u32 wifi_set_promis_process; /* wifi_set_promis_process */
extern u32 wifi_set_protocol_process; /* wifi_set_protocol_process */
extern u32 wifi_set_ps_process; /* wifi_set_ps_process */
extern u32 wifi_set_rxcb_process; /* wifi_set_rxcb_process */
extern u32 wifi_set_scan_params_process; /* wifi_set_scan_params_process */
extern u32 wifi_set_vnd_ie_cb_process; /* wifi_set_vnd_ie_cb_process */
extern u32 wifi_set_vnd_ie_cb_with_ret_process; /* wifi_set_vnd_ie_cb_with_ret_process */
extern u32 wifi_set_vnd_ie_process; /* wifi_set_vnd_ie_process */
extern u32 wifi_softap_get_config; /* wifi_softap_get_config */
extern u32 wifi_softap_max_support_num(); /* wifi_softap_max_support_num */
extern u32 wifi_softap_set_config; /* wifi_softap_set_config */
extern u32 wifi_softap_set_obss_overlap_process; /* wifi_softap_set_obss_overlap_process */
extern u32 wifi_softap_start; /* wifi_softap_start */
extern u32 wifi_softap_stop; /* wifi_softap_stop */
extern u32 wifi_sta_rx_probe_req; /* wifi_sta_rx_probe_req */
extern u32 wifi_start_process; /* wifi_start_process */
extern u32 wifi_stop_process; /* wifi_stop_process */
extern u32 wifi_tbtt_quick_wake_configure_process; /* wifi_tbtt_quick_wake_configure_process */
extern u32 wifi_update_listen_interval_process; /* wifi_update_listen_interval_process */

/* ROLE: public esp_wifi_* / esp_mesh_* / esp_nan_* API shims (caller task).
 * Recurring stub pattern (verify per function below): wifi_init_completed() gate
 * (failure -> return 0x101/0x102-class code); state/arg validation against
 * g_wifi_nvs / g_ic / g_osi_funcs_p; then either (a) synchronous path through
 * ieee80211_ioctl(req) via g_osi_funcs_p slot +176/+68 indirection, or
 * (b) async path building a request block and pp_post(type 6, ...).
 * Direction per ESP-IDF wifi_init.c/esp_wifi.h: esp_wifi_init/connect call down
 * into these stubs, which IPC into the WiFi task (wifi_*_process handlers in
 * ieee80211_ioctl.o). Blob internals below are from disasm only.
 */
/* ---- literal-rooted access patterns (offsets observed; layout NOT confirmed) ----
 * (?+-1): u32+0
 * *(*(*(g_ic+16)+228)+172): u8+236, u16+236
 * *(*(g_ic+0x130+0)+52): u8+15
 * *(*(g_ic+16)+228): u32+172
 * *(*(g_osi_funcs_p+0)+176): u32+0
 * *(?+4): u8+236, u16+236
 * *(g_ic+0x130+0): u8+52
 * *(g_ic+16): u8+228
 * *(g_osi_funcs_p+0): u8+176, u32+176
 * *(g_wifi_nvs+0): u32+144
 * .bss.old_scan_id$2: u8+0
 * .bss.s_mesh_fetch_num: u32+0, u16+0
 * .bss.s_mesh_sort_bss: u32+0
 * .bss.s_mesh_sort_num: u16+0
 * .bss.sort_bss$1: u32+0, u8+52
 * .bss.token$0: u32+0
 * .data.s_wifi_init_state: u32+0
 * .rodata.CSWTCH$548: u32+0
 * ?: u32+0, u16+4, u32+4, u32+8, u8+44, u16+236
 * WIFI_EVENT: u32+0
 * WIFI_MESH_EVENT: u32+0
 * esp_mesh_ps_duty: u8+0, u8+1
 * esp_mesh_quick_funcs: u32+112
 * g_chm: u32+0, u8+0
 * g_esp_wifi_he_md5: u32+0
 * g_esp_wifi_md5: u32+0
 * g_ic: u32+0, u32+4, u32+16, u32+16, u32+20, u32+20, u32+116, u32+136, u32+136, u32+140, u32+144, u32+148, u8+228, u16+228 (+4 more)
 * g_intr_lock_mux: u32+0
 * g_log_level: u32+0
 * g_mesh_init_ps_type: u32+0
 * g_mesh_is_root: u8+0
 * g_mesh_is_started: u8+0, u32+0
 * g_mesh_root_conflicts_allowed: u8+0
 * g_mesh_topology: u32+0
 * g_osi_funcs_p: u32+0, u32+0, u32+176
 * g_wifi_crypto_funcs_md5: u32+0
 * g_wifi_event_mask: u32+0
 * g_wifi_global_lock: u32+0, u32+0, u8+0
 * g_wifi_he_type_md5: u32+0
 * g_wifi_mac_time_delta: u32+0
 * g_wifi_menuconfig: u32+24
 * g_wifi_nvs: u32+0, u8+0, u32+116
 * g_wifi_osi_funcs_md5: u32+0
 * g_wifi_type_md5: u32+0
 * mac_list_lock: u32+0
 * map_assoc_expire: u32+0
 * net80211_funcs: u32+0, u32+0
 * s_ni: u32+320
 * s_wifi_api_lock: u32+0
 * s_wifi_stop_in_progress: u8+0
/* ---- funcdb-v2 cross-check (calls[] vs section relocs; disasm is ground truth) ----
 * confirmed funcdb edges: 456; rejected funcdb-only (no exact reloc in
 * callee section; caller-side .rela.text.<f> prefix-collision artifacts): 0;
 * disasm-only edges kept (static-local callees + funcdb relsec:null gaps): 11;
 *   e.g. wifi_station_get_config->.text.wifi_station_get_config_local, esp_wifi_get_config->.text.wifi_station_get_config_local, esp_wifi_nan_load_saved_creds->.text.nan_key_is_all_ff$constprop$0, esp_wifi_nan_save_creds_for_peer->.text.nan_key_is_all_ff$constprop$0
 */
/* ==== functions of ieee80211_api.o ==== */

/* esp_wifi_ftm_end_session_local @ ieee80211_api.o 0x00000000 size 7B bind GLOBAL
 * Calls: none | Data refs: none
 * Fidelity: high - straight-line, fully mapped (3 insns) */
u32 esp_wifi_ftm_end_session_local(void)
{
    /* frame: entry a1,32; 3 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0 */
    return 0;
}

/* esp_wifi_ftm_resp_set_offset_local @ ieee80211_api.o 0x00000000 size 8B bind GLOBAL
 * Calls: none | Data refs: none
 * Fidelity: high - straight-line, fully mapped (3 insns) */
u32 esp_wifi_ftm_resp_set_offset_local(void)
{
    /* frame: entry a1,32; 3 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0x106 */
    return 0x106;
}

/* esp_wifi_get_config_channel_local @ ieee80211_api.o 0x00000004 size 128B bind GLOBAL
 * Calls: none | Data refs: g_wifi_nvs
 * Fidelity: medium - branchy but loop-free, call sequence mapped */
u32 esp_wifi_get_config_channel_local(u32 a2)
{
    /* frame: entry a1,32; 46 insns, 7 cond-branches, 0 loops, 3 jumps */
    /* immediates: 1, 0, -3, 0x102 */
    /* first predicate: bgeui a10, 3, 14 <esp_wifi_get_config_channel_local+0x10> (condition opaque) */
    /* mem ld32: base=(?) off=0 */
    /* mem ld32: base=(?) off=12 */
    /* mem ld32: base=(?) off=16 */
    /* mem ld32: base=(lit:g_wifi_nvs) off=0 */
    /* mem ld8: base=(*(g_wifi_nvs+0)) off=0 */
    /* mem ld8: base=(*(g_wifi_nvs+0)) off=144 */
    /* mem st8: base=(*(?+12)) off=0 */
    /* mem st8: base=(*(?+16)) off=0 */
    /* mem ld8: base=((*(g_wifi_nvs+0)+196608)) off=243 */
    /* mem st8: base=(*(?+12)) off=0 */
    /* ... +3 more memops */
    return 0;
}

/* esp_wifi_band_get_config_channel_local @ ieee80211_api.o 0x00000004 size 158B bind GLOBAL
 * Calls: none | Data refs: g_wifi_nvs
 * Fidelity: medium - branchy but loop-free, call sequence mapped */
u32 esp_wifi_band_get_config_channel_local(u32 a2)
{
    /* frame: entry a1,32; 56 insns, 9 cond-branches, 0 loops, 5 jumps */
    /* immediates: 1, 0, -3, 0x102 */
    /* first predicate: bgeui a10, 3, 14 <esp_wifi_band_get_config_channel_local+0x10> (condition opaque) */
    /* mem ld32: base=(?) off=0 */
    /* mem ld32: base=(?) off=8 */
    /* mem ld32: base=(?) off=12 */
    /* mem ld32: base=(?) off=4 */
    /* mem ld32: base=(lit:g_wifi_nvs) off=0 */
    /* mem ld8: base=(*(g_wifi_nvs+0)) off=0 */
    /* mem ld8: base=(*(g_wifi_nvs+0)) off=144 */
    /* mem st8: base=(*(?+8)) off=0 */
    /* mem st8: base=(*(?+12)) off=0 */
    /* mem ld8: base=((*(g_wifi_nvs+0)+196608)) off=243 */
    /* ... +6 more memops */
    return 0;
}

/* esp_wifi_get_negotiated_channel_local @ ieee80211_api.o 0x00000010 size 184B bind GLOBAL
 * Calls: none | Data refs: g_wifi_nvs, g_ic
 * Fidelity: medium - branchy but loop-free, no direct calls; branch inventory + data refs mapped (verified against section disasm; predicates opaque) */
u32 esp_wifi_get_negotiated_channel_local(u32 a2)
{
    /* frame: entry a1,32; 67 insns, 12 cond-branches, 0 loops, 5 jumps */
    /* immediates: 1, 0, 0x102, -3 */
    /* first predicate: beq a8, a9, 28 <esp_wifi_get_negotiated_channel_local+0x18> (condition opaque) */
    /* mem ld8: base=(?) off=4 */
    /* mem ld32: base=(?) off=0 */
    /* mem ld32: base=(lit:g_wifi_nvs) off=0 */
    /* mem ld8: base=((*(g_wifi_nvs+0)+196608)) off=246 */
    /* mem ld32: base=(?) off=12 */
    /* mem ld32: base=(?) off=16 */
    /* mem ld8: base=(*(g_wifi_nvs+0)) off=0 */
    /* mem ld32: base=(lit:g_ic) off=16 */
    /* mem ld32: base=(*(g_ic+16)) off=228 */
    /* mem ld8: base=(*(g_ic+228)) off=171 */
    /* ... +11 more memops */
    return 0x102;
}

/* esp_wifi_get_negotiated_bw_local @ ieee80211_api.o 0x00000010 size 260B bind GLOBAL
 * Calls: none | Data refs: g_wifi_nvs, g_ic
 * Fidelity: low - 93 insns, 23 branches, 0 loops; skeleton only */
u32 esp_wifi_get_negotiated_bw_local(u32 a2)
{
    /* frame: entry a1,32; 93 insns, 23 cond-branches, 0 loops, 7 jumps */
    /* immediates: 1, 0, 0x102, -3, 8, 2 */
    /* first predicate: bgeui a11, 3, 21 <esp_wifi_get_negotiated_bw_local+0x11> (condition opaque) */
    /* mem ld32: base=(?) off=0 */
    /* mem ld8: base=(?) off=4 */
    /* mem ld32: base=(?) off=8 */
    /* mem ld32: base=(lit:g_wifi_nvs) off=0 */
    /* mem ld8: base=((*(g_wifi_nvs+0)+196608)) off=246 */
    /* mem ld8: base=(*(g_wifi_nvs+0)) off=0 */
    /* mem ld32: base=(lit:g_ic) off=16 */
    /* mem ld32: base=(*(g_ic+16)) off=228 */
    /* mem ld8: base=(*(*(g_ic+16)+228)) off=171 */
    /* mem ld8: base=(*(*(g_ic+16)+228)) off=172 */
    /* ... +7 more memops */
    return 0;
}

/* esp_wifi_sta_get_aid_local @ ieee80211_api.o 0x00000004 size 34B bind GLOBAL
 * Calls: none | Data refs: g_ic
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 esp_wifi_sta_get_aid_local(u32 a2)
{
    /* frame: entry a1,32; 13 insns, 2 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0 */
    /* first predicate: beqz.n a8, 19 <esp_wifi_sta_get_aid_local+0x15> (condition opaque) */
    /* mem ld32: base=(lit:g_ic) off=16 */
    /* mem ld32: base=(*(g_ic+16)) off=228 */
    /* mem ld16: base=(*(g_ic+228)) off=38 */
    /* mem st16: base=(?) off=0 */
    return 0;
}

/* esp_wifi_sta_get_negotiated_phymode_local @ ieee80211_api.o 0x0000000c size 113B bind GLOBAL
 * Calls: none | Data refs: g_ic
 * Fidelity: medium - branchy but loop-free, call sequence mapped */
u32 esp_wifi_sta_get_negotiated_phymode_local(u32 a2)
{
    /* frame: entry a1,32; 41 insns, 10 cond-branches, 0 loops, 5 jumps */
    /* immediates: 0, 8, 5, 4 */
    /* first predicate: beqz a8, 78 <esp_wifi_sta_get_negotiated_phymode_local+0x6c> (condition opaque) */
    /* mem ld32: base=(lit:g_ic) off=16 */
    /* mem ld32: base=(*(g_ic+16)) off=228 */
    /* mem ld8: base=(*(*(g_ic+16)+228)) off=50 */
    /* mem st32: base=(?) off=0 */
    /* mem st32: base=(?) off=0 */
    /* mem ld8: base=(*(*(g_ic+16)+228)) off=172 */
    /* mem ld8: base=(*(*(g_ic+16)+228)) off=171 */
    /* mem ld8: base=(*(*(g_ic+16)+228)) off=171 */
    /* mem st32: base=(?) off=0 */
    return 0;
}

/* esp_wifi_internal_reg_netstack_buf_cb_local @ ieee80211_api.o 0x00000004 size 18B bind GLOBAL
 * Calls: ieee80211_reg_netstack_buf_cb | Data refs: none
 * Fidelity: high - straight-line, fully mapped (7 insns) */
u32 esp_wifi_internal_reg_netstack_buf_cb_local(u32 a2)
{
    /* frame: entry a1,32; 7 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0 */
    /* mem ld32: base=(?) off=4 */
    /* mem ld32: base=(?) off=0 */
    /* site +0x11: ieee80211_reg_netstack_buf_cb(*(?+0), *(?+4)) */
    ieee80211_reg_netstack_buf_cb(*(?+0), *(?+4));
    return 0;
}

/* esp_wifi_send_deauth_local @ ieee80211_api.o 0x00000004 size 16B bind GLOBAL
 * Calls: esp_wifi_deauthenticate_internal | Data refs: none
 * Fidelity: high - straight-line, fully mapped (6 insns) */
u32 esp_wifi_send_deauth_local(u32 a2)
{
    /* frame: entry a1,32; 6 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0 */
    /* mem ld8: base=(?) off=0 */
    /* site +0xf: esp_wifi_deauthenticate_internal(*(?+0)) */
    esp_wifi_deauthenticate_internal(*(?+0));
    return 0;
}

/* esp_wifi_ap_get_sta_aid_local @ ieee80211_api.o 0x00000014 size 112B bind GLOBAL
 * Calls: memcmp | Data refs: g_wifi_nvs, g_ic
 * Fidelity: medium - branchy but loop-free, call sequence mapped */
u32 esp_wifi_ap_get_sta_aid_local(u32 a2)
{
    /* frame: entry a1,32; 42 insns, 6 cond-branches, 0 loops, 2 jumps */
    /* immediates: 6, 1, 0, 0x105 */
    /* first predicate: bgeui a4, 2, 82 <esp_wifi_ap_get_sta_aid_local+0x6e> (condition opaque) */
    /* mem ld32: base=(lit:g_wifi_nvs) off=0 */
    /* mem ld8: base=(*(g_wifi_nvs+0)) off=0 */
    /* mem ld32: base=(lit:g_ic) off=20 */
    /* mem ld8: base=((*(g_wifi_nvs+0)+196608)) off=246 */
    /* mem ld32: base=(?) off=236 */
    /* mem ld16: base=(*(?+236)) off=38 */
    /* mem ld32: base=(?) off=0 */
    /* mem ld32: base=(?) off=4 */
    /* mem st16: base=(*(?+4)) off=0 */
    /* site +0x5a: memcmp(*(?+0), (*(?+236)+4), 6) */
    memcmp(*(?+0), (*(?+236)+4), 6);
    return opaque_result; /* full dataflow not recovered */
}

/* esp_wifi_set_inactive_time_local @ ieee80211_api.o 0x0000000c size 172B bind GLOBAL
 * Calls: wifi_nvs_set | Data refs: g_wifi_nvs, g_ic
 * Fidelity: medium - branchy but loop-free, call sequence mapped (verified: section R_XTENSA_ASM_EXPAND + funcdb v3 agree; predicates opaque) */
u32 esp_wifi_set_inactive_time_local(u32 a2)
{
    /* frame: entry a1,32; 62 insns, 9 cond-branches, 0 loops, 3 jumps */
    /* immediates: 0x102, 1, 0, 9, -3, 85, 86 */
    /* first predicate: bltui a8, 3, 1a <esp_wifi_set_inactive_time_local+0xe> (condition opaque) */
    /* mem ld32: base=(?) off=0 */
    /* mem ld32: base=(?) off=4 */
    /* mem ld16: base=(*(?+4)) off=0 */
    /* mem ld32: base=(lit:g_wifi_nvs) off=0 */
    /* mem ld8: base=(*(g_wifi_nvs+0)) off=0 */
    /* mem ld32: base=(lit:g_ic) off=16 */
    /* mem ld8: base=((lit:g_ic+131072)) off=31 */
    /* mem st16: base=((*(g_ic+16)+131072)) off=58 */
    /* mem st16: base=((*(g_wifi_nvs+0)+262144)) off=166 */
    /* mem ld32: base=(lit:g_ic) off=20 */
    /* ... +3 more memops */
    /* site +0xb1: wifi_nvs_set(86, *(*(?+4)+0), 0, (*(g_ic+16)+131072)) */
    wifi_nvs_set(86, *(*(?+4)+0), 0, (*(g_ic+16)+131072));
    return last_call_result; /* opaque */
}

/* nan_key_is_all_ff$constprop$0 @ ieee80211_api.o 0x00000000 size 32B bind LOCAL
 * Calls: none | Data refs: none
 * Fidelity: high - exact 16B all-0xFF scan loop (13 insns fully mapped) */
u32 nan_key_is_all_ff_constprop_0(u32 a2)
{
    /* frame: entry a1,32; loop a8,16 over bytes at a2 */
    u32 i = 0;
    for (i = 0; i < 16; i++) { /* +0x8 movi.n a8,16; +0xa loop a8,17 */
        u8 b = *(u8 *)(a2 + i); /* +0xd add.n a11,a2,a9; +0xf l8ui a11,a11,0 */
        if (b != 255) /* +0x5 movi a10,255; +0x12 bne a11,a10,1c */
            return 0; /* +0x1c movi.n a2,0 */
        /* +0x15 addi.n a9,a9,1 (loop index) */
    }
    return 1; /* +0x17 movi.n a2,1 */
}

/* esp_wifi_ftm_get_report_local @ ieee80211_api.o 0x00000000 size 7B bind GLOBAL
 * Calls: none | Data refs: none
 * Fidelity: high - straight-line, fully mapped (3 insns) */
u32 esp_wifi_ftm_get_report_local(void)
{
    /* frame: entry a1,32; 3 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0 */
    return 0;
}

/* wifi_get_init_state @ ieee80211_api.o 0x00000004 size 10B bind GLOBAL
 * Calls: none | Data refs: .data.s_wifi_init_state
 * Fidelity: high - straight-line, fully mapped (4 insns) */
u32 wifi_get_init_state(void)
{
    /* frame: entry a1,32; 4 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* mem ld32: base=(lit:.data.s_wifi_init_state) off=0 */
    return opaque_result; /* full dataflow not recovered */
}

/* wifi_is_stop_in_progress @ ieee80211_api.o 0x00000004 size 11B bind GLOBAL
 * Calls: none | Data refs: s_wifi_stop_in_progress
 * Fidelity: high - straight-line, fully mapped (4 insns) */
u32 wifi_is_stop_in_progress(void)
{
    /* frame: entry a1,32; 4 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* mem ld8: base=(lit:s_wifi_stop_in_progress) off=0 */
    return opaque_result; /* full dataflow not recovered */
}

/* wifi_api_lock @ ieee80211_api.o 0x00000010 size 74B bind GLOBAL
 * Calls: current_task_is_wifi_task, indirect(a10), indirect(a8) | Data refs: s_wifi_api_lock, g_osi_funcs_p
 * Fidelity: medium - branchy but loop-free, call sequence mapped */
u32 wifi_api_lock(u32 a3)
{
    /* frame: entry a1,32; 26 insns, 4 cond-branches, 0 loops, 2 jumps */
    /* immediates: 0, 0x101 */
    /* first predicate: beqz a2, 2d <wifi_api_lock+0x1d> (condition opaque) */
    /* mem ld32: base=(lit:s_wifi_api_lock) off=0 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=76 */
    /* mem st32: base=(lit:s_wifi_api_lock) off=0 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(lit:s_wifi_api_lock) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=84 */
    /* site +0x1f: current_task_is_wifi_task(/* no traced args */) */
    current_task_is_wifi_task(/* no traced args */);
    /* site +0x3d: indirect call via a10 (base *(*(g_osi_funcs_p+0)+76)); args: *(*(g_osi_funcs_p+0)+76) */
    opaque_indirect_a10();
    /* site +0x55: indirect call via a8 (base *(g_osi_funcs_p+84)); args: *(s_wifi_api_lock+0) */
    opaque_indirect_a8();
    return 0x101;
}

/* wifi_api_unlock @ ieee80211_api.o 0x0000000c size 33B bind GLOBAL
 * Calls: current_task_is_wifi_task, indirect(a8) | Data refs: s_wifi_api_lock, g_osi_funcs_p
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 wifi_api_unlock(void)
{
    /* frame: entry a1,32; 13 insns, 2 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0 */
    /* first predicate: bnez.n a10, 29 <wifi_api_unlock+0x1d> (condition opaque) */
    /* mem ld32: base=(lit:s_wifi_api_lock) off=0 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=88 */
    /* site +0x12: current_task_is_wifi_task(/* no traced args */) */
    current_task_is_wifi_task(/* no traced args */);
    /* site +0x26: indirect call via a8 (base *(g_osi_funcs_p+88)); args: *(s_wifi_api_lock+0) */
    opaque_indirect_a8();
    return 0;
}

/* wifi_init_completed @ ieee80211_api.o 0x00000010 size 42B bind GLOBAL
 * Calls: wifi_api_lock, wifi_api_unlock, wifi_api_unlock | Data refs: .data.s_wifi_init_state
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 wifi_init_completed(void)
{
    /* frame: entry a1,32; 15 insns, 2 cond-branches, 0 loops, 1 jumps */
    /* immediates: 0, 1 */
    /* first predicate: bne a10, a2, 38 <wifi_init_completed+0x28> (condition opaque) */
    /* mem ld32: base=(lit:.data.s_wifi_init_state) off=0 */
    /* site +0x16: wifi_api_lock(/* no traced args */) */
    wifi_api_lock(/* no traced args */);
    /* site +0x29: wifi_api_unlock(ret@16) */
    wifi_api_unlock(ret@16);
    /* site +0x33: wifi_api_unlock(ret@29) */
    wifi_api_unlock(ret@29);
    return 1;
}

/* esp_wifi_get_inactive_time_local @ ieee80211_api.o 0x00000014 size 99B bind GLOBAL
 * Calls: wifi_init_completed | Data refs: g_ic, g_wifi_nvs
 * Fidelity: medium - branchy but loop-free, call sequence mapped */
u32 esp_wifi_get_inactive_time_local(u32 a2)
{
    /* frame: entry a1,32; 35 insns, 7 cond-branches, 0 loops, 1 jumps */
    /* immediates: 0x102, -3, 0 */
    /* first predicate: beqz a10, 70 <esp_wifi_get_inactive_time_local+0x5c> (condition opaque) */
    /* mem ld8: base=((lit:g_ic+65536)) off=237 */
    /* mem ld32: base=(?) off=0 */
    /* mem ld32: base=(?) off=4 */
    /* mem ld32: base=(lit:g_wifi_nvs) off=0 */
    /* mem ld8: base=(*(g_wifi_nvs+0)) off=0 */
    /* mem ld16: base=((*(g_wifi_nvs+0)+262144)) off=166 */
    /* mem ld16: base=(((*(g_wifi_nvs+0)+262144)+327680)) off=66 */
    /* mem st16: base=(*(?+4)) off=0 */
    /* site +0x1a: wifi_init_completed(/* no traced args */) */
    wifi_init_completed(/* no traced args */);
    return 0;
}

/* wifi_station_get_config_local @ ieee80211_api.o 0x00000030 size 500B bind LOCAL
 * Calls: wifi_api_lock, wifi_nvs_get, wifi_api_unlock, memset, memset, memcpy, memcpy, memcpy, memcpy, wifi_api_unlock | Data refs: g_wifi_nvs, g_ic
 * Fidelity: low - 161 insns, 5 branches, 0 loops; skeleton only */
u32 wifi_station_get_config_local(u32 a2)
{
    /* frame: entry a1,32; 161 insns, 5 cond-branches, 0 loops, 1 jumps */
    /* immediates: 0x102, 0x601, 36, 0, 64, 32, 147, 6, 1, -97 */
    /* first predicate: beqz a2, 1f0 <.text.wifi_station_get_config_local+0x1f0> (condition opaque) */
    /* mem ld32: base=(ret@51) off=4 */
    /* mem ld8: base=(((0x601 slli 3)+196608)) off=92 */
    /* mem st32: base=(?) off=96 */
    /* mem ld8: base=((0x601 slli 3)) off=146 */
    /* mem st8: base=(?) off=100 */
    /* mem ld8: base=((0x601 slli 3)) off=144 */
    /* mem st8: base=(?) off=107 */
    /* mem ld16: base=((0x601 slli 3)) off=154 */
    /* mem st16: base=(?) off=108 */
    /* mem ld8: base=(((0x601 slli 3)+196608)) off=93 */
    /* ... +32 more memops */
    /* site +0x3c: wifi_api_lock(/* no traced args */) */
    wifi_api_lock(/* no traced args */);
    /* site +0x42: wifi_nvs_get(ret@3c) */
    wifi_nvs_get(ret@3c);
    /* site +0x51: wifi_api_unlock(ret@42) */
    wifi_api_unlock(ret@42);
    /* site +0x6b: memset((ret@51+4), 0, 36) */
    memset((ret@51+4), 0, 36);
    /* site +0x77: memset((ret@51+47), 0, 64) */
    memset((ret@51+47), 0, 64);
    /* site +0x87: memcpy(ret@77, ((0x601 slli 3)+8), 32) */
    memcpy(ret@77, ((0x601 slli 3)+8), 32);
    /* site +0x96: memcpy(ret@87, (ret@51+47), 64) */
    memcpy(ret@87, (ret@51+47), 64);
    /* site +0xbb: memcpy((?+101), 147, 6) */
    memcpy((?+101), 147, 6);
    /* site +0x1d1: memcpy(151, 0x47d, 32, (*(((0x601 slli 3)+196608)+100) slli 2), *(((0x601 slli 3)+196608)+98)) */
    memcpy(151, 0x47d, 32, (*(((0x601 slli 3)+196608)+100) slli 2), *(((0x601 slli 3)+196608)+98));
    /* site +0x1eb: wifi_api_unlock(ret@1d1, 0x47d, 32, (*(((0x601 slli 3)+196608)+100) slli 2), *(((0x601 slli 3)+196608)+98)) */
    wifi_api_unlock(ret@1d1, 0x47d, 32, (*(((0x601 slli 3)+196608)+100) slli 2), *(((0x601 slli 3)+196608)+98));
    return 0;
}

/* wifi_softap_get_config @ ieee80211_api.o 0x00000030 size 434B bind GLOBAL
 * Calls: wifi_api_lock, wifi_nvs_get, wifi_api_unlock, wifi_set_default_ssid, memcpy, memcpy, ieee80211_regdomain_check_ap_channel, ieee80211_regdomain_ap_min_chan, wifi_softap_max_support_num, wifi_softap_max_support_num, wifi_api_unlock | Data refs: none
 * Fidelity: low - 152 insns, 9 branches, 0 loops; skeleton only */
u32 wifi_softap_get_config(u32 a2)
{
    /* frame: entry a1,32; 152 insns, 9 cond-branches, 0 loops, 3 jumps */
    /* immediates: 0x102, 0x601, 0x36c, 32, 0x392, 64, -3, 31, 0, 1 */
    /* first predicate: beqz a3, 1e0 <wifi_softap_get_config+0x1b0> (condition opaque) */
    /* mem ld8: base=((ret@51+196608)) off=244 */
    /* mem st32: base=(?) off=100 */
    /* mem ld32: base=(ret@51) off=0x368 */
    /* mem ld16: base=(((0x601 slli 3)+262144)) off=2 */
    /* mem st16: base=(?) off=130 */
    /* mem ld8: base=(((0x601 slli 3)+262144)) off=1 */
    /* mem ld8: base=(?) off=124 */
    /* mem st8: base=(?) off=124 */
    /* mem ld32: base=((0x601 slli 3)) off=0x368 */
    /* mem st8: base=(?) off=96 */
    /* ... +32 more memops */
    /* site +0x3e: wifi_api_lock(/* no traced args */) */
    wifi_api_lock(/* no traced args */);
    /* site +0x44: wifi_nvs_get(ret@3e) */
    wifi_nvs_get(ret@3e);
    /* site +0x51: wifi_api_unlock(ret@44) */
    wifi_api_unlock(ret@44);
    /* site +0x73: wifi_set_default_ssid(ret@51) */
    wifi_set_default_ssid(ret@51);
    /* site +0x82: memcpy(?, 0x36c, 32) */
    memcpy(?, 0x36c, 32);
    /* site +0x95: memcpy((?+32), 0x392, 64) */
    memcpy((?+32), 0x392, 64);
    /* site +0xd7: ieee80211_regdomain_check_ap_channel(*((ret@51+196608)+243), 0x392, 64) */
    ieee80211_regdomain_check_ap_channel(*((ret@51+196608)+243), 0x392, 64);
    /* site +0xe1: ieee80211_regdomain_ap_min_chan(1, 0x392, 64) */
    ieee80211_regdomain_ap_min_chan(1, 0x392, 64);
    /* site +0x108: wifi_softap_max_support_num(*((ret@51+196608)+243), 0x392, 64) */
    wifi_softap_max_support_num(*((ret@51+196608)+243), 0x392, 64);
    /* site +0x111: wifi_softap_max_support_num(ret@108, 0x392, 64) */
    wifi_softap_max_support_num(ret@108, 0x392, 64);
    /* site +0x1dd: wifi_api_unlock(0, *((ret@51+196608)+253), 64) */
    wifi_api_unlock(0, *((ret@51+196608)+253), 64);
    return opaque_result; /* full dataflow not recovered */
}

/* wifi_station_get_config @ ieee80211_api.o 0x00000004 size 16B bind GLOBAL
 * Calls: wifi_station_get_config_local | Data refs: none
 * Fidelity: high - straight-line, fully mapped (6 insns) */
u32 wifi_station_get_config(u32 a2)
{
    /* frame: entry a1,32; 6 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* site +0xd: wifi_station_get_config_local(/* no traced args */) */
    wifi_station_get_config_local(/* no traced args */);
    return last_call_result; /* opaque */
}

/* wifi_station_ap_check @ ieee80211_api.o 0x00000004 size 60B bind GLOBAL
 * Calls: wifi_nvs_get | Data refs: none
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 wifi_station_ap_check(u32 a2)
{
    /* frame: entry a1,32; 23 insns, 2 cond-branches, 0 loops, 2 jumps */
    /* immediates: 160, 0, 0x118, 1 */
    /* first predicate: bgeui a9, 2, 3c <wifi_station_ap_check+0x38> (condition opaque) */
    /* mem ld32: base=(ret@0a) off=0 */
    /* site +0xa: wifi_nvs_get(/* no traced args */) */
    wifi_nvs_get(/* no traced args */);
    return 1;
}

/* wifi_softap_cacl_mac @ ieee80211_api.o 0x00000004 size 60B bind GLOBAL
 * Calls: memcpy | Data refs: none
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 wifi_softap_cacl_mac(u32 a2, u32 a3)
{
    /* frame: entry a1,32; 23 insns, 2 cond-branches, 0 loops, 1 jumps */
    /* immediates: 1, 0, 5 */
    /* first predicate: bnez.n a8, 3c <wifi_softap_cacl_mac+0x38> (condition opaque) */
    /* mem ld8: base=(?) off=5 */
    /* mem st8: base=(?) off=5 */
    /* site +0x25: memcpy(?, ?, 5) */
    memcpy(?, ?, 5);
    return 0;
}

/* esp_wifi_sta_get_rssi @ ieee80211_api.o 0x00000010 size 61B bind GLOBAL
 * Calls: wifi_api_lock, wifi_api_unlock, wifi_api_unlock | Data refs: g_ic
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 esp_wifi_sta_get_rssi(u32 a2)
{
    /* frame: entry a1,32; 23 insns, 3 cond-branches, 0 loops, 1 jumps */
    /* immediates: 0x102, 0, -1 */
    /* first predicate: beqz.n a2, 49 <esp_wifi_sta_get_rssi+0x39> (condition opaque) */
    /* mem ld32: base=(lit:g_ic) off=16 */
    /* mem ld32: base=(*(g_ic+16)) off=228 */
    /* mem ld8: base=(*(g_ic+228)) off=166 */
    /* mem st32: base=(?) off=0 */
    /* site +0x1b: wifi_api_lock(/* no traced args */) */
    wifi_api_lock(/* no traced args */);
    /* site +0x39: wifi_api_unlock(ret@1b) */
    wifi_api_unlock(ret@1b);
    /* site +0x44: wifi_api_unlock(ret@39) */
    wifi_api_unlock(ret@39);
    return -1;
}

/* wifi_softap_get_station_num @ ieee80211_api.o 0x00000010 size 85B bind GLOBAL
 * Calls: none | Data refs: g_wifi_nvs, g_ic
 * Fidelity: medium - branchy but loop-free, call sequence mapped */
u32 wifi_softap_get_station_num(u32 a2)
{
    /* frame: entry a1,32; 31 insns, 5 cond-branches, 0 loops, 1 jumps */
    /* immediates: 0x102, 1, 0 */
    /* first predicate: bgeui a10, 2, 5e <wifi_softap_get_station_num+0x4e> (condition opaque) */
    /* mem ld32: base=(lit:g_wifi_nvs) off=0 */
    /* mem ld8: base=(*(g_wifi_nvs+0)) off=0 */
    /* mem ld32: base=(lit:g_ic) off=20 */
    /* mem ld8: base=((*(g_wifi_nvs+0)+196608)) off=246 */
    /* mem ld32: base=((*(g_wifi_nvs+0)+196608)) off=236 */
    /* mem ld16: base=(?) off=0 */
    /* mem st16: base=(?) off=0 */
    return 0;
}

/* wifi_register_user_ie_manufacturer_recv_cb @ ieee80211_api.o 0x00000004 size 23B bind GLOBAL
 * Calls: none | Data refs: g_ic
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 wifi_register_user_ie_manufacturer_recv_cb(u32 a2)
{
    /* frame: entry a1,32; 9 insns, 1 cond-branches, 0 loops, 0 jumps */
    /* immediates: -1, 0 */
    /* first predicate: beqz.n a2, 14 <wifi_register_user_ie_manufacturer_recv_cb+0x10> (condition opaque) */
    /* mem st32: base=(lit:g_ic) off=156 */
    return 0;
}

/* wifi_unregister_user_ie_manufacturer_recv_cb @ ieee80211_api.o 0x00000004 size 16B bind GLOBAL
 * Calls: none | Data refs: g_ic
 * Fidelity: high - straight-line, fully mapped (6 insns) */
u32 wifi_unregister_user_ie_manufacturer_recv_cb(void)
{
    /* frame: entry a1,32; 6 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0 */
    /* mem st32: base=(lit:g_ic) off=156 */
    return opaque_result; /* full dataflow not recovered */
}

/* wifi_set_user_ie @ ieee80211_api.o 0x00000014 size 278B bind GLOBAL
 * Calls: indirect(a8), indirect(a11), indirect(a3), memcpy, indirect(a3), indirect(a2) | Data refs: g_ic+0x88, .rodata.CSWTCH$548, g_osi_funcs_p, g_ic
 * Fidelity: low - 106 insns, 14 branches, 0 loops; skeleton only */
u32 wifi_set_user_ie(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6)
{
    /* frame: entry a1,48; 106 insns, 14 cond-branches, 0 loops, 3 jumps */
    /* immediates: 1, 0, 246, 12 */
    /* first predicate: bnez.n a2, 3a <wifi_set_user_ie+0x26> (condition opaque) */
    /* mem ld32: base=((?+-1)) off=0 */
    /* mem ld32: base=(*((?+-1)+0)) off=0 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=0x16c */
    /* mem st32: base=(?) off=4 */
    /* mem st32: base=(*((?+-1)+0)) off=0 */
    /* mem ld32: base=(?) off=4 */
    /* mem st8: base=(ret@77) off=0 */
    /* mem ld32: base=(*(?+4)) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=0x16c */
    /* ... +28 more memops */
    /* site +0x77: indirect call via a8 (base *(*(g_osi_funcs_p+0)+0x16c)); args: 12 */
    opaque_indirect_a8();
    /* site +0x97: indirect call via a11 (base *(*(g_osi_funcs_p+0)+0x16c)); args: ?, *(*(g_osi_funcs_p+0)+0x16c) */
    opaque_indirect_a11();
    /* site +0xae: indirect call via a3 (base *(*(g_osi_funcs_p+0)+176)); args: *(.rodata.CSWTCH$548+0), *(*(g_osi_funcs_p+0)+0x16c) */
    opaque_indirect_a3();
    /* site +0xda: memcpy(*(*(.rodata.CSWTCH$548+0)+4)) */
    memcpy(*(*(.rodata.CSWTCH$548+0)+4));
    /* site +0xfb: indirect call via a3 (base *(*(g_osi_funcs_p+0)+176)); args: *(g_osi_funcs_p+4) */
    opaque_indirect_a3();
    /* site +0x105: indirect call via a2 (base *(g_osi_funcs_p+176)); args: *(.rodata.CSWTCH$548+0) */
    opaque_indirect_a2();
    return opaque_result; /* full dataflow not recovered */
}

/* wifi_get_user_ie @ ieee80211_api.o 0x00000008 size 54B bind GLOBAL
 * Calls: none | Data refs: .rodata.wifi_get_user_ie, g_ic
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 wifi_get_user_ie(u32 a2)
{
    /* frame: entry a1,32; 19 insns, 1 cond-branches, 0 loops, 5 jumps */
    /* immediates: 0 */
    /* first predicate: bgeui a8, 5, 3c <wifi_get_user_ie+0x34> (condition opaque) */
    /* mem ld32: base=(?) off=0 */
    /* mem ld32: base=(lit:g_ic) off=136 */
    /* mem ld32: base=(*(g_ic+136)) off=140 */
    /* mem ld32: base=(*(g_ic+140)) off=144 */
    /* mem ld32: base=(*(g_ic+144)) off=148 */
    /* mem ld32: base=(*(g_ic+148)) off=152 */
    return opaque_result; /* full dataflow not recovered */
}

/* wifi_check_chan_param @ ieee80211_api.o 0x00000008 size 57B bind GLOBAL
 * Calls: ieee80211_regdomain_check_channel, chm_get_snd_chan_mode | Data refs: none
 * Fidelity: medium - branchy but loop-free, call sequence mapped */
u32 wifi_check_chan_param(u32 a2, u32 a3)
{
    /* frame: entry a1,32; 21 insns, 6 cond-branches, 0 loops, 2 jumps */
    /* immediates: 0 */
    /* first predicate: bnez.n a10, 1f <wifi_check_chan_param+0x17> (condition opaque) */
    /* site +0x13: ieee80211_regdomain_check_channel(/* no traced args */) */
    ieee80211_regdomain_check_channel(/* no traced args */);
    /* site +0x27: chm_get_snd_chan_mode(/* no traced args */) */
    chm_get_snd_chan_mode(/* no traced args */);
    return opaque_result; /* full dataflow not recovered */
}

/* wifi_deinit_in_caller_task @ ieee80211_api.o 0x00000018 size 77B bind GLOBAL
 * Calls: ieee80211_ioctl_deinit, ic_delete_wifi_task, misc_nvs_deinit, indirect(a8), indirect(a8) | Data refs: g_intr_lock_mux, g_osi_funcs_p, mac_list_lock
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 wifi_deinit_in_caller_task(u32 a2)
{
    /* frame: entry a1,32; 29 insns, 2 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0 */
    /* first predicate: beqz a10, 45 <wifi_deinit_in_caller_task+0x2d> (condition opaque) */
    /* mem ld32: base=(lit:g_intr_lock_mux) off=0 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=36 */
    /* mem st32: base=(lit:g_intr_lock_mux) off=0 */
    /* mem ld32: base=(lit:mac_list_lock) off=0 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=80 */
    /* mem st32: base=(lit:mac_list_lock) off=0 */
    /* site +0x1e: ieee80211_ioctl_deinit(/* no traced args */) */
    ieee80211_ioctl_deinit(/* no traced args */);
    /* site +0x24: ic_delete_wifi_task(ret@1e) */
    ic_delete_wifi_task(ret@1e);
    /* site +0x2a: misc_nvs_deinit(ret@24) */
    misc_nvs_deinit(ret@24);
    /* site +0x3e: indirect call via a8 (base *(g_osi_funcs_p+36)); args: *(g_intr_lock_mux+0) */
    opaque_indirect_a8();
    /* site +0x57: indirect call via a8 (base *(g_osi_funcs_p+80)); args: *(mac_list_lock+0) */
    opaque_indirect_a8();
    return 0;
}

/* wifi_init_in_caller_task @ ieee80211_api.o 0x0000002c size 176B bind GLOBAL
 * Calls: indirect(a10), indirect(a10), wifi_log, wifi_menuconfig_init, indirect(a10), misc_nvs_init, ic_create_wifi_task, ieee80211_ioctl_init, wifi_deinit_in_caller_task | Data refs: g_intr_lock_mux, g_wifi_global_lock, g_osi_funcs_p, .rodata_wlog_warning.4, mac_list_lock
 * Fidelity: medium - branchy but loop-free, call sequence mapped (verified: section R_XTENSA_ASM_EXPAND + funcdb v3 agree; predicates opaque) */
u32 wifi_init_in_caller_task(u32 a3)
{
    /* frame: entry a1,32; 63 insns, 10 cond-branches, 0 loops, 5 jumps */
    /* immediates: 1, 2, 0x101 */
    /* first predicate: beqz a8, 44 <wifi_init_in_caller_task+0x18> (condition opaque) */
    /* mem ld32: base=(lit:g_intr_lock_mux) off=0 */
    /* mem ld32: base=(lit:g_wifi_global_lock) off=0 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=32 */
    /* mem st32: base=(lit:g_wifi_global_lock) off=0 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=76 */
    /* mem st32: base=(lit:g_wifi_global_lock) off=0 */
    /* mem ld32: base=(lit:mac_list_lock) off=0 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* ... +2 more memops */
    /* site +0x4b: indirect call via a10 (base *(g_osi_funcs_p+32)); args: *(g_osi_funcs_p+32) */
    opaque_indirect_a10();
    /* site +0x63: indirect call via a10 (base *(g_osi_funcs_p+76)); args: *(g_osi_funcs_p+76) */
    opaque_indirect_a10();
    /* site +0x79: wifi_log(1, 1, 2, lit:.rodata_wlog_warning.4) */
    wifi_log(1, 1, 2, lit:.rodata_wlog_warning.4);
    /* site +0x91: wifi_menuconfig_init(0x101, 1, 2, lit:.rodata_wlog_warning.4) */
    wifi_menuconfig_init(0x101, 1, 2, lit:.rodata_wlog_warning.4);
    /* site +0xa5: indirect call via a10 (base *(g_osi_funcs_p+72)); args: *(g_osi_funcs_p+72), 1, 2, lit:.rodata_wlog_warning.4 */
    opaque_indirect_a10();
    /* site +0xb7: misc_nvs_init(ret@a5, 1, 2, lit:.rodata_wlog_warning.4) */
    misc_nvs_init(ret@a5, 1, 2, lit:.rodata_wlog_warning.4);
    /* site +0xc3: ic_create_wifi_task(ret@b7, 1, 2, lit:.rodata_wlog_warning.4) */
    ic_create_wifi_task(ret@b7, 1, 2, lit:.rodata_wlog_warning.4);
    /* site +0xcd: ieee80211_ioctl_init(ret@c3, 1, 2, lit:.rodata_wlog_warning.4) */
    ieee80211_ioctl_init(ret@c3, 1, 2, lit:.rodata_wlog_warning.4);
    /* site +0xd7: wifi_deinit_in_caller_task(ret@cd, 1, 2, lit:.rodata_wlog_warning.4) */
    wifi_deinit_in_caller_task(ret@cd, 1, 2, lit:.rodata_wlog_warning.4);
    return last_call_result; /* opaque */
}

/* wifi_osi_ready @ ieee80211_api.o 0x00000004 size 17B bind GLOBAL
 * Calls: none | Data refs: g_osi_funcs_p
 * Fidelity: high - straight-line, fully mapped (7 insns) */
u32 wifi_osi_ready(u32 a2)
{
    /* frame: entry a1,32; 7 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0, 1 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    return opaque_result; /* full dataflow not recovered */
}

/* wifi_osi_funcs_register @ ieee80211_api.o 0x0000001c size 73B bind GLOBAL
 * Calls: puts, net80211_printf | Data refs: g_osi_funcs_p, .rodata.wifi_osi_funcs_register.str1.1
 * Fidelity: medium - branchy but loop-free, call sequence mapped */
u32 wifi_osi_funcs_register(u32 a2)
{
    /* frame: entry a1,32; 26 insns, 4 cond-branches, 0 loops, 2 jumps */
    /* immediates: 0, 9, 0x102 */
    /* first predicate: bne a10, a8, 5e <wifi_osi_funcs_register+0x42> (condition opaque) */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(?) off=0 */
    /* mem ld32: base=(?) off=0x1e0 */
    /* mem st32: base=(lit:g_osi_funcs_p) off=0 */
    /* site +0x32: puts(lit:.rodata.wifi_osi_funcs_register.str1.1) */
    puts(lit:.rodata.wifi_osi_funcs_register.str1.1);
    /* site +0x45: net80211_printf(lit:g_osi_funcs_p, 9, *(?+0)) */
    net80211_printf(lit:g_osi_funcs_p, 9, *(?+0));
    return 0x102;
}

/* esp_wifi_internal_osi_funcs_md5_check @ ieee80211_api.o 0x00000014 size 56B bind GLOBAL
 * Calls: strlen, strncmp, net80211_printf | Data refs: g_wifi_osi_funcs_md5, .rodata.esp_wifi_internal_osi_funcs_md5_check.str1.1
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 esp_wifi_internal_osi_funcs_md5_check(u32 a2, u32 a3)
{
    /* frame: entry a1,32; 22 insns, 2 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0, 0x102 */
    /* first predicate: beq a2, a10, 48 <esp_wifi_internal_osi_funcs_md5_check+0x34> (condition opaque) */
    /* mem ld32: base=(lit:g_wifi_osi_funcs_md5) off=0 */
    /* site +0x27: strlen(0) */
    strlen(0);
    /* site +0x33: strncmp(*(g_wifi_osi_funcs_md5+0), ?, ret@27) */
    strncmp(*(g_wifi_osi_funcs_md5+0), ?, ret@27);
    /* site +0x42: net80211_printf(lit:.rodata.esp_wifi_internal_osi_funcs_m..., *(g_wifi_osi_funcs_md5+0)) */
    net80211_printf(lit:.rodata.esp_wifi_internal_osi_funcs_m..., *(g_wifi_osi_funcs_md5+0));
    return 0x102;
}

/* esp_wifi_internal_crypto_funcs_md5_check @ ieee80211_api.o 0x00000014 size 56B bind GLOBAL
 * Calls: strlen, strncmp, net80211_printf | Data refs: g_wifi_crypto_funcs_md5, .rodata.esp_wifi_internal_crypto_funcs_md5_check.str1.1
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 esp_wifi_internal_crypto_funcs_md5_check(u32 a2, u32 a3)
{
    /* frame: entry a1,32; 22 insns, 2 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0, 0x102 */
    /* first predicate: beq a2, a10, 48 <esp_wifi_internal_crypto_funcs_md5_check+0x34> (condition opaque) */
    /* mem ld32: base=(lit:g_wifi_crypto_funcs_md5) off=0 */
    /* site +0x27: strlen(0) */
    strlen(0);
    /* site +0x33: strncmp(*(g_wifi_crypto_funcs_md5+0), ?, ret@27) */
    strncmp(*(g_wifi_crypto_funcs_md5+0), ?, ret@27);
    /* site +0x42: net80211_printf(lit:.rodata.esp_wifi_internal_crypto_func..., *(g_wifi_crypto_funcs_md5+0)) */
    net80211_printf(lit:.rodata.esp_wifi_internal_crypto_func..., *(g_wifi_crypto_funcs_md5+0));
    return 0x102;
}

/* esp_wifi_internal_wifi_type_md5_check @ ieee80211_api.o 0x00000014 size 56B bind GLOBAL
 * Calls: strlen, strncmp, net80211_printf | Data refs: g_wifi_type_md5, .rodata.esp_wifi_internal_wifi_type_md5_check.str1.1
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 esp_wifi_internal_wifi_type_md5_check(u32 a2, u32 a3)
{
    /* frame: entry a1,32; 22 insns, 2 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0, 0x102 */
    /* first predicate: beq a2, a10, 48 <esp_wifi_internal_wifi_type_md5_check+0x34> (condition opaque) */
    /* mem ld32: base=(lit:g_wifi_type_md5) off=0 */
    /* site +0x27: strlen(0) */
    strlen(0);
    /* site +0x33: strncmp(*(g_wifi_type_md5+0), ?, ret@27) */
    strncmp(*(g_wifi_type_md5+0), ?, ret@27);
    /* site +0x42: net80211_printf(lit:.rodata.esp_wifi_internal_wifi_type_m..., *(g_wifi_type_md5+0)) */
    net80211_printf(lit:.rodata.esp_wifi_internal_wifi_type_m..., *(g_wifi_type_md5+0));
    return 0x102;
}

/* esp_wifi_internal_esp_wifi_md5_check @ ieee80211_api.o 0x00000014 size 56B bind GLOBAL
 * Calls: strlen, strncmp, net80211_printf | Data refs: g_esp_wifi_md5, .rodata.esp_wifi_internal_esp_wifi_md5_check.str1.1
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 esp_wifi_internal_esp_wifi_md5_check(u32 a2, u32 a3)
{
    /* frame: entry a1,32; 22 insns, 2 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0, 0x102 */
    /* first predicate: beq a2, a10, 48 <esp_wifi_internal_esp_wifi_md5_check+0x34> (condition opaque) */
    /* mem ld32: base=(lit:g_esp_wifi_md5) off=0 */
    /* site +0x27: strlen(0) */
    strlen(0);
    /* site +0x33: strncmp(*(g_esp_wifi_md5+0), ?, ret@27) */
    strncmp(*(g_esp_wifi_md5+0), ?, ret@27);
    /* site +0x42: net80211_printf(lit:.rodata.esp_wifi_internal_esp_wifi_md..., *(g_esp_wifi_md5+0)) */
    net80211_printf(lit:.rodata.esp_wifi_internal_esp_wifi_md..., *(g_esp_wifi_md5+0));
    return 0x102;
}

/* esp_wifi_internal_esp_wifi_he_md5_check @ ieee80211_api.o 0x00000014 size 56B bind GLOBAL
 * Calls: strlen, strncmp, net80211_printf | Data refs: g_esp_wifi_he_md5, .rodata.esp_wifi_internal_esp_wifi_he_md5_check.str1.1
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 esp_wifi_internal_esp_wifi_he_md5_check(u32 a2, u32 a3)
{
    /* frame: entry a1,32; 22 insns, 2 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0, 0x102 */
    /* first predicate: beq a2, a10, 48 <esp_wifi_internal_esp_wifi_he_md5_check+0x34> (condition opaque) */
    /* mem ld32: base=(lit:g_esp_wifi_he_md5) off=0 */
    /* site +0x27: strlen(0) */
    strlen(0);
    /* site +0x33: strncmp(*(g_esp_wifi_he_md5+0), ?, ret@27) */
    strncmp(*(g_esp_wifi_he_md5+0), ?, ret@27);
    /* site +0x42: net80211_printf(lit:.rodata.esp_wifi_internal_esp_wifi_he..., *(g_esp_wifi_he_md5+0)) */
    net80211_printf(lit:.rodata.esp_wifi_internal_esp_wifi_he..., *(g_esp_wifi_he_md5+0));
    return 0x102;
}

/* esp_wifi_internal_wifi_he_type_md5_check @ ieee80211_api.o 0x00000014 size 56B bind GLOBAL
 * Calls: strlen, strncmp, net80211_printf | Data refs: g_wifi_he_type_md5, .rodata.esp_wifi_internal_wifi_he_type_md5_check.str1.1
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 esp_wifi_internal_wifi_he_type_md5_check(u32 a2, u32 a3)
{
    /* frame: entry a1,32; 22 insns, 2 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0, 0x102 */
    /* first predicate: beq a2, a10, 48 <esp_wifi_internal_wifi_he_type_md5_check+0x34> (condition opaque) */
    /* mem ld32: base=(lit:g_wifi_he_type_md5) off=0 */
    /* site +0x27: strlen(0) */
    strlen(0);
    /* site +0x33: strncmp(*(g_wifi_he_type_md5+0), ?, ret@27) */
    strncmp(*(g_wifi_he_type_md5+0), ?, ret@27);
    /* site +0x42: net80211_printf(lit:.rodata.esp_wifi_internal_wifi_he_typ..., *(g_wifi_he_type_md5+0)) */
    net80211_printf(lit:.rodata.esp_wifi_internal_wifi_he_typ..., *(g_wifi_he_type_md5+0));
    return 0x102;
}

/* net80211_softap_funcs_init @ ieee80211_api.o 0x00000024 size 90B bind GLOBAL
 * Calls: ieee80211_register_hostap_timer | Data refs: net80211_funcs, hostap_input, wifi_create_softap, wifi_destroy_softap, wifi_softap_start, wifi_softap_stop, wifi_softap_set_config, wifi_softap_get_config
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque (weak) */
u32 net80211_softap_funcs_init(void)
{
    /* frame: entry a1,32; 21 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* mem ld32: base=(lit:net80211_funcs) off=0 */
    /* mem st32: base=(*(net80211_funcs+0)) off=0 */
    /* mem st32: base=(*(net80211_funcs+0)) off=4 */
    /* mem st32: base=(*(net80211_funcs+0)) off=8 */
    /* mem st32: base=(*(net80211_funcs+0)) off=12 */
    /* mem st32: base=(*(net80211_funcs+0)) off=16 */
    /* mem st32: base=(*(net80211_funcs+0)) off=20 */
    /* mem st32: base=(*(net80211_funcs+0)) off=24 */
    /* site +0x2a: ieee80211_register_hostap_timer(/* no traced args */) */
    ieee80211_register_hostap_timer(/* no traced args */);
    return opaque_result; /* full dataflow not recovered */
}

/* net80211_funcs_init @ ieee80211_api.o 0x00000014 size 62B bind GLOBAL
 * Calls: indirect(a2), wifi_log, net80211_softap_funcs_init | Data refs: g_osi_funcs_p, net80211_funcs, .rodata_wlog_error.5
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 net80211_funcs_init(u32 a2)
{
    /* frame: entry a1,32; 23 insns, 1 cond-branches, 0 loops, 1 jumps */
    /* immediates: 32, 1, 6, 0x101, 0 */
    /* first predicate: bnez.n a10, 48 <net80211_funcs_init+0x34> (condition opaque) */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=0x164 */
    /* mem st32: base=(lit:net80211_funcs) off=0 */
    /* site +0x25: indirect call via a2 (base *(g_osi_funcs_p+0x164)); args: 1, 32 */
    opaque_indirect_a2();
    /* site +0x41: wifi_log(6, 1, 1, lit:.rodata_wlog_error.5) */
    wifi_log(6, 1, 1, lit:.rodata_wlog_error.5);
    /* site +0x4b: net80211_softap_funcs_init(ret@41, 1, 1, lit:.rodata_wlog_error.5) */
    net80211_softap_funcs_init(ret@41, 1, 1, lit:.rodata_wlog_error.5);
    return 0;
}

/* net80211_funcs_deinit @ ieee80211_api.o 0x00000008 size 32B bind GLOBAL
 * Calls: indirect(a8) | Data refs: net80211_funcs, g_osi_funcs_p
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 net80211_funcs_deinit(u32 a2)
{
    /* frame: entry a1,32; 13 insns, 1 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0 */
    /* first predicate: beqz.n a10, 21 <net80211_funcs_deinit+0x19> (condition opaque) */
    /* mem ld32: base=(lit:net80211_funcs) off=0 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=176 */
    /* mem st32: base=(lit:net80211_funcs) off=0 */
    /* site +0x1a: indirect call via a8 (base *(g_osi_funcs_p+176)); args: *(net80211_funcs+0) */
    opaque_indirect_a8();
    return 0;
}

/* esp_wifi_init_internal @ ieee80211_api.o 0x00000060 size 275B bind GLOBAL
 * Calls: puts, wifi_osi_funcs_register, wifi_api_lock, wifi_api_unlock, wifi_api_unlock, wifi_log, pm_funcs_init, net80211_funcs_init, wifi_api_unlock, wifi_init_in_caller_task, indirect(a3), ieee80211_ioctl, wifi_api_lock, wifi_deinit_in_caller_task, wifi_api_lock, pm_funcs_deinit, net80211_funcs_deinit, wifi_api_unlock | Data refs: .rodata.esp_wifi_init_internal.str1.1, .data.s_wifi_init_state, .rodata_wlog_warning.6, .rodata_wlog_warning.7, g_osi_funcs_p, wifi_init_process
 * Fidelity: low - 98 insns, 12 branches, 0 loops; skeleton only */
u32 esp_wifi_init_internal(u32 a2, u32 a4)
{
    /* frame: entry a1,32; 98 insns, 12 cond-branches, 0 loops, 6 jumps */
    /* immediates: 0x102, 2, 1, 24, 38, 3, 0x101 */
    /* first predicate: bnez a2, 79 <esp_wifi_init_internal+0x19> (condition opaque) */
    /* mem ld32: base=(0x102) off=0 */
    /* mem ld32: base=(lit:.data.s_wifi_init_state) off=0 */
    /* mem st32: base=(lit:.data.s_wifi_init_state) off=0 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=0x178 */
    /* mem st8: base=(ret@113) off=0 */
    /* mem st16: base=(ret@113) off=8 */
    /* mem st8: base=(ret@113) off=10 */
    /* mem st32: base=(ret@113) off=4 */
    /* mem st32: base=(ret@113) off=12 */
    /* ... +1 more memops */
    /* site +0x71: puts(lit:.rodata.esp_wifi_init_internal.str1.1) */
    puts(lit:.rodata.esp_wifi_init_internal.str1.1);
    /* site +0x7e: wifi_osi_funcs_register(*(0x102+0)) */
    wifi_osi_funcs_register(*(0x102+0));
    /* site +0x89: wifi_api_lock(ret@7e) */
    wifi_api_lock(ret@7e);
    /* site +0xa6: wifi_api_unlock(ret@89) */
    wifi_api_unlock(ret@89);
    /* site +0xbe: wifi_api_unlock(ret@a6, *(.data.s_wifi_init_state+0), *(.data.s_wifi_init_state+0), lit:.rodata_wlog_warning.6) */
    wifi_api_unlock(ret@a6, *(.data.s_wifi_init_state+0), *(.data.s_wifi_init_state+0), lit:.rodata_wlog_warning.6);
    /* site +0xcd: wifi_log(1, 2, 2, lit:.rodata_wlog_warning.7) */
    wifi_log(1, 2, 2, lit:.rodata_wlog_warning.7);
    /* site +0xdb: pm_funcs_init(ret@cd, 2, 2, lit:.rodata_wlog_warning.7) */
    pm_funcs_init(ret@cd, 2, 2, lit:.rodata_wlog_warning.7);
    /* site +0xe7: net80211_funcs_init(ret@db, 2, 2, lit:.rodata_wlog_warning.7) */
    net80211_funcs_init(ret@db, 2, 2, lit:.rodata_wlog_warning.7);
    /* site +0xf9: wifi_api_unlock(ret@e7, 2, 2, lit:.rodata_wlog_warning.7) */
    wifi_api_unlock(ret@e7, 2, 2, lit:.rodata_wlog_warning.7);
    /* site +0x101: wifi_init_in_caller_task(?, 2, 2, lit:.rodata_wlog_warning.7) */
    wifi_init_in_caller_task(?, 2, 2, lit:.rodata_wlog_warning.7);
    /* site +0x113: indirect call via a3 (base *(g_osi_funcs_p+0x178)); args: 24, 2, 2, lit:.rodata_wlog_warning.7 */
    opaque_indirect_a3();
    /* site +0x137: ieee80211_ioctl(ret@113, 2, 2, lit:.rodata_wlog_warning.7) */
    ieee80211_ioctl(ret@113, 2, 2, lit:.rodata_wlog_warning.7);
    /* site +0x141: wifi_api_lock(ret@137, 2, 2, lit:.rodata_wlog_warning.7) */
    wifi_api_lock(ret@137, 2, 2, lit:.rodata_wlog_warning.7);
    /* site +0x14f: wifi_deinit_in_caller_task(ret@141, 2, 2, lit:.rodata_wlog_warning.7) */
    wifi_deinit_in_caller_task(ret@141, 2, 2, lit:.rodata_wlog_warning.7);
    /* site +0x155: wifi_api_lock(ret@14f, 2, 2, lit:.rodata_wlog_warning.7) */
    wifi_api_lock(ret@14f, 2, 2, lit:.rodata_wlog_warning.7);
    /* site +0x15b: pm_funcs_deinit(ret@155, 2, 2, lit:.rodata_wlog_warning.7) */
    pm_funcs_deinit(ret@155, 2, 2, lit:.rodata_wlog_warning.7);
    /* site +0x161: net80211_funcs_deinit(ret@15b, 2, 2, lit:.rodata_wlog_warning.7) */
    net80211_funcs_deinit(ret@15b, 2, 2, lit:.rodata_wlog_warning.7);
    /* site +0x16e: wifi_api_unlock(ret@161, 2, 2, lit:.rodata_wlog_warning.7) */
    wifi_api_unlock(ret@161, 2, 2, lit:.rodata_wlog_warning.7);
    return 0x101;
}

/* esp_wifi_deinit_internal @ ieee80211_api.o 0x00000064 size 247B bind GLOBAL
 * Calls: wifi_api_lock, wifi_api_unlock, wifi_log, wifi_api_unlock, wifi_api_unlock, wifi_api_unlock, wifi_log, wifi_api_unlock, indirect(a3), ieee80211_ioctl, wifi_deinit_in_caller_task, wifi_api_lock, pm_funcs_deinit, net80211_funcs_deinit, wifi_api_lock, wifi_api_unlock | Data refs: g_ic, .rodata_wlog_error.8, .data.s_wifi_init_state, .rodata_wlog_warning.9, .rodata_wlog_warning.10, g_osi_funcs_p, wifi_deinit_process
 * Fidelity: medium - branchy but loop-free, call sequence mapped (verified: section R_XTENSA_ASM_EXPAND + funcdb v3 agree; predicates opaque) */
u32 esp_wifi_deinit_internal(u32 a2, u32 a3, u32 a4)
{
    /* frame: entry a1,32; 85 insns, 8 cond-branches, 0 loops, 6 jumps */
    /* immediates: 1, 3, 2, 4, 24, 0x101 */
    /* first predicate: bnez a10, 159 <esp_wifi_deinit_internal+0xf5> (condition opaque) */
    /* mem ld8: base=((lit:g_ic+65536)) off=237 */
    /* mem ld32: base=(lit:.data.s_wifi_init_state) off=0 */
    /* mem st32: base=(lit:.data.s_wifi_init_state) off=0 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=0x178 */
    /* mem st8: base=(ret@103) off=0 */
    /* mem st32: base=(ret@103) off=4 */
    /* mem st32: base=(lit:.data.s_wifi_init_state) off=0 */
    /* site +0x6a: wifi_api_lock(/* no traced args */) */
    wifi_api_lock(/* no traced args */);
    /* site +0x82: wifi_api_unlock(ret@6a) */
    wifi_api_unlock(ret@6a);
    /* site +0x91: wifi_log(1, 3, 1, lit:.rodata_wlog_error.8) */
    wifi_log(1, 3, 1, lit:.rodata_wlog_error.8);
    /* site +0xaa: wifi_api_unlock(ret@91, 3, 1, lit:.rodata_wlog_error.8) */
    wifi_api_unlock(ret@91, 3, 1, lit:.rodata_wlog_error.8);
    /* site +0xba: wifi_api_unlock(ret@aa, 3, 1, lit:.rodata_wlog_error.8) */
    wifi_api_unlock(ret@aa, 3, 1, lit:.rodata_wlog_error.8);
    /* site +0xd2: wifi_api_unlock(ret@ba, *(.data.s_wifi_init_state+0), *(.data.s_wifi_init_state+0), lit:.rodata_wlog_warning.9) */
    wifi_api_unlock(ret@ba, *(.data.s_wifi_init_state+0), *(.data.s_wifi_init_state+0), lit:.rodata_wlog_warning.9);
    /* site +0xe1: wifi_log(1, 2, 2, lit:.rodata_wlog_warning.10) */
    wifi_log(1, 2, 2, lit:.rodata_wlog_warning.10);
    /* site +0xf5: wifi_api_unlock(ret@e1, 2, 2, lit:.rodata_wlog_warning.10) */
    wifi_api_unlock(ret@e1, 2, 2, lit:.rodata_wlog_warning.10);
    /* site +0x103: indirect call via a3 (base *(g_osi_funcs_p+0x178)); args: 24, 2, 2, lit:.rodata_wlog_warning.10 */
    opaque_indirect_a3();
    /* site +0x119: ieee80211_ioctl(ret@103, 2, 2, lit:.rodata_wlog_warning.10) */
    ieee80211_ioctl(ret@103, 2, 2, lit:.rodata_wlog_warning.10);
    /* site +0x125: wifi_deinit_in_caller_task(ret@119, 2, 2, lit:.rodata_wlog_warning.10) */
    wifi_deinit_in_caller_task(ret@119, 2, 2, lit:.rodata_wlog_warning.10);
    /* site +0x12b: wifi_api_lock(ret@125, 2, 2, lit:.rodata_wlog_warning.10) */
    wifi_api_lock(ret@125, 2, 2, lit:.rodata_wlog_warning.10);
    /* site +0x131: pm_funcs_deinit(ret@12b, 2, 2, lit:.rodata_wlog_warning.10) */
    pm_funcs_deinit(ret@12b, 2, 2, lit:.rodata_wlog_warning.10);
    /* site +0x137: net80211_funcs_deinit(ret@131, 2, 2, lit:.rodata_wlog_warning.10) */
    net80211_funcs_deinit(ret@131, 2, 2, lit:.rodata_wlog_warning.10);
    /* site +0x147: wifi_api_lock(ret@137, 2, 2, lit:.rodata_wlog_warning.10) */
    wifi_api_lock(ret@137, 2, 2, lit:.rodata_wlog_warning.10);
    /* site +0x156: wifi_api_unlock(ret@147, 2, 2, lit:.rodata_wlog_warning.10) */
    wifi_api_unlock(ret@147, 2, 2, lit:.rodata_wlog_warning.10);
    return 0x101;
}

/* esp_wifi_set_mode @ ieee80211_api.o 0x00000014 size 64B bind GLOBAL
 * Calls: wifi_init_completed, indirect(a8), ieee80211_ioctl | Data refs: g_osi_funcs_p, wifi_set_mode_process
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 esp_wifi_set_mode(u32 a2)
{
    /* frame: entry a1,32; 24 insns, 2 cond-branches, 0 loops, 0 jumps */
    /* immediates: 24, 0x101, 10 */
    /* first predicate: beqz.n a10, 50 <esp_wifi_set_mode+0x3c> (condition opaque) */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=0x178 */
    /* mem st32: base=(ret@2d) off=4 */
    /* mem st8: base=(ret@2d) off=0 */
    /* mem st8: base=(ret@2d) off=8 */
    /* site +0x1a: wifi_init_completed(/* no traced args */) */
    wifi_init_completed(/* no traced args */);
    /* site +0x2d: indirect call via a8 (base *(g_osi_funcs_p+0x178)); args: 24 */
    opaque_indirect_a8();
    /* site +0x4b: ieee80211_ioctl(ret@2d) */
    ieee80211_ioctl(ret@2d);
    return last_call_result; /* opaque */
}

/* esp_wifi_ftm_initiate_session @ ieee80211_api.o 0x00000020 size 72B bind GLOBAL
 * Calls: wifi_init_completed, wifi_log | Data refs: g_ic, g_wifi_nvs, .rodata_wlog_error.11, .rodata_wlog_error.12
 * Fidelity: medium - branchy but loop-free, call sequence mapped */
u32 esp_wifi_ftm_initiate_session(u32 a2)
{
    /* frame: entry a1,32; 27 insns, 4 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0x102, 1, 2, 6, 0x106 */
    /* first predicate: beqz.n a10, 64 <esp_wifi_ftm_initiate_session+0x44> (condition opaque) */
    /* mem ld8: base=((lit:g_ic+65536)) off=237 */
    /* mem ld32: base=(lit:g_wifi_nvs) off=0 */
    /* mem ld8: base=(*(g_wifi_nvs+0)) off=0 */
    /* site +0x26: wifi_init_completed(/* no traced args */) */
    wifi_init_completed(/* no traced args */);
    /* site +0x5e: wifi_log(6, 2, 1, lit:.rodata_wlog_error.12) */
    wifi_log(6, 2, 1, lit:.rodata_wlog_error.12);
    return 0x106;
}

/* esp_wifi_get_mode @ ieee80211_api.o 0x00000014 size 50B bind GLOBAL
 * Calls: wifi_init_completed, wifi_api_lock, wifi_api_unlock | Data refs: g_wifi_nvs
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 esp_wifi_get_mode(u32 a2)
{
    /* frame: entry a1,32; 19 insns, 2 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0x102, 0 */
    /* first predicate: beqz.n a10, 42 <esp_wifi_get_mode+0x2e> (condition opaque) */
    /* mem ld32: base=(lit:g_wifi_nvs) off=0 */
    /* mem ld8: base=(*(g_wifi_nvs+0)) off=0 */
    /* mem st32: base=(?) off=0 */
    /* site +0x1a: wifi_init_completed(/* no traced args */) */
    wifi_init_completed(/* no traced args */);
    /* site +0x2a: wifi_api_lock(ret@1a) */
    wifi_api_lock(ret@1a);
    /* site +0x3d: wifi_api_unlock(ret@2a) */
    wifi_api_unlock(ret@2a);
    return 0;
}

/* esp_wifi_restart @ ieee80211_api.o 0x0000000c size 48B bind GLOBAL
 * Calls: indirect(a2), ieee80211_ioctl | Data refs: g_osi_funcs_p, wifi_restart_process
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 esp_wifi_restart(u32 a2)
{
    /* frame: entry a1,32; 18 insns, 1 cond-branches, 0 loops, 0 jumps */
    /* immediates: 24, 0x101, 25 */
    /* first predicate: beqz.n a10, 3a <esp_wifi_restart+0x2e> (condition opaque) */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=0x178 */
    /* mem st32: base=(ret@1a) off=4 */
    /* mem st8: base=(ret@1a) off=0 */
    /* site +0x1a: indirect call via a2 (base *(g_osi_funcs_p+0x178)); args: 24 */
    opaque_indirect_a2();
    /* site +0x35: ieee80211_ioctl(ret@1a) */
    ieee80211_ioctl(ret@1a);
    return last_call_result; /* opaque */
}

/* esp_wifi_start @ ieee80211_api.o 0x00000014 size 60B bind GLOBAL
 * Calls: wifi_init_completed, indirect(a2), ieee80211_ioctl | Data refs: g_osi_funcs_p, wifi_start_process
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 esp_wifi_start(u32 a2)
{
    /* frame: entry a1,32; 22 insns, 2 cond-branches, 0 loops, 0 jumps */
    /* immediates: 24, 0x101, 1 */
    /* first predicate: beqz.n a10, 4e <esp_wifi_start+0x3a> (condition opaque) */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=0x178 */
    /* mem st32: base=(ret@2e) off=4 */
    /* mem st8: base=(ret@2e) off=0 */
    /* site +0x1a: wifi_init_completed(/* no traced args */) */
    wifi_init_completed(/* no traced args */);
    /* site +0x2e: indirect call via a2 (base *(g_osi_funcs_p+0x178)); args: 24 */
    opaque_indirect_a2();
    /* site +0x49: ieee80211_ioctl(ret@2e) */
    ieee80211_ioctl(ret@2e);
    return last_call_result; /* opaque */
}

/* esp_wifi_stop @ ieee80211_api.o 0x00000070 size 394B bind GLOBAL
 * Calls: wifi_api_lock, indirect(a2), wifi_api_unlock, wifi_log, indirect(a3), wifi_api_unlock, wifi_api_unlock, reset_cs_thres, ieee80211_ioctl, indirect(a7), ieee80211_ioctl, indirect(a7), indirect(a8), wifi_log, wifi_log, indirect(a2), ieee80211_ioctl, wifi_log, wifi_api_lock, wifi_api_unlock | Data refs: g_osi_funcs_p, .rodata_wlog_error.13, s_wifi_stop_in_progress, wifi_stop_process, .rodata_wlog_error.15, .rodata_wlog_warning.16, .rodata_wlog_warning.17, .rodata_wlog_error.18
 * Fidelity: low - 144 insns, 10 branches, 0 loops; skeleton only */
u32 esp_wifi_stop(u32 a3, u32 a4)
{
    /* frame: entry a1,48; 144 insns, 10 cond-branches, 0 loops, 7 jumps */
    /* immediates: 24, 1, 2, 6, 0x101, 64, 10, 0x1f4, 0 */
    /* first predicate: bnez a10, 1f8 <esp_wifi_stop+0x188> (condition opaque) */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=0x16c */
    /* mem ld8: base=(lit:s_wifi_stop_in_progress) off=0 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=176 */
    /* mem st8: base=(lit:s_wifi_stop_in_progress) off=0 */
    /* mem st8: base=(literal) off=0 */
    /* mem st8: base=(literal) off=8 */
    /* mem st32: base=(literal) off=4 */
    /* mem ld32: base=(*(g_osi_funcs_p+176)) off=0 */
    /* ... +16 more memops */
    /* site +0x76: wifi_api_lock(/* no traced args */) */
    wifi_api_lock(/* no traced args */);
    /* site +0x8b: indirect call via a2 (base *(*(g_osi_funcs_p+0)+0x16c)); args: 24 */
    opaque_indirect_a2();
    /* site +0x96: wifi_api_unlock(ret@8b) */
    wifi_api_unlock(ret@8b);
    /* site +0xa5: wifi_log(6, 2, 1, lit:.rodata_wlog_error.13) */
    wifi_log(6, 2, 1, lit:.rodata_wlog_error.13);
    /* site +0xbd: indirect call via a3 (base *(g_osi_funcs_p+176)); args: ret@a5, 2, 1, lit:.rodata_wlog_error.13 */
    opaque_indirect_a3();
    /* site +0xc3: wifi_api_unlock(ret@bd, 2, 1, lit:.rodata_wlog_error.13) */
    wifi_api_unlock(ret@bd, 2, 1, lit:.rodata_wlog_error.13);
    /* site +0xda: wifi_api_unlock(ret@c3, 2, 1, lit:.rodata_wlog_error.13) */
    wifi_api_unlock(ret@c3, 2, 1, lit:.rodata_wlog_error.13);
    /* site +0xe0: reset_cs_thres(ret@da, 2, 1, lit:.rodata_wlog_error.13) */
    reset_cs_thres(ret@da, 2, 1, lit:.rodata_wlog_error.13);
    /* site +0xfb: ieee80211_ioctl(literal, 2, 1, lit:.rodata_wlog_error.13) */
    ieee80211_ioctl(literal, 2, 1, lit:.rodata_wlog_error.13);
    /* site +0x11b: indirect call via a7 (base *(*(g_osi_funcs_p+0)+0x16c)); args: 24, 2, 1, lit:.rodata_wlog_error.13 */
    opaque_indirect_a7();
    /* site +0x142: ieee80211_ioctl(6, 64, 1, lit:.rodata_wlog_error.15) */
    ieee80211_ioctl(6, 64, 1, lit:.rodata_wlog_error.15);
    /* site +0x15a: indirect call via a7 (base *(*(g_osi_funcs_p+0)+160)); args: 10, 64, 1, lit:.rodata_wlog_error.15 */
    opaque_indirect_a7();
    /* site +0x15f: indirect call via a8 (base *(?+0)); args: ret@15a, 64, 1, lit:.rodata_wlog_error.15 */
    opaque_indirect_a8();
    /* site +0x18a: wifi_log(6, 64, 2, lit:.rodata_wlog_warning.16, (*(s_wifi_stop_in_progress+0)+1)) */
    wifi_log(6, 64, 2, lit:.rodata_wlog_warning.16, (*(s_wifi_stop_in_progress+0)+1));
    /* site +0x19f: wifi_log(6, 64, 2, lit:.rodata_wlog_warning.17, (*(s_wifi_stop_in_progress+0)+1)) */
    wifi_log(6, 64, 2, lit:.rodata_wlog_warning.17, (*(s_wifi_stop_in_progress+0)+1));
    /* site +0x1a9: indirect call via a2 (base *(*(g_osi_funcs_p+0)+0x16c)); args: 24, 64, 2, lit:.rodata_wlog_warning.17, (*(s_wifi_stop_in_progress+0)+1) */
    opaque_indirect_a2();
    /* site +0x1c1: ieee80211_ioctl(ret@1a9, 64, 2, lit:.rodata_wlog_warning.17, (*(s_wifi_stop_in_progress+0)+1)) */
    ieee80211_ioctl(ret@1a9, 64, 2, lit:.rodata_wlog_warning.17, (*(s_wifi_stop_in_progress+0)+1));
    /* site +0x1d5: wifi_log(1, 2, 1, lit:.rodata_wlog_error.18, (*(s_wifi_stop_in_progress+0)+1)) */
    wifi_log(1, 2, 1, lit:.rodata_wlog_error.18, (*(s_wifi_stop_in_progress+0)+1));
    /* site +0x1e3: wifi_api_lock(ret@1d5, 2, 1, lit:.rodata_wlog_error.18, (*(s_wifi_stop_in_progress+0)+1)) */
    wifi_api_lock(ret@1d5, 2, 1, lit:.rodata_wlog_error.18, (*(s_wifi_stop_in_progress+0)+1));
    /* site +0x1f5: wifi_api_unlock(ret@1e3, 2, 1, lit:.rodata_wlog_error.18, (*(s_wifi_stop_in_progress+0)+1)) */
    wifi_api_unlock(ret@1e3, 2, 1, lit:.rodata_wlog_error.18, (*(s_wifi_stop_in_progress+0)+1));
    return 0x1f4;
}

/* esp_wifi_connect_internal @ ieee80211_api.o 0x0000001c size 76B bind GLOBAL
 * Calls: wifi_init_completed, indirect(a2), ieee80211_ioctl | Data refs: g_ic, g_osi_funcs_p, wifi_connect_process
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 esp_wifi_connect_internal(u32 a2)
{
    /* frame: entry a1,32; 27 insns, 3 cond-branches, 0 loops, 0 jumps */
    /* immediates: 24, 0x101, 3 */
    /* first predicate: beqz.n a10, 66 <esp_wifi_connect_internal+0x4a> (condition opaque) */
    /* mem ld8: base=((lit:g_ic+65536)) off=237 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=0x178 */
    /* mem st32: base=(ret@45) off=4 */
    /* mem st8: base=(ret@45) off=0 */
    /* site +0x22: wifi_init_completed(/* no traced args */) */
    wifi_init_completed(/* no traced args */);
    /* site +0x45: indirect call via a2 (base *(g_osi_funcs_p+0x178)); args: 24 */
    opaque_indirect_a2();
    /* site +0x61: ieee80211_ioctl(ret@45) */
    ieee80211_ioctl(ret@45);
    return last_call_result; /* opaque */
}

/* esp_wifi_disconnect_internal @ ieee80211_api.o 0x0000001c size 76B bind GLOBAL
 * Calls: wifi_init_completed, indirect(a2), ieee80211_ioctl | Data refs: g_ic, g_osi_funcs_p, wifi_disconnect_process
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 esp_wifi_disconnect_internal(u32 a2)
{
    /* frame: entry a1,32; 27 insns, 3 cond-branches, 0 loops, 0 jumps */
    /* immediates: 24, 0x101, 4 */
    /* first predicate: beqz.n a10, 66 <esp_wifi_disconnect_internal+0x4a> (condition opaque) */
    /* mem ld8: base=((lit:g_ic+65536)) off=237 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=0x178 */
    /* mem st32: base=(ret@45) off=4 */
    /* mem st8: base=(ret@45) off=0 */
    /* site +0x22: wifi_init_completed(/* no traced args */) */
    wifi_init_completed(/* no traced args */);
    /* site +0x45: indirect call via a2 (base *(g_osi_funcs_p+0x178)); args: 24 */
    opaque_indirect_a2();
    /* site +0x61: ieee80211_ioctl(ret@45) */
    ieee80211_ioctl(ret@45);
    return last_call_result; /* opaque */
}

/* esp_wifi_clear_fast_connect @ ieee80211_api.o 0x00000008 size 19B bind GLOBAL
 * Calls: wifi_init_completed | Data refs: none
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 esp_wifi_clear_fast_connect(void)
{
    /* frame: entry a1,32; 7 insns, 1 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0 */
    /* first predicate: bne a10, a2, 19 <esp_wifi_clear_fast_connect+0x11> (condition opaque) */
    /* site +0xe: wifi_init_completed(/* no traced args */) */
    wifi_init_completed(/* no traced args */);
    return opaque_result; /* full dataflow not recovered */
}

/* esp_wifi_deauth_sta @ ieee80211_api.o 0x0000001c size 92B bind GLOBAL
 * Calls: wifi_init_completed, indirect(a2), ieee80211_ioctl | Data refs: g_ic, g_osi_funcs_p, wifi_deauth_sta_process
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 esp_wifi_deauth_sta(u32 a2)
{
    /* frame: entry a1,32; 33 insns, 3 cond-branches, 0 loops, 0 jumps */
    /* immediates: 24, 0x101, 37, 0 */
    /* first predicate: beqz a10, 76 <esp_wifi_deauth_sta+0x5a> (condition opaque) */
    /* mem ld8: base=((lit:g_ic+65536)) off=237 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=0x178 */
    /* mem st8: base=(ret@49) off=0 */
    /* mem st16: base=(ret@49) off=8 */
    /* mem st32: base=(ret@49) off=4 */
    /* mem st8: base=(ret@49) off=10 */
    /* mem st32: base=(ret@49) off=12 */
    /* site +0x22: wifi_init_completed(/* no traced args */) */
    wifi_init_completed(/* no traced args */);
    /* site +0x49: indirect call via a2 (base *(g_osi_funcs_p+0x178)); args: 24 */
    opaque_indirect_a2();
    /* site +0x71: ieee80211_ioctl(ret@49) */
    ieee80211_ioctl(ret@49);
    return last_call_result; /* opaque */
}

/* esp_wifi_promiscuous_scan_start @ ieee80211_api.o 0x00000018 size 140B bind GLOBAL
 * Calls: wifi_init_completed, indirect(a4), memcpy, indirect(a4), ieee80211_ioctl | Data refs: g_osi_funcs_p, wifi_scan_start_process
 * Fidelity: medium - branchy but loop-free, call sequence mapped */
u32 esp_wifi_promiscuous_scan_start(u32 a2, u32 a3, u32 a4)
{
    /* frame: entry a1,32; 53 insns, 4 cond-branches, 0 loops, 2 jumps */
    /* immediates: 68, 0x101, 5, 44, 0, 24, 1 */
    /* first predicate: beqz a10, a0 <esp_wifi_promiscuous_scan_start+0x88> (condition opaque) */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=0x178 */
    /* mem st8: base=(ret@35) off=0 */
    /* mem st32: base=(ret@35) off=4 */
    /* mem st16: base=(ret@35) off=8 */
    /* mem st8: base=(ret@35) off=10 */
    /* mem st32: base=(ret@35) off=12 */
    /* mem st8: base=(ret@73) off=0 */
    /* mem st32: base=(ret@73) off=4 */
    /* mem st16: base=(ret@73) off=8 */
    /* ... +3 more memops */
    /* site +0x1e: wifi_init_completed(/* no traced args */) */
    wifi_init_completed(/* no traced args */);
    /* site +0x35: indirect call via a4 (base *(g_osi_funcs_p+0x178)); args: 68 */
    opaque_indirect_a4();
    /* site +0x69: memcpy((ret@35+20), ?, 44) */
    memcpy((ret@35+20), ?, 44);
    /* site +0x73: indirect call via a4 (base 0x101); args: 24, ?, 44 */
    opaque_indirect_a4();
    /* site +0x9b: ieee80211_ioctl(ret@73, ?, 44) */
    ieee80211_ioctl(ret@73, ?, 44);
    return last_call_result; /* opaque */
}

/* get_total_scan_time @ ieee80211_api.o 0x00000010 size 220B bind GLOBAL
 * Calls: ieee80211_regdomain_policy, ieee80211_regdomain_chan_num | Data refs: g_ic
 * Fidelity: medium - branchy but loop-free, call sequence mapped (verified: section R_XTENSA_ASM_EXPAND + funcdb v3 agree; predicates opaque) */
u32 get_total_scan_time(u32 a2, u32 a4)
{
    /* frame: entry a1,32; 81 insns, 14 cond-branches, 0 loops, 7 jumps */
    /* immediates: 11, 3, 23, 12, 16, 19, 120, 0x5dc, 0x168, 200 */
    /* first predicate: beqi a3, 1, 44 <get_total_scan_time+0x34> (condition opaque) */
    /* mem ld8: base=((lit:g_ic+131072)) off=173 */
    /* mem ld32: base=(?) off=20 */
    /* mem ld32: base=(?) off=24 */
    /* mem ld32: base=(?) off=12 */
    /* mem ld32: base=(lit:g_ic) off=20 */
    /* mem ld32: base=(lit:g_ic) off=16 */
    /* mem ld32: base=(*(g_ic+16)) off=228 */
    /* mem ld32: base=(?) off=12 */
    /* mem ld32: base=(lit:g_ic) off=4 */
    /* mem ld8: base=((*(g_ic+4)+65536)) off=24 */
    /* ... +4 more memops */
    /* site +0x16: ieee80211_regdomain_policy(/* no traced args */) */
    ieee80211_regdomain_policy(/* no traced args */);
    /* site +0x29: ieee80211_regdomain_chan_num(*((lit:g_ic+131072)+173)) */
    ieee80211_regdomain_chan_num(*((lit:g_ic+131072)+173));
    return opaque_result; /* full dataflow not recovered */
}

/* esp_wifi_scan_start @ ieee80211_api.o 0x00000058 size 390B bind GLOBAL
 * Calls: wifi_init_completed, indirect(a2), indirect(a2), scan_set_scan_id, ieee80211_regdomain_check_channel, wifi_log, indirect(a2), memcpy, indirect(a2), ieee80211_ioctl, get_total_scan_time, scan_get_scan_id, wifi_log, indirect(a8), indirect(a9), wifi_log | Data refs: g_ic, g_wifi_global_lock, g_osi_funcs_p, .bss.old_scan_id$2, g_wifi_nvs, .rodata_wlog_error.19, wifi_scan_start_process, .rodata_wlog_warning.20, .rodata_wlog_verbose.21
 * Fidelity: low - 141 insns, 13 branches, 0 loops; skeleton only */
u32 esp_wifi_scan_start(u32 a2, u32 a3, u32 a7)
{
    /* frame: entry a1,48; 141 insns, 13 cond-branches, 0 loops, 6 jumps */
    /* immediates: 0, 1, 4, 0x102, 68, 0x101, 5, 44, 24, 100 */
    /* first predicate: beqz a10, 1dc <esp_wifi_scan_start+0x184> (condition opaque) */
    /* mem ld8: base=((lit:g_ic+65536)) off=237 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(lit:g_wifi_global_lock) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=84 */
    /* mem ld8: base=(lit:.bss.old_scan_id$2) off=0 */
    /* mem st8: base=(lit:.bss.old_scan_id$2) off=0 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(lit:g_wifi_global_lock) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=88 */
    /* mem ld8: base=(?) off=8 */
    /* ... +23 more memops */
    /* site +0x5e: wifi_init_completed(/* no traced args */) */
    wifi_init_completed(/* no traced args */);
    /* site +0x8d: indirect call via a2 (base *(g_ic+84)); args: *(g_wifi_global_lock+0) */
    opaque_indirect_a2();
    /* site +0xb3: indirect call via a2 (base *(g_ic+88)); args: *(g_wifi_global_lock+0) */
    opaque_indirect_a2();
    /* site +0xbb: scan_set_scan_id(*(.bss.old_scan_id$2+0)) */
    scan_set_scan_id(*(.bss.old_scan_id$2+0));
    /* site +0xc9: ieee80211_regdomain_check_channel(*(?+8)) */
    ieee80211_regdomain_check_channel(*(?+8));
    /* site +0xed: wifi_log(ret@c9, 4, 1, lit:.rodata_wlog_error.19, *(?+8)) */
    wifi_log(ret@c9, 4, 1, lit:.rodata_wlog_error.19, *(?+8));
    /* site +0xfd: indirect call via a2 (base *(g_wifi_nvs+0x178)); args: 68, 4, 1, lit:.rodata_wlog_error.19, *(?+8) */
    opaque_indirect_a2();
    /* site +0x133: memcpy((ret@fd+20), ?, 44, lit:.rodata_wlog_error.19, *(?+8)) */
    memcpy((ret@fd+20), ?, 44, lit:.rodata_wlog_error.19, *(?+8));
    /* site +0x145: indirect call via a2 (base *(g_wifi_nvs+0x178)); args: 24, ?, 44, lit:.rodata_wlog_error.19, *(?+8) */
    opaque_indirect_a2();
    /* site +0x16f: ieee80211_ioctl(ret@145, ?, 44, lit:.rodata_wlog_error.19, *(?+8)) */
    ieee80211_ioctl(ret@145, ?, 44, lit:.rodata_wlog_error.19, *(?+8));
    /* site +0x17f: get_total_scan_time(?, ?, 44, lit:.rodata_wlog_error.19, *(?+8)) */
    get_total_scan_time(?, ?, 44, lit:.rodata_wlog_error.19, *(?+8));
    /* site +0x18c: scan_get_scan_id(ret@17f, ?, 44, lit:.rodata_wlog_error.19, *(?+8)) */
    scan_get_scan_id(ret@17f, ?, 44, lit:.rodata_wlog_error.19, *(?+8));
    /* site +0x1a1: wifi_log(1, 10, 2, lit:.rodata_wlog_warning.20, *(?+8)) */
    wifi_log(1, 10, 2, lit:.rodata_wlog_warning.20, *(?+8));
    /* site +0x1bb: indirect call via a8 (base *(.bss.old_scan_id$2+160)); args: 100, 10, 2, lit:.rodata_wlog_warning.20, *(?+8) */
    opaque_indirect_a8();
    /* site +0x1c1: indirect call via a9 (base *(?+0)); args: ret@1bb, 10, 2, lit:.rodata_wlog_warning.20, *(?+8) */
    opaque_indirect_a9();
    /* site +0x1d6: wifi_log(1, 10, 5, lit:.rodata_wlog_verbose.21, *(?+8)) */
    wifi_log(1, 10, 5, lit:.rodata_wlog_verbose.21, *(?+8));
    return opaque_result; /* full dataflow not recovered */
}

/* esp_wifi_scan_stop @ ieee80211_api.o 0x0000001c size 76B bind GLOBAL
 * Calls: wifi_init_completed, indirect(a2), ieee80211_ioctl | Data refs: g_ic, g_osi_funcs_p, wifi_scan_stop_process
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 esp_wifi_scan_stop(u32 a2)
{
    /* frame: entry a1,32; 27 insns, 3 cond-branches, 0 loops, 0 jumps */
    /* immediates: 24, 0x101, 6 */
    /* first predicate: beqz.n a10, 66 <esp_wifi_scan_stop+0x4a> (condition opaque) */
    /* mem ld8: base=((lit:g_ic+65536)) off=237 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=0x178 */
    /* mem st32: base=(ret@45) off=4 */
    /* mem st8: base=(ret@45) off=0 */
    /* site +0x22: wifi_init_completed(/* no traced args */) */
    wifi_init_completed(/* no traced args */);
    /* site +0x45: indirect call via a2 (base *(g_osi_funcs_p+0x178)); args: 24 */
    opaque_indirect_a2();
    /* site +0x61: ieee80211_ioctl(ret@45) */
    ieee80211_ioctl(ret@45);
    return last_call_result; /* opaque */
}

/* esp_wifi_set_scan_parameters @ ieee80211_api.o 0x00000020 size 164B bind GLOBAL
 * Calls: wifi_init_completed, indirect(a3), memcpy, indirect(a3), ieee80211_ioctl | Data refs: g_ic, g_osi_funcs_p, wifi_set_scan_params_process
 * Fidelity: medium - branchy but loop-free, call sequence mapped */
u32 esp_wifi_set_scan_parameters(u32 a2, u32 a3)
{
    /* frame: entry a1,32; 60 insns, 5 cond-branches, 0 loops, 3 jumps */
    /* immediates: 40, 0x101, 108, 16, 0, 24, 1 */
    /* first predicate: beqz a10, c0 <esp_wifi_set_scan_parameters+0xa0> (condition opaque) */
    /* mem ld8: base=((lit:g_ic+65536)) off=237 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=0x178 */
    /* mem st8: base=(ret@4e) off=0 */
    /* mem st32: base=(ret@4e) off=4 */
    /* mem st16: base=(ret@4e) off=8 */
    /* mem st8: base=(ret@4e) off=10 */
    /* mem st32: base=(ret@4e) off=12 */
    /* mem st8: base=(ret@92) off=0 */
    /* mem st32: base=(ret@92) off=4 */
    /* ... +4 more memops */
    /* site +0x26: wifi_init_completed(/* no traced args */) */
    wifi_init_completed(/* no traced args */);
    /* site +0x4e: indirect call via a3 (base *(g_osi_funcs_p+0x178)); args: 40 */
    opaque_indirect_a3();
    /* site +0x86: memcpy((ret@4e+20), ?, 16) */
    memcpy((ret@4e+20), ?, 16);
    /* site +0x92: indirect call via a3 (base 0x101); args: 24, ?, 16 */
    opaque_indirect_a3();
    /* site +0xbb: ieee80211_ioctl(ret@92, ?, 16) */
    ieee80211_ioctl(ret@92, ?, 16);
    return last_call_result; /* opaque */
}

/* esp_wifi_get_scan_parameters @ ieee80211_api.o 0x00000014 size 84B bind GLOBAL
 * Calls: wifi_init_completed, indirect(a8), ieee80211_ioctl | Data refs: g_osi_funcs_p, wifi_get_scan_params_process
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 esp_wifi_get_scan_parameters(u32 a2)
{
    /* frame: entry a1,32; 32 insns, 3 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0x102, 24, 0x101, 109, 0 */
    /* first predicate: beqz a10, 64 <esp_wifi_get_scan_parameters+0x50> (condition opaque) */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=0x178 */
    /* mem st8: base=(ret@32) off=0 */
    /* mem st32: base=(ret@32) off=4 */
    /* mem st16: base=(ret@32) off=8 */
    /* mem st8: base=(ret@32) off=10 */
    /* mem st32: base=(ret@32) off=12 */
    /* mem st32: base=(ret@32) off=20 */
    /* site +0x1a: wifi_init_completed(/* no traced args */) */
    wifi_init_completed(/* no traced args */);
    /* site +0x32: indirect call via a8 (base *(g_osi_funcs_p+0x178)); args: 24 */
    opaque_indirect_a8();
    /* site +0x5f: ieee80211_ioctl(ret@32) */
    ieee80211_ioctl(ret@32);
    return last_call_result; /* opaque */
}

/* esp_wifi_scan_get_ap_num @ ieee80211_api.o 0x00000024 size 86B bind GLOBAL
 * Calls: wifi_init_completed, wifi_api_lock, scan_get_apnum, wifi_api_unlock, wifi_log | Data refs: g_ic, .rodata_wlog_verbose.22
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 esp_wifi_scan_get_ap_num(u32 a2)
{
    /* frame: entry a1,32; 31 insns, 3 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0x102, 5, 11, 1, 0 */
    /* first predicate: beqz a10, 76 <esp_wifi_scan_get_ap_num+0x52> (condition opaque) */
    /* mem ld8: base=((lit:g_ic+65536)) off=237 */
    /* mem st16: base=(?) off=0 */
    /* mem ld16: base=(?) off=0 */
    /* site +0x2a: wifi_init_completed(/* no traced args */) */
    wifi_init_completed(/* no traced args */);
    /* site +0x4a: wifi_api_lock(ret@2a) */
    wifi_api_lock(ret@2a);
    /* site +0x50: scan_get_apnum(ret@4a) */
    scan_get_apnum(ret@4a);
    /* site +0x5f: wifi_api_unlock(ret@50) */
    wifi_api_unlock(ret@50);
    /* site +0x71: wifi_log(1, 11, 5, lit:.rodata_wlog_verbose.22, *(?+0)) */
    wifi_log(1, 11, 5, lit:.rodata_wlog_verbose.22, *(?+0));
    return 0;
}

/* esp_wifi_scan_get_ap_records @ ieee80211_api.o 0x00000020 size 140B bind GLOBAL
 * Calls: wifi_init_completed, indirect(a8), indirect(a10), ieee80211_ioctl | Data refs: g_ic, g_osi_funcs_p, esp_mesh_quick_funcs, wifi_get_ap_list_process
 * Fidelity: medium - branchy but loop-free, call sequence mapped */
u32 esp_wifi_scan_get_ap_records(u32 a2, u32 a3)
{
    /* frame: entry a1,32; 50 insns, 8 cond-branches, 0 loops, 2 jumps */
    /* immediates: 0x102, 24, 0x101, 0x301, 7, 0 */
    /* first predicate: beqz a10, a8 <esp_wifi_scan_get_ap_records+0x88> (condition opaque) */
    /* mem ld8: base=((lit:g_ic+65536)) off=237 */
    /* mem ld16: base=(?) off=0 */
    /* mem ld32: base=(lit:g_ic) off=116 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=0x178 */
    /* mem ld32: base=(lit:esp_mesh_quick_funcs) off=112 */
    /* mem st8: base=(ret@72) off=0 */
    /* mem st32: base=(ret@72) off=4 */
    /* mem st16: base=(ret@72) off=8 */
    /* mem st8: base=(ret@72) off=10 */
    /* ... +2 more memops */
    /* site +0x26: wifi_init_completed(/* no traced args */) */
    wifi_init_completed(/* no traced args */);
    /* site +0x61: indirect call via a8 (base *(g_osi_funcs_p+0x178)); args: 24 */
    opaque_indirect_a8();
    /* site +0x72: indirect call via a10 (base *(esp_mesh_quick_funcs+112)); args: *(esp_mesh_quick_funcs+112) */
    opaque_indirect_a10();
    /* site +0xa3: ieee80211_ioctl(ret@72) */
    ieee80211_ioctl(ret@72);
    return last_call_result; /* opaque */
}

/* esp_wifi_scan_get_ap_record @ ieee80211_api.o 0x0000001c size 100B bind GLOBAL
 * Calls: wifi_init_completed, indirect(a8), ieee80211_ioctl | Data refs: g_ic, g_osi_funcs_p, wifi_get_ap_record_process
 * Fidelity: medium - branchy but loop-free, call sequence mapped */
u32 esp_wifi_scan_get_ap_record(u32 a2)
{
    /* frame: entry a1,32; 37 insns, 4 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0x102, 24, 0x101, 105, 0 */
    /* first predicate: beqz a10, 7c <esp_wifi_scan_get_ap_record+0x60> (condition opaque) */
    /* mem ld8: base=((lit:g_ic+65536)) off=237 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=0x178 */
    /* mem st8: base=(ret@49) off=0 */
    /* mem st32: base=(ret@49) off=4 */
    /* mem st16: base=(ret@49) off=8 */
    /* mem st8: base=(ret@49) off=10 */
    /* mem st32: base=(ret@49) off=12 */
    /* mem st32: base=(ret@49) off=20 */
    /* site +0x22: wifi_init_completed(/* no traced args */) */
    wifi_init_completed(/* no traced args */);
    /* site +0x49: indirect call via a8 (base *(g_osi_funcs_p+0x178)); args: 24 */
    opaque_indirect_a8();
    /* site +0x77: ieee80211_ioctl(ret@49) */
    ieee80211_ioctl(ret@49);
    return last_call_result; /* opaque */
}

/* esp_wifi_clear_ap_list @ ieee80211_api.o 0x0000001c size 76B bind GLOBAL
 * Calls: wifi_init_completed, indirect(a2), ieee80211_ioctl | Data refs: g_ic, g_osi_funcs_p, wifi_clear_ap_list_process
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 esp_wifi_clear_ap_list(u32 a2)
{
    /* frame: entry a1,32; 27 insns, 3 cond-branches, 0 loops, 0 jumps */
    /* immediates: 24, 0x101, 90 */
    /* first predicate: beqz.n a10, 66 <esp_wifi_clear_ap_list+0x4a> (condition opaque) */
    /* mem ld8: base=((lit:g_ic+65536)) off=237 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=0x178 */
    /* mem st32: base=(ret@45) off=4 */
    /* mem st8: base=(ret@45) off=0 */
    /* site +0x22: wifi_init_completed(/* no traced args */) */
    wifi_init_completed(/* no traced args */);
    /* site +0x45: indirect call via a2 (base *(g_osi_funcs_p+0x178)); args: 24 */
    opaque_indirect_a2();
    /* site +0x61: ieee80211_ioctl(ret@45) */
    ieee80211_ioctl(ret@45);
    return last_call_result; /* opaque */
}

/* esp_wifi_set_config @ ieee80211_api.o 0x0000001c size 110B bind GLOBAL
 * Calls: wifi_init_completed, indirect(a4), memcpy, ieee80211_ioctl | Data refs: g_osi_funcs_p, wifi_set_config_process
 * Fidelity: medium - branchy but loop-free, call sequence mapped */
u32 esp_wifi_set_config(u32 a2, u32 a3, u32 a4)
{
    /* frame: entry a1,32; 41 insns, 4 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0x102, 208, 0x101, 11, 184, 0 */
    /* first predicate: beqz a10, 86 <esp_wifi_set_config+0x6a> (condition opaque) */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=0x178 */
    /* mem st8: base=(ret@42) off=0 */
    /* mem st8: base=(ret@42) off=8 */
    /* mem st32: base=(ret@42) off=4 */
    /* mem st8: base=(ret@42) off=9 */
    /* mem st8: base=(ret@42) off=10 */
    /* mem st32: base=(ret@42) off=12 */
    /* site +0x22: wifi_init_completed(/* no traced args */) */
    wifi_init_completed(/* no traced args */);
    /* site +0x42: indirect call via a4 (base *(g_osi_funcs_p+0x178)); args: 208 */
    opaque_indirect_a4();
    /* site +0x79: memcpy((ret@42+20), ?, 184) */
    memcpy((ret@42+20), ?, 184);
    /* site +0x81: ieee80211_ioctl(ret@42, ?, 184) */
    ieee80211_ioctl(ret@42, ?, 184);
    return last_call_result; /* opaque */
}

/* esp_wifi_get_config @ ieee80211_api.o 0x00000018 size 80B bind GLOBAL
 * Calls: wifi_init_completed, wifi_station_get_config_local, nan_get_config_local, indirect(a2) | Data refs: net80211_funcs
 * Fidelity: medium - branchy but loop-free, call sequence mapped */
u32 esp_wifi_get_config(u32 a2, u32 a3)
{
    /* frame: entry a1,32; 29 insns, 6 cond-branches, 0 loops, 2 jumps */
    /* immediates: 0x102 */
    /* first predicate: beqz.n a10, 64 <esp_wifi_get_config+0x4c> (condition opaque) */
    /* mem ld32: base=(lit:net80211_funcs) off=0 */
    /* mem ld32: base=(*(net80211_funcs+0)) off=24 */
    /* site +0x1e: wifi_init_completed(/* no traced args */) */
    wifi_init_completed(/* no traced args */);
    /* site +0x39: wifi_station_get_config_local(ret@1e) */
    wifi_station_get_config_local(ret@1e);
    /* site +0x49: nan_get_config_local(/* no traced args */) */
    nan_get_config_local(/* no traced args */);
    /* site +0x5f: indirect call via a2 (base *(net80211_funcs+24)); args: ret@49 */
    opaque_indirect_a2();
    return last_call_result; /* opaque */
}

/* esp_wifi_ap_get_sta_list @ ieee80211_api.o 0x00000014 size 82B bind GLOBAL
 * Calls: wifi_init_completed, indirect(a8), ieee80211_ioctl | Data refs: g_osi_funcs_p, wifi_get_sta_list_process
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 esp_wifi_ap_get_sta_list(u32 a2)
{
    /* frame: entry a1,32; 32 insns, 3 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0x102, 24, 0x101, 9, 0 */
    /* first predicate: beqz.n a10, 62 <esp_wifi_ap_get_sta_list+0x4e> (condition opaque) */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=0x178 */
    /* mem st8: base=(ret@31) off=0 */
    /* mem st32: base=(ret@31) off=4 */
    /* mem st16: base=(ret@31) off=8 */
    /* mem st8: base=(ret@31) off=10 */
    /* mem st32: base=(ret@31) off=12 */
    /* mem st32: base=(ret@31) off=20 */
    /* site +0x1a: wifi_init_completed(/* no traced args */) */
    wifi_init_completed(/* no traced args */);
    /* site +0x31: indirect call via a8 (base *(g_osi_funcs_p+0x178)); args: 24 */
    opaque_indirect_a8();
    /* site +0x5d: ieee80211_ioctl(ret@31) */
    ieee80211_ioctl(ret@31);
    return last_call_result; /* opaque */
}

/* esp_wifi_connectionless_module_set_wake_interval @ ieee80211_api.o 0x00000014 size 78B bind GLOBAL
 * Calls: wifi_init_completed, indirect(a2), ieee80211_ioctl | Data refs: g_osi_funcs_p, wifi_configure_wake_interval_process
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 esp_wifi_connectionless_module_set_wake_interval(u32 a2)
{
    /* frame: entry a1,32; 28 insns, 2 cond-branches, 0 loops, 0 jumps */
    /* immediates: 24, 0x101, 115, 0 */
    /* first predicate: beqz.n a10, 60 <esp_wifi_connectionless_module_set_wake_interval+0x4c> (condition opaque) */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=0x178 */
    /* mem st8: base=(ret@31) off=0 */
    /* mem st16: base=(ret@31) off=8 */
    /* mem st32: base=(ret@31) off=4 */
    /* mem st8: base=(ret@31) off=10 */
    /* mem st32: base=(ret@31) off=12 */
    /* site +0x1a: wifi_init_completed(/* no traced args */) */
    wifi_init_completed(/* no traced args */);
    /* site +0x31: indirect call via a2 (base *(g_osi_funcs_p+0x178)); args: 24 */
    opaque_indirect_a2();
    /* site +0x5b: ieee80211_ioctl(ret@31) */
    ieee80211_ioctl(ret@31);
    return last_call_result; /* opaque */
}

/* esp_wifi_set_ps @ ieee80211_api.o 0x00000014 size 68B bind GLOBAL
 * Calls: wifi_init_completed, indirect(a2), ieee80211_ioctl | Data refs: g_osi_funcs_p, wifi_set_ps_process
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 esp_wifi_set_ps(u32 a2)
{
    /* frame: entry a1,32; 25 insns, 3 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0x102, 24, 0, 19 */
    /* first predicate: beqz.n a10, 56 <esp_wifi_set_ps+0x42> (condition opaque) */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=0x178 */
    /* mem st32: base=(ret@35) off=4 */
    /* mem st8: base=(ret@35) off=0 */
    /* mem st8: base=(ret@35) off=8 */
    /* site +0x1a: wifi_init_completed(/* no traced args */) */
    wifi_init_completed(/* no traced args */);
    /* site +0x35: indirect call via a2 (base *(g_osi_funcs_p+0x178)); args: 24 */
    opaque_indirect_a2();
    /* site +0x53: ieee80211_ioctl(ret@35) */
    ieee80211_ioctl(ret@35);
    return opaque_result; /* full dataflow not recovered */
}

/* esp_wifi_get_ps @ ieee80211_api.o 0x0000000c size 36B bind GLOBAL
 * Calls: wifi_init_completed, pm_get_sleep_type | Data refs: none
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 esp_wifi_get_ps(u32 a2)
{
    /* frame: entry a1,32; 14 insns, 2 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0x102, 0 */
    /* first predicate: beqz.n a10, 29 <esp_wifi_get_ps+0x1d> (condition opaque) */
    /* mem st32: base=(?) off=0 */
    /* site +0x12: wifi_init_completed(/* no traced args */) */
    wifi_init_completed(/* no traced args */);
    /* site +0x22: pm_get_sleep_type(ret@12) */
    pm_get_sleep_type(ret@12);
    return 0;
}

/* esp_wifi_set_protocol @ ieee80211_api.o 0x00000028 size 176B bind GLOBAL
 * Calls: wifi_log, wifi_init_completed, indirect(a3), ieee80211_ioctl | Data refs: .rodata_wlog_error.23, g_wifi_nvs, .rodata.esp_wifi_set_protocol, g_osi_funcs_p, wifi_set_protocol_process
 * Fidelity: low - jx computed-switch over protocol bitmap (bgeui bound check + jx a4 at +0x7c, cases via .rodata.esp_wifi_set_protocol, 6 jump arms); per-case bit stores observed but case-to-bit mapping structural - need rodata table dump + per-case store tracing to raise */
u32 esp_wifi_set_protocol(u32 a2, u32 a3, u32 a5)
{
    /* frame: entry a1,32; 66 insns, 6 cond-branches, 0 loops, 6 jumps */
    /* immediates: 48, 1, 3, 14, 2, 4, 24, 0x101, 12, 0 */
    /* first predicate: beqz.n a4, 48 <esp_wifi_set_protocol+0x20> (condition opaque) */
    /* mem ld32: base=(lit:g_wifi_nvs) off=0 */
    /* mem ld32: base=((*(g_wifi_nvs+0)+327680)) off=200 */
    /* mem ld32: base=((?+-1)) off=0 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=0x178 */
    /* mem st8: base=(ret@9e) off=0 */
    /* mem st8: base=(ret@9e) off=8 */
    /* mem st32: base=(ret@9e) off=4 */
    /* mem st8: base=(ret@9e) off=9 */
    /* mem st8: base=(ret@9e) off=10 */
    /* ... +1 more memops */
    /* site +0x41: wifi_log(1, 3, 1, lit:.rodata_wlog_error.23) */
    wifi_log(1, 3, 1, lit:.rodata_wlog_error.23);
    /* site +0x4b: wifi_init_completed(ret@41, 3, 1, lit:.rodata_wlog_error.23) */
    wifi_init_completed(ret@41, 3, 1, lit:.rodata_wlog_error.23);
    /* site +0x9e: indirect call via a3 (base *(g_osi_funcs_p+0x178)); args: 24, 3, 1, lit:.rodata_wlog_error.23 */
    opaque_indirect_a3();
    /* site +0xc9: ieee80211_ioctl(ret@9e, 3, 1, lit:.rodata_wlog_error.23) */
    ieee80211_ioctl(ret@9e, 3, 1, lit:.rodata_wlog_error.23);
    return 0x102;
}

/* esp_wifi_get_protocol @ ieee80211_api.o 0x00000024 size 152B bind GLOBAL
 * Calls: wifi_init_completed, wifi_log, indirect(a8), ieee80211_ioctl | Data refs: g_wifi_nvs, .rodata_wlog_error.24, g_osi_funcs_p, wifi_get_protocol_process
 * Fidelity: medium - branchy but loop-free, call sequence mapped */
u32 esp_wifi_get_protocol(u32 a2, u32 a3, u32 a4)
{
    /* frame: entry a1,32; 55 insns, 5 cond-branches, 0 loops, 1 jumps */
    /* immediates: 0x102, 1, 0x106, 24, 0x101, 13, 0 */
    /* first predicate: beqz a10, b8 <esp_wifi_get_protocol+0x94> (condition opaque) */
    /* mem ld32: base=(lit:g_wifi_nvs) off=0 */
    /* mem ld32: base=((*(g_wifi_nvs+0)+327680)) off=200 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=0x178 */
    /* mem st8: base=(ret@6e) off=0 */
    /* mem st32: base=(ret@6e) off=4 */
    /* mem ld32: base=(lit:g_wifi_nvs) off=0 */
    /* mem st8: base=(ret@6e) off=8 */
    /* mem st8: base=(ret@6e) off=9 */
    /* mem st8: base=(ret@6e) off=10 */
    /* ... +3 more memops */
    /* site +0x2a: wifi_init_completed(/* no traced args */) */
    wifi_init_completed(/* no traced args */);
    /* site +0x59: wifi_log(ret@2a, *((*(g_wifi_nvs+0)+327680)+200), 1, lit:.rodata_wlog_error.24) */
    wifi_log(ret@2a, *((*(g_wifi_nvs+0)+327680)+200), 1, lit:.rodata_wlog_error.24);
    /* site +0x6e: indirect call via a8 (base *(g_osi_funcs_p+0x178)); args: 24, *((*(g_wifi_nvs+0)+327680)+200), 1, lit:.rodata_wlog_error.24 */
    opaque_indirect_a8();
    /* site +0xb3: ieee80211_ioctl(ret@6e, *((*(g_wifi_nvs+0)+327680)+200), 1, lit:.rodata_wlog_error.24) */
    ieee80211_ioctl(ret@6e, *((*(g_wifi_nvs+0)+327680)+200), 1, lit:.rodata_wlog_error.24);
    return last_call_result; /* opaque */
}

/* esp_wifi_set_protocols @ ieee80211_api.o 0x00000038 size 242B bind GLOBAL
 * Calls: wifi_init_completed, wifi_log, wifi_log, wifi_log, indirect(a8), ieee80211_ioctl | Data refs: .rodata_wlog_error.25, .rodata_wlog_error.26, g_wifi_nvs, .rodata_wlog_error.30, .rodata_wlog_error.31, g_osi_funcs_p, wifi_set_protocol_process
 * Fidelity: medium - branchy but loop-free, call sequence mapped (verified: section R_XTENSA_ASM_EXPAND + funcdb v3 agree; predicates opaque) */
u32 esp_wifi_set_protocols(u32 a2, u32 a3)
{
    /* frame: entry a1,32; 86 insns, 13 cond-branches, 0 loops, 5 jumps */
    /* immediates: 0x102, 1, 3, 0x106, 48, -128, 2, 24, 0x101, 12 */
    /* first predicate: beqz a10, 126 <esp_wifi_set_protocols+0xee> (condition opaque) */
    /* mem ld16: base=(?) off=2 */
    /* mem ld16: base=(?) off=0 */
    /* mem ld32: base=(lit:g_wifi_nvs) off=0 */
    /* mem ld32: base=((*(g_wifi_nvs+0)+327680)) off=200 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=0x178 */
    /* mem st8: base=(ret@f6) off=0 */
    /* mem st8: base=(ret@f6) off=8 */
    /* mem st32: base=(ret@f6) off=4 */
    /* mem st8: base=(ret@f6) off=9 */
    /* ... +2 more memops */
    /* site +0x3e: wifi_init_completed(/* no traced args */) */
    wifi_init_completed(/* no traced args */);
    /* site +0x69: wifi_log(ret@3e, 3, 1, lit:.rodata_wlog_error.25) */
    wifi_log(ret@3e, 3, 1, lit:.rodata_wlog_error.25);
    /* site +0xa5: wifi_log(1, 3, 1, lit:.rodata_wlog_error.30, *(?+0)) */
    wifi_log(1, 3, 1, lit:.rodata_wlog_error.30, *(?+0));
    /* site +0xc1: wifi_log(ret@a5, 3, 1, lit:.rodata_wlog_error.31, *(?+0)) */
    wifi_log(ret@a5, 3, 1, lit:.rodata_wlog_error.31, *(?+0));
    /* site +0xf6: indirect call via a8 (base *(g_osi_funcs_p+0x178)); args: 24, 3, 1, lit:.rodata_wlog_error.31, *(?+0) */
    opaque_indirect_a8();
    /* site +0x121: ieee80211_ioctl(ret@f6, 3, 1, lit:.rodata_wlog_error.31, *(?+0)) */
    ieee80211_ioctl(ret@f6, 3, 1, lit:.rodata_wlog_error.31, *(?+0));
    return last_call_result; /* opaque */
}

/* esp_wifi_get_protocols @ ieee80211_api.o 0x0000001c size 126B bind GLOBAL
 * Calls: wifi_init_completed, indirect(a8), ieee80211_ioctl | Data refs: g_osi_funcs_p, wifi_get_protocols_process, g_wifi_nvs
 * Fidelity: medium - branchy but loop-free, call sequence mapped */
u32 esp_wifi_get_protocols(u32 a2, u32 a3)
{
    /* frame: entry a1,32; 46 insns, 6 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0x102, 24, 0x101, 116, 0, 2 */
    /* first predicate: beqz a10, 96 <esp_wifi_get_protocols+0x7a> (condition opaque) */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=0x178 */
    /* mem st8: base=(ret@42) off=0 */
    /* mem st8: base=(ret@42) off=8 */
    /* mem st32: base=(ret@42) off=4 */
    /* mem st8: base=(ret@42) off=9 */
    /* mem st8: base=(ret@42) off=10 */
    /* mem ld32: base=(lit:g_wifi_nvs) off=0 */
    /* mem ld32: base=((*(g_wifi_nvs+0)+327680)) off=200 */
    /* mem st32: base=(ret@42) off=12 */
    /* ... +1 more memops */
    /* site +0x22: wifi_init_completed(/* no traced args */) */
    wifi_init_completed(/* no traced args */);
    /* site +0x42: indirect call via a8 (base *(g_osi_funcs_p+0x178)); args: 24 */
    opaque_indirect_a8();
    /* site +0x91: ieee80211_ioctl(ret@42) */
    ieee80211_ioctl(ret@42);
    return last_call_result; /* opaque */
}

/* esp_wifi_config_11b_rate @ ieee80211_api.o 0x00000040 size 200B bind GLOBAL
 * Calls: wifi_init_completed, wifi_log, wifi_log, wifi_log, wifi_log, wifi_log, ic_set_bar_rate, ic_trc_update_def_rate | Data refs: g_ic, .rodata_wlog_warning.32, .rodata_wlog_warning.33, .rodata_wlog_info.34, .rodata_wlog_info.35, .rodata_wlog_info.36, .rodata_wlog_info.37
 * Fidelity: medium - branchy but loop-free, call sequence mapped (verified: section R_XTENSA_ASM_EXPAND + funcdb v3 agree; predicates opaque) */
u32 esp_wifi_config_11b_rate(u32 a2, u32 a3, u32 a4)
{
    /* frame: entry a1,32; 75 insns, 6 cond-branches, 0 loops, 4 jumps */
    /* immediates: 2, 3, 1, -1, 16, 32, 239, 223, 0 */
    /* first predicate: beqz a10, 104 <esp_wifi_config_11b_rate+0xc4> (condition opaque) */
    /* mem ld8: base=((lit:g_ic+65536)) off=237 */
    /* mem ld8: base=(-1) off=216 */
    /* mem ld8: base=(-1) off=216 */
    /* mem ld8: base=(-1) off=216 */
    /* mem ld8: base=(-1) off=216 */
    /* mem st8: base=(-1) off=216 */
    /* site +0x46: wifi_init_completed(/* no traced args */) */
    wifi_init_completed(/* no traced args */);
    /* site +0x71: wifi_log(1, 3, 2, lit:.rodata_wlog_warning.33) */
    wifi_log(1, 3, 2, lit:.rodata_wlog_warning.33);
    /* site +0x89: wifi_log(1, 3, 3, lit:.rodata_wlog_info.34) */
    wifi_log(1, 3, 3, lit:.rodata_wlog_info.34);
    /* site +0xa1: wifi_log(1, 3, 3, lit:.rodata_wlog_info.35) */
    wifi_log(1, 3, 3, lit:.rodata_wlog_info.35);
    /* site +0xc1: wifi_log(1, 3, 3, lit:.rodata_wlog_info.36) */
    wifi_log(1, 3, 3, lit:.rodata_wlog_info.36);
    /* site +0xd9: wifi_log(1, 3, 3, lit:.rodata_wlog_info.37) */
    wifi_log(1, 3, 3, lit:.rodata_wlog_info.37);
    /* site +0xf3: ic_set_bar_rate(?, 3, 3, lit:.rodata_wlog_info.37) */
    ic_set_bar_rate(?, 3, 3, lit:.rodata_wlog_info.37);
    /* site +0xff: ic_trc_update_def_rate(1, ?, ?, lit:.rodata_wlog_info.37) */
    ic_trc_update_def_rate(1, ?, ?, lit:.rodata_wlog_info.37);
    return 0;
}

/* esp_wifi_config_80211_tx_rate @ ieee80211_api.o 0x00000020 size 100B bind GLOBAL
 * Calls: wifi_init_completed, wifi_log, ic_set_80211_tx_rate | Data refs: .rodata_wlog_warning.38, .rodata_wlog_warning.39, g_wifi_nvs, .rodata_wlog_warning.40
 * Fidelity: medium - branchy but loop-free, call sequence mapped */
u32 esp_wifi_config_80211_tx_rate(u32 a2, u32 a3)
{
    /* frame: entry a1,32; 36 insns, 6 cond-branches, 0 loops, 2 jumps */
    /* immediates: 42, 2, 3, 1, -1, 0 */
    /* first predicate: beqz a10, 80 <esp_wifi_config_80211_tx_rate+0x60> (condition opaque) */
    /* mem ld32: base=(lit:g_wifi_nvs) off=0 */
    /* mem ld8: base=((*(g_wifi_nvs+0)+262144)) off=161 */
    /* mem ld8: base=((*(g_wifi_nvs+161)+327680)) off=61 */
    /* site +0x26: wifi_init_completed(/* no traced args */) */
    wifi_init_completed(/* no traced args */);
    /* site +0x46: wifi_log(1, 3, 2, lit:.rodata_wlog_warning.39) */
    wifi_log(1, 3, 2, lit:.rodata_wlog_warning.39);
    /* site +0x7b: ic_set_80211_tx_rate(?, ?, 2, lit:.rodata_wlog_warning.40) */
    ic_set_80211_tx_rate(?, ?, 2, lit:.rodata_wlog_warning.40);
    return 0;
}

/* esp_wifi_config_80211_tx @ ieee80211_api.o 0x00000060 size 456B bind GLOBAL
 * Calls: wifi_init_completed, wifi_log, chm_get_current_band, wifi_log, ic_set_80211_tx_rate_config | Data refs: .rodata_wlog_warning.41, .rodata_wlog_warning.42, .rodata_wlog_warning.43, g_ic, .rodata_wlog_warning.44, g_wifi_nvs, .rodata_wlog_warning.45, .rodata_wlog_warning.46, .rodata_wlog_warning.47, .rodata_wlog_warning.48, .rodata_wlog_warning.49, .rodata_wlog_warning.50, .rodata_wlog_warning.51, g_chm, .rodata_wlog_warning.52, .rodata_wlog_warning.53, .rodata_wlog_warning.54
 * Fidelity: low - 166 insns, 42 branches, 0 loops; skeleton only */
u32 esp_wifi_config_80211_tx(u32 a2, u32 a3)
{
    /* frame: entry a1,32; 166 insns, 42 cond-branches, 0 loops, 20 jumps */
    /* immediates: -1, 42, 2, 3, 1, -5, 15, 0, 26, -9 */
    /* first predicate: beqz a10, 224 <esp_wifi_config_80211_tx+0x1c4> (condition opaque) */
    /* mem ld32: base=(?) off=4 */
    /* mem ld32: base=(?) off=0 */
    /* mem ld32: base=(lit:g_ic) off=16 */
    /* mem ld32: base=(lit:g_ic) off=20 */
    /* mem ld32: base=(?) off=0 */
    /* mem ld8: base=((*(g_ic+16)+65536)) off=104 */
    /* mem ld32: base=(?) off=4 */
    /* mem ld32: base=(lit:g_wifi_nvs) off=0 */
    /* mem ld8: base=(*(g_wifi_nvs+0)) off=1 */
    /* mem ld32: base=(?) off=4 */
    /* ... +16 more memops */
    /* site +0x66: wifi_init_completed(/* no traced args */) */
    wifi_init_completed(/* no traced args */);
    /* site +0x8d: wifi_log(1, 3, 2, lit:.rodata_wlog_warning.42) */
    wifi_log(1, 3, 2, lit:.rodata_wlog_warning.42);
    /* site +0xb1: chm_get_current_band(ret@8d, 3, 2, lit:.rodata_wlog_warning.43) */
    chm_get_current_band(ret@8d, 3, 2, lit:.rodata_wlog_warning.43);
    /* site +0x205: wifi_log(1, 3, 2, lit:.rodata_wlog_warning.54) */
    wifi_log(1, 3, 2, lit:.rodata_wlog_warning.54);
    /* site +0x215: ic_set_80211_tx_rate_config(?, ?, 2, lit:.rodata_wlog_warning.54) */
    ic_set_80211_tx_rate_config(?, ?, 2, lit:.rodata_wlog_warning.54);
    return 0;
}

/* esp_wifi_set_bandwidth @ ieee80211_api.o 0x00000024 size 140B bind GLOBAL
 * Calls: wifi_init_completed, wifi_log, indirect(a8), ieee80211_ioctl | Data refs: g_wifi_nvs, .rodata_wlog_error.55, g_osi_funcs_p, wifi_set_bw_process
 * Fidelity: medium - branchy but loop-free, call sequence mapped */
u32 esp_wifi_set_bandwidth(u32 a2, u32 a3, u32 a4)
{
    /* frame: entry a1,32; 51 insns, 4 cond-branches, 0 loops, 1 jumps */
    /* immediates: 1, 0x106, 24, 0x101, 14, 0 */
    /* first predicate: beqz a10, ac <esp_wifi_set_bandwidth+0x88> (condition opaque) */
    /* mem ld32: base=(lit:g_wifi_nvs) off=0 */
    /* mem ld32: base=((*(g_wifi_nvs+0)+327680)) off=200 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=0x178 */
    /* mem st8: base=(ret@66) off=0 */
    /* mem st32: base=(ret@66) off=4 */
    /* mem ld32: base=(lit:g_wifi_nvs) off=0 */
    /* mem st8: base=(ret@66) off=8 */
    /* mem ld32: base=((*(g_wifi_nvs+0)+327680)) off=200 */
    /* mem st8: base=(ret@66) off=9 */
    /* ... +1 more memops */
    /* site +0x2a: wifi_init_completed(/* no traced args */) */
    wifi_init_completed(/* no traced args */);
    /* site +0x51: wifi_log(1, *((*(g_wifi_nvs+0)+327680)+200), 1, lit:.rodata_wlog_error.55) */
    wifi_log(1, *((*(g_wifi_nvs+0)+327680)+200), 1, lit:.rodata_wlog_error.55);
    /* site +0x66: indirect call via a8 (base *(g_osi_funcs_p+0x178)); args: 24, *((*(g_wifi_nvs+0)+327680)+200), 1, lit:.rodata_wlog_error.55 */
    opaque_indirect_a8();
    /* site +0xa7: ieee80211_ioctl(ret@66, *((*(g_wifi_nvs+0)+327680)+200), 1, lit:.rodata_wlog_error.55) */
    ieee80211_ioctl(ret@66, *((*(g_wifi_nvs+0)+327680)+200), 1, lit:.rodata_wlog_error.55);
    return last_call_result; /* opaque */
}

/* esp_wifi_get_bandwidth @ ieee80211_api.o 0x00000024 size 152B bind GLOBAL
 * Calls: wifi_init_completed, wifi_log, indirect(a8), ieee80211_ioctl | Data refs: g_wifi_nvs, .rodata_wlog_error.56, g_osi_funcs_p, wifi_get_bw_process
 * Fidelity: medium - branchy but loop-free, call sequence mapped */
u32 esp_wifi_get_bandwidth(u32 a2, u32 a3, u32 a4)
{
    /* frame: entry a1,32; 55 insns, 5 cond-branches, 0 loops, 1 jumps */
    /* immediates: 0x102, 1, 0x106, 24, 0x101, 15, 0 */
    /* first predicate: beqz a10, b8 <esp_wifi_get_bandwidth+0x94> (condition opaque) */
    /* mem ld32: base=(lit:g_wifi_nvs) off=0 */
    /* mem ld32: base=((*(g_wifi_nvs+0)+327680)) off=200 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=0x178 */
    /* mem st8: base=(ret@6e) off=0 */
    /* mem st32: base=(ret@6e) off=4 */
    /* mem ld32: base=(lit:g_wifi_nvs) off=0 */
    /* mem st8: base=(ret@6e) off=8 */
    /* mem st8: base=(ret@6e) off=9 */
    /* mem st8: base=(ret@6e) off=10 */
    /* ... +3 more memops */
    /* site +0x2a: wifi_init_completed(/* no traced args */) */
    wifi_init_completed(/* no traced args */);
    /* site +0x59: wifi_log(ret@2a, *((*(g_wifi_nvs+0)+327680)+200), 1, lit:.rodata_wlog_error.56) */
    wifi_log(ret@2a, *((*(g_wifi_nvs+0)+327680)+200), 1, lit:.rodata_wlog_error.56);
    /* site +0x6e: indirect call via a8 (base *(g_osi_funcs_p+0x178)); args: 24, *((*(g_wifi_nvs+0)+327680)+200), 1, lit:.rodata_wlog_error.56 */
    opaque_indirect_a8();
    /* site +0xb3: ieee80211_ioctl(ret@6e, *((*(g_wifi_nvs+0)+327680)+200), 1, lit:.rodata_wlog_error.56) */
    ieee80211_ioctl(ret@6e, *((*(g_wifi_nvs+0)+327680)+200), 1, lit:.rodata_wlog_error.56);
    return last_call_result; /* opaque */
}

/* esp_wifi_set_bandwidths @ ieee80211_api.o 0x00000024 size 145B bind GLOBAL
 * Calls: wifi_init_completed, wifi_log, indirect(a8), ieee80211_ioctl | Data refs: .rodata_wlog_error.57, g_osi_funcs_p, wifi_set_bw_process, g_wifi_nvs
 * Fidelity: medium - branchy but loop-free, call sequence mapped */
u32 esp_wifi_set_bandwidths(u32 a2, u32 a3)
{
    /* frame: entry a1,32; 51 insns, 7 cond-branches, 0 loops, 1 jumps */
    /* immediates: 0x102, 1, 3, 0x106, 24, 0x101, 14, 0 */
    /* first predicate: beqz a10, b1 <esp_wifi_set_bandwidths+0x8d> (condition opaque) */
    /* mem ld32: base=(?) off=4 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=0x178 */
    /* mem st8: base=(ret@66) off=0 */
    /* mem st8: base=(ret@66) off=8 */
    /* mem st32: base=(ret@66) off=4 */
    /* mem ld32: base=(lit:g_wifi_nvs) off=0 */
    /* mem ld32: base=((*(g_wifi_nvs+0)+327680)) off=200 */
    /* mem ld8: base=(?) off=0 */
    /* mem st8: base=(ret@66) off=9 */
    /* ... +2 more memops */
    /* site +0x2a: wifi_init_completed(/* no traced args */) */
    wifi_init_completed(/* no traced args */);
    /* site +0x51: wifi_log(ret@2a, 3, 1, lit:.rodata_wlog_error.57) */
    wifi_log(ret@2a, 3, 1, lit:.rodata_wlog_error.57);
    /* site +0x66: indirect call via a8 (base *(g_osi_funcs_p+0x178)); args: 24, 3, 1, lit:.rodata_wlog_error.57 */
    opaque_indirect_a8();
    /* site +0xac: ieee80211_ioctl(ret@66, 3, 1, lit:.rodata_wlog_error.57) */
    ieee80211_ioctl(ret@66, 3, 1, lit:.rodata_wlog_error.57);
    return last_call_result; /* opaque */
}

/* esp_wifi_get_bandwidths @ ieee80211_api.o 0x0000001c size 122B bind GLOBAL
 * Calls: wifi_init_completed, indirect(a8), ieee80211_ioctl | Data refs: g_osi_funcs_p, wifi_get_bw_process, g_wifi_nvs
 * Fidelity: medium - branchy but loop-free, call sequence mapped */
u32 esp_wifi_get_bandwidths(u32 a2, u32 a3)
{
    /* frame: entry a1,32; 46 insns, 6 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0x102, 24, 0x101, 15, 0, 2 */
    /* first predicate: beqz a10, 92 <esp_wifi_get_bandwidths+0x76> (condition opaque) */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=0x178 */
    /* mem st8: base=(ret@41) off=0 */
    /* mem st8: base=(ret@41) off=8 */
    /* mem st32: base=(ret@41) off=4 */
    /* mem st8: base=(ret@41) off=9 */
    /* mem st8: base=(ret@41) off=10 */
    /* mem ld32: base=(lit:g_wifi_nvs) off=0 */
    /* mem ld32: base=((*(g_wifi_nvs+0)+327680)) off=200 */
    /* mem st32: base=(ret@41) off=12 */
    /* ... +1 more memops */
    /* site +0x22: wifi_init_completed(/* no traced args */) */
    wifi_init_completed(/* no traced args */);
    /* site +0x41: indirect call via a8 (base *(g_osi_funcs_p+0x178)); args: 24 */
    opaque_indirect_a8();
    /* site +0x8d: ieee80211_ioctl(ret@41) */
    ieee80211_ioctl(ret@41);
    return last_call_result; /* opaque */
}

/* esp_wifi_set_channel @ ieee80211_api.o 0x0000001c size 90B bind GLOBAL
 * Calls: wifi_init_completed, indirect(a2), ieee80211_ioctl | Data refs: g_ic, g_osi_funcs_p, wifi_set_channel_process
 * Fidelity: medium - branchy but loop-free, call sequence mapped */
u32 esp_wifi_set_channel(u32 a2, u32 a3)
{
    /* frame: entry a1,32; 32 insns, 4 cond-branches, 0 loops, 0 jumps */
    /* immediates: 24, 0x101, 16 */
    /* first predicate: beqz a10, 74 <esp_wifi_set_channel+0x58> (condition opaque) */
    /* mem ld8: base=((lit:g_ic+65536)) off=237 */
    /* mem ld8: base=((lit:g_ic+65536)) off=239 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=0x178 */
    /* mem st32: base=(ret@4d) off=4 */
    /* mem st8: base=(ret@4d) off=0 */
    /* mem st8: base=(ret@4d) off=8 */
    /* mem st8: base=(ret@4d) off=9 */
    /* site +0x22: wifi_init_completed(/* no traced args */) */
    wifi_init_completed(/* no traced args */);
    /* site +0x4d: indirect call via a2 (base *(g_osi_funcs_p+0x178)); args: 24 */
    opaque_indirect_a2();
    /* site +0x6f: ieee80211_ioctl(ret@4d) */
    ieee80211_ioctl(ret@4d);
    return last_call_result; /* opaque */
}

/* esp_wifi_set_home_channel @ ieee80211_api.o 0x0000001c size 90B bind GLOBAL
 * Calls: wifi_init_completed, indirect(a2), ieee80211_ioctl | Data refs: g_ic, g_osi_funcs_p, wifi_set_home_channel_process
 * Fidelity: medium - branchy but loop-free, call sequence mapped */
u32 esp_wifi_set_home_channel(u32 a2, u32 a3)
{
    /* frame: entry a1,32; 32 insns, 4 cond-branches, 0 loops, 0 jumps */
    /* immediates: 24, 0x101, 17 */
    /* first predicate: beqz a10, 74 <esp_wifi_set_home_channel+0x58> (condition opaque) */
    /* mem ld8: base=((lit:g_ic+65536)) off=237 */
    /* mem ld8: base=((lit:g_ic+65536)) off=239 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=0x178 */
    /* mem st32: base=(ret@4d) off=4 */
    /* mem st8: base=(ret@4d) off=0 */
    /* mem st8: base=(ret@4d) off=8 */
    /* mem st8: base=(ret@4d) off=9 */
    /* site +0x22: wifi_init_completed(/* no traced args */) */
    wifi_init_completed(/* no traced args */);
    /* site +0x4d: indirect call via a2 (base *(g_osi_funcs_p+0x178)); args: 24 */
    opaque_indirect_a2();
    /* site +0x6f: ieee80211_ioctl(ret@4d) */
    ieee80211_ioctl(ret@4d);
    return last_call_result; /* opaque */
}

/* esp_wifi_get_channel @ ieee80211_api.o 0x00000014 size 100B bind GLOBAL
 * Calls: wifi_init_completed, indirect(a8), ieee80211_ioctl | Data refs: g_osi_funcs_p, wifi_get_channel_process
 * Fidelity: medium - branchy but loop-free, call sequence mapped */
u32 esp_wifi_get_channel(u32 a2, u32 a3)
{
    /* frame: entry a1,32; 37 insns, 4 cond-branches, 0 loops, 1 jumps */
    /* immediates: 1, 0, 24, 0x101, 18, 0x102 */
    /* first predicate: beqz a10, 74 <esp_wifi_get_channel+0x60> (condition opaque) */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=0x178 */
    /* mem st8: base=(ret@41) off=0 */
    /* mem st16: base=(ret@41) off=8 */
    /* mem st32: base=(ret@41) off=4 */
    /* mem st8: base=(ret@41) off=10 */
    /* mem st32: base=(ret@41) off=12 */
    /* mem st32: base=(ret@41) off=20 */
    /* site +0x1a: wifi_init_completed(/* no traced args */) */
    wifi_init_completed(/* no traced args */);
    /* site +0x41: indirect call via a8 (base *(g_osi_funcs_p+0x178)); args: 24 */
    opaque_indirect_a8();
    /* site +0x69: ieee80211_ioctl(ret@41) */
    ieee80211_ioctl(ret@41);
    return 0x102;
}

/* esp_wifi_get_home_channel @ ieee80211_api.o 0x0000001c size 116B bind GLOBAL
 * Calls: wifi_init_completed, indirect(a8), ieee80211_ioctl | Data refs: g_ic, g_osi_funcs_p, wifi_get_home_channel_process
 * Fidelity: medium - branchy but loop-free, call sequence mapped */
u32 esp_wifi_get_home_channel(u32 a2, u32 a3, u32 a4)
{
    /* frame: entry a1,32; 42 insns, 5 cond-branches, 0 loops, 1 jumps */
    /* immediates: 1, 0, 24, 0x101, 118, 0x102 */
    /* first predicate: beqz a10, 8c <esp_wifi_get_home_channel+0x70> (condition opaque) */
    /* mem ld8: base=((lit:g_ic+65536)) off=237 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=0x178 */
    /* mem st8: base=(ret@56) off=0 */
    /* mem st16: base=(ret@56) off=8 */
    /* mem st32: base=(ret@56) off=4 */
    /* mem st8: base=(ret@56) off=10 */
    /* mem st32: base=(ret@56) off=12 */
    /* mem st32: base=(ret@56) off=20 */
    /* site +0x22: wifi_init_completed(/* no traced args */) */
    wifi_init_completed(/* no traced args */);
    /* site +0x56: indirect call via a8 (base *(g_osi_funcs_p+0x178)); args: 24 */
    opaque_indirect_a8();
    /* site +0x7f: ieee80211_ioctl(ret@56) */
    ieee80211_ioctl(ret@56);
    return 0x102;
}

/* esp_wifi_set_country @ ieee80211_api.o 0x00000014 size 78B bind GLOBAL
 * Calls: wifi_init_completed, indirect(a8), ieee80211_ioctl | Data refs: g_osi_funcs_p, wifi_set_country
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 esp_wifi_set_country(u32 a2)
{
    /* frame: entry a1,32; 30 insns, 2 cond-branches, 0 loops, 0 jumps */
    /* immediates: 24, 0x101, 20, 0 */
    /* first predicate: beqz.n a10, 5e <esp_wifi_set_country+0x4a> (condition opaque) */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=0x178 */
    /* mem st8: base=(ret@2d) off=0 */
    /* mem st32: base=(ret@2d) off=4 */
    /* mem st16: base=(ret@2d) off=8 */
    /* mem st8: base=(ret@2d) off=10 */
    /* mem st32: base=(ret@2d) off=20 */
    /* mem st32: base=(ret@2d) off=12 */
    /* site +0x1a: wifi_init_completed(/* no traced args */) */
    wifi_init_completed(/* no traced args */);
    /* site +0x2d: indirect call via a8 (base *(g_osi_funcs_p+0x178)); args: 24 */
    opaque_indirect_a8();
    /* site +0x59: ieee80211_ioctl(ret@2d) */
    ieee80211_ioctl(ret@2d);
    return last_call_result; /* opaque */
}

/* esp_wifi_set_country_code @ ieee80211_api.o 0x0000001c size 166B bind GLOBAL
 * Calls: memset, wifi_init_completed, ieee80211_regdomain_get_country_info, indirect(a2), ieee80211_ioctl | Data refs: g_osi_funcs_p, wifi_set_country
 * Fidelity: medium - branchy but loop-free, call sequence mapped (verified: section R_XTENSA_ASM_EXPAND + funcdb v3 agree; predicates opaque) */
u32 esp_wifi_set_country_code(u32 a2, u32 a3)
{
    /* frame: entry a1,48; 61 insns, 2 cond-branches, 0 loops, 0 jumps */
    /* immediates: 12, 0, 0x102, 24, 1, 0x101, 20 */
    /* first predicate: beqz a10, be <esp_wifi_set_country_code+0xa2> (condition opaque) */
    /* mem ld8: base=(?) off=1 */
    /* mem ld8: base=(?) off=0 */
    /* mem ld8: base=(?) off=2 */
    /* mem st8: base=(?) off=1 */
    /* mem ld8: base=(?) off=12 */
    /* mem st8: base=(?) off=2 */
    /* mem ld8: base=(?) off=3 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=0x178 */
    /* mem st8: base=(?) off=4 */
    /* ... +8 more memops */
    /* site +0x2a: memset(?, 0, 12) */
    memset(?, 0, 12);
    /* site +0x30: wifi_init_completed(ret@2a, 0, 12) */
    wifi_init_completed(ret@2a, 0, 12);
    /* site +0x45: ieee80211_regdomain_get_country_info(?, ?, (?+12)) */
    ieee80211_regdomain_get_country_info(?, ?, (?+12));
    /* site +0x8d: indirect call via a2 (base *(g_osi_funcs_p+0x178)); args: 24, ?, (?+12) */
    opaque_indirect_a2();
    /* site +0xb9: ieee80211_ioctl(ret@8d, ?, (?+12)) */
    ieee80211_ioctl(ret@8d, ?, (?+12));
    return last_call_result; /* opaque */
}

/* esp_wifi_get_country @ ieee80211_api.o 0x00000014 size 82B bind GLOBAL
 * Calls: wifi_init_completed, indirect(a8), ieee80211_ioctl | Data refs: g_osi_funcs_p, wifi_get_country
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 esp_wifi_get_country(u32 a2)
{
    /* frame: entry a1,32; 32 insns, 3 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0x102, 24, 0x101, 21, 0 */
    /* first predicate: beqz.n a10, 62 <esp_wifi_get_country+0x4e> (condition opaque) */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=0x178 */
    /* mem st8: base=(ret@31) off=0 */
    /* mem st32: base=(ret@31) off=12 */
    /* mem st32: base=(ret@31) off=4 */
    /* mem st16: base=(ret@31) off=8 */
    /* mem st8: base=(ret@31) off=10 */
    /* mem st32: base=(ret@31) off=20 */
    /* site +0x1a: wifi_init_completed(/* no traced args */) */
    wifi_init_completed(/* no traced args */);
    /* site +0x31: indirect call via a8 (base *(g_osi_funcs_p+0x178)); args: 24 */
    opaque_indirect_a8();
    /* site +0x5d: ieee80211_ioctl(ret@31) */
    ieee80211_ioctl(ret@31);
    return last_call_result; /* opaque */
}

/* esp_wifi_get_country_code @ ieee80211_api.o 0x00000014 size 119B bind GLOBAL
 * Calls: wifi_init_completed, indirect(a8), ieee80211_ioctl | Data refs: g_osi_funcs_p, wifi_get_country
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 esp_wifi_get_country_code(u32 a2)
{
    /* frame: entry a1,48; 42 insns, 3 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0x102, 24, 0x101, 21, 0 */
    /* first predicate: beqz a10, 84 <esp_wifi_get_country_code+0x70> (condition opaque) */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=0x178 */
    /* mem st8: base=(ret@35) off=0 */
    /* mem st32: base=(ret@35) off=4 */
    /* mem st16: base=(ret@35) off=8 */
    /* mem st8: base=(ret@35) off=10 */
    /* mem st32: base=(ret@35) off=20 */
    /* mem st32: base=(ret@35) off=12 */
    /* mem ld8: base=(?) off=0 */
    /* mem st8: base=(?) off=0 */
    /* ... +4 more memops */
    /* site +0x1a: wifi_init_completed(/* no traced args */) */
    wifi_init_completed(/* no traced args */);
    /* site +0x35: indirect call via a8 (base *(g_osi_funcs_p+0x178)); args: 24 */
    opaque_indirect_a8();
    /* site +0x63: ieee80211_ioctl(ret@35) */
    ieee80211_ioctl(ret@35);
    return &ieee80211_ioctl();
}

/* esp_wifi_set_mac @ ieee80211_api.o 0x0000001c size 108B bind GLOBAL
 * Calls: wifi_init_completed, indirect(a4), memcpy, ieee80211_ioctl | Data refs: g_osi_funcs_p, wifi_set_mac_process
 * Fidelity: medium - branchy but loop-free, call sequence mapped */
u32 esp_wifi_set_mac(u32 a2, u32 a3, u32 a4)
{
    /* frame: entry a1,32; 41 insns, 4 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0x102, 30, 0x101, 22, 6, 0 */
    /* first predicate: beqz a10, 84 <esp_wifi_set_mac+0x68> (condition opaque) */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=0x178 */
    /* mem st8: base=(ret@41) off=0 */
    /* mem st8: base=(ret@41) off=8 */
    /* mem st32: base=(ret@41) off=4 */
    /* mem st8: base=(ret@41) off=9 */
    /* mem st8: base=(ret@41) off=10 */
    /* mem st32: base=(ret@41) off=12 */
    /* site +0x22: wifi_init_completed(/* no traced args */) */
    wifi_init_completed(/* no traced args */);
    /* site +0x41: indirect call via a4 (base *(g_osi_funcs_p+0x178)); args: 30 */
    opaque_indirect_a4();
    /* site +0x77: memcpy((ret@41+20), ?, 6) */
    memcpy((ret@41+20), ?, 6);
    /* site +0x7f: ieee80211_ioctl(ret@41, ?, 6) */
    ieee80211_ioctl(ret@41, ?, 6);
    return last_call_result; /* opaque */
}

/* esp_wifi_softap_set_obss_overlap @ ieee80211_api.o 0x00000014 size 68B bind GLOBAL
 * Calls: wifi_init_completed, indirect(a2), ieee80211_ioctl | Data refs: g_osi_funcs_p, wifi_softap_set_obss_overlap_process
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 esp_wifi_softap_set_obss_overlap(u32 a2)
{
    /* frame: entry a1,32; 24 insns, 2 cond-branches, 0 loops, 0 jumps */
    /* immediates: 24, 0x101, 114 */
    /* first predicate: beqz.n a10, 56 <esp_wifi_softap_set_obss_overlap+0x42> (condition opaque) */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=0x178 */
    /* mem st32: base=(ret@31) off=4 */
    /* mem st8: base=(ret@31) off=0 */
    /* mem st8: base=(ret@31) off=8 */
    /* site +0x1a: wifi_init_completed(/* no traced args */) */
    wifi_init_completed(/* no traced args */);
    /* site +0x31: indirect call via a2 (base *(g_osi_funcs_p+0x178)); args: 24 */
    opaque_indirect_a2();
    /* site +0x51: ieee80211_ioctl(ret@31) */
    ieee80211_ioctl(ret@31);
    return last_call_result; /* opaque */
}

/* esp_wifi_get_mac @ ieee80211_api.o 0x00000018 size 56B bind GLOBAL
 * Calls: wifi_init_completed, wifi_api_lock, wifi_get_macaddr, wifi_api_unlock | Data refs: none
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 esp_wifi_get_mac(u32 a2, u32 a3)
{
    /* frame: entry a1,32; 20 insns, 3 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0x102, 0 */
    /* first predicate: beqz.n a10, 4c <esp_wifi_get_mac+0x34> (condition opaque) */
    /* site +0x1e: wifi_init_completed(/* no traced args */) */
    wifi_init_completed(/* no traced args */);
    /* site +0x35: wifi_api_lock(ret@1e) */
    wifi_api_lock(ret@1e);
    /* site +0x41: wifi_get_macaddr(ret@35) */
    wifi_get_macaddr(ret@35);
    /* site +0x47: wifi_api_unlock(ret@41) */
    wifi_api_unlock(ret@41);
    return 0;
}

/* esp_wifi_sta_get_ap_info @ ieee80211_api.o 0x00000014 size 82B bind GLOBAL
 * Calls: wifi_init_completed, indirect(a8), ieee80211_ioctl | Data refs: g_osi_funcs_p, wifi_get_ap_info_process
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 esp_wifi_sta_get_ap_info(u32 a2)
{
    /* frame: entry a1,32; 32 insns, 3 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0x102, 24, 0x101, 8, 0 */
    /* first predicate: beqz.n a10, 62 <esp_wifi_sta_get_ap_info+0x4e> (condition opaque) */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=0x178 */
    /* mem st8: base=(ret@31) off=0 */
    /* mem st32: base=(ret@31) off=4 */
    /* mem st16: base=(ret@31) off=8 */
    /* mem st8: base=(ret@31) off=10 */
    /* mem st32: base=(ret@31) off=12 */
    /* mem st32: base=(ret@31) off=20 */
    /* site +0x1a: wifi_init_completed(/* no traced args */) */
    wifi_init_completed(/* no traced args */);
    /* site +0x31: indirect call via a8 (base *(g_osi_funcs_p+0x178)); args: 24 */
    opaque_indirect_a8();
    /* site +0x5d: ieee80211_ioctl(ret@31) */
    ieee80211_ioctl(ret@31);
    return last_call_result; /* opaque */
}

/* esp_wifi_set_promiscuous_filter @ ieee80211_api.o 0x00000014 size 74B bind GLOBAL
 * Calls: wifi_init_completed, indirect(a2), ieee80211_ioctl | Data refs: g_osi_funcs_p, wifi_set_promis_filter_process
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 esp_wifi_set_promiscuous_filter(u32 a2)
{
    /* frame: entry a1,32; 28 insns, 3 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0x102, 24, 0, 31 */
    /* first predicate: beqz.n a10, 5c <esp_wifi_set_promiscuous_filter+0x48> (condition opaque) */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=0x178 */
    /* mem st8: base=(ret@33) off=0 */
    /* mem st16: base=(ret@33) off=8 */
    /* mem st32: base=(ret@33) off=4 */
    /* mem st8: base=(ret@33) off=10 */
    /* mem st32: base=(ret@33) off=12 */
    /* site +0x1a: wifi_init_completed(/* no traced args */) */
    wifi_init_completed(/* no traced args */);
    /* site +0x33: indirect call via a2 (base *(g_osi_funcs_p+0x178)); args: 24 */
    opaque_indirect_a2();
    /* site +0x59: ieee80211_ioctl(ret@33) */
    ieee80211_ioctl(ret@33);
    return opaque_result; /* full dataflow not recovered */
}

/* esp_wifi_get_promiscuous_filter @ ieee80211_api.o 0x0000000c size 34B bind GLOBAL
 * Calls: wifi_init_completed, ic_get_promis_filter | Data refs: none
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 esp_wifi_get_promiscuous_filter(u32 a2)
{
    /* frame: entry a1,32; 13 insns, 2 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0x102, 0 */
    /* first predicate: beqz.n a10, 2a <esp_wifi_get_promiscuous_filter+0x1e> (condition opaque) */
    /* site +0x12: wifi_init_completed(/* no traced args */) */
    wifi_init_completed(/* no traced args */);
    /* site +0x25: ic_get_promis_filter(/* no traced args */) */
    ic_get_promis_filter(/* no traced args */);
    return 0;
}

/* esp_wifi_set_promiscuous_ctrl_filter @ ieee80211_api.o 0x00000014 size 74B bind GLOBAL
 * Calls: wifi_init_completed, indirect(a2), ieee80211_ioctl | Data refs: g_osi_funcs_p, wifi_set_promis_ctrl_filter_process
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 esp_wifi_set_promiscuous_ctrl_filter(u32 a2)
{
    /* frame: entry a1,32; 28 insns, 3 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0x102, 24, 0 */
    /* first predicate: beqz.n a10, 5c <esp_wifi_set_promiscuous_ctrl_filter+0x48> (condition opaque) */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=0x178 */
    /* mem st8: base=(ret@33) off=0 */
    /* mem st16: base=(ret@33) off=8 */
    /* mem st32: base=(ret@33) off=4 */
    /* mem st8: base=(ret@33) off=10 */
    /* mem st32: base=(ret@33) off=12 */
    /* site +0x1a: wifi_init_completed(/* no traced args */) */
    wifi_init_completed(/* no traced args */);
    /* site +0x33: indirect call via a2 (base *(g_osi_funcs_p+0x178)); args: 24 */
    opaque_indirect_a2();
    /* site +0x59: ieee80211_ioctl(ret@33) */
    ieee80211_ioctl(ret@33);
    return opaque_result; /* full dataflow not recovered */
}

/* esp_wifi_get_promiscuous_ctrl_filter @ ieee80211_api.o 0x0000000c size 34B bind GLOBAL
 * Calls: wifi_init_completed, ic_get_promis_ctrl_filter | Data refs: none
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 esp_wifi_get_promiscuous_ctrl_filter(u32 a2)
{
    /* frame: entry a1,32; 13 insns, 2 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0x102, 0 */
    /* first predicate: beqz.n a10, 2a <esp_wifi_get_promiscuous_ctrl_filter+0x1e> (condition opaque) */
    /* site +0x12: wifi_init_completed(/* no traced args */) */
    wifi_init_completed(/* no traced args */);
    /* site +0x25: ic_get_promis_ctrl_filter(/* no traced args */) */
    ic_get_promis_ctrl_filter(/* no traced args */);
    return 0;
}

/* esp_wifi_set_promiscuous @ ieee80211_api.o 0x00000018 size 108B bind GLOBAL
 * Calls: wifi_init_completed, indirect(a2), ieee80211_ioctl, indirect(a2), ieee80211_ioctl | Data refs: g_osi_funcs_p, wifi_set_promis_process
 * Fidelity: medium - branchy but loop-free, call sequence mapped */
u32 esp_wifi_set_promiscuous(u32 a2)
{
    /* frame: entry a1,32; 39 insns, 4 cond-branches, 0 loops, 2 jumps */
    /* immediates: 24, 23, 1, 0 */
    /* first predicate: beqz a10, 82 <esp_wifi_set_promiscuous+0x6a> (condition opaque) */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=0x178 */
    /* mem st32: base=(ret@36) off=4 */
    /* mem st8: base=(ret@36) off=0 */
    /* mem st8: base=(ret@36) off=8 */
    /* mem st32: base=(ret@61) off=4 */
    /* mem st8: base=(ret@61) off=0 */
    /* mem st8: base=(ret@61) off=8 */
    /* site +0x1e: wifi_init_completed(/* no traced args */) */
    wifi_init_completed(/* no traced args */);
    /* site +0x36: indirect call via a2 (base *(g_osi_funcs_p+0x178)); args: 24 */
    opaque_indirect_a2();
    /* site +0x56: ieee80211_ioctl(ret@36) */
    ieee80211_ioctl(ret@36);
    /* site +0x61: indirect call via a2 (base 0); args: ret@56 */
    opaque_indirect_a2();
    /* site +0x7f: ieee80211_ioctl(ret@61) */
    ieee80211_ioctl(ret@61);
    return opaque_result; /* full dataflow not recovered */
}

/* esp_wifi_set_promiscuous_rx_cb @ ieee80211_api.o 0x0000000c size 28B bind GLOBAL
 * Calls: wifi_init_completed, ic_register_promis_rx_cb | Data refs: none
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 esp_wifi_set_promiscuous_rx_cb(u32 a2)
{
    /* frame: entry a1,32; 11 insns, 1 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0 */
    /* first predicate: beqz.n a10, 24 <esp_wifi_set_promiscuous_rx_cb+0x18> (condition opaque) */
    /* site +0x12: wifi_init_completed(/* no traced args */) */
    wifi_init_completed(/* no traced args */);
    /* site +0x1f: ic_register_promis_rx_cb(/* no traced args */) */
    ic_register_promis_rx_cb(/* no traced args */);
    return 0;
}

/* esp_wifi_get_promiscuous @ ieee80211_api.o 0x0000000c size 53B bind GLOBAL
 * Calls: wifi_init_completed | Data refs: g_ic
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 esp_wifi_get_promiscuous(u32 a2)
{
    /* frame: entry a1,32; 20 insns, 2 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0x102, 1, 0 */
    /* first predicate: beqz.n a10, 3c <esp_wifi_get_promiscuous+0x30> (condition opaque) */
    /* mem ld8: base=((lit:g_ic+65536)) off=239 */
    /* mem st8: base=(?) off=0 */
    /* site +0x12: wifi_init_completed(/* no traced args */) */
    wifi_init_completed(/* no traced args */);
    return opaque_result; /* full dataflow not recovered */
}

/* esp_wifi_set_storage @ ieee80211_api.o 0x00000014 size 68B bind GLOBAL
 * Calls: wifi_init_completed, indirect(a8), indirect(a2) | Data refs: g_wifi_global_lock, g_osi_funcs_p, g_ic
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 esp_wifi_set_storage(u32 a2, u32 a3, u32 a4)
{
    /* frame: entry a1,32; 25 insns, 2 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0x102, 0 */
    /* first predicate: beqz.n a10, 54 <esp_wifi_set_storage+0x40> (condition opaque) */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(lit:g_wifi_global_lock) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=84 */
    /* mem st8: base=((lit:g_ic+131072)) off=31 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(lit:g_wifi_global_lock) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=88 */
    /* site +0x1a: wifi_init_completed(/* no traced args */) */
    wifi_init_completed(/* no traced args */);
    /* site +0x36: indirect call via a8 (base *(*(g_osi_funcs_p+0)+84)); args: *(g_wifi_global_lock+0) */
    opaque_indirect_a8();
    /* site +0x4f: indirect call via a2 (base *(*(g_osi_funcs_p+0)+88)); args: *(g_wifi_global_lock+0) */
    opaque_indirect_a2();
    return 0;
}

/* esp_wifi_internal_reg_rxcb @ ieee80211_api.o 0x00000018 size 82B bind GLOBAL
 * Calls: wifi_init_completed, indirect(a8), ieee80211_ioctl | Data refs: g_osi_funcs_p, wifi_set_rxcb_process
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 esp_wifi_internal_reg_rxcb(u32 a2, u32 a3)
{
    /* frame: entry a1,32; 31 insns, 3 cond-branches, 0 loops, 0 jumps */
    /* immediates: 24, 0x101, 26, 0 */
    /* first predicate: beqz.n a10, 66 <esp_wifi_internal_reg_rxcb+0x4e> (condition opaque) */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=0x178 */
    /* mem st8: base=(ret@36) off=0 */
    /* mem st32: base=(ret@36) off=4 */
    /* mem st8: base=(ret@36) off=9 */
    /* mem st8: base=(ret@36) off=10 */
    /* mem st8: base=(ret@36) off=8 */
    /* mem st32: base=(ret@36) off=12 */
    /* site +0x1e: wifi_init_completed(/* no traced args */) */
    wifi_init_completed(/* no traced args */);
    /* site +0x36: indirect call via a8 (base *(g_osi_funcs_p+0x178)); args: 24 */
    opaque_indirect_a8();
    /* site +0x61: ieee80211_ioctl(ret@36) */
    ieee80211_ioctl(ret@36);
    return last_call_result; /* opaque */
}

/* esp_wifi_internal_set_sta_ip @ ieee80211_api.o 0x00000010 size 49B bind GLOBAL
 * Calls: wifi_init_completed | Data refs: g_ic
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 esp_wifi_internal_set_sta_ip(void)
{
    /* frame: entry a1,32; 17 insns, 2 cond-branches, 0 loops, 0 jumps */
    /* immediates: 1, 0 */
    /* first predicate: beqz.n a10, 3c <esp_wifi_internal_set_sta_ip+0x2c> (condition opaque) */
    /* mem ld8: base=((lit:g_ic+65536)) off=237 */
    /* mem st8: base=((lit:g_ic+131072)) off=37 */
    /* site +0x16: wifi_init_completed(/* no traced args */) */
    wifi_init_completed(/* no traced args */);
    return 0;
}

/* esp_wifi_set_auto_connect @ ieee80211_api.o 0x00000014 size 66B bind GLOBAL
 * Calls: wifi_init_completed, indirect(a2), ieee80211_ioctl | Data refs: g_osi_funcs_p, wifi_set_auto_connect_process
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 esp_wifi_set_auto_connect(u32 a2)
{
    /* frame: entry a1,32; 24 insns, 2 cond-branches, 0 loops, 0 jumps */
    /* immediates: 24, 0x101, 27 */
    /* first predicate: beqz.n a10, 54 <esp_wifi_set_auto_connect+0x40> (condition opaque) */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=0x178 */
    /* mem st32: base=(ret@31) off=4 */
    /* mem st8: base=(ret@31) off=0 */
    /* mem st8: base=(ret@31) off=8 */
    /* site +0x1a: wifi_init_completed(/* no traced args */) */
    wifi_init_completed(/* no traced args */);
    /* site +0x31: indirect call via a2 (base *(g_osi_funcs_p+0x178)); args: 24 */
    opaque_indirect_a2();
    /* site +0x4f: ieee80211_ioctl(ret@31) */
    ieee80211_ioctl(ret@31);
    return last_call_result; /* opaque */
}

/* esp_wifi_get_auto_connect @ ieee80211_api.o 0x0000000c size 49B bind GLOBAL
 * Calls: wifi_init_completed | Data refs: g_wifi_nvs
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 esp_wifi_get_auto_connect(u32 a2)
{
    /* frame: entry a1,32; 19 insns, 2 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0x102, 0, 1 */
    /* first predicate: beqz.n a10, 38 <esp_wifi_get_auto_connect+0x2c> (condition opaque) */
    /* mem ld32: base=(lit:g_wifi_nvs) off=0 */
    /* mem ld8: base=(*(g_wifi_nvs+0)) off=145 */
    /* mem st8: base=(?) off=0 */
    /* site +0x12: wifi_init_completed(/* no traced args */) */
    wifi_init_completed(/* no traced args */);
    return 0;
}

/* esp_wifi_restore @ ieee80211_api.o 0x00000018 size 64B bind GLOBAL
 * Calls: wifi_init_completed, esp_wifi_stop, indirect(a2), ieee80211_ioctl | Data refs: g_osi_funcs_p, wifi_restore_process
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 esp_wifi_restore(u32 a2)
{
    /* frame: entry a1,32; 24 insns, 2 cond-branches, 0 loops, 0 jumps */
    /* immediates: 24, 0x101, 28 */
    /* first predicate: beqz.n a10, 56 <esp_wifi_restore+0x3e> (condition opaque) */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=0x178 */
    /* mem st32: base=(ret@36) off=4 */
    /* mem st8: base=(ret@36) off=0 */
    /* site +0x1e: wifi_init_completed(/* no traced args */) */
    wifi_init_completed(/* no traced args */);
    /* site +0x29: esp_wifi_stop(ret@1e) */
    esp_wifi_stop(ret@1e);
    /* site +0x36: indirect call via a2 (base *(g_osi_funcs_p+0x178)); args: 24 */
    opaque_indirect_a2();
    /* site +0x51: ieee80211_ioctl(ret@36) */
    ieee80211_ioctl(ret@36);
    return last_call_result; /* opaque */
}

/* esp_wifi_set_vendor_ie @ ieee80211_api.o 0x00000014 size 78B bind GLOBAL
 * Calls: wifi_init_completed, indirect(a2), ieee80211_ioctl | Data refs: g_osi_funcs_p, wifi_set_vnd_ie_process
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 esp_wifi_set_vendor_ie(u32 a2, u32 a3, u32 a4, u32 a5)
{
    /* frame: entry a1,32; 28 insns, 2 cond-branches, 0 loops, 0 jumps */
    /* immediates: 24, 0x101, 29 */
    /* first predicate: beqz.n a10, 60 <esp_wifi_set_vendor_ie+0x4c> (condition opaque) */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=0x178 */
    /* mem st8: base=(ret@31) off=0 */
    /* mem st8: base=(ret@31) off=8 */
    /* mem st32: base=(ret@31) off=4 */
    /* mem st8: base=(ret@31) off=9 */
    /* mem st8: base=(ret@31) off=10 */
    /* mem st32: base=(ret@31) off=12 */
    /* site +0x1a: wifi_init_completed(/* no traced args */) */
    wifi_init_completed(/* no traced args */);
    /* site +0x31: indirect call via a2 (base *(g_osi_funcs_p+0x178)); args: 24 */
    opaque_indirect_a2();
    /* site +0x5b: ieee80211_ioctl(ret@31) */
    ieee80211_ioctl(ret@31);
    return last_call_result; /* opaque */
}

/* esp_wifi_set_vendor_ie_cb @ ieee80211_api.o 0x00000014 size 76B bind GLOBAL
 * Calls: wifi_init_completed, indirect(a8), ieee80211_ioctl | Data refs: g_osi_funcs_p, wifi_set_vnd_ie_cb_process
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 esp_wifi_set_vendor_ie_cb(u32 a2, u32 a3)
{
    /* frame: entry a1,32; 29 insns, 2 cond-branches, 0 loops, 0 jumps */
    /* immediates: 24, 0x101, 30, 0 */
    /* first predicate: beqz.n a10, 5c <esp_wifi_set_vendor_ie_cb+0x48> (condition opaque) */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=0x178 */
    /* mem st8: base=(ret@2d) off=0 */
    /* mem st32: base=(ret@2d) off=4 */
    /* mem st16: base=(ret@2d) off=8 */
    /* mem st8: base=(ret@2d) off=10 */
    /* mem st32: base=(ret@2d) off=12 */
    /* mem st32: base=(ret@2d) off=20 */
    /* site +0x1a: wifi_init_completed(/* no traced args */) */
    wifi_init_completed(/* no traced args */);
    /* site +0x2d: indirect call via a8 (base *(g_osi_funcs_p+0x178)); args: 24 */
    opaque_indirect_a8();
    /* site +0x57: ieee80211_ioctl(ret@2d) */
    ieee80211_ioctl(ret@2d);
    return last_call_result; /* opaque */
}

/* esp_wifi_set_vendor_ie_with_ret_cb @ ieee80211_api.o 0x00000014 size 78B bind GLOBAL
 * Calls: wifi_init_completed, indirect(a8), ieee80211_ioctl | Data refs: g_osi_funcs_p, wifi_set_vnd_ie_cb_with_ret_process
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 esp_wifi_set_vendor_ie_with_ret_cb(u32 a2, u32 a3)
{
    /* frame: entry a1,32; 29 insns, 2 cond-branches, 0 loops, 0 jumps */
    /* immediates: 24, 0x101, 117, 0 */
    /* first predicate: beqz.n a10, 5e <esp_wifi_set_vendor_ie_with_ret_cb+0x4a> (condition opaque) */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=0x178 */
    /* mem st8: base=(ret@2e) off=0 */
    /* mem st32: base=(ret@2e) off=4 */
    /* mem st16: base=(ret@2e) off=8 */
    /* mem st8: base=(ret@2e) off=10 */
    /* mem st32: base=(ret@2e) off=12 */
    /* mem st32: base=(ret@2e) off=20 */
    /* site +0x1a: wifi_init_completed(/* no traced args */) */
    wifi_init_completed(/* no traced args */);
    /* site +0x2e: indirect call via a8 (base *(g_osi_funcs_p+0x178)); args: 24 */
    opaque_indirect_a8();
    /* site +0x59: ieee80211_ioctl(ret@2e) */
    ieee80211_ioctl(ret@2e);
    return last_call_result; /* opaque */
}

/* wifi_event_post @ ieee80211_api.o 0x00000010 size 55B bind GLOBAL
 * Calls: indirect(a2), wifi_log | Data refs: WIFI_EVENT, g_osi_funcs_p, .rodata_wlog_error.58
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 wifi_event_post(u32 a2, u32 a3, u32 a4)
{
    /* frame: entry a1,32; 23 insns, 1 cond-branches, 0 loops, 0 jumps */
    /* immediates: -1, 1 */
    /* first predicate: beqz.n a10, 45 <wifi_event_post+0x35> (condition opaque) */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=180 */
    /* mem ld32: base=(lit:WIFI_EVENT) off=0 */
    /* site +0x2a: indirect call via a2 (base *(g_osi_funcs_p+180)); args: *(WIFI_EVENT+0), ?, ?, ?, -1 */
    opaque_indirect_a2();
    /* site +0x42: wifi_log(1, (1 slli 11), 1, lit:.rodata_wlog_error.58) */
    wifi_log(1, (1 slli 11), 1, lit:.rodata_wlog_error.58);
    return last_call_result; /* opaque */
}

/* wifi_mesh_event_post @ ieee80211_api.o 0x00000010 size 55B bind GLOBAL
 * Calls: indirect(a2), wifi_log | Data refs: WIFI_MESH_EVENT, g_osi_funcs_p, .rodata_wlog_error.59
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 wifi_mesh_event_post(u32 a2, u32 a3, u32 a4)
{
    /* frame: entry a1,32; 23 insns, 1 cond-branches, 0 loops, 0 jumps */
    /* immediates: -1, 1 */
    /* first predicate: beqz.n a10, 45 <wifi_mesh_event_post+0x35> (condition opaque) */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=180 */
    /* mem ld32: base=(lit:WIFI_MESH_EVENT) off=0 */
    /* site +0x2a: indirect call via a2 (base *(g_osi_funcs_p+180)); args: *(WIFI_MESH_EVENT+0), ?, ?, ?, -1 */
    opaque_indirect_a2();
    /* site +0x42: wifi_log(1, (1 slli 11), 1, lit:.rodata_wlog_error.59) */
    wifi_log(1, (1 slli 11), 1, lit:.rodata_wlog_error.59);
    return last_call_result; /* opaque */
}

/* esp_wifi_vnd_lora_enable @ ieee80211_api.o 0x00000014 size 214B bind GLOBAL
 * Calls: indirect(a2), ieee80211_add_ie_vendor_esp_head, indirect(a4), indirect(a3) | Data refs: g_wifi_nvs, g_ic, g_osi_funcs_p, g_wifi_global_lock
 * Fidelity: medium - branchy but loop-free, call sequence mapped (verified: section R_XTENSA_ASM_EXPAND + funcdb v3 agree; predicates opaque) */
u32 esp_wifi_vnd_lora_enable(u32 a2, u32 a5, u32 a6)
{
    /* frame: entry a1,32; 79 insns, 8 cond-branches, 0 loops, 4 jumps */
    /* immediates: 0, 1, 13, 0x101, 2, 9, 7, 32, 33, 11 */
    /* first predicate: bnez.n a7, 28 <esp_wifi_vnd_lora_enable+0x14> (condition opaque) */
    /* mem ld32: base=(lit:g_wifi_nvs) off=0 */
    /* mem ld8: base=(*(g_wifi_nvs+0)) off=156 */
    /* mem ld8: base=((*(g_wifi_nvs+0)+196608)) off=250 */
    /* mem ld32: base=(lit:g_ic) off=0x2b4 */
    /* mem ld32: base=(lit:g_ic) off=0x2b8 */
    /* mem st8: base=(*(g_ic+0x2b8)) off=9 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=0x16c */
    /* mem st8: base=(ret@6a) off=10 */
    /* mem st8: base=(ret@6a) off=11 */
    /* ... +13 more memops */
    /* site +0x6a: indirect call via a2 (base *(g_wifi_nvs+0x16c)); args: 13 */
    opaque_indirect_a2();
    /* site +0x82: ieee80211_add_ie_vendor_esp_head((ret@6a+2), 7, 1, 9) */
    ieee80211_add_ie_vendor_esp_head((ret@6a+2), 7, 1, 9);
    /* site +0xaf: indirect call via a4 (base *(*(g_osi_funcs_p+0)+84)); args: *(g_wifi_global_lock+0), 7, 1, 9 */
    opaque_indirect_a4();
    /* site +0xe3: indirect call via a3 (base *(*(g_osi_funcs_p+0)+88)); args: *(g_wifi_global_lock+0), 7, 1, 9 */
    opaque_indirect_a3();
    return 0;
}

/* esp_wifi_vnd_lora_disable @ ieee80211_api.o 0x0000000c size 98B bind GLOBAL
 * Calls: indirect(a3), indirect(a2), indirect(a2), indirect(a2) | Data refs: g_wifi_global_lock, g_osi_funcs_p, g_ic
 * Fidelity: medium - branchy but loop-free, call sequence mapped */
u32 esp_wifi_vnd_lora_disable(u32 a2, u32 a4, u32 a5)
{
    /* frame: entry a1,32; 37 insns, 4 cond-branches, 0 loops, 1 jumps */
    /* immediates: 0, 1 */
    /* first predicate: bnez.n a2, 3d <esp_wifi_vnd_lora_disable+0x31> (condition opaque) */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(lit:g_wifi_global_lock) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=84 */
    /* mem ld32: base=(lit:g_ic) off=0x2b4 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=176 */
    /* mem st32: base=(lit:g_ic) off=0x2b4 */
    /* mem ld32: base=(lit:g_ic) off=0x2b8 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=176 */
    /* ... +5 more memops */
    /* site +0x1d: indirect call via a3 (base *(*(g_osi_funcs_p+0)+84)); args: *(g_wifi_global_lock+0) */
    opaque_indirect_a3();
    /* site +0x2f: indirect call via a2 (base *(*(g_osi_funcs_p+0)+176)); args: *(g_ic+0x2b4) */
    opaque_indirect_a2();
    /* site +0x4d: indirect call via a2 (base *(*(g_osi_funcs_p+0)+176)); args: *(g_ic+0x2b8) */
    opaque_indirect_a2();
    /* site +0x67: indirect call via a2 (base *(*(g_osi_funcs_p+0)+88)); args: *(g_wifi_global_lock+0) */
    opaque_indirect_a2();
    return 0;
}

/* esp_wifi_set_max_tx_power @ ieee80211_api.o 0x0000001c size 98B bind GLOBAL
 * Calls: wifi_init_completed, indirect(a2), ieee80211_ioctl | Data refs: g_ic, g_osi_funcs_p, wifi_set_max_tpw
 * Fidelity: medium - branchy but loop-free, call sequence mapped */
u32 esp_wifi_set_max_tx_power(u32 a2)
{
    /* frame: entry a1,32; 35 insns, 4 cond-branches, 0 loops, 0 jumps */
    /* immediates: 76, 0x102, 24, 0x101, 32 */
    /* first predicate: beqz a10, 7c <esp_wifi_set_max_tx_power+0x60> (condition opaque) */
    /* mem ld8: base=((lit:g_ic+65536)) off=237 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=0x178 */
    /* mem st32: base=(ret@59) off=4 */
    /* mem st8: base=(ret@59) off=0 */
    /* mem st8: base=(ret@59) off=8 */
    /* site +0x22: wifi_init_completed(/* no traced args */) */
    wifi_init_completed(/* no traced args */);
    /* site +0x59: indirect call via a2 (base *(g_osi_funcs_p+0x178)); args: 24 */
    opaque_indirect_a2();
    /* site +0x77: ieee80211_ioctl(ret@59) */
    ieee80211_ioctl(ret@59);
    return last_call_result; /* opaque */
}

/* esp_wifi_get_max_tx_power @ ieee80211_api.o 0x00000014 size 55B bind GLOBAL
 * Calls: wifi_init_completed, phy_get_most_tpw | Data refs: g_ic
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 esp_wifi_get_max_tx_power(u32 a2)
{
    /* frame: entry a1,32; 20 insns, 3 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0x102, 0 */
    /* first predicate: beqz.n a10, 44 <esp_wifi_get_max_tx_power+0x30> (condition opaque) */
    /* mem ld8: base=((lit:g_ic+65536)) off=237 */
    /* mem st8: base=(?) off=0 */
    /* site +0x1a: wifi_init_completed(/* no traced args */) */
    wifi_init_completed(/* no traced args */);
    /* site +0x39: phy_get_most_tpw(ret@1a) */
    phy_get_most_tpw(ret@1a);
    return 0;
}

/* esp_wifi_set_event_mask @ ieee80211_api.o 0x00000014 size 74B bind GLOBAL
 * Calls: wifi_init_completed, indirect(a8), ieee80211_ioctl | Data refs: g_osi_funcs_p, wifi_set_event_mask
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 esp_wifi_set_event_mask(u32 a2)
{
    /* frame: entry a1,32; 28 insns, 2 cond-branches, 0 loops, 0 jumps */
    /* immediates: 24, 0x101, 33, 0 */
    /* first predicate: beqz.n a10, 5a <esp_wifi_set_event_mask+0x46> (condition opaque) */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=0x178 */
    /* mem st8: base=(ret@2d) off=0 */
    /* mem st32: base=(ret@2d) off=4 */
    /* mem st16: base=(ret@2d) off=8 */
    /* mem st8: base=(ret@2d) off=10 */
    /* mem st32: base=(ret@2d) off=12 */
    /* site +0x1a: wifi_init_completed(/* no traced args */) */
    wifi_init_completed(/* no traced args */);
    /* site +0x2d: indirect call via a8 (base *(g_osi_funcs_p+0x178)); args: 24 */
    opaque_indirect_a8();
    /* site +0x55: ieee80211_ioctl(ret@2d) */
    ieee80211_ioctl(ret@2d);
    return last_call_result; /* opaque */
}

/* esp_wifi_get_event_mask @ ieee80211_api.o 0x0000000c size 35B bind GLOBAL
 * Calls: wifi_init_completed | Data refs: g_wifi_event_mask
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 esp_wifi_get_event_mask(u32 a2)
{
    /* frame: entry a1,32; 14 insns, 2 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0x102, 0 */
    /* first predicate: beqz.n a10, 28 <esp_wifi_get_event_mask+0x1c> (condition opaque) */
    /* mem ld32: base=(lit:g_wifi_event_mask) off=0 */
    /* mem st32: base=(?) off=0 */
    /* site +0x12: wifi_init_completed(/* no traced args */) */
    wifi_init_completed(/* no traced args */);
    return 0;
}

/* esp_wifi_set_csi @ ieee80211_api.o 0x00000028 size 116B bind GLOBAL
 * Calls: wifi_init_completed, wifi_log, indirect(a2), ieee80211_ioctl | Data refs: g_ic, g_wifi_menuconfig, .rodata_wlog_error.60, g_osi_funcs_p, wifi_set_csi
 * Fidelity: medium - branchy but loop-free, call sequence mapped */
u32 esp_wifi_set_csi(u32 a2)
{
    /* frame: entry a1,32; 42 insns, 5 cond-branches, 0 loops, 1 jumps */
    /* immediates: 1, 2, -1, 24, 0x101, 34 */
    /* first predicate: beqz a10, 9a <esp_wifi_set_csi+0x72> (condition opaque) */
    /* mem ld8: base=((lit:g_ic+65536)) off=237 */
    /* mem ld8: base=((lit:g_ic+65536)) off=239 */
    /* mem ld32: base=(lit:g_wifi_menuconfig) off=24 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=0x178 */
    /* mem st32: base=(ret@76) off=4 */
    /* mem st8: base=(ret@76) off=0 */
    /* mem st8: base=(ret@76) off=8 */
    /* site +0x2e: wifi_init_completed(/* no traced args */) */
    wifi_init_completed(/* no traced args */);
    /* site +0x62: wifi_log(1, 2, 1, lit:.rodata_wlog_error.60) */
    wifi_log(1, 2, 1, lit:.rodata_wlog_error.60);
    /* site +0x76: indirect call via a2 (base *(g_osi_funcs_p+0x178)); args: 24, 2, 1, lit:.rodata_wlog_error.60 */
    opaque_indirect_a2();
    /* site +0x95: ieee80211_ioctl(ret@76, 2, 1, lit:.rodata_wlog_error.60) */
    ieee80211_ioctl(ret@76, 2, 1, lit:.rodata_wlog_error.60);
    return last_call_result; /* opaque */
}

/* esp_wifi_set_csi_config @ ieee80211_api.o 0x00000024 size 130B bind GLOBAL
 * Calls: wifi_init_completed, indirect(a3), memcpy, ieee80211_ioctl | Data refs: g_ic, g_wifi_menuconfig, g_osi_funcs_p, wifi_csi_set_config
 * Fidelity: medium - branchy but loop-free, call sequence mapped */
u32 esp_wifi_set_csi_config(u32 a2, u32 a3)
{
    /* frame: entry a1,32; 49 insns, 6 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0x102, -1, 32, 0x101, 35, 8, 0 */
    /* first predicate: beqz a10, a2 <esp_wifi_set_csi_config+0x7e> (condition opaque) */
    /* mem ld8: base=((lit:g_ic+65536)) off=237 */
    /* mem ld8: base=((lit:g_ic+65536)) off=239 */
    /* mem ld32: base=(lit:g_wifi_menuconfig) off=24 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=0x178 */
    /* mem st8: base=(ret@62) off=0 */
    /* mem st32: base=(ret@62) off=4 */
    /* mem st16: base=(ret@62) off=8 */
    /* mem st8: base=(ret@62) off=10 */
    /* mem st32: base=(ret@62) off=12 */
    /* site +0x2a: wifi_init_completed(/* no traced args */) */
    wifi_init_completed(/* no traced args */);
    /* site +0x62: indirect call via a3 (base *(g_osi_funcs_p+0x178)); args: 32 */
    opaque_indirect_a3();
    /* site +0x95: memcpy((ret@62+20), ?, 8) */
    memcpy((ret@62+20), ?, 8);
    /* site +0x9d: ieee80211_ioctl(ret@62, ?, 8) */
    ieee80211_ioctl(ret@62, ?, 8);
    return last_call_result; /* opaque */
}

/* esp_wifi_set_csi_rx_cb @ ieee80211_api.o 0x0000000c size 30B bind GLOBAL
 * Calls: wifi_init_completed, ic_register_csi_rx_cb | Data refs: none
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 esp_wifi_set_csi_rx_cb(u32 a2, u32 a3)
{
    /* frame: entry a1,32; 12 insns, 1 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0 */
    /* first predicate: beqz.n a10, 26 <esp_wifi_set_csi_rx_cb+0x1a> (condition opaque) */
    /* site +0x12: wifi_init_completed(/* no traced args */) */
    wifi_init_completed(/* no traced args */);
    /* site +0x21: ic_register_csi_rx_cb(/* no traced args */) */
    ic_register_csi_rx_cb(/* no traced args */);
    return 0;
}

/* esp_wifi_internal_set_fix_rate @ ieee80211_api.o 0x00000020 size 102B bind GLOBAL
 * Calls: wifi_init_completed, indirect(a8), ieee80211_ioctl | Data refs: g_ic, g_osi_funcs_p, wifi_set_fix_rate_process
 * Fidelity: medium - branchy but loop-free, call sequence mapped */
u32 esp_wifi_internal_set_fix_rate(u32 a2, u32 a3, u32 a4)
{
    /* frame: entry a1,32; 37 insns, 4 cond-branches, 0 loops, 0 jumps */
    /* immediates: 24, 0x101, 36, 0 */
    /* first predicate: beqz a10, 82 <esp_wifi_internal_set_fix_rate+0x62> (condition opaque) */
    /* mem ld8: base=((lit:g_ic+65536)) off=237 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=0x178 */
    /* mem st8: base=(ret@52) off=0 */
    /* mem st8: base=(ret@52) off=8 */
    /* mem st32: base=(ret@52) off=4 */
    /* mem st8: base=(ret@52) off=9 */
    /* mem st8: base=(ret@52) off=10 */
    /* mem st32: base=(ret@52) off=12 */
    /* site +0x26: wifi_init_completed(/* no traced args */) */
    wifi_init_completed(/* no traced args */);
    /* site +0x52: indirect call via a8 (base *(g_osi_funcs_p+0x178)); args: 24 */
    opaque_indirect_a8();
    /* site +0x7d: ieee80211_ioctl(ret@52) */
    ieee80211_ioctl(ret@52);
    return last_call_result; /* opaque */
}

/* esp_wifi_internal_get_fix_rate @ ieee80211_api.o 0x00000010 size 64B bind GLOBAL
 * Calls: wifi_init_completed, ic_get_fix_rate | Data refs: none
 * Fidelity: medium - branchy but loop-free, call sequence mapped */
u32 esp_wifi_internal_get_fix_rate(u32 a2, u32 a3, u32 a4)
{
    /* frame: entry a1,32; 24 insns, 4 cond-branches, 0 loops, 1 jumps */
    /* immediates: 1, 0, 0x102 */
    /* first predicate: beqz.n a10, 4c <esp_wifi_internal_get_fix_rate+0x3c> (condition opaque) */
    /* site +0x16: wifi_init_completed(/* no traced args */) */
    wifi_init_completed(/* no traced args */);
    /* site +0x3e: ic_get_fix_rate(/* no traced args */) */
    ic_get_fix_rate(/* no traced args */);
    return 0x102;
}

/* esp_wifi_set_sta_rx_probe_req @ ieee80211_api.o 0x00000004 size 15B bind GLOBAL
 * Calls: none | Data refs: wifi_sta_rx_probe_req
 * Fidelity: high - straight-line, fully mapped (6 insns) */
u32 esp_wifi_set_sta_rx_probe_req(u32 a2)
{
    /* frame: entry a1,32; 6 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0 */
    /* mem st32: base=(lit:wifi_sta_rx_probe_req) off=0 */
    return 0;
}

/* esp_wifi_ipc_internal @ ieee80211_api.o 0x00000028 size 278B bind GLOBAL
 * Calls: wifi_init_completed, indirect(a4), ieee80211_ioctl, indirect(a4), memcpy, indirect(a4), indirect(a2), memcpy, indirect(a4), ieee80211_ioctl, wifi_log, indirect(a2), indirect(a2) | Data refs: g_osi_funcs_p, wifi_ipc_process, .rodata_wlog_error.61
 * Fidelity: low - 109 insns, 13 branches, 0 loops; skeleton only */
u32 esp_wifi_ipc_internal(u32 a2, u32 a3)
{
    /* frame: entry a1,32; 109 insns, 13 cond-branches, 0 loops, 4 jumps */
    /* immediates: 0x102, 24, 49, 1, 0, 12, 0x101, 2 */
    /* first predicate: beqz a2, 13a <esp_wifi_ipc_internal+0x112> (condition opaque) */
    /* mem ld32: base=(?) off=0 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=0x178 */
    /* mem st8: base=(ret@52) off=0 */
    /* mem st32: base=(ret@52) off=4 */
    /* mem st16: base=(ret@52) off=8 */
    /* mem st32: base=(ret@52) off=12 */
    /* mem st8: base=(ret@52) off=10 */
    /* mem st32: base=(ret@52) off=20 */
    /* mem ld32: base=(0) off=8 */
    /* ... +23 more memops */
    /* site +0x3d: wifi_init_completed(/* no traced args */) */
    wifi_init_completed(/* no traced args */);
    /* site +0x52: indirect call via a4 (base *(*(g_osi_funcs_p+0)+0x178)); args: 24 */
    opaque_indirect_a4();
    /* site +0x81: ieee80211_ioctl(ret@52) */
    ieee80211_ioctl(ret@52);
    /* site +0x8b: indirect call via a4 (base ret@81); args: 12 */
    opaque_indirect_a4();
    /* site +0x99: memcpy(ret@8b, 0, 12) */
    memcpy(ret@8b, 0, 12);
    /* site +0xa9: indirect call via a4 (base *(*(g_osi_funcs_p+0)+0x178)); args: *(0+8), 0, 12 */
    opaque_indirect_a4();
    /* site +0xba: indirect call via a2 (base *(*(g_osi_funcs_p+0)+176)); args: ret@8b, 0, 12 */
    opaque_indirect_a2();
    /* site +0xcb: memcpy(ret@ba, *(*(*(g_osi_funcs_p+0)+176)+4), *(*(*(g_osi_funcs_p+0)+176)+8)) */
    memcpy(ret@ba, *(*(*(g_osi_funcs_p+0)+176)+4), *(*(*(g_osi_funcs_p+0)+176)+8));
    /* site +0xd6: indirect call via a4 (base *(*(g_osi_funcs_p+0)+0x178)); args: 24, *(*(*(g_osi_funcs_p+0)+176)+4), *(*(*(g_osi_funcs_p+0)+176)+8) */
    opaque_indirect_a4();
    /* site +0x101: ieee80211_ioctl(ret@d6, *(*(*(g_osi_funcs_p+0)+176)+4), *(*(*(g_osi_funcs_p+0)+176)+8)) */
    ieee80211_ioctl(ret@d6, *(*(*(g_osi_funcs_p+0)+176)+4), *(*(*(g_osi_funcs_p+0)+176)+8));
    /* site +0x11b: wifi_log(1, 2, 1, lit:.rodata_wlog_error.61) */
    wifi_log(1, 2, 1, lit:.rodata_wlog_error.61);
    /* site +0x12d: indirect call via a2 (base *(*(g_osi_funcs_p+0)+176)); args: *(wifi_ipc_process+4), 2, 1, lit:.rodata_wlog_error.61 */
    opaque_indirect_a2();
    /* site +0x137: indirect call via a2 (base *(*(g_osi_funcs_p+0)+176)); args: ret@8b, 2, 1, lit:.rodata_wlog_error.61 */
    opaque_indirect_a2();
    return 0x101;
}

/* esp_wifi_ftm_end_session @ ieee80211_api.o 0x00000018 size 58B bind GLOBAL
 * Calls: wifi_init_completed, esp_wifi_ipc_internal | Data refs: g_ic, esp_wifi_ftm_end_session_local
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 esp_wifi_ftm_end_session(u32 a2)
{
    /* frame: entry a1,48; 22 insns, 2 cond-branches, 0 loops, 0 jumps */
    /* immediates: 1, 0 */
    /* first predicate: beqz.n a10, 50 <esp_wifi_ftm_end_session+0x38> (condition opaque) */
    /* mem ld8: base=((lit:g_ic+65536)) off=237 */
    /* mem st32: base=(?) off=0 */
    /* mem st32: base=(?) off=4 */
    /* mem st32: base=(?) off=8 */
    /* site +0x1e: wifi_init_completed(/* no traced args */) */
    wifi_init_completed(/* no traced args */);
    /* site +0x4b: esp_wifi_ipc_internal(?, 1) */
    esp_wifi_ipc_internal(?, 1);
    return last_call_result; /* opaque */
}

/* esp_wifi_ftm_get_report @ ieee80211_api.o 0x00000018 size 78B bind GLOBAL
 * Calls: wifi_init_completed, esp_wifi_ipc_internal | Data refs: g_ic, esp_wifi_ftm_get_report_local
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 esp_wifi_ftm_get_report(u32 a2, u32 a3)
{
    /* frame: entry a1,64; 30 insns, 3 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0x102, 1, 0 */
    /* first predicate: beqz.n a10, 62 <esp_wifi_ftm_get_report+0x4a> (condition opaque) */
    /* mem ld8: base=((lit:g_ic+65536)) off=237 */
    /* mem st32: base=(?) off=12 */
    /* mem st32: base=(?) off=0 */
    /* mem st32: base=(?) off=4 */
    /* mem st8: base=(?) off=16 */
    /* mem st32: base=(?) off=8 */
    /* site +0x1e: wifi_init_completed(/* no traced args */) */
    wifi_init_completed(/* no traced args */);
    /* site +0x5d: esp_wifi_ipc_internal(?, 1) */
    esp_wifi_ipc_internal(?, 1);
    return last_call_result; /* opaque */
}

/* esp_wifi_ftm_resp_set_offset @ ieee80211_api.o 0x00000018 size 70B bind GLOBAL
 * Calls: wifi_init_completed, esp_wifi_ipc_internal | Data refs: g_ic, esp_wifi_ftm_resp_set_offset_local
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 esp_wifi_ftm_resp_set_offset(u32 a2)
{
    /* frame: entry a1,64; 26 insns, 2 cond-branches, 0 loops, 0 jumps */
    /* immediates: 1, 0 */
    /* first predicate: beqz.n a10, 5c <esp_wifi_ftm_resp_set_offset+0x44> (condition opaque) */
    /* mem st16: base=(?) off=16 */
    /* mem ld8: base=((lit:g_ic+65536)) off=237 */
    /* mem st32: base=(?) off=0 */
    /* mem st32: base=(?) off=4 */
    /* mem st32: base=(?) off=8 */
    /* site +0x27: wifi_init_completed(/* no traced args */) */
    wifi_init_completed(/* no traced args */);
    /* site +0x57: esp_wifi_ipc_internal(?, 1) */
    esp_wifi_ipc_internal(?, 1);
    return last_call_result; /* opaque */
}

/* esp_wifi_internal_set_log_level @ ieee80211_api.o 0x00000004 size 23B bind GLOBAL
 * Calls: none | Data refs: g_log_level
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 esp_wifi_internal_set_log_level(u32 a2)
{
    /* frame: entry a1,32; 9 insns, 1 cond-branches, 0 loops, 0 jumps */
    /* immediates: -1, 0 */
    /* first predicate: bgeui a2, 8, 14 <esp_wifi_internal_set_log_level+0x10> (condition opaque) */
    /* mem st32: base=(lit:g_log_level) off=0 */
    return 0;
}

/* esp_wifi_internal_set_log_mod @ ieee80211_api.o 0x00000014 size 78B bind GLOBAL
 * Calls: wifi_init_completed, indirect(a8), ieee80211_ioctl | Data refs: g_osi_funcs_p, wifi_set_log_mod_process
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 esp_wifi_internal_set_log_mod(u32 a2, u32 a3, u32 a4)
{
    /* frame: entry a1,32; 28 insns, 2 cond-branches, 0 loops, 0 jumps */
    /* immediates: 24, 0x101, 43 */
    /* first predicate: beqz.n a10, 5e <esp_wifi_internal_set_log_mod+0x4a> (condition opaque) */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=0x178 */
    /* mem st8: base=(ret@31) off=0 */
    /* mem st8: base=(ret@31) off=8 */
    /* mem st32: base=(ret@31) off=4 */
    /* mem st8: base=(ret@31) off=9 */
    /* mem st8: base=(ret@31) off=10 */
    /* site +0x1a: wifi_init_completed(/* no traced args */) */
    wifi_init_completed(/* no traced args */);
    /* site +0x31: indirect call via a8 (base *(g_osi_funcs_p+0x178)); args: 24 */
    opaque_indirect_a8();
    /* site +0x59: ieee80211_ioctl(ret@31) */
    ieee80211_ioctl(ret@31);
    return last_call_result; /* opaque */
}

/* esp_wifi_internal_get_log @ ieee80211_api.o 0x00000014 size 44B bind GLOBAL
 * Calls: wifi_init_completed, memcpy | Data refs: g_log_level, g_log_mod
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 esp_wifi_internal_get_log(u32 a2, u32 a3)
{
    /* frame: entry a1,32; 17 insns, 1 cond-branches, 0 loops, 0 jumps */
    /* immediates: 24, 0 */
    /* first predicate: beqz.n a10, 3c <esp_wifi_internal_get_log+0x28> (condition opaque) */
    /* mem ld32: base=(lit:g_log_level) off=0 */
    /* mem st32: base=(?) off=0 */
    /* site +0x1a: wifi_init_completed(/* no traced args */) */
    wifi_init_completed(/* no traced args */);
    /* site +0x37: memcpy(?, lit:g_log_mod, 24) */
    memcpy(?, lit:g_log_mod, 24);
    return 0;
}

/* esp_wifi_internal_ioctl @ ieee80211_api.o 0x00000014 size 82B bind GLOBAL
 * Calls: wifi_init_completed, indirect(a8), ieee80211_ioctl | Data refs: g_osi_funcs_p, wifi_internal_ioctl_process
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 esp_wifi_internal_ioctl(u32 a2, u32 a3)
{
    /* frame: entry a1,32; 31 insns, 3 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0x102, 24, 0x101, 48, 0 */
    /* first predicate: beqz a3, 62 <esp_wifi_internal_ioctl+0x4e> (condition opaque) */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=0x178 */
    /* mem st8: base=(ret@32) off=0 */
    /* mem st32: base=(ret@32) off=4 */
    /* mem st16: base=(ret@32) off=8 */
    /* mem st8: base=(ret@32) off=10 */
    /* mem st32: base=(ret@32) off=12 */
    /* mem st32: base=(ret@32) off=20 */
    /* site +0x20: wifi_init_completed(/* no traced args */) */
    wifi_init_completed(/* no traced args */);
    /* site +0x32: indirect call via a8 (base *(g_osi_funcs_p+0x178)); args: 24 */
    opaque_indirect_a8();
    /* site +0x5d: ieee80211_ioctl(ret@32) */
    ieee80211_ioctl(ret@32);
    return last_call_result; /* opaque */
}

/* esp_wifi_internal_configure_wake_window @ ieee80211_api.o 0x00000014 size 88B bind GLOBAL
 * Calls: wifi_init_completed, indirect(a2), ieee80211_ioctl | Data refs: g_osi_funcs_p, wifi_configure_wake_window_process
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 esp_wifi_internal_configure_wake_window(u32 a2, u32 a3)
{
    /* frame: entry a1,32; 33 insns, 3 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0x102, 24, 0x101, 87, 0 */
    /* first predicate: beqz a10, 6a <esp_wifi_internal_configure_wake_window+0x56> (condition opaque) */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=0x178 */
    /* mem st8: base=(ret@36) off=0 */
    /* mem st32: base=(ret@36) off=4 */
    /* mem st8: base=(ret@36) off=9 */
    /* mem st8: base=(ret@36) off=10 */
    /* mem st32: base=(ret@36) off=12 */
    /* mem st8: base=(ret@36) off=8 */
    /* mem st32: base=(ret@36) off=20 */
    /* site +0x1a: wifi_init_completed(/* no traced args */) */
    wifi_init_completed(/* no traced args */);
    /* site +0x36: indirect call via a2 (base *(g_osi_funcs_p+0x178)); args: 24 */
    opaque_indirect_a2();
    /* site +0x65: ieee80211_ioctl(ret@36) */
    ieee80211_ioctl(ret@36);
    return last_call_result; /* opaque */
}

/* esp_wifi_internal_offchan_cancel @ ieee80211_api.o 0x00000014 size 84B bind GLOBAL
 * Calls: wifi_init_completed, indirect(a2), ieee80211_ioctl | Data refs: g_osi_funcs_p, wifi_offchan_cancel_process
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 esp_wifi_internal_offchan_cancel(u32 a2)
{
    /* frame: entry a1,32; 31 insns, 2 cond-branches, 0 loops, 0 jumps */
    /* immediates: 24, 0x101, 121, 0 */
    /* first predicate: beqz.n a10, 66 <esp_wifi_internal_offchan_cancel+0x52> (condition opaque) */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=0x178 */
    /* mem st8: base=(ret@31) off=0 */
    /* mem st32: base=(ret@31) off=4 */
    /* mem st8: base=(ret@31) off=9 */
    /* mem st8: base=(ret@31) off=10 */
    /* mem st32: base=(ret@31) off=12 */
    /* mem st32: base=(ret@31) off=20 */
    /* mem st8: base=(ret@31) off=8 */
    /* site +0x1a: wifi_init_completed(/* no traced args */) */
    wifi_init_completed(/* no traced args */);
    /* site +0x31: indirect call via a2 (base *(g_osi_funcs_p+0x178)); args: 24 */
    opaque_indirect_a2();
    /* site +0x61: ieee80211_ioctl(ret@31) */
    ieee80211_ioctl(ret@31);
    return last_call_result; /* opaque */
}

/* esp_wifi_force_wakeup_acquire @ ieee80211_api.o 0x0000001c size 78B bind GLOBAL
 * Calls: wifi_init_completed, indirect(a2), ieee80211_ioctl | Data refs: g_ic, g_osi_funcs_p, wifi_force_wakeup_process
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 esp_wifi_force_wakeup_acquire(u32 a2)
{
    /* frame: entry a1,32; 28 insns, 3 cond-branches, 0 loops, 0 jumps */
    /* immediates: 24, 0, 103, 1 */
    /* first predicate: beqz.n a10, 68 <esp_wifi_force_wakeup_acquire+0x4c> (condition opaque) */
    /* mem ld8: base=((lit:g_ic+65536)) off=237 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=0x178 */
    /* mem st32: base=(ret@43) off=4 */
    /* mem st8: base=(ret@43) off=0 */
    /* mem st8: base=(ret@43) off=8 */
    /* site +0x22: wifi_init_completed(/* no traced args */) */
    wifi_init_completed(/* no traced args */);
    /* site +0x43: indirect call via a2 (base *(g_osi_funcs_p+0x178)); args: 24 */
    opaque_indirect_a2();
    /* site +0x65: ieee80211_ioctl(ret@43) */
    ieee80211_ioctl(ret@43);
    return opaque_result; /* full dataflow not recovered */
}

/* esp_wifi_force_wakeup_release @ ieee80211_api.o 0x0000001c size 75B bind GLOBAL
 * Calls: wifi_init_completed, indirect(a2), ieee80211_ioctl | Data refs: g_ic, g_osi_funcs_p, wifi_force_wakeup_process
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 esp_wifi_force_wakeup_release(u32 a2)
{
    /* frame: entry a1,32; 27 insns, 3 cond-branches, 0 loops, 0 jumps */
    /* immediates: 24, 0, 103 */
    /* first predicate: beqz.n a10, 65 <esp_wifi_force_wakeup_release+0x49> (condition opaque) */
    /* mem ld8: base=((lit:g_ic+65536)) off=237 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=0x178 */
    /* mem st32: base=(ret@43) off=4 */
    /* mem st8: base=(ret@43) off=0 */
    /* mem st8: base=(ret@43) off=8 */
    /* site +0x22: wifi_init_completed(/* no traced args */) */
    wifi_init_completed(/* no traced args */);
    /* site +0x43: indirect call via a2 (base *(g_osi_funcs_p+0x178)); args: 24 */
    opaque_indirect_a2();
    /* site +0x62: ieee80211_ioctl(ret@43) */
    ieee80211_ioctl(ret@43);
    return opaque_result; /* full dataflow not recovered */
}

/* esp_wifi_internal_on_coex_start @ ieee80211_api.o 0x00000018 size 55B bind GLOBAL
 * Calls: wifi_init_completed, esp_wifi_ipc_internal | Data refs: g_ic, wifi_on_coex_start_process
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 esp_wifi_internal_on_coex_start(u32 a2)
{
    /* frame: entry a1,48; 21 insns, 2 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0 */
    /* first predicate: beqz.n a10, 4d <esp_wifi_internal_on_coex_start+0x35> (condition opaque) */
    /* mem ld8: base=((lit:g_ic+65536)) off=237 */
    /* mem st32: base=(?) off=0 */
    /* mem st32: base=(?) off=4 */
    /* mem st32: base=(?) off=8 */
    /* site +0x1e: wifi_init_completed(/* no traced args */) */
    wifi_init_completed(/* no traced args */);
    /* site +0x4a: esp_wifi_ipc_internal(?, 0) */
    esp_wifi_ipc_internal(?, 0);
    return opaque_result; /* full dataflow not recovered */
}

/* esp_wifi_internal_on_coex_schm_phase @ ieee80211_api.o 0x00000018 size 55B bind GLOBAL
 * Calls: wifi_init_completed, esp_wifi_ipc_internal | Data refs: g_ic, wifi_on_coex_schm_phase_process
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 esp_wifi_internal_on_coex_schm_phase(u32 a2)
{
    /* frame: entry a1,48; 21 insns, 2 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0 */
    /* first predicate: beqz.n a10, 4d <esp_wifi_internal_on_coex_schm_phase+0x35> (condition opaque) */
    /* mem ld8: base=((lit:g_ic+65536)) off=237 */
    /* mem st32: base=(?) off=0 */
    /* mem st32: base=(?) off=4 */
    /* mem st32: base=(?) off=8 */
    /* site +0x1e: wifi_init_completed(/* no traced args */) */
    wifi_init_completed(/* no traced args */);
    /* site +0x4a: esp_wifi_ipc_internal(?, 0) */
    esp_wifi_ipc_internal(?, 0);
    return opaque_result; /* full dataflow not recovered */
}

/* esp_wifi_coex_pwr_configure @ ieee80211_api.o 0x00000014 size 63B bind GLOBAL
 * Calls: wifi_init_completed, indirect(a2), ieee80211_ioctl | Data refs: g_osi_funcs_p, wifi_coex_pwr_process
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 esp_wifi_coex_pwr_configure(u32 a2)
{
    /* frame: entry a1,32; 23 insns, 2 cond-branches, 0 loops, 0 jumps */
    /* immediates: 24, 0, 110 */
    /* first predicate: beqz.n a10, 51 <esp_wifi_coex_pwr_configure+0x3d> (condition opaque) */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=0x178 */
    /* mem st32: base=(ret@2f) off=4 */
    /* mem st8: base=(ret@2f) off=0 */
    /* mem st8: base=(ret@2f) off=8 */
    /* site +0x1a: wifi_init_completed(/* no traced args */) */
    wifi_init_completed(/* no traced args */);
    /* site +0x2f: indirect call via a2 (base *(g_osi_funcs_p+0x178)); args: 24 */
    opaque_indirect_a2();
    /* site +0x4e: ieee80211_ioctl(ret@2f) */
    ieee80211_ioctl(ret@2f);
    return opaque_result; /* full dataflow not recovered */
}

/* esp_wifi_beacon_offset_sample_beacon @ ieee80211_api.o 0x0000001c size 72B bind GLOBAL
 * Calls: wifi_init_completed, indirect(a2), ieee80211_ioctl | Data refs: g_ic, g_osi_funcs_p, wifi_sample_beacon_process
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 esp_wifi_beacon_offset_sample_beacon(u32 a2)
{
    /* frame: entry a1,32; 26 insns, 3 cond-branches, 0 loops, 0 jumps */
    /* immediates: 24, 0, 112 */
    /* first predicate: beqz.n a10, 62 <esp_wifi_beacon_offset_sample_beacon+0x46> (condition opaque) */
    /* mem ld8: base=((lit:g_ic+65536)) off=237 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=0x178 */
    /* mem st32: base=(ret@43) off=4 */
    /* mem st8: base=(ret@43) off=0 */
    /* site +0x22: wifi_init_completed(/* no traced args */) */
    wifi_init_completed(/* no traced args */);
    /* site +0x43: indirect call via a2 (base *(g_osi_funcs_p+0x178)); args: 24 */
    opaque_indirect_a2();
    /* site +0x5f: ieee80211_ioctl(ret@43) */
    ieee80211_ioctl(ret@43);
    return opaque_result; /* full dataflow not recovered */
}

/* esp_wifi_tbtt_quick_wake_configure @ ieee80211_api.o 0x0000001c size 78B bind GLOBAL
 * Calls: wifi_init_completed, indirect(a2), ieee80211_ioctl | Data refs: g_ic, g_osi_funcs_p, wifi_tbtt_quick_wake_configure_process
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 esp_wifi_tbtt_quick_wake_configure(u32 a2)
{
    /* frame: entry a1,32; 28 insns, 3 cond-branches, 0 loops, 0 jumps */
    /* immediates: 24, 0, 113 */
    /* first predicate: beqz.n a10, 68 <esp_wifi_tbtt_quick_wake_configure+0x4c> (condition opaque) */
    /* mem ld8: base=((lit:g_ic+65536)) off=237 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=0x178 */
    /* mem st32: base=(ret@46) off=4 */
    /* mem st8: base=(ret@46) off=0 */
    /* mem st8: base=(ret@46) off=8 */
    /* site +0x22: wifi_init_completed(/* no traced args */) */
    wifi_init_completed(/* no traced args */);
    /* site +0x46: indirect call via a2 (base *(g_osi_funcs_p+0x178)); args: 24 */
    opaque_indirect_a2();
    /* site +0x65: ieee80211_ioctl(ret@46) */
    ieee80211_ioctl(ret@46);
    return opaque_result; /* full dataflow not recovered */
}

/* esp_wifi_update_listen_interval @ ieee80211_api.o 0x00000014 size 78B bind GLOBAL
 * Calls: wifi_init_completed, indirect(a2), ieee80211_ioctl | Data refs: g_osi_funcs_p, wifi_update_listen_interval_process
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 esp_wifi_update_listen_interval(u32 a2)
{
    /* frame: entry a1,32; 28 insns, 2 cond-branches, 0 loops, 0 jumps */
    /* immediates: 24, 0x101, 104, 0 */
    /* first predicate: beqz.n a10, 60 <esp_wifi_update_listen_interval+0x4c> (condition opaque) */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=0x178 */
    /* mem st8: base=(ret@31) off=0 */
    /* mem st16: base=(ret@31) off=8 */
    /* mem st32: base=(ret@31) off=4 */
    /* mem st8: base=(ret@31) off=10 */
    /* mem st32: base=(ret@31) off=12 */
    /* site +0x1a: wifi_init_completed(/* no traced args */) */
    wifi_init_completed(/* no traced args */);
    /* site +0x31: indirect call via a2 (base *(g_osi_funcs_p+0x178)); args: 24 */
    opaque_indirect_a2();
    /* site +0x5b: ieee80211_ioctl(ret@31) */
    ieee80211_ioctl(ret@31);
    return last_call_result; /* opaque */
}

/* esp_wifi_internal_update_modem_sleep_default_params @ ieee80211_api.o 0x00000004 size 11B bind GLOBAL
 * Calls: ic_update_modem_sleep_default_params | Data refs: none
 * Fidelity: high - straight-line, fully mapped (4 insns) */
u32 esp_wifi_internal_update_modem_sleep_default_params(void)
{
    /* frame: entry a1,32; 4 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* site +0xa: ic_update_modem_sleep_default_params(/* no traced args */) */
    ic_update_modem_sleep_default_params(/* no traced args */);
    return opaque_result; /* full dataflow not recovered */
}

/* esp_wifi_internal_update_light_sleep_default_params @ ieee80211_api.o 0x00000004 size 15B bind GLOBAL
 * Calls: ic_update_light_sleep_default_params | Data refs: none
 * Fidelity: high - straight-line, fully mapped (6 insns) */
u32 esp_wifi_internal_update_light_sleep_default_params(u32 a2, u32 a3)
{
    /* frame: entry a1,32; 6 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* site +0xe: ic_update_light_sleep_default_params(/* no traced args */) */
    ic_update_light_sleep_default_params(/* no traced args */);
    return opaque_result; /* full dataflow not recovered */
}

/* esp_wifi_set_sleep_min_active_time @ ieee80211_api.o 0x00000004 size 14B bind GLOBAL
 * Calls: ic_set_sleep_min_active_time | Data refs: none
 * Fidelity: high - straight-line, fully mapped (5 insns) */
u32 esp_wifi_set_sleep_min_active_time(u32 a2)
{
    /* frame: entry a1,32; 5 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* site +0xd: ic_set_sleep_min_active_time(/* no traced args */) */
    ic_set_sleep_min_active_time(/* no traced args */);
    return opaque_result; /* full dataflow not recovered */
}

/* esp_wifi_set_keep_alive_time @ ieee80211_api.o 0x00000004 size 14B bind GLOBAL
 * Calls: ic_set_keep_alive_time | Data refs: none
 * Fidelity: high - straight-line, fully mapped (5 insns) */
u32 esp_wifi_set_keep_alive_time(u32 a2)
{
    /* frame: entry a1,32; 5 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* site +0xd: ic_set_keep_alive_time(/* no traced args */) */
    ic_set_keep_alive_time(/* no traced args */);
    return opaque_result; /* full dataflow not recovered */
}

/* esp_wifi_beacon_monitor_configure @ ieee80211_api.o 0x00000004 size 14B bind GLOBAL
 * Calls: ic_beacon_monitor_configure | Data refs: none
 * Fidelity: high - straight-line, fully mapped (5 insns) */
u32 esp_wifi_beacon_monitor_configure(u32 a2)
{
    /* frame: entry a1,32; 5 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* site +0xd: ic_beacon_monitor_configure(/* no traced args */) */
    ic_beacon_monitor_configure(/* no traced args */);
    return opaque_result; /* full dataflow not recovered */
}

/* esp_wifi_set_sleep_wait_broadcast_data_time @ ieee80211_api.o 0x00000004 size 14B bind GLOBAL
 * Calls: ic_set_sleep_wait_broadcast_data_time | Data refs: none
 * Fidelity: high - straight-line, fully mapped (5 insns) */
u32 esp_wifi_set_sleep_wait_broadcast_data_time(u32 a2)
{
    /* frame: entry a1,32; 5 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* site +0xd: ic_set_sleep_wait_broadcast_data_time(/* no traced args */) */
    ic_set_sleep_wait_broadcast_data_time(/* no traced args */);
    return opaque_result; /* full dataflow not recovered */
}

/* esp_wifi_beacon_offset_configure @ ieee80211_api.o 0x0000000c size 28B bind GLOBAL
 * Calls: wifi_init_completed, ic_beacon_offset_configure | Data refs: none
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 esp_wifi_beacon_offset_configure(u32 a2)
{
    /* frame: entry a1,32; 11 insns, 1 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0 */
    /* first predicate: beqz.n a10, 24 <esp_wifi_beacon_offset_configure+0x18> (condition opaque) */
    /* site +0x12: wifi_init_completed(/* no traced args */) */
    wifi_init_completed(/* no traced args */);
    /* site +0x1f: ic_beacon_offset_configure(/* no traced args */) */
    ic_beacon_offset_configure(/* no traced args */);
    return 0;
}

/* esp_wifi_beacon_offset_set_rx_beacon_standard @ ieee80211_api.o 0x0000000c size 30B bind GLOBAL
 * Calls: wifi_init_completed, ic_beacon_offset_set_rx_beacon_standard | Data refs: none
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 esp_wifi_beacon_offset_set_rx_beacon_standard(u32 a2)
{
    /* frame: entry a1,32; 11 insns, 1 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0 */
    /* first predicate: beqz.n a10, 28 <esp_wifi_beacon_offset_set_rx_beacon_standard+0x1c> (condition opaque) */
    /* site +0x12: wifi_init_completed(/* no traced args */) */
    wifi_init_completed(/* no traced args */);
    /* site +0x23: ic_beacon_offset_set_rx_beacon_standard(ret@12) */
    ic_beacon_offset_set_rx_beacon_standard(ret@12);
    return 0;
}

/* esp_wifi_internal_reg_netstack_buf_cb @ ieee80211_api.o 0x00000008 size 37B bind GLOBAL
 * Calls: esp_wifi_ipc_internal | Data refs: esp_wifi_internal_reg_netstack_buf_cb_local
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 esp_wifi_internal_reg_netstack_buf_cb(u32 a2, u32 a3)
{
    /* frame: entry a1,64; 16 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* immediates: 1, 0 */
    /* mem st32: base=(?) off=0 */
    /* mem st32: base=(?) off=4 */
    /* mem st32: base=(?) off=12 */
    /* mem st32: base=(?) off=16 */
    /* mem st32: base=(?) off=8 */
    /* site +0x26: esp_wifi_ipc_internal(?, 1) */
    esp_wifi_ipc_internal(?, 1);
    return last_call_result; /* opaque */
}

/* esp_wifi_internal_get_config_channel @ ieee80211_api.o 0x00000008 size 48B bind GLOBAL
 * Calls: esp_wifi_ipc_internal | Data refs: esp_wifi_get_config_channel_local
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 esp_wifi_internal_get_config_channel(u32 a2, u32 a3, u32 a4)
{
    /* frame: entry a1,64; 20 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0, 1 */
    /* mem st8: base=(?) off=4 */
    /* mem st32: base=(?) off=0 */
    /* mem st32: base=(?) off=8 */
    /* mem st32: base=(?) off=12 */
    /* mem st32: base=(?) off=16 */
    /* mem st32: base=(?) off=20 */
    /* mem st32: base=(?) off=24 */
    /* mem st32: base=(?) off=28 */
    /* site +0x31: esp_wifi_ipc_internal((?+20), 1) */
    esp_wifi_ipc_internal((?+20), 1);
    return last_call_result; /* opaque */
}

/* esp_wifi_internal_band_get_config_channel @ ieee80211_api.o 0x00000008 size 40B bind GLOBAL
 * Calls: esp_wifi_ipc_internal | Data refs: esp_wifi_band_get_config_channel_local
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 esp_wifi_internal_band_get_config_channel(u32 a2, u32 a3, u32 a4, u32 a5)
{
    /* frame: entry a1,64; 17 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* immediates: 1, 0 */
    /* mem st32: base=(?) off=16 */
    /* mem st32: base=(?) off=4 */
    /* mem st32: base=(?) off=0 */
    /* mem st32: base=(?) off=8 */
    /* mem st32: base=(?) off=12 */
    /* mem st32: base=(?) off=20 */
    /* mem st32: base=(?) off=24 */
    /* site +0x29: esp_wifi_ipc_internal((?+16), 1) */
    esp_wifi_ipc_internal((?+16), 1);
    return last_call_result; /* opaque */
}

/* esp_wifi_internal_issue_disconnect @ ieee80211_api.o 0x00000008 size 40B bind GLOBAL
 * Calls: esp_wifi_ipc_internal | Data refs: esp_wifi_send_deauth_local
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 esp_wifi_internal_issue_disconnect(u32 a2)
{
    /* frame: entry a1,64; 16 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* immediates: 1, 0 */
    /* mem st32: base=(?) off=0 */
    /* mem st32: base=(?) off=4 */
    /* mem st8: base=(?) off=16 */
    /* mem st32: base=(?) off=8 */
    /* site +0x29: esp_wifi_ipc_internal(?, 1) */
    esp_wifi_ipc_internal(?, 1);
    return last_call_result; /* opaque */
}

/* esp_wifi_improve_contention_ability @ ieee80211_api.o 0x00000004 size 19B bind GLOBAL
 * Calls: none | Data refs: g_wifi_improve_contention_ability
 * Fidelity: high - straight-line, fully mapped (7 insns) */
u32 esp_wifi_improve_contention_ability(u32 a2)
{
    /* frame: entry a1,32; 7 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0 */
    /* mem st8: base=(lit:g_wifi_improve_contention_ability) off=0 */
    return 0;
}

/* esp_wifi_internal_get_negotiated_channel @ ieee80211_api.o 0x00000008 size 46B bind GLOBAL
 * Calls: esp_wifi_ipc_internal | Data refs: esp_wifi_get_negotiated_channel_local
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 esp_wifi_internal_get_negotiated_channel(u32 a2, u32 a3, u32 a4, u32 a5)
{
    /* frame: entry a1,64; 19 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0, 1 */
    /* mem st32: base=(?) off=0 */
    /* mem st8: base=(?) off=4 */
    /* mem st32: base=(?) off=8 */
    /* mem st32: base=(?) off=12 */
    /* mem st32: base=(?) off=16 */
    /* mem st32: base=(?) off=20 */
    /* mem st32: base=(?) off=24 */
    /* mem st32: base=(?) off=28 */
    /* site +0x2f: esp_wifi_ipc_internal((?+20), 1) */
    esp_wifi_ipc_internal((?+20), 1);
    return last_call_result; /* opaque */
}

/* esp_wifi_internal_get_negotiated_bandwidth @ ieee80211_api.o 0x00000008 size 46B bind GLOBAL
 * Calls: esp_wifi_ipc_internal | Data refs: esp_wifi_get_negotiated_bw_local
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 esp_wifi_internal_get_negotiated_bandwidth(u32 a2, u32 a3, u32 a4)
{
    /* frame: entry a1,64; 19 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0, 1 */
    /* mem st32: base=(?) off=0 */
    /* mem st8: base=(?) off=4 */
    /* mem st32: base=(?) off=8 */
    /* mem st32: base=(?) off=12 */
    /* mem st32: base=(?) off=16 */
    /* mem st32: base=(?) off=20 */
    /* mem st32: base=(?) off=24 */
    /* mem st32: base=(?) off=28 */
    /* site +0x2f: esp_wifi_ipc_internal((?+20), 1) */
    esp_wifi_ipc_internal((?+20), 1);
    return last_call_result; /* opaque */
}

/* esp_wifi_ap_get_sta_aid @ ieee80211_api.o 0x00000008 size 59B bind GLOBAL
 * Calls: esp_wifi_ipc_internal | Data refs: esp_wifi_ap_get_sta_aid_local
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 esp_wifi_ap_get_sta_aid(u32 a2, u32 a3)
{
    /* frame: entry a1,64; 23 insns, 2 cond-branches, 0 loops, 1 jumps */
    /* immediates: 1, 0, 0x102 */
    /* first predicate: bnez.n a9, 3c <esp_wifi_ap_get_sta_aid+0x34> (condition opaque) */
    /* mem st32: base=(?) off=12 */
    /* mem st32: base=(?) off=0 */
    /* mem st32: base=(?) off=16 */
    /* mem st32: base=(?) off=4 */
    /* mem st32: base=(?) off=8 */
    /* site +0x35: esp_wifi_ipc_internal(?, 1) */
    esp_wifi_ipc_internal(?, 1);
    return 0x102;
}

/* esp_wifi_sta_get_aid @ ieee80211_api.o 0x00000008 size 32B bind GLOBAL
 * Calls: esp_wifi_ipc_internal | Data refs: esp_wifi_sta_get_aid_local
 * Fidelity: high - straight-line, fully mapped (13 insns) */
u32 esp_wifi_sta_get_aid(u32 a2)
{
    /* frame: entry a1,48; 13 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* immediates: 1, 0 */
    /* mem st32: base=(?) off=0 */
    /* mem st32: base=(?) off=4 */
    /* mem st32: base=(?) off=8 */
    /* site +0x21: esp_wifi_ipc_internal(?, 1) */
    esp_wifi_ipc_internal(?, 1);
    return last_call_result; /* opaque */
}

/* esp_wifi_sta_get_negotiated_phymode @ ieee80211_api.o 0x00000008 size 32B bind GLOBAL
 * Calls: esp_wifi_ipc_internal | Data refs: esp_wifi_sta_get_negotiated_phymode_local
 * Fidelity: high - straight-line, fully mapped (13 insns) */
u32 esp_wifi_sta_get_negotiated_phymode(u32 a2)
{
    /* frame: entry a1,48; 13 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* immediates: 1, 0 */
    /* mem st32: base=(?) off=0 */
    /* mem st32: base=(?) off=4 */
    /* mem st32: base=(?) off=8 */
    /* site +0x21: esp_wifi_ipc_internal(?, 1) */
    esp_wifi_ipc_internal(?, 1);
    return last_call_result; /* opaque */
}

/* esp_wifi_get_tsf_time @ ieee80211_api.o 0x00000018 size 140B bind GLOBAL
 * Calls: indirect(a10), memset, wifi_get_tsf_time_process, indirect(a4), ieee80211_ioctl | Data refs: g_ic, g_osi_funcs_p
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 esp_wifi_get_tsf_time(u32 a2, u32 a3)
{
    /* frame: entry a1,64; 54 insns, 3 cond-branches, 0 loops, 1 jumps */
    /* immediates: 0, 20, 24, 50 */
    /* first predicate: bltui a4, 2, a0 <esp_wifi_get_tsf_time+0x88> (condition opaque) */
    /* mem ld8: base=((lit:g_ic+65536)) off=237 */
    /* mem st32: base=(?) off=24 */
    /* mem st32: base=(?) off=28 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=28 */
    /* mem st32: base=(?) off=20 */
    /* mem st8: base=(?) off=8 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=0x178 */
    /* mem st8: base=(ret@6e) off=0 */
    /* ... +8 more memops */
    /* site +0x39: indirect call via a10 (base *(g_ic+28)); args: *(g_ic+28) */
    opaque_indirect_a10();
    /* site +0x49: memset(?, 0, 20) */
    memset(?, 0, 20);
    /* site +0x61: wifi_get_tsf_time_process(ret@49, 0, 20) */
    wifi_get_tsf_time_process(ret@49, 0, 20);
    /* site +0x6e: indirect call via a4 (base *(g_osi_funcs_p+0x178)); args: 24, 0, 20 */
    opaque_indirect_a4();
    /* site +0x99: ieee80211_ioctl(ret@6e, 0, 20) */
    ieee80211_ioctl(ret@6e, 0, 20);
    return *(?+24);
}

/* esp_wifi_set_tx_done_cb @ ieee80211_api.o 0x0000000c size 28B bind GLOBAL
 * Calls: wifi_init_completed, ic_register_pp_tx_done_cb | Data refs: none
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 esp_wifi_set_tx_done_cb(u32 a2)
{
    /* frame: entry a1,32; 11 insns, 1 cond-branches, 0 loops, 0 jumps */
    /* first predicate: beqz.n a10, 24 <esp_wifi_set_tx_done_cb+0x18> (condition opaque) */
    /* site +0x12: wifi_init_completed(/* no traced args */) */
    wifi_init_completed(/* no traced args */);
    /* site +0x1f: ic_register_pp_tx_done_cb(/* no traced args */) */
    ic_register_pp_tx_done_cb(/* no traced args */);
    return last_call_result; /* opaque */
}

/* esp_wifi_set_inactive_time @ ieee80211_api.o 0x00000018 size 78B bind GLOBAL
 * Calls: wifi_init_completed, esp_wifi_ipc_internal | Data refs: g_ic, esp_wifi_set_inactive_time_local
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 esp_wifi_set_inactive_time(u32 a2, u32 a3)
{
    /* frame: entry a1,80; 30 insns, 2 cond-branches, 0 loops, 0 jumps */
    /* immediates: 1, 0 */
    /* first predicate: beqz.n a10, 62 <esp_wifi_set_inactive_time+0x4a> (condition opaque) */
    /* mem st16: base=(?) off=32 */
    /* mem ld8: base=((lit:g_ic+65536)) off=237 */
    /* mem st32: base=(?) off=16 */
    /* mem st32: base=(?) off=0 */
    /* mem st32: base=(?) off=4 */
    /* mem st32: base=(?) off=8 */
    /* mem st32: base=(?) off=12 */
    /* site +0x27: wifi_init_completed(/* no traced args */) */
    wifi_init_completed(/* no traced args */);
    /* site +0x5d: esp_wifi_ipc_internal(?, 1) */
    esp_wifi_ipc_internal(?, 1);
    return last_call_result; /* opaque */
}

/* esp_wifi_get_inactive_time @ ieee80211_api.o 0x00000010 size 56B bind GLOBAL
 * Calls: wifi_init_completed, esp_wifi_ipc_internal | Data refs: esp_wifi_get_inactive_time_local
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 esp_wifi_get_inactive_time(u32 a2, u32 a3)
{
    /* frame: entry a1,64; 23 insns, 2 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0x102, 1, 0 */
    /* first predicate: beqz.n a10, 44 <esp_wifi_get_inactive_time+0x34> (condition opaque) */
    /* mem st32: base=(?) off=16 */
    /* mem st32: base=(?) off=0 */
    /* mem st32: base=(?) off=4 */
    /* mem st32: base=(?) off=12 */
    /* mem st32: base=(?) off=8 */
    /* site +0x16: wifi_init_completed(/* no traced args */) */
    wifi_init_completed(/* no traced args */);
    /* site +0x3f: esp_wifi_ipc_internal(?, 1) */
    esp_wifi_ipc_internal(?, 1);
    return last_call_result; /* opaque */
}

/* esp_wifi_statis_dump @ ieee80211_api.o 0x00000010 size 36B bind GLOBAL
 * Calls: wifi_init_completed, dbg_lmac_statis_dump, dbg_hmac_statis_dump | Data refs: none
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 esp_wifi_statis_dump(u32 a2)
{
    /* frame: entry a1,32; 14 insns, 1 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0 */
    /* first predicate: beqz.n a10, 30 <esp_wifi_statis_dump+0x20> (condition opaque) */
    /* site +0x16: wifi_init_completed(/* no traced args */) */
    wifi_init_completed(/* no traced args */);
    /* site +0x23: dbg_lmac_statis_dump(/* no traced args */) */
    dbg_lmac_statis_dump(/* no traced args */);
    /* site +0x2b: dbg_hmac_statis_dump(/* no traced args */) */
    dbg_hmac_statis_dump(/* no traced args */);
    return 0;
}

/* esp_wifi_internal_set_spp_amsdu @ ieee80211_api.o 0x0000000c size 93B bind GLOBAL
 * Calls: wifi_init_completed | Data refs: g_ic
 * Fidelity: medium - branchy but loop-free, call sequence mapped */
u32 esp_wifi_internal_set_spp_amsdu(u32 a2, u32 a3, u32 a4)
{
    /* frame: entry a1,32; 32 insns, 5 cond-branches, 0 loops, 1 jumps */
    /* immediates: 0x103, 0x102, 0 */
    /* first predicate: beqz a10, 62 <esp_wifi_internal_set_spp_amsdu+0x56> (condition opaque) */
    /* mem ld8: base=((lit:g_ic+65536)) off=237 */
    /* mem st16: base=((lit:g_ic+131072)) off=124 */
    /* mem st16: base=(((lit:g_ic+131072)+131072)) off=126 */
    /* site +0x12: wifi_init_completed(/* no traced args */) */
    wifi_init_completed(/* no traced args */);
    return 0;
}

/* esp_wifi_disable_pmf_config @ ieee80211_api.o 0x00000018 size 70B bind GLOBAL
 * Calls: wifi_init_completed, indirect(a8), ieee80211_ioctl | Data refs: g_osi_funcs_p, wifi_disable_pmf_config_process
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 esp_wifi_disable_pmf_config(u32 a2)
{
    /* frame: entry a1,32; 26 insns, 3 cond-branches, 0 loops, 0 jumps */
    /* immediates: 24, 0x101, 89 */
    /* first predicate: beqz.n a10, 5a <esp_wifi_disable_pmf_config+0x42> (condition opaque) */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=0x178 */
    /* mem st32: base=(ret@36) off=4 */
    /* mem st8: base=(ret@36) off=0 */
    /* mem st8: base=(ret@36) off=8 */
    /* site +0x1e: wifi_init_completed(/* no traced args */) */
    wifi_init_completed(/* no traced args */);
    /* site +0x36: indirect call via a8 (base *(g_osi_funcs_p+0x178)); args: 24 */
    opaque_indirect_a8();
    /* site +0x55: ieee80211_ioctl(ret@36) */
    ieee80211_ioctl(ret@36);
    return last_call_result; /* opaque */
}

/* esp_phy_apply_phy_init_data @ ieee80211_api.o 0x0000000c size 36B bind GLOBAL
 * Calls: chm_get_current_channel, register_chipv7_phy_init_param, chip_v7_set_chan_misc | Data refs: none
 * Fidelity: high - straight-line, fully mapped (13 insns) */
u32 esp_phy_apply_phy_init_data(u32 a2, u32 a3)
{
    /* frame: entry a1,32; 13 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0 */
    /* mem ld8: base=(?) off=0 */
    /* site +0x12: chm_get_current_channel(/* no traced args */) */
    chm_get_current_channel(/* no traced args */);
    /* site +0x1d: register_chipv7_phy_init_param(/* no traced args */) */
    register_chipv7_phy_init_param(/* no traced args */);
    /* site +0x2b: chip_v7_set_chan_misc(*(?+0)) */
    chip_v7_set_chan_misc(*(?+0));
    return 0;
}

/* esp_nan_internal_register_callbacks @ ieee80211_api.o 0x00000014 size 82B bind GLOBAL
 * Calls: wifi_init_completed, indirect(a8), ieee80211_ioctl | Data refs: g_osi_funcs_p, wifi_nan_config_process
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 esp_nan_internal_register_callbacks(u32 a2)
{
    /* frame: entry a1,32; 32 insns, 3 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0x102, 24, 0x101, 94, 0 */
    /* first predicate: beqz.n a10, 62 <esp_nan_internal_register_callbacks+0x4e> (condition opaque) */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=0x178 */
    /* mem st8: base=(ret@31) off=0 */
    /* mem st32: base=(ret@31) off=4 */
    /* mem st16: base=(ret@31) off=8 */
    /* mem st8: base=(ret@31) off=10 */
    /* mem st32: base=(ret@31) off=12 */
    /* mem st32: base=(ret@31) off=20 */
    /* site +0x1a: wifi_init_completed(/* no traced args */) */
    wifi_init_completed(/* no traced args */);
    /* site +0x31: indirect call via a8 (base *(g_osi_funcs_p+0x178)); args: 24 */
    opaque_indirect_a8();
    /* site +0x5d: ieee80211_ioctl(ret@31) */
    ieee80211_ioctl(ret@31);
    return last_call_result; /* opaque */
}

/* esp_nan_internal_publish_service @ ieee80211_api.o 0x00000014 size 100B bind GLOBAL
 * Calls: wifi_init_completed, indirect(a8), ieee80211_ioctl | Data refs: g_osi_funcs_p, wifi_nan_publish_process
 * Fidelity: medium - branchy but loop-free, call sequence mapped */
u32 esp_nan_internal_publish_service(u32 a2, u32 a3, u32 a4)
{
    /* frame: entry a1,32; 37 insns, 5 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0x102, 1, 24, 0x101, 95, 0 */
    /* first predicate: beqz a10, 74 <esp_nan_internal_publish_service+0x60> (condition opaque) */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=0x178 */
    /* mem st8: base=(ret@41) off=0 */
    /* mem st32: base=(ret@41) off=4 */
    /* mem st8: base=(ret@41) off=9 */
    /* mem st8: base=(ret@41) off=10 */
    /* mem st8: base=(ret@41) off=8 */
    /* mem st32: base=(ret@41) off=12 */
    /* mem st32: base=(ret@41) off=20 */
    /* site +0x1a: wifi_init_completed(/* no traced args */) */
    wifi_init_completed(/* no traced args */);
    /* site +0x41: indirect call via a8 (base *(g_osi_funcs_p+0x178)); args: 24 */
    opaque_indirect_a8();
    /* site +0x6f: ieee80211_ioctl(ret@41) */
    ieee80211_ioctl(ret@41);
    return last_call_result; /* opaque */
}

/* esp_nan_internal_subscribe_service @ ieee80211_api.o 0x00000014 size 100B bind GLOBAL
 * Calls: wifi_init_completed, indirect(a8), ieee80211_ioctl | Data refs: g_osi_funcs_p, wifi_nan_subscribe_process
 * Fidelity: medium - branchy but loop-free, call sequence mapped */
u32 esp_nan_internal_subscribe_service(u32 a2, u32 a3, u32 a4)
{
    /* frame: entry a1,32; 37 insns, 5 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0x102, 1, 24, 0x101, 96, 0 */
    /* first predicate: beqz a10, 74 <esp_nan_internal_subscribe_service+0x60> (condition opaque) */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=0x178 */
    /* mem st8: base=(ret@41) off=0 */
    /* mem st32: base=(ret@41) off=4 */
    /* mem st8: base=(ret@41) off=9 */
    /* mem st8: base=(ret@41) off=10 */
    /* mem st8: base=(ret@41) off=8 */
    /* mem st32: base=(ret@41) off=12 */
    /* mem st32: base=(ret@41) off=20 */
    /* site +0x1a: wifi_init_completed(/* no traced args */) */
    wifi_init_completed(/* no traced args */);
    /* site +0x41: indirect call via a8 (base *(g_osi_funcs_p+0x178)); args: 24 */
    opaque_indirect_a8();
    /* site +0x6f: ieee80211_ioctl(ret@41) */
    ieee80211_ioctl(ret@41);
    return last_call_result; /* opaque */
}

/* esp_nan_internal_send_followup @ ieee80211_api.o 0x00000018 size 134B bind GLOBAL
 * Calls: wifi_init_completed, memset, indirect(a2), ieee80211_ioctl | Data refs: g_osi_funcs_p, wifi_nan_followup_process
 * Fidelity: medium - branchy but loop-free, call sequence mapped */
u32 esp_nan_internal_send_followup(u32 a2, u32 a3, u32 a4)
{
    /* frame: entry a1,64; 51 insns, 4 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0x102, 20, 0, 24, 0x101, 97 */
    /* first predicate: beqz a10, 9a <esp_nan_internal_send_followup+0x82> (condition opaque) */
    /* mem st32: base=(?) off=0 */
    /* mem ld32: base=(?) off=0 */
    /* mem st32: base=(?) off=4 */
    /* mem ld32: base=(?) off=4 */
    /* mem st32: base=(?) off=8 */
    /* mem ld16: base=(?) off=8 */
    /* mem st16: base=(?) off=12 */
    /* mem ld32: base=(?) off=12 */
    /* mem st32: base=(?) off=16 */
    /* mem ld16: base=(?) off=16 */
    /* ... +9 more memops */
    /* site +0x1e: wifi_init_completed(/* no traced args */) */
    wifi_init_completed(/* no traced args */);
    /* site +0x37: memset((?+4), 0, 20) */
    memset((?+4), 0, 20);
    /* site +0x6a: indirect call via a2 (base *(g_osi_funcs_p+0x178)); args: 24, 0, 20 */
    opaque_indirect_a2();
    /* site +0x95: ieee80211_ioctl(ret@6a, 0, 20) */
    ieee80211_ioctl(ret@6a, 0, 20);
    return last_call_result; /* opaque */
}

/* esp_nan_internal_datapath_req @ ieee80211_api.o 0x00000018 size 106B bind GLOBAL
 * Calls: wifi_init_completed, indirect(a3), memcpy, ieee80211_ioctl | Data refs: g_osi_funcs_p, wifi_ndp_req_process
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 esp_nan_internal_datapath_req(u32 a2, u32 a3, u32 a4)
{
    /* frame: entry a1,48; 40 insns, 3 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0x102, 32, 0x101, 98, 8, 0 */
    /* first predicate: beqz a10, 7e <esp_nan_internal_datapath_req+0x66> (condition opaque) */
    /* mem st32: base=(?) off=0 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=0x178 */
    /* mem st32: base=(?) off=4 */
    /* mem st8: base=(ret@3f) off=0 */
    /* mem st32: base=(ret@3f) off=4 */
    /* mem st16: base=(ret@3f) off=8 */
    /* mem st8: base=(ret@3f) off=10 */
    /* mem st32: base=(ret@3f) off=12 */
    /* site +0x1e: wifi_init_completed(/* no traced args */) */
    wifi_init_completed(/* no traced args */);
    /* site +0x3f: indirect call via a3 (base *(g_osi_funcs_p+0x178)); args: 32 */
    opaque_indirect_a3();
    /* site +0x71: memcpy((ret@3f+20), ?, 8) */
    memcpy((ret@3f+20), ?, 8);
    /* site +0x79: ieee80211_ioctl(ret@3f, ?, 8) */
    ieee80211_ioctl(ret@3f, ?, 8);
    return last_call_result; /* opaque */
}

/* esp_nan_internal_datapath_resp @ ieee80211_api.o 0x00000014 size 82B bind GLOBAL
 * Calls: wifi_init_completed, indirect(a8), ieee80211_ioctl | Data refs: g_osi_funcs_p, wifi_ndp_resp_process
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 esp_nan_internal_datapath_resp(u32 a2, u32 a3)
{
    /* frame: entry a1,32; 31 insns, 3 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0x102, 24, 0x101, 99, 0 */
    /* first predicate: beqz.n a10, 62 <esp_nan_internal_datapath_resp+0x4e> (condition opaque) */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=0x178 */
    /* mem st8: base=(ret@32) off=0 */
    /* mem st32: base=(ret@32) off=4 */
    /* mem st16: base=(ret@32) off=8 */
    /* mem st8: base=(ret@32) off=10 */
    /* mem st32: base=(ret@32) off=12 */
    /* mem st32: base=(ret@32) off=20 */
    /* site +0x1a: wifi_init_completed(/* no traced args */) */
    wifi_init_completed(/* no traced args */);
    /* site +0x32: indirect call via a8 (base *(g_osi_funcs_p+0x178)); args: 24 */
    opaque_indirect_a8();
    /* site +0x5d: ieee80211_ioctl(ret@32) */
    ieee80211_ioctl(ret@32);
    return last_call_result; /* opaque */
}

/* esp_nan_internal_datapath_end @ ieee80211_api.o 0x00000014 size 84B bind GLOBAL
 * Calls: wifi_init_completed, indirect(a8), ieee80211_ioctl | Data refs: g_osi_funcs_p, wifi_ndp_end_process
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 esp_nan_internal_datapath_end(u32 a2)
{
    /* frame: entry a1,32; 32 insns, 3 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0x102, 24, 0x101, 100, 0 */
    /* first predicate: beqz a10, 64 <esp_nan_internal_datapath_end+0x50> (condition opaque) */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=0x178 */
    /* mem st8: base=(ret@32) off=0 */
    /* mem st32: base=(ret@32) off=4 */
    /* mem st16: base=(ret@32) off=8 */
    /* mem st8: base=(ret@32) off=10 */
    /* mem st32: base=(ret@32) off=12 */
    /* mem st32: base=(ret@32) off=20 */
    /* site +0x1a: wifi_init_completed(/* no traced args */) */
    wifi_init_completed(/* no traced args */);
    /* site +0x32: indirect call via a8 (base *(g_osi_funcs_p+0x178)); args: 24 */
    opaque_indirect_a8();
    /* site +0x5f: ieee80211_ioctl(ret@32) */
    ieee80211_ioctl(ret@32);
    return last_call_result; /* opaque */
}

/* esp_wifi_nan_set_params_internal @ ieee80211_api.o 0x00000008 size 32B bind GLOBAL
 * Calls: none | Data refs: s_ni
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 esp_wifi_nan_set_params_internal(u32 a2)
{
    /* frame: entry a1,32; 12 insns, 1 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0 */
    /* first predicate: beqz.n a10, 21 <esp_wifi_nan_set_params_internal+0x19> (condition opaque) */
    /* mem ld32: base=(lit:s_ni) off=0x140 */
    /* mem st8: base=((lit:s_ni+65536)) off=120 */
    return 0;
}

/* esp_wifi_nan_load_saved_creds @ ieee80211_api.o 0x00000044 size 341B bind GLOBAL
 * Calls: indirect(a5), memcpy, nan_key_is_all_ff_constprop_0, memcpy, memcpy, memcpy, nan_key_is_all_ff_constprop_0, memcpy, memcpy, memcpy, nan_key_is_all_ff_constprop_0, indirect(a4), wifi_log | Data refs: .rodata.esp_wifi_nan_load_saved_creds.str1.1, g_wifi_global_lock, g_osi_funcs_p, g_wifi_nvs, .rodata_wlog_info.63
 * Fidelity: low - 124 insns, 6 branches, 0 loops; skeleton only */
u32 esp_wifi_nan_load_saved_creds(u32 a2, u32 a3, u32 a4, u32 a5)
{
    /* frame: entry a1,48; 124 insns, 6 cond-branches, 0 loops, 1 jumps */
    /* immediates: 1, 0, 0x549, 16, 0x559, 0x569, 32, 0x589, 6, 0x58f */
    /* first predicate: bnez a5, 194 <esp_wifi_nan_load_saved_creds+0x150> (condition opaque) */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=84 */
    /* mem ld32: base=(lit:g_wifi_global_lock) off=0 */
    /* mem st32: base=(?) off=4 */
    /* mem st32: base=(?) off=8 */
    /* mem ld32: base=(lit:g_wifi_nvs) off=0 */
    /* mem ld32: base=(lit:g_wifi_nvs) off=0 */
    /* mem st8: base=(?) off=0 */
    /* mem ld32: base=(lit:g_wifi_nvs) off=0 */
    /* mem st8: base=(?) off=54 */
    /* ... +11 more memops */
    /* site +0x7f: indirect call via a5 (base *(*(g_osi_funcs_p+0)+84)); args: *(g_wifi_global_lock+0), lit:g_wifi_global_lock */
    opaque_indirect_a5();
    /* site +0x93: memcpy(ret@7f, *(g_wifi_nvs+0), 16) */
    memcpy(ret@7f, *(g_wifi_nvs+0), 16);
    /* site +0x9e: nan_key_is_all_ff_constprop_0(ret@93, *(g_wifi_nvs+0), 16) */
    nan_key_is_all_ff_constprop_0(ret@93, *(g_wifi_nvs+0), 16);
    /* site +0xb9: memcpy(?, 0x559, 16) */
    memcpy(?, 0x559, 16);
    /* site +0xcd: memcpy((?+16), 0x569, 32) */
    memcpy((?+16), 0x569, 32);
    /* site +0xdd: memcpy((?+48), 0x589, 6) */
    memcpy((?+48), 0x589, 6);
    /* site +0xe5: nan_key_is_all_ff_constprop_0(?, 0x589, 6) */
    nan_key_is_all_ff_constprop_0(?, 0x589, 6);
    /* site +0x106: memcpy((?+55), 0x58f, 16, ?, (?+55)) */
    memcpy((?+55), 0x58f, 16, ?, (?+55));
    /* site +0x121: memcpy((?+71), 0x59f, 32, ?, ret@106) */
    memcpy((?+71), 0x59f, 32, ?, ret@106);
    /* site +0x133: memcpy((?+103), 0x5bf, 6, ?, ret@106) */
    memcpy((?+103), 0x5bf, 6, ?, ret@106);
    /* site +0x13e: nan_key_is_all_ff_constprop_0(ret@133, 0x5bf, 6, ?, *(?+0)) */
    nan_key_is_all_ff_constprop_0(ret@133, 0x5bf, 6, ?, *(?+0));
    /* site +0x16d: indirect call via a4 (base *(*(g_osi_funcs_p+0)+88)); args: *(g_wifi_global_lock+0), 0x5bf, 6, ?, *(?+0) */
    opaque_indirect_a4();
    /* site +0x18d: wifi_log(1, 2, 3, lit:.rodata_wlog_info.63, lit:.rodata.esp_wifi_nan_load_saved_creds...) */
    wifi_log(1, 2, 3, lit:.rodata_wlog_info.63, lit:.rodata.esp_wifi_nan_load_saved_creds...);
    return 0x102;
}

/* esp_wifi_nan_save_creds_for_peer @ ieee80211_api.o 0x00000044 size 312B bind GLOBAL
 * Calls: indirect(a5), memcmp, nan_key_is_all_ff_constprop_0, memcmp, nan_key_is_all_ff_constprop_0, indirect(a2), wifi_log, memcpy, memcpy, memcpy, wifi_nvs_set, wifi_nvs_commit, indirect(a4), wifi_log | Data refs: g_wifi_global_lock, g_osi_funcs_p, g_wifi_nvs, .rodata_wlog_warning.64, g_ic, .rodata_wlog_info.65
 * Fidelity: low - 119 insns, 6 branches, 0 loops; skeleton only */
u32 esp_wifi_nan_save_creds_for_peer(u32 a2, u32 a3, u32 a4)
{
    /* frame: entry a1,48; 119 insns, 6 cond-branches, 0 loops, 3 jumps */
    /* immediates: 0, 1, 6, 0x559, 0x58f, 255, 2, 0x101, 16, 32 */
    /* first predicate: bnez a5, 177 <esp_wifi_nan_save_creds_for_peer+0x133> (condition opaque) */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=84 */
    /* mem ld32: base=(lit:g_wifi_global_lock) off=0 */
    /* mem ld32: base=(lit:g_wifi_nvs) off=0 */
    /* mem st32: base=(?) off=0 */
    /* mem ld32: base=(?) off=0 */
    /* mem ld32: base=(?) off=0 */
    /* mem st32: base=(?) off=8 */
    /* mem st32: base=(?) off=4 */
    /* mem ld32: base=(?) off=8 */
    /* ... +8 more memops */
    /* site +0x6f: indirect call via a5 (base *(*(g_osi_funcs_p+0)+84)); args: *(g_wifi_global_lock+0) */
    opaque_indirect_a5();
    /* site +0x8e: memcmp((0x559+48), ?, 6) */
    memcmp((0x559+48), ?, 6);
    /* site +0x99: nan_key_is_all_ff_constprop_0(0x559, ?, 6) */
    nan_key_is_all_ff_constprop_0(0x559, ?, 6);
    /* site +0xb9: memcmp((0x58f+48), ?, 6) */
    memcmp((0x58f+48), ?, 6);
    /* site +0xcd: nan_key_is_all_ff_constprop_0(*(?+8), ?, 6) */
    nan_key_is_all_ff_constprop_0(*(?+8), ?, 6);
    /* site +0xdf: indirect call via a2 (base *(*(g_osi_funcs_p+0)+88)); args: *(g_wifi_global_lock+0), ?, 6 */
    opaque_indirect_a2();
    /* site +0xee: wifi_log(1, 2, 2, lit:.rodata_wlog_warning.64) */
    wifi_log(1, 2, 2, lit:.rodata_wlog_warning.64);
    /* site +0x112: memcpy(1, 0x101, 16, lit:.rodata_wlog_warning.64) */
    memcpy(1, 0x101, 16, lit:.rodata_wlog_warning.64);
    /* site +0x11f: memcpy((1+16), lit:g_osi_funcs_p, 32, lit:.rodata_wlog_warning.64) */
    memcpy((1+16), lit:g_osi_funcs_p, 32, lit:.rodata_wlog_warning.64);
    /* site +0x12d: memcpy((1+48), ?, 6, lit:.rodata_wlog_warning.64) */
    memcpy((1+48), ?, 6, lit:.rodata_wlog_warning.64);
    /* site +0x149: wifi_nvs_set(60, lit:g_wifi_global_lock, 0, lit:.rodata_wlog_warning.64) */
    wifi_nvs_set(60, lit:g_wifi_global_lock, 0, lit:.rodata_wlog_warning.64);
    /* site +0x14f: wifi_nvs_commit(ret@149, lit:g_wifi_global_lock, 0, lit:.rodata_wlog_warning.64) */
    wifi_nvs_commit(ret@149, lit:g_wifi_global_lock, 0, lit:.rodata_wlog_warning.64);
    /* site +0x15f: indirect call via a4 (base *(*(g_osi_funcs_p+0)+88)); args: *(g_wifi_global_lock+0), lit:g_wifi_global_lock, 0, lit:.rodata_wlog_warning.64 */
    opaque_indirect_a4();
    /* site +0x171: wifi_log(ret@15f, 2, 3, lit:.rodata_wlog_info.65, 1) */
    wifi_log(ret@15f, 2, 3, lit:.rodata_wlog_info.65, 1);
    return 0x102;
}

/* esp_wifi_nan_erase_all_creds @ ieee80211_api.o 0x0000002c size 154B bind GLOBAL
 * Calls: indirect(a2), memset, memset, wifi_nvs_set, wifi_nvs_set, wifi_nvs_commit, indirect(a3), wifi_log | Data refs: g_wifi_global_lock, g_osi_funcs_p, g_wifi_nvs, g_ic, .rodata_wlog_info.66
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 esp_wifi_nan_erase_all_creds(u32 a3, u32 a4, u32 a5)
{
    /* frame: entry a1,32; 56 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0x559, 1, 16, 255, 0x549, 108, 0, 59, 60, 3 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=84 */
    /* mem ld32: base=(lit:g_wifi_global_lock) off=0 */
    /* mem ld32: base=(lit:g_wifi_nvs) off=0 */
    /* mem ld8: base=((lit:g_ic+131072)) off=31 */
    /* mem ld8: base=((lit:g_ic+131072)) off=31 */
    /* mem ld32: base=(lit:g_wifi_nvs) off=0 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=88 */
    /* mem ld32: base=(lit:g_wifi_global_lock) off=0 */
    /* site +0x42: indirect call via a2 (base *(*(g_osi_funcs_p+0)+84)); args: *(g_wifi_global_lock+0) */
    opaque_indirect_a2();
    /* site +0x5b: memset(ret@42, 255, 16) */
    memset(ret@42, 255, 16);
    /* site +0x6a: memset(ret@5b, 255, 108) */
    memset(ret@5b, 255, 108);
    /* site +0x86: wifi_nvs_set(59, 255, 0) */
    wifi_nvs_set(59, 255, 0);
    /* site +0x9e: wifi_nvs_set(60, *(g_wifi_nvs+0), 0) */
    wifi_nvs_set(60, *(g_wifi_nvs+0), 0);
    /* site +0xa4: wifi_nvs_commit(ret@9e, *(g_wifi_nvs+0), 0) */
    wifi_nvs_commit(ret@9e, *(g_wifi_nvs+0), 0);
    /* site +0xb2: indirect call via a3 (base *(g_wifi_nvs+88)); args: *(g_wifi_global_lock+0), *(g_wifi_nvs+0), 0 */
    opaque_indirect_a3();
    /* site +0xc1: wifi_log(1, 2, 3, lit:.rodata_wlog_info.66) */
    wifi_log(1, 2, 3, lit:.rodata_wlog_info.66);
    return opaque_result; /* full dataflow not recovered */
}

/* esp_wifi_nan_save_own_nik @ ieee80211_api.o 0x00000028 size 122B bind GLOBAL
 * Calls: esp_wifi_nan_erase_all_creds, indirect(a8), memcpy, wifi_nvs_set, wifi_nvs_commit, indirect(a5), wifi_log | Data refs: g_wifi_global_lock, g_osi_funcs_p, g_wifi_nvs, g_ic, .rodata_wlog_info.67
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 esp_wifi_nan_save_own_nik(u32 a2, u32 a3, u32 a5)
{
    /* frame: entry a1,32; 47 insns, 2 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0x102, 0x549, 16, 1, 59, 3, 2 */
    /* first predicate: beqz a4, a0 <esp_wifi_nan_save_own_nik+0x78> (condition opaque) */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(lit:g_wifi_global_lock) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=84 */
    /* mem ld32: base=(lit:g_wifi_nvs) off=0 */
    /* mem ld8: base=((lit:g_ic+131072)) off=31 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(lit:g_wifi_global_lock) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=88 */
    /* site +0x36: esp_wifi_nan_erase_all_creds(/* no traced args */) */
    esp_wifi_nan_erase_all_creds(/* no traced args */);
    /* site +0x4d: indirect call via a8 (base *(*(g_osi_funcs_p+0)+84)); args: *(g_wifi_global_lock+0) */
    opaque_indirect_a8();
    /* site +0x65: memcpy(*(g_wifi_nvs+0), ?, 16) */
    memcpy(*(g_wifi_nvs+0), ?, 16);
    /* site +0x7d: wifi_nvs_set(59, ret@65, ret@36) */
    wifi_nvs_set(59, ret@65, ret@36);
    /* site +0x83: wifi_nvs_commit(ret@7d, ret@65, ret@36) */
    wifi_nvs_commit(ret@7d, ret@65, ret@36);
    /* site +0x8e: indirect call via a5 (base *(g_osi_funcs_p+88)); args: *(g_wifi_global_lock+0), ret@65, ret@36 */
    opaque_indirect_a5();
    /* site +0x9d: wifi_log(1, 2, 3, lit:.rodata_wlog_info.67) */
    wifi_log(1, 2, 3, lit:.rodata_wlog_info.67);
    return opaque_result; /* full dataflow not recovered */
}

/* esp_wifi_mesh_reg_rxcb @ ieee80211_api.o 0x0000000c size 40B bind GLOBAL
 * Calls: indirect(a8), indirect(a4) | Data refs: g_wifi_global_lock, g_osi_funcs_p, mesh_rxcb
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 esp_wifi_mesh_reg_rxcb(u32 a2, u32 a3, u32 a4)
{
    /* frame: entry a1,32; 15 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(lit:g_wifi_global_lock) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=84 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=88 */
    /* mem ld32: base=(lit:g_wifi_global_lock) off=0 */
    /* mem st32: base=(lit:mesh_rxcb) off=0 */
    /* site +0x1d: indirect call via a8 (base *(*(g_osi_funcs_p+0)+84)); args: *(g_wifi_global_lock+0) */
    opaque_indirect_a8();
    /* site +0x2f: indirect call via a4 (base *(g_osi_funcs_p+88)); args: *(g_wifi_global_lock+0) */
    opaque_indirect_a4();
    return opaque_result; /* full dataflow not recovered */
}

/* esp_mesh_set_ap_assoc_expire @ ieee80211_api.o 0x0000001c size 94B bind GLOBAL
 * Calls: wifi_init_completed, indirect(a2), ieee80211_ioctl | Data refs: g_ic, g_osi_funcs_p, wifi_mesh_assoc_expire_set_progress
 * Fidelity: medium - branchy but loop-free, call sequence mapped */
u32 esp_mesh_set_ap_assoc_expire(u32 a2)
{
    /* frame: entry a1,32; 34 insns, 4 cond-branches, 0 loops, 0 jumps */
    /* immediates: 9, 0x102, 24, 0, 61 */
    /* first predicate: beqz a10, 78 <esp_mesh_set_ap_assoc_expire+0x5c> (condition opaque) */
    /* mem ld8: base=((lit:g_ic+65536)) off=237 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=0x178 */
    /* mem st8: base=(ret@4f) off=0 */
    /* mem st16: base=(ret@4f) off=8 */
    /* mem st32: base=(ret@4f) off=4 */
    /* mem st8: base=(ret@4f) off=10 */
    /* mem st32: base=(ret@4f) off=12 */
    /* site +0x22: wifi_init_completed(/* no traced args */) */
    wifi_init_completed(/* no traced args */);
    /* site +0x4f: indirect call via a2 (base *(g_osi_funcs_p+0x178)); args: 24 */
    opaque_indirect_a2();
    /* site +0x75: ieee80211_ioctl(ret@4f) */
    ieee80211_ioctl(ret@4f);
    return opaque_result; /* full dataflow not recovered */
}

/* esp_mesh_get_ap_assoc_expire @ ieee80211_api.o 0x00000004 size 10B bind GLOBAL
 * Calls: none | Data refs: map_assoc_expire
 * Fidelity: high - straight-line, fully mapped (4 insns) */
u32 esp_mesh_get_ap_assoc_expire(void)
{
    /* frame: entry a1,32; 4 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* mem ld32: base=(lit:map_assoc_expire) off=0 */
    return opaque_result; /* full dataflow not recovered */
}

/* esp_mesh_set_router_bssid @ ieee80211_api.o 0x00000014 size 78B bind GLOBAL
 * Calls: wifi_init_completed, indirect(a8), ieee80211_ioctl | Data refs: g_osi_funcs_p, wifi_mesh_router_bssid_set_progress
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 esp_mesh_set_router_bssid(u32 a2)
{
    /* frame: entry a1,32; 30 insns, 3 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0x102, 24, 0x101, 62, 0 */
    /* first predicate: beqz.n a10, 5e <esp_mesh_set_router_bssid+0x4a> (condition opaque) */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=0x178 */
    /* mem st8: base=(ret@31) off=0 */
    /* mem st32: base=(ret@31) off=4 */
    /* mem st16: base=(ret@31) off=8 */
    /* mem st8: base=(ret@31) off=10 */
    /* mem st32: base=(ret@31) off=12 */
    /* site +0x1a: wifi_init_completed(/* no traced args */) */
    wifi_init_completed(/* no traced args */);
    /* site +0x31: indirect call via a8 (base *(g_osi_funcs_p+0x178)); args: 24 */
    opaque_indirect_a8();
    /* site +0x59: ieee80211_ioctl(ret@31) */
    ieee80211_ioctl(ret@31);
    return last_call_result; /* opaque */
}

/* esp_mesh_get_router_bssid @ ieee80211_api.o 0x00000014 size 78B bind GLOBAL
 * Calls: wifi_init_completed, indirect(a8), ieee80211_ioctl | Data refs: g_osi_funcs_p, wifi_mesh_router_bssid_get_progress
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 esp_mesh_get_router_bssid(u32 a2)
{
    /* frame: entry a1,32; 30 insns, 3 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0x102, 24, 0x101, 63, 0 */
    /* first predicate: beqz.n a10, 5e <esp_mesh_get_router_bssid+0x4a> (condition opaque) */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=0x178 */
    /* mem st8: base=(ret@31) off=0 */
    /* mem st32: base=(ret@31) off=4 */
    /* mem st16: base=(ret@31) off=8 */
    /* mem st8: base=(ret@31) off=10 */
    /* mem st32: base=(ret@31) off=12 */
    /* site +0x1a: wifi_init_completed(/* no traced args */) */
    wifi_init_completed(/* no traced args */);
    /* site +0x31: indirect call via a8 (base *(g_osi_funcs_p+0x178)); args: 24 */
    opaque_indirect_a8();
    /* site +0x59: ieee80211_ioctl(ret@31) */
    ieee80211_ioctl(ret@31);
    return last_call_result; /* opaque */
}

/* esp_wifi_get_beacon_interval @ ieee80211_api.o 0x00000014 size 67B bind GLOBAL
 * Calls: wifi_init_completed, wifi_nvs_get | Data refs: g_ic
 * Fidelity: medium - branchy but loop-free, call sequence mapped */
u32 esp_wifi_get_beacon_interval(u32 a2)
{
    /* frame: entry a1,32; 23 insns, 4 cond-branches, 0 loops, 1 jumps */
    /* immediates: 0x102, 0 */
    /* first predicate: beqz.n a10, 50 <esp_wifi_get_beacon_interval+0x3c> (condition opaque) */
    /* mem ld8: base=((lit:g_ic+65536)) off=237 */
    /* mem ld16: base=((ret@40+196608)) off=248 */
    /* mem st32: base=(?) off=0 */
    /* site +0x1a: wifi_init_completed(/* no traced args */) */
    wifi_init_completed(/* no traced args */);
    /* site +0x40: wifi_nvs_get(ret@1a) */
    wifi_nvs_get(ret@1a);
    return 0;
}

/* esp_wifi_set_beacon_interval @ ieee80211_api.o 0x00000024 size 120B bind GLOBAL
 * Calls: wifi_init_completed, wifi_nvs_get, indirect(a8), ieee80211_ioctl | Data refs: g_ic, g_osi_funcs_p, wifi_mesh_set_beacon_interval_progress
 * Fidelity: medium - branchy but loop-free, call sequence mapped */
u32 esp_wifi_set_beacon_interval(u32 a2)
{
    /* frame: entry a1,32; 44 insns, 6 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0x102, 0, 24, 0x101, 60 */
    /* first predicate: beqz a10, 98 <esp_wifi_set_beacon_interval+0x74> (condition opaque) */
    /* mem ld8: base=((lit:g_ic+65536)) off=237 */
    /* mem ld16: base=((ret@51+196608)) off=248 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=0x178 */
    /* mem st8: base=(ret@6b) off=0 */
    /* mem st32: base=(ret@6b) off=4 */
    /* mem st16: base=(ret@6b) off=8 */
    /* mem st8: base=(ret@6b) off=10 */
    /* mem st32: base=(ret@6b) off=12 */
    /* site +0x2a: wifi_init_completed(/* no traced args */) */
    wifi_init_completed(/* no traced args */);
    /* site +0x51: wifi_nvs_get(literal) */
    wifi_nvs_get(literal);
    /* site +0x6b: indirect call via a8 (base *(g_osi_funcs_p+0x178)); args: 24 */
    opaque_indirect_a8();
    /* site +0x93: ieee80211_ioctl(ret@6b) */
    ieee80211_ioctl(ret@6b);
    return last_call_result; /* opaque */
}

/* esp_mesh_map_deauth @ ieee80211_api.o 0x00000024 size 108B bind GLOBAL
 * Calls: wifi_init_completed, memcpy, indirect(a2), ieee80211_ioctl | Data refs: g_ic, ieee80211_ethbroadcast, g_osi_funcs_p, wifi_ap_remove_sta_node_process
 * Fidelity: medium - branchy but loop-free, call sequence mapped */
u32 esp_mesh_map_deauth(u32 a2, u32 a3)
{
    /* frame: entry a1,48; 40 insns, 4 cond-branches, 0 loops, 0 jumps */
    /* immediates: 6, 24, 0x101, 93, 0 */
    /* first predicate: beqz a10, 8c <esp_mesh_map_deauth+0x68> (condition opaque) */
    /* mem ld8: base=((lit:g_ic+65536)) off=237 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=0x178 */
    /* mem st8: base=(ret@5e) off=0 */
    /* mem st32: base=(ret@5e) off=4 */
    /* mem st16: base=(ret@5e) off=8 */
    /* mem st8: base=(ret@5e) off=10 */
    /* mem st32: base=(ret@5e) off=12 */
    /* site +0x2a: wifi_init_completed(/* no traced args */) */
    wifi_init_completed(/* no traced args */);
    /* site +0x51: memcpy(?, lit:ieee80211_ethbroadcast, 6) */
    memcpy(?, lit:ieee80211_ethbroadcast, 6);
    /* site +0x5e: indirect call via a2 (base *(g_osi_funcs_p+0x178)); args: 24, lit:ieee80211_ethbroadcast, 6 */
    opaque_indirect_a2();
    /* site +0x87: ieee80211_ioctl(ret@5e, lit:ieee80211_ethbroadcast, 6) */
    ieee80211_ioctl(ret@5e, lit:ieee80211_ethbroadcast, 6);
    return last_call_result; /* opaque */
}

/* esp_mesh_sta_disassoc @ ieee80211_api.o 0x0000001c size 76B bind GLOBAL
 * Calls: wifi_init_completed, indirect(a2), ieee80211_ioctl | Data refs: g_ic, g_osi_funcs_p, wifi_mesh_sta_disassoc_progress
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 esp_mesh_sta_disassoc(u32 a2)
{
    /* frame: entry a1,32; 27 insns, 3 cond-branches, 0 loops, 0 jumps */
    /* immediates: 24, 0x101, 59 */
    /* first predicate: beqz.n a10, 66 <esp_mesh_sta_disassoc+0x4a> (condition opaque) */
    /* mem ld8: base=((lit:g_ic+65536)) off=237 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=0x178 */
    /* mem st32: base=(ret@45) off=4 */
    /* mem st8: base=(ret@45) off=0 */
    /* site +0x22: wifi_init_completed(/* no traced args */) */
    wifi_init_completed(/* no traced args */);
    /* site +0x45: indirect call via a2 (base *(g_osi_funcs_p+0x178)); args: 24 */
    opaque_indirect_a2();
    /* site +0x61: ieee80211_ioctl(ret@45) */
    ieee80211_ioctl(ret@45);
    return last_call_result; /* opaque */
}

/* esp_wifi_scan_get_cur_ap_info @ ieee80211_api.o 0x00000018 size 210B bind GLOBAL
 * Calls: wifi_init_completed, indirect(a8), indirect(a2), indirect(a6) | Data refs: g_ic, g_wifi_global_lock, g_osi_funcs_p
 * Fidelity: medium - branchy but loop-free, call sequence mapped (verified: section R_XTENSA_ASM_EXPAND + funcdb v3 agree; predicates opaque) */
u32 esp_wifi_scan_get_cur_ap_info(u32 a3, u32 a4, u32 a6)
{
    /* frame: entry a1,32; 81 insns, 21 cond-branches, 0 loops, 12 jumps */
    /* immediates: 0, -1, 9, 24, 58, 62, 13 */
    /* first predicate: beqz a10, e6 <esp_wifi_scan_get_cur_ap_info+0xce> (condition opaque) */
    /* mem ld8: base=((lit:g_ic+65536)) off=237 */
    /* mem st32: base=(?) off=0 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(lit:g_wifi_global_lock) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=84 */
    /* mem ld32: base=(lit:g_ic) off=0x130 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=88 */
    /* mem ld32: base=(lit:g_wifi_global_lock) off=0 */
    /* mem ld32: base=(lit:g_wifi_global_lock) off=0 */
    /* ... +10 more memops */
    /* site +0x1e: wifi_init_completed(/* no traced args */) */
    wifi_init_completed(/* no traced args */);
    /* site +0x52: indirect call via a8 (base *(*(g_osi_funcs_p+0)+84)); args: *(g_wifi_global_lock+0) */
    opaque_indirect_a8();
    /* site +0x61: indirect call via a2 (base *(*(g_osi_funcs_p+0)+88)); args: *(g_wifi_global_lock+0) */
    opaque_indirect_a2();
    /* site +0x71: indirect call via a6 (base *(-1+88)); args: *(g_wifi_global_lock+0) */
    opaque_indirect_a6();
    return 0;
}

/* esp_mesh_scan_get_ap_ie_len @ ieee80211_api.o 0x00000008 size 29B bind GLOBAL
 * Calls: esp_wifi_scan_get_cur_ap_info | Data refs: g_mesh_topology
 * Fidelity: high - straight-line, fully mapped (12 insns) */
u32 esp_mesh_scan_get_ap_ie_len(u32 a2)
{
    /* frame: entry a1,32; 12 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* immediates: 1, 16 */
    /* mem ld32: base=(lit:g_mesh_topology) off=0 */
    /* site +0x1e: esp_wifi_scan_get_cur_ap_info(16) */
    esp_wifi_scan_get_cur_ap_info(16);
    return last_call_result; /* opaque */
}

/* esp_wifi_scan_get_cur_ap_record @ ieee80211_api.o 0x00000038 size 316B bind GLOBAL
 * Calls: wifi_init_completed, indirect(a5), indirect(a2), memset, memcpy, memcpy, memcpy, memcpy, memcpy, free_bss_info, indirect(a2) | Data refs: g_ic, g_wifi_global_lock, g_osi_funcs_p, g_ic+0x130
 * Fidelity: low - 122 insns, 23 branches, 0 loops; skeleton only */
u32 esp_wifi_scan_get_cur_ap_record(u32 a3, u32 a4, u32 a7)
{
    /* frame: entry a1,48; 122 insns, 23 cond-branches, 0 loops, 8 jumps */
    /* immediates: -1, 92, 0, 6, 9, 24, 58, 62, 13 */
    /* first predicate: beqz a10, 170 <esp_wifi_scan_get_cur_ap_record+0x138> (condition opaque) */
    /* mem ld8: base=((lit:g_ic+65536)) off=237 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(lit:g_wifi_global_lock) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=84 */
    /* mem st32: base=(?) off=0 */
    /* mem ld32: base=(?) off=0 */
    /* mem ld32: base=(*(?+0)) off=0x130 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=88 */
    /* mem ld32: base=(lit:g_wifi_global_lock) off=0 */
    /* ... +22 more memops */
    /* site +0x3e: wifi_init_completed(/* no traced args */) */
    wifi_init_completed(/* no traced args */);
    /* site +0x6b: indirect call via a5 (base *(*(g_osi_funcs_p+0)+84)); args: *(g_wifi_global_lock+0) */
    opaque_indirect_a5();
    /* site +0x7e: indirect call via a2 (base *(*(g_osi_funcs_p+0)+88)); args: *(g_wifi_global_lock+0) */
    opaque_indirect_a2();
    /* site +0xa1: memset(?, 0, 92) */
    memset(?, 0, 92);
    /* site +0xae: memcpy((?+6), (-1+10), *(-1+42)) */
    memcpy((?+6), (-1+10), *(-1+42));
    /* site +0xba: memcpy(?, (-1+4), 6) */
    memcpy(?, (-1+4), 6);
    /* site +0x12d: memcpy(?, *(-1+52), 58) */
    memcpy(?, *(-1+52), 58);
    /* site +0x149: memcpy(?, *(-1+52), 62) */
    memcpy(?, *(-1+52), 62);
    /* site +0x158: memcpy((?+62), *(-1+56), 13) */
    memcpy((?+62), *(-1+56), 13);
    /* site +0x160: free_bss_info(-1, *(-1+56), 13) */
    free_bss_info(-1, *(-1+56), 13);
    /* site +0x16d: indirect call via a2 (base *(*(g_osi_funcs_p+0)+88)); args: *(g_wifi_global_lock+0), *(-1+56), 13 */
    opaque_indirect_a2();
    return 0;
}

/* esp_mesh_scan_get_ap_record @ ieee80211_api.o 0x00000008 size 32B bind GLOBAL
 * Calls: esp_wifi_scan_get_cur_ap_record | Data refs: g_mesh_topology
 * Fidelity: high - straight-line, fully mapped (13 insns) */
u32 esp_mesh_scan_get_ap_record(u32 a2, u32 a3)
{
    /* frame: entry a1,32; 13 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* immediates: 1, 16 */
    /* mem ld32: base=(lit:g_mesh_topology) off=0 */
    /* site +0x21: esp_wifi_scan_get_cur_ap_record(*(g_mesh_topology+0)) */
    esp_wifi_scan_get_cur_ap_record(*(g_mesh_topology+0));
    return last_call_result; /* opaque */
}

/* esp_wifi_vnd_mesh_init @ ieee80211_api.o 0x0000001c size 120B bind GLOBAL
 * Calls: wifi_init_completed, indirect(a8), ieee80211_ioctl | Data refs: g_ic, g_osi_funcs_p, wifi_mesh_ie_init_progress
 * Fidelity: medium - branchy but loop-free, call sequence mapped */
u32 esp_wifi_vnd_mesh_init(u32 a2, u32 a3, u32 a4, u32 a5)
{
    /* frame: entry a1,32; 44 insns, 5 cond-branches, 0 loops, 1 jumps */
    /* immediates: 1, 0, 24, 0x101, 55, 0x102 */
    /* first predicate: beqz a10, 90 <esp_wifi_vnd_mesh_init+0x74> (condition opaque) */
    /* mem ld8: base=((lit:g_ic+65536)) off=237 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=0x178 */
    /* mem st8: base=(ret@5a) off=0 */
    /* mem st8: base=(ret@5a) off=8 */
    /* mem st32: base=(ret@5a) off=4 */
    /* mem st8: base=(ret@5a) off=9 */
    /* mem st8: base=(ret@5a) off=10 */
    /* mem st32: base=(ret@5a) off=12 */
    /* mem st32: base=(ret@5a) off=20 */
    /* site +0x22: wifi_init_completed(/* no traced args */) */
    wifi_init_completed(/* no traced args */);
    /* site +0x5a: indirect call via a8 (base *(g_osi_funcs_p+0x178)); args: 24 */
    opaque_indirect_a8();
    /* site +0x85: ieee80211_ioctl(ret@5a) */
    ieee80211_ioctl(ret@5a);
    return 0x102;
}

/* esp_wifi_vnd_mesh_deinit @ ieee80211_api.o 0x0000001c size 94B bind GLOBAL
 * Calls: wifi_init_completed, indirect(a8), ieee80211_ioctl | Data refs: g_ic, g_osi_funcs_p, wifi_mesh_ie_deinit_progress
 * Fidelity: medium - branchy but loop-free, call sequence mapped */
u32 esp_wifi_vnd_mesh_deinit(u32 a2)
{
    /* frame: entry a1,32; 35 insns, 4 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0x102, 24, 0x101, 56, 0 */
    /* first predicate: beqz a10, 76 <esp_wifi_vnd_mesh_deinit+0x5a> (condition opaque) */
    /* mem ld8: base=((lit:g_ic+65536)) off=237 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=0x178 */
    /* mem st8: base=(ret@49) off=0 */
    /* mem st32: base=(ret@49) off=4 */
    /* mem st16: base=(ret@49) off=8 */
    /* mem st8: base=(ret@49) off=10 */
    /* mem st32: base=(ret@49) off=12 */
    /* site +0x22: wifi_init_completed(/* no traced args */) */
    wifi_init_completed(/* no traced args */);
    /* site +0x49: indirect call via a8 (base *(g_osi_funcs_p+0x178)); args: 24 */
    opaque_indirect_a8();
    /* site +0x71: ieee80211_ioctl(ret@49) */
    ieee80211_ioctl(ret@49);
    return last_call_result; /* opaque */
}

/* esp_wifi_vnd_mesh_set @ ieee80211_api.o 0x0000001c size 104B bind GLOBAL
 * Calls: wifi_init_completed, indirect(a8), ieee80211_ioctl | Data refs: g_ic, g_osi_funcs_p, wifi_mesh_ie_set_progress
 * Fidelity: medium - branchy but loop-free, call sequence mapped */
u32 esp_wifi_vnd_mesh_set(u32 a2, u32 a3)
{
    /* frame: entry a1,32; 39 insns, 5 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0x102, -1, 24, 0x101, 53, 0 */
    /* first predicate: beqz a10, 80 <esp_wifi_vnd_mesh_set+0x64> (condition opaque) */
    /* mem ld8: base=((lit:g_ic+65536)) off=237 */
    /* mem ld32: base=(lit:g_ic) off=116 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=0x178 */
    /* mem st8: base=(ret@51) off=0 */
    /* mem st32: base=(ret@51) off=4 */
    /* mem st16: base=(ret@51) off=8 */
    /* mem st8: base=(ret@51) off=10 */
    /* mem st32: base=(ret@51) off=12 */
    /* mem st32: base=(ret@51) off=20 */
    /* site +0x22: wifi_init_completed(/* no traced args */) */
    wifi_init_completed(/* no traced args */);
    /* site +0x51: indirect call via a8 (base *(g_osi_funcs_p+0x178)); args: 24 */
    opaque_indirect_a8();
    /* site +0x7b: ieee80211_ioctl(ret@51) */
    ieee80211_ioctl(ret@51);
    return last_call_result; /* opaque */
}

/* esp_wifi_vnd_mesh_get @ ieee80211_api.o 0x00000024 size 134B bind GLOBAL
 * Calls: wifi_init_completed, memset, memset, indirect(a8), ieee80211_ioctl | Data refs: g_ic, g_osi_funcs_p, wifi_mesh_ie_get_progress
 * Fidelity: medium - branchy but loop-free, call sequence mapped */
u32 esp_wifi_vnd_mesh_get(u32 a2, u32 a3, u32 a6)
{
    /* frame: entry a1,32; 50 insns, 6 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0x102, -1, 58, 0, 4, 24, 0x101, 54 */
    /* first predicate: beqz a10, a6 <esp_wifi_vnd_mesh_get+0x82> (condition opaque) */
    /* mem ld8: base=((lit:g_ic+65536)) off=237 */
    /* mem ld32: base=(lit:g_ic) off=116 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=0x178 */
    /* mem st8: base=(ret@76) off=0 */
    /* mem st32: base=(ret@76) off=4 */
    /* mem st16: base=(ret@76) off=8 */
    /* mem st8: base=(ret@76) off=10 */
    /* mem st32: base=(ret@76) off=12 */
    /* mem st32: base=(ret@76) off=20 */
    /* site +0x2a: wifi_init_completed(/* no traced args */) */
    wifi_init_completed(/* no traced args */);
    /* site +0x5b: memset(*((lit:g_ic+65536)+237), 0, 58) */
    memset(*((lit:g_ic+65536)+237), 0, 58);
    /* site +0x69: memset(?, 0, 4) */
    memset(?, 0, 4);
    /* site +0x76: indirect call via a8 (base *(g_osi_funcs_p+0x178)); args: 24, 0, 4 */
    opaque_indirect_a8();
    /* site +0xa1: ieee80211_ioctl(ret@76, 0, 4) */
    ieee80211_ioctl(ret@76, 0, 4);
    return last_call_result; /* opaque */
}

/* esp_wifi_vnd_roots_set @ ieee80211_api.o 0x0000001c size 94B bind GLOBAL
 * Calls: wifi_init_completed, indirect(a8), ieee80211_ioctl | Data refs: g_ic, g_osi_funcs_p, wifi_mesh_roots_ie_set_progress
 * Fidelity: medium - branchy but loop-free, call sequence mapped */
u32 esp_wifi_vnd_roots_set(u32 a2)
{
    /* frame: entry a1,32; 35 insns, 4 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0x102, 24, 0x101, 64, 0 */
    /* first predicate: beqz a10, 76 <esp_wifi_vnd_roots_set+0x5a> (condition opaque) */
    /* mem ld8: base=((lit:g_ic+65536)) off=237 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=0x178 */
    /* mem st8: base=(ret@49) off=0 */
    /* mem st32: base=(ret@49) off=4 */
    /* mem st16: base=(ret@49) off=8 */
    /* mem st8: base=(ret@49) off=10 */
    /* mem st32: base=(ret@49) off=12 */
    /* site +0x22: wifi_init_completed(/* no traced args */) */
    wifi_init_completed(/* no traced args */);
    /* site +0x49: indirect call via a8 (base *(g_osi_funcs_p+0x178)); args: 24 */
    opaque_indirect_a8();
    /* site +0x71: ieee80211_ioctl(ret@49) */
    ieee80211_ioctl(ret@49);
    return last_call_result; /* opaque */
}

/* esp_wifi_vnd_roots_get @ ieee80211_api.o 0x0000001c size 94B bind GLOBAL
 * Calls: wifi_init_completed, indirect(a8), ieee80211_ioctl | Data refs: g_ic, g_osi_funcs_p, wifi_mesh_roots_ie_get_progress
 * Fidelity: medium - branchy but loop-free, call sequence mapped */
u32 esp_wifi_vnd_roots_get(u32 a2)
{
    /* frame: entry a1,32; 35 insns, 4 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0x102, 24, 0x101, 65, 0 */
    /* first predicate: beqz a10, 76 <esp_wifi_vnd_roots_get+0x5a> (condition opaque) */
    /* mem ld8: base=((lit:g_ic+65536)) off=237 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=0x178 */
    /* mem st8: base=(ret@49) off=0 */
    /* mem st32: base=(ret@49) off=4 */
    /* mem st16: base=(ret@49) off=8 */
    /* mem st8: base=(ret@49) off=10 */
    /* mem st32: base=(ret@49) off=12 */
    /* site +0x22: wifi_init_completed(/* no traced args */) */
    wifi_init_completed(/* no traced args */);
    /* site +0x49: indirect call via a8 (base *(g_osi_funcs_p+0x178)); args: 24 */
    opaque_indirect_a8();
    /* site +0x71: ieee80211_ioctl(ret@49) */
    ieee80211_ioctl(ret@49);
    return last_call_result; /* opaque */
}

/* esp_mesh_allow_root_conflicts @ ieee80211_api.o 0x00000018 size 108B bind GLOBAL
 * Calls: wifi_init_completed, indirect(a2), ieee80211_ioctl, indirect(a2), ieee80211_ioctl | Data refs: g_osi_funcs_p, wifi_mesh_root_conflicts_set_progress
 * Fidelity: medium - branchy but loop-free, call sequence mapped */
u32 esp_mesh_allow_root_conflicts(u32 a2)
{
    /* frame: entry a1,32; 39 insns, 4 cond-branches, 0 loops, 2 jumps */
    /* immediates: 24, 66, 1, 0 */
    /* first predicate: beqz a10, 82 <esp_mesh_allow_root_conflicts+0x6a> (condition opaque) */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=0x178 */
    /* mem st32: base=(ret@36) off=4 */
    /* mem st8: base=(ret@36) off=0 */
    /* mem st8: base=(ret@36) off=8 */
    /* mem st32: base=(ret@61) off=4 */
    /* mem st8: base=(ret@61) off=0 */
    /* mem st8: base=(ret@61) off=8 */
    /* site +0x1e: wifi_init_completed(/* no traced args */) */
    wifi_init_completed(/* no traced args */);
    /* site +0x36: indirect call via a2 (base *(g_osi_funcs_p+0x178)); args: 24 */
    opaque_indirect_a2();
    /* site +0x59: ieee80211_ioctl(ret@36) */
    ieee80211_ioctl(ret@36);
    /* site +0x61: indirect call via a2 (base 0); args: ret@59 */
    opaque_indirect_a2();
    /* site +0x7f: ieee80211_ioctl(ret@61) */
    ieee80211_ioctl(ret@61);
    return opaque_result; /* full dataflow not recovered */
}

/* esp_mesh_is_root_conflicts_allowed @ ieee80211_api.o 0x00000004 size 11B bind GLOBAL
 * Calls: none | Data refs: g_mesh_root_conflicts_allowed
 * Fidelity: high - straight-line, fully mapped (4 insns) */
u32 esp_mesh_is_root_conflicts_allowed(void)
{
    /* frame: entry a1,32; 4 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* mem ld8: base=(lit:g_mesh_root_conflicts_allowed) off=0 */
    return opaque_result; /* full dataflow not recovered */
}

/* esp_mesh_set_parent_monitor_config @ ieee80211_api.o 0x00000014 size 78B bind GLOBAL
 * Calls: wifi_init_completed, indirect(a8), ieee80211_ioctl | Data refs: g_osi_funcs_p, wifi_mesh_parent_monitor_set_progress
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 esp_mesh_set_parent_monitor_config(u32 a2)
{
    /* frame: entry a1,32; 30 insns, 3 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0x102, 24, 0x101, 67, 0 */
    /* first predicate: beqz.n a10, 5e <esp_mesh_set_parent_monitor_config+0x4a> (condition opaque) */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=0x178 */
    /* mem st8: base=(ret@31) off=0 */
    /* mem st32: base=(ret@31) off=4 */
    /* mem st16: base=(ret@31) off=8 */
    /* mem st8: base=(ret@31) off=10 */
    /* mem st32: base=(ret@31) off=12 */
    /* site +0x1a: wifi_init_completed(/* no traced args */) */
    wifi_init_completed(/* no traced args */);
    /* site +0x31: indirect call via a8 (base *(g_osi_funcs_p+0x178)); args: 24 */
    opaque_indirect_a8();
    /* site +0x59: ieee80211_ioctl(ret@31) */
    ieee80211_ioctl(ret@31);
    return last_call_result; /* opaque */
}

/* esp_mesh_get_parent_monitor_config @ ieee80211_api.o 0x00000014 size 94B bind GLOBAL
 * Calls: wifi_init_completed, indirect(a8), ieee80211_ioctl | Data refs: g_osi_funcs_p, wifi_mesh_parent_monitor_get_progress
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 esp_mesh_get_parent_monitor_config(u32 a2)
{
    /* frame: entry a1,32; 35 insns, 3 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0x102, 0, 24, 0x101, 68 */
    /* first predicate: beqz a10, 6e <esp_mesh_get_parent_monitor_config+0x5a> (condition opaque) */
    /* mem st8: base=(?) off=0 */
    /* mem st8: base=(?) off=1 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=0x178 */
    /* mem st8: base=(ret@41) off=0 */
    /* mem st32: base=(ret@41) off=4 */
    /* mem st16: base=(ret@41) off=8 */
    /* mem st8: base=(ret@41) off=10 */
    /* mem st32: base=(ret@41) off=12 */
    /* site +0x1a: wifi_init_completed(/* no traced args */) */
    wifi_init_completed(/* no traced args */);
    /* site +0x41: indirect call via a8 (base *(g_osi_funcs_p+0x178)); args: 24 */
    opaque_indirect_a8();
    /* site +0x69: ieee80211_ioctl(ret@41) */
    ieee80211_ioctl(ret@41);
    return last_call_result; /* opaque */
}

/* esp_mesh_set_ie_crypto_funcs_internal @ ieee80211_api.o 0x0000001c size 90B bind GLOBAL
 * Calls: wifi_init_completed, indirect(a8), ieee80211_ioctl | Data refs: g_ic, g_osi_funcs_p, wifi_mesh_ie_crypto_funcs_set_progress
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 esp_mesh_set_ie_crypto_funcs_internal(u32 a2)
{
    /* frame: entry a1,32; 33 insns, 3 cond-branches, 0 loops, 0 jumps */
    /* immediates: 24, 0x101, 57, 0 */
    /* first predicate: beqz a10, 72 <esp_mesh_set_ie_crypto_funcs_internal+0x56> (condition opaque) */
    /* mem ld8: base=((lit:g_ic+65536)) off=237 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=0x178 */
    /* mem st8: base=(ret@45) off=0 */
    /* mem st32: base=(ret@45) off=4 */
    /* mem st16: base=(ret@45) off=8 */
    /* mem st8: base=(ret@45) off=10 */
    /* mem st32: base=(ret@45) off=12 */
    /* site +0x22: wifi_init_completed(/* no traced args */) */
    wifi_init_completed(/* no traced args */);
    /* site +0x45: indirect call via a8 (base *(g_osi_funcs_p+0x178)); args: 24 */
    opaque_indirect_a8();
    /* site +0x6d: ieee80211_ioctl(ret@45) */
    ieee80211_ioctl(ret@45);
    return last_call_result; /* opaque */
}

/* esp_mesh_set_ie_crypto_key_internal @ ieee80211_api.o 0x0000001c size 94B bind GLOBAL
 * Calls: wifi_init_completed, indirect(a8), ieee80211_ioctl | Data refs: g_ic, g_osi_funcs_p, wifi_mesh_ie_crypto_key_set_progress
 * Fidelity: medium - branchy but loop-free, call sequence mapped */
u32 esp_mesh_set_ie_crypto_key_internal(u32 a2, u32 a3)
{
    /* frame: entry a1,32; 35 insns, 4 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0x102, 24, 0x101, 58, 0 */
    /* first predicate: beqz a10, 76 <esp_mesh_set_ie_crypto_key_internal+0x5a> (condition opaque) */
    /* mem ld8: base=((lit:g_ic+65536)) off=237 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=0x178 */
    /* mem st8: base=(ret@49) off=0 */
    /* mem st32: base=(ret@49) off=4 */
    /* mem st16: base=(ret@49) off=8 */
    /* mem st8: base=(ret@49) off=10 */
    /* mem st32: base=(ret@49) off=12 */
    /* site +0x22: wifi_init_completed(/* no traced args */) */
    wifi_init_completed(/* no traced args */);
    /* site +0x49: indirect call via a8 (base *(g_osi_funcs_p+0x178)); args: 24 */
    opaque_indirect_a8();
    /* site +0x71: ieee80211_ioctl(ret@49) */
    ieee80211_ioctl(ret@49);
    return last_call_result; /* opaque */
}

/* esp_wifi_scan_sort_ap_records @ ieee80211_api.o 0x00000038 size 342B bind GLOBAL
 * Calls: scan_get_apnum, wifi_log, indirect(a3), wifi_log, indirect(a3), memmove, indirect(a4) | Data refs: g_mesh_topology, .rodata_wlog_warning.68, g_osi_funcs_p, .bss.sort_bss$1, .rodata_wlog_warning.69, .bss.s_mesh_sort_bss, g_wifi_global_lock, g_ic, g_ic+0x130, .bss.s_mesh_sort_num
 * Fidelity: low - 127 insns, 15 branches, 0 loops; skeleton only */
u32 esp_wifi_scan_sort_ap_records(u32 a3, u32 a4, u32 a6)
{
    /* frame: entry a1,48; 127 insns, 15 cond-branches, 0 loops, 10 jumps */
    /* immediates: 2, 10, 1, 0x101, 0, 4 */
    /* first predicate: bnez.n a10, 5d <esp_wifi_scan_sort_ap_records+0x25> (condition opaque) */
    /* mem ld32: base=(lit:g_mesh_topology) off=0 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=0x16c */
    /* mem st32: base=(lit:.bss.sort_bss$1) off=0 */
    /* mem st32: base=(lit:.bss.s_mesh_sort_bss) off=0 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(lit:g_wifi_global_lock) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=84 */
    /* mem ld32: base=(0x101) off=0 */
    /* mem ld32: base=(0x101) off=0 */
    /* ... +19 more memops */
    /* site +0x3e: scan_get_apnum(/* no traced args */) */
    scan_get_apnum(/* no traced args */);
    /* site +0x56: wifi_log(1, 10, 2, lit:.rodata_wlog_warning.68) */
    wifi_log(1, 10, 2, lit:.rodata_wlog_warning.68);
    /* site +0x69: indirect call via a3 (base *(g_mesh_topology+0x16c)); args: (ret@56 slli 2), 10, 2, lit:.rodata_wlog_warning.68 */
    opaque_indirect_a3();
    /* site +0x82: wifi_log(1, 2, 2, lit:.rodata_wlog_warning.69) */
    wifi_log(1, 2, 2, lit:.rodata_wlog_warning.69);
    /* site +0x9e: indirect call via a3 (base *(.bss.s_mesh_sort_bss+84)); args: *(g_wifi_global_lock+0), 2, 2, lit:.rodata_wlog_warning.69 */
    opaque_indirect_a3();
    /* site +0x151: memmove((((*(*(*(g_ic+0x130+0)+52)+61) slli 8)+-1..., ((0+1)+-4), ((*(*(*(g_ic+0x130+0)+52)+61) slli 8) sll..., lit:g_ic, ((0+1)+-1)) */
    memmove((((*(*(*(g_ic+0x130+0)+52)+61) slli 8)+-1..., ((0+1)+-4), ((*(*(*(g_ic+0x130+0)+52)+61) slli 8) sll..., lit:g_ic, ((0+1)+-1));
    /* site +0x169: indirect call via a4 (base *(g_osi_funcs_p+88)); args: *(g_wifi_global_lock+0), ((0+1)+-4), ((*(*(*(g_ic+0x130+0)+52)+61) slli 8) sll..., *(?+0), ((0+1)+-1) */
    opaque_indirect_a4();
    return opaque_result; /* full dataflow not recovered */
}

/* esp_wifi_scan_sort_get_cur_ap_info @ ieee80211_api.o 0x00000024 size 233B bind GLOBAL
 * Calls: wifi_init_completed, indirect(a8), indirect(a2), indirect(a8), indirect(a8) | Data refs: g_ic, g_wifi_global_lock, g_osi_funcs_p, .bss.s_mesh_sort_bss, .bss.s_mesh_sort_num, .bss.s_mesh_fetch_num
 * Fidelity: medium - branchy but loop-free, call sequence mapped (verified: section R_XTENSA_ASM_EXPAND + funcdb v3 agree; predicates opaque) */
u32 esp_wifi_scan_sort_get_cur_ap_info(u32 a2, u32 a3, u32 a6)
{
    /* frame: entry a1,32; 87 insns, 17 cond-branches, 0 loops, 10 jumps */
    /* immediates: 0x102, 0, -1, 9, 24, 58, 62, 13 */
    /* first predicate: beqz a10, 108 <esp_wifi_scan_sort_get_cur_ap_info+0xe4> (condition opaque) */
    /* mem ld8: base=((lit:g_ic+65536)) off=237 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(lit:g_wifi_global_lock) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=84 */
    /* mem st32: base=(?) off=0 */
    /* mem ld32: base=(lit:.bss.s_mesh_sort_bss) off=0 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(lit:g_wifi_global_lock) off=0 */
    /* mem st16: base=(lit:.bss.s_mesh_sort_num) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=88 */
    /* ... +14 more memops */
    /* site +0x2a: wifi_init_completed(/* no traced args */) */
    wifi_init_completed(/* no traced args */);
    /* site +0x61: indirect call via a8 (base *(*(g_osi_funcs_p+0)+84)); args: *(g_wifi_global_lock+0) */
    opaque_indirect_a8();
    /* site +0x81: indirect call via a2 (base *(*(g_osi_funcs_p+0)+88)); args: *(g_wifi_global_lock+0) */
    opaque_indirect_a2();
    /* site +0x9a: indirect call via a8 (base *(*(g_osi_funcs_p+0)+88)); args: *(g_wifi_global_lock+0) */
    opaque_indirect_a8();
    /* site +0xa4: indirect call via a8 (base *(*(g_osi_funcs_p+0)+88)); args: ret@9a */
    opaque_indirect_a8();
    return 0;
}

/* esp_wifi_scan_sort_get_cur_ap_record @ ieee80211_api.o 0x00000040 size 404B bind GLOBAL
 * Calls: wifi_init_completed, indirect(a2), indirect(a2), memset, memcpy, memcpy, memcpy, memcpy, memcpy, free_bss_info, indirect(a2), indirect(a2) | Data refs: g_ic, g_wifi_global_lock, g_osi_funcs_p, .bss.s_mesh_sort_bss, .bss.s_mesh_sort_num, .bss.s_mesh_fetch_num
 * Fidelity: low - 152 insns, 24 branches, 0 loops; skeleton only */
u32 esp_wifi_scan_sort_get_cur_ap_record(u32 a2, u32 a3, u32 a4)
{
    /* frame: entry a1,32; 152 insns, 24 cond-branches, 0 loops, 9 jumps */
    /* immediates: 0x102, -1, 92, 0, 6, 9, 24, 58, 62, 13 */
    /* first predicate: beqz a10, 1d2 <esp_wifi_scan_sort_get_cur_ap_record+0x192> (condition opaque) */
    /* mem ld8: base=((lit:g_ic+65536)) off=237 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=84 */
    /* mem ld32: base=(lit:g_wifi_global_lock) off=0 */
    /* mem ld32: base=(lit:.bss.s_mesh_sort_bss) off=0 */
    /* mem st16: base=(lit:.bss.s_mesh_sort_num) off=0 */
    /* mem ld16: base=(lit:.bss.s_mesh_fetch_num) off=0 */
    /* mem ld32: base=(*(.bss.s_mesh_fetch_num+0)) off=0 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=88 */
    /* ... +30 more memops */
    /* site +0x46: wifi_init_completed(/* no traced args */) */
    wifi_init_completed(/* no traced args */);
    /* site +0x79: indirect call via a2 (base *(g_ic+84)); args: *(g_wifi_global_lock+0) */
    opaque_indirect_a2();
    /* site +0xae: indirect call via a2 (base *(.bss.s_mesh_fetch_num+88)); args: *(g_wifi_global_lock+0) */
    opaque_indirect_a2();
    /* site +0xc1: memset(ret@ae, 0, 92) */
    memset(ret@ae, 0, 92);
    /* site +0xce: memcpy((?+6), (*(g_wifi_global_lock+0)+10), *(*(g_wifi_global_lock+0)+42)) */
    memcpy((?+6), (*(g_wifi_global_lock+0)+10), *(*(g_wifi_global_lock+0)+42));
    /* site +0xda: memcpy(?, (*(g_wifi_global_lock+0)+4), 6) */
    memcpy(?, (*(g_wifi_global_lock+0)+4), 6);
    /* site +0x14d: memcpy(?, *(*(g_wifi_global_lock+0)+52), 58) */
    memcpy(?, *(*(g_wifi_global_lock+0)+52), 58);
    /* site +0x169: memcpy(?, *(*(g_wifi_global_lock+0)+52), 62) */
    memcpy(?, *(*(g_wifi_global_lock+0)+52), 62);
    /* site +0x178: memcpy((?+62), *(*(g_wifi_global_lock+0)+56), 13) */
    memcpy((?+62), *(*(g_wifi_global_lock+0)+56), 13);
    /* site +0x180: free_bss_info(*(g_wifi_global_lock+0), *(*(g_wifi_global_lock+0)+56), 13) */
    free_bss_info(*(g_wifi_global_lock+0), *(*(g_wifi_global_lock+0)+56), 13);
    /* site +0x1b6: indirect call via a2 (base *(.bss.s_mesh_fetch_num+176)); args: *(.bss.s_mesh_sort_bss+0), *(*(g_wifi_global_lock+0)+56), 13 */
    opaque_indirect_a2();
    /* site +0x1cd: indirect call via a2 (base *(.bss.s_mesh_fetch_num+88)); args: *(g_wifi_global_lock+0), *(*(g_wifi_global_lock+0)+56), 13 */
    opaque_indirect_a2();
    return 0;
}

/* esp_mesh_set_parent_candidate @ ieee80211_api.o 0x0000001c size 99B bind GLOBAL
 * Calls: wifi_init_completed, indirect(a2), ieee80211_ioctl | Data refs: g_ic, g_osi_funcs_p, wifi_mesh_parent_candidate_set_progress
 * Fidelity: medium - branchy but loop-free, call sequence mapped */
u32 esp_mesh_set_parent_candidate(u32 a2, u32 a3, u32 a4)
{
    /* frame: entry a1,48; 37 insns, 4 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0x102, 24, 0, 69 */
    /* first predicate: beqz a10, 7d <esp_mesh_set_parent_candidate+0x61> (condition opaque) */
    /* mem ld8: base=((lit:g_ic+65536)) off=237 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=0x178 */
    /* mem st32: base=(?) off=0 */
    /* mem st32: base=(?) off=4 */
    /* mem st8: base=(ret@52) off=0 */
    /* mem st16: base=(ret@52) off=8 */
    /* mem st32: base=(ret@52) off=4 */
    /* mem st8: base=(ret@52) off=10 */
    /* mem st32: base=(ret@52) off=12 */
    /* ... +1 more memops */
    /* site +0x22: wifi_init_completed(/* no traced args */) */
    wifi_init_completed(/* no traced args */);
    /* site +0x52: indirect call via a2 (base *(g_osi_funcs_p+0x178)); args: 24 */
    opaque_indirect_a2();
    /* site +0x7a: ieee80211_ioctl(ret@52) */
    ieee80211_ioctl(ret@52);
    return opaque_result; /* full dataflow not recovered */
}

/* esp_mesh_clear_parent_candidate @ ieee80211_api.o 0x0000000c size 44B bind GLOBAL
 * Calls: indirect(a8), ieee80211_ioctl | Data refs: g_osi_funcs_p, wifi_mesh_parent_candidate_clear_progress
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 esp_mesh_clear_parent_candidate(void)
{
    /* frame: entry a1,32; 17 insns, 1 cond-branches, 0 loops, 0 jumps */
    /* immediates: 24, 71, 0 */
    /* first predicate: beqz.n a10, 34 <esp_mesh_clear_parent_candidate+0x28> (condition opaque) */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=0x178 */
    /* mem st32: base=(ret@19) off=4 */
    /* mem st8: base=(ret@19) off=0 */
    /* site +0x19: indirect call via a8 (base *(g_osi_funcs_p+0x178)); args: 24 */
    opaque_indirect_a8();
    /* site +0x31: ieee80211_ioctl(ret@19) */
    ieee80211_ioctl(ret@19);
    return 0;
}

/* esp_mesh_get_parent_candidate @ ieee80211_api.o 0x0000001c size 90B bind GLOBAL
 * Calls: wifi_init_completed, indirect(a2), ieee80211_ioctl | Data refs: g_ic, g_osi_funcs_p, wifi_mesh_parent_candidate_get_progress
 * Fidelity: medium - branchy but loop-free, call sequence mapped */
u32 esp_mesh_get_parent_candidate(u32 a2)
{
    /* frame: entry a1,32; 33 insns, 4 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0x102, 24, 0, 70 */
    /* first predicate: beqz a10, 74 <esp_mesh_get_parent_candidate+0x58> (condition opaque) */
    /* mem ld8: base=((lit:g_ic+65536)) off=237 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=0x178 */
    /* mem st8: base=(ret@4b) off=0 */
    /* mem st16: base=(ret@4b) off=8 */
    /* mem st32: base=(ret@4b) off=4 */
    /* mem st8: base=(ret@4b) off=10 */
    /* mem st32: base=(ret@4b) off=12 */
    /* site +0x22: wifi_init_completed(/* no traced args */) */
    wifi_init_completed(/* no traced args */);
    /* site +0x4b: indirect call via a2 (base *(g_osi_funcs_p+0x178)); args: 24 */
    opaque_indirect_a2();
    /* site +0x71: ieee80211_ioctl(ret@4b) */
    ieee80211_ioctl(ret@4b);
    return opaque_result; /* full dataflow not recovered */
}

/* esp_mesh_set_rssi_threshold_internal @ ieee80211_api.o 0x0000001c size 90B bind GLOBAL
 * Calls: wifi_init_completed, indirect(a2), ieee80211_ioctl | Data refs: g_ic, g_osi_funcs_p, wifi_mesh_rssi_threshold_set_progress
 * Fidelity: medium - branchy but loop-free, call sequence mapped */
u32 esp_mesh_set_rssi_threshold_internal(u32 a2)
{
    /* frame: entry a1,32; 33 insns, 4 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0x102, 24, 0, 72 */
    /* first predicate: beqz a10, 74 <esp_mesh_set_rssi_threshold_internal+0x58> (condition opaque) */
    /* mem ld8: base=((lit:g_ic+65536)) off=237 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=0x178 */
    /* mem st8: base=(ret@4b) off=0 */
    /* mem st16: base=(ret@4b) off=8 */
    /* mem st32: base=(ret@4b) off=4 */
    /* mem st8: base=(ret@4b) off=10 */
    /* mem st32: base=(ret@4b) off=12 */
    /* site +0x22: wifi_init_completed(/* no traced args */) */
    wifi_init_completed(/* no traced args */);
    /* site +0x4b: indirect call via a2 (base *(g_osi_funcs_p+0x178)); args: 24 */
    opaque_indirect_a2();
    /* site +0x71: ieee80211_ioctl(ret@4b) */
    ieee80211_ioctl(ret@4b);
    return opaque_result; /* full dataflow not recovered */
}

/* esp_mesh_get_rssi_threshold_internal @ ieee80211_api.o 0x0000001c size 90B bind GLOBAL
 * Calls: wifi_init_completed, indirect(a2), ieee80211_ioctl | Data refs: g_ic, g_osi_funcs_p, wifi_mesh_rssi_threshold_get_progress
 * Fidelity: medium - branchy but loop-free, call sequence mapped */
u32 esp_mesh_get_rssi_threshold_internal(u32 a2)
{
    /* frame: entry a1,32; 33 insns, 4 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0x102, 24, 0, 73 */
    /* first predicate: beqz a10, 74 <esp_mesh_get_rssi_threshold_internal+0x58> (condition opaque) */
    /* mem ld8: base=((lit:g_ic+65536)) off=237 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=0x178 */
    /* mem st8: base=(ret@4b) off=0 */
    /* mem st16: base=(ret@4b) off=8 */
    /* mem st32: base=(ret@4b) off=4 */
    /* mem st8: base=(ret@4b) off=10 */
    /* mem st32: base=(ret@4b) off=12 */
    /* site +0x22: wifi_init_completed(/* no traced args */) */
    wifi_init_completed(/* no traced args */);
    /* site +0x4b: indirect call via a2 (base *(g_osi_funcs_p+0x178)); args: 24 */
    opaque_indirect_a2();
    /* site +0x71: ieee80211_ioctl(ret@4b) */
    ieee80211_ioctl(ret@4b);
    return opaque_result; /* full dataflow not recovered */
}

/* esp_mesh_is_roots_found @ ieee80211_api.o 0x0000000c size 73B bind GLOBAL
 * Calls: indirect(a8), ieee80211_ioctl | Data refs: g_osi_funcs_p, wifi_mesh_is_roots_found_progress
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 esp_mesh_is_roots_found(void)
{
    /* frame: entry a1,48; 26 insns, 1 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0, 24, 74 */
    /* first predicate: beqz.n a10, 50 <esp_mesh_is_roots_found+0x44> (condition opaque) */
    /* mem st8: base=(?) off=0 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=0x178 */
    /* mem st8: base=(ret@26) off=0 */
    /* mem st32: base=(ret@26) off=4 */
    /* mem st16: base=(ret@26) off=8 */
    /* mem st8: base=(ret@26) off=10 */
    /* mem st32: base=(ret@26) off=12 */
    /* mem ld8: base=(?) off=0 */
    /* site +0x26: indirect call via a8 (base *(g_osi_funcs_p+0x178)); args: 24 */
    opaque_indirect_a8();
    /* site +0x4d: ieee80211_ioctl(ret@26) */
    ieee80211_ioctl(ret@26);
    return opaque_result; /* full dataflow not recovered */
}

/* esp_mesh_get_storage @ ieee80211_api.o 0x00000004 size 14B bind GLOBAL
 * Calls: none | Data refs: g_ic
 * Fidelity: high - straight-line, fully mapped (5 insns) */
u32 esp_mesh_get_storage(void)
{
    /* frame: entry a1,32; 5 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* mem ld8: base=((lit:g_ic+131072)) off=31 */
    return opaque_result; /* full dataflow not recovered */
}

/* esp_mesh_switch_channel_internal @ ieee80211_api.o 0x00000014 size 68B bind GLOBAL
 * Calls: wifi_init_completed, indirect(a8), ieee80211_ioctl | Data refs: g_osi_funcs_p, wifi_mesh_switch_channel_progress
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 esp_mesh_switch_channel_internal(u32 a2, u32 a3)
{
    /* frame: entry a1,32; 25 insns, 2 cond-branches, 0 loops, 0 jumps */
    /* immediates: 24, 0x101, 75 */
    /* first predicate: beqz.n a10, 54 <esp_mesh_switch_channel_internal+0x40> (condition opaque) */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=0x178 */
    /* mem st32: base=(ret@2e) off=4 */
    /* mem st8: base=(ret@2e) off=0 */
    /* mem st8: base=(ret@2e) off=8 */
    /* mem st8: base=(ret@2e) off=9 */
    /* site +0x1a: wifi_init_completed(/* no traced args */) */
    wifi_init_completed(/* no traced args */);
    /* site +0x2e: indirect call via a8 (base *(g_osi_funcs_p+0x178)); args: 24 */
    opaque_indirect_a8();
    /* site +0x4f: ieee80211_ioctl(ret@2e) */
    ieee80211_ioctl(ret@2e);
    return last_call_result; /* opaque */
}

/* esp_mesh_set_active_duty_cycle @ ieee80211_api.o 0x00000028 size 204B bind GLOBAL
 * Calls: wifi_init_completed, wifi_log, memset, indirect(a2), ieee80211_ioctl | Data refs: .rodata_wlog_info.70, g_mesh_is_root, esp_mesh_ps_duty, g_osi_funcs_p, wifi_mesh_ps_duty_cycle_set_process
 * Fidelity: medium - branchy but loop-free, call sequence mapped (verified: section R_XTENSA_ASM_EXPAND + funcdb v3 agree; predicates opaque) */
u32 esp_mesh_set_active_duty_cycle(u32 a2, u32 a3)
{
    /* frame: entry a1,48; 76 insns, 8 cond-branches, 0 loops, 3 jumps */
    /* immediates: 100, 1, 0, -255, 128, 3, 16, 24, 0x101, 76 */
    /* first predicate: beqz a10, f0 <esp_mesh_set_active_duty_cycle+0xc8> (condition opaque) */
    /* mem ld8: base=(lit:g_mesh_is_root) off=0 */
    /* mem ld8: base=(lit:esp_mesh_ps_duty) off=1 */
    /* mem ld8: base=(lit:esp_mesh_ps_duty) off=0 */
    /* mem st8: base=(?) off=1 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=0x178 */
    /* mem st8: base=(?) off=0 */
    /* mem st8: base=(ret@b6) off=0 */
    /* mem st32: base=(ret@b6) off=4 */
    /* mem st16: base=(ret@b6) off=8 */
    /* ... +3 more memops */
    /* site +0x2e: wifi_init_completed(/* no traced args */) */
    wifi_init_completed(/* no traced args */);
    /* site +0x6e: wifi_log(1, (1 slli 16), 3, lit:.rodata_wlog_info.70) */
    wifi_log(1, (1 slli 16), 3, lit:.rodata_wlog_info.70);
    /* site +0x9a: memset(?, 0, 16, lit:.rodata_wlog_info.70) */
    memset(?, 0, 16, lit:.rodata_wlog_info.70);
    /* site +0xb6: indirect call via a2 (base *(g_osi_funcs_p+0x178)); args: 24, 0, 16, lit:.rodata_wlog_info.70 */
    opaque_indirect_a2();
    /* site +0xe5: ieee80211_ioctl(ret@b6, 0, 16, lit:.rodata_wlog_info.70) */
    ieee80211_ioctl(ret@b6, 0, 16, lit:.rodata_wlog_info.70);
    return 0x102;
}

/* esp_mesh_get_active_duty_cycle @ ieee80211_api.o 0x00000010 size 111B bind GLOBAL
 * Calls: memset, indirect(a8), ieee80211_ioctl | Data refs: g_osi_funcs_p, wifi_mesh_ps_duty_cycle_get_process
 * Fidelity: medium - branchy but loop-free, call sequence mapped */
u32 esp_mesh_get_active_duty_cycle(u32 a2, u32 a3)
{
    /* frame: entry a1,48; 43 insns, 5 cond-branches, 0 loops, 1 jumps */
    /* immediates: 0, 16, 24, 0x101, 77 */
    /* first predicate: bnez.n a8, 1d <esp_mesh_get_active_duty_cycle+0xd> (condition opaque) */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=0x178 */
    /* mem st8: base=(ret@35) off=0 */
    /* mem st32: base=(ret@35) off=4 */
    /* mem st16: base=(ret@35) off=8 */
    /* mem st8: base=(ret@35) off=10 */
    /* mem st32: base=(ret@35) off=12 */
    /* mem st32: base=(ret@35) off=20 */
    /* mem ld8: base=(?) off=1 */
    /* mem st32: base=(?) off=0 */
    /* ... +2 more memops */
    /* site +0x26: memset(?, 0, 16) */
    memset(?, 0, 16);
    /* site +0x35: indirect call via a8 (base *(g_osi_funcs_p+0x178)); args: 24, 0, 16 */
    opaque_indirect_a8();
    /* site +0x62: ieee80211_ioctl(ret@35, 0, 16) */
    ieee80211_ioctl(ret@35, 0, 16);
    return last_call_result; /* opaque */
}

/* esp_mesh_set_network_duty_internal @ ieee80211_api.o 0x00000014 size 84B bind GLOBAL
 * Calls: wifi_init_completed, indirect(a8), ieee80211_ioctl | Data refs: g_osi_funcs_p, wifi_mesh_ps_duty_cycle_set_process
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 esp_mesh_set_network_duty_internal(u32 a2, u32 a3)
{
    /* frame: entry a1,32; 32 insns, 3 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0x102, 24, 0x101, 76, 0x100, 0 */
    /* first predicate: beqz a10, 64 <esp_mesh_set_network_duty_internal+0x50> (condition opaque) */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=0x178 */
    /* mem st8: base=(ret@32) off=0 */
    /* mem st32: base=(ret@32) off=4 */
    /* mem st16: base=(ret@32) off=8 */
    /* mem st8: base=(ret@32) off=10 */
    /* mem st32: base=(ret@32) off=12 */
    /* mem st32: base=(ret@32) off=20 */
    /* site +0x1a: wifi_init_completed(/* no traced args */) */
    wifi_init_completed(/* no traced args */);
    /* site +0x32: indirect call via a8 (base *(g_osi_funcs_p+0x178)); args: 24 */
    opaque_indirect_a8();
    /* site +0x5f: ieee80211_ioctl(ret@32) */
    ieee80211_ioctl(ret@32);
    return last_call_result; /* opaque */
}

/* esp_mesh_set_network_duty_cycle @ ieee80211_api.o 0x00000018 size 164B bind GLOBAL
 * Calls: wifi_init_completed, memset, indirect(a2), ieee80211_ioctl | Data refs: g_osi_funcs_p, wifi_mesh_ps_duty_cycle_set_process
 * Fidelity: medium - branchy but loop-free, call sequence mapped */
u32 esp_mesh_set_network_duty_cycle(u32 a2, u32 a3, u32 a4)
{
    /* frame: entry a1,48; 60 insns, 5 cond-branches, 0 loops, 2 jumps */
    /* immediates: 0x102, 99, 1, 0, 15, 24, 0x101, 76, 0x100 */
    /* first predicate: beqz a10, b8 <esp_mesh_set_network_duty_cycle+0xa0> (condition opaque) */
    /* mem st8: base=(?) off=2 */
    /* mem st8: base=(?) off=4 */
    /* mem st8: base=(?) off=5 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem st8: base=(?) off=3 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=0x178 */
    /* mem st8: base=(?) off=6 */
    /* mem st8: base=(?) off=15 */
    /* mem st8: base=(ret@82) off=0 */
    /* mem st32: base=(ret@82) off=4 */
    /* ... +4 more memops */
    /* site +0x1e: wifi_init_completed(/* no traced args */) */
    wifi_init_completed(/* no traced args */);
    /* site +0x4e: memset(?, 99, 15) */
    memset(?, 99, 15);
    /* site +0x82: indirect call via a2 (base *(g_osi_funcs_p+0x178)); args: 24, 99, 15 */
    opaque_indirect_a2();
    /* site +0xad: ieee80211_ioctl(ret@82, 99, 15) */
    ieee80211_ioctl(ret@82, 99, 15);
    return 0x102;
}

/* esp_mesh_get_network_duty_cycle @ ieee80211_api.o 0x00000010 size 139B bind GLOBAL
 * Calls: memset, indirect(a8), ieee80211_ioctl | Data refs: g_osi_funcs_p, wifi_mesh_ps_duty_cycle_get_process
 * Fidelity: medium - branchy but loop-free, call sequence mapped */
u32 esp_mesh_get_network_duty_cycle(u32 a2, u32 a3, u32 a4, u32 a5)
{
    /* frame: entry a1,48; 54 insns, 7 cond-branches, 0 loops, 1 jumps */
    /* immediates: 0, 16, 24, 0x101, 77 */
    /* first predicate: bnez.n a8, 24 <esp_mesh_get_network_duty_cycle+0x14> (condition opaque) */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=0x178 */
    /* mem st8: base=(ret@3a) off=0 */
    /* mem st32: base=(ret@3a) off=4 */
    /* mem st16: base=(ret@3a) off=8 */
    /* mem st8: base=(ret@3a) off=10 */
    /* mem st32: base=(ret@3a) off=12 */
    /* mem st32: base=(ret@3a) off=20 */
    /* mem ld8: base=(?) off=2 */
    /* mem st32: base=(?) off=0 */
    /* ... +7 more memops */
    /* site +0x2d: memset(?, 0, 16) */
    memset(?, 0, 16);
    /* site +0x3a: indirect call via a8 (base *(g_osi_funcs_p+0x178)); args: 24, 0, 16 */
    opaque_indirect_a8();
    /* site +0x67: ieee80211_ioctl(ret@3a, 0, 16) */
    ieee80211_ioctl(ret@3a, 0, 16);
    return last_call_result; /* opaque */
}

/* esp_mesh_get_running_active_duty_cycle @ ieee80211_api.o 0x0000000c size 77B bind GLOBAL
 * Calls: indirect(a8), ieee80211_ioctl | Data refs: g_osi_funcs_p, wifi_mesh_ps_duty_cycle_get_process
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 esp_mesh_get_running_active_duty_cycle(void)
{
    /* frame: entry a1,48; 28 insns, 1 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0, 24, 77 */
    /* first predicate: beqz.n a10, 54 <esp_mesh_get_running_active_duty_cycle+0x48> (condition opaque) */
    /* mem st8: base=(?) off=0 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=0x178 */
    /* mem st8: base=(ret@26) off=0 */
    /* mem st32: base=(ret@26) off=4 */
    /* mem st16: base=(ret@26) off=8 */
    /* mem st8: base=(ret@26) off=10 */
    /* mem st32: base=(ret@26) off=12 */
    /* mem st32: base=(ret@26) off=20 */
    /* mem ld8: base=(?) off=0 */
    /* site +0x26: indirect call via a8 (base *(g_osi_funcs_p+0x178)); args: 24 */
    opaque_indirect_a8();
    /* site +0x51: ieee80211_ioctl(ret@26) */
    ieee80211_ioctl(ret@26);
    return opaque_result; /* full dataflow not recovered */
}

/* esp_mesh_ps_get_ext_duty @ ieee80211_api.o 0x0000000c size 68B bind GLOBAL
 * Calls: indirect(a8), ieee80211_ioctl | Data refs: g_osi_funcs_p, wifi_mesh_ps_duty_ext_get_process
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 esp_mesh_ps_get_ext_duty(u32 a2)
{
    /* frame: entry a1,32; 26 insns, 2 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0x102, 24, 0x101, 79, 0 */
    /* first predicate: beqz.n a2, 4c <esp_mesh_ps_get_ext_duty+0x40> (condition opaque) */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=0x178 */
    /* mem st8: base=(ret@1e) off=0 */
    /* mem st32: base=(ret@1e) off=4 */
    /* mem st16: base=(ret@1e) off=8 */
    /* mem st8: base=(ret@1e) off=10 */
    /* mem st32: base=(ret@1e) off=12 */
    /* site +0x1e: indirect call via a8 (base *(g_osi_funcs_p+0x178)); args: 24 */
    opaque_indirect_a8();
    /* site +0x47: ieee80211_ioctl(ret@1e) */
    ieee80211_ioctl(ret@1e);
    return last_call_result; /* opaque */
}

/* esp_mesh_ps_duty_signaling @ ieee80211_api.o 0x00000010 size 82B bind GLOBAL
 * Calls: indirect(a8), ieee80211_ioctl | Data refs: .bss.token$0, g_osi_funcs_p, wifi_mesh_act_duty_signaling_process
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 esp_mesh_ps_duty_signaling(u32 a2, u32 a3)
{
    /* frame: entry a1,32; 32 insns, 1 cond-branches, 0 loops, 0 jumps */
    /* immediates: 24, 0x101, 91, 0 */
    /* first predicate: beqz.n a10, 5e <esp_mesh_ps_duty_signaling+0x4e> (condition opaque) */
    /* mem ld32: base=(lit:.bss.token$0) off=0 */
    /* mem st32: base=(lit:.bss.token$0) off=0 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=0x178 */
    /* mem st8: base=(ret@2a) off=0 */
    /* mem st8: base=(ret@2a) off=10 */
    /* mem ld32: base=(lit:.bss.token$0) off=0 */
    /* mem st32: base=(ret@2a) off=4 */
    /* mem st16: base=(ret@2a) off=8 */
    /* mem st32: base=(ret@2a) off=12 */
    /* site +0x2a: indirect call via a8 (base *(g_osi_funcs_p+0x178)); args: 24 */
    opaque_indirect_a8();
    /* site +0x59: ieee80211_ioctl(ret@2a) */
    ieee80211_ioctl(ret@2a);
    return last_call_result; /* opaque */
}

/* esp_wifi_set_non_mesh_connections @ ieee80211_api.o 0x00000004 size 31B bind GLOBAL
 * Calls: none | Data refs: g_ic
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 esp_wifi_set_non_mesh_connections(u32 a2)
{
    /* frame: entry a1,32; 12 insns, 2 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0 */
    /* first predicate: beqz.n a8, 1c <esp_wifi_set_non_mesh_connections+0x18> (condition opaque) */
    /* mem ld32: base=(lit:g_ic) off=20 */
    /* mem ld32: base=(*(g_ic+20)) off=236 */
    /* mem st8: base=((*(g_ic+236)+131072)) off=250 */
    return 0;
}

/* esp_wifi_set_band @ ieee80211_api.o 0x00000020 size 118B bind GLOBAL
 * Calls: wifi_init_completed, indirect(a8), ieee80211_ioctl | Data refs: g_ic, g_wifi_nvs, g_osi_funcs_p, wifi_set_band_process
 * Fidelity: medium - branchy but loop-free, call sequence mapped */
u32 esp_wifi_set_band(u32 a2)
{
    /* frame: entry a1,32; 41 insns, 8 cond-branches, 0 loops, 1 jumps */
    /* immediates: 0x102, 24, 0x101, 107 */
    /* first predicate: beqz a10, 92 <esp_wifi_set_band+0x72> (condition opaque) */
    /* mem ld8: base=((lit:g_ic+65536)) off=237 */
    /* mem ld32: base=(lit:g_wifi_nvs) off=0 */
    /* mem ld32: base=((*(g_wifi_nvs+0)+327680)) off=200 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=0x178 */
    /* mem st32: base=(ret@6d) off=4 */
    /* mem st8: base=(ret@6d) off=0 */
    /* mem st8: base=(ret@6d) off=8 */
    /* site +0x26: wifi_init_completed(/* no traced args */) */
    wifi_init_completed(/* no traced args */);
    /* site +0x6d: indirect call via a8 (base *(g_osi_funcs_p+0x178)); args: 24 */
    opaque_indirect_a8();
    /* site +0x8d: ieee80211_ioctl(ret@6d) */
    ieee80211_ioctl(ret@6d);
    return last_call_result; /* opaque */
}

/* esp_wifi_get_band @ ieee80211_api.o 0x00000014 size 48B bind GLOBAL
 * Calls: wifi_init_completed, wifi_api_lock, chm_get_current_band, wifi_api_unlock | Data refs: none
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 esp_wifi_get_band(u32 a2)
{
    /* frame: entry a1,32; 18 insns, 2 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0x102, 0 */
    /* first predicate: beqz.n a10, 40 <esp_wifi_get_band+0x2c> (condition opaque) */
    /* mem st32: base=(?) off=0 */
    /* site +0x1a: wifi_init_completed(/* no traced args */) */
    wifi_init_completed(/* no traced args */);
    /* site +0x2a: wifi_api_lock(ret@1a) */
    wifi_api_lock(ret@1a);
    /* site +0x30: chm_get_current_band(ret@2a) */
    chm_get_current_band(ret@2a);
    /* site +0x3b: wifi_api_unlock(ret@30) */
    wifi_api_unlock(ret@30);
    return 0;
}

/* esp_wifi_set_band_mode @ ieee80211_api.o 0x0000002c size 134B bind GLOBAL
 * Calls: wifi_init_completed, wifi_log, wifi_log, indirect(a8), ieee80211_ioctl | Data refs: g_ic, .rodata_wlog_error.71, .rodata_wlog_error.72, g_osi_funcs_p, wifi_set_band_mode_process
 * Fidelity: medium - branchy but loop-free, call sequence mapped */
u32 esp_wifi_set_band_mode(u32 a2)
{
    /* frame: entry a1,32; 48 insns, 5 cond-branches, 0 loops, 2 jumps */
    /* immediates: 1, 0x102, 24, 0x101, 111 */
    /* first predicate: beqz a10, ae <esp_wifi_set_band_mode+0x82> (condition opaque) */
    /* mem ld8: base=((lit:g_ic+65536)) off=237 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=0x178 */
    /* mem st32: base=(ret@8a) off=4 */
    /* mem st8: base=(ret@8a) off=0 */
    /* mem st8: base=(ret@8a) off=8 */
    /* site +0x32: wifi_init_completed(/* no traced args */) */
    wifi_init_completed(/* no traced args */);
    /* site +0x5d: wifi_log(1, 1, 1, lit:.rodata_wlog_error.71) */
    wifi_log(1, 1, 1, lit:.rodata_wlog_error.71);
    /* site +0x75: wifi_log(ret@5d, 1, 1, lit:.rodata_wlog_error.72) */
    wifi_log(ret@5d, 1, 1, lit:.rodata_wlog_error.72);
    /* site +0x8a: indirect call via a8 (base *(g_osi_funcs_p+0x178)); args: 24, 1, 1, lit:.rodata_wlog_error.72 */
    opaque_indirect_a8();
    /* site +0xa9: ieee80211_ioctl(ret@8a, 1, 1, lit:.rodata_wlog_error.72) */
    ieee80211_ioctl(ret@8a, 1, 1, lit:.rodata_wlog_error.72);
    return last_call_result; /* opaque */
}

/* esp_wifi_get_band_mode @ ieee80211_api.o 0x00000014 size 54B bind GLOBAL
 * Calls: wifi_init_completed, wifi_api_lock, wifi_api_unlock | Data refs: g_wifi_nvs
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 esp_wifi_get_band_mode(u32 a2)
{
    /* frame: entry a1,32; 20 insns, 2 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0x102, 0 */
    /* first predicate: beqz.n a10, 46 <esp_wifi_get_band_mode+0x32> (condition opaque) */
    /* mem ld32: base=(lit:g_wifi_nvs) off=0 */
    /* mem ld32: base=((*(g_wifi_nvs+0)+327680)) off=200 */
    /* mem st32: base=(?) off=0 */
    /* site +0x1a: wifi_init_completed(/* no traced args */) */
    wifi_init_completed(/* no traced args */);
    /* site +0x2a: wifi_api_lock(ret@1a) */
    wifi_api_lock(ret@1a);
    /* site +0x41: wifi_api_unlock(ret@2a) */
    wifi_api_unlock(ret@2a);
    return 0;
}

/* esp_wifi_set_dynamic_cs @ ieee80211_api.o 0x0000001c size 78B bind GLOBAL
 * Calls: wifi_init_completed, indirect(a2), ieee80211_ioctl | Data refs: g_ic, g_osi_funcs_p, wifi_set_dynamic_cs_process
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 esp_wifi_set_dynamic_cs(u32 a2)
{
    /* frame: entry a1,32; 28 insns, 3 cond-branches, 0 loops, 0 jumps */
    /* immediates: 24, 0, 101 */
    /* first predicate: beqz.n a10, 68 <esp_wifi_set_dynamic_cs+0x4c> (condition opaque) */
    /* mem ld8: base=((lit:g_ic+65536)) off=237 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=0x178 */
    /* mem st32: base=(ret@46) off=4 */
    /* mem st8: base=(ret@46) off=0 */
    /* mem st8: base=(ret@46) off=8 */
    /* site +0x22: wifi_init_completed(/* no traced args */) */
    wifi_init_completed(/* no traced args */);
    /* site +0x46: indirect call via a2 (base *(g_osi_funcs_p+0x178)); args: 24 */
    opaque_indirect_a2();
    /* site +0x65: ieee80211_ioctl(ret@46) */
    ieee80211_ioctl(ret@46);
    return opaque_result; /* full dataflow not recovered */
}

/* esp_wifi_eb_tx_status_success_internal @ ieee80211_api.o 0x00000004 size 40B bind GLOBAL
 * Calls: wifi_init_completed | Data refs: none
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 esp_wifi_eb_tx_status_success_internal(u32 a2)
{
    /* frame: entry a1,32; 16 insns, 2 cond-branches, 0 loops, 1 jumps */
    /* immediates: 1, 0 */
    /* first predicate: beqz.n a10, 2a <esp_wifi_eb_tx_status_success_internal+0x26> (condition opaque) */
    /* mem ld32: base=(?) off=44 */
    /* mem ld8: base=(*(?+44)) off=19 */
    /* site +0xa: wifi_init_completed(/* no traced args */) */
    wifi_init_completed(/* no traced args */);
    return (*(*(?+44)+19)+-1);
}

/* esp_wifi_internal_get_mac_clock_time @ ieee80211_api.o 0x00000018 size 67B bind GLOBAL
 * Calls: indirect(a10) | Data refs: g_mesh_is_started, g_mesh_is_root, g_mesh_init_ps_type, g_osi_funcs_p, g_wifi_mac_time_delta
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 esp_wifi_internal_get_mac_clock_time(void)
{
    /* frame: entry a1,32; 25 insns, 3 cond-branches, 0 loops, 1 jumps */
    /* first predicate: beqz.n a8, 48 <esp_wifi_internal_get_mac_clock_time+0x30> (condition opaque) */
    /* mem ld8: base=(lit:g_mesh_is_started) off=0 */
    /* mem ld8: base=(lit:g_mesh_is_root) off=0 */
    /* mem ld32: base=(lit:g_mesh_init_ps_type) off=0 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=0x110 */
    /* mem ld32: base=(lit:g_mesh_is_started) off=0 */
    /* mem ld32: base=(lit:g_wifi_mac_time_delta) off=0 */
    /* site +0x41: indirect call via a10 (base *(g_osi_funcs_p+0x110)); args: *(g_osi_funcs_p+0x110) */
    opaque_indirect_a10();
    return *(g_mesh_is_started+0);
}

/* esp_wifi_register_80211_tx_cb @ ieee80211_api.o 0x0000000c size 29B bind GLOBAL
 * Calls: wifi_init_completed | Data refs: g_ic
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 esp_wifi_register_80211_tx_cb(u32 a2)
{
    /* frame: entry a1,32; 11 insns, 1 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0 */
    /* first predicate: beqz.n a10, 22 <esp_wifi_register_80211_tx_cb+0x16> (condition opaque) */
    /* mem st32: base=(lit:g_ic) off=0x1c0 */
    /* site +0x12: wifi_init_completed(/* no traced args */) */
    wifi_init_completed(/* no traced args */);
    return 0;
}

/* wifi_assert @ ieee80211_api.o 0x00000008 size 47B bind GLOBAL
 * Calls: wifi_log | Data refs: .rodata_wlog_error.73
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque (weak) */
u32 wifi_assert(u32 a2, u32 a3, u32 a4, u32 a5)
{
    /* frame: entry a1,48; 16 insns, 1 cond-branches, 0 loops, 1 jumps */
    /* immediates: 1, 4 */
    /* first predicate: bnez.n a2, 2d <wifi_assert+0x25> (condition opaque) */
    /* mem st32: base=(?) off=0 */
    /* site +0x25: wifi_log(4, 1, 1, lit:.rodata_wlog_error.73) */
    wifi_log(4, 1, 1, lit:.rodata_wlog_error.73);
    return opaque_result; /* full dataflow not recovered */
}
