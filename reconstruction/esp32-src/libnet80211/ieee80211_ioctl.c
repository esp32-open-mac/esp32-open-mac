/* ieee80211_ioctl.o - reconstructed control-path C (offline, from objdump -d -r).
 * 197 code sections recovered. Fidelity per function below.
 * Conventions: args a2..a7 (Xtensa windowed ABI); outgoing call args
 * traced as a10..; u32 used for pointers/regs; opaque_* marks unrecovered.
 */
#include <stdint.h>
typedef unsigned char u8; typedef unsigned short u16; typedef unsigned int u32;
static u32 opaque_result, last_call_result;
/* ---- externals (U symbols + literal refs) ---- */
extern u32 bss_g_rmac_original_scan_cb; /* .bss.g_rmac_original_scan_cb */
extern u32 bss_mesh_router_bssid; /* .bss.mesh_router_bssid */
extern u32 bss_overwrite_save_ap_id_0; /* .bss.overwrite_save_ap_id$0 */
extern u32 bss_s_rmac_was_enabled; /* .bss.s_rmac_was_enabled */
extern u32 bss_s_wpa2_start; /* .bss.s_wpa2_start */
extern u32 bss_s_wps_start; /* .bss.s_wps_start */
extern u32 rodata_CSWTCH_391; /* .rodata.CSWTCH$391 */
extern u32 rodata_CSWTCH_424; /* .rodata.CSWTCH$424 */
extern u32 rodata_CSWTCH_491; /* .rodata.CSWTCH$491 */
extern u32 rodata___FUNCTION___1; /* .rodata.__FUNCTION__$1 */
extern u32 rodata_str1_1; /* .rodata.str1.1 */
extern u32 rodata_wifi_hw_mode_switch; /* .rodata.wifi_hw_mode_switch */
extern u32 rodata_wifi_lmac_init_str1_1; /* .rodata.wifi_lmac_init.str1.1 */
extern u32 rodata_wifi_set_promis_process_str1_1; /* .rodata.wifi_set_promis_process.str1.1 */
extern u32 rodata_wlog_debug_10; /* .rodata_wlog_debug.10 */
extern u32 rodata_wlog_debug_100; /* .rodata_wlog_debug.100 */
extern u32 rodata_wlog_debug_102; /* .rodata_wlog_debug.102 */
extern u32 rodata_wlog_debug_105; /* .rodata_wlog_debug.105 */
extern u32 rodata_wlog_debug_106; /* .rodata_wlog_debug.106 */
extern u32 rodata_wlog_debug_107; /* .rodata_wlog_debug.107 */
extern u32 rodata_wlog_debug_109; /* .rodata_wlog_debug.109 */
extern u32 rodata_wlog_debug_11; /* .rodata_wlog_debug.11 */
extern u32 rodata_wlog_debug_110; /* .rodata_wlog_debug.110 */
extern u32 rodata_wlog_debug_111; /* .rodata_wlog_debug.111 */
extern u32 rodata_wlog_debug_114; /* .rodata_wlog_debug.114 */
extern u32 rodata_wlog_debug_115; /* .rodata_wlog_debug.115 */
extern u32 rodata_wlog_debug_118; /* .rodata_wlog_debug.118 */
extern u32 rodata_wlog_debug_119; /* .rodata_wlog_debug.119 */
extern u32 rodata_wlog_debug_12; /* .rodata_wlog_debug.12 */
extern u32 rodata_wlog_debug_120; /* .rodata_wlog_debug.120 */
extern u32 rodata_wlog_debug_121; /* .rodata_wlog_debug.121 */
extern u32 rodata_wlog_debug_13; /* .rodata_wlog_debug.13 */
extern u32 rodata_wlog_debug_157; /* .rodata_wlog_debug.157 */
extern u32 rodata_wlog_debug_158; /* .rodata_wlog_debug.158 */
extern u32 rodata_wlog_debug_159; /* .rodata_wlog_debug.159 */
extern u32 rodata_wlog_debug_160; /* .rodata_wlog_debug.160 */
extern u32 rodata_wlog_debug_173; /* .rodata_wlog_debug.173 */
extern u32 rodata_wlog_debug_174; /* .rodata_wlog_debug.174 */
extern u32 rodata_wlog_debug_175; /* .rodata_wlog_debug.175 */
extern u32 rodata_wlog_debug_176; /* .rodata_wlog_debug.176 */
extern u32 rodata_wlog_debug_177; /* .rodata_wlog_debug.177 */
extern u32 rodata_wlog_debug_178; /* .rodata_wlog_debug.178 */
extern u32 rodata_wlog_debug_20; /* .rodata_wlog_debug.20 */
extern u32 rodata_wlog_debug_26; /* .rodata_wlog_debug.26 */
extern u32 rodata_wlog_debug_29; /* .rodata_wlog_debug.29 */
extern u32 rodata_wlog_debug_3; /* .rodata_wlog_debug.3 */
extern u32 rodata_wlog_debug_30; /* .rodata_wlog_debug.30 */
extern u32 rodata_wlog_debug_31; /* .rodata_wlog_debug.31 */
extern u32 rodata_wlog_debug_32; /* .rodata_wlog_debug.32 */
extern u32 rodata_wlog_debug_33; /* .rodata_wlog_debug.33 */
extern u32 rodata_wlog_debug_4; /* .rodata_wlog_debug.4 */
extern u32 rodata_wlog_debug_40; /* .rodata_wlog_debug.40 */
extern u32 rodata_wlog_debug_41; /* .rodata_wlog_debug.41 */
extern u32 rodata_wlog_debug_44; /* .rodata_wlog_debug.44 */
extern u32 rodata_wlog_debug_45; /* .rodata_wlog_debug.45 */
extern u32 rodata_wlog_debug_46; /* .rodata_wlog_debug.46 */
extern u32 rodata_wlog_debug_47; /* .rodata_wlog_debug.47 */
extern u32 rodata_wlog_debug_48; /* .rodata_wlog_debug.48 */
extern u32 rodata_wlog_debug_49; /* .rodata_wlog_debug.49 */
extern u32 rodata_wlog_debug_5; /* .rodata_wlog_debug.5 */
extern u32 rodata_wlog_debug_6; /* .rodata_wlog_debug.6 */
extern u32 rodata_wlog_debug_64; /* .rodata_wlog_debug.64 */
extern u32 rodata_wlog_debug_65; /* .rodata_wlog_debug.65 */
extern u32 rodata_wlog_debug_7; /* .rodata_wlog_debug.7 */
extern u32 rodata_wlog_debug_8; /* .rodata_wlog_debug.8 */
extern u32 rodata_wlog_debug_9; /* .rodata_wlog_debug.9 */
extern u32 rodata_wlog_debug_94; /* .rodata_wlog_debug.94 */
extern u32 rodata_wlog_debug_95; /* .rodata_wlog_debug.95 */
extern u32 rodata_wlog_debug_96; /* .rodata_wlog_debug.96 */
extern u32 rodata_wlog_error_113; /* .rodata_wlog_error.113 */
extern u32 rodata_wlog_error_116; /* .rodata_wlog_error.116 */
extern u32 rodata_wlog_error_117; /* .rodata_wlog_error.117 */
extern u32 rodata_wlog_error_126; /* .rodata_wlog_error.126 */
extern u32 rodata_wlog_error_135; /* .rodata_wlog_error.135 */
extern u32 rodata_wlog_error_136; /* .rodata_wlog_error.136 */
extern u32 rodata_wlog_error_137; /* .rodata_wlog_error.137 */
extern u32 rodata_wlog_error_139; /* .rodata_wlog_error.139 */
extern u32 rodata_wlog_error_14; /* .rodata_wlog_error.14 */
extern u32 rodata_wlog_error_140; /* .rodata_wlog_error.140 */
extern u32 rodata_wlog_error_141; /* .rodata_wlog_error.141 */
extern u32 rodata_wlog_error_142; /* .rodata_wlog_error.142 */
extern u32 rodata_wlog_error_143; /* .rodata_wlog_error.143 */
extern u32 rodata_wlog_error_144; /* .rodata_wlog_error.144 */
extern u32 rodata_wlog_error_145; /* .rodata_wlog_error.145 */
extern u32 rodata_wlog_error_146; /* .rodata_wlog_error.146 */
extern u32 rodata_wlog_error_147; /* .rodata_wlog_error.147 */
extern u32 rodata_wlog_error_15; /* .rodata_wlog_error.15 */
extern u32 rodata_wlog_error_152; /* .rodata_wlog_error.152 */
extern u32 rodata_wlog_error_153; /* .rodata_wlog_error.153 */
extern u32 rodata_wlog_error_154; /* .rodata_wlog_error.154 */
extern u32 rodata_wlog_error_155; /* .rodata_wlog_error.155 */
extern u32 rodata_wlog_error_156; /* .rodata_wlog_error.156 */
extern u32 rodata_wlog_error_162; /* .rodata_wlog_error.162 */
extern u32 rodata_wlog_error_163; /* .rodata_wlog_error.163 */
extern u32 rodata_wlog_error_164; /* .rodata_wlog_error.164 */
extern u32 rodata_wlog_error_165; /* .rodata_wlog_error.165 */
extern u32 rodata_wlog_error_166; /* .rodata_wlog_error.166 */
extern u32 rodata_wlog_error_167; /* .rodata_wlog_error.167 */
extern u32 rodata_wlog_error_168; /* .rodata_wlog_error.168 */
extern u32 rodata_wlog_error_169; /* .rodata_wlog_error.169 */
extern u32 rodata_wlog_error_171; /* .rodata_wlog_error.171 */
extern u32 rodata_wlog_error_179; /* .rodata_wlog_error.179 */
extern u32 rodata_wlog_error_183; /* .rodata_wlog_error.183 */
extern u32 rodata_wlog_error_23; /* .rodata_wlog_error.23 */
extern u32 rodata_wlog_error_28; /* .rodata_wlog_error.28 */
extern u32 rodata_wlog_error_35; /* .rodata_wlog_error.35 */
extern u32 rodata_wlog_error_36; /* .rodata_wlog_error.36 */
extern u32 rodata_wlog_error_42; /* .rodata_wlog_error.42 */
extern u32 rodata_wlog_error_51; /* .rodata_wlog_error.51 */
extern u32 rodata_wlog_error_52; /* .rodata_wlog_error.52 */
extern u32 rodata_wlog_error_54; /* .rodata_wlog_error.54 */
extern u32 rodata_wlog_error_57; /* .rodata_wlog_error.57 */
extern u32 rodata_wlog_error_59; /* .rodata_wlog_error.59 */
extern u32 rodata_wlog_error_67; /* .rodata_wlog_error.67 */
extern u32 rodata_wlog_error_69; /* .rodata_wlog_error.69 */
extern u32 rodata_wlog_error_70; /* .rodata_wlog_error.70 */
extern u32 rodata_wlog_error_71; /* .rodata_wlog_error.71 */
extern u32 rodata_wlog_error_73; /* .rodata_wlog_error.73 */
extern u32 rodata_wlog_error_74; /* .rodata_wlog_error.74 */
extern u32 rodata_wlog_error_76; /* .rodata_wlog_error.76 */
extern u32 rodata_wlog_error_77; /* .rodata_wlog_error.77 */
extern u32 rodata_wlog_error_78; /* .rodata_wlog_error.78 */
extern u32 rodata_wlog_error_79; /* .rodata_wlog_error.79 */
extern u32 rodata_wlog_error_80; /* .rodata_wlog_error.80 */
extern u32 rodata_wlog_error_81; /* .rodata_wlog_error.81 */
extern u32 rodata_wlog_error_82; /* .rodata_wlog_error.82 */
extern u32 rodata_wlog_error_83; /* .rodata_wlog_error.83 */
extern u32 rodata_wlog_error_84; /* .rodata_wlog_error.84 */
extern u32 rodata_wlog_error_85; /* .rodata_wlog_error.85 */
extern u32 rodata_wlog_error_86; /* .rodata_wlog_error.86 */
extern u32 rodata_wlog_error_88; /* .rodata_wlog_error.88 */
extern u32 rodata_wlog_error_99; /* .rodata_wlog_error.99 */
extern u32 rodata_wlog_info_103; /* .rodata_wlog_info.103 */
extern u32 rodata_wlog_info_104; /* .rodata_wlog_info.104 */
extern u32 rodata_wlog_info_128; /* .rodata_wlog_info.128 */
extern u32 rodata_wlog_info_129; /* .rodata_wlog_info.129 */
extern u32 rodata_wlog_info_130; /* .rodata_wlog_info.130 */
extern u32 rodata_wlog_info_131; /* .rodata_wlog_info.131 */
extern u32 rodata_wlog_info_132; /* .rodata_wlog_info.132 */
extern u32 rodata_wlog_info_134; /* .rodata_wlog_info.134 */
extern u32 rodata_wlog_info_150; /* .rodata_wlog_info.150 */
extern u32 rodata_wlog_info_151; /* .rodata_wlog_info.151 */
extern u32 rodata_wlog_info_17; /* .rodata_wlog_info.17 */
extern u32 rodata_wlog_info_170; /* .rodata_wlog_info.170 */
extern u32 rodata_wlog_info_172; /* .rodata_wlog_info.172 */
extern u32 rodata_wlog_info_184; /* .rodata_wlog_info.184 */
extern u32 rodata_wlog_info_185; /* .rodata_wlog_info.185 */
extern u32 rodata_wlog_info_24; /* .rodata_wlog_info.24 */
extern u32 rodata_wlog_info_34; /* .rodata_wlog_info.34 */
extern u32 rodata_wlog_info_53; /* .rodata_wlog_info.53 */
extern u32 rodata_wlog_info_72; /* .rodata_wlog_info.72 */
extern u32 rodata_wlog_info_75; /* .rodata_wlog_info.75 */
extern u32 rodata_wlog_info_90; /* .rodata_wlog_info.90 */
extern u32 rodata_wlog_info_91; /* .rodata_wlog_info.91 */
extern u32 rodata_wlog_info_92; /* .rodata_wlog_info.92 */
extern u32 rodata_wlog_info_93; /* .rodata_wlog_info.93 */
extern u32 rodata_wlog_verbose_108; /* .rodata_wlog_verbose.108 */
extern u32 rodata_wlog_verbose_122; /* .rodata_wlog_verbose.122 */
extern u32 rodata_wlog_verbose_123; /* .rodata_wlog_verbose.123 */
extern u32 rodata_wlog_verbose_124; /* .rodata_wlog_verbose.124 */
extern u32 rodata_wlog_warning_101; /* .rodata_wlog_warning.101 */
extern u32 rodata_wlog_warning_112; /* .rodata_wlog_warning.112 */
extern u32 rodata_wlog_warning_125; /* .rodata_wlog_warning.125 */
extern u32 rodata_wlog_warning_127; /* .rodata_wlog_warning.127 */
extern u32 rodata_wlog_warning_133; /* .rodata_wlog_warning.133 */
extern u32 rodata_wlog_warning_148; /* .rodata_wlog_warning.148 */
extern u32 rodata_wlog_warning_149; /* .rodata_wlog_warning.149 */
extern u32 rodata_wlog_warning_16; /* .rodata_wlog_warning.16 */
extern u32 rodata_wlog_warning_161; /* .rodata_wlog_warning.161 */
extern u32 rodata_wlog_warning_18; /* .rodata_wlog_warning.18 */
extern u32 rodata_wlog_warning_180; /* .rodata_wlog_warning.180 */
extern u32 rodata_wlog_warning_181; /* .rodata_wlog_warning.181 */
extern u32 rodata_wlog_warning_182; /* .rodata_wlog_warning.182 */
extern u32 rodata_wlog_warning_19; /* .rodata_wlog_warning.19 */
extern u32 rodata_wlog_warning_21; /* .rodata_wlog_warning.21 */
extern u32 rodata_wlog_warning_22; /* .rodata_wlog_warning.22 */
extern u32 rodata_wlog_warning_27; /* .rodata_wlog_warning.27 */
extern u32 rodata_wlog_warning_37; /* .rodata_wlog_warning.37 */
extern u32 rodata_wlog_warning_38; /* .rodata_wlog_warning.38 */
extern u32 rodata_wlog_warning_39; /* .rodata_wlog_warning.39 */
extern u32 rodata_wlog_warning_43; /* .rodata_wlog_warning.43 */
extern u32 rodata_wlog_warning_55; /* .rodata_wlog_warning.55 */
extern u32 rodata_wlog_warning_56; /* .rodata_wlog_warning.56 */
extern u32 rodata_wlog_warning_58; /* .rodata_wlog_warning.58 */
extern u32 rodata_wlog_warning_60; /* .rodata_wlog_warning.60 */
extern u32 rodata_wlog_warning_61; /* .rodata_wlog_warning.61 */
extern u32 rodata_wlog_warning_62; /* .rodata_wlog_warning.62 */
extern u32 rodata_wlog_warning_63; /* .rodata_wlog_warning.63 */
extern u32 rodata_wlog_warning_87; /* .rodata_wlog_warning.87 */
extern u32 rodata_wlog_warning_89; /* .rodata_wlog_warning.89 */
extern u32 rodata_wlog_warning_97; /* .rodata_wlog_warning.97 */
extern u32 rodata_wlog_warning_98; /* .rodata_wlog_warning.98 */
extern u32 text_scan_done_restore_mac_wrapper; /* .text.scan_done_restore_mac_wrapper */
extern u32 text_wifi_wps_start; /* .text.wifi_wps_start */
extern u32 text_wifi_wps_stop; /* .text.wifi_wps_stop */
extern u32 ant_dft_cfg(); /* ant_dft_cfg */
extern u32 ant_wifirx_cfg(); /* ant_wifirx_cfg */
extern u32 ant_wifitx_cfg(); /* ant_wifitx_cfg */
extern u32 app_scan_params; /* app_scan_params */
extern u32 band2str(); /* band2str */
extern u32 chm_cancel_op(); /* chm_cancel_op */
extern u32 chm_deinit(); /* chm_deinit */
extern u32 chm_get_band_from_chan(); /* chm_get_band_from_chan */
extern u32 chm_get_current_band(); /* chm_get_current_band */
extern u32 chm_get_current_channel(); /* chm_get_current_channel */
extern u32 chm_get_home_channel(); /* chm_get_home_channel */
extern u32 chm_init(); /* chm_init */
extern u32 chm_set_current_channel(); /* chm_set_current_channel */
extern u32 chm_set_home_channel(); /* chm_set_home_channel */
extern u32 chm_set_snd_chan(); /* chm_set_snd_chan */
extern u32 clear_bss_queue(); /* clear_bss_queue */
extern u32 cnx_clear_blacklist(); /* cnx_clear_blacklist */
extern u32 cnx_csa_cancel_pending_connect(); /* cnx_csa_cancel_pending_connect */
extern u32 cnx_get_authtype_strength(); /* cnx_get_authtype_strength */
extern u32 cnx_node_leave(); /* cnx_node_leave */
extern u32 cnx_node_search(); /* cnx_node_search */
extern u32 cnx_remove_all_rc(); /* cnx_remove_all_rc */
extern u32 cnx_softap_csa(); /* cnx_softap_csa */
extern u32 cnx_sta_connect_cmd(); /* cnx_sta_connect_cmd */
extern u32 cnx_sta_scan_cmd(); /* cnx_sta_scan_cmd */
extern u32 cnx_start_obss_scan(); /* cnx_start_obss_scan */
extern u32 cnx_stop_obss_scan(); /* cnx_stop_obss_scan */
extern u32 coex_bt_high_prio(); /* coex_bt_high_prio */
extern u32 esf_buf_setup_for_mesh(); /* esf_buf_setup_for_mesh */
extern u32 esp_mesh_quick_funcs; /* esp_mesh_quick_funcs */
extern u32 esp_wifi_get_config(); /* esp_wifi_get_config */
extern u32 esp_wifi_get_mode(); /* esp_wifi_get_mode */
extern u32 esp_wifi_ipc_internal(); /* esp_wifi_ipc_internal */
extern u32 free_bss_info(); /* free_bss_info */
extern u32 gScanStruct; /* gScanStruct */
extern u32 g_cnxMgr; /* g_cnxMgr */
extern u32 g_cnxMgr_0xf74; /* g_cnxMgr+0xf74 */
extern u32 g_ic; /* g_ic */
extern u32 g_ic_0x130; /* g_ic+0x130 */
extern u32 g_ic_0x200; /* g_ic+0x200 */
extern u32 g_ic_0x20c; /* g_ic+0x20c */
extern u32 g_ic_0x212; /* g_ic+0x212 */
extern u32 g_ic_0x218; /* g_ic+0x218 */
extern u32 g_ic_0x234; /* g_ic+0x234 */
extern u32 g_ic_0x2c8; /* g_ic+0x2c8 */
extern u32 g_ic_0x2dc; /* g_ic+0x2dc */
extern u32 g_ic_0x2fa; /* g_ic+0x2fa */
extern u32 g_log_mod; /* g_log_mod */
extern u32 g_mac_sleep_en; /* g_mac_sleep_en */
extern u32 g_mesh_is_root; /* g_mesh_is_root */
extern u32 g_mesh_root_conflicts_allowed; /* g_mesh_root_conflicts_allowed */
extern u32 g_misc_nvs; /* g_misc_nvs */
extern u32 g_nan_started; /* g_nan_started */
extern u32 g_osi_funcs_p; /* g_osi_funcs_p */
extern u32 g_rmac_scan_saved; /* g_rmac_scan_saved */
extern u32 g_rmac_scan_saved_mac; /* g_rmac_scan_saved_mac */
extern u32 g_wdev_last_desc_reset; /* g_wdev_last_desc_reset */
extern u32 g_wifi_event_mask; /* g_wifi_event_mask */
extern u32 g_wifi_global_lock; /* g_wifi_global_lock */
extern u32 g_wifi_mac_time_delta; /* g_wifi_mac_time_delta */
extern u32 g_wifi_menuconfig; /* g_wifi_menuconfig */
extern u32 g_wifi_nvs; /* g_wifi_nvs */
extern u32 hal_get_tsf_time(); /* hal_get_tsf_time */
extern u32 hexstr2bin(); /* hexstr2bin */
extern u32 hostap_add_in_mac_list(); /* hostap_add_in_mac_list */
extern u32 hostap_del_mac_info_from_list(); /* hostap_del_mac_info_from_list */
extern u32 hostap_ht_operation_update(); /* hostap_ht_operation_update */
extern u32 hostap_query_mac_in_list(); /* hostap_query_mac_in_list */
extern u32 ic_clear_interrupt_handler(); /* ic_clear_interrupt_handler */
extern u32 ic_csi_set_config(); /* ic_csi_set_config */
extern u32 ic_deinit(); /* ic_deinit */
extern u32 ic_disable_rx(); /* ic_disable_rx */
extern u32 ic_enable_rx(); /* ic_enable_rx */
extern u32 ic_get_G6M_sched(); /* ic_get_G6M_sched */
extern u32 ic_get_pp_hdl(); /* ic_get_pp_hdl */
extern u32 ic_init(); /* ic_init */
extern u32 ic_mac_deinit(); /* ic_mac_deinit */
extern u32 ic_mac_init(); /* ic_mac_init */
extern u32 ic_register_config_cb(); /* ic_register_config_cb */
extern u32 ic_register_pm_tx_null_cb(); /* ic_register_pm_tx_null_cb */
extern u32 ic_register_timer_cb(); /* ic_register_timer_cb */
extern u32 ic_register_timer_post_cb(); /* ic_register_timer_post_cb */
extern u32 ic_set_beacon_int(); /* ic_set_beacon_int */
extern u32 ic_set_csi(); /* ic_set_csi */
extern u32 ic_set_fix_rate(); /* ic_set_fix_rate */
extern u32 ic_set_interrupt_handler(); /* ic_set_interrupt_handler */
extern u32 ic_set_mac(); /* ic_set_mac */
extern u32 ic_set_promis_ctrl_filter(); /* ic_set_promis_ctrl_filter */
extern u32 ic_set_promis_filter(); /* ic_set_promis_filter */
extern u32 ic_set_vif(); /* ic_set_vif */
extern u32 ic_stop_hw_txq(); /* ic_stop_hw_txq */
extern u32 ic_stop_sw_txq(); /* ic_stop_sw_txq */
extern u32 ic_txq_empty(); /* ic_txq_empty */
extern u32 ic_update_listen_interval(); /* ic_update_listen_interval */
extern u32 ieee80211_action_vendor_reset_seq_state(); /* ieee80211_action_vendor_reset_seq_state */
extern u32 ieee80211_adjust_2nd_chan(); /* ieee80211_adjust_2nd_chan */
extern u32 ieee80211_cnx_attach(); /* ieee80211_cnx_attach */
extern u32 ieee80211_empty_txq(); /* ieee80211_empty_txq */
extern u32 ieee80211_espnow_get_init_flag(); /* ieee80211_espnow_get_init_flag */
extern u32 ieee80211_get_robustmgtframe(); /* ieee80211_get_robustmgtframe */
extern u32 ieee80211_getmgtframe(); /* ieee80211_getmgtframe */
extern u32 ieee80211_ht_attach(); /* ieee80211_ht_attach */
extern u32 ieee80211_ht_deattach(); /* ieee80211_ht_deattach */
extern u32 ieee80211_ifattach(); /* ieee80211_ifattach */
extern u32 ieee80211_ifdetach(); /* ieee80211_ifdetach */
extern u32 ieee80211_is_40mhz_valid_bw(); /* ieee80211_is_40mhz_valid_bw */
extern u32 ieee80211_is_robust_mgmt_frm(); /* ieee80211_is_robust_mgmt_frm */
extern u32 ieee80211_mesh_quick_deinit(); /* ieee80211_mesh_quick_deinit */
extern u32 ieee80211_mesh_quick_init(); /* ieee80211_mesh_quick_init */
extern u32 ieee80211_mgmt_output(); /* ieee80211_mgmt_output */
extern u32 ieee80211_output_init(); /* ieee80211_output_init */
extern u32 ieee80211_phy_init(); /* ieee80211_phy_init */
extern u32 ieee80211_pm_tx_null_process; /* ieee80211_pm_tx_null_process */
extern u32 ieee80211_psq_init(); /* ieee80211_psq_init */
extern u32 ieee80211_public_action_send_mesh_awake(); /* ieee80211_public_action_send_mesh_awake */
extern u32 ieee80211_regdomain_ap_max_chan(); /* ieee80211_regdomain_ap_max_chan */
extern u32 ieee80211_regdomain_ap_min_chan(); /* ieee80211_regdomain_ap_min_chan */
extern u32 ieee80211_regdomain_check_ap_channel(); /* ieee80211_regdomain_check_ap_channel */
extern u32 ieee80211_regdomain_check_channel(); /* ieee80211_regdomain_check_channel */
extern u32 ieee80211_regdomain_get_country(); /* ieee80211_regdomain_get_country */
extern u32 ieee80211_regdomain_get_country_info(); /* ieee80211_regdomain_get_country_info */
extern u32 ieee80211_scan_attach(); /* ieee80211_scan_attach */
extern u32 ieee80211_scan_deattach(); /* ieee80211_scan_deattach */
extern u32 ieee80211_send_mgmt(); /* ieee80211_send_mgmt */
extern u32 ieee80211_set_hmac_stop(); /* ieee80211_set_hmac_stop */
extern u32 ieee80211_set_tx_desc(); /* ieee80211_set_tx_desc */
extern u32 ieee80211_sta_is_connected(); /* ieee80211_sta_is_connected */
extern u32 ieee80211_sta_new_state(); /* ieee80211_sta_new_state */
extern u32 ieee80211_timer_do_process; /* ieee80211_timer_do_process */
extern u32 ieee80211_timer_process(); /* ieee80211_timer_process */
extern u32 ieee80211_update_phy_country(); /* ieee80211_update_phy_country */
extern u32 ieee80211_vnd_mesh_quick_get(); /* ieee80211_vnd_mesh_quick_get */
extern u32 ieee80211_vnd_mesh_quick_set(); /* ieee80211_vnd_mesh_quick_set */
extern u32 ieee80211_vnd_mesh_roots_get(); /* ieee80211_vnd_mesh_roots_get */
extern u32 ieee80211_vnd_mesh_roots_set(); /* ieee80211_vnd_mesh_roots_set */
extern u32 is_off_channel(); /* is_off_channel */
extern u32 map_assoc_expire; /* map_assoc_expire */
extern u32 memcmp(); /* memcmp */
extern u32 memcpy(); /* memcpy */
extern u32 memset(); /* memset */
extern u32 mesh_clear_parent_candidate(); /* mesh_clear_parent_candidate */
extern u32 mesh_get_parent_candidate(); /* mesh_get_parent_candidate */
extern u32 mesh_get_parent_monitor_config(); /* mesh_get_parent_monitor_config */
extern u32 mesh_get_rssi_threshold(); /* mesh_get_rssi_threshold */
extern u32 mesh_set_ie_crypto_config(); /* mesh_set_ie_crypto_config */
extern u32 mesh_set_parent_candidate(); /* mesh_set_parent_candidate */
extern u32 mesh_set_parent_monitor_config(); /* mesh_set_parent_monitor_config */
extern u32 mesh_set_rssi_threshold(); /* mesh_set_rssi_threshold */
extern u32 misc_nvs_restore(); /* misc_nvs_restore */
extern u32 nan_cancel_service(); /* nan_cancel_service */
extern u32 nan_datapath_end(); /* nan_datapath_end */
extern u32 nan_datapath_send_req(); /* nan_datapath_send_req */
extern u32 nan_datapath_send_resp(); /* nan_datapath_send_resp */
extern u32 nan_register_callbacks(); /* nan_register_callbacks */
extern u32 nan_send_followup_msg(); /* nan_send_followup_msg */
extern u32 nan_set_config_local(); /* nan_set_config_local */
extern u32 nan_start(); /* nan_start */
extern u32 nan_start_publish_service(); /* nan_start_publish_service */
extern u32 nan_start_subscribe_service(); /* nan_start_subscribe_service */
extern u32 nan_stop(); /* nan_stop */
extern u32 net80211_funcs; /* net80211_funcs */
extern u32 offchan_action_tx_req(); /* offchan_action_tx_req */
extern u32 offchan_in_progress(); /* offchan_in_progress */
extern u32 offchan_roc_req(); /* offchan_roc_req */
extern u32 offchan_trigger_in_progress(); /* offchan_trigger_in_progress */
extern u32 phy_set_most_tpw(); /* phy_set_most_tpw */
extern u32 pm_coex_pwr_configure(); /* pm_coex_pwr_configure */
extern u32 pm_coex_schm_process(); /* pm_coex_schm_process */
extern u32 pm_connectionless_module_set_wake_interval(); /* pm_connectionless_module_set_wake_interval */
extern u32 pm_disconnected_start(); /* pm_disconnected_start */
extern u32 pm_disconnected_stop(); /* pm_disconnected_stop */
extern u32 pm_mac_sleep(); /* pm_mac_sleep */
extern u32 pm_mac_wakeup(); /* pm_mac_wakeup */
extern u32 pm_noise_check_disable(); /* pm_noise_check_disable */
extern u32 pm_noise_check_enable(); /* pm_noise_check_enable */
extern u32 pm_on_coex_start(); /* pm_on_coex_start */
extern u32 pm_on_sample_beacon(); /* pm_on_sample_beacon */
extern u32 pm_register_connectionless_wake_window(); /* pm_register_connectionless_wake_window */
extern u32 pm_set_sleep_type(); /* pm_set_sleep_type */
extern u32 pm_tbtt_quick_wake_configure(); /* pm_tbtt_quick_wake_configure */
extern u32 pm_unregister_connectionless_wake_window(); /* pm_unregister_connectionless_wake_window */
extern u32 pm_wake_done(); /* pm_wake_done */
extern u32 pm_wake_up(); /* pm_wake_up */
extern u32 pp_post(); /* pp_post */
extern u32 reset_cs_thres(); /* reset_cs_thres */
extern u32 s_ioctl_table; /* s_ioctl_table */
extern u32 s_wifi_stop_in_progress; /* s_wifi_stop_in_progress */
extern u32 s_wifi_task_hdl; /* s_wifi_task_hdl */
extern u32 scan_cancel(); /* scan_cancel */
extern u32 scan_flush_all_tx_buf(); /* scan_flush_all_tx_buf */
extern u32 scan_get_apnum(); /* scan_get_apnum */
extern u32 scan_reset_default_app_params(); /* scan_reset_default_app_params */
extern u32 scan_reset_offchan_duration(); /* scan_reset_offchan_duration */
extern u32 scannum; /* scannum */
extern u32 sta_is_wpa3_enabled(); /* sta_is_wpa3_enabled */
extern u32 sta_rx_csa(); /* sta_rx_csa */
extern u32 sta_set_rmac_restart; /* sta_set_rmac_restart */
extern u32 strlen(); /* strlen */
extern u32 strnlen(); /* strnlen */
extern u32 wDev_Set_Beacon_Int(); /* wDev_Set_Beacon_Int */
extern u32 wifi_ap_reg_rxcb(); /* wifi_ap_reg_rxcb */
extern u32 wifi_api_lock(); /* wifi_api_lock */
extern u32 wifi_api_unlock(); /* wifi_api_unlock */
extern u32 wifi_check_chan_param(); /* wifi_check_chan_param */
extern u32 wifi_destroy_nan(); /* wifi_destroy_nan */
extern u32 wifi_destroy_sta(); /* wifi_destroy_sta */
extern u32 wifi_event_post(); /* wifi_event_post */
extern u32 wifi_get_init_state(); /* wifi_get_init_state */
extern u32 wifi_is_stop_in_progress(); /* wifi_is_stop_in_progress */
extern u32 wifi_log(); /* wifi_log */
extern u32 wifi_mode_set(); /* wifi_mode_set */
extern u32 wifi_nan_reg_rxcb(); /* wifi_nan_reg_rxcb */
extern u32 wifi_nvs_commit(); /* wifi_nvs_commit */
extern u32 wifi_nvs_compare_cfg_diff(); /* wifi_nvs_compare_cfg_diff */
extern u32 wifi_nvs_deinit(); /* wifi_nvs_deinit */
extern u32 wifi_nvs_get(); /* wifi_nvs_get */
extern u32 wifi_nvs_init(); /* wifi_nvs_init */
extern u32 wifi_nvs_reset_current_ap_info(); /* wifi_nvs_reset_current_ap_info */
extern u32 wifi_nvs_restore(); /* wifi_nvs_restore */
extern u32 wifi_nvs_set(); /* wifi_nvs_set */
extern u32 wifi_set_default_ssid(); /* wifi_set_default_ssid */
extern u32 wifi_set_rx_policy(); /* wifi_set_rx_policy */
extern u32 wifi_sta_reg_rxcb(); /* wifi_sta_reg_rxcb */
extern u32 wifi_sta_set_scan_default_params(); /* wifi_sta_set_scan_default_params */
extern u32 wifi_station_start(); /* wifi_station_start */
extern u32 wifi_station_stop(); /* wifi_station_stop */
extern u32 wpa_crypto_funcs; /* wpa_crypto_funcs */

/* DISPATCH (verified offline from relocs + rodata):
 * .data.s_ioctl_table (24B) = 3 x { u32 cmd_id; u32 handler }:
 *    id 1 -> wifi_ioctl_ht2040_set   (R_XTENSA_32 @+4)
 *    id 2 -> wifi_ioctl_ht2040_get   (R_XTENSA_32 @+0xc)
 *    id 3 -> NULL                    (no reloc; reserved slot)
 * Byte-maps (verified via objdump -s):
 *   .rodata.CSWTCH$424 (4B: 02 00 01 02): used by map_wifi_config_sae_pwe_to_supp;
 *     range-gated (bgeui a2,4 -> default -1), sext-7 lookup for inputs 0..3.
 *   .rodata.CSWTCH$491 (11B: 00 03 0c 04 0c 0c 0c 01 02 0c 07): used by
 *     cipher_map_net80211_to_public_cipher; range-gated by immediates 10/12.
 *   .rodata.CSWTCH$391 (10B: 01 00 01 01 01 00 01 01 00 01): consulted by
 *     wifi_softap_set_config (index expression not recovered).
 * ieee80211_ioctl (caller gate): req byte@0 = cmd id (range-checked vs 121),
 *   byte@1 = flags (bit0 = in-wifi-task path, bit1 set when continuing);
 *   cmd 49 with arg 2 takes an early branch. Accesses g_osi_funcs_p slots
 *   +68/+176 indirectly; posts async work via pp_post(type 6, ...);
 *   init-state must be 3 (wifi_get_init_state); returns 0x101/0x102/0x3001-class codes.
 * ieee80211_ioctl_process (wifi-task side): handler = *(u32*)(req+4), invoked as
 *   handler(req) with pm_wake_up()/pm_wake_done() pairing, EXCEPT cmd ids in
 *   [52,54] (addi -52 / bltui 3) and [57,81] (addi -57 / bgeu 24) which bypass
 *   the wake pairing. Mesh-root gating reads g_ic+116.
 */
/* ---- literal-rooted access patterns (offsets observed; layout NOT confirmed) ----
 * &memcpy(): u32+160
 * (*(?+10)+40): u32+0
 * (*(g_wifi_nvs+0)+196608): u32+246
 * (1+1): u8+2
 * (lit:g_ic+131072): u8+31, u32+31, u16+31
 * (ret@595+262144): u32+4
 * *(?+12): u8+1, u32+2, u8+2
 * *(g_ic+16): u8+228
 * .bss.g_rmac_original_scan_cb: u32+0
 * .bss.overwrite_save_ap_id$0: u8+0
 * .bss.s_rmac_was_enabled: u8+0, u8+149
 * .bss.s_wpa2_start: u8+0
 * .bss.s_wps_start: u8+0
 * .rodata.CSWTCH$391: u8+0
 * .rodata.CSWTCH$424: u8+0
 * .rodata.CSWTCH$491: u8+0
 * ?: u16+12, u8+12, u32+12, u32+20, u16+20, u8+20, u32+68, u8+236, u16+236
 * app_scan_params: u32+0, u32+4, u32+8, u8+12, u16+14
 * esp_mesh_quick_funcs: u32+48, u32+152, u32+156, u32+164
 * gScanStruct: u8+70
 * g_ic: u32+16, u32+16, u32+20, u32+20, u32+31, u32+44, u32+64, u32+85, u32+116, u32+228, u8+228, u32+304, u32+436, u32+0x1b4 (+12 more)
 * g_log_mod: u32+0
 * g_mac_sleep_en: u8+0
 * g_mesh_is_root: u8+0
 * g_misc_nvs: u32+0
 * g_nan_started: u8+0
 * g_osi_funcs_p: u32+0, u32+0, u8+64, u32+232
 * g_rmac_scan_saved: u8+0
 * g_rmac_scan_saved_mac: u8+0, u8+1, u8+2, u8+3, u8+4, u8+5
 * g_wifi_global_lock: u32+0
 * g_wifi_menuconfig: u16+0, u32+0, u32+8, u32+12, u32+32, u32+64, u32+80, u8+97, u8+98, u32+100
 * g_wifi_nvs: u32+0, u8+0, u32+0, u32+16, u32+116, u8+228, u8+251
 * net80211_funcs: u32+0, u32+0
 * ret@255: u32+44
 * ret@5a7: u8+0
 * s_ioctl_table: u32+0, u32+4
 * s_wifi_stop_in_progress: u8+0
 * s_wifi_task_hdl: u32+0
 * scannum: u16+0
 * wpa_crypto_funcs: u8+12, u16+12, u32+12
/* ---- funcdb-v2 cross-check (calls[] vs section relocs; disasm is ground truth) ----
 * confirmed funcdb edges: 447; rejected funcdb-only (no exact reloc in
 * callee section; caller-side .rela.text.<f> prefix-collision artifacts): 0;
 * disasm-only edges kept (static-local callees + funcdb relsec:null gaps): 59;
 *   e.g. wifi_check_and_handle_rmac_timer_pending->.text.wifi_set_rmac_timer, _do_wifi_start->.text.wifi_pmk_is_valid, wifi_softap_set_config->.text.wifi_pmk_is_valid, wifi_rf_phy_enable->ic_mac_init, wifi_rf_phy_enable->pm_mac_wakeup, wifi_rf_phy_enable->wifi_log, wifi_rf_phy_disable->ic_mac_deinit, wifi_rf_phy_disable->pm_mac_sleep
 */
/* ==== functions of ieee80211_ioctl.o ==== */

/* wifi_wps_stop @ ieee80211_ioctl.o 0x00000004 size 25B bind LOCAL
 * Calls: none | Data refs: .bss.s_wps_start
 * Fidelity: high - straight-line, fully mapped (8 insns) */
u32 wifi_wps_stop(void)
{
    /* frame: entry a1,32; 8 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0 */
    /* mem st8: base=(lit:.bss.s_wps_start) off=0 */
    return 0;
}

/* wifi_wps_start @ ieee80211_ioctl.o 0x00000004 size 25B bind LOCAL
 * Calls: none | Data refs: .bss.s_wps_start
 * Fidelity: high - straight-line, fully mapped (8 insns) */
u32 wifi_wps_start(void)
{
    /* frame: entry a1,32; 8 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* immediates: 1, 0 */
    /* mem st8: base=(lit:.bss.s_wps_start) off=0 */
    return 0;
}

/* wifi_ioctl_ht2040_get @ ieee80211_ioctl.o 0x00000004 size 25B bind GLOBAL
 * Calls: none | Data refs: g_ic
 * Fidelity: high - straight-line, fully mapped (9 insns) */
u32 wifi_ioctl_ht2040_get(u32 a2)
{
    /* frame: entry a1,32; 9 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0 */
    /* mem ld32: base=(lit:g_ic) off=0x248 */
    /* mem st8: base=(?) off=0 */
    return 0;
}

/* wifi_pmk_is_valid @ ieee80211_ioctl.o 0x00000008 size 45B bind LOCAL
 * Calls: memset, memcmp | Data refs: none
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 wifi_pmk_is_valid(u32 a2)
{
    /* frame: entry a1,64; 15 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* immediates: 32, 255, 0, 1 */
    /* site +0x15: memset(?, 255, 32) */
    memset(?, 255, 32);
    /* site +0x21: memcmp(?, ?, 32) */
    memcmp(?, ?, 32);
    return opaque_result; /* full dataflow not recovered */
}

/* ieee80211_ioctl_process @ ieee80211_ioctl.o 0x00000024 size 226B bind GLOBAL
 * Calls: wifi_log, pm_wake_up, indirect(a3), pm_wake_done, indirect(a4), indirect(a2), wifi_log | Data refs: .rodata_wlog_error.179, g_ic, g_mesh_is_root, g_osi_funcs_p, .rodata_wlog_warning.180
 * Fidelity: low - 82 insns, 14 branches, 0 loops; skeleton only */
u32 ieee80211_ioctl_process(u32 a2)
{
    /* frame: entry a1,32; 82 insns, 14 cond-branches, 0 loops, 3 jumps */
    /* immediates: 1, 2, 0x102, 121, -1, 24 */
    /* first predicate: bnez.n a2, 40 <ieee80211_ioctl_process+0x1c> (condition opaque) */
    /* mem ld8: base=(?) off=0 */
    /* mem ld32: base=(?) off=4 */
    /* mem ld32: base=(lit:g_ic) off=116 */
    /* mem ld8: base=(lit:g_mesh_is_root) off=0 */
    /* mem ld32: base=(?) off=4 */
    /* mem ld32: base=(lit:g_ic) off=116 */
    /* mem ld8: base=(lit:g_mesh_is_root) off=0 */
    /* mem ld8: base=(?) off=0 */
    /* mem ld8: base=(?) off=1 */
    /* mem st32: base=(?) off=12 */
    /* ... +6 more memops */
    /* site +0x35: wifi_log(1, 2, 1, lit:.rodata_wlog_error.179) */
    wifi_log(1, 2, 1, lit:.rodata_wlog_error.179);
    /* site +0x7f: pm_wake_up(ret@35, 2, 1, lit:.rodata_wlog_error.179) */
    pm_wake_up(ret@35, 2, 1, lit:.rodata_wlog_error.179);
    /* site +0x86: indirect call via a3 (base *(?+4)); args: ?, 2, 1, lit:.rodata_wlog_error.179 */
    opaque_indirect_a3();
    /* site +0xb8: pm_wake_done(ret@86, 2, 1, lit:.rodata_wlog_error.179) */
    pm_wake_done(ret@86, 2, 1, lit:.rodata_wlog_error.179);
    /* site +0xd1: indirect call via a4 (base *(g_osi_funcs_p+176)); args: ?, 2, 1, lit:.rodata_wlog_error.179 */
    opaque_indirect_a4();
    /* site +0xea: indirect call via a2 (base *(g_osi_funcs_p+64)); args: *(?+16), 2, 1, lit:.rodata_wlog_error.179 */
    opaque_indirect_a2();
    /* site +0xff: wifi_log(1, 2, 2, lit:.rodata_wlog_warning.180, *(g_osi_funcs_p+0)) */
    wifi_log(1, 2, 2, lit:.rodata_wlog_warning.180, *(g_osi_funcs_p+0));
    return last_call_result; /* opaque */
}

/* sta_set_rmac_restart @ ieee80211_ioctl.o 0x00000004 size 18B bind GLOBAL
 * Calls: ieee80211_timer_process | Data refs: none
 * Fidelity: high - straight-line, fully mapped (7 insns) */
u32 sta_set_rmac_restart(void)
{
    /* frame: entry a1,32; 7 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0, 39, 7 */
    /* site +0x11: ieee80211_timer_process(7, 39, 0) */
    ieee80211_timer_process(7, 39, 0);
    return opaque_result; /* full dataflow not recovered */
}

/* wifi_set_rmac_timer @ ieee80211_ioctl.o 0x00000010 size 104B bind LOCAL
 * Calls: indirect(a8), indirect(a8), indirect(a8), indirect(a4), indirect(a8), indirect(a2) | Data refs: g_osi_funcs_p, g_ic+0x2c8, sta_set_rmac_restart
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 wifi_set_rmac_timer(u32 a2, u32 a4)
{
    /* frame: entry a1,32; 32 insns, 1 cond-branches, 0 loops, 1 jumps */
    /* immediates: 0 */
    /* first predicate: beqz a2, 59 <.text.wifi_set_rmac_timer+0x59> (condition opaque) */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=236 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=240 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=244 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=232 */
    /* mem ld32: base=(*(g_osi_funcs_p+232)) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=240 */
    /* site +0x23: indirect call via a8 (base *(*(g_osi_funcs_p+0)+236)); args: lit:g_osi_funcs_p */
    opaque_indirect_a8();
    /* site +0x2e: indirect call via a8 (base *(*(g_osi_funcs_p+0)+240)); args: ret@23 */
    opaque_indirect_a8();
    /* site +0x3f: indirect call via a8 (base *(*(g_osi_funcs_p+0)+244)); args: lit:g_osi_funcs_p, lit:g_osi_funcs_p, 0 */
    opaque_indirect_a8();
    /* site +0x51: indirect call via a4 (base *(g_osi_funcs_p+232)); args: lit:g_osi_funcs_p, lit:g_osi_funcs_p, 0 */
    opaque_indirect_a4();
    /* site +0x59: indirect call via a8 (base *(*(g_osi_funcs_p+0)+244)); args: ret@51, lit:g_osi_funcs_p, 0 */
    opaque_indirect_a8();
    /* site +0x63: indirect call via a2 (base *(*(g_osi_funcs_p+0)+240)); args: lit:g_osi_funcs_p, lit:g_osi_funcs_p, 0 */
    opaque_indirect_a2();
    return opaque_result; /* full dataflow not recovered */
}

/* wifi_phy_bw_is_valid @ ieee80211_ioctl.o 0x00000010 size 174B bind LOCAL
 * Calls: ieee80211_is_40mhz_valid_bw, wifi_log | Data refs: g_wifi_nvs, .rodata_wlog_warning.16
 * Fidelity: medium - branchy but loop-free, call sequence mapped */
u32 wifi_phy_bw_is_valid(u32 a2, u32 a3, u32 a4)
{
    /* frame: entry a1,32; 56 insns, 11 cond-branches, 0 loops, 11 jumps */
    /* immediates: 0, 253, 1, 2 */
    /* first predicate: bltui a2, 2, 1b <.text.wifi_phy_bw_is_valid+0x1b> (condition opaque) */
    /* mem ld32: base=(lit:g_wifi_nvs) off=0 */
    /* mem ld8: base=(*(g_wifi_nvs+0)) off=0 */
    /* mem ld8: base=((*(g_wifi_nvs+0)+196608)) off=250 */
    /* mem ld8: base=((*(g_wifi_nvs+0)+196608)) off=156 */
    /* mem ld8: base=(((*(g_wifi_nvs+0)+196608)+327680)) off=53 */
    /* mem ld8: base=((((*(g_wifi_nvs+0)+196608)+327680)+262144)) off=158 */
    /* site +0x73: ieee80211_is_40mhz_valid_bw(1) */
    ieee80211_is_40mhz_valid_bw(1);
    /* site +0x8f: wifi_log(1, 2, 2, lit:g_wifi_nvs) */
    wifi_log(1, 2, 2, lit:g_wifi_nvs);
    return 1;
}

/* wifi_ioctl_ht2040_set @ ieee80211_ioctl.o 0x0000001c size 88B bind GLOBAL
 * Calls: wifi_log, cnx_start_obss_scan, wifi_log, cnx_stop_obss_scan | Data refs: .rodata_wlog_info.150, g_ic, .rodata_wlog_info.151
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 wifi_ioctl_ht2040_set(u32 a2)
{
    /* frame: entry a1,32; 33 insns, 1 cond-branches, 0 loops, 1 jumps */
    /* immediates: 1, 3, -2, 0 */
    /* first predicate: beqz.n a8, 4d <wifi_ioctl_ht2040_set+0x31> (condition opaque) */
    /* mem ld8: base=(?) off=0 */
    /* mem ld32: base=(lit:g_ic) off=0x248 */
    /* mem st32: base=(lit:g_ic) off=0x248 */
    /* mem ld32: base=(lit:g_ic) off=0x248 */
    /* mem st32: base=(lit:g_ic) off=0x248 */
    /* site +0x33: wifi_log(1, 1, 3, lit:.rodata_wlog_info.150) */
    wifi_log(1, 1, 3, lit:.rodata_wlog_info.150);
    /* site +0x47: cnx_start_obss_scan(ret@33, 1, 3, lit:.rodata_wlog_info.150) */
    cnx_start_obss_scan(ret@33, 1, 3, lit:.rodata_wlog_info.150);
    /* site +0x59: wifi_log(1, 1, 3, lit:.rodata_wlog_info.151) */
    wifi_log(1, 1, 3, lit:.rodata_wlog_info.151);
    /* site +0x6d: cnx_stop_obss_scan(ret@59, 1, 3, lit:.rodata_wlog_info.151) */
    cnx_stop_obss_scan(ret@59, 1, 3, lit:.rodata_wlog_info.151);
    return 0;
}

/* is_valid_sta_mac @ ieee80211_ioctl.o 0x00000000 size 64B bind LOCAL
 * Calls: none | Data refs: none
 * Fidelity: low - 26 insns, 4 branches, 1 loops; skeleton only */
u32 is_valid_sta_mac(u32 a2)
{
    /* frame: entry a1,32; 26 insns, 4 cond-branches, 1 loops, 2 jumps */
    /* immediates: 0, 1, 255, 6, -1 */
    /* first predicate: loop a10, 29 <.text.is_valid_sta_mac+0x29> (condition opaque) */
    /* mem ld8: base=(?) off=0 */
    /* mem ld8: base=(?) off=0 */
    return 0;
}

/* wifi_check_and_handle_rmac_timer_pending @ ieee80211_ioctl.o 0x00000014 size 69B bind GLOBAL
 * Calls: wifi_log, wifi_set_rmac_timer | Data refs: g_ic, .rodata_wlog_debug.3, g_wifi_menuconfig
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 wifi_check_and_handle_rmac_timer_pending(u32 a2)
{
    /* frame: entry a1,32; 25 insns, 1 cond-branches, 0 loops, 0 jumps */
    /* immediates: 4, 1, 0 */
    /* first predicate: beqz.n a3, 54 <wifi_check_and_handle_rmac_timer_pending+0x40> (condition opaque) */
    /* mem ld8: base=((lit:g_ic+131072)) off=255 */
    /* mem ld8: base=(lit:g_wifi_menuconfig) off=98 */
    /* mem st16: base=((lit:g_ic+131072)) off=250 */
    /* mem st16: base=((lit:g_ic+131072)) off=252 */
    /* mem st8: base=((lit:g_ic+131072)) off=254 */
    /* mem st8: base=((lit:g_ic+131072)) off=255 */
    /* site +0x2e: wifi_log(1, 4, 4, lit:.rodata_wlog_debug.3) */
    wifi_log(1, 4, 4, lit:.rodata_wlog_debug.3);
    /* site +0x4b: wifi_set_rmac_timer(*(g_wifi_menuconfig+98), 4, 4, lit:.rodata_wlog_debug.3) */
    wifi_set_rmac_timer(*(g_wifi_menuconfig+98), 4, 4, lit:.rodata_wlog_debug.3);
    return opaque_result; /* full dataflow not recovered */
}

/* current_task_is_wifi_task @ ieee80211_ioctl.o 0x00000008 size 31B bind GLOBAL
 * Calls: indirect(a10) | Data refs: g_osi_funcs_p, s_wifi_task_hdl
 * Fidelity: high - straight-line, fully mapped (12 insns) */
u32 current_task_is_wifi_task(u32 a2)
{
    /* frame: entry a1,32; 12 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0, 1 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=164 */
    /* mem ld32: base=(lit:s_wifi_task_hdl) off=0 */
    /* site +0x13: indirect call via a10 (base *(g_osi_funcs_p+164)); args: *(g_osi_funcs_p+164) */
    opaque_indirect_a10();
    return opaque_result; /* full dataflow not recovered */
}

/* adc2_wifi_acquire @ ieee80211_ioctl.o 0x00000000 size 7B bind GLOBAL
 * Calls: none | Data refs: none
 * Fidelity: high - straight-line, fully mapped (3 insns) (weak) */
u32 adc2_wifi_acquire(void)
{
    /* frame: entry a1,32; 3 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0 */
    return 0;
}

/* adc2_wifi_release @ ieee80211_ioctl.o 0x00000000 size 7B bind GLOBAL
 * Calls: none | Data refs: none
 * Fidelity: high - straight-line, fully mapped (3 insns) (weak) */
u32 adc2_wifi_release(void)
{
    /* frame: entry a1,32; 3 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0 */
    return 0;
}

/* _do_wifi_start @ ieee80211_ioctl.o 0x00000034 size 199B bind GLOBAL
 * Calls: wifi_nvs_get, wifi_pmk_is_valid, wifi_station_start, wifi_log, indirect(a10), nan_start, wifi_log | Data refs: g_ic, g_ic+0x212, .rodata_wlog_debug.11, net80211_funcs, .rodata_wlog_debug.12, .rodata_wlog_debug.13, g_ic+0x200
 * Fidelity: low - 72 insns, 10 branches, 0 loops; skeleton only */
u32 do_wifi_start(u32 a2)
{
    /* frame: entry a1,32; 72 insns, 10 cond-branches, 0 loops, 4 jumps */
    /* immediates: 0, -3, 0x10b, 4, 2, 1, 0x102 */
    /* first predicate: beqi a2, 1, 4e <_do_wifi_start+0x1a> (condition opaque) */
    /* mem ld8: base=((lit:g_ic+65536)) off=238 */
    /* mem ld32: base=(ret@5b) off=4 */
    /* mem ld8: base=(ret@5b) off=159 */
    /* mem st8: base=(lit:g_ic+0x200) off=6 */
    /* mem st8: base=(lit:g_ic+0x200) off=6 */
    /* mem ld32: base=(lit:net80211_funcs) off=0 */
    /* mem ld32: base=(*(net80211_funcs+0)) off=12 */
    /* site +0x5b: wifi_nvs_get(/* no traced args */) */
    wifi_nvs_get(/* no traced args */);
    /* site +0x79: wifi_pmk_is_valid(ret@5b) */
    wifi_pmk_is_valid(ret@5b);
    /* site +0x9f: wifi_station_start(lit:g_ic+0x212) */
    wifi_station_start(lit:g_ic+0x212);
    /* site +0xb2: wifi_log(1, 2, 4, lit:.rodata_wlog_debug.11) */
    wifi_log(1, 2, 4, lit:.rodata_wlog_debug.11);
    /* site +0xc7: indirect call via a10 (base *(net80211_funcs+12)); args: *(net80211_funcs+12), 2, 4, lit:.rodata_wlog_debug.11 */
    opaque_indirect_a10();
    /* site +0xe3: nan_start(ret@c7, 2, 4, lit:.rodata_wlog_debug.12) */
    nan_start(ret@c7, 2, 4, lit:.rodata_wlog_debug.12);
    /* site +0xf6: wifi_log(1, 2, ?, lit:.rodata_wlog_debug.13) */
    wifi_log(1, 2, ?, lit:.rodata_wlog_debug.13);
    return last_call_result; /* opaque */
}

/* ieee80211_set_phy_2nd_chan @ ieee80211_ioctl.o 0x00000008 size 50B bind GLOBAL
 * Calls: none | Data refs: g_wifi_nvs, g_ic
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 ieee80211_set_phy_2nd_chan(u32 a2)
{
    /* frame: entry a1,32; 19 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* immediates: 2, 1 */
    /* mem ld32: base=(lit:g_wifi_nvs) off=0 */
    /* mem ld32: base=(lit:g_ic) off=20 */
    /* mem st8: base=((*(g_wifi_nvs+0)+196608)) off=252 */
    /* mem st8: base=((*(g_ic+20)+65536)) off=87 */
    /* mem st8: base=((lit:g_ic+131072)) off=30 */
    return opaque_result; /* full dataflow not recovered */
}

/* ieee80211_phy_2nd_chan_is_valid @ ieee80211_ioctl.o 0x0000000c size 124B bind GLOBAL
 * Calls: wifi_check_chan_param | Data refs: g_wifi_nvs, g_ic
 * Fidelity: medium - branchy but loop-free, call sequence mapped */
u32 ieee80211_phy_2nd_chan_is_valid(u32 a2)
{
    /* frame: entry a1,32; 44 insns, 13 cond-branches, 0 loops, 1 jumps */
    /* immediates: 0, 8 */
    /* first predicate: bgeui a12, 2, 84 <ieee80211_phy_2nd_chan_is_valid+0x78> (condition opaque) */
    /* mem ld32: base=(lit:g_wifi_nvs) off=0 */
    /* mem ld8: base=(*(g_wifi_nvs+0)) off=0 */
    /* mem ld8: base=((lit:g_ic+131072)) off=174 */
    /* mem ld8: base=((lit:g_ic+131072)) off=166 */
    /* mem ld32: base=(lit:g_ic) off=16 */
    /* mem ld32: base=(*(g_ic+16)) off=228 */
    /* mem ld8: base=(*(g_ic+228)) off=172 */
    /* mem ld8: base=(*(g_ic+228)) off=171 */
    /* mem ld8: base=((*(g_ic+171)+-1)) off=171 */
    /* mem ld8: base=((*(g_wifi_nvs+0)+196608)) off=243 */
    /* site +0x81: wifi_check_chan_param(*((*(g_wifi_nvs+0)+196608)+243), ?, (?+-1), *(*(g_wifi_nvs+0)+0), *((lit:g_ic+131072)+166)) */
    wifi_check_chan_param(*((*(g_wifi_nvs+0)+196608)+243), ?, (?+-1), *(*(g_wifi_nvs+0)+0), *((lit:g_ic+131072)+166));
    return last_call_result; /* opaque */
}

/* ieee80211_set_phy_bw @ ieee80211_ioctl.o 0x00000024 size 265B bind GLOBAL
 * Calls: chm_get_current_band, ieee80211_protocol_attach, ieee80211_protocol_attach, chm_set_snd_chan, wifi_nvs_set, wifi_nvs_commit | Data refs: g_ic, g_wifi_nvs, g_ic+0x200
 * Fidelity: low - 92 insns, 15 branches, 0 loops; skeleton only */
u32 ieee80211_set_phy_bw(u32 a2, u32 a3, u32 a4, u32 a5)
{
    /* frame: entry a1,32; 92 insns, 15 cond-branches, 0 loops, 9 jumps */
    /* immediates: 8, 0x156, 0, 1, 33 */
    /* first predicate: bnez.n a2, 68 <ieee80211_set_phy_bw+0x44> (condition opaque) */
    /* mem ld32: base=(lit:g_ic) off=20 */
    /* mem ld32: base=(lit:g_ic) off=16 */
    /* mem ld8: base=(lit:g_ic+0x200) off=170 */
    /* mem st8: base=(lit:g_ic+0x200) off=170 */
    /* mem ld8: base=(lit:g_ic+0x200) off=176 */
    /* mem ld8: base=(lit:g_ic+0x200) off=166 */
    /* mem st8: base=(lit:g_ic+0x200) off=166 */
    /* mem ld8: base=(lit:g_ic+0x200) off=174 */
    /* mem ld8: base=((*(g_ic+16)+65536)) off=87 */
    /* mem ld8: base=((*(g_ic+16)+65536)) off=86 */
    /* ... +8 more memops */
    /* site +0x35: chm_get_current_band(/* no traced args */) */
    chm_get_current_band(/* no traced args */);
    /* site +0x61: ieee80211_protocol_attach(ret@35, ?, *(g_ic+0x200+176)) */
    ieee80211_protocol_attach(ret@35, ?, *(g_ic+0x200+176));
    /* site +0x99: ieee80211_protocol_attach(*(g_ic+20), ?, *(g_ic+0x200+174)) */
    ieee80211_protocol_attach(*(g_ic+20), ?, *(g_ic+0x200+174));
    /* site +0xd5: chm_set_snd_chan(0x156, ?, *(g_ic+0x200+174)) */
    chm_set_snd_chan(0x156, ?, *(g_ic+0x200+174));
    /* site +0x10d: wifi_nvs_set(33, *((*(g_ic+20)+65536)+87), 1) */
    wifi_nvs_set(33, *((*(g_ic+20)+65536)+87), 1);
    /* site +0x116: wifi_nvs_commit(ret@10d, *((*(g_ic+20)+65536)+87), 1) */
    wifi_nvs_commit(ret@10d, *((*(g_ic+20)+65536)+87), 1);
    return 0;
}

/* ieee80211_protocol_attach @ ieee80211_ioctl.o 0x00000014 size 64B bind GLOBAL
 * Calls: ieee80211_phy_init, ieee80211_ht_attach, ieee80211_ht_deattach, ieee80211_set_phy_bw | Data refs: g_ic
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 ieee80211_protocol_attach(u32 a2, u32 a3, u32 a4)
{
    /* frame: entry a1,32; 24 insns, 3 cond-branches, 0 loops, 1 jumps */
    /* immediates: 1, 0 */
    /* first predicate: beqz.n a2, 52 <ieee80211_protocol_attach+0x3e> (condition opaque) */
    /* mem ld32: base=(lit:g_ic) off=16 */
    /* site +0x23: ieee80211_phy_init(/* no traced args */) */
    ieee80211_phy_init(/* no traced args */);
    /* site +0x2e: ieee80211_ht_attach(/* no traced args */) */
    ieee80211_ht_attach(/* no traced args */);
    /* site +0x37: ieee80211_ht_deattach(ret@2e) */
    ieee80211_ht_deattach(ret@2e);
    /* site +0x4f: ieee80211_set_phy_bw(0, 1) */
    ieee80211_set_phy_bw(0, 1);
    return opaque_result; /* full dataflow not recovered */
}

/* ieee80211_set_phy_mode @ ieee80211_ioctl.o 0x00000050 size 674B bind GLOBAL
 * Calls: wifi_nvs_get, chm_get_current_band, wifi_nvs_set, wifi_nvs_set, wifi_log, ieee80211_protocol_attach, ieee80211_protocol_attach, wifi_nvs_compare_cfg_diff, wifi_nvs_compare_cfg_diff, wifi_nvs_set, wifi_nvs_compare_cfg_diff, wifi_nvs_set, wifi_nvs_set, wifi_nvs_commit, wifi_nvs_compare_cfg_diff, wifi_nvs_compare_cfg_diff | Data refs: g_ic, g_wifi_nvs, .rodata_wlog_info.17, g_ic+0x200
 * Fidelity: low - 241 insns, 25 branches, 0 loops; skeleton only */
u32 ieee80211_set_phy_mode(u32 a2, u32 a3, u32 a4, u32 a5)
{
    /* frame: entry a1,64; 241 insns, 25 cond-branches, 0 loops, 11 jumps */
    /* immediates: 0, 71, 72, 3, 1, 10, 31, 58 */
    /* first predicate: bnei a8, 1, f6 <ieee80211_set_phy_mode+0xa6> (condition opaque) */
    /* mem st32: base=(?) off=28 */
    /* mem st32: base=(?) off=16 */
    /* mem st8: base=(?) off=20 */
    /* mem ld32: base=(lit:g_ic) off=16 */
    /* mem ld32: base=(lit:g_ic) off=20 */
    /* mem ld32: base=(?) off=28 */
    /* mem st32: base=(?) off=24 */
    /* mem ld32: base=(lit:g_wifi_nvs) off=0 */
    /* mem ld8: base=(?) off=20 */
    /* mem ld8: base=((*(g_wifi_nvs+0)+262144)) off=161 */
    /* ... +54 more memops */
    /* site +0x6a: wifi_nvs_get(/* no traced args */) */
    wifi_nvs_get(/* no traced args */);
    /* site +0x79: chm_get_current_band(ret@6a) */
    chm_get_current_band(ret@6a);
    /* site +0xb9: wifi_nvs_set(71, *(?+20)) */
    wifi_nvs_set(71, *(?+20));
    /* site +0xf1: wifi_nvs_set(72, *(?+20), *(?+28)) */
    wifi_nvs_set(72, *(?+20), *(?+28));
    /* site +0x11f: wifi_log(*(*(g_wifi_nvs+0)+156), 1, 3, lit:.rodata_wlog_info.17) */
    wifi_log(*(*(g_wifi_nvs+0)+156), 1, 3, lit:.rodata_wlog_info.17);
    /* site +0x16d: ieee80211_protocol_attach(*(g_ic+0x200+176), 1, *(?+16), lit:.rodata_wlog_info.17) */
    ieee80211_protocol_attach(*(g_ic+0x200+176), 1, *(?+16), lit:.rodata_wlog_info.17);
    /* site +0x1cd: ieee80211_protocol_attach((*(g_ic+16)+65536), &ieee80211_protocol_attach(), *(?+16), lit:.rodata_wlog_info.17) */
    ieee80211_protocol_attach((*(g_ic+16)+65536), &ieee80211_protocol_attach(), *(?+16), lit:.rodata_wlog_info.17);
    /* site +0x1ed: wifi_nvs_compare_cfg_diff(10, (?+16), 1, lit:.rodata_wlog_info.17) */
    wifi_nvs_compare_cfg_diff(10, (?+16), 1, lit:.rodata_wlog_info.17);
    /* site +0x215: wifi_nvs_compare_cfg_diff(31, (?+16), *(g_ic+0x200+31), lit:.rodata_wlog_info.17) */
    wifi_nvs_compare_cfg_diff(31, (?+16), *(g_ic+0x200+31), lit:.rodata_wlog_info.17);
    /* site +0x236: wifi_nvs_set(31, *(?+16), *(g_ic+0x200+31), lit:.rodata_wlog_info.17) */
    wifi_nvs_set(31, *(?+16), *(g_ic+0x200+31), lit:.rodata_wlog_info.17);
    /* site +0x24b: wifi_nvs_compare_cfg_diff(58, (?+16), *(g_ic+0x200+31), lit:.rodata_wlog_info.17) */
    wifi_nvs_compare_cfg_diff(58, (?+16), *(g_ic+0x200+31), lit:.rodata_wlog_info.17);
    /* site +0x26e: wifi_nvs_set(58, *(?+16), 1, lit:.rodata_wlog_info.17) */
    wifi_nvs_set(58, *(?+16), 1, lit:.rodata_wlog_info.17);
    /* site +0x2af: wifi_nvs_set(72, *(?+20), *(g_ic+0x200+31), lit:.rodata_wlog_info.17) */
    wifi_nvs_set(72, *(?+20), *(g_ic+0x200+31), lit:.rodata_wlog_info.17);
    /* site +0x2c0: wifi_nvs_commit(ret@2af, *(?+20), *(g_ic+0x200+31), lit:.rodata_wlog_info.17) */
    wifi_nvs_commit(ret@2af, *(?+20), *(g_ic+0x200+31), lit:.rodata_wlog_info.17);
    /* site +0x2d1: wifi_nvs_compare_cfg_diff(72, (?+20), *(g_ic+0x200+31), lit:.rodata_wlog_info.17) */
    wifi_nvs_compare_cfg_diff(72, (?+20), *(g_ic+0x200+31), lit:.rodata_wlog_info.17);
    /* site +0x2e5: wifi_nvs_compare_cfg_diff(71, (?+20), *(g_ic+0x200+31), lit:.rodata_wlog_info.17) */
    wifi_nvs_compare_cfg_diff(71, (?+20), *(g_ic+0x200+31), lit:.rodata_wlog_info.17);
    return last_call_result; /* opaque */
}

/* wifi_station_save_ap_channel @ ieee80211_ioctl.o 0x00000014 size 110B bind GLOBAL
 * Calls: wifi_nvs_get, wifi_nvs_set, wifi_nvs_set, wifi_nvs_commit | Data refs: g_ic
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 wifi_station_save_ap_channel(u32 a2, u32 a5)
{
    /* frame: entry a1,32; 41 insns, 2 cond-branches, 0 loops, 0 jumps */
    /* immediates: 1, 0, 5, 0x12b, 160, 13 */
    /* first predicate: bnez.n a10, 7e <wifi_station_save_ap_channel+0x6a> (condition opaque) */
    /* mem st8: base=(ret@1a) off=144 */
    /* mem ld8: base=((lit:g_ic+131072)) off=31 */
    /* mem ld8: base=(ret@1a) off=159 */
    /* mem st8: base=(*(ret@1a+159)) off=0 */
    /* mem ld8: base=((lit:g_ic+131072)) off=31 */
    /* site +0x1a: wifi_nvs_get(/* no traced args */) */
    wifi_nvs_get(/* no traced args */);
    /* site +0x45: wifi_nvs_set(5, ?, 0) */
    wifi_nvs_set(5, ?, 0);
    /* site +0x73: wifi_nvs_set(13, 160, ret@45) */
    wifi_nvs_set(13, 160, ret@45);
    /* site +0x7b: wifi_nvs_commit(ret@73, 160, ret@45) */
    wifi_nvs_commit(ret@73, 160, ret@45);
    return last_call_result; /* opaque */
}

/* map_wifi_config_sae_pwe_to_supp @ ieee80211_ioctl.o 0x00000004 size 28B bind GLOBAL
 * Calls: none | Data refs: .rodata.CSWTCH$424
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque (weak) */
u32 map_wifi_config_sae_pwe_to_supp(u32 a2)
{
    /* frame: entry a1,32; 9 insns, 1 cond-branches, 0 loops, 0 jumps */
    /* immediates: -1 */
    /* first predicate: bgeui a2, 4, 18 <map_wifi_config_sae_pwe_to_supp+0x14> (condition opaque) */
    /* mem ld8: base=(lit:.rodata.CSWTCH$424) off=0 */
    return *(.rodata.CSWTCH$424+0);
}

/* wifi_station_set_config_local_2$constprop$0 @ ieee80211_ioctl.o 0x000000c0 size 1636B bind LOCAL
 * Calls: wifi_nvs_get, strnlen, memcpy, memcpy, wifi_nvs_set, wifi_nvs_set, memcpy, wifi_nvs_set, wifi_nvs_set, wifi_nvs_set, wifi_nvs_set, wifi_nvs_set, wifi_nvs_set, wifi_nvs_set, wifi_log, wifi_nvs_set, wifi_nvs_set, wifi_nvs_set, wifi_nvs_set, wifi_nvs_set, wifi_nvs_set, wifi_nvs_set, wifi_nvs_set, wifi_nvs_set, wifi_log, wifi_nvs_set, wifi_nvs_set, wifi_nvs_set, map_wifi_config_sae_pwe_to_supp, wifi_nvs_set, wifi_nvs_set, memcpy, wifi_nvs_set, memcmp, wifi_log, memcpy, memcpy, memcpy, memset, wifi_nvs_set, wifi_nvs_set, wifi_nvs_set, wifi_nvs_commit | Data refs: g_ic, .rodata_wlog_warning.18, g_wifi_menuconfig, .rodata_wlog_warning.19, .rodata_wlog_debug.20
 * Fidelity: low - 537 insns, 38 branches, 0 loops; skeleton only */
u32 wifi_station_set_config_local_2_constprop_0(u32 a2, u32 a3)
{
    /* frame: entry a1,48; 537 insns, 38 cond-branches, 0 loops, 4 jumps */
    /* immediates: 32, 64, 0, 1, 3, 147, 6, 7, 8, 9 */
    /* first predicate: bnez a10, 660 <.text.wifi_station_set_config_local_2$constprop$0+0x660> (condition opaque) */
    /* mem st32: base=(ret@c6) off=4 */
    /* mem st32: base=(?) off=0 */
    /* mem st32: base=(?) off=4 */
    /* mem st8: base=(ret@c6) off=111 */
    /* mem ld8: base=((lit:g_ic+131072)) off=31 */
    /* mem ld8: base=((lit:g_ic+131072)) off=31 */
    /* mem ld32: base=(?) off=4 */
    /* mem ld8: base=(?) off=100 */
    /* mem st8: base=(ret@c6) off=146 */
    /* mem st32: base=(?) off=12 */
    /* ... +96 more memops */
    /* site +0xc6: wifi_nvs_get(/* no traced args */) */
    wifi_nvs_get(/* no traced args */);
    /* site +0xd2: strnlen(?, 32) */
    strnlen(?, 32);
    /* site +0xed: memcpy((ret@c6+8), ?, 32) */
    memcpy((ret@c6+8), ?, 32);
    /* site +0xff: memcpy((ret@c6+47), (?+32), 64) */
    memcpy((ret@c6+47), (?+32), 64);
    /* site +0x125: wifi_nvs_set(ret@ff, (ret@c6+4), 0) */
    wifi_nvs_set(ret@ff, (ret@c6+4), 0);
    /* site +0x13d: wifi_nvs_set(3, *(?+4), ret@125) */
    wifi_nvs_set(3, *(?+4), ret@125);
    /* site +0x166: memcpy(147, (?+101), 6) */
    memcpy(147, (?+101), 6);
    /* site +0x17a: wifi_nvs_set(7, 1, *(?+12)) */
    wifi_nvs_set(7, 1, *(?+12));
    /* site +0x192: wifi_nvs_set(8, 147, ret@17a) */
    wifi_nvs_set(8, 147, ret@17a);
    /* site +0x1b5: wifi_nvs_set(9, *(?+108), 0) */
    wifi_nvs_set(9, *(?+108), 0);
    /* site +0x1f2: wifi_nvs_set(5, *(?+107), ret@1b5) */
    wifi_nvs_set(5, *(?+107), ret@1b5);
    /* site +0x21e: wifi_nvs_set(14, ret@1f2, ret@1f2) */
    wifi_nvs_set(14, ret@1f2, ret@1f2);
    /* site +0x247: wifi_nvs_set(15, ret@21e, ret@21e) */
    wifi_nvs_set(15, ret@21e, ret@21e);
    /* site +0x26b: wifi_nvs_set(16, *(?+116), ret@247) */
    wifi_nvs_set(16, *(?+116), ret@247);
    /* site +0x28d: wifi_log(1, 2, 2, lit:g_ic) */
    wifi_log(1, 2, 2, lit:g_ic);
    /* site +0x2bd: wifi_nvs_set(17, *(?+120), 0, lit:g_ic) */
    wifi_nvs_set(17, *(?+120), 0, lit:g_ic);
    /* site +0x2e1: wifi_nvs_set(12, 158, ret@2bd, lit:g_ic) */
    wifi_nvs_set(12, 158, ret@2bd, lit:g_ic);
    /* site +0x302: wifi_nvs_set(18, 1, ret@2e1, lit:g_ic) */
    wifi_nvs_set(18, 1, ret@2e1, lit:g_ic);
    /* site +0x323: wifi_nvs_set(19, *(?+129), ret@302, lit:g_ic) */
    wifi_nvs_set(19, *(?+129), ret@302, lit:g_ic);
    /* site +0x349: wifi_nvs_set(21, *(?+120), ret@323, lit:g_ic) */
    wifi_nvs_set(21, *(?+120), ret@323, lit:g_ic);
    /* site +0x36f: wifi_nvs_set(20, *(?+120), ret@349, lit:g_ic) */
    wifi_nvs_set(20, *(?+120), ret@349, lit:g_ic);
    /* site +0x395: wifi_nvs_set(22, *(?+120), ret@36f, lit:g_ic) */
    wifi_nvs_set(22, *(?+120), ret@36f, lit:g_ic);
    /* site +0x3be: wifi_nvs_set(40, *(?+120), ret@395, lit:g_ic) */
    wifi_nvs_set(40, *(?+120), ret@395, lit:g_ic);
    /* site +0x3ed: wifi_nvs_set(41, *(g_ic+64), ret@3be, lit:g_ic) */
    wifi_nvs_set(41, *(g_ic+64), ret@3be, lit:g_ic);
    /* site +0x40b: wifi_log(1, 2, 2, lit:g_ic) */
    wifi_log(1, 2, 2, lit:g_ic);
    /* site +0x429: wifi_nvs_set(45, *(?+144), 0, lit:g_ic) */
    wifi_nvs_set(45, *(?+144), 0, lit:g_ic);
    /* site +0x44f: wifi_nvs_set(42, *(g_ic+64), ret@429, lit:g_ic) */
    wifi_nvs_set(42, *(g_ic+64), ret@429, lit:g_ic);
    /* site +0x476: wifi_nvs_set(87, *(g_ic+64), *((lit:g_ic+131072)+31), lit:g_ic) */
    wifi_nvs_set(87, *(g_ic+64), *((lit:g_ic+131072)+31), lit:g_ic);
    /* site +0x489: map_wifi_config_sae_pwe_to_supp(*(?+136), *(g_ic+64), *((lit:g_ic+131072)+31), lit:g_ic) */
    map_wifi_config_sae_pwe_to_supp(*(?+136), *(g_ic+64), *((lit:g_ic+131072)+31), lit:g_ic);
    /* site +0x4a7: wifi_nvs_set(43, *(g_ic+64), *(?+12), lit:g_ic) */
    wifi_nvs_set(43, *(g_ic+64), *(?+12), lit:g_ic);
    /* site +0x4cb: wifi_nvs_set(44, *(?+140), ret@4a7, lit:g_ic) */
    wifi_nvs_set(44, *(?+140), ret@4a7, lit:g_ic);
    /* site +0x4e9: memcpy(0x47d, 151, 32, lit:g_ic) */
    memcpy(0x47d, 151, 32, lit:g_ic);
    /* site +0x4fd: wifi_nvs_set(55, ret@4e9, *(?+12), lit:g_ic) */
    wifi_nvs_set(55, ret@4e9, *(?+12), lit:g_ic);
    /* site +0x53b: memcmp(ret@4fd, *(?+0), *((? slli 2)+160), lit:g_ic) */
    memcmp(ret@4fd, *(?+0), *((? slli 2)+160), lit:g_ic);
    /* site +0x569: wifi_log(1, 2, 4, lit:g_ic) */
    wifi_log(1, 2, 4, lit:g_ic);
    /* site +0x579: memcpy(ret@569, *(?+0), 32, lit:g_ic) */
    memcpy(ret@569, *(?+0), 32, lit:g_ic);
    /* site +0x59d: memcpy(196, *(?+4), 64, lit:g_ic) */
    memcpy(196, *(?+4), 64, lit:g_ic);
    /* site +0x5c6: memcpy(0x105, 147, 6, lit:g_ic) */
    memcpy(0x105, 147, 6, lit:g_ic);
    /* site +0x5ee: memset(ret@5c6, 255, 32, lit:g_ic) */
    memset(ret@5c6, 255, 32, lit:g_ic);
    /* site +0x605: wifi_nvs_set(13, 160, 0, lit:g_ic) */
    wifi_nvs_set(13, 160, 0, lit:g_ic);
    /* site +0x62b: wifi_nvs_set(89, ret@c6, ret@605, lit:g_ic) */
    wifi_nvs_set(89, ret@c6, ret@605, lit:g_ic);
    /* site +0x651: wifi_nvs_set(90, *(?+144), ret@62b, lit:g_ic) */
    wifi_nvs_set(90, *(?+144), ret@62b, lit:g_ic);
    /* site +0x65b: wifi_nvs_commit(ret@651, *(?+144), ret@62b, lit:g_ic) */
    wifi_nvs_commit(ret@651, *(?+144), ret@62b, lit:g_ic);
    return last_call_result; /* opaque */
}

/* print_sta_pmk @ ieee80211_ioctl.o 0x00000018 size 272B bind GLOBAL
 * Calls: wifi_nvs_get, memcmp, wifi_log, wifi_log | Data refs: .rodata_wlog_warning.21, .rodata_wlog_warning.22
 * Fidelity: low - 102 insns, 2 branches, 0 loops; skeleton only */
u32 print_sta_pmk(u32 a2)
{
    /* frame: entry a1,160; 102 insns, 2 cond-branches, 0 loops, 1 jumps */
    /* immediates: 160, 0, 32, 2, 1, 140 */
    /* first predicate: bnez a10, 119 <print_sta_pmk+0x101> (condition opaque) */
    /* mem st32: base=(?) off=0 */
    /* mem st32: base=(?) off=4 */
    /* mem ld32: base=(160) off=0 */
    /* mem ld8: base=(160) off=138 */
    /* mem ld8: base=(160) off=107 */
    /* mem st32: base=(?) off=120 */
    /* mem ld8: base=(160) off=137 */
    /* mem st32: base=(?) off=116 */
    /* mem ld8: base=(160) off=136 */
    /* mem st32: base=(?) off=112 */
    /* ... +56 more memops */
    /* site +0x1e: wifi_nvs_get(/* no traced args */) */
    wifi_nvs_get(/* no traced args */);
    /* site +0x35: memcmp((160+4), ?, 32) */
    memcmp((160+4), ?, 32);
    /* site +0x55: wifi_log(1, 2, 2, lit:.rodata_wlog_warning.21, 0) */
    wifi_log(1, 2, 2, lit:.rodata_wlog_warning.21, 0);
    /* site +0x116: wifi_log(1, 2, 2, lit:.rodata_wlog_warning.22, 0) */
    wifi_log(1, 2, 2, lit:.rodata_wlog_warning.22, 0);
    return opaque_result; /* full dataflow not recovered */
}

/* wifi_sta_change_mac_internal @ ieee80211_ioctl.o 0x00000038 size 228B bind GLOBAL
 * Calls: ieee80211_action_vendor_reset_seq_state, indirect(a10), wifi_log, memcpy, ic_set_mac, memcpy, wifi_log | Data refs: g_cnxMgr, g_ic, g_osi_funcs_p, .rodata_wlog_debug.31, g_ic+0x212, .rodata_wlog_debug.32, .rodata_wlog_debug.33, g_ic+0x200
 * Fidelity: low - 83 insns, 5 branches, 0 loops; skeleton only */
u32 wifi_sta_change_mac_internal(u32 a2, u32 a3, u32 a5)
{
    /* frame: entry a1,48; 83 insns, 5 cond-branches, 0 loops, 1 jumps */
    /* immediates: 0x102, 1, 210, 174, 4, 6, 0 */
    /* first predicate: beqz a2, 118 <wifi_sta_change_mac_internal+0xe0> (condition opaque) */
    /* mem ld32: base=((lit:g_cnxMgr+983040)) off=96 */
    /* mem st8: base=(lit:g_ic+0x200) off=6 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=188 */
    /* mem st16: base=(174) off=0 */
    /* mem ld8: base=((lit:g_ic+65536)) off=237 */
    /* mem ld8: base=(?) off=5 */
    /* mem st32: base=(?) off=12 */
    /* mem ld8: base=(?) off=4 */
    /* mem st32: base=(?) off=8 */
    /* ... +16 more memops */
    /* site +0x62: ieee80211_action_vendor_reset_seq_state(/* no traced args */) */
    ieee80211_action_vendor_reset_seq_state(/* no traced args */);
    /* site +0x7a: indirect call via a10 (base *(*(g_osi_funcs_p+0)+188)); args: *(*(g_osi_funcs_p+0)+188) */
    opaque_indirect_a10();
    /* site +0x99: wifi_log(1, ?, 4, lit:.rodata_wlog_debug.31) */
    wifi_log(1, ?, 4, lit:.rodata_wlog_debug.31);
    /* site +0xb2: memcpy((lit:g_ic+0x200+18), ?, 6, lit:.rodata_wlog_debug.31) */
    memcpy((lit:g_ic+0x200+18), ?, 6, lit:.rodata_wlog_debug.31);
    /* site +0xbd: ic_set_mac(0, lit:g_ic+0x212, 6, lit:.rodata_wlog_debug.31) */
    ic_set_mac(0, lit:g_ic+0x212, 6, lit:.rodata_wlog_debug.31);
    /* site +0xe7: memcpy(ret@bd, lit:g_ic+0x212, 6, lit:.rodata_wlog_debug.32, *(?+0)) */
    memcpy(ret@bd, lit:g_ic+0x212, 6, lit:.rodata_wlog_debug.32, *(?+0));
    /* site +0x113: wifi_log(1, 4, 4, lit:.rodata_wlog_debug.33, *(?+0)) */
    wifi_log(1, 4, 4, lit:.rodata_wlog_debug.33, *(?+0));
    return 0;
}

/* wifi_scan_restore_random_mac @ ieee80211_ioctl.o 0x0000002c size 157B bind GLOBAL
 * Calls: ieee80211_sta_is_connected, wifi_log, wifi_sta_change_mac_internal, wifi_log, wifi_check_and_handle_rmac_timer_pending | Data refs: g_rmac_scan_saved, g_ic, .rodata_wlog_debug.4, g_rmac_scan_saved_mac, .rodata_wlog_debug.5, g_wifi_menuconfig
 * Fidelity: medium - branchy but loop-free, call sequence mapped */
u32 wifi_scan_restore_random_mac(u32 a3, u32 a4)
{
    /* frame: entry a1,48; 58 insns, 7 cond-branches, 0 loops, 1 jumps */
    /* immediates: 4, 1, 0 */
    /* first predicate: beqz a2, c4 <wifi_scan_restore_random_mac+0x98> (condition opaque) */
    /* mem ld8: base=(lit:g_rmac_scan_saved) off=0 */
    /* mem ld32: base=(lit:g_ic) off=16 */
    /* mem ld8: base=((*(g_ic+16)+65536)) off=84 */
    /* mem ld32: base=(*(g_ic+16)) off=152 */
    /* mem ld8: base=((*(g_ic+16)+65536)) off=84 */
    /* mem ld32: base=(*(g_ic+16)) off=152 */
    /* mem ld8: base=(lit:g_rmac_scan_saved_mac) off=5 */
    /* mem ld8: base=(lit:g_rmac_scan_saved_mac) off=1 */
    /* mem ld8: base=(lit:g_rmac_scan_saved_mac) off=0 */
    /* mem st32: base=(?) off=12 */
    /* ... +9 more memops */
    /* site +0x42: ieee80211_sta_is_connected(/* no traced args */) */
    ieee80211_sta_is_connected(/* no traced args */);
    /* site +0x69: wifi_log(1, ?, 4, lit:.rodata_wlog_debug.4, *(*(g_ic+16)+152)) */
    wifi_log(1, ?, 4, lit:.rodata_wlog_debug.4, *(*(g_ic+16)+152));
    /* site +0x7a: wifi_sta_change_mac_internal(lit:g_rmac_scan_saved_mac, 0, 4, lit:.rodata_wlog_debug.4, *(*(g_ic+16)+152)) */
    wifi_sta_change_mac_internal(lit:g_rmac_scan_saved_mac, 0, 4, lit:.rodata_wlog_debug.4, *(*(g_ic+16)+152));
    /* site +0xa6: wifi_log(1, 4, 4, lit:.rodata_wlog_debug.5, *(g_rmac_scan_saved_mac+0)) */
    wifi_log(1, 4, 4, lit:.rodata_wlog_debug.5, *(g_rmac_scan_saved_mac+0));
    /* site +0xb9: wifi_check_and_handle_rmac_timer_pending(ret@a6, 4, 4, lit:.rodata_wlog_debug.5, *(g_rmac_scan_saved_mac+0)) */
    wifi_check_and_handle_rmac_timer_pending(ret@a6, 4, 4, lit:.rodata_wlog_debug.5, *(g_rmac_scan_saved_mac+0));
    return opaque_result; /* full dataflow not recovered */
}

/* scan_done_restore_mac_wrapper @ ieee80211_ioctl.o 0x00000008 size 40B bind LOCAL
 * Calls: wifi_scan_restore_random_mac, indirect(a8) | Data refs: .bss.g_rmac_original_scan_cb
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 scan_done_restore_mac_wrapper(u32 a2, u32 a3)
{
    /* frame: entry a1,32; 13 insns, 1 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0 */
    /* first predicate: beqz.n a8, 26 <.text.scan_done_restore_mac_wrapper+0x26> (condition opaque) */
    /* mem ld32: base=(lit:.bss.g_rmac_original_scan_cb) off=0 */
    /* mem st32: base=(lit:.bss.g_rmac_original_scan_cb) off=0 */
    /* site +0xe: wifi_scan_restore_random_mac(/* no traced args */) */
    wifi_scan_restore_random_mac(/* no traced args */);
    /* site +0x23: indirect call via a8 (base *(.bss.g_rmac_original_scan_cb+0)); args: /* no traced args */ */
    opaque_indirect_a8();
    return opaque_result; /* full dataflow not recovered */
}

/* _do_wifi_stop @ ieee80211_ioctl.o 0x00000060 size 311B bind GLOBAL
 * Calls: indirect(a8), indirect(a7), wifi_log, wifi_sta_change_mac_internal, indirect(a8), ieee80211_action_vendor_reset_seq_state, memset, wifi_station_stop, wifi_log, indirect(a10), wifi_log, nan_stop, wifi_log | Data refs: g_ic, g_wifi_menuconfig, g_ic+0x2c8, g_osi_funcs_p, g_rmac_scan_saved, .bss.g_rmac_original_scan_cb, .rodata_wlog_debug.6, g_rmac_scan_saved_mac, g_ic+0x2dc, g_ic+0x2fa, .rodata_wlog_debug.7, net80211_funcs, .rodata_wlog_debug.8, .rodata_wlog_debug.9, .rodata_wlog_debug.10
 * Fidelity: low - 116 insns, 13 branches, 0 loops; skeleton only */
u32 do_wifi_stop(u32 a2, u32 a4, u32 a6, u32 a7)
{
    /* frame: entry a1,32; 116 insns, 13 cond-branches, 0 loops, 4 jumps */
    /* immediates: 0, -3, 4, 8, 6, 2, 1, 0x102 */
    /* first predicate: beqi a2, 1, 78 <_do_wifi_stop+0x18> (condition opaque) */
    /* mem ld8: base=((lit:g_ic+65536)) off=238 */
    /* mem ld8: base=(lit:g_wifi_menuconfig) off=97 */
    /* mem ld32: base=(lit:g_ic) off=116 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=236 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=240 */
    /* mem ld8: base=(lit:g_rmac_scan_saved) off=0 */
    /* mem ld32: base=(lit:.bss.g_rmac_original_scan_cb) off=0 */
    /* mem ld32: base=(lit:.bss.g_rmac_original_scan_cb) off=0 */
    /* ... +6 more memops */
    /* site +0xa3: indirect call via a8 (base *(*(g_osi_funcs_p+0)+236)); args: /* no traced args */ */
    opaque_indirect_a8();
    /* site +0xad: indirect call via a7 (base *(g_osi_funcs_p+240)); args: lit:g_ic+0x2c8 */
    opaque_indirect_a7();
    /* site +0xcb: wifi_log(-3, 8, 4, lit:.rodata_wlog_debug.6) */
    wifi_log(-3, 8, 4, lit:.rodata_wlog_debug.6);
    /* site +0xd6: wifi_sta_change_mac_internal(lit:g_rmac_scan_saved_mac, *(g_ic+116), 4, lit:.rodata_wlog_debug.6) */
    wifi_sta_change_mac_internal(lit:g_rmac_scan_saved_mac, *(g_ic+116), 4, lit:.rodata_wlog_debug.6);
    /* site +0xdf: indirect call via a8 (base *(.bss.g_rmac_original_scan_cb+0)); args: *(g_ic+116), -3, 4, lit:.rodata_wlog_debug.6 */
    opaque_indirect_a8();
    /* site +0xf6: ieee80211_action_vendor_reset_seq_state(ret@df, -3, 4, lit:.rodata_wlog_debug.6) */
    ieee80211_action_vendor_reset_seq_state(ret@df, -3, 4, lit:.rodata_wlog_debug.6);
    /* site +0x10b: memset(lit:g_ic+0x2dc, 0, 6, lit:.rodata_wlog_debug.6) */
    memset(lit:g_ic+0x2dc, 0, 6, lit:.rodata_wlog_debug.6);
    /* site +0x12a: wifi_station_stop(ret@10b, 0, 6, lit:.rodata_wlog_debug.6) */
    wifi_station_stop(ret@10b, 0, 6, lit:.rodata_wlog_debug.6);
    /* site +0x13d: wifi_log(1, 2, 4, lit:.rodata_wlog_debug.7) */
    wifi_log(1, 2, 4, lit:.rodata_wlog_debug.7);
    /* site +0x152: indirect call via a10 (base *(net80211_funcs+16)); args: *(net80211_funcs+16), 2, 4, lit:.rodata_wlog_debug.7 */
    opaque_indirect_a10();
    /* site +0x179: wifi_log(1, 2, 4, lit:.rodata_wlog_debug.9) */
    wifi_log(1, 2, 4, lit:.rodata_wlog_debug.9);
    /* site +0x17f: nan_stop(ret@179, 2, 4, lit:.rodata_wlog_debug.9) */
    nan_stop(ret@179, 2, 4, lit:.rodata_wlog_debug.9);
    /* site +0x192: wifi_log(1, 2, ?, lit:.rodata_wlog_debug.10) */
    wifi_log(1, 2, ?, lit:.rodata_wlog_debug.10);
    return last_call_result; /* opaque */
}

/* wifi_set_phy_2nd_chan_process @ ieee80211_ioctl.o 0x00000014 size 60B bind GLOBAL
 * Calls: ieee80211_phy_2nd_chan_is_valid, do_wifi_stop, ieee80211_set_phy_2nd_chan, do_wifi_start | Data refs: g_wifi_nvs
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 wifi_set_phy_2nd_chan_process(u32 a2)
{
    /* frame: entry a1,32; 23 insns, 2 cond-branches, 0 loops, 0 jumps */
    /* immediates: 2 */
    /* first predicate: beqz.n a10, 4e <wifi_set_phy_2nd_chan_process+0x3a> (condition opaque) */
    /* mem ld8: base=(?) off=8 */
    /* mem ld32: base=(lit:g_wifi_nvs) off=0 */
    /* mem ld8: base=((*(g_wifi_nvs+0)+196608)) off=252 */
    /* site +0x1f: ieee80211_phy_2nd_chan_is_valid(*(?+8)) */
    ieee80211_phy_2nd_chan_is_valid(*(?+8));
    /* site +0x39: do_wifi_stop(2) */
    do_wifi_stop(2);
    /* site +0x41: ieee80211_set_phy_2nd_chan(*(?+8)) */
    ieee80211_set_phy_2nd_chan(*(?+8));
    /* site +0x4b: do_wifi_start(2) */
    do_wifi_start(2);
    return last_call_result; /* opaque */
}

/* wifi_stop_old_mode @ ieee80211_ioctl.o 0x00000018 size 129B bind LOCAL
 * Calls: offchan_in_progress, chm_cancel_op, scan_cancel, do_wifi_stop, do_wifi_stop | Data refs: s_wifi_stop_in_progress
 * Fidelity: medium - branchy but loop-free, call sequence mapped */
u32 wifi_stop_old_mode(u32 a2, u32 a3, u32 a4)
{
    /* frame: entry a1,32; 37 insns, 6 cond-branches, 0 loops, 1 jumps */
    /* immediates: 1, -3, 2, 0 */
    /* first predicate: beqz.n a10, 38 <.text.wifi_stop_old_mode+0x38> (condition opaque) */
    /* mem st8: base=(lit:s_wifi_stop_in_progress) off=0 */
    /* mem st8: base=(lit:s_wifi_stop_in_progress) off=0 */
    /* site +0x2d: offchan_in_progress(/* no traced args */) */
    offchan_in_progress(/* no traced args */);
    /* site +0x35: chm_cancel_op(ret@2d) */
    chm_cancel_op(ret@2d);
    /* site +0x3b: scan_cancel(ret@35) */
    scan_cancel(ret@35);
    /* site +0x4f: do_wifi_stop(ret@3b) */
    do_wifi_stop(ret@3b);
    /* site +0x71: do_wifi_stop(/* no traced args */) */
    do_wifi_stop(/* no traced args */);
    return opaque_result; /* full dataflow not recovered */
}

/* wifi_sta_restore_default_mac @ ieee80211_ioctl.o 0x00000028 size 143B bind GLOBAL
 * Calls: wifi_log, indirect(a8), wifi_sta_change_mac_internal, wifi_nvs_reset_current_ap_info, wifi_log | Data refs: g_wifi_nvs, .rodata_wlog_error.23, g_osi_funcs_p, g_ic, .rodata_wlog_info.24
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 wifi_sta_restore_default_mac(u32 a2)
{
    /* frame: entry a1,64; 53 insns, 1 cond-branches, 0 loops, 1 jumps */
    /* immediates: 253, 1, 4, 0, 3, 8 */
    /* first predicate: beqi a2, 1, 52 <wifi_sta_restore_default_mac+0x2a> (condition opaque) */
    /* mem ld32: base=(lit:g_wifi_nvs) off=0 */
    /* mem ld8: base=(*(g_wifi_nvs+0)) off=0 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=228 */
    /* mem st16: base=((lit:g_ic+131072)) off=250 */
    /* mem st16: base=((lit:g_ic+131072)) off=252 */
    /* mem st8: base=((lit:g_ic+131072)) off=254 */
    /* mem ld8: base=(?) off=21 */
    /* mem st32: base=(?) off=12 */
    /* mem ld8: base=(?) off=20 */
    /* ... +7 more memops */
    /* site +0x49: wifi_log(?, 4, 1, lit:.rodata_wlog_error.23) */
    wifi_log(?, 4, 1, lit:.rodata_wlog_error.23);
    /* site +0x5f: indirect call via a8 (base *(g_osi_funcs_p+228)); args: (?+16), 0, 1, lit:.rodata_wlog_error.23 */
    opaque_indirect_a8();
    /* site +0x6a: wifi_sta_change_mac_internal((?+16), literal, 1, lit:.rodata_wlog_error.23) */
    wifi_sta_change_mac_internal((?+16), literal, 1, lit:.rodata_wlog_error.23);
    /* site +0x70: wifi_nvs_reset_current_ap_info(ret@6a, literal, 1, lit:.rodata_wlog_error.23) */
    wifi_nvs_reset_current_ap_info(ret@6a, literal, 1, lit:.rodata_wlog_error.23);
    /* site +0xb2: wifi_log(literal, 8, 3, lit:.rodata_wlog_info.24, *(?+16)) */
    wifi_log(literal, 8, 3, lit:.rodata_wlog_info.24, *(?+16));
    return 0;
}

/* ieee80211_sta_connect @ ieee80211_ioctl.o 0x00000048 size 222B bind GLOBAL
 * Calls: wifi_log, wifi_log, pm_wake_up, wifi_log, cnx_sta_connect_cmd, pm_wake_done, wifi_log, pm_wake_done | Data refs: g_ic, .rodata_wlog_debug.41, .rodata_wlog_error.42, .rodata_wlog_warning.43, .rodata_wlog_debug.44, g_wifi_nvs, g_mesh_is_root, .rodata_wlog_debug.45
 * Fidelity: low - 80 insns, 8 branches, 0 loops; skeleton only */
u32 ieee80211_sta_connect(u32 a2)
{
    /* frame: entry a1,32; 80 insns, 8 cond-branches, 0 loops, 5 jumps */
    /* immediates: 4, 1, 2, 0, 14 */
    /* first predicate: bnez.n a8, 60 <ieee80211_sta_connect+0x18> (condition opaque) */
    /* mem ld32: base=(lit:g_ic) off=16 */
    /* mem ld8: base=((*(g_ic+16)+65536)) off=84 */
    /* mem ld32: base=(0) off=16 */
    /* mem ld8: base=((*(g_ic+16)+65536)) off=84 */
    /* mem ld32: base=(0) off=16 */
    /* mem st8: base=((*(g_ic+16)+65536)) off=84 */
    /* mem ld32: base=(lit:g_wifi_nvs) off=0 */
    /* mem ld32: base=(*(g_wifi_nvs+0)) off=4 */
    /* mem ld32: base=(0) off=116 */
    /* mem ld8: base=(lit:g_mesh_is_root) off=0 */
    /* ... +1 more memops */
    /* site +0x75: wifi_log(*((*(g_ic+16)+65536)+84), 4, 4, lit:.rodata_wlog_error.42) */
    wifi_log(*((*(g_ic+16)+65536)+84), 4, 4, lit:.rodata_wlog_error.42);
    /* site +0x8f: wifi_log(1, 4, 2, lit:.rodata_wlog_warning.43) */
    wifi_log(1, 4, 2, lit:.rodata_wlog_warning.43);
    /* site +0x9b: pm_wake_up(ret@8f, 4, 2, lit:.rodata_wlog_warning.43) */
    pm_wake_up(ret@8f, 4, 2, lit:.rodata_wlog_warning.43);
    /* site +0xb5: wifi_log(1, 4, 4, lit:.rodata_wlog_debug.44, *((*(g_ic+16)+65536)+84)) */
    wifi_log(1, 4, 4, lit:.rodata_wlog_debug.44, *((*(g_ic+16)+65536)+84));
    /* site +0xf6: cnx_sta_connect_cmd(0, 4, 4, lit:.rodata_wlog_debug.44, *((*(g_ic+16)+65536)+84)) */
    cnx_sta_connect_cmd(0, 4, 4, lit:.rodata_wlog_debug.44, *((*(g_ic+16)+65536)+84));
    /* site +0x103: pm_wake_done(ret@f6, 4, 4, lit:.rodata_wlog_debug.44, *((*(g_ic+16)+65536)+84)) */
    pm_wake_done(ret@f6, 4, 4, lit:.rodata_wlog_debug.44, *((*(g_ic+16)+65536)+84));
    /* site +0x112: wifi_log(1, 4, 4, lit:.rodata_wlog_debug.45, *((*(g_ic+16)+65536)+84)) */
    wifi_log(1, 4, 4, lit:.rodata_wlog_debug.45, *((*(g_ic+16)+65536)+84));
    /* site +0x121: pm_wake_done(ret@112, 4, 4, lit:.rodata_wlog_debug.45, *((*(g_ic+16)+65536)+84)) */
    pm_wake_done(ret@112, 4, 4, lit:.rodata_wlog_debug.45, *((*(g_ic+16)+65536)+84));
    return opaque_result; /* full dataflow not recovered */
}

/* ieee80211_sta_disconnect @ ieee80211_ioctl.o 0x00000044 size 214B bind GLOBAL
 * Calls: wifi_check_and_handle_rmac_timer_pending, pm_wake_up, offchan_in_progress, wifi_log, chm_cancel_op, scan_cancel, cnx_csa_cancel_pending_connect, ieee80211_sta_new_state, pm_wake_done, indirect(a5), indirect(a5), indirect(a5), indirect(a5), indirect(a8), indirect(a2), cnx_remove_all_rc, pm_wake_done | Data refs: g_ic, g_wifi_menuconfig, .rodata_wlog_debug.46, g_osi_funcs_p, g_cnxMgr+0xf74
 * Fidelity: low - 79 insns, 5 branches, 0 loops; skeleton only */
u32 ieee80211_sta_disconnect(u32 a2, u32 a3)
{
    /* frame: entry a1,32; 79 insns, 5 cond-branches, 0 loops, 1 jumps */
    /* immediates: 4, 2, 1, 0 */
    /* first predicate: beqz a4, 118 <ieee80211_sta_disconnect+0xd4> (condition opaque) */
    /* mem ld32: base=(lit:g_ic) off=16 */
    /* mem ld8: base=(lit:g_wifi_menuconfig) off=97 */
    /* mem ld32: base=(lit:g_ic) off=116 */
    /* mem ld32: base=(lit:g_ic) off=16 */
    /* mem ld32: base=(*(g_ic+16)) off=152 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=236 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(lit:g_ic) off=16 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=240 */
    /* ... +11 more memops */
    /* site +0x62: wifi_check_and_handle_rmac_timer_pending(/* no traced args */) */
    wifi_check_and_handle_rmac_timer_pending(/* no traced args */);
    /* site +0x68: pm_wake_up(ret@62) */
    pm_wake_up(ret@62);
    /* site +0x6e: offchan_in_progress(ret@68) */
    offchan_in_progress(ret@68);
    /* site +0x81: wifi_log(1, 2, 4, lit:.rodata_wlog_debug.46) */
    wifi_log(1, 2, 4, lit:.rodata_wlog_debug.46);
    /* site +0x87: chm_cancel_op(ret@81, 2, 4, lit:.rodata_wlog_debug.46) */
    chm_cancel_op(ret@81, 2, 4, lit:.rodata_wlog_debug.46);
    /* site +0x8d: scan_cancel(ret@87, 2, 4, lit:.rodata_wlog_debug.46) */
    scan_cancel(ret@87, 2, 4, lit:.rodata_wlog_debug.46);
    /* site +0x93: cnx_csa_cancel_pending_connect(ret@8d, 2, 4, lit:.rodata_wlog_debug.46) */
    cnx_csa_cancel_pending_connect(ret@8d, 2, 4, lit:.rodata_wlog_debug.46);
    /* site +0xa6: ieee80211_sta_new_state(lit:g_ic, 0, 0, lit:.rodata_wlog_debug.46) */
    ieee80211_sta_new_state(lit:g_ic, 0, 0, lit:.rodata_wlog_debug.46);
    /* site +0xac: pm_wake_done(ret@a6, 0, 0, lit:.rodata_wlog_debug.46) */
    pm_wake_done(ret@a6, 0, 0, lit:.rodata_wlog_debug.46);
    /* site +0xbf: indirect call via a5 (base *(*(g_osi_funcs_p+0)+236)); args: (ret@ac+4), 0, 0, lit:.rodata_wlog_debug.46 */
    opaque_indirect_a5();
    /* site +0xcb: indirect call via a5 (base *(*(g_osi_funcs_p+0)+240)); args: (*(g_ic+16)+4), 0, 0, lit:.rodata_wlog_debug.46 */
    opaque_indirect_a5();
    /* site +0xd9: indirect call via a5 (base *(*(g_osi_funcs_p+0)+236)); args: (*(g_ic+16)+24), 0, 0, lit:.rodata_wlog_debug.46 */
    opaque_indirect_a5();
    /* site +0xe6: indirect call via a5 (base *(*(g_osi_funcs_p+0)+240)); args: (*(g_ic+16)+24), 0, 0, lit:.rodata_wlog_debug.46 */
    opaque_indirect_a5();
    /* site +0xf3: indirect call via a8 (base *(*(g_osi_funcs_p+0)+236)); args: lit:g_cnxMgr+0xf74, 0, 0, lit:.rodata_wlog_debug.46 */
    opaque_indirect_a8();
    /* site +0xfe: indirect call via a2 (base *(g_osi_funcs_p+240)); args: lit:g_cnxMgr+0xf74, 0, 0, lit:.rodata_wlog_debug.46 */
    opaque_indirect_a2();
    /* site +0x104: cnx_remove_all_rc(ret@fe, 0, 0, lit:.rodata_wlog_debug.46) */
    cnx_remove_all_rc(ret@fe, 0, 0, lit:.rodata_wlog_debug.46);
    /* site +0x10a: pm_wake_done(ret@104, 0, 0, lit:.rodata_wlog_debug.46) */
    pm_wake_done(ret@104, 0, 0, lit:.rodata_wlog_debug.46);
    return opaque_result; /* full dataflow not recovered */
}

/* _do_wifi_disconnect @ ieee80211_ioctl.o 0x00000038 size 283B bind LOCAL
 * Calls: ieee80211_empty_txq, wifi_log, memset, memcpy, wifi_log, wifi_event_post, ieee80211_sta_disconnect, wifi_log, wifi_set_rx_policy | Data refs: g_wifi_nvs, g_ic, .rodata_wlog_debug.47, .rodata_wlog_debug.48, .rodata_wlog_debug.49
 * Fidelity: low - 86 insns, 5 branches, 0 loops; skeleton only */
u32 do_wifi_disconnect(u32 a2)
{
    /* frame: entry a1,80; 86 insns, 5 cond-branches, 0 loops, 1 jumps */
    /* immediates: 253, 1, 0, 4, 6, -128, 32, 5, 36, 41 */
    /* first predicate: beqi a3, 1, 5c <.text._do_wifi_disconnect+0x5c> (condition opaque) */
    /* mem ld32: base=(lit:g_wifi_nvs) off=0 */
    /* mem ld8: base=(*(g_wifi_nvs+0)) off=0 */
    /* mem ld32: base=(lit:g_wifi_nvs) off=116 */
    /* mem ld32: base=(1) off=16 */
    /* mem ld32: base=(*(g_wifi_nvs+16)) off=152 */
    /* mem ld8: base=((*(g_wifi_nvs+16)+65536)) off=84 */
    /* mem ld32: base=(1) off=16 */
    /* mem ld32: base=(1) off=116 */
    /* mem st8: base=((*(g_wifi_nvs+16)+65536)) off=84 */
    /* mem st8: base=(?) off=40 */
    /* ... +4 more memops */
    /* site +0x61: ieee80211_empty_txq(0) */
    ieee80211_empty_txq(0);
    /* site +0x83: wifi_log(0, 4, 4, lit:g_wifi_nvs, *((*(g_wifi_nvs+16)+65536)+84)) */
    wifi_log(0, 4, 4, lit:g_wifi_nvs, *((*(g_wifi_nvs+16)+65536)+84));
    /* site +0xab: memset((?+33), *(g_wifi_nvs+116), 6, lit:g_wifi_nvs, *((*(g_wifi_nvs+16)+65536)+84)) */
    memset((?+33), *(g_wifi_nvs+116), 6, lit:g_wifi_nvs, *((*(g_wifi_nvs+16)+65536)+84));
    /* site +0xb7: memcpy(?, (*(g_wifi_nvs+0)+8), 32, lit:g_wifi_nvs, *((*(g_wifi_nvs+16)+65536)+84)) */
    memcpy(?, (*(g_wifi_nvs+0)+8), 32, lit:g_wifi_nvs, *((*(g_wifi_nvs+16)+65536)+84));
    /* site +0xd9: wifi_log(0, 5, 4, lit:g_wifi_nvs, 36) */
    wifi_log(0, 5, 4, lit:g_wifi_nvs, 36);
    /* site +0xe5: wifi_event_post(5, ?, 41, lit:g_wifi_nvs, 36) */
    wifi_event_post(5, ?, 41, lit:g_wifi_nvs, 36);
    /* site +0xeb: ieee80211_sta_disconnect(ret@e5, ?, 41, lit:g_wifi_nvs, 36) */
    ieee80211_sta_disconnect(ret@e5, ?, 41, lit:g_wifi_nvs, 36);
    /* site +0xfe: wifi_log(1, 12, 4, lit:g_wifi_nvs, 7) */
    wifi_log(1, 12, 4, lit:g_wifi_nvs, 7);
    /* site +0x106: wifi_set_rx_policy(7, 12, 4, lit:g_wifi_nvs, 7) */
    wifi_set_rx_policy(7, 12, 4, lit:g_wifi_nvs, 7);
    return opaque_result; /* full dataflow not recovered */
}

/* ieee80211_sta_scan @ ieee80211_ioctl.o 0x00000014 size 49B bind GLOBAL
 * Calls: scan_reset_offchan_duration, cnx_sta_scan_cmd | Data refs: g_ic, scannum, g_ic+0x130
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 ieee80211_sta_scan(u32 a2, u32 a3)
{
    /* frame: entry a1,32; 19 insns, 1 cond-branches, 0 loops, 0 jumps */
    /* immediates: -1, 0 */
    /* first predicate: beqz.n a9, 41 <ieee80211_sta_scan+0x2d> (condition opaque) */
    /* mem ld32: base=(lit:g_ic) off=16 */
    /* mem st16: base=(lit:scannum) off=0 */
    /* site +0x23: scan_reset_offchan_duration(-1) */
    scan_reset_offchan_duration(-1);
    /* site +0x3e: cnx_sta_scan_cmd(?, ?, lit:g_ic+0x130) */
    cnx_sta_scan_cmd(?, ?, lit:g_ic+0x130);
    return last_call_result; /* opaque */
}

/* wifi_set_mac_process @ ieee80211_ioctl.o 0x00000058 size 322B bind GLOBAL
 * Calls: memcmp, memcmp, do_wifi_stop, memcpy, do_wifi_start, memcmp, memcmp, do_wifi_stop, memcpy, memcmp, memcmp, memcmp, do_wifi_stop, memcpy, do_wifi_start | Data refs: g_wifi_nvs, g_ic+0x212, g_ic+0x20c, g_ic, g_ic+0x218
 * Fidelity: low - 117 insns, 14 branches, 0 loops; skeleton only */
u32 wifi_set_mac_process(u32 a2)
{
    /* frame: entry a1,32; 117 insns, 14 cond-branches, 0 loops, 5 jumps */
    /* immediates: 0x102, -3, 6, 2 */
    /* first predicate: bltui a6, 3, 67 <wifi_set_mac_process+0xf> (condition opaque) */
    /* mem ld8: base=(?) off=8 */
    /* mem ld8: base=(?) off=20 */
    /* mem ld32: base=(lit:g_wifi_nvs) off=0 */
    /* mem ld8: base=(*(g_wifi_nvs+0)) off=0 */
    /* site +0x9b: memcmp(lit:g_ic+0x212, ?, 6) */
    memcmp(lit:g_ic+0x212, ?, 6);
    /* site +0xad: memcmp(lit:g_ic+0x20c, (?+20), 6) */
    memcmp(lit:g_ic+0x20c, (?+20), 6);
    /* site +0xbb: do_wifi_stop(*(g_wifi_nvs+0), (?+20), 6) */
    do_wifi_stop(*(g_wifi_nvs+0), (?+20), 6);
    /* site +0xce: memcpy(((lit:g_ic+131072)+18), (?+20), 6) */
    memcpy(((lit:g_ic+131072)+18), (?+20), 6);
    /* site +0xd6: do_wifi_start(*(g_wifi_nvs+0), (?+20), 6) */
    do_wifi_start(*(g_wifi_nvs+0), (?+20), 6);
    /* site +0xfb: memcmp(lit:g_ic+0x20c, (?+20), 6) */
    memcmp(lit:g_ic+0x20c, (?+20), 6);
    /* site +0x10d: memcmp(lit:g_ic+0x212, (?+20), 6) */
    memcmp(lit:g_ic+0x212, (?+20), 6);
    /* site +0x11b: do_wifi_stop(2, (?+20), 6) */
    do_wifi_stop(2, (?+20), 6);
    /* site +0x12d: memcpy(((lit:g_ic+131072)+12), (?+20), 6) */
    memcpy(((lit:g_ic+131072)+12), (?+20), 6);
    /* site +0x146: memcmp(lit:g_ic+0x212, (?+20), 6) */
    memcmp(lit:g_ic+0x212, (?+20), 6);
    /* site +0x15b: memcmp(lit:g_ic+0x20c, (?+20), 6) */
    memcmp(lit:g_ic+0x20c, (?+20), 6);
    /* site +0x16a: memcmp(lit:g_ic+0x218, (?+20), 6) */
    memcmp(lit:g_ic+0x218, (?+20), 6);
    /* site +0x176: do_wifi_stop((*(g_wifi_nvs+0)+-2), (?+20), 6) */
    do_wifi_stop((*(g_wifi_nvs+0)+-2), (?+20), 6);
    /* site +0x189: memcpy(((lit:g_ic+131072)+24), (?+20), 6) */
    memcpy(((lit:g_ic+131072)+24), (?+20), 6);
    /* site +0x191: do_wifi_start((*(g_wifi_nvs+0)+-2), (?+20), 6) */
    do_wifi_start((*(g_wifi_nvs+0)+-2), (?+20), 6);
    return *(?+20);
}

/* wifi_set_promis_filter_process @ ieee80211_ioctl.o 0x00000004 size 15B bind GLOBAL
 * Calls: ic_set_promis_filter | Data refs: none
 * Fidelity: high - straight-line, fully mapped (6 insns) */
u32 wifi_set_promis_filter_process(u32 a2)
{
    /* frame: entry a1,32; 6 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0 */
    /* mem ld32: base=(?) off=12 */
    /* site +0xe: ic_set_promis_filter(*(?+12)) */
    ic_set_promis_filter(*(?+12));
    return 0;
}

/* wifi_set_promis_ctrl_filter_process @ ieee80211_ioctl.o 0x00000004 size 15B bind GLOBAL
 * Calls: ic_set_promis_ctrl_filter | Data refs: none
 * Fidelity: high - straight-line, fully mapped (6 insns) */
u32 wifi_set_promis_ctrl_filter_process(u32 a2)
{
    /* frame: entry a1,32; 6 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0 */
    /* mem ld32: base=(?) off=12 */
    /* site +0xe: ic_set_promis_ctrl_filter(*(?+12)) */
    ic_set_promis_ctrl_filter(*(?+12));
    return 0;
}

/* wifi_set_auto_connect_process @ ieee80211_ioctl.o 0x00000018 size 93B bind GLOBAL
 * Calls: wifi_nvs_get, wifi_nvs_set, wifi_nvs_commit | Data refs: g_wifi_nvs, g_ic
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 wifi_set_auto_connect_process(u32 a2)
{
    /* frame: entry a1,32; 34 insns, 3 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0, 1, 253, 6 */
    /* first predicate: bnei a12, 1, 71 <wifi_set_auto_connect_process+0x59> (condition opaque) */
    /* mem ld8: base=(?) off=8 */
    /* mem ld32: base=(lit:g_wifi_nvs) off=0 */
    /* mem ld8: base=(*(g_wifi_nvs+0)) off=0 */
    /* mem ld8: base=(ret@1e) off=145 */
    /* mem st8: base=(ret@1e) off=145 */
    /* mem ld8: base=((lit:g_ic+131072)) off=31 */
    /* site +0x1e: wifi_nvs_get(/* no traced args */) */
    wifi_nvs_get(/* no traced args */);
    /* site +0x66: wifi_nvs_set(6, 1, *(g_wifi_nvs+0), *(ret@1e+145)) */
    wifi_nvs_set(6, 1, *(g_wifi_nvs+0), *(ret@1e+145));
    /* site +0x6e: wifi_nvs_commit(ret@66, 1, *(g_wifi_nvs+0), *(ret@1e+145)) */
    wifi_nvs_commit(ret@66, 1, *(g_wifi_nvs+0), *(ret@1e+145));
    return last_call_result; /* opaque */
}

/* wifi_softap_max_support_num @ ieee80211_ioctl.o 0x00000004 size 28B bind GLOBAL
 * Calls: none | Data refs: g_wifi_menuconfig
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 wifi_softap_max_support_num(u32 a2)
{
    /* frame: entry a1,32; 11 insns, 1 cond-branches, 0 loops, 0 jumps */
    /* immediates: 16, 0, 17, 15 */
    /* first predicate: blt a9, a8, 1e <wifi_softap_max_support_num+0x1a> (condition opaque) */
    /* mem ld32: base=(lit:g_wifi_menuconfig) off=80 */
    return opaque_result; /* full dataflow not recovered */
}

/* wifi_softap_set_config @ ieee80211_ioctl.o 0x0000019c size 2958B bind GLOBAL
 * Calls: wifi_nvs_get, map_wifi_config_sae_pwe_to_supp, wifi_log, memcmp, memcmp, memcmp, memcmp, strnlen, memcpy, wifi_nvs_compare_cfg_diff, wifi_pmk_is_valid, wifi_nvs_compare_cfg_diff, wifi_log, wifi_log, wifi_nvs_set, wifi_nvs_set, wifi_nvs_set, strnlen, hexstr2bin, wifi_log, ieee80211_regdomain_ap_min_chan, ieee80211_regdomain_check_ap_channel, chm_get_band_from_chan, ieee80211_regdomain_check_ap_channel, ieee80211_regdomain_get_country, band2str, wifi_log, chm_get_band_from_chan, band2str, band2str, wifi_log, chm_get_band_from_chan, ieee80211_regdomain_ap_min_chan, ieee80211_regdomain_ap_max_chan, wifi_log, wifi_nvs_set, wifi_nvs_set, ieee80211_adjust_2nd_chan, indirect(a10), memcmp, memcmp, memcpy, memcpy, indirect(a7), wifi_nvs_set, wifi_nvs_commit, indirect(a10), wifi_set_default_ssid, memcpy, wifi_nvs_set, memcpy, wifi_nvs_set, strnlen, wifi_nvs_set, wifi_softap_max_support_num, wifi_log, wifi_nvs_set, wifi_nvs_set, wifi_nvs_set, wifi_nvs_set, wifi_nvs_set, wifi_nvs_set, wifi_nvs_set, wifi_nvs_set, wDev_Set_Beacon_Int, wifi_pmk_is_valid, strnlen, memcpy, memcpy, indirect(a9), wifi_log, wifi_nvs_set, wifi_nvs_set, memcpy, memcpy, wifi_nvs_set, wifi_nvs_set, wifi_nvs_set, wifi_log, wifi_nvs_set, wifi_nvs_set, wifi_nvs_commit, indirect(a10) | Data refs: g_wifi_nvs, g_wifi_menuconfig, .rodata_wlog_error.51, .rodata.CSWTCH$391, g_ic, .rodata_wlog_error.52, .rodata_wlog_info.53, .rodata_wlog_error.54, .rodata_wlog_warning.55, .rodata_wlog_warning.56, .rodata_wlog_error.57, .rodata_wlog_warning.58, .rodata_wlog_error.59, net80211_funcs, wpa_crypto_funcs, .rodata_wlog_warning.60, .rodata_wlog_warning.61, .rodata_wlog_warning.62, .rodata_wlog_warning.63, g_ic+0x200
 * Fidelity: low - 1069 insns, 109 branches, 0 loops; skeleton only */
u32 wifi_softap_set_config(u32 a2, u32 a4)
{
    /* frame: entry a1,128; 1069 insns, 109 cond-branches, 0 loops, 45 jumps */
    /* immediates: 6, 9, 1, 2, 0x102, 0x36c, 32, 0x4b4, 0x392, 64 */
    /* first predicate: bnez.n a3, 1b0 <wifi_softap_set_config+0x14> (condition opaque) */
    /* mem ld32: base=(lit:g_wifi_nvs) off=0 */
    /* mem ld8: base=(*(g_wifi_nvs+0)) off=0 */
    /* mem ld32: base=(?) off=120 */
    /* mem ld32: base=(?) off=100 */
    /* mem st32: base=(?) off=100 */
    /* mem ld32: base=(?) off=100 */
    /* mem ld32: base=(lit:g_wifi_menuconfig) off=64 */
    /* mem st32: base=(?) off=72 */
    /* mem ld8: base=((ret@1bf+196608)) off=244 */
    /* mem st32: base=(?) off=64 */
    /* ... +225 more memops */
    /* site +0x1bf: wifi_nvs_get(/* no traced args */) */
    wifi_nvs_get(/* no traced args */);
    /* site +0x1ca: map_wifi_config_sae_pwe_to_supp(*(?+120)) */
    map_wifi_config_sae_pwe_to_supp(*(?+120));
    /* site +0x1fe: wifi_log(1, 2, 1, lit:.rodata_wlog_error.51) */
    wifi_log(1, 2, 1, lit:.rodata_wlog_error.51);
    /* site +0x21e: memcmp(ret@1fe, ?, 32, lit:.rodata_wlog_error.51) */
    memcmp(ret@1fe, ?, 32, lit:.rodata_wlog_error.51);
    /* site +0x231: memcmp(0x4b4, ?, 32, lit:.rodata_wlog_error.51) */
    memcmp(0x4b4, ?, 32, lit:.rodata_wlog_error.51);
    /* site +0x246: memcmp(0x392, (?+32), 64, lit:.rodata_wlog_error.51) */
    memcmp(0x392, (?+32), 64, lit:.rodata_wlog_error.51);
    /* site +0x259: memcmp(0x4d4, (?+32), 64, lit:.rodata_wlog_error.51) */
    memcmp(0x4d4, (?+32), 64, lit:.rodata_wlog_error.51);
    /* site +0x343: strnlen((ret@1bf+327680), 32, *((ret@1bf+262144)+1), lit:.rodata_wlog_error.51) */
    strnlen((ret@1bf+327680), 32, *((ret@1bf+262144)+1), lit:.rodata_wlog_error.51);
    /* site +0x356: memcpy((?+20), ?, 32, lit:.rodata_wlog_error.51) */
    memcpy((?+20), ?, 32, lit:.rodata_wlog_error.51);
    /* site +0x361: wifi_nvs_compare_cfg_diff(23, (?+16), 32, lit:.rodata_wlog_error.51) */
    wifi_nvs_compare_cfg_diff(23, (?+16), 32, lit:.rodata_wlog_error.51);
    /* site +0x37a: wifi_pmk_is_valid(0x514, (?+16), 32, lit:.rodata_wlog_error.51) */
    wifi_pmk_is_valid(0x514, (?+16), 32, lit:.rodata_wlog_error.51);
    /* site +0x396: wifi_nvs_compare_cfg_diff(34, (?+52), 32, lit:.rodata_wlog_error.51) */
    wifi_nvs_compare_cfg_diff(34, (?+52), 32, lit:.rodata_wlog_error.51);
    /* site +0x409: wifi_log(1, 3, 3, lit:.rodata_wlog_info.53) */
    wifi_log(1, 3, 3, lit:.rodata_wlog_info.53);
    /* site +0x42d: wifi_log(1, 3, 1, lit:.rodata_wlog_error.54, *(?+100)) */
    wifi_log(1, 3, 1, lit:.rodata_wlog_error.54, *(?+100));
    /* site +0x456: wifi_nvs_set(27, 3, 0, lit:.rodata_wlog_error.54, *(?+100)) */
    wifi_nvs_set(27, 3, 0, lit:.rodata_wlog_error.54, *(?+100));
    /* site +0x48a: wifi_nvs_set(84, ret@456, ret@456, lit:.rodata_wlog_error.54, *(?+100)) */
    wifi_nvs_set(84, ret@456, ret@456, lit:.rodata_wlog_error.54, *(?+100));
    /* site +0x4ca: wifi_nvs_set(56, 2, 0, lit:.rodata_wlog_error.54, *(?+100)) */
    wifi_nvs_set(56, 2, 0, lit:.rodata_wlog_error.54, *(?+100));
    /* site +0x506: strnlen((?+32), 64, 0, lit:.rodata_wlog_error.54, *(?+100)) */
    strnlen((?+32), 64, 0, lit:.rodata_wlog_error.54, *(?+100));
    /* site +0x52d: hexstr2bin(ret@506, 0x514, 32, lit:.rodata_wlog_warning.55, *(?+100)) */
    hexstr2bin(ret@506, 0x514, 32, lit:.rodata_wlog_warning.55, *(?+100));
    /* site +0x542: wifi_log(*(?+92), 2, 2, lit:.rodata_wlog_warning.56, *(?+100)) */
    wifi_log(*(?+92), 2, 2, lit:.rodata_wlog_warning.56, *(?+100));
    /* site +0x55d: ieee80211_regdomain_ap_min_chan(1, 2, 2, lit:.rodata_wlog_warning.56, *(?+100)) */
    ieee80211_regdomain_ap_min_chan(1, 2, 2, lit:.rodata_wlog_warning.56, *(?+100));
    /* site +0x56a: ieee80211_regdomain_check_ap_channel(*(?+97), 2, 2, lit:.rodata_wlog_warning.56, *(?+100)) */
    ieee80211_regdomain_check_ap_channel(*(?+97), 2, 2, lit:.rodata_wlog_warning.56, *(?+100));
    /* site +0x595: chm_get_band_from_chan(*(g_ic+171), 2, 2, lit:.rodata_wlog_warning.56, *(?+100)) */
    chm_get_band_from_chan(*(g_ic+171), 2, 2, lit:.rodata_wlog_warning.56, *(?+100));
    /* site +0x59f: ieee80211_regdomain_check_ap_channel(*(g_ic+171), 2, 2, lit:.rodata_wlog_warning.56, *(?+100)) */
    ieee80211_regdomain_check_ap_channel(*(g_ic+171), 2, 2, lit:.rodata_wlog_warning.56, *(?+100));
    /* site +0x5a7: ieee80211_regdomain_get_country(ret@59f, 2, 2, lit:.rodata_wlog_warning.56, *(?+100)) */
    ieee80211_regdomain_get_country(ret@59f, 2, 2, lit:.rodata_wlog_warning.56, *(?+100));
    /* site +0x5b1: band2str(ret@595, 2, 2, lit:.rodata_wlog_warning.56, *(?+100)) */
    band2str(ret@595, 2, 2, lit:.rodata_wlog_warning.56, *(?+100));
    /* site +0x5d1: wifi_log(1, 3, 1, lit:.rodata_wlog_error.57, *(g_ic+171)) */
    wifi_log(1, 3, 1, lit:.rodata_wlog_error.57, *(g_ic+171));
    /* site +0x5e6: chm_get_band_from_chan(*(*(ret@5a7+0)+97), 3, 1, lit:.rodata_wlog_error.57, *(*(ret@5a7+0)+97)) */
    chm_get_band_from_chan(*(*(ret@5a7+0)+97), 3, 1, lit:.rodata_wlog_error.57, *(*(ret@5a7+0)+97));
    /* site +0x5ec: band2str(ret@5e6, 3, 1, lit:.rodata_wlog_error.57, *(*(ret@5a7+0)+97)) */
    band2str(ret@5e6, 3, 1, lit:.rodata_wlog_error.57, *(*(ret@5a7+0)+97));
    /* site +0x5fd: band2str(ret@5ec, 3, 1, lit:.rodata_wlog_error.57, *(*(ret@5a7+0)+97)) */
    band2str(ret@5ec, 3, 1, lit:.rodata_wlog_error.57, *(*(ret@5a7+0)+97));
    /* site +0x619: wifi_log(1, 3, 2, lit:.rodata_wlog_warning.58, *(?+88)) */
    wifi_log(1, 3, 2, lit:.rodata_wlog_warning.58, *(?+88));
    /* site +0x626: chm_get_band_from_chan(*(*(ret@5a7+0)+97), 3, 2, lit:.rodata_wlog_warning.58, *(?+88)) */
    chm_get_band_from_chan(*(*(ret@5a7+0)+97), 3, 2, lit:.rodata_wlog_warning.58, *(?+88));
    /* site +0x63b: ieee80211_regdomain_ap_min_chan(ret@626, 3, 2, lit:.rodata_wlog_warning.58, *(?+88)) */
    ieee80211_regdomain_ap_min_chan(ret@626, 3, 2, lit:.rodata_wlog_warning.58, *(?+88));
    /* site +0x649: ieee80211_regdomain_ap_max_chan(*(?+92), 3, 2, lit:.rodata_wlog_warning.58, *(?+88)) */
    ieee80211_regdomain_ap_max_chan(*(?+92), 3, 2, lit:.rodata_wlog_warning.58, *(?+88));
    /* site +0x675: wifi_log(ret@649, 3, *(?+92), lit:.rodata_wlog_error.59, *(*(ret@5a7+0)+97)) */
    wifi_log(ret@649, 3, *(?+92), lit:.rodata_wlog_error.59, *(*(ret@5a7+0)+97));
    /* site +0x6ab: wifi_nvs_set(69, 1, 0, lit:.rodata_wlog_error.59, *(*(ret@5a7+0)+97)) */
    wifi_nvs_set(69, 1, 0, lit:.rodata_wlog_error.59, *(*(ret@5a7+0)+97));
    /* site +0x6c9: wifi_nvs_set(26, *((*((ret@595+262144)+4)+196608)+243), ret@6ab, lit:.rodata_wlog_error.59, *(*(ret@5a7+0)+97)) */
    wifi_nvs_set(26, *((*((ret@595+262144)+4)+196608)+243), ret@6ab, lit:.rodata_wlog_error.59, *(*(ret@5a7+0)+97));
    /* site +0x6da: ieee80211_adjust_2nd_chan(ret@6c9, *((*((ret@595+262144)+4)+196608)+243), ret@6ab, lit:.rodata_wlog_error.59, *(*(ret@5a7+0)+97)) */
    ieee80211_adjust_2nd_chan(ret@6c9, *((*((ret@595+262144)+4)+196608)+243), ret@6ab, lit:.rodata_wlog_error.59, *(*(ret@5a7+0)+97));
    /* site +0x6f2: indirect call via a10 (base *(net80211_funcs+16)); args: *(net80211_funcs+16), *((*((ret@595+262144)+4)+196608)+243), ret@6ab, lit:.rodata_wlog_error.59, *(*(ret@5a7+0)+97) */
    opaque_indirect_a10();
    /* site +0x72b: memcmp(*(?+72), *((*((ret@595+262144)+4)+196608)+243), 32, lit:.rodata_wlog_error.59, *(*(ret@5a7+0)+97)) */
    memcmp(*(?+72), *((*((ret@595+262144)+4)+196608)+243), 32, lit:.rodata_wlog_error.59, *(*(ret@5a7+0)+97));
    /* site +0x741: memcmp(ret@72b, 0x4d4, 64, lit:.rodata_wlog_error.59, *(*(ret@5a7+0)+97)) */
    memcmp(ret@72b, 0x4d4, 64, lit:.rodata_wlog_error.59, *(*(ret@5a7+0)+97));
    /* site +0x762: memcpy(0x4b4, *(?+72), 32, lit:.rodata_wlog_error.59, *(*(ret@5a7+0)+97)) */
    memcpy(0x4b4, *(?+72), 32, lit:.rodata_wlog_error.59, *(*(ret@5a7+0)+97));
    /* site +0x76e: memcpy(0x4d4, 0x392, 64, lit:.rodata_wlog_error.59, *(*(ret@5a7+0)+97)) */
    memcpy(0x4d4, 0x392, 64, lit:.rodata_wlog_error.59, *(*(ret@5a7+0)+97));
    /* site +0x792: indirect call via a7 (base *(wpa_crypto_funcs+12)); args: 0x4d4, 0x4b4, *(wpa_crypto_funcs+176), (1 slli 12), 0x514 */
    opaque_indirect_a7();
    /* site +0x7a9: wifi_nvs_set(57, 0x4b0, 1, (1 slli 12), 0x514) */
    wifi_nvs_set(57, 0x4b0, 1, (1 slli 12), 0x514);
    /* site +0x7b5: wifi_nvs_commit(ret@7a9, 0x4b0, 1, (1 slli 12), 0x514) */
    wifi_nvs_commit(ret@7a9, 0x4b0, 1, (1 slli 12), 0x514);
    /* site +0x7d5: indirect call via a10 (base *(net80211_funcs+12)); args: *(net80211_funcs+12), 0x4b0, 1, (1 slli 12), 0x514 */
    opaque_indirect_a10();
    /* site +0x7f3: wifi_set_default_ssid(ret@7d5, 0x4b0, 1, (1 slli 12), 0x514) */
    wifi_set_default_ssid(ret@7d5, 0x4b0, 1, (1 slli 12), 0x514);
    /* site +0x80b: memcpy(*(?+72), *(g_wifi_nvs+0), 32, (1 slli 12), 0x514) */
    memcpy(*(?+72), *(g_wifi_nvs+0), 32, (1 slli 12), 0x514);
    /* site +0x81f: wifi_nvs_set(23, *(g_wifi_nvs+0), 1, (1 slli 12), 0x514) */
    wifi_nvs_set(23, *(g_wifi_nvs+0), 1, (1 slli 12), 0x514);
    /* site +0x83a: memcpy(ret@81f, (*((lit:g_ic+131072)+31)+32), 64, (1 slli 12), 0x514) */
    memcpy(ret@81f, (*((lit:g_ic+131072)+31)+32), 64, (1 slli 12), 0x514);
    /* site +0x859: wifi_nvs_set(24, 0x392, 1, (1 slli 12), 0x514) */
    wifi_nvs_set(24, 0x392, 1, (1 slli 12), 0x514);
    /* site +0x872: strnlen(*(*((lit:g_ic+131072)+31)+96), 32, 1, (1 slli 12), 0x514) */
    strnlen(*(*((lit:g_ic+131072)+31)+96), 32, 1, (1 slli 12), 0x514);
    /* site +0x8a9: wifi_nvs_set(28, ret@872, 0, (1 slli 12), 0x514) */
    wifi_nvs_set(28, ret@872, 0, (1 slli 12), 0x514);
    /* site +0x8bd: wifi_softap_max_support_num(ret@8a9, ret@872, 0, (1 slli 12), 0x514) */
    wifi_softap_max_support_num(ret@8a9, ret@872, 0, (1 slli 12), 0x514);
    /* site +0x8de: wifi_log(1, 3, 2, lit:.rodata_wlog_warning.60, 0x514) */
    wifi_log(1, 3, 2, lit:.rodata_wlog_warning.60, 0x514);
    /* site +0x902: wifi_nvs_set(29, *(*(wpa_crypto_funcs+12)+246), 1, lit:.rodata_wlog_warning.60, 0x514) */
    wifi_nvs_set(29, *(*(wpa_crypto_funcs+12)+246), 1, lit:.rodata_wlog_warning.60, 0x514);
    /* site +0x93a: wifi_nvs_set(30, 100, 0, lit:.rodata_wlog_warning.60, 0x514) */
    wifi_nvs_set(30, 100, 0, lit:.rodata_wlog_warning.60, 0x514);
    /* site +0x95d: wifi_nvs_set(77, ret@93a, ret@93a, lit:.rodata_wlog_warning.60, 0x514) */
    wifi_nvs_set(77, ret@93a, ret@93a, lit:.rodata_wlog_warning.60, 0x514);
    /* site +0x983: wifi_nvs_set(80, *(*((lit:g_ic+131072)+31)+130), *((lit:g_ic+131072)+31), lit:.rodata_wlog_warning.60, 0x514) */
    wifi_nvs_set(80, *(*((lit:g_ic+131072)+31)+130), *((lit:g_ic+131072)+31), lit:.rodata_wlog_warning.60, 0x514);
    /* site +0x9c7: wifi_nvs_set(36, 5, 0, lit:.rodata_wlog_warning.60, 0x514) */
    wifi_nvs_set(36, 5, 0, lit:.rodata_wlog_warning.60, 0x514);
    /* site +0x9f1: wifi_nvs_set(76, *(*((lit:g_ic+131072)+31)+124), ret@9c7, lit:.rodata_wlog_warning.60, 0x514) */
    wifi_nvs_set(76, *(*((lit:g_ic+131072)+31)+124), ret@9c7, lit:.rodata_wlog_warning.60, 0x514);
    /* site +0xa1b: wifi_nvs_set(88, *(?+68), ret@9f1, lit:.rodata_wlog_warning.60, 0x514) */
    wifi_nvs_set(88, *(?+68), ret@9f1, lit:.rodata_wlog_warning.60, 0x514);
    /* site +0xa41: wifi_nvs_set(39, *(*((lit:g_ic+131072)+31)+116), *((lit:g_ic+131072)+31), lit:.rodata_wlog_warning.60, 0x514) */
    wifi_nvs_set(39, *(*((lit:g_ic+131072)+31)+116), *((lit:g_ic+131072)+31), lit:.rodata_wlog_warning.60, 0x514);
    /* site +0xa67: wDev_Set_Beacon_Int(((*(*(wpa_crypto_funcs+12)+248) srli 5) s..., *(*((lit:g_ic+131072)+31)+116), *((lit:g_ic+131072)+31), lit:.rodata_wlog_warning.60, 0x514) */
    wDev_Set_Beacon_Int(((*(*(wpa_crypto_funcs+12)+248) srli 5) s..., *(*((lit:g_ic+131072)+31)+116), *((lit:g_ic+131072)+31), lit:.rodata_wlog_warning.60, 0x514);
    /* site +0xa95: wifi_pmk_is_valid(0x514, *(*((lit:g_ic+131072)+31)+116), *((lit:g_ic+131072)+31), lit:.rodata_wlog_warning.60, 0x514) */
    wifi_pmk_is_valid(0x514, *(*((lit:g_ic+131072)+31)+116), *((lit:g_ic+131072)+31), lit:.rodata_wlog_warning.60, 0x514);
    /* site +0xaad: strnlen(0x392, 64, *((lit:g_ic+131072)+31), lit:.rodata_wlog_warning.60, 0x514) */
    strnlen(0x392, 64, *((lit:g_ic+131072)+31), lit:.rodata_wlog_warning.60, 0x514);
    /* site +0xadb: memcpy(0x4b4, *(?+72), 32, lit:.rodata_wlog_warning.60, 0x514) */
    memcpy(0x4b4, *(?+72), 32, lit:.rodata_wlog_warning.60, 0x514);
    /* site +0xaef: memcpy(0x4d4, 0x392, 64, lit:.rodata_wlog_warning.60, 0x514) */
    memcpy(0x4d4, 0x392, 64, lit:.rodata_wlog_warning.60, 0x514);
    /* site +0xb11: indirect call via a9 (base *(?+84)); args: *(?+68), *(?+92), *(g_wifi_nvs+0x368), (1 slli 12), *(?+88) */
    opaque_indirect_a9();
    /* site +0xb79: wifi_log(1, 1, 2, lit:.rodata_wlog_warning.62, *(?+88)) */
    wifi_log(1, 1, 2, lit:.rodata_wlog_warning.62, *(?+88));
    /* site +0xba1: wifi_nvs_set(34, *((*((ret@595+262144)+4)+196608)+253), 0, lit:.rodata_wlog_warning.62, *(?+88)) */
    wifi_nvs_set(34, *((*((ret@595+262144)+4)+196608)+253), 0, lit:.rodata_wlog_warning.62, *(?+88));
    /* site +0xbb9: wifi_nvs_set(35, *((*((ret@595+262144)+4)+196608)+254), ret@ba1, lit:.rodata_wlog_warning.62, *(?+88)) */
    wifi_nvs_set(35, *((*((ret@595+262144)+4)+196608)+254), ret@ba1, lit:.rodata_wlog_warning.62, *(?+88));
    /* site +0xbf6: memcpy(0x4b4, *(?+72), 32, lit:.rodata_wlog_warning.62, *(?+88)) */
    memcpy(0x4b4, *(?+72), 32, lit:.rodata_wlog_warning.62, *(?+88));
    /* site +0xc05: memcpy(0x4d4, 1, 64, lit:.rodata_wlog_warning.62, *(?+88)) */
    memcpy(0x4d4, 1, 64, lit:.rodata_wlog_warning.62, *(?+88));
    /* site +0xc25: wifi_nvs_set(57, 0x4b0, 1, lit:.rodata_wlog_warning.62, *(?+88)) */
    wifi_nvs_set(57, 0x4b0, 1, lit:.rodata_wlog_warning.62, *(?+88));
    /* site +0xc4e: wifi_nvs_set(74, 0x4b0, 0, lit:.rodata_wlog_warning.62, *(?+88)) */
    wifi_nvs_set(74, 0x4b0, 0, lit:.rodata_wlog_warning.62, *(?+88));
    /* site +0xc75: wifi_nvs_set(75, *(*((lit:g_ic+131072)+31)+109), ret@c4e, lit:.rodata_wlog_warning.62, *(?+88)) */
    wifi_nvs_set(75, *(*((lit:g_ic+131072)+31)+109), ret@c4e, lit:.rodata_wlog_warning.62, *(?+88));
    /* site +0xca1: wifi_log(1, 3, 2, lit:.rodata_wlog_warning.63, *(?+88)) */
    wifi_log(1, 3, 2, lit:.rodata_wlog_warning.63, *(?+88));
    /* site +0xcc7: wifi_nvs_set(78, *(g_wifi_nvs+62), 1, lit:.rodata_wlog_warning.63, *(?+88)) */
    wifi_nvs_set(78, *(g_wifi_nvs+62), 1, lit:.rodata_wlog_warning.63, *(?+88));
    /* site +0xcfa: wifi_nvs_set(79, *(*((lit:g_ic+131072)+31)+128), 1, lit:.rodata_wlog_warning.63, *(?+88)) */
    wifi_nvs_set(79, *(*((lit:g_ic+131072)+31)+128), 1, lit:.rodata_wlog_warning.63, *(?+88));
    /* site +0xd05: wifi_nvs_commit(ret@cfa, *(*((lit:g_ic+131072)+31)+128), 1, lit:.rodata_wlog_warning.63, *(?+88)) */
    wifi_nvs_commit(ret@cfa, *(*((lit:g_ic+131072)+31)+128), 1, lit:.rodata_wlog_warning.63, *(?+88));
    /* site +0xd21: indirect call via a10 (base *(net80211_funcs+12)); args: *(net80211_funcs+12), *(*((lit:g_ic+131072)+31)+128), 1, lit:.rodata_wlog_warning.63, *(?+88) */
    opaque_indirect_a10();
    return last_call_result; /* opaque */
}

/* wifi_get_macaddr @ ieee80211_ioctl.o 0x00000010 size 45B bind GLOBAL
 * Calls: memcpy | Data refs: g_ic+0x212, g_ic+0x218, g_ic+0x20c
 * Fidelity: medium - branchy but loop-free, call sequence mapped */
u32 wifi_get_macaddr(u32 a2, u32 a3)
{
    /* frame: entry a1,32; 17 insns, 4 cond-branches, 0 loops, 1 jumps */
    /* immediates: 6, 1, 0 */
    /* first predicate: bgeui a2, 3, 39 <wifi_get_macaddr+0x29> (condition opaque) */
    /* site +0x31: memcpy(?, lit:g_ic+0x20c, 6) */
    memcpy(?, lit:g_ic+0x20c, 6);
    return 0;
}

/* chip_post_deinit @ ieee80211_ioctl.o 0x00000008 size 17B bind GLOBAL
 * Calls: ic_deinit, ieee80211_ifdetach | Data refs: none
 * Fidelity: high - straight-line, fully mapped (6 insns) */
u32 chip_post_deinit(void)
{
    /* frame: entry a1,32; 6 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* site +0xe: ic_deinit(/* no traced args */) */
    ic_deinit(/* no traced args */);
    /* site +0x14: ieee80211_ifdetach(ret@0e) */
    ieee80211_ifdetach(ret@0e);
    return opaque_result; /* full dataflow not recovered */
}

/* chip_enable @ ieee80211_ioctl.o 0x00000010 size 36B bind GLOBAL
 * Calls: wifi_log, wifi_set_rx_policy, ic_enable_rx | Data refs: .rodata_wlog_debug.64
 * Fidelity: high - straight-line, fully mapped (14 insns) */
u32 chip_enable(void)
{
    /* frame: entry a1,32; 14 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0, 4, 12, 1 */
    /* site +0x21: wifi_log(1, 12, 4, lit:.rodata_wlog_debug.64, 0) */
    wifi_log(1, 12, 4, lit:.rodata_wlog_debug.64, 0);
    /* site +0x29: wifi_set_rx_policy(0, 12, 4, lit:.rodata_wlog_debug.64, 0) */
    wifi_set_rx_policy(0, 12, 4, lit:.rodata_wlog_debug.64, 0);
    /* site +0x2f: ic_enable_rx(ret@29, 12, 4, lit:.rodata_wlog_debug.64, 0) */
    ic_enable_rx(ret@29, 12, 4, lit:.rodata_wlog_debug.64, 0);
    return opaque_result; /* full dataflow not recovered */
}

/* chip_disable @ ieee80211_ioctl.o 0x00000010 size 36B bind GLOBAL
 * Calls: ic_disable_rx, wifi_log, wifi_set_rx_policy | Data refs: .rodata_wlog_debug.65
 * Fidelity: high - straight-line, fully mapped (14 insns) */
u32 chip_disable(void)
{
    /* frame: entry a1,32; 14 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0, 4, 12, 1 */
    /* site +0x16: ic_disable_rx(/* no traced args */) */
    ic_disable_rx(/* no traced args */);
    /* site +0x27: wifi_log(1, 12, 4, lit:.rodata_wlog_debug.65, 0) */
    wifi_log(1, 12, 4, lit:.rodata_wlog_debug.65, 0);
    /* site +0x2f: wifi_set_rx_policy(0, 12, 4, lit:.rodata_wlog_debug.65, 0) */
    wifi_set_rx_policy(0, 12, 4, lit:.rodata_wlog_debug.65, 0);
    return opaque_result; /* full dataflow not recovered */
}

/* wifi_reset_mac @ ieee80211_ioctl.o 0x00000018 size 80B bind GLOBAL
 * Calls: indirect(a8), indirect(a8), coex_bt_high_prio, indirect(a2) | Data refs: g_osi_funcs_p, g_wdev_last_desc_reset
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 wifi_reset_mac(u32 a2)
{
    /* frame: entry a1,32; 30 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0, 41, 1 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=0x19c */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=252 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=0x1a0 */
    /* mem st8: base=(lit:g_wdev_last_desc_reset) off=0 */
    /* mem ld32: base=(literal) off=0 */
    /* mem st32: base=(literal) off=0 */
    /* site +0x2a: indirect call via a8 (base *(*(g_osi_funcs_p+0)+0x19c)); args: 41, 0, literal */
    opaque_indirect_a8();
    /* site +0x32: indirect call via a8 (base *(*(g_osi_funcs_p+0)+252)); args: ret@2a, 0, literal */
    opaque_indirect_a8();
    /* site +0x38: coex_bt_high_prio(ret@32, 0, literal) */
    coex_bt_high_prio(ret@32, 0, literal);
    /* site +0x42: indirect call via a2 (base *(g_osi_funcs_p+0x1a0)); args: 41, 0, literal */
    opaque_indirect_a2();
    return opaque_result; /* full dataflow not recovered */
}

/* wifi_rf_phy_enable @ ieee80211_ioctl.o 0x00000020 size 131B bind GLOBAL
 * Calls: wifi_log, indirect(a8), indirect(a8), pm_mac_wakeup, indirect(a10), indirect(a4), ic_mac_init | Data refs: g_ic, .rodata.str1.1, .rodata_wlog_error.67, g_osi_funcs_p, g_mac_sleep_en
 * Fidelity: medium - branchy but loop-free, call sequence mapped */
u32 wifi_rf_phy_enable(u32 a2, u32 a3)
{
    /* frame: entry a1,32; 46 insns, 4 cond-branches, 0 loops, 1 jumps */
    /* immediates: 1, 0x547 */
    /* first predicate: bbc a4, a2, 4c <wifi_rf_phy_enable+0x2c> (condition opaque) */
    /* mem ld8: base=((lit:g_ic+131072)) off=82 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=200 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=0x100 */
    /* mem ld8: base=(lit:g_mac_sleep_en) off=0 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=4 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=212 */
    /* ... +2 more memops */
    /* site +0x45: wifi_log(?, (1 slli 11), 1, lit:.rodata_wlog_error.67, lit:.rodata.str1.1) */
    wifi_log(?, (1 slli 11), 1, lit:.rodata_wlog_error.67, lit:.rodata.str1.1);
    /* site +0x56: indirect call via a8 (base *(*(g_osi_funcs_p+0)+200)); args: ret@45, (1 slli 11), 1, lit:.rodata_wlog_error.67, lit:.rodata.str1.1 */
    opaque_indirect_a8();
    /* site +0x5e: indirect call via a8 (base *(*(g_osi_funcs_p+0)+0x100)); args: ret@56, (1 slli 11), 1, lit:.rodata_wlog_error.67, lit:.rodata.str1.1 */
    opaque_indirect_a8();
    /* site +0x6d: pm_mac_wakeup(ret@5e, (1 slli 11), 1, lit:.rodata_wlog_error.67, lit:.rodata.str1.1) */
    pm_mac_wakeup(ret@5e, (1 slli 11), 1, lit:.rodata_wlog_error.67, lit:.rodata.str1.1);
    /* site +0x75: indirect call via a10 (base *(g_mac_sleep_en+4)); args: *(g_mac_sleep_en+4), (1 slli 11), 1, lit:.rodata_wlog_error.67, lit:.rodata.str1.1 */
    opaque_indirect_a10();
    /* site +0x81: indirect call via a4 (base *(g_osi_funcs_p+212)); args: ret@75, (1 slli 11), 1, lit:.rodata_wlog_error.67, lit:.rodata.str1.1 */
    opaque_indirect_a4();
    /* site +0x87: ic_mac_init(ret@81, (1 slli 11), 1, lit:.rodata_wlog_error.67, lit:.rodata.str1.1) */
    ic_mac_init(ret@81, (1 slli 11), 1, lit:.rodata_wlog_error.67, lit:.rodata.str1.1);
    return opaque_result; /* full dataflow not recovered */
}

/* wifi_rf_phy_disable @ ieee80211_ioctl.o 0x00000020 size 124B bind GLOBAL
 * Calls: wifi_log, ic_mac_deinit, indirect(a10), indirect(a8), pm_mac_sleep, indirect(a8), indirect(a2) | Data refs: g_ic, .rodata.str1.1, .rodata_wlog_error.69, g_osi_funcs_p, g_mac_sleep_en
 * Fidelity: medium - branchy but loop-free, call sequence mapped */
u32 wifi_rf_phy_disable(u32 a2)
{
    /* frame: entry a1,32; 45 insns, 4 cond-branches, 0 loops, 1 jumps */
    /* immediates: 1, 0x553, -2 */
    /* first predicate: bbs a8, a2, 4c <wifi_rf_phy_disable+0x2c> (condition opaque) */
    /* mem ld8: base=((lit:g_ic+131072)) off=82 */
    /* mem st8: base=((lit:g_ic+131072)) off=82 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=4 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=208 */
    /* mem ld8: base=(lit:g_mac_sleep_en) off=0 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=0x104 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* ... +1 more memops */
    /* site +0x45: wifi_log(?, (1 slli 11), 1, lit:.rodata_wlog_error.69, lit:.rodata.str1.1) */
    wifi_log(?, (1 slli 11), 1, lit:.rodata_wlog_error.69, lit:.rodata.str1.1);
    /* site +0x65: ic_mac_deinit(-2, (1 slli 11), 1, lit:.rodata_wlog_error.69, lit:.rodata.str1.1) */
    ic_mac_deinit(-2, (1 slli 11), 1, lit:.rodata_wlog_error.69, lit:.rodata.str1.1);
    /* site +0x6f: indirect call via a10 (base *(*(g_osi_funcs_p+0)+4)); args: *(*(g_osi_funcs_p+0)+4), (1 slli 11), 1, lit:.rodata_wlog_error.69, lit:.rodata.str1.1 */
    opaque_indirect_a10();
    /* site +0x79: indirect call via a8 (base *(*(g_osi_funcs_p+0)+208)); args: ret@6f, (1 slli 11), 1, lit:.rodata_wlog_error.69, lit:.rodata.str1.1 */
    opaque_indirect_a8();
    /* site +0x87: pm_mac_sleep(ret@79, (1 slli 11), 1, lit:.rodata_wlog_error.69, lit:.rodata.str1.1) */
    pm_mac_sleep(ret@79, (1 slli 11), 1, lit:.rodata_wlog_error.69, lit:.rodata.str1.1);
    /* site +0x8f: indirect call via a8 (base *(g_mac_sleep_en+0x104)); args: ret@87, (1 slli 11), 1, lit:.rodata_wlog_error.69, lit:.rodata.str1.1 */
    opaque_indirect_a8();
    /* site +0x97: indirect call via a2 (base *(g_osi_funcs_p+204)); args: ret@8f, (1 slli 11), 1, lit:.rodata_wlog_error.69, lit:.rodata.str1.1 */
    opaque_indirect_a2();
    return opaque_result; /* full dataflow not recovered */
}

/* wifi_hw_start @ ieee80211_ioctl.o 0x0000004c size 286B bind GLOBAL
 * Calls: wifi_log, wifi_log, ieee80211_set_hmac_stop, indirect(a8), indirect(a8), indirect(a8), indirect(a8), indirect(a10), wifi_reset_mac, ic_mac_init, chm_init, ic_set_interrupt_handler, chip_enable, pm_noise_check_enable, indirect(a5), indirect(a5), pm_mac_wakeup, indirect(a10), indirect(a4), ic_mac_init, pm_disconnected_start | Data refs: g_ic, .rodata.str1.1, .rodata_wlog_error.70, .rodata_wlog_error.71, g_osi_funcs_p, g_mac_sleep_en
 * Fidelity: low - 101 insns, 8 branches, 0 loops; skeleton only */
u32 wifi_hw_start(u32 a2, u32 a5)
{
    /* frame: entry a1,32; 101 insns, 8 cond-branches, 0 loops, 3 jumps */
    /* immediates: 1, 0x55f */
    /* first predicate: bbc a10, a2, 78 <wifi_hw_start+0x2c> (condition opaque) */
    /* mem ld8: base=((lit:g_ic+131072)) off=81 */
    /* mem ld8: base=((lit:g_ic+131072)) off=82 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=200 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=0x100 */
    /* mem ld8: base=(lit:g_mac_sleep_en) off=0 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=0x10c */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* ... +16 more memops */
    /* site +0x71: wifi_log(*((lit:g_ic+131072)+81), (1 slli 11), 1, lit:.rodata_wlog_error.70, lit:.rodata.str1.1) */
    wifi_log(*((lit:g_ic+131072)+81), (1 slli 11), 1, lit:.rodata_wlog_error.70, lit:.rodata.str1.1);
    /* site +0x91: wifi_log(1, (1 slli 11), 1, lit:.rodata_wlog_error.71, lit:.rodata.str1.1) */
    wifi_log(1, (1 slli 11), 1, lit:.rodata_wlog_error.71, lit:.rodata.str1.1);
    /* site +0x9e: ieee80211_set_hmac_stop(ret@91, (1 slli 11), 1, lit:.rodata_wlog_error.71, lit:.rodata.str1.1) */
    ieee80211_set_hmac_stop(ret@91, (1 slli 11), 1, lit:.rodata_wlog_error.71, lit:.rodata.str1.1);
    /* site +0xa9: indirect call via a8 (base *(*(g_osi_funcs_p+0)+200)); args: ret@9e, (1 slli 11), 1, lit:.rodata_wlog_error.71, lit:.rodata.str1.1 */
    opaque_indirect_a8();
    /* site +0xb1: indirect call via a8 (base *(*(g_osi_funcs_p+0)+0x100)); args: ret@a9, (1 slli 11), 1, lit:.rodata_wlog_error.71, lit:.rodata.str1.1 */
    opaque_indirect_a8();
    /* site +0xc1: indirect call via a8 (base *(g_mac_sleep_en+0x10c)); args: ret@b1, (1 slli 11), 1, lit:.rodata_wlog_error.71, lit:.rodata.str1.1 */
    opaque_indirect_a8();
    /* site +0xc9: indirect call via a8 (base *(g_mac_sleep_en+212)); args: ret@c1, (1 slli 11), 1, lit:.rodata_wlog_error.71, lit:.rodata.str1.1 */
    opaque_indirect_a8();
    /* site +0xd1: indirect call via a10 (base *(g_osi_funcs_p+0x18c)); args: *(g_osi_funcs_p+0x18c), (1 slli 11), 1, lit:.rodata_wlog_error.71, lit:.rodata.str1.1 */
    opaque_indirect_a10();
    /* site +0xd7: wifi_reset_mac(ret@d1, (1 slli 11), 1, lit:.rodata_wlog_error.71, lit:.rodata.str1.1) */
    wifi_reset_mac(ret@d1, (1 slli 11), 1, lit:.rodata_wlog_error.71, lit:.rodata.str1.1);
    /* site +0xdd: ic_mac_init(ret@d7, (1 slli 11), 1, lit:.rodata_wlog_error.71, lit:.rodata.str1.1) */
    ic_mac_init(ret@d7, (1 slli 11), 1, lit:.rodata_wlog_error.71, lit:.rodata.str1.1);
    /* site +0xe5: chm_init(lit:g_ic, (1 slli 11), 1, lit:.rodata_wlog_error.71, lit:.rodata.str1.1) */
    chm_init(lit:g_ic, (1 slli 11), 1, lit:.rodata_wlog_error.71, lit:.rodata.str1.1);
    /* site +0xeb: ic_set_interrupt_handler(ret@e5, (1 slli 11), 1, lit:.rodata_wlog_error.71, lit:.rodata.str1.1) */
    ic_set_interrupt_handler(ret@e5, (1 slli 11), 1, lit:.rodata_wlog_error.71, lit:.rodata.str1.1);
    /* site +0xf1: chip_enable(ret@eb, (1 slli 11), 1, lit:.rodata_wlog_error.71, lit:.rodata.str1.1) */
    chip_enable(ret@eb, (1 slli 11), 1, lit:.rodata_wlog_error.71, lit:.rodata.str1.1);
    /* site +0xf7: pm_noise_check_enable(ret@f1, (1 slli 11), 1, lit:.rodata_wlog_error.71, lit:.rodata.str1.1) */
    pm_noise_check_enable(ret@f1, (1 slli 11), 1, lit:.rodata_wlog_error.71, lit:.rodata.str1.1);
    /* site +0x107: indirect call via a5 (base *(g_ic+200)); args: ret@f7, (1 slli 11), 1, lit:.rodata_wlog_error.71, lit:.rodata.str1.1 */
    opaque_indirect_a5();
    /* site +0x10f: indirect call via a5 (base *(g_ic+0x100)); args: ret@107, (1 slli 11), 1, lit:.rodata_wlog_error.71, lit:.rodata.str1.1 */
    opaque_indirect_a5();
    /* site +0x11e: pm_mac_wakeup(ret@10f, (1 slli 11), 1, lit:.rodata_wlog_error.71, lit:.rodata.str1.1) */
    pm_mac_wakeup(ret@10f, (1 slli 11), 1, lit:.rodata_wlog_error.71, lit:.rodata.str1.1);
    /* site +0x125: indirect call via a10 (base *(g_mac_sleep_en+4)); args: *(g_mac_sleep_en+4), (1 slli 11), 1, lit:.rodata_wlog_error.71, lit:.rodata.str1.1 */
    opaque_indirect_a10();
    /* site +0x131: indirect call via a4 (base *(g_osi_funcs_p+212)); args: ret@125, (1 slli 11), 1, lit:.rodata_wlog_error.71, lit:.rodata.str1.1 */
    opaque_indirect_a4();
    /* site +0x137: ic_mac_init(ret@131, (1 slli 11), 1, lit:.rodata_wlog_error.71, lit:.rodata.str1.1) */
    ic_mac_init(ret@131, (1 slli 11), 1, lit:.rodata_wlog_error.71, lit:.rodata.str1.1);
    /* site +0x165: pm_disconnected_start(ret@137, (1 slli 11), 1, lit:.rodata_wlog_error.71, lit:.rodata.str1.1) */
    pm_disconnected_start(ret@137, (1 slli 11), 1, lit:.rodata_wlog_error.71, lit:.rodata.str1.1);
    return opaque_result; /* full dataflow not recovered */
}

/* wifi_txq_empty @ ieee80211_ioctl.o 0x0000000c size 40B bind GLOBAL
 * Calls: indirect(a2), ic_txq_empty, indirect(a4) | Data refs: g_wifi_global_lock, g_osi_funcs_p
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 wifi_txq_empty(u32 a3, u32 a4)
{
    /* frame: entry a1,32; 15 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(lit:g_wifi_global_lock) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=84 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(lit:g_wifi_global_lock) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=88 */
    /* site +0x1d: indirect call via a2 (base *(*(g_osi_funcs_p+0)+84)); args: *(g_wifi_global_lock+0) */
    opaque_indirect_a2();
    /* site +0x23: ic_txq_empty(ret@1d) */
    ic_txq_empty(ret@1d);
    /* site +0x2f: indirect call via a4 (base *(*(g_osi_funcs_p+0)+88)); args: *(g_wifi_global_lock+0) */
    opaque_indirect_a4();
    return last_call_result; /* opaque */
}

/* wifi_stop_sw_txq @ ieee80211_ioctl.o 0x00000018 size 52B bind GLOBAL
 * Calls: wifi_log, ieee80211_empty_txq, ieee80211_empty_txq, scan_flush_all_tx_buf, ic_stop_sw_txq | Data refs: .rodata_wlog_info.72
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 wifi_stop_sw_txq(void)
{
    /* frame: entry a1,32; 20 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* immediates: 1, 3, 0 */
    /* site +0x27: wifi_log(1, 1, 3, lit:.rodata_wlog_info.72) */
    wifi_log(1, 1, 3, lit:.rodata_wlog_info.72);
    /* site +0x2f: ieee80211_empty_txq(0, 1, 3, lit:.rodata_wlog_info.72) */
    ieee80211_empty_txq(0, 1, 3, lit:.rodata_wlog_info.72);
    /* site +0x37: ieee80211_empty_txq(1, 1, 3, lit:.rodata_wlog_info.72) */
    ieee80211_empty_txq(1, 1, 3, lit:.rodata_wlog_info.72);
    /* site +0x3f: scan_flush_all_tx_buf(0, 1, 3, lit:.rodata_wlog_info.72) */
    scan_flush_all_tx_buf(0, 1, 3, lit:.rodata_wlog_info.72);
    /* site +0x45: ic_stop_sw_txq(ret@3f, 1, 3, lit:.rodata_wlog_info.72) */
    ic_stop_sw_txq(ret@3f, 1, 3, lit:.rodata_wlog_info.72);
    return 0;
}

/* wifi_hw_stop @ ieee80211_ioctl.o 0x00000050 size 268B bind GLOBAL
 * Calls: wifi_log, wifi_log, ieee80211_set_hmac_stop, pm_noise_check_disable, wifi_stop_sw_txq, ic_stop_hw_txq, chip_disable, chm_deinit, ic_mac_deinit, ic_clear_interrupt_handler, indirect(a8), indirect(a8), indirect(a8), ic_mac_deinit, indirect(a10), indirect(a8), pm_mac_sleep, indirect(a8), indirect(a3), pm_disconnected_stop | Data refs: g_ic, .rodata.str1.1, .rodata_wlog_error.73, .rodata_wlog_error.74, g_osi_funcs_p, g_mac_sleep_en
 * Fidelity: low - 94 insns, 8 branches, 0 loops; skeleton only */
u32 wifi_hw_stop(u32 a2)
{
    /* frame: entry a1,32; 94 insns, 8 cond-branches, 0 loops, 3 jumps */
    /* immediates: 1, 0x585, -1 */
    /* first predicate: bbs a3, a2, 78 <wifi_hw_stop+0x28> (condition opaque) */
    /* mem ld8: base=((lit:g_ic+131072)) off=81 */
    /* mem ld8: base=((lit:g_ic+131072)) off=82 */
    /* mem st8: base=((lit:g_ic+131072)) off=81 */
    /* mem st8: base=((lit:g_ic+131072)) off=82 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=0x190 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=208 */
    /* mem ld8: base=(lit:g_mac_sleep_en) off=0 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* ... +10 more memops */
    /* site +0x72: wifi_log(1, (1 slli 11), 1, lit:.rodata_wlog_error.73, lit:.rodata.str1.1) */
    wifi_log(1, (1 slli 11), 1, lit:.rodata_wlog_error.73, lit:.rodata.str1.1);
    /* site +0x95: wifi_log(ret@72, (1 slli 11), 1, lit:.rodata_wlog_error.74, lit:.rodata.str1.1) */
    wifi_log(ret@72, (1 slli 11), 1, lit:.rodata_wlog_error.74, lit:.rodata.str1.1);
    /* site +0xc2: ieee80211_set_hmac_stop(1, (1 slli 11), 1, lit:.rodata_wlog_error.74, lit:.rodata.str1.1) */
    ieee80211_set_hmac_stop(1, (1 slli 11), 1, lit:.rodata_wlog_error.74, lit:.rodata.str1.1);
    /* site +0xc8: pm_noise_check_disable(ret@c2, (1 slli 11), 1, lit:.rodata_wlog_error.74, lit:.rodata.str1.1) */
    pm_noise_check_disable(ret@c2, (1 slli 11), 1, lit:.rodata_wlog_error.74, lit:.rodata.str1.1);
    /* site +0xce: wifi_stop_sw_txq(ret@c8, (1 slli 11), 1, lit:.rodata_wlog_error.74, lit:.rodata.str1.1) */
    wifi_stop_sw_txq(ret@c8, (1 slli 11), 1, lit:.rodata_wlog_error.74, lit:.rodata.str1.1);
    /* site +0xd4: ic_stop_hw_txq(ret@ce, (1 slli 11), 1, lit:.rodata_wlog_error.74, lit:.rodata.str1.1) */
    ic_stop_hw_txq(ret@ce, (1 slli 11), 1, lit:.rodata_wlog_error.74, lit:.rodata.str1.1);
    /* site +0xda: chip_disable(ret@d4, (1 slli 11), 1, lit:.rodata_wlog_error.74, lit:.rodata.str1.1) */
    chip_disable(ret@d4, (1 slli 11), 1, lit:.rodata_wlog_error.74, lit:.rodata.str1.1);
    /* site +0xe0: chm_deinit(ret@da, (1 slli 11), 1, lit:.rodata_wlog_error.74, lit:.rodata.str1.1) */
    chm_deinit(ret@da, (1 slli 11), 1, lit:.rodata_wlog_error.74, lit:.rodata.str1.1);
    /* site +0xe6: ic_mac_deinit(ret@e0, (1 slli 11), 1, lit:.rodata_wlog_error.74, lit:.rodata.str1.1) */
    ic_mac_deinit(ret@e0, (1 slli 11), 1, lit:.rodata_wlog_error.74, lit:.rodata.str1.1);
    /* site +0xec: ic_clear_interrupt_handler(ret@e6, (1 slli 11), 1, lit:.rodata_wlog_error.74, lit:.rodata.str1.1) */
    ic_clear_interrupt_handler(ret@e6, (1 slli 11), 1, lit:.rodata_wlog_error.74, lit:.rodata.str1.1);
    /* site +0xf7: indirect call via a8 (base *(*(g_osi_funcs_p+0)+0x190)); args: ret@ec, (1 slli 11), 1, lit:.rodata_wlog_error.74, lit:.rodata.str1.1 */
    opaque_indirect_a8();
    /* site +0xff: indirect call via a8 (base *(*(g_osi_funcs_p+0)+208)); args: ret@f7, (1 slli 11), 1, lit:.rodata_wlog_error.74, lit:.rodata.str1.1 */
    opaque_indirect_a8();
    /* site +0x10f: indirect call via a8 (base *(g_mac_sleep_en+0x108)); args: ret@ff, (1 slli 11), 1, lit:.rodata_wlog_error.74, lit:.rodata.str1.1 */
    opaque_indirect_a8();
    /* site +0x11a: ic_mac_deinit(ret@10f, (1 slli 11), 1, lit:.rodata_wlog_error.74, lit:.rodata.str1.1) */
    ic_mac_deinit(ret@10f, (1 slli 11), 1, lit:.rodata_wlog_error.74, lit:.rodata.str1.1);
    /* site +0x125: indirect call via a10 (base *(g_mac_sleep_en+4)); args: *(g_mac_sleep_en+4), (1 slli 11), 1, lit:.rodata_wlog_error.74, lit:.rodata.str1.1 */
    opaque_indirect_a10();
    /* site +0x131: indirect call via a8 (base *(g_mac_sleep_en+208)); args: ret@125, (1 slli 11), 1, lit:.rodata_wlog_error.74, lit:.rodata.str1.1 */
    opaque_indirect_a8();
    /* site +0x13f: pm_mac_sleep(ret@131, (1 slli 11), 1, lit:.rodata_wlog_error.74, lit:.rodata.str1.1) */
    pm_mac_sleep(ret@131, (1 slli 11), 1, lit:.rodata_wlog_error.74, lit:.rodata.str1.1);
    /* site +0x147: indirect call via a8 (base *(g_mac_sleep_en+0x104)); args: ret@13f, (1 slli 11), 1, lit:.rodata_wlog_error.74, lit:.rodata.str1.1 */
    opaque_indirect_a8();
    /* site +0x14f: indirect call via a3 (base *(g_osi_funcs_p+204)); args: ret@147, (1 slli 11), 1, lit:.rodata_wlog_error.74, lit:.rodata.str1.1 */
    opaque_indirect_a3();
    /* site +0x157: pm_disconnected_stop(ret@14f, (1 slli 11), 1, lit:.rodata_wlog_error.74, lit:.rodata.str1.1) */
    pm_disconnected_stop(ret@14f, (1 slli 11), 1, lit:.rodata_wlog_error.74, lit:.rodata.str1.1);
    return opaque_result; /* full dataflow not recovered */
}

/* wifi_set_promis_process @ ieee80211_ioctl.o 0x0000001c size 118B bind GLOBAL
 * Calls: memcpy, wifi_hw_start, ic_set_vif, ic_set_vif, wifi_hw_stop | Data refs: .rodata.wifi_set_promis_process.str1.1, g_ic
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 wifi_set_promis_process(u32 a2)
{
    /* frame: entry a1,48; 45 insns, 3 cond-branches, 0 loops, 1 jumps */
    /* immediates: 6, 2, 0, 3, 1 */
    /* first predicate: beqz.n a3, 68 <wifi_set_promis_process+0x4c> (condition opaque) */
    /* mem ld8: base=(?) off=8 */
    /* mem ld8: base=((lit:g_ic+65536)) off=239 */
    /* mem ld8: base=((lit:g_ic+65536)) off=212 */
    /* mem st8: base=((lit:g_ic+65536)) off=239 */
    /* mem ld8: base=((lit:g_ic+65536)) off=212 */
    /* mem st8: base=((lit:g_ic+65536)) off=239 */
    /* site +0x2d: memcpy(?, lit:.rodata.wifi_set_promis_process.str1.1, 6) */
    memcpy(?, lit:.rodata.wifi_set_promis_process.str1.1, 6);
    /* site +0x43: wifi_hw_start(2, lit:.rodata.wifi_set_promis_process.str1.1, 6) */
    wifi_hw_start(2, lit:.rodata.wifi_set_promis_process.str1.1, 6);
    /* site +0x59: ic_set_vif(3, 0, ?, 3, 0) */
    ic_set_vif(3, 0, ?, 3, 0);
    /* site +0x7a: ic_set_vif(3, 1, 1, 3, 1) */
    ic_set_vif(3, 1, 1, 3, 1);
    /* site +0x8b: wifi_hw_stop(2, 1, 1, 3, 1) */
    wifi_hw_stop(2, 1, 1, 3, 1);
    return 0;
}

/* wifi_hw_mode_switch @ ieee80211_ioctl.o 0x00000030 size 299B bind LOCAL
 * Calls: wifi_hw_start, wifi_hw_stop, wifi_hw_start, wifi_hw_start, wifi_hw_start, wifi_hw_start, wifi_hw_start, wifi_hw_start, wifi_hw_start, wifi_hw_start, wifi_hw_stop | Data refs: .rodata.wifi_hw_mode_switch
 * Fidelity: low - 89 insns, 24 branches, 0 loops; skeleton only */
u32 wifi_hw_mode_switch(u32 a2, u32 a3)
{
    /* frame: entry a1,32; 89 insns, 24 cond-branches, 0 loops, 21 jumps */
    /* immediates: 3, 0, 1, 4 */
    /* first predicate: bltui a3, 5, 39 <.text.wifi_hw_mode_switch+0x39> (condition opaque) */
    /* mem ld32: base=(?) off=0 */
    /* site +0x49: wifi_hw_start(3) */
    wifi_hw_start(3);
    /* site +0x6a: wifi_hw_stop(0) */
    wifi_hw_stop(0);
    /* site +0x91: wifi_hw_start(0) */
    wifi_hw_start(0);
    /* site +0xb3: wifi_hw_start(/* no traced args */) */
    wifi_hw_start(/* no traced args */);
    /* site +0xd3: wifi_hw_start(/* no traced args */) */
    wifi_hw_start(/* no traced args */);
    /* site +0xdb: wifi_hw_start(1) */
    wifi_hw_start(1);
    /* site +0xe7: wifi_hw_start(0) */
    wifi_hw_start(0);
    /* site +0xf3: wifi_hw_start(0) */
    wifi_hw_start(0);
    /* site +0xfb: wifi_hw_start(1) */
    wifi_hw_start(1);
    /* site +0x109: wifi_hw_start(4) */
    wifi_hw_start(4);
    /* site +0x126: wifi_hw_stop(3) */
    wifi_hw_stop(3);
    return opaque_result; /* full dataflow not recovered */
}

/* wifi_set_mode_process @ ieee80211_ioctl.o 0x0000004c size 339B bind GLOBAL
 * Calls: wifi_stop_old_mode, wifi_mode_set, wifi_mode_set, do_wifi_start, wifi_hw_mode_switch, do_wifi_start, do_wifi_start, wifi_stop_old_mode, wifi_mode_set, wifi_hw_mode_switch, do_wifi_start, wifi_log, wifi_nvs_commit, wifi_nvs_compare_cfg_diff, wifi_nvs_set | Data refs: g_wifi_nvs, g_ic, .rodata_wlog_error.14, .rodata_wlog_error.15
 * Fidelity: low - 123 insns, 14 branches, 0 loops; skeleton only */
u32 wifi_set_mode_process(u32 a2, u32 a5, u32 a6)
{
    /* frame: entry a1,48; 123 insns, 14 cond-branches, 0 loops, 10 jumps */
    /* immediates: 0x102, -3, 2, 1, 3, 0 */
    /* first predicate: bltui a4, 5, 61 <wifi_set_mode_process+0x15> (condition opaque) */
    /* mem ld8: base=(?) off=8 */
    /* mem st8: base=(?) off=0 */
    /* mem ld32: base=(lit:g_wifi_nvs) off=0 */
    /* mem ld8: base=(*(g_wifi_nvs+0)) off=0 */
    /* mem ld8: base=((lit:g_ic+65536)) off=237 */
    /* mem ld32: base=(lit:g_wifi_nvs) off=0 */
    /* mem ld8: base=(?) off=0 */
    /* mem st8: base=(*(g_wifi_nvs+0)) off=0 */
    /* mem ld8: base=((lit:g_ic+131072)) off=31 */
    /* mem ld32: base=(lit:g_wifi_nvs) off=0 */
    /* ... +3 more memops */
    /* site +0x8b: wifi_stop_old_mode(*(*(g_wifi_nvs+0)+0), *(?+8)) */
    wifi_stop_old_mode(*(*(g_wifi_nvs+0)+0), *(?+8));
    /* site +0x93: wifi_mode_set(*(?+8), *(?+8)) */
    wifi_mode_set(*(?+8), *(?+8));
    /* site +0x9f: wifi_mode_set(*(*(g_wifi_nvs+0)+0), *(?+8)) */
    wifi_mode_set(*(*(g_wifi_nvs+0)+0), *(?+8));
    /* site +0xa7: do_wifi_start(*(*(g_wifi_nvs+0)+0), *(?+8)) */
    do_wifi_start(*(*(g_wifi_nvs+0)+0), *(?+8));
    /* site +0xbb: wifi_hw_mode_switch(*(*(g_wifi_nvs+0)+0), *(?+8), ?, lit:.rodata_wlog_error.14, ret@93) */
    wifi_hw_mode_switch(*(*(g_wifi_nvs+0)+0), *(?+8), ?, lit:.rodata_wlog_error.14, ret@93);
    /* site +0xdb: do_wifi_start(ret@bb, *(?+8), ?, lit:.rodata_wlog_error.14, ret@93) */
    do_wifi_start(ret@bb, *(?+8), ?, lit:.rodata_wlog_error.14, ret@93);
    /* site +0xfc: do_wifi_start(*(?+8), *(?+8), ?, lit:.rodata_wlog_error.14, ret@93) */
    do_wifi_start(*(?+8), *(?+8), ?, lit:.rodata_wlog_error.14, ret@93);
    /* site +0x10b: wifi_stop_old_mode(*(?+8), *(*(g_wifi_nvs+0)+0), ?, lit:.rodata_wlog_error.14, ret@93) */
    wifi_stop_old_mode(*(?+8), *(*(g_wifi_nvs+0)+0), ?, lit:.rodata_wlog_error.14, ret@93);
    /* site +0x113: wifi_mode_set(*(*(g_wifi_nvs+0)+0), *(*(g_wifi_nvs+0)+0), ?, lit:.rodata_wlog_error.14, ret@93) */
    wifi_mode_set(*(*(g_wifi_nvs+0)+0), *(*(g_wifi_nvs+0)+0), ?, lit:.rodata_wlog_error.14, ret@93);
    /* site +0x11e: wifi_hw_mode_switch(ret@113, *(*(g_wifi_nvs+0)+0), ?, lit:.rodata_wlog_error.14, ret@93) */
    wifi_hw_mode_switch(ret@113, *(*(g_wifi_nvs+0)+0), ?, lit:.rodata_wlog_error.14, ret@93);
    /* site +0x126: do_wifi_start(*(*(g_wifi_nvs+0)+0), *(*(g_wifi_nvs+0)+0), ?, lit:.rodata_wlog_error.14, ret@93) */
    do_wifi_start(*(*(g_wifi_nvs+0)+0), *(*(g_wifi_nvs+0)+0), ?, lit:.rodata_wlog_error.14, ret@93);
    /* site +0x139: wifi_log(1, 3, 1, lit:.rodata_wlog_error.15, ret@fc) */
    wifi_log(1, 3, 1, lit:.rodata_wlog_error.15, ret@fc);
    /* site +0x143: wifi_nvs_commit(ret@139, 3, 1, lit:.rodata_wlog_error.15, ret@fc) */
    wifi_nvs_commit(ret@139, 3, 1, lit:.rodata_wlog_error.15, ret@fc);
    /* site +0x155: wifi_nvs_compare_cfg_diff(0, ?, 1, lit:.rodata_wlog_error.15, ret@fc) */
    wifi_nvs_compare_cfg_diff(0, ?, 1, lit:.rodata_wlog_error.15, ret@fc);
    /* site +0x195: wifi_nvs_set(0, *(?+0), 1, lit:.rodata_wlog_error.15, ret@fc) */
    wifi_nvs_set(0, *(?+0), 1, lit:.rodata_wlog_error.15, ret@fc);
    return last_call_result; /* opaque */
}

/* esp_wifi_internal_set_baw @ ieee80211_ioctl.o 0x0000000c size 36B bind GLOBAL
 * Calls: wifi_log | Data refs: g_wifi_menuconfig, .rodata_wlog_info.75
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 esp_wifi_internal_set_baw(u32 a2, u32 a3)
{
    /* frame: entry a1,32; 15 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* immediates: 1, 3, 0 */
    /* mem st32: base=(lit:g_wifi_menuconfig) off=48 */
    /* mem st32: base=(lit:g_wifi_menuconfig) off=44 */
    /* site +0x2b: wifi_log(1, 1, 3, lit:.rodata_wlog_info.75) */
    wifi_log(1, 1, 3, lit:.rodata_wlog_info.75);
    return 0;
}

/* wifi_menuconfig_init @ ieee80211_ioctl.o 0x0000004c size 429B bind GLOBAL
 * Calls: memset, wifi_log, wifi_log, wifi_log, wifi_log | Data refs: g_wifi_menuconfig, .rodata_wlog_error.76, .rodata_wlog_error.77, .rodata_wlog_error.78, .rodata_wlog_error.79, .rodata_wlog_error.80, .rodata_wlog_error.81, .rodata_wlog_error.82, .rodata_wlog_error.83, .rodata_wlog_error.84, .rodata_wlog_error.85, .rodata_wlog_error.86, .rodata_wlog_warning.87
 * Fidelity: low - 159 insns, 15 branches, 0 loops; skeleton only */
u32 wifi_menuconfig_init(u32 a2, u32 a3)
{
    /* frame: entry a1,48; 159 insns, 15 cond-branches, 0 loops, 10 jumps */
    /* immediates: 104, 0, 1, 52, 30, 0x400, 63, 127, 26, 0x102 */
    /* first predicate: bnez.n a2, 75 <wifi_menuconfig_init+0x29> (condition opaque) */
    /* mem ld32: base=(?) off=156 */
    /* mem ld32: base=(?) off=4 */
    /* mem ld32: base=(?) off=8 */
    /* mem st32: base=(?) off=4 */
    /* mem st32: base=(?) off=0 */
    /* mem ld32: base=(?) off=56 */
    /* mem ld32: base=(?) off=60 */
    /* mem ld32: base=(?) off=56 */
    /* mem ld32: base=(?) off=60 */
    /* mem ld32: base=(?) off=64 */
    /* ... +51 more memops */
    /* site +0x5d: memset(?, 0, 104) */
    memset(?, 0, 104);
    /* site +0x6e: wifi_log(1, 1, 1, lit:.rodata_wlog_error.76) */
    wifi_log(1, 1, 1, lit:.rodata_wlog_error.76);
    /* site +0xa9: wifi_log(1, 1, 1, lit:.rodata_wlog_error.78, 52) */
    wifi_log(1, 1, 1, lit:.rodata_wlog_error.78, 52);
    /* site +0x14a: wifi_log(1, 1, 1, lit:.rodata_wlog_error.86, *(?+116)) */
    wifi_log(1, 1, 1, lit:.rodata_wlog_error.86, *(?+116));
    /* site +0x1e9: wifi_log(1, 1, 2, lit:.rodata_wlog_warning.87, *(?+116)) */
    wifi_log(1, 1, 2, lit:.rodata_wlog_warning.87, *(?+116));
    return 0;
}

/* wifi_get_rand_macaddr @ ieee80211_ioctl.o 0x00000004 size 42B bind GLOBAL
 * Calls: indirect(a8) | Data refs: g_osi_funcs_p
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 wifi_get_rand_macaddr(u32 a2)
{
    /* frame: entry a1,32; 16 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* immediates: 6, -2, 2 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=0x144 */
    /* mem ld8: base=(?) off=0 */
    /* mem st8: base=(?) off=0 */
    /* site +0x13: indirect call via a8 (base *(g_osi_funcs_p+0x144)); args: ?, 6 */
    opaque_indirect_a8();
    return opaque_result; /* full dataflow not recovered */
}

/* wifi_sta_set_random_macaddr @ ieee80211_ioctl.o 0x00000010 size 86B bind LOCAL
 * Calls: wifi_get_rand_macaddr, wifi_sta_change_mac_internal, wifi_log | Data refs: .rodata_wlog_info.34
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 wifi_sta_set_random_macaddr(void)
{
    /* frame: entry a1,64; 26 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* immediates: 1, 3, 8 */
    /* mem ld8: base=(?) off=21 */
    /* mem st32: base=(?) off=12 */
    /* mem ld8: base=(?) off=20 */
    /* mem st32: base=(?) off=8 */
    /* mem ld8: base=(?) off=19 */
    /* mem st32: base=(?) off=4 */
    /* mem ld8: base=(?) off=18 */
    /* mem ld8: base=(?) off=17 */
    /* mem ld8: base=(?) off=16 */
    /* mem st32: base=(?) off=0 */
    /* site +0x19: wifi_get_rand_macaddr((?+16)) */
    wifi_get_rand_macaddr((?+16));
    /* site +0x25: wifi_sta_change_mac_internal((?+16), 1) */
    wifi_sta_change_mac_internal((?+16), 1);
    /* site +0x51: wifi_log(1, 8, 3, lit:.rodata_wlog_info.34, *(?+16)) */
    wifi_log(1, 8, 3, lit:.rodata_wlog_info.34, *(?+16));
    return opaque_result; /* full dataflow not recovered */
}

/* wifi_crypto_deinit @ ieee80211_ioctl.o 0x00000000 size 7B bind GLOBAL
 * Calls: none | Data refs: none
 * Fidelity: high - straight-line, fully mapped (3 insns) */
u32 wifi_crypto_deinit(void)
{
    /* frame: entry a1,32; 3 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0 */
    return 0;
}

/* wpa_crypto_funcs_init @ ieee80211_ioctl.o 0x00000014 size 47B bind GLOBAL
 * Calls: memcpy, wifi_log | Data refs: wpa_crypto_funcs, .rodata.__FUNCTION__$1, .rodata_wlog_error.88
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 wpa_crypto_funcs_init(u32 a2)
{
    /* frame: entry a1,32; 18 insns, 1 cond-branches, 0 loops, 1 jumps */
    /* immediates: 52, 0, 1, 0x102 */
    /* first predicate: beqz.n a2, 2c <wpa_crypto_funcs_init+0x18> (condition opaque) */
    /* site +0x23: memcpy(lit:wpa_crypto_funcs, ?, 52) */
    memcpy(lit:wpa_crypto_funcs, ?, 52);
    /* site +0x3e: wifi_log(1, 1, 1, lit:.rodata_wlog_error.88, lit:.rodata.__FUNCTION__$1) */
    wifi_log(1, 1, 1, lit:.rodata_wlog_error.88, lit:.rodata.__FUNCTION__$1);
    return 0x102;
}

/* wifi_crypto_init @ ieee80211_ioctl.o 0x00000004 size 16B bind GLOBAL
 * Calls: wpa_crypto_funcs_init | Data refs: none
 * Fidelity: high - straight-line, fully mapped (6 insns) */
u32 wifi_crypto_init(u32 a2)
{
    /* frame: entry a1,32; 6 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* site +0xd: wpa_crypto_funcs_init((?+4)) */
    wpa_crypto_funcs_init((?+4));
    return last_call_result; /* opaque */
}

/* wifi_hmac_deinit @ ieee80211_ioctl.o 0x00000004 size 13B bind GLOBAL
 * Calls: ieee80211_ifdetach | Data refs: none
 * Fidelity: high - straight-line, fully mapped (5 insns) */
u32 wifi_hmac_deinit(void)
{
    /* frame: entry a1,32; 5 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0 */
    /* site +0xa: ieee80211_ifdetach(/* no traced args */) */
    ieee80211_ifdetach(/* no traced args */);
    return 0;
}

/* wifi_hmac_init @ ieee80211_ioctl.o 0x0000001c size 46B bind GLOBAL
 * Calls: ieee80211_ifattach, ieee80211_output_init, ic_register_pm_tx_null_cb, ic_register_timer_cb, ieee80211_cnx_attach | Data refs: ieee80211_pm_tx_null_process, ieee80211_timer_do_process
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 wifi_hmac_init(void)
{
    /* frame: entry a1,32; 16 insns, 1 cond-branches, 0 loops, 0 jumps */
    /* first predicate: bnez.n a10, 48 <wifi_hmac_init+0x2c> (condition opaque) */
    /* site +0x22: ieee80211_ifattach(/* no traced args */) */
    ieee80211_ifattach(/* no traced args */);
    /* site +0x2d: ieee80211_output_init(ret@22) */
    ieee80211_output_init(ret@22);
    /* site +0x36: ic_register_pm_tx_null_cb(lit:ieee80211_pm_tx_null_process) */
    ic_register_pm_tx_null_cb(lit:ieee80211_pm_tx_null_process);
    /* site +0x3f: ic_register_timer_cb(lit:ieee80211_timer_do_process) */
    ic_register_timer_cb(lit:ieee80211_timer_do_process);
    /* site +0x45: ieee80211_cnx_attach(ret@3f) */
    ieee80211_cnx_attach(ret@3f);
    return opaque_result; /* full dataflow not recovered */
}

/* wifi_lmac_deinit @ ieee80211_ioctl.o 0x00000004 size 13B bind GLOBAL
 * Calls: ic_deinit | Data refs: none
 * Fidelity: high - straight-line, fully mapped (5 insns) */
u32 wifi_lmac_deinit(void)
{
    /* frame: entry a1,32; 5 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0 */
    /* site +0xa: ic_deinit(/* no traced args */) */
    ic_deinit(/* no traced args */);
    return 0;
}

/* wifi_lmac_init @ ieee80211_ioctl.o 0x0000004c size 204B bind GLOBAL
 * Calls: wifi_log, wifi_log, wifi_log, wifi_log, wifi_log, ic_set_beacon_int, ic_init, ic_deinit | Data refs: .rodata.wifi_lmac_init.str1.1, g_wifi_menuconfig, .rodata_wlog_warning.89, .rodata_wlog_info.90, .rodata_wlog_info.91, .rodata_wlog_info.92, .rodata_wlog_info.93, g_wifi_nvs
 * Fidelity: low - 76 insns, 5 branches, 0 loops; skeleton only */
u32 wifi_lmac_init(u32 a2, u32 a5)
{
    /* frame: entry a1,32; 76 insns, 5 cond-branches, 0 loops, 0 jumps */
    /* immediates: 23, 1, 10, 2, 0, 3, 7 */
    /* first predicate: bgeu a8, a3, 75 <wifi_lmac_init+0x29> (condition opaque) */
    /* mem ld32: base=(lit:g_wifi_menuconfig) off=0 */
    /* mem ld32: base=(lit:g_wifi_menuconfig) off=8 */
    /* mem ld32: base=(lit:g_wifi_menuconfig) off=12 */
    /* mem ld32: base=(?) off=104 */
    /* mem ld32: base=(?) off=108 */
    /* mem ld32: base=(lit:g_wifi_nvs) off=0 */
    /* mem ld16: base=((*(g_wifi_nvs+0)+196608)) off=248 */
    /* site +0x6f: wifi_log(?, 1, 2, lit:.rodata_wlog_warning.89, *(g_wifi_menuconfig+0)) */
    wifi_log(?, 1, 2, lit:.rodata_wlog_warning.89, *(g_wifi_menuconfig+0));
    /* site +0x8f: wifi_log(ret@6f, 1, 3, lit:.rodata_wlog_info.90, lit:.rodata.wifi_lmac_init.str1.1) */
    wifi_log(ret@6f, 1, 3, lit:.rodata_wlog_info.90, lit:.rodata.wifi_lmac_init.str1.1);
    /* site +0xa2: wifi_log(1, 1, 3, lit:.rodata_wlog_info.91, 7) */
    wifi_log(1, 1, 3, lit:.rodata_wlog_info.91, 7);
    /* site +0xbe: wifi_log(ret@a2, 1, 3, lit:.rodata_wlog_info.92, lit:.rodata.wifi_lmac_init.str1.1) */
    wifi_log(ret@a2, 1, 3, lit:.rodata_wlog_info.92, lit:.rodata.wifi_lmac_init.str1.1);
    /* site +0xda: wifi_log(ret@be, 1, 3, lit:.rodata_wlog_info.93, lit:.rodata.wifi_lmac_init.str1.1) */
    wifi_log(ret@be, 1, 3, lit:.rodata_wlog_info.93, lit:.rodata.wifi_lmac_init.str1.1);
    /* site +0xfd: ic_set_beacon_int(((*((*(g_wifi_nvs+0)+196608)+248) srli 5)..., 1, 3, lit:.rodata_wlog_info.93, lit:.rodata.wifi_lmac_init.str1.1) */
    ic_set_beacon_int(((*((*(g_wifi_nvs+0)+196608)+248) srli 5)..., 1, 3, lit:.rodata_wlog_info.93, lit:.rodata.wifi_lmac_init.str1.1);
    /* site +0x109: ic_init(10, *(g_wifi_menuconfig+12), 1, lit:.rodata_wlog_info.93, lit:.rodata.wifi_lmac_init.str1.1) */
    ic_init(10, *(g_wifi_menuconfig+12), 1, lit:.rodata_wlog_info.93, lit:.rodata.wifi_lmac_init.str1.1);
    /* site +0x113: ic_deinit(ret@109, *(g_wifi_menuconfig+12), 1, lit:.rodata_wlog_info.93, lit:.rodata.wifi_lmac_init.str1.1) */
    ic_deinit(ret@109, *(g_wifi_menuconfig+12), 1, lit:.rodata_wlog_info.93, lit:.rodata.wifi_lmac_init.str1.1);
    return last_call_result; /* opaque */
}

/* wifi_deinit @ ieee80211_ioctl.o 0x0000001c size 84B bind GLOBAL
 * Calls: ieee80211_ifdetach, ic_deinit, wifi_nvs_deinit, indirect(a8), indirect(a4) | Data refs: .bss.s_rmac_was_enabled, g_ic+0x2c8, g_osi_funcs_p, g_ic
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 wifi_deinit(u32 a2, u32 a4)
{
    /* frame: entry a1,32; 31 insns, 1 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0 */
    /* first predicate: beqz.n a3, 5e <wifi_deinit+0x42> (condition opaque) */
    /* mem ld8: base=(lit:.bss.s_rmac_was_enabled) off=0 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=236 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=240 */
    /* mem st8: base=((lit:g_ic+131072)) off=255 */
    /* mem st8: base=((lit:g_ic+65536)) off=237 */
    /* site +0x22: ieee80211_ifdetach(/* no traced args */) */
    ieee80211_ifdetach(/* no traced args */);
    /* site +0x28: ic_deinit(ret@22) */
    ic_deinit(ret@22);
    /* site +0x2e: wifi_nvs_deinit(ret@28) */
    wifi_nvs_deinit(ret@28);
    /* site +0x49: indirect call via a8 (base *(*(g_osi_funcs_p+0)+236)); args: lit:g_ic+0x2c8 */
    opaque_indirect_a8();
    /* site +0x56: indirect call via a4 (base *(g_osi_funcs_p+240)); args: lit:g_ic+0x2c8 */
    opaque_indirect_a4();
    return 0;
}

/* esp_sta_reset_rmac_process @ ieee80211_ioctl.o 0x0000003c size 194B bind GLOBAL
 * Calls: ieee80211_espnow_get_init_flag, wifi_log, wifi_log, ieee80211_sta_is_connected, wifi_log, wifi_sta_set_random_macaddr, wifi_set_rmac_timer | Data refs: g_ic, s_wifi_stop_in_progress, g_wifi_menuconfig, .rodata_wlog_debug.94, g_rmac_scan_saved, .rodata_wlog_debug.95, .rodata_wlog_debug.96, g_ic+0x200
 * Fidelity: low - 69 insns, 10 branches, 0 loops; skeleton only */
u32 esp_sta_reset_rmac_process(u32 a2, u32 a4, u32 a5)
{
    /* frame: entry a1,32; 69 insns, 10 cond-branches, 0 loops, 3 jumps */
    /* immediates: 4, 1, 8, 0 */
    /* first predicate: beqz a3, fc <esp_sta_reset_rmac_process+0xc0> (condition opaque) */
    /* mem ld8: base=((lit:g_ic+65536)) off=237 */
    /* mem ld8: base=(lit:s_wifi_stop_in_progress) off=0 */
    /* mem ld8: base=(lit:g_wifi_menuconfig) off=97 */
    /* mem ld32: base=(lit:g_ic) off=116 */
    /* mem ld32: base=(lit:g_ic) off=16 */
    /* mem ld8: base=(lit:g_rmac_scan_saved) off=0 */
    /* mem ld8: base=((*(g_ic+16)+65536)) off=84 */
    /* mem ld32: base=(*(g_ic+16)) off=152 */
    /* mem ld8: base=((*(g_ic+16)+65536)) off=84 */
    /* mem ld32: base=(*(g_ic+16)) off=152 */
    /* ... +4 more memops */
    /* site +0x69: ieee80211_espnow_get_init_flag(/* no traced args */) */
    ieee80211_espnow_get_init_flag(/* no traced args */);
    /* site +0x7a: wifi_log(1, 4, 4, lit:.rodata_wlog_debug.94) */
    wifi_log(1, 4, 4, lit:.rodata_wlog_debug.94);
    /* site +0x99: wifi_log(1, 8, 4, lit:.rodata_wlog_debug.95) */
    wifi_log(1, 8, 4, lit:.rodata_wlog_debug.95);
    /* site +0xa5: ieee80211_sta_is_connected(ret@99, 8, 4, lit:.rodata_wlog_debug.95) */
    ieee80211_sta_is_connected(ret@99, 8, 4, lit:.rodata_wlog_debug.95);
    /* site +0xca: wifi_log(1, 4, 4, lit:.rodata_wlog_debug.96, *(s_wifi_stop_in_progress+152)) */
    wifi_log(1, 4, 4, lit:.rodata_wlog_debug.96, *(s_wifi_stop_in_progress+152));
    /* site +0xe2: wifi_sta_set_random_macaddr(ret@ca, 4, 4, lit:.rodata_wlog_debug.96, *(s_wifi_stop_in_progress+152)) */
    wifi_sta_set_random_macaddr(ret@ca, 4, 4, lit:.rodata_wlog_debug.96, *(s_wifi_stop_in_progress+152));
    /* site +0xf9: wifi_set_rmac_timer(*(g_wifi_menuconfig+98), 4, 4, lit:.rodata_wlog_debug.96, *(s_wifi_stop_in_progress+152)) */
    wifi_set_rmac_timer(*(g_wifi_menuconfig+98), 4, 4, lit:.rodata_wlog_debug.96, *(s_wifi_stop_in_progress+152));
    return opaque_result; /* full dataflow not recovered */
}

/* wifi_init_process @ ieee80211_ioctl.o 0x00000054 size 372B bind GLOBAL
 * Calls: wifi_log, memset, indirect(a8), indirect(a7), wifi_nvs_init, wifi_lmac_init, wifi_hmac_init, wifi_crypto_init, wifi_sta_set_random_macaddr, wifi_log, wifi_set_rmac_timer, wifi_sta_restore_default_mac, wifi_set_rmac_timer, wifi_deinit | Data refs: .rodata_wlog_warning.98, g_ic, g_ic+0x212, g_osi_funcs_p, g_ic+0x20c, g_wifi_mac_time_delta, .rodata_wlog_warning.97, g_wifi_menuconfig, .bss.s_rmac_was_enabled
 * Fidelity: low - 134 insns, 8 branches, 0 loops; skeleton only */
u32 wifi_init_process(u32 a2, u32 a5)
{
    /* frame: entry a1,32; 134 insns, 8 cond-branches, 0 loops, 3 jumps */
    /* immediates: 1, 2, 0x102, 0x304, 0, 0x400, 23, 12 */
    /* first predicate: bnez.n a4, 72 <wifi_init_process+0x1e> (condition opaque) */
    /* mem ld32: base=(?) off=12 */
    /* mem st8: base=((lit:g_ic+65536)) off=238 */
    /* mem st8: base=((lit:g_ic+131072)) off=30 */
    /* mem ld32: base=(*(?+12)) off=104 */
    /* mem st8: base=((lit:g_ic+131072)) off=80 */
    /* mem st16: base=((lit:g_ic+131072)) off=124 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem st8: base=((lit:g_ic+131072)) off=31 */
    /* mem st8: base=((lit:g_ic+131072)) off=6 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=228 */
    /* ... +23 more memops */
    /* site +0x69: wifi_log(?, 1, 2, lit:.rodata_wlog_warning.98) */
    wifi_log(?, 1, 2, lit:.rodata_wlog_warning.98);
    /* site +0x89: memset(ret@69, 0, 0x304, lit:.rodata_wlog_warning.98) */
    memset(ret@69, 0, 0x304, lit:.rodata_wlog_warning.98);
    /* site +0xc7: indirect call via a8 (base *(*(g_osi_funcs_p+0)+228)); args: lit:g_ic+0x212, 0, 0x304, lit:.rodata_wlog_warning.98 */
    opaque_indirect_a8();
    /* site +0xd5: indirect call via a7 (base *(g_osi_funcs_p+228)); args: lit:g_ic+0x20c, 1, 0x304, lit:.rodata_wlog_warning.98 */
    opaque_indirect_a7();
    /* site +0x106: wifi_nvs_init(*((lit:g_ic+131072)+20), 1, 0x304, lit:.rodata_wlog_warning.98) */
    wifi_nvs_init(*((lit:g_ic+131072)+20), 1, 0x304, lit:.rodata_wlog_warning.98);
    /* site +0x113: wifi_lmac_init(*(?+12), 1, 0x304, lit:.rodata_wlog_warning.98) */
    wifi_lmac_init(*(?+12), 1, 0x304, lit:.rodata_wlog_warning.98);
    /* site +0x11e: wifi_hmac_init(ret@113, 1, 0x304, lit:.rodata_wlog_warning.98) */
    wifi_hmac_init(ret@113, 1, 0x304, lit:.rodata_wlog_warning.98);
    /* site +0x12b: wifi_crypto_init(*(?+12), 1, 0x304, lit:.rodata_wlog_warning.98) */
    wifi_crypto_init(*(?+12), 1, 0x304, lit:.rodata_wlog_warning.98);
    /* site +0x13f: wifi_sta_set_random_macaddr(ret@12b, 1, 0x304, lit:.rodata_wlog_warning.98) */
    wifi_sta_set_random_macaddr(ret@12b, 1, 0x304, lit:.rodata_wlog_warning.98);
    /* site +0x15d: wifi_log(1, 1, 2, lit:.rodata_wlog_warning.97, *(*(?+12)+150)) */
    wifi_log(1, 1, 2, lit:.rodata_wlog_warning.97, *(*(?+12)+150));
    /* site +0x167: wifi_set_rmac_timer(12, 1, 2, lit:.rodata_wlog_warning.97, *(*(?+12)+150)) */
    wifi_set_rmac_timer(12, 1, 2, lit:.rodata_wlog_warning.97, *(*(?+12)+150));
    /* site +0x193: wifi_sta_restore_default_mac(ret@167, 1, 2, lit:.rodata_wlog_warning.97, *(*(?+12)+150)) */
    wifi_sta_restore_default_mac(ret@167, 1, 2, lit:.rodata_wlog_warning.97, *(*(?+12)+150));
    /* site +0x19b: wifi_set_rmac_timer(0, 1, 2, lit:.rodata_wlog_warning.97, *(*(?+12)+150)) */
    wifi_set_rmac_timer(0, 1, 2, lit:.rodata_wlog_warning.97, *(*(?+12)+150));
    /* site +0x1c3: wifi_deinit(ret@19b, 1, 2, lit:.rodata_wlog_warning.97, *(*(?+12)+150)) */
    wifi_deinit(ret@19b, 1, 2, lit:.rodata_wlog_warning.97, *(*(?+12)+150));
    return last_call_result; /* opaque */
}

/* wifi_deinit_process @ ieee80211_ioctl.o 0x00000004 size 13B bind GLOBAL
 * Calls: wifi_deinit | Data refs: none
 * Fidelity: high - straight-line, fully mapped (5 insns) */
u32 wifi_deinit_process(void)
{
    /* frame: entry a1,32; 5 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* site +0xa: wifi_deinit(/* no traced args */) */
    wifi_deinit(/* no traced args */);
    return last_call_result; /* opaque */
}

/* wifi_start_process @ ieee80211_ioctl.o 0x00000024 size 131B bind GLOBAL
 * Calls: adc2_wifi_acquire, ieee80211_set_hmac_stop, wifi_hw_start, wifi_hw_start, wifi_mode_set, do_wifi_start, ieee80211_update_phy_country | Data refs: g_ic, g_wifi_nvs
 * Fidelity: medium - branchy but loop-free, call sequence mapped */
u32 wifi_start_process(u32 a4, u32 a5)
{
    /* frame: entry a1,32; 47 insns, 9 cond-branches, 0 loops, 2 jumps */
    /* immediates: 0, 3, 1, 2 */
    /* first predicate: bgeui a3, 2, a5 <wifi_start_process+0x81> (condition opaque) */
    /* mem ld8: base=((lit:g_ic+65536)) off=237 */
    /* mem ld32: base=(lit:g_wifi_nvs) off=0 */
    /* mem ld8: base=(*(g_wifi_nvs+0)) off=0 */
    /* mem st8: base=((lit:g_ic+65536)) off=237 */
    /* site +0x39: adc2_wifi_acquire(/* no traced args */) */
    adc2_wifi_acquire(/* no traced args */);
    /* site +0x45: ieee80211_set_hmac_stop(ret@39) */
    ieee80211_set_hmac_stop(ret@39);
    /* site +0x66: wifi_hw_start(0) */
    wifi_hw_start(0);
    /* site +0x78: wifi_hw_start(*(g_wifi_nvs+0)) */
    wifi_hw_start(*(g_wifi_nvs+0));
    /* site +0x80: wifi_mode_set(*(g_wifi_nvs+0)) */
    wifi_mode_set(*(g_wifi_nvs+0));
    /* site +0x8d: do_wifi_start(ret@80) */
    do_wifi_start(ret@80);
    /* site +0xa2: ieee80211_update_phy_country(ret@8d) */
    ieee80211_update_phy_country(ret@8d);
    return last_call_result; /* opaque */
}

/* wifi_stop_process @ ieee80211_ioctl.o 0x00000054 size 314B bind GLOBAL
 * Calls: offchan_in_progress, chm_cancel_op, scan_cancel, ieee80211_set_hmac_stop, do_wifi_stop, wifi_destroy_sta, indirect(a2), do_wifi_stop, wifi_destroy_nan, pm_wake_up, ic_set_vif, wifi_txq_empty, ieee80211_set_hmac_stop, wifi_hw_stop, wifi_hw_stop, adc2_wifi_release, wifi_log | Data refs: g_ic, net80211_funcs, g_wifi_nvs, .rodata_wlog_error.99
 * Fidelity: low - 112 insns, 14 branches, 0 loops; skeleton only */
u32 wifi_stop_process(u32 a2, u32 a6)
{
    /* frame: entry a1,32; 112 insns, 14 cond-branches, 0 loops, 9 jumps */
    /* immediates: 1, 3, 4, 0, -1, -5, 2 */
    /* first predicate: bnez a3, e4 <wifi_stop_process+0x90> (condition opaque) */
    /* mem ld8: base=(?) off=8 */
    /* mem ld8: base=((lit:g_ic+65536)) off=237 */
    /* mem ld32: base=(lit:net80211_funcs) off=0 */
    /* mem ld32: base=(*(net80211_funcs+0)) off=8 */
    /* mem ld8: base=((lit:g_ic+65536)) off=239 */
    /* mem st8: base=((lit:g_ic+65536)) off=237 */
    /* mem ld8: base=((lit:g_ic+65536)) off=212 */
    /* mem ld32: base=(lit:g_wifi_nvs) off=0 */
    /* mem ld8: base=(*(g_wifi_nvs+0)) off=0 */
    /* mem ld8: base=((lit:g_ic+65536)) off=239 */
    /* ... +5 more memops */
    /* site +0x72: offchan_in_progress(/* no traced args */) */
    offchan_in_progress(/* no traced args */);
    /* site +0x7a: chm_cancel_op(ret@72) */
    chm_cancel_op(ret@72);
    /* site +0x80: scan_cancel(ret@7a) */
    scan_cancel(ret@7a);
    /* site +0x89: ieee80211_set_hmac_stop(1) */
    ieee80211_set_hmac_stop(1);
    /* site +0x91: do_wifi_stop(3) */
    do_wifi_stop(3);
    /* site +0x97: wifi_destroy_sta(ret@91) */
    wifi_destroy_sta(ret@91);
    /* site +0xa3: indirect call via a2 (base *(net80211_funcs+8)); args: ret@97 */
    opaque_indirect_a2();
    /* site +0xab: do_wifi_stop(4) */
    do_wifi_stop(4);
    /* site +0xb3: wifi_destroy_nan(ret@ab) */
    wifi_destroy_nan(ret@ab);
    /* site +0xb9: pm_wake_up(ret@b3) */
    pm_wake_up(ret@b3);
    /* site +0xde: ic_set_vif(3, *(g_ic+239), 0, 3, 0) */
    ic_set_vif(3, *(g_ic+239), 0, 3, 0);
    /* site +0xea: wifi_txq_empty(ret@de, *(g_ic+239), 0, 3, 0) */
    wifi_txq_empty(ret@de, *(g_ic+239), 0, 3, 0);
    /* site +0xf9: ieee80211_set_hmac_stop(ret@ea, *(g_ic+239), 0, 3, 0) */
    ieee80211_set_hmac_stop(ret@ea, *(g_ic+239), 0, 3, 0);
    /* site +0x15d: wifi_hw_stop(0, *(g_ic+239), 0, 3, 0) */
    wifi_hw_stop(0, *(g_ic+239), 0, 3, 0);
    /* site +0x16b: wifi_hw_stop(1, *(g_ic+239), 0, 3, 0) */
    wifi_hw_stop(1, *(g_ic+239), 0, 3, 0);
    /* site +0x171: adc2_wifi_release(ret@16b, *(g_ic+239), 0, 3, 0) */
    adc2_wifi_release(ret@16b, *(g_ic+239), 0, 3, 0);
    /* site +0x187: wifi_log(1, 2, 1, lit:.rodata_wlog_error.99, (lit:g_ic+65536)) */
    wifi_log(1, 2, 1, lit:.rodata_wlog_error.99, (lit:g_ic+65536));
    return -1;
}

/* wifi_connect_process @ ieee80211_ioctl.o 0x000000a8 size 880B bind GLOBAL
 * Calls: wifi_log, ieee80211_espnow_get_init_flag, wifi_log, wifi_check_and_handle_rmac_timer_pending, wifi_log, wifi_nvs_get, memcmp, is_valid_sta_mac, wifi_log, wifi_get_rand_macaddr, wifi_nvs_get, is_valid_sta_mac, memcpy, wifi_log, wifi_log, wifi_sta_change_mac_internal, wifi_log, wifi_nvs_get, wifi_sta_set_random_macaddr, wifi_log, wifi_set_rmac_timer, wifi_log, ieee80211_sta_connect, wifi_log, wifi_log | Data refs: g_wifi_nvs, g_ic, .rodata_wlog_debug.100, g_wifi_menuconfig, .bss.s_wps_start, .rodata_wlog_warning.101, g_rmac_scan_saved, .rodata_wlog_debug.102, .rodata_wlog_debug.29, .rodata_wlog_debug.26, .rodata_wlog_debug.30, .rodata_wlog_info.103, .rodata_wlog_info.104, .rodata_wlog_debug.105, .rodata_wlog_error.28, .rodata_wlog_warning.27
 * Fidelity: low - 328 insns, 22 branches, 0 loops; skeleton only */
u32 wifi_connect_process(u32 a2, u32 a4)
{
    /* frame: entry a1,96; 328 insns, 22 cond-branches, 0 loops, 15 jumps */
    /* immediates: -3, 4, 6, 1, 2, 32, 160, 140, 0x2fa, 0x2dc */
    /* first predicate: beqi a2, 1, dc <wifi_connect_process+0x34> (condition opaque) */
    /* mem ld32: base=(lit:g_wifi_nvs) off=0 */
    /* mem ld8: base=(*(g_wifi_nvs+0)) off=0 */
    /* mem ld8: base=((lit:g_ic+65536)) off=239 */
    /* mem ld8: base=(lit:g_wifi_menuconfig) off=97 */
    /* mem ld32: base=(lit:g_ic) off=116 */
    /* mem ld8: base=(lit:.bss.s_wps_start) off=0 */
    /* mem ld8: base=(lit:g_rmac_scan_saved) off=0 */
    /* mem st8: base=(lit:g_rmac_scan_saved) off=0 */
    /* mem ld32: base=(*(g_wifi_nvs+0)) off=4 */
    /* mem ld8: base=(lit:g_wifi_menuconfig) off=97 */
    /* ... +79 more memops */
    /* site +0xd1: wifi_log(1, 6, 4, lit:.rodata_wlog_debug.100, *(*(g_wifi_nvs+0)+0)) */
    wifi_log(1, 6, 4, lit:.rodata_wlog_debug.100, *(*(g_wifi_nvs+0)+0));
    /* site +0xfa: ieee80211_espnow_get_init_flag(ret@d1, 6, 4, lit:.rodata_wlog_debug.100, *(*(g_wifi_nvs+0)+0)) */
    ieee80211_espnow_get_init_flag(ret@d1, 6, 4, lit:.rodata_wlog_debug.100, *(*(g_wifi_nvs+0)+0));
    /* site +0x10d: wifi_log(literal, 4, 2, lit:.rodata_wlog_warning.101, *(*(g_wifi_nvs+0)+0)) */
    wifi_log(literal, 4, 2, lit:.rodata_wlog_warning.101, *(*(g_wifi_nvs+0)+0));
    /* site +0x117: wifi_check_and_handle_rmac_timer_pending(ret@10d, 4, 2, lit:.rodata_wlog_warning.101, *(*(g_wifi_nvs+0)+0)) */
    wifi_check_and_handle_rmac_timer_pending(ret@10d, 4, 2, lit:.rodata_wlog_warning.101, *(*(g_wifi_nvs+0)+0));
    /* site +0x12e: wifi_log(literal, 4, 4, lit:.rodata_wlog_debug.102, *(*(g_wifi_nvs+0)+0)) */
    wifi_log(literal, 4, 4, lit:.rodata_wlog_debug.102, *(*(g_wifi_nvs+0)+0));
    /* site +0x147: wifi_nvs_get(ret@12e, 4, 4, lit:.rodata_wlog_debug.102, *(*(g_wifi_nvs+0)+0)) */
    wifi_nvs_get(ret@12e, 4, 4, lit:.rodata_wlog_debug.102, *(*(g_wifi_nvs+0)+0));
    /* site +0x1a5: memcmp((ret@fa+4), (*(g_wifi_nvs+0)+8), *(*(g_wifi_nvs+0)+4), lit:.rodata_wlog_debug.102, *(g_ic+116)) */
    memcmp((ret@fa+4), (*(g_wifi_nvs+0)+8), *(*(g_wifi_nvs+0)+4), lit:.rodata_wlog_debug.102, *(g_ic+116));
    /* site +0x1f6: is_valid_sta_mac(ret@1a5, (*(g_wifi_nvs+0)+8), *(*(g_wifi_nvs+0)+4), lit:.rodata_wlog_debug.102, *(?+52)) */
    is_valid_sta_mac(ret@1a5, (*(g_wifi_nvs+0)+8), *(*(g_wifi_nvs+0)+4), lit:.rodata_wlog_debug.102, *(?+52));
    /* site +0x249: wifi_log(1, 4, 4, lit:.rodata_wlog_debug.29, (ret@fa+1)) */
    wifi_log(1, 4, 4, lit:.rodata_wlog_debug.29, (ret@fa+1));
    /* site +0x255: wifi_get_rand_macaddr((?+32), 4, 4, lit:.rodata_wlog_debug.29, (ret@fa+1)) */
    wifi_get_rand_macaddr((?+32), 4, 4, lit:.rodata_wlog_debug.29, (ret@fa+1));
    /* site +0x25b: wifi_nvs_get(ret@255, 4, 4, lit:.rodata_wlog_debug.29, (ret@fa+1)) */
    wifi_nvs_get(ret@255, 4, 4, lit:.rodata_wlog_debug.29, (ret@fa+1));
    /* site +0x281: is_valid_sta_mac(*(*(g_wifi_nvs+0)+4), 4, 4, lit:.rodata_wlog_debug.29, (ret@fa+1)) */
    is_valid_sta_mac(*(*(g_wifi_nvs+0)+4), 4, 4, lit:.rodata_wlog_debug.29, (ret@fa+1));
    /* site +0x2aa: memcpy(ret@281, (*(g_wifi_nvs+0)+4), 36, lit:.rodata_wlog_debug.29, (ret@fa+1)) */
    memcpy(ret@281, (*(g_wifi_nvs+0)+4), 36, lit:.rodata_wlog_debug.29, (ret@fa+1));
    /* site +0x301: wifi_log(1, 4, 4, lit:.rodata_wlog_debug.26, *(?+32)) */
    wifi_log(1, 4, 4, lit:.rodata_wlog_debug.26, *(?+32));
    /* site +0x339: wifi_log(1, 4, 4, lit:.rodata_wlog_debug.30, (ret@fa+1)) */
    wifi_log(1, 4, 4, lit:.rodata_wlog_debug.30, (ret@fa+1));
    /* site +0x347: wifi_sta_change_mac_internal((?+32), 0, 4, lit:.rodata_wlog_debug.30, (ret@fa+1)) */
    wifi_sta_change_mac_internal((?+32), 0, 4, lit:.rodata_wlog_debug.30, (ret@fa+1));
    /* site +0x379: wifi_log(1, 4, 3, lit:.rodata_wlog_info.103, (ret@fa+1)) */
    wifi_log(1, 4, 3, lit:.rodata_wlog_info.103, (ret@fa+1));
    /* site +0x37f: wifi_nvs_get(ret@379, 4, 3, lit:.rodata_wlog_info.103, (ret@fa+1)) */
    wifi_nvs_get(ret@379, 4, 3, lit:.rodata_wlog_info.103, (ret@fa+1));
    /* site +0x396: wifi_sta_set_random_macaddr(ret@37f, 4, 3, lit:.rodata_wlog_info.103, (ret@fa+1)) */
    wifi_sta_set_random_macaddr(ret@37f, 4, 3, lit:.rodata_wlog_info.103, (ret@fa+1));
    /* site +0x3c2: wifi_log(1, 4, 3, lit:.rodata_wlog_info.104, *(g_ic+18)) */
    wifi_log(1, 4, 3, lit:.rodata_wlog_info.104, *(g_ic+18));
    /* site +0x3ce: wifi_set_rmac_timer(*(g_wifi_menuconfig+98), 4, 3, lit:.rodata_wlog_info.104, *(g_ic+18)) */
    wifi_set_rmac_timer(*(g_wifi_menuconfig+98), 4, 3, lit:.rodata_wlog_info.104, *(g_ic+18));
    /* site +0x3dd: wifi_log(1, 4, 4, lit:.rodata_wlog_debug.105, *(g_ic+18)) */
    wifi_log(1, 4, 4, lit:.rodata_wlog_debug.105, *(g_ic+18));
    /* site +0x3e3: ieee80211_sta_connect(ret@3dd, 4, 4, lit:.rodata_wlog_debug.105, *(g_ic+18)) */
    ieee80211_sta_connect(ret@3dd, 4, 4, lit:.rodata_wlog_debug.105, *(g_ic+18));
    /* site +0x3f9: wifi_log(1, 4, 1, lit:.rodata_wlog_error.28, *(g_ic+18)) */
    wifi_log(1, 4, 1, lit:.rodata_wlog_error.28, *(g_ic+18));
    /* site +0x40b: wifi_log(1, 4, 2, lit:.rodata_wlog_warning.27, *(g_ic+18)) */
    wifi_log(1, 4, 2, lit:.rodata_wlog_warning.27, *(g_ic+18));
    return 0;
}

/* wifi_sta_disconnect @ ieee80211_ioctl.o 0x00000000 size 7B bind GLOBAL
 * Calls: none | Data refs: none
 * Fidelity: high - straight-line, fully mapped (3 insns) */
u32 wifi_sta_disconnect(void)
{
    /* frame: entry a1,32; 3 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0 */
    return 0;
}

/* wifi_disconnect_process @ ieee80211_ioctl.o 0x00000020 size 96B bind GLOBAL
 * Calls: wifi_log, do_wifi_disconnect, wifi_log, do_wifi_disconnect | Data refs: g_wifi_nvs, g_ic, .rodata_wlog_debug.106, .rodata_wlog_debug.107
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 wifi_disconnect_process(u32 a2)
{
    /* frame: entry a1,32; 35 insns, 2 cond-branches, 0 loops, 2 jumps */
    /* immediates: 2, -3, 4, 3, 1, -1 */
    /* first predicate: beqi a10, 1, 59 <wifi_disconnect_process+0x39> (condition opaque) */
    /* mem ld32: base=(lit:g_wifi_nvs) off=0 */
    /* mem ld8: base=(*(g_wifi_nvs+0)) off=0 */
    /* mem st8: base=((lit:g_ic+65536)) off=237 */
    /* mem ld32: base=(-1) off=116 */
    /* site +0x51: wifi_log(1, 3, 4, lit:.rodata_wlog_debug.106) */
    wifi_log(1, 3, 4, lit:.rodata_wlog_debug.106);
    /* site +0x61: do_wifi_disconnect(ret@51, 3, 4, lit:.rodata_wlog_debug.106) */
    do_wifi_disconnect(ret@51, 3, 4, lit:.rodata_wlog_debug.106);
    /* site +0x75: wifi_log(ret@61, 3, 4, lit:.rodata_wlog_debug.107) */
    wifi_log(ret@61, 3, 4, lit:.rodata_wlog_debug.107);
    /* site +0x7b: do_wifi_disconnect(ret@75, 3, 4, lit:.rodata_wlog_debug.107) */
    do_wifi_disconnect(ret@75, 3, 4, lit:.rodata_wlog_debug.107);
    return last_call_result; /* opaque */
}

/* wifi_scan_start_process @ ieee80211_ioctl.o 0x0000006c size 393B bind GLOBAL
 * Calls: wifi_log, reset_cs_thres, wifi_log, ieee80211_espnow_get_init_flag, wifi_log, scan_cancel, memcpy, wifi_get_rand_macaddr, wifi_sta_change_mac_internal, wifi_log, ieee80211_sta_scan, wifi_log, wifi_sta_change_mac_internal, ieee80211_sta_scan | Data refs: .text.scan_done_restore_mac_wrapper, g_wifi_nvs, .rodata_wlog_verbose.108, g_ic, .rodata_wlog_debug.109, g_wifi_menuconfig, .bss.s_wps_start, g_rmac_scan_saved, .rodata_wlog_debug.110, g_rmac_scan_saved_mac, .rodata_wlog_debug.111, .bss.g_rmac_original_scan_cb, .rodata_wlog_warning.112
 * Fidelity: low - 147 insns, 15 branches, 0 loops; skeleton only */
u32 wifi_scan_start_process(u32 a2, u32 a3)
{
    /* frame: entry a1,64; 147 insns, 15 cond-branches, 0 loops, 3 jumps */
    /* immediates: 253, 5, 11, 1, -1, 0, 4, 8, 6, 2 */
    /* first predicate: beqi a3, 1, 99 <wifi_scan_start_process+0x2d> (condition opaque) */
    /* mem ld32: base=(lit:g_wifi_nvs) off=0 */
    /* mem ld8: base=(*(g_wifi_nvs+0)) off=0 */
    /* mem ld32: base=(?) off=12 */
    /* mem ld8: base=(?) off=8 */
    /* mem ld32: base=(lit:g_ic) off=16 */
    /* mem ld32: base=(*(g_ic+16)) off=152 */
    /* mem ld8: base=((*(g_ic+16)+65536)) off=84 */
    /* mem ld32: base=((?+20)) off=12 */
    /* mem ld8: base=(lit:g_wifi_menuconfig) off=97 */
    /* mem ld32: base=(lit:g_ic) off=116 */
    /* ... +17 more memops */
    /* site +0x91: wifi_log(1, 11, 5, lit:.rodata_wlog_verbose.108) */
    wifi_log(1, 11, 5, lit:.rodata_wlog_verbose.108);
    /* site +0xd0: reset_cs_thres(ret@91, 11, 5, lit:.rodata_wlog_verbose.108) */
    reset_cs_thres(ret@91, 11, 5, lit:.rodata_wlog_verbose.108);
    /* site +0xe1: wifi_log(1, 4, 4, lit:.rodata_wlog_debug.109) */
    wifi_log(1, 4, 4, lit:.rodata_wlog_debug.109);
    /* site +0x105: ieee80211_espnow_get_init_flag(ret@e1, 4, 4, lit:.rodata_wlog_debug.109) */
    ieee80211_espnow_get_init_flag(ret@e1, 4, 4, lit:.rodata_wlog_debug.109);
    /* site +0x121: wifi_log(1, 8, 4, lit:.rodata_wlog_debug.110) */
    wifi_log(1, 8, 4, lit:.rodata_wlog_debug.110);
    /* site +0x127: scan_cancel(ret@121, 8, 4, lit:.rodata_wlog_debug.110) */
    scan_cancel(ret@121, 8, 4, lit:.rodata_wlog_debug.110);
    /* site +0x13a: memcpy(lit:g_rmac_scan_saved_mac, ((lit:g_ic+131072)+18), 6, lit:.rodata_wlog_debug.110) */
    memcpy(lit:g_rmac_scan_saved_mac, ((lit:g_ic+131072)+18), 6, lit:.rodata_wlog_debug.110);
    /* site +0x14e: wifi_get_rand_macaddr((?+16), ((lit:g_ic+131072)+18), 6, lit:.rodata_wlog_debug.110) */
    wifi_get_rand_macaddr((?+16), ((lit:g_ic+131072)+18), 6, lit:.rodata_wlog_debug.110);
    /* site +0x159: wifi_sta_change_mac_internal((?+16), 0, 6, lit:.rodata_wlog_debug.110) */
    wifi_sta_change_mac_internal((?+16), 0, 6, lit:.rodata_wlog_debug.110);
    /* site +0x185: wifi_log(1, 4, 4, lit:.rodata_wlog_debug.111, *(?+16)) */
    wifi_log(1, 4, 4, lit:.rodata_wlog_debug.111, *(?+16));
    /* site +0x195: ieee80211_sta_scan((?+20), lit:.text.scan_done_restore_mac_wrapper, 4, lit:.rodata_wlog_debug.111, *(?+16)) */
    ieee80211_sta_scan((?+20), lit:.text.scan_done_restore_mac_wrapper, 4, lit:.rodata_wlog_debug.111, *(?+16));
    /* site +0x1b7: wifi_log(1, 8, 2, lit:.rodata_wlog_warning.112, ret@195) */
    wifi_log(1, 8, 2, lit:.rodata_wlog_warning.112, ret@195);
    /* site +0x1c1: wifi_sta_change_mac_internal(lit:.bss.g_rmac_original_scan_cb, 0, 2, lit:.rodata_wlog_warning.112, ret@195) */
    wifi_sta_change_mac_internal(lit:.bss.g_rmac_original_scan_cb, 0, 2, lit:.rodata_wlog_warning.112, ret@195);
    /* site +0x1dd: ieee80211_sta_scan(ret@195, *(?+12), 2, lit:.rodata_wlog_warning.112, ret@195) */
    ieee80211_sta_scan(ret@195, *(?+12), 2, lit:.rodata_wlog_warning.112, ret@195);
    return last_call_result; /* opaque */
}

/* wifi_scan_stop_process @ ieee80211_ioctl.o 0x00000034 size 128B bind GLOBAL
 * Calls: wifi_log, wifi_log, wifi_sta_change_mac_internal, scan_cancel, wifi_log | Data refs: g_ic, .rodata_wlog_error.113, g_rmac_scan_saved, .rodata_wlog_debug.114, g_rmac_scan_saved_mac, .bss.g_rmac_original_scan_cb, .rodata_wlog_debug.115
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 wifi_scan_stop_process(u32 a4)
{
    /* frame: entry a1,32; 47 insns, 3 cond-branches, 0 loops, 1 jumps */
    /* immediates: 11, 8, 1, 4, 0 */
    /* first predicate: beqz.n a2, 5d <wifi_scan_stop_process+0x29> (condition opaque) */
    /* mem ld32: base=(lit:g_ic) off=16 */
    /* mem ld8: base=((*(g_ic+16)+65536)) off=84 */
    /* mem ld8: base=(lit:g_rmac_scan_saved) off=0 */
    /* mem st8: base=(lit:g_rmac_scan_saved) off=0 */
    /* mem st32: base=(lit:.bss.g_rmac_original_scan_cb) off=0 */
    /* mem ld32: base=(lit:g_ic) off=116 */
    /* site +0x51: wifi_log(*((*(g_ic+16)+65536)+84), 11, *((*(g_ic+16)+65536)+84), lit:.rodata_wlog_error.113) */
    wifi_log(*((*(g_ic+16)+65536)+84), 11, *((*(g_ic+16)+65536)+84), lit:.rodata_wlog_error.113);
    /* site +0x72: wifi_log(1, 8, 4, lit:.rodata_wlog_debug.114) */
    wifi_log(1, 8, 4, lit:.rodata_wlog_debug.114);
    /* site +0x7d: wifi_sta_change_mac_internal(lit:g_rmac_scan_saved_mac, 0, 4, lit:.rodata_wlog_debug.114) */
    wifi_sta_change_mac_internal(lit:g_rmac_scan_saved_mac, 0, 4, lit:.rodata_wlog_debug.114);
    /* site +0x8e: scan_cancel(ret@7d, 0, 4, lit:.rodata_wlog_debug.114) */
    scan_cancel(ret@7d, 0, 4, lit:.rodata_wlog_debug.114);
    /* site +0xa9: wifi_log(1, 11, 4, lit:.rodata_wlog_debug.115) */
    wifi_log(1, 11, 4, lit:.rodata_wlog_debug.115);
    return opaque_result; /* full dataflow not recovered */
}

/* wifi_ant_to_ant_type @ ieee80211_ioctl.o 0x00000000 size 22B bind GLOBAL
 * Calls: none | Data refs: none
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 wifi_ant_to_ant_type(u32 a2)
{
    /* frame: entry a1,32; 9 insns, 1 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0, 2, 1 */
    /* first predicate: beq a8, a2, 14 <wifi_ant_to_ant_type+0x14> (condition opaque) */
    return opaque_result; /* full dataflow not recovered */
}

/* wifi_set_scan_params_process @ ieee80211_ioctl.o 0x00000028 size 113B bind GLOBAL
 * Calls: wifi_log, wifi_log, wifi_log, scan_reset_default_app_params, wifi_sta_set_scan_default_params | Data refs: g_wifi_nvs, .rodata_wlog_error.116, g_ic, .rodata_wlog_error.117, .rodata_wlog_debug.118
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 wifi_set_scan_params_process(u32 a2)
{
    /* frame: entry a1,32; 41 insns, 3 cond-branches, 0 loops, 3 jumps */
    /* immediates: 253, 1, 11, 0x106, 10, -1, 4, 0 */
    /* first predicate: beqi a10, 1, 58 <wifi_set_scan_params_process+0x30> (condition opaque) */
    /* mem ld32: base=(lit:g_wifi_nvs) off=0 */
    /* mem ld8: base=(*(g_wifi_nvs+0)) off=0 */
    /* mem ld8: base=(?) off=8 */
    /* mem ld32: base=(lit:g_ic) off=16 */
    /* site +0x4d: wifi_log(*(g_wifi_nvs+0), 11, 1, lit:.rodata_wlog_error.116) */
    wifi_log(*(g_wifi_nvs+0), 11, 1, lit:.rodata_wlog_error.116);
    /* site +0x69: wifi_log(0x106, 10, 0x106, lit:.rodata_wlog_error.117) */
    wifi_log(0x106, 10, 0x106, lit:.rodata_wlog_error.117);
    /* site +0x7b: wifi_log(-1, 10, 4, lit:.rodata_wlog_debug.118) */
    wifi_log(-1, 10, 4, lit:.rodata_wlog_debug.118);
    /* site +0x83: scan_reset_default_app_params(ret@7b, 10, 4, lit:.rodata_wlog_debug.118) */
    scan_reset_default_app_params(ret@7b, 10, 4, lit:.rodata_wlog_debug.118);
    /* site +0x92: wifi_sta_set_scan_default_params((?+20), 10, 4, lit:.rodata_wlog_debug.118) */
    wifi_sta_set_scan_default_params((?+20), 10, 4, lit:.rodata_wlog_debug.118);
    return last_call_result; /* opaque */
}

/* wifi_get_scan_params_process @ ieee80211_ioctl.o 0x00000018 size 68B bind GLOBAL
 * Calls: memcpy, wifi_log | Data refs: g_ic, app_scan_params, .rodata_wlog_debug.119
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 wifi_get_scan_params_process(u32 a2)
{
    /* frame: entry a1,48; 28 insns, 1 cond-branches, 0 loops, 0 jumps */
    /* immediates: 16, 4, 8, 1, 0 */
    /* first predicate: beqz.n a8, 5a <wifi_get_scan_params_process+0x42> (condition opaque) */
    /* mem ld32: base=(?) off=20 */
    /* mem ld32: base=(lit:g_ic) off=16 */
    /* mem ld16: base=(lit:app_scan_params) off=14 */
    /* mem st32: base=(?) off=8 */
    /* mem ld8: base=(lit:app_scan_params) off=12 */
    /* mem st32: base=(?) off=4 */
    /* mem ld32: base=(lit:app_scan_params) off=8 */
    /* mem st32: base=(?) off=0 */
    /* mem ld32: base=(lit:app_scan_params) off=4 */
    /* mem ld32: base=(lit:app_scan_params) off=0 */
    /* site +0x31: memcpy(*(?+20), lit:app_scan_params, 16) */
    memcpy(*(?+20), lit:app_scan_params, 16);
    /* site +0x57: wifi_log(1, 8, 4, lit:.rodata_wlog_debug.119, *(app_scan_params+0)) */
    wifi_log(1, 8, 4, lit:.rodata_wlog_debug.119, *(app_scan_params+0));
    return 0;
}

/* cipher_map_net80211_to_public_cipher @ ieee80211_ioctl.o 0x00000004 size 25B bind GLOBAL
 * Calls: none | Data refs: .rodata.CSWTCH$491
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 cipher_map_net80211_to_public_cipher(u32 a2)
{
    /* frame: entry a1,32; 10 insns, 1 cond-branches, 0 loops, 0 jumps */
    /* immediates: 10, 12 */
    /* first predicate: bltu a9, a2, 19 <cipher_map_net80211_to_public_cipher+0x15> (condition opaque) */
    /* mem ld8: base=(lit:.rodata.CSWTCH$491) off=0 */
    return *(.rodata.CSWTCH$491+0);
}

/* wifi_clear_ap_list_process @ ieee80211_ioctl.o 0x0000001c size 66B bind GLOBAL
 * Calls: wifi_log, wifi_log, clear_bss_queue | Data refs: g_wifi_nvs, .rodata_wlog_debug.120, .rodata_wlog_debug.121
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 wifi_clear_ap_list_process(u32 a2)
{
    /* frame: entry a1,32; 24 insns, 1 cond-branches, 0 loops, 1 jumps */
    /* immediates: 253, 4, 7, 1, 0 */
    /* first predicate: beqi a10, 1, 46 <wifi_clear_ap_list_process+0x2a> (condition opaque) */
    /* mem ld32: base=(lit:g_wifi_nvs) off=0 */
    /* mem ld8: base=(*(g_wifi_nvs+0)) off=0 */
    /* site +0x3d: wifi_log(1, 7, 4, lit:.rodata_wlog_debug.120) */
    wifi_log(1, 7, 4, lit:.rodata_wlog_debug.120);
    /* site +0x51: wifi_log(ret@3d, 7, 4, lit:.rodata_wlog_debug.121) */
    wifi_log(ret@3d, 7, 4, lit:.rodata_wlog_debug.121);
    /* site +0x59: clear_bss_queue(ret@51, 7, 4, lit:.rodata_wlog_debug.121) */
    clear_bss_queue(ret@51, 7, 4, lit:.rodata_wlog_debug.121);
    return 0;
}

/* wifi_copy_ap_record @ ieee80211_ioctl.o 0x00000014 size 254B bind GLOBAL
 * Calls: memset, memcpy, memcpy, wifi_ant_to_ant_type, memcpy | Data refs: none
 * Fidelity: low - 93 insns, 5 branches, 0 loops; skeleton only */
u32 wifi_copy_ap_record(u32 a2, u32 a3)
{
    /* frame: entry a1,32; 93 insns, 5 cond-branches, 0 loops, 1 jumps */
    /* immediates: 1, 0, 92, 6, 20, 21, 7, 3, 2, 0x48f */
    /* first predicate: bnez a4, 10d <wifi_copy_ap_record+0xf9> (condition opaque) */
    /* mem ld8: base=(?) off=42 */
    /* mem ld8: base=(?) off=43 */
    /* mem st8: base=(?) off=39 */
    /* mem ld8: base=(?) off=44 */
    /* mem st32: base=(?) off=40 */
    /* mem ld8: base=(?) off=45 */
    /* mem st8: base=(?) off=44 */
    /* mem ld8: base=(?) off=46 */
    /* mem st32: base=(?) off=48 */
    /* mem ld32: base=(?) off=64 */
    /* ... +11 more memops */
    /* site +0x31: memset(?, 1, 92) */
    memset(?, 1, 92);
    /* site +0x3e: memcpy((?+6), (?+10), *(?+42)) */
    memcpy((?+6), (?+10), *(?+42));
    /* site +0x4a: memcpy(?, (?+4), 6) */
    memcpy(?, (?+4), 6);
    /* site +0x96: wifi_ant_to_ant_type(*(?+92), (?+4), 6) */
    wifi_ant_to_ant_type(*(?+92), (?+4), 6);
    /* site +0x105: memcpy((?+68), (?+80), 12) */
    memcpy((?+68), (?+80), 12);
    return 0x102;
}

/* wifi_get_ap_list_process @ ieee80211_ioctl.o 0x0000003c size 270B bind GLOBAL
 * Calls: scan_get_apnum, wifi_log, wifi_log, indirect(a8), memset, wifi_copy_ap_record, free_bss_info, indirect(a2), wifi_log | Data refs: .rodata_wlog_verbose.122, .rodata_wlog_verbose.123, g_wifi_global_lock, g_osi_funcs_p, g_ic, g_ic+0x130, scannum, .rodata_wlog_verbose.124
 * Fidelity: low - 100 insns, 6 branches, 0 loops; skeleton only */
u32 wifi_get_ap_list_process(u32 a2, u32 a6)
{
    /* frame: entry a1,64; 100 insns, 6 cond-branches, 0 loops, 3 jumps */
    /* immediates: 0, 1, 5, 10, 0x102 */
    /* first predicate: bnez.n a2, 65 <wifi_get_ap_list_process+0x29> (condition opaque) */
    /* mem ld32: base=(?) off=20 */
    /* mem ld32: base=(?) off=12 */
    /* mem st32: base=(?) off=16 */
    /* mem st16: base=(*(?+12)) off=0 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(lit:g_wifi_global_lock) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=84 */
    /* mem ld16: base=(*(?+12)) off=0 */
    /* mem st16: base=(*(?+12)) off=0 */
    /* mem ld32: base=(?) off=16 */
    /* ... +11 more memops */
    /* site +0x4e: scan_get_apnum(/* no traced args */) */
    scan_get_apnum(/* no traced args */);
    /* site +0x71: wifi_log(1, 10, 5, lit:.rodata_wlog_verbose.122) */
    wifi_log(1, 10, 5, lit:.rodata_wlog_verbose.122);
    /* site +0x91: wifi_log(ret@71, 10, 5, lit:.rodata_wlog_verbose.123) */
    wifi_log(ret@71, 10, 5, lit:.rodata_wlog_verbose.123);
    /* site +0xb2: indirect call via a8 (base *(*(g_osi_funcs_p+0)+84)); args: *(g_wifi_global_lock+0), 10, 5, lit:.rodata_wlog_verbose.123 */
    opaque_indirect_a8();
    /* site +0xc5: memset(*(?+16), ?, (5 slli 2), lit:.rodata_wlog_verbose.123) */
    memset(*(?+16), ?, (5 slli 2), lit:.rodata_wlog_verbose.123);
    /* site +0xf3: wifi_copy_ap_record(ret@c5, lit:g_wifi_global_lock, (5 slli 2), lit:.rodata_wlog_verbose.123) */
    wifi_copy_ap_record(ret@c5, lit:g_wifi_global_lock, (5 slli 2), lit:.rodata_wlog_verbose.123);
    /* site +0xfb: free_bss_info(lit:g_wifi_global_lock, lit:g_wifi_global_lock, (5 slli 2), lit:.rodata_wlog_verbose.123) */
    free_bss_info(lit:g_wifi_global_lock, lit:g_wifi_global_lock, (5 slli 2), lit:.rodata_wlog_verbose.123);
    /* site +0x122: indirect call via a2 (base *(g_osi_funcs_p+88)); args: *(g_wifi_global_lock+0), lit:g_wifi_global_lock, (5 slli 2), lit:.rodata_wlog_verbose.123, (?+1) */
    opaque_indirect_a2();
    /* site +0x145: wifi_log(1, 10, 5, lit:.rodata_wlog_verbose.124) */
    wifi_log(1, 10, 5, lit:.rodata_wlog_verbose.124);
    return *(g_ic+0x130);
}

/* wifi_get_ap_record_process @ ieee80211_ioctl.o 0x0000001c size 112B bind GLOBAL
 * Calls: indirect(a2), indirect(a2), wifi_copy_ap_record, free_bss_info, indirect(a2) | Data refs: g_wifi_global_lock, g_osi_funcs_p, g_ic, g_ic+0x130, scannum
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 wifi_get_ap_record_process(u32 a2, u32 a3, u32 a4)
{
    /* frame: entry a1,32; 43 insns, 3 cond-branches, 0 loops, 1 jumps */
    /* immediates: -1, 0 */
    /* first predicate: bnez.n a2, 49 <wifi_get_ap_record_process+0x2d> (condition opaque) */
    /* mem ld32: base=(?) off=20 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(lit:g_wifi_global_lock) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=84 */
    /* mem ld32: base=(lit:g_ic) off=0x130 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(lit:g_wifi_global_lock) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=88 */
    /* mem ld32: base=(-1) off=0 */
    /* mem st32: base=(lit:g_ic) off=0x130 */
    /* ... +6 more memops */
    /* site +0x2e: indirect call via a2 (base *(*(g_osi_funcs_p+0)+84)); args: *(g_wifi_global_lock+0) */
    opaque_indirect_a2();
    /* site +0x41: indirect call via a2 (base *(*(g_osi_funcs_p+0)+88)); args: *(g_wifi_global_lock+0) */
    opaque_indirect_a2();
    /* site +0x62: wifi_copy_ap_record(*(?+20), -1) */
    wifi_copy_ap_record(*(?+20), -1);
    /* site +0x6a: free_bss_info(-1, -1) */
    free_bss_info(-1, -1);
    /* site +0x85: indirect call via a2 (base *(*(g_osi_funcs_p+0)+88)); args: *(g_wifi_global_lock+0), -1 */
    opaque_indirect_a2();
    return 0;
}

/* wifi_get_ap_info_process @ ieee80211_ioctl.o 0x00000030 size 350B bind GLOBAL
 * Calls: memset, memcpy, memcpy, cipher_map_net80211_to_public_cipher, cipher_map_net80211_to_public_cipher, wifi_ant_to_ant_type, memcpy, wifi_log | Data refs: g_ic, .rodata_wlog_warning.125
 * Fidelity: low - 125 insns, 10 branches, 0 loops; skeleton only */
u32 wifi_get_ap_info_process(u32 a2, u32 a5)
{
    /* frame: entry a1,32; 125 insns, 10 cond-branches, 0 loops, 5 jumps */
    /* immediates: 92, 0, 0x380, 32, 6, 0xfffffe7f, 0x180, 2, 1, 8 */
    /* first predicate: beqz a4, 18c <wifi_get_ap_info_process+0x15c> (condition opaque) */
    /* mem ld32: base=(lit:g_ic) off=16 */
    /* mem ld32: base=(?) off=20 */
    /* mem ld32: base=(*(g_ic+16)) off=228 */
    /* mem ld8: base=(*(*(g_ic+16)+228)) off=171 */
    /* mem st8: base=(*(?+20)) off=39 */
    /* mem ld8: base=(*(*(g_ic+16)+228)) off=172 */
    /* mem st32: base=(*(?+20)) off=40 */
    /* mem ld8: base=(*(*(g_ic+16)+228)) off=166 */
    /* mem st8: base=(*(?+20)) off=44 */
    /* mem ld8: base=((*(*(g_ic+16)+228)+131072)) off=139 */
    /* ... +24 more memops */
    /* site +0x4d: memset(*(?+20), 0, 92) */
    memset(*(?+20), 0, 92);
    /* site +0x5f: memcpy((*(?+20)+6), 0x380, 32) */
    memcpy((*(?+20)+6), 0x380, 32);
    /* site +0x6d: memcpy(ret@5f, (*(*(g_ic+16)+228)+4), 6) */
    memcpy(ret@5f, (*(*(g_ic+16)+228)+4), 6);
    /* site +0x9b: cipher_map_net80211_to_public_cipher(*(g_ic+2), (*(*(g_ic+16)+228)+4), 6) */
    cipher_map_net80211_to_public_cipher(*(g_ic+2), (*(*(g_ic+16)+228)+4), 6);
    /* site +0xa9: cipher_map_net80211_to_public_cipher(*(g_ic+4), (*(*(g_ic+16)+228)+4), 6) */
    cipher_map_net80211_to_public_cipher(*(g_ic+4), (*(*(g_ic+16)+228)+4), 6);
    /* site +0xb7: wifi_ant_to_ant_type(*((*(*(g_ic+16)+228)+131072)+184), (*(*(g_ic+16)+228)+4), 6) */
    wifi_ant_to_ant_type(*((*(*(g_ic+16)+228)+131072)+184), (*(*(g_ic+16)+228)+4), 6);
    /* site +0x171: memcpy((*(?+20)+68), 0x2ac, 12) */
    memcpy((*(?+20)+68), 0x2ac, 12);
    /* site +0x186: wifi_log(1, 2, 2, lit:.rodata_wlog_warning.125) */
    wifi_log(1, 2, 2, lit:.rodata_wlog_warning.125);
    return opaque_result; /* full dataflow not recovered */
}

/* wifi_get_sta_list_process @ ieee80211_ioctl.o 0x00000018 size 312B bind GLOBAL
 * Calls: memset, memcpy | Data refs: g_wifi_nvs, g_ic
 * Fidelity: low - 108 insns, 14 branches, 0 loops; skeleton only */
u32 wifi_get_sta_list_process(u32 a2, u32 a4, u32 a7)
{
    /* frame: entry a1,32; 108 insns, 14 cond-branches, 0 loops, 10 jumps */
    /* immediates: 0x102, 184, 0, 1, -8, 6, -4, 3, 7, 8 */
    /* first predicate: beqz a3, 14e <wifi_get_sta_list_process+0x136> (condition opaque) */
    /* mem ld32: base=(?) off=20 */
    /* mem ld32: base=(lit:g_wifi_nvs) off=0 */
    /* mem ld8: base=(*(g_wifi_nvs+0)) off=0 */
    /* mem ld32: base=(lit:g_ic) off=20 */
    /* mem ld32: base=(?) off=236 */
    /* mem ld16: base=(*(?+236)) off=38 */
    /* mem ld32: base=(*(?+20)) off=180 */
    /* mem ld32: base=(*(?+20)) off=180 */
    /* mem ld8: base=(*(?+236)) off=164 */
    /* mem st8: base=(&memcpy()) off=6 */
    /* ... +19 more memops */
    /* site +0x35: memset(*(?+20), 0, 184) */
    memset(*(?+20), 0, 184);
    /* site +0x79: memcpy(*(*(?+20)+180), (*(?+236)+4), 6) */
    memcpy(*(*(?+20)+180), (*(?+236)+4), 6);
    return opaque_result; /* full dataflow not recovered */
}

/* wifi_set_protocol_process @ ieee80211_ioctl.o 0x0000001c size 279B bind GLOBAL
 * Calls: wifi_nvs_compare_cfg_diff, wifi_nvs_compare_cfg_diff, wifi_nvs_compare_cfg_diff, do_wifi_stop, ieee80211_set_phy_mode, do_wifi_start | Data refs: g_wifi_nvs
 * Fidelity: low - 102 insns, 19 branches, 0 loops; skeleton only */
u32 wifi_set_protocol_process(u32 a2)
{
    /* frame: entry a1,48; 102 insns, 19 cond-branches, 0 loops, 18 jumps */
    /* immediates: 1, 2, 0, 0x102, -3, 10, 31, 58, 72, 71 */
    /* first predicate: bne a4, a2, 36 <wifi_set_protocol_process+0x1a> (condition opaque) */
    /* mem ld8: base=(?) off=8 */
    /* mem ld8: base=(?) off=9 */
    /* mem ld32: base=(lit:g_wifi_nvs) off=0 */
    /* mem ld8: base=(*(g_wifi_nvs+0)) off=0 */
    /* mem ld8: base=(?) off=10 */
    /* mem st32: base=(?) off=0 */
    /* mem st8: base=(?) off=4 */
    /* mem ld8: base=((*(g_wifi_nvs+0)+196608)) off=250 */
    /* mem ld8: base=(*(g_wifi_nvs+0)) off=156 */
    /* mem ld8: base=((*(g_wifi_nvs+0)+327680)) off=72 */
    /* ... +2 more memops */
    /* site +0xc9: wifi_nvs_compare_cfg_diff(10, -3) */
    wifi_nvs_compare_cfg_diff(10, -3);
    /* site +0xd9: wifi_nvs_compare_cfg_diff(31) */
    wifi_nvs_compare_cfg_diff(31);
    /* site +0xef: wifi_nvs_compare_cfg_diff(72, (?+4)) */
    wifi_nvs_compare_cfg_diff(72, (?+4));
    /* site +0xf9: do_wifi_stop(1, (?+4)) */
    do_wifi_stop(1, (?+4));
    /* site +0x107: ieee80211_set_phy_mode(*(?+8), 1, *(?+9), *(?+10)) */
    ieee80211_set_phy_mode(*(?+8), 1, *(?+9), *(?+10));
    /* site +0x115: do_wifi_start(1, 1, *(?+9), *(?+10)) */
    do_wifi_start(1, 1, *(?+9), *(?+10));
    return 0x102;
}

/* wifi_get_protocol_process @ ieee80211_ioctl.o 0x00000004 size 195B bind GLOBAL
 * Calls: none | Data refs: g_wifi_nvs
 * Fidelity: low - 70 insns, 13 branches, 0 loops; skeleton only */
u32 wifi_get_protocol_process(u32 a2)
{
    /* frame: entry a1,32; 70 insns, 13 cond-branches, 0 loops, 10 jumps */
    /* immediates: 0, 1, 0x102, 8, 9, 11, 3, 15, 7 */
    /* first predicate: bnei a11, 1, 2c <wifi_get_protocol_process+0x28> (condition opaque) */
    /* mem ld8: base=(?) off=8 */
    /* mem ld32: base=(?) off=12 */
    /* mem ld32: base=(lit:g_wifi_nvs) off=0 */
    /* mem ld8: base=((*(g_wifi_nvs+0)+327680)) off=61 */
    /* mem ld8: base=((*(g_wifi_nvs+0)+196608)) off=250 */
    /* mem ld32: base=(lit:g_wifi_nvs) off=0 */
    /* mem ld8: base=(*(g_wifi_nvs+0)) off=156 */
    /* mem ld8: base=((*(g_wifi_nvs+0)+262144)) off=161 */
    /* mem st8: base=(*(?+12)) off=0 */
    /* mem st8: base=(*(?+12)) off=0 */
    /* ... +3 more memops */
    return 3;
}

/* wifi_get_protocols_process @ ieee80211_ioctl.o 0x00000004 size 199B bind GLOBAL
 * Calls: none | Data refs: g_wifi_nvs
 * Fidelity: low - 72 insns, 13 branches, 0 loops; skeleton only */
u32 wifi_get_protocols_process(u32 a2, u32 a4)
{
    /* frame: entry a1,32; 72 insns, 13 cond-branches, 0 loops, 11 jumps */
    /* immediates: 0, 1, 0x102, 8, 9, 11, 3, 15, 7 */
    /* first predicate: bnei a9, 1, 2c <wifi_get_protocols_process+0x28> (condition opaque) */
    /* mem ld8: base=(?) off=8 */
    /* mem ld32: base=(?) off=12 */
    /* mem ld32: base=(lit:g_wifi_nvs) off=0 */
    /* mem ld8: base=((*(g_wifi_nvs+0)+327680)) off=61 */
    /* mem ld8: base=((*(g_wifi_nvs+0)+196608)) off=250 */
    /* mem ld32: base=(lit:g_wifi_nvs) off=0 */
    /* mem ld8: base=(*(g_wifi_nvs+0)) off=156 */
    /* mem ld8: base=((*(g_wifi_nvs+0)+262144)) off=161 */
    /* mem st16: base=(*(?+12)) off=0 */
    /* mem st16: base=(*(?+12)) off=0 */
    /* ... +3 more memops */
    return opaque_result; /* full dataflow not recovered */
}

/* wifi_set_bw_nvs @ ieee80211_ioctl.o 0x0000001c size 238B bind GLOBAL
 * Calls: wifi_nvs_set, wifi_nvs_commit, wifi_nvs_compare_cfg_diff, wifi_nvs_compare_cfg_diff, wifi_nvs_set | Data refs: g_wifi_nvs, g_ic
 * Fidelity: low - 85 insns, 8 branches, 0 loops; skeleton only */
u32 wifi_set_bw_nvs(u32 a2, u32 a3)
{
    /* frame: entry a1,48; 85 insns, 8 cond-branches, 0 loops, 4 jumps */
    /* immediates: 1, 11, 0, 32 */
    /* first predicate: bnez.n a2, 65 <wifi_set_bw_nvs+0x49> (condition opaque) */
    /* mem st32: base=(?) off=0 */
    /* mem ld32: base=(lit:g_wifi_nvs) off=0 */
    /* mem ld32: base=(?) off=0 */
    /* mem ld8: base=(*(g_wifi_nvs+0)) off=157 */
    /* mem st8: base=(*(g_wifi_nvs+0)) off=157 */
    /* mem ld8: base=((lit:g_ic+131072)) off=31 */
    /* mem ld32: base=(lit:g_wifi_nvs) off=0 */
    /* mem ld32: base=(?) off=0 */
    /* mem ld8: base=((*(g_wifi_nvs+0)+196608)) off=251 */
    /* mem st8: base=((*(g_wifi_nvs+0)+196608)) off=251 */
    /* ... +9 more memops */
    /* site +0x56: wifi_nvs_set(11, *(?+0), *(g_ic+31)) */
    wifi_nvs_set(11, *(?+0), *(g_ic+31));
    /* site +0x5f: wifi_nvs_commit(ret@56, *(?+0), *(g_ic+31)) */
    wifi_nvs_commit(ret@56, *(?+0), *(g_ic+31));
    /* site +0xa1: wifi_nvs_compare_cfg_diff(11, ?, 0) */
    wifi_nvs_compare_cfg_diff(11, ?, 0);
    /* site +0xd2: wifi_nvs_compare_cfg_diff(32) */
    wifi_nvs_compare_cfg_diff(32);
    /* site +0xfd: wifi_nvs_set(32, *(?+0), 0) */
    wifi_nvs_set(32, *(?+0), 0);
    return last_call_result; /* opaque */
}

/* wifi_set_bw_process @ ieee80211_ioctl.o 0x00000024 size 249B bind GLOBAL
 * Calls: wifi_phy_bw_is_valid, wifi_nvs_compare_cfg_diff, wifi_phy_bw_is_valid, wifi_nvs_compare_cfg_diff, do_wifi_stop, wifi_set_bw_nvs, ieee80211_set_phy_bw, do_wifi_start | Data refs: g_wifi_nvs
 * Fidelity: low - 93 insns, 18 branches, 0 loops; skeleton only */
u32 wifi_set_bw_process(u32 a2)
{
    /* frame: entry a1,48; 93 insns, 18 cond-branches, 0 loops, 10 jumps */
    /* immediates: 1, 2, 0x102, 11, 32, 0, 65, 66 */
    /* first predicate: beqz a4, 115 <wifi_set_bw_process+0xf1> (condition opaque) */
    /* mem ld8: base=(?) off=8 */
    /* mem ld8: base=(?) off=9 */
    /* mem ld8: base=(?) off=10 */
    /* mem st32: base=(?) off=0 */
    /* mem ld32: base=(lit:g_wifi_nvs) off=0 */
    /* mem ld8: base=((*(g_wifi_nvs+0)+196608)) off=251 */
    /* mem ld8: base=(*(g_wifi_nvs+251)) off=157 */
    /* mem st32: base=(?) off=0 */
    /* mem ld32: base=(lit:g_wifi_nvs) off=0 */
    /* mem ld8: base=((*(g_wifi_nvs+0)+327680)) off=54 */
    /* ... +1 more memops */
    /* site +0x41: wifi_phy_bw_is_valid(*(?+8), *(?+9), 1) */
    wifi_phy_bw_is_valid(*(?+8), *(?+9), 1);
    /* site +0x87: wifi_nvs_compare_cfg_diff(32, ?, 1) */
    wifi_nvs_compare_cfg_diff(32, ?, 1);
    /* site +0x9d: wifi_phy_bw_is_valid(ret@87, ?, 2) */
    wifi_phy_bw_is_valid(ret@87, ?, 2);
    /* site +0xd7: wifi_nvs_compare_cfg_diff(66, ?, 2) */
    wifi_nvs_compare_cfg_diff(66, ?, 2);
    /* site +0xe9: do_wifi_stop(2, ?, 2) */
    do_wifi_stop(2, ?, 2);
    /* site +0xf7: wifi_set_bw_nvs(*(?+8), *(?+9), 1) */
    wifi_set_bw_nvs(*(?+8), *(?+9), 1);
    /* site +0x105: ieee80211_set_phy_bw(*(?+8), *(?+9), 1) */
    ieee80211_set_phy_bw(*(?+8), *(?+9), 1);
    /* site +0x10d: do_wifi_start(2, *(?+9), 1) */
    do_wifi_start(2, *(?+9), 1);
    return opaque_result; /* full dataflow not recovered */
}

/* wifi_get_bw_process @ ieee80211_ioctl.o 0x00000004 size 47B bind GLOBAL
 * Calls: none | Data refs: g_wifi_nvs
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 wifi_get_bw_process(u32 a2)
{
    /* frame: entry a1,32; 18 insns, 3 cond-branches, 0 loops, 1 jumps */
    /* immediates: 0 */
    /* first predicate: bnei a2, 1, 20 <wifi_get_bw_process+0x1c> (condition opaque) */
    /* mem ld32: base=(?) off=12 */
    /* mem ld8: base=(?) off=8 */
    /* mem ld32: base=(lit:g_wifi_nvs) off=0 */
    /* mem ld8: base=((*(g_wifi_nvs+0)+196608)) off=251 */
    /* mem ld32: base=(lit:g_wifi_nvs) off=0 */
    /* mem ld8: base=(*(g_wifi_nvs+0)) off=157 */
    /* mem st32: base=(*(?+12)) off=0 */
    return 0;
}

/* wifi_set_channel_process @ ieee80211_ioctl.o 0x00000030 size 344B bind GLOBAL
 * Calls: wifi_check_chan_param, ieee80211_regdomain_check_ap_channel, chm_get_current_band, chm_get_band_from_chan, cnx_softap_csa, chm_set_home_channel, chm_set_current_channel, wifi_log | Data refs: g_wifi_nvs, g_ic, gScanStruct, .rodata_wlog_warning.127
 * Fidelity: low - 129 insns, 17 branches, 0 loops; skeleton only */
u32 wifi_set_channel_process(u32 a2, u32 a7)
{
    /* frame: entry a1,64; 129 insns, 17 cond-branches, 0 loops, 7 jumps */
    /* immediates: 0x102, -3, 0, -1, 1, 240, 2 */
    /* first predicate: bnez.n a10, 69 <wifi_set_channel_process+0x39> (condition opaque) */
    /* mem ld8: base=(?) off=8 */
    /* mem ld8: base=(?) off=9 */
    /* mem ld32: base=(lit:g_wifi_nvs) off=0 */
    /* mem ld8: base=(*(g_wifi_nvs+0)) off=0 */
    /* mem ld8: base=(lit:gScanStruct) off=70 */
    /* mem ld32: base=(lit:g_ic) off=16 */
    /* mem ld32: base=(lit:g_ic) off=20 */
    /* mem st32: base=(?) off=24 */
    /* mem ld32: base=(?) off=24 */
    /* mem st32: base=(?) off=20 */
    /* ... +17 more memops */
    /* site +0x5a: wifi_check_chan_param(*(?+8), *(?+9), *(*(g_wifi_nvs+0)+0)) */
    wifi_check_chan_param(*(?+8), *(?+9), *(*(g_wifi_nvs+0)+0));
    /* site +0x8a: ieee80211_regdomain_check_ap_channel(*(?+8), (*(?+24)+-2), *(?+24)) */
    ieee80211_regdomain_check_ap_channel(*(?+8), (*(?+24)+-2), *(?+24));
    /* site +0x105: chm_get_current_band(*(g_wifi_nvs+0), *(?+16), *(?+24)) */
    chm_get_current_band(*(g_wifi_nvs+0), *(?+16), *(?+24));
    /* site +0x111: chm_get_band_from_chan(ret@105, *(?+16), *(?+24)) */
    chm_get_band_from_chan(ret@105, *(?+16), *(?+24));
    /* site +0x12a: cnx_softap_csa(?, 0, *(?+24)) */
    cnx_softap_csa(?, 0, *(?+24));
    /* site +0x147: chm_set_home_channel(?, 0, *(?+24)) */
    chm_set_home_channel(?, 0, *(?+24));
    /* site +0x15b: chm_set_current_channel(?, 0, *(?+24)) */
    chm_set_current_channel(?, 0, *(?+24));
    /* site +0x181: wifi_log(1, 2, 2, lit:.rodata_wlog_warning.127) */
    wifi_log(1, 2, 2, lit:.rodata_wlog_warning.127);
    return -1;
}

/* wifi_set_home_channel_process @ ieee80211_ioctl.o 0x00000008 size 48B bind GLOBAL
 * Calls: wifi_check_chan_param, chm_set_home_channel | Data refs: none
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 wifi_set_home_channel_process(u32 a2)
{
    /* frame: entry a1,48; 18 insns, 1 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0x102, 0 */
    /* first predicate: beqz.n a10, 36 <wifi_set_home_channel_process+0x2e> (condition opaque) */
    /* mem ld8: base=(?) off=8 */
    /* mem ld8: base=(?) off=9 */
    /* mem st8: base=(?) off=0 */
    /* mem st8: base=(?) off=1 */
    /* site +0x1b: wifi_check_chan_param(*(?+8), *(?+9)) */
    wifi_check_chan_param(*(?+8), *(?+9));
    /* site +0x33: chm_set_home_channel(?, *(?+9)) */
    chm_set_home_channel(?, *(?+9));
    return 0;
}

/* wifi_get_channel_process @ ieee80211_ioctl.o 0x00000004 size 61B bind GLOBAL
 * Calls: chm_get_current_channel | Data refs: none
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 wifi_get_channel_process(u32 a2)
{
    /* frame: entry a1,32; 22 insns, 2 cond-branches, 0 loops, 1 jumps */
    /* immediates: 0, 1, 0x102 */
    /* first predicate: bnez a8, 3c <wifi_get_channel_process+0x38> (condition opaque) */
    /* mem ld32: base=(?) off=12 */
    /* mem ld32: base=(?) off=20 */
    /* mem ld8: base=(ret@21) off=0 */
    /* mem st8: base=(*(?+12)) off=0 */
    /* mem ld8: base=(ret@21) off=1 */
    /* mem st8: base=(*(?+20)) off=0 */
    /* site +0x21: chm_get_current_channel(/* no traced args */) */
    chm_get_current_channel(/* no traced args */);
    return 0x102;
}

/* wifi_get_home_channel_process @ ieee80211_ioctl.o 0x00000004 size 61B bind GLOBAL
 * Calls: chm_get_home_channel | Data refs: none
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 wifi_get_home_channel_process(u32 a2)
{
    /* frame: entry a1,32; 22 insns, 2 cond-branches, 0 loops, 1 jumps */
    /* immediates: 0, 1, 0x102 */
    /* first predicate: bnez a8, 3c <wifi_get_home_channel_process+0x38> (condition opaque) */
    /* mem ld32: base=(?) off=12 */
    /* mem ld32: base=(?) off=20 */
    /* mem ld8: base=(ret@21) off=0 */
    /* mem st8: base=(*(?+12)) off=0 */
    /* mem ld8: base=(ret@21) off=1 */
    /* mem st8: base=(*(?+20)) off=0 */
    /* site +0x21: chm_get_home_channel(/* no traced args */) */
    chm_get_home_channel(/* no traced args */);
    return 0x102;
}

/* wifi_check_home_channel @ ieee80211_ioctl.o 0x00000034 size 141B bind GLOBAL
 * Calls: chm_get_home_channel, chm_get_band_from_chan, ieee80211_regdomain_check_ap_channel, do_wifi_stop, ieee80211_regdomain_ap_min_chan, wifi_nvs_set, ieee80211_adjust_2nd_chan, do_wifi_start, ieee80211_regdomain_check_channel, ieee80211_adjust_2nd_chan, wifi_nvs_commit | Data refs: g_wifi_nvs, g_ic
 * Fidelity: medium - branchy but loop-free, call sequence mapped */
u32 wifi_check_home_channel(u32 a2)
{
    /* frame: entry a1,32; 51 insns, 4 cond-branches, 0 loops, 1 jumps */
    /* immediates: 1, 0, 26 */
    /* first predicate: bgeui a8, 2, a1 <wifi_check_home_channel+0x6d> (condition opaque) */
    /* mem ld32: base=(lit:g_wifi_nvs) off=0 */
    /* mem ld8: base=(ret@3a) off=0 */
    /* mem ld8: base=(*(g_wifi_nvs+0)) off=0 */
    /* mem ld8: base=(ret@3a) off=0 */
    /* mem ld8: base=((lit:g_ic+131072)) off=31 */
    /* site +0x3a: chm_get_home_channel(/* no traced args */) */
    chm_get_home_channel(/* no traced args */);
    /* site +0x4d: chm_get_band_from_chan(*(ret@3a+0)) */
    chm_get_band_from_chan(*(ret@3a+0));
    /* site +0x5f: ieee80211_regdomain_check_ap_channel(*(ret@3a+0)) */
    ieee80211_regdomain_check_ap_channel(*(ret@3a+0));
    /* site +0x6a: do_wifi_stop(*(g_wifi_nvs+0)) */
    do_wifi_stop(*(g_wifi_nvs+0));
    /* site +0x72: ieee80211_regdomain_ap_min_chan(1) */
    ieee80211_regdomain_ap_min_chan(1);
    /* site +0x8d: wifi_nvs_set(26, ?, 1) */
    wifi_nvs_set(26, ?, 1);
    /* site +0x93: ieee80211_adjust_2nd_chan(ret@8d, ?, 1) */
    ieee80211_adjust_2nd_chan(ret@8d, ?, 1);
    /* site +0x9b: do_wifi_start(*(g_wifi_nvs+0), ?, 1) */
    do_wifi_start(*(g_wifi_nvs+0), ?, 1);
    /* site +0xa4: ieee80211_regdomain_check_channel(ret@9b, ?, 1) */
    ieee80211_regdomain_check_channel(ret@9b, ?, 1);
    /* site +0xb4: ieee80211_adjust_2nd_chan(ret@a4, ?, 1) */
    ieee80211_adjust_2nd_chan(ret@a4, ?, 1);
    /* site +0xba: wifi_nvs_commit(ret@b4, ?, 1) */
    wifi_nvs_commit(ret@b4, ?, 1);
    return last_call_result; /* opaque */
}

/* wifi_set_ps_process @ ieee80211_ioctl.o 0x00000004 size 16B bind GLOBAL
 * Calls: pm_set_sleep_type | Data refs: none
 * Fidelity: high - straight-line, fully mapped (6 insns) */
u32 wifi_set_ps_process(u32 a2)
{
    /* frame: entry a1,32; 6 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0 */
    /* mem ld8: base=(?) off=8 */
    /* site +0xf: pm_set_sleep_type(*(?+8)) */
    pm_set_sleep_type(*(?+8));
    return 0;
}

/* wifi_set_country @ ieee80211_ioctl.o 0x00000048 size 388B bind GLOBAL
 * Calls: memset, ieee80211_regdomain_get_country_info, wifi_log, wifi_log, wifi_log, wifi_log, memcpy, wifi_nvs_set, wifi_nvs_commit, ieee80211_update_phy_country, wifi_check_home_channel | Data refs: g_wifi_nvs, .rodata_wlog_info.128, .rodata_wlog_info.129, .rodata_wlog_info.130, .rodata_wlog_info.131, g_ic
 * Fidelity: low - 144 insns, 14 branches, 0 loops; skeleton only */
u32 wifi_set_country(u32 a2, u32 a4)
{
    /* frame: entry a1,64; 144 insns, 14 cond-branches, 0 loops, 5 jumps */
    /* immediates: 12, 0, 0x102, 3, 2, 1, 15, 0x404, 32, 38 */
    /* first predicate: beqz a3, 1ca <wifi_set_country+0x182> (condition opaque) */
    /* mem ld32: base=(?) off=12 */
    /* mem ld32: base=(lit:g_wifi_nvs) off=0 */
    /* mem ld8: base=(*(?+12)) off=1 */
    /* mem ld8: base=(*(?+12)) off=0 */
    /* mem ld8: base=(*(?+12)) off=2 */
    /* mem st32: base=(?) off=0 */
    /* mem ld8: base=(*(*(?+12)+2)) off=3 */
    /* mem ld8: base=(?) off=19 */
    /* mem ld8: base=(?) off=28 */
    /* mem ld8: base=(*(*(?+12)+2)) off=4 */
    /* ... +21 more memops */
    /* site +0x5d: memset((?+16), 0, 12) */
    memset((?+16), 0, 12);
    /* site +0x71: ieee80211_regdomain_get_country_info(*(?+12), (?+16), (?+28)) */
    ieee80211_regdomain_get_country_info(*(?+12), (?+16), (?+28));
    /* site +0x91: wifi_log(1, 2, 3, lit:.rodata_wlog_info.128, *(*(?+12)+0)) */
    wifi_log(1, 2, 3, lit:.rodata_wlog_info.128, *(*(?+12)+0));
    /* site +0xb5: wifi_log(1, 2, 3, lit:.rodata_wlog_info.129, *(*(*(?+12)+2)+3)) */
    wifi_log(1, 2, 3, lit:.rodata_wlog_info.129, *(*(*(?+12)+2)+3));
    /* site +0xd6: wifi_log(1, 2, 3, lit:.rodata_wlog_info.130, *(*(*(?+12)+2)+3)) */
    wifi_log(1, 2, 3, lit:.rodata_wlog_info.130, *(*(*(?+12)+2)+3));
    /* site +0x107: wifi_log(1, 2, 3, lit:.rodata_wlog_info.131, *(*(*(?+12)+2)+0)) */
    wifi_log(1, 2, 3, lit:.rodata_wlog_info.131, *(*(*(?+12)+2)+0));
    /* site +0x135: memcpy(*((*(g_wifi_nvs+0)+262144)+12), *(*(?+12)+2), 12, lit:.rodata_wlog_info.131, *(*(*(?+12)+2)+0)) */
    memcpy(*((*(g_wifi_nvs+0)+262144)+12), *(*(?+12)+2), 12, lit:.rodata_wlog_info.131, *(*(*(?+12)+2)+0));
    /* site +0x191: wifi_nvs_set(38, &memcpy(), 0, lit:.rodata_wlog_info.131, *(*(*(?+12)+2)+0)) */
    wifi_nvs_set(38, &memcpy(), 0, lit:.rodata_wlog_info.131, *(*(*(?+12)+2)+0));
    /* site +0x19b: wifi_nvs_commit(ret@191, &memcpy(), 0, lit:.rodata_wlog_info.131, *(*(*(?+12)+2)+0)) */
    wifi_nvs_commit(ret@191, &memcpy(), 0, lit:.rodata_wlog_info.131, *(*(*(?+12)+2)+0));
    /* site +0x1a9: ieee80211_update_phy_country(ret@19b, &memcpy(), 0, lit:.rodata_wlog_info.131, *(*(*(?+12)+2)+0)) */
    ieee80211_update_phy_country(ret@19b, &memcpy(), 0, lit:.rodata_wlog_info.131, *(*(*(?+12)+2)+0));
    /* site +0x1c1: wifi_check_home_channel(ret@1a9, &memcpy(), 0, lit:.rodata_wlog_info.131, *(*(*(?+12)+2)+0)) */
    wifi_check_home_channel(ret@1a9, &memcpy(), 0, lit:.rodata_wlog_info.131, *(*(*(?+12)+2)+0));
    return opaque_result; /* full dataflow not recovered */
}

/* wifi_get_country @ ieee80211_ioctl.o 0x0000000c size 93B bind GLOBAL
 * Calls: ieee80211_regdomain_get_country, memcpy | Data refs: none
 * Fidelity: medium - branchy but loop-free, call sequence mapped */
u32 wifi_get_country(u32 a2)
{
    /* frame: entry a1,32; 33 insns, 4 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0x102, 12, 1, 0, 15, 32 */
    /* first predicate: beqz a3, 64 <wifi_get_country+0x58> (condition opaque) */
    /* mem ld32: base=(?) off=12 */
    /* mem ld8: base=(*(?+12)) off=2 */
    /* mem st8: base=(*(?+12)) off=2 */
    /* site +0x15: ieee80211_regdomain_get_country(/* no traced args */) */
    ieee80211_regdomain_get_country(/* no traced args */);
    /* site +0x2a: memcpy(ret@15, ?, 12) */
    memcpy(ret@15, ?, 12);
    return 0;
}

/* wifi_set_band_process @ ieee80211_ioctl.o 0x0000002c size 380B bind GLOBAL
 * Calls: chm_get_current_band, chm_get_current_band, wifi_log, chm_set_home_channel, chm_set_current_channel, wifi_log | Data refs: g_wifi_nvs, g_ic, gScanStruct, .rodata_wlog_info.132, .rodata_wlog_warning.133
 * Fidelity: low - 138 insns, 20 branches, 0 loops; skeleton only */
u32 wifi_set_band_process(u32 a2, u32 a5)
{
    /* frame: entry a1,64; 138 insns, 20 cond-branches, 0 loops, 13 jumps */
    /* immediates: 0, -3, -1, 1, 3, 2, 36 */
    /* first predicate: bne a10, a4, 5c <wifi_set_band_process+0x30> (condition opaque) */
    /* mem ld8: base=(?) off=8 */
    /* mem ld32: base=(lit:g_wifi_nvs) off=0 */
    /* mem ld8: base=(*(g_wifi_nvs+0)) off=0 */
    /* mem ld32: base=(lit:g_ic) off=16 */
    /* mem ld32: base=(lit:g_ic) off=20 */
    /* mem ld8: base=(lit:gScanStruct) off=70 */
    /* mem st32: base=(?) off=16 */
    /* mem ld32: base=(?) off=16 */
    /* mem ld32: base=(*(g_ic+16)) off=152 */
    /* mem ld32: base=(lit:g_wifi_nvs) off=0 */
    /* ... +19 more memops */
    /* site +0x51: chm_get_current_band(?, *(gScanStruct+70)) */
    chm_get_current_band(?, *(gScanStruct+70));
    /* site +0xd6: chm_get_current_band((*(g_ic+20)+4), *((*(g_wifi_nvs+0)+196608)+246), *(*(g_ic+20)+240)) */
    chm_get_current_band((*(g_ic+20)+4), *((*(g_wifi_nvs+0)+196608)+246), *(*(g_ic+20)+240));
    /* site +0xe9: wifi_log(1, 2, 3, lit:.rodata_wlog_info.132, *(?+8)) */
    wifi_log(1, 2, 3, lit:.rodata_wlog_info.132, *(?+8));
    /* site +0x16a: chm_set_home_channel(?, 2, 3, lit:.rodata_wlog_info.132, *(?+8)) */
    chm_set_home_channel(?, 2, 3, lit:.rodata_wlog_info.132, *(?+8));
    /* site +0x172: chm_set_current_channel(?, 2, 3, lit:.rodata_wlog_info.132, *(?+8)) */
    chm_set_current_channel(?, 2, 3, lit:.rodata_wlog_info.132, *(?+8));
    /* site +0x1a1: wifi_log(1, 2, 2, lit:.rodata_wlog_warning.133, *(?+8)) */
    wifi_log(1, 2, 2, lit:.rodata_wlog_warning.133, *(?+8));
    return -1;
}

/* wifi_set_band_mode_process @ ieee80211_ioctl.o 0x00000050 size 434B bind GLOBAL
 * Calls: wifi_nvs_compare_cfg_diff, wifi_nvs_set, wifi_nvs_set, wifi_log, do_wifi_stop, ieee80211_scan_deattach, chm_init, ieee80211_scan_attach, do_wifi_start, chm_get_home_channel, chm_get_band_from_chan, chm_get_current_channel, chm_get_band_from_chan, is_off_channel, is_off_channel, wifi_nvs_commit | Data refs: g_wifi_nvs, g_ic, .rodata_wlog_info.134, gScanStruct
 * Fidelity: low - 158 insns, 22 branches, 0 loops; skeleton only */
u32 wifi_set_band_mode_process(u32 a2, u32 a6)
{
    /* frame: entry a1,64; 158 insns, 22 cond-branches, 0 loops, 8 jumps */
    /* immediates: 62, 1, 0, 3, 2, -3, 240 */
    /* first predicate: bne a11, a9, b0 <wifi_set_band_mode_process+0x60> (condition opaque) */
    /* mem ld8: base=(?) off=8 */
    /* mem ld32: base=(lit:g_wifi_nvs) off=0 */
    /* mem st32: base=(?) off=0 */
    /* mem ld8: base=(*(g_wifi_nvs+0)) off=0 */
    /* mem ld32: base=((*(g_wifi_nvs+0)+327680)) off=200 */
    /* mem st8: base=((lit:g_ic+131072)) off=173 */
    /* mem ld32: base=(lit:g_wifi_nvs) off=0 */
    /* mem ld32: base=(?) off=0 */
    /* mem ld8: base=((lit:g_ic+131072)) off=31 */
    /* mem st32: base=((*(g_wifi_nvs+0)+327680)) off=200 */
    /* ... +20 more memops */
    /* site +0x81: wifi_nvs_compare_cfg_diff(62, *(?+8)) */
    wifi_nvs_compare_cfg_diff(62, *(?+8));
    /* site +0xa3: wifi_nvs_set(62, *(?+0), 1) */
    wifi_nvs_set(62, *(?+0), 1);
    /* site +0xc7: wifi_nvs_set(62, *(?+0), 0) */
    wifi_nvs_set(62, *(?+0), 0);
    /* site +0xe1: wifi_log(1, 2, 3, lit:.rodata_wlog_info.134, *(?+0)) */
    wifi_log(1, 2, 3, lit:.rodata_wlog_info.134, *(?+0));
    /* site +0x139: do_wifi_stop(*(*(g_wifi_nvs+0)+0), *(g_ic+20), *(g_ic+16), lit:.rodata_wlog_info.134, *(?+0)) */
    do_wifi_stop(*(*(g_wifi_nvs+0)+0), *(g_ic+20), *(g_ic+16), lit:.rodata_wlog_info.134, *(?+0));
    /* site +0x13f: ieee80211_scan_deattach(ret@139, *(g_ic+20), *(g_ic+16), lit:.rodata_wlog_info.134, *(?+0)) */
    ieee80211_scan_deattach(ret@139, *(g_ic+20), *(g_ic+16), lit:.rodata_wlog_info.134, *(?+0));
    /* site +0x147: chm_init(*((lit:g_ic+131072)+31), *(g_ic+20), *(g_ic+16), lit:.rodata_wlog_info.134, *(?+0)) */
    chm_init(*((lit:g_ic+131072)+31), *(g_ic+20), *(g_ic+16), lit:.rodata_wlog_info.134, *(?+0));
    /* site +0x14f: ieee80211_scan_attach(*((lit:g_ic+131072)+31), *(g_ic+20), *(g_ic+16), lit:.rodata_wlog_info.134, *(?+0)) */
    ieee80211_scan_attach(*((lit:g_ic+131072)+31), *(g_ic+20), *(g_ic+16), lit:.rodata_wlog_info.134, *(?+0));
    /* site +0x157: do_wifi_start(*(*(g_wifi_nvs+0)+0), *(g_ic+20), *(g_ic+16), lit:.rodata_wlog_info.134, *(?+0)) */
    do_wifi_start(*(*(g_wifi_nvs+0)+0), *(g_ic+20), *(g_ic+16), lit:.rodata_wlog_info.134, *(?+0));
    /* site +0x178: chm_get_home_channel(ret@157, *(g_ic+20), *(g_ic+16), lit:.rodata_wlog_info.134, *(?+0)) */
    chm_get_home_channel(ret@157, *(g_ic+20), *(g_ic+16), lit:.rodata_wlog_info.134, *(?+0));
    /* site +0x181: chm_get_band_from_chan(*(ret@178+0), *(g_ic+20), *(g_ic+16), lit:.rodata_wlog_info.134, *(?+0)) */
    chm_get_band_from_chan(*(ret@178+0), *(g_ic+20), *(g_ic+16), lit:.rodata_wlog_info.134, *(?+0));
    /* site +0x189: chm_get_current_channel(ret@181, *(g_ic+20), *(g_ic+16), lit:.rodata_wlog_info.134, *(?+0)) */
    chm_get_current_channel(ret@181, *(g_ic+20), *(g_ic+16), lit:.rodata_wlog_info.134, *(?+0));
    /* site +0x192: chm_get_band_from_chan(*(ret@189+0), *(g_ic+20), *(g_ic+16), lit:.rodata_wlog_info.134, *(?+0)) */
    chm_get_band_from_chan(*(ret@189+0), *(g_ic+20), *(g_ic+16), lit:.rodata_wlog_info.134, *(?+0));
    /* site +0x1b5: is_off_channel(ret@192, *(g_ic+20), *(g_ic+16), lit:.rodata_wlog_info.134, *(?+0)) */
    is_off_channel(ret@192, *(g_ic+20), *(g_ic+16), lit:.rodata_wlog_info.134, *(?+0));
    /* site +0x1e2: is_off_channel(ret@1b5, *(g_ic+20), *(g_ic+16), lit:.rodata_wlog_info.134, *(?+0)) */
    is_off_channel(ret@1b5, *(g_ic+20), *(g_ic+16), lit:.rodata_wlog_info.134, *(?+0));
    /* site +0x1fb: wifi_nvs_commit(ret@1e2, *(g_ic+20), *(g_ic+16), lit:.rodata_wlog_info.134, *(?+0)) */
    wifi_nvs_commit(ret@1e2, *(g_ic+20), *(g_ic+16), lit:.rodata_wlog_info.134, *(?+0));
    return last_call_result; /* opaque */
}

/* wifi_restart_process @ ieee80211_ioctl.o 0x0000000c size 48B bind GLOBAL
 * Calls: wifi_station_stop, indirect(a10) | Data refs: g_wifi_nvs, net80211_funcs
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 wifi_restart_process(u32 a2)
{
    /* frame: entry a1,32; 18 insns, 3 cond-branches, 0 loops, 0 jumps */
    /* immediates: -3, 1 */
    /* first predicate: bnei a8, 1, 25 <wifi_restart_process+0x19> (condition opaque) */
    /* mem ld32: base=(lit:g_wifi_nvs) off=0 */
    /* mem ld8: base=(*(g_wifi_nvs+0)) off=0 */
    /* mem ld32: base=(lit:net80211_funcs) off=0 */
    /* mem ld32: base=(*(net80211_funcs+0)) off=16 */
    /* site +0x22: wifi_station_stop(/* no traced args */) */
    wifi_station_stop(/* no traced args */);
    /* site +0x35: indirect call via a10 (base *(net80211_funcs+16)); args: *(net80211_funcs+16) */
    opaque_indirect_a10();
    return 1;
}

/* wifi_set_rxcb_process @ ieee80211_ioctl.o 0x0000000c size 48B bind GLOBAL
 * Calls: wifi_sta_reg_rxcb, wifi_ap_reg_rxcb, wifi_nan_reg_rxcb | Data refs: none
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 wifi_set_rxcb_process(u32 a2)
{
    /* frame: entry a1,32; 17 insns, 3 cond-branches, 0 loops, 2 jumps */
    /* immediates: 0x102, 0 */
    /* first predicate: bnez.n a3, 20 <wifi_set_rxcb_process+0x14> (condition opaque) */
    /* mem ld8: base=(?) off=8 */
    /* mem ld32: base=(?) off=12 */
    /* site +0x19: wifi_sta_reg_rxcb(*(?+12)) */
    wifi_sta_reg_rxcb(*(?+12));
    /* site +0x26: wifi_ap_reg_rxcb(ret@19) */
    wifi_ap_reg_rxcb(ret@19);
    /* site +0x35: wifi_nan_reg_rxcb(ret@26) */
    wifi_nan_reg_rxcb(ret@26);
    return 0;
}

/* wifi_restore_process @ ieee80211_ioctl.o 0x00000008 size 19B bind GLOBAL
 * Calls: misc_nvs_restore, wifi_nvs_restore | Data refs: none
 * Fidelity: high - straight-line, fully mapped (7 insns) */
u32 wifi_restore_process(void)
{
    /* frame: entry a1,32; 7 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0 */
    /* site +0xe: misc_nvs_restore(/* no traced args */) */
    misc_nvs_restore(/* no traced args */);
    /* site +0x14: wifi_nvs_restore(ret@0e) */
    wifi_nvs_restore(ret@0e);
    return 0;
}

/* wifi_set_vnd_ie_process @ ieee80211_ioctl.o 0x00000014 size 266B bind GLOBAL
 * Calls: wifi_log, indirect(a2), indirect(a8), indirect(a2), memcpy, indirect(a7), indirect(a3) | Data refs: g_ic, .rodata_wlog_error.135, g_osi_funcs_p
 * Fidelity: low - 99 insns, 12 branches, 0 loops; skeleton only */
u32 wifi_set_vnd_ie_process(u32 a2, u32 a6)
{
    /* frame: entry a1,32; 99 insns, 12 cond-branches, 0 loops, 4 jumps */
    /* immediates: 221, 1, 2, 0x102, 12, 0x101, 0 */
    /* first predicate: bgeui a4, 5, 5c <wifi_set_vnd_ie_process+0x48> (condition opaque) */
    /* mem ld8: base=(?) off=9 */
    /* mem ld8: base=(?) off=8 */
    /* mem ld8: base=(?) off=10 */
    /* mem ld32: base=(?) off=12 */
    /* mem ld8: base=(*(?+12)) off=0 */
    /* mem ld8: base=(*(?+12)) off=1 */
    /* mem ld32: base=((*(?+10)+40)) off=0 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=0x16c */
    /* mem st32: base=((*(?+10)+40)) off=0 */
    /* ... +21 more memops */
    /* site +0x59: wifi_log(?, 2, 1, lit:.rodata_wlog_error.135) */
    wifi_log(?, 2, 1, lit:.rodata_wlog_error.135);
    /* site +0x6f: indirect call via a2 (base *(g_ic+0x16c)); args: 12, 2, 1, lit:.rodata_wlog_error.135 */
    opaque_indirect_a2();
    /* site +0x8e: indirect call via a8 (base *(*(g_osi_funcs_p+0)+0x16c)); args: (*(*(?+12)+1)+2), 2, 1, lit:.rodata_wlog_error.135 */
    opaque_indirect_a8();
    /* site +0xa1: indirect call via a2 (base *(g_ic+176)); args: *((*(?+10)+40)+0), 2, 1, lit:.rodata_wlog_error.135 */
    opaque_indirect_a2();
    /* site +0xb9: memcpy(*(*((*(?+10)+40)+0)+4), *(?+12), 0x101, lit:.rodata_wlog_error.135) */
    memcpy(*(*((*(?+10)+40)+0)+4), *(?+12), 0x101, lit:.rodata_wlog_error.135);
    /* site +0xed: indirect call via a7 (base *(*(g_osi_funcs_p+0)+176)); args: *(g_osi_funcs_p+4), *(?+12), 0x101, lit:.rodata_wlog_error.135 */
    opaque_indirect_a7();
    /* site +0xff: indirect call via a3 (base *(*(g_osi_funcs_p+0)+176)); args: *(g_ic+0), *(?+12), 0x101, lit:.rodata_wlog_error.135 */
    opaque_indirect_a3();
    return *(?+9);
}

/* wifi_set_vnd_ie_cb_process @ ieee80211_ioctl.o 0x00000004 size 23B bind GLOBAL
 * Calls: none | Data refs: g_ic
 * Fidelity: high - straight-line, fully mapped (9 insns) */
u32 wifi_set_vnd_ie_cb_process(u32 a2)
{
    /* frame: entry a1,32; 9 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0 */
    /* mem ld32: base=(?) off=12 */
    /* mem ld32: base=(?) off=20 */
    /* mem st32: base=(lit:g_ic) off=200 */
    /* mem st32: base=(lit:g_ic) off=204 */
    return 0;
}

/* wifi_set_vnd_ie_cb_with_ret_process @ ieee80211_ioctl.o 0x00000004 size 23B bind GLOBAL
 * Calls: none | Data refs: g_ic
 * Fidelity: high - straight-line, fully mapped (9 insns) */
u32 wifi_set_vnd_ie_cb_with_ret_process(u32 a2)
{
    /* frame: entry a1,32; 9 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0 */
    /* mem ld32: base=(?) off=12 */
    /* mem ld32: base=(?) off=20 */
    /* mem st32: base=(lit:g_ic) off=0x2c0 */
    /* mem st32: base=(lit:g_ic) off=0x2c4 */
    return 0;
}

/* wifi_set_max_tpw @ ieee80211_ioctl.o 0x00000004 size 19B bind GLOBAL
 * Calls: phy_set_most_tpw | Data refs: none
 * Fidelity: high - straight-line, fully mapped (7 insns) */
u32 wifi_set_max_tpw(u32 a2)
{
    /* frame: entry a1,32; 7 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0 */
    /* mem ld8: base=(?) off=8 */
    /* site +0x12: phy_set_most_tpw(*(?+8)) */
    phy_set_most_tpw(*(?+8));
    return 0;
}

/* wifi_set_event_mask @ ieee80211_ioctl.o 0x00000004 size 17B bind GLOBAL
 * Calls: none | Data refs: g_wifi_event_mask
 * Fidelity: high - straight-line, fully mapped (7 insns) */
u32 wifi_set_event_mask(u32 a2)
{
    /* frame: entry a1,32; 7 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0 */
    /* mem ld32: base=(?) off=12 */
    /* mem st32: base=(lit:g_wifi_event_mask) off=0 */
    return 0;
}

/* wifi_set_csi @ ieee80211_ioctl.o 0x00000004 size 24B bind GLOBAL
 * Calls: ic_set_csi | Data refs: none
 * Fidelity: high - straight-line, fully mapped (9 insns) */
u32 wifi_set_csi(u32 a2)
{
    /* frame: entry a1,32; 9 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0, 1 */
    /* mem ld8: base=(?) off=8 */
    /* site +0x15: ic_set_csi(1) */
    ic_set_csi(1);
    return last_call_result; /* opaque */
}

/* wifi_csi_set_config @ ieee80211_ioctl.o 0x00000004 size 16B bind GLOBAL
 * Calls: ic_csi_set_config | Data refs: none
 * Fidelity: high - straight-line, fully mapped (6 insns) */
u32 wifi_csi_set_config(u32 a2)
{
    /* frame: entry a1,32; 6 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* site +0xd: ic_csi_set_config((?+20)) */
    ic_csi_set_config((?+20));
    return last_call_result; /* opaque */
}

/* wifi_ant_config_check @ ieee80211_ioctl.o 0x00000010 size 76B bind GLOBAL
 * Calls: wifi_log, wifi_log | Data refs: .rodata_wlog_error.136, .rodata_wlog_error.137
 * Fidelity: medium - branchy but loop-free, call sequence mapped */
u32 wifi_ant_config_check(u32 a2)
{
    /* frame: entry a1,48; 28 insns, 5 cond-branches, 0 loops, 2 jumps */
    /* immediates: 1, 2, 0x102, 0 */
    /* first predicate: bgeui a14, 3, 22 <wifi_ant_config_check+0x12> (condition opaque) */
    /* mem ld32: base=(?) off=0 */
    /* mem ld32: base=(?) off=8 */
    /* mem ld32: base=(?) off=4 */
    /* mem st32: base=(?) off=0 */
    /* site +0x35: wifi_log(?, 2, 1, lit:.rodata_wlog_error.136, *(?+0)) */
    wifi_log(?, 2, 1, lit:.rodata_wlog_error.136, *(?+0));
    /* site +0x4e: wifi_log(1, 2, 1, lit:.rodata_wlog_error.137, *(?+0)) */
    wifi_log(1, 2, 1, lit:.rodata_wlog_error.137, *(?+0));
    return 0;
}

/* wifi_ant_update @ ieee80211_ioctl.o 0x00000018 size 129B bind GLOBAL
 * Calls: wifi_ant_config_check, ant_dft_cfg, ant_wifitx_cfg, ant_wifirx_cfg | Data refs: g_ic, g_ic+0x234
 * Fidelity: medium - branchy but loop-free, call sequence mapped */
u32 wifi_ant_update(u32 a5)
{
    /* frame: entry a1,48; 49 insns, 4 cond-branches, 0 loops, 4 jumps */
    /* immediates: 1, 0, 0x102 */
    /* first predicate: bnez a10, 94 <wifi_ant_update+0x7c> (condition opaque) */
    /* mem ld32: base=(lit:g_ic) off=0x240 */
    /* mem ld32: base=(lit:g_ic) off=0x234 */
    /* mem ld32: base=(lit:g_ic) off=0x23c */
    /* mem ld32: base=(lit:g_ic) off=0x238 */
    /* mem st32: base=(?) off=0 */
    /* mem ld32: base=(?) off=0 */
    /* site +0x27: wifi_ant_config_check(lit:g_ic+0x234) */
    wifi_ant_config_check(lit:g_ic+0x234);
    /* site +0x77: ant_dft_cfg(1, ?, *(g_ic+0x240)) */
    ant_dft_cfg(1, ?, *(g_ic+0x240));
    /* site +0x81: ant_wifitx_cfg(*(g_ic+0x240), *(g_ic+0x240), *(g_ic+0x240)) */
    ant_wifitx_cfg(*(g_ic+0x240), *(g_ic+0x240), *(g_ic+0x240));
    /* site +0x8d: ant_wifirx_cfg(ret@27, *(g_ic+0x240), *(?+0)) */
    ant_wifirx_cfg(ret@27, *(g_ic+0x240), *(?+0));
    return 0x102;
}

/* wifi_set_fix_rate_process @ ieee80211_ioctl.o 0x00000034 size 186B bind GLOBAL
 * Calls: wifi_log, wifi_log, wifi_log, ic_set_fix_rate | Data refs: .rodata_wlog_error.139, g_wifi_menuconfig, g_ic, .rodata_wlog_error.140, .rodata_wlog_error.141, g_nan_started, .rodata_wlog_error.142
 * Fidelity: low - 67 insns, 12 branches, 0 loops; skeleton only */
u32 wifi_set_fix_rate_process(u32 a2)
{
    /* frame: entry a1,32; 67 insns, 12 cond-branches, 0 loops, 5 jumps */
    /* immediates: 0x102, 42, 1, 2, 0 */
    /* first predicate: bltui a10, 3, 45 <wifi_set_fix_rate_process+0x11> (condition opaque) */
    /* mem ld8: base=(?) off=8 */
    /* mem ld8: base=(?) off=9 */
    /* mem ld32: base=(?) off=12 */
    /* mem ld32: base=(lit:g_wifi_menuconfig) off=32 */
    /* mem ld32: base=(lit:g_ic) off=16 */
    /* mem ld8: base=((*(g_ic+16)+65536)) off=84 */
    /* mem ld32: base=(literal) off=20 */
    /* mem ld8: base=((*(g_ic+20)+65536)) off=85 */
    /* mem ld32: base=(*(g_ic+85)) off=0x2a0 */
    /* mem ld8: base=(lit:g_nan_started) off=0 */
    /* site +0x61: wifi_log(*(?+8), 2, 1, lit:.rodata_wlog_error.139, *(?+12)) */
    wifi_log(*(?+8), 2, 1, lit:.rodata_wlog_error.139, *(?+12));
    /* site +0x8e: wifi_log(1, 2, 1, lit:.rodata_wlog_error.140, *(?+12)) */
    wifi_log(1, 2, 1, lit:.rodata_wlog_error.140, *(?+12));
    /* site +0xd1: wifi_log(1, 2, 1, lit:.rodata_wlog_error.142, *(?+12)) */
    wifi_log(1, 2, 1, lit:.rodata_wlog_error.142, *(?+12));
    /* site +0xe7: ic_set_fix_rate(ret@d1, 1, 1, lit:.rodata_wlog_error.142, *(?+12)) */
    ic_set_fix_rate(ret@d1, 1, 1, lit:.rodata_wlog_error.142, *(?+12));
    return last_call_result; /* opaque */
}

/* wifi_deauth_sta_process @ ieee80211_ioctl.o 0x00000028 size 228B bind GLOBAL
 * Calls: ieee80211_send_mgmt, ieee80211_send_mgmt, cnx_node_leave, ieee80211_send_mgmt, ieee80211_send_mgmt, cnx_node_leave | Data refs: g_ic, g_wifi_nvs
 * Fidelity: low - 85 insns, 12 branches, 0 loops; skeleton only */
u32 wifi_deauth_sta_process(u32 a2, u32 a3, u32 a5)
{
    /* frame: entry a1,32; 85 insns, 12 cond-branches, 0 loops, 4 jumps */
    /* immediates: 0x102, 2, 160, 192, 0 */
    /* first predicate: beqz a4, 108 <wifi_deauth_sta_process+0xe0> (condition opaque) */
    /* mem ld32: base=(lit:g_ic) off=20 */
    /* mem ld32: base=(lit:g_wifi_nvs) off=0 */
    /* mem ld8: base=(*(g_wifi_nvs+0)) off=0 */
    /* mem ld8: base=((*(g_ic+20)+65536)) off=85 */
    /* mem ld32: base=(?) off=12 */
    /* mem ld8: base=((*(g_wifi_nvs+0)+196608)) off=246 */
    /* mem ld32: base=(?) off=236 */
    /* mem st16: base=((*(?+236)+196608)) off=176 */
    /* mem ld32: base=(lit:g_wifi_nvs) off=0 */
    /* mem ld8: base=((*(g_wifi_nvs+0)+196608)) off=246 */
    /* ... +2 more memops */
    /* site +0x8a: ieee80211_send_mgmt(*(?+236), 160, 2) */
    ieee80211_send_mgmt(*(?+236), 160, 2);
    /* site +0x99: ieee80211_send_mgmt(*(?+236), 192, 2) */
    ieee80211_send_mgmt(*(?+236), 192, 2);
    /* site +0xb1: cnx_node_leave(*(?+236), 192, 2) */
    cnx_node_leave(*(?+236), 192, 2);
    /* site +0xda: ieee80211_send_mgmt(*(*((*(g_wifi_nvs+0)+196608)+246)+236), 160, 2) */
    ieee80211_send_mgmt(*(*((*(g_wifi_nvs+0)+196608)+246)+236), 160, 2);
    /* site +0xee: ieee80211_send_mgmt(*(*((*(g_wifi_nvs+0)+196608)+246)+236), 192, 2) */
    ieee80211_send_mgmt(*(*((*(g_wifi_nvs+0)+196608)+246)+236), 192, 2);
    /* site +0x103: cnx_node_leave(*(*((*(g_wifi_nvs+0)+196608)+246)+236), 192, 2) */
    cnx_node_leave(*(*((*(g_wifi_nvs+0)+196608)+246)+236), 192, 2);
    return 0;
}

/* wifi_wps_is_started @ ieee80211_ioctl.o 0x00000004 size 11B bind GLOBAL
 * Calls: none | Data refs: .bss.s_wps_start
 * Fidelity: high - straight-line, fully mapped (4 insns) */
u32 wifi_wps_is_started(void)
{
    /* frame: entry a1,32; 4 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* mem ld8: base=(lit:.bss.s_wps_start) off=0 */
    return opaque_result; /* full dataflow not recovered */
}

/* wifi_set_wps_start_flag @ ieee80211_ioctl.o 0x0000000c size 40B bind GLOBAL
 * Calls: esp_wifi_ipc_internal | Data refs: .text.wifi_wps_start, .text.wifi_wps_stop
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 wifi_set_wps_start_flag(u32 a2)
{
    /* frame: entry a1,48; 16 insns, 1 cond-branches, 0 loops, 0 jumps */
    /* immediates: 1, 0 */
    /* first predicate: bnez.n a2, 1a <wifi_set_wps_start_flag+0xe> (condition opaque) */
    /* mem st32: base=(?) off=0 */
    /* mem st32: base=(?) off=4 */
    /* mem st32: base=(?) off=8 */
    /* site +0x2d: esp_wifi_ipc_internal(?, 1) */
    esp_wifi_ipc_internal(?, 1);
    return last_call_result; /* opaque */
}

/* wifi_wpa2_is_started @ ieee80211_ioctl.o 0x00000004 size 11B bind GLOBAL
 * Calls: none | Data refs: .bss.s_wpa2_start
 * Fidelity: high - straight-line, fully mapped (4 insns) */
u32 wifi_wpa2_is_started(void)
{
    /* frame: entry a1,32; 4 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* mem ld8: base=(lit:.bss.s_wpa2_start) off=0 */
    return opaque_result; /* full dataflow not recovered */
}

/* wifi_wpa2_ent_enable_process @ ieee80211_ioctl.o 0x0000000c size 60B bind GLOBAL
 * Calls: wifi_log, indirect(a8) | Data refs: .rodata_wlog_error.143, .bss.s_wpa2_start
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 wifi_wpa2_ent_enable_process(u32 a2)
{
    /* frame: entry a1,32; 22 insns, 2 cond-branches, 0 loops, 1 jumps */
    /* immediates: 1, 2, 0x102 */
    /* first predicate: beqz.n a14, 19 <wifi_wpa2_ent_enable_process+0xd> (condition opaque) */
    /* mem ld32: base=(?) off=12 */
    /* mem ld32: base=(*(?+12)) off=0 */
    /* mem st8: base=(lit:.bss.s_wpa2_start) off=0 */
    /* mem ld32: base=(*(?+12)) off=4 */
    /* site +0x25: wifi_log(1, 2, 1, lit:.rodata_wlog_error.143, *(?+12)) */
    wifi_log(1, 2, 1, lit:.rodata_wlog_error.143, *(?+12));
    /* site +0x41: indirect call via a8 (base &wifi_log()); args: *(*(?+12)+4), 2, 1, lit:.rodata_wlog_error.143, *(?+12) */
    opaque_indirect_a8();
    return last_call_result; /* opaque */
}

/* wifi_wpa2_ent_disable_process @ ieee80211_ioctl.o 0x0000000c size 60B bind GLOBAL
 * Calls: wifi_log, indirect(a8) | Data refs: .rodata_wlog_error.144, .bss.s_wpa2_start
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 wifi_wpa2_ent_disable_process(u32 a2)
{
    /* frame: entry a1,32; 22 insns, 2 cond-branches, 0 loops, 1 jumps */
    /* immediates: 1, 2, 0x102, 0 */
    /* first predicate: beqz.n a14, 19 <wifi_wpa2_ent_disable_process+0xd> (condition opaque) */
    /* mem ld32: base=(?) off=12 */
    /* mem ld32: base=(*(?+12)) off=0 */
    /* mem st8: base=(lit:.bss.s_wpa2_start) off=0 */
    /* mem ld32: base=(*(?+12)) off=4 */
    /* site +0x25: wifi_log(1, 2, 1, lit:.rodata_wlog_error.144, *(?+12)) */
    wifi_log(1, 2, 1, lit:.rodata_wlog_error.144, *(?+12));
    /* site +0x41: indirect call via a8 (base &wifi_log()); args: *(*(?+12)+4), 2, 1, lit:.rodata_wlog_error.144, *(?+12) */
    opaque_indirect_a8();
    return last_call_result; /* opaque */
}

/* wifi_set_log_mod_process @ ieee80211_ioctl.o 0x00000004 size 129B bind GLOBAL
 * Calls: none | Data refs: g_log_mod
 * Fidelity: medium - branchy but loop-free, call sequence mapped */
u32 wifi_set_log_mod_process(u32 a2)
{
    /* frame: entry a1,32; 53 insns, 6 cond-branches, 0 loops, 5 jumps */
    /* immediates: 0x102, -1, 0 */
    /* first predicate: bgeui a9, 7, 80 <wifi_set_log_mod_process+0x7c> (condition opaque) */
    /* mem ld8: base=(?) off=8 */
    /* mem ld8: base=(?) off=9 */
    /* mem ld8: base=(?) off=10 */
    /* mem st32: base=(lit:g_log_mod) off=0 */
    /* mem st32: base=(lit:g_log_mod) off=4 */
    /* mem st32: base=(lit:g_log_mod) off=8 */
    /* mem st32: base=(lit:g_log_mod) off=12 */
    /* mem st32: base=(lit:g_log_mod) off=16 */
    /* mem st32: base=(lit:g_log_mod) off=20 */
    /* mem st32: base=(lit:g_log_mod) off=0 */
    /* ... +10 more memops */
    return 0;
}

/* wifi_set_wps_type_process @ ieee80211_ioctl.o 0x0000000c size 50B bind GLOBAL
 * Calls: wifi_log | Data refs: .rodata_wlog_error.145, g_misc_nvs
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 wifi_set_wps_type_process(u32 a2)
{
    /* frame: entry a1,32; 18 insns, 1 cond-branches, 0 loops, 1 jumps */
    /* immediates: 8, 1, 2, 0x102, 0 */
    /* first predicate: bgeu a2, a14, 30 <wifi_set_wps_type_process+0x24> (condition opaque) */
    /* mem ld8: base=(?) off=8 */
    /* mem ld32: base=(lit:g_misc_nvs) off=0 */
    /* mem st32: base=(*(g_misc_nvs+0)) off=4 */
    /* site +0x25: wifi_log(?, 2, 1, lit:.rodata_wlog_error.145, *(?+8)) */
    wifi_log(?, 2, 1, lit:.rodata_wlog_error.145, *(?+8));
    return 0;
}

/* wifi_set_wps_status_process @ ieee80211_ioctl.o 0x0000000c size 46B bind GLOBAL
 * Calls: wifi_log | Data refs: .rodata_wlog_error.146, g_misc_nvs
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 wifi_set_wps_status_process(u32 a2)
{
    /* frame: entry a1,32; 17 insns, 1 cond-branches, 0 loops, 1 jumps */
    /* immediates: 1, 2, 0x102, 0 */
    /* first predicate: bltui a14, 4, 2c <wifi_set_wps_status_process+0x20> (condition opaque) */
    /* mem ld8: base=(?) off=8 */
    /* mem ld32: base=(lit:g_misc_nvs) off=0 */
    /* mem st32: base=(*(g_misc_nvs+0)) off=8 */
    /* site +0x21: wifi_log(1, 2, 1, lit:.rodata_wlog_error.146, *(?+8)) */
    wifi_log(1, 2, 1, lit:.rodata_wlog_error.146, *(?+8));
    return 0;
}

/* wifi_ipc_process @ ieee80211_ioctl.o 0x0000000c size 87B bind GLOBAL
 * Calls: wifi_log, indirect(a4), indirect(a8), indirect(a5) | Data refs: .rodata_wlog_error.147, g_osi_funcs_p
 * Fidelity: medium - branchy but loop-free, call sequence mapped */
u32 wifi_ipc_process(u32 a2)
{
    /* frame: entry a1,32; 35 insns, 5 cond-branches, 0 loops, 1 jumps */
    /* immediates: 1, 2, 0x102, 0 */
    /* first predicate: beqz.n a3, 19 <wifi_ipc_process+0xd> (condition opaque) */
    /* mem ld32: base=(?) off=12 */
    /* mem ld32: base=(*(?+12)) off=0 */
    /* mem ld32: base=(*(?+12)) off=4 */
    /* mem ld8: base=(?) off=8 */
    /* mem ld32: base=(*(?+12)) off=4 */
    /* mem ld32: base=(*(?+12)) off=8 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=176 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=176 */
    /* ... +1 more memops */
    /* site +0x25: wifi_log(1, 2, 1, lit:.rodata_wlog_error.147) */
    wifi_log(1, 2, 1, lit:.rodata_wlog_error.147);
    /* site +0x30: indirect call via a4 (base 0x102); args: *(*(?+12)+4), 2, 1, lit:.rodata_wlog_error.147 */
    opaque_indirect_a4();
    /* site +0x4b: indirect call via a8 (base *(*(g_osi_funcs_p+0)+176)); args: *(*(?+12)+4), 2, 1, lit:.rodata_wlog_error.147 */
    opaque_indirect_a8();
    /* site +0x57: indirect call via a5 (base *(g_osi_funcs_p+176)); args: *(?+12), 2, 1, lit:.rodata_wlog_error.147 */
    opaque_indirect_a5();
    return last_call_result; /* opaque */
}

/* ieee80211_set_appie @ ieee80211_ioctl.o 0x00000020 size 401B bind GLOBAL
 * Calls: indirect(a9), indirect(a8), wifi_log, memcpy, indirect(a11), indirect(a6), wifi_log, memcpy | Data refs: g_ic, g_osi_funcs_p, .rodata_wlog_warning.148, .rodata_wlog_warning.149
 * Fidelity: low - 156 insns, 13 branches, 0 loops; skeleton only */
u32 ieee80211_set_appie(u32 a2, u32 a3, u32 a4, u32 a5, u32 a7)
{
    /* frame: entry a1,48; 156 insns, 13 cond-branches, 0 loops, 9 jumps */
    /* immediates: 10, 14, 1, 0x298, 160, 0, 2 */
    /* first predicate: bltu a2, a6, 34 <ieee80211_set_appie+0x14> (condition opaque) */
    /* mem st8: base=((lit:g_ic+131072)) off=30 */
    /* mem ld8: base=(1) off=0 */
    /* mem ld32: base=(160) off=8 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=176 */
    /* mem st32: base=(?) off=0 */
    /* mem ld32: base=(?) off=0 */
    /* mem st32: base=(160) off=8 */
    /* mem st32: base=(160) off=8 */
    /* mem st8: base=(0) off=0 */
    /* ... +25 more memops */
    /* site +0x79: indirect call via a9 (base *(g_osi_funcs_p+176)); args: *(160+8) */
    opaque_indirect_a9();
    /* site +0xca: indirect call via a8 (base *(g_osi_funcs_p+0x16c)); args: (?+2) */
    opaque_indirect_a8();
    /* site +0xea: wifi_log(1, 2, 2, lit:.rodata_wlog_warning.148) */
    wifi_log(1, 2, 2, lit:.rodata_wlog_warning.148);
    /* site +0xf9: memcpy((ret@ea+2), ?, ?, lit:.rodata_wlog_warning.148) */
    memcpy((ret@ea+2), ?, ?, lit:.rodata_wlog_warning.148);
    /* site +0x123: indirect call via a11 (base *(g_osi_funcs_p+176)); args: *(1+8), *(g_osi_funcs_p+176), ?, lit:.rodata_wlog_warning.148 */
    opaque_indirect_a11();
    /* site +0x176: indirect call via a6 (base *(g_osi_funcs_p+0x16c)); args: (?+2), 0, ?, lit:.rodata_wlog_warning.148 */
    opaque_indirect_a6();
    /* site +0x18e: wifi_log(*(?+4), 2, 2, lit:.rodata_wlog_warning.149) */
    wifi_log(*(?+4), 2, 2, lit:.rodata_wlog_warning.149);
    /* site +0x1a1: memcpy((ret@18e+2), *((?+-11)+8), ?, lit:.rodata_wlog_warning.149) */
    memcpy((ret@18e+2), *((?+-11)+8), ?, lit:.rodata_wlog_warning.149);
    return *(?+4);
}

/* wifi_set_appie_process @ ieee80211_ioctl.o 0x00000004 size 24B bind GLOBAL
 * Calls: ieee80211_set_appie | Data refs: none
 * Fidelity: high - straight-line, fully mapped (9 insns) */
u32 wifi_set_appie_process(u32 a2)
{
    /* frame: entry a1,32; 9 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* mem ld8: base=(?) off=9 */
    /* mem ld16: base=(?) off=12 */
    /* mem ld32: base=(?) off=20 */
    /* mem ld8: base=(?) off=8 */
    /* site +0x15: ieee80211_set_appie(*(?+8), *(?+20), *(?+12), *(?+9)) */
    ieee80211_set_appie(*(?+8), *(?+20), *(?+12), *(?+9));
    return last_call_result; /* opaque */
}

/* wifi_set_wps_cb_process @ ieee80211_ioctl.o 0x00000008 size 34B bind GLOBAL
 * Calls: indirect(a8) | Data refs: g_ic, g_osi_funcs_p
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 wifi_set_wps_cb_process(u32 a2, u32 a3)
{
    /* frame: entry a1,32; 13 insns, 1 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0 */
    /* first predicate: beqz.n a10, 1e <wifi_set_wps_cb_process+0x16> (condition opaque) */
    /* mem ld32: base=(lit:g_ic) off=0x1bc */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=176 */
    /* mem ld32: base=(?) off=12 */
    /* mem st32: base=(lit:g_ic) off=0x1bc */
    /* site +0x1b: indirect call via a8 (base *(g_osi_funcs_p+176)); args: *(g_ic+0x1bc) */
    opaque_indirect_a8();
    return 0;
}

/* wifi_internal_ioctl_process @ ieee80211_ioctl.o 0x00000018 size 87B bind GLOBAL
 * Calls: wifi_log, indirect(a11), wifi_log | Data refs: .rodata_wlog_error.152, .rodata_wlog_error.153, s_ioctl_table, .rodata_wlog_error.154
 * Fidelity: medium - branchy but loop-free, call sequence mapped */
u32 wifi_internal_ioctl_process(u32 a2)
{
    /* frame: entry a1,32; 33 insns, 5 cond-branches, 0 loops, 2 jumps */
    /* immediates: 1, 2, 0, 0x102 */
    /* first predicate: bnez.n a10, 35 <wifi_internal_ioctl_process+0x1d> (condition opaque) */
    /* mem ld32: base=(?) off=20 */
    /* mem ld32: base=(?) off=12 */
    /* mem ld32: base=(lit:s_ioctl_table) off=0 */
    /* mem ld32: base=(lit:s_ioctl_table) off=4 */
    /* site +0x2d: wifi_log(1, 2, 1, lit:.rodata_wlog_error.152, *(?+12)) */
    wifi_log(1, 2, 1, lit:.rodata_wlog_error.152, *(?+12));
    /* site +0x49: indirect call via a11 (base *(s_ioctl_table+4)); args: ret@2d, *(s_ioctl_table+4), 1, lit:.rodata_wlog_error.153, *(?+12) */
    opaque_indirect_a11();
    /* site +0x65: wifi_log(ret@49, 2, 1, lit:.rodata_wlog_error.154, *(?+12)) */
    wifi_log(ret@49, 2, 1, lit:.rodata_wlog_error.154, *(?+12));
    return 0x102;
}

/* wifi_get_tsf_time_process @ ieee80211_ioctl.o 0x0000000c size 124B bind GLOBAL
 * Calls: esp_wifi_get_mode, hal_get_tsf_time | Data refs: g_ic
 * Fidelity: medium - branchy but loop-free, call sequence mapped */
u32 wifi_get_tsf_time_process(u32 a2)
{
    /* frame: entry a1,48; 48 insns, 9 cond-branches, 0 loops, 4 jumps */
    /* immediates: 0x102, 0, 1, -1 */
    /* first predicate: beqz a3, 86 <wifi_get_tsf_time_process+0x7a> (condition opaque) */
    /* mem ld32: base=(?) off=20 */
    /* mem st32: base=(?) off=0 */
    /* mem ld8: base=(?) off=8 */
    /* mem ld32: base=(?) off=0 */
    /* mem ld32: base=(lit:g_ic) off=16 */
    /* mem ld32: base=(lit:g_ic) off=20 */
    /* mem ld32: base=((*(g_ic+16)+-1)) off=228 */
    /* mem ld8: base=((*((*(g_ic+16)+-1)+228)+131072)) off=246 */
    /* mem st32: base=(*(?+20)) off=0 */
    /* mem st32: base=(*(?+20)) off=4 */
    /* site +0x29: esp_wifi_get_mode(/* no traced args */) */
    esp_wifi_get_mode(/* no traced args */);
    /* site +0x77: hal_get_tsf_time(1) */
    hal_get_tsf_time(1);
    return -1;
}

/* wifi_ftm_start_initiator_process @ ieee80211_ioctl.o 0x00000000 size 8B bind GLOBAL
 * Calls: none | Data refs: none
 * Fidelity: high - straight-line, fully mapped (3 insns) */
u32 wifi_ftm_start_initiator_process(void)
{
    /* frame: entry a1,32; 3 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0x106 */
    return 0x106;
}

/* wifi_send_mgmt_frame @ ieee80211_ioctl.o 0x00000078 size 744B bind GLOBAL
 * Calls: wifi_log, cnx_node_search, memcpy, wifi_log, hostap_query_mac_in_list, hostap_query_mac_in_list, wifi_log, hostap_query_mac_in_list, wifi_log, hostap_add_in_mac_list, ieee80211_send_mgmt, ieee80211_is_robust_mgmt_frm, ieee80211_get_robustmgtframe, ieee80211_getmgtframe, memcpy, ieee80211_set_tx_desc, ic_get_G6M_sched, hostap_add_in_mac_list, ieee80211_mgmt_output, hostap_del_mac_info_from_list, wifi_log | Data refs: g_ic, .rodata.str1.1, .rodata_wlog_error.155, .rodata_wlog_error.156, .rodata_wlog_debug.157, .rodata_wlog_debug.158, .rodata_wlog_debug.160, .rodata_wlog_debug.159, .rodata_wlog_warning.161
 * Fidelity: low - 275 insns, 36 branches, 0 loops; skeleton only */
u32 wifi_send_mgmt_frame(u32 a2, u32 a3)
{
    /* frame: entry a1,64; 275 insns, 36 cond-branches, 0 loops, 16 jumps */
    /* immediates: 1, 0x5d1, 156, 6, 2, 0x105, 176, 192, 223, 0 */
    /* first predicate: bnez.n a4, 8c <wifi_send_mgmt_frame+0x14> (condition opaque) */
    /* mem ld32: base=(?) off=20 */
    /* mem ld32: base=(lit:g_ic) off=16 */
    /* mem ld32: base=(*(g_ic+16)) off=0x2a0 */
    /* mem ld32: base=(*(g_ic+0x2a0)) off=20 */
    /* mem ld32: base=(*(g_ic+20)) off=0x240 */
    /* mem ld32: base=(*(g_ic+20)) off=228 */
    /* mem ld32: base=(?) off=20 */
    /* mem ld8: base=(?) off=24 */
    /* mem ld8: base=(?) off=37 */
    /* mem st32: base=(?) off=12 */
    /* ... +62 more memops */
    /* site +0xb2: wifi_log(1, (1 slli 11), 1, lit:.rodata_wlog_error.155, lit:.rodata.str1.1) */
    wifi_log(1, (1 slli 11), 1, lit:.rodata_wlog_error.155, lit:.rodata.str1.1);
    /* site +0xc1: cnx_node_search((?+32), (1 slli 11), 1, lit:.rodata_wlog_error.155, lit:.rodata.str1.1) */
    cnx_node_search((?+32), (1 slli 11), 1, lit:.rodata_wlog_error.155, lit:.rodata.str1.1);
    /* site +0xd6: memcpy(156, (?+32), 6, lit:.rodata_wlog_error.155, lit:.rodata.str1.1) */
    memcpy(156, (?+32), 6, lit:.rodata_wlog_error.155, lit:.rodata.str1.1);
    /* site +0xf5: wifi_log(1, 2, 1, lit:.rodata_wlog_error.156, *(?+20)) */
    wifi_log(1, 2, 1, lit:.rodata_wlog_error.156, *(?+20));
    /* site +0x117: hostap_query_mac_in_list((?+32), 2, 1, lit:.rodata_wlog_error.156, *(?+20)) */
    hostap_query_mac_in_list((?+32), 2, 1, lit:.rodata_wlog_error.156, *(?+20));
    /* site +0x15d: hostap_query_mac_in_list((?+32), 0, 1, lit:.rodata_wlog_debug.157, *(?+32)) */
    hostap_query_mac_in_list((?+32), 0, 1, lit:.rodata_wlog_debug.157, *(?+32));
    /* site +0x1a1: wifi_log(1, 4, 4, lit:.rodata_wlog_debug.160, *(g_ic+228)) */
    wifi_log(1, 4, 4, lit:.rodata_wlog_debug.160, *(g_ic+228));
    /* site +0x1b5: hostap_query_mac_in_list((?+32), 3, 4, lit:.rodata_wlog_debug.160, *(g_ic+228)) */
    hostap_query_mac_in_list((?+32), 3, 4, lit:.rodata_wlog_debug.160, *(g_ic+228));
    /* site +0x1e3: wifi_log(1, 4, 4, lit:.rodata_wlog_debug.159, *(?+32)) */
    wifi_log(1, 4, 4, lit:.rodata_wlog_debug.159, *(?+32));
    /* site +0x1fa: hostap_add_in_mac_list((?+32), 3, 4, lit:.rodata_wlog_debug.159, *(?+32)) */
    hostap_add_in_mac_list((?+32), 3, 4, lit:.rodata_wlog_debug.159, *(?+32));
    /* site +0x212: ieee80211_send_mgmt(*(g_ic+228), *(?+24), *(?+38), lit:.rodata_wlog_debug.159, *(?+32)) */
    ieee80211_send_mgmt(*(g_ic+228), *(?+24), *(?+38), lit:.rodata_wlog_debug.159, *(?+32));
    /* site +0x243: ieee80211_is_robust_mgmt_frm(*(?+24), *(?+38), *(?+38), lit:.rodata_wlog_debug.159, *(?+32)) */
    ieee80211_is_robust_mgmt_frm(*(?+24), *(?+38), *(?+38), lit:.rodata_wlog_debug.159, *(?+32));
    /* site +0x255: ieee80211_get_robustmgtframe((?+16), 24, *(?+28), *(g_ic+228), *(?+32)) */
    ieee80211_get_robustmgtframe((?+16), 24, *(?+28), *(g_ic+228), *(?+32));
    /* site +0x279: ieee80211_getmgtframe((?+16), 24, *(?+28), *(g_ic+228), *(?+32)) */
    ieee80211_getmgtframe((?+16), 24, *(?+28), *(g_ic+228), *(?+32));
    /* site +0x299: memcpy(*(?+16), (?+38), *(?+28), *(g_ic+228), *(?+32)) */
    memcpy(*(?+16), (?+38), *(?+28), *(g_ic+228), *(?+32));
    /* site +0x2b5: ieee80211_set_tx_desc(ret@299, ret@279, 7, 0, 0) */
    ieee80211_set_tx_desc(ret@299, ret@279, 7, 0, 0);
    /* site +0x2cf: ic_get_G6M_sched(ret@2b5, ret@279, 7, 0, 0) */
    ic_get_G6M_sched(ret@2b5, ret@279, 7, 0, 0);
    /* site +0x306: hostap_add_in_mac_list((?+32), 2, 7, 0, 0) */
    hostap_add_in_mac_list((?+32), 2, 7, 0, 0);
    /* site +0x31b: ieee80211_mgmt_output(ret@306, 2, *(?+24), 0, 0) */
    ieee80211_mgmt_output(ret@306, 2, *(?+24), 0, 0);
    /* site +0x342: hostap_del_mac_info_from_list((?+32), 0, *(?+24), 0, 0) */
    hostap_del_mac_info_from_list((?+32), 0, *(?+24), 0, 0);
    /* site +0x356: wifi_log(1, 64, 2, lit:.rodata_wlog_warning.161, 0) */
    wifi_log(1, 64, 2, lit:.rodata_wlog_warning.161, 0);
    return 0x101;
}

/* wifi_set_rssi_threshold @ ieee80211_ioctl.o 0x00000004 size 18B bind GLOBAL
 * Calls: none | Data refs: g_ic
 * Fidelity: high - straight-line, fully mapped (7 insns) */
u32 wifi_set_rssi_threshold(u32 a2)
{
    /* frame: entry a1,32; 7 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0 */
    /* mem ld32: base=(?) off=12 */
    /* mem st32: base=(lit:g_ic) off=0x270 */
    return 0;
}

/* wifi_register_mgmt_frame @ ieee80211_ioctl.o 0x00000004 size 23B bind GLOBAL
 * Calls: none | Data refs: g_ic
 * Fidelity: high - straight-line, fully mapped (9 insns) */
u32 wifi_register_mgmt_frame(u32 a2)
{
    /* frame: entry a1,32; 9 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0 */
    /* mem ld32: base=(?) off=20 */
    /* mem ld32: base=(?) off=12 */
    /* mem st32: base=(lit:g_ic) off=0x278 */
    /* mem st32: base=(lit:g_ic) off=0x274 */
    return 0;
}

/* wifi_nan_set_config_local @ ieee80211_ioctl.o 0x00000030 size 190B bind GLOBAL
 * Calls: wifi_log, wifi_check_chan_param, wifi_log, wifi_log, nan_set_config_local, wifi_log | Data refs: g_wifi_nvs, .rodata_wlog_error.162, .rodata_wlog_error.163, .rodata_wlog_error.164, .rodata_wlog_error.165
 * Fidelity: medium - branchy but loop-free, call sequence mapped (weak) */
u32 wifi_nan_set_config_local(u32 a2, u32 a3)
{
    /* frame: entry a1,32; 53 insns, 5 cond-branches, 0 loops, 3 jumps */
    /* immediates: 1, 2, 0, 120, 0x102, -1 */
    /* first predicate: beqi a14, 4, 56 <wifi_nan_set_config_local+0x26> (condition opaque) */
    /* mem ld32: base=(lit:g_wifi_nvs) off=0 */
    /* mem ld8: base=(*(g_wifi_nvs+0)) off=0 */
    /* mem ld8: base=(?) off=0 */
    /* mem ld8: base=(?) off=2 */
    /* mem ld16: base=(?) off=4 */
    /* site +0x4d: wifi_log(1, 2, 1, lit:.rodata_wlog_error.162, *(g_wifi_nvs+0)) */
    wifi_log(1, 2, 1, lit:.rodata_wlog_error.162, *(g_wifi_nvs+0));
    /* site +0x5e: wifi_check_chan_param(literal, 0, 1, lit:.rodata_wlog_error.162, *(g_wifi_nvs+0)) */
    wifi_check_chan_param(literal, 0, 1, lit:.rodata_wlog_error.162, *(g_wifi_nvs+0));
    /* site +0x71: wifi_log(1, 2, 1, lit:.rodata_wlog_error.163, *(?+0)) */
    wifi_log(1, 2, 1, lit:.rodata_wlog_error.163, *(?+0));
    /* site +0x95: wifi_log(ret@71, 2, 1, lit:.rodata_wlog_error.164, *(?+2)) */
    wifi_log(ret@71, 2, 1, lit:.rodata_wlog_error.164, *(?+2));
    /* site +0xa3: nan_set_config_local(?, 2, 1, lit:.rodata_wlog_error.164, *(?+2)) */
    nan_set_config_local(?, 2, 1, lit:.rodata_wlog_error.164, *(?+2));
    /* site +0xb5: wifi_log(ret@a3, 2, 1, lit:.rodata_wlog_error.165, *(?+2)) */
    wifi_log(ret@a3, 2, 1, lit:.rodata_wlog_error.165, *(?+2));
    return -1;
}

/* wifi_set_config_process @ ieee80211_ioctl.o 0x000000b8 size 1368B bind GLOBAL
 * Calls: wifi_log, cnx_clear_blacklist, strnlen, cnx_remove_all_rc, wifi_nvs_get, wifi_nvs_get, map_wifi_config_sae_pwe_to_supp, wifi_log, strlen, wifi_log, wifi_log, strlen, wifi_log, cnx_get_authtype_strength, cnx_get_authtype_strength, sta_is_wpa3_enabled, wifi_log, wifi_nvs_get, map_wifi_config_sae_pwe_to_supp, memcmp, memcmp, memcmp, memcmp, memcmp, map_wifi_config_sae_pwe_to_supp, memcmp, memcmp, wifi_pmk_is_valid, indirect(a3), wifi_station_set_config_local_2_constprop_0, wifi_station_set_config_local_2_constprop_0, indirect(a3), wifi_nan_set_config_local, indirect(a2) | Data refs: g_ic, .rodata_wlog_error.126, g_cnxMgr, g_wifi_nvs, .rodata_wlog_error.35, .rodata_wlog_error.36, .rodata_wlog_warning.37, .rodata_wlog_warning.38, .rodata_wlog_warning.39, .rodata_wlog_debug.40, .bss.overwrite_save_ap_id$0, net80211_funcs, g_ic+0x200
 * Fidelity: low - 492 insns, 72 branches, 0 loops; skeleton only */
u32 wifi_set_config_process(u32 a2, u32 a3, u32 a4)
{
    /* frame: entry a1,64; 492 insns, 72 cond-branches, 0 loops, 29 jumps */
    /* immediates: 11, 32, -3, 3, -127, 1, 0, 16, 0x102, 2 */
    /* first predicate: bnez a11, 5c5 <wifi_set_config_process+0x50d> (condition opaque) */
    /* mem ld8: base=(?) off=8 */
    /* mem ld32: base=(lit:g_ic) off=16 */
    /* mem ld8: base=((*(g_ic+16)+65536)) off=84 */
    /* mem ld32: base=(lit:g_ic) off=116 */
    /* mem ld32: base=(lit:g_ic) off=16 */
    /* mem ld32: base=(*(g_ic+16)) off=152 */
    /* mem st32: base=((lit:g_cnxMgr+983040)) off=96 */
    /* mem ld32: base=(lit:g_wifi_nvs) off=0 */
    /* mem ld8: base=(*(g_wifi_nvs+0)) off=0 */
    /* mem ld32: base=(?) off=156 */
    /* ... +105 more memops */
    /* site +0xdd: wifi_log(*((*(g_ic+16)+65536)+84), 11, *((*(g_ic+16)+65536)+84), lit:.rodata_wlog_error.126) */
    wifi_log(*((*(g_ic+16)+65536)+84), 11, *((*(g_ic+16)+65536)+84), lit:.rodata_wlog_error.126);
    /* site +0xec: cnx_clear_blacklist(literal, 11, *((*(g_ic+16)+65536)+84), lit:.rodata_wlog_error.126) */
    cnx_clear_blacklist(literal, 11, *((*(g_ic+16)+65536)+84), lit:.rodata_wlog_error.126);
    /* site +0x101: strnlen((?+20), 32, *((*(g_ic+16)+65536)+84), lit:.rodata_wlog_error.126) */
    strnlen((?+20), 32, *((*(g_ic+16)+65536)+84), lit:.rodata_wlog_error.126);
    /* site +0x115: cnx_remove_all_rc(ret@101, 32, *((*(g_ic+16)+65536)+84), lit:.rodata_wlog_error.126) */
    cnx_remove_all_rc(ret@101, 32, *((*(g_ic+16)+65536)+84), lit:.rodata_wlog_error.126);
    /* site +0x131: wifi_nvs_get(ret@115, 32, *((*(g_ic+16)+65536)+84), lit:.rodata_wlog_error.126) */
    wifi_nvs_get(ret@115, 32, *((*(g_ic+16)+65536)+84), lit:.rodata_wlog_error.126);
    /* site +0x145: wifi_nvs_get(literal, 32, *((*(g_ic+16)+65536)+84), lit:.rodata_wlog_error.126) */
    wifi_nvs_get(literal, 32, *((*(g_ic+16)+65536)+84), lit:.rodata_wlog_error.126);
    /* site +0x14e: map_wifi_config_sae_pwe_to_supp(*(?+156), 32, *((*(g_ic+16)+65536)+84), lit:.rodata_wlog_error.126) */
    map_wifi_config_sae_pwe_to_supp(*(?+156), 32, *((*(g_ic+16)+65536)+84), lit:.rodata_wlog_error.126);
    /* site +0x1b5: wifi_log(*(g_wifi_nvs+0), 3, 1, lit:.rodata_wlog_error.36, *(?+140)) */
    wifi_log(*(g_wifi_nvs+0), 3, 1, lit:.rodata_wlog_error.36, *(?+140));
    /* site +0x1c9: strlen((?+52), 3, 1, lit:.rodata_wlog_error.36, *(?+140)) */
    strlen((?+52), 3, 1, lit:.rodata_wlog_error.36, *(?+140));
    /* site +0x1e6: wifi_log(1, 2, 2, lit:.rodata_wlog_warning.37, *(?+140)) */
    wifi_log(1, 2, 2, lit:.rodata_wlog_warning.37, *(?+140));
    /* site +0x219: wifi_log(1, 2, 2, lit:.rodata_wlog_warning.38, *(?+140)) */
    wifi_log(1, 2, 2, lit:.rodata_wlog_warning.38, *(?+140));
    /* site +0x22f: strlen((?+52), 2, 2, lit:.rodata_wlog_warning.38, *(?+140)) */
    strlen((?+52), 2, 2, lit:.rodata_wlog_warning.38, *(?+140));
    /* site +0x245: wifi_log(1, 2, 2, lit:.rodata_wlog_warning.39, *(?+140)) */
    wifi_log(1, 2, 2, lit:.rodata_wlog_warning.39, *(?+140));
    /* site +0x253: cnx_get_authtype_strength(ret@245, 2, 2, lit:.rodata_wlog_warning.39, *(?+140)) */
    cnx_get_authtype_strength(ret@245, 2, 2, lit:.rodata_wlog_warning.39, *(?+140));
    /* site +0x25e: cnx_get_authtype_strength(9, 2, 2, lit:.rodata_wlog_warning.39, *(?+140)) */
    cnx_get_authtype_strength(9, 2, 2, lit:.rodata_wlog_warning.39, *(?+140));
    /* site +0x292: sta_is_wpa3_enabled(ret@25e, 2, 2, lit:.rodata_wlog_warning.39, *(?+140)) */
    sta_is_wpa3_enabled(ret@25e, 2, 2, lit:.rodata_wlog_warning.39, *(?+140));
    /* site +0x2c1: wifi_log(1, 2, 4, lit:.rodata_wlog_debug.40, *(?+140)) */
    wifi_log(1, 2, 4, lit:.rodata_wlog_debug.40, *(?+140));
    /* site +0x2c7: wifi_nvs_get(ret@2c1, 2, 4, lit:.rodata_wlog_debug.40, *(?+140)) */
    wifi_nvs_get(ret@2c1, 2, 4, lit:.rodata_wlog_debug.40, *(?+140));
    /* site +0x2d2: map_wifi_config_sae_pwe_to_supp(*(?+156), 2, 4, lit:.rodata_wlog_debug.40, *(?+140)) */
    map_wifi_config_sae_pwe_to_supp(*(?+156), 2, 4, lit:.rodata_wlog_debug.40, *(?+140));
    /* site +0x2e6: memcmp((ret@2c7+8), 2, 32, lit:.rodata_wlog_debug.40, *(?+140)) */
    memcmp((ret@2c7+8), 2, 32, lit:.rodata_wlog_debug.40, *(?+140));
    /* site +0x2f6: memcmp((ret@2c7+47), (?+52), 64, lit:.rodata_wlog_debug.40, *(?+140)) */
    memcmp((ret@2c7+47), (?+52), 64, lit:.rodata_wlog_debug.40, *(?+140));
    /* site +0x30e: memcmp(147, (?+121), 6, lit:.rodata_wlog_debug.40, *(?+140)) */
    memcmp(147, (?+121), 6, lit:.rodata_wlog_debug.40, *(?+140));
    /* site +0x3f5: memcmp(0x47d, 171, 32, (ret@2c7+196608), *(?+140)) */
    memcmp(0x47d, 171, 32, (ret@2c7+196608), *(?+140));
    /* site +0x457: memcmp(*((ret@2c7+262144)+169), (?+20), *(?+140), *(?+12), *(?+140)) */
    memcmp(*((ret@2c7+262144)+169), (?+20), *(?+140), *(?+12), *(?+140));
    /* site +0x46b: map_wifi_config_sae_pwe_to_supp(*(?+156), (?+20), *(?+140), *(?+12), *(?+8)) */
    map_wifi_config_sae_pwe_to_supp(*(?+156), (?+20), *(?+140), *(?+12), *(?+8));
    /* site +0x482: memcmp(196, (?+52), 64, *(?+12), *(?+8)) */
    memcmp(196, (?+52), 64, *(?+12), *(?+8));
    /* site +0x49a: memcmp(0x47d, 151, 32, *(?+12), *(?+8)) */
    memcmp(0x47d, 151, 32, *(?+12), *(?+8));
    /* site +0x4e5: wifi_pmk_is_valid(0x10b, ret@49a, *((ret@131+262144)+20), *(?+12), *(?+8)) */
    wifi_pmk_is_valid(0x10b, ret@49a, *((ret@131+262144)+20), *(?+12), *(?+8));
    /* site +0x50f: indirect call via a3 (base *(g_ic+104)); args: ret@4e5, lit:g_ic, *((ret@131+262144)+20), *(?+12), *(?+8) */
    opaque_indirect_a3();
    /* site +0x585: wifi_station_set_config_local_2_constprop_0((?+20), 0, *((ret@131+262144)+20), 140, 32) */
    wifi_station_set_config_local_2_constprop_0((?+20), 0, *((ret@131+262144)+20), 140, 32);
    /* site +0x5b1: wifi_station_set_config_local_2_constprop_0((?+20), *(.bss.overwrite_save_ap_id$0+0), *((ret@131+262144)+20), 140, 32) */
    wifi_station_set_config_local_2_constprop_0((?+20), *(.bss.overwrite_save_ap_id$0+0), *((ret@131+262144)+20), 140, 32);
    /* site +0x5e5: indirect call via a3 (base *(net80211_funcs+20)); args: (140+20), *(.bss.overwrite_save_ap_id$0+0), *((ret@131+262144)+20), 140, 32 */
    opaque_indirect_a3();
    /* site +0x5f9: wifi_nan_set_config_local((0+20), *(.bss.overwrite_save_ap_id$0+0), *((ret@131+262144)+20), 140, 32) */
    wifi_nan_set_config_local((0+20), *(.bss.overwrite_save_ap_id$0+0), *((ret@131+262144)+20), 140, 32);
    /* site +0x607: indirect call via a2 (base *(ret@5f9+88)); args: ret@5f9, *(.bss.overwrite_save_ap_id$0+0), *((ret@131+262144)+20), 140, 32 */
    opaque_indirect_a2();
    return 0;
}

/* wifi_nan_config_process @ ieee80211_ioctl.o 0x00000004 size 15B bind GLOBAL
 * Calls: nan_register_callbacks | Data refs: none
 * Fidelity: high - straight-line, fully mapped (6 insns) */
u32 wifi_nan_config_process(u32 a2)
{
    /* frame: entry a1,32; 6 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0 */
    /* mem ld32: base=(?) off=20 */
    /* site +0xe: nan_register_callbacks(*(?+20)) */
    nan_register_callbacks(*(?+20));
    return 0;
}

/* wifi_nan_publish_process @ ieee80211_ioctl.o 0x00000008 size 44B bind GLOBAL
 * Calls: nan_cancel_service, nan_start_publish_service | Data refs: none
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 wifi_nan_publish_process(u32 a2)
{
    /* frame: entry a1,32; 17 insns, 1 cond-branches, 0 loops, 1 jumps */
    /* immediates: 1, 0 */
    /* first predicate: beqz.n a3, 24 <wifi_nan_publish_process+0x1c> (condition opaque) */
    /* mem ld8: base=(?) off=8 */
    /* mem ld32: base=(?) off=20 */
    /* mem ld32: base=(?) off=12 */
    /* mem ld8: base=(*(?+12)) off=0 */
    /* site +0x1e: nan_cancel_service(*(*(?+12)+0), *(?+12)) */
    nan_cancel_service(*(*(?+12)+0), *(?+12));
    /* site +0x27: nan_start_publish_service(ret@1e, *(?+12)) */
    nan_start_publish_service(ret@1e, *(?+12));
    return opaque_result; /* full dataflow not recovered */
}

/* wifi_nan_subscribe_process @ ieee80211_ioctl.o 0x00000008 size 44B bind GLOBAL
 * Calls: nan_cancel_service, nan_start_subscribe_service | Data refs: none
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 wifi_nan_subscribe_process(u32 a2)
{
    /* frame: entry a1,32; 17 insns, 1 cond-branches, 0 loops, 1 jumps */
    /* immediates: 1, 0 */
    /* first predicate: beqz.n a3, 24 <wifi_nan_subscribe_process+0x1c> (condition opaque) */
    /* mem ld8: base=(?) off=8 */
    /* mem ld32: base=(?) off=20 */
    /* mem ld32: base=(?) off=12 */
    /* mem ld8: base=(*(?+12)) off=0 */
    /* site +0x1e: nan_cancel_service(*(*(?+12)+0), *(?+12)) */
    nan_cancel_service(*(*(?+12)+0), *(?+12));
    /* site +0x27: nan_start_subscribe_service(ret@1e, *(?+12)) */
    nan_start_subscribe_service(ret@1e, *(?+12));
    return opaque_result; /* full dataflow not recovered */
}

/* wifi_nan_followup_process @ ieee80211_ioctl.o 0x00000004 size 26B bind GLOBAL
 * Calls: nan_send_followup_msg | Data refs: none
 * Fidelity: high - straight-line, fully mapped (10 insns) */
u32 wifi_nan_followup_process(u32 a2)
{
    /* frame: entry a1,32; 10 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* immediates: 1, 0 */
    /* mem ld32: base=(?) off=20 */
    /* mem ld32: base=(?) off=12 */
    /* site +0x11: nan_send_followup_msg(*(?+12), *(?+20)) */
    nan_send_followup_msg(*(?+12), *(?+20));
    return opaque_result; /* full dataflow not recovered */
}

/* wifi_ndp_req_process @ ieee80211_ioctl.o 0x0000000c size 40B bind GLOBAL
 * Calls: nan_datapath_send_req, wifi_log | Data refs: .rodata_wlog_error.166
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 wifi_ndp_req_process(u32 a2)
{
    /* frame: entry a1,32; 16 insns, 1 cond-branches, 0 loops, 0 jumps */
    /* immediates: 1, 2, -1 */
    /* first predicate: beqz.n a10, 30 <wifi_ndp_req_process+0x24> (condition opaque) */
    /* mem ld32: base=(?) off=24 */
    /* mem ld32: base=(?) off=20 */
    /* mem ld32: base=(?) off=12 */
    /* site +0x19: nan_datapath_send_req(*(?+12), *(?+20), *(?+24)) */
    nan_datapath_send_req(*(?+12), *(?+20), *(?+24));
    /* site +0x2b: wifi_log(1, 2, 1, lit:.rodata_wlog_error.166) */
    wifi_log(1, 2, 1, lit:.rodata_wlog_error.166);
    return -1;
}

/* wifi_ndp_resp_process @ ieee80211_ioctl.o 0x00000010 size 60B bind GLOBAL
 * Calls: memcpy, nan_datapath_send_resp, wifi_log | Data refs: .rodata_wlog_error.167
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 wifi_ndp_resp_process(u32 a2)
{
    /* frame: entry a1,48; 25 insns, 1 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0, 8, 1, 2, -1 */
    /* first predicate: beqz.n a10, 48 <wifi_ndp_resp_process+0x38> (condition opaque) */
    /* mem ld32: base=(?) off=12 */
    /* mem ld32: base=(?) off=20 */
    /* mem st32: base=(?) off=0 */
    /* mem st32: base=(?) off=4 */
    /* site +0x27: memcpy(?, *(?+12), 8) */
    memcpy(?, *(?+12), 8);
    /* site +0x31: nan_datapath_send_resp(*(?+20), ?, 8) */
    nan_datapath_send_resp(*(?+20), ?, 8);
    /* site +0x43: wifi_log(1, 2, 1, lit:.rodata_wlog_error.167) */
    wifi_log(1, 2, 1, lit:.rodata_wlog_error.167);
    return -1;
}

/* wifi_ndp_end_process @ ieee80211_ioctl.o 0x0000000c size 36B bind GLOBAL
 * Calls: nan_datapath_end, wifi_log | Data refs: .rodata_wlog_error.168
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 wifi_ndp_end_process(u32 a2)
{
    /* frame: entry a1,32; 14 insns, 1 cond-branches, 0 loops, 0 jumps */
    /* immediates: 1, 2, -1 */
    /* first predicate: beqz.n a10, 2c <wifi_ndp_end_process+0x20> (condition opaque) */
    /* mem ld32: base=(?) off=20 */
    /* site +0x15: nan_datapath_end(*(?+20)) */
    nan_datapath_end(*(?+20));
    /* site +0x27: wifi_log(1, 2, 1, lit:.rodata_wlog_error.168) */
    wifi_log(1, 2, 1, lit:.rodata_wlog_error.168);
    return -1;
}

/* wifi_roc_process @ ieee80211_ioctl.o 0x00000004 size 18B bind GLOBAL
 * Calls: offchan_roc_req | Data refs: none
 * Fidelity: high - straight-line, fully mapped (7 insns) */
u32 wifi_roc_process(u32 a2)
{
    /* frame: entry a1,32; 7 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* mem ld8: base=(?) off=8 */
    /* mem ld32: base=(?) off=20 */
    /* site +0xf: offchan_roc_req(*(?+20), *(?+8)) */
    offchan_roc_req(*(?+20), *(?+8));
    return last_call_result; /* opaque */
}

/* wifi_action_tx_process @ ieee80211_ioctl.o 0x00000004 size 18B bind GLOBAL
 * Calls: offchan_action_tx_req | Data refs: none
 * Fidelity: high - straight-line, fully mapped (7 insns) */
u32 wifi_action_tx_process(u32 a2)
{
    /* frame: entry a1,32; 7 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* mem ld8: base=(?) off=8 */
    /* mem ld32: base=(?) off=20 */
    /* site +0xf: offchan_action_tx_req(*(?+20), *(?+8)) */
    offchan_action_tx_req(*(?+20), *(?+8));
    return last_call_result; /* opaque */
}

/* wifi_offchan_cancel_process @ ieee80211_ioctl.o 0x00000008 size 24B bind GLOBAL
 * Calls: offchan_trigger_in_progress, chm_cancel_op | Data refs: none
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 wifi_offchan_cancel_process(u32 a2)
{
    /* frame: entry a1,32; 9 insns, 1 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0 */
    /* first predicate: beqz.n a10, 1c <wifi_offchan_cancel_process+0x14> (condition opaque) */
    /* mem ld8: base=(?) off=8 */
    /* site +0x11: offchan_trigger_in_progress(*(?+8)) */
    offchan_trigger_in_progress(*(?+8));
    /* site +0x19: chm_cancel_op(ret@11) */
    chm_cancel_op(ret@11);
    return 0;
}

/* wifi_configure_wake_window_process @ ieee80211_ioctl.o 0x00000008 size 29B bind GLOBAL
 * Calls: pm_register_connectionless_wake_window, pm_unregister_connectionless_wake_window | Data refs: none
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 wifi_configure_wake_window_process(u32 a2)
{
    /* frame: entry a1,32; 11 insns, 1 cond-branches, 0 loops, 1 jumps */
    /* immediates: 0 */
    /* first predicate: beqz.n a2, 1b <wifi_configure_wake_window_process+0x13> (condition opaque) */
    /* mem ld32: base=(?) off=20 */
    /* mem ld8: base=(?) off=8 */
    /* site +0x15: pm_register_connectionless_wake_window(*(?+20)) */
    pm_register_connectionless_wake_window(*(?+20));
    /* site +0x1e: pm_unregister_connectionless_wake_window(ret@15) */
    pm_unregister_connectionless_wake_window(ret@15);
    return 0;
}

/* wifi_configure_wake_interval_process @ ieee80211_ioctl.o 0x00000004 size 16B bind GLOBAL
 * Calls: pm_connectionless_module_set_wake_interval | Data refs: none
 * Fidelity: high - straight-line, fully mapped (6 insns) */
u32 wifi_configure_wake_interval_process(u32 a2)
{
    /* frame: entry a1,32; 6 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0 */
    /* mem ld16: base=(?) off=12 */
    /* site +0xf: pm_connectionless_module_set_wake_interval(*(?+12)) */
    pm_connectionless_module_set_wake_interval(*(?+12));
    return 0;
}

/* wifi_disable_pmf_config_process @ ieee80211_ioctl.o 0x00000044 size 398B bind GLOBAL
 * Calls: wifi_nvs_get, wifi_nvs_set, wifi_nvs_set, wifi_nvs_commit, wifi_log, wifi_log, indirect(a10), wifi_nvs_set, wifi_nvs_set, wifi_nvs_commit, wifi_log, indirect(a10) | Data refs: g_wifi_nvs, .rodata_wlog_error.169, g_ic, .rodata_wlog_info.170, .rodata_wlog_error.171, net80211_funcs, .rodata_wlog_info.172
 * Fidelity: low - 146 insns, 19 branches, 0 loops; skeleton only */
u32 wifi_disable_pmf_config_process(u32 a2)
{
    /* frame: entry a1,32; 146 insns, 19 cond-branches, 0 loops, 5 jumps */
    /* immediates: 1, 0, 18, 19, 3, 2, -1, 0x102, 34, 35 */
    /* first predicate: bnez a4, f9 <wifi_disable_pmf_config_process+0xb5> (condition opaque) */
    /* mem ld8: base=(?) off=8 */
    /* mem ld32: base=(lit:g_wifi_nvs) off=0 */
    /* mem ld8: base=((*(g_wifi_nvs+0)+196608)) off=95 */
    /* mem ld8: base=((*(g_wifi_nvs+0)+262144)) off=168 */
    /* mem st8: base=((ret@4d+196608)) off=96 */
    /* mem ld8: base=((lit:g_ic+131072)) off=31 */
    /* mem ld8: base=((lit:g_ic+131072)) off=31 */
    /* mem st8: base=((ret@4d+196608)) off=97 */
    /* mem ld8: base=((ret@f1+196608)) off=244 */
    /* mem ld32: base=(lit:g_wifi_nvs) off=0 */
    /* ... +11 more memops */
    /* site +0x4d: wifi_nvs_get(/* no traced args */) */
    wifi_nvs_get(/* no traced args */);
    /* site +0xab: wifi_nvs_set(18, 0, 0, lit:.rodata_wlog_error.169) */
    wifi_nvs_set(18, 0, 0, lit:.rodata_wlog_error.169);
    /* site +0xce: wifi_nvs_set(19, ret@ab, *(g_ic+31), lit:.rodata_wlog_error.169) */
    wifi_nvs_set(19, ret@ab, *(g_ic+31), lit:.rodata_wlog_error.169);
    /* site +0xd9: wifi_nvs_commit(ret@ce, ret@ab, *(g_ic+31), lit:.rodata_wlog_error.169) */
    wifi_nvs_commit(ret@ce, ret@ab, *(g_ic+31), lit:.rodata_wlog_error.169);
    /* site +0xf1: wifi_log(ret@d9, 2, 3, lit:.rodata_wlog_info.170, ret@d9) */
    wifi_log(ret@d9, 2, 3, lit:.rodata_wlog_info.170, ret@d9);
    /* site +0x135: wifi_log(1, 2, 1, lit:.rodata_wlog_error.171, ret@d9) */
    wifi_log(1, 2, 1, lit:.rodata_wlog_error.171, ret@d9);
    /* site +0x155: indirect call via a10 (base *(net80211_funcs+16)); args: *(net80211_funcs+16), 2, 1, lit:.rodata_wlog_error.171, ret@d9 */
    opaque_indirect_a10();
    /* site +0x177: wifi_nvs_set(34, 0, 0, lit:.rodata_wlog_error.171, ret@d9) */
    wifi_nvs_set(34, 0, 0, lit:.rodata_wlog_error.171, ret@d9);
    /* site +0x199: wifi_nvs_set(35, ret@177, ret@177, lit:.rodata_wlog_error.171, ret@d9) */
    wifi_nvs_set(35, ret@177, ret@177, lit:.rodata_wlog_error.171, ret@d9);
    /* site +0x1a3: wifi_nvs_commit(ret@199, ret@177, ret@177, lit:.rodata_wlog_error.171, ret@d9) */
    wifi_nvs_commit(ret@199, ret@177, ret@177, lit:.rodata_wlog_error.171, ret@d9);
    /* site +0x1b9: wifi_log(ret@1a3, 2, 3, lit:.rodata_wlog_info.172, 1) */
    wifi_log(ret@1a3, 2, 3, lit:.rodata_wlog_info.172, 1);
    /* site +0x1cb: indirect call via a10 (base *(net80211_funcs+12)); args: *(net80211_funcs+12), 2, 3, lit:.rodata_wlog_info.172, 1 */
    opaque_indirect_a10();
    return last_call_result; /* opaque */
}

/* wifi_ap_remove_sta_node_process @ ieee80211_ioctl.o 0x00000048 size 364B bind GLOBAL
 * Calls: cnx_node_search, wifi_log, ieee80211_send_mgmt, cnx_node_leave, wifi_log, hostap_query_mac_in_list, wifi_log, cnx_node_leave, hostap_add_in_mac_list, ieee80211_send_mgmt, hostap_del_mac_info_from_list, wifi_log | Data refs: g_ic, .rodata_wlog_debug.173, g_wifi_nvs, .rodata_wlog_debug.174, .rodata_wlog_debug.175, .rodata_wlog_debug.176
 * Fidelity: low - 137 insns, 10 branches, 0 loops; skeleton only */
u32 wifi_ap_remove_sta_node_process(u32 a2, u32 a4)
{
    /* frame: entry a1,48; 137 insns, 10 cond-branches, 0 loops, 4 jumps */
    /* immediates: 0x102, 4, 1, 192, 240, 0, 0x105 */
    /* first predicate: beqz a2, 1b0 <wifi_ap_remove_sta_node_process+0x168> (condition opaque) */
    /* mem ld32: base=(?) off=12 */
    /* mem ld8: base=(?) off=10 */
    /* mem ld32: base=(lit:g_ic) off=20 */
    /* mem ld32: base=(*(g_ic+20)) off=236 */
    /* mem ld32: base=(240) off=0 */
    /* mem st16: base=((*(240+0)+196608)) off=176 */
    /* mem ld32: base=(lit:g_wifi_nvs) off=0 */
    /* mem ld8: base=((*(g_wifi_nvs+0)+196608)) off=246 */
    /* mem ld8: base=((1+1)) off=5 */
    /* mem ld8: base=((1+1)) off=1 */
    /* ... +30 more memops */
    /* site +0x63: cnx_node_search(*(?+12)) */
    cnx_node_search(*(?+12));
    /* site +0x7d: wifi_log(1, 4, 4, lit:.rodata_wlog_debug.173) */
    wifi_log(1, 4, 4, lit:.rodata_wlog_debug.173);
    /* site +0x8a: ieee80211_send_mgmt(*(g_ic+236), 192, *(?+10), lit:.rodata_wlog_debug.173) */
    ieee80211_send_mgmt(*(g_ic+236), 192, *(?+10), lit:.rodata_wlog_debug.173);
    /* site +0xb1: cnx_node_leave(*(240+0), 192, *(?+10), lit:.rodata_wlog_debug.173) */
    cnx_node_leave(*(240+0), 192, *(?+10), lit:.rodata_wlog_debug.173);
    /* site +0xf7: wifi_log(1, 4, 4, lit:.rodata_wlog_debug.174, *((1+1)+0)) */
    wifi_log(1, 4, 4, lit:.rodata_wlog_debug.174, *((1+1)+0));
    /* site +0x102: hostap_query_mac_in_list(ret@f7, 0, 4, lit:.rodata_wlog_debug.174, *((1+1)+0)) */
    hostap_query_mac_in_list(ret@f7, 0, 4, lit:.rodata_wlog_debug.174, *((1+1)+0));
    /* site +0x131: wifi_log(1, 4, 4, lit:.rodata_wlog_debug.175, *((1+1)+0)) */
    wifi_log(1, 4, 4, lit:.rodata_wlog_debug.175, *((1+1)+0));
    /* site +0x142: cnx_node_leave((240+4), 4, 4, lit:.rodata_wlog_debug.175, *((1+1)+0)) */
    cnx_node_leave((240+4), 4, 4, lit:.rodata_wlog_debug.175, *((1+1)+0));
    /* site +0x152: hostap_add_in_mac_list(ret@142, ret@142, 4, lit:.rodata_wlog_debug.175, *((1+1)+0)) */
    hostap_add_in_mac_list(ret@142, ret@142, 4, lit:.rodata_wlog_debug.175, *((1+1)+0));
    /* site +0x161: ieee80211_send_mgmt((240+4), 192, *(?+10), lit:.rodata_wlog_debug.175, *((1+1)+0)) */
    ieee80211_send_mgmt((240+4), 192, *(?+10), lit:.rodata_wlog_debug.175, *((1+1)+0));
    /* site +0x17a: hostap_del_mac_info_from_list(*((1+1)+2), ret@152, *(?+10), lit:.rodata_wlog_debug.175, *((1+1)+0)) */
    hostap_del_mac_info_from_list(*((1+1)+2), ret@152, *(?+10), lit:.rodata_wlog_debug.175, *((1+1)+0));
    /* site +0x1aa: wifi_log(1, 4, 4, lit:.rodata_wlog_debug.176, *(*((1+1)+2)+0)) */
    wifi_log(1, 4, 4, lit:.rodata_wlog_debug.176, *(*((1+1)+2)+0));
    return 0x105;
}

/* wifi_ap_sta_sae_auth_done_process @ ieee80211_ioctl.o 0x00000020 size 234B bind GLOBAL
 * Calls: cnx_node_search, memcpy, wifi_event_post, ieee80211_psq_init, wifi_log, wifi_log | Data refs: .rodata_wlog_debug.177, .rodata_wlog_debug.178
 * Fidelity: low - 87 insns, 5 branches, 0 loops; skeleton only */
u32 wifi_ap_sta_sae_auth_done_process(u32 a2)
{
    /* frame: entry a1,80; 87 insns, 5 cond-branches, 0 loops, 2 jumps */
    /* immediates: 0x102, 1, 6, 10, 15, 2, 0x108, 4, 0, 0x105 */
    /* first predicate: beqz a3, 108 <wifi_ap_sta_sae_auth_done_process+0xe8> (condition opaque) */
    /* mem ld32: base=(?) off=12 */
    /* mem ld32: base=(ret@37) off=12 */
    /* mem ld16: base=(ret@37) off=38 */
    /* mem st8: base=(?) off=38 */
    /* mem st16: base=(?) off=40 */
    /* mem ld32: base=(ret@37) off=12 */
    /* mem st32: base=(ret@37) off=12 */
    /* mem st32: base=(ret@77) off=12 */
    /* mem ld8: base=(*(?+12)) off=5 */
    /* mem ld8: base=(*(?+12)) off=0 */
    /* ... +20 more memops */
    /* site +0x37: cnx_node_search(/* no traced args */) */
    cnx_node_search(/* no traced args */);
    /* site +0x59: memcpy((?+32), (ret@37+4), 6) */
    memcpy((?+32), (ret@37+4), 6);
    /* site +0x77: wifi_event_post(15, (?+32), 10) */
    wifi_event_post(15, (?+32), 10);
    /* site +0x9f: ieee80211_psq_init(0x108, (?+32), 10) */
    ieee80211_psq_init(0x108, (?+32), 10);
    /* site +0xd1: wifi_log(1, 4, 4, lit:.rodata_wlog_debug.177, *(ret@37+12)) */
    wifi_log(1, 4, 4, lit:.rodata_wlog_debug.177, *(ret@37+12));
    /* site +0x102: wifi_log(1, 4, 4, lit:.rodata_wlog_debug.178, *(*(*(?+12)+1)+0)) */
    wifi_log(1, 4, 4, lit:.rodata_wlog_debug.178, *(*(*(?+12)+1)+0));
    return 0x105;
}

/* wifi_force_wakeup_process @ ieee80211_ioctl.o 0x00000008 size 25B bind GLOBAL
 * Calls: pm_wake_up, pm_wake_done | Data refs: none
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 wifi_force_wakeup_process(u32 a2)
{
    /* frame: entry a1,32; 9 insns, 1 cond-branches, 0 loops, 1 jumps */
    /* first predicate: beqz.n a8, 19 <wifi_force_wakeup_process+0x11> (condition opaque) */
    /* mem ld8: base=(?) off=8 */
    /* site +0x13: pm_wake_up(/* no traced args */) */
    pm_wake_up(/* no traced args */);
    /* site +0x1c: pm_wake_done(ret@13) */
    pm_wake_done(ret@13);
    return opaque_result; /* full dataflow not recovered */
}

/* wifi_update_listen_interval_process @ ieee80211_ioctl.o 0x00000004 size 14B bind GLOBAL
 * Calls: ic_update_listen_interval | Data refs: none
 * Fidelity: high - straight-line, fully mapped (5 insns) */
u32 wifi_update_listen_interval_process(u32 a2)
{
    /* frame: entry a1,32; 5 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* mem ld16: base=(?) off=12 */
    /* site +0xd: ic_update_listen_interval(*(?+12)) */
    ic_update_listen_interval(*(?+12));
    return opaque_result; /* full dataflow not recovered */
}

/* wifi_coex_pwr_process @ ieee80211_ioctl.o 0x00000004 size 22B bind GLOBAL
 * Calls: pm_coex_pwr_configure | Data refs: none
 * Fidelity: high - straight-line, fully mapped (8 insns) */
u32 wifi_coex_pwr_process(u32 a2)
{
    /* frame: entry a1,32; 8 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0, 1 */
    /* mem ld8: base=(?) off=8 */
    /* site +0x15: pm_coex_pwr_configure(1) */
    pm_coex_pwr_configure(1);
    return opaque_result; /* full dataflow not recovered */
}

/* wifi_on_coex_start_process @ ieee80211_ioctl.o 0x0000000c size 34B bind GLOBAL
 * Calls: pm_on_coex_start | Data refs: g_wifi_nvs
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 wifi_on_coex_start_process(u32 a2)
{
    /* frame: entry a1,32; 12 insns, 1 cond-branches, 0 loops, 0 jumps */
    /* immediates: 253, 0 */
    /* first predicate: bnei a8, 1, 2c <wifi_on_coex_start_process+0x20> (condition opaque) */
    /* mem ld32: base=(lit:g_wifi_nvs) off=0 */
    /* mem ld8: base=(*(g_wifi_nvs+0)) off=0 */
    /* site +0x27: pm_on_coex_start(/* no traced args */) */
    pm_on_coex_start(/* no traced args */);
    return 0;
}

/* wifi_on_coex_schm_phase_process @ ieee80211_ioctl.o 0x00000004 size 13B bind GLOBAL
 * Calls: pm_coex_schm_process | Data refs: none
 * Fidelity: high - straight-line, fully mapped (5 insns) */
u32 wifi_on_coex_schm_phase_process(void)
{
    /* frame: entry a1,32; 5 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0 */
    /* site +0xa: pm_coex_schm_process(/* no traced args */) */
    pm_coex_schm_process(/* no traced args */);
    return 0;
}

/* wifi_sample_beacon_process @ ieee80211_ioctl.o 0x00000004 size 13B bind GLOBAL
 * Calls: pm_on_sample_beacon | Data refs: none
 * Fidelity: high - straight-line, fully mapped (5 insns) */
u32 wifi_sample_beacon_process(void)
{
    /* frame: entry a1,32; 5 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0 */
    /* site +0xa: pm_on_sample_beacon(/* no traced args */) */
    pm_on_sample_beacon(/* no traced args */);
    return 0;
}

/* wifi_tbtt_quick_wake_configure_process @ ieee80211_ioctl.o 0x00000004 size 22B bind GLOBAL
 * Calls: pm_tbtt_quick_wake_configure | Data refs: none
 * Fidelity: high - straight-line, fully mapped (8 insns) */
u32 wifi_tbtt_quick_wake_configure_process(u32 a2)
{
    /* frame: entry a1,32; 8 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* immediates: 1, 0 */
    /* mem ld8: base=(?) off=8 */
    /* site +0x15: pm_tbtt_quick_wake_configure(1) */
    pm_tbtt_quick_wake_configure(1);
    return opaque_result; /* full dataflow not recovered */
}

/* wifi_mesh_ie_set_progress @ ieee80211_ioctl.o 0x00000004 size 26B bind GLOBAL
 * Calls: ieee80211_vnd_mesh_quick_set | Data refs: none
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 wifi_mesh_ie_set_progress(u32 a2)
{
    /* frame: entry a1,32; 11 insns, 2 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0x102 */
    /* first predicate: beqz.n a2, 1a <wifi_mesh_ie_set_progress+0x16> (condition opaque) */
    /* mem ld32: base=(?) off=12 */
    /* mem ld32: base=(?) off=20 */
    /* site +0x15: ieee80211_vnd_mesh_quick_set(*(?+12), *(?+20)) */
    ieee80211_vnd_mesh_quick_set(*(?+12), *(?+20));
    return last_call_result; /* opaque */
}

/* wifi_mesh_ie_get_progress @ ieee80211_ioctl.o 0x00000004 size 26B bind GLOBAL
 * Calls: ieee80211_vnd_mesh_quick_get | Data refs: none
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 wifi_mesh_ie_get_progress(u32 a2)
{
    /* frame: entry a1,32; 11 insns, 2 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0x102 */
    /* first predicate: beqz.n a2, 1a <wifi_mesh_ie_get_progress+0x16> (condition opaque) */
    /* mem ld32: base=(?) off=12 */
    /* mem ld32: base=(?) off=20 */
    /* site +0x15: ieee80211_vnd_mesh_quick_get(*(?+12), *(?+20)) */
    ieee80211_vnd_mesh_quick_get(*(?+12), *(?+20));
    return last_call_result; /* opaque */
}

/* wifi_mesh_roots_ie_set_progress @ ieee80211_ioctl.o 0x00000004 size 41B bind GLOBAL
 * Calls: ieee80211_vnd_mesh_roots_set | Data refs: none
 * Fidelity: medium - branchy but loop-free, call sequence mapped */
u32 wifi_mesh_roots_ie_set_progress(u32 a2)
{
    /* frame: entry a1,32; 17 insns, 5 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0x102 */
    /* first predicate: beqz.n a2, 29 <wifi_mesh_roots_ie_set_progress+0x25> (condition opaque) */
    /* mem ld32: base=(?) off=12 */
    /* mem ld32: base=(*(?+12)) off=0 */
    /* mem ld32: base=(*(?+12)) off=4 */
    /* mem ld8: base=(*(?+12)) off=1 */
    /* site +0x26: ieee80211_vnd_mesh_roots_set(*(*(?+12)+0), *(*(?+12)+4), *(*(?+12)+1)) */
    ieee80211_vnd_mesh_roots_set(*(*(?+12)+0), *(*(?+12)+4), *(*(?+12)+1));
    return last_call_result; /* opaque */
}

/* wifi_mesh_roots_ie_get_progress @ ieee80211_ioctl.o 0x00000004 size 41B bind GLOBAL
 * Calls: ieee80211_vnd_mesh_roots_get | Data refs: none
 * Fidelity: medium - branchy but loop-free, call sequence mapped */
u32 wifi_mesh_roots_ie_get_progress(u32 a2)
{
    /* frame: entry a1,32; 17 insns, 5 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0x102 */
    /* first predicate: beqz.n a2, 29 <wifi_mesh_roots_ie_get_progress+0x25> (condition opaque) */
    /* mem ld32: base=(?) off=12 */
    /* mem ld32: base=(*(?+12)) off=0 */
    /* mem ld32: base=(*(?+12)) off=4 */
    /* mem ld8: base=(*(?+12)) off=1 */
    /* site +0x26: ieee80211_vnd_mesh_roots_get(*(*(?+12)+0), *(*(?+12)+4), *(*(?+12)+1)) */
    ieee80211_vnd_mesh_roots_get(*(*(?+12)+0), *(*(?+12)+4), *(*(?+12)+1));
    return last_call_result; /* opaque */
}

/* wifi_mesh_ie_init_progress @ ieee80211_ioctl.o 0x00000008 size 40B bind GLOBAL
 * Calls: ieee80211_mesh_quick_init, esf_buf_setup_for_mesh | Data refs: none
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 wifi_mesh_ie_init_progress(u32 a2)
{
    /* frame: entry a1,32; 16 insns, 2 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0x102, 1, 0 */
    /* first predicate: beqz.n a2, 2c <wifi_mesh_ie_init_progress+0x24> (condition opaque) */
    /* mem ld8: base=(?) off=8 */
    /* mem ld32: base=(?) off=20 */
    /* mem ld32: base=(?) off=12 */
    /* site +0x21: ieee80211_mesh_quick_init(*(?+12), *(?+20), 1) */
    ieee80211_mesh_quick_init(*(?+12), *(?+20), 1);
    /* site +0x29: esf_buf_setup_for_mesh(ret@21, *(?+20), 1) */
    esf_buf_setup_for_mesh(ret@21, *(?+20), 1);
    return last_call_result; /* opaque */
}

/* wifi_mesh_ie_deinit_progress @ ieee80211_ioctl.o 0x00000004 size 20B bind GLOBAL
 * Calls: ieee80211_mesh_quick_deinit | Data refs: none
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 wifi_mesh_ie_deinit_progress(u32 a2)
{
    /* frame: entry a1,32; 8 insns, 1 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0x102 */
    /* first predicate: beqz.n a2, 14 <wifi_mesh_ie_deinit_progress+0x10> (condition opaque) */
    /* mem ld32: base=(?) off=12 */
    /* site +0x11: ieee80211_mesh_quick_deinit(*(?+12)) */
    ieee80211_mesh_quick_deinit(*(?+12));
    return last_call_result; /* opaque */
}

/* wifi_mesh_sta_disassoc @ ieee80211_ioctl.o 0x00000014 size 74B bind GLOBAL
 * Calls: memset, esp_wifi_get_config, memcpy, ieee80211_send_mgmt | Data refs: g_ic
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 wifi_mesh_sta_disassoc(u32 a2)
{
    /* frame: entry a1,224; 29 insns, 2 cond-branches, 0 loops, 0 jumps */
    /* immediates: -1, 184, 0, 6, 8, 160 */
    /* first predicate: beqz.n a8, 5c <wifi_mesh_sta_disassoc+0x48> (condition opaque) */
    /* mem ld32: base=(lit:g_ic) off=16 */
    /* mem ld32: base=(*(g_ic+16)) off=228 */
    /* mem ld32: base=(*(g_ic+16)) off=232 */
    /* site +0x33: memset(?, 0, 184) */
    memset(?, 0, 184);
    /* site +0x3d: esp_wifi_get_config(0, ?, 184) */
    esp_wifi_get_config(0, ?, 184);
    /* site +0x4a: memcpy((*(*(g_ic+16)+232)+4), (?+101), 6) */
    memcpy((*(*(g_ic+16)+232)+4), (?+101), 6);
    /* site +0x57: ieee80211_send_mgmt(*(*(g_ic+16)+232), 160, 8) */
    ieee80211_send_mgmt(*(*(g_ic+16)+232), 160, 8);
    return 0;
}

/* wifi_mesh_map_deauth_progress @ ieee80211_ioctl.o 0x00000000 size 8B bind GLOBAL
 * Calls: none | Data refs: none
 * Fidelity: high - straight-line, fully mapped (3 insns) */
u32 wifi_mesh_map_deauth_progress(void)
{
    /* frame: entry a1,32; 3 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0x106 */
    return 0x106;
}

/* wifi_mesh_sta_disassoc_progress @ ieee80211_ioctl.o 0x00000004 size 13B bind GLOBAL
 * Calls: wifi_mesh_sta_disassoc | Data refs: none
 * Fidelity: high - straight-line, fully mapped (5 insns) */
u32 wifi_mesh_sta_disassoc_progress(void)
{
    /* frame: entry a1,32; 5 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* site +0xa: wifi_mesh_sta_disassoc(/* no traced args */) */
    wifi_mesh_sta_disassoc(/* no traced args */);
    return last_call_result; /* opaque */
}

/* wifi_mesh_set_beacon_interval_progress @ ieee80211_ioctl.o 0x0000001c size 117B bind GLOBAL
 * Calls: wifi_nvs_get, wifi_nvs_set, wifi_nvs_commit, ic_set_beacon_int | Data refs: g_ic
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 wifi_mesh_set_beacon_interval_progress(u32 a2, u32 a4)
{
    /* frame: entry a1,32; 41 insns, 3 cond-branches, 0 loops, 1 jumps */
    /* immediates: 0x102, 100, 0, 1, 30 */
    /* first predicate: bnez.n a2, 27 <wifi_mesh_set_beacon_interval_progress+0xb> (condition opaque) */
    /* mem ld32: base=(0x102) off=12 */
    /* mem ld8: base=((lit:g_ic+131072)) off=31 */
    /* mem st16: base=((ret@2a+196608)) off=248 */
    /* mem st8: base=((lit:g_ic+131072)) off=30 */
    /* site +0x2a: wifi_nvs_get(/* no traced args */) */
    wifi_nvs_get(/* no traced args */);
    /* site +0x65: wifi_nvs_set(30, ?, 0) */
    wifi_nvs_set(30, ?, 0);
    /* site +0x6b: wifi_nvs_commit(ret@65, ?, 0) */
    wifi_nvs_commit(ret@65, ?, 0);
    /* site +0x83: ic_set_beacon_int(((ret@6b srli 5) slli 12), ?, 0) */
    ic_set_beacon_int(((ret@6b srli 5) slli 12), ?, 0);
    return opaque_result; /* full dataflow not recovered */
}

/* wifi_mesh_assoc_expire_set_progress @ ieee80211_ioctl.o 0x00000004 size 27B bind GLOBAL
 * Calls: none | Data refs: map_assoc_expire
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 wifi_mesh_assoc_expire_set_progress(u32 a2)
{
    /* frame: entry a1,32; 11 insns, 2 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0x102, 0 */
    /* first predicate: beqz.n a2, 18 <wifi_mesh_assoc_expire_set_progress+0x14> (condition opaque) */
    /* mem ld32: base=(?) off=12 */
    /* mem st32: base=(lit:map_assoc_expire) off=0 */
    return 0;
}

/* wifi_mesh_router_bssid_set_progress @ ieee80211_ioctl.o 0x00000008 size 30B bind GLOBAL
 * Calls: memcpy | Data refs: .bss.mesh_router_bssid
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 wifi_mesh_router_bssid_set_progress(u32 a2)
{
    /* frame: entry a1,32; 12 insns, 2 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0x102, 6, 0 */
    /* first predicate: beqz.n a2, 22 <wifi_mesh_router_bssid_set_progress+0x1a> (condition opaque) */
    /* mem ld32: base=(?) off=12 */
    /* site +0x1d: memcpy(lit:.bss.mesh_router_bssid, *(?+12), 6) */
    memcpy(lit:.bss.mesh_router_bssid, *(?+12), 6);
    return 0;
}

/* wifi_mesh_router_bssid_get_progress @ ieee80211_ioctl.o 0x00000008 size 30B bind GLOBAL
 * Calls: memcpy | Data refs: .bss.mesh_router_bssid
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 wifi_mesh_router_bssid_get_progress(u32 a2)
{
    /* frame: entry a1,32; 12 insns, 2 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0x102, 6, 0 */
    /* first predicate: beqz.n a2, 22 <wifi_mesh_router_bssid_get_progress+0x1a> (condition opaque) */
    /* mem ld32: base=(?) off=12 */
    /* site +0x1d: memcpy(*(?+12), lit:.bss.mesh_router_bssid, 6) */
    memcpy(*(?+12), lit:.bss.mesh_router_bssid, 6);
    return 0;
}

/* wifi_mesh_root_conflicts_set_progress @ ieee80211_ioctl.o 0x00000004 size 34B bind GLOBAL
 * Calls: none | Data refs: g_mesh_root_conflicts_allowed
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 wifi_mesh_root_conflicts_set_progress(u32 a2)
{
    /* frame: entry a1,32; 13 insns, 1 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0x102, 0, 1 */
    /* first predicate: beqz.n a8, 21 <wifi_mesh_root_conflicts_set_progress+0x1d> (condition opaque) */
    /* mem ld8: base=(?) off=8 */
    /* mem st8: base=(lit:g_mesh_root_conflicts_allowed) off=0 */
    return opaque_result; /* full dataflow not recovered */
}

/* wifi_mesh_ie_crypto_funcs_set_progress @ ieee80211_ioctl.o 0x00000008 size 44B bind GLOBAL
 * Calls: memset, mesh_set_ie_crypto_config | Data refs: none
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 wifi_mesh_ie_crypto_funcs_set_progress(u32 a2)
{
    /* frame: entry a1,80; 17 insns, 1 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0x102, 32, 0 */
    /* first predicate: beqz.n a2, 30 <wifi_mesh_ie_crypto_funcs_set_progress+0x28> (condition opaque) */
    /* mem ld32: base=(?) off=12 */
    /* mem st32: base=(?) off=32 */
    /* site +0x1d: memset(?, 0, 32) */
    memset(?, 0, 32);
    /* site +0x2b: mesh_set_ie_crypto_config(?, 0, 32) */
    mesh_set_ie_crypto_config(?, 0, 32);
    return 0;
}

/* wifi_mesh_ie_crypto_key_set_progress @ ieee80211_ioctl.o 0x0000000c size 52B bind GLOBAL
 * Calls: memset, memcpy, mesh_set_ie_crypto_config | Data refs: none
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 wifi_mesh_ie_crypto_key_set_progress(u32 a2)
{
    /* frame: entry a1,80; 21 insns, 2 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0x102, 36, 0 */
    /* first predicate: beqz.n a2, 3c <wifi_mesh_ie_crypto_key_set_progress+0x30> (condition opaque) */
    /* mem ld32: base=(?) off=12 */
    /* mem ld8: base=(?) off=10 */
    /* site +0x22: memset(?, 0, 36) */
    memset(?, 0, 36);
    /* site +0x2f: memcpy(?, *(?+12), *(?+10)) */
    memcpy(?, *(?+12), *(?+10));
    /* site +0x37: mesh_set_ie_crypto_config(?, *(?+12), *(?+10)) */
    mesh_set_ie_crypto_config(?, *(?+12), *(?+10));
    return 0;
}

/* wifi_mesh_parent_monitor_set_progress @ ieee80211_ioctl.o 0x00000004 size 22B bind GLOBAL
 * Calls: mesh_set_parent_monitor_config | Data refs: none
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 wifi_mesh_parent_monitor_set_progress(u32 a2)
{
    /* frame: entry a1,32; 9 insns, 1 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0x102, 0 */
    /* first predicate: beqz.n a2, 16 <wifi_mesh_parent_monitor_set_progress+0x12> (condition opaque) */
    /* mem ld32: base=(?) off=12 */
    /* site +0x11: mesh_set_parent_monitor_config(*(?+12)) */
    mesh_set_parent_monitor_config(*(?+12));
    return 0;
}

/* wifi_mesh_parent_monitor_get_progress @ ieee80211_ioctl.o 0x00000004 size 22B bind GLOBAL
 * Calls: mesh_get_parent_monitor_config | Data refs: none
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 wifi_mesh_parent_monitor_get_progress(u32 a2)
{
    /* frame: entry a1,32; 9 insns, 1 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0x102, 0 */
    /* first predicate: beqz.n a2, 16 <wifi_mesh_parent_monitor_get_progress+0x12> (condition opaque) */
    /* mem ld32: base=(?) off=12 */
    /* site +0x11: mesh_get_parent_monitor_config(*(?+12)) */
    mesh_get_parent_monitor_config(*(?+12));
    return 0;
}

/* wifi_mesh_parent_candidate_set_progress @ ieee80211_ioctl.o 0x00000004 size 32B bind GLOBAL
 * Calls: mesh_set_parent_candidate | Data refs: none
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 wifi_mesh_parent_candidate_set_progress(u32 a2)
{
    /* frame: entry a1,32; 14 insns, 3 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0x102, 0 */
    /* first predicate: beqz.n a2, 20 <wifi_mesh_parent_candidate_set_progress+0x1c> (condition opaque) */
    /* mem ld32: base=(?) off=12 */
    /* mem ld32: base=(?) off=20 */
    /* mem ld32: base=(*(?+20)) off=4 */
    /* mem ld32: base=(*(?+20)) off=0 */
    /* site +0x1b: mesh_set_parent_candidate(*(?+12), *(*(?+20)+0), *(*(?+20)+4)) */
    mesh_set_parent_candidate(*(?+12), *(*(?+20)+0), *(*(?+20)+4));
    return 0;
}

/* wifi_mesh_parent_candidate_clear_progress @ ieee80211_ioctl.o 0x00000004 size 13B bind GLOBAL
 * Calls: mesh_clear_parent_candidate | Data refs: none
 * Fidelity: high - straight-line, fully mapped (5 insns) */
u32 wifi_mesh_parent_candidate_clear_progress(void)
{
    /* frame: entry a1,32; 5 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0 */
    /* site +0xa: mesh_clear_parent_candidate(/* no traced args */) */
    mesh_clear_parent_candidate(/* no traced args */);
    return 0;
}

/* wifi_mesh_parent_candidate_get_progress @ ieee80211_ioctl.o 0x00000004 size 22B bind GLOBAL
 * Calls: mesh_get_parent_candidate | Data refs: none
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 wifi_mesh_parent_candidate_get_progress(u32 a2)
{
    /* frame: entry a1,32; 9 insns, 1 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0x102, 0 */
    /* first predicate: beqz.n a2, 16 <wifi_mesh_parent_candidate_get_progress+0x12> (condition opaque) */
    /* mem ld32: base=(?) off=12 */
    /* site +0x11: mesh_get_parent_candidate(*(?+12)) */
    mesh_get_parent_candidate(*(?+12));
    return 0;
}

/* wifi_mesh_rssi_threshold_set_progress @ ieee80211_ioctl.o 0x00000004 size 22B bind GLOBAL
 * Calls: mesh_set_rssi_threshold | Data refs: none
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 wifi_mesh_rssi_threshold_set_progress(u32 a2)
{
    /* frame: entry a1,32; 9 insns, 1 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0x102, 0 */
    /* first predicate: beqz.n a2, 16 <wifi_mesh_rssi_threshold_set_progress+0x12> (condition opaque) */
    /* mem ld32: base=(?) off=12 */
    /* site +0x11: mesh_set_rssi_threshold(*(?+12)) */
    mesh_set_rssi_threshold(*(?+12));
    return 0;
}

/* wifi_mesh_rssi_threshold_get_progress @ ieee80211_ioctl.o 0x00000004 size 22B bind GLOBAL
 * Calls: mesh_get_rssi_threshold | Data refs: none
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 wifi_mesh_rssi_threshold_get_progress(u32 a2)
{
    /* frame: entry a1,32; 9 insns, 1 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0x102, 0 */
    /* first predicate: beqz.n a2, 16 <wifi_mesh_rssi_threshold_get_progress+0x12> (condition opaque) */
    /* mem ld32: base=(?) off=12 */
    /* site +0x11: mesh_get_rssi_threshold(*(?+12)) */
    mesh_get_rssi_threshold(*(?+12));
    return 0;
}

/* wifi_mesh_is_roots_found_progress @ ieee80211_ioctl.o 0x00000004 size 49B bind GLOBAL
 * Calls: indirect(a8) | Data refs: esp_mesh_quick_funcs
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 wifi_mesh_is_roots_found_progress(u32 a2)
{
    /* frame: entry a1,32; 19 insns, 2 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0x102, 0, 1 */
    /* first predicate: beqz.n a2, 2e <wifi_mesh_is_roots_found_progress+0x2a> (condition opaque) */
    /* mem ld32: base=(lit:esp_mesh_quick_funcs) off=48 */
    /* mem ld32: base=(?) off=12 */
    /* mem st8: base=(*(?+12)) off=0 */
    /* site +0x19: indirect call via a8 (base *(esp_mesh_quick_funcs+48)); args: 0 */
    opaque_indirect_a8();
    return 0;
}

/* wifi_mesh_switch_channel_progress @ ieee80211_ioctl.o 0x00000004 size 52B bind GLOBAL
 * Calls: sta_rx_csa | Data refs: none
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 wifi_mesh_switch_channel_progress(u32 a2)
{
    /* frame: entry a1,48; 19 insns, 1 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0x102, 0 */
    /* first predicate: beqz.n a2, 34 <wifi_mesh_switch_channel_progress+0x30> (condition opaque) */
    /* mem ld8: base=(?) off=9 */
    /* mem st16: base=(?) off=0 */
    /* mem st8: base=(?) off=2 */
    /* mem ld8: base=(?) off=8 */
    /* mem st8: base=(?) off=4 */
    /* mem st8: base=(?) off=3 */
    /* site +0x31: sta_rx_csa(0) */
    sta_rx_csa(0);
    return last_call_result; /* opaque */
}

/* wifi_mesh_ps_duty_cycle_set_process @ ieee80211_ioctl.o 0x00000008 size 64B bind GLOBAL
 * Calls: indirect(a15) | Data refs: g_ic, esp_mesh_quick_funcs
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 wifi_mesh_ps_duty_cycle_set_process(u32 a2)
{
    /* frame: entry a1,32; 25 insns, 3 cond-branches, 0 loops, 0 jumps */
    /* immediates: -1, 0x102, 0, 1 */
    /* first predicate: beqz.n a9, 44 <wifi_mesh_ps_duty_cycle_set_process+0x3c> (condition opaque) */
    /* mem ld32: base=(lit:g_ic) off=116 */
    /* mem ld32: base=(lit:esp_mesh_quick_funcs) off=156 */
    /* mem ld8: base=(?) off=10 */
    /* mem ld8: base=(?) off=9 */
    /* mem ld8: base=(?) off=8 */
    /* mem ld32: base=(?) off=20 */
    /* mem ld32: base=(?) off=12 */
    /* site +0x41: indirect call via a15 (base *(esp_mesh_quick_funcs+156)); args: 1, 0, 0, *(?+12), *(?+20) */
    opaque_indirect_a15();
    return last_call_result; /* opaque */
}

/* wifi_mesh_ps_duty_cycle_get_process @ ieee80211_ioctl.o 0x00000008 size 37B bind GLOBAL
 * Calls: indirect(a8) | Data refs: g_ic, esp_mesh_quick_funcs
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 wifi_mesh_ps_duty_cycle_get_process(u32 a2)
{
    /* frame: entry a1,32; 15 insns, 3 cond-branches, 0 loops, 0 jumps */
    /* immediates: -1, 0x102 */
    /* first predicate: beqz.n a8, 29 <wifi_mesh_ps_duty_cycle_get_process+0x21> (condition opaque) */
    /* mem ld32: base=(lit:g_ic) off=116 */
    /* mem ld32: base=(lit:esp_mesh_quick_funcs) off=152 */
    /* mem ld32: base=(?) off=20 */
    /* mem ld32: base=(?) off=12 */
    /* site +0x26: indirect call via a8 (base *(esp_mesh_quick_funcs+152)); args: *(?+12), *(?+20) */
    opaque_indirect_a8();
    return last_call_result; /* opaque */
}

/* wifi_mesh_ps_duty_ext_get_process @ ieee80211_ioctl.o 0x00000008 size 42B bind GLOBAL
 * Calls: indirect(a9) | Data refs: g_ic, esp_mesh_quick_funcs
 * Fidelity: medium - branchy but loop-free, call sequence mapped */
u32 wifi_mesh_ps_duty_ext_get_process(u32 a2)
{
    /* frame: entry a1,32; 17 insns, 4 cond-branches, 0 loops, 0 jumps */
    /* immediates: -1, 0x102 */
    /* first predicate: beqz.n a9, 2e <wifi_mesh_ps_duty_ext_get_process+0x26> (condition opaque) */
    /* mem ld32: base=(lit:g_ic) off=116 */
    /* mem ld32: base=(lit:esp_mesh_quick_funcs) off=164 */
    /* mem ld32: base=(?) off=12 */
    /* site +0x29: indirect call via a9 (base *(esp_mesh_quick_funcs+164)); args: *(?+12) */
    opaque_indirect_a9();
    return last_call_result; /* opaque */
}

/* wifi_mesh_act_duty_signaling_process @ ieee80211_ioctl.o 0x00000008 size 42B bind GLOBAL
 * Calls: ieee80211_public_action_send_mesh_awake | Data refs: g_ic
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 wifi_mesh_act_duty_signaling_process(u32 a2)
{
    /* frame: entry a1,32; 17 insns, 3 cond-branches, 0 loops, 0 jumps */
    /* immediates: -1, 0x102, 0 */
    /* first predicate: beqz.n a10, 2e <wifi_mesh_act_duty_signaling_process+0x26> (condition opaque) */
    /* mem ld32: base=(lit:g_ic) off=116 */
    /* mem ld32: base=(lit:g_ic) off=16 */
    /* mem ld8: base=(?) off=10 */
    /* mem ld32: base=(?) off=12 */
    /* site +0x29: ieee80211_public_action_send_mesh_awake(*(?+12), *(?+10), 0) */
    ieee80211_public_action_send_mesh_awake(*(?+12), *(?+10), 0);
    return 0;
}

/* ieee80211_ioctl_init @ ieee80211_ioctl.o 0x00000018 size 39B bind GLOBAL
 * Calls: ic_register_config_cb, ic_register_timer_post_cb, ic_get_pp_hdl | Data refs: ieee80211_ioctl_process, ieee80211_timer_process, s_wifi_task_hdl
 * Fidelity: high - straight-line, fully mapped (14 insns) */
u32 ieee80211_ioctl_init(void)
{
    /* frame: entry a1,32; 14 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0 */
    /* mem st32: base=(lit:s_wifi_task_hdl) off=0 */
    /* site +0x23: ic_register_config_cb(lit:ieee80211_ioctl_process) */
    ic_register_config_cb(lit:ieee80211_ioctl_process);
    /* site +0x2c: ic_register_timer_post_cb(lit:ieee80211_timer_process) */
    ic_register_timer_post_cb(lit:ieee80211_timer_process);
    /* site +0x32: ic_get_pp_hdl(ret@2c) */
    ic_get_pp_hdl(ret@2c);
    return 0;
}

/* ieee80211_ioctl_deinit @ ieee80211_ioctl.o 0x00000004 size 15B bind GLOBAL
 * Calls: none | Data refs: s_wifi_task_hdl
 * Fidelity: high - straight-line, fully mapped (6 insns) */
u32 ieee80211_ioctl_deinit(void)
{
    /* frame: entry a1,32; 6 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0 */
    /* mem st32: base=(lit:s_wifi_task_hdl) off=0 */
    return opaque_result; /* full dataflow not recovered */
}

/* ieee80211_ioctl @ ieee80211_ioctl.o 0x00000048 size 442B bind GLOBAL
 * Calls: indirect(a3), current_task_is_wifi_task, indirect(a10), indirect(a3), wifi_log, wifi_api_lock, wifi_get_init_state, wifi_api_unlock, indirect(a3), wifi_is_stop_in_progress, wifi_api_unlock, indirect(a3), pp_post, wifi_log, wifi_api_unlock, indirect(a3), wifi_api_unlock, indirect(a8), ieee80211_ioctl_process, indirect(a4) | Data refs: g_osi_funcs_p, .rodata_wlog_warning.181, .rodata_wlog_warning.182
 * Fidelity: low - 157 insns, 19 branches, 0 loops; skeleton only */
u32 ieee80211_ioctl(u32 a2)
{
    /* frame: entry a1,32; 157 insns, 19 cond-branches, 0 loops, 9 jumps */
    /* immediates: 0x102, 121, 0, 1, 49, 2, 0x101, 6, -1 */
    /* first predicate: beqz a2, 1fe <ieee80211_ioctl+0x1b6> (condition opaque) */
    /* mem ld8: base=(?) off=0 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=176 */
    /* mem st8: base=(?) off=1 */
    /* mem ld8: base=(?) off=1 */
    /* mem st8: base=(?) off=1 */
    /* mem ld8: base=(?) off=0 */
    /* mem ld8: base=(?) off=8 */
    /* mem ld8: base=(?) off=1 */
    /* mem st8: base=(?) off=1 */
    /* ... +22 more memops */
    /* site +0x65: indirect call via a3 (base *(g_osi_funcs_p+176)); args: /* no traced args */ */
    opaque_indirect_a3();
    /* site +0x7c: current_task_is_wifi_task(ret@65) */
    current_task_is_wifi_task(ret@65);
    /* site +0xc1: indirect call via a10 (base *(*(g_osi_funcs_p+0)+68)); args: *(*(g_osi_funcs_p+0)+68) */
    opaque_indirect_a10();
    /* site +0xd2: indirect call via a3 (base *(g_osi_funcs_p+176)); args: /* no traced args */ */
    opaque_indirect_a3();
    /* site +0xe1: wifi_log(1, 2, 2, lit:.rodata_wlog_warning.181) */
    wifi_log(1, 2, 2, lit:.rodata_wlog_warning.181);
    /* site +0xf9: wifi_api_lock(ret@e1, 2, 2, lit:.rodata_wlog_warning.181) */
    wifi_api_lock(ret@e1, 2, 2, lit:.rodata_wlog_warning.181);
    /* site +0x107: wifi_get_init_state(ret@f9, 2, 2, lit:.rodata_wlog_warning.181) */
    wifi_get_init_state(ret@f9, 2, 2, lit:.rodata_wlog_warning.181);
    /* site +0x12a: wifi_api_unlock(*(?+0), (*(?+0)+-38), 2, lit:.rodata_wlog_warning.181) */
    wifi_api_unlock(*(?+0), (*(?+0)+-38), 2, lit:.rodata_wlog_warning.181);
    /* site +0x139: indirect call via a3 (base *(g_osi_funcs_p+176)); args: ret@12a, (*(?+0)+-38), 2, lit:.rodata_wlog_warning.181 */
    opaque_indirect_a3();
    /* site +0x147: wifi_is_stop_in_progress(ret@139, (*(?+0)+-38), 2, lit:.rodata_wlog_warning.181) */
    wifi_is_stop_in_progress(ret@139, (*(?+0)+-38), 2, lit:.rodata_wlog_warning.181);
    /* site +0x169: wifi_api_unlock(0, (*(?+0)+-2), 2, lit:.rodata_wlog_warning.181) */
    wifi_api_unlock(0, (*(?+0)+-2), 2, lit:.rodata_wlog_warning.181);
    /* site +0x176: indirect call via a3 (base *(g_osi_funcs_p+176)); args: ?, (*(?+0)+-2), 2, lit:.rodata_wlog_warning.181 */
    opaque_indirect_a3();
    /* site +0x187: pp_post(6, ?, 2, lit:.rodata_wlog_warning.181) */
    pp_post(6, ?, 2, lit:.rodata_wlog_warning.181);
    /* site +0x19d: wifi_log(1, ?, 2, lit:.rodata_wlog_warning.182, *(?+0)) */
    wifi_log(1, ?, 2, lit:.rodata_wlog_warning.182, *(?+0));
    /* site +0x1a3: wifi_api_unlock(ret@19d, ?, 2, lit:.rodata_wlog_warning.182, *(?+0)) */
    wifi_api_unlock(ret@19d, ?, 2, lit:.rodata_wlog_warning.182, *(?+0));
    /* site +0x1b1: indirect call via a3 (base *(g_osi_funcs_p+176)); args: ?, ?, 2, lit:.rodata_wlog_warning.182, *(?+0) */
    opaque_indirect_a3();
    /* site +0x1bf: wifi_api_unlock(ret@1b1, ?, 2, lit:.rodata_wlog_warning.182, *(?+0)) */
    wifi_api_unlock(ret@1b1, ?, 2, lit:.rodata_wlog_warning.182, *(?+0));
    /* site +0x1d9: indirect call via a8 (base *(*(g_osi_funcs_p+0)+60)); args: *(?+16), -1, 2, lit:.rodata_wlog_warning.182, *(?+0) */
    opaque_indirect_a8();
    /* site +0x1e9: ieee80211_ioctl_process(?, -1, 2, lit:.rodata_wlog_warning.182, *(?+0)) */
    ieee80211_ioctl_process(?, -1, 2, lit:.rodata_wlog_warning.182, *(?+0));
    /* site +0x1fb: indirect call via a4 (base *(g_osi_funcs_p+176)); args: ?, -1, 2, lit:.rodata_wlog_warning.182, *(?+0) */
    opaque_indirect_a4();
    return last_call_result; /* opaque */
}

/* wifi_set_dynamic_cs_process @ ieee80211_ioctl.o 0x00000024 size 122B bind GLOBAL
 * Calls: wifi_log, wifi_log, reset_cs_thres, wifi_log | Data refs: g_ic, .rodata_wlog_error.183, .rodata_wlog_info.184, .rodata_wlog_info.185, g_ic+0x200
 * Fidelity: medium - branchy but loop-free, call sequence mapped */
u32 wifi_set_dynamic_cs_process(u32 a2)
{
    /* frame: entry a1,32; 45 insns, 4 cond-branches, 0 loops, 2 jumps */
    /* immediates: 1, 2, -1, 3, 0 */
    /* first predicate: beqz a9, 3c <wifi_set_dynamic_cs_process+0x18> (condition opaque) */
    /* mem ld32: base=(lit:g_ic) off=20 */
    /* mem ld8: base=(?) off=8 */
    /* mem ld8: base=((*(g_ic+20)+65536)) off=85 */
    /* mem ld8: base=((lit:g_ic+65536)) off=239 */
    /* mem st8: base=(lit:g_ic+0x200) off=164 */
    /* mem st8: base=(lit:g_ic+0x200) off=164 */
    /* site +0x51: wifi_log(1, 2, 1, lit:.rodata_wlog_error.183) */
    wifi_log(1, 2, 1, lit:.rodata_wlog_error.183);
    /* site +0x6d: wifi_log(1, 2, 3, lit:.rodata_wlog_info.184) */
    wifi_log(1, 2, 3, lit:.rodata_wlog_info.184);
    /* site +0x81: reset_cs_thres(ret@6d, 2, 3, lit:.rodata_wlog_info.184) */
    reset_cs_thres(ret@6d, 2, 3, lit:.rodata_wlog_info.184);
    /* site +0x99: wifi_log(1, 2, 3, lit:.rodata_wlog_info.185) */
    wifi_log(1, 2, 3, lit:.rodata_wlog_info.185);
    return opaque_result; /* full dataflow not recovered */
}

/* config_is_cache_tx_buf_enabled @ ieee80211_ioctl.o 0x00000004 size 14B bind GLOBAL
 * Calls: none | Data refs: g_wifi_menuconfig
 * Fidelity: high - straight-line, fully mapped (5 insns) */
u32 config_is_cache_tx_buf_enabled(u32 a2)
{
    /* frame: entry a1,32; 5 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* mem ld32: base=(lit:g_wifi_menuconfig) off=64 */
    return opaque_result; /* full dataflow not recovered */
}

/* config_get_wifi_task_stack_size @ ieee80211_ioctl.o 0x00000004 size 11B bind GLOBAL
 * Calls: none | Data refs: g_wifi_menuconfig
 * Fidelity: high - straight-line, fully mapped (4 insns) */
u32 config_get_wifi_task_stack_size(void)
{
    /* frame: entry a1,32; 4 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* mem ld32: base=(lit:g_wifi_menuconfig) off=100 */
    return opaque_result; /* full dataflow not recovered */
}

/* wifi_softap_set_obss_overlap_process @ ieee80211_ioctl.o 0x00000008 size 61B bind GLOBAL
 * Calls: hostap_ht_operation_update | Data refs: g_ic
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 wifi_softap_set_obss_overlap_process(u32 a2, u32 a3)
{
    /* frame: entry a1,32; 22 insns, 3 cond-branches, 0 loops, 0 jumps */
    /* immediates: -1, 0, 1 */
    /* first predicate: beqz.n a10, 40 <wifi_softap_set_obss_overlap_process+0x38> (condition opaque) */
    /* mem ld32: base=(lit:g_ic) off=20 */
    /* mem ld8: base=((lit:g_ic+131072)) off=172 */
    /* mem st8: base=((*(g_ic+20)+131072)) off=77 */
    /* mem st8: base=((lit:g_ic+131072)) off=30 */
    /* site +0x32: hostap_ht_operation_update(*(g_ic+20)) */
    hostap_ht_operation_update(*(g_ic+20));
    return 0;
}

/* wifi_set_partial_ru_max_txpwr_process @ ieee80211_ioctl.o 0x00000000 size 7B bind GLOBAL
 * Calls: none | Data refs: none
 * Fidelity: high - straight-line, fully mapped (3 insns) */
u32 wifi_set_partial_ru_max_txpwr_process(void)
{
    /* frame: entry a1,32; 3 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0 */
    return 0;
}

/* wifi_get_partial_ru_max_txpwr_process @ ieee80211_ioctl.o 0x00000000 size 24B bind GLOBAL
 * Calls: none | Data refs: none
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 wifi_get_partial_ru_max_txpwr_process(u32 a2)
{
    /* frame: entry a1,32; 10 insns, 2 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0x102, 0 */
    /* first predicate: beqz.n a2, 14 <wifi_get_partial_ru_max_txpwr_process+0x14> (condition opaque) */
    /* mem ld8: base=(?) off=8 */
    /* mem ld32: base=(?) off=12 */
    return 0x102;
}
