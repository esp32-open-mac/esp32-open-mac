/* ===== if_hwctrl.o : reconstructed from libpp.a (ESP32, Xtensa, esp-2022r1) =====
 * Toolchain: xtensa-esp32-elf (GCC 11.2.0 crosstool-NG esp-2022r1).
 * ABI: args a2..a7, return a2 (all functions take a2..a7, return int32_t).
 * memw barriers preserved as MEMW(). MMIO as REG32/REG16/REG8(addr).
 * Calls with unknown arg counts are modeled with 4 live args (a2..a5);
 * a2..a7 are clobbered across calls (windowed-ABI approximation).
 * Sections: .text.bb_intr_handl, .text.esp_mesh_set_6m_rate, .text.esp_wifi_internal_free_rx_buffer, .text.ic_add_rx_ba, .text.ic_ampdu_op, .text.ic_bb_check_noise_init, .text.ic_beacon_monitor_configure, .text.ic_beacon_offset_configure, .text.ic_beacon_offset_set_rx_beacon_standard, .text.ic_clear_data_ifx_tx_queue, .text.ic_clear_interrupt_handler, .text.ic_create_wifi_task, .text.ic_csi_set_config, .text.ic_deinit, .text.ic_del_key, .text.ic_del_key_all, .text.ic_del_ptk_and_gtk_alg, .text.ic_del_rx_ba, .text.ic_delete_wifi_task, .text.ic_disable_crypto, .text.ic_disable_rx, .text.ic_disable_sniffer, .text.ic_ebuf_alloc, .text.ic_ebuf_recycle_rx, .text.ic_ebuf_recycle_tx, .text.ic_enable_rx, .text.ic_enable_sniffer, .text.ic_get_80211_tx_rate, .text.ic_get_80211_tx_rate_config, .text.ic_get_G6M_sched, .text.ic_get_addr, .text.ic_get_default_sched, .text.ic_get_espnow_rate, .text.ic_get_fix_rate, .text.ic_get_keep_alive_time, .text.ic_get_key, .text.ic_get_next_bcnoffset, .text.ic_get_next_tbtt, .text.ic_get_pp_hdl, .text.ic_get_promis_ctrl_filter, .text.ic_get_promis_filter, .text.ic_get_ptk_alg, .text.ic_get_random, .text.ic_get_rssi, .text.ic_get_trc, .text.ic_init, .text.ic_is_mgmt_hwdecr_enabled, .text.ic_is_pure_sta, .text.ic_obtain_key, .text.ic_pp_post, .text.ic_register_config_cb, .text.ic_register_csi_rx_cb, .text.ic_register_ftm_callbacks, .text.ic_register_michael_mic_failure_cb, .text.ic_register_nan_callbacks, .text.ic_register_net80211_tx_cb, .text.ic_register_pm_tx_null_cb, .text.ic_register_pp_tx_done_cb, .text.ic_register_promis_rx_cb, .text.ic_register_rx_cb, .text.ic_register_timer_cb, .text.ic_register_timer_post_cb, .text.ic_register_tx_cb, .text.ic_reset_rx_ba, .text.ic_reset_tbtt, .text.ic_rx_disable_bssid_check, .text.ic_rx_enable_bssid_check, .text.ic_set_80211_tx_rate, .text.ic_set_80211_tx_rate_config, .text.ic_set_ac_param, .text.ic_set_bar_rate, .text.ic_set_beacon_int, .text.ic_set_bssid, .text.ic_set_csi, .text.ic_set_current_channel, .text.ic_set_fix_rate, .text.ic_set_interface, .text.ic_set_interrupt_handler, .text.ic_set_keep_alive_time, .text.ic_set_key, .text.ic_set_mac, .text.ic_set_promis_ctrl_filter, .text.ic_set_promis_filter, .text.ic_set_rx_policy, .text.ic_set_rx_policy_ubssid_check, .text.ic_set_sleep_min_active_time, .text.ic_set_sleep_wait_broadcast_data_time, .text.ic_set_trc, .text.ic_set_vif, .text.ic_stop_hw_txq, .text.ic_stop_sw_txq, .text.ic_trc_set_per_pkt_rate, .text.ic_trc_update_def_rate, .text.ic_trc_update_ifx_phy_mode, .text.ic_tx_is_idle, .text.ic_tx_pkt, .text.ic_txq_empty, .text.ic_update_light_sleep_default_params, .text.ic_update_listen_interval, .text.ic_update_modem_sleep_default_params, .text.ic_update_trc_params, .wifislprxiram.13, .wifislprxiram.14, .wifislprxiram.2
 * Undefined refs (117): esf_buf_alloc, esf_buf_recycle, esp_wifi_internal_on_coex_schm_phase, esp_wifi_internal_on_coex_start, g_mesh_is_root, g_mesh_is_started, g_osi_funcs_p, g_wifi_menuconfig, hal_agreement_add_rx_ba, hal_agreement_clr_rx_ba, hal_agreement_del_rx_ba, hal_crypto_get_key_entry, hal_crypto_is_key_valid, hal_deinit, hal_init, hal_mac_deinit, hal_mac_init, hal_mac_rx_set_policy, hal_mac_set_addr, hal_mac_set_bssid, hal_mac_set_csi, hal_mac_set_rxq_policy, hal_random, hal_rx_disable_bssid_check...
 */
#include <stdint.h>
#define REG32(a) (*(volatile uint32_t *)(a))
#define REG16(a) (*(volatile uint16_t *)(a))
#define REG8(a)  (*(volatile uint8_t *)(a))
#define MEM32(a) (*(volatile uint32_t *)(a))
#define MEM16(a) (*(volatile uint16_t *)(a))
#define MEM8(a)  (*(volatile uint8_t *)(a))
#define MEMW() __asm__ volatile("memw" ::: "memory")

extern int32_t if_ctrl();
extern uint32_t wDevCtrl; /* wDevCtrl */
extern int32_t wDev_Crypto_Disable();
extern int32_t g_osi_funcs_p();
extern int32_t wDev_Insert_KeyEntry();
extern int32_t memset();
extern int32_t hal_crypto_get_key_entry();
extern int32_t memcpy();
extern int32_t hal_crypto_is_key_valid();
extern int32_t memcmp();
extern int32_t rc_get_trc();
extern int32_t ppTxPkt();
extern int32_t esf_buf_alloc();
extern int32_t ppClearAlldataTxq_ifx();
extern int32_t esf_buf_recycle();
extern int32_t ppRecycleRxPkt();
extern int32_t ppRegisterTxCallback();
extern int32_t ppRegisterRxCallback();
extern int32_t pp_timer_register_post_cb();
extern int32_t pp_register_michael_mic_failure_cb();
extern int32_t ppRegisterTxDoneUserActionCallback();
extern int32_t wdev_set_promis_filter();
extern int32_t wdev_get_promis_filter();
extern int32_t wdev_set_promis_ctrl_filter();
extern int32_t wdev_get_promis_ctrl_filter();
extern int32_t ppRegisterPromisRxCallback();
extern int32_t wdev_set_csi_rx_cb();
extern int32_t pp_register_config_cb();
extern int32_t wdev_is_mgmt_hwdecr_enabled();
extern int32_t pm_register_pm_tx_null_cb();
extern int32_t pp_register_net80211_tx_cb();
extern int32_t pp_register_timer_cb();
extern int32_t wdev_nan_set_callbacks();
extern int32_t pp_post();
extern int32_t wdev_set_promis();
extern uint32_t rodata_wlog_debug_3; /* .rodata_wlog_debug.3 */
extern int32_t wifi_log();
extern uint32_t rodata_wlog_debug_4; /* .rodata_wlog_debug.4 */
extern int32_t wifi_set_rx_policy();
extern uint32_t rodata_wlog_debug_5; /* .rodata_wlog_debug.5 */
extern int32_t rc_disable_trc_by_interface();
extern int32_t pm_force_scan_unlock();
extern uint32_t rodata_wlog_debug_6; /* .rodata_wlog_debug.6 */
extern uint32_t rodata_wlog_debug_7; /* .rodata_wlog_debug.7 */
extern uint32_t rodata_wlog_debug_8; /* .rodata_wlog_debug.8 */
extern uint32_t rodata_wlog_error_9; /* .rodata_wlog_error.9 */
extern int32_t wDev_Get_Next_TBTT();
extern int32_t wDev_Get_Next_BcnOffset();
extern int32_t hal_agreement_del_rx_ba();
extern int32_t hal_agreement_clr_rx_ba();
extern int32_t hal_agreement_add_rx_ba();
extern int32_t wDev_Reset_TBTT();
extern int32_t wDev_remove_KeyEntry_all_cnx();
extern int32_t wDev_remove_KeyEntry();
extern int32_t lmacSetAcParam();
extern int32_t rc_get_trc_by_index();
extern int32_t trc_onAmpduOp();
uint32_t s_is_6m; /* defined here (.bss/.data); was: s_is_6m */
extern int32_t rc_enable_trc();
extern uint32_t g_mesh_is_started; /* g_mesh_is_started */
extern uint32_t g_mesh_is_root; /* g_mesh_is_root */
extern int32_t rcUpdateAMPDUParam();
extern int32_t rcUpdatePhyMode();
extern int32_t rc_disable_trc();
extern uint32_t rodata_wlog_info_10; /* .rodata_wlog_info.10 */
extern int32_t pm_deattach();
extern int32_t wDev_Rxbuf_Deinit();
extern int32_t pp_deattach();
extern int32_t trc_deinit();
extern int32_t trc_init();
extern int32_t lmacInit();
extern int32_t pp_attach();
extern int32_t wDev_Rxbuf_Init();
extern int32_t pm_attach();
extern int32_t esp_wifi_internal_on_coex_start();
extern int32_t esp_wifi_internal_on_coex_schm_phase();
extern uint32_t g_wifi_menuconfig; /* g_wifi_menuconfig */
extern int32_t pm_enable_sta_disconnected_power_management();
extern int32_t hal_init();
extern uint32_t wDev_ProcessFiq; /* wDev_ProcessFiq */
extern int32_t hal_deinit();
extern int32_t wDev_Set_Beacon_Int();
extern uint32_t rodata_wlog_error_11; /* .rodata_wlog_error.11 */
extern int32_t hal_mac_set_addr();
extern int32_t hal_mac_set_bssid();
extern int32_t wDev_SetCurChannel();
extern int32_t hal_random();
extern int32_t lmacIsIdle();
extern int32_t ppGetTaskHdl();
extern int32_t hal_mac_set_rxq_policy();
extern int32_t hal_mac_rx_set_policy();
extern int32_t ppSetInterface();
extern int32_t trc_set_per_pkt_rate();
extern int32_t trc_update_ifx_phy_mode();
extern int32_t lmac_stop_hw_txq();
extern uint32_t rodata_wlog_info_12; /* .rodata_wlog_info.12 */
extern int32_t pp_stop_sw_txq();
extern int32_t ppTxqEmpty();
extern int32_t rc_set_fix_rate();
extern int32_t rc_get_fix_rate();
extern int32_t pp_create_task();
extern int32_t pp_delete_task();
extern int32_t hal_mac_set_csi();
extern int32_t hal_mac_init();
extern int32_t hal_mac_deinit();
extern int32_t phy_chan_dump_cfg();
extern int32_t phy_chan_filt_set();
extern int32_t pm_update_modem_sleep_default_params();
extern int32_t pm_update_light_sleep_default_params();
extern int32_t pm_set_sleep_min_active_time();
extern int32_t pm_set_keep_alive_time();
extern int32_t pm_get_keep_alive_time();
extern int32_t pm_set_sleep_wait_broadcast_data_time();
extern int32_t pm_beacon_monitor_configure();
extern int32_t ptr_beacon_offset_funcs();
extern int32_t wifi_nvs_set_sta_listen_interval();
extern int32_t pm_is_open();
extern int32_t pm_scale_listen_interval();
extern int32_t hal_rx_disable_bssid_check();
extern int32_t hal_rx_enable_bssid_check();
extern int32_t ppSetBarRate();
extern int32_t trc_update_def_rate();
extern int32_t trc_get_espnow_rate();
extern int32_t trc_get_80211_tx_rate();
extern int32_t trc_get_80211_tx_rate_config();
extern int32_t trc_set_80211_tx_rate();
extern int32_t trc_set_80211_tx_rate_config();
extern int32_t rc_get_default_sched();
extern int32_t rc_get_G6M_sched();

/* pool[bb_intr_handl]: +0x0=0x3FF5D04C */
/* pool[ic_get_addr]: +0x0=0x00000000(if_ctrl) */
/* pool[ic_interface_enabled]: +0x0=0x00000000(wDevCtrl) */
/* pool[ic_is_pure_sta]: +0x0=0x00000000(if_ctrl) */
/* pool[ic_get_ptk_alg]: +0x0=0x00000000(if_ctrl) */
/* pool[ic_disable_crypto]: +0x0=0x00000000(if_ctrl), +0x4=0x00000000(wDev_Crypto_Disable) */
/* pool[ic_del_ptk_and_gtk_alg]: +0x0=0x00000000(if_ctrl) */
/* pool[ic_set_key]: +0x0=0x00000000(if_ctrl), +0x4=0x00000000(g_osi_funcs_p), +0x8=0x00000000(wDev_Insert_KeyEntry) */
/* pool[ic_get_key]: +0x0=0x00000000(memset), +0x4=0x00000000(hal_crypto_get_key_entry), +0x8=0x00000000(memcpy) */
/* pool[ic_obtain_key]: +0x0=0x00000000(hal_crypto_is_key_valid), +0x4=0x00000000(ic_get_key), +0x8=0x00000000(memcmp) */
/* pool[ic_get_rssi]: +0x4=0x00000000(rc_get_trc), +0x0=0x00000000(wDevCtrl) */
/* pool[ic_tx_pkt]: +0x0=0x00000000(ppTxPkt) */
/* pool[ic_ebuf_alloc]: +0x0=0x00000000(esf_buf_alloc) */
/* pool[ic_clear_data_ifx_tx_queue]: +0x0=0x00000000(ppClearAlldataTxq_ifx) */
/* pool[ic_ebuf_recycle_tx]: +0x0=0x00000000(esf_buf_recycle) */
/* pool[ic_ebuf_recycle_rx]: +0x0=0x00000000(ppRecycleRxPkt) */
/* pool[esp_wifi_internal_free_rx_buffer]: +0x0=0x00000000(ppRecycleRxPkt) */
/* pool[ic_register_tx_cb]: +0x0=0x00000000(ppRegisterTxCallback) */
/* pool[ic_register_rx_cb]: +0x0=0x00000000(ppRegisterRxCallback) */
/* pool[ic_register_timer_post_cb]: +0x0=0x00000000(pp_timer_register_post_cb) */
/* pool[ic_register_michael_mic_failure_cb]: +0x0=0x00000000(pp_register_michael_mic_failure_cb) */
/* pool[ic_register_pp_tx_done_cb]: +0x0=0x00000000(ppRegisterTxDoneUserActionCallback) */
/* pool[ic_set_promis_filter]: +0x0=0x00000000(wdev_set_promis_filter) */
/* pool[ic_get_promis_filter]: +0x0=0x00000000(wdev_get_promis_filter) */
/* pool[ic_set_promis_ctrl_filter]: +0x0=0x00000000(wdev_set_promis_ctrl_filter) */
/* pool[ic_get_promis_ctrl_filter]: +0x0=0x00000000(wdev_get_promis_ctrl_filter) */
/* pool[ic_register_promis_rx_cb]: +0x0=0x00000000(ppRegisterPromisRxCallback) */
/* pool[ic_register_csi_rx_cb]: +0x0=0x00000000(wdev_set_csi_rx_cb) */
/* pool[ic_register_config_cb]: +0x0=0x00000000(pp_register_config_cb) */
/* pool[ic_is_mgmt_hwdecr_enabled]: +0x0=0x00000000(wdev_is_mgmt_hwdecr_enabled) */
/* pool[ic_register_pm_tx_null_cb]: +0x0=0x00000000(pm_register_pm_tx_null_cb) */
/* pool[ic_register_net80211_tx_cb]: +0x0=0x00000000(pp_register_net80211_tx_cb) */
/* pool[ic_register_timer_cb]: +0x0=0x00000000(pp_register_timer_cb) */
/* pool[ic_register_nan_callbacks]: +0x0=0x00000000(wdev_nan_set_callbacks) */
/* pool[ic_pp_post]: +0x0=0x00000000(pp_post) */
/* pool[ic_enable_sniffer]: +0x0=0x00000000(wdev_set_promis) */
/* pool[ic_disable_sniffer]: +0x0=0x00000000(wdev_set_promis) */
/* pool[ic_set_vif]: +0x0=0x00000000(if_ctrl), +0x4=0x00000000(.rodata_wlog_debug.3), +0x2c=0x00000000(wifi_log), +0x8=0x00000000(.rodata_wlog_debug.4), +0x30=0x00000000(wifi_log), +0x34=0x00000000(wifi_set_rx_policy), +0xc=0x00000000(.rodata_wlog_debug.5), +0x38=0x00000000(wifi_log), +0x3c=0x00000000(ic_enable_sniffer), +0x40=0x00000000(memcpy), +0x10=0x00000000(wDevCtrl), +0x14=0x3FF73084, +0x44=0x00000000(ic_disable_crypto), +0x48=0x00000000(rc_disable_trc_by_interface), +0x18=0x7FFFFFFF, +0x4c=0x00000000(pm_force_scan_unlock), +0x1c=0x00000000(.rodata_wlog_debug.6), +0x50=0x00000000(wifi_log), +0x20=0x00000000(.rodata_wlog_debug.7), +0x54=0x00000000(wifi_log), +0x24=0x00000000(.rodata_wlog_debug.8), +0x58=0x00000000(wifi_log), +0x5c=0x00000000(wifi_set_rx_policy), +0x60=0x00000000(ic_disable_sniffer), +0x28=0x00000000(.rodata_wlog_error.9), +0x64=0x00000000(wifi_log) */
/* pool[ic_get_next_tbtt]: +0x0=0x00000000(wDev_Get_Next_TBTT) */
/* pool[ic_get_next_bcnoffset]: +0x0=0x00000000(wDev_Get_Next_BcnOffset) */
/* pool[ic_del_rx_ba]: +0x0=0x00000000(hal_agreement_del_rx_ba) */
/* pool[ic_reset_rx_ba]: +0x0=0x00000000(hal_agreement_clr_rx_ba) */
/* pool[ic_add_rx_ba]: +0x0=0x00000000(hal_agreement_add_rx_ba) */
/* pool[ic_reset_tbtt]: +0x0=0x00000000(wDev_Reset_TBTT) */
/* pool[ic_del_key_all]: +0x0=0x00000000(wDev_remove_KeyEntry_all_cnx) */
/* pool[ic_del_key]: +0x0=0x00000000(g_osi_funcs_p), +0x4=0x00000000(wDev_remove_KeyEntry) */
/* pool[ic_set_ac_param]: +0x0=0x00000000(lmacSetAcParam) */
/* pool[ic_ampdu_op]: +0x0=0x00000000(rc_get_trc_by_index), +0x4=0x00000000(trc_onAmpduOp) */
/* pool[esp_mesh_set_6m_rate]: +0x0=0x00000000(s_is_6m) */
/* pool[ic_set_trc]: +0x10=0x00000000(rc_enable_trc), +0x0=0x00000000(if_ctrl), +0x4=0x00000000(g_mesh_is_started), +0x8=0x00000000(s_is_6m), +0xc=0x00000000(g_mesh_is_root), +0x14=0x00000000(rcUpdateAMPDUParam), +0x18=0x00000000(rcUpdatePhyMode), +0x1c=0x00000000(rc_disable_trc) */
/* pool[ic_bb_check_noise_init]: +0x0=0x00000000(.rodata_wlog_info.10), +0xc=0x00000000(wifi_log), +0x8=0x00000000(g_osi_funcs_p), +0x4=0x00000000(bb_intr_handl) */
/* pool[ic_deinit]: +0x0=0x00000000(pm_deattach), +0x4=0x00000000(wDev_Rxbuf_Deinit), +0x8=0x00000000(pp_deattach), +0xc=0x00000000(trc_deinit) */
/* pool[ic_init]: +0x10=0x00000000(trc_init), +0x14=0x00000000(lmacInit), +0x18=0x00000000(pp_attach), +0x1c=0x00000000(wDev_Rxbuf_Init), +0x20=0x00000000(pm_attach), +0x4=0x00000000(g_osi_funcs_p), +0x0=0x00000000(esp_wifi_internal_on_coex_start), +0x8=0x00000000(esp_wifi_internal_on_coex_schm_phase), +0xc=0x00000000(g_wifi_menuconfig), +0x24=0x00000000(pm_enable_sta_disconnected_power_management), +0x28=0x00000000(ic_deinit) */
/* pool[ic_set_interrupt_handler]: +0xc=0x00000000(hal_init), +0x4=0x00000000(g_osi_funcs_p), +0x0=0x00000000(g_wifi_menuconfig), +0x8=0x00000000(wDev_ProcessFiq) */
/* pool[ic_clear_interrupt_handler]: +0x0=0x00000000(g_osi_funcs_p), +0x4=0x00000000(hal_deinit) */
/* pool[ic_enable_rx]: +0x0=0x3FF73084 */
/* pool[ic_disable_rx]: +0x0=0x3FF73084, +0x4=0x7FFFFFFF */
/* pool[ic_set_beacon_int]: +0x0=0x00000000(wDev_Set_Beacon_Int) */
/* pool[ic_set_mac]: +0x0=0x00000000(.rodata_wlog_error.11), +0x8=0x00000000(wifi_log), +0xc=0x00000000(hal_mac_set_addr), +0x4=0x00000000(if_ctrl), +0x10=0x00000000(memcpy) */
/* pool[ic_set_bssid]: +0x0=0x00000000(hal_mac_set_bssid) */
/* pool[ic_set_current_channel]: +0x0=0x00000000(wDev_SetCurChannel) */
/* pool[ic_get_random]: +0x0=0x00000000(hal_random) */
/* pool[ic_get_trc]: +0x0=0x00000000(rc_get_trc_by_index) */
/* pool[ic_tx_is_idle]: +0x0=0x00000000(lmacIsIdle) */
/* pool[ic_get_pp_hdl]: +0x0=0x00000000(ppGetTaskHdl) */
/* pool[ic_set_rx_policy_ubssid_check]: +0x0=0x00000000(hal_mac_set_rxq_policy) */
/* pool[ic_set_rx_policy]: +0x0=0x00000000(hal_mac_rx_set_policy) */
/* pool[ic_set_interface]: +0x0=0x00000000(ppSetInterface) */
/* pool[ic_trc_set_per_pkt_rate]: +0x0=0x00000000(trc_set_per_pkt_rate) */
/* pool[ic_trc_update_ifx_phy_mode]: +0x0=0x00000000(trc_update_ifx_phy_mode) */
/* pool[ic_update_trc_params]: +0x0=0x00000000(rc_get_trc_by_index), +0x4=0x00000000(rcUpdateAMPDUParam) */
/* pool[ic_stop_hw_txq]: +0x0=0x00000000(lmac_stop_hw_txq) */
/* pool[ic_stop_sw_txq]: +0x0=0x00000000(.rodata_wlog_info.12), +0x4=0x00000000(wifi_log), +0x8=0x00000000(pp_stop_sw_txq) */
/* pool[ic_txq_empty]: +0x0=0x00000000(ppTxqEmpty) */
/* pool[ic_set_fix_rate]: +0x0=0x00000000(rc_set_fix_rate) */
/* pool[ic_get_fix_rate]: +0x0=0x00000000(rc_get_fix_rate) */
/* pool[ic_create_wifi_task]: +0x0=0x00000000(pp_create_task) */
/* pool[ic_delete_wifi_task]: +0x0=0x00000000(pp_delete_task) */
/* pool[ic_set_csi]: +0x0=0x00000000(hal_mac_set_csi) */
/* pool[ic_mac_init]: +0x0=0x00000000(hal_mac_init) */
/* pool[ic_mac_deinit]: +0x0=0x00000000(hal_mac_deinit) */
/* pool[ic_csi_set_config]: +0xc=0x00000000(phy_chan_dump_cfg), +0x10=0x00000000(phy_chan_filt_set), +0x0=0x3FF730F8, +0x4=0x3FF730FC, +0x8=0xDFFFFFFF */
/* pool[ic_update_modem_sleep_default_params]: +0x0=0x00000000(pm_update_modem_sleep_default_params) */
/* pool[ic_update_light_sleep_default_params]: +0x0=0x00000000(pm_update_light_sleep_default_params) */
/* pool[ic_set_sleep_min_active_time]: +0x0=0x00000000(pm_set_sleep_min_active_time) */
/* pool[ic_set_keep_alive_time]: +0x0=0x00000000(pm_set_keep_alive_time) */
/* pool[ic_get_keep_alive_time]: +0x0=0x00000000(pm_get_keep_alive_time) */
/* pool[ic_set_sleep_wait_broadcast_data_time]: +0x0=0x00000000(pm_set_sleep_wait_broadcast_data_time) */
/* pool[ic_beacon_monitor_configure]: +0x0=0x00000000(pm_beacon_monitor_configure) */
/* pool[ic_beacon_offset_configure]: +0x0=0x00000000(ptr_beacon_offset_funcs) */
/* pool[ic_beacon_offset_set_rx_beacon_standard]: +0x0=0x00000000(ptr_beacon_offset_funcs) */
/* pool[ic_update_listen_interval]: +0x0=0x00000000(wifi_nvs_set_sta_listen_interval), +0x4=0x00000000(pm_is_open), +0x8=0x00000000(pm_scale_listen_interval) */
/* pool[ic_rx_disable_bssid_check]: +0x0=0x00000000(hal_rx_disable_bssid_check) */
/* pool[ic_rx_enable_bssid_check]: +0x0=0x00000000(hal_rx_enable_bssid_check) */
/* pool[ic_set_bar_rate]: +0x0=0x00000000(ppSetBarRate) */
/* pool[ic_trc_update_def_rate]: +0x0=0x00000000(trc_update_def_rate) */
/* pool[ic_get_espnow_rate]: +0x0=0x00000000(trc_get_espnow_rate) */
/* pool[ic_get_80211_tx_rate]: +0x0=0x00000000(trc_get_80211_tx_rate) */
/* pool[ic_get_80211_tx_rate_config]: +0x0=0x00000000(trc_get_80211_tx_rate_config) */
/* pool[ic_set_80211_tx_rate]: +0x0=0x00000000(trc_set_80211_tx_rate) */
/* pool[ic_set_80211_tx_rate_config]: +0x0=0x00000000(trc_set_80211_tx_rate_config) */
/* pool[ic_get_default_sched]: +0x0=0x00000000(rc_get_default_sched) */
/* pool[ic_get_G6M_sched]: +0x0=0x00000000(rc_get_G6M_sched) */

/* bb_intr_handl @ if_hwctrl.o 00000004 size 13B bind GLOBAL
 * Calls: none | Data refs: none
 *   MMIO: 0x3FF5D04C
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t bb_intr_handl(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.bb_intr_handl; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a8 = 0x3FF5D04C; /* 0007: l32r a8, 0 <bb_intr_handl-0x4> (3ff5d04c <ic_set_vif+0x3ff5cfe4>) */ /* MMIO base */ @0x0
  MEMW(); /* 000a: memw  */
  a8 = REG32(0x3FF5D04C); /* 000d: l32i.n a8, a8, 0 */ /* MMIO read: base 0x3FF5D04C+0 */
  return (int32_t)a2; /* 000f: retw.n  */
}

/* ic_get_addr @ if_hwctrl.o 00000004 size 17B bind GLOBAL
 * Calls: none | Data refs: if_ctrl
 *   MMIO: none
 *   funcdb v3: 0 call(s), 1 ref(s); disasm: 0 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t ic_get_addr(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.ic_get_addr; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a8 = (uint32_t)&if_ctrl; /* 0007: l32r a8, 0 <ic_get_addr-0x4> (0 <ic_get_addr-0x4>) */ /* literal @0x0: if_ctrl */
  a2 = (a2 >> 0) & 0xFF; /* 000a: extui a2, a2, 0, 8 */
  a2 = (a2 << 4) + a2; /* 000d: addx4 a2, a2, a2 */
  a2 = (a2 << 2) + a8; /* 0010: addx2 a2, a2, a8 */
  return (int32_t)a2; /* 0013: retw.n  */
}

/* ic_interface_enabled @ if_hwctrl.o 00000004 size 20B bind GLOBAL
 * Calls: none | Data refs: wDevCtrl
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t ic_interface_enabled(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .wifislprxiram.2; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a8 = (uint32_t)&wDevCtrl; /* 0007: l32r a8, 0 <ic_interface_enabled-0x4> (0 <ic_interface_enabled-0x4>) */ /* literal @0x0: wDevCtrl */
  a8 = MEM8(a8 + 49); /* 000a: l8ui a8, a8, 49 */
  /* 000d: ssr a2 */ /* UNMODELED: a2 clobbered */
  /* 0010: srl a2, a8 */ /* UNMODELED: a2 clobbered */
  a2 = (a2 >> 0) & 0x1; /* 0013: extui a2, a2, 0, 1 */
  return (int32_t)a2; /* 0016: retw.n  */
}

/* ic_is_pure_sta @ if_hwctrl.o 00000004 size 41B bind GLOBAL
 * Calls: none | Data refs: if_ctrl
 *   MMIO: none
 *   funcdb v3: 0 call(s), 1 ref(s); disasm: 0 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t ic_is_pure_sta(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.ic_is_pure_sta; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a8 = (uint32_t)&if_ctrl; /* 0007: l32r a8, 0 <ic_is_pure_sta-0x4> (0 <ic_is_pure_sta-0x4>) */ /* literal @0x0: if_ctrl */
  a2 = (a2 >> 0) & 0xFF; /* 000a: extui a2, a2, 0, 8 */
  a2 = (a2 << 4) + a2; /* 000d: addx4 a2, a2, a2 */
  a8 = (a2 << 2) + a8; /* 0010: addx2 a8, a2, a8 */
  a2 = 0x0; /* 0013: movi a2, 0 */
  a9 = MEM8(a8 + 6); /* 0016: l8ui a9, a8, 6 */
  if (a9 == 1) goto L_28; /* 0019: beqi a9, 1, 28 <ic_is_pure_sta+0x24> */
  a2 = MEM8(a8 + 7); /* 001c: l8ui a2, a8, 7 */
  a8 = 0x1; /* 001f: movi a8, 1 */
  a2 = a2 ^ a8; /* 0022: xor a2, a2, a8 */
  a2 = (a2 >> 0) & 0xFF; /* 0025: extui a2, a2, 0, 8 */
L_28:;
  a2 = (a2 >> 0) & 0x1; /* 0028: extui a2, a2, 0, 1 */
  return (int32_t)a2; /* 002b: retw.n  */
}

/* ic_get_ptk_alg @ if_hwctrl.o 00000004 size 20B bind GLOBAL
 * Calls: none | Data refs: if_ctrl
 *   MMIO: none
 *   funcdb v3: 0 call(s), 1 ref(s); disasm: 0 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t ic_get_ptk_alg(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.ic_get_ptk_alg; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a8 = (uint32_t)&if_ctrl; /* 0007: l32r a8, 0 <ic_get_ptk_alg-0x4> (0 <ic_get_ptk_alg-0x4>) */ /* literal @0x0: if_ctrl */
  a2 = (a2 >> 0) & 0xFF; /* 000a: extui a2, a2, 0, 8 */
  a2 = (a2 << 4) + a2; /* 000d: addx4 a2, a2, a2 */
  a2 = (a2 << 2) + a8; /* 0010: addx2 a2, a2, a8 */
  a2 = MEM8(a2 + 8); /* 0013: l8ui a2, a2, 8 */
  return (int32_t)a2; /* 0016: retw.n  */
}

/* ic_disable_crypto @ if_hwctrl.o 00000008 size 40B bind GLOBAL
 * Calls: wDev_Crypto_Disable | Data refs: if_ctrl, wDev_Crypto_Disable
 *   MMIO: none
 *   funcdb v3: 1 call(s), 2 ref(s); disasm: 1 call(s), 2 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t ic_disable_crypto(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.ic_disable_crypto; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_8:;
  /* 0008: entry a1, 32 */
  a3 = (a3 >> 0) & 0xFF; /* 000b: extui a3, a3, 0, 8 */
  a10 = (a2 >> 0) & 0xFF; /* 000e: extui a10, a2, 0, 8 */
  if (a3 != 0) goto L_2e; /* 0011: bnez.n a3, 2e <ic_disable_crypto+0x26> */
  a9 = (uint32_t)&if_ctrl; /* 0013: l32r a9, 0 <ic_disable_crypto-0x8> (0 <ic_disable_crypto-0x8>) */ /* literal @0x0: if_ctrl */
  a8 = (a10 << 4) + a10; /* 0016: addx4 a8, a10, a10 */
  a8 = (a8 << 2) + a9; /* 0019: addx2 a8, a8, a9 */
  MEM8(a8 + 8) = a3; /* 001c: s8i a3, a8, 8 */
  MEM8(a8 + 9) = a3; /* 001f: s8i a3, a8, 9 */
  MEMW(); /* 0022: memw  */
  MEMW(); /* 0025: memw  */
  a8 = (uint32_t)&wDev_Crypto_Disable; /* 0028: l32r a8, 4 <ic_disable_crypto-0x4> (0 <ic_disable_crypto-0x8>) */ /* literal: GOT slot for wDev_Crypto_Disable */
  wDev_Crypto_Disable(a2, a3, a4, a5); /* call via literal slot */ /* 002b: callx8 a8 */
L_2e:;
  return (int32_t)a2; /* 002e: retw.n  */
}

/* ic_del_ptk_and_gtk_alg @ if_hwctrl.o 00000004 size 31B bind GLOBAL
 * Calls: none | Data refs: if_ctrl
 *   MMIO: none
 *   funcdb v3: 0 call(s), 1 ref(s); disasm: 0 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t ic_del_ptk_and_gtk_alg(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.ic_del_ptk_and_gtk_alg; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a8 = (uint32_t)&if_ctrl; /* 0007: l32r a8, 0 <ic_del_ptk_and_gtk_alg-0x4> (0 <ic_del_ptk_and_gtk_alg-0x4>) */ /* literal @0x0: if_ctrl */
  a2 = (a2 >> 0) & 0xFF; /* 000a: extui a2, a2, 0, 8 */
  a2 = (a2 << 4) + a2; /* 000d: addx4 a2, a2, a2 */
  a2 = (a2 << 2) + a8; /* 0010: addx2 a2, a2, a8 */
  a8 = 0x0; /* 0013: movi.n a8, 0 */
  MEM8(a2 + 8) = a8; /* 0015: s8i a8, a2, 8 */
  MEM8(a2 + 9) = a8; /* 0018: s8i a8, a2, 9 */
  MEMW(); /* 001b: memw  */
  MEMW(); /* 001e: memw  */
  return (int32_t)a2; /* 0021: retw.n  */
}

/* ic_set_key @ if_hwctrl.o 0000000c size 128B bind GLOBAL
 * Calls: wDev_Insert_KeyEntry | Data refs: g_osi_funcs_p, if_ctrl, wDev_Insert_KeyEntry
 *   MMIO: none
 *   funcdb v3: 1 call(s), 3 ref(s); disasm: 1 call(s), 3 data ref(s)
 * Fidelity: medium - 51 instr, 3 branches, calls resolved */
int32_t ic_set_key(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.ic_set_key; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_c:;
  /* 000c: entry a1, 64 */
  a2 = (a2 >> 0) & 0xFF; /* 000f: extui a2, a2, 0, 8 */
  a12 = (a4 >> 0) & 0xFF; /* 0012: extui a12, a4, 0, 8 */
  a8 = a2 << (2 & 31); /* 0015: slli a8, a2, 2 */
  a4 = (uint32_t)&if_ctrl; /* 0018: l32r a4, 0 <ic_set_key-0xc> (0 <ic_set_key-0xc>) */ /* literal @0x0: if_ctrl */
  a8 = a8 + a2; /* 001b: add.n a8, a8, a2 */
  a6 = (a6 >> 0) & 0xFF; /* 001d: extui a6, a6, 0, 8 */
  a3 = (a3 >> 0) & 0xFF; /* 0020: extui a3, a3, 0, 8 */
  a9 = MEM8(a1 + 64); /* 0023: l8ui a9, a1, 64 */
  a8 = (a8 << 2) + a4; /* 0026: addx2 a8, a8, a4 */
  a10 = MEM8(a1 + 68); /* 0029: l8ui a10, a1, 68 */
  a11 = MEM8(a1 + 72); /* 002c: l8ui a11, a1, 72 */
  if (a6 < 4) goto L_40; /* 002f: bltui a6, 4, 40 <ic_set_key+0x34> */
  MEM8(a8 + 8) = a3; /* 0032: s8i a3, a8, 8 */
  MEMW(); /* 0035: memw  */
  MEMW(); /* 0038: memw  */
  goto L_4b; /* 003b: j 4b <ic_set_key+0x3f> */
  /* 003e: .byte 00 */
  /* 003f: .byte 00 */
L_40:;
  if (a3 != 0) goto L_45; /* 0040: bnez.n a3, 45 <ic_set_key+0x39> */
  MEM8(a8 + 8) = a3; /* 0042: s8i a3, a8, 8 */
L_45:;
  MEM8(a8 + 9) = a3; /* 0045: s8i a3, a8, 9 */
  MEMW(); /* 0048: memw  */
L_4b:;
  a4 = (uint32_t)&g_osi_funcs_p; /* 004b: l32r a4, 4 <ic_set_key-0x8> (0 <ic_set_key-0xc>) */ /* literal @0x4: g_osi_funcs_p */
  a8 = MEM32(a4 + 0); /* 004e: l32i.n a8, a4, 0 */
  a8 = MEM32(a8 + 216); /* 0050: l32i a8, a8, 216 */
  MEM32(a1 + 20) = a9; /* 0053: s32i.n a9, a1, 20 */
  MEM32(a1 + 24) = a10; /* 0055: s32i.n a10, a1, 24 */
  MEM32(a1 + 28) = a11; /* 0057: s32i.n a11, a1, 28 */
  MEM32(a1 + 16) = a12; /* 0059: s32i.n a12, a1, 16 */
  MEMW(); /* 005b: memw  */
  ((int32_t(*)())a8)(a2, a3, a4, a5); /* 005e: callx8 a8 */ /* indirect */
  a15 = a7; /* 0061: mov.n a15, a7 */
  a14 = a6; /* 0063: mov.n a14, a6 */
  a13 = a5; /* 0065: mov.n a13, a5 */
  a11 = MEM32(a1 + 28); /* 0067: l32i.n a11, a1, 28 */
  a10 = MEM32(a1 + 24); /* 0069: l32i.n a10, a1, 24 */
  a9 = MEM32(a1 + 20); /* 006b: l32i.n a9, a1, 20 */
  a12 = MEM32(a1 + 16); /* 006d: l32i.n a12, a1, 16 */
  MEM32(a1 + 8) = a11; /* 006f: s32i.n a11, a1, 8 */
  a11 = a2; /* 0071: mov.n a11, a2 */
  MEM32(a1 + 4) = a10; /* 0073: s32i.n a10, a1, 4 */
  a10 = a3; /* 0075: mov.n a10, a3 */
  MEM32(a1 + 0) = a9; /* 0077: s32i.n a9, a1, 0 */
  MEMW(); /* 0079: memw  */
  a8 = (uint32_t)&wDev_Insert_KeyEntry; /* 007c: l32r a8, 8 <ic_set_key-0x4> (0 <ic_set_key-0xc>) */ /* literal: GOT slot for wDev_Insert_KeyEntry */
  wDev_Insert_KeyEntry(a2, a3, a4, a5); /* call via literal slot */ /* 007f: callx8 a8 */
  a2 = MEM32(a4 + 0); /* 0082: l32i.n a2, a4, 0 */
  a2 = MEM32(a2 + 220); /* 0084: l32i a2, a2, 220 */
  ((int32_t(*)())a2)(a2, a3, a4, a5); /* 0087: callx8 a2 */ /* indirect */
  return (int32_t)a2; /* 008a: retw.n  */
}

/* ic_get_key @ if_hwctrl.o 0000000c size 80B bind GLOBAL
 * Calls: hal_crypto_get_key_entry, memcpy, memset | Data refs: hal_crypto_get_key_entry, memcpy, memset
 *   MMIO: none
 *   funcdb v3: 3 call(s), 3 ref(s); disasm: 3 call(s), 3 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t ic_get_key(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.ic_get_key; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_c:;
  /* 000c: entry a1, 64 */
  a8 = MEM8(a1 + 64); /* 000f: l8ui a8, a1, 64 */
  a12 = 0x9; /* 0012: movi.n a12, 9 */
  a11 = 0x0; /* 0014: movi.n a11, 0 */
  a10 = a1; /* 0016: mov.n a10, a1 */
  a6 = (a6 >> 0) & 0xFF; /* 0018: extui a6, a6, 0, 8 */
  MEM32(a1 + 16) = a8; /* 001b: s32i.n a8, a1, 16 */
  MEMW(); /* 001d: memw  */
  a8 = (uint32_t)&memset; /* 0020: l32r a8, 0 <ic_get_key-0xc> (0 <ic_get_key-0xc>) */ /* literal: GOT slot for memset */
  memset(a2, a3, a4, a5); /* call via literal slot */ /* 0023: callx8 a8 */
  a13 = a1; /* 0026: mov.n a13, a1 */
  a11 = a7; /* 0028: mov.n a11, a7 */
  a10 = a6; /* 002a: mov.n a10, a6 */
  a8 = MEM32(a1 + 16); /* 002c: l32i.n a8, a1, 16 */
  a12 = a8; /* 002e: mov.n a12, a8 */
  a8 = (uint32_t)&hal_crypto_get_key_entry; /* 0030: l32r a8, 4 <ic_get_key-0x8> (0 <ic_get_key-0xc>) */ /* literal: GOT slot for hal_crypto_get_key_entry */
  hal_crypto_get_key_entry(a2, a3, a4, a5); /* call via literal slot */ /* 0033: callx8 a8 */
  a12 = 0x6; /* 0036: movi.n a12, 6 */
  a8 = MEM8(a1 + 0); /* 0038: l8ui a8, a1, 0 */
  a11 = a1 + (3); /* 003b: addi.n a11, a1, 3 */
  a10 = a5; /* 003d: mov.n a10, a5 */
  MEM8(a2 + 0) = a8; /* 003f: s8i a8, a2, 0 */
  MEMW(); /* 0042: memw  */
  a2 = 0x0; /* 0045: movi.n a2, 0 */
  a8 = MEM8(a1 + 1); /* 0047: l8ui a8, a1, 1 */
  MEM32(a3 + 0) = a8; /* 004a: s32i.n a8, a3, 0 */
  a8 = MEM8(a1 + 2); /* 004c: l8ui a8, a1, 2 */
  MEM32(a4 + 0) = a8; /* 004f: s32i.n a8, a4, 0 */
  MEMW(); /* 0051: memw  */
  a8 = (uint32_t)&memcpy; /* 0054: l32r a8, 8 <ic_get_key-0x4> (0 <ic_get_key-0xc>) */ /* literal: GOT slot for memcpy */
  memcpy(a2, a3, a4, a5); /* call via literal slot */ /* 0057: callx8 a8 */
  return (int32_t)a2; /* 005a: retw.n  */
}

/* ic_obtain_key @ if_hwctrl.o 0000000c size 138B bind GLOBAL
 * Calls: hal_crypto_is_key_valid, ic_get_key, memcmp | Data refs: hal_crypto_is_key_valid, ic_get_key, memcmp
 *   MMIO: none
 *   funcdb v3: 3 call(s), 3 ref(s); disasm: 3 call(s), 3 data ref(s)
 * Fidelity: medium - 53 instr, 7 branches, calls resolved */
int32_t ic_obtain_key(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.ic_obtain_key; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_c:;
  /* 000c: entry a1, 96 */
  a8 = 0x3; /* 000f: movi.n a8, 3 */
  a3 = (a3 >> 0) & 0xFF; /* 0011: extui a3, a3, 0, 8 */
  a2 = (a2 >> 0) & 0xFF; /* 0014: extui a2, a2, 0, 8 */
  MEM8(a1 + 32) = a8; /* 0017: s8i a8, a1, 32 */
  a9 = 0x3; /* 001a: movi.n a9, 3 */
  a8 = 0x0; /* 001c: movi.n a8, 0 */
  a4 = (a4 >> 0) & 0xFF; /* 001e: extui a4, a4, 0, 8 */
  MEM32(a1 + 52) = a3; /* 0021: s32i.n a3, a1, 52 */
  a3 = 0x4; /* 0023: movi.n a3, 4 */
  MEM32(a1 + 48) = a2; /* 0025: s32i.n a2, a1, 48 */
  MEM32(a1 + 28) = a8; /* 0027: s32i.n a8, a1, 28 */
  MEM32(a1 + 24) = a9; /* 0029: s32i a9, a1, 24 */
  MEM32(a1 + 16) = a8; /* 002c: s32i a8, a1, 16 */
  MEM16(a1 + 20) = a8; /* 002f: s16i a8, a1, 20 */
  MEMW(); /* 0032: memw  */
L_35:;
  a10 = 0x4; /* 0035: mov.n a10, a3 */
  MEMW(); /* 0037: memw  */
  a8 = (uint32_t)&hal_crypto_is_key_valid; /* 003a: l32r a8, 0 <ic_obtain_key-0xc> (0 <ic_obtain_key-0xc>) */ /* literal: GOT slot for hal_crypto_is_key_valid */
  hal_crypto_is_key_valid(a2, a3, a4, a5); /* call via literal slot */ /* 003d: callx8 a8 */
  a2 = 0x4; /* 0040: mov.n a2, a10 */
  if (a10 != 0) goto L_50; /* 0042: bnez.n a10, 50 <ic_obtain_key+0x44> */
L_44:;
  a3 = a3 + (1); /* 0044: addi.n a3, a3, 1 */
  a9 = 0x19; /* 0046: movi.n a9, 25 */
  if (a3 != a9) goto L_35; /* 0048: bne a3, a9, 35 <ic_obtain_key+0x29> */
  a2 = 0x0; /* 004b: movi.n a2, 0 */
  goto L_94; /* 004d: j 94 <ic_obtain_key+0x88> */
L_50:;
  a10 = (a7 >> 0) & 0xFF; /* 0050: extui a10, a7, 0, 8 */
  MEM32(a1 + 0) = a10; /* 0053: s32i a10, a1, 0 */
  a15 = a6; /* 0056: mov.n a15, a6 */
  a14 = a3 | a3; /* 0058: or a14, a3, a3 */
  a13 = a1 + (16); /* 005b: addi a13, a1, 16 */
  a12 = a1 + (24); /* 005e: addi a12, a1, 24 */
  a11 = a1 + (28); /* 0061: addi a11, a1, 28 */
  a10 = a1 + (32); /* 0064: addi a10, a1, 32 */
  MEMW(); /* 0067: memw  */
  a8 = (uint32_t)&ic_get_key; /* 006a: l32r a8, 4 <ic_obtain_key-0x8> (0 <ic_obtain_key-0xc>) */ /* literal: GOT slot for ic_get_key */
  ic_get_key(a2, a3, a4, a5); /* call via literal slot */ /* 006d: callx8 a8 */
  a10 = MEM8(a1 + 32); /* 0070: l8ui a10, a1, 32 */
  a8 = MEM32(a1 + 48); /* 0073: l32i.n a8, a1, 48 */
  if (a10 != a8) goto L_44; /* 0075: bne a10, a8, 44 <ic_obtain_key+0x38> */
  a10 = MEM32(a1 + 28); /* 0078: l32i.n a10, a1, 28 */
  a8 = MEM32(a1 + 52); /* 007a: l32i.n a8, a1, 52 */
  if (a8 != a10) goto L_44; /* 007c: bne a8, a10, 44 <ic_obtain_key+0x38> */
  a10 = MEM32(a1 + 24); /* 007f: l32i.n a10, a1, 24 */
  if (a4 != a10) goto L_44; /* 0081: bne a4, a10, 44 <ic_obtain_key+0x38> */
  a12 = 0x6; /* 0084: movi.n a12, 6 */
  a11 = a5; /* 0086: mov.n a11, a5 */
  a10 = a1 + (16); /* 0088: addi a10, a1, 16 */
  a8 = (uint32_t)&memcmp; /* 008b: l32r a8, 8 <ic_obtain_key-0x4> (0 <ic_obtain_key-0xc>) */ /* literal: GOT slot for memcmp */
  memcmp(a2, a3, a4, a5); /* call via literal slot */ /* 008e: callx8 a8 */
  if (a10 != 0) goto L_44; /* 0091: bnez a10, 44 <ic_obtain_key+0x38> */
L_94:;
  return (int32_t)a2; /* 0094: retw.n  */
}

/* ic_get_rssi @ if_hwctrl.o 00000008 size 35B bind GLOBAL
 * Calls: rc_get_trc | Data refs: rc_get_trc, wDevCtrl
 *   MMIO: none
 *   funcdb v3: 1 call(s), 2 ref(s); disasm: 1 call(s), 2 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t ic_get_rssi(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.ic_get_rssi; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_8:;
  /* 0008: entry a1, 32 */
  a10 = (a2 >> 0) & 0xFF; /* 000b: extui a10, a2, 0, 8 */
  a11 = a3; /* 000e: mov.n a11, a3 */
  a8 = (uint32_t)&rc_get_trc; /* 0010: l32r a8, 4 <ic_get_rssi-0x4> (0 <ic_get_rssi-0x8>) */ /* literal: GOT slot for rc_get_trc */
  rc_get_trc(a2, a3, a4, a5); /* call via literal slot */ /* 0013: callx8 a8 */
  a2 = 0x1F; /* 0016: movi.n a2, 31 */
  if (a10 == 0) goto L_29; /* 0018: beqz.n a10, 29 <ic_get_rssi+0x21> */
  a8 = (uint32_t)&wDevCtrl; /* 001a: l32r a8, 0 <ic_get_rssi-0x8> (0 <ic_get_rssi-0x8>) */ /* literal @0x0: wDevCtrl */
  a2 = MEM8(a10 + 3); /* 001d: l8ui a2, a10, 3 */
  a8 = MEM8(a8 + 46); /* 0020: l8ui a8, a8, 46 */
  a2 = a2 - a8; /* 0023: sub a2, a2, a8 */
  a2 = (a2 >> 0) & 0xFF; /* 0026: extui a2, a2, 0, 8 */
L_29:;
  return (int32_t)a2; /* 0029: retw.n  */
}

/* ic_tx_pkt @ if_hwctrl.o 00000004 size 17B bind GLOBAL
 * Calls: ppTxPkt | Data refs: ppTxPkt
 *   MMIO: none
 *   funcdb v3: 1 call(s), 1 ref(s); disasm: 1 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t ic_tx_pkt(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.ic_tx_pkt; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a11 = 0x1; /* 0007: movi.n a11, 1 */
  a10 = a2; /* 0009: mov.n a10, a2 */
  a8 = (uint32_t)&ppTxPkt; /* 000b: l32r a8, 0 <ic_tx_pkt-0x4> (0 <ic_tx_pkt-0x4>) */ /* literal: GOT slot for ppTxPkt */
  ppTxPkt(a2, a3, a4, a5); /* call via literal slot */ /* 000e: callx8 a8 */
  a2 = a10; /* 0011: mov.n a2, a10 */
  return (int32_t)a2; /* 0013: retw.n  */
}

/* ic_ebuf_alloc @ if_hwctrl.o 00000004 size 20B bind GLOBAL
 * Calls: esf_buf_alloc | Data refs: esf_buf_alloc
 *   MMIO: none
 *   funcdb v3: 1 call(s), 1 ref(s); disasm: 1 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t ic_ebuf_alloc(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.ic_ebuf_alloc; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a12 = a4; /* 0007: mov.n a12, a4 */
  a11 = a3; /* 0009: mov.n a11, a3 */
  a10 = a2 | a2; /* 000b: or a10, a2, a2 */
  a8 = (uint32_t)&esf_buf_alloc; /* 000e: l32r a8, 0 <ic_ebuf_alloc-0x4> (0 <ic_ebuf_alloc-0x4>) */ /* literal: GOT slot for esf_buf_alloc */
  esf_buf_alloc(a2, a3, a4, a5); /* call via literal slot */ /* 0011: callx8 a8 */
  a2 = a10; /* 0014: mov.n a2, a10 */
  return (int32_t)a2; /* 0016: retw.n  */
}

/* ic_clear_data_ifx_tx_queue @ if_hwctrl.o 00000004 size 14B bind GLOBAL
 * Calls: ppClearAlldataTxq_ifx | Data refs: ppClearAlldataTxq_ifx
 *   MMIO: none
 *   funcdb v3: 1 call(s), 1 ref(s); disasm: 1 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t ic_clear_data_ifx_tx_queue(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.ic_clear_data_ifx_tx_queue; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a10 = (a2 >> 0) & 0xFF; /* 0007: extui a10, a2, 0, 8 */
  a8 = (uint32_t)&ppClearAlldataTxq_ifx; /* 000a: l32r a8, 0 <ic_clear_data_ifx_tx_queue-0x4> (0 <ic_clear_data_ifx_tx_queue-0x4>) */ /* literal: GOT slot for ppClearAlldataTxq_ifx */
  ppClearAlldataTxq_ifx(a2, a3, a4, a5); /* call via literal slot */ /* 000d: callx8 a8 */
  return (int32_t)a2; /* 0010: retw.n  */
}

/* ic_ebuf_recycle_tx @ if_hwctrl.o 00000004 size 14B bind GLOBAL
 * Calls: esf_buf_recycle | Data refs: esf_buf_recycle
 *   MMIO: none
 *   funcdb v3: 1 call(s), 1 ref(s); disasm: 1 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t ic_ebuf_recycle_tx(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.ic_ebuf_recycle_tx; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a10 = a2 | a2; /* 0007: or a10, a2, a2 */
  a8 = (uint32_t)&esf_buf_recycle; /* 000a: l32r a8, 0 <ic_ebuf_recycle_tx-0x4> (0 <ic_ebuf_recycle_tx-0x4>) */ /* literal: GOT slot for esf_buf_recycle */
  esf_buf_recycle(a2, a3, a4, a5); /* call via literal slot */ /* 000d: callx8 a8 */
  return (int32_t)a2; /* 0010: retw.n  */
}

/* ic_ebuf_recycle_rx @ if_hwctrl.o 00000004 size 14B bind GLOBAL
 * Calls: ppRecycleRxPkt | Data refs: ppRecycleRxPkt
 *   MMIO: none
 *   funcdb v3: 1 call(s), 1 ref(s); disasm: 1 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t ic_ebuf_recycle_rx(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.ic_ebuf_recycle_rx; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a10 = a2 | a2; /* 0007: or a10, a2, a2 */
  a8 = (uint32_t)&ppRecycleRxPkt; /* 000a: l32r a8, 0 <ic_ebuf_recycle_rx-0x4> (0 <ic_ebuf_recycle_rx-0x4>) */ /* literal: GOT slot for ppRecycleRxPkt */
  ppRecycleRxPkt(a2, a3, a4, a5); /* call via literal slot */ /* 000d: callx8 a8 */
  return (int32_t)a2; /* 0010: retw.n  */
}

/* esp_wifi_internal_free_rx_buffer @ if_hwctrl.o 00000004 size 14B bind GLOBAL
 * Calls: ppRecycleRxPkt | Data refs: ppRecycleRxPkt
 *   MMIO: none
 *   funcdb v3: 1 call(s), 1 ref(s); disasm: 1 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t esp_wifi_internal_free_rx_buffer(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.esp_wifi_internal_free_rx_buffer; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a10 = a2 | a2; /* 0007: or a10, a2, a2 */
  a8 = (uint32_t)&ppRecycleRxPkt; /* 000a: l32r a8, 0 <esp_wifi_internal_free_rx_buffer-0x4> (0 <esp_wifi_internal_free_rx_buffer-0x4>) */ /* literal: GOT slot for ppRecycleRxPkt */
  ppRecycleRxPkt(a2, a3, a4, a5); /* call via literal slot */ /* 000d: callx8 a8 */
  return (int32_t)a2; /* 0010: retw.n  */
}

/* ic_register_tx_cb @ if_hwctrl.o 00000004 size 21B bind GLOBAL
 * Calls: ppRegisterTxCallback | Data refs: ppRegisterTxCallback
 *   MMIO: none
 *   funcdb v3: 1 call(s), 1 ref(s); disasm: 1 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t ic_register_tx_cb(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.ic_register_tx_cb; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a12 = (a4 >> 0) & 0xFF; /* 0007: extui a12, a4, 0, 8 */
  a11 = (a3 >> 0) & 0xFF; /* 000a: extui a11, a3, 0, 8 */
  a10 = a2; /* 000d: mov.n a10, a2 */
  a8 = (uint32_t)&ppRegisterTxCallback; /* 000f: l32r a8, 0 <ic_register_tx_cb-0x4> (0 <ic_register_tx_cb-0x4>) */ /* literal: GOT slot for ppRegisterTxCallback */
  ppRegisterTxCallback(a2, a3, a4, a5); /* call via literal slot */ /* 0012: callx8 a8 */
  a2 = a10; /* 0015: mov.n a2, a10 */
  return (int32_t)a2; /* 0017: retw.n  */
}

/* ic_register_rx_cb @ if_hwctrl.o 00000004 size 18B bind GLOBAL
 * Calls: ppRegisterRxCallback | Data refs: ppRegisterRxCallback
 *   MMIO: none
 *   funcdb v3: 1 call(s), 1 ref(s); disasm: 1 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t ic_register_rx_cb(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.ic_register_rx_cb; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a11 = (a3 >> 0) & 0xFF; /* 0007: extui a11, a3, 0, 8 */
  a10 = a2; /* 000a: mov.n a10, a2 */
  a8 = (uint32_t)&ppRegisterRxCallback; /* 000c: l32r a8, 0 <ic_register_rx_cb-0x4> (0 <ic_register_rx_cb-0x4>) */ /* literal: GOT slot for ppRegisterRxCallback */
  ppRegisterRxCallback(a2, a3, a4, a5); /* call via literal slot */ /* 000f: callx8 a8 */
  a2 = a10; /* 0012: mov.n a2, a10 */
  return (int32_t)a2; /* 0014: retw.n  */
}

/* ic_register_timer_post_cb @ if_hwctrl.o 00000004 size 16B bind GLOBAL
 * Calls: pp_timer_register_post_cb | Data refs: pp_timer_register_post_cb
 *   MMIO: none
 *   funcdb v3: 1 call(s), 1 ref(s); disasm: 1 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t ic_register_timer_post_cb(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.ic_register_timer_post_cb; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a10 = a2 | a2; /* 0007: or a10, a2, a2 */
  a8 = (uint32_t)&pp_timer_register_post_cb; /* 000a: l32r a8, 0 <ic_register_timer_post_cb-0x4> (0 <ic_register_timer_post_cb-0x4>) */ /* literal: GOT slot for pp_timer_register_post_cb */
  pp_timer_register_post_cb(a2, a3, a4, a5); /* call via literal slot */ /* 000d: callx8 a8 */
  a2 = a10; /* 0010: mov.n a2, a10 */
  return (int32_t)a2; /* 0012: retw.n  */
}

/* ic_register_michael_mic_failure_cb @ if_hwctrl.o 00000004 size 16B bind GLOBAL
 * Calls: pp_register_michael_mic_failure_cb | Data refs: pp_register_michael_mic_failure_cb
 *   MMIO: none
 *   funcdb v3: 1 call(s), 1 ref(s); disasm: 1 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t ic_register_michael_mic_failure_cb(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.ic_register_michael_mic_failure_cb; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a10 = a2 | a2; /* 0007: or a10, a2, a2 */
  a8 = (uint32_t)&pp_register_michael_mic_failure_cb; /* 000a: l32r a8, 0 <ic_register_michael_mic_failure_cb-0x4> (0 <ic_register_michael_mic_failure_cb-0x4>) */ /* literal: GOT slot for pp_register_michael_mic_failure_cb */
  pp_register_michael_mic_failure_cb(a2, a3, a4, a5); /* call via literal slot */ /* 000d: callx8 a8 */
  a2 = a10; /* 0010: mov.n a2, a10 */
  return (int32_t)a2; /* 0012: retw.n  */
}

/* ic_register_pp_tx_done_cb @ if_hwctrl.o 00000004 size 16B bind GLOBAL
 * Calls: ppRegisterTxDoneUserActionCallback | Data refs: ppRegisterTxDoneUserActionCallback
 *   MMIO: none
 *   funcdb v3: 1 call(s), 1 ref(s); disasm: 1 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t ic_register_pp_tx_done_cb(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.ic_register_pp_tx_done_cb; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a10 = a2 | a2; /* 0007: or a10, a2, a2 */
  a8 = (uint32_t)&ppRegisterTxDoneUserActionCallback; /* 000a: l32r a8, 0 <ic_register_pp_tx_done_cb-0x4> (0 <ic_register_pp_tx_done_cb-0x4>) */ /* literal: GOT slot for ppRegisterTxDoneUserActionCallback */
  ppRegisterTxDoneUserActionCallback(a2, a3, a4, a5); /* call via literal slot */ /* 000d: callx8 a8 */
  a2 = a10; /* 0010: mov.n a2, a10 */
  return (int32_t)a2; /* 0012: retw.n  */
}

/* ic_set_promis_filter @ if_hwctrl.o 00000004 size 16B bind GLOBAL
 * Calls: wdev_set_promis_filter | Data refs: wdev_set_promis_filter
 *   MMIO: none
 *   funcdb v3: 1 call(s), 1 ref(s); disasm: 1 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t ic_set_promis_filter(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.ic_set_promis_filter; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a10 = a2 | a2; /* 0007: or a10, a2, a2 */
  a8 = (uint32_t)&wdev_set_promis_filter; /* 000a: l32r a8, 0 <ic_set_promis_filter-0x4> (0 <ic_set_promis_filter-0x4>) */ /* literal: GOT slot for wdev_set_promis_filter */
  wdev_set_promis_filter(a2, a3, a4, a5); /* call via literal slot */ /* 000d: callx8 a8 */
  a2 = a10; /* 0010: mov.n a2, a10 */
  return (int32_t)a2; /* 0012: retw.n  */
}

/* ic_get_promis_filter @ if_hwctrl.o 00000004 size 16B bind GLOBAL
 * Calls: wdev_get_promis_filter | Data refs: wdev_get_promis_filter
 *   MMIO: none
 *   funcdb v3: 1 call(s), 1 ref(s); disasm: 1 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t ic_get_promis_filter(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.ic_get_promis_filter; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a10 = a2 | a2; /* 0007: or a10, a2, a2 */
  a8 = (uint32_t)&wdev_get_promis_filter; /* 000a: l32r a8, 0 <ic_get_promis_filter-0x4> (0 <ic_get_promis_filter-0x4>) */ /* literal: GOT slot for wdev_get_promis_filter */
  wdev_get_promis_filter(a2, a3, a4, a5); /* call via literal slot */ /* 000d: callx8 a8 */
  a2 = a10; /* 0010: mov.n a2, a10 */
  return (int32_t)a2; /* 0012: retw.n  */
}

/* ic_set_promis_ctrl_filter @ if_hwctrl.o 00000004 size 16B bind GLOBAL
 * Calls: wdev_set_promis_ctrl_filter | Data refs: wdev_set_promis_ctrl_filter
 *   MMIO: none
 *   funcdb v3: 1 call(s), 1 ref(s); disasm: 1 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t ic_set_promis_ctrl_filter(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.ic_set_promis_ctrl_filter; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a10 = a2 | a2; /* 0007: or a10, a2, a2 */
  a8 = (uint32_t)&wdev_set_promis_ctrl_filter; /* 000a: l32r a8, 0 <ic_set_promis_ctrl_filter-0x4> (0 <ic_set_promis_ctrl_filter-0x4>) */ /* literal: GOT slot for wdev_set_promis_ctrl_filter */
  wdev_set_promis_ctrl_filter(a2, a3, a4, a5); /* call via literal slot */ /* 000d: callx8 a8 */
  a2 = a10; /* 0010: mov.n a2, a10 */
  return (int32_t)a2; /* 0012: retw.n  */
}

/* ic_get_promis_ctrl_filter @ if_hwctrl.o 00000004 size 16B bind GLOBAL
 * Calls: wdev_get_promis_ctrl_filter | Data refs: wdev_get_promis_ctrl_filter
 *   MMIO: none
 *   funcdb v3: 1 call(s), 1 ref(s); disasm: 1 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t ic_get_promis_ctrl_filter(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.ic_get_promis_ctrl_filter; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a10 = a2 | a2; /* 0007: or a10, a2, a2 */
  a8 = (uint32_t)&wdev_get_promis_ctrl_filter; /* 000a: l32r a8, 0 <ic_get_promis_ctrl_filter-0x4> (0 <ic_get_promis_ctrl_filter-0x4>) */ /* literal: GOT slot for wdev_get_promis_ctrl_filter */
  wdev_get_promis_ctrl_filter(a2, a3, a4, a5); /* call via literal slot */ /* 000d: callx8 a8 */
  a2 = a10; /* 0010: mov.n a2, a10 */
  return (int32_t)a2; /* 0012: retw.n  */
}

/* ic_register_promis_rx_cb @ if_hwctrl.o 00000004 size 21B bind GLOBAL
 * Calls: ppRegisterPromisRxCallback | Data refs: ppRegisterPromisRxCallback
 *   MMIO: none
 *   funcdb v3: 1 call(s), 1 ref(s); disasm: 1 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t ic_register_promis_rx_cb(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.ic_register_promis_rx_cb; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a10 = a2 | a2; /* 0007: or a10, a2, a2 */
  a8 = (uint32_t)&ppRegisterPromisRxCallback; /* 000a: l32r a8, 0 <ic_register_promis_rx_cb-0x4> (0 <ic_register_promis_rx_cb-0x4>) */ /* literal: GOT slot for ppRegisterPromisRxCallback */
  ppRegisterPromisRxCallback(a2, a3, a4, a5); /* call via literal slot */ /* 000d: callx8 a8 */
  a8 = 0x0; /* 0010: movi.n a8, 0 */
  a2 = 0x1; /* 0012: movi.n a2, 1 */
  if (a10 == 0) a2 = a8; /* 0014: moveqz a2, a8, a10 */
  return (int32_t)a2; /* 0017: retw.n  */
}

/* ic_register_csi_rx_cb @ if_hwctrl.o 00000004 size 17B bind GLOBAL
 * Calls: wdev_set_csi_rx_cb | Data refs: wdev_set_csi_rx_cb
 *   MMIO: none
 *   funcdb v3: 1 call(s), 1 ref(s); disasm: 1 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t ic_register_csi_rx_cb(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.ic_register_csi_rx_cb; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a11 = a3; /* 0007: mov.n a11, a3 */
  a10 = a2; /* 0009: mov.n a10, a2 */
  a8 = (uint32_t)&wdev_set_csi_rx_cb; /* 000b: l32r a8, 0 <ic_register_csi_rx_cb-0x4> (0 <ic_register_csi_rx_cb-0x4>) */ /* literal: GOT slot for wdev_set_csi_rx_cb */
  wdev_set_csi_rx_cb(a2, a3, a4, a5); /* call via literal slot */ /* 000e: callx8 a8 */
  a2 = a10; /* 0011: mov.n a2, a10 */
  return (int32_t)a2; /* 0013: retw.n  */
}

/* ic_register_config_cb @ if_hwctrl.o 00000004 size 20B bind GLOBAL
 * Calls: pp_register_config_cb | Data refs: pp_register_config_cb
 *   MMIO: none
 *   funcdb v3: 1 call(s), 1 ref(s); disasm: 1 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t ic_register_config_cb(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.ic_register_config_cb; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a10 = a2; /* 0007: mov.n a10, a2 */
  a2 = 0x0; /* 0009: movi.n a2, 0 */
  if (a10 == a2) goto L_16; /* 000b: beq a10, a2, 16 <ic_register_config_cb+0x12> */
  a8 = (uint32_t)&pp_register_config_cb; /* 000e: l32r a8, 0 <ic_register_config_cb-0x4> (0 <ic_register_config_cb-0x4>) */ /* literal: GOT slot for pp_register_config_cb */
  pp_register_config_cb(a2, a3, a4, a5); /* call via literal slot */ /* 0011: callx8 a8 */
  a2 = 0x1; /* 0014: movi.n a2, 1 */
L_16:;
  return (int32_t)a2; /* 0016: retw.n  */
}

/* ic_is_mgmt_hwdecr_enabled @ if_hwctrl.o 00000004 size 16B bind GLOBAL
 * Calls: wdev_is_mgmt_hwdecr_enabled | Data refs: wdev_is_mgmt_hwdecr_enabled
 *   MMIO: none
 *   funcdb v3: 1 call(s), 1 ref(s); disasm: 1 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t ic_is_mgmt_hwdecr_enabled(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.ic_is_mgmt_hwdecr_enabled; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a10 = (a2 >> 0) & 0xFF; /* 0007: extui a10, a2, 0, 8 */
  a8 = (uint32_t)&wdev_is_mgmt_hwdecr_enabled; /* 000a: l32r a8, 0 <ic_is_mgmt_hwdecr_enabled-0x4> (0 <ic_is_mgmt_hwdecr_enabled-0x4>) */ /* literal: GOT slot for wdev_is_mgmt_hwdecr_enabled */
  wdev_is_mgmt_hwdecr_enabled(a2, a3, a4, a5); /* call via literal slot */ /* 000d: callx8 a8 */
  a2 = a10; /* 0010: mov.n a2, a10 */
  return (int32_t)a2; /* 0012: retw.n  */
}

/* ic_register_pm_tx_null_cb @ if_hwctrl.o 00000004 size 20B bind GLOBAL
 * Calls: pm_register_pm_tx_null_cb | Data refs: pm_register_pm_tx_null_cb
 *   MMIO: none
 *   funcdb v3: 1 call(s), 1 ref(s); disasm: 1 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t ic_register_pm_tx_null_cb(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.ic_register_pm_tx_null_cb; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a10 = a2; /* 0007: mov.n a10, a2 */
  a2 = 0x0; /* 0009: movi.n a2, 0 */
  if (a10 == a2) goto L_16; /* 000b: beq a10, a2, 16 <ic_register_pm_tx_null_cb+0x12> */
  a8 = (uint32_t)&pm_register_pm_tx_null_cb; /* 000e: l32r a8, 0 <ic_register_pm_tx_null_cb-0x4> (0 <ic_register_pm_tx_null_cb-0x4>) */ /* literal: GOT slot for pm_register_pm_tx_null_cb */
  pm_register_pm_tx_null_cb(a2, a3, a4, a5); /* call via literal slot */ /* 0011: callx8 a8 */
  a2 = 0x1; /* 0014: movi.n a2, 1 */
L_16:;
  return (int32_t)a2; /* 0016: retw.n  */
}

/* ic_register_net80211_tx_cb @ if_hwctrl.o 00000004 size 20B bind GLOBAL
 * Calls: pp_register_net80211_tx_cb | Data refs: pp_register_net80211_tx_cb
 *   MMIO: none
 *   funcdb v3: 1 call(s), 1 ref(s); disasm: 1 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t ic_register_net80211_tx_cb(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.ic_register_net80211_tx_cb; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a10 = a2; /* 0007: mov.n a10, a2 */
  a2 = 0x0; /* 0009: movi.n a2, 0 */
  if (a10 == a2) goto L_16; /* 000b: beq a10, a2, 16 <ic_register_net80211_tx_cb+0x12> */
  a8 = (uint32_t)&pp_register_net80211_tx_cb; /* 000e: l32r a8, 0 <ic_register_net80211_tx_cb-0x4> (0 <ic_register_net80211_tx_cb-0x4>) */ /* literal: GOT slot for pp_register_net80211_tx_cb */
  pp_register_net80211_tx_cb(a2, a3, a4, a5); /* call via literal slot */ /* 0011: callx8 a8 */
  a2 = a10; /* 0014: mov.n a2, a10 */
L_16:;
  return (int32_t)a2; /* 0016: retw.n  */
}

/* ic_register_timer_cb @ if_hwctrl.o 00000004 size 20B bind GLOBAL
 * Calls: pp_register_timer_cb | Data refs: pp_register_timer_cb
 *   MMIO: none
 *   funcdb v3: 1 call(s), 1 ref(s); disasm: 1 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t ic_register_timer_cb(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.ic_register_timer_cb; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a10 = a2; /* 0007: mov.n a10, a2 */
  a2 = 0x0; /* 0009: movi.n a2, 0 */
  if (a10 == a2) goto L_16; /* 000b: beq a10, a2, 16 <ic_register_timer_cb+0x12> */
  a8 = (uint32_t)&pp_register_timer_cb; /* 000e: l32r a8, 0 <ic_register_timer_cb-0x4> (0 <ic_register_timer_cb-0x4>) */ /* literal: GOT slot for pp_register_timer_cb */
  pp_register_timer_cb(a2, a3, a4, a5); /* call via literal slot */ /* 0011: callx8 a8 */
  a2 = a10; /* 0014: mov.n a2, a10 */
L_16:;
  return (int32_t)a2; /* 0016: retw.n  */
}

/* ic_register_ftm_callbacks @ if_hwctrl.o 00000000 size 7B bind GLOBAL
 * Calls: none | Data refs: none
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t ic_register_ftm_callbacks(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.ic_register_ftm_callbacks; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_0:;
  /* 0000: entry a1, 32 */
  a2 = 0x0; /* 0003: movi.n a2, 0 */
  return (int32_t)a2; /* 0005: retw.n  */
}

/* ic_register_nan_callbacks @ if_hwctrl.o 00000004 size 16B bind GLOBAL
 * Calls: wdev_nan_set_callbacks | Data refs: wdev_nan_set_callbacks
 *   MMIO: none
 *   funcdb v3: 1 call(s), 1 ref(s); disasm: 1 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t ic_register_nan_callbacks(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.ic_register_nan_callbacks; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a10 = a2 | a2; /* 0007: or a10, a2, a2 */
  a8 = (uint32_t)&wdev_nan_set_callbacks; /* 000a: l32r a8, 0 <ic_register_nan_callbacks-0x4> (0 <ic_register_nan_callbacks-0x4>) */ /* literal: GOT slot for wdev_nan_set_callbacks */
  wdev_nan_set_callbacks(a2, a3, a4, a5); /* call via literal slot */ /* 000d: callx8 a8 */
  a2 = a10; /* 0010: mov.n a2, a10 */
  return (int32_t)a2; /* 0012: retw.n  */
}

/* ic_pp_post @ if_hwctrl.o 00000004 size 17B bind GLOBAL
 * Calls: pp_post | Data refs: pp_post
 *   MMIO: none
 *   funcdb v3: 1 call(s), 1 ref(s); disasm: 1 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t ic_pp_post(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.ic_pp_post; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a11 = a3; /* 0007: mov.n a11, a3 */
  a10 = a2; /* 0009: mov.n a10, a2 */
  a8 = (uint32_t)&pp_post; /* 000b: l32r a8, 0 <ic_pp_post-0x4> (0 <ic_pp_post-0x4>) */ /* literal: GOT slot for pp_post */
  pp_post(a2, a3, a4, a5); /* call via literal slot */ /* 000e: callx8 a8 */
  a2 = a10; /* 0011: mov.n a2, a10 */
  return (int32_t)a2; /* 0013: retw.n  */
}

/* ic_enable_sniffer @ if_hwctrl.o 00000004 size 14B bind GLOBAL
 * Calls: wdev_set_promis | Data refs: wdev_set_promis
 *   MMIO: none
 *   funcdb v3: 1 call(s), 1 ref(s); disasm: 1 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t ic_enable_sniffer(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.ic_enable_sniffer; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a10 = 0x1; /* 0007: movi a10, 1 */
  a8 = (uint32_t)&wdev_set_promis; /* 000a: l32r a8, 0 <ic_enable_sniffer-0x4> (0 <ic_enable_sniffer-0x4>) */ /* literal: GOT slot for wdev_set_promis */
  wdev_set_promis(a2, a3, a4, a5); /* call via literal slot */ /* 000d: callx8 a8 */
  return (int32_t)a2; /* 0010: retw.n  */
}

/* ic_disable_sniffer @ if_hwctrl.o 00000004 size 14B bind GLOBAL
 * Calls: wdev_set_promis | Data refs: wdev_set_promis
 *   MMIO: none
 *   funcdb v3: 1 call(s), 1 ref(s); disasm: 1 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t ic_disable_sniffer(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.ic_disable_sniffer; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a10 = 0x0; /* 0007: movi a10, 0 */
  a8 = (uint32_t)&wdev_set_promis; /* 000a: l32r a8, 0 <ic_disable_sniffer-0x4> (0 <ic_disable_sniffer-0x4>) */ /* literal: GOT slot for wdev_set_promis */
  wdev_set_promis(a2, a3, a4, a5); /* call via literal slot */ /* 000d: callx8 a8 */
  return (int32_t)a2; /* 0010: retw.n  */
}

/* ic_set_vif @ if_hwctrl.o 00000068 size 431B bind GLOBAL
 * Calls: ic_disable_crypto, ic_disable_sniffer, ic_enable_sniffer, memcpy, pm_force_scan_unlock, rc_disable_trc_by_interface, wifi_log, wifi_set_rx_policy | Data refs: .rodata_wlog_debug.3, .rodata_wlog_debug.4, .rodata_wlog_debug.5, .rodata_wlog_debug.6, .rodata_wlog_debug.7, .rodata_wlog_debug.8, .rodata_wlog_error.9, ic_disable_crypto, ic_disable_sniffer, ic_enable_sniffer, if_ctrl, memcpy, pm_force_scan_unlock, rc_disable_trc_by_interface, wDevCtrl, wifi_log, wifi_set_rx_policy
 *   MMIO: 0x3FF73084
 *   funcdb v3: 8 call(s), 17 ref(s); disasm: 15 call(s), 17 data ref(s)
 * Fidelity: medium - 165 instr, 24 branches, 0 indirect; flow + direct calls mapped, GOT-indirects enumerated (verified against section disasm) */
int32_t ic_set_vif(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.ic_set_vif; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_68:;
  /* 0068: entry a1, 32 */
  a2 = (a2 >> 0) & 0xFF; /* 006b: extui a2, a2, 0, 8 */
  a6 = (a6 >> 0) & 0xFF; /* 006e: extui a6, a6, 0, 8 */
  a7 = (a7 >> 0) & 0xFF; /* 0071: extui a7, a7, 0, 8 */
  if (a3 != 2) goto L_90; /* 0074: bnei a3, 2, 90 <ic_set_vif+0x28> */
  a3 = (uint32_t)&if_ctrl; /* 0077: l32r a3, 0 <ic_set_vif-0x68> (0 <ic_set_vif-0x68>) */ /* literal @0x0: if_ctrl */
  a2 = (a2 << 4) + a2; /* 007a: addx4 a2, a2, a2 */
  a2 = (a2 << 2) + a3; /* 007d: addx2 a2, a2, a3 */
  MEM8(a2 + 6) = a5; /* 0080: s8i a5, a2, 6 */
  MEM8(a2 + 7) = a6; /* 0083: s8i a6, a2, 7 */
  MEMW(); /* 0086: memw  */
  MEMW(); /* 0089: memw  */
  goto L_215; /* 008c: j 215 <ic_set_vif+0x1ad> */
  /* 008f: .byte 00 */
L_90:;
  if (a3 != 0) goto L_155; /* 0090: bnez a3, 155 <ic_set_vif+0xed> */
  if (a2 != 0) goto L_ac; /* 0093: bnez.n a2, ac <ic_set_vif+0x44> */
  a14 = 0x1; /* 0095: movi.n a14, 1 */
  a13 = (uint32_t)&lit_rodata_wlog_debug_3; /* 0097: l32r a13, 4 <ic_set_vif-0x64> (0 <ic_set_vif-0x68>) */ /* literal @0x4: .rodata_wlog_debug.3 */
  a10 = 0x1; /* 009a: mov.n a10, a14 */
  a12 = 0x4; /* 009c: movi.n a12, 4 */
  a11 = 0xC; /* 009e: movi.n a11, 12 */
  a8 = (uint32_t)&wifi_log; /* 00a0: l32r a8, 2c <ic_set_vif-0x3c> (0 <ic_set_vif-0x68>) */ /* literal: GOT slot for wifi_log */
  wifi_log(a2, a3, a4, a5); /* call via literal slot */ /* 00a3: callx8 a8 */
  a10 = 0x1; /* 00a6: movi.n a10, 1 */
  goto L_c2; /* 00a8: j c2 <ic_set_vif+0x5a> */
  /* 00ab: .byte 00 */
L_ac:;
  if (a2 != 2) goto L_cc; /* 00ac: bnei a2, 2, cc <ic_set_vif+0x64> */
  a13 = (uint32_t)&lit_rodata_wlog_debug_4; /* 00af: l32r a13, 8 <ic_set_vif-0x60> (0 <ic_set_vif-0x68>) */ /* literal @0x8: .rodata_wlog_debug.4 */
  a10 = 0x1; /* 00b2: movi.n a10, 1 */
  a14 = 0xA; /* 00b4: movi.n a14, 10 */
  a12 = 0x4; /* 00b6: movi.n a12, 4 */
  a11 = 0xC; /* 00b8: movi.n a11, 12 */
  a8 = (uint32_t)&wifi_log; /* 00ba: l32r a8, 30 <ic_set_vif-0x38> (0 <ic_set_vif-0x68>) */ /* literal: GOT slot for wifi_log */
  wifi_log(a2, a3, a4, a5); /* call via literal slot */ /* 00bd: callx8 a8 */
  a10 = 0xA; /* 00c0: movi.n a10, 10 */
L_c2:;
  a8 = (uint32_t)&wifi_set_rx_policy; /* 00c2: l32r a8, 34 <ic_set_vif-0x34> (0 <ic_set_vif-0x68>) */ /* literal: GOT slot for wifi_set_rx_policy */
  wifi_set_rx_policy(a2, a3, a4, a5); /* call via literal slot */ /* 00c5: callx8 a8 */
  goto L_ee; /* 00c8: j ee <ic_set_vif+0x86> */
  /* 00cb: .byte 00 */
L_cc:;
  if (a2 != 1) goto L_e5; /* 00cc: bnei a2, 1, e5 <ic_set_vif+0x7d> */
  a13 = (uint32_t)&lit_rodata_wlog_debug_5; /* 00cf: l32r a13, c <ic_set_vif-0x5c> (0 <ic_set_vif-0x68>) */ /* literal @0xC: .rodata_wlog_debug.5 */
  a10 = a2; /* 00d2: mov.n a10, a2 */
  a14 = 0x8; /* 00d4: movi.n a14, 8 */
  a12 = 0x4; /* 00d6: movi.n a12, 4 */
  a11 = 0xC; /* 00d8: movi.n a11, 12 */
  a8 = (uint32_t)&wifi_log; /* 00da: l32r a8, 38 <ic_set_vif-0x30> (0 <ic_set_vif-0x68>) */ /* literal: GOT slot for wifi_log */
  wifi_log(a2, a3, a4, a5); /* call via literal slot */ /* 00dd: callx8 a8 */
  a10 = 0x8; /* 00e0: movi.n a10, 8 */
  goto L_c2; /* 00e2: j c2 <ic_set_vif+0x5a> */
L_e5:;
  if (a2 != 3) goto L_ee; /* 00e5: bnei a2, 3, ee <ic_set_vif+0x86> */
  a8 = (uint32_t)&ic_enable_sniffer; /* 00e8: l32r a8, 3c <ic_set_vif-0x2c> (0 <ic_set_vif-0x68>) */ /* literal: GOT slot for ic_enable_sniffer */
  ic_enable_sniffer(a2, a3, a4, a5); /* call via literal slot */ /* 00eb: callx8 a8 */
L_ee:;
  a3 = (uint32_t)&if_ctrl; /* 00ee: l32r a3, 0 <ic_set_vif-0x68> (0 <ic_set_vif-0x68>) */ /* literal @0x0: if_ctrl */
  a11 = a4 | a4; /* 00f1: or a11, a4, a4 */
  a10 = (a2 << 4) + a2; /* 00f4: addx4 a10, a2, a2 */
  a4 = (a2 << 4) + a2; /* 00f7: addx4 a4, a2, a2 */
  a10 = (a10 << 2) + a3; /* 00fa: addx2 a10, a10, a3 */
  a12 = 0x6; /* 00fd: movi.n a12, 6 */
  a3 = (a4 << 2) + a3; /* 00ff: addx2 a3, a4, a3 */
  a8 = (uint32_t)&memcpy; /* 0102: l32r a8, 40 <ic_set_vif-0x28> (0 <ic_set_vif-0x68>) */ /* literal: GOT slot for memcpy */
  memcpy(a2, a3, a4, a5); /* call via literal slot */ /* 0105: callx8 a8 */
  MEM8(a3 + 6) = a5; /* 0108: s8i a5, a3, 6 */
  a8 = 0x1; /* 010b: movi.n a8, 1 */
  /* 010d: ssl a2 */ /* UNMODELED: a2 clobbered */
  /* 0110: sll a8, a8 */ /* UNMODELED: a8 clobbered */
  MEM8(a3 + 7) = a6; /* 0113: s8i a6, a3, 7 */
  MEMW(); /* 0116: memw  */
  a3 = (uint32_t)&wDevCtrl; /* 0119: l32r a3, 10 <ic_set_vif-0x58> (0 <ic_set_vif-0x68>) */ /* literal @0x10: wDevCtrl */
  a4 = MEM8(a3 + 49); /* 011c: l8ui a4, a3, 49 */
  a8 = a8 | a4; /* 011f: or a8, a8, a4 */
  a8 = (a8 >> 0) & 0xFF; /* 0122: extui a8, a8, 0, 8 */
  MEM8(a3 + 49) = a8; /* 0125: s8i a8, a3, 49 */
  MEMW(); /* 0128: memw  */
  if (a8 == 0) goto L_142; /* 012b: beqz.n a8, 142 <ic_set_vif+0xda> */
  a4 = 0xFFFFFFFF; /* 012d: movi.n a4, -1 */
  a4 = 0x80000000; /* 012f: slli a4, a4, 31 */
  a5 = 0x3FF73084; /* 0132: l32r a5, 14 <ic_set_vif-0x54> (3ff73084 <ic_set_vif+0x3ff7301c>) */ /* MMIO base */ @0x14
  MEMW(); /* 0135: memw  */
  a3 = REG32(0x3FF73084); /* 0138: l32i.n a3, a5, 0 */ /* MMIO read: base 0x3FF73084+0 */
  a3 = a3 | a4; /* 013a: or a3, a3, a4 */
  MEMW(); /* 013d: memw  */
  REG32(0x3FF73084) = a3; /* 0140: s32i.n a3, a5, 0 */ /* MMIO write: base 0x3FF73084+0 */
L_142:;
  a11 = a7; /* 0142: mov.n a11, a7 */
  a10 = a2 | a2; /* 0144: or a10, a2, a2 */
  MEMW(); /* 0147: memw  */
  a8 = (uint32_t)&ic_disable_crypto; /* 014a: l32r a8, 44 <ic_set_vif-0x24> (0 <ic_set_vif-0x68>) */ /* literal: GOT slot for ic_disable_crypto */
  ic_disable_crypto(a2, a3, a4, a5); /* call via literal slot */ /* 014d: callx8 a8 */
  goto L_215; /* 0150: j 215 <ic_set_vif+0x1ad> */
  /* 0153: .byte 00 */
  /* 0154: .byte 00 */
L_155:;
  if (a3 == 1) goto L_15b; /* 0155: beqi a3, 1, 15b <ic_set_vif+0xf3> */
  goto L_204; /* 0158: j 204 <ic_set_vif+0x19c> */
L_15b:;
  a5 = (uint32_t)&wDevCtrl; /* 015b: l32r a5, 10 <ic_set_vif-0x58> (0 <ic_set_vif-0x68>) */ /* literal @0x10: wDevCtrl */
  a4 = MEM8(a5 + 49); /* 015e: l8ui a4, a5, 49 */
  if (!((a4 >> (a2 & 31)) & 1)) goto L_184; /* 0161: bbc a4, a2, 184 <ic_set_vif+0x11c> */
  /* 0164: ssl a2 */ /* UNMODELED: a2 clobbered */
  /* 0167: sll a3, a3 */ /* UNMODELED: a3 clobbered */
  a6 = 0xFFFFFFFF; /* 016a: movi.n a6, -1 */
  a3 = a6 ^ a3; /* 016c: xor a3, a6, a3 */
  a4 = a4 & a3; /* 016f: and a4, a4, a3 */
  a10 = a2 | a2; /* 0172: or a10, a2, a2 */
  MEM8(a5 + 49) = a4; /* 0175: s8i a4, a5, 49 */
  MEMW(); /* 0178: memw  */
  MEMW(); /* 017b: memw  */
  a8 = (uint32_t)&rc_disable_trc_by_interface; /* 017e: l32r a8, 48 <ic_set_vif-0x20> (0 <ic_set_vif-0x68>) */ /* literal: GOT slot for rc_disable_trc_by_interface */
  rc_disable_trc_by_interface(a2, a3, a4, a5); /* call via literal slot */ /* 0181: callx8 a8 */
L_184:;
  a3 = MEM8(a5 + 49); /* 0184: l8ui a3, a5, 49 */
  if (a3 != 0) goto L_1a5; /* 0187: bnez.n a3, 1a5 <ic_set_vif+0x13d> */
  a4 = 0x3FF73084; /* 0189: l32r a4, 14 <ic_set_vif-0x54> (3ff73084 <ic_set_vif+0x3ff7301c>) */ /* MMIO base */ @0x14
  a5 = 0x7FFFFFFF; /* 018c: l32r a5, 18 <ic_set_vif-0x50> (7fffffff <ic_set_vif+0x7fffff97>) */ @0x18
  MEMW(); /* 018f: memw  */
  a3 = REG32(0x3FF73084); /* 0192: l32i.n a3, a4, 0 */ /* MMIO read: base 0x3FF73084+0 */
  a3 = a3 & a5; /* 0194: and a3, a3, a5 */
  MEMW(); /* 0197: memw  */
  REG32(0x3FF73084) = a3; /* 019a: s32i.n a3, a4, 0 */ /* MMIO write: base 0x3FF73084+0 */
  MEMW(); /* 019c: memw  */
  a8 = (uint32_t)&pm_force_scan_unlock; /* 019f: l32r a8, 4c <ic_set_vif-0x1c> (0 <ic_set_vif-0x68>) */ /* literal: GOT slot for pm_force_scan_unlock */
  pm_force_scan_unlock(a2, a3, a4, a5); /* call via literal slot */ /* 01a2: callx8 a8 */
L_1a5:;
  if (a2 != 0) goto L_1bd; /* 01a5: bnez.n a2, 1bd <ic_set_vif+0x155> */
  a10 = 0x1; /* 01a7: movi.n a10, 1 */
  a14 = 0x2; /* 01a9: movi.n a14, 2 */
  a13 = (uint32_t)&lit_rodata_wlog_debug_6; /* 01ab: l32r a13, 1c <ic_set_vif-0x4c> (0 <ic_set_vif-0x68>) */ /* literal @0x1C: .rodata_wlog_debug.6 */
  a12 = 0x4; /* 01ae: movi.n a12, 4 */
  a11 = 0xC; /* 01b0: movi.n a11, 12 */
  a8 = (uint32_t)&wifi_log; /* 01b2: l32r a8, 50 <ic_set_vif-0x18> (0 <ic_set_vif-0x68>) */ /* literal: GOT slot for wifi_log */
  wifi_log(a2, a3, a4, a5); /* call via literal slot */ /* 01b5: callx8 a8 */
  a10 = 0x2; /* 01b8: movi.n a10, 2 */
  goto L_1ee; /* 01ba: j 1ee <ic_set_vif+0x186> */
L_1bd:;
  if (a2 != 2) goto L_1d8; /* 01bd: bnei a2, 2, 1d8 <ic_set_vif+0x170> */
  a14 = 0xC; /* 01c0: movi.n a14, 12 */
  a13 = (uint32_t)&lit_rodata_wlog_debug_7; /* 01c2: l32r a13, 20 <ic_set_vif-0x48> (0 <ic_set_vif-0x68>) */ /* literal @0x20: .rodata_wlog_debug.7 */
  a10 = 0x1; /* 01c5: movi.n a10, 1 */
  a12 = 0x4; /* 01c7: movi.n a12, 4 */
  a11 = 0xC; /* 01c9: mov.n a11, a14 */
  a8 = (uint32_t)&wifi_log; /* 01cb: l32r a8, 54 <ic_set_vif-0x14> (0 <ic_set_vif-0x68>) */ /* literal: GOT slot for wifi_log */
  wifi_log(a2, a3, a4, a5); /* call via literal slot */ /* 01ce: callx8 a8 */
  a10 = 0xC; /* 01d1: movi.n a10, 12 */
  goto L_1ee; /* 01d3: j 1ee <ic_set_vif+0x186> */
  /* 01d6: .byte 00 */
  /* 01d7: .byte 00 */
L_1d8:;
  if (a2 != 1) goto L_1f8; /* 01d8: bnei a2, 1, 1f8 <ic_set_vif+0x190> */
  a13 = (uint32_t)&lit_rodata_wlog_debug_8; /* 01db: l32r a13, 24 <ic_set_vif-0x44> (0 <ic_set_vif-0x68>) */ /* literal @0x24: .rodata_wlog_debug.8 */
  a10 = a2; /* 01de: mov.n a10, a2 */
  a14 = 0x9; /* 01e0: movi.n a14, 9 */
  a12 = 0x4; /* 01e2: movi.n a12, 4 */
  a11 = 0xC; /* 01e4: movi.n a11, 12 */
  a8 = (uint32_t)&wifi_log; /* 01e6: l32r a8, 58 <ic_set_vif-0x10> (0 <ic_set_vif-0x68>) */ /* literal: GOT slot for wifi_log */
  wifi_log(a2, a3, a4, a5); /* call via literal slot */ /* 01e9: callx8 a8 */
  a10 = 0x9; /* 01ec: movi.n a10, 9 */
L_1ee:;
  a8 = (uint32_t)&wifi_set_rx_policy; /* 01ee: l32r a8, 5c <ic_set_vif-0xc> (0 <ic_set_vif-0x68>) */ /* literal: GOT slot for wifi_set_rx_policy */
  wifi_set_rx_policy(a2, a3, a4, a5); /* call via literal slot */ /* 01f1: callx8 a8 */
  goto L_215; /* 01f4: j 215 <ic_set_vif+0x1ad> */
  /* 01f7: .byte 00 */
L_1f8:;
  if (a2 != 3) goto L_215; /* 01f8: bnei a2, 3, 215 <ic_set_vif+0x1ad> */
  a8 = (uint32_t)&ic_disable_sniffer; /* 01fb: l32r a8, 60 <ic_set_vif-0x8> (0 <ic_set_vif-0x68>) */ /* literal: GOT slot for ic_disable_sniffer */
  ic_disable_sniffer(a2, a3, a4, a5); /* call via literal slot */ /* 01fe: callx8 a8 */
  goto L_215; /* 0201: j 215 <ic_set_vif+0x1ad> */
L_204:;
  a12 = 0x1; /* 0204: movi.n a12, 1 */
  a13 = (uint32_t)&lit_rodata_wlog_error_9; /* 0206: l32r a13, 28 <ic_set_vif-0x40> (0 <ic_set_vif-0x68>) */ /* literal @0x28: .rodata_wlog_error.9 */
  a14 = a2; /* 0209: mov.n a14, a2 */
  a11 = 0x1; /* 020b: mov.n a11, a12 */
  a10 = 0x6; /* 020d: movi.n a10, 6 */
  a8 = (uint32_t)&wifi_log; /* 020f: l32r a8, 64 <ic_set_vif-0x4> (0 <ic_set_vif-0x68>) */ /* literal: GOT slot for wifi_log */
  wifi_log(a2, a3, a4, a5); /* call via literal slot */ /* 0212: callx8 a8 */
L_215:;
  return (int32_t)a2; /* 0215: retw.n  */
}

/* ic_get_next_tbtt @ if_hwctrl.o 00000004 size 13B bind GLOBAL
 * Calls: wDev_Get_Next_TBTT | Data refs: wDev_Get_Next_TBTT
 *   MMIO: none
 *   funcdb v3: 1 call(s), 1 ref(s); disasm: 1 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t ic_get_next_tbtt(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.ic_get_next_tbtt; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a8 = (uint32_t)&wDev_Get_Next_TBTT; /* 0007: l32r a8, 0 <ic_get_next_tbtt-0x4> (0 <ic_get_next_tbtt-0x4>) */ /* literal: GOT slot for wDev_Get_Next_TBTT */
  wDev_Get_Next_TBTT(a2, a3, a4, a5); /* call via literal slot */ /* 000a: callx8 a8 */
  a2 = a10; /* 000d: mov.n a2, a10 */
  return (int32_t)a2; /* 000f: retw.n  */
}

/* ic_get_next_bcnoffset @ if_hwctrl.o 00000004 size 13B bind GLOBAL
 * Calls: wDev_Get_Next_BcnOffset | Data refs: wDev_Get_Next_BcnOffset
 *   MMIO: none
 *   funcdb v3: 1 call(s), 1 ref(s); disasm: 1 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t ic_get_next_bcnoffset(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.ic_get_next_bcnoffset; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a8 = (uint32_t)&wDev_Get_Next_BcnOffset; /* 0007: l32r a8, 0 <ic_get_next_bcnoffset-0x4> (0 <ic_get_next_bcnoffset-0x4>) */ /* literal: GOT slot for wDev_Get_Next_BcnOffset */
  wDev_Get_Next_BcnOffset(a2, a3, a4, a5); /* call via literal slot */ /* 000a: callx8 a8 */
  a2 = a10; /* 000d: mov.n a2, a10 */
  return (int32_t)a2; /* 000f: retw.n  */
}

/* ic_del_rx_ba @ if_hwctrl.o 00000004 size 14B bind GLOBAL
 * Calls: hal_agreement_del_rx_ba | Data refs: hal_agreement_del_rx_ba
 *   MMIO: none
 *   funcdb v3: 1 call(s), 1 ref(s); disasm: 1 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t ic_del_rx_ba(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.ic_del_rx_ba; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a10 = (a2 >> 0) & 0xFF; /* 0007: extui a10, a2, 0, 8 */
  a8 = (uint32_t)&hal_agreement_del_rx_ba; /* 000a: l32r a8, 0 <ic_del_rx_ba-0x4> (0 <ic_del_rx_ba-0x4>) */ /* literal: GOT slot for hal_agreement_del_rx_ba */
  hal_agreement_del_rx_ba(a2, a3, a4, a5); /* call via literal slot */ /* 000d: callx8 a8 */
  return (int32_t)a2; /* 0010: retw.n  */
}

/* ic_reset_rx_ba @ if_hwctrl.o 00000004 size 23B bind GLOBAL
 * Calls: hal_agreement_clr_rx_ba | Data refs: hal_agreement_clr_rx_ba
 *   MMIO: none
 *   funcdb v3: 1 call(s), 1 ref(s); disasm: 1 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t ic_reset_rx_ba(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.ic_reset_rx_ba; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a13 = (a5 >> 0) & 0xFF; /* 0007: extui a13, a5, 0, 8 */
  a12 = (a4 >> 0) & 0xFFFF; /* 000a: extui a12, a4, 0, 16 */
  a11 = (a3 >> 0) & 0xFF; /* 000d: extui a11, a3, 0, 8 */
  a10 = (a2 >> 0) & 0xFF; /* 0010: extui a10, a2, 0, 8 */
  a8 = (uint32_t)&hal_agreement_clr_rx_ba; /* 0013: l32r a8, 0 <ic_reset_rx_ba-0x4> (0 <ic_reset_rx_ba-0x4>) */ /* literal: GOT slot for hal_agreement_clr_rx_ba */
  hal_agreement_clr_rx_ba(a2, a3, a4, a5); /* call via literal slot */ /* 0016: callx8 a8 */
  return (int32_t)a2; /* 0019: retw.n  */
}

/* ic_add_rx_ba @ if_hwctrl.o 00000004 size 28B bind GLOBAL
 * Calls: hal_agreement_add_rx_ba | Data refs: hal_agreement_add_rx_ba
 *   MMIO: none
 *   funcdb v3: 1 call(s), 1 ref(s); disasm: 1 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t ic_add_rx_ba(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.ic_add_rx_ba; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a15 = (a7 >> 0) & 0xFF; /* 0007: extui a15, a7, 0, 8 */
  a14 = (a6 >> 0) & 0xFFFF; /* 000a: extui a14, a6, 0, 16 */
  a13 = (a5 >> 0) & 0xFF; /* 000d: extui a13, a5, 0, 8 */
  a12 = a4; /* 0010: mov.n a12, a4 */
  a11 = (a2 >> 0) & 0xFF; /* 0012: extui a11, a2, 0, 8 */
  a10 = (a3 >> 0) & 0xFF; /* 0015: extui a10, a3, 0, 8 */
  a8 = (uint32_t)&hal_agreement_add_rx_ba; /* 0018: l32r a8, 0 <ic_add_rx_ba-0x4> (0 <ic_add_rx_ba-0x4>) */ /* literal: GOT slot for hal_agreement_add_rx_ba */
  hal_agreement_add_rx_ba(a2, a3, a4, a5); /* call via literal slot */ /* 001b: callx8 a8 */
  return (int32_t)a2; /* 001e: retw.n  */
}

/* ic_reset_tbtt @ if_hwctrl.o 00000004 size 11B bind GLOBAL
 * Calls: wDev_Reset_TBTT | Data refs: wDev_Reset_TBTT
 *   MMIO: none
 *   funcdb v3: 1 call(s), 1 ref(s); disasm: 1 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t ic_reset_tbtt(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.ic_reset_tbtt; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a8 = (uint32_t)&wDev_Reset_TBTT; /* 0007: l32r a8, 0 <ic_reset_tbtt-0x4> (0 <ic_reset_tbtt-0x4>) */ /* literal: GOT slot for wDev_Reset_TBTT */
  wDev_Reset_TBTT(a2, a3, a4, a5); /* call via literal slot */ /* 000a: callx8 a8 */
  return (int32_t)a2; /* 000d: retw.n  */
}

/* ic_del_key_all @ if_hwctrl.o 00000004 size 16B bind GLOBAL
 * Calls: wDev_remove_KeyEntry_all_cnx | Data refs: wDev_remove_KeyEntry_all_cnx
 *   MMIO: none
 *   funcdb v3: 1 call(s), 1 ref(s); disasm: 1 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t ic_del_key_all(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.ic_del_key_all; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a11 = a3; /* 0007: mov.n a11, a3 */
  a10 = (a2 >> 0) & 0xFF; /* 0009: extui a10, a2, 0, 8 */
  a8 = (uint32_t)&wDev_remove_KeyEntry_all_cnx; /* 000c: l32r a8, 0 <ic_del_key_all-0x4> (0 <ic_del_key_all-0x4>) */ /* literal: GOT slot for wDev_remove_KeyEntry_all_cnx */
  wDev_remove_KeyEntry_all_cnx(a2, a3, a4, a5); /* call via literal slot */ /* 000f: callx8 a8 */
  return (int32_t)a2; /* 0012: retw.n  */
}

/* ic_del_key @ if_hwctrl.o 00000008 size 32B bind GLOBAL
 * Calls: wDev_remove_KeyEntry, g_osi_funcs_p[got] | Data refs: g_osi_funcs_p, wDev_remove_KeyEntry
 *   MMIO: none
 *   funcdb v3: 1 call(s), 2 ref(s); disasm: 2 call(s), 2 data ref(s)
 * Fidelity: medium - 12 instr, 0 branches, calls resolved */
int32_t ic_del_key(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.ic_del_key; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_8:;
  /* 0008: entry a1, 32 */
  a3 = (uint32_t)&g_osi_funcs_p; /* 000b: l32r a3, 0 <ic_del_key-0x8> (0 <ic_del_key-0x8>) */ /* literal @0x0: g_osi_funcs_p */
  a8 = MEM32(a3 + 0); /* 000e: l32i.n a8, a3, 0 */
  a8 = MEM32(a8 + 216); /* 0010: l32i a8, a8, 216 */
  ((int32_t(*)())a8)(a2, a3, a4, a5); /* 0013: callx8 a8 */ /* indirect */
  a10 = a2; /* 0016: mov.n a10, a2 */
  a8 = (uint32_t)&wDev_remove_KeyEntry; /* 0018: l32r a8, 4 <ic_del_key-0x4> (0 <ic_del_key-0x8>) */ /* literal: GOT slot for wDev_remove_KeyEntry */
  wDev_remove_KeyEntry(a2, a3, a4, a5); /* call via literal slot */ /* 001b: callx8 a8 */
  a3 = MEM32(a3 + 0); /* 001e: l32i.n a3, a3, 0 */
  a3 = MEM32(a3 + 220); /* 0020: l32i a3, a3, 220 */
  g_osi_funcs_p(a2, a3, a4, a5); /* call via literal slot */ /* 0023: callx8 a3 */
  return (int32_t)a2; /* 0026: retw.n  */
}

/* ic_set_ac_param @ if_hwctrl.o 00000004 size 26B bind GLOBAL
 * Calls: lmacSetAcParam | Data refs: lmacSetAcParam
 *   MMIO: none
 *   funcdb v3: 1 call(s), 1 ref(s); disasm: 1 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t ic_set_ac_param(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.ic_set_ac_param; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a14 = (a6 >> 0) & 0xFFFF; /* 0007: extui a14, a6, 0, 16 */
  a13 = (a5 >> 0) & 0xFF; /* 000a: extui a13, a5, 0, 8 */
  a12 = (a4 >> 0) & 0xFF; /* 000d: extui a12, a4, 0, 8 */
  a11 = (a3 >> 0) & 0xFF; /* 0010: extui a11, a3, 0, 8 */
  a10 = (a2 >> 0) & 0xFF; /* 0013: extui a10, a2, 0, 8 */
  a8 = (uint32_t)&lmacSetAcParam; /* 0016: l32r a8, 0 <ic_set_ac_param-0x4> (0 <ic_set_ac_param-0x4>) */ /* literal: GOT slot for lmacSetAcParam */
  lmacSetAcParam(a2, a3, a4, a5); /* call via literal slot */ /* 0019: callx8 a8 */
  return (int32_t)a2; /* 001c: retw.n  */
}

/* ic_ampdu_op @ if_hwctrl.o 00000008 size 36B bind GLOBAL
 * Calls: rc_get_trc_by_index, trc_onAmpduOp | Data refs: rc_get_trc_by_index, trc_onAmpduOp
 *   MMIO: none
 *   funcdb v3: 2 call(s), 2 ref(s); disasm: 2 call(s), 2 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t ic_ampdu_op(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.ic_ampdu_op; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_8:;
  /* 0008: entry a1, 32 */
  a11 = (a3 >> 0) & 0xFF; /* 000b: extui a11, a3, 0, 8 */
  a10 = (a2 >> 0) & 0xFF; /* 000e: extui a10, a2, 0, 8 */
  a8 = (uint32_t)&rc_get_trc_by_index; /* 0011: l32r a8, 0 <ic_ampdu_op-0x8> (0 <ic_ampdu_op-0x8>) */ /* literal: GOT slot for rc_get_trc_by_index */
  rc_get_trc_by_index(a2, a3, a4, a5); /* call via literal slot */ /* 0014: callx8 a8 */
  a4 = (a4 >> 0) & 0xFF; /* 0017: extui a4, a4, 0, 8 */
  a12 = a4; /* 001a: mov.n a12, a4 */
  a11 = 0x2; /* 001c: movi a11, 2 */
  if (a5 == 1) goto L_24; /* 001f: beqi a5, 1, 24 <ic_ampdu_op+0x1c> */
  a11 = 0x1; /* 0022: movi.n a11, 1 */
L_24:;
  a8 = (uint32_t)&trc_onAmpduOp; /* 0024: l32r a8, 4 <ic_ampdu_op-0x4> (0 <ic_ampdu_op-0x8>) */ /* literal: GOT slot for trc_onAmpduOp */
  trc_onAmpduOp(a2, a3, a4, a5); /* call via literal slot */ /* 0027: callx8 a8 */
  return (int32_t)a2; /* 002a: retw.n  */
}

/* esp_mesh_set_6m_rate @ if_hwctrl.o 00000004 size 19B bind GLOBAL
 * Calls: none | Data refs: s_is_6m
 *   MMIO: none
 *   funcdb v3: 0 call(s), 1 ref(s); disasm: 0 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t esp_mesh_set_6m_rate(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.esp_mesh_set_6m_rate; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a8 = (uint32_t)&s_is_6m; /* 0007: l32r a8, 0 <esp_mesh_set_6m_rate-0x4> (0 <esp_mesh_set_6m_rate-0x4>) */ /* literal @0x0: s_is_6m */
  MEM8(a8 + 0) = a2; /* 000a: s8i a2, a8, 0 */
  MEMW(); /* 000d: memw  */
  a2 = 0x0; /* 0010: movi.n a2, 0 */
  MEMW(); /* 0012: memw  */
  return (int32_t)a2; /* 0015: retw.n  */
}

/* ic_set_trc @ if_hwctrl.o 00000020 size 176B bind GLOBAL
 * Calls: rcUpdateAMPDUParam, rcUpdatePhyMode, rc_disable_trc, rc_enable_trc | Data refs: g_mesh_is_root, g_mesh_is_started, if_ctrl, rcUpdateAMPDUParam, rcUpdatePhyMode, rc_disable_trc, rc_enable_trc, s_is_6m
 *   MMIO: none
 *   funcdb v3: 4 call(s), 8 ref(s); disasm: 4 call(s), 8 data ref(s)
 * Fidelity: medium - 63 instr, 9 branches, calls resolved */
int32_t ic_set_trc(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.ic_set_trc; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_20:;
  /* 0020: entry a1, 32 */
  a3 = MEM8(a2 + 0); /* 0023: l8ui a3, a2, 0 */
  a10 = MEM8(a2 + 1); /* 0026: l8ui a10, a2, 1 */
  a11 = MEM32(a2 + 4); /* 0029: l32i a11, a2, 4 */
  a12 = MEM8(a2 + 8); /* 002c: l8ui a12, a2, 8 */
  if (a3 == 0) goto L_c8; /* 002f: beqz a3, c8 <ic_set_trc+0xa8> */
  a13 = MEM8(a2 + 10); /* 0032: l8ui a13, a2, 10 */
  a4 = MEM32(a2 + 20); /* 0035: l32i a4, a2, 20 */
  a8 = (uint32_t)&rc_enable_trc; /* 0038: l32r a8, 10 <ic_set_trc-0x10> (0 <ic_set_trc-0x20>) */ /* literal: GOT slot for rc_enable_trc */
  rc_enable_trc(a2, a3, a4, a5); /* call via literal slot */ /* 003b: callx8 a8 */
  a3 = a10; /* 003e: mov.n a3, a10 */
  if (a10 == 0) goto L_ce; /* 0040: beqz a10, ce <ic_set_trc+0xae> */
  a8 = MEM8(a2 + 1); /* 0043: l8ui a8, a2, 1 */
  a9 = (a8 << 4) + a8; /* 0046: addx4 a9, a8, a8 */
  a5 = (uint32_t)&if_ctrl; /* 0049: l32r a5, 0 <ic_set_trc-0x20> (0 <ic_set_trc-0x20>) */ /* literal @0x0: if_ctrl */
  a9 = (a9 << 2) + a5; /* 004c: addx2 a9, a9, a5 */
  a5 = MEM8(a9 + 7); /* 004f: l8ui a5, a9, 7 */
  a9 = (uint32_t)&g_mesh_is_started; /* 0052: l32r a9, 4 <ic_set_trc-0x1c> (0 <ic_set_trc-0x20>) */ /* literal @0x4: g_mesh_is_started */
  a9 = MEM8(a9 + 0); /* 0055: l8ui a9, a9, 0 */
  if (a9 == 0) goto L_74; /* 0058: beqz.n a9, 74 <ic_set_trc+0x54> */
  if (a8 == 0) goto L_65; /* 005a: beqz.n a8, 65 <ic_set_trc+0x45> */
L_5c:;
  a5 = (uint32_t)&s_is_6m; /* 005c: l32r a5, 8 <ic_set_trc-0x18> (0 <ic_set_trc-0x20>) */ /* literal @0x8: s_is_6m */
  a5 = MEM8(a5 + 0); /* 005f: l8ui a5, a5, 0 */
  goto L_74; /* 0062: j 74 <ic_set_trc+0x54> */
L_65:;
  a8 = (uint32_t)&g_mesh_is_root; /* 0065: l32r a8, c <ic_set_trc-0x14> (0 <ic_set_trc-0x20>) */ /* literal @0xC: g_mesh_is_root */
  MEMW(); /* 0068: memw  */
  a8 = MEM8(a8 + 0); /* 006b: l8ui a8, a8, 0 */
  a8 = (a8 >> 0) & 0xFF; /* 006e: extui a8, a8, 0, 8 */
  if (a8 == 0) goto L_5c; /* 0071: beqz a8, 5c <ic_set_trc+0x3c> */
L_74:;
  a10 = a3; /* 0074: mov.n a10, a3 */
  a12 = MEM8(a2 + 26); /* 0076: l8ui a12, a2, 26 */
  a13 = (a12 >> 2) & 0x7; /* 0079: extui a13, a12, 2, 3 */
  a12 = (a12 >> 0) & 0x3; /* 007c: extui a12, a12, 0, 2 */
  a11 = MEM8(a2 + 12); /* 007f: l8ui a11, a2, 12 */
  a8 = (uint32_t)&rcUpdateAMPDUParam; /* 0082: l32r a8, 14 <ic_set_trc-0xc> (0 <ic_set_trc-0x20>) */ /* literal: GOT slot for rcUpdateAMPDUParam */
  rcUpdateAMPDUParam(a2, a3, a4, a5); /* call via literal slot */ /* 0085: callx8 a8 */
  a8 = MEM8(a2 + 12); /* 0088: l8ui a8, a2, 12 */
  MEM8(a3 + 130) = a8; /* 008b: s8i a8, a3, 130 */
  MEMW(); /* 008e: memw  */
  if (a4 == 0) goto L_a9; /* 0091: beqz.n a4, a9 <ic_set_trc+0x89> */
  a8 = MEM8(a4 + 1); /* 0093: l8ui a8, a4, 1 */
  MEM8(a3 + 135) = a8; /* 0096: s8i a8, a3, 135 */
  MEMW(); /* 0099: memw  */
  a4 = MEM8(a4 + 0); /* 009c: l8ui a4, a4, 0 */
  if (a4 == 0) goto L_a9; /* 009f: beqz.n a4, a9 <ic_set_trc+0x89> */
  a4 = 0x6; /* 00a1: movi.n a4, 6 */
  MEM8(a3 + 130) = a4; /* 00a3: s8i a4, a3, 130 */
  MEMW(); /* 00a6: memw  */
L_a9:;
  a12 = a5; /* 00a9: mov.n a12, a5 */
  a10 = a3; /* 00ab: mov.n a10, a3 */
  a11 = MEM32(a2 + 16); /* 00ad: l32i.n a11, a2, 16 */
  a11 = a11 + (96); /* 00af: addi a11, a11, 96 */
  a11 = ((int32_t)(a11 << (32 - (7 & 31)))) >> (32 - (7 & 31)); /* 00b2: sext a11, a11, 7 */
  a14 = MEM8(a2 + 25); /* 00b5: l8ui a14, a2, 25 */
  a13 = MEM8(a2 + 24); /* 00b8: l8ui a13, a2, 24 */
  MEMW(); /* 00bb: memw  */
  a8 = (uint32_t)&rcUpdatePhyMode; /* 00be: l32r a8, 18 <ic_set_trc-0x8> (0 <ic_set_trc-0x20>) */ /* literal: GOT slot for rcUpdatePhyMode */
  rcUpdatePhyMode(a2, a3, a4, a5); /* call via literal slot */ /* 00c1: callx8 a8 */
  goto L_ce; /* 00c4: j ce <ic_set_trc+0xae> */
  /* 00c7: .byte 00 */
L_c8:;
  a8 = (uint32_t)&rc_disable_trc; /* 00c8: l32r a8, 1c <ic_set_trc-0x4> (0 <ic_set_trc-0x20>) */ /* literal: GOT slot for rc_disable_trc */
  rc_disable_trc(a2, a3, a4, a5); /* call via literal slot */ /* 00cb: callx8 a8 */
L_ce:;
  return (int32_t)a2; /* 00ce: retw.n  */
}

/* ic_bb_check_noise_init @ if_hwctrl.o 00000010 size 52B bind GLOBAL
 * Calls: wifi_log, g_osi_funcs_p[got] | Data refs: .rodata_wlog_info.10, bb_intr_handl, g_osi_funcs_p, wifi_log
 *   MMIO: none
 *   funcdb v3: 1 call(s), 4 ref(s); disasm: 3 call(s), 4 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t ic_bb_check_noise_init(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.ic_bb_check_noise_init; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_10:;
  /* 0010: entry a1, 32 */
  a13 = (uint32_t)&lit_rodata_wlog_info_10; /* 0013: l32r a13, 0 <ic_bb_check_noise_init-0x10> (0 <ic_bb_check_noise_init-0x10>) */ /* literal @0x0: .rodata_wlog_info.10 */
  a11 = 0x1; /* 0016: movi.n a11, 1 */
  a12 = 0x3; /* 0018: movi.n a12, 3 */
  a11 = 0x800; /* 001a: slli a11, a11, 11 */
  a10 = 0x6; /* 001d: movi.n a10, 6 */
  a8 = (uint32_t)&wifi_log; /* 001f: l32r a8, c <ic_bb_check_noise_init-0x4> (0 <ic_bb_check_noise_init-0x10>) */ /* literal: GOT slot for wifi_log */
  wifi_log(a2, a3, a4, a5); /* call via literal slot */ /* 0022: callx8 a8 */
  a2 = (uint32_t)&g_osi_funcs_p; /* 0025: l32r a2, 8 <ic_bb_check_noise_init-0x8> (0 <ic_bb_check_noise_init-0x10>) */ /* literal @0x8: g_osi_funcs_p */
  a12 = 0x0; /* 0028: movi.n a12, 0 */
  a10 = 0x9; /* 002a: movi.n a10, 9 */
  a8 = MEM32(a2 + 0); /* 002c: l32i a8, a2, 0 */
  a11 = (uint32_t)&bb_intr_handl; /* 002f: l32r a11, 4 <ic_bb_check_noise_init-0xc> (0 <ic_bb_check_noise_init-0x10>) */ /* literal @0x4: bb_intr_handl */
  a8 = MEM32(a8 + 16); /* 0032: l32i a8, a8, 16 */
  wifi_log(a2, a3, a4, a5); /* call via literal slot */ /* 0035: callx8 a8 */
  a10 = 0x200; /* 0038: movi a10, 0x200 */
  a2 = MEM32(a2 + 0); /* 003b: l32i.n a2, a2, 0 */
  a2 = MEM32(a2 + 20); /* 003d: l32i.n a2, a2, 20 */
  g_osi_funcs_p(a2, a3, a4, a5); /* call via literal slot */ /* 003f: callx8 a2 */
  return (int32_t)a2; /* 0042: retw.n  */
}

/* ic_deinit @ if_hwctrl.o 00000010 size 31B bind GLOBAL
 * Calls: pm_deattach, pp_deattach, trc_deinit, wDev_Rxbuf_Deinit | Data refs: pm_deattach, pp_deattach, trc_deinit, wDev_Rxbuf_Deinit
 *   MMIO: none
 *   funcdb v3: 4 call(s), 4 ref(s); disasm: 4 call(s), 4 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t ic_deinit(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.ic_deinit; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_10:;
  /* 0010: entry a1, 32 */
  a8 = (uint32_t)&pm_deattach; /* 0013: l32r a8, 0 <ic_deinit-0x10> (0 <ic_deinit-0x10>) */ /* literal: GOT slot for pm_deattach */
  pm_deattach(a2, a3, a4, a5); /* call via literal slot */ /* 0016: callx8 a8 */
  a8 = (uint32_t)&wDev_Rxbuf_Deinit; /* 0019: l32r a8, 4 <ic_deinit-0xc> (0 <ic_deinit-0x10>) */ /* literal: GOT slot for wDev_Rxbuf_Deinit */
  wDev_Rxbuf_Deinit(a2, a3, a4, a5); /* call via literal slot */ /* 001c: callx8 a8 */
  a8 = (uint32_t)&pp_deattach; /* 001f: l32r a8, 8 <ic_deinit-0x8> (0 <ic_deinit-0x10>) */ /* literal: GOT slot for pp_deattach */
  pp_deattach(a2, a3, a4, a5); /* call via literal slot */ /* 0022: callx8 a8 */
  a8 = (uint32_t)&trc_deinit; /* 0025: l32r a8, c <ic_deinit-0x4> (0 <ic_deinit-0x10>) */ /* literal: GOT slot for trc_deinit */
  trc_deinit(a2, a3, a4, a5); /* call via literal slot */ /* 0028: callx8 a8 */
  a2 = 0x0; /* 002b: movi.n a2, 0 */
  return (int32_t)a2; /* 002d: retw.n  */
}

/* ic_init @ if_hwctrl.o 0000002c size 108B bind GLOBAL
 * Calls: ic_deinit, lmacInit, pm_attach, pm_enable_sta_disconnected_power_management, pp_attach, trc_init, wDev_Rxbuf_Init, g_osi_funcs_p[got] | Data refs: esp_wifi_internal_on_coex_schm_phase, esp_wifi_internal_on_coex_start, g_osi_funcs_p, g_wifi_menuconfig, ic_deinit, lmacInit, pm_attach, pm_enable_sta_disconnected_power_management, pp_attach, trc_init, wDev_Rxbuf_Init
 *   MMIO: none
 *   funcdb v3: 7 call(s), 11 ref(s); disasm: 9 call(s), 11 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t ic_init(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.ic_init; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_2c:;
  /* 002c: entry a1, 32 */
  a10 = (a4 >> 0) & 0xFF; /* 002f: extui a10, a4, 0, 8 */
  a8 = (uint32_t)&trc_init; /* 0032: l32r a8, 10 <ic_init-0x1c> (0 <ic_init-0x2c>) */ /* literal: GOT slot for trc_init */
  trc_init(a2, a3, a4, a5); /* call via literal slot */ /* 0035: callx8 a8 */
  a8 = (uint32_t)&lmacInit; /* 0038: l32r a8, 14 <ic_init-0x18> (0 <ic_init-0x2c>) */ /* literal: GOT slot for lmacInit */
  lmacInit(a2, a3, a4, a5); /* call via literal slot */ /* 003b: callx8 a8 */
  a10 = a3; /* 003e: mov.n a10, a3 */
  a8 = (uint32_t)&pp_attach; /* 0040: l32r a8, 18 <ic_init-0x14> (0 <ic_init-0x2c>) */ /* literal: GOT slot for pp_attach */
  pp_attach(a2, a3, a4, a5); /* call via literal slot */ /* 0043: callx8 a8 */
  a5 = a2; /* 0046: mov.n a5, a2 */
  a2 = a10 | a10; /* 0048: or a2, a10, a10 */
  if (a10 != 0) goto L_90; /* 004b: bnez a10, 90 <ic_init+0x64> */
  a10 = a5; /* 004e: mov.n a10, a5 */
  a8 = (uint32_t)&wDev_Rxbuf_Init; /* 0050: l32r a8, 1c <ic_init-0x10> (0 <ic_init-0x2c>) */ /* literal: GOT slot for wDev_Rxbuf_Init */
  wDev_Rxbuf_Init(a2, a3, a4, a5); /* call via literal slot */ /* 0053: callx8 a8 */
  a2 = a10; /* 0056: mov.n a2, a10 */
  if (a10 != 0) goto L_90; /* 0058: bnez.n a10, 90 <ic_init+0x64> */
  a8 = (uint32_t)&pm_attach; /* 005a: l32r a8, 20 <ic_init-0xc> (0 <ic_init-0x2c>) */ /* literal: GOT slot for pm_attach */
  pm_attach(a2, a3, a4, a5); /* call via literal slot */ /* 005d: callx8 a8 */
  a3 = (uint32_t)&g_osi_funcs_p; /* 0060: l32r a3, 4 <ic_init-0x28> (0 <ic_init-0x2c>) */ /* literal @0x4: g_osi_funcs_p */
  a8 = MEM32(a3 + 0); /* 0063: l32i.n a8, a3, 0 */
  a10 = (uint32_t)&esp_wifi_internal_on_coex_start; /* 0065: l32r a10, 0 <ic_init-0x2c> (0 <ic_init-0x2c>) */ /* literal @0x0: esp_wifi_internal_on_coex_start */
  a8 = MEM32(a8 + 464); /* 0068: l32i a8, a8, 0x1d0 */
  pm_attach(a2, a3, a4, a5); /* call via literal slot */ /* 006b: callx8 a8 */
  a10 = a2; /* 006e: mov.n a10, a2 */
  a3 = MEM32(a3 + 0); /* 0070: l32i a3, a3, 0 */
  a11 = (uint32_t)&esp_wifi_internal_on_coex_schm_phase; /* 0073: l32r a11, 8 <ic_init-0x24> (0 <ic_init-0x2c>) */ /* literal @0x8: esp_wifi_internal_on_coex_schm_phase */
  a3 = MEM32(a3 + 460); /* 0076: l32i a3, a3, 0x1cc */
  g_osi_funcs_p(a2, a3, a4, a5); /* call via literal slot */ /* 0079: callx8 a3 */
  a3 = (uint32_t)&g_wifi_menuconfig; /* 007c: l32r a3, c <ic_init-0x20> (0 <ic_init-0x2c>) */ /* literal @0xC: g_wifi_menuconfig */
  a3 = MEM8(a3 + 72); /* 007f: l8ui a3, a3, 72 */
  if (a3 == 0) goto L_96; /* 0082: beqz.n a3, 96 <ic_init+0x6a> */
  a10 = 0x1; /* 0084: movi.n a10, 1 */
  a8 = (uint32_t)&pm_enable_sta_disconnected_power_management; /* 0086: l32r a8, 24 <ic_init-0x8> (0 <ic_init-0x2c>) */ /* literal: GOT slot for pm_enable_sta_disconnected_power_management */
  pm_enable_sta_disconnected_power_management(a2, a3, a4, a5); /* call via literal slot */ /* 0089: callx8 a8 */
  goto L_96; /* 008c: j 96 <ic_init+0x6a> */
  /* 008f: .byte 00 */
L_90:;
  a8 = (uint32_t)&ic_deinit; /* 0090: l32r a8, 28 <ic_init-0x4> (0 <ic_init-0x2c>) */ /* literal: GOT slot for ic_deinit */
  ic_deinit(a2, a3, a4, a5); /* call via literal slot */ /* 0093: callx8 a8 */
L_96:;
  return (int32_t)a2; /* 0096: retw.n  */
}

/* ic_set_interrupt_handler @ if_hwctrl.o 00000010 size 55B bind GLOBAL
 * Calls: hal_init, g_osi_funcs_p[got] | Data refs: g_osi_funcs_p, g_wifi_menuconfig, hal_init, wDev_ProcessFiq
 *   MMIO: none
 *   funcdb v3: 1 call(s), 4 ref(s); disasm: 4 call(s), 4 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t ic_set_interrupt_handler(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.ic_set_interrupt_handler; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_10:;
  /* 0010: entry a1, 32 */
  a8 = (uint32_t)&hal_init; /* 0013: l32r a8, c <ic_set_interrupt_handler-0x4> (0 <ic_set_interrupt_handler-0x10>) */ /* literal: GOT slot for hal_init */
  hal_init(a2, a3, a4, a5); /* call via literal slot */ /* 0016: callx8 a8 */
  a2 = (uint32_t)&g_osi_funcs_p; /* 0019: l32r a2, 4 <ic_set_interrupt_handler-0xc> (0 <ic_set_interrupt_handler-0x10>) */ /* literal @0x4: g_osi_funcs_p */
  a12 = 0x0; /* 001c: movi.n a12, 0 */
  a13 = 0x1; /* 001e: movi.n a13, 1 */
  a11 = 0x0; /* 0020: mov.n a11, a12 */
  a9 = (uint32_t)&g_wifi_menuconfig; /* 0022: l32r a9, 0 <ic_set_interrupt_handler-0x10> (0 <ic_set_interrupt_handler-0x10>) */ /* literal @0x0: g_wifi_menuconfig */
  a8 = MEM32(a2 + 0); /* 0025: l32i.n a8, a2, 0 */
  a10 = MEM32(a9 + 52); /* 0027: l32i.n a10, a9, 52 */
  a8 = MEM32(a8 + 8); /* 0029: l32i.n a8, a8, 8 */
  hal_init(a2, a3, a4, a5); /* call via literal slot */ /* 002b: callx8 a8 */
  a12 = 0x0; /* 002e: movi.n a12, 0 */
  a10 = 0x0; /* 0030: mov.n a10, a12 */
  a8 = MEM32(a2 + 0); /* 0032: l32i.n a8, a2, 0 */
  a11 = (uint32_t)&wDev_ProcessFiq; /* 0034: l32r a11, 8 <ic_set_interrupt_handler-0x8> (0 <ic_set_interrupt_handler-0x10>) */ /* literal @0x8: wDev_ProcessFiq */
  a8 = MEM32(a8 + 16); /* 0037: l32i.n a8, a8, 16 */
  hal_init(a2, a3, a4, a5); /* call via literal slot */ /* 0039: callx8 a8 */
  a10 = 0x1; /* 003c: movi.n a10, 1 */
  a2 = MEM32(a2 + 0); /* 003e: l32i.n a2, a2, 0 */
  a2 = MEM32(a2 + 20); /* 0040: l32i.n a2, a2, 20 */
  g_osi_funcs_p(a2, a3, a4, a5); /* call via literal slot */ /* 0042: callx8 a2 */
  return (int32_t)a2; /* 0045: retw.n  */
}

/* ic_clear_interrupt_handler @ if_hwctrl.o 00000008 size 48B bind GLOBAL
 * Calls: hal_deinit, g_osi_funcs_p[got] | Data refs: g_osi_funcs_p, hal_deinit
 *   MMIO: none
 *   funcdb v3: 1 call(s), 2 ref(s); disasm: 2 call(s), 2 data ref(s)
 * Fidelity: medium - 20 instr, 0 branches, calls resolved */
int32_t ic_clear_interrupt_handler(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.ic_clear_interrupt_handler; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_8:;
  /* 0008: entry a1, 32 */
  a2 = (uint32_t)&g_osi_funcs_p; /* 000b: l32r a2, 0 <ic_clear_interrupt_handler-0x8> (0 <ic_clear_interrupt_handler-0x8>) */ /* literal @0x0: g_osi_funcs_p */
  a10 = 0x1; /* 000e: movi.n a10, 1 */
  a8 = MEM32(a2 + 0); /* 0010: l32i.n a8, a2, 0 */
  a8 = MEM32(a8 + 24); /* 0012: l32i a8, a8, 24 */
  ((int32_t(*)())a8)(a2, a3, a4, a5); /* 0015: callx8 a8 */ /* indirect */
  a12 = 0x0; /* 0018: movi.n a12, 0 */
  a11 = 0x0; /* 001a: mov.n a11, a12 */
  a8 = MEM32(a2 + 0); /* 001c: l32i.n a8, a2, 0 */
  a10 = 0x0; /* 001e: mov.n a10, a12 */
  a8 = MEM32(a8 + 16); /* 0020: l32i.n a8, a8, 16 */
  ((int32_t(*)())a8)(a2, a3, a4, a5); /* 0022: callx8 a8 */ /* indirect */
  a11 = 0x0; /* 0025: movi.n a11, 0 */
  a10 = 0x0; /* 0027: mov.n a10, a11 */
  a2 = MEM32(a2 + 0); /* 0029: l32i.n a2, a2, 0 */
  a2 = MEM32(a2 + 12); /* 002b: l32i.n a2, a2, 12 */
  g_osi_funcs_p(a2, a3, a4, a5); /* call via literal slot */ /* 002d: callx8 a2 */
  a8 = (uint32_t)&hal_deinit; /* 0030: l32r a8, 4 <ic_clear_interrupt_handler-0x4> (0 <ic_clear_interrupt_handler-0x8>) */ /* literal: GOT slot for hal_deinit */
  hal_deinit(a2, a3, a4, a5); /* call via literal slot */ /* 0033: callx8 a8 */
  return (int32_t)a2; /* 0036: retw.n  */
}

/* ic_enable_rx @ if_hwctrl.o 00000004 size 29B bind GLOBAL
 * Calls: none | Data refs: none
 *   MMIO: 0x3FF73084
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t ic_enable_rx(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.ic_enable_rx; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a10 = 0x3FF73084; /* 0007: l32r a10, 0 <ic_enable_rx-0x4> (3ff73084 <ic_set_vif+0x3ff7301c>) */ /* MMIO base */ @0x0
  a9 = 0xFFFFFFFF; /* 000a: movi.n a9, -1 */
  a9 = 0x80000000; /* 000c: slli a9, a9, 31 */
  MEMW(); /* 000f: memw  */
  a8 = REG32(0x3FF73084); /* 0012: l32i.n a8, a10, 0 */ /* MMIO read: base 0x3FF73084+0 */
  a8 = a8 | a9; /* 0014: or a8, a8, a9 */
  MEMW(); /* 0017: memw  */
  REG32(0x3FF73084) = a8; /* 001a: s32i.n a8, a10, 0 */ /* MMIO write: base 0x3FF73084+0 */
  MEMW(); /* 001c: memw  */
  return (int32_t)a2; /* 001f: retw.n  */
}

/* ic_disable_rx @ if_hwctrl.o 00000008 size 27B bind GLOBAL
 * Calls: none | Data refs: none
 *   MMIO: 0x3FF73084
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t ic_disable_rx(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.ic_disable_rx; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_8:;
  /* 0008: entry a1, 32 */
  a9 = 0x3FF73084; /* 000b: l32r a9, 0 <ic_disable_rx-0x8> (3ff73084 <ic_set_vif+0x3ff7301c>) */ /* MMIO base */ @0x0
  a10 = 0x7FFFFFFF; /* 000e: l32r a10, 4 <ic_disable_rx-0x4> (7fffffff <ic_set_vif+0x7fffff97>) */ @0x4
  MEMW(); /* 0011: memw  */
  a8 = REG32(0x3FF73084); /* 0014: l32i.n a8, a9, 0 */ /* MMIO read: base 0x3FF73084+0 */
  a8 = a8 & a10; /* 0016: and a8, a8, a10 */
  MEMW(); /* 0019: memw  */
  REG32(0x3FF73084) = a8; /* 001c: s32i.n a8, a9, 0 */ /* MMIO write: base 0x3FF73084+0 */
  MEMW(); /* 001e: memw  */
  return (int32_t)a2; /* 0021: retw.n  */
}

/* ic_set_beacon_int @ if_hwctrl.o 00000004 size 14B bind GLOBAL
 * Calls: wDev_Set_Beacon_Int | Data refs: wDev_Set_Beacon_Int
 *   MMIO: none
 *   funcdb v3: 1 call(s), 1 ref(s); disasm: 1 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t ic_set_beacon_int(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.ic_set_beacon_int; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a10 = a2 | a2; /* 0007: or a10, a2, a2 */
  a8 = (uint32_t)&wDev_Set_Beacon_Int; /* 000a: l32r a8, 0 <ic_set_beacon_int-0x4> (0 <ic_set_beacon_int-0x4>) */ /* literal: GOT slot for wDev_Set_Beacon_Int */
  wDev_Set_Beacon_Int(a2, a3, a4, a5); /* call via literal slot */ /* 000d: callx8 a8 */
  return (int32_t)a2; /* 0010: retw.n  */
}

/* ic_set_mac @ if_hwctrl.o 00000014 size 66B bind GLOBAL
 * Calls: hal_mac_set_addr, memcpy, wifi_log | Data refs: .rodata_wlog_error.11, hal_mac_set_addr, if_ctrl, memcpy, wifi_log
 *   MMIO: none
 *   funcdb v3: 3 call(s), 5 ref(s); disasm: 3 call(s), 5 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t ic_set_mac(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.ic_set_mac; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_14:;
  /* 0014: entry a1, 32 */
  a2 = (a2 >> 0) & 0xFF; /* 0017: extui a2, a2, 0, 8 */
  if (a2 < 4) goto L_36; /* 001a: bltui a2, 4, 36 <ic_set_mac+0x22> */
  a12 = 0x1; /* 001d: movi.n a12, 1 */
  a13 = (uint32_t)&lit_rodata_wlog_error_11; /* 001f: l32r a13, 0 <ic_set_mac-0x14> (0 <ic_set_mac-0x14>) */ /* literal @0x0: .rodata_wlog_error.11 */
  a15 = 0x3; /* 0022: movi.n a15, 3 */
  a14 = a2; /* 0024: mov.n a14, a2 */
  a11 = 0x1; /* 0026: mov.n a11, a12 */
  a10 = 0x1; /* 0028: mov.n a10, a12 */
  a8 = (uint32_t)&wifi_log; /* 002a: l32r a8, 8 <ic_set_mac-0xc> (0 <ic_set_mac-0x14>) */ /* literal: GOT slot for wifi_log */
  wifi_log(a2, a3, a4, a5); /* call via literal slot */ /* 002d: callx8 a8 */
  goto L_54; /* 0030: j 54 <ic_set_mac+0x40> */
  /* 0033: .byte 00 */
  /* 0034: .byte 00 */
  /* 0035: .byte 00 */
L_36:;
  a10 = a2; /* 0036: mov.n a10, a2 */
  a11 = a3 | a3; /* 0038: or a11, a3, a3 */
  a8 = (uint32_t)&hal_mac_set_addr; /* 003b: l32r a8, c <ic_set_mac-0x8> (0 <ic_set_mac-0x14>) */ /* literal: GOT slot for hal_mac_set_addr */
  hal_mac_set_addr(a2, a3, a4, a5); /* call via literal slot */ /* 003e: callx8 a8 */
  a10 = (uint32_t)&if_ctrl; /* 0041: l32r a10, 4 <ic_set_mac-0x10> (0 <ic_set_mac-0x14>) */ /* literal @0x4: if_ctrl */
  a2 = (a2 << 4) + a2; /* 0044: addx4 a2, a2, a2 */
  a12 = 0x6; /* 0047: movi.n a12, 6 */
  a11 = a3; /* 0049: mov.n a11, a3 */
  a10 = (a2 << 2) + a10; /* 004b: addx2 a10, a2, a10 */
  a8 = (uint32_t)&memcpy; /* 004e: l32r a8, 10 <ic_set_mac-0x4> (0 <ic_set_mac-0x14>) */ /* literal: GOT slot for memcpy */
  memcpy(a2, a3, a4, a5); /* call via literal slot */ /* 0051: callx8 a8 */
L_54:;
  return (int32_t)a2; /* 0054: retw.n  */
}

/* ic_set_bssid @ if_hwctrl.o 00000004 size 16B bind GLOBAL
 * Calls: hal_mac_set_bssid | Data refs: hal_mac_set_bssid
 *   MMIO: none
 *   funcdb v3: 1 call(s), 1 ref(s); disasm: 1 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t ic_set_bssid(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.ic_set_bssid; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a11 = a3; /* 0007: mov.n a11, a3 */
  a10 = (a2 >> 0) & 0xFF; /* 0009: extui a10, a2, 0, 8 */
  a8 = (uint32_t)&hal_mac_set_bssid; /* 000c: l32r a8, 0 <ic_set_bssid-0x4> (0 <ic_set_bssid-0x4>) */ /* literal: GOT slot for hal_mac_set_bssid */
  hal_mac_set_bssid(a2, a3, a4, a5); /* call via literal slot */ /* 000f: callx8 a8 */
  return (int32_t)a2; /* 0012: retw.n  */
}

/* ic_set_current_channel @ if_hwctrl.o 00000004 size 15B bind GLOBAL
 * Calls: wDev_SetCurChannel | Data refs: wDev_SetCurChannel
 *   MMIO: none
 *   funcdb v3: 1 call(s), 1 ref(s); disasm: 1 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t ic_set_current_channel(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.ic_set_current_channel; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a10 = a2; /* 0007: mov.n a10, a2 */
  if (a2 == 0) goto L_11; /* 0009: beqz.n a2, 11 <ic_set_current_channel+0xd> */
  a8 = (uint32_t)&wDev_SetCurChannel; /* 000b: l32r a8, 0 <ic_set_current_channel-0x4> (0 <ic_set_current_channel-0x4>) */ /* literal: GOT slot for wDev_SetCurChannel */
  wDev_SetCurChannel(a2, a3, a4, a5); /* call via literal slot */ /* 000e: callx8 a8 */
L_11:;
  return (int32_t)a2; /* 0011: retw.n  */
}

/* ic_get_random @ if_hwctrl.o 00000004 size 13B bind GLOBAL
 * Calls: hal_random | Data refs: hal_random
 *   MMIO: none
 *   funcdb v3: 1 call(s), 1 ref(s); disasm: 1 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t ic_get_random(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.ic_get_random; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a8 = (uint32_t)&hal_random; /* 0007: l32r a8, 0 <ic_get_random-0x4> (0 <ic_get_random-0x4>) */ /* literal: GOT slot for hal_random */
  hal_random(a2, a3, a4, a5); /* call via literal slot */ /* 000a: callx8 a8 */
  a2 = a10; /* 000d: mov.n a2, a10 */
  return (int32_t)a2; /* 000f: retw.n  */
}

/* ic_get_trc @ if_hwctrl.o 00000004 size 19B bind GLOBAL
 * Calls: rc_get_trc_by_index | Data refs: rc_get_trc_by_index
 *   MMIO: none
 *   funcdb v3: 1 call(s), 1 ref(s); disasm: 1 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t ic_get_trc(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.ic_get_trc; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a11 = (a3 >> 0) & 0xFF; /* 0007: extui a11, a3, 0, 8 */
  a10 = (a2 >> 0) & 0xFF; /* 000a: extui a10, a2, 0, 8 */
  a8 = (uint32_t)&rc_get_trc_by_index; /* 000d: l32r a8, 0 <ic_get_trc-0x4> (0 <ic_get_trc-0x4>) */ /* literal: GOT slot for rc_get_trc_by_index */
  rc_get_trc_by_index(a2, a3, a4, a5); /* call via literal slot */ /* 0010: callx8 a8 */
  a2 = a10; /* 0013: mov.n a2, a10 */
  return (int32_t)a2; /* 0015: retw.n  */
}

/* ic_tx_is_idle @ if_hwctrl.o 00000004 size 16B bind GLOBAL
 * Calls: lmacIsIdle | Data refs: lmacIsIdle
 *   MMIO: none
 *   funcdb v3: 1 call(s), 1 ref(s); disasm: 1 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t ic_tx_is_idle(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.ic_tx_is_idle; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a10 = (a2 >> 0) & 0xFF; /* 0007: extui a10, a2, 0, 8 */
  a8 = (uint32_t)&lmacIsIdle; /* 000a: l32r a8, 0 <ic_tx_is_idle-0x4> (0 <ic_tx_is_idle-0x4>) */ /* literal: GOT slot for lmacIsIdle */
  lmacIsIdle(a2, a3, a4, a5); /* call via literal slot */ /* 000d: callx8 a8 */
  a2 = a10; /* 0010: mov.n a2, a10 */
  return (int32_t)a2; /* 0012: retw.n  */
}

/* ic_get_pp_hdl @ if_hwctrl.o 00000004 size 13B bind GLOBAL
 * Calls: ppGetTaskHdl | Data refs: ppGetTaskHdl
 *   MMIO: none
 *   funcdb v3: 1 call(s), 1 ref(s); disasm: 1 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t ic_get_pp_hdl(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.ic_get_pp_hdl; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a8 = (uint32_t)&ppGetTaskHdl; /* 0007: l32r a8, 0 <ic_get_pp_hdl-0x4> (0 <ic_get_pp_hdl-0x4>) */ /* literal: GOT slot for ppGetTaskHdl */
  ppGetTaskHdl(a2, a3, a4, a5); /* call via literal slot */ /* 000a: callx8 a8 */
  a2 = a10; /* 000d: mov.n a2, a10 */
  return (int32_t)a2; /* 000f: retw.n  */
}

/* ic_set_rx_policy_ubssid_check @ if_hwctrl.o 00000004 size 24B bind GLOBAL
 * Calls: hal_mac_set_rxq_policy | Data refs: hal_mac_set_rxq_policy
 *   MMIO: none
 *   funcdb v3: 1 call(s), 1 ref(s); disasm: 1 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t ic_set_rx_policy_ubssid_check(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.ic_set_rx_policy_ubssid_check; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a10 = (a2 >> 0) & 0xFF; /* 0007: extui a10, a2, 0, 8 */
  a11 = (a3 >> 0) & 0xFF; /* 000a: extui a11, a3, 0, 8 */
  a2 = 0x0; /* 000d: movi.n a2, 0 */
  if (a10 >= 4) goto L_1a; /* 000f: bgeui a10, 4, 1a <ic_set_rx_policy_ubssid_check+0x16> */
  a8 = (uint32_t)&hal_mac_set_rxq_policy; /* 0012: l32r a8, 0 <ic_set_rx_policy_ubssid_check-0x4> (0 <ic_set_rx_policy_ubssid_check-0x4>) */ /* literal: GOT slot for hal_mac_set_rxq_policy */
  hal_mac_set_rxq_policy(a2, a3, a4, a5); /* call via literal slot */ /* 0015: callx8 a8 */
  a2 = 0x1; /* 0018: movi.n a2, 1 */
L_1a:;
  return (int32_t)a2; /* 001a: retw.n  */
}

/* ic_set_rx_policy @ if_hwctrl.o 00000004 size 25B bind GLOBAL
 * Calls: hal_mac_rx_set_policy | Data refs: hal_mac_rx_set_policy
 *   MMIO: none
 *   funcdb v3: 1 call(s), 1 ref(s); disasm: 1 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t ic_set_rx_policy(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.ic_set_rx_policy; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a13 = (a5 >> 0) & 0xFF; /* 0007: extui a13, a5, 0, 8 */
  a12 = (a4 >> 0) & 0xFF; /* 000a: extui a12, a4, 0, 8 */
  a11 = (a3 >> 0) & 0xFF; /* 000d: extui a11, a3, 0, 8 */
  a10 = (a2 >> 0) & 0xFF; /* 0010: extui a10, a2, 0, 8 */
  a8 = (uint32_t)&hal_mac_rx_set_policy; /* 0013: l32r a8, 0 <ic_set_rx_policy-0x4> (0 <ic_set_rx_policy-0x4>) */ /* literal: GOT slot for hal_mac_rx_set_policy */
  hal_mac_rx_set_policy(a2, a3, a4, a5); /* call via literal slot */ /* 0016: callx8 a8 */
  a2 = 0x1; /* 0019: movi.n a2, 1 */
  return (int32_t)a2; /* 001b: retw.n  */
}

/* ic_set_interface @ if_hwctrl.o 00000004 size 16B bind GLOBAL
 * Calls: ppSetInterface | Data refs: ppSetInterface
 *   MMIO: none
 *   funcdb v3: 1 call(s), 1 ref(s); disasm: 1 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t ic_set_interface(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.ic_set_interface; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a11 = a3; /* 0007: mov.n a11, a3 */
  a10 = (a2 >> 0) & 0xFF; /* 0009: extui a10, a2, 0, 8 */
  a8 = (uint32_t)&ppSetInterface; /* 000c: l32r a8, 0 <ic_set_interface-0x4> (0 <ic_set_interface-0x4>) */ /* literal: GOT slot for ppSetInterface */
  ppSetInterface(a2, a3, a4, a5); /* call via literal slot */ /* 000f: callx8 a8 */
  return (int32_t)a2; /* 0012: retw.n  */
}

/* ic_trc_set_per_pkt_rate @ if_hwctrl.o 00000004 size 15B bind GLOBAL
 * Calls: trc_set_per_pkt_rate | Data refs: trc_set_per_pkt_rate
 *   MMIO: none
 *   funcdb v3: 1 call(s), 1 ref(s); disasm: 1 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t ic_trc_set_per_pkt_rate(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.ic_trc_set_per_pkt_rate; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a11 = a3; /* 0007: mov.n a11, a3 */
  a10 = a2; /* 0009: mov.n a10, a2 */
  a8 = (uint32_t)&trc_set_per_pkt_rate; /* 000b: l32r a8, 0 <ic_trc_set_per_pkt_rate-0x4> (0 <ic_trc_set_per_pkt_rate-0x4>) */ /* literal: GOT slot for trc_set_per_pkt_rate */
  trc_set_per_pkt_rate(a2, a3, a4, a5); /* call via literal slot */ /* 000e: callx8 a8 */
  return (int32_t)a2; /* 0011: retw.n  */
}

/* ic_trc_update_ifx_phy_mode @ if_hwctrl.o 00000004 size 15B bind GLOBAL
 * Calls: trc_update_ifx_phy_mode | Data refs: trc_update_ifx_phy_mode
 *   MMIO: none
 *   funcdb v3: 1 call(s), 1 ref(s); disasm: 1 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t ic_trc_update_ifx_phy_mode(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.ic_trc_update_ifx_phy_mode; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a11 = a3; /* 0007: mov.n a11, a3 */
  a10 = a2; /* 0009: mov.n a10, a2 */
  a8 = (uint32_t)&trc_update_ifx_phy_mode; /* 000b: l32r a8, 0 <ic_trc_update_ifx_phy_mode-0x4> (0 <ic_trc_update_ifx_phy_mode-0x4>) */ /* literal: GOT slot for trc_update_ifx_phy_mode */
  trc_update_ifx_phy_mode(a2, a3, a4, a5); /* call via literal slot */ /* 000e: callx8 a8 */
  return (int32_t)a2; /* 0011: retw.n  */
}

/* ic_update_trc_params @ if_hwctrl.o 00000008 size 48B bind GLOBAL
 * Calls: rcUpdateAMPDUParam, rc_get_trc_by_index | Data refs: rcUpdateAMPDUParam, rc_get_trc_by_index
 *   MMIO: none
 *   funcdb v3: 2 call(s), 2 ref(s); disasm: 2 call(s), 2 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t ic_update_trc_params(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.ic_update_trc_params; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_8:;
  /* 0008: entry a1, 32 */
  a11 = (a3 >> 0) & 0xFF; /* 000b: extui a11, a3, 0, 8 */
  a10 = (a2 >> 0) & 0xFF; /* 000e: extui a10, a2, 0, 8 */
  a4 = (a4 >> 0) & 0xFF; /* 0011: extui a4, a4, 0, 8 */
  a5 = (a5 >> 0) & 0xFF; /* 0014: extui a5, a5, 0, 8 */
  a8 = (uint32_t)&rc_get_trc_by_index; /* 0017: l32r a8, 0 <ic_update_trc_params-0x8> (0 <ic_update_trc_params-0x8>) */ /* literal: GOT slot for rc_get_trc_by_index */
  rc_get_trc_by_index(a2, a3, a4, a5); /* call via literal slot */ /* 001a: callx8 a8 */
  if (a10 == 0) goto L_36; /* 001d: beqz.n a10, 36 <ic_update_trc_params+0x2e> */
  MEM8(a10 + 130) = a4; /* 001f: s8i a4, a10, 130 */
  MEMW(); /* 0022: memw  */
  a13 = (a5 >> 2) & 0x7; /* 0025: extui a13, a5, 2, 3 */
  a12 = (a5 >> 0) & 0x3; /* 0028: extui a12, a5, 0, 2 */
  a11 = a4; /* 002b: mov.n a11, a4 */
  MEMW(); /* 002d: memw  */
  a8 = (uint32_t)&rcUpdateAMPDUParam; /* 0030: l32r a8, 4 <ic_update_trc_params-0x4> (0 <ic_update_trc_params-0x8>) */ /* literal: GOT slot for rcUpdateAMPDUParam */
  rcUpdateAMPDUParam(a2, a3, a4, a5); /* call via literal slot */ /* 0033: callx8 a8 */
L_36:;
  return (int32_t)a2; /* 0036: retw.n  */
}

/* ic_stop_hw_txq @ if_hwctrl.o 00000004 size 13B bind GLOBAL
 * Calls: lmac_stop_hw_txq | Data refs: lmac_stop_hw_txq
 *   MMIO: none
 *   funcdb v3: 1 call(s), 1 ref(s); disasm: 1 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t ic_stop_hw_txq(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.ic_stop_hw_txq; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a8 = (uint32_t)&lmac_stop_hw_txq; /* 0007: l32r a8, 0 <ic_stop_hw_txq-0x4> (0 <ic_stop_hw_txq-0x4>) */ /* literal: GOT slot for lmac_stop_hw_txq */
  lmac_stop_hw_txq(a2, a3, a4, a5); /* call via literal slot */ /* 000a: callx8 a8 */
  a2 = a10; /* 000d: mov.n a2, a10 */
  return (int32_t)a2; /* 000f: retw.n  */
}

/* ic_stop_sw_txq @ if_hwctrl.o 0000000c size 30B bind GLOBAL
 * Calls: pp_stop_sw_txq, wifi_log | Data refs: .rodata_wlog_info.12, pp_stop_sw_txq, wifi_log
 *   MMIO: none
 *   funcdb v3: 2 call(s), 3 ref(s); disasm: 2 call(s), 3 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t ic_stop_sw_txq(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.ic_stop_sw_txq; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_c:;
  /* 000c: entry a1, 32 */
  a13 = (uint32_t)&lit_rodata_wlog_info_12; /* 000f: l32r a13, 0 <ic_stop_sw_txq-0xc> (0 <ic_stop_sw_txq-0xc>) */ /* literal @0x0: .rodata_wlog_info.12 */
  a12 = 0x3; /* 0012: movi.n a12, 3 */
  a11 = 0x1; /* 0014: movi a11, 1 */
  a10 = 0x6; /* 0017: movi a10, 6 */
  a8 = (uint32_t)&wifi_log; /* 001a: l32r a8, 4 <ic_stop_sw_txq-0x8> (0 <ic_stop_sw_txq-0xc>) */ /* literal: GOT slot for wifi_log */
  wifi_log(a2, a3, a4, a5); /* call via literal slot */ /* 001d: callx8 a8 */
  a8 = (uint32_t)&pp_stop_sw_txq; /* 0020: l32r a8, 8 <ic_stop_sw_txq-0x4> (0 <ic_stop_sw_txq-0xc>) */ /* literal: GOT slot for pp_stop_sw_txq */
  pp_stop_sw_txq(a2, a3, a4, a5); /* call via literal slot */ /* 0023: callx8 a8 */
  a2 = 0x0; /* 0026: movi.n a2, 0 */
  return (int32_t)a2; /* 0028: retw.n  */
}

/* ic_txq_empty @ if_hwctrl.o 00000004 size 13B bind GLOBAL
 * Calls: ppTxqEmpty | Data refs: ppTxqEmpty
 *   MMIO: none
 *   funcdb v3: 1 call(s), 1 ref(s); disasm: 1 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t ic_txq_empty(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.ic_txq_empty; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a8 = (uint32_t)&ppTxqEmpty; /* 0007: l32r a8, 0 <ic_txq_empty-0x4> (0 <ic_txq_empty-0x4>) */ /* literal: GOT slot for ppTxqEmpty */
  ppTxqEmpty(a2, a3, a4, a5); /* call via literal slot */ /* 000a: callx8 a8 */
  a2 = a10; /* 000d: mov.n a2, a10 */
  return (int32_t)a2; /* 000f: retw.n  */
}

/* ic_set_fix_rate @ if_hwctrl.o 00000004 size 20B bind GLOBAL
 * Calls: rc_set_fix_rate | Data refs: rc_set_fix_rate
 *   MMIO: none
 *   funcdb v3: 1 call(s), 1 ref(s); disasm: 1 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t ic_set_fix_rate(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.ic_set_fix_rate; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a12 = a4; /* 0007: mov.n a12, a4 */
  a11 = (a3 >> 0) & 0xFF; /* 0009: extui a11, a3, 0, 8 */
  a10 = a2; /* 000c: mov.n a10, a2 */
  a8 = (uint32_t)&rc_set_fix_rate; /* 000e: l32r a8, 0 <ic_set_fix_rate-0x4> (0 <ic_set_fix_rate-0x4>) */ /* literal: GOT slot for rc_set_fix_rate */
  rc_set_fix_rate(a2, a3, a4, a5); /* call via literal slot */ /* 0011: callx8 a8 */
  a2 = a10; /* 0014: mov.n a2, a10 */
  return (int32_t)a2; /* 0016: retw.n  */
}

/* ic_get_fix_rate @ if_hwctrl.o 00000004 size 20B bind GLOBAL
 * Calls: rc_get_fix_rate | Data refs: rc_get_fix_rate
 *   MMIO: none
 *   funcdb v3: 1 call(s), 1 ref(s); disasm: 1 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t ic_get_fix_rate(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.ic_get_fix_rate; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a12 = a4; /* 0007: mov.n a12, a4 */
  a11 = a3; /* 0009: mov.n a11, a3 */
  a10 = a2 | a2; /* 000b: or a10, a2, a2 */
  a8 = (uint32_t)&rc_get_fix_rate; /* 000e: l32r a8, 0 <ic_get_fix_rate-0x4> (0 <ic_get_fix_rate-0x4>) */ /* literal: GOT slot for rc_get_fix_rate */
  rc_get_fix_rate(a2, a3, a4, a5); /* call via literal slot */ /* 0011: callx8 a8 */
  a2 = a10; /* 0014: mov.n a2, a10 */
  return (int32_t)a2; /* 0016: retw.n  */
}

/* ic_create_wifi_task @ if_hwctrl.o 00000004 size 13B bind GLOBAL
 * Calls: pp_create_task | Data refs: pp_create_task
 *   MMIO: none
 *   funcdb v3: 1 call(s), 1 ref(s); disasm: 1 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t ic_create_wifi_task(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.ic_create_wifi_task; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a8 = (uint32_t)&pp_create_task; /* 0007: l32r a8, 0 <ic_create_wifi_task-0x4> (0 <ic_create_wifi_task-0x4>) */ /* literal: GOT slot for pp_create_task */
  pp_create_task(a2, a3, a4, a5); /* call via literal slot */ /* 000a: callx8 a8 */
  a2 = a10; /* 000d: mov.n a2, a10 */
  return (int32_t)a2; /* 000f: retw.n  */
}

/* ic_delete_wifi_task @ if_hwctrl.o 00000004 size 13B bind GLOBAL
 * Calls: pp_delete_task | Data refs: pp_delete_task
 *   MMIO: none
 *   funcdb v3: 1 call(s), 1 ref(s); disasm: 1 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t ic_delete_wifi_task(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.ic_delete_wifi_task; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a8 = (uint32_t)&pp_delete_task; /* 0007: l32r a8, 0 <ic_delete_wifi_task-0x4> (0 <ic_delete_wifi_task-0x4>) */ /* literal: GOT slot for pp_delete_task */
  pp_delete_task(a2, a3, a4, a5); /* call via literal slot */ /* 000a: callx8 a8 */
  a2 = a10; /* 000d: mov.n a2, a10 */
  return (int32_t)a2; /* 000f: retw.n  */
}

/* ic_set_csi @ if_hwctrl.o 00000004 size 16B bind GLOBAL
 * Calls: hal_mac_set_csi | Data refs: hal_mac_set_csi
 *   MMIO: none
 *   funcdb v3: 1 call(s), 1 ref(s); disasm: 1 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t ic_set_csi(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.ic_set_csi; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a10 = (a2 >> 0) & 0xFF; /* 0007: extui a10, a2, 0, 8 */
  a8 = (uint32_t)&hal_mac_set_csi; /* 000a: l32r a8, 0 <ic_set_csi-0x4> (0 <ic_set_csi-0x4>) */ /* literal: GOT slot for hal_mac_set_csi */
  hal_mac_set_csi(a2, a3, a4, a5); /* call via literal slot */ /* 000d: callx8 a8 */
  a2 = a10; /* 0010: mov.n a2, a10 */
  return (int32_t)a2; /* 0012: retw.n  */
}

/* ic_mac_init @ if_hwctrl.o 00000004 size 13B bind GLOBAL
 * Calls: hal_mac_init[got] | Data refs: hal_mac_init
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 1 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t ic_mac_init(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .wifislprxiram.13; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a8 = (uint32_t)&hal_mac_init; /* 0007: l32r a8, 0 <ic_mac_init-0x4> (0 <ic_mac_init-0x4>) */ /* literal: GOT slot for hal_mac_init */
  hal_mac_init(a2, a3, a4, a5); /* call via literal slot */ /* 000a: callx8 a8 */
  a2 = 0x0; /* 000d: movi.n a2, 0 */
  return (int32_t)a2; /* 000f: retw.n  */
}

/* ic_mac_deinit @ if_hwctrl.o 00000004 size 13B bind GLOBAL
 * Calls: hal_mac_deinit[got] | Data refs: hal_mac_deinit
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 1 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t ic_mac_deinit(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .wifislprxiram.14; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a8 = (uint32_t)&hal_mac_deinit; /* 0007: l32r a8, 0 <ic_mac_deinit-0x4> (0 <ic_mac_deinit-0x4>) */ /* literal: GOT slot for hal_mac_deinit */
  hal_mac_deinit(a2, a3, a4, a5); /* call via literal slot */ /* 000a: callx8 a8 */
  a2 = 0x0; /* 000d: movi.n a2, 0 */
  return (int32_t)a2; /* 000f: retw.n  */
}

/* ic_csi_set_config @ if_hwctrl.o 00000014 size 123B bind GLOBAL
 * Calls: phy_chan_dump_cfg, phy_chan_filt_set | Data refs: phy_chan_dump_cfg, phy_chan_filt_set
 *   MMIO: 0x3FF730F8, 0x3FF730FC
 *   funcdb v3: 2 call(s), 2 ref(s); disasm: 2 call(s), 2 data ref(s)
 * Fidelity: medium - 45 instr, 2 branches, calls resolved */
int32_t ic_csi_set_config(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.ic_csi_set_config; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_14:;
  /* 0014: entry a1, 32 */
  a14 = MEM8(a2 + 2); /* 0017: l8ui a14, a2, 2 */
  a13 = MEM8(a2 + 1); /* 001a: l8ui a13, a2, 1 */
  a12 = MEM8(a2 + 0); /* 001d: l8ui a12, a2, 0 */
  a11 = MEM8(a2 + 6); /* 0020: l8ui a11, a2, 6 */
  a10 = MEM8(a2 + 5); /* 0023: l8ui a10, a2, 5 */
  a8 = (uint32_t)&phy_chan_dump_cfg; /* 0026: l32r a8, c <ic_csi_set_config-0x8> (0 <ic_csi_set_config-0x14>) */ /* literal: GOT slot for phy_chan_dump_cfg */
  phy_chan_dump_cfg(a2, a3, a4, a5); /* call via literal slot */ /* 0029: callx8 a8 */
  a11 = MEM8(a2 + 3); /* 002c: l8ui a11, a2, 3 */
  a10 = MEM8(a2 + 4); /* 002f: l8ui a10, a2, 4 */
  a8 = (uint32_t)&phy_chan_filt_set; /* 0032: l32r a8, 10 <ic_csi_set_config-0x4> (0 <ic_csi_set_config-0x14>) */ /* literal: GOT slot for phy_chan_filt_set */
  phy_chan_filt_set(a2, a3, a4, a5); /* call via literal slot */ /* 0035: callx8 a8 */
  a8 = MEM8(a2 + 7); /* 0038: l8ui a8, a2, 7 */
  a2 = 0x3FF730F8; /* 003b: l32r a2, 0 <ic_csi_set_config-0x14> (3ff730f8 <ic_set_vif+0x3ff73090>) */ /* MMIO base */ @0x0
  if (a8 == 0) goto L_68; /* 003e: beqz.n a8, 68 <ic_csi_set_config+0x54> */
  a8 = 0x1; /* 0040: movi.n a8, 1 */
  a8 = 0x20000000; /* 0042: slli a8, a8, 29 */
  MEMW(); /* 0045: memw  */
  a9 = REG32(0x3FF730F8); /* 0048: l32i.n a9, a2, 0 */ /* MMIO read: base 0x3FF730F8+0 */
  a9 = a9 | a8; /* 004a: or a9, a9, a8 */
  MEMW(); /* 004d: memw  */
  REG32(0x3FF730F8) = a9; /* 0050: s32i.n a9, a2, 0 */ /* MMIO write: base 0x3FF730F8+0 */
  a9 = 0x3FF730FC; /* 0052: l32r a9, 4 <ic_csi_set_config-0x10> (3ff730fc <ic_set_vif+0x3ff73094>) */ /* MMIO base */ @0x4
  MEMW(); /* 0055: memw  */
  a2 = REG32(0x3FF730FC); /* 0058: l32i.n a2, a9, 0 */ /* MMIO read: base 0x3FF730FC+0 */
  a2 = a2 | a8; /* 005a: or a2, a2, a8 */
  MEMW(); /* 005d: memw  */
  REG32(0x3FF730FC) = a2; /* 0060: s32i.n a2, a9, 0 */ /* MMIO write: base 0x3FF730FC+0 */
  MEMW(); /* 0062: memw  */
  goto L_88; /* 0065: j 88 <ic_csi_set_config+0x74> */
L_68:;
  MEMW(); /* 0068: memw  */
  a8 = MEM32(a2 + 0); /* 006b: l32i.n a8, a2, 0 */
  a9 = 0xDFFFFFFF; /* 006d: l32r a9, 8 <ic_csi_set_config-0xc> (dfffffff <ic_set_vif+0xdfffff97>) */ @0x8
  a8 = a8 & a9; /* 0070: and a8, a8, a9 */
  MEMW(); /* 0073: memw  */
  MEM32(a2 + 0) = a8; /* 0076: s32i.n a8, a2, 0 */
  a8 = 0x3FF730FC; /* 0078: l32r a8, 4 <ic_csi_set_config-0x10> (3ff730fc <ic_set_vif+0x3ff73094>) */ /* MMIO base */ @0x4
  MEMW(); /* 007b: memw  */
  a2 = REG32(0x3FF730FC); /* 007e: l32i.n a2, a8, 0 */ /* MMIO read: base 0x3FF730FC+0 */
  a2 = a2 & a9; /* 0080: and a2, a2, a9 */
  MEMW(); /* 0083: memw  */
  REG32(0x3FF730FC) = a2; /* 0086: s32i.n a2, a8, 0 */ /* MMIO write: base 0x3FF730FC+0 */
L_88:;
  a2 = 0x0; /* 0088: movi.n a2, 0 */
  MEMW(); /* 008a: memw  */
  return (int32_t)a2; /* 008d: retw.n  */
}

/* ic_update_modem_sleep_default_params @ if_hwctrl.o 00000004 size 11B bind GLOBAL
 * Calls: pm_update_modem_sleep_default_params | Data refs: pm_update_modem_sleep_default_params
 *   MMIO: none
 *   funcdb v3: 1 call(s), 1 ref(s); disasm: 1 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t ic_update_modem_sleep_default_params(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.ic_update_modem_sleep_default_params; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a8 = (uint32_t)&pm_update_modem_sleep_default_params; /* 0007: l32r a8, 0 <ic_update_modem_sleep_default_params-0x4> (0 <ic_update_modem_sleep_default_params-0x4>) */ /* literal: GOT slot for pm_update_modem_sleep_default_params */
  pm_update_modem_sleep_default_params(a2, a3, a4, a5); /* call via literal slot */ /* 000a: callx8 a8 */
  return (int32_t)a2; /* 000d: retw.n  */
}

/* ic_update_light_sleep_default_params @ if_hwctrl.o 00000004 size 15B bind GLOBAL
 * Calls: pm_update_light_sleep_default_params | Data refs: pm_update_light_sleep_default_params
 *   MMIO: none
 *   funcdb v3: 1 call(s), 1 ref(s); disasm: 1 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t ic_update_light_sleep_default_params(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.ic_update_light_sleep_default_params; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a11 = a3; /* 0007: mov.n a11, a3 */
  a10 = a2; /* 0009: mov.n a10, a2 */
  a8 = (uint32_t)&pm_update_light_sleep_default_params; /* 000b: l32r a8, 0 <ic_update_light_sleep_default_params-0x4> (0 <ic_update_light_sleep_default_params-0x4>) */ /* literal: GOT slot for pm_update_light_sleep_default_params */
  pm_update_light_sleep_default_params(a2, a3, a4, a5); /* call via literal slot */ /* 000e: callx8 a8 */
  return (int32_t)a2; /* 0011: retw.n  */
}

/* ic_set_sleep_min_active_time @ if_hwctrl.o 00000004 size 14B bind GLOBAL
 * Calls: pm_set_sleep_min_active_time | Data refs: pm_set_sleep_min_active_time
 *   MMIO: none
 *   funcdb v3: 1 call(s), 1 ref(s); disasm: 1 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t ic_set_sleep_min_active_time(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.ic_set_sleep_min_active_time; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a10 = a2 | a2; /* 0007: or a10, a2, a2 */
  a8 = (uint32_t)&pm_set_sleep_min_active_time; /* 000a: l32r a8, 0 <ic_set_sleep_min_active_time-0x4> (0 <ic_set_sleep_min_active_time-0x4>) */ /* literal: GOT slot for pm_set_sleep_min_active_time */
  pm_set_sleep_min_active_time(a2, a3, a4, a5); /* call via literal slot */ /* 000d: callx8 a8 */
  return (int32_t)a2; /* 0010: retw.n  */
}

/* ic_set_keep_alive_time @ if_hwctrl.o 00000004 size 14B bind GLOBAL
 * Calls: pm_set_keep_alive_time | Data refs: pm_set_keep_alive_time
 *   MMIO: none
 *   funcdb v3: 1 call(s), 1 ref(s); disasm: 1 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t ic_set_keep_alive_time(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.ic_set_keep_alive_time; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a10 = a2 | a2; /* 0007: or a10, a2, a2 */
  a8 = (uint32_t)&pm_set_keep_alive_time; /* 000a: l32r a8, 0 <ic_set_keep_alive_time-0x4> (0 <ic_set_keep_alive_time-0x4>) */ /* literal: GOT slot for pm_set_keep_alive_time */
  pm_set_keep_alive_time(a2, a3, a4, a5); /* call via literal slot */ /* 000d: callx8 a8 */
  return (int32_t)a2; /* 0010: retw.n  */
}

/* ic_get_keep_alive_time @ if_hwctrl.o 00000004 size 13B bind GLOBAL
 * Calls: pm_get_keep_alive_time | Data refs: pm_get_keep_alive_time
 *   MMIO: none
 *   funcdb v3: 1 call(s), 1 ref(s); disasm: 1 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t ic_get_keep_alive_time(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.ic_get_keep_alive_time; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a8 = (uint32_t)&pm_get_keep_alive_time; /* 0007: l32r a8, 0 <ic_get_keep_alive_time-0x4> (0 <ic_get_keep_alive_time-0x4>) */ /* literal: GOT slot for pm_get_keep_alive_time */
  pm_get_keep_alive_time(a2, a3, a4, a5); /* call via literal slot */ /* 000a: callx8 a8 */
  a2 = a10; /* 000d: mov.n a2, a10 */
  return (int32_t)a2; /* 000f: retw.n  */
}

/* ic_set_sleep_wait_broadcast_data_time @ if_hwctrl.o 00000004 size 14B bind GLOBAL
 * Calls: pm_set_sleep_wait_broadcast_data_time | Data refs: pm_set_sleep_wait_broadcast_data_time
 *   MMIO: none
 *   funcdb v3: 1 call(s), 1 ref(s); disasm: 1 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t ic_set_sleep_wait_broadcast_data_time(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.ic_set_sleep_wait_broadcast_data_time; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a10 = a2 | a2; /* 0007: or a10, a2, a2 */
  a8 = (uint32_t)&pm_set_sleep_wait_broadcast_data_time; /* 000a: l32r a8, 0 <ic_set_sleep_wait_broadcast_data_time-0x4> (0 <ic_set_sleep_wait_broadcast_data_time-0x4>) */ /* literal: GOT slot for pm_set_sleep_wait_broadcast_data_time */
  pm_set_sleep_wait_broadcast_data_time(a2, a3, a4, a5); /* call via literal slot */ /* 000d: callx8 a8 */
  return (int32_t)a2; /* 0010: retw.n  */
}

/* ic_beacon_monitor_configure @ if_hwctrl.o 00000004 size 14B bind GLOBAL
 * Calls: pm_beacon_monitor_configure | Data refs: pm_beacon_monitor_configure
 *   MMIO: none
 *   funcdb v3: 1 call(s), 1 ref(s); disasm: 1 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t ic_beacon_monitor_configure(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.ic_beacon_monitor_configure; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a10 = a2 | a2; /* 0007: or a10, a2, a2 */
  a8 = (uint32_t)&pm_beacon_monitor_configure; /* 000a: l32r a8, 0 <ic_beacon_monitor_configure-0x4> (0 <ic_beacon_monitor_configure-0x4>) */ /* literal: GOT slot for pm_beacon_monitor_configure */
  pm_beacon_monitor_configure(a2, a3, a4, a5); /* call via literal slot */ /* 000d: callx8 a8 */
  return (int32_t)a2; /* 0010: retw.n  */
}

/* ic_beacon_offset_configure @ if_hwctrl.o 00000004 size 19B bind GLOBAL
 * Calls: ptr_beacon_offset_funcs[got] | Data refs: ptr_beacon_offset_funcs
 *   MMIO: none
 *   funcdb v3: 0 call(s), 1 ref(s); disasm: 1 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t ic_beacon_offset_configure(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.ic_beacon_offset_configure; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a8 = (uint32_t)&ptr_beacon_offset_funcs; /* 0007: l32r a8, 0 <ic_beacon_offset_configure-0x4> (0 <ic_beacon_offset_configure-0x4>) */ /* literal @0x0: ptr_beacon_offset_funcs */
  a10 = a2; /* 000a: mov.n a10, a2 */
  a8 = MEM32(a8 + 0); /* 000c: l32i.n a8, a8, 0 */
  a8 = MEM32(a8 + 20); /* 000e: l32i.n a8, a8, 20 */
  if (a8 == 0) goto L_15; /* 0010: beqz.n a8, 15 <ic_beacon_offset_configure+0x11> */
  ptr_beacon_offset_funcs(a2, a3, a4, a5); /* call via literal slot */ /* 0012: callx8 a8 */
L_15:;
  return (int32_t)a2; /* 0015: retw.n  */
}

/* ic_beacon_offset_set_rx_beacon_standard @ if_hwctrl.o 00000004 size 20B bind GLOBAL
 * Calls: ptr_beacon_offset_funcs[got] | Data refs: ptr_beacon_offset_funcs
 *   MMIO: none
 *   funcdb v3: 0 call(s), 1 ref(s); disasm: 1 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t ic_beacon_offset_set_rx_beacon_standard(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.ic_beacon_offset_set_rx_beacon_standard; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a8 = (uint32_t)&ptr_beacon_offset_funcs; /* 0007: l32r a8, 0 <ic_beacon_offset_set_rx_beacon_standard-0x4> (0 <ic_beacon_offset_set_rx_beacon_standard-0x4>) */ /* literal @0x0: ptr_beacon_offset_funcs */
  a10 = (a2 >> 0) & 0xFF; /* 000a: extui a10, a2, 0, 8 */
  a8 = MEM32(a8 + 0); /* 000d: l32i.n a8, a8, 0 */
  a8 = MEM32(a8 + 28); /* 000f: l32i.n a8, a8, 28 */
  if (a8 == 0) goto L_16; /* 0011: beqz.n a8, 16 <ic_beacon_offset_set_rx_beacon_standard+0x12> */
  ptr_beacon_offset_funcs(a2, a3, a4, a5); /* call via literal slot */ /* 0013: callx8 a8 */
L_16:;
  return (int32_t)a2; /* 0016: retw.n  */
}

/* ic_update_listen_interval @ if_hwctrl.o 0000000c size 28B bind GLOBAL
 * Calls: pm_is_open, pm_scale_listen_interval, wifi_nvs_set_sta_listen_interval | Data refs: pm_is_open, pm_scale_listen_interval, wifi_nvs_set_sta_listen_interval
 *   MMIO: none
 *   funcdb v3: 3 call(s), 3 ref(s); disasm: 3 call(s), 3 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t ic_update_listen_interval(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.ic_update_listen_interval; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_c:;
  /* 000c: entry a1, 32 */
  a10 = (a2 >> 0) & 0xFFFF; /* 000f: extui a10, a2, 0, 16 */
  a8 = (uint32_t)&wifi_nvs_set_sta_listen_interval; /* 0012: l32r a8, 0 <ic_update_listen_interval-0xc> (0 <ic_update_listen_interval-0xc>) */ /* literal: GOT slot for wifi_nvs_set_sta_listen_interval */
  wifi_nvs_set_sta_listen_interval(a2, a3, a4, a5); /* call via literal slot */ /* 0015: callx8 a8 */
  a8 = (uint32_t)&pm_is_open; /* 0018: l32r a8, 4 <ic_update_listen_interval-0x8> (0 <ic_update_listen_interval-0xc>) */ /* literal: GOT slot for pm_is_open */
  pm_is_open(a2, a3, a4, a5); /* call via literal slot */ /* 001b: callx8 a8 */
  if (a10 == 0) goto L_26; /* 001e: beqz.n a10, 26 <ic_update_listen_interval+0x1a> */
  a8 = (uint32_t)&pm_scale_listen_interval; /* 0020: l32r a8, 8 <ic_update_listen_interval-0x4> (0 <ic_update_listen_interval-0xc>) */ /* literal: GOT slot for pm_scale_listen_interval */
  pm_scale_listen_interval(a2, a3, a4, a5); /* call via literal slot */ /* 0023: callx8 a8 */
L_26:;
  return (int32_t)a2; /* 0026: retw.n  */
}

/* ic_rx_disable_bssid_check @ if_hwctrl.o 00000004 size 14B bind GLOBAL
 * Calls: hal_rx_disable_bssid_check | Data refs: hal_rx_disable_bssid_check
 *   MMIO: none
 *   funcdb v3: 1 call(s), 1 ref(s); disasm: 1 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t ic_rx_disable_bssid_check(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.ic_rx_disable_bssid_check; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a10 = (a2 >> 0) & 0xFF; /* 0007: extui a10, a2, 0, 8 */
  a8 = (uint32_t)&hal_rx_disable_bssid_check; /* 000a: l32r a8, 0 <ic_rx_disable_bssid_check-0x4> (0 <ic_rx_disable_bssid_check-0x4>) */ /* literal: GOT slot for hal_rx_disable_bssid_check */
  hal_rx_disable_bssid_check(a2, a3, a4, a5); /* call via literal slot */ /* 000d: callx8 a8 */
  return (int32_t)a2; /* 0010: retw.n  */
}

/* ic_rx_enable_bssid_check @ if_hwctrl.o 00000004 size 14B bind GLOBAL
 * Calls: hal_rx_enable_bssid_check | Data refs: hal_rx_enable_bssid_check
 *   MMIO: none
 *   funcdb v3: 1 call(s), 1 ref(s); disasm: 1 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t ic_rx_enable_bssid_check(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.ic_rx_enable_bssid_check; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a10 = (a2 >> 0) & 0xFF; /* 0007: extui a10, a2, 0, 8 */
  a8 = (uint32_t)&hal_rx_enable_bssid_check; /* 000a: l32r a8, 0 <ic_rx_enable_bssid_check-0x4> (0 <ic_rx_enable_bssid_check-0x4>) */ /* literal: GOT slot for hal_rx_enable_bssid_check */
  hal_rx_enable_bssid_check(a2, a3, a4, a5); /* call via literal slot */ /* 000d: callx8 a8 */
  return (int32_t)a2; /* 0010: retw.n  */
}

/* ic_set_bar_rate @ if_hwctrl.o 00000004 size 14B bind GLOBAL
 * Calls: ppSetBarRate | Data refs: ppSetBarRate
 *   MMIO: none
 *   funcdb v3: 1 call(s), 1 ref(s); disasm: 1 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t ic_set_bar_rate(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.ic_set_bar_rate; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a10 = (a2 >> 0) & 0xFF; /* 0007: extui a10, a2, 0, 8 */
  a8 = (uint32_t)&ppSetBarRate; /* 000a: l32r a8, 0 <ic_set_bar_rate-0x4> (0 <ic_set_bar_rate-0x4>) */ /* literal: GOT slot for ppSetBarRate */
  ppSetBarRate(a2, a3, a4, a5); /* call via literal slot */ /* 000d: callx8 a8 */
  return (int32_t)a2; /* 0010: retw.n  */
}

/* ic_trc_update_def_rate @ if_hwctrl.o 00000004 size 19B bind GLOBAL
 * Calls: trc_update_def_rate | Data refs: trc_update_def_rate
 *   MMIO: none
 *   funcdb v3: 1 call(s), 1 ref(s); disasm: 1 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t ic_trc_update_def_rate(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.ic_trc_update_def_rate; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a12 = (a4 >> 0) & 0xFF; /* 0007: extui a12, a4, 0, 8 */
  a11 = a3; /* 000a: mov.n a11, a3 */
  a10 = (a2 >> 0) & 0xFF; /* 000c: extui a10, a2, 0, 8 */
  a8 = (uint32_t)&trc_update_def_rate; /* 000f: l32r a8, 0 <ic_trc_update_def_rate-0x4> (0 <ic_trc_update_def_rate-0x4>) */ /* literal: GOT slot for trc_update_def_rate */
  trc_update_def_rate(a2, a3, a4, a5); /* call via literal slot */ /* 0012: callx8 a8 */
  return (int32_t)a2; /* 0015: retw.n  */
}

/* ic_get_espnow_rate @ if_hwctrl.o 00000004 size 16B bind GLOBAL
 * Calls: trc_get_espnow_rate | Data refs: trc_get_espnow_rate
 *   MMIO: none
 *   funcdb v3: 1 call(s), 1 ref(s); disasm: 1 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t ic_get_espnow_rate(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.ic_get_espnow_rate; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a10 = (a2 >> 0) & 0xFF; /* 0007: extui a10, a2, 0, 8 */
  a8 = (uint32_t)&trc_get_espnow_rate; /* 000a: l32r a8, 0 <ic_get_espnow_rate-0x4> (0 <ic_get_espnow_rate-0x4>) */ /* literal: GOT slot for trc_get_espnow_rate */
  trc_get_espnow_rate(a2, a3, a4, a5); /* call via literal slot */ /* 000d: callx8 a8 */
  a2 = a10; /* 0010: mov.n a2, a10 */
  return (int32_t)a2; /* 0012: retw.n  */
}

/* ic_get_80211_tx_rate @ if_hwctrl.o 00000004 size 16B bind GLOBAL
 * Calls: trc_get_80211_tx_rate | Data refs: trc_get_80211_tx_rate
 *   MMIO: none
 *   funcdb v3: 1 call(s), 1 ref(s); disasm: 1 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t ic_get_80211_tx_rate(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.ic_get_80211_tx_rate; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a10 = (a2 >> 0) & 0xFF; /* 0007: extui a10, a2, 0, 8 */
  a8 = (uint32_t)&trc_get_80211_tx_rate; /* 000a: l32r a8, 0 <ic_get_80211_tx_rate-0x4> (0 <ic_get_80211_tx_rate-0x4>) */ /* literal: GOT slot for trc_get_80211_tx_rate */
  trc_get_80211_tx_rate(a2, a3, a4, a5); /* call via literal slot */ /* 000d: callx8 a8 */
  a2 = a10; /* 0010: mov.n a2, a10 */
  return (int32_t)a2; /* 0012: retw.n  */
}

/* ic_get_80211_tx_rate_config @ if_hwctrl.o 00000004 size 16B bind GLOBAL
 * Calls: trc_get_80211_tx_rate_config | Data refs: trc_get_80211_tx_rate_config
 *   MMIO: none
 *   funcdb v3: 1 call(s), 1 ref(s); disasm: 1 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t ic_get_80211_tx_rate_config(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.ic_get_80211_tx_rate_config; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a11 = a3; /* 0007: mov.n a11, a3 */
  a10 = (a2 >> 0) & 0xFF; /* 0009: extui a10, a2, 0, 8 */
  a8 = (uint32_t)&trc_get_80211_tx_rate_config; /* 000c: l32r a8, 0 <ic_get_80211_tx_rate_config-0x4> (0 <ic_get_80211_tx_rate_config-0x4>) */ /* literal: GOT slot for trc_get_80211_tx_rate_config */
  trc_get_80211_tx_rate_config(a2, a3, a4, a5); /* call via literal slot */ /* 000f: callx8 a8 */
  return (int32_t)a2; /* 0012: retw.n  */
}

/* ic_set_80211_tx_rate @ if_hwctrl.o 00000004 size 16B bind GLOBAL
 * Calls: trc_set_80211_tx_rate | Data refs: trc_set_80211_tx_rate
 *   MMIO: none
 *   funcdb v3: 1 call(s), 1 ref(s); disasm: 1 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t ic_set_80211_tx_rate(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.ic_set_80211_tx_rate; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a11 = a3; /* 0007: mov.n a11, a3 */
  a10 = (a2 >> 0) & 0xFF; /* 0009: extui a10, a2, 0, 8 */
  a8 = (uint32_t)&trc_set_80211_tx_rate; /* 000c: l32r a8, 0 <ic_set_80211_tx_rate-0x4> (0 <ic_set_80211_tx_rate-0x4>) */ /* literal: GOT slot for trc_set_80211_tx_rate */
  trc_set_80211_tx_rate(a2, a3, a4, a5); /* call via literal slot */ /* 000f: callx8 a8 */
  return (int32_t)a2; /* 0012: retw.n  */
}

/* ic_set_80211_tx_rate_config @ if_hwctrl.o 00000004 size 16B bind GLOBAL
 * Calls: trc_set_80211_tx_rate_config | Data refs: trc_set_80211_tx_rate_config
 *   MMIO: none
 *   funcdb v3: 1 call(s), 1 ref(s); disasm: 1 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t ic_set_80211_tx_rate_config(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.ic_set_80211_tx_rate_config; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a11 = a3; /* 0007: mov.n a11, a3 */
  a10 = (a2 >> 0) & 0xFF; /* 0009: extui a10, a2, 0, 8 */
  a8 = (uint32_t)&trc_set_80211_tx_rate_config; /* 000c: l32r a8, 0 <ic_set_80211_tx_rate_config-0x4> (0 <ic_set_80211_tx_rate_config-0x4>) */ /* literal: GOT slot for trc_set_80211_tx_rate_config */
  trc_set_80211_tx_rate_config(a2, a3, a4, a5); /* call via literal slot */ /* 000f: callx8 a8 */
  return (int32_t)a2; /* 0012: retw.n  */
}

/* ic_get_default_sched @ if_hwctrl.o 00000004 size 13B bind GLOBAL
 * Calls: rc_get_default_sched | Data refs: rc_get_default_sched
 *   MMIO: none
 *   funcdb v3: 1 call(s), 1 ref(s); disasm: 1 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t ic_get_default_sched(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.ic_get_default_sched; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a8 = (uint32_t)&rc_get_default_sched; /* 0007: l32r a8, 0 <ic_get_default_sched-0x4> (0 <ic_get_default_sched-0x4>) */ /* literal: GOT slot for rc_get_default_sched */
  rc_get_default_sched(a2, a3, a4, a5); /* call via literal slot */ /* 000a: callx8 a8 */
  a2 = a10; /* 000d: mov.n a2, a10 */
  return (int32_t)a2; /* 000f: retw.n  */
}

/* ic_get_G6M_sched @ if_hwctrl.o 00000004 size 13B bind GLOBAL
 * Calls: rc_get_G6M_sched | Data refs: rc_get_G6M_sched
 *   MMIO: none
 *   funcdb v3: 1 call(s), 1 ref(s); disasm: 1 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t ic_get_G6M_sched(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.ic_get_G6M_sched; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a8 = (uint32_t)&rc_get_G6M_sched; /* 0007: l32r a8, 0 <ic_get_G6M_sched-0x4> (0 <ic_get_G6M_sched-0x4>) */ /* literal: GOT slot for rc_get_G6M_sched */
  rc_get_G6M_sched(a2, a3, a4, a5); /* call via literal slot */ /* 000a: callx8 a8 */
  a2 = a10; /* 000d: mov.n a2, a10 */
  return (int32_t)a2; /* 000f: retw.n  */
}

