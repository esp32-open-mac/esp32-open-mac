/* ===== wdev.o : reconstructed from libpp.a (ESP32, Xtensa, esp-2022r1) =====
 * Toolchain: xtensa-esp32-elf (GCC 11.2.0 crosstool-NG esp-2022r1).
 * ABI: args a2..a7, return a2 (all functions take a2..a7, return int32_t).
 * memw barriers preserved as MEMW(). MMIO as REG32/REG16/REG8(addr).
 * Calls with unknown arg counts are modeled with 4 live args (a2..a5);
 * a2..a7 are clobbered across calls (windowed-ABI approximation).
 * Sections: .iram1.17, .iram1.41, .iram1.42, .iram1.44, .iram1.45, .text.wDev_Crypto_Disable, .text.wDev_FetchFirstDesc, .text.wDev_Get_Next_BcnOffset, .text.wDev_Get_Next_TBTT, .text.wDev_IndicateCtrlFrame, .text.wDev_Insert_KeyEntry, .text.wDev_Mesh_Enable_Tsf, .text.wDev_Mesh_Set_TBTT, .text.wDev_ProcessRxData_NAN_Interface_Hook, .text.wDev_Reset_TBTT, .text.wDev_RxSecError, .text.wDev_Rxbuf_Deinit, .text.wDev_Rxbuf_Init, .text.wDev_SetCurChannel, .text.wDev_Set_Beacon_Int, .text.wDev_SnifferRxAmpdu, .text.wDev_SnifferRxData, .text.wDev_disable_low_rate, .text.wDev_enable_low_rate, .text.wDev_isNANPktInValidSlot, .text.wDev_is_low_rate_enable, .text.wDev_remove_KeyEntry, .text.wDev_remove_KeyEntry_all_cnx, .text.wDev_reset_bcnSendTick, .text.wdev_csi_hw_bug_check, .text.wdev_csi_rx_process, .text.wdev_get_promis_ctrl_filter, .text.wdev_get_promis_filter, .text.wdev_is_mgmt_hwdecr_enabled, .text.wdev_mac_sleep_deinit, .text.wdev_mac_sleep_init, .text.wdev_nan_set_callbacks, .text.wdev_pop_promis_misc_buf, .text.wdev_process_misc_pkt, .text.wdev_set_csi_rx_cb, .text.wdev_set_promis, .text.wdev_set_promis_ctrl_filter, .text.wdev_set_promis_ctrl_pkt, .text.wdev_set_promis_filter, .text.wdev_set_promis_misc_buf, .text.wdev_set_promis_misc_pkt, .wifi0iram.11, .wifi0iram.12, .wifi0iram.13, .wifi0iram.3, .wifi0iram.4, .wifi0iram.5, .wifi0iram.6, .wifi0iram.7, .wifi0iram.8, .wifiorslpiram.25, .wifirxiram.23, .wifirxiram.26, .wifislpiram.14, .wifislpiram.24, .wifislprxiram.21, .wifislprxiram.27, .wifislprxiram.28, .wifislprxiram.49, .wifislprxiram.51
 * Undefined refs (56): NAN_NETWORK_ID, NAN_STANDARD_BSSID, bb_wdt_get_status, bb_wdt_timeout_clear, esf_buf_alloc, esf_buf_recycle, g_intr_lock_mux, g_lmac_cnt, g_osi_funcs_p, g_wifi_menuconfig, hal_ba_session_restore, hal_ba_session_store, hal_crypto_clr_key_entry, hal_crypto_disable, hal_crypto_enable, hal_crypto_mgmt_rx_enabled, hal_crypto_set_key_entry, hal_disable_mac, hal_enable_mac, hal_get_tsf_time, hal_mac_disable_low_rate, hal_mac_enable_low_rate, hal_mac_interrupt_clr_event, hal_mac_interrupt_clr_watchdog...
 */
#include <stdint.h>
#define REG32(a) (*(volatile uint32_t *)(a))
#define REG16(a) (*(volatile uint16_t *)(a))
#define REG8(a)  (*(volatile uint8_t *)(a))
#define MEM32(a) (*(volatile uint32_t *)(a))
#define MEM16(a) (*(volatile uint16_t *)(a))
#define MEM8(a)  (*(volatile uint8_t *)(a))
#define MEMW() __asm__ volatile("memw" ::: "memory")

extern int32_t wDevCtrl();
extern int32_t BcnInterval();
extern int32_t hal_mac_tsf_reset();
extern int32_t BcnSendTick();
extern int32_t hal_mac_tsf_set_time();
extern int32_t hal_get_tsf_time();
uint32_t wDevMacSleep; /* defined here (.bss/.data); was: wDevMacSleep */
extern int32_t hal_ba_session_restore();
extern int32_t hal_ba_session_store();
extern int32_t g_osi_funcs_p();
extern uint32_t rodata_wlog_warning_9; /* .rodata_wlog_warning.9 */
extern int32_t wifi_log();
extern uint32_t rodata_wlog_info_10; /* .rodata_wlog_info.10 */
extern int32_t hal_enable_mac();
extern int32_t hal_mac_rx_get_last_dscr();
extern int32_t hal_disable_mac();
extern uint32_t rodata_wlog_warning_15; /* .rodata_wlog_warning.15 */
extern int32_t hal_sniffer_rx_set_promis();
extern int32_t dram1_16();
extern int32_t memcpy();
extern int32_t pp_post();
extern uint32_t rodata_wlog_error_18; /* .rodata_wlog_error.18 */
extern int32_t memset();
extern int32_t dram1_2();
extern uint32_t rodata_wlog_info_19; /* .rodata_wlog_info.19 */
extern int32_t hal_sniffer_enable();
extern uint32_t rodata_wlog_info_20; /* .rodata_wlog_info.20 */
extern int32_t hal_sniffer_disable();
extern int32_t read_hw_noisefloor();
uint32_t g_wdev_csi_rx; /* defined here (.bss/.data); was: g_wdev_csi_rx */
uint32_t g_wdev_csi_rx_ctx; /* defined here (.bss/.data); was: g_wdev_csi_rx_ctx */
extern uint32_t rodata_wlog_warning_22; /* .rodata_wlog_warning.22 */
uint32_t g_wdev_is_nan_pkt_in_valid_slot_cb; /* defined here (.bss/.data); was: g_wdev_is_nan_pkt_in_valid_slot_cb */
extern uint32_t NAN_STANDARD_BSSID; /* NAN_STANDARD_BSSID */
extern int32_t memcmp();
extern uint32_t NAN_NETWORK_ID; /* NAN_NETWORK_ID */
extern uint32_t rodata_wlog_info_36; /* .rodata_wlog_info.36 */
extern uint32_t rodata_wlog_error_31; /* .rodata_wlog_error.31 */
extern uint32_t g_wifi_menuconfig; /* g_wifi_menuconfig */
extern int32_t pTxRx();
extern uint32_t rodata_wlog_info_32; /* .rodata_wlog_info.32 */
extern uint32_t rodata_wlog_warning_30; /* .rodata_wlog_warning.30 */
extern uint32_t rodata_wlog_info_33; /* .rodata_wlog_info.33 */
extern uint32_t rodata_wlog_info_34; /* .rodata_wlog_info.34 */
extern uint32_t rodata_wlog_error_35; /* .rodata_wlog_error.35 */
extern int32_t hal_mac_disable_low_rate();
extern int32_t hal_mac_enable_low_rate();
extern int32_t hal_mac_is_low_rate_enabled();
extern int32_t hal_mac_rx_get_end_state();
extern int32_t bb_wdt_get_status();
extern int32_t bb_wdt_timeout_clear();
extern int32_t hal_mac_interrupt_clr_watchdog();
extern int32_t hal_mac_interrupt_get_event();
extern int32_t hal_mac_interrupt_clr_event();
extern int32_t dram1_37();
extern int32_t dram1_38();
extern int32_t hal_mac_rx_get_end_info();
extern int32_t dram1_40();
extern int32_t hal_sniffer_rx_clr_statistics();
extern int32_t dram1_39();
extern int32_t lmacProcessRxSucData();
extern int32_t lmacPostTxComplete();
extern int32_t lmacProcessAllTxTimeout();
extern int32_t lmacProcessCollisions();
uint32_t s_record_list; /* defined here (.bss/.data); was: s_record_list */
extern uint32_t rodata_wlog_info_46; /* .rodata_wlog_info.46 */
extern uint32_t rodata_wlog_info_47; /* .rodata_wlog_info.47 */
extern uint32_t rodata_wlog_info_48; /* .rodata_wlog_info.48 */
extern uint32_t rodata_FUNCTION_1; /* .rodata.__FUNCTION__$1 */
extern uint32_t rodata_str1_1; /* .rodata.str1.1 */
extern int32_t wifi_assert();
extern uint32_t g_intr_lock_mux; /* g_intr_lock_mux */
extern int32_t hal_mac_rx_set_dscr_reload();
extern int32_t hal_mac_rx_is_dscr_reload();
extern int32_t hal_mac_rx_read_rxdscrnext();
extern int32_t hal_mac_rx_set_base();
extern int32_t esf_buf_alloc();
extern int32_t wifi_gpio_debug();
extern int32_t lmacRxDone();
extern int32_t roundup2();
extern int32_t esf_buf_recycle();
extern uint32_t g_lmac_cnt; /* g_lmac_cnt */
extern int32_t ic_interface_enabled();
extern int32_t wifi_sta_rx_probe_req();
extern uint32_t rodata_FUNCTION_3; /* .rodata.__FUNCTION__$3 */
uint32_t g_wdev_last_desc_reset; /* defined here (.bss/.data); was: g_wdev_last_desc_reset */
extern int32_t rodata_FUNCTION_2();
extern int32_t hal_crypto_set_key_entry();
extern int32_t hal_crypto_enable();
extern int32_t hal_crypto_clr_key_entry();
extern int32_t hal_crypto_disable();
extern uint32_t rodata_wlog_error_50; /* .rodata_wlog_error.50 */
extern uint32_t rodata_FUNCTION_0; /* .rodata.__FUNCTION__$0 */
extern int32_t hal_crypto_mgmt_rx_enabled();

/* pool[wDev_SetCurChannel]: +0x0=0x00000000(wDevCtrl) */
/* pool[wDev_Set_Beacon_Int]: +0x0=0x00000000(BcnInterval) */
/* pool[wDev_Reset_TBTT]: +0x0=0x00000000(hal_mac_tsf_reset) */
/* pool[wDev_reset_bcnSendTick]: +0x0=0x00000000(BcnSendTick) */
/* pool[wDev_Mesh_Enable_Tsf]: +0x0=0x00000000(hal_mac_tsf_reset) */
/* pool[wDev_Mesh_Set_TBTT]: +0x0=0x00000000(hal_mac_tsf_set_time) */
/* pool[wDev_Get_Next_TBTT]: +0x0=0x00000000(BcnSendTick), +0x4=0x00000000(BcnInterval), +0xc=0x00000000(hal_get_tsf_time), +0x8=0x10624DD3 */
/* pool[wDev_Get_Next_BcnOffset]: +0x0=0x00000000(BcnSendTick), +0x4=0x00000000(BcnInterval), +0xc=0x00000000(hal_get_tsf_time), +0x8=0x10624DD3 */
/* pool[wdev_mac_reg_load]: +0x0=0x3FF73000, +0x18=0x00000000(wdev_bank_load), +0x4=0x3FF73400, +0x1c=0x00000000(wdev_bank_load), +0x8=0x3FF73800, +0x20=0x00000000(wdev_bank_load), +0xc=0x3FF73C00, +0x24=0x00000000(wdev_bank_load), +0x10=0x3FF74000, +0x28=0x00000000(wdev_bank_load), +0x14=0x3FF74400, +0x2c=0x00000000(wdev_bank_load) */
/* pool[wdev_mac_reg_store]: +0x0=0x3FF73000, +0x18=0x00000000(wdev_bank_store), +0x4=0x3FF73400, +0x1c=0x00000000(wdev_bank_store), +0x8=0x3FF73800, +0x20=0x00000000(wdev_bank_store), +0xc=0x3FF73C00, +0x24=0x00000000(wdev_bank_store), +0x10=0x3FF74000, +0x28=0x00000000(wdev_bank_store), +0x14=0x3FF74400, +0x2c=0x00000000(wdev_bank_store) */
/* pool[wdev_mac_special_reg_load]: +0x0=0x00000000(wDevMacSleep+0x50), +0x4=0x00000000(wDevMacSleep+0x30), +0x8=0x00000000(wDevMacSleep+0x10), +0xc=0x00000000(hal_ba_session_restore) */
/* pool[wdev_mac_special_reg_store]: +0x0=0x00000000(wDevMacSleep+0x50), +0x4=0x00000000(wDevMacSleep+0x30), +0x8=0x00000000(wDevMacSleep+0x10), +0xc=0x00000000(hal_ba_session_store) */
/* pool[wdev_mac_sleep_init]: +0x0=0x00000000(wDevMacSleep), +0x4=0x00000000(g_osi_funcs_p), +0x8=0x00000000(.rodata_wlog_warning.9), +0x10=0x00000000(wifi_log), +0xc=0x00000000(.rodata_wlog_info.10), +0x14=0x00000000(wifi_log) */
/* pool[wdev_mac_sleep_deinit]: +0x0=0x00000000(wDevMacSleep), +0x4=0x00000000(g_osi_funcs_p) */
/* pool[wdev_mac_wakeup]: +0x0=0x00000000(wDevMacSleep), +0x4=0x00000000(g_osi_funcs_p), +0x8=0x3FF73C04, +0xc=0x3FF73084, +0x10=0x7FFFFFFF, +0x14=0x00000000(wdev_mac_reg_load), +0x18=0x00000000(hal_enable_mac), +0x1c=0x00000000(wdev_mac_special_reg_load) */
/* pool[wdev_is_data_in_rxlist]: +0x0=0x00000000(wDevCtrl), +0x4=0x00000000(hal_mac_rx_get_last_dscr) */
/* pool[wdev_mac_sleep]: +0x0=0x00000000(wDevMacSleep), +0x4=0x3FF73084, +0x8=0x7FFFFFFF, +0x14=0x00000000(wdev_is_data_in_rxlist), +0x18=0x00000000(wdev_mac_special_reg_store), +0x1c=0x00000000(hal_disable_mac), +0x20=0x00000000(wdev_mac_reg_store), +0xc=0x00000000(wDevCtrl), +0x10=0x00000000(g_osi_funcs_p) */
/* pool[wdev_csi_hw_bug_check]: +0x0=0x00000000(.rodata_wlog_warning.15), +0x8=0x00000000(wifi_log), +0x4=0x00000000(wDevCtrl) */
/* pool[wdev_set_promis_misc_pkt]: +0x0=0x00000000(wDevCtrl), +0xc=0x00000000(hal_sniffer_rx_set_promis), +0x4=0x3FF730F4, +0x8=0xFFFF00FF, +0x10=0x00000000(hal_sniffer_rx_set_promis) */
/* pool[wdev_push_promis_misc_buf]: +0x0=0x00000000(.dram1.16), +0x4=0x00000000(memcpy) */
/* pool[wdev_pop_promis_misc_buf]: +0x0=0x00000000(.dram1.16), +0x4=0x00000000(memcpy) */
/* pool[wdev_process_misc_pkt]: +0x0=0x00000000(.dram1.16), +0x4=0x00000000(g_osi_funcs_p), +0x8=0x00000000(memcpy), +0xc=0x00000000(pp_post), +0x10=0x00000000(wdev_pop_promis_misc_buf) */
/* pool[wdev_set_promis_misc_buf]: +0x0=0x00000000(.dram1.16), +0x4=0x00000000(g_osi_funcs_p), +0x8=0x00000000(.rodata_wlog_error.18), +0xc=0x00000000(wifi_log), +0x10=0x00000000(memset) */
/* pool[wdev_set_promis_ctrl_pkt]: +0x0=0x00000000(wDevCtrl), +0x4=0x00000000(.dram1.2), +0x8=0x00000000(hal_sniffer_rx_set_promis) */
/* pool[wdev_set_promis]: +0x4=0x00000000(wDevCtrl), +0x0=0x00000000(.rodata_wlog_info.19), +0xc=0x00000000(wifi_log), +0x10=0x00000000(hal_sniffer_enable), +0x14=0x00000000(wdev_set_promis_misc_buf), +0x18=0x00000000(wdev_set_promis_misc_pkt), +0x8=0x00000000(.rodata_wlog_info.20), +0x1c=0x00000000(wifi_log), +0x20=0x00000000(hal_sniffer_disable), +0x24=0x00000000(wdev_set_promis_misc_buf), +0x28=0x00000000(wdev_set_promis_misc_pkt), +0x2c=0x00000000(wdev_set_promis_ctrl_pkt) */
/* pool[wdev_set_promis_filter]: +0x0=0x00000000(wDevCtrl+0x34), +0x4=0x00000000(wdev_set_promis_misc_pkt) */
/* pool[wdev_get_promis_filter]: +0x0=0x00000000(wDevCtrl+0x34) */
/* pool[wdev_set_promis_ctrl_filter]: +0x0=0x00000000(.dram1.2), +0x4=0x00000000(wdev_set_promis_ctrl_pkt) */
/* pool[wdev_get_promis_ctrl_filter]: +0x0=0x00000000(.dram1.2) */
/* pool[wDev_SnifferRxAmpdu]: +0x0=0x00000000(wDevCtrl), +0x4=0x00000000(g_osi_funcs_p), +0x8=0x00000000(memcpy), +0xc=0x00000000(pp_post) */
/* pool[wDev_GetNoiseFloor]: +0x0=0x00000000(wDevCtrl), +0x4=0x00000000(read_hw_noisefloor) */
/* pool[wdev_csi_rx_process]: +0x0=0x00000000(g_wdev_csi_rx), +0x4=0x00000000(g_osi_funcs_p), +0x10=0x00000000(memcpy), +0x14=0x00000000(memset), +0x18=0x00000000(memcpy), +0x8=0x00000000(wDevCtrl), +0x1c=0x00000000(memcpy), +0x20=0x00000000(wDev_GetNoiseFloor), +0xc=0x00000000(g_wdev_csi_rx_ctx) */
/* pool[wDev_SnifferRxData]: +0x0=0x00000000(wDevCtrl), +0x8=0x00000000(wdev_csi_len_align), +0xc=0x00000000(wdev_csi_hw_bug_check), +0x4=0x00000000(g_osi_funcs_p), +0x10=0x00000000(memcpy), +0x14=0x00000000(memcpy), +0x18=0x00000000(memcpy), +0x1c=0x00000000(memcpy), +0x20=0x00000000(memcpy), +0x24=0x00000000(memcpy), +0x28=0x00000000(memcpy), +0x2c=0x00000000(wdev_csi_rx_process), +0x30=0x00000000(pp_post) */
/* pool[wDev_IndicateCtrlFrame]: +0x0=0x00000000(.rodata_wlog_warning.22), +0xc=0x00000000(wifi_log), +0x4=0x00000000(wDevCtrl), +0x10=0x00000000(wdev_csi_len_align), +0x14=0x00000000(wdev_csi_hw_bug_check), +0x8=0x00000000(g_osi_funcs_p), +0x18=0x00000000(memcpy), +0x1c=0x00000000(memcpy), +0x20=0x00000000(wdev_csi_rx_process) */
/* pool[wdev_nan_set_callbacks]: +0x0=0x00000000(g_wdev_is_nan_pkt_in_valid_slot_cb) */
/* pool[wDev_isNANPktInValidSlot]: +0x0=0x00000000(g_wdev_is_nan_pkt_in_valid_slot_cb) */
/* pool[wDev_ProcessRxData_NAN_Interface_Hook]: +0x0=0x00000000(NAN_STANDARD_BSSID), +0xc=0x00000000(memcmp), +0x4=0xBFFFFFFF, +0x8=0x00000000(NAN_NETWORK_ID), +0x10=0x00000000(memcmp) */
/* pool[wDev_Rxbuf_Deinit]: +0x0=0x00000000(wDevCtrl), +0x4=0x00000000(g_osi_funcs_p), +0x8=0x00000000(.rodata_wlog_info.36), +0xc=0x00000000(wifi_log) */
/* pool[wDev_Rxbuf_Init]: +0x0=0x00000000(g_osi_funcs_p), +0x4=0x00000000(wDevCtrl), +0x8=0x00000000(.rodata_wlog_error.31), +0x3c=0x00000000(wifi_log), +0x10=0x00000000(g_wifi_menuconfig), +0xc=0x00000000(pTxRx), +0x14=0x000008A4, +0x18=0x00000000(.rodata_wlog_info.32), +0x40=0x00000000(wifi_log), +0x1c=0x00000000(.rodata_wlog_warning.30), +0x44=0x00000000(wifi_log), +0x48=0x00000000(memset), +0x20=0xFF000FFF, +0x24=0xBFFFFFFF, +0x28=0xDFFFFFFF, +0x2c=0x00000000(.rodata_wlog_info.33), +0x4c=0x00000000(wifi_log), +0x30=0x00000000(.rodata_wlog_info.34), +0x50=0x00000000(wifi_log), +0x34=0x00000000(.rodata_wlog_error.35), +0x54=0x00000000(wifi_log), +0x58=0x00000000(wDev_Rxbuf_Deinit), +0x38=0xDEADBEEF */
/* pool[wDev_disable_low_rate]: +0x0=0x00000000(hal_mac_disable_low_rate) */
/* pool[wDev_enable_low_rate]: +0x0=0x00000000(hal_mac_enable_low_rate) */
/* pool[wDev_is_low_rate_enable]: +0x0=0x00000000(hal_mac_is_low_rate_enabled) */
/* pool[wdev_process_panic_watchdog]: +0x4=0x00000000(hal_mac_rx_get_end_state), +0x8=0x00000000(bb_wdt_get_status), +0x0=0x3FF00024, +0xc=0x3FF40078, +0x10=0x3FF40078, +0x14=0x00000000(bb_wdt_timeout_clear), +0x18=0x00000000(hal_mac_interrupt_clr_watchdog) */
/* pool[wDev_ProcessFiq]: +0x0=0x00000000(g_osi_funcs_p), +0x44=0x00000000(hal_mac_interrupt_get_event), +0x48=0x00000000(hal_mac_interrupt_clr_event), +0x4c=0x00000000(wdev_process_panic_watchdog), +0x50=0x00000000(pp_post), +0x4=0x01000024, +0x8=0x00000000(wDevCtrl), +0x18=0x00000000(.dram1.37), +0x14=0x0000000C(.dram1.37), +0x1c=0x00000004(.dram1.38), +0x20=0x00000000(.dram1.38), +0xc=0x00000004(.dram1.37), +0x10=0x00000008(.dram1.37), +0x54=0x00000000(hal_mac_rx_get_end_info), +0x24=0x6001C06C, +0x28=0x00000000(.dram1.40), +0x58=0x00000000(hal_sniffer_rx_clr_statistics), +0x2c=0x00000000(.dram1.39), +0x30=0xFF0000FF, +0x34=0x00000FFF, +0x38=0xFFFF3FFF, +0x3c=0xF7FFFF00, +0x40=0x00FFF000, +0x5c=0x00000000(wdev_push_promis_misc_buf), +0x60=0x00000000(pp_post), +0x64=0x00000000(lmacProcessRxSucData), +0x68=0x00000000(lmacPostTxComplete), +0x6c=0x00000000(lmacProcessAllTxTimeout), +0x70=0x00000000(lmacProcessCollisions) */
/* pool[wdev_record_rx_linked_list]: +0x0=0x00000000(g_osi_funcs_p), +0x4=0x00000000(s_record_list), +0x8=0x3FF73088, +0xc=0x3FF73090, +0x10=0x3FF7308C, +0x14=0x3FF73098, +0x18=0x00000000(wDevCtrl), +0x1c=0x3FF732F4, +0x20=0x3FF732FC */
/* pool[wdev_dump_rx_linked_list]: +0x10=0x00000000(wdev_record_rx_linked_list), +0x0=0x00000000(.rodata_wlog_info.46), +0x14=0x00000000(wifi_log), +0x4=0x00000000(s_record_list), +0x8=0x00000000(.rodata_wlog_info.47), +0x18=0x00000000(wifi_log), +0xc=0x00000000(.rodata_wlog_info.48), +0x1c=0x00000000(wifi_log) */
/* pool[wDev_AppendRxBlocks]: +0x4=0x00000D23, +0x8=0x00000000(.rodata.__FUNCTION__$1), +0xc=0x00000000(.rodata.str1.1), +0x2c=0x00000000(wifi_assert), +0x10=0xBFFFFFFF, +0x14=0xDFFFFFFF, +0x18=0xFF000FFF, +0x1c=0xDEADBEEF, +0x20=0x00000000(wDevCtrl), +0x28=0x00000000(g_osi_funcs_p), +0x24=0x00000000(g_intr_lock_mux), +0x30=0x00000000(wdev_record_rx_linked_list), +0x34=0x00000000(hal_mac_rx_set_dscr_reload), +0x38=0x00000000(wdev_record_rx_linked_list), +0x0=0x000186A1, +0x3c=0x00000000(wdev_dump_rx_linked_list), +0x40=0x00000000(hal_mac_rx_is_dscr_reload), +0x44=0x00000000(hal_mac_rx_read_rxdscrnext), +0x48=0x00000000(hal_mac_rx_get_last_dscr), +0x4c=0x00000000(hal_mac_rx_set_base) */
/* pool[wDev_DiscardFrame]: +0x0=0x00000000(wDevCtrl), +0x4=0x00000000(wDev_AppendRxBlocks) */
/* pool[wDev_IndicateFrame]: +0x0=0x00000000(wDevCtrl), +0x4=0x00000000(pTxRx), +0xc=0x00000000(esf_buf_alloc), +0x10=0x00000000(esf_buf_alloc), +0x14=0x00000000(wifi_gpio_debug), +0x18=0x00000000(wifi_gpio_debug), +0x1c=0x00000000(wDev_DiscardFrame), +0x20=0x00000000(wdev_csi_len_align), +0x24=0x00000000(wdev_csi_hw_bug_check), +0x28=0x00000000(memcpy), +0x2c=0x00000000(memcpy), +0x30=0x00000000(memcpy), +0x34=0x00000000(memcpy), +0x38=0x00000000(memcpy), +0x3c=0x00000000(memcpy), +0x8=0xFF000FFF, +0x40=0x00000000(wdev_csi_rx_process), +0x44=0x00000000(wDev_DiscardFrame), +0x48=0x00000000(lmacRxDone) */
/* pool[wDev_IndicateAmpdu]: +0x0=0x00000000(wDevCtrl), +0x4=0x00000000(wdev_csi_len_align), +0x8=0x00000000(wdev_csi_hw_bug_check), +0xc=0x00000000(wDev_RxSecError), +0x10=0x00000000(roundup2), +0x14=0x00000000(esf_buf_alloc), +0x18=0x00000000(memcpy), +0x1c=0x00000000(memcpy), +0x20=0x00000000(esf_buf_recycle), +0x24=0x00000000(memcpy), +0x28=0x00000000(roundup2), +0x2c=0x00000000(memcpy), +0x30=0x00000000(roundup2), +0x34=0x00000000(wdev_csi_rx_process), +0x38=0x00000000(wDev_SnifferRxAmpdu), +0x3c=0x00000000(lmacRxDone), +0x40=0x00000000(esf_buf_recycle), +0x44=0x00000000(wDev_DiscardFrame) */
/* pool[wDev_ProcessRxSucData]: +0x0=0x00000000(wDevCtrl), +0x18=0x00000000(wDev_GetNoiseFloor), +0x1c=0x00000000(wdev_csi_len_align), +0x20=0x00000000(wdev_csi_hw_bug_check), +0x24=0x00000000(wDev_SnifferRxData), +0x28=0x00000000(wDev_SnifferRxData), +0x4=0x00000000(g_lmac_cnt), +0x2c=0x00000000(ic_interface_enabled), +0x8=0x00000000(wifi_sta_rx_probe_req), +0x30=0x00000000(ic_interface_enabled), +0x34=0x00000000(wDev_ProcessRxData_NAN_Interface_Hook), +0x38=0x00000000(ic_interface_enabled), +0x3c=0x00000000(wDev_ProcessRxData_NAN_Interface_Hook), +0x40=0x00000000(wDev_IndicateCtrlFrame), +0xc=0x00000000(g_osi_funcs_p), +0x44=0x00000000(ic_interface_enabled), +0x48=0x00000000(ic_interface_enabled), +0x4c=0x00000000(ic_interface_enabled), +0x50=0x00000000(wDev_DiscardFrame), +0x10=0x00000000(.rodata.__FUNCTION__$3), +0x14=0x00000000(.rodata.str1.1), +0x54=0x00000000(wifi_assert), +0x58=0x00000000(wDev_IndicateAmpdu), +0x5c=0x00000000(wDev_IndicateFrame) */
/* pool[wdevProcessRxSucDataAll]: +0x1c=0x00000000(hal_mac_rx_get_last_dscr), +0x4=0x00000000(g_wdev_last_desc_reset), +0x0=0x00000000(wDevCtrl), +0x8=0x00000971, +0xc=0x00000000(.rodata.__FUNCTION__$2), +0x10=0x00000000(.rodata.str1.1), +0x20=0x00000000(wifi_assert), +0x18=0x00000000(g_osi_funcs_p), +0x14=0x00000000(g_intr_lock_mux), +0x24=0x00000000(wDev_ProcessRxSucData), +0x28=0x00000000(hal_mac_rx_get_last_dscr), +0x2c=0x00000000(wifi_assert) */
/* pool[wDev_Insert_KeyEntry]: +0x4=0x00000000(memcpy), +0x8=0x00000000(hal_crypto_set_key_entry), +0x0=0x00000000(wDevCtrl), +0xc=0x00000000(hal_crypto_enable) */
/* pool[wDev_remove_KeyEntry]: +0x0=0x00000000(wDevCtrl), +0x4=0x00000000(hal_crypto_clr_key_entry) */
/* pool[wDev_remove_KeyEntry_all_cnx]: +0x0=0x00000000(wDevCtrl), +0x4=0x00000000(wDev_remove_KeyEntry) */
/* pool[wDev_Crypto_Disable]: +0x0=0x00000000(wDevCtrl), +0x4=0x00000000(hal_crypto_disable) */
/* pool[wDevCheckBlockError]: +0x0=0xDEADBEEF, +0x4=0x00000FFC, +0x8=0x00000000(.rodata_wlog_error.50), +0x14=0x00000000(wifi_log), +0xc=0x00000000(.rodata.__FUNCTION__$0), +0x10=0x00000000(.rodata.str1.1), +0x18=0x00000000(wifi_assert) */
/* pool[wdev_set_csi_rx_cb]: +0x0=0x00000000(g_wdev_csi_rx), +0x4=0x00000000(g_wdev_csi_rx_ctx) */
/* pool[wdev_is_mgmt_hwdecr_enabled]: +0x0=0x00000000(hal_crypto_mgmt_rx_enabled) */

/* wDev_SetCurChannel @ wdev.o 00000004 size 29B bind GLOBAL
 * Calls: none | Data refs: wDevCtrl
 *   MMIO: none
 *   funcdb v3: 0 call(s), 1 ref(s); disasm: 0 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t wDev_SetCurChannel(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.wDev_SetCurChannel; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a9 = MEM8(a2 + 0); /* 0007: l8ui a9, a2, 0 */
  a8 = (uint32_t)&wDevCtrl; /* 000a: l32r a8, 0 <wDev_SetCurChannel-0x4> (0 <wDev_SetCurChannel-0x4>) */ /* literal @0x0: wDevCtrl */
  MEM8(a8 + 44) = a9; /* 000d: s8i a9, a8, 44 */
  MEMW(); /* 0010: memw  */
  a2 = MEM8(a2 + 1); /* 0013: l8ui a2, a2, 1 */
  MEM8(a8 + 45) = a2; /* 0016: s8i a2, a8, 45 */
  MEMW(); /* 0019: memw  */
  MEMW(); /* 001c: memw  */
  return (int32_t)a2; /* 001f: retw.n  */
}

/* wDev_Set_Beacon_Int @ wdev.o 00000004 size 13B bind GLOBAL
 * Calls: none | Data refs: BcnInterval
 *   MMIO: none
 *   funcdb v3: 0 call(s), 1 ref(s); disasm: 0 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t wDev_Set_Beacon_Int(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.wDev_Set_Beacon_Int; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a8 = (uint32_t)&BcnInterval; /* 0007: l32r a8, 0 <wDev_Set_Beacon_Int-0x4> (0 <wDev_Set_Beacon_Int-0x4>) */ /* literal @0x0: BcnInterval */
  MEM32(a8 + 0) = a2; /* 000a: s32i.n a2, a8, 0 */
  MEMW(); /* 000c: memw  */
  return (int32_t)a2; /* 000f: retw.n  */
}

/* wDev_Reset_TBTT @ wdev.o 00000004 size 14B bind GLOBAL
 * Calls: hal_mac_tsf_reset | Data refs: hal_mac_tsf_reset
 *   MMIO: none
 *   funcdb v3: 1 call(s), 1 ref(s); disasm: 1 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t wDev_Reset_TBTT(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.wDev_Reset_TBTT; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a10 = 0x0; /* 0007: movi a10, 0 */
  a8 = (uint32_t)&hal_mac_tsf_reset; /* 000a: l32r a8, 0 <wDev_Reset_TBTT-0x4> (0 <wDev_Reset_TBTT-0x4>) */ /* literal: GOT slot for hal_mac_tsf_reset */
  hal_mac_tsf_reset(a2, a3, a4, a5); /* call via literal slot */ /* 000d: callx8 a8 */
  return (int32_t)a2; /* 0010: retw.n  */
}

/* wDev_reset_bcnSendTick @ wdev.o 00000004 size 15B bind GLOBAL
 * Calls: none | Data refs: BcnSendTick
 *   MMIO: none
 *   funcdb v3: 0 call(s), 1 ref(s); disasm: 0 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t wDev_reset_bcnSendTick(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.wDev_reset_bcnSendTick; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a8 = (uint32_t)&BcnSendTick; /* 0007: l32r a8, 0 <wDev_reset_bcnSendTick-0x4> (0 <wDev_reset_bcnSendTick-0x4>) */ /* literal @0x0: BcnSendTick */
  a9 = 0x0; /* 000a: movi.n a9, 0 */
  MEM32(a8 + 0) = a9; /* 000c: s32i.n a9, a8, 0 */
  MEMW(); /* 000e: memw  */
  return (int32_t)a2; /* 0011: retw.n  */
}

/* wDev_Mesh_Enable_Tsf @ wdev.o 00000004 size 14B bind GLOBAL
 * Calls: hal_mac_tsf_reset | Data refs: hal_mac_tsf_reset
 *   MMIO: none
 *   funcdb v3: 1 call(s), 1 ref(s); disasm: 1 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t wDev_Mesh_Enable_Tsf(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.wDev_Mesh_Enable_Tsf; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a10 = 0x1; /* 0007: movi a10, 1 */
  a8 = (uint32_t)&hal_mac_tsf_reset; /* 000a: l32r a8, 0 <wDev_Mesh_Enable_Tsf-0x4> (0 <wDev_Mesh_Enable_Tsf-0x4>) */ /* literal: GOT slot for hal_mac_tsf_reset */
  hal_mac_tsf_reset(a2, a3, a4, a5); /* call via literal slot */ /* 000d: callx8 a8 */
  return (int32_t)a2; /* 0010: retw.n  */
}

/* wDev_Mesh_Set_TBTT @ wdev.o 00000004 size 18B bind GLOBAL
 * Calls: hal_mac_tsf_set_time | Data refs: hal_mac_tsf_set_time
 *   MMIO: none
 *   funcdb v3: 1 call(s), 1 ref(s); disasm: 1 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t wDev_Mesh_Set_TBTT(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.wDev_Mesh_Set_TBTT; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a12 = a2; /* 0007: mov.n a12, a2 */
  a13 = a3; /* 0009: mov.n a13, a3 */
  a10 = 0x1; /* 000b: movi a10, 1 */
  a8 = (uint32_t)&hal_mac_tsf_set_time; /* 000e: l32r a8, 0 <wDev_Mesh_Set_TBTT-0x4> (0 <wDev_Mesh_Set_TBTT-0x4>) */ /* literal: GOT slot for hal_mac_tsf_set_time */
  hal_mac_tsf_set_time(a2, a3, a4, a5); /* call via literal slot */ /* 0011: callx8 a8 */
  return (int32_t)a2; /* 0014: retw.n  */
}

/* wDev_Get_Next_TBTT @ wdev.o 00000010 size 49B bind GLOBAL
 * Calls: hal_get_tsf_time | Data refs: BcnInterval, BcnSendTick, hal_get_tsf_time
 *   MMIO: none
 *   funcdb v3: 1 call(s), 3 ref(s); disasm: 1 call(s), 3 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t wDev_Get_Next_TBTT(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.wDev_Get_Next_TBTT; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_10:;
  /* 0010: entry a1, 32 */
  a4 = (uint32_t)&BcnSendTick; /* 0013: l32r a4, 0 <wDev_Get_Next_TBTT-0x10> (0 <wDev_Get_Next_TBTT-0x10>) */ /* literal @0x0: BcnSendTick */
L_16:;
  a10 = 0x1; /* 0016: movi.n a10, 1 */
  a3 = (uint32_t)&BcnInterval; /* 0018: l32r a3, 4 <wDev_Get_Next_TBTT-0xc> (0 <wDev_Get_Next_TBTT-0x10>) */ /* literal @0x4: BcnInterval */
  a2 = MEM32(a4 + 0); /* 001b: l32i.n a2, a4, 0 */
  a8 = MEM32(a3 + 0); /* 001d: l32i.n a8, a3, 0 */
  a2 = a2 + a8; /* 001f: add.n a2, a2, a8 */
  MEM32(a4 + 0) = a2; /* 0021: s32i.n a2, a4, 0 */
  MEMW(); /* 0023: memw  */
  a8 = (uint32_t)&hal_get_tsf_time; /* 0026: l32r a8, c <wDev_Get_Next_TBTT-0x4> (0 <wDev_Get_Next_TBTT-0x10>) */ /* literal: GOT slot for hal_get_tsf_time */
  hal_get_tsf_time(a2, a3, a4, a5); /* call via literal slot */ /* 0029: callx8 a8 */
  a10 = a2 - a10; /* 002c: sub a10, a2, a10 */
  a2 = MEM32(a3 + 0); /* 002f: l32i.n a2, a3, 0 */
  if (a2 < a10) goto L_16; /* 0031: bltu a2, a10, 16 <wDev_Get_Next_TBTT+0x6> */
  a2 = 0x10624DD3; /* 0034: l32r a2, 8 <wDev_Get_Next_TBTT-0x8> (10624dd3 <wDev_ProcessFiq+0x10624d5f>) */ @0x8
  a2 = (uint32_t)(((uint64_t)a10 * a2) >> 32) /* muluh: high word */; /* 0037: muluh a2, a10, a2 */
  a2 = a2 >> (6 & 31); /* 003a: srli a2, a2, 6 */
  a2 = a2 + (1); /* 003d: addi.n a2, a2, 1 */
  return (int32_t)a2; /* 003f: retw.n  */
}

/* wDev_Get_Next_BcnOffset @ wdev.o 00000010 size 45B bind GLOBAL
 * Calls: hal_get_tsf_time | Data refs: BcnInterval, BcnSendTick, hal_get_tsf_time
 *   MMIO: none
 *   funcdb v3: 1 call(s), 3 ref(s); disasm: 1 call(s), 3 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t wDev_Get_Next_BcnOffset(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.wDev_Get_Next_BcnOffset; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_10:;
  /* 0010: entry a1, 32 */
  a2 = (uint32_t)&BcnSendTick; /* 0013: l32r a2, 0 <wDev_Get_Next_BcnOffset-0x10> (0 <wDev_Get_Next_BcnOffset-0x10>) */ /* literal @0x0: BcnSendTick */
  a3 = (uint32_t)&BcnInterval; /* 0016: l32r a3, 4 <wDev_Get_Next_BcnOffset-0xc> (0 <wDev_Get_Next_BcnOffset-0x10>) */ /* literal @0x4: BcnInterval */
  a2 = MEM32(a2 + 0); /* 0019: l32i a2, a2, 0 */
L_1c:;
  a10 = 0x1; /* 001c: movi.n a10, 1 */
  a8 = MEM32(a3 + 0); /* 001e: l32i.n a8, a3, 0 */
  a2 = a2 + a8; /* 0020: add.n a2, a2, a8 */
  a8 = (uint32_t)&hal_get_tsf_time; /* 0022: l32r a8, c <wDev_Get_Next_BcnOffset-0x4> (0 <wDev_Get_Next_BcnOffset-0x10>) */ /* literal: GOT slot for hal_get_tsf_time */
  hal_get_tsf_time(a2, a3, a4, a5); /* call via literal slot */ /* 0025: callx8 a8 */
  a10 = a2 - a10; /* 0028: sub a10, a2, a10 */
  a8 = MEM32(a3 + 0); /* 002b: l32i.n a8, a3, 0 */
  if (a8 < a10) goto L_1c; /* 002d: bltu a8, a10, 1c <wDev_Get_Next_BcnOffset+0xc> */
  a2 = 0x10624DD3; /* 0030: l32r a2, 8 <wDev_Get_Next_BcnOffset-0x8> (10624dd3 <wDev_ProcessFiq+0x10624d5f>) */ @0x8
  a10 = (uint32_t)(((uint64_t)a10 * a2) >> 32) /* muluh: high word */; /* 0033: muluh a10, a10, a2 */
  a2 = a10 >> (6 & 31); /* 0036: srli a2, a10, 6 */
  a2 = a2 + (1); /* 0039: addi.n a2, a2, 1 */
  return (int32_t)a2; /* 003b: retw.n  */
}

/* wdev_bank_store @ wdev.o 00000000 size 32B bind GLOBAL
 * Calls: none | Data refs: none
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t wdev_bank_store(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .wifi0iram.3; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_0:;
  /* 0000: entry a1, 32 */
  a8 = a3; /* 0003: mov.n a8, a3 */
  goto L_16; /* 0005: j 16 <wdev_bank_store+0x16> */
L_8:;
  MEMW(); /* 0008: memw  */
  a10 = MEM32(a8 + 0); /* 000b: l32i.n a10, a8, 0 */
  a9 = a8 - a3; /* 000d: sub a9, a8, a3 */
  a9 = a2 + a9; /* 0010: add.n a9, a2, a9 */
  a8 = a8 + (4); /* 0012: addi.n a8, a8, 4 */
  MEM32(a9 + 0) = a10; /* 0014: s32i.n a10, a9, 0 */
L_16:;
  a4 = a4 + (-1); /* 0016: addi.n a4, a4, -1 */
  if (a4 != -1) goto L_8; /* 0018: bnei a4, -1, 8 <wdev_bank_store+0x8> */
  MEMW(); /* 001b: memw  */
  return (int32_t)a2; /* 001e: retw.n  */
}

/* wdev_bank_load @ wdev.o 00000000 size 30B bind GLOBAL
 * Calls: none | Data refs: none
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t wdev_bank_load(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .wifi0iram.4; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_0:;
  /* 0000: entry a1, 32 */
  a2 = a2 - a3; /* 0003: sub a2, a2, a3 */
  goto L_12; /* 0006: j 12 <wdev_bank_load+0x12> */
L_9:;
  a9 = MEM32(a3 + 0); /* 0009: l32i.n a9, a3, 0 */
  a3 = a3 + (4); /* 000b: addi.n a3, a3, 4 */
  MEMW(); /* 000d: memw  */
  MEM32(a8 + 0) = a9; /* 0010: s32i.n a9, a8, 0 */
L_12:;
  a4 = a4 + (-1); /* 0012: addi.n a4, a4, -1 */
  a8 = a3 + a2; /* 0014: add.n a8, a3, a2 */
  if (a4 != -1) goto L_9; /* 0016: bnei a4, -1, 9 <wdev_bank_load+0x9> */
  MEMW(); /* 0019: memw  */
  return (int32_t)a2; /* 001c: retw.n  */
}

/* wdev_mac_reg_load @ wdev.o 00000030 size 104B bind GLOBAL
 * Calls: wdev_bank_load[got], wdev_bank_load[got], wdev_bank_load[got], wdev_bank_load[got], wdev_bank_load[got], wdev_bank_load[got] | Data refs: wdev_bank_load
 *   MMIO: none
 *   FP/data literals (loaded, never dereferenced - NOT MMIO): 0x3FF73000, 0x3FF73400, 0x3FF73800, 0x3FF73C00, 0x3FF74000, 0x3FF74400
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 6 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t wdev_mac_reg_load(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .wifi0iram.5; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_30:;
  /* 0030: entry a1, 32 */
  a10 = 0x3FF73000; /* 0033: l32r a10, 0 <wdev_mac_reg_load-0x30> (3ff73000 <wDev_ProcessFiq+0x3ff72f8c>) */ /* MMIO base */ @0x0
  a11 = a2; /* 0036: mov.n a11, a2 */
  a12 = 0xBC; /* 0038: movi a12, 188 */
  a8 = (uint32_t)&wdev_bank_load; /* 003b: l32r a8, 18 <wdev_mac_reg_load-0x18> (0 <wdev_mac_reg_load-0x30>) */ /* literal: GOT slot for wdev_bank_load */
  wdev_bank_load(a2, a3, a4, a5); /* call via literal slot */ /* 003e: callx8 a8 */
  a11 = 0x2F0; /* 0041: movi a11, 0x2f0 */
  a10 = 0x3FF73400; /* 0044: l32r a10, 4 <wdev_mac_reg_load-0x2c> (3ff73400 <wDev_ProcessFiq+0x3ff7338c>) */ /* MMIO base */ @0x4
  a11 = a2 + a11; /* 0047: add.n a11, a2, a11 */
  a12 = 0x10; /* 0049: movi.n a12, 16 */
  a8 = (uint32_t)&wdev_bank_load; /* 004b: l32r a8, 1c <wdev_mac_reg_load-0x14> (0 <wdev_mac_reg_load-0x30>) */ /* literal: GOT slot for wdev_bank_load */
  wdev_bank_load(a2, a3, a4, a5); /* call via literal slot */ /* 004e: callx8 a8 */
  a11 = 0x330; /* 0051: movi a11, 0x330 */
  a10 = 0x3FF73800; /* 0054: l32r a10, 8 <wdev_mac_reg_load-0x28> (3ff73800 <wDev_ProcessFiq+0x3ff7378c>) */ /* MMIO base */ @0x8
  a11 = a2 + a11; /* 0057: add.n a11, a2, a11 */
  a12 = 0x11; /* 0059: movi.n a12, 17 */
  a8 = (uint32_t)&wdev_bank_load; /* 005b: l32r a8, 20 <wdev_mac_reg_load-0x10> (0 <wdev_mac_reg_load-0x30>) */ /* literal: GOT slot for wdev_bank_load */
  wdev_bank_load(a2, a3, a4, a5); /* call via literal slot */ /* 005e: callx8 a8 */
  a11 = 0x374; /* 0061: movi a11, 0x374 */
  a10 = 0x3FF73C00; /* 0064: l32r a10, c <wdev_mac_reg_load-0x24> (3ff73c00 <wDev_ProcessFiq+0x3ff73b8c>) */ /* MMIO base */ @0xC
  a11 = a2 + a11; /* 0067: add.n a11, a2, a11 */
  a12 = 0x78; /* 0069: movi a12, 120 */
  a8 = (uint32_t)&wdev_bank_load; /* 006c: l32r a8, 24 <wdev_mac_reg_load-0xc> (0 <wdev_mac_reg_load-0x30>) */ /* literal: GOT slot for wdev_bank_load */
  wdev_bank_load(a2, a3, a4, a5); /* call via literal slot */ /* 006f: callx8 a8 */
  a11 = 0x554; /* 0072: movi a11, 0x554 */
  a10 = 0x3FF74000; /* 0075: l32r a10, 10 <wdev_mac_reg_load-0x20> (3ff74000 <wDev_ProcessFiq+0x3ff73f8c>) */ /* MMIO base */ @0x10
  a11 = a2 + a11; /* 0078: add a11, a2, a11 */
  a12 = 0xD2; /* 007b: movi a12, 210 */
  a8 = (uint32_t)&wdev_bank_load; /* 007e: l32r a8, 28 <wdev_mac_reg_load-0x8> (0 <wdev_mac_reg_load-0x30>) */ /* literal: GOT slot for wdev_bank_load */
  wdev_bank_load(a2, a3, a4, a5); /* call via literal slot */ /* 0081: callx8 a8 */
  a11 = 0x227; /* 0084: movi a11, 0x227 */
  a10 = 0x3FF74400; /* 0087: l32r a10, 14 <wdev_mac_reg_load-0x1c> (3ff74400 <wDev_ProcessFiq+0x3ff7438c>) */ /* MMIO base */ @0x14
  a12 = 0xFA; /* 008a: movi a12, 250 */
  a11 = (a11 << 4) + a2; /* 008d: addx4 a11, a11, a2 */
  a8 = (uint32_t)&wdev_bank_load; /* 0090: l32r a8, 2c <wdev_mac_reg_load-0x4> (0 <wdev_mac_reg_load-0x30>) */ /* literal: GOT slot for wdev_bank_load */
  wdev_bank_load(a2, a3, a4, a5); /* call via literal slot */ /* 0093: callx8 a8 */
  return (int32_t)a2; /* 0096: retw.n  */
}

/* wdev_mac_reg_store @ wdev.o 00000030 size 104B bind GLOBAL
 * Calls: wdev_bank_store[got], wdev_bank_store[got], wdev_bank_store[got], wdev_bank_store[got], wdev_bank_store[got], wdev_bank_store[got] | Data refs: wdev_bank_store
 *   MMIO: none
 *   FP/data literals (loaded, never dereferenced - NOT MMIO): 0x3FF73000, 0x3FF73400, 0x3FF73800, 0x3FF73C00, 0x3FF74000, 0x3FF74400
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 6 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t wdev_mac_reg_store(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .wifi0iram.6; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_30:;
  /* 0030: entry a1, 32 */
  a11 = 0x3FF73000; /* 0033: l32r a11, 0 <wdev_mac_reg_store-0x30> (3ff73000 <wDev_ProcessFiq+0x3ff72f8c>) */ /* MMIO base */ @0x0
  a10 = a2; /* 0036: mov.n a10, a2 */
  a12 = 0xBC; /* 0038: movi a12, 188 */
  a8 = (uint32_t)&wdev_bank_store; /* 003b: l32r a8, 18 <wdev_mac_reg_store-0x18> (0 <wdev_mac_reg_store-0x30>) */ /* literal: GOT slot for wdev_bank_store */
  wdev_bank_store(a2, a3, a4, a5); /* call via literal slot */ /* 003e: callx8 a8 */
  a10 = 0x2F0; /* 0041: movi a10, 0x2f0 */
  a11 = 0x3FF73400; /* 0044: l32r a11, 4 <wdev_mac_reg_store-0x2c> (3ff73400 <wDev_ProcessFiq+0x3ff7338c>) */ /* MMIO base */ @0x4
  a10 = a2 + a10; /* 0047: add.n a10, a2, a10 */
  a12 = 0x10; /* 0049: movi.n a12, 16 */
  a8 = (uint32_t)&wdev_bank_store; /* 004b: l32r a8, 1c <wdev_mac_reg_store-0x14> (0 <wdev_mac_reg_store-0x30>) */ /* literal: GOT slot for wdev_bank_store */
  wdev_bank_store(a2, a3, a4, a5); /* call via literal slot */ /* 004e: callx8 a8 */
  a10 = 0x330; /* 0051: movi a10, 0x330 */
  a11 = 0x3FF73800; /* 0054: l32r a11, 8 <wdev_mac_reg_store-0x28> (3ff73800 <wDev_ProcessFiq+0x3ff7378c>) */ /* MMIO base */ @0x8
  a10 = a2 + a10; /* 0057: add.n a10, a2, a10 */
  a12 = 0x11; /* 0059: movi.n a12, 17 */
  a8 = (uint32_t)&wdev_bank_store; /* 005b: l32r a8, 20 <wdev_mac_reg_store-0x10> (0 <wdev_mac_reg_store-0x30>) */ /* literal: GOT slot for wdev_bank_store */
  wdev_bank_store(a2, a3, a4, a5); /* call via literal slot */ /* 005e: callx8 a8 */
  a10 = 0x374; /* 0061: movi a10, 0x374 */
  a11 = 0x3FF73C00; /* 0064: l32r a11, c <wdev_mac_reg_store-0x24> (3ff73c00 <wDev_ProcessFiq+0x3ff73b8c>) */ /* MMIO base */ @0xC
  a10 = a2 + a10; /* 0067: add.n a10, a2, a10 */
  a12 = 0x78; /* 0069: movi a12, 120 */
  a8 = (uint32_t)&wdev_bank_store; /* 006c: l32r a8, 24 <wdev_mac_reg_store-0xc> (0 <wdev_mac_reg_store-0x30>) */ /* literal: GOT slot for wdev_bank_store */
  wdev_bank_store(a2, a3, a4, a5); /* call via literal slot */ /* 006f: callx8 a8 */
  a10 = 0x554; /* 0072: movi a10, 0x554 */
  a11 = 0x3FF74000; /* 0075: l32r a11, 10 <wdev_mac_reg_store-0x20> (3ff74000 <wDev_ProcessFiq+0x3ff73f8c>) */ /* MMIO base */ @0x10
  a10 = a2 + a10; /* 0078: add a10, a2, a10 */
  a12 = 0xD2; /* 007b: movi a12, 210 */
  a8 = (uint32_t)&wdev_bank_store; /* 007e: l32r a8, 28 <wdev_mac_reg_store-0x8> (0 <wdev_mac_reg_store-0x30>) */ /* literal: GOT slot for wdev_bank_store */
  wdev_bank_store(a2, a3, a4, a5); /* call via literal slot */ /* 0081: callx8 a8 */
  a10 = 0x227; /* 0084: movi a10, 0x227 */
  a11 = 0x3FF74400; /* 0087: l32r a11, 14 <wdev_mac_reg_store-0x1c> (3ff74400 <wDev_ProcessFiq+0x3ff7438c>) */ /* MMIO base */ @0x14
  a12 = 0xFA; /* 008a: movi a12, 250 */
  a10 = (a10 << 4) + a2; /* 008d: addx4 a10, a10, a2 */
  a8 = (uint32_t)&wdev_bank_store; /* 0090: l32r a8, 2c <wdev_mac_reg_store-0x4> (0 <wdev_mac_reg_store-0x30>) */ /* literal: GOT slot for wdev_bank_store */
  wdev_bank_store(a2, a3, a4, a5); /* call via literal slot */ /* 0093: callx8 a8 */
  return (int32_t)a2; /* 0096: retw.n  */
}

/* wdev_mac_special_reg_load @ wdev.o 00000010 size 20B bind GLOBAL
 * Calls: hal_ba_session_restore[got] | Data refs: wDevMacSleep, hal_ba_session_restore
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 1 call(s), 2 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t wdev_mac_special_reg_load(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .wifi0iram.7; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_10:;
  /* 0010: entry a1, 32 */
  a12 = (uint32_t)&wDevMacSleep; /* 0013: l32r a12, 0 <wdev_mac_special_reg_load-0x10> (0 <wdev_mac_special_reg_load-0x10>) */ /* literal @0x0: wDevMacSleep */
  a11 = (uint32_t)&wDevMacSleep; /* 0016: l32r a11, 4 <wdev_mac_special_reg_load-0xc> (0 <wdev_mac_special_reg_load-0x10>) */ /* literal @0x4: wDevMacSleep */
  a10 = (uint32_t)&wDevMacSleep; /* 0019: l32r a10, 8 <wdev_mac_special_reg_load-0x8> (0 <wdev_mac_special_reg_load-0x10>) */ /* literal @0x8: wDevMacSleep */
  a8 = (uint32_t)&hal_ba_session_restore; /* 001c: l32r a8, c <wdev_mac_special_reg_load-0x4> (0 <wdev_mac_special_reg_load-0x10>) */ /* literal: GOT slot for hal_ba_session_restore */
  hal_ba_session_restore(a2, a3, a4, a5); /* call via literal slot */ /* 001f: callx8 a8 */
  return (int32_t)a2; /* 0022: retw.n  */
}

/* wdev_mac_special_reg_store @ wdev.o 00000010 size 20B bind GLOBAL
 * Calls: hal_ba_session_store[got] | Data refs: wDevMacSleep, hal_ba_session_store
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 1 call(s), 2 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t wdev_mac_special_reg_store(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .wifi0iram.8; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_10:;
  /* 0010: entry a1, 32 */
  a12 = (uint32_t)&wDevMacSleep; /* 0013: l32r a12, 0 <wdev_mac_special_reg_store-0x10> (0 <wdev_mac_special_reg_store-0x10>) */ /* literal @0x0: wDevMacSleep */
  a11 = (uint32_t)&wDevMacSleep; /* 0016: l32r a11, 4 <wdev_mac_special_reg_store-0xc> (0 <wdev_mac_special_reg_store-0x10>) */ /* literal @0x4: wDevMacSleep */
  a10 = (uint32_t)&wDevMacSleep; /* 0019: l32r a10, 8 <wdev_mac_special_reg_store-0x8> (0 <wdev_mac_special_reg_store-0x10>) */ /* literal @0x8: wDevMacSleep */
  a8 = (uint32_t)&hal_ba_session_store; /* 001c: l32r a8, c <wdev_mac_special_reg_store-0x4> (0 <wdev_mac_special_reg_store-0x10>) */ /* literal: GOT slot for hal_ba_session_store */
  hal_ba_session_store(a2, a3, a4, a5); /* call via literal slot */ /* 001f: callx8 a8 */
  return (int32_t)a2; /* 0022: retw.n  */
}

/* wdev_mac_sleep_init @ wdev.o 00000018 size 74B bind GLOBAL
 * Calls: wifi_log, g_osi_funcs_p[got] | Data refs: .rodata_wlog_info.10, .rodata_wlog_warning.9, g_osi_funcs_p, wDevMacSleep, wifi_log
 *   MMIO: none
 *   funcdb v3: 1 call(s), 5 ref(s); disasm: 3 call(s), 5 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t wdev_mac_sleep_init(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.wdev_mac_sleep_init; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_18:;
  /* 0018: entry a1, 32 */
  a2 = (uint32_t)&wDevMacSleep; /* 001b: l32r a2, 0 <wdev_mac_sleep_init-0x18> (0 <wdev_mac_sleep_init-0x18>) */ /* literal @0x0: wDevMacSleep */
  a8 = MEM32(a2 + 4); /* 001e: l32i.n a8, a2, 4 */
  if (a8 != 0) goto L_60; /* 0020: bnez.n a8, 60 <wdev_mac_sleep_init+0x48> */
  a10 = 0x321; /* 0022: movi a10, 0x321 */
  a10 = 0xC84; /* 0025: slli a10, a10, 2 */
  a8 = (uint32_t)&g_osi_funcs_p; /* 0028: l32r a8, 4 <wdev_mac_sleep_init-0x14> (0 <wdev_mac_sleep_init-0x18>) */ /* literal @0x4: g_osi_funcs_p */
  a8 = MEM32(a8 + 0); /* 002b: l32i a8, a8, 0 */
  a8 = MEM32(a8 + 348); /* 002e: l32i a8, a8, 0x15c */
  g_osi_funcs_p(a2, a3, a4, a5); /* call via literal slot */ /* 0031: callx8 a8 */
  a11 = 0x1; /* 0034: movi.n a11, 1 */
  a11 = 0x1000; /* 0036: slli a11, a11, 12 */
  MEM32(a2 + 4) = a10; /* 0039: s32i.n a10, a2, 4 */
  if (a10 != 0) goto L_51; /* 003b: bnez.n a10, 51 <wdev_mac_sleep_init+0x39> */
  a12 = 0x2; /* 003d: movi.n a12, 2 */
  a10 = 0x6; /* 003f: movi.n a10, 6 */
  a13 = (uint32_t)&lit_rodata_wlog_warning_9; /* 0041: l32r a13, 8 <wdev_mac_sleep_init-0x10> (0 <wdev_mac_sleep_init-0x18>) */ /* literal @0x8: .rodata_wlog_warning.9 */
  MEMW(); /* 0044: memw  */
  a8 = (uint32_t)&wifi_log; /* 0047: l32r a8, 10 <wdev_mac_sleep_init-0x8> (0 <wdev_mac_sleep_init-0x18>) */ /* literal: GOT slot for wifi_log */
  wifi_log(a2, a3, a4, a5); /* call via literal slot */ /* 004a: callx8 a8 */
  goto L_60; /* 004d: j 60 <wdev_mac_sleep_init+0x48> */
  /* 0050: .byte 00 */
L_51:;
  a13 = (uint32_t)&lit_rodata_wlog_info_10; /* 0051: l32r a13, c <wdev_mac_sleep_init-0xc> (0 <wdev_mac_sleep_init-0x18>) */ /* literal @0xC: .rodata_wlog_info.10 */
  a14 = 0x6; /* 0054: mov.n a14, a10 */
  a12 = 0x3; /* 0056: movi.n a12, 3 */
  a10 = 0x6; /* 0058: movi.n a10, 6 */
  a8 = (uint32_t)&wifi_log; /* 005a: l32r a8, 14 <wdev_mac_sleep_init-0x4> (0 <wdev_mac_sleep_init-0x18>) */ /* literal: GOT slot for wifi_log */
  wifi_log(a2, a3, a4, a5); /* call via literal slot */ /* 005d: callx8 a8 */
L_60:;
  return (int32_t)a2; /* 0060: retw.n  */
}

/* wdev_mac_sleep_deinit @ wdev.o 00000008 size 30B bind GLOBAL
 * Calls: g_osi_funcs_p[got] | Data refs: g_osi_funcs_p, wDevMacSleep
 *   MMIO: none
 *   funcdb v3: 0 call(s), 2 ref(s); disasm: 1 call(s), 2 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t wdev_mac_sleep_deinit(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.wdev_mac_sleep_deinit; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_8:;
  /* 0008: entry a1, 32 */
  a2 = (uint32_t)&wDevMacSleep; /* 000b: l32r a2, 0 <wdev_mac_sleep_deinit-0x8> (0 <wdev_mac_sleep_deinit-0x8>) */ /* literal @0x0: wDevMacSleep */
  a10 = MEM32(a2 + 4); /* 000e: l32i.n a10, a2, 4 */
  if (a10 == 0) goto L_21; /* 0010: beqz.n a10, 21 <wdev_mac_sleep_deinit+0x19> */
  a8 = (uint32_t)&g_osi_funcs_p; /* 0012: l32r a8, 4 <wdev_mac_sleep_deinit-0x4> (0 <wdev_mac_sleep_deinit-0x8>) */ /* literal @0x4: g_osi_funcs_p */
  a8 = MEM32(a8 + 0); /* 0015: l32i.n a8, a8, 0 */
  a8 = MEM32(a8 + 176); /* 0017: l32i a8, a8, 176 */
  g_osi_funcs_p(a2, a3, a4, a5); /* call via literal slot */ /* 001a: callx8 a8 */
  a8 = 0x0; /* 001d: movi.n a8, 0 */
  MEM32(a2 + 4) = a8; /* 001f: s32i.n a8, a2, 4 */
L_21:;
  MEMW(); /* 0021: memw  */
  return (int32_t)a2; /* 0024: retw.n  */
}

/* wdev_mac_wakeup @ wdev.o 00000020 size 145B bind GLOBAL
 * Calls: g_osi_funcs_p[got], wdev_mac_reg_load[got], hal_enable_mac[got], wdev_mac_special_reg_load[got] | Data refs: wDevMacSleep, g_osi_funcs_p, wdev_mac_reg_load, hal_enable_mac, wdev_mac_special_reg_load
 *   MMIO: 0x3FF73C04, 0x3FF73084
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 4 call(s), 5 data ref(s)
 * Fidelity: medium - 53 instr, 4 branches, calls resolved */
int32_t wdev_mac_wakeup(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .wifi0iram.11; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_20:;
  /* 0020: entry a1, 32 */
  a2 = (uint32_t)&wDevMacSleep; /* 0023: l32r a2, 0 <wdev_mac_wakeup-0x20> (0 <wdev_mac_wakeup-0x20>) */ /* literal @0x0: wDevMacSleep */
  a3 = MEM8(a2 + 0); /* 0026: l8ui a3, a2, 0 */
  if (a3 == 0) goto L_39; /* 0029: beqz.n a3, 39 <wdev_mac_wakeup+0x19> */
  a3 = 0x0; /* 002b: movi.n a3, 0 */
  MEM8(a2 + 0) = a3; /* 002d: s8i a3, a2, 0 */
  MEMW(); /* 0030: memw  */
  MEMW(); /* 0033: memw  */
  goto L_ac; /* 0036: j ac <wdev_mac_wakeup+0x8c> */
L_39:;
  a8 = MEM8(a2 + 1); /* 0039: l8ui a8, a2, 1 */
  if (a8 == 0) goto L_ac; /* 003c: beqz a8, ac <wdev_mac_wakeup+0x8c> */
  MEM8(a2 + 1) = a3; /* 003f: s8i a3, a2, 1 */
  MEMW(); /* 0042: memw  */
  a3 = MEM32(a2 + 4); /* 0045: l32i.n a3, a2, 4 */
  if (a3 == 0) goto L_ac; /* 0047: beqz a3, ac <wdev_mac_wakeup+0x8c> */
  a3 = (uint32_t)&g_osi_funcs_p; /* 004a: l32r a3, 4 <wdev_mac_wakeup-0x1c> (0 <wdev_mac_wakeup-0x20>) */ /* literal @0x4: g_osi_funcs_p */
  a3 = MEM32(a3 + 0); /* 004d: l32i.n a3, a3, 0 */
  a3 = MEM32(a3 + 268); /* 004f: l32i a3, a3, 0x10c */
  MEMW(); /* 0052: memw  */
  g_osi_funcs_p(a2, a3, a4, a5); /* call via literal slot */ /* 0055: callx8 a3 */
  a9 = 0xF0; /* 0058: movi a9, 240 */
  a8 = 0x3FF73C04; /* 005b: l32r a8, 8 <wdev_mac_wakeup-0x18> (3ff73c04 <wDev_ProcessFiq+0x3ff73b90>) */ /* MMIO base */ @0x8
  MEMW(); /* 005e: memw  */
  a3 = REG32(0x3FF73C04); /* 0061: l32i.n a3, a8, 0 */ /* MMIO read: base 0x3FF73C04+0 */
  a3 = a3 | a9; /* 0063: or a3, a3, a9 */
  MEMW(); /* 0066: memw  */
  REG32(0x3FF73C04) = a3; /* 0069: s32i.n a3, a8, 0 */ /* MMIO write: base 0x3FF73C04+0 */
  a3 = 0x3FF73084; /* 006b: l32r a3, c <wdev_mac_wakeup-0x14> (3ff73084 <wDev_ProcessFiq+0x3ff73010>) */ /* MMIO base */ @0xC
  a9 = 0x7FFFFFFF; /* 006e: l32r a9, 10 <wdev_mac_wakeup-0x10> (7fffffff <wDev_ProcessFiq+0x7fffff8b>) */ @0x10
  MEMW(); /* 0071: memw  */
  a8 = REG32(0x3FF73084); /* 0074: l32i.n a8, a3, 0 */ /* MMIO read: base 0x3FF73084+0 */
  a8 = a8 & a9; /* 0076: and a8, a8, a9 */
  a10 = MEM32(a2 + 4); /* 0079: l32i.n a10, a2, 4 */
  MEMW(); /* 007b: memw  */
  REG32(0x3FF73084) = a8; /* 007e: s32i a8, a3, 0 */ /* MMIO write: base 0x3FF73084+0 */
  MEMW(); /* 0081: memw  */
  a8 = (uint32_t)&wdev_mac_reg_load; /* 0084: l32r a8, 14 <wdev_mac_wakeup-0xc> (0 <wdev_mac_wakeup-0x20>) */ /* literal: GOT slot for wdev_mac_reg_load */
  wdev_mac_reg_load(a2, a3, a4, a5); /* call via literal slot */ /* 0087: callx8 a8 */
  a11 = MEM32(a2 + 12); /* 008a: l32i.n a11, a2, 12 */
  a10 = MEM32(a2 + 8); /* 008c: l32i.n a10, a2, 8 */
  a8 = (uint32_t)&hal_enable_mac; /* 008e: l32r a8, 18 <wdev_mac_wakeup-0x8> (0 <wdev_mac_wakeup-0x20>) */ /* literal: GOT slot for hal_enable_mac */
  hal_enable_mac(a2, a3, a4, a5); /* call via literal slot */ /* 0091: callx8 a8 */
  a8 = (uint32_t)&wdev_mac_special_reg_load; /* 0094: l32r a8, 1c <wdev_mac_wakeup-0x4> (0 <wdev_mac_wakeup-0x20>) */ /* literal: GOT slot for wdev_mac_special_reg_load */
  wdev_mac_special_reg_load(a2, a3, a4, a5); /* call via literal slot */ /* 0097: callx8 a8 */
  a8 = 0xFFFFFFFF; /* 009a: movi.n a8, -1 */
  MEMW(); /* 009c: memw  */
  a2 = MEM32(a3 + 0); /* 009f: l32i.n a2, a3, 0 */
  a8 = 0x80000000; /* 00a1: slli a8, a8, 31 */
  a2 = a2 | a8; /* 00a4: or a2, a2, a8 */
  MEMW(); /* 00a7: memw  */
  MEM32(a3 + 0) = a2; /* 00aa: s32i.n a2, a3, 0 */
L_ac:;
  MEMW(); /* 00ac: memw  */
  return (int32_t)a2; /* 00af: retw.n  */
}

/* wdev_is_data_in_rxlist @ wdev.o 00000008 size 42B bind GLOBAL
 * Calls: hal_mac_rx_get_last_dscr[got] | Data refs: wDevCtrl, hal_mac_rx_get_last_dscr
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 1 call(s), 2 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t wdev_is_data_in_rxlist(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .wifi0iram.12; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_8:;
  /* 0008: entry a1, 32 */
  a2 = (uint32_t)&wDevCtrl; /* 000b: l32r a2, 0 <wdev_is_data_in_rxlist-0x8> (0 <wdev_is_data_in_rxlist-0x8>) */ /* literal @0x0: wDevCtrl */
  a3 = MEM32(a2 + 0); /* 000e: l32i.n a3, a2, 0 */
  a8 = (uint32_t)&hal_mac_rx_get_last_dscr; /* 0010: l32r a8, 4 <wdev_is_data_in_rxlist-0x4> (0 <wdev_is_data_in_rxlist-0x8>) */ /* literal: GOT slot for hal_mac_rx_get_last_dscr */
  hal_mac_rx_get_last_dscr(a2, a3, a4, a5); /* call via literal slot */ /* 0013: callx8 a8 */
  goto L_2b; /* 0016: j 2b <wdev_is_data_in_rxlist+0x23> */
L_19:;
  MEMW(); /* 0019: memw  */
  a2 = MEM32(a3 + 0); /* 001c: l32i.n a2, a3, 0 */
  a2 = (a2 >> 30) & 0x1; /* 001e: extui a2, a2, 30, 1 */
  a8 = MEM32(a3 + 8); /* 0021: l32i.n a8, a3, 8 */
  if (a2 == 1) goto L_30; /* 0023: beqi a2, 1, 30 <wdev_is_data_in_rxlist+0x28> */
  if (a3 == a10) goto L_30; /* 0026: beq a3, a10, 30 <wdev_is_data_in_rxlist+0x28> */
  a3 = a8; /* 0029: mov.n a3, a8 */
L_2b:;
  if (a3 != 0) goto L_19; /* 002b: bnez a3, 19 <wdev_is_data_in_rxlist+0x11> */
  a2 = a3; /* 002e: mov.n a2, a3 */
L_30:;
  return (int32_t)a2; /* 0030: retw.n  */
}

/* wdev_mac_sleep @ wdev.o 00000024 size 131B bind GLOBAL
 * Calls: wdev_is_data_in_rxlist[got], wdev_mac_special_reg_store[got], hal_disable_mac[got], wdev_mac_reg_store[got], g_osi_funcs_p[got] | Data refs: wDevMacSleep, wdev_is_data_in_rxlist, wdev_mac_special_reg_store, hal_disable_mac, wdev_mac_reg_store, wDevCtrl, g_osi_funcs_p
 *   MMIO: 0x3FF73084
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 5 call(s), 7 data ref(s)
 * Fidelity: medium - 48 instr, 3 branches, calls resolved */
int32_t wdev_mac_sleep(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .wifi0iram.13; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_24:;
  /* 0024: entry a1, 32 */
  a2 = (uint32_t)&wDevMacSleep; /* 0027: l32r a2, 0 <wdev_mac_sleep-0x24> (0 <wdev_mac_sleep-0x24>) */ /* literal @0x0: wDevMacSleep */
  a3 = MEM32(a2 + 4); /* 002a: l32i.n a3, a2, 4 */
  if (a3 == 0) goto L_a5; /* 002c: beqz a3, a5 <wdev_mac_sleep+0x81> */
  a3 = 0x3FF73084; /* 002f: l32r a3, 4 <wdev_mac_sleep-0x20> (3ff73084 <wDev_ProcessFiq+0x3ff73010>) */ /* MMIO base */ @0x4
  a9 = 0x7FFFFFFF; /* 0032: l32r a9, 8 <wdev_mac_sleep-0x1c> (7fffffff <wDev_ProcessFiq+0x7fffff8b>) */ @0x8
  MEMW(); /* 0035: memw  */
  a8 = REG32(0x3FF73084); /* 0038: l32i.n a8, a3, 0 */ /* MMIO read: base 0x3FF73084+0 */
  a8 = a8 & a9; /* 003a: and a8, a8, a9 */
  MEMW(); /* 003d: memw  */
  REG32(0x3FF73084) = a8; /* 0040: s32i a8, a3, 0 */ /* MMIO write: base 0x3FF73084+0 */
  MEMW(); /* 0043: memw  */
  a8 = (uint32_t)&wdev_is_data_in_rxlist; /* 0046: l32r a8, 14 <wdev_mac_sleep-0x10> (0 <wdev_mac_sleep-0x24>) */ /* literal: GOT slot for wdev_is_data_in_rxlist */
  wdev_is_data_in_rxlist(a2, a3, a4, a5); /* call via literal slot */ /* 0049: callx8 a8 */
  MEM8(a2 + 0) = a10; /* 004c: s8i a10, a2, 0 */
  MEMW(); /* 004f: memw  */
  if (a10 == 0) goto L_6c; /* 0052: beqz.n a10, 6c <wdev_mac_sleep+0x48> */
  a8 = 0xFFFFFFFF; /* 0054: movi.n a8, -1 */
  a8 = 0x80000000; /* 0056: slli a8, a8, 31 */
  MEMW(); /* 0059: memw  */
  a2 = MEM32(a3 + 0); /* 005c: l32i.n a2, a3, 0 */
  a2 = a2 | a8; /* 005e: or a2, a2, a8 */
  MEMW(); /* 0061: memw  */
  MEM32(a3 + 0) = a2; /* 0064: s32i.n a2, a3, 0 */
  MEMW(); /* 0066: memw  */
  goto L_a5; /* 0069: j a5 <wdev_mac_sleep+0x81> */
L_6c:;
  a3 = 0x1; /* 006c: movi.n a3, 1 */
  MEM8(a2 + 1) = a3; /* 006e: s8i a3, a2, 1 */
  MEMW(); /* 0071: memw  */
  MEMW(); /* 0074: memw  */
  a8 = (uint32_t)&wdev_mac_special_reg_store; /* 0077: l32r a8, 18 <wdev_mac_sleep-0xc> (0 <wdev_mac_sleep-0x24>) */ /* literal: GOT slot for wdev_mac_special_reg_store */
  wdev_mac_special_reg_store(a2, a3, a4, a5); /* call via literal slot */ /* 007a: callx8 a8 */
  a8 = (uint32_t)&hal_disable_mac; /* 007d: l32r a8, 1c <wdev_mac_sleep-0x8> (0 <wdev_mac_sleep-0x24>) */ /* literal: GOT slot for hal_disable_mac */
  hal_disable_mac(a2, a3, a4, a5); /* call via literal slot */ /* 0080: callx8 a8 */
  MEM32(a2 + 8) = a10; /* 0083: s32i.n a10, a2, 8 */
  a10 = MEM32(a2 + 4); /* 0085: l32i.n a10, a2, 4 */
  MEMW(); /* 0087: memw  */
  a8 = (uint32_t)&wdev_mac_reg_store; /* 008a: l32r a8, 20 <wdev_mac_sleep-0x4> (0 <wdev_mac_sleep-0x24>) */ /* literal: GOT slot for wdev_mac_reg_store */
  wdev_mac_reg_store(a2, a3, a4, a5); /* call via literal slot */ /* 008d: callx8 a8 */
  a3 = (uint32_t)&wDevCtrl; /* 0090: l32r a3, c <wdev_mac_sleep-0x18> (0 <wdev_mac_sleep-0x24>) */ /* literal @0xC: wDevCtrl */
  a3 = MEM32(a3 + 0); /* 0093: l32i.n a3, a3, 0 */
  MEM32(a2 + 12) = a3; /* 0095: s32i.n a3, a2, 12 */
  a2 = (uint32_t)&g_osi_funcs_p; /* 0097: l32r a2, 10 <wdev_mac_sleep-0x14> (0 <wdev_mac_sleep-0x24>) */ /* literal @0x10: g_osi_funcs_p */
  a2 = MEM32(a2 + 0); /* 009a: l32i.n a2, a2, 0 */
  a2 = MEM32(a2 + 264); /* 009c: l32i a2, a2, 0x108 */
  MEMW(); /* 009f: memw  */
  g_osi_funcs_p(a2, a3, a4, a5); /* call via literal slot */ /* 00a2: callx8 a2 */
L_a5:;
  return (int32_t)a2; /* 00a5: retw.n  */
}

/* wdev_csi_len_align @ wdev.o 00000000 size 30B bind GLOBAL
 * Calls: none | Data refs: none
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t wdev_csi_len_align(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .wifislpiram.14; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_0:;
  /* 0000: entry a1, 32 */
  a8 = MEM32(a2 + 20); /* 0003: l32i.n a8, a2, 20 */
  a2 = 0x3FF; /* 0005: movi a2, 0x3ff */
  a2 = 0x3FF00; /* 0008: slli a2, a2, 8 */
  a2 = a8 & a2; /* 000b: and a2, a8, a2 */
  if (a2 == 0) goto L_1c; /* 000e: beqz.n a2, 1c <wdev_csi_len_align+0x1c> */
  a2 = (a8 >> 8) & 0x3FF; /* 0010: extui a2, a8, 8, 10 */
  a2 = a2 + (3); /* 0013: addi a2, a2, 3 */
  a2 = (int32_t)a2 >> (2 & 31); /* 0016: srai a2, a2, 2 */
  a2 = a2 << (2 & 31); /* 0019: slli a2, a2, 2 */
L_1c:;
  return (int32_t)a2; /* 001c: retw.n  */
}

/* wdev_csi_hw_bug_check @ wdev.o 0000000c size 107B bind GLOBAL
 * Calls: wifi_log | Data refs: .rodata_wlog_warning.15, wDevCtrl, wifi_log
 *   MMIO: none
 *   funcdb v3: 1 call(s), 3 ref(s); disasm: 1 call(s), 3 data ref(s)
 * Fidelity: medium - 43 instr, 10 branches, calls resolved */
int32_t wdev_csi_hw_bug_check(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.wdev_csi_hw_bug_check; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_c:;
  /* 000c: entry a1, 32 */
  a9 = MEM32(a2 + 0); /* 000f: l32i.n a9, a2, 0 */
  a8 = (a9 >> 0) & 0xFFF; /* 0011: extui a8, a9, 0, 12 */
  a9 = (a9 >> 12) & 0xFFF; /* 0014: extui a9, a9, 12, 12 */
  a2 = MEM32(a3 + 0); /* 0017: l32i.n a2, a3, 0 */
  a10 = (a2 >> 0) & 0xFFF; /* 0019: extui a10, a2, 0, 12 */
  if (a8 != a9) goto L_21; /* 001c: bne a8, a9, 21 <wdev_csi_hw_bug_check+0x15> */
  if (a8 != 0) goto L_29; /* 001f: bnez.n a8, 29 <wdev_csi_hw_bug_check+0x1d> */
L_21:;
  a9 = a9 + (8); /* 0021: addi.n a9, a9, 8 */
  if (a9 != a8) goto L_38; /* 0023: bne a9, a8, 38 <wdev_csi_hw_bug_check+0x2c> */
  goto L_6b; /* 0026: j 6b <wdev_csi_hw_bug_check+0x5f> */
L_29:;
  a8 = a8 - a10; /* 0029: sub a8, a8, a10 */
  a9 = 0x1; /* 002c: movi.n a9, 1 */
  a2 = 0x2; /* 002e: movi.n a2, 2 */
  if (a8 == 0) a2 = a9; /* 0030: moveqz a2, a9, a8 */
  goto L_75; /* 0033: j 75 <wdev_csi_hw_bug_check+0x69> */
  /* 0036: .byte 00 */
  /* 0037: .byte 00 */
L_38:;
  a8 = (a2 >> 12) & 0xFFF; /* 0038: extui a8, a2, 12, 12 */
  a2 = 0x0; /* 003b: movi.n a2, 0 */
  if (a10 == a8) goto L_75; /* 003d: beq a10, a8, 75 <wdev_csi_hw_bug_check+0x69> */
  a8 = a8 + (8); /* 0040: addi.n a8, a8, 8 */
  if (a8 == a10) goto L_75; /* 0042: beq a8, a10, 75 <wdev_csi_hw_bug_check+0x69> */
  a13 = (uint32_t)&lit_rodata_wlog_warning_15; /* 0045: l32r a13, 0 <wdev_csi_hw_bug_check-0xc> (0 <wdev_csi_hw_bug_check-0xc>) */ /* literal @0x0: .rodata_wlog_warning.15 */
  a12 = 0x2; /* 0048: movi.n a12, 2 */
  a11 = 0x20; /* 004a: movi.n a11, 32 */
  a10 = 0x6; /* 004c: movi.n a10, 6 */
  a8 = (uint32_t)&wifi_log; /* 004e: l32r a8, 8 <wdev_csi_hw_bug_check-0x4> (0 <wdev_csi_hw_bug_check-0xc>) */ /* literal: GOT slot for wifi_log */
  wifi_log(a2, a3, a4, a5); /* call via literal slot */ /* 0051: callx8 a8 */
  a2 = (uint32_t)&wDevCtrl; /* 0054: l32r a2, 4 <wdev_csi_hw_bug_check-0x8> (0 <wdev_csi_hw_bug_check-0xc>) */ /* literal @0x4: wDevCtrl */
  a2 = MEM32(a2 + 0); /* 0057: l32i.n a2, a2, 0 */
  goto L_5e; /* 0059: j 5e <wdev_csi_hw_bug_check+0x52> */
L_5c:;
  a2 = MEM32(a2 + 8); /* 005c: l32i.n a2, a2, 8 */
L_5e:;
  MEMW(); /* 005e: memw  */
  a8 = MEM32(a2 + 0); /* 0061: l32i.n a8, a2, 0 */
  if (!((a8 >> 30) & 1)) goto L_5c; /* 0063: bbci a8, 30, 5c <wdev_csi_hw_bug_check+0x50> */
  a2 = 0x3; /* 0066: movi.n a2, 3 */
  goto L_75; /* 0068: j 75 <wdev_csi_hw_bug_check+0x69> */
L_6b:;
  a8 = a8 - a10; /* 006b: sub a8, a8, a10 */
  a2 = 0x1; /* 006e: movi.n a2, 1 */
  a9 = 0x2; /* 0070: movi.n a9, 2 */
  if (a8 != 0) a2 = a9; /* 0072: movnez a2, a9, a8 */
L_75:;
  return (int32_t)a2; /* 0075: retw.n  */
}

/* wdev_set_promis_misc_pkt @ wdev.o 00000014 size 115B bind GLOBAL
 * Calls: hal_sniffer_rx_set_promis | Data refs: hal_sniffer_rx_set_promis, wDevCtrl
 *   MMIO: 0x3FF730F4
 *   funcdb v3: 1 call(s), 2 ref(s); disasm: 2 call(s), 2 data ref(s)
 * Fidelity: medium - 45 instr, 6 branches, calls resolved */
int32_t wdev_set_promis_misc_pkt(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.wdev_set_promis_misc_pkt; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_14:;
  /* 0014: entry a1, 32 */
  a2 = (a2 >> 0) & 0xFF; /* 0017: extui a2, a2, 0, 8 */
  a3 = (uint32_t)&wDevCtrl; /* 001a: l32r a3, 0 <wdev_set_promis_misc_pkt-0x14> (0 <wdev_set_promis_misc_pkt-0x14>) */ /* literal @0x0: wDevCtrl */
  if (a2 == 0) goto L_5c; /* 001d: beqz.n a2, 5c <wdev_set_promis_misc_pkt+0x48> */
  a8 = MEM8(a3 + 48); /* 001f: l8ui a8, a3, 48 */
  if (a8 == 0) goto L_5c; /* 0022: beqz.n a8, 5c <wdev_set_promis_misc_pkt+0x48> */
  a8 = MEM32(a3 + 52); /* 0024: l32i.n a8, a3, 52 */
  if (!((a8 >> 3) & 1)) goto L_5c; /* 0026: bbci a8, 3, 5c <wdev_set_promis_misc_pkt+0x48> */
  a12 = 0x0; /* 0029: movi.n a12, 0 */
  a11 = 0x1; /* 002b: movi.n a11, 1 */
  a10 = 0x0; /* 002d: mov.n a10, a12 */
  a8 = (uint32_t)&hal_sniffer_rx_set_promis; /* 002f: l32r a8, c <wdev_set_promis_misc_pkt-0x8> (0 <wdev_set_promis_misc_pkt-0x14>) */ /* literal: GOT slot for hal_sniffer_rx_set_promis */
  hal_sniffer_rx_set_promis(a2, a3, a4, a5); /* call via literal slot */ /* 0032: callx8 a8 */
  a3 = MEM32(a3 + 52); /* 0035: l32i.n a3, a3, 52 */
  if (!((a3 >> 6) & 1)) goto L_80; /* 0037: bbci a3, 6, 80 <wdev_set_promis_misc_pkt+0x6c> */
  a9 = 0x3FF730F4; /* 003a: l32r a9, 4 <wdev_set_promis_misc_pkt-0x10> (3ff730f4 <wDev_ProcessFiq+0x3ff73080>) */ /* MMIO base */ @0x4
  a3 = 0xFFFF00FF; /* 003d: l32r a3, 8 <wdev_set_promis_misc_pkt-0xc> (ffff00ff <wDev_ProcessFiq+0xffff008b>) */ @0x8
  MEMW(); /* 0040: memw  */
  a8 = REG32(0x3FF730F4); /* 0043: l32i.n a8, a9, 0 */ /* MMIO read: base 0x3FF730F4+0 */
  a8 = a8 & a3; /* 0045: and a8, a8, a3 */
  a3 = 0x41; /* 0048: movi.n a3, 65 */
  a3 = 0x4100; /* 004a: slli a3, a3, 8 */
  a8 = a8 | a3; /* 004d: or a8, a8, a3 */
  MEMW(); /* 0050: memw  */
  REG32(0x3FF730F4) = a8; /* 0053: s32i.n a8, a9, 0 */ /* MMIO write: base 0x3FF730F4+0 */
  MEMW(); /* 0055: memw  */
  goto L_80; /* 0058: j 80 <wdev_set_promis_misc_pkt+0x6c> */
  /* 005b: .byte 00 */
L_5c:;
  a12 = 0x0; /* 005c: movi.n a12, 0 */
  a11 = 0x0; /* 005e: mov.n a11, a12 */
  a10 = 0x0; /* 0060: mov.n a10, a12 */
  a8 = (uint32_t)&hal_sniffer_rx_set_promis; /* 0062: l32r a8, 10 <wdev_set_promis_misc_pkt-0x4> (0 <wdev_set_promis_misc_pkt-0x14>) */ /* literal: GOT slot for hal_sniffer_rx_set_promis */
  hal_sniffer_rx_set_promis(a2, a3, a4, a5); /* call via literal slot */ /* 0065: callx8 a8 */
  a3 = MEM32(a3 + 52); /* 0068: l32i.n a3, a3, 52 */
  if (!((a3 >> 6) & 1)) goto L_80; /* 006a: bbci a3, 6, 80 <wdev_set_promis_misc_pkt+0x6c> */
  a8 = 0x3FF730F4; /* 006d: l32r a8, 4 <wdev_set_promis_misc_pkt-0x10> (3ff730f4 <wDev_ProcessFiq+0x3ff73080>) */ /* MMIO base */ @0x4
  a9 = 0xFFFF00FF; /* 0070: l32r a9, 8 <wdev_set_promis_misc_pkt-0xc> (ffff00ff <wDev_ProcessFiq+0xffff008b>) */ @0x8
  MEMW(); /* 0073: memw  */
  a3 = REG32(0x3FF730F4); /* 0076: l32i.n a3, a8, 0 */ /* MMIO read: base 0x3FF730F4+0 */
  a3 = a3 & a9; /* 0078: and a3, a3, a9 */
  MEMW(); /* 007b: memw  */
  REG32(0x3FF730F4) = a3; /* 007e: s32i.n a3, a8, 0 */ /* MMIO write: base 0x3FF730F4+0 */
L_80:;
  a2 = 0x0; /* 0080: movi.n a2, 0 */
  MEMW(); /* 0082: memw  */
  return (int32_t)a2; /* 0085: retw.n  */
}

/* wdev_push_promis_misc_buf @ wdev.o 00000008 size 97B bind GLOBAL
 * Calls: memcpy[got] | Data refs: .dram1.16, memcpy
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 1 call(s), 2 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t wdev_push_promis_misc_buf(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .iram1.17; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_8:;
  /* 0008: entry a1, 32 */
  a3 = (uint32_t)&dram1_16; /* 000b: l32r a3, 0 <wdev_push_promis_misc_buf-0x8> (0 <wdev_push_promis_misc_buf-0x8>) */ /* literal @0x0: .dram1.16 */
  a11 = a2; /* 000e: mov.n a11, a2 */
  a2 = 0xFFFFFFFF; /* 0010: movi.n a2, -1 */
  a10 = MEM32(a3 + 0); /* 0012: l32i.n a10, a3, 0 */
  if (a10 == 0) goto L_64; /* 0014: beqz a10, 64 <wdev_push_promis_misc_buf+0x5c> */
  a13 = 0x9; /* 0017: movi.n a13, 9 */
  a8 = MEM8(a10 + 0); /* 0019: l8ui a8, a10, 0 */
  a3 = (a8 << 8) + a8; /* 001c: addx8 a3, a8, a8 */
  a3 = a8 - (a3 << 8) /* verify order vs disasm */; /* 001f: subx8 a3, a3, a8 */
  a9 = a3 << (2 & 31); /* 0022: slli a9, a3, 2 */
  a3 = (a3 << 4) + a10; /* 0025: addx4 a3, a3, a10 */
  a12 = MEM8(a3 + 6); /* 0028: l8ui a12, a3, 6 */
  if (a13 < a12) goto L_64; /* 002b: bltu a13, a12, 64 <wdev_push_promis_misc_buf+0x5c> */
  a9 = a9 + (8); /* 002e: addi.n a9, a9, 8 */
  a12 = 0x1C; /* 0030: movi.n a12, 28 */
  a8 = MEM8(a3 + 4); /* 0032: l8ui a8, a3, 4 */
  a8 = a8 - (a8 << 8) /* verify order vs disasm */; /* 0035: subx8 a8, a8, a8 */
  a8 = (a8 << 4) + a9; /* 0038: addx4 a8, a8, a9 */
  a10 = a10 + a8; /* 003b: add a10, a10, a8 */
  a8 = (uint32_t)&memcpy; /* 003e: l32r a8, 4 <wdev_push_promis_misc_buf-0x4> (0 <wdev_push_promis_misc_buf-0x8>) */ /* literal: GOT slot for memcpy */
  memcpy(a2, a3, a4, a5); /* call via literal slot */ /* 0041: callx8 a8 */
  a8 = MEM8(a3 + 4); /* 0044: l8ui a8, a3, 4 */
  a8 = a8 + (1); /* 0047: addi.n a8, a8, 1 */
  a8 = (a8 >> 0) & 0xFF; /* 0049: extui a8, a8, 0, 8 */
  if (a8 != 10) goto L_51; /* 004c: bnei a8, 10, 51 <wdev_push_promis_misc_buf+0x49> */
  a8 = 0x0; /* 004f: movi.n a8, 0 */
L_51:;
  MEM8(a3 + 4) = a8; /* 0051: s8i a8, a3, 4 */
  MEMW(); /* 0054: memw  */
  a2 = 0x0; /* 0057: movi.n a2, 0 */
  a8 = MEM8(a3 + 6); /* 0059: l8ui a8, a3, 6 */
  a8 = a8 + (1); /* 005c: addi.n a8, a8, 1 */
  MEM8(a3 + 6) = a8; /* 005e: s8i a8, a3, 6 */
  MEMW(); /* 0061: memw  */
L_64:;
  MEMW(); /* 0064: memw  */
  return (int32_t)a2; /* 0067: retw.n  */
}

/* wdev_pop_promis_misc_buf @ wdev.o 00000008 size 101B bind GLOBAL
 * Calls: memcpy | Data refs: .dram1.16, memcpy
 *   MMIO: none
 *   funcdb v3: 1 call(s), 2 ref(s); disasm: 1 call(s), 2 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t wdev_pop_promis_misc_buf(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.wdev_pop_promis_misc_buf; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_8:;
  /* 0008: entry a1, 32 */
  a3 = (uint32_t)&dram1_16; /* 000b: l32r a3, 0 <wdev_pop_promis_misc_buf-0x8> (0 <wdev_pop_promis_misc_buf-0x8>) */ /* literal @0x0: .dram1.16 */
  a10 = a2; /* 000e: mov.n a10, a2 */
  a2 = 0xFFFFFFFF; /* 0010: movi.n a2, -1 */
  a11 = MEM32(a3 + 0); /* 0012: l32i.n a11, a3, 0 */
  if (a11 == 0) goto L_68; /* 0014: beqz a11, 68 <wdev_pop_promis_misc_buf+0x60> */
  a8 = 0x1; /* 0017: movi.n a8, 1 */
  a3 = MEM8(a11 + 0); /* 0019: l8ui a3, a11, 0 */
  a8 = a8 - a3; /* 001c: sub a8, a8, a3 */
  a3 = (a8 << 8) + a8; /* 001f: addx8 a3, a8, a8 */
  a3 = a8 - (a3 << 8) /* verify order vs disasm */; /* 0022: subx8 a3, a3, a8 */
  a9 = a3 << (2 & 31); /* 0025: slli a9, a3, 2 */
  a3 = (a3 << 4) + a11; /* 0028: addx4 a3, a3, a11 */
  a12 = MEM8(a3 + 6); /* 002b: l8ui a12, a3, 6 */
  if (a12 == 0) goto L_68; /* 002e: beqz.n a12, 68 <wdev_pop_promis_misc_buf+0x60> */
  a9 = a9 + (8); /* 0030: addi.n a9, a9, 8 */
  a12 = 0x1C; /* 0032: movi.n a12, 28 */
  a8 = MEM8(a3 + 5); /* 0034: l8ui a8, a3, 5 */
  a8 = a8 - (a8 << 8) /* verify order vs disasm */; /* 0037: subx8 a8, a8, a8 */
  a8 = (a8 << 4) + a9; /* 003a: addx4 a8, a8, a9 */
  a11 = a11 + a8; /* 003d: add.n a11, a11, a8 */
  a8 = (uint32_t)&memcpy; /* 003f: l32r a8, 4 <wdev_pop_promis_misc_buf-0x4> (0 <wdev_pop_promis_misc_buf-0x8>) */ /* literal: GOT slot for memcpy */
  memcpy(a2, a3, a4, a5); /* call via literal slot */ /* 0042: callx8 a8 */
  a8 = MEM8(a3 + 5); /* 0045: l8ui a8, a3, 5 */
  a8 = a8 + (1); /* 0048: addi a8, a8, 1 */
  a8 = (a8 >> 0) & 0xFF; /* 004b: extui a8, a8, 0, 8 */
  if (a8 != 10) goto L_54; /* 004e: bnei a8, 10, 54 <wdev_pop_promis_misc_buf+0x4c> */
  a8 = 0x0; /* 0051: movi a8, 0 */
L_54:;
  MEM8(a3 + 5) = a8; /* 0054: s8i a8, a3, 5 */
  MEMW(); /* 0057: memw  */
  a2 = 0x0; /* 005a: movi.n a2, 0 */
  a8 = MEM8(a3 + 6); /* 005c: l8ui a8, a3, 6 */
  a8 = a8 + (-1); /* 005f: addi a8, a8, -1 */
  MEM8(a3 + 6) = a8; /* 0062: s8i a8, a3, 6 */
  MEMW(); /* 0065: memw  */
L_68:;
  MEMW(); /* 0068: memw  */
  return (int32_t)a2; /* 006b: retw.n  */
}

/* wdev_process_misc_pkt @ wdev.o 00000014 size 136B bind GLOBAL
 * Calls: memcpy, pp_post, wdev_pop_promis_misc_buf, .dram1.16[got] | Data refs: .dram1.16, g_osi_funcs_p, memcpy, pp_post, wdev_pop_promis_misc_buf
 *   MMIO: none
 *   funcdb v3: 3 call(s), 5 ref(s); disasm: 5 call(s), 5 data ref(s)
 * Fidelity: medium - 53 instr, 7 branches, calls resolved */
int32_t wdev_process_misc_pkt(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.wdev_process_misc_pkt; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_14:;
  /* 0014: entry a1, 64 */
  a2 = (uint32_t)&dram1_16; /* 0017: l32r a2, 0 <wdev_process_misc_pkt-0x14> (0 <wdev_process_misc_pkt-0x14>) */ /* literal @0x0: .dram1.16 */
  a2 = MEM32(a2 + 0); /* 001a: l32i.n a2, a2, 0 */
  if (a2 == 0) goto L_98; /* 001c: beqz a2, 98 <wdev_process_misc_pkt+0x84> */
  a3 = 0x1; /* 001f: movi.n a3, 1 */
  a4 = MEM8(a2 + 0); /* 0021: l8ui a4, a2, 0 */
  a3 = a3 - a4; /* 0024: sub a3, a3, a4 */
  MEM8(a2 + 0) = a3; /* 0027: s8i a3, a2, 0 */
  MEMW(); /* 002a: memw  */
  a3 = (uint32_t)&g_osi_funcs_p; /* 002d: l32r a3, 4 <wdev_process_misc_pkt-0x10> (0 <wdev_process_misc_pkt-0x14>) */ /* literal @0x4: g_osi_funcs_p */
  MEMW(); /* 0030: memw  */
  goto L_8d; /* 0033: j 8d <wdev_process_misc_pkt+0x79> */
L_36:;
  a2 = MEM32(a3 + 0); /* 0036: l32i.n a2, a3, 0 */
  a10 = 0x8; /* 0038: movi a10, 8 */
  a2 = MEM32(a2 + 364); /* 003b: l32i a2, a2, 0x16c */
  dram1_16(a2, a3, a4, a5); /* call via literal slot */ /* 003e: callx8 a2 */
  a2 = 0x8; /* 0041: mov.n a2, a10 */
  if (a10 == 0) goto L_8d; /* 0043: beqz a10, 8d <wdev_process_misc_pkt+0x79> */
  a4 = MEM32(a3 + 0); /* 0046: l32i.n a4, a3, 0 */
  a10 = 0x1C; /* 0048: movi.n a10, 28 */
  a4 = MEM32(a4 + 364); /* 004a: l32i a4, a4, 0x16c */
  ((int32_t(*)())a4)(a2, a3, a4, a5); /* 004d: callx8 a4 */ /* indirect */
  a4 = 0x1C; /* 0050: mov.n a4, a10 */
  if (a10 != 0) goto L_58; /* 0052: bnez.n a10, 58 <wdev_process_misc_pkt+0x44> */
  goto L_82; /* 0054: j 82 <wdev_process_misc_pkt+0x6e> */
  /* 0057: .byte 00 */
L_58:;
  a11 = a1; /* 0058: mov.n a11, a1 */
  a12 = 0x1C; /* 005a: movi.n a12, 28 */
  a8 = (uint32_t)&memcpy; /* 005c: l32r a8, 8 <wdev_process_misc_pkt-0xc> (0 <wdev_process_misc_pkt-0x14>) */ /* literal: GOT slot for memcpy */
  memcpy(a2, a3, a4, a5); /* call via literal slot */ /* 005f: callx8 a8 */
  a8 = 0x3; /* 0062: movi.n a8, 3 */
  MEM32(a2 + 0) = a8; /* 0064: s32i.n a8, a2, 0 */
  a11 = a2; /* 0066: mov.n a11, a2 */
  a10 = 0xD; /* 0068: movi.n a10, 13 */
  MEM32(a2 + 4) = a4; /* 006a: s32i.n a4, a2, 4 */
  MEMW(); /* 006c: memw  */
  a8 = (uint32_t)&pp_post; /* 006f: l32r a8, c <wdev_process_misc_pkt-0x8> (0 <wdev_process_misc_pkt-0x14>) */ /* literal: GOT slot for pp_post */
  pp_post(a2, a3, a4, a5); /* call via literal slot */ /* 0072: callx8 a8 */
  if (a10 != 1) goto L_8d; /* 0075: bnei a10, 1, 8d <wdev_process_misc_pkt+0x79> */
  a10 = a4; /* 0078: mov.n a10, a4 */
  a8 = MEM32(a3 + 0); /* 007a: l32i.n a8, a3, 0 */
  a8 = MEM32(a8 + 176); /* 007c: l32i a8, a8, 176 */
  pp_post(a2, a3, a4, a5); /* call via literal slot */ /* 007f: callx8 a8 */
L_82:;
  a10 = a2; /* 0082: mov.n a10, a2 */
  a4 = MEM32(a3 + 0); /* 0084: l32i a4, a3, 0 */
  a4 = MEM32(a4 + 176); /* 0087: l32i a4, a4, 176 */
  ((int32_t(*)())a4)(a2, a3, a4, a5); /* 008a: callx8 a4 */ /* indirect */
L_8d:;
  a10 = a1; /* 008d: mov.n a10, a1 */
  a8 = (uint32_t)&wdev_pop_promis_misc_buf; /* 008f: l32r a8, 10 <wdev_process_misc_pkt-0x4> (0 <wdev_process_misc_pkt-0x14>) */ /* literal: GOT slot for wdev_pop_promis_misc_buf */
  wdev_pop_promis_misc_buf(a2, a3, a4, a5); /* call via literal slot */ /* 0092: callx8 a8 */
  if (a10 != -1) goto L_36; /* 0095: bnei a10, -1, 36 <wdev_process_misc_pkt+0x22> */
L_98:;
  a2 = 0x0; /* 0098: movi.n a2, 0 */
  return (int32_t)a2; /* 009a: retw.n  */
}

/* wdev_set_promis_misc_buf @ wdev.o 00000014 size 109B bind GLOBAL
 * Calls: memset, wifi_log, g_osi_funcs_p[got], g_osi_funcs_p[got] | Data refs: .dram1.16, .rodata_wlog_error.18, g_osi_funcs_p, memset, wifi_log
 *   MMIO: none
 *   funcdb v3: 2 call(s), 5 ref(s); disasm: 4 call(s), 5 data ref(s)
 * Fidelity: medium - 41 instr, 6 branches, calls resolved */
int32_t wdev_set_promis_misc_buf(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.wdev_set_promis_misc_buf; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_14:;
  /* 0014: entry a1, 32 */
  a3 = (uint32_t)&dram1_16; /* 0017: l32r a3, 0 <wdev_set_promis_misc_buf-0x14> (0 <wdev_set_promis_misc_buf-0x14>) */ /* literal @0x0: .dram1.16 */
  a2 = (a2 >> 0) & 0xFF; /* 001a: extui a2, a2, 0, 8 */
  a10 = MEM32(a3 + 0); /* 001d: l32i a10, a3, 0 */
  if (a2 == 0) goto L_6d; /* 0020: beqz a2, 6d <wdev_set_promis_misc_buf+0x59> */
  a2 = (uint32_t)&g_osi_funcs_p; /* 0023: l32r a2, 4 <wdev_set_promis_misc_buf-0x10> (0 <wdev_set_promis_misc_buf-0x14>) */ /* literal @0x4: g_osi_funcs_p */
  if (a10 == 0) goto L_31; /* 0026: beqz.n a10, 31 <wdev_set_promis_misc_buf+0x1d> */
  a8 = MEM32(a2 + 0); /* 0028: l32i a8, a2, 0 */
  a8 = MEM32(a8 + 176); /* 002b: l32i a8, a8, 176 */
  ((int32_t(*)())a8)(a2, a3, a4, a5); /* 002e: callx8 a8 */ /* indirect */
L_31:;
  a10 = 0x23C; /* 0031: movi a10, 0x23c */
  a2 = MEM32(a2 + 0); /* 0034: l32i.n a2, a2, 0 */
  a2 = MEM32(a2 + 348); /* 0036: l32i a2, a2, 0x15c */
  g_osi_funcs_p(a2, a3, a4, a5); /* call via literal slot */ /* 0039: callx8 a2 */
  MEM32(a3 + 0) = a10; /* 003c: s32i.n a10, a3, 0 */
  if (a10 != 0) goto L_5d; /* 003e: bnez.n a10, 5d <wdev_set_promis_misc_buf+0x49> */
  a12 = 0x1; /* 0040: movi a12, 1 */
  a11 = 0x800; /* 0043: slli a11, a12, 11 */
  a10 = 0x6; /* 0046: movi a10, 6 */
  a13 = (uint32_t)&lit_rodata_wlog_error_18; /* 0049: l32r a13, 8 <wdev_set_promis_misc_buf-0xc> (0 <wdev_set_promis_misc_buf-0x14>) */ /* literal @0x8: .rodata_wlog_error.18 */
  a2 = 0x101; /* 004c: movi a2, 0x101 */
  MEMW(); /* 004f: memw  */
  a8 = (uint32_t)&wifi_log; /* 0052: l32r a8, c <wdev_set_promis_misc_buf-0x8> (0 <wdev_set_promis_misc_buf-0x14>) */ /* literal: GOT slot for wifi_log */
  wifi_log(a2, a3, a4, a5); /* call via literal slot */ /* 0055: callx8 a8 */
  goto L_7c; /* 0058: j 7c <wdev_set_promis_misc_buf+0x68> */
  /* 005b: .byte 00 */
  /* 005c: .byte 00 */
L_5d:;
  a12 = 0x23C; /* 005d: movi a12, 0x23c */
  a11 = 0x0; /* 0060: movi.n a11, 0 */
  a8 = (uint32_t)&memset; /* 0062: l32r a8, 10 <wdev_set_promis_misc_buf-0x4> (0 <wdev_set_promis_misc_buf-0x14>) */ /* literal: GOT slot for memset */
  memset(a2, a3, a4, a5); /* call via literal slot */ /* 0065: callx8 a8 */
  a2 = 0x0; /* 0068: movi.n a2, 0 */
  goto L_7c; /* 006a: j 7c <wdev_set_promis_misc_buf+0x68> */
L_6d:;
  if (a10 == 0) goto L_7c; /* 006d: beqz.n a10, 7c <wdev_set_promis_misc_buf+0x68> */
  a8 = (uint32_t)&g_osi_funcs_p; /* 006f: l32r a8, 4 <wdev_set_promis_misc_buf-0x10> (0 <wdev_set_promis_misc_buf-0x14>) */ /* literal @0x4: g_osi_funcs_p */
  a8 = MEM32(a8 + 0); /* 0072: l32i.n a8, a8, 0 */
  a8 = MEM32(a8 + 176); /* 0074: l32i a8, a8, 176 */
  g_osi_funcs_p(a2, a3, a4, a5); /* call via literal slot */ /* 0077: callx8 a8 */
  MEM32(a3 + 0) = a2; /* 007a: s32i.n a2, a3, 0 */
L_7c:;
  MEMW(); /* 007c: memw  */
  return (int32_t)a2; /* 007f: retw.n  */
}

/* wdev_set_promis_ctrl_pkt @ wdev.o 0000000c size 49B bind GLOBAL
 * Calls: hal_sniffer_rx_set_promis | Data refs: .dram1.2, hal_sniffer_rx_set_promis, wDevCtrl
 *   MMIO: none
 *   funcdb v3: 1 call(s), 3 ref(s); disasm: 1 call(s), 3 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t wdev_set_promis_ctrl_pkt(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.wdev_set_promis_ctrl_pkt; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_c:;
  /* 000c: entry a1, 32 */
  a2 = (a2 >> 0) & 0xFF; /* 000f: extui a2, a2, 0, 8 */
  if (a2 == 0) goto L_2d; /* 0012: beqz.n a2, 2d <wdev_set_promis_ctrl_pkt+0x21> */
  a8 = (uint32_t)&wDevCtrl; /* 0014: l32r a8, 0 <wdev_set_promis_ctrl_pkt-0xc> (0 <wdev_set_promis_ctrl_pkt-0xc>) */ /* literal @0x0: wDevCtrl */
  a9 = MEM8(a8 + 48); /* 0017: l8ui a9, a8, 48 */
  if (a9 == 0) goto L_2d; /* 001a: beqz.n a9, 2d <wdev_set_promis_ctrl_pkt+0x21> */
  a8 = MEM32(a8 + 52); /* 001c: l32i.n a8, a8, 52 */
  if (!((a8 >> 1) & 1)) goto L_2d; /* 001e: bbci a8, 1, 2d <wdev_set_promis_ctrl_pkt+0x21> */
  a11 = 0x1; /* 0021: movi.n a11, 1 */
  a10 = 0x1; /* 0023: mov.n a10, a11 */
  a8 = (uint32_t)&dram1_2; /* 0025: l32r a8, 4 <wdev_set_promis_ctrl_pkt-0x8> (0 <wdev_set_promis_ctrl_pkt-0xc>) */ /* literal @0x4: .dram1.2 */
  a12 = MEM32(a8 + 0); /* 0028: l32i.n a12, a8, 0 */
  goto L_33; /* 002a: j 33 <wdev_set_promis_ctrl_pkt+0x27> */
L_2d:;
  a12 = 0x0; /* 002d: movi.n a12, 0 */
  a11 = 0x0; /* 002f: mov.n a11, a12 */
  a10 = 0x1; /* 0031: movi.n a10, 1 */
L_33:;
  a8 = (uint32_t)&hal_sniffer_rx_set_promis; /* 0033: l32r a8, 8 <wdev_set_promis_ctrl_pkt-0x4> (0 <wdev_set_promis_ctrl_pkt-0xc>) */ /* literal: GOT slot for hal_sniffer_rx_set_promis */
  hal_sniffer_rx_set_promis(a2, a3, a4, a5); /* call via literal slot */ /* 0036: callx8 a8 */
  a2 = 0x0; /* 0039: movi.n a2, 0 */
  return (int32_t)a2; /* 003b: retw.n  */
}

/* wdev_set_promis @ wdev.o 00000030 size 130B bind GLOBAL
 * Calls: hal_sniffer_disable, hal_sniffer_enable, wdev_set_promis_ctrl_pkt, wdev_set_promis_misc_buf, wdev_set_promis_misc_pkt, wifi_log | Data refs: .rodata_wlog_info.19, .rodata_wlog_info.20, hal_sniffer_disable, hal_sniffer_enable, wDevCtrl, wdev_set_promis_ctrl_pkt, wdev_set_promis_misc_buf, wdev_set_promis_misc_pkt, wifi_log
 *   MMIO: none
 *   funcdb v3: 6 call(s), 9 ref(s); disasm: 9 call(s), 9 data ref(s)
 * Fidelity: medium - 47 instr, 3 branches, calls resolved */
int32_t wdev_set_promis(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.wdev_set_promis; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_30:;
  /* 0030: entry a1, 32 */
  a11 = 0x1; /* 0033: movi.n a11, 1 */
  a2 = (a2 >> 0) & 0xFF; /* 0035: extui a2, a2, 0, 8 */
  a3 = (uint32_t)&wDevCtrl; /* 0038: l32r a3, 4 <wdev_set_promis-0x2c> (0 <wdev_set_promis-0x30>) */ /* literal @0x4: wDevCtrl */
  a11 = 0x800; /* 003b: slli a11, a11, 11 */
  if (a2 == 0) goto L_7a; /* 003e: beqz.n a2, 7a <wdev_set_promis+0x4a> */
  a12 = 0x3; /* 0040: movi.n a12, 3 */
  a10 = 0x6; /* 0042: movi a10, 6 */
  a13 = (uint32_t)&lit_rodata_wlog_info_19; /* 0045: l32r a13, 0 <wdev_set_promis-0x30> (0 <wdev_set_promis-0x30>) */ /* literal @0x0: .rodata_wlog_info.19 */
  a2 = 0x1; /* 0048: movi a2, 1 */
  a8 = (uint32_t)&wifi_log; /* 004b: l32r a8, c <wdev_set_promis-0x24> (0 <wdev_set_promis-0x30>) */ /* literal: GOT slot for wifi_log */
  wifi_log(a2, a3, a4, a5); /* call via literal slot */ /* 004e: callx8 a8 */
  MEM8(a3 + 48) = a2; /* 0051: s8i a2, a3, 48 */
  MEMW(); /* 0054: memw  */
  MEMW(); /* 0057: memw  */
  a8 = (uint32_t)&hal_sniffer_enable; /* 005a: l32r a8, 10 <wdev_set_promis-0x20> (0 <wdev_set_promis-0x30>) */ /* literal: GOT slot for hal_sniffer_enable */
  hal_sniffer_enable(a2, a3, a4, a5); /* call via literal slot */ /* 005d: callx8 a8 */
  a10 = 0x1; /* 0060: movi.n a10, 1 */
  a8 = (uint32_t)&wdev_set_promis_misc_buf; /* 0062: l32r a8, 14 <wdev_set_promis-0x1c> (0 <wdev_set_promis-0x30>) */ /* literal: GOT slot for wdev_set_promis_misc_buf */
  wdev_set_promis_misc_buf(a2, a3, a4, a5); /* call via literal slot */ /* 0065: callx8 a8 */
  a2 = 0x1; /* 0068: mov.n a2, a10 */
  if (a10 != 0) goto L_b0; /* 006a: bnez a10, b0 <wdev_set_promis+0x80> */
  a10 = 0x1; /* 006d: movi.n a10, 1 */
  a8 = (uint32_t)&wdev_set_promis_misc_pkt; /* 006f: l32r a8, 18 <wdev_set_promis-0x18> (0 <wdev_set_promis-0x30>) */ /* literal: GOT slot for wdev_set_promis_misc_pkt */
  wdev_set_promis_misc_pkt(a2, a3, a4, a5); /* call via literal slot */ /* 0072: callx8 a8 */
  a10 = 0x1; /* 0075: movi.n a10, 1 */
  goto L_aa; /* 0077: j aa <wdev_set_promis+0x7a> */
L_7a:;
  a13 = (uint32_t)&lit_rodata_wlog_info_20; /* 007a: l32r a13, 8 <wdev_set_promis-0x28> (0 <wdev_set_promis-0x30>) */ /* literal @0x8: .rodata_wlog_info.20 */
  a12 = 0x3; /* 007d: movi.n a12, 3 */
  a10 = 0x6; /* 007f: movi a10, 6 */
  a8 = (uint32_t)&wifi_log; /* 0082: l32r a8, 1c <wdev_set_promis-0x14> (0 <wdev_set_promis-0x30>) */ /* literal: GOT slot for wifi_log */
  wifi_log(a2, a3, a4, a5); /* call via literal slot */ /* 0085: callx8 a8 */
  MEM8(a3 + 48) = a2; /* 0088: s8i a2, a3, 48 */
  MEMW(); /* 008b: memw  */
  MEMW(); /* 008e: memw  */
  a8 = (uint32_t)&hal_sniffer_disable; /* 0091: l32r a8, 20 <wdev_set_promis-0x10> (0 <wdev_set_promis-0x30>) */ /* literal: GOT slot for hal_sniffer_disable */
  hal_sniffer_disable(a2, a3, a4, a5); /* call via literal slot */ /* 0094: callx8 a8 */
  a10 = a2 | a2; /* 0097: or a10, a2, a2 */
  a8 = (uint32_t)&wdev_set_promis_misc_buf; /* 009a: l32r a8, 24 <wdev_set_promis-0xc> (0 <wdev_set_promis-0x30>) */ /* literal: GOT slot for wdev_set_promis_misc_buf */
  wdev_set_promis_misc_buf(a2, a3, a4, a5); /* call via literal slot */ /* 009d: callx8 a8 */
  a10 = a2; /* 00a0: mov.n a10, a2 */
  a8 = (uint32_t)&wdev_set_promis_misc_pkt; /* 00a2: l32r a8, 28 <wdev_set_promis-0x8> (0 <wdev_set_promis-0x30>) */ /* literal: GOT slot for wdev_set_promis_misc_pkt */
  wdev_set_promis_misc_pkt(a2, a3, a4, a5); /* call via literal slot */ /* 00a5: callx8 a8 */
  a10 = a2; /* 00a8: mov.n a10, a2 */
L_aa:;
  a8 = (uint32_t)&wdev_set_promis_ctrl_pkt; /* 00aa: l32r a8, 2c <wdev_set_promis-0x4> (0 <wdev_set_promis-0x30>) */ /* literal: GOT slot for wdev_set_promis_ctrl_pkt */
  wdev_set_promis_ctrl_pkt(a2, a3, a4, a5); /* call via literal slot */ /* 00ad: callx8 a8 */
L_b0:;
  return (int32_t)a2; /* 00b0: retw.n  */
}

/* wdev_set_promis_filter @ wdev.o 00000008 size 54B bind GLOBAL
 * Calls: wdev_set_promis_misc_pkt | Data refs: wDevCtrl, wdev_set_promis_misc_pkt
 *   MMIO: none
 *   funcdb v3: 1 call(s), 2 ref(s); disasm: 1 call(s), 2 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t wdev_set_promis_filter(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.wdev_set_promis_filter; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_8:;
  /* 0008: entry a1, 32 */
  a9 = MEM8(a2 + 0); /* 000b: l8ui a9, a2, 0 */
  a8 = (uint32_t)&wDevCtrl; /* 000e: l32r a8, 0 <wdev_set_promis_filter-0x8> (0 <wdev_set_promis_filter-0x8>) */ /* literal @0x0: wDevCtrl */
  a10 = MEM8(a2 + 1); /* 0011: l8ui a10, a2, 1 */
  MEM8(a8 + 0) = a9; /* 0014: s8i a9, a8, 0 */
  MEMW(); /* 0017: memw  */
  a9 = MEM8(a2 + 2); /* 001a: l8ui a9, a2, 2 */
  MEM8(a8 + 1) = a10; /* 001d: s8i a10, a8, 1 */
  MEMW(); /* 0020: memw  */
  a10 = 0x1; /* 0023: movi.n a10, 1 */
  a2 = MEM8(a2 + 3); /* 0025: l8ui a2, a2, 3 */
  MEM8(a8 + 2) = a9; /* 0028: s8i a9, a8, 2 */
  MEM8(a8 + 3) = a2; /* 002b: s8i a2, a8, 3 */
  MEMW(); /* 002e: memw  */
  MEMW(); /* 0031: memw  */
  a8 = (uint32_t)&wdev_set_promis_misc_pkt; /* 0034: l32r a8, 4 <wdev_set_promis_filter-0x4> (0 <wdev_set_promis_filter-0x8>) */ /* literal: GOT slot for wdev_set_promis_misc_pkt */
  wdev_set_promis_misc_pkt(a2, a3, a4, a5); /* call via literal slot */ /* 0037: callx8 a8 */
  a2 = 0x0; /* 003a: movi.n a2, 0 */
  return (int32_t)a2; /* 003c: retw.n  */
}

/* wdev_get_promis_filter @ wdev.o 00000004 size 46B bind GLOBAL
 * Calls: none | Data refs: wDevCtrl
 *   MMIO: none
 *   funcdb v3: 0 call(s), 1 ref(s); disasm: 0 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t wdev_get_promis_filter(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.wdev_get_promis_filter; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a8 = (uint32_t)&wDevCtrl; /* 0007: l32r a8, 0 <wdev_get_promis_filter-0x4> (0 <wdev_get_promis_filter-0x4>) */ /* literal @0x0: wDevCtrl */
  a9 = MEM8(a8 + 0); /* 000a: l8ui a9, a8, 0 */
  a10 = MEM8(a8 + 1); /* 000d: l8ui a10, a8, 1 */
  MEM8(a2 + 0) = a9; /* 0010: s8i a9, a2, 0 */
  MEMW(); /* 0013: memw  */
  a9 = MEM8(a8 + 2); /* 0016: l8ui a9, a8, 2 */
  MEM8(a2 + 1) = a10; /* 0019: s8i a10, a2, 1 */
  MEMW(); /* 001c: memw  */
  a8 = MEM8(a8 + 3); /* 001f: l8ui a8, a8, 3 */
  MEM8(a2 + 2) = a9; /* 0022: s8i a9, a2, 2 */
  MEM8(a2 + 3) = a8; /* 0025: s8i a8, a2, 3 */
  MEMW(); /* 0028: memw  */
  a2 = 0x0; /* 002b: movi.n a2, 0 */
  MEMW(); /* 002d: memw  */
  return (int32_t)a2; /* 0030: retw.n  */
}

/* wdev_set_promis_ctrl_filter @ wdev.o 00000008 size 54B bind GLOBAL
 * Calls: wdev_set_promis_ctrl_pkt | Data refs: .dram1.2, wdev_set_promis_ctrl_pkt
 *   MMIO: none
 *   funcdb v3: 1 call(s), 2 ref(s); disasm: 1 call(s), 2 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t wdev_set_promis_ctrl_filter(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.wdev_set_promis_ctrl_filter; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_8:;
  /* 0008: entry a1, 32 */
  a9 = MEM8(a2 + 0); /* 000b: l8ui a9, a2, 0 */
  a8 = (uint32_t)&dram1_2; /* 000e: l32r a8, 0 <wdev_set_promis_ctrl_filter-0x8> (0 <wdev_set_promis_ctrl_filter-0x8>) */ /* literal @0x0: .dram1.2 */
  a10 = MEM8(a2 + 1); /* 0011: l8ui a10, a2, 1 */
  MEM8(a8 + 0) = a9; /* 0014: s8i a9, a8, 0 */
  MEMW(); /* 0017: memw  */
  a9 = MEM8(a2 + 2); /* 001a: l8ui a9, a2, 2 */
  MEM8(a8 + 1) = a10; /* 001d: s8i a10, a8, 1 */
  MEMW(); /* 0020: memw  */
  a10 = 0x1; /* 0023: movi.n a10, 1 */
  a2 = MEM8(a2 + 3); /* 0025: l8ui a2, a2, 3 */
  MEM8(a8 + 2) = a9; /* 0028: s8i a9, a8, 2 */
  MEM8(a8 + 3) = a2; /* 002b: s8i a2, a8, 3 */
  MEMW(); /* 002e: memw  */
  MEMW(); /* 0031: memw  */
  a8 = (uint32_t)&wdev_set_promis_ctrl_pkt; /* 0034: l32r a8, 4 <wdev_set_promis_ctrl_filter-0x4> (0 <wdev_set_promis_ctrl_filter-0x8>) */ /* literal: GOT slot for wdev_set_promis_ctrl_pkt */
  wdev_set_promis_ctrl_pkt(a2, a3, a4, a5); /* call via literal slot */ /* 0037: callx8 a8 */
  a2 = 0x0; /* 003a: movi.n a2, 0 */
  return (int32_t)a2; /* 003c: retw.n  */
}

/* wdev_get_promis_ctrl_filter @ wdev.o 00000004 size 46B bind GLOBAL
 * Calls: none | Data refs: .dram1.2
 *   MMIO: none
 *   funcdb v3: 0 call(s), 1 ref(s); disasm: 0 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t wdev_get_promis_ctrl_filter(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.wdev_get_promis_ctrl_filter; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a8 = (uint32_t)&dram1_2; /* 0007: l32r a8, 0 <wdev_get_promis_ctrl_filter-0x4> (0 <wdev_get_promis_ctrl_filter-0x4>) */ /* literal @0x0: .dram1.2 */
  a9 = MEM8(a8 + 0); /* 000a: l8ui a9, a8, 0 */
  a10 = MEM8(a8 + 1); /* 000d: l8ui a10, a8, 1 */
  MEM8(a2 + 0) = a9; /* 0010: s8i a9, a2, 0 */
  MEMW(); /* 0013: memw  */
  a9 = MEM8(a8 + 2); /* 0016: l8ui a9, a8, 2 */
  MEM8(a2 + 1) = a10; /* 0019: s8i a10, a2, 1 */
  MEMW(); /* 001c: memw  */
  a8 = MEM8(a8 + 3); /* 001f: l8ui a8, a8, 3 */
  MEM8(a2 + 2) = a9; /* 0022: s8i a9, a2, 2 */
  MEM8(a2 + 3) = a8; /* 0025: s8i a8, a2, 3 */
  MEMW(); /* 0028: memw  */
  a2 = 0x0; /* 002b: movi.n a2, 0 */
  MEMW(); /* 002d: memw  */
  return (int32_t)a2; /* 0030: retw.n  */
}

/* wDev_SnifferRxAmpdu @ wdev.o 00000010 size 118B bind GLOBAL
 * Calls: memcpy, pp_post | Data refs: g_osi_funcs_p, memcpy, pp_post, wDevCtrl
 *   MMIO: none
 *   funcdb v3: 2 call(s), 4 ref(s); disasm: 2 call(s), 4 data ref(s)
 * Fidelity: medium - 48 instr, 5 branches, 4 indirect; flow + direct calls mapped, GOT-indirects enumerated */
int32_t wDev_SnifferRxAmpdu(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.wDev_SnifferRxAmpdu; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_10:;
  /* 0010: entry a1, 32 */
  a3 = (uint32_t)&wDevCtrl; /* 0013: l32r a3, 0 <wDev_SnifferRxAmpdu-0x10> (0 <wDev_SnifferRxAmpdu-0x10>) */ /* literal @0x0: wDevCtrl */
  a4 = 0x24; /* 0016: movi.n a4, 36 */
  a3 = MEM32(a3 + 52); /* 0018: l32i.n a3, a3, 52 */
  if ((a4 & a3) == 0) goto L_84; /* 001a: bnone a4, a3, 84 <wDev_SnifferRxAmpdu+0x74> */
  a10 = 0x8; /* 001d: movi.n a10, 8 */
  a2 = MEM32(a2 + 4); /* 001f: l32i.n a2, a2, 4 */
  a4 = (uint32_t)&g_osi_funcs_p; /* 0021: l32r a4, 4 <wDev_SnifferRxAmpdu-0xc> (0 <wDev_SnifferRxAmpdu-0x10>) */ /* literal @0x4: g_osi_funcs_p */
  a6 = MEM32(a2 + 4); /* 0024: l32i.n a6, a2, 4 */
  a2 = MEM32(a4 + 0); /* 0026: l32i.n a2, a4, 0 */
  a2 = MEM32(a2 + 364); /* 0028: l32i a2, a2, 0x16c */
  ((int32_t(*)())a2)(a2, a3, a4, a5); /* 002b: callx8 a2 */ /* indirect */
  a3 = 0x8; /* 002e: mov.n a3, a10 */
  a2 = MEM32(a6 + 24); /* 0030: l32i.n a2, a6, 24 */
  a2 = (a2 >> 0) & 0xFFF; /* 0032: extui a2, a2, 0, 12 */
  a2 = a2 + (28); /* 0035: addi a2, a2, 28 */
  a2 = (a2 >> 0) & 0xFFFF; /* 0038: extui a2, a2, 0, 16 */
  if (a10 == 0) goto L_84; /* 003b: beqz a10, 84 <wDev_SnifferRxAmpdu+0x74> */
  a5 = MEM32(a4 + 0); /* 003e: l32i.n a5, a4, 0 */
  a10 = a2; /* 0040: mov.n a10, a2 */
  a5 = MEM32(a5 + 364); /* 0042: l32i a5, a5, 0x16c */
  ((int32_t(*)())a5)(a2, a3, a4, a5); /* 0045: callx8 a5 */ /* indirect */
  a5 = a10; /* 0048: mov.n a5, a10 */
  if (a10 != 0) goto L_50; /* 004a: bnez.n a10, 50 <wDev_SnifferRxAmpdu+0x40> */
  goto L_7a; /* 004c: j 7a <wDev_SnifferRxAmpdu+0x6a> */
  /* 004f: .byte 00 */
L_50:;
  a12 = a2; /* 0050: mov.n a12, a2 */
  a11 = a6; /* 0052: mov.n a11, a6 */
  a8 = (uint32_t)&memcpy; /* 0054: l32r a8, 8 <wDev_SnifferRxAmpdu-0x8> (0 <wDev_SnifferRxAmpdu-0x10>) */ /* literal: GOT slot for memcpy */
  memcpy(a2, a3, a4, a5); /* call via literal slot */ /* 0057: callx8 a8 */
  a2 = 0x2; /* 005a: movi.n a2, 2 */
  MEM32(a3 + 0) = a2; /* 005c: s32i.n a2, a3, 0 */
  a11 = a3; /* 005e: mov.n a11, a3 */
  a10 = 0xD; /* 0060: movi.n a10, 13 */
  MEM32(a3 + 4) = a5; /* 0062: s32i.n a5, a3, 4 */
  MEMW(); /* 0064: memw  */
  a8 = (uint32_t)&pp_post; /* 0067: l32r a8, c <wDev_SnifferRxAmpdu-0x4> (0 <wDev_SnifferRxAmpdu-0x10>) */ /* literal: GOT slot for pp_post */
  pp_post(a2, a3, a4, a5); /* call via literal slot */ /* 006a: callx8 a8 */
  if (a10 != 1) goto L_84; /* 006d: bnei a10, 1, 84 <wDev_SnifferRxAmpdu+0x74> */
  a10 = a5; /* 0070: mov.n a10, a5 */
  a2 = MEM32(a4 + 0); /* 0072: l32i.n a2, a4, 0 */
  a2 = MEM32(a2 + 176); /* 0074: l32i a2, a2, 176 */
  ((int32_t(*)())a2)(a2, a3, a4, a5); /* 0077: callx8 a2 */ /* indirect */
L_7a:;
  a10 = a3; /* 007a: mov.n a10, a3 */
  a2 = MEM32(a4 + 0); /* 007c: l32i.n a2, a4, 0 */
  a2 = MEM32(a2 + 176); /* 007e: l32i a2, a2, 176 */
  ((int32_t(*)())a2)(a2, a3, a4, a5); /* 0081: callx8 a2 */ /* indirect */
L_84:;
  return (int32_t)a2; /* 0084: retw.n  */
}

/* wDev_RxSecError @ wdev.o 00000000 size 44B bind GLOBAL
 * Calls: none | Data refs: none
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t wDev_RxSecError(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.wDev_RxSecError; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_0:;
  /* 0000: entry a1, 32 */
  a2 = (a2 >> 0) & 0xFF; /* 0003: extui a2, a2, 0, 8 */
  a9 = a2 + (31); /* 0006: addi a9, a2, 31 */
  a9 = (a9 >> 0) & 0xFF; /* 0009: extui a9, a9, 0, 8 */
  a8 = 0x1; /* 000c: movi a8, 1 */
  if (a9 < 6) goto L_15; /* 000f: bltui a9, 6, 15 <wDev_RxSecError+0x15> */
  a8 = 0x0; /* 0012: movi a8, 0 */
L_15:;
  a2 = a2 + (16); /* 0015: addi a2, a2, 16 */
  a2 = (a2 >> 0) & 0xFF; /* 0018: extui a2, a2, 0, 8 */
  a10 = 0xC; /* 001b: movi.n a10, 12 */
  a9 = 0x1; /* 001d: movi.n a9, 1 */
  if (a10 >= a2) goto L_24; /* 001f: bgeu a10, a2, 24 <wDev_RxSecError+0x24> */
  a9 = 0x0; /* 0022: movi.n a9, 0 */
L_24:;
  a2 = 0x0; /* 0024: or a2, a8, a9 */
  a2 = 0x0; /* 0027: extui a2, a2, 0, 1 */
  return (int32_t)a2; /* 002a: retw.n  */
}

/* wDev_GetNoiseFloor @ wdev.o 00000008 size 43B bind GLOBAL
 * Calls: read_hw_noisefloor[got] | Data refs: wDevCtrl, read_hw_noisefloor
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 1 call(s), 2 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t wDev_GetNoiseFloor(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .wifiorslpiram.25; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_8:;
  /* 0008: entry a1, 32 */
  a2 = (uint32_t)&wDevCtrl; /* 000b: l32r a2, 0 <wDev_GetNoiseFloor-0x8> (0 <wDev_GetNoiseFloor-0x8>) */ /* literal @0x0: wDevCtrl */
  a8 = MEM8(a2 + 47); /* 000e: l8ui a8, a2, 47 */
  a8 = ((int32_t)(a8 << (32 - (7 & 31)))) >> (32 - (7 & 31)); /* 0011: sext a8, a8, 7 */
  if (a8 < 1) goto L_28; /* 0014: blti a8, 1, 28 <wDev_GetNoiseFloor+0x20> */
  a8 = (uint32_t)&read_hw_noisefloor; /* 0017: l32r a8, 4 <wDev_GetNoiseFloor-0x4> (0 <wDev_GetNoiseFloor-0x8>) */ /* literal: GOT slot for read_hw_noisefloor */
  read_hw_noisefloor(a2, a3, a4, a5); /* call via literal slot */ /* 001a: callx8 a8 */
  a10 = a10 + (2); /* 001d: addi.n a10, a10, 2 */
  a10 = (int32_t)a10 >> (2 & 31); /* 001f: srai a10, a10, 2 */
  MEM8(a2 + 47) = a10; /* 0022: s8i a10, a2, 47 */
  MEMW(); /* 0025: memw  */
L_28:;
  a2 = MEM8(a2 + 47); /* 0028: l8ui a2, a2, 47 */
  a2 = ((int32_t)(a2 << (32 - (7 & 31)))) >> (32 - (7 & 31)); /* 002b: sext a2, a2, 7 */
  MEMW(); /* 002e: memw  */
  return (int32_t)a2; /* 0031: retw.n  */
}

/* wdev_csi_rx_process @ wdev.o 00000024 size 274B bind GLOBAL
 * Calls: memcpy, memset, wDev_GetNoiseFloor | Data refs: g_osi_funcs_p, g_wdev_csi_rx, g_wdev_csi_rx_ctx, memcpy, memset, wDevCtrl, wDev_GetNoiseFloor
 *   MMIO: none
 *   funcdb v3: 3 call(s), 7 ref(s); disasm: 5 call(s), 7 data ref(s)
 * Fidelity: medium - 102 instr, 10 branches, 3 indirect; flow + direct calls mapped, GOT-indirects enumerated (verified against section disasm) */
int32_t wdev_csi_rx_process(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.wdev_csi_rx_process; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_24:;
  /* 0024: entry a1, 48 */
  a3 = (a3 >> 0) & 0xFFFF; /* 0027: extui a3, a3, 0, 16 */
  MEM32(a1 + 0) = a3; /* 002a: s32i.n a3, a1, 0 */
  a3 = (a6 >> 0) & 0xFFFF; /* 002c: extui a3, a6, 0, 16 */
  if (a7 != 3) goto L_35; /* 002f: bnei a7, 3, 35 <wdev_csi_rx_process+0x11> */
  goto L_134; /* 0032: j 134 <wdev_csi_rx_process+0x110> */
L_35:;
  a6 = (uint32_t)&g_wdev_csi_rx; /* 0035: l32r a6, 0 <wdev_csi_rx_process-0x24> (0 <wdev_csi_rx_process-0x24>) */ /* literal @0x0: g_wdev_csi_rx */
  a8 = MEM32(a6 + 0); /* 0038: l32i.n a8, a6, 0 */
  if (a8 == 0) goto L_134; /* 003a: beqz a8, 134 <wdev_csi_rx_process+0x110> */
  a10 = 0x40; /* 003d: movi.n a10, 64 */
  a6 = (uint32_t)&g_osi_funcs_p; /* 003f: l32r a6, 4 <wdev_csi_rx_process-0x20> (0 <wdev_csi_rx_process-0x24>) */ /* literal @0x4: g_osi_funcs_p */
  a8 = MEM32(a6 + 0); /* 0042: l32i.n a8, a6, 0 */
  a8 = MEM32(a8 + 364); /* 0044: l32i a8, a8, 0x16c */
  MEMW(); /* 0047: memw  */
  ((int32_t(*)())a8)(a2, a3, a4, a5); /* 004a: callx8 a8 */ /* indirect */
  a6 = 0x40; /* 004d: mov.n a6, a10 */
  if (a10 == 0) goto L_134; /* 004f: beqz a10, 134 <wdev_csi_rx_process+0x110> */
  a9 = 0xF; /* 0052: movi.n a9, 15 */
  a10 = 0x5C; /* 0054: addi a10, a10, 28 */
  a12 = 0x6; /* 0057: movi.n a12, 6 */
  if (a9 >= a3) goto L_68; /* 0059: bgeu a9, a3, 68 <wdev_csi_rx_process+0x44> */
  a11 = a5 + (10); /* 005c: addi.n a11, a5, 10 */
  a8 = (uint32_t)&memcpy; /* 005e: l32r a8, 10 <wdev_csi_rx_process-0x14> (0 <wdev_csi_rx_process-0x24>) */ /* literal: GOT slot for memcpy */
  memcpy(a2, a3, a4, a5); /* call via literal slot */ /* 0061: callx8 a8 */
  goto L_70; /* 0064: j 70 <wdev_csi_rx_process+0x4c> */
  /* 0067: .byte 00 */
L_68:;
  a11 = 0x0; /* 0068: movi.n a11, 0 */
  a8 = (uint32_t)&memset; /* 006a: l32r a8, 14 <wdev_csi_rx_process-0x10> (0 <wdev_csi_rx_process-0x24>) */ /* literal: GOT slot for memset */
  memset(a2, a3, a4, a5); /* call via literal slot */ /* 006d: callx8 a8 */
L_70:;
  a12 = 0x6; /* 0070: movi.n a12, 6 */
  a11 = a5 + (4); /* 0072: addi.n a11, a5, 4 */
  a10 = a6 + (34); /* 0074: addi a10, a6, 34 */
  a8 = (uint32_t)&memcpy; /* 0077: l32r a8, 18 <wdev_csi_rx_process-0xc> (0 <wdev_csi_rx_process-0x24>) */ /* literal: GOT slot for memcpy */
  memcpy(a2, a3, a4, a5); /* call via literal slot */ /* 007a: callx8 a8 */
  a10 = (uint32_t)&wDevCtrl; /* 007d: l32r a10, 8 <wdev_csi_rx_process-0x1c> (0 <wdev_csi_rx_process-0x24>) */ /* literal @0x8: wDevCtrl */
  a11 = a4; /* 0080: mov.n a11, a4 */
  a12 = 0x1C; /* 0082: movi.n a12, 28 */
  a7 = a7 + (-1); /* 0084: addi a7, a7, -1 */
  a9 = MEM8(a10 + 45); /* 0087: l8ui a9, a10, 45 */
  a9 = a9 << (4 & 31); /* 008a: slli a9, a9, 4 */
  a10 = MEM8(a10 + 44); /* 008d: l8ui a10, a10, 44 */
  a10 = (a10 >> 0) & 0xF; /* 0090: extui a10, a10, 0, 4 */
  a9 = a9 | a10; /* 0093: or a9, a9, a10 */
  a10 = a6 | a6; /* 0096: or a10, a6, a6 */
  MEM8(a4 + 10) = a9; /* 0099: s8i a9, a4, 10 */
  MEMW(); /* 009c: memw  */
  MEMW(); /* 009f: memw  */
  a8 = (uint32_t)&memcpy; /* 00a2: l32r a8, 1c <wdev_csi_rx_process-0x8> (0 <wdev_csi_rx_process-0x24>) */ /* literal: GOT slot for memcpy */
  memcpy(a2, a3, a4, a5); /* call via literal slot */ /* 00a5: callx8 a8 */
  a8 = (uint32_t)&wDev_GetNoiseFloor; /* 00a8: l32r a8, 20 <wdev_csi_rx_process-0x4> (0 <wdev_csi_rx_process-0x24>) */ /* literal: GOT slot for wDev_GetNoiseFloor */
  wDev_GetNoiseFloor(a2, a3, a4, a5); /* call via literal slot */ /* 00ab: callx8 a8 */
  a9 = 0x1; /* 00ae: movi.n a9, 1 */
  MEM8(a6 + 8) = a10; /* 00b0: s8i a10, a6, 8 */
  MEMW(); /* 00b3: memw  */
  a10 = 0x0; /* 00b6: movi.n a10, 0 */
  a11 = 0x0; /* 00b8: mov.n a11, a10 */
  if (a7 == 0) a11 = a9; /* 00ba: moveqz a11, a9, a7 */
  MEM32(a6 + 44) = a2; /* 00bd: s32i.n a2, a6, 44 */
  a2 = MEM32(a1 + 0); /* 00bf: l32i.n a2, a1, 0 */
  MEM16(a6 + 48) = a2; /* 00c1: s16i a2, a6, 48 */
  a2 = a5 + (24); /* 00c4: addi a2, a5, 24 */
  MEM16(a6 + 60) = a3; /* 00c7: s16i a3, a6, 60 */
  a3 = 0xC; /* 00ca: movi.n a3, 12 */
  MEM8(a6 + 40) = a11; /* 00cc: s8i a11, a6, 40 */
  MEMW(); /* 00cf: memw  */
  MEM32(a6 + 52) = a5; /* 00d2: s32i.n a5, a6, 52 */
  MEM32(a6 + 56) = a2; /* 00d4: s32i.n a2, a6, 56 */
  a2 = MEM8(a5 + 0); /* 00d6: l8ui a2, a5, 0 */
  a2 = a2 & a3; /* 00d9: and a2, a2, a3 */
  if (a2 != 4) goto L_e7; /* 00dc: bnei a2, 4, e7 <wdev_csi_rx_process+0xc3> */
  a2 = 0xFFFFFFFF; /* 00df: movi.n a2, -1 */
  MEMW(); /* 00e1: memw  */
  goto L_10e; /* 00e4: j 10e <wdev_csi_rx_process+0xea> */
L_e7:;
  a2 = MEM8(a4 + 27); /* 00e7: l8ui a2, a4, 27 */
  a4 = 0xFFFFFF3A; /* 00ea: movi a4, -198 */
  a3 = 0x0; /* 00ed: mov.n a3, a10 */
  a4 = a2 + a4; /* 00ef: add.n a4, a2, a4 */
  if (a2 == 0) a3 = a9; /* 00f1: moveqz a3, a9, a2 */
  if (a4 == 0) a10 = a9; /* 00f4: moveqz a10, a9, a4 */
  a3 = a3 | a10; /* 00f7: or a3, a3, a10 */
  if (a3 != 0) goto L_108; /* 00fa: bnez.n a3, 108 <wdev_csi_rx_process+0xe4> */
  a4 = 0xFFFFFF0B; /* 00fc: movi a4, -245 */
  a2 = a2 + a4; /* 00ff: add a2, a2, a4 */
  if (a2 != 0) a9 = a3; /* 0102: movnez a9, a3, a2 */
  if (a9 == 0) goto L_114; /* 0105: beqz a9, 114 <wdev_csi_rx_process+0xf0> */
L_108:;
  a2 = MEM16(a5 + 22); /* 0108: l16ui a2, a5, 22 */
  a2 = a2 >> (4 & 31); /* 010b: srli a2, a2, 4 */
L_10e:;
  MEM16(a6 + 62) = a2; /* 010e: s16i a2, a6, 62 */
  MEMW(); /* 0111: memw  */
L_114:;
  a11 = a6; /* 0114: mov.n a11, a6 */
  a3 = (uint32_t)&g_wdev_csi_rx; /* 0116: l32r a3, 0 <wdev_csi_rx_process-0x24> (0 <wdev_csi_rx_process-0x24>) */ /* literal @0x0: g_wdev_csi_rx */
  a2 = MEM32(a3 + 0); /* 0119: l32i.n a2, a3, 0 */
  a3 = (uint32_t)&g_wdev_csi_rx_ctx; /* 011b: l32r a3, c <wdev_csi_rx_process-0x18> (0 <wdev_csi_rx_process-0x24>) */ /* literal @0xC: g_wdev_csi_rx_ctx */
  a10 = MEM32(a3 + 0); /* 011e: l32i.n a10, a3, 0 */
  MEMW(); /* 0120: memw  */
  ((int32_t(*)())a2)(a2, a3, a4, a5); /* 0123: callx8 a2 */ /* indirect */
  a10 = a6; /* 0126: mov.n a10, a6 */
  a3 = (uint32_t)&g_osi_funcs_p; /* 0128: l32r a3, 4 <wdev_csi_rx_process-0x20> (0 <wdev_csi_rx_process-0x24>) */ /* literal @0x4: g_osi_funcs_p */
  a2 = MEM32(a3 + 0); /* 012b: l32i a2, a3, 0 */
  a2 = MEM32(a2 + 176); /* 012e: l32i a2, a2, 176 */
  ((int32_t(*)())a2)(a2, a3, a4, a5); /* 0131: callx8 a2 */ /* indirect */
L_134:;
  return (int32_t)a2; /* 0134: retw.n  */
}

/* wDev_SnifferRxData @ wdev.o 00000034 size 604B bind GLOBAL
 * Calls: memcpy, pp_post, wdev_csi_hw_bug_check, wdev_csi_len_align, wdev_csi_rx_process | Data refs: g_osi_funcs_p, memcpy, pp_post, wDevCtrl, wdev_csi_hw_bug_check, wdev_csi_len_align, wdev_csi_rx_process
 *   MMIO: none
 *   funcdb v3: 5 call(s), 7 ref(s); disasm: 11 call(s), 7 data ref(s)
 * Fidelity: medium - 235 instr, 26 branches, 4 indirect; flow + direct calls mapped, GOT-indirects enumerated (verified against section disasm) */
int32_t wDev_SnifferRxData(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.wDev_SnifferRxData; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_34:;
  /* 0034: entry a1, 48 */
  a6 = (uint32_t)&wDevCtrl; /* 0037: l32r a6, 0 <wDev_SnifferRxData-0x34> (0 <wDev_SnifferRxData-0x34>) */ /* literal @0x0: wDevCtrl */
  a3 = (a3 >> 0) & 0xFF; /* 003a: extui a3, a3, 0, 8 */
  MEM32(a1 + 8) = a2; /* 003d: s32i.n a2, a1, 8 */
  a2 = MEM32(a6 + 0); /* 003f: l32i.n a2, a6, 0 */
  MEM32(a1 + 12) = a4; /* 0041: s32i.n a4, a1, 12 */
  a4 = MEM32(a2 + 4); /* 0043: l32i.n a4, a2, 4 */
  a2 = MEM32(a1 + 12); /* 0045: l32i.n a2, a1, 12 */
  if (a2 != 64) goto L_4d; /* 0047: bnei a2, 64, 4d <wDev_SnifferRxData+0x19> */
  goto L_28e; /* 004a: j 28e <wDev_SnifferRxData+0x25a> */
L_4d:;
  a2 = 0x62; /* 004d: movi a2, 98 */
  a5 = MEM32(a1 + 12); /* 0050: l32i a5, a1, 12 */
  if (a5 != a2) goto L_59; /* 0053: bne a5, a2, 59 <wDev_SnifferRxData+0x25> */
  goto L_10a; /* 0056: j 10a <wDev_SnifferRxData+0xd6> */
L_59:;
  a10 = a4; /* 0059: mov.n a10, a4 */
  MEMW(); /* 005b: memw  */
  a8 = (uint32_t)&wdev_csi_len_align; /* 005e: l32r a8, 8 <wDev_SnifferRxData-0x2c> (0 <wDev_SnifferRxData-0x34>) */ /* literal: GOT slot for wdev_csi_len_align */
  wdev_csi_len_align(a2, a3, a4, a5); /* call via literal slot */ /* 0061: callx8 a8 */
  a8 = 0x0; /* 0064: movi.n a8, 0 */
  a2 = (a10 >> 0) & 0xFFFF; /* 0066: extui a2, a10, 0, 16 */
  MEM32(a1 + 0) = a8; /* 0069: s32i.n a8, a1, 0 */
  if (a2 == a8) goto L_bc; /* 006b: beq a2, a8, bc <wDev_SnifferRxData+0x88> */
  a5 = (a10 >> 0) & 0xFFFF; /* 006e: extui a5, a10, 0, 16 */
  a5 = a5 + (24); /* 0071: addi a5, a5, 24 */
  a5 = a4 + a5; /* 0074: add.n a5, a4, a5 */
  a7 = a4 + (24); /* 0076: addi a7, a4, 24 */
  a11 = a5; /* 0079: mov.n a11, a5 */
  a10 = a7; /* 007b: mov.n a10, a7 */
  MEMW(); /* 007d: memw  */
  a8 = (uint32_t)&wdev_csi_hw_bug_check; /* 0080: l32r a8, c <wDev_SnifferRxData-0x28> (0 <wDev_SnifferRxData-0x34>) */ /* literal: GOT slot for wdev_csi_hw_bug_check */
  wdev_csi_hw_bug_check(a2, a3, a4, a5); /* call via literal slot */ /* 0083: callx8 a8 */
  MEM32(a1 + 0) = a10; /* 0086: s32i.n a10, a1, 0 */
  if (a10 != 1) goto L_b2; /* 0088: bnei a10, 1, b2 <wDev_SnifferRxData+0x7e> */
  a10 = MEM8(a4 + 24); /* 008b: l8ui a10, a4, 24 */
  a11 = MEM8(a4 + 25); /* 008e: l8ui a11, a4, 25 */
  MEM8(a5 + 0) = a10; /* 0091: s8i a10, a5, 0 */
  MEMW(); /* 0094: memw  */
  a10 = MEM8(a4 + 26); /* 0097: l8ui a10, a4, 26 */
  MEM8(a5 + 1) = a11; /* 009a: s8i a11, a5, 1 */
  MEMW(); /* 009d: memw  */
  a8 = MEM8(a4 + 27); /* 00a0: l8ui a8, a4, 27 */
  MEM8(a5 + 2) = a10; /* 00a3: s8i a10, a5, 2 */
  MEM8(a5 + 3) = a8; /* 00a6: s8i a8, a5, 3 */
  MEMW(); /* 00a9: memw  */
  MEMW(); /* 00ac: memw  */
  goto L_bc; /* 00af: j bc <wDev_SnifferRxData+0x88> */
L_b2:;
  a9 = MEM32(a1 + 0); /* 00b2: l32i.n a9, a1, 0 */
  a8 = 0x0; /* 00b4: movi.n a8, 0 */
  a5 = a9 + (-2); /* 00b6: addi a5, a9, -2 */
  if (a5 == 0) a2 = a8; /* 00b9: moveqz a2, a8, a5 */
L_bc:;
  a5 = a4 + a2; /* 00bc: add.n a5, a4, a2 */
  a10 = MEM16(a5 + 28); /* 00be: l16ui a10, a5, 28 */
  a5 = 0x0; /* 00c1: movi.n a5, 0 */
  a8 = MEM32(a6 + 0); /* 00c3: l32i.n a8, a6, 0 */
  goto L_d7; /* 00c5: j d7 <wDev_SnifferRxData+0xa3> */
L_c8:;
  MEMW(); /* 00c8: memw  */
  a11 = MEM32(a8 + 0); /* 00cb: l32i.n a11, a8, 0 */
  a11 = (a11 >> 12) & 0xFFF; /* 00cd: extui a11, a11, 12, 12 */
  a5 = a11 + a5; /* 00d0: add.n a5, a11, a5 */
  a5 = (a5 >> 0) & 0xFFFF; /* 00d2: extui a5, a5, 0, 16 */
  a8 = MEM32(a8 + 8); /* 00d5: l32i.n a8, a8, 8 */
L_d7:;
  a9 = MEM32(a1 + 8); /* 00d7: l32i.n a9, a1, 8 */
  if (a8 != a9) goto L_c8; /* 00d9: bne a8, a9, c8 <wDev_SnifferRxData+0x94> */
  a8 = a5 - a2; /* 00dc: sub a8, a5, a2 */
  a5 = (a10 >> 0) & 0xF; /* 00df: extui a5, a10, 0, 4 */
  MEMW(); /* 00e2: memw  */
  a11 = MEM32(a9 + 0); /* 00e5: l32i.n a11, a9, 0 */
  a10 = 0x1; /* 00e7: movi.n a10, 1 */
  a11 = (a11 >> 12) & 0xFFF; /* 00e9: extui a11, a11, 12, 12 */
  a8 = a8 + a11; /* 00ec: add.n a8, a8, a11 */
  a7 = (a8 >> 0) & 0xFFFF; /* 00ee: extui a7, a8, 0, 16 */
  MEM32(a1 + 4) = a5; /* 00f1: s32i.n a5, a1, 4 */
  if (a5 == 0) goto L_116; /* 00f3: beqz.n a5, 116 <wDev_SnifferRxData+0xe2> */
  a11 = 0x2; /* 00f5: movi.n a11, 2 */
  a5 = a5 + (-4); /* 00f7: addi a5, a5, -4 */
  if (a5 != 0) a10 = a11; /* 00fa: movnez a10, a11, a5 */
  MEM32(a1 + 4) = a10; /* 00fd: s32i.n a10, a1, 4 */
  a10 = 0x14; /* 00ff: movi.n a10, 20 */
  if (a5 == 0) a10 = a11; /* 0101: moveqz a10, a11, a5 */
  MEMW(); /* 0104: memw  */
  goto L_116; /* 0107: j 116 <wDev_SnifferRxData+0xe2> */
L_10a:;
  a2 = 0x0; /* 010a: movi.n a2, 0 */
  a5 = 0x3; /* 010c: movi.n a5, 3 */
  MEM32(a1 + 0) = a2; /* 010e: s32i.n a2, a1, 0 */
  a7 = 0x1C; /* 0110: movi.n a7, 28 */
  a10 = 0x8; /* 0112: movi.n a10, 8 */
  MEM32(a1 + 4) = a5; /* 0114: s32i.n a5, a1, 4 */
L_116:;
  a5 = MEM32(a6 + 52); /* 0116: l32i.n a5, a6, 52 */
  if ((a10 & a5) != 0) goto L_11e; /* 0118: bany a10, a5, 11e <wDev_SnifferRxData+0xea> */
  goto L_28e; /* 011b: j 28e <wDev_SnifferRxData+0x25a> */
L_11e:;
  a10 = 0x8; /* 011e: movi.n a10, 8 */
  a8 = (uint32_t)&g_osi_funcs_p; /* 0120: l32r a8, 4 <wDev_SnifferRxData-0x30> (0 <wDev_SnifferRxData-0x34>) */ /* literal @0x4: g_osi_funcs_p */
  a5 = MEM32(a8 + 0); /* 0123: l32i.n a5, a8, 0 */
  a5 = MEM32(a5 + 364); /* 0125: l32i a5, a5, 0x16c */
  MEMW(); /* 0128: memw  */
  ((int32_t(*)())a5)(a2, a3, a4, a5); /* 012b: callx8 a5 */ /* indirect */
  a5 = 0x8; /* 012e: mov.n a5, a10 */
  if (a10 == 0) goto L_28e; /* 0130: beqz a10, 28e <wDev_SnifferRxData+0x25a> */
  a9 = (uint32_t)&g_osi_funcs_p; /* 0133: l32r a9, 4 <wDev_SnifferRxData-0x30> (0 <wDev_SnifferRxData-0x34>) */ /* literal @0x4: g_osi_funcs_p */
  a10 = MEM32(a9 + 0); /* 0136: l32i.n a10, a9, 0 */
  a11 = MEM32(a10 + 364); /* 0138: l32i a11, a10, 0x16c */
  a10 = a7; /* 013b: mov.n a10, a7 */
  ((int32_t(*)())a11)(a2, a3, a4, a5); /* 013d: callx8 a11 */ /* indirect */
  a7 = a10; /* 0140: mov.n a7, a10 */
  if (a10 != 0) goto L_14a; /* 0142: bnez.n a10, 14a <wDev_SnifferRxData+0x116> */
  a3 = (uint32_t)&g_osi_funcs_p; /* 0144: l32r a3, 4 <wDev_SnifferRxData-0x30> (0 <wDev_SnifferRxData-0x34>) */ /* literal @0x4: g_osi_funcs_p */
  goto L_284; /* 0147: j 284 <wDev_SnifferRxData+0x250> */
L_14a:;
  a8 = MEM32(a1 + 12); /* 014a: l32i.n a8, a1, 12 */
  a10 = 0x62; /* 014c: movi a10, 98 */
  if (a8 != a10) goto L_191; /* 014f: bne a8, a10, 191 <wDev_SnifferRxData+0x15d> */
  a2 = a2 + (24); /* 0152: addi a2, a2, 24 */
  a2 = a4 + a2; /* 0155: add.n a2, a4, a2 */
  a11 = a4; /* 0157: mov.n a11, a4 */
  a12 = 0x18; /* 0159: movi.n a12, 24 */
  a10 = a7 | a7; /* 015b: or a10, a7, a7 */
  a8 = (uint32_t)&memcpy; /* 015e: l32r a8, 10 <wDev_SnifferRxData-0x24> (0 <wDev_SnifferRxData-0x34>) */ /* literal: GOT slot for memcpy */
  memcpy(a2, a3, a4, a5); /* call via literal slot */ /* 0161: callx8 a8 */
  a4 = MEM8(a2 + 0); /* 0164: l8ui a4, a2, 0 */
  a3 = a7 + (24); /* 0167: addi a3, a7, 24 */
  a6 = MEM8(a2 + 1); /* 016a: l8ui a6, a2, 1 */
  MEM8(a7 + 24) = a4; /* 016d: s8i a4, a7, 24 */
  MEMW(); /* 0170: memw  */
  a4 = MEM8(a2 + 2); /* 0173: l8ui a4, a2, 2 */
  MEM8(a7 + 25) = a6; /* 0176: s8i a6, a7, 25 */
  MEMW(); /* 0179: memw  */
  a2 = MEM8(a2 + 3); /* 017c: l8ui a2, a2, 3 */
  MEM8(a7 + 26) = a4; /* 017f: s8i a4, a7, 26 */
  MEM8(a7 + 27) = a2; /* 0182: s8i a2, a7, 27 */
  MEMW(); /* 0185: memw  */
  MEMW(); /* 0188: memw  */
  goto L_260; /* 018b: j 260 <wDev_SnifferRxData+0x22c> */
  /* 018e: .byte 00 */
  /* 018f: .byte 00 */
  /* 0190: .byte 00 */
L_191:;
  if (a3 >= 2) goto L_1c4; /* 0191: bgeui a3, 2, 1c4 <wDev_SnifferRxData+0x190> */
  a11 = a4; /* 0194: mov.n a11, a4 */
  a12 = 0x18; /* 0196: movi a12, 24 */
  a10 = a7 | a7; /* 0199: or a10, a7, a7 */
  a8 = (uint32_t)&memcpy; /* 019c: l32r a8, 14 <wDev_SnifferRxData-0x20> (0 <wDev_SnifferRxData-0x34>) */ /* literal: GOT slot for memcpy */
  memcpy(a2, a3, a4, a5); /* call via literal slot */ /* 019f: callx8 a8 */
  a3 = MEM32(a6 + 0); /* 01a2: l32i.n a3, a6, 0 */
  a11 = a2 + (24); /* 01a4: addi a11, a2, 24 */
  a11 = a4 + a11; /* 01a7: add.n a11, a4, a11 */
  a10 = a7 + (24); /* 01a9: addi a10, a7, 24 */
  MEMW(); /* 01ac: memw  */
  a12 = MEM32(a3 + 0); /* 01af: l32i.n a12, a3, 0 */
  a12 = (a12 >> 12) & 0xFFF; /* 01b1: extui a12, a12, 12, 12 */
  a12 = a12 + (-24); /* 01b4: addi a12, a12, -24 */
  a12 = a12 - a2; /* 01b7: sub a12, a12, a2 */
  a8 = (uint32_t)&memcpy; /* 01ba: l32r a8, 18 <wDev_SnifferRxData-0x1c> (0 <wDev_SnifferRxData-0x34>) */ /* literal: GOT slot for memcpy */
  memcpy(a2, a3, a4, a5); /* call via literal slot */ /* 01bd: callx8 a8 */
  goto L_242; /* 01c0: j 242 <wDev_SnifferRxData+0x20e> */
  /* 01c3: .byte 00 */
L_1c4:;
  a4 = MEM32(a6 + 0); /* 01c4: l32i.n a4, a6, 0 */
  a3 = a7; /* 01c6: mov.n a3, a7 */
  a10 = 0x1; /* 01c8: movi.n a10, 1 */
  goto L_226; /* 01ca: j 226 <wDev_SnifferRxData+0x1f2> */
L_1cd:;
  if (a10 == 0) goto L_208; /* 01cd: beqz.n a10, 208 <wDev_SnifferRxData+0x1d4> */
  a12 = 0x18; /* 01cf: movi.n a12, 24 */
  a10 = a3; /* 01d1: mov.n a10, a3 */
  a8 = (uint32_t)&memcpy; /* 01d3: l32r a8, 1c <wDev_SnifferRxData-0x18> (0 <wDev_SnifferRxData-0x34>) */ /* literal: GOT slot for memcpy */
  memcpy(a2, a3, a4, a5); /* call via literal slot */ /* 01d6: callx8 a8 */
  MEMW(); /* 01d9: memw  */
  a10 = MEM32(a4 + 0); /* 01dc: l32i.n a10, a4, 0 */
  a9 = 0xFFFFFFE8; /* 01de: movi.n a9, -24 */
  a10 = (a10 >> 12) & 0xFFF; /* 01e0: extui a10, a10, 12, 12 */
  a12 = a9 - a2; /* 01e3: sub a12, a9, a2 */
  a11 = a2 + (24); /* 01e6: addi a11, a2, 24 */
  a13 = MEM32(a4 + 4); /* 01e9: l32i.n a13, a4, 4 */
  a12 = a12 + a10; /* 01eb: add.n a12, a12, a10 */
  a11 = a13 + a11; /* 01ed: add.n a11, a13, a11 */
  a10 = a3 + (24); /* 01ef: addi a10, a3, 24 */
  a8 = (uint32_t)&memcpy; /* 01f2: l32r a8, 20 <wDev_SnifferRxData-0x14> (0 <wDev_SnifferRxData-0x34>) */ /* literal: GOT slot for memcpy */
  memcpy(a2, a3, a4, a5); /* call via literal slot */ /* 01f5: callx8 a8 */
  MEMW(); /* 01f8: memw  */
  a10 = MEM32(a4 + 0); /* 01fb: l32i.n a10, a4, 0 */
  a10 = (a10 >> 12) & 0xFFF; /* 01fd: extui a10, a10, 12, 12 */
  a10 = a10 - a2; /* 0200: sub a10, a10, a2 */
  goto L_220; /* 0203: j 220 <wDev_SnifferRxData+0x1ec> */
  /* 0206: .byte 00 */
  /* 0207: .byte 00 */
L_208:;
  MEMW(); /* 0208: memw  */
  a12 = MEM32(a4 + 0); /* 020b: l32i.n a12, a4, 0 */
  a10 = a3; /* 020d: mov.n a10, a3 */
  a12 = (a12 >> 12) & 0xFFF; /* 020f: extui a12, a12, 12, 12 */
  a8 = (uint32_t)&memcpy; /* 0212: l32r a8, 24 <wDev_SnifferRxData-0x10> (0 <wDev_SnifferRxData-0x34>) */ /* literal: GOT slot for memcpy */
  memcpy(a2, a3, a4, a5); /* call via literal slot */ /* 0215: callx8 a8 */
  MEMW(); /* 0218: memw  */
  a10 = MEM32(a4 + 0); /* 021b: l32i.n a10, a4, 0 */
  a10 = (a10 >> 12) & 0xFFF; /* 021d: extui a10, a10, 12, 12 */
L_220:;
  a3 = a3 + a10; /* 0220: add.n a3, a3, a10 */
  a10 = 0x0; /* 0222: movi.n a10, 0 */
  a4 = MEM32(a4 + 8); /* 0224: l32i.n a4, a4, 8 */
L_226:;
  a8 = MEM32(a1 + 8); /* 0226: l32i.n a8, a1, 8 */
  a11 = MEM32(a4 + 4); /* 0228: l32i.n a11, a4, 4 */
  if (a4 != a8) goto L_1cd; /* 022a: bne a4, a8, 1cd <wDev_SnifferRxData+0x199> */
  a10 = a3; /* 022d: mov.n a10, a3 */
  MEMW(); /* 022f: memw  */
  a12 = MEM32(a4 + 0); /* 0232: l32i.n a12, a4, 0 */
  a12 = (a12 >> 12) & 0xFFF; /* 0234: extui a12, a12, 12, 12 */
  a8 = (uint32_t)&memcpy; /* 0237: l32r a8, 28 <wDev_SnifferRxData-0xc> (0 <wDev_SnifferRxData-0x34>) */ /* literal: GOT slot for memcpy */
  memcpy(a2, a3, a4, a5); /* call via literal slot */ /* 023a: callx8 a8 */
  MEMW(); /* 023d: memw  */
  a3 = MEM32(a4 + 0); /* 0240: l32i.n a3, a4, 0 */
L_242:;
  if (a2 == 0) goto L_260; /* 0242: beqz.n a2, 260 <wDev_SnifferRxData+0x22c> */
  a13 = a7 + (28); /* 0244: addi a13, a7, 28 */
  a12 = a7; /* 0247: mov.n a12, a7 */
  a11 = a2; /* 0249: mov.n a11, a2 */
  a3 = MEM32(a6 + 0); /* 024b: l32i.n a3, a6, 0 */
  a14 = MEM32(a7 + 24); /* 024d: l32i.n a14, a7, 24 */
  a14 = (a14 >> 0) & 0xFFF; /* 024f: extui a14, a14, 0, 12 */
  a10 = MEM32(a3 + 4); /* 0252: l32i a10, a3, 4 */
  a10 = a10 + (24); /* 0255: addi a10, a10, 24 */
  a15 = MEM32(a1 + 0); /* 0258: l32i.n a15, a1, 0 */
  a8 = (uint32_t)&wdev_csi_rx_process; /* 025a: l32r a8, 2c <wDev_SnifferRxData-0x8> (0 <wDev_SnifferRxData-0x34>) */ /* literal: GOT slot for wdev_csi_rx_process */
  wdev_csi_rx_process(a2, a3, a4, a5); /* call via literal slot */ /* 025d: callx8 a8 */
L_260:;
  a11 = a5; /* 0260: mov.n a11, a5 */
  a10 = 0xD; /* 0262: movi.n a10, 13 */
  a9 = MEM32(a1 + 4); /* 0264: l32i.n a9, a1, 4 */
  MEM32(a5 + 4) = a7; /* 0266: s32i a7, a5, 4 */
  MEM32(a5 + 0) = a9; /* 0269: s32i.n a9, a5, 0 */
  MEMW(); /* 026b: memw  */
  a8 = (uint32_t)&pp_post; /* 026e: l32r a8, 30 <wDev_SnifferRxData-0x4> (0 <wDev_SnifferRxData-0x34>) */ /* literal: GOT slot for pp_post */
  pp_post(a2, a3, a4, a5); /* call via literal slot */ /* 0271: callx8 a8 */
  if (a10 != 1) goto L_28e; /* 0274: bnei a10, 1, 28e <wDev_SnifferRxData+0x25a> */
  a10 = a7; /* 0277: mov.n a10, a7 */
  a3 = (uint32_t)&g_osi_funcs_p; /* 0279: l32r a3, 4 <wDev_SnifferRxData-0x30> (0 <wDev_SnifferRxData-0x34>) */ /* literal @0x4: g_osi_funcs_p */
  a2 = MEM32(a3 + 0); /* 027c: l32i.n a2, a3, 0 */
  a2 = MEM32(a2 + 176); /* 027e: l32i a2, a2, 176 */
  ((int32_t(*)())a2)(a2, a3, a4, a5); /* 0281: callx8 a2 */ /* indirect */
L_284:;
  a10 = a5; /* 0284: mov.n a10, a5 */
  a2 = MEM32(a3 + 0); /* 0286: l32i.n a2, a3, 0 */
  a2 = MEM32(a2 + 176); /* 0288: l32i a2, a2, 176 */
  ((int32_t(*)())a2)(a2, a3, a4, a5); /* 028b: callx8 a2 */ /* indirect */
L_28e:;
  return (int32_t)a2; /* 028e: retw.n  */
}

/* wDev_IndicateCtrlFrame @ wdev.o 00000024 size 244B bind GLOBAL
 * Calls: memcpy, wdev_csi_hw_bug_check, wdev_csi_len_align, wdev_csi_rx_process, wifi_log, wDevCtrl[got] | Data refs: .rodata_wlog_warning.22, g_osi_funcs_p, memcpy, wDevCtrl, wdev_csi_hw_bug_check, wdev_csi_len_align, wdev_csi_rx_process, wifi_log
 *   MMIO: none
 *   funcdb v3: 5 call(s), 8 ref(s); disasm: 7 call(s), 8 data ref(s)
 * Fidelity: medium - 91 instr, 8 branches, calls resolved */
int32_t wDev_IndicateCtrlFrame(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.wDev_IndicateCtrlFrame; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_24:;
  /* 0024: entry a1, 32 */
  a14 = (a4 >> 0) & 0xFFFF; /* 0027: extui a14, a4, 0, 16 */
  if (a14 == 1) goto L_3f; /* 002a: beqi a14, 1, 3f <wDev_IndicateCtrlFrame+0x1b> */
  a13 = (uint32_t)&lit_rodata_wlog_warning_22; /* 002d: l32r a13, 0 <wDev_IndicateCtrlFrame-0x24> (0 <wDev_IndicateCtrlFrame-0x24>) */ /* literal @0x0: .rodata_wlog_warning.22 */
  a12 = 0x2; /* 0030: movi.n a12, 2 */
  a11 = 0x20; /* 0032: movi.n a11, 32 */
  a10 = 0x6; /* 0034: movi.n a10, 6 */
  a8 = (uint32_t)&wifi_log; /* 0036: l32r a8, c <wDev_IndicateCtrlFrame-0x18> (0 <wDev_IndicateCtrlFrame-0x24>) */ /* literal: GOT slot for wifi_log */
  wifi_log(a2, a3, a4, a5); /* call via literal slot */ /* 0039: callx8 a8 */
  goto L_114; /* 003c: j 114 <wDev_IndicateCtrlFrame+0xf0> */
L_3f:;
  a2 = (uint32_t)&wDevCtrl; /* 003f: l32r a2, 4 <wDev_IndicateCtrlFrame-0x20> (0 <wDev_IndicateCtrlFrame-0x24>) */ /* literal @0x4: wDevCtrl */
  a3 = MEM32(a2 + 0); /* 0042: l32i a3, a2, 0 */
  a5 = MEM32(a3 + 4); /* 0045: l32i a5, a3, 4 */
  a10 = a5; /* 0048: mov.n a10, a5 */
  a8 = (uint32_t)&wdev_csi_len_align; /* 004a: l32r a8, 10 <wDev_IndicateCtrlFrame-0x14> (0 <wDev_IndicateCtrlFrame-0x24>) */ /* literal: GOT slot for wdev_csi_len_align */
  wdev_csi_len_align(a2, a3, a4, a5); /* call via literal slot */ /* 004d: callx8 a8 */
  a4 = (a10 >> 0) & 0xFFFF; /* 0050: extui a4, a10, 0, 16 */
  if (a4 == 0) goto L_114; /* 0053: beqz a4, 114 <wDev_IndicateCtrlFrame+0xf0> */
  a2 = MEM8(a2 + 48); /* 0056: l8ui a2, a2, 48 */
  if (a2 != 1) goto L_61; /* 0059: bnei a2, 1, 61 <wDev_IndicateCtrlFrame+0x3d> */
  a2 = MEM32(a5 + 0); /* 005c: l32i.n a2, a5, 0 */
  /* 005e: bltz a2, 114 <wDev_IndicateCtrlFrame+0xf0> */ /* UNMODELED branch */
L_61:;
  a2 = (a10 >> 0) & 0xFFFF; /* 0061: extui a2, a10, 0, 16 */
  a2 = a2 + (24); /* 0064: addi a2, a2, 24 */
  a6 = a5 + (24); /* 0067: addi a6, a5, 24 */
  a2 = a5 + a2; /* 006a: add.n a2, a5, a2 */
  a11 = a2; /* 006c: mov.n a11, a2 */
  a10 = a6; /* 006e: mov.n a10, a6 */
  a8 = (uint32_t)&wdev_csi_hw_bug_check; /* 0070: l32r a8, 14 <wDev_IndicateCtrlFrame-0x10> (0 <wDev_IndicateCtrlFrame-0x24>) */ /* literal: GOT slot for wdev_csi_hw_bug_check */
  wdev_csi_hw_bug_check(a2, a3, a4, a5); /* call via literal slot */ /* 0073: callx8 a8 */
  a7 = a10; /* 0076: mov.n a7, a10 */
  if (a10 != 1) goto L_a4; /* 0078: bnei a10, 1, a4 <wDev_IndicateCtrlFrame+0x80> */
  a8 = MEM8(a5 + 24); /* 007b: l8ui a8, a5, 24 */
  a5 = MEM8(a5 + 25); /* 007e: l8ui a5, a5, 25 */
  MEM8(a2 + 0) = a8; /* 0081: s8i a8, a2, 0 */
  MEMW(); /* 0084: memw  */
  a8 = MEM8(a6 + 2); /* 0087: l8ui a8, a6, 2 */
  MEM8(a2 + 1) = a5; /* 008a: s8i a5, a2, 1 */
  MEMW(); /* 008d: memw  */
  a5 = MEM8(a6 + 3); /* 0090: l8ui a5, a6, 3 */
  MEM8(a2 + 2) = a8; /* 0093: s8i a8, a2, 2 */
  MEM8(a2 + 3) = a5; /* 0096: s8i a5, a2, 3 */
  MEMW(); /* 0099: memw  */
  MEMW(); /* 009c: memw  */
  goto L_ac; /* 009f: j ac <wDev_IndicateCtrlFrame+0x88> */
  /* 00a2: .byte 00 */
  /* 00a3: .byte 00 */
L_a4:;
  a2 = a10 + (-2); /* 00a4: addi a2, a10, -2 */
  a5 = 0x0; /* 00a7: movi.n a5, 0 */
  if (a2 == 0) a4 = a5; /* 00a9: moveqz a4, a5, a2 */
L_ac:;
  a5 = (uint32_t)&g_osi_funcs_p; /* 00ac: l32r a5, 8 <wDev_IndicateCtrlFrame-0x1c> (0 <wDev_IndicateCtrlFrame-0x24>) */ /* literal @0x8: g_osi_funcs_p */
  MEMW(); /* 00af: memw  */
  a10 = MEM32(a3 + 0); /* 00b2: l32i.n a10, a3, 0 */
  a10 = (a10 >> 12) & 0xFFF; /* 00b4: extui a10, a10, 12, 12 */
  a10 = a10 - a4; /* 00b7: sub a10, a10, a4 */
  a2 = MEM32(a5 + 0); /* 00ba: l32i.n a2, a5, 0 */
  a2 = MEM32(a2 + 364); /* 00bc: l32i a2, a2, 0x16c */
  ((int32_t(*)())a2)(a2, a3, a4, a5); /* 00bf: callx8 a2 */ /* indirect */
  a2 = a10; /* 00c2: mov.n a2, a10 */
  if (a10 == 0) goto L_114; /* 00c4: beqz a10, 114 <wDev_IndicateCtrlFrame+0xf0> */
  a11 = MEM32(a3 + 4); /* 00c7: l32i.n a11, a3, 4 */
  a12 = 0x18; /* 00c9: movi.n a12, 24 */
  a8 = (uint32_t)&memcpy; /* 00cb: l32r a8, 18 <wDev_IndicateCtrlFrame-0xc> (0 <wDev_IndicateCtrlFrame-0x24>) */ /* literal: GOT slot for memcpy */
  memcpy(a2, a3, a4, a5); /* call via literal slot */ /* 00ce: callx8 a8 */
  a6 = a4 + (24); /* 00d1: addi a6, a4, 24 */
  a10 = a2 + (24); /* 00d4: addi a10, a2, 24 */
  MEMW(); /* 00d7: memw  */
  a12 = MEM32(a3 + 0); /* 00da: l32i.n a12, a3, 0 */
  a12 = (a12 >> 12) & 0xFFF; /* 00dc: extui a12, a12, 12, 12 */
  a12 = a12 - a4; /* 00df: sub a12, a12, a4 */
  a12 = a12 + (-24); /* 00e2: addi a12, a12, -24 */
  a11 = MEM32(a3 + 4); /* 00e5: l32i.n a11, a3, 4 */
  a11 = a11 + a6; /* 00e7: add a11, a11, a6 */
  a8 = (uint32_t)&memcpy; /* 00ea: l32r a8, 1c <wDev_IndicateCtrlFrame-0x8> (0 <wDev_IndicateCtrlFrame-0x24>) */ /* literal: GOT slot for memcpy */
  memcpy(a2, a3, a4, a5); /* call via literal slot */ /* 00ed: callx8 a8 */
  a15 = a7; /* 00f0: mov.n a15, a7 */
  a10 = MEM32(a3 + 4); /* 00f2: l32i.n a10, a3, 4 */
  a13 = a2 + (28); /* 00f4: addi a13, a2, 28 */
  a10 = a10 + (24); /* 00f7: addi a10, a10, 24 */
  a12 = a2; /* 00fa: mov.n a12, a2 */
  a11 = a4; /* 00fc: mov.n a11, a4 */
  a14 = MEM32(a2 + 24); /* 00fe: l32i a14, a2, 24 */
  a14 = (a14 >> 0) & 0xFFF; /* 0101: extui a14, a14, 0, 12 */
  a8 = (uint32_t)&wdev_csi_rx_process; /* 0104: l32r a8, 20 <wDev_IndicateCtrlFrame-0x4> (0 <wDev_IndicateCtrlFrame-0x24>) */ /* literal: GOT slot for wdev_csi_rx_process */
  wdev_csi_rx_process(a2, a3, a4, a5); /* call via literal slot */ /* 0107: callx8 a8 */
  a10 = a2; /* 010a: mov.n a10, a2 */
  a3 = MEM32(a5 + 0); /* 010c: l32i.n a3, a5, 0 */
  a3 = MEM32(a3 + 176); /* 010e: l32i a3, a3, 176 */
  ((int32_t(*)())a3)(a2, a3, a4, a5); /* 0111: callx8 a3 */ /* indirect */
L_114:;
  a2 = 0x1; /* 0114: movi.n a2, 1 */
  return (int32_t)a2; /* 0116: retw.n  */
}

/* wDev_record_ftm_data @ wdev.o 00000000 size 5B bind GLOBAL
 * Calls: none | Data refs: none
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t wDev_record_ftm_data(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .wifirxiram.26; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_0:;
  /* 0000: entry a1, 32 */
  return (int32_t)a2; /* 0003: retw.n  */
}

/* wdev_nan_set_callbacks @ wdev.o 00000004 size 15B bind GLOBAL
 * Calls: none | Data refs: g_wdev_is_nan_pkt_in_valid_slot_cb
 *   MMIO: none
 *   funcdb v3: 0 call(s), 1 ref(s); disasm: 0 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t wdev_nan_set_callbacks(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.wdev_nan_set_callbacks; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a8 = (uint32_t)&g_wdev_is_nan_pkt_in_valid_slot_cb; /* 0007: l32r a8, 0 <wdev_nan_set_callbacks-0x4> (0 <wdev_nan_set_callbacks-0x4>) */ /* literal @0x0: g_wdev_is_nan_pkt_in_valid_slot_cb */
  MEM32(a8 + 0) = a2; /* 000a: s32i.n a2, a8, 0 */
  a2 = 0x0; /* 000c: movi.n a2, 0 */
  MEMW(); /* 000e: memw  */
  return (int32_t)a2; /* 0011: retw.n  */
}

/* wDev_isNANPktInValidSlot @ wdev.o 00000004 size 44B bind GLOBAL
 * Calls: none | Data refs: g_wdev_is_nan_pkt_in_valid_slot_cb
 *   MMIO: none
 *   funcdb v3: 0 call(s), 1 ref(s); disasm: 0 call(s), 1 data ref(s)
 * Fidelity: medium - 18 instr, 2 branches, calls resolved */
int32_t wDev_isNANPktInValidSlot(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.wDev_isNANPktInValidSlot; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a8 = MEM32(a2 + 44); /* 0007: l32i.n a8, a2, 44 */
  a9 = 0x1; /* 0009: movi.n a9, 1 */
  a9 = 0x80000; /* 000b: slli a9, a9, 19 */
  a10 = a2; /* 000e: mov.n a10, a2 */
  a2 = 0x1; /* 0010: movi.n a2, 1 */
  a11 = MEM32(a8 + 16); /* 0012: l32i.n a11, a8, 16 */
  a8 = 0x3; /* 0014: movi.n a8, 3 */
  a8 = 0xC0000; /* 0016: slli a8, a8, 18 */
  a11 = a11 & a8; /* 0019: and a11, a11, a8 */
  if (a11 != a9) goto L_2e; /* 001c: bne a11, a9, 2e <wDev_isNANPktInValidSlot+0x2a> */
  a8 = (uint32_t)&g_wdev_is_nan_pkt_in_valid_slot_cb; /* 001f: l32r a8, 0 <wDev_isNANPktInValidSlot-0x4> (0 <wDev_isNANPktInValidSlot-0x4>) */ /* literal @0x0: g_wdev_is_nan_pkt_in_valid_slot_cb */
  a2 = 0x0; /* 0022: movi.n a2, 0 */
  a9 = MEM32(a8 + 0); /* 0024: l32i.n a9, a8, 0 */
  if (a9 == a2) goto L_2e; /* 0026: beq a9, a2, 2e <wDev_isNANPktInValidSlot+0x2a> */
  ((int32_t(*)())a9)(a2, a3, a4, a5); /* 0029: callx8 a9 */ /* indirect */
  a2 = a10; /* 002c: mov.n a2, a10 */
L_2e:;
  return (int32_t)a2; /* 002e: retw.n  */
}

/* wDev_ProcessRxData_NAN_Interface_Hook @ wdev.o 00000014 size 108B bind GLOBAL
 * Calls: memcmp | Data refs: NAN_NETWORK_ID, NAN_STANDARD_BSSID, memcmp
 *   MMIO: none
 *   funcdb v3: 1 call(s), 3 ref(s); disasm: 2 call(s), 3 data ref(s)
 * Fidelity: medium - 41 instr, 6 branches, calls resolved */
int32_t wDev_ProcessRxData_NAN_Interface_Hook(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.wDev_ProcessRxData_NAN_Interface_Hook; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_14:;
  /* 0014: entry a1, 32 */
  a8 = MEM16(a3 + 0); /* 0017: l16ui a8, a3, 0 */
  a4 = 0xF0; /* 001a: movi a4, 240 */
  a8 = a8 & a4; /* 001d: and a8, a8, a4 */
  if (a8 != 128) goto L_64; /* 0020: bnei a8, 128, 64 <wDev_ProcessRxData_NAN_Interface_Hook+0x50> */
  a12 = 0x4; /* 0023: movi a12, 4 */
  a11 = (uint32_t)&NAN_STANDARD_BSSID; /* 0026: l32r a11, 0 <wDev_ProcessRxData_NAN_Interface_Hook-0x14> (0 <wDev_ProcessRxData_NAN_Interface_Hook-0x14>) */ /* literal @0x0: NAN_STANDARD_BSSID */
  a10 = a3 + (16); /* 0029: addi a10, a3, 16 */
  a8 = (uint32_t)&memcmp; /* 002c: l32r a8, c <wDev_ProcessRxData_NAN_Interface_Hook-0x8> (0 <wDev_ProcessRxData_NAN_Interface_Hook-0x14>) */ /* literal: GOT slot for memcmp */
  memcmp(a2, a3, a4, a5); /* call via literal slot */ /* 002f: callx8 a8 */
  if (a10 != 0) goto L_50; /* 0032: bnez.n a10, 50 <wDev_ProcessRxData_NAN_Interface_Hook+0x3c> */
L_34:;
  a3 = 0xFFFFFF8F; /* 0034: movi a3, -113 */
  a8 = MEM8(a2 + 3); /* 0037: l8ui a8, a2, 3 */
  a4 = 0x1; /* 003a: movi.n a4, 1 */
  a8 = a8 & a3; /* 003c: and a8, a8, a3 */
  a3 = 0x40; /* 003f: movi.n a3, 64 */
  a8 = a8 | a3; /* 0041: or a8, a8, a3 */
  MEM8(a2 + 3) = a8; /* 0044: s8i a8, a2, 3 */
  MEMW(); /* 0047: memw  */
  MEMW(); /* 004a: memw  */
  goto L_7c; /* 004d: j 7c <wDev_ProcessRxData_NAN_Interface_Hook+0x68> */
L_50:;
  a3 = MEM32(a2 + 0); /* 0050: l32i.n a3, a2, 0 */
  a4 = 0xBFFFFFFF; /* 0052: l32r a4, 4 <wDev_ProcessRxData_NAN_Interface_Hook-0x10> (bfffffff <wDev_ProcessFiq+0xbfffff8b>) */ @0x4
  a3 = a3 & a4; /* 0055: and a3, a3, a4 */
  a4 = 0x0; /* 0058: movi.n a4, 0 */
  MEM32(a2 + 0) = a3; /* 005a: s32i.n a3, a2, 0 */
  MEMW(); /* 005c: memw  */
  goto L_7c; /* 005f: j 7c <wDev_ProcessRxData_NAN_Interface_Hook+0x68> */
  /* 0062: .byte 00 */
  /* 0063: .byte 00 */
L_64:;
  a9 = 0xD0; /* 0064: movi a9, 208 */
  a4 = 0x1; /* 0067: movi.n a4, 1 */
  if (a8 != a9) goto L_7c; /* 0069: bne a8, a9, 7c <wDev_ProcessRxData_NAN_Interface_Hook+0x68> */
  a11 = (uint32_t)&NAN_NETWORK_ID; /* 006c: l32r a11, 8 <wDev_ProcessRxData_NAN_Interface_Hook-0xc> (0 <wDev_ProcessRxData_NAN_Interface_Hook-0x14>) */ /* literal @0x8: NAN_NETWORK_ID */
  a12 = 0x6; /* 006f: movi.n a12, 6 */
  a10 = a3 + (4); /* 0071: addi.n a10, a3, 4 */
  a8 = (uint32_t)&memcmp; /* 0073: l32r a8, 10 <wDev_ProcessRxData_NAN_Interface_Hook-0x4> (0 <wDev_ProcessRxData_NAN_Interface_Hook-0x14>) */ /* literal: GOT slot for memcmp */
  memcmp(a2, a3, a4, a5); /* call via literal slot */ /* 0076: callx8 a8 */
  if (a10 == 0) goto L_34; /* 0079: beqz a10, 34 <wDev_ProcessRxData_NAN_Interface_Hook+0x20> */
L_7c:;
  a2 = a4; /* 007c: mov.n a2, a4 */
  return (int32_t)a2; /* 007e: retw.n  */
}

/* wDev_FetchFirstDesc @ wdev.o 00000000 size 7B bind GLOBAL
 * Calls: none | Data refs: none
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t wDev_FetchFirstDesc(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.wDev_FetchFirstDesc; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_0:;
  /* 0000: entry a1, 32 */
  a2 = 0x0; /* 0003: movi.n a2, 0 */
  return (int32_t)a2; /* 0005: retw.n  */
}

/* wDev_Rxbuf_Deinit @ wdev.o 00000010 size 97B bind GLOBAL
 * Calls: wifi_log, g_osi_funcs_p[got] | Data refs: .rodata_wlog_info.36, g_osi_funcs_p, wDevCtrl, wifi_log
 *   MMIO: none
 *   funcdb v3: 1 call(s), 4 ref(s); disasm: 2 call(s), 4 data ref(s)
 * Fidelity: medium - 38 instr, 5 branches, calls resolved */
int32_t wDev_Rxbuf_Deinit(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.wDev_Rxbuf_Deinit; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_10:;
  /* 0010: entry a1, 32 */
  a3 = (uint32_t)&wDevCtrl; /* 0013: l32r a3, 0 <wDev_Rxbuf_Deinit-0x10> (0 <wDev_Rxbuf_Deinit-0x10>) */ /* literal @0x0: wDevCtrl */
  a4 = 0x0; /* 0016: movi.n a4, 0 */
  a5 = MEM32(a3 + 0); /* 0018: l32i.n a5, a3, 0 */
  a2 = a5; /* 001a: mov.n a2, a5 */
  a7 = (uint32_t)&g_osi_funcs_p; /* 001c: l32r a7, 4 <wDev_Rxbuf_Deinit-0xc> (0 <wDev_Rxbuf_Deinit-0x10>) */ /* literal @0x4: g_osi_funcs_p */
  goto L_3d; /* 001f: j 3d <wDev_Rxbuf_Deinit+0x2d> */
L_22:;
  a10 = MEM32(a2 + 4); /* 0022: l32i.n a10, a2, 4 */
  a6 = MEM32(a2 + 8); /* 0024: l32i.n a6, a2, 8 */
  if (a10 == 0) goto L_36; /* 0026: beqz a10, 36 <wDev_Rxbuf_Deinit+0x26> */
  a8 = MEM32(a7 + 0); /* 0029: l32i a8, a7, 0 */
  a8 = MEM32(a8 + 176); /* 002c: l32i a8, a8, 176 */
  ((int32_t(*)())a8)(a2, a3, a4, a5); /* 002f: callx8 a8 */ /* indirect */
  a8 = 0x0; /* 0032: movi.n a8, 0 */
  MEM32(a2 + 4) = a8; /* 0034: s32i.n a8, a2, 4 */
L_36:;
  a4 = a4 + (1); /* 0036: addi.n a4, a4, 1 */
  if (a5 == a6) goto L_40; /* 0038: beq a5, a6, 40 <wDev_Rxbuf_Deinit+0x30> */
  a2 = a6; /* 003b: mov.n a2, a6 */
L_3d:;
  if (a2 != 0) goto L_22; /* 003d: bnez a2, 22 <wDev_Rxbuf_Deinit+0x12> */
L_40:;
  a13 = (uint32_t)&lit_rodata_wlog_info_36; /* 0040: l32r a13, 8 <wDev_Rxbuf_Deinit-0x8> (0 <wDev_Rxbuf_Deinit-0x10>) */ /* literal @0x8: .rodata_wlog_info.36 */
  a10 = 0x6; /* 0043: movi.n a10, 6 */
  a2 = 0x0; /* 0045: movi.n a2, 0 */
  a14 = a4; /* 0047: mov.n a14, a4 */
  a12 = 0x3; /* 0049: movi.n a12, 3 */
  a11 = 0x1; /* 004b: movi a11, 1 */
  MEM32(a3 + 0) = a2; /* 004e: s32i a2, a3, 0 */
  MEMW(); /* 0051: memw  */
  a8 = (uint32_t)&wifi_log; /* 0054: l32r a8, c <wDev_Rxbuf_Deinit-0x4> (0 <wDev_Rxbuf_Deinit-0x10>) */ /* literal: GOT slot for wifi_log */
  wifi_log(a2, a3, a4, a5); /* call via literal slot */ /* 0057: callx8 a8 */
  a10 = MEM32(a3 + 8); /* 005a: l32i.n a10, a3, 8 */
  if (a10 == a2) goto L_6c; /* 005c: beq a10, a2, 6c <wDev_Rxbuf_Deinit+0x5c> */
  a4 = (uint32_t)&g_osi_funcs_p; /* 005f: l32r a4, 4 <wDev_Rxbuf_Deinit-0xc> (0 <wDev_Rxbuf_Deinit-0x10>) */ /* literal @0x4: g_osi_funcs_p */
  a4 = MEM32(a4 + 0); /* 0062: l32i.n a4, a4, 0 */
  a4 = MEM32(a4 + 176); /* 0064: l32i a4, a4, 176 */
  g_osi_funcs_p(a2, a3, a4, a5); /* call via literal slot */ /* 0067: callx8 a4 */
  MEM32(a3 + 8) = a2; /* 006a: s32i.n a2, a3, 8 */
L_6c:;
  MEMW(); /* 006c: memw  */
  return (int32_t)a2; /* 006f: retw.n  */
}

/* wDev_Rxbuf_Init @ wdev.o 0000005c size 498B bind GLOBAL
 * Calls: memset, wDev_Rxbuf_Deinit, wifi_log | Data refs: .rodata_wlog_error.31, .rodata_wlog_error.35, .rodata_wlog_info.32, .rodata_wlog_info.33, .rodata_wlog_info.34, .rodata_wlog_warning.30, g_osi_funcs_p, g_wifi_menuconfig, memset, pTxRx, wDevCtrl, wDev_Rxbuf_Deinit, wifi_log
 *   MMIO: none
 *   funcdb v3: 3 call(s), 13 ref(s); disasm: 8 call(s), 13 data ref(s)
 * Fidelity: medium - 196 instr, 12 branches, 2 indirect; flow + direct calls mapped, GOT-indirects enumerated (verified against section disasm) */
int32_t wDev_Rxbuf_Init(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.wDev_Rxbuf_Init; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_5c:;
  /* 005c: entry a1, 64 */
  a4 = (uint32_t)&g_osi_funcs_p; /* 005f: l32r a4, 0 <wDev_Rxbuf_Init-0x5c> (0 <wDev_Rxbuf_Init-0x5c>) */ /* literal @0x0: g_osi_funcs_p */
  a10 = (a2 << 2) + a2; /* 0062: addx2 a10, a2, a2 */
  a10 = a10 << (2 & 31); /* 0065: slli a10, a10, 2 */
  a10 = (a10 >> 0) & 0xFFFF; /* 0068: extui a10, a10, 0, 16 */
  a3 = MEM32(a4 + 0); /* 006b: l32i a3, a4, 0 */
  a3 = MEM32(a3 + 360); /* 006e: l32i a3, a3, 0x168 */
  ((int32_t(*)())a3)(a2, a3, a4, a5); /* 0071: callx8 a3 */ /* indirect */
  a3 = (uint32_t)&wDevCtrl; /* 0074: l32r a3, 4 <wDev_Rxbuf_Init-0x58> (0 <wDev_Rxbuf_Init-0x5c>) */ /* literal @0x4: wDevCtrl */
  MEM32(a3 + 8) = a10; /* 0077: s32i.n a10, a3, 8 */
  if (a10 != 0) goto L_94; /* 0079: bnez.n a10, 94 <wDev_Rxbuf_Init+0x38> */
  a12 = 0x1; /* 007b: movi.n a12, 1 */
  a13 = (uint32_t)&lit_rodata_wlog_error_31; /* 007d: l32r a13, 8 <wDev_Rxbuf_Init-0x54> (0 <wDev_Rxbuf_Init-0x5c>) */ /* literal @0x8: .rodata_wlog_error.31 */
  a14 = a2; /* 0080: mov.n a14, a2 */
  a11 = 0x1; /* 0082: mov.n a11, a12 */
  a10 = 0x6; /* 0084: movi a10, 6 */
  MEMW(); /* 0087: memw  */
  a8 = (uint32_t)&wifi_log; /* 008a: l32r a8, 3c <wDev_Rxbuf_Init-0x20> (0 <wDev_Rxbuf_Init-0x5c>) */ /* literal: GOT slot for wifi_log */
  wifi_log(a2, a3, a4, a5); /* call via literal slot */ /* 008d: callx8 a8 */
  goto L_1de; /* 0090: j 1de <wDev_Rxbuf_Init+0x182> */
  /* 0093: .byte 00 */
L_94:;
  a5 = (uint32_t)&g_wifi_menuconfig; /* 0094: l32r a5, 10 <wDev_Rxbuf_Init-0x4c> (0 <wDev_Rxbuf_Init-0x5c>) */ /* literal @0x10: g_wifi_menuconfig */
  a4 = (uint32_t)&pTxRx; /* 0097: l32r a4, c <wDev_Rxbuf_Init-0x50> (0 <wDev_Rxbuf_Init-0x5c>) */ /* literal @0xC: pTxRx */
  a8 = MEM32(a5 + 24); /* 009a: l32i.n a8, a5, 24 */
  a7 = MEM32(a4 + 0); /* 009c: l32i.n a7, a4, 0 */
  if (a8 == 0) goto L_a6; /* 009e: beqz.n a8, a6 <wDev_Rxbuf_Init+0x4a> */
  a8 = 0x8A4; /* 00a0: l32r a8, 14 <wDev_Rxbuf_Init-0x48> (8a4 <wDev_ProcessFiq+0x830>) */ @0x14
  MEM32(a7 + 964) = a8; /* 00a3: s32i a8, a7, 0x3c4 */
L_a6:;
  a12 = 0x3; /* 00a6: movi.n a12, 3 */
  a11 = 0x1; /* 00a8: movi.n a11, 1 */
  a10 = 0x6; /* 00aa: movi.n a10, 6 */
  a5 = 0x0; /* 00ac: movi.n a5, 0 */
  a14 = MEM32(a7 + 964); /* 00ae: l32i a14, a7, 0x3c4 */
  a7 = a1 | a1; /* 00b1: or a7, a1, a1 */
  a13 = (uint32_t)&lit_rodata_wlog_info_32; /* 00b4: l32r a13, 18 <wDev_Rxbuf_Init-0x44> (0 <wDev_Rxbuf_Init-0x5c>) */ /* literal @0x18: .rodata_wlog_info.32 */
  MEMW(); /* 00b7: memw  */
  a8 = (uint32_t)&wifi_log; /* 00ba: l32r a8, 40 <wDev_Rxbuf_Init-0x1c> (0 <wDev_Rxbuf_Init-0x5c>) */ /* literal: GOT slot for wifi_log */
  wifi_log(a2, a3, a4, a5); /* call via literal slot */ /* 00bd: callx8 a8 */
  a9 = (a2 >> 0) & 0xFFFF; /* 00c0: extui a9, a2, 0, 16 */
  a4 = MEM32(a4 + 0); /* 00c3: l32i.n a4, a4, 0 */
  a4 = MEM32(a4 + 964); /* 00c5: l32i a4, a4, 0x3c4 */
  a4 = a4 + (4); /* 00c8: addi.n a4, a4, 4 */
  a6 = (a4 >> 0) & 0xFFFF; /* 00ca: extui a6, a4, 0, 16 */
  a4 = (a4 >> 0) & 0xFFF; /* 00cd: extui a4, a4, 0, 12 */
  a8 = MEM32(a3 + 8); /* 00d0: l32i.n a8, a3, 8 */
  MEM32(a1 + 16) = a9; /* 00d2: s32i.n a9, a1, 16 */
  MEMW(); /* 00d4: memw  */
  goto L_186; /* 00d7: j 186 <wDev_Rxbuf_Init+0x12a> */
  /* 00da: .byte 00 */
  /* 00db: .byte 00 */
L_dc:;
  a10 = (uint32_t)&g_osi_funcs_p; /* 00dc: l32r a10, 0 <wDev_Rxbuf_Init-0x5c> (0 <wDev_Rxbuf_Init-0x5c>) */ /* literal @0x0: g_osi_funcs_p */
  a9 = MEM32(a10 + 0); /* 00df: l32i.n a9, a10, 0 */
  a10 = a6; /* 00e1: mov.n a10, a6 */
  a9 = MEM32(a9 + 348); /* 00e3: l32i a9, a9, 0x15c */
  MEM32(a1 + 20) = a8; /* 00e6: s32i.n a8, a1, 20 */
  MEMW(); /* 00e8: memw  */
  ((int32_t(*)())a9)(a2, a3, a4, a5); /* 00eb: callx8 a9 */ /* indirect */
  a8 = MEM32(a1 + 20); /* 00ee: l32i.n a8, a1, 20 */
  if (a10 != 0) goto L_106; /* 00f0: bnez.n a10, 106 <wDev_Rxbuf_Init+0xaa> */
  a13 = (uint32_t)&lit_rodata_wlog_warning_30; /* 00f2: l32r a13, 1c <wDev_Rxbuf_Init-0x40> (0 <wDev_Rxbuf_Init-0x5c>) */ /* literal @0x1C: .rodata_wlog_warning.30 */
  a12 = 0x2; /* 00f5: movi.n a12, 2 */
  a11 = 0x1; /* 00f7: movi.n a11, 1 */
  a10 = 0x6; /* 00f9: movi.n a10, 6 */
  a8 = (uint32_t)&wifi_log; /* 00fb: l32r a8, 44 <wDev_Rxbuf_Init-0x18> (0 <wDev_Rxbuf_Init-0x5c>) */ /* literal: GOT slot for wifi_log */
  wifi_log(a2, a3, a4, a5); /* call via literal slot */ /* 00fe: callx8 a8 */
  goto L_198; /* 0101: j 198 <wDev_Rxbuf_Init+0x13c> */
  /* 0104: .byte 00 */
  /* 0105: .byte 00 */
L_106:;
  a11 = 0x0; /* 0106: movi.n a11, 0 */
  a12 = a6; /* 0108: mov.n a12, a6 */
  MEM32(a1 + 20) = a8; /* 010a: s32i.n a8, a1, 20 */
  MEMW(); /* 010c: memw  */
  a8 = (uint32_t)&memset; /* 010f: l32r a8, 48 <wDev_Rxbuf_Init-0x14> (0 <wDev_Rxbuf_Init-0x5c>) */ /* literal: GOT slot for memset */
  memset(a2, a3, a4, a5); /* call via literal slot */ /* 0112: callx8 a8 */
  a5 = a5 + (1); /* 0115: addi.n a5, a5, 1 */
  a8 = MEM32(a1 + 20); /* 0117: l32i.n a8, a1, 20 */
  MEMW(); /* 0119: memw  */
  a9 = MEM32(a8 + 0); /* 011c: l32i.n a9, a8, 0 */
  MEM32(a8 + 4) = a10; /* 011e: s32i.n a10, a8, 4 */
  a10 = 0xFFFFFFFF; /* 0120: movi.n a10, -1 */
  a10 = 0xFFFFF000; /* 0122: slli a10, a10, 12 */
  a9 = a9 & a10; /* 0125: and a9, a9, a10 */
  a9 = a9 | a4; /* 0128: or a9, a9, a4 */
  MEMW(); /* 012b: memw  */
  MEM32(a8 + 0) = a9; /* 012e: s32i.n a9, a8, 0 */
  a10 = 0xFFFFFFFF; /* 0130: movi.n a10, -1 */
  a10 = 0x80000000; /* 0132: slli a10, a10, 31 */
  MEMW(); /* 0135: memw  */
  a9 = MEM32(a8 + 0); /* 0138: l32i.n a9, a8, 0 */
  a9 = a9 | a10; /* 013a: or a9, a9, a10 */
  MEMW(); /* 013d: memw  */
  MEM32(a8 + 0) = a9; /* 0140: s32i.n a9, a8, 0 */
  MEMW(); /* 0142: memw  */
  a10 = MEM32(a8 + 0); /* 0145: l32i.n a10, a8, 0 */
  a10 = (a10 >> 0) & 0xFFF; /* 0147: extui a10, a10, 0, 12 */
  a10 = a10 << (12 & 31); /* 014a: slli a10, a10, 12 */
  MEMW(); /* 014d: memw  */
  a9 = MEM32(a8 + 0); /* 0150: l32i.n a9, a8, 0 */
  a11 = 0xFF000FFF; /* 0152: l32r a11, 20 <wDev_Rxbuf_Init-0x3c> (ff000fff <wDev_ProcessFiq+0xff000f8b>) */ @0x20
  a9 = a9 & a11; /* 0155: and a9, a9, a11 */
  a9 = a9 | a10; /* 0158: or a9, a9, a10 */
  MEMW(); /* 015b: memw  */
  MEM32(a8 + 0) = a9; /* 015e: s32i.n a9, a8, 0 */
  MEMW(); /* 0160: memw  */
  a9 = MEM32(a8 + 0); /* 0163: l32i.n a9, a8, 0 */
  a10 = 0xBFFFFFFF; /* 0165: l32r a10, 24 <wDev_Rxbuf_Init-0x38> (bfffffff <wDev_ProcessFiq+0xbfffff8b>) */ @0x24
  a9 = a9 & a10; /* 0168: and a9, a9, a10 */
  MEMW(); /* 016b: memw  */
  MEM32(a8 + 0) = a9; /* 016e: s32i.n a9, a8, 0 */
  MEMW(); /* 0170: memw  */
  a9 = MEM32(a8 + 0); /* 0173: l32i.n a9, a8, 0 */
  a10 = 0xDFFFFFFF; /* 0175: l32r a10, 28 <wDev_Rxbuf_Init-0x34> (dfffffff <wDev_ProcessFiq+0xdfffff8b>) */ @0x28
  a9 = a9 & a10; /* 0178: and a9, a9, a10 */
  MEMW(); /* 017b: memw  */
  MEM32(a8 + 0) = a9; /* 017e: s32i.n a9, a8, 0 */
  MEM32(a7 + 8) = a8; /* 0180: s32i.n a8, a7, 8 */
  a7 = a8; /* 0182: mov.n a7, a8 */
  a8 = a8 + (12); /* 0184: addi.n a8, a8, 12 */
L_186:;
  a9 = MEM32(a1 + 16); /* 0186: l32i.n a9, a1, 16 */
  if (a5 >= a9) goto L_18e; /* 0188: bge a5, a9, 18e <wDev_Rxbuf_Init+0x132> */
  goto L_dc; /* 018b: j dc <wDev_Rxbuf_Init+0x80> */
L_18e:;
  a4 = 0x0; /* 018e: movi.n a4, 0 */
  MEM32(a7 + 8) = a4; /* 0190: s32i.n a4, a7, 8 */
  a4 = MEM32(a1 + 8); /* 0192: l32i.n a4, a1, 8 */
  MEM32(a3 + 4) = a7; /* 0194: s32i.n a7, a3, 4 */
  MEM32(a3 + 0) = a4; /* 0196: s32i.n a4, a3, 0 */
L_198:;
  a14 = a5; /* 0198: mov.n a14, a5 */
  a12 = 0x3; /* 019a: movi.n a12, 3 */
  a11 = 0x1; /* 019c: movi.n a11, 1 */
  a10 = 0x6; /* 019e: movi.n a10, 6 */
  a13 = (uint32_t)&lit_rodata_wlog_info_33; /* 01a0: l32r a13, 2c <wDev_Rxbuf_Init-0x30> (0 <wDev_Rxbuf_Init-0x5c>) */ /* literal @0x2C: .rodata_wlog_info.33 */
  MEMW(); /* 01a3: memw  */
  a8 = (uint32_t)&wifi_log; /* 01a6: l32r a8, 4c <wDev_Rxbuf_Init-0x10> (0 <wDev_Rxbuf_Init-0x5c>) */ /* literal: GOT slot for wifi_log */
  wifi_log(a2, a3, a4, a5); /* call via literal slot */ /* 01a9: callx8 a8 */
  a12 = 0x3; /* 01ac: movi.n a12, 3 */
  a11 = 0x1; /* 01ae: movi.n a11, 1 */
  a10 = (uint32_t)&g_wifi_menuconfig; /* 01b0: l32r a10, 10 <wDev_Rxbuf_Init-0x4c> (0 <wDev_Rxbuf_Init-0x5c>) */ /* literal @0x10: g_wifi_menuconfig */
  a13 = (uint32_t)&lit_rodata_wlog_info_34; /* 01b3: l32r a13, 30 <wDev_Rxbuf_Init-0x2c> (0 <wDev_Rxbuf_Init-0x5c>) */ /* literal @0x30: .rodata_wlog_info.34 */
  a14 = MEM32(a10 + 4); /* 01b6: l32i.n a14, a10, 4 */
  a10 = 0x6; /* 01b8: movi.n a10, 6 */
  a8 = (uint32_t)&wifi_log; /* 01ba: l32r a8, 50 <wDev_Rxbuf_Init-0xc> (0 <wDev_Rxbuf_Init-0x5c>) */ /* literal: GOT slot for wifi_log */
  wifi_log(a2, a3, a4, a5); /* call via literal slot */ /* 01bd: callx8 a8 */
  if (a5 >= a2) goto L_1e4; /* 01c0: bgeu a5, a2, 1e4 <wDev_Rxbuf_Init+0x188> */
  a12 = 0x1; /* 01c3: movi.n a12, 1 */
  a13 = (uint32_t)&lit_rodata_wlog_error_35; /* 01c5: l32r a13, 34 <wDev_Rxbuf_Init-0x28> (0 <wDev_Rxbuf_Init-0x5c>) */ /* literal @0x34: .rodata_wlog_error.35 */
  a15 = a5; /* 01c8: mov.n a15, a5 */
  a14 = a2; /* 01ca: mov.n a14, a2 */
  a11 = 0x1; /* 01cc: or a11, a12, a12 */
  a10 = 0x6; /* 01cf: movi a10, 6 */
  a8 = (uint32_t)&wifi_log; /* 01d2: l32r a8, 54 <wDev_Rxbuf_Init-0x8> (0 <wDev_Rxbuf_Init-0x5c>) */ /* literal: GOT slot for wifi_log */
  wifi_log(a2, a3, a4, a5); /* call via literal slot */ /* 01d5: callx8 a8 */
  a8 = (uint32_t)&wDev_Rxbuf_Deinit; /* 01d8: l32r a8, 58 <wDev_Rxbuf_Init-0x4> (0 <wDev_Rxbuf_Init-0x5c>) */ /* literal: GOT slot for wDev_Rxbuf_Deinit */
  wDev_Rxbuf_Deinit(a2, a3, a4, a5); /* call via literal slot */ /* 01db: callx8 a8 */
L_1de:;
  a2 = 0x101; /* 01de: movi a2, 0x101 */
  goto L_249; /* 01e1: j 249 <wDev_Rxbuf_Init+0x1ed> */
L_1e4:;
  a2 = MEM32(a3 + 0); /* 01e4: l32i.n a2, a3, 0 */
  a7 = 0xFF000FFF; /* 01e6: l32r a7, 20 <wDev_Rxbuf_Init-0x3c> (ff000fff <wDev_ProcessFiq+0xff000f8b>) */ @0x20
  a6 = 0xDEADBEEF; /* 01e9: l32r a6, 38 <wDev_Rxbuf_Init-0x24> (deadbeef <wDev_ProcessFiq+0xdeadbe7b>) */ @0x38
  goto L_240; /* 01ec: j 240 <wDev_Rxbuf_Init+0x1e4> */
  /* 01ef: .byte 00 */
L_1f0:;
  MEMW(); /* 01f0: memw  */
  a4 = MEM32(a2 + 0); /* 01f3: l32i.n a4, a2, 0 */
  a8 = 0xFFFFFFFF; /* 01f5: movi.n a8, -1 */
  a4 = (a4 >> 0) & 0xFFF; /* 01f7: extui a4, a4, 0, 12 */
  a4 = a4 + (-4); /* 01fa: addi a4, a4, -4 */
  a8 = 0xFFFFF000; /* 01fd: slli a8, a8, 12 */
  MEMW(); /* 0200: memw  */
  a5 = MEM32(a2 + 0); /* 0203: l32i.n a5, a2, 0 */
  a4 = (a4 >> 0) & 0xFFF; /* 0205: extui a4, a4, 0, 12 */
  a5 = a5 & a8; /* 0208: and a5, a5, a8 */
  a4 = a5 | a4; /* 020b: or a4, a5, a4 */
  MEMW(); /* 020e: memw  */
  MEM32(a2 + 0) = a4; /* 0211: s32i.n a4, a2, 0 */
  MEMW(); /* 0213: memw  */
  a5 = MEM32(a2 + 0); /* 0216: l32i.n a5, a2, 0 */
  a5 = (a5 >> 0) & 0xFFF; /* 0218: extui a5, a5, 0, 12 */
  a5 = a5 << (12 & 31); /* 021b: slli a5, a5, 12 */
  MEMW(); /* 021e: memw  */
  a4 = MEM32(a2 + 0); /* 0221: l32i.n a4, a2, 0 */
  a4 = a4 & a7; /* 0223: and a4, a4, a7 */
  a4 = a4 | a5; /* 0226: or a4, a4, a5 */
  MEMW(); /* 0229: memw  */
  MEM32(a2 + 0) = a4; /* 022c: s32i.n a4, a2, 0 */
  a4 = MEM32(a2 + 4); /* 022e: l32i.n a4, a2, 4 */
  MEM32(a4 + 0) = a6; /* 0230: s32i.n a6, a4, 0 */
  MEMW(); /* 0232: memw  */
  a5 = MEM32(a2 + 0); /* 0235: l32i.n a5, a2, 0 */
  a5 = (a5 >> 0) & 0xFFF; /* 0237: extui a5, a5, 0, 12 */
  a4 = a4 + a5; /* 023a: add.n a4, a4, a5 */
  MEM32(a4 + 0) = a6; /* 023c: s32i.n a6, a4, 0 */
  a2 = MEM32(a2 + 8); /* 023e: l32i.n a2, a2, 8 */
L_240:;
  if (a2 != 0) goto L_1f0; /* 0240: bnez a2, 1f0 <wDev_Rxbuf_Init+0x194> */
  MEM8(a3 + 48) = a2; /* 0243: s8i a2, a3, 48 */
  MEMW(); /* 0246: memw  */
L_249:;
  MEMW(); /* 0249: memw  */
  return (int32_t)a2; /* 024c: retw.n  */
}

/* wDev_disable_low_rate @ wdev.o 00000004 size 11B bind GLOBAL
 * Calls: hal_mac_disable_low_rate | Data refs: hal_mac_disable_low_rate
 *   MMIO: none
 *   funcdb v3: 1 call(s), 1 ref(s); disasm: 1 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t wDev_disable_low_rate(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.wDev_disable_low_rate; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a8 = (uint32_t)&hal_mac_disable_low_rate; /* 0007: l32r a8, 0 <wDev_disable_low_rate-0x4> (0 <wDev_disable_low_rate-0x4>) */ /* literal: GOT slot for hal_mac_disable_low_rate */
  hal_mac_disable_low_rate(a2, a3, a4, a5); /* call via literal slot */ /* 000a: callx8 a8 */
  return (int32_t)a2; /* 000d: retw.n  */
}

/* wDev_enable_low_rate @ wdev.o 00000004 size 11B bind GLOBAL
 * Calls: hal_mac_enable_low_rate | Data refs: hal_mac_enable_low_rate
 *   MMIO: none
 *   funcdb v3: 1 call(s), 1 ref(s); disasm: 1 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t wDev_enable_low_rate(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.wDev_enable_low_rate; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a8 = (uint32_t)&hal_mac_enable_low_rate; /* 0007: l32r a8, 0 <wDev_enable_low_rate-0x4> (0 <wDev_enable_low_rate-0x4>) */ /* literal: GOT slot for hal_mac_enable_low_rate */
  hal_mac_enable_low_rate(a2, a3, a4, a5); /* call via literal slot */ /* 000a: callx8 a8 */
  return (int32_t)a2; /* 000d: retw.n  */
}

/* wDev_is_low_rate_enable @ wdev.o 00000004 size 13B bind GLOBAL
 * Calls: hal_mac_is_low_rate_enabled | Data refs: hal_mac_is_low_rate_enabled
 *   MMIO: none
 *   funcdb v3: 1 call(s), 1 ref(s); disasm: 1 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t wDev_is_low_rate_enable(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.wDev_is_low_rate_enable; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a8 = (uint32_t)&hal_mac_is_low_rate_enabled; /* 0007: l32r a8, 0 <wDev_is_low_rate_enable-0x4> (0 <wDev_is_low_rate_enable-0x4>) */ /* literal: GOT slot for hal_mac_is_low_rate_enabled */
  hal_mac_is_low_rate_enabled(a2, a3, a4, a5); /* call via literal slot */ /* 000a: callx8 a8 */
  a2 = a10; /* 000d: mov.n a2, a10 */
  return (int32_t)a2; /* 000f: retw.n  */
}

/* wdev_process_panic_watchdog @ wdev.o 0000001c size 118B bind GLOBAL
 * Calls: hal_mac_rx_get_end_state[got], bb_wdt_get_status[got], bb_wdt_timeout_clear[got], hal_mac_interrupt_clr_watchdog[got] | Data refs: hal_mac_rx_get_end_state, bb_wdt_get_status, bb_wdt_timeout_clear, hal_mac_interrupt_clr_watchdog
 *   MMIO: 0x3FF00024, 0x3FF40078
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 4 call(s), 4 data ref(s)
 * Fidelity: medium - 44 instr, 3 branches, calls resolved */
int32_t wdev_process_panic_watchdog(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .iram1.41; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_1c:;
  /* 001c: entry a1, 32 */
  a8 = (uint32_t)&hal_mac_rx_get_end_state; /* 001f: l32r a8, 4 <wdev_process_panic_watchdog-0x18> (0 <wdev_process_panic_watchdog-0x1c>) */ /* literal: GOT slot for hal_mac_rx_get_end_state */
  hal_mac_rx_get_end_state(a2, a3, a4, a5); /* call via literal slot */ /* 0022: callx8 a8 */
  a2 = a10; /* 0025: mov.n a2, a10 */
  a8 = (uint32_t)&bb_wdt_get_status; /* 0027: l32r a8, 8 <wdev_process_panic_watchdog-0x14> (0 <wdev_process_panic_watchdog-0x1c>) */ /* literal: GOT slot for bb_wdt_get_status */
  bb_wdt_get_status(a2, a3, a4, a5); /* call via literal slot */ /* 002a: callx8 a8 */
  a8 = 0x1; /* 002d: movi.n a8, 1 */
  a8 = 0x20000000; /* 002f: slli a8, a8, 29 */
  a8 = a10 & a8; /* 0032: and a8, a10, a8 */
  if (a8 != 0) goto L_81; /* 0035: bnez a8, 81 <wdev_process_panic_watchdog+0x65> */
  a8 = 0xF0; /* 0038: movi a8, 240 */
  a10 = a10 & a8; /* 003b: and a10, a10, a8 */
  if (a10 != 32) goto L_81; /* 003e: bnei a10, 32, 81 <wdev_process_panic_watchdog+0x65> */
  a2 = a2 + (-100); /* 0041: addi a2, a2, -100 */
  if (a2 != 0) goto L_81; /* 0044: bnez.n a2, 81 <wdev_process_panic_watchdog+0x65> */
  a9 = 0x3FF00024; /* 0046: l32r a9, 0 <wdev_process_panic_watchdog-0x1c> (3ff00024 <wDev_ProcessFiq+0x3fefffb0>) */ /* MMIO base */ @0x0
  a8 = 0x3FF00024; /* 0049: mov.n a8, a9 */
  a2 = 0x3FF40078; /* 004b: l32r a2, c <wdev_process_panic_watchdog-0x10> (3ff40078 <wDev_ProcessFiq+0x3ff40004>) */ /* MMIO base */ @0xC
  /* 004e: rsil a10, 3 */ /* UNMODELED: a10 clobbered */
  a2 = REG32(0x3FF40078); /* 0051: l32i.n a2, a2, 0 */ /* MMIO read: base 0x3FF40078+0 */
  a8 = REG32(0x3FF00024); /* 0053: l32i.n a8, a8, 0 */ /* MMIO read: base 0x3FF00024+0 */
  /* 0055: wsr.ps a10 */ /* UNMODELED: a10 clobbered */
  MEMW(); /* 0058: rsync  */
  a2 = 0x1; /* 005b: movi.n a2, 1 */
  a8 = a8 | a2; /* 005d: or a8, a8, a2 */
  MEMW(); /* 0060: memw  */
  REG32(0x3FF00024) = a8; /* 0063: s32i.n a8, a9, 0 */ /* MMIO write: base 0x3FF00024+0 */
  a8 = 0x3FF00024; /* 0065: mov.n a8, a9 */
  a2 = 0x3FF40078; /* 0067: l32r a2, 10 <wdev_process_panic_watchdog-0xc> (3ff40078 <wDev_ProcessFiq+0x3ff40004>) */ /* MMIO base */ @0x10
  /* 006a: rsil a10, 3 */ /* UNMODELED: a10 clobbered */
  a2 = REG32(0x3FF40078); /* 006d: l32i.n a2, a2, 0 */ /* MMIO read: base 0x3FF40078+0 */
  a8 = REG32(0x3FF00024); /* 006f: l32i.n a8, a8, 0 */ /* MMIO read: base 0x3FF00024+0 */
  /* 0071: wsr.ps a10 */ /* UNMODELED: a10 clobbered */
  MEMW(); /* 0074: rsync  */
  a2 = 0xFFFFFFFE; /* 0077: movi.n a2, -2 */
  a8 = a8 & a2; /* 0079: and a8, a8, a2 */
  MEMW(); /* 007c: memw  */
  REG32(0x3FF00024) = a8; /* 007f: s32i.n a8, a9, 0 */ /* MMIO write: base 0x3FF00024+0 */
L_81:;
  MEMW(); /* 0081: memw  */
  a8 = (uint32_t)&bb_wdt_timeout_clear; /* 0084: l32r a8, 14 <wdev_process_panic_watchdog-0x8> (0 <wdev_process_panic_watchdog-0x1c>) */ /* literal: GOT slot for bb_wdt_timeout_clear */
  bb_wdt_timeout_clear(a2, a3, a4, a5); /* call via literal slot */ /* 0087: callx8 a8 */
  a8 = (uint32_t)&hal_mac_interrupt_clr_watchdog; /* 008a: l32r a8, 18 <wdev_process_panic_watchdog-0x4> (0 <wdev_process_panic_watchdog-0x1c>) */ /* literal: GOT slot for hal_mac_interrupt_clr_watchdog */
  hal_mac_interrupt_clr_watchdog(a2, a3, a4, a5); /* call via literal slot */ /* 008d: callx8 a8 */
  return (int32_t)a2; /* 0090: retw.n  */
}

/* wDev_ProcessFiq @ wdev.o 00000074 size 414B bind GLOBAL
 * Calls: hal_mac_interrupt_get_event[got], hal_mac_interrupt_clr_event[got], wdev_process_panic_watchdog[got], pp_post[got], hal_mac_rx_get_end_info[got], hal_sniffer_rx_clr_statistics[got], wdev_push_promis_misc_buf[got], pp_post[got], lmacProcessRxSucData[got], lmacPostTxComplete[got], lmacProcessAllTxTimeout[got], lmacProcessCollisions[got] | Data refs: g_osi_funcs_p, hal_mac_interrupt_get_event, hal_mac_interrupt_clr_event, wdev_process_panic_watchdog, pp_post, wDevCtrl, .dram1.37, .dram1.38, hal_mac_rx_get_end_info, .dram1.40, hal_sniffer_rx_clr_statistics, .dram1.39, wdev_push_promis_misc_buf, lmacProcessRxSucData, lmacPostTxComplete, lmacProcessAllTxTimeout, lmacProcessCollisions
 *   MMIO: 0x6001C06C
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 12 call(s), 17 data ref(s)
 * Fidelity: medium - 150 instr, 25 branches, calls resolved */
int32_t wDev_ProcessFiq(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .iram1.42; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_74:;
  /* 0074: entry a1, 32 */
  a3 = (uint32_t)&g_osi_funcs_p; /* 0077: l32r a3, 0 <wDev_ProcessFiq-0x74> (0 <wDev_ProcessFiq-0x74>) */ /* literal @0x0: g_osi_funcs_p */
  a2 = MEM32(a3 + 0); /* 007a: l32i.n a2, a3, 0 */
  a2 = MEM32(a2 + 216); /* 007c: l32i a2, a2, 216 */
  ((int32_t(*)())a2)(a2, a3, a4, a5); /* 007f: callx8 a2 */ /* indirect */
L_82:;
  a8 = (uint32_t)&hal_mac_interrupt_get_event; /* 0082: l32r a8, 44 <wDev_ProcessFiq-0x30> (0 <wDev_ProcessFiq-0x74>) */ /* literal: GOT slot for hal_mac_interrupt_get_event */
  hal_mac_interrupt_get_event(a2, a3, a4, a5); /* call via literal slot */ /* 0085: callx8 a8 */
  a2 = a10 | a10; /* 0088: or a2, a10, a10 */
  if (a10 == 0) goto L_208; /* 008b: beqz a10, 208 <wDev_ProcessFiq+0x194> */
  a8 = (uint32_t)&hal_mac_interrupt_clr_event; /* 008e: l32r a8, 48 <wDev_ProcessFiq-0x2c> (0 <wDev_ProcessFiq-0x74>) */ /* literal: GOT slot for hal_mac_interrupt_clr_event */
  hal_mac_interrupt_clr_event(a2, a3, a4, a5); /* call via literal slot */ /* 0091: callx8 a8 */
  if (!((a2 >> 11) & 1)) goto L_9d; /* 0094: bbci a2, 11, 9d <wDev_ProcessFiq+0x29> */
  a8 = (uint32_t)&wdev_process_panic_watchdog; /* 0097: l32r a8, 4c <wDev_ProcessFiq-0x28> (0 <wDev_ProcessFiq-0x74>) */ /* literal: GOT slot for wdev_process_panic_watchdog */
  wdev_process_panic_watchdog(a2, a3, a4, a5); /* call via literal slot */ /* 009a: callx8 a8 */
L_9d:;
  a4 = 0x3; /* 009d: movi.n a4, 3 */
  a4 = 0x600000; /* 009f: slli a4, a4, 21 */
  if ((a2 & a4) == 0) goto L_b0; /* 00a2: bnone a2, a4, b0 <wDev_ProcessFiq+0x3c> */
  a11 = 0x1; /* 00a5: movi a11, 1 */
  a10 = 0xE; /* 00a8: movi.n a10, 14 */
  a8 = (uint32_t)&pp_post; /* 00aa: l32r a8, 50 <wDev_ProcessFiq-0x24> (0 <wDev_ProcessFiq-0x74>) */ /* literal: GOT slot for pp_post */
  pp_post(a2, a3, a4, a5); /* call via literal slot */ /* 00ad: callx8 a8 */
L_b0:;
  a4 = 0x1000024; /* 00b0: l32r a4, 4 <wDev_ProcessFiq-0x70> (1000024 <wDev_ProcessFiq+0xffffb0>) */ @0x4
  if ((a2 & a4) != 0) goto L_b9; /* 00b3: bany a2, a4, b9 <wDev_ProcessFiq+0x45> */
  goto L_1e7; /* 00b6: j 1e7 <wDev_ProcessFiq+0x173> */
L_b9:;
  a4 = (uint32_t)&wDevCtrl; /* 00b9: l32r a4, 8 <wDev_ProcessFiq-0x6c> (0 <wDev_ProcessFiq-0x74>) */ /* literal @0x8: wDevCtrl */
  a5 = MEM8(a4 + 48); /* 00bc: l8ui a5, a4, 48 */
  if (a5 == 0) goto L_1e1; /* 00bf: beqz a5, 1e1 <wDev_ProcessFiq+0x16d> */
  a4 = MEM32(a4 + 52); /* 00c2: l32i.n a4, a4, 52 */
  if ((a4 >> 3) & 1) goto L_ca; /* 00c4: bbsi a4, 3, ca <wDev_ProcessFiq+0x56> */
  goto L_1e1; /* 00c7: j 1e1 <wDev_ProcessFiq+0x16d> */
L_ca:;
  a7 = (uint32_t)&dram1_37; /* 00ca: l32r a7, 18 <wDev_ProcessFiq-0x5c> (0 <wDev_ProcessFiq-0x74>) */ /* literal @0x18: .dram1.37 */
  a12 = a7; /* 00cd: mov.n a12, a7 */
  a5 = (uint32_t)&dram1_37; /* 00cf: l32r a5, 14 <wDev_ProcessFiq-0x60> (c <wDev_ProcessFiq-0x68>) */ /* literal @0x14: .dram1.37 */
  a13 = a5; /* 00d2: mov.n a13, a5 */
  a4 = (uint32_t)&dram1_38; /* 00d4: l32r a4, 1c <wDev_ProcessFiq-0x58> (4 <wDev_ProcessFiq-0x70>) */ /* literal @0x1C: .dram1.38 */
  a11 = a4 | a4; /* 00d7: or a11, a4, a4 */
  a6 = (uint32_t)&dram1_38; /* 00da: l32r a6, 20 <wDev_ProcessFiq-0x54> (0 <wDev_ProcessFiq-0x74>) */ /* literal @0x20: .dram1.38 */
  a10 = a6 | a6; /* 00dd: or a10, a6, a6 */
  a15 = (uint32_t)&dram1_37; /* 00e0: l32r a15, c <wDev_ProcessFiq-0x68> (4 <wDev_ProcessFiq-0x70>) */ /* literal @0xC: .dram1.37 */
  a14 = (uint32_t)&dram1_37; /* 00e3: l32r a14, 10 <wDev_ProcessFiq-0x64> (8 <wDev_ProcessFiq-0x6c>) */ /* literal @0x10: .dram1.37 */
  a8 = (uint32_t)&hal_mac_rx_get_end_info; /* 00e6: l32r a8, 54 <wDev_ProcessFiq-0x20> (0 <wDev_ProcessFiq-0x74>) */ /* literal: GOT slot for hal_mac_rx_get_end_info */
  hal_mac_rx_get_end_info(a2, a3, a4, a5); /* call via literal slot */ /* 00e9: callx8 a8 */
  a10 = 0x62; /* 00ec: movi a10, 98 */
  a8 = 0x6001C06C; /* 00ef: l32r a8, 24 <wDev_ProcessFiq-0x50> (6001c06c <wDev_ProcessFiq+0x6001bff8>) */ /* MMIO base */ @0x24
  a7 = MEM32(a7 + 0); /* 00f2: l32i.n a7, a7, 0 */
  MEMW(); /* 00f4: memw  */
  a8 = REG32(0x6001C06C); /* 00f7: l32i.n a8, a8, 0 */ /* MMIO read: base 0x6001C06C+0 */
  if (a7 == a10) goto L_ff; /* 00f9: beq a7, a10, ff <wDev_ProcessFiq+0x8b> */
  goto L_1e1; /* 00fc: j 1e1 <wDev_ProcessFiq+0x16d> */
L_ff:;
  a7 = (uint32_t)&dram1_40; /* 00ff: l32r a7, 28 <wDev_ProcessFiq-0x4c> (0 <wDev_ProcessFiq-0x74>) */ /* literal @0x28: .dram1.40 */
  a10 = MEM8(a7 + 0); /* 0102: l8ui a10, a7, 0 */
  a6 = MEM32(a6 + 0); /* 0105: l32i.n a6, a6, 0 */
  if (a10 != 0) goto L_120; /* 0107: bnez.n a10, 120 <wDev_ProcessFiq+0xac> */
  a4 = MEM32(a4 + 0); /* 0109: l32i.n a4, a4, 0 */
  if (a4 == a6) goto L_111; /* 010b: beq a4, a6, 111 <wDev_ProcessFiq+0x9d> */
  goto L_132; /* 010e: j 132 <wDev_ProcessFiq+0xbe> */
L_111:;
  a4 = 0x1; /* 0111: movi.n a4, 1 */
  MEM8(a7 + 0) = a4; /* 0113: s8i a4, a7, 0 */
  MEMW(); /* 0116: memw  */
  MEMW(); /* 0119: memw  */
  goto L_1e1; /* 011c: j 1e1 <wDev_ProcessFiq+0x16d> */
  /* 011f: .byte 00 */
L_120:;
  a10 = 0xFFFFFFEF; /* 0120: movi.n a10, -17 */
  if (a10 < a6) goto L_12a; /* 0122: bltu a10, a6, 12a <wDev_ProcessFiq+0xb6> */
  a9 = MEM32(a4 + 0); /* 0125: l32i.n a9, a4, 0 */
  if (a9 >= a6) goto L_141; /* 0127: bgeu a9, a6, 141 <wDev_ProcessFiq+0xcd> */
L_12a:;
  a4 = 0x0; /* 012a: movi.n a4, 0 */
  MEM8(a7 + 0) = a4; /* 012c: s8i a4, a7, 0 */
  MEMW(); /* 012f: memw  */
L_132:;
  MEMW(); /* 0132: memw  */
  a8 = (uint32_t)&hal_sniffer_rx_clr_statistics; /* 0135: l32r a8, 58 <wDev_ProcessFiq-0x1c> (0 <wDev_ProcessFiq-0x74>) */ /* literal: GOT slot for hal_sniffer_rx_clr_statistics */
  hal_sniffer_rx_clr_statistics(a2, a3, a4, a5); /* call via literal slot */ /* 0138: callx8 a8 */
  goto L_1e1; /* 013b: j 1e1 <wDev_ProcessFiq+0x16d> */
  /* 013e: .byte 00 */
  /* 013f: .byte 00 */
  /* 0140: .byte 00 */
L_141:;
  if (a9 == a6) goto L_147; /* 0141: beq a9, a6, 147 <wDev_ProcessFiq+0xd3> */
  goto L_1e1; /* 0144: j 1e1 <wDev_ProcessFiq+0x16d> */
L_147:;
  a10 = (uint32_t)&dram1_39; /* 0147: l32r a10, 2c <wDev_ProcessFiq-0x48> (0 <wDev_ProcessFiq-0x74>) */ /* literal @0x2C: .dram1.39 */
  a7 = MEM32(a5 + 0); /* 014a: l32i.n a7, a5, 0 */
  a5 = (a7 >> 16) & 0xFFFF; /* 014c: extui a5, a7, 16, 16 */
  a9 = a5 << (8 & 31); /* 014f: slli a9, a5, 8 */
  a6 = MEM32(a10 + 4); /* 0152: l32i.n a6, a10, 4 */
  a11 = 0xFF0000FF; /* 0154: l32r a11, 30 <wDev_ProcessFiq-0x44> (ff0000ff <wDev_ProcessFiq+0xff00008b>) */ @0x30
  a6 = a6 & a11; /* 0157: and a6, a6, a11 */
  a6 = a6 | a9; /* 015a: or a6, a6, a9 */
  a9 = 0xFFF; /* 015d: l32r a9, 34 <wDev_ProcessFiq-0x40> (fff <wDev_ProcessFiq+0xf8b>) */ @0x34
  MEM32(a10 + 4) = a6; /* 0160: s32i.n a6, a10, 4 */
  if (a9 < a5) goto L_1e1; /* 0162: bltu a9, a5, 1e1 <wDev_ProcessFiq+0x16d> */
  a8 = a8 >> (8 & 31); /* 0165: srli a8, a8, 8 */
  a5 = (a5 >> 0) & 0xFFF; /* 0168: extui a5, a5, 0, 12 */
  a4 = (uint32_t)&dram1_37; /* 016b: l32r a4, c <wDev_ProcessFiq-0x68> (4 <wDev_ProcessFiq-0x70>) */ /* literal @0xC: .dram1.37 */
  MEM8(a10 + 0) = a8; /* 016e: s8i a8, a10, 0 */
  MEMW(); /* 0171: memw  */
  a8 = MEM32(a4 + 0); /* 0174: l32i.n a8, a4, 0 */
  a4 = (uint32_t)&dram1_37; /* 0176: l32r a4, 10 <wDev_ProcessFiq-0x64> (8 <wDev_ProcessFiq-0x6c>) */ /* literal @0x10: .dram1.37 */
  a9 = MEM32(a4 + 0); /* 0179: l32i.n a9, a4, 0 */
  a9 = (a9 >> 30) & 0x3; /* 017b: extui a9, a9, 30, 2 */
  a9 = a9 << (14 & 31); /* 017e: slli a9, a9, 14 */
  a4 = MEM32(a10 + 0); /* 0181: l32i.n a4, a10, 0 */
  a11 = 0xFFFF3FFF; /* 0183: l32r a11, 38 <wDev_ProcessFiq-0x3c> (ffff3fff <wDev_ProcessFiq+0xffff3f8b>) */ @0x38
  a4 = a4 & a11; /* 0186: and a4, a4, a11 */
  a4 = a4 | a9; /* 0189: or a4, a4, a9 */
  MEM32(a10 + 0) = a4; /* 018c: s32i.n a4, a10, 0 */
  a4 = a7 >> (15 & 31); /* 018e: srli a4, a7, 15 */
  a4 = a4 << (7 & 31); /* 0191: slli a4, a4, 7 */
  a7 = (a7 >> 8) & 0x7F; /* 0194: extui a7, a7, 8, 7 */
  a4 = (a4 >> 0) & 0xFF; /* 0197: extui a4, a4, 0, 8 */
  a4 = a4 | a7; /* 019a: or a4, a4, a7 */
  a7 = a8 << (26 & 31); /* 019d: slli a7, a8, 26 */
  a8 = 0x1; /* 01a0: movi.n a8, 1 */
  a8 = 0x8000000; /* 01a2: slli a8, a8, 27 */
  a7 = a7 & a8; /* 01a5: and a7, a7, a8 */
  a4 = a4 | a7; /* 01a8: or a4, a4, a7 */
  a7 = 0xF7FFFF00; /* 01ab: l32r a7, 3c <wDev_ProcessFiq-0x38> (f7ffff00 <wDev_ProcessFiq+0xf7fffe8c>) */ @0x3C
  a6 = a6 & a7; /* 01ae: and a6, a6, a7 */
  a4 = a4 | a6; /* 01b1: or a4, a4, a6 */
  MEM32(a10 + 4) = a4; /* 01b4: s32i.n a4, a10, 4 */
  a4 = 0x31; /* 01b6: movi.n a4, 49 */
  a4 = 0x62000000; /* 01b8: slli a4, a4, 25 */
  a5 = a5 | a4; /* 01bb: or a5, a5, a4 */
  a6 = 0xFFF000; /* 01be: l32r a6, 40 <wDev_ProcessFiq-0x34> (fff000 <wDev_ProcessFiq+0xffef8c>) */ @0x40
  a4 = MEM32(a10 + 24); /* 01c1: l32i a4, a10, 24 */
  a4 = a4 & a6; /* 01c4: and a4, a4, a6 */
  a5 = a5 | a4; /* 01c7: or a5, a5, a4 */
  MEM32(a10 + 24) = a5; /* 01ca: s32i a5, a10, 24 */
  MEMW(); /* 01cd: memw  */
  a8 = (uint32_t)&wdev_push_promis_misc_buf; /* 01d0: l32r a8, 5c <wDev_ProcessFiq-0x18> (0 <wDev_ProcessFiq-0x74>) */ /* literal: GOT slot for wdev_push_promis_misc_buf */
  wdev_push_promis_misc_buf(a2, a3, a4, a5); /* call via literal slot */ /* 01d3: callx8 a8 */
  a11 = 0x0; /* 01d6: movi.n a11, 0 */
  a10 = 0x1A; /* 01d8: movi a10, 26 */
  a8 = (uint32_t)&pp_post; /* 01db: l32r a8, 60 <wDev_ProcessFiq-0x14> (0 <wDev_ProcessFiq-0x74>) */ /* literal: GOT slot for pp_post */
  pp_post(a2, a3, a4, a5); /* call via literal slot */ /* 01de: callx8 a8 */
L_1e1:;
  a8 = (uint32_t)&lmacProcessRxSucData; /* 01e1: l32r a8, 64 <wDev_ProcessFiq-0x10> (0 <wDev_ProcessFiq-0x74>) */ /* literal: GOT slot for lmacProcessRxSucData */
  lmacProcessRxSucData(a2, a3, a4, a5); /* call via literal slot */ /* 01e4: callx8 a8 */
L_1e7:;
  if (!((a2 >> 7) & 1)) goto L_1f0; /* 01e7: bbci a2, 7, 1f0 <wDev_ProcessFiq+0x17c> */
  a8 = (uint32_t)&lmacPostTxComplete; /* 01ea: l32r a8, 68 <wDev_ProcessFiq-0xc> (0 <wDev_ProcessFiq-0x74>) */ /* literal: GOT slot for lmacPostTxComplete */
  lmacPostTxComplete(a2, a3, a4, a5); /* call via literal slot */ /* 01ed: callx8 a8 */
L_1f0:;
  if (!((a2 >> 19) & 1)) goto L_1f9; /* 01f0: bbci a2, 19, 1f9 <wDev_ProcessFiq+0x185> */
  a8 = (uint32_t)&lmacProcessAllTxTimeout; /* 01f3: l32r a8, 6c <wDev_ProcessFiq-0x8> (0 <wDev_ProcessFiq-0x74>) */ /* literal: GOT slot for lmacProcessAllTxTimeout */
  lmacProcessAllTxTimeout(a2, a3, a4, a5); /* call via literal slot */ /* 01f6: callx8 a8 */
L_1f9:;
  if ((a2 >> 8) & 1) goto L_1ff; /* 01f9: bbsi a2, 8, 1ff <wDev_ProcessFiq+0x18b> */
  goto L_82; /* 01fc: j 82 <wDev_ProcessFiq+0xe> */
L_1ff:;
  a8 = (uint32_t)&lmacProcessCollisions; /* 01ff: l32r a8, 70 <wDev_ProcessFiq-0x4> (0 <wDev_ProcessFiq-0x74>) */ /* literal: GOT slot for lmacProcessCollisions */
  lmacProcessCollisions(a2, a3, a4, a5); /* call via literal slot */ /* 0202: callx8 a8 */
  goto L_82; /* 0205: j 82 <wDev_ProcessFiq+0xe> */
L_208:;
  a2 = MEM32(a3 + 0); /* 0208: l32i.n a2, a3, 0 */
  a2 = MEM32(a2 + 220); /* 020a: l32i a2, a2, 220 */
  ((int32_t(*)())a2)(a2, a3, a4, a5); /* 020d: callx8 a2 */ /* indirect */
  return (int32_t)a2; /* 0210: retw.n  */
}

/* wdev_record_rx_linked_list @ wdev.o 00000024 size 113B bind GLOBAL
 * Calls: none | Data refs: g_osi_funcs_p, s_record_list, wDevCtrl
 *   MMIO: 0x3FF73088, 0x3FF73090, 0x3FF7308C, 0x3FF73098, 0x3FF732F4, 0x3FF732FC
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 3 data ref(s)
 * Fidelity: medium - 44 instr, 1 branches, calls resolved */
int32_t wdev_record_rx_linked_list(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .iram1.44; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_24:;
  /* 0024: entry a1, 32 */
  if (a2 >= 3) goto L_90; /* 0027: bgeui a2, 3, 90 <wdev_record_rx_linked_list+0x6c> */
  a8 = (uint32_t)&g_osi_funcs_p; /* 002a: l32r a8, 0 <wdev_record_rx_linked_list-0x24> (0 <wdev_record_rx_linked_list-0x24>) */ /* literal @0x0: g_osi_funcs_p */
  a8 = MEM32(a8 + 0); /* 002d: l32i.n a8, a8, 0 */
  a10 = MEM32(a8 + 272); /* 002f: l32i a10, a8, 0x110 */
  ((int32_t(*)())a10)(a2, a3, a4, a5); /* 0032: callx8 a10 */ /* indirect */
  a8 = (a2 << 4) + a2; /* 0035: addx4 a8, a2, a2 */
  a8 = (a8 << 2) + a2; /* 0038: addx2 a8, a8, a2 */
  a2 = (uint32_t)&s_record_list; /* 003b: l32r a2, 4 <wdev_record_rx_linked_list-0x20> (0 <wdev_record_rx_linked_list-0x24>) */ /* literal @0x4: s_record_list */
  a8 = (a8 << 4) + a2; /* 003e: addx4 a8, a8, a2 */
  a2 = 0x3FF73088; /* 0041: l32r a2, 8 <wdev_record_rx_linked_list-0x1c> (3ff73088 <wDev_ProcessFiq+0x3ff73014>) */ /* MMIO base */ @0x8
  MEM32(a8 + 0) = a10; /* 0044: s32i.n a10, a8, 0 */
  MEMW(); /* 0046: memw  */
  a2 = REG32(0x3FF73088); /* 0049: l32i.n a2, a2, 0 */ /* MMIO read: base 0x3FF73088+0 */
  MEM32(a8 + 4) = a2; /* 004b: s32i.n a2, a8, 4 */
  a2 = 0x3FF73090; /* 004d: l32r a2, c <wdev_record_rx_linked_list-0x18> (3ff73090 <wDev_ProcessFiq+0x3ff7301c>) */ /* MMIO base */ @0xC
  MEMW(); /* 0050: memw  */
  a2 = REG32(0x3FF73090); /* 0053: l32i.n a2, a2, 0 */ /* MMIO read: base 0x3FF73090+0 */
  MEM32(a8 + 8) = a2; /* 0055: s32i.n a2, a8, 8 */
  a2 = 0x3FF7308C; /* 0057: l32r a2, 10 <wdev_record_rx_linked_list-0x14> (3ff7308c <wDev_ProcessFiq+0x3ff73018>) */ /* MMIO base */ @0x10
  MEMW(); /* 005a: memw  */
  a2 = REG32(0x3FF7308C); /* 005d: l32i.n a2, a2, 0 */ /* MMIO read: base 0x3FF7308C+0 */
  MEM32(a8 + 12) = a2; /* 005f: s32i.n a2, a8, 12 */
  a2 = 0x3FF73098; /* 0061: l32r a2, 14 <wdev_record_rx_linked_list-0x10> (3ff73098 <wDev_ProcessFiq+0x3ff73024>) */ /* MMIO base */ @0x14
  MEMW(); /* 0064: memw  */
  a2 = REG32(0x3FF73098); /* 0067: l32i.n a2, a2, 0 */ /* MMIO read: base 0x3FF73098+0 */
  MEM32(a8 + 20) = a2; /* 0069: s32i.n a2, a8, 20 */
  a2 = (uint32_t)&wDevCtrl; /* 006b: l32r a2, 18 <wdev_record_rx_linked_list-0xc> (0 <wdev_record_rx_linked_list-0x24>) */ /* literal @0x18: wDevCtrl */
  a9 = MEM32(a2 + 0); /* 006e: l32i.n a9, a2, 0 */
  a2 = MEM32(a2 + 4); /* 0070: l32i.n a2, a2, 4 */
  MEM32(a8 + 28) = a2; /* 0072: s32i.n a2, a8, 28 */
  a2 = MEM32(a2 + 8); /* 0074: l32i.n a2, a2, 8 */
  MEM32(a8 + 32) = a2; /* 0076: s32i.n a2, a8, 32 */
  a2 = 0x3FF732F4; /* 0078: l32r a2, 1c <wdev_record_rx_linked_list-0x8> (3ff732f4 <wDev_ProcessFiq+0x3ff73280>) */ /* MMIO base */ @0x1C
  MEM32(a8 + 24) = a9; /* 007b: s32i.n a9, a8, 24 */
  MEMW(); /* 007d: memw  */
  a2 = REG32(0x3FF732F4); /* 0080: l32i.n a2, a2, 0 */ /* MMIO read: base 0x3FF732F4+0 */
  MEM32(a8 + 36) = a2; /* 0082: s32i.n a2, a8, 36 */
  a2 = 0x3FF732FC; /* 0084: l32r a2, 20 <wdev_record_rx_linked_list-0x4> (3ff732fc <wDev_ProcessFiq+0x3ff73288>) */ /* MMIO base */ @0x20
  MEMW(); /* 0087: memw  */
  a2 = REG32(0x3FF732FC); /* 008a: l32i a2, a2, 0 */ /* MMIO read: base 0x3FF732FC+0 */
  MEM32(a8 + 40) = a2; /* 008d: s32i a2, a8, 40 */
L_90:;
  MEMW(); /* 0090: memw  */
  return (int32_t)a2; /* 0093: retw.n  */
}

/* wdev_dump_rx_linked_list @ wdev.o 00000020 size 121B bind GLOBAL
 * Calls: wdev_record_rx_linked_list[got], wifi_log[got], wifi_log[got], wifi_log[got] | Data refs: wdev_record_rx_linked_list, .rodata_wlog_info.46, wifi_log, s_record_list, .rodata_wlog_info.47, .rodata_wlog_info.48
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 4 call(s), 6 data ref(s)
 * Fidelity: medium - 50 instr, 1 branches, calls resolved */
int32_t wdev_dump_rx_linked_list(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .iram1.45; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_20:;
  /* 0020: entry a1, 48 */
  a10 = 0x2; /* 0023: movi a10, 2 */
  a8 = (uint32_t)&wdev_record_rx_linked_list; /* 0026: l32r a8, 10 <wdev_dump_rx_linked_list-0x10> (0 <wdev_dump_rx_linked_list-0x20>) */ /* literal: GOT slot for wdev_record_rx_linked_list */
  wdev_record_rx_linked_list(a2, a3, a4, a5); /* call via literal slot */ /* 0029: callx8 a8 */
  a13 = (uint32_t)&lit_rodata_wlog_info_46; /* 002c: l32r a13, 0 <wdev_dump_rx_linked_list-0x20> (0 <wdev_dump_rx_linked_list-0x20>) */ /* literal @0x0: .rodata_wlog_info.46 */
  a15 = a3; /* 002f: mov.n a15, a3 */
  a14 = a2; /* 0031: mov.n a14, a2 */
  a12 = 0x3; /* 0033: movi.n a12, 3 */
  a11 = 0x20; /* 0035: movi a11, 32 */
  a10 = 0x1; /* 0038: movi.n a10, 1 */
  a8 = (uint32_t)&wifi_log; /* 003a: l32r a8, 14 <wdev_dump_rx_linked_list-0xc> (0 <wdev_dump_rx_linked_list-0x20>) */ /* literal: GOT slot for wifi_log */
  wifi_log(a2, a3, a4, a5); /* call via literal slot */ /* 003d: callx8 a8 */
  a2 = (uint32_t)&s_record_list; /* 0040: l32r a2, 4 <wdev_dump_rx_linked_list-0x1c> (0 <wdev_dump_rx_linked_list-0x20>) */ /* literal @0x4: s_record_list */
  a3 = 0x84; /* 0043: movi a3, 132 */
  a3 = a2 + a3; /* 0046: add.n a3, a2, a3 */
L_48:;
  a12 = 0x3; /* 0048: movi.n a12, 3 */
  a11 = 0x20; /* 004a: movi.n a11, 32 */
  a8 = MEM32(a2 + 20); /* 004c: l32i.n a8, a2, 20 */
  a10 = 0x1; /* 004e: movi.n a10, 1 */
  MEM32(a1 + 12) = a8; /* 0050: s32i.n a8, a1, 12 */
  a8 = MEM32(a2 + 16); /* 0052: l32i.n a8, a2, 16 */
  MEM32(a1 + 8) = a8; /* 0054: s32i.n a8, a1, 8 */
  a8 = MEM32(a2 + 12); /* 0056: l32i.n a8, a2, 12 */
  MEM32(a1 + 4) = a8; /* 0058: s32i.n a8, a1, 4 */
  a8 = MEM32(a2 + 8); /* 005a: l32i.n a8, a2, 8 */
  MEM32(a1 + 0) = a8; /* 005c: s32i.n a8, a1, 0 */
  a15 = MEM32(a2 + 4); /* 005e: l32i.n a15, a2, 4 */
  a14 = MEM32(a2 + 0); /* 0060: l32i.n a14, a2, 0 */
  a13 = (uint32_t)&lit_rodata_wlog_info_47; /* 0062: l32r a13, 8 <wdev_dump_rx_linked_list-0x18> (0 <wdev_dump_rx_linked_list-0x20>) */ /* literal @0x8: .rodata_wlog_info.47 */
  MEMW(); /* 0065: memw  */
  a8 = (uint32_t)&wifi_log; /* 0068: l32r a8, 18 <wdev_dump_rx_linked_list-0x8> (0 <wdev_dump_rx_linked_list-0x20>) */ /* literal: GOT slot for wifi_log */
  wifi_log(a2, a3, a4, a5); /* call via literal slot */ /* 006b: callx8 a8 */
  a12 = 0x3; /* 006e: movi.n a12, 3 */
  a11 = 0x20; /* 0070: movi.n a11, 32 */
  a8 = MEM32(a2 + 40); /* 0072: l32i.n a8, a2, 40 */
  a10 = 0x1; /* 0074: movi.n a10, 1 */
  MEM32(a1 + 8) = a8; /* 0076: s32i.n a8, a1, 8 */
  a8 = MEM32(a2 + 36); /* 0078: l32i.n a8, a2, 36 */
  MEM32(a1 + 4) = a8; /* 007a: s32i.n a8, a1, 4 */
  a8 = MEM32(a2 + 32); /* 007c: l32i.n a8, a2, 32 */
  MEM32(a1 + 0) = a8; /* 007e: s32i.n a8, a1, 0 */
  a15 = MEM32(a2 + 28); /* 0080: l32i.n a15, a2, 28 */
  a14 = MEM32(a2 + 24); /* 0082: l32i a14, a2, 24 */
  a2 = a2 + (44); /* 0085: addi a2, a2, 44 */
  a13 = (uint32_t)&lit_rodata_wlog_info_48; /* 0088: l32r a13, c <wdev_dump_rx_linked_list-0x14> (0 <wdev_dump_rx_linked_list-0x20>) */ /* literal @0xC: .rodata_wlog_info.48 */
  MEMW(); /* 008b: memw  */
  a8 = (uint32_t)&wifi_log; /* 008e: l32r a8, 1c <wdev_dump_rx_linked_list-0x4> (0 <wdev_dump_rx_linked_list-0x20>) */ /* literal: GOT slot for wifi_log */
  wifi_log(a2, a3, a4, a5); /* call via literal slot */ /* 0091: callx8 a8 */
  if (a2 != a3) goto L_48; /* 0094: bne a2, a3, 48 <wdev_dump_rx_linked_list+0x28> */
  return (int32_t)a2; /* 0097: retw.n  */
}

/* wDev_AppendRxBlocks @ wdev.o 00000050 size 296B bind GLOBAL
 * Calls: wifi_assert[got], wdev_record_rx_linked_list[got], hal_mac_rx_set_dscr_reload[got], wdev_record_rx_linked_list[got], wdev_dump_rx_linked_list[got], hal_mac_rx_is_dscr_reload[got], hal_mac_rx_read_rxdscrnext[got], hal_mac_rx_get_last_dscr[got], hal_mac_rx_set_base[got] | Data refs: .rodata.__FUNCTION__$1, .rodata.str1.1, wifi_assert, wDevCtrl, g_osi_funcs_p, g_intr_lock_mux, wdev_record_rx_linked_list, hal_mac_rx_set_dscr_reload, wdev_dump_rx_linked_list, hal_mac_rx_is_dscr_reload, hal_mac_rx_read_rxdscrnext, hal_mac_rx_get_last_dscr, hal_mac_rx_set_base
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 9 call(s), 13 data ref(s)
 * Fidelity: medium - 116 instr, 11 branches, calls resolved */
int32_t wDev_AppendRxBlocks(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .wifislprxiram.49; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_50:;
  /* 0050: entry a1, 48 */
  a13 = 0xD23; /* 0053: l32r a13, 4 <wDev_AppendRxBlocks-0x4c> (d23 <wDev_ProcessFiq+0xcaf>) */ @0x4
  a4 = 0x0; /* 0056: movi.n a4, 0 */
  a10 = 0x1; /* 0058: movi.n a10, 1 */
  if (a2 == 0) a10 = a4; /* 005a: moveqz a10, a4, a2 */
  a4 = a2 | a2; /* 005d: or a4, a2, a2 */
  a12 = (uint32_t)&lit_rodata_FUNCTION_1; /* 0060: l32r a12, 8 <wDev_AppendRxBlocks-0x48> (0 <wDev_AppendRxBlocks-0x50>) */ /* literal @0x8: .rodata.__FUNCTION__$1 */
  a11 = (uint32_t)&lit_rodata_str1_1; /* 0063: l32r a11, c <wDev_AppendRxBlocks-0x44> (0 <wDev_AppendRxBlocks-0x50>) */ /* literal @0xC: .rodata.str1.1 */
  a8 = (uint32_t)&wifi_assert; /* 0066: l32r a8, 2c <wDev_AppendRxBlocks-0x24> (0 <wDev_AppendRxBlocks-0x50>) */ /* literal: GOT slot for wifi_assert */
  wifi_assert(a2, a3, a4, a5); /* call via literal slot */ /* 0069: callx8 a8 */
  a11 = 0xBFFFFFFF; /* 006c: l32r a11, 10 <wDev_AppendRxBlocks-0x40> (bfffffff <wDev_ProcessFiq+0xbfffff8b>) */ @0x10
  a12 = 0xDFFFFFFF; /* 006f: l32r a12, 14 <wDev_AppendRxBlocks-0x3c> (dfffffff <wDev_ProcessFiq+0xdfffff8b>) */ @0x14
  a13 = 0xFF000FFF; /* 0072: l32r a13, 18 <wDev_AppendRxBlocks-0x38> (ff000fff <wDev_ProcessFiq+0xff000f8b>) */ @0x18
  a10 = 0xDEADBEEF; /* 0075: l32r a10, 1c <wDev_AppendRxBlocks-0x34> (deadbeef <wDev_ProcessFiq+0xdeadbe7b>) */ @0x1C
  goto L_d5; /* 0078: j d5 <wDev_AppendRxBlocks+0x85> */
  /* 007b: .byte 00 */
L_7c:;
  MEMW(); /* 007c: memw  */
  a5 = MEM32(a4 + 0); /* 007f: l32i.n a5, a4, 0 */
  a8 = 0xFFFFFFFF; /* 0081: movi.n a8, -1 */
  a8 = 0x80000000; /* 0083: slli a8, a8, 31 */
  a5 = a5 | a8; /* 0086: or a5, a5, a8 */
  MEMW(); /* 0089: memw  */
  MEM32(a4 + 0) = a5; /* 008c: s32i.n a5, a4, 0 */
  MEMW(); /* 008e: memw  */
  a5 = MEM32(a4 + 0); /* 0091: l32i.n a5, a4, 0 */
  a5 = a5 & a11; /* 0093: and a5, a5, a11 */
  MEMW(); /* 0096: memw  */
  MEM32(a4 + 0) = a5; /* 0099: s32i.n a5, a4, 0 */
  MEMW(); /* 009b: memw  */
  a5 = MEM32(a4 + 0); /* 009e: l32i.n a5, a4, 0 */
  a5 = a5 & a12; /* 00a0: and a5, a5, a12 */
  MEMW(); /* 00a3: memw  */
  MEM32(a4 + 0) = a5; /* 00a6: s32i.n a5, a4, 0 */
  MEMW(); /* 00a8: memw  */
  a9 = MEM32(a4 + 0); /* 00ab: l32i.n a9, a4, 0 */
  a9 = (a9 >> 0) & 0xFFF; /* 00ad: extui a9, a9, 0, 12 */
  a9 = a9 << (12 & 31); /* 00b0: slli a9, a9, 12 */
  MEMW(); /* 00b3: memw  */
  a8 = MEM32(a4 + 0); /* 00b6: l32i.n a8, a4, 0 */
  a8 = a8 & a13; /* 00b8: and a8, a8, a13 */
  a8 = a8 | a9; /* 00bb: or a8, a8, a9 */
  a5 = MEM32(a4 + 4); /* 00be: l32i.n a5, a4, 4 */
  MEMW(); /* 00c0: memw  */
  MEM32(a4 + 0) = a8; /* 00c3: s32i.n a8, a4, 0 */
  MEM32(a5 + 0) = a10; /* 00c5: s32i.n a10, a5, 0 */
  MEMW(); /* 00c7: memw  */
  a8 = MEM32(a4 + 0); /* 00ca: l32i.n a8, a4, 0 */
  a8 = (a8 >> 0) & 0xFFF; /* 00cc: extui a8, a8, 0, 12 */
  a5 = a5 + a8; /* 00cf: add.n a5, a5, a8 */
  MEM32(a5 + 0) = a10; /* 00d1: s32i.n a10, a5, 0 */
  a4 = MEM32(a4 + 8); /* 00d3: l32i.n a4, a4, 8 */
L_d5:;
  if (a4 != 0) goto L_7c; /* 00d5: bnez a4, 7c <wDev_AppendRxBlocks+0x2c> */
  a5 = (uint32_t)&wDevCtrl; /* 00d8: l32r a5, 20 <wDev_AppendRxBlocks-0x30> (0 <wDev_AppendRxBlocks-0x50>) */ /* literal @0x20: wDevCtrl */
  a6 = MEM32(a5 + 0); /* 00db: l32i.n a6, a5, 0 */
  if (a6 == 0) goto L_164; /* 00dd: beqz a6, 164 <wDev_AppendRxBlocks+0x114> */
  a7 = (uint32_t)&g_osi_funcs_p; /* 00e0: l32r a7, 28 <wDev_AppendRxBlocks-0x28> (0 <wDev_AppendRxBlocks-0x50>) */ /* literal @0x28: g_osi_funcs_p */
  a6 = (uint32_t)&g_intr_lock_mux; /* 00e3: l32r a6, 24 <wDev_AppendRxBlocks-0x2c> (0 <wDev_AppendRxBlocks-0x50>) */ /* literal @0x24: g_intr_lock_mux */
  a8 = MEM32(a7 + 0); /* 00e6: l32i.n a8, a7, 0 */
  a10 = MEM32(a6 + 0); /* 00e8: l32i.n a10, a6, 0 */
  a8 = MEM32(a8 + 40); /* 00ea: l32i.n a8, a8, 40 */
  MEMW(); /* 00ec: memw  */
  ((int32_t(*)())a8)(a2, a3, a4, a5); /* 00ef: callx8 a8 */ /* indirect */
  a11 = a10; /* 00f2: mov.n a11, a10 */
  a10 = a4; /* 00f4: mov.n a10, a4 */
  MEM32(a1 + 0) = a11; /* 00f6: s32i.n a11, a1, 0 */
  MEMW(); /* 00f8: memw  */
  a8 = (uint32_t)&wdev_record_rx_linked_list; /* 00fb: l32r a8, 30 <wDev_AppendRxBlocks-0x20> (0 <wDev_AppendRxBlocks-0x50>) */ /* literal: GOT slot for wdev_record_rx_linked_list */
  wdev_record_rx_linked_list(a2, a3, a4, a5); /* call via literal slot */ /* 00fe: callx8 a8 */
  a4 = MEM32(a5 + 4); /* 0101: l32i.n a4, a5, 4 */
  MEM32(a4 + 8) = a2; /* 0103: s32i.n a2, a4, 8 */
  MEMW(); /* 0105: memw  */
  a8 = (uint32_t)&hal_mac_rx_set_dscr_reload; /* 0108: l32r a8, 34 <wDev_AppendRxBlocks-0x1c> (0 <wDev_AppendRxBlocks-0x50>) */ /* literal: GOT slot for hal_mac_rx_set_dscr_reload */
  hal_mac_rx_set_dscr_reload(a2, a3, a4, a5); /* call via literal slot */ /* 010b: callx8 a8 */
  a10 = 0x1; /* 010e: movi.n a10, 1 */
  a8 = (uint32_t)&wdev_record_rx_linked_list; /* 0110: l32r a8, 38 <wDev_AppendRxBlocks-0x18> (0 <wDev_AppendRxBlocks-0x50>) */ /* literal: GOT slot for wdev_record_rx_linked_list */
  wdev_record_rx_linked_list(a2, a3, a4, a5); /* call via literal slot */ /* 0113: callx8 a8 */
  a4 = MEM32(a7 + 0); /* 0116: l32i.n a4, a7, 0 */
  a11 = MEM32(a1 + 0); /* 0118: l32i.n a11, a1, 0 */
  a4 = MEM32(a4 + 44); /* 011a: l32i.n a4, a4, 44 */
  a10 = MEM32(a6 + 0); /* 011c: l32i.n a10, a6, 0 */
  ((int32_t(*)())a4)(a2, a3, a4, a5); /* 011e: callx8 a4 */ /* indirect */
  a4 = 0x186A1; /* 0121: l32r a4, 0 <wDev_AppendRxBlocks-0x50> (186a1 <wDev_ProcessFiq+0x1862d>) */ @0x0
  goto L_13c; /* 0124: j 13c <wDev_AppendRxBlocks+0xec> */
  /* 0127: .byte 00 */
  /* 0128: .byte 00 */
  /* 0129: .byte 00 */
L_12a:;
  a4 = 0x186A0; /* 012a: addi.n a4, a4, -1 */
  if (a4 != 0) goto L_13c; /* 012c: bnez.n a4, 13c <wDev_AppendRxBlocks+0xec> */
  a11 = a3; /* 012e: mov.n a11, a3 */
  a10 = a2; /* 0130: mov.n a10, a2 */
  a8 = (uint32_t)&wdev_dump_rx_linked_list; /* 0132: l32r a8, 3c <wDev_AppendRxBlocks-0x14> (0 <wDev_AppendRxBlocks-0x50>) */ /* literal: GOT slot for wdev_dump_rx_linked_list */
  wdev_dump_rx_linked_list(a2, a3, a4, a5); /* call via literal slot */ /* 0135: callx8 a8 */
  goto L_145; /* 0138: j 145 <wDev_AppendRxBlocks+0xf5> */
  /* 013b: .byte 00 */
L_13c:;
  a8 = (uint32_t)&hal_mac_rx_is_dscr_reload; /* 013c: l32r a8, 40 <wDev_AppendRxBlocks-0x10> (0 <wDev_AppendRxBlocks-0x50>) */ /* literal: GOT slot for hal_mac_rx_is_dscr_reload */
  hal_mac_rx_is_dscr_reload(a2, a3, a4, a5); /* call via literal slot */ /* 013f: callx8 a8 */
  if (a10 != 0) goto L_12a; /* 0142: bnez a10, 12a <wDev_AppendRxBlocks+0xda> */
L_145:;
  a2 = 0x3FF; /* 0145: movi a2, 0x3ff */
  a8 = (uint32_t)&hal_mac_rx_read_rxdscrnext; /* 0148: l32r a8, 44 <wDev_AppendRxBlocks-0xc> (0 <wDev_AppendRxBlocks-0x50>) */ /* literal: GOT slot for hal_mac_rx_read_rxdscrnext */
  hal_mac_rx_read_rxdscrnext(a2, a3, a4, a5); /* call via literal slot */ /* 014b: callx8 a8 */
  a2 = a2 << (20 & 31); /* 014e: slli a2, a2, 20 */
  if (a10 != a2) goto L_171; /* 0151: bne a10, a2, 171 <wDev_AppendRxBlocks+0x121> */
  a8 = (uint32_t)&hal_mac_rx_get_last_dscr; /* 0154: l32r a8, 48 <wDev_AppendRxBlocks-0x8> (0 <wDev_AppendRxBlocks-0x50>) */ /* literal: GOT slot for hal_mac_rx_get_last_dscr */
  hal_mac_rx_get_last_dscr(a2, a3, a4, a5); /* call via literal slot */ /* 0157: callx8 a8 */
  if (a3 == a10) goto L_171; /* 015a: beq a3, a10, 171 <wDev_AppendRxBlocks+0x121> */
  a10 = MEM32(a10 + 8); /* 015d: l32i.n a10, a10, 8 */
  if (a10 == 0) goto L_171; /* 015f: beqz.n a10, 171 <wDev_AppendRxBlocks+0x121> */
  goto L_168; /* 0161: j 168 <wDev_AppendRxBlocks+0x118> */
L_164:;
  MEM32(a5 + 0) = a2; /* 0164: s32i.n a2, a5, 0 */
  a10 = a2; /* 0166: mov.n a10, a2 */
L_168:;
  MEMW(); /* 0168: memw  */
  a8 = (uint32_t)&hal_mac_rx_set_base; /* 016b: l32r a8, 4c <wDev_AppendRxBlocks-0x4> (0 <wDev_AppendRxBlocks-0x50>) */ /* literal: GOT slot for hal_mac_rx_set_base */
  hal_mac_rx_set_base(a2, a3, a4, a5); /* call via literal slot */ /* 016e: callx8 a8 */
L_171:;
  MEM32(a5 + 4) = a3; /* 0171: s32i.n a3, a5, 4 */
  MEMW(); /* 0173: memw  */
  return (int32_t)a2; /* 0176: retw.n  */
}

/* wDev_DiscardFrame @ wdev.o 00000008 size 32B bind GLOBAL
 * Calls: wDev_AppendRxBlocks[got] | Data refs: wDevCtrl, wDev_AppendRxBlocks
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 1 call(s), 2 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t wDev_DiscardFrame(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .wifislpiram.24; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_8:;
  /* 0008: entry a1, 32 */
  a8 = (uint32_t)&wDevCtrl; /* 000b: l32r a8, 0 <wDev_DiscardFrame-0x8> (0 <wDev_DiscardFrame-0x8>) */ /* literal @0x0: wDevCtrl */
  a11 = a2; /* 000e: mov.n a11, a2 */
  a12 = (a3 >> 0) & 0xFFFF; /* 0010: extui a12, a3, 0, 16 */
  a9 = MEM32(a2 + 8); /* 0013: l32i.n a9, a2, 8 */
  a10 = MEM32(a8 + 0); /* 0015: l32i.n a10, a8, 0 */
  MEM32(a8 + 0) = a9; /* 0017: s32i.n a9, a8, 0 */
  a8 = 0x0; /* 0019: movi.n a8, 0 */
  MEM32(a2 + 8) = a8; /* 001b: s32i.n a8, a2, 8 */
  MEMW(); /* 001d: memw  */
  a8 = (uint32_t)&wDev_AppendRxBlocks; /* 0020: l32r a8, 4 <wDev_DiscardFrame-0x4> (0 <wDev_DiscardFrame-0x8>) */ /* literal: GOT slot for wDev_AppendRxBlocks */
  wDev_AppendRxBlocks(a2, a3, a4, a5); /* call via literal slot */ /* 0023: callx8 a8 */
  return (int32_t)a2; /* 0026: retw.n  */
}

/* wDev_IndicateFrame @ wdev.o 0000004c size 662B bind GLOBAL
 * Calls: esf_buf_alloc[got], esf_buf_alloc[got], wifi_gpio_debug[got], wifi_gpio_debug[got], wDev_DiscardFrame[got], wdev_csi_len_align[got], wdev_csi_hw_bug_check[got], memcpy[got], memcpy[got], memcpy[got], memcpy[got], memcpy[got], memcpy[got], wdev_csi_rx_process[got], wDev_DiscardFrame[got], lmacRxDone[got] | Data refs: wDevCtrl, pTxRx, esf_buf_alloc, wifi_gpio_debug, wDev_DiscardFrame, wdev_csi_len_align, wdev_csi_hw_bug_check, memcpy, wdev_csi_rx_process, lmacRxDone
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 16 call(s), 10 data ref(s)
 * Fidelity: medium - 257 instr, 22 branches, 0 indirect; flow + direct calls mapped, GOT-indirects enumerated (verified against section disasm) */
int32_t wDev_IndicateFrame(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .wifislprxiram.21; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4c:;
  /* 004c: entry a1, 64 */
  a3 = (a3 >> 0) & 0xFF; /* 004f: extui a3, a3, 0, 8 */
  MEM32(a1 + 12) = a6; /* 0052: s32i.n a6, a1, 12 */
  a2 = (a2 >> 0) & 0xFF; /* 0054: extui a2, a2, 0, 8 */
  a5 = (a5 >> 0) & 0xFFFF; /* 0057: extui a5, a5, 0, 16 */
  MEM32(a1 + 8) = a3; /* 005a: s32i.n a3, a1, 8 */
  if (a2 == 0) goto L_a1; /* 005c: beqz a2, a1 <wDev_IndicateFrame+0x55> */
  a7 = 0x1F4; /* 005f: movi a7, 0x1f4 */
  a3 = (uint32_t)&wDevCtrl; /* 0062: l32r a3, 0 <wDev_IndicateFrame-0x4c> (0 <wDev_IndicateFrame-0x4c>) */ /* literal @0x0: wDevCtrl */
  a6 = MEM32(a3 + 0); /* 0065: l32i.n a6, a3, 0 */
  MEMW(); /* 0067: memw  */
  a3 = MEM32(a6 + 0); /* 006a: l32i.n a3, a6, 0 */
  a3 = (a3 >> 12) & 0xFFF; /* 006c: extui a3, a3, 12, 12 */
  if (a7 >= a3) goto L_88; /* 006f: bgeu a7, a3, 88 <wDev_IndicateFrame+0x3c> */
L_72:;
  a11 = 0x7; /* 0072: movi.n a11, 7 */
  a3 = (uint32_t)&pTxRx; /* 0074: l32r a3, 4 <wDev_IndicateFrame-0x48> (0 <wDev_IndicateFrame-0x4c>) */ /* literal @0x4: pTxRx */
  a10 = 0x0; /* 0077: movi.n a10, 0 */
  a3 = MEM32(a3 + 0); /* 0079: l32i.n a3, a3, 0 */
  a12 = MEM32(a3 + 964); /* 007b: l32i a12, a3, 0x3c4 */
  a12 = (uint32_t)((uint64_t)a5 * a12); /* 007e: mull a12, a5, a12 */
  MEMW(); /* 0081: memw  */
  goto L_b0; /* 0084: j b0 <wDev_IndicateFrame+0x64> */
  /* 0087: .byte 00 */
L_88:;
  MEMW(); /* 0088: memw  */
  a12 = MEM32(a6 + 0); /* 008b: l32i.n a12, a6, 0 */
  a11 = 0x8; /* 008d: movi.n a11, 8 */
  a12 = (a12 >> 12) & 0xFFF; /* 008f: extui a12, a12, 12, 12 */
  a10 = 0x0; /* 0092: movi.n a10, 0 */
  a8 = (uint32_t)&esf_buf_alloc; /* 0094: l32r a8, c <wDev_IndicateFrame-0x40> (0 <wDev_IndicateFrame-0x4c>) */ /* literal: GOT slot for esf_buf_alloc */
  esf_buf_alloc(a2, a3, a4, a5); /* call via literal slot */ /* 0097: callx8 a8 */
  a7 = 0x0; /* 009a: mov.n a7, a10 */
  if (a10 != 0) goto L_b8; /* 009c: bnez.n a10, b8 <wDev_IndicateFrame+0x6c> */
  goto L_72; /* 009e: j 72 <wDev_IndicateFrame+0x26> */
L_a1:;
  a3 = (uint32_t)&pTxRx; /* 00a1: l32r a3, 4 <wDev_IndicateFrame-0x48> (0 <wDev_IndicateFrame-0x4c>) */ /* literal @0x4: pTxRx */
  a11 = 0x7; /* 00a4: movi.n a11, 7 */
  a10 = a2; /* 00a6: mov.n a10, a2 */
  a3 = MEM32(a3 + 0); /* 00a8: l32i.n a3, a3, 0 */
  a12 = MEM32(a3 + 964); /* 00aa: l32i a12, a3, 0x3c4 */
  a12 = (uint32_t)((uint64_t)a5 * a12); /* 00ad: mull a12, a5, a12 */
L_b0:;
  a8 = (uint32_t)&esf_buf_alloc; /* 00b0: l32r a8, 10 <wDev_IndicateFrame-0x3c> (0 <wDev_IndicateFrame-0x4c>) */ /* literal: GOT slot for esf_buf_alloc */
  esf_buf_alloc(a2, a3, a4, a5); /* call via literal slot */ /* 00b3: callx8 a8 */
  a7 = a10; /* 00b6: mov.n a7, a10 */
L_b8:;
  a2 = a2 + (2); /* 00b8: addi.n a2, a2, 2 */
  a11 = a2 | a2; /* 00ba: or a11, a2, a2 */
  a10 = 0xB; /* 00bd: movi a10, 11 */
  a8 = (uint32_t)&wifi_gpio_debug; /* 00c0: l32r a8, 14 <wDev_IndicateFrame-0x38> (0 <wDev_IndicateFrame-0x4c>) */ /* literal: GOT slot for wifi_gpio_debug */
  wifi_gpio_debug(a2, a3, a4, a5); /* call via literal slot */ /* 00c3: callx8 a8 */
  if (a7 != 0) goto L_e1; /* 00c6: bnez.n a7, e1 <wDev_IndicateFrame+0x95> */
  a11 = a2; /* 00c8: mov.n a11, a2 */
  a10 = 0xC; /* 00ca: movi.n a10, 12 */
  a8 = (uint32_t)&wifi_gpio_debug; /* 00cc: l32r a8, 18 <wDev_IndicateFrame-0x34> (0 <wDev_IndicateFrame-0x4c>) */ /* literal: GOT slot for wifi_gpio_debug */
  wifi_gpio_debug(a2, a3, a4, a5); /* call via literal slot */ /* 00cf: callx8 a8 */
  a11 = a5; /* 00d2: mov.n a11, a5 */
  a10 = a4; /* 00d4: mov.n a10, a4 */
  a8 = (uint32_t)&wDev_DiscardFrame; /* 00d6: l32r a8, 1c <wDev_IndicateFrame-0x30> (0 <wDev_IndicateFrame-0x4c>) */ /* literal: GOT slot for wDev_DiscardFrame */
  wDev_DiscardFrame(a2, a3, a4, a5); /* call via literal slot */ /* 00d9: callx8 a8 */
  goto L_2e0; /* 00dc: j 2e0 <wDev_IndicateFrame+0x294> */
  /* 00df: .byte 00 */
  /* 00e0: .byte 00 */
L_e1:;
  a2 = (uint32_t)&wDevCtrl; /* 00e1: l32r a2, 0 <wDev_IndicateFrame-0x4c> (0 <wDev_IndicateFrame-0x4c>) */ /* literal @0x0: wDevCtrl */
  a6 = MEM32(a2 + 0); /* 00e4: l32i.n a6, a2, 0 */
  a3 = MEM32(a6 + 4); /* 00e6: l32i.n a3, a6, 4 */
  a10 = a3; /* 00e8: mov.n a10, a3 */
  a8 = (uint32_t)&wdev_csi_len_align; /* 00ea: l32r a8, 20 <wDev_IndicateFrame-0x2c> (0 <wDev_IndicateFrame-0x4c>) */ /* literal: GOT slot for wdev_csi_len_align */
  wdev_csi_len_align(a2, a3, a4, a5); /* call via literal slot */ /* 00ed: callx8 a8 */
  a8 = 0x0; /* 00f0: movi.n a8, 0 */
  a2 = (a10 >> 0) & 0xFFFF; /* 00f2: extui a2, a10, 0, 16 */
  MEM32(a1 + 0) = a8; /* 00f5: s32i.n a8, a1, 0 */
  if (a2 == a8) goto L_150; /* 00f7: beq a2, a8, 150 <wDev_IndicateFrame+0x104> */
  a9 = (a10 >> 0) & 0xFFFF; /* 00fa: extui a9, a10, 0, 16 */
  a9 = a9 + (24); /* 00fd: addi a9, a9, 24 */
  a12 = a3 + (24); /* 0100: addi a12, a3, 24 */
  a9 = a3 + a9; /* 0103: add.n a9, a3, a9 */
  a11 = a9; /* 0105: mov.n a11, a9 */
  a10 = a12; /* 0107: mov.n a10, a12 */
  MEM32(a1 + 20) = a9; /* 0109: s32i.n a9, a1, 20 */
  MEM32(a1 + 16) = a12; /* 010b: s32i.n a12, a1, 16 */
  MEMW(); /* 010d: memw  */
  a8 = (uint32_t)&wdev_csi_hw_bug_check; /* 0110: l32r a8, 24 <wDev_IndicateFrame-0x28> (0 <wDev_IndicateFrame-0x4c>) */ /* literal: GOT slot for wdev_csi_hw_bug_check */
  wdev_csi_hw_bug_check(a2, a3, a4, a5); /* call via literal slot */ /* 0113: callx8 a8 */
  MEM32(a1 + 0) = a10; /* 0116: s32i.n a10, a1, 0 */
  a9 = MEM32(a1 + 20); /* 0118: l32i.n a9, a1, 20 */
  a12 = MEM32(a1 + 16); /* 011a: l32i.n a12, a1, 16 */
  if (a10 != 1) goto L_146; /* 011c: bnei a10, 1, 146 <wDev_IndicateFrame+0xfa> */
  a11 = MEM8(a3 + 24); /* 011f: l8ui a11, a3, 24 */
  a10 = MEM8(a12 + 1); /* 0122: l8ui a10, a12, 1 */
  MEM8(a9 + 0) = a11; /* 0125: s8i a11, a9, 0 */
  MEMW(); /* 0128: memw  */
  a11 = MEM8(a12 + 2); /* 012b: l8ui a11, a12, 2 */
  MEM8(a9 + 1) = a10; /* 012e: s8i a10, a9, 1 */
  MEMW(); /* 0131: memw  */
  a10 = MEM8(a12 + 3); /* 0134: l8ui a10, a12, 3 */
  MEM8(a9 + 2) = a11; /* 0137: s8i a11, a9, 2 */
  MEM8(a9 + 3) = a10; /* 013a: s8i a10, a9, 3 */
  MEMW(); /* 013d: memw  */
  MEMW(); /* 0140: memw  */
  goto L_150; /* 0143: j 150 <wDev_IndicateFrame+0x104> */
L_146:;
  a8 = MEM32(a1 + 0); /* 0146: l32i.n a8, a1, 0 */
  a10 = 0x0; /* 0148: movi.n a10, 0 */
  a9 = a8 + (-2); /* 014a: addi a9, a8, -2 */
  if (a9 == 0) a2 = a10; /* 014d: moveqz a2, a10, a9 */
L_150:;
  a10 = 0x1; /* 0150: movi.n a10, 1 */
  a9 = MEM32(a7 + 4); /* 0152: l32i.n a9, a7, 4 */
  a9 = MEM32(a9 + 4); /* 0154: l32i.n a9, a9, 4 */
  if (a6 == a4) goto L_168; /* 0156: beq a6, a4, 168 <wDev_IndicateFrame+0x11c> */
  a11 = a2 + (24); /* 0159: addi a11, a2, 24 */
  a11 = (a11 >> 0) & 0xFFFF; /* 015c: extui a11, a11, 0, 16 */
  MEM32(a1 + 4) = a11; /* 015f: s32i.n a11, a1, 4 */
  MEMW(); /* 0161: memw  */
  goto L_1aa; /* 0164: j 1aa <wDev_IndicateFrame+0x15e> */
  /* 0167: .byte 00 */
L_168:;
  a11 = MEM32(a4 + 4); /* 0168: l32i.n a11, a4, 4 */
  a12 = 0x18; /* 016a: movi.n a12, 24 */
  a10 = a9; /* 016c: mov.n a10, a9 */
  a8 = (uint32_t)&memcpy; /* 016e: l32r a8, 28 <wDev_IndicateFrame-0x24> (0 <wDev_IndicateFrame-0x4c>) */ /* literal: GOT slot for memcpy */
  memcpy(a2, a3, a4, a5); /* call via literal slot */ /* 0171: callx8 a8 */
  a11 = a2 + (24); /* 0174: addi a11, a2, 24 */
  MEMW(); /* 0177: memw  */
  a12 = MEM32(a4 + 0); /* 017a: l32i.n a12, a4, 0 */
  a10 = a10 + (24); /* 017c: addi a10, a10, 24 */
  a12 = (a12 >> 12) & 0xFFF; /* 017f: extui a12, a12, 12, 12 */
  a12 = a12 + (-24); /* 0182: addi a12, a12, -24 */
  a12 = a12 - a2; /* 0185: sub a12, a12, a2 */
  a6 = MEM32(a4 + 4); /* 0188: l32i a6, a4, 4 */
  a11 = a6 + a11; /* 018b: add a11, a6, a11 */
  a8 = (uint32_t)&memcpy; /* 018e: l32r a8, 2c <wDev_IndicateFrame-0x20> (0 <wDev_IndicateFrame-0x4c>) */ /* literal: GOT slot for memcpy */
  memcpy(a2, a3, a4, a5); /* call via literal slot */ /* 0191: callx8 a8 */
  MEMW(); /* 0194: memw  */
  a6 = MEM32(a4 + 0); /* 0197: l32i.n a6, a4, 0 */
  MEMW(); /* 0199: memw  */
  a6 = MEM32(a4 + 0); /* 019c: l32i.n a6, a4, 0 */
  a6 = (a6 >> 12) & 0xFFF; /* 019e: extui a6, a6, 12, 12 */
  a6 = a6 - a2; /* 01a1: sub a6, a6, a2 */
  a10 = MEM32(a7 + 4); /* 01a4: l32i.n a10, a7, 4 */
  goto L_239; /* 01a6: j 239 <wDev_IndicateFrame+0x1ed> */
  /* 01a9: .byte 00 */
L_1aa:;
  a11 = MEM32(a6 + 4); /* 01aa: l32i.n a11, a6, 4 */
  if (a10 == 0) goto L_1e8; /* 01ac: beqz.n a10, 1e8 <wDev_IndicateFrame+0x19c> */
  a12 = 0x18; /* 01ae: movi.n a12, 24 */
  a10 = a9; /* 01b0: mov.n a10, a9 */
  a8 = (uint32_t)&memcpy; /* 01b2: l32r a8, 30 <wDev_IndicateFrame-0x1c> (0 <wDev_IndicateFrame-0x4c>) */ /* literal: GOT slot for memcpy */
  memcpy(a2, a3, a4, a5); /* call via literal slot */ /* 01b5: callx8 a8 */
  a8 = (uint32_t)&pTxRx; /* 01b8: l32r a8, 4 <wDev_IndicateFrame-0x48> (0 <wDev_IndicateFrame-0x4c>) */ /* literal @0x4: pTxRx */
  a9 = a10 + (24); /* 01bb: addi a9, a10, 24 */
  a10 = a9; /* 01be: mov.n a10, a9 */
  a13 = MEM32(a8 + 0); /* 01c0: l32i.n a13, a8, 0 */
  a3 = MEM32(a6 + 4); /* 01c2: l32i.n a3, a6, 4 */
  a12 = MEM32(a13 + 964); /* 01c4: l32i a12, a13, 0x3c4 */
  a8 = MEM32(a1 + 4); /* 01c7: l32i.n a8, a1, 4 */
  a12 = a12 - a8; /* 01c9: sub a12, a12, a8 */
  a11 = a3 + a8; /* 01cc: add.n a11, a3, a8 */
  MEM32(a1 + 16) = a13; /* 01ce: s32i.n a13, a1, 16 */
  MEMW(); /* 01d0: memw  */
  a8 = (uint32_t)&memcpy; /* 01d3: l32r a8, 34 <wDev_IndicateFrame-0x18> (0 <wDev_IndicateFrame-0x4c>) */ /* literal: GOT slot for memcpy */
  memcpy(a2, a3, a4, a5); /* call via literal slot */ /* 01d6: callx8 a8 */
  a9 = a10; /* 01d9: mov.n a9, a10 */
  a13 = MEM32(a1 + 16); /* 01db: l32i.n a13, a1, 16 */
  a8 = MEM32(a1 + 4); /* 01dd: l32i.n a8, a1, 4 */
  a10 = MEM32(a13 + 964); /* 01df: l32i a10, a13, 0x3c4 */
  a10 = a10 - a8; /* 01e2: sub a10, a10, a8 */
  goto L_202; /* 01e5: j 202 <wDev_IndicateFrame+0x1b6> */
L_1e8:;
  a8 = (uint32_t)&pTxRx; /* 01e8: l32r a8, 4 <wDev_IndicateFrame-0x48> (0 <wDev_IndicateFrame-0x4c>) */ /* literal @0x4: pTxRx */
  a10 = MEM32(a8 + 0); /* 01eb: l32i.n a10, a8, 0 */
  a12 = MEM32(a10 + 964); /* 01ed: l32i a12, a10, 0x3c4 */
  a10 = a9; /* 01f0: mov.n a10, a9 */
  a8 = (uint32_t)&memcpy; /* 01f2: l32r a8, 38 <wDev_IndicateFrame-0x14> (0 <wDev_IndicateFrame-0x4c>) */ /* literal: GOT slot for memcpy */
  memcpy(a2, a3, a4, a5); /* call via literal slot */ /* 01f5: callx8 a8 */
  a9 = a10; /* 01f8: mov.n a9, a10 */
  a8 = (uint32_t)&pTxRx; /* 01fa: l32r a8, 4 <wDev_IndicateFrame-0x48> (0 <wDev_IndicateFrame-0x4c>) */ /* literal @0x4: pTxRx */
  a10 = MEM32(a8 + 0); /* 01fd: l32i.n a10, a8, 0 */
  a10 = MEM32(a10 + 964); /* 01ff: l32i a10, a10, 0x3c4 */
L_202:;
  a9 = a9 + a10; /* 0202: add.n a9, a9, a10 */
  a10 = 0x0; /* 0204: movi.n a10, 0 */
  a6 = MEM32(a6 + 8); /* 0206: l32i.n a6, a6, 8 */
  if (a4 != a6) goto L_1aa; /* 0208: bne a4, a6, 1aa <wDev_IndicateFrame+0x15e> */
  a10 = a9; /* 020b: mov.n a10, a9 */
  MEMW(); /* 020d: memw  */
  a12 = MEM32(a4 + 0); /* 0210: l32i.n a12, a4, 0 */
  a12 = (a12 >> 12) & 0xFFF; /* 0212: extui a12, a12, 12, 12 */
  a11 = MEM32(a4 + 4); /* 0215: l32i.n a11, a4, 4 */
  a8 = (uint32_t)&memcpy; /* 0217: l32r a8, 3c <wDev_IndicateFrame-0x10> (0 <wDev_IndicateFrame-0x4c>) */ /* literal: GOT slot for memcpy */
  memcpy(a2, a3, a4, a5); /* call via literal slot */ /* 021a: callx8 a8 */
  a11 = a5 + (-1); /* 021d: addi.n a11, a5, -1 */
  a8 = (uint32_t)&pTxRx; /* 021f: l32r a8, 4 <wDev_IndicateFrame-0x48> (0 <wDev_IndicateFrame-0x4c>) */ /* literal @0x4: pTxRx */
  a9 = MEM32(a8 + 0); /* 0222: l32i.n a9, a8, 0 */
  a9 = MEM32(a9 + 964); /* 0224: l32i a9, a9, 0x3c4 */
  /* 0227: mul16u a9, a9, a11 */ /* UNMODELED: a9 clobbered */
  a9 = a9 - a2; /* 022a: sub a9, a9, a2 */
  MEMW(); /* 022d: memw  */
  a6 = MEM32(a4 + 0); /* 0230: l32i.n a6, a4, 0 */
  a6 = (a6 >> 12) & 0xFFF; /* 0232: extui a6, a6, 12, 12 */
  a6 = a6 + a9; /* 0235: add.n a6, a6, a9 */
  a10 = MEM32(a7 + 4); /* 0237: l32i.n a10, a7, 4 */
L_239:;
  a6 = (a6 >> 0) & 0xFFF; /* 0239: extui a6, a6, 0, 12 */
  a6 = a6 << (12 & 31); /* 023c: slli a6, a6, 12 */
  MEMW(); /* 023f: memw  */
  a9 = MEM32(a10 + 0); /* 0242: l32i.n a9, a10, 0 */
  a11 = 0xFF000FFF; /* 0244: l32r a11, 8 <wDev_IndicateFrame-0x44> (ff000fff <wDev_ProcessFiq+0xff000f8b>) */ @0x8
  a9 = a9 & a11; /* 0247: and a9, a9, a11 */
  a6 = a9 | a6; /* 024a: or a6, a9, a6 */
  MEMW(); /* 024d: memw  */
  MEM32(a10 + 0) = a6; /* 0250: s32i.n a6, a10, 0 */
  a6 = (uint32_t)&wDevCtrl; /* 0252: l32r a6, 0 <wDev_IndicateFrame-0x4c> (0 <wDev_IndicateFrame-0x4c>) */ /* literal @0x0: wDevCtrl */
  a9 = MEM8(a6 + 48); /* 0255: l8ui a9, a6, 48 */
  if (a9 != 1) goto L_260; /* 0258: bnei a9, 1, 260 <wDev_IndicateFrame+0x214> */
  a3 = MEM32(a3 + 0); /* 025b: l32i.n a3, a3, 0 */
  /* 025d: bltz a3, 280 <wDev_IndicateFrame+0x234> */ /* UNMODELED branch */
L_260:;
  if (a2 == 0) goto L_280; /* 0260: beqz.n a2, 280 <wDev_IndicateFrame+0x234> */
  a11 = a2; /* 0262: mov.n a11, a2 */
  a12 = MEM32(a7 + 16); /* 0264: l32i.n a12, a7, 16 */
  a13 = a12 + (28); /* 0266: addi a13, a12, 28 */
  a3 = MEM32(a6 + 0); /* 0269: l32i.n a3, a6, 0 */
  a14 = MEM32(a12 + 24); /* 026b: l32i.n a14, a12, 24 */
  a14 = (a14 >> 0) & 0xFFF; /* 026d: extui a14, a14, 0, 12 */
  a10 = MEM32(a3 + 4); /* 0270: l32i.n a10, a3, 4 */
  a10 = a10 + (24); /* 0272: addi a10, a10, 24 */
  a15 = MEM32(a1 + 0); /* 0275: l32i.n a15, a1, 0 */
  MEMW(); /* 0277: memw  */
  a8 = (uint32_t)&wdev_csi_rx_process; /* 027a: l32r a8, 40 <wDev_IndicateFrame-0xc> (0 <wDev_IndicateFrame-0x4c>) */ /* literal: GOT slot for wdev_csi_rx_process */
  wdev_csi_rx_process(a2, a3, a4, a5); /* call via literal slot */ /* 027d: callx8 a8 */
L_280:;
  a10 = a4; /* 0280: mov.n a10, a4 */
  a11 = a5; /* 0282: mov.n a11, a5 */
  a8 = (uint32_t)&wDev_DiscardFrame; /* 0284: l32r a8, 44 <wDev_IndicateFrame-0x8> (0 <wDev_IndicateFrame-0x4c>) */ /* literal: GOT slot for wDev_DiscardFrame */
  wDev_DiscardFrame(a2, a3, a4, a5); /* call via literal slot */ /* 0287: callx8 a8 */
  a8 = MEM32(a1 + 12); /* 028a: l32i.n a8, a1, 12 */
  a3 = 0x100; /* 028c: movi a3, 0x100 */
  a4 = MEM32(a7 + 44); /* 028f: l32i.n a4, a7, 44 */
  MEM32(a4 + 4) = a8; /* 0291: s32i.n a8, a4, 4 */
  a2 = MEM8(a6 + 44); /* 0293: l8ui a2, a6, 44 */
  MEM8(a4 + 8) = a2; /* 0296: s8i a2, a4, 8 */
  MEMW(); /* 0299: memw  */
  a2 = MEM8(a6 + 45); /* 029c: l8ui a2, a6, 45 */
  MEM8(a4 + 9) = a2; /* 029f: s8i a2, a4, 9 */
  MEMW(); /* 02a2: memw  */
  a2 = MEM32(a4 + 0); /* 02a5: l32i.n a2, a4, 0 */
  a2 = (a2 >> 0) & 0xFFF; /* 02a7: extui a2, a2, 0, 12 */
  if (a5 == 1) goto L_2b0; /* 02aa: beqi a5, 1, 2b0 <wDev_IndicateFrame+0x264> */
  a3 = 0x80; /* 02ad: movi a3, 128 */
L_2b0:;
  a8 = MEM32(a1 + 8); /* 02b0: l32i.n a8, a1, 8 */
  a2 = a2 | a3; /* 02b2: or a2, a2, a3 */
  a2 = (a2 >> 0) & 0xFFFF; /* 02b5: extui a2, a2, 0, 16 */
  a3 = MEM32(a4 + 0); /* 02b8: l32i.n a3, a4, 0 */
  if (a8 != 0) goto L_2c2; /* 02ba: bnez.n a8, 2c2 <wDev_IndicateFrame+0x276> */
  MEMW(); /* 02bc: memw  */
  goto L_2c7; /* 02bf: j 2c7 <wDev_IndicateFrame+0x27b> */
L_2c2:;
  a5 = 0x10; /* 02c2: movi.n a5, 16 */
  a2 = a2 | a5; /* 02c4: or a2, a2, a5 */
L_2c7:;
  a5 = 0xFFFFFFFF; /* 02c7: movi.n a5, -1 */
  a5 = 0xFFFFF000; /* 02c9: slli a5, a5, 12 */
  a3 = a3 & a5; /* 02cc: and a3, a3, a5 */
  a3 = a3 | a2; /* 02cf: or a3, a3, a2 */
  MEM32(a4 + 0) = a3; /* 02d2: s32i.n a3, a4, 0 */
  a10 = a7 | a7; /* 02d4: or a10, a7, a7 */
  MEMW(); /* 02d7: memw  */
  a8 = (uint32_t)&lmacRxDone; /* 02da: l32r a8, 48 <wDev_IndicateFrame-0x4> (0 <wDev_IndicateFrame-0x4c>) */ /* literal: GOT slot for lmacRxDone */
  lmacRxDone(a2, a3, a4, a5); /* call via literal slot */ /* 02dd: callx8 a8 */
L_2e0:;
  return (int32_t)a2; /* 02e0: retw.n  */
}

/* wDev_IndicateAmpdu @ wdev.o 00000048 size 752B bind GLOBAL
 * Calls: wdev_csi_len_align[got], wdev_csi_hw_bug_check[got], wDev_RxSecError[got], roundup2[got], esf_buf_alloc[got], memcpy[got], memcpy[got], esf_buf_recycle[got], memcpy[got], roundup2[got], memcpy[got], roundup2[got], wdev_csi_rx_process[got], wDev_SnifferRxAmpdu[got], lmacRxDone[got], esf_buf_recycle[got], wDev_DiscardFrame[got] | Data refs: wDevCtrl, wdev_csi_len_align, wdev_csi_hw_bug_check, wDev_RxSecError, roundup2, esf_buf_alloc, memcpy, esf_buf_recycle, wdev_csi_rx_process, wDev_SnifferRxAmpdu, lmacRxDone, wDev_DiscardFrame
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 17 call(s), 12 data ref(s)
 * Fidelity: medium - 295 instr, 38 branches, 0 indirect; flow + direct calls mapped, GOT-indirects enumerated (verified against section disasm) */
int32_t wDev_IndicateAmpdu(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .wifirxiram.23; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_48:;
  /* 0048: entry a1, 64 */
  MEM32(a1 + 12) = a2; /* 004b: s32i.n a2, a1, 12 */
  a3 = (a3 >> 0) & 0xFFFF; /* 004d: extui a3, a3, 0, 16 */
  a5 = 0x0; /* 0050: movi.n a5, 0 */
  a2 = (uint32_t)&wDevCtrl; /* 0052: l32r a2, 0 <wDev_IndicateAmpdu-0x48> (0 <wDev_IndicateAmpdu-0x48>) */ /* literal @0x0: wDevCtrl */
  a2 = MEM32(a2 + 0); /* 0055: l32i.n a2, a2, 0 */
  MEM32(a1 + 16) = a3; /* 0057: s32i.n a3, a1, 16 */
  a3 = MEM32(a2 + 4); /* 0059: l32i.n a3, a2, 4 */
  a10 = a3; /* 005b: mov.n a10, a3 */
  MEM32(a1 + 20) = a4; /* 005d: s32i.n a4, a1, 20 */
  MEMW(); /* 005f: memw  */
  a8 = (uint32_t)&wdev_csi_len_align; /* 0062: l32r a8, 4 <wDev_IndicateAmpdu-0x44> (0 <wDev_IndicateAmpdu-0x48>) */ /* literal: GOT slot for wdev_csi_len_align */
  wdev_csi_len_align(a2, a3, a4, a5); /* call via literal slot */ /* 0065: callx8 a8 */
  a4 = (a10 >> 0) & 0xFFFF; /* 0068: extui a4, a10, 0, 16 */
  a8 = (a10 >> 0) & 0xFFFF; /* 006b: extui a8, a10, 0, 16 */
  a7 = a8 + (24); /* 006e: addi a7, a8, 24 */
  MEM32(a1 + 0) = a4; /* 0071: s32i.n a4, a1, 0 */
  MEM32(a1 + 8) = a5; /* 0073: s32i.n a5, a1, 8 */
  if (a4 != a5) goto L_7b; /* 0075: bne a4, a5, 7b <wDev_IndicateAmpdu+0x33> */
  goto L_2ee; /* 0078: j 2ee <wDev_IndicateAmpdu+0x2a6> */
L_7b:;
  a5 = a3 + (24); /* 007b: addi a5, a3, 24 */
  a4 = a3 + a7; /* 007e: add.n a4, a3, a7 */
  a11 = a4; /* 0080: mov.n a11, a4 */
  a10 = a5; /* 0082: mov.n a10, a5 */
  MEMW(); /* 0084: memw  */
  a8 = (uint32_t)&wdev_csi_hw_bug_check; /* 0087: l32r a8, 8 <wDev_IndicateAmpdu-0x40> (0 <wDev_IndicateAmpdu-0x48>) */ /* literal: GOT slot for wdev_csi_hw_bug_check */
  wdev_csi_hw_bug_check(a2, a3, a4, a5); /* call via literal slot */ /* 008a: callx8 a8 */
  MEM32(a1 + 8) = a10; /* 008d: s32i.n a10, a1, 8 */
  if (a10 != 1) goto L_b9; /* 008f: bnei a10, 1, b9 <wDev_IndicateAmpdu+0x71> */
  a6 = MEM8(a3 + 24); /* 0092: l8ui a6, a3, 24 */
  a9 = MEM8(a3 + 25); /* 0095: l8ui a9, a3, 25 */
  MEM8(a4 + 0) = a6; /* 0098: s8i a6, a4, 0 */
  MEMW(); /* 009b: memw  */
  a6 = MEM8(a3 + 26); /* 009e: l8ui a6, a3, 26 */
  MEM8(a4 + 1) = a9; /* 00a1: s8i a9, a4, 1 */
  MEMW(); /* 00a4: memw  */
  a5 = MEM8(a3 + 27); /* 00a7: l8ui a5, a3, 27 */
  MEM8(a4 + 2) = a6; /* 00aa: s8i a6, a4, 2 */
  MEM8(a4 + 3) = a5; /* 00ad: s8i a5, a4, 3 */
  MEMW(); /* 00b0: memw  */
  MEMW(); /* 00b3: memw  */
  goto L_2ee; /* 00b6: j 2ee <wDev_IndicateAmpdu+0x2a6> */
L_b9:;
  a6 = MEM32(a1 + 8); /* 00b9: l32i.n a6, a1, 8 */
  a5 = 0x0; /* 00bb: movi.n a5, 0 */
  a4 = a6 + (-2); /* 00bd: addi a4, a6, -2 */
  a8 = MEM32(a1 + 0); /* 00c0: l32i.n a8, a1, 0 */
  if (a4 == 0) a8 = a5; /* 00c2: moveqz a8, a5, a4 */
  a5 = 0x18; /* 00c5: movi.n a5, 24 */
  if (a4 == 0) a7 = a5; /* 00c7: moveqz a7, a5, a4 */
  MEM32(a1 + 0) = a8; /* 00ca: s32i.n a8, a1, 0 */
  MEMW(); /* 00cc: memw  */
  goto L_2ee; /* 00cf: j 2ee <wDev_IndicateAmpdu+0x2a6> */
L_d2:;
  a13 = MEM32(a2 + 4); /* 00d2: l32i.n a13, a2, 4 */
  a9 = 0x627; /* 00d4: movi a9, 0x627 */
  a13 = a13 + a7; /* 00d7: add.n a13, a13, a7 */
  a12 = MEM32(a13 + 0); /* 00d9: l32i.n a12, a13, 0 */
  a5 = (a12 >> 0) & 0xFFF; /* 00db: extui a5, a12, 0, 12 */
  a6 = a5 + (-24); /* 00de: addi a6, a5, -24 */
  a4 = a5; /* 00e1: mov.n a4, a5 */
  if (a9 >= a6) goto L_e9; /* 00e3: bgeu a9, a6, e9 <wDev_IndicateAmpdu+0xa1> */
  goto L_329; /* 00e6: j 329 <wDev_IndicateAmpdu+0x2e1> */
L_e9:;
  MEMW(); /* 00e9: memw  */
  a9 = MEM32(a2 + 0); /* 00ec: l32i.n a9, a2, 0 */
  a6 = a7 + (4); /* 00ee: addi.n a6, a7, 4 */
  a9 = (a9 >> 12) & 0xFFF; /* 00f0: extui a9, a9, 12, 12 */
  if (a6 >= a9) goto L_fe; /* 00f3: bgeu a6, a9, fe <wDev_IndicateAmpdu+0xb6> */
  a9 = MEM16(a13 + 4); /* 00f6: l16ui a9, a13, 4 */
  goto L_105; /* 00f9: j 105 <wDev_IndicateAmpdu+0xbd> */
  /* 00fc: .byte 00 */
  /* 00fd: .byte 00 */
L_fe:;
  a9 = MEM32(a2 + 8); /* 00fe: l32i.n a9, a2, 8 */
  a9 = MEM32(a9 + 4); /* 0100: l32i.n a9, a9, 4 */
  a9 = MEM16(a9 + 0); /* 0102: l16ui a9, a9, 0 */
L_105:;
  if (!((a9 >> 14) & 1)) goto L_115; /* 0105: bbci a9, 14, 115 <wDev_IndicateAmpdu+0xcd> */
  a9 = 0x7; /* 0108: movi.n a9, 7 */
  a9 = 0x70000000; /* 010a: slli a9, a9, 28 */
  a10 = MEM32(a3 + 0); /* 010d: l32i.n a10, a3, 0 */
  if ((a10 & a9) == 0) goto L_115; /* 010f: bnone a10, a9, 115 <wDev_IndicateAmpdu+0xcd> */
  a4 = a5 + (-8); /* 0112: addi a4, a5, -8 */
L_115:;
  a9 = 0x0; /* 0115: movi.n a9, 0 */
  a10 = MEM8(a13 + 3); /* 0117: l8ui a10, a13, 3 */
  a8 = 0x1; /* 011a: movi.n a8, 1 */
  if (a10 != 0) a9 = a8; /* 011c: movnez a9, a8, a10 */
  a9 = (a9 >> 0) & 0xFF; /* 011f: extui a9, a9, 0, 8 */
  if (a9 == 0) goto L_178; /* 0122: beqz a9, 178 <wDev_IndicateAmpdu+0x130> */
  a11 = 0xFFFFFF3A; /* 0125: movi a11, -198 */
  a11 = a10 + a11; /* 0128: add.n a11, a10, a11 */
  a9 = 0x0; /* 012a: movi.n a9, 0 */
  if (a11 != 0) a9 = a8; /* 012c: movnez a9, a8, a11 */
  a9 = (a9 >> 0) & 0xFF; /* 012f: extui a9, a9, 0, 8 */
  if (a9 == 0) goto L_178; /* 0132: beqz a9, 178 <wDev_IndicateAmpdu+0x130> */
  MEM32(a1 + 28) = a13; /* 0135: s32i.n a13, a1, 28 */
  MEMW(); /* 0137: memw  */
  a8 = (uint32_t)&wDev_RxSecError; /* 013a: l32r a8, c <wDev_IndicateAmpdu-0x3c> (0 <wDev_IndicateAmpdu-0x48>) */ /* literal: GOT slot for wDev_RxSecError */
  wDev_RxSecError(a2, a3, a4, a5); /* call via literal slot */ /* 013d: callx8 a8 */
  a13 = MEM32(a1 + 28); /* 0140: l32i.n a13, a1, 28 */
  if (a10 != 0) goto L_178; /* 0142: bnez.n a10, 178 <wDev_IndicateAmpdu+0x130> */
  a10 = a4 + a7; /* 0144: add.n a10, a4, a7 */
  MEMW(); /* 0146: memw  */
  a4 = MEM32(a2 + 0); /* 0149: l32i.n a4, a2, 0 */
  a4 = (a4 >> 12) & 0xFFF; /* 014b: extui a4, a4, 12, 12 */
  if (a10 < a4) goto L_169; /* 014e: bltu a10, a4, 169 <wDev_IndicateAmpdu+0x121> */
  MEMW(); /* 0151: memw  */
  a4 = MEM32(a2 + 0); /* 0154: l32i.n a4, a2, 0 */
  if (!((a4 >> 30) & 1)) goto L_15c; /* 0156: bbci a4, 30, 15c <wDev_IndicateAmpdu+0x114> */
  goto L_324; /* 0159: j 324 <wDev_IndicateAmpdu+0x2dc> */
L_15c:;
  MEMW(); /* 015c: memw  */
  a4 = MEM32(a2 + 0); /* 015f: l32i.n a4, a2, 0 */
  a4 = (a4 >> 12) & 0xFFF; /* 0161: extui a4, a4, 12, 12 */
  a10 = a10 - a4; /* 0164: sub a10, a10, a4 */
  a2 = MEM32(a2 + 8); /* 0167: l32i.n a2, a2, 8 */
L_169:;
  a11 = 0x4; /* 0169: movi.n a11, 4 */
  a8 = (uint32_t)&roundup2; /* 016b: l32r a8, 10 <wDev_IndicateAmpdu-0x38> (0 <wDev_IndicateAmpdu-0x48>) */ /* literal: GOT slot for roundup2 */
  roundup2(a2, a3, a4, a5); /* call via literal slot */ /* 016e: callx8 a8 */
  a7 = a10; /* 0171: mov.n a7, a10 */
  goto L_300; /* 0173: j 300 <wDev_IndicateAmpdu+0x2b8> */
  /* 0176: .byte 00 */
  /* 0177: .byte 00 */
L_178:;
  a12 = a5 + (28); /* 0178: addi a12, a5, 28 */
  a12 = (a12 >> 0) & 0xFFF; /* 017b: extui a12, a12, 0, 12 */
  a11 = 0x7; /* 017e: movi.n a11, 7 */
  a10 = 0x0; /* 0180: movi.n a10, 0 */
  MEM32(a1 + 28) = a13; /* 0182: s32i.n a13, a1, 28 */
  MEMW(); /* 0184: memw  */
  a8 = (uint32_t)&esf_buf_alloc; /* 0187: l32r a8, 14 <wDev_IndicateAmpdu-0x34> (0 <wDev_IndicateAmpdu-0x48>) */ /* literal: GOT slot for esf_buf_alloc */
  esf_buf_alloc(a2, a3, a4, a5); /* call via literal slot */ /* 018a: callx8 a8 */
  a5 = 0x0; /* 018d: mov.n a5, a10 */
  if (a10 == 0) goto L_329; /* 018f: beqz a10, 329 <wDev_IndicateAmpdu+0x2e1> */
  a12 = 0x18; /* 0192: movi.n a12, 24 */
  a10 = MEM32(a10 + 4); /* 0194: l32i.n a10, a10, 4 */
  a11 = a3; /* 0196: mov.n a11, a3 */
  a10 = MEM32(a10 + 4); /* 0198: l32i.n a10, a10, 4 */
  a8 = (uint32_t)&memcpy; /* 019a: l32r a8, 18 <wDev_IndicateAmpdu-0x30> (0 <wDev_IndicateAmpdu-0x48>) */ /* literal: GOT slot for memcpy */
  memcpy(a2, a3, a4, a5); /* call via literal slot */ /* 019d: callx8 a8 */
  a13 = MEM32(a1 + 28); /* 01a0: l32i.n a13, a1, 28 */
  a10 = MEM32(a5 + 4); /* 01a2: l32i.n a10, a5, 4 */
  a12 = MEM8(a13 + 0); /* 01a4: l8ui a12, a13, 0 */
  a11 = MEM32(a10 + 4); /* 01a7: l32i.n a11, a10, 4 */
  a10 = a11 + (24); /* 01a9: addi a10, a11, 24 */
  a14 = MEM8(a13 + 1); /* 01ac: l8ui a14, a13, 1 */
  MEM8(a11 + 24) = a12; /* 01af: s8i a12, a11, 24 */
  MEMW(); /* 01b2: memw  */
  a12 = MEM8(a13 + 2); /* 01b5: l8ui a12, a13, 2 */
  MEM8(a11 + 25) = a14; /* 01b8: s8i a14, a11, 25 */
  MEMW(); /* 01bb: memw  */
  a11 = MEM8(a13 + 3); /* 01be: l8ui a11, a13, 3 */
  MEM8(a10 + 2) = a12; /* 01c1: s8i a12, a10, 2 */
  MEM8(a10 + 3) = a11; /* 01c4: s8i a11, a10, 3 */
  MEMW(); /* 01c7: memw  */
  a11 = a4 + a7; /* 01ca: add.n a11, a4, a7 */
  MEMW(); /* 01cc: memw  */
  a10 = MEM32(a2 + 0); /* 01cf: l32i.n a10, a2, 0 */
  a10 = (a10 >> 12) & 0xFFF; /* 01d1: extui a10, a10, 12, 12 */
  if (a11 < a10) goto L_244; /* 01d4: bltu a11, a10, 244 <wDev_IndicateAmpdu+0x1fc> */
  MEMW(); /* 01d7: memw  */
  a11 = MEM32(a2 + 0); /* 01da: l32i.n a11, a2, 0 */
  a11 = (a11 >> 12) & 0xFFF; /* 01dc: extui a11, a11, 12, 12 */
  a13 = a11 - a7; /* 01df: sub a13, a11, a7 */
  a11 = a7 - a11; /* 01e2: sub a11, a7, a11 */
  a10 = MEM32(a5 + 4); /* 01e5: l32i.n a10, a5, 4 */
  a7 = a11 + a4; /* 01e7: add.n a7, a11, a4 */
  a12 = a13 + (-4); /* 01e9: addi a12, a13, -4 */
  a10 = MEM32(a10 + 4); /* 01ec: l32i.n a10, a10, 4 */
  a10 = a10 + (28); /* 01ee: addi a10, a10, 28 */
  a11 = MEM32(a2 + 4); /* 01f1: l32i.n a11, a2, 4 */
  a11 = a11 + a6; /* 01f3: add.n a11, a11, a6 */
  MEM32(a1 + 28) = a13; /* 01f5: s32i.n a13, a1, 28 */
  MEMW(); /* 01f7: memw  */
  a8 = (uint32_t)&memcpy; /* 01fa: l32r a8, 1c <wDev_IndicateAmpdu-0x2c> (0 <wDev_IndicateAmpdu-0x48>) */ /* literal: GOT slot for memcpy */
  memcpy(a2, a3, a4, a5); /* call via literal slot */ /* 01fd: callx8 a8 */
  MEMW(); /* 0200: memw  */
  a6 = MEM32(a2 + 0); /* 0203: l32i.n a6, a2, 0 */
  a6 = (a6 >> 30) & 0x1; /* 0205: extui a6, a6, 30, 1 */
  a13 = MEM32(a1 + 28); /* 0208: l32i.n a13, a1, 28 */
  if (a6 != 1) goto L_21c; /* 020a: bnei a6, 1, 21c <wDev_IndicateAmpdu+0x1d4> */
  if (a7 == 0) goto L_266; /* 020d: beqz a7, 266 <wDev_IndicateAmpdu+0x21e> */
  a10 = a5; /* 0210: mov.n a10, a5 */
  a8 = (uint32_t)&esf_buf_recycle; /* 0212: l32r a8, 20 <wDev_IndicateAmpdu-0x28> (0 <wDev_IndicateAmpdu-0x48>) */ /* literal: GOT slot for esf_buf_recycle */
  esf_buf_recycle(a2, a3, a4, a5); /* call via literal slot */ /* 0215: callx8 a8 */
  goto L_324; /* 0218: j 324 <wDev_IndicateAmpdu+0x2dc> */
  /* 021b: .byte 00 */
L_21c:;
  a2 = MEM32(a2 + 8); /* 021c: l32i.n a2, a2, 8 */
  if (a7 == 0) goto L_266; /* 021e: beqz a7, 266 <wDev_IndicateAmpdu+0x21e> */
  a13 = a13 + (24); /* 0221: addi a13, a13, 24 */
  a12 = a7; /* 0224: mov.n a12, a7 */
  a10 = MEM32(a5 + 4); /* 0226: l32i.n a10, a5, 4 */
  a10 = MEM32(a10 + 4); /* 0228: l32i.n a10, a10, 4 */
  a10 = a10 + a13; /* 022a: add.n a10, a10, a13 */
  a11 = MEM32(a2 + 4); /* 022c: l32i.n a11, a2, 4 */
  a8 = (uint32_t)&memcpy; /* 022e: l32r a8, 24 <wDev_IndicateAmpdu-0x24> (0 <wDev_IndicateAmpdu-0x48>) */ /* literal: GOT slot for memcpy */
  memcpy(a2, a3, a4, a5); /* call via literal slot */ /* 0231: callx8 a8 */
  a10 = a7; /* 0234: mov.n a10, a7 */
  a11 = 0x4; /* 0236: movi.n a11, 4 */
  a8 = (uint32_t)&roundup2; /* 0238: l32r a8, 28 <wDev_IndicateAmpdu-0x20> (0 <wDev_IndicateAmpdu-0x48>) */ /* literal: GOT slot for roundup2 */
  roundup2(a2, a3, a4, a5); /* call via literal slot */ /* 023b: callx8 a8 */
  a7 = a10; /* 023e: mov.n a7, a10 */
  goto L_266; /* 0240: j 266 <wDev_IndicateAmpdu+0x21e> */
  /* 0243: .byte 00 */
L_244:;
  a10 = MEM32(a5 + 4); /* 0244: l32i.n a10, a5, 4 */
  a12 = a4 + (-4); /* 0246: addi a12, a4, -4 */
  a10 = MEM32(a10 + 4); /* 0249: l32i.n a10, a10, 4 */
  a10 = a10 + (28); /* 024b: addi a10, a10, 28 */
  a11 = MEM32(a2 + 4); /* 024e: l32i.n a11, a2, 4 */
  a11 = a11 + a6; /* 0250: add.n a11, a11, a6 */
  a8 = (uint32_t)&memcpy; /* 0252: l32r a8, 2c <wDev_IndicateAmpdu-0x1c> (0 <wDev_IndicateAmpdu-0x48>) */ /* literal: GOT slot for memcpy */
  memcpy(a2, a3, a4, a5); /* call via literal slot */ /* 0255: callx8 a8 */
  a11 = 0x4; /* 0258: movi.n a11, 4 */
  a10 = a4; /* 025a: mov.n a10, a4 */
  a8 = (uint32_t)&roundup2; /* 025c: l32r a8, 30 <wDev_IndicateAmpdu-0x18> (0 <wDev_IndicateAmpdu-0x48>) */ /* literal: GOT slot for roundup2 */
  roundup2(a2, a3, a4, a5); /* call via literal slot */ /* 025f: callx8 a8 */
  a7 = a7 + a10; /* 0262: add.n a7, a7, a10 */
  a6 = 0x0; /* 0264: movi.n a6, 0 */
L_266:;
  a8 = MEM32(a1 + 24); /* 0266: l32i.n a8, a1, 24 */
  if (a8 == 0) goto L_28e; /* 0268: beqz.n a8, 28e <wDev_IndicateAmpdu+0x246> */
  a8 = MEM32(a1 + 4); /* 026a: l32i.n a8, a1, 4 */
  if (a8 == 0) goto L_28e; /* 026c: beqz.n a8, 28e <wDev_IndicateAmpdu+0x246> */
  a14 = a4; /* 026e: mov.n a14, a4 */
  a4 = 0x0; /* 0270: movi.n a4, 0 */
  a10 = (uint32_t)&wDevCtrl; /* 0272: l32r a10, 0 <wDev_IndicateAmpdu-0x48> (0 <wDev_IndicateAmpdu-0x48>) */ /* literal @0x0: wDevCtrl */
  a10 = MEM32(a10 + 0); /* 0275: l32i.n a10, a10, 0 */
  a12 = MEM32(a5 + 16); /* 0277: l32i.n a12, a5, 16 */
  a13 = a12 + (28); /* 0279: addi a13, a12, 28 */
  a10 = MEM32(a10 + 4); /* 027c: l32i.n a10, a10, 4 */
  a10 = a10 + (24); /* 027e: addi a10, a10, 24 */
  a15 = MEM32(a1 + 8); /* 0281: l32i a15, a1, 8 */
  a11 = MEM32(a1 + 0); /* 0284: l32i.n a11, a1, 0 */
  a8 = (uint32_t)&wdev_csi_rx_process; /* 0286: l32r a8, 34 <wDev_IndicateAmpdu-0x14> (0 <wDev_IndicateAmpdu-0x48>) */ /* literal: GOT slot for wdev_csi_rx_process */
  wdev_csi_rx_process(a2, a3, a4, a5); /* call via literal slot */ /* 0289: callx8 a8 */
  MEM32(a1 + 4) = a4; /* 028c: s32i.n a4, a1, 4 */
L_28e:;
  a12 = 0x10; /* 028e: movi.n a12, 16 */
  a4 = MEM32(a5 + 44); /* 0290: l32i.n a4, a5, 44 */
  a8 = MEM32(a1 + 20); /* 0292: l32i.n a8, a1, 20 */
  a10 = (uint32_t)&wDevCtrl; /* 0294: l32r a10, 0 <wDev_IndicateAmpdu-0x48> (0 <wDev_IndicateAmpdu-0x48>) */ /* literal @0x0: wDevCtrl */
  MEM32(a4 + 4) = a8; /* 0297: s32i.n a8, a4, 4 */
  a11 = MEM8(a10 + 44); /* 0299: l8ui a11, a10, 44 */
  MEM8(a4 + 8) = a11; /* 029c: s8i a11, a4, 8 */
  MEMW(); /* 029f: memw  */
  a11 = MEM8(a10 + 45); /* 02a2: l8ui a11, a10, 45 */
  MEM8(a4 + 9) = a11; /* 02a5: s8i a11, a4, 9 */
  MEMW(); /* 02a8: memw  */
  a11 = MEM32(a4 + 0); /* 02ab: l32i.n a11, a4, 0 */
  a11 = a11 | a12; /* 02ad: or a11, a11, a12 */
  MEM32(a4 + 0) = a11; /* 02b0: s32i.n a11, a4, 0 */
  a4 = MEM8(a10 + 48); /* 02b2: l8ui a4, a10, 48 */
  if (a4 != 1) goto L_2ca; /* 02b5: bnei a4, 1, 2ca <wDev_IndicateAmpdu+0x282> */
  a4 = MEM32(a3 + 0); /* 02b8: l32i a4, a3, 0 */
  /* 02bb: bgez a4, 2ca <wDev_IndicateAmpdu+0x282> */ /* UNMODELED branch */
  a10 = a5 | a5; /* 02be: or a10, a5, a5 */
  MEMW(); /* 02c1: memw  */
  a8 = (uint32_t)&wDev_SnifferRxAmpdu; /* 02c4: l32r a8, 38 <wDev_IndicateAmpdu-0x10> (0 <wDev_IndicateAmpdu-0x48>) */ /* literal: GOT slot for wDev_SnifferRxAmpdu */
  wDev_SnifferRxAmpdu(a2, a3, a4, a5); /* call via literal slot */ /* 02c7: callx8 a8 */
L_2ca:;
  a4 = 0x7; /* 02ca: movi.n a4, 7 */
  a10 = MEM32(a3 + 0); /* 02cc: l32i.n a10, a3, 0 */
  a4 = 0x70000000; /* 02ce: slli a4, a4, 28 */
  if ((a10 & a4) == 0) goto L_2e0; /* 02d1: bnone a10, a4, 2e0 <wDev_IndicateAmpdu+0x298> */
  a10 = a5; /* 02d4: mov.n a10, a5 */
  a8 = (uint32_t)&lmacRxDone; /* 02d6: l32r a8, 3c <wDev_IndicateAmpdu-0xc> (0 <wDev_IndicateAmpdu-0x48>) */ /* literal: GOT slot for lmacRxDone */
  lmacRxDone(a2, a3, a4, a5); /* call via literal slot */ /* 02d9: callx8 a8 */
  goto L_2e8; /* 02dc: j 2e8 <wDev_IndicateAmpdu+0x2a0> */
  /* 02df: .byte 00 */
L_2e0:;
  a10 = a5; /* 02e0: mov.n a10, a5 */
  a8 = (uint32_t)&esf_buf_recycle; /* 02e2: l32r a8, 40 <wDev_IndicateAmpdu-0x8> (0 <wDev_IndicateAmpdu-0x48>) */ /* literal: GOT slot for esf_buf_recycle */
  esf_buf_recycle(a2, a3, a4, a5); /* call via literal slot */ /* 02e5: callx8 a8 */
L_2e8:;
  if (a6 == 0) goto L_300; /* 02e8: beqz.n a6, 300 <wDev_IndicateAmpdu+0x2b8> */
  goto L_324; /* 02ea: j 324 <wDev_IndicateAmpdu+0x2dc> */
  /* 02ed: .byte 00 */
L_2ee:;
  a4 = 0x1; /* 02ee: movi.n a4, 1 */
  MEM32(a1 + 4) = a4; /* 02f0: s32i.n a4, a1, 4 */
  a4 = 0x0; /* 02f2: movi.n a4, 0 */
  a5 = MEM32(a1 + 0); /* 02f4: l32i.n a5, a1, 0 */
  a6 = MEM32(a1 + 4); /* 02f6: l32i.n a6, a1, 4 */
  if (a5 != 0) a4 = a6; /* 02f8: movnez a4, a6, a5 */
  a4 = (a4 >> 0) & 0xFF; /* 02fb: extui a4, a4, 0, 8 */
  MEM32(a1 + 24) = a4; /* 02fe: s32i.n a4, a1, 24 */
L_300:;
  MEMW(); /* 0300: memw  */
  a4 = MEM32(a2 + 0); /* 0303: l32i.n a4, a2, 0 */
  if ((a4 >> 30) & 1) goto L_30b; /* 0305: bbsi a4, 30, 30b <wDev_IndicateAmpdu+0x2c3> */
  goto L_d2; /* 0308: j d2 <wDev_IndicateAmpdu+0x8a> */
L_30b:;
  MEMW(); /* 030b: memw  */
  a4 = MEM32(a2 + 0); /* 030e: l32i.n a4, a2, 0 */
  if (!((a4 >> 30) & 1)) goto L_324; /* 0310: bbci a4, 30, 324 <wDev_IndicateAmpdu+0x2dc> */
  a6 = a7 + (24); /* 0313: addi a6, a7, 24 */
  MEMW(); /* 0316: memw  */
  a4 = MEM32(a2 + 0); /* 0319: l32i.n a4, a2, 0 */
  a4 = (a4 >> 12) & 0xFFF; /* 031b: extui a4, a4, 12, 12 */
  if (a6 >= a4) goto L_324; /* 031e: bgeu a6, a4, 324 <wDev_IndicateAmpdu+0x2dc> */
  goto L_d2; /* 0321: j d2 <wDev_IndicateAmpdu+0x8a> */
L_324:;
  MEMW(); /* 0324: memw  */
  a2 = MEM32(a2 + 0); /* 0327: l32i.n a2, a2, 0 */
L_329:;
  a11 = MEM32(a1 + 16); /* 0329: l32i.n a11, a1, 16 */
  a10 = MEM32(a1 + 12); /* 032b: l32i.n a10, a1, 12 */
  MEMW(); /* 032d: memw  */
  a8 = (uint32_t)&wDev_DiscardFrame; /* 0330: l32r a8, 44 <wDev_IndicateAmpdu-0x4> (0 <wDev_IndicateAmpdu-0x48>) */ /* literal: GOT slot for wDev_DiscardFrame */
  wDev_DiscardFrame(a2, a3, a4, a5); /* call via literal slot */ /* 0333: callx8 a8 */
  return (int32_t)a2; /* 0336: retw.n  */
}

/* wDev_ProcessRxSucData @ wdev.o 00000060 size 905B bind GLOBAL
 * Calls: wDev_GetNoiseFloor[got], wdev_csi_len_align[got], wdev_csi_hw_bug_check[got], wDev_SnifferRxData[got], wDev_SnifferRxData[got], ic_interface_enabled[got], wifi_sta_rx_probe_req[got], ic_interface_enabled[got], wDev_ProcessRxData_NAN_Interface_Hook[got], ic_interface_enabled[got], wDev_ProcessRxData_NAN_Interface_Hook[got], wDev_IndicateCtrlFrame[got], ic_interface_enabled[got], ic_interface_enabled[got], ic_interface_enabled[got], wDev_DiscardFrame[got], wifi_assert[got], wDev_IndicateAmpdu[got], wDev_IndicateFrame[got] | Data refs: wDevCtrl, wDev_GetNoiseFloor, wdev_csi_len_align, wdev_csi_hw_bug_check, wDev_SnifferRxData, g_lmac_cnt, ic_interface_enabled, wifi_sta_rx_probe_req, wDev_ProcessRxData_NAN_Interface_Hook, wDev_IndicateCtrlFrame, g_osi_funcs_p, wDev_DiscardFrame, .rodata.__FUNCTION__$3, .rodata.str1.1, wifi_assert, wDev_IndicateAmpdu, wDev_IndicateFrame
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 19 call(s), 17 data ref(s)
 * Fidelity: medium - 349 instr, 68 branches, 1 indirect; flow + direct calls mapped, GOT-indirects enumerated (verified against section disasm) */
int32_t wDev_ProcessRxSucData(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .wifislprxiram.27; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_60:;
  /* 0060: entry a1, 48 */
  a13 = (uint32_t)&wDevCtrl; /* 0063: l32r a13, 0 <wDev_ProcessRxSucData-0x60> (0 <wDev_ProcessRxSucData-0x60>) */ /* literal @0x0: wDevCtrl */
  a3 = (a3 >> 0) & 0xFFFF; /* 0066: extui a3, a3, 0, 16 */
  MEM32(a1 + 4) = a4; /* 0069: s32i.n a4, a1, 4 */
  a4 = MEM32(a13 + 0); /* 006b: l32i a4, a13, 0 */
  a5 = MEM32(a4 + 4); /* 006e: l32i.n a5, a4, 4 */
  a6 = MEM8(a13 + 46); /* 0070: l8ui a6, a13, 46 */
  a4 = MEM8(a5 + 0); /* 0073: l8ui a4, a5, 0 */
  a4 = a4 - a6; /* 0076: sub a4, a4, a6 */
  MEM8(a5 + 0) = a4; /* 0079: s8i a4, a5, 0 */
  MEMW(); /* 007c: memw  */
  a4 = MEM8(a13 + 45); /* 007f: l8ui a4, a13, 45 */
  a4 = a4 << (4 & 31); /* 0082: slli a4, a4, 4 */
  a6 = MEM8(a13 + 44); /* 0085: l8ui a6, a13, 44 */
  a6 = (a6 >> 0) & 0xF; /* 0088: extui a6, a6, 0, 4 */
  a4 = a4 | a6; /* 008b: or a4, a4, a6 */
  MEM8(a5 + 10) = a4; /* 008e: s8i a4, a5, 10 */
  MEMW(); /* 0091: memw  */
  MEM32(a1 + 12) = a13; /* 0094: s32i a13, a1, 12 */
  MEMW(); /* 0097: memw  */
  a8 = (uint32_t)&wDev_GetNoiseFloor; /* 009a: l32r a8, 18 <wDev_ProcessRxSucData-0x48> (0 <wDev_ProcessRxSucData-0x60>) */ /* literal: GOT slot for wDev_GetNoiseFloor */
  wDev_GetNoiseFloor(a2, a3, a4, a5); /* call via literal slot */ /* 009d: callx8 a8 */
  MEM8(a5 + 8) = a10; /* 00a0: s8i a10, a5, 8 */
  MEMW(); /* 00a3: memw  */
  a10 = a5; /* 00a6: mov.n a10, a5 */
  MEMW(); /* 00a8: memw  */
  a8 = (uint32_t)&wdev_csi_len_align; /* 00ab: l32r a8, 1c <wDev_ProcessRxSucData-0x44> (0 <wDev_ProcessRxSucData-0x60>) */ /* literal: GOT slot for wdev_csi_len_align */
  wdev_csi_len_align(a2, a3, a4, a5); /* call via literal slot */ /* 00ae: callx8 a8 */
  a6 = (a10 >> 0) & 0xFFFF; /* 00b1: extui a6, a10, 0, 16 */
  a13 = MEM32(a1 + 12); /* 00b4: l32i.n a13, a1, 12 */
  if (a6 == 0) goto L_e8; /* 00b6: beqz.n a6, e8 <wDev_ProcessRxSucData+0x88> */
  a4 = MEM32(a13 + 0); /* 00b8: l32i.n a4, a13, 0 */
  a7 = MEM32(a4 + 4); /* 00ba: l32i.n a7, a4, 4 */
  a4 = (a10 >> 0) & 0xFFFF; /* 00bc: extui a4, a10, 0, 16 */
  a4 = a4 + (24); /* 00bf: addi a4, a4, 24 */
  a4 = a7 + a4; /* 00c2: add.n a4, a7, a4 */
  a11 = a4; /* 00c4: mov.n a11, a4 */
  a12 = MEM8(a7 + 27); /* 00c6: l8ui a12, a7, 27 */
  a10 = a7 + (24); /* 00c9: addi a10, a7, 24 */
  MEM32(a1 + 8) = a12; /* 00cc: s32i a12, a1, 8 */
  MEMW(); /* 00cf: memw  */
  a8 = (uint32_t)&wdev_csi_hw_bug_check; /* 00d2: l32r a8, 20 <wDev_ProcessRxSucData-0x40> (0 <wDev_ProcessRxSucData-0x60>) */ /* literal: GOT slot for wdev_csi_hw_bug_check */
  wdev_csi_hw_bug_check(a2, a3, a4, a5); /* call via literal slot */ /* 00d5: callx8 a8 */
  a12 = MEM32(a1 + 8); /* 00d8: l32i.n a12, a1, 8 */
  a13 = MEM32(a1 + 12); /* 00da: l32i.n a13, a1, 12 */
  if (a10 == 2) goto L_ee; /* 00dc: beqi a10, 2, ee <wDev_ProcessRxSucData+0x8e> */
  if (a10 != 0) goto L_f0; /* 00df: bnez.n a10, f0 <wDev_ProcessRxSucData+0x90> */
  a12 = MEM8(a4 + 3); /* 00e1: l8ui a12, a4, 3 */
  goto L_f0; /* 00e4: j f0 <wDev_ProcessRxSucData+0x90> */
  /* 00e7: .byte 00 */
L_e8:;
  a12 = MEM8(a5 + 27); /* 00e8: l8ui a12, a5, 27 */
  goto L_f0; /* 00eb: j f0 <wDev_ProcessRxSucData+0x90> */
L_ee:;
  a6 = 0x0; /* 00ee: movi.n a6, 0 */
L_f0:;
  a4 = 0x0; /* 00f0: movi.n a4, 0 */
  a8 = 0x1; /* 00f2: movi.n a8, 1 */
  a9 = 0x0; /* 00f4: mov.n a9, a4 */
  if (a12 != 0) a9 = a8; /* 00f6: movnez a9, a8, a12 */
  a7 = a9; /* 00f9: mov.n a7, a9 */
  a9 = 0xFFFFFF0B; /* 00fb: movi a9, -245 */
  a9 = a12 + a9; /* 00fe: add.n a9, a12, a9 */
  a10 = 0x0; /* 0100: mov.n a10, a4 */
  if (a9 != 0) a10 = a8; /* 0102: movnez a10, a8, a9 */
  a9 = 0xFFFFFF3A; /* 0105: movi a9, -198 */
  a9 = a12 + a9; /* 0108: add.n a9, a12, a9 */
  a7 = a7 & a10; /* 010a: and a7, a7, a10 */
  if (a9 != 0) a4 = a8; /* 010d: movnez a4, a8, a9 */
  a4 = a4 & a7; /* 0110: and a4, a4, a7 */
  if (a4 == 0) goto L_13c; /* 0113: beqz.n a4, 13c <wDev_ProcessRxSucData+0xdc> */
  a4 = a12 + (-65); /* 0115: addi a4, a12, -65 */
  if (a4 == 0) goto L_120; /* 0118: beqz.n a4, 120 <wDev_ProcessRxSucData+0xc0> */
  a4 = a12 + (-98); /* 011a: addi a4, a12, -98 */
  if (a4 != 0) goto L_362; /* 011d: bnez a4, 362 <wDev_ProcessRxSucData+0x302> */
L_120:;
  a4 = MEM8(a13 + 48); /* 0120: l8ui a4, a13, 48 */
  if (a4 == 0) goto L_362; /* 0123: beqz a4, 362 <wDev_ProcessRxSucData+0x302> */
  a4 = MEM32(a13 + 52); /* 0126: l32i.n a4, a13, 52 */
  if ((a4 >> 3) & 1) goto L_12e; /* 0128: bbsi a4, 3, 12e <wDev_ProcessRxSucData+0xce> */
  goto L_362; /* 012b: j 362 <wDev_ProcessRxSucData+0x302> */
L_12e:;
  a11 = (a3 >> 0) & 0xFF; /* 012e: extui a11, a3, 0, 8 */
  a10 = a2; /* 0131: mov.n a10, a2 */
  a8 = (uint32_t)&wDev_SnifferRxData; /* 0133: l32r a8, 24 <wDev_ProcessRxSucData-0x3c> (0 <wDev_ProcessRxSucData-0x60>) */ /* literal: GOT slot for wDev_SnifferRxData */
  wDev_SnifferRxData(a2, a3, a4, a5); /* call via literal slot */ /* 0136: callx8 a8 */
  goto L_362; /* 0139: j 362 <wDev_ProcessRxSucData+0x302> */
L_13c:;
  a11 = MEM8(a13 + 48); /* 013c: l8ui a11, a13, 48 */
  a10 = a4; /* 013f: mov.n a10, a4 */
  a11 = a11 + (-1); /* 0141: addi.n a11, a11, -1 */
  a6 = a6 + (28); /* 0143: addi a6, a6, 28 */
  if (a11 == 0) a10 = a8; /* 0146: moveqz a10, a8, a11 */
  a7 = MEM32(a5 + 4); /* 0149: l32i.n a7, a5, 4 */
  a9 = a8 << (27 & 31); /* 014b: slli a9, a8, 27 */
  a6 = a5 + a6; /* 014e: add.n a6, a5, a6 */
  a10 = (a10 >> 0) & 0xFF; /* 0150: extui a10, a10, 0, 8 */
  a7 = a7 & a9; /* 0153: and a7, a7, a9 */
  a9 = MEM16(a6 + 0); /* 0156: l16ui a9, a6, 0 */
  if (a10 == 0) goto L_17e; /* 0159: beqz.n a10, 17e <wDev_ProcessRxSucData+0x11e> */
  if (a7 != 0) a8 = a4; /* 015b: movnez a8, a4, a7 */
  a8 = (a8 >> 0) & 0xFF; /* 015e: extui a8, a8, 0, 8 */
  if (a8 == 0) goto L_17e; /* 0161: beqz.n a8, 17e <wDev_ProcessRxSucData+0x11e> */
  a8 = MEM32(a5 + 0); /* 0163: l32i.n a8, a5, 0 */
  /* 0165: bgez a8, 17e <wDev_ProcessRxSucData+0x11e> */ /* UNMODELED branch */
  a11 = (a3 >> 0) & 0xFF; /* 0168: extui a11, a3, 0, 8 */
  a10 = a2; /* 016b: mov.n a10, a2 */
  MEM32(a1 + 8) = a9; /* 016d: s32i.n a9, a1, 8 */
  MEM32(a1 + 12) = a13; /* 016f: s32i.n a13, a1, 12 */
  MEMW(); /* 0171: memw  */
  a8 = (uint32_t)&wDev_SnifferRxData; /* 0174: l32r a8, 28 <wDev_ProcessRxSucData-0x38> (0 <wDev_ProcessRxSucData-0x60>) */ /* literal: GOT slot for wDev_SnifferRxData */
  wDev_SnifferRxData(a2, a3, a4, a5); /* call via literal slot */ /* 0177: callx8 a8 */
  a13 = MEM32(a1 + 12); /* 017a: l32i.n a13, a1, 12 */
  a9 = MEM32(a1 + 8); /* 017c: l32i.n a9, a1, 8 */
L_17e:;
  a8 = 0x4; /* 017e: movi.n a8, 4 */
  a10 = MEM8(a6 + 1); /* 0180: l8ui a10, a6, 1 */
  a8 = a10 & a8; /* 0183: and a8, a10, a8 */
  MEM32(a1 + 0) = a8; /* 0186: s32i.n a8, a1, 0 */
  a10 = MEM32(a5 + 0); /* 0188: l32i.n a10, a5, 0 */
  if (a7 == 0) goto L_1c6; /* 018a: beqz.n a7, 1c6 <wDev_ProcessRxSucData+0x166> */
  a6 = 0x3; /* 018c: movi.n a6, 3 */
  a6 = 0x30000000; /* 018e: slli a6, a6, 28 */
  a6 = a10 & a6; /* 0191: and a6, a10, a6 */
  a9 = 0x0; /* 0194: movi.n a9, 0 */
  a8 = 0x1; /* 0196: movi.n a8, 1 */
  if (a6 != 0) a8 = a9; /* 0198: movnez a8, a9, a6 */
  a9 = MEM8(a13 + 48); /* 019b: l8ui a9, a13, 48 */
  a8 = (a8 >> 0) & 0xFF; /* 019e: extui a8, a8, 0, 8 */
  a6 = a4 | a4; /* 01a1: or a6, a4, a4 */
  if (a9 != 1) goto L_1b0; /* 01a4: bnei a9, 1, 1b0 <wDev_ProcessRxSucData+0x150> */
  a6 = a9 | a9; /* 01a7: or a6, a9, a9 */
  if (a10 < 0) a8 = a4; /* 01aa: movltz a8, a4, a10 */
  if (a10 >= 0) a6 = a4; /* 01ad: movgez a6, a4, a10 */
L_1b0:;
  a10 = (uint32_t)&g_lmac_cnt; /* 01b0: l32r a10, 4 <wDev_ProcessRxSucData-0x5c> (0 <wDev_ProcessRxSucData-0x60>) */ /* literal @0x4: g_lmac_cnt */
  a9 = MEM32(a10 + 160); /* 01b3: l32i a9, a10, 160 */
  a9 = a9 + (1); /* 01b6: addi.n a9, a9, 1 */
  MEM32(a10 + 160) = a9; /* 01b8: s32i a9, a10, 160 */
  if (a6 != 0) goto L_375; /* 01bb: bnez a6, 375 <wDev_ProcessRxSucData+0x315> */
  MEMW(); /* 01be: memw  */
  goto L_322; /* 01c1: j 322 <wDev_ProcessRxSucData+0x2c2> */
  /* 01c4: .byte 00 */
  /* 01c5: .byte 00 */
L_1c6:;
  a8 = 0x7; /* 01c6: movi.n a8, 7 */
  a8 = 0x70000000; /* 01c8: slli a8, a8, 28 */
  if ((a10 & a8) != 0) goto L_1d1; /* 01cb: bany a10, a8, 1d1 <wDev_ProcessRxSucData+0x171> */
  goto L_3c9; /* 01ce: j 3c9 <wDev_ProcessRxSucData+0x369> */
L_1d1:;
  a10 = (a9 >> 0) & 0xF; /* 01d1: extui a10, a9, 0, 4 */
  if (a10 != 4) goto L_1da; /* 01d4: bnei a10, 4, 1da <wDev_ProcessRxSucData+0x17a> */
  goto L_291; /* 01d7: j 291 <wDev_ProcessRxSucData+0x231> */
L_1da:;
  if (a10 != 8) goto L_1e0; /* 01da: bnei a10, 8, 1e0 <wDev_ProcessRxSucData+0x180> */
  goto L_2f1; /* 01dd: j 2f1 <wDev_ProcessRxSucData+0x291> */
L_1e0:;
  a8 = 0x1; /* 01e0: movi.n a8, 1 */
  if (a10 != 0) goto L_324; /* 01e2: bnez a10, 324 <wDev_ProcessRxSucData+0x2c4> */
  a8 = 0xF0; /* 01e5: movi a8, 240 */
  a8 = a9 & a8; /* 01e8: and a8, a9, a8 */
  if (a8 != 64) goto L_22c; /* 01eb: bnei a8, 64, 22c <wDev_ProcessRxSucData+0x1cc> */
  a8 = MEM8(a5 + 3); /* 01ee: l8ui a8, a5, 3 */
  a9 = 0xFFFFFFCF; /* 01f1: movi a9, -49 */
  a8 = a8 & a9; /* 01f4: and a8, a8, a9 */
  a9 = 0x20; /* 01f7: movi.n a9, 32 */
  a8 = a8 | a9; /* 01f9: or a8, a8, a9 */
  MEM8(a5 + 3) = a8; /* 01fc: s8i a8, a5, 3 */
  MEMW(); /* 01ff: memw  */
  a10 = a7; /* 0202: mov.n a10, a7 */
  MEMW(); /* 0204: memw  */
  a8 = (uint32_t)&ic_interface_enabled; /* 0207: l32r a8, 2c <wDev_ProcessRxSucData-0x34> (0 <wDev_ProcessRxSucData-0x60>) */ /* literal: GOT slot for ic_interface_enabled */
  ic_interface_enabled(a2, a3, a4, a5); /* call via literal slot */ /* 020a: callx8 a8 */
  if (a10 == 0) goto L_27c; /* 020d: beqz a10, 27c <wDev_ProcessRxSucData+0x21c> */
  a8 = (uint32_t)&wifi_sta_rx_probe_req; /* 0210: l32r a8, 8 <wDev_ProcessRxSucData-0x58> (0 <wDev_ProcessRxSucData-0x60>) */ /* literal @0x8: wifi_sta_rx_probe_req */
  a8 = MEM32(a8 + 0); /* 0213: l32i.n a8, a8, 0 */
  if (a8 == 0) goto L_27c; /* 0215: beqz a8, 27c <wDev_ProcessRxSucData+0x21c> */
  a10 = a6; /* 0218: mov.n a10, a6 */
  a12 = MEM8(a5 + 0); /* 021a: l8ui a12, a5, 0 */
  a12 = ((int32_t)(a12 << (32 - (7 & 31)))) >> (32 - (7 & 31)); /* 021d: sext a12, a12, 7 */
  a11 = MEM32(a5 + 24); /* 0220: l32i.n a11, a5, 24 */
  a11 = (a11 >> 0) & 0xFFF; /* 0222: extui a11, a11, 0, 12 */
  wifi_sta_rx_probe_req(a2, a3, a4, a5); /* call via literal slot */ /* 0225: callx8 a8 */
  goto L_27c; /* 0228: j 27c <wDev_ProcessRxSucData+0x21c> */
  /* 022b: .byte 00 */
L_22c:;
  if (a8 == 128) goto L_238; /* 022c: beqi a8, 128, 238 <wDev_ProcessRxSucData+0x1d8> */
  a9 = 0xD0; /* 022f: movi a9, 208 */
  if (a8 != a9) goto L_27c; /* 0232: bne a8, a9, 27c <wDev_ProcessRxSucData+0x21c> */
  goto L_268; /* 0235: j 268 <wDev_ProcessRxSucData+0x208> */
L_238:;
  a10 = 0x2; /* 0238: movi.n a10, 2 */
  a8 = (uint32_t)&ic_interface_enabled; /* 023a: l32r a8, 30 <wDev_ProcessRxSucData-0x30> (0 <wDev_ProcessRxSucData-0x60>) */ /* literal: GOT slot for ic_interface_enabled */
  ic_interface_enabled(a2, a3, a4, a5); /* call via literal slot */ /* 023d: callx8 a8 */
  if (a10 == 0) goto L_27c; /* 0240: beqz.n a10, 27c <wDev_ProcessRxSucData+0x21c> */
  a11 = a6; /* 0242: mov.n a11, a6 */
  a10 = a5; /* 0244: mov.n a10, a5 */
  a8 = (uint32_t)&wDev_ProcessRxData_NAN_Interface_Hook; /* 0246: l32r a8, 34 <wDev_ProcessRxSucData-0x2c> (0 <wDev_ProcessRxSucData-0x60>) */ /* literal: GOT slot for wDev_ProcessRxData_NAN_Interface_Hook */
  wDev_ProcessRxData_NAN_Interface_Hook(a2, a3, a4, a5); /* call via literal slot */ /* 0249: callx8 a8 */
  if (a10 != 0) goto L_27c; /* 024c: bnez.n a10, 27c <wDev_ProcessRxSucData+0x21c> */
  a6 = MEM8(a5 + 3); /* 024e: l8ui a6, a5, 3 */
  a8 = 0xFFFFFFCF; /* 0251: movi a8, -49 */
  a6 = a6 & a8; /* 0254: and a6, a6, a8 */
  a8 = 0x10; /* 0257: movi.n a8, 16 */
  a6 = a6 | a8; /* 0259: or a6, a6, a8 */
  MEM8(a5 + 3) = a6; /* 025c: s8i a6, a5, 3 */
  MEMW(); /* 025f: memw  */
  MEMW(); /* 0262: memw  */
  goto L_27c; /* 0265: j 27c <wDev_ProcessRxSucData+0x21c> */
L_268:;
  a10 = 0x2; /* 0268: movi.n a10, 2 */
  a8 = (uint32_t)&ic_interface_enabled; /* 026a: l32r a8, 38 <wDev_ProcessRxSucData-0x28> (0 <wDev_ProcessRxSucData-0x60>) */ /* literal: GOT slot for ic_interface_enabled */
  ic_interface_enabled(a2, a3, a4, a5); /* call via literal slot */ /* 026d: callx8 a8 */
  if (a10 == 0) goto L_27c; /* 0270: beqz.n a10, 27c <wDev_ProcessRxSucData+0x21c> */
  a11 = a6; /* 0272: mov.n a11, a6 */
  a10 = a5; /* 0274: mov.n a10, a5 */
  a8 = (uint32_t)&wDev_ProcessRxData_NAN_Interface_Hook; /* 0276: l32r a8, 3c <wDev_ProcessRxSucData-0x24> (0 <wDev_ProcessRxSucData-0x60>) */ /* literal: GOT slot for wDev_ProcessRxData_NAN_Interface_Hook */
  wDev_ProcessRxData_NAN_Interface_Hook(a2, a3, a4, a5); /* call via literal slot */ /* 0279: callx8 a8 */
L_27c:;
  a8 = (uint32_t)&g_lmac_cnt; /* 027c: l32r a8, 4 <wDev_ProcessRxSucData-0x5c> (0 <wDev_ProcessRxSucData-0x60>) */ /* literal @0x4: g_lmac_cnt */
  a6 = MEM32(a8 + 168); /* 027f: l32i a6, a8, 168 */
  a6 = a6 + (1); /* 0282: addi.n a6, a6, 1 */
  MEM32(a8 + 168) = a6; /* 0284: s32i a6, a8, 168 */
  a8 = a4; /* 0287: mov.n a8, a4 */
  a6 = 0x1; /* 0289: movi.n a6, 1 */
  MEMW(); /* 028b: memw  */
  goto L_3cd; /* 028e: j 3cd <wDev_ProcessRxSucData+0x36d> */
L_291:;
  a8 = (uint32_t)&g_lmac_cnt; /* 0291: l32r a8, 4 <wDev_ProcessRxSucData-0x5c> (0 <wDev_ProcessRxSucData-0x60>) */ /* literal @0x4: g_lmac_cnt */
  a6 = MEM32(a8 + 172); /* 0294: l32i a6, a8, 172 */
  a6 = a6 + (1); /* 0297: addi.n a6, a6, 1 */
  MEM32(a8 + 172) = a6; /* 0299: s32i a6, a8, 172 */
  a6 = 0xF0; /* 029c: movi a6, 240 */
  a6 = 0xD0; /* 029f: and a6, a9, a6 */
  a8 = 0xB0; /* 02a2: movi a8, 176 */
  if (a6 != a8) goto L_2ab; /* 02a5: bne a6, a8, 2ab <wDev_ProcessRxSucData+0x24b> */
  goto L_3bc; /* 02a8: j 3bc <wDev_ProcessRxSucData+0x35c> */
L_2ab:;
  if (a8 < a6) goto L_2c9; /* 02ab: bltu a8, a6, 2c9 <wDev_ProcessRxSucData+0x269> */
  a8 = 0xA0; /* 02ae: movi a8, 160 */
  if (a6 != a8) goto L_2b7; /* 02b1: bne a6, a8, 2b7 <wDev_ProcessRxSucData+0x257> */
  goto L_3d9; /* 02b4: j 3d9 <wDev_ProcessRxSucData+0x379> */
L_2b7:;
  a6 = 0xE0; /* 02b7: movi a6, 224 */
  a6 = 0xC0; /* 02ba: and a6, a9, a6 */
  if (a6 != 128) goto L_2c3; /* 02bd: bnei a6, 128, 2c3 <wDev_ProcessRxSucData+0x263> */
  goto L_3d9; /* 02c0: j 3d9 <wDev_ProcessRxSucData+0x379> */
L_2c3:;
  MEMW(); /* 02c3: memw  */
  goto L_2dc; /* 02c6: j 2dc <wDev_ProcessRxSucData+0x27c> */
L_2c9:;
  a6 = 0xE0; /* 02c9: movi a6, 224 */
  a6 = 0xC0; /* 02cc: and a6, a9, a6 */
  a10 = 0xC0; /* 02cf: movi a10, 192 */
  a11 = a4; /* 02d2: mov.n a11, a4 */
  a8 = a4; /* 02d4: mov.n a8, a4 */
  if (a6 != a10) goto L_2dc; /* 02d6: bne a6, a10, 2dc <wDev_ProcessRxSucData+0x27c> */
  goto L_3c0; /* 02d9: j 3c0 <wDev_ProcessRxSucData+0x360> */
L_2dc:;
  a11 = a2; /* 02dc: mov.n a11, a2 */
  a12 = a3; /* 02de: mov.n a12, a3 */
  a10 = 0xD0; /* 02e0: mov.n a10, a9 */
  a8 = (uint32_t)&wDev_IndicateCtrlFrame; /* 02e2: l32r a8, 40 <wDev_ProcessRxSucData-0x20> (0 <wDev_ProcessRxSucData-0x60>) */ /* literal: GOT slot for wDev_IndicateCtrlFrame */
  wDev_IndicateCtrlFrame(a2, a3, a4, a5); /* call via literal slot */ /* 02e5: callx8 a8 */
  a8 = 0xD0; /* 02e8: mov.n a8, a10 */
  a11 = a4; /* 02ea: mov.n a11, a4 */
  goto L_3c0; /* 02ec: j 3c0 <wDev_ProcessRxSucData+0x360> */
  /* 02ef: .byte 00 */
  /* 02f0: .byte 00 */
L_2f1:;
  a8 = 0x70; /* 02f1: movi a8, 112 */
  a9 = 0x50; /* 02f4: and a9, a9, a8 */
  a11 = 0x1; /* 02f7: movi.n a11, 1 */
  if (a9 == 64) goto L_310; /* 02f9: beqi a9, 64, 310 <wDev_ProcessRxSucData+0x2b0> */
  a8 = (uint32_t)&g_osi_funcs_p; /* 02fc: l32r a8, c <wDev_ProcessRxSucData-0x54> (0 <wDev_ProcessRxSucData-0x60>) */ /* literal @0xC: g_osi_funcs_p */
  a8 = MEM32(a8 + 0); /* 02ff: l32i.n a8, a8, 0 */
  a10 = MEM32(a8 + 4); /* 0301: l32i.n a10, a8, 4 */
  ((int32_t(*)())a10)(a2, a3, a4, a5); /* 0303: callx8 a10 */ /* indirect */
  a11 = a4; /* 0306: mov.n a11, a4 */
  if (a10 != 0) goto L_310; /* 0308: bnez.n a10, 310 <wDev_ProcessRxSucData+0x2b0> */
  a11 = MEM8(a6 + 4); /* 030a: l8ui a11, a6, 4 */
  a11 = (a11 >> 0) & 0x1; /* 030d: extui a11, a11, 0, 1 */
L_310:;
  a8 = (uint32_t)&g_lmac_cnt; /* 0310: l32r a8, 4 <wDev_ProcessRxSucData-0x5c> (0 <wDev_ProcessRxSucData-0x60>) */ /* literal @0x4: g_lmac_cnt */
  a6 = MEM32(a8 + 164); /* 0313: l32i a6, a8, 164 */
  a6 = a6 + (1); /* 0316: addi.n a6, a6, 1 */
  MEM32(a8 + 164) = a6; /* 0318: s32i a6, a8, 164 */
  MEMW(); /* 031b: memw  */
  goto L_3be; /* 031e: j 3be <wDev_ProcessRxSucData+0x35e> */
  /* 0321: .byte 00 */
L_322:;
  a4 = a6; /* 0322: mov.n a4, a6 */
L_324:;
  a10 = 0x1; /* 0324: movi.n a10, 1 */
  MEM32(a1 + 8) = a8; /* 0326: s32i.n a8, a1, 8 */
  MEMW(); /* 0328: memw  */
  a8 = (uint32_t)&ic_interface_enabled; /* 032b: l32r a8, 44 <wDev_ProcessRxSucData-0x1c> (0 <wDev_ProcessRxSucData-0x60>) */ /* literal: GOT slot for ic_interface_enabled */
  ic_interface_enabled(a2, a3, a4, a5); /* call via literal slot */ /* 032e: callx8 a8 */
  a8 = MEM32(a1 + 8); /* 0331: l32i.n a8, a1, 8 */
  if (a10 == 0) goto L_33a; /* 0333: beqz.n a10, 33a <wDev_ProcessRxSucData+0x2da> */
  a6 = MEM32(a5 + 0); /* 0335: l32i.n a6, a5, 0 */
  if ((a6 >> 29) & 1) goto L_375; /* 0337: bbsi a6, 29, 375 <wDev_ProcessRxSucData+0x315> */
L_33a:;
  a10 = 0x0; /* 033a: movi.n a10, 0 */
  MEM32(a1 + 8) = a8; /* 033c: s32i a8, a1, 8 */
  MEMW(); /* 033f: memw  */
  a8 = (uint32_t)&ic_interface_enabled; /* 0342: l32r a8, 48 <wDev_ProcessRxSucData-0x18> (0 <wDev_ProcessRxSucData-0x60>) */ /* literal: GOT slot for ic_interface_enabled */
  ic_interface_enabled(a2, a3, a4, a5); /* call via literal slot */ /* 0345: callx8 a8 */
  a8 = MEM32(a1 + 8); /* 0348: l32i.n a8, a1, 8 */
  if (a10 == 0) goto L_351; /* 034a: beqz.n a10, 351 <wDev_ProcessRxSucData+0x2f1> */
  a6 = MEM32(a5 + 0); /* 034c: l32i.n a6, a5, 0 */
  if ((a6 >> 28) & 1) goto L_375; /* 034e: bbsi a6, 28, 375 <wDev_ProcessRxSucData+0x315> */
L_351:;
  a10 = 0x2; /* 0351: movi.n a10, 2 */
  MEM32(a1 + 8) = a8; /* 0353: s32i.n a8, a1, 8 */
  MEMW(); /* 0355: memw  */
  a8 = (uint32_t)&ic_interface_enabled; /* 0358: l32r a8, 4c <wDev_ProcessRxSucData-0x14> (0 <wDev_ProcessRxSucData-0x60>) */ /* literal: GOT slot for ic_interface_enabled */
  ic_interface_enabled(a2, a3, a4, a5); /* call via literal slot */ /* 035b: callx8 a8 */
  a8 = MEM32(a1 + 8); /* 035e: l32i.n a8, a1, 8 */
  if (a10 != 0) goto L_370; /* 0360: bnez.n a10, 370 <wDev_ProcessRxSucData+0x310> */
L_362:;
  a11 = a3; /* 0362: mov.n a11, a3 */
  a10 = a2; /* 0364: mov.n a10, a2 */
  a8 = (uint32_t)&wDev_DiscardFrame; /* 0366: l32r a8, 50 <wDev_ProcessRxSucData-0x10> (0 <wDev_ProcessRxSucData-0x60>) */ /* literal: GOT slot for wDev_DiscardFrame */
  wDev_DiscardFrame(a2, a3, a4, a5); /* call via literal slot */ /* 0369: callx8 a8 */
  goto L_3e7; /* 036c: j 3e7 <wDev_ProcessRxSucData+0x387> */
  /* 036f: .byte 00 */
L_370:;
  a5 = MEM32(a5 + 0); /* 0370: l32i.n a5, a5, 0 */
  if (!((a5 >> 30) & 1)) goto L_362; /* 0372: bbci a5, 30, 362 <wDev_ProcessRxSucData+0x302> */
L_375:;
  if (a8 != 0) goto L_362; /* 0375: bnez a8, 362 <wDev_ProcessRxSucData+0x302> */
  a13 = 0x49F; /* 0378: movi a13, 0x49f */
  MEMW(); /* 037b: memw  */
  a5 = MEM32(a2 + 0); /* 037e: l32i.n a5, a2, 0 */
  a10 = 0x1; /* 0380: movi.n a10, 1 */
  a5 = (a5 >> 12) & 0xFFF; /* 0382: extui a5, a5, 12, 12 */
  a13 = 0x93E; /* 0385: add.n a13, a13, a13 */
  if (a5 == 0) a10 = a8; /* 0387: moveqz a10, a8, a5 */
  a12 = (uint32_t)&lit_rodata_FUNCTION_3; /* 038a: l32r a12, 10 <wDev_ProcessRxSucData-0x50> (0 <wDev_ProcessRxSucData-0x60>) */ /* literal @0x10: .rodata.__FUNCTION__$3 */
  a11 = (uint32_t)&lit_rodata_str1_1; /* 038d: l32r a11, 14 <wDev_ProcessRxSucData-0x4c> (0 <wDev_ProcessRxSucData-0x60>) */ /* literal @0x14: .rodata.str1.1 */
  a8 = (uint32_t)&wifi_assert; /* 0390: l32r a8, 54 <wDev_ProcessRxSucData-0xc> (0 <wDev_ProcessRxSucData-0x60>) */ /* literal: GOT slot for wifi_assert */
  wifi_assert(a2, a3, a4, a5); /* call via literal slot */ /* 0393: callx8 a8 */
  if (a7 == 0) goto L_3a7; /* 0396: beqz.n a7, 3a7 <wDev_ProcessRxSucData+0x347> */
  a11 = a3; /* 0398: mov.n a11, a3 */
  a12 = MEM32(a1 + 4); /* 039a: l32i.n a12, a1, 4 */
  a10 = a2; /* 039c: mov.n a10, a2 */
  a8 = (uint32_t)&wDev_IndicateAmpdu; /* 039e: l32r a8, 58 <wDev_ProcessRxSucData-0x8> (0 <wDev_ProcessRxSucData-0x60>) */ /* literal: GOT slot for wDev_IndicateAmpdu */
  wDev_IndicateAmpdu(a2, a3, a4, a5); /* call via literal slot */ /* 03a1: callx8 a8 */
  goto L_3e7; /* 03a4: j 3e7 <wDev_ProcessRxSucData+0x387> */
L_3a7:;
  a14 = MEM32(a1 + 4); /* 03a7: l32i.n a14, a1, 4 */
  a13 = a3; /* 03a9: mov.n a13, a3 */
  a12 = a2; /* 03ab: mov.n a12, a2 */
  a11 = a7; /* 03ad: mov.n a11, a7 */
  a10 = a4 | a4; /* 03af: or a10, a4, a4 */
  a8 = (uint32_t)&wDev_IndicateFrame; /* 03b2: l32r a8, 5c <wDev_ProcessRxSucData-0x4> (0 <wDev_ProcessRxSucData-0x60>) */ /* literal: GOT slot for wDev_IndicateFrame */
  wDev_IndicateFrame(a2, a3, a4, a5); /* call via literal slot */ /* 03b5: callx8 a8 */
  goto L_3e7; /* 03b8: j 3e7 <wDev_ProcessRxSucData+0x387> */
  /* 03bb: .byte 00 */
L_3bc:;
  a11 = a4; /* 03bc: mov.n a11, a4 */
L_3be:;
  a8 = a4; /* 03be: mov.n a8, a4 */
L_3c0:;
  a6 = MEM32(a1 + 0); /* 03c0: l32i.n a6, a1, 0 */
  if (a6 == 0) goto L_3d4; /* 03c2: beqz.n a6, 3d4 <wDev_ProcessRxSucData+0x374> */
  goto L_324; /* 03c4: j 324 <wDev_ProcessRxSucData+0x2c4> */
  /* 03c7: .byte 00 */
  /* 03c8: .byte 00 */
L_3c9:;
  a6 = a4; /* 03c9: mov.n a6, a4 */
  a8 = 0x1; /* 03cb: movi.n a8, 1 */
L_3cd:;
  a9 = MEM32(a1 + 0); /* 03cd: l32i.n a9, a1, 0 */
  if (a9 == 0) goto L_322; /* 03cf: beqz a9, 322 <wDev_ProcessRxSucData+0x2c2> */
  a11 = a4; /* 03d2: mov.n a11, a4 */
L_3d4:;
  a4 = a11; /* 03d4: mov.n a4, a11 */
  goto L_324; /* 03d6: j 324 <wDev_ProcessRxSucData+0x2c4> */
L_3d9:;
  a9 = MEM32(a1 + 0); /* 03d9: l32i.n a9, a1, 0 */
  a8 = 0x0; /* 03db: movi.n a8, 0 */
  a6 = 0x1; /* 03dd: movi.n a6, 1 */
  if (a9 != 0) a6 = a8; /* 03df: movnez a6, a8, a9 */
  a8 = a4; /* 03e2: mov.n a8, a4 */
  goto L_322; /* 03e4: j 322 <wDev_ProcessRxSucData+0x2c2> */
L_3e7:;
  return (int32_t)a2; /* 03e7: retw.n  */
}

/* wdevProcessRxSucDataAll @ wdev.o 00000030 size 207B bind GLOBAL
 * Calls: hal_mac_rx_get_last_dscr[got], wifi_assert[got], .rodata.__FUNCTION__$2[got], wDev_ProcessRxSucData[got], wDev_ProcessRxSucData[got], hal_mac_rx_get_last_dscr[got], wifi_assert[got] | Data refs: hal_mac_rx_get_last_dscr, g_wdev_last_desc_reset, wDevCtrl, .rodata.__FUNCTION__$2, .rodata.str1.1, wifi_assert, g_osi_funcs_p, g_intr_lock_mux, wDev_ProcessRxSucData
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 7 call(s), 9 data ref(s)
 * Fidelity: medium - 81 instr, 8 branches, calls resolved */
int32_t wdevProcessRxSucDataAll(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .wifislprxiram.28; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_30:;
  /* 0030: entry a1, 48 */
  a8 = (uint32_t)&hal_mac_rx_get_last_dscr; /* 0033: l32r a8, 1c <wdevProcessRxSucDataAll-0x14> (0 <wdevProcessRxSucDataAll-0x30>) */ /* literal: GOT slot for hal_mac_rx_get_last_dscr */
  hal_mac_rx_get_last_dscr(a2, a3, a4, a5); /* call via literal slot */ /* 0036: callx8 a8 */
  a6 = (uint32_t)&g_wdev_last_desc_reset; /* 0039: l32r a6, 4 <wdevProcessRxSucDataAll-0x2c> (0 <wdevProcessRxSucDataAll-0x30>) */ /* literal @0x4: g_wdev_last_desc_reset */
  a4 = a10; /* 003c: mov.n a4, a10 */
  a3 = (uint32_t)&wDevCtrl; /* 003e: l32r a3, 0 <wdevProcessRxSucDataAll-0x30> (0 <wdevProcessRxSucDataAll-0x30>) */ /* literal @0x0: wDevCtrl */
  a5 = MEM8(a6 + 0); /* 0041: l8ui a5, a6, 0 */
  a3 = MEM32(a3 + 0); /* 0044: l32i.n a3, a3, 0 */
  if (a5 == 0) goto L_58; /* 0046: beqz.n a5, 58 <wdevProcessRxSucDataAll+0x28> */
  if (a10 == 0) goto L_6c; /* 0048: beqz.n a10, 6c <wdevProcessRxSucDataAll+0x3c> */
  a5 = 0x0; /* 004a: movi.n a5, 0 */
  MEM8(a6 + 0) = a5; /* 004c: s8i a5, a6, 0 */
  MEMW(); /* 004f: memw  */
  MEMW(); /* 0052: memw  */
  goto L_6c; /* 0055: j 6c <wdevProcessRxSucDataAll+0x3c> */
L_58:;
  a10 = 0x1; /* 0058: movi.n a10, 1 */
  a13 = 0x971; /* 005a: l32r a13, 8 <wdevProcessRxSucDataAll-0x28> (971 <wDev_ProcessFiq+0x8fd>) */ @0x8
  if (a4 == 0) a10 = a5; /* 005d: moveqz a10, a5, a4 */
  a12 = (uint32_t)&lit_rodata_FUNCTION_2; /* 0060: l32r a12, c <wdevProcessRxSucDataAll-0x24> (0 <wdevProcessRxSucDataAll-0x30>) */ /* literal @0xC: .rodata.__FUNCTION__$2 */
  a11 = (uint32_t)&lit_rodata_str1_1; /* 0063: l32r a11, 10 <wdevProcessRxSucDataAll-0x20> (0 <wdevProcessRxSucDataAll-0x30>) */ /* literal @0x10: .rodata.str1.1 */
  a8 = (uint32_t)&wifi_assert; /* 0066: l32r a8, 20 <wdevProcessRxSucDataAll-0x10> (0 <wdevProcessRxSucDataAll-0x30>) */ /* literal: GOT slot for wifi_assert */
  wifi_assert(a2, a3, a4, a5); /* call via literal slot */ /* 0069: callx8 a8 */
L_6c:;
  a5 = 0x0; /* 006c: movi.n a5, 0 */
  a6 = (uint32_t)&g_osi_funcs_p; /* 006e: l32r a6, 18 <wdevProcessRxSucDataAll-0x18> (0 <wdevProcessRxSucDataAll-0x30>) */ /* literal @0x18: g_osi_funcs_p */
  a8 = (uint32_t)&g_intr_lock_mux; /* 0071: l32r a8, 14 <wdevProcessRxSucDataAll-0x1c> (0 <wdevProcessRxSucDataAll-0x30>) */ /* literal @0x14: g_intr_lock_mux */
  a7 = MEM32(a6 + 0); /* 0074: l32i.n a7, a6, 0 */
  a10 = MEM32(a8 + 0); /* 0076: l32i.n a10, a8, 0 */
  a7 = MEM32(a7 + 40); /* 0078: l32i.n a7, a7, 40 */
  ((int32_t(*)())a7)(a2, a3, a4, a5); /* 007a: callx8 a7 */ /* indirect */
  a7 = a10; /* 007d: mov.n a7, a10 */
  goto L_ec; /* 007f: j ec <wdevProcessRxSucDataAll+0xbc> */
L_82:;
  a8 = MEM32(a3 + 8); /* 0082: l32i.n a8, a3, 8 */
  MEMW(); /* 0084: memw  */
  a10 = MEM32(a3 + 0); /* 0087: l32i.n a10, a3, 0 */
  MEM32(a1 + 0) = a8; /* 0089: s32i.n a8, a1, 0 */
  a8 = a5 + (1); /* 008b: addi.n a8, a5, 1 */
  a5 = (a8 >> 0) & 0xFFFF; /* 008d: extui a5, a8, 0, 16 */
  if (!((a10 >> 30) & 1)) goto L_c0; /* 0090: bbci a10, 30, c0 <wdevProcessRxSucDataAll+0x90> */
  a11 = a7; /* 0093: mov.n a11, a7 */
  a8 = (uint32_t)&g_intr_lock_mux; /* 0095: l32r a8, 14 <wdevProcessRxSucDataAll-0x1c> (0 <wdevProcessRxSucDataAll-0x30>) */ /* literal @0x14: g_intr_lock_mux */
  a10 = MEM32(a6 + 0); /* 0098: l32i.n a10, a6, 0 */
  a12 = MEM32(a10 + 44); /* 009a: l32i.n a12, a10, 44 */
  a10 = MEM32(a8 + 0); /* 009c: l32i.n a10, a8, 0 */
  MEMW(); /* 009e: memw  */
  lit_rodata_FUNCTION_2(a2, a3, a4, a5); /* call via literal slot */ /* 00a1: callx8 a12 */
  a11 = a5; /* 00a4: mov.n a11, a5 */
  a12 = a2; /* 00a6: mov.n a12, a2 */
  a10 = a3; /* 00a8: mov.n a10, a3 */
  a8 = (uint32_t)&wDev_ProcessRxSucData; /* 00aa: l32r a8, 24 <wdevProcessRxSucDataAll-0xc> (0 <wdevProcessRxSucDataAll-0x30>) */ /* literal: GOT slot for wDev_ProcessRxSucData */
  wDev_ProcessRxSucData(a2, a3, a4, a5); /* call via literal slot */ /* 00ad: callx8 a8 */
  a8 = MEM32(a6 + 0); /* 00b0: l32i.n a8, a6, 0 */
  a5 = (uint32_t)&g_intr_lock_mux; /* 00b2: l32r a5, 14 <wdevProcessRxSucDataAll-0x1c> (0 <wdevProcessRxSucDataAll-0x30>) */ /* literal @0x14: g_intr_lock_mux */
  a8 = MEM32(a8 + 40); /* 00b5: l32i.n a8, a8, 40 */
  a10 = MEM32(a5 + 0); /* 00b7: l32i.n a10, a5, 0 */
  a5 = 0x0; /* 00b9: movi.n a5, 0 */
  wDev_ProcessRxSucData(a2, a3, a4, a5); /* call via literal slot */ /* 00bb: callx8 a8 */
  a7 = a10; /* 00be: mov.n a7, a10 */
L_c0:;
  if (a3 == a4) goto L_ef; /* 00c0: beq a3, a4, ef <wdevProcessRxSucDataAll+0xbf> */
  a8 = (uint32_t)&hal_mac_rx_get_last_dscr; /* 00c3: l32r a8, 28 <wdevProcessRxSucDataAll-0x8> (0 <wdevProcessRxSucDataAll-0x30>) */ /* literal: GOT slot for hal_mac_rx_get_last_dscr */
  hal_mac_rx_get_last_dscr(a2, a3, a4, a5); /* call via literal slot */ /* 00c6: callx8 a8 */
  a8 = (uint32_t)&g_wdev_last_desc_reset; /* 00c9: l32r a8, 4 <wdevProcessRxSucDataAll-0x2c> (0 <wdevProcessRxSucDataAll-0x30>) */ /* literal @0x4: g_wdev_last_desc_reset */
  a4 = a10; /* 00cc: mov.n a4, a10 */
  a3 = MEM8(a8 + 0); /* 00ce: l8ui a3, a8, 0 */
  if (a3 != 0) goto L_ea; /* 00d1: bnez.n a3, ea <wdevProcessRxSucDataAll+0xba> */
  a13 = 0x265; /* 00d3: movi a13, 0x265 */
  a10 = 0x1; /* 00d6: movi.n a10, 1 */
  a12 = (uint32_t)&lit_rodata_FUNCTION_2; /* 00d8: l32r a12, c <wdevProcessRxSucDataAll-0x24> (0 <wdevProcessRxSucDataAll-0x30>) */ /* literal @0xC: .rodata.__FUNCTION__$2 */
  a13 = 0x994; /* 00db: slli a13, a13, 2 */
  if (a4 == 0) a10 = a3; /* 00de: moveqz a10, a3, a4 */
  a11 = (uint32_t)&lit_rodata_str1_1; /* 00e1: l32r a11, 10 <wdevProcessRxSucDataAll-0x20> (0 <wdevProcessRxSucDataAll-0x30>) */ /* literal @0x10: .rodata.str1.1 */
  a8 = (uint32_t)&wifi_assert; /* 00e4: l32r a8, 2c <wdevProcessRxSucDataAll-0x4> (0 <wdevProcessRxSucDataAll-0x30>) */ /* literal: GOT slot for wifi_assert */
  wifi_assert(a2, a3, a4, a5); /* call via literal slot */ /* 00e7: callx8 a8 */
L_ea:;
  a3 = MEM32(a1 + 0); /* 00ea: l32i.n a3, a1, 0 */
L_ec:;
  if (a3 != 0) goto L_82; /* 00ec: bnez a3, 82 <wdevProcessRxSucDataAll+0x52> */
L_ef:;
  a2 = MEM32(a6 + 0); /* 00ef: l32i.n a2, a6, 0 */
  a11 = a7; /* 00f1: mov.n a11, a7 */
  a3 = (uint32_t)&g_intr_lock_mux; /* 00f3: l32r a3, 14 <wdevProcessRxSucDataAll-0x1c> (0 <wdevProcessRxSucDataAll-0x30>) */ /* literal @0x14: g_intr_lock_mux */
  a2 = MEM32(a2 + 44); /* 00f6: l32i.n a2, a2, 44 */
  a10 = MEM32(a3 + 0); /* 00f8: l32i.n a10, a3, 0 */
  ((int32_t(*)())a2)(a2, a3, a4, a5); /* 00fa: callx8 a2 */ /* indirect */
  return (int32_t)a2; /* 00fd: retw.n  */
}

/* wDev_Insert_KeyEntry @ wdev.o 00000010 size 114B bind GLOBAL
 * Calls: hal_crypto_enable, hal_crypto_set_key_entry, memcpy | Data refs: hal_crypto_enable, hal_crypto_set_key_entry, memcpy, wDevCtrl
 *   MMIO: none
 *   funcdb v3: 3 call(s), 4 ref(s); disasm: 3 call(s), 4 data ref(s)
 * Fidelity: medium - 44 instr, 2 branches, calls resolved */
int32_t wDev_Insert_KeyEntry(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.wDev_Insert_KeyEntry; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_10:;
  /* 0010: entry a1, 64 */
  a8 = MEM8(a1 + 72); /* 0013: l8ui a8, a1, 72 */
  a9 = a7; /* 0016: mov.n a9, a7 */
  a12 = 0x6; /* 0018: movi.n a12, 6 */
  a11 = a5; /* 001a: mov.n a11, a5 */
  a3 = (a3 >> 0) & 0xFF; /* 001c: extui a3, a3, 0, 8 */
  a10 = a1 + (3); /* 001f: addi.n a10, a1, 3 */
  MEM32(a1 + 20) = a8; /* 0021: s32i.n a8, a1, 20 */
  MEM32(a1 + 16) = a9; /* 0023: s32i.n a9, a1, 16 */
  a7 = MEM8(a1 + 68); /* 0025: l8ui a7, a1, 68 */
  MEM8(a1 + 1) = a2; /* 0028: s8i a2, a1, 1 */
  MEM8(a1 + 0) = a3; /* 002b: s8i a3, a1, 0 */
  MEM8(a1 + 2) = a4; /* 002e: s8i a4, a1, 2 */
  MEMW(); /* 0031: memw  */
  MEMW(); /* 0034: memw  */
  a8 = (uint32_t)&memcpy; /* 0037: l32r a8, 4 <wDev_Insert_KeyEntry-0xc> (0 <wDev_Insert_KeyEntry-0x10>) */ /* literal: GOT slot for memcpy */
  memcpy(a2, a3, a4, a5); /* call via literal slot */ /* 003a: callx8 a8 */
  a13 = a1; /* 003d: mov.n a13, a1 */
  a10 = a6; /* 003f: mov.n a10, a6 */
  a9 = MEM32(a1 + 16); /* 0041: l32i.n a9, a1, 16 */
  a11 = a9; /* 0043: mov.n a11, a9 */
  a12 = MEM32(a1 + 64); /* 0045: l32i a12, a1, 64 */
  a8 = (uint32_t)&hal_crypto_set_key_entry; /* 0048: l32r a8, 8 <wDev_Insert_KeyEntry-0x8> (0 <wDev_Insert_KeyEntry-0x10>) */ /* literal: GOT slot for hal_crypto_set_key_entry */
  hal_crypto_set_key_entry(a2, a3, a4, a5); /* call via literal slot */ /* 004b: callx8 a8 */
  a8 = MEM32(a1 + 20); /* 004e: l32i.n a8, a1, 20 */
  if (a3 >= 3) goto L_6d; /* 0050: bgeui a3, 3, 6d <wDev_Insert_KeyEntry+0x5d> */
  if (a6 < 3) goto L_6d; /* 0053: blti a6, 3, 6d <wDev_Insert_KeyEntry+0x5d> */
  a3 = a3 + (4); /* 0056: addi.n a3, a3, 4 */
  a9 = (uint32_t)&wDevCtrl; /* 0058: l32r a9, 0 <wDev_Insert_KeyEntry-0x10> (0 <wDev_Insert_KeyEntry-0x10>) */ /* literal @0x0: wDevCtrl */
  a3 = (a3 << 4) + a9; /* 005b: addx4 a3, a3, a9 */
  a9 = 0x1; /* 005e: movi.n a9, 1 */
  /* 0060: ssl a6 */ /* UNMODELED: a6 clobbered */
  /* 0063: sll a9, a9 */ /* UNMODELED: a9 clobbered */
  a10 = MEM32(a3 + 12); /* 0066: l32i.n a10, a3, 12 */
  a10 = a10 | a9; /* 0068: or a10, a10, a9 */
  MEM32(a3 + 12) = a10; /* 006b: s32i.n a10, a3, 12 */
L_6d:;
  a13 = a8; /* 006d: mov.n a13, a8 */
  a12 = a7; /* 006f: mov.n a12, a7 */
  a11 = MEM8(a1 + 1); /* 0071: l8ui a11, a1, 1 */
  a10 = MEM8(a1 + 0); /* 0074: l8ui a10, a1, 0 */
  MEMW(); /* 0077: memw  */
  a8 = (uint32_t)&hal_crypto_enable; /* 007a: l32r a8, c <wDev_Insert_KeyEntry-0x4> (0 <wDev_Insert_KeyEntry-0x10>) */ /* literal: GOT slot for hal_crypto_enable */
  hal_crypto_enable(a2, a3, a4, a5); /* call via literal slot */ /* 007d: callx8 a8 */
  return (int32_t)a2; /* 0080: retw.n  */
}

/* wDev_remove_KeyEntry @ wdev.o 00000008 size 55B bind GLOBAL
 * Calls: hal_crypto_clr_key_entry | Data refs: hal_crypto_clr_key_entry, wDevCtrl
 *   MMIO: none
 *   funcdb v3: 1 call(s), 2 ref(s); disasm: 1 call(s), 2 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t wDev_remove_KeyEntry(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.wDev_remove_KeyEntry; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_8:;
  /* 0008: entry a1, 32 */
  a8 = (uint32_t)&wDevCtrl; /* 000b: l32r a8, 0 <wDev_remove_KeyEntry-0x8> (0 <wDev_remove_KeyEntry-0x8>) */ /* literal @0x0: wDevCtrl */
  a9 = 0xFFFFFFFE; /* 000e: movi.n a9, -2 */
  /* 0010: ssl a2 */ /* UNMODELED: a2 clobbered */
  /* 0013: src a9, a9, a9 */ /* UNMODELED: a9 clobbered */
  a10 = a2; /* 0016: mov.n a10, a2 */
  a11 = MEM32(a8 + 28); /* 0018: l32i.n a11, a8, 28 */
  a11 = a11 & a9; /* 001a: and a11, a11, a9 */
  MEM32(a8 + 28) = a11; /* 001d: s32i.n a11, a8, 28 */
  a11 = MEM32(a8 + 32); /* 001f: l32i.n a11, a8, 32 */
  a11 = a11 & a9; /* 0021: and a11, a11, a9 */
  MEM32(a8 + 32) = a11; /* 0024: s32i.n a11, a8, 32 */
  a11 = MEM32(a8 + 36); /* 0026: l32i.n a11, a8, 36 */
  a11 = a11 & a9; /* 0028: and a11, a11, a9 */
  MEM32(a8 + 36) = a11; /* 002b: s32i.n a11, a8, 36 */
  a11 = MEM32(a8 + 40); /* 002d: l32i.n a11, a8, 40 */
  a9 = a11 & a9; /* 002f: and a9, a11, a9 */
  MEM32(a8 + 40) = a9; /* 0032: s32i.n a9, a8, 40 */
  MEMW(); /* 0034: memw  */
  a8 = (uint32_t)&hal_crypto_clr_key_entry; /* 0037: l32r a8, 4 <wDev_remove_KeyEntry-0x4> (0 <wDev_remove_KeyEntry-0x8>) */ /* literal: GOT slot for hal_crypto_clr_key_entry */
  hal_crypto_clr_key_entry(a2, a3, a4, a5); /* call via literal slot */ /* 003a: callx8 a8 */
  return (int32_t)a2; /* 003d: retw.n  */
}

/* wDev_remove_KeyEntry_all_cnx @ wdev.o 00000008 size 45B bind GLOBAL
 * Calls: wDev_remove_KeyEntry | Data refs: wDevCtrl, wDev_remove_KeyEntry
 *   MMIO: none
 *   funcdb v3: 1 call(s), 2 ref(s); disasm: 1 call(s), 2 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t wDev_remove_KeyEntry_all_cnx(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.wDev_remove_KeyEntry_all_cnx; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_8:;
  /* 0008: entry a1, 32 */
  a8 = (uint32_t)&wDevCtrl; /* 000b: l32r a8, 0 <wDev_remove_KeyEntry_all_cnx-0x8> (0 <wDev_remove_KeyEntry_all_cnx-0x8>) */ /* literal @0x0: wDevCtrl */
  a2 = (a2 >> 0) & 0xFF; /* 000e: extui a2, a2, 0, 8 */
  a2 = (a2 << 4) + a8; /* 0011: addx4 a2, a2, a8 */
  a8 = 0xFFFFFFFF; /* 0014: movi.n a8, -1 */
  a3 = a8 ^ a3; /* 0016: xor a3, a8, a3 */
  a2 = MEM32(a2 + 28); /* 0019: l32i.n a2, a2, 28 */
  a3 = a3 & a2; /* 001b: and a3, a3, a2 */
  a2 = 0x0; /* 001e: movi a2, 0 */
L_21:;
  if (!((a3 >> (a2 & 31)) & 1)) goto L_2c; /* 0021: bbc a3, a2, 2c <wDev_remove_KeyEntry_all_cnx+0x24> */
  a10 = 0x0; /* 0024: mov.n a10, a2 */
  a8 = (uint32_t)&wDev_remove_KeyEntry; /* 0026: l32r a8, 4 <wDev_remove_KeyEntry_all_cnx-0x4> (0 <wDev_remove_KeyEntry_all_cnx-0x8>) */ /* literal: GOT slot for wDev_remove_KeyEntry */
  wDev_remove_KeyEntry(a2, a3, a4, a5); /* call via literal slot */ /* 0029: callx8 a8 */
L_2c:;
  a2 = a2 + (1); /* 002c: addi.n a2, a2, 1 */
  a8 = 0x19; /* 002e: movi.n a8, 25 */
  if (a2 != a8) goto L_21; /* 0030: bne a2, a8, 21 <wDev_remove_KeyEntry_all_cnx+0x19> */
  return (int32_t)a2; /* 0033: retw.n  */
}

/* wDev_Crypto_Disable @ wdev.o 00000008 size 31B bind GLOBAL
 * Calls: hal_crypto_disable | Data refs: hal_crypto_disable, wDevCtrl
 *   MMIO: none
 *   funcdb v3: 1 call(s), 2 ref(s); disasm: 1 call(s), 2 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t wDev_Crypto_Disable(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.wDev_Crypto_Disable; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_8:;
  /* 0008: entry a1, 32 */
  a9 = (uint32_t)&wDevCtrl; /* 000b: l32r a9, 0 <wDev_Crypto_Disable-0x8> (0 <wDev_Crypto_Disable-0x8>) */ /* literal @0x0: wDevCtrl */
  a10 = (a2 >> 0) & 0xFF; /* 000e: extui a10, a2, 0, 8 */
  a8 = a10 + (4); /* 0011: addi.n a8, a10, 4 */
  a8 = (a8 << 4) + a9; /* 0013: addx4 a8, a8, a9 */
  a9 = 0x0; /* 0016: movi.n a9, 0 */
  a11 = MEM32(a8 + 12); /* 0018: l32i.n a11, a8, 12 */
  MEM32(a8 + 12) = a9; /* 001a: s32i.n a9, a8, 12 */
  MEMW(); /* 001c: memw  */
  a8 = (uint32_t)&hal_crypto_disable; /* 001f: l32r a8, 4 <wDev_Crypto_Disable-0x4> (0 <wDev_Crypto_Disable-0x8>) */ /* literal: GOT slot for hal_crypto_disable */
  hal_crypto_disable(a2, a3, a4, a5); /* call via literal slot */ /* 0022: callx8 a8 */
  return (int32_t)a2; /* 0025: retw.n  */
}

/* wDevCheckBlockError @ wdev.o 0000001c size 108B bind GLOBAL
 * Calls: wifi_log[got], wifi_assert[got] | Data refs: .rodata_wlog_error.50, wifi_log, .rodata.__FUNCTION__$0, .rodata.str1.1, wifi_assert
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 2 call(s), 5 data ref(s)
 * Fidelity: medium - 43 instr, 6 branches, calls resolved */
int32_t wDevCheckBlockError(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .wifislprxiram.51; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_1c:;
  /* 001c: entry a1, 48 */
  a3 = MEM32(a2 + 44); /* 001f: l32i.n a3, a2, 44 */
  a3 = MEM32(a3 + 0); /* 0021: l32i.n a3, a3, 0 */
  if (!((a3 >> 4) & 1)) goto L_86; /* 0023: bbci a3, 4, 86 <wDevCheckBlockError+0x6a> */
  a3 = MEM32(a2 + 4); /* 0026: l32i.n a3, a2, 4 */
  goto L_83; /* 0028: j 83 <wDevCheckBlockError+0x67> */
  /* 002b: .byte 00 */
L_2c:;
  MEMW(); /* 002c: memw  */
  a8 = MEM32(a3 + 0); /* 002f: l32i.n a8, a3, 0 */
  a8 = (a8 >> 0) & 0xFFF; /* 0031: extui a8, a8, 0, 12 */
  a14 = MEM32(a3 + 4); /* 0034: l32i.n a14, a3, 4 */
  a8 = a14 + a8; /* 0036: add.n a8, a14, a8 */
  a11 = MEM32(a8 + 0); /* 0038: l32i.n a11, a8, 0 */
  a4 = 0xDEADBEEF; /* 003a: l32r a4, 0 <wDevCheckBlockError-0x1c> (deadbeef <wDev_ProcessFiq+0xdeadbe7b>) */ @0x0
  if (a11 == a4) goto L_7c; /* 003d: beq a11, a4, 7c <wDevCheckBlockError+0x60> */
  MEMW(); /* 0040: memw  */
  a10 = MEM32(a3 + 0); /* 0043: l32i.n a10, a3, 0 */
  a10 = (a10 >> 0) & 0xFFF; /* 0045: extui a10, a10, 0, 12 */
  a9 = 0xFFC; /* 0048: l32r a9, 4 <wDevCheckBlockError-0x18> (ffc <wDev_ProcessFiq+0xf88>) */ @0x4
  a9 = 0xFFC; /* 004b: extui a9, a9, 0, 16 */
  if (a10 == a9) goto L_7c; /* 004e: beq a10, a9, 7c <wDevCheckBlockError+0x60> */
  a12 = 0x1; /* 0051: movi.n a12, 1 */
  MEM32(a1 + 4) = a11; /* 0053: s32i.n a11, a1, 4 */
  a10 = 0x6; /* 0055: movi.n a10, 6 */
  a11 = 0x20; /* 0057: movi.n a11, 32 */
  MEM32(a1 + 0) = a8; /* 0059: s32i.n a8, a1, 0 */
  a13 = (uint32_t)&lit_rodata_wlog_error_50; /* 005b: l32r a13, 8 <wDevCheckBlockError-0x14> (0 <wDevCheckBlockError-0x1c>) */ /* literal @0x8: .rodata_wlog_error.50 */
  a15 = MEM32(a14 + 0); /* 005e: l32i.n a15, a14, 0 */
  MEMW(); /* 0060: memw  */
  a8 = (uint32_t)&wifi_log; /* 0063: l32r a8, 14 <wDevCheckBlockError-0x8> (0 <wDevCheckBlockError-0x1c>) */ /* literal: GOT slot for wifi_log */
  wifi_log(a2, a3, a4, a5); /* call via literal slot */ /* 0066: callx8 a8 */
  a13 = 0x6DB; /* 0069: movi a13, 0x6db */
  a13 = 0xDB6; /* 006c: add.n a13, a13, a13 */
  a12 = (uint32_t)&lit_rodata_FUNCTION_0; /* 006e: l32r a12, c <wDevCheckBlockError-0x10> (0 <wDevCheckBlockError-0x1c>) */ /* literal @0xC: .rodata.__FUNCTION__$0 */
  a10 = 0x0; /* 0071: movi.n a10, 0 */
  a11 = (uint32_t)&lit_rodata_str1_1; /* 0073: l32r a11, 10 <wDevCheckBlockError-0xc> (0 <wDevCheckBlockError-0x1c>) */ /* literal @0x10: .rodata.str1.1 */
  a8 = (uint32_t)&wifi_assert; /* 0076: l32r a8, 18 <wDevCheckBlockError-0x4> (0 <wDevCheckBlockError-0x1c>) */ /* literal: GOT slot for wifi_assert */
  wifi_assert(a2, a3, a4, a5); /* call via literal slot */ /* 0079: callx8 a8 */
L_7c:;
  a8 = MEM32(a2 + 8); /* 007c: l32i.n a8, a2, 8 */
  if (a8 == a3) goto L_86; /* 007e: beq a8, a3, 86 <wDevCheckBlockError+0x6a> */
  a3 = MEM32(a3 + 8); /* 0081: l32i.n a3, a3, 8 */
L_83:;
  if (a3 != 0) goto L_2c; /* 0083: bnez a3, 2c <wDevCheckBlockError+0x10> */
L_86:;
  return (int32_t)a2; /* 0086: retw.n  */
}

/* wdev_set_csi_rx_cb @ wdev.o 00000008 size 20B bind GLOBAL
 * Calls: none | Data refs: g_wdev_csi_rx, g_wdev_csi_rx_ctx
 *   MMIO: none
 *   funcdb v3: 0 call(s), 2 ref(s); disasm: 0 call(s), 2 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t wdev_set_csi_rx_cb(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.wdev_set_csi_rx_cb; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_8:;
  /* 0008: entry a1, 32 */
  a8 = (uint32_t)&g_wdev_csi_rx; /* 000b: l32r a8, 0 <wdev_set_csi_rx_cb-0x8> (0 <wdev_set_csi_rx_cb-0x8>) */ /* literal @0x0: g_wdev_csi_rx */
  MEM32(a8 + 0) = a2; /* 000e: s32i.n a2, a8, 0 */
  a2 = 0x0; /* 0010: movi.n a2, 0 */
  a8 = (uint32_t)&g_wdev_csi_rx_ctx; /* 0012: l32r a8, 4 <wdev_set_csi_rx_cb-0x4> (0 <wdev_set_csi_rx_cb-0x8>) */ /* literal @0x4: g_wdev_csi_rx_ctx */
  MEM32(a8 + 0) = a3; /* 0015: s32i.n a3, a8, 0 */
  MEMW(); /* 0017: memw  */
  return (int32_t)a2; /* 001a: retw.n  */
}

/* wdev_is_mgmt_hwdecr_enabled @ wdev.o 00000004 size 16B bind GLOBAL
 * Calls: hal_crypto_mgmt_rx_enabled | Data refs: hal_crypto_mgmt_rx_enabled
 *   MMIO: none
 *   funcdb v3: 1 call(s), 1 ref(s); disasm: 1 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t wdev_is_mgmt_hwdecr_enabled(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.wdev_is_mgmt_hwdecr_enabled; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a10 = (a2 >> 0) & 0xFF; /* 0007: extui a10, a2, 0, 8 */
  a8 = (uint32_t)&hal_crypto_mgmt_rx_enabled; /* 000a: l32r a8, 0 <wdev_is_mgmt_hwdecr_enabled-0x4> (0 <wdev_is_mgmt_hwdecr_enabled-0x4>) */ /* literal: GOT slot for hal_crypto_mgmt_rx_enabled */
  hal_crypto_mgmt_rx_enabled(a2, a3, a4, a5); /* call via literal slot */ /* 000d: callx8 a8 */
  a2 = a10; /* 0010: mov.n a2, a10 */
  return (int32_t)a2; /* 0012: retw.n  */
}

