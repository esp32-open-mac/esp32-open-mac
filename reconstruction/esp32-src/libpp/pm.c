/* ===== pm.o : reconstructed from libpp.a (ESP32, Xtensa, esp-2022r1) =====
 * Toolchain: xtensa-esp32-elf (GCC 11.2.0 crosstool-NG esp-2022r1).
 * ABI: args a2..a7, return a2 (all functions take a2..a7, return int32_t).
 * memw barriers preserved as MEMW(). MMIO as REG32/REG16/REG8(addr).
 * Calls with unknown arg counts are modeled with 4 live args (a2..a5);
 * a2..a7 are clobbered across calls (windowed-ABI approximation).
 * Sections: .iram1.7, .text.hal_pm_unblock_txq, .text.is_off_channel, .text.pm_active_timeout, .text.pm_active_timeout_process, .text.pm_allow_to_enable_bcn_filter, .text.pm_allow_tx, .text.pm_attach, .text.pm_beacon_add_loss_counter, .text.pm_beacon_add_total_counter, .text.pm_beacon_loss_info_clean, .text.pm_beacon_loss_info_get, .text.pm_beacon_misc_process, .text.pm_beacon_monitor_configure, .text.pm_beacon_monitor_init, .text.pm_beacon_monitor_tbtt_timeout, .text.pm_beacon_monitor_timeout, .text.pm_beacon_timestamp_statistic, .text.pm_coex_go_to_sleep, .text.pm_coex_restart_timeout, .text.pm_coex_restart_timeout_process, .text.pm_coex_schm_process, .text.pm_coex_schm_process_restart, .text.pm_coex_separate_connectionless_window, .text.pm_coex_slice_timeout_process, .text.pm_coex_slice_wifi_timeout, .text.pm_coex_tbtt_process, .text.pm_connectionless_module_set_wake_interval, .text.pm_connectionless_wake_interval_timeout, .text.pm_connectionless_wake_window_timeout, .text.pm_deattach, .text.pm_disable_active_timer, .text.pm_disable_disconnected_sleep_delay_timer, .text.pm_disable_keep_alive_timer, .text.pm_disconnected_sleep, .text.pm_disconnected_sleep_delay_timeout, .text.pm_disconnected_sleep_delay_timeout_process, .text.pm_disconnected_start, .text.pm_disconnected_stop, .text.pm_disconnected_wake, .text.pm_dream_timeout, .text.pm_dream_timeout_process, .text.pm_enable_disconnected_sleep_delay_timer, .text.pm_enable_keep_alive_timer, .text.pm_enable_send_wake_null_on_channel, .text.pm_enable_sleep_delay_timer, .text.pm_enable_sta_disconnected_power_management, .text.pm_force_scan_unlock, .text.pm_get_beacon_duration, .text.pm_get_idle_wait_time, .text.pm_get_keep_alive_time, .text.pm_get_sleep_type, .text.pm_get_tx_blocks_retention_mask, .text.pm_go_to_sleep, .text.pm_go_to_wake, .text.pm_illegal_beacon_logger, .text.pm_incr_coex_active_cnt, .text.pm_is_dream, .text.pm_is_force_return_home_chan, .text.pm_is_in_wifi_slice_threshold, .text.pm_is_open, .text.pm_is_sending_keep_alive, .text.pm_is_sleeping, .text.pm_keep_alive_timeout, .text.pm_keep_alive_timeout_process, .text.pm_mac_sleep, .text.pm_mac_sleep_deinit, .text.pm_mac_sleep_init, .text.pm_mac_wakeup, .text.pm_mesh_set_next_tbtt, .text.pm_noise_check, .text.pm_noise_check_disable, .text.pm_noise_check_enable, .text.pm_noise_check_process, .text.pm_off_channel, .text.pm_offchan_execute_ready_cb, .text.pm_offchan_is_waiting, .text.pm_offchan_ready_or_defer, .text.pm_on_channel, .text.pm_on_coex_schm_process_restart, .text.pm_on_coex_schm_status_config, .text.pm_on_coex_start, .text.pm_on_data_tx_done, .text.pm_on_probe_resp_rx, .text.pm_on_sample_beacon, .text.pm_pend_noise_check, .text.pm_register_connectionless_wake_window, .text.pm_register_pm_tx_null_cb, .text.pm_scan_lock, .text.pm_scan_unlock, .text.pm_send_nullfunc, .text.pm_send_probe_start, .text.pm_send_probe_stop, .text.pm_send_sleep_null_cb, .text.pm_send_wake_null_cb, .text.pm_set_bss_max_idle, .text.pm_set_keep_alive_time, .text.pm_set_next_tbtt, .text.pm_set_sleep_min_active_time, .text.pm_set_sleep_type, .text.pm_set_sleep_wait_broadcast_data_time, .text.pm_set_state, .text.pm_sleep_delay_timeout, .text.pm_sleep_delay_timeout_process, .text.pm_start, .text.pm_stop, .text.pm_tbtt_quick_wake_configure, .text.pm_tbtt_timeout, .text.pm_try_scan_unlock, .text.pm_tx_data_done_process, .text.pm_tx_null_data_done_process, .text.pm_tx_null_data_done_quick_wake_process, .text.pm_unregister_connectionless_wake_window, .text.pm_update_at_next_beacon, .text.pm_update_light_sleep_default_params, .text.pm_update_modem_sleep_default_params, .text.pm_update_params, .text.pm_wake_done, .text.pm_wake_up, .text.wifi_pm_sleep_lock_acquire, .text.wifi_pm_sleep_lock_release, .wifiextrairam.48, .wifiextrairam.56, .wifirxiram.17, .wifirxiram.49, .wifirxiram.50, .wifirxiram.55, .wifislpiram.18, .wifislpiram.19, .wifislpiram.21, .wifislpiram.36, .wifislpiram.38, .wifislpiram.4, .wifislpiram.43, .wifislpiram.44, .wifislprxiram.12, .wifislprxiram.2, .wifislprxiram.20, .wifislprxiram.22, .wifislprxiram.23, .wifislprxiram.24, .wifislprxiram.25, .wifislprxiram.26, .wifislprxiram.27, .wifislprxiram.28, .wifislprxiram.29, .wifislprxiram.3, .wifislprxiram.30, .wifislprxiram.31, .wifislprxiram.34, .wifislprxiram.40, .wifislprxiram.41, .wifislprxiram.42, .wifislprxiram.46, .wifislprxiram.47, .wifislprxiram.5, .wifislprxiram.54, .wifislprxiram.62
 * Undefined refs (44): __divsf3, __extendsfdf2, __floatundisf, __udivdi3, __umoddi3, dbg_lmac_ps_statis_reset, esp_mesh_get_running_active_duty_cycle, esp_mesh_quick_funcs, esp_wifi_get_mode, g_ic, g_intr_lock_mux, g_mesh_init_ps_type, g_mesh_is_root, g_mesh_is_started, g_osi_funcs_p, g_pm_cnt, g_wifi_mac_time_delta, ieee80211_hostapd_beacon_txcb, memcmp, memcpy, memset, noise_check_loop, pm_coex_pwr_update, pm_coex_schm_overall_period_get...

 * POWER-MANAGEMENT SLEEP/WAKE STATE MACHINE (call-sequence level):
 * States (mutated in the g_pm struct via s8i/s32i, committed with a static
 * pm_set_state notify call - see per-caller a2/struct + store windows below):
 *   pm_start / pm_stop ......... attach/detach modem-sleep (enable/disable
 *                                dream/active/sleep-delay/keep-alive/beacon-
 *                                monitor timers; phy enable/disable)
 *   pm_go_to_sleep .............. gate: ppCheckTxQIdle && ppCheckTxIdle &&
 *                                !offchan_waiting; -> pm_sleep_for -> wdev_mac_sleep
 *                                + pm_mac_sleep + wifi_rf_phy_disable
 *   pm_go_to_wake / pm_wake_up ... wifi_rf_phy_enable + wdev_mac_wakeup +
 *                                pm_mac_wakeup + pm_wake_done
 *   pm_dream .................... light/deep sleep entry; pm_dream_timeout_process
 *                                re-arms; pm_is_dream predicate
 *   pm_sleep / pm_sleep_for ..... timed sleep window computation
 *   pm_tbtt_process ............. TBTT ISR path: pm_handle_tbtt_interval,
 *                                pm_update_next_tbtt/pm_set_next_tbtt,
 *                                pm_save_tbtt_info, beacon-monitor TBTT
 *                                start/stop/allowed, coex schm restart
 *   pm_rx_beacon_process ........ pm_parse_beacon (beacon interval/DTIM/TIM
 *                                IE validation + illegal-beacon logger) ->
 *                                pm_process_tim -> pm_tx_data_process /
 *                                ppProcessWaitingQueue; pm_on_beacon_rx stats
 *   pm_tx_data_process .......... pm_allow_tx gate; null-data done callbacks
 *                                (pm_tx_null_data_done_process +
 *                                quick-wake variant), keep-alive send
 *                                (pm_send_nullfunc, pm_keep_alive_timeout_process)
 *   pm_coex_* ................... BT/WiFi slice scheduler: pm_coex_schm_process
 *                                (+restart), pm_coex_go_to_sleep, pm_coex_tbtt_process,
 *                                connectionless window split
 *                                (pm_coex_separate_connectionless_window),
 *                                pm_on_coex_* config hooks
 *   pm_off_channel .............. pm_offchan_ready_or_defer / is_waiting /
 *                                execute_ready_cb; scan lock/unlock; forced
 *                                home-channel return; probe start/stop
 *   pm_beacon_monitor_* ......... loss/total counters, miss-exceeded ->
 *                                wakeup-disabled, noise check
 *                                (pm_noise_check -> read_hw_noisefloor via
 *                                noise_check_loop), tbtt count (64-bit div
 *                                via __udivdi3/__umoddi3), listen-interval
 *                                scaling (float via __extendsfdf2/__divsf3).
 * Timer fan-out: pp_timer_* wrappers (pp_timer.o) -> pm_*_timeout_process.

 * pm_set_state call sites (a2 = struct ptr; state via struct stores):
 *   pm_dream+0x15e: a2 forwarded; stores: [(339, 's8i', 'a3, a2, 24')]
 *   pm_disconnected_wake+0x4a: a2 <= l32r a2, 4 <pm_disconnected_wake-0x18> (0 <pm_disconnected_wake-0x1c>) @0x2b (&g_mesh_is_started); stores: [(65, 's8i', 'a8, a3, 29')]
 *   pm_sleep+0x21f: a2 forwarded; stores: [(516, 's32i.n', 'a8, a3, 60'), (534, 's32i', 'a2, a3, 64'), (537, 's32i', 'a8, a3, 68')]
 *   pm_check_state+0x4a: a2 <= movi.n a2, 0 @0x3a; stores: none
 *   pm_go_to_sleep+0x3f: a2 <= l32r a2, 0 <pm_go_to_sleep-0x28> (0 <pm_go_to_sleep-0x28>) @0x34 (&g_pm); stores: none
 *   pm_tx_null_data_done_process+0x1d6: a2 <= movi.n a2, 0 @0x1b3; stores: [(418, 's8i', 'a2, a6, 200'), (423, 's8i', 'a2, a5, 19'), (461, 's8i', 'a2, a5, 18')]
 *   pm_stop+0xd0: a2 forwarded; stores: [(186, 's16i', 'a3, a2, 26')]
 *   pm_attach+0xa2: a2 <= l32r a2, 0 <pm_attach-0x84> (0 <pm_attach-0x84>) @0x87 (&g_pm); stores: [(157, 's32i.n', 'a5, a2, 36')]
 *   pm_set_sleep_type+0xb0: a2 forwarded; stores: [(121, 's32i.n', 'a2, a3, 36')]
 */
#include <stdint.h>
#define REG32(a) (*(volatile uint32_t *)(a))
#define REG16(a) (*(volatile uint16_t *)(a))
#define REG8(a)  (*(volatile uint8_t *)(a))
#define MEM32(a) (*(volatile uint32_t *)(a))
#define MEM16(a) (*(volatile uint16_t *)(a))
#define MEM8(a)  (*(volatile uint8_t *)(a))
#define MEMW() __asm__ volatile("memw" ::: "memory")

extern int32_t wifi_log();
extern int32_t wifi_gpio_debug();
extern int32_t pp_timer_process();
extern int32_t g_pm();
extern int32_t g_mesh_is_started();
extern uint32_t g_mesh_is_root; /* g_mesh_is_root */
extern int32_t g_mesh_init_ps_type();
extern int32_t memcmp();
extern int32_t wdev_mac_sleep_init();
extern int32_t wdev_mac_sleep_deinit();
extern int32_t g_pm_cfg();
extern int32_t g_osi_funcs_p();
extern int32_t noise_check_loop();
extern int32_t read_hw_noisefloor();
extern uint32_t wDevCtrl; /* wDevCtrl */
extern int32_t bss_g_pm_tx_null_func();
extern int32_t wdev_mac_wakeup();
extern int32_t wdev_mac_sleep();
extern int32_t udivdi3();
extern int32_t pm_coex_schm_overall_period_get();
extern int32_t ptr_beacon_offset_funcs();
extern uint32_t bss_beacon_monitor_data_0; /* .bss.beacon_monitor_data$0 (verify defined-here with nm) */
extern int32_t wifi_rf_phy_enable();
extern int32_t esp_wifi_get_mode();
extern int32_t g_pm_cnt();
extern int32_t ppCheckTxQIdle();
extern int32_t ppCheckTxIdle();
extern int32_t wifi_rf_phy_disable();
extern uint32_t bss_g_offchan_ready_cb; /* .bss.g_offchan_ready_cb (verify defined-here with nm) */
extern uint32_t rodata_wlog_debug_33; /* .rodata_wlog_debug.33 */
extern uint32_t bss_g_offchan_ready_ctx; /* .bss.g_offchan_ready_ctx (verify defined-here with nm) */
extern int32_t wifi_event_post();
extern int32_t esp_mesh_quick_funcs();
extern uint32_t g_intr_lock_mux; /* g_intr_lock_mux */
extern uint32_t rodata_wlog_warning_35; /* .rodata_wlog_warning.35 */
extern uint32_t rodata_str1_1; /* .rodata.str1.1 */
extern uint32_t rodata_wlog_error_37; /* .rodata_wlog_error.37 */
extern int32_t umoddi3();
extern uint32_t g_wifi_mac_time_delta; /* g_wifi_mac_time_delta */
extern uint32_t rodata_wlog_warning_39; /* .rodata_wlog_warning.39 */
extern int32_t ppCheckTxConnTrafficIdle();
extern int32_t sta_reset_beacon_timeout();
extern uint32_t g_ic; /* g_ic */
extern uint32_t rodata_wlog_debug_51; /* .rodata_wlog_debug.51 */
extern uint32_t rodata_pm_tx_null_data_done_process_str1_1; /* .rodata.pm_tx_null_data_done_process.str1.1 */
extern uint32_t rodata_wlog_debug_52; /* .rodata_wlog_debug.52 */
extern int32_t ppProcessWaitingQueue();
extern uint32_t rodata_wlog_error_32; /* .rodata_wlog_error.32 */
extern uint32_t rodata_wlog_debug_45; /* .rodata_wlog_debug.45 */
extern uint32_t rodata_wlog_info_53; /* .rodata_wlog_info.53 */
extern int32_t wifi_nvs_get_sta_listen_interval();
extern uint32_t rodata_wlog_info_6; /* .rodata_wlog_info.6 */
extern int32_t pm_coex_pwr_update();
extern uint32_t rodata_wlog_info_13; /* .rodata_wlog_info.13 */
extern uint32_t rodata_wlog_info_14; /* .rodata_wlog_info.14 */
extern uint32_t rodata_wlog_info_15; /* .rodata_wlog_info.15 */
extern uint32_t rodata_wlog_info_16; /* .rodata_wlog_info.16 */
extern uint32_t rodata_wlog_info_57; /* .rodata_wlog_info.57 */
extern int32_t memcpy();
extern int32_t dbg_lmac_ps_statis_reset();
extern uint32_t rodata_wlog_info_58; /* .rodata_wlog_info.58 */
extern int32_t esp_mesh_get_running_active_duty_cycle();
extern int32_t floatundisf();
extern int32_t divsf3();
extern int32_t extendsfdf2();
extern uint32_t rodata_wlog_info_59; /* .rodata_wlog_info.59 */
extern int32_t ieee80211_hostapd_beacon_txcb();
extern int32_t memset();
extern int32_t ppRegisterTxCallback();
extern uint32_t rodata_wlog_info_60; /* .rodata_wlog_info.60 */
extern uint32_t rodata_wlog_info_61; /* .rodata_wlog_info.61 */
extern uint32_t rodata_wlog_debug_63; /* .rodata_wlog_debug.63 */

/* pool[hal_pm_unblock_txq]: +0x0=0x3FF73CB8, +0x4=0xFFF1FFFF */
/* pool[pm_incr_coex_active_cnt]: +0x0=0x00000000 */
/* pool[pm_disable_active_timer]: +0x4=0x00000000, +0x0=0x00000000 */
/* pool[pm_illegal_beacon_logger]: +0x0=0x00000000, +0xc=0x00000000, +0x4=0x00000000, +0x10=0x00000000, +0x8=0x00000000, +0x14=0x00000000 */
/* pool[pm_set_state]: +0x0=0x00000000, +0x4=0x00000000, +0x8=0x00000000 */
/* pool[pm_beacon_monitor_tbtt_timeout]: +0x0=0x00000000 */
/* pool[pm_coex_restart_timeout]: +0x0=0x00000000 */
/* pool[pm_keep_alive_timeout]: +0x0=0x00000000 */
/* pool[pm_beacon_monitor_timeout]: +0x0=0x00000000 */
/* pool[pm_connectionless_wake_window_timeout]: +0x0=0x00000000 */
/* pool[pm_connectionless_wake_interval_timeout]: +0x0=0x00000000 */
/* pool[pm_disconnected_sleep_delay_timeout]: +0x0=0x00000000 */
/* pool[pm_coex_slice_wifi_timeout]: +0x0=0x00000000 */
/* pool[pm_sleep_delay_timeout]: +0x0=0x00000000 */
/* pool[pm_active_timeout]: +0x0=0x00000000 */
/* pool[pm_dream_timeout]: +0x0=0x00000000 */
/* pool[pm_tbtt_timeout]: +0x0=0x00000000 */
/* pool[pm_is_waked]: +0x0=0x00000000(g_pm) */
/* pool[pm_is_dream]: +0x0=0x00000000(g_pm) */
/* pool[pm_is_sleeping]: +0x0=0x00000000(g_pm) */
/* pool[pm_is_open]: +0x0=0x00000000(g_pm) */
/* pool[pm_sleep_for]: +0x0=0x00000000(g_mesh_is_started), +0x4=0x00000000(g_mesh_is_root), +0x8=0x00000000(g_mesh_init_ps_type), +0xc=0x00000000(g_pm+0x3), +0x14=0x00000000(memcmp), +0x10=0x00000000(g_pm), +0x18=0x00000000(memcmp) */
/* pool[pm_allow_tx]: +0x4=0x00000000(g_mesh_is_started), +0x0=0x00000000(g_pm), +0x8=0x00000000(g_mesh_is_root), +0xc=0x00000000(g_mesh_init_ps_type) */
/* pool[pm_get_connectionless_status]: +0x0=0x00000000(g_pm) */
/* pool[pm_mac_sleep_init]: +0x0=0x00000000(wdev_mac_sleep_init) */
/* pool[pm_mac_sleep_deinit]: +0x0=0x00000000(wdev_mac_sleep_deinit) */
/* pool[pm_enable_keep_alive_timer]: +0x4=0x00000000(g_pm_cfg), +0x8=0x00000000(g_mesh_is_started), +0xc=0x00000000(g_mesh_is_root), +0x0=0x002DC6C0, +0x14=0x00000000(g_osi_funcs_p), +0x10=0x00000000(g_pm+0x1ec) */
/* pool[pm_disable_keep_alive_timer]: +0x4=0x00000000(g_osi_funcs_p), +0x0=0x00000000(g_pm+0x1ec) */
/* pool[pm_is_sending_keep_alive]: +0x0=0x00000000(g_pm) */
/* pool[pm_set_bss_max_idle]: +0x0=0x00000000(g_pm_cfg), +0x4=0x0007A120, +0x8=0x001E8480 */
/* pool[pm_noise_check_disable]: +0x0=0x00000000(g_pm) */
/* pool[pm_noise_check_enable]: +0x0=0x00000000(g_pm) */
/* pool[pm_enable_active_timer]: +0x4=0x00000000(g_osi_funcs_p), +0x0=0x00000000(g_pm+0xcc), +0x8=0x00000000(g_pm), +0xc=0x00000000(g_mesh_is_started), +0x10=0x00000000(g_mesh_is_root), +0x14=0x00000000(g_mesh_init_ps_type) */
/* pool[pm_disable_dream_timer]: +0x4=0x00000000(g_osi_funcs_p), +0x0=0x00000000(g_pm+0xb8) */
/* pool[pm_enable_dream_timer]: +0x4=0x00000000(g_osi_funcs_p), +0x0=0x00000000(g_pm+0xb8), +0x8=0x00000000(g_pm) */
/* pool[pm_disable_sleep_delay_timer]: +0x0=0x00000000(g_pm), +0x8=0x00000000(g_osi_funcs_p), +0x4=0x00000000(g_pm+0x108) */
/* pool[pm_enable_sleep_delay_timer]: +0x4=0x00000000(g_osi_funcs_p), +0x0=0x00000000(g_pm+0x108), +0x8=0x00000000(g_pm) */
/* pool[pm_disable_disconnected_sleep_delay_timer]: +0x0=0x00000000(g_pm), +0x8=0x00000000(g_osi_funcs_p), +0x4=0x00000000(g_pm+0x124) */
/* pool[pm_enable_disconnected_sleep_delay_timer]: +0x0=0x00000000(g_pm), +0x4=0x00000000(g_mesh_is_started), +0xc=0x00000000(g_osi_funcs_p), +0x8=0x00000000(g_pm+0x124) */
/* pool[pm_noise_check]: +0x0=0x00000000(g_pm), +0x8=0x00000000(noise_check_loop), +0xc=0x00000000(read_hw_noisefloor), +0x4=0x00000000(wDevCtrl) */
/* pool[pm_register_pm_tx_null_cb]: +0x0=0x00000000(.bss.g_pm_tx_null_func) */
/* pool[pm_send_nullfunc]: +0x0=0x00000000(g_pm), +0x8=0x00000000(wifi_gpio_debug), +0x4=0x00000000(.bss.g_pm_tx_null_func) */
/* pool[pm_mac_wakeup]: +0x0=0x00000000(wdev_mac_wakeup) */
/* pool[pm_mac_sleep]: +0x0=0x00000000(wdev_mac_sleep) */
/* pool[pm_get_tbtt_count]: +0x0=0x00000000(g_osi_funcs_p), +0x4=0x00000000(g_pm), +0x8=0x00000000(__udivdi3), +0xc=0x00000000(pm_coex_schm_overall_period_get) */
/* pool[pm_save_tbtt_info]: +0x0=0x00000000(pm_get_tbtt_count) */
/* pool[pm_beacon_miss_exceeded_wakeup_disabled]: +0x0=0x00000000(g_pm_cfg), +0x4=0x00000000(g_pm) */
/* pool[pm_beacon_monitor_tbtt_allowed]: +0x4=0x00000000(pm_beacon_miss_exceeded_wakeup_disabled), +0x0=0x00000000(ptr_beacon_offset_funcs) */
/* pool[pm_beacon_monitor_tbtt_start]: +0x0=0x00000000(ptr_beacon_offset_funcs), +0x4=0x00000000(g_osi_funcs_p), +0x10=0x00000000(__udivdi3), +0x8=0x00001387, +0xc=0x00000000(g_pm) */
/* pool[pm_beacon_monitor_tbtt_stop]: +0x0=0x00000000(g_osi_funcs_p) */
/* pool[pm_disable_beacon_monitor_timer]: +0x0=0x00000000(g_osi_funcs_p), +0x4=0x00000000(pm_beacon_monitor_tbtt_stop) */
/* pool[pm_beacon_monitor_init]: +0x0=0x00000000(g_pm_cfg), +0x4=0x00000000(g_pm), +0x10=0x00000000(g_osi_funcs_p), +0x8=0x00000000(.bss.beacon_monitor_data$0), +0xc=0x00000004(.text.pm_beacon_monitor_tbtt_timeout) */
/* pool[pm_dream]: +0x0=0x00000000(g_pm), +0x1c=0x00000000(wifi_rf_phy_enable), +0x4=0x00000000(g_mesh_is_started), +0x8=0x00000000(g_mesh_is_root), +0xc=0x00000000(g_mesh_init_ps_type), +0x20=0x00000000(esp_wifi_get_mode), +0x24=0x00000000(wifi_rf_phy_enable), +0x10=0x00000000(g_osi_funcs_p), +0x14=0x00000000(g_pm_cnt), +0x18=0x00000000(g_pm+0xf4), +0x28=0x0000000C(.text.pm_set_state) */
/* pool[pm_disconnected_wake]: +0x0=0x00000000(g_pm), +0x4=0x00000000(g_mesh_is_started), +0x8=0x00000000(wifi_rf_phy_enable), +0xc=0x0000000C(.text.pm_set_state), +0x10=0x00000000(wifi_gpio_debug), +0x14=0x00000000(wifi_gpio_debug), +0x18=0x00000000(wifi_gpio_debug) */
/* pool[pm_sleep]: +0x4=0x00000000(g_mesh_is_started), +0x0=0x00000000(g_pm), +0x8=0x00000000(g_mesh_is_root), +0xc=0x00000000(g_mesh_init_ps_type), +0x1c=0x00000000(ppCheckTxQIdle), +0x10=0x00000000(g_osi_funcs_p), +0x20=0x00000000(ppCheckTxIdle), +0x14=0x00000000(g_pm+0xf4), +0x24=0x00000000(wifi_rf_phy_disable), +0x28=0x00000000(esp_wifi_get_mode), +0x2c=0x00000000(wifi_rf_phy_disable), +0x18=0x00000000(g_pm_cnt), +0x30=0x0000000C(.text.pm_set_state) */
/* pool[pm_disconnected_sleep]: +0xc=0x00000000(ppCheckTxIdle), +0x0=0x00000000(g_pm), +0x4=0x00000000(g_osi_funcs_p), +0x8=0x00000000(g_mesh_is_started), +0x10=0x00000000(wifi_rf_phy_disable), +0x14=0x00000000(wifi_gpio_debug), +0x18=0x00000000(wifi_gpio_debug), +0x1c=0x00000000(wifi_gpio_debug) */
/* pool[is_off_channel]: +0x0=0x00000000(g_pm) */
/* pool[pm_enable_send_wake_null_on_channel]: +0x0=0x00000000(g_pm) */
/* pool[pm_offchan_is_waiting]: +0x0=0x00000000(.bss.g_offchan_ready_cb) */
/* pool[pm_is_force_return_home_chan]: +0x0=0x00000000(g_pm) */
/* pool[pm_offchan_execute_ready_cb]: +0x0=0x00000000(.bss.g_offchan_ready_cb), +0x4=0x00000000(.rodata_wlog_debug.33), +0xc=0x00000000(wifi_log), +0x8=0x00000000(.bss.g_offchan_ready_ctx) */
/* pool[pm_wake_up]: +0x0=0x00000000(g_pm), +0x4=0x00000000(pm_disable_sleep_delay_timer), +0x8=0x00000000(pm_dream), +0xc=0x00000000(pm_disable_disconnected_sleep_delay_timer), +0x10=0x00000000(pm_disconnected_wake) */
/* pool[pm_send_probe_start]: +0x0=0x00000000(g_pm), +0x4=0x00000008(.text.pm_disable_active_timer), +0x8=0x00000000(pm_wake_up) */
/* pool[pm_off_channel]: +0x0=0x00000000(g_pm), +0xc=0x00000008(.text.pm_disable_active_timer), +0x10=0x00000000(pm_wake_up), +0x4=0x00000000(g_osi_funcs_p), +0x14=0x00000000(pm_dream), +0x8=0x3FF73CB8, +0x18=0x00000000(pm_send_nullfunc), +0x1c=0x00000000(pm_dream), +0x20=0x00000000(pm_wake_up) */
/* pool[pm_wake_done]: +0x0=0x00000000(g_pm), +0x4=0x00000000(pm_sleep), +0x8=0x00000000(pm_disconnected_sleep) */
/* pool[pm_coex_separate_connectionless_window]: +0x0=0x00000000(g_osi_funcs_p), +0x4=0x00000000(g_pm), +0x8=0x00000000(g_pm+0x14c), +0xc=0x00000000(g_pm+0x138), +0x10=0x00000000(pm_coex_schm_overall_period_get), +0x14=0x00000000(pm_wake_up), +0x18=0x00000000(wifi_gpio_debug), +0x1c=0x00000000(wifi_gpio_debug), +0x20=0x00000000(pm_wake_done) */
/* pool[pm_update_by_connectionless_status]: +0x8=0x00000000(g_osi_funcs_p), +0x4=0x00000000(g_pm+0x138), +0xc=0x00000000(g_pm+0x14c), +0x10=0x00000000(g_pm), +0x14=0x00000000(wifi_gpio_debug), +0x18=0x00000000(pm_wake_done), +0x1c=0x00000000(pm_get_connectionless_status), +0x20=0x00000000(wifi_event_post), +0x24=0x00000000(wifi_gpio_debug), +0x0=0x0000FFFF, +0x28=0x00000000(pm_coex_separate_connectionless_window), +0x2c=0x00000000(pm_wake_up), +0x30=0x00000000(wifi_gpio_debug) */
/* pool[pm_check_state]: +0x0=0x00000000(g_pm), +0x4=0x00000000(g_osi_funcs_p), +0x8=0x00000000(pm_dream), +0xc=0x0000000C(.text.pm_set_state) */
/* pool[pm_go_to_sleep]: +0x1c=0x00000000(pm_check_state), +0x0=0x00000000(g_pm), +0x20=0x0000000C(.text.pm_set_state), +0x4=0x00000000(g_mesh_is_started), +0x8=0x00000000(g_mesh_is_root), +0xc=0x00000000(g_mesh_init_ps_type), +0x18=0x00000000(esp_mesh_quick_funcs), +0x10=0x00000000(g_pm+0x13), +0x14=0x00000000(g_pm+0x14), +0x24=0x00000000(pm_send_nullfunc) */
/* pool[pm_set_next_tbtt]: +0x0=0x00000000(g_osi_funcs_p), +0x4=0x00000000(g_pm), +0x18=0x00000000(pm_coex_schm_overall_period_get), +0x8=0x00000000(g_intr_lock_mux), +0xc=0x00001387, +0x1c=0x00000000(__udivdi3), +0x10=0x00000000(g_pm+0xa4), +0x14=0x00000000(.rodata_wlog_warning.35), +0x20=0x00000000(wifi_log) */
/* pool[pm_mesh_set_next_tbtt]: +0x0=0x00000000(g_mesh_is_started), +0x4=0x00000000(g_mesh_is_root), +0x8=0x00000000(g_mesh_init_ps_type), +0xc=0x00000000(g_pm), +0x10=0x00000000(esp_mesh_quick_funcs), +0x18=0x00000000(g_osi_funcs_p), +0x14=0x00000000(g_pm+0xa4) */
/* pool[pm_handle_tbtt_interval]: +0x0=0x00000000(g_pm), +0x4=0x00000837, +0x8=0x00000000(.rodata.str1.1), +0xc=0x00000000(.rodata_wlog_error.37), +0x10=0x00000000(wifi_log) */
/* pool[pm_update_next_tbtt]: +0x0=0x00000000(g_osi_funcs_p), +0x4=0x00000000(g_pm_cfg), +0x8=0x00000000(g_pm), +0x38=0x00000000(__umoddi3), +0xc=0x00000000(ptr_beacon_offset_funcs), +0x3c=0x00000000(pm_coex_schm_overall_period_get), +0x40=0x00000000(pm_handle_tbtt_interval), +0x10=0x00000000(g_intr_lock_mux), +0x14=0x00000000(g_mesh_is_started), +0x18=0x00000000(g_mesh_is_root), +0x1c=0x00000000(g_mesh_init_ps_type), +0x20=0x3FF73C00, +0x24=0x00000000(g_wifi_mac_time_delta), +0x28=0x00001387, +0x2c=0x00000000(.rodata_wlog_warning.39), +0x44=0x00000000(wifi_log), +0x30=0x00000000(g_pm+0xa4), +0x34=0x00000000(esp_mesh_quick_funcs) */
/* pool[pm_beacon_timestamp_statistic]: +0x4=0x00000000(g_pm), +0x0=0x00000000(g_pm_cnt), +0x8=0x00000000(__umoddi3) */
/* pool[pm_beacon_misc_process]: +0x0=0x00000000(pm_beacon_timestamp_statistic) */
/* pool[pm_is_in_wifi_slice_threshold]: +0x0=0x00000000(g_osi_funcs_p), +0x4=0x00000000(g_pm) */
/* pool[pm_coex_schm_process]: +0x0=0x00000000(g_osi_funcs_p), +0x4=0x00000000(g_pm), +0x10=0x00000000(ppCheckTxIdle), +0x14=0x00000000(pm_disconnected_wake), +0x18=0x00000000(pm_coex_schm_overall_period_get), +0x1c=0x00000000(pm_coex_separate_connectionless_window), +0x20=0x00000000(pm_is_sleeping), +0x24=0x00000008(.text.hal_pm_unblock_txq), +0x28=0x00000000(wifi_gpio_debug), +0x8=0x00000000(g_pm+0xf4), +0x2c=0x00000000(pm_is_sleeping), +0xc=0x3FF73CB8 */
/* pool[pm_coex_schm_process_restart]: +0x0=0x00000000(g_osi_funcs_p) */
/* pool[pm_coex_go_to_sleep]: +0x0=0x00000000(g_osi_funcs_p), +0x4=0x00000000(g_pm), +0x14=0x00000000(wifi_gpio_debug), +0x18=0x00000000(ppCheckTxIdle), +0x8=0x00000000(g_pm+0x200), +0x1c=0x00000000(pm_enable_disconnected_sleep_delay_timer), +0xc=0x3FF73CB8, +0x10=0x00000000(g_pm_cfg), +0x20=0x00000000(ppCheckTxConnTrafficIdle), +0x24=0x00000000(pm_go_to_sleep), +0x28=0x00000000(pm_enable_sleep_delay_timer) */
/* pool[pm_coex_slice_timeout_process]: +0x0=0x00000000(pm_coex_go_to_sleep) */
/* pool[pm_active_timeout_process]: +0x0=0x00000000(g_pm_cnt), +0x4=0x00000000(g_pm), +0x8=0x00000000(pm_enable_active_timer), +0xc=0x00000000(ppCheckTxIdle), +0x10=0x00000000(pm_go_to_sleep) */
/* pool[pm_dream_timeout_process]: +0x0=0x00000000(g_pm), +0x4=0x00000000(pm_enable_sleep_delay_timer) */
/* pool[pm_sleep_delay_timeout_process]: +0x0=0x00000000(g_pm), +0x4=0x00000000(pm_sleep) */
/* pool[pm_disconnected_sleep_delay_timeout_process]: +0x0=0x00000000(g_pm), +0x4=0x00000000(pm_disconnected_sleep) */
/* pool[pm_connectionless_wake_interval_timeout_process]: +0x0=0x00000000(g_pm), +0x8=0x00000000(pm_update_by_connectionless_status), +0x4=0x00000000(g_osi_funcs_p) */
/* pool[pm_connectionless_wake_window_timeout_process]: +0x0=0x00000000(g_pm), +0x4=0x00000000(g_osi_funcs_p), +0x8=0x00000000(pm_coex_separate_connectionless_window), +0xc=0x00000000(pm_get_connectionless_status), +0x10=0x00000000(wifi_gpio_debug), +0x14=0x00000000(pm_wake_done) */
/* pool[pm_coex_restart_timeout_process]: +0x0=0x00000000(g_osi_funcs_p), +0x4=0x00000000(g_pm), +0x8=0x00000000(pm_coex_schm_process_restart) */
/* pool[pm_rx_data_process]: +0x4=0x00000000(pm_check_state), +0x8=0x00000004(.text.pm_incr_coex_active_cnt), +0x0=0x00000000(g_pm), +0xc=0x00000000(pm_enable_dream_timer), +0x10=0x00000000(pm_disable_dream_timer), +0x14=0x00000000(pm_enable_sleep_delay_timer), +0x18=0x00000000(pm_enable_active_timer) */
/* pool[pm_tx_data_done_process]: +0x0=0x00000000(g_mesh_is_started), +0x10=0x00000000(sta_reset_beacon_timeout), +0x4=0x00000000(g_osi_funcs_p), +0x8=0x00000000(g_pm), +0xc=0x000186A0, +0x14=0x00000000(pm_enable_keep_alive_timer), +0x18=0x00000000(ppCheckTxIdle), +0x1c=0x00000000(pm_enable_sleep_delay_timer), +0x20=0x00000000(pm_enable_disconnected_sleep_delay_timer), +0x24=0x00000000(pm_check_state), +0x28=0x00000004(.text.pm_incr_coex_active_cnt), +0x2c=0x00000000(pm_enable_active_timer) */
/* pool[pm_tx_null_data_done_quick_wake_process]: +0x0=0x00000000(g_pm), +0x8=0x00000000(sta_reset_beacon_timeout), +0x4=0x00000000(g_osi_funcs_p), +0xc=0x00000000(ppCheckTxIdle), +0x10=0x00000000(pm_send_nullfunc) */
/* pool[pm_tx_null_data_done_process]: +0x8=0x00000000(g_mesh_is_started), +0x14=0x00000000(g_pm), +0xc=0x00000000(g_mesh_is_root), +0x10=0x00000000(g_mesh_init_ps_type), +0x18=0x00000000(esp_mesh_quick_funcs), +0x30=0x00000000(pm_check_state), +0x34=0x00000000(pm_dream), +0x1c=0x00000000(g_ic), +0x20=0x00000000(.rodata_wlog_debug.51), +0x38=0x00000000(wifi_log), +0x3c=0x00000000(pm_enable_keep_alive_timer), +0x24=0x00000000(g_osi_funcs_p), +0x0=0x00000000(.rodata.pm_tx_null_data_done_process.str1.1), +0x4=0x0000000A(.rodata.pm_tx_null_data_done_process.str1.1), +0x28=0x00000000(.rodata_wlog_debug.52), +0x40=0x00000000(wifi_log), +0x44=0x00000000(pm_tx_null_data_done_quick_wake_process), +0x48=0x0000000C(.text.pm_set_state), +0x4c=0x00000000(pm_enable_active_timer), +0x2c=0x00000000(g_pm_cnt), +0x50=0x00000000(ppProcessWaitingQueue), +0x54=0x00000000(pm_sleep), +0x58=0x00000000(pm_enable_sleep_delay_timer), +0x5c=0x00000000(pm_is_in_wifi_slice_threshold), +0x60=0x00000000(pm_send_nullfunc), +0x64=0x00000000(pm_enable_sleep_delay_timer), +0x68=0x00000000(pm_offchan_execute_ready_cb) */
/* pool[pm_go_to_wake]: +0x0=0x00000000(g_pm), +0x20=0x00000000(pm_dream), +0x4=0x00000000(g_mesh_is_started), +0x8=0x00000000(g_mesh_is_root), +0xc=0x00000000(g_mesh_init_ps_type), +0x18=0x00000000(esp_mesh_quick_funcs), +0x10=0x00000000(g_pm+0x13), +0x14=0x00000000(g_pm+0x14), +0x24=0x00000000(ppCheckTxConnTrafficIdle), +0x28=0x00000000(pm_tx_null_data_done_process), +0x1c=0x00000000(g_osi_funcs_p), +0x2c=0x00000000(pm_is_in_wifi_slice_threshold), +0x30=0x00000000(pm_send_nullfunc), +0x34=0x00000000(pm_send_nullfunc), +0x38=0x00000000(pm_tx_null_data_done_process) */
/* pool[pm_send_probe_stop]: +0x0=0x00000000(g_pm), +0x4=0x00000000(pm_go_to_wake), +0x8=0x00000000(ppCheckTxConnTrafficIdle), +0xc=0x00000000(pm_enable_active_timer), +0x10=0x00000000(pm_wake_done) */
/* pool[pm_on_channel]: +0x0=0x00000000(g_pm), +0x4=0x00000000(pm_wake_done), +0x8=0x00000008(.text.hal_pm_unblock_txq), +0xc=0x00000000(pm_go_to_wake), +0x10=0x00000000(ppCheckTxConnTrafficIdle), +0x14=0x00000000(pm_wake_done), +0x18=0x00000000(pm_enable_active_timer) */
/* pool[pm_offchan_ready_or_defer]: +0x0=0x00000000(g_pm), +0x10=0x00000000(pm_off_channel), +0x4=0x00000000(.bss.g_offchan_ready_cb), +0x8=0x00000000(.bss.g_offchan_ready_ctx), +0xc=0x00000000(.rodata_wlog_error.32), +0x14=0x00000000(wifi_log), +0x18=0x00000000(pm_on_channel) */
/* pool[pm_update_params]: +0x0=0x00000000(g_osi_funcs_p), +0x4=0x00000000(g_pm), +0x8=0x00000000(g_pm_cfg), +0xc=0x00000000(pm_coex_schm_overall_period_get), +0x10=0x00000000(pm_go_to_wake) */
/* pool[pm_process_tim]: +0x0=0x00000000(g_pm), +0x4=0x00000000(g_osi_funcs_p), +0xc=0x00000000(pm_is_in_wifi_slice_threshold), +0x10=0x00000000(pm_go_to_wake), +0x8=0x00000000(g_pm_cnt), +0x14=0x00000000(pm_is_in_wifi_slice_threshold), +0x18=0x00000000(pm_enable_dream_timer), +0x1c=0x00000000(pm_disable_sleep_delay_timer), +0x20=0x00000000(pm_sleep), +0x24=0x00000008(.text.pm_disable_active_timer), +0x28=0x00000000(pm_active_timeout_process) */
/* pool[pm_rx_beacon_process]: +0x0=0x00000000(g_pm), +0x4=0x00000000(g_osi_funcs_p), +0xc=0x00000000(wifi_gpio_debug), +0x10=0x00000000(sta_reset_beacon_timeout), +0x8=0x00000000(g_pm_cfg), +0x14=0x00000000(pm_process_tim) */
/* pool[pm_coex_tbtt_process]: +0x4=0x00000000(g_osi_funcs_p), +0x0=0x00000000(g_pm+0xf4), +0x8=0x00000000(g_pm), +0x10=0x00000000(pm_coex_schm_overall_period_get), +0xc=0x51EB851F, +0x14=0x00000000(pm_coex_schm_process_restart), +0x18=0x00000000(pm_is_sleeping), +0x1c=0x00000008(.text.hal_pm_unblock_txq), +0x20=0x00000000(ppCheckTxConnTrafficIdle), +0x24=0x00000000(pm_is_sleeping), +0x28=0x00000008(.text.hal_pm_unblock_txq), +0x2c=0x00000000(pm_go_to_wake) */
/* pool[pm_keep_alive_timeout_process]: +0x8=0x00000000(pm_enable_keep_alive_timer), +0x0=0x00000000(g_pm), +0xc=0x00000000(pm_go_to_wake), +0x10=0x00000000(pm_dream), +0x14=0x00000000(pm_send_nullfunc), +0x4=0x00000000(.rodata_wlog_debug.45), +0x18=0x00000000(wifi_log) */
/* pool[pm_tx_data_process]: +0x0=0x00000000(g_mesh_is_started), +0x4=0x00000000(g_mesh_is_root), +0x8=0x00000000(g_mesh_init_ps_type), +0xc=0x00000000(esp_mesh_quick_funcs), +0x10=0x00000000(g_pm), +0x20=0x00000000(pm_check_state), +0x24=0x00000000(pm_check_state), +0x14=0x00000000(g_osi_funcs_p), +0x28=0x00000000(pm_is_in_wifi_slice_threshold), +0x2c=0x00000000(pm_disconnected_wake), +0x18=0x00000000(g_pm+0x200), +0x30=0x00000000(pm_coex_schm_process_restart), +0x34=0x00000000(pm_is_in_wifi_slice_threshold), +0x38=0x00000000(pm_go_to_wake), +0x3c=0x00000000(pm_is_in_wifi_slice_threshold), +0x40=0x00000000(pm_dream), +0x44=0x00000000(pm_go_to_wake), +0x1c=0x00000000(g_pm_cnt), +0x48=0x00000000(pm_enable_active_timer), +0x4c=0x00000004(.text.pm_incr_coex_active_cnt) */
/* pool[pm_send_sleep_null_cb]: +0x0=0x00000000(pm_tx_null_data_done_process) */
/* pool[pm_send_wake_null_cb]: +0x0=0x00000000(pm_tx_null_data_done_process) */
/* pool[pm_on_coex_schm_process_restart]: +0x0=0x00000000(pm_coex_schm_process_restart) */
/* pool[pm_on_coex_schm_status_config]: +0x10=0x00000000(pm_get_connectionless_status), +0x4=0x00000000(g_osi_funcs_p), +0x0=0x0000FFFF, +0x8=0x00000000(g_pm), +0xc=0x51EB851F */
/* pool[pm_on_coex_start]: +0x0=0x00000000(g_pm), +0x8=0x00000000(pm_on_coex_schm_status_config), +0xc=0x00000000(pm_coex_schm_process_restart), +0x10=0x00000000(pm_update_by_connectionless_status), +0x4=0x00000000(.rodata_wlog_info.53), +0x14=0x00000000(wifi_log) */
/* pool[pm_on_data_rx]: +0x0=0x00000000(pm_sleep_for), +0x4=0x00000000(pm_rx_data_process) */
/* pool[pm_on_data_tx]: +0x0=0x00000000(pm_tx_data_process) */
/* pool[pm_on_data_tx_done]: +0x0=0x00000000(pm_tx_data_done_process) */
/* pool[pm_on_sample_beacon]: +0x0=0x00000000(g_pm), +0x4=0x00000000(ptr_beacon_offset_funcs) */
/* pool[pm_scale_listen_interval]: +0x8=0x00000000(wifi_nvs_get_sta_listen_interval), +0x0=0x00000000(g_pm), +0xc=0x00000000(wifi_nvs_get_sta_listen_interval), +0x4=0x00000000(.rodata_wlog_info.6), +0x10=0x00000000(wifi_log), +0x14=0x00000000(pm_coex_pwr_update), +0x18=0x00000000(pm_on_sample_beacon) */
/* pool[pm_parse_beacon]: +0x0=0x00000000(g_pm), +0x4=0x00000000(.rodata_wlog_info.13), +0x1c=0x00000000(wifi_log), +0x20=0x00000018(.text.pm_illegal_beacon_logger), +0x8=0x00000000(.rodata_wlog_info.14), +0xc=0x00000000(.rodata_wlog_info.15), +0x24=0x00000000(wifi_log), +0x28=0x00000018(.text.pm_illegal_beacon_logger), +0x2c=0x00000000(pm_scale_listen_interval), +0x10=0x00000000(g_osi_funcs_p), +0x14=0x51EB851F, +0x30=0x00000000(pm_scale_listen_interval), +0x34=0x00000000(pm_scale_listen_interval), +0x18=0x00000000(.rodata_wlog_info.16), +0x38=0x00000000(wifi_log) */
/* pool[pm_on_beacon_rx]: +0x0=0x00000000(g_pm), +0x1c=0x00000000(pm_disable_beacon_monitor_timer), +0x4=0x00000000(g_osi_funcs_p), +0x20=0x00000000(pm_coex_schm_overall_period_get), +0x24=0x00000000(pm_beacon_monitor_tbtt_stop), +0x8=0x00000000(g_mesh_is_root), +0xc=0x00000000(g_mesh_init_ps_type), +0x10=0x00000000(esp_mesh_quick_funcs), +0x28=0x00000000(pm_parse_beacon), +0x2c=0x00000000(pm_update_next_tbtt), +0x14=0x00000000(g_pm_cnt), +0x30=0x00000000(pm_rx_beacon_process), +0x34=0x00000000(pm_beacon_timestamp_statistic), +0x18=0x00000000(ptr_beacon_offset_funcs) */
/* pool[pm_on_probe_resp_rx]: +0x0=0x00000000(g_pm), +0xc=0x00000000(pm_scale_listen_interval), +0x4=0x00000000(g_osi_funcs_p), +0x8=0x51EB851F, +0x10=0x00000000(pm_update_next_tbtt) */
/* pool[pm_disconnected_start]: +0x0=0x00000000(g_pm), +0x8=0x00000000(pm_on_coex_schm_status_config), +0x4=0x00000000(g_osi_funcs_p), +0xc=0x00000000(pm_coex_schm_process_restart), +0x10=0x00000000(pm_disable_disconnected_sleep_delay_timer), +0x14=0x00000000(wifi_gpio_debug), +0x18=0x00000000(wifi_gpio_debug), +0x1c=0x00000000(wifi_gpio_debug), +0x20=0x00000000(pm_update_by_connectionless_status) */
/* pool[pm_disconnected_stop]: +0x8=0x00000000(g_osi_funcs_p), +0x0=0x00000000(g_pm), +0x4=0x00000000(g_pm+0xf4), +0xc=0x00000000(pm_disable_disconnected_sleep_delay_timer), +0x10=0x00000000(wifi_gpio_debug), +0x14=0x00000000(wifi_gpio_debug), +0x18=0x00000000(wifi_gpio_debug), +0x1c=0x00000000(pm_update_by_connectionless_status) */
/* pool[pm_tbtt_quick_wake_configure]: +0x0=0x00000000(g_pm), +0x4=0x00000000(ptr_beacon_offset_funcs) */
/* pool[pm_start]: +0x0=0x00000000(g_pm), +0x4=0x00000000(ptr_beacon_offset_funcs), +0x8=0x00000000(.rodata_wlog_info.57), +0x1c=0x00000000(wifi_log), +0x20=0x00000000(memcpy), +0xc=0x00000000(g_osi_funcs_p), +0x10=0x51EB851F, +0x24=0x00000000(pm_scale_listen_interval), +0x28=0x00000000(dbg_lmac_ps_statis_reset), +0x2c=0x00000000(pm_update_next_tbtt), +0x30=0x00000000(pm_beacon_monitor_init), +0x34=0x00000000(pm_enable_active_timer), +0x38=0x00000000(pm_on_coex_schm_status_config), +0x3c=0x00000000(wifi_gpio_debug), +0x40=0x00000000(wifi_gpio_debug), +0x44=0x00000000(wifi_gpio_debug), +0x14=0x00000000(.bss.g_offchan_ready_cb), +0x18=0x00000000(.bss.g_offchan_ready_ctx), +0x48=0x00000000(pm_update_by_connectionless_status) */
/* pool[pm_stop]: +0x0=0x00000000(g_pm), +0x2c=0x00000008(.text.hal_pm_unblock_txq), +0x30=0x00000000(pm_disable_sleep_delay_timer), +0x34=0x00000008(.text.pm_disable_active_timer), +0x8=0x00000000(g_osi_funcs_p), +0x4=0x00000000(g_pm+0xa4), +0xc=0x00000000(g_pm+0xb8), +0x38=0x00000000(pm_dream), +0x3c=0x0000000C(.text.pm_set_state), +0x40=0x00000000(ppProcessWaitingQueue), +0x10=0x00000000(.rodata_wlog_info.58), +0x44=0x00000000(wifi_log), +0x48=0x00000000(pm_wake_done), +0x14=0x00030000, +0x4c=0x00000000(pm_coex_pwr_update), +0x50=0x00000000(pm_on_coex_schm_status_config), +0x54=0x00000000(pm_coex_schm_process_restart), +0x18=0x00000000(ptr_beacon_offset_funcs), +0x58=0x00000000(pm_enable_disconnected_sleep_delay_timer), +0x5c=0x00000000(pm_update_by_connectionless_status), +0x1c=0x00000000(g_mesh_is_started), +0x20=0x00000000(g_mesh_is_root), +0x24=0x00000000(g_mesh_init_ps_type), +0x60=0x00000000(esp_mesh_get_running_active_duty_cycle), +0x64=0x00000000(__floatundisf), +0x68=0x00000000(__floatundisf), +0x6c=0x00000000(__divsf3), +0x70=0x00000000(__extendsfdf2), +0x28=0x00000000(.rodata_wlog_info.59), +0x74=0x00000000(wifi_log), +0x78=0x00000000(ieee80211_hostapd_beacon_txcb), +0x7c=0x00000000(pm_set_bss_max_idle) */
/* pool[pm_attach]: +0x0=0x00000000(g_pm), +0x74=0x00000000(memset), +0x78=0x0000000C(.text.pm_set_state), +0x4=0x00000000(g_pm_cfg), +0x8=0x00019000, +0xc=0x00030000, +0x10=0x00000000(pm_send_sleep_null_cb), +0x7c=0x00000000(ppRegisterTxCallback), +0x14=0x00000000(pm_send_wake_null_cb), +0x80=0x00000000(ppRegisterTxCallback), +0x20=0x00000000(g_osi_funcs_p), +0x18=0x00000004(.text.pm_tbtt_timeout), +0x1c=0x00000000(g_pm+0xa4), +0x24=0x00000004(.text.pm_dream_timeout), +0x28=0x00000000(g_pm+0xb8), +0x2c=0x00000004(.text.pm_active_timeout), +0x30=0x00000000(g_pm+0xcc), +0x34=0x00000004(.text.pm_sleep_delay_timeout), +0x38=0x00000000(g_pm+0x108), +0x3c=0x00000004(.text.pm_coex_slice_wifi_timeout), +0x40=0x00000000(g_pm+0xf4), +0x44=0x00000004(.text.pm_disconnected_sleep_delay_timeout), +0x48=0x00000000(g_pm+0x124), +0x4c=0x00000004(.text.pm_connectionless_wake_interval_timeout), +0x50=0x00000000(g_pm+0x138), +0x54=0x00000004(.text.pm_connectionless_wake_window_timeout), +0x58=0x00000000(g_pm+0x14c), +0x5c=0x00000004(.text.pm_beacon_monitor_timeout), +0x60=0x00000000(g_pm+0x168), +0x64=0x00000004(.text.pm_keep_alive_timeout), +0x68=0x00000000(g_pm+0x1ec), +0x6c=0x00000004(.text.pm_coex_restart_timeout), +0x70=0x00000000(g_pm+0x200) */
/* pool[pm_deattach]: +0x0=0x00000000(g_pm), +0x8=0x00000000(g_osi_funcs_p), +0x4=0x00000000(g_pm+0xa4), +0xc=0x00000000(g_pm+0xb8), +0x10=0x00000000(g_pm+0xcc), +0x14=0x00000000(g_pm+0x108), +0x18=0x00000000(g_pm+0xf4), +0x1c=0x00000000(g_pm+0x124), +0x20=0x00000000(g_pm+0x138), +0x24=0x00000000(g_pm+0x14c), +0x28=0x00000000(g_pm+0x168), +0x2c=0x00000000(g_pm+0x1ec), +0x30=0x00000000(g_pm+0x200) */
/* pool[pm_set_sleep_type]: +0x0=0x00000000(g_osi_funcs_p), +0x4=0x00000000(.rodata_wlog_info.60), +0x10=0x00000000(wifi_log), +0x8=0x00000000(.rodata_wlog_info.61), +0x14=0x00000000(wifi_log), +0xc=0x00000000(g_pm), +0x18=0x00000000(pm_enable_active_timer), +0x1c=0x00000000(pm_dream), +0x20=0x0000000C(.text.pm_set_state), +0x24=0x00000000(pm_go_to_wake), +0x28=0x00000008(.text.pm_disable_active_timer), +0x2c=0x00000000(pm_coex_pwr_update) */
/* pool[pm_get_sleep_type]: +0x0=0x00000000(g_pm) */
/* pool[pm_beacon_monitor_configure]: +0x0=0x00000000(g_pm_cfg) */
/* pool[pm_update_modem_sleep_default_params]: +0x0=0x00000000(g_pm_cfg) */
/* pool[pm_update_light_sleep_default_params]: +0x0=0x00000000(g_pm_cfg) */
/* pool[pm_set_sleep_min_active_time]: +0x0=0x00000000(g_pm_cfg) */
/* pool[pm_set_keep_alive_time]: +0x0=0x00000000(g_pm_cfg) */
/* pool[pm_get_keep_alive_time]: +0x0=0x00000000(g_pm_cfg) */
/* pool[pm_set_sleep_wait_broadcast_data_time]: +0x0=0x00000000(g_pm_cfg) */
/* pool[pm_enable_sta_disconnected_power_management]: +0x0=0x00000000(g_pm) */
/* pool[pm_register_connectionless_wake_window]: +0x0=0x00000000(g_osi_funcs_p), +0x4=0x00000000(g_pm), +0x8=0x00000000(pm_update_by_connectionless_status), +0xc=0x00000000(pm_on_coex_schm_status_config), +0x10=0x00000000(pm_coex_schm_process_restart) */
/* pool[pm_unregister_connectionless_wake_window]: +0x0=0x00000000(g_pm), +0x4=0x00000000(g_osi_funcs_p), +0x8=0x00000000(pm_update_by_connectionless_status), +0xc=0x00000000(pm_on_coex_schm_status_config), +0x10=0x00000000(pm_coex_schm_process_restart) */
/* pool[pm_connectionless_module_set_wake_interval]: +0x0=0x00000000(g_pm), +0x4=0x00000000(pm_update_by_connectionless_status) */
/* pool[pm_set_beacon_duration]: +0x0=0x00000000(g_pm), +0x8=0x00000000(pm_on_sample_beacon), +0x4=0x00000000(.rodata_wlog_debug.63), +0xc=0x00000000(wifi_log) */
/* pool[pm_get_beacon_duration]: +0x0=0x00000000(g_pm) */
/* pool[pm_beacon_add_total_counter]: +0x0=0x00000000(g_pm), +0x4=0x00000000(ptr_beacon_offset_funcs) */
/* pool[pm_enable_beacon_monitor_timer]: +0x0=0x00000000(ptr_beacon_offset_funcs), +0x4=0x00000000(g_osi_funcs_p), +0x8=0x00000000(__udivdi3), +0xc=0x00000000(pm_beacon_miss_exceeded_wakeup_disabled), +0x10=0x00000000(pm_beacon_add_total_counter), +0x14=0x00000000(pm_beacon_monitor_tbtt_allowed), +0x18=0x00000000(pm_beacon_monitor_tbtt_start) */
/* pool[pm_tbtt_process]: +0x0=0x00000000(g_osi_funcs_p), +0x28=0x00000000(pm_check_state), +0x4=0x00000000(g_pm), +0x8=0x00000000(g_pm+0xa4), +0xc=0x00000000(g_pm+0xf4), +0x2c=0x00000008(.text.hal_pm_unblock_txq), +0x30=0x00000000(pm_save_tbtt_info), +0x34=0x00000000(pm_enable_beacon_monitor_timer), +0x38=0x00000000(pm_beacon_monitor_tbtt_allowed), +0x3c=0x00000000(pm_coex_schm_overall_period_get), +0x40=0x00000000(pm_beacon_monitor_tbtt_start), +0x44=0x00000000(wifi_gpio_debug), +0x10=0x00000000(g_pm_cnt), +0x48=0x00000000(pm_dream), +0x14=0x00000000(g_mesh_is_started), +0x18=0x00000000(g_mesh_is_root), +0x1c=0x00000000(g_mesh_init_ps_type), +0x20=0x3FF73C00, +0x24=0x00000000(g_wifi_mac_time_delta), +0x4c=0x00000000(pm_coex_tbtt_process), +0x50=0x00000000(pm_noise_check), +0x54=0x00000000(pm_mesh_set_next_tbtt), +0x58=0x00000000(pm_set_next_tbtt), +0x5c=0x00000000(pm_go_to_wake), +0x60=0x00000000(pm_update_params), +0x64=0x00000000(pm_update_by_connectionless_status) */
/* pool[pm_beacon_monitor_tbtt_timeout_process]: +0x0=0x00000000(g_osi_funcs_p), +0x4=0x00000000(pm_tbtt_process) */
/* pool[pm_beacon_add_loss_counter]: +0x0=0x00000000(g_pm), +0x4=0x00000000(ptr_beacon_offset_funcs) */
/* pool[pm_beacon_monitor_timeout_process]: +0x4=0x00000000(pm_beacon_add_loss_counter), +0x0=0x00000000(g_osi_funcs_p), +0x8=0x00000000(pm_sleep), +0xc=0x00000000(wifi_gpio_debug) */
/* pool[pm_beacon_loss_info_get]: +0x0=0x00000000(g_pm) */
/* pool[pm_beacon_loss_info_clean]: +0x0=0x00000000(g_pm) */
/* pool[pm_get_tx_blocks_retention_mask]: +0x4=0x00000000(g_pm), +0x0=0xFFF1FFFF */

/* pm_is_waked @ pm.o 00000004 size 18B bind GLOBAL
 * Calls: none | Data refs: g_pm
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t pm_is_waked(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .wifislprxiram.2; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a2 = (uint32_t)&g_pm; /* 0007: l32r a2, 0 <pm_is_waked-0x4> (0 <pm_is_waked-0x4>) */ /* literal @0x0: g_pm */
  a8 = 0x0; /* 000a: movi.n a8, 0 */
  a9 = MEM8(a2 + 1); /* 000c: l8ui a9, a2, 1 */
  a2 = 0x1; /* 000f: movi.n a2, 1 */
  if (a9 != 0) a2 = a8; /* 0011: movnez a2, a8, a9 */
  return (int32_t)a2; /* 0014: retw.n  */
}

/* pm_is_dream @ pm.o 00000004 size 20B bind GLOBAL
 * Calls: none | Data refs: g_pm
 *   MMIO: none
 *   funcdb v3: 0 call(s), 1 ref(s); disasm: 0 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t pm_is_dream(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pm_is_dream; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a2 = (uint32_t)&g_pm; /* 0007: l32r a2, 0 <pm_is_dream-0x4> (0 <pm_is_dream-0x4>) */ /* literal @0x0: g_pm */
  a9 = 0x0; /* 000a: movi.n a9, 0 */
  a8 = MEM8(a2 + 1); /* 000c: l8ui a8, a2, 1 */
  a2 = 0x1; /* 000f: movi.n a2, 1 */
  a8 = a8 + (-1); /* 0011: addi.n a8, a8, -1 */
  if (a8 != 0) a2 = a9; /* 0013: movnez a2, a9, a8 */
  return (int32_t)a2; /* 0016: retw.n  */
}

/* pm_is_sleeping @ pm.o 00000004 size 30B bind GLOBAL
 * Calls: none | Data refs: g_pm
 *   MMIO: none
 *   funcdb v3: 0 call(s), 1 ref(s); disasm: 0 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t pm_is_sleeping(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pm_is_sleeping; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a8 = (uint32_t)&g_pm; /* 0007: l32r a8, 0 <pm_is_sleeping-0x4> (0 <pm_is_sleeping-0x4>) */ /* literal @0x0: g_pm */
  a2 = 0x1; /* 000a: movi.n a2, 1 */
  a9 = MEM8(a8 + 1); /* 000c: l8ui a9, a8, 1 */
  if (a9 == 2) goto L_20; /* 000f: beqi a9, 2, 20 <pm_is_sleeping+0x1c> */
  a8 = a8 + ((0x100) << 8); /* 0012: addmi a8, a8, 0x100 */
  a9 = 0x0; /* 0015: movi.n a9, 0 */
  a8 = MEM8(a8 + 29); /* 0017: l8ui a8, a8, 29 */
  a8 = a8 + (-3); /* 001a: addi a8, a8, -3 */
  if (a8 != 0) a2 = a9; /* 001d: movnez a2, a9, a8 */
L_20:;
  return (int32_t)a2; /* 0020: retw.n  */
}

/* pm_is_open @ pm.o 00000004 size 11B bind GLOBAL
 * Calls: none | Data refs: g_pm
 *   MMIO: none
 *   funcdb v3: 0 call(s), 1 ref(s); disasm: 0 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t pm_is_open(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pm_is_open; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a8 = (uint32_t)&g_pm; /* 0007: l32r a8, 0 <pm_is_open-0x4> (0 <pm_is_open-0x4>) */ /* literal @0x0: g_pm */
  a2 = MEM8(a8 + 13); /* 000a: l8ui a2, a8, 13 */
  return (int32_t)a2; /* 000d: retw.n  */
}

/* pm_sleep_for @ pm.o 0000001c size 88B bind GLOBAL
 * Calls: memcmp[got], memcmp[got] | Data refs: g_mesh_is_started, g_mesh_is_root, g_mesh_init_ps_type, g_pm, memcmp
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 2 call(s), 5 data ref(s)
 * Fidelity: medium - 35 instr, 5 branches, calls resolved */
int32_t pm_sleep_for(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .wifislprxiram.3; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_1c:;
  /* 001c: entry a1, 32 */
  a10 = a2; /* 001f: mov.n a10, a2 */
  a2 = (uint32_t)&g_mesh_is_started; /* 0021: l32r a2, 0 <pm_sleep_for-0x1c> (0 <pm_sleep_for-0x1c>) */ /* literal @0x0: g_mesh_is_started */
  a2 = MEM8(a2 + 0); /* 0024: l8ui a2, a2, 0 */
  if (a2 == 0) goto L_55; /* 0027: beqz.n a2, 55 <pm_sleep_for+0x39> */
  a2 = (uint32_t)&g_mesh_is_root; /* 0029: l32r a2, 4 <pm_sleep_for-0x18> (0 <pm_sleep_for-0x1c>) */ /* literal @0x4: g_mesh_is_root */
  MEMW(); /* 002c: memw  */
  a3 = MEM8(a2 + 0); /* 002f: l8ui a3, a2, 0 */
  a3 = (a3 >> 0) & 0xFF; /* 0032: extui a3, a3, 0, 8 */
  if (a3 != 0) goto L_55; /* 0035: bnez.n a3, 55 <pm_sleep_for+0x39> */
  a2 = (uint32_t)&g_mesh_init_ps_type; /* 0037: l32r a2, 8 <pm_sleep_for-0x14> (0 <pm_sleep_for-0x1c>) */ /* literal @0x8: g_mesh_init_ps_type */
  a2 = MEM32(a2 + 0); /* 003a: l32i.n a2, a2, 0 */
  if (a2 == 0) goto L_55; /* 003c: beqz.n a2, 55 <pm_sleep_for+0x39> */
  a12 = 0x6; /* 003e: movi.n a12, 6 */
  a2 = 0x1; /* 0040: movi a2, 1 */
  a11 = (uint32_t)&g_pm; /* 0043: l32r a11, c <pm_sleep_for-0x10> (0 <pm_sleep_for-0x1c>) */ /* literal @0xC: g_pm */
  a8 = (uint32_t)&memcmp; /* 0046: l32r a8, 14 <pm_sleep_for-0x8> (0 <pm_sleep_for-0x1c>) */ /* literal: GOT slot for memcmp */
  memcmp(a2, a3, a4, a5); /* call via literal slot */ /* 0049: callx8 a8 */
  if (a10 != 0) a2 = a3; /* 004c: movnez a2, a3, a10 */
  goto L_72; /* 004f: j 72 <pm_sleep_for+0x56> */
  /* 0052: .byte 00 */
  /* 0053: .byte 00 */
  /* 0054: .byte 00 */
L_55:;
  a2 = (uint32_t)&g_pm; /* 0055: l32r a2, 10 <pm_sleep_for-0xc> (0 <pm_sleep_for-0x1c>) */ /* literal @0x10: g_pm */
  a3 = 0x0; /* 0058: movi.n a3, 0 */
  a2 = MEM8(a2 + 13); /* 005a: l8ui a2, a2, 13 */
  if (a2 == a3) goto L_70; /* 005d: beq a2, a3, 70 <pm_sleep_for+0x54> */
  a12 = 0x6; /* 0060: movi.n a12, 6 */
  a2 = 0x1; /* 0062: movi.n a2, 1 */
  a11 = (uint32_t)&g_pm; /* 0064: l32r a11, c <pm_sleep_for-0x10> (0 <pm_sleep_for-0x1c>) */ /* literal @0xC: g_pm */
  a8 = (uint32_t)&memcmp; /* 0067: l32r a8, 18 <pm_sleep_for-0x4> (0 <pm_sleep_for-0x1c>) */ /* literal: GOT slot for memcmp */
  memcmp(a2, a3, a4, a5); /* call via literal slot */ /* 006a: callx8 a8 */
  if (a10 == 0) a3 = a2; /* 006d: moveqz a3, a2, a10 */
L_70:;
  a2 = a3; /* 0070: mov.n a2, a3 */
L_72:;
  return (int32_t)a2; /* 0072: retw.n  */
}

/* pm_allow_tx @ pm.o 00000010 size 90B bind GLOBAL
 * Calls: none | Data refs: g_mesh_init_ps_type, g_mesh_is_root, g_mesh_is_started, g_pm
 *   MMIO: none
 *   funcdb v3: 0 call(s), 4 ref(s); disasm: 0 call(s), 4 data ref(s)
 * Fidelity: medium - 35 instr, 7 branches, calls resolved */
int32_t pm_allow_tx(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pm_allow_tx; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_10:;
  /* 0010: entry a1, 32 */
  a11 = (a2 >> 0) & 0xFF; /* 0013: extui a11, a2, 0, 8 */
  a2 = (uint32_t)&g_mesh_is_started; /* 0016: l32r a2, 4 <pm_allow_tx-0xc> (0 <pm_allow_tx-0x10>) */ /* literal @0x4: g_mesh_is_started */
  a9 = (uint32_t)&g_pm; /* 0019: l32r a9, 0 <pm_allow_tx-0x10> (0 <pm_allow_tx-0x10>) */ /* literal @0x0: g_pm */
  a2 = MEM8(a2 + 0); /* 001c: l8ui a2, a2, 0 */
  a10 = MEM8(a9 + 1); /* 001f: l8ui a10, a9, 1 */
  if (a2 == 0) goto L_59; /* 0022: beqz.n a2, 59 <pm_allow_tx+0x49> */
  a12 = (uint32_t)&g_mesh_is_root; /* 0024: l32r a12, 8 <pm_allow_tx-0x8> (0 <pm_allow_tx-0x10>) */ /* literal @0x8: g_mesh_is_root */
  MEMW(); /* 0027: memw  */
  a8 = MEM8(a12 + 0); /* 002a: l8ui a8, a12, 0 */
  a8 = (a8 >> 0) & 0xFF; /* 002d: extui a8, a8, 0, 8 */
  if (a8 != 0) goto L_59; /* 0030: bnez.n a8, 59 <pm_allow_tx+0x49> */
  a2 = (uint32_t)&g_mesh_init_ps_type; /* 0032: l32r a2, c <pm_allow_tx-0x4> (0 <pm_allow_tx-0x10>) */ /* literal @0xC: g_mesh_init_ps_type */
  a2 = MEM32(a2 + 0); /* 0035: l32i.n a2, a2, 0 */
  if (a2 == 0) goto L_59; /* 0037: beqz.n a2, 59 <pm_allow_tx+0x49> */
  a2 = 0x1; /* 0039: movi.n a2, 1 */
  if (a10 == 0) goto L_68; /* 003b: beqz.n a10, 68 <pm_allow_tx+0x58> */
  MEMW(); /* 003d: memw  */
  a10 = MEM8(a12 + 0); /* 0040: l8ui a10, a12, 0 */
  a2 = a8; /* 0043: mov.n a2, a8 */
  a10 = (a10 >> 0) & 0xFF; /* 0045: extui a10, a10, 0, 8 */
  if (a10 == 0) goto L_68; /* 0048: beqz.n a10, 68 <pm_allow_tx+0x58> */
  a8 = MEM8(a9 + 2); /* 004a: l8ui a8, a9, 2 */
  a9 = 0x1; /* 004d: movi.n a9, 1 */
  a8 = a8 - a11; /* 004f: sub a8, a8, a11 */
  if (a8 != 0) a2 = a9; /* 0052: movnez a2, a9, a8 */
  goto L_68; /* 0055: j 68 <pm_allow_tx+0x58> */
  /* 0058: .byte 00 */
L_59:;
  a2 = 0x1; /* 0059: movi.n a2, 1 */
  if (a10 == 0) goto L_68; /* 005b: beqz.n a10, 68 <pm_allow_tx+0x58> */
  a8 = MEM8(a9 + 2); /* 005d: l8ui a8, a9, 2 */
  a9 = 0x0; /* 0060: movi.n a9, 0 */
  a8 = a8 - a11; /* 0062: sub a8, a8, a11 */
  if (a8 == 0) a2 = a9; /* 0065: moveqz a2, a9, a8 */
L_68:;
  return (int32_t)a2; /* 0068: retw.n  */
}

/* pm_allow_to_enable_bcn_filter @ pm.o 00000000 size 7B bind GLOBAL
 * Calls: none | Data refs: none
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t pm_allow_to_enable_bcn_filter(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pm_allow_to_enable_bcn_filter; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_0:;
  /* 0000: entry a1, 32 */
  a2 = 0x0; /* 0003: movi.n a2, 0 */
  return (int32_t)a2; /* 0005: retw.n  */
}

/* pm_get_connectionless_status @ pm.o 00000004 size 39B bind GLOBAL
 * Calls: none | Data refs: g_pm
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t pm_get_connectionless_status(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .wifislpiram.4; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a10 = (uint32_t)&g_pm; /* 0007: l32r a10, 0 <pm_get_connectionless_status-0x4> (0 <pm_get_connectionless_status-0x4>) */ /* literal @0x0: g_pm */
  a8 = MEM32(a10 + 352); /* 000a: l32i a8, a10, 0x160 */
  a2 = a8; /* 000d: mov.n a2, a8 */
  if (a8 == 0) goto L_29; /* 000f: beqz.n a8, 29 <pm_get_connectionless_status+0x25> */
  a9 = MEM32(a8 + 0); /* 0011: l32i.n a9, a8, 0 */
  a2 = a9; /* 0013: mov.n a2, a9 */
  if (a9 == 0) goto L_29; /* 0015: beqz.n a9, 29 <pm_get_connectionless_status+0x25> */
  a2 = 0xFFFFFFFE; /* 0017: movi.n a2, -2 */
  a8 = MEM16(a10 + 394); /* 0019: l16ui a8, a10, 0x18a */
  if (a8 == 0) goto L_29; /* 001c: beqz.n a8, 29 <pm_get_connectionless_status+0x25> */
  a2 = MEM16(a9 + 0); /* 001e: l16ui a2, a9, 0 */
  a8 = a8 - a2; /* 0021: sub a8, a8, a2 */
  if (a8 >= 6) goto L_29; /* 0024: bgei a8, 6, 29 <pm_get_connectionless_status+0x25> */
  a2 = 0xFFFFFFFF; /* 0027: movi.n a2, -1 */
L_29:;
  return (int32_t)a2; /* 0029: retw.n  */
}

/* pm_mac_sleep_init @ pm.o 00000004 size 11B bind GLOBAL
 * Calls: wdev_mac_sleep_init | Data refs: wdev_mac_sleep_init
 *   MMIO: none
 *   funcdb v3: 1 call(s), 1 ref(s); disasm: 1 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t pm_mac_sleep_init(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pm_mac_sleep_init; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a8 = (uint32_t)&wdev_mac_sleep_init; /* 0007: l32r a8, 0 <pm_mac_sleep_init-0x4> (0 <pm_mac_sleep_init-0x4>) */ /* literal: GOT slot for wdev_mac_sleep_init */
  wdev_mac_sleep_init(a2, a3, a4, a5); /* call via literal slot */ /* 000a: callx8 a8 */
  return (int32_t)a2; /* 000d: retw.n  */
}

/* pm_mac_sleep_deinit @ pm.o 00000004 size 11B bind GLOBAL
 * Calls: wdev_mac_sleep_deinit | Data refs: wdev_mac_sleep_deinit
 *   MMIO: none
 *   funcdb v3: 1 call(s), 1 ref(s); disasm: 1 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t pm_mac_sleep_deinit(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pm_mac_sleep_deinit; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a8 = (uint32_t)&wdev_mac_sleep_deinit; /* 0007: l32r a8, 0 <pm_mac_sleep_deinit-0x4> (0 <pm_mac_sleep_deinit-0x4>) */ /* literal: GOT slot for wdev_mac_sleep_deinit */
  wdev_mac_sleep_deinit(a2, a3, a4, a5); /* call via literal slot */ /* 000a: callx8 a8 */
  return (int32_t)a2; /* 000d: retw.n  */
}

/* pm_enable_keep_alive_timer @ pm.o 00000018 size 96B bind GLOBAL
 * Calls: g_pm_cfg[got], g_osi_funcs_p[got] | Data refs: g_mesh_is_root, g_mesh_is_started, g_osi_funcs_p, g_pm, g_pm_cfg
 *   MMIO: none
 *   funcdb v3: 0 call(s), 5 ref(s); disasm: 2 call(s), 5 data ref(s)
 * Fidelity: medium - 36 instr, 5 branches, calls resolved */
int32_t pm_enable_keep_alive_timer(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pm_enable_keep_alive_timer; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_18:;
  /* 0018: entry a1, 32 */
  a8 = (uint32_t)&g_pm_cfg; /* 001b: l32r a8, 4 <pm_enable_keep_alive_timer-0x14> (0 <pm_enable_keep_alive_timer-0x18>) */ /* literal @0x4: g_pm_cfg */
  a2 = MEM8(a8 + 29); /* 001e: l8ui a2, a8, 29 */
  if (a2 == 0) goto L_3a; /* 0021: beqz.n a2, 3a <pm_enable_keep_alive_timer+0x22> */
  a2 = MEM16(a8 + 48); /* 0023: l16ui a2, a8, 48 */
  a3 = a2 << (10 & 31); /* 0026: slli a3, a2, 10 */
  a2 = a2 << (15 & 31); /* 0029: slli a2, a2, 15 */
  a2 = a2 - a3; /* 002c: sub a2, a2, a3 */
  a2 = (a2 << 4) + a3; /* 002f: addx4 a2, a2, a3 */
  a3 = MEM32(a8 + 32); /* 0032: l32i.n a3, a8, 32 */
  a2 = a3 - (a2 << 8) /* verify order vs disasm */; /* 0034: subx8 a2, a2, a3 */
  goto L_58; /* 0037: j 58 <pm_enable_keep_alive_timer+0x40> */
L_3a:;
  a2 = MEM32(a8 + 16); /* 003a: l32i.n a2, a8, 16 */
  if (a2 == 0) goto L_76; /* 003c: beqz.n a2, 76 <pm_enable_keep_alive_timer+0x5e> */
  a3 = (uint32_t)&g_mesh_is_started; /* 003e: l32r a3, 8 <pm_enable_keep_alive_timer-0x10> (0 <pm_enable_keep_alive_timer-0x18>) */ /* literal @0x8: g_mesh_is_started */
  a3 = MEM8(a3 + 0); /* 0041: l8ui a3, a3, 0 */
  if (a3 == 0) goto L_58; /* 0044: beqz a3, 58 <pm_enable_keep_alive_timer+0x40> */
  a3 = (uint32_t)&g_mesh_is_root; /* 0047: l32r a3, c <pm_enable_keep_alive_timer-0xc> (0 <pm_enable_keep_alive_timer-0x18>) */ /* literal @0xC: g_mesh_is_root */
  MEMW(); /* 004a: memw  */
  a8 = MEM8(a3 + 0); /* 004d: l8ui a8, a3, 0 */
  a8 = (a8 >> 0) & 0xFF; /* 0050: extui a8, a8, 0, 8 */
  if (a8 != 0) goto L_58; /* 0053: bnez.n a8, 58 <pm_enable_keep_alive_timer+0x40> */
  a2 = 0x2DC6C0; /* 0055: l32r a2, 0 <pm_enable_keep_alive_timer-0x18> (2dc6c0 <pm_attach+0x2dc63c>) */ @0x0
L_58:;
  a4 = (uint32_t)&g_osi_funcs_p; /* 0058: l32r a4, 14 <pm_enable_keep_alive_timer-0x4> (0 <pm_enable_keep_alive_timer-0x18>) */ /* literal @0x14: g_osi_funcs_p */
  a8 = MEM32(a4 + 0); /* 005b: l32i.n a8, a4, 0 */
  a3 = (uint32_t)&g_pm; /* 005d: l32r a3, 10 <pm_enable_keep_alive_timer-0x8> (0 <pm_enable_keep_alive_timer-0x18>) */ /* literal @0x10: g_pm */
  a10 = a3; /* 0060: mov.n a10, a3 */
  a8 = MEM32(a8 + 236); /* 0062: l32i a8, a8, 236 */
  ((int32_t(*)())a8)(a2, a3, a4, a5); /* 0065: callx8 a8 */ /* indirect */
  a12 = 0x0; /* 0068: movi.n a12, 0 */
  a11 = a2; /* 006a: mov.n a11, a2 */
  a4 = MEM32(a4 + 0); /* 006c: l32i.n a4, a4, 0 */
  a10 = a3; /* 006e: mov.n a10, a3 */
  a4 = MEM32(a4 + 248); /* 0070: l32i a4, a4, 248 */
  g_osi_funcs_p(a2, a3, a4, a5); /* call via literal slot */ /* 0073: callx8 a4 */
L_76:;
  return (int32_t)a2; /* 0076: retw.n  */
}

/* pm_disable_keep_alive_timer @ pm.o 00000008 size 19B bind GLOBAL
 * Calls: g_osi_funcs_p[got] | Data refs: g_osi_funcs_p, g_pm
 *   MMIO: none
 *   funcdb v3: 0 call(s), 2 ref(s); disasm: 1 call(s), 2 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t pm_disable_keep_alive_timer(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pm_disable_keep_alive_timer; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_8:;
  /* 0008: entry a1, 32 */
  a8 = (uint32_t)&g_osi_funcs_p; /* 000b: l32r a8, 4 <pm_disable_keep_alive_timer-0x4> (0 <pm_disable_keep_alive_timer-0x8>) */ /* literal @0x4: g_osi_funcs_p */
  a8 = MEM32(a8 + 0); /* 000e: l32i.n a8, a8, 0 */
  a10 = (uint32_t)&g_pm; /* 0010: l32r a10, 0 <pm_disable_keep_alive_timer-0x8> (0 <pm_disable_keep_alive_timer-0x8>) */ /* literal @0x0: g_pm */
  a8 = MEM32(a8 + 236); /* 0013: l32i a8, a8, 236 */
  g_osi_funcs_p(a2, a3, a4, a5); /* call via literal slot */ /* 0016: callx8 a8 */
  return (int32_t)a2; /* 0019: retw.n  */
}

/* pm_is_sending_keep_alive @ pm.o 00000004 size 14B bind GLOBAL
 * Calls: none | Data refs: g_pm
 *   MMIO: none
 *   funcdb v3: 0 call(s), 1 ref(s); disasm: 0 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t pm_is_sending_keep_alive(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pm_is_sending_keep_alive; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a8 = (uint32_t)&g_pm; /* 0007: l32r a8, 0 <pm_is_sending_keep_alive-0x4> (0 <pm_is_sending_keep_alive-0x4>) */ /* literal @0x0: g_pm */
  a8 = a8 + ((0x100) << 8); /* 000a: addmi a8, a8, 0x100 */
  a2 = MEM8(a8 + 232); /* 000d: l8ui a2, a8, 232 */
  return (int32_t)a2; /* 0010: retw.n  */
}

/* pm_set_bss_max_idle @ pm.o 0000000c size 59B bind GLOBAL
 * Calls: none | Data refs: g_pm_cfg
 *   MMIO: none
 *   funcdb v3: 0 call(s), 1 ref(s); disasm: 0 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t pm_set_bss_max_idle(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pm_set_bss_max_idle; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_c:;
  /* 000c: entry a1, 32 */
  a2 = (a2 >> 0) & 0xFFFF; /* 000f: extui a2, a2, 0, 16 */
  a8 = (uint32_t)&g_pm_cfg; /* 0012: l32r a8, 0 <pm_set_bss_max_idle-0xc> (0 <pm_set_bss_max_idle-0xc>) */ /* literal @0x0: g_pm_cfg */
  if (a2 == 0) goto L_3c; /* 0015: beqz.n a2, 3c <pm_set_bss_max_idle+0x30> */
  a9 = 0x1; /* 0017: movi.n a9, 1 */
  MEM8(a8 + 29) = a9; /* 0019: s8i a9, a8, 29 */
  MEM16(a8 + 48) = a2; /* 001c: s16i a2, a8, 48 */
  MEMW(); /* 001f: memw  */
  if (a2 >= 4) goto L_30; /* 0022: bgeui a2, 4, 30 <pm_set_bss_max_idle+0x24> */
  a2 = 0x7A120; /* 0025: l32r a2, 4 <pm_set_bss_max_idle-0x8> (7a120 <pm_attach+0x7a09c>) */ @0x4
  MEMW(); /* 0028: memw  */
  goto L_33; /* 002b: j 33 <pm_set_bss_max_idle+0x27> */
  /* 002e: .byte 00 */
  /* 002f: .byte 00 */
L_30:;
  a2 = 0x1E8480; /* 0030: l32r a2, 8 <pm_set_bss_max_idle-0x4> (1e8480 <pm_attach+0x1e83fc>) */ @0x8
L_33:;
  MEM32(a8 + 32) = a2; /* 0033: s32i.n a2, a8, 32 */
  MEMW(); /* 0035: memw  */
  goto L_42; /* 0038: j 42 <pm_set_bss_max_idle+0x36> */
  /* 003b: .byte 00 */
L_3c:;
  MEM8(a8 + 29) = a2; /* 003c: s8i a2, a8, 29 */
  MEMW(); /* 003f: memw  */
L_42:;
  MEMW(); /* 0042: memw  */
  return (int32_t)a2; /* 0045: retw.n  */
}

/* pm_noise_check_disable @ pm.o 00000004 size 19B bind GLOBAL
 * Calls: none | Data refs: g_pm
 *   MMIO: none
 *   funcdb v3: 0 call(s), 1 ref(s); disasm: 0 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t pm_noise_check_disable(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pm_noise_check_disable; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a8 = (uint32_t)&g_pm; /* 0007: l32r a8, 0 <pm_noise_check_disable-0x4> (0 <pm_noise_check_disable-0x4>) */ /* literal @0x0: g_pm */
  a9 = 0x0; /* 000a: movi.n a9, 0 */
  MEM8(a8 + 21) = a9; /* 000c: s8i a9, a8, 21 */
  MEMW(); /* 000f: memw  */
  MEMW(); /* 0012: memw  */
  return (int32_t)a2; /* 0015: retw.n  */
}

/* pm_noise_check_enable @ pm.o 00000004 size 19B bind GLOBAL
 * Calls: none | Data refs: g_pm
 *   MMIO: none
 *   funcdb v3: 0 call(s), 1 ref(s); disasm: 0 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t pm_noise_check_enable(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pm_noise_check_enable; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a8 = (uint32_t)&g_pm; /* 0007: l32r a8, 0 <pm_noise_check_enable-0x4> (0 <pm_noise_check_enable-0x4>) */ /* literal @0x0: g_pm */
  a9 = 0x1; /* 000a: movi.n a9, 1 */
  MEM8(a8 + 21) = a9; /* 000c: s8i a9, a8, 21 */
  MEMW(); /* 000f: memw  */
  MEMW(); /* 0012: memw  */
  return (int32_t)a2; /* 0015: retw.n  */
}

/* pm_enable_active_timer @ pm.o 00000018 size 72B bind GLOBAL
 * Calls: g_osi_funcs_p[got] | Data refs: g_osi_funcs_p, g_pm, g_mesh_is_started, g_mesh_is_root, g_mesh_init_ps_type
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 1 call(s), 5 data ref(s)
 * Fidelity: medium - 28 instr, 4 branches, calls resolved */
int32_t pm_enable_active_timer(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .wifirxiram.17; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_18:;
  /* 0018: entry a1, 32 */
  a3 = (uint32_t)&g_osi_funcs_p; /* 001b: l32r a3, 4 <pm_enable_active_timer-0x14> (0 <pm_enable_active_timer-0x18>) */ /* literal @0x4: g_osi_funcs_p */
  a8 = MEM32(a3 + 0); /* 001e: l32i a8, a3, 0 */
  a2 = (uint32_t)&g_pm; /* 0021: l32r a2, 0 <pm_enable_active_timer-0x18> (0 <pm_enable_active_timer-0x18>) */ /* literal @0x0: g_pm */
  a10 = a2; /* 0024: mov.n a10, a2 */
  a8 = MEM32(a8 + 236); /* 0026: l32i a8, a8, 236 */
  ((int32_t(*)())a8)(a2, a3, a4, a5); /* 0029: callx8 a8 */ /* indirect */
  a9 = (uint32_t)&g_pm; /* 002c: l32r a9, 8 <pm_enable_active_timer-0x10> (0 <pm_enable_active_timer-0x18>) */ /* literal @0x8: g_pm */
  a8 = MEM32(a9 + 36); /* 002f: l32i.n a8, a9, 36 */
  if (a8 == 0) goto L_5e; /* 0031: beqz.n a8, 5e <pm_enable_active_timer+0x46> */
  a8 = (uint32_t)&g_mesh_is_started; /* 0033: l32r a8, c <pm_enable_active_timer-0xc> (0 <pm_enable_active_timer-0x18>) */ /* literal @0xC: g_mesh_is_started */
  a8 = MEM8(a8 + 0); /* 0036: l8ui a8, a8, 0 */
  if (a8 == 0) goto L_50; /* 0039: beqz.n a8, 50 <pm_enable_active_timer+0x38> */
  a8 = (uint32_t)&g_mesh_is_root; /* 003b: l32r a8, 10 <pm_enable_active_timer-0x8> (0 <pm_enable_active_timer-0x18>) */ /* literal @0x10: g_mesh_is_root */
  MEMW(); /* 003e: memw  */
  a8 = MEM8(a8 + 0); /* 0041: l8ui a8, a8, 0 */
  a8 = (a8 >> 0) & 0xFF; /* 0044: extui a8, a8, 0, 8 */
  if (a8 != 0) goto L_50; /* 0047: bnez.n a8, 50 <pm_enable_active_timer+0x38> */
  a8 = (uint32_t)&g_mesh_init_ps_type; /* 0049: l32r a8, 14 <pm_enable_active_timer-0x4> (0 <pm_enable_active_timer-0x18>) */ /* literal @0x14: g_mesh_init_ps_type */
  a8 = MEM32(a8 + 0); /* 004c: l32i.n a8, a8, 0 */
  if (a8 != 0) goto L_5e; /* 004e: bnez.n a8, 5e <pm_enable_active_timer+0x46> */
L_50:;
  a12 = 0x0; /* 0050: movi.n a12, 0 */
  a10 = a2; /* 0052: mov.n a10, a2 */
  a3 = MEM32(a3 + 0); /* 0054: l32i.n a3, a3, 0 */
  a11 = MEM32(a9 + 48); /* 0056: l32i.n a11, a9, 48 */
  a3 = MEM32(a3 + 248); /* 0058: l32i a3, a3, 248 */
  g_osi_funcs_p(a2, a3, a4, a5); /* call via literal slot */ /* 005b: callx8 a3 */
L_5e:;
  return (int32_t)a2; /* 005e: retw.n  */
}

/* pm_disable_dream_timer @ pm.o 00000008 size 19B bind GLOBAL
 * Calls: g_osi_funcs_p[got] | Data refs: g_osi_funcs_p, g_pm
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 1 call(s), 2 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t pm_disable_dream_timer(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .wifislpiram.18; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_8:;
  /* 0008: entry a1, 32 */
  a8 = (uint32_t)&g_osi_funcs_p; /* 000b: l32r a8, 4 <pm_disable_dream_timer-0x4> (0 <pm_disable_dream_timer-0x8>) */ /* literal @0x4: g_osi_funcs_p */
  a8 = MEM32(a8 + 0); /* 000e: l32i.n a8, a8, 0 */
  a10 = (uint32_t)&g_pm; /* 0010: l32r a10, 0 <pm_disable_dream_timer-0x8> (0 <pm_disable_dream_timer-0x8>) */ /* literal @0x0: g_pm */
  a8 = MEM32(a8 + 236); /* 0013: l32i a8, a8, 236 */
  g_osi_funcs_p(a2, a3, a4, a5); /* call via literal slot */ /* 0016: callx8 a8 */
  return (int32_t)a2; /* 0019: retw.n  */
}

/* pm_enable_dream_timer @ pm.o 0000000c size 40B bind GLOBAL
 * Calls: g_osi_funcs_p[got] | Data refs: g_osi_funcs_p, g_pm
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 1 call(s), 2 data ref(s)
 * Fidelity: medium - 15 instr, 0 branches, calls resolved */
int32_t pm_enable_dream_timer(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .wifislpiram.19; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_c:;
  /* 000c: entry a1, 32 */
  a3 = (uint32_t)&g_osi_funcs_p; /* 000f: l32r a3, 4 <pm_enable_dream_timer-0x8> (0 <pm_enable_dream_timer-0xc>) */ /* literal @0x4: g_osi_funcs_p */
  a8 = MEM32(a3 + 0); /* 0012: l32i a8, a3, 0 */
  a2 = (uint32_t)&g_pm; /* 0015: l32r a2, 0 <pm_enable_dream_timer-0xc> (0 <pm_enable_dream_timer-0xc>) */ /* literal @0x0: g_pm */
  a10 = a2; /* 0018: mov.n a10, a2 */
  a8 = MEM32(a8 + 236); /* 001a: l32i a8, a8, 236 */
  ((int32_t(*)())a8)(a2, a3, a4, a5); /* 001d: callx8 a8 */ /* indirect */
  a12 = 0x0; /* 0020: movi.n a12, 0 */
  a10 = a2; /* 0022: mov.n a10, a2 */
  a8 = (uint32_t)&g_pm; /* 0024: l32r a8, 8 <pm_enable_dream_timer-0x4> (0 <pm_enable_dream_timer-0xc>) */ /* literal @0x8: g_pm */
  a3 = MEM32(a3 + 0); /* 0027: l32i.n a3, a3, 0 */
  a11 = MEM32(a8 + 452); /* 0029: l32i a11, a8, 0x1c4 */
  a3 = MEM32(a3 + 248); /* 002c: l32i a3, a3, 248 */
  g_osi_funcs_p(a2, a3, a4, a5); /* call via literal slot */ /* 002f: callx8 a3 */
  return (int32_t)a2; /* 0032: retw.n  */
}

/* pm_disable_sleep_delay_timer @ pm.o 0000000c size 36B bind GLOBAL
 * Calls: g_osi_funcs_p[got] | Data refs: g_pm, g_osi_funcs_p
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 1 call(s), 2 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t pm_disable_sleep_delay_timer(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .wifislprxiram.20; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_c:;
  /* 000c: entry a1, 32 */
  a8 = (uint32_t)&g_pm; /* 000f: l32r a8, 0 <pm_disable_sleep_delay_timer-0xc> (0 <pm_disable_sleep_delay_timer-0xc>) */ /* literal @0x0: g_pm */
  a9 = 0x0; /* 0012: movi.n a9, 0 */
  a8 = a8 + ((0x100) << 8); /* 0014: addmi a8, a8, 0x100 */
  MEM8(a8 + 184) = a9; /* 0017: s8i a9, a8, 184 */
  MEMW(); /* 001a: memw  */
  a8 = (uint32_t)&g_osi_funcs_p; /* 001d: l32r a8, 8 <pm_disable_sleep_delay_timer-0x4> (0 <pm_disable_sleep_delay_timer-0xc>) */ /* literal @0x8: g_osi_funcs_p */
  a8 = MEM32(a8 + 0); /* 0020: l32i.n a8, a8, 0 */
  a10 = (uint32_t)&g_pm; /* 0022: l32r a10, 4 <pm_disable_sleep_delay_timer-0x8> (0 <pm_disable_sleep_delay_timer-0xc>) */ /* literal @0x4: g_pm */
  a8 = MEM32(a8 + 236); /* 0025: l32i a8, a8, 236 */
  MEMW(); /* 0028: memw  */
  g_osi_funcs_p(a2, a3, a4, a5); /* call via literal slot */ /* 002b: callx8 a8 */
  return (int32_t)a2; /* 002e: retw.n  */
}

/* pm_enable_sleep_delay_timer @ pm.o 0000000c size 55B bind GLOBAL
 * Calls: g_osi_funcs_p[got] | Data refs: g_osi_funcs_p, g_pm
 *   MMIO: none
 *   funcdb v3: 0 call(s), 2 ref(s); disasm: 1 call(s), 2 data ref(s)
 * Fidelity: medium - 20 instr, 0 branches, calls resolved */
int32_t pm_enable_sleep_delay_timer(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pm_enable_sleep_delay_timer; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_c:;
  /* 000c: entry a1, 32 */
  a4 = (uint32_t)&g_osi_funcs_p; /* 000f: l32r a4, 4 <pm_enable_sleep_delay_timer-0x8> (0 <pm_enable_sleep_delay_timer-0xc>) */ /* literal @0x4: g_osi_funcs_p */
  a2 = MEM32(a4 + 0); /* 0012: l32i a2, a4, 0 */
  a3 = (uint32_t)&g_pm; /* 0015: l32r a3, 0 <pm_enable_sleep_delay_timer-0xc> (0 <pm_enable_sleep_delay_timer-0xc>) */ /* literal @0x0: g_pm */
  a10 = a3; /* 0018: mov.n a10, a3 */
  a2 = MEM32(a2 + 236); /* 001a: l32i a2, a2, 236 */
  ((int32_t(*)())a2)(a2, a3, a4, a5); /* 001d: callx8 a2 */ /* indirect */
  a10 = a3; /* 0020: mov.n a10, a3 */
  a12 = 0x0; /* 0022: movi.n a12, 0 */
  a2 = (uint32_t)&g_pm; /* 0024: l32r a2, 8 <pm_enable_sleep_delay_timer-0x4> (0 <pm_enable_sleep_delay_timer-0xc>) */ /* literal @0x8: g_pm */
  a3 = 0x1; /* 0027: movi.n a3, 1 */
  a4 = MEM32(a4 + 0); /* 0029: l32i a4, a4, 0 */
  a11 = MEM32(a2 + 56); /* 002c: l32i a11, a2, 56 */
  a2 = a2 + ((0x100) << 8); /* 002f: addmi a2, a2, 0x100 */
  a4 = MEM32(a4 + 248); /* 0032: l32i a4, a4, 248 */
  g_osi_funcs_p(a2, a3, a4, a5); /* call via literal slot */ /* 0035: callx8 a4 */
  MEM8(a2 + 184) = a3; /* 0038: s8i a3, a2, 184 */
  MEMW(); /* 003b: memw  */
  MEMW(); /* 003e: memw  */
  return (int32_t)a2; /* 0041: retw.n  */
}

/* pm_disable_disconnected_sleep_delay_timer @ pm.o 0000000c size 36B bind GLOBAL
 * Calls: g_osi_funcs_p[got] | Data refs: g_osi_funcs_p, g_pm
 *   MMIO: none
 *   funcdb v3: 0 call(s), 2 ref(s); disasm: 1 call(s), 2 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t pm_disable_disconnected_sleep_delay_timer(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pm_disable_disconnected_sleep_delay_timer; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_c:;
  /* 000c: entry a1, 32 */
  a8 = (uint32_t)&g_pm; /* 000f: l32r a8, 0 <pm_disable_disconnected_sleep_delay_timer-0xc> (0 <pm_disable_disconnected_sleep_delay_timer-0xc>) */ /* literal @0x0: g_pm */
  a9 = 0x0; /* 0012: movi.n a9, 0 */
  a8 = a8 + ((0x100) << 8); /* 0014: addmi a8, a8, 0x100 */
  MEM8(a8 + 184) = a9; /* 0017: s8i a9, a8, 184 */
  MEMW(); /* 001a: memw  */
  a8 = (uint32_t)&g_osi_funcs_p; /* 001d: l32r a8, 8 <pm_disable_disconnected_sleep_delay_timer-0x4> (0 <pm_disable_disconnected_sleep_delay_timer-0xc>) */ /* literal @0x8: g_osi_funcs_p */
  a8 = MEM32(a8 + 0); /* 0020: l32i.n a8, a8, 0 */
  a10 = (uint32_t)&g_pm; /* 0022: l32r a10, 4 <pm_disable_disconnected_sleep_delay_timer-0x8> (0 <pm_disable_disconnected_sleep_delay_timer-0xc>) */ /* literal @0x4: g_pm */
  a8 = MEM32(a8 + 236); /* 0025: l32i a8, a8, 236 */
  MEMW(); /* 0028: memw  */
  g_osi_funcs_p(a2, a3, a4, a5); /* call via literal slot */ /* 002b: callx8 a8 */
  return (int32_t)a2; /* 002e: retw.n  */
}

/* pm_enable_disconnected_sleep_delay_timer @ pm.o 00000010 size 71B bind GLOBAL
 * Calls: g_osi_funcs_p[got] | Data refs: g_mesh_is_started, g_osi_funcs_p, g_pm
 *   MMIO: none
 *   funcdb v3: 0 call(s), 3 ref(s); disasm: 1 call(s), 3 data ref(s)
 * Fidelity: medium - 25 instr, 2 branches, calls resolved */
int32_t pm_enable_disconnected_sleep_delay_timer(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pm_enable_disconnected_sleep_delay_timer; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_10:;
  /* 0010: entry a1, 32 */
  a2 = (uint32_t)&g_pm; /* 0013: l32r a2, 0 <pm_enable_disconnected_sleep_delay_timer-0x10> (0 <pm_enable_disconnected_sleep_delay_timer-0x10>) */ /* literal @0x0: g_pm */
  a2 = a2 + ((0x100) << 8); /* 0016: addmi a2, a2, 0x100 */
  a3 = MEM8(a2 + 29); /* 0019: l8ui a3, a2, 29 */
  if (a3 != 2) goto L_52; /* 001c: bnei a3, 2, 52 <pm_enable_disconnected_sleep_delay_timer+0x42> */
  a3 = (uint32_t)&g_mesh_is_started; /* 001f: l32r a3, 4 <pm_enable_disconnected_sleep_delay_timer-0xc> (0 <pm_enable_disconnected_sleep_delay_timer-0x10>) */ /* literal @0x4: g_mesh_is_started */
  a4 = MEM8(a3 + 0); /* 0022: l8ui a4, a3, 0 */
  if (a4 != 0) goto L_52; /* 0025: bnez a4, 52 <pm_enable_disconnected_sleep_delay_timer+0x42> */
  a5 = (uint32_t)&g_osi_funcs_p; /* 0028: l32r a5, c <pm_enable_disconnected_sleep_delay_timer-0x4> (0 <pm_enable_disconnected_sleep_delay_timer-0x10>) */ /* literal @0xC: g_osi_funcs_p */
  a8 = MEM32(a5 + 0); /* 002b: l32i a8, a5, 0 */
  a3 = (uint32_t)&g_pm; /* 002e: l32r a3, 8 <pm_enable_disconnected_sleep_delay_timer-0x8> (0 <pm_enable_disconnected_sleep_delay_timer-0x10>) */ /* literal @0x8: g_pm */
  a10 = a3; /* 0031: mov.n a10, a3 */
  a8 = MEM32(a8 + 236); /* 0033: l32i a8, a8, 236 */
  ((int32_t(*)())a8)(a2, a3, a4, a5); /* 0036: callx8 a8 */ /* indirect */
  a10 = a3; /* 0039: mov.n a10, a3 */
  a12 = a4; /* 003b: mov.n a12, a4 */
  a5 = MEM32(a5 + 0); /* 003d: l32i a5, a5, 0 */
  a11 = 0x3E8; /* 0040: movi a11, 0x3e8 */
  a3 = 0x1; /* 0043: movi a3, 1 */
  a5 = MEM32(a5 + 248); /* 0046: l32i a5, a5, 248 */
  g_osi_funcs_p(a2, a3, a4, a5); /* call via literal slot */ /* 0049: callx8 a5 */
  MEM8(a2 + 184) = a3; /* 004c: s8i a3, a2, 184 */
  MEMW(); /* 004f: memw  */
L_52:;
  MEMW(); /* 0052: memw  */
  return (int32_t)a2; /* 0055: retw.n  */
}

/* pm_noise_check @ pm.o 00000010 size 98B bind GLOBAL
 * Calls: noise_check_loop, read_hw_noisefloor | Data refs: g_pm, noise_check_loop, read_hw_noisefloor, wDevCtrl
 *   MMIO: none
 *   funcdb v3: 2 call(s), 4 ref(s); disasm: 2 call(s), 4 data ref(s)
 * Fidelity: medium - 36 instr, 7 branches, calls resolved */
int32_t pm_noise_check(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pm_noise_check; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_10:;
  /* 0010: entry a1, 32 */
  a9 = (uint32_t)&g_pm; /* 0013: l32r a9, 0 <pm_noise_check-0x10> (0 <pm_noise_check-0x10>) */ /* literal @0x0: g_pm */
  a2 = 0xFFFFFFFE; /* 0016: movi.n a2, -2 */
  a8 = MEM8(a9 + 21); /* 0018: l8ui a8, a9, 21 */
  if (a8 == 0) goto L_70; /* 001b: beqz a8, 70 <pm_noise_check+0x60> */
  a2 = MEM32(a9 + 36); /* 001e: l32i.n a2, a9, 36 */
  a8 = MEM32(a9 + 44); /* 0020: l32i.n a8, a9, 44 */
  if (a2 == 0) goto L_36; /* 0022: beqz.n a2, 36 <pm_noise_check+0x26> */
  if (a2 != 1) goto L_2d; /* 0024: bnei a2, 1, 2d <pm_noise_check+0x1d> */
  a2 = MEM8(a9 + 11); /* 0027: l8ui a2, a9, 11 */
  goto L_33; /* 002a: j 33 <pm_noise_check+0x23> */
L_2d:;
  if (a2 != 2) goto L_36; /* 002d: bnei a2, 2, 36 <pm_noise_check+0x26> */
  a2 = MEM16(a9 + 32); /* 0030: l16ui a2, a9, 32 */
L_33:;
  a8 = (uint32_t)((uint64_t)a2 * a8); /* 0033: mull a8, a2, a8 */
L_36:;
  a2 = MEM16(a9 + 28); /* 0036: l16ui a2, a9, 28 */
  a9 = 0x1; /* 0039: movi.n a9, 1 */
  a9 = 0x40000; /* 003b: slli a9, a9, 18 */
  a9 = a8 + a9; /* 003e: add.n a9, a8, a9 */
  /* 0040: quos a9, a9, a8 */ /* UNMODELED: a9 clobbered */
  /* 0043: rems a2, a2, a9 */ /* UNMODELED: a2 clobbered */
  if (a2 != 0) goto L_6e; /* 0046: bnez.n a2, 6e <pm_noise_check+0x5e> */
  a11 = 0x1; /* 0048: movi a11, 1 */
  a10 = 0x1; /* 004b: or a10, a11, a11 */
  a8 = (uint32_t)&noise_check_loop; /* 004e: l32r a8, 8 <pm_noise_check-0x8> (0 <pm_noise_check-0x10>) */ /* literal: GOT slot for noise_check_loop */
  noise_check_loop(a2, a3, a4, a5); /* call via literal slot */ /* 0051: callx8 a8 */
  a8 = (uint32_t)&read_hw_noisefloor; /* 0054: l32r a8, c <pm_noise_check-0x4> (0 <pm_noise_check-0x10>) */ /* literal: GOT slot for read_hw_noisefloor */
  read_hw_noisefloor(a2, a3, a4, a5); /* call via literal slot */ /* 0057: callx8 a8 */
  a8 = (uint32_t)&wDevCtrl; /* 005a: l32r a8, 4 <pm_noise_check-0xc> (0 <pm_noise_check-0x10>) */ /* literal @0x4: wDevCtrl */
  a10 = 0x3; /* 005d: addi.n a10, a10, 2 */
  a10 = 0x0; /* 005f: srai a10, a10, 2 */
  MEM8(a8 + 47) = a10; /* 0062: s8i a10, a8, 47 */
  MEMW(); /* 0065: memw  */
  MEMW(); /* 0068: memw  */
  goto L_70; /* 006b: j 70 <pm_noise_check+0x60> */
L_6e:;
  a2 = 0x0; /* 006e: movi.n a2, 0 */
L_70:;
  return (int32_t)a2; /* 0070: retw.n  */
}

/* pm_pend_noise_check @ pm.o 00000000 size 5B bind GLOBAL
 * Calls: none | Data refs: none
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t pm_pend_noise_check(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pm_pend_noise_check; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_0:;
  /* 0000: entry a1, 32 */
  return (int32_t)a2; /* 0003: retw.n  */
}

/* pm_noise_check_process @ pm.o 00000000 size 5B bind GLOBAL
 * Calls: none | Data refs: none
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t pm_noise_check_process(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pm_noise_check_process; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_0:;
  /* 0000: entry a1, 32 */
  return (int32_t)a2; /* 0003: retw.n  */
}

/* pm_register_pm_tx_null_cb @ pm.o 00000004 size 15B bind GLOBAL
 * Calls: none | Data refs: .bss.g_pm_tx_null_func
 *   MMIO: none
 *   funcdb v3: 0 call(s), 1 ref(s); disasm: 0 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t pm_register_pm_tx_null_cb(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pm_register_pm_tx_null_cb; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a8 = (uint32_t)&bss_g_pm_tx_null_func; /* 0007: l32r a8, 0 <pm_register_pm_tx_null_cb-0x4> (0 <pm_register_pm_tx_null_cb-0x4>) */ /* literal @0x0: .bss.g_pm_tx_null_func */
  MEM32(a8 + 0) = a2; /* 000a: s32i.n a2, a8, 0 */
  a2 = 0x1; /* 000c: movi.n a2, 1 */
  MEMW(); /* 000e: memw  */
  return (int32_t)a2; /* 0011: retw.n  */
}

/* pm_send_nullfunc @ pm.o 0000000c size 89B bind GLOBAL
 * Calls: wifi_gpio_debug, .bss.g_pm_tx_null_func[got] | Data refs: .bss.g_pm_tx_null_func, g_pm, wifi_gpio_debug
 *   MMIO: none
 *   funcdb v3: 1 call(s), 3 ref(s); disasm: 2 call(s), 3 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t pm_send_nullfunc(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pm_send_nullfunc; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_c:;
  /* 000c: entry a1, 32 */
  a3 = (uint32_t)&g_pm; /* 000f: l32r a3, 0 <pm_send_nullfunc-0xc> (0 <pm_send_nullfunc-0xc>) */ /* literal @0x0: g_pm */
  a2 = (a2 >> 0) & 0xFF; /* 0012: extui a2, a2, 0, 8 */
  a8 = 0x1; /* 0015: movi.n a8, 1 */
  a5 = MEM8(a3 + 20); /* 0017: l8ui a5, a3, 20 */
  a4 = MEM8(a3 + 19); /* 001a: l8ui a4, a3, 19 */
  if (a2 == 0) goto L_30; /* 001d: beqz.n a2, 30 <pm_send_nullfunc+0x24> */
  MEM8(a3 + 20) = a8; /* 001f: s8i a8, a3, 20 */
  a8 = 0x0; /* 0022: movi.n a8, 0 */
  MEM8(a3 + 19) = a8; /* 0024: s8i a8, a3, 19 */
  MEMW(); /* 0027: memw  */
  MEMW(); /* 002a: memw  */
  goto L_39; /* 002d: j 39 <pm_send_nullfunc+0x2d> */
L_30:;
  MEM8(a3 + 19) = a8; /* 0030: s8i a8, a3, 19 */
  MEM8(a3 + 20) = a2; /* 0033: s8i a2, a3, 20 */
  MEMW(); /* 0036: memw  */
L_39:;
  a11 = a2 + (2); /* 0039: addi.n a11, a2, 2 */
  a10 = 0x6; /* 003b: movi.n a10, 6 */
  MEMW(); /* 003d: memw  */
  a8 = (uint32_t)&wifi_gpio_debug; /* 0040: l32r a8, 8 <pm_send_nullfunc-0x4> (0 <pm_send_nullfunc-0xc>) */ /* literal: GOT slot for wifi_gpio_debug */
  wifi_gpio_debug(a2, a3, a4, a5); /* call via literal slot */ /* 0043: callx8 a8 */
  a12 = 0x0; /* 0046: movi.n a12, 0 */
  a8 = (uint32_t)&bss_g_pm_tx_null_func; /* 0048: l32r a8, 4 <pm_send_nullfunc-0x8> (0 <pm_send_nullfunc-0xc>) */ /* literal @0x4: .bss.g_pm_tx_null_func */
  a11 = 0x0; /* 004b: mov.n a11, a12 */
  a10 = a2; /* 004d: mov.n a10, a2 */
  a8 = MEM32(a8 + 0); /* 004f: l32i a8, a8, 0 */
  bss_g_pm_tx_null_func(a2, a3, a4, a5); /* call via literal slot */ /* 0052: callx8 a8 */
  if (a10 != 0) goto L_60; /* 0055: bnez.n a10, 60 <pm_send_nullfunc+0x54> */
  MEM8(a3 + 20) = a5; /* 0057: s8i a5, a3, 20 */
  MEM8(a3 + 19) = a4; /* 005a: s8i a4, a3, 19 */
  MEMW(); /* 005d: memw  */
L_60:;
  MEMW(); /* 0060: memw  */
  return (int32_t)a2; /* 0063: retw.n  */
}

/* pm_mac_wakeup @ pm.o 00000004 size 11B bind GLOBAL
 * Calls: wdev_mac_wakeup | Data refs: wdev_mac_wakeup
 *   MMIO: none
 *   funcdb v3: 1 call(s), 1 ref(s); disasm: 1 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t pm_mac_wakeup(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pm_mac_wakeup; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a8 = (uint32_t)&wdev_mac_wakeup; /* 0007: l32r a8, 0 <pm_mac_wakeup-0x4> (0 <pm_mac_wakeup-0x4>) */ /* literal: GOT slot for wdev_mac_wakeup */
  wdev_mac_wakeup(a2, a3, a4, a5); /* call via literal slot */ /* 000a: callx8 a8 */
  return (int32_t)a2; /* 000d: retw.n  */
}

/* pm_mac_sleep @ pm.o 00000004 size 11B bind GLOBAL
 * Calls: wdev_mac_sleep | Data refs: wdev_mac_sleep
 *   MMIO: none
 *   funcdb v3: 1 call(s), 1 ref(s); disasm: 1 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t pm_mac_sleep(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pm_mac_sleep; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a8 = (uint32_t)&wdev_mac_sleep; /* 0007: l32r a8, 0 <pm_mac_sleep-0x4> (0 <pm_mac_sleep-0x4>) */ /* literal: GOT slot for wdev_mac_sleep */
  wdev_mac_sleep(a2, a3, a4, a5); /* call via literal slot */ /* 000a: callx8 a8 */
  return (int32_t)a2; /* 000d: retw.n  */
}

/* pm_get_tbtt_count @ pm.o 00000010 size 144B bind GLOBAL
 * Calls: __udivdi3[got], pm_coex_schm_overall_period_get[got] | Data refs: g_osi_funcs_p, g_pm, __udivdi3, pm_coex_schm_overall_period_get
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 2 call(s), 4 data ref(s)
 * Fidelity: medium - 57 instr, 10 branches, calls resolved */
int32_t pm_get_tbtt_count(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .wifislprxiram.22; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_10:;
  /* 0010: entry a1, 32 */
  a5 = (uint32_t)&g_osi_funcs_p; /* 0013: l32r a5, 0 <pm_get_tbtt_count-0x10> (0 <pm_get_tbtt_count-0x10>) */ /* literal @0x0: g_osi_funcs_p */
  a4 = MEM32(a5 + 0); /* 0016: l32i.n a4, a5, 0 */
  a10 = MEM32(a4 + 272); /* 0018: l32i a10, a4, 0x110 */
  ((int32_t(*)())a10)(a2, a3, a4, a5); /* 001b: callx8 a10 */ /* indirect */
  a8 = 0x1; /* 001e: movi.n a8, 1 */
  a4 = (uint32_t)&g_pm; /* 0020: l32r a4, 4 <pm_get_tbtt_count-0xc> (0 <pm_get_tbtt_count-0x10>) */ /* literal @0x4: g_pm */
  a12 = MEM32(a4 + 44); /* 0023: l32i.n a12, a4, 44 */
  a9 = MEM32(a4 + 88); /* 0025: l32i a9, a4, 88 */
  a9 = a12 + a9; /* 0028: add.n a9, a12, a9 */
  a6 = MEM32(a4 + 92); /* 002a: l32i a6, a4, 92 */
  if (a9 < a12) goto L_32; /* 002d: bltu a9, a12, 32 <pm_get_tbtt_count+0x22> */
  a8 = 0x0; /* 0030: movi.n a8, 0 */
L_32:;
  a13 = a8 + a6; /* 0032: add.n a13, a8, a6 */
  a8 = 0x1; /* 0034: movi.n a8, 1 */
  a6 = MEM32(a4 + 40); /* 0036: l32i.n a6, a4, 40 */
  a10 = a6 + a10; /* 0038: add.n a10, a6, a10 */
  if (a10 < a6) goto L_40; /* 003a: bltu a10, a6, 40 <pm_get_tbtt_count+0x30> */
  a8 = 0x0; /* 003d: movi a8, 0 */
L_40:;
  a10 = a9 - a10; /* 0040: sub a10, a9, a10 */
  a8 = a8 + a11; /* 0043: add.n a8, a8, a11 */
  a11 = 0x1; /* 0045: movi.n a11, 1 */
  if (a9 < a10) goto L_4c; /* 0047: bltu a9, a10, 4c <pm_get_tbtt_count+0x3c> */
  a11 = 0x0; /* 004a: movi.n a11, 0 */
L_4c:;
  a8 = a13 - a8; /* 004c: sub a8, a13, a8 */
  a11 = a8 - a11; /* 004f: sub a11, a8, a11 */
  a13 = 0x0; /* 0052: movi.n a13, 0 */
  a8 = (uint32_t)&udivdi3; /* 0054: l32r a8, 8 <pm_get_tbtt_count-0x8> (0 <pm_get_tbtt_count-0x10>) */ /* literal: GOT slot for __udivdi3 */
  udivdi3(a2, a3, a4, a5); /* call via literal slot */ /* 0057: callx8 a8 */
  a5 = MEM32(a5 + 0); /* 005a: l32i.n a5, a5, 0 */
  a6 = a10 | a10; /* 005c: or a6, a10, a10 */
  a10 = MEM32(a5 + 404); /* 005f: l32i a10, a5, 0x194 */
  ((int32_t(*)())a10)(a2, a3, a4, a5); /* 0062: callx8 a10 */ /* indirect */
  if (a10 == 0) goto L_78; /* 0065: beqz.n a10, 78 <pm_get_tbtt_count+0x68> */
  a10 = 0x1; /* 0067: movi.n a10, 1 */
  a4 = MEM8(a4 + 14); /* 0069: l8ui a4, a4, 14 */
  if (a4 == 0) goto L_8c; /* 006c: beqz.n a4, 8c <pm_get_tbtt_count+0x7c> */
  a8 = (uint32_t)&pm_coex_schm_overall_period_get; /* 006e: l32r a8, c <pm_get_tbtt_count-0x4> (0 <pm_get_tbtt_count-0x10>) */ /* literal: GOT slot for pm_coex_schm_overall_period_get */
  pm_coex_schm_overall_period_get(a2, a3, a4, a5); /* call via literal slot */ /* 0071: callx8 a8 */
  goto L_8c; /* 0074: j 8c <pm_get_tbtt_count+0x7c> */
  /* 0077: .byte 00 */
L_78:;
  a5 = MEM32(a4 + 36); /* 0078: l32i.n a5, a4, 36 */
  if (a5 != 1) goto L_84; /* 007a: bnei a5, 1, 84 <pm_get_tbtt_count+0x74> */
  a10 = MEM8(a4 + 11); /* 007d: l8ui a10, a4, 11 */
  goto L_8c; /* 0080: j 8c <pm_get_tbtt_count+0x7c> */
  /* 0083: .byte 00 */
L_84:;
  a10 = 0x1; /* 0084: movi.n a10, 1 */
  if (a5 != 2) goto L_8c; /* 0086: bnei a5, 2, 8c <pm_get_tbtt_count+0x7c> */
  a10 = MEM16(a4 + 32); /* 0089: l16ui a10, a4, 32 */
L_8c:;
  MEM32(a3 + 0) = a10; /* 008c: s32i.n a10, a3, 0 */
  a3 = 0x0; /* 008e: movi.n a3, 0 */
  if (a10 < a6) goto L_99; /* 0090: bltu a10, a6, 99 <pm_get_tbtt_count+0x89> */
  a3 = a10 - a6; /* 0093: sub a3, a10, a6 */
  /* 0096: remu a3, a3, a10 */ /* UNMODELED: a3 clobbered */
L_99:;
  MEM32(a2 + 0) = a3; /* 0099: s32i.n a3, a2, 0 */
  MEMW(); /* 009b: memw  */
  return (int32_t)a2; /* 009e: retw.n  */
}

/* pm_save_tbtt_info @ pm.o 00000004 size 37B bind GLOBAL
 * Calls: pm_get_tbtt_count[got] | Data refs: pm_get_tbtt_count
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 1 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t pm_save_tbtt_info(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .wifislprxiram.23; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 48 */
  a11 = a1; /* 0007: mov.n a11, a1 */
  a10 = a1 + (4); /* 0009: addi.n a10, a1, 4 */
  a8 = (uint32_t)&pm_get_tbtt_count; /* 000b: l32r a8, 0 <pm_save_tbtt_info-0x4> (0 <pm_save_tbtt_info-0x4>) */ /* literal: GOT slot for pm_get_tbtt_count */
  pm_get_tbtt_count(a2, a3, a4, a5); /* call via literal slot */ /* 000e: callx8 a8 */
  a8 = MEM32(a1 + 4); /* 0011: l32i.n a8, a1, 4 */
  a2 = a2 + ((0x100) << 8); /* 0013: addmi a2, a2, 0x100 */
  MEM8(a2 + 214) = a8; /* 0016: s8i a8, a2, 214 */
  MEMW(); /* 0019: memw  */
  a8 = MEM32(a1 + 0); /* 001c: l32i.n a8, a1, 0 */
  MEM8(a2 + 215) = a8; /* 001e: s8i a8, a2, 215 */
  MEMW(); /* 0021: memw  */
  MEMW(); /* 0024: memw  */
  return (int32_t)a2; /* 0027: retw.n  */
}

/* pm_beacon_miss_exceeded_wakeup_disabled @ pm.o 00000008 size 33B bind GLOBAL
 * Calls: none | Data refs: g_pm_cfg, g_pm
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 2 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t pm_beacon_miss_exceeded_wakeup_disabled(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .wifislprxiram.24; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_8:;
  /* 0008: entry a1, 32 */
  a2 = (uint32_t)&g_pm_cfg; /* 000b: l32r a2, 0 <pm_beacon_miss_exceeded_wakeup_disabled-0x8> (0 <pm_beacon_miss_exceeded_wakeup_disabled-0x8>) */ /* literal @0x0: g_pm_cfg */
  a8 = MEM8(a2 + 51); /* 000e: l8ui a8, a2, 51 */
  a2 = 0x1; /* 0011: movi.n a2, 1 */
  if (a8 == 2) goto L_24; /* 0013: beqi a8, 2, 24 <pm_beacon_miss_exceeded_wakeup_disabled+0x1c> */
  a2 = 0x0; /* 0016: movi.n a2, 0 */
  if (a8 != 1) goto L_24; /* 0018: bnei a8, 1, 24 <pm_beacon_miss_exceeded_wakeup_disabled+0x1c> */
  a2 = (uint32_t)&g_pm; /* 001b: l32r a2, 4 <pm_beacon_miss_exceeded_wakeup_disabled-0x4> (0 <pm_beacon_miss_exceeded_wakeup_disabled-0x8>) */ /* literal @0x4: g_pm */
  a2 = a2 + ((0x200) << 8); /* 001e: addmi a2, a2, 0x200 */
  a2 = MEM8(a2 + 28); /* 0021: l8ui a2, a2, 28 */
L_24:;
  a2 = (a2 >> 0) & 0x1; /* 0024: extui a2, a2, 0, 1 */
  return (int32_t)a2; /* 0027: retw.n  */
}

/* pm_beacon_monitor_tbtt_allowed @ pm.o 00000008 size 85B bind GLOBAL
 * Calls: pm_beacon_miss_exceeded_wakeup_disabled[got] | Data refs: pm_beacon_miss_exceeded_wakeup_disabled, ptr_beacon_offset_funcs
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 1 call(s), 2 data ref(s)
 * Fidelity: medium - 33 instr, 9 branches, calls resolved */
int32_t pm_beacon_monitor_tbtt_allowed(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .wifislprxiram.25; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_8:;
  /* 0008: entry a1, 32 */
  a8 = (uint32_t)&pm_beacon_miss_exceeded_wakeup_disabled; /* 000b: l32r a8, 4 <pm_beacon_monitor_tbtt_allowed-0x4> (0 <pm_beacon_monitor_tbtt_allowed-0x8>) */ /* literal: GOT slot for pm_beacon_miss_exceeded_wakeup_disabled */
  pm_beacon_miss_exceeded_wakeup_disabled(a2, a3, a4, a5); /* call via literal slot */ /* 000e: callx8 a8 */
  a8 = a2 + ((0x100) << 8); /* 0011: addmi a8, a2, 0x100 */
  a3 = 0x1; /* 0014: movi.n a3, 1 */
  if (a10 == 0) goto L_25; /* 0016: beqz.n a10, 25 <pm_beacon_monitor_tbtt_allowed+0x1d> */
  a9 = MEM16(a2 + 386); /* 0018: l16si a9, a2, 0x182 */
  a9 = a9 + (-1); /* 001b: addi.n a9, a9, -1 */
  a10 = MEM8(a8 + 214); /* 001d: l8ui a10, a8, 214 */
  if (a10 < a9) goto L_25; /* 0020: blt a10, a9, 25 <pm_beacon_monitor_tbtt_allowed+0x1d> */
  a3 = 0x0; /* 0023: movi.n a3, 0 */
L_25:;
  a9 = MEM8(a8 + 100); /* 0025: l8ui a9, a8, 100 */
  if (a9 != 0) goto L_31; /* 0028: bnez.n a9, 31 <pm_beacon_monitor_tbtt_allowed+0x29> */
L_2a:;
  a3 = 0x0; /* 002a: movi.n a3, 0 */
  goto L_58; /* 002c: j 58 <pm_beacon_monitor_tbtt_allowed+0x50> */
  /* 002f: .byte 00 */
  /* 0030: .byte 00 */
L_31:;
  a9 = MEM8(a8 + 212); /* 0031: l8ui a9, a8, 212 */
  if (a9 != 0) goto L_2a; /* 0034: bnez a9, 2a <pm_beacon_monitor_tbtt_allowed+0x22> */
  a2 = MEM8(a2 + 13); /* 0037: l8ui a2, a2, 13 */
  if (a2 == 0) goto L_2a; /* 003a: beqz a2, 2a <pm_beacon_monitor_tbtt_allowed+0x22> */
  a2 = MEM8(a8 + 214); /* 003d: l8ui a2, a8, 214 */
  a8 = MEM8(a8 + 215); /* 0040: l8ui a8, a8, 215 */
  a8 = a8 + (-1); /* 0043: addi.n a8, a8, -1 */
  if (a2 == a8) goto L_2a; /* 0045: beq a2, a8, 2a <pm_beacon_monitor_tbtt_allowed+0x22> */
  a2 = (uint32_t)&ptr_beacon_offset_funcs; /* 0048: l32r a2, 0 <pm_beacon_monitor_tbtt_allowed-0x8> (0 <pm_beacon_monitor_tbtt_allowed-0x8>) */ /* literal @0x0: ptr_beacon_offset_funcs */
  a2 = MEM32(a2 + 0); /* 004b: l32i.n a2, a2, 0 */
  a10 = MEM32(a2 + 12); /* 004d: l32i.n a10, a2, 12 */
  if (a10 == 0) goto L_58; /* 004f: beqz a10, 58 <pm_beacon_monitor_tbtt_allowed+0x50> */
  ((int32_t(*)())a10)(a2, a3, a4, a5); /* 0052: callx8 a10 */ /* indirect */
  if (a10 != 0) goto L_2a; /* 0055: bnez a10, 2a <pm_beacon_monitor_tbtt_allowed+0x22> */
L_58:;
  a2 = (a3 >> 0) & 0x1; /* 0058: extui a2, a3, 0, 1 */
  return (int32_t)a2; /* 005b: retw.n  */
}

/* pm_beacon_monitor_tbtt_start @ pm.o 00000014 size 246B bind GLOBAL
 * Calls: __udivdi3[got] | Data refs: ptr_beacon_offset_funcs, g_osi_funcs_p, __udivdi3, g_pm
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 1 call(s), 4 data ref(s)
 * Fidelity: medium - 91 instr, 17 branches, 4 indirect; flow + direct calls mapped, GOT-indirects enumerated */
int32_t pm_beacon_monitor_tbtt_start(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .wifislprxiram.26; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_14:;
  /* 0014: entry a1, 48 */
  a3 = (uint32_t)&ptr_beacon_offset_funcs; /* 0017: l32r a3, 0 <pm_beacon_monitor_tbtt_start-0x14> (0 <pm_beacon_monitor_tbtt_start-0x14>) */ /* literal @0x0: ptr_beacon_offset_funcs */
  a3 = MEM32(a3 + 0); /* 001a: l32i.n a3, a3, 0 */
  a10 = MEM32(a3 + 16); /* 001c: l32i.n a10, a3, 16 */
  if (a10 != 0) goto L_32; /* 001e: bnez.n a10, 32 <pm_beacon_monitor_tbtt_start+0x1e> */
L_20:;
  a3 = a2 + ((0x100) << 8); /* 0020: addmi a3, a2, 0x100 */
  a5 = MEM8(a3 + 126); /* 0023: l8ui a5, a3, 126 */
  a5 = a5 << (5 & 31); /* 0026: slli a5, a5, 5 */
  a3 = MEM16(a2 + 384); /* 0029: l16si a3, a2, 0x180 */
  a5 = (uint32_t)((uint64_t)a5 * a3); /* 002c: mull a5, a5, a3 */
  goto L_3a; /* 002f: j 3a <pm_beacon_monitor_tbtt_start+0x26> */
L_32:;
  ((int32_t(*)())a10)(a2, a3, a4, a5); /* 0032: callx8 a10 */ /* indirect */
  if (a10 == 0) goto L_20; /* 0035: beqz a10, 20 <pm_beacon_monitor_tbtt_start+0xc> */
  a5 = 0x0; /* 0038: movi.n a5, 0 */
L_3a:;
  a6 = (uint32_t)&g_osi_funcs_p; /* 003a: l32r a6, 4 <pm_beacon_monitor_tbtt_start-0x10> (0 <pm_beacon_monitor_tbtt_start-0x14>) */ /* literal @0x4: g_osi_funcs_p */
  a3 = MEM32(a6 + 0); /* 003d: l32i a3, a6, 0 */
  a10 = MEM32(a3 + 272); /* 0040: l32i a10, a3, 0x110 */
  ((int32_t(*)())a10)(a2, a3, a4, a5); /* 0043: callx8 a10 */ /* indirect */
  a8 = a10; /* 0046: mov.n a8, a10 */
  a7 = a11; /* 0048: mov.n a7, a11 */
  a4 = MEM32(a2 + 92); /* 004a: l32i a4, a2, 92 */
  a3 = MEM32(a2 + 88); /* 004d: l32i a3, a2, 88 */
  if (a11 < a4) goto L_59; /* 0050: bltu a11, a4, 59 <pm_beacon_monitor_tbtt_start+0x45> */
  if (a4 != a11) goto L_a0; /* 0053: bne a4, a11, a0 <pm_beacon_monitor_tbtt_start+0x8c> */
  if (a10 >= a3) goto L_a0; /* 0056: bgeu a10, a3, a0 <pm_beacon_monitor_tbtt_start+0x8c> */
L_59:;
  a10 = a3 - a10; /* 0059: sub a10, a3, a10 */
  a9 = MEM32(a2 + 44); /* 005c: l32i.n a9, a2, 44 */
  a14 = 0x1; /* 005e: movi.n a14, 1 */
  if (a3 < a10) goto L_65; /* 0060: bltu a3, a10, 65 <pm_beacon_monitor_tbtt_start+0x51> */
  a14 = 0x0; /* 0063: movi.n a14, 0 */
L_65:;
  a11 = a4 - a11; /* 0065: sub a11, a4, a11 */
  a12 = a9; /* 0068: mov.n a12, a9 */
  a13 = 0x0; /* 006a: movi.n a13, 0 */
  a11 = a11 - a14; /* 006c: sub a11, a11, a14 */
  MEM32(a1 + 4) = a8; /* 006f: s32i a8, a1, 4 */
  MEM32(a1 + 0) = a9; /* 0072: s32i.n a9, a1, 0 */
  MEMW(); /* 0074: memw  */
  a8 = (uint32_t)&udivdi3; /* 0077: l32r a8, 10 <pm_beacon_monitor_tbtt_start-0x4> (0 <pm_beacon_monitor_tbtt_start-0x14>) */ /* literal: GOT slot for __udivdi3 */
  udivdi3(a2, a3, a4, a5); /* call via literal slot */ /* 007a: callx8 a8 */
  a9 = MEM32(a1 + 0); /* 007d: l32i.n a9, a1, 0 */
  a12 = (uint32_t)((uint64_t)a10 * a9); /* 007f: mull a12, a10, a9 */
  a11 = (uint32_t)((uint64_t)a11 * a9); /* 0082: mull a11, a11, a9 */
  a10 = (uint32_t)(((uint64_t)a10 * a9) >> 32) /* muluh: high word */; /* 0085: muluh a10, a10, a9 */
  a9 = a3 - a12; /* 0088: sub a9, a3, a12 */
  a10 = a11 + a10; /* 008b: add.n a10, a11, a10 */
  a8 = MEM32(a1 + 4); /* 008d: l32i.n a8, a1, 4 */
  a11 = 0x1; /* 008f: movi a11, 1 */
  if (a3 < a9) goto L_98; /* 0092: bltu a3, a9, 98 <pm_beacon_monitor_tbtt_start+0x84> */
  a11 = 0x0; /* 0095: movi a11, 0 */
L_98:;
  a10 = a4 - a10; /* 0098: sub a10, a4, a10 */
  a3 = a9; /* 009b: mov.n a3, a9 */
  a4 = a10 - a11; /* 009d: sub a4, a10, a11 */
L_a0:;
  a13 = 0x1387; /* 00a0: l32r a13, 8 <pm_beacon_monitor_tbtt_start-0xc> (1387 <pm_attach+0x1303>) */ @0x8
  a10 = 0x1; /* 00a3: movi.n a10, 1 */
  a11 = 0x0; /* 00a5: movi.n a11, 0 */
  goto L_bb; /* 00a7: j bb <pm_beacon_monitor_tbtt_start+0xa7> */
L_aa:;
  a9 = MEM32(a2 + 44); /* 00aa: l32i.n a9, a2, 44 */
  a12 = 0x1; /* 00ac: mov.n a12, a10 */
  a9 = a3 + a9; /* 00ae: add.n a9, a3, a9 */
  if (a9 < a3) goto L_b6; /* 00b0: bltu a9, a3, b6 <pm_beacon_monitor_tbtt_start+0xa2> */
  a12 = 0x0; /* 00b3: or a12, a11, a11 */
L_b6:;
  a3 = a9; /* 00b6: mov.n a3, a9 */
  a4 = a12 + a4; /* 00b8: add a4, a12, a4 */
L_bb:;
  if (a7 < a4) goto L_c4; /* 00bb: bltu a7, a4, c4 <pm_beacon_monitor_tbtt_start+0xb0> */
  if (a4 != a7) goto L_aa; /* 00be: bne a4, a7, aa <pm_beacon_monitor_tbtt_start+0x96> */
  if (a8 >= a3) goto L_aa; /* 00c1: bgeu a8, a3, aa <pm_beacon_monitor_tbtt_start+0x96> */
L_c4:;
  a9 = a3 - a8; /* 00c4: sub a9, a3, a8 */
  a12 = 0x1; /* 00c7: or a12, a10, a10 */
  if (a3 < a9) goto L_d0; /* 00ca: bltu a3, a9, d0 <pm_beacon_monitor_tbtt_start+0xbc> */
  a12 = 0x0; /* 00cd: or a12, a11, a11 */
L_d0:;
  a14 = a4 - a7; /* 00d0: sub a14, a4, a7 */
  if (a14 != a12) goto L_d9; /* 00d3: bne a14, a12, d9 <pm_beacon_monitor_tbtt_start+0xc5> */
  if (a13 >= a9) goto L_aa; /* 00d6: bgeu a13, a9, aa <pm_beacon_monitor_tbtt_start+0x96> */
L_d9:;
  a4 = MEM16(a2 + 386); /* 00d9: l16si a4, a2, 0x182 */
  a3 = a3 - a5; /* 00dc: sub a3, a3, a5 */
  a4 = a4 + (-1); /* 00df: addi.n a4, a4, -1 */
  a5 = MEM16(a2 + 384); /* 00e1: l16si a5, a2, 0x180 */
  if (a5 != a4) goto L_f0; /* 00e4: bne a5, a4, f0 <pm_beacon_monitor_tbtt_start+0xdc> */
  a4 = (uint32_t)&g_pm; /* 00e7: l32r a4, c <pm_beacon_monitor_tbtt_start-0x8> (0 <pm_beacon_monitor_tbtt_start-0x14>) */ /* literal @0xC: g_pm */
  a4 = MEM32(a4 + 460); /* 00ea: l32i a4, a4, 0x1cc */
  a3 = a3 - a4; /* 00ed: sub a3, a3, a4 */
L_f0:;
  a4 = MEM32(a6 + 0); /* 00f0: l32i.n a4, a6, 0 */
  a10 = MEM32(a4 + 272); /* 00f2: l32i a10, a4, 0x110 */
  a2 = MEM32(a2 + 388); /* 00f5: l32i a2, a2, 0x184 */
  a5 = MEM32(a4 + 248); /* 00f8: l32i a5, a4, 248 */
  ((int32_t(*)())a10)(a2, a3, a4, a5); /* 00fb: callx8 a10 */ /* indirect */
  a11 = a3 - a10; /* 00fe: sub a11, a3, a10 */
  a12 = 0x0; /* 0101: movi.n a12, 0 */
  a10 = a2; /* 0103: mov.n a10, a2 */
  ((int32_t(*)())a5)(a2, a3, a4, a5); /* 0105: callx8 a5 */ /* indirect */
  return (int32_t)a2; /* 0108: retw.n  */
}

/* pm_beacon_monitor_tbtt_stop @ pm.o 00000004 size 19B bind GLOBAL
 * Calls: g_osi_funcs_p[got] | Data refs: g_osi_funcs_p
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 1 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t pm_beacon_monitor_tbtt_stop(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .wifislprxiram.27; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a8 = (uint32_t)&g_osi_funcs_p; /* 0007: l32r a8, 0 <pm_beacon_monitor_tbtt_stop-0x4> (0 <pm_beacon_monitor_tbtt_stop-0x4>) */ /* literal @0x0: g_osi_funcs_p */
  a8 = MEM32(a8 + 0); /* 000a: l32i.n a8, a8, 0 */
  a10 = MEM32(a2 + 388); /* 000c: l32i a10, a2, 0x184 */
  a8 = MEM32(a8 + 236); /* 000f: l32i a8, a8, 236 */
  g_osi_funcs_p(a2, a3, a4, a5); /* call via literal slot */ /* 0012: callx8 a8 */
  return (int32_t)a2; /* 0015: retw.n  */
}

/* pm_disable_beacon_monitor_timer @ pm.o 00000008 size 59B bind GLOBAL
 * Calls: g_osi_funcs_p[got], pm_beacon_monitor_tbtt_stop[got] | Data refs: g_osi_funcs_p, pm_beacon_monitor_tbtt_stop
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 2 call(s), 2 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t pm_disable_beacon_monitor_timer(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .wifislprxiram.29; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_8:;
  /* 0008: entry a1, 32 */
  a3 = a2 + ((0x100) << 8); /* 000b: addmi a3, a2, 0x100 */
  a4 = MEM8(a3 + 100); /* 000e: l8ui a4, a3, 100 */
  if (a4 == 0) goto L_3e; /* 0011: beqz.n a4, 3e <pm_disable_beacon_monitor_timer+0x36> */
  a4 = MEM8(a3 + 212); /* 0013: l8ui a4, a3, 212 */
  if (a4 != 0) goto L_3e; /* 0016: bnez.n a4, 3e <pm_disable_beacon_monitor_timer+0x36> */
  a8 = MEM8(a2 + 13); /* 0018: l8ui a8, a2, 13 */
  if (a8 == 0) goto L_3e; /* 001b: beqz.n a8, 3e <pm_disable_beacon_monitor_timer+0x36> */
  a10 = 0x168; /* 001d: movi a10, 0x168 */
  a10 = a2 + a10; /* 0020: add.n a10, a2, a10 */
  a8 = (uint32_t)&g_osi_funcs_p; /* 0022: l32r a8, 0 <pm_disable_beacon_monitor_timer-0x8> (0 <pm_disable_beacon_monitor_timer-0x8>) */ /* literal @0x0: g_osi_funcs_p */
  a8 = MEM32(a8 + 0); /* 0025: l32i.n a8, a8, 0 */
  a8 = MEM32(a8 + 236); /* 0027: l32i a8, a8, 236 */
  g_osi_funcs_p(a2, a3, a4, a5); /* call via literal slot */ /* 002a: callx8 a8 */
  a10 = a2; /* 002d: mov.n a10, a2 */
  a8 = (uint32_t)&pm_beacon_monitor_tbtt_stop; /* 002f: l32r a8, 4 <pm_disable_beacon_monitor_timer-0x4> (0 <pm_disable_beacon_monitor_timer-0x8>) */ /* literal: GOT slot for pm_beacon_monitor_tbtt_stop */
  pm_beacon_monitor_tbtt_stop(a2, a3, a4, a5); /* call via literal slot */ /* 0032: callx8 a8 */
  MEM16(a2 + 384) = a4; /* 0035: s16i a4, a2, 0x180 */
  MEM8(a3 + 125) = a4; /* 0038: s8i a4, a3, 125 */
  MEMW(); /* 003b: memw  */
L_3e:;
  MEMW(); /* 003e: memw  */
  return (int32_t)a2; /* 0041: retw.n  */
}

/* pm_beacon_monitor_init @ pm.o 00000014 size 86B bind GLOBAL
 * Calls: g_osi_funcs_p[got] | Data refs: .bss.beacon_monitor_data$0, g_osi_funcs_p, g_pm, g_pm_cfg, .text.pm_beacon_monitor_tbtt_timeout
 *   MMIO: none
 *   funcdb v3: 0 call(s), 4 ref(s); disasm: 1 call(s), 5 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t pm_beacon_monitor_init(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pm_beacon_monitor_init; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_14:;
  /* 0014: entry a1, 32 */
  a9 = (uint32_t)&g_pm_cfg; /* 0017: l32r a9, 0 <pm_beacon_monitor_init-0x14> (0 <pm_beacon_monitor_init-0x14>) */ /* literal @0x0: g_pm_cfg */
  a12 = (uint32_t)&g_pm; /* 001a: l32r a12, 4 <pm_beacon_monitor_init-0x10> (0 <pm_beacon_monitor_init-0x14>) */ /* literal @0x4: g_pm */
  a8 = a12 + ((0x100) << 8); /* 001d: addmi a8, a12, 0x100 */
  a10 = MEM8(a9 + 36); /* 0020: l8ui a10, a9, 36 */
  MEM8(a8 + 100) = a10; /* 0023: s8i a10, a8, 100 */
  MEMW(); /* 0026: memw  */
  if (a10 == 0) goto L_51; /* 0029: beqz.n a10, 51 <pm_beacon_monitor_init+0x3d> */
  a10 = MEM8(a9 + 37); /* 002b: l8ui a10, a9, 37 */
  MEM8(a8 + 124) = a10; /* 002e: s8i a10, a8, 124 */
  a10 = 0x0; /* 0031: movi.n a10, 0 */
  MEM8(a8 + 125) = a10; /* 0033: s8i a10, a8, 125 */
  MEMW(); /* 0036: memw  */
  a10 = MEM8(a9 + 38); /* 0039: l8ui a10, a9, 38 */
  MEM16(a12 + 386) = a10; /* 003c: s16i a10, a12, 0x182 */
  MEMW(); /* 003f: memw  */
  a10 = MEM8(a9 + 39); /* 0042: l8ui a10, a9, 39 */
  a9 = MEM8(a9 + 40); /* 0045: l8ui a9, a9, 40 */
  MEM8(a8 + 126) = a10; /* 0048: s8i a10, a8, 126 */
  MEM8(a8 + 127) = a9; /* 004b: s8i a9, a8, 127 */
  MEMW(); /* 004e: memw  */
L_51:;
  a8 = (uint32_t)&g_osi_funcs_p; /* 0051: l32r a8, 10 <pm_beacon_monitor_init-0x4> (0 <pm_beacon_monitor_init-0x14>) */ /* literal @0x10: g_osi_funcs_p */
  a8 = MEM32(a8 + 0); /* 0054: l32i.n a8, a8, 0 */
  a10 = (uint32_t)&bss_beacon_monitor_data_0; /* 0056: l32r a10, 8 <pm_beacon_monitor_init-0xc> (0 <pm_beacon_monitor_init-0x14>) */ /* literal @0x8: .bss.beacon_monitor_data$0 */
  a8 = MEM32(a8 + 244); /* 0059: l32i a8, a8, 244 */
  a11 = (uint32_t)&pm_beacon_monitor_tbtt_timeout; /* 005c: l32r a11, c <pm_beacon_monitor_init-0x8> (4 <pm_beacon_monitor_init-0x10>) */ /* literal @0xC: .text.pm_beacon_monitor_tbtt_timeout */
  MEM32(a12 + 388) = a10; /* 005f: s32i a10, a12, 0x184 */
  MEMW(); /* 0062: memw  */
  g_osi_funcs_p(a2, a3, a4, a5); /* call via literal slot */ /* 0065: callx8 a8 */
  return (int32_t)a2; /* 0068: retw.n  */
}

/* pm_dream @ pm.o 0000002c size 314B bind GLOBAL
 * Calls: wifi_rf_phy_enable[got], esp_wifi_get_mode[got], wifi_rf_phy_enable[got], g_pm_cnt[got], g_pm[got], .text.pm_set_state[got] | Data refs: g_pm, wifi_rf_phy_enable, g_mesh_is_started, g_mesh_is_root, g_mesh_init_ps_type, esp_wifi_get_mode, g_osi_funcs_p, g_pm_cnt, .text.pm_set_state
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 6 call(s), 9 data ref(s)
 * Fidelity: low - 120 instr, 17 branches, 3 indirect; call-sequence + MMIO skeleton */
int32_t pm_dream(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .wifislprxiram.30; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_2c:;
  /* 002c: entry a1, 48 */
  a2 = (uint32_t)&g_pm; /* 002f: l32r a2, 0 <pm_dream-0x2c> (0 <pm_dream-0x2c>) */ /* literal @0x0: g_pm */
  a3 = MEM8(a2 + 1); /* 0032: l8ui a3, a2, 1 */
  if (a3 == 2) goto L_3b; /* 0035: beqi a3, 2, 3b <pm_dream+0xf> */
  goto L_f9; /* 0038: j f9 <pm_dream+0xcd> */
L_3b:;
  a10 = 0x0; /* 003b: movi a10, 0 */
  a8 = (uint32_t)&wifi_rf_phy_enable; /* 003e: l32r a8, 1c <pm_dream-0x10> (0 <pm_dream-0x2c>) */ /* literal: GOT slot for wifi_rf_phy_enable */
  wifi_rf_phy_enable(a2, a3, a4, a5); /* call via literal slot */ /* 0041: callx8 a8 */
  a3 = (uint32_t)&g_mesh_is_started; /* 0044: l32r a3, 4 <pm_dream-0x28> (0 <pm_dream-0x2c>) */ /* literal @0x4: g_mesh_is_started */
  a3 = MEM8(a3 + 0); /* 0047: l8ui a3, a3, 0 */
  if (a3 == 0) goto L_7d; /* 004a: beqz.n a3, 7d <pm_dream+0x51> */
  a3 = (uint32_t)&g_mesh_is_root; /* 004c: l32r a3, 8 <pm_dream-0x24> (0 <pm_dream-0x2c>) */ /* literal @0x8: g_mesh_is_root */
  MEMW(); /* 004f: memw  */
  a3 = MEM8(a3 + 0); /* 0052: l8ui a3, a3, 0 */
  a3 = (a3 >> 0) & 0xFF; /* 0055: extui a3, a3, 0, 8 */
  if (a3 != 0) goto L_7d; /* 0058: bnez.n a3, 7d <pm_dream+0x51> */
  a4 = (uint32_t)&g_mesh_init_ps_type; /* 005a: l32r a4, c <pm_dream-0x20> (0 <pm_dream-0x2c>) */ /* literal @0xC: g_mesh_init_ps_type */
  a4 = MEM32(a4 + 0); /* 005d: l32i.n a4, a4, 0 */
  if (a4 == 0) goto L_7d; /* 005f: beqz.n a4, 7d <pm_dream+0x51> */
  a10 = a1; /* 0061: mov.n a10, a1 */
  MEM32(a1 + 0) = a3; /* 0063: s32i.n a3, a1, 0 */
  MEMW(); /* 0065: memw  */
  a8 = (uint32_t)&esp_wifi_get_mode; /* 0068: l32r a8, 20 <pm_dream-0xc> (0 <pm_dream-0x2c>) */ /* literal: GOT slot for esp_wifi_get_mode */
  esp_wifi_get_mode(a2, a3, a4, a5); /* call via literal slot */ /* 006b: callx8 a8 */
  if (a10 != 0) goto L_7d; /* 006e: bnez.n a10, 7d <pm_dream+0x51> */
  a3 = MEM32(a1 + 0); /* 0070: l32i.n a3, a1, 0 */
  if (a3 != 3) goto L_7d; /* 0072: bnei a3, 3, 7d <pm_dream+0x51> */
  a10 = 0x1; /* 0075: movi.n a10, 1 */
  a8 = (uint32_t)&wifi_rf_phy_enable; /* 0077: l32r a8, 24 <pm_dream-0x8> (0 <pm_dream-0x2c>) */ /* literal: GOT slot for wifi_rf_phy_enable */
  wifi_rf_phy_enable(a2, a3, a4, a5); /* call via literal slot */ /* 007a: callx8 a8 */
L_7d:;
  a3 = (uint32_t)&g_osi_funcs_p; /* 007d: l32r a3, 10 <pm_dream-0x1c> (0 <pm_dream-0x2c>) */ /* literal @0x10: g_osi_funcs_p */
  a3 = MEM32(a3 + 0); /* 0080: l32i.n a3, a3, 0 */
  a10 = MEM32(a3 + 272); /* 0082: l32i a10, a3, 0x110 */
  ((int32_t(*)())a10)(a2, a3, a4, a5); /* 0085: callx8 a10 */ /* indirect */
  a5 = a10; /* 0088: mov.n a5, a10 */
  a8 = (uint32_t)&g_pm_cnt; /* 008a: l32r a8, 14 <pm_dream-0x18> (0 <pm_dream-0x2c>) */ /* literal @0x14: g_pm_cnt */
  a3 = MEM32(a8 + 44); /* 008d: l32i.n a3, a8, 44 */
  a3 = a3 + (1); /* 008f: addi.n a3, a3, 1 */
  MEM32(a8 + 44) = a3; /* 0091: s32i.n a3, a8, 44 */
  a3 = MEM32(a2 + 112); /* 0093: l32i a3, a2, 112 */
  MEM32(a2 + 120) = a10; /* 0096: s32i a10, a2, 120 */
  a10 = a10 - a3; /* 0099: sub a10, a10, a3 */
  a3 = 0x1; /* 009c: movi.n a3, 1 */
  MEM32(a2 + 124) = a11; /* 009e: s32i a11, a2, 124 */
  a4 = MEM32(a2 + 116); /* 00a1: l32i a4, a2, 116 */
  if (a5 < a10) goto L_a9; /* 00a4: bltu a5, a10, a9 <pm_dream+0x7d> */
  a3 = 0x0; /* 00a7: movi.n a3, 0 */
L_a9:;
  a9 = a11 - a4; /* 00a9: sub a9, a11, a4 */
  a9 = a9 - a3; /* 00ac: sub a9, a9, a3 */
  a5 = MEM32(a8 + 48); /* 00af: l32i.n a5, a8, 48 */
  a3 = 0x1; /* 00b1: movi.n a3, 1 */
  a4 = a5 + a10; /* 00b3: add.n a4, a5, a10 */
  a11 = MEM32(a8 + 52); /* 00b5: l32i.n a11, a8, 52 */
  if (a4 < a5) goto L_bd; /* 00b7: bltu a4, a5, bd <pm_dream+0x91> */
  a3 = 0x0; /* 00ba: movi a3, 0 */
L_bd:;
  a11 = a11 + a9; /* 00bd: add.n a11, a11, a9 */
  a3 = a3 + a11; /* 00bf: add.n a3, a3, a11 */
  a5 = MEM32(a8 + 64); /* 00c1: l32i a5, a8, 64 */
  MEM32(a8 + 48) = a4; /* 00c4: s32i.n a4, a8, 48 */
  a4 = a5 + a10; /* 00c6: add.n a4, a5, a10 */
  MEM32(a8 + 52) = a3; /* 00c8: s32i.n a3, a8, 52 */
  a3 = 0x1; /* 00ca: movi.n a3, 1 */
  a11 = MEM32(a8 + 68); /* 00cc: l32i a11, a8, 68 */
  if (a4 < a5) goto L_d4; /* 00cf: bltu a4, a5, d4 <pm_dream+0xa8> */
  a3 = 0x0; /* 00d2: movi.n a3, 0 */
L_d4:;
  a11 = a11 + a9; /* 00d4: add.n a11, a11, a9 */
  a3 = a3 + a11; /* 00d6: add.n a3, a3, a11 */
  MEM32(a8 + 64) = a4; /* 00d8: s32i a4, a8, 64 */
  a4 = MEM32(a2 + 136); /* 00db: l32i a4, a2, 136 */
  a10 = a4 + a10; /* 00de: add.n a10, a4, a10 */
  MEM32(a8 + 68) = a3; /* 00e0: s32i a3, a8, 68 */
  a3 = 0x1; /* 00e3: movi.n a3, 1 */
  a8 = MEM32(a2 + 140); /* 00e5: l32i a8, a2, 140 */
  if (a10 < a4) goto L_ee; /* 00e8: bltu a10, a4, ee <pm_dream+0xc2> */
  a3 = 0x0; /* 00eb: movi a3, 0 */
L_ee:;
  a8 = a8 + a9; /* 00ee: add.n a8, a8, a9 */
  a3 = a3 + a8; /* 00f0: add a3, a3, a8 */
  MEM32(a2 + 136) = a10; /* 00f3: s32i a10, a2, 136 */
  MEM32(a2 + 140) = a3; /* 00f6: s32i a3, a2, 140 */
L_f9:;
  a3 = a2 + ((0x100) << 8); /* 00f9: addmi a3, a2, 0x100 */
  a3 = MEM8(a3 + 213); /* 00fc: l8ui a3, a3, 213 */
  if (a3 == 0) goto L_159; /* 00ff: beqz a3, 159 <pm_dream+0x12d> */
  a3 = (uint32_t)&g_osi_funcs_p; /* 0102: l32r a3, 10 <pm_dream-0x1c> (0 <pm_dream-0x2c>) */ /* literal @0x10: g_osi_funcs_p */
  a4 = MEM32(a3 + 0); /* 0105: l32i a4, a3, 0 */
  a10 = MEM32(a4 + 404); /* 0108: l32i a10, a4, 0x194 */
  MEMW(); /* 010b: memw  */
  ((int32_t(*)())a10)(a2, a3, a4, a5); /* 010e: callx8 a10 */ /* indirect */
  if (a10 == 0) goto L_159; /* 0111: beqz a10, 159 <pm_dream+0x12d> */
  a4 = MEM32(a3 + 0); /* 0114: l32i.n a4, a3, 0 */
  a10 = MEM32(a4 + 272); /* 0116: l32i a10, a4, 0x110 */
  ((int32_t(*)())a10)(a2, a3, a4, a5); /* 0119: callx8 a10 */ /* indirect */
  a5 = a10; /* 011c: mov.n a5, a10 */
  a4 = MEM32(a2 + 108); /* 011e: l32i a4, a2, 108 */
  if (a11 < a4) goto L_12d; /* 0121: bltu a11, a4, 12d <pm_dream+0x101> */
  if (a4 != a11) goto L_151; /* 0124: bne a4, a11, 151 <pm_dream+0x125> */
  a4 = MEM32(a2 + 104); /* 0127: l32i a4, a2, 104 */
  if (a10 >= a4) goto L_151; /* 012a: bgeu a10, a4, 151 <pm_dream+0x125> */
L_12d:;
  a8 = MEM32(a3 + 0); /* 012d: l32i.n a8, a3, 0 */
  a4 = (uint32_t)&g_pm; /* 012f: l32r a4, 18 <pm_dream-0x14> (0 <pm_dream-0x2c>) */ /* literal @0x18: g_pm */
  a10 = a4; /* 0132: mov.n a10, a4 */
  a8 = MEM32(a8 + 236); /* 0134: l32i a8, a8, 236 */
  ((int32_t(*)())a8)(a2, a3, a4, a5); /* 0137: callx8 a8 */ /* indirect */
  a12 = 0x0; /* 013a: movi.n a12, 0 */
  a10 = a4; /* 013c: mov.n a10, a4 */
  a11 = MEM32(a2 + 104); /* 013e: l32i a11, a2, 104 */
  a11 = a11 - a5; /* 0141: sub a11, a11, a5 */
  a2 = MEM32(a3 + 0); /* 0144: l32i.n a2, a3, 0 */
  a2 = MEM32(a2 + 248); /* 0146: l32i a2, a2, 248 */
  g_pm(a2, a3, a4, a5); /* call via literal slot */ /* 0149: callx8 a2 */
  goto L_159; /* 014c: j 159 <pm_dream+0x12d> */
  /* 014f: .byte 00 */
  /* 0150: .byte 00 */
L_151:;
  a3 = 0x0; /* 0151: movi.n a3, 0 */
  MEM8(a2 + 24) = a3; /* 0153: s8i a3, a2, 24 */
  MEMW(); /* 0156: memw  */
L_159:;
  a10 = 0x1; /* 0159: movi.n a10, 1 */
  MEMW(); /* 015b: memw  */
  a8 = (uint32_t)&pm_set_state; /* 015e: l32r a8, 28 <pm_dream-0x4> (c <pm_dream-0x20>) */ /* literal: GOT slot for .text.pm_set_state */
  pm_set_state(a2, a3, a4, a5); /* call via literal slot */ /* 0161: callx8 a8 */
  return (int32_t)a2; /* 0164: retw.n  */
}

/* pm_disconnected_wake @ pm.o 0000001c size 84B bind GLOBAL
 * Calls: wifi_gpio_debug, wifi_rf_phy_enable, .text.pm_set_state[got] | Data refs: g_mesh_is_started, g_pm, wifi_gpio_debug, wifi_rf_phy_enable, .text.pm_set_state
 *   MMIO: none
 *   funcdb v3: 2 call(s), 4 ref(s); disasm: 5 call(s), 5 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t pm_disconnected_wake(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pm_disconnected_wake; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_1c:;
  /* 001c: entry a1, 32 */
  a3 = (uint32_t)&g_pm; /* 001f: l32r a3, 0 <pm_disconnected_wake-0x1c> (0 <pm_disconnected_wake-0x1c>) */ /* literal @0x0: g_pm */
  a3 = a3 + ((0x100) << 8); /* 0022: addmi a3, a3, 0x100 */
  a4 = MEM8(a3 + 29); /* 0025: l8ui a4, a3, 29 */
  if (a4 != 3) goto L_6e; /* 0028: bnei a4, 3, 6e <pm_disconnected_wake+0x52> */
  a2 = (uint32_t)&g_mesh_is_started; /* 002b: l32r a2, 4 <pm_disconnected_wake-0x18> (0 <pm_disconnected_wake-0x1c>) */ /* literal @0x4: g_mesh_is_started */
  a2 = MEM8(a2 + 0); /* 002e: l8ui a2, a2, 0 */
  if (a2 != 0) goto L_6e; /* 0031: bnez.n a2, 6e <pm_disconnected_wake+0x52> */
  a10 = a2 | a2; /* 0033: or a10, a2, a2 */
  a8 = (uint32_t)&wifi_rf_phy_enable; /* 0036: l32r a8, 8 <pm_disconnected_wake-0x14> (0 <pm_disconnected_wake-0x1c>) */ /* literal: GOT slot for wifi_rf_phy_enable */
  wifi_rf_phy_enable(a2, a3, a4, a5); /* call via literal slot */ /* 0039: callx8 a8 */
  a8 = 0x2; /* 003c: movi a8, 2 */
  a10 = a2; /* 003f: mov.n a10, a2 */
  MEM8(a3 + 29) = a8; /* 0041: s8i a8, a3, 29 */
  MEMW(); /* 0044: memw  */
  MEMW(); /* 0047: memw  */
  a8 = (uint32_t)&pm_set_state; /* 004a: l32r a8, c <pm_disconnected_wake-0x10> (c <pm_disconnected_wake-0x10>) */ /* literal: GOT slot for .text.pm_set_state */
  pm_set_state(a2, a3, a4, a5); /* call via literal slot */ /* 004d: callx8 a8 */
  a11 = 0x1; /* 0050: movi.n a11, 1 */
  a10 = a4; /* 0052: mov.n a10, a4 */
  a8 = (uint32_t)&wifi_gpio_debug; /* 0054: l32r a8, 10 <pm_disconnected_wake-0xc> (0 <pm_disconnected_wake-0x1c>) */ /* literal: GOT slot for wifi_gpio_debug */
  wifi_gpio_debug(a2, a3, a4, a5); /* call via literal slot */ /* 0057: callx8 a8 */
  a11 = 0x1; /* 005a: movi.n a11, 1 */
  a10 = 0x4; /* 005c: movi.n a10, 4 */
  a8 = (uint32_t)&wifi_gpio_debug; /* 005e: l32r a8, 14 <pm_disconnected_wake-0x8> (0 <pm_disconnected_wake-0x1c>) */ /* literal: GOT slot for wifi_gpio_debug */
  wifi_gpio_debug(a2, a3, a4, a5); /* call via literal slot */ /* 0061: callx8 a8 */
  a11 = a2; /* 0064: mov.n a11, a2 */
  a10 = 0x5; /* 0066: movi.n a10, 5 */
  a8 = (uint32_t)&wifi_gpio_debug; /* 0068: l32r a8, 18 <pm_disconnected_wake-0x4> (0 <pm_disconnected_wake-0x1c>) */ /* literal: GOT slot for wifi_gpio_debug */
  wifi_gpio_debug(a2, a3, a4, a5); /* call via literal slot */ /* 006b: callx8 a8 */
L_6e:;
  return (int32_t)a2; /* 006e: retw.n  */
}

/* pm_sleep @ pm.o 00000034 size 499B bind GLOBAL
 * Calls: ppCheckTxQIdle[got], ppCheckTxIdle[got], g_osi_funcs_p[got], wifi_rf_phy_disable[got], esp_wifi_get_mode[got], wifi_rf_phy_disable[got], .text.pm_set_state[got] | Data refs: g_mesh_is_started, g_pm, g_mesh_is_root, g_mesh_init_ps_type, ppCheckTxQIdle, g_osi_funcs_p, ppCheckTxIdle, wifi_rf_phy_disable, esp_wifi_get_mode, g_pm_cnt, .text.pm_set_state
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 7 call(s), 11 data ref(s)
 * Fidelity: low - 186 instr, 41 branches, 9 indirect; call-sequence + MMIO skeleton */
int32_t pm_sleep(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .wifislprxiram.31; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_34:;
  /* 0034: entry a1, 48 */
  a3 = (uint32_t)&g_mesh_is_started; /* 0037: l32r a3, 4 <pm_sleep-0x30> (0 <pm_sleep-0x34>) */ /* literal @0x4: g_mesh_is_started */
  a2 = (uint32_t)&g_pm; /* 003a: l32r a2, 0 <pm_sleep-0x34> (0 <pm_sleep-0x34>) */ /* literal @0x0: g_pm */
  a4 = MEM8(a3 + 0); /* 003d: l8ui a4, a3, 0 */
  a8 = MEM8(a2 + 16); /* 0040: l8ui a8, a2, 16 */
  if (a4 == 0) goto L_ad; /* 0043: beqz a4, ad <pm_sleep+0x79> */
  a4 = (uint32_t)&g_mesh_is_root; /* 0046: l32r a4, 8 <pm_sleep-0x2c> (0 <pm_sleep-0x34>) */ /* literal @0x8: g_mesh_is_root */
  MEMW(); /* 0049: memw  */
  a4 = MEM8(a4 + 0); /* 004c: l8ui a4, a4, 0 */
  a4 = (a4 >> 0) & 0xFF; /* 004f: extui a4, a4, 0, 8 */
  if (a4 != 0) goto L_ad; /* 0052: bnez a4, ad <pm_sleep+0x79> */
  a4 = (uint32_t)&g_mesh_init_ps_type; /* 0055: l32r a4, c <pm_sleep-0x28> (0 <pm_sleep-0x34>) */ /* literal @0xC: g_mesh_init_ps_type */
  a4 = MEM32(a4 + 0); /* 0058: l32i.n a4, a4, 0 */
  if (a4 == 0) goto L_ad; /* 005a: beqz a4, ad <pm_sleep+0x79> */
  if (a8 != 0) goto L_64; /* 005d: bnez.n a8, 64 <pm_sleep+0x30> */
  goto L_122; /* 005f: j 122 <pm_sleep+0xee> */
  /* 0062: .byte 00 */
  /* 0063: .byte 00 */
L_64:;
  a4 = MEM8(a2 + 18); /* 0064: l8ui a4, a2, 18 */
  if (a4 != 0) goto L_122; /* 0067: bnez a4, 122 <pm_sleep+0xee> */
  a4 = MEM8(a2 + 19); /* 006a: l8ui a4, a2, 19 */
  if (a4 != 0) goto L_122; /* 006d: bnez a4, 122 <pm_sleep+0xee> */
  a4 = MEM8(a2 + 20); /* 0070: l8ui a4, a2, 20 */
  if (a4 != 0) goto L_122; /* 0073: bnez a4, 122 <pm_sleep+0xee> */
  a4 = MEM8(a2 + 14); /* 0076: l8ui a4, a2, 14 */
  if (a4 == 0) goto L_122; /* 0079: beqz a4, 122 <pm_sleep+0xee> */
  a4 = MEM32(a2 + 288); /* 007c: l32i a4, a2, 0x120 */
  if (a4 != 0) goto L_122; /* 007f: bnez a4, 122 <pm_sleep+0xee> */
  a10 = 0x1; /* 0082: movi.n a10, 1 */
  a8 = (uint32_t)&ppCheckTxQIdle; /* 0084: l32r a8, 1c <pm_sleep-0x18> (0 <pm_sleep-0x34>) */ /* literal: GOT slot for ppCheckTxQIdle */
  ppCheckTxQIdle(a2, a3, a4, a5); /* call via literal slot */ /* 0087: callx8 a8 */
  a8 = 0x1; /* 008a: movi a8, 1 */
  if (a10 == 0) goto L_124; /* 008d: beqz a10, 124 <pm_sleep+0xf0> */
  a4 = (uint32_t)&g_osi_funcs_p; /* 0090: l32r a4, 10 <pm_sleep-0x24> (0 <pm_sleep-0x34>) */ /* literal @0x10: g_osi_funcs_p */
  a4 = MEM32(a4 + 0); /* 0093: l32i a4, a4, 0 */
  a10 = MEM32(a4 + 404); /* 0096: l32i a10, a4, 0x194 */
  ((int32_t(*)())a10)(a2, a3, a4, a5); /* 0099: callx8 a10 */ /* indirect */
  if (a10 == 0) goto L_122; /* 009c: beqz a10, 122 <pm_sleep+0xee> */
  a4 = 0x1; /* 009f: movi.n a4, 1 */
  a8 = MEM8(a2 + 24); /* 00a1: l8ui a8, a2, 24 */
  a8 = a8 ^ a4; /* 00a4: xor a8, a8, a4 */
  a8 = (a8 >> 0) & 0xFF; /* 00a7: extui a8, a8, 0, 8 */
  goto L_124; /* 00aa: j 124 <pm_sleep+0xf0> */
L_ad:;
  if (a8 != 0) goto L_b2; /* 00ad: bnez.n a8, b2 <pm_sleep+0x7e> */
  goto L_122; /* 00af: j 122 <pm_sleep+0xee> */
L_b2:;
  a4 = MEM8(a2 + 17); /* 00b2: l8ui a4, a2, 17 */
  if (a4 != 0) goto L_122; /* 00b5: bnez a4, 122 <pm_sleep+0xee> */
  a4 = MEM8(a2 + 18); /* 00b8: l8ui a4, a2, 18 */
  if (a4 != 0) goto L_122; /* 00bb: bnez a4, 122 <pm_sleep+0xee> */
  a4 = MEM8(a2 + 19); /* 00be: l8ui a4, a2, 19 */
  if (a4 != 0) goto L_122; /* 00c1: bnez a4, 122 <pm_sleep+0xee> */
  a4 = MEM8(a2 + 20); /* 00c4: l8ui a4, a2, 20 */
  if (a4 != 0) goto L_122; /* 00c7: bnez a4, 122 <pm_sleep+0xee> */
  a4 = MEM8(a2 + 14); /* 00ca: l8ui a4, a2, 14 */
  if (a4 == 0) goto L_122; /* 00cd: beqz a4, 122 <pm_sleep+0xee> */
  a4 = MEM8(a2 + 15); /* 00d0: l8ui a4, a2, 15 */
  if (a4 != 0) goto L_122; /* 00d3: bnez a4, 122 <pm_sleep+0xee> */
  a4 = MEM32(a2 + 288); /* 00d6: l32i a4, a2, 0x120 */
  if (a4 != 0) goto L_122; /* 00d9: bnez a4, 122 <pm_sleep+0xee> */
  a10 = 0x1; /* 00dc: movi.n a10, 1 */
  a8 = (uint32_t)&ppCheckTxIdle; /* 00de: l32r a8, 20 <pm_sleep-0x14> (0 <pm_sleep-0x34>) */ /* literal: GOT slot for ppCheckTxIdle */
  ppCheckTxIdle(a2, a3, a4, a5); /* call via literal slot */ /* 00e1: callx8 a8 */
  if (a10 != 0) goto L_ed; /* 00e4: bnez.n a10, ed <pm_sleep+0xb9> */
L_e6:;
  a8 = 0x1; /* 00e6: movi.n a8, 1 */
  goto L_124; /* 00e8: j 124 <pm_sleep+0xf0> */
  /* 00eb: .byte 00 */
  /* 00ec: .byte 00 */
L_ed:;
  a4 = (uint32_t)&g_osi_funcs_p; /* 00ed: l32r a4, 10 <pm_sleep-0x24> (0 <pm_sleep-0x34>) */ /* literal @0x10: g_osi_funcs_p */
  a8 = MEM32(a4 + 0); /* 00f0: l32i a8, a4, 0 */
  a10 = MEM32(a8 + 404); /* 00f3: l32i a10, a8, 0x194 */
  ((int32_t(*)())a10)(a2, a3, a4, a5); /* 00f6: callx8 a10 */ /* indirect */
  if (a10 == 0) goto L_122; /* 00f9: beqz.n a10, 122 <pm_sleep+0xee> */
  a8 = MEM8(a2 + 24); /* 00fb: l8ui a8, a2, 24 */
  if (a8 == 0) goto L_e6; /* 00fe: beqz a8, e6 <pm_sleep+0xb2> */
  a8 = a2 + ((0x200) << 8); /* 0101: addmi a8, a2, 0x200 */
  a8 = MEM8(a8 + 31); /* 0104: l8ui a8, a8, 31 */
  if (a8 == 0) goto L_122; /* 0107: beqz.n a8, 122 <pm_sleep+0xee> */
  a4 = MEM32(a4 + 0); /* 0109: l32i.n a4, a4, 0 */
  a10 = MEM32(a4 + 272); /* 010b: l32i a10, a4, 0x110 */
  ((int32_t(*)())a10)(a2, a3, a4, a5); /* 010e: callx8 a10 */ /* indirect */
  a8 = 0x1; /* 0111: movi.n a8, 1 */
  a4 = MEM32(a2 + 572); /* 0113: l32i a4, a2, 0x23c */
  if (a11 < a4) goto L_122; /* 0116: bltu a11, a4, 122 <pm_sleep+0xee> */
  if (a4 != a11) goto L_124; /* 0119: bne a4, a11, 124 <pm_sleep+0xf0> */
  a4 = MEM32(a2 + 568); /* 011c: l32i a4, a2, 0x238 */
  if (a10 >= a4) goto L_124; /* 011f: bgeu a10, a4, 124 <pm_sleep+0xf0> */
L_122:;
  a8 = 0x0; /* 0122: movi.n a8, 0 */
L_124:;
  a8 = 0x0; /* 0124: extui a8, a8, 0, 1 */
  if (a8 == 0) goto L_225; /* 0127: beqz a8, 225 <pm_sleep+0x1f1> */
  a4 = (uint32_t)&g_osi_funcs_p; /* 012a: l32r a4, 10 <pm_sleep-0x24> (0 <pm_sleep-0x34>) */ /* literal @0x10: g_osi_funcs_p */
  a8 = MEM32(a4 + 0); /* 012d: l32i.n a8, a4, 0 */
  a10 = MEM32(a8 + 272); /* 012f: l32i a10, a8, 0x110 */
  ((int32_t(*)())a10)(a2, a3, a4, a5); /* 0132: callx8 a10 */ /* indirect */
  a8 = MEM32(a4 + 0); /* 0135: l32i a8, a4, 0 */
  a8 = MEM32(a8 + 416); /* 0138: l32i a8, a8, 0x1a0 */
  MEM32(a2 + 116) = a11; /* 013b: s32i a11, a2, 116 */
  MEM32(a2 + 112) = a10; /* 013e: s32i a10, a2, 112 */
  a10 = 0x1; /* 0141: movi a10, 1 */
  MEMW(); /* 0144: memw  */
  ((int32_t(*)())a8)(a2, a3, a4, a5); /* 0147: callx8 a8 */ /* indirect */
  a10 = 0x2; /* 014a: movi.n a10, 2 */
  a8 = MEM32(a4 + 0); /* 014c: l32i.n a8, a4, 0 */
  a8 = MEM32(a8 + 416); /* 014e: l32i a8, a8, 0x1a0 */
  ((int32_t(*)())a8)(a2, a3, a4, a5); /* 0151: callx8 a8 */ /* indirect */
  a10 = 0x26; /* 0154: movi.n a10, 38 */
  a8 = MEM32(a4 + 0); /* 0156: l32i.n a8, a4, 0 */
  a8 = MEM32(a8 + 416); /* 0158: l32i a8, a8, 0x1a0 */
  ((int32_t(*)())a8)(a2, a3, a4, a5); /* 015b: callx8 a8 */ /* indirect */
  a10 = 0x0; /* 015e: movi.n a10, 0 */
  a8 = MEM32(a4 + 0); /* 0160: l32i.n a8, a4, 0 */
  a8 = MEM32(a8 + 416); /* 0162: l32i a8, a8, 0x1a0 */
  ((int32_t(*)())a8)(a2, a3, a4, a5); /* 0165: callx8 a8 */ /* indirect */
  a8 = a2 + ((0x100) << 8); /* 0168: addmi a8, a2, 0x100 */
  a8 = MEM8(a8 + 213); /* 016b: l8ui a8, a8, 213 */
  if (a8 == 0) goto L_185; /* 016e: beqz.n a8, 185 <pm_sleep+0x151> */
  a8 = MEM32(a4 + 0); /* 0170: l32i.n a8, a4, 0 */
  a10 = MEM32(a8 + 404); /* 0172: l32i a10, a8, 0x194 */
  ((int32_t(*)())a10)(a2, a3, a4, a5); /* 0175: callx8 a10 */ /* indirect */
  if (a10 == 0) goto L_185; /* 0178: beqz.n a10, 185 <pm_sleep+0x151> */
  a4 = MEM32(a4 + 0); /* 017a: l32i.n a4, a4, 0 */
  a10 = (uint32_t)&g_pm; /* 017c: l32r a10, 14 <pm_sleep-0x20> (0 <pm_sleep-0x34>) */ /* literal @0x14: g_pm */
  a4 = MEM32(a4 + 236); /* 017f: l32i a4, a4, 236 */
  g_osi_funcs_p(a2, a3, a4, a5); /* call via literal slot */ /* 0182: callx8 a4 */
L_185:;
  a10 = 0x0; /* 0185: movi.n a10, 0 */
  a8 = (uint32_t)&wifi_rf_phy_disable; /* 0187: l32r a8, 24 <pm_sleep-0x10> (0 <pm_sleep-0x34>) */ /* literal: GOT slot for wifi_rf_phy_disable */
  wifi_rf_phy_disable(a2, a3, a4, a5); /* call via literal slot */ /* 018a: callx8 a8 */
  a3 = MEM8(a3 + 0); /* 018d: l8ui a3, a3, 0 */
  if (a3 == 0) goto L_1c5; /* 0190: beqz.n a3, 1c5 <pm_sleep+0x191> */
  a3 = (uint32_t)&g_mesh_is_root; /* 0192: l32r a3, 8 <pm_sleep-0x2c> (0 <pm_sleep-0x34>) */ /* literal @0x8: g_mesh_is_root */
  MEMW(); /* 0195: memw  */
  a3 = MEM8(a3 + 0); /* 0198: l8ui a3, a3, 0 */
  a3 = (a3 >> 0) & 0xFF; /* 019b: extui a3, a3, 0, 8 */
  if (a3 != 0) goto L_1c5; /* 019e: bnez.n a3, 1c5 <pm_sleep+0x191> */
  a4 = (uint32_t)&g_mesh_init_ps_type; /* 01a0: l32r a4, c <pm_sleep-0x28> (0 <pm_sleep-0x34>) */ /* literal @0xC: g_mesh_init_ps_type */
  a4 = MEM32(a4 + 0); /* 01a3: l32i.n a4, a4, 0 */
  if (a4 == 0) goto L_1c5; /* 01a5: beqz.n a4, 1c5 <pm_sleep+0x191> */
  a10 = a1; /* 01a7: mov.n a10, a1 */
  MEM32(a1 + 0) = a3; /* 01a9: s32i a3, a1, 0 */
  MEMW(); /* 01ac: memw  */
  a8 = (uint32_t)&esp_wifi_get_mode; /* 01af: l32r a8, 28 <pm_sleep-0xc> (0 <pm_sleep-0x34>) */ /* literal: GOT slot for esp_wifi_get_mode */
  esp_wifi_get_mode(a2, a3, a4, a5); /* call via literal slot */ /* 01b2: callx8 a8 */
  if (a10 != 0) goto L_1c5; /* 01b5: bnez.n a10, 1c5 <pm_sleep+0x191> */
  a3 = MEM32(a1 + 0); /* 01b7: l32i.n a3, a1, 0 */
  if (a3 != 3) goto L_1c5; /* 01b9: bnei a3, 3, 1c5 <pm_sleep+0x191> */
  a10 = 0x1; /* 01bc: movi a10, 1 */
  a8 = (uint32_t)&wifi_rf_phy_disable; /* 01bf: l32r a8, 2c <pm_sleep-0x8> (0 <pm_sleep-0x34>) */ /* literal: GOT slot for wifi_rf_phy_disable */
  wifi_rf_phy_disable(a2, a3, a4, a5); /* call via literal slot */ /* 01c2: callx8 a8 */
L_1c5:;
  a3 = (uint32_t)&g_pm_cnt; /* 01c5: l32r a3, 18 <pm_sleep-0x1c> (0 <pm_sleep-0x34>) */ /* literal @0x18: g_pm_cnt */
  a4 = MEM32(a3 + 40); /* 01c8: l32i.n a4, a3, 40 */
  a4 = a4 + (1); /* 01ca: addi.n a4, a4, 1 */
  a8 = MEM32(a2 + 120); /* 01cc: l32i a8, a2, 120 */
  a9 = MEM32(a2 + 112); /* 01cf: l32i a9, a2, 112 */
  a10 = MEM32(a2 + 124); /* 01d2: l32i a10, a2, 124 */
  MEM32(a3 + 40) = a4; /* 01d5: s32i.n a4, a3, 40 */
  a4 = MEM32(a2 + 116); /* 01d7: l32i a4, a2, 116 */
  a2 = a9 - a8; /* 01da: sub a2, a9, a8 */
  a8 = 0x1; /* 01dd: movi.n a8, 1 */
  if (a9 < a2) goto L_1e5; /* 01df: bltu a9, a2, 1e5 <pm_sleep+0x1b1> */
  a8 = 0x0; /* 01e2: movi a8, 0 */
L_1e5:;
  a11 = MEM32(a3 + 56); /* 01e5: l32i.n a11, a3, 56 */
  a4 = a4 - a10; /* 01e7: sub a4, a4, a10 */
  a10 = a11 + a2; /* 01ea: add.n a10, a11, a2 */
  a4 = a4 - a8; /* 01ec: sub a4, a4, a8 */
  a8 = 0x1; /* 01ef: movi.n a8, 1 */
  a9 = MEM32(a3 + 60); /* 01f1: l32i.n a9, a3, 60 */
  if (a10 < a11) goto L_1f9; /* 01f3: bltu a10, a11, 1f9 <pm_sleep+0x1c5> */
  a8 = 0x0; /* 01f6: movi a8, 0 */
L_1f9:;
  a9 = a9 + a4; /* 01f9: add.n a9, a9, a4 */
  a8 = a8 + a9; /* 01fb: add.n a8, a8, a9 */
  MEM32(a3 + 56) = a10; /* 01fd: s32i.n a10, a3, 56 */
  a10 = MEM32(a3 + 64); /* 01ff: l32i a10, a3, 64 */
  a2 = a10 + a2; /* 0202: add.n a2, a10, a2 */
  MEM32(a3 + 60) = a8; /* 0204: s32i.n a8, a3, 60 */
  a8 = 0x1; /* 0206: movi.n a8, 1 */
  a9 = MEM32(a3 + 68); /* 0208: l32i a9, a3, 68 */
  if (a2 < a10) goto L_210; /* 020b: bltu a2, a10, 210 <pm_sleep+0x1dc> */
  a8 = 0x0; /* 020e: movi.n a8, 0 */
L_210:;
  a4 = a9 + a4; /* 0210: add.n a4, a9, a4 */
  a8 = a8 + a4; /* 0212: add.n a8, a8, a4 */
  a10 = 0x2; /* 0214: movi.n a10, 2 */
  MEM32(a3 + 64) = a2; /* 0216: s32i a2, a3, 64 */
  MEM32(a3 + 68) = a8; /* 0219: s32i a8, a3, 68 */
  MEMW(); /* 021c: memw  */
  a8 = (uint32_t)&pm_set_state; /* 021f: l32r a8, 30 <pm_sleep-0x4> (c <pm_sleep-0x28>) */ /* literal: GOT slot for .text.pm_set_state */
  pm_set_state(a2, a3, a4, a5); /* call via literal slot */ /* 0222: callx8 a8 */
L_225:;
  return (int32_t)a2; /* 0225: retw.n  */
}

/* pm_disconnected_sleep @ pm.o 00000020 size 140B bind GLOBAL
 * Calls: ppCheckTxIdle, wifi_gpio_debug, wifi_rf_phy_disable, g_osi_funcs_p[got] | Data refs: g_mesh_is_started, g_osi_funcs_p, g_pm, ppCheckTxIdle, wifi_gpio_debug, wifi_rf_phy_disable
 *   MMIO: none
 *   funcdb v3: 3 call(s), 6 ref(s); disasm: 7 call(s), 6 data ref(s)
 * Fidelity: medium - 52 instr, 7 branches, calls resolved */
int32_t pm_disconnected_sleep(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pm_disconnected_sleep; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_20:;
  /* 0020: entry a1, 32 */
  a10 = 0x1; /* 0023: movi a10, 1 */
  a8 = (uint32_t)&ppCheckTxIdle; /* 0026: l32r a8, c <pm_disconnected_sleep-0x14> (0 <pm_disconnected_sleep-0x20>) */ /* literal: GOT slot for ppCheckTxIdle */
  ppCheckTxIdle(a2, a3, a4, a5); /* call via literal slot */ /* 0029: callx8 a8 */
  if (a10 != 0) goto L_39; /* 002c: bnez.n a10, 39 <pm_disconnected_sleep+0x19> */
L_2e:;
  a2 = (uint32_t)&g_pm; /* 002e: l32r a2, 0 <pm_disconnected_sleep-0x20> (0 <pm_disconnected_sleep-0x20>) */ /* literal @0x0: g_pm */
  a3 = MEM32(a2 + 288); /* 0031: l32i a3, a2, 0x120 */
  if (a3 == 0) goto L_54; /* 0034: beqz.n a3, 54 <pm_disconnected_sleep+0x34> */
  goto L_aa; /* 0036: j aa <pm_disconnected_sleep+0x8a> */
L_39:;
  a2 = (uint32_t)&g_osi_funcs_p; /* 0039: l32r a2, 4 <pm_disconnected_sleep-0x1c> (0 <pm_disconnected_sleep-0x20>) */ /* literal @0x4: g_osi_funcs_p */
  a2 = MEM32(a2 + 0); /* 003c: l32i.n a2, a2, 0 */
  a10 = MEM32(a2 + 404); /* 003e: l32i a10, a2, 0x194 */
  ((int32_t(*)())a10)(a2, a3, a4, a5); /* 0041: callx8 a10 */ /* indirect */
  if (a10 == 0) goto L_aa; /* 0044: beqz a10, aa <pm_disconnected_sleep+0x8a> */
  a2 = (uint32_t)&g_pm; /* 0047: l32r a2, 0 <pm_disconnected_sleep-0x20> (0 <pm_disconnected_sleep-0x20>) */ /* literal @0x0: g_pm */
  a2 = MEM8(a2 + 24); /* 004a: l8ui a2, a2, 24 */
  if (a2 != 0) goto L_aa; /* 004d: bnez a2, aa <pm_disconnected_sleep+0x8a> */
  goto L_2e; /* 0050: j 2e <pm_disconnected_sleep+0xe> */
  /* 0053: .byte 00 */
L_54:;
  a3 = (uint32_t)&g_mesh_is_started; /* 0054: l32r a3, 8 <pm_disconnected_sleep-0x18> (0 <pm_disconnected_sleep-0x20>) */ /* literal @0x8: g_mesh_is_started */
  a3 = MEM8(a3 + 0); /* 0057: l8ui a3, a3, 0 */
  if (a3 != 0) goto L_aa; /* 005a: bnez a3, aa <pm_disconnected_sleep+0x8a> */
  a10 = 0x1; /* 005d: movi.n a10, 1 */
  a2 = a2 + ((0x100) << 8); /* 005f: addmi a2, a2, 0x100 */
  a4 = (uint32_t)&g_osi_funcs_p; /* 0062: l32r a4, 4 <pm_disconnected_sleep-0x1c> (0 <pm_disconnected_sleep-0x20>) */ /* literal @0x4: g_osi_funcs_p */
  a8 = MEM32(a4 + 0); /* 0065: l32i a8, a4, 0 */
  a8 = MEM32(a8 + 416); /* 0068: l32i a8, a8, 0x1a0 */
  ppCheckTxIdle(a2, a3, a4, a5); /* call via literal slot */ /* 006b: callx8 a8 */
  a10 = 0x26; /* 006e: movi.n a10, 38 */
  a4 = MEM32(a4 + 0); /* 0070: l32i a4, a4, 0 */
  a4 = MEM32(a4 + 416); /* 0073: l32i a4, a4, 0x1a0 */
  g_osi_funcs_p(a2, a3, a4, a5); /* call via literal slot */ /* 0076: callx8 a4 */
  a10 = a3; /* 0079: mov.n a10, a3 */
  a8 = (uint32_t)&wifi_rf_phy_disable; /* 007b: l32r a8, 10 <pm_disconnected_sleep-0x10> (0 <pm_disconnected_sleep-0x20>) */ /* literal: GOT slot for wifi_rf_phy_disable */
  wifi_rf_phy_disable(a2, a3, a4, a5); /* call via literal slot */ /* 007e: callx8 a8 */
  a11 = a3; /* 0081: mov.n a11, a3 */
  a10 = 0x3; /* 0083: movi.n a10, 3 */
  a4 = 0x3; /* 0085: movi.n a4, 3 */
  MEM8(a2 + 29) = a4; /* 0087: s8i a4, a2, 29 */
  MEMW(); /* 008a: memw  */
  MEMW(); /* 008d: memw  */
  a8 = (uint32_t)&wifi_gpio_debug; /* 0090: l32r a8, 14 <pm_disconnected_sleep-0xc> (0 <pm_disconnected_sleep-0x20>) */ /* literal: GOT slot for wifi_gpio_debug */
  wifi_gpio_debug(a2, a3, a4, a5); /* call via literal slot */ /* 0093: callx8 a8 */
  a11 = 0x1; /* 0096: movi.n a11, 1 */
  a10 = 0x4; /* 0098: movi.n a10, 4 */
  a8 = (uint32_t)&wifi_gpio_debug; /* 009a: l32r a8, 18 <pm_disconnected_sleep-0x8> (0 <pm_disconnected_sleep-0x20>) */ /* literal: GOT slot for wifi_gpio_debug */
  wifi_gpio_debug(a2, a3, a4, a5); /* call via literal slot */ /* 009d: callx8 a8 */
  a11 = 0x1; /* 00a0: movi.n a11, 1 */
  a10 = 0x5; /* 00a2: movi.n a10, 5 */
  a8 = (uint32_t)&wifi_gpio_debug; /* 00a4: l32r a8, 1c <pm_disconnected_sleep-0x4> (0 <pm_disconnected_sleep-0x20>) */ /* literal: GOT slot for wifi_gpio_debug */
  wifi_gpio_debug(a2, a3, a4, a5); /* call via literal slot */ /* 00a7: callx8 a8 */
L_aa:;
  return (int32_t)a2; /* 00aa: retw.n  */
}

/* is_off_channel @ pm.o 00000004 size 19B bind GLOBAL
 * Calls: none | Data refs: g_pm
 *   MMIO: none
 *   funcdb v3: 0 call(s), 1 ref(s); disasm: 0 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t is_off_channel(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.is_off_channel; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a2 = (uint32_t)&g_pm; /* 0007: l32r a2, 0 <is_off_channel-0x4> (0 <is_off_channel-0x4>) */ /* literal @0x0: g_pm */
  a8 = 0x1; /* 000a: movi.n a8, 1 */
  a2 = MEM8(a2 + 14); /* 000c: l8ui a2, a2, 14 */
  a2 = a2 ^ a8; /* 000f: xor a2, a2, a8 */
  a2 = (a2 >> 0) & 0xFF; /* 0012: extui a2, a2, 0, 8 */
  return (int32_t)a2; /* 0015: retw.n  */
}

/* pm_enable_send_wake_null_on_channel @ pm.o 00000004 size 22B bind GLOBAL
 * Calls: none | Data refs: g_pm
 *   MMIO: none
 *   funcdb v3: 0 call(s), 1 ref(s); disasm: 0 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t pm_enable_send_wake_null_on_channel(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pm_enable_send_wake_null_on_channel; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a8 = (uint32_t)&g_pm; /* 0007: l32r a8, 0 <pm_enable_send_wake_null_on_channel-0x4> (0 <pm_enable_send_wake_null_on_channel-0x4>) */ /* literal @0x0: g_pm */
  a9 = 0x1; /* 000a: movi.n a9, 1 */
  a8 = a8 + ((0x100) << 8); /* 000c: addmi a8, a8, 0x100 */
  MEM8(a8 + 28) = a9; /* 000f: s8i a9, a8, 28 */
  MEMW(); /* 0012: memw  */
  MEMW(); /* 0015: memw  */
  return (int32_t)a2; /* 0018: retw.n  */
}

/* pm_offchan_is_waiting @ pm.o 00000004 size 17B bind GLOBAL
 * Calls: none | Data refs: .bss.g_offchan_ready_cb
 *   MMIO: none
 *   funcdb v3: 0 call(s), 1 ref(s); disasm: 0 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t pm_offchan_is_waiting(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pm_offchan_is_waiting; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a2 = (uint32_t)&bss_g_offchan_ready_cb; /* 0007: l32r a2, 0 <pm_offchan_is_waiting-0x4> (0 <pm_offchan_is_waiting-0x4>) */ /* literal @0x0: .bss.g_offchan_ready_cb */
  a8 = 0x0; /* 000a: movi.n a8, 0 */
  a9 = MEM32(a2 + 0); /* 000c: l32i.n a9, a2, 0 */
  a2 = 0x1; /* 000e: movi.n a2, 1 */
  if (a9 == 0) a2 = a8; /* 0010: moveqz a2, a8, a9 */
  return (int32_t)a2; /* 0013: retw.n  */
}

/* pm_is_force_return_home_chan @ pm.o 00000004 size 14B bind GLOBAL
 * Calls: none | Data refs: g_pm
 *   MMIO: none
 *   funcdb v3: 0 call(s), 1 ref(s); disasm: 0 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t pm_is_force_return_home_chan(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pm_is_force_return_home_chan; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a8 = (uint32_t)&g_pm; /* 0007: l32r a8, 0 <pm_is_force_return_home_chan-0x4> (0 <pm_is_force_return_home_chan-0x4>) */ /* literal @0x0: g_pm */
  a8 = a8 + ((0x200) << 8); /* 000a: addmi a8, a8, 0x200 */
  a2 = MEM8(a8 + 64); /* 000d: l8ui a2, a8, 64 */
  return (int32_t)a2; /* 0010: retw.n  */
}

/* pm_offchan_execute_ready_cb @ pm.o 00000010 size 52B bind GLOBAL
 * Calls: wifi_log | Data refs: .bss.g_offchan_ready_cb, .bss.g_offchan_ready_ctx, .rodata_wlog_debug.33, wifi_log
 *   MMIO: none
 *   funcdb v3: 1 call(s), 4 ref(s); disasm: 1 call(s), 4 data ref(s)
 * Fidelity: medium - 21 instr, 1 branches, calls resolved */
int32_t pm_offchan_execute_ready_cb(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pm_offchan_execute_ready_cb; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_10:;
  /* 0010: entry a1, 32 */
  a3 = (uint32_t)&bss_g_offchan_ready_cb; /* 0013: l32r a3, 0 <pm_offchan_execute_ready_cb-0x10> (0 <pm_offchan_execute_ready_cb-0x10>) */ /* literal @0x0: .bss.g_offchan_ready_cb */
  a14 = MEM32(a3 + 0); /* 0016: l32i.n a14, a3, 0 */
  if (a14 == 0) goto L_42; /* 0018: beqz.n a14, 42 <pm_offchan_execute_ready_cb+0x32> */
  a11 = 0x1; /* 001a: movi.n a11, 1 */
  a12 = 0x4; /* 001c: movi.n a12, 4 */
  a13 = (uint32_t)&lit_rodata_wlog_debug_33; /* 001e: l32r a13, 4 <pm_offchan_execute_ready_cb-0xc> (0 <pm_offchan_execute_ready_cb-0x10>) */ /* literal @0x4: .rodata_wlog_debug.33 */
  a11 = 0x1000; /* 0021: slli a11, a11, 12 */
  a10 = 0x6; /* 0024: movi.n a10, 6 */
  a8 = (uint32_t)&wifi_log; /* 0026: l32r a8, c <pm_offchan_execute_ready_cb-0x4> (0 <pm_offchan_execute_ready_cb-0x10>) */ /* literal: GOT slot for wifi_log */
  wifi_log(a2, a3, a4, a5); /* call via literal slot */ /* 0029: callx8 a8 */
  a9 = 0x0; /* 002c: movi.n a9, 0 */
  a8 = (uint32_t)&bss_g_offchan_ready_ctx; /* 002e: l32r a8, 8 <pm_offchan_execute_ready_cb-0x8> (0 <pm_offchan_execute_ready_cb-0x10>) */ /* literal @0x8: .bss.g_offchan_ready_ctx */
  a11 = (a2 >> 0) & 0xFF; /* 0031: extui a11, a2, 0, 8 */
  a12 = MEM32(a3 + 0); /* 0034: l32i.n a12, a3, 0 */
  a10 = MEM32(a8 + 0); /* 0036: l32i.n a10, a8, 0 */
  MEM32(a3 + 0) = a9; /* 0038: s32i.n a9, a3, 0 */
  MEM32(a8 + 0) = a9; /* 003a: s32i.n a9, a8, 0 */
  MEMW(); /* 003c: memw  */
  ((int32_t(*)())a12)(a2, a3, a4, a5); /* 003f: callx8 a12 */ /* indirect */
L_42:;
  return (int32_t)a2; /* 0042: retw.n  */
}

/* pm_wake_up @ pm.o 00000014 size 57B bind GLOBAL
 * Calls: pm_disable_disconnected_sleep_delay_timer, pm_disable_sleep_delay_timer, pm_disconnected_wake, pm_dream | Data refs: g_pm, pm_disable_disconnected_sleep_delay_timer, pm_disable_sleep_delay_timer, pm_disconnected_wake, pm_dream
 *   MMIO: none
 *   funcdb v3: 4 call(s), 5 ref(s); disasm: 4 call(s), 5 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t pm_wake_up(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pm_wake_up; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_14:;
  /* 0014: entry a1, 32 */
  a2 = (uint32_t)&g_pm; /* 0017: l32r a2, 0 <pm_wake_up-0x14> (0 <pm_wake_up-0x14>) */ /* literal @0x0: g_pm */
  a8 = MEM8(a2 + 13); /* 001a: l8ui a8, a2, 13 */
  if (a8 == 0) goto L_34; /* 001d: beqz.n a8, 34 <pm_wake_up+0x20> */
  a8 = (uint32_t)&pm_disable_sleep_delay_timer; /* 001f: l32r a8, 4 <pm_wake_up-0x10> (0 <pm_wake_up-0x14>) */ /* literal: GOT slot for pm_disable_sleep_delay_timer */
  pm_disable_sleep_delay_timer(a2, a3, a4, a5); /* call via literal slot */ /* 0022: callx8 a8 */
  a8 = MEM8(a2 + 1); /* 0025: l8ui a8, a2, 1 */
  if (a8 != 2) goto L_40; /* 0028: bnei a8, 2, 40 <pm_wake_up+0x2c> */
  a8 = (uint32_t)&pm_dream; /* 002b: l32r a8, 8 <pm_wake_up-0xc> (0 <pm_wake_up-0x14>) */ /* literal: GOT slot for pm_dream */
  pm_dream(a2, a3, a4, a5); /* call via literal slot */ /* 002e: callx8 a8 */
  goto L_40; /* 0031: j 40 <pm_wake_up+0x2c> */
L_34:;
  a8 = (uint32_t)&pm_disable_disconnected_sleep_delay_timer; /* 0034: l32r a8, c <pm_wake_up-0x8> (0 <pm_wake_up-0x14>) */ /* literal: GOT slot for pm_disable_disconnected_sleep_delay_timer */
  pm_disable_disconnected_sleep_delay_timer(a2, a3, a4, a5); /* call via literal slot */ /* 0037: callx8 a8 */
  a8 = (uint32_t)&pm_disconnected_wake; /* 003a: l32r a8, 10 <pm_wake_up-0x4> (0 <pm_wake_up-0x14>) */ /* literal: GOT slot for pm_disconnected_wake */
  pm_disconnected_wake(a2, a3, a4, a5); /* call via literal slot */ /* 003d: callx8 a8 */
L_40:;
  a8 = MEM32(a2 + 288); /* 0040: l32i a8, a2, 0x120 */
  a8 = a8 + (1); /* 0043: addi.n a8, a8, 1 */
  MEM32(a2 + 288) = a8; /* 0045: s32i a8, a2, 0x120 */
  MEMW(); /* 0048: memw  */
  return (int32_t)a2; /* 004b: retw.n  */
}

/* pm_send_probe_start @ pm.o 0000000c size 51B bind GLOBAL
 * Calls: pm_wake_up, .text.pm_disable_active_timer[got] | Data refs: g_pm, pm_wake_up, .text.pm_disable_active_timer
 *   MMIO: none
 *   funcdb v3: 1 call(s), 2 ref(s); disasm: 2 call(s), 3 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t pm_send_probe_start(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pm_send_probe_start; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_c:;
  /* 000c: entry a1, 32 */
  a2 = (uint32_t)&g_pm; /* 000f: l32r a2, 0 <pm_send_probe_start-0xc> (0 <pm_send_probe_start-0xc>) */ /* literal @0x0: g_pm */
  a8 = a2 + ((0x100) << 8); /* 0012: addmi a8, a2, 0x100 */
  a8 = MEM8(a8 + 29); /* 0015: l8ui a8, a8, 29 */
  if (a8 >= 2) goto L_21; /* 0018: bgeui a8, 2, 21 <pm_send_probe_start+0x15> */
  a8 = MEM8(a2 + 13); /* 001b: l8ui a8, a2, 13 */
  if (a8 == 0) goto L_3a; /* 001e: beqz a8, 3a <pm_send_probe_start+0x2e> */
L_21:;
  a8 = MEM8(a2 + 15); /* 0021: l8ui a8, a2, 15 */
  if (a8 != 0) goto L_3a; /* 0024: bnez.n a8, 3a <pm_send_probe_start+0x2e> */
  a8 = (uint32_t)&pm_disable_active_timer; /* 0026: l32r a8, 4 <pm_send_probe_start-0x8> (8 <pm_send_probe_start-0x4>) */ /* literal: GOT slot for .text.pm_disable_active_timer */
  pm_disable_active_timer(a2, a3, a4, a5); /* call via literal slot */ /* 0029: callx8 a8 */
  a8 = (uint32_t)&pm_wake_up; /* 002c: l32r a8, 8 <pm_send_probe_start-0x4> (0 <pm_send_probe_start-0xc>) */ /* literal: GOT slot for pm_wake_up */
  pm_wake_up(a2, a3, a4, a5); /* call via literal slot */ /* 002f: callx8 a8 */
  a8 = 0x1; /* 0032: movi.n a8, 1 */
  MEM8(a2 + 15) = a8; /* 0034: s8i a8, a2, 15 */
  MEMW(); /* 0037: memw  */
L_3a:;
  MEMW(); /* 003a: memw  */
  return (int32_t)a2; /* 003d: retw.n  */
}

/* pm_off_channel @ pm.o 00000024 size 232B bind GLOBAL
 * Calls: pm_dream, pm_send_nullfunc, pm_wake_up, .text.pm_disable_active_timer[got] | Data refs: g_osi_funcs_p, g_pm, pm_dream, pm_send_nullfunc, pm_wake_up, .text.pm_disable_active_timer
 *   MMIO: 0x3FF73CB8
 *   funcdb v3: 3 call(s), 5 ref(s); disasm: 6 call(s), 6 data ref(s)
 * Fidelity: medium - 86 instr, 14 branches, calls resolved */
int32_t pm_off_channel(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pm_off_channel; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_24:;
  /* 0024: entry a1, 32 */
  a2 = (uint32_t)&g_pm; /* 0027: l32r a2, 0 <pm_off_channel-0x24> (0 <pm_off_channel-0x24>) */ /* literal @0x0: g_pm */
  a3 = a2 + ((0x100) << 8); /* 002a: addmi a3, a2, 0x100 */
  a4 = MEM8(a3 + 29); /* 002d: l8ui a4, a3, 29 */
  if (a4 >= 2) goto L_38; /* 0030: bgeui a4, 2, 38 <pm_off_channel+0x14> */
  a4 = MEM8(a2 + 13); /* 0033: l8ui a4, a2, 13 */
  if (a4 == 0) goto L_3d; /* 0036: beqz.n a4, 3d <pm_off_channel+0x19> */
L_38:;
  a4 = MEM8(a2 + 14); /* 0038: l8ui a4, a2, 14 */
  if (a4 != 0) goto L_4c; /* 003b: bnez.n a4, 4c <pm_off_channel+0x28> */
L_3d:;
  a3 = 0x0; /* 003d: movi.n a3, 0 */
  MEM8(a2 + 14) = a3; /* 003f: s8i a3, a2, 14 */
  MEMW(); /* 0042: memw  */
  MEMW(); /* 0045: memw  */
  goto L_107; /* 0048: j 107 <pm_off_channel+0xe3> */
  /* 004b: .byte 00 */
L_4c:;
  a8 = (uint32_t)&pm_disable_active_timer; /* 004c: l32r a8, c <pm_off_channel-0x18> (8 <pm_off_channel-0x1c>) */ /* literal: GOT slot for .text.pm_disable_active_timer */
  pm_disable_active_timer(a2, a3, a4, a5); /* call via literal slot */ /* 004f: callx8 a8 */
  a4 = MEM8(a2 + 13); /* 0052: l8ui a4, a2, 13 */
  if (a4 != 0) goto L_69; /* 0055: bnez.n a4, 69 <pm_off_channel+0x45> */
  a8 = (uint32_t)&pm_wake_up; /* 0057: l32r a8, 10 <pm_off_channel-0x14> (0 <pm_off_channel-0x24>) */ /* literal: GOT slot for pm_wake_up */
  pm_wake_up(a2, a3, a4, a5); /* call via literal slot */ /* 005a: callx8 a8 */
  MEM8(a2 + 14) = a4; /* 005d: s8i a4, a2, 14 */
  MEMW(); /* 0060: memw  */
  MEMW(); /* 0063: memw  */
  goto L_107; /* 0066: j 107 <pm_off_channel+0xe3> */
L_69:;
  a5 = a2 + ((0x200) << 8); /* 0069: addmi a5, a2, 0x200 */
  a6 = 0x1; /* 006c: movi.n a6, 1 */
  a4 = MEM8(a2 + 1); /* 006e: l8ui a4, a2, 1 */
  MEM8(a5 + 30) = a6; /* 0071: s8i a6, a5, 30 */
  MEMW(); /* 0074: memw  */
  if (a4 != 0) goto L_c9; /* 0077: bnez a4, c9 <pm_off_channel+0xa5> */
  a4 = (uint32_t)&g_osi_funcs_p; /* 007a: l32r a4, 4 <pm_off_channel-0x20> (0 <pm_off_channel-0x24>) */ /* literal @0x4: g_osi_funcs_p */
  a4 = MEM32(a4 + 0); /* 007d: l32i.n a4, a4, 0 */
  a10 = MEM32(a4 + 404); /* 007f: l32i a10, a4, 0x194 */
  MEMW(); /* 0082: memw  */
  ((int32_t(*)())a10)(a2, a3, a4, a5); /* 0085: callx8 a10 */ /* indirect */
  if (a10 == 0) goto L_8d; /* 0088: beqz.n a10, 8d <pm_off_channel+0x69> */
  MEM8(a2 + 25) = a6; /* 008a: s8i a6, a2, 25 */
L_8d:;
  a4 = 0x1; /* 008d: movi.n a4, 1 */
  MEM8(a3 + 28) = a4; /* 008f: s8i a4, a3, 28 */
  MEMW(); /* 0092: memw  */
  MEMW(); /* 0095: memw  */
  a8 = (uint32_t)&pm_dream; /* 0098: l32r a8, 14 <pm_off_channel-0x10> (0 <pm_off_channel-0x24>) */ /* literal: GOT slot for pm_dream */
  pm_dream(a2, a3, a4, a5); /* call via literal slot */ /* 009b: callx8 a8 */
  a4 = 0x7; /* 009e: movi.n a4, 7 */
  a4 = 0xE0000; /* 00a0: slli a4, a4, 17 */
  a8 = 0x3FF73CB8; /* 00a3: l32r a8, 8 <pm_off_channel-0x1c> (3ff73cb8 <pm_attach+0x3ff73c34>) */ /* MMIO base */ @0x8
  MEMW(); /* 00a6: memw  */
  a3 = REG32(0x3FF73CB8); /* 00a9: l32i.n a3, a8, 0 */ /* MMIO read: base 0x3FF73CB8+0 */
  a3 = a3 | a4; /* 00ab: or a3, a3, a4 */
  MEMW(); /* 00ae: memw  */
  REG32(0x3FF73CB8) = a3; /* 00b1: s32i.n a3, a8, 0 */ /* MMIO write: base 0x3FF73CB8+0 */
L_b3:;
  a3 = MEM8(a2 + 20); /* 00b3: l8ui a3, a2, 20 */
  if (a3 != 0) goto L_f6; /* 00b6: bnez.n a3, f6 <pm_off_channel+0xd2> */
  a10 = 0x1; /* 00b8: movi a10, 1 */
  MEMW(); /* 00bb: memw  */
  a8 = (uint32_t)&pm_send_nullfunc; /* 00be: l32r a8, 18 <pm_off_channel-0xc> (0 <pm_off_channel-0x24>) */ /* literal: GOT slot for pm_send_nullfunc */
  pm_send_nullfunc(a2, a3, a4, a5); /* call via literal slot */ /* 00c1: callx8 a8 */
  goto L_f6; /* 00c4: j f6 <pm_off_channel+0xd2> */
  /* 00c7: .byte 00 */
  /* 00c8: .byte 00 */
L_c9:;
  if (a4 != 1) goto L_f0; /* 00c9: bnei a4, 1, f0 <pm_off_channel+0xcc> */
  a6 = MEM8(a2 + 19); /* 00cc: l8ui a6, a2, 19 */
  if (a6 == 0) goto L_f6; /* 00cf: beqz.n a6, f6 <pm_off_channel+0xd2> */
  a6 = (uint32_t)&g_osi_funcs_p; /* 00d1: l32r a6, 4 <pm_off_channel-0x20> (0 <pm_off_channel-0x24>) */ /* literal @0x4: g_osi_funcs_p */
  a6 = MEM32(a6 + 0); /* 00d4: l32i.n a6, a6, 0 */
  a10 = MEM32(a6 + 404); /* 00d6: l32i a10, a6, 0x194 */
  ((int32_t(*)())a10)(a2, a3, a4, a5); /* 00d9: callx8 a10 */ /* indirect */
  if (a10 == 0) goto L_e1; /* 00dc: beqz.n a10, e1 <pm_off_channel+0xbd> */
  MEM8(a2 + 25) = a4; /* 00de: s8i a4, a2, 25 */
L_e1:;
  a4 = 0x1; /* 00e1: movi.n a4, 1 */
  MEM8(a3 + 28) = a4; /* 00e3: s8i a4, a3, 28 */
  MEMW(); /* 00e6: memw  */
  MEMW(); /* 00e9: memw  */
  goto L_b3; /* 00ec: j b3 <pm_off_channel+0x8f> */
  /* 00ef: .byte 00 */
L_f0:;
  a8 = (uint32_t)&pm_dream; /* 00f0: l32r a8, 1c <pm_off_channel-0x8> (0 <pm_off_channel-0x24>) */ /* literal: GOT slot for pm_dream */
  pm_dream(a2, a3, a4, a5); /* call via literal slot */ /* 00f3: callx8 a8 */
L_f6:;
  a3 = 0x0; /* 00f6: movi.n a3, 0 */
  a8 = (uint32_t)&pm_wake_up; /* 00f8: l32r a8, 20 <pm_off_channel-0x4> (0 <pm_off_channel-0x24>) */ /* literal: GOT slot for pm_wake_up */
  pm_wake_up(a2, a3, a4, a5); /* call via literal slot */ /* 00fb: callx8 a8 */
  MEM8(a2 + 14) = a3; /* 00fe: s8i a3, a2, 14 */
  MEM8(a5 + 30) = a3; /* 0101: s8i a3, a5, 30 */
  MEMW(); /* 0104: memw  */
L_107:;
  MEMW(); /* 0107: memw  */
  return (int32_t)a2; /* 010a: retw.n  */
}

/* pm_wake_done @ pm.o 0000000c size 76B bind GLOBAL
 * Calls: pm_disconnected_sleep, pm_sleep | Data refs: g_pm, pm_disconnected_sleep, pm_sleep
 *   MMIO: none
 *   funcdb v3: 2 call(s), 3 ref(s); disasm: 2 call(s), 3 data ref(s)
 * Fidelity: medium - 28 instr, 9 branches, calls resolved */
int32_t pm_wake_done(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pm_wake_done; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_c:;
  /* 000c: entry a1, 32 */
  a8 = (uint32_t)&g_pm; /* 000f: l32r a8, 0 <pm_wake_done-0xc> (0 <pm_wake_done-0xc>) */ /* literal @0x0: g_pm */
  a9 = MEM32(a8 + 288); /* 0012: l32i a9, a8, 0x120 */
  if (a9 == 0) goto L_1c; /* 0015: beqz.n a9, 1c <pm_wake_done+0x10> */
  a9 = a9 + (-1); /* 0017: addi.n a9, a9, -1 */
  MEM32(a8 + 288) = a9; /* 0019: s32i a9, a8, 0x120 */
L_1c:;
  a10 = MEM8(a8 + 13); /* 001c: l8ui a10, a8, 13 */
  a9 = MEM32(a8 + 288); /* 001f: l32i a9, a8, 0x120 */
  if (a10 == 0) goto L_40; /* 0022: beqz.n a10, 40 <pm_wake_done+0x34> */
  if (a9 != 0) goto L_56; /* 0024: bnez.n a9, 56 <pm_wake_done+0x4a> */
  a9 = MEM8(a8 + 1); /* 0026: l8ui a9, a8, 1 */
  if (a9 != 1) goto L_56; /* 0029: bnei a9, 1, 56 <pm_wake_done+0x4a> */
  a8 = a8 + ((0x100) << 8); /* 002c: addmi a8, a8, 0x100 */
  a8 = MEM8(a8 + 184); /* 002f: l8ui a8, a8, 184 */
  if (a8 != 0) goto L_56; /* 0032: bnez.n a8, 56 <pm_wake_done+0x4a> */
  MEMW(); /* 0034: memw  */
  a8 = (uint32_t)&pm_sleep; /* 0037: l32r a8, 4 <pm_wake_done-0x8> (0 <pm_wake_done-0xc>) */ /* literal: GOT slot for pm_sleep */
  pm_sleep(a2, a3, a4, a5); /* call via literal slot */ /* 003a: callx8 a8 */
  goto L_56; /* 003d: j 56 <pm_wake_done+0x4a> */
L_40:;
  if (a9 != 0) goto L_56; /* 0040: bnez.n a9, 56 <pm_wake_done+0x4a> */
  a8 = a8 + ((0x100) << 8); /* 0042: addmi a8, a8, 0x100 */
  a9 = MEM8(a8 + 29); /* 0045: l8ui a9, a8, 29 */
  if (a9 != 2) goto L_56; /* 0048: bnei a9, 2, 56 <pm_wake_done+0x4a> */
  a8 = MEM8(a8 + 184); /* 004b: l8ui a8, a8, 184 */
  if (a8 != 0) goto L_56; /* 004e: bnez.n a8, 56 <pm_wake_done+0x4a> */
  a8 = (uint32_t)&pm_disconnected_sleep; /* 0050: l32r a8, 8 <pm_wake_done-0x4> (0 <pm_wake_done-0xc>) */ /* literal: GOT slot for pm_disconnected_sleep */
  pm_disconnected_sleep(a2, a3, a4, a5); /* call via literal slot */ /* 0053: callx8 a8 */
L_56:;
  return (int32_t)a2; /* 0056: retw.n  */
}

/* pm_coex_separate_connectionless_window @ pm.o 00000024 size 692B bind GLOBAL
 * Calls: pm_coex_schm_overall_period_get, pm_wake_done, pm_wake_up, wifi_gpio_debug, g_pm[got], g_pm[got] | Data refs: g_osi_funcs_p, g_pm, pm_coex_schm_overall_period_get, pm_wake_done, pm_wake_up, wifi_gpio_debug
 *   MMIO: none
 *   funcdb v3: 4 call(s), 6 ref(s); disasm: 8 call(s), 6 data ref(s)
 * Fidelity: low - 261 instr, 49 branches, 7 indirect; call-sequence + MMIO skeleton */
int32_t pm_coex_separate_connectionless_window(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pm_coex_separate_connectionless_window; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_24:;
  /* 0024: entry a1, 64 */
  a3 = (uint32_t)&g_osi_funcs_p; /* 0027: l32r a3, 0 <pm_coex_separate_connectionless_window-0x24> (0 <pm_coex_separate_connectionless_window-0x24>) */ /* literal @0x0: g_osi_funcs_p */
  a2 = MEM32(a3 + 0); /* 002a: l32i.n a2, a3, 0 */
  a10 = MEM32(a2 + 404); /* 002c: l32i a10, a2, 0x194 */
  ((int32_t(*)())a10)(a2, a3, a4, a5); /* 002f: callx8 a10 */ /* indirect */
  if (a10 == 0) goto L_2d6; /* 0032: beqz a10, 2d6 <pm_coex_separate_connectionless_window+0x2b2> */
  a6 = (uint32_t)&g_pm; /* 0035: l32r a6, 4 <pm_coex_separate_connectionless_window-0x20> (0 <pm_coex_separate_connectionless_window-0x24>) */ /* literal @0x4: g_pm */
  a4 = a6 + ((0x100) << 8); /* 0038: addmi a4, a6, 0x100 */
  a2 = MEM8(a4 + 29); /* 003b: l8ui a2, a4, 29 */
  if (a2 >= 2) goto L_47; /* 003e: bgeui a2, 2, 47 <pm_coex_separate_connectionless_window+0x23> */
  a2 = MEM8(a6 + 13); /* 0041: l8ui a2, a6, 13 */
  if (a2 == 0) goto L_2d6; /* 0044: beqz a2, 2d6 <pm_coex_separate_connectionless_window+0x2b2> */
L_47:;
  a2 = MEM32(a3 + 0); /* 0047: l32i a2, a3, 0 */
  a10 = MEM32(a2 + 272); /* 004a: l32i a10, a2, 0x110 */
  ((int32_t(*)())a10)(a2, a3, a4, a5); /* 004d: callx8 a10 */ /* indirect */
  a5 = a10; /* 0050: mov.n a5, a10 */
  a13 = a11; /* 0052: mov.n a13, a11 */
  a2 = MEM8(a4 + 136); /* 0054: l8ui a2, a4, 136 */
  if (a2 == 0) goto L_ab; /* 0057: beqz a2, ab <pm_coex_separate_connectionless_window+0x87> */
  a2 = MEM16(a6 + 394); /* 005a: l16ui a2, a6, 0x18a */
  if (a2 == 0) goto L_ab; /* 005d: beqz a2, ab <pm_coex_separate_connectionless_window+0x87> */
  a7 = 0x1; /* 0060: movi a7, 1 */
  a2 = MEM32(a3 + 0); /* 0063: l32i a2, a3, 0 */
  a10 = (uint32_t)&g_pm; /* 0066: l32r a10, 8 <pm_coex_separate_connectionless_window-0x1c> (0 <pm_coex_separate_connectionless_window-0x24>) */ /* literal @0x8: g_pm */
  a2 = MEM32(a2 + 236); /* 0069: l32i a2, a2, 236 */
  MEM32(a1 + 16) = a11; /* 006c: s32i a11, a1, 16 */
  MEMW(); /* 006f: memw  */
  ((int32_t(*)())a2)(a2, a3, a4, a5); /* 0072: callx8 a2 */ /* indirect */
  a9 = MEM32(a6 + 424); /* 0075: l32i a9, a6, 0x1a8 */
  a8 = MEM32(a6 + 416); /* 0078: l32i a8, a6, 0x1a0 */
  a8 = a9 + a8; /* 007b: add.n a8, a9, a8 */
  a2 = MEM32(a6 + 428); /* 007d: l32i a2, a6, 0x1ac */
  a10 = MEM32(a6 + 420); /* 0080: l32i a10, a6, 0x1a4 */
  a13 = MEM32(a1 + 16); /* 0083: l32i.n a13, a1, 16 */
  if (a8 < a9) goto L_8a; /* 0085: bltu a8, a9, 8a <pm_coex_separate_connectionless_window+0x66> */
  a7 = 0x0; /* 0088: movi.n a7, 0 */
L_8a:;
  a2 = a2 + a10; /* 008a: add.n a2, a2, a10 */
  a2 = a7 + a2; /* 008c: add.n a2, a7, a2 */
  a7 = a8 - a5; /* 008e: sub a7, a8, a5 */
  a9 = 0x1; /* 0091: movi.n a9, 1 */
  if (a8 < a7) goto L_98; /* 0093: bltu a8, a7, 98 <pm_coex_separate_connectionless_window+0x74> */
  a9 = 0x0; /* 0096: movi.n a9, 0 */
L_98:;
  a2 = a2 - a13; /* 0098: sub a2, a2, a13 */
  a2 = a2 - a9; /* 009b: sub a2, a2, a9 */
  /* 009e: bgez a2, a5 <pm_coex_separate_connectionless_window+0x81> */ /* UNMODELED branch */
  a7 = 0x0; /* 00a1: movi.n a7, 0 */
  a2 = 0x0; /* 00a3: mov.n a2, a7 */
L_a5:;
  MEM32(a6 + 424) = a7; /* 00a5: s32i a7, a6, 0x1a8 */
  MEM32(a6 + 428) = a2; /* 00a8: s32i a2, a6, 0x1ac */
L_ab:;
  a7 = MEM32(a6 + 424); /* 00ab: l32i a7, a6, 0x1a8 */
  a8 = MEM32(a6 + 428); /* 00ae: l32i a8, a6, 0x1ac */
  a9 = a7 | a8; /* 00b1: or a9, a7, a8 */
  a14 = MEM32(a6 + 96); /* 00b4: l32i a14, a6, 96 */
  a2 = MEM32(a6 + 100); /* 00b7: l32i a2, a6, 100 */
  if (a9 == 0) goto L_2b5; /* 00ba: beqz a9, 2b5 <pm_coex_separate_connectionless_window+0x291> */
  a12 = MEM16(a6 + 394); /* 00bd: l16ui a12, a6, 0x18a */
  if (a12 != 0) goto L_14c; /* 00c0: bnez a12, 14c <pm_coex_separate_connectionless_window+0x128> */
  a8 = MEM32(a3 + 0); /* 00c3: l32i.n a8, a3, 0 */
  a7 = (uint32_t)&g_pm; /* 00c5: l32r a7, c <pm_coex_separate_connectionless_window-0x18> (0 <pm_coex_separate_connectionless_window-0x24>) */ /* literal @0xC: g_pm */
  a10 = a7; /* 00c8: mov.n a10, a7 */
  a8 = MEM32(a8 + 236); /* 00ca: l32i a8, a8, 236 */
  MEM32(a1 + 16) = a13; /* 00cd: s32i.n a13, a1, 16 */
  MEM32(a1 + 8) = a14; /* 00cf: s32i.n a14, a1, 8 */
  MEM32(a1 + 4) = a12; /* 00d1: s32i a12, a1, 4 */
  MEMW(); /* 00d4: memw  */
  ((int32_t(*)())a8)(a2, a3, a4, a5); /* 00d7: callx8 a8 */ /* indirect */
  a8 = MEM32(a3 + 0); /* 00da: l32i.n a8, a3, 0 */
  a8 = MEM32(a8 + 248); /* 00dc: l32i a8, a8, 248 */
  MEM32(a1 + 12) = a8; /* 00df: s32i.n a8, a1, 12 */
  MEMW(); /* 00e1: memw  */
  a8 = (uint32_t)&pm_coex_schm_overall_period_get; /* 00e4: l32r a8, 10 <pm_coex_separate_connectionless_window-0x14> (0 <pm_coex_separate_connectionless_window-0x24>) */ /* literal: GOT slot for pm_coex_schm_overall_period_get */
  pm_coex_schm_overall_period_get(a2, a3, a4, a5); /* call via literal slot */ /* 00e7: callx8 a8 */
  a11 = a10; /* 00ea: mov.n a11, a10 */
  a9 = MEM32(a3 + 0); /* 00ec: l32i.n a9, a3, 0 */
  a10 = MEM32(a9 + 444); /* 00ee: l32i a10, a9, 0x1bc */
  MEM32(a1 + 0) = a11; /* 00f1: s32i.n a11, a1, 0 */
  MEMW(); /* 00f3: memw  */
  ((int32_t(*)())a10)(a2, a3, a4, a5); /* 00f6: callx8 a10 */ /* indirect */
  a11 = MEM32(a1 + 0); /* 00f9: l32i.n a11, a1, 0 */
  a10 = (uint32_t)((uint64_t)a11 * a10); /* 00fb: mull a10, a11, a10 */
  a10 = (a10 << 4) + a10; /* 00fe: addx4 a10, a10, a10 */
  a10 = (a10 << 4) + a10; /* 0101: addx4 a10, a10, a10 */
  a12 = MEM32(a1 + 4); /* 0104: l32i.n a12, a1, 4 */
  a11 = a10 << (2 & 31); /* 0106: slli a11, a10, 2 */
  a10 = a7; /* 0109: mov.n a10, a7 */
  a8 = MEM32(a1 + 12); /* 010b: l32i a8, a1, 12 */
  pm_coex_schm_overall_period_get(a2, a3, a4, a5); /* call via literal slot */ /* 010e: callx8 a8 */
  a13 = MEM32(a1 + 16); /* 0111: l32i.n a13, a1, 16 */
  a14 = MEM32(a1 + 8); /* 0113: l32i.n a14, a1, 8 */
  if (a13 < a2) goto L_124; /* 0115: bltu a13, a2, 124 <pm_coex_separate_connectionless_window+0x100> */
  if (a2 == a13) goto L_11e; /* 0118: beq a2, a13, 11e <pm_coex_separate_connectionless_window+0xfa> */
  goto L_2b5; /* 011b: j 2b5 <pm_coex_separate_connectionless_window+0x291> */
L_11e:;
  if (a5 < a14) goto L_124; /* 011e: bltu a5, a14, 124 <pm_coex_separate_connectionless_window+0x100> */
  goto L_2b5; /* 0121: j 2b5 <pm_coex_separate_connectionless_window+0x291> */
L_124:;
  a2 = 0x1; /* 0124: movi.n a2, 1 */
  a7 = MEM32(a6 + 96); /* 0126: l32i a7, a6, 96 */
  a5 = a7 - a5; /* 0129: sub a5, a7, a5 */
  a8 = MEM32(a6 + 100); /* 012c: l32i a8, a6, 100 */
  if (a7 < a5) goto L_134; /* 012f: bltu a7, a5, 134 <pm_coex_separate_connectionless_window+0x110> */
  a2 = 0x0; /* 0132: movi.n a2, 0 */
L_134:;
  a8 = a8 - a13; /* 0134: sub a8, a8, a13 */
  a8 = a8 - a2; /* 0137: sub a8, a8, a2 */
  a2 = MEM32(a3 + 0); /* 013a: l32i.n a2, a3, 0 */
  a7 = a5; /* 013c: mov.n a7, a5 */
  a12 = a5; /* 013e: mov.n a12, a5 */
  a11 = 0x0; /* 0140: movi.n a11, 0 */
  a10 = 0x1; /* 0142: movi.n a10, 1 */
  a2 = MEM32(a2 + 412); /* 0144: l32i a2, a2, 0x19c */
  goto L_25c; /* 0147: j 25c <pm_coex_separate_connectionless_window+0x238> */
  /* 014a: .byte 00 */
  /* 014b: .byte 00 */
L_14c:;
  if (a13 < a2) goto L_155; /* 014c: bltu a13, a2, 155 <pm_coex_separate_connectionless_window+0x131> */
  if (a2 != a13) goto L_17e; /* 014f: bne a2, a13, 17e <pm_coex_separate_connectionless_window+0x15a> */
  if (a5 >= a14) goto L_17e; /* 0152: bgeu a5, a14, 17e <pm_coex_separate_connectionless_window+0x15a> */
L_155:;
  a12 = a14 - a5; /* 0155: sub a12, a14, a5 */
  a5 = 0x1; /* 0158: movi a5, 1 */
  if (a14 < a12) goto L_161; /* 015b: bltu a14, a12, 161 <pm_coex_separate_connectionless_window+0x13d> */
  a5 = 0x0; /* 015e: movi a5, 0 */
L_161:;
  a2 = a2 - a13; /* 0161: sub a2, a2, a13 */
  a2 = a2 - a5; /* 0164: sub a2, a2, a5 */
  if (a2 < a8) goto L_170; /* 0167: bltu a2, a8, 170 <pm_coex_separate_connectionless_window+0x14c> */
  if (a8 != a2) goto L_172; /* 016a: bne a8, a2, 172 <pm_coex_separate_connectionless_window+0x14e> */
  if (a12 >= a7) goto L_172; /* 016d: bgeu a12, a7, 172 <pm_coex_separate_connectionless_window+0x14e> */
L_170:;
  a7 = a12; /* 0170: mov.n a7, a12 */
L_172:;
  a2 = MEM32(a3 + 0); /* 0172: l32i.n a2, a3, 0 */
  a11 = 0x0; /* 0174: movi.n a11, 0 */
  a10 = 0x1; /* 0176: movi.n a10, 1 */
  a2 = MEM32(a2 + 412); /* 0178: l32i a2, a2, 0x19c */
  goto L_1fd; /* 017b: j 1fd <pm_coex_separate_connectionless_window+0x1d9> */
L_17e:;
  a9 = a12 << (5 & 31); /* 017e: slli a9, a12, 5 */
  a10 = MEM32(a6 + 408); /* 0181: l32i a10, a6, 0x198 */
  a9 = a9 - a12; /* 0184: sub a9, a9, a12 */
  a12 = (a9 << 4) + a12; /* 0187: addx4 a12, a9, a12 */
  a15 = a12 << (3 & 31); /* 018a: slli a15, a12, 3 */
  a9 = (int32_t)a12 >> (31 & 31); /* 018d: srai a9, a12, 31 */
  a12 = (a12 << 8) + a10; /* 0190: addx8 a12, a12, a10 */
  a11 = MEM32(a6 + 412); /* 0193: l32i a11, a6, 0x19c */
  a10 = 0x1; /* 0196: movi.n a10, 1 */
  if (a12 < a15) goto L_19e; /* 0198: bltu a12, a15, 19e <pm_coex_separate_connectionless_window+0x17a> */
  a10 = 0x0; /* 019b: movi a10, 0 */
L_19e:;
  a9 = a9 + a11; /* 019e: add.n a9, a9, a11 */
  a9 = a10 + a9; /* 01a0: add.n a9, a10, a9 */
  a10 = a12 - a5; /* 01a2: sub a10, a12, a5 */
  a11 = 0x1; /* 01a5: movi.n a11, 1 */
  if (a12 < a10) goto L_1ac; /* 01a7: bltu a12, a10, 1ac <pm_coex_separate_connectionless_window+0x188> */
  a11 = 0x0; /* 01aa: movi.n a11, 0 */
L_1ac:;
  a9 = a9 - a13; /* 01ac: sub a9, a9, a13 */
  a9 = a9 - a11; /* 01af: sub a9, a9, a11 */
  /* 01b2: bgez a9, 1b9 <pm_coex_separate_connectionless_window+0x195> */ /* UNMODELED branch */
  a10 = 0x0; /* 01b5: movi.n a10, 0 */
  a9 = 0x0; /* 01b7: mov.n a9, a10 */
L_1b9:;
  a11 = MEM32(a6 + 432); /* 01b9: l32i a11, a6, 0x1b0 */
  a12 = 0x1; /* 01bc: movi.n a12, 1 */
  a11 = a14 + a11; /* 01be: add a11, a14, a11 */
  a15 = MEM32(a6 + 436); /* 01c1: l32i a15, a6, 0x1b4 */
  if (a11 < a14) goto L_1ca; /* 01c4: bltu a11, a14, 1ca <pm_coex_separate_connectionless_window+0x1a6> */
  a12 = 0x0; /* 01c7: movi a12, 0 */
L_1ca:;
  a2 = a2 + a15; /* 01ca: add.n a2, a2, a15 */
  a5 = a11 - a5; /* 01cc: sub a5, a11, a5 */
  a2 = a12 + a2; /* 01cf: add.n a2, a12, a2 */
  a12 = 0x1; /* 01d1: movi.n a12, 1 */
  if (a11 < a5) goto L_1d8; /* 01d3: bltu a11, a5, 1d8 <pm_coex_separate_connectionless_window+0x1b4> */
  a12 = 0x0; /* 01d6: movi.n a12, 0 */
L_1d8:;
  a2 = a2 - a13; /* 01d8: sub a2, a2, a13 */
  a2 = a2 - a12; /* 01db: sub a2, a2, a12 */
  /* 01de: bgez a2, 1e9 <pm_coex_separate_connectionless_window+0x1c5> */ /* UNMODELED branch */
  a5 = 0x0; /* 01e1: movi.n a5, 0 */
  a2 = 0x0; /* 01e3: mov.n a2, a5 */
  goto L_1ec; /* 01e5: j 1ec <pm_coex_separate_connectionless_window+0x1c8> */
  /* 01e8: .byte 00 */
L_1e9:;
  if (a9 < a2) goto L_1f2; /* 01e9: bltu a9, a2, 1f2 <pm_coex_separate_connectionless_window+0x1ce> */
L_1ec:;
  if (a2 != a9) goto L_205; /* 01ec: bne a2, a9, 205 <pm_coex_separate_connectionless_window+0x1e1> */
  if (a10 >= a5) goto L_205; /* 01ef: bgeu a10, a5, 205 <pm_coex_separate_connectionless_window+0x1e1> */
L_1f2:;
  a2 = MEM32(a3 + 0); /* 01f2: l32i.n a2, a3, 0 */
  a12 = a7; /* 01f4: mov.n a12, a7 */
  a11 = 0x0; /* 01f6: movi.n a11, 0 */
  a10 = 0x26; /* 01f8: movi.n a10, 38 */
  a2 = MEM32(a2 + 412); /* 01fa: l32i a2, a2, 0x19c */
L_1fd:;
  ((int32_t(*)())a2)(a2, a3, a4, a5); /* 01fd: callx8 a2 */ /* indirect */
  goto L_26d; /* 0200: j 26d <pm_coex_separate_connectionless_window+0x249> */
  /* 0203: .byte 00 */
  /* 0204: .byte 00 */
L_205:;
  a12 = a10 - a5; /* 0205: sub a12, a10, a5 */
  a13 = 0x1; /* 0208: movi.n a13, 1 */
  if (a10 < a12) goto L_210; /* 020a: bltu a10, a12, 210 <pm_coex_separate_connectionless_window+0x1ec> */
  a13 = 0x0; /* 020d: movi a13, 0 */
L_210:;
  a11 = a9 - a2; /* 0210: sub a11, a9, a2 */
  a11 = a11 - a13; /* 0213: sub a11, a11, a13 */
  a11 = a11 + a11; /* 0216: add.n a11, a11, a11 */
  a13 = (a12 >> 31) & 0x1; /* 0218: extui a13, a12, 31, 1 */
  a11 = a13 | a11; /* 021b: or a11, a13, a11 */
  a12 = a12 + a12; /* 021e: add a12, a12, a12 */
  if (a11 < a8) goto L_230; /* 0221: bltu a11, a8, 230 <pm_coex_separate_connectionless_window+0x20c> */
  if (a8 == a11) goto L_22a; /* 0224: beq a8, a11, 22a <pm_coex_separate_connectionless_window+0x206> */
  goto L_2b5; /* 0227: j 2b5 <pm_coex_separate_connectionless_window+0x291> */
L_22a:;
  if (a12 < a7) goto L_230; /* 022a: bltu a12, a7, 230 <pm_coex_separate_connectionless_window+0x20c> */
  goto L_2b5; /* 022d: j 2b5 <pm_coex_separate_connectionless_window+0x291> */
L_230:;
  a5 = a7 + a5; /* 0230: add.n a5, a7, a5 */
  a11 = 0x1; /* 0232: movi.n a11, 1 */
  if (a5 < a7) goto L_23a; /* 0234: bltu a5, a7, 23a <pm_coex_separate_connectionless_window+0x216> */
  a11 = 0x0; /* 0237: movi a11, 0 */
L_23a:;
  a2 = a8 + a2; /* 023a: add.n a2, a8, a2 */
  a10 = a5 - a10; /* 023c: sub a10, a5, a10 */
  a2 = a11 + a2; /* 023f: add.n a2, a11, a2 */
  a8 = 0x1; /* 0241: movi.n a8, 1 */
  if (a5 < a10) goto L_249; /* 0243: bltu a5, a10, 249 <pm_coex_separate_connectionless_window+0x225> */
  a8 = 0x0; /* 0246: movi a8, 0 */
L_249:;
  a2 = a2 - a9; /* 0249: sub a2, a2, a9 */
  a8 = a2 - a8; /* 024c: sub a8, a2, a8 */
  a2 = MEM32(a3 + 0); /* 024f: l32i.n a2, a3, 0 */
  a7 = a10; /* 0251: mov.n a7, a10 */
  a12 = a10; /* 0253: mov.n a12, a10 */
  a11 = 0x0; /* 0255: movi.n a11, 0 */
  a10 = 0x26; /* 0257: movi.n a10, 38 */
  a2 = MEM32(a2 + 412); /* 0259: l32i a2, a2, 0x19c */
L_25c:;
  MEM32(a1 + 12) = a8; /* 025c: s32i a8, a1, 12 */
  MEMW(); /* 025f: memw  */
  ((int32_t(*)())a2)(a2, a3, a4, a5); /* 0262: callx8 a2 */ /* indirect */
  a8 = MEM32(a1 + 12); /* 0265: l32i.n a8, a1, 12 */
  a8 = a7 | a8; /* 0267: or a8, a7, a8 */
  if (a8 == 0) goto L_2b5; /* 026a: beqz a8, 2b5 <pm_coex_separate_connectionless_window+0x291> */
L_26d:;
  a2 = MEM8(a4 + 136); /* 026d: l8ui a2, a4, 136 */
  if (a2 != 0) goto L_28d; /* 0270: bnez.n a2, 28d <pm_coex_separate_connectionless_window+0x269> */
  a8 = (uint32_t)&pm_wake_up; /* 0272: l32r a8, 14 <pm_coex_separate_connectionless_window-0x10> (0 <pm_coex_separate_connectionless_window-0x24>) */ /* literal: GOT slot for pm_wake_up */
  pm_wake_up(a2, a3, a4, a5); /* call via literal slot */ /* 0275: callx8 a8 */
  a5 = 0x1; /* 0278: movi.n a5, 1 */
  a11 = a2; /* 027a: mov.n a11, a2 */
  a10 = 0x11; /* 027c: movi.n a10, 17 */
  MEM8(a4 + 136) = a5; /* 027e: s8i a5, a4, 136 */
  MEMW(); /* 0281: memw  */
  MEMW(); /* 0284: memw  */
  a8 = (uint32_t)&wifi_gpio_debug; /* 0287: l32r a8, 18 <pm_coex_separate_connectionless_window-0xc> (0 <pm_coex_separate_connectionless_window-0x24>) */ /* literal: GOT slot for wifi_gpio_debug */
  wifi_gpio_debug(a2, a3, a4, a5); /* call via literal slot */ /* 028a: callx8 a8 */
L_28d:;
  a2 = MEM16(a6 + 394); /* 028d: l16ui a2, a6, 0x18a */
  if (a2 == 0) goto L_2a1; /* 0290: beqz.n a2, 2a1 <pm_coex_separate_connectionless_window+0x27d> */
  a12 = 0x0; /* 0292: movi.n a12, 0 */
  a11 = a7; /* 0294: mov.n a11, a7 */
  a2 = MEM32(a3 + 0); /* 0296: l32i.n a2, a3, 0 */
  a10 = (uint32_t)&g_pm; /* 0298: l32r a10, 8 <pm_coex_separate_connectionless_window-0x1c> (0 <pm_coex_separate_connectionless_window-0x24>) */ /* literal @0x8: g_pm */
  a2 = MEM32(a2 + 248); /* 029b: l32i a2, a2, 248 */
  ((int32_t(*)())a2)(a2, a3, a4, a5); /* 029e: callx8 a2 */ /* indirect */
L_2a1:;
  a2 = MEM32(a3 + 0); /* 02a1: l32i.n a2, a3, 0 */
  a10 = MEM32(a2 + 272); /* 02a3: l32i a10, a2, 0x110 */
  g_pm(a2, a3, a4, a5); /* call via literal slot */ /* 02a6: callx8 a10 */
  MEM32(a6 + 416) = a10; /* 02a9: s32i a10, a6, 0x1a0 */
  MEM32(a6 + 420) = a11; /* 02ac: s32i a11, a6, 0x1a4 */
  MEMW(); /* 02af: memw  */
  goto L_2d6; /* 02b2: j 2d6 <pm_coex_separate_connectionless_window+0x2b2> */
L_2b5:;
  a2 = MEM8(a4 + 136); /* 02b5: l8ui a2, a4, 136 */
  if (a2 == 0) goto L_2d6; /* 02b8: beqz.n a2, 2d6 <pm_coex_separate_connectionless_window+0x2b2> */
  a2 = 0x0; /* 02ba: movi.n a2, 0 */
  a11 = 0x1; /* 02bc: movi a11, 1 */
  a10 = 0x11; /* 02bf: movi.n a10, 17 */
  MEM8(a4 + 136) = a2; /* 02c1: s8i a2, a4, 136 */
  MEMW(); /* 02c4: memw  */
  MEMW(); /* 02c7: memw  */
  a8 = (uint32_t)&wifi_gpio_debug; /* 02ca: l32r a8, 1c <pm_coex_separate_connectionless_window-0x8> (0 <pm_coex_separate_connectionless_window-0x24>) */ /* literal: GOT slot for wifi_gpio_debug */
  wifi_gpio_debug(a2, a3, a4, a5); /* call via literal slot */ /* 02cd: callx8 a8 */
  a8 = (uint32_t)&pm_wake_done; /* 02d0: l32r a8, 20 <pm_coex_separate_connectionless_window-0x4> (0 <pm_coex_separate_connectionless_window-0x24>) */ /* literal: GOT slot for pm_wake_done */
  pm_wake_done(a2, a3, a4, a5); /* call via literal slot */ /* 02d3: callx8 a8 */
L_2d6:;
  return (int32_t)a2; /* 02d6: retw.n  */
}

/* pm_update_by_connectionless_status @ pm.o 00000034 size 318B bind GLOBAL
 * Calls: wifi_gpio_debug[got], pm_wake_done[got], pm_get_connectionless_status[got], wifi_event_post[got], wifi_event_post[got], wifi_gpio_debug[got], pm_coex_separate_connectionless_window[got], pm_wake_up[got], wifi_gpio_debug[got], g_osi_funcs_p[got] | Data refs: g_osi_funcs_p, g_pm, wifi_gpio_debug, pm_wake_done, pm_get_connectionless_status, wifi_event_post, pm_coex_separate_connectionless_window, pm_wake_up
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 10 call(s), 8 data ref(s)
 * Fidelity: low - 116 instr, 11 branches, 4 indirect; call-sequence + MMIO skeleton */
int32_t pm_update_by_connectionless_status(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .wifislpiram.21; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_34:;
  /* 0034: entry a1, 32 */
  a3 = (uint32_t)&g_osi_funcs_p; /* 0037: l32r a3, 8 <pm_update_by_connectionless_status-0x2c> (0 <pm_update_by_connectionless_status-0x34>) */ /* literal @0x8: g_osi_funcs_p */
  a6 = 0x0; /* 003a: movi.n a6, 0 */
  a2 = MEM32(a3 + 0); /* 003c: l32i.n a2, a3, 0 */
  a7 = (uint32_t)&g_pm; /* 003e: l32r a7, 4 <pm_update_by_connectionless_status-0x30> (0 <pm_update_by_connectionless_status-0x34>) */ /* literal @0x4: g_pm */
  a10 = a7; /* 0041: mov.n a10, a7 */
  a2 = MEM32(a2 + 236); /* 0043: l32i a2, a2, 236 */
  ((int32_t(*)())a2)(a2, a3, a4, a5); /* 0046: callx8 a2 */ /* indirect */
  a2 = MEM32(a3 + 0); /* 0049: l32i a2, a3, 0 */
  a5 = (uint32_t)&g_pm; /* 004c: l32r a5, c <pm_update_by_connectionless_status-0x28> (0 <pm_update_by_connectionless_status-0x34>) */ /* literal @0xC: g_pm */
  a10 = a5 | a5; /* 004f: or a10, a5, a5 */
  a2 = MEM32(a2 + 236); /* 0052: l32i a2, a2, 236 */
  ((int32_t(*)())a2)(a2, a3, a4, a5); /* 0055: callx8 a2 */ /* indirect */
  a2 = (uint32_t)&g_pm; /* 0058: l32r a2, 10 <pm_update_by_connectionless_status-0x24> (0 <pm_update_by_connectionless_status-0x34>) */ /* literal @0x10: g_pm */
  a4 = a2 + ((0x100) << 8); /* 005b: addmi a4, a2, 0x100 */
  a8 = MEM8(a4 + 136); /* 005e: l8ui a8, a4, 136 */
  MEM8(a4 + 140) = a6; /* 0061: s8i a6, a4, 140 */
  MEMW(); /* 0064: memw  */
  if (a8 == 0) goto L_82; /* 0067: beqz.n a8, 82 <pm_update_by_connectionless_status+0x4e> */
  a11 = 0x1; /* 0069: movi.n a11, 1 */
  a10 = 0x11; /* 006b: movi.n a10, 17 */
  MEM8(a4 + 136) = a6; /* 006d: s8i a6, a4, 136 */
  MEMW(); /* 0070: memw  */
  MEMW(); /* 0073: memw  */
  a8 = (uint32_t)&wifi_gpio_debug; /* 0076: l32r a8, 14 <pm_update_by_connectionless_status-0x20> (0 <pm_update_by_connectionless_status-0x34>) */ /* literal: GOT slot for wifi_gpio_debug */
  wifi_gpio_debug(a2, a3, a4, a5); /* call via literal slot */ /* 0079: callx8 a8 */
  a8 = (uint32_t)&pm_wake_done; /* 007c: l32r a8, 18 <pm_update_by_connectionless_status-0x1c> (0 <pm_update_by_connectionless_status-0x34>) */ /* literal: GOT slot for pm_wake_done */
  pm_wake_done(a2, a3, a4, a5); /* call via literal slot */ /* 007f: callx8 a8 */
L_82:;
  a6 = MEM8(a4 + 29); /* 0082: l8ui a6, a4, 29 */
  if (a6 >= 2) goto L_8e; /* 0085: bgeui a6, 2, 8e <pm_update_by_connectionless_status+0x5a> */
  a6 = MEM8(a2 + 13); /* 0088: l8ui a6, a2, 13 */
  if (a6 == 0) goto L_170; /* 008b: beqz a6, 170 <pm_update_by_connectionless_status+0x13c> */
L_8e:;
  a8 = (uint32_t)&pm_get_connectionless_status; /* 008e: l32r a8, 1c <pm_update_by_connectionless_status-0x18> (0 <pm_update_by_connectionless_status-0x34>) */ /* literal: GOT slot for pm_get_connectionless_status */
  pm_get_connectionless_status(a2, a3, a4, a5); /* call via literal slot */ /* 0091: callx8 a8 */
  a6 = 0x11; /* 0094: mov.n a6, a10 */
  a8 = MEM16(a2 + 394); /* 0096: l16ui a8, a2, 0x18a */
  if (a8 == 0) goto L_ea; /* 0099: beqz a8, ea <pm_update_by_connectionless_status+0xb6> */
  a12 = 0x0; /* 009c: movi.n a12, 0 */
  a11 = 0x0; /* 009e: mov.n a11, a12 */
  a10 = 0x16; /* 00a0: movi a10, 22 */
  a8 = (uint32_t)&wifi_event_post; /* 00a3: l32r a8, 20 <pm_update_by_connectionless_status-0x14> (0 <pm_update_by_connectionless_status-0x34>) */ /* literal: GOT slot for wifi_event_post */
  wifi_event_post(a2, a3, a4, a5); /* call via literal slot */ /* 00a6: callx8 a8 */
  a8 = MEM16(a2 + 394); /* 00a9: l16ui a8, a2, 0x18a */
  a12 = 0x0; /* 00ac: movi.n a12, 0 */
  a11 = a8 << (5 & 31); /* 00ae: slli a11, a8, 5 */
  a11 = a11 - a8; /* 00b1: sub a11, a11, a8 */
  a11 = (a11 << 4) + a8; /* 00b4: addx4 a11, a11, a8 */
  a8 = MEM32(a3 + 0); /* 00b7: l32i a8, a3, 0 */
  a10 = a7 | a7; /* 00ba: or a10, a7, a7 */
  a11 = a11 << (3 & 31); /* 00bd: slli a11, a11, 3 */
  a8 = MEM32(a8 + 248); /* 00c0: l32i a8, a8, 248 */
  wifi_event_post(a2, a3, a4, a5); /* call via literal slot */ /* 00c3: callx8 a8 */
  a7 = MEM32(a3 + 0); /* 00c6: l32i.n a7, a3, 0 */
  a10 = MEM32(a7 + 272); /* 00c8: l32i a10, a7, 0x110 */
  a7 = 0x1; /* 00cb: movi a7, 1 */
  ((int32_t(*)())a10)(a2, a3, a4, a5); /* 00ce: callx8 a10 */ /* indirect */
  MEM32(a2 + 408) = a10; /* 00d1: s32i a10, a2, 0x198 */
  a10 = 0x10; /* 00d4: movi.n a10, 16 */
  MEM32(a2 + 412) = a11; /* 00d6: s32i a11, a2, 0x19c */
  a11 = 0x2; /* 00d9: movi.n a11, 2 */
  MEMW(); /* 00db: memw  */
  a8 = (uint32_t)&wifi_gpio_debug; /* 00de: l32r a8, 24 <pm_update_by_connectionless_status-0x10> (0 <pm_update_by_connectionless_status-0x34>) */ /* literal: GOT slot for wifi_gpio_debug */
  wifi_gpio_debug(a2, a3, a4, a5); /* call via literal slot */ /* 00e1: callx8 a8 */
  MEM8(a4 + 140) = a7; /* 00e4: s8i a7, a4, 140 */
  MEMW(); /* 00e7: memw  */
L_ea:;
  a9 = 0xFFFFFFFE; /* 00ea: movi.n a9, -2 */
  a7 = 0x0; /* 00ec: movi.n a7, 0 */
  a8 = 0xFFFF; /* 00ee: l32r a8, 0 <pm_update_by_connectionless_status-0x34> (ffff <pm_attach+0xff7b>) */ @0x0
  if (a6 == a9) goto L_114; /* 00f1: beq a6, a9, 114 <pm_update_by_connectionless_status+0xe0> */
  a7 = (a6 >> 0) & 0xFFFF; /* 00f4: extui a7, a6, 0, 16 */
  if (a6 != -1) goto L_105; /* 00f7: bnei a6, -1, 105 <pm_update_by_connectionless_status+0xd1> */
  a7 = MEM16(a2 + 394); /* 00fa: l16ui a7, a2, 0x18a */
  MEMW(); /* 00fd: memw  */
  goto L_105; /* 0100: j 105 <pm_update_by_connectionless_status+0xd1> */
  /* 0103: .byte 00 */
  /* 0104: .byte 00 */
L_105:;
  a8 = a7 << (5 & 31); /* 0105: slli a8, a7, 5 */
  a8 = a8 - a7; /* 0108: sub a8, a8, a7 */
  a8 = (a8 << 4) + a7; /* 010b: addx4 a8, a8, a7 */
  a8 = a8 << (3 & 31); /* 010e: slli a8, a8, 3 */
  a7 = (int32_t)a8 >> (31 & 31); /* 0111: srai a7, a8, 31 */
L_114:;
  MEM32(a2 + 424) = a8; /* 0114: s32i a8, a2, 0x1a8 */
  MEM32(a2 + 428) = a7; /* 0117: s32i a7, a2, 0x1ac */
  a2 = MEM32(a3 + 0); /* 011a: l32i a2, a3, 0 */
  a10 = MEM32(a2 + 404); /* 011d: l32i a10, a2, 0x194 */
  MEMW(); /* 0120: memw  */
  ((int32_t(*)())a10)(a2, a3, a4, a5); /* 0123: callx8 a10 */ /* indirect */
  a2 = a10; /* 0126: mov.n a2, a10 */
  if (a10 == 0) goto L_134; /* 0128: beqz.n a10, 134 <pm_update_by_connectionless_status+0x100> */
  a8 = (uint32_t)&pm_coex_separate_connectionless_window; /* 012a: l32r a8, 28 <pm_update_by_connectionless_status-0xc> (0 <pm_update_by_connectionless_status-0x34>) */ /* literal: GOT slot for pm_coex_separate_connectionless_window */
  pm_coex_separate_connectionless_window(a2, a3, a4, a5); /* call via literal slot */ /* 012d: callx8 a8 */
  goto L_170; /* 0130: j 170 <pm_update_by_connectionless_status+0x13c> */
  /* 0133: .byte 00 */
L_134:;
  if (a6 == 0) goto L_170; /* 0134: beqz.n a6, 170 <pm_update_by_connectionless_status+0x13c> */
  a8 = (uint32_t)&pm_wake_up; /* 0136: l32r a8, 2c <pm_update_by_connectionless_status-0x8> (0 <pm_update_by_connectionless_status-0x34>) */ /* literal: GOT slot for pm_wake_up */
  pm_wake_up(a2, a3, a4, a5); /* call via literal slot */ /* 0139: callx8 a8 */
  a7 = 0x1; /* 013c: movi.n a7, 1 */
  a11 = a2; /* 013e: mov.n a11, a2 */
  a10 = 0x11; /* 0140: movi.n a10, 17 */
  MEM8(a4 + 136) = a7; /* 0142: s8i a7, a4, 136 */
  MEMW(); /* 0145: memw  */
  MEMW(); /* 0148: memw  */
  a8 = (uint32_t)&wifi_gpio_debug; /* 014b: l32r a8, 30 <pm_update_by_connectionless_status-0x4> (0 <pm_update_by_connectionless_status-0x34>) */ /* literal: GOT slot for wifi_gpio_debug */
  wifi_gpio_debug(a2, a3, a4, a5); /* call via literal slot */ /* 014e: callx8 a8 */
  if (a6 < 1) goto L_170; /* 0151: blti a6, 1, 170 <pm_update_by_connectionless_status+0x13c> */
  a6 = (a6 >> 0) & 0xFFFF; /* 0154: extui a6, a6, 0, 16 */
  a11 = a6 << (5 & 31); /* 0157: slli a11, a6, 5 */
  a3 = MEM32(a3 + 0); /* 015a: l32i.n a3, a3, 0 */
  a11 = a11 - a6; /* 015c: sub a11, a11, a6 */
  a11 = (a11 << 4) + a6; /* 015f: addx4 a11, a11, a6 */
  a12 = a2; /* 0162: mov.n a12, a2 */
  a11 = a11 << (3 & 31); /* 0164: slli a11, a11, 3 */
  a3 = MEM32(a3 + 248); /* 0167: l32i a3, a3, 248 */
  a10 = a5 | a5; /* 016a: or a10, a5, a5 */
  g_osi_funcs_p(a2, a3, a4, a5); /* call via literal slot */ /* 016d: callx8 a3 */
L_170:;
  return (int32_t)a2; /* 0170: retw.n  */
}

/* pm_check_state @ pm.o 00000010 size 66B bind GLOBAL
 * Calls: pm_dream[got], .text.pm_set_state[got] | Data refs: g_pm, g_osi_funcs_p, pm_dream, .text.pm_set_state
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 2 call(s), 4 data ref(s)
 * Fidelity: medium - 24 instr, 6 branches, calls resolved */
int32_t pm_check_state(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .wifislprxiram.34; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_10:;
  /* 0010: entry a1, 32 */
  a3 = (uint32_t)&g_pm; /* 0013: l32r a3, 0 <pm_check_state-0x10> (0 <pm_check_state-0x10>) */ /* literal @0x0: g_pm */
  a2 = MEM32(a3 + 36); /* 0016: l32i a2, a3, 36 */
  if (a2 == 0) goto L_25; /* 0019: beqz a2, 25 <pm_check_state+0x15> */
L_1c:;
  a2 = MEM8(a3 + 13); /* 001c: l8ui a2, a3, 13 */
  if (a2 != 0) goto L_50; /* 001f: bnez.n a2, 50 <pm_check_state+0x40> */
  goto L_3a; /* 0021: j 3a <pm_check_state+0x2a> */
  /* 0024: .byte 00 */
L_25:;
  a2 = (uint32_t)&g_osi_funcs_p; /* 0025: l32r a2, 4 <pm_check_state-0xc> (0 <pm_check_state-0x10>) */ /* literal @0x4: g_osi_funcs_p */
  a2 = MEM32(a2 + 0); /* 0028: l32i a2, a2, 0 */
  a10 = MEM32(a2 + 404); /* 002b: l32i a10, a2, 0x194 */
  ((int32_t(*)())a10)(a2, a3, a4, a5); /* 002e: callx8 a10 */ /* indirect */
  if (a10 != 0) goto L_1c; /* 0031: bnez a10, 1c <pm_check_state+0xc> */
  a2 = MEM8(a3 + 14); /* 0034: l8ui a2, a3, 14 */
  if (a2 == 0) goto L_1c; /* 0037: beqz a2, 1c <pm_check_state+0xc> */
L_3a:;
  a2 = 0x0; /* 003a: movi.n a2, 0 */
  a3 = MEM8(a3 + 1); /* 003c: l8ui a3, a3, 1 */
  if (a3 == a2) goto L_50; /* 003f: beq a3, a2, 50 <pm_check_state+0x40> */
  a8 = (uint32_t)&pm_dream; /* 0042: l32r a8, 8 <pm_check_state-0x8> (0 <pm_check_state-0x10>) */ /* literal: GOT slot for pm_dream */
  pm_dream(a2, a3, a4, a5); /* call via literal slot */ /* 0045: callx8 a8 */
  a10 = a2; /* 0048: mov.n a10, a2 */
  a8 = (uint32_t)&pm_set_state; /* 004a: l32r a8, c <pm_check_state-0x4> (c <pm_check_state-0x4>) */ /* literal: GOT slot for .text.pm_set_state */
  pm_set_state(a2, a3, a4, a5); /* call via literal slot */ /* 004d: callx8 a8 */
L_50:;
  return (int32_t)a2; /* 0050: retw.n  */
}

/* pm_go_to_sleep @ pm.o 00000028 size 95B bind GLOBAL
 * Calls: pm_check_state, pm_send_nullfunc, .text.pm_set_state[got], esp_mesh_quick_funcs[got] | Data refs: esp_mesh_quick_funcs, g_mesh_init_ps_type, g_mesh_is_root, g_mesh_is_started, g_pm, pm_check_state, pm_send_nullfunc, .text.pm_set_state
 *   MMIO: none
 *   funcdb v3: 2 call(s), 7 ref(s); disasm: 4 call(s), 8 data ref(s)
 * Fidelity: medium - 35 instr, 7 branches, calls resolved */
int32_t pm_go_to_sleep(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pm_go_to_sleep; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_28:;
  /* 0028: entry a1, 32 */
  a8 = (uint32_t)&pm_check_state; /* 002b: l32r a8, 1c <pm_go_to_sleep-0xc> (0 <pm_go_to_sleep-0x28>) */ /* literal: GOT slot for pm_check_state */
  pm_check_state(a2, a3, a4, a5); /* call via literal slot */ /* 002e: callx8 a8 */
  if (a10 == 0) goto L_85; /* 0031: beqz a10, 85 <pm_go_to_sleep+0x5d> */
  a2 = (uint32_t)&g_pm; /* 0034: l32r a2, 0 <pm_go_to_sleep-0x28> (0 <pm_go_to_sleep-0x28>) */ /* literal @0x0: g_pm */
  a8 = MEM8(a2 + 1); /* 0037: l8ui a8, a2, 1 */
  if (a8 == 2) goto L_85; /* 003a: beqi a8, 2, 85 <pm_go_to_sleep+0x5d> */
  a10 = 0x1; /* 003d: movi.n a10, 1 */
  a8 = (uint32_t)&pm_set_state; /* 003f: l32r a8, 20 <pm_go_to_sleep-0x8> (c <pm_go_to_sleep-0x1c>) */ /* literal: GOT slot for .text.pm_set_state */
  pm_set_state(a2, a3, a4, a5); /* call via literal slot */ /* 0042: callx8 a8 */
  a8 = (uint32_t)&g_mesh_is_started; /* 0045: l32r a8, 4 <pm_go_to_sleep-0x24> (0 <pm_go_to_sleep-0x28>) */ /* literal @0x4: g_mesh_is_started */
  a8 = MEM8(a8 + 0); /* 0048: l8ui a8, a8, 0 */
  if (a8 == 0) goto L_78; /* 004b: beqz.n a8, 78 <pm_go_to_sleep+0x50> */
  a8 = (uint32_t)&g_mesh_is_root; /* 004d: l32r a8, 8 <pm_go_to_sleep-0x20> (0 <pm_go_to_sleep-0x28>) */ /* literal @0x8: g_mesh_is_root */
  MEMW(); /* 0050: memw  */
  a8 = MEM8(a8 + 0); /* 0053: l8ui a8, a8, 0 */
  a8 = (a8 >> 0) & 0xFF; /* 0056: extui a8, a8, 0, 8 */
  if (a8 != 0) goto L_78; /* 0059: bnez.n a8, 78 <pm_go_to_sleep+0x50> */
  a8 = (uint32_t)&g_mesh_init_ps_type; /* 005b: l32r a8, c <pm_go_to_sleep-0x1c> (0 <pm_go_to_sleep-0x28>) */ /* literal @0xC: g_mesh_init_ps_type */
  a8 = MEM32(a8 + 0); /* 005e: l32i.n a8, a8, 0 */
  if (a8 == 0) goto L_78; /* 0060: beqz.n a8, 78 <pm_go_to_sleep+0x50> */
  a10 = 0x1; /* 0062: movi a10, 1 */
  a2 = (uint32_t)&esp_mesh_quick_funcs; /* 0065: l32r a2, 18 <pm_go_to_sleep-0x10> (0 <pm_go_to_sleep-0x28>) */ /* literal @0x18: esp_mesh_quick_funcs */
  a12 = (uint32_t)&g_pm; /* 0068: l32r a12, 10 <pm_go_to_sleep-0x18> (0 <pm_go_to_sleep-0x28>) */ /* literal @0x10: g_pm */
  a2 = MEM32(a2 + 136); /* 006b: l32i a2, a2, 136 */
  a11 = (uint32_t)&g_pm; /* 006e: l32r a11, 14 <pm_go_to_sleep-0x14> (0 <pm_go_to_sleep-0x28>) */ /* literal @0x14: g_pm */
  esp_mesh_quick_funcs(a2, a3, a4, a5); /* call via literal slot */ /* 0071: callx8 a2 */
  goto L_85; /* 0074: j 85 <pm_go_to_sleep+0x5d> */
  /* 0077: .byte 00 */
L_78:;
  a2 = MEM8(a2 + 20); /* 0078: l8ui a2, a2, 20 */
  if (a2 != 0) goto L_85; /* 007b: bnez.n a2, 85 <pm_go_to_sleep+0x5d> */
  a10 = 0x1; /* 007d: movi.n a10, 1 */
  a8 = (uint32_t)&pm_send_nullfunc; /* 007f: l32r a8, 24 <pm_go_to_sleep-0x4> (0 <pm_go_to_sleep-0x28>) */ /* literal: GOT slot for pm_send_nullfunc */
  pm_send_nullfunc(a2, a3, a4, a5); /* call via literal slot */ /* 0082: callx8 a8 */
L_85:;
  return (int32_t)a2; /* 0085: retw.n  */
}

/* pm_set_next_tbtt @ pm.o 00000024 size 558B bind GLOBAL
 * Calls: __udivdi3, pm_coex_schm_overall_period_get, wifi_log, g_pm[got], g_osi_funcs_p[got] | Data refs: .rodata_wlog_warning.35, __udivdi3, g_intr_lock_mux, g_osi_funcs_p, g_pm, pm_coex_schm_overall_period_get, wifi_log
 *   MMIO: none
 *   funcdb v3: 3 call(s), 7 ref(s); disasm: 5 call(s), 7 data ref(s)
 * Fidelity: low - 219 instr, 35 branches, 7 indirect; call-sequence + MMIO skeleton */
int32_t pm_set_next_tbtt(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pm_set_next_tbtt; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_24:;
  /* 0024: entry a1, 96 */
  a4 = (uint32_t)&g_osi_funcs_p; /* 0027: l32r a4, 0 <pm_set_next_tbtt-0x24> (0 <pm_set_next_tbtt-0x24>) */ /* literal @0x0: g_osi_funcs_p */
  a2 = MEM32(a4 + 0); /* 002a: l32i.n a2, a4, 0 */
  a10 = MEM32(a2 + 272); /* 002c: l32i a10, a2, 0x110 */
  a2 = 0x1; /* 002f: movi a2, 1 */
  ((int32_t(*)())a10)(a2, a3, a4, a5); /* 0032: callx8 a10 */ /* indirect */
  a6 = (uint32_t)&g_pm; /* 0035: l32r a6, 4 <pm_set_next_tbtt-0x20> (0 <pm_set_next_tbtt-0x24>) */ /* literal @0x4: g_pm */
  a3 = MEM32(a6 + 40); /* 0038: l32i.n a3, a6, 40 */
  a10 = a3 + a10; /* 003a: add.n a10, a3, a10 */
  if (a10 < a3) goto L_41; /* 003c: bltu a10, a3, 41 <pm_set_next_tbtt+0x1d> */
  a2 = 0x0; /* 003f: movi.n a2, 0 */
L_41:;
  a3 = MEM32(a6 + 92); /* 0041: l32i a3, a6, 92 */
  a2 = a2 + a11; /* 0044: add a2, a2, a11 */
  if (a2 >= a3) goto L_4d; /* 0047: bgeu a2, a3, 4d <pm_set_next_tbtt+0x29> */
  goto L_250; /* 004a: j 250 <pm_set_next_tbtt+0x22c> */
L_4d:;
  if (a3 != a2) goto L_59; /* 004d: bne a3, a2, 59 <pm_set_next_tbtt+0x35> */
  a2 = MEM32(a6 + 88); /* 0050: l32i a2, a6, 88 */
  if (a10 >= a2) goto L_59; /* 0053: bgeu a10, a2, 59 <pm_set_next_tbtt+0x35> */
  goto L_250; /* 0056: j 250 <pm_set_next_tbtt+0x22c> */
L_59:;
  a2 = MEM32(a4 + 0); /* 0059: l32i.n a2, a4, 0 */
  a10 = MEM32(a2 + 272); /* 005b: l32i a10, a2, 0x110 */
  ((int32_t(*)())a10)(a2, a3, a4, a5); /* 005e: callx8 a10 */ /* indirect */
  a2 = MEM32(a4 + 0); /* 0061: l32i.n a2, a4, 0 */
  MEM32(a1 + 32) = a10; /* 0063: s32i.n a10, a1, 32 */
  a10 = MEM32(a2 + 404); /* 0065: l32i a10, a2, 0x194 */
  MEM32(a1 + 36) = a11; /* 0068: s32i.n a11, a1, 36 */
  MEMW(); /* 006a: memw  */
  ((int32_t(*)())a10)(a2, a3, a4, a5); /* 006d: callx8 a10 */ /* indirect */
  if (a10 == 0) goto L_aa; /* 0070: beqz.n a10, aa <pm_set_next_tbtt+0x86> */
  a5 = MEM8(a6 + 14); /* 0072: l8ui a5, a6, 14 */
  if (a5 == 0) goto L_94; /* 0075: beqz.n a5, 94 <pm_set_next_tbtt+0x70> */
  a8 = (uint32_t)&pm_coex_schm_overall_period_get; /* 0077: l32r a8, 18 <pm_set_next_tbtt-0xc> (0 <pm_set_next_tbtt-0x24>) */ /* literal: GOT slot for pm_coex_schm_overall_period_get */
  pm_coex_schm_overall_period_get(a2, a3, a4, a5); /* call via literal slot */ /* 007a: callx8 a8 */
  a3 = 0x1; /* 007d: movi.n a3, 1 */
  a2 = MEM32(a6 + 44); /* 007f: l32i.n a2, a6, 44 */
  a10 = (uint32_t)((uint64_t)a10 * a2); /* 0081: mull a10, a10, a2 */
  a2 = MEM32(a6 + 88); /* 0084: l32i a2, a6, 88 */
  a2 = a10 + a2; /* 0087: add.n a2, a10, a2 */
  a5 = MEM32(a6 + 92); /* 0089: l32i a5, a6, 92 */
  if (a2 < a10) goto L_f6; /* 008c: bltu a2, a10, f6 <pm_set_next_tbtt+0xd2> */
  a3 = 0x0; /* 008f: movi.n a3, 0 */
  goto L_f6; /* 0091: j f6 <pm_set_next_tbtt+0xd2> */
L_94:;
  a7 = MEM32(a6 + 44); /* 0094: l32i.n a7, a6, 44 */
  a3 = 0x1; /* 0096: movi.n a3, 1 */
  a2 = MEM32(a6 + 88); /* 0098: l32i a2, a6, 88 */
  a2 = a7 + a2; /* 009b: add.n a2, a7, a2 */
  a8 = MEM32(a6 + 92); /* 009d: l32i a8, a6, 92 */
  if (a2 < a7) goto L_a5; /* 00a0: bltu a2, a7, a5 <pm_set_next_tbtt+0x81> */
  a3 = a5; /* 00a3: mov.n a3, a5 */
L_a5:;
  a3 = a3 + a8; /* 00a5: add.n a3, a3, a8 */
  goto L_f8; /* 00a7: j f8 <pm_set_next_tbtt+0xd4> */
L_aa:;
  a5 = MEM32(a6 + 36); /* 00aa: l32i.n a5, a6, 36 */
  a2 = MEM32(a6 + 88); /* 00ac: l32i a2, a6, 88 */
  a3 = MEM32(a6 + 92); /* 00af: l32i a3, a6, 92 */
  a8 = MEM32(a6 + 44); /* 00b2: l32i.n a8, a6, 44 */
  if (a5 != 0) goto L_c4; /* 00b4: bnez.n a5, c4 <pm_set_next_tbtt+0xa0> */
  a2 = a8 + a2; /* 00b6: add.n a2, a8, a2 */
  a7 = 0x1; /* 00b8: movi.n a7, 1 */
  if (a2 < a8) goto L_e8; /* 00ba: bltu a2, a8, e8 <pm_set_next_tbtt+0xc4> */
  a7 = a5; /* 00bd: mov.n a7, a5 */
  goto L_e8; /* 00bf: j e8 <pm_set_next_tbtt+0xc4> */
  /* 00c2: .byte 00 */
  /* 00c3: .byte 00 */
L_c4:;
  if (a5 != 1) goto L_d5; /* 00c4: bnei a5, 1, d5 <pm_set_next_tbtt+0xb1> */
  a7 = MEM8(a6 + 11); /* 00c7: l8ui a7, a6, 11 */
  a7 = (uint32_t)((uint64_t)a7 * a8); /* 00ca: mull a7, a7, a8 */
  a2 = a7 + a2; /* 00cd: add.n a2, a7, a2 */
  if (a2 < a7) goto L_f6; /* 00cf: bltu a2, a7, f6 <pm_set_next_tbtt+0xd2> */
  goto L_f4; /* 00d2: j f4 <pm_set_next_tbtt+0xd0> */
L_d5:;
  if (a5 != 2) goto L_ed; /* 00d5: bnei a5, 2, ed <pm_set_next_tbtt+0xc9> */
  a5 = MEM16(a6 + 32); /* 00d8: l16ui a5, a6, 32 */
  a7 = 0x1; /* 00db: movi.n a7, 1 */
  a5 = (uint32_t)((uint64_t)a5 * a8); /* 00dd: mull a5, a5, a8 */
  a2 = a5 + a2; /* 00e0: add.n a2, a5, a2 */
  if (a2 < a5) goto L_e8; /* 00e2: bltu a2, a5, e8 <pm_set_next_tbtt+0xc4> */
  a7 = a10 | a10; /* 00e5: or a7, a10, a10 */
L_e8:;
  a3 = a7 + a3; /* 00e8: add.n a3, a7, a3 */
  goto L_f8; /* 00ea: j f8 <pm_set_next_tbtt+0xd4> */
L_ed:;
  a2 = a8 + a2; /* 00ed: add.n a2, a8, a2 */
  a5 = 0x1; /* 00ef: movi.n a5, 1 */
  if (a2 < a8) goto L_f6; /* 00f1: bltu a2, a8, f6 <pm_set_next_tbtt+0xd2> */
L_f4:;
  a5 = a10; /* 00f4: mov.n a5, a10 */
L_f6:;
  a3 = a5 + a3; /* 00f6: add.n a3, a5, a3 */
L_f8:;
  MEM32(a6 + 88) = a2; /* 00f8: s32i a2, a6, 88 */
  MEM32(a6 + 92) = a3; /* 00fb: s32i a3, a6, 92 */
  a2 = MEM32(a4 + 0); /* 00fe: l32i.n a2, a4, 0 */
  a3 = (uint32_t)&g_intr_lock_mux; /* 0100: l32r a3, 8 <pm_set_next_tbtt-0x1c> (0 <pm_set_next_tbtt-0x24>) */ /* literal @0x8: g_intr_lock_mux */
  a2 = MEM32(a2 + 40); /* 0103: l32i.n a2, a2, 40 */
  a10 = MEM32(a3 + 0); /* 0105: l32i.n a10, a3, 0 */
  MEMW(); /* 0107: memw  */
  ((int32_t(*)())a2)(a2, a3, a4, a5); /* 010a: callx8 a2 */ /* indirect */
  a2 = MEM32(a4 + 0); /* 010d: l32i.n a2, a4, 0 */
  MEM32(a1 + 40) = a10; /* 010f: s32i.n a10, a1, 40 */
  a10 = MEM32(a2 + 272); /* 0111: l32i a10, a2, 0x110 */
  MEMW(); /* 0114: memw  */
  ((int32_t(*)())a10)(a2, a3, a4, a5); /* 0117: callx8 a10 */ /* indirect */
  a9 = a10; /* 011a: mov.n a9, a10 */
  a7 = a11; /* 011c: mov.n a7, a11 */
  a2 = MEM32(a6 + 88); /* 011e: l32i a2, a6, 88 */
  a11 = 0x1; /* 0121: movi a11, 1 */
  a10 = a2 - a10; /* 0124: sub a10, a2, a10 */
  a5 = MEM32(a6 + 92); /* 0127: l32i a5, a6, 92 */
  if (a2 < a10) goto L_130; /* 012a: bltu a2, a10, 130 <pm_set_next_tbtt+0x10c> */
  a11 = 0x0; /* 012d: movi a11, 0 */
L_130:;
  a12 = a5 - a7; /* 0130: sub a12, a5, a7 */
  a3 = a12 - a11; /* 0133: sub a3, a12, a11 */
  if (a12 != a11) goto L_162; /* 0136: bne a12, a11, 162 <pm_set_next_tbtt+0x13e> */
  a11 = 0x1387; /* 0139: l32r a11, c <pm_set_next_tbtt-0x18> (1387 <pm_attach+0x1303>) */ @0xC
  if (a11 < a10) goto L_15a; /* 013c: bltu a11, a10, 15a <pm_set_next_tbtt+0x136> */
  a10 = 0x1; /* 013f: movi.n a10, 1 */
  a11 = MEM32(a6 + 44); /* 0141: l32i.n a11, a6, 44 */
  a2 = a11 + a2; /* 0143: add.n a2, a11, a2 */
  if (a2 < a11) goto L_14a; /* 0145: bltu a2, a11, 14a <pm_set_next_tbtt+0x126> */
  a10 = a3; /* 0148: mov.n a10, a3 */
L_14a:;
  a10 = a10 + a5; /* 014a: add.n a10, a10, a5 */
  MEM32(a6 + 88) = a2; /* 014c: s32i a2, a6, 88 */
  a3 = 0x0; /* 014f: movi.n a3, 0 */
  MEM32(a6 + 92) = a10; /* 0151: s32i a10, a6, 92 */
  MEMW(); /* 0154: memw  */
  goto L_1d2; /* 0157: j 1d2 <pm_set_next_tbtt+0x1ae> */
L_15a:;
  a11 = 0xFFFFFFFF; /* 015a: movi.n a11, -1 */
  a11 = 0x80000000; /* 015c: slli a11, a11, 31 */
  if (a11 >= a10) goto L_1d2; /* 015f: bgeu a11, a10, 1d2 <pm_set_next_tbtt+0x1ae> */
L_162:;
  a3 = 0x271; /* 0162: movi a3, 0x271 */
  a3 = 0x1388; /* 0165: slli a3, a3, 3 */
  a12 = a3 - a2; /* 0168: sub a12, a3, a2 */
  a6 = MEM32(a6 + 44); /* 016b: l32i.n a6, a6, 44 */
  a10 = 0x1; /* 016d: movi.n a10, 1 */
  if (a3 < a12) goto L_175; /* 016f: bltu a3, a12, 175 <pm_set_next_tbtt+0x151> */
  a10 = 0x0; /* 0172: movi a10, 0 */
L_175:;
  a3 = -a5; /* 0175: neg a3, a5 */
  a3 = a3 - a10; /* 0178: sub a3, a3, a10 */
  a10 = a12 + a9; /* 017b: add.n a10, a12, a9 */
  a11 = 0x1; /* 017d: movi a11, 1 */
  if (a10 < a12) goto L_186; /* 0180: bltu a10, a12, 186 <pm_set_next_tbtt+0x162> */
  a11 = 0x0; /* 0183: movi a11, 0 */
L_186:;
  a3 = a3 + a7; /* 0186: add.n a3, a3, a7 */
  a12 = a6; /* 0188: mov.n a12, a6 */
  a13 = 0x0; /* 018a: movi.n a13, 0 */
  a11 = a11 + a3; /* 018c: add.n a11, a11, a3 */
  MEM32(a1 + 52) = a9; /* 018e: s32i a9, a1, 52 */
  MEMW(); /* 0191: memw  */
  a8 = (uint32_t)&udivdi3; /* 0194: l32r a8, 1c <pm_set_next_tbtt-0x8> (0 <pm_set_next_tbtt-0x24>) */ /* literal: GOT slot for __udivdi3 */
  udivdi3(a2, a3, a4, a5); /* call via literal slot */ /* 0197: callx8 a8 */
  a3 = a10; /* 019a: mov.n a3, a10 */
  a10 = a10 + (1); /* 019c: addi.n a10, a10, 1 */
  a13 = a11; /* 019e: mov.n a13, a11 */
  a14 = (uint32_t)&g_pm; /* 01a0: l32r a14, 4 <pm_set_next_tbtt-0x20> (0 <pm_set_next_tbtt-0x24>) */ /* literal @0x4: g_pm */
  a12 = 0x1; /* 01a3: movi.n a12, 1 */
  a9 = MEM32(a1 + 52); /* 01a5: l32i.n a9, a1, 52 */
  if (a10 < a3) goto L_1ac; /* 01a7: bltu a10, a3, 1ac <pm_set_next_tbtt+0x188> */
  a12 = 0x0; /* 01aa: movi.n a12, 0 */
L_1ac:;
  a12 = a12 + a11; /* 01ac: add.n a12, a12, a11 */
  a11 = (uint32_t)((uint64_t)a10 * a6); /* 01ae: mull a11, a10, a6 */
  a12 = (uint32_t)((uint64_t)a12 * a6); /* 01b1: mull a12, a12, a6 */
  a10 = (uint32_t)(((uint64_t)a10 * a6) >> 32) /* muluh: high word */; /* 01b4: muluh a10, a10, a6 */
  a2 = a11 + a2; /* 01b7: add.n a2, a11, a2 */
  a10 = a12 + a10; /* 01b9: add.n a10, a12, a10 */
  a6 = 0x1; /* 01bb: movi.n a6, 1 */
  if (a2 < a11) goto L_1c2; /* 01bd: bltu a2, a11, 1c2 <pm_set_next_tbtt+0x19e> */
  a6 = 0x0; /* 01c0: movi.n a6, 0 */
L_1c2:;
  a10 = a10 + a5; /* 01c2: add.n a10, a10, a5 */
  a6 = a6 + a10; /* 01c4: add.n a6, a6, a10 */
  MEM32(a14 + 88) = a2; /* 01c6: s32i a2, a14, 88 */
  MEM32(a14 + 92) = a6; /* 01c9: s32i a6, a14, 92 */
  MEMW(); /* 01cc: memw  */
  goto L_1d4; /* 01cf: j 1d4 <pm_set_next_tbtt+0x1b0> */
L_1d2:;
  a13 = a3; /* 01d2: mov.n a13, a3 */
L_1d4:;
  a2 = MEM32(a4 + 0); /* 01d4: l32i.n a2, a4, 0 */
  a5 = (uint32_t)&g_pm; /* 01d6: l32r a5, 10 <pm_set_next_tbtt-0x14> (0 <pm_set_next_tbtt-0x24>) */ /* literal @0x10: g_pm */
  a10 = a5; /* 01d9: mov.n a10, a5 */
  a2 = MEM32(a2 + 236); /* 01db: l32i a2, a2, 236 */
  MEM32(a1 + 52) = a9; /* 01de: s32i.n a9, a1, 52 */
  MEM32(a1 + 48) = a13; /* 01e0: s32i.n a13, a1, 48 */
  MEMW(); /* 01e2: memw  */
  ((int32_t(*)())a2)(a2, a3, a4, a5); /* 01e5: callx8 a2 */ /* indirect */
  a2 = (uint32_t)&g_pm; /* 01e8: l32r a2, 4 <pm_set_next_tbtt-0x20> (0 <pm_set_next_tbtt-0x24>) */ /* literal @0x4: g_pm */
  a10 = MEM32(a4 + 0); /* 01eb: l32i.n a10, a4, 0 */
  a14 = MEM32(a2 + 88); /* 01ed: l32i a14, a2, 88 */
  a6 = MEM32(a10 + 248); /* 01f0: l32i a6, a10, 248 */
  a10 = MEM32(a10 + 272); /* 01f3: l32i a10, a10, 0x110 */
  MEM32(a1 + 44) = a14; /* 01f6: s32i.n a14, a1, 44 */
  MEMW(); /* 01f8: memw  */
  ((int32_t(*)())a10)(a2, a3, a4, a5); /* 01fb: callx8 a10 */ /* indirect */
  a12 = 0x0; /* 01fe: movi.n a12, 0 */
  a14 = MEM32(a1 + 44); /* 0200: l32i.n a14, a1, 44 */
  a11 = a14 - a10; /* 0202: sub a11, a14, a10 */
  a10 = a5; /* 0205: mov.n a10, a5 */
  ((int32_t(*)())a6)(a2, a3, a4, a5); /* 0207: callx8 a6 */ /* indirect */
  a4 = MEM32(a4 + 0); /* 020a: l32i.n a4, a4, 0 */
  a5 = (uint32_t)&g_intr_lock_mux; /* 020c: l32r a5, 8 <pm_set_next_tbtt-0x1c> (0 <pm_set_next_tbtt-0x24>) */ /* literal @0x8: g_intr_lock_mux */
  a4 = MEM32(a4 + 44); /* 020f: l32i.n a4, a4, 44 */
  a11 = MEM32(a1 + 40); /* 0211: l32i.n a11, a1, 40 */
  a10 = MEM32(a5 + 0); /* 0213: l32i a10, a5, 0 */
  g_osi_funcs_p(a2, a3, a4, a5); /* call via literal slot */ /* 0216: callx8 a4 */
  a13 = MEM32(a1 + 48); /* 0219: l32i.n a13, a1, 48 */
  a9 = MEM32(a1 + 52); /* 021b: l32i.n a9, a1, 52 */
  if (a13 != 0) goto L_225; /* 021d: bnez.n a13, 225 <pm_set_next_tbtt+0x201> */
  a4 = 0x64; /* 021f: movi a4, 100 */
  if (a4 >= a3) goto L_250; /* 0222: bgeu a4, a3, 250 <pm_set_next_tbtt+0x22c> */
L_225:;
  a11 = 0x1; /* 0225: movi.n a11, 1 */
  a3 = MEM32(a2 + 44); /* 0227: l32i.n a3, a2, 44 */
  a12 = 0x2; /* 0229: movi.n a12, 2 */
  a11 = 0x1000; /* 022b: slli a11, a11, 12 */
  a10 = 0x6; /* 022e: movi.n a10, 6 */
  MEM32(a1 + 16) = a3; /* 0230: s32i.n a3, a1, 16 */
  a3 = MEM32(a2 + 92); /* 0232: l32i a3, a2, 92 */
  a2 = MEM32(a2 + 88); /* 0235: l32i a2, a2, 88 */
  a14 = MEM32(a1 + 32); /* 0238: l32i.n a14, a1, 32 */
  a15 = MEM32(a1 + 36); /* 023a: l32i.n a15, a1, 36 */
  a13 = (uint32_t)&lit_rodata_wlog_warning_35; /* 023c: l32r a13, 14 <pm_set_next_tbtt-0x10> (0 <pm_set_next_tbtt-0x24>) */ /* literal @0x14: .rodata_wlog_warning.35 */
  MEM32(a1 + 8) = a2; /* 023f: s32i.n a2, a1, 8 */
  MEM32(a1 + 12) = a3; /* 0241: s32i.n a3, a1, 12 */
  MEM32(a1 + 0) = a9; /* 0243: s32i.n a9, a1, 0 */
  MEM32(a1 + 4) = a7; /* 0245: s32i.n a7, a1, 4 */
  MEMW(); /* 0247: memw  */
  a8 = (uint32_t)&wifi_log; /* 024a: l32r a8, 20 <pm_set_next_tbtt-0x4> (0 <pm_set_next_tbtt-0x24>) */ /* literal: GOT slot for wifi_log */
  wifi_log(a2, a3, a4, a5); /* call via literal slot */ /* 024d: callx8 a8 */
L_250:;
  return (int32_t)a2; /* 0250: retw.n  */
}

/* pm_mesh_set_next_tbtt @ pm.o 0000001c size 106B bind GLOBAL
 * Calls: esp_mesh_quick_funcs[got], g_osi_funcs_p[got] | Data refs: esp_mesh_quick_funcs, g_mesh_init_ps_type, g_mesh_is_root, g_mesh_is_started, g_osi_funcs_p, g_pm
 *   MMIO: none
 *   funcdb v3: 0 call(s), 6 ref(s); disasm: 2 call(s), 6 data ref(s)
 * Fidelity: medium - 40 instr, 5 branches, calls resolved */
int32_t pm_mesh_set_next_tbtt(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pm_mesh_set_next_tbtt; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_1c:;
  /* 001c: entry a1, 48 */
  a2 = (uint32_t)&g_mesh_is_started; /* 001f: l32r a2, 0 <pm_mesh_set_next_tbtt-0x1c> (0 <pm_mesh_set_next_tbtt-0x1c>) */ /* literal @0x0: g_mesh_is_started */
  a2 = MEM8(a2 + 0); /* 0022: l8ui a2, a2, 0 */
  if (a2 == 0) goto L_84; /* 0025: beqz a2, 84 <pm_mesh_set_next_tbtt+0x68> */
  a3 = (uint32_t)&g_mesh_is_root; /* 0028: l32r a3, 4 <pm_mesh_set_next_tbtt-0x18> (0 <pm_mesh_set_next_tbtt-0x1c>) */ /* literal @0x4: g_mesh_is_root */
  MEMW(); /* 002b: memw  */
  a3 = MEM8(a3 + 0); /* 002e: l8ui a3, a3, 0 */
  a3 = (a3 >> 0) & 0xFF; /* 0031: extui a3, a3, 0, 8 */
  if (a3 != 0) goto L_7c; /* 0034: bnez a3, 7c <pm_mesh_set_next_tbtt+0x60> */
  a4 = (uint32_t)&g_mesh_init_ps_type; /* 0037: l32r a4, 8 <pm_mesh_set_next_tbtt-0x14> (0 <pm_mesh_set_next_tbtt-0x1c>) */ /* literal @0x8: g_mesh_init_ps_type */
  a8 = MEM32(a4 + 0); /* 003a: l32i.n a8, a4, 0 */
  if (a8 == 0) goto L_82; /* 003c: beqz a8, 82 <pm_mesh_set_next_tbtt+0x66> */
  a12 = a1; /* 003f: mov.n a12, a1 */
  a4 = (uint32_t)&g_pm; /* 0041: l32r a4, c <pm_mesh_set_next_tbtt-0x10> (0 <pm_mesh_set_next_tbtt-0x1c>) */ /* literal @0xC: g_pm */
  a5 = (uint32_t)&esp_mesh_quick_funcs; /* 0044: l32r a5, 10 <pm_mesh_set_next_tbtt-0xc> (0 <pm_mesh_set_next_tbtt-0x1c>) */ /* literal @0x10: esp_mesh_quick_funcs */
  a11 = MEM8(a4 + 11); /* 0047: l8ui a11, a4, 11 */
  a5 = MEM32(a5 + 120); /* 004a: l32i a5, a5, 120 */
  a10 = MEM32(a4 + 44); /* 004d: l32i.n a10, a4, 44 */
  MEM32(a1 + 0) = a3; /* 004f: s32i a3, a1, 0 */
  MEMW(); /* 0052: memw  */
  esp_mesh_quick_funcs(a2, a3, a4, a5); /* call via literal slot */ /* 0055: callx8 a5 */
  a5 = (uint32_t)&g_osi_funcs_p; /* 0058: l32r a5, 18 <pm_mesh_set_next_tbtt-0x4> (0 <pm_mesh_set_next_tbtt-0x1c>) */ /* literal @0x18: g_osi_funcs_p */
  a8 = MEM32(a5 + 0); /* 005b: l32i a8, a5, 0 */
  a4 = (uint32_t)&g_pm; /* 005e: l32r a4, 14 <pm_mesh_set_next_tbtt-0x8> (0 <pm_mesh_set_next_tbtt-0x1c>) */ /* literal @0x14: g_pm */
  a10 = a4 | a4; /* 0061: or a10, a4, a4 */
  a8 = MEM32(a8 + 236); /* 0064: l32i a8, a8, 236 */
  ((int32_t(*)())a8)(a2, a3, a4, a5); /* 0067: callx8 a8 */ /* indirect */
  a12 = a3; /* 006a: mov.n a12, a3 */
  a10 = a4; /* 006c: mov.n a10, a4 */
  a5 = MEM32(a5 + 0); /* 006e: l32i.n a5, a5, 0 */
  a11 = MEM32(a1 + 0); /* 0070: l32i.n a11, a1, 0 */
  a5 = MEM32(a5 + 248); /* 0072: l32i a5, a5, 248 */
  g_osi_funcs_p(a2, a3, a4, a5); /* call via literal slot */ /* 0075: callx8 a5 */
  goto L_84; /* 0078: j 84 <pm_mesh_set_next_tbtt+0x68> */
  /* 007b: .byte 00 */
L_7c:;
  a2 = 0x0; /* 007c: movi.n a2, 0 */
  goto L_84; /* 007e: j 84 <pm_mesh_set_next_tbtt+0x68> */
  /* 0081: .byte 00 */
L_82:;
  a2 = a8; /* 0082: mov.n a2, a8 */
L_84:;
  return (int32_t)a2; /* 0084: retw.n  */
}

/* pm_update_at_next_beacon @ pm.o 00000000 size 5B bind GLOBAL
 * Calls: none | Data refs: none
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t pm_update_at_next_beacon(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pm_update_at_next_beacon; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_0:;
  /* 0000: entry a1, 32 */
  return (int32_t)a2; /* 0003: retw.n  */
}

/* pm_handle_tbtt_interval @ pm.o 00000014 size 88B bind GLOBAL
 * Calls: wifi_log[got] | Data refs: g_pm, .rodata.str1.1, .rodata_wlog_error.37, wifi_log
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 1 call(s), 4 data ref(s)
 * Fidelity: medium - 32 instr, 10 branches, calls resolved */
int32_t pm_handle_tbtt_interval(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .wifislpiram.36; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_14:;
  /* 0014: entry a1, 32 */
  a9 = (uint32_t)&g_pm; /* 0017: l32r a9, 0 <pm_handle_tbtt_interval-0x14> (0 <pm_handle_tbtt_interval-0x14>) */ /* literal @0x0: g_pm */
  if (a3 == 0) goto L_60; /* 001a: beqz a3, 60 <pm_handle_tbtt_interval+0x4c> */
  a8 = MEM8(a3 + 3); /* 001d: l8ui a8, a3, 3 */
  a10 = MEM8(a9 + 11); /* 0020: l8ui a10, a9, 11 */
  if (a8 != 0) goto L_28; /* 0023: bnez.n a8, 28 <pm_handle_tbtt_interval+0x14> */
  if (a10 == 1) goto L_50; /* 0025: beqi a10, 1, 50 <pm_handle_tbtt_interval+0x3c> */
L_28:;
  if (a8 == a10) goto L_44; /* 0028: beq a8, a10, 44 <pm_handle_tbtt_interval+0x30> */
  a12 = 0x1; /* 002b: movi.n a12, 1 */
  a15 = 0x837; /* 002d: l32r a15, 4 <pm_handle_tbtt_interval-0x10> (837 <pm_attach+0x7b3>) */ @0x4
  a11 = 0x1000; /* 0030: slli a11, a12, 12 */
  a10 = 0x6; /* 0033: movi.n a10, 6 */
  a14 = (uint32_t)&lit_rodata_str1_1; /* 0035: l32r a14, 8 <pm_handle_tbtt_interval-0xc> (0 <pm_handle_tbtt_interval-0x14>) */ /* literal @0x8: .rodata.str1.1 */
  a13 = (uint32_t)&lit_rodata_wlog_error_37; /* 0038: l32r a13, c <pm_handle_tbtt_interval-0x8> (0 <pm_handle_tbtt_interval-0x14>) */ /* literal @0xC: .rodata_wlog_error.37 */
  a8 = (uint32_t)&wifi_log; /* 003b: l32r a8, 10 <pm_handle_tbtt_interval-0x4> (0 <pm_handle_tbtt_interval-0x14>) */ /* literal: GOT slot for wifi_log */
  wifi_log(a2, a3, a4, a5); /* call via literal slot */ /* 003e: callx8 a8 */
L_41:;
  goto L_41; /* 0041: j 41 <pm_handle_tbtt_interval+0x2d> */
L_44:;
  /* 0044: remu a10, a2, a8 */ /* UNMODELED: a10 clobbered */
  if (a10 == 0) goto L_50; /* 0047: beqz a10, 50 <pm_handle_tbtt_interval+0x3c> */
  /* 004a: remu a8, a8, a2 */ /* UNMODELED: a8 clobbered */
  if (a8 != 0) goto L_65; /* 004d: bnez a8, 65 <pm_handle_tbtt_interval+0x51> */
L_50:;
  a8 = MEM8(a3 + 2); /* 0050: l8ui a8, a3, 2 */
  /* 0053: remu a8, a8, a2 */ /* UNMODELED: a8 clobbered */
  if (a8 == 0) goto L_65; /* 0056: beqz.n a8, 65 <pm_handle_tbtt_interval+0x51> */
  a2 = MEM32(a9 + 44); /* 0058: l32i.n a2, a9, 44 */
  a2 = (uint32_t)((uint64_t)a8 * a2); /* 005a: mull a2, a8, a2 */
  goto L_6a; /* 005d: j 6a <pm_handle_tbtt_interval+0x56> */
L_60:;
  a2 = MEM32(a9 + 44); /* 0060: l32i.n a2, a9, 44 */
  goto L_6a; /* 0062: j 6a <pm_handle_tbtt_interval+0x56> */
L_65:;
  a3 = MEM32(a9 + 44); /* 0065: l32i.n a3, a9, 44 */
  a2 = (uint32_t)((uint64_t)a2 * a3); /* 0067: mull a2, a2, a3 */
L_6a:;
  return (int32_t)a2; /* 006a: retw.n  */
}

/* pm_update_next_tbtt @ pm.o 00000048 size 734B bind GLOBAL
 * Calls: __umoddi3[got], ptr_beacon_offset_funcs[got], pm_coex_schm_overall_period_get[got], pm_handle_tbtt_interval[got], ptr_beacon_offset_funcs[got], g_mesh_init_ps_type[got], g_pm_cfg[got], g_mesh_init_ps_type[got], wifi_log[got], g_pm_cfg[got], g_mesh_init_ps_type[got], g_mesh_init_ps_type[got], esp_mesh_quick_funcs[got], esp_mesh_quick_funcs[got], g_mesh_init_ps_type[got], g_mesh_is_started[got], esp_mesh_quick_funcs[got] | Data refs: g_osi_funcs_p, g_pm_cfg, g_pm, __umoddi3, ptr_beacon_offset_funcs, pm_coex_schm_overall_period_get, pm_handle_tbtt_interval, g_intr_lock_mux, g_mesh_is_started, g_mesh_is_root, g_mesh_init_ps_type, g_wifi_mac_time_delta, .rodata_wlog_warning.39, wifi_log, esp_mesh_quick_funcs
 *   MMIO: 0x3FF73C00
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 17 call(s), 15 data ref(s)
 * Fidelity: low - 292 instr, 42 branches, 2 indirect; call-sequence + MMIO skeleton */
int32_t pm_update_next_tbtt(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .wifislpiram.38; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_48:;
  /* 0048: entry a1, 96 */
  a5 = (uint32_t)&g_osi_funcs_p; /* 004b: l32r a5, 0 <pm_update_next_tbtt-0x48> (0 <pm_update_next_tbtt-0x48>) */ /* literal @0x0: g_osi_funcs_p */
  a6 = MEM32(a5 + 0); /* 004e: l32i.n a6, a5, 0 */
  a10 = MEM32(a6 + 404); /* 0050: l32i a10, a6, 0x194 */
  MEM32(a1 + 52) = a3; /* 0053: s32i a3, a1, 52 */
  MEMW(); /* 0056: memw  */
  ((int32_t(*)())a10)(a2, a3, a4, a5); /* 0059: callx8 a10 */ /* indirect */
  a13 = 0x0; /* 005c: movi.n a13, 0 */
  a7 = (uint32_t)&g_pm_cfg; /* 005e: l32r a7, 4 <pm_update_next_tbtt-0x44> (0 <pm_update_next_tbtt-0x48>) */ /* literal @0x4: g_pm_cfg */
  a3 = (uint32_t)&g_pm; /* 0061: l32r a3, 8 <pm_update_next_tbtt-0x40> (0 <pm_update_next_tbtt-0x48>) */ /* literal @0x8: g_pm */
  a8 = MEM32(a1 + 52); /* 0064: l32i.n a8, a1, 52 */
  a6 = MEM32(a7 + 4); /* 0066: l32i.n a6, a7, 4 */
  a7 = MEM32(a7 + 8); /* 0068: l32i.n a7, a7, 8 */
  if (a10 != 0) a6 = a7; /* 006a: movnez a6, a7, a10 */
  a12 = MEM32(a3 + 44); /* 006d: l32i.n a12, a3, 44 */
  a10 = MEM32(a8 + 0); /* 006f: l32i.n a10, a8, 0 */
  a11 = MEM32(a8 + 4); /* 0071: l32i.n a11, a8, 4 */
  MEM32(a3 + 40) = a6; /* 0073: s32i.n a6, a3, 40 */
  a6 = a3 + ((0x100) << 8); /* 0075: addmi a6, a3, 0x100 */
  MEMW(); /* 0078: memw  */
  a8 = (uint32_t)&umoddi3; /* 007b: l32r a8, 38 <pm_update_next_tbtt-0x10> (0 <pm_update_next_tbtt-0x48>) */ /* literal: GOT slot for __umoddi3 */
  umoddi3(a2, a3, a4, a5); /* call via literal slot */ /* 007e: callx8 a8 */
  a7 = MEM8(a6 + 100); /* 0081: l8ui a7, a6, 100 */
  MEM32(a1 + 48) = a10; /* 0084: s32i.n a10, a1, 48 */
  if (a7 == 0) goto L_a2; /* 0086: beqz.n a7, a2 <pm_update_next_tbtt+0x5a> */
  a6 = MEM8(a6 + 212); /* 0088: l8ui a6, a6, 212 */
  if (a6 != 0) goto L_a2; /* 008b: bnez.n a6, a2 <pm_update_next_tbtt+0x5a> */
  a6 = MEM8(a3 + 13); /* 008d: l8ui a6, a3, 13 */
  if (a6 == 0) goto L_a2; /* 0090: beqz.n a6, a2 <pm_update_next_tbtt+0x5a> */
  a6 = (uint32_t)&ptr_beacon_offset_funcs; /* 0092: l32r a6, c <pm_update_next_tbtt-0x3c> (0 <pm_update_next_tbtt-0x48>) */ /* literal @0xC: ptr_beacon_offset_funcs */
  a6 = MEM32(a6 + 0); /* 0095: l32i.n a6, a6, 0 */
  a6 = MEM32(a6 + 4); /* 0097: l32i.n a6, a6, 4 */
  if (a6 == 0) goto L_a2; /* 0099: beqz a6, a2 <pm_update_next_tbtt+0x5a> */
  MEMW(); /* 009c: memw  */
  ptr_beacon_offset_funcs(a2, a3, a4, a5); /* call via literal slot */ /* 009f: callx8 a6 */
L_a2:;
  a6 = MEM32(a1 + 48); /* 00a2: l32i.n a6, a1, 48 */
  a2 = a2 - a6; /* 00a4: sub a2, a2, a6 */
  a6 = MEM32(a5 + 0); /* 00a7: l32i a6, a5, 0 */
  a10 = MEM32(a6 + 404); /* 00aa: l32i a10, a6, 0x194 */
  ((int32_t(*)())a10)(a2, a3, a4, a5); /* 00ad: callx8 a10 */ /* indirect */
  if (a10 == 0) goto L_c2; /* 00b0: beqz.n a10, c2 <pm_update_next_tbtt+0x7a> */
  a6 = MEM8(a3 + 14); /* 00b2: l8ui a6, a3, 14 */
  if (a6 == 0) goto L_e9; /* 00b5: beqz.n a6, e9 <pm_update_next_tbtt+0xa1> */
  a8 = (uint32_t)&pm_coex_schm_overall_period_get; /* 00b7: l32r a8, 3c <pm_update_next_tbtt-0xc> (0 <pm_update_next_tbtt-0x48>) */ /* literal: GOT slot for pm_coex_schm_overall_period_get */
  pm_coex_schm_overall_period_get(a2, a3, a4, a5); /* call via literal slot */ /* 00ba: callx8 a8 */
  a11 = a4; /* 00bd: mov.n a11, a4 */
  goto L_d2; /* 00bf: j d2 <pm_update_next_tbtt+0x8a> */
L_c2:;
  a6 = MEM32(a3 + 36); /* 00c2: l32i.n a6, a3, 36 */
  if (a6 != 0) goto L_c9; /* 00c4: bnez.n a6, c9 <pm_update_next_tbtt+0x81> */
  goto L_e9; /* 00c6: j e9 <pm_update_next_tbtt+0xa1> */
L_c9:;
  if (a6 != 1) goto L_dd; /* 00c9: bnei a6, 1, dd <pm_update_next_tbtt+0x95> */
  a10 = MEM8(a3 + 11); /* 00cc: l8ui a10, a3, 11 */
  a11 = a4 | a4; /* 00cf: or a11, a4, a4 */
L_d2:;
  a8 = (uint32_t)&pm_handle_tbtt_interval; /* 00d2: l32r a8, 40 <pm_update_next_tbtt-0x8> (0 <pm_update_next_tbtt-0x48>) */ /* literal: GOT slot for pm_handle_tbtt_interval */
  pm_handle_tbtt_interval(a2, a3, a4, a5); /* call via literal slot */ /* 00d5: callx8 a8 */
  a9 = a10 + a2; /* 00d8: add.n a9, a10, a2 */
  goto L_ed; /* 00da: j ed <pm_update_next_tbtt+0xa5> */
L_dd:;
  if (a6 != 2) goto L_e9; /* 00dd: bnei a6, 2, e9 <pm_update_next_tbtt+0xa1> */
  a10 = MEM16(a3 + 32); /* 00e0: l16ui a10, a3, 32 */
  a11 = a4; /* 00e3: mov.n a11, a4 */
  goto L_d2; /* 00e5: j d2 <pm_update_next_tbtt+0x8a> */
  /* 00e8: .byte 00 */
L_e9:;
  a9 = MEM32(a3 + 44); /* 00e9: l32i.n a9, a3, 44 */
  a9 = a2 + a9; /* 00eb: add.n a9, a2, a9 */
L_ed:;
  a6 = MEM32(a3 + 40); /* 00ed: l32i.n a6, a3, 40 */
  a7 = MEM32(a3 + 460); /* 00ef: l32i a7, a3, 0x1cc */
  a7 = a7 - a6; /* 00f2: sub a7, a7, a6 */
  a7 = a7 + a9; /* 00f5: add.n a7, a7, a9 */
  a6 = MEM32(a5 + 0); /* 00f7: l32i.n a6, a5, 0 */
  a10 = (uint32_t)&g_intr_lock_mux; /* 00f9: l32r a10, 10 <pm_update_next_tbtt-0x38> (0 <pm_update_next_tbtt-0x48>) */ /* literal @0x10: g_intr_lock_mux */
  a6 = MEM32(a6 + 40); /* 00fc: l32i.n a6, a6, 40 */
  a10 = MEM32(a10 + 0); /* 00fe: l32i.n a10, a10, 0 */
  MEM32(a1 + 56) = a9; /* 0100: s32i.n a9, a1, 56 */
  MEMW(); /* 0102: memw  */
  ptr_beacon_offset_funcs(a2, a3, a4, a5); /* call via literal slot */ /* 0105: callx8 a6 */
  a6 = a10; /* 0108: mov.n a6, a10 */
  a10 = (uint32_t)&g_mesh_is_started; /* 010a: l32r a10, 14 <pm_update_next_tbtt-0x34> (0 <pm_update_next_tbtt-0x48>) */ /* literal @0x14: g_mesh_is_started */
  a10 = MEM8(a10 + 0); /* 010d: l8ui a10, a10, 0 */
  a9 = MEM32(a1 + 56); /* 0110: l32i.n a9, a1, 56 */
  if (a10 == 0) goto L_138; /* 0112: beqz.n a10, 138 <pm_update_next_tbtt+0xf0> */
  a10 = (uint32_t)&g_mesh_is_root; /* 0114: l32r a10, 18 <pm_update_next_tbtt-0x30> (0 <pm_update_next_tbtt-0x48>) */ /* literal @0x18: g_mesh_is_root */
  MEMW(); /* 0117: memw  */
  a10 = MEM8(a10 + 0); /* 011a: l8ui a10, a10, 0 */
  a10 = (a10 >> 0) & 0xFF; /* 011d: extui a10, a10, 0, 8 */
  if (a10 != 0) goto L_138; /* 0120: bnez.n a10, 138 <pm_update_next_tbtt+0xf0> */
  a10 = (uint32_t)&g_mesh_init_ps_type; /* 0122: l32r a10, 1c <pm_update_next_tbtt-0x2c> (0 <pm_update_next_tbtt-0x48>) */ /* literal @0x1C: g_mesh_init_ps_type */
  a10 = MEM32(a10 + 0); /* 0125: l32i.n a10, a10, 0 */
  if (a10 == 0) goto L_138; /* 0127: beqz.n a10, 138 <pm_update_next_tbtt+0xf0> */
  a10 = MEM32(a5 + 0); /* 0129: l32i.n a10, a5, 0 */
  a10 = MEM32(a10 + 272); /* 012b: l32i a10, a10, 0x110 */
  g_mesh_init_ps_type(a2, a3, a4, a5); /* call via literal slot */ /* 012e: callx8 a10 */
  a9 = MEM32(a1 + 56); /* 0131: l32i.n a9, a1, 56 */
  goto L_147; /* 0133: j 147 <pm_update_next_tbtt+0xff> */
  /* 0136: .byte 00 */
  /* 0137: .byte 00 */
L_138:;
  a10 = 0x3FF73C00; /* 0138: l32r a10, 20 <pm_update_next_tbtt-0x28> (3ff73c00 <pm_attach+0x3ff73b7c>) */ /* MMIO base */ @0x20
  a11 = (uint32_t)&g_wifi_mac_time_delta; /* 013b: l32r a11, 24 <pm_update_next_tbtt-0x24> (0 <pm_update_next_tbtt-0x48>) */ /* literal @0x24: g_wifi_mac_time_delta */
  MEMW(); /* 013e: memw  */
  a10 = REG32(0x3FF73C00); /* 0141: l32i.n a10, a10, 0 */ /* MMIO read: base 0x3FF73C00+0 */
  a11 = MEM32(a11 + 0); /* 0143: l32i.n a11, a11, 0 */
  a10 = a10 + a11; /* 0145: add.n a10, a10, a11 */
L_147:;
  a13 = a7 - a10; /* 0147: sub a13, a7, a10 */
  a11 = 0x1387; /* 014a: l32r a11, 28 <pm_update_next_tbtt-0x20> (1387 <pm_attach+0x1303>) */ @0x28
  a12 = MEM32(a5 + 0); /* 014d: l32i.n a12, a5, 0 */
  if (a11 < a13) goto L_159; /* 014f: bltu a11, a13, 159 <pm_update_next_tbtt+0x111> */
  a2 = MEM32(a3 + 44); /* 0152: l32i.n a2, a3, 44 */
  a9 = a9 + a2; /* 0154: add.n a9, a9, a2 */
  goto L_215; /* 0156: j 215 <pm_update_next_tbtt+0x1cd> */
L_159:;
  a11 = 0xFFFFFFFF; /* 0159: movi.n a11, -1 */
  a11 = 0x80000000; /* 015b: slli a11, a11, 31 */
  if (a11 < a13) goto L_164; /* 015e: bltu a11, a13, 164 <pm_update_next_tbtt+0x11c> */
  goto L_215; /* 0161: j 215 <pm_update_next_tbtt+0x1cd> */
L_164:;
  a11 = 0x271; /* 0164: movi a11, 0x271 */
  a13 = MEM32(a3 + 44); /* 0167: l32i.n a13, a3, 44 */
  a7 = a7 - (a11 << 8) /* verify order vs disasm */; /* 0169: subx8 a7, a11, a7 */
  a10 = a7 + a10; /* 016c: add.n a10, a7, a10 */
  /* 016e: quou a10, a10, a13 */ /* UNMODELED: a10 clobbered */
  a7 = a10 + (1); /* 0171: addi.n a7, a10, 1 */
  a7 = (uint32_t)((uint64_t)a7 * a13); /* 0173: mull a7, a7, a13 */
  a9 = a9 + a7; /* 0176: add.n a9, a9, a7 */
  a7 = 0x64; /* 0178: movi a7, 100 */
  if (a7 < a10) goto L_181; /* 017b: bltu a7, a10, 181 <pm_update_next_tbtt+0x139> */
  goto L_215; /* 017e: j 215 <pm_update_next_tbtt+0x1cd> */
L_181:;
  a11 = a6; /* 0181: mov.n a11, a6 */
  a6 = (uint32_t)&g_intr_lock_mux; /* 0183: l32r a6, 10 <pm_update_next_tbtt-0x38> (0 <pm_update_next_tbtt-0x48>) */ /* literal @0x10: g_intr_lock_mux */
  a7 = MEM32(a12 + 44); /* 0186: l32i.n a7, a12, 44 */
  a10 = MEM32(a6 + 0); /* 0188: l32i.n a10, a6, 0 */
  a6 = a4 | a4; /* 018a: or a6, a4, a4 */
  MEM32(a1 + 56) = a9; /* 018d: s32i a9, a1, 56 */
  MEMW(); /* 0190: memw  */
  ((int32_t(*)())a7)(a2, a3, a4, a5); /* 0193: callx8 a7 */ /* indirect */
  a7 = a4; /* 0196: mov.n a7, a4 */
  a12 = MEM32(a3 + 44); /* 0198: l32i.n a12, a3, 44 */
  a9 = MEM32(a1 + 56); /* 019a: l32i.n a9, a1, 56 */
  if (a4 == 0) goto L_1a5; /* 019c: beqz a4, 1a5 <pm_update_next_tbtt+0x15d> */
  a6 = MEM8(a4 + 3); /* 019f: l8ui a6, a4, 3 */
  a7 = MEM8(a4 + 2); /* 01a2: l8ui a7, a4, 2 */
L_1a5:;
  a4 = (uint32_t)&g_mesh_is_started; /* 01a5: l32r a4, 14 <pm_update_next_tbtt-0x34> (0 <pm_update_next_tbtt-0x48>) */ /* literal @0x14: g_mesh_is_started */
  a4 = MEM8(a4 + 0); /* 01a8: l8ui a4, a4, 0 */
  a3 = MEM16(a3 + 32); /* 01ab: l16ui a3, a3, 32 */
  if (a4 == 0) goto L_1dc; /* 01ae: beqz.n a4, 1dc <pm_update_next_tbtt+0x194> */
  a4 = (uint32_t)&g_mesh_is_root; /* 01b0: l32r a4, 18 <pm_update_next_tbtt-0x30> (0 <pm_update_next_tbtt-0x48>) */ /* literal @0x18: g_mesh_is_root */
  MEMW(); /* 01b3: memw  */
  a4 = MEM8(a4 + 0); /* 01b6: l8ui a4, a4, 0 */
  a4 = (a4 >> 0) & 0xFF; /* 01b9: extui a4, a4, 0, 8 */
  if (a4 != 0) goto L_1dc; /* 01bc: bnez.n a4, 1dc <pm_update_next_tbtt+0x194> */
  a4 = (uint32_t)&g_mesh_init_ps_type; /* 01be: l32r a4, 1c <pm_update_next_tbtt-0x2c> (0 <pm_update_next_tbtt-0x48>) */ /* literal @0x1C: g_mesh_init_ps_type */
  a4 = MEM32(a4 + 0); /* 01c1: l32i.n a4, a4, 0 */
  if (a4 == 0) goto L_1dc; /* 01c3: beqz.n a4, 1dc <pm_update_next_tbtt+0x194> */
  a4 = MEM32(a5 + 0); /* 01c5: l32i.n a4, a5, 0 */
  a10 = MEM32(a4 + 272); /* 01c7: l32i a10, a4, 0x110 */
  MEM32(a1 + 56) = a9; /* 01ca: s32i.n a9, a1, 56 */
  MEM32(a1 + 52) = a12; /* 01cc: s32i.n a12, a1, 52 */
  MEMW(); /* 01ce: memw  */
  ((int32_t(*)())a10)(a2, a3, a4, a5); /* 01d1: callx8 a10 */ /* indirect */
  a9 = MEM32(a1 + 56); /* 01d4: l32i.n a9, a1, 56 */
  a12 = MEM32(a1 + 52); /* 01d6: l32i.n a12, a1, 52 */
  goto L_1eb; /* 01d8: j 1eb <pm_update_next_tbtt+0x1a3> */
  /* 01db: .byte 00 */
L_1dc:;
  a4 = 0x3FF73C00; /* 01dc: l32r a4, 20 <pm_update_next_tbtt-0x28> (3ff73c00 <pm_attach+0x3ff73b7c>) */ /* MMIO base */ @0x20
  MEMW(); /* 01df: memw  */
  a10 = REG32(0x3FF73C00); /* 01e2: l32i.n a10, a4, 0 */ /* MMIO read: base 0x3FF73C00+0 */
  a4 = (uint32_t)&g_wifi_mac_time_delta; /* 01e4: l32r a4, 24 <pm_update_next_tbtt-0x24> (0 <pm_update_next_tbtt-0x48>) */ /* literal @0x24: g_wifi_mac_time_delta */
  a4 = MEM32(a4 + 0); /* 01e7: l32i.n a4, a4, 0 */
  a10 = a10 + a4; /* 01e9: add.n a10, a10, a4 */
L_1eb:;
  a11 = 0x1; /* 01eb: movi.n a11, 1 */
  a14 = a2; /* 01ed: mov.n a14, a2 */
  a15 = MEM32(a1 + 48); /* 01ef: l32i.n a15, a1, 48 */
  a11 = 0x1000; /* 01f1: slli a11, a11, 12 */
  a13 = (uint32_t)&lit_rodata_wlog_warning_39; /* 01f4: l32r a13, 2c <pm_update_next_tbtt-0x1c> (0 <pm_update_next_tbtt-0x48>) */ /* literal @0x2C: .rodata_wlog_warning.39 */
  MEM32(a1 + 20) = a10; /* 01f7: s32i.n a10, a1, 20 */
  a10 = 0x6; /* 01f9: movi.n a10, 6 */
  MEM32(a1 + 4) = a12; /* 01fb: s32i.n a12, a1, 4 */
  a12 = 0x2; /* 01fd: movi.n a12, 2 */
  MEM32(a1 + 16) = a3; /* 01ff: s32i.n a3, a1, 16 */
  MEM32(a1 + 12) = a7; /* 0201: s32i.n a7, a1, 12 */
  MEM32(a1 + 8) = a6; /* 0203: s32i.n a6, a1, 8 */
  MEM32(a1 + 0) = a9; /* 0205: s32i.n a9, a1, 0 */
  MEMW(); /* 0207: memw  */
  a8 = (uint32_t)&wifi_log; /* 020a: l32r a8, 44 <pm_update_next_tbtt-0x4> (0 <pm_update_next_tbtt-0x48>) */ /* literal: GOT slot for wifi_log */
  wifi_log(a2, a3, a4, a5); /* call via literal slot */ /* 020d: callx8 a8 */
  goto L_324; /* 0210: j 324 <pm_update_next_tbtt+0x2dc> */
  /* 0213: .byte 00 */
  /* 0214: .byte 00 */
L_215:;
  a4 = MEM32(a3 + 40); /* 0215: l32i.n a4, a3, 40 */
  a2 = MEM32(a3 + 460); /* 0217: l32i a2, a3, 0x1cc */
  a2 = a2 - a4; /* 021a: sub a2, a2, a4 */
  a2 = a2 + a9; /* 021d: add.n a2, a2, a9 */
  a4 = (uint32_t)&g_pm; /* 021f: l32r a4, 30 <pm_update_next_tbtt-0x18> (0 <pm_update_next_tbtt-0x48>) */ /* literal @0x30: g_pm */
  a10 = a4; /* 0222: mov.n a10, a4 */
  a7 = MEM32(a12 + 236); /* 0224: l32i a7, a12, 236 */
  ((int32_t(*)())a7)(a2, a3, a4, a5); /* 0227: callx8 a7 */ /* indirect */
  a7 = MEM32(a5 + 0); /* 022a: l32i.n a7, a5, 0 */
  a10 = MEM32(a7 + 272); /* 022c: l32i a10, a7, 0x110 */
  ((int32_t(*)())a10)(a2, a3, a4, a5); /* 022f: callx8 a10 */ /* indirect */
  a9 = a10; /* 0232: mov.n a9, a10 */
  a7 = 0x1000; /* 0234: mov.n a7, a11 */
  a8 = (uint32_t)&g_mesh_is_started; /* 0236: l32r a8, 14 <pm_update_next_tbtt-0x34> (0 <pm_update_next_tbtt-0x48>) */ /* literal @0x14: g_mesh_is_started */
  a10 = MEM8(a8 + 0); /* 0239: l8ui a10, a8, 0 */
  if (a10 == 0) goto L_265; /* 023c: beqz.n a10, 265 <pm_update_next_tbtt+0x21d> */
  a10 = (uint32_t)&g_mesh_is_root; /* 023e: l32r a10, 18 <pm_update_next_tbtt-0x30> (0 <pm_update_next_tbtt-0x48>) */ /* literal @0x18: g_mesh_is_root */
  MEMW(); /* 0241: memw  */
  a10 = MEM8(a10 + 0); /* 0244: l8ui a10, a10, 0 */
  a10 = (a10 >> 0) & 0xFF; /* 0247: extui a10, a10, 0, 8 */
  if (a10 != 0) goto L_265; /* 024a: bnez.n a10, 265 <pm_update_next_tbtt+0x21d> */
  a10 = (uint32_t)&g_mesh_init_ps_type; /* 024c: l32r a10, 1c <pm_update_next_tbtt-0x2c> (0 <pm_update_next_tbtt-0x48>) */ /* literal @0x1C: g_mesh_init_ps_type */
  a10 = MEM32(a10 + 0); /* 024f: l32i.n a10, a10, 0 */
  if (a10 == 0) goto L_265; /* 0251: beqz.n a10, 265 <pm_update_next_tbtt+0x21d> */
  a10 = MEM32(a5 + 0); /* 0253: l32i.n a10, a5, 0 */
  a10 = MEM32(a10 + 272); /* 0255: l32i a10, a10, 0x110 */
  MEM32(a1 + 56) = a9; /* 0258: s32i.n a9, a1, 56 */
  MEMW(); /* 025a: memw  */
  g_mesh_init_ps_type(a2, a3, a4, a5); /* call via literal slot */ /* 025d: callx8 a10 */
  a9 = MEM32(a1 + 56); /* 0260: l32i.n a9, a1, 56 */
  goto L_274; /* 0262: j 274 <pm_update_next_tbtt+0x22c> */
L_265:;
  a10 = 0x3FF73C00; /* 0265: l32r a10, 20 <pm_update_next_tbtt-0x28> (3ff73c00 <pm_attach+0x3ff73b7c>) */ /* MMIO base */ @0x20
  a11 = (uint32_t)&g_wifi_mac_time_delta; /* 0268: l32r a11, 24 <pm_update_next_tbtt-0x24> (0 <pm_update_next_tbtt-0x48>) */ /* literal @0x24: g_wifi_mac_time_delta */
  MEMW(); /* 026b: memw  */
  a10 = REG32(0x3FF73C00); /* 026e: l32i.n a10, a10, 0 */ /* MMIO read: base 0x3FF73C00+0 */
  a11 = MEM32(a11 + 0); /* 0270: l32i.n a11, a11, 0 */
  a10 = a10 + a11; /* 0272: add.n a10, a10, a11 */
L_274:;
  a10 = a2 - a10; /* 0274: sub a10, a2, a10 */
  a11 = a10 + a9; /* 0277: add.n a11, a10, a9 */
  a9 = 0x1; /* 0279: movi.n a9, 1 */
  if (a11 < a10) goto L_281; /* 027b: bltu a11, a10, 281 <pm_update_next_tbtt+0x239> */
  a9 = 0x0; /* 027e: movi a9, 0 */
L_281:;
  a8 = (uint32_t)&g_mesh_is_started; /* 0281: l32r a8, 14 <pm_update_next_tbtt-0x34> (0 <pm_update_next_tbtt-0x48>) */ /* literal @0x14: g_mesh_is_started */
  a9 = a9 + a7; /* 0284: add.n a9, a9, a7 */
  MEM32(a3 + 92) = a9; /* 0286: s32i a9, a3, 92 */
  a9 = MEM8(a8 + 0); /* 0289: l8ui a9, a8, 0 */
  MEM32(a3 + 88) = a11; /* 028c: s32i a11, a3, 88 */
  if (a9 == 0) goto L_2d1; /* 028f: beqz.n a9, 2d1 <pm_update_next_tbtt+0x289> */
  a7 = (uint32_t)&g_mesh_is_root; /* 0291: l32r a7, 18 <pm_update_next_tbtt-0x30> (0 <pm_update_next_tbtt-0x48>) */ /* literal @0x18: g_mesh_is_root */
  MEMW(); /* 0294: memw  */
  a7 = MEM8(a7 + 0); /* 0297: l8ui a7, a7, 0 */
  a7 = (a7 >> 0) & 0xFF; /* 029a: extui a7, a7, 0, 8 */
  if (a7 != 0) goto L_2d1; /* 029d: bnez.n a7, 2d1 <pm_update_next_tbtt+0x289> */
  a10 = (uint32_t)&g_mesh_init_ps_type; /* 029f: l32r a10, 1c <pm_update_next_tbtt-0x2c> (0 <pm_update_next_tbtt-0x48>) */ /* literal @0x1C: g_mesh_init_ps_type */
  a10 = MEM32(a10 + 0); /* 02a2: l32i.n a10, a10, 0 */
  if (a10 == 0) goto L_2d1; /* 02a4: beqz.n a10, 2d1 <pm_update_next_tbtt+0x289> */
  a13 = a1 + (32); /* 02a6: addi a13, a1, 32 */
  a2 = (uint32_t)&esp_mesh_quick_funcs; /* 02a9: l32r a2, 34 <pm_update_next_tbtt-0x14> (0 <pm_update_next_tbtt-0x48>) */ /* literal @0x34: esp_mesh_quick_funcs */
  a12 = MEM32(a1 + 48); /* 02ac: l32i.n a12, a1, 48 */
  a11 = MEM8(a3 + 11); /* 02ae: l8ui a11, a3, 11 */
  a2 = MEM32(a2 + 124); /* 02b1: l32i a2, a2, 124 */
  a10 = MEM32(a3 + 44); /* 02b4: l32i.n a10, a3, 44 */
  MEM32(a1 + 32) = a7; /* 02b6: s32i.n a7, a1, 32 */
  MEMW(); /* 02b8: memw  */
  esp_mesh_quick_funcs(a2, a3, a4, a5); /* call via literal slot */ /* 02bb: callx8 a2 */
  a12 = a7; /* 02be: mov.n a12, a7 */
  a10 = a4; /* 02c0: mov.n a10, a4 */
  a2 = MEM32(a5 + 0); /* 02c2: l32i.n a2, a5, 0 */
  a11 = MEM32(a1 + 32); /* 02c4: l32i.n a11, a1, 32 */
  a2 = MEM32(a2 + 248); /* 02c6: l32i a2, a2, 248 */
  esp_mesh_quick_funcs(a2, a3, a4, a5); /* call via literal slot */ /* 02c9: callx8 a2 */
  goto L_316; /* 02cc: j 316 <pm_update_next_tbtt+0x2ce> */
  /* 02cf: .byte 00 */
  /* 02d0: .byte 00 */
L_2d1:;
  a7 = MEM32(a5 + 0); /* 02d1: l32i.n a7, a5, 0 */
  a8 = MEM32(a7 + 248); /* 02d3: l32i a8, a7, 248 */
  if (a9 == 0) goto L_2fd; /* 02d6: beqz.n a9, 2fd <pm_update_next_tbtt+0x2b5> */
  a3 = (uint32_t)&g_mesh_is_root; /* 02d8: l32r a3, 18 <pm_update_next_tbtt-0x30> (0 <pm_update_next_tbtt-0x48>) */ /* literal @0x18: g_mesh_is_root */
  MEMW(); /* 02db: memw  */
  a3 = MEM8(a3 + 0); /* 02de: l8ui a3, a3, 0 */
  a3 = (a3 >> 0) & 0xFF; /* 02e1: extui a3, a3, 0, 8 */
  if (a3 != 0) goto L_2fd; /* 02e4: bnez.n a3, 2fd <pm_update_next_tbtt+0x2b5> */
  a3 = (uint32_t)&g_mesh_init_ps_type; /* 02e6: l32r a3, 1c <pm_update_next_tbtt-0x2c> (0 <pm_update_next_tbtt-0x48>) */ /* literal @0x1C: g_mesh_init_ps_type */
  a3 = MEM32(a3 + 0); /* 02e9: l32i.n a3, a3, 0 */
  if (a3 == 0) goto L_2fd; /* 02eb: beqz.n a3, 2fd <pm_update_next_tbtt+0x2b5> */
  a10 = MEM32(a7 + 272); /* 02ed: l32i a10, a7, 0x110 */
  MEM32(a1 + 52) = a8; /* 02f0: s32i.n a8, a1, 52 */
  MEMW(); /* 02f2: memw  */
  ((int32_t(*)())a10)(a2, a3, a4, a5); /* 02f5: callx8 a10 */ /* indirect */
  a8 = MEM32(a1 + 52); /* 02f8: l32i.n a8, a1, 52 */
  goto L_30c; /* 02fa: j 30c <pm_update_next_tbtt+0x2c4> */
L_2fd:;
  a3 = 0x3FF73C00; /* 02fd: l32r a3, 20 <pm_update_next_tbtt-0x28> (3ff73c00 <pm_attach+0x3ff73b7c>) */ /* MMIO base */ @0x20
  MEMW(); /* 0300: memw  */
  a10 = REG32(0x3FF73C00); /* 0303: l32i.n a10, a3, 0 */ /* MMIO read: base 0x3FF73C00+0 */
  a3 = (uint32_t)&g_wifi_mac_time_delta; /* 0305: l32r a3, 24 <pm_update_next_tbtt-0x24> (0 <pm_update_next_tbtt-0x48>) */ /* literal @0x24: g_wifi_mac_time_delta */
  a3 = MEM32(a3 + 0); /* 0308: l32i.n a3, a3, 0 */
  a10 = a10 + a3; /* 030a: add.n a10, a10, a3 */
L_30c:;
  a11 = a2 - a10; /* 030c: sub a11, a2, a10 */
  a12 = 0x0; /* 030f: movi.n a12, 0 */
  a10 = a4; /* 0311: mov.n a10, a4 */
  g_mesh_is_started(a2, a3, a4, a5); /* call via literal slot */ /* 0313: callx8 a8 */
L_316:;
  a2 = MEM32(a5 + 0); /* 0316: l32i.n a2, a5, 0 */
  a11 = a6; /* 0318: mov.n a11, a6 */
  a3 = (uint32_t)&g_intr_lock_mux; /* 031a: l32r a3, 10 <pm_update_next_tbtt-0x38> (0 <pm_update_next_tbtt-0x48>) */ /* literal @0x10: g_intr_lock_mux */
  a2 = MEM32(a2 + 44); /* 031d: l32i.n a2, a2, 44 */
  a10 = MEM32(a3 + 0); /* 031f: l32i.n a10, a3, 0 */
  esp_mesh_quick_funcs(a2, a3, a4, a5); /* call via literal slot */ /* 0321: callx8 a2 */
L_324:;
  return (int32_t)a2; /* 0324: retw.n  */
}

/* pm_beacon_timestamp_statistic @ pm.o 0000000c size 45B bind GLOBAL
 * Calls: __umoddi3 | Data refs: __umoddi3, g_pm, g_pm_cnt
 *   MMIO: none
 *   funcdb v3: 1 call(s), 3 ref(s); disasm: 1 call(s), 3 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t pm_beacon_timestamp_statistic(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pm_beacon_timestamp_statistic; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_c:;
  /* 000c: entry a1, 32 */
  if (a2 == 0) goto L_34; /* 000f: beqz.n a2, 34 <pm_beacon_timestamp_statistic+0x28> */
  a8 = (uint32_t)&g_pm; /* 0011: l32r a8, 4 <pm_beacon_timestamp_statistic-0x8> (0 <pm_beacon_timestamp_statistic-0xc>) */ /* literal @0x4: g_pm */
  a13 = 0x0; /* 0014: movi.n a13, 0 */
  a3 = (uint32_t)&g_pm_cnt; /* 0016: l32r a3, 0 <pm_beacon_timestamp_statistic-0xc> (0 <pm_beacon_timestamp_statistic-0xc>) */ /* literal @0x0: g_pm_cnt */
  a10 = MEM32(a2 + 0); /* 0019: l32i.n a10, a2, 0 */
  a11 = MEM32(a2 + 4); /* 001b: l32i.n a11, a2, 4 */
  a12 = MEM32(a8 + 44); /* 001d: l32i a12, a8, 44 */
  a8 = (uint32_t)&umoddi3; /* 0020: l32r a8, 8 <pm_beacon_timestamp_statistic-0x4> (0 <pm_beacon_timestamp_statistic-0xc>) */ /* literal: GOT slot for __umoddi3 */
  umoddi3(a2, a3, a4, a5); /* call via literal slot */ /* 0023: callx8 a8 */
  a4 = MEM32(a3 + 36); /* 0026: l32i.n a4, a3, 36 */
  a10 = a10 - a4; /* 0028: sub a10, a10, a4 */
  a2 = MEM32(a3 + 4); /* 002b: l32i.n a2, a3, 4 */
  /* 002d: quou a10, a10, a2 */ /* UNMODELED: a10 clobbered */
  a10 = a10 + a4; /* 0030: add.n a10, a10, a4 */
  MEM32(a3 + 36) = a10; /* 0032: s32i.n a10, a3, 36 */
L_34:;
  MEMW(); /* 0034: memw  */
  return (int32_t)a2; /* 0037: retw.n  */
}

/* pm_beacon_misc_process @ pm.o 00000004 size 14B bind GLOBAL
 * Calls: pm_beacon_timestamp_statistic | Data refs: pm_beacon_timestamp_statistic
 *   MMIO: none
 *   funcdb v3: 1 call(s), 1 ref(s); disasm: 1 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t pm_beacon_misc_process(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pm_beacon_misc_process; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a10 = a2 | a2; /* 0007: or a10, a2, a2 */
  a8 = (uint32_t)&pm_beacon_timestamp_statistic; /* 000a: l32r a8, 0 <pm_beacon_misc_process-0x4> (0 <pm_beacon_misc_process-0x4>) */ /* literal: GOT slot for pm_beacon_timestamp_statistic */
  pm_beacon_timestamp_statistic(a2, a3, a4, a5); /* call via literal slot */ /* 000d: callx8 a8 */
  return (int32_t)a2; /* 0010: retw.n  */
}

/* pm_is_in_wifi_slice_threshold @ pm.o 00000008 size 119B bind GLOBAL
 * Calls: none | Data refs: g_osi_funcs_p, g_pm
 *   MMIO: none
 *   funcdb v3: 0 call(s), 2 ref(s); disasm: 0 call(s), 2 data ref(s)
 * Fidelity: medium - 42 instr, 13 branches, calls resolved */
int32_t pm_is_in_wifi_slice_threshold(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pm_is_in_wifi_slice_threshold; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_8:;
  /* 0008: entry a1, 32 */
  a8 = (uint32_t)&g_osi_funcs_p; /* 000b: l32r a8, 0 <pm_is_in_wifi_slice_threshold-0x8> (0 <pm_is_in_wifi_slice_threshold-0x8>) */ /* literal @0x0: g_osi_funcs_p */
  a8 = MEM32(a8 + 0); /* 000e: l32i.n a8, a8, 0 */
  a10 = MEM32(a8 + 404); /* 0010: l32i a10, a8, 0x194 */
  ((int32_t(*)())a10)(a2, a3, a4, a5); /* 0013: callx8 a10 */ /* indirect */
  a8 = 0x1; /* 0016: movi a8, 1 */
  if (a10 == 0) goto L_7a; /* 0019: beqz a10, 7a <pm_is_in_wifi_slice_threshold+0x72> */
  a9 = (uint32_t)&g_pm; /* 001c: l32r a9, 4 <pm_is_in_wifi_slice_threshold-0x4> (0 <pm_is_in_wifi_slice_threshold-0x8>) */ /* literal @0x4: g_pm */
  a11 = 0x0; /* 001f: movi a11, 0 */
  a8 = MEM32(a9 + 108); /* 0022: l32i a8, a9, 108 */
  a10 = MEM32(a9 + 104); /* 0025: l32i a10, a9, 104 */
  if (a3 < a8) goto L_31; /* 0028: bltu a3, a8, 31 <pm_is_in_wifi_slice_threshold+0x29> */
  if (a8 != a3) goto L_78; /* 002b: bne a8, a3, 78 <pm_is_in_wifi_slice_threshold+0x70> */
  if (a2 >= a10) goto L_78; /* 002e: bgeu a2, a10, 78 <pm_is_in_wifi_slice_threshold+0x70> */
L_31:;
  a12 = a10 - a2; /* 0031: sub a12, a10, a2 */
  a13 = 0x1; /* 0034: movi a13, 1 */
  if (a10 < a12) goto L_3d; /* 0037: bltu a10, a12, 3d <pm_is_in_wifi_slice_threshold+0x35> */
  a13 = 0x0; /* 003a: movi a13, 0 */
L_3d:;
  a8 = a8 - a3; /* 003d: sub a8, a8, a3 */
  a8 = a8 - a13; /* 0040: sub a8, a8, a13 */
  if (a11 != a8) goto L_4c; /* 0043: bne a11, a8, 4c <pm_is_in_wifi_slice_threshold+0x44> */
  a8 = 0x0; /* 0046: movi a8, 0 */
  if (a12 < a4) goto L_7a; /* 0049: bltu a12, a4, 7a <pm_is_in_wifi_slice_threshold+0x72> */
L_4c:;
  a3 = a9 + ((0x200) << 8); /* 004c: addmi a3, a9, 0x200 */
  a3 = MEM8(a3 + 31); /* 004f: l8ui a3, a3, 31 */
  a8 = 0x1; /* 0052: movi.n a8, 1 */
  if (a3 == 0) goto L_7a; /* 0054: beqz.n a3, 7a <pm_is_in_wifi_slice_threshold+0x72> */
  a8 = MEM32(a9 + 572); /* 0056: l32i a8, a9, 0x23c */
  a10 = MEM32(a9 + 568); /* 0059: l32i a10, a9, 0x238 */
  if (a8 != 0) goto L_61; /* 005c: bnez.n a8, 61 <pm_is_in_wifi_slice_threshold+0x59> */
  if (a2 >= a10) goto L_7a; /* 005e: bgeu a2, a10, 7a <pm_is_in_wifi_slice_threshold+0x72> */
L_61:;
  a2 = a10 - a2; /* 0061: sub a2, a10, a2 */
  a9 = 0x1; /* 0064: movi a9, 1 */
  if (a10 < a2) goto L_6d; /* 0067: bltu a10, a2, 6d <pm_is_in_wifi_slice_threshold+0x65> */
  a9 = 0x0; /* 006a: movi a9, 0 */
L_6d:;
  a9 = a8 - a9; /* 006d: sub a9, a8, a9 */
  a8 = 0x1; /* 0070: movi.n a8, 1 */
  if (a11 != a9) goto L_7a; /* 0072: bne a11, a9, 7a <pm_is_in_wifi_slice_threshold+0x72> */
  if (a2 >= a4) goto L_7a; /* 0075: bgeu a2, a4, 7a <pm_is_in_wifi_slice_threshold+0x72> */
L_78:;
  a8 = 0x0; /* 0078: movi.n a8, 0 */
L_7a:;
  a2 = 0x0; /* 007a: extui a2, a8, 0, 1 */
  return (int32_t)a2; /* 007d: retw.n  */
}

/* pm_coex_schm_process @ pm.o 00000030 size 470B bind GLOBAL
 * Calls: pm_coex_schm_overall_period_get, pm_coex_separate_connectionless_window, pm_disconnected_wake, pm_is_sleeping, ppCheckTxIdle, wifi_gpio_debug, .text.hal_pm_unblock_txq[got] | Data refs: g_osi_funcs_p, g_pm, pm_coex_schm_overall_period_get, pm_coex_separate_connectionless_window, pm_disconnected_wake, pm_is_sleeping, ppCheckTxIdle, wifi_gpio_debug, .text.hal_pm_unblock_txq
 *   MMIO: 0x3FF73CB8
 *   funcdb v3: 6 call(s), 8 ref(s); disasm: 8 call(s), 9 data ref(s)
 * Fidelity: low - 173 instr, 19 branches, 14 indirect; call-sequence + MMIO skeleton */
int32_t pm_coex_schm_process(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pm_coex_schm_process; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_30:;
  /* 0030: entry a1, 48 */
  a3 = (uint32_t)&g_osi_funcs_p; /* 0033: l32r a3, 0 <pm_coex_schm_process-0x30> (0 <pm_coex_schm_process-0x30>) */ /* literal @0x0: g_osi_funcs_p */
  a2 = MEM32(a3 + 0); /* 0036: l32i.n a2, a3, 0 */
  a10 = MEM32(a2 + 452); /* 0038: l32i a10, a2, 0x1c4 */
  ((int32_t(*)())a10)(a2, a3, a4, a5); /* 003b: callx8 a10 */ /* indirect */
  a6 = a10; /* 003e: mov.n a6, a10 */
  if (a10 == 0) goto L_201; /* 0040: beqz a10, 201 <pm_coex_schm_process+0x1d1> */
  a2 = MEM32(a3 + 0); /* 0043: l32i.n a2, a3, 0 */
  a5 = 0x1; /* 0045: movi.n a5, 1 */
  a10 = MEM32(a2 + 272); /* 0047: l32i a10, a2, 0x110 */
  ((int32_t(*)())a10)(a2, a3, a4, a5); /* 004a: callx8 a10 */ /* indirect */
  a7 = a10; /* 004d: mov.n a7, a10 */
  a2 = MEM32(a3 + 0); /* 004f: l32i a2, a3, 0 */
  a10 = MEM32(a2 + 448); /* 0052: l32i a10, a2, 0x1c0 */
  MEM32(a1 + 4) = a11; /* 0055: s32i a11, a1, 4 */
  MEMW(); /* 0058: memw  */
  ((int32_t(*)())a10)(a2, a3, a4, a5); /* 005b: callx8 a10 */ /* indirect */
  a4 = a10; /* 005e: mov.n a4, a10 */
  a2 = MEM32(a3 + 0); /* 0060: l32i.n a2, a3, 0 */
  a10 = MEM32(a2 + 444); /* 0062: l32i a10, a2, 0x1bc */
  ((int32_t(*)())a10)(a2, a3, a4, a5); /* 0065: callx8 a10 */ /* indirect */
  a2 = MEM8(a6 + 0); /* 0068: l8ui a2, a6, 0 */
  a10 = (uint32_t)((uint64_t)a2 * a10); /* 006b: mull a10, a2, a10 */
  a10 = (uint32_t)((uint64_t)a10 * a4); /* 006e: mull a10, a10, a4 */
  a11 = MEM32(a1 + 4); /* 0071: l32i.n a11, a1, 4 */
  a4 = a7 + a10; /* 0073: add.n a4, a7, a10 */
  MEM32(a1 + 0) = a10; /* 0075: s32i a10, a1, 0 */
  if (a4 < a7) goto L_7e; /* 0078: bltu a4, a7, 7e <pm_coex_schm_process+0x4e> */
  a5 = 0x0; /* 007b: movi a5, 0 */
L_7e:;
  a5 = a5 + a11; /* 007e: add.n a5, a5, a11 */
  a2 = MEM8(a6 + 1); /* 0080: l8ui a2, a6, 1 */
  if ((a2 >> 1) & 1) goto L_89; /* 0083: bbsi a2, 1, 89 <pm_coex_schm_process+0x59> */
  goto L_152; /* 0086: j 152 <pm_coex_schm_process+0x122> */
L_89:;
  a7 = 0xFFFFFFBF; /* 0089: movi a7, -65 */
  a2 = (uint32_t)&g_pm; /* 008c: l32r a2, 4 <pm_coex_schm_process-0x2c> (0 <pm_coex_schm_process-0x30>) */ /* literal @0x4: g_pm */
  a8 = MEM32(a2 + 400); /* 008f: l32i a8, a2, 0x190 */
  a7 = a7 & a8; /* 0092: and a7, a7, a8 */
  if (a7 != 0) goto L_d6; /* 0095: bnez.n a7, d6 <pm_coex_schm_process+0xa6> */
  a10 = 0x1; /* 0097: movi.n a10, 1 */
  MEMW(); /* 0099: memw  */
  a8 = (uint32_t)&ppCheckTxIdle; /* 009c: l32r a8, 10 <pm_coex_schm_process-0x20> (0 <pm_coex_schm_process-0x30>) */ /* literal: GOT slot for ppCheckTxIdle */
  ppCheckTxIdle(a2, a3, a4, a5); /* call via literal slot */ /* 009f: callx8 a8 */
  if (a10 == 0) goto L_c6; /* 00a2: beqz.n a10, c6 <pm_coex_schm_process+0x96> */
  a8 = MEM32(a3 + 0); /* 00a4: l32i.n a8, a3, 0 */
  a9 = MEM32(a8 + 412); /* 00a6: l32i a9, a8, 0x19c */
  a10 = MEM32(a8 + 272); /* 00a9: l32i a10, a8, 0x110 */
  MEM32(a1 + 4) = a9; /* 00ac: s32i.n a9, a1, 4 */
  MEMW(); /* 00ae: memw  */
  ((int32_t(*)())a10)(a2, a3, a4, a5); /* 00b1: callx8 a10 */ /* indirect */
  a12 = a4 - a10; /* 00b4: sub a12, a4, a10 */
  a11 = a7; /* 00b7: mov.n a11, a7 */
  a10 = 0x1; /* 00b9: movi.n a10, 1 */
  a9 = MEM32(a1 + 4); /* 00bb: l32i.n a9, a1, 4 */
  ((int32_t(*)())a9)(a2, a3, a4, a5); /* 00bd: callx8 a9 */ /* indirect */
  a8 = (uint32_t)&pm_disconnected_wake; /* 00c0: l32r a8, 14 <pm_coex_schm_process-0x1c> (0 <pm_coex_schm_process-0x30>) */ /* literal: GOT slot for pm_disconnected_wake */
  pm_disconnected_wake(a2, a3, a4, a5); /* call via literal slot */ /* 00c3: callx8 a8 */
L_c6:;
  a7 = 0x1; /* 00c6: movi.n a7, 1 */
  MEM8(a2 + 24) = a7; /* 00c8: s8i a7, a2, 24 */
  MEMW(); /* 00cb: memw  */
  MEMW(); /* 00ce: memw  */
  goto L_ed; /* 00d1: j ed <pm_coex_schm_process+0xbd> */
  /* 00d4: .byte 00 */
  /* 00d5: .byte 00 */
L_d6:;
  a8 = MEM32(a3 + 0); /* 00d6: l32i.n a8, a3, 0 */
  a10 = MEM32(a8 + 272); /* 00d8: l32i a10, a8, 0x110 */
  a7 = MEM32(a8 + 412); /* 00db: l32i a7, a8, 0x19c */
  ((int32_t(*)())a10)(a2, a3, a4, a5); /* 00de: callx8 a10 */ /* indirect */
  a12 = a4 - a10; /* 00e1: sub a12, a4, a10 */
  a11 = 0x0; /* 00e4: movi a11, 0 */
  a10 = 0x1; /* 00e7: movi a10, 1 */
  ((int32_t(*)())a7)(a2, a3, a4, a5); /* 00ea: callx8 a7 */ /* indirect */
L_ed:;
  MEM32(a2 + 96) = a4; /* 00ed: s32i a4, a2, 96 */
  MEM32(a2 + 100) = a5; /* 00f0: s32i a5, a2, 100 */
  MEMW(); /* 00f3: memw  */
  a8 = (uint32_t)&pm_coex_schm_overall_period_get; /* 00f6: l32r a8, 18 <pm_coex_schm_process-0x18> (0 <pm_coex_schm_process-0x30>) */ /* literal: GOT slot for pm_coex_schm_overall_period_get */
  pm_coex_schm_overall_period_get(a2, a3, a4, a5); /* call via literal slot */ /* 00f9: callx8 a8 */
  a7 = 0x1; /* 00fc: or a7, a10, a10 */
  a8 = MEM32(a3 + 0); /* 00ff: l32i a8, a3, 0 */
  a10 = MEM32(a8 + 444); /* 0102: l32i a10, a8, 0x1bc */
  ((int32_t(*)())a10)(a2, a3, a4, a5); /* 0105: callx8 a10 */ /* indirect */
  a10 = (uint32_t)((uint64_t)a7 * a10); /* 0108: mull a10, a7, a10 */
  a7 = 0x1; /* 010b: movi.n a7, 1 */
  a9 = MEM32(a1 + 0); /* 010d: l32i.n a9, a1, 0 */
  a10 = (a10 << 4) + a10; /* 010f: addx4 a10, a10, a10 */
  a10 = (a10 << 4) + a10; /* 0112: addx4 a10, a10, a10 */
  a8 = a10 << (2 & 31); /* 0115: slli a8, a10, 2 */
  a10 = a9 - (a10 << 4) /* verify order vs disasm */; /* 0118: subx4 a10, a10, a9 */
  if (a8 < a10) goto L_120; /* 011b: bltu a8, a10, 120 <pm_coex_schm_process+0xf0> */
  a7 = 0x0; /* 011e: movi.n a7, 0 */
L_120:;
  a7 = 0x0; /* 0120: neg a7, a7 */
  MEM32(a2 + 432) = a10; /* 0123: s32i a10, a2, 0x1b0 */
  MEM32(a2 + 436) = a7; /* 0126: s32i a7, a2, 0x1b4 */
  MEMW(); /* 0129: memw  */
  a8 = (uint32_t)&pm_coex_separate_connectionless_window; /* 012c: l32r a8, 1c <pm_coex_schm_process-0x14> (0 <pm_coex_schm_process-0x30>) */ /* literal: GOT slot for pm_coex_separate_connectionless_window */
  pm_coex_separate_connectionless_window(a2, a3, a4, a5); /* call via literal slot */ /* 012f: callx8 a8 */
  a8 = (uint32_t)&pm_is_sleeping; /* 0132: l32r a8, 20 <pm_coex_schm_process-0x10> (0 <pm_coex_schm_process-0x30>) */ /* literal: GOT slot for pm_is_sleeping */
  pm_is_sleeping(a2, a3, a4, a5); /* call via literal slot */ /* 0135: callx8 a8 */
  if (a10 != 0) goto L_152; /* 0138: bnez.n a10, 152 <pm_coex_schm_process+0x122> */
  a7 = MEM8(a2 + 13); /* 013a: l8ui a7, a2, 13 */
  if (a7 == 0) goto L_14c; /* 013d: beqz.n a7, 14c <pm_coex_schm_process+0x11c> */
  a7 = MEM8(a2 + 14); /* 013f: l8ui a7, a2, 14 */
  if (a7 == 0) goto L_152; /* 0142: beqz.n a7, 152 <pm_coex_schm_process+0x122> */
  a2 = a2 + ((0x200) << 8); /* 0144: addmi a2, a2, 0x200 */
  a2 = MEM8(a2 + 30); /* 0147: l8ui a2, a2, 30 */
  if (a2 != 0) goto L_152; /* 014a: bnez.n a2, 152 <pm_coex_schm_process+0x122> */
L_14c:;
  a8 = (uint32_t)&hal_pm_unblock_txq; /* 014c: l32r a8, 24 <pm_coex_schm_process-0xc> (8 <pm_coex_schm_process-0x28>) */ /* literal: GOT slot for .text.hal_pm_unblock_txq */
  hal_pm_unblock_txq(a2, a3, a4, a5); /* call via literal slot */ /* 014f: callx8 a8 */
L_152:;
  a2 = MEM8(a6 + 1); /* 0152: l8ui a2, a6, 1 */
  if (!((a2 >> 0) & 1)) goto L_1c4; /* 0155: bbci a2, 0, 1c4 <pm_coex_schm_process+0x194> */
  a11 = 0x0; /* 0158: movi a11, 0 */
  a10 = 0x7; /* 015b: movi a10, 7 */
  a8 = (uint32_t)&wifi_gpio_debug; /* 015e: l32r a8, 28 <pm_coex_schm_process-0x8> (0 <pm_coex_schm_process-0x30>) */ /* literal: GOT slot for wifi_gpio_debug */
  wifi_gpio_debug(a2, a3, a4, a5); /* call via literal slot */ /* 0161: callx8 a8 */
  a8 = (uint32_t)&g_pm; /* 0164: l32r a8, 4 <pm_coex_schm_process-0x2c> (0 <pm_coex_schm_process-0x30>) */ /* literal @0x4: g_pm */
  a9 = MEM8(a8 + 13); /* 0167: l8ui a9, a8, 13 */
  if (a9 == 0) goto L_17e; /* 016a: beqz.n a9, 17e <pm_coex_schm_process+0x14e> */
  a7 = 0x1; /* 016c: movi.n a7, 1 */
  a2 = MEM32(a8 + 56); /* 016e: l32i.n a2, a8, 56 */
  a2 = a4 - a2; /* 0170: sub a2, a4, a2 */
  if (a4 < a2) goto L_178; /* 0173: bltu a4, a2, 178 <pm_coex_schm_process+0x148> */
  a7 = 0x0; /* 0176: movi.n a7, 0 */
L_178:;
  a5 = a5 - a7; /* 0178: sub a5, a5, a7 */
  goto L_18e; /* 017b: j 18e <pm_coex_schm_process+0x15e> */
L_17e:;
  a2 = 0xFFFFFC18; /* 017e: movi a2, 0xfffffc18 */
  a2 = a4 + a2; /* 0181: add.n a2, a4, a2 */
  a7 = 0x1; /* 0183: movi.n a7, 1 */
  if (a2 < a4) goto L_18a; /* 0185: bltu a2, a4, 18a <pm_coex_schm_process+0x15a> */
  a7 = a9; /* 0188: mov.n a7, a9 */
L_18a:;
  a5 = a5 + (-1); /* 018a: addi.n a5, a5, -1 */
  a5 = a7 + a5; /* 018c: add.n a5, a7, a5 */
L_18e:;
  MEM32(a8 + 108) = a5; /* 018e: s32i a5, a8, 108 */
  a5 = MEM32(a3 + 0); /* 0191: l32i.n a5, a3, 0 */
  MEM32(a8 + 104) = a2; /* 0193: s32i a2, a8, 104 */
  a2 = (uint32_t)&g_pm; /* 0196: l32r a2, 8 <pm_coex_schm_process-0x28> (0 <pm_coex_schm_process-0x30>) */ /* literal @0x8: g_pm */
  a10 = a2 | a2; /* 0199: or a10, a2, a2 */
  a5 = MEM32(a5 + 236); /* 019c: l32i a5, a5, 236 */
  MEM32(a1 + 4) = a8; /* 019f: s32i a8, a1, 4 */
  MEMW(); /* 01a2: memw  */
  ((int32_t(*)())a5)(a2, a3, a4, a5); /* 01a5: callx8 a5 */ /* indirect */
  a9 = MEM32(a3 + 0); /* 01a8: l32i.n a9, a3, 0 */
  a8 = MEM32(a1 + 4); /* 01aa: l32i a8, a1, 4 */
  a10 = MEM32(a9 + 272); /* 01ad: l32i a10, a9, 0x110 */
  a5 = MEM32(a8 + 104); /* 01b0: l32i a5, a8, 104 */
  a7 = MEM32(a9 + 248); /* 01b3: l32i a7, a9, 248 */
  ((int32_t(*)())a10)(a2, a3, a4, a5); /* 01b6: callx8 a10 */ /* indirect */
  a11 = a5 - a10; /* 01b9: sub a11, a5, a10 */
  a12 = 0x0; /* 01bc: movi.n a12, 0 */
  a10 = a2 | a2; /* 01be: or a10, a2, a2 */
  ((int32_t(*)())a7)(a2, a3, a4, a5); /* 01c1: callx8 a7 */ /* indirect */
L_1c4:;
  a2 = MEM8(a6 + 1); /* 01c4: l8ui a2, a6, 1 */
  if (!((a2 >> 2) & 1)) goto L_201; /* 01c7: bbci a2, 2, 201 <pm_coex_schm_process+0x1d1> */
  a8 = (uint32_t)&pm_is_sleeping; /* 01ca: l32r a8, 2c <pm_coex_schm_process-0x4> (0 <pm_coex_schm_process-0x30>) */ /* literal: GOT slot for pm_is_sleeping */
  pm_is_sleeping(a2, a3, a4, a5); /* call via literal slot */ /* 01cd: callx8 a8 */
  a2 = a10; /* 01d0: mov.n a2, a10 */
  if (a10 != 0) goto L_1ec; /* 01d2: bnez a10, 1ec <pm_coex_schm_process+0x1bc> */
  a3 = MEM32(a3 + 0); /* 01d5: l32i a3, a3, 0 */
  a10 = MEM32(a3 + 272); /* 01d8: l32i a10, a3, 0x110 */
  a5 = MEM32(a3 + 412); /* 01db: l32i a5, a3, 0x19c */
  ((int32_t(*)())a10)(a2, a3, a4, a5); /* 01de: callx8 a10 */ /* indirect */
  a12 = a4 - a10; /* 01e1: sub a12, a4, a10 */
  a11 = a2; /* 01e4: mov.n a11, a2 */
  a10 = 0x1; /* 01e6: movi a10, 1 */
  ((int32_t(*)())a5)(a2, a3, a4, a5); /* 01e9: callx8 a5 */ /* indirect */
L_1ec:;
  a4 = 0x3FF73CB8; /* 01ec: l32r a4, c <pm_coex_schm_process-0x24> (3ff73cb8 <pm_attach+0x3ff73c34>) */ /* MMIO base */ @0xC
  a3 = 0x7; /* 01ef: movi.n a3, 7 */
  a3 = 0xE0000; /* 01f1: slli a3, a3, 17 */
  MEMW(); /* 01f4: memw  */
  a2 = REG32(0x3FF73CB8); /* 01f7: l32i.n a2, a4, 0 */ /* MMIO read: base 0x3FF73CB8+0 */
  a2 = a2 | a3; /* 01f9: or a2, a2, a3 */
  MEMW(); /* 01fc: memw  */
  REG32(0x3FF73CB8) = a2; /* 01ff: s32i.n a2, a4, 0 */ /* MMIO write: base 0x3FF73CB8+0 */
L_201:;
  MEMW(); /* 0201: memw  */
  return (int32_t)a2; /* 0204: retw.n  */
}

/* pm_coex_schm_process_restart @ pm.o 00000004 size 16B bind GLOBAL
 * Calls: none | Data refs: g_osi_funcs_p
 *   MMIO: none
 *   funcdb v3: 0 call(s), 1 ref(s); disasm: 0 call(s), 1 data ref(s)
 * Fidelity: medium - 6 instr, 0 branches, calls resolved */
int32_t pm_coex_schm_process_restart(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pm_coex_schm_process_restart; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a8 = (uint32_t)&g_osi_funcs_p; /* 0007: l32r a8, 0 <pm_coex_schm_process_restart-0x4> (0 <pm_coex_schm_process_restart-0x4>) */ /* literal @0x0: g_osi_funcs_p */
  a8 = MEM32(a8 + 0); /* 000a: l32i.n a8, a8, 0 */
  a10 = MEM32(a8 + 456); /* 000c: l32i a10, a8, 0x1c8 */
  ((int32_t(*)())a10)(a2, a3, a4, a5); /* 000f: callx8 a10 */ /* indirect */
  return (int32_t)a2; /* 0012: retw.n  */
}

/* pm_coex_go_to_sleep @ pm.o 0000002c size 271B bind GLOBAL
 * Calls: pm_enable_disconnected_sleep_delay_timer, pm_enable_sleep_delay_timer, pm_go_to_sleep, ppCheckTxConnTrafficIdle, ppCheckTxIdle, wifi_gpio_debug, g_osi_funcs_p[got] | Data refs: g_osi_funcs_p, g_pm, g_pm_cfg, pm_enable_disconnected_sleep_delay_timer, pm_enable_sleep_delay_timer, pm_go_to_sleep, ppCheckTxConnTrafficIdle, ppCheckTxIdle, wifi_gpio_debug
 *   MMIO: 0x3FF73CB8
 *   funcdb v3: 6 call(s), 9 ref(s); disasm: 7 call(s), 9 data ref(s)
 * Fidelity: low - 102 instr, 20 branches, 3 indirect; call-sequence + MMIO skeleton */
int32_t pm_coex_go_to_sleep(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pm_coex_go_to_sleep; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_2c:;
  /* 002c: entry a1, 32 */
  a5 = (uint32_t)&g_osi_funcs_p; /* 002f: l32r a5, 0 <pm_coex_go_to_sleep-0x2c> (0 <pm_coex_go_to_sleep-0x2c>) */ /* literal @0x0: g_osi_funcs_p */
  a2 = (a2 >> 0) & 0xFF; /* 0032: extui a2, a2, 0, 8 */
  a3 = MEM32(a5 + 0); /* 0035: l32i.n a3, a5, 0 */
  a10 = MEM32(a3 + 272); /* 0037: l32i a10, a3, 0x110 */
  ((int32_t(*)())a10)(a2, a3, a4, a5); /* 003a: callx8 a10 */ /* indirect */
  a3 = (uint32_t)&g_pm; /* 003d: l32r a3, 4 <pm_coex_go_to_sleep-0x28> (0 <pm_coex_go_to_sleep-0x2c>) */ /* literal @0x4: g_pm */
  a4 = MEM8(a3 + 14); /* 0040: l8ui a4, a3, 14 */
  if (a4 == 0) goto L_139; /* 0043: beqz a4, 139 <pm_coex_go_to_sleep+0x10d> */
  a6 = MEM8(a3 + 15); /* 0046: l8ui a6, a3, 15 */
  if (a6 != 0) goto L_139; /* 0049: bnez a6, 139 <pm_coex_go_to_sleep+0x10d> */
  a10 = 0x7; /* 004c: movi.n a10, 7 */
  a11 = 0x1; /* 004e: movi.n a11, 1 */
  a8 = (uint32_t)&wifi_gpio_debug; /* 0050: l32r a8, 14 <pm_coex_go_to_sleep-0x18> (0 <pm_coex_go_to_sleep-0x2c>) */ /* literal: GOT slot for wifi_gpio_debug */
  wifi_gpio_debug(a2, a3, a4, a5); /* call via literal slot */ /* 0053: callx8 a8 */
  a4 = MEM32(a5 + 0); /* 0056: l32i.n a4, a5, 0 */
  a10 = MEM32(a4 + 404); /* 0058: l32i a10, a4, 0x194 */
  ((int32_t(*)())a10)(a2, a3, a4, a5); /* 005b: callx8 a10 */ /* indirect */
  if (a10 == 0) goto L_139; /* 005e: beqz a10, 139 <pm_coex_go_to_sleep+0x10d> */
  a8 = 0xFFFFFFBF; /* 0061: movi a8, -65 */
  a4 = MEM32(a3 + 400); /* 0064: l32i a4, a3, 0x190 */
  a8 = a4 & a8; /* 0067: and a8, a4, a8 */
  if (a8 != 0) goto L_bd; /* 006a: bnez a8, bd <pm_coex_go_to_sleep+0x91> */
  if (a2 == 0) goto L_75; /* 006d: beqz.n a2, 75 <pm_coex_go_to_sleep+0x49> */
  MEM8(a3 + 24) = a8; /* 006f: s8i a8, a3, 24 */
  MEMW(); /* 0072: memw  */
L_75:;
  if (a4 != 0) goto L_a5; /* 0075: bnez.n a4, a5 <pm_coex_go_to_sleep+0x79> */
  a10 = 0x1; /* 0077: movi.n a10, 1 */
  MEMW(); /* 0079: memw  */
  a8 = (uint32_t)&ppCheckTxIdle; /* 007c: l32r a8, 18 <pm_coex_go_to_sleep-0x14> (0 <pm_coex_go_to_sleep-0x2c>) */ /* literal: GOT slot for ppCheckTxIdle */
  ppCheckTxIdle(a2, a3, a4, a5); /* call via literal slot */ /* 007f: callx8 a8 */
  if (a10 == 0) goto L_a5; /* 0082: beqz.n a10, a5 <pm_coex_go_to_sleep+0x79> */
  a6 = MEM32(a5 + 0); /* 0084: l32i.n a6, a5, 0 */
  a2 = (uint32_t)&g_pm; /* 0086: l32r a2, 8 <pm_coex_go_to_sleep-0x24> (0 <pm_coex_go_to_sleep-0x2c>) */ /* literal @0x8: g_pm */
  a10 = a2; /* 0089: mov.n a10, a2 */
  a6 = MEM32(a6 + 236); /* 008b: l32i a6, a6, 236 */
  ((int32_t(*)())a6)(a2, a3, a4, a5); /* 008e: callx8 a6 */ /* indirect */
  a11 = 0x3E8; /* 0091: movi a11, 0x3e8 */
  a12 = a4; /* 0094: mov.n a12, a4 */
  a5 = MEM32(a5 + 0); /* 0096: l32i.n a5, a5, 0 */
  a10 = a2; /* 0098: mov.n a10, a2 */
  a6 = MEM32(a3 + 432); /* 009a: l32i a6, a3, 0x1b0 */
  a11 = a11 + a6; /* 009d: add.n a11, a11, a6 */
  a5 = MEM32(a5 + 248); /* 009f: l32i a5, a5, 248 */
  g_osi_funcs_p(a2, a3, a4, a5); /* call via literal slot */ /* 00a2: callx8 a5 */
L_a5:;
  a3 = a3 + ((0x100) << 8); /* 00a5: addmi a3, a3, 0x100 */
  a2 = MEM8(a3 + 29); /* 00a8: l8ui a2, a3, 29 */
  if (a2 == 2) goto L_b1; /* 00ab: beqi a2, 2, b1 <pm_coex_go_to_sleep+0x85> */
  goto L_139; /* 00ae: j 139 <pm_coex_go_to_sleep+0x10d> */
L_b1:;
  a8 = (uint32_t)&pm_enable_disconnected_sleep_delay_timer; /* 00b1: l32r a8, 1c <pm_coex_go_to_sleep-0x10> (0 <pm_coex_go_to_sleep-0x2c>) */ /* literal: GOT slot for pm_enable_disconnected_sleep_delay_timer */
  pm_enable_disconnected_sleep_delay_timer(a2, a3, a4, a5); /* call via literal slot */ /* 00b4: callx8 a8 */
  goto L_139; /* 00b7: j 139 <pm_coex_go_to_sleep+0x10d> */
  /* 00ba: .byte 00 */
  /* 00bb: .byte 00 */
  /* 00bc: .byte 00 */
L_bd:;
  if (a4 != 4) goto L_139; /* 00bd: bnei a4, 4, 139 <pm_coex_go_to_sleep+0x10d> */
  if (a2 == 0) goto L_c9; /* 00c0: beqz a2, c9 <pm_coex_go_to_sleep+0x9d> */
  MEM8(a3 + 24) = a6; /* 00c3: s8i a6, a3, 24 */
  MEMW(); /* 00c6: memw  */
L_c9:;
  a2 = a3 + ((0x200) << 8); /* 00c9: addmi a2, a3, 0x200 */
  a5 = 0x7; /* 00cc: movi.n a5, 7 */
  a5 = 0xE0000; /* 00ce: slli a5, a5, 17 */
  a4 = MEM8(a3 + 17); /* 00d1: l8ui a4, a3, 17 */
  a8 = 0x3FF73CB8; /* 00d4: l32r a8, c <pm_coex_go_to_sleep-0x20> (3ff73cb8 <pm_attach+0x3ff73c34>) */ /* MMIO base */ @0xC
  MEM8(a2 + 29) = a4; /* 00d7: s8i a4, a2, 29 */
  a4 = 0x0; /* 00da: movi.n a4, 0 */
  MEM8(a3 + 17) = a4; /* 00dc: s8i a4, a3, 17 */
  MEM8(a3 + 18) = a4; /* 00df: s8i a4, a3, 18 */
  MEMW(); /* 00e2: memw  */
  MEMW(); /* 00e5: memw  */
  a4 = REG32(0x3FF73CB8); /* 00e8: l32i.n a4, a8, 0 */ /* MMIO read: base 0x3FF73CB8+0 */
  a4 = a4 | a5; /* 00ea: or a4, a4, a5 */
  MEMW(); /* 00ed: memw  */
  REG32(0x3FF73CB8) = a4; /* 00f0: s32i.n a4, a8, 0 */ /* MMIO write: base 0x3FF73CB8+0 */
  a4 = MEM8(a3 + 1); /* 00f2: l8ui a4, a3, 1 */
  if (a4 == 0) goto L_fc; /* 00f5: beqz.n a4, fc <pm_coex_go_to_sleep+0xd0> */
  a2 = MEM8(a3 + 19); /* 00f7: l8ui a2, a3, 19 */
  if (a2 == 0) goto L_130; /* 00fa: beqz.n a2, 130 <pm_coex_go_to_sleep+0x104> */
L_fc:;
  a2 = (uint32_t)&g_pm_cfg; /* 00fc: l32r a2, 10 <pm_coex_go_to_sleep-0x1c> (0 <pm_coex_go_to_sleep-0x2c>) */ /* literal @0x10: g_pm_cfg */
  a2 = MEM8(a2 + 0); /* 00ff: l8ui a2, a2, 0 */
  if (a2 == 0) goto L_115; /* 0102: beqz.n a2, 115 <pm_coex_go_to_sleep+0xe9> */
L_104:;
  a2 = 0x1; /* 0104: movi.n a2, 1 */
  MEM8(a3 + 25) = a2; /* 0106: s8i a2, a3, 25 */
  MEMW(); /* 0109: memw  */
  MEMW(); /* 010c: memw  */
  goto L_127; /* 010f: j 127 <pm_coex_go_to_sleep+0xfb> */
  /* 0112: .byte 00 */
  /* 0113: .byte 00 */
  /* 0114: .byte 00 */
L_115:;
  a2 = MEM32(a3 + 64); /* 0115: l32i a2, a3, 64 */
  if (a2 != 0) goto L_104; /* 0118: bnez a2, 104 <pm_coex_go_to_sleep+0xd8> */
  a10 = 0x1; /* 011b: movi a10, 1 */
  a8 = (uint32_t)&ppCheckTxConnTrafficIdle; /* 011e: l32r a8, 20 <pm_coex_go_to_sleep-0xc> (0 <pm_coex_go_to_sleep-0x2c>) */ /* literal: GOT slot for ppCheckTxConnTrafficIdle */
  ppCheckTxConnTrafficIdle(a2, a3, a4, a5); /* call via literal slot */ /* 0121: callx8 a8 */
  if (a10 != 0) goto L_104; /* 0124: bnez a10, 104 <pm_coex_go_to_sleep+0xd8> */
L_127:;
  a8 = (uint32_t)&pm_go_to_sleep; /* 0127: l32r a8, 24 <pm_coex_go_to_sleep-0x8> (0 <pm_coex_go_to_sleep-0x2c>) */ /* literal: GOT slot for pm_go_to_sleep */
  pm_go_to_sleep(a2, a3, a4, a5); /* call via literal slot */ /* 012a: callx8 a8 */
  goto L_139; /* 012d: j 139 <pm_coex_go_to_sleep+0x10d> */
L_130:;
  if (a4 != 1) goto L_139; /* 0130: bnei a4, 1, 139 <pm_coex_go_to_sleep+0x10d> */
  a8 = (uint32_t)&pm_enable_sleep_delay_timer; /* 0133: l32r a8, 28 <pm_coex_go_to_sleep-0x4> (0 <pm_coex_go_to_sleep-0x2c>) */ /* literal: GOT slot for pm_enable_sleep_delay_timer */
  pm_enable_sleep_delay_timer(a2, a3, a4, a5); /* call via literal slot */ /* 0136: callx8 a8 */
L_139:;
  return (int32_t)a2; /* 0139: retw.n  */
}

/* pm_coex_slice_timeout_process @ pm.o 00000004 size 14B bind GLOBAL
 * Calls: pm_coex_go_to_sleep | Data refs: pm_coex_go_to_sleep
 *   MMIO: none
 *   funcdb v3: 1 call(s), 1 ref(s); disasm: 1 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t pm_coex_slice_timeout_process(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pm_coex_slice_timeout_process; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a10 = 0x1; /* 0007: movi a10, 1 */
  a8 = (uint32_t)&pm_coex_go_to_sleep; /* 000a: l32r a8, 0 <pm_coex_slice_timeout_process-0x4> (0 <pm_coex_slice_timeout_process-0x4>) */ /* literal: GOT slot for pm_coex_go_to_sleep */
  pm_coex_go_to_sleep(a2, a3, a4, a5); /* call via literal slot */ /* 000d: callx8 a8 */
  return (int32_t)a2; /* 0010: retw.n  */
}

/* pm_active_timeout_process @ pm.o 00000014 size 71B bind GLOBAL
 * Calls: pm_enable_active_timer, pm_go_to_sleep, ppCheckTxIdle | Data refs: g_pm, g_pm_cnt, pm_enable_active_timer, pm_go_to_sleep, ppCheckTxIdle
 *   MMIO: none
 *   funcdb v3: 3 call(s), 5 ref(s); disasm: 3 call(s), 5 data ref(s)
 * Fidelity: medium - 27 instr, 7 branches, calls resolved */
int32_t pm_active_timeout_process(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pm_active_timeout_process; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_14:;
  /* 0014: entry a1, 32 */
  a9 = (uint32_t)&g_pm_cnt; /* 0017: l32r a9, 0 <pm_active_timeout_process-0x14> (0 <pm_active_timeout_process-0x14>) */ /* literal @0x0: g_pm_cnt */
  a8 = MEM32(a9 + 20); /* 001a: l32i.n a8, a9, 20 */
  a8 = a8 + (1); /* 001c: addi.n a8, a8, 1 */
  MEM32(a9 + 20) = a8; /* 001e: s32i.n a8, a9, 20 */
  a8 = (uint32_t)&g_pm; /* 0020: l32r a8, 4 <pm_active_timeout_process-0x10> (0 <pm_active_timeout_process-0x14>) */ /* literal @0x4: g_pm */
  a9 = MEM8(a8 + 13); /* 0023: l8ui a9, a8, 13 */
  if (a9 == 0) goto L_59; /* 0026: beqz.n a9, 59 <pm_active_timeout_process+0x45> */
  a9 = MEM8(a8 + 14); /* 0028: l8ui a9, a8, 14 */
  if (a9 == 0) goto L_59; /* 002b: beqz.n a9, 59 <pm_active_timeout_process+0x45> */
  a9 = MEM8(a8 + 15); /* 002d: l8ui a9, a8, 15 */
  if (a9 != 0) goto L_59; /* 0030: bnez.n a9, 59 <pm_active_timeout_process+0x45> */
  a9 = MEM8(a8 + 1); /* 0032: l8ui a9, a8, 1 */
  if (a9 != 0) goto L_59; /* 0035: bnez.n a9, 59 <pm_active_timeout_process+0x45> */
  a8 = MEM8(a8 + 18); /* 0037: l8ui a8, a8, 18 */
  if (a8 == 0) goto L_48; /* 003a: beqz.n a8, 48 <pm_active_timeout_process+0x34> */
L_3c:;
  MEMW(); /* 003c: memw  */
  a8 = (uint32_t)&pm_enable_active_timer; /* 003f: l32r a8, 8 <pm_active_timeout_process-0xc> (0 <pm_active_timeout_process-0x14>) */ /* literal: GOT slot for pm_enable_active_timer */
  pm_enable_active_timer(a2, a3, a4, a5); /* call via literal slot */ /* 0042: callx8 a8 */
  goto L_59; /* 0045: j 59 <pm_active_timeout_process+0x45> */
L_48:;
  a10 = 0x1; /* 0048: movi.n a10, 1 */
  a8 = (uint32_t)&ppCheckTxIdle; /* 004a: l32r a8, c <pm_active_timeout_process-0x8> (0 <pm_active_timeout_process-0x14>) */ /* literal: GOT slot for ppCheckTxIdle */
  ppCheckTxIdle(a2, a3, a4, a5); /* call via literal slot */ /* 004d: callx8 a8 */
  if (a10 != 0) goto L_3c; /* 0050: bnez a10, 3c <pm_active_timeout_process+0x28> */
  a8 = (uint32_t)&pm_go_to_sleep; /* 0053: l32r a8, 10 <pm_active_timeout_process-0x4> (0 <pm_active_timeout_process-0x14>) */ /* literal: GOT slot for pm_go_to_sleep */
  pm_go_to_sleep(a2, a3, a4, a5); /* call via literal slot */ /* 0056: callx8 a8 */
L_59:;
  return (int32_t)a2; /* 0059: retw.n  */
}

/* pm_dream_timeout_process @ pm.o 00000008 size 26B bind GLOBAL
 * Calls: pm_enable_sleep_delay_timer | Data refs: g_pm, pm_enable_sleep_delay_timer
 *   MMIO: none
 *   funcdb v3: 1 call(s), 2 ref(s); disasm: 1 call(s), 2 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t pm_dream_timeout_process(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pm_dream_timeout_process; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_8:;
  /* 0008: entry a1, 32 */
  a8 = (uint32_t)&g_pm; /* 000b: l32r a8, 0 <pm_dream_timeout_process-0x8> (0 <pm_dream_timeout_process-0x8>) */ /* literal @0x0: g_pm */
  a9 = 0x0; /* 000e: movi a9, 0 */
  MEM8(a8 + 18) = a9; /* 0011: s8i a9, a8, 18 */
  MEMW(); /* 0014: memw  */
  MEMW(); /* 0017: memw  */
  a8 = (uint32_t)&pm_enable_sleep_delay_timer; /* 001a: l32r a8, 4 <pm_dream_timeout_process-0x4> (0 <pm_dream_timeout_process-0x8>) */ /* literal: GOT slot for pm_enable_sleep_delay_timer */
  pm_enable_sleep_delay_timer(a2, a3, a4, a5); /* call via literal slot */ /* 001d: callx8 a8 */
  return (int32_t)a2; /* 0020: retw.n  */
}

/* pm_sleep_delay_timeout_process @ pm.o 00000008 size 34B bind GLOBAL
 * Calls: pm_sleep | Data refs: g_pm, pm_sleep
 *   MMIO: none
 *   funcdb v3: 1 call(s), 2 ref(s); disasm: 1 call(s), 2 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t pm_sleep_delay_timeout_process(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pm_sleep_delay_timeout_process; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_8:;
  /* 0008: entry a1, 32 */
  a8 = (uint32_t)&g_pm; /* 000b: l32r a8, 0 <pm_sleep_delay_timeout_process-0x8> (0 <pm_sleep_delay_timeout_process-0x8>) */ /* literal @0x0: g_pm */
  a10 = 0x0; /* 000e: movi.n a10, 0 */
  a9 = a8 + ((0x100) << 8); /* 0010: addmi a9, a8, 0x100 */
  a8 = MEM8(a8 + 1); /* 0013: l8ui a8, a8, 1 */
  MEM8(a9 + 184) = a10; /* 0016: s8i a10, a9, 184 */
  MEMW(); /* 0019: memw  */
  if (a8 != 1) goto L_28; /* 001c: bnei a8, 1, 28 <pm_sleep_delay_timeout_process+0x20> */
  MEMW(); /* 001f: memw  */
  a8 = (uint32_t)&pm_sleep; /* 0022: l32r a8, 4 <pm_sleep_delay_timeout_process-0x4> (0 <pm_sleep_delay_timeout_process-0x8>) */ /* literal: GOT slot for pm_sleep */
  pm_sleep(a2, a3, a4, a5); /* call via literal slot */ /* 0025: callx8 a8 */
L_28:;
  return (int32_t)a2; /* 0028: retw.n  */
}

/* pm_disconnected_sleep_delay_timeout_process @ pm.o 00000008 size 34B bind GLOBAL
 * Calls: pm_disconnected_sleep | Data refs: g_pm, pm_disconnected_sleep
 *   MMIO: none
 *   funcdb v3: 1 call(s), 2 ref(s); disasm: 1 call(s), 2 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t pm_disconnected_sleep_delay_timeout_process(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pm_disconnected_sleep_delay_timeout_process; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_8:;
  /* 0008: entry a1, 32 */
  a8 = (uint32_t)&g_pm; /* 000b: l32r a8, 0 <pm_disconnected_sleep_delay_timeout_process-0x8> (0 <pm_disconnected_sleep_delay_timeout_process-0x8>) */ /* literal @0x0: g_pm */
  a9 = 0x0; /* 000e: movi.n a9, 0 */
  a8 = a8 + ((0x100) << 8); /* 0010: addmi a8, a8, 0x100 */
  MEM8(a8 + 184) = a9; /* 0013: s8i a9, a8, 184 */
  MEMW(); /* 0016: memw  */
  a8 = MEM8(a8 + 29); /* 0019: l8ui a8, a8, 29 */
  if (a8 != 2) goto L_28; /* 001c: bnei a8, 2, 28 <pm_disconnected_sleep_delay_timeout_process+0x20> */
  MEMW(); /* 001f: memw  */
  a8 = (uint32_t)&pm_disconnected_sleep; /* 0022: l32r a8, 4 <pm_disconnected_sleep_delay_timeout_process-0x4> (0 <pm_disconnected_sleep_delay_timeout_process-0x8>) */ /* literal: GOT slot for pm_disconnected_sleep */
  pm_disconnected_sleep(a2, a3, a4, a5); /* call via literal slot */ /* 0025: callx8 a8 */
L_28:;
  return (int32_t)a2; /* 0028: retw.n  */
}

/* pm_connectionless_wake_interval_timeout_process @ pm.o 0000000c size 94B bind GLOBAL
 * Calls: pm_update_by_connectionless_status[got] | Data refs: g_pm, pm_update_by_connectionless_status, g_osi_funcs_p
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 1 call(s), 3 data ref(s)
 * Fidelity: medium - 32 instr, 6 branches, calls resolved */
int32_t pm_connectionless_wake_interval_timeout_process(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .wifislpiram.43; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_c:;
  /* 000c: entry a1, 32 */
  a3 = (uint32_t)&g_pm; /* 000f: l32r a3, 0 <pm_connectionless_wake_interval_timeout_process-0xc> (0 <pm_connectionless_wake_interval_timeout_process-0xc>) */ /* literal @0x0: g_pm */
  a4 = 0x0; /* 0012: movi a4, 0 */
  a2 = a3 + ((0x100) << 8); /* 0015: addmi a2, a3, 0x100 */
  MEM8(a2 + 140) = a4; /* 0018: s8i a4, a2, 140 */
  MEMW(); /* 001b: memw  */
  a2 = MEM8(a3 + 13); /* 001e: l8ui a2, a3, 13 */
  if (a2 != 0) goto L_30; /* 0021: bnez a2, 30 <pm_connectionless_wake_interval_timeout_process+0x24> */
L_24:;
  MEMW(); /* 0024: memw  */
  a8 = (uint32_t)&pm_update_by_connectionless_status; /* 0027: l32r a8, 8 <pm_connectionless_wake_interval_timeout_process-0x4> (0 <pm_connectionless_wake_interval_timeout_process-0xc>) */ /* literal: GOT slot for pm_update_by_connectionless_status */
  pm_update_by_connectionless_status(a2, a3, a4, a5); /* call via literal slot */ /* 002a: callx8 a8 */
  goto L_68; /* 002d: j 68 <pm_connectionless_wake_interval_timeout_process+0x5c> */
L_30:;
  a8 = (uint32_t)&g_osi_funcs_p; /* 0030: l32r a8, 4 <pm_connectionless_wake_interval_timeout_process-0x8> (0 <pm_connectionless_wake_interval_timeout_process-0xc>) */ /* literal @0x4: g_osi_funcs_p */
  a8 = MEM32(a8 + 0); /* 0033: l32i.n a8, a8, 0 */
  a10 = MEM32(a8 + 272); /* 0035: l32i a10, a8, 0x110 */
  a4 = MEM32(a3 + 88); /* 0038: l32i a4, a3, 88 */
  a2 = MEM32(a3 + 92); /* 003b: l32i a2, a3, 92 */
  ((int32_t(*)())a10)(a2, a3, a4, a5); /* 003e: callx8 a10 */ /* indirect */
  a10 = a4 - a10; /* 0041: sub a10, a4, a10 */
  a8 = MEM16(a3 + 394); /* 0044: l16ui a8, a3, 0x18a */
  a3 = 0x3E8; /* 0047: movi a3, 0x3e8 */
  a9 = (uint32_t)((uint64_t)a8 * a3); /* 004a: mull a9, a8, a3 */
  a8 = (uint32_t)(((uint64_t)a8 * a3) >> 32) /* muluh: high word */; /* 004d: muluh a8, a8, a3 */
  a3 = 0x1; /* 0050: movi a3, 1 */
  if (a4 < a10) goto L_59; /* 0053: bltu a4, a10, 59 <pm_connectionless_wake_interval_timeout_process+0x4d> */
  a3 = 0x0; /* 0056: movi a3, 0 */
L_59:;
  a11 = a2 - a11; /* 0059: sub a11, a2, a11 */
  a11 = a11 - a3; /* 005c: sub a11, a11, a3 */
  if (a11 < a8) goto L_68; /* 005f: bltu a11, a8, 68 <pm_connectionless_wake_interval_timeout_process+0x5c> */
  if (a8 != a11) goto L_24; /* 0062: bne a8, a11, 24 <pm_connectionless_wake_interval_timeout_process+0x18> */
  if (a10 >= a9) goto L_24; /* 0065: bgeu a10, a9, 24 <pm_connectionless_wake_interval_timeout_process+0x18> */
L_68:;
  return (int32_t)a2; /* 0068: retw.n  */
}

/* pm_connectionless_wake_window_timeout_process @ pm.o 00000018 size 92B bind GLOBAL
 * Calls: pm_coex_separate_connectionless_window[got], pm_get_connectionless_status[got], wifi_gpio_debug[got], pm_wake_done[got] | Data refs: g_pm, g_osi_funcs_p, pm_coex_separate_connectionless_window, pm_get_connectionless_status, wifi_gpio_debug, pm_wake_done
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 4 call(s), 6 data ref(s)
 * Fidelity: medium - 33 instr, 6 branches, calls resolved */
int32_t pm_connectionless_wake_window_timeout_process(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .wifislpiram.44; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_18:;
  /* 0018: entry a1, 32 */
  a3 = (uint32_t)&g_pm; /* 001b: l32r a3, 0 <pm_connectionless_wake_window_timeout_process-0x18> (0 <pm_connectionless_wake_window_timeout_process-0x18>) */ /* literal @0x0: g_pm */
  a2 = a3 + ((0x100) << 8); /* 001e: addmi a2, a3, 0x100 */
  a8 = MEM8(a2 + 29); /* 0021: l8ui a8, a2, 29 */
  if (a8 >= 2) goto L_2d; /* 0024: bgeui a8, 2, 2d <pm_connectionless_wake_window_timeout_process+0x15> */
  a3 = MEM8(a3 + 13); /* 0027: l8ui a3, a3, 13 */
  if (a3 == 0) goto L_72; /* 002a: beqz a3, 72 <pm_connectionless_wake_window_timeout_process+0x5a> */
L_2d:;
  a3 = (uint32_t)&g_osi_funcs_p; /* 002d: l32r a3, 4 <pm_connectionless_wake_window_timeout_process-0x14> (0 <pm_connectionless_wake_window_timeout_process-0x18>) */ /* literal @0x4: g_osi_funcs_p */
  a3 = MEM32(a3 + 0); /* 0030: l32i.n a3, a3, 0 */
  a10 = MEM32(a3 + 404); /* 0032: l32i a10, a3, 0x194 */
  ((int32_t(*)())a10)(a2, a3, a4, a5); /* 0035: callx8 a10 */ /* indirect */
  a3 = a10 | a10; /* 0038: or a3, a10, a10 */
  if (a10 == 0) goto L_49; /* 003b: beqz a10, 49 <pm_connectionless_wake_window_timeout_process+0x31> */
  a8 = (uint32_t)&pm_coex_separate_connectionless_window; /* 003e: l32r a8, 8 <pm_connectionless_wake_window_timeout_process-0x10> (0 <pm_connectionless_wake_window_timeout_process-0x18>) */ /* literal: GOT slot for pm_coex_separate_connectionless_window */
  pm_coex_separate_connectionless_window(a2, a3, a4, a5); /* call via literal slot */ /* 0041: callx8 a8 */
  goto L_72; /* 0044: j 72 <pm_connectionless_wake_window_timeout_process+0x5a> */
  /* 0047: .byte 00 */
  /* 0048: .byte 00 */
L_49:;
  a8 = MEM8(a2 + 136); /* 0049: l8ui a8, a2, 136 */
  if (a8 == 0) goto L_72; /* 004c: beqz.n a8, 72 <pm_connectionless_wake_window_timeout_process+0x5a> */
  a8 = (uint32_t)&pm_get_connectionless_status; /* 004e: l32r a8, c <pm_connectionless_wake_window_timeout_process-0xc> (0 <pm_connectionless_wake_window_timeout_process-0x18>) */ /* literal: GOT slot for pm_get_connectionless_status */
  pm_get_connectionless_status(a2, a3, a4, a5); /* call via literal slot */ /* 0051: callx8 a8 */
  if (a10 < 1) goto L_72; /* 0054: blti a10, 1, 72 <pm_connectionless_wake_window_timeout_process+0x5a> */
  a11 = 0x1; /* 0057: movi a11, 1 */
  a10 = 0x11; /* 005a: movi a10, 17 */
  MEM8(a2 + 136) = a3; /* 005d: s8i a3, a2, 136 */
  MEMW(); /* 0060: memw  */
  MEMW(); /* 0063: memw  */
  a8 = (uint32_t)&wifi_gpio_debug; /* 0066: l32r a8, 10 <pm_connectionless_wake_window_timeout_process-0x8> (0 <pm_connectionless_wake_window_timeout_process-0x18>) */ /* literal: GOT slot for wifi_gpio_debug */
  wifi_gpio_debug(a2, a3, a4, a5); /* call via literal slot */ /* 0069: callx8 a8 */
  a8 = (uint32_t)&pm_wake_done; /* 006c: l32r a8, 14 <pm_connectionless_wake_window_timeout_process-0x4> (0 <pm_connectionless_wake_window_timeout_process-0x18>) */ /* literal: GOT slot for pm_wake_done */
  pm_wake_done(a2, a3, a4, a5); /* call via literal slot */ /* 006f: callx8 a8 */
L_72:;
  return (int32_t)a2; /* 0072: retw.n  */
}

/* pm_coex_restart_timeout_process @ pm.o 0000000c size 32B bind GLOBAL
 * Calls: pm_coex_schm_process_restart | Data refs: g_osi_funcs_p, g_pm, pm_coex_schm_process_restart
 *   MMIO: none
 *   funcdb v3: 1 call(s), 3 ref(s); disasm: 1 call(s), 3 data ref(s)
 * Fidelity: medium - 12 instr, 2 branches, calls resolved */
int32_t pm_coex_restart_timeout_process(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pm_coex_restart_timeout_process; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_c:;
  /* 000c: entry a1, 32 */
  a8 = (uint32_t)&g_osi_funcs_p; /* 000f: l32r a8, 0 <pm_coex_restart_timeout_process-0xc> (0 <pm_coex_restart_timeout_process-0xc>) */ /* literal @0x0: g_osi_funcs_p */
  a8 = MEM32(a8 + 0); /* 0012: l32i.n a8, a8, 0 */
  a10 = MEM32(a8 + 404); /* 0014: l32i a10, a8, 0x194 */
  ((int32_t(*)())a10)(a2, a3, a4, a5); /* 0017: callx8 a10 */ /* indirect */
  if (a10 == 0) goto L_2a; /* 001a: beqz.n a10, 2a <pm_coex_restart_timeout_process+0x1e> */
  a8 = (uint32_t)&g_pm; /* 001c: l32r a8, 4 <pm_coex_restart_timeout_process-0x8> (0 <pm_coex_restart_timeout_process-0xc>) */ /* literal @0x4: g_pm */
  a8 = MEM32(a8 + 400); /* 001f: l32i a8, a8, 0x190 */
  if (a8 != 0) goto L_2a; /* 0022: bnez.n a8, 2a <pm_coex_restart_timeout_process+0x1e> */
  a8 = (uint32_t)&pm_coex_schm_process_restart; /* 0024: l32r a8, 8 <pm_coex_restart_timeout_process-0x4> (0 <pm_coex_restart_timeout_process-0xc>) */ /* literal: GOT slot for pm_coex_schm_process_restart */
  pm_coex_schm_process_restart(a2, a3, a4, a5); /* call via literal slot */ /* 0027: callx8 a8 */
L_2a:;
  return (int32_t)a2; /* 002a: retw.n  */
}

/* pm_rx_data_process @ pm.o 0000001c size 122B bind GLOBAL
 * Calls: pm_check_state[got], .text.pm_incr_coex_active_cnt[got], pm_enable_dream_timer[got], pm_disable_dream_timer[got], pm_enable_sleep_delay_timer[got], pm_enable_active_timer[got] | Data refs: pm_check_state, .text.pm_incr_coex_active_cnt, g_pm, pm_enable_dream_timer, pm_disable_dream_timer, pm_enable_sleep_delay_timer, pm_enable_active_timer
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 6 call(s), 7 data ref(s)
 * Fidelity: medium - 43 instr, 11 branches, calls resolved */
int32_t pm_rx_data_process(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .wifirxiram.49; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_1c:;
  /* 001c: entry a1, 32 */
  a2 = (a2 >> 0) & 0xFF; /* 001f: extui a2, a2, 0, 8 */
  a3 = (a3 >> 0) & 0xFF; /* 0022: extui a3, a3, 0, 8 */
  a8 = (uint32_t)&pm_check_state; /* 0025: l32r a8, 4 <pm_rx_data_process-0x18> (0 <pm_rx_data_process-0x1c>) */ /* literal: GOT slot for pm_check_state */
  pm_check_state(a2, a3, a4, a5); /* call via literal slot */ /* 0028: callx8 a8 */
  if (a10 == 0) goto L_94; /* 002b: beqz a10, 94 <pm_rx_data_process+0x78> */
  a8 = (uint32_t)&pm_incr_coex_active_cnt; /* 002e: l32r a8, 8 <pm_rx_data_process-0x14> (4 <pm_rx_data_process-0x18>) */ /* literal: GOT slot for .text.pm_incr_coex_active_cnt */
  pm_incr_coex_active_cnt(a2, a3, a4, a5); /* call via literal slot */ /* 0031: callx8 a8 */
  a8 = (uint32_t)&g_pm; /* 0034: l32r a8, 0 <pm_rx_data_process-0x1c> (0 <pm_rx_data_process-0x1c>) */ /* literal @0x0: g_pm */
  a9 = MEM8(a8 + 1); /* 0037: l8ui a9, a8, 1 */
  if (a9 != 1) goto L_8c; /* 003a: bnei a9, 1, 8c <pm_rx_data_process+0x70> */
  a10 = MEM8(a8 + 24); /* 003d: l8ui a10, a8, 24 */
  if (a10 == 0) goto L_94; /* 0040: beqz a10, 94 <pm_rx_data_process+0x78> */
  if (a2 == 0) goto L_71; /* 0043: beqz.n a2, 71 <pm_rx_data_process+0x55> */
  if (a3 == 0) goto L_59; /* 0045: beqz.n a3, 59 <pm_rx_data_process+0x3d> */
  MEM8(a8 + 18) = a9; /* 0047: s8i a9, a8, 18 */
  MEMW(); /* 004a: memw  */
  MEMW(); /* 004d: memw  */
  a8 = (uint32_t)&pm_enable_dream_timer; /* 0050: l32r a8, c <pm_rx_data_process-0x10> (0 <pm_rx_data_process-0x1c>) */ /* literal: GOT slot for pm_enable_dream_timer */
  pm_enable_dream_timer(a2, a3, a4, a5); /* call via literal slot */ /* 0053: callx8 a8 */
  goto L_94; /* 0056: j 94 <pm_rx_data_process+0x78> */
L_59:;
  MEM8(a8 + 18) = a3; /* 0059: s8i a3, a8, 18 */
  MEMW(); /* 005c: memw  */
  MEMW(); /* 005f: memw  */
  a8 = (uint32_t)&pm_disable_dream_timer; /* 0062: l32r a8, 10 <pm_rx_data_process-0xc> (0 <pm_rx_data_process-0x1c>) */ /* literal: GOT slot for pm_disable_dream_timer */
  pm_disable_dream_timer(a2, a3, a4, a5); /* call via literal slot */ /* 0065: callx8 a8 */
  a8 = (uint32_t)&pm_enable_sleep_delay_timer; /* 0068: l32r a8, 14 <pm_rx_data_process-0x8> (0 <pm_rx_data_process-0x1c>) */ /* literal: GOT slot for pm_enable_sleep_delay_timer */
  pm_enable_sleep_delay_timer(a2, a3, a4, a5); /* call via literal slot */ /* 006b: callx8 a8 */
  goto L_94; /* 006e: j 94 <pm_rx_data_process+0x78> */
L_71:;
  if (a3 == 0) goto L_80; /* 0071: beqz.n a3, 80 <pm_rx_data_process+0x64> */
  MEM8(a8 + 18) = a9; /* 0073: s8i a9, a8, 18 */
  MEMW(); /* 0076: memw  */
  MEMW(); /* 0079: memw  */
  goto L_94; /* 007c: j 94 <pm_rx_data_process+0x78> */
  /* 007f: .byte 00 */
L_80:;
  MEM8(a8 + 18) = a3; /* 0080: s8i a3, a8, 18 */
  MEMW(); /* 0083: memw  */
  MEMW(); /* 0086: memw  */
  goto L_94; /* 0089: j 94 <pm_rx_data_process+0x78> */
L_8c:;
  if (a9 != 0) goto L_94; /* 008c: bnez.n a9, 94 <pm_rx_data_process+0x78> */
  a8 = (uint32_t)&pm_enable_active_timer; /* 008e: l32r a8, 18 <pm_rx_data_process-0x4> (0 <pm_rx_data_process-0x1c>) */ /* literal: GOT slot for pm_enable_active_timer */
  pm_enable_active_timer(a2, a3, a4, a5); /* call via literal slot */ /* 0091: callx8 a8 */
L_94:;
  return (int32_t)a2; /* 0094: retw.n  */
}

/* pm_hmac_rx_data_process @ pm.o 00000000 size 5B bind GLOBAL
 * Calls: none | Data refs: none
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t pm_hmac_rx_data_process(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .wifirxiram.50; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_0:;
  /* 0000: entry a1, 32 */
  return (int32_t)a2; /* 0003: retw.n  */
}

/* pm_tx_data_done_process @ pm.o 00000030 size 192B bind GLOBAL
 * Calls: pm_check_state, pm_enable_active_timer, pm_enable_disconnected_sleep_delay_timer, pm_enable_keep_alive_timer, pm_enable_sleep_delay_timer, ppCheckTxIdle, sta_reset_beacon_timeout, .text.pm_incr_coex_active_cnt[got] | Data refs: g_mesh_is_started, g_osi_funcs_p, g_pm, pm_check_state, pm_enable_active_timer, pm_enable_disconnected_sleep_delay_timer, pm_enable_keep_alive_timer, pm_enable_sleep_delay_timer, ppCheckTxIdle, sta_reset_beacon_timeout, .text.pm_incr_coex_active_cnt
 *   MMIO: none
 *   funcdb v3: 7 call(s), 10 ref(s); disasm: 8 call(s), 11 data ref(s)
 * Fidelity: medium - 68 instr, 15 branches, calls resolved */
int32_t pm_tx_data_done_process(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pm_tx_data_done_process; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_30:;
  /* 0030: entry a1, 32 */
  a2 = (a2 >> 0) & 0xFF; /* 0033: extui a2, a2, 0, 8 */
  a3 = (a3 >> 0) & 0xFF; /* 0036: extui a3, a3, 0, 8 */
  a4 = (a4 >> 0) & 0xFF; /* 0039: extui a4, a4, 0, 8 */
  if (a2 == 0) goto L_90; /* 003c: beqz a2, 90 <pm_tx_data_done_process+0x60> */
  a2 = (uint32_t)&g_mesh_is_started; /* 003f: l32r a2, 0 <pm_tx_data_done_process-0x30> (0 <pm_tx_data_done_process-0x30>) */ /* literal @0x0: g_mesh_is_started */
  a2 = MEM8(a2 + 0); /* 0042: l8ui a2, a2, 0 */
  if (a2 == 0) goto L_49; /* 0045: beqz.n a2, 49 <pm_tx_data_done_process+0x19> */
  if (a3 != 0) goto L_4f; /* 0047: bnez.n a3, 4f <pm_tx_data_done_process+0x1f> */
L_49:;
  a8 = (uint32_t)&sta_reset_beacon_timeout; /* 0049: l32r a8, 10 <pm_tx_data_done_process-0x20> (0 <pm_tx_data_done_process-0x30>) */ /* literal: GOT slot for sta_reset_beacon_timeout */
  sta_reset_beacon_timeout(a2, a3, a4, a5); /* call via literal slot */ /* 004c: callx8 a8 */
L_4f:;
  if (a4 == 0) goto L_90; /* 004f: beqz.n a4, 90 <pm_tx_data_done_process+0x60> */
  a3 = (uint32_t)&g_osi_funcs_p; /* 0051: l32r a3, 4 <pm_tx_data_done_process-0x2c> (0 <pm_tx_data_done_process-0x30>) */ /* literal @0x4: g_osi_funcs_p */
  a2 = MEM32(a3 + 0); /* 0054: l32i a2, a3, 0 */
  a10 = MEM32(a2 + 272); /* 0057: l32i a10, a2, 0x110 */
  ((int32_t(*)())a10)(a2, a3, a4, a5); /* 005a: callx8 a10 */ /* indirect */
  a9 = 0x1; /* 005d: movi.n a9, 1 */
  a2 = (uint32_t)&g_pm; /* 005f: l32r a2, 8 <pm_tx_data_done_process-0x28> (0 <pm_tx_data_done_process-0x30>) */ /* literal @0x8: g_pm */
  a8 = MEM32(a2 + 480); /* 0062: l32i a8, a2, 0x1e0 */
  a8 = a10 - a8; /* 0065: sub a8, a10, a8 */
  a12 = MEM32(a2 + 484); /* 0068: l32i a12, a2, 0x1e4 */
  if (a10 < a8) goto L_70; /* 006b: bltu a10, a8, 70 <pm_tx_data_done_process+0x40> */
  a9 = 0x0; /* 006e: movi.n a9, 0 */
L_70:;
  a11 = a11 - a12; /* 0070: sub a11, a11, a12 */
  if (a11 != a9) goto L_7c; /* 0073: bne a11, a9, 7c <pm_tx_data_done_process+0x4c> */
  a9 = 0x186A0; /* 0076: l32r a9, c <pm_tx_data_done_process-0x24> (186a0 <pm_attach+0x1861c>) */ @0xC
  if (a9 >= a8) goto L_90; /* 0079: bgeu a9, a8, 90 <pm_tx_data_done_process+0x60> */
L_7c:;
  a8 = (uint32_t)&pm_enable_keep_alive_timer; /* 007c: l32r a8, 14 <pm_tx_data_done_process-0x1c> (0 <pm_tx_data_done_process-0x30>) */ /* literal: GOT slot for pm_enable_keep_alive_timer */
  pm_enable_keep_alive_timer(a2, a3, a4, a5); /* call via literal slot */ /* 007f: callx8 a8 */
  a3 = MEM32(a3 + 0); /* 0082: l32i.n a3, a3, 0 */
  a10 = MEM32(a3 + 272); /* 0084: l32i a10, a3, 0x110 */
  ((int32_t(*)())a10)(a2, a3, a4, a5); /* 0087: callx8 a10 */ /* indirect */
  MEM32(a2 + 480) = a10; /* 008a: s32i a10, a2, 0x1e0 */
  MEM32(a2 + 484) = a11; /* 008d: s32i a11, a2, 0x1e4 */
L_90:;
  a10 = 0x1; /* 0090: movi a10, 1 */
  MEMW(); /* 0093: memw  */
  a8 = (uint32_t)&ppCheckTxIdle; /* 0096: l32r a8, 18 <pm_tx_data_done_process-0x18> (0 <pm_tx_data_done_process-0x30>) */ /* literal: GOT slot for ppCheckTxIdle */
  ppCheckTxIdle(a2, a3, a4, a5); /* call via literal slot */ /* 0099: callx8 a8 */
  if (a10 != 0) goto L_be; /* 009c: bnez a10, be <pm_tx_data_done_process+0x8e> */
  a2 = (uint32_t)&g_pm; /* 009f: l32r a2, 8 <pm_tx_data_done_process-0x28> (0 <pm_tx_data_done_process-0x30>) */ /* literal @0x8: g_pm */
  a3 = MEM8(a2 + 13); /* 00a2: l8ui a3, a2, 13 */
  if (a3 == 0) goto L_b8; /* 00a5: beqz a3, b8 <pm_tx_data_done_process+0x88> */
  a2 = MEM8(a2 + 1); /* 00a8: l8ui a2, a2, 1 */
  if (a2 != 1) goto L_be; /* 00ab: bnei a2, 1, be <pm_tx_data_done_process+0x8e> */
  a8 = (uint32_t)&pm_enable_sleep_delay_timer; /* 00ae: l32r a8, 1c <pm_tx_data_done_process-0x14> (0 <pm_tx_data_done_process-0x30>) */ /* literal: GOT slot for pm_enable_sleep_delay_timer */
  pm_enable_sleep_delay_timer(a2, a3, a4, a5); /* call via literal slot */ /* 00b1: callx8 a8 */
  goto L_be; /* 00b4: j be <pm_tx_data_done_process+0x8e> */
  /* 00b7: .byte 00 */
L_b8:;
  a8 = (uint32_t)&pm_enable_disconnected_sleep_delay_timer; /* 00b8: l32r a8, 20 <pm_tx_data_done_process-0x10> (0 <pm_tx_data_done_process-0x30>) */ /* literal: GOT slot for pm_enable_disconnected_sleep_delay_timer */
  pm_enable_disconnected_sleep_delay_timer(a2, a3, a4, a5); /* call via literal slot */ /* 00bb: callx8 a8 */
L_be:;
  a8 = (uint32_t)&pm_check_state; /* 00be: l32r a8, 24 <pm_tx_data_done_process-0xc> (0 <pm_tx_data_done_process-0x30>) */ /* literal: GOT slot for pm_check_state */
  pm_check_state(a2, a3, a4, a5); /* call via literal slot */ /* 00c1: callx8 a8 */
  if (a10 == 0) goto L_ee; /* 00c4: beqz.n a10, ee <pm_tx_data_done_process+0xbe> */
  if (a4 == 0) goto L_ee; /* 00c6: beqz.n a4, ee <pm_tx_data_done_process+0xbe> */
  a8 = (uint32_t)&pm_incr_coex_active_cnt; /* 00c8: l32r a8, 28 <pm_tx_data_done_process-0x8> (4 <pm_tx_data_done_process-0x2c>) */ /* literal: GOT slot for .text.pm_incr_coex_active_cnt */
  pm_incr_coex_active_cnt(a2, a3, a4, a5); /* call via literal slot */ /* 00cb: callx8 a8 */
  a8 = (uint32_t)&g_pm; /* 00ce: l32r a8, 8 <pm_tx_data_done_process-0x28> (0 <pm_tx_data_done_process-0x30>) */ /* literal @0x8: g_pm */
  a2 = MEM8(a8 + 24); /* 00d1: l8ui a2, a8, 24 */
  if (a2 != 0) goto L_e0; /* 00d4: bnez a2, e0 <pm_tx_data_done_process+0xb0> */
  a2 = 0x1; /* 00d7: movi a2, 1 */
  MEM8(a8 + 25) = a2; /* 00da: s8i a2, a8, 25 */
  MEMW(); /* 00dd: memw  */
L_e0:;
  a2 = MEM8(a8 + 1); /* 00e0: l8ui a2, a8, 1 */
  if (a2 != 0) goto L_ee; /* 00e3: bnez.n a2, ee <pm_tx_data_done_process+0xbe> */
  MEMW(); /* 00e5: memw  */
  a8 = (uint32_t)&pm_enable_active_timer; /* 00e8: l32r a8, 2c <pm_tx_data_done_process-0x4> (0 <pm_tx_data_done_process-0x30>) */ /* literal: GOT slot for pm_enable_active_timer */
  pm_enable_active_timer(a2, a3, a4, a5); /* call via literal slot */ /* 00eb: callx8 a8 */
L_ee:;
  return (int32_t)a2; /* 00ee: retw.n  */
}

/* pm_tx_null_data_done_quick_wake_process @ pm.o 00000014 size 96B bind GLOBAL
 * Calls: pm_send_nullfunc, ppCheckTxIdle, sta_reset_beacon_timeout, g_osi_funcs_p[got] | Data refs: g_osi_funcs_p, g_pm, pm_send_nullfunc, ppCheckTxIdle, sta_reset_beacon_timeout
 *   MMIO: none
 *   funcdb v3: 3 call(s), 5 ref(s); disasm: 4 call(s), 5 data ref(s)
 * Fidelity: medium - 36 instr, 8 branches, calls resolved */
int32_t pm_tx_null_data_done_quick_wake_process(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pm_tx_null_data_done_quick_wake_process; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_14:;
  /* 0014: entry a1, 32 */
  a3 = (uint32_t)&g_pm; /* 0017: l32r a3, 0 <pm_tx_null_data_done_quick_wake_process-0x14> (0 <pm_tx_null_data_done_quick_wake_process-0x14>) */ /* literal @0x0: g_pm */
  a2 = (a2 >> 0) & 0xFF; /* 001a: extui a2, a2, 0, 8 */
  a8 = a3 + ((0x100) << 8); /* 001d: addmi a8, a3, 0x100 */
  a8 = MEM8(a8 + 212); /* 0020: l8ui a8, a8, 212 */
  if (a8 != 0) goto L_2a; /* 0023: bnez.n a8, 2a <pm_tx_null_data_done_quick_wake_process+0x16> */
L_25:;
  a2 = 0x1; /* 0025: movi.n a2, 1 */
  goto L_72; /* 0027: j 72 <pm_tx_null_data_done_quick_wake_process+0x5e> */
L_2a:;
  if (a2 == 0) goto L_32; /* 002a: beqz.n a2, 32 <pm_tx_null_data_done_quick_wake_process+0x1e> */
  a8 = (uint32_t)&sta_reset_beacon_timeout; /* 002c: l32r a8, 8 <pm_tx_null_data_done_quick_wake_process-0xc> (0 <pm_tx_null_data_done_quick_wake_process-0x14>) */ /* literal: GOT slot for sta_reset_beacon_timeout */
  sta_reset_beacon_timeout(a2, a3, a4, a5); /* call via literal slot */ /* 002f: callx8 a8 */
L_32:;
  a2 = MEM8(a3 + 17); /* 0032: l8ui a2, a3, 17 */
  if (a2 == 0) goto L_54; /* 0035: beqz.n a2, 54 <pm_tx_null_data_done_quick_wake_process+0x40> */
  a8 = 0x0; /* 0037: movi.n a8, 0 */
  a10 = 0x0; /* 0039: movi.n a10, 0 */
  MEM8(a3 + 17) = a8; /* 003b: s8i a8, a3, 17 */
  MEMW(); /* 003e: memw  */
  a3 = (uint32_t)&g_osi_funcs_p; /* 0041: l32r a3, 4 <pm_tx_null_data_done_quick_wake_process-0x10> (0 <pm_tx_null_data_done_quick_wake_process-0x14>) */ /* literal @0x4: g_osi_funcs_p */
  a3 = MEM32(a3 + 0); /* 0044: l32i a3, a3, 0 */
  a3 = MEM32(a3 + 416); /* 0047: l32i a3, a3, 0x1a0 */
  MEMW(); /* 004a: memw  */
  g_osi_funcs_p(a2, a3, a4, a5); /* call via literal slot */ /* 004d: callx8 a3 */
  goto L_72; /* 0050: j 72 <pm_tx_null_data_done_quick_wake_process+0x5e> */
  /* 0053: .byte 00 */
L_54:;
  a2 = MEM8(a3 + 18); /* 0054: l8ui a2, a3, 18 */
  if (a2 != 0) goto L_25; /* 0057: bnez a2, 25 <pm_tx_null_data_done_quick_wake_process+0x11> */
  a10 = 0x1; /* 005a: movi.n a10, 1 */
  a8 = (uint32_t)&ppCheckTxIdle; /* 005c: l32r a8, c <pm_tx_null_data_done_quick_wake_process-0x8> (0 <pm_tx_null_data_done_quick_wake_process-0x14>) */ /* literal: GOT slot for ppCheckTxIdle */
  ppCheckTxIdle(a2, a3, a4, a5); /* call via literal slot */ /* 005f: callx8 a8 */
  if (a10 != 0) goto L_25; /* 0062: bnez a10, 25 <pm_tx_null_data_done_quick_wake_process+0x11> */
  a3 = MEM8(a3 + 20); /* 0065: l8ui a3, a3, 20 */
  if (a3 != 0) goto L_72; /* 0068: bnez.n a3, 72 <pm_tx_null_data_done_quick_wake_process+0x5e> */
  a10 = 0x1; /* 006a: movi.n a10, 1 */
  a8 = (uint32_t)&pm_send_nullfunc; /* 006c: l32r a8, 10 <pm_tx_null_data_done_quick_wake_process-0x4> (0 <pm_tx_null_data_done_quick_wake_process-0x14>) */ /* literal: GOT slot for pm_send_nullfunc */
  pm_send_nullfunc(a2, a3, a4, a5); /* call via literal slot */ /* 006f: callx8 a8 */
L_72:;
  return (int32_t)a2; /* 0072: retw.n  */
}

/* pm_tx_null_data_done_process @ pm.o 0000006c size 668B bind GLOBAL
 * Calls: pm_check_state, pm_dream, pm_enable_active_timer, pm_enable_keep_alive_timer, pm_enable_sleep_delay_timer, pm_is_in_wifi_slice_threshold, pm_offchan_execute_ready_cb, pm_send_nullfunc, pm_sleep, pm_tx_null_data_done_quick_wake_process, ppProcessWaitingQueue, wifi_log, esp_mesh_quick_funcs[got], .text.pm_set_state[got] | Data refs: .rodata.pm_tx_null_data_done_process.str1.1, .rodata_wlog_debug.51, .rodata_wlog_debug.52, esp_mesh_quick_funcs, g_ic, g_mesh_init_ps_type, g_mesh_is_root, g_mesh_is_started, g_osi_funcs_p, g_pm, g_pm_cnt, pm_check_state, pm_dream, pm_enable_active_timer, pm_enable_keep_alive_timer, pm_enable_sleep_delay_timer, pm_is_in_wifi_slice_threshold, pm_offchan_execute_ready_cb, pm_send_nullfunc, pm_sleep, pm_tx_null_data_done_quick_wake_process, ppProcessWaitingQueue, wifi_log, .text.pm_set_state
 *   MMIO: none
 *   funcdb v3: 12 call(s), 23 ref(s); disasm: 16 call(s), 24 data ref(s)
 * Fidelity: low - 253 instr, 55 branches, 4 indirect; call-sequence + MMIO skeleton */
int32_t pm_tx_null_data_done_process(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pm_tx_null_data_done_process; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_6c:;
  /* 006c: entry a1, 48 */
  a7 = (uint32_t)&g_mesh_is_started; /* 006f: l32r a7, 8 <pm_tx_null_data_done_process-0x64> (0 <pm_tx_null_data_done_process-0x6c>) */ /* literal @0x8: g_mesh_is_started */
  a4 = (a4 >> 0) & 0xFF; /* 0072: extui a4, a4, 0, 8 */
  a8 = MEM8(a7 + 0); /* 0075: l8ui a8, a7, 0 */
  a5 = (uint32_t)&g_pm; /* 0078: l32r a5, 14 <pm_tx_null_data_done_process-0x58> (0 <pm_tx_null_data_done_process-0x6c>) */ /* literal @0x14: g_pm */
  if (a8 == 0) goto L_a4; /* 007b: beqz.n a8, a4 <pm_tx_null_data_done_process+0x38> */
  a6 = (uint32_t)&g_mesh_is_root; /* 007d: l32r a6, c <pm_tx_null_data_done_process-0x60> (0 <pm_tx_null_data_done_process-0x6c>) */ /* literal @0xC: g_mesh_is_root */
  MEMW(); /* 0080: memw  */
  a6 = MEM8(a6 + 0); /* 0083: l8ui a6, a6, 0 */
  a6 = (a6 >> 0) & 0xFF; /* 0086: extui a6, a6, 0, 8 */
  if (a6 != 0) goto L_a4; /* 0089: bnez.n a6, a4 <pm_tx_null_data_done_process+0x38> */
  a6 = (uint32_t)&g_mesh_init_ps_type; /* 008b: l32r a6, 10 <pm_tx_null_data_done_process-0x5c> (0 <pm_tx_null_data_done_process-0x6c>) */ /* literal @0x10: g_mesh_init_ps_type */
  a6 = MEM32(a6 + 0); /* 008e: l32i.n a6, a6, 0 */
  if (a6 == 0) goto L_a4; /* 0090: beqz.n a6, a4 <pm_tx_null_data_done_process+0x38> */
  if (a3 == 0) goto L_b4; /* 0092: beqz.n a3, b4 <pm_tx_null_data_done_process+0x48> */
  a11 = a3; /* 0094: mov.n a11, a3 */
  a6 = (uint32_t)&esp_mesh_quick_funcs; /* 0096: l32r a6, 18 <pm_tx_null_data_done_process-0x54> (0 <pm_tx_null_data_done_process-0x6c>) */ /* literal @0x18: esp_mesh_quick_funcs */
  a10 = a2; /* 0099: mov.n a10, a2 */
  a6 = MEM32(a6 + 132); /* 009b: l32i a6, a6, 132 */
  a12 = MEM8(a5 + 9); /* 009e: l8ui a12, a5, 9 */
  esp_mesh_quick_funcs(a2, a3, a4, a5); /* call via literal slot */ /* 00a1: callx8 a6 */
L_a4:;
  a9 = a3 + (-1); /* 00a4: addi.n a9, a3, -1 */
  a8 = 0x1; /* 00a6: movi.n a8, 1 */
  a6 = 0x0; /* 00a8: movi.n a6, 0 */
  if (a9 != 0) a8 = a6; /* 00aa: movnez a8, a6, a9 */
  a8 = (a8 >> 0) & 0xFF; /* 00ad: extui a8, a8, 0, 8 */
  goto L_b6; /* 00b0: j b6 <pm_tx_null_data_done_process+0x4a> */
  /* 00b3: .byte 00 */
L_b4:;
  a3 = 0x1; /* 00b4: movi.n a3, 1 */
L_b6:;
  a10 = MEM8(a5 + 14); /* 00b6: l8ui a10, a5, 14 */
  a6 = a5 + ((0x100) << 8); /* 00b9: addmi a6, a5, 0x100 */
  a9 = MEM8(a6 + 232); /* 00bc: l8ui a9, a6, 232 */
  if (a10 == 0) goto L_c6; /* 00bf: beqz.n a10, c6 <pm_tx_null_data_done_process+0x5a> */
  a10 = MEM8(a5 + 15); /* 00c1: l8ui a10, a5, 15 */
  if (a10 == 0) goto L_c8; /* 00c4: beqz.n a10, c8 <pm_tx_null_data_done_process+0x5c> */
L_c6:;
  if (a9 == 0) goto L_d6; /* 00c6: beqz.n a9, d6 <pm_tx_null_data_done_process+0x6a> */
L_c8:;
  if (a2 != 0) goto L_d8; /* 00c8: bnez.n a2, d8 <pm_tx_null_data_done_process+0x6c> */
  a9 = MEM8(a5 + 9); /* 00ca: l8ui a9, a5, 9 */
  a10 = 0xF; /* 00cd: movi.n a10, 15 */
  if (a10 < a9) goto L_d6; /* 00cf: bltu a10, a9, d6 <pm_tx_null_data_done_process+0x6a> */
  goto L_d8; /* 00d2: j d8 <pm_tx_null_data_done_process+0x6c> */
  /* 00d5: .byte 00 */
L_d6:;
  a8 = 0x1; /* 00d6: movi.n a8, 1 */
L_d8:;
  a7 = MEM8(a7 + 0); /* 00d8: l8ui a7, a7, 0 */
  a9 = 0x1; /* 00db: movi.n a9, 1 */
  a7 = a7 ^ a9; /* 00dd: xor a7, a7, a9 */
  a7 = (a7 >> 0) & 0xFF; /* 00e0: extui a7, a7, 0, 8 */
  if (a7 != 0) goto L_e9; /* 00e3: bnez a7, e9 <pm_tx_null_data_done_process+0x7d> */
  if (a8 == 0) goto L_105; /* 00e6: beqz a8, 105 <pm_tx_null_data_done_process+0x99> */
L_e9:;
  MEM32(a1 + 0) = a8; /* 00e9: s32i.n a8, a1, 0 */
  MEMW(); /* 00eb: memw  */
  a8 = (uint32_t)&pm_check_state; /* 00ee: l32r a8, 30 <pm_tx_null_data_done_process-0x3c> (0 <pm_tx_null_data_done_process-0x6c>) */ /* literal: GOT slot for pm_check_state */
  pm_check_state(a2, a3, a4, a5); /* call via literal slot */ /* 00f1: callx8 a8 */
  a8 = MEM32(a1 + 0); /* 00f4: l32i.n a8, a1, 0 */
  if (a10 != 0) goto L_105; /* 00f6: bnez.n a10, 105 <pm_tx_null_data_done_process+0x99> */
  a7 = MEM8(a5 + 13); /* 00f8: l8ui a7, a5, 13 */
  if (a7 != 0) goto L_105; /* 00fb: bnez.n a7, 105 <pm_tx_null_data_done_process+0x99> */
L_fd:;
  a10 = 0x0; /* 00fd: movi.n a10, 0 */
  goto L_300; /* 00ff: j 300 <pm_tx_null_data_done_process+0x294> */
  /* 0102: .byte 00 */
  /* 0103: .byte 00 */
  /* 0104: .byte 00 */
L_105:;
  a7 = MEM8(a5 + 19); /* 0105: l8ui a7, a5, 19 */
  if (a7 != 0) goto L_111; /* 0108: bnez a7, 111 <pm_tx_null_data_done_process+0xa5> */
  a9 = MEM8(a5 + 20); /* 010b: l8ui a9, a5, 20 */
  if (a9 == 0) goto L_306; /* 010e: beqz a9, 306 <pm_tx_null_data_done_process+0x29a> */
L_111:;
  if (a8 == 0) goto L_271; /* 0111: beqz a8, 271 <pm_tx_null_data_done_process+0x205> */
  a7 = MEM8(a5 + 1); /* 0114: l8ui a7, a5, 1 */
  if (a7 != 2) goto L_120; /* 0117: bnei a7, 2, 120 <pm_tx_null_data_done_process+0xb4> */
  a8 = (uint32_t)&pm_dream; /* 011a: l32r a8, 34 <pm_tx_null_data_done_process-0x38> (0 <pm_tx_null_data_done_process-0x6c>) */ /* literal: GOT slot for pm_dream */
  pm_dream(a2, a3, a4, a5); /* call via literal slot */ /* 011d: callx8 a8 */
L_120:;
  a7 = MEM8(a6 + 232); /* 0120: l8ui a7, a6, 232 */
  if (a7 == 0) goto L_18d; /* 0123: beqz a7, 18d <pm_tx_null_data_done_process+0x121> */
  a7 = (uint32_t)&g_ic; /* 0126: l32r a7, 1c <pm_tx_null_data_done_process-0x50> (0 <pm_tx_null_data_done_process-0x6c>) */ /* literal @0x1C: g_ic */
  a7 = MEM32(a7 + 16); /* 0129: l32i.n a7, a7, 16 */
  if (a7 != 0) goto L_141; /* 012b: bnez.n a7, 141 <pm_tx_null_data_done_process+0xd5> */
  a13 = (uint32_t)&lit_rodata_wlog_debug_51; /* 012d: l32r a13, 20 <pm_tx_null_data_done_process-0x4c> (0 <pm_tx_null_data_done_process-0x6c>) */ /* literal @0x20: .rodata_wlog_debug.51 */
  a12 = 0x4; /* 0130: movi.n a12, 4 */
  a11 = 0x8; /* 0132: movi.n a11, 8 */
  a10 = 0x1; /* 0134: movi.n a10, 1 */
  a8 = (uint32_t)&wifi_log; /* 0136: l32r a8, 38 <pm_tx_null_data_done_process-0x34> (0 <pm_tx_null_data_done_process-0x6c>) */ /* literal: GOT slot for wifi_log */
  wifi_log(a2, a3, a4, a5); /* call via literal slot */ /* 0139: callx8 a8 */
  goto L_306; /* 013c: j 306 <pm_tx_null_data_done_process+0x29a> */
  /* 013f: .byte 00 */
  /* 0140: .byte 00 */
L_141:;
  a7 = MEM32(a7 + 228); /* 0141: l32i a7, a7, 228 */
  if (a7 == 0) goto L_18d; /* 0144: beqz a7, 18d <pm_tx_null_data_done_process+0x121> */
  a7 = a7 + ((0x300) << 8); /* 0147: addmi a7, a7, 0x300 */
  a7 = MEM8(a7 + 52); /* 014a: l8ui a7, a7, 52 */
  if (a7 == 0) goto L_151; /* 014d: beqz.n a7, 151 <pm_tx_null_data_done_process+0xe5> */
  if (a4 == 0) goto L_18d; /* 014f: beqz.n a4, 18d <pm_tx_null_data_done_process+0x121> */
L_151:;
  a8 = (uint32_t)&pm_enable_keep_alive_timer; /* 0151: l32r a8, 3c <pm_tx_null_data_done_process-0x30> (0 <pm_tx_null_data_done_process-0x6c>) */ /* literal: GOT slot for pm_enable_keep_alive_timer */
  pm_enable_keep_alive_timer(a2, a3, a4, a5); /* call via literal slot */ /* 0154: callx8 a8 */
  a7 = (uint32_t)&g_osi_funcs_p; /* 0157: l32r a7, 24 <pm_tx_null_data_done_process-0x48> (0 <pm_tx_null_data_done_process-0x6c>) */ /* literal @0x24: g_osi_funcs_p */
  a7 = MEM32(a7 + 0); /* 015a: l32i.n a7, a7, 0 */
  a10 = MEM32(a7 + 272); /* 015c: l32i a10, a7, 0x110 */
  a7 = 0x0; /* 015f: movi.n a7, 0 */
  ((int32_t(*)())a10)(a2, a3, a4, a5); /* 0161: callx8 a10 */ /* indirect */
  MEM32(a5 + 480) = a10; /* 0164: s32i a10, a5, 0x1e0 */
  MEM32(a5 + 484) = a11; /* 0167: s32i a11, a5, 0x1e4 */
  MEM8(a6 + 232) = a7; /* 016a: s8i a7, a6, 232 */
  MEMW(); /* 016d: memw  */
  a14 = (uint32_t)&lit_rodata_pm_tx_null_data_done_process_str1_1; /* 0170: l32r a14, 0 <pm_tx_null_data_done_process-0x6c> (0 <pm_tx_null_data_done_process-0x6c>) */ /* literal @0x0: .rodata.pm_tx_null_data_done_process.str1.1 */
  if (a4 != 0) goto L_178; /* 0173: bnez.n a4, 178 <pm_tx_null_data_done_process+0x10c> */
  a14 = (uint32_t)&lit_rodata_pm_tx_null_data_done_process_str1_1; /* 0175: l32r a14, 4 <pm_tx_null_data_done_process-0x68> (a <pm_tx_null_data_done_process-0x62>) */ /* literal @0x4: .rodata.pm_tx_null_data_done_process.str1.1 */
L_178:;
  a11 = 0x1; /* 0178: movi.n a11, 1 */
  a12 = 0x4; /* 017a: movi.n a12, 4 */
  a11 = 0x1000; /* 017c: slli a11, a11, 12 */
  a10 = 0x6; /* 017f: movi.n a10, 6 */
  a13 = (uint32_t)&lit_rodata_wlog_debug_52; /* 0181: l32r a13, 28 <pm_tx_null_data_done_process-0x44> (0 <pm_tx_null_data_done_process-0x6c>) */ /* literal @0x28: .rodata_wlog_debug.52 */
  MEMW(); /* 0184: memw  */
  a8 = (uint32_t)&wifi_log; /* 0187: l32r a8, 40 <pm_tx_null_data_done_process-0x2c> (0 <pm_tx_null_data_done_process-0x6c>) */ /* literal: GOT slot for wifi_log */
  wifi_log(a2, a3, a4, a5); /* call via literal slot */ /* 018a: callx8 a8 */
L_18d:;
  if (a2 != 0) goto L_1f7; /* 018d: bnez a2, 1f7 <pm_tx_null_data_done_process+0x18b> */
  a4 = MEM8(a5 + 19); /* 0190: l8ui a4, a5, 19 */
  MEM8(a5 + 9) = a2; /* 0193: s8i a2, a5, 9 */
  MEMW(); /* 0196: memw  */
  if (a4 == 0) goto L_306; /* 0199: beqz a4, 306 <pm_tx_null_data_done_process+0x29a> */
  a4 = MEM8(a6 + 200); /* 019c: l8ui a4, a6, 200 */
  if (a4 == 0) goto L_1a5; /* 019f: beqz a4, 1a5 <pm_tx_null_data_done_process+0x139> */
  MEM8(a6 + 200) = a2; /* 01a2: s8i a2, a6, 200 */
L_1a5:;
  a2 = 0x0; /* 01a5: movi.n a2, 0 */
  MEM8(a5 + 19) = a2; /* 01a7: s8i a2, a5, 19 */
  MEMW(); /* 01aa: memw  */
  a2 = MEM8(a5 + 24); /* 01ad: l8ui a2, a5, 24 */
  if (a2 == 0) goto L_2b0; /* 01b0: beqz a2, 2b0 <pm_tx_null_data_done_process+0x244> */
  a2 = 0x0; /* 01b3: movi.n a2, 0 */
  a3 = a3 + (-1); /* 01b5: addi.n a3, a3, -1 */
  a10 = 0x1; /* 01b7: movi.n a10, 1 */
  if (a3 != 0) a10 = a2; /* 01b9: movnez a10, a2, a3 */
  MEMW(); /* 01bc: memw  */
  a8 = (uint32_t)&pm_tx_null_data_done_quick_wake_process; /* 01bf: l32r a8, 44 <pm_tx_null_data_done_process-0x28> (0 <pm_tx_null_data_done_process-0x6c>) */ /* literal: GOT slot for pm_tx_null_data_done_quick_wake_process */
  pm_tx_null_data_done_quick_wake_process(a2, a3, a4, a5); /* call via literal slot */ /* 01c2: callx8 a8 */
  if (a10 != a2) goto L_1cb; /* 01c5: bne a10, a2, 1cb <pm_tx_null_data_done_process+0x15f> */
  goto L_306; /* 01c8: j 306 <pm_tx_null_data_done_process+0x29a> */
L_1cb:;
  a10 = a2; /* 01cb: mov.n a10, a2 */
  MEM8(a5 + 18) = a2; /* 01cd: s8i a2, a5, 18 */
  MEMW(); /* 01d0: memw  */
  MEMW(); /* 01d3: memw  */
  a8 = (uint32_t)&pm_set_state; /* 01d6: l32r a8, 48 <pm_tx_null_data_done_process-0x24> (c <pm_tx_null_data_done_process-0x60>) */ /* literal: GOT slot for .text.pm_set_state */
  pm_set_state(a2, a3, a4, a5); /* call via literal slot */ /* 01d9: callx8 a8 */
  a8 = (uint32_t)&pm_enable_active_timer; /* 01dc: l32r a8, 4c <pm_tx_null_data_done_process-0x20> (0 <pm_tx_null_data_done_process-0x6c>) */ /* literal: GOT slot for pm_enable_active_timer */
  pm_enable_active_timer(a2, a3, a4, a5); /* call via literal slot */ /* 01df: callx8 a8 */
  a3 = (uint32_t)&g_pm_cnt; /* 01e2: l32r a3, 2c <pm_tx_null_data_done_process-0x40> (0 <pm_tx_null_data_done_process-0x6c>) */ /* literal @0x2C: g_pm_cnt */
  a2 = MEM32(a3 + 32); /* 01e5: l32i.n a2, a3, 32 */
  a2 = a2 + (1); /* 01e7: addi.n a2, a2, 1 */
  MEM32(a3 + 32) = a2; /* 01e9: s32i.n a2, a3, 32 */
  MEMW(); /* 01eb: memw  */
  a8 = (uint32_t)&ppProcessWaitingQueue; /* 01ee: l32r a8, 50 <pm_tx_null_data_done_process-0x1c> (0 <pm_tx_null_data_done_process-0x6c>) */ /* literal: GOT slot for ppProcessWaitingQueue */
  ppProcessWaitingQueue(a2, a3, a4, a5); /* call via literal slot */ /* 01f1: callx8 a8 */
  goto L_306; /* 01f4: j 306 <pm_tx_null_data_done_process+0x29a> */
L_1f7:;
  a2 = 0x0; /* 01f7: movi.n a2, 0 */
  a3 = MEM8(a5 + 20); /* 01f9: l8ui a3, a5, 20 */
  MEM8(a5 + 10) = a2; /* 01fc: s8i a2, a5, 10 */
  MEMW(); /* 01ff: memw  */
  if (a3 == 0) goto L_fd; /* 0202: beqz a3, fd <pm_tx_null_data_done_process+0x91> */
  MEM8(a5 + 20) = a2; /* 0205: s8i a2, a5, 20 */
  MEMW(); /* 0208: memw  */
  a2 = MEM8(a6 + 212); /* 020b: l8ui a2, a6, 212 */
  if (a2 != 0) goto L_221; /* 020e: bnez.n a2, 221 <pm_tx_null_data_done_process+0x1b5> */
L_210:;
  a2 = a5 + ((0x200) << 8); /* 0210: addmi a2, a5, 0x200 */
  a2 = MEM8(a2 + 31); /* 0213: l8ui a2, a2, 31 */
  if (a2 != 0) goto L_241; /* 0216: bnez.n a2, 241 <pm_tx_null_data_done_process+0x1d5> */
  MEMW(); /* 0218: memw  */
  goto L_25c; /* 021b: j 25c <pm_tx_null_data_done_process+0x1f0> */
  /* 021e: .byte 00 */
  /* 021f: .byte 00 */
  /* 0220: .byte 00 */
L_221:;
  a2 = (uint32_t)&g_osi_funcs_p; /* 0221: l32r a2, 24 <pm_tx_null_data_done_process-0x48> (0 <pm_tx_null_data_done_process-0x6c>) */ /* literal @0x24: g_osi_funcs_p */
  a2 = MEM32(a2 + 0); /* 0224: l32i.n a2, a2, 0 */
  a10 = MEM32(a2 + 404); /* 0226: l32i a10, a2, 0x194 */
  ((int32_t(*)())a10)(a2, a3, a4, a5); /* 0229: callx8 a10 */ /* indirect */
  if (a10 != 0) goto L_238; /* 022c: bnez.n a10, 238 <pm_tx_null_data_done_process+0x1cc> */
L_22e:;
  a8 = (uint32_t)&pm_sleep; /* 022e: l32r a8, 54 <pm_tx_null_data_done_process-0x18> (0 <pm_tx_null_data_done_process-0x6c>) */ /* literal: GOT slot for pm_sleep */
  pm_sleep(a2, a3, a4, a5); /* call via literal slot */ /* 0231: callx8 a8 */
  goto L_262; /* 0234: j 262 <pm_tx_null_data_done_process+0x1f6> */
  /* 0237: .byte 00 */
L_238:;
  a2 = MEM8(a5 + 25); /* 0238: l8ui a2, a5, 25 */
  if (a2 != 0) goto L_210; /* 023b: bnez a2, 210 <pm_tx_null_data_done_process+0x1a4> */
  goto L_22e; /* 023e: j 22e <pm_tx_null_data_done_process+0x1c2> */
L_241:;
  a2 = (uint32_t)&g_osi_funcs_p; /* 0241: l32r a2, 24 <pm_tx_null_data_done_process-0x48> (0 <pm_tx_null_data_done_process-0x6c>) */ /* literal @0x24: g_osi_funcs_p */
  a2 = MEM32(a2 + 0); /* 0244: l32i a2, a2, 0 */
  a10 = MEM32(a2 + 272); /* 0247: l32i a10, a2, 0x110 */
  ((int32_t(*)())a10)(a2, a3, a4, a5); /* 024a: callx8 a10 */ /* indirect */
  a2 = MEM32(a5 + 572); /* 024d: l32i a2, a5, 0x23c */
  if (a11 < a2) goto L_25c; /* 0250: bltu a11, a2, 25c <pm_tx_null_data_done_process+0x1f0> */
  if (a2 != a11) goto L_22e; /* 0253: bne a2, a11, 22e <pm_tx_null_data_done_process+0x1c2> */
  a2 = MEM32(a5 + 568); /* 0256: l32i a2, a5, 0x238 */
  if (a10 >= a2) goto L_22e; /* 0259: bgeu a10, a2, 22e <pm_tx_null_data_done_process+0x1c2> */
L_25c:;
  a8 = (uint32_t)&pm_enable_sleep_delay_timer; /* 025c: l32r a8, 58 <pm_tx_null_data_done_process-0x14> (0 <pm_tx_null_data_done_process-0x6c>) */ /* literal: GOT slot for pm_enable_sleep_delay_timer */
  pm_enable_sleep_delay_timer(a2, a3, a4, a5); /* call via literal slot */ /* 025f: callx8 a8 */
L_262:;
  a3 = (uint32_t)&g_pm_cnt; /* 0262: l32r a3, 2c <pm_tx_null_data_done_process-0x40> (0 <pm_tx_null_data_done_process-0x6c>) */ /* literal @0x2C: g_pm_cnt */
  a2 = MEM32(a3 + 28); /* 0265: l32i.n a2, a3, 28 */
  a2 = a2 + (1); /* 0267: addi.n a2, a2, 1 */
  MEM32(a3 + 28) = a2; /* 0269: s32i.n a2, a3, 28 */
  MEMW(); /* 026b: memw  */
  goto L_fd; /* 026e: j fd <pm_tx_null_data_done_process+0x91> */
L_271:;
  if (a2 != 0) goto L_2c0; /* 0271: bnez a2, 2c0 <pm_tx_null_data_done_process+0x254> */
  if (a7 == 0) goto L_306; /* 0274: beqz a7, 306 <pm_tx_null_data_done_process+0x29a> */
  a3 = (uint32_t)&g_osi_funcs_p; /* 0277: l32r a3, 24 <pm_tx_null_data_done_process-0x48> (0 <pm_tx_null_data_done_process-0x6c>) */ /* literal @0x24: g_osi_funcs_p */
  a3 = MEM32(a3 + 0); /* 027a: l32i a3, a3, 0 */
  a10 = MEM32(a3 + 272); /* 027d: l32i a10, a3, 0x110 */
  MEM8(a5 + 19) = a2; /* 0280: s8i a2, a5, 19 */
  MEMW(); /* 0283: memw  */
  MEMW(); /* 0286: memw  */
  ((int32_t(*)())a10)(a2, a3, a4, a5); /* 0289: callx8 a10 */ /* indirect */
  a12 = 0x271; /* 028c: movi a12, 0x271 */
  a12 = 0x1388; /* 028f: slli a12, a12, 3 */
  a8 = (uint32_t)&pm_is_in_wifi_slice_threshold; /* 0292: l32r a8, 5c <pm_tx_null_data_done_process-0x10> (0 <pm_tx_null_data_done_process-0x6c>) */ /* literal: GOT slot for pm_is_in_wifi_slice_threshold */
  pm_is_in_wifi_slice_threshold(a2, a3, a4, a5); /* call via literal slot */ /* 0295: callx8 a8 */
  if (a10 == 0) goto L_2ad; /* 0298: beqz.n a10, 2ad <pm_tx_null_data_done_process+0x241> */
  a3 = MEM8(a5 + 9); /* 029a: l8ui a3, a5, 9 */
  a3 = a3 + (1); /* 029d: addi.n a3, a3, 1 */
  MEM8(a5 + 9) = a3; /* 029f: s8i a3, a5, 9 */
  MEMW(); /* 02a2: memw  */
  MEMW(); /* 02a5: memw  */
  goto L_2de; /* 02a8: j 2de <pm_tx_null_data_done_process+0x272> */
  /* 02ab: .byte 00 */
  /* 02ac: .byte 00 */
L_2ad:;
  MEM8(a5 + 9) = a2; /* 02ad: s8i a2, a5, 9 */
L_2b0:;
  a2 = 0x1; /* 02b0: movi.n a2, 1 */
  MEM8(a5 + 25) = a2; /* 02b2: s8i a2, a5, 25 */
  MEMW(); /* 02b5: memw  */
  MEMW(); /* 02b8: memw  */
  goto L_306; /* 02bb: j 306 <pm_tx_null_data_done_process+0x29a> */
  /* 02be: .byte 00 */
  /* 02bf: .byte 00 */
L_2c0:;
  if (a2 != 1) goto L_306; /* 02c0: bnei a2, 1, 306 <pm_tx_null_data_done_process+0x29a> */
  a3 = MEM8(a5 + 20); /* 02c3: l8ui a3, a5, 20 */
  if (a3 == 0) goto L_306; /* 02c6: beqz.n a3, 306 <pm_tx_null_data_done_process+0x29a> */
  a3 = MEM8(a5 + 24); /* 02c8: l8ui a3, a5, 24 */
  MEM8(a5 + 20) = a8; /* 02cb: s8i a8, a5, 20 */
  MEMW(); /* 02ce: memw  */
  if (a3 == 0) goto L_2ec; /* 02d1: beqz.n a3, 2ec <pm_tx_null_data_done_process+0x280> */
  a3 = MEM8(a5 + 10); /* 02d3: l8ui a3, a5, 10 */
  a3 = a3 + (1); /* 02d6: addi.n a3, a3, 1 */
  MEM8(a5 + 10) = a3; /* 02d8: s8i a3, a5, 10 */
  MEMW(); /* 02db: memw  */
L_2de:;
  a10 = 0x1; /* 02de: mov.n a10, a2 */
  MEMW(); /* 02e0: memw  */
  a8 = (uint32_t)&pm_send_nullfunc; /* 02e3: l32r a8, 60 <pm_tx_null_data_done_process-0xc> (0 <pm_tx_null_data_done_process-0x6c>) */ /* literal: GOT slot for pm_send_nullfunc */
  pm_send_nullfunc(a2, a3, a4, a5); /* call via literal slot */ /* 02e6: callx8 a8 */
  goto L_306; /* 02e9: j 306 <pm_tx_null_data_done_process+0x29a> */
L_2ec:;
  MEM8(a5 + 10) = a8; /* 02ec: s8i a8, a5, 10 */
  MEM8(a5 + 25) = a2; /* 02ef: s8i a2, a5, 25 */
  MEMW(); /* 02f2: memw  */
  MEMW(); /* 02f5: memw  */
  a8 = (uint32_t)&pm_enable_sleep_delay_timer; /* 02f8: l32r a8, 64 <pm_tx_null_data_done_process-0x8> (0 <pm_tx_null_data_done_process-0x6c>) */ /* literal: GOT slot for pm_enable_sleep_delay_timer */
  pm_enable_sleep_delay_timer(a2, a3, a4, a5); /* call via literal slot */ /* 02fb: callx8 a8 */
  a10 = a2; /* 02fe: mov.n a10, a2 */
L_300:;
  a8 = (uint32_t)&pm_offchan_execute_ready_cb; /* 0300: l32r a8, 68 <pm_tx_null_data_done_process-0x4> (0 <pm_tx_null_data_done_process-0x6c>) */ /* literal: GOT slot for pm_offchan_execute_ready_cb */
  pm_offchan_execute_ready_cb(a2, a3, a4, a5); /* call via literal slot */ /* 0303: callx8 a8 */
L_306:;
  return (int32_t)a2; /* 0306: retw.n  */
}

/* pm_go_to_wake @ pm.o 0000003c size 276B bind GLOBAL
 * Calls: pm_dream, pm_is_in_wifi_slice_threshold, pm_send_nullfunc, pm_tx_null_data_done_process, ppCheckTxConnTrafficIdle, esp_mesh_quick_funcs[got] | Data refs: esp_mesh_quick_funcs, g_mesh_init_ps_type, g_mesh_is_root, g_mesh_is_started, g_osi_funcs_p, g_pm, pm_dream, pm_is_in_wifi_slice_threshold, pm_send_nullfunc, pm_tx_null_data_done_process, ppCheckTxConnTrafficIdle
 *   MMIO: none
 *   funcdb v3: 5 call(s), 11 ref(s); disasm: 8 call(s), 11 data ref(s)
 * Fidelity: medium - 103 instr, 24 branches, calls resolved */
int32_t pm_go_to_wake(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pm_go_to_wake; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_3c:;
  /* 003c: entry a1, 32 */
  a4 = (uint32_t)&g_pm; /* 003f: l32r a4, 0 <pm_go_to_wake-0x3c> (0 <pm_go_to_wake-0x3c>) */ /* literal @0x0: g_pm */
  a6 = (a2 >> 0) & 0xFF; /* 0042: extui a6, a2, 0, 8 */
  a2 = 0x0; /* 0045: movi a2, 0 */
  a3 = (a3 >> 0) & 0xFF; /* 0048: extui a3, a3, 0, 8 */
  a5 = MEM8(a4 + 13); /* 004b: l8ui a5, a4, 13 */
  if (a5 != a2) goto L_54; /* 004e: bne a5, a2, 54 <pm_go_to_wake+0x18> */
  goto L_14e; /* 0051: j 14e <pm_go_to_wake+0x112> */
L_54:;
  a5 = MEM8(a4 + 14); /* 0054: l8ui a5, a4, 14 */
  if (a5 != a2) goto L_5d; /* 0057: bne a5, a2, 5d <pm_go_to_wake+0x21> */
  goto L_14e; /* 005a: j 14e <pm_go_to_wake+0x112> */
L_5d:;
  a9 = 0x1; /* 005d: movi a9, 1 */
  a5 = a4 + ((0x100) << 8); /* 0060: addmi a5, a4, 0x100 */
  a8 = MEM8(a4 + 15); /* 0063: l8ui a8, a4, 15 */
  a8 = a8 ^ a9; /* 0066: xor a8, a8, a9 */
  a8 = (a8 >> 0) & 0xFF; /* 0069: extui a8, a8, 0, 8 */
  a5 = MEM8(a5 + 232); /* 006c: l8ui a5, a5, 232 */
  if (a8 != a2) goto L_78; /* 006f: bne a8, a2, 78 <pm_go_to_wake+0x3c> */
  if (a5 != a2) goto L_78; /* 0072: bne a5, a2, 78 <pm_go_to_wake+0x3c> */
  goto L_14e; /* 0075: j 14e <pm_go_to_wake+0x112> */
L_78:;
  a2 = MEM8(a4 + 24); /* 0078: l8ui a2, a4, 24 */
  if (a2 != 0) goto L_8d; /* 007b: bnez.n a2, 8d <pm_go_to_wake+0x51> */
L_7d:;
  a2 = 0x1; /* 007d: movi.n a2, 1 */
  MEM8(a4 + 25) = a2; /* 007f: s8i a2, a4, 25 */
  MEMW(); /* 0082: memw  */
  a2 = 0x1; /* 0085: movi.n a2, 1 */
  MEMW(); /* 0087: memw  */
  goto L_14e; /* 008a: j 14e <pm_go_to_wake+0x112> */
L_8d:;
  a2 = MEM8(a4 + 1); /* 008d: l8ui a2, a4, 1 */
  if (a2 != 2) goto L_99; /* 0090: bnei a2, 2, 99 <pm_go_to_wake+0x5d> */
  a8 = (uint32_t)&pm_dream; /* 0093: l32r a8, 20 <pm_go_to_wake-0x1c> (0 <pm_go_to_wake-0x3c>) */ /* literal: GOT slot for pm_dream */
  pm_dream(a2, a3, a4, a5); /* call via literal slot */ /* 0096: callx8 a8 */
L_99:;
  if (a6 == 0) goto L_cc; /* 0099: beqz.n a6, cc <pm_go_to_wake+0x90> */
  a2 = (uint32_t)&g_mesh_is_started; /* 009b: l32r a2, 4 <pm_go_to_wake-0x38> (0 <pm_go_to_wake-0x3c>) */ /* literal @0x4: g_mesh_is_started */
  a2 = MEM8(a2 + 0); /* 009e: l8ui a2, a2, 0 */
  if (a2 == 0) goto L_cc; /* 00a1: beqz.n a2, cc <pm_go_to_wake+0x90> */
  a2 = (uint32_t)&g_mesh_is_root; /* 00a3: l32r a2, 8 <pm_go_to_wake-0x34> (0 <pm_go_to_wake-0x3c>) */ /* literal @0x8: g_mesh_is_root */
  MEMW(); /* 00a6: memw  */
  a10 = MEM8(a2 + 0); /* 00a9: l8ui a10, a2, 0 */
  a10 = (a10 >> 0) & 0xFF; /* 00ac: extui a10, a10, 0, 8 */
  if (a10 != 0) goto L_cc; /* 00af: bnez.n a10, cc <pm_go_to_wake+0x90> */
  a2 = (uint32_t)&g_mesh_init_ps_type; /* 00b1: l32r a2, c <pm_go_to_wake-0x30> (0 <pm_go_to_wake-0x3c>) */ /* literal @0xC: g_mesh_init_ps_type */
  a2 = MEM32(a2 + 0); /* 00b4: l32i.n a2, a2, 0 */
  if (a2 == 0) goto L_cc; /* 00b6: beqz a2, cc <pm_go_to_wake+0x90> */
  a2 = (uint32_t)&esp_mesh_quick_funcs; /* 00b9: l32r a2, 18 <pm_go_to_wake-0x24> (0 <pm_go_to_wake-0x3c>) */ /* literal @0x18: esp_mesh_quick_funcs */
  a12 = (uint32_t)&g_pm; /* 00bc: l32r a12, 10 <pm_go_to_wake-0x2c> (0 <pm_go_to_wake-0x3c>) */ /* literal @0x10: g_pm */
  a2 = MEM32(a2 + 140); /* 00bf: l32i a2, a2, 140 */
  a11 = (uint32_t)&g_pm; /* 00c2: l32r a11, 14 <pm_go_to_wake-0x28> (0 <pm_go_to_wake-0x3c>) */ /* literal @0x14: g_pm */
  esp_mesh_quick_funcs(a2, a3, a4, a5); /* call via literal slot */ /* 00c5: callx8 a2 */
  goto L_14c; /* 00c8: j 14c <pm_go_to_wake+0x110> */
  /* 00cb: .byte 00 */
L_cc:;
  a2 = MEM8(a4 + 19); /* 00cc: l8ui a2, a4, 19 */
  if (a2 != 0) goto L_126; /* 00cf: bnez a2, 126 <pm_go_to_wake+0xea> */
  if (a3 != 0) goto L_126; /* 00d2: bnez a3, 126 <pm_go_to_wake+0xea> */
  a10 = 0x1; /* 00d5: movi.n a10, 1 */
  a8 = (uint32_t)&ppCheckTxConnTrafficIdle; /* 00d7: l32r a8, 24 <pm_go_to_wake-0x18> (0 <pm_go_to_wake-0x3c>) */ /* literal: GOT slot for ppCheckTxConnTrafficIdle */
  ppCheckTxConnTrafficIdle(a2, a3, a4, a5); /* call via literal slot */ /* 00da: callx8 a8 */
  a2 = 0x1; /* 00dd: mov.n a2, a10 */
  if (a10 == 0) goto L_f9; /* 00df: beqz.n a10, f9 <pm_go_to_wake+0xbd> */
  a5 = 0x1; /* 00e1: movi.n a5, 1 */
  a12 = a3; /* 00e3: mov.n a12, a3 */
  a11 = 0x1; /* 00e5: movi.n a11, 1 */
  a10 = a3 | a3; /* 00e7: or a10, a3, a3 */
  MEM8(a4 + 19) = a5; /* 00ea: s8i a5, a4, 19 */
  MEMW(); /* 00ed: memw  */
  MEMW(); /* 00f0: memw  */
  a8 = (uint32_t)&pm_tx_null_data_done_process; /* 00f3: l32r a8, 28 <pm_go_to_wake-0x14> (0 <pm_go_to_wake-0x3c>) */ /* literal: GOT slot for pm_tx_null_data_done_process */
  pm_tx_null_data_done_process(a2, a3, a4, a5); /* call via literal slot */ /* 00f6: callx8 a8 */
L_f9:;
  a3 = (uint32_t)&g_osi_funcs_p; /* 00f9: l32r a3, 1c <pm_go_to_wake-0x20> (0 <pm_go_to_wake-0x3c>) */ /* literal @0x1C: g_osi_funcs_p */
  a3 = MEM32(a3 + 0); /* 00fc: l32i.n a3, a3, 0 */
  a10 = MEM32(a3 + 272); /* 00fe: l32i a10, a3, 0x110 */
  ((int32_t(*)())a10)(a2, a3, a4, a5); /* 0101: callx8 a10 */ /* indirect */
  a12 = 0x271; /* 0104: movi a12, 0x271 */
  a12 = 0x1388; /* 0107: slli a12, a12, 3 */
  a8 = (uint32_t)&pm_is_in_wifi_slice_threshold; /* 010a: l32r a8, 2c <pm_go_to_wake-0x10> (0 <pm_go_to_wake-0x3c>) */ /* literal: GOT slot for pm_is_in_wifi_slice_threshold */
  pm_is_in_wifi_slice_threshold(a2, a3, a4, a5); /* call via literal slot */ /* 010d: callx8 a8 */
  if (a10 == 0) goto L_11f; /* 0110: beqz.n a10, 11f <pm_go_to_wake+0xe3> */
  a10 = 0x0; /* 0112: movi.n a10, 0 */
  a8 = (uint32_t)&pm_send_nullfunc; /* 0114: l32r a8, 30 <pm_go_to_wake-0xc> (0 <pm_go_to_wake-0x3c>) */ /* literal: GOT slot for pm_send_nullfunc */
  pm_send_nullfunc(a2, a3, a4, a5); /* call via literal slot */ /* 0117: callx8 a8 */
  a2 = 0x3; /* 011a: movi.n a2, 3 */
  goto L_14e; /* 011c: j 14e <pm_go_to_wake+0x112> */
L_11f:;
  if (a2 == 0) goto L_7d; /* 011f: beqz a2, 7d <pm_go_to_wake+0x41> */
  goto L_14c; /* 0122: j 14c <pm_go_to_wake+0x110> */
  /* 0125: .byte 00 */
L_126:;
  if (a5 == 0) goto L_135; /* 0126: beqz.n a5, 135 <pm_go_to_wake+0xf9> */
  a10 = 0x0; /* 0128: movi.n a10, 0 */
  a8 = (uint32_t)&pm_send_nullfunc; /* 012a: l32r a8, 34 <pm_go_to_wake-0x8> (0 <pm_go_to_wake-0x3c>) */ /* literal: GOT slot for pm_send_nullfunc */
  pm_send_nullfunc(a2, a3, a4, a5); /* call via literal slot */ /* 012d: callx8 a8 */
  goto L_14c; /* 0130: j 14c <pm_go_to_wake+0x110> */
  /* 0133: .byte 00 */
  /* 0134: .byte 00 */
L_135:;
  a2 = 0x1; /* 0135: movi.n a2, 1 */
  a12 = a5; /* 0137: mov.n a12, a5 */
  a11 = 0x1; /* 0139: movi.n a11, 1 */
  a10 = a5; /* 013b: mov.n a10, a5 */
  MEM8(a4 + 19) = a2; /* 013d: s8i a2, a4, 19 */
  MEMW(); /* 0140: memw  */
  MEMW(); /* 0143: memw  */
  a8 = (uint32_t)&pm_tx_null_data_done_process; /* 0146: l32r a8, 38 <pm_go_to_wake-0x4> (0 <pm_go_to_wake-0x3c>) */ /* literal: GOT slot for pm_tx_null_data_done_process */
  pm_tx_null_data_done_process(a2, a3, a4, a5); /* call via literal slot */ /* 0149: callx8 a8 */
L_14c:;
  a2 = 0x2; /* 014c: movi.n a2, 2 */
L_14e:;
  return (int32_t)a2; /* 014e: retw.n  */
}

/* pm_send_probe_stop @ pm.o 00000014 size 93B bind GLOBAL
 * Calls: pm_enable_active_timer, pm_go_to_wake, pm_wake_done, ppCheckTxConnTrafficIdle | Data refs: g_pm, pm_enable_active_timer, pm_go_to_wake, pm_wake_done, ppCheckTxConnTrafficIdle
 *   MMIO: none
 *   funcdb v3: 4 call(s), 5 ref(s); disasm: 4 call(s), 5 data ref(s)
 * Fidelity: medium - 33 instr, 8 branches, calls resolved */
int32_t pm_send_probe_stop(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pm_send_probe_stop; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_14:;
  /* 0014: entry a1, 32 */
  a8 = (uint32_t)&g_pm; /* 0017: l32r a8, 0 <pm_send_probe_stop-0x14> (0 <pm_send_probe_stop-0x14>) */ /* literal @0x0: g_pm */
  a9 = a8 + ((0x100) << 8); /* 001a: addmi a9, a8, 0x100 */
  a10 = MEM8(a9 + 29); /* 001d: l8ui a10, a9, 29 */
  if (a10 >= 2) goto L_29; /* 0020: bgeui a10, 2, 29 <pm_send_probe_stop+0x15> */
  a10 = MEM8(a8 + 13); /* 0023: l8ui a10, a8, 13 */
  if (a10 == 0) goto L_6f; /* 0026: beqz a10, 6f <pm_send_probe_stop+0x5b> */
L_29:;
  a10 = MEM8(a8 + 15); /* 0029: l8ui a10, a8, 15 */
  if (a10 == 0) goto L_6f; /* 002c: beqz.n a10, 6f <pm_send_probe_stop+0x5b> */
  a10 = 0x0; /* 002e: movi.n a10, 0 */
  MEM8(a8 + 15) = a10; /* 0030: s8i a10, a8, 15 */
  MEMW(); /* 0033: memw  */
  a10 = MEM8(a9 + 28); /* 0036: l8ui a10, a9, 28 */
  if (a10 == 0) goto L_4c; /* 0039: beqz a10, 4c <pm_send_probe_stop+0x38> */
L_3c:;
  a11 = 0x0; /* 003c: movi.n a11, 0 */
  a10 = 0x0; /* 003e: mov.n a10, a11 */
  MEMW(); /* 0040: memw  */
  a8 = (uint32_t)&pm_go_to_wake; /* 0043: l32r a8, 4 <pm_send_probe_stop-0x10> (0 <pm_send_probe_stop-0x14>) */ /* literal: GOT slot for pm_go_to_wake */
  pm_go_to_wake(a2, a3, a4, a5); /* call via literal slot */ /* 0046: callx8 a8 */
  goto L_63; /* 0049: j 63 <pm_send_probe_stop+0x4f> */
L_4c:;
  a9 = MEM8(a9 + 200); /* 004c: l8ui a9, a9, 200 */
  if (a9 != 0) goto L_3c; /* 004f: bnez a9, 3c <pm_send_probe_stop+0x28> */
  a8 = MEM8(a8 + 25); /* 0052: l8ui a8, a8, 25 */
  if (a8 != 0) goto L_3c; /* 0055: bnez a8, 3c <pm_send_probe_stop+0x28> */
  a10 = 0x1; /* 0058: movi.n a10, 1 */
  a8 = (uint32_t)&ppCheckTxConnTrafficIdle; /* 005a: l32r a8, 8 <pm_send_probe_stop-0xc> (0 <pm_send_probe_stop-0x14>) */ /* literal: GOT slot for ppCheckTxConnTrafficIdle */
  ppCheckTxConnTrafficIdle(a2, a3, a4, a5); /* call via literal slot */ /* 005d: callx8 a8 */
  if (a10 != 0) goto L_3c; /* 0060: bnez a10, 3c <pm_send_probe_stop+0x28> */
L_63:;
  a8 = (uint32_t)&pm_enable_active_timer; /* 0063: l32r a8, c <pm_send_probe_stop-0x8> (0 <pm_send_probe_stop-0x14>) */ /* literal: GOT slot for pm_enable_active_timer */
  pm_enable_active_timer(a2, a3, a4, a5); /* call via literal slot */ /* 0066: callx8 a8 */
  a8 = (uint32_t)&pm_wake_done; /* 0069: l32r a8, 10 <pm_send_probe_stop-0x4> (0 <pm_send_probe_stop-0x14>) */ /* literal: GOT slot for pm_wake_done */
  pm_wake_done(a2, a3, a4, a5); /* call via literal slot */ /* 006c: callx8 a8 */
L_6f:;
  return (int32_t)a2; /* 006f: retw.n  */
}

/* pm_on_channel @ pm.o 0000001c size 165B bind GLOBAL
 * Calls: pm_enable_active_timer, pm_go_to_wake, pm_wake_done, ppCheckTxConnTrafficIdle, .text.hal_pm_unblock_txq[got] | Data refs: g_pm, pm_enable_active_timer, pm_go_to_wake, pm_wake_done, ppCheckTxConnTrafficIdle, .text.hal_pm_unblock_txq
 *   MMIO: none
 *   funcdb v3: 4 call(s), 5 ref(s); disasm: 6 call(s), 6 data ref(s)
 * Fidelity: medium - 63 instr, 14 branches, calls resolved */
int32_t pm_on_channel(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pm_on_channel; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_1c:;
  /* 001c: entry a1, 32 */
  a2 = (uint32_t)&g_pm; /* 001f: l32r a2, 0 <pm_on_channel-0x1c> (0 <pm_on_channel-0x1c>) */ /* literal @0x0: g_pm */
  a3 = a2 + ((0x100) << 8); /* 0022: addmi a3, a2, 0x100 */
  a8 = MEM8(a3 + 29); /* 0025: l8ui a8, a3, 29 */
  if (a8 >= 2) goto L_30; /* 0028: bgeui a8, 2, 30 <pm_on_channel+0x14> */
  a8 = MEM8(a2 + 13); /* 002b: l8ui a8, a2, 13 */
  if (a8 == 0) goto L_35; /* 002e: beqz.n a8, 35 <pm_on_channel+0x19> */
L_30:;
  a8 = MEM8(a2 + 14); /* 0030: l8ui a8, a2, 14 */
  if (a8 == 0) goto L_46; /* 0033: beqz.n a8, 46 <pm_on_channel+0x2a> */
L_35:;
  a3 = 0x1; /* 0035: movi.n a3, 1 */
  MEM8(a2 + 14) = a3; /* 0037: s8i a3, a2, 14 */
  MEMW(); /* 003a: memw  */
  MEMW(); /* 003d: memw  */
  goto L_bf; /* 0040: j bf <pm_on_channel+0xa3> */
  /* 0043: .byte 00 */
  /* 0044: .byte 00 */
  /* 0045: .byte 00 */
L_46:;
  a8 = 0x1; /* 0046: movi.n a8, 1 */
  MEM8(a2 + 14) = a8; /* 0048: s8i a8, a2, 14 */
  MEMW(); /* 004b: memw  */
  a8 = MEM8(a2 + 13); /* 004e: l8ui a8, a2, 13 */
  if (a8 != 0) goto L_61; /* 0051: bnez.n a8, 61 <pm_on_channel+0x45> */
  MEMW(); /* 0053: memw  */
  a8 = (uint32_t)&pm_wake_done; /* 0056: l32r a8, 4 <pm_on_channel-0x18> (0 <pm_on_channel-0x1c>) */ /* literal: GOT slot for pm_wake_done */
  pm_wake_done(a2, a3, a4, a5); /* call via literal slot */ /* 0059: callx8 a8 */
  goto L_bf; /* 005c: j bf <pm_on_channel+0xa3> */
  /* 005f: .byte 00 */
  /* 0060: .byte 00 */
L_61:;
  a8 = MEM8(a2 + 24); /* 0061: l8ui a8, a2, 24 */
  if (a8 == 0) goto L_6d; /* 0064: beqz a8, 6d <pm_on_channel+0x51> */
  a8 = (uint32_t)&hal_pm_unblock_txq; /* 0067: l32r a8, 8 <pm_on_channel-0x14> (8 <pm_on_channel-0x14>) */ /* literal: GOT slot for .text.hal_pm_unblock_txq */
  hal_pm_unblock_txq(a2, a3, a4, a5); /* call via literal slot */ /* 006a: callx8 a8 */
L_6d:;
  a8 = MEM8(a3 + 28); /* 006d: l8ui a8, a3, 28 */
  if (a8 == 0) goto L_81; /* 0070: beqz.n a8, 81 <pm_on_channel+0x65> */
L_72:;
  a11 = 0x0; /* 0072: movi.n a11, 0 */
  a10 = 0x0; /* 0074: mov.n a10, a11 */
  a8 = (uint32_t)&pm_go_to_wake; /* 0076: l32r a8, c <pm_on_channel-0x10> (0 <pm_on_channel-0x1c>) */ /* literal: GOT slot for pm_go_to_wake */
  pm_go_to_wake(a2, a3, a4, a5); /* call via literal slot */ /* 0079: callx8 a8 */
  if (a10 != 0) goto L_98; /* 007c: bnez.n a10, 98 <pm_on_channel+0x7c> */
  goto L_a0; /* 007e: j a0 <pm_on_channel+0x84> */
L_81:;
  a8 = MEM8(a3 + 200); /* 0081: l8ui a8, a3, 200 */
  if (a8 != 0) goto L_72; /* 0084: bnez a8, 72 <pm_on_channel+0x56> */
  a8 = MEM8(a2 + 25); /* 0087: l8ui a8, a2, 25 */
  if (a8 != 0) goto L_72; /* 008a: bnez a8, 72 <pm_on_channel+0x56> */
  a10 = 0x1; /* 008d: movi.n a10, 1 */
  a8 = (uint32_t)&ppCheckTxConnTrafficIdle; /* 008f: l32r a8, 10 <pm_on_channel-0xc> (0 <pm_on_channel-0x1c>) */ /* literal: GOT slot for ppCheckTxConnTrafficIdle */
  ppCheckTxConnTrafficIdle(a2, a3, a4, a5); /* call via literal slot */ /* 0092: callx8 a8 */
  if (a10 != 0) goto L_72; /* 0095: bnez a10, 72 <pm_on_channel+0x56> */
L_98:;
  a8 = 0x0; /* 0098: movi.n a8, 0 */
  MEM8(a3 + 28) = a8; /* 009a: s8i a8, a3, 28 */
  MEMW(); /* 009d: memw  */
L_a0:;
  a2 = a2 + ((0x200) << 8); /* 00a0: addmi a2, a2, 0x200 */
  a3 = MEM8(a2 + 64); /* 00a3: l8ui a3, a2, 64 */
  if (a3 == 0) goto L_b0; /* 00a6: beqz.n a3, b0 <pm_on_channel+0x94> */
  a3 = 0x0; /* 00a8: movi.n a3, 0 */
  MEM8(a2 + 64) = a3; /* 00aa: s8i a3, a2, 64 */
  MEMW(); /* 00ad: memw  */
L_b0:;
  MEMW(); /* 00b0: memw  */
  a8 = (uint32_t)&pm_wake_done; /* 00b3: l32r a8, 14 <pm_on_channel-0x8> (0 <pm_on_channel-0x1c>) */ /* literal: GOT slot for pm_wake_done */
  pm_wake_done(a2, a3, a4, a5); /* call via literal slot */ /* 00b6: callx8 a8 */
  a8 = (uint32_t)&pm_enable_active_timer; /* 00b9: l32r a8, 18 <pm_on_channel-0x4> (0 <pm_on_channel-0x1c>) */ /* literal: GOT slot for pm_enable_active_timer */
  pm_enable_active_timer(a2, a3, a4, a5); /* call via literal slot */ /* 00bc: callx8 a8 */
L_bf:;
  return (int32_t)a2; /* 00bf: retw.n  */
}

/* pm_offchan_ready_or_defer @ pm.o 0000001c size 88B bind GLOBAL
 * Calls: pm_off_channel, pm_on_channel, wifi_log | Data refs: .bss.g_offchan_ready_cb, .bss.g_offchan_ready_ctx, .rodata_wlog_error.32, g_pm, pm_off_channel, pm_on_channel, wifi_log
 *   MMIO: none
 *   funcdb v3: 3 call(s), 7 ref(s); disasm: 3 call(s), 7 data ref(s)
 * Fidelity: medium - 32 instr, 5 branches, calls resolved */
int32_t pm_offchan_ready_or_defer(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pm_offchan_ready_or_defer; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_1c:;
  /* 001c: entry a1, 32 */
  a4 = (uint32_t)&g_pm; /* 001f: l32r a4, 0 <pm_offchan_ready_or_defer-0x1c> (0 <pm_offchan_ready_or_defer-0x1c>) */ /* literal @0x0: g_pm */
  a8 = 0x2; /* 0022: movi a8, 2 */
  a9 = MEM8(a4 + 14); /* 0025: l8ui a9, a4, 14 */
  if (a9 == 0) goto L_70; /* 0028: beqz a9, 70 <pm_offchan_ready_or_defer+0x54> */
  a8 = (uint32_t)&pm_off_channel; /* 002b: l32r a8, 10 <pm_offchan_ready_or_defer-0xc> (0 <pm_offchan_ready_or_defer-0x1c>) */ /* literal: GOT slot for pm_off_channel */
  pm_off_channel(a2, a3, a4, a5); /* call via literal slot */ /* 002e: callx8 a8 */
  a8 = 0x0; /* 0031: movi.n a8, 0 */
  a9 = MEM8(a4 + 13); /* 0033: l8ui a9, a4, 13 */
  if (a9 == a8) goto L_70; /* 0036: beq a9, a8, 70 <pm_offchan_ready_or_defer+0x54> */
  a9 = MEM8(a4 + 20); /* 0039: l8ui a9, a4, 20 */
  if (a9 == a8) goto L_51; /* 003c: beq a9, a8, 51 <pm_offchan_ready_or_defer+0x35> */
  a8 = 0x1; /* 003f: movi.n a8, 1 */
  a4 = (uint32_t)&bss_g_offchan_ready_cb; /* 0041: l32r a4, 4 <pm_offchan_ready_or_defer-0x18> (0 <pm_offchan_ready_or_defer-0x1c>) */ /* literal @0x4: .bss.g_offchan_ready_cb */
  MEM32(a4 + 0) = a2; /* 0044: s32i.n a2, a4, 0 */
  a4 = (uint32_t)&bss_g_offchan_ready_ctx; /* 0046: l32r a4, 8 <pm_offchan_ready_or_defer-0x14> (0 <pm_offchan_ready_or_defer-0x1c>) */ /* literal @0x8: .bss.g_offchan_ready_ctx */
  MEM32(a4 + 0) = a3; /* 0049: s32i.n a3, a4, 0 */
  MEMW(); /* 004b: memw  */
  goto L_70; /* 004e: j 70 <pm_offchan_ready_or_defer+0x54> */
L_51:;
  a4 = MEM8(a4 + 1); /* 0051: l8ui a4, a4, 1 */
  if (a4 != 0) goto L_70; /* 0054: bnez.n a4, 70 <pm_offchan_ready_or_defer+0x54> */
  a12 = 0x1; /* 0056: movi a12, 1 */
  a11 = 0x1000; /* 0059: slli a11, a12, 12 */
  a13 = (uint32_t)&lit_rodata_wlog_error_32; /* 005c: l32r a13, c <pm_offchan_ready_or_defer-0x10> (0 <pm_offchan_ready_or_defer-0x1c>) */ /* literal @0xC: .rodata_wlog_error.32 */
  a10 = 0x6; /* 005f: movi a10, 6 */
  a8 = (uint32_t)&wifi_log; /* 0062: l32r a8, 14 <pm_offchan_ready_or_defer-0x8> (0 <pm_offchan_ready_or_defer-0x1c>) */ /* literal: GOT slot for wifi_log */
  wifi_log(a2, a3, a4, a5); /* call via literal slot */ /* 0065: callx8 a8 */
  a8 = (uint32_t)&pm_on_channel; /* 0068: l32r a8, 18 <pm_offchan_ready_or_defer-0x4> (0 <pm_offchan_ready_or_defer-0x1c>) */ /* literal: GOT slot for pm_on_channel */
  pm_on_channel(a2, a3, a4, a5); /* call via literal slot */ /* 006b: callx8 a8 */
  a8 = 0x2; /* 006e: movi.n a8, 2 */
L_70:;
  a2 = 0x2; /* 0070: mov.n a2, a8 */
  return (int32_t)a2; /* 0072: retw.n  */
}

/* pm_update_params @ pm.o 00000014 size 136B bind GLOBAL
 * Calls: pm_coex_schm_overall_period_get, pm_go_to_wake | Data refs: g_osi_funcs_p, g_pm, g_pm_cfg, pm_coex_schm_overall_period_get, pm_go_to_wake
 *   MMIO: none
 *   funcdb v3: 2 call(s), 5 ref(s); disasm: 2 call(s), 5 data ref(s)
 * Fidelity: medium - 52 instr, 8 branches, 3 indirect; flow + direct calls mapped, GOT-indirects enumerated */
int32_t pm_update_params(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pm_update_params; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_14:;
  /* 0014: entry a1, 32 */
  a4 = (uint32_t)&g_osi_funcs_p; /* 0017: l32r a4, 0 <pm_update_params-0x14> (0 <pm_update_params-0x14>) */ /* literal @0x0: g_osi_funcs_p */
  a2 = MEM32(a4 + 0); /* 001a: l32i.n a2, a4, 0 */
  a10 = MEM32(a2 + 404); /* 001c: l32i a10, a2, 0x194 */
  ((int32_t(*)())a10)(a2, a3, a4, a5); /* 001f: callx8 a10 */ /* indirect */
  a2 = (uint32_t)&g_pm; /* 0022: l32r a2, 4 <pm_update_params-0x10> (0 <pm_update_params-0x14>) */ /* literal @0x4: g_pm */
  a3 = (uint32_t)&g_pm_cfg; /* 0025: l32r a3, 8 <pm_update_params-0xc> (0 <pm_update_params-0x14>) */ /* literal @0x8: g_pm_cfg */
  if (a10 != 0) goto L_38; /* 0028: bnez.n a10, 38 <pm_update_params+0x24> */
  a8 = MEM32(a3 + 20); /* 002a: l32i.n a8, a3, 20 */
  a3 = MEM32(a3 + 4); /* 002c: l32i.n a3, a3, 4 */
  MEM32(a2 + 48) = a8; /* 002e: s32i.n a8, a2, 48 */
  MEMW(); /* 0030: memw  */
  goto L_54; /* 0033: j 54 <pm_update_params+0x40> */
  /* 0036: .byte 00 */
  /* 0037: .byte 00 */
L_38:;
  a8 = a2 + ((0x100) << 8); /* 0038: addmi a8, a2, 0x100 */
  a8 = MEM8(a8 + 213); /* 003b: l8ui a8, a8, 213 */
  if (a8 == 0) goto L_45; /* 003e: beqz.n a8, 45 <pm_update_params+0x31> */
  a10 = MEM32(a3 + 20); /* 0040: l32i.n a10, a3, 20 */
  goto L_50; /* 0042: j 50 <pm_update_params+0x3c> */
L_45:;
  a8 = (uint32_t)&pm_coex_schm_overall_period_get; /* 0045: l32r a8, c <pm_update_params-0x8> (0 <pm_update_params-0x14>) */ /* literal: GOT slot for pm_coex_schm_overall_period_get */
  pm_coex_schm_overall_period_get(a2, a3, a4, a5); /* call via literal slot */ /* 0048: callx8 a8 */
  a8 = MEM32(a2 + 44); /* 004b: l32i.n a8, a2, 44 */
  a10 = (uint32_t)((uint64_t)a10 * a8); /* 004d: mull a10, a10, a8 */
L_50:;
  a3 = MEM32(a3 + 8); /* 0050: l32i.n a3, a3, 8 */
  MEM32(a2 + 48) = a10; /* 0052: s32i.n a10, a2, 48 */
L_54:;
  a8 = MEM32(a2 + 40); /* 0054: l32i a8, a2, 40 */
  if (a8 == a3) goto L_5d; /* 0057: beq a8, a3, 5d <pm_update_params+0x49> */
  MEM32(a2 + 40) = a3; /* 005a: s32i a3, a2, 40 */
L_5d:;
  a3 = MEM32(a4 + 0); /* 005d: l32i.n a3, a4, 0 */
  a10 = MEM32(a3 + 404); /* 005f: l32i a10, a3, 0x194 */
  MEMW(); /* 0062: memw  */
  ((int32_t(*)())a10)(a2, a3, a4, a5); /* 0065: callx8 a10 */ /* indirect */
  a3 = MEM8(a2 + 12); /* 0068: l8ui a3, a2, 12 */
  if (a10 == a3) goto L_97; /* 006b: beq a10, a3, 97 <pm_update_params+0x83> */
  if (a3 != 1) goto L_89; /* 006e: bnei a3, 1, 89 <pm_update_params+0x75> */
  a10 = MEM32(a2 + 36); /* 0071: l32i.n a10, a2, 36 */
  if (a10 != 0) goto L_89; /* 0073: bnez.n a10, 89 <pm_update_params+0x75> */
  a8 = a2 + ((0x100) << 8); /* 0075: addmi a8, a2, 0x100 */
  a11 = a10; /* 0078: mov.n a11, a10 */
  MEM8(a8 + 200) = a3; /* 007a: s8i a3, a8, 200 */
  MEMW(); /* 007d: memw  */
  MEMW(); /* 0080: memw  */
  a8 = (uint32_t)&pm_go_to_wake; /* 0083: l32r a8, 10 <pm_update_params-0x4> (0 <pm_update_params-0x14>) */ /* literal: GOT slot for pm_go_to_wake */
  pm_go_to_wake(a2, a3, a4, a5); /* call via literal slot */ /* 0086: callx8 a8 */
L_89:;
  a3 = MEM32(a4 + 0); /* 0089: l32i.n a3, a4, 0 */
  a10 = MEM32(a3 + 404); /* 008b: l32i a10, a3, 0x194 */
  ((int32_t(*)())a10)(a2, a3, a4, a5); /* 008e: callx8 a10 */ /* indirect */
  MEM8(a2 + 12) = a10; /* 0091: s8i a10, a2, 12 */
  MEMW(); /* 0094: memw  */
L_97:;
  MEMW(); /* 0097: memw  */
  return (int32_t)a2; /* 009a: retw.n  */
}

/* pm_process_tim @ pm.o 0000002c size 343B bind GLOBAL
 * Calls: pm_is_in_wifi_slice_threshold[got], pm_go_to_wake[got], pm_is_in_wifi_slice_threshold[got], pm_enable_dream_timer[got], pm_disable_sleep_delay_timer[got], pm_sleep[got], .text.pm_disable_active_timer[got], pm_active_timeout_process[got] | Data refs: g_pm, g_osi_funcs_p, pm_is_in_wifi_slice_threshold, pm_go_to_wake, g_pm_cnt, pm_enable_dream_timer, pm_disable_sleep_delay_timer, pm_sleep, .text.pm_disable_active_timer, pm_active_timeout_process
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 8 call(s), 10 data ref(s)
 * Fidelity: low - 126 instr, 23 branches, 4 indirect; call-sequence + MMIO skeleton */
int32_t pm_process_tim(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .wifislprxiram.40; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_2c:;
  /* 002c: entry a1, 32 */
  a4 = (uint32_t)&g_pm; /* 002f: l32r a4, 0 <pm_process_tim-0x2c> (0 <pm_process_tim-0x2c>) */ /* literal @0x0: g_pm */
  a2 = (a2 >> 0) & 0xFF; /* 0032: extui a2, a2, 0, 8 */
  a3 = (a3 >> 0) & 0xFF; /* 0035: extui a3, a3, 0, 8 */
  a7 = MEM8(a4 + 1); /* 0038: l8ui a7, a4, 1 */
  if (a7 == 1) goto L_41; /* 003b: beqi a7, 1, 41 <pm_process_tim+0x15> */
  goto L_151; /* 003e: j 151 <pm_process_tim+0x125> */
L_41:;
  if (a2 == 0) goto L_b1; /* 0041: beqz a2, b1 <pm_process_tim+0x85> */
  a5 = (uint32_t)&g_osi_funcs_p; /* 0044: l32r a5, 4 <pm_process_tim-0x28> (0 <pm_process_tim-0x2c>) */ /* literal @0x4: g_osi_funcs_p */
  a2 = MEM32(a5 + 0); /* 0047: l32i a2, a5, 0 */
  a10 = MEM32(a2 + 272); /* 004a: l32i a10, a2, 0x110 */
  ((int32_t(*)())a10)(a2, a3, a4, a5); /* 004d: callx8 a10 */ /* indirect */
  a12 = 0x271; /* 0050: movi a12, 0x271 */
  a12 = 0x1388; /* 0053: slli a12, a12, 3 */
  a2 = a10; /* 0056: mov.n a2, a10 */
  a3 = a11 | a11; /* 0058: or a3, a11, a11 */
  a8 = (uint32_t)&pm_is_in_wifi_slice_threshold; /* 005b: l32r a8, c <pm_process_tim-0x20> (0 <pm_process_tim-0x2c>) */ /* literal: GOT slot for pm_is_in_wifi_slice_threshold */
  pm_is_in_wifi_slice_threshold(a2, a3, a4, a5); /* call via literal slot */ /* 005e: callx8 a8 */
  if (a10 == 0) goto L_a4; /* 0061: beqz.n a10, a4 <pm_process_tim+0x78> */
  a12 = MEM32(a4 + 96); /* 0063: l32i a12, a4, 96 */
  MEM8(a4 + 18) = a7; /* 0066: s8i a7, a4, 18 */
  MEMW(); /* 0069: memw  */
  a4 = MEM32(a4 + 100); /* 006c: l32i a4, a4, 100 */
  if (a3 < a4) goto L_78; /* 006f: bltu a3, a4, 78 <pm_process_tim+0x4c> */
  if (a4 != a3) goto L_8a; /* 0072: bne a4, a3, 8a <pm_process_tim+0x5e> */
  if (a2 >= a12) goto L_8a; /* 0075: bgeu a2, a12, 8a <pm_process_tim+0x5e> */
L_78:;
  a3 = MEM32(a5 + 0); /* 0078: l32i.n a3, a5, 0 */
  a12 = a12 - a2; /* 007a: sub a12, a12, a2 */
  a11 = 0x0; /* 007d: movi.n a11, 0 */
  a10 = 0x1; /* 007f: movi.n a10, 1 */
  a3 = MEM32(a3 + 412); /* 0081: l32i a3, a3, 0x19c */
  MEMW(); /* 0084: memw  */
  ((int32_t(*)())a3)(a2, a3, a4, a5); /* 0087: callx8 a3 */ /* indirect */
L_8a:;
  a11 = 0x0; /* 008a: movi.n a11, 0 */
  a10 = 0x1; /* 008c: movi.n a10, 1 */
  a8 = (uint32_t)&pm_go_to_wake; /* 008e: l32r a8, 10 <pm_process_tim-0x1c> (0 <pm_process_tim-0x2c>) */ /* literal: GOT slot for pm_go_to_wake */
  pm_go_to_wake(a2, a3, a4, a5); /* call via literal slot */ /* 0091: callx8 a8 */
  a3 = (uint32_t)&g_pm_cnt; /* 0094: l32r a3, 8 <pm_process_tim-0x24> (0 <pm_process_tim-0x2c>) */ /* literal @0x8: g_pm_cnt */
  a2 = MEM32(a3 + 8); /* 0097: l32i.n a2, a3, 8 */
  a2 = a2 + (1); /* 0099: addi.n a2, a2, 1 */
  MEM32(a3 + 8) = a2; /* 009b: s32i.n a2, a3, 8 */
  MEMW(); /* 009d: memw  */
  goto L_181; /* 00a0: j 181 <pm_process_tim+0x155> */
  /* 00a3: .byte 00 */
L_a4:;
  MEM8(a4 + 25) = a7; /* 00a4: s8i a7, a4, 25 */
  MEMW(); /* 00a7: memw  */
  MEMW(); /* 00aa: memw  */
  goto L_181; /* 00ad: j 181 <pm_process_tim+0x155> */
  /* 00b0: .byte 00 */
L_b1:;
  if (a3 == 0) goto L_12d; /* 00b1: beqz a3, 12d <pm_process_tim+0x101> */
  a3 = (uint32_t)&g_osi_funcs_p; /* 00b4: l32r a3, 4 <pm_process_tim-0x28> (0 <pm_process_tim-0x2c>) */ /* literal @0x4: g_osi_funcs_p */
  a2 = MEM32(a3 + 0); /* 00b7: l32i a2, a3, 0 */
  a10 = MEM32(a2 + 272); /* 00ba: l32i a10, a2, 0x110 */
  ((int32_t(*)())a10)(a2, a3, a4, a5); /* 00bd: callx8 a10 */ /* indirect */
  a12 = 0x3E8; /* 00c0: movi a12, 0x3e8 */
  a2 = a10; /* 00c3: mov.n a2, a10 */
  a3 = 0x0; /* 00c5: mov.n a3, a11 */
  a6 = a10; /* 00c7: mov.n a6, a10 */
  a5 = 0x0; /* 00c9: mov.n a5, a11 */
  a8 = (uint32_t)&pm_is_in_wifi_slice_threshold; /* 00cb: l32r a8, 14 <pm_process_tim-0x18> (0 <pm_process_tim-0x2c>) */ /* literal: GOT slot for pm_is_in_wifi_slice_threshold */
  pm_is_in_wifi_slice_threshold(a2, a3, a4, a5); /* call via literal slot */ /* 00ce: callx8 a8 */
  if (a10 == 0) goto L_181; /* 00d1: beqz a10, 181 <pm_process_tim+0x155> */
  MEM8(a4 + 18) = a7; /* 00d4: s8i a7, a4, 18 */
  MEMW(); /* 00d7: memw  */
  MEMW(); /* 00da: memw  */
  a8 = (uint32_t)&pm_enable_dream_timer; /* 00dd: l32r a8, 18 <pm_process_tim-0x14> (0 <pm_process_tim-0x2c>) */ /* literal: GOT slot for pm_enable_dream_timer */
  pm_enable_dream_timer(a2, a3, a4, a5); /* call via literal slot */ /* 00e0: callx8 a8 */
  a8 = MEM32(a4 + 100); /* 00e3: l32i a8, a4, 100 */
  a7 = MEM32(a4 + 96); /* 00e6: l32i a7, a4, 96 */
  if (a3 < a8) goto L_f2; /* 00e9: bltu a3, a8, f2 <pm_process_tim+0xc6> */
  if (a8 != a3) goto L_11c; /* 00ec: bne a8, a3, 11c <pm_process_tim+0xf0> */
  if (a2 >= a7) goto L_11c; /* 00ef: bgeu a2, a7, 11c <pm_process_tim+0xf0> */
L_f2:;
  a2 = a7 - a2; /* 00f2: sub a2, a7, a2 */
  a12 = MEM32(a4 + 52); /* 00f5: l32i.n a12, a4, 52 */
  a5 = 0x1; /* 00f7: movi.n a5, 1 */
  a4 = 0x0; /* 00f9: movi.n a4, 0 */
  if (a7 < a2) goto L_101; /* 00fb: bltu a7, a2, 101 <pm_process_tim+0xd5> */
  a5 = 0x0; /* 00fe: or a5, a4, a4 */
L_101:;
  a8 = a8 - a3; /* 0101: sub a8, a8, a3 */
  a8 = a8 - a5; /* 0104: sub a8, a8, a5 */
  if (a4 != a8) goto L_10d; /* 0107: bne a4, a8, 10d <pm_process_tim+0xe1> */
  /* 010a: minu a12, a12, a2 */ /* UNMODELED: a12 clobbered */
L_10d:;
  a3 = (uint32_t)&g_osi_funcs_p; /* 010d: l32r a3, 4 <pm_process_tim-0x28> (0 <pm_process_tim-0x2c>) */ /* literal @0x4: g_osi_funcs_p */
  a11 = 0x0; /* 0110: movi.n a11, 0 */
  a10 = 0x2; /* 0112: movi.n a10, 2 */
  a2 = MEM32(a3 + 0); /* 0114: l32i.n a2, a3, 0 */
  a2 = MEM32(a2 + 412); /* 0116: l32i a2, a2, 0x19c */
  ((int32_t(*)())a2)(a2, a3, a4, a5); /* 0119: callx8 a2 */ /* indirect */
L_11c:;
  a3 = (uint32_t)&g_pm_cnt; /* 011c: l32r a3, 8 <pm_process_tim-0x24> (0 <pm_process_tim-0x2c>) */ /* literal @0x8: g_pm_cnt */
  a2 = MEM32(a3 + 12); /* 011f: l32i.n a2, a3, 12 */
  a2 = a2 + (1); /* 0121: addi.n a2, a2, 1 */
  MEM32(a3 + 12) = a2; /* 0123: s32i.n a2, a3, 12 */
  MEMW(); /* 0125: memw  */
  goto L_181; /* 0128: j 181 <pm_process_tim+0x155> */
  /* 012b: .byte 00 */
  /* 012c: .byte 00 */
L_12d:;
  a2 = MEM8(a4 + 19); /* 012d: l8ui a2, a4, 19 */
  MEM8(a4 + 18) = a3; /* 0130: s8i a3, a4, 18 */
  MEMW(); /* 0133: memw  */
  if (a2 != 0) goto L_181; /* 0136: bnez a2, 181 <pm_process_tim+0x155> */
  a2 = MEM8(a4 + 20); /* 0139: l8ui a2, a4, 20 */
  if (a2 != 0) goto L_181; /* 013c: bnez a2, 181 <pm_process_tim+0x155> */
  MEMW(); /* 013f: memw  */
  a8 = (uint32_t)&pm_disable_sleep_delay_timer; /* 0142: l32r a8, 1c <pm_process_tim-0x10> (0 <pm_process_tim-0x2c>) */ /* literal: GOT slot for pm_disable_sleep_delay_timer */
  pm_disable_sleep_delay_timer(a2, a3, a4, a5); /* call via literal slot */ /* 0145: callx8 a8 */
  a8 = (uint32_t)&pm_sleep; /* 0148: l32r a8, 20 <pm_process_tim-0xc> (0 <pm_process_tim-0x2c>) */ /* literal: GOT slot for pm_sleep */
  pm_sleep(a2, a3, a4, a5); /* call via literal slot */ /* 014b: callx8 a8 */
  goto L_181; /* 014e: j 181 <pm_process_tim+0x155> */
L_151:;
  a5 = 0x1; /* 0151: movi.n a5, 1 */
  a6 = 0x0; /* 0153: movi.n a6, 0 */
  if (a7 == 0) a5 = a6; /* 0155: moveqz a5, a6, a7 */
  a3 = a3 | a5; /* 0158: or a3, a3, a5 */
  if (a3 != a6) goto L_181; /* 015b: bne a3, a6, 181 <pm_process_tim+0x155> */
  if (a2 != a6) goto L_181; /* 015e: bne a2, a6, 181 <pm_process_tim+0x155> */
  MEM8(a4 + 18) = a2; /* 0161: s8i a2, a4, 18 */
  MEMW(); /* 0164: memw  */
  a4 = a4 + ((0x100) << 8); /* 0167: addmi a4, a4, 0x100 */
  a3 = MEM8(a4 + 212); /* 016a: l8ui a3, a4, 212 */
  if (a3 == a6) goto L_181; /* 016d: beq a3, a6, 181 <pm_process_tim+0x155> */
  MEMW(); /* 0170: memw  */
  a8 = (uint32_t)&pm_disable_active_timer; /* 0173: l32r a8, 24 <pm_process_tim-0x8> (8 <pm_process_tim-0x24>) */ /* literal: GOT slot for .text.pm_disable_active_timer */
  pm_disable_active_timer(a2, a3, a4, a5); /* call via literal slot */ /* 0176: callx8 a8 */
  a10 = a2; /* 0179: mov.n a10, a2 */
  a8 = (uint32_t)&pm_active_timeout_process; /* 017b: l32r a8, 28 <pm_process_tim-0x4> (0 <pm_process_tim-0x2c>) */ /* literal: GOT slot for pm_active_timeout_process */
  pm_active_timeout_process(a2, a3, a4, a5); /* call via literal slot */ /* 017e: callx8 a8 */
L_181:;
  return (int32_t)a2; /* 0181: retw.n  */
}

/* pm_rx_beacon_process @ pm.o 00000018 size 162B bind GLOBAL
 * Calls: wifi_gpio_debug[got], sta_reset_beacon_timeout[got], pm_process_tim[got], g_pm_cfg[got] | Data refs: g_pm, g_osi_funcs_p, wifi_gpio_debug, sta_reset_beacon_timeout, g_pm_cfg, pm_process_tim
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 4 call(s), 6 data ref(s)
 * Fidelity: medium - 62 instr, 9 branches, calls resolved */
int32_t pm_rx_beacon_process(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .wifislprxiram.47; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_18:;
  /* 0018: entry a1, 32 */
  a6 = (uint32_t)&g_pm; /* 001b: l32r a6, 0 <pm_rx_beacon_process-0x18> (0 <pm_rx_beacon_process-0x18>) */ /* literal @0x0: g_pm */
  a4 = 0x0; /* 001e: movi.n a4, 0 */
  a5 = a6 + ((0x200) << 8); /* 0020: addmi a5, a6, 0x200 */
  a3 = (a3 >> 0) & 0xFF; /* 0023: extui a3, a3, 0, 8 */
  MEM8(a5 + 29) = a4; /* 0026: s8i a4, a5, 29 */
  MEM8(a6 + 17) = a4; /* 0029: s8i a4, a6, 17 */
  MEMW(); /* 002c: memw  */
  a4 = MEM8(a6 + 14); /* 002f: l8ui a4, a6, 14 */
  a5 = (uint32_t)&g_osi_funcs_p; /* 0032: l32r a5, 4 <pm_rx_beacon_process-0x14> (0 <pm_rx_beacon_process-0x18>) */ /* literal @0x4: g_osi_funcs_p */
  if (a4 != 0) goto L_3e; /* 0035: bnez.n a4, 3e <pm_rx_beacon_process+0x26> */
  MEMW(); /* 0037: memw  */
  goto L_ae; /* 003a: j ae <pm_rx_beacon_process+0x96> */
  /* 003d: .byte 00 */
L_3e:;
  a11 = 0x2; /* 003e: movi.n a11, 2 */
  a10 = 0x1; /* 0040: movi.n a10, 1 */
  a8 = (uint32_t)&wifi_gpio_debug; /* 0042: l32r a8, c <pm_rx_beacon_process-0xc> (0 <pm_rx_beacon_process-0x18>) */ /* literal: GOT slot for wifi_gpio_debug */
  wifi_gpio_debug(a2, a3, a4, a5); /* call via literal slot */ /* 0045: callx8 a8 */
  if (a3 == 0) goto L_59; /* 0048: beqz.n a3, 59 <pm_rx_beacon_process+0x41> */
  a4 = 0x0; /* 004a: movi.n a4, 0 */
  a8 = (uint32_t)&sta_reset_beacon_timeout; /* 004c: l32r a8, 10 <pm_rx_beacon_process-0x8> (0 <pm_rx_beacon_process-0x18>) */ /* literal: GOT slot for sta_reset_beacon_timeout */
  sta_reset_beacon_timeout(a2, a3, a4, a5); /* call via literal slot */ /* 004f: callx8 a8 */
  a3 = a4; /* 0052: mov.n a3, a4 */
  goto L_a4; /* 0054: j a4 <pm_rx_beacon_process+0x8c> */
  /* 0057: .byte 00 */
  /* 0058: .byte 00 */
L_59:;
  if (a2 == 0) goto L_a4; /* 0059: beqz a2, a4 <pm_rx_beacon_process+0x8c> */
  a11 = MEM16(a6 + 26); /* 005c: l16ui a11, a6, 26 */
  a4 = 0x1; /* 005f: movi.n a4, 1 */
  a8 = (a11 >> 0) & 0x3FFF; /* 0061: extui a8, a11, 0, 14 */
  a10 = MEM8(a2 + 4); /* 0064: l8ui a10, a2, 4 */
  if (a8 == 0) goto L_99; /* 0067: beqz.n a8, 99 <pm_rx_beacon_process+0x81> */
  a4 = 0xFFFFFFFE; /* 0069: movi.n a4, -2 */
  a6 = a10 & a4; /* 006b: and a6, a10, a4 */
  a8 = a8 >> (3 & 31); /* 006e: srli a8, a8, 3 */
  a4 = a3; /* 0071: mov.n a4, a3 */
  if (a8 < a6) goto L_99; /* 0073: bltu a8, a6, 99 <pm_rx_beacon_process+0x81> */
  a9 = MEM8(a2 + 1); /* 0076: l8ui a9, a2, 1 */
  a9 = a9 + (-4); /* 0079: addi a9, a9, -4 */
  a9 = a6 + a9; /* 007c: add.n a9, a6, a9 */
  a9 = (a9 >> 0) & 0xFF; /* 007e: extui a9, a9, 0, 8 */
  if (a9 < a8) goto L_99; /* 0081: bltu a9, a8, 99 <pm_rx_beacon_process+0x81> */
  a8 = a8 - a6; /* 0084: sub a8, a8, a6 */
  a2 = a2 + a8; /* 0087: add a2, a2, a8 */
  a4 = MEM8(a2 + 5); /* 008a: l8ui a4, a2, 5 */
  a11 = (a11 >> 0) & 0x7; /* 008d: extui a11, a11, 0, 3 */
  /* 0090: ssr a11 */ /* UNMODELED: a11 clobbered */
  /* 0093: sra a4, a4 */ /* UNMODELED: a4 clobbered */
  a4 = (a4 >> 0) & 0x1; /* 0096: extui a4, a4, 0, 1 */
L_99:;
  a2 = (uint32_t)&g_pm_cfg; /* 0099: l32r a2, 8 <pm_rx_beacon_process-0x10> (0 <pm_rx_beacon_process-0x18>) */ /* literal @0x8: g_pm_cfg */
  a2 = MEM8(a2 + 28); /* 009c: l8ui a2, a2, 28 */
  if (a2 != 0) goto L_a4; /* 009f: bnez.n a2, a4 <pm_rx_beacon_process+0x8c> */
  a3 = (a10 >> 0) & 0x1; /* 00a1: extui a3, a10, 0, 1 */
L_a4:;
  a11 = a3; /* 00a4: mov.n a11, a3 */
  a10 = a4; /* 00a6: mov.n a10, a4 */
  a8 = (uint32_t)&pm_process_tim; /* 00a8: l32r a8, 14 <pm_rx_beacon_process-0x4> (0 <pm_rx_beacon_process-0x18>) */ /* literal: GOT slot for pm_process_tim */
  pm_process_tim(a2, a3, a4, a5); /* call via literal slot */ /* 00ab: callx8 a8 */
L_ae:;
  a2 = MEM32(a5 + 0); /* 00ae: l32i.n a2, a5, 0 */
  a10 = 0x0; /* 00b0: movi.n a10, 0 */
  a2 = MEM32(a2 + 416); /* 00b2: l32i a2, a2, 0x1a0 */
  g_pm_cfg(a2, a3, a4, a5); /* call via literal slot */ /* 00b5: callx8 a2 */
  return (int32_t)a2; /* 00b8: retw.n  */
}

/* pm_coex_tbtt_process @ pm.o 00000030 size 296B bind GLOBAL
 * Calls: pm_coex_schm_overall_period_get, pm_coex_schm_process_restart, pm_go_to_wake, pm_is_sleeping, ppCheckTxConnTrafficIdle, g_pm[got], .text.hal_pm_unblock_txq[got], .text.hal_pm_unblock_txq[got] | Data refs: g_osi_funcs_p, g_pm, pm_coex_schm_overall_period_get, pm_coex_schm_process_restart, pm_go_to_wake, pm_is_sleeping, ppCheckTxConnTrafficIdle, .text.hal_pm_unblock_txq
 *   MMIO: none
 *   funcdb v3: 5 call(s), 7 ref(s); disasm: 9 call(s), 8 data ref(s)
 * Fidelity: low - 114 instr, 22 branches, 3 indirect; call-sequence + MMIO skeleton */
int32_t pm_coex_tbtt_process(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pm_coex_tbtt_process; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_30:;
  /* 0030: entry a1, 32 */
  a5 = (uint32_t)&g_osi_funcs_p; /* 0033: l32r a5, 4 <pm_coex_tbtt_process-0x2c> (0 <pm_coex_tbtt_process-0x30>) */ /* literal @0x4: g_osi_funcs_p */
  a4 = MEM32(a5 + 0); /* 0036: l32i a4, a5, 0 */
  a10 = (uint32_t)&g_pm; /* 0039: l32r a10, 0 <pm_coex_tbtt_process-0x30> (0 <pm_coex_tbtt_process-0x30>) */ /* literal @0x0: g_pm */
  a4 = MEM32(a4 + 236); /* 003c: l32i a4, a4, 236 */
  ((int32_t(*)())a4)(a2, a3, a4, a5); /* 003f: callx8 a4 */ /* indirect */
  a8 = 0x1; /* 0042: movi.n a8, 1 */
  a4 = (uint32_t)&g_pm; /* 0044: l32r a4, 8 <pm_coex_tbtt_process-0x28> (0 <pm_coex_tbtt_process-0x30>) */ /* literal @0x8: g_pm */
  MEM8(a4 + 24) = a8; /* 0047: s8i a8, a4, 24 */
  MEMW(); /* 004a: memw  */
  a8 = MEM32(a5 + 0); /* 004d: l32i.n a8, a5, 0 */
  a10 = MEM32(a8 + 404); /* 004f: l32i a10, a8, 0x194 */
  MEMW(); /* 0052: memw  */
  g_pm(a2, a3, a4, a5); /* call via literal slot */ /* 0055: callx8 a10 */
  if (a10 == 0) goto L_cc; /* 0058: beqz a10, cc <pm_coex_tbtt_process+0x9c> */
  a8 = MEM8(a4 + 14); /* 005b: l8ui a8, a4, 14 */
  if (a8 == 0) goto L_89; /* 005e: beqz.n a8, 89 <pm_coex_tbtt_process+0x59> */
  a8 = (uint32_t)&pm_coex_schm_overall_period_get; /* 0060: l32r a8, 10 <pm_coex_tbtt_process-0x20> (0 <pm_coex_tbtt_process-0x30>) */ /* literal: GOT slot for pm_coex_schm_overall_period_get */
  pm_coex_schm_overall_period_get(a2, a3, a4, a5); /* call via literal slot */ /* 0063: callx8 a8 */
  a9 = 0x1; /* 0066: movi.n a9, 1 */
  a8 = MEM32(a4 + 44); /* 0068: l32i.n a8, a4, 44 */
  a10 = (uint32_t)((uint64_t)a10 * a8); /* 006a: mull a10, a10, a8 */
  a2 = a10 + a2; /* 006d: add.n a2, a10, a2 */
  if (a2 < a10) goto L_74; /* 006f: bltu a2, a10, 74 <pm_coex_tbtt_process+0x44> */
  a9 = 0x0; /* 0072: movi.n a9, 0 */
L_74:;
  a9 = a9 + a3; /* 0074: add.n a9, a9, a3 */
  MEM32(a4 + 104) = a2; /* 0076: s32i a2, a4, 104 */
  a2 = MEM8(a4 + 14); /* 0079: l8ui a2, a4, 14 */
  MEM32(a4 + 108) = a9; /* 007c: s32i a9, a4, 108 */
  if (a2 != 0) goto L_a4; /* 007f: bnez.n a2, a4 <pm_coex_tbtt_process+0x74> */
  MEMW(); /* 0081: memw  */
  goto L_10a; /* 0084: j 10a <pm_coex_tbtt_process+0xda> */
  /* 0087: .byte 00 */
  /* 0088: .byte 00 */
L_89:;
  a9 = MEM32(a4 + 44); /* 0089: l32i.n a9, a4, 44 */
  a5 = 0x1; /* 008b: movi.n a5, 1 */
  a2 = a9 + a2; /* 008d: add.n a2, a9, a2 */
  if (a2 < a9) goto L_94; /* 008f: bltu a2, a9, 94 <pm_coex_tbtt_process+0x64> */
  a5 = a8; /* 0092: mov.n a5, a8 */
L_94:;
  a5 = a5 + a3; /* 0094: add.n a5, a5, a3 */
  MEM32(a4 + 104) = a2; /* 0096: s32i a2, a4, 104 */
  MEM32(a4 + 108) = a5; /* 0099: s32i a5, a4, 108 */
  MEMW(); /* 009c: memw  */
  goto L_10a; /* 009f: j 10a <pm_coex_tbtt_process+0xda> */
  /* 00a2: .byte 00 */
  /* 00a3: .byte 00 */
L_a4:;
  a2 = 0x51EB851F; /* 00a4: l32r a2, c <pm_coex_tbtt_process-0x24> (51eb851f <pm_attach+0x51eb849b>) */ @0xC
  a10 = (uint32_t)(((uint64_t)a8 * a2) >> 32) /* muluh: high word */; /* 00a7: muluh a10, a8, a2 */
  a10 = a10 >> (5 & 31); /* 00aa: srli a10, a10, 5 */
  a2 = MEM32(a5 + 0); /* 00ad: l32i.n a2, a5, 0 */
  a2 = MEM32(a2 + 440); /* 00af: l32i a2, a2, 0x1b8 */
  ((int32_t(*)())a2)(a2, a3, a4, a5); /* 00b2: callx8 a2 */ /* indirect */
  a8 = (uint32_t)&pm_coex_schm_process_restart; /* 00b5: l32r a8, 14 <pm_coex_tbtt_process-0x1c> (0 <pm_coex_tbtt_process-0x30>) */ /* literal: GOT slot for pm_coex_schm_process_restart */
  pm_coex_schm_process_restart(a2, a3, a4, a5); /* call via literal slot */ /* 00b8: callx8 a8 */
  a11 = 0x0; /* 00bb: movi.n a11, 0 */
  a2 = MEM32(a5 + 0); /* 00bd: l32i.n a2, a5, 0 */
  a10 = 0x0; /* 00bf: mov.n a10, a11 */
  a2 = MEM32(a2 + 412); /* 00c1: l32i a2, a2, 0x19c */
  a12 = MEM32(a4 + 52); /* 00c4: l32i.n a12, a4, 52 */
  ((int32_t(*)())a2)(a2, a3, a4, a5); /* 00c6: callx8 a2 */ /* indirect */
  goto L_10a; /* 00c9: j 10a <pm_coex_tbtt_process+0xda> */
L_cc:;
  a8 = (uint32_t)&pm_is_sleeping; /* 00cc: l32r a8, 18 <pm_coex_tbtt_process-0x18> (0 <pm_coex_tbtt_process-0x30>) */ /* literal: GOT slot for pm_is_sleeping */
  pm_is_sleeping(a2, a3, a4, a5); /* call via literal slot */ /* 00cf: callx8 a8 */
  if (a10 != 0) goto L_156; /* 00d2: bnez a10, 156 <pm_coex_tbtt_process+0x126> */
  a2 = MEM8(a4 + 13); /* 00d5: l8ui a2, a4, 13 */
  if (a2 == 0) goto L_e9; /* 00d8: beqz.n a2, e9 <pm_coex_tbtt_process+0xb9> */
  a2 = MEM8(a4 + 14); /* 00da: l8ui a2, a4, 14 */
  if (a2 == 0) goto L_156; /* 00dd: beqz a2, 156 <pm_coex_tbtt_process+0x126> */
  a2 = a4 + ((0x200) << 8); /* 00e0: addmi a2, a4, 0x200 */
  a2 = MEM8(a2 + 30); /* 00e3: l8ui a2, a2, 30 */
  if (a2 != 0) goto L_156; /* 00e6: bnez a2, 156 <pm_coex_tbtt_process+0x126> */
L_e9:;
  a8 = (uint32_t)&hal_pm_unblock_txq; /* 00e9: l32r a8, 1c <pm_coex_tbtt_process-0x14> (8 <pm_coex_tbtt_process-0x28>) */ /* literal: GOT slot for .text.hal_pm_unblock_txq */
  hal_pm_unblock_txq(a2, a3, a4, a5); /* call via literal slot */ /* 00ec: callx8 a8 */
  a10 = 0x1; /* 00ef: movi a10, 1 */
  a8 = (uint32_t)&ppCheckTxConnTrafficIdle; /* 00f2: l32r a8, 20 <pm_coex_tbtt_process-0x10> (0 <pm_coex_tbtt_process-0x30>) */ /* literal: GOT slot for ppCheckTxConnTrafficIdle */
  ppCheckTxConnTrafficIdle(a2, a3, a4, a5); /* call via literal slot */ /* 00f5: callx8 a8 */
  if (a10 == 0) goto L_156; /* 00f8: beqz a10, 156 <pm_coex_tbtt_process+0x126> */
  a2 = MEM8(a4 + 14); /* 00fb: l8ui a2, a4, 14 */
  a11 = 0x1; /* 00fe: movi.n a11, 1 */
  a10 = 0x0; /* 0100: movi.n a10, 0 */
  if (a2 != 0) goto L_14d; /* 0102: bnez a2, 14d <pm_coex_tbtt_process+0x11d> */
  goto L_156; /* 0105: j 156 <pm_coex_tbtt_process+0x126> */
  /* 0108: .byte 00 */
  /* 0109: .byte 00 */
L_10a:;
  a2 = 0x0; /* 010a: movi.n a2, 0 */
  MEM32(a4 + 64) = a2; /* 010c: s32i a2, a4, 64 */
  MEMW(); /* 010f: memw  */
  a8 = (uint32_t)&pm_is_sleeping; /* 0112: l32r a8, 24 <pm_coex_tbtt_process-0xc> (0 <pm_coex_tbtt_process-0x30>) */ /* literal: GOT slot for pm_is_sleeping */
  pm_is_sleeping(a2, a3, a4, a5); /* call via literal slot */ /* 0115: callx8 a8 */
  if (a10 != a2) goto L_133; /* 0118: bne a10, a2, 133 <pm_coex_tbtt_process+0x103> */
  a2 = MEM8(a4 + 13); /* 011b: l8ui a2, a4, 13 */
  if (a2 == 0) goto L_12d; /* 011e: beqz.n a2, 12d <pm_coex_tbtt_process+0xfd> */
  a2 = MEM8(a4 + 14); /* 0120: l8ui a2, a4, 14 */
  if (a2 == 0) goto L_133; /* 0123: beqz.n a2, 133 <pm_coex_tbtt_process+0x103> */
  a2 = a4 + ((0x200) << 8); /* 0125: addmi a2, a4, 0x200 */
  a2 = MEM8(a2 + 30); /* 0128: l8ui a2, a2, 30 */
  if (a2 != 0) goto L_133; /* 012b: bnez.n a2, 133 <pm_coex_tbtt_process+0x103> */
L_12d:;
  a8 = (uint32_t)&hal_pm_unblock_txq; /* 012d: l32r a8, 28 <pm_coex_tbtt_process-0x8> (8 <pm_coex_tbtt_process-0x28>) */ /* literal: GOT slot for .text.hal_pm_unblock_txq */
  hal_pm_unblock_txq(a2, a3, a4, a5); /* call via literal slot */ /* 0130: callx8 a8 */
L_133:;
  a2 = MEM32(a4 + 36); /* 0133: l32i.n a2, a4, 36 */
  if (a2 == 0) goto L_13c; /* 0135: beqz.n a2, 13c <pm_coex_tbtt_process+0x10c> */
  a2 = MEM8(a4 + 25); /* 0137: l8ui a2, a4, 25 */
  if (a2 == 0) goto L_156; /* 013a: beqz.n a2, 156 <pm_coex_tbtt_process+0x126> */
L_13c:;
  a2 = MEM8(a4 + 14); /* 013c: l8ui a2, a4, 14 */
  if (a2 == 0) goto L_156; /* 013f: beqz.n a2, 156 <pm_coex_tbtt_process+0x126> */
  a2 = 0x0; /* 0141: movi.n a2, 0 */
  a11 = 0x0; /* 0143: movi.n a11, 0 */
  MEM8(a4 + 25) = a2; /* 0145: s8i a2, a4, 25 */
  MEMW(); /* 0148: memw  */
  a10 = 0x1; /* 014b: movi.n a10, 1 */
L_14d:;
  MEMW(); /* 014d: memw  */
  a8 = (uint32_t)&pm_go_to_wake; /* 0150: l32r a8, 2c <pm_coex_tbtt_process-0x4> (0 <pm_coex_tbtt_process-0x30>) */ /* literal: GOT slot for pm_go_to_wake */
  pm_go_to_wake(a2, a3, a4, a5); /* call via literal slot */ /* 0153: callx8 a8 */
L_156:;
  return (int32_t)a2; /* 0156: retw.n  */
}

/* pm_keep_alive_timeout_process @ pm.o 0000001c size 142B bind GLOBAL
 * Calls: pm_dream, pm_enable_keep_alive_timer, pm_go_to_wake, pm_send_nullfunc, wifi_log | Data refs: .rodata_wlog_debug.45, g_pm, pm_dream, pm_enable_keep_alive_timer, pm_go_to_wake, pm_send_nullfunc, wifi_log
 *   MMIO: none
 *   funcdb v3: 5 call(s), 7 ref(s); disasm: 5 call(s), 7 data ref(s)
 * Fidelity: medium - 56 instr, 11 branches, calls resolved */
int32_t pm_keep_alive_timeout_process(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pm_keep_alive_timeout_process; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_1c:;
  /* 001c: entry a1, 32 */
  a8 = (uint32_t)&pm_enable_keep_alive_timer; /* 001f: l32r a8, 8 <pm_keep_alive_timeout_process-0x14> (0 <pm_keep_alive_timeout_process-0x1c>) */ /* literal: GOT slot for pm_enable_keep_alive_timer */
  pm_enable_keep_alive_timer(a2, a3, a4, a5); /* call via literal slot */ /* 0022: callx8 a8 */
  a8 = (uint32_t)&g_pm; /* 0025: l32r a8, 0 <pm_keep_alive_timeout_process-0x1c> (0 <pm_keep_alive_timeout_process-0x1c>) */ /* literal @0x0: g_pm */
  a10 = MEM8(a8 + 13); /* 0028: l8ui a10, a8, 13 */
  a9 = MEM8(a8 + 14); /* 002b: l8ui a9, a8, 14 */
  if (a10 == 0) goto L_3d; /* 002e: beqz.n a10, 3d <pm_keep_alive_timeout_process+0x21> */
  if (a9 == 0) goto L_40; /* 0030: beqz.n a9, 40 <pm_keep_alive_timeout_process+0x24> */
  a9 = MEM8(a8 + 15); /* 0032: l8ui a9, a8, 15 */
  if (a9 == 0) goto L_5c; /* 0035: beqz.n a9, 5c <pm_keep_alive_timeout_process+0x40> */
  goto L_a8; /* 0037: j a8 <pm_keep_alive_timeout_process+0x8c> */
  /* 003a: .byte 00 */
  /* 003b: .byte 00 */
  /* 003c: .byte 00 */
L_3d:;
  if (a9 != 0) goto L_a8; /* 003d: bnez a9, a8 <pm_keep_alive_timeout_process+0x8c> */
L_40:;
  a10 = a8 + ((0x100) << 8); /* 0040: addmi a10, a8, 0x100 */
  a9 = 0x1; /* 0043: movi.n a9, 1 */
  a8 = a8 + ((0x200) << 8); /* 0045: addmi a8, a8, 0x200 */
  MEM8(a10 + 28) = a9; /* 0048: s8i a9, a10, 28 */
  MEM8(a10 + 232) = a9; /* 004b: s8i a9, a10, 232 */
  MEM8(a8 + 64) = a9; /* 004e: s8i a9, a8, 64 */
  MEMW(); /* 0051: memw  */
  MEMW(); /* 0054: memw  */
  goto L_a8; /* 0057: j a8 <pm_keep_alive_timeout_process+0x8c> */
  /* 005a: .byte 00 */
  /* 005b: .byte 00 */
L_5c:;
  a9 = a8 + ((0x100) << 8); /* 005c: addmi a9, a8, 0x100 */
  a10 = MEM8(a9 + 232); /* 005f: l8ui a10, a9, 232 */
  if (a10 != 0) goto L_a8; /* 0062: bnez a10, a8 <pm_keep_alive_timeout_process+0x8c> */
  a10 = 0x1; /* 0065: movi.n a10, 1 */
  MEM8(a9 + 232) = a10; /* 0067: s8i a10, a9, 232 */
  MEMW(); /* 006a: memw  */
  a10 = MEM32(a8 + 36); /* 006d: l32i.n a10, a8, 36 */
  if (a10 != 0) goto L_80; /* 006f: bnez.n a10, 80 <pm_keep_alive_timeout_process+0x64> */
  a11 = a10; /* 0071: mov.n a11, a10 */
  MEMW(); /* 0073: memw  */
  a8 = (uint32_t)&pm_go_to_wake; /* 0076: l32r a8, c <pm_keep_alive_timeout_process-0x10> (0 <pm_keep_alive_timeout_process-0x1c>) */ /* literal: GOT slot for pm_go_to_wake */
  pm_go_to_wake(a2, a3, a4, a5); /* call via literal slot */ /* 0079: callx8 a8 */
  goto L_96; /* 007c: j 96 <pm_keep_alive_timeout_process+0x7a> */
  /* 007f: .byte 00 */
L_80:;
  a10 = MEM8(a8 + 1); /* 0080: l8ui a10, a8, 1 */
  if (a10 != 0) goto L_88; /* 0083: bnez.n a10, 88 <pm_keep_alive_timeout_process+0x6c> */
  goto L_90; /* 0085: j 90 <pm_keep_alive_timeout_process+0x74> */
L_88:;
  a8 = (uint32_t)&pm_dream; /* 0088: l32r a8, 10 <pm_keep_alive_timeout_process-0xc> (0 <pm_keep_alive_timeout_process-0x1c>) */ /* literal: GOT slot for pm_dream */
  pm_dream(a2, a3, a4, a5); /* call via literal slot */ /* 008b: callx8 a8 */
  a10 = 0x1; /* 008e: movi.n a10, 1 */
L_90:;
  a8 = (uint32_t)&pm_send_nullfunc; /* 0090: l32r a8, 14 <pm_keep_alive_timeout_process-0x8> (0 <pm_keep_alive_timeout_process-0x1c>) */ /* literal: GOT slot for pm_send_nullfunc */
  pm_send_nullfunc(a2, a3, a4, a5); /* call via literal slot */ /* 0093: callx8 a8 */
L_96:;
  a11 = 0x1; /* 0096: movi.n a11, 1 */
  a13 = (uint32_t)&lit_rodata_wlog_debug_45; /* 0098: l32r a13, 4 <pm_keep_alive_timeout_process-0x18> (0 <pm_keep_alive_timeout_process-0x1c>) */ /* literal @0x4: .rodata_wlog_debug.45 */
  a12 = 0x4; /* 009b: movi.n a12, 4 */
  a11 = 0x1000; /* 009d: slli a11, a11, 12 */
  a10 = 0x6; /* 00a0: movi.n a10, 6 */
  a8 = (uint32_t)&wifi_log; /* 00a2: l32r a8, 18 <pm_keep_alive_timeout_process-0x4> (0 <pm_keep_alive_timeout_process-0x1c>) */ /* literal: GOT slot for wifi_log */
  wifi_log(a2, a3, a4, a5); /* call via literal slot */ /* 00a5: callx8 a8 */
L_a8:;
  return (int32_t)a2; /* 00a8: retw.n  */
}

/* pm_tx_data_process @ pm.o 00000050 size 507B bind GLOBAL
 * Calls: esp_mesh_quick_funcs[got], pm_check_state[got], pm_check_state[got], pm_is_in_wifi_slice_threshold[got], pm_disconnected_wake[got], pm_coex_schm_process_restart[got], pm_is_in_wifi_slice_threshold[got], esp_mesh_quick_funcs[got], pm_go_to_wake[got], pm_is_in_wifi_slice_threshold[got], g_pm[got], pm_dream[got], pm_go_to_wake[got], pm_enable_active_timer[got], .text.pm_incr_coex_active_cnt[got] | Data refs: g_mesh_is_started, g_mesh_is_root, g_mesh_init_ps_type, esp_mesh_quick_funcs, g_pm, pm_check_state, g_osi_funcs_p, pm_is_in_wifi_slice_threshold, pm_disconnected_wake, pm_coex_schm_process_restart, pm_go_to_wake, pm_dream, g_pm_cnt, pm_enable_active_timer, .text.pm_incr_coex_active_cnt
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 15 call(s), 15 data ref(s)
 * Fidelity: low - 191 instr, 48 branches, 6 indirect; call-sequence + MMIO skeleton */
int32_t pm_tx_data_process(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .wifiextrairam.48; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_50:;
  /* 0050: entry a1, 48 */
  a6 = (a2 >> 0) & 0xFF; /* 0053: extui a6, a2, 0, 8 */
  a2 = 0x0; /* 0056: movi.n a2, 0 */
  MEM8(a1 + 0) = a2; /* 0058: s8i a2, a1, 0 */
  MEMW(); /* 005b: memw  */
  a3 = (a3 >> 0) & 0xFF; /* 005e: extui a3, a3, 0, 8 */
  a2 = (uint32_t)&g_mesh_is_started; /* 0061: l32r a2, 0 <pm_tx_data_process-0x50> (0 <pm_tx_data_process-0x50>) */ /* literal @0x0: g_mesh_is_started */
  a5 = MEM8(a2 + 0); /* 0064: l8ui a5, a2, 0 */
  if (a5 == 0) goto L_8f; /* 0067: beqz.n a5, 8f <pm_tx_data_process+0x3f> */
  a2 = (uint32_t)&g_mesh_is_root; /* 0069: l32r a2, 4 <pm_tx_data_process-0x4c> (0 <pm_tx_data_process-0x50>) */ /* literal @0x4: g_mesh_is_root */
  MEMW(); /* 006c: memw  */
  a4 = MEM8(a2 + 0); /* 006f: l8ui a4, a2, 0 */
  a4 = (a4 >> 0) & 0xFF; /* 0072: extui a4, a4, 0, 8 */
  if (a4 != 0) goto L_8f; /* 0075: bnez.n a4, 8f <pm_tx_data_process+0x3f> */
  a2 = (uint32_t)&g_mesh_init_ps_type; /* 0077: l32r a2, 8 <pm_tx_data_process-0x48> (0 <pm_tx_data_process-0x50>) */ /* literal @0x8: g_mesh_init_ps_type */
  a2 = MEM32(a2 + 0); /* 007a: l32i.n a2, a2, 0 */
  if (a2 == 0) goto L_8f; /* 007c: beqz.n a2, 8f <pm_tx_data_process+0x3f> */
  a10 = a1; /* 007e: mov.n a10, a1 */
  a2 = (uint32_t)&esp_mesh_quick_funcs; /* 0080: l32r a2, c <pm_tx_data_process-0x44> (0 <pm_tx_data_process-0x50>) */ /* literal @0xC: esp_mesh_quick_funcs */
  a2 = MEM32(a2 + 128); /* 0083: l32i a2, a2, 128 */
  MEMW(); /* 0086: memw  */
  esp_mesh_quick_funcs(a2, a3, a4, a5); /* call via literal slot */ /* 0089: callx8 a2 */
  goto L_246; /* 008c: j 246 <pm_tx_data_process+0x1f6> */
L_8f:;
  a4 = (uint32_t)&g_pm; /* 008f: l32r a4, 10 <pm_tx_data_process-0x40> (0 <pm_tx_data_process-0x50>) */ /* literal @0x10: g_pm */
  a2 = 0x0; /* 0092: movi.n a2, 0 */
  a7 = MEM8(a4 + 2); /* 0094: l8ui a7, a4, 2 */
  if (a7 == a6) goto L_9d; /* 0097: beq a7, a6, 9d <pm_tx_data_process+0x4d> */
  goto L_249; /* 009a: j 249 <pm_tx_data_process+0x1f9> */
L_9d:;
  if (a5 == a2) goto L_ad; /* 009d: beq a5, a2, ad <pm_tx_data_process+0x5d> */
  a8 = (uint32_t)&pm_check_state; /* 00a0: l32r a8, 20 <pm_tx_data_process-0x30> (0 <pm_tx_data_process-0x50>) */ /* literal: GOT slot for pm_check_state */
  pm_check_state(a2, a3, a4, a5); /* call via literal slot */ /* 00a3: callx8 a8 */
  if (a10 != a2) goto L_b3; /* 00a6: bne a10, a2, b3 <pm_tx_data_process+0x63> */
  goto L_246; /* 00a9: j 246 <pm_tx_data_process+0x1f6> */
  /* 00ac: .byte 00 */
L_ad:;
  a8 = (uint32_t)&pm_check_state; /* 00ad: l32r a8, 24 <pm_tx_data_process-0x2c> (0 <pm_tx_data_process-0x50>) */ /* literal: GOT slot for pm_check_state */
  pm_check_state(a2, a3, a4, a5); /* call via literal slot */ /* 00b0: callx8 a8 */
L_b3:;
  a2 = MEM8(a4 + 13); /* 00b3: l8ui a2, a4, 13 */
  if (a2 != 0) goto L_141; /* 00b6: bnez a2, 141 <pm_tx_data_process+0xf1> */
  a6 = (uint32_t)&g_osi_funcs_p; /* 00b9: l32r a6, 14 <pm_tx_data_process-0x3c> (0 <pm_tx_data_process-0x50>) */ /* literal @0x14: g_osi_funcs_p */
  a2 = MEM32(a6 + 0); /* 00bc: l32i.n a2, a6, 0 */
  a10 = MEM32(a2 + 272); /* 00be: l32i a10, a2, 0x110 */
  ((int32_t(*)())a10)(a2, a3, a4, a5); /* 00c1: callx8 a10 */ /* indirect */
  a12 = 0x271; /* 00c4: movi a12, 0x271 */
  a12 = 0x1388; /* 00c7: slli a12, a12, 3 */
  a2 = a10; /* 00ca: mov.n a2, a10 */
  a5 = a11; /* 00cc: mov.n a5, a11 */
  a8 = (uint32_t)&pm_is_in_wifi_slice_threshold; /* 00ce: l32r a8, 28 <pm_tx_data_process-0x28> (0 <pm_tx_data_process-0x50>) */ /* literal: GOT slot for pm_is_in_wifi_slice_threshold */
  pm_is_in_wifi_slice_threshold(a2, a3, a4, a5); /* call via literal slot */ /* 00d1: callx8 a8 */
  a12 = MEM32(a4 + 96); /* 00d4: l32i a12, a4, 96 */
  a8 = MEM32(a4 + 100); /* 00d7: l32i a8, a4, 100 */
  if (a10 == 0) goto L_fd; /* 00da: beqz.n a10, fd <pm_tx_data_process+0xad> */
  if (a5 < a8) goto L_e5; /* 00dc: bltu a5, a8, e5 <pm_tx_data_process+0x95> */
  if (a8 != a5) goto L_f4; /* 00df: bne a8, a5, f4 <pm_tx_data_process+0xa4> */
  if (a2 >= a12) goto L_f4; /* 00e2: bgeu a2, a12, f4 <pm_tx_data_process+0xa4> */
L_e5:;
  a3 = MEM32(a6 + 0); /* 00e5: l32i.n a3, a6, 0 */
  a12 = a12 - a2; /* 00e7: sub a12, a12, a2 */
  a11 = 0x0; /* 00ea: movi.n a11, 0 */
  a10 = 0x1; /* 00ec: movi.n a10, 1 */
  a3 = MEM32(a3 + 412); /* 00ee: l32i a3, a3, 0x19c */
  ((int32_t(*)())a3)(a2, a3, a4, a5); /* 00f1: callx8 a3 */ /* indirect */
L_f4:;
  a8 = (uint32_t)&pm_disconnected_wake; /* 00f4: l32r a8, 2c <pm_tx_data_process-0x24> (0 <pm_tx_data_process-0x50>) */ /* literal: GOT slot for pm_disconnected_wake */
  pm_disconnected_wake(a2, a3, a4, a5); /* call via literal slot */ /* 00f7: callx8 a8 */
  goto L_246; /* 00fa: j 246 <pm_tx_data_process+0x1f6> */
L_fd:;
  a3 = MEM32(a4 + 432); /* 00fd: l32i a3, a4, 0x1b0 */
  a3 = a12 + a3; /* 0100: add.n a3, a12, a3 */
  a7 = MEM32(a4 + 436); /* 0102: l32i a7, a4, 0x1b4 */
  a4 = 0x1; /* 0105: movi.n a4, 1 */
  if (a3 < a12) goto L_10c; /* 0107: bltu a3, a12, 10c <pm_tx_data_process+0xbc> */
  a4 = 0x1; /* 010a: mov.n a4, a10 */
L_10c:;
  a8 = a8 + a7; /* 010c: add.n a8, a8, a7 */
  a4 = a4 + a8; /* 010e: add.n a4, a4, a8 */
  if (a5 < a4) goto L_119; /* 0110: bltu a5, a4, 119 <pm_tx_data_process+0xc9> */
  if (a4 != a5) goto L_138; /* 0113: bne a4, a5, 138 <pm_tx_data_process+0xe8> */
  if (a2 >= a3) goto L_138; /* 0116: bgeu a2, a3, 138 <pm_tx_data_process+0xe8> */
L_119:;
  a5 = MEM32(a6 + 0); /* 0119: l32i.n a5, a6, 0 */
  a4 = (uint32_t)&g_pm; /* 011b: l32r a4, 18 <pm_tx_data_process-0x38> (0 <pm_tx_data_process-0x50>) */ /* literal @0x18: g_pm */
  a10 = a4; /* 011e: mov.n a10, a4 */
  a5 = MEM32(a5 + 236); /* 0120: l32i a5, a5, 236 */
  ((int32_t(*)())a5)(a2, a3, a4, a5); /* 0123: callx8 a5 */ /* indirect */
  a12 = 0x0; /* 0126: movi.n a12, 0 */
  a11 = a3 - a2; /* 0128: sub a11, a3, a2 */
  a5 = MEM32(a6 + 0); /* 012b: l32i.n a5, a6, 0 */
  a10 = a4; /* 012d: mov.n a10, a4 */
  a5 = MEM32(a5 + 248); /* 012f: l32i a5, a5, 248 */
  ((int32_t(*)())a5)(a2, a3, a4, a5); /* 0132: callx8 a5 */ /* indirect */
  goto L_246; /* 0135: j 246 <pm_tx_data_process+0x1f6> */
L_138:;
  a8 = (uint32_t)&pm_coex_schm_process_restart; /* 0138: l32r a8, 30 <pm_tx_data_process-0x20> (0 <pm_tx_data_process-0x50>) */ /* literal: GOT slot for pm_coex_schm_process_restart */
  pm_coex_schm_process_restart(a2, a3, a4, a5); /* call via literal slot */ /* 013b: callx8 a8 */
  goto L_246; /* 013e: j 246 <pm_tx_data_process+0x1f6> */
L_141:;
  a2 = MEM8(a4 + 1); /* 0141: l8ui a2, a4, 1 */
  if (a2 != 1) goto L_1b0; /* 0144: bnei a2, 1, 1b0 <pm_tx_data_process+0x160> */
  a7 = (uint32_t)&g_osi_funcs_p; /* 0147: l32r a7, 14 <pm_tx_data_process-0x3c> (0 <pm_tx_data_process-0x50>) */ /* literal @0x14: g_osi_funcs_p */
  a5 = MEM32(a7 + 0); /* 014a: l32i.n a5, a7, 0 */
  a10 = MEM32(a5 + 272); /* 014c: l32i a10, a5, 0x110 */
  ((int32_t(*)())a10)(a2, a3, a4, a5); /* 014f: callx8 a10 */ /* indirect */
  a12 = 0x271; /* 0152: movi a12, 0x271 */
  a12 = 0x1388; /* 0155: slli a12, a12, 3 */
  a5 = a10; /* 0158: mov.n a5, a10 */
  a6 = a11; /* 015a: mov.n a6, a11 */
  a8 = (uint32_t)&pm_is_in_wifi_slice_threshold; /* 015c: l32r a8, 34 <pm_tx_data_process-0x1c> (0 <pm_tx_data_process-0x50>) */ /* literal: GOT slot for pm_is_in_wifi_slice_threshold */
  pm_is_in_wifi_slice_threshold(a2, a3, a4, a5); /* call via literal slot */ /* 015f: callx8 a8 */
  if (a10 == 0) goto L_19d; /* 0162: beqz.n a10, 19d <pm_tx_data_process+0x14d> */
  a2 = MEM32(a4 + 100); /* 0164: l32i a2, a4, 100 */
  a12 = MEM32(a4 + 96); /* 0167: l32i a12, a4, 96 */
  if (a6 < a2) goto L_173; /* 016a: bltu a6, a2, 173 <pm_tx_data_process+0x123> */
  if (a2 != a6) goto L_188; /* 016d: bne a2, a6, 188 <pm_tx_data_process+0x138> */
  if (a5 >= a12) goto L_188; /* 0170: bgeu a5, a12, 188 <pm_tx_data_process+0x138> */
L_173:;
  a2 = MEM8(a4 + 14); /* 0173: l8ui a2, a4, 14 */
  if (a2 == 0) goto L_188; /* 0176: beqz.n a2, 188 <pm_tx_data_process+0x138> */
  a12 = a12 - a5; /* 0178: sub a12, a12, a5 */
  a11 = 0x0; /* 017b: movi.n a11, 0 */
  a2 = MEM32(a7 + 0); /* 017d: l32i.n a2, a7, 0 */
  a10 = 0x1; /* 017f: movi a10, 1 */
  a2 = MEM32(a2 + 412); /* 0182: l32i a2, a2, 0x19c */
  ((int32_t(*)())a2)(a2, a3, a4, a5); /* 0185: callx8 a2 */ /* indirect */
L_188:;
  if (a3 == 0) goto L_246; /* 0188: beqz a3, 246 <pm_tx_data_process+0x1f6> */
  a11 = 0x1; /* 018b: movi.n a11, 1 */
  a10 = 0x0; /* 018d: movi.n a10, 0 */
  a8 = (uint32_t)&pm_go_to_wake; /* 018f: l32r a8, 38 <pm_tx_data_process-0x18> (0 <pm_tx_data_process-0x50>) */ /* literal: GOT slot for pm_go_to_wake */
  pm_go_to_wake(a2, a3, a4, a5); /* call via literal slot */ /* 0192: callx8 a8 */
  a2 = 0x1; /* 0195: movi.n a2, 1 */
  if (a10 < 2) goto L_1a3; /* 0197: bltui a10, 2, 1a3 <pm_tx_data_process+0x153> */
  goto L_240; /* 019a: j 240 <pm_tx_data_process+0x1f0> */
L_19d:;
  if (a3 == 0) goto L_246; /* 019d: beqz a3, 246 <pm_tx_data_process+0x1f6> */
  MEM8(a4 + 25) = a2; /* 01a0: s8i a2, a4, 25 */
L_1a3:;
  MEM8(a1 + 0) = a2; /* 01a3: s8i a2, a1, 0 */
  MEMW(); /* 01a6: memw  */
  MEMW(); /* 01a9: memw  */
  goto L_240; /* 01ac: j 240 <pm_tx_data_process+0x1f0> */
  /* 01af: .byte 00 */
L_1b0:;
  if (a2 != 2) goto L_22a; /* 01b0: bnei a2, 2, 22a <pm_tx_data_process+0x1da> */
  a6 = (uint32_t)&g_osi_funcs_p; /* 01b3: l32r a6, 14 <pm_tx_data_process-0x3c> (0 <pm_tx_data_process-0x50>) */ /* literal @0x14: g_osi_funcs_p */
  a2 = MEM32(a6 + 0); /* 01b6: l32i.n a2, a6, 0 */
  a10 = MEM32(a2 + 272); /* 01b8: l32i a10, a2, 0x110 */
  ((int32_t(*)())a10)(a2, a3, a4, a5); /* 01bb: callx8 a10 */ /* indirect */
  a12 = 0x271; /* 01be: movi a12, 0x271 */
  a12 = 0x1388; /* 01c1: slli a12, a12, 3 */
  a2 = a10; /* 01c4: mov.n a2, a10 */
  a5 = 0x1; /* 01c6: mov.n a5, a11 */
  a8 = (uint32_t)&pm_is_in_wifi_slice_threshold; /* 01c8: l32r a8, 3c <pm_tx_data_process-0x14> (0 <pm_tx_data_process-0x50>) */ /* literal: GOT slot for pm_is_in_wifi_slice_threshold */
  pm_is_in_wifi_slice_threshold(a2, a3, a4, a5); /* call via literal slot */ /* 01cb: callx8 a8 */
  if (a10 == 0) goto L_20e; /* 01ce: beqz.n a10, 20e <pm_tx_data_process+0x1be> */
  a8 = MEM32(a4 + 100); /* 01d0: l32i a8, a4, 100 */
  a12 = MEM32(a4 + 96); /* 01d3: l32i a12, a4, 96 */
  if (a5 < a8) goto L_1df; /* 01d6: bltu a5, a8, 1df <pm_tx_data_process+0x18f> */
  if (a8 != a5) goto L_1f4; /* 01d9: bne a8, a5, 1f4 <pm_tx_data_process+0x1a4> */
  if (a2 >= a12) goto L_1f4; /* 01dc: bgeu a2, a12, 1f4 <pm_tx_data_process+0x1a4> */
L_1df:;
  a4 = MEM8(a4 + 14); /* 01df: l8ui a4, a4, 14 */
  if (a4 == 0) goto L_1f4; /* 01e2: beqz.n a4, 1f4 <pm_tx_data_process+0x1a4> */
  a12 = a12 - a2; /* 01e4: sub a12, a12, a2 */
  a11 = 0x0; /* 01e7: movi.n a11, 0 */
  a4 = MEM32(a6 + 0); /* 01e9: l32i.n a4, a6, 0 */
  a10 = 0x1; /* 01eb: movi a10, 1 */
  a4 = MEM32(a4 + 412); /* 01ee: l32i a4, a4, 0x19c */
  g_pm(a2, a3, a4, a5); /* call via literal slot */ /* 01f1: callx8 a4 */
L_1f4:;
  a8 = (uint32_t)&pm_dream; /* 01f4: l32r a8, 40 <pm_tx_data_process-0x10> (0 <pm_tx_data_process-0x50>) */ /* literal: GOT slot for pm_dream */
  pm_dream(a2, a3, a4, a5); /* call via literal slot */ /* 01f7: callx8 a8 */
  if (a3 == 0) goto L_21b; /* 01fa: beqz.n a3, 21b <pm_tx_data_process+0x1cb> */
  a11 = 0x1; /* 01fc: movi.n a11, 1 */
  a10 = 0x0; /* 01fe: movi.n a10, 0 */
  a8 = (uint32_t)&pm_go_to_wake; /* 0200: l32r a8, 44 <pm_tx_data_process-0xc> (0 <pm_tx_data_process-0x50>) */ /* literal: GOT slot for pm_go_to_wake */
  pm_go_to_wake(a2, a3, a4, a5); /* call via literal slot */ /* 0203: callx8 a8 */
  a2 = 0x1; /* 0206: movi.n a2, 1 */
  if (a10 < 2) goto L_215; /* 0208: bltui a10, 2, 215 <pm_tx_data_process+0x1c5> */
  goto L_21b; /* 020b: j 21b <pm_tx_data_process+0x1cb> */
L_20e:;
  if (a3 == 0) goto L_21b; /* 020e: beqz.n a3, 21b <pm_tx_data_process+0x1cb> */
  a2 = 0x1; /* 0210: movi.n a2, 1 */
  MEM8(a4 + 25) = a2; /* 0212: s8i a2, a4, 25 */
L_215:;
  MEM8(a1 + 0) = a2; /* 0215: s8i a2, a1, 0 */
  MEMW(); /* 0218: memw  */
L_21b:;
  a4 = (uint32_t)&g_pm_cnt; /* 021b: l32r a4, 1c <pm_tx_data_process-0x34> (0 <pm_tx_data_process-0x50>) */ /* literal @0x1C: g_pm_cnt */
  a2 = MEM32(a4 + 24); /* 021e: l32i.n a2, a4, 24 */
  a2 = a2 + (1); /* 0220: addi.n a2, a2, 1 */
  MEM32(a4 + 24) = a2; /* 0222: s32i.n a2, a4, 24 */
  MEMW(); /* 0224: memw  */
  goto L_23e; /* 0227: j 23e <pm_tx_data_process+0x1ee> */
L_22a:;
  if (a2 != 0) goto L_23e; /* 022a: bnez.n a2, 23e <pm_tx_data_process+0x1ee> */
  if (a3 == 0) goto L_246; /* 022c: beqz.n a3, 246 <pm_tx_data_process+0x1f6> */
  a2 = MEM32(a4 + 36); /* 022e: l32i.n a2, a4, 36 */
  if (a2 == 0) goto L_240; /* 0230: beqz.n a2, 240 <pm_tx_data_process+0x1f0> */
  a8 = (uint32_t)&pm_enable_active_timer; /* 0232: l32r a8, 48 <pm_tx_data_process-0x8> (0 <pm_tx_data_process-0x50>) */ /* literal: GOT slot for pm_enable_active_timer */
  pm_enable_active_timer(a2, a3, a4, a5); /* call via literal slot */ /* 0235: callx8 a8 */
  goto L_240; /* 0238: j 240 <pm_tx_data_process+0x1f0> */
  /* 023b: .byte 00 */
  /* 023c: .byte 00 */
  /* 023d: .byte 00 */
L_23e:;
  if (a3 == 0) goto L_246; /* 023e: beqz.n a3, 246 <pm_tx_data_process+0x1f6> */
L_240:;
  a8 = (uint32_t)&pm_incr_coex_active_cnt; /* 0240: l32r a8, 4c <pm_tx_data_process-0x4> (4 <pm_tx_data_process-0x4c>) */ /* literal: GOT slot for .text.pm_incr_coex_active_cnt */
  pm_incr_coex_active_cnt(a2, a3, a4, a5); /* call via literal slot */ /* 0243: callx8 a8 */
L_246:;
  a2 = MEM8(a1 + 0); /* 0246: l8ui a2, a1, 0 */
L_249:;
  return (int32_t)a2; /* 0249: retw.n  */
}

/* pm_send_sleep_null_cb @ pm.o 00000004 size 23B bind GLOBAL
 * Calls: pm_tx_null_data_done_process | Data refs: pm_tx_null_data_done_process
 *   MMIO: none
 *   funcdb v3: 1 call(s), 1 ref(s); disasm: 1 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t pm_send_sleep_null_cb(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pm_send_sleep_null_cb; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a8 = MEM32(a2 + 44); /* 0007: l32i.n a8, a2, 44 */
  a10 = 0x1; /* 0009: movi.n a10, 1 */
  a12 = MEM32(a8 + 0); /* 000b: l32i.n a12, a8, 0 */
  a12 = (a12 >> 0) & 0x1; /* 000d: extui a12, a12, 0, 1 */
  a11 = MEM8(a8 + 19); /* 0010: l8ui a11, a8, 19 */
  a8 = (uint32_t)&pm_tx_null_data_done_process; /* 0013: l32r a8, 0 <pm_send_sleep_null_cb-0x4> (0 <pm_send_sleep_null_cb-0x4>) */ /* literal: GOT slot for pm_tx_null_data_done_process */
  pm_tx_null_data_done_process(a2, a3, a4, a5); /* call via literal slot */ /* 0016: callx8 a8 */
  return (int32_t)a2; /* 0019: retw.n  */
}

/* pm_send_wake_null_cb @ pm.o 00000004 size 23B bind GLOBAL
 * Calls: pm_tx_null_data_done_process | Data refs: pm_tx_null_data_done_process
 *   MMIO: none
 *   funcdb v3: 1 call(s), 1 ref(s); disasm: 1 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t pm_send_wake_null_cb(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pm_send_wake_null_cb; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a8 = MEM32(a2 + 44); /* 0007: l32i.n a8, a2, 44 */
  a10 = 0x0; /* 0009: movi.n a10, 0 */
  a12 = MEM32(a8 + 0); /* 000b: l32i.n a12, a8, 0 */
  a12 = (a12 >> 0) & 0x1; /* 000d: extui a12, a12, 0, 1 */
  a11 = MEM8(a8 + 19); /* 0010: l8ui a11, a8, 19 */
  a8 = (uint32_t)&pm_tx_null_data_done_process; /* 0013: l32r a8, 0 <pm_send_wake_null_cb-0x4> (0 <pm_send_wake_null_cb-0x4>) */ /* literal: GOT slot for pm_tx_null_data_done_process */
  pm_tx_null_data_done_process(a2, a3, a4, a5); /* call via literal slot */ /* 0016: callx8 a8 */
  return (int32_t)a2; /* 0019: retw.n  */
}

/* pm_on_coex_schm_process_restart @ pm.o 00000004 size 11B bind GLOBAL
 * Calls: pm_coex_schm_process_restart | Data refs: pm_coex_schm_process_restart
 *   MMIO: none
 *   funcdb v3: 1 call(s), 1 ref(s); disasm: 1 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t pm_on_coex_schm_process_restart(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pm_on_coex_schm_process_restart; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a8 = (uint32_t)&pm_coex_schm_process_restart; /* 0007: l32r a8, 0 <pm_on_coex_schm_process_restart-0x4> (0 <pm_on_coex_schm_process_restart-0x4>) */ /* literal: GOT slot for pm_coex_schm_process_restart */
  pm_coex_schm_process_restart(a2, a3, a4, a5); /* call via literal slot */ /* 000a: callx8 a8 */
  return (int32_t)a2; /* 000d: retw.n  */
}

/* pm_on_coex_schm_status_config @ pm.o 00000014 size 144B bind GLOBAL
 * Calls: pm_get_connectionless_status | Data refs: g_osi_funcs_p, g_pm, pm_get_connectionless_status
 *   MMIO: none
 *   funcdb v3: 1 call(s), 3 ref(s); disasm: 3 call(s), 3 data ref(s)
 * Fidelity: medium - 55 instr, 8 branches, calls resolved */
int32_t pm_on_coex_schm_status_config(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pm_on_coex_schm_status_config; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_14:;
  /* 0014: entry a1, 32 */
  if (a2 != 0) goto L_28; /* 0017: bnez a2, 28 <pm_on_coex_schm_status_config+0x14> */
  a8 = (uint32_t)&pm_get_connectionless_status; /* 001a: l32r a8, 10 <pm_on_coex_schm_status_config-0x4> (0 <pm_on_coex_schm_status_config-0x14>) */ /* literal: GOT slot for pm_get_connectionless_status */
  pm_get_connectionless_status(a2, a3, a4, a5); /* call via literal slot */ /* 001d: callx8 a8 */
  a3 = 0x1; /* 0020: movi.n a3, 1 */
  if (a10 != 0) a2 = a3; /* 0022: movnez a2, a3, a10 */
  a2 = a2 << (6 & 31); /* 0025: slli a2, a2, 6 */
L_28:;
  a3 = (uint32_t)&g_osi_funcs_p; /* 0028: l32r a3, 4 <pm_on_coex_schm_status_config-0x10> (0 <pm_on_coex_schm_status_config-0x14>) */ /* literal @0x4: g_osi_funcs_p */
  a10 = 0x0; /* 002b: movi.n a10, 0 */
  a8 = MEM32(a3 + 0); /* 002d: l32i.n a8, a3, 0 */
  a11 = 0xFFFF; /* 002f: l32r a11, 0 <pm_on_coex_schm_status_config-0x14> (ffff <pm_attach+0xff7b>) */ @0x0
  a8 = MEM32(a8 + 432); /* 0032: l32i a8, a8, 0x1b0 */
  pm_get_connectionless_status(a2, a3, a4, a5); /* call via literal slot */ /* 0035: callx8 a8 */
  a11 = a2; /* 0038: mov.n a11, a2 */
  a10 = 0x0; /* 003a: movi.n a10, 0 */
  a8 = MEM32(a3 + 0); /* 003c: l32i.n a8, a3, 0 */
  a8 = MEM32(a8 + 436); /* 003e: l32i a8, a8, 0x1b4 */
  pm_get_connectionless_status(a2, a3, a4, a5); /* call via literal slot */ /* 0041: callx8 a8 */
  a9 = 0xFFFFFFBF; /* 0044: movi a9, -65 */
  a8 = (uint32_t)&g_pm; /* 0047: l32r a8, 8 <pm_on_coex_schm_status_config-0xc> (0 <pm_on_coex_schm_status_config-0x14>) */ /* literal @0x8: g_pm */
  MEM32(a8 + 400) = a2; /* 004a: s32i a2, a8, 0x190 */
  if ((a2 & a9) != 0) goto L_60; /* 004d: bany a2, a9, 60 <pm_on_coex_schm_status_config+0x4c> */
  a10 = 0x3E8; /* 0050: movi a10, 0x3e8 */
  a2 = MEM32(a3 + 0); /* 0053: l32i.n a2, a3, 0 */
  a2 = MEM32(a2 + 440); /* 0055: l32i a2, a2, 0x1b8 */
  MEMW(); /* 0058: memw  */
  goto L_9f; /* 005b: j 9f <pm_on_coex_schm_status_config+0x8b> */
  /* 005e: .byte 00 */
  /* 005f: .byte 00 */
L_60:;
  if (a2 != 1) goto L_70; /* 0060: bnei a2, 1, 70 <pm_on_coex_schm_status_config+0x5c> */
  a2 = MEM32(a3 + 0); /* 0063: l32i.n a2, a3, 0 */
  a10 = 0x64; /* 0065: movi a10, 100 */
  a2 = MEM32(a2 + 440); /* 0068: l32i a2, a2, 0x1b8 */
  goto L_9f; /* 006b: j 9f <pm_on_coex_schm_status_config+0x8b> */
  /* 006e: .byte 00 */
  /* 006f: .byte 00 */
L_70:;
  if (a2 != 2) goto L_8c; /* 0070: bnei a2, 2, 8c <pm_on_coex_schm_status_config+0x78> */
  a8 = a8 + ((0x100) << 8); /* 0073: addmi a8, a8, 0x100 */
  a10 = MEM8(a8 + 201); /* 0076: l8ui a10, a8, 201 */
  a8 = 0x64; /* 0079: movi a8, 100 */
  a2 = MEM32(a3 + 0); /* 007c: l32i.n a2, a3, 0 */
  a3 = 0xF0; /* 007e: movi a3, 240 */
  if (a10 != 0) a3 = a8; /* 0081: movnez a3, a8, a10 */
  a10 = a3; /* 0084: mov.n a10, a3 */
  a2 = MEM32(a2 + 440); /* 0086: l32i a2, a2, 0x1b8 */
  goto L_9f; /* 0089: j 9f <pm_on_coex_schm_status_config+0x8b> */
L_8c:;
  if (a2 != 4) goto L_a2; /* 008c: bnei a2, 4, a2 <pm_on_coex_schm_status_config+0x8e> */
  a2 = 0x51EB851F; /* 008f: l32r a2, c <pm_on_coex_schm_status_config-0x8> (51eb851f <pm_attach+0x51eb849b>) */ @0xC
  a10 = MEM32(a8 + 44); /* 0092: l32i.n a10, a8, 44 */
  a10 = (uint32_t)(((uint64_t)a10 * a2) >> 32) /* muluh: high word */; /* 0094: muluh a10, a10, a2 */
  a10 = a10 >> (5 & 31); /* 0097: srli a10, a10, 5 */
  a2 = MEM32(a3 + 0); /* 009a: l32i.n a2, a3, 0 */
  a2 = MEM32(a2 + 440); /* 009c: l32i a2, a2, 0x1b8 */
L_9f:;
  ((int32_t(*)())a2)(a2, a3, a4, a5); /* 009f: callx8 a2 */ /* indirect */
L_a2:;
  return (int32_t)a2; /* 00a2: retw.n  */
}

/* pm_on_coex_start @ pm.o 00000018 size 67B bind GLOBAL
 * Calls: pm_coex_schm_process_restart, pm_on_coex_schm_status_config, pm_update_by_connectionless_status, wifi_log | Data refs: .rodata_wlog_info.53, g_pm, pm_coex_schm_process_restart, pm_on_coex_schm_status_config, pm_update_by_connectionless_status, wifi_log
 *   MMIO: none
 *   funcdb v3: 4 call(s), 6 ref(s); disasm: 4 call(s), 6 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t pm_on_coex_start(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pm_on_coex_start; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_18:;
  /* 0018: entry a1, 32 */
  a2 = (uint32_t)&g_pm; /* 001b: l32r a2, 0 <pm_on_coex_start-0x18> (0 <pm_on_coex_start-0x18>) */ /* literal @0x0: g_pm */
  a10 = MEM32(a2 + 400); /* 001e: l32i a10, a2, 0x190 */
  if (a10 != 0) goto L_29; /* 0021: bnez.n a10, 29 <pm_on_coex_start+0x11> */
  a8 = (uint32_t)&pm_on_coex_schm_status_config; /* 0023: l32r a8, 8 <pm_on_coex_start-0x10> (0 <pm_on_coex_start-0x18>) */ /* literal: GOT slot for pm_on_coex_schm_status_config */
  pm_on_coex_schm_status_config(a2, a3, a4, a5); /* call via literal slot */ /* 0026: callx8 a8 */
L_29:;
  a8 = (uint32_t)&pm_coex_schm_process_restart; /* 0029: l32r a8, c <pm_on_coex_start-0xc> (0 <pm_on_coex_start-0x18>) */ /* literal: GOT slot for pm_coex_schm_process_restart */
  pm_coex_schm_process_restart(a2, a3, a4, a5); /* call via literal slot */ /* 002c: callx8 a8 */
  a8 = (uint32_t)&pm_update_by_connectionless_status; /* 002f: l32r a8, 10 <pm_on_coex_start-0x8> (0 <pm_on_coex_start-0x18>) */ /* literal: GOT slot for pm_update_by_connectionless_status */
  pm_update_by_connectionless_status(a2, a3, a4, a5); /* call via literal slot */ /* 0032: callx8 a8 */
  a3 = MEM32(a2 + 36); /* 0035: l32i.n a3, a2, 36 */
  if (a3 != 0) goto L_56; /* 0037: bnez.n a3, 56 <pm_on_coex_start+0x3e> */
  a11 = 0x1; /* 0039: movi.n a11, 1 */
  a12 = 0x3; /* 003b: movi a12, 3 */
  a13 = (uint32_t)&lit_rodata_wlog_info_53; /* 003e: l32r a13, 4 <pm_on_coex_start-0x14> (0 <pm_on_coex_start-0x18>) */ /* literal @0x4: .rodata_wlog_info.53 */
  a11 = 0x1000; /* 0041: slli a11, a11, 12 */
  a10 = 0x6; /* 0044: movi a10, 6 */
  a2 = a2 + ((0x100) << 8); /* 0047: addmi a2, a2, 0x100 */
  a8 = (uint32_t)&wifi_log; /* 004a: l32r a8, 14 <pm_on_coex_start-0x4> (0 <pm_on_coex_start-0x18>) */ /* literal: GOT slot for wifi_log */
  wifi_log(a2, a3, a4, a5); /* call via literal slot */ /* 004d: callx8 a8 */
  MEM8(a2 + 200) = a3; /* 0050: s8i a3, a2, 200 */
  MEMW(); /* 0053: memw  */
L_56:;
  MEMW(); /* 0056: memw  */
  return (int32_t)a2; /* 0059: retw.n  */
}

/* pm_on_data_rx @ pm.o 00000008 size 34B bind GLOBAL
 * Calls: pm_sleep_for[got], pm_rx_data_process[got] | Data refs: pm_sleep_for, pm_rx_data_process
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 2 call(s), 2 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t pm_on_data_rx(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .wifirxiram.55; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_8:;
  /* 0008: entry a1, 32 */
  a10 = a2; /* 000b: mov.n a10, a2 */
  a5 = (a5 >> 0) & 0xFF; /* 000d: extui a5, a5, 0, 8 */
  a8 = (uint32_t)&pm_sleep_for; /* 0010: l32r a8, 0 <pm_on_data_rx-0x8> (0 <pm_on_data_rx-0x8>) */ /* literal: GOT slot for pm_sleep_for */
  pm_sleep_for(a2, a3, a4, a5); /* call via literal slot */ /* 0013: callx8 a8 */
  if (a10 == 0) goto L_28; /* 0016: beqz a10, 28 <pm_on_data_rx+0x20> */
  a10 = MEM8(a4 + 0); /* 0019: l8ui a10, a4, 0 */
  a11 = (a5 >> 5) & 0x1; /* 001c: extui a11, a5, 5, 1 */
  a10 = (a10 >> 0) & 0x1; /* 001f: extui a10, a10, 0, 1 */
  a8 = (uint32_t)&pm_rx_data_process; /* 0022: l32r a8, 4 <pm_on_data_rx-0x4> (0 <pm_on_data_rx-0x8>) */ /* literal: GOT slot for pm_rx_data_process */
  pm_rx_data_process(a2, a3, a4, a5); /* call via literal slot */ /* 0025: callx8 a8 */
L_28:;
  return (int32_t)a2; /* 0028: retw.n  */
}

/* pm_on_data_tx @ pm.o 00000004 size 19B bind GLOBAL
 * Calls: pm_tx_data_process[got] | Data refs: pm_tx_data_process
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 1 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t pm_on_data_tx(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .wifiextrairam.56; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a11 = (a3 >> 0) & 0xFF; /* 0007: extui a11, a3, 0, 8 */
  a10 = (a2 >> 0) & 0xFF; /* 000a: extui a10, a2, 0, 8 */
  a8 = (uint32_t)&pm_tx_data_process; /* 000d: l32r a8, 0 <pm_on_data_tx-0x4> (0 <pm_on_data_tx-0x4>) */ /* literal: GOT slot for pm_tx_data_process */
  pm_tx_data_process(a2, a3, a4, a5); /* call via literal slot */ /* 0010: callx8 a8 */
  a2 = a10; /* 0013: mov.n a2, a10 */
  return (int32_t)a2; /* 0015: retw.n  */
}

/* pm_on_data_tx_done @ pm.o 00000004 size 20B bind GLOBAL
 * Calls: pm_tx_data_done_process | Data refs: pm_tx_data_done_process
 *   MMIO: none
 *   funcdb v3: 1 call(s), 1 ref(s); disasm: 1 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t pm_on_data_tx_done(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pm_on_data_tx_done; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a12 = (a4 >> 0) & 0xFF; /* 0007: extui a12, a4, 0, 8 */
  a11 = (a3 >> 0) & 0xFF; /* 000a: extui a11, a3, 0, 8 */
  a10 = (a2 >> 0) & 0xFF; /* 000d: extui a10, a2, 0, 8 */
  a8 = (uint32_t)&pm_tx_data_done_process; /* 0010: l32r a8, 0 <pm_on_data_tx_done-0x4> (0 <pm_on_data_tx_done-0x4>) */ /* literal: GOT slot for pm_tx_data_done_process */
  pm_tx_data_done_process(a2, a3, a4, a5); /* call via literal slot */ /* 0013: callx8 a8 */
  return (int32_t)a2; /* 0016: retw.n  */
}

/* pm_on_sample_beacon @ pm.o 00000008 size 47B bind GLOBAL
 * Calls: g_pm[got] | Data refs: g_pm, ptr_beacon_offset_funcs
 *   MMIO: none
 *   funcdb v3: 0 call(s), 2 ref(s); disasm: 1 call(s), 2 data ref(s)
 * Fidelity: medium - 19 instr, 5 branches, calls resolved */
int32_t pm_on_sample_beacon(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pm_on_sample_beacon; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_8:;
  /* 0008: entry a1, 32 */
  a8 = (uint32_t)&g_pm; /* 000b: l32r a8, 0 <pm_on_sample_beacon-0x8> (0 <pm_on_sample_beacon-0x8>) */ /* literal @0x0: g_pm */
  a2 = MEM8(a8 + 13); /* 000e: l8ui a2, a8, 13 */
  if (a2 == 0) goto L_35; /* 0011: beqz.n a2, 35 <pm_on_sample_beacon+0x2d> */
  a8 = a8 + ((0x100) << 8); /* 0013: addmi a8, a8, 0x100 */
  a2 = MEM8(a8 + 100); /* 0016: l8ui a2, a8, 100 */
  if (a2 == 0) goto L_35; /* 0019: beqz.n a2, 35 <pm_on_sample_beacon+0x2d> */
  a2 = MEM8(a8 + 212); /* 001b: l8ui a2, a8, 212 */
  if (a2 != 0) goto L_35; /* 001e: bnez.n a2, 35 <pm_on_sample_beacon+0x2d> */
  a2 = (uint32_t)&ptr_beacon_offset_funcs; /* 0020: l32r a2, 4 <pm_on_sample_beacon-0x4> (0 <pm_on_sample_beacon-0x8>) */ /* literal @0x4: ptr_beacon_offset_funcs */
  a8 = MEM32(a2 + 0); /* 0023: l32i.n a8, a2, 0 */
  a8 = MEM32(a8 + 0); /* 0025: l32i.n a8, a8, 0 */
  if (a8 == 0) goto L_2c; /* 0027: beqz.n a8, 2c <pm_on_sample_beacon+0x24> */
  ((int32_t(*)())a8)(a2, a3, a4, a5); /* 0029: callx8 a8 */ /* indirect */
L_2c:;
  a2 = MEM32(a2 + 0); /* 002c: l32i.n a2, a2, 0 */
  a10 = MEM32(a2 + 12); /* 002e: l32i.n a10, a2, 12 */
  if (a10 == 0) goto L_35; /* 0030: beqz.n a10, 35 <pm_on_sample_beacon+0x2d> */
  ((int32_t(*)())a10)(a2, a3, a4, a5); /* 0032: callx8 a10 */ /* indirect */
L_35:;
  return (int32_t)a2; /* 0035: retw.n  */
}

/* pm_scale_listen_interval @ pm.o 0000001c size 184B bind GLOBAL
 * Calls: wifi_nvs_get_sta_listen_interval[got], wifi_nvs_get_sta_listen_interval[got], wifi_log[got], pm_coex_pwr_update[got], pm_on_sample_beacon[got] | Data refs: wifi_nvs_get_sta_listen_interval, g_pm, .rodata_wlog_info.6, wifi_log, pm_coex_pwr_update, pm_on_sample_beacon
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 5 call(s), 6 data ref(s)
 * Fidelity: medium - 68 instr, 9 branches, calls resolved */
int32_t pm_scale_listen_interval(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .wifislprxiram.5; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_1c:;
  /* 001c: entry a1, 48 */
  a8 = (uint32_t)&wifi_nvs_get_sta_listen_interval; /* 001f: l32r a8, 8 <pm_scale_listen_interval-0x14> (0 <pm_scale_listen_interval-0x1c>) */ /* literal: GOT slot for wifi_nvs_get_sta_listen_interval */
  wifi_nvs_get_sta_listen_interval(a2, a3, a4, a5); /* call via literal slot */ /* 0022: callx8 a8 */
  a2 = (uint32_t)&g_pm; /* 0025: l32r a2, 0 <pm_scale_listen_interval-0x1c> (0 <pm_scale_listen_interval-0x1c>) */ /* literal @0x0: g_pm */
  a10 = (a10 << 4) + a10; /* 0028: addx4 a10, a10, a10 */
  a8 = (a10 << 4) + a10; /* 002b: addx4 a8, a10, a10 */
  a8 = a8 << (12 & 31); /* 002e: slli a8, a8, 12 */
  a4 = 0x1; /* 0031: movi.n a4, 1 */
  a3 = MEM32(a2 + 44); /* 0033: l32i.n a3, a2, 44 */
  /* 0035: quou a8, a8, a3 */ /* UNMODELED: a8 clobbered */
  a8 = (a8 >> 0) & 0xFFFF; /* 0038: extui a8, a8, 0, 16 */
  /* 003b: maxu a8, a8, a4 */ /* UNMODELED: a8 clobbered */
  a5 = MEM8(a2 + 11); /* 003e: l8ui a5, a2, 11 */
  if (a8 < a5) goto L_50; /* 0041: bltu a8, a5, 50 <pm_scale_listen_interval+0x34> */
  goto L_6b; /* 0044: j 6b <pm_scale_listen_interval+0x4f> */
  /* 0047: .byte 00 */
L_48:;
  a9 = a9 + (1); /* 0048: addi.n a9, a9, 1 */
  a9 = (a9 >> 0) & 0xFFFF; /* 004a: extui a9, a9, 0, 16 */
  goto L_52; /* 004d: j 52 <pm_scale_listen_interval+0x36> */
L_50:;
  a9 = a8; /* 0050: mov.n a9, a8 */
L_52:;
  /* 0052: rems a4, a5, a9 */ /* UNMODELED: a4 clobbered */
  if (a4 != 0) goto L_48; /* 0055: bnez a4, 48 <pm_scale_listen_interval+0x2c> */
  a4 = a8; /* 0058: mov.n a4, a8 */
  goto L_62; /* 005a: j 62 <pm_scale_listen_interval+0x46> */
L_5d:;
  a4 = a4 + (-1); /* 005d: addi.n a4, a4, -1 */
  a4 = (a4 >> 0) & 0xFFFF; /* 005f: extui a4, a4, 0, 16 */
L_62:;
  /* 0062: rems a10, a5, a4 */ /* UNMODELED: a10 clobbered */
  if (a10 != 0) goto L_5d; /* 0065: bnez a10, 5d <pm_scale_listen_interval+0x41> */
  goto L_79; /* 0068: j 79 <pm_scale_listen_interval+0x5d> */
L_6b:;
  /* 006b: rems a4, a8, a5 */ /* UNMODELED: a4 clobbered */
  a4 = a8 - a4; /* 006e: sub a4, a8, a4 */
  a4 = (a4 >> 0) & 0xFFFF; /* 0071: extui a4, a4, 0, 16 */
  a9 = a5 + a4; /* 0074: add.n a9, a5, a4 */
  a9 = (a9 >> 0) & 0xFFFF; /* 0076: extui a9, a9, 0, 16 */
L_79:;
  a10 = a9 - a8; /* 0079: sub a10, a9, a8 */
  a8 = a8 - a4; /* 007c: sub a8, a8, a4 */
  if (a8 < a10) goto L_84; /* 007f: blt a8, a10, 84 <pm_scale_listen_interval+0x68> */
  a4 = a9; /* 0082: mov.n a4, a9 */
L_84:;
  a8 = MEM16(a2 + 32); /* 0084: l16ui a8, a2, 32 */
  if (a8 == a4) goto L_c3; /* 0087: beq a8, a4, c3 <pm_scale_listen_interval+0xa7> */
  a8 = (uint32_t)&wifi_nvs_get_sta_listen_interval; /* 008a: l32r a8, c <pm_scale_listen_interval-0x10> (0 <pm_scale_listen_interval-0x1c>) */ /* literal: GOT slot for wifi_nvs_get_sta_listen_interval */
  wifi_nvs_get_sta_listen_interval(a2, a3, a4, a5); /* call via literal slot */ /* 008d: callx8 a8 */
  a10 = (a10 << 4) + a10; /* 0090: addx4 a10, a10, a10 */
  a8 = MEM32(a2 + 44); /* 0093: l32i.n a8, a2, 44 */
  a10 = (a10 << 4) + a10; /* 0095: addx4 a10, a10, a10 */
  a8 = (uint32_t)((uint64_t)a4 * a8); /* 0098: mull a8, a4, a8 */
  a10 = a10 << (12 & 31); /* 009b: slli a10, a10, 12 */
  a11 = 0x1; /* 009e: movi.n a11, 1 */
  a13 = (uint32_t)&lit_rodata_wlog_info_6; /* 00a0: l32r a13, 4 <pm_scale_listen_interval-0x18> (0 <pm_scale_listen_interval-0x1c>) */ /* literal @0x4: .rodata_wlog_info.6 */
  a15 = a3; /* 00a3: mov.n a15, a3 */
  a14 = a5; /* 00a5: mov.n a14, a5 */
  a12 = 0x3; /* 00a7: movi.n a12, 3 */
  a11 = 0x1000; /* 00a9: slli a11, a11, 12 */
  MEM32(a1 + 4) = a10; /* 00ac: s32i.n a10, a1, 4 */
  a10 = 0x6; /* 00ae: movi.n a10, 6 */
  MEM32(a1 + 8) = a8; /* 00b0: s32i.n a8, a1, 8 */
  MEM32(a1 + 0) = a4; /* 00b2: s32i.n a4, a1, 0 */
  MEMW(); /* 00b4: memw  */
  a8 = (uint32_t)&wifi_log; /* 00b7: l32r a8, 10 <pm_scale_listen_interval-0xc> (0 <pm_scale_listen_interval-0x1c>) */ /* literal: GOT slot for wifi_log */
  wifi_log(a2, a3, a4, a5); /* call via literal slot */ /* 00ba: callx8 a8 */
  MEM16(a2 + 32) = a4; /* 00bd: s16i a4, a2, 32 */
  MEMW(); /* 00c0: memw  */
L_c3:;
  MEMW(); /* 00c3: memw  */
  a8 = (uint32_t)&pm_coex_pwr_update; /* 00c6: l32r a8, 14 <pm_scale_listen_interval-0x8> (0 <pm_scale_listen_interval-0x1c>) */ /* literal: GOT slot for pm_coex_pwr_update */
  pm_coex_pwr_update(a2, a3, a4, a5); /* call via literal slot */ /* 00c9: callx8 a8 */
  a8 = (uint32_t)&pm_on_sample_beacon; /* 00cc: l32r a8, 18 <pm_scale_listen_interval-0x4> (0 <pm_scale_listen_interval-0x1c>) */ /* literal: GOT slot for pm_on_sample_beacon */
  pm_on_sample_beacon(a2, a3, a4, a5); /* call via literal slot */ /* 00cf: callx8 a8 */
  return (int32_t)a2; /* 00d2: retw.n  */
}

/* pm_parse_beacon @ pm.o 0000003c size 384B bind GLOBAL
 * Calls: wifi_log[got], .text.pm_illegal_beacon_logger[got], wifi_log[got], .text.pm_illegal_beacon_logger[got], pm_scale_listen_interval[got], g_osi_funcs_p[got], pm_scale_listen_interval[got], pm_scale_listen_interval[got], g_osi_funcs_p[got], wifi_log[got] | Data refs: g_pm, .rodata_wlog_info.13, wifi_log, .text.pm_illegal_beacon_logger, .rodata_wlog_info.14, .rodata_wlog_info.15, pm_scale_listen_interval, g_osi_funcs_p, .rodata_wlog_info.16
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 10 call(s), 9 data ref(s)
 * Fidelity: medium - 143 instr, 28 branches, calls resolved */
int32_t pm_parse_beacon(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .wifislprxiram.12; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_3c:;
  /* 003c: entry a1, 32 */
  a6 = a3 - a2; /* 003f: sub a6, a3, a2 */
  a8 = 0xB; /* 0042: movi.n a8, 11 */
  a7 = 0x0; /* 0044: movi.n a7, 0 */
  if (a8 < a6) goto L_4c; /* 0046: blt a8, a6, 4c <pm_parse_beacon+0x10> */
  goto L_1b8; /* 0049: j 1b8 <pm_parse_beacon+0x17c> */
L_4c:;
  a6 = MEM16(a2 + 8); /* 004c: l16ui a6, a2, 8 */
  MEM32(a5 + 0) = a2; /* 004f: s32i.n a2, a5, 0 */
  a5 = a6 << (10 & 31); /* 0051: slli a5, a6, 10 */
  if (a6 != a7) goto L_85; /* 0054: bne a6, a7, 85 <pm_parse_beacon+0x49> */
  a5 = (uint32_t)&g_pm; /* 0057: l32r a5, 0 <pm_parse_beacon-0x3c> (0 <pm_parse_beacon-0x3c>) */ /* literal @0x0: g_pm */
  a6 = MEM8(a5 + 16); /* 005a: l8ui a6, a5, 16 */
  a5 = 0x19; /* 005d: movi.n a5, 25 */
  a5 = 0x19000; /* 005f: slli a5, a5, 12 */
  if (a6 != a7) goto L_85; /* 0062: bne a6, a7, 85 <pm_parse_beacon+0x49> */
  a11 = 0x1; /* 0065: movi.n a11, 1 */
  a13 = (uint32_t)&lit_rodata_wlog_info_13; /* 0067: l32r a13, 4 <pm_parse_beacon-0x38> (0 <pm_parse_beacon-0x3c>) */ /* literal @0x4: .rodata_wlog_info.13 */
  a12 = 0x3; /* 006a: movi.n a12, 3 */
  a11 = 0x1000; /* 006c: slli a11, a11, 12 */
  a10 = 0x6; /* 006f: movi.n a10, 6 */
  a5 = 0x19; /* 0071: movi.n a5, 25 */
  MEMW(); /* 0073: memw  */
  a8 = (uint32_t)&wifi_log; /* 0076: l32r a8, 1c <pm_parse_beacon-0x20> (0 <pm_parse_beacon-0x3c>) */ /* literal: GOT slot for wifi_log */
  wifi_log(a2, a3, a4, a5); /* call via literal slot */ /* 0079: callx8 a8 */
  a5 = a5 << (12 & 31); /* 007c: slli a5, a5, 12 */
  a8 = (uint32_t)&pm_illegal_beacon_logger; /* 007f: l32r a8, 20 <pm_parse_beacon-0x1c> (18 <pm_parse_beacon-0x24>) */ /* literal: GOT slot for .text.pm_illegal_beacon_logger */
  pm_illegal_beacon_logger(a2, a3, a4, a5); /* call via literal slot */ /* 0082: callx8 a8 */
L_85:;
  a2 = a2 + (12); /* 0085: addi.n a2, a2, 12 */
  goto L_a6; /* 0087: j a6 <pm_parse_beacon+0x6a> */
  /* 008a: .byte 00 */
  /* 008b: .byte 00 */
L_8c:;
  a6 = MEM8(a2 + 1); /* 008c: l8ui a6, a2, 1 */
  a8 = a6 + (1); /* 008f: addi.n a8, a6, 1 */
  if (a8 >= a7) goto L_ac; /* 0091: bge a8, a7, ac <pm_parse_beacon+0x70> */
  a7 = MEM8(a2 + 0); /* 0094: l8ui a7, a2, 0 */
  if (a7 != 5) goto L_a2; /* 0097: bnei a7, 5, a2 <pm_parse_beacon+0x66> */
  MEM32(a4 + 0) = a2; /* 009a: s32i.n a2, a4, 0 */
  MEMW(); /* 009c: memw  */
  goto L_ac; /* 009f: j ac <pm_parse_beacon+0x70> */
L_a2:;
  a6 = a6 + (2); /* 00a2: addi.n a6, a6, 2 */
  a2 = a2 + a6; /* 00a4: add.n a2, a2, a6 */
L_a6:;
  a7 = a3 - a2; /* 00a6: sub a7, a3, a2 */
  if (a7 >= 2) goto L_8c; /* 00a9: bgei a7, 2, 8c <pm_parse_beacon+0x50> */
L_ac:;
  a3 = (uint32_t)&g_pm; /* 00ac: l32r a3, 0 <pm_parse_beacon-0x3c> (0 <pm_parse_beacon-0x3c>) */ /* literal @0x0: g_pm */
  a6 = MEM32(a4 + 0); /* 00af: l32i.n a6, a4, 0 */
  a2 = MEM8(a3 + 16); /* 00b1: l8ui a2, a3, 16 */
  if (a6 != 0) goto L_c5; /* 00b4: bnez.n a6, c5 <pm_parse_beacon+0x89> */
  if (a2 != 0) goto L_e7; /* 00b6: bnez.n a2, e7 <pm_parse_beacon+0xab> */
  a11 = 0x1; /* 00b8: movi.n a11, 1 */
  a12 = 0x3; /* 00ba: movi.n a12, 3 */
  a13 = (uint32_t)&lit_rodata_wlog_info_14; /* 00bc: l32r a13, 8 <pm_parse_beacon-0x34> (0 <pm_parse_beacon-0x3c>) */ /* literal @0x8: .rodata_wlog_info.14 */
  a11 = 0x1000; /* 00bf: slli a11, a11, 12 */
  goto L_d8; /* 00c2: j d8 <pm_parse_beacon+0x9c> */
L_c5:;
  a6 = MEM8(a6 + 3); /* 00c5: l8ui a6, a6, 3 */
  if (a6 != 0) goto L_e7; /* 00c8: bnez.n a6, e7 <pm_parse_beacon+0xab> */
  a6 = 0x1; /* 00ca: movi.n a6, 1 */
  if (a2 != 0) goto L_e7; /* 00cc: bnez a2, e7 <pm_parse_beacon+0xab> */
  a13 = (uint32_t)&lit_rodata_wlog_info_15; /* 00cf: l32r a13, c <pm_parse_beacon-0x30> (0 <pm_parse_beacon-0x3c>) */ /* literal @0xC: .rodata_wlog_info.15 */
  a12 = 0x3; /* 00d2: movi a12, 3 */
  a11 = 0x1000; /* 00d5: slli a11, a6, 12 */
L_d8:;
  a10 = 0x6; /* 00d8: movi a10, 6 */
  a8 = (uint32_t)&wifi_log; /* 00db: l32r a8, 24 <pm_parse_beacon-0x18> (0 <pm_parse_beacon-0x3c>) */ /* literal: GOT slot for wifi_log */
  wifi_log(a2, a3, a4, a5); /* call via literal slot */ /* 00de: callx8 a8 */
  a8 = (uint32_t)&pm_illegal_beacon_logger; /* 00e1: l32r a8, 28 <pm_parse_beacon-0x14> (18 <pm_parse_beacon-0x24>) */ /* literal: GOT slot for .text.pm_illegal_beacon_logger */
  pm_illegal_beacon_logger(a2, a3, a4, a5); /* call via literal slot */ /* 00e4: callx8 a8 */
L_e7:;
  a7 = MEM8(a3 + 16); /* 00e7: l8ui a7, a3, 16 */
  if (a7 == 0) goto L_14d; /* 00ea: beqz a7, 14d <pm_parse_beacon+0x111> */
  a2 = MEM32(a3 + 44); /* 00ed: l32i.n a2, a3, 44 */
  if (a2 == a5) goto L_121; /* 00ef: beq a2, a5, 121 <pm_parse_beacon+0xe5> */
  MEM32(a3 + 44) = a5; /* 00f2: s32i.n a5, a3, 44 */
  MEMW(); /* 00f4: memw  */
  a8 = (uint32_t)&pm_scale_listen_interval; /* 00f7: l32r a8, 2c <pm_parse_beacon-0x10> (0 <pm_parse_beacon-0x3c>) */ /* literal: GOT slot for pm_scale_listen_interval */
  pm_scale_listen_interval(a2, a3, a4, a5); /* call via literal slot */ /* 00fa: callx8 a8 */
  a2 = (uint32_t)&g_osi_funcs_p; /* 00fd: l32r a2, 10 <pm_parse_beacon-0x2c> (0 <pm_parse_beacon-0x3c>) */ /* literal @0x10: g_osi_funcs_p */
  a8 = MEM32(a2 + 0); /* 0100: l32i a8, a2, 0 */
  a10 = MEM32(a8 + 404); /* 0103: l32i a10, a8, 0x194 */
  ((int32_t(*)())a10)(a2, a3, a4, a5); /* 0106: callx8 a10 */ /* indirect */
  if (a10 == 0) goto L_121; /* 0109: beqz.n a10, 121 <pm_parse_beacon+0xe5> */
  a8 = MEM8(a3 + 14); /* 010b: l8ui a8, a3, 14 */
  if (a8 == 0) goto L_121; /* 010e: beqz.n a8, 121 <pm_parse_beacon+0xe5> */
  a10 = 0x51EB851F; /* 0110: l32r a10, 14 <pm_parse_beacon-0x28> (51eb851f <pm_attach+0x51eb849b>) */ @0x14
  a10 = (uint32_t)(((uint64_t)a5 * a10) >> 32) /* muluh: high word */; /* 0113: muluh a10, a5, a10 */
  a10 = a10 >> (5 & 31); /* 0116: srli a10, a10, 5 */
  a2 = MEM32(a2 + 0); /* 0119: l32i.n a2, a2, 0 */
  a2 = MEM32(a2 + 440); /* 011b: l32i a2, a2, 0x1b8 */
  g_osi_funcs_p(a2, a3, a4, a5); /* call via literal slot */ /* 011e: callx8 a2 */
L_121:;
  a4 = MEM32(a4 + 0); /* 0121: l32i.n a4, a4, 0 */
  if (a4 == 0) goto L_1b8; /* 0123: beqz a4, 1b8 <pm_parse_beacon+0x17c> */
  a2 = MEM8(a3 + 11); /* 0126: l8ui a2, a3, 11 */
  if (a2 != a6) goto L_138; /* 0129: bne a2, a6, 138 <pm_parse_beacon+0xfc> */
  a5 = MEM8(a3 + 17); /* 012c: l8ui a5, a3, 17 */
  if (a5 == 0) goto L_1b8; /* 012f: beqz a5, 1b8 <pm_parse_beacon+0x17c> */
  a4 = MEM8(a4 + 2); /* 0132: l8ui a4, a4, 2 */
  if (a4 == 0) goto L_1b8; /* 0135: beqz a4, 1b8 <pm_parse_beacon+0x17c> */
L_138:;
  MEM8(a3 + 11) = a6; /* 0138: s8i a6, a3, 11 */
  MEMW(); /* 013b: memw  */
  if (a2 == a6) goto L_1b8; /* 013e: beq a2, a6, 1b8 <pm_parse_beacon+0x17c> */
  MEMW(); /* 0141: memw  */
  a8 = (uint32_t)&pm_scale_listen_interval; /* 0144: l32r a8, 30 <pm_parse_beacon-0xc> (0 <pm_parse_beacon-0x3c>) */ /* literal: GOT slot for pm_scale_listen_interval */
  pm_scale_listen_interval(a2, a3, a4, a5); /* call via literal slot */ /* 0147: callx8 a8 */
  goto L_1b8; /* 014a: j 1b8 <pm_parse_beacon+0x17c> */
L_14d:;
  a2 = MEM32(a4 + 0); /* 014d: l32i.n a2, a4, 0 */
  MEM32(a3 + 44) = a5; /* 014f: s32i.n a5, a3, 44 */
  if (a2 == 0) goto L_159; /* 0151: beqz.n a2, 159 <pm_parse_beacon+0x11d> */
  MEM8(a3 + 11) = a6; /* 0153: s8i a6, a3, 11 */
  MEMW(); /* 0156: memw  */
L_159:;
  a2 = MEM8(a3 + 11); /* 0159: l8ui a2, a3, 11 */
  if (a2 != 0) goto L_168; /* 015c: bnez a2, 168 <pm_parse_beacon+0x12c> */
  a2 = 0x1; /* 015f: movi a2, 1 */
  MEM8(a3 + 11) = a2; /* 0162: s8i a2, a3, 11 */
  MEMW(); /* 0165: memw  */
L_168:;
  MEMW(); /* 0168: memw  */
  a8 = (uint32_t)&pm_scale_listen_interval; /* 016b: l32r a8, 34 <pm_parse_beacon-0x8> (0 <pm_parse_beacon-0x3c>) */ /* literal: GOT slot for pm_scale_listen_interval */
  pm_scale_listen_interval(a2, a3, a4, a5); /* call via literal slot */ /* 016e: callx8 a8 */
  a2 = (uint32_t)&g_osi_funcs_p; /* 0171: l32r a2, 10 <pm_parse_beacon-0x2c> (0 <pm_parse_beacon-0x3c>) */ /* literal @0x10: g_osi_funcs_p */
  a4 = MEM32(a2 + 0); /* 0174: l32i.n a4, a2, 0 */
  a10 = MEM32(a4 + 404); /* 0176: l32i a10, a4, 0x194 */
  ((int32_t(*)())a10)(a2, a3, a4, a5); /* 0179: callx8 a10 */ /* indirect */
  if (a10 == 0) goto L_194; /* 017c: beqz.n a10, 194 <pm_parse_beacon+0x158> */
  a4 = MEM8(a3 + 14); /* 017e: l8ui a4, a3, 14 */
  if (a4 == 0) goto L_194; /* 0181: beqz.n a4, 194 <pm_parse_beacon+0x158> */
  a4 = 0x51EB851F; /* 0183: l32r a4, 14 <pm_parse_beacon-0x28> (51eb851f <pm_attach+0x51eb849b>) */ @0x14
  a10 = (uint32_t)(((uint64_t)a5 * a4) >> 32) /* muluh: high word */; /* 0186: muluh a10, a5, a4 */
  a10 = a10 >> (5 & 31); /* 0189: srli a10, a10, 5 */
  a2 = MEM32(a2 + 0); /* 018c: l32i.n a2, a2, 0 */
  a2 = MEM32(a2 + 440); /* 018e: l32i a2, a2, 0x1b8 */
  g_osi_funcs_p(a2, a3, a4, a5); /* call via literal slot */ /* 0191: callx8 a2 */
L_194:;
  a11 = 0x1; /* 0194: movi.n a11, 1 */
  a2 = 0x1; /* 0196: movi.n a2, 1 */
  a15 = MEM8(a3 + 11); /* 0198: l8ui a15, a3, 11 */
  a12 = 0x3; /* 019b: movi.n a12, 3 */
  a11 = 0x1000; /* 019d: slli a11, a11, 12 */
  a10 = 0x6; /* 01a0: movi.n a10, 6 */
  a7 = 0x1; /* 01a2: movi.n a7, 1 */
  a14 = MEM32(a3 + 44); /* 01a4: l32i.n a14, a3, 44 */
  a13 = (uint32_t)&lit_rodata_wlog_info_16; /* 01a6: l32r a13, 18 <pm_parse_beacon-0x24> (0 <pm_parse_beacon-0x3c>) */ /* literal @0x18: .rodata_wlog_info.16 */
  MEM8(a3 + 16) = a2; /* 01a9: s8i a2, a3, 16 */
  MEMW(); /* 01ac: memw  */
  MEMW(); /* 01af: memw  */
  a8 = (uint32_t)&wifi_log; /* 01b2: l32r a8, 38 <pm_parse_beacon-0x4> (0 <pm_parse_beacon-0x3c>) */ /* literal: GOT slot for wifi_log */
  wifi_log(a2, a3, a4, a5); /* call via literal slot */ /* 01b5: callx8 a8 */
L_1b8:;
  a2 = a7; /* 01b8: mov.n a2, a7 */
  return (int32_t)a2; /* 01ba: retw.n  */
}

/* pm_on_beacon_rx @ pm.o 00000038 size 190B bind GLOBAL
 * Calls: pm_disable_beacon_monitor_timer[got], pm_coex_schm_overall_period_get[got], pm_beacon_monitor_tbtt_stop[got], pm_parse_beacon[got], pm_update_next_tbtt[got], pm_rx_beacon_process[got], pm_beacon_timestamp_statistic[got], ptr_beacon_offset_funcs[got] | Data refs: g_pm, pm_disable_beacon_monitor_timer, g_osi_funcs_p, pm_coex_schm_overall_period_get, pm_beacon_monitor_tbtt_stop, g_mesh_is_root, g_mesh_init_ps_type, esp_mesh_quick_funcs, pm_parse_beacon, pm_update_next_tbtt, g_pm_cnt, pm_rx_beacon_process, pm_beacon_timestamp_statistic, ptr_beacon_offset_funcs
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 8 call(s), 14 data ref(s)
 * Fidelity: medium - 73 instr, 9 branches, calls resolved */
int32_t pm_on_beacon_rx(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .wifislprxiram.54; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_38:;
  /* 0038: entry a1, 48 */
  a6 = 0x0; /* 003b: movi.n a6, 0 */
  MEM32(a1 + 4) = a6; /* 003d: s32i a6, a1, 4 */
  a5 = (a5 >> 0) & 0xFF; /* 0040: extui a5, a5, 0, 8 */
  MEM32(a1 + 0) = a6; /* 0043: s32i a6, a1, 0 */
  a6 = (uint32_t)&g_pm; /* 0046: l32r a6, 0 <pm_on_beacon_rx-0x38> (0 <pm_on_beacon_rx-0x38>) */ /* literal @0x0: g_pm */
  a10 = a6 | a6; /* 0049: or a10, a6, a6 */
  MEMW(); /* 004c: memw  */
  a8 = (uint32_t)&pm_disable_beacon_monitor_timer; /* 004f: l32r a8, 1c <pm_on_beacon_rx-0x1c> (0 <pm_on_beacon_rx-0x38>) */ /* literal: GOT slot for pm_disable_beacon_monitor_timer */
  pm_disable_beacon_monitor_timer(a2, a3, a4, a5); /* call via literal slot */ /* 0052: callx8 a8 */
  a8 = (uint32_t)&g_osi_funcs_p; /* 0055: l32r a8, 4 <pm_on_beacon_rx-0x34> (0 <pm_on_beacon_rx-0x38>) */ /* literal @0x4: g_osi_funcs_p */
  a8 = MEM32(a8 + 0); /* 0058: l32i a8, a8, 0 */
  a10 = MEM32(a8 + 404); /* 005b: l32i a10, a8, 0x194 */
  ((int32_t(*)())a10)(a2, a3, a4, a5); /* 005e: callx8 a10 */ /* indirect */
  if (a10 == 0) goto L_74; /* 0061: beqz.n a10, 74 <pm_on_beacon_rx+0x3c> */
  a8 = (uint32_t)&pm_coex_schm_overall_period_get; /* 0063: l32r a8, 20 <pm_on_beacon_rx-0x18> (0 <pm_on_beacon_rx-0x38>) */ /* literal: GOT slot for pm_coex_schm_overall_period_get */
  pm_coex_schm_overall_period_get(a2, a3, a4, a5); /* call via literal slot */ /* 0066: callx8 a8 */
  if (a10 == 1) goto L_74; /* 0069: beqi a10, 1, 74 <pm_on_beacon_rx+0x3c> */
  a10 = a6; /* 006c: mov.n a10, a6 */
  a8 = (uint32_t)&pm_beacon_monitor_tbtt_stop; /* 006e: l32r a8, 24 <pm_on_beacon_rx-0x14> (0 <pm_on_beacon_rx-0x38>) */ /* literal: GOT slot for pm_beacon_monitor_tbtt_stop */
  pm_beacon_monitor_tbtt_stop(a2, a3, a4, a5); /* call via literal slot */ /* 0071: callx8 a8 */
L_74:;
  a8 = (uint32_t)&g_mesh_is_root; /* 0074: l32r a8, 8 <pm_on_beacon_rx-0x30> (0 <pm_on_beacon_rx-0x38>) */ /* literal @0x8: g_mesh_is_root */
  MEMW(); /* 0077: memw  */
  a8 = MEM8(a8 + 0); /* 007a: l8ui a8, a8, 0 */
  a8 = (a8 >> 0) & 0xFF; /* 007d: extui a8, a8, 0, 8 */
  if (a8 == 0) goto L_94; /* 0080: beqz.n a8, 94 <pm_on_beacon_rx+0x5c> */
  a8 = (uint32_t)&g_mesh_init_ps_type; /* 0082: l32r a8, c <pm_on_beacon_rx-0x2c> (0 <pm_on_beacon_rx-0x38>) */ /* literal @0xC: g_mesh_init_ps_type */
  a8 = MEM32(a8 + 0); /* 0085: l32i.n a8, a8, 0 */
  if (a8 == 0) goto L_94; /* 0087: beqz.n a8, 94 <pm_on_beacon_rx+0x5c> */
  a8 = (uint32_t)&esp_mesh_quick_funcs; /* 0089: l32r a8, 10 <pm_on_beacon_rx-0x28> (0 <pm_on_beacon_rx-0x38>) */ /* literal @0x10: esp_mesh_quick_funcs */
  a10 = MEM32(a8 + 148); /* 008c: l32i a10, a8, 148 */
  if (a10 == 0) goto L_94; /* 008f: beqz.n a10, 94 <pm_on_beacon_rx+0x5c> */
  ((int32_t(*)())a10)(a2, a3, a4, a5); /* 0091: callx8 a10 */ /* indirect */
L_94:;
  a8 = MEM8(a6 + 13); /* 0094: l8ui a8, a6, 13 */
  if (a8 == 0) goto L_f4; /* 0097: beqz a8, f4 <pm_on_beacon_rx+0xbc> */
  if (a5 != 0) goto L_b8; /* 009a: bnez.n a5, b8 <pm_on_beacon_rx+0x80> */
  a13 = a1 + (4); /* 009c: addi.n a13, a1, 4 */
  a12 = a1; /* 009e: mov.n a12, a1 */
  a11 = a4; /* 00a0: mov.n a11, a4 */
  a10 = a3; /* 00a2: mov.n a10, a3 */
  a8 = (uint32_t)&pm_parse_beacon; /* 00a4: l32r a8, 28 <pm_on_beacon_rx-0x10> (0 <pm_on_beacon_rx-0x38>) */ /* literal: GOT slot for pm_parse_beacon */
  pm_parse_beacon(a2, a3, a4, a5); /* call via literal slot */ /* 00a7: callx8 a8 */
  if (a10 == 0) goto L_b8; /* 00aa: beqz.n a10, b8 <pm_on_beacon_rx+0x80> */
  a12 = MEM32(a1 + 0); /* 00ac: l32i.n a12, a1, 0 */
  a10 = a2; /* 00ae: mov.n a10, a2 */
  a11 = MEM32(a1 + 4); /* 00b0: l32i.n a11, a1, 4 */
  a8 = (uint32_t)&pm_update_next_tbtt; /* 00b2: l32r a8, 2c <pm_on_beacon_rx-0xc> (0 <pm_on_beacon_rx-0x38>) */ /* literal: GOT slot for pm_update_next_tbtt */
  pm_update_next_tbtt(a2, a3, a4, a5); /* call via literal slot */ /* 00b5: callx8 a8 */
L_b8:;
  a11 = a5; /* 00b8: mov.n a11, a5 */
  a8 = MEM16(a6 + 30); /* 00ba: l16ui a8, a6, 30 */
  a8 = a8 + (1); /* 00bd: addi.n a8, a8, 1 */
  a3 = (uint32_t)&g_pm_cnt; /* 00bf: l32r a3, 14 <pm_on_beacon_rx-0x24> (0 <pm_on_beacon_rx-0x38>) */ /* literal @0x14: g_pm_cnt */
  MEM16(a6 + 30) = a8; /* 00c2: s16i a8, a6, 30 */
  MEMW(); /* 00c5: memw  */
  a6 = MEM32(a3 + 4); /* 00c8: l32i.n a6, a3, 4 */
  a6 = a6 + (1); /* 00ca: addi.n a6, a6, 1 */
  a10 = MEM32(a1 + 0); /* 00cc: l32i.n a10, a1, 0 */
  MEM32(a3 + 4) = a6; /* 00ce: s32i a6, a3, 4 */
  MEMW(); /* 00d1: memw  */
  a8 = (uint32_t)&pm_rx_beacon_process; /* 00d4: l32r a8, 30 <pm_on_beacon_rx-0x8> (0 <pm_on_beacon_rx-0x38>) */ /* literal: GOT slot for pm_rx_beacon_process */
  pm_rx_beacon_process(a2, a3, a4, a5); /* call via literal slot */ /* 00d7: callx8 a8 */
  a4 = MEM32(a1 + 4); /* 00da: l32i.n a4, a1, 4 */
  a10 = a4; /* 00dc: mov.n a10, a4 */
  a8 = (uint32_t)&pm_beacon_timestamp_statistic; /* 00de: l32r a8, 34 <pm_on_beacon_rx-0x4> (0 <pm_on_beacon_rx-0x38>) */ /* literal: GOT slot for pm_beacon_timestamp_statistic */
  pm_beacon_timestamp_statistic(a2, a3, a4, a5); /* call via literal slot */ /* 00e1: callx8 a8 */
  a3 = (uint32_t)&ptr_beacon_offset_funcs; /* 00e4: l32r a3, 18 <pm_on_beacon_rx-0x20> (0 <pm_on_beacon_rx-0x38>) */ /* literal @0x18: ptr_beacon_offset_funcs */
  a3 = MEM32(a3 + 0); /* 00e7: l32i.n a3, a3, 0 */
  a3 = MEM32(a3 + 44); /* 00e9: l32i.n a3, a3, 44 */
  if (a3 == 0) goto L_f4; /* 00eb: beqz.n a3, f4 <pm_on_beacon_rx+0xbc> */
  a11 = a2; /* 00ed: mov.n a11, a2 */
  a10 = a4; /* 00ef: mov.n a10, a4 */
  ptr_beacon_offset_funcs(a2, a3, a4, a5); /* call via literal slot */ /* 00f1: callx8 a3 */
L_f4:;
  return (int32_t)a2; /* 00f4: retw.n  */
}

/* pm_on_probe_resp_rx @ pm.o 00000014 size 94B bind GLOBAL
 * Calls: pm_scale_listen_interval, pm_update_next_tbtt, g_osi_funcs_p[got] | Data refs: g_osi_funcs_p, g_pm, pm_scale_listen_interval, pm_update_next_tbtt
 *   MMIO: none
 *   funcdb v3: 2 call(s), 4 ref(s); disasm: 3 call(s), 4 data ref(s)
 * Fidelity: medium - 36 instr, 4 branches, calls resolved */
int32_t pm_on_probe_resp_rx(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pm_on_probe_resp_rx; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_14:;
  /* 0014: entry a1, 48 */
  a6 = (uint32_t)&g_pm; /* 0017: l32r a6, 0 <pm_on_probe_resp_rx-0x14> (0 <pm_on_probe_resp_rx-0x14>) */ /* literal @0x0: g_pm */
  a2 = (a2 >> 0) & 0xFFFF; /* 001a: extui a2, a2, 0, 16 */
  a8 = MEM8(a6 + 13); /* 001d: l8ui a8, a6, 13 */
  if (a8 == 0) goto L_70; /* 0020: beqz a8, 70 <pm_on_probe_resp_rx+0x5c> */
  a8 = a2 << (10 & 31); /* 0023: slli a8, a2, 10 */
  if (a2 != 0) goto L_2d; /* 0026: bnez.n a2, 2d <pm_on_probe_resp_rx+0x19> */
  a8 = 0x19; /* 0028: movi.n a8, 25 */
  a8 = 0x19000; /* 002a: slli a8, a8, 12 */
L_2d:;
  a2 = MEM32(a6 + 44); /* 002d: l32i.n a2, a6, 44 */
  if (a2 == a8) goto L_3d; /* 002f: beq a2, a8, 3d <pm_on_probe_resp_rx+0x29> */
  MEM32(a6 + 44) = a8; /* 0032: s32i.n a8, a6, 44 */
  MEMW(); /* 0034: memw  */
  a8 = (uint32_t)&pm_scale_listen_interval; /* 0037: l32r a8, c <pm_on_probe_resp_rx-0x8> (0 <pm_on_probe_resp_rx-0x14>) */ /* literal: GOT slot for pm_scale_listen_interval */
  pm_scale_listen_interval(a2, a3, a4, a5); /* call via literal slot */ /* 003a: callx8 a8 */
L_3d:;
  a2 = (uint32_t)&g_osi_funcs_p; /* 003d: l32r a2, 4 <pm_on_probe_resp_rx-0x10> (0 <pm_on_probe_resp_rx-0x14>) */ /* literal @0x4: g_osi_funcs_p */
  a8 = MEM32(a2 + 0); /* 0040: l32i.n a8, a2, 0 */
  a10 = MEM32(a8 + 404); /* 0042: l32i a10, a8, 0x194 */
  ((int32_t(*)())a10)(a2, a3, a4, a5); /* 0045: callx8 a10 */ /* indirect */
  if (a10 == 0) goto L_5d; /* 0048: beqz.n a10, 5d <pm_on_probe_resp_rx+0x49> */
  a10 = MEM32(a6 + 44); /* 004a: l32i.n a10, a6, 44 */
  a6 = 0x51EB851F; /* 004c: l32r a6, 8 <pm_on_probe_resp_rx-0xc> (51eb851f <pm_attach+0x51eb849b>) */ @0x8
  a10 = (uint32_t)(((uint64_t)a10 * a6) >> 32) /* muluh: high word */; /* 004f: muluh a10, a10, a6 */
  a10 = a10 >> (5 & 31); /* 0052: srli a10, a10, 5 */
  a2 = MEM32(a2 + 0); /* 0055: l32i.n a2, a2, 0 */
  a2 = MEM32(a2 + 440); /* 0057: l32i a2, a2, 0x1b8 */
  g_osi_funcs_p(a2, a3, a4, a5); /* call via literal slot */ /* 005a: callx8 a2 */
L_5d:;
  a12 = 0x0; /* 005d: movi.n a12, 0 */
  a11 = a1; /* 005f: mov.n a11, a1 */
  a10 = a3; /* 0061: mov.n a10, a3 */
  MEM32(a1 + 0) = a4; /* 0063: s32i.n a4, a1, 0 */
  MEM32(a1 + 4) = a5; /* 0065: s32i.n a5, a1, 4 */
  MEMW(); /* 0067: memw  */
  a8 = (uint32_t)&pm_update_next_tbtt; /* 006a: l32r a8, 10 <pm_on_probe_resp_rx-0x4> (0 <pm_on_probe_resp_rx-0x14>) */ /* literal: GOT slot for pm_update_next_tbtt */
  pm_update_next_tbtt(a2, a3, a4, a5); /* call via literal slot */ /* 006d: callx8 a8 */
L_70:;
  return (int32_t)a2; /* 0070: retw.n  */
}

/* pm_disconnected_start @ pm.o 00000024 size 128B bind GLOBAL
 * Calls: pm_coex_schm_process_restart, pm_disable_disconnected_sleep_delay_timer, pm_on_coex_schm_status_config, pm_update_by_connectionless_status, wifi_gpio_debug | Data refs: g_osi_funcs_p, g_pm, pm_coex_schm_process_restart, pm_disable_disconnected_sleep_delay_timer, pm_on_coex_schm_status_config, pm_update_by_connectionless_status, wifi_gpio_debug
 *   MMIO: none
 *   funcdb v3: 5 call(s), 7 ref(s); disasm: 7 call(s), 7 data ref(s)
 * Fidelity: medium - 46 instr, 2 branches, calls resolved */
int32_t pm_disconnected_start(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pm_disconnected_start; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_24:;
  /* 0024: entry a1, 32 */
  a2 = (uint32_t)&g_pm; /* 0027: l32r a2, 0 <pm_disconnected_start-0x24> (0 <pm_disconnected_start-0x24>) */ /* literal @0x0: g_pm */
  a10 = 0x0; /* 002a: movi a10, 0 */
  MEM32(a2 + 288) = a10; /* 002d: s32i a10, a2, 0x120 */
  MEMW(); /* 0030: memw  */
  a8 = (uint32_t)&pm_on_coex_schm_status_config; /* 0033: l32r a8, 8 <pm_disconnected_start-0x1c> (0 <pm_disconnected_start-0x24>) */ /* literal: GOT slot for pm_on_coex_schm_status_config */
  pm_on_coex_schm_status_config(a2, a3, a4, a5); /* call via literal slot */ /* 0036: callx8 a8 */
  a3 = (uint32_t)&g_osi_funcs_p; /* 0039: l32r a3, 4 <pm_disconnected_start-0x20> (0 <pm_disconnected_start-0x24>) */ /* literal @0x4: g_osi_funcs_p */
  a3 = MEM32(a3 + 0); /* 003c: l32i.n a3, a3, 0 */
  a10 = MEM32(a3 + 404); /* 003e: l32i a10, a3, 0x194 */
  ((int32_t(*)())a10)(a2, a3, a4, a5); /* 0041: callx8 a10 */ /* indirect */
  if (a10 == 0) goto L_4c; /* 0044: beqz.n a10, 4c <pm_disconnected_start+0x28> */
  a8 = (uint32_t)&pm_coex_schm_process_restart; /* 0046: l32r a8, c <pm_disconnected_start-0x18> (0 <pm_disconnected_start-0x24>) */ /* literal: GOT slot for pm_coex_schm_process_restart */
  pm_coex_schm_process_restart(a2, a3, a4, a5); /* call via literal slot */ /* 0049: callx8 a8 */
L_4c:;
  a3 = MEM32(a2 + 288); /* 004c: l32i a3, a2, 0x120 */
  a3 = a3 + (1); /* 004f: addi.n a3, a3, 1 */
  MEM32(a2 + 288) = a3; /* 0051: s32i a3, a2, 0x120 */
  a3 = a2 + ((0x100) << 8); /* 0054: addmi a3, a2, 0x100 */
  a8 = MEM8(a3 + 29); /* 0057: l8ui a8, a3, 29 */
  if (a8 == 0) goto L_a2; /* 005a: beqz a8, a2 <pm_disconnected_start+0x7e> */
  MEMW(); /* 005d: memw  */
  a8 = (uint32_t)&pm_disable_disconnected_sleep_delay_timer; /* 0060: l32r a8, 10 <pm_disconnected_start-0x14> (0 <pm_disconnected_start-0x24>) */ /* literal: GOT slot for pm_disable_disconnected_sleep_delay_timer */
  pm_disable_disconnected_sleep_delay_timer(a2, a3, a4, a5); /* call via literal slot */ /* 0063: callx8 a8 */
  a8 = 0x1; /* 0066: movi.n a8, 1 */
  MEM16(a2 + 14) = a8; /* 0068: s16i a8, a2, 14 */
  a2 = 0x0; /* 006b: movi.n a2, 0 */
  a11 = 0x1; /* 006d: movi.n a11, 1 */
  a10 = 0x3; /* 006f: movi.n a10, 3 */
  MEM8(a3 + 136) = a2; /* 0071: s8i a2, a3, 136 */
  a2 = 0x2; /* 0074: movi a2, 2 */
  MEM8(a3 + 29) = a2; /* 0077: s8i a2, a3, 29 */
  MEMW(); /* 007a: memw  */
  MEMW(); /* 007d: memw  */
  a8 = (uint32_t)&wifi_gpio_debug; /* 0080: l32r a8, 14 <pm_disconnected_start-0x10> (0 <pm_disconnected_start-0x24>) */ /* literal: GOT slot for wifi_gpio_debug */
  wifi_gpio_debug(a2, a3, a4, a5); /* call via literal slot */ /* 0083: callx8 a8 */
  a11 = 0x1; /* 0086: movi a11, 1 */
  a10 = 0x4; /* 0089: movi a10, 4 */
  a8 = (uint32_t)&wifi_gpio_debug; /* 008c: l32r a8, 18 <pm_disconnected_start-0xc> (0 <pm_disconnected_start-0x24>) */ /* literal: GOT slot for wifi_gpio_debug */
  wifi_gpio_debug(a2, a3, a4, a5); /* call via literal slot */ /* 008f: callx8 a8 */
  a11 = 0x0; /* 0092: movi.n a11, 0 */
  a10 = 0x5; /* 0094: movi.n a10, 5 */
  a8 = (uint32_t)&wifi_gpio_debug; /* 0096: l32r a8, 1c <pm_disconnected_start-0x8> (0 <pm_disconnected_start-0x24>) */ /* literal: GOT slot for wifi_gpio_debug */
  wifi_gpio_debug(a2, a3, a4, a5); /* call via literal slot */ /* 0099: callx8 a8 */
  a8 = (uint32_t)&pm_update_by_connectionless_status; /* 009c: l32r a8, 20 <pm_disconnected_start-0x4> (0 <pm_disconnected_start-0x24>) */ /* literal: GOT slot for pm_update_by_connectionless_status */
  pm_update_by_connectionless_status(a2, a3, a4, a5); /* call via literal slot */ /* 009f: callx8 a8 */
L_a2:;
  return (int32_t)a2; /* 00a2: retw.n  */
}

/* pm_disconnected_stop @ pm.o 00000020 size 96B bind GLOBAL
 * Calls: pm_disable_disconnected_sleep_delay_timer, pm_update_by_connectionless_status, wifi_gpio_debug, g_osi_funcs_p[got] | Data refs: g_osi_funcs_p, g_pm, pm_disable_disconnected_sleep_delay_timer, pm_update_by_connectionless_status, wifi_gpio_debug
 *   MMIO: none
 *   funcdb v3: 3 call(s), 5 ref(s); disasm: 6 call(s), 5 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t pm_disconnected_stop(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pm_disconnected_stop; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_20:;
  /* 0020: entry a1, 32 */
  a8 = (uint32_t)&g_osi_funcs_p; /* 0023: l32r a8, 8 <pm_disconnected_stop-0x18> (0 <pm_disconnected_stop-0x20>) */ /* literal @0x8: g_osi_funcs_p */
  a3 = 0x0; /* 0026: movi a3, 0 */
  a8 = MEM32(a8 + 0); /* 0029: l32i a8, a8, 0 */
  a2 = (uint32_t)&g_pm; /* 002c: l32r a2, 0 <pm_disconnected_stop-0x20> (0 <pm_disconnected_stop-0x20>) */ /* literal @0x0: g_pm */
  a2 = a2 + ((0x100) << 8); /* 002f: addmi a2, a2, 0x100 */
  a8 = MEM32(a8 + 236); /* 0032: l32i a8, a8, 236 */
  a10 = (uint32_t)&g_pm; /* 0035: l32r a10, 4 <pm_disconnected_stop-0x1c> (0 <pm_disconnected_stop-0x20>) */ /* literal @0x4: g_pm */
  MEM32(a2 + 32) = a3; /* 0038: s32i a3, a2, 32 */
  MEMW(); /* 003b: memw  */
  g_osi_funcs_p(a2, a3, a4, a5); /* call via literal slot */ /* 003e: callx8 a8 */
  a8 = MEM8(a2 + 29); /* 0041: l8ui a8, a2, 29 */
  if (a8 == a3) goto L_7e; /* 0044: beq a8, a3, 7e <pm_disconnected_stop+0x5e> */
  a8 = (uint32_t)&pm_disable_disconnected_sleep_delay_timer; /* 0047: l32r a8, c <pm_disconnected_stop-0x14> (0 <pm_disconnected_stop-0x20>) */ /* literal: GOT slot for pm_disable_disconnected_sleep_delay_timer */
  pm_disable_disconnected_sleep_delay_timer(a2, a3, a4, a5); /* call via literal slot */ /* 004a: callx8 a8 */
  a8 = 0x1; /* 004d: movi.n a8, 1 */
  a11 = a3 | a3; /* 004f: or a11, a3, a3 */
  a10 = 0x3; /* 0052: movi a10, 3 */
  MEM8(a2 + 29) = a8; /* 0055: s8i a8, a2, 29 */
  MEMW(); /* 0058: memw  */
  MEMW(); /* 005b: memw  */
  a8 = (uint32_t)&wifi_gpio_debug; /* 005e: l32r a8, 10 <pm_disconnected_stop-0x10> (0 <pm_disconnected_stop-0x20>) */ /* literal: GOT slot for wifi_gpio_debug */
  wifi_gpio_debug(a2, a3, a4, a5); /* call via literal slot */ /* 0061: callx8 a8 */
  a11 = 0x1; /* 0064: movi.n a11, 1 */
  a10 = 0x4; /* 0066: movi.n a10, 4 */
  a8 = (uint32_t)&wifi_gpio_debug; /* 0068: l32r a8, 14 <pm_disconnected_stop-0xc> (0 <pm_disconnected_stop-0x20>) */ /* literal: GOT slot for wifi_gpio_debug */
  wifi_gpio_debug(a2, a3, a4, a5); /* call via literal slot */ /* 006b: callx8 a8 */
  a11 = 0x1; /* 006e: movi.n a11, 1 */
  a10 = 0x5; /* 0070: movi.n a10, 5 */
  a8 = (uint32_t)&wifi_gpio_debug; /* 0072: l32r a8, 18 <pm_disconnected_stop-0x8> (0 <pm_disconnected_stop-0x20>) */ /* literal: GOT slot for wifi_gpio_debug */
  wifi_gpio_debug(a2, a3, a4, a5); /* call via literal slot */ /* 0075: callx8 a8 */
  a8 = (uint32_t)&pm_update_by_connectionless_status; /* 0078: l32r a8, 1c <pm_disconnected_stop-0x4> (0 <pm_disconnected_stop-0x20>) */ /* literal: GOT slot for pm_update_by_connectionless_status */
  pm_update_by_connectionless_status(a2, a3, a4, a5); /* call via literal slot */ /* 007b: callx8 a8 */
L_7e:;
  return (int32_t)a2; /* 007e: retw.n  */
}

/* pm_tbtt_quick_wake_configure @ pm.o 00000008 size 38B bind GLOBAL
 * Calls: g_pm[got] | Data refs: g_pm, ptr_beacon_offset_funcs
 *   MMIO: none
 *   funcdb v3: 0 call(s), 2 ref(s); disasm: 1 call(s), 2 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t pm_tbtt_quick_wake_configure(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pm_tbtt_quick_wake_configure; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_8:;
  /* 0008: entry a1, 32 */
  a8 = (uint32_t)&g_pm; /* 000b: l32r a8, 0 <pm_tbtt_quick_wake_configure-0x8> (0 <pm_tbtt_quick_wake_configure-0x8>) */ /* literal @0x0: g_pm */
  a2 = (a2 >> 0) & 0xFF; /* 000e: extui a2, a2, 0, 8 */
  a8 = a8 + ((0x100) << 8); /* 0011: addmi a8, a8, 0x100 */
  MEM8(a8 + 212) = a2; /* 0014: s8i a2, a8, 212 */
  MEMW(); /* 0017: memw  */
  if (a2 == 0) goto L_2c; /* 001a: beqz.n a2, 2c <pm_tbtt_quick_wake_configure+0x24> */
  a2 = (uint32_t)&ptr_beacon_offset_funcs; /* 001c: l32r a2, 4 <pm_tbtt_quick_wake_configure-0x4> (0 <pm_tbtt_quick_wake_configure-0x8>) */ /* literal @0x4: ptr_beacon_offset_funcs */
  a2 = MEM32(a2 + 0); /* 001f: l32i.n a2, a2, 0 */
  a8 = MEM32(a2 + 8); /* 0021: l32i.n a8, a2, 8 */
  if (a8 == 0) goto L_2c; /* 0023: beqz a8, 2c <pm_tbtt_quick_wake_configure+0x24> */
  MEMW(); /* 0026: memw  */
  ((int32_t(*)())a8)(a2, a3, a4, a5); /* 0029: callx8 a8 */ /* indirect */
L_2c:;
  return (int32_t)a2; /* 002c: retw.n  */
}

/* pm_start @ pm.o 0000004c size 466B bind GLOBAL
 * Calls: dbg_lmac_ps_statis_reset, memcpy, pm_beacon_monitor_init, pm_enable_active_timer, pm_on_coex_schm_status_config, pm_scale_listen_interval, pm_update_by_connectionless_status, pm_update_next_tbtt, wifi_gpio_debug, wifi_log, ptr_beacon_offset_funcs[got] | Data refs: .bss.g_offchan_ready_cb, .bss.g_offchan_ready_ctx, .rodata_wlog_info.57, dbg_lmac_ps_statis_reset, g_osi_funcs_p, g_pm, memcpy, pm_beacon_monitor_init, pm_enable_active_timer, pm_on_coex_schm_status_config, pm_scale_listen_interval, pm_update_by_connectionless_status, pm_update_next_tbtt, ptr_beacon_offset_funcs, wifi_gpio_debug, wifi_log
 *   MMIO: none
 *   funcdb v3: 10 call(s), 16 ref(s); disasm: 13 call(s), 16 data ref(s)
 * Fidelity: low - 171 instr, 5 branches, 7 indirect; call-sequence + MMIO skeleton */
int32_t pm_start(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pm_start; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4c:;
  /* 004c: entry a1, 64 */
  a7 = (uint32_t)&g_pm; /* 004f: l32r a7, 0 <pm_start-0x4c> (0 <pm_start-0x4c>) */ /* literal @0x0: g_pm */
  a2 = (a2 >> 0) & 0xFF; /* 0052: extui a2, a2, 0, 8 */
  a3 = (a3 >> 0) & 0xFFFF; /* 0055: extui a3, a3, 0, 16 */
  a5 = (a5 >> 0) & 0xFFFF; /* 0058: extui a5, a5, 0, 16 */
  a8 = MEM8(a7 + 13); /* 005b: l8ui a8, a7, 13 */
  if (a8 != 0) goto L_21c; /* 005e: bnez a8, 21c <pm_start+0x1d0> */
  a8 = (uint32_t)&ptr_beacon_offset_funcs; /* 0061: l32r a8, 4 <pm_start-0x48> (0 <pm_start-0x4c>) */ /* literal @0x4: ptr_beacon_offset_funcs */
  a8 = MEM32(a8 + 0); /* 0064: l32i.n a8, a8, 0 */
  a8 = MEM32(a8 + 48); /* 0066: l32i.n a8, a8, 48 */
  if (a8 == 0) goto L_6d; /* 0068: beqz.n a8, 6d <pm_start+0x21> */
  ptr_beacon_offset_funcs(a2, a3, a4, a5); /* call via literal slot */ /* 006a: callx8 a8 */
L_6d:;
  a11 = 0x1; /* 006d: movi.n a11, 1 */
  a14 = MEM32(a7 + 36); /* 006f: l32i.n a14, a7, 36 */
  a12 = 0x3; /* 0071: movi.n a12, 3 */
  a11 = 0x1000; /* 0073: slli a11, a11, 12 */
  a10 = 0x6; /* 0076: movi.n a10, 6 */
  a13 = (uint32_t)&lit_rodata_wlog_info_57; /* 0078: l32r a13, 8 <pm_start-0x44> (0 <pm_start-0x4c>) */ /* literal @0x8: .rodata_wlog_info.57 */
  a8 = (uint32_t)&wifi_log; /* 007b: l32r a8, 1c <pm_start-0x30> (0 <pm_start-0x4c>) */ /* literal: GOT slot for wifi_log */
  wifi_log(a2, a3, a4, a5); /* call via literal slot */ /* 007e: callx8 a8 */
  a8 = 0x1; /* 0081: movi.n a8, 1 */
  a12 = 0x6; /* 0083: movi.n a12, 6 */
  MEM16(a7 + 14) = a8; /* 0085: s16i a8, a7, 14 */
  a8 = 0x0; /* 0088: movi.n a8, 0 */
  a11 = a4; /* 008a: mov.n a11, a4 */
  a10 = a7 + (3); /* 008c: addi.n a10, a7, 3 */
  MEM16(a7 + 26) = a3; /* 008e: s16i a3, a7, 26 */
  a3 = a7 + ((0x100) << 8); /* 0091: addmi a3, a7, 0x100 */
  MEM8(a3 + 192) = a8; /* 0094: s8i a8, a3, 192 */
  MEM8(a7 + 2) = a2; /* 0097: s8i a2, a7, 2 */
  MEMW(); /* 009a: memw  */
  a2 = 0x0; /* 009d: movi.n a2, 0 */
  MEM32(a1 + 16) = a8; /* 009f: s32i.n a8, a1, 16 */
  MEMW(); /* 00a1: memw  */
  a8 = (uint32_t)&memcpy; /* 00a4: l32r a8, 20 <pm_start-0x2c> (0 <pm_start-0x4c>) */ /* literal: GOT slot for memcpy */
  memcpy(a2, a3, a4, a5); /* call via literal slot */ /* 00a7: callx8 a8 */
  a8 = MEM32(a1 + 16); /* 00aa: l32i.n a8, a1, 16 */
  MEM32(a7 + 60) = a2; /* 00ac: s32i.n a2, a7, 60 */
  MEM32(a7 + 64) = a2; /* 00ae: s32i a2, a7, 64 */
  MEM32(a7 + 136) = a2; /* 00b1: s32i a2, a7, 136 */
  MEM32(a7 + 140) = a2; /* 00b4: s32i a2, a7, 140 */
  a2 = (uint32_t)&g_osi_funcs_p; /* 00b7: l32r a2, c <pm_start-0x40> (0 <pm_start-0x4c>) */ /* literal @0xC: g_osi_funcs_p */
  a4 = MEM32(a2 + 0); /* 00ba: l32i a4, a2, 0 */
  a10 = MEM32(a4 + 272); /* 00bd: l32i a10, a4, 0x110 */
  MEM8(a7 + 19) = a8; /* 00c0: s8i a8, a7, 19 */
  MEM8(a7 + 20) = a8; /* 00c3: s8i a8, a7, 20 */
  MEM8(a3 + 232) = a8; /* 00c6: s8i a8, a3, 232 */
  MEM8(a7 + 9) = a8; /* 00c9: s8i a8, a7, 9 */
  MEM8(a7 + 10) = a8; /* 00cc: s8i a8, a7, 10 */
  MEMW(); /* 00cf: memw  */
  MEMW(); /* 00d2: memw  */
  ((int32_t(*)())a10)(a2, a3, a4, a5); /* 00d5: callx8 a10 */ /* indirect */
  a4 = MEM32(a2 + 0); /* 00d8: l32i.n a4, a2, 0 */
  MEM32(a7 + 128) = a10; /* 00da: s32i a10, a7, 128 */
  a10 = MEM32(a4 + 272); /* 00dd: l32i a10, a4, 0x110 */
  MEM32(a7 + 132) = a11; /* 00e0: s32i a11, a7, 132 */
  MEMW(); /* 00e3: memw  */
  ((int32_t(*)())a10)(a2, a3, a4, a5); /* 00e6: callx8 a10 */ /* indirect */
  a4 = MEM32(a2 + 0); /* 00e9: l32i.n a4, a2, 0 */
  MEM32(a7 + 112) = a10; /* 00eb: s32i a10, a7, 112 */
  a10 = MEM32(a4 + 272); /* 00ee: l32i a10, a4, 0x110 */
  MEM32(a7 + 116) = a11; /* 00f1: s32i a11, a7, 116 */
  MEMW(); /* 00f4: memw  */
  ((int32_t(*)())a10)(a2, a3, a4, a5); /* 00f7: callx8 a10 */ /* indirect */
  a4 = MEM32(a2 + 0); /* 00fa: l32i.n a4, a2, 0 */
  MEM32(a7 + 120) = a10; /* 00fc: s32i a10, a7, 120 */
  a10 = MEM32(a4 + 272); /* 00ff: l32i a10, a4, 0x110 */
  a4 = a5 << (10 & 31); /* 0102: slli a4, a5, 10 */
  MEM32(a7 + 124) = a11; /* 0105: s32i a11, a7, 124 */
  MEMW(); /* 0108: memw  */
  ((int32_t(*)())a10)(a2, a3, a4, a5); /* 010b: callx8 a10 */ /* indirect */
  MEM32(a7 + 72) = a10; /* 010e: s32i a10, a7, 72 */
  MEM32(a7 + 76) = a11; /* 0111: s32i a11, a7, 76 */
  if (a5 != 0) goto L_11c; /* 0114: bnez.n a5, 11c <pm_start+0xd0> */
  a4 = 0x19; /* 0116: movi a4, 25 */
  a4 = 0x19000; /* 0119: slli a4, a4, 12 */
L_11c:;
  MEM32(a7 + 44) = a4; /* 011c: s32i.n a4, a7, 44 */
  a4 = MEM32(a2 + 0); /* 011e: l32i.n a4, a2, 0 */
  a10 = MEM32(a4 + 404); /* 0120: l32i a10, a4, 0x194 */
  MEMW(); /* 0123: memw  */
  ((int32_t(*)())a10)(a2, a3, a4, a5); /* 0126: callx8 a10 */ /* indirect */
  if (a10 == 0) goto L_13e; /* 0129: beqz.n a10, 13e <pm_start+0xf2> */
  a4 = 0x51EB851F; /* 012b: l32r a4, 10 <pm_start-0x3c> (51eb851f <pm_attach+0x51eb849b>) */ @0x10
  a10 = MEM32(a7 + 44); /* 012e: l32i.n a10, a7, 44 */
  a10 = (uint32_t)(((uint64_t)a10 * a4) >> 32) /* muluh: high word */; /* 0130: muluh a10, a10, a4 */
  a10 = a10 >> (5 & 31); /* 0133: srli a10, a10, 5 */
  a4 = MEM32(a2 + 0); /* 0136: l32i.n a4, a2, 0 */
  a4 = MEM32(a4 + 440); /* 0138: l32i a4, a4, 0x1b8 */
  ((int32_t(*)())a4)(a2, a3, a4, a5); /* 013b: callx8 a4 */ /* indirect */
L_13e:;
  a5 = 0x1; /* 013e: movi.n a5, 1 */
  a4 = 0x0; /* 0140: movi a4, 0 */
  MEM8(a7 + 11) = a5; /* 0143: s8i a5, a7, 11 */
  MEMW(); /* 0146: memw  */
  MEMW(); /* 0149: memw  */
  a8 = (uint32_t)&pm_scale_listen_interval; /* 014c: l32r a8, 24 <pm_start-0x28> (0 <pm_start-0x4c>) */ /* literal: GOT slot for pm_scale_listen_interval */
  pm_scale_listen_interval(a2, a3, a4, a5); /* call via literal slot */ /* 014f: callx8 a8 */
  a13 = 0x1; /* 0152: movi.n a13, 1 */
  a2 = MEM32(a2 + 0); /* 0154: l32i.n a2, a2, 0 */
  MEM16(a7 + 24) = a13; /* 0156: s16i a13, a7, 24 */
  MEMW(); /* 0159: memw  */
  a10 = MEM32(a2 + 404); /* 015c: l32i a10, a2, 0x194 */
  MEM8(a3 + 28) = a4; /* 015f: s8i a4, a3, 28 */
  MEMW(); /* 0162: memw  */
  MEM32(a1 + 16) = a13; /* 0165: s32i.n a13, a1, 16 */
  MEMW(); /* 0167: memw  */
  ((int32_t(*)())a10)(a2, a3, a4, a5); /* 016a: callx8 a10 */ /* indirect */
  a8 = 0x0; /* 016d: movi.n a8, 0 */
  a2 = 0x0; /* 016f: mov.n a2, a8 */
  MEM8(a3 + 200) = a4; /* 0171: s8i a4, a3, 200 */
  a4 = a7 + ((0x200) << 8); /* 0174: addmi a4, a7, 0x200 */
  MEM8(a7 + 12) = a10; /* 0177: s8i a10, a7, 12 */
  MEM32(a7 + 80) = a8; /* 017a: s32i a8, a7, 80 */
  MEM32(a7 + 84) = a8; /* 017d: s32i a8, a7, 84 */
  MEM32(a7 + 464) = a8; /* 0180: s32i a8, a7, 0x1d0 */
  MEM8(a4 + 28) = a8; /* 0183: s8i a8, a4, 28 */
  MEMW(); /* 0186: memw  */
  MEMW(); /* 0189: memw  */
  a8 = (uint32_t)&dbg_lmac_ps_statis_reset; /* 018c: l32r a8, 28 <pm_start-0x24> (0 <pm_start-0x4c>) */ /* literal: GOT slot for dbg_lmac_ps_statis_reset */
  dbg_lmac_ps_statis_reset(a2, a3, a4, a5); /* call via literal slot */ /* 018f: callx8 a8 */
  a12 = a2; /* 0192: mov.n a12, a2 */
  a11 = a1; /* 0194: mov.n a11, a1 */
  a10 = a6; /* 0196: mov.n a10, a6 */
  a8 = MEM32(a1 + 64); /* 0198: l32i a8, a1, 64 */
  a9 = MEM32(a1 + 68); /* 019b: l32i a9, a1, 68 */
  MEM32(a1 + 0) = a8; /* 019e: s32i a8, a1, 0 */
  MEM32(a1 + 4) = a9; /* 01a1: s32i a9, a1, 4 */
  MEMW(); /* 01a4: memw  */
  a8 = (uint32_t)&pm_update_next_tbtt; /* 01a7: l32r a8, 2c <pm_start-0x20> (0 <pm_start-0x4c>) */ /* literal: GOT slot for pm_update_next_tbtt */
  pm_update_next_tbtt(a2, a3, a4, a5); /* call via literal slot */ /* 01aa: callx8 a8 */
  a8 = (uint32_t)&pm_beacon_monitor_init; /* 01ad: l32r a8, 30 <pm_start-0x1c> (0 <pm_start-0x4c>) */ /* literal: GOT slot for pm_beacon_monitor_init */
  pm_beacon_monitor_init(a2, a3, a4, a5); /* call via literal slot */ /* 01b0: callx8 a8 */
  a8 = (uint32_t)&pm_enable_active_timer; /* 01b3: l32r a8, 34 <pm_start-0x18> (0 <pm_start-0x4c>) */ /* literal: GOT slot for pm_enable_active_timer */
  pm_enable_active_timer(a2, a3, a4, a5); /* call via literal slot */ /* 01b6: callx8 a8 */
  a10 = 0x4; /* 01b9: movi a10, 4 */
  a8 = (uint32_t)&pm_on_coex_schm_status_config; /* 01bc: l32r a8, 38 <pm_start-0x14> (0 <pm_start-0x4c>) */ /* literal: GOT slot for pm_on_coex_schm_status_config */
  pm_on_coex_schm_status_config(a2, a3, a4, a5); /* call via literal slot */ /* 01bf: callx8 a8 */
  a13 = MEM32(a1 + 16); /* 01c2: l32i.n a13, a1, 16 */
  a2 = MEM8(a3 + 29); /* 01c4: l8ui a2, a3, 29 */
  MEM8(a3 + 201) = a13; /* 01c7: s8i a13, a3, 201 */
  MEMW(); /* 01ca: memw  */
  if (a2 == 0) goto L_1d5; /* 01cd: beqz.n a2, 1d5 <pm_start+0x189> */
  MEM8(a3 + 29) = a5; /* 01cf: s8i a5, a3, 29 */
  MEMW(); /* 01d2: memw  */
L_1d5:;
  a11 = 0x1; /* 01d5: movi.n a11, 1 */
  a10 = 0x3; /* 01d7: movi.n a10, 3 */
  MEMW(); /* 01d9: memw  */
  a8 = (uint32_t)&wifi_gpio_debug; /* 01dc: l32r a8, 3c <pm_start-0x10> (0 <pm_start-0x4c>) */ /* literal: GOT slot for wifi_gpio_debug */
  wifi_gpio_debug(a2, a3, a4, a5); /* call via literal slot */ /* 01df: callx8 a8 */
  a11 = 0x1; /* 01e2: movi.n a11, 1 */
  a10 = 0x4; /* 01e4: movi.n a10, 4 */
  a8 = (uint32_t)&wifi_gpio_debug; /* 01e6: l32r a8, 40 <pm_start-0xc> (0 <pm_start-0x4c>) */ /* literal: GOT slot for wifi_gpio_debug */
  wifi_gpio_debug(a2, a3, a4, a5); /* call via literal slot */ /* 01e9: callx8 a8 */
  a11 = 0x0; /* 01ec: movi.n a11, 0 */
  a10 = 0x5; /* 01ee: movi.n a10, 5 */
  a8 = (uint32_t)&wifi_gpio_debug; /* 01f0: l32r a8, 44 <pm_start-0x8> (0 <pm_start-0x4c>) */ /* literal: GOT slot for wifi_gpio_debug */
  wifi_gpio_debug(a2, a3, a4, a5); /* call via literal slot */ /* 01f3: callx8 a8 */
  a2 = 0x1; /* 01f6: movi.n a2, 1 */
  a3 = (uint32_t)&bss_g_offchan_ready_cb; /* 01f8: l32r a3, 14 <pm_start-0x38> (0 <pm_start-0x4c>) */ /* literal @0x14: .bss.g_offchan_ready_cb */
  MEM8(a7 + 13) = a2; /* 01fb: s8i a2, a7, 13 */
  MEMW(); /* 01fe: memw  */
  a2 = 0x0; /* 0201: movi.n a2, 0 */
  MEM32(a3 + 0) = a2; /* 0203: s32i.n a2, a3, 0 */
  a3 = (uint32_t)&bss_g_offchan_ready_ctx; /* 0205: l32r a3, 18 <pm_start-0x34> (0 <pm_start-0x4c>) */ /* literal @0x18: .bss.g_offchan_ready_ctx */
  MEM8(a4 + 30) = a2; /* 0208: s8i a2, a4, 30 */
  MEM32(a3 + 0) = a2; /* 020b: s32i.n a2, a3, 0 */
  MEM8(a4 + 64) = a2; /* 020d: s8i a2, a4, 64 */
  MEMW(); /* 0210: memw  */
  MEMW(); /* 0213: memw  */
  a8 = (uint32_t)&pm_update_by_connectionless_status; /* 0216: l32r a8, 48 <pm_start-0x4> (0 <pm_start-0x4c>) */ /* literal: GOT slot for pm_update_by_connectionless_status */
  pm_update_by_connectionless_status(a2, a3, a4, a5); /* call via literal slot */ /* 0219: callx8 a8 */
L_21c:;
  return (int32_t)a2; /* 021c: retw.n  */
}

/* pm_stop @ pm.o 00000080 size 514B bind GLOBAL
 * Calls: __divsf3, __extendsfdf2, __floatundisf, esp_mesh_get_running_active_duty_cycle, ieee80211_hostapd_beacon_txcb, pm_coex_pwr_update, pm_coex_schm_process_restart, pm_disable_sleep_delay_timer, pm_dream, pm_enable_disconnected_sleep_delay_timer, pm_on_coex_schm_status_config, pm_set_bss_max_idle, pm_update_by_connectionless_status, pm_wake_done, ppProcessWaitingQueue, wifi_log, .text.hal_pm_unblock_txq[got], .text.pm_disable_active_timer[got], .text.pm_set_state[got], g_pm[got], g_pm[got], ptr_beacon_offset_funcs[got], g_pm[got] | Data refs: .rodata_wlog_info.58, .rodata_wlog_info.59, __divsf3, __extendsfdf2, __floatundisf, esp_mesh_get_running_active_duty_cycle, g_mesh_init_ps_type, g_mesh_is_root, g_mesh_is_started, g_osi_funcs_p, g_pm, ieee80211_hostapd_beacon_txcb, pm_coex_pwr_update, pm_coex_schm_process_restart, pm_disable_sleep_delay_timer, pm_dream, pm_enable_disconnected_sleep_delay_timer, pm_on_coex_schm_status_config, pm_set_bss_max_idle, pm_update_by_connectionless_status, pm_wake_done, ppProcessWaitingQueue, ptr_beacon_offset_funcs, wifi_log, .text.hal_pm_unblock_txq, .text.pm_disable_active_timer, .text.pm_set_state
 *   MMIO: none
 *   funcdb v3: 16 call(s), 24 ref(s); disasm: 25 call(s), 27 data ref(s)
 * Fidelity: low - 186 instr, 12 branches, 2 indirect; call-sequence + MMIO skeleton */
int32_t pm_stop(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pm_stop; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_80:;
  /* 0080: entry a1, 80 */
  a2 = (uint32_t)&g_pm; /* 0083: l32r a2, 0 <pm_stop-0x80> (0 <pm_stop-0x80>) */ /* literal @0x0: g_pm */
  a3 = MEM8(a2 + 13); /* 0086: l8ui a3, a2, 13 */
  if (a3 == 0) goto L_280; /* 0089: beqz a3, 280 <pm_stop+0x200> */
  a8 = (uint32_t)&hal_pm_unblock_txq; /* 008c: l32r a8, 2c <pm_stop-0x54> (8 <pm_stop-0x78>) */ /* literal: GOT slot for .text.hal_pm_unblock_txq */
  hal_pm_unblock_txq(a2, a3, a4, a5); /* call via literal slot */ /* 008f: callx8 a8 */
  a8 = (uint32_t)&pm_disable_sleep_delay_timer; /* 0092: l32r a8, 30 <pm_stop-0x50> (0 <pm_stop-0x80>) */ /* literal: GOT slot for pm_disable_sleep_delay_timer */
  pm_disable_sleep_delay_timer(a2, a3, a4, a5); /* call via literal slot */ /* 0095: callx8 a8 */
  a8 = (uint32_t)&pm_disable_active_timer; /* 0098: l32r a8, 34 <pm_stop-0x4c> (8 <pm_stop-0x78>) */ /* literal: GOT slot for .text.pm_disable_active_timer */
  pm_disable_active_timer(a2, a3, a4, a5); /* call via literal slot */ /* 009b: callx8 a8 */
  a5 = (uint32_t)&g_osi_funcs_p; /* 009e: l32r a5, 8 <pm_stop-0x78> (0 <pm_stop-0x80>) */ /* literal @0x8: g_osi_funcs_p */
  a3 = MEM32(a5 + 0); /* 00a1: l32i a3, a5, 0 */
  a10 = (uint32_t)&g_pm; /* 00a4: l32r a10, 4 <pm_stop-0x7c> (0 <pm_stop-0x80>) */ /* literal @0x4: g_pm */
  a3 = MEM32(a3 + 236); /* 00a7: l32i a3, a3, 236 */
  ((int32_t(*)())a3)(a2, a3, a4, a5); /* 00aa: callx8 a3 */ /* indirect */
  a3 = MEM32(a5 + 0); /* 00ad: l32i.n a3, a5, 0 */
  a10 = (uint32_t)&g_pm; /* 00af: l32r a10, c <pm_stop-0x74> (0 <pm_stop-0x80>) */ /* literal @0xC: g_pm */
  a3 = MEM32(a3 + 236); /* 00b2: l32i a3, a3, 236 */
  ((int32_t(*)())a3)(a2, a3, a4, a5); /* 00b5: callx8 a3 */ /* indirect */
  a3 = 0x0; /* 00b8: movi.n a3, 0 */
  MEM16(a2 + 26) = a3; /* 00ba: s16i a3, a2, 26 */
  MEMW(); /* 00bd: memw  */
  a3 = MEM8(a2 + 1); /* 00c0: l8ui a3, a2, 1 */
  if (a3 == 0) goto L_dc; /* 00c3: beqz.n a3, dc <pm_stop+0x5c> */
  MEMW(); /* 00c5: memw  */
  a8 = (uint32_t)&pm_dream; /* 00c8: l32r a8, 38 <pm_stop-0x48> (0 <pm_stop-0x80>) */ /* literal: GOT slot for pm_dream */
  pm_dream(a2, a3, a4, a5); /* call via literal slot */ /* 00cb: callx8 a8 */
  a10 = 0x0; /* 00ce: movi.n a10, 0 */
  a8 = (uint32_t)&pm_set_state; /* 00d0: l32r a8, 3c <pm_stop-0x44> (c <pm_stop-0x74>) */ /* literal: GOT slot for .text.pm_set_state */
  pm_set_state(a2, a3, a4, a5); /* call via literal slot */ /* 00d3: callx8 a8 */
  a8 = (uint32_t)&ppProcessWaitingQueue; /* 00d6: l32r a8, 40 <pm_stop-0x40> (0 <pm_stop-0x80>) */ /* literal: GOT slot for ppProcessWaitingQueue */
  ppProcessWaitingQueue(a2, a3, a4, a5); /* call via literal slot */ /* 00d9: callx8 a8 */
L_dc:;
  a3 = MEM32(a5 + 0); /* 00dc: l32i.n a3, a5, 0 */
  a6 = 0x1; /* 00de: movi a6, 1 */
  a14 = MEM32(a2 + 136); /* 00e1: l32i a14, a2, 136 */
  a15 = MEM32(a2 + 140); /* 00e4: l32i a15, a2, 140 */
  a10 = MEM32(a3 + 272); /* 00e7: l32i a10, a3, 0x110 */
  MEM32(a1 + 32) = a14; /* 00ea: s32i a14, a1, 32 */
  MEM32(a1 + 36) = a15; /* 00ed: s32i a15, a1, 36 */
  MEMW(); /* 00f0: memw  */
  g_pm(a2, a3, a4, a5); /* call via literal slot */ /* 00f3: callx8 a10 */
  a3 = a11; /* 00f6: mov.n a3, a11 */
  a11 = 0x1; /* 00f8: movi.n a11, 1 */
  a11 = 0x1000; /* 00fa: slli a11, a11, 12 */
  a4 = MEM32(a2 + 128); /* 00fd: l32i a4, a2, 128 */
  a4 = a10 - a4; /* 0100: sub a4, a10, a4 */
  a7 = MEM32(a2 + 132); /* 0103: l32i a7, a2, 132 */
  a14 = MEM32(a1 + 32); /* 0106: l32i.n a14, a1, 32 */
  a15 = MEM32(a1 + 36); /* 0108: l32i a15, a1, 36 */
  if (a10 < a4) goto L_111; /* 010b: bltu a10, a4, 111 <pm_stop+0x91> */
  a6 = 0x0; /* 010e: movi a6, 0 */
L_111:;
  a3 = a3 - a7; /* 0111: sub a3, a3, a7 */
  a3 = a3 - a6; /* 0114: sub a3, a3, a6 */
  a13 = (uint32_t)&lit_rodata_wlog_info_58; /* 0117: l32r a13, 10 <pm_stop-0x70> (0 <pm_stop-0x80>) */ /* literal @0x10: .rodata_wlog_info.58 */
  a12 = 0x3; /* 011a: movi.n a12, 3 */
  a10 = 0x6; /* 011c: movi.n a10, 6 */
  MEM32(a1 + 4) = a3; /* 011e: s32i a3, a1, 4 */
  MEM32(a1 + 0) = a4; /* 0121: s32i a4, a1, 0 */
  MEMW(); /* 0124: memw  */
  a8 = (uint32_t)&wifi_log; /* 0127: l32r a8, 44 <pm_stop-0x3c> (0 <pm_stop-0x80>) */ /* literal: GOT slot for wifi_log */
  wifi_log(a2, a3, a4, a5); /* call via literal slot */ /* 012a: callx8 a8 */
  a3 = MEM8(a2 + 15); /* 012d: l8ui a3, a2, 15 */
  if (a3 == 0) goto L_138; /* 0130: beqz.n a3, 138 <pm_stop+0xb8> */
  a8 = (uint32_t)&pm_wake_done; /* 0132: l32r a8, 48 <pm_stop-0x38> (0 <pm_stop-0x80>) */ /* literal: GOT slot for pm_wake_done */
  pm_wake_done(a2, a3, a4, a5); /* call via literal slot */ /* 0135: callx8 a8 */
L_138:;
  a4 = 0x1; /* 0138: movi.n a4, 1 */
  a6 = 0x30000; /* 013a: l32r a6, 14 <pm_stop-0x6c> (30000 <pm_attach+0x2ff7c>) */ @0x14
  a3 = 0x0; /* 013d: movi.n a3, 0 */
  MEM8(a2 + 11) = a4; /* 013f: s8i a4, a2, 11 */
  a4 = 0x1; /* 0142: movi.n a4, 1 */
  MEM16(a2 + 24) = a4; /* 0144: s16i a4, a2, 24 */
  a4 = a2 + ((0x100) << 8); /* 0147: addmi a4, a2, 0x100 */
  MEM32(a2 + 384) = a6; /* 014a: s32i a6, a2, 0x180 */
  MEM8(a2 + 15) = a3; /* 014d: s8i a3, a2, 15 */
  MEM8(a2 + 16) = a3; /* 0150: s8i a3, a2, 16 */
  MEM8(a2 + 13) = a3; /* 0153: s8i a3, a2, 13 */
  MEM8(a4 + 100) = a3; /* 0156: s8i a3, a4, 100 */
  MEM8(a4 + 125) = a3; /* 0159: s8i a3, a4, 125 */
  MEM8(a4 + 193) = a3; /* 015c: s8i a3, a4, 193 */
  MEM8(a4 + 200) = a3; /* 015f: s8i a3, a4, 200 */
  MEMW(); /* 0162: memw  */
  MEMW(); /* 0165: memw  */
  a8 = (uint32_t)&pm_coex_pwr_update; /* 0168: l32r a8, 4c <pm_stop-0x34> (0 <pm_stop-0x80>) */ /* literal: GOT slot for pm_coex_pwr_update */
  pm_coex_pwr_update(a2, a3, a4, a5); /* call via literal slot */ /* 016b: callx8 a8 */
  a10 = 0x0; /* 016e: movi.n a10, 0 */
  a8 = (uint32_t)&pm_on_coex_schm_status_config; /* 0170: l32r a8, 50 <pm_stop-0x30> (0 <pm_stop-0x80>) */ /* literal: GOT slot for pm_on_coex_schm_status_config */
  pm_on_coex_schm_status_config(a2, a3, a4, a5); /* call via literal slot */ /* 0173: callx8 a8 */
  a3 = MEM32(a5 + 0); /* 0176: l32i.n a3, a5, 0 */
  a10 = MEM32(a3 + 404); /* 0178: l32i a10, a3, 0x194 */
  g_pm(a2, a3, a4, a5); /* call via literal slot */ /* 017b: callx8 a10 */
  if (a10 == 0) goto L_186; /* 017e: beqz.n a10, 186 <pm_stop+0x106> */
  a8 = (uint32_t)&pm_coex_schm_process_restart; /* 0180: l32r a8, 54 <pm_stop-0x2c> (0 <pm_stop-0x80>) */ /* literal: GOT slot for pm_coex_schm_process_restart */
  pm_coex_schm_process_restart(a2, a3, a4, a5); /* call via literal slot */ /* 0183: callx8 a8 */
L_186:;
  a3 = (uint32_t)&ptr_beacon_offset_funcs; /* 0186: l32r a3, 18 <pm_stop-0x68> (0 <pm_stop-0x80>) */ /* literal @0x18: ptr_beacon_offset_funcs */
  a3 = MEM32(a3 + 0); /* 0189: l32i.n a3, a3, 0 */
  a3 = MEM32(a3 + 52); /* 018b: l32i a3, a3, 52 */
  if (a3 == 0) goto L_194; /* 018e: beqz a3, 194 <pm_stop+0x114> */
  ptr_beacon_offset_funcs(a2, a3, a4, a5); /* call via literal slot */ /* 0191: callx8 a3 */
L_194:;
  a3 = MEM8(a4 + 29); /* 0194: l8ui a3, a4, 29 */
  if (a3 == 0) goto L_1b0; /* 0197: beqz.n a3, 1b0 <pm_stop+0x130> */
  a3 = 0x2; /* 0199: movi a3, 2 */
  MEM8(a4 + 29) = a3; /* 019c: s8i a3, a4, 29 */
  MEMW(); /* 019f: memw  */
  a3 = MEM32(a2 + 288); /* 01a2: l32i a3, a2, 0x120 */
  if (a3 != 0) goto L_1b0; /* 01a5: bnez.n a3, 1b0 <pm_stop+0x130> */
  MEMW(); /* 01a7: memw  */
  a8 = (uint32_t)&pm_enable_disconnected_sleep_delay_timer; /* 01aa: l32r a8, 58 <pm_stop-0x28> (0 <pm_stop-0x80>) */ /* literal: GOT slot for pm_enable_disconnected_sleep_delay_timer */
  pm_enable_disconnected_sleep_delay_timer(a2, a3, a4, a5); /* call via literal slot */ /* 01ad: callx8 a8 */
L_1b0:;
  a8 = (uint32_t)&pm_update_by_connectionless_status; /* 01b0: l32r a8, 5c <pm_stop-0x24> (0 <pm_stop-0x80>) */ /* literal: GOT slot for pm_update_by_connectionless_status */
  pm_update_by_connectionless_status(a2, a3, a4, a5); /* call via literal slot */ /* 01b3: callx8 a8 */
  a3 = (uint32_t)&g_mesh_is_started; /* 01b6: l32r a3, 1c <pm_stop-0x64> (0 <pm_stop-0x80>) */ /* literal @0x1C: g_mesh_is_started */
  a3 = MEM8(a3 + 0); /* 01b9: l8ui a3, a3, 0 */
  if (a3 == 0) goto L_278; /* 01bc: beqz a3, 278 <pm_stop+0x1f8> */
  a3 = (uint32_t)&g_mesh_is_root; /* 01bf: l32r a3, 20 <pm_stop-0x60> (0 <pm_stop-0x80>) */ /* literal @0x20: g_mesh_is_root */
  MEMW(); /* 01c2: memw  */
  a4 = MEM8(a3 + 0); /* 01c5: l8ui a4, a3, 0 */
  a4 = (a4 >> 0) & 0xFF; /* 01c8: extui a4, a4, 0, 8 */
  if (a4 != 0) goto L_278; /* 01cb: bnez a4, 278 <pm_stop+0x1f8> */
  a3 = (uint32_t)&g_mesh_init_ps_type; /* 01ce: l32r a3, 24 <pm_stop-0x5c> (0 <pm_stop-0x80>) */ /* literal @0x24: g_mesh_init_ps_type */
  a3 = MEM32(a3 + 0); /* 01d1: l32i.n a3, a3, 0 */
  if (a3 == 0) goto L_278; /* 01d3: beqz a3, 278 <pm_stop+0x1f8> */
  a6 = 0x1; /* 01d6: movi.n a6, 1 */
  a3 = MEM32(a5 + 0); /* 01d8: l32i.n a3, a5, 0 */
  a10 = MEM32(a3 + 272); /* 01da: l32i a10, a3, 0x110 */
  g_pm(a2, a3, a4, a5); /* call via literal slot */ /* 01dd: callx8 a10 */
  a5 = MEM32(a2 + 128); /* 01e0: l32i a5, a2, 128 */
  a5 = a10 - a5; /* 01e3: sub a5, a10, a5 */
  a3 = MEM32(a2 + 132); /* 01e6: l32i a3, a2, 132 */
  if (a10 < a5) goto L_1ee; /* 01e9: bltu a10, a5, 1ee <pm_stop+0x16e> */
  a6 = a4; /* 01ec: mov.n a6, a4 */
L_1ee:;
  a3 = a11 - a3; /* 01ee: sub a3, a11, a3 */
  a3 = a3 - a6; /* 01f1: sub a3, a3, a6 */
  a15 = MEM32(a2 + 140); /* 01f4: l32i a15, a2, 140 */
  a7 = 0x1; /* 01f7: movi.n a7, 1 */
  a4 = a15 << (12 & 31); /* 01f9: slli a4, a15, 12 */
  a7 = 0x1000; /* 01fc: slli a7, a7, 12 */
  a6 = MEM32(a2 + 136); /* 01ff: l32i a6, a2, 136 */
  a6 = (a6 >> 20) & 0xFFF; /* 0202: extui a6, a6, 20, 12 */
  a6 = a4 | a6; /* 0205: or a6, a4, a6 */
  a4 = (a15 >> 20) & 0xFFF; /* 0208: extui a4, a15, 20, 12 */
  a8 = (uint32_t)&esp_mesh_get_running_active_duty_cycle; /* 020b: l32r a8, 60 <pm_stop-0x20> (0 <pm_stop-0x80>) */ /* literal: GOT slot for esp_mesh_get_running_active_duty_cycle */
  esp_mesh_get_running_active_duty_cycle(a2, a3, a4, a5); /* call via literal slot */ /* 020e: callx8 a8 */
  a11 = MEM32(a2 + 140); /* 0211: l32i a11, a2, 140 */
  a8 = a10; /* 0214: mov.n a8, a10 */
  a10 = MEM32(a2 + 136); /* 0216: l32i a10, a2, 136 */
  MEM32(a1 + 32) = a8; /* 0219: s32i.n a8, a1, 32 */
  MEMW(); /* 021b: memw  */
  a8 = (uint32_t)&floatundisf; /* 021e: l32r a8, 64 <pm_stop-0x1c> (0 <pm_stop-0x80>) */ /* literal: GOT slot for __floatundisf */
  floatundisf(a2, a3, a4, a5); /* call via literal slot */ /* 0221: callx8 a8 */
  a2 = a10; /* 0224: mov.n a2, a10 */
  a11 = a3 | a3; /* 0226: or a11, a3, a3 */
  a10 = a5 | a5; /* 0229: or a10, a5, a5 */
  a8 = (uint32_t)&floatundisf; /* 022c: l32r a8, 68 <pm_stop-0x18> (0 <pm_stop-0x80>) */ /* literal: GOT slot for __floatundisf */
  floatundisf(a2, a3, a4, a5); /* call via literal slot */ /* 022f: callx8 a8 */
  a11 = a10; /* 0232: mov.n a11, a10 */
  a10 = a2; /* 0234: mov.n a10, a2 */
  a8 = (uint32_t)&divsf3; /* 0236: l32r a8, 6c <pm_stop-0x14> (0 <pm_stop-0x80>) */ /* literal: GOT slot for __divsf3 */
  divsf3(a2, a3, a4, a5); /* call via literal slot */ /* 0239: callx8 a8 */
  a8 = (uint32_t)&extendsfdf2; /* 023c: l32r a8, 70 <pm_stop-0x10> (0 <pm_stop-0x80>) */ /* literal: GOT slot for __extendsfdf2 */
  extendsfdf2(a2, a3, a4, a5); /* call via literal slot */ /* 023f: callx8 a8 */
  a8 = MEM32(a1 + 32); /* 0242: l32i.n a8, a1, 32 */
  a2 = a3 << (12 & 31); /* 0244: slli a2, a3, 12 */
  a3 = (a3 >> 20) & 0xFFF; /* 0247: extui a3, a3, 20, 12 */
  a14 = a6; /* 024a: mov.n a14, a6 */
  a15 = a4; /* 024c: mov.n a15, a4 */
  MEM32(a1 + 16) = a10; /* 024e: s32i.n a10, a1, 16 */
  a10 = (a5 >> 20) & 0xFFF; /* 0250: extui a10, a5, 20, 12 */
  a10 = a2 | a10; /* 0253: or a10, a2, a10 */
  a12 = 0x3; /* 0256: movi.n a12, 3 */
  a13 = (uint32_t)&lit_rodata_wlog_info_59; /* 0258: l32r a13, 28 <pm_stop-0x58> (0 <pm_stop-0x80>) */ /* literal @0x28: .rodata_wlog_info.59 */
  MEM32(a1 + 20) = a11; /* 025b: s32i.n a11, a1, 20 */
  a11 = a7; /* 025d: mov.n a11, a7 */
  MEM32(a1 + 0) = a10; /* 025f: s32i.n a10, a1, 0 */
  a10 = 0x6; /* 0261: movi.n a10, 6 */
  MEM32(a1 + 8) = a8; /* 0263: s32i.n a8, a1, 8 */
  MEM32(a1 + 4) = a3; /* 0265: s32i.n a3, a1, 4 */
  MEMW(); /* 0267: memw  */
  a8 = (uint32_t)&wifi_log; /* 026a: l32r a8, 74 <pm_stop-0xc> (0 <pm_stop-0x80>) */ /* literal: GOT slot for wifi_log */
  wifi_log(a2, a3, a4, a5); /* call via literal slot */ /* 026d: callx8 a8 */
  a10 = 0x0; /* 0270: movi.n a10, 0 */
  a8 = (uint32_t)&ieee80211_hostapd_beacon_txcb; /* 0272: l32r a8, 78 <pm_stop-0x8> (0 <pm_stop-0x80>) */ /* literal: GOT slot for ieee80211_hostapd_beacon_txcb */
  ieee80211_hostapd_beacon_txcb(a2, a3, a4, a5); /* call via literal slot */ /* 0275: callx8 a8 */
L_278:;
  a10 = 0x0; /* 0278: movi.n a10, 0 */
  a8 = (uint32_t)&pm_set_bss_max_idle; /* 027a: l32r a8, 7c <pm_stop-0x4> (0 <pm_stop-0x80>) */ /* literal: GOT slot for pm_set_bss_max_idle */
  pm_set_bss_max_idle(a2, a3, a4, a5); /* call via literal slot */ /* 027d: callx8 a8 */
L_280:;
  return (int32_t)a2; /* 0280: retw.n  */
}

/* pm_attach @ pm.o 00000084 size 339B bind GLOBAL
 * Calls: memset, ppRegisterTxCallback, .text.pm_set_state[got], g_osi_funcs_p[got] | Data refs: g_osi_funcs_p, g_pm, g_pm_cfg, memset, pm_send_sleep_null_cb, pm_send_wake_null_cb, ppRegisterTxCallback, .text.pm_set_state, .text.pm_tbtt_timeout, .text.pm_dream_timeout, .text.pm_active_timeout, .text.pm_sleep_delay_timeout, .text.pm_coex_slice_wifi_timeout, .text.pm_disconnected_sleep_delay_timeout, .text.pm_connectionless_wake_interval_timeout, .text.pm_connectionless_wake_window_timeout, .text.pm_beacon_monitor_timeout, .text.pm_keep_alive_timeout, .text.pm_coex_restart_timeout
 *   MMIO: none
 *   funcdb v3: 2 call(s), 7 ref(s); disasm: 15 call(s), 19 data ref(s)
 * Fidelity: medium - 127 instr, 0 branches, calls resolved */
int32_t pm_attach(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pm_attach; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_84:;
  /* 0084: entry a1, 32 */
  a2 = (uint32_t)&g_pm; /* 0087: l32r a2, 0 <pm_attach-0x84> (0 <pm_attach-0x84>) */ /* literal @0x0: g_pm */
  a12 = 0x248; /* 008a: movi a12, 0x248 */
  a11 = 0x0; /* 008d: movi a11, 0 */
  a10 = a2 | a2; /* 0090: or a10, a2, a2 */
  a8 = (uint32_t)&memset; /* 0093: l32r a8, 74 <pm_attach-0x10> (0 <pm_attach-0x84>) */ /* literal: GOT slot for memset */
  memset(a2, a3, a4, a5); /* call via literal slot */ /* 0096: callx8 a8 */
  a5 = 0x1; /* 0099: movi.n a5, 1 */
  a10 = 0x0; /* 009b: movi.n a10, 0 */
  MEM32(a2 + 36) = a5; /* 009d: s32i.n a5, a2, 36 */
  MEMW(); /* 009f: memw  */
  a8 = (uint32_t)&pm_set_state; /* 00a2: l32r a8, 78 <pm_attach-0xc> (c <pm_attach-0x78>) */ /* literal: GOT slot for .text.pm_set_state */
  pm_set_state(a2, a3, a4, a5); /* call via literal slot */ /* 00a5: callx8 a8 */
  a6 = a2 + ((0x100) << 8); /* 00a8: addmi a6, a2, 0x100 */
  a11 = 0x5; /* 00ab: movi.n a11, 5 */
  a3 = (uint32_t)&g_pm_cfg; /* 00ad: l32r a3, 4 <pm_attach-0x80> (0 <pm_attach-0x84>) */ /* literal @0x4: g_pm_cfg */
  a4 = MEM32(a3 + 4); /* 00b0: l32i.n a4, a3, 4 */
  MEM32(a2 + 40) = a4; /* 00b2: s32i.n a4, a2, 40 */
  a4 = MEM32(a3 + 12); /* 00b4: l32i.n a4, a3, 12 */
  MEM32(a2 + 52) = a4; /* 00b6: s32i.n a4, a2, 52 */
  a4 = 0x19000; /* 00b8: l32r a4, 8 <pm_attach-0x7c> (19000 <pm_attach+0x18f7c>) */ @0x8
  MEM32(a2 + 44) = a4; /* 00bb: s32i.n a4, a2, 44 */
  a4 = MEM32(a3 + 20); /* 00bd: l32i.n a4, a3, 20 */
  MEM32(a2 + 48) = a4; /* 00bf: s32i.n a4, a2, 48 */
  a4 = MEM32(a3 + 44); /* 00c1: l32i.n a4, a3, 44 */
  a3 = MEM32(a3 + 24); /* 00c3: l32i.n a3, a3, 24 */
  MEM32(a2 + 452) = a4; /* 00c5: s32i a4, a2, 0x1c4 */
  a4 = 0x30000; /* 00c8: l32r a4, c <pm_attach-0x78> (30000 <pm_attach+0x2ff7c>) */ @0xC
  MEM32(a2 + 56) = a3; /* 00cb: s32i.n a3, a2, 56 */
  a3 = 0x0; /* 00cd: movi.n a3, 0 */
  a12 = 0x0; /* 00cf: mov.n a12, a3 */
  a10 = (uint32_t)&pm_send_sleep_null_cb; /* 00d1: l32r a10, 10 <pm_attach-0x74> (0 <pm_attach-0x84>) */ /* literal @0x10: pm_send_sleep_null_cb */
  MEM32(a2 + 384) = a4; /* 00d4: s32i a4, a2, 0x180 */
  MEM16(a2 + 24) = a5; /* 00d7: s16i a5, a2, 24 */
  MEM16(a2 + 382) = a3; /* 00da: s16i a3, a2, 0x17e */
  MEM8(a2 + 11) = a5; /* 00dd: s8i a5, a2, 11 */
  MEM16(a2 + 32) = a5; /* 00e0: s16i a5, a2, 32 */
  MEM32(a2 + 60) = a3; /* 00e3: s32i.n a3, a2, 60 */
  MEM8(a2 + 21) = a3; /* 00e5: s8i a3, a2, 21 */
  MEM8(a6 + 125) = a3; /* 00e8: s8i a3, a6, 125 */
  MEM8(a2 + 14) = a5; /* 00eb: s8i a5, a2, 14 */
  MEM8(a6 + 212) = a3; /* 00ee: s8i a3, a6, 212 */
  MEMW(); /* 00f1: memw  */
  MEMW(); /* 00f4: memw  */
  a8 = (uint32_t)&ppRegisterTxCallback; /* 00f7: l32r a8, 7c <pm_attach-0x8> (0 <pm_attach-0x84>) */ /* literal: GOT slot for ppRegisterTxCallback */
  ppRegisterTxCallback(a2, a3, a4, a5); /* call via literal slot */ /* 00fa: callx8 a8 */
  a12 = a3; /* 00fd: mov.n a12, a3 */
  a11 = 0x6; /* 00ff: movi.n a11, 6 */
  a10 = (uint32_t)&pm_send_wake_null_cb; /* 0101: l32r a10, 14 <pm_attach-0x70> (0 <pm_attach-0x84>) */ /* literal @0x14: pm_send_wake_null_cb */
  a8 = (uint32_t)&ppRegisterTxCallback; /* 0104: l32r a8, 80 <pm_attach-0x4> (0 <pm_attach-0x84>) */ /* literal: GOT slot for ppRegisterTxCallback */
  ppRegisterTxCallback(a2, a3, a4, a5); /* call via literal slot */ /* 0107: callx8 a8 */
  a12 = a3; /* 010a: mov.n a12, a3 */
  a4 = (uint32_t)&g_osi_funcs_p; /* 010c: l32r a4, 20 <pm_attach-0x64> (0 <pm_attach-0x84>) */ /* literal @0x20: g_osi_funcs_p */
  a8 = MEM32(a4 + 0); /* 010f: l32i.n a8, a4, 0 */
  a11 = (uint32_t)&pm_tbtt_timeout; /* 0111: l32r a11, 18 <pm_attach-0x6c> (4 <pm_attach-0x80>) */ /* literal @0x18: .text.pm_tbtt_timeout */
  a8 = MEM32(a8 + 244); /* 0114: l32i a8, a8, 244 */
  a10 = (uint32_t)&g_pm; /* 0117: l32r a10, 1c <pm_attach-0x68> (0 <pm_attach-0x84>) */ /* literal @0x1C: g_pm */
  ppRegisterTxCallback(a2, a3, a4, a5); /* call via literal slot */ /* 011a: callx8 a8 */
  a12 = a3; /* 011d: mov.n a12, a3 */
  a8 = MEM32(a4 + 0); /* 011f: l32i.n a8, a4, 0 */
  a11 = (uint32_t)&pm_dream_timeout; /* 0121: l32r a11, 24 <pm_attach-0x60> (4 <pm_attach-0x80>) */ /* literal @0x24: .text.pm_dream_timeout */
  a8 = MEM32(a8 + 244); /* 0124: l32i a8, a8, 244 */
  a10 = (uint32_t)&g_pm; /* 0127: l32r a10, 28 <pm_attach-0x5c> (0 <pm_attach-0x84>) */ /* literal @0x28: g_pm */
  ppRegisterTxCallback(a2, a3, a4, a5); /* call via literal slot */ /* 012a: callx8 a8 */
  a12 = a3; /* 012d: mov.n a12, a3 */
  a8 = MEM32(a4 + 0); /* 012f: l32i.n a8, a4, 0 */
  a11 = (uint32_t)&pm_active_timeout; /* 0131: l32r a11, 2c <pm_attach-0x58> (4 <pm_attach-0x80>) */ /* literal @0x2C: .text.pm_active_timeout */
  a8 = MEM32(a8 + 244); /* 0134: l32i a8, a8, 244 */
  a10 = (uint32_t)&g_pm; /* 0137: l32r a10, 30 <pm_attach-0x54> (0 <pm_attach-0x84>) */ /* literal @0x30: g_pm */
  ppRegisterTxCallback(a2, a3, a4, a5); /* call via literal slot */ /* 013a: callx8 a8 */
  a12 = a3; /* 013d: mov.n a12, a3 */
  a8 = MEM32(a4 + 0); /* 013f: l32i.n a8, a4, 0 */
  a11 = (uint32_t)&pm_sleep_delay_timeout; /* 0141: l32r a11, 34 <pm_attach-0x50> (4 <pm_attach-0x80>) */ /* literal @0x34: .text.pm_sleep_delay_timeout */
  a8 = MEM32(a8 + 244); /* 0144: l32i a8, a8, 244 */
  a10 = (uint32_t)&g_pm; /* 0147: l32r a10, 38 <pm_attach-0x4c> (0 <pm_attach-0x84>) */ /* literal @0x38: g_pm */
  ppRegisterTxCallback(a2, a3, a4, a5); /* call via literal slot */ /* 014a: callx8 a8 */
  a12 = a3; /* 014d: mov.n a12, a3 */
  a8 = MEM32(a4 + 0); /* 014f: l32i.n a8, a4, 0 */
  a11 = (uint32_t)&pm_coex_slice_wifi_timeout; /* 0151: l32r a11, 3c <pm_attach-0x48> (4 <pm_attach-0x80>) */ /* literal @0x3C: .text.pm_coex_slice_wifi_timeout */
  a8 = MEM32(a8 + 244); /* 0154: l32i a8, a8, 244 */
  a10 = (uint32_t)&g_pm; /* 0157: l32r a10, 40 <pm_attach-0x44> (0 <pm_attach-0x84>) */ /* literal @0x40: g_pm */
  ppRegisterTxCallback(a2, a3, a4, a5); /* call via literal slot */ /* 015a: callx8 a8 */
  a12 = a3; /* 015d: mov.n a12, a3 */
  a8 = MEM32(a4 + 0); /* 015f: l32i.n a8, a4, 0 */
  a11 = (uint32_t)&pm_disconnected_sleep_delay_timeout; /* 0161: l32r a11, 44 <pm_attach-0x40> (4 <pm_attach-0x80>) */ /* literal @0x44: .text.pm_disconnected_sleep_delay_timeout */
  a8 = MEM32(a8 + 244); /* 0164: l32i a8, a8, 244 */
  a10 = (uint32_t)&g_pm; /* 0167: l32r a10, 48 <pm_attach-0x3c> (0 <pm_attach-0x84>) */ /* literal @0x48: g_pm */
  ppRegisterTxCallback(a2, a3, a4, a5); /* call via literal slot */ /* 016a: callx8 a8 */
  a12 = a3; /* 016d: mov.n a12, a3 */
  a8 = MEM32(a4 + 0); /* 016f: l32i.n a8, a4, 0 */
  a11 = (uint32_t)&pm_connectionless_wake_interval_timeout; /* 0171: l32r a11, 4c <pm_attach-0x38> (4 <pm_attach-0x80>) */ /* literal @0x4C: .text.pm_connectionless_wake_interval_timeout */
  a8 = MEM32(a8 + 244); /* 0174: l32i a8, a8, 244 */
  a10 = (uint32_t)&g_pm; /* 0177: l32r a10, 50 <pm_attach-0x34> (0 <pm_attach-0x84>) */ /* literal @0x50: g_pm */
  ppRegisterTxCallback(a2, a3, a4, a5); /* call via literal slot */ /* 017a: callx8 a8 */
  a12 = a3; /* 017d: mov.n a12, a3 */
  a8 = MEM32(a4 + 0); /* 017f: l32i.n a8, a4, 0 */
  a11 = (uint32_t)&pm_connectionless_wake_window_timeout; /* 0181: l32r a11, 54 <pm_attach-0x30> (4 <pm_attach-0x80>) */ /* literal @0x54: .text.pm_connectionless_wake_window_timeout */
  a8 = MEM32(a8 + 244); /* 0184: l32i a8, a8, 244 */
  a10 = (uint32_t)&g_pm; /* 0187: l32r a10, 58 <pm_attach-0x2c> (0 <pm_attach-0x84>) */ /* literal @0x58: g_pm */
  ppRegisterTxCallback(a2, a3, a4, a5); /* call via literal slot */ /* 018a: callx8 a8 */
  a12 = a2; /* 018d: mov.n a12, a2 */
  a8 = MEM32(a4 + 0); /* 018f: l32i.n a8, a4, 0 */
  a11 = (uint32_t)&pm_beacon_monitor_timeout; /* 0191: l32r a11, 5c <pm_attach-0x28> (4 <pm_attach-0x80>) */ /* literal @0x5C: .text.pm_beacon_monitor_timeout */
  a8 = MEM32(a8 + 244); /* 0194: l32i a8, a8, 244 */
  a10 = (uint32_t)&g_pm; /* 0197: l32r a10, 60 <pm_attach-0x24> (0 <pm_attach-0x84>) */ /* literal @0x60: g_pm */
  ppRegisterTxCallback(a2, a3, a4, a5); /* call via literal slot */ /* 019a: callx8 a8 */
  a12 = a3; /* 019d: mov.n a12, a3 */
  a8 = MEM32(a4 + 0); /* 019f: l32i.n a8, a4, 0 */
  a11 = (uint32_t)&pm_keep_alive_timeout; /* 01a1: l32r a11, 64 <pm_attach-0x20> (4 <pm_attach-0x80>) */ /* literal @0x64: .text.pm_keep_alive_timeout */
  a8 = MEM32(a8 + 244); /* 01a4: l32i a8, a8, 244 */
  a10 = (uint32_t)&g_pm; /* 01a7: l32r a10, 68 <pm_attach-0x1c> (0 <pm_attach-0x84>) */ /* literal @0x68: g_pm */
  ppRegisterTxCallback(a2, a3, a4, a5); /* call via literal slot */ /* 01aa: callx8 a8 */
  a12 = a3; /* 01ad: mov.n a12, a3 */
  a4 = MEM32(a4 + 0); /* 01af: l32i.n a4, a4, 0 */
  a11 = (uint32_t)&pm_coex_restart_timeout; /* 01b1: l32r a11, 6c <pm_attach-0x18> (4 <pm_attach-0x80>) */ /* literal @0x6C: .text.pm_coex_restart_timeout */
  a4 = MEM32(a4 + 244); /* 01b4: l32i a4, a4, 244 */
  a10 = (uint32_t)&g_pm; /* 01b7: l32r a10, 70 <pm_attach-0x14> (0 <pm_attach-0x84>) */ /* literal @0x70: g_pm */
  g_osi_funcs_p(a2, a3, a4, a5); /* call via literal slot */ /* 01ba: callx8 a4 */
  MEM16(a2 + 394) = a3; /* 01bd: s16i a3, a2, 0x18a */
  MEM32(a2 + 424) = a3; /* 01c0: s32i a3, a2, 0x1a8 */
  MEM32(a2 + 428) = a3; /* 01c3: s32i a3, a2, 0x1ac */
  MEM8(a6 + 29) = a3; /* 01c6: s8i a3, a6, 29 */
  MEM8(a6 + 201) = a5; /* 01c9: s8i a5, a6, 201 */
  MEM8(a2 + 0) = a5; /* 01cc: s8i a5, a2, 0 */
  MEMW(); /* 01cf: memw  */
  MEMW(); /* 01d2: memw  */
  return (int32_t)a2; /* 01d5: retw.n  */
}

/* pm_deattach @ pm.o 00000034 size 161B bind GLOBAL
 * Calls: g_osi_funcs_p[got] | Data refs: g_osi_funcs_p, g_pm
 *   MMIO: none
 *   funcdb v3: 0 call(s), 2 ref(s); disasm: 1 call(s), 2 data ref(s)
 * Fidelity: medium - 55 instr, 2 branches, 10 indirect; flow + direct calls mapped, GOT-indirects enumerated */
int32_t pm_deattach(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pm_deattach; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_34:;
  /* 0034: entry a1, 32 */
  a3 = (uint32_t)&g_pm; /* 0037: l32r a3, 0 <pm_deattach-0x34> (0 <pm_deattach-0x34>) */ /* literal @0x0: g_pm */
  a2 = MEM8(a3 + 0); /* 003a: l8ui a2, a3, 0 */
  if (a2 == 1) goto L_43; /* 003d: beqi a2, 1, 43 <pm_deattach+0xf> */
  goto L_d0; /* 0040: j d0 <pm_deattach+0x9c> */
L_43:;
  a2 = (uint32_t)&g_osi_funcs_p; /* 0043: l32r a2, 8 <pm_deattach-0x2c> (0 <pm_deattach-0x34>) */ /* literal @0x8: g_osi_funcs_p */
  a8 = MEM32(a2 + 0); /* 0046: l32i a8, a2, 0 */
  a10 = (uint32_t)&g_pm; /* 0049: l32r a10, 4 <pm_deattach-0x30> (0 <pm_deattach-0x34>) */ /* literal @0x4: g_pm */
  a8 = MEM32(a8 + 240); /* 004c: l32i a8, a8, 240 */
  ((int32_t(*)())a8)(a2, a3, a4, a5); /* 004f: callx8 a8 */ /* indirect */
  a8 = MEM32(a2 + 0); /* 0052: l32i a8, a2, 0 */
  a10 = (uint32_t)&g_pm; /* 0055: l32r a10, c <pm_deattach-0x28> (0 <pm_deattach-0x34>) */ /* literal @0xC: g_pm */
  a8 = MEM32(a8 + 240); /* 0058: l32i a8, a8, 240 */
  ((int32_t(*)())a8)(a2, a3, a4, a5); /* 005b: callx8 a8 */ /* indirect */
  a8 = MEM32(a2 + 0); /* 005e: l32i a8, a2, 0 */
  a10 = (uint32_t)&g_pm; /* 0061: l32r a10, 10 <pm_deattach-0x24> (0 <pm_deattach-0x34>) */ /* literal @0x10: g_pm */
  a8 = MEM32(a8 + 240); /* 0064: l32i a8, a8, 240 */
  ((int32_t(*)())a8)(a2, a3, a4, a5); /* 0067: callx8 a8 */ /* indirect */
  a8 = MEM32(a2 + 0); /* 006a: l32i a8, a2, 0 */
  a10 = (uint32_t)&g_pm; /* 006d: l32r a10, 14 <pm_deattach-0x20> (0 <pm_deattach-0x34>) */ /* literal @0x14: g_pm */
  a8 = MEM32(a8 + 240); /* 0070: l32i a8, a8, 240 */
  ((int32_t(*)())a8)(a2, a3, a4, a5); /* 0073: callx8 a8 */ /* indirect */
  a8 = MEM32(a2 + 0); /* 0076: l32i a8, a2, 0 */
  a10 = (uint32_t)&g_pm; /* 0079: l32r a10, 18 <pm_deattach-0x1c> (0 <pm_deattach-0x34>) */ /* literal @0x18: g_pm */
  a8 = MEM32(a8 + 240); /* 007c: l32i a8, a8, 240 */
  ((int32_t(*)())a8)(a2, a3, a4, a5); /* 007f: callx8 a8 */ /* indirect */
  a8 = MEM32(a2 + 0); /* 0082: l32i a8, a2, 0 */
  a10 = (uint32_t)&g_pm; /* 0085: l32r a10, 1c <pm_deattach-0x18> (0 <pm_deattach-0x34>) */ /* literal @0x1C: g_pm */
  a8 = MEM32(a8 + 240); /* 0088: l32i a8, a8, 240 */
  ((int32_t(*)())a8)(a2, a3, a4, a5); /* 008b: callx8 a8 */ /* indirect */
  a8 = MEM32(a2 + 0); /* 008e: l32i a8, a2, 0 */
  a10 = (uint32_t)&g_pm; /* 0091: l32r a10, 20 <pm_deattach-0x14> (0 <pm_deattach-0x34>) */ /* literal @0x20: g_pm */
  a8 = MEM32(a8 + 240); /* 0094: l32i a8, a8, 240 */
  ((int32_t(*)())a8)(a2, a3, a4, a5); /* 0097: callx8 a8 */ /* indirect */
  a8 = MEM32(a2 + 0); /* 009a: l32i a8, a2, 0 */
  a10 = (uint32_t)&g_pm; /* 009d: l32r a10, 24 <pm_deattach-0x10> (0 <pm_deattach-0x34>) */ /* literal @0x24: g_pm */
  a8 = MEM32(a8 + 240); /* 00a0: l32i a8, a8, 240 */
  ((int32_t(*)())a8)(a2, a3, a4, a5); /* 00a3: callx8 a8 */ /* indirect */
  a8 = MEM32(a2 + 0); /* 00a6: l32i a8, a2, 0 */
  a10 = (uint32_t)&g_pm; /* 00a9: l32r a10, 28 <pm_deattach-0xc> (0 <pm_deattach-0x34>) */ /* literal @0x28: g_pm */
  a8 = MEM32(a8 + 240); /* 00ac: l32i a8, a8, 240 */
  ((int32_t(*)())a8)(a2, a3, a4, a5); /* 00af: callx8 a8 */ /* indirect */
  a8 = MEM32(a2 + 0); /* 00b2: l32i.n a8, a2, 0 */
  a10 = (uint32_t)&g_pm; /* 00b4: l32r a10, 2c <pm_deattach-0x8> (0 <pm_deattach-0x34>) */ /* literal @0x2C: g_pm */
  a8 = MEM32(a8 + 240); /* 00b7: l32i a8, a8, 240 */
  ((int32_t(*)())a8)(a2, a3, a4, a5); /* 00ba: callx8 a8 */ /* indirect */
  a2 = MEM32(a2 + 0); /* 00bd: l32i.n a2, a2, 0 */
  a10 = (uint32_t)&g_pm; /* 00bf: l32r a10, 30 <pm_deattach-0x4> (0 <pm_deattach-0x34>) */ /* literal @0x30: g_pm */
  a2 = MEM32(a2 + 240); /* 00c2: l32i a2, a2, 240 */
  g_osi_funcs_p(a2, a3, a4, a5); /* call via literal slot */ /* 00c5: callx8 a2 */
  a2 = 0x0; /* 00c8: movi.n a2, 0 */
  MEM8(a3 + 0) = a2; /* 00ca: s8i a2, a3, 0 */
  MEMW(); /* 00cd: memw  */
L_d0:;
  MEMW(); /* 00d0: memw  */
  return (int32_t)a2; /* 00d3: retw.n  */
}

/* pm_set_sleep_type @ pm.o 00000030 size 158B bind GLOBAL
 * Calls: pm_coex_pwr_update, pm_dream, pm_enable_active_timer, pm_go_to_wake, wifi_log, .text.pm_set_state[got], .text.pm_disable_active_timer[got] | Data refs: .rodata_wlog_info.60, .rodata_wlog_info.61, g_osi_funcs_p, g_pm, pm_coex_pwr_update, pm_dream, pm_enable_active_timer, pm_go_to_wake, wifi_log, .text.pm_set_state, .text.pm_disable_active_timer
 *   MMIO: none
 *   funcdb v3: 5 call(s), 9 ref(s); disasm: 8 call(s), 11 data ref(s)
 * Fidelity: medium - 61 instr, 10 branches, 3 indirect; flow + direct calls mapped, GOT-indirects enumerated */
int32_t pm_set_sleep_type(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pm_set_sleep_type; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_30:;
  /* 0030: entry a1, 32 */
  a5 = (uint32_t)&g_osi_funcs_p; /* 0033: l32r a5, 0 <pm_set_sleep_type-0x30> (0 <pm_set_sleep_type-0x30>) */ /* literal @0x0: g_osi_funcs_p */
  a3 = MEM32(a5 + 0); /* 0036: l32i.n a3, a5, 0 */
  a10 = MEM32(a3 + 404); /* 0038: l32i a10, a3, 0x194 */
  a3 = 0x1; /* 003b: movi.n a3, 1 */
  ((int32_t(*)())a10)(a2, a3, a4, a5); /* 003d: callx8 a10 */ /* indirect */
  a3 = a3 << (12 & 31); /* 0040: slli a3, a3, 12 */
  a15 = a10; /* 0043: mov.n a15, a10 */
  a13 = (uint32_t)&lit_rodata_wlog_info_60; /* 0045: l32r a13, 4 <pm_set_sleep_type-0x2c> (0 <pm_set_sleep_type-0x30>) */ /* literal @0x4: .rodata_wlog_info.60 */
  a14 = a2; /* 0048: mov.n a14, a2 */
  a12 = 0x3; /* 004a: movi.n a12, 3 */
  a11 = a3; /* 004c: mov.n a11, a3 */
  a10 = 0x6; /* 004e: movi.n a10, 6 */
  a8 = (uint32_t)&wifi_log; /* 0050: l32r a8, 10 <pm_set_sleep_type-0x20> (0 <pm_set_sleep_type-0x30>) */ /* literal: GOT slot for wifi_log */
  wifi_log(a2, a3, a4, a5); /* call via literal slot */ /* 0053: callx8 a8 */
  if (a2 != 0) goto L_71; /* 0056: bnez.n a2, 71 <pm_set_sleep_type+0x41> */
  a4 = MEM32(a5 + 0); /* 0058: l32i.n a4, a5, 0 */
  a10 = MEM32(a4 + 404); /* 005a: l32i a10, a4, 0x194 */
  ((int32_t(*)())a10)(a2, a3, a4, a5); /* 005d: callx8 a10 */ /* indirect */
  if (a10 == 0) goto L_71; /* 0060: beqz.n a10, 71 <pm_set_sleep_type+0x41> */
  a12 = 0x3; /* 0062: movi.n a12, 3 */
  a13 = (uint32_t)&lit_rodata_wlog_info_61; /* 0064: l32r a13, 8 <pm_set_sleep_type-0x28> (0 <pm_set_sleep_type-0x30>) */ /* literal @0x8: .rodata_wlog_info.61 */
  a11 = a3; /* 0067: mov.n a11, a3 */
  a10 = 0x6; /* 0069: movi.n a10, 6 */
  a8 = (uint32_t)&wifi_log; /* 006b: l32r a8, 14 <pm_set_sleep_type-0x1c> (0 <pm_set_sleep_type-0x30>) */ /* literal: GOT slot for wifi_log */
  wifi_log(a2, a3, a4, a5); /* call via literal slot */ /* 006e: callx8 a8 */
L_71:;
  a3 = (uint32_t)&g_pm; /* 0071: l32r a3, c <pm_set_sleep_type-0x24> (0 <pm_set_sleep_type-0x30>) */ /* literal @0xC: g_pm */
  a8 = MEM8(a3 + 13); /* 0074: l8ui a8, a3, 13 */
  a4 = MEM32(a3 + 36); /* 0077: l32i.n a4, a3, 36 */
  MEM32(a3 + 36) = a2; /* 0079: s32i.n a2, a3, 36 */
  if (a8 == 0) goto L_c6; /* 007b: beqz a8, c6 <pm_set_sleep_type+0x96> */
  a5 = MEM32(a5 + 0); /* 007e: l32i.n a5, a5, 0 */
  a10 = MEM32(a5 + 404); /* 0080: l32i a10, a5, 0x194 */
  MEMW(); /* 0083: memw  */
  ((int32_t(*)())a10)(a2, a3, a4, a5); /* 0086: callx8 a10 */ /* indirect */
  if (a10 == 1) goto L_c6; /* 0089: beqi a10, 1, c6 <pm_set_sleep_type+0x96> */
  if (a4 != 0) goto L_9c; /* 008c: bnez.n a4, 9c <pm_set_sleep_type+0x6c> */
  a2 = a2 + (-1); /* 008e: addi.n a2, a2, -1 */
  if (a2 >= 2) goto L_c6; /* 0090: bgeui a2, 2, c6 <pm_set_sleep_type+0x96> */
  a8 = (uint32_t)&pm_enable_active_timer; /* 0093: l32r a8, 18 <pm_set_sleep_type-0x18> (0 <pm_set_sleep_type-0x30>) */ /* literal: GOT slot for pm_enable_active_timer */
  pm_enable_active_timer(a2, a3, a4, a5); /* call via literal slot */ /* 0096: callx8 a8 */
  goto L_c6; /* 0099: j c6 <pm_set_sleep_type+0x96> */
L_9c:;
  if (a2 != 0) goto L_c6; /* 009c: bnez.n a2, c6 <pm_set_sleep_type+0x96> */
  a4 = a4 + (-1); /* 009e: addi.n a4, a4, -1 */
  if (a4 >= 2) goto L_c6; /* 00a0: bgeui a4, 2, c6 <pm_set_sleep_type+0x96> */
  a3 = MEM8(a3 + 1); /* 00a3: l8ui a3, a3, 1 */
  if (a3 == 0) goto L_c0; /* 00a6: beqz.n a3, c0 <pm_set_sleep_type+0x90> */
  a8 = (uint32_t)&pm_dream; /* 00a8: l32r a8, 1c <pm_set_sleep_type-0x14> (0 <pm_set_sleep_type-0x30>) */ /* literal: GOT slot for pm_dream */
  pm_dream(a2, a3, a4, a5); /* call via literal slot */ /* 00ab: callx8 a8 */
  a10 = a2; /* 00ae: mov.n a10, a2 */
  a8 = (uint32_t)&pm_set_state; /* 00b0: l32r a8, 20 <pm_set_sleep_type-0x10> (c <pm_set_sleep_type-0x24>) */ /* literal: GOT slot for .text.pm_set_state */
  pm_set_state(a2, a3, a4, a5); /* call via literal slot */ /* 00b3: callx8 a8 */
  a11 = a2; /* 00b6: mov.n a11, a2 */
  a10 = a2; /* 00b8: mov.n a10, a2 */
  a8 = (uint32_t)&pm_go_to_wake; /* 00ba: l32r a8, 24 <pm_set_sleep_type-0xc> (0 <pm_set_sleep_type-0x30>) */ /* literal: GOT slot for pm_go_to_wake */
  pm_go_to_wake(a2, a3, a4, a5); /* call via literal slot */ /* 00bd: callx8 a8 */
L_c0:;
  a8 = (uint32_t)&pm_disable_active_timer; /* 00c0: l32r a8, 28 <pm_set_sleep_type-0x8> (8 <pm_set_sleep_type-0x28>) */ /* literal: GOT slot for .text.pm_disable_active_timer */
  pm_disable_active_timer(a2, a3, a4, a5); /* call via literal slot */ /* 00c3: callx8 a8 */
L_c6:;
  a8 = (uint32_t)&pm_coex_pwr_update; /* 00c6: l32r a8, 2c <pm_set_sleep_type-0x4> (0 <pm_set_sleep_type-0x30>) */ /* literal: GOT slot for pm_coex_pwr_update */
  pm_coex_pwr_update(a2, a3, a4, a5); /* call via literal slot */ /* 00c9: callx8 a8 */
  return (int32_t)a2; /* 00cc: retw.n  */
}

/* pm_get_sleep_type @ pm.o 00000004 size 10B bind GLOBAL
 * Calls: none | Data refs: g_pm
 *   MMIO: none
 *   funcdb v3: 0 call(s), 1 ref(s); disasm: 0 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t pm_get_sleep_type(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pm_get_sleep_type; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a8 = (uint32_t)&g_pm; /* 0007: l32r a8, 0 <pm_get_sleep_type-0x4> (0 <pm_get_sleep_type-0x4>) */ /* literal @0x0: g_pm */
  a2 = MEM32(a8 + 36); /* 000a: l32i.n a2, a8, 36 */
  return (int32_t)a2; /* 000c: retw.n  */
}

/* pm_beacon_monitor_configure @ pm.o 00000004 size 66B bind GLOBAL
 * Calls: none | Data refs: g_pm_cfg
 *   MMIO: none
 *   funcdb v3: 0 call(s), 1 ref(s); disasm: 0 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t pm_beacon_monitor_configure(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pm_beacon_monitor_configure; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a9 = MEM8(a2 + 0); /* 0007: l8ui a9, a2, 0 */
  a8 = (uint32_t)&g_pm_cfg; /* 000a: l32r a8, 0 <pm_beacon_monitor_configure-0x4> (0 <pm_beacon_monitor_configure-0x4>) */ /* literal @0x0: g_pm_cfg */
  MEM8(a8 + 36) = a9; /* 000d: s8i a9, a8, 36 */
  MEMW(); /* 0010: memw  */
  if (a9 == 0) goto L_41; /* 0013: beqz.n a9, 41 <pm_beacon_monitor_configure+0x3d> */
  a9 = MEM8(a2 + 1); /* 0015: l8ui a9, a2, 1 */
  MEM8(a8 + 37) = a9; /* 0018: s8i a9, a8, 37 */
  MEMW(); /* 001b: memw  */
  a9 = MEM8(a2 + 2); /* 001e: l8ui a9, a2, 2 */
  MEM8(a8 + 38) = a9; /* 0021: s8i a9, a8, 38 */
  MEMW(); /* 0024: memw  */
  a9 = MEM8(a2 + 3); /* 0027: l8ui a9, a2, 3 */
  MEM8(a8 + 39) = a9; /* 002a: s8i a9, a8, 39 */
  MEMW(); /* 002d: memw  */
  a9 = MEM8(a2 + 4); /* 0030: l8ui a9, a2, 4 */
  MEM8(a8 + 40) = a9; /* 0033: s8i a9, a8, 40 */
  MEMW(); /* 0036: memw  */
  a2 = MEM32(a2 + 8); /* 0039: l32i.n a2, a2, 8 */
  MEM8(a8 + 51) = a2; /* 003b: s8i a2, a8, 51 */
  MEMW(); /* 003e: memw  */
L_41:;
  MEMW(); /* 0041: memw  */
  return (int32_t)a2; /* 0044: retw.n  */
}

/* pm_update_modem_sleep_default_params @ pm.o 00000004 size 16B bind GLOBAL
 * Calls: none | Data refs: g_pm_cfg
 *   MMIO: none
 *   funcdb v3: 0 call(s), 1 ref(s); disasm: 0 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t pm_update_modem_sleep_default_params(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pm_update_modem_sleep_default_params; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a8 = (uint32_t)&g_pm_cfg; /* 0007: l32r a8, 0 <pm_update_modem_sleep_default_params-0x4> (0 <pm_update_modem_sleep_default_params-0x4>) */ /* literal @0x0: g_pm_cfg */
  a9 = 0x1F4; /* 000a: movi a9, 0x1f4 */
  MEM32(a8 + 4) = a9; /* 000d: s32i.n a9, a8, 4 */
  MEMW(); /* 000f: memw  */
  return (int32_t)a2; /* 0012: retw.n  */
}

/* pm_update_light_sleep_default_params @ pm.o 00000004 size 16B bind GLOBAL
 * Calls: none | Data refs: g_pm_cfg
 *   MMIO: none
 *   funcdb v3: 0 call(s), 1 ref(s); disasm: 0 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t pm_update_light_sleep_default_params(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pm_update_light_sleep_default_params; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a8 = (uint32_t)&g_pm_cfg; /* 0007: l32r a8, 0 <pm_update_light_sleep_default_params-0x4> (0 <pm_update_light_sleep_default_params-0x4>) */ /* literal @0x0: g_pm_cfg */
  a9 = 0x1F4; /* 000a: movi a9, 0x1f4 */
  MEM32(a8 + 4) = a9; /* 000d: s32i.n a9, a8, 4 */
  MEMW(); /* 000f: memw  */
  return (int32_t)a2; /* 0012: retw.n  */
}

/* pm_set_sleep_min_active_time @ pm.o 00000004 size 13B bind GLOBAL
 * Calls: none | Data refs: g_pm_cfg
 *   MMIO: none
 *   funcdb v3: 0 call(s), 1 ref(s); disasm: 0 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t pm_set_sleep_min_active_time(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pm_set_sleep_min_active_time; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a8 = (uint32_t)&g_pm_cfg; /* 0007: l32r a8, 0 <pm_set_sleep_min_active_time-0x4> (0 <pm_set_sleep_min_active_time-0x4>) */ /* literal @0x0: g_pm_cfg */
  MEM32(a8 + 20) = a2; /* 000a: s32i.n a2, a8, 20 */
  MEMW(); /* 000c: memw  */
  return (int32_t)a2; /* 000f: retw.n  */
}

/* pm_set_keep_alive_time @ pm.o 00000004 size 13B bind GLOBAL
 * Calls: none | Data refs: g_pm_cfg
 *   MMIO: none
 *   funcdb v3: 0 call(s), 1 ref(s); disasm: 0 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t pm_set_keep_alive_time(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pm_set_keep_alive_time; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a8 = (uint32_t)&g_pm_cfg; /* 0007: l32r a8, 0 <pm_set_keep_alive_time-0x4> (0 <pm_set_keep_alive_time-0x4>) */ /* literal @0x0: g_pm_cfg */
  MEM32(a8 + 16) = a2; /* 000a: s32i.n a2, a8, 16 */
  MEMW(); /* 000c: memw  */
  return (int32_t)a2; /* 000f: retw.n  */
}

/* pm_get_keep_alive_time @ pm.o 00000004 size 10B bind GLOBAL
 * Calls: none | Data refs: g_pm_cfg
 *   MMIO: none
 *   funcdb v3: 0 call(s), 1 ref(s); disasm: 0 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t pm_get_keep_alive_time(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pm_get_keep_alive_time; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a8 = (uint32_t)&g_pm_cfg; /* 0007: l32r a8, 0 <pm_get_keep_alive_time-0x4> (0 <pm_get_keep_alive_time-0x4>) */ /* literal @0x0: g_pm_cfg */
  a2 = MEM32(a8 + 16); /* 000a: l32i.n a2, a8, 16 */
  return (int32_t)a2; /* 000c: retw.n  */
}

/* pm_set_sleep_wait_broadcast_data_time @ pm.o 00000004 size 13B bind GLOBAL
 * Calls: none | Data refs: g_pm_cfg
 *   MMIO: none
 *   funcdb v3: 0 call(s), 1 ref(s); disasm: 0 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t pm_set_sleep_wait_broadcast_data_time(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pm_set_sleep_wait_broadcast_data_time; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a8 = (uint32_t)&g_pm_cfg; /* 0007: l32r a8, 0 <pm_set_sleep_wait_broadcast_data_time-0x4> (0 <pm_set_sleep_wait_broadcast_data_time-0x4>) */ /* literal @0x0: g_pm_cfg */
  MEM32(a8 + 44) = a2; /* 000a: s32i.n a2, a8, 44 */
  MEMW(); /* 000c: memw  */
  return (int32_t)a2; /* 000f: retw.n  */
}

/* pm_scan_lock @ pm.o 00000000 size 5B bind GLOBAL
 * Calls: none | Data refs: none
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t pm_scan_lock(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pm_scan_lock; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_0:;
  /* 0000: entry a1, 32 */
  return (int32_t)a2; /* 0003: retw.n  */
}

/* pm_scan_unlock @ pm.o 00000000 size 5B bind GLOBAL
 * Calls: none | Data refs: none
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t pm_scan_unlock(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pm_scan_unlock; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_0:;
  /* 0000: entry a1, 32 */
  return (int32_t)a2; /* 0003: retw.n  */
}

/* pm_try_scan_unlock @ pm.o 00000000 size 5B bind GLOBAL
 * Calls: none | Data refs: none
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t pm_try_scan_unlock(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pm_try_scan_unlock; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_0:;
  /* 0000: entry a1, 32 */
  return (int32_t)a2; /* 0003: retw.n  */
}

/* pm_force_scan_unlock @ pm.o 00000000 size 5B bind GLOBAL
 * Calls: none | Data refs: none
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t pm_force_scan_unlock(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pm_force_scan_unlock; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_0:;
  /* 0000: entry a1, 32 */
  return (int32_t)a2; /* 0003: retw.n  */
}

/* pm_get_idle_wait_time @ pm.o 00000000 size 7B bind GLOBAL
 * Calls: none | Data refs: none
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t pm_get_idle_wait_time(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pm_get_idle_wait_time; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_0:;
  /* 0000: entry a1, 32 */
  a2 = 0x0; /* 0003: movi.n a2, 0 */
  return (int32_t)a2; /* 0005: retw.n  */
}

/* pm_enable_sta_disconnected_power_management @ pm.o 00000004 size 58B bind GLOBAL
 * Calls: none | Data refs: g_pm
 *   MMIO: none
 *   funcdb v3: 0 call(s), 1 ref(s); disasm: 0 call(s), 1 data ref(s)
 * Fidelity: medium - 22 instr, 5 branches, calls resolved */
int32_t pm_enable_sta_disconnected_power_management(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pm_enable_sta_disconnected_power_management; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a9 = (uint32_t)&g_pm; /* 0007: l32r a9, 0 <pm_enable_sta_disconnected_power_management-0x4> (0 <pm_enable_sta_disconnected_power_management-0x4>) */ /* literal @0x0: g_pm */
  a2 = (a2 >> 0) & 0xFF; /* 000a: extui a2, a2, 0, 8 */
  a8 = a9 + ((0x100) << 8); /* 000d: addmi a8, a9, 0x100 */
  a10 = MEM8(a8 + 29); /* 0010: l8ui a10, a8, 29 */
  if (a10 >= 2) goto L_3a; /* 0013: bgeui a10, 2, 3a <pm_enable_sta_disconnected_power_management+0x36> */
  a9 = MEM8(a9 + 13); /* 0016: l8ui a9, a9, 13 */
  if (a9 != 0) goto L_3a; /* 0019: bnez.n a9, 3a <pm_enable_sta_disconnected_power_management+0x36> */
  if (a2 == 0) goto L_2c; /* 001b: beqz.n a2, 2c <pm_enable_sta_disconnected_power_management+0x28> */
  a9 = 0x1; /* 001d: movi.n a9, 1 */
  MEM8(a8 + 29) = a9; /* 001f: s8i a9, a8, 29 */
  MEMW(); /* 0022: memw  */
  MEMW(); /* 0025: memw  */
  goto L_3c; /* 0028: j 3c <pm_enable_sta_disconnected_power_management+0x38> */
  /* 002b: .byte 00 */
L_2c:;
  MEM8(a8 + 29) = a2; /* 002c: s8i a2, a8, 29 */
  MEMW(); /* 002f: memw  */
  a2 = 0x1; /* 0032: movi.n a2, 1 */
  MEMW(); /* 0034: memw  */
  goto L_3c; /* 0037: j 3c <pm_enable_sta_disconnected_power_management+0x38> */
L_3a:;
  a2 = 0x0; /* 003a: movi.n a2, 0 */
L_3c:;
  return (int32_t)a2; /* 003c: retw.n  */
}

/* pm_register_connectionless_wake_window @ pm.o 00000014 size 122B bind GLOBAL
 * Calls: pm_coex_schm_process_restart, pm_on_coex_schm_status_config, pm_update_by_connectionless_status | Data refs: g_osi_funcs_p, g_pm, pm_coex_schm_process_restart, pm_on_coex_schm_status_config, pm_update_by_connectionless_status
 *   MMIO: none
 *   funcdb v3: 3 call(s), 5 ref(s); disasm: 3 call(s), 5 data ref(s)
 * Fidelity: medium - 47 instr, 9 branches, calls resolved */
int32_t pm_register_connectionless_wake_window(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pm_register_connectionless_wake_window; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_14:;
  /* 0014: entry a1, 48 */
  if (a2 == 0) goto L_8c; /* 0017: beqz a2, 8c <pm_register_connectionless_wake_window+0x78> */
  a3 = MEM16(a2 + 0); /* 001a: l16ui a3, a2, 0 */
  if (a3 == 0) goto L_8c; /* 001d: beqz a3, 8c <pm_register_connectionless_wake_window+0x78> */
  a10 = 0x8; /* 0020: movi.n a10, 8 */
  a4 = (uint32_t)&g_osi_funcs_p; /* 0022: l32r a4, 0 <pm_register_connectionless_wake_window-0x14> (0 <pm_register_connectionless_wake_window-0x14>) */ /* literal @0x0: g_osi_funcs_p */
  a3 = MEM32(a4 + 0); /* 0025: l32i.n a3, a4, 0 */
  a3 = MEM32(a3 + 364); /* 0027: l32i a3, a3, 0x16c */
  ((int32_t(*)())a3)(a2, a3, a4, a5); /* 002a: callx8 a3 */ /* indirect */
  if (a10 == 0) goto L_8c; /* 002d: beqz a10, 8c <pm_register_connectionless_wake_window+0x78> */
  a3 = 0x0; /* 0030: movi.n a3, 0 */
  MEM32(a10 + 4) = a3; /* 0032: s32i.n a3, a10, 4 */
  a3 = (uint32_t)&g_pm; /* 0034: l32r a3, 4 <pm_register_connectionless_wake_window-0x10> (0 <pm_register_connectionless_wake_window-0x14>) */ /* literal @0x4: g_pm */
  a8 = MEM32(a3 + 352); /* 0037: l32i a8, a3, 0x160 */
  MEM32(a10 + 0) = a2; /* 003a: s32i.n a2, a10, 0 */
  MEM32(a1 + 4) = a8; /* 003c: s32i.n a8, a1, 4 */
  a8 = a1; /* 003e: mov.n a8, a1 */
  MEMW(); /* 0040: memw  */
  goto L_5a; /* 0043: j 5a <pm_register_connectionless_wake_window+0x46> */
L_46:;
  a11 = MEM32(a8 + 0); /* 0046: l32i.n a11, a8, 0 */
  a12 = MEM16(a11 + 0); /* 0048: l16ui a12, a11, 0 */
  a11 = MEM16(a2 + 0); /* 004b: l16ui a11, a2, 0 */
  if (a12 >= a11) goto L_5a; /* 004e: bgeu a12, a11, 5a <pm_register_connectionless_wake_window+0x46> */
  MEM32(a10 + 4) = a8; /* 0051: s32i.n a8, a10, 4 */
  MEMW(); /* 0053: memw  */
  goto L_61; /* 0056: j 61 <pm_register_connectionless_wake_window+0x4d> */
  /* 0059: .byte 00 */
L_5a:;
  a9 = a8; /* 005a: mov.n a9, a8 */
  a8 = MEM32(a8 + 4); /* 005c: l32i.n a8, a8, 4 */
  if (a8 != 0) goto L_46; /* 005e: bnez a8, 46 <pm_register_connectionless_wake_window+0x32> */
L_61:;
  MEM32(a9 + 4) = a10; /* 0061: s32i.n a10, a9, 4 */
  a2 = MEM32(a1 + 4); /* 0063: l32i.n a2, a1, 4 */
  MEM32(a3 + 352) = a2; /* 0065: s32i a2, a3, 0x160 */
  MEMW(); /* 0068: memw  */
  a8 = (uint32_t)&pm_update_by_connectionless_status; /* 006b: l32r a8, 8 <pm_register_connectionless_wake_window-0xc> (0 <pm_register_connectionless_wake_window-0x14>) */ /* literal: GOT slot for pm_update_by_connectionless_status */
  pm_update_by_connectionless_status(a2, a3, a4, a5); /* call via literal slot */ /* 006e: callx8 a8 */
  a10 = MEM8(a3 + 13); /* 0071: l8ui a10, a3, 13 */
  if (a10 != 0) goto L_8c; /* 0074: bnez.n a10, 8c <pm_register_connectionless_wake_window+0x78> */
  a8 = (uint32_t)&pm_on_coex_schm_status_config; /* 0076: l32r a8, c <pm_register_connectionless_wake_window-0x8> (0 <pm_register_connectionless_wake_window-0x14>) */ /* literal: GOT slot for pm_on_coex_schm_status_config */
  pm_on_coex_schm_status_config(a2, a3, a4, a5); /* call via literal slot */ /* 0079: callx8 a8 */
  a2 = MEM32(a4 + 0); /* 007c: l32i.n a2, a4, 0 */
  a10 = MEM32(a2 + 404); /* 007e: l32i a10, a2, 0x194 */
  ((int32_t(*)())a10)(a2, a3, a4, a5); /* 0081: callx8 a10 */ /* indirect */
  if (a10 == 0) goto L_8c; /* 0084: beqz.n a10, 8c <pm_register_connectionless_wake_window+0x78> */
  a8 = (uint32_t)&pm_coex_schm_process_restart; /* 0086: l32r a8, 10 <pm_register_connectionless_wake_window-0x4> (0 <pm_register_connectionless_wake_window-0x14>) */ /* literal: GOT slot for pm_coex_schm_process_restart */
  pm_coex_schm_process_restart(a2, a3, a4, a5); /* call via literal slot */ /* 0089: callx8 a8 */
L_8c:;
  return (int32_t)a2; /* 008c: retw.n  */
}

/* pm_unregister_connectionless_wake_window @ pm.o 00000014 size 102B bind GLOBAL
 * Calls: pm_coex_schm_process_restart, pm_on_coex_schm_status_config, pm_update_by_connectionless_status, g_osi_funcs_p[got] | Data refs: g_osi_funcs_p, g_pm, pm_coex_schm_process_restart, pm_on_coex_schm_status_config, pm_update_by_connectionless_status
 *   MMIO: none
 *   funcdb v3: 3 call(s), 5 ref(s); disasm: 4 call(s), 5 data ref(s)
 * Fidelity: medium - 38 instr, 7 branches, calls resolved */
int32_t pm_unregister_connectionless_wake_window(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pm_unregister_connectionless_wake_window; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_14:;
  /* 0014: entry a1, 48 */
  if (a2 == 0) goto L_78; /* 0017: beqz a2, 78 <pm_unregister_connectionless_wake_window+0x64> */
  a3 = (uint32_t)&g_pm; /* 001a: l32r a3, 0 <pm_unregister_connectionless_wake_window-0x14> (0 <pm_unregister_connectionless_wake_window-0x14>) */ /* literal @0x0: g_pm */
  a10 = a1; /* 001d: mov.n a10, a1 */
  a8 = MEM32(a3 + 352); /* 001f: l32i a8, a3, 0x160 */
  MEM32(a1 + 4) = a8; /* 0022: s32i.n a8, a1, 4 */
  MEMW(); /* 0024: memw  */
  goto L_44; /* 0027: j 44 <pm_unregister_connectionless_wake_window+0x30> */
L_2a:;
  a9 = MEM32(a10 + 0); /* 002a: l32i.n a9, a10, 0 */
  if (a9 != a2) goto L_44; /* 002c: bne a9, a2, 44 <pm_unregister_connectionless_wake_window+0x30> */
  a2 = MEM32(a10 + 4); /* 002f: l32i.n a2, a10, 4 */
  MEM32(a8 + 4) = a2; /* 0031: s32i.n a2, a8, 4 */
  a2 = (uint32_t)&g_osi_funcs_p; /* 0033: l32r a2, 4 <pm_unregister_connectionless_wake_window-0x10> (0 <pm_unregister_connectionless_wake_window-0x14>) */ /* literal @0x4: g_osi_funcs_p */
  a2 = MEM32(a2 + 0); /* 0036: l32i.n a2, a2, 0 */
  a2 = MEM32(a2 + 176); /* 0038: l32i a2, a2, 176 */
  MEMW(); /* 003b: memw  */
  g_osi_funcs_p(a2, a3, a4, a5); /* call via literal slot */ /* 003e: callx8 a2 */
  goto L_4b; /* 0041: j 4b <pm_unregister_connectionless_wake_window+0x37> */
L_44:;
  a8 = a10; /* 0044: mov.n a8, a10 */
  a10 = MEM32(a10 + 4); /* 0046: l32i.n a10, a10, 4 */
  if (a10 != 0) goto L_2a; /* 0048: bnez a10, 2a <pm_unregister_connectionless_wake_window+0x16> */
L_4b:;
  a2 = MEM32(a1 + 4); /* 004b: l32i.n a2, a1, 4 */
  MEM32(a3 + 352) = a2; /* 004d: s32i a2, a3, 0x160 */
  MEMW(); /* 0050: memw  */
  a8 = (uint32_t)&pm_update_by_connectionless_status; /* 0053: l32r a8, 8 <pm_unregister_connectionless_wake_window-0xc> (0 <pm_unregister_connectionless_wake_window-0x14>) */ /* literal: GOT slot for pm_update_by_connectionless_status */
  pm_update_by_connectionless_status(a2, a3, a4, a5); /* call via literal slot */ /* 0056: callx8 a8 */
  a10 = MEM8(a3 + 13); /* 0059: l8ui a10, a3, 13 */
  if (a10 != 0) goto L_78; /* 005c: bnez a10, 78 <pm_unregister_connectionless_wake_window+0x64> */
  a8 = (uint32_t)&pm_on_coex_schm_status_config; /* 005f: l32r a8, c <pm_unregister_connectionless_wake_window-0x8> (0 <pm_unregister_connectionless_wake_window-0x14>) */ /* literal: GOT slot for pm_on_coex_schm_status_config */
  pm_on_coex_schm_status_config(a2, a3, a4, a5); /* call via literal slot */ /* 0062: callx8 a8 */
  a2 = (uint32_t)&g_osi_funcs_p; /* 0065: l32r a2, 4 <pm_unregister_connectionless_wake_window-0x10> (0 <pm_unregister_connectionless_wake_window-0x14>) */ /* literal @0x4: g_osi_funcs_p */
  a2 = MEM32(a2 + 0); /* 0068: l32i.n a2, a2, 0 */
  a10 = MEM32(a2 + 404); /* 006a: l32i a10, a2, 0x194 */
  ((int32_t(*)())a10)(a2, a3, a4, a5); /* 006d: callx8 a10 */ /* indirect */
  if (a10 == 0) goto L_78; /* 0070: beqz.n a10, 78 <pm_unregister_connectionless_wake_window+0x64> */
  a8 = (uint32_t)&pm_coex_schm_process_restart; /* 0072: l32r a8, 10 <pm_unregister_connectionless_wake_window-0x4> (0 <pm_unregister_connectionless_wake_window-0x14>) */ /* literal: GOT slot for pm_coex_schm_process_restart */
  pm_coex_schm_process_restart(a2, a3, a4, a5); /* call via literal slot */ /* 0075: callx8 a8 */
L_78:;
  return (int32_t)a2; /* 0078: retw.n  */
}

/* pm_connectionless_module_set_wake_interval @ pm.o 00000008 size 23B bind GLOBAL
 * Calls: pm_update_by_connectionless_status | Data refs: g_pm, pm_update_by_connectionless_status
 *   MMIO: none
 *   funcdb v3: 1 call(s), 2 ref(s); disasm: 1 call(s), 2 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t pm_connectionless_module_set_wake_interval(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pm_connectionless_module_set_wake_interval; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_8:;
  /* 0008: entry a1, 32 */
  a8 = (uint32_t)&g_pm; /* 000b: l32r a8, 0 <pm_connectionless_module_set_wake_interval-0x8> (0 <pm_connectionless_module_set_wake_interval-0x8>) */ /* literal @0x0: g_pm */
  MEM16(a8 + 394) = a2; /* 000e: s16i a2, a8, 0x18a */
  MEMW(); /* 0011: memw  */
  MEMW(); /* 0014: memw  */
  a8 = (uint32_t)&pm_update_by_connectionless_status; /* 0017: l32r a8, 4 <pm_connectionless_module_set_wake_interval-0x4> (0 <pm_connectionless_module_set_wake_interval-0x8>) */ /* literal: GOT slot for pm_update_by_connectionless_status */
  pm_update_by_connectionless_status(a2, a3, a4, a5); /* call via literal slot */ /* 001a: callx8 a8 */
  return (int32_t)a2; /* 001d: retw.n  */
}

/* pm_set_beacon_duration @ pm.o 00000010 size 53B bind GLOBAL
 * Calls: pm_on_sample_beacon[got], wifi_log[got] | Data refs: g_pm, pm_on_sample_beacon, .rodata_wlog_debug.63, wifi_log
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 2 call(s), 4 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t pm_set_beacon_duration(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .wifislprxiram.62; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_10:;
  /* 0010: entry a1, 32 */
  a3 = (uint32_t)&g_pm; /* 0013: l32r a3, 0 <pm_set_beacon_duration-0x10> (0 <pm_set_beacon_duration-0x10>) */ /* literal @0x0: g_pm */
  a8 = MEM32(a3 + 464); /* 0016: l32i a8, a3, 0x1d0 */
  if (a8 == a2) goto L_40; /* 0019: beq a8, a2, 40 <pm_set_beacon_duration+0x30> */
  if (a8 != 0) goto L_25; /* 001c: bnez a8, 25 <pm_set_beacon_duration+0x15> */
  a8 = (uint32_t)&pm_on_sample_beacon; /* 001f: l32r a8, 8 <pm_set_beacon_duration-0x8> (0 <pm_set_beacon_duration-0x10>) */ /* literal: GOT slot for pm_on_sample_beacon */
  pm_on_sample_beacon(a2, a3, a4, a5); /* call via literal slot */ /* 0022: callx8 a8 */
L_25:;
  a14 = MEM32(a3 + 464); /* 0025: l32i a14, a3, 0x1d0 */
  a11 = 0x1; /* 0028: movi.n a11, 1 */
  a15 = a2; /* 002a: mov.n a15, a2 */
  a12 = 0x4; /* 002c: movi.n a12, 4 */
  a11 = 0x1000; /* 002e: slli a11, a11, 12 */
  a13 = (uint32_t)&lit_rodata_wlog_debug_63; /* 0031: l32r a13, 4 <pm_set_beacon_duration-0xc> (0 <pm_set_beacon_duration-0x10>) */ /* literal @0x4: .rodata_wlog_debug.63 */
  a10 = 0x1; /* 0034: movi a10, 1 */
  a8 = (uint32_t)&wifi_log; /* 0037: l32r a8, c <pm_set_beacon_duration-0x4> (0 <pm_set_beacon_duration-0x10>) */ /* literal: GOT slot for wifi_log */
  wifi_log(a2, a3, a4, a5); /* call via literal slot */ /* 003a: callx8 a8 */
  MEM32(a3 + 464) = a2; /* 003d: s32i a2, a3, 0x1d0 */
L_40:;
  MEMW(); /* 0040: memw  */
  return (int32_t)a2; /* 0043: retw.n  */
}

/* pm_get_beacon_duration @ pm.o 00000004 size 11B bind GLOBAL
 * Calls: none | Data refs: g_pm
 *   MMIO: none
 *   funcdb v3: 0 call(s), 1 ref(s); disasm: 0 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t pm_get_beacon_duration(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pm_get_beacon_duration; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a8 = (uint32_t)&g_pm; /* 0007: l32r a8, 0 <pm_get_beacon_duration-0x4> (0 <pm_get_beacon_duration-0x4>) */ /* literal @0x0: g_pm */
  a2 = MEM32(a8 + 464); /* 000a: l32i a2, a8, 0x1d0 */
  return (int32_t)a2; /* 000d: retw.n  */
}

/* pm_beacon_add_total_counter @ pm.o 00000008 size 31B bind GLOBAL
 * Calls: ptr_beacon_offset_funcs[got] | Data refs: g_pm, ptr_beacon_offset_funcs
 *   MMIO: none
 *   funcdb v3: 0 call(s), 2 ref(s); disasm: 1 call(s), 2 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t pm_beacon_add_total_counter(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pm_beacon_add_total_counter; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_8:;
  /* 0008: entry a1, 32 */
  a9 = (uint32_t)&g_pm; /* 000b: l32r a9, 0 <pm_beacon_add_total_counter-0x8> (0 <pm_beacon_add_total_counter-0x8>) */ /* literal @0x0: g_pm */
  a8 = MEM32(a9 + 532); /* 000e: l32i a8, a9, 0x214 */
  a8 = a8 + (1); /* 0011: addi.n a8, a8, 1 */
  MEM32(a9 + 532) = a8; /* 0013: s32i a8, a9, 0x214 */
  a8 = (uint32_t)&ptr_beacon_offset_funcs; /* 0016: l32r a8, 4 <pm_beacon_add_total_counter-0x4> (0 <pm_beacon_add_total_counter-0x8>) */ /* literal @0x4: ptr_beacon_offset_funcs */
  a8 = MEM32(a8 + 0); /* 0019: l32i.n a8, a8, 0 */
  a8 = MEM32(a8 + 36); /* 001b: l32i.n a8, a8, 36 */
  if (a8 == 0) goto L_25; /* 001d: beqz.n a8, 25 <pm_beacon_add_total_counter+0x1d> */
  MEMW(); /* 001f: memw  */
  ptr_beacon_offset_funcs(a2, a3, a4, a5); /* call via literal slot */ /* 0022: callx8 a8 */
L_25:;
  return (int32_t)a2; /* 0025: retw.n  */
}

/* pm_enable_beacon_monitor_timer @ pm.o 0000001c size 290B bind GLOBAL
 * Calls: __udivdi3[got], pm_beacon_miss_exceeded_wakeup_disabled[got], pm_beacon_add_total_counter[got], g_osi_funcs_p[got], pm_beacon_monitor_tbtt_allowed[got], pm_beacon_monitor_tbtt_start[got] | Data refs: ptr_beacon_offset_funcs, g_osi_funcs_p, __udivdi3, pm_beacon_miss_exceeded_wakeup_disabled, pm_beacon_add_total_counter, pm_beacon_monitor_tbtt_allowed, pm_beacon_monitor_tbtt_start
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 6 call(s), 7 data ref(s)
 * Fidelity: low - 109 instr, 22 branches, 3 indirect; call-sequence + MMIO skeleton */
int32_t pm_enable_beacon_monitor_timer(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .wifislprxiram.28; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_1c:;
  /* 001c: entry a1, 48 */
  a8 = (uint32_t)&ptr_beacon_offset_funcs; /* 001f: l32r a8, 0 <pm_enable_beacon_monitor_timer-0x1c> (0 <pm_enable_beacon_monitor_timer-0x1c>) */ /* literal @0x0: ptr_beacon_offset_funcs */
  a6 = a2 + ((0x100) << 8); /* 0022: addmi a6, a2, 0x100 */
  a4 = MEM32(a8 + 0); /* 0025: l32i.n a4, a8, 0 */
  a3 = MEM8(a6 + 124); /* 0027: l8ui a3, a6, 124 */
  a3 = a3 << (10 & 31); /* 002a: slli a3, a3, 10 */
  a10 = MEM32(a4 + 16); /* 002d: l32i.n a10, a4, 16 */
  a7 = MEM8(a6 + 214); /* 002f: l8ui a7, a6, 214 */
  a5 = MEM8(a6 + 215); /* 0032: l8ui a5, a6, 215 */
  if (a10 != 0) goto L_45; /* 0035: bnez a10, 45 <pm_enable_beacon_monitor_timer+0x29> */
L_38:;
  a4 = MEM8(a6 + 125); /* 0038: l8ui a4, a6, 125 */
  a4 = a4 << (10 & 31); /* 003b: slli a4, a4, 10 */
  a3 = a4 + a3; /* 003e: add.n a3, a4, a3 */
  goto L_ab; /* 0040: j ab <pm_enable_beacon_monitor_timer+0x8f> */
  /* 0043: .byte 00 */
  /* 0044: .byte 00 */
L_45:;
  ((int32_t(*)())a10)(a2, a3, a4, a5); /* 0045: callx8 a10 */ /* indirect */
  if (a10 == 0) goto L_38; /* 0048: beqz a10, 38 <pm_enable_beacon_monitor_timer+0x1c> */
  a4 = (uint32_t)&g_osi_funcs_p; /* 004b: l32r a4, 4 <pm_enable_beacon_monitor_timer-0x18> (0 <pm_enable_beacon_monitor_timer-0x1c>) */ /* literal @0x4: g_osi_funcs_p */
  a4 = MEM32(a4 + 0); /* 004e: l32i.n a4, a4, 0 */
  a10 = MEM32(a4 + 272); /* 0050: l32i a10, a4, 0x110 */
  ((int32_t(*)())a10)(a2, a3, a4, a5); /* 0053: callx8 a10 */ /* indirect */
  a14 = a10 | a10; /* 0056: or a14, a10, a10 */
  a12 = MEM32(a2 + 92); /* 0059: l32i a12, a2, 92 */
  a4 = MEM32(a2 + 88); /* 005c: l32i a4, a2, 88 */
  if (a11 < a12) goto L_68; /* 005f: bltu a11, a12, 68 <pm_enable_beacon_monitor_timer+0x4c> */
  if (a12 != a11) goto L_99; /* 0062: bne a12, a11, 99 <pm_enable_beacon_monitor_timer+0x7d> */
  if (a10 >= a4) goto L_99; /* 0065: bgeu a10, a4, 99 <pm_enable_beacon_monitor_timer+0x7d> */
L_68:;
  a10 = a4 - a14; /* 0068: sub a10, a4, a14 */
  a9 = MEM32(a2 + 44); /* 006b: l32i.n a9, a2, 44 */
  a15 = 0x1; /* 006d: movi.n a15, 1 */
  if (a4 < a10) goto L_75; /* 006f: bltu a4, a10, 75 <pm_enable_beacon_monitor_timer+0x59> */
  a15 = 0x0; /* 0072: movi a15, 0 */
L_75:;
  a11 = a12 - a11; /* 0075: sub a11, a12, a11 */
  a13 = 0x0; /* 0078: movi.n a13, 0 */
  a12 = a9; /* 007a: mov.n a12, a9 */
  a11 = a11 - a15; /* 007c: sub a11, a11, a15 */
  MEM32(a1 + 4) = a9; /* 007f: s32i.n a9, a1, 4 */
  MEM32(a1 + 0) = a14; /* 0081: s32i a14, a1, 0 */
  MEMW(); /* 0084: memw  */
  a8 = (uint32_t)&udivdi3; /* 0087: l32r a8, 8 <pm_enable_beacon_monitor_timer-0x14> (0 <pm_enable_beacon_monitor_timer-0x1c>) */ /* literal: GOT slot for __udivdi3 */
  udivdi3(a2, a3, a4, a5); /* call via literal slot */ /* 008a: callx8 a8 */
  a10 = a10 + (1); /* 008d: addi.n a10, a10, 1 */
  a9 = MEM32(a1 + 4); /* 008f: l32i.n a9, a1, 4 */
  a10 = (uint32_t)((uint64_t)a10 * a9); /* 0091: mull a10, a10, a9 */
  a4 = a4 - a10; /* 0094: sub a4, a4, a10 */
  a14 = MEM32(a1 + 0); /* 0097: l32i.n a14, a1, 0 */
L_99:;
  a10 = a14 - a4; /* 0099: sub a10, a14, a4 */
  a11 = 0x0; /* 009c: movi.n a11, 0 */
  a9 = MEM32(a2 + 40); /* 009e: l32i.n a9, a2, 40 */
  if (a10 >= a9) goto L_a9; /* 00a0: bgeu a10, a9, a9 <pm_enable_beacon_monitor_timer+0x8d> */
  a9 = a9 - a14; /* 00a3: sub a9, a9, a14 */
  a11 = a9 + a4; /* 00a6: add a11, a9, a4 */
L_a9:;
  a3 = a3 + a11; /* 00a9: add.n a3, a3, a11 */
L_ab:;
  a4 = MEM8(a6 + 100); /* 00ab: l8ui a4, a6, 100 */
  if (a4 != 0) goto L_b5; /* 00ae: bnez.n a4, b5 <pm_enable_beacon_monitor_timer+0x99> */
L_b0:;
  a3 = 0x0; /* 00b0: movi.n a3, 0 */
  goto L_132; /* 00b2: j 132 <pm_enable_beacon_monitor_timer+0x116> */
L_b5:;
  a8 = MEM8(a6 + 212); /* 00b5: l8ui a8, a6, 212 */
  if (a8 != 0) goto L_b0; /* 00b8: bnez a8, b0 <pm_enable_beacon_monitor_timer+0x94> */
  a4 = MEM8(a2 + 13); /* 00bb: l8ui a4, a2, 13 */
  if (a4 == 0) goto L_b0; /* 00be: beqz a4, b0 <pm_enable_beacon_monitor_timer+0x94> */
  MEM32(a1 + 0) = a8; /* 00c1: s32i.n a8, a1, 0 */
  MEMW(); /* 00c3: memw  */
  a8 = (uint32_t)&pm_beacon_miss_exceeded_wakeup_disabled; /* 00c6: l32r a8, c <pm_enable_beacon_monitor_timer-0x10> (0 <pm_enable_beacon_monitor_timer-0x1c>) */ /* literal: GOT slot for pm_beacon_miss_exceeded_wakeup_disabled */
  pm_beacon_miss_exceeded_wakeup_disabled(a2, a3, a4, a5); /* call via literal slot */ /* 00c9: callx8 a8 */
  a9 = MEM16(a2 + 384); /* 00cc: l16si a9, a2, 0x180 */
  a4 = MEM16(a2 + 386); /* 00cf: l16si a4, a2, 0x182 */
  a8 = MEM32(a1 + 0); /* 00d2: l32i.n a8, a1, 0 */
  if (a10 == 0) goto L_eb; /* 00d4: beqz.n a10, eb <pm_enable_beacon_monitor_timer+0xcf> */
  if (a9 >= a4) goto L_e5; /* 00d6: bge a9, a4, e5 <pm_enable_beacon_monitor_timer+0xc9> */
L_d9:;
  a6 = (uint32_t)&ptr_beacon_offset_funcs; /* 00d9: l32r a6, 0 <pm_enable_beacon_monitor_timer-0x1c> (0 <pm_enable_beacon_monitor_timer-0x1c>) */ /* literal @0x0: ptr_beacon_offset_funcs */
  a4 = MEM32(a6 + 0); /* 00dc: l32i.n a4, a6, 0 */
  a10 = MEM32(a4 + 12); /* 00de: l32i.n a10, a4, 12 */
  if (a10 != 0) goto L_121; /* 00e0: bnez.n a10, 121 <pm_enable_beacon_monitor_timer+0x105> */
  goto L_f7; /* 00e2: j f7 <pm_enable_beacon_monitor_timer+0xdb> */
L_e5:;
  MEM16(a2 + 384) = a8; /* 00e5: s16i a8, a2, 0x180 */
  MEMW(); /* 00e8: memw  */
L_eb:;
  a8 = MEM16(a2 + 384); /* 00eb: l16si a8, a2, 0x180 */
  if (a8 >= a4) goto L_b0; /* 00ee: bge a8, a4, b0 <pm_enable_beacon_monitor_timer+0x94> */
  MEMW(); /* 00f1: memw  */
  goto L_d9; /* 00f4: j d9 <pm_enable_beacon_monitor_timer+0xbd> */
L_f7:;
  a8 = (uint32_t)&pm_beacon_add_total_counter; /* 00f7: l32r a8, 10 <pm_enable_beacon_monitor_timer-0xc> (0 <pm_enable_beacon_monitor_timer-0x1c>) */ /* literal: GOT slot for pm_beacon_add_total_counter */
  pm_beacon_add_total_counter(a2, a3, a4, a5); /* call via literal slot */ /* 00fa: callx8 a8 */
  a4 = (uint32_t)&g_osi_funcs_p; /* 00fd: l32r a4, 4 <pm_enable_beacon_monitor_timer-0x18> (0 <pm_enable_beacon_monitor_timer-0x1c>) */ /* literal @0x4: g_osi_funcs_p */
  a10 = 0x168; /* 0100: movi a10, 0x168 */
  a11 = a3; /* 0103: mov.n a11, a3 */
  a12 = 0x0; /* 0105: movi.n a12, 0 */
  a10 = a2 + a10; /* 0107: add.n a10, a2, a10 */
  a4 = MEM32(a4 + 0); /* 0109: l32i.n a4, a4, 0 */
  a4 = MEM32(a4 + 248); /* 010b: l32i a4, a4, 248 */
  g_osi_funcs_p(a2, a3, a4, a5); /* call via literal slot */ /* 010e: callx8 a4 */
  a10 = a2; /* 0111: mov.n a10, a2 */
  a8 = (uint32_t)&pm_beacon_monitor_tbtt_allowed; /* 0113: l32r a8, 14 <pm_enable_beacon_monitor_timer-0x8> (0 <pm_enable_beacon_monitor_timer-0x1c>) */ /* literal: GOT slot for pm_beacon_monitor_tbtt_allowed */
  pm_beacon_monitor_tbtt_allowed(a2, a3, a4, a5); /* call via literal slot */ /* 0116: callx8 a8 */
  a3 = a10; /* 0119: mov.n a3, a10 */
  if (a10 == 0) goto L_b0; /* 011b: beqz a10, b0 <pm_enable_beacon_monitor_timer+0x94> */
  goto L_12a; /* 011e: j 12a <pm_enable_beacon_monitor_timer+0x10e> */
L_121:;
  ((int32_t(*)())a10)(a2, a3, a4, a5); /* 0121: callx8 a10 */ /* indirect */
  if (a10 != 0) goto L_b0; /* 0124: bnez a10, b0 <pm_enable_beacon_monitor_timer+0x94> */
  goto L_f7; /* 0127: j f7 <pm_enable_beacon_monitor_timer+0xdb> */
L_12a:;
  a10 = a2; /* 012a: mov.n a10, a2 */
  a8 = (uint32_t)&pm_beacon_monitor_tbtt_start; /* 012c: l32r a8, 18 <pm_enable_beacon_monitor_timer-0x4> (0 <pm_enable_beacon_monitor_timer-0x1c>) */ /* literal: GOT slot for pm_beacon_monitor_tbtt_start */
  pm_beacon_monitor_tbtt_start(a2, a3, a4, a5); /* call via literal slot */ /* 012f: callx8 a8 */
L_132:;
  a5 = a5 + (-1); /* 0132: addi.n a5, a5, -1 */
  a5 = a5 - a7; /* 0134: sub a5, a5, a7 */
  a2 = 0x1; /* 0137: movi.n a2, 1 */
  if (a5 != 0) a2 = a3; /* 0139: movnez a2, a3, a5 */
  return (int32_t)a2; /* 013c: retw.n  */
}

/* pm_tbtt_process @ pm.o 00000068 size 419B bind GLOBAL
 * Calls: pm_check_state[got], .text.hal_pm_unblock_txq[got], pm_save_tbtt_info[got], pm_enable_beacon_monitor_timer[got], g_pm[got], pm_beacon_monitor_tbtt_allowed[got], pm_coex_schm_overall_period_get[got], pm_beacon_monitor_tbtt_start[got], wifi_gpio_debug[got], pm_dream[got], g_pm[got], g_pm[got], pm_coex_tbtt_process[got], pm_noise_check[got], pm_mesh_set_next_tbtt[got], pm_set_next_tbtt[got], pm_go_to_wake[got], pm_update_params[got], pm_update_by_connectionless_status[got] | Data refs: g_osi_funcs_p, pm_check_state, g_pm, .text.hal_pm_unblock_txq, pm_save_tbtt_info, pm_enable_beacon_monitor_timer, pm_beacon_monitor_tbtt_allowed, pm_coex_schm_overall_period_get, pm_beacon_monitor_tbtt_start, wifi_gpio_debug, g_pm_cnt, pm_dream, g_mesh_is_started, g_mesh_is_root, g_mesh_init_ps_type, g_wifi_mac_time_delta, pm_coex_tbtt_process, pm_noise_check, pm_mesh_set_next_tbtt, pm_set_next_tbtt, pm_go_to_wake, pm_update_params, pm_update_by_connectionless_status
 *   MMIO: 0x3FF73C00
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 19 call(s), 23 data ref(s)
 * Fidelity: low - 153 instr, 28 branches, 3 indirect; call-sequence + MMIO skeleton */
int32_t pm_tbtt_process(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .wifislprxiram.46; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_68:;
  /* 0068: entry a1, 32 */
  a7 = (uint32_t)&g_osi_funcs_p; /* 006b: l32r a7, 0 <pm_tbtt_process-0x68> (0 <pm_tbtt_process-0x68>) */ /* literal @0x0: g_osi_funcs_p */
  a2 = MEM32(a7 + 0); /* 006e: l32i.n a2, a7, 0 */
  a10 = MEM32(a2 + 272); /* 0070: l32i a10, a2, 0x110 */
  ((int32_t(*)())a10)(a2, a3, a4, a5); /* 0073: callx8 a10 */ /* indirect */
  a4 = a10; /* 0076: mov.n a4, a10 */
  a5 = a11 | a11; /* 0078: or a5, a11, a11 */
  a8 = (uint32_t)&pm_check_state; /* 007b: l32r a8, 28 <pm_tbtt_process-0x40> (0 <pm_tbtt_process-0x68>) */ /* literal: GOT slot for pm_check_state */
  pm_check_state(a2, a3, a4, a5); /* call via literal slot */ /* 007e: callx8 a8 */
  a2 = (uint32_t)&g_pm; /* 0081: l32r a2, 4 <pm_tbtt_process-0x64> (0 <pm_tbtt_process-0x68>) */ /* literal @0x4: g_pm */
  a3 = MEM8(a2 + 13); /* 0084: l8ui a3, a2, 13 */
  if (a3 != 0) goto L_b4; /* 0087: bnez.n a3, b4 <pm_tbtt_process+0x4c> */
  a3 = MEM32(a7 + 0); /* 0089: l32i a3, a7, 0 */
  a10 = (uint32_t)&g_pm; /* 008c: l32r a10, 8 <pm_tbtt_process-0x60> (0 <pm_tbtt_process-0x68>) */ /* literal @0x8: g_pm */
  a3 = MEM32(a3 + 236); /* 008f: l32i a3, a3, 236 */
  ((int32_t(*)())a3)(a2, a3, a4, a5); /* 0092: callx8 a3 */ /* indirect */
  a3 = MEM32(a7 + 0); /* 0095: l32i.n a3, a7, 0 */
  a10 = (uint32_t)&g_pm; /* 0097: l32r a10, c <pm_tbtt_process-0x5c> (0 <pm_tbtt_process-0x68>) */ /* literal @0xC: g_pm */
  a3 = MEM32(a3 + 236); /* 009a: l32i a3, a3, 236 */
  ((int32_t(*)())a3)(a2, a3, a4, a5); /* 009d: callx8 a3 */ /* indirect */
  a3 = 0x1; /* 00a0: movi.n a3, 1 */
  MEM8(a2 + 24) = a3; /* 00a2: s8i a3, a2, 24 */
  MEMW(); /* 00a5: memw  */
  MEMW(); /* 00a8: memw  */
  a8 = (uint32_t)&hal_pm_unblock_txq; /* 00ab: l32r a8, 2c <pm_tbtt_process-0x3c> (8 <pm_tbtt_process-0x60>) */ /* literal: GOT slot for .text.hal_pm_unblock_txq */
  hal_pm_unblock_txq(a2, a3, a4, a5); /* call via literal slot */ /* 00ae: callx8 a8 */
  goto L_209; /* 00b1: j 209 <pm_tbtt_process+0x1a1> */
L_b4:;
  a10 = a2; /* 00b4: mov.n a10, a2 */
  a6 = 0x1; /* 00b6: movi.n a6, 1 */
  a3 = MEM8(a2 + 17); /* 00b8: l8ui a3, a2, 17 */
  MEM8(a2 + 17) = a6; /* 00bb: s8i a6, a2, 17 */
  MEMW(); /* 00be: memw  */
  MEMW(); /* 00c1: memw  */
  a8 = (uint32_t)&pm_save_tbtt_info; /* 00c4: l32r a8, 30 <pm_tbtt_process-0x38> (0 <pm_tbtt_process-0x68>) */ /* literal: GOT slot for pm_save_tbtt_info */
  pm_save_tbtt_info(a2, a3, a4, a5); /* call via literal slot */ /* 00c7: callx8 a8 */
  a10 = a2; /* 00ca: mov.n a10, a2 */
  a8 = (uint32_t)&pm_enable_beacon_monitor_timer; /* 00cc: l32r a8, 34 <pm_tbtt_process-0x34> (0 <pm_tbtt_process-0x68>) */ /* literal: GOT slot for pm_enable_beacon_monitor_timer */
  pm_enable_beacon_monitor_timer(a2, a3, a4, a5); /* call via literal slot */ /* 00cf: callx8 a8 */
  if (a10 != 0) goto L_114; /* 00d2: bnez.n a10, 114 <pm_tbtt_process+0xac> */
  a6 = a2 + ((0x100) << 8); /* 00d4: addmi a6, a2, 0x100 */
  a8 = MEM8(a6 + 100); /* 00d7: l8ui a8, a6, 100 */
  if (a8 != 0) goto L_e9; /* 00da: bnez.n a8, e9 <pm_tbtt_process+0x81> */
L_dc:;
  a6 = MEM32(a7 + 0); /* 00dc: l32i.n a6, a7, 0 */
  a10 = MEM32(a6 + 404); /* 00de: l32i a10, a6, 0x194 */
  ((int32_t(*)())a10)(a2, a3, a4, a5); /* 00e1: callx8 a10 */ /* indirect */
  if (a10 == 0) goto L_114; /* 00e4: beqz.n a10, 114 <pm_tbtt_process+0xac> */
  goto L_103; /* 00e6: j 103 <pm_tbtt_process+0x9b> */
L_e9:;
  a6 = MEM8(a6 + 212); /* 00e9: l8ui a6, a6, 212 */
  if (a6 != 0) goto L_dc; /* 00ec: bnez a6, dc <pm_tbtt_process+0x74> */
  a6 = MEM8(a2 + 13); /* 00ef: l8ui a6, a2, 13 */
  if (a6 == 0) goto L_dc; /* 00f2: beqz a6, dc <pm_tbtt_process+0x74> */
  a10 = a2; /* 00f5: mov.n a10, a2 */
  a8 = (uint32_t)&pm_beacon_monitor_tbtt_allowed; /* 00f7: l32r a8, 38 <pm_tbtt_process-0x30> (0 <pm_tbtt_process-0x68>) */ /* literal: GOT slot for pm_beacon_monitor_tbtt_allowed */
  pm_beacon_monitor_tbtt_allowed(a2, a3, a4, a5); /* call via literal slot */ /* 00fa: callx8 a8 */
  if (a10 != 0) goto L_dc; /* 00fd: bnez a10, dc <pm_tbtt_process+0x74> */
  goto L_114; /* 0100: j 114 <pm_tbtt_process+0xac> */
L_103:;
  a8 = (uint32_t)&pm_coex_schm_overall_period_get; /* 0103: l32r a8, 3c <pm_tbtt_process-0x2c> (0 <pm_tbtt_process-0x68>) */ /* literal: GOT slot for pm_coex_schm_overall_period_get */
  pm_coex_schm_overall_period_get(a2, a3, a4, a5); /* call via literal slot */ /* 0106: callx8 a8 */
  if (a10 == 1) goto L_114; /* 0109: beqi a10, 1, 114 <pm_tbtt_process+0xac> */
  a10 = a2; /* 010c: mov.n a10, a2 */
  a8 = (uint32_t)&pm_beacon_monitor_tbtt_start; /* 010e: l32r a8, 40 <pm_tbtt_process-0x28> (0 <pm_tbtt_process-0x68>) */ /* literal: GOT slot for pm_beacon_monitor_tbtt_start */
  pm_beacon_monitor_tbtt_start(a2, a3, a4, a5); /* call via literal slot */ /* 0111: callx8 a8 */
L_114:;
  a11 = 0x2; /* 0114: movi.n a11, 2 */
  a10 = 0x0; /* 0116: movi.n a10, 0 */
  a8 = (uint32_t)&wifi_gpio_debug; /* 0118: l32r a8, 44 <pm_tbtt_process-0x24> (0 <pm_tbtt_process-0x68>) */ /* literal: GOT slot for wifi_gpio_debug */
  wifi_gpio_debug(a2, a3, a4, a5); /* call via literal slot */ /* 011b: callx8 a8 */
  a8 = MEM8(a2 + 1); /* 011e: l8ui a8, a2, 1 */
  a6 = (uint32_t)&g_pm_cnt; /* 0121: l32r a6, 10 <pm_tbtt_process-0x58> (0 <pm_tbtt_process-0x68>) */ /* literal @0x10: g_pm_cnt */
  if (a8 != 2) goto L_13e; /* 0124: bnei a8, 2, 13e <pm_tbtt_process+0xd6> */
  a8 = (uint32_t)&pm_dream; /* 0127: l32r a8, 48 <pm_tbtt_process-0x20> (0 <pm_tbtt_process-0x68>) */ /* literal: GOT slot for pm_dream */
  pm_dream(a2, a3, a4, a5); /* call via literal slot */ /* 012a: callx8 a8 */
  a8 = 0x0; /* 012d: movi.n a8, 0 */
  MEM8(a2 + 18) = a8; /* 012f: s8i a8, a2, 18 */
  MEMW(); /* 0132: memw  */
  a8 = MEM32(a6 + 16); /* 0135: l32i a8, a6, 16 */
  a8 = a8 + (1); /* 0138: addi a8, a8, 1 */
  MEM32(a6 + 16) = a8; /* 013b: s32i a8, a6, 16 */
L_13e:;
  if (a3 == 0) goto L_14c; /* 013e: beqz.n a3, 14c <pm_tbtt_process+0xe4> */
L_140:;
  a3 = MEM8(a2 + 14); /* 0140: l8ui a3, a2, 14 */
  if (a3 != 0) goto L_1aa; /* 0143: bnez a3, 1aa <pm_tbtt_process+0x142> */
  MEMW(); /* 0146: memw  */
  goto L_156; /* 0149: j 156 <pm_tbtt_process+0xee> */
L_14c:;
  a3 = MEM32(a7 + 0); /* 014c: l32i.n a3, a7, 0 */
  a10 = MEM32(a3 + 404); /* 014e: l32i a10, a3, 0x194 */
  ((int32_t(*)())a10)(a2, a3, a4, a5); /* 0151: callx8 a10 */ /* indirect */
  if (a10 != 0) goto L_161; /* 0154: bnez.n a10, 161 <pm_tbtt_process+0xf9> */
L_156:;
  a3 = (uint32_t)&g_mesh_is_started; /* 0156: l32r a3, 14 <pm_tbtt_process-0x54> (0 <pm_tbtt_process-0x68>) */ /* literal @0x14: g_mesh_is_started */
  a3 = MEM8(a3 + 0); /* 0159: l8ui a3, a3, 0 */
  if (a3 != 0) goto L_16d; /* 015c: bnez.n a3, 16d <pm_tbtt_process+0x105> */
  goto L_191; /* 015e: j 191 <pm_tbtt_process+0x129> */
L_161:;
  a3 = a2 + ((0x200) << 8); /* 0161: addmi a3, a2, 0x200 */
  a3 = MEM8(a3 + 29); /* 0164: l8ui a3, a3, 29 */
  if (a3 != 0) goto L_140; /* 0167: bnez a3, 140 <pm_tbtt_process+0xd8> */
  goto L_156; /* 016a: j 156 <pm_tbtt_process+0xee> */
L_16d:;
  a3 = (uint32_t)&g_mesh_is_root; /* 016d: l32r a3, 18 <pm_tbtt_process-0x50> (0 <pm_tbtt_process-0x68>) */ /* literal @0x18: g_mesh_is_root */
  MEMW(); /* 0170: memw  */
  a3 = MEM8(a3 + 0); /* 0173: l8ui a3, a3, 0 */
  a3 = (a3 >> 0) & 0xFF; /* 0176: extui a3, a3, 0, 8 */
  if (a3 != 0) goto L_191; /* 0179: bnez.n a3, 191 <pm_tbtt_process+0x129> */
  a8 = (uint32_t)&g_mesh_init_ps_type; /* 017b: l32r a8, 1c <pm_tbtt_process-0x4c> (0 <pm_tbtt_process-0x68>) */ /* literal @0x1C: g_mesh_init_ps_type */
  a8 = MEM32(a8 + 0); /* 017e: l32i.n a8, a8, 0 */
  if (a8 == 0) goto L_191; /* 0180: beqz a8, 191 <pm_tbtt_process+0x129> */
  a7 = MEM32(a7 + 0); /* 0183: l32i a7, a7, 0 */
  a10 = MEM32(a7 + 272); /* 0186: l32i a10, a7, 0x110 */
  ((int32_t(*)())a10)(a2, a3, a4, a5); /* 0189: callx8 a10 */ /* indirect */
  goto L_1a4; /* 018c: j 1a4 <pm_tbtt_process+0x13c> */
  /* 018f: .byte 00 */
  /* 0190: .byte 00 */
L_191:;
  a3 = 0x3FF73C00; /* 0191: l32r a3, 20 <pm_tbtt_process-0x48> (3ff73c00 <pm_attach+0x3ff73b7c>) */ /* MMIO base */ @0x20
  MEMW(); /* 0194: memw  */
  a10 = REG32(0x3FF73C00); /* 0197: l32i.n a10, a3, 0 */ /* MMIO read: base 0x3FF73C00+0 */
  a3 = (uint32_t)&g_wifi_mac_time_delta; /* 0199: l32r a3, 24 <pm_tbtt_process-0x44> (0 <pm_tbtt_process-0x68>) */ /* literal @0x24: g_wifi_mac_time_delta */
  a3 = MEM32(a3 + 0); /* 019c: l32i.n a3, a3, 0 */
  a10 = a10 + a3; /* 019e: add a10, a10, a3 */
  a3 = 0x0; /* 01a1: movi a3, 0 */
L_1a4:;
  MEM32(a2 + 80) = a10; /* 01a4: s32i a10, a2, 80 */
  MEM32(a2 + 84) = a3; /* 01a7: s32i a3, a2, 84 */
L_1aa:;
  a11 = a5; /* 01aa: mov.n a11, a5 */
  a10 = a4; /* 01ac: mov.n a10, a4 */
  a3 = MEM16(a2 + 28); /* 01ae: l16ui a3, a2, 28 */
  a3 = a3 + (1); /* 01b1: addi.n a3, a3, 1 */
  MEM16(a2 + 28) = a3; /* 01b3: s16i a3, a2, 28 */
  MEMW(); /* 01b6: memw  */
  a3 = MEM32(a6 + 0); /* 01b9: l32i.n a3, a6, 0 */
  a3 = a3 + (1); /* 01bb: addi.n a3, a3, 1 */
  MEM32(a6 + 0) = a3; /* 01bd: s32i a3, a6, 0 */
  MEMW(); /* 01c0: memw  */
  a8 = (uint32_t)&pm_coex_tbtt_process; /* 01c3: l32r a8, 4c <pm_tbtt_process-0x1c> (0 <pm_tbtt_process-0x68>) */ /* literal: GOT slot for pm_coex_tbtt_process */
  pm_coex_tbtt_process(a2, a3, a4, a5); /* call via literal slot */ /* 01c6: callx8 a8 */
  a8 = (uint32_t)&pm_noise_check; /* 01c9: l32r a8, 50 <pm_tbtt_process-0x18> (0 <pm_tbtt_process-0x68>) */ /* literal: GOT slot for pm_noise_check */
  pm_noise_check(a2, a3, a4, a5); /* call via literal slot */ /* 01cc: callx8 a8 */
  a8 = (uint32_t)&pm_mesh_set_next_tbtt; /* 01cf: l32r a8, 54 <pm_tbtt_process-0x14> (0 <pm_tbtt_process-0x68>) */ /* literal: GOT slot for pm_mesh_set_next_tbtt */
  pm_mesh_set_next_tbtt(a2, a3, a4, a5); /* call via literal slot */ /* 01d2: callx8 a8 */
  if (a10 != 0) goto L_209; /* 01d5: bnez.n a10, 209 <pm_tbtt_process+0x1a1> */
  a3 = a2 + ((0x100) << 8); /* 01d7: addmi a3, a2, 0x100 */
  a8 = (uint32_t)&pm_set_next_tbtt; /* 01da: l32r a8, 58 <pm_tbtt_process-0x10> (0 <pm_tbtt_process-0x68>) */ /* literal: GOT slot for pm_set_next_tbtt */
  pm_set_next_tbtt(a2, a3, a4, a5); /* call via literal slot */ /* 01dd: callx8 a8 */
  a4 = MEM8(a3 + 212); /* 01e0: l8ui a4, a3, 212 */
  if (a4 == 0) goto L_1f8; /* 01e3: beqz.n a4, 1f8 <pm_tbtt_process+0x190> */
  a4 = MEM8(a2 + 14); /* 01e5: l8ui a4, a2, 14 */
  if (a4 == 0) goto L_1f8; /* 01e8: beqz.n a4, 1f8 <pm_tbtt_process+0x190> */
  a10 = MEM8(a2 + 15); /* 01ea: l8ui a10, a2, 15 */
  if (a10 != 0) goto L_1f8; /* 01ed: bnez a10, 1f8 <pm_tbtt_process+0x190> */
  a11 = a10; /* 01f0: mov.n a11, a10 */
  a8 = (uint32_t)&pm_go_to_wake; /* 01f2: l32r a8, 5c <pm_tbtt_process-0xc> (0 <pm_tbtt_process-0x68>) */ /* literal: GOT slot for pm_go_to_wake */
  pm_go_to_wake(a2, a3, a4, a5); /* call via literal slot */ /* 01f5: callx8 a8 */
L_1f8:;
  a8 = (uint32_t)&pm_update_params; /* 01f8: l32r a8, 60 <pm_tbtt_process-0x8> (0 <pm_tbtt_process-0x68>) */ /* literal: GOT slot for pm_update_params */
  pm_update_params(a2, a3, a4, a5); /* call via literal slot */ /* 01fb: callx8 a8 */
  a2 = MEM8(a3 + 140); /* 01fe: l8ui a2, a3, 140 */
  if (a2 != 0) goto L_209; /* 0201: bnez.n a2, 209 <pm_tbtt_process+0x1a1> */
  a8 = (uint32_t)&pm_update_by_connectionless_status; /* 0203: l32r a8, 64 <pm_tbtt_process-0x4> (0 <pm_tbtt_process-0x68>) */ /* literal: GOT slot for pm_update_by_connectionless_status */
  pm_update_by_connectionless_status(a2, a3, a4, a5); /* call via literal slot */ /* 0206: callx8 a8 */
L_209:;
  return (int32_t)a2; /* 0209: retw.n  */
}

/* pm_beacon_monitor_tbtt_timeout_process @ pm.o 00000008 size 27B bind GLOBAL
 * Calls: g_osi_funcs_p[got], pm_tbtt_process[got] | Data refs: g_osi_funcs_p, pm_tbtt_process
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 2 call(s), 2 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t pm_beacon_monitor_tbtt_timeout_process(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .wifislprxiram.42; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_8:;
  /* 0008: entry a1, 32 */
  a8 = (uint32_t)&g_osi_funcs_p; /* 000b: l32r a8, 0 <pm_beacon_monitor_tbtt_timeout_process-0x8> (0 <pm_beacon_monitor_tbtt_timeout_process-0x8>) */ /* literal @0x0: g_osi_funcs_p */
  a8 = MEM32(a8 + 0); /* 000e: l32i.n a8, a8, 0 */
  a10 = MEM32(a2 + 388); /* 0010: l32i a10, a2, 0x184 */
  a8 = MEM32(a8 + 236); /* 0013: l32i a8, a8, 236 */
  g_osi_funcs_p(a2, a3, a4, a5); /* call via literal slot */ /* 0016: callx8 a8 */
  a10 = 0x0; /* 0019: movi.n a10, 0 */
  a8 = (uint32_t)&pm_tbtt_process; /* 001b: l32r a8, 4 <pm_beacon_monitor_tbtt_timeout_process-0x4> (0 <pm_beacon_monitor_tbtt_timeout_process-0x8>) */ /* literal: GOT slot for pm_tbtt_process */
  pm_tbtt_process(a2, a3, a4, a5); /* call via literal slot */ /* 001e: callx8 a8 */
  return (int32_t)a2; /* 0021: retw.n  */
}

/* pm_beacon_add_loss_counter @ pm.o 00000008 size 31B bind GLOBAL
 * Calls: ptr_beacon_offset_funcs[got] | Data refs: g_pm, ptr_beacon_offset_funcs
 *   MMIO: none
 *   funcdb v3: 0 call(s), 2 ref(s); disasm: 1 call(s), 2 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t pm_beacon_add_loss_counter(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pm_beacon_add_loss_counter; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_8:;
  /* 0008: entry a1, 32 */
  a9 = (uint32_t)&g_pm; /* 000b: l32r a9, 0 <pm_beacon_add_loss_counter-0x8> (0 <pm_beacon_add_loss_counter-0x8>) */ /* literal @0x0: g_pm */
  a8 = MEM32(a9 + 536); /* 000e: l32i a8, a9, 0x218 */
  a8 = a8 + (1); /* 0011: addi.n a8, a8, 1 */
  MEM32(a9 + 536) = a8; /* 0013: s32i a8, a9, 0x218 */
  a8 = (uint32_t)&ptr_beacon_offset_funcs; /* 0016: l32r a8, 4 <pm_beacon_add_loss_counter-0x4> (0 <pm_beacon_add_loss_counter-0x8>) */ /* literal @0x4: ptr_beacon_offset_funcs */
  a8 = MEM32(a8 + 0); /* 0019: l32i.n a8, a8, 0 */
  a8 = MEM32(a8 + 40); /* 001b: l32i.n a8, a8, 40 */
  if (a8 == 0) goto L_25; /* 001d: beqz.n a8, 25 <pm_beacon_add_loss_counter+0x1d> */
  MEMW(); /* 001f: memw  */
  ptr_beacon_offset_funcs(a2, a3, a4, a5); /* call via literal slot */ /* 0022: callx8 a8 */
L_25:;
  return (int32_t)a2; /* 0025: retw.n  */
}

/* pm_beacon_monitor_timeout_process @ pm.o 00000010 size 110B bind GLOBAL
 * Calls: pm_beacon_add_loss_counter[got], g_osi_funcs_p[got], pm_sleep[got], wifi_gpio_debug[got] | Data refs: pm_beacon_add_loss_counter, g_osi_funcs_p, pm_sleep, wifi_gpio_debug
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 4 call(s), 4 data ref(s)
 * Fidelity: medium - 38 instr, 5 branches, calls resolved */
int32_t pm_beacon_monitor_timeout_process(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .wifislprxiram.41; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_10:;
  /* 0010: entry a1, 32 */
  a3 = a2 + ((0x100) << 8); /* 0013: addmi a3, a2, 0x100 */
  a4 = MEM8(a3 + 100); /* 0016: l8ui a4, a3, 100 */
  if (a4 == 0) goto L_7c; /* 0019: beqz a4, 7c <pm_beacon_monitor_timeout_process+0x6c> */
  a4 = MEM8(a3 + 212); /* 001c: l8ui a4, a3, 212 */
  if (a4 != 0) goto L_7c; /* 001f: bnez a4, 7c <pm_beacon_monitor_timeout_process+0x6c> */
  a8 = MEM8(a2 + 13); /* 0022: l8ui a8, a2, 13 */
  if (a8 == 0) goto L_7c; /* 0025: beqz a8, 7c <pm_beacon_monitor_timeout_process+0x6c> */
  a8 = (uint32_t)&pm_beacon_add_loss_counter; /* 0028: l32r a8, 4 <pm_beacon_monitor_timeout_process-0xc> (0 <pm_beacon_monitor_timeout_process-0x10>) */ /* literal: GOT slot for pm_beacon_add_loss_counter */
  pm_beacon_add_loss_counter(a2, a3, a4, a5); /* call via literal slot */ /* 002b: callx8 a8 */
  a8 = MEM8(a2 + 1); /* 002e: l8ui a8, a2, 1 */
  if (a8 != 1) goto L_72; /* 0031: bnei a8, 1, 72 <pm_beacon_monitor_timeout_process+0x62> */
  a8 = MEM16(a2 + 384); /* 0034: l16ui a8, a2, 0x180 */
  a10 = ((int32_t)(a8 << (32 - (15 & 31)))) >> (32 - (15 & 31)); /* 0037: sext a10, a8, 15 */
  a8 = a8 + (1); /* 003a: addi.n a8, a8, 1 */
  a8 = (a8 >> 0) & 0xFFFF; /* 003c: extui a8, a8, 0, 16 */
  a9 = MEM16(a2 + 386); /* 003f: l16si a9, a2, 0x182 */
  MEM16(a2 + 384) = a8; /* 0042: s16i a8, a2, 0x180 */
  MEMW(); /* 0045: memw  */
  if (a10 >= a9) goto L_72; /* 0048: bge a10, a9, 72 <pm_beacon_monitor_timeout_process+0x62> */
  a10 = a4 | a4; /* 004b: or a10, a4, a4 */
  a9 = MEM8(a3 + 127); /* 004e: l8ui a9, a3, 127 */
  /* 0051: mul16u a8, a9, a8 */ /* UNMODELED: a8 clobbered */
  MEM8(a3 + 125) = a8; /* 0054: s8i a8, a3, 125 */
  MEM8(a2 + 17) = a4; /* 0057: s8i a4, a2, 17 */
  MEMW(); /* 005a: memw  */
  a2 = (uint32_t)&g_osi_funcs_p; /* 005d: l32r a2, 0 <pm_beacon_monitor_timeout_process-0x10> (0 <pm_beacon_monitor_timeout_process-0x10>) */ /* literal @0x0: g_osi_funcs_p */
  a2 = MEM32(a2 + 0); /* 0060: l32i a2, a2, 0 */
  a2 = MEM32(a2 + 416); /* 0063: l32i a2, a2, 0x1a0 */
  MEMW(); /* 0066: memw  */
  g_osi_funcs_p(a2, a3, a4, a5); /* call via literal slot */ /* 0069: callx8 a2 */
  a8 = (uint32_t)&pm_sleep; /* 006c: l32r a8, 8 <pm_beacon_monitor_timeout_process-0x8> (0 <pm_beacon_monitor_timeout_process-0x10>) */ /* literal: GOT slot for pm_sleep */
  pm_sleep(a2, a3, a4, a5); /* call via literal slot */ /* 006f: callx8 a8 */
L_72:;
  a11 = 0x2; /* 0072: movi.n a11, 2 */
  a10 = 0x2; /* 0074: mov.n a10, a11 */
  a8 = (uint32_t)&wifi_gpio_debug; /* 0076: l32r a8, c <pm_beacon_monitor_timeout_process-0x4> (0 <pm_beacon_monitor_timeout_process-0x10>) */ /* literal: GOT slot for wifi_gpio_debug */
  wifi_gpio_debug(a2, a3, a4, a5); /* call via literal slot */ /* 0079: callx8 a8 */
L_7c:;
  return (int32_t)a2; /* 007c: retw.n  */
}

/* pm_beacon_loss_info_get @ pm.o 00000004 size 21B bind GLOBAL
 * Calls: none | Data refs: g_pm
 *   MMIO: none
 *   funcdb v3: 0 call(s), 1 ref(s); disasm: 0 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t pm_beacon_loss_info_get(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pm_beacon_loss_info_get; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a8 = (uint32_t)&g_pm; /* 0007: l32r a8, 0 <pm_beacon_loss_info_get-0x4> (0 <pm_beacon_loss_info_get-0x4>) */ /* literal @0x0: g_pm */
  a9 = MEM32(a8 + 532); /* 000a: l32i a9, a8, 0x214 */
  MEM32(a2 + 0) = a9; /* 000d: s32i.n a9, a2, 0 */
  a8 = MEM32(a8 + 536); /* 000f: l32i a8, a8, 0x218 */
  MEM32(a3 + 0) = a8; /* 0012: s32i.n a8, a3, 0 */
  MEMW(); /* 0014: memw  */
  return (int32_t)a2; /* 0017: retw.n  */
}

/* pm_beacon_loss_info_clean @ pm.o 00000004 size 19B bind GLOBAL
 * Calls: none | Data refs: g_pm
 *   MMIO: none
 *   funcdb v3: 0 call(s), 1 ref(s); disasm: 0 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t pm_beacon_loss_info_clean(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pm_beacon_loss_info_clean; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a8 = (uint32_t)&g_pm; /* 0007: l32r a8, 0 <pm_beacon_loss_info_clean-0x4> (0 <pm_beacon_loss_info_clean-0x4>) */ /* literal @0x0: g_pm */
  a9 = 0x0; /* 000a: movi.n a9, 0 */
  MEM32(a8 + 536) = a9; /* 000c: s32i a9, a8, 0x218 */
  MEM32(a8 + 532) = a9; /* 000f: s32i a9, a8, 0x214 */
  MEMW(); /* 0012: memw  */
  return (int32_t)a2; /* 0015: retw.n  */
}

/* pm_get_tx_blocks_retention_mask @ pm.o 00000008 size 36B bind GLOBAL
 * Calls: none | Data refs: g_pm
 *   MMIO: none
 *   funcdb v3: 0 call(s), 1 ref(s); disasm: 0 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t pm_get_tx_blocks_retention_mask(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pm_get_tx_blocks_retention_mask; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_8:;
  /* 0008: entry a1, 32 */
  a8 = (uint32_t)&g_pm; /* 000b: l32r a8, 4 <pm_get_tx_blocks_retention_mask-0x4> (0 <pm_get_tx_blocks_retention_mask-0x8>) */ /* literal @0x4: g_pm */
  a2 = 0xFFFFFFFF; /* 000e: movi.n a2, -1 */
  a9 = MEM8(a8 + 13); /* 0010: l8ui a9, a8, 13 */
  if (a9 == 0) goto L_2a; /* 0013: beqz.n a9, 2a <pm_get_tx_blocks_retention_mask+0x22> */
  a9 = MEM8(a8 + 14); /* 0015: l8ui a9, a8, 14 */
  a2 = 0xFFF1FFFF; /* 0018: l32r a2, 0 <pm_get_tx_blocks_retention_mask-0x8> (fff1ffff <pm_attach+0xfff1ff7b>) */ @0x0
  if (a9 == 0) goto L_2a; /* 001b: beqz.n a9, 2a <pm_get_tx_blocks_retention_mask+0x22> */
  a8 = a8 + ((0x200) << 8); /* 001d: addmi a8, a8, 0x200 */
  a2 = 0xFFFFFFFF; /* 0020: movi.n a2, -1 */
  a8 = MEM8(a8 + 30); /* 0022: l8ui a8, a8, 30 */
  if (a8 == 0) goto L_2a; /* 0025: beqz.n a8, 2a <pm_get_tx_blocks_retention_mask+0x22> */
  a2 = 0xFFF1FFFF; /* 0027: l32r a2, 0 <pm_get_tx_blocks_retention_mask-0x8> (fff1ffff <pm_attach+0xfff1ff7b>) */ @0x0
L_2a:;
  return (int32_t)a2; /* 002a: retw.n  */
}

/* hal_pm_unblock_txq @ pm.o 00000000 size 36B bind LOCAL
 * Calls: none | Data refs: none
 *   MMIO: 0x3FF73CB8
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
static int32_t hal_pm_unblock_txq(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.hal_pm_unblock_txq; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
  /* 0000: .word 0x3ff73cb8 (literal pool) */
  /* 0004: .word 0xfff1ffff (literal pool) */
  /* 0008: entry a1, 32 */
  a9 = 0x3FF73CB8; /* 000b: l32r a9, 0 <.text.hal_pm_unblock_txq> (3ff73cb8 <pm_attach+0x3ff73c34>) */ /* MMIO base */ @0x0
  a10 = 0xFFF1FFFF; /* 000e: l32r a10, 4 <.text.hal_pm_unblock_txq+0x4> (fff1ffff <pm_attach+0xfff1ff7b>) */ @0x4
  MEMW(); /* 0011: memw  */
  a8 = REG32(0x3FF73CB8); /* 0014: l32i.n a8, a9, 0 */ /* MMIO read: base 0x3FF73CB8+0 */
  a8 = a8 & a10; /* 0016: and a8, a8, a10 */
  MEMW(); /* 0019: memw  */
  REG32(0x3FF73CB8) = a8; /* 001c: s32i.n a8, a9, 0 */ /* MMIO write: base 0x3FF73CB8+0 */
  MEMW(); /* 001e: memw  */
  return (int32_t)a2; /* 0021: retw.n  */
}

/* pm_incr_coex_active_cnt @ pm.o 00000000 size 30B bind LOCAL
 * Calls: none | Data refs: none
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
static int32_t pm_incr_coex_active_cnt(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pm_incr_coex_active_cnt; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
  /* 0000: .word 0x00000000 (literal pool) */
  /* 0004: entry a1, 32 */
  a9 = 0x0; /* 0007: l32r a9, 0 <.text.pm_incr_coex_active_cnt> (0 <.text.pm_incr_coex_active_cnt>) */ @0x0
  a10 = 0x1; /* 000a: movi.n a10, 1 */
  a8 = MEM32(a9 + 64); /* 000c: l32i a8, a9, 64 */
  a8 = a8 + (1); /* 000f: addi.n a8, a8, 1 */
  /* 0011: maxu a8, a8, a10 */ /* UNMODELED: a8 clobbered */
  MEM32(a9 + 64) = a8; /* 0014: s32i a8, a9, 64 */
  MEMW(); /* 0017: memw  */
  return (int32_t)a2; /* 001a: retw.n  */
}

/* pm_disable_active_timer @ pm.o 00000000 size 21B bind LOCAL
 * Calls: none | Data refs: none
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: medium - 7 instr, 0 branches, calls resolved */
static int32_t pm_disable_active_timer(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pm_disable_active_timer; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
  /* 0008: entry a1, 32 */
  a8 = 0x0; /* 000b: l32r a8, 4 <.text.pm_disable_active_timer+0x4> (0 <.text.pm_disable_active_timer>) */ @0x4
  a8 = MEM32(a8 + 0); /* 000e: l32i.n a8, a8, 0 */
  a10 = 0x0; /* 0010: l32r a10, 0 <.text.pm_disable_active_timer> (0 <.text.pm_disable_active_timer>) */ @0x0
  a8 = MEM32(a8 + 236); /* 0013: l32i a8, a8, 236 */
  ((int32_t(*)())a8)(a2, a3, a4, a5); /* 0016: callx8 a8 */ /* indirect */
  return (int32_t)a2; /* 0019: retw.n  */
}

/* pm_illegal_beacon_logger @ pm.o 00000000 size 66B bind LOCAL
 * Calls: wifi_log[got], wifi_log[got], wifi_log[got] | Data refs: wifi_log
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 3 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
static int32_t pm_illegal_beacon_logger(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pm_illegal_beacon_logger; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
  /* 0018: entry a1, 32 */
  a2 = 0x1; /* 001b: movi.n a2, 1 */
  a2 = 0x1000; /* 001d: slli a2, a2, 12 */
  a13 = 0x0; /* 0020: l32r a13, 0 <.text.pm_illegal_beacon_logger> (0 <.text.pm_illegal_beacon_logger>) */ @0x0
  a11 = 0x1000; /* 0023: mov.n a11, a2 */
  a12 = 0x3; /* 0025: movi a12, 3 */
  a10 = 0x6; /* 0028: movi a10, 6 */
  a8 = (uint32_t)&wifi_log; /* 002b: l32r a8, c <.text.pm_illegal_beacon_logger+0xc> (0 <.text.pm_illegal_beacon_logger>) */ /* literal: GOT slot for wifi_log */
  wifi_log(a2, a3, a4, a5); /* call via literal slot */ /* 002e: callx8 a8 */
  a13 = 0x0; /* 0031: l32r a13, 4 <.text.pm_illegal_beacon_logger+0x4> (0 <.text.pm_illegal_beacon_logger>) */ @0x4
  a11 = a2; /* 0034: mov.n a11, a2 */
  a12 = 0x3; /* 0036: movi.n a12, 3 */
  a10 = 0x6; /* 0038: movi a10, 6 */
  a8 = (uint32_t)&wifi_log; /* 003b: l32r a8, 10 <.text.pm_illegal_beacon_logger+0x10> (0 <.text.pm_illegal_beacon_logger>) */ /* literal: GOT slot for wifi_log */
  wifi_log(a2, a3, a4, a5); /* call via literal slot */ /* 003e: callx8 a8 */
  a13 = 0x0; /* 0041: l32r a13, 8 <.text.pm_illegal_beacon_logger+0x8> (0 <.text.pm_illegal_beacon_logger>) */ @0x8
  a12 = 0x3; /* 0044: movi.n a12, 3 */
  a11 = a2; /* 0046: mov.n a11, a2 */
  a10 = 0x6; /* 0048: movi.n a10, 6 */
  a8 = (uint32_t)&wifi_log; /* 004a: l32r a8, 14 <.text.pm_illegal_beacon_logger+0x14> (0 <.text.pm_illegal_beacon_logger>) */ /* literal: GOT slot for wifi_log */
  wifi_log(a2, a3, a4, a5); /* call via literal slot */ /* 004d: callx8 a8 */
  return (int32_t)a2; /* 0050: retw.n  */
}

/* pm_set_state @ pm.o 00000000 size 51B bind LOCAL
 * Calls: wifi_gpio_debug[got], wifi_gpio_debug[got] | Data refs: wifi_gpio_debug
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 2 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
static int32_t pm_set_state(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pm_set_state; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
  /* 000c: entry a1, 32 */
  a3 = 0x0; /* 000f: l32r a3, 0 <.text.pm_set_state> (0 <.text.pm_set_state>) */ @0x0
  a10 = MEM8(a3 + 1); /* 0012: l8ui a10, a3, 1 */
  if (a10 == a2) goto L_30; /* 0015: beq a10, a2, 30 <.text.pm_set_state+0x30> */
  a4 = 0x5; /* 0018: movi.n a4, 5 */
  a11 = 0x1; /* 001a: movi.n a11, 1 */
  a10 = a4 - a10; /* 001c: sub a10, a4, a10 */
  a8 = (uint32_t)&wifi_gpio_debug; /* 001f: l32r a8, 4 <.text.pm_set_state+0x4> (0 <.text.pm_set_state>) */ /* literal: GOT slot for wifi_gpio_debug */
  wifi_gpio_debug(a2, a3, a4, a5); /* call via literal slot */ /* 0022: callx8 a8 */
  a11 = 0x0; /* 0025: movi.n a11, 0 */
  a10 = a4 - a2; /* 0027: sub a10, a4, a2 */
  a8 = (uint32_t)&wifi_gpio_debug; /* 002a: l32r a8, 8 <.text.pm_set_state+0x8> (0 <.text.pm_set_state>) */ /* literal: GOT slot for wifi_gpio_debug */
  wifi_gpio_debug(a2, a3, a4, a5); /* call via literal slot */ /* 002d: callx8 a8 */
L_30:;
  MEM8(a3 + 1) = a2; /* 0030: s8i a2, a3, 1 */
  MEMW(); /* 0033: memw  */
  MEMW(); /* 0036: memw  */
  return (int32_t)a2; /* 0039: retw.n  */
}

/* pm_beacon_monitor_tbtt_timeout @ pm.o 00000000 size 21B bind LOCAL
 * Calls: pp_timer_process[got] | Data refs: pp_timer_process
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 1 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
static int32_t pm_beacon_monitor_tbtt_timeout(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pm_beacon_monitor_tbtt_timeout; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
  /* 0000: .word 0x00000000 (literal pool) */
  /* 0004: entry a1, 32 */
  a11 = a2; /* 0007: mov.n a11, a2 */
  a10 = 0xA; /* 0009: movi.n a10, 10 */
  a8 = (uint32_t)&pp_timer_process; /* 000b: l32r a8, 0 <.text.pm_beacon_monitor_tbtt_timeout> (0 <.text.pm_beacon_monitor_tbtt_timeout>) */ /* literal: GOT slot for pp_timer_process */
  pp_timer_process(a2, a3, a4, a5); /* call via literal slot */ /* 000e: callx8 a8 */
  return (int32_t)a2; /* 0011: retw.n  */
}

/* pm_coex_restart_timeout @ pm.o 00000000 size 21B bind LOCAL
 * Calls: pp_timer_process[got] | Data refs: pp_timer_process
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 1 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
static int32_t pm_coex_restart_timeout(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pm_coex_restart_timeout; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
  /* 0000: .word 0x00000000 (literal pool) */
  /* 0004: entry a1, 32 */
  a11 = 0x0; /* 0007: movi.n a11, 0 */
  a10 = 0xD; /* 0009: movi.n a10, 13 */
  a8 = (uint32_t)&pp_timer_process; /* 000b: l32r a8, 0 <.text.pm_coex_restart_timeout> (0 <.text.pm_coex_restart_timeout>) */ /* literal: GOT slot for pp_timer_process */
  pp_timer_process(a2, a3, a4, a5); /* call via literal slot */ /* 000e: callx8 a8 */
  return (int32_t)a2; /* 0011: retw.n  */
}

/* pm_keep_alive_timeout @ pm.o 00000000 size 21B bind LOCAL
 * Calls: pp_timer_process[got] | Data refs: pp_timer_process
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 1 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
static int32_t pm_keep_alive_timeout(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pm_keep_alive_timeout; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
  /* 0000: .word 0x00000000 (literal pool) */
  /* 0004: entry a1, 32 */
  a11 = 0x0; /* 0007: movi.n a11, 0 */
  a10 = 0xB; /* 0009: movi.n a10, 11 */
  a8 = (uint32_t)&pp_timer_process; /* 000b: l32r a8, 0 <.text.pm_keep_alive_timeout> (0 <.text.pm_keep_alive_timeout>) */ /* literal: GOT slot for pp_timer_process */
  pp_timer_process(a2, a3, a4, a5); /* call via literal slot */ /* 000e: callx8 a8 */
  return (int32_t)a2; /* 0011: retw.n  */
}

/* pm_beacon_monitor_timeout @ pm.o 00000000 size 21B bind LOCAL
 * Calls: pp_timer_process[got] | Data refs: pp_timer_process
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 1 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
static int32_t pm_beacon_monitor_timeout(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pm_beacon_monitor_timeout; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
  /* 0000: .word 0x00000000 (literal pool) */
  /* 0004: entry a1, 32 */
  a11 = a2; /* 0007: mov.n a11, a2 */
  a10 = 0x9; /* 0009: movi.n a10, 9 */
  a8 = (uint32_t)&pp_timer_process; /* 000b: l32r a8, 0 <.text.pm_beacon_monitor_timeout> (0 <.text.pm_beacon_monitor_timeout>) */ /* literal: GOT slot for pp_timer_process */
  pp_timer_process(a2, a3, a4, a5); /* call via literal slot */ /* 000e: callx8 a8 */
  return (int32_t)a2; /* 0011: retw.n  */
}

/* pm_connectionless_wake_window_timeout @ pm.o 00000000 size 21B bind LOCAL
 * Calls: pp_timer_process[got] | Data refs: pp_timer_process
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 1 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
static int32_t pm_connectionless_wake_window_timeout(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pm_connectionless_wake_window_timeout; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
  /* 0000: .word 0x00000000 (literal pool) */
  /* 0004: entry a1, 32 */
  a11 = 0x0; /* 0007: movi.n a11, 0 */
  a10 = 0x8; /* 0009: movi.n a10, 8 */
  a8 = (uint32_t)&pp_timer_process; /* 000b: l32r a8, 0 <.text.pm_connectionless_wake_window_timeout> (0 <.text.pm_connectionless_wake_window_timeout>) */ /* literal: GOT slot for pp_timer_process */
  pp_timer_process(a2, a3, a4, a5); /* call via literal slot */ /* 000e: callx8 a8 */
  return (int32_t)a2; /* 0011: retw.n  */
}

/* pm_connectionless_wake_interval_timeout @ pm.o 00000000 size 21B bind LOCAL
 * Calls: pp_timer_process[got] | Data refs: pp_timer_process
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 1 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
static int32_t pm_connectionless_wake_interval_timeout(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pm_connectionless_wake_interval_timeout; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
  /* 0000: .word 0x00000000 (literal pool) */
  /* 0004: entry a1, 32 */
  a11 = 0x0; /* 0007: movi.n a11, 0 */
  a10 = 0x7; /* 0009: movi.n a10, 7 */
  a8 = (uint32_t)&pp_timer_process; /* 000b: l32r a8, 0 <.text.pm_connectionless_wake_interval_timeout> (0 <.text.pm_connectionless_wake_interval_timeout>) */ /* literal: GOT slot for pp_timer_process */
  pp_timer_process(a2, a3, a4, a5); /* call via literal slot */ /* 000e: callx8 a8 */
  return (int32_t)a2; /* 0011: retw.n  */
}

/* pm_disconnected_sleep_delay_timeout @ pm.o 00000000 size 21B bind LOCAL
 * Calls: pp_timer_process[got] | Data refs: pp_timer_process
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 1 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
static int32_t pm_disconnected_sleep_delay_timeout(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pm_disconnected_sleep_delay_timeout; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
  /* 0000: .word 0x00000000 (literal pool) */
  /* 0004: entry a1, 32 */
  a11 = 0x0; /* 0007: movi.n a11, 0 */
  a10 = 0x6; /* 0009: movi.n a10, 6 */
  a8 = (uint32_t)&pp_timer_process; /* 000b: l32r a8, 0 <.text.pm_disconnected_sleep_delay_timeout> (0 <.text.pm_disconnected_sleep_delay_timeout>) */ /* literal: GOT slot for pp_timer_process */
  pp_timer_process(a2, a3, a4, a5); /* call via literal slot */ /* 000e: callx8 a8 */
  return (int32_t)a2; /* 0011: retw.n  */
}

/* pm_coex_slice_wifi_timeout @ pm.o 00000000 size 21B bind LOCAL
 * Calls: pp_timer_process[got] | Data refs: pp_timer_process
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 1 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
static int32_t pm_coex_slice_wifi_timeout(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pm_coex_slice_wifi_timeout; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
  /* 0000: .word 0x00000000 (literal pool) */
  /* 0004: entry a1, 32 */
  a11 = 0x0; /* 0007: movi.n a11, 0 */
  a10 = 0x4; /* 0009: movi.n a10, 4 */
  a8 = (uint32_t)&pp_timer_process; /* 000b: l32r a8, 0 <.text.pm_coex_slice_wifi_timeout> (0 <.text.pm_coex_slice_wifi_timeout>) */ /* literal: GOT slot for pp_timer_process */
  pp_timer_process(a2, a3, a4, a5); /* call via literal slot */ /* 000e: callx8 a8 */
  return (int32_t)a2; /* 0011: retw.n  */
}

/* pm_sleep_delay_timeout @ pm.o 00000000 size 21B bind LOCAL
 * Calls: pp_timer_process[got] | Data refs: pp_timer_process
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 1 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
static int32_t pm_sleep_delay_timeout(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pm_sleep_delay_timeout; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
  /* 0000: .word 0x00000000 (literal pool) */
  /* 0004: entry a1, 32 */
  a11 = 0x0; /* 0007: movi.n a11, 0 */
  a10 = 0x5; /* 0009: movi.n a10, 5 */
  a8 = (uint32_t)&pp_timer_process; /* 000b: l32r a8, 0 <.text.pm_sleep_delay_timeout> (0 <.text.pm_sleep_delay_timeout>) */ /* literal: GOT slot for pp_timer_process */
  pp_timer_process(a2, a3, a4, a5); /* call via literal slot */ /* 000e: callx8 a8 */
  return (int32_t)a2; /* 0011: retw.n  */
}

/* pm_active_timeout @ pm.o 00000000 size 21B bind LOCAL
 * Calls: pp_timer_process[got] | Data refs: pp_timer_process
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 1 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
static int32_t pm_active_timeout(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pm_active_timeout; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
  /* 0000: .word 0x00000000 (literal pool) */
  /* 0004: entry a1, 32 */
  a11 = 0x0; /* 0007: movi.n a11, 0 */
  a10 = 0x3; /* 0009: movi.n a10, 3 */
  a8 = (uint32_t)&pp_timer_process; /* 000b: l32r a8, 0 <.text.pm_active_timeout> (0 <.text.pm_active_timeout>) */ /* literal: GOT slot for pp_timer_process */
  pp_timer_process(a2, a3, a4, a5); /* call via literal slot */ /* 000e: callx8 a8 */
  return (int32_t)a2; /* 0011: retw.n  */
}

/* pm_dream_timeout @ pm.o 00000000 size 21B bind LOCAL
 * Calls: pp_timer_process[got] | Data refs: pp_timer_process
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 1 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
static int32_t pm_dream_timeout(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pm_dream_timeout; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
  /* 0000: .word 0x00000000 (literal pool) */
  /* 0004: entry a1, 32 */
  a11 = 0x0; /* 0007: movi.n a11, 0 */
  a10 = 0x2; /* 0009: movi.n a10, 2 */
  a8 = (uint32_t)&pp_timer_process; /* 000b: l32r a8, 0 <.text.pm_dream_timeout> (0 <.text.pm_dream_timeout>) */ /* literal: GOT slot for pp_timer_process */
  pp_timer_process(a2, a3, a4, a5); /* call via literal slot */ /* 000e: callx8 a8 */
  return (int32_t)a2; /* 0011: retw.n  */
}

/* pm_tbtt_timeout @ pm.o 00000000 size 21B bind LOCAL
 * Calls: pp_timer_process[got] | Data refs: pp_timer_process
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 1 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
static int32_t pm_tbtt_timeout(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pm_tbtt_timeout; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
  /* 0000: .word 0x00000000 (literal pool) */
  /* 0004: entry a1, 32 */
  a11 = 0x0; /* 0007: movi.n a11, 0 */
  a10 = 0x1; /* 0009: movi.n a10, 1 */
  a8 = (uint32_t)&pp_timer_process; /* 000b: l32r a8, 0 <.text.pm_tbtt_timeout> (0 <.text.pm_tbtt_timeout>) */ /* literal: GOT slot for pp_timer_process */
  pp_timer_process(a2, a3, a4, a5); /* call via literal slot */ /* 000e: callx8 a8 */
  return (int32_t)a2; /* 0011: retw.n  */
}

/* wifi_pm_sleep_lock_acquire @ pm.o 00000000 size 6B bind LOCAL
 * Calls: none | Data refs: none
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
static int32_t wifi_pm_sleep_lock_acquire(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.wifi_pm_sleep_lock_acquire; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_0:;
  /* 0000: entry a1, 32 */
  return (int32_t)a2; /* 0003: retw.n  */
}

/* wifi_pm_sleep_lock_release @ pm.o 00000000 size 6B bind LOCAL
 * Calls: none | Data refs: none
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
static int32_t wifi_pm_sleep_lock_release(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.wifi_pm_sleep_lock_release; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_0:;
  /* 0000: entry a1, 32 */
  return (int32_t)a2; /* 0003: retw.n  */
}

/* pm_parse_beacon_trace @ pm.o 00000000 size 6B bind LOCAL
 * Calls: none | Data refs: none
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
static int32_t pm_parse_beacon_trace(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .iram1.7; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_0:;
  /* 0000: entry a1, 32 */
  return (int32_t)a2; /* 0003: retw.n  */
}

