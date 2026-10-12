/* ===== trc.o : reconstructed from libpp.a (ESP32, Xtensa, esp-2022r1) =====
 * Toolchain: xtensa-esp32-elf (GCC 11.2.0 crosstool-NG esp-2022r1).
 * ABI: args a2..a7, return a2 (all functions take a2..a7, return int32_t).
 * memw barriers preserved as MEMW(). MMIO as REG32/REG16/REG8(addr).
 * Calls with unknown arg counts are modeled with 4 live args (a2..a5);
 * a2..a7 are clobbered across calls (windowed-ABI approximation).
 * Sections: .text.TRC_AMPDU_PER_DOWN_THRESHOLD, .text.TRC_AMPDU_PER_UP_THRESHOLD, .text.TRC_PER_IS_GOOD, .text.rc11BRate2SchedIdx, .text.rc11GRate2SchedIdx, .text.rc11NRate2SchedIdx, .text.rcAmpduLowerRate, .text.rcAttach, .text.rcBuildIndex, .text.rcClearCurAMPDUSched, .text.rcClearCurSched, .text.rcClearCurStat, .text.rcGet11BHighestRateIdx, .text.rcGet11GHighestRateIdx, .text.rcGet11NHighestRateIdx, .text.rcGetAmpduSched, .text.rcGetDefaultHigestRateIdx, .text.rcGetHighestRateIdx, .text.rcLoRaRate2SchedIdx, .text.rcLowerSched, .text.rcReachRetryLimit, .text.rcSetBarRate, .text.rcSetTxAmpduLimit, .text.rcTxUpdatePer, .text.rcUpSched, .text.rcUpdateAMPDUParam, .text.rcUpdateAckSnr, .text.rcUpdatePhyMode, .text.rcUpdateRate, .text.rc_disable_trc, .text.rc_disable_trc_by_interface, .text.rc_enable_trc, .text.rc_get_G6M_sched, .text.rc_get_default_sched, .text.rc_get_fix_rate, .text.rc_get_mask, .text.rc_get_sta_trc, .text.rc_get_trc_by_index, .text.rc_get_trc_default, .text.rc_only_sta_trc, .text.rc_set_fix_rate, .text.rc_set_per_conn_fix_rate, .text.rssi_margin, .text.rx11NRate2AMPDULimit, .text.trcAmpduSetState, .text.trcResumeAmpdu$constprop$0, .text.trcStopAmpdu$constprop$0, .text.trc_NeedRTS, .text.trc_SetTxAmpduState, .text.trc_calc_duration, .text.trc_deinit, .text.trc_get_80211_tx_rate, .text.trc_get_80211_tx_rate_config, .text.trc_get_espnow_rate, .text.trc_init, .text.trc_isAmpduOn, .text.trc_onAmpduOp, .text.trc_onDisconnect, .text.trc_onScanDone, .text.trc_onScanStart, .text.trc_set_80211_tx_rate, .text.trc_set_80211_tx_rate_config, .text.trc_set_per_pkt_rate, .text.trc_update_def_rate, .text.trc_update_ifx_phy_mode, .wifi0iram.10, .wifi0iram.15, .wifi0iram.16, .wifi0iram.7, .wifi0iram.9, .wifiextrairam.11, .wifiextrairam.14, .wifirxiram.20, .wifirxiram.8
 * Undefined refs (15): g_ic, g_mesh_init_ps_type, g_mesh_is_root, g_mesh_is_started, g_osi_funcs_p, g_wifi_mac_time_delta, g_wifi_nvs, lmacConfMib, memcmp, memcpy, memset, wDevCtrl, wifi_assert, wifi_log, wl_is_ap_no_lr
 */
#include <stdint.h>
#define REG32(a) (*(volatile uint32_t *)(a))
#define REG16(a) (*(volatile uint16_t *)(a))
#define REG8(a)  (*(volatile uint8_t *)(a))
#define MEM32(a) (*(volatile uint32_t *)(a))
#define MEM16(a) (*(volatile uint16_t *)(a))
#define MEM8(a)  (*(volatile uint8_t *)(a))
#define MEMW() __asm__ volatile("memw" ::: "memory")

extern uint32_t rodata_CSWTCH_98; /* .rodata.CSWTCH$98 */
extern uint32_t rodata_wlog_error_2; /* .rodata_wlog_error.2 */
extern int32_t wifi_log();
extern uint32_t rodata_wlog_error_3; /* .rodata_wlog_error.3 */
extern uint32_t rodata_wlog_error_4; /* .rodata_wlog_error.4 */
extern uint32_t g_mesh_is_started; /* g_mesh_is_started */
extern uint32_t rodata_wlog_warning_5; /* .rodata_wlog_warning.5 */
extern int32_t trc_ctl();
extern int32_t rcP2P11NSchedTbl();
extern int32_t rc11NSchedTbl();
extern int32_t rcP2P11GSchedTbl();
extern int32_t rc11GSchedTbl();
extern int32_t BasicOFDMSched();
extern int32_t rc11BSchedTbl();
extern int32_t rcLoRaSchedTbl();
extern uint32_t rodata_wlog_warning_6; /* .rodata_wlog_warning.6 */
extern uint32_t g_mesh_is_root; /* g_mesh_is_root */
extern uint32_t g_mesh_init_ps_type; /* g_mesh_init_ps_type */
extern int32_t g_osi_funcs_p();
extern uint32_t g_wifi_mac_time_delta; /* g_wifi_mac_time_delta */
extern uint32_t wDevCtrl; /* wDevCtrl */
extern int32_t BAROFDMSched();
extern uint32_t rodata_FUNCTION_2; /* .rodata.__FUNCTION__$2 */
extern uint32_t rodata_rcGetAmpduSched_str1_1; /* .rodata.rcGetAmpduSched.str1.1 */
extern int32_t wifi_assert();
extern uint32_t rodata_FUNCTION_1; /* .rodata.__FUNCTION__$1 */
extern int32_t rodata_rssi_margin();
extern uint32_t rodata_TRC_AMPDU_PER_DOWN_THRESHOLD; /* .rodata.TRC_AMPDU_PER_DOWN_THRESHOLD */
extern int32_t trcStopAmpdu_constprop_0(); /* fwd: static in another object */
extern uint32_t rodata_TRC_AMPDU_PER_UP_THRESHOLD; /* .rodata.TRC_AMPDU_PER_UP_THRESHOLD */
extern int32_t wl_is_ap_no_lr();
extern uint32_t g_wifi_nvs; /* g_wifi_nvs */
extern uint32_t rodata_wlog_error_12; /* .rodata_wlog_error.12 */
extern uint32_t rodata_FUNCTION_0; /* .rodata.__FUNCTION__$0 */
extern uint32_t rodata_wlog_error_13; /* .rodata_wlog_error.13 */
extern int32_t rodata_trc_NeedRTS();
extern uint32_t lmacConfMib; /* lmacConfMib */
extern int32_t trcResumeAmpdu_constprop_0(); /* fwd: static in another object */
extern uint32_t bss_g_per_conn_trc; /* .bss.g_per_conn_trc (verify defined-here with nm) */
extern int32_t memcmp();
extern uint32_t rodata_wlog_warning_19; /* .rodata_wlog_warning.19 */
extern uint32_t rodata_wlog_error_21; /* .rodata_wlog_error.21 */
extern uint32_t rodata_wlog_warning_22; /* .rodata_wlog_warning.22 */
extern uint32_t g_ic; /* g_ic */
extern uint32_t rodata_wlog_error_23; /* .rodata_wlog_error.23 */
uint32_t s_fix_rate_mask; /* defined here (.bss/.data); was: s_fix_rate_mask */
uint32_t s_fix_rate; /* defined here (.bss/.data); was: s_fix_rate */
extern uint32_t rodata_wlog_warning_24; /* .rodata_wlog_warning.24 */
extern uint32_t rodata_wlog_error_17; /* .rodata_wlog_error.17 */
extern uint32_t rodata_wlog_warning_18; /* .rodata_wlog_warning.18 */
extern int32_t memset();
extern int32_t memcpy();
extern uint32_t rodata_g_espnow_rate; /* .rodata.g_espnow_rate */
extern uint32_t bss_g_80211_tx_rate; /* .bss.g_80211_tx_rate (verify defined-here with nm) */
extern uint32_t bss_g_80211_tx_rate_config; /* .bss.g_80211_tx_rate_config (verify defined-here with nm) */

/* pool[rc11NRate2SchedIdx]: +0x0=0x00000000 */
/* pool[rc11GRate2SchedIdx]: +0x0=0x00000000 */
/* pool[rc11BRate2SchedIdx]: +0x0=0x00000000 */
/* pool[rx11NRate2AMPDULimit]: +0x0=0x00000000(.rodata.CSWTCH$98) */
/* pool[rcUpdateAMPDUParam]: +0x8=0x00007FFF, +0xc=0x0000FFFF, +0x0=0x00001FFF, +0x4=0x00003FFF */
/* pool[rcGet11NHighestRateIdx]: +0x0=0x00000000(.rodata_wlog_error.2), +0x4=0x00000000(wifi_log) */
/* pool[rcGet11GHighestRateIdx]: +0x0=0x00000000(.rodata_wlog_error.3), +0x4=0x00000000(wifi_log) */
/* pool[rcGet11BHighestRateIdx]: +0x0=0x00000000(.rodata_wlog_error.4), +0x4=0x00000000(wifi_log) */
/* pool[rcGetHighestRateIdx]: +0x0=0x00000000(rcGet11NHighestRateIdx), +0x4=0x00000000(rcGet11GHighestRateIdx), +0x8=0x00000000(rcGet11BHighestRateIdx), +0xc=0x00000000(rcGetDefaultHigestRateIdx) */
/* pool[rcClearCurSched]: +0x0=0x0007A120 */
/* pool[rcClearCurAMPDUSched]: +0x0=0x0007A120 */
/* pool[rcUpdatePhyMode]: +0x24=0x00000000(g_mesh_is_started), +0x28=0x00000000(.rodata_wlog_warning.5), +0x4c=0x00000000(wifi_log), +0x50=0x00000000(rcGetHighestRateIdx), +0x2c=0x00000000(trc_ctl), +0x0=0x00000000(rcP2P11NSchedTbl), +0x4=0x00000000(rc11NSchedTbl), +0x30=0x00000004(.text.rc11NRate2SchedIdx), +0x54=0x00000000(rx11NRate2AMPDULimit), +0x58=0x00000000(rcSetTxAmpduLimit), +0x5c=0x00000000(trcAmpduSetState), +0x60=0x00000000(rcClearCurAMPDUSched), +0x10=0x00000000(rcP2P11GSchedTbl), +0x14=0x00000000(rc11GSchedTbl), +0x34=0x00000004(.text.rc11GRate2SchedIdx), +0x8=0x00000000(rcP2P11GSchedTbl+0x54), +0xc=0x00000000(BasicOFDMSched), +0x38=0x00000000(rc11BSchedTbl), +0x18=0x00000000(rc11BSchedTbl+0x24), +0x3c=0x00000004(.text.rc11BRate2SchedIdx), +0x40=0x00000000(rcLoRaRate2SchedIdx), +0x1c=0x00000000(rcLoRaSchedTbl), +0x44=0x00000000(.rodata_wlog_warning.6), +0x64=0x00000000(wifi_log), +0x68=0x00000000(rcClearCurSched), +0x48=0x7F7F7F7F, +0x20=0x00000000(rcLoRaSchedTbl+0xc) */
/* pool[rcLowerSched]: +0x18=0x00000000(rcClearCurSched), +0x0=0x00000000(g_mesh_is_started), +0x4=0x00000000(g_mesh_is_root), +0x8=0x00000000(g_mesh_init_ps_type), +0xc=0x00000000(g_osi_funcs_p), +0x10=0x3FF73C00, +0x14=0x00000000(g_wifi_mac_time_delta) */
/* pool[rcUpSched]: +0x18=0x00000000(rcClearCurSched), +0x0=0x00000000(g_mesh_is_started), +0x4=0x00000000(g_mesh_is_root), +0x8=0x00000000(g_mesh_init_ps_type), +0xc=0x00000000(g_osi_funcs_p), +0x10=0x3FF73C00, +0x14=0x00000000(g_wifi_mac_time_delta) */
/* pool[rcTxUpdatePer]: +0x0=0x01FFFFFF, +0x4=0x00000000(rcLowerSched) */
/* pool[rcUpdateTxDone]: +0x4=0x00000000(rcUpdateAckSnr), +0x0=0x00000000(g_mesh_is_started), +0x8=0x00000000(rcTxUpdatePer) */
/* pool[rcUpdateRxDone]: +0x0=0x00000000(wDevCtrl) */
/* pool[trc_onAmpduOp]: +0x0=0x00000000(trcAmpduSetState) */
/* pool[trcResumeAmpdu_constprop_0]: +0x0=0x00000000, +0x4=0x00000000, +0x8=0x00000000, +0xc=0x00000000 */
/* pool[trcStopAmpdu_constprop_0]: +0x0=0x00000000, +0x4=0x00000000, +0x8=0x00000000, +0xc=0x00000000 */
/* pool[rcSetBarRate]: +0x0=0x00000000(BAROFDMSched), +0x4=0x00000000(rc11BSchedTbl+0x24) */
/* pool[rc_get_default_sched]: +0x0=0x00000000(rc11BSchedTbl+0x24) */
/* pool[rc_get_G6M_sched]: +0x0=0x00000000(rc11GSchedTbl+0x54) */
/* pool[rcGetAmpduSched]: +0x0=0x000008CD, +0x4=0x00000000(.rodata.__FUNCTION__$2), +0x8=0x00000000(.rodata.rcGetAmpduSched.str1.1), +0xc=0x00000000(wifi_assert) */
/* pool[rcGetRate]: +0x0=0x0000096B, +0x4=0x00000000(.rodata.__FUNCTION__$1), +0x8=0x00000000(.rodata.rcGetAmpduSched.str1.1), +0xc=0x00000000(wifi_assert) */
/* pool[rssi_margin]: +0x0=0x00000000(.rodata.rssi_margin) */
/* pool[TRC_PER_IS_GOOD]: +0x0=0x00000000(rssi_margin) */
/* pool[TRC_AMPDU_PER_DOWN_THRESHOLD]: +0x0=0x00000000(.rodata.TRC_AMPDU_PER_DOWN_THRESHOLD), +0x4=0x00000000(rssi_margin), +0x8=0x00000000(rssi_margin), +0xc=0x00000000(rssi_margin), +0x10=0x00000000(rssi_margin) */
/* pool[rcAmpduLowerRate]: +0x0=0x00000000(trc_ctl), +0x1c=0x00000000(TRC_AMPDU_PER_DOWN_THRESHOLD), +0x20=0x00000010(.text.trcStopAmpdu$constprop$0), +0x4=0x00000000(g_mesh_is_started), +0x8=0x00000000(g_mesh_is_root), +0xc=0x00000000(g_mesh_init_ps_type), +0x10=0x00000000(g_osi_funcs_p), +0x14=0x3FF73C00, +0x18=0x00000000(g_wifi_mac_time_delta), +0x24=0x00000000(rx11NRate2AMPDULimit), +0x28=0x00000000(rcSetTxAmpduLimit), +0x2c=0x00000000(rcClearCurAMPDUSched) */
/* pool[TRC_AMPDU_PER_UP_THRESHOLD]: +0x0=0x00000000(.rodata.TRC_AMPDU_PER_UP_THRESHOLD), +0x4=0x00000000(rssi_margin), +0x8=0x00000000(rssi_margin) */
/* pool[rcUpdateTxDoneAmpdu2]: +0x30=0x00000000(rcUpdateAckSnr), +0x0=0x01FFFFFF, +0x4=0x00000000(trc_ctl), +0x34=0x00000000(TRC_AMPDU_PER_DOWN_THRESHOLD), +0x8=0x00000000(g_mesh_is_started), +0xc=0x00000000(g_mesh_is_root), +0x10=0x00000000(g_mesh_init_ps_type), +0x14=0x00000000(g_osi_funcs_p), +0x18=0x3FF73C00, +0x1c=0x00000000(g_wifi_mac_time_delta), +0x38=0x00000000(trc_calc_duration), +0x20=0x0001869F, +0x28=0x003D08FF, +0x3c=0x00000000(trc_calc_duration), +0x24=0x000186A0, +0x40=0x00000000(rcAmpduLowerRate), +0x2c=0x0007A120, +0x44=0x00000000(TRC_AMPDU_PER_UP_THRESHOLD), +0x48=0x00000000(trc_calc_duration), +0x4c=0x00000000(rx11NRate2AMPDULimit), +0x50=0x00000000(rcSetTxAmpduLimit), +0x54=0x00000000(rcClearCurAMPDUSched) */
/* pool[rcUpdateRate]: +0x0=0x00000000(g_mesh_is_started), +0x4=0x00000000(g_mesh_is_root), +0x8=0x00000000(g_mesh_init_ps_type), +0xc=0x00000000(g_osi_funcs_p), +0x10=0x3FF73C00, +0x14=0x00000000(g_wifi_mac_time_delta), +0x2c=0x00000000(trc_calc_duration), +0x18=0x0001E847, +0x24=0x00000000(trc_ctl), +0x30=0x00000000(trc_calc_duration), +0x20=0x0007A120, +0x34=0x00000000(rcClearCurSched), +0x38=0x00000000(trc_calc_duration), +0x3c=0x00000000(TRC_PER_IS_GOOD), +0x40=0x00000000(rcUpSched), +0x44=0x00000000(rssi_margin), +0x28=0x003D08FF, +0x48=0x00000000(trc_calc_duration), +0x1c=0x0001E848, +0x4c=0x00000000(rcLowerSched) */
/* pool[rcGetSched]: +0x0=0x02000008, +0x18=0x00000000(rcUpdateRate), +0x4=0x00000000(rcLoRaSchedTbl+0xc), +0x8=0x00000000(rc11BSchedTbl+0x24), +0x1c=0x00000000(wl_is_ap_no_lr), +0xc=0x00000000(g_wifi_nvs), +0x10=0x00000000(BasicOFDMSched), +0x14=0x00000000(rcLoRaSchedTbl) */
/* pool[rcReachRetryLimit]: +0x0=0x00000000(.rodata_wlog_error.12), +0x18=0x00000000(wifi_log), +0x4=0x00000ACD, +0x8=0x00000000(.rodata.__FUNCTION__$0), +0xc=0x00000000(.rodata.rcGetAmpduSched.str1.1), +0x1c=0x00000000(wifi_assert), +0x10=0x00000000(.rodata_wlog_error.13), +0x20=0x00000000(wifi_log), +0x24=0x00000000(wifi_assert), +0x14=0x00000000(g_mesh_is_started) */
/* pool[rcAttach]: +0x0=0x00000000(trc_ctl), +0x4=0x00000000(rc11NSchedTbl), +0x1c=0x00000000(.text.rcBuildIndex), +0x8=0x00000000(rcP2P11NSchedTbl), +0x20=0x00000000(.text.rcBuildIndex), +0xc=0x00000000(rc11GSchedTbl), +0x24=0x00000000(.text.rcBuildIndex), +0x10=0x00000000(rcP2P11GSchedTbl), +0x28=0x00000000(.text.rcBuildIndex), +0x14=0x00000000(rc11BSchedTbl), +0x2c=0x00000000(.text.rcBuildIndex), +0x18=0x00000000(rcLoRaSchedTbl), +0x30=0x00000000(.text.rcBuildIndex) */
/* pool[trc_NeedRTS]: +0x0=0x02020480, +0x4=0x01010840, +0x8=0x00000000(.rodata.trc_NeedRTS), +0xc=0x00000000(lmacConfMib) */
/* pool[trc_onPPTxDone]: +0x0=0x00000000(trc_ctl), +0x4=0x00000010(.text.trcResumeAmpdu$constprop$0) */
/* pool[rc_get_mask]: +0x0=0x00000000(trc_ctl) */
/* pool[rc_disable_trc]: +0x0=0x00000000(trc_ctl), +0x4=0x00000000(.bss.g_per_conn_trc), +0xc=0x00000000(memcmp), +0x8=0x00000000(.rodata_wlog_warning.19), +0x10=0x00000000(wifi_log) */
/* pool[rc_disable_trc_by_interface]: +0x0=0x00000000(trc_ctl) */
/* pool[rc_get_sta_trc]: +0x0=0x00000000(trc_ctl), +0x4=0x00000000(.bss.g_per_conn_trc) */
/* pool[rc_get_trc]: +0x0=0x00000000(trc_ctl), +0x4=0x00000000(.bss.g_per_conn_trc), +0x8=0x00000000(memcmp) */
/* pool[rc_get_trc_by_index]: +0x0=0x00000000(trc_ctl), +0x4=0x00000000(.bss.g_per_conn_trc) */
/* pool[rc_get_trc_default]: +0x0=0x00000000(.bss.g_per_conn_trc) */
/* pool[rc_only_sta_trc]: +0x0=0x00000000(trc_ctl) */
/* pool[trc_init]: +0x0=0x00000000(g_osi_funcs_p), +0x4=0x00000000(.bss.g_per_conn_trc), +0x8=0x00000000(.rodata_wlog_error.21), +0x18=0x00000000(wifi_log), +0xc=0x00000000(rc11BSchedTbl+0x24), +0x10=0x00000000(rc11BSchedTbl), +0x14=0x00000000(rcP2P11GSchedTbl+0x54) */
/* pool[trc_update_def_rate]: +0x0=0x00000000(.bss.g_per_conn_trc), +0x4=0x00000000(rcP2P11GSchedTbl+0x54), +0x8=0x00000000(rcP2P11GSchedTbl), +0xc=0x00000000(rc11BSchedTbl+0x24), +0x10=0x00000000(rc11BSchedTbl), +0x14=0x00000000(.rodata_wlog_warning.22), +0x18=0x00000000(wifi_log) */
/* pool[trc_update_ifx_phy_mode]: +0x8=0x00000000(.bss.g_per_conn_trc), +0xc=0x00000000(g_ic), +0x10=0x00000000(.rodata_wlog_error.23), +0x1c=0x00000000(wifi_log), +0x14=0x00000000(rcLoRaSchedTbl+0xc), +0x18=0x00000000(rcLoRaSchedTbl), +0x0=0x00000000(rcP2P11GSchedTbl+0x54), +0x4=0x00000000(rc11BSchedTbl+0x24) */
/* pool[trc_deinit]: +0x0=0x00000000(.bss.g_per_conn_trc), +0x4=0x00000000(g_osi_funcs_p) */
/* pool[rc_set_per_conn_fix_rate]: +0x0=0x00000000(.bss.g_per_conn_trc), +0x4=0x00000000(s_fix_rate_mask), +0x8=0x00000000(s_fix_rate), +0x10=0x00000010(.text.trcResumeAmpdu$constprop$0), +0x14=0x00000000(rx11NRate2AMPDULimit), +0x18=0x00000000(rcSetTxAmpduLimit), +0x1c=0x00000010(.text.trcStopAmpdu$constprop$0), +0xc=0x00000000(.rodata_wlog_warning.24), +0x20=0x00000000(wifi_log), +0x24=0x00000000(trcAmpduSetState), +0x28=0x00000010(.text.trcResumeAmpdu$constprop$0) */
/* pool[rc_enable_trc]: +0x0=0x00000000(.bss.g_per_conn_trc), +0x4=0x00000000(g_osi_funcs_p), +0x8=0x00000000(.rodata_wlog_error.17), +0x14=0x00000000(wifi_log), +0xc=0x00000000(trc_ctl), +0x18=0x00000000(memcmp), +0x10=0x00000000(.rodata_wlog_warning.18), +0x1c=0x00000000(wifi_log), +0x20=0x00000000(memset), +0x24=0x00000000(memcpy), +0x28=0x00000000(rc_set_per_conn_fix_rate) */
/* pool[rc_get_fix_rate]: +0x0=0x00000000(s_fix_rate), +0x4=0x00000000(s_fix_rate_mask) */
/* pool[rc_set_fix_rate]: +0x0=0x00000000(s_fix_rate_mask), +0x4=0x00000000(s_fix_rate), +0x8=0x00000000(rc_set_per_conn_fix_rate), +0xc=0x00000000(rc_set_per_conn_fix_rate), +0x10=0x00000000(rc_set_per_conn_fix_rate), +0x14=0x00000000(rc_set_per_conn_fix_rate), +0x18=0x00000000(rc_set_per_conn_fix_rate) */
/* pool[trc_get_espnow_rate]: +0x0=0x00000000(.rodata.g_espnow_rate) */
/* pool[trc_get_80211_tx_rate]: +0x0=0x00000000(.bss.g_80211_tx_rate) */
/* pool[trc_get_80211_tx_rate_config]: +0x0=0x00000000(.bss.g_80211_tx_rate_config), +0x4=0x00000000(memcpy) */
/* pool[trc_set_80211_tx_rate]: +0x0=0x00000000(.bss.g_80211_tx_rate) */
/* pool[trc_set_80211_tx_rate_config]: +0x0=0x00000000(.bss.g_80211_tx_rate_config), +0x4=0x00000000(memcpy) */

/* rcLoRaRate2SchedIdx @ trc.o 00000000 size 30B bind GLOBAL
 * Calls: none | Data refs: none
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t rcLoRaRate2SchedIdx(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.rcLoRaRate2SchedIdx; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_0:;
  /* 0000: entry a1, 32 */
  a8 = (a2 >> 0) & 0xFF; /* 0003: extui a8, a2, 0, 8 */
  a9 = 0x29; /* 0006: movi.n a9, 41 */
  a2 = 0x1; /* 0008: movi.n a2, 1 */
  if (a8 == a9) goto L_1c; /* 000a: beq a8, a9, 1c <rcLoRaRate2SchedIdx+0x1c> */
  a8 = a8 + (-42); /* 000d: addi a8, a8, -42 */
  a9 = 0x0; /* 0010: movi a9, 0 */
  if (a8 == 0) a2 = a9; /* 0013: moveqz a2, a9, a8 */
  a2 = -a2; /* 0016: neg a2, a2 */
  a2 = (a2 >> 0) & 0xFF; /* 0019: extui a2, a2, 0, 8 */
L_1c:;
  return (int32_t)a2; /* 001c: retw.n  */
}

/* trc_calc_duration @ trc.o 00000000 size 16B bind GLOBAL
 * Calls: none | Data refs: none
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t trc_calc_duration(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.trc_calc_duration; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_0:;
  /* 0000: entry a1, 32 */
  a8 = a2 - a3; /* 0003: sub a8, a2, a3 */
  if (a2 >= a3) goto L_c; /* 0006: bgeu a2, a3, c <trc_calc_duration+0xc> */
  a8 = a8 + (-1); /* 0009: addi a8, a8, -1 */
L_c:;
  a2 = a8; /* 000c: mov.n a2, a8 */
  return (int32_t)a2; /* 000e: retw.n  */
}

/* rx11NRate2AMPDULimit @ trc.o 00000004 size 27B bind GLOBAL
 * Calls: none | Data refs: .rodata.CSWTCH$98
 *   MMIO: none
 *   funcdb v3: 0 call(s), 1 ref(s); disasm: 0 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t rx11NRate2AMPDULimit(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.rx11NRate2AMPDULimit; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a2 = a2 + (-16); /* 0007: addi a2, a2, -16 */
  a8 = (a2 >> 0) & 0xFF; /* 000a: extui a8, a2, 0, 8 */
  a9 = 0xF; /* 000d: movi.n a9, 15 */
  a2 = 0x0; /* 000f: movi.n a2, 0 */
  if (a9 < a8) goto L_1d; /* 0011: bltu a9, a8, 1d <rx11NRate2AMPDULimit+0x19> */
  a2 = (uint32_t)&lit_rodata_CSWTCH_98; /* 0014: l32r a2, 0 <rx11NRate2AMPDULimit-0x4> (0 <rx11NRate2AMPDULimit-0x4>) */ /* literal @0x0: .rodata.CSWTCH$98 */
  a8 = (a8 << 2) + a2; /* 0017: addx2 a8, a8, a2 */
  a2 = MEM16(a8 + 0); /* 001a: l16ui a2, a8, 0 */
L_1d:;
  return (int32_t)a2; /* 001d: retw.n  */
}

/* trcAmpduSetState @ trc.o 00000000 size 35B bind GLOBAL
 * Calls: none | Data refs: none
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t trcAmpduSetState(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.trcAmpduSetState; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_0:;
  /* 0000: entry a1, 32 */
  a10 = MEM8(a2 + 16); /* 0003: l8ui a10, a2, 16 */
  a3 = (a3 >> 0) & 0xFF; /* 0006: extui a3, a3, 0, 8 */
  a8 = 0x0; /* 0009: movi.n a8, 0 */
  a9 = 0x8; /* 000b: movi a9, 8 */
  /* 000e: loop a9, 1e <trcAmpduSetState+0x1e> */ /* loop a9 times, end L_1e; body shown single-pass */
  if (!((a10 >> (a8 & 31)) & 1)) goto L_1c; /* 0011: bbc a10, a8, 1c <trcAmpduSetState+0x1c> */
  a11 = a2 + a8; /* 0014: add.n a11, a2, a8 */
  MEM8(a11 + 17) = a3; /* 0016: s8i a3, a11, 17 */
  MEMW(); /* 0019: memw  */
L_1c:;
  a8 = 0x1; /* 001c: addi.n a8, a8, 1 */
L_1e:;
  MEMW(); /* 001e: memw  */
  return (int32_t)a2; /* 0021: retw.n  */
}

/* rcSetTxAmpduLimit @ trc.o 00000000 size 32B bind GLOBAL
 * Calls: none | Data refs: none
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t rcSetTxAmpduLimit(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.rcSetTxAmpduLimit; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_0:;
  /* 0000: entry a1, 32 */
  a8 = MEM16(a2 + 120); /* 0003: l16ui a8, a2, 120 */
  a3 = (a3 >> 0) & 0xFFFF; /* 0006: extui a3, a3, 0, 16 */
  /* 0009: minu a9, a8, a3 */ /* UNMODELED: a9 clobbered */
  a3 = a3 >> (1 & 31); /* 000c: srli a3, a3, 1 */
  /* 000f: minu a3, a3, a8 */ /* UNMODELED: a3 clobbered */
  MEM16(a2 + 124) = a9; /* 0012: s16i a9, a2, 124 */
  MEM16(a2 + 122) = a3; /* 0015: s16i a3, a2, 122 */
  MEMW(); /* 0018: memw  */
  MEMW(); /* 001b: memw  */
  return (int32_t)a2; /* 001e: retw.n  */
}

/* rcUpdateAMPDUParam @ trc.o 00000010 size 157B bind GLOBAL
 * Calls: none | Data refs: none
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: medium - 55 instr, 21 branches, calls resolved */
int32_t rcUpdateAMPDUParam(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.rcUpdateAMPDUParam; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_10:;
  /* 0010: entry a1, 32 */
  a3 = (a3 >> 0) & 0xFF; /* 0013: extui a3, a3, 0, 8 */
  MEM8(a2 + 130) = a3; /* 0016: s8i a3, a2, 130 */
  MEMW(); /* 0019: memw  */
  a4 = (a4 >> 0) & 0xFF; /* 001c: extui a4, a4, 0, 8 */
  a5 = (a5 >> 0) & 0xFF; /* 001f: extui a5, a5, 0, 8 */
  if (a3 >= 4) goto L_30; /* 0022: bgeui a3, 4, 30 <rcUpdateAMPDUParam+0x20> */
  if (a3 < 2) goto L_a8; /* 0025: bltui a3, 2, a8 <rcUpdateAMPDUParam+0x98> */
  MEMW(); /* 0028: memw  */
  goto L_3c; /* 002b: j 3c <rcUpdateAMPDUParam+0x2c> */
  /* 002e: .byte 00 */
  /* 002f: .byte 00 */
L_30:;
  a3 = a3 + (-4); /* 0030: addi a3, a3, -4 */
  a3 = (a3 >> 0) & 0xFF; /* 0033: extui a3, a3, 0, 8 */
  if (a3 < 2) goto L_78; /* 0036: bltui a3, 2, 78 <rcUpdateAMPDUParam+0x68> */
  goto L_a8; /* 0039: j a8 <rcUpdateAMPDUParam+0x98> */
L_3c:;
  a3 = 0x7FFF; /* 003c: l32r a3, 8 <rcUpdateAMPDUParam-0x8> (7fff <rcUpdatePhyMode+0x7f93>) */ @0x8
  if (a4 == 2) goto L_51; /* 003f: beqi a4, 2, 51 <rcUpdateAMPDUParam+0x41> */
  a3 = 0xFFFF; /* 0042: l32r a3, c <rcUpdateAMPDUParam-0x4> (ffff <rcUpdatePhyMode+0xff93>) */ @0xC
  if (a4 == 3) goto L_51; /* 0045: beqi a4, 3, 51 <rcUpdateAMPDUParam+0x41> */
  a3 = 0x1FFF; /* 0048: l32r a3, 0 <rcUpdateAMPDUParam-0x10> (1fff <rcUpdatePhyMode+0x1f93>) */ @0x0
  if (a4 != 1) goto L_51; /* 004b: bnei a4, 1, 51 <rcUpdateAMPDUParam+0x41> */
  a3 = 0x3FFF; /* 004e: l32r a3, 4 <rcUpdateAMPDUParam-0xc> (3fff <rcUpdatePhyMode+0x3f93>) */ @0x4
L_51:;
  MEM16(a2 + 120) = a3; /* 0051: s16i a3, a2, 120 */
  MEMW(); /* 0054: memw  */
  a3 = 0x28; /* 0057: movi.n a3, 40 */
  if (a5 == 5) goto L_a2; /* 0059: beqi a5, 5, a2 <rcUpdateAMPDUParam+0x92> */
  if (a5 < 6) goto L_68; /* 005c: bltui a5, 6, 68 <rcUpdateAMPDUParam+0x58> */
  if (a5 == 6) goto L_6d; /* 005f: beqi a5, 6, 6d <rcUpdateAMPDUParam+0x5d> */
  MEMW(); /* 0062: memw  */
  goto L_72; /* 0065: j 72 <rcUpdateAMPDUParam+0x62> */
L_68:;
  a3 = 0x14; /* 0068: movi.n a3, 20 */
  goto L_a2; /* 006a: j a2 <rcUpdateAMPDUParam+0x92> */
L_6d:;
  a3 = 0x4C; /* 006d: movi.n a3, 76 */
  goto L_a2; /* 006f: j a2 <rcUpdateAMPDUParam+0x92> */
L_72:;
  a3 = 0x94; /* 0072: movi a3, 148 */
  goto L_a2; /* 0075: j a2 <rcUpdateAMPDUParam+0x92> */
L_78:;
  a3 = 0x7FFF; /* 0078: l32r a3, 8 <rcUpdateAMPDUParam-0x8> (7fff <rcUpdatePhyMode+0x7f93>) */ @0x8
  if (a4 == 2) goto L_8d; /* 007b: beqi a4, 2, 8d <rcUpdateAMPDUParam+0x7d> */
  a3 = 0xFFFF; /* 007e: l32r a3, c <rcUpdateAMPDUParam-0x4> (ffff <rcUpdatePhyMode+0xff93>) */ @0xC
  if (a4 == 3) goto L_8d; /* 0081: beqi a4, 3, 8d <rcUpdateAMPDUParam+0x7d> */
  a3 = 0x1FFF; /* 0084: l32r a3, 0 <rcUpdateAMPDUParam-0x10> (1fff <rcUpdatePhyMode+0x1f93>) */ @0x0
  if (a4 != 1) goto L_8d; /* 0087: bnei a4, 1, 8d <rcUpdateAMPDUParam+0x7d> */
  a3 = 0x3FFF; /* 008a: l32r a3, 4 <rcUpdateAMPDUParam-0xc> (3fff <rcUpdatePhyMode+0x3f93>) */ @0x4
L_8d:;
  MEM16(a2 + 120) = a3; /* 008d: s16i a3, a2, 120 */
  MEMW(); /* 0090: memw  */
  if (a5 == 5) goto L_6d; /* 0093: beqi a5, 5, 6d <rcUpdateAMPDUParam+0x5d> */
  if (a5 < 6) goto L_68; /* 0096: bltui a5, 6, 68 <rcUpdateAMPDUParam+0x58> */
  a3 = 0x98; /* 0099: movi a3, 152 */
  if (a5 == 6) goto L_a2; /* 009c: beqi a5, 6, a2 <rcUpdateAMPDUParam+0x92> */
  a3 = 0x12C; /* 009f: movi a3, 0x12c */
L_a2:;
  MEM16(a2 + 126) = a3; /* 00a2: s16i a3, a2, 126 */
  MEMW(); /* 00a5: memw  */
L_a8:;
  MEMW(); /* 00a8: memw  */
  return (int32_t)a2; /* 00ab: retw.n  */
}

/* rcGet11NHighestRateIdx @ trc.o 00000008 size 104B bind GLOBAL
 * Calls: wifi_log | Data refs: .rodata_wlog_error.2, wifi_log
 *   MMIO: none
 *   funcdb v3: 1 call(s), 2 ref(s); disasm: 1 call(s), 2 data ref(s)
 * Fidelity: medium - 42 instr, 12 branches, calls resolved */
int32_t rcGet11NHighestRateIdx(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.rcGet11NHighestRateIdx; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_8:;
  /* 0008: entry a1, 32 */
  a14 = (a2 >> 0) & 0xFF; /* 000b: extui a14, a2, 0, 8 */
  a8 = 0x4E; /* 000e: movi.n a8, 78 */
  a2 = 0x4; /* 0010: movi.n a2, 4 */
  if (a14 == a8) goto L_6e; /* 0012: beq a14, a8, 6e <rcGet11NHighestRateIdx+0x66> */
  if (a8 < a14) goto L_38; /* 0015: bltu a8, a14, 38 <rcGet11NHighestRateIdx+0x30> */
  a8 = 0x27; /* 0018: movi.n a8, 39 */
  a2 = 0x6; /* 001a: movi.n a2, 6 */
  if (a14 == a8) goto L_6e; /* 001c: beq a14, a8, 6e <rcGet11NHighestRateIdx+0x66> */
  if (a8 < a14) goto L_30; /* 001f: bltu a8, a14, 30 <rcGet11NHighestRateIdx+0x28> */
  a8 = 0xD; /* 0022: movi.n a8, 13 */
  a2 = 0x8; /* 0024: movi.n a2, 8 */
  if (a14 == a8) goto L_6e; /* 0026: beq a14, a8, 6e <rcGet11NHighestRateIdx+0x66> */
  a8 = 0x1A; /* 0029: movi.n a8, 26 */
  a2 = 0x7; /* 002b: movi.n a2, 7 */
  goto L_59; /* 002d: j 59 <rcGet11NHighestRateIdx+0x51> */
L_30:;
  a8 = 0x34; /* 0030: movi.n a8, 52 */
  a2 = 0x5; /* 0032: movi.n a2, 5 */
  goto L_59; /* 0034: j 59 <rcGet11NHighestRateIdx+0x51> */
  /* 0037: .byte 00 */
L_38:;
  a8 = 0x82; /* 0038: movi a8, 130 */
  a2 = 0x1; /* 003b: movi.n a2, 1 */
  if (a14 == a8) goto L_6e; /* 003d: beq a14, a8, 6e <rcGet11NHighestRateIdx+0x66> */
  if (a8 < a14) goto L_54; /* 0040: bltu a8, a14, 54 <rcGet11NHighestRateIdx+0x4c> */
  a8 = 0x68; /* 0043: movi a8, 104 */
  a2 = 0x3; /* 0046: movi.n a2, 3 */
  if (a14 == a8) goto L_6e; /* 0048: beq a14, a8, 6e <rcGet11NHighestRateIdx+0x66> */
  a8 = 0x75; /* 004b: movi a8, 117 */
  a2 = 0x2; /* 004e: movi.n a2, 2 */
  goto L_59; /* 0050: j 59 <rcGet11NHighestRateIdx+0x51> */
  /* 0053: .byte 00 */
L_54:;
  a8 = 0x90; /* 0054: movi a8, 144 */
  a2 = 0x0; /* 0057: movi.n a2, 0 */
L_59:;
  if (a14 == a8) goto L_6e; /* 0059: beq a14, a8, 6e <rcGet11NHighestRateIdx+0x66> */
  a13 = (uint32_t)&lit_rodata_wlog_error_2; /* 005c: l32r a13, 0 <rcGet11NHighestRateIdx-0x8> (0 <rcGet11NHighestRateIdx-0x8>) */ /* literal @0x0: .rodata_wlog_error.2 */
  a12 = 0x1; /* 005f: movi.n a12, 1 */
  a11 = 0x200; /* 0061: movi a11, 0x200 */
  a10 = 0x6; /* 0064: movi.n a10, 6 */
  a8 = (uint32_t)&wifi_log; /* 0066: l32r a8, 4 <rcGet11NHighestRateIdx-0x4> (0 <rcGet11NHighestRateIdx-0x8>) */ /* literal: GOT slot for wifi_log */
  wifi_log(a2, a3, a4, a5); /* call via literal slot */ /* 0069: callx8 a8 */
  a2 = 0x0; /* 006c: movi.n a2, 0 */
L_6e:;
  return (int32_t)a2; /* 006e: retw.n  */
}

/* rcGet11GHighestRateIdx @ trc.o 00000008 size 88B bind GLOBAL
 * Calls: wifi_log | Data refs: .rodata_wlog_error.3, wifi_log
 *   MMIO: none
 *   funcdb v3: 1 call(s), 2 ref(s); disasm: 1 call(s), 2 data ref(s)
 * Fidelity: medium - 35 instr, 10 branches, calls resolved */
int32_t rcGet11GHighestRateIdx(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.rcGet11GHighestRateIdx; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_8:;
  /* 0008: entry a1, 32 */
  a14 = (a2 >> 0) & 0xFF; /* 000b: extui a14, a2, 0, 8 */
  a8 = 0x30; /* 000e: movi.n a8, 48 */
  a2 = 0x3; /* 0010: movi.n a2, 3 */
  if (a14 == a8) goto L_5e; /* 0012: beq a14, a8, 5e <rcGet11GHighestRateIdx+0x56> */
  if (a8 < a14) goto L_35; /* 0015: bltu a8, a14, 35 <rcGet11GHighestRateIdx+0x2d> */
  a8 = 0x18; /* 0018: movi.n a8, 24 */
  a2 = 0x5; /* 001a: movi.n a2, 5 */
  if (a14 == a8) goto L_5e; /* 001c: beq a14, a8, 5e <rcGet11GHighestRateIdx+0x56> */
  if (a8 < a14) goto L_2e; /* 001f: bltu a8, a14, 2e <rcGet11GHighestRateIdx+0x26> */
  a2 = 0x7; /* 0022: movi.n a2, 7 */
  if (a14 == 12) goto L_5e; /* 0024: beqi a14, 12, 5e <rcGet11GHighestRateIdx+0x56> */
  a8 = 0x12; /* 0027: movi.n a8, 18 */
  a2 = 0x6; /* 0029: movi.n a2, 6 */
  goto L_49; /* 002b: j 49 <rcGet11GHighestRateIdx+0x41> */
L_2e:;
  a8 = 0x24; /* 002e: movi.n a8, 36 */
  a2 = 0x4; /* 0030: movi.n a2, 4 */
  goto L_49; /* 0032: j 49 <rcGet11GHighestRateIdx+0x41> */
L_35:;
  a8 = 0x60; /* 0035: movi a8, 96 */
  a2 = 0x1; /* 0038: movi.n a2, 1 */
  if (a14 == a8) goto L_5e; /* 003a: beq a14, a8, 5e <rcGet11GHighestRateIdx+0x56> */
  a8 = 0x6C; /* 003d: movi a8, 108 */
  a2 = 0x0; /* 0040: movi.n a2, 0 */
  if (a14 == a8) goto L_5e; /* 0042: beq a14, a8, 5e <rcGet11GHighestRateIdx+0x56> */
  a8 = 0x48; /* 0045: movi.n a8, 72 */
  a2 = 0x2; /* 0047: movi.n a2, 2 */
L_49:;
  if (a14 == a8) goto L_5e; /* 0049: beq a14, a8, 5e <rcGet11GHighestRateIdx+0x56> */
  a13 = (uint32_t)&lit_rodata_wlog_error_3; /* 004c: l32r a13, 0 <rcGet11GHighestRateIdx-0x8> (0 <rcGet11GHighestRateIdx-0x8>) */ /* literal @0x0: .rodata_wlog_error.3 */
  a12 = 0x1; /* 004f: movi.n a12, 1 */
  a11 = 0x200; /* 0051: movi a11, 0x200 */
  a10 = 0x6; /* 0054: movi.n a10, 6 */
  a8 = (uint32_t)&wifi_log; /* 0056: l32r a8, 4 <rcGet11GHighestRateIdx-0x4> (0 <rcGet11GHighestRateIdx-0x8>) */ /* literal: GOT slot for wifi_log */
  wifi_log(a2, a3, a4, a5); /* call via literal slot */ /* 0059: callx8 a8 */
  a2 = 0x0; /* 005c: movi.n a2, 0 */
L_5e:;
  return (int32_t)a2; /* 005e: retw.n  */
}

/* rcGet11BHighestRateIdx @ trc.o 00000008 size 56B bind GLOBAL
 * Calls: wifi_log | Data refs: .rodata_wlog_error.4, wifi_log
 *   MMIO: none
 *   funcdb v3: 1 call(s), 2 ref(s); disasm: 1 call(s), 2 data ref(s)
 * Fidelity: medium - 22 instr, 6 branches, calls resolved */
int32_t rcGet11BHighestRateIdx(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.rcGet11BHighestRateIdx; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_8:;
  /* 0008: entry a1, 32 */
  a14 = (a2 >> 0) & 0xFF; /* 000b: extui a14, a2, 0, 8 */
  a8 = 0xB; /* 000e: movi.n a8, 11 */
  a2 = 0x1; /* 0010: movi.n a2, 1 */
  if (a14 == a8) goto L_3e; /* 0012: beq a14, a8, 3e <rcGet11BHighestRateIdx+0x36> */
  if (a8 < a14) goto L_25; /* 0015: bltu a8, a14, 25 <rcGet11BHighestRateIdx+0x1d> */
  a2 = 0x3; /* 0018: movi.n a2, 3 */
  if (a14 == 2) goto L_3e; /* 001a: beqi a14, 2, 3e <rcGet11BHighestRateIdx+0x36> */
  a2 = 0x2; /* 001d: movi.n a2, 2 */
  if (a14 == 4) goto L_3e; /* 001f: beqi a14, 4, 3e <rcGet11BHighestRateIdx+0x36> */
  goto L_2c; /* 0022: j 2c <rcGet11BHighestRateIdx+0x24> */
L_25:;
  a8 = 0x16; /* 0025: movi.n a8, 22 */
  a2 = 0x0; /* 0027: movi.n a2, 0 */
  if (a14 == a8) goto L_3e; /* 0029: beq a14, a8, 3e <rcGet11BHighestRateIdx+0x36> */
L_2c:;
  a13 = (uint32_t)&lit_rodata_wlog_error_4; /* 002c: l32r a13, 0 <rcGet11BHighestRateIdx-0x8> (0 <rcGet11BHighestRateIdx-0x8>) */ /* literal @0x0: .rodata_wlog_error.4 */
  a12 = 0x1; /* 002f: movi.n a12, 1 */
  a11 = 0x200; /* 0031: movi a11, 0x200 */
  a10 = 0x6; /* 0034: movi.n a10, 6 */
  a8 = (uint32_t)&wifi_log; /* 0036: l32r a8, 4 <rcGet11BHighestRateIdx-0x4> (0 <rcGet11BHighestRateIdx-0x8>) */ /* literal: GOT slot for wifi_log */
  wifi_log(a2, a3, a4, a5); /* call via literal slot */ /* 0039: callx8 a8 */
  a2 = 0x0; /* 003c: movi.n a2, 0 */
L_3e:;
  return (int32_t)a2; /* 003e: retw.n  */
}

/* rcGetDefaultHigestRateIdx @ trc.o 00000000 size 24B bind GLOBAL
 * Calls: none | Data refs: none
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t rcGetDefaultHigestRateIdx(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.rcGetDefaultHigestRateIdx; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_0:;
  /* 0000: entry a1, 32 */
  a8 = MEM8(a2 + 130); /* 0003: l8ui a8, a2, 130 */
  a2 = 0xFD; /* 0006: movi a2, 253 */
  a8 = a8 + (-2); /* 0009: addi a8, a8, -2 */
  a8 = a8 & a2; /* 000c: and a8, a8, a2 */
  a9 = 0x0; /* 000f: movi.n a9, 0 */
  a2 = 0x1; /* 0011: movi.n a2, 1 */
  if (a8 != 0) a2 = a9; /* 0013: movnez a2, a9, a8 */
  return (int32_t)a2; /* 0016: retw.n  */
}

/* rcGetHighestRateIdx @ trc.o 00000010 size 73B bind GLOBAL
 * Calls: rcGet11BHighestRateIdx, rcGet11GHighestRateIdx, rcGet11NHighestRateIdx, rcGetDefaultHigestRateIdx | Data refs: rcGet11BHighestRateIdx, rcGet11GHighestRateIdx, rcGet11NHighestRateIdx, rcGetDefaultHigestRateIdx
 *   MMIO: none
 *   funcdb v3: 4 call(s), 4 ref(s); disasm: 4 call(s), 4 data ref(s)
 * Fidelity: medium - 27 instr, 8 branches, calls resolved */
int32_t rcGetHighestRateIdx(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.rcGetHighestRateIdx; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_10:;
  /* 0010: entry a1, 32 */
  a4 = (a4 >> 0) & 0xFF; /* 0013: extui a4, a4, 0, 8 */
  a10 = (a3 >> 0) & 0xFF; /* 0016: extui a10, a3, 0, 8 */
  if (a4 != 0) goto L_20; /* 0019: bnez.n a4, 20 <rcGetHighestRateIdx+0x10> */
  goto L_4d; /* 001b: j 4d <rcGetHighestRateIdx+0x3d> */
  /* 001e: .byte 00 */
  /* 001f: .byte 00 */
L_20:;
  a8 = MEM8(a2 + 130); /* 0020: l8ui a8, a2, 130 */
  if (a8 == 1) goto L_3b; /* 0023: beqi a8, 1, 3b <rcGetHighestRateIdx+0x2b> */
  if (a8 < 2) goto L_44; /* 0026: bltui a8, 2, 44 <rcGetHighestRateIdx+0x34> */
  a8 = a8 + (-2); /* 0029: addi a8, a8, -2 */
  a8 = (a8 >> 0) & 0xFF; /* 002c: extui a8, a8, 0, 8 */
  if (a8 >= 4) goto L_4d; /* 002f: bgeui a8, 4, 4d <rcGetHighestRateIdx+0x3d> */
  a8 = (uint32_t)&rcGet11NHighestRateIdx; /* 0032: l32r a8, 0 <rcGetHighestRateIdx-0x10> (0 <rcGetHighestRateIdx-0x10>) */ /* literal: GOT slot for rcGet11NHighestRateIdx */
  rcGet11NHighestRateIdx(a2, a3, a4, a5); /* call via literal slot */ /* 0035: callx8 a8 */
  goto L_55; /* 0038: j 55 <rcGetHighestRateIdx+0x45> */
L_3b:;
  a8 = (uint32_t)&rcGet11GHighestRateIdx; /* 003b: l32r a8, 4 <rcGetHighestRateIdx-0xc> (0 <rcGetHighestRateIdx-0x10>) */ /* literal: GOT slot for rcGet11GHighestRateIdx */
  rcGet11GHighestRateIdx(a2, a3, a4, a5); /* call via literal slot */ /* 003e: callx8 a8 */
  goto L_55; /* 0041: j 55 <rcGetHighestRateIdx+0x45> */
L_44:;
  a8 = (uint32_t)&rcGet11BHighestRateIdx; /* 0044: l32r a8, 8 <rcGetHighestRateIdx-0x8> (0 <rcGetHighestRateIdx-0x10>) */ /* literal: GOT slot for rcGet11BHighestRateIdx */
  rcGet11BHighestRateIdx(a2, a3, a4, a5); /* call via literal slot */ /* 0047: callx8 a8 */
  goto L_55; /* 004a: j 55 <rcGetHighestRateIdx+0x45> */
L_4d:;
  a10 = a2; /* 004d: mov.n a10, a2 */
  a8 = (uint32_t)&rcGetDefaultHigestRateIdx; /* 004f: l32r a8, c <rcGetHighestRateIdx-0x4> (0 <rcGetHighestRateIdx-0x10>) */ /* literal: GOT slot for rcGetDefaultHigestRateIdx */
  rcGetDefaultHigestRateIdx(a2, a3, a4, a5); /* call via literal slot */ /* 0052: callx8 a8 */
L_55:;
  a2 = a10; /* 0055: mov.n a2, a10 */
  return (int32_t)a2; /* 0057: retw.n  */
}

/* rcClearCurStat @ trc.o 00000000 size 16B bind GLOBAL
 * Calls: none | Data refs: none
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t rcClearCurStat(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.rcClearCurStat; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_0:;
  /* 0000: entry a1, 32 */
  a8 = 0x0; /* 0003: movi.n a8, 0 */
  MEM32(a2 + 44) = a8; /* 0005: s32i.n a8, a2, 44 */
  MEM32(a2 + 40) = a8; /* 0007: s32i.n a8, a2, 40 */
  MEM32(a2 + 60) = a8; /* 0009: s32i.n a8, a2, 60 */
  MEMW(); /* 000b: memw  */
  return (int32_t)a2; /* 000e: retw.n  */
}

/* rcClearCurSched @ trc.o 00000004 size 45B bind GLOBAL
 * Calls: none | Data refs: none
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t rcClearCurSched(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.rcClearCurSched; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a8 = MEM32(a2 + 96); /* 0007: l32i a8, a2, 96 */
  a9 = 0x0; /* 000a: movi.n a9, 0 */
  MEM8(a8 + 11) = a9; /* 000c: s8i a9, a8, 11 */
  MEMW(); /* 000f: memw  */
  a8 = 0x7A120; /* 0012: l32r a8, 0 <rcClearCurSched-0x4> (7a120 <rcUpdatePhyMode+0x7a0b4>) */ @0x0
  MEM32(a2 + 92) = a8; /* 0015: s32i a8, a2, 92 */
  a8 = 0x0; /* 0018: movi.n a8, 0 */
  MEM32(a2 + 44) = a8; /* 001a: s32i.n a8, a2, 44 */
  MEM32(a2 + 40) = a8; /* 001c: s32i.n a8, a2, 40 */
  MEM32(a2 + 60) = a8; /* 001e: s32i.n a8, a2, 60 */
  MEM8(a2 + 27) = a8; /* 0020: s8i a8, a2, 27 */
  MEM8(a2 + 28) = a9; /* 0023: s8i a9, a2, 28 */
  MEM8(a2 + 7) = a9; /* 0026: s8i a9, a2, 7 */
  MEMW(); /* 0029: memw  */
  MEMW(); /* 002c: memw  */
  return (int32_t)a2; /* 002f: retw.n  */
}

/* rcClearCurAMPDUSched @ trc.o 00000004 size 51B bind GLOBAL
 * Calls: none | Data refs: none
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t rcClearCurAMPDUSched(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.rcClearCurAMPDUSched; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a8 = MEM32(a2 + 96); /* 0007: l32i a8, a2, 96 */
  a9 = 0x0; /* 000a: movi.n a9, 0 */
  MEM8(a8 + 11) = a9; /* 000c: s8i a9, a8, 11 */
  MEMW(); /* 000f: memw  */
  a8 = 0x7A120; /* 0012: l32r a8, 0 <rcClearCurAMPDUSched-0x4> (7a120 <rcUpdatePhyMode+0x7a0b4>) */ @0x0
  MEM32(a2 + 92) = a8; /* 0015: s32i a8, a2, 92 */
  a8 = 0x0; /* 0018: movi.n a8, 0 */
  MEM32(a2 + 68) = a8; /* 001a: s32i a8, a2, 68 */
  MEM32(a2 + 64) = a8; /* 001d: s32i a8, a2, 64 */
  MEM32(a2 + 72) = a8; /* 0020: s32i a8, a2, 72 */
  MEM8(a2 + 29) = a8; /* 0023: s8i a8, a2, 29 */
  MEM8(a2 + 30) = a9; /* 0026: s8i a9, a2, 30 */
  MEM8(a2 + 15) = a9; /* 0029: s8i a9, a2, 15 */
  MEMW(); /* 002c: memw  */
  MEM32(a2 + 88) = a8; /* 002f: s32i a8, a2, 88 */
  MEMW(); /* 0032: memw  */
  return (int32_t)a2; /* 0035: retw.n  */
}

/* rcUpdatePhyMode @ trc.o 0000006c size 664B bind GLOBAL
 * Calls: rcClearCurAMPDUSched, rcClearCurSched, rcGetHighestRateIdx, rcSetTxAmpduLimit, rx11NRate2AMPDULimit, trcAmpduSetState, wifi_log | Data refs: .rodata_wlog_warning.5, .rodata_wlog_warning.6, BasicOFDMSched, g_mesh_is_started, rc11BSchedTbl, rc11GSchedTbl, rc11NSchedTbl, rcClearCurAMPDUSched, rcClearCurSched, rcGetHighestRateIdx, rcLoRaRate2SchedIdx, rcLoRaSchedTbl, rcP2P11GSchedTbl, rcP2P11NSchedTbl, rcSetTxAmpduLimit, rx11NRate2AMPDULimit, trcAmpduSetState, trc_ctl, wifi_log, .text.rc11NRate2SchedIdx, .text.rc11GRate2SchedIdx, .text.rc11BRate2SchedIdx
 *   MMIO: none
 *   funcdb v3: 7 call(s), 19 ref(s); disasm: 8 call(s), 22 data ref(s)
 * Fidelity: low - 244 instr, 34 branches, 0 indirect; call-sequence + MMIO skeleton */
int32_t rcUpdatePhyMode(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.rcUpdatePhyMode; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_6c:;
  /* 006c: entry a1, 48 */
  a8 = (uint32_t)&g_mesh_is_started; /* 006f: l32r a8, 24 <rcUpdatePhyMode-0x48> (0 <rcUpdatePhyMode-0x6c>) */ /* literal @0x24: g_mesh_is_started */
  a3 = (a3 >> 0) & 0xFF; /* 0072: extui a3, a3, 0, 8 */
  a4 = (a4 >> 0) & 0xFF; /* 0075: extui a4, a4, 0, 8 */
  a5 = (a5 >> 0) & 0xFF; /* 0078: extui a5, a5, 0, 8 */
  a6 = (a6 >> 0) & 0xFF; /* 007b: extui a6, a6, 0, 8 */
  a9 = MEM8(a8 + 0); /* 007e: l8ui a9, a8, 0 */
  a7 = MEM8(a2 + 135); /* 0081: l8ui a7, a2, 135 */
  if (a9 == 0) goto L_a5; /* 0084: beqz.n a9, a5 <rcUpdatePhyMode+0x39> */
  if (a4 == 0) goto L_a5; /* 0086: beqz.n a4, a5 <rcUpdatePhyMode+0x39> */
  a9 = ((int32_t)(a3 << (32 - (7 & 31)))) >> (32 - (7 & 31)); /* 0088: sext a9, a3, 7 */
  a15 = a7; /* 008b: mov.n a15, a7 */
  a14 = MEM8(a2 + 130); /* 008d: l8ui a14, a2, 130 */
  a12 = 0x2; /* 0090: movi.n a12, 2 */
  a11 = 0x200; /* 0092: movi a11, 0x200 */
  a10 = 0x6; /* 0095: movi.n a10, 6 */
  a13 = (uint32_t)&lit_rodata_wlog_warning_5; /* 0097: l32r a13, 28 <rcUpdatePhyMode-0x44> (0 <rcUpdatePhyMode-0x6c>) */ /* literal @0x28: .rodata_wlog_warning.5 */
  MEM32(a1 + 0) = a9; /* 009a: s32i.n a9, a1, 0 */
  MEMW(); /* 009c: memw  */
  a8 = (uint32_t)&wifi_log; /* 009f: l32r a8, 4c <rcUpdatePhyMode-0x20> (0 <rcUpdatePhyMode-0x6c>) */ /* literal: GOT slot for wifi_log */
  wifi_log(a2, a3, a4, a5); /* call via literal slot */ /* 00a2: callx8 a8 */
L_a5:;
  a11 = a5; /* 00a5: mov.n a11, a5 */
  a12 = a6; /* 00a7: mov.n a12, a6 */
  a10 = a2; /* 00a9: mov.n a10, a2 */
  a8 = (uint32_t)&rcGetHighestRateIdx; /* 00ab: l32r a8, 50 <rcUpdatePhyMode-0x1c> (0 <rcUpdatePhyMode-0x6c>) */ /* literal: GOT slot for rcGetHighestRateIdx */
  rcGetHighestRateIdx(a2, a3, a4, a5); /* call via literal slot */ /* 00ae: callx8 a8 */
  a5 = MEM8(a2 + 130); /* 00b1: l8ui a5, a2, 130 */
  MEM8(a2 + 26) = a3; /* 00b4: s8i a3, a2, 26 */
  MEMW(); /* 00b7: memw  */
  if (a5 >= 6) goto L_c9; /* 00ba: bgeui a5, 6, c9 <rcUpdatePhyMode+0x5d> */
  if (a5 >= 2) goto L_d4; /* 00bd: bgeui a5, 2, d4 <rcUpdatePhyMode+0x68> */
  if (a5 != 0) goto L_1ac; /* 00c0: bnez a5, 1ac <rcUpdatePhyMode+0x140> */
  MEMW(); /* 00c3: memw  */
  goto L_230; /* 00c6: j 230 <rcUpdatePhyMode+0x1c4> */
L_c9:;
  if (a5 != 6) goto L_cf; /* 00c9: bnei a5, 6, cf <rcUpdatePhyMode+0x63> */
  goto L_270; /* 00cc: j 270 <rcUpdatePhyMode+0x204> */
L_cf:;
  goto L_290; /* 00cf: j 290 <rcUpdatePhyMode+0x224> */
  /* 00d2: .byte 00 */
  /* 00d3: .byte 00 */
L_d4:;
  a5 = (uint32_t)&trc_ctl; /* 00d4: l32r a5, 2c <rcUpdatePhyMode-0x40> (0 <rcUpdatePhyMode-0x6c>) */ /* literal @0x2C: trc_ctl */
  a9 = 0x505; /* 00d7: movi a9, 0x505 */
  MEM16(a5 + 24) = a9; /* 00da: s16i a9, a5, 24 */
  MEMW(); /* 00dd: memw  */
  a9 = (uint32_t)&rcP2P11NSchedTbl; /* 00e0: l32r a9, 0 <rcUpdatePhyMode-0x6c> (0 <rcUpdatePhyMode-0x6c>) */ /* literal @0x0: rcP2P11NSchedTbl */
  if (a4 != 0) goto L_e8; /* 00e3: bnez.n a4, e8 <rcUpdatePhyMode+0x7c> */
  a9 = (uint32_t)&rc11NSchedTbl; /* 00e5: l32r a9, 4 <rcUpdatePhyMode-0x68> (0 <rcUpdatePhyMode-0x6c>) */ /* literal @0x4: rc11NSchedTbl */
L_e8:;
  a5 = 0x9; /* 00e8: movi.n a5, 9 */
  MEM32(a2 + 112) = a9; /* 00ea: s32i a9, a2, 112 */
  if (a4 != 0) goto L_f8; /* 00ed: bnez a4, f8 <rcUpdatePhyMode+0x8c> */
  a5 = 0xD; /* 00f0: movi.n a5, 13 */
  a11 = 0xB; /* 00f2: movi a11, 11 */
  if (a7 == 0) a5 = a11; /* 00f5: moveqz a5, a11, a7 */
L_f8:;
  MEM8(a2 + 5) = a5; /* 00f8: s8i a5, a2, 5 */
  MEMW(); /* 00fb: memw  */
  a11 = 0xE; /* 00fe: movi.n a11, 14 */
  a3 = ((int32_t)(a3 << (32 - (7 & 31)))) >> (32 - (7 & 31)); /* 0100: sext a3, a3, 7 */
  a5 = (uint32_t)&rc11NRate2SchedIdx; /* 0103: l32r a5, 30 <rcUpdatePhyMode-0x3c> (4 <rcUpdatePhyMode-0x68>) */ /* literal @0x30: .text.rc11NRate2SchedIdx */
  MEM32(a2 + 116) = a5; /* 0106: s32i a5, a2, 116 */
  a5 = 0xA; /* 0109: movi.n a5, 10 */
  if (a4 == 0) a5 = a11; /* 010b: moveqz a5, a11, a4 */
  MEM8(a2 + 6) = a5; /* 010e: s8i a5, a2, 6 */
  a5 = 0xB; /* 0111: movi.n a5, 11 */
  MEM8(a2 + 4) = a10; /* 0113: s8i a10, a2, 4 */
  MEMW(); /* 0116: memw  */
  if (a5 >= a3) goto L_141; /* 0119: bge a5, a3, 141 <rcUpdatePhyMode+0xd5> */
  a11 = 0x10; /* 011c: movi.n a11, 16 */
  a5 = 0x7; /* 011e: movi.n a5, 7 */
  if (a11 >= a3) goto L_141; /* 0120: bge a11, a3, 141 <rcUpdatePhyMode+0xd5> */
  a11 = 0x15; /* 0123: movi.n a11, 21 */
  a5 = 0x5; /* 0125: movi.n a5, 5 */
  if (a11 >= a3) goto L_141; /* 0127: bge a11, a3, 141 <rcUpdatePhyMode+0xd5> */
  a11 = 0x1A; /* 012a: movi.n a11, 26 */
  a5 = 0x4; /* 012c: movi.n a5, 4 */
  if (a11 >= a3) goto L_141; /* 012e: bge a11, a3, 141 <rcUpdatePhyMode+0xd5> */
  a11 = 0x1D; /* 0131: movi.n a11, 29 */
  a5 = 0x3; /* 0133: movi.n a5, 3 */
  if (a11 >= a3) goto L_141; /* 0135: bge a11, a3, 141 <rcUpdatePhyMode+0xd5> */
  a11 = 0x21; /* 0138: movi.n a11, 33 */
  a5 = a10; /* 013a: mov.n a5, a10 */
  if (a11 < a3) goto L_141; /* 013c: blt a11, a3, 141 <rcUpdatePhyMode+0xd5> */
  a5 = 0x2; /* 013f: movi.n a5, 2 */
L_141:;
  /* 0141: maxu a5, a5, a10 */ /* UNMODELED: a5 clobbered */
  a5 = (a5 >> 0) & 0xFF; /* 0144: extui a5, a5, 0, 8 */
  if (a5 < 8) goto L_150; /* 0147: bltui a5, 8, 150 <rcUpdatePhyMode+0xe4> */
  a3 = 0x7; /* 014a: movi a3, 7 */
  if (a4 != 0) a5 = a3; /* 014d: movnez a5, a3, a4 */
L_150:;
  if (a6 != 0) a5 = a10; /* 0150: movnez a5, a10, a6 */
  a3 = (a5 >> 0) & 0xFFFF; /* 0153: extui a3, a5, 0, 16 */
  a3 = (a3 << 2) + a3; /* 0156: addx2 a3, a3, a3 */
  a3 = (a3 << 4) + a9; /* 0159: addx4 a3, a3, a9 */
  MEM32(a2 + 96) = a3; /* 015c: s32i a3, a2, 96 */
  a3 = 0x5; /* 015f: movi.n a3, 5 */
  /* 0161: minu a3, a5, a3 */ /* UNMODELED: a3 clobbered */
  a3 = (a3 >> 0) & 0xFF; /* 0164: extui a3, a3, 0, 8 */
  a3 = (a3 << 2) + a3; /* 0167: addx2 a3, a3, a3 */
  a3 = (a3 << 4) + a9; /* 016a: addx4 a3, a3, a9 */
  a10 = MEM8(a3 + 0); /* 016d: l8ui a10, a3, 0 */
  a3 = 0x4; /* 0170: movi a3, 4 */
  MEM8(a2 + 13) = a10; /* 0173: s8i a10, a2, 13 */
  MEMW(); /* 0176: memw  */
  MEMW(); /* 0179: memw  */
  a8 = (uint32_t)&rx11NRate2AMPDULimit; /* 017c: l32r a8, 54 <rcUpdatePhyMode-0x18> (0 <rcUpdatePhyMode-0x6c>) */ /* literal: GOT slot for rx11NRate2AMPDULimit */
  rx11NRate2AMPDULimit(a2, a3, a4, a5); /* call via literal slot */ /* 017f: callx8 a8 */
  a11 = a10 | a10; /* 0182: or a11, a10, a10 */
  a10 = a2 | a2; /* 0185: or a10, a2, a2 */
  a8 = (uint32_t)&rcSetTxAmpduLimit; /* 0188: l32r a8, 58 <rcUpdatePhyMode-0x14> (0 <rcUpdatePhyMode-0x6c>) */ /* literal: GOT slot for rcSetTxAmpduLimit */
  rcSetTxAmpduLimit(a2, a3, a4, a5); /* call via literal slot */ /* 018b: callx8 a8 */
  a10 = a2; /* 018e: mov.n a10, a2 */
  a11 = 0x4; /* 0190: movi.n a11, 4 */
  a8 = (uint32_t)&trcAmpduSetState; /* 0192: l32r a8, 5c <rcUpdatePhyMode-0x10> (0 <rcUpdatePhyMode-0x6c>) */ /* literal: GOT slot for trcAmpduSetState */
  trcAmpduSetState(a2, a3, a4, a5); /* call via literal slot */ /* 0195: callx8 a8 */
  a10 = a2; /* 0198: mov.n a10, a2 */
  MEM8(a2 + 14) = a3; /* 019a: s8i a3, a2, 14 */
  MEMW(); /* 019d: memw  */
  MEMW(); /* 01a0: memw  */
  a8 = (uint32_t)&rcClearCurAMPDUSched; /* 01a3: l32r a8, 60 <rcUpdatePhyMode-0xc> (0 <rcUpdatePhyMode-0x6c>) */ /* literal: GOT slot for rcClearCurAMPDUSched */
  rcClearCurAMPDUSched(a2, a3, a4, a5); /* call via literal slot */ /* 01a6: callx8 a8 */
  goto L_221; /* 01a9: j 221 <rcUpdatePhyMode+0x1b5> */
L_1ac:;
  a9 = (uint32_t)&rcP2P11GSchedTbl; /* 01ac: l32r a9, 10 <rcUpdatePhyMode-0x5c> (0 <rcUpdatePhyMode-0x6c>) */ /* literal @0x10: rcP2P11GSchedTbl */
  if (a4 != 0) goto L_1b4; /* 01af: bnez.n a4, 1b4 <rcUpdatePhyMode+0x148> */
  a9 = (uint32_t)&rc11GSchedTbl; /* 01b1: l32r a9, 14 <rcUpdatePhyMode-0x58> (0 <rcUpdatePhyMode-0x6c>) */ /* literal @0x14: rc11GSchedTbl */
L_1b4:;
  a5 = 0x7; /* 01b4: movi.n a5, 7 */
  MEM32(a2 + 112) = a9; /* 01b6: s32i a9, a2, 112 */
  MEM8(a2 + 4) = a10; /* 01b9: s8i a10, a2, 4 */
  MEMW(); /* 01bc: memw  */
  if (a4 != 0) goto L_1c8; /* 01bf: bnez.n a4, 1c8 <rcUpdatePhyMode+0x15c> */
  a5 = 0xC; /* 01c1: movi.n a5, 12 */
  a11 = 0xA; /* 01c3: movi.n a11, 10 */
  if (a7 == 0) a5 = a11; /* 01c5: moveqz a5, a11, a7 */
L_1c8:;
  MEM8(a2 + 5) = a5; /* 01c8: s8i a5, a2, 5 */
  MEMW(); /* 01cb: memw  */
  a11 = 0xD; /* 01ce: movi.n a11, 13 */
  a3 = ((int32_t)(a3 << (32 - (7 & 31)))) >> (32 - (7 & 31)); /* 01d0: sext a3, a3, 7 */
  a5 = (uint32_t)&rc11GRate2SchedIdx; /* 01d3: l32r a5, 34 <rcUpdatePhyMode-0x38> (4 <rcUpdatePhyMode-0x68>) */ /* literal @0x34: .text.rc11GRate2SchedIdx */
  MEM32(a2 + 116) = a5; /* 01d6: s32i a5, a2, 116 */
  a5 = 0x8; /* 01d9: movi.n a5, 8 */
  if (a4 == 0) a5 = a11; /* 01db: moveqz a5, a11, a4 */
  MEM8(a2 + 6) = a5; /* 01de: s8i a5, a2, 6 */
  MEMW(); /* 01e1: memw  */
  a5 = 0xB; /* 01e4: movi.n a5, 11 */
  if (a5 < a3) goto L_1f6; /* 01e6: blt a5, a3, 1f6 <rcUpdatePhyMode+0x18a> */
  a5 = 0x7; /* 01e9: movi.n a5, 7 */
  a3 = 0xA; /* 01eb: movi.n a3, 10 */
  if (a4 == 0) a5 = a3; /* 01ed: moveqz a5, a3, a4 */
  MEMW(); /* 01f0: memw  */
  goto L_212; /* 01f3: j 212 <rcUpdatePhyMode+0x1a6> */
L_1f6:;
  a11 = 0x10; /* 01f6: movi.n a11, 16 */
  a5 = 0x5; /* 01f8: movi.n a5, 5 */
  if (a11 >= a3) goto L_212; /* 01fa: bge a11, a3, 212 <rcUpdatePhyMode+0x1a6> */
  a11 = 0x15; /* 01fd: movi.n a11, 21 */
  a5 = 0x3; /* 01ff: movi.n a5, 3 */
  if (a11 >= a3) goto L_212; /* 0201: bge a11, a3, 212 <rcUpdatePhyMode+0x1a6> */
  a11 = 0x1D; /* 0204: movi.n a11, 29 */
  a5 = 0x1; /* 0206: movi.n a5, 1 */
  if (a11 >= a3) goto L_20d; /* 0208: bge a11, a3, 20d <rcUpdatePhyMode+0x1a1> */
  a5 = 0x0; /* 020b: movi.n a5, 0 */
L_20d:;
  a5 = 0x0; /* 020d: add.n a5, a5, a5 */
  a5 = 0x0; /* 020f: extui a5, a5, 0, 8 */
L_212:;
  if (a6 != 0) a5 = a10; /* 0212: movnez a5, a10, a6 */
  a3 = (a5 >> 0) & 0xFFFF; /* 0215: extui a3, a5, 0, 16 */
  a3 = (a3 << 2) + a3; /* 0218: addx2 a3, a3, a3 */
  a3 = (a3 << 4) + a9; /* 021b: addx4 a3, a3, a9 */
  MEM32(a2 + 96) = a3; /* 021e: s32i a3, a2, 96 */
L_221:;
  a3 = (uint32_t)&rcP2P11GSchedTbl; /* 0221: l32r a3, 8 <rcUpdatePhyMode-0x64> (0 <rcUpdatePhyMode-0x6c>) */ /* literal @0x8: rcP2P11GSchedTbl */
  if (a4 != 0) goto L_2c0; /* 0224: bnez a4, 2c0 <rcUpdatePhyMode+0x254> */
  a3 = (uint32_t)&BasicOFDMSched; /* 0227: l32r a3, c <rcUpdatePhyMode-0x60> (0 <rcUpdatePhyMode-0x6c>) */ /* literal @0xC: BasicOFDMSched */
  MEMW(); /* 022a: memw  */
  goto L_2c0; /* 022d: j 2c0 <rcUpdatePhyMode+0x254> */
L_230:;
  a11 = (uint32_t)&rc11BSchedTbl; /* 0230: l32r a11, 38 <rcUpdatePhyMode-0x34> (0 <rcUpdatePhyMode-0x6c>) */ /* literal @0x38: rc11BSchedTbl */
  a3 = (uint32_t)&rc11BSchedTbl; /* 0233: l32r a3, 18 <rcUpdatePhyMode-0x54> (0 <rcUpdatePhyMode-0x6c>) */ /* literal @0x18: rc11BSchedTbl */
  a9 = a3 | a3; /* 0236: or a9, a3, a3 */
  MEM32(a2 + 112) = a11; /* 0239: s32i a11, a2, 112 */
  if (a6 == 0) goto L_248; /* 023c: beqz a6, 248 <rcUpdatePhyMode+0x1dc> */
  a9 = (a10 >> 0) & 0xFFFF; /* 023f: extui a9, a10, 0, 16 */
  a9 = (a9 << 2) + a9; /* 0242: addx2 a9, a9, a9 */
  a9 = (a9 << 4) + a11; /* 0245: addx4 a9, a9, a11 */
L_248:;
  MEM32(a2 + 96) = a9; /* 0248: s32i a9, a2, 96 */
  a8 = 0x5; /* 024b: movi.n a8, 5 */
  a9 = 0x3; /* 024d: movi.n a9, 3 */
  if (a7 == 0) a8 = a9; /* 024f: moveqz a8, a9, a7 */
  MEM8(a2 + 5) = a8; /* 0252: s8i a8, a2, 5 */
  MEMW(); /* 0255: memw  */
  a8 = (uint32_t)&rc11BRate2SchedIdx; /* 0258: l32r a8, 3c <rcUpdatePhyMode-0x30> (4 <rcUpdatePhyMode-0x68>) */ /* literal @0x3C: .text.rc11BRate2SchedIdx */
  MEM32(a2 + 116) = a8; /* 025b: s32i a8, a2, 116 */
  a8 = 0x6; /* 025e: movi.n a8, 6 */
  MEM8(a2 + 4) = a10; /* 0260: s8i a10, a2, 4 */
  MEM8(a2 + 6) = a8; /* 0263: s8i a8, a2, 6 */
  MEMW(); /* 0266: memw  */
  MEMW(); /* 0269: memw  */
  goto L_2c0; /* 026c: j 2c0 <rcUpdatePhyMode+0x254> */
  /* 026f: .byte 00 */
L_270:;
  a5 = (uint32_t)&rcLoRaRate2SchedIdx; /* 0270: l32r a5, 40 <rcUpdatePhyMode-0x2c> (0 <rcUpdatePhyMode-0x6c>) */ /* literal @0x40: rcLoRaRate2SchedIdx */
  a3 = (uint32_t)&rcLoRaSchedTbl; /* 0273: l32r a3, 1c <rcUpdatePhyMode-0x50> (0 <rcUpdatePhyMode-0x6c>) */ /* literal @0x1C: rcLoRaSchedTbl */
  MEM32(a2 + 116) = a5; /* 0276: s32i a5, a2, 116 */
  a5 = 0x100; /* 0279: movi a5, 0x100 */
  MEM16(a2 + 4) = a5; /* 027c: s16i a5, a2, 4 */
  MEMW(); /* 027f: memw  */
  a5 = 0x2; /* 0282: movi.n a5, 2 */
  MEM32(a2 + 112) = a3; /* 0284: s32i a3, a2, 112 */
  MEM32(a2 + 96) = a3; /* 0287: s32i a3, a2, 96 */
  MEMW(); /* 028a: memw  */
  goto L_2b7; /* 028d: j 2b7 <rcUpdatePhyMode+0x24b> */
L_290:;
  a5 = 0x0; /* 0290: movi.n a5, 0 */
  a3 = (uint32_t)&rc11BSchedTbl; /* 0292: l32r a3, 38 <rcUpdatePhyMode-0x34> (0 <rcUpdatePhyMode-0x6c>) */ /* literal @0x38: rc11BSchedTbl */
  a8 = 0x3; /* 0295: movi.n a8, 3 */
  MEM8(a2 + 4) = a5; /* 0297: s8i a5, a2, 4 */
  a5 = 0x5; /* 029a: movi a5, 5 */
  if (a7 == 0) a5 = a8; /* 029d: moveqz a5, a8, a7 */
  MEM32(a2 + 112) = a3; /* 02a0: s32i a3, a2, 112 */
  MEM8(a2 + 5) = a5; /* 02a3: s8i a5, a2, 5 */
  MEMW(); /* 02a6: memw  */
  a3 = (uint32_t)&rc11BSchedTbl; /* 02a9: l32r a3, 18 <rcUpdatePhyMode-0x54> (0 <rcUpdatePhyMode-0x6c>) */ /* literal @0x18: rc11BSchedTbl */
  a5 = (uint32_t)&rc11BRate2SchedIdx; /* 02ac: l32r a5, 3c <rcUpdatePhyMode-0x30> (4 <rcUpdatePhyMode-0x68>) */ /* literal @0x3C: .text.rc11BRate2SchedIdx */
  MEM32(a2 + 96) = a3; /* 02af: s32i a3, a2, 96 */
  MEM32(a2 + 116) = a5; /* 02b2: s32i a5, a2, 116 */
  a5 = 0x6; /* 02b5: movi.n a5, 6 */
L_2b7:;
  MEM8(a2 + 6) = a5; /* 02b7: s8i a5, a2, 6 */
  MEMW(); /* 02ba: memw  */
  a5 = 0x0; /* 02bd: movi a5, 0 */
L_2c0:;
  a6 = (uint32_t)&g_mesh_is_started; /* 02c0: l32r a6, 24 <rcUpdatePhyMode-0x48> (0 <rcUpdatePhyMode-0x6c>) */ /* literal @0x24: g_mesh_is_started */
  MEM32(a2 + 100) = a3; /* 02c3: s32i a3, a2, 100 */
  a3 = MEM8(a6 + 0); /* 02c6: l8ui a3, a6, 0 */
  if (a3 == 0) goto L_2e5; /* 02c9: beqz.n a3, 2e5 <rcUpdatePhyMode+0x279> */
  if (a4 == 0) goto L_2e5; /* 02cb: beqz.n a4, 2e5 <rcUpdatePhyMode+0x279> */
  a15 = 0x0; /* 02cd: mov.n a15, a5 */
  a14 = MEM8(a2 + 5); /* 02cf: l8ui a14, a2, 5 */
  a12 = 0x2; /* 02d2: movi.n a12, 2 */
  a11 = 0x200; /* 02d4: movi a11, 0x200 */
  a10 = 0x6; /* 02d7: movi.n a10, 6 */
  a13 = (uint32_t)&lit_rodata_wlog_warning_6; /* 02d9: l32r a13, 44 <rcUpdatePhyMode-0x28> (0 <rcUpdatePhyMode-0x6c>) */ /* literal @0x44: .rodata_wlog_warning.6 */
  MEMW(); /* 02dc: memw  */
  a8 = (uint32_t)&wifi_log; /* 02df: l32r a8, 64 <rcUpdatePhyMode-0x8> (0 <rcUpdatePhyMode-0x6c>) */ /* literal: GOT slot for wifi_log */
  wifi_log(a2, a3, a4, a5); /* call via literal slot */ /* 02e2: callx8 a8 */
L_2e5:;
  a10 = a2; /* 02e5: mov.n a10, a2 */
  a8 = (uint32_t)&rcClearCurSched; /* 02e7: l32r a8, 68 <rcUpdatePhyMode-0x4> (0 <rcUpdatePhyMode-0x6c>) */ /* literal: GOT slot for rcClearCurSched */
  rcClearCurSched(a2, a3, a4, a5); /* call via literal slot */ /* 02ea: callx8 a8 */
  a3 = 0x7F7F7F7F; /* 02ed: l32r a3, 48 <rcUpdatePhyMode-0x24> (7f7f7f7f <rcUpdatePhyMode+0x7f7f7f13>) */ @0x48
  MEM32(a2 + 0) = a3; /* 02f0: s32i a3, a2, 0 */
  a3 = (uint32_t)&rcLoRaSchedTbl; /* 02f3: l32r a3, 20 <rcUpdatePhyMode-0x4c> (0 <rcUpdatePhyMode-0x6c>) */ /* literal @0x20: rcLoRaSchedTbl */
  if (a7 != 0) goto L_2fc; /* 02f6: bnez a7, 2fc <rcUpdatePhyMode+0x290> */
  a3 = MEM32(a2 + 100); /* 02f9: l32i a3, a2, 100 */
L_2fc:;
  MEM32(a2 + 104) = a3; /* 02fc: s32i a3, a2, 104 */
  MEMW(); /* 02ff: memw  */
  return (int32_t)a2; /* 0302: retw.n  */
}

/* rcLowerSched @ trc.o 0000001c size 122B bind GLOBAL
 * Calls: rcClearCurSched | Data refs: g_mesh_init_ps_type, g_mesh_is_root, g_mesh_is_started, g_osi_funcs_p, g_wifi_mac_time_delta, rcClearCurSched
 *   MMIO: 0x3FF73C00
 *   funcdb v3: 1 call(s), 6 ref(s); disasm: 1 call(s), 6 data ref(s)
 * Fidelity: medium - 47 instr, 6 branches, calls resolved */
int32_t rcLowerSched(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.rcLowerSched; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_1c:;
  /* 001c: entry a1, 32 */
  a10 = a2 | a2; /* 001f: or a10, a2, a2 */
  a8 = (uint32_t)&rcClearCurSched; /* 0022: l32r a8, 18 <rcLowerSched-0x4> (0 <rcLowerSched-0x1c>) */ /* literal: GOT slot for rcClearCurSched */
  rcClearCurSched(a2, a3, a4, a5); /* call via literal slot */ /* 0025: callx8 a8 */
  a10 = MEM32(a2 + 96); /* 0028: l32i a10, a2, 96 */
  a3 = (a3 >> 0) & 0xFF; /* 002b: extui a3, a3, 0, 8 */
  a9 = MEM8(a10 + 10); /* 002e: l8ui a9, a10, 10 */
  a9 = a9 + a3; /* 0031: add.n a9, a9, a3 */
  a8 = MEM8(a2 + 5); /* 0033: l8ui a8, a2, 5 */
  if (a8 < a9) goto L_45; /* 0036: blt a8, a9, 45 <rcLowerSched+0x29> */
  a3 = (a3 << 2) + a3; /* 0039: addx2 a3, a3, a3 */
  a8 = (a3 << 4) + a10; /* 003c: addx4 a8, a3, a10 */
  goto L_4e; /* 003f: j 4e <rcLowerSched+0x32> */
  /* 0042: .byte 00 */
  /* 0043: .byte 00 */
  /* 0044: .byte 00 */
L_45:;
  a3 = MEM32(a2 + 112); /* 0045: l32i a3, a2, 112 */
  a8 = (a8 << 2) + a8; /* 0048: addx2 a8, a8, a8 */
  a8 = (a8 << 4) + a3; /* 004b: addx4 a8, a8, a3 */
L_4e:;
  a3 = (uint32_t)&g_mesh_is_started; /* 004e: l32r a3, 0 <rcLowerSched-0x1c> (0 <rcLowerSched-0x1c>) */ /* literal @0x0: g_mesh_is_started */
  a3 = MEM8(a3 + 0); /* 0051: l8ui a3, a3, 0 */
  MEM32(a2 + 96) = a8; /* 0054: s32i a8, a2, 96 */
  if (a3 == 0) goto L_80; /* 0057: beqz.n a3, 80 <rcLowerSched+0x64> */
  a3 = (uint32_t)&g_mesh_is_root; /* 0059: l32r a3, 4 <rcLowerSched-0x18> (0 <rcLowerSched-0x1c>) */ /* literal @0x4: g_mesh_is_root */
  MEMW(); /* 005c: memw  */
  a3 = MEM8(a3 + 0); /* 005f: l8ui a3, a3, 0 */
  a3 = (a3 >> 0) & 0xFF; /* 0062: extui a3, a3, 0, 8 */
  if (a3 != 0) goto L_80; /* 0065: bnez.n a3, 80 <rcLowerSched+0x64> */
  a3 = (uint32_t)&g_mesh_init_ps_type; /* 0067: l32r a3, 8 <rcLowerSched-0x14> (0 <rcLowerSched-0x1c>) */ /* literal @0x8: g_mesh_init_ps_type */
  a3 = MEM32(a3 + 0); /* 006a: l32i.n a3, a3, 0 */
  if (a3 == 0) goto L_80; /* 006c: beqz.n a3, 80 <rcLowerSched+0x64> */
  a3 = (uint32_t)&g_osi_funcs_p; /* 006e: l32r a3, c <rcLowerSched-0x10> (0 <rcLowerSched-0x1c>) */ /* literal @0xC: g_osi_funcs_p */
  a3 = MEM32(a3 + 0); /* 0071: l32i.n a3, a3, 0 */
  a10 = MEM32(a3 + 272); /* 0073: l32i a10, a3, 0x110 */
  MEMW(); /* 0076: memw  */
  ((int32_t(*)())a10)(a2, a3, a4, a5); /* 0079: callx8 a10 */ /* indirect */
  goto L_8f; /* 007c: j 8f <rcLowerSched+0x73> */
  /* 007f: .byte 00 */
L_80:;
  a3 = 0x3FF73C00; /* 0080: l32r a3, 10 <rcLowerSched-0xc> (3ff73c00 <rcUpdatePhyMode+0x3ff73b94>) */ /* MMIO base */ @0x10
  MEMW(); /* 0083: memw  */
  a10 = REG32(0x3FF73C00); /* 0086: l32i.n a10, a3, 0 */ /* MMIO read: base 0x3FF73C00+0 */
  a3 = (uint32_t)&g_wifi_mac_time_delta; /* 0088: l32r a3, 14 <rcLowerSched-0x8> (0 <rcLowerSched-0x1c>) */ /* literal @0x14: g_wifi_mac_time_delta */
  a3 = MEM32(a3 + 0); /* 008b: l32i.n a3, a3, 0 */
  a10 = a10 + a3; /* 008d: add.n a10, a10, a3 */
L_8f:;
  MEM32(a2 + 48) = a10; /* 008f: s32i.n a10, a2, 48 */
  MEMW(); /* 0091: memw  */
  return (int32_t)a2; /* 0094: retw.n  */
}

/* rcUpSched @ trc.o 0000001c size 114B bind GLOBAL
 * Calls: rcClearCurSched | Data refs: g_mesh_init_ps_type, g_mesh_is_root, g_mesh_is_started, g_osi_funcs_p, g_wifi_mac_time_delta, rcClearCurSched
 *   MMIO: 0x3FF73C00
 *   funcdb v3: 1 call(s), 6 ref(s); disasm: 1 call(s), 6 data ref(s)
 * Fidelity: medium - 42 instr, 5 branches, calls resolved */
int32_t rcUpSched(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.rcUpSched; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_1c:;
  /* 001c: entry a1, 32 */
  a10 = a2 | a2; /* 001f: or a10, a2, a2 */
  a8 = (uint32_t)&rcClearCurSched; /* 0022: l32r a8, 18 <rcUpSched-0x4> (0 <rcUpSched-0x1c>) */ /* literal: GOT slot for rcClearCurSched */
  rcClearCurSched(a2, a3, a4, a5); /* call via literal slot */ /* 0025: callx8 a8 */
  a8 = MEM32(a2 + 96); /* 0028: l32i a8, a2, 96 */
  a10 = MEM8(a2 + 4); /* 002b: l8ui a10, a2, 4 */
  a9 = MEM8(a8 + 10); /* 002e: l8ui a9, a8, 10 */
  if (a10 >= a9) goto L_89; /* 0031: bgeu a10, a9, 89 <rcUpSched+0x6d> */
  a8 = a8 + (-12); /* 0034: addi a8, a8, -12 */
  a10 = 0x1; /* 0037: movi.n a10, 1 */
  MEM32(a2 + 96) = a8; /* 0039: s32i a8, a2, 96 */
  a9 = MEM8(a8 + 11); /* 003c: l8ui a9, a8, 11 */
  a9 = a9 | a10; /* 003f: or a9, a9, a10 */
  MEM8(a8 + 11) = a9; /* 0042: s8i a9, a8, 11 */
  MEMW(); /* 0045: memw  */
  a8 = (uint32_t)&g_mesh_is_started; /* 0048: l32r a8, 0 <rcUpSched-0x1c> (0 <rcUpSched-0x1c>) */ /* literal @0x0: g_mesh_is_started */
  a8 = MEM8(a8 + 0); /* 004b: l8ui a8, a8, 0 */
  if (a8 == 0) goto L_78; /* 004e: beqz.n a8, 78 <rcUpSched+0x5c> */
  a8 = (uint32_t)&g_mesh_is_root; /* 0050: l32r a8, 4 <rcUpSched-0x18> (0 <rcUpSched-0x1c>) */ /* literal @0x4: g_mesh_is_root */
  MEMW(); /* 0053: memw  */
  a8 = MEM8(a8 + 0); /* 0056: l8ui a8, a8, 0 */
  a8 = (a8 >> 0) & 0xFF; /* 0059: extui a8, a8, 0, 8 */
  if (a8 != 0) goto L_78; /* 005c: bnez.n a8, 78 <rcUpSched+0x5c> */
  a8 = (uint32_t)&g_mesh_init_ps_type; /* 005e: l32r a8, 8 <rcUpSched-0x14> (0 <rcUpSched-0x1c>) */ /* literal @0x8: g_mesh_init_ps_type */
  a8 = MEM32(a8 + 0); /* 0061: l32i.n a8, a8, 0 */
  if (a8 == 0) goto L_78; /* 0063: beqz.n a8, 78 <rcUpSched+0x5c> */
  a8 = (uint32_t)&g_osi_funcs_p; /* 0065: l32r a8, c <rcUpSched-0x10> (0 <rcUpSched-0x1c>) */ /* literal @0xC: g_osi_funcs_p */
  a8 = MEM32(a8 + 0); /* 0068: l32i a8, a8, 0 */
  a10 = MEM32(a8 + 272); /* 006b: l32i a10, a8, 0x110 */
  MEMW(); /* 006e: memw  */
  ((int32_t(*)())a10)(a2, a3, a4, a5); /* 0071: callx8 a10 */ /* indirect */
  goto L_87; /* 0074: j 87 <rcUpSched+0x6b> */
  /* 0077: .byte 00 */
L_78:;
  a8 = 0x3FF73C00; /* 0078: l32r a8, 10 <rcUpSched-0xc> (3ff73c00 <rcUpdatePhyMode+0x3ff73b94>) */ /* MMIO base */ @0x10
  MEMW(); /* 007b: memw  */
  a10 = REG32(0x3FF73C00); /* 007e: l32i.n a10, a8, 0 */ /* MMIO read: base 0x3FF73C00+0 */
  a8 = (uint32_t)&g_wifi_mac_time_delta; /* 0080: l32r a8, 14 <rcUpSched-0x8> (0 <rcUpSched-0x1c>) */ /* literal @0x14: g_wifi_mac_time_delta */
  a8 = MEM32(a8 + 0); /* 0083: l32i.n a8, a8, 0 */
  a10 = a10 + a8; /* 0085: add.n a10, a10, a8 */
L_87:;
  MEM32(a2 + 52) = a10; /* 0087: s32i.n a10, a2, 52 */
L_89:;
  MEMW(); /* 0089: memw  */
  return (int32_t)a2; /* 008c: retw.n  */
}

/* rcUpdateAckSnr @ trc.o 00000000 size 91B bind GLOBAL
 * Calls: none | Data refs: none
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t rcUpdateAckSnr(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.rcUpdateAckSnr; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_0:;
  /* 0000: entry a1, 32 */
  a11 = (a3 >> 0) & 0xFF; /* 0003: extui a11, a3, 0, 8 */
  a10 = 0x7F; /* 0006: movi a10, 127 */
  a3 = ((int32_t)(a3 << (32 - (7 & 31)))) >> (32 - (7 & 31)); /* 0009: sext a3, a3, 7 */
  if (a3 == a10) goto L_56; /* 000c: beq a3, a10, 56 <rcUpdateAckSnr+0x56> */
  a8 = MEM8(a2 + 0); /* 000f: l8ui a8, a2, 0 */
  a9 = 0x0; /* 0012: movi.n a9, 0 */
  a8 = ((int32_t)(a8 << (32 - (7 & 31)))) >> (32 - (7 & 31)); /* 0014: sext a8, a8, 7 */
  if (a8 == a10) goto L_20; /* 0017: beq a8, a10, 20 <rcUpdateAckSnr+0x20> */
  a8 = a8 + a3; /* 001a: add a8, a8, a3 */
  a9 = (a8 >> 1) & 0xFF; /* 001d: extui a9, a8, 1, 8 */
L_20:;
  a8 = MEM8(a2 + 1); /* 0020: l8ui a8, a2, 1 */
  a3 = 0x7F; /* 0023: movi a3, 127 */
  a8 = ((int32_t)(a8 << (32 - (7 & 31)))) >> (32 - (7 & 31)); /* 0026: sext a8, a8, 7 */
  MEM8(a2 + 0) = a11; /* 0029: s8i a11, a2, 0 */
  MEMW(); /* 002c: memw  */
  if (a8 == a3) goto L_50; /* 002f: beq a8, a3, 50 <rcUpdateAckSnr+0x50> */
  a9 = ((int32_t)(a9 << (32 - (7 & 31)))) >> (32 - (7 & 31)); /* 0032: sext a9, a9, 7 */
  a8 = (a8 << 2) + a8; /* 0035: addx2 a8, a8, a8 */
  a8 = a8 + a9; /* 0038: add.n a8, a8, a9 */
  a9 = a8 + (3); /* 003a: addi.n a9, a8, 3 */
  if (a8 >= 0) a9 = a8; /* 003c: movgez a9, a8, a8 */
  a8 = (int32_t)a9 >> (2 & 31); /* 003f: srai a8, a9, 2 */
  MEM8(a2 + 1) = a8; /* 0042: s8i a8, a2, 1 */
  MEMW(); /* 0045: memw  */
  MEMW(); /* 0048: memw  */
  goto L_56; /* 004b: j 56 <rcUpdateAckSnr+0x56> */
  /* 004e: .byte 00 */
  /* 004f: .byte 00 */
L_50:;
  MEM8(a2 + 1) = a9; /* 0050: s8i a9, a2, 1 */
  MEMW(); /* 0053: memw  */
L_56:;
  MEMW(); /* 0056: memw  */
  return (int32_t)a2; /* 0059: retw.n  */
}

/* rcTxUpdatePer @ trc.o 00000008 size 130B bind GLOBAL
 * Calls: rcLowerSched | Data refs: rcLowerSched
 *   MMIO: none
 *   funcdb v3: 1 call(s), 1 ref(s); disasm: 1 call(s), 1 data ref(s)
 * Fidelity: medium - 49 instr, 9 branches, calls resolved */
int32_t rcTxUpdatePer(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.rcTxUpdatePer; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_8:;
  /* 0008: entry a1, 32 */
  a8 = MEM32(a2 + 96); /* 000b: l32i a8, a2, 96 */
  a3 = (a3 >> 0) & 0xFF; /* 000e: extui a3, a3, 0, 8 */
  a10 = a2; /* 0011: mov.n a10, a2 */
  a9 = MEM8(a8 + 1); /* 0013: l8ui a9, a8, 1 */
  a8 = a9 + (2); /* 0016: addi a8, a9, 2 */
  a8 = (a8 >> 0) & 0xFF; /* 0019: extui a8, a8, 0, 8 */
  if (a9 < a3) goto L_24; /* 001c: bltu a9, a3, 24 <rcTxUpdatePer+0x1c> */
  a8 = a3 + (1); /* 001f: addi.n a8, a3, 1 */
  a8 = (a8 >> 0) & 0xFF; /* 0021: extui a8, a8, 0, 8 */
L_24:;
  a9 = MEM32(a10 + 44); /* 0024: l32i.n a9, a10, 44 */
  a11 = a9 + (1); /* 0026: addi.n a11, a9, 1 */
  a12 = 0x1FFFFFF; /* 0028: l32r a12, 0 <rcTxUpdatePer-0x8> (1ffffff <rcUpdatePhyMode+0x1ffff93>) */ @0x0
  if (a12 >= a11) goto L_3a; /* 002b: bgeu a12, a11, 3a <rcTxUpdatePer+0x32> */
  a9 = a9 >> (1 & 31); /* 002e: srli a9, a9, 1 */
  a11 = MEM32(a10 + 40); /* 0031: l32i.n a11, a10, 40 */
  a11 = a11 >> (1 & 31); /* 0033: srli a11, a11, 1 */
  MEM32(a10 + 40) = a11; /* 0036: s32i.n a11, a10, 40 */
  MEM32(a10 + 44) = a9; /* 0038: s32i.n a9, a10, 44 */
L_3a:;
  a9 = MEM32(a10 + 44); /* 003a: l32i.n a9, a10, 44 */
  a9 = a9 + (1); /* 003c: addi.n a9, a9, 1 */
  MEM32(a10 + 44) = a9; /* 003e: s32i.n a9, a10, 44 */
  a9 = MEM32(a10 + 40); /* 0040: l32i.n a9, a10, 40 */
  a8 = a9 + a8; /* 0042: add.n a8, a9, a8 */
  MEM32(a10 + 40) = a8; /* 0044: s32i.n a8, a10, 40 */
  if (a3 < 8) goto L_54; /* 0046: bltui a3, 8, 54 <rcTxUpdatePer+0x4c> */
  a3 = MEM8(a10 + 7); /* 0049: l8ui a3, a10, 7 */
  a3 = a3 + (2); /* 004c: addi.n a3, a3, 2 */
  MEMW(); /* 004e: memw  */
  goto L_5c; /* 0051: j 5c <rcTxUpdatePer+0x54> */
L_54:;
  if (a3 < 5) goto L_68; /* 0054: bltui a3, 5, 68 <rcTxUpdatePer+0x60> */
  a3 = MEM8(a10 + 7); /* 0057: l8ui a3, a10, 7 */
  a3 = a3 + (1); /* 005a: addi.n a3, a3, 1 */
L_5c:;
  MEM8(a10 + 7) = a3; /* 005c: s8i a3, a10, 7 */
  MEMW(); /* 005f: memw  */
  MEMW(); /* 0062: memw  */
  goto L_79; /* 0065: j 79 <rcTxUpdatePer+0x71> */
L_68:;
  if (a3 >= 3) goto L_79; /* 0068: bgeui a3, 3, 79 <rcTxUpdatePer+0x71> */
  a3 = 0x0; /* 006b: movi.n a3, 0 */
  MEM8(a10 + 7) = a3; /* 006d: s8i a3, a10, 7 */
  MEMW(); /* 0070: memw  */
  MEMW(); /* 0073: memw  */
  goto L_88; /* 0076: j 88 <rcTxUpdatePer+0x80> */
L_79:;
  a3 = MEM8(a10 + 7); /* 0079: l8ui a3, a10, 7 */
  if (a3 < 7) goto L_88; /* 007c: bltui a3, 7, 88 <rcTxUpdatePer+0x80> */
  a11 = 0x1; /* 007f: movi a11, 1 */
  a8 = (uint32_t)&rcLowerSched; /* 0082: l32r a8, 4 <rcTxUpdatePer-0x4> (0 <rcTxUpdatePer-0x8>) */ /* literal: GOT slot for rcLowerSched */
  rcLowerSched(a2, a3, a4, a5); /* call via literal slot */ /* 0085: callx8 a8 */
L_88:;
  return (int32_t)a2; /* 0088: retw.n  */
}

/* rcUpdateTxDone @ trc.o 0000000c size 107B bind GLOBAL
 * Calls: rcUpdateAckSnr[got], rcTxUpdatePer[got] | Data refs: rcUpdateAckSnr, g_mesh_is_started, rcTxUpdatePer
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 2 call(s), 3 data ref(s)
 * Fidelity: medium - 40 instr, 9 branches, calls resolved */
int32_t rcUpdateTxDone(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .wifi0iram.7; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_c:;
  /* 000c: entry a1, 32 */
  if (a2 == 0) goto L_75; /* 000f: beqz a2, 75 <rcUpdateTxDone+0x69> */
  a8 = MEM8(a2 + 11); /* 0012: l8ui a8, a2, 11 */
  a9 = ((int32_t)(a8 << (32 - (7 & 31)))) >> (32 - (7 & 31)); /* 0015: sext a9, a8, 7 */
  /* 0018: bltz a9, 75 <rcUpdateTxDone+0x69> */ /* UNMODELED branch */
  a10 = MEM32(a2 + 96); /* 001b: l32i a10, a2, 96 */
  a9 = MEM32(a3 + 28); /* 001e: l32i.n a9, a3, 28 */
  if (a9 != a10) goto L_75; /* 0020: bne a9, a10, 75 <rcUpdateTxDone+0x69> */
  a10 = 0x4; /* 0023: movi.n a10, 4 */
  if ((a8 & a10) != 0) goto L_75; /* 0025: bany a8, a10, 75 <rcUpdateTxDone+0x69> */
  a8 = MEM32(a2 + 60); /* 0028: l32i.n a8, a2, 60 */
  a8 = a8 + (1); /* 002a: addi.n a8, a8, 1 */
  MEM32(a2 + 60) = a8; /* 002c: s32i.n a8, a2, 60 */
  a8 = MEM8(a3 + 19); /* 002e: l8ui a8, a3, 19 */
  if (a8 != 1) goto L_54; /* 0031: bnei a8, 1, 54 <rcUpdateTxDone+0x48> */
  a8 = MEM8(a2 + 25); /* 0034: l8ui a8, a2, 25 */
  if ((a8 & a10) != 0) goto L_4c; /* 0037: bany a8, a10, 4c <rcUpdateTxDone+0x40> */
  a10 = a2 | a2; /* 003a: or a10, a2, a2 */
  a11 = MEM8(a3 + 13); /* 003d: l8ui a11, a3, 13 */
  a11 = ((int32_t)(a11 << (32 - (7 & 31)))) >> (32 - (7 & 31)); /* 0040: sext a11, a11, 7 */
  MEMW(); /* 0043: memw  */
  a8 = (uint32_t)&rcUpdateAckSnr; /* 0046: l32r a8, 4 <rcUpdateTxDone-0x8> (0 <rcUpdateTxDone-0xc>) */ /* literal: GOT slot for rcUpdateAckSnr */
  rcUpdateAckSnr(a2, a3, a4, a5); /* call via literal slot */ /* 0049: callx8 a8 */
L_4c:;
  a11 = MEM8(a3 + 5); /* 004c: l8ui a11, a3, 5 */
  goto L_6d; /* 004f: j 6d <rcUpdateTxDone+0x61> */
  /* 0052: .byte 00 */
  /* 0053: .byte 00 */
L_54:;
  a8 = a8 + (-2); /* 0054: addi a8, a8, -2 */
  a8 = (a8 >> 0) & 0xFF; /* 0057: extui a8, a8, 0, 8 */
  if (a8 >= 2) goto L_75; /* 005a: bgeui a8, 2, 75 <rcUpdateTxDone+0x69> */
  a3 = (uint32_t)&g_mesh_is_started; /* 005d: l32r a3, 0 <rcUpdateTxDone-0xc> (0 <rcUpdateTxDone-0xc>) */ /* literal @0x0: g_mesh_is_started */
  a3 = MEM8(a3 + 0); /* 0060: l8ui a3, a3, 0 */
  a11 = MEM8(a9 + 8); /* 0063: l8ui a11, a9, 8 */
  if (a3 == 0) goto L_6d; /* 0066: beqz.n a3, 6d <rcUpdateTxDone+0x61> */
  a3 = 0xB; /* 0068: movi.n a3, 11 */
  /* 006a: minu a11, a11, a3 */ /* UNMODELED: a11 clobbered */
L_6d:;
  a10 = a2; /* 006d: mov.n a10, a2 */
  a8 = (uint32_t)&rcTxUpdatePer; /* 006f: l32r a8, 8 <rcUpdateTxDone-0x4> (0 <rcUpdateTxDone-0xc>) */ /* literal: GOT slot for rcTxUpdatePer */
  rcTxUpdatePer(a2, a3, a4, a5); /* call via literal slot */ /* 0072: callx8 a8 */
L_75:;
  return (int32_t)a2; /* 0075: retw.n  */
}

/* rcUpdateRxDone @ trc.o 00000004 size 115B bind GLOBAL
 * Calls: none | Data refs: wDevCtrl
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 1 data ref(s)
 * Fidelity: medium - 42 instr, 5 branches, calls resolved */
int32_t rcUpdateRxDone(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .wifirxiram.8; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a8 = MEM8(a2 + 11); /* 0007: l8ui a8, a2, 11 */
  if ((a8 >> 7) & 1) goto L_72; /* 000a: bbsi a8, 7, 72 <rcUpdateRxDone+0x6e> */
  a9 = MEM8(a2 + 25); /* 000d: l8ui a9, a2, 25 */
  a9 = (a9 >> 0) & 0x1; /* 0010: extui a9, a9, 0, 1 */
  if (a9 != 0) goto L_72; /* 0013: bnez a9, 72 <rcUpdateRxDone+0x6e> */
  a12 = 0x7F; /* 0016: movi a12, 127 */
  a10 = (uint32_t)&wDevCtrl; /* 0019: l32r a10, 0 <rcUpdateRxDone-0x4> (0 <rcUpdateRxDone-0x4>) */ /* literal @0x0: wDevCtrl */
  a8 = MEM8(a3 + 0); /* 001c: l8ui a8, a3, 0 */
  a10 = MEM8(a10 + 46); /* 001f: l8ui a10, a10, 46 */
  a8 = a8 + a10; /* 0022: add.n a8, a8, a10 */
  a8 = (a8 >> 0) & 0xFF; /* 0024: extui a8, a8, 0, 8 */
  a11 = a8; /* 0027: mov.n a11, a8 */
  a10 = MEM8(a2 + 2); /* 0029: l8ui a10, a2, 2 */
  a10 = ((int32_t)(a10 << (32 - (7 & 31)))) >> (32 - (7 & 31)); /* 002c: sext a10, a10, 7 */
  if (a10 == a12) goto L_3c; /* 002f: beq a10, a12, 3c <rcUpdateRxDone+0x38> */
  a9 = ((int32_t)(a8 << (32 - (7 & 31)))) >> (32 - (7 & 31)); /* 0032: sext a9, a8, 7 */
  a10 = a10 + a9; /* 0035: add.n a10, a10, a9 */
  a9 = (a10 >> 1) & 0xFF; /* 0037: extui a9, a10, 1, 8 */
  a11 = a9; /* 003a: mov.n a11, a9 */
L_3c:;
  MEM8(a2 + 2) = a8; /* 003c: s8i a8, a2, 2 */
  MEMW(); /* 003f: memw  */
  a10 = 0x7F; /* 0042: movi a10, 127 */
  a8 = MEM8(a2 + 3); /* 0045: l8ui a8, a2, 3 */
  a8 = ((int32_t)(a8 << (32 - (7 & 31)))) >> (32 - (7 & 31)); /* 0048: sext a8, a8, 7 */
  if (a8 == a10) goto L_6c; /* 004b: beq a8, a10, 6c <rcUpdateRxDone+0x68> */
  a9 = ((int32_t)(a9 << (32 - (7 & 31)))) >> (32 - (7 & 31)); /* 004e: sext a9, a9, 7 */
  a8 = (a8 << 2) + a8; /* 0051: addx2 a8, a8, a8 */
  a8 = a8 + a9; /* 0054: add.n a8, a8, a9 */
  a9 = a8 + (3); /* 0056: addi.n a9, a8, 3 */
  if (a8 >= 0) a9 = a8; /* 0058: movgez a9, a8, a8 */
  a8 = (int32_t)a9 >> (2 & 31); /* 005b: srai a8, a9, 2 */
  MEM8(a2 + 3) = a8; /* 005e: s8i a8, a2, 3 */
  MEMW(); /* 0061: memw  */
  MEMW(); /* 0064: memw  */
  goto L_72; /* 0067: j 72 <rcUpdateRxDone+0x6e> */
  /* 006a: .byte 00 */
  /* 006b: .byte 00 */
L_6c:;
  MEM8(a2 + 3) = a11; /* 006c: s8i a11, a2, 3 */
  MEMW(); /* 006f: memw  */
L_72:;
  MEMW(); /* 0072: memw  */
  return (int32_t)a2; /* 0075: retw.n  */
}

/* trc_onAmpduOp @ trc.o 00000004 size 230B bind GLOBAL
 * Calls: trcAmpduSetState | Data refs: trcAmpduSetState
 *   MMIO: none
 *   funcdb v3: 1 call(s), 1 ref(s); disasm: 1 call(s), 1 data ref(s)
 * Fidelity: medium - 81 instr, 12 branches, calls resolved */
int32_t trc_onAmpduOp(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.trc_onAmpduOp; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a8 = MEM8(a2 + 130); /* 0007: l8ui a8, a2, 130 */
  a4 = (a4 >> 0) & 0xFF; /* 000a: extui a4, a4, 0, 8 */
  if (a8 >= 2) goto L_13; /* 000d: bgeui a8, 2, 13 <trc_onAmpduOp+0xf> */
  goto L_e5; /* 0010: j e5 <trc_onAmpduOp+0xe1> */
L_13:;
  if (a3 == 2) goto L_19; /* 0013: beqi a3, 2, 19 <trc_onAmpduOp+0x15> */
  goto L_aa; /* 0016: j aa <trc_onAmpduOp+0xa6> */
L_19:;
  a9 = 0xFFFFFF80; /* 0019: movi a9, -128 */
  a8 = MEM8(a2 + 25); /* 001c: l8ui a8, a2, 25 */
  a10 = 0xFD; /* 001f: movi a10, 253 */
  a8 = a8 | a9; /* 0022: or a8, a8, a9 */
  MEM8(a2 + 25) = a8; /* 0025: s8i a8, a2, 25 */
  MEMW(); /* 0028: memw  */
  a8 = 0x1; /* 002b: movi a8, 1 */
  /* 002e: ssl a4 */ /* UNMODELED: a4 clobbered */
  /* 0031: sll a8, a8 */ /* UNMODELED: a8 clobbered */
  a9 = MEM8(a2 + 16); /* 0034: l8ui a9, a2, 16 */
  a9 = a8 | a9; /* 0037: or a9, a8, a9 */
  MEM8(a2 + 16) = a9; /* 003a: s8i a9, a2, 16 */
  MEMW(); /* 003d: memw  */
  a9 = MEM8(a2 + 14); /* 0040: l8ui a9, a2, 14 */
  a9 = a9 + (-2); /* 0043: addi a9, a9, -2 */
  if ((a9 & a10) != 0) goto L_60; /* 0046: bany a9, a10, 60 <trc_onAmpduOp+0x5c> */
  a9 = a2 + a4; /* 0049: add.n a9, a2, a4 */
  MEM8(a9 + 17) = a3; /* 004b: s8i a3, a9, 17 */
  MEMW(); /* 004e: memw  */
  a9 = MEM8(a2 + 38); /* 0051: l8ui a9, a2, 38 */
  a8 = a8 | a9; /* 0054: or a8, a8, a9 */
  MEM8(a2 + 38) = a8; /* 0057: s8i a8, a2, 38 */
  MEM8(a2 + 14) = a3; /* 005a: s8i a3, a2, 14 */
  MEMW(); /* 005d: memw  */
L_60:;
  a8 = 0x10; /* 0060: movi.n a8, 16 */
  a3 = MEM8(a2 + 26); /* 0062: l8ui a3, a2, 26 */
  if (a8 < a3) goto L_9c; /* 0065: bltu a8, a3, 9c <trc_onAmpduOp+0x98> */
  a8 = 0x6D; /* 0068: movi a8, 109 */
  a3 = MEM8(a2 + 1); /* 006b: l8ui a3, a2, 1 */
  a3 = a3 + (-17); /* 006e: addi a3, a3, -17 */
  a3 = (a3 >> 0) & 0xFF; /* 0071: extui a3, a3, 0, 8 */
  if (a8 >= a3) goto L_9c; /* 0074: bgeu a8, a3, 9c <trc_onAmpduOp+0x98> */
  a3 = 0x3; /* 0077: movi.n a3, 3 */
  a11 = 0x3; /* 0079: movi a11, 3 */
  a10 = a2 | a2; /* 007c: or a10, a2, a2 */
  MEMW(); /* 007f: memw  */
  a8 = (uint32_t)&trcAmpduSetState; /* 0082: l32r a8, 0 <trc_onAmpduOp-0x4> (0 <trc_onAmpduOp-0x4>) */ /* literal: GOT slot for trcAmpduSetState */
  trcAmpduSetState(a2, a3, a4, a5); /* call via literal slot */ /* 0085: callx8 a8 */
  MEM8(a2 + 14) = a3; /* 0088: s8i a3, a2, 14 */
  a3 = 0x21; /* 008b: movi.n a3, 33 */
  MEM8(a2 + 26) = a3; /* 008d: s8i a3, a2, 26 */
  MEMW(); /* 0090: memw  */
  a3 = 0x3; /* 0093: movi.n a3, 3 */
  MEMW(); /* 0095: memw  */
  goto L_aa; /* 0098: j aa <trc_onAmpduOp+0xa6> */
  /* 009b: .byte 00 */
L_9c:;
  a3 = 0x21; /* 009c: movi.n a3, 33 */
  MEM8(a2 + 26) = a3; /* 009e: s8i a3, a2, 26 */
  MEMW(); /* 00a1: memw  */
  MEMW(); /* 00a4: memw  */
  goto L_e5; /* 00a7: j e5 <trc_onAmpduOp+0xe1> */
L_aa:;
  a8 = 0xFFFFFFFD; /* 00aa: movi.n a8, -3 */
  a8 = 0x21; /* 00ac: and a8, a3, a8 */
  if (a8 != 1) goto L_e5; /* 00af: bnei a8, 1, e5 <trc_onAmpduOp+0xe1> */
  if (a3 != 1) goto L_c9; /* 00b2: bnei a3, 1, c9 <trc_onAmpduOp+0xc5> */
  a8 = 0xFFFFFFFF; /* 00b5: movi.n a8, -1 */
  /* 00b7: ssl a4 */ /* UNMODELED: a4 clobbered */
  /* 00ba: sll a3, a3 */ /* UNMODELED: a3 clobbered */
  a3 = a8 ^ a3; /* 00bd: xor a3, a8, a3 */
  a8 = MEM8(a2 + 16); /* 00c0: l8ui a8, a2, 16 */
  a3 = a3 & a8; /* 00c3: and a3, a3, a8 */
  MEM8(a2 + 16) = a3; /* 00c6: s8i a3, a2, 16 */
L_c9:;
  a4 = a2 + a4; /* 00c9: add.n a4, a2, a4 */
  a8 = 0x1; /* 00cb: movi.n a8, 1 */
  MEM8(a4 + 17) = a8; /* 00cd: s8i a8, a4, 17 */
  MEMW(); /* 00d0: memw  */
  a3 = MEM8(a2 + 14); /* 00d3: l8ui a3, a2, 14 */
  a3 = a3 + (-3); /* 00d6: addi a3, a3, -3 */
  a3 = (a3 >> 0) & 0xFF; /* 00d9: extui a3, a3, 0, 8 */
  if (a3 >= 2) goto L_e5; /* 00dc: bgeui a3, 2, e5 <trc_onAmpduOp+0xe1> */
  MEM8(a2 + 14) = a8; /* 00df: s8i a8, a2, 14 */
  MEMW(); /* 00e2: memw  */
L_e5:;
  MEMW(); /* 00e5: memw  */
  return (int32_t)a2; /* 00e8: retw.n  */
}

/* trc_set_per_pkt_rate @ trc.o 00000000 size 22B bind GLOBAL
 * Calls: none | Data refs: none
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t trc_set_per_pkt_rate(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.trc_set_per_pkt_rate; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_0:;
  /* 0000: entry a1, 32 */
  a10 = MEM32(a2 + 44); /* 0003: l32i.n a10, a2, 44 */
  a9 = 0x1; /* 0005: movi.n a9, 1 */
  a9 = 0x2000000; /* 0007: slli a9, a9, 25 */
  a8 = MEM32(a10 + 0); /* 000a: l32i.n a8, a10, 0 */
  a8 = a8 | a9; /* 000c: or a8, a8, a9 */
  MEM32(a10 + 0) = a8; /* 000f: s32i.n a8, a10, 0 */
  MEMW(); /* 0011: memw  */
  return (int32_t)a2; /* 0014: retw.n  */
}

/* rcSetBarRate @ trc.o 00000008 size 30B bind GLOBAL
 * Calls: none | Data refs: BAROFDMSched, rc11BSchedTbl
 *   MMIO: none
 *   funcdb v3: 0 call(s), 2 ref(s); disasm: 0 call(s), 2 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t rcSetBarRate(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.rcSetBarRate; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_8:;
  /* 0008: entry a1, 32 */
  a3 = (a3 >> 0) & 0xFF; /* 000b: extui a3, a3, 0, 8 */
  a8 = (uint32_t)&BAROFDMSched; /* 000e: l32r a8, 0 <rcSetBarRate-0x8> (0 <rcSetBarRate-0x8>) */ /* literal @0x0: BAROFDMSched */
  if (a3 != 0) goto L_16; /* 0011: bnez.n a3, 16 <rcSetBarRate+0xe> */
  a8 = (uint32_t)&rc11BSchedTbl; /* 0013: l32r a8, 4 <rcSetBarRate-0x4> (0 <rcSetBarRate-0x8>) */ /* literal @0x4: rc11BSchedTbl */
L_16:;
  MEM32(a2 + 28) = a8; /* 0016: s32i.n a8, a2, 28 */
  a8 = MEM8(a8 + 0); /* 0018: l8ui a8, a8, 0 */
  MEM8(a2 + 12) = a8; /* 001b: s8i a8, a2, 12 */
  MEMW(); /* 001e: memw  */
  MEMW(); /* 0021: memw  */
  return (int32_t)a2; /* 0024: retw.n  */
}

/* rc_get_default_sched @ trc.o 00000004 size 8B bind GLOBAL
 * Calls: none | Data refs: rc11BSchedTbl
 *   MMIO: none
 *   funcdb v3: 0 call(s), 1 ref(s); disasm: 0 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t rc_get_default_sched(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.rc_get_default_sched; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a2 = (uint32_t)&rc11BSchedTbl; /* 0007: l32r a2, 0 <rc_get_default_sched-0x4> (0 <rc_get_default_sched-0x4>) */ /* literal @0x0: rc11BSchedTbl */
  return (int32_t)a2; /* 000a: retw.n  */
}

/* rc_get_G6M_sched @ trc.o 00000004 size 8B bind GLOBAL
 * Calls: none | Data refs: rc11GSchedTbl
 *   MMIO: none
 *   funcdb v3: 0 call(s), 1 ref(s); disasm: 0 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t rc_get_G6M_sched(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.rc_get_G6M_sched; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a2 = (uint32_t)&rc11GSchedTbl; /* 0007: l32r a2, 0 <rc_get_G6M_sched-0x4> (0 <rc_get_G6M_sched-0x4>) */ /* literal @0x0: rc11GSchedTbl */
  return (int32_t)a2; /* 000a: retw.n  */
}

/* rcGetAmpduSched @ trc.o 00000010 size 112B bind GLOBAL
 * Calls: wifi_assert | Data refs: .rodata.__FUNCTION__$2, .rodata.rcGetAmpduSched.str1.1, wifi_assert
 *   MMIO: none
 *   funcdb v3: 1 call(s), 3 ref(s); disasm: 2 call(s), 3 data ref(s)
 * Fidelity: medium - 40 instr, 4 branches, calls resolved */
int32_t rcGetAmpduSched(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.rcGetAmpduSched; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_10:;
  /* 0010: entry a1, 32 */
  a13 = 0x8CD; /* 0013: l32r a13, 0 <rcGetAmpduSched-0x10> (8cd <rcUpdatePhyMode+0x861>) */ @0x0
  a10 = 0x1; /* 0016: movi.n a10, 1 */
  a12 = (uint32_t)&lit_rodata_FUNCTION_2; /* 0018: l32r a12, 4 <rcGetAmpduSched-0xc> (0 <rcGetAmpduSched-0x10>) */ /* literal @0x4: .rodata.__FUNCTION__$2 */
  a11 = (uint32_t)&lit_rodata_rcGetAmpduSched_str1_1; /* 001b: l32r a11, 8 <rcGetAmpduSched-0x8> (0 <rcGetAmpduSched-0x10>) */ /* literal @0x8: .rodata.rcGetAmpduSched.str1.1 */
  a8 = (uint32_t)&wifi_assert; /* 001e: l32r a8, c <rcGetAmpduSched-0x4> (0 <rcGetAmpduSched-0x10>) */ /* literal: GOT slot for wifi_assert */
  wifi_assert(a2, a3, a4, a5); /* call via literal slot */ /* 0021: callx8 a8 */
  a4 = MEM32(a2 + 96); /* 0024: l32i a4, a2, 96 */
  MEM32(a3 + 28) = a4; /* 0027: s32i.n a4, a3, 28 */
  a4 = MEM8(a2 + 11); /* 0029: l8ui a4, a2, 11 */
  if (!((a4 >> 2) & 1)) goto L_39; /* 002c: bbci a4, 2, 39 <rcGetAmpduSched+0x29> */
  a2 = MEM8(a2 + 10); /* 002f: l8ui a2, a2, 10 */
  MEMW(); /* 0032: memw  */
  goto L_75; /* 0035: j 75 <rcGetAmpduSched+0x65> */
  /* 0038: .byte 00 */
L_39:;
  a4 = MEM8(a2 + 25); /* 0039: l8ui a4, a2, 25 */
  if ((a4 >> 3) & 1) goto L_7b; /* 003c: bbsi a4, 3, 7b <rcGetAmpduSched+0x6b> */
  a4 = MEM32(a2 + 116); /* 003f: l32i a4, a2, 116 */
  a10 = MEM8(a2 + 13); /* 0042: l8ui a10, a2, 13 */
  ((int32_t(*)())a4)(a2, a3, a4, a5); /* 0045: callx8 a4 */ /* indirect */
  a4 = MEM8(a2 + 12); /* 0048: l8ui a4, a2, 12 */
  a4 = a10 + a4; /* 004b: add.n a4, a10, a4 */
  a10 = 0x10; /* 004d: movi a10, 16 */
  a4 = (a4 >> 0) & 0xFF; /* 0050: extui a4, a4, 0, 8 */
  a8 = MEM32(a2 + 116); /* 0053: l32i a8, a2, 116 */
  wifi_assert(a2, a3, a4, a5); /* call via literal slot */ /* 0056: callx8 a8 */
  if (a10 >= a4) goto L_66; /* 0059: bgeu a10, a4, 66 <rcGetAmpduSched+0x56> */
  a10 = 0x10; /* 005c: movi.n a10, 16 */
  a4 = MEM32(a2 + 116); /* 005e: l32i a4, a2, 116 */
  ((int32_t(*)())a4)(a2, a3, a4, a5); /* 0061: callx8 a4 */ /* indirect */
  a4 = 0x10; /* 0064: mov.n a4, a10 */
L_66:;
  a4 = 0x10; /* 0066: extui a4, a4, 0, 16 */
  a2 = MEM32(a2 + 112); /* 0069: l32i a2, a2, 112 */
  a4 = 0x30; /* 006c: addx2 a4, a4, a4 */
  a4 = (a4 << 4) + a2; /* 006f: addx4 a4, a4, a2 */
  a2 = MEM8(a4 + 0); /* 0072: l8ui a2, a4, 0 */
L_75:;
  MEM8(a3 + 12) = a2; /* 0075: s8i a2, a3, 12 */
  MEMW(); /* 0078: memw  */
L_7b:;
  MEMW(); /* 007b: memw  */
  return (int32_t)a2; /* 007e: retw.n  */
}

/* rcGetRate @ trc.o 00000010 size 124B bind GLOBAL
 * Calls: wifi_assert[got] | Data refs: .rodata.__FUNCTION__$1, .rodata.rcGetAmpduSched.str1.1, wifi_assert
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 1 call(s), 3 data ref(s)
 * Fidelity: medium - 47 instr, 10 branches, calls resolved */
int32_t rcGetRate(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .wifiextrairam.11; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_10:;
  /* 0010: entry a1, 32 */
  a5 = MEM32(a3 + 0); /* 0013: l32i.n a5, a3, 0 */
  a9 = (a5 >> 22) & 0x1; /* 0015: extui a9, a5, 22, 1 */
  a10 = MEM8(a3 + 5); /* 0018: l8ui a10, a3, 5 */
  a4 = MEM8(a3 + 6); /* 001b: l8ui a4, a3, 6 */
  if (a9 != 0) goto L_8a; /* 001e: bnez a9, 8a <rcGetRate+0x7a> */
  a8 = 0x1; /* 0021: movi.n a8, 1 */
  if (a2 != 0) a8 = a9; /* 0023: movnez a8, a9, a2 */
  if (a8 != 0) goto L_8a; /* 0026: bnez a8, 8a <rcGetRate+0x7a> */
  a8 = MEM8(a2 + 11); /* 0029: l8ui a8, a2, 11 */
  a8 = (a8 >> 0) & 0x3; /* 002c: extui a8, a8, 0, 2 */
  if (a8 == 0) goto L_45; /* 002f: beqz.n a8, 45 <rcGetRate+0x35> */
  if ((a5 >> 21) & 1) goto L_45; /* 0031: bbsi a5, 21, 45 <rcGetRate+0x35> */
  if (!((a5 >> 3) & 1)) goto L_3d; /* 0034: bbci a5, 3, 3d <rcGetRate+0x2d> */
  a2 = MEM8(a2 + 8); /* 0037: l8ui a2, a2, 8 */
  goto L_7a; /* 003a: j 7a <rcGetRate+0x6a> */
L_3d:;
  a2 = MEM8(a2 + 9); /* 003d: l8ui a2, a2, 9 */
  goto L_7a; /* 0040: j 7a <rcGetRate+0x6a> */
  /* 0043: .byte 00 */
  /* 0044: .byte 00 */
L_45:;
  a5 = MEM32(a3 + 28); /* 0045: l32i.n a5, a3, 28 */
  a2 = 0x0; /* 0047: movi.n a2, 0 */
  /* 0049: maxu a4, a4, a10 */ /* UNMODELED: a4 clobbered */
  a10 = 0x1; /* 004c: movi.n a10, 1 */
  if (a5 == 0) a10 = a2; /* 004e: moveqz a10, a2, a5 */
  a13 = 0x96B; /* 0051: l32r a13, 0 <rcGetRate-0x10> (96b <rcUpdatePhyMode+0x8ff>) */ @0x0
  a12 = (uint32_t)&lit_rodata_FUNCTION_1; /* 0054: l32r a12, 4 <rcGetRate-0xc> (0 <rcGetRate-0x10>) */ /* literal @0x4: .rodata.__FUNCTION__$1 */
  a11 = (uint32_t)&lit_rodata_rcGetAmpduSched_str1_1; /* 0057: l32r a11, 8 <rcGetRate-0x8> (0 <rcGetRate-0x10>) */ /* literal @0x8: .rodata.rcGetAmpduSched.str1.1 */
  a8 = (uint32_t)&wifi_assert; /* 005a: l32r a8, c <rcGetRate-0x4> (0 <rcGetRate-0x10>) */ /* literal: GOT slot for wifi_assert */
  wifi_assert(a2, a3, a4, a5); /* call via literal slot */ /* 005d: callx8 a8 */
  a10 = a5 + (1); /* 0060: addi.n a10, a5, 1 */
  a8 = a2; /* 0062: mov.n a8, a2 */
  a9 = 0x4; /* 0064: movi.n a9, 4 */
  /* 0066: loop a9, 8a <rcGetRate+0x7a> */ /* loop a9 times, end L_8a; body shown single-pass */
  a11 = MEM8(a10 + 0); /* 0069: l8ui a11, a10, 0 */
  a2 = a2 + a11; /* 006c: add.n a2, a2, a11 */
  a2 = (a2 >> 0) & 0xFF; /* 006e: extui a2, a2, 0, 8 */
  if (a4 >= a2) goto L_86; /* 0071: bgeu a4, a2, 86 <rcGetRate+0x76> */
  a8 = (a8 << 2) + a5; /* 0074: addx2 a8, a8, a5 */
  a2 = MEM8(a8 + 0); /* 0077: l8ui a2, a8, 0 */
L_7a:;
  MEM8(a3 + 12) = a2; /* 007a: s8i a2, a3, 12 */
  MEMW(); /* 007d: memw  */
  MEMW(); /* 0080: memw  */
  goto L_8a; /* 0083: j 8a <rcGetRate+0x7a> */
L_86:;
  a8 = a8 + (1); /* 0086: addi.n a8, a8, 1 */
  a10 = a10 + (2); /* 0088: addi.n a10, a10, 2 */
L_8a:;
  return (int32_t)a2; /* 008a: retw.n  */
}

/* rssi_margin @ trc.o 00000004 size 322B bind GLOBAL
 * Calls: .rodata.rssi_margin[tail] | Data refs: .rodata.rssi_margin
 *   MMIO: none
 *   funcdb v3: 0 call(s), 1 ref(s); disasm: 1 call(s), 1 data ref(s)
 * Fidelity: low - 119 instr, 48 branches, 0 indirect; jx computed tail dispatch at +0x27 (addi -9/extui/movi 22/bltu at +0x1c, l32r .rodata.rssi_margin at +0x1f + addx4 at +0x22, jx a2); threshold-to-case mapping structural - need jump-table case decode to raise */
int32_t rssi_margin(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.rssi_margin; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a3 = (a3 >> 0) & 0xFF; /* 0007: extui a3, a3, 0, 8 */
  a8 = (a2 >> 0) & 0xFF; /* 000a: extui a8, a2, 0, 8 */
  if (a3 >= 8) goto L_50; /* 000d: bgeui a3, 8, 50 <rssi_margin+0x4c> */
  goto L_2c; /* 0010: j 2c <rssi_margin+0x28> */
  /* 0013: .byte 00 */
L_14:;
  a3 = a3 + (-9); /* 0014: addi a3, a3, -9 */
  a3 = (a3 >> 0) & 0xFF; /* 0017: extui a3, a3, 0, 8 */
  a2 = 0x16; /* 001a: movi.n a2, 22 */
  if (a2 < a3) goto L_90; /* 001c: bltu a2, a3, 90 <rssi_margin+0x8c> */
  a2 = (uint32_t)&lit_rodata_rssi_margin; /* 001f: l32r a2, 0 <rssi_margin-0x4> (0 <rssi_margin-0x4>) */ /* literal @0x0: .rodata.rssi_margin */
  a3 = (a3 << 4) + a2; /* 0022: addx4 a3, a3, a2 */
  a2 = MEM32(a3 + 0); /* 0025: l32i.n a2, a3, 0 */
  return lit_rodata_rssi_margin(a2, a3, a4, a5); /* tail jump */ /* 0027: jx a2 */
  /* 002a: .byte 00 */
  /* 002b: .byte 00 */
L_2c:;
  a2 = 0x1; /* 002c: movi.n a2, 1 */
  /* 002e: ssl a3 */ /* UNMODELED: a3 clobbered */
  /* 0031: sll a3, a2 */ /* UNMODELED: a3 clobbered */
  a9 = 0x23; /* 0034: movi.n a9, 35 */
  a9 = a3 & a9; /* 0036: and a9, a3, a9 */
  if (a9 != 0) goto L_124; /* 0039: bnez a9, 124 <rssi_margin+0x120> */
  a10 = 0x88; /* 003c: movi a10, 136 */
  if ((a3 & a10) == 0) goto L_45; /* 003f: bnone a3, a10, 45 <rssi_margin+0x41> */
  goto L_110; /* 0042: j 110 <rssi_margin+0x10c> */
L_45:;
  a2 = 0x44; /* 0045: movi.n a2, 68 */
  a2 = a3 & a2; /* 0047: and a2, a3, a2 */
  if (a2 != 0) goto L_dd; /* 004a: bnez a2, dd <rssi_margin+0xd9> */
  goto L_144; /* 004d: j 144 <rssi_margin+0x140> */
L_50:;
  a2 = a3 + (-8); /* 0050: addi a2, a3, -8 */
  a2 = (a2 >> 0) & 0xFF; /* 0053: extui a2, a2, 0, 8 */
  a9 = 0x17; /* 0056: movi.n a9, 23 */
  if (a9 >= a2) goto L_14; /* 0058: bgeu a9, a2, 14 <rssi_margin+0x10> */
  goto L_142; /* 005b: j 142 <rssi_margin+0x13e> */
  /* 005e: .byte 00 */
  a2 = 0x21; /* 005f: movi.n a2, 33 */
  if (a2 < a8) goto L_67; /* 0061: bltu a2, a8, 67 <rssi_margin+0x63> */
  goto L_142; /* 0064: j 142 <rssi_margin+0x13e> */
L_67:;
  a2 = a8 + (-127); /* 0067: addi a2, a8, -127 */
  if (a2 == 0) goto L_142; /* 006a: beqz a2, 142 <rssi_margin+0x13e> */
  a2 = a8 + (-33); /* 006d: addi a2, a8, -33 */
  goto L_84; /* 0070: j 84 <rssi_margin+0x80> */
  a2 = 0x1D; /* 0073: movi.n a2, 29 */
  if (a2 < a8) goto L_7b; /* 0075: bltu a2, a8, 7b <rssi_margin+0x77> */
  goto L_142; /* 0078: j 142 <rssi_margin+0x13e> */
L_7b:;
  a2 = a8 + (-127); /* 007b: addi a2, a8, -127 */
  if (a2 == 0) goto L_142; /* 007e: beqz a2, 142 <rssi_margin+0x13e> */
  a2 = a8 + (-29); /* 0081: addi a2, a8, -29 */
L_84:;
  a2 = (int32_t)a2 >> (1 & 31); /* 0084: srai a2, a2, 1 */
  a2 = (a2 << 2) + a2; /* 0087: addx2 a2, a2, a2 */
  a2 = (a2 >> 0) & 0xFF; /* 008a: extui a2, a2, 0, 8 */
  goto L_13a; /* 008d: j 13a <rssi_margin+0x136> */
L_90:;
  a2 = 0x1A; /* 0090: movi.n a2, 26 */
  if (a2 < a8) goto L_98; /* 0092: bltu a2, a8, 98 <rssi_margin+0x94> */
  goto L_142; /* 0095: j 142 <rssi_margin+0x13e> */
L_98:;
  a2 = a8 + (-127); /* 0098: addi a2, a8, -127 */
  if (a2 == 0) goto L_142; /* 009b: beqz a2, 142 <rssi_margin+0x13e> */
  a2 = a8 + (-26); /* 009e: addi a2, a8, -26 */
  goto L_84; /* 00a1: j 84 <rssi_margin+0x80> */
  a2 = 0x15; /* 00a4: movi.n a2, 21 */
  if (a2 < a8) goto L_ac; /* 00a6: bltu a2, a8, ac <rssi_margin+0xa8> */
  goto L_142; /* 00a9: j 142 <rssi_margin+0x13e> */
L_ac:;
  a2 = a8 + (-127); /* 00ac: addi a2, a8, -127 */
  if (a2 == 0) goto L_142; /* 00af: beqz a2, 142 <rssi_margin+0x13e> */
  a2 = a8 + (-21); /* 00b2: addi a2, a8, -21 */
  goto L_84; /* 00b5: j 84 <rssi_margin+0x80> */
  a2 = 0x10; /* 00b8: movi.n a2, 16 */
  if (a2 < a8) goto L_c0; /* 00ba: bltu a2, a8, c0 <rssi_margin+0xbc> */
  goto L_142; /* 00bd: j 142 <rssi_margin+0x13e> */
L_c0:;
  a2 = a8 + (-127); /* 00c0: addi a2, a8, -127 */
  if (a2 == 0) goto L_142; /* 00c3: beqz a2, 142 <rssi_margin+0x13e> */
  a2 = a8 + (-16); /* 00c6: addi a2, a8, -16 */
  goto L_84; /* 00c9: j 84 <rssi_margin+0x80> */
  a2 = 0xD; /* 00cc: movi.n a2, 13 */
  if (a2 >= a8) goto L_142; /* 00ce: bgeu a2, a8, 142 <rssi_margin+0x13e> */
  a2 = a8 + (-127); /* 00d1: addi a2, a8, -127 */
  if (a2 == 0) goto L_142; /* 00d4: beqz a2, 142 <rssi_margin+0x13e> */
  a2 = a8 + (-13); /* 00d7: addi a2, a8, -13 */
  goto L_84; /* 00da: j 84 <rssi_margin+0x80> */
L_dd:;
  a2 = 0xB; /* 00dd: movi.n a2, 11 */
  if (a2 >= a8) goto L_142; /* 00df: bgeu a2, a8, 142 <rssi_margin+0x13e> */
  a2 = a8 + (-127); /* 00e2: addi a2, a8, -127 */
  if (a2 == 0) goto L_142; /* 00e5: beqz a2, 142 <rssi_margin+0x13e> */
  a2 = a8 + (-11); /* 00e8: addi a2, a8, -11 */
  goto L_84; /* 00eb: j 84 <rssi_margin+0x80> */
  a2 = 0x8; /* 00ee: movi.n a2, 8 */
  if (a2 >= a8) goto L_142; /* 00f0: bgeu a2, a8, 142 <rssi_margin+0x13e> */
  a2 = a8 + (-127); /* 00f3: addi a2, a8, -127 */
  if (a2 == 0) goto L_142; /* 00f6: beqz a2, 142 <rssi_margin+0x13e> */
  a2 = a8 + (-8); /* 00f9: addi a2, a8, -8 */
  goto L_84; /* 00fc: j 84 <rssi_margin+0x80> */
  /* 00ff: .byte 00 */
  a2 = 0x9; /* 0100: movi.n a2, 9 */
  if (a2 >= a8) goto L_142; /* 0102: bgeu a2, a8, 142 <rssi_margin+0x13e> */
  a2 = a8 + (-127); /* 0105: addi a2, a8, -127 */
  if (a2 == 0) goto L_142; /* 0108: beqz.n a2, 142 <rssi_margin+0x13e> */
  a2 = a8 + (-9); /* 010a: addi a2, a8, -9 */
  goto L_84; /* 010d: j 84 <rssi_margin+0x80> */
L_110:;
  a3 = 0xE; /* 0110: movi.n a3, 14 */
  if (a3 >= a8) goto L_142; /* 0112: bgeu a3, a8, 142 <rssi_margin+0x13e> */
  a3 = a8 + (-127); /* 0115: addi a3, a8, -127 */
  if (a3 == 0) a2 = a9; /* 0118: moveqz a2, a9, a3 */
  if (a2 == 0) goto L_142; /* 011b: beqz.n a2, 142 <rssi_margin+0x13e> */
  a2 = a8 + (-14); /* 011d: addi a2, a8, -14 */
  goto L_84; /* 0120: j 84 <rssi_margin+0x80> */
  /* 0123: .byte 00 */
L_124:;
  a2 = 0xA; /* 0124: movi.n a2, 10 */
  if (a2 >= a8) goto L_142; /* 0126: bgeu a2, a8, 142 <rssi_margin+0x13e> */
  a2 = a8 + (-127); /* 0129: addi a2, a8, -127 */
  if (a2 == 0) goto L_142; /* 012c: beqz.n a2, 142 <rssi_margin+0x13e> */
  a8 = a8 + (-10); /* 012e: addi a8, a8, -10 */
  a8 = (int32_t)a8 >> (1 & 31); /* 0131: srai a8, a8, 1 */
  a8 = (a8 << 2) + a8; /* 0134: addx2 a8, a8, a8 */
  a2 = (a8 >> 0) & 0xFF; /* 0137: extui a2, a8, 0, 8 */
L_13a:;
  a3 = 0x20; /* 013a: movi.n a3, 32 */
  /* 013c: minu a2, a2, a3 */ /* UNMODELED: a2 clobbered */
  goto L_144; /* 013f: j 144 <rssi_margin+0x140> */
L_142:;
  a2 = 0x0; /* 0142: movi.n a2, 0 */
L_144:;
  return (int32_t)a2; /* 0144: retw.n  */
}

/* TRC_PER_IS_GOOD @ trc.o 00000004 size 81B bind GLOBAL
 * Calls: rssi_margin | Data refs: rssi_margin
 *   MMIO: none
 *   funcdb v3: 1 call(s), 1 ref(s); disasm: 1 call(s), 1 data ref(s)
 * Fidelity: medium - 29 instr, 6 branches, calls resolved */
int32_t TRC_PER_IS_GOOD(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.TRC_PER_IS_GOOD; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a4 = MEM32(a2 + 96); /* 0007: l32i a4, a2, 96 */
  a10 = MEM8(a2 + 1); /* 000a: l8ui a10, a2, 1 */
  a2 = 0x5A; /* 000d: movi a2, 90 */
  a11 = MEM8(a4 + 0); /* 0010: l8ui a11, a4, 0 */
  a8 = (uint32_t)&rssi_margin; /* 0013: l32r a8, 0 <TRC_PER_IS_GOOD-0x4> (0 <TRC_PER_IS_GOOD-0x4>) */ /* literal: GOT slot for rssi_margin */
  rssi_margin(a2, a3, a4, a5); /* call via literal slot */ /* 0016: callx8 a8 */
  a9 = a2 - a10; /* 0019: sub a9, a2, a10 */
  a8 = MEM8(a4 + 9); /* 001c: l8ui a8, a4, 9 */
  if (a8 == 0) goto L_2d; /* 001f: beqz.n a8, 2d <TRC_PER_IS_GOOD+0x29> */
  a9 = 0x64; /* 0021: movi a9, 100 */
  a2 = 0x40; /* 0024: movi a2, 64 */
  a9 = a9 - a10; /* 0027: sub a9, a9, a10 */
  if (a2 < a8) goto L_3a; /* 002a: bltu a2, a8, 3a <TRC_PER_IS_GOOD+0x36> */
L_2d:;
  a2 = 0x1; /* 002d: movi.n a2, 1 */
  if (a9 < a3) goto L_34; /* 002f: bltu a9, a3, 34 <TRC_PER_IS_GOOD+0x30> */
  a2 = 0x0; /* 0032: movi.n a2, 0 */
L_34:;
  a2 = 0x0; /* 0034: extui a2, a2, 0, 8 */
  goto L_53; /* 0037: j 53 <TRC_PER_IS_GOOD+0x4f> */
L_3a:;
  a2 = 0x0; /* 003a: movi.n a2, 0 */
  if (a9 >= a3) goto L_50; /* 003c: bgeu a9, a3, 50 <TRC_PER_IS_GOOD+0x4c> */
  a8 = a8 + (2); /* 003f: addi a8, a8, 2 */
  a8 = a8 - a10; /* 0042: sub a8, a8, a10 */
  a9 = 0x1; /* 0045: movi a9, 1 */
  if (a8 < a3) goto L_4e; /* 0048: bltu a8, a3, 4e <TRC_PER_IS_GOOD+0x4a> */
  a9 = 0x0; /* 004b: or a9, a2, a2 */
L_4e:;
  a2 = 0x0; /* 004e: mov.n a2, a9 */
L_50:;
  a2 = 0x0; /* 0050: extui a2, a2, 0, 1 */
L_53:;
  return (int32_t)a2; /* 0053: retw.n  */
}

/* TRC_AMPDU_PER_DOWN_THRESHOLD @ trc.o 00000014 size 117B bind GLOBAL
 * Calls: rssi_margin | Data refs: .rodata.TRC_AMPDU_PER_DOWN_THRESHOLD, rssi_margin
 *   MMIO: none
 *   funcdb v3: 1 call(s), 2 ref(s); disasm: 4 call(s), 2 data ref(s)
 * Fidelity: low - 44 instr, 7 branches, jx computed tail dispatch via rssi_margin table (+0x27 jx a2); threshold comparisons observed, case targets structural - need jump-table case decode to raise */
int32_t TRC_AMPDU_PER_DOWN_THRESHOLD(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.TRC_AMPDU_PER_DOWN_THRESHOLD; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_14:;
  /* 0014: entry a1, 32 */
  a8 = MEM8(a2 + 13); /* 0017: l8ui a8, a2, 13 */
  a9 = 0xC; /* 001a: movi.n a9, 12 */
  a8 = a8 + (-19); /* 001c: addi a8, a8, -19 */
  a8 = (a8 >> 0) & 0xFF; /* 001f: extui a8, a8, 0, 8 */
  if (a9 < a8) goto L_84; /* 0022: bltu a9, a8, 84 <TRC_AMPDU_PER_DOWN_THRESHOLD+0x70> */
  a9 = (uint32_t)&lit_rodata_TRC_AMPDU_PER_DOWN_THRESHOLD; /* 0025: l32r a9, 0 <TRC_AMPDU_PER_DOWN_THRESHOLD-0x14> (0 <TRC_AMPDU_PER_DOWN_THRESHOLD-0x14>) */ /* literal @0x0: .rodata.TRC_AMPDU_PER_DOWN_THRESHOLD */
  a8 = (a8 << 4) + a9; /* 0028: addx4 a8, a8, a9 */
  a8 = MEM32(a8 + 0); /* 002b: l32i.n a8, a8, 0 */
  /* 002d: jx a8 */ /* jx a8: computed tail jump; modeled as return */
  return (int32_t)a2;
  a11 = 0x1F; /* 0030: movi.n a11, 31 */
  goto L_3c; /* 0032: j 3c <TRC_AMPDU_PER_DOWN_THRESHOLD+0x28> */
  a11 = 0x17; /* 0035: movi.n a11, 23 */
  goto L_4d; /* 0037: j 4d <TRC_AMPDU_PER_DOWN_THRESHOLD+0x39> */
  a11 = 0x16; /* 003a: movi.n a11, 22 */
L_3c:;
  a10 = MEM8(a2 + 1); /* 003c: l8ui a10, a2, 1 */
  a2 = 0x72; /* 003f: movi a2, 114 */
  a8 = (uint32_t)&rssi_margin; /* 0042: l32r a8, 4 <TRC_AMPDU_PER_DOWN_THRESHOLD-0x10> (0 <TRC_AMPDU_PER_DOWN_THRESHOLD-0x14>) */ /* literal: GOT slot for rssi_margin */
  rssi_margin(a2, a3, a4, a5); /* call via literal slot */ /* 0045: callx8 a8 */
  goto L_7c; /* 0048: j 7c <TRC_AMPDU_PER_DOWN_THRESHOLD+0x68> */
  a11 = 0x15; /* 004b: movi.n a11, 21 */
L_4d:;
  a10 = MEM8(a2 + 1); /* 004d: l8ui a10, a2, 1 */
  a2 = 0x73; /* 0050: movi a2, 115 */
  a8 = (uint32_t)&rssi_margin; /* 0053: l32r a8, 8 <TRC_AMPDU_PER_DOWN_THRESHOLD-0xc> (0 <TRC_AMPDU_PER_DOWN_THRESHOLD-0x14>) */ /* literal: GOT slot for rssi_margin */
  rssi_margin(a2, a3, a4, a5); /* call via literal slot */ /* 0056: callx8 a8 */
  goto L_7c; /* 0059: j 7c <TRC_AMPDU_PER_DOWN_THRESHOLD+0x68> */
  /* 005c: .byte 00 */
  a10 = MEM8(a2 + 1); /* 005d: l8ui a10, a2, 1 */
  a11 = 0x14; /* 0060: movi.n a11, 20 */
  a8 = (uint32_t)&rssi_margin; /* 0062: l32r a8, c <TRC_AMPDU_PER_DOWN_THRESHOLD-0x8> (0 <TRC_AMPDU_PER_DOWN_THRESHOLD-0x14>) */ /* literal: GOT slot for rssi_margin */
  rssi_margin(a2, a3, a4, a5); /* call via literal slot */ /* 0065: callx8 a8 */
  a2 = 0x6D; /* 0068: movi a2, 109 */
  goto L_7c; /* 006b: j 7c <TRC_AMPDU_PER_DOWN_THRESHOLD+0x68> */
  a10 = MEM8(a2 + 1); /* 006e: l8ui a10, a2, 1 */
  a11 = 0x13; /* 0071: movi.n a11, 19 */
  a8 = (uint32_t)&rssi_margin; /* 0073: l32r a8, 10 <TRC_AMPDU_PER_DOWN_THRESHOLD-0x4> (0 <TRC_AMPDU_PER_DOWN_THRESHOLD-0x14>) */ /* literal: GOT slot for rssi_margin */
  rssi_margin(a2, a3, a4, a5); /* call via literal slot */ /* 0076: callx8 a8 */
  a2 = 0x6C; /* 0079: movi a2, 108 */
L_7c:;
  a2 = a2 - a10; /* 007c: sub a2, a2, a10 */
  goto L_87; /* 007f: j 87 <TRC_AMPDU_PER_DOWN_THRESHOLD+0x73> */
  /* 0082: .byte 00 */
  /* 0083: .byte 00 */
L_84:;
  a2 = 0x72; /* 0084: movi a2, 114 */
L_87:;
  return (int32_t)a2; /* 0087: retw.n  */
}

/* rcAmpduLowerRate @ trc.o 00000030 size 170B bind GLOBAL
 * Calls: TRC_AMPDU_PER_DOWN_THRESHOLD, rcClearCurAMPDUSched, rcSetTxAmpduLimit, rx11NRate2AMPDULimit, .text.trcStopAmpdu$constprop$0[got] | Data refs: TRC_AMPDU_PER_DOWN_THRESHOLD, g_mesh_init_ps_type, g_mesh_is_root, g_mesh_is_started, g_osi_funcs_p, g_wifi_mac_time_delta, rcClearCurAMPDUSched, rcSetTxAmpduLimit, rx11NRate2AMPDULimit, trc_ctl, .text.trcStopAmpdu$constprop$0
 *   MMIO: 0x3FF73C00
 *   funcdb v3: 4 call(s), 10 ref(s); disasm: 5 call(s), 11 data ref(s)
 * Fidelity: medium - 63 instr, 7 branches, calls resolved */
int32_t rcAmpduLowerRate(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.rcAmpduLowerRate; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_30:;
  /* 0030: entry a1, 32 */
  a8 = (uint32_t)&trc_ctl; /* 0033: l32r a8, 0 <rcAmpduLowerRate-0x30> (0 <rcAmpduLowerRate-0x30>) */ /* literal @0x0: trc_ctl */
  a3 = (a3 >> 0) & 0xFF; /* 0036: extui a3, a3, 0, 8 */
  a8 = MEM8(a8 + 24); /* 0039: l8ui a8, a8, 24 */
  if (a8 != a3) goto L_5d; /* 003c: bne a8, a3, 5d <rcAmpduLowerRate+0x2d> */
  a10 = a2 | a2; /* 003f: or a10, a2, a2 */
  a8 = (uint32_t)&TRC_AMPDU_PER_DOWN_THRESHOLD; /* 0042: l32r a8, 1c <rcAmpduLowerRate-0x14> (0 <rcAmpduLowerRate-0x30>) */ /* literal: GOT slot for TRC_AMPDU_PER_DOWN_THRESHOLD */
  TRC_AMPDU_PER_DOWN_THRESHOLD(a2, a3, a4, a5); /* call via literal slot */ /* 0045: callx8 a8 */
  a3 = MEM8(a2 + 30); /* 0048: l8ui a3, a2, 30 */
  a3 = a3 + (20); /* 004b: addi a3, a3, 20 */
  if (a3 >= a10) goto L_d0; /* 004e: bgeu a3, a10, d0 <rcAmpduLowerRate+0xa0> */
  a10 = a2; /* 0051: mov.n a10, a2 */
  a8 = (uint32_t)&trcStopAmpdu_constprop_0; /* 0053: l32r a8, 20 <rcAmpduLowerRate-0x10> (10 <rcAmpduLowerRate-0x20>) */ /* literal: GOT slot for .text.trcStopAmpdu$constprop$0 */
  trcStopAmpdu_constprop_0(a2, a3, a4, a5); /* call via literal slot */ /* 0056: callx8 a8 */
  goto L_d8; /* 0059: j d8 <rcAmpduLowerRate+0xa8> */
  /* 005c: .byte 00 */
L_5d:;
  a8 = 0x0; /* 005d: movi.n a8, 0 */
  MEM8(a2 + 12) = a8; /* 005f: s8i a8, a2, 12 */
  MEMW(); /* 0062: memw  */
  a8 = (uint32_t)&g_mesh_is_started; /* 0065: l32r a8, 4 <rcAmpduLowerRate-0x2c> (0 <rcAmpduLowerRate-0x30>) */ /* literal @0x4: g_mesh_is_started */
  a8 = MEM8(a8 + 0); /* 0068: l8ui a8, a8, 0 */
  if (a8 == 0) goto L_94; /* 006b: beqz.n a8, 94 <rcAmpduLowerRate+0x64> */
  a8 = (uint32_t)&g_mesh_is_root; /* 006d: l32r a8, 8 <rcAmpduLowerRate-0x28> (0 <rcAmpduLowerRate-0x30>) */ /* literal @0x8: g_mesh_is_root */
  MEMW(); /* 0070: memw  */
  a8 = MEM8(a8 + 0); /* 0073: l8ui a8, a8, 0 */
  a8 = (a8 >> 0) & 0xFF; /* 0076: extui a8, a8, 0, 8 */
  if (a8 != 0) goto L_94; /* 0079: bnez.n a8, 94 <rcAmpduLowerRate+0x64> */
  a8 = (uint32_t)&g_mesh_init_ps_type; /* 007b: l32r a8, c <rcAmpduLowerRate-0x24> (0 <rcAmpduLowerRate-0x30>) */ /* literal @0xC: g_mesh_init_ps_type */
  a8 = MEM32(a8 + 0); /* 007e: l32i.n a8, a8, 0 */
  if (a8 == 0) goto L_94; /* 0080: beqz.n a8, 94 <rcAmpduLowerRate+0x64> */
  a8 = (uint32_t)&g_osi_funcs_p; /* 0082: l32r a8, 10 <rcAmpduLowerRate-0x20> (0 <rcAmpduLowerRate-0x30>) */ /* literal @0x10: g_osi_funcs_p */
  a8 = MEM32(a8 + 0); /* 0085: l32i.n a8, a8, 0 */
  a10 = MEM32(a8 + 272); /* 0087: l32i a10, a8, 0x110 */
  MEMW(); /* 008a: memw  */
  ((int32_t(*)())a10)(a2, a3, a4, a5); /* 008d: callx8 a10 */ /* indirect */
  goto L_a3; /* 0090: j a3 <rcAmpduLowerRate+0x73> */
  /* 0093: .byte 00 */
L_94:;
  a8 = 0x3FF73C00; /* 0094: l32r a8, 14 <rcAmpduLowerRate-0x1c> (3ff73c00 <rcUpdatePhyMode+0x3ff73b94>) */ /* MMIO base */ @0x14
  MEMW(); /* 0097: memw  */
  a10 = REG32(0x3FF73C00); /* 009a: l32i.n a10, a8, 0 */ /* MMIO read: base 0x3FF73C00+0 */
  a8 = (uint32_t)&g_wifi_mac_time_delta; /* 009c: l32r a8, 18 <rcAmpduLowerRate-0x18> (0 <rcAmpduLowerRate-0x30>) */ /* literal @0x18: g_wifi_mac_time_delta */
  a8 = MEM32(a8 + 0); /* 009f: l32i.n a8, a8, 0 */
  a10 = a10 + a8; /* 00a1: add.n a10, a10, a8 */
L_a3:;
  a3 = a3 + (1); /* 00a3: addi.n a3, a3, 1 */
  a3 = (a3 >> 0) & 0xFF; /* 00a5: extui a3, a3, 0, 8 */
  a8 = MEM32(a2 + 112); /* 00a8: l32i a8, a2, 112 */
  a3 = (a3 << 2) + a3; /* 00ab: addx2 a3, a3, a3 */
  a3 = (a3 << 4) + a8; /* 00ae: addx4 a3, a3, a8 */
  MEM32(a2 + 80) = a10; /* 00b1: s32i a10, a2, 80 */
  a10 = MEM8(a3 + 0); /* 00b4: l8ui a10, a3, 0 */
  MEM8(a2 + 13) = a10; /* 00b7: s8i a10, a2, 13 */
  MEMW(); /* 00ba: memw  */
  MEMW(); /* 00bd: memw  */
  a8 = (uint32_t)&rx11NRate2AMPDULimit; /* 00c0: l32r a8, 24 <rcAmpduLowerRate-0xc> (0 <rcAmpduLowerRate-0x30>) */ /* literal: GOT slot for rx11NRate2AMPDULimit */
  rx11NRate2AMPDULimit(a2, a3, a4, a5); /* call via literal slot */ /* 00c3: callx8 a8 */
  a11 = a10; /* 00c6: mov.n a11, a10 */
  a10 = a2; /* 00c8: mov.n a10, a2 */
  a8 = (uint32_t)&rcSetTxAmpduLimit; /* 00ca: l32r a8, 28 <rcAmpduLowerRate-0x8> (0 <rcAmpduLowerRate-0x30>) */ /* literal: GOT slot for rcSetTxAmpduLimit */
  rcSetTxAmpduLimit(a2, a3, a4, a5); /* call via literal slot */ /* 00cd: callx8 a8 */
L_d0:;
  a10 = a2; /* 00d0: mov.n a10, a2 */
  a8 = (uint32_t)&rcClearCurAMPDUSched; /* 00d2: l32r a8, 2c <rcAmpduLowerRate-0x4> (0 <rcAmpduLowerRate-0x30>) */ /* literal: GOT slot for rcClearCurAMPDUSched */
  rcClearCurAMPDUSched(a2, a3, a4, a5); /* call via literal slot */ /* 00d5: callx8 a8 */
L_d8:;
  return (int32_t)a2; /* 00d8: retw.n  */
}

/* TRC_AMPDU_PER_UP_THRESHOLD @ trc.o 0000000c size 94B bind GLOBAL
 * Calls: rssi_margin | Data refs: .rodata.TRC_AMPDU_PER_UP_THRESHOLD, rssi_margin
 *   MMIO: none
 *   funcdb v3: 1 call(s), 2 ref(s); disasm: 2 call(s), 2 data ref(s)
 * Fidelity: low - 37 instr, 7 branches, jx computed tail dispatch via rssi_margin table (+0x2d jx a8); threshold comparisons observed, case targets structural - need jump-table case decode to raise */
int32_t TRC_AMPDU_PER_UP_THRESHOLD(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.TRC_AMPDU_PER_UP_THRESHOLD; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_c:;
  /* 000c: entry a1, 32 */
  a8 = MEM8(a2 + 13); /* 000f: l8ui a8, a2, 13 */
  a9 = 0xC; /* 0012: movi.n a9, 12 */
  a8 = a8 + (-19); /* 0014: addi a8, a8, -19 */
  a8 = (a8 >> 0) & 0xFF; /* 0017: extui a8, a8, 0, 8 */
  if (a9 < a8) goto L_65; /* 001a: bltu a9, a8, 65 <TRC_AMPDU_PER_UP_THRESHOLD+0x59> */
  a9 = (uint32_t)&lit_rodata_TRC_AMPDU_PER_UP_THRESHOLD; /* 001d: l32r a9, 0 <TRC_AMPDU_PER_UP_THRESHOLD-0xc> (0 <TRC_AMPDU_PER_UP_THRESHOLD-0xc>) */ /* literal @0x0: .rodata.TRC_AMPDU_PER_UP_THRESHOLD */
  a8 = (a8 << 4) + a9; /* 0020: addx4 a8, a8, a9 */
  a8 = MEM32(a8 + 0); /* 0023: l32i.n a8, a8, 0 */
  /* 0025: jx a8 */ /* jx a8: computed tail jump; modeled as return */
  return (int32_t)a2;
  a11 = 0x1F; /* 0028: movi.n a11, 31 */
  goto L_40; /* 002a: j 40 <TRC_AMPDU_PER_UP_THRESHOLD+0x34> */
  a11 = 0x17; /* 002d: movi.n a11, 23 */
  goto L_40; /* 002f: j 40 <TRC_AMPDU_PER_UP_THRESHOLD+0x34> */
  a11 = 0x16; /* 0032: movi.n a11, 22 */
  goto L_40; /* 0034: j 40 <TRC_AMPDU_PER_UP_THRESHOLD+0x34> */
  a11 = 0x15; /* 0037: movi.n a11, 21 */
  goto L_40; /* 0039: j 40 <TRC_AMPDU_PER_UP_THRESHOLD+0x34> */
  /* 003c: .byte 00 */
  /* 003d: .byte 00 */
  a11 = 0x14; /* 003e: movi.n a11, 20 */
L_40:;
  a10 = MEM8(a2 + 1); /* 0040: l8ui a10, a2, 1 */
  a2 = 0x79; /* 0043: movi a2, 121 */
  a8 = (uint32_t)&rssi_margin; /* 0046: l32r a8, 4 <TRC_AMPDU_PER_UP_THRESHOLD-0x8> (0 <TRC_AMPDU_PER_UP_THRESHOLD-0xc>) */ /* literal: GOT slot for rssi_margin */
  rssi_margin(a2, a3, a4, a5); /* call via literal slot */ /* 0049: callx8 a8 */
  goto L_5f; /* 004c: j 5f <TRC_AMPDU_PER_UP_THRESHOLD+0x53> */
  /* 004f: .byte 00 */
  /* 0050: .byte 00 */
  a10 = MEM8(a2 + 1); /* 0051: l8ui a10, a2, 1 */
  a11 = 0x13; /* 0054: movi.n a11, 19 */
  a8 = (uint32_t)&rssi_margin; /* 0056: l32r a8, 8 <TRC_AMPDU_PER_UP_THRESHOLD-0x4> (0 <TRC_AMPDU_PER_UP_THRESHOLD-0xc>) */ /* literal: GOT slot for rssi_margin */
  rssi_margin(a2, a3, a4, a5); /* call via literal slot */ /* 0059: callx8 a8 */
  a2 = 0x74; /* 005c: movi a2, 116 */
L_5f:;
  a2 = a2 - a10; /* 005f: sub a2, a2, a10 */
  goto L_68; /* 0062: j 68 <TRC_AMPDU_PER_UP_THRESHOLD+0x5c> */
L_65:;
  a2 = 0x79; /* 0065: movi a2, 121 */
L_68:;
  return (int32_t)a2; /* 0068: retw.n  */
}

/* rcUpdateTxDoneAmpdu2 @ trc.o 00000058 size 807B bind GLOBAL
 * Calls: rcUpdateAckSnr[got], rcUpdateAckSnr[got], TRC_AMPDU_PER_DOWN_THRESHOLD[got], trc_calc_duration[got], trc_calc_duration[got], rcAmpduLowerRate[got], TRC_AMPDU_PER_UP_THRESHOLD[got], trc_calc_duration[got], rx11NRate2AMPDULimit[got], rcSetTxAmpduLimit[got], rcClearCurAMPDUSched[got] | Data refs: rcUpdateAckSnr, trc_ctl, TRC_AMPDU_PER_DOWN_THRESHOLD, g_mesh_is_started, g_mesh_is_root, g_mesh_init_ps_type, g_osi_funcs_p, g_wifi_mac_time_delta, trc_calc_duration, rcAmpduLowerRate, TRC_AMPDU_PER_UP_THRESHOLD, rx11NRate2AMPDULimit, rcSetTxAmpduLimit, rcClearCurAMPDUSched
 *   MMIO: 0x3FF73C00
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 11 call(s), 14 data ref(s)
 * Fidelity: medium - 301 instr, 58 branches, 3 indirect; flow + direct calls mapped, GOT-indirects enumerated (verified against section disasm) */
int32_t rcUpdateTxDoneAmpdu2(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .wifi0iram.9; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_58:;
  /* 0058: entry a1, 48 */
  a5 = MEM32(a3 + 4); /* 005b: l32i.n a5, a3, 4 */
  a7 = (a4 >> 0) & 0xFFFF; /* 005d: extui a7, a4, 0, 16 */
  a5 = (a5 >> 0) & 0xF; /* 0060: extui a5, a5, 0, 4 */
  a9 = MEM8(a3 + 7); /* 0063: l8ui a9, a3, 7 */
  a6 = MEM8(a3 + 6); /* 0066: l8ui a6, a3, 6 */
  if (a9 == 0) goto L_37a; /* 0069: beqz a9, 37a <rcUpdateTxDoneAmpdu2+0x322> */
  a4 = MEM32(a2 + 96); /* 006c: l32i a4, a2, 96 */
  if (a4 == 0) goto L_37a; /* 006f: beqz a4, 37a <rcUpdateTxDoneAmpdu2+0x322> */
  a4 = MEM8(a2 + 14); /* 0072: l8ui a4, a2, 14 */
  if (a4 == 2) goto L_7b; /* 0075: beqi a4, 2, 7b <rcUpdateTxDoneAmpdu2+0x23> */
  goto L_37a; /* 0078: j 37a <rcUpdateTxDoneAmpdu2+0x322> */
L_7b:;
  a10 = 0x4; /* 007b: movi.n a10, 4 */
  a4 = MEM8(a2 + 11); /* 007d: l8ui a4, a2, 11 */
  if ((a4 & a10) == 0) goto L_86; /* 0080: bnone a4, a10, 86 <rcUpdateTxDoneAmpdu2+0x2e> */
  goto L_37a; /* 0083: j 37a <rcUpdateTxDoneAmpdu2+0x322> */
L_86:;
  a4 = 0x7FF; /* 0086: movi a4, 0x7ff */
  a7 = a7 + a4; /* 0089: add.n a7, a7, a4 */
  a11 = MEM8(a3 + 19); /* 008b: l8ui a11, a3, 19 */
  a8 = (a6 >> 0) & 0xFFFF; /* 008e: extui a8, a6, 0, 16 */
  a7 = a7 >> (11 & 31); /* 0091: srli a7, a7, 11 */
  a4 = MEM8(a3 + 5); /* 0094: l8ui a4, a3, 5 */
  if (a11 != 1) goto L_bd; /* 0097: bnei a11, 1, bd <rcUpdateTxDoneAmpdu2+0x65> */
  /* 009a: mul16u a4, a4, a7 */ /* UNMODELED: a4 clobbered */
  a4 = a9 + a4; /* 009d: add.n a4, a9, a4 */
  a7 = MEM8(a2 + 25); /* 009f: l8ui a7, a2, 25 */
  if ((a7 & a10) != 0) goto L_d4; /* 00a2: bany a7, a10, d4 <rcUpdateTxDoneAmpdu2+0x7c> */
  a10 = a2; /* 00a5: mov.n a10, a2 */
  a11 = MEM8(a3 + 13); /* 00a7: l8ui a11, a3, 13 */
  a11 = ((int32_t)(a11 << (32 - (7 & 31)))) >> (32 - (7 & 31)); /* 00aa: sext a11, a11, 7 */
  MEM32(a1 + 0) = a8; /* 00ad: s32i.n a8, a1, 0 */
  MEMW(); /* 00af: memw  */
  a8 = (uint32_t)&rcUpdateAckSnr; /* 00b2: l32r a8, 30 <rcUpdateTxDoneAmpdu2-0x28> (0 <rcUpdateTxDoneAmpdu2-0x58>) */ /* literal: GOT slot for rcUpdateAckSnr */
  rcUpdateAckSnr(a2, a3, a4, a5); /* call via literal slot */ /* 00b5: callx8 a8 */
  a8 = MEM32(a1 + 0); /* 00b8: l32i.n a8, a1, 0 */
  goto L_d4; /* 00ba: j d4 <rcUpdateTxDoneAmpdu2+0x7c> */
L_bd:;
  if (a8 == 0) goto L_cc; /* 00bd: beqz.n a8, cc <rcUpdateTxDoneAmpdu2+0x74> */
  a4 = a4 + (-1); /* 00bf: addi.n a4, a4, -1 */
  /* 00c1: mul16u a4, a4, a7 */ /* UNMODELED: a4 clobbered */
  a9 = a9 + a4; /* 00c4: add.n a9, a9, a4 */
  a4 = (a9 >> 0) & 0xFFFF; /* 00c6: extui a4, a9, 0, 16 */
  goto L_d4; /* 00c9: j d4 <rcUpdateTxDoneAmpdu2+0x7c> */
L_cc:;
  a4 = (uint32_t)((uint64_t)a4 * a7); /* 00cc: mull a4, a4, a7 */
  goto L_da; /* 00cf: j da <rcUpdateTxDoneAmpdu2+0x82> */
  /* 00d2: .byte 00 */
  /* 00d3: .byte 00 */
L_d4:;
  if (a4 >= a8) goto L_da; /* 00d4: bgeu a4, a8, da <rcUpdateTxDoneAmpdu2+0x82> */
  goto L_37a; /* 00d7: j 37a <rcUpdateTxDoneAmpdu2+0x322> */
L_da:;
  a3 = MEM32(a2 + 68); /* 00da: l32i a3, a2, 68 */
  a7 = a3 + a6; /* 00dd: add.n a7, a3, a6 */
  a9 = 0x1FFFFFF; /* 00df: l32r a9, 0 <rcUpdateTxDoneAmpdu2-0x58> (1ffffff <rcUpdatePhyMode+0x1ffff93>) */ @0x0
  if (a9 >= a7) goto L_f4; /* 00e2: bgeu a9, a7, f4 <rcUpdateTxDoneAmpdu2+0x9c> */
  a3 = a3 >> (1 & 31); /* 00e5: srli a3, a3, 1 */
  a7 = MEM32(a2 + 64); /* 00e8: l32i a7, a2, 64 */
  MEM32(a2 + 68) = a3; /* 00eb: s32i a3, a2, 68 */
  a3 = a7 >> (1 & 31); /* 00ee: srli a3, a7, 1 */
  MEM32(a2 + 64) = a3; /* 00f1: s32i a3, a2, 64 */
L_f4:;
  a3 = MEM32(a2 + 68); /* 00f4: l32i a3, a2, 68 */
  a3 = a3 + a6; /* 00f7: add.n a3, a3, a6 */
  MEM32(a2 + 68) = a3; /* 00f9: s32i a3, a2, 68 */
  a3 = MEM32(a2 + 64); /* 00fc: l32i a3, a2, 64 */
  a3 = a3 + a4; /* 00ff: add.n a3, a3, a4 */
  MEM32(a2 + 64) = a3; /* 0101: s32i a3, a2, 64 */
  a10 = MEM8(a2 + 13); /* 0104: l8ui a10, a2, 13 */
  a3 = MEM32(a2 + 116); /* 0107: l32i a3, a2, 116 */
  MEM32(a1 + 0) = a8; /* 010a: s32i.n a8, a1, 0 */
  MEMW(); /* 010c: memw  */
  ((int32_t(*)())a3)(a2, a3, a4, a5); /* 010f: callx8 a3 */ /* indirect */
  a3 = a10; /* 0112: mov.n a3, a10 */
  a8 = MEM32(a1 + 0); /* 0114: l32i.n a8, a1, 0 */
  a7 = MEM8(a2 + 12); /* 0116: l8ui a7, a2, 12 */
  if (a8 != 0) goto L_168; /* 0119: bnez a8, 168 <rcUpdateTxDoneAmpdu2+0x110> */
  a7 = a7 + (1); /* 011c: addi.n a7, a7, 1 */
  a7 = (a7 >> 0) & 0xFF; /* 011e: extui a7, a7, 0, 8 */
  a8 = MEM8(a2 + 15); /* 0121: l8ui a8, a2, 15 */
  a8 = a4 + a8; /* 0124: add.n a8, a4, a8 */
  MEM8(a2 + 15) = a8; /* 0126: s8i a8, a2, 15 */
  MEMW(); /* 0129: memw  */
  a8 = MEM32(a2 + 116); /* 012c: l32i a8, a2, 116 */
  MEM8(a2 + 12) = a7; /* 012f: s8i a7, a2, 12 */
  MEMW(); /* 0132: memw  */
  a7 = a7 + a10; /* 0135: add a7, a7, a10 */
  a10 = 0x10; /* 0138: movi a10, 16 */
  MEMW(); /* 013b: memw  */
  ((int32_t(*)())a8)(a2, a3, a4, a5); /* 013e: callx8 a8 */ /* indirect */
  if (a10 >= a7) goto L_150; /* 0141: bge a10, a7, 150 <rcUpdateTxDoneAmpdu2+0xf8> */
  a7 = (uint32_t)&trc_ctl; /* 0144: l32r a7, 4 <rcUpdateTxDoneAmpdu2-0x54> (0 <rcUpdateTxDoneAmpdu2-0x58>) */ /* literal @0x4: trc_ctl */
  a7 = MEM8(a7 + 24); /* 0147: l8ui a7, a7, 24 */
  if (a3 >= a7) goto L_150; /* 014a: bgeu a3, a7, 150 <rcUpdateTxDoneAmpdu2+0xf8> */
  goto L_28d; /* 014d: j 28d <rcUpdateTxDoneAmpdu2+0x235> */
L_150:;
  a8 = 0x8; /* 0150: movi.n a8, 8 */
  a7 = MEM8(a2 + 12); /* 0152: l8ui a7, a2, 12 */
  if (a8 >= a7) goto L_15c; /* 0155: bgeu a8, a7, 15c <rcUpdateTxDoneAmpdu2+0x104> */
  goto L_28d; /* 0158: j 28d <rcUpdateTxDoneAmpdu2+0x235> */
  /* 015b: .byte 00 */
L_15c:;
  a7 = MEM8(a2 + 15); /* 015c: l8ui a7, a2, 15 */
  a8 = 0x40; /* 015f: movi.n a8, 64 */
  if (a8 >= a7) goto L_17a; /* 0161: bgeu a8, a7, 17a <rcUpdateTxDoneAmpdu2+0x122> */
  goto L_28d; /* 0164: j 28d <rcUpdateTxDoneAmpdu2+0x235> */
  /* 0167: .byte 00 */
L_168:;
  if (a7 == 0) goto L_17a; /* 0168: beqz.n a7, 17a <rcUpdateTxDoneAmpdu2+0x122> */
  a3 = 0x0; /* 016a: movi.n a3, 0 */
  MEM8(a2 + 12) = a3; /* 016c: s8i a3, a2, 12 */
  MEMW(); /* 016f: memw  */
  MEMW(); /* 0172: memw  */
  goto L_37a; /* 0175: j 37a <rcUpdateTxDoneAmpdu2+0x322> */
  /* 0178: .byte 00 */
  /* 0179: .byte 00 */
L_17a:;
  a10 = a2; /* 017a: mov.n a10, a2 */
  a6 = a6 << (7 & 31); /* 017c: slli a6, a6, 7 */
  a8 = (uint32_t)&TRC_AMPDU_PER_DOWN_THRESHOLD; /* 017f: l32r a8, 34 <rcUpdateTxDoneAmpdu2-0x24> (0 <rcUpdateTxDoneAmpdu2-0x58>) */ /* literal: GOT slot for TRC_AMPDU_PER_DOWN_THRESHOLD */
  TRC_AMPDU_PER_DOWN_THRESHOLD(a2, a3, a4, a5); /* call via literal slot */ /* 0182: callx8 a8 */
  /* 0185: quos a6, a6, a4 */ /* UNMODELED: a6 clobbered */
  a7 = a10; /* 0188: mov.n a7, a10 */
  if (a10 >= a6) goto L_195; /* 018a: bgeu a10, a6, 195 <rcUpdateTxDoneAmpdu2+0x13d> */
  a4 = 0x0; /* 018d: movi.n a4, 0 */
  MEM8(a2 + 15) = a4; /* 018f: s8i a4, a2, 15 */
  MEMW(); /* 0192: memw  */
L_195:;
  a6 = (uint32_t)&g_mesh_is_started; /* 0195: l32r a6, 8 <rcUpdateTxDoneAmpdu2-0x50> (0 <rcUpdateTxDoneAmpdu2-0x58>) */ /* literal @0x8: g_mesh_is_started */
  a4 = MEM8(a6 + 0); /* 0198: l8ui a4, a6, 0 */
  if (a4 == 0) goto L_1c5; /* 019b: beqz.n a4, 1c5 <rcUpdateTxDoneAmpdu2+0x16d> */
  a4 = (uint32_t)&g_mesh_is_root; /* 019d: l32r a4, c <rcUpdateTxDoneAmpdu2-0x4c> (0 <rcUpdateTxDoneAmpdu2-0x58>) */ /* literal @0xC: g_mesh_is_root */
  MEMW(); /* 01a0: memw  */
  a4 = MEM8(a4 + 0); /* 01a3: l8ui a4, a4, 0 */
  a4 = (a4 >> 0) & 0xFF; /* 01a6: extui a4, a4, 0, 8 */
  if (a4 != 0) goto L_1c5; /* 01a9: bnez.n a4, 1c5 <rcUpdateTxDoneAmpdu2+0x16d> */
  a4 = (uint32_t)&g_mesh_init_ps_type; /* 01ab: l32r a4, 10 <rcUpdateTxDoneAmpdu2-0x48> (0 <rcUpdateTxDoneAmpdu2-0x58>) */ /* literal @0x10: g_mesh_init_ps_type */
  a4 = MEM32(a4 + 0); /* 01ae: l32i.n a4, a4, 0 */
  if (a4 == 0) goto L_1c5; /* 01b0: beqz.n a4, 1c5 <rcUpdateTxDoneAmpdu2+0x16d> */
  a4 = (uint32_t)&g_osi_funcs_p; /* 01b2: l32r a4, 14 <rcUpdateTxDoneAmpdu2-0x44> (0 <rcUpdateTxDoneAmpdu2-0x58>) */ /* literal @0x14: g_osi_funcs_p */
  a4 = MEM32(a4 + 0); /* 01b5: l32i.n a4, a4, 0 */
  a10 = MEM32(a4 + 272); /* 01b7: l32i a10, a4, 0x110 */
  MEMW(); /* 01ba: memw  */
  ((int32_t(*)())a10)(a2, a3, a4, a5); /* 01bd: callx8 a10 */ /* indirect */
  a6 = a10; /* 01c0: mov.n a6, a10 */
  goto L_1d4; /* 01c2: j 1d4 <rcUpdateTxDoneAmpdu2+0x17c> */
L_1c5:;
  a4 = 0x3FF73C00; /* 01c5: l32r a4, 18 <rcUpdateTxDoneAmpdu2-0x40> (3ff73c00 <rcUpdatePhyMode+0x3ff73b94>) */ /* MMIO base */ @0x18
  MEMW(); /* 01c8: memw  */
  a9 = REG32(0x3FF73C00); /* 01cb: l32i.n a9, a4, 0 */ /* MMIO read: base 0x3FF73C00+0 */
  a4 = (uint32_t)&g_wifi_mac_time_delta; /* 01cd: l32r a4, 1c <rcUpdateTxDoneAmpdu2-0x3c> (0 <rcUpdateTxDoneAmpdu2-0x58>) */ /* literal @0x1C: g_wifi_mac_time_delta */
  a4 = MEM32(a4 + 0); /* 01d0: l32i.n a4, a4, 0 */
  a6 = a9 + a4; /* 01d2: add.n a6, a9, a4 */
L_1d4:;
  a4 = MEM32(a2 + 64); /* 01d4: l32i a4, a2, 64 */
  a11 = MEM32(a2 + 76); /* 01d7: l32i a11, a2, 76 */
  if (a4 == 0) goto L_37a; /* 01da: beqz a4, 37a <rcUpdateTxDoneAmpdu2+0x322> */
  a10 = a6; /* 01dd: mov.n a10, a6 */
  a8 = (uint32_t)&trc_calc_duration; /* 01df: l32r a8, 38 <rcUpdateTxDoneAmpdu2-0x20> (0 <rcUpdateTxDoneAmpdu2-0x58>) */ /* literal: GOT slot for trc_calc_duration */
  trc_calc_duration(a2, a3, a4, a5); /* call via literal slot */ /* 01e2: callx8 a8 */
  a8 = 0x1869F; /* 01e5: l32r a8, 20 <rcUpdateTxDoneAmpdu2-0x38> (1869f <rcUpdatePhyMode+0x18633>) */ @0x20
  if (a8 < a10) goto L_1f4; /* 01e8: bltu a8, a10, 1f4 <rcUpdateTxDoneAmpdu2+0x19c> */
  a8 = 0x1F3; /* 01eb: movi a8, 0x1f3 */
  if (a8 < a4) goto L_1f4; /* 01ee: bltu a8, a4, 1f4 <rcUpdateTxDoneAmpdu2+0x19c> */
  goto L_37a; /* 01f1: j 37a <rcUpdateTxDoneAmpdu2+0x322> */
L_1f4:;
  a8 = MEM32(a2 + 88); /* 01f4: l32i a8, a2, 88 */
  a8 = a8 + (1); /* 01f7: addi.n a8, a8, 1 */
  MEM32(a2 + 88) = a8; /* 01f9: s32i a8, a2, 88 */
  a8 = MEM32(a2 + 68); /* 01fc: l32i a8, a2, 68 */
  a8 = a8 << (7 & 31); /* 01ff: slli a8, a8, 7 */
  /* 0202: quou a8, a8, a4 */ /* UNMODELED: a8 clobbered */
  a4 = (a8 >> 0) & 0xFF; /* 0205: extui a4, a8, 0, 8 */
  a11 = MEM8(a2 + 30); /* 0208: l8ui a11, a2, 30 */
  MEM32(a2 + 76) = a6; /* 020b: s32i a6, a2, 76 */
  MEM8(a2 + 29) = a4; /* 020e: s8i a4, a2, 29 */
  MEMW(); /* 0211: memw  */
  if (a11 == 0) goto L_238; /* 0214: beqz.n a11, 238 <rcUpdateTxDoneAmpdu2+0x1e0> */
  a8 = (a8 >> 0) & 0xFF; /* 0216: extui a8, a8, 0, 8 */
  a4 = (a11 << 2) + a11; /* 0219: addx2 a4, a11, a11 */
  a4 = a4 + a8; /* 021c: add.n a4, a4, a8 */
  a4 = (int32_t)a4 >> (2 & 31); /* 021e: srai a4, a4, 2 */
  MEM8(a2 + 30) = a4; /* 0221: s8i a4, a2, 30 */
  MEMW(); /* 0224: memw  */
  /* 0227: maxu a10, a4, a11 */ /* UNMODELED: a10 clobbered */
  a8 = MEM8(a2 + 39); /* 022a: l8ui a8, a2, 39 */
  if (a10 >= a7) goto L_29c; /* 022d: bgeu a10, a7, 29c <rcUpdateTxDoneAmpdu2+0x244> */
  MEMW(); /* 0230: memw  */
  goto L_266; /* 0233: j 266 <rcUpdateTxDoneAmpdu2+0x20e> */
  /* 0236: .byte 00 */
  /* 0237: .byte 00 */
L_238:;
  a3 = 0x80; /* 0238: movi a3, 128 */
  a10 = (a7 << 2) + a7; /* 023b: addx2 a10, a7, a7 */
  a10 = a10 + a3; /* 023e: add.n a10, a10, a3 */
  a3 = a10 >> (2 & 31); /* 0240: srli a3, a10, 2 */
  a10 = (a10 >> 2) & 0xFF; /* 0243: extui a10, a10, 2, 8 */
  if (a10 < a4) goto L_24c; /* 0246: bltu a10, a4, 24c <rcUpdateTxDoneAmpdu2+0x1f4> */
  goto L_369; /* 0249: j 369 <rcUpdateTxDoneAmpdu2+0x311> */
L_24c:;
  a3 = (a3 >> 0) & 0xFF; /* 024c: extui a3, a3, 0, 8 */
  a8 = (a8 >> 0) & 0xFF; /* 024f: extui a8, a8, 0, 8 */
  a3 = a3 + a8; /* 0252: add.n a3, a3, a8 */
  a3 = (int32_t)a3 >> (1 & 31); /* 0254: srai a3, a3, 1 */
  MEM8(a2 + 30) = a3; /* 0257: s8i a3, a2, 30 */
  MEMW(); /* 025a: memw  */
  MEMW(); /* 025d: memw  */
  goto L_36f; /* 0260: j 36f <rcUpdateTxDoneAmpdu2+0x317> */
  /* 0263: .byte 00 */
  /* 0264: .byte 00 */
  /* 0265: .byte 00 */
L_266:;
  if (a8 == 0) goto L_276; /* 0266: beqz.n a8, 276 <rcUpdateTxDoneAmpdu2+0x21e> */
  a4 = MEM32(a2 + 92); /* 0268: l32i a4, a2, 92 */
  a7 = 0x3D08FF; /* 026b: l32r a7, 28 <rcUpdateTxDoneAmpdu2-0x30> (3d08ff <rcUpdatePhyMode+0x3d0893>) */ @0x28
  if (a7 < a4) goto L_276; /* 026e: bltu a7, a4, 276 <rcUpdateTxDoneAmpdu2+0x21e> */
  a4 = a4 + a4; /* 0271: add.n a4, a4, a4 */
  MEM32(a2 + 92) = a4; /* 0273: s32i a4, a2, 92 */
L_276:;
  a10 = a6; /* 0276: mov.n a10, a6 */
  a11 = MEM32(a2 + 80); /* 0278: l32i a11, a2, 80 */
  MEMW(); /* 027b: memw  */
  a8 = (uint32_t)&trc_calc_duration; /* 027e: l32r a8, 3c <rcUpdateTxDoneAmpdu2-0x1c> (0 <rcUpdateTxDoneAmpdu2-0x58>) */ /* literal: GOT slot for trc_calc_duration */
  trc_calc_duration(a2, a3, a4, a5); /* call via literal slot */ /* 0281: callx8 a8 */
  a4 = 0x186A0; /* 0284: l32r a4, 24 <rcUpdateTxDoneAmpdu2-0x34> (186a0 <rcUpdatePhyMode+0x18634>) */ @0x24
  if (a4 < a10) goto L_28d; /* 0287: bltu a4, a10, 28d <rcUpdateTxDoneAmpdu2+0x235> */
  goto L_36f; /* 028a: j 36f <rcUpdateTxDoneAmpdu2+0x317> */
L_28d:;
  a12 = a5; /* 028d: mov.n a12, a5 */
  a11 = a3; /* 028f: mov.n a11, a3 */
  a10 = a2; /* 0291: mov.n a10, a2 */
  a8 = (uint32_t)&rcAmpduLowerRate; /* 0293: l32r a8, 40 <rcUpdateTxDoneAmpdu2-0x18> (0 <rcUpdateTxDoneAmpdu2-0x58>) */ /* literal: GOT slot for rcAmpduLowerRate */
  rcAmpduLowerRate(a2, a3, a4, a5); /* call via literal slot */ /* 0296: callx8 a8 */
  goto L_37a; /* 0299: j 37a <rcUpdateTxDoneAmpdu2+0x322> */
L_29c:;
  if (a8 == 0) goto L_2b4; /* 029c: beqz.n a8, 2b4 <rcUpdateTxDoneAmpdu2+0x25c> */
  a3 = 0x0; /* 029e: movi.n a3, 0 */
  MEM8(a2 + 39) = a3; /* 02a0: s8i a3, a2, 39 */
  MEMW(); /* 02a3: memw  */
  a3 = 0x7A120; /* 02a6: l32r a3, 2c <rcUpdateTxDoneAmpdu2-0x2c> (7a120 <rcUpdatePhyMode+0x7a0b4>) */ @0x2C
  MEM32(a2 + 92) = a3; /* 02a9: s32i a3, a2, 92 */
  MEMW(); /* 02ac: memw  */
  goto L_36f; /* 02af: j 36f <rcUpdateTxDoneAmpdu2+0x317> */
  /* 02b2: .byte 00 */
  /* 02b3: .byte 00 */
L_2b4:;
  a5 = MEM8(a2 + 4); /* 02b4: l8ui a5, a2, 4 */
  if (a5 != a3) goto L_2bd; /* 02b7: bne a5, a3, 2bd <rcUpdateTxDoneAmpdu2+0x265> */
  goto L_36f; /* 02ba: j 36f <rcUpdateTxDoneAmpdu2+0x317> */
L_2bd:;
  a10 = a2; /* 02bd: mov.n a10, a2 */
  MEM32(a1 + 0) = a11; /* 02bf: s32i.n a11, a1, 0 */
  MEMW(); /* 02c1: memw  */
  a8 = (uint32_t)&TRC_AMPDU_PER_UP_THRESHOLD; /* 02c4: l32r a8, 44 <rcUpdateTxDoneAmpdu2-0x14> (0 <rcUpdateTxDoneAmpdu2-0x58>) */ /* literal: GOT slot for TRC_AMPDU_PER_UP_THRESHOLD */
  TRC_AMPDU_PER_UP_THRESHOLD(a2, a3, a4, a5); /* call via literal slot */ /* 02c7: callx8 a8 */
  a11 = MEM32(a1 + 0); /* 02ca: l32i.n a11, a1, 0 */
  /* 02cc: minu a4, a4, a11 */ /* UNMODELED: a4 clobbered */
  if (a10 < a4) goto L_2d5; /* 02cf: bltu a10, a4, 2d5 <rcUpdateTxDoneAmpdu2+0x27d> */
  goto L_36f; /* 02d2: j 36f <rcUpdateTxDoneAmpdu2+0x317> */
L_2d5:;
  a10 = a6; /* 02d5: mov.n a10, a6 */
  a11 = MEM32(a2 + 84); /* 02d7: l32i a11, a2, 84 */
  a8 = (uint32_t)&trc_calc_duration; /* 02da: l32r a8, 48 <rcUpdateTxDoneAmpdu2-0x10> (0 <rcUpdateTxDoneAmpdu2-0x58>) */ /* literal: GOT slot for trc_calc_duration */
  trc_calc_duration(a2, a3, a4, a5); /* call via literal slot */ /* 02dd: callx8 a8 */
  a4 = MEM32(a2 + 92); /* 02e0: l32i a4, a2, 92 */
  if (a4 < a10) goto L_2e9; /* 02e3: bltu a4, a10, 2e9 <rcUpdateTxDoneAmpdu2+0x291> */
  goto L_36f; /* 02e6: j 36f <rcUpdateTxDoneAmpdu2+0x317> */
L_2e9:;
  a5 = (uint32_t)&g_mesh_is_started; /* 02e9: l32r a5, 8 <rcUpdateTxDoneAmpdu2-0x50> (0 <rcUpdateTxDoneAmpdu2-0x58>) */ /* literal @0x8: g_mesh_is_started */
  a4 = MEM8(a5 + 0); /* 02ec: l8ui a4, a5, 0 */
  if (a4 == 0) goto L_315; /* 02ef: beqz.n a4, 315 <rcUpdateTxDoneAmpdu2+0x2bd> */
  a4 = (uint32_t)&g_mesh_is_root; /* 02f1: l32r a4, c <rcUpdateTxDoneAmpdu2-0x4c> (0 <rcUpdateTxDoneAmpdu2-0x58>) */ /* literal @0xC: g_mesh_is_root */
  MEMW(); /* 02f4: memw  */
  a4 = MEM8(a4 + 0); /* 02f7: l8ui a4, a4, 0 */
  a4 = (a4 >> 0) & 0xFF; /* 02fa: extui a4, a4, 0, 8 */
  if (a4 != 0) goto L_315; /* 02fd: bnez.n a4, 315 <rcUpdateTxDoneAmpdu2+0x2bd> */
  a4 = (uint32_t)&g_mesh_init_ps_type; /* 02ff: l32r a4, 10 <rcUpdateTxDoneAmpdu2-0x48> (0 <rcUpdateTxDoneAmpdu2-0x58>) */ /* literal @0x10: g_mesh_init_ps_type */
  a4 = MEM32(a4 + 0); /* 0302: l32i.n a4, a4, 0 */
  if (a4 == 0) goto L_315; /* 0304: beqz.n a4, 315 <rcUpdateTxDoneAmpdu2+0x2bd> */
  a4 = (uint32_t)&g_osi_funcs_p; /* 0306: l32r a4, 14 <rcUpdateTxDoneAmpdu2-0x44> (0 <rcUpdateTxDoneAmpdu2-0x58>) */ /* literal @0x14: g_osi_funcs_p */
  a4 = MEM32(a4 + 0); /* 0309: l32i.n a4, a4, 0 */
  a10 = MEM32(a4 + 272); /* 030b: l32i a10, a4, 0x110 */
  ((int32_t(*)())a10)(a2, a3, a4, a5); /* 030e: callx8 a10 */ /* indirect */
  goto L_324; /* 0311: j 324 <rcUpdateTxDoneAmpdu2+0x2cc> */
  /* 0314: .byte 00 */
L_315:;
  a4 = 0x3FF73C00; /* 0315: l32r a4, 18 <rcUpdateTxDoneAmpdu2-0x40> (3ff73c00 <rcUpdatePhyMode+0x3ff73b94>) */ /* MMIO base */ @0x18
  MEMW(); /* 0318: memw  */
  a10 = REG32(0x3FF73C00); /* 031b: l32i.n a10, a4, 0 */ /* MMIO read: base 0x3FF73C00+0 */
  a4 = (uint32_t)&g_wifi_mac_time_delta; /* 031d: l32r a4, 1c <rcUpdateTxDoneAmpdu2-0x3c> (0 <rcUpdateTxDoneAmpdu2-0x58>) */ /* literal @0x1C: g_wifi_mac_time_delta */
  a4 = MEM32(a4 + 0); /* 0320: l32i.n a4, a4, 0 */
  a10 = a10 + a4; /* 0322: add.n a10, a10, a4 */
L_324:;
  a4 = 0x0; /* 0324: movi.n a4, 0 */
  a3 = a3 + (-1); /* 0326: addi.n a3, a3, -1 */
  MEM8(a2 + 12) = a4; /* 0328: s8i a4, a2, 12 */
  MEMW(); /* 032b: memw  */
  a3 = (a3 >> 0) & 0xFF; /* 032e: extui a3, a3, 0, 8 */
  a3 = (a3 << 2) + a3; /* 0331: addx2 a3, a3, a3 */
  a4 = MEM32(a2 + 112); /* 0334: l32i a4, a2, 112 */
  a3 = (a3 << 4) + a4; /* 0337: addx4 a3, a3, a4 */
  MEM32(a2 + 84) = a10; /* 033a: s32i a10, a2, 84 */
  a10 = MEM8(a3 + 0); /* 033d: l8ui a10, a3, 0 */
  a3 = 0x1; /* 0340: movi.n a3, 1 */
  MEM8(a2 + 13) = a10; /* 0342: s8i a10, a2, 13 */
  MEM8(a2 + 39) = a3; /* 0345: s8i a3, a2, 39 */
  MEMW(); /* 0348: memw  */
  MEMW(); /* 034b: memw  */
  a8 = (uint32_t)&rx11NRate2AMPDULimit; /* 034e: l32r a8, 4c <rcUpdateTxDoneAmpdu2-0xc> (0 <rcUpdateTxDoneAmpdu2-0x58>) */ /* literal: GOT slot for rx11NRate2AMPDULimit */
  rx11NRate2AMPDULimit(a2, a3, a4, a5); /* call via literal slot */ /* 0351: callx8 a8 */
  a11 = a10; /* 0354: mov.n a11, a10 */
  a10 = a2; /* 0356: mov.n a10, a2 */
  a8 = (uint32_t)&rcSetTxAmpduLimit; /* 0358: l32r a8, 50 <rcUpdateTxDoneAmpdu2-0x8> (0 <rcUpdateTxDoneAmpdu2-0x58>) */ /* literal: GOT slot for rcSetTxAmpduLimit */
  rcSetTxAmpduLimit(a2, a3, a4, a5); /* call via literal slot */ /* 035b: callx8 a8 */
  a10 = a2; /* 035e: mov.n a10, a2 */
  a8 = (uint32_t)&rcClearCurAMPDUSched; /* 0360: l32r a8, 54 <rcUpdateTxDoneAmpdu2-0x4> (0 <rcUpdateTxDoneAmpdu2-0x58>) */ /* literal: GOT slot for rcClearCurAMPDUSched */
  rcClearCurAMPDUSched(a2, a3, a4, a5); /* call via literal slot */ /* 0363: callx8 a8 */
  goto L_37a; /* 0366: j 37a <rcUpdateTxDoneAmpdu2+0x322> */
L_369:;
  MEM8(a2 + 30) = a10; /* 0369: s8i a10, a2, 30 */
  MEMW(); /* 036c: memw  */
L_36f:;
  a3 = 0x0; /* 036f: movi.n a3, 0 */
  MEM32(a2 + 68) = a3; /* 0371: s32i a3, a2, 68 */
  MEM32(a2 + 64) = a3; /* 0374: s32i a3, a2, 64 */
  MEM32(a2 + 72) = a3; /* 0377: s32i a3, a2, 72 */
L_37a:;
  MEMW(); /* 037a: memw  */
  return (int32_t)a2; /* 037d: retw.n  */
}

/* rcUpdateRate @ trc.o 00000050 size 509B bind GLOBAL
 * Calls: TRC_PER_IS_GOOD, rcClearCurSched, rcLowerSched, rcUpSched, rssi_margin, trc_calc_duration | Data refs: TRC_PER_IS_GOOD, g_mesh_init_ps_type, g_mesh_is_root, g_mesh_is_started, g_osi_funcs_p, g_wifi_mac_time_delta, rcClearCurSched, rcLowerSched, rcUpSched, rssi_margin, trc_calc_duration, trc_ctl
 *   MMIO: 0x3FF73C00
 *   funcdb v3: 6 call(s), 12 ref(s); disasm: 9 call(s), 12 data ref(s)
 * Fidelity: medium - 188 instr, 35 branches, 2 indirect; flow + direct calls mapped, GOT-indirects enumerated (verified against section disasm) */
int32_t rcUpdateRate(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.rcUpdateRate; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_50:;
  /* 0050: entry a1, 48 */
  a3 = (uint32_t)&g_mesh_is_started; /* 0053: l32r a3, 0 <rcUpdateRate-0x50> (0 <rcUpdateRate-0x50>) */ /* literal @0x0: g_mesh_is_started */
  a3 = MEM8(a3 + 0); /* 0056: l8ui a3, a3, 0 */
  if (a3 == 0) goto L_81; /* 0059: beqz.n a3, 81 <rcUpdateRate+0x31> */
  a3 = (uint32_t)&g_mesh_is_root; /* 005b: l32r a3, 4 <rcUpdateRate-0x4c> (0 <rcUpdateRate-0x50>) */ /* literal @0x4: g_mesh_is_root */
  MEMW(); /* 005e: memw  */
  a3 = MEM8(a3 + 0); /* 0061: l8ui a3, a3, 0 */
  a3 = (a3 >> 0) & 0xFF; /* 0064: extui a3, a3, 0, 8 */
  if (a3 != 0) goto L_81; /* 0067: bnez.n a3, 81 <rcUpdateRate+0x31> */
  a3 = (uint32_t)&g_mesh_init_ps_type; /* 0069: l32r a3, 8 <rcUpdateRate-0x48> (0 <rcUpdateRate-0x50>) */ /* literal @0x8: g_mesh_init_ps_type */
  a3 = MEM32(a3 + 0); /* 006c: l32i.n a3, a3, 0 */
  if (a3 == 0) goto L_81; /* 006e: beqz.n a3, 81 <rcUpdateRate+0x31> */
  a3 = (uint32_t)&g_osi_funcs_p; /* 0070: l32r a3, c <rcUpdateRate-0x44> (0 <rcUpdateRate-0x50>) */ /* literal @0xC: g_osi_funcs_p */
  a3 = MEM32(a3 + 0); /* 0073: l32i a3, a3, 0 */
  a10 = MEM32(a3 + 272); /* 0076: l32i a10, a3, 0x110 */
  ((int32_t(*)())a10)(a2, a3, a4, a5); /* 0079: callx8 a10 */ /* indirect */
  a4 = a10; /* 007c: mov.n a4, a10 */
  goto L_90; /* 007e: j 90 <rcUpdateRate+0x40> */
L_81:;
  a3 = 0x3FF73C00; /* 0081: l32r a3, 10 <rcUpdateRate-0x40> (3ff73c00 <rcUpdatePhyMode+0x3ff73b94>) */ /* MMIO base */ @0x10
  MEMW(); /* 0084: memw  */
  a4 = REG32(0x3FF73C00); /* 0087: l32i.n a4, a3, 0 */ /* MMIO read: base 0x3FF73C00+0 */
  a3 = (uint32_t)&g_wifi_mac_time_delta; /* 0089: l32r a3, 14 <rcUpdateRate-0x3c> (0 <rcUpdateRate-0x50>) */ /* literal @0x14: g_wifi_mac_time_delta */
  a3 = MEM32(a3 + 0); /* 008c: l32i.n a3, a3, 0 */
  a4 = a4 + a3; /* 008e: add.n a4, a4, a3 */
L_90:;
  a6 = MEM32(a2 + 40); /* 0090: l32i.n a6, a2, 40 */
  a3 = MEM32(a2 + 56); /* 0092: l32i.n a3, a2, 56 */
  if (a6 == 0) goto L_d8; /* 0094: beqz a6, d8 <rcUpdateRate+0x88> */
  a11 = a3; /* 0097: mov.n a11, a3 */
  a10 = a4; /* 0099: mov.n a10, a4 */
  a8 = (uint32_t)&trc_calc_duration; /* 009b: l32r a8, 2c <rcUpdateRate-0x24> (0 <rcUpdateRate-0x50>) */ /* literal: GOT slot for trc_calc_duration */
  trc_calc_duration(a2, a3, a4, a5); /* call via literal slot */ /* 009e: callx8 a8 */
  a5 = MEM32(a2 + 60); /* 00a1: l32i.n a5, a2, 60 */
  a7 = 0x63; /* 00a3: movi a7, 99 */
  if (a7 >= a5) goto L_d8; /* 00a6: bgeu a7, a5, d8 <rcUpdateRate+0x88> */
  a5 = 0x1E847; /* 00a9: l32r a5, 18 <rcUpdateRate-0x38> (1e847 <rcUpdatePhyMode+0x1e7db>) */ @0x18
  if (a5 >= a10) goto L_d8; /* 00ac: bgeu a5, a10, d8 <rcUpdateRate+0x88> */
  a3 = (uint32_t)&trc_ctl; /* 00af: l32r a3, 24 <rcUpdateRate-0x2c> (0 <rcUpdateRate-0x50>) */ /* literal @0x24: trc_ctl */
  a5 = MEM32(a3 + 0); /* 00b2: l32i.n a5, a3, 0 */
  a5 = a5 + (1); /* 00b4: addi.n a5, a5, 1 */
  MEM32(a3 + 0) = a5; /* 00b6: s32i.n a5, a3, 0 */
  a3 = MEM32(a2 + 44); /* 00b8: l32i.n a3, a2, 44 */
  a3 = a3 << (7 & 31); /* 00ba: slli a3, a3, 7 */
  /* 00bd: quou a3, a3, a6 */ /* UNMODELED: a3 clobbered */
  a6 = (a3 >> 0) & 0xFF; /* 00c0: extui a6, a3, 0, 8 */
  a7 = MEM8(a2 + 28); /* 00c3: l8ui a7, a2, 28 */
  MEM32(a2 + 56) = a4; /* 00c6: s32i.n a4, a2, 56 */
  MEM8(a2 + 27) = a6; /* 00c8: s8i a6, a2, 27 */
  MEMW(); /* 00cb: memw  */
  if (a7 != 0) goto L_14a; /* 00ce: bnez a7, 14a <rcUpdateRate+0xfa> */
  MEMW(); /* 00d1: memw  */
  goto L_176; /* 00d4: j 176 <rcUpdateRate+0x126> */
  /* 00d7: .byte 00 */
L_d8:;
  a4 = MEM32(a2 + 76); /* 00d8: l32i a4, a2, 76 */
  a11 = a3; /* 00db: mov.n a11, a3 */
  a10 = a4; /* 00dd: mov.n a10, a4 */
  a8 = (uint32_t)&trc_calc_duration; /* 00df: l32r a8, 30 <rcUpdateRate-0x20> (0 <rcUpdateRate-0x50>) */ /* literal: GOT slot for trc_calc_duration */
  trc_calc_duration(a2, a3, a4, a5); /* call via literal slot */ /* 00e2: callx8 a8 */
  a3 = MEM8(a2 + 14); /* 00e5: l8ui a3, a2, 14 */
  if (a3 == 2) goto L_ee; /* 00e8: beqi a3, 2, ee <rcUpdateRate+0x9e> */
  goto L_248; /* 00eb: j 248 <rcUpdateRate+0x1f8> */
L_ee:;
  a3 = 0x1E847; /* 00ee: l32r a3, 18 <rcUpdateRate-0x38> (1e847 <rcUpdatePhyMode+0x1e7db>) */ @0x18
  if (a3 < a10) goto L_f7; /* 00f1: bltu a3, a10, f7 <rcUpdateRate+0xa7> */
  goto L_248; /* 00f4: j 248 <rcUpdateRate+0x1f8> */
L_f7:;
  a10 = a2; /* 00f7: mov.n a10, a2 */
  a3 = MEM32(a2 + 96); /* 00f9: l32i a3, a2, 96 */
  a3 = MEM8(a3 + 10); /* 00fc: l8ui a3, a3, 10 */
  MEM32(a2 + 56) = a4; /* 00ff: s32i.n a4, a2, 56 */
  a4 = 0x7A120; /* 0101: l32r a4, 20 <rcUpdateRate-0x30> (7a120 <rcUpdatePhyMode+0x7a0b4>) */ @0x20
  MEM32(a2 + 92) = a4; /* 0104: s32i a4, a2, 92 */
  MEMW(); /* 0107: memw  */
  a8 = (uint32_t)&rcClearCurSched; /* 010a: l32r a8, 34 <rcUpdateRate-0x1c> (0 <rcUpdateRate-0x50>) */ /* literal: GOT slot for rcClearCurSched */
  rcClearCurSched(a2, a3, a4, a5); /* call via literal slot */ /* 010d: callx8 a8 */
  a10 = MEM8(a2 + 13); /* 0110: l8ui a10, a2, 13 */
  a5 = MEM32(a2 + 116); /* 0113: l32i a5, a2, 116 */
  a4 = MEM32(a2 + 112); /* 0116: l32i a4, a2, 112 */
  ((int32_t(*)())a5)(a2, a3, a4, a5); /* 0119: callx8 a5 */ /* indirect */
  a10 = (a10 >> 0) & 0xFFFF; /* 011c: extui a10, a10, 0, 16 */
  a10 = (a10 << 2) + a10; /* 011f: addx2 a10, a10, a10 */
  a10 = (a10 << 4) + a4; /* 0122: addx4 a10, a10, a4 */
  MEM32(a2 + 96) = a10; /* 0125: s32i a10, a2, 96 */
  a4 = MEM8(a10 + 10); /* 0128: l8ui a4, a10, 10 */
  if (a3 >= a4) goto L_139; /* 012b: bgeu a3, a4, 139 <rcUpdateRate+0xe9> */
  a3 = MEM32(a2 + 76); /* 012e: l32i a3, a2, 76 */
  MEM32(a2 + 48) = a3; /* 0131: s32i.n a3, a2, 48 */
  MEMW(); /* 0133: memw  */
  goto L_240; /* 0136: j 240 <rcUpdateRate+0x1f0> */
L_139:;
  if (a4 < a3) goto L_13f; /* 0139: bltu a4, a3, 13f <rcUpdateRate+0xef> */
  goto L_240; /* 013c: j 240 <rcUpdateRate+0x1f0> */
L_13f:;
  a3 = MEM32(a2 + 76); /* 013f: l32i a3, a2, 76 */
  MEM32(a2 + 52) = a3; /* 0142: s32i.n a3, a2, 52 */
  MEMW(); /* 0144: memw  */
  goto L_240; /* 0147: j 240 <rcUpdateRate+0x1f0> */
L_14a:;
  a3 = (a3 >> 0) & 0xFF; /* 014a: extui a3, a3, 0, 8 */
  a3 = a3 + a7; /* 014d: add.n a3, a3, a7 */
  a11 = MEM32(a2 + 52); /* 014f: l32i.n a11, a2, 52 */
  a3 = (int32_t)a3 >> (1 & 31); /* 0151: srai a3, a3, 1 */
  a10 = a4; /* 0154: mov.n a10, a4 */
  MEM8(a2 + 28) = a3; /* 0156: s8i a3, a2, 28 */
  MEMW(); /* 0159: memw  */
  MEMW(); /* 015c: memw  */
  a8 = (uint32_t)&trc_calc_duration; /* 015f: l32r a8, 38 <rcUpdateRate-0x18> (0 <rcUpdateRate-0x50>) */ /* literal: GOT slot for trc_calc_duration */
  trc_calc_duration(a2, a3, a4, a5); /* call via literal slot */ /* 0162: callx8 a8 */
  a7 = a10; /* 0165: mov.n a7, a10 */
  a11 = a3; /* 0167: mov.n a11, a3 */
  a10 = a2; /* 0169: mov.n a10, a2 */
  a8 = (uint32_t)&TRC_PER_IS_GOOD; /* 016b: l32r a8, 3c <rcUpdateRate-0x14> (0 <rcUpdateRate-0x50>) */ /* literal: GOT slot for TRC_PER_IS_GOOD */
  TRC_PER_IS_GOOD(a2, a3, a4, a5); /* call via literal slot */ /* 016e: callx8 a8 */
  if (a10 != 0) goto L_1ad; /* 0171: bnez.n a10, 1ad <rcUpdateRate+0x15d> */
  goto L_1c0; /* 0173: j 1c0 <rcUpdateRate+0x170> */
L_176:;
  a4 = MEM32(a2 + 96); /* 0176: l32i a4, a2, 96 */
  a8 = MEM8(a4 + 9); /* 0179: l8ui a8, a4, 9 */
  a4 = 0x80; /* 017c: movi a4, 128 */
  a8 = (a8 << 2) + a8; /* 017f: addx2 a8, a8, a8 */
  a8 = a8 + a4; /* 0182: add.n a8, a8, a4 */
  a4 = (int32_t)a8 >> (2 & 31); /* 0184: srai a4, a8, 2 */
  a8 = (a8 >> 2) & 0xFF; /* 0187: extui a8, a8, 2, 8 */
  if (a8 < a6) goto L_199; /* 018a: bltu a8, a6, 199 <rcUpdateRate+0x149> */
  MEM8(a2 + 28) = a8; /* 018d: s8i a8, a2, 28 */
  MEMW(); /* 0190: memw  */
  MEMW(); /* 0193: memw  */
  goto L_240; /* 0196: j 240 <rcUpdateRate+0x1f0> */
L_199:;
  a3 = (a3 >> 0) & 0xFF; /* 0199: extui a3, a3, 0, 8 */
  a3 = a3 + a4; /* 019c: add.n a3, a3, a4 */
  a3 = (int32_t)a3 >> (1 & 31); /* 019e: srai a3, a3, 1 */
  MEM8(a2 + 28) = a3; /* 01a1: s8i a3, a2, 28 */
  MEMW(); /* 01a4: memw  */
  MEMW(); /* 01a7: memw  */
  goto L_240; /* 01aa: j 240 <rcUpdateRate+0x1f0> */
L_1ad:;
  a6 = MEM32(a2 + 92); /* 01ad: l32i a6, a2, 92 */
  if (a6 >= a7) goto L_1c0; /* 01b0: bgeu a6, a7, 1c0 <rcUpdateRate+0x170> */
  a10 = a2 | a2; /* 01b3: or a10, a2, a2 */
  a8 = (uint32_t)&rcUpSched; /* 01b6: l32r a8, 40 <rcUpdateRate-0x10> (0 <rcUpdateRate-0x50>) */ /* literal: GOT slot for rcUpSched */
  rcUpSched(a2, a3, a4, a5); /* call via literal slot */ /* 01b9: callx8 a8 */
  goto L_240; /* 01bc: j 240 <rcUpdateRate+0x1f0> */
  /* 01bf: .byte 00 */
L_1c0:;
  a6 = MEM32(a2 + 96); /* 01c0: l32i a6, a2, 96 */
  a8 = MEM8(a6 + 11); /* 01c3: l8ui a8, a6, 11 */
  a9 = (a8 >> 0) & 0x1; /* 01c6: extui a9, a8, 0, 1 */
  if (a9 != 0) goto L_1d1; /* 01c9: bnez.n a9, 1d1 <rcUpdateRate+0x181> */
  a5 = (a5 >> 0) & 0x3; /* 01cb: extui a5, a5, 0, 2 */
  if (a5 != 0) goto L_240; /* 01ce: bnez a5, 240 <rcUpdateRate+0x1f0> */
L_1d1:;
  a11 = MEM8(a6 + 0); /* 01d1: l8ui a11, a6, 0 */
  a10 = MEM8(a2 + 1); /* 01d4: l8ui a10, a2, 1 */
  MEM32(a1 + 0) = a8; /* 01d7: s32i.n a8, a1, 0 */
  MEM32(a1 + 4) = a9; /* 01d9: s32i.n a9, a1, 4 */
  MEMW(); /* 01db: memw  */
  a8 = (uint32_t)&rssi_margin; /* 01de: l32r a8, 44 <rcUpdateRate-0xc> (0 <rcUpdateRate-0x50>) */ /* literal: GOT slot for rssi_margin */
  rssi_margin(a2, a3, a4, a5); /* call via literal slot */ /* 01e1: callx8 a8 */
  a10 = (a10 >> 1) & 0xFF; /* 01e4: extui a10, a10, 1, 8 */
  a5 = MEM8(a6 + 9); /* 01e7: l8ui a5, a6, 9 */
  a5 = a5 - a10; /* 01ea: sub a5, a5, a10 */
  a8 = MEM32(a1 + 0); /* 01ed: l32i.n a8, a1, 0 */
  a9 = MEM32(a1 + 4); /* 01ef: l32i.n a9, a1, 4 */
  if (a3 >= a5) goto L_21d; /* 01f1: bge a3, a5, 21d <rcUpdateRate+0x1cd> */
  if (a9 == 0) goto L_204; /* 01f4: beqz.n a9, 204 <rcUpdateRate+0x1b4> */
  a3 = MEM32(a2 + 92); /* 01f6: l32i a3, a2, 92 */
  a5 = 0x3D08FF; /* 01f9: l32r a5, 28 <rcUpdateRate-0x28> (3d08ff <rcUpdatePhyMode+0x3d0893>) */ @0x28
  if (a5 < a3) goto L_204; /* 01fc: bltu a5, a3, 204 <rcUpdateRate+0x1b4> */
  a3 = a3 + a3; /* 01ff: add.n a3, a3, a3 */
  MEM32(a2 + 92) = a3; /* 0201: s32i a3, a2, 92 */
L_204:;
  a10 = a4; /* 0204: mov.n a10, a4 */
  a11 = MEM32(a2 + 48); /* 0206: l32i.n a11, a2, 48 */
  MEMW(); /* 0208: memw  */
  a8 = (uint32_t)&trc_calc_duration; /* 020b: l32r a8, 48 <rcUpdateRate-0x8> (0 <rcUpdateRate-0x50>) */ /* literal: GOT slot for trc_calc_duration */
  trc_calc_duration(a2, a3, a4, a5); /* call via literal slot */ /* 020e: callx8 a8 */
  a3 = 0x1E848; /* 0211: l32r a3, 1c <rcUpdateRate-0x34> (1e848 <rcUpdatePhyMode+0x1e7dc>) */ @0x1C
  if (a3 >= a7) goto L_240; /* 0214: bgeu a3, a7, 240 <rcUpdateRate+0x1f0> */
  if (a3 < a10) goto L_236; /* 0217: bltu a3, a10, 236 <rcUpdateRate+0x1e6> */
  goto L_240; /* 021a: j 240 <rcUpdateRate+0x1f0> */
L_21d:;
  if (a9 == 0) goto L_240; /* 021d: beqz.n a9, 240 <rcUpdateRate+0x1f0> */
  a3 = 0xFFFFFFFE; /* 021f: movi.n a3, -2 */
  a8 = a8 & a3; /* 0221: and a8, a8, a3 */
  a3 = 0x7A120; /* 0224: l32r a3, 20 <rcUpdateRate-0x30> (7a120 <rcUpdatePhyMode+0x7a0b4>) */ @0x20
  MEM8(a6 + 11) = a8; /* 0227: s8i a8, a6, 11 */
  MEMW(); /* 022a: memw  */
  MEM32(a2 + 92) = a3; /* 022d: s32i a3, a2, 92 */
  MEMW(); /* 0230: memw  */
  goto L_240; /* 0233: j 240 <rcUpdateRate+0x1f0> */
L_236:;
  a11 = 0x1; /* 0236: movi.n a11, 1 */
  a10 = a2; /* 0238: mov.n a10, a2 */
  a8 = (uint32_t)&rcLowerSched; /* 023a: l32r a8, 4c <rcUpdateRate-0x4> (0 <rcUpdateRate-0x50>) */ /* literal: GOT slot for rcLowerSched */
  rcLowerSched(a2, a3, a4, a5); /* call via literal slot */ /* 023d: callx8 a8 */
L_240:;
  a3 = 0x0; /* 0240: movi.n a3, 0 */
  MEM32(a2 + 44) = a3; /* 0242: s32i.n a3, a2, 44 */
  MEM32(a2 + 40) = a3; /* 0244: s32i.n a3, a2, 40 */
  MEM32(a2 + 60) = a3; /* 0246: s32i.n a3, a2, 60 */
L_248:;
  MEMW(); /* 0248: memw  */
  return (int32_t)a2; /* 024b: retw.n  */
}

/* rcGetSched @ trc.o 00000020 size 206B bind GLOBAL
 * Calls: rcUpdateRate[got], wl_is_ap_no_lr[got] | Data refs: rcUpdateRate, rcLoRaSchedTbl, rc11BSchedTbl, wl_is_ap_no_lr, g_wifi_nvs, BasicOFDMSched
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 2 call(s), 6 data ref(s)
 * Fidelity: medium - 78 instr, 23 branches, calls resolved */
int32_t rcGetSched(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .wifi0iram.10; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_20:;
  /* 0020: entry a1, 32 */
  a10 = a2; /* 0023: mov.n a10, a2 */
  if (a2 == 0) goto L_e9; /* 0025: beqz a2, e9 <rcGetSched+0xc9> */
  a9 = MEM32(a3 + 0); /* 0028: l32i.n a9, a3, 0 */
  a11 = 0x2000008; /* 002a: l32r a11, 0 <rcGetSched-0x20> (2000008 <rcUpdatePhyMode+0x1ffff9c>) */ @0x0
  a11 = a9 & a11; /* 002d: and a11, a9, a11 */
  a8 = MEM8(a2 + 11); /* 0030: l8ui a8, a2, 11 */
  if (a11 != 8) goto L_60; /* 0033: bnei a11, 8, 60 <rcGetSched+0x40> */
  a11 = MEM32(a2 + 96); /* 0036: l32i a11, a2, 96 */
  MEM32(a3 + 28) = a11; /* 0039: s32i.n a11, a3, 28 */
  if (!((a8 >> 0) & 1)) goto L_48; /* 003b: bbci a8, 0, 48 <rcGetSched+0x28> */
  a8 = MEM8(a2 + 8); /* 003e: l8ui a8, a2, 8 */
  MEMW(); /* 0041: memw  */
  goto L_e3; /* 0044: j e3 <rcGetSched+0xc3> */
  /* 0047: .byte 00 */
L_48:;
  if (!((a9 >> 1) & 1)) goto L_51; /* 0048: bbci a9, 1, 51 <rcGetSched+0x31> */
  a8 = MEM32(a2 + 104); /* 004b: l32i a8, a2, 104 */
  goto L_dc; /* 004e: j dc <rcGetSched+0xbc> */
L_51:;
  a8 = ((int32_t)(a8 << (32 - (7 & 31)))) >> (32 - (7 & 31)); /* 0051: sext a8, a8, 7 */
  /* 0054: bltz a8, de <rcGetSched+0xbe> */ /* UNMODELED branch */
  a8 = (uint32_t)&rcUpdateRate; /* 0057: l32r a8, 18 <rcGetSched-0x8> (0 <rcGetSched-0x20>) */ /* literal: GOT slot for rcUpdateRate */
  rcUpdateRate(a2, a3, a4, a5); /* call via literal slot */ /* 005a: callx8 a8 */
  goto L_de; /* 005d: j de <rcGetSched+0xbe> */
L_60:;
  a11 = MEM32(a2 + 100); /* 0060: l32i a11, a2, 100 */
  MEM32(a3 + 28) = a11; /* 0063: s32i.n a11, a3, 28 */
  if (!((a8 >> 1) & 1)) goto L_71; /* 0065: bbci a8, 1, 71 <rcGetSched+0x51> */
  a8 = MEM8(a2 + 9); /* 0068: l8ui a8, a2, 9 */
  MEMW(); /* 006b: memw  */
  goto L_e3; /* 006e: j e3 <rcGetSched+0xc3> */
L_71:;
  a8 = ((int32_t)(a8 << (32 - (7 & 31)))) >> (32 - (7 & 31)); /* 0071: sext a8, a8, 7 */
  /* 0074: bgez a8, c1 <rcGetSched+0xa1> */ /* UNMODELED branch */
  a9 = 0x3; /* 0077: movi.n a9, 3 */
  a8 = MEM32(a3 + 16); /* 0079: l32i.n a8, a3, 16 */
  a9 = 0xC0000; /* 007b: slli a9, a9, 18 */
  if ((a8 & a9) != 0) goto L_b0; /* 007e: bany a8, a9, b0 <rcGetSched+0x90> */
  if (!((a8 >> 16) & 1)) goto L_8d; /* 0081: bbci a8, 16, 8d <rcGetSched+0x6d> */
L_84:;
  a8 = (uint32_t)&rcLoRaSchedTbl; /* 0084: l32r a8, 4 <rcGetSched-0x1c> (0 <rcGetSched-0x20>) */ /* literal @0x4: rcLoRaSchedTbl */
  goto L_dc; /* 0087: j dc <rcGetSched+0xbc> */
  /* 008a: .byte 00 */
  /* 008b: .byte 00 */
  /* 008c: .byte 00 */
L_8d:;
  if ((a8 >> 17) & 1) goto L_98; /* 008d: bbsi a8, 17, 98 <rcGetSched+0x78> */
L_90:;
  a8 = (uint32_t)&rc11BSchedTbl; /* 0090: l32r a8, 8 <rcGetSched-0x18> (0 <rcGetSched-0x20>) */ /* literal @0x8: rc11BSchedTbl */
  goto L_dc; /* 0093: j dc <rcGetSched+0xbc> */
  /* 0096: .byte 00 */
  /* 0097: .byte 00 */
L_98:;
  a8 = (uint32_t)&wl_is_ap_no_lr; /* 0098: l32r a8, 1c <rcGetSched-0x4> (0 <rcGetSched-0x20>) */ /* literal: GOT slot for wl_is_ap_no_lr */
  wl_is_ap_no_lr(a2, a3, a4, a5); /* call via literal slot */ /* 009b: callx8 a8 */
  if (a10 != 0) goto L_90; /* 009e: bnez a10, 90 <rcGetSched+0x70> */
  a8 = (uint32_t)&g_wifi_nvs; /* 00a1: l32r a8, c <rcGetSched-0x14> (0 <rcGetSched-0x20>) */ /* literal @0xC: g_wifi_nvs */
  a8 = MEM32(a8 + 0); /* 00a4: l32i.n a8, a8, 0 */
  a8 = a8 + ((0x400) << 8); /* 00a6: addmi a8, a8, 0x400 */
  a8 = MEM8(a8 + 161); /* 00a9: l8ui a8, a8, 161 */
  goto L_bb; /* 00ac: j bb <rcGetSched+0x9b> */
  /* 00af: .byte 00 */
L_b0:;
  a8 = (uint32_t)&g_wifi_nvs; /* 00b0: l32r a8, c <rcGetSched-0x14> (0 <rcGetSched-0x20>) */ /* literal @0xC: g_wifi_nvs */
  a8 = MEM32(a8 + 0); /* 00b3: l32i.n a8, a8, 0 */
  a8 = a8 + ((0x500) << 8); /* 00b5: addmi a8, a8, 0x500 */
  a8 = MEM8(a8 + 61); /* 00b8: l8ui a8, a8, 61 */
L_bb:;
  if (a8 != 0) goto L_84; /* 00bb: bnez a8, 84 <rcGetSched+0x64> */
  goto L_de; /* 00be: j de <rcGetSched+0xbe> */
L_c1:;
  a8 = 0x401; /* 00c1: movi a8, 0x401 */
  a8 = 0x200800; /* 00c4: slli a8, a8, 11 */
  if ((a9 & a8) == 0) goto L_de; /* 00c7: bnone a9, a8, de <rcGetSched+0xbe> */
  a8 = MEM8(a2 + 130); /* 00ca: l8ui a8, a2, 130 */
  if (a8 == 0) goto L_de; /* 00cd: beqz.n a8, de <rcGetSched+0xbe> */
  a8 = (uint32_t)&BasicOFDMSched; /* 00cf: l32r a8, 10 <rcGetSched-0x10> (0 <rcGetSched-0x20>) */ /* literal @0x10: BasicOFDMSched */
  MEM32(a3 + 28) = a8; /* 00d2: s32i.n a8, a3, 28 */
  a8 = MEM8(a2 + 135); /* 00d4: l8ui a8, a2, 135 */
  if (a8 == 0) goto L_de; /* 00d7: beqz.n a8, de <rcGetSched+0xbe> */
  a8 = (uint32_t)&rcLoRaSchedTbl; /* 00d9: l32r a8, 14 <rcGetSched-0xc> (0 <rcGetSched-0x20>) */ /* literal @0x14: rcLoRaSchedTbl */
L_dc:;
  MEM32(a3 + 28) = a8; /* 00dc: s32i.n a8, a3, 28 */
L_de:;
  a8 = MEM32(a3 + 28); /* 00de: l32i.n a8, a3, 28 */
  a8 = MEM8(a8 + 0); /* 00e0: l8ui a8, a8, 0 */
L_e3:;
  MEM8(a3 + 12) = a8; /* 00e3: s8i a8, a3, 12 */
  MEMW(); /* 00e6: memw  */
L_e9:;
  MEMW(); /* 00e9: memw  */
  return (int32_t)a2; /* 00ec: retw.n  */
}

/* rcReachRetryLimit @ trc.o 00000028 size 153B bind GLOBAL
 * Calls: wifi_assert, wifi_log | Data refs: .rodata.__FUNCTION__$0, .rodata.rcGetAmpduSched.str1.1, .rodata_wlog_error.12, .rodata_wlog_error.13, g_mesh_is_started, wifi_assert, wifi_log
 *   MMIO: none
 *   funcdb v3: 2 call(s), 7 ref(s); disasm: 4 call(s), 7 data ref(s)
 * Fidelity: medium - 58 instr, 9 branches, calls resolved */
int32_t rcReachRetryLimit(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.rcReachRetryLimit; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_28:;
  /* 0028: entry a1, 48 */
  if (a2 != 0) goto L_51; /* 002b: bnez.n a2, 51 <rcReachRetryLimit+0x29> */
  a13 = (uint32_t)&lit_rodata_wlog_error_12; /* 002d: l32r a13, 0 <rcReachRetryLimit-0x28> (0 <rcReachRetryLimit-0x28>) */ /* literal @0x0: .rodata_wlog_error.12 */
  a12 = 0x1; /* 0030: movi.n a12, 1 */
  a11 = 0x200; /* 0032: movi a11, 0x200 */
  a10 = 0x6; /* 0035: movi.n a10, 6 */
  a8 = (uint32_t)&wifi_log; /* 0037: l32r a8, 18 <rcReachRetryLimit-0x10> (0 <rcReachRetryLimit-0x28>) */ /* literal: GOT slot for wifi_log */
  wifi_log(a2, a3, a4, a5); /* call via literal slot */ /* 003a: callx8 a8 */
  a13 = 0xACD; /* 003d: l32r a13, 4 <rcReachRetryLimit-0x24> (acd <rcUpdatePhyMode+0xa61>) */ @0x4
  a10 = a2; /* 0040: mov.n a10, a2 */
  a12 = (uint32_t)&lit_rodata_FUNCTION_0; /* 0042: l32r a12, 8 <rcReachRetryLimit-0x20> (0 <rcReachRetryLimit-0x28>) */ /* literal @0x8: .rodata.__FUNCTION__$0 */
  a11 = (uint32_t)&lit_rodata_rcGetAmpduSched_str1_1; /* 0045: l32r a11, c <rcReachRetryLimit-0x1c> (0 <rcReachRetryLimit-0x28>) */ /* literal @0xC: .rodata.rcGetAmpduSched.str1.1 */
  a8 = (uint32_t)&wifi_assert; /* 0048: l32r a8, 1c <rcReachRetryLimit-0xc> (0 <rcReachRetryLimit-0x28>) */ /* literal: GOT slot for wifi_assert */
  wifi_assert(a2, a3, a4, a5); /* call via literal slot */ /* 004b: callx8 a8 */
  goto L_60; /* 004e: j 60 <rcReachRetryLimit+0x38> */
L_51:;
  a3 = MEM8(a2 + 5); /* 0051: l8ui a3, a2, 5 */
  if (a3 < 5) goto L_5e; /* 0054: bltui a3, 5, 5e <rcReachRetryLimit+0x36> */
  a8 = 0x1; /* 0057: movi.n a8, 1 */
  a3 = MEM32(a2 + 0); /* 0059: l32i.n a3, a2, 0 */
  if ((a3 >> 27) & 1) goto L_bd; /* 005b: bbsi a3, 27, bd <rcReachRetryLimit+0x95> */
L_5e:;
  a3 = MEM32(a2 + 28); /* 005e: l32i.n a3, a2, 28 */
L_60:;
  if (a3 != 0) goto L_98; /* 0060: bnez.n a3, 98 <rcReachRetryLimit+0x70> */
  a12 = 0x1; /* 0062: movi.n a12, 1 */
  a11 = 0x200; /* 0064: movi a11, 0x200 */
  a10 = 0x6; /* 0067: movi.n a10, 6 */
  a15 = MEM32(a2 + 4); /* 0069: l32i.n a15, a2, 4 */
  a15 = (a15 >> 0) & 0xF; /* 006b: extui a15, a15, 0, 4 */
  a14 = MEM32(a2 + 16); /* 006e: l32i.n a14, a2, 16 */
  a14 = (a14 >> 18) & 0x3; /* 0070: extui a14, a14, 18, 2 */
  a8 = MEM32(a2 + 0); /* 0073: l32i.n a8, a2, 0 */
  a13 = (uint32_t)&lit_rodata_wlog_error_13; /* 0075: l32r a13, 10 <rcReachRetryLimit-0x18> (0 <rcReachRetryLimit-0x28>) */ /* literal @0x10: .rodata_wlog_error.13 */
  MEM32(a1 + 0) = a8; /* 0078: s32i a8, a1, 0 */
  MEMW(); /* 007b: memw  */
  a8 = (uint32_t)&wifi_log; /* 007e: l32r a8, 20 <rcReachRetryLimit-0x8> (0 <rcReachRetryLimit-0x28>) */ /* literal: GOT slot for wifi_log */
  wifi_log(a2, a3, a4, a5); /* call via literal slot */ /* 0081: callx8 a8 */
  a13 = 0x15B; /* 0084: movi a13, 0x15b */
  a13 = 0xAD8; /* 0087: slli a13, a13, 3 */
  a10 = a3; /* 008a: mov.n a10, a3 */
  a12 = (uint32_t)&lit_rodata_FUNCTION_0; /* 008c: l32r a12, 8 <rcReachRetryLimit-0x20> (0 <rcReachRetryLimit-0x28>) */ /* literal @0x8: .rodata.__FUNCTION__$0 */
  a11 = (uint32_t)&lit_rodata_rcGetAmpduSched_str1_1; /* 008f: l32r a11, c <rcReachRetryLimit-0x1c> (0 <rcReachRetryLimit-0x28>) */ /* literal @0xC: .rodata.rcGetAmpduSched.str1.1 */
  a8 = (uint32_t)&wifi_assert; /* 0092: l32r a8, 24 <rcReachRetryLimit-0x4> (0 <rcReachRetryLimit-0x28>) */ /* literal: GOT slot for wifi_assert */
  wifi_assert(a2, a3, a4, a5); /* call via literal slot */ /* 0095: callx8 a8 */
L_98:;
  a8 = 0x1; /* 0098: movi.n a8, 1 */
  a9 = MEM8(a2 + 5); /* 009a: l8ui a9, a2, 5 */
  a2 = MEM8(a3 + 8); /* 009d: l8ui a2, a3, 8 */
  a3 = (uint32_t)&g_mesh_is_started; /* 00a0: l32r a3, 14 <rcReachRetryLimit-0x14> (0 <rcReachRetryLimit-0x28>) */ /* literal @0x14: g_mesh_is_started */
  a3 = MEM8(a3 + 0); /* 00a3: l8ui a3, a3, 0 */
  if (a3 == 0) goto L_b5; /* 00a6: beqz.n a3, b5 <rcReachRetryLimit+0x8d> */
  a3 = 0xB; /* 00a8: movi.n a3, 11 */
  /* 00aa: minu a2, a2, a3 */ /* UNMODELED: a2 clobbered */
  if (a9 >= a2) goto L_ba; /* 00ad: bgeu a9, a2, ba <rcReachRetryLimit+0x92> */
  a8 = 0x0; /* 00b0: movi.n a8, 0 */
  goto L_ba; /* 00b2: j ba <rcReachRetryLimit+0x92> */
L_b5:;
  if (a9 >= a2) goto L_ba; /* 00b5: bgeu a9, a2, ba <rcReachRetryLimit+0x92> */
  a8 = 0xB; /* 00b8: mov.n a8, a3 */
L_ba:;
  a8 = 0xB; /* 00ba: extui a8, a8, 0, 8 */
L_bd:;
  a2 = 0xB; /* 00bd: mov.n a2, a8 */
  return (int32_t)a2; /* 00bf: retw.n  */
}

/* rcAttach @ trc.o 00000034 size 94B bind GLOBAL
 * Calls: .text.rcBuildIndex[got], .text.rcBuildIndex[got], .text.rcBuildIndex[got], .text.rcBuildIndex[got], .text.rcBuildIndex[got], .text.rcBuildIndex[got] | Data refs: rc11BSchedTbl, rc11GSchedTbl, rc11NSchedTbl, rcLoRaSchedTbl, rcP2P11GSchedTbl, rcP2P11NSchedTbl, trc_ctl, .text.rcBuildIndex
 *   MMIO: none
 *   funcdb v3: 0 call(s), 7 ref(s); disasm: 6 call(s), 8 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t rcAttach(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.rcAttach; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_34:;
  /* 0034: entry a1, 32 */
  a8 = (uint32_t)&trc_ctl; /* 0037: l32r a8, 0 <rcAttach-0x34> (0 <rcAttach-0x34>) */ /* literal @0x0: trc_ctl */
  a9 = 0x0; /* 003a: movi.n a9, 0 */
  a11 = 0xE; /* 003c: movi.n a11, 14 */
  a10 = (uint32_t)&rc11NSchedTbl; /* 003e: l32r a10, 4 <rcAttach-0x30> (0 <rcAttach-0x34>) */ /* literal @0x4: rc11NSchedTbl */
  MEM32(a8 + 4) = a9; /* 0041: s32i.n a9, a8, 4 */
  MEM32(a8 + 8) = a9; /* 0043: s32i a9, a8, 8 */
  MEM32(a8 + 12) = a9; /* 0046: s32i a9, a8, 12 */
  MEM32(a8 + 20) = a9; /* 0049: s32i a9, a8, 20 */
  MEMW(); /* 004c: memw  */
  a8 = (uint32_t)&rcBuildIndex; /* 004f: l32r a8, 1c <rcAttach-0x18> (0 <rcAttach-0x34>) */ /* literal: GOT slot for .text.rcBuildIndex */
  rcBuildIndex(a2, a3, a4, a5); /* call via literal slot */ /* 0052: callx8 a8 */
  a11 = 0xA; /* 0055: movi a11, 10 */
  a10 = (uint32_t)&rcP2P11NSchedTbl; /* 0058: l32r a10, 8 <rcAttach-0x2c> (0 <rcAttach-0x34>) */ /* literal @0x8: rcP2P11NSchedTbl */
  a8 = (uint32_t)&rcBuildIndex; /* 005b: l32r a8, 20 <rcAttach-0x14> (0 <rcAttach-0x34>) */ /* literal: GOT slot for .text.rcBuildIndex */
  rcBuildIndex(a2, a3, a4, a5); /* call via literal slot */ /* 005e: callx8 a8 */
  a11 = 0xD; /* 0061: movi a11, 13 */
  a10 = (uint32_t)&rc11GSchedTbl; /* 0064: l32r a10, c <rcAttach-0x28> (0 <rcAttach-0x34>) */ /* literal @0xC: rc11GSchedTbl */
  a8 = (uint32_t)&rcBuildIndex; /* 0067: l32r a8, 24 <rcAttach-0x10> (0 <rcAttach-0x34>) */ /* literal: GOT slot for .text.rcBuildIndex */
  rcBuildIndex(a2, a3, a4, a5); /* call via literal slot */ /* 006a: callx8 a8 */
  a11 = 0x8; /* 006d: movi a11, 8 */
  a10 = (uint32_t)&rcP2P11GSchedTbl; /* 0070: l32r a10, 10 <rcAttach-0x24> (0 <rcAttach-0x34>) */ /* literal @0x10: rcP2P11GSchedTbl */
  a8 = (uint32_t)&rcBuildIndex; /* 0073: l32r a8, 28 <rcAttach-0xc> (0 <rcAttach-0x34>) */ /* literal: GOT slot for .text.rcBuildIndex */
  rcBuildIndex(a2, a3, a4, a5); /* call via literal slot */ /* 0076: callx8 a8 */
  a11 = 0x6; /* 0079: movi a11, 6 */
  a10 = (uint32_t)&rc11BSchedTbl; /* 007c: l32r a10, 14 <rcAttach-0x20> (0 <rcAttach-0x34>) */ /* literal @0x14: rc11BSchedTbl */
  a8 = (uint32_t)&rcBuildIndex; /* 007f: l32r a8, 2c <rcAttach-0x8> (0 <rcAttach-0x34>) */ /* literal: GOT slot for .text.rcBuildIndex */
  rcBuildIndex(a2, a3, a4, a5); /* call via literal slot */ /* 0082: callx8 a8 */
  a11 = 0x2; /* 0085: movi.n a11, 2 */
  a10 = (uint32_t)&rcLoRaSchedTbl; /* 0087: l32r a10, 18 <rcAttach-0x1c> (0 <rcAttach-0x34>) */ /* literal @0x18: rcLoRaSchedTbl */
  a8 = (uint32_t)&rcBuildIndex; /* 008a: l32r a8, 30 <rcAttach-0x4> (0 <rcAttach-0x34>) */ /* literal: GOT slot for .text.rcBuildIndex */
  rcBuildIndex(a2, a3, a4, a5); /* call via literal slot */ /* 008d: callx8 a8 */
  return (int32_t)a2; /* 0090: retw.n  */
}

/* trc_NeedRTS @ trc.o 00000010 size 138B bind GLOBAL
 * Calls: .rodata.trc_NeedRTS[tail] | Data refs: .rodata.trc_NeedRTS, lmacConfMib
 *   MMIO: none
 *   funcdb v3: 0 call(s), 2 ref(s); disasm: 1 call(s), 2 data ref(s)
 * Fidelity: low - 52 instr, 15 branches, jx computed tail dispatch (+0x4c jx a2 via .rodata.trc_NeedRTS); RTS threshold comparisons observed, case targets structural - need jump-table case decode to raise */
int32_t trc_NeedRTS(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.trc_NeedRTS; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_10:;
  /* 0010: entry a1, 32 */
  a8 = MEM32(a2 + 44); /* 0013: l32i.n a8, a2, 44 */
  a10 = MEM8(a8 + 12); /* 0015: l8ui a10, a8, 12 */
  a8 = MEM16(a2 + 20); /* 0018: l16ui a8, a2, 20 */
  a2 = MEM16(a2 + 22); /* 001b: l16ui a2, a2, 22 */
  a8 = a8 + a2; /* 001e: add.n a8, a8, a2 */
  if (a10 >= 6) goto L_50; /* 0020: bgeui a10, 6, 50 <trc_NeedRTS+0x40> */
  goto L_44; /* 0023: j 44 <trc_NeedRTS+0x34> */
L_26:;
  a2 = 0x1; /* 0026: movi.n a2, 1 */
  a11 = 0x2020480; /* 0028: l32r a11, 0 <trc_NeedRTS-0x10> (2020480 <rcUpdatePhyMode+0x2020414>) */ @0x0
  /* 002b: ssl a10 */ /* UNMODELED: a10 clobbered */
  /* 002e: sll a9, a2 */ /* UNMODELED: a9 clobbered */
  if ((a9 & a11) != 0) goto L_80; /* 0031: bany a9, a11, 80 <trc_NeedRTS+0x70> */
  a11 = 0x1010840; /* 0034: l32r a11, 4 <trc_NeedRTS-0xc> (1010840 <rcUpdatePhyMode+0x10107d4>) */ @0x4
  a9 = a9 & a11; /* 0037: and a9, a9, a11 */
  if (a9 != 0) goto L_6e; /* 003a: bnez.n a9, 6e <trc_NeedRTS+0x5e> */
  a11 = 0xF; /* 003c: movi.n a11, 15 */
  if (a10 != a11) goto L_88; /* 003e: bne a10, a11, 88 <trc_NeedRTS+0x78> */
  goto L_77; /* 0041: j 77 <trc_NeedRTS+0x67> */
L_44:;
  a2 = (uint32_t)&lit_rodata_trc_NeedRTS; /* 0044: l32r a2, 8 <trc_NeedRTS-0x8> (0 <trc_NeedRTS-0x10>) */ /* literal @0x8: .rodata.trc_NeedRTS */
  a2 = (a10 << 4) + a2; /* 0047: addx4 a2, a10, a2 */
  a2 = MEM32(a2 + 0); /* 004a: l32i.n a2, a2, 0 */
  /* 004c: jx a2 */ /* jx a2: computed tail jump; modeled as return */
  return (int32_t)a2;
  /* 004f: .byte 00 */
L_50:;
  a2 = a10 + (-6); /* 0050: addi a2, a10, -6 */
  a2 = (a2 >> 0) & 0xFF; /* 0053: extui a2, a2, 0, 8 */
  a9 = 0x13; /* 0056: movi.n a9, 19 */
  if (a9 >= a2) goto L_26; /* 0058: bgeu a9, a2, 26 <trc_NeedRTS+0x16> */
  goto L_88; /* 005b: j 88 <trc_NeedRTS+0x78> */
  a2 = 0x1; /* 005e: movi.n a2, 1 */
  a9 = 0x271; /* 0060: movi a9, 0x271 */
  goto L_90; /* 0063: j 90 <trc_NeedRTS+0x80> */
  a2 = 0x1; /* 0066: movi.n a2, 1 */
  a9 = 0x3E8; /* 0068: movi a9, 0x3e8 */
  goto L_90; /* 006b: j 90 <trc_NeedRTS+0x80> */
L_6e:;
  a2 = 0x1; /* 006e: movi.n a2, 1 */
  a9 = 0x2BC; /* 0070: movi a9, 0x2bc */
  goto L_90; /* 0073: j 90 <trc_NeedRTS+0x80> */
  /* 0076: .byte 00 */
L_77:;
  a10 = 0x41A; /* 0077: movi a10, 0x41a */
  if (a10 < a8) goto L_95; /* 007a: blt a10, a8, 95 <trc_NeedRTS+0x85> */
  goto L_93; /* 007d: j 93 <trc_NeedRTS+0x83> */
L_80:;
  a2 = 0x1; /* 0080: movi.n a2, 1 */
  a9 = 0x460; /* 0082: movi a9, 0x460 */
  goto L_90; /* 0085: j 90 <trc_NeedRTS+0x80> */
L_88:;
  a2 = (uint32_t)&lmacConfMib; /* 0088: l32r a2, c <trc_NeedRTS-0x4> (0 <trc_NeedRTS-0x10>) */ /* literal @0xC: lmacConfMib */
  a9 = MEM16(a2 + 22); /* 008b: l16ui a9, a2, 22 */
  a2 = 0x1; /* 008e: movi.n a2, 1 */
L_90:;
  if (a9 < a8) goto L_95; /* 0090: blt a9, a8, 95 <trc_NeedRTS+0x85> */
L_93:;
  a2 = 0x0; /* 0093: movi.n a2, 0 */
L_95:;
  a2 = 0x0; /* 0095: extui a2, a2, 0, 8 */
  return (int32_t)a2; /* 0098: retw.n  */
}

/* trc_onDisconnect @ trc.o 00000000 size 5B bind GLOBAL
 * Calls: none | Data refs: none
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t trc_onDisconnect(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.trc_onDisconnect; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_0:;
  /* 0000: entry a1, 32 */
  return (int32_t)a2; /* 0003: retw.n  */
}

/* trc_onScanStart @ trc.o 00000000 size 27B bind GLOBAL
 * Calls: none | Data refs: none
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t trc_onScanStart(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.trc_onScanStart; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_0:;
  /* 0000: entry a1, 32 */
  a8 = MEM8(a2 + 25); /* 0003: l8ui a8, a2, 25 */
  a9 = 0xFFFFFFFA; /* 0006: movi.n a9, -6 */
  a8 = a8 & a9; /* 0008: and a8, a8, a9 */
  a9 = 0x5; /* 000b: movi.n a9, 5 */
  a8 = a8 | a9; /* 000d: or a8, a8, a9 */
  MEM8(a2 + 25) = a8; /* 0010: s8i a8, a2, 25 */
  MEMW(); /* 0013: memw  */
  MEMW(); /* 0016: memw  */
  return (int32_t)a2; /* 0019: retw.n  */
}

/* trc_onScanDone @ trc.o 00000000 size 22B bind GLOBAL
 * Calls: none | Data refs: none
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t trc_onScanDone(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.trc_onScanDone; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_0:;
  /* 0000: entry a1, 32 */
  a8 = MEM8(a2 + 25); /* 0003: l8ui a8, a2, 25 */
  a9 = 0xFFFFFFFA; /* 0006: movi.n a9, -6 */
  a8 = a8 & a9; /* 0008: and a8, a8, a9 */
  MEM8(a2 + 25) = a8; /* 000b: s8i a8, a2, 25 */
  MEMW(); /* 000e: memw  */
  MEMW(); /* 0011: memw  */
  return (int32_t)a2; /* 0014: retw.n  */
}

/* trc_isAmpduOn @ trc.o 00000000 size 11B bind GLOBAL
 * Calls: none | Data refs: none
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t trc_isAmpduOn(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.trc_isAmpduOn; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_0:;
  /* 0000: entry a1, 32 */
  a2 = MEM8(a2 + 25); /* 0003: l8ui a2, a2, 25 */
  a2 = a2 >> (7 & 31); /* 0006: srli a2, a2, 7 */
  return (int32_t)a2; /* 0009: retw.n  */
}

/* trc_onPPTxDone @ trc.o 00000008 size 66B bind GLOBAL
 * Calls: .text.trcResumeAmpdu$constprop$0[got] | Data refs: trc_ctl, .text.trcResumeAmpdu$constprop$0
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 1 call(s), 2 data ref(s)
 * Fidelity: medium - 24 instr, 6 branches, calls resolved */
int32_t trc_onPPTxDone(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .wifiextrairam.14; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_8:;
  /* 0008: entry a1, 32 */
  a10 = a2; /* 000b: mov.n a10, a2 */
  if (a2 == 0) goto L_48; /* 000d: beqz.n a2, 48 <trc_onPPTxDone+0x40> */
  a8 = MEM8(a2 + 11); /* 000f: l8ui a8, a2, 11 */
  a9 = ((int32_t)(a8 << (32 - (7 & 31)))) >> (32 - (7 & 31)); /* 0012: sext a9, a8, 7 */
  /* 0015: bltz a9, 48 <trc_onPPTxDone+0x40> */ /* UNMODELED branch */
  if ((a8 >> 0) & 1) goto L_48; /* 0018: bbsi a8, 0, 48 <trc_onPPTxDone+0x40> */
  a8 = MEM8(a2 + 25); /* 001b: l8ui a8, a2, 25 */
  if (!((a8 >> 7) & 1)) goto L_48; /* 001e: bbci a8, 7, 48 <trc_onPPTxDone+0x40> */
  a8 = MEM32(a3 + 44); /* 0021: l32i.n a8, a3, 44 */
  a8 = MEM32(a8 + 4); /* 0023: l32i.n a8, a8, 4 */
  a8 = (a8 >> 0) & 0xF; /* 0025: extui a8, a8, 0, 4 */
  a8 = a2 + a8; /* 0028: add.n a8, a2, a8 */
  a8 = MEM8(a8 + 17); /* 002a: l8ui a8, a8, 17 */
  if (a8 != 1) goto L_48; /* 002d: bnei a8, 1, 48 <trc_onPPTxDone+0x40> */
  a8 = MEM32(a2 + 96); /* 0030: l32i a8, a2, 96 */
  a9 = MEM8(a8 + 10); /* 0033: l8ui a9, a8, 10 */
  a8 = (uint32_t)&trc_ctl; /* 0036: l32r a8, 0 <trc_onPPTxDone-0x8> (0 <trc_onPPTxDone-0x8>) */ /* literal @0x0: trc_ctl */
  a8 = MEM8(a8 + 25); /* 0039: l8ui a8, a8, 25 */
  a8 = a8 + (-1); /* 003c: addi a8, a8, -1 */
  if (a9 >= a8) goto L_48; /* 003f: bge a9, a8, 48 <trc_onPPTxDone+0x40> */
  a8 = (uint32_t)&trcResumeAmpdu_constprop_0; /* 0042: l32r a8, 4 <trc_onPPTxDone-0x4> (10 <trc_onPPTxDone+0x8>) */ /* literal: GOT slot for .text.trcResumeAmpdu$constprop$0 */
  trcResumeAmpdu_constprop_0(a2, a3, a4, a5); /* call via literal slot */ /* 0045: callx8 a8 */
L_48:;
  return (int32_t)a2; /* 0048: retw.n  */
}

/* trc_SetTxAmpduState @ trc.o 00000000 size 14B bind GLOBAL
 * Calls: none | Data refs: none
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t trc_SetTxAmpduState(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.trc_SetTxAmpduState; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_0:;
  /* 0000: entry a1, 32 */
  MEM8(a2 + 14) = a3; /* 0003: s8i a3, a2, 14 */
  MEMW(); /* 0006: memw  */
  MEMW(); /* 0009: memw  */
  return (int32_t)a2; /* 000c: retw.n  */
}

/* trc_isTxAmpduOperational @ trc.o 00000000 size 18B bind GLOBAL
 * Calls: none | Data refs: none
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t trc_isTxAmpduOperational(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .wifi0iram.15; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_0:;
  /* 0000: entry a1, 32 */
  a8 = MEM8(a2 + 14); /* 0003: l8ui a8, a2, 14 */
  a9 = 0x0; /* 0006: movi.n a9, 0 */
  a8 = a8 + (-2); /* 0008: addi a8, a8, -2 */
  a2 = 0x1; /* 000b: movi.n a2, 1 */
  if (a8 != 0) a2 = a9; /* 000d: movnez a2, a9, a8 */
  return (int32_t)a2; /* 0010: retw.n  */
}

/* trc_tid_isTxAmpduOperational @ trc.o 00000000 size 23B bind GLOBAL
 * Calls: none | Data refs: none
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t trc_tid_isTxAmpduOperational(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .wifi0iram.16; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_0:;
  /* 0000: entry a1, 32 */
  a3 = (a3 >> 0) & 0xFF; /* 0003: extui a3, a3, 0, 8 */
  a2 = a2 + a3; /* 0006: add.n a2, a2, a3 */
  a8 = MEM8(a2 + 17); /* 0008: l8ui a8, a2, 17 */
  a3 = 0x0; /* 000b: movi.n a3, 0 */
  a8 = a8 + (-2); /* 000d: addi a8, a8, -2 */
  a2 = 0x1; /* 0010: movi.n a2, 1 */
  if (a8 != 0) a2 = a3; /* 0012: movnez a2, a3, a8 */
  return (int32_t)a2; /* 0015: retw.n  */
}

/* rc_get_mask @ trc.o 00000004 size 10B bind GLOBAL
 * Calls: none | Data refs: trc_ctl
 *   MMIO: none
 *   funcdb v3: 0 call(s), 1 ref(s); disasm: 0 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t rc_get_mask(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.rc_get_mask; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a8 = (uint32_t)&trc_ctl; /* 0007: l32r a8, 0 <rc_get_mask-0x4> (0 <rc_get_mask-0x4>) */ /* literal @0x0: trc_ctl */
  a2 = MEM32(a8 + 20); /* 000a: l32i.n a2, a8, 20 */
  return (int32_t)a2; /* 000c: retw.n  */
}

/* rc_disable_trc @ trc.o 00000014 size 90B bind GLOBAL
 * Calls: memcmp, wifi_log | Data refs: .bss.g_per_conn_trc, .rodata_wlog_warning.19, memcmp, trc_ctl, wifi_log
 *   MMIO: none
 *   funcdb v3: 2 call(s), 5 ref(s); disasm: 2 call(s), 5 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t rc_disable_trc(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.rc_disable_trc; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_14:;
  /* 0014: entry a1, 32 */
  a6 = (uint32_t)&trc_ctl; /* 0017: l32r a6, 0 <rc_disable_trc-0x14> (0 <rc_disable_trc-0x14>) */ /* literal @0x0: trc_ctl */
  a2 = (a2 >> 0) & 0xFF; /* 001a: extui a2, a2, 0, 8 */
  a2 = (a2 << 4) + a6; /* 001d: addx4 a2, a2, a6 */
  a11 = a3; /* 0020: mov.n a11, a3 */
  a7 = (a4 >> 0) & 0xFF; /* 0022: extui a7, a4, 0, 8 */
  a5 = MEM32(a2 + 4); /* 0025: l32i.n a5, a2, 4 */
  if (!((a5 >> (a4 & 31)) & 1)) goto L_5a; /* 0027: bbc a5, a4, 5a <rc_disable_trc+0x46> */
  a12 = 0x6; /* 002a: movi.n a12, 6 */
  a8 = (uint32_t)&bss_g_per_conn_trc; /* 002c: l32r a8, 4 <rc_disable_trc-0x10> (0 <rc_disable_trc-0x14>) */ /* literal @0x4: .bss.g_per_conn_trc */
  a8 = (a7 << 4) + a8; /* 002f: addx4 a8, a7, a8 */
  a10 = MEM32(a8 + 0); /* 0032: l32i.n a10, a8, 0 */
  a10 = a10 + (31); /* 0034: addi a10, a10, 31 */
  a8 = (uint32_t)&memcmp; /* 0037: l32r a8, c <rc_disable_trc-0x8> (0 <rc_disable_trc-0x14>) */ /* literal: GOT slot for memcmp */
  memcmp(a2, a3, a4, a5); /* call via literal slot */ /* 003a: callx8 a8 */
  if (a10 != 0) goto L_5a; /* 003d: bnez.n a10, 5a <rc_disable_trc+0x46> */
  a8 = 0xFFFFFFFE; /* 003f: movi.n a8, -2 */
  /* 0041: ssl a7 */ /* UNMODELED: a7 clobbered */
  /* 0044: src a8, a8, a8 */ /* UNMODELED: a8 clobbered */
  a5 = a5 & a8; /* 0047: and a5, a5, a8 */
  MEM32(a2 + 4) = a5; /* 004a: s32i.n a5, a2, 4 */
  a2 = MEM32(a6 + 20); /* 004c: l32i.n a2, a6, 20 */
  a2 = a2 & a8; /* 004e: and a2, a2, a8 */
  MEM32(a6 + 20) = a2; /* 0051: s32i.n a2, a6, 20 */
  MEMW(); /* 0053: memw  */
  goto L_6c; /* 0056: j 6c <rc_disable_trc+0x58> */
  /* 0059: .byte 00 */
L_5a:;
  a11 = 0x1; /* 005a: movi.n a11, 1 */
  a13 = (uint32_t)&lit_rodata_wlog_warning_19; /* 005c: l32r a13, 8 <rc_disable_trc-0xc> (0 <rc_disable_trc-0x14>) */ /* literal @0x8: .rodata_wlog_warning.19 */
  a12 = 0x2; /* 005f: movi.n a12, 2 */
  a11 = 0x800; /* 0061: slli a11, a11, 11 */
  a10 = 0x6; /* 0064: movi.n a10, 6 */
  a8 = (uint32_t)&wifi_log; /* 0066: l32r a8, 10 <rc_disable_trc-0x4> (0 <rc_disable_trc-0x14>) */ /* literal: GOT slot for wifi_log */
  wifi_log(a2, a3, a4, a5); /* call via literal slot */ /* 0069: callx8 a8 */
L_6c:;
  return (int32_t)a2; /* 006c: retw.n  */
}

/* rc_disable_trc_by_interface @ trc.o 00000004 size 30B bind GLOBAL
 * Calls: none | Data refs: trc_ctl
 *   MMIO: none
 *   funcdb v3: 0 call(s), 1 ref(s); disasm: 0 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t rc_disable_trc_by_interface(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.rc_disable_trc_by_interface; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a8 = (uint32_t)&trc_ctl; /* 0007: l32r a8, 0 <rc_disable_trc_by_interface-0x4> (0 <rc_disable_trc_by_interface-0x4>) */ /* literal @0x0: trc_ctl */
  a2 = (a2 >> 0) & 0xFF; /* 000a: extui a2, a2, 0, 8 */
  a2 = (a2 << 4) + a8; /* 000d: addx4 a2, a2, a8 */
  a9 = MEM32(a8 + 20); /* 0010: l32i.n a9, a8, 20 */
  a10 = MEM32(a2 + 4); /* 0012: l32i.n a10, a2, 4 */
  a9 = a9 ^ a10; /* 0014: xor a9, a9, a10 */
  MEM32(a8 + 20) = a9; /* 0017: s32i.n a9, a8, 20 */
  a8 = 0x0; /* 0019: movi.n a8, 0 */
  MEM32(a2 + 4) = a8; /* 001b: s32i.n a8, a2, 4 */
  MEMW(); /* 001d: memw  */
  return (int32_t)a2; /* 0020: retw.n  */
}

/* rc_get_sta_trc @ trc.o 00000008 size 48B bind GLOBAL
 * Calls: none | Data refs: .bss.g_per_conn_trc, trc_ctl
 *   MMIO: none
 *   funcdb v3: 0 call(s), 2 ref(s); disasm: 0 call(s), 2 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t rc_get_sta_trc(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.rc_get_sta_trc; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_8:;
  /* 0008: entry a1, 32 */
  a8 = (uint32_t)&trc_ctl; /* 000b: l32r a8, 0 <rc_get_sta_trc-0x8> (0 <rc_get_sta_trc-0x8>) */ /* literal @0x0: trc_ctl */
  a2 = (a2 >> 0) & 0xFF; /* 000e: extui a2, a2, 0, 8 */
  a2 = (a2 << 4) + a8; /* 0011: addx4 a2, a2, a8 */
  a9 = MEM32(a2 + 4); /* 0014: l32i.n a9, a2, 4 */
  a2 = a9; /* 0016: mov.n a2, a9 */
  if (a9 == 0) goto L_36; /* 0018: beqz.n a9, 36 <rc_get_sta_trc+0x2e> */
  a8 = a9 + (-1); /* 001a: addi.n a8, a9, -1 */
  a2 = 0x0; /* 001c: movi.n a2, 0 */
  if ((a8 & a9) != 0) goto L_36; /* 001e: bany a8, a9, 36 <rc_get_sta_trc+0x2e> */
  a8 = -a9; /* 0021: neg a8, a9 */
  a8 = a8 & a9; /* 0024: and a8, a8, a9 */
  a2 = (uint32_t)&bss_g_per_conn_trc; /* 0027: l32r a2, 4 <rc_get_sta_trc-0x4> (0 <rc_get_sta_trc-0x8>) */ /* literal @0x4: .bss.g_per_conn_trc */
  a8 = __builtin_clz(a8) /* approx for nsau */; /* 002a: nsau a8, a8 */
  a8 = -a8; /* 002d: neg a8, a8 */
  a8 = (a8 << 4) + a2; /* 0030: addx4 a8, a8, a2 */
  a2 = MEM32(a8 + 124); /* 0033: l32i a2, a8, 124 */
L_36:;
  return (int32_t)a2; /* 0036: retw.n  */
}

/* rc_get_trc @ trc.o 0000000c size 87B bind GLOBAL
 * Calls: memcmp[got] | Data refs: trc_ctl, .bss.g_per_conn_trc, memcmp
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 1 call(s), 3 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t rc_get_trc(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .wifirxiram.20; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_c:;
  /* 000c: entry a1, 48 */
  a4 = (uint32_t)&trc_ctl; /* 000f: l32r a4, 0 <rc_get_trc-0xc> (0 <rc_get_trc-0xc>) */ /* literal @0x0: trc_ctl */
  a2 = (a2 >> 0) & 0xFF; /* 0012: extui a2, a2, 0, 8 */
  a2 = (a2 << 4) + a4; /* 0015: addx4 a2, a2, a4 */
  a6 = 0x6; /* 0018: movi.n a6, 6 */
  a7 = 0x1; /* 001a: movi.n a7, 1 */
  a5 = MEM32(a2 + 4); /* 001c: l32i.n a5, a2, 4 */
  a9 = 0xFFFFFFFF; /* 001e: movi.n a9, -1 */
  goto L_5c; /* 0020: j 5c <rc_get_trc+0x50> */
L_23:;
  a8 = -a5; /* 0023: neg a8, a5 */
  a8 = a8 & a5; /* 0026: and a8, a8, a5 */
  a8 = __builtin_clz(a8) /* approx for nsau */; /* 0029: nsau a8, a8 */
  a8 = -a8; /* 002c: neg a8, a8 */
  a4 = a8 + (31); /* 002f: addi a4, a8, 31 */
  a8 = (uint32_t)&bss_g_per_conn_trc; /* 0032: l32r a8, 4 <rc_get_trc-0x8> (0 <rc_get_trc-0xc>) */ /* literal @0x4: .bss.g_per_conn_trc */
  a12 = 0x6; /* 0035: mov.n a12, a6 */
  a2 = (a4 << 4) + a8; /* 0037: addx4 a2, a4, a8 */
  a11 = a3; /* 003a: mov.n a11, a3 */
  a2 = MEM32(a2 + 0); /* 003c: l32i.n a2, a2, 0 */
  a10 = a2 + (31); /* 003e: addi a10, a2, 31 */
  MEM32(a1 + 0) = a9; /* 0041: s32i.n a9, a1, 0 */
  MEMW(); /* 0043: memw  */
  a8 = (uint32_t)&memcmp; /* 0046: l32r a8, 8 <rc_get_trc-0x4> (0 <rc_get_trc-0xc>) */ /* literal: GOT slot for memcmp */
  memcmp(a2, a3, a4, a5); /* call via literal slot */ /* 0049: callx8 a8 */
  a9 = MEM32(a1 + 0); /* 004c: l32i.n a9, a1, 0 */
  if (a10 == 0) goto L_61; /* 004e: beqz.n a10, 61 <rc_get_trc+0x55> */
  /* 0050: ssl a4 */ /* UNMODELED: a4 clobbered */
  /* 0053: sll a8, a7 */ /* UNMODELED: a8 clobbered */
  a8 = a9 ^ a8; /* 0056: xor a8, a9, a8 */
  a5 = a5 & a8; /* 0059: and a5, a5, a8 */
L_5c:;
  if (a5 != 0) goto L_23; /* 005c: bnez a5, 23 <rc_get_trc+0x17> */
  a2 = a5; /* 005f: mov.n a2, a5 */
L_61:;
  return (int32_t)a2; /* 0061: retw.n  */
}

/* rc_get_trc_by_index @ trc.o 00000008 size 90B bind GLOBAL
 * Calls: none | Data refs: .bss.g_per_conn_trc, trc_ctl
 *   MMIO: none
 *   funcdb v3: 0 call(s), 2 ref(s); disasm: 0 call(s), 2 data ref(s)
 * Fidelity: medium - 35 instr, 13 branches, calls resolved */
int32_t rc_get_trc_by_index(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.rc_get_trc_by_index; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_8:;
  /* 0008: entry a1, 32 */
  a8 = (a2 >> 0) & 0xFF; /* 000b: extui a8, a2, 0, 8 */
  a3 = (a3 >> 0) & 0xFF; /* 000e: extui a3, a3, 0, 8 */
  if (a8 != 0) goto L_28; /* 0011: bnez.n a8, 28 <rc_get_trc_by_index+0x20> */
  a2 = (uint32_t)&trc_ctl; /* 0013: l32r a2, 0 <rc_get_trc_by_index-0x8> (0 <rc_get_trc_by_index-0x8>) */ /* literal @0x0: trc_ctl */
  a8 = MEM32(a2 + 20); /* 0016: l32i.n a8, a2, 20 */
  a2 = (uint32_t)&bss_g_per_conn_trc; /* 0018: l32r a2, 4 <rc_get_trc_by_index-0x4> (0 <rc_get_trc_by_index-0x8>) */ /* literal @0x4: .bss.g_per_conn_trc */
  if (!((a8 >> (a3 & 31)) & 1)) goto L_21; /* 001b: bbc a8, a3, 21 <rc_get_trc_by_index+0x19> */
  goto L_54; /* 001e: j 54 <rc_get_trc_by_index+0x4c> */
L_21:;
  a2 = MEM32(a2 + 76); /* 0021: l32i a2, a2, 76 */
  goto L_60; /* 0024: j 60 <rc_get_trc_by_index+0x58> */
  /* 0027: .byte 00 */
L_28:;
  if (a8 != 1) goto L_42; /* 0028: bnei a8, 1, 42 <rc_get_trc_by_index+0x3a> */
  a2 = (uint32_t)&bss_g_per_conn_trc; /* 002b: l32r a2, 4 <rc_get_trc_by_index-0x4> (0 <rc_get_trc_by_index-0x8>) */ /* literal @0x4: .bss.g_per_conn_trc */
  if (a3 == 0) goto L_3c; /* 002e: beqz.n a3, 3c <rc_get_trc_by_index+0x34> */
  a8 = (uint32_t)&trc_ctl; /* 0030: l32r a8, 0 <rc_get_trc_by_index-0x8> (0 <rc_get_trc_by_index-0x8>) */ /* literal @0x0: trc_ctl */
  a8 = MEM32(a8 + 20); /* 0033: l32i.n a8, a8, 20 */
  if (!((a8 >> (a3 & 31)) & 1)) goto L_3c; /* 0035: bbc a8, a3, 3c <rc_get_trc_by_index+0x34> */
  goto L_54; /* 0038: j 54 <rc_get_trc_by_index+0x4c> */
  /* 003b: .byte 00 */
L_3c:;
  a2 = MEM32(a2 + 80); /* 003c: l32i a2, a2, 80 */
  goto L_60; /* 003f: j 60 <rc_get_trc_by_index+0x58> */
L_42:;
  a2 = 0x0; /* 0042: movi.n a2, 0 */
  if (a8 != 2) goto L_60; /* 0044: bnei a8, 2, 60 <rc_get_trc_by_index+0x58> */
  a2 = (uint32_t)&bss_g_per_conn_trc; /* 0047: l32r a2, 4 <rc_get_trc_by_index-0x4> (0 <rc_get_trc_by_index-0x8>) */ /* literal @0x4: .bss.g_per_conn_trc */
  if (a3 == 0) goto L_5d; /* 004a: beqz.n a3, 5d <rc_get_trc_by_index+0x55> */
  a8 = (uint32_t)&trc_ctl; /* 004c: l32r a8, 0 <rc_get_trc_by_index-0x8> (0 <rc_get_trc_by_index-0x8>) */ /* literal @0x0: trc_ctl */
  a8 = MEM32(a8 + 20); /* 004f: l32i.n a8, a8, 20 */
  if (!((a8 >> (a3 & 31)) & 1)) goto L_5d; /* 0051: bbc a8, a3, 5d <rc_get_trc_by_index+0x55> */
L_54:;
  a3 = (a3 << 4) + a2; /* 0054: addx4 a3, a3, a2 */
  a2 = MEM32(a3 + 0); /* 0057: l32i.n a2, a3, 0 */
  goto L_60; /* 0059: j 60 <rc_get_trc_by_index+0x58> */
  /* 005c: .byte 00 */
L_5d:;
  a2 = MEM32(a2 + 84); /* 005d: l32i a2, a2, 84 */
L_60:;
  return (int32_t)a2; /* 0060: retw.n  */
}

/* rc_get_trc_default @ trc.o 00000004 size 42B bind GLOBAL
 * Calls: none | Data refs: .bss.g_per_conn_trc
 *   MMIO: none
 *   funcdb v3: 0 call(s), 1 ref(s); disasm: 0 call(s), 1 data ref(s)
 * Fidelity: medium - 15 instr, 5 branches, calls resolved */
int32_t rc_get_trc_default(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.rc_get_trc_default; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a8 = (a2 >> 0) & 0xFF; /* 0007: extui a8, a2, 0, 8 */
  if (a8 != 0) goto L_15; /* 000a: bnez.n a8, 15 <rc_get_trc_default+0x11> */
  a2 = (uint32_t)&bss_g_per_conn_trc; /* 000c: l32r a2, 0 <rc_get_trc_default-0x4> (0 <rc_get_trc_default-0x4>) */ /* literal @0x0: .bss.g_per_conn_trc */
  a2 = MEM32(a2 + 76); /* 000f: l32i a2, a2, 76 */
  goto L_2c; /* 0012: j 2c <rc_get_trc_default+0x28> */
L_15:;
  if (a8 != 1) goto L_21; /* 0015: bnei a8, 1, 21 <rc_get_trc_default+0x1d> */
  a2 = (uint32_t)&bss_g_per_conn_trc; /* 0018: l32r a2, 0 <rc_get_trc_default-0x4> (0 <rc_get_trc_default-0x4>) */ /* literal @0x0: .bss.g_per_conn_trc */
  a2 = MEM32(a2 + 80); /* 001b: l32i a2, a2, 80 */
  goto L_2c; /* 001e: j 2c <rc_get_trc_default+0x28> */
L_21:;
  a2 = 0x0; /* 0021: movi.n a2, 0 */
  if (a8 != 2) goto L_2c; /* 0023: bnei a8, 2, 2c <rc_get_trc_default+0x28> */
  a2 = (uint32_t)&bss_g_per_conn_trc; /* 0026: l32r a2, 0 <rc_get_trc_default-0x4> (0 <rc_get_trc_default-0x4>) */ /* literal @0x0: .bss.g_per_conn_trc */
  a2 = MEM32(a2 + 84); /* 0029: l32i a2, a2, 84 */
L_2c:;
  return (int32_t)a2; /* 002c: retw.n  */
}

/* rc_only_sta_trc @ trc.o 00000004 size 42B bind GLOBAL
 * Calls: none | Data refs: trc_ctl
 *   MMIO: none
 *   funcdb v3: 0 call(s), 1 ref(s); disasm: 0 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t rc_only_sta_trc(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.rc_only_sta_trc; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a11 = (uint32_t)&trc_ctl; /* 0007: l32r a11, 0 <rc_only_sta_trc-0x4> (0 <rc_only_sta_trc-0x4>) */ /* literal @0x0: trc_ctl */
  a2 = 0x1; /* 000a: movi.n a2, 1 */
  a9 = 0x0; /* 000c: movi.n a9, 0 */
  a10 = MEM32(a11 + 20); /* 000e: l32i.n a10, a11, 20 */
  a8 = a10 + (-1); /* 0010: addi.n a8, a10, -1 */
  a8 = a8 & a10; /* 0012: and a8, a8, a10 */
  if (a8 != 0) a9 = a2; /* 0015: movnez a9, a2, a8 */
  a8 = (a9 >> 0) & 0xFF; /* 0018: extui a8, a9, 0, 8 */
  if (a9 != 0) goto L_2a; /* 001b: bnez.n a9, 2a <rc_only_sta_trc+0x26> */
  if (a10 == 0) a8 = a2; /* 001d: moveqz a8, a2, a10 */
  if (a8 != 0) goto L_2a; /* 0020: bnez.n a8, 2a <rc_only_sta_trc+0x26> */
  a9 = MEM32(a11 + 4); /* 0022: l32i.n a9, a11, 4 */
  if (a9 != 0) a2 = a8; /* 0024: movnez a2, a8, a9 */
  goto L_2c; /* 0027: j 2c <rc_only_sta_trc+0x28> */
L_2a:;
  a2 = 0xFFFFFFFF; /* 002a: movi.n a2, -1 */
L_2c:;
  return (int32_t)a2; /* 002c: retw.n  */
}

/* trc_init @ trc.o 0000001c size 215B bind GLOBAL
 * Calls: wifi_log, g_osi_funcs_p[got] | Data refs: .bss.g_per_conn_trc, .rodata_wlog_error.21, g_osi_funcs_p, rc11BSchedTbl, rcP2P11GSchedTbl, wifi_log
 *   MMIO: none
 *   funcdb v3: 1 call(s), 6 ref(s); disasm: 2 call(s), 6 data ref(s)
 * Fidelity: medium - 76 instr, 4 branches, calls resolved */
int32_t trc_init(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.trc_init; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_1c:;
  /* 001c: entry a1, 32 */
  a3 = (uint32_t)&g_osi_funcs_p; /* 001f: l32r a3, 0 <trc_init-0x1c> (0 <trc_init-0x1c>) */ /* literal @0x0: g_osi_funcs_p */
  a10 = 0x88; /* 0022: movi a10, 136 */
  a2 = MEM32(a3 + 0); /* 0025: l32i.n a2, a3, 0 */
  a2 = MEM32(a2 + 376); /* 0027: l32i a2, a2, 0x178 */
  ((int32_t(*)())a2)(a2, a3, a4, a5); /* 002a: callx8 a2 */ /* indirect */
  a8 = MEM32(a3 + 0); /* 002d: l32i.n a8, a3, 0 */
  a2 = (uint32_t)&bss_g_per_conn_trc; /* 002f: l32r a2, 4 <trc_init-0x18> (0 <trc_init-0x1c>) */ /* literal @0x4: .bss.g_per_conn_trc */
  a8 = MEM32(a8 + 376); /* 0032: l32i a8, a8, 0x178 */
  MEM32(a2 + 76) = a10; /* 0035: s32i a10, a2, 76 */
  a10 = 0x88; /* 0038: movi a10, 136 */
  MEMW(); /* 003b: memw  */
  ((int32_t(*)())a8)(a2, a3, a4, a5); /* 003e: callx8 a8 */ /* indirect */
  a3 = MEM32(a3 + 0); /* 0041: l32i.n a3, a3, 0 */
  a3 = MEM32(a3 + 376); /* 0043: l32i a3, a3, 0x178 */
  MEM32(a2 + 80) = a10; /* 0046: s32i a10, a2, 80 */
  a10 = 0x88; /* 0049: movi a10, 136 */
  MEMW(); /* 004c: memw  */
  g_osi_funcs_p(a2, a3, a4, a5); /* call via literal slot */ /* 004f: callx8 a3 */
  a9 = MEM32(a2 + 76); /* 0052: l32i a9, a2, 76 */
  MEM32(a2 + 84) = a10; /* 0055: s32i a10, a2, 84 */
  if (a9 == 0) goto L_71; /* 0058: beqz.n a9, 71 <trc_init+0x55> */
  a15 = 0x1; /* 005a: movi.n a15, 1 */
  a11 = 0x0; /* 005c: movi a11, 0 */
  if (a10 == 0) a11 = a15; /* 005f: moveqz a11, a15, a10 */
  a8 = MEM32(a2 + 80); /* 0062: l32i a8, a2, 80 */
  a2 = (a11 >> 0) & 0xFF; /* 0065: extui a2, a11, 0, 8 */
  if (a11 != 0) goto L_71; /* 0068: bnez a11, 71 <trc_init+0x55> */
  if (a8 == 0) a2 = a15; /* 006b: moveqz a2, a15, a8 */
  if (a2 == 0) goto L_8c; /* 006e: beqz a2, 8c <trc_init+0x70> */
L_71:;
  a13 = (uint32_t)&lit_rodata_wlog_error_21; /* 0071: l32r a13, 8 <trc_init-0x14> (0 <trc_init-0x1c>) */ /* literal @0x8: .rodata_wlog_error.21 */
  a12 = 0x1; /* 0074: movi.n a12, 1 */
  a11 = 0x200; /* 0076: movi a11, 0x200 */
  a10 = 0x6; /* 0079: movi.n a10, 6 */
  MEMW(); /* 007b: memw  */
  a8 = (uint32_t)&wifi_log; /* 007e: l32r a8, 18 <trc_init-0x4> (0 <trc_init-0x1c>) */ /* literal: GOT slot for wifi_log */
  wifi_log(a2, a3, a4, a5); /* call via literal slot */ /* 0081: callx8 a8 */
  a2 = 0x101; /* 0084: movi a2, 0x101 */
  goto L_ee; /* 0087: j ee <trc_init+0xd2> */
  /* 008a: .byte 00 */
  /* 008b: .byte 00 */
L_8c:;
  a11 = (uint32_t)&rc11BSchedTbl; /* 008c: l32r a11, c <trc_init-0x10> (0 <trc_init-0x1c>) */ /* literal @0xC: rc11BSchedTbl */
  a12 = 0xFFFFFF80; /* 008f: movi a12, -128 */
  a3 = 0x2; /* 0092: movi.n a3, 2 */
  a14 = (uint32_t)&rc11BSchedTbl; /* 0094: l32r a14, 10 <trc_init-0xc> (0 <trc_init-0x1c>) */ /* literal @0x10: rc11BSchedTbl */
  a13 = (uint32_t)&rcP2P11GSchedTbl; /* 0097: l32r a13, 14 <trc_init-0x8> (0 <trc_init-0x1c>) */ /* literal @0x14: rcP2P11GSchedTbl */
  MEM32(a9 + 96) = a11; /* 009a: s32i a11, a9, 96 */
  MEM32(a9 + 112) = a14; /* 009d: s32i a14, a9, 112 */
  MEM32(a9 + 100) = a11; /* 00a0: s32i a11, a9, 100 */
  MEM32(a9 + 104) = a11; /* 00a3: s32i a11, a9, 104 */
  MEM32(a9 + 108) = a13; /* 00a6: s32i a13, a9, 108 */
  MEM8(a9 + 11) = a12; /* 00a9: s8i a12, a9, 11 */
  MEM8(a9 + 38) = a2; /* 00ac: s8i a2, a9, 38 */
  MEM8(a9 + 131) = a2; /* 00af: s8i a2, a9, 131 */
  MEM8(a9 + 129) = a2; /* 00b2: s8i a2, a9, 129 */
  MEM32(a8 + 96) = a11; /* 00b5: s32i a11, a8, 96 */
  MEM32(a8 + 112) = a14; /* 00b8: s32i a14, a8, 112 */
  MEM32(a8 + 100) = a11; /* 00bb: s32i a11, a8, 100 */
  MEM32(a8 + 104) = a11; /* 00be: s32i a11, a8, 104 */
  MEM32(a8 + 108) = a13; /* 00c1: s32i a13, a8, 108 */
  MEM8(a8 + 11) = a12; /* 00c4: s8i a12, a8, 11 */
  MEM8(a8 + 38) = a2; /* 00c7: s8i a2, a8, 38 */
  MEM8(a8 + 131) = a2; /* 00ca: s8i a2, a8, 131 */
  MEM8(a8 + 129) = a15; /* 00cd: s8i a15, a8, 129 */
  MEM32(a10 + 96) = a11; /* 00d0: s32i a11, a10, 96 */
  MEM32(a10 + 112) = a14; /* 00d3: s32i a14, a10, 112 */
  MEM32(a10 + 100) = a11; /* 00d6: s32i a11, a10, 100 */
  MEM32(a10 + 104) = a11; /* 00d9: s32i a11, a10, 104 */
  MEM32(a10 + 108) = a13; /* 00dc: s32i a13, a10, 108 */
  MEM8(a10 + 11) = a12; /* 00df: s8i a12, a10, 11 */
  MEM8(a10 + 38) = a2; /* 00e2: s8i a2, a10, 38 */
  MEM8(a10 + 131) = a2; /* 00e5: s8i a2, a10, 131 */
  MEM8(a10 + 129) = a3; /* 00e8: s8i a3, a10, 129 */
  MEMW(); /* 00eb: memw  */
L_ee:;
  MEMW(); /* 00ee: memw  */
  return (int32_t)a2; /* 00f1: retw.n  */
}

/* trc_update_def_rate @ trc.o 0000001c size 255B bind GLOBAL
 * Calls: wifi_log | Data refs: .bss.g_per_conn_trc, .rodata_wlog_warning.22, rc11BSchedTbl, rcP2P11GSchedTbl, wifi_log
 *   MMIO: none
 *   funcdb v3: 1 call(s), 5 ref(s); disasm: 1 call(s), 5 data ref(s)
 * Fidelity: medium - 89 instr, 12 branches, calls resolved */
int32_t trc_update_def_rate(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.trc_update_def_rate; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_1c:;
  /* 001c: entry a1, 32 */
  a10 = (uint32_t)&bss_g_per_conn_trc; /* 001f: l32r a10, 0 <trc_update_def_rate-0x1c> (0 <trc_update_def_rate-0x1c>) */ /* literal @0x0: .bss.g_per_conn_trc */
  a4 = (a4 >> 0) & 0xFF; /* 0022: extui a4, a4, 0, 8 */
  a9 = MEM32(a10 + 76); /* 0025: l32i a9, a10, 76 */
  a8 = MEM32(a10 + 80); /* 0028: l32i a8, a10, 80 */
  a10 = MEM32(a10 + 84); /* 002b: l32i a10, a10, 84 */
  if (a3 != 0) goto L_7c; /* 002e: bnez a3, 7c <trc_update_def_rate+0x60> */
  if (a4 == 0) goto L_58; /* 0031: beqz.n a4, 58 <trc_update_def_rate+0x3c> */
  a3 = (uint32_t)&rcP2P11GSchedTbl; /* 0033: l32r a3, 4 <trc_update_def_rate-0x18> (0 <trc_update_def_rate-0x1c>) */ /* literal @0x4: rcP2P11GSchedTbl */
  a4 = (uint32_t)&rcP2P11GSchedTbl; /* 0036: l32r a4, 8 <trc_update_def_rate-0x14> (0 <trc_update_def_rate-0x1c>) */ /* literal @0x8: rcP2P11GSchedTbl */
  MEM32(a9 + 96) = a3; /* 0039: s32i a3, a9, 96 */
  MEM32(a9 + 100) = a3; /* 003c: s32i a3, a9, 100 */
  MEM32(a9 + 104) = a3; /* 003f: s32i a3, a9, 104 */
  a3 = 0x40; /* 0042: movi.n a3, 64 */
  MEM8(a9 + 11) = a3; /* 0044: s8i a3, a9, 11 */
  a3 = 0x1; /* 0047: movi.n a3, 1 */
  MEM32(a9 + 112) = a4; /* 0049: s32i a4, a9, 112 */
  MEM8(a9 + 130) = a3; /* 004c: s8i a3, a9, 130 */
  MEMW(); /* 004f: memw  */
  MEMW(); /* 0052: memw  */
  goto L_119; /* 0055: j 119 <trc_update_def_rate+0xfd> */
L_58:;
  a3 = (uint32_t)&rc11BSchedTbl; /* 0058: l32r a3, c <trc_update_def_rate-0x10> (0 <trc_update_def_rate-0x1c>) */ /* literal @0xC: rc11BSchedTbl */
  a8 = (uint32_t)&rc11BSchedTbl; /* 005b: l32r a8, 10 <trc_update_def_rate-0xc> (0 <trc_update_def_rate-0x1c>) */ /* literal @0x10: rc11BSchedTbl */
  MEM32(a9 + 96) = a3; /* 005e: s32i a3, a9, 96 */
  MEM32(a9 + 100) = a3; /* 0061: s32i a3, a9, 100 */
  MEM32(a9 + 104) = a3; /* 0064: s32i a3, a9, 104 */
  a3 = 0xFFFFFF80; /* 0067: movi a3, -128 */
  MEM32(a9 + 112) = a8; /* 006a: s32i a8, a9, 112 */
  MEM8(a9 + 11) = a3; /* 006d: s8i a3, a9, 11 */
  MEM8(a9 + 130) = a4; /* 0070: s8i a4, a9, 130 */
  MEMW(); /* 0073: memw  */
  MEMW(); /* 0076: memw  */
  goto L_119; /* 0079: j 119 <trc_update_def_rate+0xfd> */
L_7c:;
  if (a3 != 1) goto L_c8; /* 007c: bnei a3, 1, c8 <trc_update_def_rate+0xac> */
  if (a4 == 0) goto L_a4; /* 007f: beqz.n a4, a4 <trc_update_def_rate+0x88> */
  a4 = (uint32_t)&rcP2P11GSchedTbl; /* 0081: l32r a4, 4 <trc_update_def_rate-0x18> (0 <trc_update_def_rate-0x1c>) */ /* literal @0x4: rcP2P11GSchedTbl */
  a9 = (uint32_t)&rcP2P11GSchedTbl; /* 0084: l32r a9, 8 <trc_update_def_rate-0x14> (0 <trc_update_def_rate-0x1c>) */ /* literal @0x8: rcP2P11GSchedTbl */
  MEM32(a8 + 96) = a4; /* 0087: s32i a4, a8, 96 */
  MEM32(a8 + 100) = a4; /* 008a: s32i a4, a8, 100 */
  MEM32(a8 + 104) = a4; /* 008d: s32i a4, a8, 104 */
  a4 = 0x40; /* 0090: movi.n a4, 64 */
  MEM32(a8 + 112) = a9; /* 0092: s32i a9, a8, 112 */
  MEM8(a8 + 11) = a4; /* 0095: s8i a4, a8, 11 */
  MEM8(a8 + 130) = a3; /* 0098: s8i a3, a8, 130 */
  MEMW(); /* 009b: memw  */
  MEMW(); /* 009e: memw  */
  goto L_119; /* 00a1: j 119 <trc_update_def_rate+0xfd> */
L_a4:;
  a3 = (uint32_t)&rc11BSchedTbl; /* 00a4: l32r a3, c <trc_update_def_rate-0x10> (0 <trc_update_def_rate-0x1c>) */ /* literal @0xC: rc11BSchedTbl */
  a9 = (uint32_t)&rc11BSchedTbl; /* 00a7: l32r a9, 10 <trc_update_def_rate-0xc> (0 <trc_update_def_rate-0x1c>) */ /* literal @0x10: rc11BSchedTbl */
  MEM32(a8 + 96) = a3; /* 00aa: s32i a3, a8, 96 */
  MEM32(a8 + 100) = a3; /* 00ad: s32i a3, a8, 100 */
  MEM32(a8 + 104) = a3; /* 00b0: s32i a3, a8, 104 */
  a3 = 0xFFFFFF80; /* 00b3: movi a3, -128 */
  MEM32(a8 + 112) = a9; /* 00b6: s32i a9, a8, 112 */
  MEM8(a8 + 11) = a3; /* 00b9: s8i a3, a8, 11 */
  MEM8(a8 + 130) = a4; /* 00bc: s8i a4, a8, 130 */
  MEMW(); /* 00bf: memw  */
  MEMW(); /* 00c2: memw  */
  goto L_119; /* 00c5: j 119 <trc_update_def_rate+0xfd> */
L_c8:;
  if (a3 != 2) goto L_109; /* 00c8: bnei a3, 2, 109 <trc_update_def_rate+0xed> */
  if (a4 == 0) goto L_e8; /* 00cb: beqz.n a4, e8 <trc_update_def_rate+0xcc> */
  a3 = (uint32_t)&rcP2P11GSchedTbl; /* 00cd: l32r a3, 4 <trc_update_def_rate-0x18> (0 <trc_update_def_rate-0x1c>) */ /* literal @0x4: rcP2P11GSchedTbl */
  a4 = (uint32_t)&rcP2P11GSchedTbl; /* 00d0: l32r a4, 8 <trc_update_def_rate-0x14> (0 <trc_update_def_rate-0x1c>) */ /* literal @0x8: rcP2P11GSchedTbl */
  MEM32(a10 + 96) = a3; /* 00d3: s32i a3, a10, 96 */
  MEM32(a10 + 100) = a3; /* 00d6: s32i a3, a10, 100 */
  MEM32(a10 + 104) = a3; /* 00d9: s32i a3, a10, 104 */
  a3 = 0x40; /* 00dc: movi.n a3, 64 */
  MEM32(a10 + 112) = a4; /* 00de: s32i a4, a10, 112 */
  MEMW(); /* 00e1: memw  */
  goto L_fd; /* 00e4: j fd <trc_update_def_rate+0xe1> */
  /* 00e7: .byte 00 */
L_e8:;
  a3 = (uint32_t)&rc11BSchedTbl; /* 00e8: l32r a3, c <trc_update_def_rate-0x10> (0 <trc_update_def_rate-0x1c>) */ /* literal @0xC: rc11BSchedTbl */
  a4 = (uint32_t)&rc11BSchedTbl; /* 00eb: l32r a4, 10 <trc_update_def_rate-0xc> (0 <trc_update_def_rate-0x1c>) */ /* literal @0x10: rc11BSchedTbl */
  MEM32(a10 + 96) = a3; /* 00ee: s32i a3, a10, 96 */
  MEM32(a10 + 100) = a3; /* 00f1: s32i a3, a10, 100 */
  MEM32(a10 + 104) = a3; /* 00f4: s32i a3, a10, 104 */
  a3 = 0xFFFFFF80; /* 00f7: movi a3, -128 */
  MEM32(a10 + 112) = a4; /* 00fa: s32i a4, a10, 112 */
L_fd:;
  MEM8(a10 + 11) = a3; /* 00fd: s8i a3, a10, 11 */
  MEMW(); /* 0100: memw  */
  MEMW(); /* 0103: memw  */
  goto L_119; /* 0106: j 119 <trc_update_def_rate+0xfd> */
L_109:;
  a13 = (uint32_t)&lit_rodata_wlog_warning_22; /* 0109: l32r a13, 14 <trc_update_def_rate-0x8> (0 <trc_update_def_rate-0x1c>) */ /* literal @0x14: .rodata_wlog_warning.22 */
  a12 = 0x2; /* 010c: movi.n a12, 2 */
  a11 = 0x200; /* 010e: movi a11, 0x200 */
  a10 = 0x6; /* 0111: movi.n a10, 6 */
  a8 = (uint32_t)&wifi_log; /* 0113: l32r a8, 18 <trc_update_def_rate-0x4> (0 <trc_update_def_rate-0x1c>) */ /* literal: GOT slot for wifi_log */
  wifi_log(a2, a3, a4, a5); /* call via literal slot */ /* 0116: callx8 a8 */
L_119:;
  return (int32_t)a2; /* 0119: retw.n  */
}

/* trc_update_ifx_phy_mode @ trc.o 00000020 size 144B bind GLOBAL
 * Calls: wifi_log | Data refs: .bss.g_per_conn_trc, .rodata_wlog_error.23, g_ic, rc11BSchedTbl, rcLoRaSchedTbl, rcP2P11GSchedTbl, wifi_log
 *   MMIO: none
 *   funcdb v3: 1 call(s), 7 ref(s); disasm: 1 call(s), 7 data ref(s)
 * Fidelity: medium - 52 instr, 11 branches, calls resolved */
int32_t trc_update_ifx_phy_mode(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.trc_update_ifx_phy_mode; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_20:;
  /* 0020: entry a1, 32 */
  if (a2 != 0) goto L_3a; /* 0023: bnez.n a2, 3a <trc_update_ifx_phy_mode+0x1a> */
  a2 = (uint32_t)&bss_g_per_conn_trc; /* 0025: l32r a2, 8 <trc_update_ifx_phy_mode-0x18> (0 <trc_update_ifx_phy_mode-0x20>) */ /* literal @0x8: .bss.g_per_conn_trc */
  a8 = MEM32(a2 + 76); /* 0028: l32i a8, a2, 76 */
  a2 = (uint32_t)&g_ic; /* 002b: l32r a2, c <trc_update_ifx_phy_mode-0x14> (0 <trc_update_ifx_phy_mode-0x20>) */ /* literal @0xC: g_ic */
  a2 = a2 + ((0x100) << 8); /* 002e: addmi a2, a2, 0x100 */
  a10 = MEM8(a2 + 216); /* 0031: l8ui a10, a2, 216 */
  a10 = (a10 >> 4) & 0x1; /* 0034: extui a10, a10, 4, 1 */
  goto L_7a; /* 0037: j 7a <trc_update_ifx_phy_mode+0x5a> */
L_3a:;
  if (a2 != 1) goto L_54; /* 003a: bnei a2, 1, 54 <trc_update_ifx_phy_mode+0x34> */
  a2 = (uint32_t)&bss_g_per_conn_trc; /* 003d: l32r a2, 8 <trc_update_ifx_phy_mode-0x18> (0 <trc_update_ifx_phy_mode-0x20>) */ /* literal @0x8: .bss.g_per_conn_trc */
  a8 = MEM32(a2 + 80); /* 0040: l32i a8, a2, 80 */
  a2 = (uint32_t)&g_ic; /* 0043: l32r a2, c <trc_update_ifx_phy_mode-0x14> (0 <trc_update_ifx_phy_mode-0x20>) */ /* literal @0xC: g_ic */
  a2 = a2 + ((0x100) << 8); /* 0046: addmi a2, a2, 0x100 */
  a10 = MEM8(a2 + 216); /* 0049: l8ui a10, a2, 216 */
  a10 = (a10 >> 5) & 0x1; /* 004c: extui a10, a10, 5, 1 */
  goto L_7a; /* 004f: j 7a <trc_update_ifx_phy_mode+0x5a> */
  /* 0052: .byte 00 */
  /* 0053: .byte 00 */
L_54:;
  if (a2 != 2) goto L_64; /* 0054: bnei a2, 2, 64 <trc_update_ifx_phy_mode+0x44> */
  a2 = (uint32_t)&bss_g_per_conn_trc; /* 0057: l32r a2, 8 <trc_update_ifx_phy_mode-0x18> (0 <trc_update_ifx_phy_mode-0x20>) */ /* literal @0x8: .bss.g_per_conn_trc */
  a8 = MEM32(a2 + 84); /* 005a: l32i a8, a2, 84 */
  if (a3 == 6) goto L_7d; /* 005d: beqi a3, 6, 7d <trc_update_ifx_phy_mode+0x5d> */
  goto L_9a; /* 0060: j 9a <trc_update_ifx_phy_mode+0x7a> */
  /* 0063: .byte 00 */
L_64:;
  a13 = (uint32_t)&lit_rodata_wlog_error_23; /* 0064: l32r a13, 10 <trc_update_ifx_phy_mode-0x10> (0 <trc_update_ifx_phy_mode-0x20>) */ /* literal @0x10: .rodata_wlog_error.23 */
  a12 = 0x1; /* 0067: movi.n a12, 1 */
  a11 = 0x200; /* 0069: movi a11, 0x200 */
  a10 = 0x6; /* 006c: movi.n a10, 6 */
  a8 = (uint32_t)&wifi_log; /* 006e: l32r a8, 1c <trc_update_ifx_phy_mode-0x4> (0 <trc_update_ifx_phy_mode-0x20>) */ /* literal: GOT slot for wifi_log */
  wifi_log(a2, a3, a4, a5); /* call via literal slot */ /* 0071: callx8 a8 */
  a2 = 0x102; /* 0074: movi a2, 0x102 */
  goto L_ab; /* 0077: j ab <trc_update_ifx_phy_mode+0x8b> */
L_7a:;
  if (a3 != 6) goto L_95; /* 007a: bnei a3, 6, 95 <trc_update_ifx_phy_mode+0x75> */
L_7d:;
  a2 = (uint32_t)&rcLoRaSchedTbl; /* 007d: l32r a2, 14 <trc_update_ifx_phy_mode-0xc> (0 <trc_update_ifx_phy_mode-0x20>) */ /* literal @0x14: rcLoRaSchedTbl */
  a9 = (uint32_t)&rcLoRaSchedTbl; /* 0080: l32r a9, 18 <trc_update_ifx_phy_mode-0x8> (0 <trc_update_ifx_phy_mode-0x20>) */ /* literal @0x18: rcLoRaSchedTbl */
  MEM32(a8 + 96) = a2; /* 0083: s32i a2, a8, 96 */
  MEM32(a8 + 112) = a9; /* 0086: s32i a9, a8, 112 */
  MEM32(a8 + 100) = a9; /* 0089: s32i a9, a8, 100 */
  MEM32(a8 + 104) = a2; /* 008c: s32i a2, a8, 104 */
  MEMW(); /* 008f: memw  */
  goto L_a9; /* 0092: j a9 <trc_update_ifx_phy_mode+0x89> */
L_95:;
  a9 = (uint32_t)&rcP2P11GSchedTbl; /* 0095: l32r a9, 0 <trc_update_ifx_phy_mode-0x20> (0 <trc_update_ifx_phy_mode-0x20>) */ /* literal @0x0: rcP2P11GSchedTbl */
  if (a10 != 0) goto L_9d; /* 0098: bnez.n a10, 9d <trc_update_ifx_phy_mode+0x7d> */
L_9a:;
  a9 = (uint32_t)&rc11BSchedTbl; /* 009a: l32r a9, 4 <trc_update_ifx_phy_mode-0x1c> (0 <trc_update_ifx_phy_mode-0x20>) */ /* literal @0x4: rc11BSchedTbl */
L_9d:;
  MEM32(a8 + 96) = a9; /* 009d: s32i a9, a8, 96 */
  MEM32(a8 + 112) = a9; /* 00a0: s32i a9, a8, 112 */
  MEM32(a8 + 100) = a9; /* 00a3: s32i a9, a8, 100 */
  MEM32(a8 + 104) = a9; /* 00a6: s32i a9, a8, 104 */
L_a9:;
  a2 = 0x0; /* 00a9: movi.n a2, 0 */
L_ab:;
  MEMW(); /* 00ab: memw  */
  return (int32_t)a2; /* 00ae: retw.n  */
}

/* trc_deinit @ trc.o 00000008 size 44B bind GLOBAL
 * Calls: none | Data refs: .bss.g_per_conn_trc, g_osi_funcs_p
 *   MMIO: none
 *   funcdb v3: 0 call(s), 2 ref(s); disasm: 0 call(s), 2 data ref(s)
 * Fidelity: medium - 18 instr, 2 branches, calls resolved */
int32_t trc_deinit(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.trc_deinit; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_8:;
  /* 0008: entry a1, 32 */
  a2 = (uint32_t)&bss_g_per_conn_trc; /* 000b: l32r a2, 0 <trc_deinit-0x8> (0 <trc_deinit-0x8>) */ /* literal @0x0: .bss.g_per_conn_trc */
  a3 = 0x0; /* 000e: movi a3, 0 */
  a4 = (uint32_t)&g_osi_funcs_p; /* 0011: l32r a4, 4 <trc_deinit-0x4> (0 <trc_deinit-0x8>) */ /* literal @0x4: g_osi_funcs_p */
L_14:;
  a10 = MEM32(a2 + 0); /* 0014: l32i.n a10, a2, 0 */
  if (a10 == 0) goto L_24; /* 0016: beqz.n a10, 24 <trc_deinit+0x1c> */
  a8 = MEM32(a4 + 0); /* 0018: l32i.n a8, a4, 0 */
  a8 = MEM32(a8 + 176); /* 001a: l32i a8, a8, 176 */
  ((int32_t(*)())a8)(a2, a3, a4, a5); /* 001d: callx8 a8 */ /* indirect */
  a8 = 0x0; /* 0020: movi.n a8, 0 */
  MEM32(a2 + 0) = a8; /* 0022: s32i.n a8, a2, 0 */
L_24:;
  a3 = a3 + (1); /* 0024: addi.n a3, a3, 1 */
  a8 = 0x16; /* 0026: movi.n a8, 22 */
  a2 = a2 + (4); /* 0028: addi.n a2, a2, 4 */
  if (a3 != a8) goto L_14; /* 002a: bne a3, a8, 14 <trc_deinit+0xc> */
  a2 = 0x0; /* 002d: movi.n a2, 0 */
  MEMW(); /* 002f: memw  */
  return (int32_t)a2; /* 0032: retw.n  */
}

/* rc_set_per_conn_fix_rate @ trc.o 0000002c size 296B bind GLOBAL
 * Calls: rcSetTxAmpduLimit, rx11NRate2AMPDULimit, trcAmpduSetState, wifi_log, .text.trcResumeAmpdu$constprop$0[got], .text.trcStopAmpdu$constprop$0[got], .text.trcResumeAmpdu$constprop$0[got] | Data refs: .bss.g_per_conn_trc, .rodata_wlog_warning.24, rcSetTxAmpduLimit, rx11NRate2AMPDULimit, s_fix_rate, s_fix_rate_mask, trcAmpduSetState, wifi_log, .text.trcResumeAmpdu$constprop$0, .text.trcStopAmpdu$constprop$0
 *   MMIO: none
 *   funcdb v3: 4 call(s), 8 ref(s); disasm: 7 call(s), 10 data ref(s)
 * Fidelity: medium - 109 instr, 16 branches, calls resolved */
int32_t rc_set_per_conn_fix_rate(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.rc_set_per_conn_fix_rate; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_2c:;
  /* 002c: entry a1, 32 */
  a5 = (a2 >> 0) & 0xFF; /* 002f: extui a5, a2, 0, 8 */
  a3 = 0x15; /* 0032: movi.n a3, 21 */
  a2 = 0x102; /* 0034: movi a2, 0x102 */
  if (a3 >= a5) goto L_3d; /* 0037: bgeu a3, a5, 3d <rc_set_per_conn_fix_rate+0x11> */
  goto L_152; /* 003a: j 152 <rc_set_per_conn_fix_rate+0x126> */
L_3d:;
  a3 = (uint32_t)&bss_g_per_conn_trc; /* 003d: l32r a3, 0 <rc_set_per_conn_fix_rate-0x2c> (0 <rc_set_per_conn_fix_rate-0x2c>) */ /* literal @0x0: .bss.g_per_conn_trc */
  a3 = (a5 << 4) + a3; /* 0040: addx4 a3, a5, a3 */
  a3 = MEM32(a3 + 0); /* 0043: l32i.n a3, a3, 0 */
  if (a3 == 0) goto L_152; /* 0045: beqz a3, 152 <rc_set_per_conn_fix_rate+0x126> */
  a4 = 0x0; /* 0048: movi.n a4, 0 */
  a8 = 0x1; /* 004a: movi.n a8, 1 */
  a2 = 0x0; /* 004c: mov.n a2, a4 */
  a9 = a5 + (-19); /* 004e: addi a9, a5, -19 */
  if (a5 == 0) a4 = a8; /* 0051: moveqz a4, a8, a5 */
  if (a9 == 0) a2 = a8; /* 0054: moveqz a2, a8, a9 */
  a2 = a2 | a4; /* 0057: or a2, a2, a4 */
  a8 = a8 ^ a2; /* 005a: xor a8, a8, a2 */
  a2 = (uint32_t)&s_fix_rate_mask; /* 005d: l32r a2, 4 <rc_set_per_conn_fix_rate-0x28> (0 <rc_set_per_conn_fix_rate-0x2c>) */ /* literal @0x4: s_fix_rate_mask */
  a2 = MEM32(a2 + 0); /* 0060: l32i.n a2, a2, 0 */
  /* 0062: ssr a8 */ /* UNMODELED: a8 clobbered */
  /* 0065: srl a2, a2 */ /* UNMODELED: a2 clobbered */
  a2 = (a2 >> 0) & 0x1; /* 0068: extui a2, a2, 0, 1 */
  a4 = MEM8(a3 + 11); /* 006b: l8ui a4, a3, 11 */
  if (a2 == 0) goto L_130; /* 006e: beqz a2, 130 <rc_set_per_conn_fix_rate+0x104> */
  a5 = a8 << (2 & 31); /* 0071: slli a5, a8, 2 */
  a2 = (uint32_t)&s_fix_rate; /* 0074: l32r a2, 8 <rc_set_per_conn_fix_rate-0x24> (0 <rc_set_per_conn_fix_rate-0x2c>) */ /* literal @0x8: s_fix_rate */
  a8 = (a8 << 4) + a2; /* 0077: addx4 a8, a8, a2 */
  a8 = MEM32(a8 + 0); /* 007a: l32i.n a8, a8, 0 */
  a9 = (a8 >> 0) & 0xFF; /* 007c: extui a9, a8, 0, 8 */
  MEM8(a3 + 8) = a9; /* 007f: s8i a9, a3, 8 */
  MEM8(a3 + 9) = a9; /* 0082: s8i a9, a3, 9 */
  MEMW(); /* 0085: memw  */
  a9 = (a8 >> 0) & 0x7; /* 0088: extui a9, a8, 0, 3 */
  if (a9 < 3) goto L_e1; /* 008b: bltui a9, 3, e1 <rc_set_per_conn_fix_rate+0xb5> */
  a8 = a8 + (-16); /* 008e: addi a8, a8, -16 */
  a9 = 0xF; /* 0091: movi.n a9, 15 */
  if (a9 < a8) goto L_e1; /* 0093: bltu a9, a8, e1 <rc_set_per_conn_fix_rate+0xb5> */
  a8 = MEM8(a3 + 25); /* 0096: l8ui a8, a3, 25 */
  if (!((a8 >> 7) & 1)) goto L_ae; /* 0099: bbci a8, 7, ae <rc_set_per_conn_fix_rate+0x82> */
  a8 = MEM8(a3 + 14); /* 009c: l8ui a8, a3, 14 */
  if (a8 == 2) goto L_ae; /* 009f: beqi a8, 2, ae <rc_set_per_conn_fix_rate+0x82> */
  a10 = a3 | a3; /* 00a2: or a10, a3, a3 */
  MEMW(); /* 00a5: memw  */
  a8 = (uint32_t)&trcResumeAmpdu_constprop_0; /* 00a8: l32r a8, 10 <rc_set_per_conn_fix_rate-0x1c> (10 <rc_set_per_conn_fix_rate-0x1c>) */ /* literal: GOT slot for .text.trcResumeAmpdu$constprop$0 */
  trcResumeAmpdu_constprop_0(a2, a3, a4, a5); /* call via literal slot */ /* 00ab: callx8 a8 */
L_ae:;
  a5 = a2 + a5; /* 00ae: add.n a5, a2, a5 */
  a10 = MEM32(a5 + 0); /* 00b0: l32i.n a10, a5, 0 */
  a2 = 0x7; /* 00b2: movi.n a2, 7 */
  a2 = a4 | a2; /* 00b4: or a2, a4, a2 */
  MEM8(a3 + 10) = a10; /* 00b7: s8i a10, a3, 10 */
  a10 = (a10 >> 0) & 0xFF; /* 00ba: extui a10, a10, 0, 8 */
  MEM8(a3 + 11) = a2; /* 00bd: s8i a2, a3, 11 */
  MEMW(); /* 00c0: memw  */
  MEMW(); /* 00c3: memw  */
  a8 = (uint32_t)&rx11NRate2AMPDULimit; /* 00c6: l32r a8, 14 <rc_set_per_conn_fix_rate-0x18> (0 <rc_set_per_conn_fix_rate-0x2c>) */ /* literal: GOT slot for rx11NRate2AMPDULimit */
  rx11NRate2AMPDULimit(a2, a3, a4, a5); /* call via literal slot */ /* 00c9: callx8 a8 */
  if (a10 != 0) goto L_d2; /* 00cc: bnez.n a10, d2 <rc_set_per_conn_fix_rate+0xa6> */
  goto L_dc; /* 00ce: j dc <rc_set_per_conn_fix_rate+0xb0> */
  /* 00d1: .byte 00 */
L_d2:;
  a11 = a10; /* 00d2: mov.n a11, a10 */
  a10 = a3; /* 00d4: mov.n a10, a3 */
  a8 = (uint32_t)&rcSetTxAmpduLimit; /* 00d6: l32r a8, 18 <rc_set_per_conn_fix_rate-0x14> (0 <rc_set_per_conn_fix_rate-0x2c>) */ /* literal: GOT slot for rcSetTxAmpduLimit */
  rcSetTxAmpduLimit(a2, a3, a4, a5); /* call via literal slot */ /* 00d9: callx8 a8 */
L_dc:;
  a2 = 0x0; /* 00dc: movi.n a2, 0 */
  goto L_152; /* 00de: j 152 <rc_set_per_conn_fix_rate+0x126> */
L_e1:;
  a8 = 0xFFFFFFFB; /* 00e1: movi.n a8, -5 */
  a4 = a4 & a8; /* 00e3: and a4, a4, a8 */
  a8 = 0x3; /* 00e6: movi.n a8, 3 */
  a4 = a4 | a8; /* 00e8: or a4, a4, a8 */
  MEM8(a3 + 11) = a4; /* 00eb: s8i a4, a3, 11 */
  MEMW(); /* 00ee: memw  */
  a4 = MEM8(a3 + 14); /* 00f1: l8ui a4, a3, 14 */
  if (a4 != 2) goto L_118; /* 00f4: bnei a4, 2, 118 <rc_set_per_conn_fix_rate+0xec> */
  a10 = a3; /* 00f7: mov.n a10, a3 */
  MEMW(); /* 00f9: memw  */
  a8 = (uint32_t)&trcStopAmpdu_constprop_0; /* 00fc: l32r a8, 1c <rc_set_per_conn_fix_rate-0x10> (10 <rc_set_per_conn_fix_rate-0x1c>) */ /* literal: GOT slot for .text.trcStopAmpdu$constprop$0 */
  trcStopAmpdu_constprop_0(a2, a3, a4, a5); /* call via literal slot */ /* 00ff: callx8 a8 */
  a2 = a2 + a5; /* 0102: add.n a2, a2, a5 */
  a14 = MEM32(a2 + 0); /* 0104: l32i.n a14, a2, 0 */
  a12 = a4; /* 0106: mov.n a12, a4 */
  a11 = 0x40; /* 0108: movi.n a11, 64 */
  a10 = 0x6; /* 010a: movi.n a10, 6 */
  a13 = (uint32_t)&lit_rodata_wlog_warning_24; /* 010c: l32r a13, c <rc_set_per_conn_fix_rate-0x20> (0 <rc_set_per_conn_fix_rate-0x2c>) */ /* literal @0xC: .rodata_wlog_warning.24 */
  a8 = (uint32_t)&wifi_log; /* 010f: l32r a8, 20 <rc_set_per_conn_fix_rate-0xc> (0 <rc_set_per_conn_fix_rate-0x2c>) */ /* literal: GOT slot for wifi_log */
  wifi_log(a2, a3, a4, a5); /* call via literal slot */ /* 0112: callx8 a8 */
  goto L_dc; /* 0115: j dc <rc_set_per_conn_fix_rate+0xb0> */
L_118:;
  a11 = 0x1; /* 0118: movi.n a11, 1 */
  a10 = a3; /* 011a: mov.n a10, a3 */
  a2 = 0x1; /* 011c: movi.n a2, 1 */
  a8 = (uint32_t)&trcAmpduSetState; /* 011e: l32r a8, 24 <rc_set_per_conn_fix_rate-0x8> (0 <rc_set_per_conn_fix_rate-0x2c>) */ /* literal: GOT slot for trcAmpduSetState */
  trcAmpduSetState(a2, a3, a4, a5); /* call via literal slot */ /* 0121: callx8 a8 */
  MEM8(a3 + 14) = a2; /* 0124: s8i a2, a3, 14 */
  MEMW(); /* 0127: memw  */
  MEMW(); /* 012a: memw  */
  goto L_dc; /* 012d: j dc <rc_set_per_conn_fix_rate+0xb0> */
L_130:;
  a5 = 0xFFFFFFF8; /* 0130: movi.n a5, -8 */
  a4 = a4 & a5; /* 0132: and a4, a4, a5 */
  MEM8(a3 + 11) = a4; /* 0135: s8i a4, a3, 11 */
  MEMW(); /* 0138: memw  */
  a4 = MEM8(a3 + 25); /* 013b: l8ui a4, a3, 25 */
  if (!((a4 >> 7) & 1)) goto L_dc; /* 013e: bbci a4, 7, dc <rc_set_per_conn_fix_rate+0xb0> */
  a4 = MEM8(a3 + 14); /* 0141: l8ui a4, a3, 14 */
  if (a4 == 2) goto L_dc; /* 0144: beqi a4, 2, dc <rc_set_per_conn_fix_rate+0xb0> */
  a10 = a3; /* 0147: mov.n a10, a3 */
  MEMW(); /* 0149: memw  */
  a8 = (uint32_t)&trcResumeAmpdu_constprop_0; /* 014c: l32r a8, 28 <rc_set_per_conn_fix_rate-0x4> (10 <rc_set_per_conn_fix_rate-0x1c>) */ /* literal: GOT slot for .text.trcResumeAmpdu$constprop$0 */
  trcResumeAmpdu_constprop_0(a2, a3, a4, a5); /* call via literal slot */ /* 014f: callx8 a8 */
L_152:;
  return (int32_t)a2; /* 0152: retw.n  */
}

/* rc_enable_trc @ trc.o 0000002c size 208B bind GLOBAL
 * Calls: memcmp, memcpy, memset, rc_set_per_conn_fix_rate, wifi_log, g_osi_funcs_p[got] | Data refs: .bss.g_per_conn_trc, .rodata_wlog_error.17, .rodata_wlog_warning.18, g_osi_funcs_p, memcmp, memcpy, memset, rc_set_per_conn_fix_rate, trc_ctl, wifi_log
 *   MMIO: none
 *   funcdb v3: 5 call(s), 10 ref(s); disasm: 7 call(s), 10 data ref(s)
 * Fidelity: medium - 79 instr, 7 branches, calls resolved */
int32_t rc_enable_trc(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.rc_enable_trc; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_2c:;
  /* 002c: entry a1, 32 */
  a7 = (uint32_t)&bss_g_per_conn_trc; /* 002f: l32r a7, 0 <rc_enable_trc-0x2c> (0 <rc_enable_trc-0x2c>) */ /* literal @0x0: .bss.g_per_conn_trc */
  a4 = (a4 >> 0) & 0xFF; /* 0032: extui a4, a4, 0, 8 */
  a7 = (a4 << 4) + a7; /* 0035: addx4 a7, a4, a7 */
  a6 = (a2 >> 0) & 0xFF; /* 0038: extui a6, a2, 0, 8 */
  a5 = (a5 >> 0) & 0xFF; /* 003b: extui a5, a5, 0, 8 */
  a2 = MEM32(a7 + 0); /* 003e: l32i a2, a7, 0 */
  if (a2 != 0) goto L_70; /* 0041: bnez.n a2, 70 <rc_enable_trc+0x44> */
  a10 = 0x88; /* 0043: movi a10, 136 */
  a2 = (uint32_t)&g_osi_funcs_p; /* 0046: l32r a2, 4 <rc_enable_trc-0x28> (0 <rc_enable_trc-0x2c>) */ /* literal @0x4: g_osi_funcs_p */
  a2 = MEM32(a2 + 0); /* 0049: l32i a2, a2, 0 */
  a2 = MEM32(a2 + 376); /* 004c: l32i a2, a2, 0x178 */
  g_osi_funcs_p(a2, a3, a4, a5); /* call via literal slot */ /* 004f: callx8 a2 */
  a2 = 0x88; /* 0052: mov.n a2, a10 */
  MEM32(a7 + 0) = a10; /* 0054: s32i.n a10, a7, 0 */
  if (a10 != 0) goto L_b5; /* 0056: bnez a10, b5 <rc_enable_trc+0x89> */
  a13 = (uint32_t)&lit_rodata_wlog_error_17; /* 0059: l32r a13, 8 <rc_enable_trc-0x24> (0 <rc_enable_trc-0x2c>) */ /* literal @0x8: .rodata_wlog_error.17 */
  a12 = 0x1; /* 005c: movi.n a12, 1 */
  a11 = 0x200; /* 005e: movi a11, 0x200 */
  a10 = 0x6; /* 0061: movi.n a10, 6 */
  MEMW(); /* 0063: memw  */
  a8 = (uint32_t)&wifi_log; /* 0066: l32r a8, 14 <rc_enable_trc-0x18> (0 <rc_enable_trc-0x2c>) */ /* literal: GOT slot for wifi_log */
  wifi_log(a2, a3, a4, a5); /* call via literal slot */ /* 0069: callx8 a8 */
  goto L_fa; /* 006c: j fa <rc_enable_trc+0xce> */
  /* 006f: .byte 00 */
L_70:;
  a8 = (uint32_t)&trc_ctl; /* 0070: l32r a8, c <rc_enable_trc-0x20> (0 <rc_enable_trc-0x2c>) */ /* literal @0xC: trc_ctl */
  a7 = MEM32(a8 + 20); /* 0073: l32i.n a7, a8, 20 */
  if (!((a7 >> (a4 & 31)) & 1)) goto L_a8; /* 0075: bbc a7, a4, a8 <rc_enable_trc+0x7c> */
  a8 = (a6 << 4) + a8; /* 0078: addx4 a8, a6, a8 */
  a7 = MEM32(a8 + 4); /* 007b: l32i.n a7, a8, 4 */
  if (!((a7 >> (a4 & 31)) & 1)) goto L_90; /* 007d: bbc a7, a4, 90 <rc_enable_trc+0x64> */
  a12 = 0x6; /* 0080: movi.n a12, 6 */
  a11 = a3 | a3; /* 0082: or a11, a3, a3 */
  a10 = a2 + (31); /* 0085: addi a10, a2, 31 */
  a8 = (uint32_t)&memcmp; /* 0088: l32r a8, 18 <rc_enable_trc-0x14> (0 <rc_enable_trc-0x2c>) */ /* literal: GOT slot for memcmp */
  memcmp(a2, a3, a4, a5); /* call via literal slot */ /* 008b: callx8 a8 */
  if (a10 == 0) goto L_a8; /* 008e: beqz.n a10, a8 <rc_enable_trc+0x7c> */
L_90:;
  a13 = (uint32_t)&lit_rodata_wlog_warning_18; /* 0090: l32r a13, 10 <rc_enable_trc-0x1c> (0 <rc_enable_trc-0x2c>) */ /* literal @0x10: .rodata_wlog_warning.18 */
  a11 = 0x1; /* 0093: movi.n a11, 1 */
  a12 = 0x2; /* 0095: movi.n a12, 2 */
  a11 = 0x800; /* 0097: slli a11, a11, 11 */
  a10 = 0x6; /* 009a: movi.n a10, 6 */
  a8 = (uint32_t)&wifi_log; /* 009c: l32r a8, 1c <rc_enable_trc-0x10> (0 <rc_enable_trc-0x2c>) */ /* literal: GOT slot for wifi_log */
  wifi_log(a2, a3, a4, a5); /* call via literal slot */ /* 009f: callx8 a8 */
  a2 = 0x0; /* 00a2: movi.n a2, 0 */
  goto L_fa; /* 00a4: j fa <rc_enable_trc+0xce> */
  /* 00a7: .byte 00 */
L_a8:;
  a12 = 0x88; /* 00a8: movi a12, 136 */
  a11 = 0x0; /* 00ab: movi.n a11, 0 */
  a10 = 0x0; /* 00ad: mov.n a10, a2 */
  a8 = (uint32_t)&memset; /* 00af: l32r a8, 20 <rc_enable_trc-0xc> (0 <rc_enable_trc-0x2c>) */ /* literal: GOT slot for memset */
  memset(a2, a3, a4, a5); /* call via literal slot */ /* 00b2: callx8 a8 */
L_b5:;
  a8 = (uint32_t)&trc_ctl; /* 00b5: l32r a8, c <rc_enable_trc-0x20> (0 <rc_enable_trc-0x2c>) */ /* literal @0xC: trc_ctl */
  a9 = 0x1; /* 00b8: movi.n a9, 1 */
  /* 00ba: ssl a4 */ /* UNMODELED: a4 clobbered */
  /* 00bd: sll a9, a9 */ /* UNMODELED: a9 clobbered */
  a12 = 0x6; /* 00c0: movi.n a12, 6 */
  a11 = a3; /* 00c2: mov.n a11, a3 */
  a7 = MEM32(a8 + 20); /* 00c4: l32i.n a7, a8, 20 */
  a10 = a2 + (31); /* 00c6: addi a10, a2, 31 */
  a7 = a7 | a9; /* 00c9: or a7, a7, a9 */
  MEM32(a8 + 20) = a7; /* 00cc: s32i.n a7, a8, 20 */
  a8 = (a6 << 4) + a8; /* 00ce: addx4 a8, a6, a8 */
  a7 = MEM32(a8 + 4); /* 00d1: l32i.n a7, a8, 4 */
  a7 = a7 | a9; /* 00d3: or a7, a7, a9 */
  MEM8(a2 + 37) = a5; /* 00d6: s8i a5, a2, 37 */
  a5 = 0x0; /* 00d9: movi.n a5, 0 */
  MEM32(a8 + 4) = a7; /* 00db: s32i.n a7, a8, 4 */
  MEM8(a2 + 128) = a4; /* 00dd: s8i a4, a2, 128 */
  MEM8(a2 + 129) = a6; /* 00e0: s8i a6, a2, 129 */
  MEM8(a2 + 38) = a5; /* 00e3: s8i a5, a2, 38 */
  MEMW(); /* 00e6: memw  */
  MEMW(); /* 00e9: memw  */
  a8 = (uint32_t)&memcpy; /* 00ec: l32r a8, 24 <rc_enable_trc-0x8> (0 <rc_enable_trc-0x2c>) */ /* literal: GOT slot for memcpy */
  memcpy(a2, a3, a4, a5); /* call via literal slot */ /* 00ef: callx8 a8 */
  a10 = a4; /* 00f2: mov.n a10, a4 */
  a8 = (uint32_t)&rc_set_per_conn_fix_rate; /* 00f4: l32r a8, 28 <rc_enable_trc-0x4> (0 <rc_enable_trc-0x2c>) */ /* literal: GOT slot for rc_set_per_conn_fix_rate */
  rc_set_per_conn_fix_rate(a2, a3, a4, a5); /* call via literal slot */ /* 00f7: callx8 a8 */
L_fa:;
  return (int32_t)a2; /* 00fa: retw.n  */
}

/* rc_get_fix_rate @ trc.o 00000008 size 40B bind GLOBAL
 * Calls: none | Data refs: s_fix_rate, s_fix_rate_mask
 *   MMIO: none
 *   funcdb v3: 0 call(s), 2 ref(s); disasm: 0 call(s), 2 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t rc_get_fix_rate(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.rc_get_fix_rate; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_8:;
  /* 0008: entry a1, 32 */
  a8 = (uint32_t)&s_fix_rate; /* 000b: l32r a8, 0 <rc_get_fix_rate-0x8> (0 <rc_get_fix_rate-0x8>) */ /* literal @0x0: s_fix_rate */
  a8 = (a2 << 4) + a8; /* 000e: addx4 a8, a2, a8 */
  a8 = MEM32(a8 + 0); /* 0011: l32i.n a8, a8, 0 */
  MEM32(a4 + 0) = a8; /* 0013: s32i.n a8, a4, 0 */
  a8 = (uint32_t)&s_fix_rate_mask; /* 0015: l32r a8, 4 <rc_get_fix_rate-0x4> (0 <rc_get_fix_rate-0x8>) */ /* literal @0x4: s_fix_rate_mask */
  a8 = MEM32(a8 + 0); /* 0018: l32i.n a8, a8, 0 */
  /* 001a: ssr a2 */ /* UNMODELED: a2 clobbered */
  /* 001d: srl a8, a8 */ /* UNMODELED: a8 clobbered */
  a8 = (a8 >> 0) & 0x1; /* 0020: extui a8, a8, 0, 1 */
  a2 = 0x0; /* 0023: movi.n a2, 0 */
  MEM8(a3 + 0) = a8; /* 0025: s8i a8, a3, 0 */
  MEMW(); /* 0028: memw  */
  MEMW(); /* 002b: memw  */
  return (int32_t)a2; /* 002e: retw.n  */
}

/* rc_set_fix_rate @ trc.o 0000001c size 124B bind GLOBAL
 * Calls: rc_set_per_conn_fix_rate | Data refs: rc_set_per_conn_fix_rate, s_fix_rate, s_fix_rate_mask
 *   MMIO: none
 *   funcdb v3: 1 call(s), 3 ref(s); disasm: 5 call(s), 3 data ref(s)
 * Fidelity: medium - 49 instr, 8 branches, calls resolved */
int32_t rc_set_fix_rate(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.rc_set_fix_rate; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_1c:;
  /* 001c: entry a1, 32 */
  a11 = (uint32_t)&s_fix_rate_mask; /* 001f: l32r a11, 0 <rc_set_fix_rate-0x1c> (0 <rc_set_fix_rate-0x1c>) */ /* literal @0x0: s_fix_rate_mask */
  a8 = 0x1; /* 0022: movi.n a8, 1 */
  a3 = (a3 >> 0) & 0xFF; /* 0024: extui a3, a3, 0, 8 */
  a10 = a2; /* 0027: mov.n a10, a2 */
  /* 0029: ssl a2 */ /* UNMODELED: a2 clobbered */
  /* 002c: sll a8, a8 */ /* UNMODELED: a8 clobbered */
  a2 = MEM32(a11 + 0); /* 002f: l32i.n a2, a11, 0 */
  if (a3 == 0) goto L_39; /* 0031: beqz.n a3, 39 <rc_set_fix_rate+0x1d> */
  a2 = a8 | a2; /* 0033: or a2, a8, a2 */
  goto L_41; /* 0036: j 41 <rc_set_fix_rate+0x25> */
L_39:;
  a9 = 0xFFFFFFFF; /* 0039: movi.n a9, -1 */
  a8 = a9 ^ a8; /* 003b: xor a8, a9, a8 */
  a2 = a8 & a2; /* 003e: and a2, a8, a2 */
L_41:;
  MEM32(a11 + 0) = a2; /* 0041: s32i.n a2, a11, 0 */
  a2 = (uint32_t)&s_fix_rate; /* 0043: l32r a2, 4 <rc_set_fix_rate-0x18> (0 <rc_set_fix_rate-0x1c>) */ /* literal @0x4: s_fix_rate */
  a2 = (a10 << 4) + a2; /* 0046: addx4 a2, a10, a2 */
  MEM32(a2 + 0) = a4; /* 0049: s32i.n a4, a2, 0 */
  if (a10 != 0) goto L_5d; /* 004b: bnez.n a10, 5d <rc_set_fix_rate+0x41> */
  MEMW(); /* 004d: memw  */
  a8 = (uint32_t)&rc_set_per_conn_fix_rate; /* 0050: l32r a8, 8 <rc_set_fix_rate-0x14> (0 <rc_set_fix_rate-0x1c>) */ /* literal: GOT slot for rc_set_per_conn_fix_rate */
  rc_set_per_conn_fix_rate(a2, a3, a4, a5); /* call via literal slot */ /* 0053: callx8 a8 */
  a10 = 0x13; /* 0056: movi.n a10, 19 */
  goto L_8e; /* 0058: j 8e <rc_set_fix_rate+0x72> */
  /* 005b: .byte 00 */
  /* 005c: .byte 00 */
L_5d:;
  if (a10 != 1) goto L_79; /* 005d: bnei a10, 1, 79 <rc_set_fix_rate+0x5d> */
  a2 = 0x13; /* 0060: or a2, a10, a10 */
  a3 = 0x11; /* 0063: movi a3, 17 */
L_66:;
  a10 = 0x13; /* 0066: mov.n a10, a2 */
  a2 = 0x14; /* 0068: addi.n a2, a2, 1 */
  a8 = (uint32_t)&rc_set_per_conn_fix_rate; /* 006a: l32r a8, c <rc_set_fix_rate-0x10> (0 <rc_set_fix_rate-0x1c>) */ /* literal: GOT slot for rc_set_per_conn_fix_rate */
  rc_set_per_conn_fix_rate(a2, a3, a4, a5); /* call via literal slot */ /* 006d: callx8 a8 */
  if (a2 != a3) goto L_66; /* 0070: bne a2, a3, 66 <rc_set_fix_rate+0x4a> */
  a10 = 0x14; /* 0073: movi.n a10, 20 */
  goto L_8e; /* 0075: j 8e <rc_set_fix_rate+0x72> */
  /* 0078: .byte 00 */
L_79:;
  if (a10 != 2) goto L_94; /* 0079: bnei a10, 2, 94 <rc_set_fix_rate+0x78> */
  a10 = 0x11; /* 007c: movi.n a10, 17 */
  a8 = (uint32_t)&rc_set_per_conn_fix_rate; /* 007e: l32r a8, 10 <rc_set_fix_rate-0xc> (0 <rc_set_fix_rate-0x1c>) */ /* literal: GOT slot for rc_set_per_conn_fix_rate */
  rc_set_per_conn_fix_rate(a2, a3, a4, a5); /* call via literal slot */ /* 0081: callx8 a8 */
  a10 = 0x12; /* 0084: movi.n a10, 18 */
  a8 = (uint32_t)&rc_set_per_conn_fix_rate; /* 0086: l32r a8, 14 <rc_set_fix_rate-0x8> (0 <rc_set_fix_rate-0x1c>) */ /* literal: GOT slot for rc_set_per_conn_fix_rate */
  rc_set_per_conn_fix_rate(a2, a3, a4, a5); /* call via literal slot */ /* 0089: callx8 a8 */
  a10 = 0x15; /* 008c: movi.n a10, 21 */
L_8e:;
  a8 = (uint32_t)&rc_set_per_conn_fix_rate; /* 008e: l32r a8, 18 <rc_set_fix_rate-0x4> (0 <rc_set_fix_rate-0x1c>) */ /* literal: GOT slot for rc_set_per_conn_fix_rate */
  rc_set_per_conn_fix_rate(a2, a3, a4, a5); /* call via literal slot */ /* 0091: callx8 a8 */
L_94:;
  a2 = 0x0; /* 0094: movi.n a2, 0 */
  return (int32_t)a2; /* 0096: retw.n  */
}

/* trc_get_espnow_rate @ trc.o 00000004 size 16B bind GLOBAL
 * Calls: none | Data refs: .rodata.g_espnow_rate
 *   MMIO: none
 *   funcdb v3: 0 call(s), 1 ref(s); disasm: 0 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t trc_get_espnow_rate(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.trc_get_espnow_rate; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a8 = (uint32_t)&lit_rodata_g_espnow_rate; /* 0007: l32r a8, 0 <trc_get_espnow_rate-0x4> (0 <trc_get_espnow_rate-0x4>) */ /* literal @0x0: .rodata.g_espnow_rate */
  a2 = (a2 >> 0) & 0xFF; /* 000a: extui a2, a2, 0, 8 */
  a2 = (a2 << 4) + a8; /* 000d: addx4 a2, a2, a8 */
  a2 = MEM32(a2 + 0); /* 0010: l32i.n a2, a2, 0 */
  return (int32_t)a2; /* 0012: retw.n  */
}

/* trc_get_80211_tx_rate @ trc.o 00000004 size 16B bind GLOBAL
 * Calls: none | Data refs: .bss.g_80211_tx_rate
 *   MMIO: none
 *   funcdb v3: 0 call(s), 1 ref(s); disasm: 0 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t trc_get_80211_tx_rate(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.trc_get_80211_tx_rate; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a8 = (uint32_t)&bss_g_80211_tx_rate; /* 0007: l32r a8, 0 <trc_get_80211_tx_rate-0x4> (0 <trc_get_80211_tx_rate-0x4>) */ /* literal @0x0: .bss.g_80211_tx_rate */
  a2 = (a2 >> 0) & 0xFF; /* 000a: extui a2, a2, 0, 8 */
  a2 = (a2 << 4) + a8; /* 000d: addx4 a2, a2, a8 */
  a2 = MEM32(a2 + 0); /* 0010: l32i.n a2, a2, 0 */
  return (int32_t)a2; /* 0012: retw.n  */
}

/* trc_get_80211_tx_rate_config @ trc.o 00000008 size 27B bind GLOBAL
 * Calls: memcpy | Data refs: .bss.g_80211_tx_rate_config, memcpy
 *   MMIO: none
 *   funcdb v3: 1 call(s), 2 ref(s); disasm: 1 call(s), 2 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t trc_get_80211_tx_rate_config(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.trc_get_80211_tx_rate_config; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_8:;
  /* 0008: entry a1, 32 */
  a11 = (uint32_t)&bss_g_80211_tx_rate_config; /* 000b: l32r a11, 0 <trc_get_80211_tx_rate_config-0x8> (0 <trc_get_80211_tx_rate_config-0x8>) */ /* literal @0x0: .bss.g_80211_tx_rate_config */
  a2 = (a2 >> 0) & 0xFF; /* 000e: extui a2, a2, 0, 8 */
  a2 = (a2 << 2) + a2; /* 0011: addx2 a2, a2, a2 */
  a12 = 0xC; /* 0014: movi.n a12, 12 */
  a11 = (a2 << 4) + a11; /* 0016: addx4 a11, a2, a11 */
  a10 = a3; /* 0019: mov.n a10, a3 */
  a8 = (uint32_t)&memcpy; /* 001b: l32r a8, 4 <trc_get_80211_tx_rate_config-0x4> (0 <trc_get_80211_tx_rate_config-0x8>) */ /* literal: GOT slot for memcpy */
  memcpy(a2, a3, a4, a5); /* call via literal slot */ /* 001e: callx8 a8 */
  return (int32_t)a2; /* 0021: retw.n  */
}

/* trc_set_80211_tx_rate @ trc.o 00000004 size 19B bind GLOBAL
 * Calls: none | Data refs: .bss.g_80211_tx_rate
 *   MMIO: none
 *   funcdb v3: 0 call(s), 1 ref(s); disasm: 0 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t trc_set_80211_tx_rate(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.trc_set_80211_tx_rate; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a8 = (uint32_t)&bss_g_80211_tx_rate; /* 0007: l32r a8, 0 <trc_set_80211_tx_rate-0x4> (0 <trc_set_80211_tx_rate-0x4>) */ /* literal @0x0: .bss.g_80211_tx_rate */
  a2 = (a2 >> 0) & 0xFF; /* 000a: extui a2, a2, 0, 8 */
  a2 = (a2 << 4) + a8; /* 000d: addx4 a2, a2, a8 */
  MEM32(a2 + 0) = a3; /* 0010: s32i.n a3, a2, 0 */
  MEMW(); /* 0012: memw  */
  return (int32_t)a2; /* 0015: retw.n  */
}

/* trc_set_80211_tx_rate_config @ trc.o 00000008 size 27B bind GLOBAL
 * Calls: memcpy | Data refs: .bss.g_80211_tx_rate_config, memcpy
 *   MMIO: none
 *   funcdb v3: 1 call(s), 2 ref(s); disasm: 1 call(s), 2 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t trc_set_80211_tx_rate_config(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.trc_set_80211_tx_rate_config; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_8:;
  /* 0008: entry a1, 32 */
  a10 = (uint32_t)&bss_g_80211_tx_rate_config; /* 000b: l32r a10, 0 <trc_set_80211_tx_rate_config-0x8> (0 <trc_set_80211_tx_rate_config-0x8>) */ /* literal @0x0: .bss.g_80211_tx_rate_config */
  a2 = (a2 >> 0) & 0xFF; /* 000e: extui a2, a2, 0, 8 */
  a2 = (a2 << 2) + a2; /* 0011: addx2 a2, a2, a2 */
  a12 = 0xC; /* 0014: movi.n a12, 12 */
  a11 = a3; /* 0016: mov.n a11, a3 */
  a10 = (a2 << 4) + a10; /* 0018: addx4 a10, a2, a10 */
  a8 = (uint32_t)&memcpy; /* 001b: l32r a8, 4 <trc_set_80211_tx_rate_config-0x4> (0 <trc_set_80211_tx_rate_config-0x8>) */ /* literal: GOT slot for memcpy */
  memcpy(a2, a3, a4, a5); /* call via literal slot */ /* 001e: callx8 a8 */
  return (int32_t)a2; /* 0021: retw.n  */
}

/* rc11NRate2SchedIdx @ trc.o 00000000 size 87B bind LOCAL
 * Calls: none | Data refs: none
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: low - 28 instr, 8 branches, jx computed tail dispatch (+0x15 jx a2); rate-to-sched-index mapping structural - need jump-table case decode to raise */
static int32_t rc11NRate2SchedIdx(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.rc11NRate2SchedIdx; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
  /* 0000: .word 0x00000000 (literal pool) */
  /* 0004: entry a1, 32 */
  a9 = (a2 >> 0) & 0xFF; /* 0007: extui a9, a2, 0, 8 */
  if (a9 >= 7) goto L_1d; /* 000a: bgeui a9, 7, 1d <.text.rc11NRate2SchedIdx+0x1d> */
  a2 = 0x0; /* 000d: l32r a2, 0 <.text.rc11NRate2SchedIdx> (0 <.text.rc11NRate2SchedIdx>) */ @0x0
  a2 = (a9 << 4) + a2; /* 0010: addx4 a2, a9, a2 */
  a2 = MEM32(a2 + 0); /* 0013: l32i.n a2, a2, 0 */
  /* 0015: jx a2 */ /* jx a2: computed tail jump; modeled as return */
  return (int32_t)a2;
  a2 = 0x9; /* 0018: movi.n a2, 9 */
  goto L_48; /* 001a: j 48 <.text.rc11NRate2SchedIdx+0x48> */
L_1d:;
  a8 = 0x29; /* 001d: movi.n a8, 41 */
  a2 = 0xD; /* 001f: movi.n a2, 13 */
  if (a9 == a8) goto L_48; /* 0021: beq a9, a8, 48 <.text.rc11NRate2SchedIdx+0x48> */
  a8 = 0x2A; /* 0024: movi.n a8, 42 */
  a2 = 0xC; /* 0026: movi.n a2, 12 */
  if (a9 == a8) goto L_48; /* 0028: beq a9, a8, 48 <.text.rc11NRate2SchedIdx+0x48> */
  a8 = 0x1F; /* 002b: movi.n a8, 31 */
  a2 = 0x0; /* 002d: movi.n a2, 0 */
  if (a9 == a8) goto L_48; /* 002f: beq a9, a8, 48 <.text.rc11NRate2SchedIdx+0x48> */
  goto L_3b; /* 0032: j 3b <.text.rc11NRate2SchedIdx+0x3b> */
  /* 0035: .byte 00 */
  a2 = 0xB; /* 0036: movi.n a2, 11 */
  goto L_48; /* 0038: j 48 <.text.rc11NRate2SchedIdx+0x48> */
L_3b:;
  a8 = 0x18; /* 003b: movi.n a8, 24 */
  a2 = a8 - a9; /* 003d: sub a2, a8, a9 */
  a2 = (a2 >> 0) & 0xFF; /* 0040: extui a2, a2, 0, 8 */
  goto L_48; /* 0043: j 48 <.text.rc11NRate2SchedIdx+0x48> */
  a2 = 0xA; /* 0046: movi.n a2, 10 */
L_48:;
  return (int32_t)a2; /* 0048: retw.n  */
}

/* rc11GRate2SchedIdx @ trc.o 00000000 size 30B bind LOCAL
 * Calls: none | Data refs: none
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
static int32_t rc11GRate2SchedIdx(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.rc11GRate2SchedIdx; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
  /* 0000: .word 0x00000000 (literal pool) */
  /* 0004: entry a1, 32 */
  a9 = (a2 >> 0) & 0xFF; /* 0007: extui a9, a2, 0, 8 */
  a8 = 0x2A; /* 000a: movi.n a8, 42 */
  a2 = 0xFF; /* 000c: movi a2, 255 */
  if (a8 < a9) goto L_1a; /* 000f: bltu a8, a9, 1a <.text.rc11GRate2SchedIdx+0x1a> */
  a8 = 0x0; /* 0012: l32r a8, 0 <.text.rc11GRate2SchedIdx> (0 <.text.rc11GRate2SchedIdx>) */ @0x0
  a8 = a8 + a9; /* 0015: add.n a8, a8, a9 */
  a2 = MEM8(a8 + 0); /* 0017: l8ui a2, a8, 0 */
L_1a:;
  return (int32_t)a2; /* 001a: retw.n  */
}

/* rc11BRate2SchedIdx @ trc.o 00000000 size 30B bind LOCAL
 * Calls: none | Data refs: none
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
static int32_t rc11BRate2SchedIdx(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.rc11BRate2SchedIdx; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
  /* 0000: .word 0x00000000 (literal pool) */
  /* 0004: entry a1, 32 */
  a9 = (a2 >> 0) & 0xFF; /* 0007: extui a9, a2, 0, 8 */
  a8 = 0x2A; /* 000a: movi.n a8, 42 */
  a2 = 0xFF; /* 000c: movi a2, 255 */
  if (a8 < a9) goto L_1a; /* 000f: bltu a8, a9, 1a <.text.rc11BRate2SchedIdx+0x1a> */
  a8 = 0x0; /* 0012: l32r a8, 0 <.text.rc11BRate2SchedIdx> (0 <.text.rc11BRate2SchedIdx>) */ @0x0
  a8 = a8 + a9; /* 0015: add.n a8, a8, a9 */
  a2 = MEM8(a8 + 0); /* 0017: l8ui a2, a8, 0 */
L_1a:;
  return (int32_t)a2; /* 001a: retw.n  */
}

/* rcBuildIndex @ trc.o 00000000 size 42B bind LOCAL
 * Calls: none | Data refs: none
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
static int32_t rcBuildIndex(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.rcBuildIndex; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_0:;
  /* 0000: entry a1, 32 */
  a3 = a3 + (-1); /* 0003: addi.n a3, a3, -1 */
  a3 = (a3 >> 0) & 0xFF; /* 0005: extui a3, a3, 0, 8 */
  a8 = 0x0; /* 0008: movi.n a8, 0 */
  a3 = a3 + (1); /* 000a: addi.n a3, a3, 1 */
L_c:;
  MEM8(a2 + 10) = a8; /* 000c: s8i a8, a2, 10 */
  MEMW(); /* 000f: memw  */
  a8 = 0x1; /* 0012: addi.n a8, a8, 1 */
  a8 = 0x1; /* 0014: extui a8, a8, 0, 8 */
  a2 = a2 + (12); /* 0017: addi.n a2, a2, 12 */
  a3 = a3 + (-1); /* 0019: addi.n a3, a3, -1 */
  if (a3 != 0) goto L_c; /* 001b: bnez a3, c <.text.rcBuildIndex+0xc> */
  MEMW(); /* 001e: memw  */
  return (int32_t)a2; /* 0021: retw.n  */
}

/* trcResumeAmpdu_constprop_0 @ trc.o 00000000 size 105B bind LOCAL
 * Calls: trcAmpduSetState[got], rcClearCurAMPDUSched[got], trc_onAmpduOp[got] | Data refs: trcAmpduSetState, rcClearCurAMPDUSched, trc_onAmpduOp
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 3 call(s), 3 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
static int32_t trcResumeAmpdu_constprop_0(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.trcResumeAmpdu$constprop$0; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
  /* 0010: entry a1, 32 */
  a3 = 0x0; /* 0013: l32r a3, 0 <.text.trcResumeAmpdu$constprop$0> (0 <.text.trcResumeAmpdu$constprop$0>) */ @0x0
  a11 = 0x4; /* 0016: movi.n a11, 4 */
  a10 = a2; /* 0018: mov.n a10, a2 */
  a4 = 0x2; /* 001a: movi a4, 2 */
  a8 = MEM8(a3 + 25); /* 001d: l8ui a8, a3, 25 */
  a8 = a8 + (-2); /* 0020: addi a8, a8, -2 */
  a8 = (a8 >> 0) & 0xFF; /* 0023: extui a8, a8, 0, 8 */
  a8 = (a8 << 2) + a8; /* 0026: addx2 a8, a8, a8 */
  a3 = MEM32(a2 + 112); /* 0029: l32i a3, a2, 112 */
  a8 = (a8 << 4) + a3; /* 002c: addx4 a8, a8, a3 */
  a3 = MEM8(a8 + 0); /* 002f: l8ui a3, a8, 0 */
  MEM8(a2 + 13) = a3; /* 0032: s8i a3, a2, 13 */
  MEMW(); /* 0035: memw  */
  MEMW(); /* 0038: memw  */
  a8 = (uint32_t)&trcAmpduSetState; /* 003b: l32r a8, 4 <.text.trcResumeAmpdu$constprop$0+0x4> (0 <.text.trcResumeAmpdu$constprop$0>) */ /* literal: GOT slot for trcAmpduSetState */
  trcAmpduSetState(a2, a3, a4, a5); /* call via literal slot */ /* 003e: callx8 a8 */
  a3 = 0x4; /* 0041: movi a3, 4 */
  a10 = a2 | a2; /* 0044: or a10, a2, a2 */
  MEM8(a2 + 14) = a3; /* 0047: s8i a3, a2, 14 */
  MEMW(); /* 004a: memw  */
  MEMW(); /* 004d: memw  */
  a8 = (uint32_t)&rcClearCurAMPDUSched; /* 0050: l32r a8, 8 <.text.trcResumeAmpdu$constprop$0+0x8> (0 <.text.trcResumeAmpdu$constprop$0>) */ /* literal: GOT slot for rcClearCurAMPDUSched */
  rcClearCurAMPDUSched(a2, a3, a4, a5); /* call via literal slot */ /* 0053: callx8 a8 */
  a3 = 0x0; /* 0056: movi.n a3, 0 */
L_58:;
  a8 = MEM8(a2 + 16); /* 0058: l8ui a8, a2, 16 */
  if (!((a8 >> (a3 & 31)) & 1)) goto L_6a; /* 005b: bbc a8, a3, 6a <.text.trcResumeAmpdu$constprop$0+0x6a> */
  a12 = 0x0; /* 005e: mov.n a12, a3 */
  a11 = a4; /* 0060: mov.n a11, a4 */
  a10 = a2; /* 0062: mov.n a10, a2 */
  a8 = (uint32_t)&trc_onAmpduOp; /* 0064: l32r a8, c <.text.trcResumeAmpdu$constprop$0+0xc> (0 <.text.trcResumeAmpdu$constprop$0>) */ /* literal: GOT slot for trc_onAmpduOp */
  trc_onAmpduOp(a2, a3, a4, a5); /* call via literal slot */ /* 0067: callx8 a8 */
L_6a:;
  a3 = a3 + (1); /* 006a: addi.n a3, a3, 1 */
  if (a3 != 8) goto L_58; /* 006c: bnei a3, 8, 58 <.text.trcResumeAmpdu$constprop$0+0x58> */
  return (int32_t)a2; /* 006f: retw.n  */
}

/* trcStopAmpdu_constprop_0 @ trc.o 00000000 size 96B bind LOCAL
 * Calls: trcAmpduSetState[got], rcClearCurSched[got], trc_onAmpduOp[got] | Data refs: trcAmpduSetState, rcClearCurSched, trc_onAmpduOp
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 3 call(s), 3 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
static int32_t trcStopAmpdu_constprop_0(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.trcStopAmpdu$constprop$0; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
  /* 0010: entry a1, 32 */
  a3 = 0x0; /* 0013: l32r a3, 0 <.text.trcStopAmpdu$constprop$0> (0 <.text.trcStopAmpdu$constprop$0>) */ @0x0
  a11 = 0x3; /* 0016: movi.n a11, 3 */
  a10 = a2; /* 0018: mov.n a10, a2 */
  a4 = 0x3; /* 001a: movi a4, 3 */
  a3 = MEM8(a3 + 24); /* 001d: l8ui a3, a3, 24 */
  a8 = (uint32_t)&trcAmpduSetState; /* 0020: l32r a8, 4 <.text.trcStopAmpdu$constprop$0+0x4> (0 <.text.trcStopAmpdu$constprop$0>) */ /* literal: GOT slot for trcAmpduSetState */
  trcAmpduSetState(a2, a3, a4, a5); /* call via literal slot */ /* 0023: callx8 a8 */
  a3 = a3 + (-1); /* 0026: addi.n a3, a3, -1 */
  a3 = (a3 >> 0) & 0xFF; /* 0028: extui a3, a3, 0, 8 */
  a3 = (a3 << 2) + a3; /* 002b: addx2 a3, a3, a3 */
  MEM8(a2 + 14) = a4; /* 002e: s8i a4, a2, 14 */
  MEMW(); /* 0031: memw  */
  a10 = a2; /* 0034: mov.n a10, a2 */
  a4 = MEM32(a2 + 112); /* 0036: l32i a4, a2, 112 */
  a3 = (a3 << 4) + a4; /* 0039: addx4 a3, a3, a4 */
  a4 = 0x3; /* 003c: movi.n a4, 3 */
  MEM32(a2 + 96) = a3; /* 003e: s32i a3, a2, 96 */
  MEMW(); /* 0041: memw  */
  a8 = (uint32_t)&rcClearCurSched; /* 0044: l32r a8, 8 <.text.trcStopAmpdu$constprop$0+0x8> (0 <.text.trcStopAmpdu$constprop$0>) */ /* literal: GOT slot for rcClearCurSched */
  rcClearCurSched(a2, a3, a4, a5); /* call via literal slot */ /* 0047: callx8 a8 */
  a3 = 0x0; /* 004a: movi.n a3, 0 */
L_4c:;
  a8 = MEM8(a2 + 16); /* 004c: l8ui a8, a2, 16 */
  if (!((a8 >> (a3 & 31)) & 1)) goto L_5e; /* 004f: bbc a8, a3, 5e <.text.trcStopAmpdu$constprop$0+0x5e> */
  a12 = 0x0; /* 0052: mov.n a12, a3 */
  a11 = a4; /* 0054: mov.n a11, a4 */
  a10 = a2; /* 0056: mov.n a10, a2 */
  a8 = (uint32_t)&trc_onAmpduOp; /* 0058: l32r a8, c <.text.trcStopAmpdu$constprop$0+0xc> (0 <.text.trcStopAmpdu$constprop$0>) */ /* literal: GOT slot for trc_onAmpduOp */
  trc_onAmpduOp(a2, a3, a4, a5); /* call via literal slot */ /* 005b: callx8 a8 */
L_5e:;
  a3 = a3 + (1); /* 005e: addi.n a3, a3, 1 */
  if (a3 != 8) goto L_4c; /* 0060: bnei a3, 8, 4c <.text.trcStopAmpdu$constprop$0+0x4c> */
  return (int32_t)a2; /* 0063: retw.n  */
}

