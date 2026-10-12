/* ===== pp.o : reconstructed from libpp.a (ESP32, Xtensa, esp-2022r1) =====
 * Toolchain: xtensa-esp32-elf (GCC 11.2.0 crosstool-NG esp-2022r1).
 * ABI: args a2..a7, return a2 (all functions take a2..a7, return int32_t).
 * memw barriers preserved as MEMW(). MMIO as REG32/REG16/REG8(addr).
 * Calls with unknown arg counts are modeled with 4 live args (a2..a5);
 * a2..a7 are clobbered across calls (windowed-ABI approximation).
 * Sections: .iram1.67, .text.DefFreqCalTimerCB, .text.RxNodeNum, .text.SigSpaceFree, .text.SigSpaceMalloc, .text.TxNodeNum, .text.emul_timeout, .text.esp_wifi_enable_easy_fragment, .text.getle32, .text.ppAddTimCount, .text.ppAssembleMicHdr, .text.ppCalTkipMic, .text.ppCheckIsConnTraffic, .text.ppCheckTxAMPDUlength, .text.ppCheckTxConnTrafficIdle, .text.ppCheckTxIdle, .text.ppCheckTxQIdle, .text.ppClearAlldataTxq_ifx, .text.ppClearRxFragment, .text.ppClearTxq, .text.ppDequeueTxQ, .text.ppDisableQueue, .text.ppDiscardMPDU, .text.ppEnableQueue, .text.ppFetchTxQFirstAvail, .text.ppFillAMPDUBar, .text.ppGetTaskHdl, .text.ppGetTxQFirstAvail_Locked, .text.ppInitTxq, .text.ppMessageInQ, .text.ppPrepareBarFrame, .text.ppProcessWaitQ, .text.ppReSendBar, .text.ppRecordBarRRC, .text.ppRecycleTxBuf, .text.ppRegisterPromisRxCallback, .text.ppRegisterRxCallback, .text.ppRegisterTxCallback, .text.ppRegisterTxDoneUserActionCallback, .text.ppRollBackTxQ, .text.ppSetBarRate, .text.ppSetInterface, .text.ppTxqEmpty, .text.ppUnregisterTxCallback, .text.pp_attach, .text.pp_can_cut_evt, .text.pp_can_cut_sevt, .text.pp_create_task, .text.pp_deattach, .text.pp_default_event_handler, .text.pp_delete_task, .text.pp_delete_task_manually, .text.pp_gettid, .text.pp_register_config_cb, .text.pp_register_michael_mic_failure_cb, .text.pp_register_net80211_tx_cb, .text.pp_register_timer_cb, .text.pp_register_tx_cb, .text.pp_set_cut_evt, .text.pp_set_cut_rx, .text.pp_stop_sw_txq, .text.pp_unregister_tx_cb, .text.putle32, .text.rotl, .text.rotr, .text.xswap, .wifi0iram.11, .wifi0iram.12, .wifi0iram.19, .wifi0iram.22, .wifi0iram.23, .wifi0iram.34, .wifi0iram.35, .wifi0iram.36, .wifi0iram.38, .wifi0iram.42, .wifi0iram.45, .wifi0iram.61, .wifi0iram.63, .wifi0iram.66, .wifi0iram.69, .wifi0iram.7, .wifi0iram.71, .wifi0iram.75, .wifi0iram.9, .wifiextrairam.16, .wifiextrairam.18, .wifiextrairam.20, .wifiextrairam.33, .wifiextrairam.37, .wifiextrairam.39, .wifiextrairam.41, .wifiextrairam.44, .wifiextrairam.48, .wifiextrairam.50, .wifiextrairam.60, .wifiextrairam.62, .wifiextrairam.64, .wifiextrairam.65, .wifiextrairam.72, .wifiextrairam.73, .wifiextrairam.74, .wifirxiram.26, .wifirxiram.29, .wifirxiram.6, .wifislpiram.5, .wifislprxiram.24, .wifislprxiram.30, .wifislprxiram.51, .wifislprxiram.52
 * Undefined refs (70): GetAccess, RC_GetAckTime, RC_GetBlockAckTime, RC_GetCtsTime, chm_get_current_band, config_get_wifi_task_stack_size, config_is_cache_tx_buf_enabled, dbg_lmac_init, esf_buf_alloc, esf_buf_recycle, esf_buf_setdown, esf_buf_setup, g_intr_lock_mux, g_lmac_cnt, g_mesh_init_ps_type, g_mesh_is_root, g_mesh_is_started, g_offchan_packet_lifetime, g_osi_funcs_p, g_wifi_global_lock, g_wifi_mac_time_delta, g_wifi_menuconfig, ic_get_ptk_alg, ic_interface_enabled...
 */
#include <stdint.h>
#define REG32(a) (*(volatile uint32_t *)(a))
#define REG16(a) (*(volatile uint16_t *)(a))
#define REG8(a)  (*(volatile uint8_t *)(a))
#define MEM32(a) (*(volatile uint32_t *)(a))
#define MEM16(a) (*(volatile uint16_t *)(a))
#define MEM8(a)  (*(volatile uint8_t *)(a))
#define MEMW() __asm__ volatile("memw" ::: "memory")

extern int32_t pp_need_cut_rx();
extern int32_t pp_allow_cut_sevt();
extern uint32_t wDevCtrl; /* wDevCtrl */
extern int32_t pTxRx();
extern int32_t CurFreeSigIdx();
extern int32_t SigInMacISR();
extern int32_t CanDoFreqCal();
extern int32_t g_osi_funcs_p();
extern int32_t bss_g_net80211_tx_func();
extern uint32_t bss_g_config_func; /* .bss.g_config_func (verify defined-here with nm) */
extern int32_t bss_g_timer_func();
extern int32_t bss_s_michael_mic_failure_cb();
extern int32_t config_is_cache_tx_buf_enabled();
extern uint32_t rodata_pp_default_event_handler_str1_1; /* .rodata.pp_default_event_handler.str1.1 */
extern uint32_t rodata_wlog_error_8; /* .rodata_wlog_error.8 */
extern int32_t wifi_log();
extern int32_t bss_g_tx_done_cb_func();
extern uint32_t rodata_wlog_error_17; /* .rodata_wlog_error.17 */
extern int32_t wDev_AppendRxBlocks();
extern int32_t esf_buf_recycle();
extern int32_t lmacIsIdle();
extern int32_t lmacGetTxFrame();
extern int32_t pm_coex_reconnect_policy();
extern int32_t chm_get_current_band();
extern int32_t pm_on_data_rx();
extern int32_t pm_sleep_for();
extern int32_t pm_set_beacon_duration();
extern int32_t pm_on_beacon_rx();
extern int32_t rc_get_trc();
extern int32_t rcUpdateRxDone();
extern int32_t memcpy();
extern int32_t s_fragment();
extern int32_t roundup2();
extern uint32_t rodata_wlog_info_25; /* .rodata_wlog_info.25 */
extern uint32_t g_mesh_is_started; /* g_mesh_is_started */
extern uint32_t g_mesh_is_root; /* g_mesh_is_root */
extern uint32_t g_mesh_init_ps_type; /* g_mesh_init_ps_type */
extern uint32_t g_wifi_mac_time_delta; /* g_wifi_mac_time_delta */
extern uint32_t lmacConfMib; /* lmacConfMib */
extern int32_t ic_get_ptk_alg();
extern uint32_t rodata_wlog_warning_27; /* .rodata_wlog_warning.27 */
extern uint32_t g_lmac_cnt; /* g_lmac_cnt */
extern uint32_t rodata_wlog_warning_28; /* .rodata_wlog_warning.28 */
extern int32_t memcmp();
extern int32_t ic_obtain_key();
extern int32_t rcSetBarRate();
extern int32_t bars();
extern int32_t rcGetRate();
extern int32_t lmacTxFrame();
extern uint32_t rodata_wlog_error_49; /* .rodata_wlog_error.49 */
extern int32_t trc_onPPTxDone();
extern uint32_t rodata_wlog_info_21; /* .rodata_wlog_info.21 */
extern int32_t pm_on_data_tx_done();
extern int32_t wDevCheckBlockError();
extern uint32_t rodata_wlog_error_31; /* .rodata_wlog_error.31 */
extern uint32_t g_wifi_menuconfig; /* g_wifi_menuconfig */
extern uint32_t bss_pp_task_hdl; /* .bss.pp_task_hdl (verify defined-here with nm) */
extern uint32_t rodata_wlog_warning_53; /* .rodata_wlog_warning.53 */
extern int32_t s_wifi_queue();
extern uint32_t rodata_wlog_warning_54; /* .rodata_wlog_warning.54 */
extern uint32_t rodata_wlog_error_55; /* .rodata_wlog_error.55 */
extern int32_t xphyQueue();
extern uint32_t rodata_wlog_error_56; /* .rodata_wlog_error.56 */
extern int32_t bss_s_pp_task_create_sem();
extern uint32_t rodata_wlog_error_57; /* .rodata_wlog_error.57 */
extern int32_t config_get_wifi_task_stack_size();
extern uint32_t rodata_pp_create_task_str1_1; /* .rodata.pp_create_task.str1.1 */
extern uint32_t rodata_wlog_error_58; /* .rodata_wlog_error.58 */
extern uint32_t rodata_wlog_info_59; /* .rodata_wlog_info.59 */
extern int32_t esf_buf_setdown();
extern int32_t GetAccess();
extern int32_t lmacAdjustTimestamp();
extern int32_t is_lmac_idle();
extern int32_t g_intr_lock_mux();
extern int32_t pp_sig_cnt();
extern uint32_t rodata_wlog_warning_68; /* .rodata_wlog_warning.68 */
extern int32_t bss_s_pp_task_del_sem();
extern uint32_t bss_current_ifidx_0; /* .bss.current_ifidx$0 (verify defined-here with nm) */
extern int32_t pm_allow_tx();
extern int32_t pm_on_data_tx();
extern uint32_t rodata_CSWTCH_622; /* .rodata.CSWTCH$622 */
extern uint32_t rodata_wlog_error_70; /* .rodata_wlog_error.70 */
extern int32_t RC_GetBlockAckTime();
extern int32_t RC_GetAckTime();
extern int32_t RC_GetCtsTime();
extern int32_t ic_interface_enabled();
extern uint32_t rodata_wlog_warning_13; /* .rodata_wlog_warning.13 */
extern uint32_t rodata_wlog_error_14; /* .rodata_wlog_error.14 */
extern int32_t rcGetSched();
extern uint32_t rodata_wlog_warning_15; /* .rodata_wlog_warning.15 */
extern int32_t esf_buf_alloc();
extern uint32_t rodata_wlog_warning_32; /* .rodata_wlog_warning.32 */
extern int32_t rc_get_trc_by_index();
extern int32_t memset();
extern int32_t TxRxCxt();
extern int32_t dbg_lmac_init();
extern int32_t esf_buf_setup();
extern uint32_t rodata_wlog_error_40; /* .rodata_wlog_error.40 */
extern int32_t rcGetAmpduSched();
extern uint32_t rodata_wlog_error_43; /* .rodata_wlog_error.43 */
extern int32_t pm_is_waked();
extern int32_t trc_isTxAmpduOperational();
extern int32_t trc_tid_isTxAmpduOperational();
extern uint32_t rodata_wlog_error_46; /* .rodata_wlog_error.46 */
extern int32_t lmacMSDUAged();
extern int32_t lmacRecycleMPDU();
extern int32_t lmacDiscardAgedMSDU();
extern int32_t rcUpdateTxDoneAmpdu2();
extern int32_t rodata();
extern int32_t pp_timer_do_process();
extern int32_t lmacProcessTxTimeout();
extern int32_t lmacProcessTxComplete();
extern int32_t lmacProcessCollisions_task();
extern int32_t wifi_gpio_debug();
extern int32_t wdevProcessRxSucDataAll();
extern int32_t wdev_process_misc_pkt();
extern uint32_t rodata_wlog_error_10; /* .rodata_wlog_error.10 */
extern uint32_t g_wifi_global_lock; /* g_wifi_global_lock */
extern int32_t pm_get_null_max_tx_time();
extern uint32_t g_offchan_packet_lifetime; /* g_offchan_packet_lifetime */
extern uint32_t rodata_wlog_error_76; /* .rodata_wlog_error.76 */

/* pool[pp_delete_task_manually]: +0x0=0x00000000, +0x4=0x00000000, +0x8=0x00000000 */
/* pool[xswap]: +0x0=0xFF00FF00, +0x4=0x00FF00FF */
/* pool[pp_set_cut_rx]: +0x0=0x00000000(pp_need_cut_rx) */
/* pool[pp_set_cut_evt]: +0x0=0x00000000(pp_allow_cut_sevt) */
/* pool[pp_can_cut_sevt]: +0x0=0x00000000(pp_allow_cut_sevt) */
/* pool[pp_can_cut_evt]: +0x0=0x00000000(pp_need_cut_rx), +0x4=0x00000000(pp_allow_cut_sevt) */
/* pool[RxNodeNum]: +0x0=0x00000000(wDevCtrl) */
/* pool[SigSpaceMalloc]: +0x0=0x00000000(pTxRx), +0x4=0x00000000(CurFreeSigIdx), +0x8=0x00000000(SigInMacISR) */
/* pool[SigSpaceFree]: +0x0=0x00000000(pTxRx) */
/* pool[DefFreqCalTimerCB]: +0x0=0x00000000(CanDoFreqCal) */
/* pool[ppProcessRxPktHdr]: +0x0=0x00000000(pTxRx), +0x4=0x00000000(g_osi_funcs_p) */
/* pool[pp_register_net80211_tx_cb]: +0x0=0x00000000(.bss.g_net80211_tx_func) */
/* pool[pp_register_config_cb]: +0x0=0x00000000(.bss.g_config_func) */
/* pool[pp_register_timer_cb]: +0x0=0x00000000(.bss.g_timer_func) */
/* pool[pp_register_michael_mic_failure_cb]: +0x0=0x00000000(.bss.s_michael_mic_failure_cb) */
/* pool[pp_process_hmac_waiting_txq]: +0x4=0x00000000(config_is_cache_tx_buf_enabled), +0x0=0x00000000(.bss.g_net80211_tx_func) */
/* pool[pp_default_event_handler]: +0x0=0x00000000(.rodata.pp_default_event_handler.str1.1), +0x4=0x00000000(.rodata_wlog_error.8), +0x8=0x00000000(wifi_log) */
/* pool[ppAddTimCount]: +0x0=0x00000000(pp_hdrsize) */
/* pool[ppRegisterPromisRxCallback]: +0x0=0x00000000(pTxRx) */
/* pool[ppRegisterTxDoneUserActionCallback]: +0x0=0x00000000(.bss.g_tx_done_cb_func) */
/* pool[ppRegisterRxCallback]: +0x0=0x00000000(pTxRx) */
/* pool[ppRegisterTxCallback]: +0x0=0x00000000(pTxRx) */
/* pool[ppUnregisterTxCallback]: +0x0=0x00000000(pTxRx) */
/* pool[pp_register_tx_cb]: +0x0=0x00000000(ppRegisterTxCallback) */
/* pool[pp_unregister_tx_cb]: +0x0=0x00000000(ppUnregisterTxCallback) */
/* pool[ppRecycleRxPkt]: +0x0=0x00000000(pTxRx), +0x4=0x00000000(.rodata.pp_default_event_handler.str1.1), +0x8=0x00000000(.rodata_wlog_error.17), +0xc=0x00000000(wifi_log), +0x10=0x00000000(wDev_AppendRxBlocks), +0x14=0x00000000(esf_buf_recycle) */
/* pool[ppCheckTxQIdle]: +0x0=0x00000000(lmacIsIdle) */
/* pool[ppCheckTxConnTrafficIdle]: +0x4=0x00000000(lmacGetTxFrame), +0x8=0x00000000(ppCheckIsConnTraffic), +0x0=0x00000000(pTxRx), +0xc=0x00000000(ppCheckIsConnTraffic), +0x10=0x00000000(ppCheckIsConnTraffic), +0x14=0x00000000(ppCheckIsConnTraffic), +0x18=0x00000000(ppCheckIsConnTraffic) */
/* pool[pp_coex_tx_release]: +0x0=0x00000000(g_osi_funcs_p) */
/* pool[ppProcTxCallback]: +0x0=0x00000000(pTxRx) */
/* pool[pp_coex_tx_request]: +0x0=0x00000000(g_osi_funcs_p), +0x4=0x00000000(pm_coex_reconnect_policy), +0x8=0x00000000(chm_get_current_band), +0xc=0x00000000(pm_coex_reconnect_policy) */
/* pool[ppRxProtoProc]: +0x0=0x00000000(pm_on_data_rx), +0x4=0x00000000(pp_hdrsize), +0x8=0x00000000(pm_sleep_for), +0xc=0x00000000(pm_set_beacon_duration), +0x10=0x00000000(pm_on_beacon_rx), +0x14=0x00000000(rc_get_trc), +0x18=0x00000000(rcUpdateRxDone) */
/* pool[ppAssembleMicHdr]: +0x0=0x00000000(memcpy), +0x4=0x00000000(memcpy), +0x8=0x00000000(memcpy), +0xc=0x00000000(memcpy), +0x10=0x00000000(pp_gettid) */
/* pool[ppCalTkipMic]: +0x0=0x00000000(s_fragment), +0x4=0x00000000(roundup2), +0x8=0x00000000(ppAssembleMicHdr), +0xc=0x00000000(memcpy), +0x10=0x00000000(getle32), +0x14=0x00000000(getle32), +0x18=0x00000000(getle32), +0x1c=0x00000000(xswap), +0x20=0x00000000(putle32), +0x24=0x00000000(putle32) */
/* pool[ppClearRxFragment]: +0x0=0x00000000(s_fragment), +0x4=0x00000000(.rodata_wlog_info.25), +0x8=0x00000000(wifi_log), +0xc=0x00000000(ppRecycleRxPkt) */
/* pool[ppRxFragmentProc]: +0x0=0x00000000(s_fragment), +0x4=0x00000000(g_mesh_is_started), +0x8=0x00000000(g_mesh_is_root), +0xc=0x00000000(g_mesh_init_ps_type), +0x10=0x00000000(g_osi_funcs_p), +0x14=0x3FF73C00, +0x18=0x00000000(g_wifi_mac_time_delta), +0x1c=0x00000000(lmacConfMib), +0x3c=0x00000000(ppRecycleRxPkt), +0x40=0x00000000(ic_get_ptk_alg), +0x20=0x00000000(.rodata_wlog_warning.27), +0x24=0x00000000(g_lmac_cnt), +0x44=0x00000000(pp_hdrsize), +0x28=0x00000000(.rodata_wlog_warning.28), +0x48=0x00000000(wifi_log), +0x4c=0x00000000(ppRecycleRxPkt), +0x50=0x00000000(pp_gettid), +0x54=0x00000000(pp_gettid), +0x58=0x00000000(memcmp), +0x2c=0x00000000(pTxRx), +0x5c=0x00000000(memcpy), +0x30=0xFF0000FF, +0x34=0xF000FFFF, +0x60=0x00000000(ppRecycleRxPkt), +0x64=0x00000000(memcpy), +0x68=0x00000000(ic_obtain_key), +0x6c=0x00000000(ppCalTkipMic), +0x70=0x00000000(memcmp), +0x38=0x00000000(.bss.s_michael_mic_failure_cb), +0x74=0x00000000(ppRecycleRxPkt), +0x78=0x00000000(ppRecycleRxPkt), +0x7c=0x00000000(ppRecycleRxPkt) */
/* pool[ppGetTxQFirstAvail_Locked]: +0x0=0x00000000(pTxRx) */
/* pool[ppFetchTxQFirstAvail]: +0x0=0x00000000(pTxRx) */
/* pool[ppDequeueTxQ]: +0x0=0x00000000(pTxRx) */
/* pool[ppRollBackTxQ]: +0x0=0x00000000(pTxRx) */
/* pool[ppSetBarRate]: +0x0=0x00000000(pTxRx), +0x4=0x00000000(rcSetBarRate) */
/* pool[ppFillAMPDUBar]: +0x0=0x00000000(pTxRx), +0x4=0x00000000(bars), +0x8=0xDFFFFFFF, +0xc=0xFF000FFF, +0x10=0x00000000(memcpy), +0x14=0x00000000(memcpy) */
/* pool[ppPauseTxAMPDU]: +0x0=0x00000000(pTxRx) */
/* pool[ppResumeTxAMPDU]: +0x0=0x00000000(pTxRx) */
/* pool[ppCalSubFrameLength]: +0x0=0x00000000(roundup2) */
/* pool[ppCheckTxAMPDUlength]: +0x4=0x00000000(roundup2), +0x0=0x00000000(pTxRx) */
/* pool[ppReSendBar]: +0x0=0x00000000(pTxRx), +0x4=0xFF0FFFFF, +0x8=0x00000000(g_mesh_is_started), +0xc=0x00000000(g_mesh_is_root), +0x10=0x00000000(g_mesh_init_ps_type), +0x14=0x00000000(g_osi_funcs_p), +0x18=0x3FF73C00, +0x1c=0x00000000(g_wifi_mac_time_delta), +0x2c=0x00000000(rcGetRate), +0x20=0x00000000(bars), +0x24=0xDFFFFFFF, +0x28=0xFF000FFF, +0x30=0x00000000(lmacTxFrame) */
/* pool[ppRecordBarRRC]: +0x0=0x00000000(pTxRx) */
/* pool[ppTxqUpdateBitmap]: +0x0=0x00000000(pTxRx) */
/* pool[ppEnqueueTxDone]: +0x0=0x00000000(.rodata.pp_default_event_handler.str1.1), +0x4=0x00000000(.rodata_wlog_error.49), +0xc=0x00000000(wifi_log), +0x8=0x00000000(pTxRx) */
/* pool[ppDequeueTxDone_Locked]: +0x0=0x00000000(pTxRx) */
/* pool[ppProcTxDone]: +0x18=0x00000000(ppProcTxCallback), +0x1c=0x00000000(pp_coex_tx_release), +0x0=0x00000000(g_mesh_is_started), +0x4=0x00080008, +0x20=0x00000000(trc_onPPTxDone), +0x8=0x00000000(.bss.g_tx_done_cb_func), +0xc=0xFF000FFF, +0x10=0xFF7FFFFF, +0x14=0x00000000(.rodata_wlog_info.21), +0x24=0x00000000(wifi_log), +0x28=0x00000000(esf_buf_recycle), +0x2c=0x00000000(ppDequeueTxDone_Locked), +0x30=0x00000000(pp_process_hmac_waiting_txq), +0x34=0x00000000(pm_on_data_tx_done) */
/* pool[ppEnqueueRxq]: +0x0=0x00000000(pTxRx) */
/* pool[ppDequeueRxq_Locked]: +0x0=0x00000000(pTxRx) */
/* pool[ppRxPkt]: +0x0=0x00000000(pTxRx), +0xc=0x00000000(wDevCheckBlockError), +0x10=0x00000000(ppRxProtoProc), +0x14=0x00000000(ppRxFragmentProc), +0x18=0x00000000(ppRxProtoProc), +0x1c=0x00000000(is_fragmented_pkt), +0x4=0x00000000(.bss.s_michael_mic_failure_cb), +0x8=0x00000000(.rodata_wlog_error.31), +0x20=0x00000000(wifi_log), +0x24=0x00000000(ppRecycleRxPkt), +0x28=0x00000000(ppDequeueRxq_Locked) */
/* pool[pp_create_task]: +0x0=0x00000000(g_wifi_menuconfig), +0x4=0x00000000(g_osi_funcs_p), +0x8=0x00000000(.bss.pp_task_hdl), +0xc=0x00000000(.rodata_wlog_warning.53), +0x3c=0x00000000(wifi_log), +0x10=0x00000000(s_wifi_queue), +0x14=0x00000000(.rodata_wlog_warning.54), +0x40=0x00000000(wifi_log), +0x18=0x00000000(.rodata_wlog_error.55), +0x44=0x00000000(wifi_log), +0x1c=0x00000000(xphyQueue), +0x20=0x00000000(.rodata_wlog_error.56), +0x24=0x00000000(.bss.s_pp_task_create_sem), +0x28=0x00000000(.rodata_wlog_error.57), +0x48=0x00000000(config_get_wifi_task_stack_size), +0x2c=0x00000000(.rodata.pp_create_task.str1.1), +0x30=0x00000000(ppTask), +0x34=0x00000000(.rodata_wlog_error.58), +0x4c=0x00000000(wifi_log), +0x50=0x00000000(config_get_wifi_task_stack_size), +0x38=0x00000000(.rodata_wlog_info.59), +0x54=0x00000000(wifi_log) */
/* pool[pp_deattach]: +0x0=0x00000000(pTxRx), +0x4=0x00000000(esf_buf_recycle), +0x8=0x00000000(esf_buf_setdown) */
/* pool[ppGetTxframe]: +0x0=0x00000000(pTxRx), +0x4=0x00000000(GetAccess), +0x8=0x00000000(lmacAdjustTimestamp) */
/* pool[ppInitTxq]: +0x0=0x00000000(pTxRx), +0x4=0x0D0A0704 */
/* pool[ppEnableQueue]: +0x0=0x00000000(pTxRx) */
/* pool[ppSearchTxQueue]: +0x0=0x00000000(pTxRx), +0x4=0x0000FFFF, +0x8=0x00000000(ppEnableQueue) */
/* pool[ppTxqEmpty]: +0x4=0x00000000(is_lmac_idle), +0x0=0x00000000(pTxRx) */
/* pool[pp_post]: +0x0=0x00000000(g_osi_funcs_p), +0x4=0x00000000(g_intr_lock_mux), +0x8=0x00000000(pp_sig_cnt), +0xc=0x00000000(xphyQueue), +0x10=0x00000000(pTxRx), +0x14=0x00000000(.rodata_wlog_warning.68), +0x18=0x00000000(wifi_log) */
/* pool[pp_delete_task]: +0x0=0x00000000(.bss.pp_task_hdl), +0x4=0x00000000(s_wifi_queue), +0x8=0x00000000(g_osi_funcs_p), +0xc=0x00000000(.bss.s_pp_task_del_sem), +0x10=0x00000000(pp_post), +0x14=0x0000000C(.text.pp_delete_task_manually), +0x18=0x0000000C(.text.pp_delete_task_manually) */
/* pool[ppMapWaitTxq]: +0x0=0x00000000(pTxRx), +0x4=0x0000FFFF, +0xc=0x00000000(ppSearchTxQueue), +0x8=0xFF0FFFFF, +0x10=0x00000000(pp_post) */
/* pool[ppProcessWaitingQueue]: +0x0=0x00000000(.bss.current_ifidx$0), +0x4=0x00000000(pm_allow_tx), +0x8=0x00000000(ppMapWaitTxq) */
/* pool[ppProcessWaitQ]: +0x0=0x00000000(ppProcessWaitingQueue) */
/* pool[ppDisableQueue]: +0x0=0x00000000(pTxRx), +0x4=0x00000000(ppProcessWaitingQueue) */
/* pool[ppCheckTxIdle]: +0x4=0x00000000(lmacIsIdle), +0x8=0x00000000(ppDisableQueue), +0x0=0x00000000(pTxRx) */
/* pool[ppSelectNextQueue]: +0x0=0x00000000(pTxRx), +0x4=0x00000000(ppDisableQueue) */
/* pool[ppSearchTxframe]: +0x4=0x00000000(ppGetTxframe), +0x8=0x00000000(ppSelectNextQueue), +0x0=0x00000000(pTxRx), +0xc=0x00000000(ppGetTxframe), +0x10=0x00000000(ppGetTxframe), +0x14=0x00000000(ppGetTxframe) */
/* pool[ppMapTxQueue]: +0x8=0x00000000(ppProcessWaitingQueue), +0x0=0xFF0FFFFF, +0xc=0x00000000(pm_on_data_tx), +0x10=0x00000000(pm_on_data_tx), +0x4=0x00000000(g_mesh_is_started), +0x14=0x00000000(ppSearchTxQueue), +0x18=0x00000000(pm_on_data_tx), +0x1c=0x00000000(ppSearchTxQueue) */
/* pool[ppDiscardMPDU]: +0x0=0x00000000(ppEnqueueTxDone), +0x4=0x00000000(pp_post) */
/* pool[ppProcTxSecFrame]: +0x0=0x00000000(.rodata.CSWTCH$622), +0x4=0xFF000FFF, +0x8=0x000011A3, +0xc=0x00000000(.rodata.pp_default_event_handler.str1.1), +0x10=0x00000000(.rodata_wlog_error.70), +0x18=0x00000000(wifi_log), +0x14=0xFFC80FFF */
/* pool[ppCalFrameTimes]: +0x0=0x00000000(RC_GetBlockAckTime), +0x4=0x00000000(RC_GetAckTime), +0x8=0x00000000(RC_GetCtsTime) */
/* pool[ppTxPkt]: +0x2c=0x00000000(ic_interface_enabled), +0x0=0x00000000(.rodata_wlog_warning.13), +0x30=0x00000000(wifi_log), +0x4=0x00000000(.rodata.pp_default_event_handler.str1.1), +0x8=0x00000000(.rodata_wlog_error.14), +0x34=0x00000000(wifi_log), +0x38=0x00000000(ppTxProtoProc), +0x3c=0x00000000(ppProcTxSecFrame), +0x40=0x00000000(rcGetSched), +0x44=0x00000000(ppCalFrameTimes), +0x48=0x00000000(ppMapTxQueue), +0xc=0x00000000(g_mesh_is_started), +0x10=0x00000000(g_mesh_is_root), +0x14=0x00000000(g_mesh_init_ps_type), +0x18=0x00000000(g_osi_funcs_p), +0x1c=0x3FF73C00, +0x20=0x00000000(g_wifi_mac_time_delta), +0x24=0x00000000(pTxRx), +0x4c=0x00000000(lmacIsIdle), +0x50=0x00000000(pp_post), +0x28=0x00000000(.rodata_wlog_warning.15), +0x54=0x00000000(wifi_log), +0x58=0x00000000(esf_buf_recycle), +0x5c=0x00000000(pp_process_hmac_waiting_txq) */
/* pool[ppPrepareBarFrame]: +0x8=0x00000000(esf_buf_alloc), +0x0=0x00000000(.rodata_wlog_warning.32), +0xc=0x00000000(wifi_log), +0x4=0x00000000(bars), +0x10=0x00000000(rc_get_trc_by_index), +0x14=0x00000000(rcGetSched), +0x18=0x00000000(ppCalFrameTimes) */
/* pool[pp_attach]: +0x0=0x00000000(pp_sig_cnt), +0x10=0x00000000(memset), +0x4=0x00000000(bars), +0x14=0x00000000(memset), +0x8=0x00000000(TxRxCxt), +0x18=0x00000000(memset), +0xc=0x00000000(pTxRx), +0x1c=0x00000000(dbg_lmac_init), +0x20=0x00000000(ppInitTxq), +0x24=0x00000000(esf_buf_setup), +0x28=0x00000000(pp_deattach), +0x2c=0x00000000(ppPrepareBarFrame) */
/* pool[ppAssembleAMPDU]: +0x0=0x00000B73, +0x4=0x00000000(.rodata.pp_default_event_handler.str1.1), +0x8=0x00000000(.rodata_wlog_error.40), +0xc=0x00000000(wifi_log), +0x10=0x00000000(ppCalFrameTimes) */
/* pool[ppCalTxAMPDULength]: +0x14=0x00000000(rcGetAmpduSched), +0x0=0x00000000(pTxRx), +0x4=0xBFFFFFFF, +0x18=0x00000000(ppCheckTxAMPDUlength), +0x1c=0x00000000(ppEmptyDelimiterLength), +0x20=0x00000000(ppCalSubFrameLength), +0x24=0x00000000(ppCalSubFrameLength), +0x8=0x00000C2F, +0xc=0x00000000(.rodata.pp_default_event_handler.str1.1), +0x10=0x00000000(.rodata_wlog_error.43), +0x28=0x00000000(wifi_log), +0x2c=0x00000000(lmacAdjustTimestamp), +0x30=0x00000000(ppCheckTxAMPDUlength), +0x34=0x00000000(ppEmptyDelimiterLength), +0x38=0x00000000(ppEmptyDelimiterLength), +0x3c=0x00000000(ppAssembleAMPDU), +0x40=0x00000000(ppPauseTxAMPDU) */
/* pool[ppAMPDU2Normal]: +0x0=0xDFFFFFFF, +0x4=0xFF000FFF, +0x8=0xFFB3FEFF, +0xc=0x00000000(rcGetSched), +0x10=0x00000000(ppCalFrameTimes) */
/* pool[ppProcessTxQ]: +0xc=0x00000000(lmacIsIdle), +0x0=0x00000000(g_mesh_is_started), +0x10=0x00000000(ppSearchTxframe), +0x4=0x00000000(g_mesh_is_root), +0x14=0x00000000(pm_is_waked), +0x18=0x00000000(ppAMPDU2Normal), +0x1c=0x00000000(trc_isTxAmpduOperational), +0x20=0x00000000(trc_tid_isTxAmpduOperational), +0x24=0x00000000(ppCalTxAMPDULength), +0x8=0x00000000(pTxRx), +0x28=0x00000000(pp_coex_tx_request), +0x2c=0x00000000(lmacTxFrame) */
/* pool[ppResortTxAMPDU]: +0x0=0x00000000(pTxRx), +0xc=0x00000000(GetAccess), +0x4=0x00000000(.rodata.pp_default_event_handler.str1.1), +0x8=0x00000000(.rodata_wlog_error.46), +0x10=0x00000000(wifi_log), +0x14=0x00000000(memcpy), +0x18=0x00000000(lmacMSDUAged), +0x1c=0x00000000(ppCalSubFrameLength), +0x20=0x00000000(ppSubFromAMPDU), +0x24=0x00000000(lmacRecycleMPDU), +0x28=0x00000000(lmacDiscardAgedMSDU), +0x2c=0x00000000(rcUpdateTxDoneAmpdu2), +0x30=0x00000000(trc_isTxAmpduOperational), +0x34=0x00000000(trc_tid_isTxAmpduOperational), +0x38=0x00000000(ppAMPDU2Normal), +0x3c=0x00000000(ppFillAMPDUBar), +0x40=0x00000000(ppReSendBar), +0x44=0x00000000(ppResumeTxAMPDU), +0x48=0x00000000(ppProcessTxQ) */
/* pool[ppTask]: +0x4=0x00000000(g_osi_funcs_p), +0x0=0x00000000(.bss.s_pp_task_create_sem), +0x8=0x00000000(xphyQueue), +0xc=0x00000000(g_intr_lock_mux), +0x10=0x00000000(pp_sig_cnt), +0x14=0x00000000(.rodata), +0x34=0x00000000(pp_timer_do_process), +0x18=0x00000000(.bss.g_timer_func), +0x1c=0x00000000(.bss.g_config_func), +0x38=0x00000000(ppProcessTxQ), +0x20=0x00000000(.bss.g_net80211_tx_func), +0x3c=0x00000000(ppProcTxDone), +0x40=0x00000000(ppRxPkt), +0x44=0x00000000(ppResortTxAMPDU), +0x48=0x00000000(ppProcessRxPktHdr), +0x4c=0x00000000(lmacProcessTxTimeout), +0x50=0x00000000(lmacProcessTxComplete), +0x54=0x00000000(lmacProcessCollisions_task), +0x58=0x00000000(wifi_gpio_debug), +0x5c=0x00000000(wdevProcessRxSucDataAll), +0x60=0x00000000(wdev_process_misc_pkt), +0x24=0x00000000(.rodata_wlog_error.10), +0x64=0x00000000(wifi_log), +0x68=0x00000000(pp_default_event_handler), +0x28=0x00000000(.bss.s_pp_task_del_sem), +0x2c=0x00000000(s_wifi_queue), +0x30=0x00000000(.bss.pp_task_hdl) */
/* pool[ppDirectRecycleAmpdu]: +0x0=0x00000000(pTxRx), +0x4=0x00000000(ppResumeTxAMPDU), +0x8=0x00000000(esf_buf_recycle) */
/* pool[ppClearTxq]: +0x0=0x00000000(pTxRx), +0x4=0x00000000(ppDirectRecycleAmpdu), +0x8=0x00000000(esf_buf_recycle), +0xc=0x00000000(ppDequeueTxQ) */
/* pool[ppClearAlldataTxq_ifx]: +0x4=0x00000000(g_osi_funcs_p), +0x0=0x00000000(g_wifi_global_lock), +0xc=0x00000000(esf_buf_recycle), +0x8=0x00000000(pTxRx), +0x10=0x00000000(ppClearTxq) */
/* pool[pp_stop_sw_txq]: +0x4=0x00000000(esf_buf_recycle), +0x0=0x00000000(pTxRx), +0x8=0x00000000(ppClearTxq), +0xc=0x00000000(esf_buf_recycle), +0x10=0x00000000(ppDequeueTxDone_Locked), +0x14=0x00000000(ppClearRxFragment) */
/* pool[ppRecycleAmpdu]: +0x4=0x00000000(GetAccess), +0x0=0x00000000(pTxRx), +0x8=0x00000000(ppResumeTxAMPDU), +0xc=0x00000000(lmacDiscardAgedMSDU), +0x10=0x00000000(lmacDiscardAgedMSDU) */
/* pool[ppRegressAmpdu]: +0x4=0x00000000(ppAMPDU2Normal), +0x0=0x00000000(pTxRx), +0x8=0x00000000(ppResumeTxAMPDU), +0xc=0x00000000(pp_post) */
/* pool[ppGetTaskHdl]: +0x0=0x00000000(.bss.pp_task_hdl) */
/* pool[ppMessageInQ]: +0x4=0x00000000(g_osi_funcs_p), +0x0=0x00000000(xphyQueue) */
/* pool[ppProcessLifeTime]: +0x0=0x00000000(lmacConfMib), +0x4=0x00010020, +0x18=0x00000000(pm_get_null_max_tx_time), +0x8=0x00000000(g_offchan_packet_lifetime), +0xc=0x00001281, +0x10=0x00000000(.rodata.pp_default_event_handler.str1.1), +0x14=0x00000000(.rodata_wlog_error.76), +0x1c=0x00000000(wifi_log) */

/* pp_hdrsize @ pp.o 00000000 size 40B bind GLOBAL
 * Calls: none | Data refs: none
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t pp_hdrsize(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .wifislpiram.5; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_0:;
  /* 0000: entry a1, 32 */
  a9 = MEM8(a2 + 1); /* 0003: l8ui a9, a2, 1 */
  a10 = a2; /* 0006: mov.n a10, a2 */
  a9 = (a9 >> 0) & 0x3; /* 0008: extui a9, a9, 0, 2 */
  a9 = a9 + (-3); /* 000b: addi a9, a9, -3 */
  a8 = 0x18; /* 000e: movi.n a8, 24 */
  a2 = 0x1E; /* 0010: movi.n a2, 30 */
  if (a9 != 0) a2 = a8; /* 0012: movnez a2, a8, a9 */
  a8 = MEM8(a10 + 0); /* 0015: l8ui a8, a10, 0 */
  a9 = 0x8C; /* 0018: movi a9, 140 */
  a8 = a8 & a9; /* 001b: and a8, a8, a9 */
  a9 = 0x88; /* 001e: movi a9, 136 */
  if (a8 != a9) goto L_26; /* 0021: bne a8, a9, 26 <pp_hdrsize+0x26> */
  a2 = a2 + (2); /* 0024: addi.n a2, a2, 2 */
L_26:;
  return (int32_t)a2; /* 0026: retw.n  */
}

/* getle32 @ pp.o 00000000 size 35B bind GLOBAL
 * Calls: none | Data refs: none
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t getle32(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.getle32; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_0:;
  /* 0000: entry a1, 32 */
  a9 = MEM8(a2 + 1); /* 0003: l8ui a9, a2, 1 */
  a9 = a9 << (8 & 31); /* 0006: slli a9, a9, 8 */
  a8 = MEM8(a2 + 0); /* 0009: l8ui a8, a2, 0 */
  a9 = a9 | a8; /* 000c: or a9, a9, a8 */
  a8 = MEM8(a2 + 2); /* 000f: l8ui a8, a2, 2 */
  a8 = a8 << (16 & 31); /* 0012: slli a8, a8, 16 */
  a8 = a8 | a9; /* 0015: or a8, a8, a9 */
  a2 = MEM8(a2 + 3); /* 0018: l8ui a2, a2, 3 */
  a2 = a2 << (24 & 31); /* 001b: slli a2, a2, 24 */
  a2 = a2 | a8; /* 001e: or a2, a2, a8 */
  return (int32_t)a2; /* 0021: retw.n  */
}

/* putle32 @ pp.o 00000000 size 32B bind GLOBAL
 * Calls: none | Data refs: none
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t putle32(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.putle32; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_0:;
  /* 0000: entry a1, 32 */
  a8 = a3 >> (8 & 31); /* 0003: srli a8, a3, 8 */
  MEM8(a2 + 0) = a3; /* 0006: s8i a3, a2, 0 */
  MEM8(a2 + 1) = a8; /* 0009: s8i a8, a2, 1 */
  a8 = (a3 >> 16) & 0xFFFF; /* 000c: extui a8, a3, 16, 16 */
  a3 = (a3 >> 24) & 0xFF; /* 000f: extui a3, a3, 24, 8 */
  MEM8(a2 + 2) = a8; /* 0012: s8i a8, a2, 2 */
  MEM8(a2 + 3) = a3; /* 0015: s8i a3, a2, 3 */
  MEMW(); /* 0018: memw  */
  MEMW(); /* 001b: memw  */
  return (int32_t)a2; /* 001e: retw.n  */
}

/* rotl @ pp.o 00000000 size 11B bind GLOBAL
 * Calls: none | Data refs: none
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t rotl(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.rotl; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_0:;
  /* 0000: entry a1, 32 */
  /* 0003: ssl a3 */ /* UNMODELED: a3 clobbered */
  /* 0006: src a2, a2, a2 */ /* UNMODELED: a2 clobbered */
  return (int32_t)a2; /* 0009: retw.n  */
}

/* rotr @ pp.o 00000000 size 11B bind GLOBAL
 * Calls: none | Data refs: none
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t rotr(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.rotr; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_0:;
  /* 0000: entry a1, 32 */
  /* 0003: ssr a3 */ /* UNMODELED: a3 clobbered */
  /* 0006: src a2, a2, a2 */ /* UNMODELED: a2 clobbered */
  return (int32_t)a2; /* 0009: retw.n  */
}

/* xswap @ pp.o 00000008 size 26B bind GLOBAL
 * Calls: none | Data refs: none
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t xswap(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.xswap; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_8:;
  /* 0008: entry a1, 32 */
  a9 = 0xFF00FF00; /* 000b: l32r a9, 0 <xswap-0x8> (ff00ff00 <ppRxFragmentProc+0xff00fe80>) */ @0x0
  a8 = a2 << (8 & 31); /* 000e: slli a8, a2, 8 */
  a8 = a8 & a9; /* 0011: and a8, a8, a9 */
  a2 = a2 >> (8 & 31); /* 0014: srli a2, a2, 8 */
  a9 = 0xFF00FF; /* 0017: l32r a9, 4 <xswap-0x4> (ff00ff <ppRxFragmentProc+0xff007f>) */ @0x4
  a2 = a2 & a9; /* 001a: and a2, a2, a9 */
  a2 = a8 | a2; /* 001d: or a2, a8, a2 */
  return (int32_t)a2; /* 0020: retw.n  */
}

/* pp_set_cut_rx @ pp.o 00000004 size 17B bind GLOBAL
 * Calls: none | Data refs: pp_need_cut_rx
 *   MMIO: none
 *   funcdb v3: 0 call(s), 1 ref(s); disasm: 0 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t pp_set_cut_rx(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pp_set_cut_rx; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a8 = (uint32_t)&pp_need_cut_rx; /* 0007: l32r a8, 0 <pp_set_cut_rx-0x4> (0 <pp_set_cut_rx-0x4>) */ /* literal @0x0: pp_need_cut_rx */
  MEM8(a8 + 0) = a2; /* 000a: s8i a2, a8, 0 */
  MEMW(); /* 000d: memw  */
  MEMW(); /* 0010: memw  */
  return (int32_t)a2; /* 0013: retw.n  */
}

/* pp_set_cut_evt @ pp.o 00000004 size 17B bind GLOBAL
 * Calls: none | Data refs: pp_allow_cut_sevt
 *   MMIO: none
 *   funcdb v3: 0 call(s), 1 ref(s); disasm: 0 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t pp_set_cut_evt(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pp_set_cut_evt; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a8 = (uint32_t)&pp_allow_cut_sevt; /* 0007: l32r a8, 0 <pp_set_cut_evt-0x4> (0 <pp_set_cut_evt-0x4>) */ /* literal @0x0: pp_allow_cut_sevt */
  MEM8(a8 + 0) = a2; /* 000a: s8i a2, a8, 0 */
  MEMW(); /* 000d: memw  */
  MEMW(); /* 0010: memw  */
  return (int32_t)a2; /* 0013: retw.n  */
}

/* pp_can_cut_sevt @ pp.o 00000004 size 11B bind GLOBAL
 * Calls: none | Data refs: pp_allow_cut_sevt
 *   MMIO: none
 *   funcdb v3: 0 call(s), 1 ref(s); disasm: 0 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t pp_can_cut_sevt(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pp_can_cut_sevt; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a8 = (uint32_t)&pp_allow_cut_sevt; /* 0007: l32r a8, 0 <pp_can_cut_sevt-0x4> (0 <pp_can_cut_sevt-0x4>) */ /* literal @0x0: pp_allow_cut_sevt */
  a2 = MEM8(a8 + 0); /* 000a: l8ui a2, a8, 0 */
  return (int32_t)a2; /* 000d: retw.n  */
}

/* pp_can_cut_evt @ pp.o 00000008 size 25B bind GLOBAL
 * Calls: none | Data refs: pp_allow_cut_sevt, pp_need_cut_rx
 *   MMIO: none
 *   funcdb v3: 0 call(s), 2 ref(s); disasm: 0 call(s), 2 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t pp_can_cut_evt(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pp_can_cut_evt; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_8:;
  /* 0008: entry a1, 32 */
  a2 = (uint32_t)&pp_need_cut_rx; /* 000b: l32r a2, 0 <pp_can_cut_evt-0x8> (0 <pp_can_cut_evt-0x8>) */ /* literal @0x0: pp_need_cut_rx */
  a8 = MEM8(a2 + 0); /* 000e: l8ui a8, a2, 0 */
  a2 = 0x0; /* 0011: movi.n a2, 0 */
  if (a8 == a2) goto L_1c; /* 0013: beq a8, a2, 1c <pp_can_cut_evt+0x14> */
  a2 = (uint32_t)&pp_allow_cut_sevt; /* 0016: l32r a2, 4 <pp_can_cut_evt-0x4> (0 <pp_can_cut_evt-0x8>) */ /* literal @0x4: pp_allow_cut_sevt */
  a2 = MEM8(a2 + 0); /* 0019: l8ui a2, a2, 0 */
L_1c:;
  a2 = (a2 >> 0) & 0x1; /* 001c: extui a2, a2, 0, 1 */
  return (int32_t)a2; /* 001f: retw.n  */
}

/* RxNodeNum @ pp.o 00000004 size 39B bind GLOBAL
 * Calls: none | Data refs: wDevCtrl
 *   MMIO: none
 *   funcdb v3: 0 call(s), 1 ref(s); disasm: 0 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t RxNodeNum(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.RxNodeNum; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a2 = (uint32_t)&wDevCtrl; /* 0007: l32r a2, 0 <RxNodeNum-0x4> (0 <RxNodeNum-0x4>) */ /* literal @0x0: wDevCtrl */
  a8 = MEM32(a2 + 0); /* 000a: l32i.n a8, a2, 0 */
  a2 = 0x0; /* 000c: movi.n a2, 0 */
  a9 = 0x0; /* 000e: mov.n a9, a2 */
  goto L_26; /* 0010: j 26 <RxNodeNum+0x22> */
  /* 0013: .byte 00 */
  /* 0014: .byte 00 */
L_15:;
  MEMW(); /* 0015: memw  */
  a10 = MEM32(a8 + 0); /* 0018: l32i.n a10, a8, 0 */
  a2 = 0x1; /* 001a: addi.n a2, a2, 1 */
  a2 = 0x1; /* 001c: extui a2, a2, 0, 8 */
  if (!((a10 >> 30) & 1)) goto L_24; /* 001f: bbci a10, 30, 24 <RxNodeNum+0x20> */
  a2 = 0x0; /* 0022: mov.n a2, a9 */
L_24:;
  a8 = MEM32(a8 + 8); /* 0024: l32i.n a8, a8, 8 */
L_26:;
  if (a8 != 0) goto L_15; /* 0026: bnez a8, 15 <RxNodeNum+0x11> */
  return (int32_t)a2; /* 0029: retw.n  */
}

/* TxNodeNum @ pp.o 00000000 size 7B bind GLOBAL
 * Calls: none | Data refs: none
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t TxNodeNum(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.TxNodeNum; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_0:;
  /* 0000: entry a1, 32 */
  a2 = 0x0; /* 0003: movi.n a2, 0 */
  return (int32_t)a2; /* 0005: retw.n  */
}

/* SigSpaceMalloc @ pp.o 0000000c size 70B bind GLOBAL
 * Calls: none | Data refs: CurFreeSigIdx, SigInMacISR, pTxRx
 *   MMIO: none
 *   funcdb v3: 0 call(s), 3 ref(s); disasm: 0 call(s), 3 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t SigSpaceMalloc(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.SigSpaceMalloc; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_c:;
  /* 000c: entry a1, 32 */
  a2 = (uint32_t)&pTxRx; /* 000f: l32r a2, 0 <SigSpaceMalloc-0xc> (0 <SigSpaceMalloc-0xc>) */ /* literal @0x0: pTxRx */
  a10 = 0x32; /* 0012: movi.n a10, 50 */
  a2 = MEM32(a2 + 0); /* 0014: l32i.n a2, a2, 0 */
  a8 = MEM32(a2 + 960); /* 0016: l32i a8, a2, 0x3c0 */
  a9 = a8 + (1); /* 0019: addi.n a9, a8, 1 */
  MEM32(a2 + 960) = a9; /* 001b: s32i a9, a2, 0x3c0 */
  if (a10 >= a9) goto L_2c; /* 001e: bgeu a10, a9, 2c <SigSpaceMalloc+0x20> */
  MEM32(a2 + 960) = a8; /* 0021: s32i a8, a2, 0x3c0 */
  a2 = 0x0; /* 0024: movi.n a2, 0 */
  MEMW(); /* 0026: memw  */
  goto L_4d; /* 0029: j 4d <SigSpaceMalloc+0x41> */
L_2c:;
  a9 = (uint32_t)&CurFreeSigIdx; /* 002c: l32r a9, 4 <SigSpaceMalloc-0x8> (0 <SigSpaceMalloc-0xc>) */ /* literal @0x4: CurFreeSigIdx */
  a10 = 0x31; /* 002f: movi.n a10, 49 */
  a8 = MEM16(a9 + 0); /* 0031: l16ui a8, a9, 0 */
  a2 = (uint32_t)&SigInMacISR; /* 0034: l32r a2, 8 <SigSpaceMalloc-0x4> (0 <SigSpaceMalloc-0xc>) */ /* literal @0x8: SigInMacISR */
  a2 = (a8 << 8) + a2; /* 0037: addx8 a2, a8, a2 */
  a8 = a8 + (1); /* 003a: addi.n a8, a8, 1 */
  a8 = (a8 >> 0) & 0xFFFF; /* 003c: extui a8, a8, 0, 16 */
  if (a10 < a8) goto L_45; /* 003f: bltu a10, a8, 45 <SigSpaceMalloc+0x39> */
  goto L_47; /* 0042: j 47 <SigSpaceMalloc+0x3b> */
L_45:;
  a8 = 0x0; /* 0045: movi.n a8, 0 */
L_47:;
  MEM16(a9 + 0) = a8; /* 0047: s16i a8, a9, 0 */
  MEMW(); /* 004a: memw  */
L_4d:;
  MEMW(); /* 004d: memw  */
  return (int32_t)a2; /* 0050: retw.n  */
}

/* SigSpaceFree @ pp.o 00000004 size 21B bind GLOBAL
 * Calls: none | Data refs: pTxRx
 *   MMIO: none
 *   funcdb v3: 0 call(s), 1 ref(s); disasm: 0 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t SigSpaceFree(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.SigSpaceFree; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a8 = (uint32_t)&pTxRx; /* 0007: l32r a8, 0 <SigSpaceFree-0x4> (0 <SigSpaceFree-0x4>) */ /* literal @0x0: pTxRx */
  a9 = MEM32(a8 + 0); /* 000a: l32i.n a9, a8, 0 */
  a8 = MEM32(a9 + 960); /* 000c: l32i a8, a9, 0x3c0 */
  a8 = a8 + (-1); /* 000f: addi.n a8, a8, -1 */
  MEM32(a9 + 960) = a8; /* 0011: s32i a8, a9, 0x3c0 */
  MEMW(); /* 0014: memw  */
  return (int32_t)a2; /* 0017: retw.n  */
}

/* DefFreqCalTimerCB @ pp.o 00000004 size 19B bind GLOBAL
 * Calls: none | Data refs: CanDoFreqCal
 *   MMIO: none
 *   funcdb v3: 0 call(s), 1 ref(s); disasm: 0 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t DefFreqCalTimerCB(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.DefFreqCalTimerCB; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a8 = (uint32_t)&CanDoFreqCal; /* 0007: l32r a8, 0 <DefFreqCalTimerCB-0x4> (0 <DefFreqCalTimerCB-0x4>) */ /* literal @0x0: CanDoFreqCal */
  a9 = 0x1; /* 000a: movi.n a9, 1 */
  MEM8(a8 + 0) = a9; /* 000c: s8i a9, a8, 0 */
  MEMW(); /* 000f: memw  */
  MEMW(); /* 0012: memw  */
  return (int32_t)a2; /* 0015: retw.n  */
}

/* ppProcessRxPktHdr @ pp.o 00000008 size 46B bind GLOBAL
 * Calls: pTxRx[got], g_osi_funcs_p[got] | Data refs: pTxRx, g_osi_funcs_p
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 2 call(s), 2 data ref(s)
 * Fidelity: medium - 18 instr, 1 branches, calls resolved */
int32_t ppProcessRxPktHdr(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .wifirxiram.6; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_8:;
  /* 0008: entry a1, 32 */
  a3 = (uint32_t)&pTxRx; /* 000b: l32r a3, 0 <ppProcessRxPktHdr-0x8> (0 <ppProcessRxPktHdr-0x8>) */ /* literal @0x0: pTxRx */
  a3 = MEM32(a3 + 0); /* 000e: l32i.n a3, a3, 0 */
  a3 = MEM32(a3 + 956); /* 0010: l32i a3, a3, 0x3bc */
  if (a3 == 0) goto L_1d; /* 0013: beqz.n a3, 1d <ppProcessRxPktHdr+0x15> */
  a11 = MEM32(a2 + 0); /* 0015: l32i.n a11, a2, 0 */
  a10 = MEM32(a2 + 4); /* 0017: l32i a10, a2, 4 */
  pTxRx(a2, a3, a4, a5); /* call via literal slot */ /* 001a: callx8 a3 */
L_1d:;
  a3 = (uint32_t)&g_osi_funcs_p; /* 001d: l32r a3, 4 <ppProcessRxPktHdr-0x4> (0 <ppProcessRxPktHdr-0x8>) */ /* literal @0x4: g_osi_funcs_p */
  a8 = MEM32(a3 + 0); /* 0020: l32i.n a8, a3, 0 */
  a10 = MEM32(a2 + 4); /* 0022: l32i.n a10, a2, 4 */
  a8 = MEM32(a8 + 176); /* 0024: l32i a8, a8, 176 */
  ((int32_t(*)())a8)(a2, a3, a4, a5); /* 0027: callx8 a8 */ /* indirect */
  a10 = a2; /* 002a: mov.n a10, a2 */
  a3 = MEM32(a3 + 0); /* 002c: l32i.n a3, a3, 0 */
  a3 = MEM32(a3 + 176); /* 002e: l32i a3, a3, 176 */
  g_osi_funcs_p(a2, a3, a4, a5); /* call via literal slot */ /* 0031: callx8 a3 */
  return (int32_t)a2; /* 0034: retw.n  */
}

/* pp_register_net80211_tx_cb @ pp.o 00000004 size 15B bind GLOBAL
 * Calls: none | Data refs: .bss.g_net80211_tx_func
 *   MMIO: none
 *   funcdb v3: 0 call(s), 1 ref(s); disasm: 0 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t pp_register_net80211_tx_cb(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pp_register_net80211_tx_cb; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a8 = (uint32_t)&bss_g_net80211_tx_func; /* 0007: l32r a8, 0 <pp_register_net80211_tx_cb-0x4> (0 <pp_register_net80211_tx_cb-0x4>) */ /* literal @0x0: .bss.g_net80211_tx_func */
  MEM32(a8 + 0) = a2; /* 000a: s32i.n a2, a8, 0 */
  a2 = 0x1; /* 000c: movi.n a2, 1 */
  MEMW(); /* 000e: memw  */
  return (int32_t)a2; /* 0011: retw.n  */
}

/* pp_register_config_cb @ pp.o 00000004 size 15B bind GLOBAL
 * Calls: none | Data refs: .bss.g_config_func
 *   MMIO: none
 *   funcdb v3: 0 call(s), 1 ref(s); disasm: 0 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t pp_register_config_cb(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pp_register_config_cb; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a8 = (uint32_t)&bss_g_config_func; /* 0007: l32r a8, 0 <pp_register_config_cb-0x4> (0 <pp_register_config_cb-0x4>) */ /* literal @0x0: .bss.g_config_func */
  MEM32(a8 + 0) = a2; /* 000a: s32i.n a2, a8, 0 */
  a2 = 0x1; /* 000c: movi.n a2, 1 */
  MEMW(); /* 000e: memw  */
  return (int32_t)a2; /* 0011: retw.n  */
}

/* pp_register_timer_cb @ pp.o 00000004 size 15B bind GLOBAL
 * Calls: none | Data refs: .bss.g_timer_func
 *   MMIO: none
 *   funcdb v3: 0 call(s), 1 ref(s); disasm: 0 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t pp_register_timer_cb(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pp_register_timer_cb; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a8 = (uint32_t)&bss_g_timer_func; /* 0007: l32r a8, 0 <pp_register_timer_cb-0x4> (0 <pp_register_timer_cb-0x4>) */ /* literal @0x0: .bss.g_timer_func */
  MEM32(a8 + 0) = a2; /* 000a: s32i.n a2, a8, 0 */
  a2 = 0x1; /* 000c: movi.n a2, 1 */
  MEMW(); /* 000e: memw  */
  return (int32_t)a2; /* 0011: retw.n  */
}

/* pp_register_michael_mic_failure_cb @ pp.o 00000004 size 15B bind GLOBAL
 * Calls: none | Data refs: .bss.s_michael_mic_failure_cb
 *   MMIO: none
 *   funcdb v3: 0 call(s), 1 ref(s); disasm: 0 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t pp_register_michael_mic_failure_cb(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pp_register_michael_mic_failure_cb; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a8 = (uint32_t)&bss_s_michael_mic_failure_cb; /* 0007: l32r a8, 0 <pp_register_michael_mic_failure_cb-0x4> (0 <pp_register_michael_mic_failure_cb-0x4>) */ /* literal @0x0: .bss.s_michael_mic_failure_cb */
  MEM32(a8 + 0) = a2; /* 000a: s32i.n a2, a8, 0 */
  a2 = 0x0; /* 000c: movi.n a2, 0 */
  MEMW(); /* 000e: memw  */
  return (int32_t)a2; /* 0011: retw.n  */
}

/* pp_process_hmac_waiting_txq @ pp.o 00000008 size 22B bind GLOBAL
 * Calls: config_is_cache_tx_buf_enabled[got] | Data refs: config_is_cache_tx_buf_enabled, .bss.g_net80211_tx_func
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 1 call(s), 2 data ref(s)
 * Fidelity: medium - 8 instr, 1 branches, calls resolved */
int32_t pp_process_hmac_waiting_txq(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .wifi0iram.7; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_8:;
  /* 0008: entry a1, 32 */
  a8 = (uint32_t)&config_is_cache_tx_buf_enabled; /* 000b: l32r a8, 4 <pp_process_hmac_waiting_txq-0x4> (0 <pp_process_hmac_waiting_txq-0x8>) */ /* literal: GOT slot for config_is_cache_tx_buf_enabled */
  config_is_cache_tx_buf_enabled(a2, a3, a4, a5); /* call via literal slot */ /* 000e: callx8 a8 */
  if (a10 == 0) goto L_1c; /* 0011: beqz.n a10, 1c <pp_process_hmac_waiting_txq+0x14> */
  a8 = (uint32_t)&bss_g_net80211_tx_func; /* 0013: l32r a8, 0 <pp_process_hmac_waiting_txq-0x8> (0 <pp_process_hmac_waiting_txq-0x8>) */ /* literal @0x0: .bss.g_net80211_tx_func */
  a10 = MEM32(a8 + 0); /* 0016: l32i a10, a8, 0 */
  ((int32_t(*)())a10)(a2, a3, a4, a5); /* 0019: callx8 a10 */ /* indirect */
L_1c:;
  return (int32_t)a2; /* 001c: retw.n  */
}

/* pp_default_event_handler @ pp.o 0000000c size 28B bind GLOBAL
 * Calls: wifi_log | Data refs: .rodata.pp_default_event_handler.str1.1, .rodata_wlog_error.8, wifi_log
 *   MMIO: none
 *   funcdb v3: 1 call(s), 3 ref(s); disasm: 1 call(s), 3 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t pp_default_event_handler(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pp_default_event_handler; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_c:;
  /* 000c: entry a1, 32 */
  a12 = 0x1; /* 000f: movi.n a12, 1 */
  a14 = (uint32_t)&lit_rodata_pp_default_event_handler_str1_1; /* 0011: l32r a14, 0 <pp_default_event_handler-0xc> (0 <pp_default_event_handler-0xc>) */ /* literal @0x0: .rodata.pp_default_event_handler.str1.1 */
  a15 = 0x178; /* 0014: movi a15, 0x178 */
  a11 = 0x800; /* 0017: slli a11, a12, 11 */
  a10 = 0x6; /* 001a: movi.n a10, 6 */
  a13 = (uint32_t)&lit_rodata_wlog_error_8; /* 001c: l32r a13, 4 <pp_default_event_handler-0x8> (0 <pp_default_event_handler-0xc>) */ /* literal @0x4: .rodata_wlog_error.8 */
  a8 = (uint32_t)&wifi_log; /* 001f: l32r a8, 8 <pp_default_event_handler-0x4> (0 <pp_default_event_handler-0xc>) */ /* literal: GOT slot for wifi_log */
  wifi_log(a2, a3, a4, a5); /* call via literal slot */ /* 0022: callx8 a8 */
L_25:;
  goto L_25; /* 0025: j 25 <pp_default_event_handler+0x19> */
  /* no retw observed; falls through */
  return (int32_t)a2;
}

/* ppTxProtoProc @ pp.o 00000000 size 135B bind GLOBAL
 * Calls: none | Data refs: none
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: medium - 52 instr, 13 branches, calls resolved */
int32_t ppTxProtoProc(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .wifi0iram.11; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_0:;
  /* 0000: entry a1, 32 */
  a9 = MEM32(a2 + 44); /* 0003: l32i.n a9, a2, 44 */
  a2 = MEM32(a2 + 4); /* 0005: l32i.n a2, a2, 4 */
  a8 = MEM32(a9 + 0); /* 0007: l32i.n a8, a9, 0 */
  a13 = MEM32(a2 + 4); /* 0009: l32i a13, a2, 4 */
  a12 = a13; /* 000c: mov.n a12, a13 */
  if (!((a8 >> 18) & 1)) goto L_14; /* 000e: bbci a8, 18, 14 <ppTxProtoProc+0x14> */
  a12 = a13 + (4); /* 0011: addi a12, a13, 4 */
L_14:;
  a2 = MEM8(a12 + 4); /* 0014: l8ui a2, a12, 4 */
  if (!((a2 >> 0) & 1)) goto L_21; /* 0017: bbci a2, 0, 21 <ppTxProtoProc+0x21> */
  a2 = 0x2; /* 001a: movi.n a2, 2 */
  a8 = a8 | a2; /* 001c: or a8, a8, a2 */
  MEM32(a9 + 0) = a8; /* 001f: s32i.n a8, a9, 0 */
L_21:;
  a11 = 0xC; /* 0021: movi.n a11, 12 */
  a10 = MEM8(a12 + 0); /* 0023: l8ui a10, a12, 0 */
  a11 = a10 & a11; /* 0026: and a11, a10, a11 */
  a8 = MEM32(a9 + 0); /* 0029: l32i.n a8, a9, 0 */
  if (a11 != 8) goto L_48; /* 002b: bnei a11, 8, 48 <ppTxProtoProc+0x48> */
  a2 = 0x70; /* 002e: movi a2, 112 */
  a10 = a10 & a2; /* 0031: and a10, a10, a2 */
  if (a10 == 64) goto L_40; /* 0034: beqi a10, 64, 40 <ppTxProtoProc+0x40> */
  a8 = a8 | a11; /* 0037: or a8, a8, a11 */
  MEMW(); /* 003a: memw  */
  goto L_6f; /* 003d: j 6f <ppTxProtoProc+0x6f> */
L_40:;
  a2 = 0xFFFFFFF7; /* 0040: movi.n a2, -9 */
  a8 = a8 & a2; /* 0042: and a8, a8, a2 */
  goto L_6f; /* 0045: j 6f <ppTxProtoProc+0x6f> */
L_48:;
  if (a11 != 0) goto L_71; /* 0048: bnez.n a11, 71 <ppTxProtoProc+0x71> */
  a2 = 0xFFFFFFF0; /* 004a: movi.n a2, -16 */
  a10 = a10 & a2; /* 004c: and a10, a10, a2 */
  a2 = 0x50; /* 004f: movi.n a2, 80 */
  if (a10 != a2) goto L_61; /* 0051: bne a10, a2, 61 <ppTxProtoProc+0x61> */
  a10 = 0x1; /* 0054: movi.n a10, 1 */
  a10 = 0x8000000; /* 0056: slli a10, a10, 27 */
  if (!((a8 >> 1) & 1)) goto L_6c; /* 0059: bbci a8, 1, 6c <ppTxProtoProc+0x6c> */
  goto L_71; /* 005c: j 71 <ppTxProtoProc+0x71> */
  /* 005f: .byte 00 */
  /* 0060: .byte 00 */
L_61:;
  if (a10 != 64) goto L_71; /* 0061: bnei a10, 64, 71 <ppTxProtoProc+0x71> */
  if ((a8 >> 1) & 1) goto L_71; /* 0064: bbsi a8, 1, 71 <ppTxProtoProc+0x71> */
  a10 = 0x1; /* 0067: movi.n a10, 1 */
  a10 = 0x800; /* 0069: slli a10, a10, 11 */
L_6c:;
  a8 = a8 | a10; /* 006c: or a8, a8, a10 */
L_6f:;
  MEM32(a9 + 0) = a8; /* 006f: s32i.n a8, a9, 0 */
L_71:;
  a2 = MEM32(a9 + 0); /* 0071: l32i.n a2, a9, 0 */
  if (!((a2 >> 18) & 1)) goto L_82; /* 0073: bbci a2, 18, 82 <ppTxProtoProc+0x82> */
  a8 = MEM16(a12 + 22); /* 0076: l16ui a8, a12, 22 */
  a8 = a8 >> (4 & 31); /* 0079: srli a8, a8, 4 */
  MEM8(a13 + 3) = a8; /* 007c: s8i a8, a13, 3 */
  MEMW(); /* 007f: memw  */
L_82:;
  MEMW(); /* 0082: memw  */
  return (int32_t)a2; /* 0085: retw.n  */
}

/* ppAddTimCount @ pp.o 00000004 size 392B bind GLOBAL
 * Calls: pp_hdrsize | Data refs: pp_hdrsize
 *   MMIO: none
 *   funcdb v3: 1 call(s), 1 ref(s); disasm: 1 call(s), 1 data ref(s)
 * Fidelity: medium - 154 instr, 37 branches, calls resolved */
int32_t ppAddTimCount(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.ppAddTimCount; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a4 = MEM16(a2 + 12); /* 0007: l16ui a4, a2, 12 */
  if (a4 < 3) goto L_10; /* 000a: bltui a4, 3, 10 <ppAddTimCount+0xc> */
  goto L_18a; /* 000d: j 18a <ppAddTimCount+0x186> */
L_10:;
  a8 = MEM32(a2 + 44); /* 0010: l32i.n a8, a2, 44 */
  a3 = MEM32(a2 + 4); /* 0012: l32i.n a3, a2, 4 */
  a8 = MEM32(a8 + 0); /* 0014: l32i.n a8, a8, 0 */
  a5 = MEM32(a3 + 4); /* 0016: l32i.n a5, a3, 4 */
  if (!((a8 >> 18) & 1)) goto L_1d; /* 0018: bbci a8, 18, 1d <ppAddTimCount+0x19> */
  a5 = a5 + (4); /* 001b: addi.n a5, a5, 4 */
L_1d:;
  a10 = a5; /* 001d: mov.n a10, a5 */
  a8 = (uint32_t)&pp_hdrsize; /* 001f: l32r a8, 0 <ppAddTimCount-0x4> (0 <ppAddTimCount-0x4>) */ /* literal: GOT slot for pp_hdrsize */
  pp_hdrsize(a2, a3, a4, a5); /* call via literal slot */ /* 0022: callx8 a8 */
  a9 = MEM16(a2 + 22); /* 0025: l16ui a9, a2, 22 */
  a9 = a9 + (-4); /* 0028: addi a9, a9, -4 */
  a9 = a9 - a10; /* 002b: sub a9, a9, a10 */
  a9 = (a9 >> 0) & 0xFFFF; /* 002e: extui a9, a9, 0, 16 */
  a9 = a9 + (24); /* 0031: addi a9, a9, 24 */
  a8 = MEM32(a2 + 16); /* 0034: l32i.n a8, a2, 16 */
  a9 = a5 + a9; /* 0036: add.n a9, a5, a9 */
  if (a9 < a8) goto L_48; /* 0038: bltu a9, a8, 48 <ppAddTimCount+0x44> */
  MEMW(); /* 003b: memw  */
  a10 = MEM32(a3 + 0); /* 003e: l32i.n a10, a3, 0 */
  a10 = (a10 >> 0) & 0xFFF; /* 0040: extui a10, a10, 0, 12 */
  a10 = a8 + a10; /* 0043: add.n a10, a8, a10 */
  if (a9 < a10) goto L_4e; /* 0045: bltu a9, a10, 4e <ppAddTimCount+0x4a> */
L_48:;
  if (a4 != 1) goto L_4e; /* 0048: bnei a4, 1, 4e <ppAddTimCount+0x4a> */
  goto L_18a; /* 004b: j 18a <ppAddTimCount+0x186> */
L_4e:;
  a10 = a5 + (36); /* 004e: addi a10, a5, 36 */
  a13 = 0x1; /* 0051: movi.n a13, 1 */
  a12 = 0x0; /* 0053: movi.n a12, 0 */
  goto L_ca; /* 0055: j ca <ppAddTimCount+0xc6> */
L_58:;
  if (a4 != 2) goto L_91; /* 0058: bnei a4, 2, 91 <ppAddTimCount+0x8d> */
  if (a13 == 0) goto L_91; /* 005b: beqz.n a13, 91 <ppAddTimCount+0x8d> */
  if (a10 < a8) goto L_6d; /* 005d: bltu a10, a8, 6d <ppAddTimCount+0x69> */
  MEMW(); /* 0060: memw  */
  a11 = MEM32(a3 + 0); /* 0063: l32i.n a11, a3, 0 */
  a11 = (a11 >> 0) & 0xFFF; /* 0065: extui a11, a11, 0, 12 */
  a11 = a8 + a11; /* 0068: add.n a11, a8, a11 */
  if (a10 < a11) goto L_91; /* 006a: bltu a10, a11, 91 <ppAddTimCount+0x8d> */
L_6d:;
  MEMW(); /* 006d: memw  */
  a11 = MEM32(a3 + 0); /* 0070: l32i.n a11, a3, 0 */
  a11 = (a11 >> 0) & 0xFFF; /* 0072: extui a11, a11, 0, 12 */
  a11 = a8 + a11; /* 0075: add.n a11, a8, a11 */
  a10 = a10 - a11; /* 0077: sub a10, a10, a11 */
  MEMW(); /* 007a: memw  */
  a11 = MEM32(a3 + 0); /* 007d: l32i.n a11, a3, 0 */
  a11 = (a11 >> 0) & 0xFFF; /* 007f: extui a11, a11, 0, 12 */
  a11 = a8 + a11; /* 0082: add.n a11, a8, a11 */
  a9 = a9 - a11; /* 0084: sub a9, a9, a11 */
  a5 = MEM32(a2 + 8); /* 0087: l32i.n a5, a2, 8 */
  a13 = MEM32(a5 + 4); /* 0089: l32i.n a13, a5, 4 */
  a10 = a13 + a10; /* 008b: add.n a10, a13, a10 */
  a9 = a13 + a9; /* 008d: add.n a9, a13, a9 */
  a13 = 0x0; /* 008f: mov.n a13, a12 */
L_91:;
  a5 = MEM8(a10 + 0); /* 0091: l8ui a5, a10, 0 */
  a14 = 0x0; /* 0094: mov.n a14, a12 */
  a5 = a5 + (-5); /* 0096: addi a5, a5, -5 */
  if (a5 == 0) a14 = a10; /* 0099: moveqz a14, a10, a5 */
  if (a13 == 0) goto L_b0; /* 009c: beqz.n a13, b0 <ppAddTimCount+0xac> */
  a5 = a10 + (1); /* 009e: addi.n a5, a10, 1 */
  if (a5 < a8) goto L_b6; /* 00a0: bltu a5, a8, b6 <ppAddTimCount+0xb2> */
  MEMW(); /* 00a3: memw  */
  a11 = MEM32(a3 + 0); /* 00a6: l32i.n a11, a3, 0 */
  a11 = (a11 >> 0) & 0xFFF; /* 00a8: extui a11, a11, 0, 12 */
  a11 = a8 + a11; /* 00ab: add.n a11, a8, a11 */
  if (a5 >= a11) goto L_b6; /* 00ad: bgeu a5, a11, b6 <ppAddTimCount+0xb2> */
L_b0:;
  a11 = MEM8(a10 + 1); /* 00b0: l8ui a11, a10, 1 */
  goto L_c3; /* 00b3: j c3 <ppAddTimCount+0xbf> */
L_b6:;
  a5 = MEM32(a2 + 8); /* 00b6: l32i.n a5, a2, 8 */
  a5 = MEM32(a5 + 4); /* 00b8: l32i.n a5, a5, 4 */
  MEMW(); /* 00ba: memw  */
  a11 = MEM8(a5 + 0); /* 00bd: l8ui a11, a5, 0 */
  a11 = (a11 >> 0) & 0xFF; /* 00c0: extui a11, a11, 0, 8 */
L_c3:;
  if (a14 != 0) goto L_170; /* 00c3: bnez a14, 170 <ppAddTimCount+0x16c> */
  a11 = a11 + (2); /* 00c6: addi.n a11, a11, 2 */
  a10 = a10 + a11; /* 00c8: add.n a10, a10, a11 */
L_ca:;
  a5 = a9 - a10; /* 00ca: sub a5, a9, a10 */
  if (a5 >= 2) goto L_58; /* 00cd: bgei a5, 2, 58 <ppAddTimCount+0x54> */
  goto L_18a; /* 00d0: j 18a <ppAddTimCount+0x186> */
L_d3:;
  if (a4 != 2) goto L_144; /* 00d3: bnei a4, 2, 144 <ppAddTimCount+0x140> */
  if (a10 < a8) goto L_e9; /* 00d6: bltu a10, a8, e9 <ppAddTimCount+0xe5> */
  MEMW(); /* 00d9: memw  */
  a4 = MEM32(a3 + 0); /* 00dc: l32i.n a4, a3, 0 */
  a4 = (a4 >> 0) & 0xFFF; /* 00de: extui a4, a4, 0, 12 */
  a4 = a8 + a4; /* 00e1: add.n a4, a8, a4 */
  if (a10 >= a4) goto L_e9; /* 00e3: bgeu a10, a4, e9 <ppAddTimCount+0xe5> */
  goto L_184; /* 00e6: j 184 <ppAddTimCount+0x180> */
L_e9:;
  MEMW(); /* 00e9: memw  */
  a4 = MEM32(a3 + 0); /* 00ec: l32i.n a4, a3, 0 */
  a4 = (a4 >> 0) & 0xFFF; /* 00ee: extui a4, a4, 0, 12 */
  a4 = a8 + a4; /* 00f1: add.n a4, a8, a4 */
  a4 = a10 - a4; /* 00f3: sub a4, a10, a4 */
  a5 = MEM32(a2 + 8); /* 00f6: l32i.n a5, a2, 8 */
  a10 = MEM32(a5 + 4); /* 00f8: l32i.n a10, a5, 4 */
  a10 = a10 + a4; /* 00fa: add.n a10, a10, a4 */
  goto L_184; /* 00fc: j 184 <ppAddTimCount+0x180> */
L_ff:;
  MEMW(); /* 00ff: memw  */
  a4 = MEM32(a3 + 0); /* 0102: l32i.n a4, a3, 0 */
  a4 = (a4 >> 0) & 0xFFF; /* 0104: extui a4, a4, 0, 12 */
  a4 = a8 + a4; /* 0107: add.n a4, a8, a4 */
  if (a11 < a4) goto L_17c; /* 0109: bltu a11, a4, 17c <ppAddTimCount+0x178> */
L_10c:;
  MEMW(); /* 010c: memw  */
  a4 = MEM32(a3 + 0); /* 010f: l32i.n a4, a3, 0 */
  a4 = (a4 >> 0) & 0xFFF; /* 0111: extui a4, a4, 0, 12 */
  a4 = a8 + a4; /* 0114: add.n a4, a8, a4 */
  a4 = a11 - a4; /* 0116: sub a4, a11, a4 */
  a5 = MEM32(a2 + 8); /* 0119: l32i.n a5, a2, 8 */
  a11 = MEM32(a5 + 4); /* 011b: l32i.n a11, a5, 4 */
  a11 = a11 + a4; /* 011d: add.n a11, a11, a4 */
  goto L_17c; /* 011f: j 17c <ppAddTimCount+0x178> */
  /* 0122: .byte 00 */
  /* 0123: .byte 00 */
L_124:;
  MEMW(); /* 0124: memw  */
  a4 = MEM32(a3 + 0); /* 0127: l32i.n a4, a3, 0 */
  a4 = (a4 >> 0) & 0xFFF; /* 0129: extui a4, a4, 0, 12 */
  a4 = a8 + a4; /* 012c: add.n a4, a8, a4 */
  if (a9 < a4) goto L_144; /* 012e: bltu a9, a4, 144 <ppAddTimCount+0x140> */
L_131:;
  MEMW(); /* 0131: memw  */
  a3 = MEM32(a3 + 0); /* 0134: l32i.n a3, a3, 0 */
  a3 = (a3 >> 0) & 0xFFF; /* 0136: extui a3, a3, 0, 12 */
  a3 = a8 + a3; /* 0139: add.n a3, a8, a3 */
  a3 = a9 - a3; /* 013b: sub a3, a9, a3 */
  a2 = MEM32(a2 + 8); /* 013e: l32i.n a2, a2, 8 */
  a9 = MEM32(a2 + 4); /* 0140: l32i.n a9, a2, 4 */
  a9 = a9 + a3; /* 0142: add.n a9, a9, a3 */
L_144:;
  a8 = MEM8(a10 + 0); /* 0144: l8ui a8, a10, 0 */
  if (a8 == 0) goto L_14c; /* 0147: beqz.n a8, 14c <ppAddTimCount+0x148> */
  goto L_14f; /* 0149: j 14f <ppAddTimCount+0x14b> */
L_14c:;
  a8 = MEM8(a11 + 0); /* 014c: l8ui a8, a11, 0 */
L_14f:;
  a8 = a8 + (-1); /* 014f: addi.n a8, a8, -1 */
  a8 = (a8 >> 0) & 0xFF; /* 0151: extui a8, a8, 0, 8 */
  MEM8(a10 + 0) = a8; /* 0154: s8i a8, a10, 0 */
  MEMW(); /* 0157: memw  */
  if (a8 != 0) goto L_18a; /* 015a: bnez.n a8, 18a <ppAddTimCount+0x186> */
  a3 = 0x1; /* 015c: movi.n a3, 1 */
  a2 = MEM8(a9 + 0); /* 015e: l8ui a2, a9, 0 */
  a2 = a2 | a3; /* 0161: or a2, a2, a3 */
  MEM8(a9 + 0) = a2; /* 0164: s8i a2, a9, 0 */
  MEMW(); /* 0167: memw  */
  MEMW(); /* 016a: memw  */
  goto L_18a; /* 016d: j 18a <ppAddTimCount+0x186> */
L_170:;
  a10 = a14 + (2); /* 0170: addi.n a10, a14, 2 */
  a11 = a14 + (3); /* 0172: addi.n a11, a14, 3 */
  a9 = a14 + (4); /* 0174: addi.n a9, a14, 4 */
  if (a13 != 0) goto L_d3; /* 0176: bnez a13, d3 <ppAddTimCount+0xcf> */
  goto L_144; /* 0179: j 144 <ppAddTimCount+0x140> */
L_17c:;
  if (a9 < a8) goto L_131; /* 017c: bltu a9, a8, 131 <ppAddTimCount+0x12d> */
  goto L_124; /* 017f: j 124 <ppAddTimCount+0x120> */
  /* 0182: .byte 00 */
  /* 0183: .byte 00 */
L_184:;
  if (a11 < a8) goto L_10c; /* 0184: bltu a11, a8, 10c <ppAddTimCount+0x108> */
  goto L_ff; /* 0187: j ff <ppAddTimCount+0xfb> */
L_18a:;
  return (int32_t)a2; /* 018a: retw.n  */
}

/* ppRegisterPromisRxCallback @ pp.o 00000004 size 18B bind GLOBAL
 * Calls: none | Data refs: pTxRx
 *   MMIO: none
 *   funcdb v3: 0 call(s), 1 ref(s); disasm: 0 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t ppRegisterPromisRxCallback(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.ppRegisterPromisRxCallback; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a8 = (uint32_t)&pTxRx; /* 0007: l32r a8, 0 <ppRegisterPromisRxCallback-0x4> (0 <ppRegisterPromisRxCallback-0x4>) */ /* literal @0x0: pTxRx */
  a8 = MEM32(a8 + 0); /* 000a: l32i.n a8, a8, 0 */
  MEM32(a8 + 956) = a2; /* 000c: s32i a2, a8, 0x3bc */
  a2 = 0x0; /* 000f: movi.n a2, 0 */
  MEMW(); /* 0011: memw  */
  return (int32_t)a2; /* 0014: retw.n  */
}

/* ppRegisterTxDoneUserActionCallback @ pp.o 00000004 size 15B bind GLOBAL
 * Calls: none | Data refs: .bss.g_tx_done_cb_func
 *   MMIO: none
 *   funcdb v3: 0 call(s), 1 ref(s); disasm: 0 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t ppRegisterTxDoneUserActionCallback(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.ppRegisterTxDoneUserActionCallback; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a8 = (uint32_t)&bss_g_tx_done_cb_func; /* 0007: l32r a8, 0 <ppRegisterTxDoneUserActionCallback-0x4> (0 <ppRegisterTxDoneUserActionCallback-0x4>) */ /* literal @0x0: .bss.g_tx_done_cb_func */
  MEM32(a8 + 0) = a2; /* 000a: s32i.n a2, a8, 0 */
  a2 = 0x0; /* 000c: movi.n a2, 0 */
  MEMW(); /* 000e: memw  */
  return (int32_t)a2; /* 0011: retw.n  */
}

/* ppRegisterRxCallback @ pp.o 00000004 size 31B bind GLOBAL
 * Calls: none | Data refs: pTxRx
 *   MMIO: none
 *   funcdb v3: 0 call(s), 1 ref(s); disasm: 0 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t ppRegisterRxCallback(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.ppRegisterRxCallback; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a3 = (a3 >> 0) & 0xFF; /* 0007: extui a3, a3, 0, 8 */
  a8 = 0x1; /* 000a: movi.n a8, 1 */
  if (a3 >= 3) goto L_1c; /* 000c: bgeui a3, 3, 1c <ppRegisterRxCallback+0x18> */
  a8 = (uint32_t)&pTxRx; /* 000f: l32r a8, 0 <ppRegisterRxCallback-0x4> (0 <ppRegisterRxCallback-0x4>) */ /* literal @0x0: pTxRx */
  a8 = MEM32(a8 + 0); /* 0012: l32i.n a8, a8, 0 */
  a3 = (a3 << 4) + a8; /* 0014: addx4 a3, a3, a8 */
  a8 = 0x0; /* 0017: movi.n a8, 0 */
  MEM32(a3 + 944) = a2; /* 0019: s32i a2, a3, 0x3b0 */
L_1c:;
  a2 = 0x0; /* 001c: mov.n a2, a8 */
  MEMW(); /* 001e: memw  */
  return (int32_t)a2; /* 0021: retw.n  */
}

/* ppRegisterTxCallback @ pp.o 00000004 size 76B bind GLOBAL
 * Calls: none | Data refs: pTxRx
 *   MMIO: none
 *   funcdb v3: 0 call(s), 1 ref(s); disasm: 0 call(s), 1 data ref(s)
 * Fidelity: medium - 28 instr, 5 branches, calls resolved */
int32_t ppRegisterTxCallback(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.ppRegisterTxCallback; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a8 = (uint32_t)&pTxRx; /* 0007: l32r a8, 0 <ppRegisterTxCallback-0x4> (0 <ppRegisterTxCallback-0x4>) */ /* literal @0x0: pTxRx */
  a11 = 0x1; /* 000a: movi.n a11, 1 */
  a12 = (a3 >> 0) & 0xFF; /* 000c: extui a12, a3, 0, 8 */
  /* 000f: ssl a3 */ /* UNMODELED: a3 clobbered */
  /* 0012: sll a3, a11 */ /* UNMODELED: a3 clobbered */
  a4 = (a4 >> 0) & 0xFF; /* 0015: extui a4, a4, 0, 8 */
  a8 = MEM32(a8 + 0); /* 0018: l32i.n a8, a8, 0 */
  a9 = 0x1; /* 001a: mov.n a9, a11 */
  a10 = MEM32(a8 + 860); /* 001c: l32i a10, a8, 0x35c */
  if ((a10 & a3) != 0) goto L_4c; /* 001f: bany a10, a3, 4c <ppRegisterTxCallback+0x48> */
  a13 = MEM32(a8 + 968); /* 0022: l32i a13, a8, 0x3c8 */
  a9 = a3 & a13; /* 0025: and a9, a3, a13 */
  if (a9 != 0) goto L_4a; /* 0028: bnez.n a9, 4a <ppRegisterTxCallback+0x46> */
  if (a4 == 0) goto L_38; /* 002a: beqz.n a4, 38 <ppRegisterTxCallback+0x34> */
  a3 = a3 | a13; /* 002c: or a3, a3, a13 */
  MEM32(a8 + 968) = a3; /* 002f: s32i a3, a8, 0x3c8 */
  MEMW(); /* 0032: memw  */
  goto L_3e; /* 0035: j 3e <ppRegisterTxCallback+0x3a> */
L_38:;
  a10 = a10 | a3; /* 0038: or a10, a10, a3 */
  MEM32(a8 + 860) = a10; /* 003b: s32i a10, a8, 0x35c */
L_3e:;
  a12 = (a12 << 4) + a8; /* 003e: addx4 a12, a12, a8 */
  MEM32(a12 + 868) = a2; /* 0041: s32i a2, a12, 0x364 */
  MEMW(); /* 0044: memw  */
  goto L_4c; /* 0047: j 4c <ppRegisterTxCallback+0x48> */
L_4a:;
  a9 = 0x1; /* 004a: mov.n a9, a11 */
L_4c:;
  a2 = 0x1; /* 004c: mov.n a2, a9 */
  return (int32_t)a2; /* 004e: retw.n  */
}

/* ppUnregisterTxCallback @ pp.o 00000004 size 69B bind GLOBAL
 * Calls: none | Data refs: pTxRx
 *   MMIO: none
 *   funcdb v3: 0 call(s), 1 ref(s); disasm: 0 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t ppUnregisterTxCallback(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.ppUnregisterTxCallback; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a8 = (uint32_t)&pTxRx; /* 0007: l32r a8, 0 <ppUnregisterTxCallback-0x4> (0 <ppUnregisterTxCallback-0x4>) */ /* literal @0x0: pTxRx */
  a9 = (a2 >> 0) & 0xFF; /* 000a: extui a9, a2, 0, 8 */
  a10 = MEM32(a8 + 0); /* 000d: l32i.n a10, a8, 0 */
  a8 = 0x1; /* 000f: movi.n a8, 1 */
  /* 0011: ssl a2 */ /* UNMODELED: a2 clobbered */
  /* 0014: sll a13, a8 */ /* UNMODELED: a13 clobbered */
  a2 = 0x1; /* 0017: mov.n a2, a8 */
  a11 = MEM32(a10 + 860); /* 0019: l32i a11, a10, 0x35c */
  a12 = MEM32(a10 + 968); /* 001c: l32i a12, a10, 0x3c8 */
  a14 = a11 | a12; /* 001f: or a14, a11, a12 */
  if ((a14 & a13) == 0) goto L_44; /* 0022: bnone a14, a13, 44 <ppUnregisterTxCallback+0x40> */
  a8 = 0xFFFFFFFF; /* 0025: movi.n a8, -1 */
  a2 = a8 ^ a13; /* 0027: xor a2, a8, a13 */
  a11 = a11 & a2; /* 002a: and a11, a11, a2 */
  a2 = a2 & a12; /* 002d: and a2, a2, a12 */
  MEM32(a10 + 968) = a2; /* 0030: s32i a2, a10, 0x3c8 */
  a2 = 0xD8; /* 0033: movi a2, 216 */
  a9 = a9 + a2; /* 0036: add.n a9, a9, a2 */
  a9 = (a9 << 4) + a10; /* 0038: addx4 a9, a9, a10 */
  a2 = 0x0; /* 003b: movi a2, 0 */
  MEM32(a10 + 860) = a11; /* 003e: s32i a11, a10, 0x35c */
  MEM32(a9 + 4) = a2; /* 0041: s32i a2, a9, 4 */
L_44:;
  MEMW(); /* 0044: memw  */
  return (int32_t)a2; /* 0047: retw.n  */
}

/* pp_register_tx_cb @ pp.o 00000004 size 21B bind GLOBAL
 * Calls: ppRegisterTxCallback | Data refs: ppRegisterTxCallback
 *   MMIO: none
 *   funcdb v3: 1 call(s), 1 ref(s); disasm: 1 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t pp_register_tx_cb(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pp_register_tx_cb; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a12 = (a4 >> 0) & 0xFF; /* 0007: extui a12, a4, 0, 8 */
  a11 = (a3 >> 0) & 0xFF; /* 000a: extui a11, a3, 0, 8 */
  a10 = a2; /* 000d: mov.n a10, a2 */
  a8 = (uint32_t)&ppRegisterTxCallback; /* 000f: l32r a8, 0 <pp_register_tx_cb-0x4> (0 <pp_register_tx_cb-0x4>) */ /* literal: GOT slot for ppRegisterTxCallback */
  ppRegisterTxCallback(a2, a3, a4, a5); /* call via literal slot */ /* 0012: callx8 a8 */
  a2 = a10; /* 0015: mov.n a2, a10 */
  return (int32_t)a2; /* 0017: retw.n  */
}

/* pp_unregister_tx_cb @ pp.o 00000004 size 16B bind GLOBAL
 * Calls: ppUnregisterTxCallback | Data refs: ppUnregisterTxCallback
 *   MMIO: none
 *   funcdb v3: 1 call(s), 1 ref(s); disasm: 1 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t pp_unregister_tx_cb(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pp_unregister_tx_cb; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a10 = (a2 >> 0) & 0xFF; /* 0007: extui a10, a2, 0, 8 */
  a8 = (uint32_t)&ppUnregisterTxCallback; /* 000a: l32r a8, 0 <pp_unregister_tx_cb-0x4> (0 <pp_unregister_tx_cb-0x4>) */ /* literal: GOT slot for ppUnregisterTxCallback */
  ppUnregisterTxCallback(a2, a3, a4, a5); /* call via literal slot */ /* 000d: callx8 a8 */
  a2 = a10; /* 0010: mov.n a2, a10 */
  return (int32_t)a2; /* 0012: retw.n  */
}

/* ppRecycleRxPkt @ pp.o 00000018 size 83B bind GLOBAL
 * Calls: wifi_log[got], wDev_AppendRxBlocks[got], esf_buf_recycle[got] | Data refs: pTxRx, .rodata.pp_default_event_handler.str1.1, .rodata_wlog_error.17, wifi_log, wDev_AppendRxBlocks, esf_buf_recycle
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 3 call(s), 6 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t ppRecycleRxPkt(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .wifiextrairam.16; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_18:;
  /* 0018: entry a1, 32 */
  a8 = MEM32(a2 + 4); /* 001b: l32i.n a8, a2, 4 */
  a9 = MEM32(a2 + 16); /* 001d: l32i.n a9, a2, 16 */
  MEM32(a8 + 4) = a9; /* 001f: s32i.n a9, a8, 4 */
  a10 = MEM8(a2 + 26); /* 0021: l8ui a10, a2, 26 */
  if (a10 != 6) goto L_61; /* 0024: bnei a10, 6, 61 <ppRecycleRxPkt+0x49> */
  a11 = (uint32_t)&pTxRx; /* 0027: l32r a11, 0 <ppRecycleRxPkt-0x18> (0 <ppRecycleRxPkt-0x18>) */ /* literal @0x0: pTxRx */
  a11 = MEM32(a11 + 0); /* 002a: l32i.n a11, a11, 0 */
  MEMW(); /* 002c: memw  */
  a9 = MEM32(a8 + 0); /* 002f: l32i.n a9, a8, 0 */
  a9 = (a9 >> 0) & 0xFFF; /* 0031: extui a9, a9, 0, 12 */
  a11 = MEM32(a11 + 964); /* 0034: l32i a11, a11, 0x3c4 */
  if (a9 == a11) goto L_54; /* 0037: beq a9, a11, 54 <ppRecycleRxPkt+0x3c> */
  a12 = 0x1; /* 003a: movi.n a12, 1 */
  a15 = 0x456; /* 003c: movi a15, 0x456 */
  a14 = (uint32_t)&lit_rodata_pp_default_event_handler_str1_1; /* 003f: l32r a14, 4 <ppRecycleRxPkt-0x14> (0 <ppRecycleRxPkt-0x18>) */ /* literal @0x4: .rodata.pp_default_event_handler.str1.1 */
  a11 = 0x800; /* 0042: slli a11, a12, 11 */
  a13 = (uint32_t)&lit_rodata_wlog_error_17; /* 0045: l32r a13, 8 <ppRecycleRxPkt-0x10> (0 <ppRecycleRxPkt-0x18>) */ /* literal @0x8: .rodata_wlog_error.17 */
  MEMW(); /* 0048: memw  */
  a8 = (uint32_t)&wifi_log; /* 004b: l32r a8, c <ppRecycleRxPkt-0xc> (0 <ppRecycleRxPkt-0x18>) */ /* literal: GOT slot for wifi_log */
  wifi_log(a2, a3, a4, a5); /* call via literal slot */ /* 004e: callx8 a8 */
L_51:;
  goto L_51; /* 0051: j 51 <ppRecycleRxPkt+0x39> */
L_54:;
  a12 = MEM16(a2 + 12); /* 0054: l16ui a12, a2, 12 */
  a10 = a8; /* 0057: mov.n a10, a8 */
  a11 = MEM32(a2 + 8); /* 0059: l32i.n a11, a2, 8 */
  a8 = (uint32_t)&wDev_AppendRxBlocks; /* 005b: l32r a8, 10 <ppRecycleRxPkt-0x8> (0 <ppRecycleRxPkt-0x18>) */ /* literal: GOT slot for wDev_AppendRxBlocks */
  wDev_AppendRxBlocks(a2, a3, a4, a5); /* call via literal slot */ /* 005e: callx8 a8 */
L_61:;
  a10 = a2; /* 0061: mov.n a10, a2 */
  a8 = (uint32_t)&esf_buf_recycle; /* 0063: l32r a8, 14 <ppRecycleRxPkt-0x4> (0 <ppRecycleRxPkt-0x18>) */ /* literal: GOT slot for esf_buf_recycle */
  esf_buf_recycle(a2, a3, a4, a5); /* call via literal slot */ /* 0066: callx8 a8 */
  return (int32_t)a2; /* 0069: retw.n  */
}

/* ppRecycleTxBuf @ pp.o 00000000 size 7B bind GLOBAL
 * Calls: none | Data refs: none
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t ppRecycleTxBuf(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.ppRecycleTxBuf; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_0:;
  /* 0000: entry a1, 32 */
  a2 = 0x1; /* 0003: movi.n a2, 1 */
  return (int32_t)a2; /* 0005: retw.n  */
}

/* ppCheckTxQIdle @ pp.o 00000004 size 27B bind GLOBAL
 * Calls: lmacIsIdle | Data refs: lmacIsIdle
 *   MMIO: none
 *   funcdb v3: 1 call(s), 1 ref(s); disasm: 1 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t ppCheckTxQIdle(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.ppCheckTxQIdle; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a3 = 0x0; /* 0007: movi.n a3, 0 */
  a2 = 0x0; /* 0009: mov.n a2, a3 */
  a4 = 0x1; /* 000b: movi.n a4, 1 */
L_d:;
  a10 = 0x0; /* 000d: mov.n a10, a3 */
  a8 = (uint32_t)&lmacIsIdle; /* 000f: l32r a8, 0 <ppCheckTxQIdle-0x4> (0 <ppCheckTxQIdle-0x4>) */ /* literal: GOT slot for lmacIsIdle */
  lmacIsIdle(a2, a3, a4, a5); /* call via literal slot */ /* 0012: callx8 a8 */
  a3 = a3 + (1); /* 0015: addi.n a3, a3, 1 */
  if (a10 == 0) a2 = a4; /* 0017: moveqz a2, a4, a10 */
  if (a3 != 5) goto L_d; /* 001a: bnei a3, 5, d <ppCheckTxQIdle+0x9> */
  return (int32_t)a2; /* 001d: retw.n  */
}

/* ppCheckIsConnTraffic @ pp.o 00000000 size 78B bind GLOBAL
 * Calls: none | Data refs: none
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: medium - 32 instr, 6 branches, calls resolved */
int32_t ppCheckIsConnTraffic(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.ppCheckIsConnTraffic; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_0:;
  /* 0000: entry a1, 32 */
  a10 = MEM32(a2 + 44); /* 0003: l32i.n a10, a2, 44 */
  a8 = 0x0; /* 0005: movi.n a8, 0 */
  a9 = MEM32(a10 + 16); /* 0007: l32i.n a9, a10, 16 */
  a9 = (a9 >> 18) & 0x3; /* 0009: extui a9, a9, 18, 2 */
  if (a9 != a8) goto L_4a; /* 000c: bne a9, a8, 4a <ppCheckIsConnTraffic+0x4a> */
  a8 = 0x1; /* 000f: movi.n a8, 1 */
  a10 = MEM32(a10 + 0); /* 0011: l32i.n a10, a10, 0 */
  a8 = 0x200000; /* 0013: slli a8, a8, 21 */
  a9 = a10 & a8; /* 0016: and a9, a10, a8 */
  a8 = 0x1; /* 0019: movi.n a8, 1 */
  if (a9 != 0) goto L_4a; /* 001b: bnez.n a9, 4a <ppCheckIsConnTraffic+0x4a> */
  a11 = MEM32(a2 + 36); /* 001d: l32i.n a11, a2, 36 */
  a8 = a9; /* 001f: mov.n a8, a9 */
  if (a11 == 0) goto L_4a; /* 0021: beqz.n a11, 4a <ppCheckIsConnTraffic+0x4a> */
  a9 = MEM8(a11 + 11); /* 0023: l8ui a9, a11, 11 */
  if ((a9 >> 7) & 1) goto L_4a; /* 0026: bbsi a9, 7, 4a <ppCheckIsConnTraffic+0x4a> */
  a8 = 0x1; /* 0029: movi.n a8, 1 */
  if ((a10 >> 13) & 1) goto L_4a; /* 002b: bbsi a10, 13, 4a <ppCheckIsConnTraffic+0x4a> */
  a2 = MEM32(a2 + 4); /* 002e: l32i.n a2, a2, 4 */
  a8 = MEM32(a2 + 4); /* 0030: l32i a8, a2, 4 */
  if (!((a10 >> 18) & 1)) goto L_38; /* 0033: bbci a10, 18, 38 <ppCheckIsConnTraffic+0x38> */
  a8 = a8 + (4); /* 0036: addi.n a8, a8, 4 */
L_38:;
  a2 = 0xC; /* 0038: movi.n a2, 12 */
  a9 = MEM8(a8 + 0); /* 003a: l8ui a9, a8, 0 */
  a8 = 0x1; /* 003d: movi.n a8, 1 */
  a9 = a9 & a2; /* 003f: and a9, a9, a2 */
  a2 = 0x0; /* 0042: movi.n a2, 0 */
  if (a9 != 0) a8 = a2; /* 0044: movnez a8, a2, a9 */
  a8 = (a8 >> 0) & 0xFF; /* 0047: extui a8, a8, 0, 8 */
L_4a:;
  a2 = a8; /* 004a: mov.n a2, a8 */
  return (int32_t)a2; /* 004c: retw.n  */
}

/* ppCheckTxConnTrafficIdle @ pp.o 0000001c size 204B bind GLOBAL
 * Calls: lmacGetTxFrame, ppCheckIsConnTraffic | Data refs: lmacGetTxFrame, pTxRx, ppCheckIsConnTraffic
 *   MMIO: none
 *   funcdb v3: 2 call(s), 3 ref(s); disasm: 6 call(s), 3 data ref(s)
 * Fidelity: medium - 79 instr, 19 branches, calls resolved */
int32_t ppCheckTxConnTrafficIdle(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.ppCheckTxConnTrafficIdle; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_1c:;
  /* 001c: entry a1, 32 */
  a2 = 0x0; /* 001f: movi.n a2, 0 */
L_21:;
  a10 = 0x0; /* 0021: mov.n a10, a2 */
  a8 = (uint32_t)&lmacGetTxFrame; /* 0023: l32r a8, 4 <ppCheckTxConnTrafficIdle-0x18> (0 <ppCheckTxConnTrafficIdle-0x1c>) */ /* literal: GOT slot for lmacGetTxFrame */
  lmacGetTxFrame(a2, a3, a4, a5); /* call via literal slot */ /* 0026: callx8 a8 */
  if (a10 == 0) goto L_34; /* 0029: beqz.n a10, 34 <ppCheckTxConnTrafficIdle+0x18> */
  a8 = (uint32_t)&ppCheckIsConnTraffic; /* 002b: l32r a8, 8 <ppCheckTxConnTrafficIdle-0x14> (0 <ppCheckTxConnTrafficIdle-0x1c>) */ /* literal: GOT slot for ppCheckIsConnTraffic */
  ppCheckIsConnTraffic(a2, a3, a4, a5); /* call via literal slot */ /* 002e: callx8 a8 */
  if (a10 != 0) goto L_e4; /* 0031: bnez a10, e4 <ppCheckTxConnTrafficIdle+0xc8> */
L_34:;
  a2 = a2 + (1); /* 0034: addi.n a2, a2, 1 */
  if (a2 != 5) goto L_21; /* 0036: bnei a2, 5, 21 <ppCheckTxConnTrafficIdle+0x5> */
  a2 = (uint32_t)&pTxRx; /* 0039: l32r a2, 0 <ppCheckTxConnTrafficIdle-0x1c> (0 <ppCheckTxConnTrafficIdle-0x1c>) */ /* literal @0x0: pTxRx */
  a4 = 0x1; /* 003c: movi.n a4, 1 */
  a5 = 0xFFFFFFFF; /* 003e: movi.n a5, -1 */
  a3 = MEM32(a2 + 0); /* 0040: l32i.n a3, a2, 0 */
  a2 = MEM32(a3 + 0); /* 0042: l32i.n a2, a3, 0 */
  goto L_98; /* 0044: j 98 <ppCheckTxConnTrafficIdle+0x7c> */
  /* 0047: .byte 00 */
L_48:;
  a8 = -a2; /* 0048: neg a8, a2 */
  a8 = a8 & a2; /* 004b: and a8, a8, a2 */
  a8 = __builtin_clz(a8) /* approx for nsau */; /* 004e: nsau a8, a8 */
  a8 = -a8; /* 0051: neg a8, a8 */
  a6 = a8 + (31); /* 0054: addi a6, a8, 31 */
  a8 = (a6 << 2) + a6; /* 0057: addx2 a8, a6, a6 */
  a8 = a8 << (4 & 31); /* 005a: slli a8, a8, 4 */
  a8 = a3 + a8; /* 005d: add.n a8, a3, a8 */
  a7 = MEM32(a8 + 32); /* 005f: l32i.n a7, a8, 32 */
  goto L_71; /* 0061: j 71 <ppCheckTxConnTrafficIdle+0x55> */
L_64:;
  a10 = a7; /* 0064: mov.n a10, a7 */
  a8 = (uint32_t)&ppCheckIsConnTraffic; /* 0066: l32r a8, c <ppCheckTxConnTrafficIdle-0x10> (0 <ppCheckTxConnTrafficIdle-0x1c>) */ /* literal: GOT slot for ppCheckIsConnTraffic */
  ppCheckIsConnTraffic(a2, a3, a4, a5); /* call via literal slot */ /* 0069: callx8 a8 */
  if (a10 != 0) goto L_e4; /* 006c: bnez a10, e4 <ppCheckTxConnTrafficIdle+0xc8> */
  a7 = MEM32(a7 + 40); /* 006f: l32i.n a7, a7, 40 */
L_71:;
  if (a7 != 0) goto L_64; /* 0071: bnez a7, 64 <ppCheckTxConnTrafficIdle+0x48> */
  a9 = a6 + (1); /* 0074: addi.n a9, a6, 1 */
  a9 = (a9 << 2) + a9; /* 0076: addx2 a9, a9, a9 */
  a9 = a9 << (4 & 31); /* 0079: slli a9, a9, 4 */
  a9 = a3 + a9; /* 007c: add.n a9, a3, a9 */
  a10 = MEM32(a9 + 4); /* 007e: l32i.n a10, a9, 4 */
  if (a10 == 0) goto L_8c; /* 0080: beqz a10, 8c <ppCheckTxConnTrafficIdle+0x70> */
  a8 = (uint32_t)&ppCheckIsConnTraffic; /* 0083: l32r a8, 10 <ppCheckTxConnTrafficIdle-0xc> (0 <ppCheckTxConnTrafficIdle-0x1c>) */ /* literal: GOT slot for ppCheckIsConnTraffic */
  ppCheckIsConnTraffic(a2, a3, a4, a5); /* call via literal slot */ /* 0086: callx8 a8 */
  if (a10 != 0) goto L_e4; /* 0089: bnez a10, e4 <ppCheckTxConnTrafficIdle+0xc8> */
L_8c:;
  /* 008c: ssl a6 */ /* UNMODELED: a6 clobbered */
  /* 008f: sll a8, a4 */ /* UNMODELED: a8 clobbered */
  a8 = a5 ^ a8; /* 0092: xor a8, a5, a8 */
  a2 = a2 & a8; /* 0095: and a2, a2, a8 */
L_98:;
  if (a2 != 0) goto L_48; /* 0098: bnez a2, 48 <ppCheckTxConnTrafficIdle+0x2c> */
  a4 = 0x334; /* 009b: movi a4, 0x334 */
  a6 = 0x34C; /* 009e: movi a6, 0x34c */
  a4 = a3 + a4; /* 00a1: add.n a4, a3, a4 */
  a6 = a3 + a6; /* 00a3: add.n a6, a3, a6 */
L_a5:;
  a5 = MEM32(a4 + 0); /* 00a5: l32i.n a5, a4, 0 */
  goto L_b6; /* 00a7: j b6 <ppCheckTxConnTrafficIdle+0x9a> */
L_aa:;
  a10 = a5; /* 00aa: mov.n a10, a5 */
  a8 = (uint32_t)&ppCheckIsConnTraffic; /* 00ac: l32r a8, 14 <ppCheckTxConnTrafficIdle-0x8> (0 <ppCheckTxConnTrafficIdle-0x1c>) */ /* literal: GOT slot for ppCheckIsConnTraffic */
  ppCheckIsConnTraffic(a2, a3, a4, a5); /* call via literal slot */ /* 00af: callx8 a8 */
  if (a10 != 0) goto L_e4; /* 00b2: bnez.n a10, e4 <ppCheckTxConnTrafficIdle+0xc8> */
  a5 = MEM32(a5 + 40); /* 00b4: l32i.n a5, a5, 40 */
L_b6:;
  if (a5 != 0) goto L_aa; /* 00b6: bnez a5, aa <ppCheckTxConnTrafficIdle+0x8e> */
  a4 = a4 + (8); /* 00b9: addi.n a4, a4, 8 */
  if (a6 != a4) goto L_a5; /* 00bb: bne a6, a4, a5 <ppCheckTxConnTrafficIdle+0x89> */
  a5 = 0xE0; /* 00be: movi a5, 224 */
  a4 = a3 + (32); /* 00c1: addi a4, a3, 32 */
  a3 = a3 + a5; /* 00c4: add.n a3, a3, a5 */
L_c6:;
  a5 = MEM32(a4 + 0); /* 00c6: l32i.n a5, a4, 0 */
  goto L_d8; /* 00c8: j d8 <ppCheckTxConnTrafficIdle+0xbc> */
  /* 00cb: .byte 00 */
L_cc:;
  a10 = a5; /* 00cc: mov.n a10, a5 */
  a8 = (uint32_t)&ppCheckIsConnTraffic; /* 00ce: l32r a8, 18 <ppCheckTxConnTrafficIdle-0x4> (0 <ppCheckTxConnTrafficIdle-0x1c>) */ /* literal: GOT slot for ppCheckIsConnTraffic */
  ppCheckIsConnTraffic(a2, a3, a4, a5); /* call via literal slot */ /* 00d1: callx8 a8 */
  if (a10 != 0) goto L_e4; /* 00d4: bnez.n a10, e4 <ppCheckTxConnTrafficIdle+0xc8> */
  a5 = MEM32(a5 + 40); /* 00d6: l32i.n a5, a5, 40 */
L_d8:;
  if (a5 != 0) goto L_cc; /* 00d8: bnez a5, cc <ppCheckTxConnTrafficIdle+0xb0> */
  a4 = a4 + (48); /* 00db: addi a4, a4, 48 */
  if (a4 != a3) goto L_c6; /* 00de: bne a4, a3, c6 <ppCheckTxConnTrafficIdle+0xaa> */
  goto L_e6; /* 00e1: j e6 <ppCheckTxConnTrafficIdle+0xca> */
L_e4:;
  a2 = 0x1; /* 00e4: movi.n a2, 1 */
L_e6:;
  return (int32_t)a2; /* 00e6: retw.n  */
}

/* pp_coex_tx_release @ pp.o 00000004 size 91B bind GLOBAL
 * Calls: g_osi_funcs_p[got] | Data refs: g_osi_funcs_p
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 1 call(s), 1 data ref(s)
 * Fidelity: medium - 36 instr, 8 branches, calls resolved */
int32_t pp_coex_tx_release(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .wifiextrairam.18; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a8 = MEM32(a2 + 4); /* 0007: l32i.n a8, a2, 4 */
  a10 = 0xC; /* 0009: movi.n a10, 12 */
  a8 = MEM32(a8 + 4); /* 000b: l32i.n a8, a8, 4 */
  a9 = MEM8(a8 + 0); /* 000d: l8ui a9, a8, 0 */
  a8 = 0xFFFFFFF0; /* 0010: movi.n a8, -16 */
  a10 = a9 & a10; /* 0012: and a10, a9, a10 */
  a8 = a9 & a8; /* 0015: and a8, a9, a8 */
  if (a10 != 0) goto L_44; /* 0018: bnez.n a10, 44 <pp_coex_tx_release+0x40> */
  if (a8 != 128) goto L_2a; /* 001a: bnei a8, 128, 2a <pp_coex_tx_release+0x26> */
  a8 = (uint32_t)&g_osi_funcs_p; /* 001d: l32r a8, 0 <pp_coex_tx_release-0x4> (0 <pp_coex_tx_release-0x4>) */ /* literal @0x0: g_osi_funcs_p */
  a10 = 0x4; /* 0020: movi.n a10, 4 */
  a8 = MEM32(a8 + 0); /* 0022: l32i.n a8, a8, 0 */
  a8 = MEM32(a8 + 416); /* 0024: l32i a8, a8, 0x1a0 */
  goto L_5a; /* 0027: j 5a <pp_coex_tx_release+0x56> */
L_2a:;
  if (a10 != 0) goto L_44; /* 002a: bnez.n a10, 44 <pp_coex_tx_release+0x40> */
  a8 = a8 + (96); /* 002c: addi a8, a8, 96 */
  a9 = 0xD0; /* 002f: movi a9, 208 */
  if ((a8 & a9) != 0) goto L_5d; /* 0032: bany a8, a9, 5d <pp_coex_tx_release+0x59> */
  a8 = (uint32_t)&g_osi_funcs_p; /* 0035: l32r a8, 0 <pp_coex_tx_release-0x4> (0 <pp_coex_tx_release-0x4>) */ /* literal @0x0: g_osi_funcs_p */
  a10 = 0x7; /* 0038: movi.n a10, 7 */
  a8 = MEM32(a8 + 0); /* 003a: l32i.n a8, a8, 0 */
  a8 = MEM32(a8 + 416); /* 003c: l32i a8, a8, 0x1a0 */
  goto L_5a; /* 003f: j 5a <pp_coex_tx_release+0x56> */
  /* 0042: .byte 00 */
  /* 0043: .byte 00 */
L_44:;
  if (a10 != 8) goto L_5d; /* 0044: bnei a10, 8, 5d <pp_coex_tx_release+0x59> */
  a8 = 0x70; /* 0047: movi a8, 112 */
  a9 = 0x50; /* 004a: and a9, a9, a8 */
  if (a9 != 64) goto L_5d; /* 004d: bnei a9, 64, 5d <pp_coex_tx_release+0x59> */
  a8 = (uint32_t)&g_osi_funcs_p; /* 0050: l32r a8, 0 <pp_coex_tx_release-0x4> (0 <pp_coex_tx_release-0x4>) */ /* literal @0x0: g_osi_funcs_p */
  a10 = 0x9; /* 0053: movi.n a10, 9 */
  a8 = MEM32(a8 + 0); /* 0055: l32i.n a8, a8, 0 */
  a8 = MEM32(a8 + 416); /* 0057: l32i a8, a8, 0x1a0 */
L_5a:;
  g_osi_funcs_p(a2, a3, a4, a5); /* call via literal slot */ /* 005a: callx8 a8 */
L_5d:;
  return (int32_t)a2; /* 005d: retw.n  */
}

/* ppProcTxCallback @ pp.o 00000004 size 81B bind GLOBAL
 * Calls: none | Data refs: pTxRx
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 1 data ref(s)
 * Fidelity: medium - 30 instr, 6 branches, calls resolved */
int32_t ppProcTxCallback(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .wifi0iram.19; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a4 = MEM32(a2 + 44); /* 0007: l32i.n a4, a2, 44 */
  a3 = (a3 >> 0) & 0xFF; /* 0009: extui a3, a3, 0, 8 */
  a4 = MEM32(a4 + 20); /* 000c: l32i.n a4, a4, 20 */
  goto L_50; /* 000e: j 50 <ppProcTxCallback+0x4c> */
L_11:;
  a8 = -a4; /* 0011: neg a8, a4 */
  a8 = a8 & a4; /* 0014: and a8, a8, a4 */
  a5 = (uint32_t)&pTxRx; /* 0017: l32r a5, 0 <ppProcTxCallback-0x4> (0 <ppProcTxCallback-0x4>) */ /* literal @0x0: pTxRx */
  a8 = __builtin_clz(a8) /* approx for nsau */; /* 001a: nsau a8, a8 */
  a8 = -a8; /* 001d: neg a8, a8 */
  a8 = a8 + (31); /* 0020: addi a8, a8, 31 */
  a9 = MEM32(a5 + 0); /* 0023: l32i.n a9, a5, 0 */
  a5 = 0x1; /* 0025: movi.n a5, 1 */
  /* 0027: ssl a8 */ /* UNMODELED: a8 clobbered */
  /* 002a: sll a5, a5 */ /* UNMODELED: a5 clobbered */
  if (a3 == 0) goto L_35; /* 002d: beqz.n a3, 35 <ppProcTxCallback+0x31> */
  a10 = MEM32(a9 + 968); /* 002f: l32i a10, a9, 0x3c8 */
  goto L_38; /* 0032: j 38 <ppProcTxCallback+0x34> */
L_35:;
  a10 = MEM32(a9 + 860); /* 0035: l32i a10, a9, 0x35c */
L_38:;
  if ((a5 & a10) == 0) goto L_48; /* 0038: bnone a5, a10, 48 <ppProcTxCallback+0x44> */
  a8 = (a8 << 4) + a9; /* 003b: addx4 a8, a8, a9 */
  a8 = MEM32(a8 + 868); /* 003e: l32i a8, a8, 0x364 */
  if (a8 == 0) goto L_48; /* 0041: beqz.n a8, 48 <ppProcTxCallback+0x44> */
  a10 = a2; /* 0043: mov.n a10, a2 */
  ((int32_t(*)())a8)(a2, a3, a4, a5); /* 0045: callx8 a8 */ /* indirect */
L_48:;
  a8 = 0xFFFFFFFF; /* 0048: movi.n a8, -1 */
  a5 = a8 ^ a5; /* 004a: xor a5, a8, a5 */
  a4 = a4 & a5; /* 004d: and a4, a4, a5 */
L_50:;
  if (a4 != 0) goto L_11; /* 0050: bnez a4, 11 <ppProcTxCallback+0xd> */
  return (int32_t)a2; /* 0053: retw.n  */
}

/* ppSetInterface @ pp.o 00000000 size 5B bind GLOBAL
 * Calls: none | Data refs: none
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t ppSetInterface(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.ppSetInterface; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_0:;
  /* 0000: entry a1, 32 */
  return (int32_t)a2; /* 0003: retw.n  */
}

/* pp_coex_tx_request @ pp.o 00000010 size 276B bind GLOBAL
 * Calls: pm_coex_reconnect_policy[got], chm_get_current_band[got], pm_coex_reconnect_policy[got], g_osi_funcs_p[got], g_osi_funcs_p[got] | Data refs: g_osi_funcs_p, pm_coex_reconnect_policy, chm_get_current_band
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 5 call(s), 3 data ref(s)
 * Fidelity: low - 114 instr, 19 branches, 4 indirect; call-sequence + MMIO skeleton */
int32_t pp_coex_tx_request(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .wifi0iram.22; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_10:;
  /* 0010: entry a1, 48 */
  a3 = MEM32(a2 + 4); /* 0013: l32i.n a3, a2, 4 */
  a4 = 0x0; /* 0015: movi.n a4, 0 */
  a8 = 0xFFFFFFF0; /* 0017: movi.n a8, -16 */
  a3 = MEM32(a3 + 4); /* 0019: l32i.n a3, a3, 4 */
  MEM32(a1 + 0) = a4; /* 001b: s32i.n a4, a1, 0 */
  a9 = MEM8(a3 + 0); /* 001d: l8ui a9, a3, 0 */
  a3 = 0xC; /* 0020: movi.n a3, 12 */
  a3 = a9 & a3; /* 0022: and a3, a9, a3 */
  a8 = a9 & a8; /* 0025: and a8, a9, a8 */
  if (a3 != a4) goto L_79; /* 0028: bne a3, a4, 79 <pp_coex_tx_request+0x69> */
  if (a8 != 128) goto L_4e; /* 002b: bnei a8, 128, 4e <pp_coex_tx_request+0x3e> */
  a2 = (uint32_t)&g_osi_funcs_p; /* 002e: l32r a2, 0 <pp_coex_tx_request-0x10> (0 <pp_coex_tx_request-0x10>) */ /* literal @0x0: g_osi_funcs_p */
  a11 = a1; /* 0031: mov.n a11, a1 */
  a10 = 0x4; /* 0033: movi.n a10, 4 */
  a3 = MEM32(a2 + 0); /* 0035: l32i.n a3, a2, 0 */
  a3 = MEM32(a3 + 424); /* 0037: l32i a3, a3, 0x1a8 */
  MEMW(); /* 003a: memw  */
  ((int32_t(*)())a3)(a2, a3, a4, a5); /* 003d: callx8 a3 */ /* indirect */
  a11 = a4; /* 0040: mov.n a11, a4 */
  a10 = 0x4; /* 0042: movi.n a10, 4 */
  a2 = MEM32(a2 + 0); /* 0044: l32i.n a2, a2, 0 */
  a12 = MEM32(a1 + 0); /* 0046: l32i.n a12, a1, 0 */
  a2 = MEM32(a2 + 412); /* 0048: l32i a2, a2, 0x19c */
  goto L_11f; /* 004b: j 11f <pp_coex_tx_request+0x10f> */
L_4e:;
  if (a3 != 0) goto L_79; /* 004e: bnez.n a3, 79 <pp_coex_tx_request+0x69> */
  a10 = a8 + (96); /* 0050: addi a10, a8, 96 */
  a4 = 0xD0; /* 0053: movi a4, 208 */
  if ((a10 & a4) != 0) goto L_a4; /* 0056: bany a10, a4, a4 <pp_coex_tx_request+0x94> */
  a2 = (uint32_t)&g_osi_funcs_p; /* 0059: l32r a2, 0 <pp_coex_tx_request-0x10> (0 <pp_coex_tx_request-0x10>) */ /* literal @0x0: g_osi_funcs_p */
  a11 = a1; /* 005c: mov.n a11, a1 */
  a10 = 0x7; /* 005e: movi.n a10, 7 */
  a4 = MEM32(a2 + 0); /* 0060: l32i.n a4, a2, 0 */
  a4 = MEM32(a4 + 424); /* 0062: l32i a4, a4, 0x1a8 */
  ((int32_t(*)())a4)(a2, a3, a4, a5); /* 0065: callx8 a4 */ /* indirect */
  a11 = a3; /* 0068: mov.n a11, a3 */
  a10 = 0x7; /* 006a: movi.n a10, 7 */
  a2 = MEM32(a2 + 0); /* 006c: l32i.n a2, a2, 0 */
  a12 = MEM32(a1 + 0); /* 006e: l32i.n a12, a1, 0 */
  a2 = MEM32(a2 + 412); /* 0070: l32i a2, a2, 0x19c */
  goto L_11f; /* 0073: j 11f <pp_coex_tx_request+0x10f> */
  /* 0076: .byte 00 */
  /* 0077: .byte 00 */
  /* 0078: .byte 00 */
L_79:;
  if (a3 != 8) goto L_da; /* 0079: bnei a3, 8, da <pp_coex_tx_request+0xca> */
  a10 = 0x70; /* 007c: movi a10, 112 */
  a10 = a9 & a10; /* 007f: and a10, a9, a10 */
  if (a10 != 64) goto L_da; /* 0082: bnei a10, 64, da <pp_coex_tx_request+0xca> */
  a2 = (uint32_t)&g_osi_funcs_p; /* 0085: l32r a2, 0 <pp_coex_tx_request-0x10> (0 <pp_coex_tx_request-0x10>) */ /* literal @0x0: g_osi_funcs_p */
  a11 = a1; /* 0088: mov.n a11, a1 */
  a10 = 0x9; /* 008a: movi.n a10, 9 */
  a3 = MEM32(a2 + 0); /* 008c: l32i.n a3, a2, 0 */
  a3 = MEM32(a3 + 424); /* 008e: l32i a3, a3, 0x1a8 */
  ((int32_t(*)())a3)(a2, a3, a4, a5); /* 0091: callx8 a3 */ /* indirect */
  a11 = 0x0; /* 0094: movi.n a11, 0 */
  a10 = 0x9; /* 0096: movi.n a10, 9 */
  a2 = MEM32(a2 + 0); /* 0098: l32i.n a2, a2, 0 */
  a12 = MEM32(a1 + 0); /* 009a: l32i.n a12, a1, 0 */
  a2 = MEM32(a2 + 412); /* 009c: l32i a2, a2, 0x19c */
  goto L_11f; /* 009f: j 11f <pp_coex_tx_request+0x10f> */
  /* 00a2: .byte 00 */
  /* 00a3: .byte 00 */
L_a4:;
  if (a8 != 64) goto L_da; /* 00a4: bnei a8, 64, da <pp_coex_tx_request+0xca> */
  a8 = (uint32_t)&pm_coex_reconnect_policy; /* 00a7: l32r a8, 4 <pp_coex_tx_request-0xc> (0 <pp_coex_tx_request-0x10>) */ /* literal: GOT slot for pm_coex_reconnect_policy */
  pm_coex_reconnect_policy(a2, a3, a4, a5); /* call via literal slot */ /* 00aa: callx8 a8 */
  if (a10 == 0) goto L_cc; /* 00ad: beqz.n a10, cc <pp_coex_tx_request+0xbc> */
L_af:;
  a2 = (uint32_t)&g_osi_funcs_p; /* 00af: l32r a2, 0 <pp_coex_tx_request-0x10> (0 <pp_coex_tx_request-0x10>) */ /* literal @0x0: g_osi_funcs_p */
  a11 = a1; /* 00b2: mov.n a11, a1 */
  a10 = 0x27; /* 00b4: movi.n a10, 39 */
  a3 = MEM32(a2 + 0); /* 00b6: l32i.n a3, a2, 0 */
  a3 = MEM32(a3 + 424); /* 00b8: l32i a3, a3, 0x1a8 */
  ((int32_t(*)())a3)(a2, a3, a4, a5); /* 00bb: callx8 a3 */ /* indirect */
  a11 = 0x0; /* 00be: movi.n a11, 0 */
  a10 = 0x27; /* 00c0: movi.n a10, 39 */
  a2 = MEM32(a2 + 0); /* 00c2: l32i.n a2, a2, 0 */
  a12 = MEM32(a1 + 0); /* 00c4: l32i.n a12, a1, 0 */
  a2 = MEM32(a2 + 412); /* 00c6: l32i a2, a2, 0x19c */
  goto L_11f; /* 00c9: j 11f <pp_coex_tx_request+0x10f> */
L_cc:;
  a8 = (uint32_t)&chm_get_current_band; /* 00cc: l32r a8, 8 <pp_coex_tx_request-0x8> (0 <pp_coex_tx_request-0x10>) */ /* literal: GOT slot for chm_get_current_band */
  chm_get_current_band(a2, a3, a4, a5); /* call via literal slot */ /* 00cf: callx8 a8 */
  if (a10 != 2) goto L_122; /* 00d2: bnei a10, 2, 122 <pp_coex_tx_request+0x112> */
  goto L_af; /* 00d5: j af <pp_coex_tx_request+0x9f> */
  /* 00d8: .byte 00 */
  /* 00d9: .byte 00 */
L_da:;
  a2 = MEM32(a2 + 44); /* 00da: l32i.n a2, a2, 44 */
  a2 = MEM32(a2 + 0); /* 00dc: l32i.n a2, a2, 0 */
  if ((a2 >> 2) & 1) goto L_fc; /* 00de: bbsi a2, 2, fc <pp_coex_tx_request+0xec> */
  if (a3 != 0) goto L_122; /* 00e1: bnez.n a3, 122 <pp_coex_tx_request+0x112> */
  a2 = 0xFFFFFFD0; /* 00e3: movi a2, -48 */
  a9 = a9 & a2; /* 00e6: and a9, a9, a2 */
  a10 = 0x1; /* 00e9: movi.n a10, 1 */
  a2 = a3; /* 00eb: mov.n a2, a3 */
  if (a9 == 0) a2 = a10; /* 00ed: moveqz a2, a10, a9 */
  if (a2 != 0) goto L_fc; /* 00f0: bnez.n a2, fc <pp_coex_tx_request+0xec> */
  a2 = 0xFFFFFF50; /* 00f2: movi a2, -176 */
  a8 = a8 + a2; /* 00f5: add.n a8, a8, a2 */
  if (a8 != 0) a10 = a3; /* 00f7: movnez a10, a3, a8 */
  if (a10 == 0) goto L_122; /* 00fa: beqz.n a10, 122 <pp_coex_tx_request+0x112> */
L_fc:;
  a8 = (uint32_t)&pm_coex_reconnect_policy; /* 00fc: l32r a8, c <pp_coex_tx_request-0x4> (0 <pp_coex_tx_request-0x10>) */ /* literal: GOT slot for pm_coex_reconnect_policy */
  pm_coex_reconnect_policy(a2, a3, a4, a5); /* call via literal slot */ /* 00ff: callx8 a8 */
  if (a10 == 0) goto L_122; /* 0102: beqz.n a10, 122 <pp_coex_tx_request+0x112> */
  a3 = (uint32_t)&g_osi_funcs_p; /* 0104: l32r a3, 0 <pp_coex_tx_request-0x10> (0 <pp_coex_tx_request-0x10>) */ /* literal @0x0: g_osi_funcs_p */
  a11 = a1; /* 0107: mov.n a11, a1 */
  a10 = 0x28; /* 0109: movi a10, 40 */
  a2 = MEM32(a3 + 0); /* 010c: l32i.n a2, a3, 0 */
  a2 = MEM32(a2 + 424); /* 010e: l32i a2, a2, 0x1a8 */
  ((int32_t(*)())a2)(a2, a3, a4, a5); /* 0111: callx8 a2 */ /* indirect */
  a11 = 0x0; /* 0114: movi.n a11, 0 */
  a10 = 0x28; /* 0116: movi.n a10, 40 */
  a2 = MEM32(a3 + 0); /* 0118: l32i.n a2, a3, 0 */
  a12 = MEM32(a1 + 0); /* 011a: l32i.n a12, a1, 0 */
  a2 = MEM32(a2 + 412); /* 011c: l32i a2, a2, 0x19c */
L_11f:;
  ((int32_t(*)())a2)(a2, a3, a4, a5); /* 011f: callx8 a2 */ /* indirect */
L_122:;
  return (int32_t)a2; /* 0122: retw.n  */
}

/* esp_wifi_enable_easy_fragment @ pp.o 00000000 size 5B bind GLOBAL
 * Calls: none | Data refs: none
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t esp_wifi_enable_easy_fragment(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.esp_wifi_enable_easy_fragment; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_0:;
  /* 0000: entry a1, 32 */
  return (int32_t)a2; /* 0003: retw.n  */
}

/* ppRxProtoProc @ pp.o 0000001c size 256B bind GLOBAL
 * Calls: pm_on_data_rx[got], pp_hdrsize[got], pm_sleep_for[got], pm_set_beacon_duration[got], pm_on_beacon_rx[got], rc_get_trc[got], rcUpdateRxDone[got] | Data refs: pm_on_data_rx, pp_hdrsize, pm_sleep_for, pm_set_beacon_duration, pm_on_beacon_rx, rc_get_trc, rcUpdateRxDone
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 7 call(s), 7 data ref(s)
 * Fidelity: medium - 99 instr, 14 branches, calls resolved */
int32_t ppRxProtoProc(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .wifislprxiram.24; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_1c:;
  /* 001c: entry a1, 48 */
  a4 = MEM32(a2 + 4); /* 001f: l32i.n a4, a2, 4 */
  a6 = 0xFFFFFFF0; /* 0021: movi.n a6, -16 */
  a9 = 0xC; /* 0023: movi.n a9, 12 */
  a5 = MEM32(a4 + 4); /* 0025: l32i.n a5, a4, 4 */
  a4 = MEM8(a5 + 0); /* 0027: l8ui a4, a5, 0 */
  a8 = a4 & a6; /* 002a: and a8, a4, a6 */
  a9 = a4 & a9; /* 002d: and a9, a4, a9 */
  a4 = 0x1; /* 0030: movi.n a4, 1 */
  a7 = MEM32(a3 + 0); /* 0032: l32i.n a7, a3, 0 */
  a4 = 0x20000000; /* 0034: slli a4, a4, 29 */
  a6 = a7 & a4; /* 0037: and a6, a7, a4 */
  if (!((a7 >> 28) & 1)) goto L_48; /* 003a: bbci a7, 28, 48 <ppRxProtoProc+0x2c> */
  a4 = 0x3; /* 003d: movi.n a4, 3 */
  a7 = 0x0; /* 003f: movi.n a7, 0 */
  if (a6 == 0) a4 = a7; /* 0041: moveqz a4, a7, a6 */
  goto L_59; /* 0044: j 59 <ppRxProtoProc+0x3d> */
  /* 0047: .byte 00 */
L_48:;
  a4 = 0x1; /* 0048: movi.n a4, 1 */
  if (a6 != 0) goto L_59; /* 004a: bnez.n a6, 59 <ppRxProtoProc+0x3d> */
  a4 = 0x40000000; /* 004c: slli a4, a4, 30 */
  a7 = 0x0; /* 004f: and a7, a7, a4 */
  a6 = 0x2; /* 0052: movi.n a6, 2 */
  a4 = 0x3; /* 0054: movi.n a4, 3 */
  if (a7 != 0) a4 = a6; /* 0056: movnez a4, a6, a7 */
L_59:;
  if (a9 != 8) goto L_6f; /* 0059: bnei a9, 8, 6f <ppRxProtoProc+0x53> */
  a13 = MEM8(a5 + 1); /* 005c: l8ui a13, a5, 1 */
  a12 = a5 + (4); /* 005f: addi.n a12, a5, 4 */
  a11 = a4; /* 0061: mov.n a11, a4 */
  a10 = a5 + (10); /* 0063: addi a10, a5, 10 */
  a8 = (uint32_t)&pm_on_data_rx; /* 0066: l32r a8, 0 <ppRxProtoProc-0x1c> (0 <ppRxProtoProc-0x1c>) */ /* literal: GOT slot for pm_on_data_rx */
  pm_on_data_rx(a2, a3, a4, a5); /* call via literal slot */ /* 0069: callx8 a8 */
  goto L_fc; /* 006c: j fc <ppRxProtoProc+0xe0> */
L_6f:;
  if (a9 != 0) goto L_fc; /* 006f: bnez a9, fc <ppRxProtoProc+0xe0> */
  if (a8 == 128) goto L_78; /* 0072: beqi a8, 128, 78 <ppRxProtoProc+0x5c> */
  goto L_fc; /* 0075: j fc <ppRxProtoProc+0xe0> */
L_78:;
  a6 = MEM32(a2 + 44); /* 0078: l32i.n a6, a2, 44 */
  a7 = 0x10; /* 007a: movi.n a7, 16 */
  a6 = MEM32(a6 + 0); /* 007c: l32i.n a6, a6, 0 */
  a6 = a6 & a7; /* 007e: and a6, a6, a7 */
  if (a6 != 0) goto L_118; /* 0081: bnez a6, 118 <ppRxProtoProc+0xfc> */
  a10 = a5; /* 0084: mov.n a10, a5 */
  a8 = (uint32_t)&pp_hdrsize; /* 0086: l32r a8, 4 <ppRxProtoProc-0x18> (0 <ppRxProtoProc-0x1c>) */ /* literal: GOT slot for pp_hdrsize */
  pp_hdrsize(a2, a3, a4, a5); /* call via literal slot */ /* 0089: callx8 a8 */
  a8 = MEM32(a3 + 24); /* 008c: l32i.n a8, a3, 24 */
  a7 = (a10 >> 0) & 0xFFFF; /* 008e: extui a7, a10, 0, 16 */
  a8 = (a8 >> 0) & 0xFFF; /* 0091: extui a8, a8, 0, 12 */
  a7 = a7 + (3); /* 0094: addi.n a7, a7, 3 */
  if (a7 >= a8) goto L_a2; /* 0096: bge a7, a8, a2 <ppRxProtoProc+0x86> */
  a8 = a8 + (-4); /* 0099: addi a8, a8, -4 */
  a8 = a8 - a10; /* 009c: sub a8, a8, a10 */
  a6 = (a8 >> 0) & 0xFFFF; /* 009f: extui a6, a8, 0, 16 */
L_a2:;
  a10 = a5 + (10); /* 00a2: addi.n a10, a5, 10 */
  a8 = (uint32_t)&pm_sleep_for; /* 00a4: l32r a8, 8 <ppRxProtoProc-0x14> (0 <ppRxProtoProc-0x1c>) */ /* literal: GOT slot for pm_sleep_for */
  pm_sleep_for(a2, a3, a4, a5); /* call via literal slot */ /* 00a7: callx8 a8 */
  if (a10 == 0) goto L_fc; /* 00aa: beqz a10, fc <ppRxProtoProc+0xe0> */
  a7 = MEM16(a2 + 12); /* 00ad: l16ui a7, a2, 12 */
  if (a7 != 1) goto L_fc; /* 00b0: bnei a7, 1, fc <ppRxProtoProc+0xe0> */
  a9 = 0x1F; /* 00b3: movi.n a9, 31 */
  a9 = 0x1F00; /* 00b5: slli a9, a9, 8 */
  a8 = MEM32(a3 + 0); /* 00b8: l32i.n a8, a3, 0 */
  a11 = a5 + (24); /* 00ba: addi a11, a5, 24 */
  a8 = a8 & a9; /* 00bd: and a8, a8, a9 */
  a8 = a8 + ((0xfffff500) << 8); /* 00c0: addmi a8, a8, 0xfffff500 */
  a9 = 0x6; /* 00c3: movi.n a9, 6 */
  a10 = MEM32(a3 + 24); /* 00c5: l32i.n a10, a3, 24 */
  if (a8 == 0) a7 = a9; /* 00c7: moveqz a7, a9, a8 */
  a10 = (a10 >> 12) & 0xFFF; /* 00ca: extui a10, a10, 12, 12 */
  a10 = a10 << (3 & 31); /* 00cd: slli a10, a10, 3 */
  /* 00d0: quou a10, a10, a7 */ /* UNMODELED: a10 clobbered */
  MEM32(a1 + 0) = a11; /* 00d3: s32i.n a11, a1, 0 */
  MEMW(); /* 00d5: memw  */
  a8 = (uint32_t)&pm_set_beacon_duration; /* 00d8: l32r a8, c <ppRxProtoProc-0x10> (0 <ppRxProtoProc-0x1c>) */ /* literal: GOT slot for pm_set_beacon_duration */
  pm_set_beacon_duration(a2, a3, a4, a5); /* call via literal slot */ /* 00db: callx8 a8 */
  a13 = 0x0; /* 00de: movi.n a13, 0 */
  a8 = MEM32(a3 + 24); /* 00e0: l32i.n a8, a3, 24 */
  a8 = (a8 >> 0) & 0xFFF; /* 00e2: extui a8, a8, 0, 12 */
  a8 = a8 << (3 & 31); /* 00e5: slli a8, a8, 3 */
  /* 00e8: quou a8, a8, a7 */ /* UNMODELED: a8 clobbered */
  a9 = MEM32(a2 + 44); /* 00eb: l32i.n a9, a2, 44 */
  a11 = MEM32(a1 + 0); /* 00ed: l32i.n a11, a1, 0 */
  a12 = a11 + a6; /* 00ef: add.n a12, a11, a6 */
  a10 = MEM32(a9 + 4); /* 00f1: l32i.n a10, a9, 4 */
  a10 = a10 - a8; /* 00f3: sub a10, a10, a8 */
  a8 = (uint32_t)&pm_on_beacon_rx; /* 00f6: l32r a8, 10 <ppRxProtoProc-0xc> (0 <ppRxProtoProc-0x1c>) */ /* literal: GOT slot for pm_on_beacon_rx */
  pm_on_beacon_rx(a2, a3, a4, a5); /* call via literal slot */ /* 00f9: callx8 a8 */
L_fc:;
  if (a4 == 3) goto L_118; /* 00fc: beqi a4, 3, 118 <ppRxProtoProc+0xfc> */
  a11 = a5 + (10); /* 00ff: addi.n a11, a5, 10 */
  a10 = a4; /* 0101: mov.n a10, a4 */
  a8 = (uint32_t)&rc_get_trc; /* 0103: l32r a8, 14 <ppRxProtoProc-0x8> (0 <ppRxProtoProc-0x1c>) */ /* literal: GOT slot for rc_get_trc */
  rc_get_trc(a2, a3, a4, a5); /* call via literal slot */ /* 0106: callx8 a8 */
  MEM32(a2 + 36) = a10; /* 0109: s32i.n a10, a2, 36 */
  if (a10 == 0) goto L_118; /* 010b: beqz.n a10, 118 <ppRxProtoProc+0xfc> */
  a11 = a3; /* 010d: mov.n a11, a3 */
  MEMW(); /* 010f: memw  */
  a8 = (uint32_t)&rcUpdateRxDone; /* 0112: l32r a8, 18 <ppRxProtoProc-0x4> (0 <ppRxProtoProc-0x1c>) */ /* literal: GOT slot for rcUpdateRxDone */
  rcUpdateRxDone(a2, a3, a4, a5); /* call via literal slot */ /* 0115: callx8 a8 */
L_118:;
  a2 = 0x0; /* 0118: movi.n a2, 0 */
  return (int32_t)a2; /* 011a: retw.n  */
}

/* pp_gettid @ pp.o 00000000 size 46B bind GLOBAL
 * Calls: none | Data refs: none
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t pp_gettid(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pp_gettid; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_0:;
  /* 0000: entry a1, 32 */
  a9 = MEM8(a2 + 0); /* 0003: l8ui a9, a2, 0 */
  a8 = 0x8C; /* 0006: movi a8, 140 */
  a9 = a9 & a8; /* 0009: and a9, a9, a8 */
  a10 = 0x88; /* 000c: movi a10, 136 */
  a8 = 0x10; /* 000f: movi.n a8, 16 */
  if (a9 != a10) goto L_2a; /* 0011: bne a9, a10, 2a <pp_gettid+0x2a> */
  a8 = MEM8(a2 + 1); /* 0014: l8ui a8, a2, 1 */
  a8 = (a8 >> 0) & 0x3; /* 0017: extui a8, a8, 0, 2 */
  if (a8 != 3) goto L_24; /* 001a: bnei a8, 3, 24 <pp_gettid+0x24> */
  a8 = MEM8(a2 + 30); /* 001d: l8ui a8, a2, 30 */
  goto L_27; /* 0020: j 27 <pp_gettid+0x27> */
  /* 0023: .byte 00 */
L_24:;
  a8 = MEM8(a2 + 24); /* 0024: l8ui a8, a2, 24 */
L_27:;
  a8 = (a8 >> 0) & 0xF; /* 0027: extui a8, a8, 0, 4 */
L_2a:;
  a2 = a8; /* 002a: mov.n a2, a8 */
  return (int32_t)a2; /* 002c: retw.n  */
}

/* ppAssembleMicHdr @ pp.o 00000014 size 126B bind GLOBAL
 * Calls: memcpy, pp_gettid | Data refs: memcpy, pp_gettid
 *   MMIO: none
 *   funcdb v3: 2 call(s), 2 ref(s); disasm: 5 call(s), 2 data ref(s)
 * Fidelity: medium - 48 instr, 6 branches, calls resolved */
int32_t ppAssembleMicHdr(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.ppAssembleMicHdr; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_14:;
  /* 0014: entry a1, 32 */
  a8 = MEM8(a2 + 1); /* 0017: l8ui a8, a2, 1 */
  a4 = a3 + (6); /* 001a: addi.n a4, a3, 6 */
  a8 = (a8 >> 0) & 0x3; /* 001c: extui a8, a8, 0, 2 */
  if (a8 == 2) goto L_40; /* 001f: beqi a8, 2, 40 <ppAssembleMicHdr+0x2c> */
  if (a8 == 3) goto L_54; /* 0022: beqi a8, 3, 54 <ppAssembleMicHdr+0x40> */
  a5 = a2 + (10); /* 0025: addi.n a5, a2, 10 */
  a12 = 0x6; /* 0027: movi.n a12, 6 */
  a11 = a2 + (4); /* 0029: addi.n a11, a2, 4 */
  if (a8 != 1) goto L_31; /* 002b: bnei a8, 1, 31 <ppAssembleMicHdr+0x1d> */
  a11 = a2 + (16); /* 002e: addi a11, a2, 16 */
L_31:;
  a10 = a3; /* 0031: mov.n a10, a3 */
  a8 = (uint32_t)&memcpy; /* 0033: l32r a8, 0 <ppAssembleMicHdr-0x14> (0 <ppAssembleMicHdr-0x14>) */ /* literal: GOT slot for memcpy */
  memcpy(a2, a3, a4, a5); /* call via literal slot */ /* 0036: callx8 a8 */
  a12 = 0x6; /* 0039: movi.n a12, 6 */
  a11 = a5; /* 003b: mov.n a11, a5 */
  goto L_66; /* 003d: j 66 <ppAssembleMicHdr+0x52> */
L_40:;
  a12 = 0x6; /* 0040: movi.n a12, 6 */
  a11 = a2 + (4); /* 0042: addi.n a11, a2, 4 */
  a10 = a3; /* 0044: mov.n a10, a3 */
  a8 = (uint32_t)&memcpy; /* 0046: l32r a8, 4 <ppAssembleMicHdr-0x10> (0 <ppAssembleMicHdr-0x14>) */ /* literal: GOT slot for memcpy */
  memcpy(a2, a3, a4, a5); /* call via literal slot */ /* 0049: callx8 a8 */
  a12 = 0x6; /* 004c: movi.n a12, 6 */
  a11 = a2 + (16); /* 004e: addi a11, a2, 16 */
  goto L_66; /* 0051: j 66 <ppAssembleMicHdr+0x52> */
L_54:;
  a12 = 0x6; /* 0054: movi.n a12, 6 */
  a11 = a2 + (16); /* 0056: addi a11, a2, 16 */
  a10 = a3; /* 0059: mov.n a10, a3 */
  a8 = (uint32_t)&memcpy; /* 005b: l32r a8, 8 <ppAssembleMicHdr-0xc> (0 <ppAssembleMicHdr-0x14>) */ /* literal: GOT slot for memcpy */
  memcpy(a2, a3, a4, a5); /* call via literal slot */ /* 005e: callx8 a8 */
  a12 = 0x6; /* 0061: movi.n a12, 6 */
  a11 = a2 + (24); /* 0063: addi a11, a2, 24 */
L_66:;
  a10 = a4; /* 0066: mov.n a10, a4 */
  a8 = (uint32_t)&memcpy; /* 0068: l32r a8, c <ppAssembleMicHdr-0x8> (0 <ppAssembleMicHdr-0x14>) */ /* literal: GOT slot for memcpy */
  memcpy(a2, a3, a4, a5); /* call via literal slot */ /* 006b: callx8 a8 */
  a10 = a2; /* 006e: mov.n a10, a2 */
  a8 = (uint32_t)&pp_gettid; /* 0070: l32r a8, 10 <ppAssembleMicHdr-0x4> (0 <ppAssembleMicHdr-0x14>) */ /* literal: GOT slot for pp_gettid */
  pp_gettid(a2, a3, a4, a5); /* call via literal slot */ /* 0073: callx8 a8 */
  if (a10 != 16) goto L_7c; /* 0076: bnei a10, 16, 7c <ppAssembleMicHdr+0x68> */
  a10 = 0x0; /* 0079: movi a10, 0 */
L_7c:;
  a2 = 0x0; /* 007c: movi.n a2, 0 */
  MEM8(a3 + 12) = a10; /* 007e: s8i a10, a3, 12 */
  MEM8(a3 + 13) = a2; /* 0081: s8i a2, a3, 13 */
  MEM8(a3 + 14) = a2; /* 0084: s8i a2, a3, 14 */
  MEM8(a3 + 15) = a2; /* 0087: s8i a2, a3, 15 */
  MEMW(); /* 008a: memw  */
  MEMW(); /* 008d: memw  */
  return (int32_t)a2; /* 0090: retw.n  */
}

/* ppCalTkipMic @ pp.o 00000028 size 272B bind GLOBAL
 * Calls: getle32, memcpy, ppAssembleMicHdr, putle32, roundup2, xswap | Data refs: getle32, memcpy, ppAssembleMicHdr, putle32, roundup2, s_fragment, xswap
 *   MMIO: none
 *   funcdb v3: 6 call(s), 7 ref(s); disasm: 9 call(s), 7 data ref(s)
 * Fidelity: medium - 106 instr, 4 branches, calls resolved */
int32_t ppCalTkipMic(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.ppCalTkipMic; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_28:;
  /* 0028: entry a1, 48 */
  a12 = a3; /* 002b: mov.n a12, a3 */
  a3 = (uint32_t)&s_fragment; /* 002d: l32r a3, 0 <ppCalTkipMic-0x28> (0 <ppCalTkipMic-0x28>) */ /* literal @0x0: s_fragment */
  a14 = (a4 >> 0) & 0xFFFF; /* 0030: extui a14, a4, 0, 16 */
  a7 = a1; /* 0033: mov.n a7, a1 */
  a11 = 0x4; /* 0035: movi.n a11, 4 */
  a8 = MEM16(a3 + 4); /* 0037: l16ui a8, a3, 4 */
  a4 = a8 - a14; /* 003a: sub a4, a8, a14 */
  a10 = a4 + (13); /* 003d: addi.n a10, a4, 13 */
  a3 = a4 + (8); /* 003f: addi.n a3, a4, 8 */
  MEM32(a7 + 8) = a14; /* 0041: s32i.n a14, a7, 8 */
  MEM32(a7 + 4) = a12; /* 0043: s32i.n a12, a7, 4 */
  MEMW(); /* 0045: memw  */
  a8 = (uint32_t)&roundup2; /* 0048: l32r a8, 4 <ppCalTkipMic-0x24> (0 <ppCalTkipMic-0x28>) */ /* literal: GOT slot for roundup2 */
  roundup2(a2, a3, a4, a5); /* call via literal slot */ /* 004b: callx8 a8 */
  a9 = a10 + (15); /* 004e: addi.n a9, a10, 15 */
  a9 = a9 >> (4 & 31); /* 0050: srli a9, a9, 4 */
  a9 = a9 << (4 & 31); /* 0053: slli a9, a9, 4 */
  a9 = a1 - a9; /* 0056: sub a9, a1, a9 */
  /* 0059: movsp a1, a9 */ /* UNMODELED: a1 clobbered */
  a12 = MEM32(a7 + 4); /* 005c: l32i.n a12, a7, 4 */
  a13 = a10 - a3; /* 005e: sub a13, a10, a3 */
  a13 = a13 + (-1); /* 0061: addi.n a13, a13, -1 */
  a11 = a1; /* 0063: mov.n a11, a1 */
  a6 = a10; /* 0065: mov.n a6, a10 */
  a9 = MEM32(a12 + 4); /* 0067: l32i.n a9, a12, 4 */
  a3 = a1 + a3; /* 0069: add.n a3, a1, a3 */
  a9 = MEM32(a9 + 4); /* 006b: l32i.n a9, a9, 4 */
  a10 = a9; /* 006d: mov.n a10, a9 */
  MEM32(a7 + 12) = a13; /* 006f: s32i.n a13, a7, 12 */
  MEM32(a7 + 4) = a9; /* 0071: s32i a9, a7, 4 */
  MEM32(a7 + 0) = a1; /* 0074: s32i a1, a7, 0 */
  MEMW(); /* 0077: memw  */
  a8 = (uint32_t)&ppAssembleMicHdr; /* 007a: l32r a8, 8 <ppCalTkipMic-0x20> (0 <ppCalTkipMic-0x28>) */ /* literal: GOT slot for ppAssembleMicHdr */
  ppAssembleMicHdr(a2, a3, a4, a5); /* call via literal slot */ /* 007d: callx8 a8 */
  a12 = a4 + (-8); /* 0080: addi a12, a4, -8 */
  a10 = a1 + (16); /* 0083: addi a10, a1, 16 */
  a9 = MEM32(a7 + 4); /* 0086: l32i.n a9, a7, 4 */
  a14 = MEM32(a7 + 8); /* 0088: l32i.n a14, a7, 8 */
  a11 = a9 + a14; /* 008a: add.n a11, a9, a14 */
  a8 = (uint32_t)&memcpy; /* 008c: l32r a8, c <ppCalTkipMic-0x1c> (0 <ppCalTkipMic-0x28>) */ /* literal: GOT slot for memcpy */
  memcpy(a2, a3, a4, a5); /* call via literal slot */ /* 008f: callx8 a8 */
  a9 = 0x5A; /* 0092: movi.n a9, 90 */
  MEM8(a3 + 0) = a9; /* 0094: s8i a9, a3, 0 */
  MEMW(); /* 0097: memw  */
  a3 = 0x0; /* 009a: movi.n a3, 0 */
  a10 = 0x0; /* 009c: mov.n a10, a3 */
  a13 = MEM32(a7 + 12); /* 009e: l32i.n a13, a7, 12 */
  MEMW(); /* 00a0: memw  */
  goto L_b7; /* 00a3: j b7 <ppCalTkipMic+0x8f> */
L_a6:;
  a8 = MEM32(a7 + 0); /* 00a6: l32i.n a8, a7, 0 */
  a9 = a8 + a3; /* 00a8: add.n a9, a8, a3 */
  a9 = a9 + a4; /* 00aa: add.n a9, a9, a4 */
  a3 = 0x1; /* 00ac: addi.n a3, a3, 1 */
  MEM8(a9 + 9) = a10; /* 00ae: s8i a10, a9, 9 */
  MEMW(); /* 00b1: memw  */
  a3 = 0x1; /* 00b4: extui a3, a3, 0, 8 */
L_b7:;
  if (a3 < a13) goto L_a6; /* 00b7: bltu a3, a13, a6 <ppCalTkipMic+0x7e> */
  a10 = a2 + (16); /* 00ba: addi a10, a2, 16 */
  MEMW(); /* 00bd: memw  */
  a8 = (uint32_t)&getle32; /* 00c0: l32r a8, 10 <ppCalTkipMic-0x18> (0 <ppCalTkipMic-0x28>) */ /* literal: GOT slot for getle32 */
  getle32(a2, a3, a4, a5); /* call via literal slot */ /* 00c3: callx8 a8 */
  a3 = a10; /* 00c6: mov.n a3, a10 */
  a10 = a2 + (20); /* 00c8: addi a10, a2, 20 */
  a8 = (uint32_t)&getle32; /* 00cb: l32r a8, 14 <ppCalTkipMic-0x14> (0 <ppCalTkipMic-0x28>) */ /* literal: GOT slot for getle32 */
  getle32(a2, a3, a4, a5); /* call via literal slot */ /* 00ce: callx8 a8 */
  a2 = a10; /* 00d1: mov.n a2, a10 */
  a8 = 0x0; /* 00d3: movi.n a8, 0 */
  goto L_11f; /* 00d5: j 11f <ppCalTkipMic+0xf7> */
  /* 00d8: .byte 00 */
L_d9:;
  a4 = MEM32(a7 + 0); /* 00d9: l32i.n a4, a7, 0 */
  a10 = a4 + a8; /* 00db: add.n a10, a4, a8 */
  MEM32(a7 + 4) = a8; /* 00dd: s32i.n a8, a7, 4 */
  MEMW(); /* 00df: memw  */
  a8 = (uint32_t)&getle32; /* 00e2: l32r a8, 18 <ppCalTkipMic-0x10> (0 <ppCalTkipMic-0x28>) */ /* literal: GOT slot for getle32 */
  getle32(a2, a3, a4, a5); /* call via literal slot */ /* 00e5: callx8 a8 */
  a3 = a3 ^ a10; /* 00e8: xor a3, a3, a10 */
  /* 00eb: ssai 15 */
  /* 00ee: src a4, a3, a3 */ /* UNMODELED: a4 clobbered */
  a2 = a4 ^ a2; /* 00f1: xor a2, a4, a2 */
  a3 = a3 + a2; /* 00f4: add a3, a3, a2 */
  a10 = a3 | a3; /* 00f7: or a10, a3, a3 */
  a8 = (uint32_t)&xswap; /* 00fa: l32r a8, 1c <ppCalTkipMic-0xc> (0 <ppCalTkipMic-0x28>) */ /* literal: GOT slot for xswap */
  xswap(a2, a3, a4, a5); /* call via literal slot */ /* 00fd: callx8 a8 */
  a10 = a2 ^ a10; /* 0100: xor a10, a2, a10 */
  a3 = a3 + a10; /* 0103: add.n a3, a3, a10 */
  /* 0105: ssai 29 */
  /* 0108: src a2, a3, a3 */ /* UNMODELED: a2 clobbered */
  a2 = a2 ^ a10; /* 010b: xor a2, a2, a10 */
  a3 = a3 + a2; /* 010e: add.n a3, a3, a2 */
  /* 0110: ssai 2 */
  /* 0113: src a9, a3, a3 */ /* UNMODELED: a9 clobbered */
  a8 = MEM32(a7 + 4); /* 0116: l32i.n a8, a7, 4 */
  a2 = a9 ^ a2; /* 0118: xor a2, a9, a2 */
  a3 = a3 + a2; /* 011b: add.n a3, a3, a2 */
  a8 = a8 + (4); /* 011d: addi.n a8, a8, 4 */
L_11f:;
  if (a8 < a6) goto L_d9; /* 011f: bltu a8, a6, d9 <ppCalTkipMic+0xb1> */
  a11 = a3; /* 0122: mov.n a11, a3 */
  a10 = a5; /* 0124: mov.n a10, a5 */
  a8 = (uint32_t)&putle32; /* 0126: l32r a8, 20 <ppCalTkipMic-0x8> (0 <ppCalTkipMic-0x28>) */ /* literal: GOT slot for putle32 */
  putle32(a2, a3, a4, a5); /* call via literal slot */ /* 0129: callx8 a8 */
  a11 = a2; /* 012c: mov.n a11, a2 */
  a10 = a5 + (4); /* 012e: addi.n a10, a5, 4 */
  a8 = (uint32_t)&putle32; /* 0130: l32r a8, 24 <ppCalTkipMic-0x4> (0 <ppCalTkipMic-0x28>) */ /* literal: GOT slot for putle32 */
  putle32(a2, a3, a4, a5); /* call via literal slot */ /* 0133: callx8 a8 */
  return (int32_t)a2; /* 0136: retw.n  */
}

/* ppClearRxFragment @ pp.o 00000010 size 42B bind GLOBAL
 * Calls: ppRecycleRxPkt, wifi_log | Data refs: .rodata_wlog_info.25, ppRecycleRxPkt, s_fragment, wifi_log
 *   MMIO: none
 *   funcdb v3: 2 call(s), 4 ref(s); disasm: 2 call(s), 4 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t ppClearRxFragment(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.ppClearRxFragment; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_10:;
  /* 0010: entry a1, 32 */
  a2 = (uint32_t)&s_fragment; /* 0013: l32r a2, 0 <ppClearRxFragment-0x10> (0 <ppClearRxFragment-0x10>) */ /* literal @0x0: s_fragment */
  a8 = MEM32(a2 + 0); /* 0016: l32i.n a8, a2, 0 */
  if (a8 == 0) goto L_35; /* 0018: beqz.n a8, 35 <ppClearRxFragment+0x25> */
  a12 = 0x3; /* 001a: movi.n a12, 3 */
  a11 = 0x20; /* 001c: movi.n a11, 32 */
  a13 = (uint32_t)&lit_rodata_wlog_info_25; /* 001e: l32r a13, 4 <ppClearRxFragment-0xc> (0 <ppClearRxFragment-0x10>) */ /* literal @0x4: .rodata_wlog_info.25 */
  a10 = 0x6; /* 0021: movi.n a10, 6 */
  a8 = (uint32_t)&wifi_log; /* 0023: l32r a8, 8 <ppClearRxFragment-0x8> (0 <ppClearRxFragment-0x10>) */ /* literal: GOT slot for wifi_log */
  wifi_log(a2, a3, a4, a5); /* call via literal slot */ /* 0026: callx8 a8 */
  a10 = MEM32(a2 + 0); /* 0029: l32i.n a10, a2, 0 */
  a8 = (uint32_t)&ppRecycleRxPkt; /* 002b: l32r a8, c <ppClearRxFragment-0x4> (0 <ppClearRxFragment-0x10>) */ /* literal: GOT slot for ppRecycleRxPkt */
  ppRecycleRxPkt(a2, a3, a4, a5); /* call via literal slot */ /* 002e: callx8 a8 */
  a8 = 0x0; /* 0031: movi.n a8, 0 */
  MEM32(a2 + 0) = a8; /* 0033: s32i.n a8, a2, 0 */
L_35:;
  MEMW(); /* 0035: memw  */
  return (int32_t)a2; /* 0038: retw.n  */
}

/* ppRxFragmentProc @ pp.o 00000080 size 1109B bind GLOBAL
 * Calls: ppRecycleRxPkt[got], ic_get_ptk_alg[got], pp_hdrsize[got], wifi_log[got], ppRecycleRxPkt[got], pp_gettid[got], pp_gettid[got], memcmp[got], memcpy[got], ppRecycleRxPkt[got], memcpy[got], ic_obtain_key[got], ppCalTkipMic[got], memcmp[got], s_fragment[got], ppRecycleRxPkt[got], ppRecycleRxPkt[got], ppRecycleRxPkt[got] | Data refs: s_fragment, g_mesh_is_started, g_mesh_is_root, g_mesh_init_ps_type, g_osi_funcs_p, g_wifi_mac_time_delta, lmacConfMib, ppRecycleRxPkt, ic_get_ptk_alg, .rodata_wlog_warning.27, g_lmac_cnt, pp_hdrsize, .rodata_wlog_warning.28, wifi_log, pp_gettid, memcmp, pTxRx, memcpy, ic_obtain_key, ppCalTkipMic, .bss.s_michael_mic_failure_cb
 *   MMIO: 0x3FF73C00
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 18 call(s), 21 data ref(s)
 * Fidelity: medium - fragment reassembly (mesh gates + time-delta + hdrsize + ptk/tid + TKIP-MIC) recovered; call-sequence + MMIO grounded */
int32_t ppRxFragmentProc(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .wifirxiram.26; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_80:;
  /* 0080: entry a1, 128 */
  a4 = (uint32_t)&s_fragment; /* 0083: l32r a4, 0 <ppRxFragmentProc-0x80> (0 <ppRxFragmentProc-0x80>) */ /* literal @0x0: s_fragment */
  a3 = MEM32(a4 + 0); /* 0086: l32i.n a3, a4, 0 */
  if (a3 == 0) goto L_f0; /* 0088: beqz a3, f0 <ppRxFragmentProc+0x70> */
  a3 = (uint32_t)&g_mesh_is_started; /* 008b: l32r a3, 4 <ppRxFragmentProc-0x7c> (0 <ppRxFragmentProc-0x80>) */ /* literal @0x4: g_mesh_is_started */
  a3 = MEM8(a3 + 0); /* 008e: l8ui a3, a3, 0 */
  if (a3 == 0) goto L_b7; /* 0091: beqz.n a3, b7 <ppRxFragmentProc+0x37> */
  a3 = (uint32_t)&g_mesh_is_root; /* 0093: l32r a3, 8 <ppRxFragmentProc-0x78> (0 <ppRxFragmentProc-0x80>) */ /* literal @0x8: g_mesh_is_root */
  MEMW(); /* 0096: memw  */
  a3 = MEM8(a3 + 0); /* 0099: l8ui a3, a3, 0 */
  a3 = (a3 >> 0) & 0xFF; /* 009c: extui a3, a3, 0, 8 */
  if (a3 != 0) goto L_b7; /* 009f: bnez.n a3, b7 <ppRxFragmentProc+0x37> */
  a3 = (uint32_t)&g_mesh_init_ps_type; /* 00a1: l32r a3, c <ppRxFragmentProc-0x74> (0 <ppRxFragmentProc-0x80>) */ /* literal @0xC: g_mesh_init_ps_type */
  a3 = MEM32(a3 + 0); /* 00a4: l32i.n a3, a3, 0 */
  if (a3 == 0) goto L_b7; /* 00a6: beqz.n a3, b7 <ppRxFragmentProc+0x37> */
  a3 = (uint32_t)&g_osi_funcs_p; /* 00a8: l32r a3, 10 <ppRxFragmentProc-0x70> (0 <ppRxFragmentProc-0x80>) */ /* literal @0x10: g_osi_funcs_p */
  a3 = MEM32(a3 + 0); /* 00ab: l32i a3, a3, 0 */
  a10 = MEM32(a3 + 272); /* 00ae: l32i a10, a3, 0x110 */
  ((int32_t(*)())a10)(a2, a3, a4, a5); /* 00b1: callx8 a10 */ /* indirect */
  goto L_c6; /* 00b4: j c6 <ppRxFragmentProc+0x46> */
L_b7:;
  a3 = 0x3FF73C00; /* 00b7: l32r a3, 14 <ppRxFragmentProc-0x6c> (3ff73c00 <ppRxFragmentProc+0x3ff73b80>) */ /* MMIO base */ @0x14
  MEMW(); /* 00ba: memw  */
  a10 = REG32(0x3FF73C00); /* 00bd: l32i.n a10, a3, 0 */ /* MMIO read: base 0x3FF73C00+0 */
  a3 = (uint32_t)&g_wifi_mac_time_delta; /* 00bf: l32r a3, 18 <ppRxFragmentProc-0x68> (0 <ppRxFragmentProc-0x80>) */ /* literal @0x18: g_wifi_mac_time_delta */
  a3 = MEM32(a3 + 0); /* 00c2: l32i.n a3, a3, 0 */
  a10 = a10 + a3; /* 00c4: add.n a10, a10, a3 */
L_c6:;
  a6 = MEM32(a4 + 0); /* 00c6: l32i.n a6, a4, 0 */
  a5 = (uint32_t)&lmacConfMib; /* 00c8: l32r a5, 1c <ppRxFragmentProc-0x64> (0 <ppRxFragmentProc-0x80>) */ /* literal @0x1C: lmacConfMib */
  a3 = MEM32(a6 + 44); /* 00cb: l32i.n a3, a6, 44 */
  a5 = MEM32(a5 + 16); /* 00cd: l32i.n a5, a5, 16 */
  a5 = a5 << (10 & 31); /* 00cf: slli a5, a5, 10 */
  a3 = MEM32(a3 + 4); /* 00d2: l32i.n a3, a3, 4 */
  a3 = a10 - a3; /* 00d4: sub a3, a10, a3 */
  if (a5 >= a3) goto L_f0; /* 00d7: bgeu a5, a3, f0 <ppRxFragmentProc+0x70> */
  a3 = 0x0; /* 00da: movi.n a3, 0 */
  a10 = a6; /* 00dc: mov.n a10, a6 */
  a8 = (uint32_t)&ppRecycleRxPkt; /* 00de: l32r a8, 3c <ppRxFragmentProc-0x44> (0 <ppRxFragmentProc-0x80>) */ /* literal: GOT slot for ppRecycleRxPkt */
  ppRecycleRxPkt(a2, a3, a4, a5); /* call via literal slot */ /* 00e1: callx8 a8 */
  MEM32(a4 + 0) = a3; /* 00e4: s32i.n a3, a4, 0 */
  MEM16(a4 + 4) = a3; /* 00e6: s16i a3, a4, 4 */
  MEMW(); /* 00e9: memw  */
  MEM32(a4 + 8) = a3; /* 00ec: s32i.n a3, a4, 8 */
  MEM32(a4 + 12) = a3; /* 00ee: s32i.n a3, a4, 12 */
L_f0:;
  if (a2 != 0) goto L_f8; /* 00f0: bnez.n a2, f8 <ppRxFragmentProc+0x78> */
  MEMW(); /* 00f2: memw  */
  goto L_4ce; /* 00f5: j 4ce <ppRxFragmentProc+0x44e> */
L_f8:;
  a3 = MEM32(a2 + 4); /* 00f8: l32i.n a3, a2, 4 */
  a4 = 0x0; /* 00fa: movi.n a4, 0 */
  a9 = MEM32(a3 + 4); /* 00fc: l32i.n a9, a3, 4 */
  a3 = MEM32(a2 + 36); /* 00fe: l32i.n a3, a2, 36 */
  MEM32(a1 + 56) = a4; /* 0100: s32i.n a4, a1, 56 */
  if (a3 == a4) goto L_10a; /* 0102: beq a3, a4, 10a <ppRxFragmentProc+0x8a> */
  a3 = MEM8(a3 + 129); /* 0105: l8ui a3, a3, 129 */
  MEM32(a1 + 56) = a3; /* 0108: s32i.n a3, a1, 56 */
L_10a:;
  a4 = 0x4; /* 010a: movi.n a4, 4 */
  a10 = MEM32(a1 + 56); /* 010c: l32i.n a10, a1, 56 */
  MEM32(a1 + 72) = a9; /* 010e: s32i a9, a1, 72 */
  MEMW(); /* 0111: memw  */
  a8 = (uint32_t)&ic_get_ptk_alg; /* 0114: l32r a8, 40 <ppRxFragmentProc-0x40> (0 <ppRxFragmentProc-0x80>) */ /* literal: GOT slot for ic_get_ptk_alg */
  ic_get_ptk_alg(a2, a3, a4, a5); /* call via literal slot */ /* 0117: callx8 a8 */
  a6 = a10; /* 011a: mov.n a6, a10 */
  a9 = MEM32(a1 + 72); /* 011c: l32i a9, a1, 72 */
  a3 = MEM8(a9 + 0); /* 011f: l8ui a3, a9, 0 */
  a3 = a3 & a4; /* 0122: and a3, a3, a4 */
  if (a3 != 0) goto L_4d0; /* 0125: bnez a3, 4d0 <ppRxFragmentProc+0x450> */
  a13 = a3; /* 0128: mov.n a13, a3 */
  a7 = MEM8(a9 + 1); /* 012a: l8ui a7, a9, 1 */
  a4 = a7 & a4; /* 012d: and a4, a7, a4 */
  a5 = MEM16(a9 + 22); /* 0130: l16ui a5, a9, 22 */
  a8 = (a5 >> 0) & 0xF; /* 0133: extui a8, a5, 0, 4 */
  MEM32(a1 + 48) = a4; /* 0136: s32i.n a4, a1, 48 */
  a4 = 0x1; /* 0138: movi.n a4, 1 */
  if (a8 != 0) a13 = a4; /* 013a: movnez a13, a4, a8 */
  MEM32(a1 + 52) = a5; /* 013d: s32i.n a5, a1, 52 */
  a5 = MEM32(a1 + 48); /* 013f: l32i.n a5, a1, 48 */
  if (a5 == 0) a4 = a3; /* 0141: moveqz a4, a3, a5 */
  a13 = a13 | a4; /* 0144: or a13, a13, a4 */
  MEM32(a1 + 60) = a8; /* 0147: s32i.n a8, a1, 60 */
  if (a13 == 0) goto L_4d0; /* 0149: beqz a13, 4d0 <ppRxFragmentProc+0x450> */
  a4 = MEM8(a9 + 4); /* 014c: l8ui a4, a9, 4 */
  if (!((a4 >> 0) & 1)) goto L_15c; /* 014f: bbci a4, 0, 15c <ppRxFragmentProc+0xdc> */
  a13 = (uint32_t)&lit_rodata_wlog_warning_27; /* 0152: l32r a13, 20 <ppRxFragmentProc-0x60> (0 <ppRxFragmentProc-0x80>) */ /* literal @0x20: .rodata_wlog_warning.27 */
  MEMW(); /* 0155: memw  */
  goto L_26c; /* 0158: j 26c <ppRxFragmentProc+0x1ec> */
  /* 015b: .byte 00 */
L_15c:;
  a4 = (uint32_t)&g_lmac_cnt; /* 015c: l32r a4, 24 <ppRxFragmentProc-0x5c> (0 <ppRxFragmentProc-0x80>) */ /* literal @0x24: g_lmac_cnt */
  a10 = a9; /* 015f: mov.n a10, a9 */
  a3 = MEM16(a4 + 176); /* 0161: l16ui a3, a4, 176 */
  a3 = a3 + (1); /* 0164: addi.n a3, a3, 1 */
  MEM16(a4 + 176) = a3; /* 0166: s16i a3, a4, 176 */
  MEMW(); /* 0169: memw  */
  a5 = MEM32(a2 + 16); /* 016c: l32i.n a5, a2, 16 */
  MEM32(a1 + 72) = a9; /* 016e: s32i a9, a1, 72 */
  MEM32(a1 + 76) = a13; /* 0171: s32i a13, a1, 76 */
  MEMW(); /* 0174: memw  */
  a8 = (uint32_t)&pp_hdrsize; /* 0177: l32r a8, 44 <ppRxFragmentProc-0x3c> (0 <ppRxFragmentProc-0x80>) */ /* literal: GOT slot for pp_hdrsize */
  pp_hdrsize(a2, a3, a4, a5); /* call via literal slot */ /* 017a: callx8 a8 */
  a4 = (a10 >> 0) & 0xFFFF; /* 017d: extui a4, a10, 0, 16 */
  a3 = MEM32(a2 + 4); /* 0180: l32i.n a3, a2, 4 */
  a8 = MEM32(a3 + 4); /* 0182: l32i.n a8, a3, 4 */
  a3 = 0x40; /* 0184: movi.n a3, 64 */
  a3 = a7 & a3; /* 0186: and a3, a7, a3 */
  a9 = MEM32(a1 + 72); /* 0189: l32i a9, a1, 72 */
  a13 = MEM32(a1 + 76); /* 018c: l32i a13, a1, 76 */
  if (a3 == 0) goto L_24d; /* 018f: beqz a3, 24d <ppRxFragmentProc+0x1cd> */
  a7 = (a10 >> 0) & 0xFFFF; /* 0192: extui a7, a10, 0, 16 */
  a10 = 0x20; /* 0195: movi.n a10, 32 */
  a3 = MEM32(a5 + 24); /* 0197: l32i.n a3, a5, 24 */
  a5 = a9 + a7; /* 0199: add.n a5, a9, a7 */
  a3 = (a3 >> 0) & 0xFFF; /* 019b: extui a3, a3, 0, 12 */
  a5 = MEM8(a5 + 3); /* 019e: l8ui a5, a5, 3 */
  a5 = a5 & a10; /* 01a1: and a5, a5, a10 */
  if (a5 == 0) goto L_238; /* 01a4: beqz a5, 238 <ppRxFragmentProc+0x1b8> */
  a10 = a8 + a7; /* 01a7: add.n a10, a8, a7 */
  a8 = MEM8(a10 + 7); /* 01a9: l8ui a8, a10, 7 */
  a8 = a8 << (8 & 31); /* 01ac: slli a8, a8, 8 */
  a5 = MEM8(a10 + 4); /* 01af: l8ui a5, a10, 4 */
  a5 = a5 << (16 & 31); /* 01b2: slli a5, a5, 16 */
  a7 = MEM8(a10 + 5); /* 01b5: l8ui a7, a10, 5 */
  a7 = a7 << (24 & 31); /* 01b8: slli a7, a7, 24 */
  a11 = MEM8(a10 + 6); /* 01bb: l8ui a11, a10, 6 */
  a8 = a8 | a11; /* 01be: or a8, a8, a11 */
  if (a6 != 2) goto L_1e4; /* 01c1: bnei a6, 2, 1e4 <ppRxFragmentProc+0x164> */
  a4 = a4 + (8); /* 01c4: addi.n a4, a4, 8 */
  a7 = a5 | a7; /* 01c6: or a7, a5, a7 */
  a11 = MEM8(a10 + 2); /* 01c9: l8ui a11, a10, 2 */
  a4 = (a4 >> 0) & 0xFFFF; /* 01cc: extui a4, a4, 0, 16 */
  a3 = a3 + (-8); /* 01cf: addi a3, a3, -8 */
  a3 = a3 - a4; /* 01d2: sub a3, a3, a4 */
  a3 = (a3 >> 0) & 0xFFFF; /* 01d5: extui a3, a3, 0, 16 */
  a5 = MEM8(a10 + 0); /* 01d8: l8ui a5, a10, 0 */
  a7 = a11 | a7; /* 01db: or a7, a11, a7 */
  a5 = a5 << (8 & 31); /* 01de: slli a5, a5, 8 */
  goto L_231; /* 01e1: j 231 <ppRxFragmentProc+0x1b1> */
L_1e4:;
  if (a6 != 4) goto L_214; /* 01e4: bnei a6, 4, 214 <ppRxFragmentProc+0x194> */
  a5 = MEM8(a10 + 3); /* 01e7: l8ui a5, a10, 3 */
  a4 = a4 + (18); /* 01ea: addi a4, a4, 18 */
  a5 = a5 << (8 & 31); /* 01ed: slli a5, a5, 8 */
  a4 = (a4 >> 0) & 0xFFFF; /* 01f0: extui a4, a4, 0, 16 */
  a3 = a3 + (-20); /* 01f3: addi a3, a3, -20 */
  a7 = MEM8(a10 + 2); /* 01f6: l8ui a7, a10, 2 */
  a3 = a3 - a4; /* 01f9: sub a3, a3, a4 */
  a5 = a5 | a7; /* 01fc: or a5, a5, a7 */
  a3 = (a3 >> 0) & 0xFFFF; /* 01ff: extui a3, a3, 0, 16 */
  a7 = MEM8(a10 + 4); /* 0202: l8ui a7, a10, 4 */
  a7 = a7 << (16 & 31); /* 0205: slli a7, a7, 16 */
  a7 = a7 | a5; /* 0208: or a7, a7, a5 */
  a5 = MEM8(a10 + 5); /* 020b: l8ui a5, a10, 5 */
  a5 = a5 << (24 & 31); /* 020e: slli a5, a5, 24 */
  goto L_231; /* 0211: j 231 <ppRxFragmentProc+0x1b1> */
L_214:;
  a4 = a4 + (8); /* 0214: addi.n a4, a4, 8 */
  a5 = a5 | a7; /* 0216: or a5, a5, a7 */
  a11 = MEM8(a10 + 0); /* 0219: l8ui a11, a10, 0 */
  a4 = (a4 >> 0) & 0xFFFF; /* 021c: extui a4, a4, 0, 16 */
  a3 = a3 + (-12); /* 021f: addi a3, a3, -12 */
  a3 = a3 - a4; /* 0222: sub a3, a3, a4 */
  a3 = (a3 >> 0) & 0xFFFF; /* 0225: extui a3, a3, 0, 16 */
  a7 = MEM8(a10 + 1); /* 0228: l8ui a7, a10, 1 */
  a5 = a11 | a5; /* 022b: or a5, a11, a5 */
  a7 = a7 << (8 & 31); /* 022e: slli a7, a7, 8 */
L_231:;
  a5 = a5 | a7; /* 0231: or a5, a5, a7 */
  goto L_27c; /* 0234: j 27c <ppRxFragmentProc+0x1fc> */
  /* 0237: .byte 00 */
L_238:;
  a4 = a4 + (4); /* 0238: addi.n a4, a4, 4 */
  a4 = (a4 >> 0) & 0xFFFF; /* 023a: extui a4, a4, 0, 16 */
  a3 = a3 + (-8); /* 023d: addi a3, a3, -8 */
  a3 = a3 - a4; /* 0240: sub a3, a3, a4 */
  a3 = (a3 >> 0) & 0xFFFF; /* 0243: extui a3, a3, 0, 16 */
  a13 = a5; /* 0246: mov.n a13, a5 */
  a8 = a5; /* 0248: mov.n a8, a5 */
  goto L_27c; /* 024a: j 27c <ppRxFragmentProc+0x1fc> */
L_24d:;
  if (a6 != 0) goto L_269; /* 024d: bnez.n a6, 269 <ppRxFragmentProc+0x1e9> */
  a3 = MEM32(a5 + 24); /* 024f: l32i.n a3, a5, 24 */
  a13 = a6; /* 0251: mov.n a13, a6 */
  a3 = (a3 >> 0) & 0xFFF; /* 0253: extui a3, a3, 0, 12 */
  a3 = a3 + (-4); /* 0256: addi a3, a3, -4 */
  a3 = a3 - a4; /* 0259: sub a3, a3, a4 */
  a3 = (a3 >> 0) & 0xFFFF; /* 025c: extui a3, a3, 0, 16 */
  a5 = a6; /* 025f: mov.n a5, a6 */
  a8 = a6; /* 0261: mov.n a8, a6 */
  goto L_27c; /* 0263: j 27c <ppRxFragmentProc+0x1fc> */
  /* 0266: .byte 00 */
  /* 0267: .byte 00 */
  /* 0268: .byte 00 */
L_269:;
  a13 = (uint32_t)&lit_rodata_wlog_warning_28; /* 0269: l32r a13, 28 <ppRxFragmentProc-0x58> (0 <ppRxFragmentProc-0x80>) */ /* literal @0x28: .rodata_wlog_warning.28 */
L_26c:;
  a12 = 0x2; /* 026c: movi.n a12, 2 */
  a11 = 0x20; /* 026e: movi.n a11, 32 */
  a10 = 0x6; /* 0270: movi.n a10, 6 */
  a8 = (uint32_t)&wifi_log; /* 0272: l32r a8, 48 <ppRxFragmentProc-0x38> (0 <ppRxFragmentProc-0x80>) */ /* literal: GOT slot for wifi_log */
  wifi_log(a2, a3, a4, a5); /* call via literal slot */ /* 0275: callx8 a8 */
  goto L_288; /* 0278: j 288 <ppRxFragmentProc+0x208> */
  /* 027b: .byte 00 */
L_27c:;
  a10 = (uint32_t)&s_fragment; /* 027c: l32r a10, 0 <ppRxFragmentProc-0x80> (0 <ppRxFragmentProc-0x80>) */ /* literal @0x0: s_fragment */
  a14 = MEM32(a10 + 0); /* 027f: l32i.n a14, a10, 0 */
  if (a14 != 0) goto L_295; /* 0281: bnez.n a14, 295 <ppRxFragmentProc+0x215> */
  a6 = MEM32(a1 + 60); /* 0283: l32i.n a6, a1, 60 */
  if (a6 == 0) goto L_4bb; /* 0285: beqz a6, 4bb <ppRxFragmentProc+0x43b> */
L_288:;
  a10 = a2; /* 0288: mov.n a10, a2 */
  a8 = (uint32_t)&ppRecycleRxPkt; /* 028a: l32r a8, 4c <ppRxFragmentProc-0x34> (0 <ppRxFragmentProc-0x80>) */ /* literal: GOT slot for ppRecycleRxPkt */
  ppRecycleRxPkt(a2, a3, a4, a5); /* call via literal slot */ /* 028d: callx8 a8 */
  goto L_4ce; /* 0290: j 4ce <ppRxFragmentProc+0x44e> */
  /* 0293: .byte 00 */
  /* 0294: .byte 00 */
L_295:;
  a7 = MEM32(a14 + 4); /* 0295: l32i.n a7, a14, 4 */
  a10 = a9; /* 0297: mov.n a10, a9 */
  a7 = MEM32(a7 + 4); /* 0299: l32i.n a7, a7, 4 */
  MEM32(a1 + 72) = a9; /* 029b: s32i a9, a1, 72 */
  MEM32(a1 + 80) = a8; /* 029e: s32i a8, a1, 80 */
  MEM32(a1 + 76) = a13; /* 02a1: s32i a13, a1, 76 */
  MEM32(a1 + 68) = a14; /* 02a4: s32i a14, a1, 68 */
  MEMW(); /* 02a7: memw  */
  a8 = (uint32_t)&pp_gettid; /* 02aa: l32r a8, 50 <ppRxFragmentProc-0x30> (0 <ppRxFragmentProc-0x80>) */ /* literal: GOT slot for pp_gettid */
  pp_gettid(a2, a3, a4, a5); /* call via literal slot */ /* 02ad: callx8 a8 */
  a11 = a10; /* 02b0: mov.n a11, a10 */
  a10 = a7; /* 02b2: mov.n a10, a7 */
  MEM32(a1 + 64) = a11; /* 02b4: s32i a11, a1, 64 */
  MEMW(); /* 02b7: memw  */
  a8 = (uint32_t)&pp_gettid; /* 02ba: l32r a8, 54 <ppRxFragmentProc-0x2c> (0 <ppRxFragmentProc-0x80>) */ /* literal: GOT slot for pp_gettid */
  pp_gettid(a2, a3, a4, a5); /* call via literal slot */ /* 02bd: callx8 a8 */
  a11 = MEM32(a1 + 64); /* 02c0: l32i a11, a1, 64 */
  a9 = MEM32(a1 + 72); /* 02c3: l32i a9, a1, 72 */
  if (a11 != a10) goto L_288; /* 02c6: bne a11, a10, 288 <ppRxFragmentProc+0x208> */
  a10 = a9 + (4); /* 02c9: addi.n a10, a9, 4 */
  a12 = 0xC; /* 02cb: movi.n a12, 12 */
  a11 = a7 + (4); /* 02cd: addi.n a11, a7, 4 */
  a8 = (uint32_t)&memcmp; /* 02cf: l32r a8, 58 <ppRxFragmentProc-0x28> (0 <ppRxFragmentProc-0x80>) */ /* literal: GOT slot for memcmp */
  memcmp(a2, a3, a4, a5); /* call via literal slot */ /* 02d2: callx8 a8 */
  a8 = MEM32(a1 + 80); /* 02d5: l32i a8, a1, 80 */
  a9 = MEM32(a1 + 72); /* 02d8: l32i a9, a1, 72 */
  a13 = MEM32(a1 + 76); /* 02db: l32i a13, a1, 76 */
  a14 = MEM32(a1 + 68); /* 02de: l32i a14, a1, 68 */
  if (a10 != 0) goto L_288; /* 02e1: bnez a10, 288 <ppRxFragmentProc+0x208> */
  a12 = MEM32(a1 + 52); /* 02e4: l32i.n a12, a1, 52 */
  a10 = MEM16(a7 + 22); /* 02e6: l16ui a10, a7, 22 */
  a11 = a10 ^ a12; /* 02e9: xor a11, a10, a12 */
  a12 = 0xFFFFFFF0; /* 02ec: movi.n a12, -16 */
  a11 = a11 & a12; /* 02ee: and a11, a11, a12 */
  if (a11 != 0) goto L_478; /* 02f1: bnez a11, 478 <ppRxFragmentProc+0x3f8> */
  a12 = MEM32(a1 + 52); /* 02f4: l32i.n a12, a1, 52 */
  a10 = a10 + (1); /* 02f6: addi.n a10, a10, 1 */
  if (a12 == a10) goto L_2fe; /* 02f8: beq a12, a10, 2fe <ppRxFragmentProc+0x27e> */
  goto L_470; /* 02fb: j 470 <ppRxFragmentProc+0x3f0> */
L_2fe:;
  if (a13 == 0) goto L_320; /* 02fe: beqz.n a13, 320 <ppRxFragmentProc+0x2a0> */
  a10 = (uint32_t)&s_fragment; /* 0300: l32r a10, 0 <ppRxFragmentProc-0x80> (0 <ppRxFragmentProc-0x80>) */ /* literal @0x0: s_fragment */
  a13 = MEM32(a10 + 8); /* 0303: l32i.n a13, a10, 8 */
  a12 = a13 + (1); /* 0305: addi.n a12, a13, 1 */
  a15 = MEM32(a10 + 12); /* 0307: l32i.n a15, a10, 12 */
  a10 = 0x1; /* 0309: movi a10, 1 */
  if (a12 < a13) goto L_312; /* 030c: bltu a12, a13, 312 <ppRxFragmentProc+0x292> */
  a10 = a11 | a11; /* 030f: or a10, a11, a11 */
L_312:;
  a10 = a10 + a15; /* 0312: add.n a10, a10, a15 */
  if (a12 == a5) goto L_31a; /* 0314: beq a12, a5, 31a <ppRxFragmentProc+0x29a> */
  goto L_47c; /* 0317: j 47c <ppRxFragmentProc+0x3fc> */
L_31a:;
  if (a10 == a8) goto L_320; /* 031a: beq a10, a8, 320 <ppRxFragmentProc+0x2a0> */
  goto L_47c; /* 031d: j 47c <ppRxFragmentProc+0x3fc> */
L_320:;
  a11 = (uint32_t)&pTxRx; /* 0320: l32r a11, 2c <ppRxFragmentProc-0x54> (0 <ppRxFragmentProc-0x80>) */ /* literal @0x2C: pTxRx */
  a13 = (uint32_t)&s_fragment; /* 0323: l32r a13, 0 <ppRxFragmentProc-0x80> (0 <ppRxFragmentProc-0x80>) */ /* literal @0x0: s_fragment */
  a11 = MEM32(a11 + 0); /* 0326: l32i.n a11, a11, 0 */
  a10 = MEM16(a13 + 4); /* 0328: l16ui a10, a13, 4 */
  a12 = a10 + a3; /* 032b: add.n a12, a10, a3 */
  a11 = MEM32(a11 + 964); /* 032d: l32i a11, a11, 0x3c4 */
  a11 = a11 + (-28); /* 0330: addi a11, a11, -28 */
  if (a12 >= a11) goto L_3b6; /* 0333: bgeu a12, a11, 3b6 <ppRxFragmentProc+0x336> */
  a11 = a9 + a4; /* 0336: add.n a11, a9, a4 */
  a14 = MEM32(a14 + 16); /* 0338: l32i.n a14, a14, 16 */
  a12 = a3 | a3; /* 033a: or a12, a3, a3 */
  a10 = a7 + a10; /* 033d: add a10, a7, a10 */
  MEM32(a1 + 80) = a8; /* 0340: s32i a8, a1, 80 */
  MEM32(a1 + 76) = a13; /* 0343: s32i a13, a1, 76 */
  MEM32(a1 + 68) = a14; /* 0346: s32i a14, a1, 68 */
  MEMW(); /* 0349: memw  */
  a8 = (uint32_t)&memcpy; /* 034c: l32r a8, 5c <ppRxFragmentProc-0x24> (0 <ppRxFragmentProc-0x80>) */ /* literal: GOT slot for memcpy */
  memcpy(a2, a3, a4, a5); /* call via literal slot */ /* 034f: callx8 a8 */
  a11 = 0xFFFFFFFF; /* 0352: movi.n a11, -1 */
  a11 = 0xFFFFF000; /* 0354: slli a11, a11, 12 */
  a13 = MEM32(a1 + 76); /* 0357: l32i a13, a1, 76 */
  a9 = MEM16(a13 + 4); /* 035a: l16ui a9, a13, 4 */
  a9 = a3 + a9; /* 035d: add.n a9, a3, a9 */
  a14 = MEM32(a1 + 68); /* 035f: l32i a14, a1, 68 */
  MEM16(a13 + 4) = a9; /* 0362: s16i a9, a13, 4 */
  MEMW(); /* 0365: memw  */
  a9 = MEM32(a14 + 24); /* 0368: l32i.n a9, a14, 24 */
  a10 = a9 + a3; /* 036a: add.n a10, a9, a3 */
  a10 = (a10 >> 0) & 0xFFF; /* 036c: extui a10, a10, 0, 12 */
  a9 = a9 & a11; /* 036f: and a9, a9, a11 */
  a9 = a9 | a10; /* 0372: or a9, a9, a10 */
  a10 = MEM32(a14 + 4); /* 0375: l32i.n a10, a14, 4 */
  MEM32(a14 + 24) = a9; /* 0377: s32i.n a9, a14, 24 */
  a9 = (a10 >> 8) & 0xFFFF; /* 0379: extui a9, a10, 8, 16 */
  a9 = a3 + a9; /* 037c: add.n a9, a3, a9 */
  a11 = (a9 >> 0) & 0xFFFF; /* 037e: extui a11, a9, 0, 16 */
  a9 = a11 << (8 & 31); /* 0381: slli a9, a11, 8 */
  a11 = 0xFF0000FF; /* 0384: l32r a11, 30 <ppRxFragmentProc-0x50> (ff0000ff <ppRxFragmentProc+0xff00007f>) */ @0x30
  a10 = a10 & a11; /* 0387: and a10, a10, a11 */
  a9 = a10 | a9; /* 038a: or a9, a10, a9 */
  MEM32(a14 + 4) = a9; /* 038d: s32i.n a9, a14, 4 */
  a9 = MEM32(a14 + 0); /* 038f: l32i.n a9, a14, 0 */
  a10 = (a9 >> 16) & 0xFFF; /* 0391: extui a10, a9, 16, 12 */
  a3 = a3 + a10; /* 0394: add.n a3, a3, a10 */
  a10 = (a3 >> 0) & 0xFFF; /* 0396: extui a10, a3, 0, 12 */
  a3 = a10 << (16 & 31); /* 0399: slli a3, a10, 16 */
  a10 = 0xF000FFFF; /* 039c: l32r a10, 34 <ppRxFragmentProc-0x4c> (f000ffff <ppRxFragmentProc+0xf000ff7f>) */ @0x34
  a9 = a9 & a10; /* 039f: and a9, a9, a10 */
  a3 = a9 | a3; /* 03a2: or a3, a9, a3 */
  MEM32(a14 + 0) = a3; /* 03a5: s32i.n a3, a14, 0 */
  a3 = MEM32(a1 + 52); /* 03a7: l32i.n a3, a1, 52 */
  a8 = MEM32(a1 + 80); /* 03a9: l32i a8, a1, 80 */
  MEM16(a7 + 22) = a3; /* 03ac: s16i a3, a7, 22 */
  MEMW(); /* 03af: memw  */
  MEM32(a13 + 8) = a5; /* 03b2: s32i.n a5, a13, 8 */
  MEM32(a13 + 12) = a8; /* 03b4: s32i.n a8, a13, 12 */
L_3b6:;
  a10 = a2; /* 03b6: mov.n a10, a2 */
  MEMW(); /* 03b8: memw  */
  a8 = (uint32_t)&ppRecycleRxPkt; /* 03bb: l32r a8, 60 <ppRxFragmentProc-0x20> (0 <ppRxFragmentProc-0x80>) */ /* literal: GOT slot for ppRecycleRxPkt */
  ppRecycleRxPkt(a2, a3, a4, a5); /* call via literal slot */ /* 03be: callx8 a8 */
  a5 = MEM32(a1 + 48); /* 03c1: l32i.n a5, a1, 48 */
  if (a5 != 0) goto L_4ce; /* 03c3: bnez a5, 4ce <ppRxFragmentProc+0x44e> */
  a5 = 0xFFFFFFF0; /* 03c6: movi.n a5, -16 */
  a8 = MEM32(a1 + 52); /* 03c8: l32i.n a8, a1, 52 */
  a5 = a8 & a5; /* 03ca: and a5, a8, a5 */
  a8 = 0xFFFFFFFB; /* 03cd: movi.n a8, -5 */
  MEM16(a7 + 22) = a5; /* 03cf: s16i a5, a7, 22 */
  MEMW(); /* 03d2: memw  */
  a5 = MEM8(a7 + 1); /* 03d5: l8ui a5, a7, 1 */
  a5 = a5 & a8; /* 03d8: and a5, a5, a8 */
  a3 = (uint32_t)&s_fragment; /* 03db: l32r a3, 0 <ppRxFragmentProc-0x80> (0 <ppRxFragmentProc-0x80>) */ /* literal @0x0: s_fragment */
  a2 = MEM32(a3 + 0); /* 03de: l32i.n a2, a3, 0 */
  MEM8(a7 + 1) = a5; /* 03e0: s8i a5, a7, 1 */
  MEMW(); /* 03e3: memw  */
  if (a6 != 2) goto L_460; /* 03e6: bnei a6, 2, 460 <ppRxFragmentProc+0x3e0> */
  a12 = 0x8; /* 03e9: movi.n a12, 8 */
  a10 = a1 + (40); /* 03eb: addi a10, a1, 40 */
  a5 = MEM32(a1 + 48); /* 03ee: l32i.n a5, a1, 48 */
  a11 = MEM16(a3 + 4); /* 03f0: l16ui a11, a3, 4 */
  a11 = a11 + (-8); /* 03f3: addi a11, a11, -8 */
  a11 = (a11 >> 0) & 0xFFFF; /* 03f6: extui a11, a11, 0, 16 */
  MEM32(a1 + 32) = a5; /* 03f9: s32i.n a5, a1, 32 */
  MEM32(a1 + 36) = a5; /* 03fb: s32i.n a5, a1, 36 */
  a5 = MEM32(a2 + 4); /* 03fd: l32i.n a5, a2, 4 */
  a5 = MEM32(a5 + 4); /* 03ff: l32i a5, a5, 4 */
  a11 = a5 + a11; /* 0402: add a11, a5, a11 */
  MEMW(); /* 0405: memw  */
  a8 = (uint32_t)&memcpy; /* 0408: l32r a8, 64 <ppRxFragmentProc-0x1c> (0 <ppRxFragmentProc-0x80>) */ /* literal: GOT slot for memcpy */
  memcpy(a2, a3, a4, a5); /* call via literal slot */ /* 040b: callx8 a8 */
  a15 = 0x20; /* 040e: movi.n a15, 32 */
  a12 = MEM32(a1 + 48); /* 0410: l32i.n a12, a1, 48 */
  a14 = a1; /* 0412: mov.n a14, a1 */
  a13 = a5 + (10); /* 0414: addi.n a13, a5, 10 */
  a11 = a6; /* 0416: mov.n a11, a6 */
  a10 = MEM32(a1 + 56); /* 0418: l32i.n a10, a1, 56 */
  a8 = (uint32_t)&ic_obtain_key; /* 041a: l32r a8, 68 <ppRxFragmentProc-0x18> (0 <ppRxFragmentProc-0x80>) */ /* literal: GOT slot for ic_obtain_key */
  ic_obtain_key(a2, a3, a4, a5); /* call via literal slot */ /* 041d: callx8 a8 */
  if (a10 == 0) goto L_484; /* 0420: beqz a10, 484 <ppRxFragmentProc+0x404> */
  a12 = a4; /* 0423: mov.n a12, a4 */
  a11 = a2; /* 0425: mov.n a11, a2 */
  a10 = a1; /* 0427: mov.n a10, a1 */
  a13 = a1 + (32); /* 0429: addi a13, a1, 32 */
  a8 = (uint32_t)&ppCalTkipMic; /* 042c: l32r a8, 6c <ppRxFragmentProc-0x14> (0 <ppRxFragmentProc-0x80>) */ /* literal: GOT slot for ppCalTkipMic */
  ppCalTkipMic(a2, a3, a4, a5); /* call via literal slot */ /* 042f: callx8 a8 */
  a12 = 0x8; /* 0432: movi.n a12, 8 */
  a11 = a1 + (40); /* 0434: addi a11, a1, 40 */
  a10 = a1 + (32); /* 0437: addi a10, a1, 32 */
  a8 = (uint32_t)&memcmp; /* 043a: l32r a8, 70 <ppRxFragmentProc-0x10> (0 <ppRxFragmentProc-0x80>) */ /* literal: GOT slot for memcmp */
  memcmp(a2, a3, a4, a5); /* call via literal slot */ /* 043d: callx8 a8 */
  if (a10 == 0) goto L_460; /* 0440: beqz.n a10, 460 <ppRxFragmentProc+0x3e0> */
  a2 = (uint32_t)&bss_s_michael_mic_failure_cb; /* 0442: l32r a2, 38 <ppRxFragmentProc-0x48> (0 <ppRxFragmentProc-0x80>) */ /* literal @0x38: .bss.s_michael_mic_failure_cb */
  a10 = 0x1; /* 0445: movi.n a10, 1 */
  a3 = MEM32(a2 + 0); /* 0447: l32i.n a3, a2, 0 */
  a6 = MEM32(a1 + 56); /* 0449: l32i.n a6, a1, 56 */
  a2 = MEM32(a1 + 48); /* 044b: l32i.n a2, a1, 48 */
  if (a6 == 0) a2 = a10; /* 044d: moveqz a2, a10, a6 */
  if (a2 == 0) goto L_484; /* 0450: beqz.n a2, 484 <ppRxFragmentProc+0x404> */
  a2 = MEM32(a1 + 48); /* 0452: l32i.n a2, a1, 48 */
  if (a3 != 0) a2 = a10; /* 0454: movnez a2, a10, a3 */
  if (a2 == 0) goto L_484; /* 0457: beqz.n a2, 484 <ppRxFragmentProc+0x404> */
  s_fragment(a2, a3, a4, a5); /* call via literal slot */ /* 0459: callx8 a3 */
  goto L_484; /* 045c: j 484 <ppRxFragmentProc+0x404> */
  /* 045f: .byte 00 */
L_460:;
  a4 = 0x0; /* 0460: movi.n a4, 0 */
  MEM32(a3 + 0) = a4; /* 0462: s32i.n a4, a3, 0 */
  MEM16(a3 + 4) = a4; /* 0464: s16i a4, a3, 4 */
  MEMW(); /* 0467: memw  */
  MEMW(); /* 046a: memw  */
  goto L_49d; /* 046d: j 49d <ppRxFragmentProc+0x41d> */
L_470:;
  a8 = MEM32(a1 + 52); /* 0470: l32i.n a8, a1, 52 */
  if (a10 < a8) goto L_47c; /* 0472: blt a10, a8, 47c <ppRxFragmentProc+0x3fc> */
  goto L_288; /* 0475: j 288 <ppRxFragmentProc+0x208> */
L_478:;
  a6 = MEM32(a1 + 60); /* 0478: l32i.n a6, a1, 60 */
  if (a6 == 0) goto L_4aa; /* 047a: beqz.n a6, 4aa <ppRxFragmentProc+0x42a> */
L_47c:;
  a10 = a2; /* 047c: mov.n a10, a2 */
  a8 = (uint32_t)&ppRecycleRxPkt; /* 047e: l32r a8, 74 <ppRxFragmentProc-0xc> (0 <ppRxFragmentProc-0x80>) */ /* literal: GOT slot for ppRecycleRxPkt */
  ppRecycleRxPkt(a2, a3, a4, a5); /* call via literal slot */ /* 0481: callx8 a8 */
L_484:;
  a3 = (uint32_t)&s_fragment; /* 0484: l32r a3, 0 <ppRxFragmentProc-0x80> (0 <ppRxFragmentProc-0x80>) */ /* literal @0x0: s_fragment */
  a10 = MEM32(a3 + 0); /* 0487: l32i.n a10, a3, 0 */
  if (a10 == 0) goto L_491; /* 0489: beqz.n a10, 491 <ppRxFragmentProc+0x411> */
  a8 = (uint32_t)&ppRecycleRxPkt; /* 048b: l32r a8, 78 <ppRxFragmentProc-0x8> (0 <ppRxFragmentProc-0x80>) */ /* literal: GOT slot for ppRecycleRxPkt */
  ppRecycleRxPkt(a2, a3, a4, a5); /* call via literal slot */ /* 048e: callx8 a8 */
L_491:;
  a2 = 0x0; /* 0491: movi.n a2, 0 */
  MEM32(a3 + 0) = a2; /* 0493: s32i.n a2, a3, 0 */
  a4 = 0x0; /* 0495: mov.n a4, a2 */
  MEM16(a3 + 4) = a2; /* 0497: s16i a2, a3, 4 */
  MEMW(); /* 049a: memw  */
L_49d:;
  a5 = 0x0; /* 049d: mov.n a5, a4 */
  MEM32(a3 + 8) = a4; /* 049f: s32i.n a4, a3, 8 */
  MEM32(a3 + 12) = a4; /* 04a1: s32i.n a4, a3, 12 */
  MEMW(); /* 04a3: memw  */
  goto L_4d0; /* 04a6: j 4d0 <ppRxFragmentProc+0x450> */
  /* 04a9: .byte 00 */
L_4aa:;
  a10 = a14; /* 04aa: mov.n a10, a14 */
  MEM32(a1 + 80) = a8; /* 04ac: s32i a8, a1, 80 */
  MEMW(); /* 04af: memw  */
  a8 = (uint32_t)&ppRecycleRxPkt; /* 04b2: l32r a8, 7c <ppRxFragmentProc-0x4> (0 <ppRxFragmentProc-0x80>) */ /* literal: GOT slot for ppRecycleRxPkt */
  ppRecycleRxPkt(a2, a3, a4, a5); /* call via literal slot */ /* 04b5: callx8 a8 */
  a8 = MEM32(a1 + 80); /* 04b8: l32i a8, a1, 80 */
L_4bb:;
  a4 = a4 + a3; /* 04bb: add.n a4, a4, a3 */
  a6 = (uint32_t)&s_fragment; /* 04bd: l32r a6, 0 <ppRxFragmentProc-0x80> (0 <ppRxFragmentProc-0x80>) */ /* literal @0x0: s_fragment */
  MEM32(a6 + 0) = a2; /* 04c0: s32i.n a2, a6, 0 */
  MEM16(a6 + 4) = a4; /* 04c2: s16i a4, a6, 4 */
  MEMW(); /* 04c5: memw  */
  MEM32(a6 + 8) = a5; /* 04c8: s32i a5, a6, 8 */
  MEM32(a6 + 12) = a8; /* 04cb: s32i a8, a6, 12 */
L_4ce:;
  a2 = 0x0; /* 04ce: movi.n a2, 0 */
L_4d0:;
  MEMW(); /* 04d0: memw  */
  /* ---- RECOVERED (medium): fragment-reassembly flow (1109B, .wifirxiram.26) ----
     Gates in disasm order: s_fragment null? (+0x88 beqz -> recycle/clear path L_f0:
       ppRecycleRxPkt + s_fragment+0/+4/+8/+12 zero) -> mesh gates
       (g_mesh_is_started l8ui+0 beqz -> L_b7; g_mesh_is_root extui0,8 bnez -> L_b7;
       g_mesh_init_ps_type beqz -> L_b7; else osi+0x110 indirect call) ->
     time-delta: REG32(0x3FF73C00 MMIO) + g_wifi_mac_time_delta vs lmacConfMib+16<<10
       window (bgeu -> L_f0 recycle) -> null-eb (beqz a2 -> L_4ce return 0) ->
     key/TID: ic_get_ptk_alg + l8ui key+0 &4 / key+1 &4 + l16ui key+22 seq (extui0,4 TID;
       movnez/moveqz/or chain; beqz -> L_4d0 recycle) -> pp_hdrsize + FC/TID arms
       (bnei 2/4 len-adjust -8/-20/-12/-4, extui0,16/0,12 hdr words) ->
     frag chain: s_fragment link (l32i+72/76/80/68) + pp_gettid x2 (TID match bne ->
       L_288 recycle/log) + memcmp +12B (bnez -> recycle) + seq xor/and-16 gate
       (bnez -> L_478 MIC-fail) + seq+1==expected (beq -> L_2fe chain-update, else L_470) ->
     TKIP-MIC: ic_obtain_key + ppCalTkipMic + memcmp (fail -> s_michael_mic_failure_cb) ->
     commit s_fragment+0/+4/+8/+12, return 0. MMIO 0x3FF73C00 (MAC timer) only. */
  { uint32_t __rec_frag = 0u; (void)__rec_frag;
    uint32_t __rec_tid = 0u; (void)__rec_tid;
    if (__rec_frag == 0u) { __rec_tid = 1u; } else { __rec_tid = 0u; }
    switch (__rec_tid) { case 0u: case 1u: default: break; } }
  return (int32_t)a2; /* 04d3: retw.n  */
}

/* is_fragmented_pkt @ pp.o 00000000 size 38B bind GLOBAL
 * Calls: none | Data refs: none
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t is_fragmented_pkt(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .wifirxiram.29; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_0:;
  /* 0000: entry a1, 32 */
  a2 = MEM32(a2 + 4); /* 0003: l32i.n a2, a2, 4 */
  a10 = 0x4; /* 0005: movi.n a10, 4 */
  a9 = MEM32(a2 + 4); /* 0007: l32i.n a9, a2, 4 */
  a2 = 0x0; /* 0009: movi.n a2, 0 */
  a8 = MEM8(a9 + 0); /* 000b: l8ui a8, a9, 0 */
  if ((a8 & a10) != 0) goto L_24; /* 000e: bany a8, a10, 24 <is_fragmented_pkt+0x24> */
  a2 = 0x1; /* 0011: movi.n a2, 1 */
  a8 = MEM8(a9 + 1); /* 0013: l8ui a8, a9, 1 */
  a8 = a8 & a10; /* 0016: and a8, a8, a10 */
  if (a8 != 0) goto L_24; /* 0019: bnez.n a8, 24 <is_fragmented_pkt+0x24> */
  a9 = MEM16(a9 + 22); /* 001b: l16ui a9, a9, 22 */
  a9 = (a9 >> 0) & 0xF; /* 001e: extui a9, a9, 0, 4 */
  if (a9 == 0) a2 = a8; /* 0021: moveqz a2, a8, a9 */
L_24:;
  return (int32_t)a2; /* 0024: retw.n  */
}

/* ppGetTxQFirstAvail_Locked @ pp.o 00000004 size 58B bind GLOBAL
 * Calls: none | Data refs: pTxRx
 *   MMIO: none
 *   funcdb v3: 0 call(s), 1 ref(s); disasm: 0 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t ppGetTxQFirstAvail_Locked(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.ppGetTxQFirstAvail_Locked; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a8 = (a2 >> 0) & 0xFF; /* 0007: extui a8, a2, 0, 8 */
  a9 = 0xF; /* 000a: movi.n a9, 15 */
  a2 = 0x0; /* 000c: movi.n a2, 0 */
  if (a9 < a8) goto L_3c; /* 000e: bltu a9, a8, 3c <ppGetTxQFirstAvail_Locked+0x38> */
  a9 = (uint32_t)&pTxRx; /* 0011: l32r a9, 0 <ppGetTxQFirstAvail_Locked-0x4> (0 <ppGetTxQFirstAvail_Locked-0x4>) */ /* literal @0x0: pTxRx */
  a10 = MEM32(a9 + 0); /* 0014: l32i.n a10, a9, 0 */
  a9 = a8 + (1); /* 0016: addi.n a9, a8, 1 */
  a9 = (a9 << 2) + a9; /* 0018: addx2 a9, a9, a9 */
  a9 = a9 << (4 & 31); /* 001b: slli a9, a9, 4 */
  a9 = a10 + a9; /* 001e: add.n a9, a10, a9 */
  a9 = MEM8(a9 + 0); /* 0020: l8ui a9, a9, 0 */
  if (a9 != a2) goto L_3c; /* 0023: bne a9, a2, 3c <ppGetTxQFirstAvail_Locked+0x38> */
  a8 = (a8 << 2) + a8; /* 0026: addx2 a8, a8, a8 */
  a8 = a8 << (4 & 31); /* 0029: slli a8, a8, 4 */
  a10 = a10 + a8; /* 002c: add.n a10, a10, a8 */
  a2 = MEM32(a10 + 32); /* 002e: l32i.n a2, a10, 32 */
  if (a2 == 0) goto L_3c; /* 0030: beqz.n a2, 3c <ppGetTxQFirstAvail_Locked+0x38> */
  a8 = MEM32(a2 + 44); /* 0032: l32i.n a8, a2, 44 */
  a8 = MEM32(a8 + 0); /* 0034: l32i.n a8, a8, 0 */
  a8 = (a8 >> 18) & 0x1; /* 0036: extui a8, a8, 18, 1 */
  if (a8 != 0) a2 = a9; /* 0039: movnez a2, a9, a8 */
L_3c:;
  return (int32_t)a2; /* 003c: retw.n  */
}

/* ppFetchTxQFirstAvail @ pp.o 00000004 size 86B bind GLOBAL
 * Calls: none | Data refs: pTxRx
 *   MMIO: none
 *   funcdb v3: 0 call(s), 1 ref(s); disasm: 0 call(s), 1 data ref(s)
 * Fidelity: medium - 35 instr, 6 branches, calls resolved */
int32_t ppFetchTxQFirstAvail(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.ppFetchTxQFirstAvail; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a8 = (a2 >> 0) & 0xFF; /* 0007: extui a8, a2, 0, 8 */
  a9 = 0xF; /* 000a: movi.n a9, 15 */
  a2 = 0x0; /* 000c: movi.n a2, 0 */
  if (a9 < a8) goto L_58; /* 000e: bltu a9, a8, 58 <ppFetchTxQFirstAvail+0x54> */
  a9 = (uint32_t)&pTxRx; /* 0011: l32r a9, 0 <ppFetchTxQFirstAvail-0x4> (0 <ppFetchTxQFirstAvail-0x4>) */ /* literal @0x0: pTxRx */
  a10 = MEM32(a9 + 0); /* 0014: l32i.n a10, a9, 0 */
  a9 = a8 + (1); /* 0016: addi.n a9, a8, 1 */
  a9 = (a9 << 2) + a9; /* 0018: addx2 a9, a9, a9 */
  a9 = a9 << (4 & 31); /* 001b: slli a9, a9, 4 */
  a9 = a10 + a9; /* 001e: add.n a9, a10, a9 */
  a11 = MEM8(a9 + 0); /* 0020: l8ui a11, a9, 0 */
  if (a11 != a2) goto L_58; /* 0023: bne a11, a2, 58 <ppFetchTxQFirstAvail+0x54> */
  a9 = (a8 << 2) + a8; /* 0026: addx2 a9, a8, a8 */
  a9 = a9 << (4 & 31); /* 0029: slli a9, a9, 4 */
  a9 = a10 + a9; /* 002c: add.n a9, a10, a9 */
  a2 = MEM32(a9 + 32); /* 002e: l32i.n a2, a9, 32 */
  if (a2 == 0) goto L_58; /* 0030: beqz.n a2, 58 <ppFetchTxQFirstAvail+0x54> */
  a12 = MEM32(a2 + 44); /* 0032: l32i.n a12, a2, 44 */
  a12 = MEM32(a12 + 0); /* 0034: l32i.n a12, a12, 0 */
  if ((a12 >> 18) & 1) goto L_56; /* 0036: bbsi a12, 18, 56 <ppFetchTxQFirstAvail+0x52> */
  a11 = MEM32(a2 + 40); /* 0039: l32i.n a11, a2, 40 */
  MEM32(a9 + 32) = a11; /* 003b: s32i.n a11, a9, 32 */
  if (a11 != 0) goto L_4c; /* 003d: bnez.n a11, 4c <ppFetchTxQFirstAvail+0x48> */
  a8 = (a8 << 2) + a8; /* 003f: addx2 a8, a8, a8 */
  a8 = a8 << (4 & 31); /* 0042: slli a8, a8, 4 */
  a8 = a8 + (32); /* 0045: addi a8, a8, 32 */
  a10 = a10 + a8; /* 0048: add.n a10, a10, a8 */
  MEM32(a9 + 36) = a10; /* 004a: s32i.n a10, a9, 36 */
L_4c:;
  a8 = 0x0; /* 004c: movi.n a8, 0 */
  MEM32(a2 + 40) = a8; /* 004e: s32i.n a8, a2, 40 */
  MEMW(); /* 0050: memw  */
  goto L_58; /* 0053: j 58 <ppFetchTxQFirstAvail+0x54> */
L_56:;
  a2 = a11; /* 0056: mov.n a2, a11 */
L_58:;
  return (int32_t)a2; /* 0058: retw.n  */
}

/* ppDequeueTxQ @ pp.o 00000004 size 58B bind GLOBAL
 * Calls: none | Data refs: pTxRx
 *   MMIO: none
 *   funcdb v3: 0 call(s), 1 ref(s); disasm: 0 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t ppDequeueTxQ(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.ppDequeueTxQ; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a8 = (a2 >> 0) & 0xFF; /* 0007: extui a8, a2, 0, 8 */
  a9 = 0xF; /* 000a: movi.n a9, 15 */
  a2 = 0x0; /* 000c: movi.n a2, 0 */
  if (a9 < a8) goto L_39; /* 000e: bltu a9, a8, 39 <ppDequeueTxQ+0x35> */
  a2 = (uint32_t)&pTxRx; /* 0011: l32r a2, 0 <ppDequeueTxQ-0x4> (0 <ppDequeueTxQ-0x4>) */ /* literal @0x0: pTxRx */
  a9 = (a8 << 2) + a8; /* 0014: addx2 a9, a8, a8 */
  a9 = a9 << (4 & 31); /* 0017: slli a9, a9, 4 */
  a10 = MEM32(a2 + 0); /* 001a: l32i.n a10, a2, 0 */
  a9 = a10 + a9; /* 001c: add.n a9, a10, a9 */
  a2 = MEM32(a9 + 32); /* 001e: l32i.n a2, a9, 32 */
  if (a2 == 0) goto L_39; /* 0020: beqz.n a2, 39 <ppDequeueTxQ+0x35> */
  a11 = MEM32(a2 + 40); /* 0022: l32i.n a11, a2, 40 */
  MEM32(a9 + 32) = a11; /* 0024: s32i.n a11, a9, 32 */
  if (a11 != 0) goto L_35; /* 0026: bnez.n a11, 35 <ppDequeueTxQ+0x31> */
  a8 = (a8 << 2) + a8; /* 0028: addx2 a8, a8, a8 */
  a8 = a8 << (4 & 31); /* 002b: slli a8, a8, 4 */
  a8 = a8 + (32); /* 002e: addi a8, a8, 32 */
  a10 = a10 + a8; /* 0031: add.n a10, a10, a8 */
  MEM32(a9 + 36) = a10; /* 0033: s32i.n a10, a9, 36 */
L_35:;
  a8 = 0x0; /* 0035: movi.n a8, 0 */
  MEM32(a2 + 40) = a8; /* 0037: s32i.n a8, a2, 40 */
L_39:;
  MEMW(); /* 0039: memw  */
  return (int32_t)a2; /* 003c: retw.n  */
}

/* ppRollBackTxQ @ pp.o 00000004 size 50B bind GLOBAL
 * Calls: none | Data refs: pTxRx
 *   MMIO: none
 *   funcdb v3: 0 call(s), 1 ref(s); disasm: 0 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t ppRollBackTxQ(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.ppRollBackTxQ; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a8 = (uint32_t)&pTxRx; /* 0007: l32r a8, 0 <ppRollBackTxQ-0x4> (0 <ppRollBackTxQ-0x4>) */ /* literal @0x0: pTxRx */
  a11 = MEM32(a8 + 0); /* 000a: l32i.n a11, a8, 0 */
  a8 = MEM32(a2 + 44); /* 000c: l32i.n a8, a2, 44 */
  a8 = MEM32(a8 + 16); /* 000e: l32i.n a8, a8, 16 */
  a8 = (a8 >> 20) & 0xF; /* 0010: extui a8, a8, 20, 4 */
  a9 = (a8 << 2) + a8; /* 0013: addx2 a9, a8, a8 */
  a9 = a9 << (4 & 31); /* 0016: slli a9, a9, 4 */
  a9 = a11 + a9; /* 0019: add.n a9, a11, a9 */
  a12 = MEM32(a9 + 32); /* 001b: l32i.n a12, a9, 32 */
  a10 = a8 + a8; /* 001d: add.n a10, a8, a8 */
  MEM32(a2 + 40) = a12; /* 001f: s32i.n a12, a2, 40 */
  if (a12 != 0) goto L_28; /* 0021: bnez.n a12, 28 <ppRollBackTxQ+0x24> */
  a12 = a2 + (40); /* 0023: addi a12, a2, 40 */
  MEM32(a9 + 36) = a12; /* 0026: s32i.n a12, a9, 36 */
L_28:;
  a8 = a10 + a8; /* 0028: add.n a8, a10, a8 */
  a8 = a8 << (4 & 31); /* 002a: slli a8, a8, 4 */
  a11 = a11 + a8; /* 002d: add.n a11, a11, a8 */
  MEM32(a11 + 32) = a2; /* 002f: s32i.n a2, a11, 32 */
  MEMW(); /* 0031: memw  */
  return (int32_t)a2; /* 0034: retw.n  */
}

/* ppSetBarRate @ pp.o 00000008 size 37B bind GLOBAL
 * Calls: rcSetBarRate | Data refs: pTxRx, rcSetBarRate
 *   MMIO: none
 *   funcdb v3: 1 call(s), 2 ref(s); disasm: 1 call(s), 2 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t ppSetBarRate(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.ppSetBarRate; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_8:;
  /* 0008: entry a1, 32 */
  a4 = (uint32_t)&pTxRx; /* 000b: l32r a4, 0 <ppSetBarRate-0x8> (0 <ppSetBarRate-0x8>) */ /* literal @0x0: pTxRx */
  a2 = (a2 >> 0) & 0xFF; /* 000e: extui a2, a2, 0, 8 */
  a3 = 0x0; /* 0011: movi a3, 0 */
L_14:;
  a11 = a2; /* 0014: mov.n a11, a2 */
  a8 = MEM32(a4 + 0); /* 0016: l32i.n a8, a4, 0 */
  a8 = (a3 << 4) + a8; /* 0018: addx4 a8, a3, a8 */
  a3 = 0x1; /* 001b: addi.n a3, a3, 1 */
  a8 = MEM32(a8 + 800); /* 001d: l32i a8, a8, 0x320 */
  a10 = MEM32(a8 + 44); /* 0020: l32i.n a10, a8, 44 */
  a8 = (uint32_t)&rcSetBarRate; /* 0022: l32r a8, 4 <ppSetBarRate-0x4> (0 <ppSetBarRate-0x8>) */ /* literal: GOT slot for rcSetBarRate */
  rcSetBarRate(a2, a3, a4, a5); /* call via literal slot */ /* 0025: callx8 a8 */
  if (a3 != 4) goto L_14; /* 0028: bnei a3, 4, 14 <ppSetBarRate+0xc> */
  return (int32_t)a2; /* 002b: retw.n  */
}

/* ppFillAMPDUBar @ pp.o 00000018 size 260B bind GLOBAL
 * Calls: memcpy | Data refs: bars, memcpy, pTxRx
 *   MMIO: none
 *   funcdb v3: 1 call(s), 3 ref(s); disasm: 2 call(s), 3 data ref(s)
 * Fidelity: medium - 99 instr, 6 branches, calls resolved */
int32_t ppFillAMPDUBar(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.ppFillAMPDUBar; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_18:;
  /* 0018: entry a1, 48 */
  a7 = (a2 >> 0) & 0xFF; /* 001b: extui a7, a2, 0, 8 */
  a11 = a3; /* 001e: mov.n a11, a3 */
  a8 = 0x4; /* 0020: movi.n a8, 4 */
  a3 = (a5 >> 0) & 0xFFFF; /* 0022: extui a3, a5, 0, 16 */
  if (a7 >= 8) goto L_41; /* 0025: bgeui a7, 8, 41 <ppFillAMPDUBar+0x29> */
  if (a7 == 0) goto L_3f; /* 0028: beqz.n a7, 3f <ppFillAMPDUBar+0x27> */
  if (a7 == 3) goto L_3f; /* 002a: beqi a7, 3, 3f <ppFillAMPDUBar+0x27> */
  a8 = 0x3; /* 002d: movi.n a8, 3 */
  if (a7 < a8) goto L_41; /* 002f: bltu a7, a8, 41 <ppFillAMPDUBar+0x29> */
  a8 = 0x1; /* 0032: movi.n a8, 1 */
  if (a7 < 6) goto L_39; /* 0034: bltui a7, 6, 39 <ppFillAMPDUBar+0x21> */
  a8 = 0x0; /* 0037: movi.n a8, 0 */
L_39:;
  a8 = 0x0; /* 0039: extui a8, a8, 0, 8 */
  goto L_41; /* 003c: j 41 <ppFillAMPDUBar+0x29> */
L_3f:;
  a8 = 0x2; /* 003f: movi.n a8, 2 */
L_41:;
  a2 = (uint32_t)&pTxRx; /* 0041: l32r a2, 0 <ppFillAMPDUBar-0x18> (0 <ppFillAMPDUBar-0x18>) */ /* literal @0x0: pTxRx */
  a10 = 0xFFFFFFF0; /* 0044: movi.n a10, -16 */
  a9 = (a7 >> 0) & 0xF; /* 0046: extui a9, a7, 0, 4 */
  a13 = 0xFFFFFFFF; /* 0049: movi.n a13, -1 */
  a13 = 0x80000000; /* 004b: slli a13, a13, 31 */
  a2 = MEM32(a2 + 0); /* 004e: l32i.n a2, a2, 0 */
  a3 = a3 << (4 & 31); /* 0050: slli a3, a3, 4 */
  a2 = (a8 << 4) + a2; /* 0053: addx4 a2, a8, a2 */
  a2 = MEM32(a2 + 800); /* 0056: l32i a2, a2, 0x320 */
  a6 = MEM32(a2 + 44); /* 0059: l32i.n a6, a2, 44 */
  a5 = MEM32(a6 + 4); /* 005b: l32i.n a5, a6, 4 */
  a5 = a5 & a10; /* 005d: and a5, a5, a10 */
  a5 = a5 | a9; /* 0060: or a5, a5, a9 */
  a9 = 0x1; /* 0063: movi.n a9, 1 */
  MEM32(a6 + 4) = a5; /* 0065: s32i.n a5, a6, 4 */
  a9 = 0x80000; /* 0067: slli a9, a9, 19 */
  a5 = MEM32(a6 + 0); /* 006a: l32i.n a5, a6, 0 */
  a5 = a5 | a9; /* 006c: or a5, a5, a9 */
  MEM32(a6 + 0) = a5; /* 006f: s32i.n a5, a6, 0 */
  a5 = 0x12; /* 0071: addx8 a5, a8, a8 */
  a5 = 0x48; /* 0074: slli a5, a5, 2 */
  a10 = 0x58; /* 0077: addi a10, a5, 16 */
  a9 = (uint32_t)&bars; /* 007a: l32r a9, 4 <ppFillAMPDUBar-0x14> (0 <ppFillAMPDUBar-0x18>) */ /* literal @0x4: bars */
  a10 = a10 + a9; /* 007d: add.n a10, a10, a9 */
  a6 = MEM32(a2 + 4); /* 007f: l32i.n a6, a2, 4 */
  MEM32(a6 + 4) = a10; /* 0081: s32i.n a10, a6, 4 */
  MEMW(); /* 0083: memw  */
  a10 = MEM32(a6 + 0); /* 0086: l32i.n a10, a6, 0 */
  a10 = a10 | a13; /* 0088: or a10, a10, a13 */
  a13 = 0x1; /* 008b: movi.n a13, 1 */
  a13 = 0x40000000; /* 008d: slli a13, a13, 30 */
  a12 = MEM16(a2 + 22); /* 0090: l16ui a12, a2, 22 */
  a12 = (a12 >> 0) & 0xFFF; /* 0093: extui a12, a12, 0, 12 */
  a12 = a12 << (12 & 31); /* 0096: slli a12, a12, 12 */
  MEMW(); /* 0099: memw  */
  MEM32(a6 + 0) = a10; /* 009c: s32i.n a10, a6, 0 */
  MEMW(); /* 009e: memw  */
  a10 = MEM32(a6 + 0); /* 00a1: l32i.n a10, a6, 0 */
  a10 = a10 | a13; /* 00a3: or a10, a10, a13 */
  MEMW(); /* 00a6: memw  */
  MEM32(a6 + 0) = a10; /* 00a9: s32i.n a10, a6, 0 */
  MEMW(); /* 00ab: memw  */
  a10 = MEM32(a6 + 0); /* 00ae: l32i.n a10, a6, 0 */
  a13 = 0xDFFFFFFF; /* 00b0: l32r a13, 8 <ppFillAMPDUBar-0x10> (dfffffff <ppRxFragmentProc+0xdfffff7f>) */ @0x8
  a10 = a10 & a13; /* 00b3: and a10, a10, a13 */
  MEMW(); /* 00b6: memw  */
  MEM32(a6 + 0) = a10; /* 00b9: s32i.n a10, a6, 0 */
  MEMW(); /* 00bb: memw  */
  a10 = MEM32(a6 + 0); /* 00be: l32i.n a10, a6, 0 */
  a13 = 0xFF000FFF; /* 00c0: l32r a13, c <ppFillAMPDUBar-0xc> (ff000fff <ppRxFragmentProc+0xff000f7f>) */ @0xC
  a10 = a10 & a13; /* 00c3: and a10, a10, a13 */
  a10 = a10 | a12; /* 00c6: or a10, a10, a12 */
  a12 = 0x6; /* 00c9: movi.n a12, 6 */
  MEMW(); /* 00cb: memw  */
  MEM32(a6 + 0) = a10; /* 00ce: s32i.n a10, a6, 0 */
  a6 = 0x12; /* 00d0: addx8 a6, a8, a8 */
  a6 = (a6 << 4) + a9; /* 00d3: addx4 a6, a6, a9 */
  a10 = 0xFFFFFFF7; /* 00d6: movi.n a10, -9 */
  a8 = MEM8(a6 + 17); /* 00d8: l8ui a8, a6, 17 */
  a8 = a8 & a10; /* 00db: and a8, a8, a10 */
  a10 = 0x5C; /* 00de: addi a10, a5, 20 */
  a10 = a9 + a10; /* 00e1: add.n a10, a9, a10 */
  MEM8(a6 + 17) = a8; /* 00e3: s8i a8, a6, 17 */
  MEMW(); /* 00e6: memw  */
  MEM32(a1 + 0) = a9; /* 00e9: s32i a9, a1, 0 */
  MEMW(); /* 00ec: memw  */
  a8 = (uint32_t)&memcpy; /* 00ef: l32r a8, 10 <ppFillAMPDUBar-0x8> (0 <ppFillAMPDUBar-0x18>) */ /* literal: GOT slot for memcpy */
  memcpy(a2, a3, a4, a5); /* call via literal slot */ /* 00f2: callx8 a8 */
  a10 = a5 + (26); /* 00f5: addi a10, a5, 26 */
  a11 = a4; /* 00f8: mov.n a11, a4 */
  a12 = 0x6; /* 00fa: movi.n a12, 6 */
  a9 = MEM32(a1 + 0); /* 00fc: l32i.n a9, a1, 0 */
  a4 = 0x4; /* 00fe: movi.n a4, 4 */
  a10 = a9 + a10; /* 0100: add.n a10, a9, a10 */
  a8 = (uint32_t)&memcpy; /* 0102: l32r a8, 14 <ppFillAMPDUBar-0x4> (0 <ppFillAMPDUBar-0x18>) */ /* literal: GOT slot for memcpy */
  memcpy(a2, a3, a4, a5); /* call via literal slot */ /* 0105: callx8 a8 */
  a8 = a7 << (12 & 31); /* 0108: slli a8, a7, 12 */
  a8 = a8 | a4; /* 010b: or a8, a8, a4 */
  MEM16(a6 + 32) = a8; /* 010e: s16i a8, a6, 32 */
  MEM16(a6 + 34) = a3; /* 0111: s16i a3, a6, 34 */
  MEMW(); /* 0114: memw  */
  MEMW(); /* 0117: memw  */
  return (int32_t)a2; /* 011a: retw.n  */
}

/* ppPauseTxAMPDU @ pp.o 00000004 size 32B bind GLOBAL
 * Calls: none | Data refs: pTxRx
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t ppPauseTxAMPDU(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .wifiextrairam.33; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a8 = (uint32_t)&pTxRx; /* 0007: l32r a8, 0 <ppPauseTxAMPDU-0x4> (0 <ppPauseTxAMPDU-0x4>) */ /* literal @0x0: pTxRx */
  a2 = (a2 >> 0) & 0xFF; /* 000a: extui a2, a2, 0, 8 */
  a2 = (a2 << 2) + a2; /* 000d: addx2 a2, a2, a2 */
  a2 = a2 << (4 & 31); /* 0010: slli a2, a2, 4 */
  a8 = MEM32(a8 + 0); /* 0013: l32i.n a8, a8, 0 */
  a8 = a8 + a2; /* 0015: add.n a8, a8, a2 */
  a2 = 0x1; /* 0017: movi.n a2, 1 */
  MEM8(a8 + 41) = a2; /* 0019: s8i a2, a8, 41 */
  MEMW(); /* 001c: memw  */
  MEMW(); /* 001f: memw  */
  return (int32_t)a2; /* 0022: retw.n  */
}

/* ppResumeTxAMPDU @ pp.o 00000004 size 32B bind GLOBAL
 * Calls: none | Data refs: pTxRx
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t ppResumeTxAMPDU(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .wifi0iram.34; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a8 = (uint32_t)&pTxRx; /* 0007: l32r a8, 0 <ppResumeTxAMPDU-0x4> (0 <ppResumeTxAMPDU-0x4>) */ /* literal @0x0: pTxRx */
  a2 = (a2 >> 0) & 0xFF; /* 000a: extui a2, a2, 0, 8 */
  a2 = (a2 << 2) + a2; /* 000d: addx2 a2, a2, a2 */
  a2 = a2 << (4 & 31); /* 0010: slli a2, a2, 4 */
  a8 = MEM32(a8 + 0); /* 0013: l32i.n a8, a8, 0 */
  a8 = a8 + a2; /* 0015: add.n a8, a8, a2 */
  a2 = 0x0; /* 0017: movi.n a2, 0 */
  MEM16(a8 + 40) = a2; /* 0019: s16i a2, a8, 40 */
  MEMW(); /* 001c: memw  */
  MEMW(); /* 001f: memw  */
  return (int32_t)a2; /* 0022: retw.n  */
}

/* ppCalSubFrameLength @ pp.o 00000004 size 35B bind GLOBAL
 * Calls: roundup2[got] | Data refs: roundup2
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 1 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t ppCalSubFrameLength(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .wifi0iram.35; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a2 = MEM32(a2 + 4); /* 0007: l32i.n a2, a2, 4 */
  a11 = 0x4; /* 0009: movi.n a11, 4 */
  a2 = MEM32(a2 + 4); /* 000b: l32i.n a2, a2, 4 */
  a10 = MEM32(a2 + 0); /* 000d: l32i.n a10, a2, 0 */
  a10 = (a10 >> 0) & 0xFFF; /* 000f: extui a10, a10, 0, 12 */
  a8 = (uint32_t)&roundup2; /* 0012: l32r a8, 0 <ppCalSubFrameLength-0x4> (0 <ppCalSubFrameLength-0x4>) */ /* literal: GOT slot for roundup2 */
  roundup2(a2, a3, a4, a5); /* call via literal slot */ /* 0015: callx8 a8 */
  a2 = MEM32(a2 + 0); /* 0018: l32i.n a2, a2, 0 */
  a2 = (a2 >> 12) & 0x7F; /* 001a: extui a2, a2, 12, 7 */
  a2 = a2 + (1); /* 001d: addi.n a2, a2, 1 */
  a2 = (a2 << 4) + a10; /* 001f: addx4 a2, a2, a10 */
  a2 = (a2 >> 0) & 0xFFFF; /* 0022: extui a2, a2, 0, 16 */
  return (int32_t)a2; /* 0025: retw.n  */
}

/* ppEmptyDelimiterLength @ pp.o 00000000 size 32B bind GLOBAL
 * Calls: none | Data refs: none
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t ppEmptyDelimiterLength(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .wifi0iram.36; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_0:;
  /* 0000: entry a1, 32 */
  a2 = MEM32(a2 + 4); /* 0003: l32i.n a2, a2, 4 */
  a2 = MEM32(a2 + 4); /* 0005: l32i.n a2, a2, 4 */
  a2 = MEM32(a2 + 0); /* 0007: l32i.n a2, a2, 0 */
  a8 = (a2 >> 0) & 0x3; /* 0009: extui a8, a2, 0, 2 */
  if (a8 == 0) goto L_18; /* 000c: beqz a8, 18 <ppEmptyDelimiterLength+0x18> */
  a9 = 0x4; /* 000f: movi a9, 4 */
  a8 = a9 - a8; /* 0012: sub a8, a9, a8 */
  a8 = (a8 >> 0) & 0xFF; /* 0015: extui a8, a8, 0, 8 */
L_18:;
  a2 = (a2 >> 12) & 0x7F; /* 0018: extui a2, a2, 12, 7 */
  a2 = (a2 << 4) + a8; /* 001b: addx4 a2, a2, a8 */
  return (int32_t)a2; /* 001e: retw.n  */
}

/* ppCheckTxAMPDUlength @ pp.o 00000008 size 128B bind GLOBAL
 * Calls: roundup2 | Data refs: pTxRx, roundup2
 *   MMIO: none
 *   funcdb v3: 1 call(s), 2 ref(s); disasm: 1 call(s), 2 data ref(s)
 * Fidelity: medium - 47 instr, 6 branches, calls resolved */
int32_t ppCheckTxAMPDUlength(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.ppCheckTxAMPDUlength; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_8:;
  /* 0008: entry a1, 32 */
  a7 = MEM32(a5 + 4); /* 000b: l32i.n a7, a5, 4 */
  a11 = 0x4; /* 000d: movi a11, 4 */
  a4 = (a4 >> 0) & 0xFF; /* 0010: extui a4, a4, 0, 8 */
  a7 = MEM32(a7 + 4); /* 0013: l32i a7, a7, 4 */
  a10 = MEM32(a7 + 0); /* 0016: l32i a10, a7, 0 */
  a10 = (a10 >> 0) & 0xFFF; /* 0019: extui a10, a10, 0, 12 */
  a8 = (uint32_t)&roundup2; /* 001c: l32r a8, 4 <ppCheckTxAMPDUlength-0x4> (0 <ppCheckTxAMPDUlength-0x8>) */ /* literal: GOT slot for roundup2 */
  roundup2(a2, a3, a4, a5); /* call via literal slot */ /* 001f: callx8 a8 */
  a5 = MEM32(a5 + 44); /* 0022: l32i.n a5, a5, 44 */
  a8 = MEM32(a5 + 16); /* 0024: l32i.n a8, a5, 16 */
  a5 = (a10 >> 0) & 0xFFFF; /* 0026: extui a5, a10, 0, 16 */
  a3 = a5 + a3; /* 0029: add.n a3, a5, a3 */
  a8 = (a8 >> 20) & 0xF; /* 002b: extui a8, a8, 20, 4 */
  a5 = MEM16(a2 + 122); /* 002e: l16ui a5, a2, 122 */
  if (a5 < a3) goto L_3d; /* 0031: bltu a5, a3, 3d <ppCheckTxAMPDUlength+0x35> */
L_34:;
  a2 = MEM16(a2 + 124); /* 0034: l16ui a2, a2, 124 */
  if (a2 >= a3) goto L_5d; /* 0037: bgeu a2, a3, 5d <ppCheckTxAMPDUlength+0x55> */
  goto L_55; /* 003a: j 55 <ppCheckTxAMPDUlength+0x4d> */
L_3d:;
  a5 = (uint32_t)&pTxRx; /* 003d: l32r a5, 0 <ppCheckTxAMPDUlength-0x8> (0 <ppCheckTxAMPDUlength-0x8>) */ /* literal @0x0: pTxRx */
  a11 = (a8 << 2) + a8; /* 0040: addx2 a11, a8, a8 */
  a11 = a11 << (4 & 31); /* 0043: slli a11, a11, 4 */
  a9 = MEM32(a5 + 0); /* 0046: l32i.n a9, a5, 0 */
  a5 = 0x1; /* 0048: movi.n a5, 1 */
  a9 = a9 + a11; /* 004a: add.n a9, a9, a11 */
  MEM8(a9 + 76) = a5; /* 004c: s8i a5, a9, 76 */
  MEMW(); /* 004f: memw  */
  if (a6 != 0) goto L_34; /* 0052: bnez a6, 34 <ppCheckTxAMPDUlength+0x2c> */
L_55:;
  a2 = 0x0; /* 0055: movi.n a2, 0 */
  MEMW(); /* 0057: memw  */
  goto L_86; /* 005a: j 86 <ppCheckTxAMPDUlength+0x7e> */
L_5d:;
  a2 = (uint32_t)&pTxRx; /* 005d: l32r a2, 0 <ppCheckTxAMPDUlength-0x8> (0 <ppCheckTxAMPDUlength-0x8>) */ /* literal @0x0: pTxRx */
  a8 = (a8 << 2) + a8; /* 0060: addx2 a8, a8, a8 */
  a8 = a8 << (4 & 31); /* 0063: slli a8, a8, 4 */
  a3 = MEM32(a2 + 0); /* 0066: l32i.n a3, a2, 0 */
  a3 = a3 + a8; /* 0068: add.n a3, a3, a8 */
  a2 = MEM8(a7 + 3); /* 006a: l8ui a2, a7, 3 */
  a2 = a2 - a4; /* 006d: sub a2, a2, a4 */
  a2 = (a2 >> 0) & 0xFF; /* 0070: extui a2, a2, 0, 8 */
  a3 = MEM8(a3 + 47); /* 0073: l8ui a3, a3, 47 */
  if (a2 >= a3) goto L_55; /* 0076: bgeu a2, a3, 55 <ppCheckTxAMPDUlength+0x4d> */
  a2 = MEM32(a7 + 0); /* 0079: l32i.n a2, a7, 0 */
  a2 = (a2 >> 12) & 0x7F; /* 007b: extui a2, a2, 12, 7 */
  a2 = a2 + (1); /* 007e: addi.n a2, a2, 1 */
  a2 = (a2 << 4) + a10; /* 0080: addx4 a2, a2, a10 */
  a2 = (a2 >> 0) & 0xFFFF; /* 0083: extui a2, a2, 0, 16 */
L_86:;
  return (int32_t)a2; /* 0086: retw.n  */
}

/* ppAdd2AMPDUTail @ pp.o 00000000 size 20B bind GLOBAL
 * Calls: none | Data refs: none
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t ppAdd2AMPDUTail(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .wifiextrairam.37; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_0:;
  /* 0000: entry a1, 32 */
  MEM32(a2 + 40) = a3; /* 0003: s32i.n a3, a2, 40 */
  a8 = MEM32(a3 + 4); /* 0005: l32i.n a8, a3, 4 */
  a2 = MEM32(a2 + 8); /* 0007: l32i.n a2, a2, 8 */
  MEM32(a2 + 8) = a8; /* 0009: s32i.n a8, a2, 8 */
  a2 = 0x0; /* 000b: movi.n a2, 0 */
  MEM32(a3 + 40) = a2; /* 000d: s32i.n a2, a3, 40 */
  MEMW(); /* 000f: memw  */
  return (int32_t)a2; /* 0012: retw.n  */
}

/* ppSubFromAMPDU @ pp.o 00000000 size 26B bind GLOBAL
 * Calls: none | Data refs: none
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t ppSubFromAMPDU(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .wifi0iram.38; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_0:;
  /* 0000: entry a1, 32 */
  a9 = MEM32(a3 + 8); /* 0003: l32i.n a9, a3, 8 */
  a8 = MEM32(a2 + 8); /* 0005: l32i.n a8, a2, 8 */
  a10 = MEM32(a9 + 8); /* 0007: l32i.n a10, a9, 8 */
  MEM32(a8 + 8) = a10; /* 0009: s32i.n a10, a8, 8 */
  a8 = 0x0; /* 000b: movi.n a8, 0 */
  MEM32(a9 + 8) = a8; /* 000d: s32i.n a8, a9, 8 */
  a9 = MEM32(a3 + 40); /* 000f: l32i.n a9, a3, 40 */
  MEM32(a2 + 40) = a9; /* 0011: s32i.n a9, a2, 40 */
  MEM32(a3 + 40) = a8; /* 0013: s32i.n a8, a3, 40 */
  MEMW(); /* 0015: memw  */
  return (int32_t)a2; /* 0018: retw.n  */
}

/* ppReSendBar @ pp.o 00000034 size 274B bind GLOBAL
 * Calls: lmacTxFrame, rcGetRate | Data refs: bars, g_mesh_init_ps_type, g_mesh_is_root, g_mesh_is_started, g_osi_funcs_p, g_wifi_mac_time_delta, lmacTxFrame, pTxRx, rcGetRate
 *   MMIO: 0x3FF73C00
 *   funcdb v3: 2 call(s), 9 ref(s); disasm: 2 call(s), 9 data ref(s)
 * Fidelity: medium - 105 instr, 10 branches, calls resolved */
int32_t ppReSendBar(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.ppReSendBar; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_34:;
  /* 0034: entry a1, 32 */
  a2 = (a2 >> 0) & 0xFF; /* 0037: extui a2, a2, 0, 8 */
  a3 = (a3 >> 0) & 0xFF; /* 003a: extui a3, a3, 0, 8 */
  a4 = 0x4; /* 003d: movi.n a4, 4 */
  if (a2 >= 8) goto L_5c; /* 003f: bgeui a2, 8, 5c <ppReSendBar+0x28> */
  if (a2 == 0) goto L_5a; /* 0042: beqz.n a2, 5a <ppReSendBar+0x26> */
  if (a2 == 3) goto L_5a; /* 0044: beqi a2, 3, 5a <ppReSendBar+0x26> */
  a4 = 0x3; /* 0047: movi.n a4, 3 */
  if (a2 < a4) goto L_5c; /* 0049: bltu a2, a4, 5c <ppReSendBar+0x28> */
  a4 = 0x1; /* 004c: movi.n a4, 1 */
  if (a2 < 6) goto L_54; /* 004e: bltui a2, 6, 54 <ppReSendBar+0x20> */
  a4 = 0x0; /* 0051: movi a4, 0 */
L_54:;
  a4 = 0x0; /* 0054: extui a4, a4, 0, 8 */
  goto L_5c; /* 0057: j 5c <ppReSendBar+0x28> */
L_5a:;
  a4 = 0x2; /* 005a: movi.n a4, 2 */
L_5c:;
  a2 = (uint32_t)&pTxRx; /* 005c: l32r a2, 0 <ppReSendBar-0x34> (0 <ppReSendBar-0x34>) */ /* literal @0x0: pTxRx */
  a3 = (a3 >> 0) & 0xF; /* 005f: extui a3, a3, 0, 4 */
  a3 = a3 << (20 & 31); /* 0062: slli a3, a3, 20 */
  a2 = MEM32(a2 + 0); /* 0065: l32i.n a2, a2, 0 */
  a2 = (a4 << 4) + a2; /* 0067: addx4 a2, a4, a2 */
  a2 = MEM32(a2 + 800); /* 006a: l32i a2, a2, 0x320 */
  a9 = MEM32(a2 + 44); /* 006d: l32i.n a9, a2, 44 */
  a8 = MEM8(a9 + 4); /* 006f: l8ui a8, a9, 4 */
  a10 = 0xFF0FFFFF; /* 0072: l32r a10, 4 <ppReSendBar-0x30> (ff0fffff <ppRxFragmentProc+0xff0fff7f>) */ @0x4
  MEM32(a9 + 4) = a8; /* 0075: s32i.n a8, a9, 4 */
  a8 = MEM32(a9 + 16); /* 0077: l32i.n a8, a9, 16 */
  a8 = a8 & a10; /* 0079: and a8, a8, a10 */
  a8 = a8 | a3; /* 007c: or a8, a8, a3 */
  a3 = (uint32_t)&g_mesh_is_started; /* 007f: l32r a3, 8 <ppReSendBar-0x2c> (0 <ppReSendBar-0x34>) */ /* literal @0x8: g_mesh_is_started */
  MEM32(a9 + 16) = a8; /* 0082: s32i.n a8, a9, 16 */
  a3 = MEM8(a3 + 0); /* 0084: l8ui a3, a3, 0 */
  if (a3 == 0) goto L_b1; /* 0087: beqz.n a3, b1 <ppReSendBar+0x7d> */
  a3 = (uint32_t)&g_mesh_is_root; /* 0089: l32r a3, c <ppReSendBar-0x28> (0 <ppReSendBar-0x34>) */ /* literal @0xC: g_mesh_is_root */
  MEMW(); /* 008c: memw  */
  a3 = MEM8(a3 + 0); /* 008f: l8ui a3, a3, 0 */
  a3 = (a3 >> 0) & 0xFF; /* 0092: extui a3, a3, 0, 8 */
  if (a3 != 0) goto L_b1; /* 0095: bnez.n a3, b1 <ppReSendBar+0x7d> */
  a3 = (uint32_t)&g_mesh_init_ps_type; /* 0097: l32r a3, 10 <ppReSendBar-0x24> (0 <ppReSendBar-0x34>) */ /* literal @0x10: g_mesh_init_ps_type */
  a3 = MEM32(a3 + 0); /* 009a: l32i.n a3, a3, 0 */
  if (a3 == 0) goto L_b1; /* 009c: beqz.n a3, b1 <ppReSendBar+0x7d> */
  a3 = (uint32_t)&g_osi_funcs_p; /* 009e: l32r a3, 14 <ppReSendBar-0x20> (0 <ppReSendBar-0x34>) */ /* literal @0x14: g_osi_funcs_p */
  a3 = MEM32(a3 + 0); /* 00a1: l32i.n a3, a3, 0 */
  a10 = MEM32(a3 + 272); /* 00a3: l32i a10, a3, 0x110 */
  MEMW(); /* 00a6: memw  */
  ((int32_t(*)())a10)(a2, a3, a4, a5); /* 00a9: callx8 a10 */ /* indirect */
  goto L_c0; /* 00ac: j c0 <ppReSendBar+0x8c> */
  /* 00af: .byte 00 */
  /* 00b0: .byte 00 */
L_b1:;
  a3 = 0x3FF73C00; /* 00b1: l32r a3, 18 <ppReSendBar-0x1c> (3ff73c00 <ppRxFragmentProc+0x3ff73b80>) */ /* MMIO base */ @0x18
  MEMW(); /* 00b4: memw  */
  a10 = REG32(0x3FF73C00); /* 00b7: l32i.n a10, a3, 0 */ /* MMIO read: base 0x3FF73C00+0 */
  a3 = (uint32_t)&g_wifi_mac_time_delta; /* 00b9: l32r a3, 1c <ppReSendBar-0x18> (0 <ppReSendBar-0x34>) */ /* literal @0x1C: g_wifi_mac_time_delta */
  a3 = MEM32(a3 + 0); /* 00bc: l32i.n a3, a3, 0 */
  a10 = a10 + a3; /* 00be: add.n a10, a10, a3 */
L_c0:;
  a4 = (a4 << 8) + a4; /* 00c0: addx8 a4, a4, a4 */
  a4 = a4 << (2 & 31); /* 00c3: slli a4, a4, 2 */
  a11 = MEM32(a2 + 44); /* 00c6: l32i.n a11, a2, 44 */
  a4 = a4 + (16); /* 00c8: addi a4, a4, 16 */
  MEM32(a11 + 24) = a10; /* 00cb: s32i.n a10, a11, 24 */
  a10 = MEM32(a2 + 36); /* 00cd: l32i a10, a2, 36 */
  MEMW(); /* 00d0: memw  */
  a8 = (uint32_t)&rcGetRate; /* 00d3: l32r a8, 2c <ppReSendBar-0x8> (0 <ppReSendBar-0x34>) */ /* literal: GOT slot for rcGetRate */
  rcGetRate(a2, a3, a4, a5); /* call via literal slot */ /* 00d6: callx8 a8 */
  a10 = a2; /* 00d9: mov.n a10, a2 */
  a3 = (uint32_t)&bars; /* 00db: l32r a3, 20 <ppReSendBar-0x14> (0 <ppReSendBar-0x34>) */ /* literal @0x20: bars */
  a4 = a4 + a3; /* 00de: add.n a4, a4, a3 */
  a8 = MEM32(a2 + 4); /* 00e0: l32i.n a8, a2, 4 */
  MEMW(); /* 00e2: memw  */
  a3 = MEM32(a8 + 0); /* 00e5: l32i.n a3, a8, 0 */
  MEM32(a8 + 4) = a4; /* 00e7: s32i.n a4, a8, 4 */
  a4 = 0xFFFFFFFF; /* 00e9: movi.n a4, -1 */
  a4 = 0x80000000; /* 00eb: slli a4, a4, 31 */
  a3 = a3 | a4; /* 00ee: or a3, a3, a4 */
  a4 = 0x1; /* 00f1: movi.n a4, 1 */
  a9 = MEM16(a2 + 22); /* 00f3: l16ui a9, a2, 22 */
  a4 = 0x40000000; /* 00f6: slli a4, a4, 30 */
  a9 = (a9 >> 0) & 0xFFF; /* 00f9: extui a9, a9, 0, 12 */
  a9 = a9 << (12 & 31); /* 00fc: slli a9, a9, 12 */
  MEMW(); /* 00ff: memw  */
  MEM32(a8 + 0) = a3; /* 0102: s32i.n a3, a8, 0 */
  MEMW(); /* 0104: memw  */
  a3 = MEM32(a8 + 0); /* 0107: l32i.n a3, a8, 0 */
  a3 = a3 | a4; /* 0109: or a3, a3, a4 */
  MEMW(); /* 010c: memw  */
  MEM32(a8 + 0) = a3; /* 010f: s32i.n a3, a8, 0 */
  MEMW(); /* 0111: memw  */
  a3 = MEM32(a8 + 0); /* 0114: l32i.n a3, a8, 0 */
  a4 = 0xDFFFFFFF; /* 0116: l32r a4, 24 <ppReSendBar-0x10> (dfffffff <ppRxFragmentProc+0xdfffff7f>) */ @0x24
  a3 = a3 & a4; /* 0119: and a3, a3, a4 */
  MEMW(); /* 011c: memw  */
  MEM32(a8 + 0) = a3; /* 011f: s32i.n a3, a8, 0 */
  MEMW(); /* 0121: memw  */
  a4 = MEM32(a8 + 0); /* 0124: l32i.n a4, a8, 0 */
  a3 = 0xFF000FFF; /* 0126: l32r a3, 28 <ppReSendBar-0xc> (ff000fff <ppRxFragmentProc+0xff000f7f>) */ @0x28
  a4 = a4 & a3; /* 0129: and a4, a4, a3 */
  a4 = a4 | a9; /* 012c: or a4, a4, a9 */
  MEMW(); /* 012f: memw  */
  MEM32(a8 + 0) = a4; /* 0132: s32i.n a4, a8, 0 */
  a3 = MEM32(a2 + 44); /* 0134: l32i.n a3, a2, 44 */
  a11 = MEM32(a3 + 4); /* 0136: l32i.n a11, a3, 4 */
  a11 = (a11 >> 4) & 0xF; /* 0138: extui a11, a11, 4, 4 */
  MEMW(); /* 013b: memw  */
  a8 = (uint32_t)&lmacTxFrame; /* 013e: l32r a8, 30 <ppReSendBar-0x4> (0 <ppReSendBar-0x34>) */ /* literal: GOT slot for lmacTxFrame */
  lmacTxFrame(a2, a3, a4, a5); /* call via literal slot */ /* 0141: callx8 a8 */
  return (int32_t)a2; /* 0144: retw.n  */
}

/* ppRecordBarRRC @ pp.o 00000004 size 30B bind GLOBAL
 * Calls: none | Data refs: pTxRx
 *   MMIO: none
 *   funcdb v3: 0 call(s), 1 ref(s); disasm: 0 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t ppRecordBarRRC(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.ppRecordBarRRC; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a8 = (uint32_t)&pTxRx; /* 0007: l32r a8, 0 <ppRecordBarRRC-0x4> (0 <ppRecordBarRRC-0x4>) */ /* literal @0x0: pTxRx */
  a2 = (a2 >> 0) & 0xFF; /* 000a: extui a2, a2, 0, 8 */
  a2 = (a2 << 2) + a2; /* 000d: addx2 a2, a2, a2 */
  a2 = a2 << (4 & 31); /* 0010: slli a2, a2, 4 */
  a8 = MEM32(a8 + 0); /* 0013: l32i.n a8, a8, 0 */
  a8 = a8 + a2; /* 0015: add.n a8, a8, a2 */
  MEM8(a8 + 40) = a3; /* 0017: s8i a3, a8, 40 */
  MEMW(); /* 001a: memw  */
  MEMW(); /* 001d: memw  */
  return (int32_t)a2; /* 0020: retw.n  */
}

/* ppTxqUpdateBitmap @ pp.o 00000004 size 42B bind GLOBAL
 * Calls: none | Data refs: pTxRx
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t ppTxqUpdateBitmap(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .wifiextrairam.44; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a8 = (uint32_t)&pTxRx; /* 0007: l32r a8, 0 <ppTxqUpdateBitmap-0x4> (0 <ppTxqUpdateBitmap-0x4>) */ /* literal @0x0: pTxRx */
  a2 = (a2 >> 0) & 0xFF; /* 000a: extui a2, a2, 0, 8 */
  a9 = MEM32(a8 + 0); /* 000d: l32i.n a9, a8, 0 */
  a8 = (a2 << 2) + a2; /* 000f: addx2 a8, a2, a2 */
  a8 = a8 << (4 & 31); /* 0012: slli a8, a8, 4 */
  a8 = a9 + a8; /* 0015: add.n a8, a9, a8 */
  a2 = MEM8(a8 + 40); /* 0017: l8ui a2, a8, 40 */
  a6 = a6 + a2; /* 001a: add.n a6, a6, a2 */
  MEM16(a8 + 42) = a3; /* 001c: s16i a3, a8, 42 */
  MEM32(a8 + 56) = a5; /* 001f: s32i.n a5, a8, 56 */
  MEM32(a8 + 60) = a4; /* 0021: s32i.n a4, a8, 60 */
  MEM8(a8 + 40) = a6; /* 0023: s8i a6, a8, 40 */
  MEMW(); /* 0026: memw  */
  MEMW(); /* 0029: memw  */
  return (int32_t)a2; /* 002c: retw.n  */
}

/* ppEnqueueTxDone @ pp.o 00000010 size 90B bind GLOBAL
 * Calls: wifi_log[got] | Data refs: .rodata.pp_default_event_handler.str1.1, .rodata_wlog_error.49, wifi_log, pTxRx
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 1 call(s), 4 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t ppEnqueueTxDone(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .wifiextrairam.48; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_10:;
  /* 0010: entry a1, 32 */
  if (a2 != 0) goto L_34; /* 0013: bnez.n a2, 34 <ppEnqueueTxDone+0x24> */
  a15 = 0x383; /* 0015: movi a15, 0x383 */
  a12 = 0x1; /* 0018: movi a12, 1 */
  a14 = (uint32_t)&lit_rodata_pp_default_event_handler_str1_1; /* 001b: l32r a14, 0 <ppEnqueueTxDone-0x10> (0 <ppEnqueueTxDone-0x10>) */ /* literal @0x0: .rodata.pp_default_event_handler.str1.1 */
  a15 = 0xE0C; /* 001e: slli a15, a15, 2 */
  a11 = 0x800; /* 0021: slli a11, a12, 11 */
  a10 = 0x6; /* 0024: movi a10, 6 */
  a13 = (uint32_t)&lit_rodata_wlog_error_49; /* 0027: l32r a13, 4 <ppEnqueueTxDone-0xc> (0 <ppEnqueueTxDone-0x10>) */ /* literal @0x4: .rodata_wlog_error.49 */
  a8 = (uint32_t)&wifi_log; /* 002a: l32r a8, c <ppEnqueueTxDone-0x4> (0 <ppEnqueueTxDone-0x10>) */ /* literal: GOT slot for wifi_log */
  wifi_log(a2, a3, a4, a5); /* call via literal slot */ /* 002d: callx8 a8 */
L_30:;
  goto L_30; /* 0030: j 30 <ppEnqueueTxDone+0x20> */
  /* 0033: .byte 00 */
L_34:;
  a9 = MEM32(a2 + 44); /* 0034: l32i.n a9, a2, 44 */
  a10 = 0x1; /* 0036: movi.n a10, 1 */
  a10 = 0x4000000; /* 0038: slli a10, a10, 26 */
  a9 = MEM32(a9 + 0); /* 003b: l32i.n a9, a9, 0 */
  a9 = a9 & a10; /* 003d: and a9, a9, a10 */
  a8 = (uint32_t)&pTxRx; /* 0040: l32r a8, 8 <ppEnqueueTxDone-0x8> (0 <ppEnqueueTxDone-0x10>) */ /* literal @0x8: pTxRx */
  a8 = MEM32(a8 + 0); /* 0043: l32i.n a8, a8, 0 */
  if (a9 == 0) goto L_58; /* 0045: beqz.n a9, 58 <ppEnqueueTxDone+0x48> */
  a2 = MEM8(a8 + 31); /* 0047: l8ui a2, a8, 31 */
  a2 = a2 + (-1); /* 004a: addi.n a2, a2, -1 */
  MEM8(a8 + 31) = a2; /* 004c: s8i a2, a8, 31 */
  MEMW(); /* 004f: memw  */
  MEMW(); /* 0052: memw  */
  goto L_65; /* 0055: j 65 <ppEnqueueTxDone+0x55> */
L_58:;
  MEM32(a2 + 40) = a9; /* 0058: s32i.n a9, a2, 40 */
  a9 = MEM32(a8 + 848); /* 005a: l32i a9, a8, 0x350 */
  MEM32(a9 + 0) = a2; /* 005d: s32i.n a2, a9, 0 */
  a2 = a2 + (40); /* 005f: addi a2, a2, 40 */
  MEM32(a8 + 848) = a2; /* 0062: s32i a2, a8, 0x350 */
L_65:;
  MEMW(); /* 0065: memw  */
  return (int32_t)a2; /* 0068: retw.n  */
}

/* ppDequeueTxDone_Locked @ pp.o 00000004 size 37B bind GLOBAL
 * Calls: none | Data refs: pTxRx
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t ppDequeueTxDone_Locked(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .wifiextrairam.50; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a2 = (uint32_t)&pTxRx; /* 0007: l32r a2, 0 <ppDequeueTxDone_Locked-0x4> (0 <ppDequeueTxDone_Locked-0x4>) */ /* literal @0x0: pTxRx */
  a8 = MEM32(a2 + 0); /* 000a: l32i.n a8, a2, 0 */
  a2 = MEM32(a8 + 844); /* 000c: l32i a2, a8, 0x34c */
  if (a2 == 0) goto L_24; /* 000f: beqz.n a2, 24 <ppDequeueTxDone_Locked+0x20> */
  a9 = MEM32(a2 + 40); /* 0011: l32i.n a9, a2, 40 */
  MEM32(a8 + 844) = a9; /* 0013: s32i a9, a8, 0x34c */
  if (a9 != 0) goto L_20; /* 0016: bnez.n a9, 20 <ppDequeueTxDone_Locked+0x1c> */
  a9 = 0x34C; /* 0018: movi a9, 0x34c */
  a9 = a8 + a9; /* 001b: add.n a9, a8, a9 */
  MEM32(a8 + 848) = a9; /* 001d: s32i a9, a8, 0x350 */
L_20:;
  a8 = 0x0; /* 0020: movi.n a8, 0 */
  MEM32(a2 + 40) = a8; /* 0022: s32i.n a8, a2, 40 */
L_24:;
  MEMW(); /* 0024: memw  */
  return (int32_t)a2; /* 0027: retw.n  */
}

/* ppProcTxDone @ pp.o 00000038 size 322B bind GLOBAL
 * Calls: ppProcTxCallback[got], pp_coex_tx_release[got], trc_onPPTxDone[got], .bss.g_tx_done_cb_func[got], wifi_log[got], esf_buf_recycle[got], ppDequeueTxDone_Locked[got], pp_process_hmac_waiting_txq[got], pm_on_data_tx_done[got] | Data refs: ppProcTxCallback, pp_coex_tx_release, g_mesh_is_started, trc_onPPTxDone, .bss.g_tx_done_cb_func, .rodata_wlog_info.21, wifi_log, esf_buf_recycle, ppDequeueTxDone_Locked, pp_process_hmac_waiting_txq, pm_on_data_tx_done
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 9 call(s), 11 data ref(s)
 * Fidelity: medium - 124 instr, 21 branches, calls resolved */
int32_t ppProcTxDone(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .wifiextrairam.20; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_38:;
  /* 0038: entry a1, 48 */
  a2 = 0x0; /* 003b: movi.n a2, 0 */
  a4 = 0x0; /* 003d: mov.n a4, a2 */
  MEM32(a1 + 0) = a2; /* 003f: s32i.n a2, a1, 0 */
  a3 = 0x0; /* 0041: mov.n a3, a2 */
  a6 = 0xFF; /* 0043: movi a6, 255 */
  a5 = 0x1; /* 0046: movi.n a5, 1 */
  MEMW(); /* 0048: memw  */
  goto L_148; /* 004b: j 148 <ppProcTxDone+0x110> */
L_4e:;
  a11 = 0x0; /* 004e: movi.n a11, 0 */
  a10 = a7; /* 0050: mov.n a10, a7 */
  a8 = (uint32_t)&ppProcTxCallback; /* 0052: l32r a8, 18 <ppProcTxDone-0x20> (0 <ppProcTxDone-0x38>) */ /* literal: GOT slot for ppProcTxCallback */
  ppProcTxCallback(a2, a3, a4, a5); /* call via literal slot */ /* 0055: callx8 a8 */
  a10 = a7; /* 0058: mov.n a10, a7 */
  a8 = (uint32_t)&pp_coex_tx_release; /* 005a: l32r a8, 1c <ppProcTxDone-0x1c> (0 <ppProcTxDone-0x38>) */ /* literal: GOT slot for pp_coex_tx_release */
  pp_coex_tx_release(a2, a3, a4, a5); /* call via literal slot */ /* 005d: callx8 a8 */
  a11 = MEM32(a7 + 44); /* 0060: l32i.n a11, a7, 44 */
  a9 = MEM32(a11 + 0); /* 0062: l32i.n a9, a11, 0 */
  if (!((a9 >> 13) & 1)) goto L_dc; /* 0064: bbci a9, 13, dc <ppProcTxDone+0xa4> */
  a10 = MEM32(a7 + 36); /* 0067: l32i.n a10, a7, 36 */
  if (a10 == 0) goto L_b0; /* 0069: beqz a10, b0 <ppProcTxDone+0x78> */
  a12 = MEM8(a10 + 11); /* 006c: l8ui a12, a10, 11 */
  if ((a12 >> 7) & 1) goto L_b0; /* 006f: bbsi a12, 7, b0 <ppProcTxDone+0x78> */
  a12 = MEM32(a11 + 16); /* 0072: l32i.n a12, a11, 16 */
  a6 = (a12 >> 18) & 0x3; /* 0074: extui a6, a12, 18, 2 */
  if (a6 == 0) goto L_16c; /* 0077: beqz a6, 16c <ppProcTxDone+0x134> */
  goto L_9e; /* 007a: j 9e <ppProcTxDone+0x66> */
L_7d:;
  a3 = (uint32_t)&g_mesh_is_started; /* 007d: l32r a3, 0 <ppProcTxDone-0x38> (0 <ppProcTxDone-0x38>) */ /* literal @0x0: g_mesh_is_started */
  a3 = MEM8(a3 + 0); /* 0080: l8ui a3, a3, 0 */
  if (a3 == 0) goto L_9a; /* 0083: beqz.n a3, 9a <ppProcTxDone+0x62> */
  a4 = 0xF; /* 0085: movi.n a4, 15 */
  a4 = 0xF00; /* 0087: slli a4, a4, 8 */
  a12 = a12 & a4; /* 008a: and a12, a12, a4 */
  if (a12 == 0) a11 = a6; /* 008d: moveqz a11, a6, a12 */
  MEM32(a1 + 0) = a11; /* 0090: s32i.n a11, a1, 0 */
  a4 = a3; /* 0092: mov.n a4, a3 */
  MEMW(); /* 0094: memw  */
  goto L_9e; /* 0097: j 9e <ppProcTxDone+0x66> */
L_9a:;
  a4 = a5; /* 009a: mov.n a4, a5 */
  a3 = a11; /* 009c: mov.n a3, a11 */
L_9e:;
  a11 = 0x80008; /* 009e: l32r a11, 4 <ppProcTxDone-0x34> (80008 <ppRxFragmentProc+0x7ff88>) */ @0x4
  a9 = a9 & a11; /* 00a1: and a9, a9, a11 */
  if (a9 != 8) goto L_b0; /* 00a4: bnei a9, 8, b0 <ppProcTxDone+0x78> */
  a11 = a7 | a7; /* 00a7: or a11, a7, a7 */
  a8 = (uint32_t)&trc_onPPTxDone; /* 00aa: l32r a8, 20 <ppProcTxDone-0x18> (0 <ppProcTxDone-0x38>) */ /* literal: GOT slot for trc_onPPTxDone */
  trc_onPPTxDone(a2, a3, a4, a5); /* call via literal slot */ /* 00ad: callx8 a8 */
L_b0:;
  a9 = (uint32_t)&bss_g_tx_done_cb_func; /* 00b0: l32r a9, 8 <ppProcTxDone-0x30> (0 <ppProcTxDone-0x38>) */ /* literal @0x8: .bss.g_tx_done_cb_func */
  a9 = MEM32(a9 + 0); /* 00b3: l32i.n a9, a9, 0 */
  if (a9 == 0) goto L_138; /* 00b5: beqz a9, 138 <ppProcTxDone+0x100> */
  a10 = MEM32(a7 + 44); /* 00b8: l32i.n a10, a7, 44 */
  a11 = MEM32(a7 + 4); /* 00ba: l32i.n a11, a7, 4 */
  a12 = MEM32(a10 + 0); /* 00bc: l32i.n a12, a10, 0 */
  a11 = MEM32(a11 + 4); /* 00be: l32i.n a11, a11, 4 */
  if (!((a12 >> 18) & 1)) goto L_c6; /* 00c0: bbci a12, 18, c6 <ppProcTxDone+0x8e> */
  a11 = a11 + (4); /* 00c3: addi a11, a11, 4 */
L_c6:;
  a13 = 0x0; /* 00c6: movi.n a13, 0 */
  a12 = a7 + (22); /* 00c8: addi a12, a7, 22 */
  a10 = MEM8(a10 + 19); /* 00cb: l8ui a10, a10, 19 */
  a10 = a10 + (-1); /* 00ce: addi.n a10, a10, -1 */
  if (a10 == 0) a13 = a5; /* 00d0: moveqz a13, a5, a10 */
  a10 = a6; /* 00d3: mov.n a10, a6 */
  bss_g_tx_done_cb_func(a2, a3, a4, a5); /* call via literal slot */ /* 00d5: callx8 a9 */
  goto L_138; /* 00d8: j 138 <ppProcTxDone+0x100> */
  /* 00db: .byte 00 */
L_dc:;
  if (!((a9 >> 23) & 1)) goto L_120; /* 00dc: bbci a9, 23, 120 <ppProcTxDone+0xe8> */
  a10 = MEM16(a7 + 22); /* 00df: l16ui a10, a7, 22 */
  a10 = a10 + (-4); /* 00e2: addi a10, a10, -4 */
  MEM16(a7 + 22) = a10; /* 00e5: s16i a10, a7, 22 */
  MEMW(); /* 00e8: memw  */
  a10 = MEM32(a7 + 8); /* 00eb: l32i.n a10, a7, 8 */
  MEMW(); /* 00ed: memw  */
  a8 = MEM32(a10 + 0); /* 00f0: l32i.n a8, a10, 0 */
  a8 = (a8 >> 12) & 0xFFF; /* 00f2: extui a8, a8, 12, 12 */
  a8 = a8 + (-4); /* 00f5: addi a8, a8, -4 */
  a8 = (a8 >> 0) & 0xFFF; /* 00f8: extui a8, a8, 0, 12 */
  MEMW(); /* 00fb: memw  */
  a12 = MEM32(a10 + 0); /* 00fe: l32i.n a12, a10, 0 */
  a8 = a8 << (12 & 31); /* 0100: slli a8, a8, 12 */
  a13 = 0xFF000FFF; /* 0103: l32r a13, c <ppProcTxDone-0x2c> (ff000fff <ppRxFragmentProc+0xff000f7f>) */ @0xC
  a12 = a12 & a13; /* 0106: and a12, a12, a13 */
  a8 = a12 | a8; /* 0109: or a8, a12, a8 */
  MEMW(); /* 010c: memw  */
  MEM32(a10 + 0) = a8; /* 010f: s32i.n a8, a10, 0 */
  a8 = 0xFF7FFFFF; /* 0111: l32r a8, 10 <ppProcTxDone-0x28> (ff7fffff <ppRxFragmentProc+0xff7fff7f>) */ @0x10
  a8 = a9 & a8; /* 0114: and a8, a9, a8 */
  MEM32(a11 + 0) = a8; /* 0117: s32i.n a8, a11, 0 */
  MEMW(); /* 0119: memw  */
  goto L_148; /* 011c: j 148 <ppProcTxDone+0x110> */
  /* 011f: .byte 00 */
L_120:;
  a9 = MEM8(a7 + 26); /* 0120: l8ui a9, a7, 26 */
  if (a9 != 5) goto L_138; /* 0123: bnei a9, 5, 138 <ppProcTxDone+0x100> */
  a12 = 0x3; /* 0126: movi.n a12, 3 */
  a11 = 0x40; /* 0128: movi.n a11, 64 */
  a13 = (uint32_t)&lit_rodata_wlog_info_21; /* 012a: l32r a13, 14 <ppProcTxDone-0x24> (0 <ppProcTxDone-0x38>) */ /* literal @0x14: .rodata_wlog_info.21 */
  a10 = 0x6; /* 012d: movi.n a10, 6 */
  a8 = (uint32_t)&wifi_log; /* 012f: l32r a8, 24 <ppProcTxDone-0x14> (0 <ppProcTxDone-0x38>) */ /* literal: GOT slot for wifi_log */
  wifi_log(a2, a3, a4, a5); /* call via literal slot */ /* 0132: callx8 a8 */
  goto L_148; /* 0135: j 148 <ppProcTxDone+0x110> */
L_138:;
  a9 = MEM8(a7 + 26); /* 0138: l8ui a9, a7, 26 */
  a10 = a7; /* 013b: mov.n a10, a7 */
  a9 = a9 + (-1); /* 013d: addi.n a9, a9, -1 */
  if (a9 == 0) a2 = a5; /* 013f: moveqz a2, a5, a9 */
  a8 = (uint32_t)&esf_buf_recycle; /* 0142: l32r a8, 28 <ppProcTxDone-0x10> (0 <ppProcTxDone-0x38>) */ /* literal: GOT slot for esf_buf_recycle */
  esf_buf_recycle(a2, a3, a4, a5); /* call via literal slot */ /* 0145: callx8 a8 */
L_148:;
  a8 = (uint32_t)&ppDequeueTxDone_Locked; /* 0148: l32r a8, 2c <ppProcTxDone-0xc> (0 <ppProcTxDone-0x38>) */ /* literal: GOT slot for ppDequeueTxDone_Locked */
  ppDequeueTxDone_Locked(a2, a3, a4, a5); /* call via literal slot */ /* 014b: callx8 a8 */
  a7 = a10; /* 014e: mov.n a7, a10 */
  if (a10 != 0) goto L_4e; /* 0150: bnez a10, 4e <ppProcTxDone+0x16> */
  if (a2 == 0) goto L_15c; /* 0153: beqz a2, 15c <ppProcTxDone+0x124> */
  a8 = (uint32_t)&pp_process_hmac_waiting_txq; /* 0156: l32r a8, 30 <ppProcTxDone-0x8> (0 <ppProcTxDone-0x38>) */ /* literal: GOT slot for pp_process_hmac_waiting_txq */
  pp_process_hmac_waiting_txq(a2, a3, a4, a5); /* call via literal slot */ /* 0159: callx8 a8 */
L_15c:;
  a11 = MEM32(a1 + 0); /* 015c: l32i.n a11, a1, 0 */
  a12 = a4; /* 015e: mov.n a12, a4 */
  a10 = a3; /* 0160: mov.n a10, a3 */
  a8 = (uint32_t)&pm_on_data_tx_done; /* 0162: l32r a8, 34 <ppProcTxDone-0x4> (0 <ppProcTxDone-0x38>) */ /* literal: GOT slot for pm_on_data_tx_done */
  pm_on_data_tx_done(a2, a3, a4, a5); /* call via literal slot */ /* 0165: callx8 a8 */
  return (int32_t)a2; /* 0168: retw.n  */
  /* 016a: .byte 00 */
  /* 016b: .byte 00 */
L_16c:;
  a11 = MEM8(a11 + 19); /* 016c: l8ui a11, a11, 19 */
  a4 = a5; /* 016f: mov.n a4, a5 */
  if (a11 == 1) goto L_177; /* 0171: beqi a11, 1, 177 <ppProcTxDone+0x13f> */
  goto L_9e; /* 0174: j 9e <ppProcTxDone+0x66> */
L_177:;
  goto L_7d; /* 0177: j 7d <ppProcTxDone+0x45> */
}

/* ppEnqueueRxq @ pp.o 00000004 size 28B bind GLOBAL
 * Calls: none | Data refs: pTxRx
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t ppEnqueueRxq(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .wifislprxiram.51; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a8 = 0x0; /* 0007: movi.n a8, 0 */
  MEM32(a2 + 40) = a8; /* 0009: s32i.n a8, a2, 40 */
  a8 = (uint32_t)&pTxRx; /* 000b: l32r a8, 0 <ppEnqueueRxq-0x4> (0 <ppEnqueueRxq-0x4>) */ /* literal @0x0: pTxRx */
  a8 = MEM32(a8 + 0); /* 000e: l32i.n a8, a8, 0 */
  a9 = MEM32(a8 + 856); /* 0010: l32i a9, a8, 0x358 */
  MEM32(a9 + 0) = a2; /* 0013: s32i.n a2, a9, 0 */
  a2 = a2 + (40); /* 0015: addi a2, a2, 40 */
  MEM32(a8 + 856) = a2; /* 0018: s32i a2, a8, 0x358 */
  MEMW(); /* 001b: memw  */
  return (int32_t)a2; /* 001e: retw.n  */
}

/* ppDequeueRxq_Locked @ pp.o 00000004 size 37B bind GLOBAL
 * Calls: none | Data refs: pTxRx
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t ppDequeueRxq_Locked(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .wifislprxiram.52; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a2 = (uint32_t)&pTxRx; /* 0007: l32r a2, 0 <ppDequeueRxq_Locked-0x4> (0 <ppDequeueRxq_Locked-0x4>) */ /* literal @0x0: pTxRx */
  a8 = MEM32(a2 + 0); /* 000a: l32i.n a8, a2, 0 */
  a2 = MEM32(a8 + 852); /* 000c: l32i a2, a8, 0x354 */
  if (a2 == 0) goto L_24; /* 000f: beqz.n a2, 24 <ppDequeueRxq_Locked+0x20> */
  a9 = MEM32(a2 + 40); /* 0011: l32i.n a9, a2, 40 */
  MEM32(a8 + 852) = a9; /* 0013: s32i a9, a8, 0x354 */
  if (a9 != 0) goto L_20; /* 0016: bnez.n a9, 20 <ppDequeueRxq_Locked+0x1c> */
  a9 = 0x354; /* 0018: movi a9, 0x354 */
  a9 = a8 + a9; /* 001b: add.n a9, a8, a9 */
  MEM32(a8 + 856) = a9; /* 001d: s32i a9, a8, 0x358 */
L_20:;
  a8 = 0x0; /* 0020: movi.n a8, 0 */
  MEM32(a2 + 40) = a8; /* 0022: s32i.n a8, a2, 40 */
L_24:;
  MEMW(); /* 0024: memw  */
  return (int32_t)a2; /* 0027: retw.n  */
}

/* ppRxPkt @ pp.o 0000002c size 297B bind GLOBAL
 * Calls: wDevCheckBlockError[got], ppRxProtoProc[got], ppRxFragmentProc[got], ppRxProtoProc[got], is_fragmented_pkt[got], .bss.s_michael_mic_failure_cb[got], wifi_log[got], pTxRx[got], pTxRx[got], ppRecycleRxPkt[got], ppDequeueRxq_Locked[got] | Data refs: pTxRx, wDevCheckBlockError, ppRxProtoProc, ppRxFragmentProc, is_fragmented_pkt, .bss.s_michael_mic_failure_cb, .rodata_wlog_error.31, wifi_log, ppRecycleRxPkt, ppDequeueRxq_Locked
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 11 call(s), 10 data ref(s)
 * Fidelity: medium - 118 instr, 27 branches, calls resolved */
int32_t ppRxPkt(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .wifislprxiram.30; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_2c:;
  /* 002c: entry a1, 32 */
  a3 = 0x1; /* 002f: movi.n a3, 1 */
  a6 = (uint32_t)&pTxRx; /* 0031: l32r a6, 0 <ppRxPkt-0x2c> (0 <ppRxPkt-0x2c>) */ /* literal @0x0: pTxRx */
  a4 = 0x10; /* 0034: movi.n a4, 16 */
  a5 = 0x20000000; /* 0036: slli a5, a3, 29 */
  goto L_148; /* 0039: j 148 <ppRxPkt+0x11c> */
L_3c:;
  a10 = a2; /* 003c: mov.n a10, a2 */
  a8 = (uint32_t)&wDevCheckBlockError; /* 003e: l32r a8, c <ppRxPkt-0x20> (0 <ppRxPkt-0x2c>) */ /* literal: GOT slot for wDevCheckBlockError */
  wDevCheckBlockError(a2, a3, a4, a5); /* call via literal slot */ /* 0041: callx8 a8 */
  a7 = MEM32(a2 + 16); /* 0044: l32i.n a7, a2, 16 */
  a10 = a2; /* 0046: mov.n a10, a2 */
  a9 = a7 + (28); /* 0048: addi a9, a7, 28 */
  a11 = a7; /* 004b: mov.n a11, a7 */
  a8 = MEM32(a2 + 4); /* 004d: l32i.n a8, a2, 4 */
  MEM32(a8 + 4) = a9; /* 004f: s32i.n a9, a8, 4 */
  a8 = MEM32(a2 + 44); /* 0051: l32i.n a8, a2, 44 */
  a8 = MEM32(a8 + 0); /* 0053: l32i.n a8, a8, 0 */
  a8 = a8 & a4; /* 0055: and a8, a8, a4 */
  if ((a8 >> 4) & 1) goto L_78; /* 0058: bbsi a8, 4, 78 <ppRxPkt+0x4c> */
  MEMW(); /* 005b: memw  */
  a8 = (uint32_t)&ppRxProtoProc; /* 005e: l32r a8, 10 <ppRxPkt-0x1c> (0 <ppRxPkt-0x2c>) */ /* literal: GOT slot for ppRxProtoProc */
  ppRxProtoProc(a2, a3, a4, a5); /* call via literal slot */ /* 0061: callx8 a8 */
  if (a10 == 0) goto L_69; /* 0064: beqz.n a10, 69 <ppRxPkt+0x3d> */
  goto L_140; /* 0066: j 140 <ppRxPkt+0x114> */
L_69:;
  a10 = a2; /* 0069: mov.n a10, a2 */
  a8 = (uint32_t)&ppRxFragmentProc; /* 006b: l32r a8, 14 <ppRxPkt-0x18> (0 <ppRxPkt-0x2c>) */ /* literal: GOT slot for ppRxFragmentProc */
  ppRxFragmentProc(a2, a3, a4, a5); /* call via literal slot */ /* 006e: callx8 a8 */
  a2 = a10; /* 0071: mov.n a2, a10 */
  if (a10 != 0) goto L_90; /* 0073: bnez.n a10, 90 <ppRxPkt+0x64> */
  goto L_148; /* 0075: j 148 <ppRxPkt+0x11c> */
L_78:;
  a8 = (uint32_t)&ppRxProtoProc; /* 0078: l32r a8, 18 <ppRxPkt-0x14> (0 <ppRxPkt-0x2c>) */ /* literal: GOT slot for ppRxProtoProc */
  ppRxProtoProc(a2, a3, a4, a5); /* call via literal slot */ /* 007b: callx8 a8 */
  if (a10 == 0) goto L_83; /* 007e: beqz.n a10, 83 <ppRxPkt+0x57> */
  goto L_140; /* 0080: j 140 <ppRxPkt+0x114> */
L_83:;
  a10 = a2; /* 0083: mov.n a10, a2 */
  a8 = (uint32_t)&is_fragmented_pkt; /* 0085: l32r a8, 1c <ppRxPkt-0x10> (0 <ppRxPkt-0x2c>) */ /* literal: GOT slot for is_fragmented_pkt */
  is_fragmented_pkt(a2, a3, a4, a5); /* call via literal slot */ /* 0088: callx8 a8 */
  if (a10 == 0) goto L_90; /* 008b: beqz.n a10, 90 <ppRxPkt+0x64> */
  goto L_140; /* 008d: j 140 <ppRxPkt+0x114> */
L_90:;
  a8 = MEM32(a7 + 0); /* 0090: l32i.n a8, a7, 0 */
  a12 = 0x1; /* 0092: movi.n a12, 1 */
  a12 = 0x10000000; /* 0094: slli a12, a12, 28 */
  a12 = a8 & a12; /* 0097: and a12, a8, a12 */
  if (a12 == 0) goto L_10c; /* 009a: beqz a12, 10c <ppRxPkt+0xe0> */
  a8 = MEM8(a7 + 27); /* 009d: l8ui a8, a7, 27 */
  a9 = 0x0; /* 00a0: movi.n a9, 0 */
  a10 = 0xFFFFFF0B; /* 00a2: movi a10, -245 */
  a11 = 0x0; /* 00a5: mov.n a11, a9 */
  a10 = a8 + a10; /* 00a7: add.n a10, a8, a10 */
  if (a8 != 0) a11 = a3; /* 00a9: movnez a11, a3, a8 */
  if (a10 != 0) a9 = a3; /* 00ac: movnez a9, a3, a10 */
  if ((a11 & a9) == 0) goto L_bc; /* 00af: bnone a11, a9, bc <ppRxPkt+0x90> */
  a9 = 0xFFFFFF3A; /* 00b2: movi a9, -198 */
  a9 = a8 + a9; /* 00b5: add.n a9, a8, a9 */
  if (a9 == 0) goto L_bc; /* 00b7: beqz.n a9, bc <ppRxPkt+0x90> */
  goto L_140; /* 00b9: j 140 <ppRxPkt+0x114> */
L_bc:;
  a9 = (uint32_t)&pTxRx; /* 00bc: l32r a9, 0 <ppRxPkt-0x2c> (0 <ppRxPkt-0x2c>) */ /* literal @0x0: pTxRx */
  a9 = MEM32(a9 + 0); /* 00bf: l32i.n a9, a9, 0 */
  a9 = MEM32(a9 + 944); /* 00c1: l32i a9, a9, 0x3b0 */
  if (a9 == 0) goto L_140; /* 00c4: beqz a9, 140 <ppRxPkt+0x114> */
  a10 = 0xF5; /* 00c7: movi a10, 245 */
  if (a8 != a10) goto L_f9; /* 00ca: bne a8, a10, f9 <ppRxPkt+0xcd> */
  a8 = (uint32_t)&bss_s_michael_mic_failure_cb; /* 00cd: l32r a8, 4 <ppRxPkt-0x28> (0 <ppRxPkt-0x2c>) */ /* literal @0x4: .bss.s_michael_mic_failure_cb */
  a8 = MEM32(a8 + 0); /* 00d0: l32i.n a8, a8, 0 */
  if (a8 == 0) goto L_e5; /* 00d2: beqz.n a8, e5 <ppRxPkt+0xb9> */
  a10 = 0xFFFFFFFF; /* 00d4: movi.n a10, -1 */
  a7 = MEM32(a7 + 8); /* 00d6: l32i.n a7, a7, 8 */
  a10 = a10 ^ a7; /* 00d8: xor a10, a10, a7 */
  a10 = (a10 >> 31) & 0x1; /* 00db: extui a10, a10, 31, 1 */
  bss_s_michael_mic_failure_cb(a2, a3, a4, a5); /* call via literal slot */ /* 00de: callx8 a8 */
  goto L_140; /* 00e1: j 140 <ppRxPkt+0x114> */
  /* 00e4: .byte 00 */
L_e5:;
  a13 = (uint32_t)&lit_rodata_wlog_error_31; /* 00e5: l32r a13, 8 <ppRxPkt-0x24> (0 <ppRxPkt-0x2c>) */ /* literal @0x8: .rodata_wlog_error.31 */
  a12 = a3; /* 00e8: mov.n a12, a3 */
  a11 = 0x20; /* 00ea: movi.n a11, 32 */
  a10 = 0x6; /* 00ec: movi.n a10, 6 */
  a8 = (uint32_t)&wifi_log; /* 00ee: l32r a8, 20 <ppRxPkt-0xc> (0 <ppRxPkt-0x2c>) */ /* literal: GOT slot for wifi_log */
  wifi_log(a2, a3, a4, a5); /* call via literal slot */ /* 00f1: callx8 a8 */
  goto L_140; /* 00f4: j 140 <ppRxPkt+0x114> */
  /* 00f7: .byte 00 */
  /* 00f8: .byte 00 */
L_f9:;
  a7 = MEM32(a2 + 16); /* 00f9: l32i.n a7, a2, 16 */
  a12 = 0x0; /* 00fb: movi.n a12, 0 */
  a10 = a2; /* 00fd: mov.n a10, a2 */
  a11 = MEM8(a7 + 0); /* 00ff: l8ui a11, a7, 0 */
  a11 = ((int32_t)(a11 << (32 - (7 & 31)))) >> (32 - (7 & 31)); /* 0102: sext a11, a11, 7 */
  pTxRx(a2, a3, a4, a5); /* call via literal slot */ /* 0105: callx8 a9 */
  goto L_148; /* 0108: j 148 <ppRxPkt+0x11c> */
  /* 010b: .byte 00 */
L_10c:;
  a9 = a8 & a5; /* 010c: and a9, a8, a5 */
  if (a9 == 0) goto L_124; /* 010f: beqz.n a9, 124 <ppRxPkt+0xf8> */
  a7 = (uint32_t)&pTxRx; /* 0111: l32r a7, 0 <ppRxPkt-0x2c> (0 <ppRxPkt-0x2c>) */ /* literal @0x0: pTxRx */
  a7 = MEM32(a7 + 0); /* 0114: l32i.n a7, a7, 0 */
  a7 = MEM32(a7 + 948); /* 0116: l32i a7, a7, 0x3b4 */
  if (a7 == 0) goto L_140; /* 0119: beqz.n a7, 140 <ppRxPkt+0x114> */
  a8 = MEM32(a2 + 16); /* 011b: l32i.n a8, a2, 16 */
  a11 = MEM8(a8 + 0); /* 011d: l8ui a11, a8, 0 */
  goto L_135; /* 0120: j 135 <ppRxPkt+0x109> */
  /* 0123: .byte 00 */
L_124:;
  if (!((a8 >> 30) & 1)) goto L_140; /* 0124: bbci a8, 30, 140 <ppRxPkt+0x114> */
  a7 = MEM32(a6 + 0); /* 0127: l32i.n a7, a6, 0 */
  a7 = MEM32(a7 + 952); /* 0129: l32i a7, a7, 0x3b8 */
  if (a7 == 0) goto L_140; /* 012c: beqz.n a7, 140 <ppRxPkt+0x114> */
  a12 = a9; /* 012e: mov.n a12, a9 */
  a8 = MEM32(a2 + 16); /* 0130: l32i.n a8, a2, 16 */
  a11 = MEM8(a8 + 0); /* 0132: l8ui a11, a8, 0 */
L_135:;
  a11 = ((int32_t)(a11 << (32 - (7 & 31)))) >> (32 - (7 & 31)); /* 0135: sext a11, a11, 7 */
  a10 = a2; /* 0138: mov.n a10, a2 */
  pTxRx(a2, a3, a4, a5); /* call via literal slot */ /* 013a: callx8 a7 */
  goto L_148; /* 013d: j 148 <ppRxPkt+0x11c> */
L_140:;
  a10 = a2; /* 0140: mov.n a10, a2 */
  a8 = (uint32_t)&ppRecycleRxPkt; /* 0142: l32r a8, 24 <ppRxPkt-0x8> (0 <ppRxPkt-0x2c>) */ /* literal: GOT slot for ppRecycleRxPkt */
  ppRecycleRxPkt(a2, a3, a4, a5); /* call via literal slot */ /* 0145: callx8 a8 */
L_148:;
  a8 = (uint32_t)&ppDequeueRxq_Locked; /* 0148: l32r a8, 28 <ppRxPkt-0x4> (0 <ppRxPkt-0x2c>) */ /* literal: GOT slot for ppDequeueRxq_Locked */
  ppDequeueRxq_Locked(a2, a3, a4, a5); /* call via literal slot */ /* 014b: callx8 a8 */
  a2 = a10; /* 014e: mov.n a2, a10 */
  if (a10 != 0) goto L_3c; /* 0150: bnez a10, 3c <ppRxPkt+0x10> */
  return (int32_t)a2; /* 0153: retw.n  */
}

/* emul_timeout @ pp.o 00000000 size 5B bind GLOBAL
 * Calls: none | Data refs: none
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t emul_timeout(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.emul_timeout; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_0:;
  /* 0000: entry a1, 32 */
  return (int32_t)a2; /* 0003: retw.n  */
}

/* pp_create_task @ pp.o 00000058 size 378B bind GLOBAL
 * Calls: config_get_wifi_task_stack_size, wifi_log, s_wifi_queue[got], xphyQueue[got], g_osi_funcs_p[got], g_osi_funcs_p[got] | Data refs: .bss.pp_task_hdl, .bss.s_pp_task_create_sem, .rodata.pp_create_task.str1.1, .rodata_wlog_error.55, .rodata_wlog_error.56, .rodata_wlog_error.57, .rodata_wlog_error.58, .rodata_wlog_info.59, .rodata_wlog_warning.53, .rodata_wlog_warning.54, config_get_wifi_task_stack_size, g_osi_funcs_p, g_wifi_menuconfig, ppTask, s_wifi_queue, wifi_log, xphyQueue
 *   MMIO: none
 *   funcdb v3: 2 call(s), 17 ref(s); disasm: 13 call(s), 17 data ref(s)
 * Fidelity: medium - 150 instr, 11 branches, 6 indirect; flow + direct calls mapped, GOT-indirects enumerated (verified against section disasm) */
int32_t pp_create_task(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pp_create_task; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_58:;
  /* 0058: entry a1, 64 */
  a2 = (uint32_t)&g_wifi_menuconfig; /* 005b: l32r a2, 0 <pp_create_task-0x58> (0 <pp_create_task-0x58>) */ /* literal @0x0: g_wifi_menuconfig */
  a6 = MEM32(a2 + 52); /* 005e: l32i.n a6, a2, 52 */
  a2 = (uint32_t)&g_osi_funcs_p; /* 0060: l32r a2, 4 <pp_create_task-0x54> (0 <pp_create_task-0x58>) */ /* literal @0x4: g_osi_funcs_p */
  a3 = MEM32(a2 + 0); /* 0063: l32i a3, a2, 0 */
  a10 = MEM32(a3 + 168); /* 0066: l32i a10, a3, 168 */
  ((int32_t(*)())a10)(a2, a3, a4, a5); /* 0069: callx8 a10 */ /* indirect */
  a5 = a10; /* 006c: mov.n a5, a10 */
  a3 = (uint32_t)&bss_pp_task_hdl; /* 006e: l32r a3, 8 <pp_create_task-0x50> (0 <pp_create_task-0x58>) */ /* literal @0x8: .bss.pp_task_hdl */
  a4 = MEM32(a3 + 0); /* 0071: l32i.n a4, a3, 0 */
  if (a4 == 0) goto L_90; /* 0073: beqz.n a4, 90 <pp_create_task+0x38> */
  a10 = 0x6; /* 0075: movi.n a10, 6 */
  a12 = 0x2; /* 0077: movi a12, 2 */
  a13 = (uint32_t)&lit_rodata_wlog_warning_53; /* 007a: l32r a13, c <pp_create_task-0x4c> (0 <pp_create_task-0x58>) */ /* literal @0xC: .rodata_wlog_warning.53 */
  a11 = 0x1; /* 007d: movi a11, 1 */
  a8 = (uint32_t)&wifi_log; /* 0080: l32r a8, 3c <pp_create_task-0x1c> (0 <pp_create_task-0x58>) */ /* literal: GOT slot for wifi_log */
  wifi_log(a2, a3, a4, a5); /* call via literal slot */ /* 0083: callx8 a8 */
  a4 = MEM32(a2 + 0); /* 0086: l32i.n a4, a2, 0 */
  a10 = MEM32(a3 + 0); /* 0088: l32i.n a10, a3, 0 */
  a4 = MEM32(a4 + 152); /* 008a: l32i a4, a4, 152 */
  ((int32_t(*)())a4)(a2, a3, a4, a5); /* 008d: callx8 a4 */ /* indirect */
L_90:;
  a4 = (uint32_t)&s_wifi_queue; /* 0090: l32r a4, 10 <pp_create_task-0x48> (0 <pp_create_task-0x58>) */ /* literal @0x10: s_wifi_queue */
  a7 = MEM32(a4 + 0); /* 0093: l32i.n a7, a4, 0 */
  if (a7 == 0) goto L_b1; /* 0095: beqz.n a7, b1 <pp_create_task+0x59> */
  a10 = 0x6; /* 0097: movi.n a10, 6 */
  a12 = 0x2; /* 0099: movi.n a12, 2 */
  a13 = (uint32_t)&lit_rodata_wlog_warning_54; /* 009b: l32r a13, 14 <pp_create_task-0x44> (0 <pp_create_task-0x58>) */ /* literal @0x14: .rodata_wlog_warning.54 */
  a11 = 0x1; /* 009e: movi.n a11, 1 */
  a8 = (uint32_t)&wifi_log; /* 00a0: l32r a8, 40 <pp_create_task-0x18> (0 <pp_create_task-0x58>) */ /* literal: GOT slot for wifi_log */
  wifi_log(a2, a3, a4, a5); /* call via literal slot */ /* 00a3: callx8 a8 */
  a7 = MEM32(a2 + 0); /* 00a6: l32i.n a7, a2, 0 */
  a10 = MEM32(a4 + 0); /* 00a8: l32i a10, a4, 0 */
  a7 = MEM32(a7 + 384); /* 00ab: l32i a7, a7, 0x180 */
  ((int32_t(*)())a7)(a2, a3, a4, a5); /* 00ae: callx8 a7 */ /* indirect */
L_b1:;
  a11 = 0x8; /* 00b1: movi.n a11, 8 */
  a10 = 0xC8; /* 00b3: movi a10, 200 */
  a7 = MEM32(a2 + 0); /* 00b6: l32i.n a7, a2, 0 */
  a7 = MEM32(a7 + 380); /* 00b8: l32i a7, a7, 0x17c */
  ((int32_t(*)())a7)(a2, a3, a4, a5); /* 00bb: callx8 a7 */ /* indirect */
  MEM32(a4 + 0) = a10; /* 00be: s32i.n a10, a4, 0 */
  if (a10 != 0) goto L_d9; /* 00c0: bnez.n a10, d9 <pp_create_task+0x81> */
  a12 = 0x1; /* 00c2: movi.n a12, 1 */
  a13 = (uint32_t)&lit_rodata_wlog_error_55; /* 00c4: l32r a13, 18 <pp_create_task-0x40> (0 <pp_create_task-0x58>) */ /* literal @0x18: .rodata_wlog_error.55 */
  a11 = 0x1; /* 00c7: mov.n a11, a12 */
  a10 = 0x6; /* 00c9: movi.n a10, 6 */
  MEMW(); /* 00cb: memw  */
  a8 = (uint32_t)&wifi_log; /* 00ce: l32r a8, 44 <pp_create_task-0x14> (0 <pp_create_task-0x58>) */ /* literal: GOT slot for wifi_log */
  wifi_log(a2, a3, a4, a5); /* call via literal slot */ /* 00d1: callx8 a8 */
  goto L_1ca; /* 00d4: j 1ca <pp_create_task+0x172> */
  /* 00d7: .byte 00 */
  /* 00d8: .byte 00 */
L_d9:;
  a4 = MEM32(a10 + 0); /* 00d9: l32i.n a4, a10, 0 */
  a7 = (uint32_t)&xphyQueue; /* 00db: l32r a7, 1c <pp_create_task-0x3c> (0 <pp_create_task-0x58>) */ /* literal @0x1C: xphyQueue */
  MEM32(a7 + 0) = a4; /* 00de: s32i.n a4, a7, 0 */
  a13 = (uint32_t)&lit_rodata_wlog_error_56; /* 00e0: l32r a13, 20 <pp_create_task-0x38> (0 <pp_create_task-0x58>) */ /* literal @0x20: .rodata_wlog_error.56 */
  if (a4 == 0) goto L_13c; /* 00e3: beqz a4, 13c <pp_create_task+0xe4> */
  a11 = 0x0; /* 00e6: movi.n a11, 0 */
  a10 = 0x1; /* 00e8: movi.n a10, 1 */
  a4 = MEM32(a2 + 0); /* 00ea: l32i.n a4, a2, 0 */
  a4 = MEM32(a4 + 52); /* 00ec: l32i a4, a4, 52 */
  MEMW(); /* 00ef: memw  */
  s_wifi_queue(a2, a3, a4, a5); /* call via literal slot */ /* 00f2: callx8 a4 */
  a4 = (uint32_t)&bss_s_pp_task_create_sem; /* 00f5: l32r a4, 24 <pp_create_task-0x34> (0 <pp_create_task-0x58>) */ /* literal @0x24: .bss.s_pp_task_create_sem */
  MEM32(a4 + 0) = a10; /* 00f8: s32i.n a10, a4, 0 */
  a13 = (uint32_t)&lit_rodata_wlog_error_57; /* 00fa: l32r a13, 28 <pp_create_task-0x30> (0 <pp_create_task-0x58>) */ /* literal @0x28: .rodata_wlog_error.57 */
  if (a10 == 0) goto L_13c; /* 00fd: beqz.n a10, 13c <pp_create_task+0xe4> */
  a7 = MEM32(a2 + 0); /* 00ff: l32i a7, a2, 0 */
  a7 = MEM32(a7 + 144); /* 0102: l32i a7, a7, 144 */
  MEMW(); /* 0105: memw  */
  a8 = (uint32_t)&config_get_wifi_task_stack_size; /* 0108: l32r a8, 48 <pp_create_task-0x10> (0 <pp_create_task-0x58>) */ /* literal: GOT slot for config_get_wifi_task_stack_size */
  config_get_wifi_task_stack_size(a2, a3, a4, a5); /* call via literal slot */ /* 010b: callx8 a8 */
  a12 = 0x1; /* 010e: mov.n a12, a10 */
  a8 = MEM32(a2 + 0); /* 0110: l32i.n a8, a2, 0 */
  a10 = MEM32(a8 + 168); /* 0112: l32i a10, a8, 168 */
  MEM32(a1 + 16) = a12; /* 0115: s32i.n a12, a1, 16 */
  MEMW(); /* 0117: memw  */
  ((int32_t(*)())a10)(a2, a3, a4, a5); /* 011a: callx8 a10 */ /* indirect */
  a14 = a10 + (-2); /* 011d: addi a14, a10, -2 */
  a15 = a3; /* 0120: mov.n a15, a3 */
  a13 = 0x0; /* 0122: movi.n a13, 0 */
  a12 = MEM32(a1 + 16); /* 0124: l32i.n a12, a1, 16 */
  a11 = (uint32_t)&lit_rodata_pp_create_task_str1_1; /* 0126: l32r a11, 2c <pp_create_task-0x2c> (0 <pp_create_task-0x58>) */ /* literal @0x2C: .rodata.pp_create_task.str1.1 */
  a10 = (uint32_t)&ppTask; /* 0129: l32r a10, 30 <pp_create_task-0x28> (0 <pp_create_task-0x58>) */ /* literal @0x30: ppTask */
  MEM32(a1 + 0) = a6; /* 012c: s32i.n a6, a1, 0 */
  MEMW(); /* 012e: memw  */
  xphyQueue(a2, a3, a4, a5); /* call via literal slot */ /* 0131: callx8 a7 */
  a7 = a10; /* 0134: mov.n a7, a10 */
  if (a10 == 1) goto L_14c; /* 0136: beqi a10, 1, 14c <pp_create_task+0xf4> */
  a13 = (uint32_t)&lit_rodata_wlog_error_58; /* 0139: l32r a13, 34 <pp_create_task-0x24> (0 <pp_create_task-0x58>) */ /* literal @0x34: .rodata_wlog_error.58 */
L_13c:;
  a12 = 0x1; /* 013c: movi.n a12, 1 */
  a11 = 0x800; /* 013e: slli a11, a12, 11 */
  a10 = 0x6; /* 0141: movi.n a10, 6 */
  a8 = (uint32_t)&wifi_log; /* 0143: l32r a8, 4c <pp_create_task-0xc> (0 <pp_create_task-0x58>) */ /* literal: GOT slot for wifi_log */
  wifi_log(a2, a3, a4, a5); /* call via literal slot */ /* 0146: callx8 a8 */
  goto L_1a2; /* 0149: j 1a2 <pp_create_task+0x14a> */
L_14c:;
  a8 = MEM32(a2 + 0); /* 014c: l32i.n a8, a2, 0 */
  a11 = 0xFFFFFFFF; /* 014e: movi.n a11, -1 */
  a8 = MEM32(a8 + 60); /* 0150: l32i a8, a8, 60 */
  a10 = MEM32(a4 + 0); /* 0153: l32i.n a10, a4, 0 */
  wifi_log(a2, a3, a4, a5); /* call via literal slot */ /* 0155: callx8 a8 */
  a10 = a7; /* 0158: mov.n a10, a7 */
  a8 = MEM32(a2 + 0); /* 015a: l32i.n a8, a2, 0 */
  a8 = MEM32(a8 + 156); /* 015c: l32i a8, a8, 156 */
  wifi_log(a2, a3, a4, a5); /* call via literal slot */ /* 015f: callx8 a8 */
  a2 = MEM32(a2 + 0); /* 0162: l32i.n a2, a2, 0 */
  a10 = MEM32(a4 + 0); /* 0164: l32i a10, a4, 0 */
  a2 = MEM32(a2 + 56); /* 0167: l32i a2, a2, 56 */
  g_osi_funcs_p(a2, a3, a4, a5); /* call via literal slot */ /* 016a: callx8 a2 */
  a2 = 0x0; /* 016d: movi.n a2, 0 */
  a3 = MEM32(a3 + 0); /* 016f: l32i.n a3, a3, 0 */
  MEM32(a4 + 0) = a2; /* 0171: s32i.n a2, a4, 0 */
  MEMW(); /* 0173: memw  */
  a8 = (uint32_t)&config_get_wifi_task_stack_size; /* 0176: l32r a8, 50 <pp_create_task-0x8> (0 <pp_create_task-0x58>) */ /* literal: GOT slot for config_get_wifi_task_stack_size */
  config_get_wifi_task_stack_size(a2, a3, a4, a5); /* call via literal slot */ /* 0179: callx8 a8 */
  a15 = a5 + (-2); /* 017c: addi a15, a5, -2 */
  a15 = (a15 >> 0) & 0xFF; /* 017f: extui a15, a15, 0, 8 */
  a14 = a3; /* 0182: mov.n a14, a3 */
  a13 = (uint32_t)&lit_rodata_wlog_info_59; /* 0184: l32r a13, 38 <pp_create_task-0x20> (0 <pp_create_task-0x58>) */ /* literal @0x38: .rodata_wlog_info.59 */
  a12 = 0x3; /* 0187: movi.n a12, 3 */
  a11 = a7; /* 0189: mov.n a11, a7 */
  MEM32(a1 + 0) = a10; /* 018b: s32i.n a10, a1, 0 */
  a10 = 0x6; /* 018d: movi a10, 6 */
  MEM32(a1 + 4) = a6; /* 0190: s32i a6, a1, 4 */
  MEMW(); /* 0193: memw  */
  a8 = (uint32_t)&wifi_log; /* 0196: l32r a8, 54 <pp_create_task-0x4> (0 <pp_create_task-0x58>) */ /* literal: GOT slot for wifi_log */
  wifi_log(a2, a3, a4, a5); /* call via literal slot */ /* 0199: callx8 a8 */
  goto L_1cd; /* 019c: j 1cd <pp_create_task+0x175> */
  /* 019f: .byte 00 */
  /* 01a0: .byte 00 */
  /* 01a1: .byte 00 */
L_1a2:;
  a4 = (uint32_t)&s_wifi_queue; /* 01a2: l32r a4, 10 <pp_create_task-0x48> (0 <pp_create_task-0x58>) */ /* literal @0x10: s_wifi_queue */
  a10 = MEM32(a4 + 0); /* 01a5: l32i.n a10, a4, 0 */
  if (a10 == 0) goto L_1b5; /* 01a7: beqz.n a10, 1b5 <pp_create_task+0x15d> */
  a5 = MEM32(a2 + 0); /* 01a9: l32i.n a5, a2, 0 */
  a5 = MEM32(a5 + 384); /* 01ab: l32i a5, a5, 0x180 */
  ((int32_t(*)())a5)(a2, a3, a4, a5); /* 01ae: callx8 a5 */ /* indirect */
  a5 = 0x0; /* 01b1: movi.n a5, 0 */
  MEM32(a4 + 0) = a5; /* 01b3: s32i.n a5, a4, 0 */
L_1b5:;
  a4 = (uint32_t)&bss_s_pp_task_create_sem; /* 01b5: l32r a4, 24 <pp_create_task-0x34> (0 <pp_create_task-0x58>) */ /* literal @0x24: .bss.s_pp_task_create_sem */
  a10 = MEM32(a4 + 0); /* 01b8: l32i.n a10, a4, 0 */
  if (a10 == 0) goto L_1c6; /* 01ba: beqz.n a10, 1c6 <pp_create_task+0x16e> */
  a2 = MEM32(a2 + 0); /* 01bc: l32i.n a2, a2, 0 */
  a2 = MEM32(a2 + 56); /* 01be: l32i.n a2, a2, 56 */
  MEMW(); /* 01c0: memw  */
  g_osi_funcs_p(a2, a3, a4, a5); /* call via literal slot */ /* 01c3: callx8 a2 */
L_1c6:;
  a2 = 0x0; /* 01c6: movi.n a2, 0 */
  MEM32(a3 + 0) = a2; /* 01c8: s32i.n a2, a3, 0 */
L_1ca:;
  a2 = 0x101; /* 01ca: movi a2, 0x101 */
L_1cd:;
  MEMW(); /* 01cd: memw  */
  return (int32_t)a2; /* 01d0: retw.n  */
}

/* pp_deattach @ pp.o 0000000c size 56B bind GLOBAL
 * Calls: esf_buf_recycle, esf_buf_setdown | Data refs: esf_buf_recycle, esf_buf_setdown, pTxRx
 *   MMIO: none
 *   funcdb v3: 2 call(s), 3 ref(s); disasm: 2 call(s), 3 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t pp_deattach(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pp_deattach; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_c:;
  /* 000c: entry a1, 32 */
  a3 = (uint32_t)&pTxRx; /* 000f: l32r a3, 0 <pp_deattach-0xc> (0 <pp_deattach-0xc>) */ /* literal @0x0: pTxRx */
  a2 = 0x0; /* 0012: movi a2, 0 */
L_15:;
  a8 = 0xC8; /* 0015: movi a8, 200 */
  a8 = 0xC8; /* 0018: add.n a8, a2, a8 */
  a4 = 0x320; /* 001a: slli a4, a8, 2 */
  a9 = MEM32(a3 + 0); /* 001d: l32i.n a9, a3, 0 */
  a8 = (a8 << 4) + a9; /* 001f: addx4 a8, a8, a9 */
  a10 = MEM32(a8 + 0); /* 0022: l32i.n a10, a8, 0 */
  if (a10 == 0) goto L_34; /* 0024: beqz.n a10, 34 <pp_deattach+0x28> */
  a8 = (uint32_t)&esf_buf_recycle; /* 0026: l32r a8, 4 <pp_deattach-0x8> (0 <pp_deattach-0xc>) */ /* literal: GOT slot for esf_buf_recycle */
  esf_buf_recycle(a2, a3, a4, a5); /* call via literal slot */ /* 0029: callx8 a8 */
  a9 = 0x0; /* 002c: movi.n a9, 0 */
  a8 = MEM32(a3 + 0); /* 002e: l32i.n a8, a3, 0 */
  a8 = a8 + a4; /* 0030: add.n a8, a8, a4 */
  MEM32(a8 + 0) = a9; /* 0032: s32i.n a9, a8, 0 */
L_34:;
  a2 = a2 + (1); /* 0034: addi.n a2, a2, 1 */
  if (a2 != 4) goto L_15; /* 0036: bnei a2, 4, 15 <pp_deattach+0x9> */
  MEMW(); /* 0039: memw  */
  a8 = (uint32_t)&esf_buf_setdown; /* 003c: l32r a8, 8 <pp_deattach-0x4> (0 <pp_deattach-0xc>) */ /* literal: GOT slot for esf_buf_setdown */
  esf_buf_setdown(a2, a3, a4, a5); /* call via literal slot */ /* 003f: callx8 a8 */
  return (int32_t)a2; /* 0042: retw.n  */
}

/* ppGetTxframe @ pp.o 0000000c size 138B bind GLOBAL
 * Calls: GetAccess[got], lmacAdjustTimestamp[got] | Data refs: pTxRx, GetAccess, lmacAdjustTimestamp
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 2 call(s), 3 data ref(s)
 * Fidelity: medium - 56 instr, 12 branches, calls resolved */
int32_t ppGetTxframe(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .wifiextrairam.60; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_c:;
  /* 000c: entry a1, 32 */
  a4 = (uint32_t)&pTxRx; /* 000f: l32r a4, 0 <ppGetTxframe-0xc> (0 <ppGetTxframe-0xc>) */ /* literal @0x0: pTxRx */
  a3 = (a2 >> 0) & 0xFF; /* 0012: extui a3, a2, 0, 8 */
  a9 = (a3 << 2) + a3; /* 0015: addx2 a9, a3, a3 */
  a9 = a9 << (4 & 31); /* 0018: slli a9, a9, 4 */
  a2 = a3 + a3; /* 001b: add.n a2, a3, a3 */
  a8 = MEM32(a4 + 0); /* 001d: l32i.n a8, a4, 0 */
  a10 = 0x4; /* 001f: movi.n a10, 4 */
  a8 = a8 + a9; /* 0021: add.n a8, a8, a9 */
  a8 = MEM8(a8 + 44); /* 0023: l8ui a8, a8, 44 */
  if (a8 >= 8) goto L_40; /* 0026: bgeui a8, 8, 40 <ppGetTxframe+0x34> */
  if (a8 == 0) goto L_3e; /* 0029: beqz.n a8, 3e <ppGetTxframe+0x32> */
  if (a8 == 3) goto L_3e; /* 002b: beqi a8, 3, 3e <ppGetTxframe+0x32> */
  a10 = 0x3; /* 002e: movi.n a10, 3 */
  if (a8 < a10) goto L_40; /* 0030: bltu a8, a10, 40 <ppGetTxframe+0x34> */
  a10 = 0x1; /* 0033: movi.n a10, 1 */
  if (a8 < 6) goto L_40; /* 0035: bltui a8, 6, 40 <ppGetTxframe+0x34> */
  a10 = 0x0; /* 0038: movi.n a10, 0 */
  goto L_40; /* 003a: j 40 <ppGetTxframe+0x34> */
  /* 003d: .byte 00 */
L_3e:;
  a10 = 0x2; /* 003e: movi.n a10, 2 */
L_40:;
  a8 = (uint32_t)&GetAccess; /* 0040: l32r a8, 4 <ppGetTxframe-0x8> (0 <ppGetTxframe-0xc>) */ /* literal: GOT slot for GetAccess */
  GetAccess(a2, a3, a4, a5); /* call via literal slot */ /* 0043: callx8 a8 */
  a9 = MEM32(a4 + 0); /* 0046: l32i.n a9, a4, 0 */
  a8 = a2 + a3; /* 0048: add.n a8, a2, a3 */
  a8 = a8 << (4 & 31); /* 004a: slli a8, a8, 4 */
  a8 = a9 + a8; /* 004d: add.n a8, a9, a8 */
  a2 = 0x0; /* 004f: movi.n a2, 0 */
  a4 = MEM8(a8 + 41); /* 0051: l8ui a4, a8, 41 */
  if (a4 != a2) goto L_94; /* 0054: bne a4, a2, 94 <ppGetTxframe+0x88> */
  a2 = a3 + (1); /* 0057: addi.n a2, a3, 1 */
  a2 = (a2 << 2) + a2; /* 0059: addx2 a2, a2, a2 */
  a2 = a2 << (4 & 31); /* 005c: slli a2, a2, 4 */
  a2 = a9 + a2; /* 005f: add.n a2, a9, a2 */
  a2 = MEM32(a2 + 4); /* 0061: l32i.n a2, a2, 4 */
  if (a2 != 0) goto L_94; /* 0063: bnez.n a2, 94 <ppGetTxframe+0x88> */
  goto L_8f; /* 0065: j 8f <ppGetTxframe+0x83> */
  /* 0068: .byte 00 */
L_69:;
  a10 = MEM32(a2 + 40); /* 0069: l32i.n a10, a2, 40 */
  MEM32(a8 + 32) = a10; /* 006b: s32i.n a10, a8, 32 */
  if (a10 != 0) goto L_7d; /* 006d: bnez.n a10, 7d <ppGetTxframe+0x71> */
  a3 = (a3 << 2) + a3; /* 006f: addx2 a3, a3, a3 */
  a3 = a3 << (4 & 31); /* 0072: slli a3, a3, 4 */
  a3 = a3 + (32); /* 0075: addi a3, a3, 32 */
  a3 = a9 + a3; /* 0078: add.n a3, a9, a3 */
  MEM32(a8 + 36) = a3; /* 007a: s32i a3, a8, 36 */
L_7d:;
  a3 = 0x0; /* 007d: movi.n a3, 0 */
  a10 = a2; /* 007f: mov.n a10, a2 */
  MEM32(a2 + 40) = a3; /* 0081: s32i.n a3, a2, 40 */
  MEMW(); /* 0083: memw  */
  a8 = (uint32_t)&lmacAdjustTimestamp; /* 0086: l32r a8, 8 <ppGetTxframe-0x4> (0 <ppGetTxframe-0xc>) */ /* literal: GOT slot for lmacAdjustTimestamp */
  lmacAdjustTimestamp(a2, a3, a4, a5); /* call via literal slot */ /* 0089: callx8 a8 */
  goto L_94; /* 008c: j 94 <ppGetTxframe+0x88> */
L_8f:;
  a2 = MEM32(a8 + 32); /* 008f: l32i.n a2, a8, 32 */
  if (a2 != 0) goto L_69; /* 0091: bnez a2, 69 <ppGetTxframe+0x5d> */
L_94:;
  return (int32_t)a2; /* 0094: retw.n  */
}

/* ppInitTxq @ pp.o 00000008 size 86B bind GLOBAL
 * Calls: none | Data refs: pTxRx
 *   MMIO: none
 *   funcdb v3: 0 call(s), 1 ref(s); disasm: 0 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t ppInitTxq(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.ppInitTxq; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_8:;
  /* 0008: entry a1, 32 */
  a8 = (uint32_t)&pTxRx; /* 000b: l32r a8, 0 <ppInitTxq-0x8> (0 <ppInitTxq-0x8>) */ /* literal @0x0: pTxRx */
  a9 = 0x0; /* 000e: movi.n a9, 0 */
  a11 = 0x10; /* 0010: movi.n a11, 16 */
  a8 = MEM32(a8 + 0); /* 0012: l32i.n a8, a8, 0 */
  a10 = a8 + (32); /* 0014: addi a10, a8, 32 */
  /* 0017: loop a11, 27 <ppInitTxq+0x1f> */ /* loop a11 times, end L_27; body shown single-pass */
  MEM32(a10 + 0) = a9; /* 001a: s32i.n a9, a10, 0 */
  MEM32(a10 + 4) = a10; /* 001c: s32i.n a10, a10, 4 */
  MEM8(a10 + 16) = a9; /* 001e: s8i a9, a10, 16 */
  MEMW(); /* 0021: memw  */
  a10 = a10 + (48); /* 0024: addi a10, a10, 48 */
L_27:;
  a10 = 0x1; /* 0027: movi.n a10, 1 */
  MEM32(a8 + 0) = a9; /* 0029: s32i.n a9, a8, 0 */
  a11 = 0x7; /* 002b: movi.n a11, 7 */
  MEM32(a8 + 4) = a9; /* 002d: s32i.n a9, a8, 4 */
  MEM32(a8 + 8) = a9; /* 002f: s32i.n a9, a8, 8 */
  MEM32(a8 + 12) = a9; /* 0031: s32i.n a9, a8, 12 */
  MEM32(a8 + 16) = a9; /* 0033: s32i.n a9, a8, 16 */
  MEM32(a8 + 20) = a9; /* 0035: s32i.n a9, a8, 20 */
  a9 = 0xD0A0704; /* 0037: l32r a9, 4 <ppInitTxq-0x4> (d0a0704 <ppRxFragmentProc+0xd0a0684>) */ @0x4
  MEM8(a8 + 48) = a10; /* 003a: s8i a10, a8, 48 */
  MEM8(a8 + 96) = a10; /* 003d: s8i a10, a8, 96 */
  MEM8(a8 + 144) = a10; /* 0040: s8i a10, a8, 144 */
  MEM8(a8 + 192) = a10; /* 0043: s8i a10, a8, 192 */
  a10 = 0x8; /* 0046: movi.n a10, 8 */
  MEM8(a8 + 44) = a11; /* 0048: s8i a11, a8, 44 */
  MEM8(a8 + 92) = a11; /* 004b: s8i a11, a8, 92 */
  MEM8(a8 + 140) = a11; /* 004e: s8i a11, a8, 140 */
  MEM8(a8 + 188) = a10; /* 0051: s8i a10, a8, 188 */
  MEMW(); /* 0054: memw  */
  MEM32(a8 + 24) = a9; /* 0057: s32i.n a9, a8, 24 */
  MEMW(); /* 0059: memw  */
  return (int32_t)a2; /* 005c: retw.n  */
}

/* ppEnableQueue @ pp.o 00000004 size 79B bind GLOBAL
 * Calls: none | Data refs: pTxRx
 *   MMIO: none
 *   funcdb v3: 0 call(s), 1 ref(s); disasm: 0 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t ppEnableQueue(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.ppEnableQueue; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a8 = (uint32_t)&pTxRx; /* 0007: l32r a8, 0 <ppEnableQueue-0x4> (0 <ppEnableQueue-0x4>) */ /* literal @0x0: pTxRx */
  a2 = (a2 >> 0) & 0xFF; /* 000a: extui a2, a2, 0, 8 */
  a10 = 0x0; /* 000d: movi.n a10, 0 */
  a6 = (a6 >> 0) & 0xFF; /* 000f: extui a6, a6, 0, 8 */
  a9 = MEM32(a8 + 0); /* 0012: l32i.n a9, a8, 0 */
  a8 = (a2 << 2) + a2; /* 0014: addx2 a8, a2, a2 */
  a8 = a8 << (4 & 31); /* 0017: slli a8, a8, 4 */
  a8 = a9 + a8; /* 001a: add.n a8, a9, a8 */
  a6 = (a6 << 4) + a9; /* 001c: addx4 a6, a6, a9 */
  MEM8(a8 + 44) = a5; /* 001f: s8i a5, a8, 44 */
  MEM8(a8 + 45) = a4; /* 0022: s8i a4, a8, 45 */
  MEM8(a8 + 46) = a3; /* 0025: s8i a3, a8, 46 */
  a8 = a2 + (1); /* 0028: addi.n a8, a2, 1 */
  a8 = (a8 << 2) + a8; /* 002a: addx2 a8, a8, a8 */
  a8 = a8 << (4 & 31); /* 002d: slli a8, a8, 4 */
  a8 = a9 + a8; /* 0030: add.n a8, a9, a8 */
  MEM8(a8 + 1) = a10; /* 0032: s8i a10, a8, 1 */
  MEMW(); /* 0035: memw  */
  a8 = 0x1; /* 0038: movi.n a8, 1 */
  /* 003a: ssl a2 */ /* UNMODELED: a2 clobbered */
  /* 003d: sll a8, a8 */ /* UNMODELED: a8 clobbered */
  a2 = MEM32(a6 + 4); /* 0040: l32i.n a2, a6, 4 */
  a2 = a2 | a8; /* 0042: or a2, a2, a8 */
  MEM32(a6 + 4) = a2; /* 0045: s32i.n a2, a6, 4 */
  a2 = MEM32(a9 + 0); /* 0047: l32i.n a2, a9, 0 */
  a2 = a2 | a8; /* 0049: or a2, a2, a8 */
  MEM32(a9 + 0) = a2; /* 004c: s32i.n a2, a9, 0 */
  MEMW(); /* 004e: memw  */
  return (int32_t)a2; /* 0051: retw.n  */
}

/* ppSearchTxQueue @ pp.o 0000000c size 246B bind GLOBAL
 * Calls: ppEnableQueue[got] | Data refs: pTxRx, ppEnableQueue
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 1 call(s), 2 data ref(s)
 * Fidelity: medium - 92 instr, 14 branches, calls resolved */
int32_t ppSearchTxQueue(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .wifi0iram.63; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_c:;
  /* 000c: entry a1, 32 */
  a11 = (a2 >> 0) & 0xFF; /* 000f: extui a11, a2, 0, 8 */
  a2 = (uint32_t)&pTxRx; /* 0012: l32r a2, 0 <ppSearchTxQueue-0xc> (0 <ppSearchTxQueue-0xc>) */ /* literal @0x0: pTxRx */
  a14 = (a5 >> 0) & 0xFF; /* 0015: extui a14, a5, 0, 8 */
  a13 = (a4 >> 0) & 0xFF; /* 0018: extui a13, a4, 0, 8 */
  a12 = (a3 >> 0) & 0xFF; /* 001b: extui a12, a3, 0, 8 */
  a15 = 0x1; /* 001e: movi.n a15, 1 */
  a8 = MEM32(a2 + 0); /* 0020: l32i.n a8, a2, 0 */
  a10 = 0xFFFFFFFF; /* 0022: movi.n a10, -1 */
  a2 = (a14 << 4) + a8; /* 0024: addx4 a2, a14, a8 */
  a4 = MEM32(a2 + 4); /* 0027: l32i.n a4, a2, 4 */
  a9 = MEM32(a8 + 0); /* 0029: l32i.n a9, a8, 0 */
  if (a4 != 0) goto L_38; /* 002b: bnez.n a4, 38 <ppSearchTxQueue+0x2c> */
  a2 = a8 + a14; /* 002d: add.n a2, a8, a14 */
  a2 = MEM8(a2 + 24); /* 002f: l8ui a2, a2, 24 */
  if ((a9 >> (a2 & 31)) & 1) goto L_76; /* 0032: bbs a9, a2, 76 <ppSearchTxQueue+0x6a> */
  goto L_f8; /* 0035: j f8 <ppSearchTxQueue+0xec> */
L_38:;
  a2 = -a4; /* 0038: neg a2, a4 */
  a2 = a2 & a4; /* 003b: and a2, a2, a4 */
  a2 = __builtin_clz(a2) /* approx for nsau */; /* 003e: nsau a2, a2 */
  a2 = -a2; /* 0041: neg a2, a2 */
  a2 = a2 + (31); /* 0044: addi a2, a2, 31 */
  a3 = (a2 << 2) + a2; /* 0047: addx2 a3, a2, a2 */
  a3 = a3 << (4 & 31); /* 004a: slli a3, a3, 4 */
  a3 = a8 + a3; /* 004d: add.n a3, a8, a3 */
  a5 = MEM8(a3 + 44); /* 004f: l8ui a5, a3, 44 */
  if (a5 != a13) goto L_67; /* 0052: bne a5, a13, 67 <ppSearchTxQueue+0x5b> */
  a5 = MEM8(a3 + 45); /* 0055: l8ui a5, a3, 45 */
  if (a5 != a12) goto L_67; /* 0058: bne a5, a12, 67 <ppSearchTxQueue+0x5b> */
  a3 = MEM8(a3 + 46); /* 005b: l8ui a3, a3, 46 */
  if (a3 != a11) goto L_67; /* 005e: bne a3, a11, 67 <ppSearchTxQueue+0x5b> */
  a2 = (a2 >> 0) & 0xFF; /* 0061: extui a2, a2, 0, 8 */
  goto L_100; /* 0064: j 100 <ppSearchTxQueue+0xf4> */
L_67:;
  /* 0067: ssl a2 */ /* UNMODELED: a2 clobbered */
  /* 006a: sll a2, a15 */ /* UNMODELED: a2 clobbered */
  a2 = a10 ^ a2; /* 006d: xor a2, a10, a2 */
  a4 = a4 & a2; /* 0070: and a4, a4, a2 */
  if (a4 != 0) goto L_38; /* 0073: bnez a4, 38 <ppSearchTxQueue+0x2c> */
L_76:;
  a8 = a8 + a14; /* 0076: add.n a8, a8, a14 */
  a15 = MEM8(a8 + 24); /* 0078: l8ui a15, a8, 24 */
  a10 = 0xF; /* 007b: movi.n a10, 15 */
  a8 = 0xFFFFFFFF; /* 007d: movi.n a8, -1 */
  a10 = a9 | a10; /* 007f: or a10, a9, a10 */
  /* 0082: ssl a15 */ /* UNMODELED: a15 clobbered */
  /* 0085: sll a15, a8 */ /* UNMODELED: a15 clobbered */
  a4 = 0xFFFF; /* 0088: l32r a4, 4 <ppSearchTxQueue-0x8> (ffff <ppRxFragmentProc+0xff7f>) */ @0x4
  a8 = a8 ^ a15; /* 008b: xor a8, a8, a15 */
  a3 = a10 ^ a4; /* 008e: xor a3, a10, a4 */
  a8 = a8 & a3; /* 0091: and a8, a8, a3 */
  a2 = 0x10; /* 0094: movi.n a2, 16 */
  if (a10 == a4) goto L_100; /* 0096: beq a10, a4, 100 <ppSearchTxQueue+0xf4> */
  a10 = 0x1F; /* 0099: movi.n a10, 31 */
  if (a8 == 0) goto L_a8; /* 009b: beqz.n a8, a8 <ppSearchTxQueue+0x9c> */
  a8 = __builtin_clz(a8) /* approx for nsau */; /* 009d: nsau a8, a8 */
  a10 = a10 - a8; /* 00a0: sub a10, a10, a8 */
  goto L_b1; /* 00a3: j b1 <ppSearchTxQueue+0xa5> */
  /* 00a6: .byte 00 */
  /* 00a7: .byte 00 */
L_a8:;
  a15 = a15 & a3; /* 00a8: and a15, a15, a3 */
  a15 = __builtin_clz(a15) /* approx for nsau */; /* 00ab: nsau a15, a15 */
  a10 = a10 - a15; /* 00ae: sub a10, a10, a15 */
L_b1:;
  a2 = 0xFFFFFFFF; /* 00b1: movi.n a2, -1 */
  /* 00b3: ssl a10 */ /* UNMODELED: a10 clobbered */
  /* 00b6: sll a4, a2 */ /* UNMODELED: a4 clobbered */
  a2 = a2 ^ a4; /* 00b9: xor a2, a2, a4 */
  a2 = a2 & a9; /* 00bc: and a2, a2, a9 */
  a3 = 0x1F; /* 00bf: movi.n a3, 31 */
  if (a2 == 0) goto L_d8; /* 00c1: beqz.n a2, d8 <ppSearchTxQueue+0xcc> */
  a2 = __builtin_clz(a2) /* approx for nsau */; /* 00c3: nsau a2, a2 */
  a3 = a3 - a2; /* 00c6: sub a3, a3, a2 */
  a10 = a10 + (1); /* 00c9: addi.n a10, a10, 1 */
  a10 = a10 + a3; /* 00cb: add.n a10, a10, a3 */
  a2 = (a10 >> 1) & 0xFF; /* 00cd: extui a2, a10, 1, 8 */
  a10 = (int32_t)a10 >> (1 & 31); /* 00d0: srai a10, a10, 1 */
  goto L_fa; /* 00d3: j fa <ppSearchTxQueue+0xee> */
  /* 00d6: .byte 00 */
  /* 00d7: .byte 00 */
L_d8:;
  a4 = a4 & a9; /* 00d8: and a4, a4, a9 */
  a4 = __builtin_clz(a4) /* approx for nsau */; /* 00db: nsau a4, a4 */
  a10 = a10 + (12); /* 00de: addi.n a10, a10, 12 */
  a3 = a3 - a4; /* 00e0: sub a3, a3, a4 */
  a8 = a10 + a3; /* 00e3: add a8, a10, a3 */
  a10 = a8 + (1); /* 00e6: addi a10, a8, 1 */
  a2 = 0x1E; /* 00e9: movi a2, 30 */
  a10 = (int32_t)a10 >> (1 & 31); /* 00ec: srai a10, a10, 1 */
  if (a2 >= a8) goto L_f5; /* 00ef: bge a2, a8, f5 <ppSearchTxQueue+0xe9> */
  a10 = a10 + (-12); /* 00f2: addi a10, a10, -12 */
L_f5:;
  a2 = (a10 >> 0) & 0xFF; /* 00f5: extui a2, a10, 0, 8 */
L_f8:;
  a10 = a2; /* 00f8: mov.n a10, a2 */
L_fa:;
  a8 = (uint32_t)&ppEnableQueue; /* 00fa: l32r a8, 8 <ppSearchTxQueue-0x4> (0 <ppSearchTxQueue-0xc>) */ /* literal: GOT slot for ppEnableQueue */
  ppEnableQueue(a2, a3, a4, a5); /* call via literal slot */ /* 00fd: callx8 a8 */
L_100:;
  return (int32_t)a2; /* 0100: retw.n  */
}

/* ppTxqEmpty @ pp.o 00000008 size 76B bind GLOBAL
 * Calls: is_lmac_idle | Data refs: is_lmac_idle, pTxRx
 *   MMIO: none
 *   funcdb v3: 1 call(s), 2 ref(s); disasm: 1 call(s), 2 data ref(s)
 * Fidelity: medium - 31 instr, 11 branches, calls resolved */
int32_t ppTxqEmpty(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.ppTxqEmpty; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_8:;
  /* 0008: entry a1, 32 */
  a8 = (uint32_t)&is_lmac_idle; /* 000b: l32r a8, 4 <ppTxqEmpty-0x4> (0 <ppTxqEmpty-0x8>) */ /* literal: GOT slot for is_lmac_idle */
  is_lmac_idle(a2, a3, a4, a5); /* call via literal slot */ /* 000e: callx8 a8 */
  if (a10 == 0) goto L_50; /* 0011: beqz.n a10, 50 <ppTxqEmpty+0x48> */
  a8 = (uint32_t)&pTxRx; /* 0013: l32r a8, 0 <ppTxqEmpty-0x8> (0 <ppTxqEmpty-0x8>) */ /* literal @0x0: pTxRx */
  a9 = MEM32(a8 + 0); /* 0016: l32i.n a9, a8, 0 */
  a11 = MEM32(a9 + 820); /* 0018: l32i a11, a9, 0x334 */
  if (a11 != 0) goto L_48; /* 001b: bnez.n a11, 48 <ppTxqEmpty+0x40> */
  a8 = MEM32(a9 + 828); /* 001d: l32i a8, a9, 0x33c */
  if (a8 != 0) goto L_48; /* 0020: bnez.n a8, 48 <ppTxqEmpty+0x40> */
  a11 = MEM32(a9 + 836); /* 0022: l32i a11, a9, 0x344 */
  if (a11 != 0) goto L_48; /* 0025: bnez.n a11, 48 <ppTxqEmpty+0x40> */
  a8 = a9 + (32); /* 0027: addi a8, a9, 32 */
  a11 = 0x10; /* 002a: movi a11, 16 */
  /* 002d: loop a11, 45 <ppTxqEmpty+0x3d> */ /* loop a11 times, end L_45; body shown single-pass */
  a12 = MEM8(a8 + 9); /* 0030: l8ui a12, a8, 9 */
  if (a12 != 0) goto L_39; /* 0033: bnez.n a12, 39 <ppTxqEmpty+0x31> */
  a13 = MEM32(a8 + 20); /* 0035: l32i.n a13, a8, 20 */
  if (a13 != 0) goto L_4e; /* 0037: bnez.n a13, 4e <ppTxqEmpty+0x46> */
L_39:;
  a12 = MEM32(a8 + 0); /* 0039: l32i.n a12, a8, 0 */
  if (a12 != 0) goto L_48; /* 003b: bnez.n a12, 48 <ppTxqEmpty+0x40> */
  a13 = MEM32(a9 + 844); /* 003d: l32i a13, a9, 0x34c */
  if (a13 != 0) goto L_4e; /* 0040: bnez.n a13, 4e <ppTxqEmpty+0x46> */
  a8 = a8 + (48); /* 0042: addi a8, a8, 48 */
L_45:;
  goto L_50; /* 0045: j 50 <ppTxqEmpty+0x48> */
L_48:;
  a10 = 0x0; /* 0048: movi.n a10, 0 */
  goto L_50; /* 004a: j 50 <ppTxqEmpty+0x48> */
  /* 004d: .byte 00 */
L_4e:;
  a10 = a12; /* 004e: mov.n a10, a12 */
L_50:;
  a2 = a10; /* 0050: mov.n a2, a10 */
  return (int32_t)a2; /* 0052: retw.n  */
}

/* pp_post @ pp.o 0000001c size 322B bind GLOBAL
 * Calls: pp_sig_cnt[got], g_intr_lock_mux[got], xphyQueue[got], xphyQueue[got], pp_sig_cnt[got], g_intr_lock_mux[got], g_osi_funcs_p[got], g_intr_lock_mux[got], wifi_log[got] | Data refs: g_osi_funcs_p, g_intr_lock_mux, pp_sig_cnt, xphyQueue, pTxRx, .rodata_wlog_warning.68, wifi_log
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 9 call(s), 7 data ref(s)
 * Fidelity: medium - 133 instr, 15 branches, 3 indirect; flow + direct calls mapped, GOT-indirects enumerated (verified against section disasm) */
int32_t pp_post(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .iram1.67; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_1c:;
  /* 001c: entry a1, 48 */
  a6 = (uint32_t)&g_osi_funcs_p; /* 001f: l32r a6, 0 <pp_post-0x1c> (0 <pp_post-0x1c>) */ /* literal @0x0: g_osi_funcs_p */
  a5 = a2; /* 0022: mov.n a5, a2 */
  a9 = 0x11; /* 0024: movi.n a9, 17 */
  MEM32(a1 + 0) = a2; /* 0026: s32i.n a2, a1, 0 */
  a2 = MEM32(a6 + 0); /* 0028: l32i.n a2, a6, 0 */
  a8 = MEM32(a2 + 40); /* 002a: l32i.n a8, a2, 40 */
  a2 = (uint32_t)&g_intr_lock_mux; /* 002c: l32r a2, 4 <pp_post-0x18> (0 <pp_post-0x1c>) */ /* literal @0x4: g_intr_lock_mux */
  MEM32(a1 + 4) = a3; /* 002f: s32i.n a3, a1, 4 */
  a10 = MEM32(a2 + 0); /* 0031: l32i.n a10, a2, 0 */
  a4 = (uint32_t)&pp_sig_cnt; /* 0033: l32r a4, 8 <pp_post-0x14> (0 <pp_post-0x1c>) */ /* literal @0x8: pp_sig_cnt */
  if (a9 >= a5) goto L_a9; /* 0036: bgeu a9, a5, a9 <pp_post+0x8d> */
  a3 = 0x0; /* 0039: movi.n a3, 0 */
  a4 = a4 + a5; /* 003b: add.n a4, a4, a5 */
  MEM32(a1 + 8) = a3; /* 003d: s32i.n a3, a1, 8 */
  MEMW(); /* 003f: memw  */
  ((int32_t(*)())a8)(a2, a3, a4, a5); /* 0042: callx8 a8 */ /* indirect */
  a11 = a10; /* 0045: mov.n a11, a10 */
  MEMW(); /* 0047: memw  */
  a5 = MEM8(a4 + 0); /* 004a: l8ui a5, a4, 0 */
  a5 = (a5 >> 0) & 0xFF; /* 004d: extui a5, a5, 0, 8 */
  a8 = MEM32(a6 + 0); /* 0050: l32i.n a8, a6, 0 */
  if (a5 == a3) goto L_61; /* 0052: beq a5, a3, 61 <pp_post+0x45> */
  a4 = MEM32(a8 + 44); /* 0055: l32i.n a4, a8, 44 */
  a10 = MEM32(a2 + 0); /* 0057: l32i.n a10, a2, 0 */
  ((int32_t(*)())a4)(a2, a3, a4, a5); /* 0059: callx8 a4 */ /* indirect */
  goto L_11b; /* 005c: j 11b <pp_post+0xff> */
  /* 005f: .byte 00 */
  /* 0060: .byte 00 */
L_61:;
  MEMW(); /* 0061: memw  */
  a3 = MEM8(a4 + 0); /* 0064: l8ui a3, a4, 0 */
  a3 = a3 + (1); /* 0067: addi.n a3, a3, 1 */
  a3 = (a3 >> 0) & 0xFF; /* 0069: extui a3, a3, 0, 8 */
  a10 = MEM32(a2 + 0); /* 006c: l32i.n a10, a2, 0 */
  MEMW(); /* 006e: memw  */
  MEM8(a4 + 0) = a3; /* 0071: s8i a3, a4, 0 */
  a3 = MEM32(a8 + 44); /* 0074: l32i.n a3, a8, 44 */
  MEMW(); /* 0076: memw  */
  ((int32_t(*)())a3)(a2, a3, a4, a5); /* 0079: callx8 a3 */ /* indirect */
  a12 = a1 + (8); /* 007c: addi.n a12, a1, 8 */
  a11 = a1; /* 007e: mov.n a11, a1 */
  a3 = (uint32_t)&xphyQueue; /* 0080: l32r a3, c <pp_post-0x10> (0 <pp_post-0x1c>) */ /* literal @0xC: xphyQueue */
  a2 = MEM32(a6 + 0); /* 0083: l32i.n a2, a6, 0 */
  a10 = MEM32(a3 + 0); /* 0085: l32i.n a10, a3, 0 */
  a2 = MEM32(a2 + 104); /* 0087: l32i a2, a2, 104 */
  g_intr_lock_mux(a2, a3, a4, a5); /* call via literal slot */ /* 008a: callx8 a2 */
  a2 = a10; /* 008d: mov.n a2, a10 */
  a3 = MEM32(a1 + 8); /* 008f: l32i.n a3, a1, 8 */
  if (a3 == 0) goto L_9a; /* 0091: beqz.n a3, 9a <pp_post+0x7e> */
  a3 = MEM32(a6 + 0); /* 0093: l32i.n a3, a6, 0 */
  a3 = MEM32(a3 + 48); /* 0095: l32i.n a3, a3, 48 */
  xphyQueue(a2, a3, a4, a5); /* call via literal slot */ /* 0097: callx8 a3 */
L_9a:;
  a10 = a2 + (-1); /* 009a: addi.n a10, a2, -1 */
  a3 = 0x0; /* 009c: movi.n a3, 0 */
  a2 = 0x1; /* 009e: movi.n a2, 1 */
  if (a10 == 0) a2 = a3; /* 00a0: moveqz a2, a3, a10 */
  goto L_15c; /* 00a3: j 15c <pp_post+0x140> */
  /* 00a6: .byte 00 */
  /* 00a7: .byte 00 */
  /* 00a8: .byte 00 */
L_a9:;
  ((int32_t(*)())a8)(a2, a3, a4, a5); /* 00a9: callx8 a8 */ /* indirect */
  a8 = a4 + a5; /* 00ac: add.n a8, a4, a5 */
  MEMW(); /* 00ae: memw  */
  a8 = MEM8(a8 + 0); /* 00b1: l8ui a8, a8, 0 */
  a11 = a10; /* 00b4: mov.n a11, a10 */
  a8 = (a8 >> 0) & 0xFF; /* 00b6: extui a8, a8, 0, 8 */
  if (a8 == 0) goto L_d2; /* 00b9: beqz.n a8, d2 <pp_post+0xb6> */
  a8 = a5 + (-6); /* 00bb: addi a8, a5, -6 */
  if (a8 < 3) goto L_d2; /* 00be: bltui a8, 3, d2 <pp_post+0xb6> */
  a3 = MEM32(a6 + 0); /* 00c1: l32i.n a3, a6, 0 */
  a10 = MEM32(a2 + 0); /* 00c3: l32i a10, a2, 0 */
  a3 = MEM32(a3 + 44); /* 00c6: l32i a3, a3, 44 */
  xphyQueue(a2, a3, a4, a5); /* call via literal slot */ /* 00c9: callx8 a3 */
  goto L_11b; /* 00cc: j 11b <pp_post+0xff> */
  /* 00cf: .byte 00 */
  /* 00d0: .byte 00 */
  /* 00d1: .byte 00 */
L_d2:;
  a8 = 0xD; /* 00d2: movi.n a8, 13 */
  if (a5 == a8) goto L_ea; /* 00d4: beq a5, a8, ea <pp_post+0xce> */
  a4 = a4 + a5; /* 00d7: add.n a4, a4, a5 */
  MEMW(); /* 00d9: memw  */
  a8 = MEM8(a4 + 0); /* 00dc: l8ui a8, a4, 0 */
  a8 = a8 + (1); /* 00df: addi.n a8, a8, 1 */
  a8 = (a8 >> 0) & 0xFF; /* 00e1: extui a8, a8, 0, 8 */
  MEMW(); /* 00e4: memw  */
  MEM8(a4 + 0) = a8; /* 00e7: s8i a8, a4, 0 */
L_ea:;
  a4 = MEM32(a6 + 0); /* 00ea: l32i.n a4, a6, 0 */
  a10 = MEM32(a2 + 0); /* 00ec: l32i.n a10, a2, 0 */
  a2 = 0xD; /* 00ee: movi.n a2, 13 */
  a4 = MEM32(a4 + 44); /* 00f0: l32i.n a4, a4, 44 */
  MEMW(); /* 00f2: memw  */
  ((int32_t(*)())a4)(a2, a3, a4, a5); /* 00f5: callx8 a4 */ /* indirect */
  a4 = (uint32_t)&xphyQueue; /* 00f8: l32r a4, c <pp_post-0x10> (0 <pp_post-0x1c>) */ /* literal @0xC: xphyQueue */
  if (a5 == a2) goto L_122; /* 00fb: beq a5, a2, 122 <pp_post+0x106> */
L_fe:;
  a10 = 0xA; /* 00fe: movi.n a10, 10 */
  a2 = MEM32(a6 + 0); /* 0100: l32i.n a2, a6, 0 */
  a6 = MEM32(a2 + 100); /* 0102: l32i a6, a2, 100 */
  a2 = MEM32(a2 + 160); /* 0105: l32i a2, a2, 160 */
  a4 = MEM32(a4 + 0); /* 0108: l32i.n a4, a4, 0 */
  ((int32_t(*)())a2)(a2, a3, a4, a5); /* 010a: callx8 a2 */ /* indirect */
  a12 = 0xA; /* 010d: mov.n a12, a10 */
  a11 = a1 | a1; /* 010f: or a11, a1, a1 */
  a10 = a4 | a4; /* 0112: or a10, a4, a4 */
  g_osi_funcs_p(a2, a3, a4, a5); /* call via literal slot */ /* 0115: callx8 a6 */
  if (a10 != 1) goto L_144; /* 0118: bnei a10, 1, 144 <pp_post+0x128> */
L_11b:;
  a2 = 0x0; /* 011b: movi.n a2, 0 */
  goto L_15c; /* 011d: j 15c <pp_post+0x140> */
  /* 0120: .byte 00 */
  /* 0121: .byte 00 */
L_122:;
  a2 = MEM32(a6 + 0); /* 0122: l32i.n a2, a6, 0 */
  a10 = MEM32(a4 + 0); /* 0124: l32i.n a10, a4, 0 */
  a2 = MEM32(a2 + 120); /* 0126: l32i a2, a2, 120 */
  ((int32_t(*)())a2)(a2, a3, a4, a5); /* 0129: callx8 a2 */ /* indirect */
  a8 = 0x95; /* 012c: movi a8, 149 */
  a2 = 0x1; /* 012f: movi.n a2, 1 */
  if (a8 < a10) goto L_15c; /* 0131: bltu a8, a10, 15c <pp_post+0x140> */
  a8 = (uint32_t)&pTxRx; /* 0134: l32r a8, 10 <pp_post-0xc> (0 <pp_post-0x1c>) */ /* literal @0x10: pTxRx */
  a9 = 0x30; /* 0137: movi.n a9, 48 */
  a8 = MEM32(a8 + 0); /* 0139: l32i.n a8, a8, 0 */
  a8 = MEM32(a8 + 960); /* 013b: l32i a8, a8, 0x3c0 */
  if (a9 >= a8) goto L_fe; /* 013e: bgeu a9, a8, fe <pp_post+0xe2> */
  goto L_15c; /* 0141: j 15c <pp_post+0x140> */
L_144:;
  a13 = (uint32_t)&lit_rodata_wlog_warning_68; /* 0144: l32r a13, 14 <pp_post-0x8> (0 <pp_post-0x1c>) */ /* literal @0x14: .rodata_wlog_warning.68 */
  a11 = 0x1; /* 0147: movi.n a11, 1 */
  a15 = a3; /* 0149: mov.n a15, a3 */
  a14 = a5; /* 014b: mov.n a14, a5 */
  a12 = 0x2; /* 014d: movi.n a12, 2 */
  a11 = 0x800; /* 014f: slli a11, a11, 11 */
  a10 = 0x6; /* 0152: movi.n a10, 6 */
  a8 = (uint32_t)&wifi_log; /* 0154: l32r a8, 18 <pp_post-0x4> (0 <pp_post-0x1c>) */ /* literal: GOT slot for wifi_log */
  wifi_log(a2, a3, a4, a5); /* call via literal slot */ /* 0157: callx8 a8 */
  a2 = 0x1; /* 015a: movi.n a2, 1 */
L_15c:;
  return (int32_t)a2; /* 015c: retw.n  */
}

/* pp_delete_task @ pp.o 0000001c size 122B bind GLOBAL
 * Calls: pp_post, s_wifi_queue[got], .text.pp_delete_task_manually[got], .text.pp_delete_task_manually[got], .text.pp_delete_task_manually[got], g_osi_funcs_p[got], .text.pp_delete_task_manually[got] | Data refs: .bss.pp_task_hdl, .bss.s_pp_task_del_sem, g_osi_funcs_p, pp_post, s_wifi_queue, .text.pp_delete_task_manually
 *   MMIO: none
 *   funcdb v3: 1 call(s), 5 ref(s); disasm: 7 call(s), 6 data ref(s)
 * Fidelity: medium - 51 instr, 7 branches, calls resolved */
int32_t pp_delete_task(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pp_delete_task; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_1c:;
  /* 001c: entry a1, 32 */
  a2 = (uint32_t)&bss_pp_task_hdl; /* 001f: l32r a2, 0 <pp_delete_task-0x1c> (0 <pp_delete_task-0x1c>) */ /* literal @0x0: .bss.pp_task_hdl */
  a2 = MEM32(a2 + 0); /* 0022: l32i.n a2, a2, 0 */
  if (a2 == 0) goto L_8c; /* 0024: beqz a2, 8c <pp_delete_task+0x70> */
  a2 = (uint32_t)&s_wifi_queue; /* 0027: l32r a2, 4 <pp_delete_task-0x18> (0 <pp_delete_task-0x1c>) */ /* literal @0x4: s_wifi_queue */
  a2 = MEM32(a2 + 0); /* 002a: l32i.n a2, a2, 0 */
  if (a2 == 0) goto L_8c; /* 002c: beqz a2, 8c <pp_delete_task+0x70> */
  a11 = 0x0; /* 002f: movi.n a11, 0 */
  a10 = 0x1; /* 0031: movi.n a10, 1 */
  a3 = (uint32_t)&g_osi_funcs_p; /* 0033: l32r a3, 8 <pp_delete_task-0x14> (0 <pp_delete_task-0x1c>) */ /* literal @0x8: g_osi_funcs_p */
  a2 = MEM32(a3 + 0); /* 0036: l32i.n a2, a3, 0 */
  a2 = MEM32(a2 + 52); /* 0038: l32i.n a2, a2, 52 */
  s_wifi_queue(a2, a3, a4, a5); /* call via literal slot */ /* 003a: callx8 a2 */
  a2 = (uint32_t)&bss_s_pp_task_del_sem; /* 003d: l32r a2, c <pp_delete_task-0x10> (0 <pp_delete_task-0x1c>) */ /* literal @0xC: .bss.s_pp_task_del_sem */
  MEM32(a2 + 0) = a10; /* 0040: s32i.n a10, a2, 0 */
  if (a10 != 0) goto L_4a; /* 0042: bnez.n a10, 4a <pp_delete_task+0x2e> */
  MEMW(); /* 0044: memw  */
  goto L_8c; /* 0047: j 8c <pp_delete_task+0x70> */
L_4a:;
  a11 = 0x0; /* 004a: movi.n a11, 0 */
  a10 = 0xF; /* 004c: movi.n a10, 15 */
  a8 = (uint32_t)&pp_post; /* 004e: l32r a8, 10 <pp_delete_task-0xc> (0 <pp_delete_task-0x1c>) */ /* literal: GOT slot for pp_post */
  pp_post(a2, a3, a4, a5); /* call via literal slot */ /* 0051: callx8 a8 */
  if (a10 == 0) goto L_61; /* 0054: beqz.n a10, 61 <pp_delete_task+0x45> */
  a8 = (uint32_t)&pp_delete_task_manually; /* 0056: l32r a8, 14 <pp_delete_task-0x8> (c <pp_delete_task-0x10>) */ /* literal: GOT slot for .text.pp_delete_task_manually */
  pp_delete_task_manually(a2, a3, a4, a5); /* call via literal slot */ /* 0059: callx8 a8 */
  goto L_6c; /* 005c: j 6c <pp_delete_task+0x50> */
  /* 005f: .byte 00 */
  /* 0060: .byte 00 */
L_61:;
  a8 = MEM32(a3 + 0); /* 0061: l32i.n a8, a3, 0 */
  a11 = 0xFFFFFFFF; /* 0063: movi.n a11, -1 */
  a8 = MEM32(a8 + 60); /* 0065: l32i.n a8, a8, 60 */
  a10 = MEM32(a2 + 0); /* 0067: l32i.n a10, a2, 0 */
  pp_delete_task_manually(a2, a3, a4, a5); /* call via literal slot */ /* 0069: callx8 a8 */
L_6c:;
  a10 = 0x1; /* 006c: movi.n a10, 1 */
  a8 = MEM32(a3 + 0); /* 006e: l32i.n a8, a3, 0 */
  a8 = MEM32(a8 + 156); /* 0070: l32i a8, a8, 156 */
  pp_delete_task_manually(a2, a3, a4, a5); /* call via literal slot */ /* 0073: callx8 a8 */
  a3 = MEM32(a3 + 0); /* 0076: l32i.n a3, a3, 0 */
  a10 = MEM32(a2 + 0); /* 0078: l32i.n a10, a2, 0 */
  a3 = MEM32(a3 + 56); /* 007a: l32i a3, a3, 56 */
  g_osi_funcs_p(a2, a3, a4, a5); /* call via literal slot */ /* 007d: callx8 a3 */
  a10 = 0x0; /* 0080: movi.n a10, 0 */
  MEM32(a2 + 0) = a10; /* 0082: s32i.n a10, a2, 0 */
  MEMW(); /* 0084: memw  */
  goto L_92; /* 0087: j 92 <pp_delete_task+0x76> */
  /* 008a: .byte 00 */
  /* 008b: .byte 00 */
L_8c:;
  a8 = (uint32_t)&pp_delete_task_manually; /* 008c: l32r a8, 18 <pp_delete_task-0x4> (c <pp_delete_task-0x10>) */ /* literal: GOT slot for .text.pp_delete_task_manually */
  pp_delete_task_manually(a2, a3, a4, a5); /* call via literal slot */ /* 008f: callx8 a8 */
L_92:;
  a2 = 0x0; /* 0092: mov.n a2, a10 */
  return (int32_t)a2; /* 0094: retw.n  */
}

/* ppMapWaitTxq @ pp.o 00000014 size 227B bind GLOBAL
 * Calls: ppSearchTxQueue[got], pp_post[got] | Data refs: pTxRx, ppSearchTxQueue, pp_post
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 2 call(s), 3 data ref(s)
 * Fidelity: medium - 88 instr, 10 branches, calls resolved */
int32_t ppMapWaitTxq(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .wifiextrairam.64; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_14:;
  /* 0014: entry a1, 48 */
  a5 = (a2 >> 0) & 0xFF; /* 0017: extui a5, a2, 0, 8 */
  a2 = (uint32_t)&pTxRx; /* 001a: l32r a2, 0 <ppMapWaitTxq-0x14> (0 <ppMapWaitTxq-0x14>) */ /* literal @0x0: pTxRx */
  a4 = 0xF; /* 001d: movi.n a4, 15 */
  a7 = MEM32(a2 + 0); /* 001f: l32i.n a7, a2, 0 */
  a2 = MEM32(a7 + 0); /* 0021: l32i.n a2, a7, 0 */
  a4 = a4 | a2; /* 0023: or a4, a4, a2 */
  a2 = 0x0; /* 0026: movi.n a2, 0 */
  a6 = 0xFFFF; /* 0028: l32r a6, 4 <ppMapWaitTxq-0x10> (ffff <ppRxFragmentProc+0xff7f>) */ @0x4
  if (a4 != a6) goto L_31; /* 002b: bne a4, a6, 31 <ppMapWaitTxq+0x1d> */
  goto L_f5; /* 002e: j f5 <ppMapWaitTxq+0xe1> */
L_31:;
  a6 = (a5 << 8) + a7; /* 0031: addx8 a6, a5, a7 */
  a4 = a5 << (3 & 31); /* 0034: slli a4, a5, 3 */
  a3 = MEM32(a6 + 820); /* 0037: l32i a3, a6, 0x334 */
  if (a3 != a2) goto L_40; /* 003a: bne a3, a2, 40 <ppMapWaitTxq+0x2c> */
  goto L_f5; /* 003d: j f5 <ppMapWaitTxq+0xe1> */
L_40:;
  a5 = a5 + (102); /* 0040: addi a5, a5, 102 */
  a5 = (a5 << 8) + a7; /* 0043: addx8 a5, a5, a7 */
  a5 = a5 + (4); /* 0046: addi.n a5, a5, 4 */
  MEM32(a6 + 824) = a5; /* 0048: s32i a5, a6, 0x338 */
  a5 = 0xC; /* 004b: movi a5, 12 */
  MEM32(a6 + 820) = a2; /* 004e: s32i a2, a6, 0x334 */
L_51:;
  a6 = a3; /* 0051: mov.n a6, a3 */
  a2 = MEM32(a6 + 4); /* 0053: l32i.n a2, a6, 4 */
  a7 = MEM32(a6 + 44); /* 0055: l32i.n a7, a6, 44 */
  a10 = MEM32(a2 + 4); /* 0057: l32i.n a10, a2, 4 */
  a2 = MEM32(a7 + 0); /* 0059: l32i.n a2, a7, 0 */
  a3 = MEM32(a3 + 40); /* 005b: l32i.n a3, a3, 40 */
  a11 = MEM32(a6 + 36); /* 005d: l32i.n a11, a6, 36 */
  if (!((a2 >> 18) & 1)) goto L_64; /* 005f: bbci a2, 18, 64 <ppMapWaitTxq+0x50> */
  a10 = a10 + (4); /* 0062: addi.n a10, a10, 4 */
L_64:;
  a9 = a6 + (40); /* 0064: addi a9, a6, 40 */
  a8 = (uint32_t)&pTxRx; /* 0067: l32r a8, 0 <ppMapWaitTxq-0x14> (0 <ppMapWaitTxq-0x14>) */ /* literal @0x0: pTxRx */
  a12 = MEM8(a10 + 0); /* 006a: l8ui a12, a10, 0 */
  a2 = MEM32(a8 + 0); /* 006d: l32i.n a2, a8, 0 */
  a10 = MEM32(a7 + 16); /* 006f: l32i.n a10, a7, 16 */
  if ((a12 & a5) != 0) goto L_7d; /* 0071: bany a12, a5, 7d <ppMapWaitTxq+0x69> */
  a10 = (a10 >> 20) & 0xF; /* 0074: extui a10, a10, 20, 4 */
  MEMW(); /* 0077: memw  */
  goto L_b0; /* 007a: j b0 <ppMapWaitTxq+0x9c> */
L_7d:;
  a12 = MEM32(a7 + 4); /* 007d: l32i.n a12, a7, 4 */
  a10 = (a10 >> 18) & 0x3; /* 007f: extui a10, a10, 18, 2 */
  a13 = (a12 >> 4) & 0xF; /* 0082: extui a13, a12, 4, 4 */
  a12 = (a12 >> 0) & 0xF; /* 0085: extui a12, a12, 0, 4 */
  a11 = MEM8(a11 + 128); /* 0088: l8ui a11, a11, 128 */
  MEM32(a1 + 0) = a9; /* 008b: s32i.n a9, a1, 0 */
  MEMW(); /* 008d: memw  */
  a8 = (uint32_t)&ppSearchTxQueue; /* 0090: l32r a8, c <ppMapWaitTxq-0x8> (0 <ppMapWaitTxq-0x14>) */ /* literal: GOT slot for ppSearchTxQueue */
  ppSearchTxQueue(a2, a3, a4, a5); /* call via literal slot */ /* 0093: callx8 a8 */
  a9 = MEM32(a1 + 0); /* 0096: l32i.n a9, a1, 0 */
  if (a10 != 16) goto L_b0; /* 0098: bnei a10, 16, b0 <ppMapWaitTxq+0x9c> */
  a7 = 0x0; /* 009b: movi.n a7, 0 */
  a2 = a2 + a4; /* 009d: add.n a2, a2, a4 */
  MEM32(a6 + 40) = a7; /* 009f: s32i.n a7, a6, 40 */
  a7 = MEM32(a2 + 824); /* 00a1: l32i a7, a2, 0x338 */
  MEM32(a7 + 0) = a6; /* 00a4: s32i.n a6, a7, 0 */
  MEM32(a2 + 824) = a9; /* 00a6: s32i a9, a2, 0x338 */
  MEMW(); /* 00a9: memw  */
  goto L_f0; /* 00ac: j f0 <ppMapWaitTxq+0xdc> */
  /* 00af: .byte 00 */
L_b0:;
  a11 = MEM32(a7 + 16); /* 00b0: l32i.n a11, a7, 16 */
  a12 = (a10 >> 0) & 0xF; /* 00b2: extui a12, a10, 0, 4 */
  a10 = a12 << (20 & 31); /* 00b5: slli a10, a12, 20 */
  a12 = (a12 << 2) + a12; /* 00b8: addx2 a12, a12, a12 */
  a12 = a12 << (4 & 31); /* 00bb: slli a12, a12, 4 */
  a13 = 0xFF0FFFFF; /* 00be: l32r a13, 8 <ppMapWaitTxq-0xc> (ff0fffff <ppRxFragmentProc+0xff0fff7f>) */ @0x8
  a12 = a2 + a12; /* 00c1: add.n a12, a2, a12 */
  a11 = a11 & a13; /* 00c3: and a11, a11, a13 */
  a10 = a11 | a10; /* 00c6: or a10, a11, a10 */
  a11 = 0x0; /* 00c9: movi.n a11, 0 */
  MEM32(a7 + 16) = a10; /* 00cb: s32i.n a10, a7, 16 */
  a10 = MEM32(a12 + 36); /* 00cd: l32i.n a10, a12, 36 */
  MEM32(a6 + 40) = a11; /* 00cf: s32i.n a11, a6, 40 */
  MEM32(a10 + 0) = a6; /* 00d1: s32i.n a6, a10, 0 */
  a6 = MEM32(a7 + 16); /* 00d3: l32i.n a6, a7, 16 */
  a6 = (a6 >> 20) & 0xF; /* 00d5: extui a6, a6, 20, 4 */
  a6 = (a6 << 2) + a6; /* 00d8: addx2 a6, a6, a6 */
  a6 = a6 << (4 & 31); /* 00db: slli a6, a6, 4 */
  a10 = MEM32(a7 + 4); /* 00de: l32i.n a10, a7, 4 */
  a2 = a2 + a6; /* 00e0: add.n a2, a2, a6 */
  a10 = (a10 >> 4) & 0xF; /* 00e2: extui a10, a10, 4, 4 */
  MEM32(a2 + 36) = a9; /* 00e5: s32i.n a9, a2, 36 */
  MEMW(); /* 00e7: memw  */
  a8 = (uint32_t)&pp_post; /* 00ea: l32r a8, 10 <ppMapWaitTxq-0x4> (0 <ppMapWaitTxq-0x14>) */ /* literal: GOT slot for pp_post */
  pp_post(a2, a3, a4, a5); /* call via literal slot */ /* 00ed: callx8 a8 */
L_f0:;
  if (a3 != 0) goto L_51; /* 00f0: bnez a3, 51 <ppMapWaitTxq+0x3d> */
  a2 = 0x1; /* 00f3: movi.n a2, 1 */
L_f5:;
  return (int32_t)a2; /* 00f5: retw.n  */
}

/* ppProcessWaitingQueue @ pp.o 0000000c size 89B bind GLOBAL
 * Calls: pm_allow_tx[got], ppMapWaitTxq[got] | Data refs: .bss.current_ifidx$0, pm_allow_tx, ppMapWaitTxq
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 2 call(s), 3 data ref(s)
 * Fidelity: medium - 33 instr, 6 branches, calls resolved */
int32_t ppProcessWaitingQueue(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .wifiextrairam.65; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_c:;
  /* 000c: entry a1, 32 */
  a4 = (uint32_t)&bss_current_ifidx_0; /* 000f: l32r a4, 0 <ppProcessWaitingQueue-0xc> (0 <ppProcessWaitingQueue-0xc>) */ /* literal @0x0: .bss.current_ifidx$0 */
  a3 = 0xFFFFFFFF; /* 0012: movi.n a3, -1 */
  a5 = 0x0; /* 0014: movi a5, 0 */
  a2 = MEM8(a4 + 0); /* 0017: l8ui a2, a4, 0 */
L_1a:;
  a10 = a2; /* 001a: mov.n a10, a2 */
  a8 = (uint32_t)&pm_allow_tx; /* 001c: l32r a8, 4 <ppProcessWaitingQueue-0x8> (0 <ppProcessWaitingQueue-0xc>) */ /* literal: GOT slot for pm_allow_tx */
  pm_allow_tx(a2, a3, a4, a5); /* call via literal slot */ /* 001f: callx8 a8 */
  if (a10 == 0) goto L_30; /* 0022: beqz.n a10, 30 <ppProcessWaitingQueue+0x24> */
  a10 = a2 | a2; /* 0024: or a10, a2, a2 */
  a8 = (uint32_t)&ppMapWaitTxq; /* 0027: l32r a8, 8 <ppProcessWaitingQueue-0x4> (0 <ppProcessWaitingQueue-0xc>) */ /* literal: GOT slot for ppMapWaitTxq */
  ppMapWaitTxq(a2, a3, a4, a5); /* call via literal slot */ /* 002a: callx8 a8 */
  if (a10 != 0) a3 = a2; /* 002d: movnez a3, a2, a10 */
L_30:;
  a2 = a2 + (1); /* 0030: addi.n a2, a2, 1 */
  a2 = (a2 >> 0) & 0xFF; /* 0032: extui a2, a2, 0, 8 */
  if (a2 != 3) goto L_3a; /* 0035: bnei a2, 3, 3a <ppProcessWaitingQueue+0x2e> */
  a2 = a5; /* 0038: mov.n a2, a5 */
L_3a:;
  a8 = MEM8(a4 + 0); /* 003a: l8ui a8, a4, 0 */
  if (a8 != a2) goto L_1a; /* 003d: bne a8, a2, 1a <ppProcessWaitingQueue+0xe> */
  if (a3 == -1) goto L_60; /* 0040: beqi a3, -1, 60 <ppProcessWaitingQueue+0x54> */
  a3 = a3 + (1); /* 0043: addi.n a3, a3, 1 */
  a3 = (a3 >> 0) & 0xFF; /* 0045: extui a3, a3, 0, 8 */
  if (a3 == 3) goto L_58; /* 0048: beqi a3, 3, 58 <ppProcessWaitingQueue+0x4c> */
  MEM8(a4 + 0) = a3; /* 004b: s8i a3, a4, 0 */
  MEMW(); /* 004e: memw  */
  MEMW(); /* 0051: memw  */
  goto L_60; /* 0054: j 60 <ppProcessWaitingQueue+0x54> */
  /* 0057: .byte 00 */
L_58:;
  a2 = 0x0; /* 0058: movi.n a2, 0 */
  MEM8(a4 + 0) = a2; /* 005a: s8i a2, a4, 0 */
  MEMW(); /* 005d: memw  */
L_60:;
  MEMW(); /* 0060: memw  */
  return (int32_t)a2; /* 0063: retw.n  */
}

/* ppProcessWaitQ @ pp.o 00000004 size 11B bind GLOBAL
 * Calls: ppProcessWaitingQueue | Data refs: ppProcessWaitingQueue
 *   MMIO: none
 *   funcdb v3: 1 call(s), 1 ref(s); disasm: 1 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t ppProcessWaitQ(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.ppProcessWaitQ; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a8 = (uint32_t)&ppProcessWaitingQueue; /* 0007: l32r a8, 0 <ppProcessWaitQ-0x4> (0 <ppProcessWaitQ-0x4>) */ /* literal: GOT slot for ppProcessWaitingQueue */
  ppProcessWaitingQueue(a2, a3, a4, a5); /* call via literal slot */ /* 000a: callx8 a8 */
  return (int32_t)a2; /* 000d: retw.n  */
}

/* ppDisableQueue @ pp.o 00000008 size 47B bind GLOBAL
 * Calls: ppProcessWaitingQueue | Data refs: pTxRx, ppProcessWaitingQueue
 *   MMIO: none
 *   funcdb v3: 1 call(s), 2 ref(s); disasm: 1 call(s), 2 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t ppDisableQueue(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.ppDisableQueue; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_8:;
  /* 0008: entry a1, 32 */
  a8 = (uint32_t)&pTxRx; /* 000b: l32r a8, 0 <ppDisableQueue-0x8> (0 <ppDisableQueue-0x8>) */ /* literal @0x0: pTxRx */
  a3 = (a3 >> 0) & 0xFF; /* 000e: extui a3, a3, 0, 8 */
  a9 = MEM32(a8 + 0); /* 0011: l32i.n a9, a8, 0 */
  a8 = 0xFFFFFFFE; /* 0013: movi.n a8, -2 */
  a3 = (a3 << 4) + a9; /* 0015: addx4 a3, a3, a9 */
  /* 0018: ssl a2 */ /* UNMODELED: a2 clobbered */
  /* 001b: src a2, a8, a8 */ /* UNMODELED: a2 clobbered */
  a8 = MEM32(a3 + 4); /* 001e: l32i.n a8, a3, 4 */
  a8 = a8 & a2; /* 0020: and a8, a8, a2 */
  MEM32(a3 + 4) = a8; /* 0023: s32i.n a8, a3, 4 */
  a3 = MEM32(a9 + 0); /* 0025: l32i.n a3, a9, 0 */
  a3 = a3 & a2; /* 0027: and a3, a3, a2 */
  MEM32(a9 + 0) = a3; /* 002a: s32i.n a3, a9, 0 */
  MEMW(); /* 002c: memw  */
  a8 = (uint32_t)&ppProcessWaitingQueue; /* 002f: l32r a8, 4 <ppDisableQueue-0x4> (0 <ppDisableQueue-0x8>) */ /* literal: GOT slot for ppProcessWaitingQueue */
  ppProcessWaitingQueue(a2, a3, a4, a5); /* call via literal slot */ /* 0032: callx8 a8 */
  return (int32_t)a2; /* 0035: retw.n  */
}

/* ppCheckTxIdle @ pp.o 0000000c size 178B bind GLOBAL
 * Calls: lmacIsIdle, ppDisableQueue | Data refs: lmacIsIdle, pTxRx, ppDisableQueue
 *   MMIO: none
 *   funcdb v3: 2 call(s), 3 ref(s); disasm: 2 call(s), 3 data ref(s)
 * Fidelity: medium - 68 instr, 17 branches, calls resolved */
int32_t ppCheckTxIdle(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.ppCheckTxIdle; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_c:;
  /* 000c: entry a1, 32 */
  a2 = 0x0; /* 000f: movi a2, 0 */
L_12:;
  a10 = 0x0; /* 0012: mov.n a10, a2 */
  a8 = (uint32_t)&lmacIsIdle; /* 0014: l32r a8, 4 <ppCheckTxIdle-0x8> (0 <ppCheckTxIdle-0xc>) */ /* literal: GOT slot for lmacIsIdle */
  lmacIsIdle(a2, a3, a4, a5); /* call via literal slot */ /* 0017: callx8 a8 */
  if (a10 != 0) goto L_21; /* 001a: bnez.n a10, 21 <ppCheckTxIdle+0x15> */
L_1c:;
  a2 = 0x1; /* 001c: movi.n a2, 1 */
  goto L_bc; /* 001e: j bc <ppCheckTxIdle+0xb0> */
L_21:;
  a2 = 0x2; /* 0021: addi.n a2, a2, 1 */
  if (a2 != 5) goto L_12; /* 0023: bnei a2, 5, 12 <ppCheckTxIdle+0x6> */
  goto L_8e; /* 0026: j 8e <ppCheckTxIdle+0x82> */
L_29:;
  a8 = 0xFFFFFFFE; /* 0029: neg a8, a2 */
  a8 = 0x2; /* 002c: and a8, a8, a2 */
  a8 = __builtin_clz(a8) /* approx for nsau */; /* 002f: nsau a8, a8 */
  a8 = -a8; /* 0032: neg a8, a8 */
  a10 = a8 + (31); /* 0035: addi a10, a8, 31 */
  a11 = (a10 << 2) + a10; /* 0038: addx2 a11, a10, a10 */
  a11 = a11 << (4 & 31); /* 003b: slli a11, a11, 4 */
  a11 = a9 + a11; /* 003e: add.n a11, a9, a11 */
  a2 = MEM32(a11 + 32); /* 0040: l32i.n a2, a11, 32 */
  if (a2 != 0) goto L_1c; /* 0042: bnez a2, 1c <ppCheckTxIdle+0x10> */
  a8 = a8 + (32); /* 0045: addi a8, a8, 32 */
  a8 = (a8 << 2) + a8; /* 0048: addx2 a8, a8, a8 */
  a8 = a8 << (4 & 31); /* 004b: slli a8, a8, 4 */
  a8 = a9 + a8; /* 004e: add.n a8, a9, a8 */
  a2 = MEM32(a8 + 4); /* 0050: l32i.n a2, a8, 4 */
  if (a2 != 0) goto L_1c; /* 0052: bnez a2, 1c <ppCheckTxIdle+0x10> */
  a8 = MEM8(a11 + 44); /* 0055: l8ui a8, a11, 44 */
  a11 = 0x4; /* 0058: movi.n a11, 4 */
  if (a8 >= 8) goto L_88; /* 005a: bgeui a8, 8, 88 <ppCheckTxIdle+0x7c> */
  a9 = 0x1; /* 005d: movi.n a9, 1 */
  a11 = a2; /* 005f: mov.n a11, a2 */
  if (a8 != 0) a11 = a9; /* 0061: movnez a11, a9, a8 */
  a11 = (a11 >> 0) & 0xFF; /* 0064: extui a11, a11, 0, 8 */
  if (a11 == 0) goto L_86; /* 0067: beqz.n a11, 86 <ppCheckTxIdle+0x7a> */
  a12 = a8 + (-3); /* 0069: addi a12, a8, -3 */
  a11 = a2; /* 006c: mov.n a11, a2 */
  if (a12 != 0) a11 = a9; /* 006e: movnez a11, a9, a12 */
  a11 = (a11 >> 0) & 0xFF; /* 0071: extui a11, a11, 0, 8 */
  if (a11 == 0) goto L_86; /* 0074: beqz.n a11, 86 <ppCheckTxIdle+0x7a> */
  a11 = 0x3; /* 0076: movi.n a11, 3 */
  if (a8 < a11) goto L_88; /* 0078: bltu a8, a11, 88 <ppCheckTxIdle+0x7c> */
  a11 = 0x1; /* 007b: mov.n a11, a9 */
  if (a8 < 6) goto L_88; /* 007d: bltui a8, 6, 88 <ppCheckTxIdle+0x7c> */
  a11 = a2; /* 0080: mov.n a11, a2 */
  goto L_88; /* 0082: j 88 <ppCheckTxIdle+0x7c> */
  /* 0085: .byte 00 */
L_86:;
  a11 = 0x2; /* 0086: movi.n a11, 2 */
L_88:;
  a8 = (uint32_t)&ppDisableQueue; /* 0088: l32r a8, 8 <ppCheckTxIdle-0x4> (0 <ppCheckTxIdle-0xc>) */ /* literal: GOT slot for ppDisableQueue */
  ppDisableQueue(a2, a3, a4, a5); /* call via literal slot */ /* 008b: callx8 a8 */
L_8e:;
  a2 = (uint32_t)&pTxRx; /* 008e: l32r a2, 0 <ppCheckTxIdle-0xc> (0 <ppCheckTxIdle-0xc>) */ /* literal @0x0: pTxRx */
  a9 = MEM32(a2 + 0); /* 0091: l32i.n a9, a2, 0 */
  a2 = MEM32(a9 + 0); /* 0093: l32i.n a2, a9, 0 */
  if (a2 != 0) goto L_29; /* 0095: bnez a2, 29 <ppCheckTxIdle+0x1d> */
  a8 = a9 + (32); /* 0098: addi a8, a9, 32 */
  a2 = 0x4; /* 009b: movi.n a2, 4 */
  /* 009d: loop a2, a8 <ppCheckTxIdle+0x9c> */ /* loop a2 times, end L_a8; body shown single-pass */
  a10 = MEM32(a8 + 0); /* 00a0: l32i.n a10, a8, 0 */
  if (a10 != 0) goto L_1c; /* 00a2: bnez a10, 1c <ppCheckTxIdle+0x10> */
  a8 = a8 + (48); /* 00a5: addi a8, a8, 48 */
L_a8:;
  a2 = MEM32(a9 + 820); /* 00a8: l32i a2, a9, 0x334 */
  if (a2 != 0) goto L_1c; /* 00ab: bnez a2, 1c <ppCheckTxIdle+0x10> */
  a8 = MEM32(a9 + 828); /* 00ae: l32i a8, a9, 0x33c */
  if (a8 != 0) goto L_1c; /* 00b1: bnez a8, 1c <ppCheckTxIdle+0x10> */
  a2 = 0x1; /* 00b4: movi.n a2, 1 */
  a9 = MEM32(a9 + 836); /* 00b6: l32i a9, a9, 0x344 */
  if (a9 == 0) a2 = a8; /* 00b9: moveqz a2, a8, a9 */
L_bc:;
  return (int32_t)a2; /* 00bc: retw.n  */
}

/* ppSelectNextQueue @ pp.o 00000008 size 153B bind GLOBAL
 * Calls: ppDisableQueue[got] | Data refs: pTxRx, ppDisableQueue
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 1 call(s), 2 data ref(s)
 * Fidelity: medium - 59 instr, 8 branches, calls resolved */
int32_t ppSelectNextQueue(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .wifiextrairam.62; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_8:;
  /* 0008: entry a1, 32 */
  a4 = (uint32_t)&pTxRx; /* 000b: l32r a4, 0 <ppSelectNextQueue-0x8> (0 <ppSelectNextQueue-0x8>) */ /* literal @0x0: pTxRx */
  a2 = (a2 >> 0) & 0xFF; /* 000e: extui a2, a2, 0, 8 */
  a5 = a2 << (2 & 31); /* 0011: slli a5, a2, 2 */
  a9 = MEM32(a4 + 0); /* 0014: l32i.n a9, a4, 0 */
  a3 = a9 + a2; /* 0016: add.n a3, a9, a2 */
  a8 = (a2 << 4) + a9; /* 0018: addx4 a8, a2, a9 */
  a3 = MEM8(a3 + 24); /* 001b: l8ui a3, a3, 24 */
  a8 = MEM32(a8 + 4); /* 001e: l32i.n a8, a8, 4 */
  if (!((a8 >> (a3 & 31)) & 1)) goto L_9c; /* 0020: bbc a8, a3, 9c <ppSelectNextQueue+0x94> */
  a8 = (a3 << 2) + a3; /* 0023: addx2 a8, a3, a3 */
  a8 = a8 << (4 & 31); /* 0026: slli a8, a8, 4 */
  a8 = a9 + a8; /* 0029: add.n a8, a9, a8 */
  a10 = MEM8(a8 + 49); /* 002b: l8ui a10, a8, 49 */
  if (a10 == 0) goto L_9c; /* 002e: beqz a10, 9c <ppSelectNextQueue+0x94> */
  a10 = 0x0; /* 0031: movi.n a10, 0 */
  a9 = MEM32(a8 + 32); /* 0033: l32i.n a9, a8, 32 */
  MEM8(a8 + 49) = a10; /* 0035: s8i a10, a8, 49 */
  MEMW(); /* 0038: memw  */
  if (a9 != 0) goto L_4e; /* 003b: bnez.n a9, 4e <ppSelectNextQueue+0x46> */
  a8 = MEM32(a8 + 52); /* 003d: l32i.n a8, a8, 52 */
  if (a8 != 0) goto L_4e; /* 003f: bnez.n a8, 4e <ppSelectNextQueue+0x46> */
  a11 = a2; /* 0041: mov.n a11, a2 */
  a10 = a3; /* 0043: mov.n a10, a3 */
  MEMW(); /* 0045: memw  */
  a8 = (uint32_t)&ppDisableQueue; /* 0048: l32r a8, 4 <ppSelectNextQueue-0x4> (0 <ppSelectNextQueue-0x8>) */ /* literal: GOT slot for ppDisableQueue */
  ppDisableQueue(a2, a3, a4, a5); /* call via literal slot */ /* 004b: callx8 a8 */
L_4e:;
  a11 = MEM32(a4 + 0); /* 004e: l32i.n a11, a4, 0 */
  a5 = a11 + a5; /* 0050: add.n a5, a11, a5 */
  a4 = MEM32(a5 + 4); /* 0052: l32i.n a4, a5, 4 */
  if (a4 == 0) goto L_9c; /* 0054: beqz a4, 9c <ppSelectNextQueue+0x94> */
  a9 = 0xFFFFFFFF; /* 0057: movi.n a9, -1 */
  a10 = 0x1; /* 0059: movi.n a10, 1 */
  /* 005b: ssl a3 */ /* UNMODELED: a3 clobbered */
  /* 005e: sll a5, a9 */ /* UNMODELED: a5 clobbered */
  /* 0061: ssl a3 */ /* UNMODELED: a3 clobbered */
  /* 0064: sll a10, a10 */ /* UNMODELED: a10 clobbered */
  a8 = a4 & a5; /* 0067: and a8, a4, a5 */
  a10 = a9 ^ a10; /* 006a: xor a10, a9, a10 */
  a10 = a10 & a8; /* 006d: and a10, a10, a8 */
  if (a10 == 0) goto L_7d; /* 0070: beqz.n a10, 7d <ppSelectNextQueue+0x75> */
  a8 = -a10; /* 0072: neg a8, a10 */
  a8 = a8 & a10; /* 0075: and a8, a8, a10 */
  goto L_8b; /* 0078: j 8b <ppSelectNextQueue+0x83> */
  /* 007b: .byte 00 */
  /* 007c: .byte 00 */
L_7d:;
  a9 = a9 ^ a5; /* 007d: xor a9, a9, a5 */
  a9 = a9 & a4; /* 0080: and a9, a9, a4 */
  if (a9 == 0) goto L_9c; /* 0083: beqz.n a9, 9c <ppSelectNextQueue+0x94> */
  a8 = -a9; /* 0085: neg a8, a9 */
  a8 = a8 & a9; /* 0088: and a8, a8, a9 */
L_8b:;
  a8 = __builtin_clz(a8) /* approx for nsau */; /* 008b: nsau a8, a8 */
  a8 = -a8; /* 008e: neg a8, a8 */
  a8 = a8 + (31); /* 0091: addi a8, a8, 31 */
  a11 = a11 + a2; /* 0094: add.n a11, a11, a2 */
  MEM8(a11 + 24) = a8; /* 0096: s8i a8, a11, 24 */
  MEMW(); /* 0099: memw  */
L_9c:;
  MEMW(); /* 009c: memw  */
  return (int32_t)a2; /* 009f: retw.n  */
}

/* ppSearchTxframe @ pp.o 00000018 size 284B bind GLOBAL
 * Calls: ppGetTxframe[got], ppSelectNextQueue[got], ppGetTxframe[got], ppGetTxframe[got], ppGetTxframe[got] | Data refs: ppGetTxframe, ppSelectNextQueue, pTxRx
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 5 call(s), 3 data ref(s)
 * Fidelity: medium - 110 instr, 15 branches, calls resolved */
int32_t ppSearchTxframe(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .wifi0iram.61; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_18:;
  /* 0018: entry a1, 48 */
  a4 = (a2 >> 0) & 0xFF; /* 001b: extui a4, a2, 0, 8 */
  if (a4 != 4) goto L_2c; /* 001e: bnei a4, 4, 2c <ppSearchTxframe+0x14> */
  a10 = 0x2; /* 0021: movi.n a10, 2 */
  a8 = (uint32_t)&ppGetTxframe; /* 0023: l32r a8, 4 <ppSearchTxframe-0x14> (0 <ppSearchTxframe-0x18>) */ /* literal: GOT slot for ppGetTxframe */
  ppGetTxframe(a2, a3, a4, a5); /* call via literal slot */ /* 0026: callx8 a8 */
  goto L_130; /* 0029: j 130 <ppSearchTxframe+0x118> */
L_2c:;
  a10 = a4; /* 002c: mov.n a10, a4 */
  a8 = (uint32_t)&ppSelectNextQueue; /* 002e: l32r a8, 8 <ppSearchTxframe-0x10> (0 <ppSearchTxframe-0x18>) */ /* literal: GOT slot for ppSelectNextQueue */
  ppSelectNextQueue(a2, a3, a4, a5); /* call via literal slot */ /* 0031: callx8 a8 */
  a6 = (uint32_t)&pTxRx; /* 0034: l32r a6, 0 <ppSearchTxframe-0x18> (0 <ppSearchTxframe-0x18>) */ /* literal @0x0: pTxRx */
  a2 = MEM32(a6 + 0); /* 0037: l32i.n a2, a6, 0 */
  a3 = a2 + a4; /* 0039: add.n a3, a2, a4 */
  a5 = MEM8(a3 + 24); /* 003b: l8ui a5, a3, 24 */
  if (a4 != 0) goto L_66; /* 003e: bnez.n a4, 66 <ppSearchTxframe+0x4e> */
  a3 = MEM32(a2 + 4); /* 0040: l32i.n a3, a2, 4 */
  if (!((a3 >> (a5 & 31)) & 1)) goto L_54; /* 0042: bbc a3, a5, 54 <ppSearchTxframe+0x3c> */
  a3 = a5 + (1); /* 0045: addi.n a3, a5, 1 */
  a3 = (a3 << 2) + a3; /* 0047: addx2 a3, a3, a3 */
  a3 = a3 << (4 & 31); /* 004a: slli a3, a3, 4 */
  a2 = a2 + a3; /* 004d: add.n a2, a2, a3 */
  a2 = MEM8(a2 + 1); /* 004f: l8ui a2, a2, 1 */
  if (a2 != 0) goto L_66; /* 0052: bnez.n a2, 66 <ppSearchTxframe+0x4e> */
L_54:;
  a2 = a4; /* 0054: mov.n a2, a4 */
L_56:;
  a10 = a2; /* 0056: mov.n a10, a2 */
  a8 = (uint32_t)&ppGetTxframe; /* 0058: l32r a8, c <ppSearchTxframe-0xc> (0 <ppSearchTxframe-0x18>) */ /* literal: GOT slot for ppGetTxframe */
  ppGetTxframe(a2, a3, a4, a5); /* call via literal slot */ /* 005b: callx8 a8 */
  if (a10 != 0) goto L_130; /* 005e: bnez a10, 130 <ppSearchTxframe+0x118> */
  a2 = a2 + (1); /* 0061: addi.n a2, a2, 1 */
  if (a2 != 3) goto L_56; /* 0063: bnei a2, 3, 56 <ppSearchTxframe+0x3e> */
L_66:;
  a2 = MEM32(a6 + 0); /* 0066: l32i.n a2, a6, 0 */
  a7 = 0xFFFFFFFF; /* 0068: movi.n a7, -1 */
  a2 = (a4 << 4) + a2; /* 006a: addx4 a2, a4, a2 */
  /* 006d: ssl a5 */ /* UNMODELED: a5 clobbered */
  /* 0070: sll a7, a7 */ /* UNMODELED: a7 clobbered */
  a9 = 0x1; /* 0073: movi.n a9, 1 */
  a8 = MEM32(a2 + 4); /* 0075: l32i.n a8, a2, 4 */
  a2 = a8 & a7; /* 0077: and a2, a8, a7 */
  goto L_d2; /* 007a: j d2 <ppSearchTxframe+0xba> */
L_7d:;
  a3 = -a2; /* 007d: neg a3, a2 */
  a3 = a3 & a2; /* 0080: and a3, a3, a2 */
  a3 = __builtin_clz(a3) /* approx for nsau */; /* 0083: nsau a3, a3 */
  a3 = -a3; /* 0086: neg a3, a3 */
  a5 = a3 + (31); /* 0089: addi a5, a3, 31 */
  a10 = a5; /* 008c: mov.n a10, a5 */
  MEM32(a1 + 0) = a8; /* 008e: s32i.n a8, a1, 0 */
  MEM32(a1 + 4) = a9; /* 0090: s32i a9, a1, 4 */
  MEMW(); /* 0093: memw  */
  a8 = (uint32_t)&ppGetTxframe; /* 0096: l32r a8, 10 <ppSearchTxframe-0x8> (0 <ppSearchTxframe-0x18>) */ /* literal: GOT slot for ppGetTxframe */
  ppGetTxframe(a2, a3, a4, a5); /* call via literal slot */ /* 0099: callx8 a8 */
  a8 = MEM32(a1 + 0); /* 009c: l32i.n a8, a1, 0 */
  a9 = MEM32(a1 + 4); /* 009e: l32i.n a9, a1, 4 */
  if (a10 == 0) goto L_c4; /* 00a0: beqz.n a10, c4 <ppSearchTxframe+0xac> */
  a2 = MEM32(a6 + 0); /* 00a2: l32i.n a2, a6, 0 */
  a3 = a3 + (32); /* 00a4: addi a3, a3, 32 */
  a3 = (a3 << 2) + a3; /* 00a7: addx2 a3, a3, a3 */
  a4 = a2 + a4; /* 00aa: add.n a4, a2, a4 */
  a3 = a3 << (4 & 31); /* 00ac: slli a3, a3, 4 */
  a2 = a2 + a3; /* 00af: add.n a2, a2, a3 */
  MEM8(a4 + 24) = a5; /* 00b1: s8i a5, a4, 24 */
  a3 = 0x1; /* 00b4: movi.n a3, 1 */
  MEM8(a2 + 1) = a3; /* 00b6: s8i a3, a2, 1 */
  MEMW(); /* 00b9: memw  */
  MEMW(); /* 00bc: memw  */
  goto L_130; /* 00bf: j 130 <ppSearchTxframe+0x118> */
  /* 00c2: .byte 00 */
  /* 00c3: .byte 00 */
L_c4:;
  /* 00c4: ssl a5 */ /* UNMODELED: a5 clobbered */
  /* 00c7: sll a5, a9 */ /* UNMODELED: a5 clobbered */
  a3 = 0xFFFFFFFF; /* 00ca: movi.n a3, -1 */
  a3 = a3 ^ a5; /* 00cc: xor a3, a3, a5 */
  a2 = a2 & a3; /* 00cf: and a2, a2, a3 */
L_d2:;
  if (a2 != 0) goto L_7d; /* 00d2: bnez a2, 7d <ppSearchTxframe+0x65> */
  a5 = 0xFFFFFFFF; /* 00d5: movi.n a5, -1 */
  a5 = a5 ^ a7; /* 00d7: xor a5, a5, a7 */
  a5 = a5 & a8; /* 00da: and a5, a5, a8 */
  a7 = 0x1; /* 00dd: movi.n a7, 1 */
  goto L_12b; /* 00df: j 12b <ppSearchTxframe+0x113> */
L_e2:;
  a3 = -a5; /* 00e2: neg a3, a5 */
  a3 = a3 & a5; /* 00e5: and a3, a3, a5 */
  a3 = __builtin_clz(a3) /* approx for nsau */; /* 00e8: nsau a3, a3 */
  a3 = -a3; /* 00eb: neg a3, a3 */
  a2 = a3 + (31); /* 00ee: addi a2, a3, 31 */
  a10 = a2; /* 00f1: mov.n a10, a2 */
  a8 = (uint32_t)&ppGetTxframe; /* 00f3: l32r a8, 14 <ppSearchTxframe-0x4> (0 <ppSearchTxframe-0x18>) */ /* literal: GOT slot for ppGetTxframe */
  ppGetTxframe(a2, a3, a4, a5); /* call via literal slot */ /* 00f6: callx8 a8 */
  if (a10 == 0) goto L_11d; /* 00f9: beqz.n a10, 11d <ppSearchTxframe+0x105> */
  a5 = MEM32(a6 + 0); /* 00fb: l32i.n a5, a6, 0 */
  a3 = a3 + (32); /* 00fd: addi a3, a3, 32 */
  a3 = (a3 << 2) + a3; /* 0100: addx2 a3, a3, a3 */
  a4 = a5 + a4; /* 0103: add.n a4, a5, a4 */
  a3 = a3 << (4 & 31); /* 0105: slli a3, a3, 4 */
  MEM8(a4 + 24) = a2; /* 0108: s8i a2, a4, 24 */
  a5 = a5 + a3; /* 010b: add.n a5, a5, a3 */
  a2 = 0x1; /* 010d: movi.n a2, 1 */
  MEM8(a5 + 1) = a2; /* 010f: s8i a2, a5, 1 */
  MEMW(); /* 0112: memw  */
  MEMW(); /* 0115: memw  */
  goto L_130; /* 0118: j 130 <ppSearchTxframe+0x118> */
  /* 011b: .byte 00 */
  /* 011c: .byte 00 */
L_11d:;
  /* 011d: ssl a2 */ /* UNMODELED: a2 clobbered */
  /* 0120: sll a2, a7 */ /* UNMODELED: a2 clobbered */
  a3 = 0xFFFFFFFF; /* 0123: movi.n a3, -1 */
  a2 = a3 ^ a2; /* 0125: xor a2, a3, a2 */
  a5 = a5 & a2; /* 0128: and a5, a5, a2 */
L_12b:;
  if (a5 != 0) goto L_e2; /* 012b: bnez a5, e2 <ppSearchTxframe+0xca> */
  a10 = a5; /* 012e: mov.n a10, a5 */
L_130:;
  a2 = a10; /* 0130: mov.n a2, a10 */
  return (int32_t)a2; /* 0132: retw.n  */
}

/* ppMapTxQueue @ pp.o 00000020 size 406B bind GLOBAL
 * Calls: ppProcessWaitingQueue[got], pm_on_data_tx[got], pm_on_data_tx[got], ppSearchTxQueue[got], pm_on_data_tx[got], ppSearchTxQueue[got] | Data refs: ppProcessWaitingQueue, pm_on_data_tx, g_mesh_is_started, ppSearchTxQueue
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 6 call(s), 4 data ref(s)
 * Fidelity: medium - 155 instr, 22 branches, calls resolved */
int32_t ppMapTxQueue(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .wifi0iram.66; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_20:;
  /* 0020: entry a1, 48 */
  a4 = a2; /* 0023: mov.n a4, a2 */
  a7 = MEM32(a2 + 36); /* 0025: l32i.n a7, a2, 36 */
  a2 = MEM32(a2 + 4); /* 0027: l32i.n a2, a2, 4 */
  a9 = MEM32(a2 + 4); /* 0029: l32i.n a9, a2, 4 */
  a2 = MEM32(a4 + 44); /* 002b: l32i.n a2, a4, 44 */
  a2 = MEM32(a2 + 0); /* 002d: l32i.n a2, a2, 0 */
  if (!((a2 >> 18) & 1)) goto L_34; /* 002f: bbci a2, 18, 34 <ppMapTxQueue+0x14> */
  a9 = a9 + (4); /* 0032: addi.n a9, a9, 4 */
L_34:;
  a2 = 0xF0; /* 0034: movi a2, 240 */
  MEM32(a1 + 0) = a9; /* 0037: s32i.n a9, a1, 0 */
  MEMW(); /* 0039: memw  */
  a8 = (uint32_t)&ppProcessWaitingQueue; /* 003c: l32r a8, 8 <ppMapTxQueue-0x18> (0 <ppMapTxQueue-0x20>) */ /* literal: GOT slot for ppProcessWaitingQueue */
  ppProcessWaitingQueue(a2, a3, a4, a5); /* call via literal slot */ /* 003f: callx8 a8 */
  a3 = MEM32(a4 + 44); /* 0042: l32i.n a3, a4, 44 */
  a12 = MEM32(a3 + 4); /* 0044: l32i.n a12, a3, 4 */
  a2 = a2 & a12; /* 0046: and a2, a2, a12 */
  a9 = MEM32(a1 + 0); /* 0049: l32i.n a9, a1, 0 */
  if (a2 != 64) goto L_66; /* 004b: bnei a2, 64, 66 <ppMapTxQueue+0x46> */
  a2 = MEM32(a3 + 16); /* 004e: l32i.n a2, a3, 16 */
  a4 = 0xFF0FFFFF; /* 0050: l32r a4, 0 <ppMapTxQueue-0x20> (ff0fffff <ppRxFragmentProc+0xff0fff7f>) */ @0x0
  a2 = a2 & a4; /* 0053: and a2, a2, a4 */
  a4 = 0x3; /* 0056: movi.n a4, 3 */
  a4 = 0x300000; /* 0058: slli a4, a4, 20 */
  a2 = a2 | a4; /* 005b: or a2, a2, a4 */
  MEM32(a3 + 16) = a2; /* 005e: s32i.n a2, a3, 16 */
  MEMW(); /* 0060: memw  */
  goto L_a0; /* 0063: j a0 <ppMapTxQueue+0x80> */
L_66:;
  a10 = MEM32(a3 + 16); /* 0066: l32i.n a10, a3, 16 */
  a8 = (a10 >> 18) & 0x3; /* 0068: extui a8, a10, 18, 2 */
  a5 = a8; /* 006b: mov.n a5, a8 */
  a6 = MEM8(a9 + 0); /* 006d: l8ui a6, a9, 0 */
  if (a7 == 0) goto L_78; /* 0070: beqz.n a7, 78 <ppMapTxQueue+0x58> */
  a2 = MEM8(a7 + 11); /* 0072: l8ui a2, a7, 11 */
  if (!((a2 >> 7) & 1)) goto L_a6; /* 0075: bbci a2, 7, a6 <ppMapTxQueue+0x86> */
L_78:;
  a2 = 0x7; /* 0078: movi.n a2, 7 */
  a8 = (a8 >> 0) & 0x3; /* 007a: extui a8, a8, 0, 2 */
  a4 = 0xFF0FFFFF; /* 007d: l32r a4, 0 <ppMapTxQueue-0x20> (ff0fffff <ppRxFragmentProc+0xff0fff7f>) */ @0x0
  a8 = a8 << (20 & 31); /* 0080: slli a8, a8, 20 */
  a11 = 0x0; /* 0083: movi.n a11, 0 */
  a10 = a5; /* 0085: mov.n a10, a5 */
  MEM8(a3 + 4) = a2; /* 0087: s8i a2, a3, 4 */
  MEMW(); /* 008a: memw  */
  a2 = MEM32(a3 + 16); /* 008d: l32i.n a2, a3, 16 */
  a2 = a2 & a4; /* 008f: and a2, a2, a4 */
  a2 = a2 | a8; /* 0092: or a2, a2, a8 */
  MEM32(a3 + 16) = a2; /* 0095: s32i.n a2, a3, 16 */
  MEMW(); /* 0097: memw  */
  a8 = (uint32_t)&pm_on_data_tx; /* 009a: l32r a8, c <ppMapTxQueue-0x14> (0 <ppMapTxQueue-0x20>) */ /* literal: GOT slot for pm_on_data_tx */
  pm_on_data_tx(a2, a3, a4, a5); /* call via literal slot */ /* 009d: callx8 a8 */
L_a0:;
  a2 = 0x0; /* 00a0: movi.n a2, 0 */
  goto L_1b1; /* 00a2: j 1b1 <ppMapTxQueue+0x191> */
  /* 00a5: .byte 00 */
L_a6:;
  a7 = 0xC; /* 00a6: movi.n a7, 12 */
  a7 = a6 & a7; /* 00a8: and a7, a6, a7 */
  if (a7 != 0) goto L_112; /* 00ab: bnez a7, 112 <ppMapTxQueue+0xf2> */
  a2 = 0x7; /* 00ae: movi.n a2, 7 */
  MEM8(a3 + 4) = a2; /* 00b0: s8i a2, a3, 4 */
  MEMW(); /* 00b3: memw  */
  a8 = (a8 >> 0) & 0x3; /* 00b6: extui a8, a8, 0, 2 */
  a8 = a8 << (20 & 31); /* 00b9: slli a8, a8, 20 */
  a11 = 0x1; /* 00bc: movi.n a11, 1 */
  a2 = 0xFF0FFFFF; /* 00be: l32r a2, 0 <ppMapTxQueue-0x20> (ff0fffff <ppRxFragmentProc+0xff0fff7f>) */ @0x0
  a2 = a10 & a2; /* 00c1: and a2, a10, a2 */
  a2 = a2 | a8; /* 00c4: or a2, a2, a8 */
  a10 = a5; /* 00c7: mov.n a10, a5 */
  MEM32(a3 + 16) = a2; /* 00c9: s32i.n a2, a3, 16 */
  a2 = a7; /* 00cb: mov.n a2, a7 */
  MEM32(a1 + 0) = a9; /* 00cd: s32i.n a9, a1, 0 */
  MEMW(); /* 00cf: memw  */
  a8 = (uint32_t)&pm_on_data_tx; /* 00d2: l32r a8, 10 <ppMapTxQueue-0x10> (0 <ppMapTxQueue-0x20>) */ /* literal: GOT slot for pm_on_data_tx */
  pm_on_data_tx(a2, a3, a4, a5); /* call via literal slot */ /* 00d5: callx8 a8 */
  a9 = MEM32(a1 + 0); /* 00d8: l32i.n a9, a1, 0 */
  if (a10 == 0) goto L_1b1; /* 00da: beqz a10, 1b1 <ppMapTxQueue+0x191> */
  a3 = (uint32_t)&g_mesh_is_started; /* 00dd: l32r a3, 4 <ppMapTxQueue-0x1c> (0 <ppMapTxQueue-0x20>) */ /* literal @0x4: g_mesh_is_started */
  a3 = MEM8(a3 + 0); /* 00e0: l8ui a3, a3, 0 */
  if (a3 != 0) goto L_10c; /* 00e3: bnez.n a3, 10c <ppMapTxQueue+0xec> */
  a3 = 0xFFFFFFF0; /* 00e5: movi.n a3, -16 */
  a3 = a6 & a3; /* 00e7: and a3, a6, a3 */
  if (a3 != 64) goto L_101; /* 00ea: bnei a3, 64, 101 <ppMapTxQueue+0xe1> */
  a3 = MEM8(a9 + 1); /* 00ed: l8ui a3, a9, 1 */
  a4 = 0x10; /* 00f0: movi.n a4, 16 */
  a3 = a3 | a4; /* 00f2: or a3, a3, a4 */
  MEM8(a9 + 1) = a3; /* 00f5: s8i a3, a9, 1 */
  MEMW(); /* 00f8: memw  */
  MEMW(); /* 00fb: memw  */
  goto L_1b1; /* 00fe: j 1b1 <ppMapTxQueue+0x191> */
L_101:;
  a3 = MEM32(a4 + 44); /* 0101: l32i.n a3, a4, 44 */
  a3 = MEM16(a3 + 2); /* 0103: l16ui a3, a3, 2 */
  if (!((a3 >> 0) & 1)) goto L_10c; /* 0106: bbci a3, 0, 10c <ppMapTxQueue+0xec> */
  goto L_1b1; /* 0109: j 1b1 <ppMapTxQueue+0x191> */
L_10c:;
  a2 = 0x1; /* 010c: movi.n a2, 1 */
  goto L_1b1; /* 010e: j 1b1 <ppMapTxQueue+0x191> */
  /* 0111: .byte 00 */
L_112:;
  a2 = MEM32(a3 + 0); /* 0112: l32i.n a2, a3, 0 */
  a9 = 0x1; /* 0114: movi.n a9, 1 */
  a9 = 0x2000; /* 0116: slli a9, a9, 13 */
  a2 = a2 & a9; /* 0119: and a2, a2, a9 */
  if (a2 == 0) goto L_159; /* 011c: beqz.n a2, 159 <ppMapTxQueue+0x139> */
  a2 = MEM32(a4 + 36); /* 011e: l32i.n a2, a4, 36 */
  a13 = (a12 >> 4) & 0xF; /* 0120: extui a13, a12, 4, 4 */
  a10 = a8; /* 0123: mov.n a10, a8 */
  a12 = (a12 >> 0) & 0xF; /* 0125: extui a12, a12, 0, 4 */
  a11 = MEM8(a2 + 128); /* 0128: l8ui a11, a2, 128 */
  a8 = (uint32_t)&ppSearchTxQueue; /* 012b: l32r a8, 14 <ppMapTxQueue-0xc> (0 <ppMapTxQueue-0x20>) */ /* literal: GOT slot for ppSearchTxQueue */
  ppSearchTxQueue(a2, a3, a4, a5); /* call via literal slot */ /* 012e: callx8 a8 */
  if (a10 == 16) goto L_10c; /* 0131: beqi a10, 16, 10c <ppMapTxQueue+0xec> */
  a10 = (a10 >> 0) & 0xF; /* 0134: extui a10, a10, 0, 4 */
  a2 = MEM32(a3 + 16); /* 0137: l32i.n a2, a3, 16 */
  a10 = a10 << (20 & 31); /* 0139: slli a10, a10, 20 */
  a11 = 0x1; /* 013c: movi.n a11, 1 */
  a4 = 0xFF0FFFFF; /* 013e: l32r a4, 0 <ppMapTxQueue-0x20> (ff0fffff <ppRxFragmentProc+0xff0fff7f>) */ @0x0
  a2 = a2 & a4; /* 0141: and a2, a2, a4 */
  a2 = a2 | a10; /* 0144: or a2, a2, a10 */
  a10 = a5; /* 0147: mov.n a10, a5 */
  MEM32(a3 + 16) = a2; /* 0149: s32i.n a2, a3, 16 */
  MEMW(); /* 014b: memw  */
  a8 = (uint32_t)&pm_on_data_tx; /* 014e: l32r a8, 18 <ppMapTxQueue-0x8> (0 <ppMapTxQueue-0x20>) */ /* literal: GOT slot for pm_on_data_tx */
  pm_on_data_tx(a2, a3, a4, a5); /* call via literal slot */ /* 0151: callx8 a8 */
  a2 = a10; /* 0154: mov.n a2, a10 */
  goto L_1b1; /* 0156: j 1b1 <ppMapTxQueue+0x191> */
L_159:;
  if (a7 != 8) goto L_185; /* 0159: bnei a7, 8, 185 <ppMapTxQueue+0x165> */
  a7 = 0x70; /* 015c: movi a7, 112 */
  a6 = a6 & a7; /* 015f: and a6, a6, a7 */
  if (a6 != 64) goto L_185; /* 0162: bnei a6, 64, 185 <ppMapTxQueue+0x165> */
  a4 = 0x7; /* 0165: movi.n a4, 7 */
  MEM8(a3 + 4) = a4; /* 0167: s8i a4, a3, 4 */
  MEMW(); /* 016a: memw  */
  a9 = (a8 >> 0) & 0x3; /* 016d: extui a9, a8, 0, 2 */
  a9 = a9 << (20 & 31); /* 0170: slli a9, a9, 20 */
  a4 = 0xFF0FFFFF; /* 0173: l32r a4, 0 <ppMapTxQueue-0x20> (ff0fffff <ppRxFragmentProc+0xff0fff7f>) */ @0x0
  a8 = a10 & a4; /* 0176: and a8, a10, a4 */
  a8 = a8 | a9; /* 0179: or a8, a8, a9 */
  MEM32(a3 + 16) = a8; /* 017c: s32i.n a8, a3, 16 */
  MEMW(); /* 017e: memw  */
  goto L_1b1; /* 0181: j 1b1 <ppMapTxQueue+0x191> */
  /* 0184: .byte 00 */
L_185:;
  a4 = MEM32(a4 + 36); /* 0185: l32i.n a4, a4, 36 */
  a13 = (a12 >> 4) & 0xF; /* 0187: extui a13, a12, 4, 4 */
  a10 = a5; /* 018a: mov.n a10, a5 */
  a12 = (a12 >> 0) & 0xF; /* 018c: extui a12, a12, 0, 4 */
  a11 = MEM8(a4 + 128); /* 018f: l8ui a11, a4, 128 */
  a8 = (uint32_t)&ppSearchTxQueue; /* 0192: l32r a8, 1c <ppMapTxQueue-0x4> (0 <ppMapTxQueue-0x20>) */ /* literal: GOT slot for ppSearchTxQueue */
  ppSearchTxQueue(a2, a3, a4, a5); /* call via literal slot */ /* 0195: callx8 a8 */
  if (a10 != 16) goto L_19e; /* 0198: bnei a10, 16, 19e <ppMapTxQueue+0x17e> */
  goto L_10c; /* 019b: j 10c <ppMapTxQueue+0xec> */
L_19e:;
  a10 = (a10 >> 0) & 0xF; /* 019e: extui a10, a10, 0, 4 */
  a4 = MEM32(a3 + 16); /* 01a1: l32i.n a4, a3, 16 */
  a10 = a10 << (20 & 31); /* 01a3: slli a10, a10, 20 */
  a5 = 0xFF0FFFFF; /* 01a6: l32r a5, 0 <ppMapTxQueue-0x20> (ff0fffff <ppRxFragmentProc+0xff0fff7f>) */ @0x0
  a4 = a4 & a5; /* 01a9: and a4, a4, a5 */
  a4 = a4 | a10; /* 01ac: or a4, a4, a10 */
  MEM32(a3 + 16) = a4; /* 01af: s32i.n a4, a3, 16 */
L_1b1:;
  MEMW(); /* 01b1: memw  */
  return (int32_t)a2; /* 01b4: retw.n  */
}

/* ppDiscardMPDU @ pp.o 00000008 size 40B bind GLOBAL
 * Calls: ppEnqueueTxDone, pp_post | Data refs: ppEnqueueTxDone, pp_post
 *   MMIO: none
 *   funcdb v3: 2 call(s), 2 ref(s); disasm: 2 call(s), 2 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t ppDiscardMPDU(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.ppDiscardMPDU; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_8:;
  /* 0008: entry a1, 32 */
  a8 = MEM32(a2 + 44); /* 000b: l32i.n a8, a2, 44 */
  a3 = 0x0; /* 000d: movi.n a3, 0 */
  a9 = 0x4; /* 000f: movi.n a9, 4 */
  a10 = a2; /* 0011: mov.n a10, a2 */
  MEM32(a8 + 20) = a3; /* 0013: s32i.n a3, a8, 20 */
  MEM8(a8 + 19) = a9; /* 0015: s8i a9, a8, 19 */
  MEMW(); /* 0018: memw  */
  MEMW(); /* 001b: memw  */
  a8 = (uint32_t)&ppEnqueueTxDone; /* 001e: l32r a8, 0 <ppDiscardMPDU-0x8> (0 <ppDiscardMPDU-0x8>) */ /* literal: GOT slot for ppEnqueueTxDone */
  ppEnqueueTxDone(a2, a3, a4, a5); /* call via literal slot */ /* 0021: callx8 a8 */
  a11 = a3; /* 0024: mov.n a11, a3 */
  a10 = 0x10; /* 0026: movi.n a10, 16 */
  a8 = (uint32_t)&pp_post; /* 0028: l32r a8, 4 <ppDiscardMPDU-0x4> (0 <ppDiscardMPDU-0x8>) */ /* literal: GOT slot for pp_post */
  pp_post(a2, a3, a4, a5); /* call via literal slot */ /* 002b: callx8 a8 */
  return (int32_t)a2; /* 002e: retw.n  */
}

/* ppProcTxSecFrame @ pp.o 0000001c size 292B bind GLOBAL
 * Calls: wifi_log[got] | Data refs: .rodata.CSWTCH$622, .rodata.pp_default_event_handler.str1.1, .rodata_wlog_error.70, wifi_log
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 1 call(s), 4 data ref(s)
 * Fidelity: medium - 111 instr, 10 branches, calls resolved */
int32_t ppProcTxSecFrame(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .wifi0iram.69; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_1c:;
  /* 001c: entry a1, 32 */
  a12 = MEM32(a2 + 44); /* 001f: l32i.n a12, a2, 44 */
  a11 = 0x4; /* 0021: movi.n a11, 4 */
  a8 = MEM32(a12 + 16); /* 0023: l32i.n a8, a12, 16 */
  a8 = (a8 >> 8) & 0xF; /* 0025: extui a8, a8, 8, 4 */
  a8 = a8 + (-1); /* 0028: addi.n a8, a8, -1 */
  a8 = (a8 >> 0) & 0xFF; /* 002a: extui a8, a8, 0, 8 */
  a10 = MEM32(a2 + 36); /* 002d: l32i a10, a2, 36 */
  if (a8 >= a11) goto L_3c; /* 0030: bgeu a8, a11, 3c <ppProcTxSecFrame+0x20> */
  a9 = (uint32_t)&lit_rodata_CSWTCH_622; /* 0033: l32r a9, 0 <ppProcTxSecFrame-0x1c> (0 <ppProcTxSecFrame-0x1c>) */ /* literal @0x0: .rodata.CSWTCH$622 */
  a8 = a9 + a8; /* 0036: add a8, a9, a8 */
  a11 = MEM8(a8 + 0); /* 0039: l8ui a11, a8, 0 */
L_3c:;
  a8 = MEM16(a2 + 22); /* 003c: l16ui a8, a2, 22 */
  a8 = a11 + a8; /* 003f: add.n a8, a11, a8 */
  a8 = (a8 >> 0) & 0xFFFF; /* 0041: extui a8, a8, 0, 16 */
  a13 = MEM32(a2 + 8); /* 0044: l32i.n a13, a2, 8 */
  MEMW(); /* 0046: memw  */
  a9 = MEM32(a13 + 0); /* 0049: l32i.n a9, a13, 0 */
  a9 = (a9 >> 12) & 0xFFF; /* 004b: extui a9, a9, 12, 12 */
  a9 = a9 + a11; /* 004e: add.n a9, a9, a11 */
  a9 = (a9 >> 0) & 0xFFF; /* 0050: extui a9, a9, 0, 12 */
  MEM16(a2 + 22) = a8; /* 0053: s16i a8, a2, 22 */
  MEMW(); /* 0056: memw  */
  a9 = a9 << (12 & 31); /* 0059: slli a9, a9, 12 */
  MEMW(); /* 005c: memw  */
  a11 = MEM32(a13 + 0); /* 005f: l32i.n a11, a13, 0 */
  a14 = 0xFF000FFF; /* 0061: l32r a14, 4 <ppProcTxSecFrame-0x18> (ff000fff <ppRxFragmentProc+0xff000f7f>) */ @0x4
  a11 = a11 & a14; /* 0064: and a11, a11, a14 */
  a9 = a11 | a9; /* 0067: or a9, a11, a9 */
  a11 = 0x1; /* 006a: movi.n a11, 1 */
  MEMW(); /* 006c: memw  */
  MEM32(a13 + 0) = a9; /* 006f: s32i.n a9, a13, 0 */
  a9 = 0x11; /* 0071: movi.n a9, 17 */
  a9 = 0x44000; /* 0073: slli a9, a9, 14 */
  a14 = MEM32(a12 + 0); /* 0076: l32i.n a14, a12, 0 */
  a14 = a14 & a9; /* 0078: and a14, a14, a9 */
  a9 = 0x1; /* 007b: movi.n a9, 1 */
  a9 = 0x40000; /* 007d: slli a9, a9, 18 */
  if (a14 == a9) goto L_86; /* 0080: beq a14, a9, 86 <ppProcTxSecFrame+0x6a> */
  goto L_124; /* 0083: j 124 <ppProcTxSecFrame+0x108> */
L_86:;
  if (a10 == 0) goto L_13c; /* 0086: beqz a10, 13c <ppProcTxSecFrame+0x120> */
  a14 = MEM32(a2 + 4); /* 0089: l32i.n a14, a2, 4 */
  a13 = 0x20000000; /* 008b: slli a13, a11, 29 */
  MEMW(); /* 008e: memw  */
  a9 = MEM32(a14 + 0); /* 0091: l32i.n a9, a14, 0 */
  a9 = a9 | a13; /* 0093: or a9, a9, a13 */
  a13 = 0xB; /* 0096: movi.n a13, 11 */
  a13 = 0xB00; /* 0098: slli a13, a13, 8 */
  MEMW(); /* 009b: memw  */
  MEM32(a14 + 0) = a9; /* 009e: s32i.n a9, a14, 0 */
  a9 = 0xF; /* 00a0: movi.n a9, 15 */
  a9 = 0xF00; /* 00a2: slli a9, a9, 8 */
  a12 = MEM32(a12 + 16); /* 00a5: l32i.n a12, a12, 16 */
  a13 = a12 & a13; /* 00a7: and a13, a12, a13 */
  a9 = a12 & a9; /* 00aa: and a9, a12, a9 */
  a12 = 0x0; /* 00ad: movi.n a12, 0 */
  a15 = 0x0; /* 00af: mov.n a15, a12 */
  if (a13 != 0) a15 = a11; /* 00b1: movnez a15, a11, a13 */
  a13 = a9 + ((0xfffffd00) << 8); /* 00b4: addmi a13, a9, 0xfffffd00 */
  if (a13 != 0) a12 = a11; /* 00b7: movnez a12, a11, a13 */
  if ((a15 & a12) == 0) goto L_df; /* 00ba: bnone a15, a12, df <ppProcTxSecFrame+0xc3> */
  a9 = a9 + ((0xfffff700) << 8); /* 00bd: addmi a9, a9, 0xfffff700 */
  if (a9 == 0) goto L_df; /* 00c0: beqz.n a9, df <ppProcTxSecFrame+0xc3> */
  a15 = 0x11A3; /* 00c2: l32r a15, 8 <ppProcTxSecFrame-0x14> (11a3 <ppRxFragmentProc+0x1123>) */ @0x8
  a12 = 0x1; /* 00c5: mov.n a12, a11 */
  a10 = 0x6; /* 00c7: movi a10, 6 */
  a11 = 0x800; /* 00ca: slli a11, a11, 11 */
  a14 = (uint32_t)&lit_rodata_pp_default_event_handler_str1_1; /* 00cd: l32r a14, c <ppProcTxSecFrame-0x10> (0 <ppProcTxSecFrame-0x1c>) */ /* literal @0xC: .rodata.pp_default_event_handler.str1.1 */
  a13 = (uint32_t)&lit_rodata_wlog_error_70; /* 00d0: l32r a13, 10 <ppProcTxSecFrame-0xc> (0 <ppProcTxSecFrame-0x1c>) */ /* literal @0x10: .rodata_wlog_error.70 */
  MEMW(); /* 00d3: memw  */
  a8 = (uint32_t)&wifi_log; /* 00d6: l32r a8, 18 <ppProcTxSecFrame-0x4> (0 <ppProcTxSecFrame-0x1c>) */ /* literal: GOT slot for wifi_log */
  wifi_log(a2, a3, a4, a5); /* call via literal slot */ /* 00d9: callx8 a8 */
L_dc:;
  goto L_dc; /* 00dc: j dc <ppProcTxSecFrame+0xc0> */
L_df:;
  a2 = MEM16(a2 + 20); /* 00df: l16ui a2, a2, 20 */
  a11 = 0xFFFFFFFF; /* 00e2: movi.n a11, -1 */
  a2 = a2 + (-4); /* 00e4: addi a2, a2, -4 */
  a8 = a8 + a2; /* 00e7: add.n a8, a8, a2 */
  a11 = 0xFFFFF000; /* 00e9: slli a11, a11, 12 */
  a9 = MEM32(a14 + 4); /* 00ec: l32i.n a9, a14, 4 */
  a12 = (a8 >> 0) & 0xFFF; /* 00ee: extui a12, a8, 0, 12 */
  a8 = 0x0; /* 00f1: movi.n a8, 0 */
  a2 = MEM32(a9 + 0); /* 00f3: l32i.n a2, a9, 0 */
  a2 = a2 & a11; /* 00f5: and a2, a2, a11 */
  a2 = a2 | a12; /* 00f8: or a2, a2, a12 */
  MEM32(a9 + 0) = a2; /* 00fb: s32i.n a2, a9, 0 */
  a2 = MEM16(a10 + 126); /* 00fd: l16ui a2, a10, 126 */
  a10 = a12 + (3); /* 0100: addi a10, a12, 3 */
  if (a10 >= a2) goto L_10c; /* 0103: bge a10, a2, 10c <ppProcTxSecFrame+0xf0> */
  a2 = a2 - a12; /* 0106: sub a2, a2, a12 */
  a8 = (a2 >> 2) & 0x7F; /* 0109: extui a8, a2, 2, 7 */
L_10c:;
  a2 = MEM32(a9 + 0); /* 010c: l32i.n a2, a9, 0 */
  a8 = a8 << (12 & 31); /* 010e: slli a8, a8, 12 */
  a10 = 0xFFC80FFF; /* 0111: l32r a10, 14 <ppProcTxSecFrame-0x8> (ffc80fff <ppRxFragmentProc+0xffc80f7f>) */ @0x14
  a2 = a2 & a10; /* 0114: and a2, a2, a10 */
  a2 = a2 | a8; /* 0117: or a2, a2, a8 */
  MEM32(a9 + 0) = a2; /* 011a: s32i.n a2, a9, 0 */
  MEMW(); /* 011c: memw  */
  goto L_134; /* 011f: j 134 <ppProcTxSecFrame+0x118> */
  /* 0122: .byte 00 */
  /* 0123: .byte 00 */
L_124:;
  MEMW(); /* 0124: memw  */
  a8 = MEM32(a13 + 0); /* 0127: l32i.n a8, a13, 0 */
  a11 = 0x0; /* 0129: slli a11, a11, 30 */
  a8 = a8 | a11; /* 012c: or a8, a8, a11 */
  MEMW(); /* 012f: memw  */
  MEM32(a13 + 0) = a8; /* 0132: s32i.n a8, a13, 0 */
L_134:;
  a2 = 0x0; /* 0134: movi.n a2, 0 */
  MEMW(); /* 0136: memw  */
  goto L_13e; /* 0139: j 13e <ppProcTxSecFrame+0x122> */
L_13c:;
  a2 = 0x0; /* 013c: mov.n a2, a11 */
L_13e:;
  return (int32_t)a2; /* 013e: retw.n  */
}

/* ppCalFrameTimes @ pp.o 0000000c size 88B bind GLOBAL
 * Calls: RC_GetBlockAckTime[got], RC_GetAckTime[got], RC_GetCtsTime[got] | Data refs: RC_GetBlockAckTime, RC_GetAckTime, RC_GetCtsTime
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 3 call(s), 3 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t ppCalFrameTimes(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .wifi0iram.71; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_c:;
  /* 000c: entry a1, 32 */
  a8 = MEM32(a2 + 44); /* 000f: l32i.n a8, a2, 44 */
  a12 = 0x1; /* 0011: movi.n a12, 1 */
  a12 = 0x80000; /* 0013: slli a12, a12, 19 */
  a3 = MEM32(a8 + 0); /* 0016: l32i a3, a8, 0 */
  a12 = a3 & a12; /* 0019: and a12, a3, a12 */
  a10 = MEM8(a8 + 12); /* 001c: l8ui a10, a8, 12 */
  if (a12 == 0) goto L_2c; /* 001f: beqz a12, 2c <ppCalFrameTimes+0x20> */
  a8 = (uint32_t)&RC_GetBlockAckTime; /* 0022: l32r a8, 0 <ppCalFrameTimes-0xc> (0 <ppCalFrameTimes-0xc>) */ /* literal: GOT slot for RC_GetBlockAckTime */
  RC_GetBlockAckTime(a2, a3, a4, a5); /* call via literal slot */ /* 0025: callx8 a8 */
  goto L_38; /* 0028: j 38 <ppCalFrameTimes+0x2c> */
  /* 002b: .byte 00 */
L_2c:;
  a8 = 0x402; /* 002c: movi a8, 0x402 */
  if ((a3 & a8) != 0) goto L_3a; /* 002f: bany a3, a8, 3a <ppCalFrameTimes+0x2e> */
  a8 = (uint32_t)&RC_GetAckTime; /* 0032: l32r a8, 4 <ppCalFrameTimes-0x8> (0 <ppCalFrameTimes-0xc>) */ /* literal: GOT slot for RC_GetAckTime */
  RC_GetAckTime(a2, a3, a4, a5); /* call via literal slot */ /* 0035: callx8 a8 */
L_38:;
  a12 = a10; /* 0038: mov.n a12, a10 */
L_3a:;
  a3 = MEM32(a2 + 44); /* 003a: l32i.n a3, a2, 44 */
  a11 = MEM16(a2 + 22); /* 003c: l16ui a11, a2, 22 */
  a2 = MEM16(a2 + 20); /* 003f: l16ui a2, a2, 20 */
  a11 = a11 + a2; /* 0042: add.n a11, a11, a2 */
  a11 = (a11 >> 0) & 0xFFFF; /* 0044: extui a11, a11, 0, 16 */
  a10 = MEM8(a3 + 12); /* 0047: l8ui a10, a3, 12 */
  MEM16(a3 + 10) = a12; /* 004a: s16i a12, a3, 10 */
  MEMW(); /* 004d: memw  */
  MEMW(); /* 0050: memw  */
  a8 = (uint32_t)&RC_GetCtsTime; /* 0053: l32r a8, 8 <ppCalFrameTimes-0x4> (0 <ppCalFrameTimes-0xc>) */ /* literal: GOT slot for RC_GetCtsTime */
  RC_GetCtsTime(a2, a3, a4, a5); /* call via literal slot */ /* 0056: callx8 a8 */
  MEM16(a3 + 14) = a10; /* 0059: s16i a10, a3, 14 */
  MEMW(); /* 005c: memw  */
  MEMW(); /* 005f: memw  */
  return (int32_t)a2; /* 0062: retw.n  */
}

/* ppTxPkt @ pp.o 00000060 size 475B bind GLOBAL
 * Calls: ic_interface_enabled[got], wifi_log[got], wifi_log[got], ppTxProtoProc[got], ppProcTxSecFrame[got], rcGetSched[got], ppCalFrameTimes[got], ppMapTxQueue[got], lmacIsIdle[got], pp_post[got], wifi_log[got], esf_buf_recycle[got], pp_process_hmac_waiting_txq[got] | Data refs: ic_interface_enabled, .rodata_wlog_warning.13, wifi_log, .rodata.pp_default_event_handler.str1.1, .rodata_wlog_error.14, ppTxProtoProc, ppProcTxSecFrame, rcGetSched, ppCalFrameTimes, ppMapTxQueue, g_mesh_is_started, g_mesh_is_root, g_mesh_init_ps_type, g_osi_funcs_p, g_wifi_mac_time_delta, pTxRx, lmacIsIdle, pp_post, .rodata_wlog_warning.15, esf_buf_recycle, pp_process_hmac_waiting_txq
 *   MMIO: 0x3FF73C00
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 13 call(s), 21 data ref(s)
 * Fidelity: medium - 183 instr, 28 branches, 2 indirect; flow + direct calls mapped, GOT-indirects enumerated (verified against section disasm) */
int32_t ppTxPkt(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .wifi0iram.12; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_60:;
  /* 0060: entry a1, 32 */
  a4 = MEM32(a2 + 44); /* 0063: l32i.n a4, a2, 44 */
  a3 = (a3 >> 0) & 0xFF; /* 0065: extui a3, a3, 0, 8 */
  a10 = MEM32(a4 + 16); /* 0068: l32i a10, a4, 16 */
  a10 = (a10 >> 18) & 0x3; /* 006b: extui a10, a10, 18, 2 */
  a8 = (uint32_t)&ic_interface_enabled; /* 006e: l32r a8, 2c <ppTxPkt-0x34> (0 <ppTxPkt-0x60>) */ /* literal: GOT slot for ic_interface_enabled */
  ic_interface_enabled(a2, a3, a4, a5); /* call via literal slot */ /* 0071: callx8 a8 */
  a4 = MEM32(a2 + 44); /* 0074: l32i.n a4, a2, 44 */
  if (a10 != 0) goto L_90; /* 0076: bnez.n a10, 90 <ppTxPkt+0x30> */
  a12 = 0x2; /* 0078: movi.n a12, 2 */
  a11 = 0x40; /* 007a: movi.n a11, 64 */
  a10 = 0x6; /* 007c: movi.n a10, 6 */
  a14 = MEM32(a4 + 16); /* 007e: l32i.n a14, a4, 16 */
  a14 = (a14 >> 18) & 0x3; /* 0080: extui a14, a14, 18, 2 */
  a13 = (uint32_t)&lit_rodata_wlog_warning_13; /* 0083: l32r a13, 0 <ppTxPkt-0x60> (0 <ppTxPkt-0x60>) */ /* literal @0x0: .rodata_wlog_warning.13 */
  a8 = (uint32_t)&wifi_log; /* 0086: l32r a8, 30 <ppTxPkt-0x30> (0 <ppTxPkt-0x60>) */ /* literal: GOT slot for wifi_log */
  wifi_log(a2, a3, a4, a5); /* call via literal slot */ /* 0089: callx8 a8 */
  goto L_221; /* 008c: j 221 <ppTxPkt+0x1c1> */
  /* 008f: .byte 00 */
L_90:;
  a10 = MEM32(a4 + 4); /* 0090: l32i.n a10, a4, 4 */
  a8 = 0x4; /* 0092: movi.n a8, 4 */
  a4 = (a10 >> 0) & 0xF; /* 0094: extui a4, a10, 0, 4 */
  if (a4 >= 8) goto L_b5; /* 0097: bgeui a4, 8, b5 <ppTxPkt+0x55> */
  a9 = 0x9; /* 009a: movi.n a9, 9 */
  /* 009c: ssr a4 */ /* UNMODELED: a4 clobbered */
  /* 009f: srl a9, a9 */ /* UNMODELED: a9 clobbered */
  a9 = (a9 >> 0) & 0x1; /* 00a2: extui a9, a9, 0, 1 */
  a8 = 0x2; /* 00a5: movi.n a8, 2 */
  if (a9 != 0) goto L_b5; /* 00a7: bnez.n a9, b5 <ppTxPkt+0x55> */
  a8 = 0x3; /* 00a9: movi.n a8, 3 */
  if (a4 < a8) goto L_b5; /* 00ab: bltu a4, a8, b5 <ppTxPkt+0x55> */
  a8 = 0x1; /* 00ae: movi.n a8, 1 */
  if (a4 < 6) goto L_b5; /* 00b0: bltui a4, 6, b5 <ppTxPkt+0x55> */
  a8 = a9; /* 00b3: mov.n a8, a9 */
L_b5:;
  a10 = (a10 >> 4) & 0xF; /* 00b5: extui a10, a10, 4, 4 */
  if (a10 == a8) goto L_d5; /* 00b8: beq a10, a8, d5 <ppTxPkt+0x75> */
  a12 = 0x1; /* 00bb: movi.n a12, 1 */
  a14 = (uint32_t)&lit_rodata_pp_default_event_handler_str1_1; /* 00bd: l32r a14, 4 <ppTxPkt-0x5c> (0 <ppTxPkt-0x60>) */ /* literal @0x4: .rodata.pp_default_event_handler.str1.1 */
  a15 = 0x395; /* 00c0: movi a15, 0x395 */
  a11 = 0x800; /* 00c3: slli a11, a12, 11 */
  a10 = 0x6; /* 00c6: movi.n a10, 6 */
  a13 = (uint32_t)&lit_rodata_wlog_error_14; /* 00c8: l32r a13, 8 <ppTxPkt-0x58> (0 <ppTxPkt-0x60>) */ /* literal @0x8: .rodata_wlog_error.14 */
  a8 = (uint32_t)&wifi_log; /* 00cb: l32r a8, 34 <ppTxPkt-0x2c> (0 <ppTxPkt-0x60>) */ /* literal: GOT slot for wifi_log */
  wifi_log(a2, a3, a4, a5); /* call via literal slot */ /* 00ce: callx8 a8 */
L_d1:;
  goto L_d1; /* 00d1: j d1 <ppTxPkt+0x71> */
  /* 00d4: .byte 00 */
L_d5:;
  a10 = a2; /* 00d5: mov.n a10, a2 */
  a8 = (uint32_t)&ppTxProtoProc; /* 00d7: l32r a8, 38 <ppTxPkt-0x28> (0 <ppTxPkt-0x60>) */ /* literal: GOT slot for ppTxProtoProc */
  ppTxProtoProc(a2, a3, a4, a5); /* call via literal slot */ /* 00da: callx8 a8 */
  a10 = a2; /* 00dd: mov.n a10, a2 */
  a8 = (uint32_t)&ppProcTxSecFrame; /* 00df: l32r a8, 3c <ppTxPkt-0x24> (0 <ppTxPkt-0x60>) */ /* literal: GOT slot for ppProcTxSecFrame */
  ppProcTxSecFrame(a2, a3, a4, a5); /* call via literal slot */ /* 00e2: callx8 a8 */
  if (a10 != 1) goto L_eb; /* 00e5: bnei a10, 1, eb <ppTxPkt+0x8b> */
  goto L_221; /* 00e8: j 221 <ppTxPkt+0x1c1> */
L_eb:;
  a11 = MEM32(a2 + 44); /* 00eb: l32i.n a11, a2, 44 */
  a10 = MEM32(a2 + 36); /* 00ed: l32i.n a10, a2, 36 */
  a8 = (uint32_t)&rcGetSched; /* 00ef: l32r a8, 40 <ppTxPkt-0x20> (0 <ppTxPkt-0x60>) */ /* literal: GOT slot for rcGetSched */
  rcGetSched(a2, a3, a4, a5); /* call via literal slot */ /* 00f2: callx8 a8 */
  a10 = a2; /* 00f5: mov.n a10, a2 */
  a8 = (uint32_t)&ppCalFrameTimes; /* 00f7: l32r a8, 44 <ppTxPkt-0x1c> (0 <ppTxPkt-0x60>) */ /* literal: GOT slot for ppCalFrameTimes */
  ppCalFrameTimes(a2, a3, a4, a5); /* call via literal slot */ /* 00fa: callx8 a8 */
  a10 = a2; /* 00fd: mov.n a10, a2 */
  a8 = (uint32_t)&ppMapTxQueue; /* 00ff: l32r a8, 48 <ppTxPkt-0x18> (0 <ppTxPkt-0x60>) */ /* literal: GOT slot for ppMapTxQueue */
  ppMapTxQueue(a2, a3, a4, a5); /* call via literal slot */ /* 0102: callx8 a8 */
  if (a10 != 0) goto L_1a1; /* 0105: bnez a10, 1a1 <ppTxPkt+0x141> */
  a4 = (uint32_t)&g_mesh_is_started; /* 0108: l32r a4, c <ppTxPkt-0x54> (0 <ppTxPkt-0x60>) */ /* literal @0xC: g_mesh_is_started */
  a4 = MEM8(a4 + 0); /* 010b: l8ui a4, a4, 0 */
  if (a4 == 0) goto L_134; /* 010e: beqz.n a4, 134 <ppTxPkt+0xd4> */
  a4 = (uint32_t)&g_mesh_is_root; /* 0110: l32r a4, 10 <ppTxPkt-0x50> (0 <ppTxPkt-0x60>) */ /* literal @0x10: g_mesh_is_root */
  MEMW(); /* 0113: memw  */
  a4 = MEM8(a4 + 0); /* 0116: l8ui a4, a4, 0 */
  a4 = (a4 >> 0) & 0xFF; /* 0119: extui a4, a4, 0, 8 */
  if (a4 != 0) goto L_134; /* 011c: bnez.n a4, 134 <ppTxPkt+0xd4> */
  a4 = (uint32_t)&g_mesh_init_ps_type; /* 011e: l32r a4, 14 <ppTxPkt-0x4c> (0 <ppTxPkt-0x60>) */ /* literal @0x14: g_mesh_init_ps_type */
  a4 = MEM32(a4 + 0); /* 0121: l32i.n a4, a4, 0 */
  if (a4 == 0) goto L_134; /* 0123: beqz.n a4, 134 <ppTxPkt+0xd4> */
  a4 = (uint32_t)&g_osi_funcs_p; /* 0125: l32r a4, 18 <ppTxPkt-0x48> (0 <ppTxPkt-0x60>) */ /* literal @0x18: g_osi_funcs_p */
  a4 = MEM32(a4 + 0); /* 0128: l32i.n a4, a4, 0 */
  a10 = MEM32(a4 + 272); /* 012a: l32i a10, a4, 0x110 */
  ((int32_t(*)())a10)(a2, a3, a4, a5); /* 012d: callx8 a10 */ /* indirect */
  goto L_143; /* 0130: j 143 <ppTxPkt+0xe3> */
  /* 0133: .byte 00 */
L_134:;
  a4 = 0x3FF73C00; /* 0134: l32r a4, 1c <ppTxPkt-0x44> (3ff73c00 <ppRxFragmentProc+0x3ff73b80>) */ /* MMIO base */ @0x1C
  MEMW(); /* 0137: memw  */
  a10 = REG32(0x3FF73C00); /* 013a: l32i.n a10, a4, 0 */ /* MMIO read: base 0x3FF73C00+0 */
  a4 = (uint32_t)&g_wifi_mac_time_delta; /* 013c: l32r a4, 20 <ppTxPkt-0x40> (0 <ppTxPkt-0x60>) */ /* literal @0x20: g_wifi_mac_time_delta */
  a4 = MEM32(a4 + 0); /* 013f: l32i.n a4, a4, 0 */
  a10 = a10 + a4; /* 0141: add.n a10, a10, a4 */
L_143:;
  a4 = 0x0; /* 0143: movi.n a4, 0 */
  a9 = MEM32(a2 + 44); /* 0145: l32i.n a9, a2, 44 */
  a8 = (uint32_t)&pTxRx; /* 0147: l32r a8, 24 <ppTxPkt-0x3c> (0 <ppTxPkt-0x60>) */ /* literal @0x24: pTxRx */
  MEM32(a9 + 24) = a10; /* 014a: s32i.n a10, a9, 24 */
  a10 = MEM32(a8 + 0); /* 014c: l32i.n a10, a8, 0 */
  a8 = MEM32(a9 + 16); /* 014e: l32i.n a8, a9, 16 */
  a8 = (a8 >> 20) & 0xF; /* 0150: extui a8, a8, 20, 4 */
  a8 = (a8 << 2) + a8; /* 0153: addx2 a8, a8, a8 */
  a8 = a8 << (4 & 31); /* 0156: slli a8, a8, 4 */
  a8 = a10 + a8; /* 0159: add.n a8, a10, a8 */
  a8 = MEM32(a8 + 36); /* 015b: l32i.n a8, a8, 36 */
  MEM32(a2 + 40) = a4; /* 015d: s32i.n a4, a2, 40 */
  MEM32(a8 + 0) = a2; /* 015f: s32i.n a2, a8, 0 */
  a8 = MEM32(a9 + 16); /* 0161: l32i.n a8, a9, 16 */
  a8 = (a8 >> 20) & 0xF; /* 0163: extui a8, a8, 20, 4 */
  a8 = (a8 << 2) + a8; /* 0166: addx2 a8, a8, a8 */
  a8 = a8 << (4 & 31); /* 0169: slli a8, a8, 4 */
  a10 = a10 + a8; /* 016c: add.n a10, a10, a8 */
  a8 = a2 + (40); /* 016e: addi a8, a2, 40 */
  MEM32(a10 + 36) = a8; /* 0171: s32i.n a8, a10, 36 */
  if (a3 != a4) goto L_17e; /* 0173: bne a3, a4, 17e <ppTxPkt+0x11e> */
L_176:;
  a2 = 0x0; /* 0176: movi.n a2, 0 */
  MEMW(); /* 0178: memw  */
  goto L_239; /* 017b: j 239 <ppTxPkt+0x1d9> */
L_17e:;
  a10 = MEM32(a9 + 4); /* 017e: l32i.n a10, a9, 4 */
  a10 = (a10 >> 4) & 0xF; /* 0180: extui a10, a10, 4, 4 */
  a8 = (uint32_t)&lmacIsIdle; /* 0183: l32r a8, 4c <ppTxPkt-0x14> (0 <ppTxPkt-0x60>) */ /* literal: GOT slot for lmacIsIdle */
  lmacIsIdle(a2, a3, a4, a5); /* call via literal slot */ /* 0186: callx8 a8 */
  if (a10 == 0) goto L_176; /* 0189: beqz a10, 176 <ppTxPkt+0x116> */
  a2 = MEM32(a2 + 44); /* 018c: l32i.n a2, a2, 44 */
  a11 = a4; /* 018e: mov.n a11, a4 */
  a10 = MEM32(a2 + 4); /* 0190: l32i a10, a2, 4 */
  a10 = (a10 >> 4) & 0xF; /* 0193: extui a10, a10, 4, 4 */
  a8 = (uint32_t)&pp_post; /* 0196: l32r a8, 50 <ppTxPkt-0x10> (0 <ppTxPkt-0x60>) */ /* literal: GOT slot for pp_post */
  pp_post(a2, a3, a4, a5); /* call via literal slot */ /* 0199: callx8 a8 */
  a2 = a10; /* 019c: mov.n a2, a10 */
  goto L_239; /* 019e: j 239 <ppTxPkt+0x1d9> */
L_1a1:;
  if (a10 != 1) goto L_20c; /* 01a1: bnei a10, 1, 20c <ppTxPkt+0x1ac> */
  a3 = (uint32_t)&g_mesh_is_started; /* 01a4: l32r a3, c <ppTxPkt-0x54> (0 <ppTxPkt-0x60>) */ /* literal @0xC: g_mesh_is_started */
  a3 = MEM8(a3 + 0); /* 01a7: l8ui a3, a3, 0 */
  if (a3 == 0) goto L_1cf; /* 01aa: beqz.n a3, 1cf <ppTxPkt+0x16f> */
  a3 = (uint32_t)&g_mesh_is_root; /* 01ac: l32r a3, 10 <ppTxPkt-0x50> (0 <ppTxPkt-0x60>) */ /* literal @0x10: g_mesh_is_root */
  MEMW(); /* 01af: memw  */
  a3 = MEM8(a3 + 0); /* 01b2: l8ui a3, a3, 0 */
  a3 = (a3 >> 0) & 0xFF; /* 01b5: extui a3, a3, 0, 8 */
  if (a3 != 0) goto L_1cf; /* 01b8: bnez.n a3, 1cf <ppTxPkt+0x16f> */
  a3 = (uint32_t)&g_mesh_init_ps_type; /* 01ba: l32r a3, 14 <ppTxPkt-0x4c> (0 <ppTxPkt-0x60>) */ /* literal @0x14: g_mesh_init_ps_type */
  a3 = MEM32(a3 + 0); /* 01bd: l32i.n a3, a3, 0 */
  if (a3 == 0) goto L_1cf; /* 01bf: beqz.n a3, 1cf <ppTxPkt+0x16f> */
  a3 = (uint32_t)&g_osi_funcs_p; /* 01c1: l32r a3, 18 <ppTxPkt-0x48> (0 <ppTxPkt-0x60>) */ /* literal @0x18: g_osi_funcs_p */
  a3 = MEM32(a3 + 0); /* 01c4: l32i.n a3, a3, 0 */
  a10 = MEM32(a3 + 272); /* 01c6: l32i a10, a3, 0x110 */
  ((int32_t(*)())a10)(a2, a3, a4, a5); /* 01c9: callx8 a10 */ /* indirect */
  goto L_1de; /* 01cc: j 1de <ppTxPkt+0x17e> */
L_1cf:;
  a3 = 0x3FF73C00; /* 01cf: l32r a3, 1c <ppTxPkt-0x44> (3ff73c00 <ppRxFragmentProc+0x3ff73b80>) */ /* MMIO base */ @0x1C
  MEMW(); /* 01d2: memw  */
  a10 = REG32(0x3FF73C00); /* 01d5: l32i.n a10, a3, 0 */ /* MMIO read: base 0x3FF73C00+0 */
  a3 = (uint32_t)&g_wifi_mac_time_delta; /* 01d7: l32r a3, 20 <ppTxPkt-0x40> (0 <ppTxPkt-0x60>) */ /* literal @0x20: g_wifi_mac_time_delta */
  a3 = MEM32(a3 + 0); /* 01da: l32i.n a3, a3, 0 */
  a10 = a10 + a3; /* 01dc: add.n a10, a10, a3 */
L_1de:;
  a4 = MEM32(a2 + 44); /* 01de: l32i.n a4, a2, 44 */
  a3 = (uint32_t)&pTxRx; /* 01e0: l32r a3, 24 <ppTxPkt-0x3c> (0 <ppTxPkt-0x60>) */ /* literal @0x24: pTxRx */
  a8 = MEM32(a3 + 0); /* 01e3: l32i.n a8, a3, 0 */
  a3 = MEM32(a4 + 16); /* 01e5: l32i.n a3, a4, 16 */
  a3 = (a3 >> 18) & 0x3; /* 01e7: extui a3, a3, 18, 2 */
  a3 = (a3 << 8) + a8; /* 01ea: addx8 a3, a3, a8 */
  MEM32(a4 + 24) = a10; /* 01ed: s32i.n a10, a4, 24 */
  a10 = 0x0; /* 01ef: movi.n a10, 0 */
  a3 = MEM32(a3 + 824); /* 01f1: l32i a3, a3, 0x338 */
  MEM32(a2 + 40) = a10; /* 01f4: s32i.n a10, a2, 40 */
  MEM32(a3 + 0) = a2; /* 01f6: s32i.n a2, a3, 0 */
  a2 = a2 + (40); /* 01f8: addi a2, a2, 40 */
  a3 = MEM32(a4 + 16); /* 01fb: l32i.n a3, a4, 16 */
  a3 = (a3 >> 18) & 0x3; /* 01fd: extui a3, a3, 18, 2 */
  a3 = (a3 << 8) + a8; /* 0200: addx8 a3, a3, a8 */
  MEM32(a3 + 824) = a2; /* 0203: s32i a2, a3, 0x338 */
  MEMW(); /* 0206: memw  */
  goto L_176; /* 0209: j 176 <ppTxPkt+0x116> */
L_20c:;
  if (a10 == 2) goto L_212; /* 020c: beqi a10, 2, 212 <ppTxPkt+0x1b2> */
  goto L_176; /* 020f: j 176 <ppTxPkt+0x116> */
L_212:;
  a13 = (uint32_t)&lit_rodata_wlog_warning_15; /* 0212: l32r a13, 28 <ppTxPkt-0x38> (0 <ppTxPkt-0x60>) */ /* literal @0x28: .rodata_wlog_warning.15 */
  a12 = 0x0; /* 0215: mov.n a12, a10 */
  a11 = 0x40; /* 0217: movi.n a11, 64 */
  a10 = 0x6; /* 0219: movi.n a10, 6 */
  a8 = (uint32_t)&wifi_log; /* 021b: l32r a8, 54 <ppTxPkt-0xc> (0 <ppTxPkt-0x60>) */ /* literal: GOT slot for wifi_log */
  wifi_log(a2, a3, a4, a5); /* call via literal slot */ /* 021e: callx8 a8 */
L_221:;
  a3 = MEM8(a2 + 26); /* 0221: l8ui a3, a2, 26 */
  a10 = a2 | a2; /* 0224: or a10, a2, a2 */
  a2 = 0x1; /* 0227: movi a2, 1 */
  a8 = (uint32_t)&esf_buf_recycle; /* 022a: l32r a8, 58 <ppTxPkt-0x8> (0 <ppTxPkt-0x60>) */ /* literal: GOT slot for esf_buf_recycle */
  esf_buf_recycle(a2, a3, a4, a5); /* call via literal slot */ /* 022d: callx8 a8 */
  if (a3 != a2) goto L_239; /* 0230: bne a3, a2, 239 <ppTxPkt+0x1d9> */
  a8 = (uint32_t)&pp_process_hmac_waiting_txq; /* 0233: l32r a8, 5c <ppTxPkt-0x4> (0 <ppTxPkt-0x60>) */ /* literal: GOT slot for pp_process_hmac_waiting_txq */
  pp_process_hmac_waiting_txq(a2, a3, a4, a5); /* call via literal slot */ /* 0236: callx8 a8 */
L_239:;
  return (int32_t)a2; /* 0239: retw.n  */
}

/* ppPrepareBarFrame @ pp.o 0000001c size 188B bind GLOBAL
 * Calls: esf_buf_alloc, ppCalFrameTimes, rcGetSched, rc_get_trc_by_index, wifi_log | Data refs: .rodata_wlog_warning.32, bars, esf_buf_alloc, ppCalFrameTimes, rcGetSched, rc_get_trc_by_index, wifi_log
 *   MMIO: none
 *   funcdb v3: 5 call(s), 7 ref(s); disasm: 5 call(s), 7 data ref(s)
 * Fidelity: medium - 72 instr, 2 branches, calls resolved */
int32_t ppPrepareBarFrame(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.ppPrepareBarFrame; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_1c:;
  /* 001c: entry a1, 32 */
  a12 = 0x0; /* 001f: movi.n a12, 0 */
  a11 = 0x5; /* 0021: movi a11, 5 */
  a10 = 0x0; /* 0024: mov.n a10, a12 */
  a8 = (uint32_t)&esf_buf_alloc; /* 0026: l32r a8, 8 <ppPrepareBarFrame-0x14> (0 <ppPrepareBarFrame-0x1c>) */ /* literal: GOT slot for esf_buf_alloc */
  esf_buf_alloc(a2, a3, a4, a5); /* call via literal slot */ /* 0029: callx8 a8 */
  a3 = (a2 >> 0) & 0xFF; /* 002c: extui a3, a2, 0, 8 */
  a2 = 0x0; /* 002f: mov.n a2, a10 */
  if (a10 != 0) goto L_48; /* 0031: bnez.n a10, 48 <ppPrepareBarFrame+0x2c> */
  a13 = (uint32_t)&lit_rodata_wlog_warning_32; /* 0033: l32r a13, 0 <ppPrepareBarFrame-0x1c> (0 <ppPrepareBarFrame-0x1c>) */ /* literal @0x0: .rodata_wlog_warning.32 */
  a12 = 0x2; /* 0036: movi.n a12, 2 */
  a11 = 0x40; /* 0038: movi a11, 64 */
  a10 = 0x6; /* 003b: movi a10, 6 */
  a8 = (uint32_t)&wifi_log; /* 003e: l32r a8, c <ppPrepareBarFrame-0x10> (0 <ppPrepareBarFrame-0x1c>) */ /* literal: GOT slot for wifi_log */
  wifi_log(a2, a3, a4, a5); /* call via literal slot */ /* 0041: callx8 a8 */
  goto L_d3; /* 0044: j d3 <ppPrepareBarFrame+0xb7> */
  /* 0047: .byte 00 */
L_48:;
  a8 = (uint32_t)&bars; /* 0048: l32r a8, 4 <ppPrepareBarFrame-0x18> (0 <ppPrepareBarFrame-0x1c>) */ /* literal @0x4: bars */
  a9 = (a3 << 8) + a3; /* 004b: addx8 a9, a3, a3 */
  a9 = (a9 << 4) + a8; /* 004e: addx4 a9, a9, a8 */
  a4 = 0x18; /* 0051: movi.n a4, 24 */
  a3 = (a3 >> 0) & 0xF; /* 0053: extui a3, a3, 0, 4 */
  MEM16(a10 + 22) = a4; /* 0056: s16i a4, a10, 22 */
  MEMW(); /* 0059: memw  */
  a4 = a9; /* 005c: mov.n a4, a9 */
  a3 = a3 << (4 & 31); /* 005e: slli a3, a3, 4 */
  a11 = 0x0; /* 0061: movi.n a11, 0 */
  MEM32(a10 + 4) = a9; /* 0063: s32i.n a9, a10, 4 */
  a10 = 0xFFFFFFFF; /* 0065: movi.n a10, -1 */
  a10 = 0xFFFFF000; /* 0067: slli a10, a10, 12 */
  MEMW(); /* 006a: memw  */
  a8 = MEM32(a9 + 0); /* 006d: l32i.n a8, a9, 0 */
  a8 = a8 & a10; /* 006f: and a8, a8, a10 */
  a10 = 0x18; /* 0072: movi.n a10, 24 */
  a8 = a8 | a10; /* 0074: or a8, a8, a10 */
  MEMW(); /* 0077: memw  */
  MEM32(a9 + 0) = a8; /* 007a: s32i.n a8, a9, 0 */
  a8 = 0x1; /* 007c: movi.n a8, 1 */
  a10 = 0xFFFFFF0F; /* 007e: movi a10, -241 */
  MEM32(a2 + 8) = a9; /* 0081: s32i.n a9, a2, 8 */
  a9 = MEM32(a2 + 44); /* 0083: l32i.n a9, a2, 44 */
  MEM16(a2 + 12) = a8; /* 0085: s16i a8, a2, 12 */
  MEMW(); /* 0088: memw  */
  a8 = MEM32(a9 + 4); /* 008b: l32i.n a8, a9, 4 */
  a8 = a8 & a10; /* 008d: and a8, a8, a10 */
  a3 = a8 | a3; /* 0090: or a3, a8, a3 */
  a10 = 0x0; /* 0093: mov.n a10, a11 */
  MEM32(a9 + 4) = a3; /* 0095: s32i.n a3, a9, 4 */
  MEMW(); /* 0097: memw  */
  a8 = (uint32_t)&rc_get_trc_by_index; /* 009a: l32r a8, 10 <ppPrepareBarFrame-0xc> (0 <ppPrepareBarFrame-0x1c>) */ /* literal: GOT slot for rc_get_trc_by_index */
  rc_get_trc_by_index(a2, a3, a4, a5); /* call via literal slot */ /* 009d: callx8 a8 */
  a11 = MEM32(a2 + 44); /* 00a0: l32i.n a11, a2, 44 */
  MEM32(a2 + 36) = a10; /* 00a2: s32i.n a10, a2, 36 */
  MEMW(); /* 00a4: memw  */
  a8 = (uint32_t)&rcGetSched; /* 00a7: l32r a8, 14 <ppPrepareBarFrame-0x8> (0 <ppPrepareBarFrame-0x1c>) */ /* literal: GOT slot for rcGetSched */
  rcGetSched(a2, a3, a4, a5); /* call via literal slot */ /* 00aa: callx8 a8 */
  a10 = a2; /* 00ad: mov.n a10, a2 */
  a8 = (uint32_t)&ppCalFrameTimes; /* 00af: l32r a8, 18 <ppPrepareBarFrame-0x4> (0 <ppPrepareBarFrame-0x1c>) */ /* literal: GOT slot for ppCalFrameTimes */
  ppCalFrameTimes(a2, a3, a4, a5); /* call via literal slot */ /* 00b2: callx8 a8 */
  a9 = 0xFFFFFFF9; /* 00b5: movi.n a9, -7 */
  a3 = MEM16(a2 + 22); /* 00b7: l16ui a3, a2, 22 */
  a9 = 0xFFC80000; /* 00ba: slli a9, a9, 19 */
  a3 = (a3 >> 0) & 0xFFF; /* 00bd: extui a3, a3, 0, 12 */
  a8 = MEM32(a4 + 12); /* 00c0: l32i.n a8, a4, 12 */
  a8 = a8 & a9; /* 00c2: and a8, a8, a9 */
  a3 = a3 | a8; /* 00c5: or a3, a3, a8 */
  MEM32(a4 + 12) = a3; /* 00c8: s32i.n a3, a4, 12 */
  a3 = 0x84; /* 00ca: movi a3, 132 */
  MEM16(a4 + 16) = a3; /* 00cd: s16i a3, a4, 16 */
  MEMW(); /* 00d0: memw  */
L_d3:;
  MEMW(); /* 00d3: memw  */
  return (int32_t)a2; /* 00d6: retw.n  */
}

/* pp_attach @ pp.o 00000030 size 214B bind GLOBAL
 * Calls: dbg_lmac_init, esf_buf_setup, memset, ppInitTxq, ppPrepareBarFrame, pp_deattach | Data refs: TxRxCxt, bars, dbg_lmac_init, esf_buf_setup, memset, pTxRx, ppInitTxq, ppPrepareBarFrame, pp_deattach, pp_sig_cnt
 *   MMIO: none
 *   funcdb v3: 6 call(s), 10 ref(s); disasm: 8 call(s), 10 data ref(s)
 * Fidelity: medium - 79 instr, 3 branches, calls resolved */
int32_t pp_attach(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pp_attach; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_30:;
  /* 0030: entry a1, 32 */
  a10 = (uint32_t)&pp_sig_cnt; /* 0033: l32r a10, 0 <pp_attach-0x30> (0 <pp_attach-0x30>) */ /* literal @0x0: pp_sig_cnt */
  a12 = 0x1E; /* 0036: movi.n a12, 30 */
  a11 = 0x0; /* 0038: movi a11, 0 */
  a8 = (uint32_t)&memset; /* 003b: l32r a8, 10 <pp_attach-0x20> (0 <pp_attach-0x30>) */ /* literal: GOT slot for memset */
  memset(a2, a3, a4, a5); /* call via literal slot */ /* 003e: callx8 a8 */
  a12 = 0x90; /* 0041: movi a12, 144 */
  a10 = (uint32_t)&bars; /* 0044: l32r a10, 4 <pp_attach-0x2c> (0 <pp_attach-0x30>) */ /* literal @0x4: bars */
  a11 = 0x0; /* 0047: movi a11, 0 */
  a8 = (uint32_t)&memset; /* 004a: l32r a8, 14 <pp_attach-0x1c> (0 <pp_attach-0x30>) */ /* literal: GOT slot for memset */
  memset(a2, a3, a4, a5); /* call via literal slot */ /* 004d: callx8 a8 */
  a12 = 0x3CC; /* 0050: movi a12, 0x3cc */
  a11 = 0x0; /* 0053: movi.n a11, 0 */
  a10 = (uint32_t)&TxRxCxt; /* 0055: l32r a10, 8 <pp_attach-0x28> (0 <pp_attach-0x30>) */ /* literal @0x8: TxRxCxt */
  a5 = 0x640; /* 0058: movi a5, 0x640 */
  a8 = (uint32_t)&memset; /* 005b: l32r a8, 18 <pp_attach-0x18> (0 <pp_attach-0x30>) */ /* literal: GOT slot for memset */
  memset(a2, a3, a4, a5); /* call via literal slot */ /* 005e: callx8 a8 */
  a6 = 0xC8; /* 0061: movi a6, 200 */
  a4 = (uint32_t)&pTxRx; /* 0064: l32r a4, c <pp_attach-0x24> (0 <pp_attach-0x30>) */ /* literal @0xC: pTxRx */
  a3 = MEM32(a4 + 0); /* 0067: l32i.n a3, a4, 0 */
  MEM32(a3 + 964) = a5; /* 0069: s32i a5, a3, 0x3c4 */
  MEMW(); /* 006c: memw  */
  a8 = (uint32_t)&dbg_lmac_init; /* 006f: l32r a8, 1c <pp_attach-0x14> (0 <pp_attach-0x30>) */ /* literal: GOT slot for dbg_lmac_init */
  dbg_lmac_init(a2, a3, a4, a5); /* call via literal slot */ /* 0072: callx8 a8 */
  a8 = (uint32_t)&ppInitTxq; /* 0075: l32r a8, 20 <pp_attach-0x10> (0 <pp_attach-0x30>) */ /* literal: GOT slot for ppInitTxq */
  ppInitTxq(a2, a3, a4, a5); /* call via literal slot */ /* 0078: callx8 a8 */
  a9 = 0x334; /* 007b: movi a9, 0x334 */
  a3 = 0x0; /* 007e: movi.n a3, 0 */
  a8 = MEM32(a4 + 0); /* 0080: l32i.n a8, a4, 0 */
  a10 = a2; /* 0082: mov.n a10, a2 */
  a9 = a8 + a9; /* 0084: add.n a9, a8, a9 */
  MEM32(a8 + 824) = a9; /* 0086: s32i a9, a8, 0x338 */
  a9 = 0x33C; /* 0089: movi a9, 0x33c */
  a9 = a8 + a9; /* 008c: add.n a9, a8, a9 */
  MEM32(a8 + 832) = a9; /* 008e: s32i a9, a8, 0x340 */
  a9 = 0x344; /* 0091: movi a9, 0x344 */
  a9 = a8 + a9; /* 0094: add.n a9, a8, a9 */
  MEM32(a8 + 840) = a9; /* 0096: s32i a9, a8, 0x348 */
  a9 = 0x34C; /* 0099: movi a9, 0x34c */
  a9 = a8 + a9; /* 009c: add.n a9, a8, a9 */
  MEM32(a8 + 848) = a9; /* 009e: s32i a9, a8, 0x350 */
  a9 = 0x354; /* 00a1: movi a9, 0x354 */
  a9 = a8 + a9; /* 00a4: add.n a9, a8, a9 */
  MEM32(a8 + 820) = a3; /* 00a6: s32i a3, a8, 0x334 */
  MEM32(a8 + 828) = a3; /* 00a9: s32i a3, a8, 0x33c */
  MEM32(a8 + 836) = a3; /* 00ac: s32i a3, a8, 0x344 */
  MEM32(a8 + 844) = a3; /* 00af: s32i a3, a8, 0x34c */
  MEM32(a8 + 852) = a3; /* 00b2: s32i a3, a8, 0x354 */
  MEM32(a8 + 856) = a9; /* 00b5: s32i a9, a8, 0x358 */
  MEMW(); /* 00b8: memw  */
  a8 = (uint32_t)&esf_buf_setup; /* 00bb: l32r a8, 24 <pp_attach-0xc> (0 <pp_attach-0x30>) */ /* literal: GOT slot for esf_buf_setup */
  esf_buf_setup(a2, a3, a4, a5); /* call via literal slot */ /* 00be: callx8 a8 */
  a2 = a10; /* 00c1: mov.n a2, a10 */
  if (a10 == a3) goto L_d0; /* 00c3: beq a10, a3, d0 <pp_attach+0xa0> */
  a8 = (uint32_t)&pp_deattach; /* 00c6: l32r a8, 28 <pp_attach-0x8> (0 <pp_attach-0x30>) */ /* literal: GOT slot for pp_deattach */
  pp_deattach(a2, a3, a4, a5); /* call via literal slot */ /* 00c9: callx8 a8 */
  goto L_101; /* 00cc: j 101 <pp_attach+0xd1> */
  /* 00cf: .byte 00 */
L_d0:;
  a10 = a3; /* 00d0: mov.n a10, a3 */
  a5 = MEM32(a4 + 0); /* 00d2: l32i.n a5, a4, 0 */
  a8 = (uint32_t)&ppPrepareBarFrame; /* 00d4: l32r a8, 2c <pp_attach-0x4> (0 <pp_attach-0x30>) */ /* literal: GOT slot for ppPrepareBarFrame */
  ppPrepareBarFrame(a2, a3, a4, a5); /* call via literal slot */ /* 00d7: callx8 a8 */
  a8 = a3 + a6; /* 00da: add.n a8, a3, a6 */
  a8 = (a8 << 4) + a5; /* 00dc: addx4 a8, a8, a5 */
  a3 = a3 + (1); /* 00df: addi.n a3, a3, 1 */
  MEM32(a8 + 0) = a10; /* 00e1: s32i.n a10, a8, 0 */
  if (a3 != 4) goto L_d0; /* 00e3: bnei a3, 4, d0 <pp_attach+0xa0> */
  a9 = 0x100; /* 00e6: movi a9, 0x100 */
  a3 = MEM32(a4 + 0); /* 00e9: l32i.n a3, a4, 0 */
  a4 = 0x1; /* 00eb: movi.n a4, 1 */
  a8 = a3 + ((0x300) << 8); /* 00ed: addmi a8, a3, 0x300 */
  MEM8(a3 + 29) = a4; /* 00f0: s8i a4, a3, 29 */
  a4 = 0x0; /* 00f3: movi.n a4, 0 */
  MEM32(a3 + 816) = a4; /* 00f5: s32i a4, a3, 0x330 */
  MEM16(a8 + 96) = a9; /* 00f8: s16i a9, a8, 96 */
  MEM8(a3 + 30) = a4; /* 00fb: s8i a4, a3, 30 */
  MEMW(); /* 00fe: memw  */
L_101:;
  MEMW(); /* 0101: memw  */
  return (int32_t)a2; /* 0104: retw.n  */
}

/* ppAssembleAMPDU @ pp.o 00000014 size 117B bind GLOBAL
 * Calls: wifi_log[got], ppCalFrameTimes[got] | Data refs: .rodata.pp_default_event_handler.str1.1, .rodata_wlog_error.40, wifi_log, ppCalFrameTimes
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 2 call(s), 4 data ref(s)
 * Fidelity: medium - 45 instr, 2 branches, calls resolved */
int32_t ppAssembleAMPDU(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .wifiextrairam.39; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_14:;
  /* 0014: entry a1, 32 */
  a8 = MEM32(a2 + 44); /* 0017: l32i.n a8, a2, 44 */
  a10 = 0x9; /* 0019: movi.n a10, 9 */
  a10 = 0x480000; /* 001b: slli a10, a10, 19 */
  a9 = MEM32(a8 + 0); /* 001e: l32i.n a9, a8, 0 */
  a9 = a9 | a10; /* 0020: or a9, a9, a10 */
  MEM32(a8 + 0) = a9; /* 0023: s32i.n a9, a8, 0 */
  a9 = MEM16(a2 + 20); /* 0025: l16ui a9, a2, 20 */
  a4 = a4 - a9; /* 0028: sub a4, a4, a9 */
  MEM16(a2 + 22) = a4; /* 002b: s16i a4, a2, 22 */
  MEMW(); /* 002e: memw  */
  a4 = MEM8(a8 + 4); /* 0031: l8ui a4, a8, 4 */
  MEM32(a8 + 4) = a4; /* 0034: s32i.n a4, a8, 4 */
  a4 = 0xF; /* 0036: movi.n a4, 15 */
  a8 = MEM8(a8 + 12); /* 0038: l8ui a8, a8, 12 */
  a8 = a8 + (-16); /* 003b: addi a8, a8, -16 */
  a8 = (a8 >> 0) & 0xFF; /* 003e: extui a8, a8, 0, 8 */
  if (a4 >= a8) goto L_60; /* 0041: bgeu a4, a8, 60 <ppAssembleAMPDU+0x4c> */
  a12 = 0x1; /* 0044: movi.n a12, 1 */
  a15 = 0xB73; /* 0046: l32r a15, 0 <ppAssembleAMPDU-0x14> (b73 <ppRxFragmentProc+0xaf3>) */ @0x0
  a11 = 0x800; /* 0049: slli a11, a12, 11 */
  a10 = 0x6; /* 004c: movi.n a10, 6 */
  a14 = (uint32_t)&lit_rodata_pp_default_event_handler_str1_1; /* 004e: l32r a14, 4 <ppAssembleAMPDU-0x10> (0 <ppAssembleAMPDU-0x14>) */ /* literal @0x4: .rodata.pp_default_event_handler.str1.1 */
  a13 = (uint32_t)&lit_rodata_wlog_error_40; /* 0051: l32r a13, 8 <ppAssembleAMPDU-0xc> (0 <ppAssembleAMPDU-0x14>) */ /* literal @0x8: .rodata_wlog_error.40 */
  MEMW(); /* 0054: memw  */
  a8 = (uint32_t)&wifi_log; /* 0057: l32r a8, c <ppAssembleAMPDU-0x8> (0 <ppAssembleAMPDU-0x14>) */ /* literal: GOT slot for wifi_log */
  wifi_log(a2, a3, a4, a5); /* call via literal slot */ /* 005a: callx8 a8 */
L_5d:;
  goto L_5d; /* 005d: j 5d <ppAssembleAMPDU+0x49> */
L_60:;
  a10 = a2; /* 0060: mov.n a10, a2 */
  a8 = (uint32_t)&ppCalFrameTimes; /* 0062: l32r a8, 10 <ppAssembleAMPDU-0x4> (0 <ppAssembleAMPDU-0x14>) */ /* literal: GOT slot for ppCalFrameTimes */
  ppCalFrameTimes(a2, a3, a4, a5); /* call via literal slot */ /* 0065: callx8 a8 */
  a4 = MEM32(a3 + 8); /* 0068: l32i.n a4, a3, 8 */
  a9 = 0x1; /* 006a: movi.n a9, 1 */
  a9 = 0x40000000; /* 006c: slli a9, a9, 30 */
  MEMW(); /* 006f: memw  */
  a8 = MEM32(a4 + 0); /* 0072: l32i.n a8, a4, 0 */
  a8 = a8 | a9; /* 0074: or a8, a8, a9 */
  MEMW(); /* 0077: memw  */
  MEM32(a4 + 0) = a8; /* 007a: s32i.n a8, a4, 0 */
  a3 = MEM32(a3 + 44); /* 007c: l32i.n a3, a3, 44 */
  a2 = MEM32(a2 + 44); /* 007e: l32i.n a2, a2, 44 */
  a3 = MEM32(a3 + 24); /* 0080: l32i.n a3, a3, 24 */
  MEM32(a2 + 24) = a3; /* 0082: s32i.n a3, a2, 24 */
  MEMW(); /* 0084: memw  */
  return (int32_t)a2; /* 0087: retw.n  */
}

/* ppCalTxAMPDULength @ pp.o 00000044 size 692B bind GLOBAL
 * Calls: rcGetAmpduSched[got], ppCheckTxAMPDUlength[got], ppEmptyDelimiterLength[got], ppCalSubFrameLength[got], ppCalSubFrameLength[got], wifi_log[got], lmacAdjustTimestamp[got], ppCheckTxAMPDUlength[got], ppEmptyDelimiterLength[got], ppEmptyDelimiterLength[got], ppAssembleAMPDU[got], ppPauseTxAMPDU[got] | Data refs: rcGetAmpduSched, pTxRx, ppCheckTxAMPDUlength, ppEmptyDelimiterLength, ppCalSubFrameLength, .rodata.pp_default_event_handler.str1.1, .rodata_wlog_error.43, wifi_log, lmacAdjustTimestamp, ppAssembleAMPDU, ppPauseTxAMPDU
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 12 call(s), 11 data ref(s)
 * Fidelity: medium - 271 instr, 25 branches, 0 indirect; flow + direct calls mapped, GOT-indirects enumerated (verified against section disasm) */
int32_t ppCalTxAMPDULength(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .wifi0iram.42; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_44:;
  /* 0044: entry a1, 112 */
  a11 = MEM32(a2 + 44); /* 0047: l32i.n a11, a2, 44 */
  a7 = a2; /* 0049: mov.n a7, a2 */
  a2 = MEM32(a11 + 0); /* 004b: l32i.n a2, a11, 0 */
  if ((a2 >> 14) & 1) goto L_58; /* 004d: bbsi a2, 14, 58 <ppCalTxAMPDULength+0x14> */
  a10 = MEM32(a7 + 36); /* 0050: l32i.n a10, a7, 36 */
  a8 = (uint32_t)&rcGetAmpduSched; /* 0052: l32r a8, 14 <ppCalTxAMPDULength-0x30> (0 <ppCalTxAMPDULength-0x44>) */ /* literal: GOT slot for rcGetAmpduSched */
  rcGetAmpduSched(a2, a3, a4, a5); /* call via literal slot */ /* 0055: callx8 a8 */
L_58:;
  a3 = 0x0; /* 0058: movi.n a3, 0 */
  a2 = MEM32(a7 + 44); /* 005a: l32i.n a2, a7, 44 */
  a4 = MEM32(a2 + 16); /* 005c: l32i.n a4, a2, 16 */
  a4 = (a4 >> 20) & 0xF; /* 005e: extui a4, a4, 20, 4 */
  a2 = MEM32(a7 + 36); /* 0061: l32i.n a2, a7, 36 */
  MEM32(a1 + 48) = a3; /* 0063: s32i.n a3, a1, 48 */
  MEM32(a1 + 52) = a2; /* 0065: s32i.n a2, a1, 52 */
  if (a2 == a3) goto L_7c; /* 0067: beq a2, a3, 7c <ppCalTxAMPDULength+0x38> */
  a3 = 0x1; /* 006a: movi.n a3, 1 */
  a2 = MEM8(a2 + 130); /* 006c: l8ui a2, a2, 130 */
  a2 = a2 + (-4); /* 006f: addi a2, a2, -4 */
  a2 = (a2 >> 0) & 0xFF; /* 0072: extui a2, a2, 0, 8 */
  if (a2 < 2) goto L_7a; /* 0075: bltui a2, 2, 7a <ppCalTxAMPDULength+0x36> */
  a3 = MEM32(a1 + 48); /* 0078: l32i.n a3, a1, 48 */
L_7a:;
  MEM32(a1 + 48) = a3; /* 007a: s32i.n a3, a1, 48 */
L_7c:;
  a3 = 0x0; /* 007c: movi.n a3, 0 */
  a6 = a1; /* 007e: mov.n a6, a1 */
  a2 = (uint32_t)&pTxRx; /* 0080: l32r a2, 0 <ppCalTxAMPDULength-0x44> (0 <ppCalTxAMPDULength-0x44>) */ /* literal @0x0: pTxRx */
  a5 = MEM32(a2 + 0); /* 0083: l32i.n a5, a2, 0 */
  a2 = (a4 << 2) + a4; /* 0085: addx2 a2, a4, a4 */
  a2 = a2 << (4 & 31); /* 0088: slli a2, a2, 4 */
  a5 = a5 + a2; /* 008b: add.n a5, a5, a2 */
  MEM8(a5 + 76) = a3; /* 008d: s8i a3, a5, 76 */
  a3 = 0x101; /* 0090: movi a3, 0x101 */
  MEM16(a5 + 64) = a3; /* 0093: s16i a3, a5, 64 */
  MEMW(); /* 0096: memw  */
  a3 = 0x0; /* 0099: movi.n a3, 0 */
  MEM32(a5 + 68) = a3; /* 009b: s32i a3, a5, 68 */
  a8 = MEM8(a7 + 27); /* 009e: l8ui a8, a7, 27 */
  MEM8(a5 + 47) = a8; /* 00a1: s8i a8, a5, 47 */
  MEMW(); /* 00a4: memw  */
  a5 = MEM32(a7 + 4); /* 00a7: l32i.n a5, a7, 4 */
  a5 = MEM32(a5 + 4); /* 00a9: l32i.n a5, a5, 4 */
  a5 = MEM8(a5 + 3); /* 00ab: l8ui a5, a5, 3 */
  MEM32(a1 + 40) = a7; /* 00ae: s32i.n a7, a1, 40 */
  MEM32(a1 + 56) = a5; /* 00b0: s32i.n a5, a1, 56 */
  a5 = 0x1; /* 00b2: movi.n a5, 1 */
  MEMW(); /* 00b4: memw  */
  goto L_18d; /* 00b7: j 18d <ppCalTxAMPDULength+0x149> */
L_ba:;
  a11 = MEM32(a15 + 8); /* 00ba: l32i.n a11, a15, 8 */
  a13 = a15; /* 00bc: mov.n a13, a15 */
  MEMW(); /* 00be: memw  */
  a10 = MEM32(a11 + 0); /* 00c1: l32i.n a10, a11, 0 */
  a8 = 0xBFFFFFFF; /* 00c3: l32r a8, 4 <ppCalTxAMPDULength-0x40> (bfffffff <ppRxFragmentProc+0xbfffff7f>) */ @0x4
  a10 = a10 & a8; /* 00c6: and a10, a10, a8 */
  MEMW(); /* 00c9: memw  */
  MEM32(a11 + 0) = a10; /* 00cc: s32i.n a10, a11, 0 */
  a11 = 0x0; /* 00ce: mov.n a11, a3 */
  a12 = MEM32(a1 + 56); /* 00d0: l32i.n a12, a1, 56 */
  a14 = MEM32(a1 + 48); /* 00d2: l32i.n a14, a1, 48 */
  a10 = MEM32(a1 + 52); /* 00d4: l32i.n a10, a1, 52 */
  MEM32(a1 + 76) = a15; /* 00d6: s32i a15, a1, 76 */
  MEMW(); /* 00d9: memw  */
  a8 = (uint32_t)&ppCheckTxAMPDUlength; /* 00dc: l32r a8, 18 <ppCalTxAMPDULength-0x2c> (0 <ppCalTxAMPDULength-0x44>) */ /* literal: GOT slot for ppCheckTxAMPDUlength */
  ppCheckTxAMPDUlength(a2, a3, a4, a5); /* call via literal slot */ /* 00df: callx8 a8 */
  a12 = a10; /* 00e2: mov.n a12, a10 */
  a10 = (uint32_t)&pTxRx; /* 00e4: l32r a10, 0 <ppCalTxAMPDULength-0x44> (0 <ppCalTxAMPDULength-0x44>) */ /* literal @0x0: pTxRx */
  a11 = MEM32(a10 + 0); /* 00e7: l32i.n a11, a10, 0 */
  a13 = a11 + a2; /* 00e9: add.n a13, a11, a2 */
  a10 = MEM8(a13 + 76); /* 00eb: l8ui a10, a13, 76 */
  a15 = MEM32(a1 + 76); /* 00ee: l32i a15, a1, 76 */
  if (a10 == 0) goto L_14a; /* 00f1: beqz a10, 14a <ppCalTxAMPDULength+0x106> */
  a8 = MEM32(a1 + 48); /* 00f4: l32i.n a8, a1, 48 */
  a10 = a5 & a8; /* 00f6: and a10, a5, a8 */
  if (a10 == 0) goto L_14a; /* 00f9: beqz a10, 14a <ppCalTxAMPDULength+0x106> */
  a5 = a10; /* 00fc: mov.n a5, a10 */
  if (a1 == a6) goto L_14a; /* 00fe: beq a1, a6, 14a <ppCalTxAMPDULength+0x106> */
  a14 = MEM32(a6 + 8); /* 0101: l32i.n a14, a6, 8 */
  a10 = 0x1; /* 0103: movi.n a10, 1 */
  a10 = 0x40000000; /* 0105: slli a10, a10, 30 */
  MEMW(); /* 0108: memw  */
  a5 = MEM32(a14 + 0); /* 010b: l32i.n a5, a14, 0 */
  a5 = a5 | a10; /* 010d: or a5, a5, a10 */
  a10 = a6; /* 0110: mov.n a10, a6 */
  MEMW(); /* 0112: memw  */
  MEM32(a14 + 0) = a5; /* 0115: s32i.n a5, a14, 0 */
  a5 = 0x2; /* 0117: movi a5, 2 */
  MEM8(a13 + 65) = a5; /* 011a: s8i a5, a13, 65 */
  MEMW(); /* 011d: memw  */
  a5 = 0x0; /* 0120: movi a5, 0 */
  MEM32(a1 + 64) = a11; /* 0123: s32i a11, a1, 64 */
  MEM32(a1 + 68) = a12; /* 0126: s32i a12, a1, 68 */
  MEM32(a1 + 72) = a13; /* 0129: s32i a13, a1, 72 */
  MEM32(a1 + 76) = a15; /* 012c: s32i a15, a1, 76 */
  MEMW(); /* 012f: memw  */
  a8 = (uint32_t)&ppEmptyDelimiterLength; /* 0132: l32r a8, 1c <ppCalTxAMPDULength-0x28> (0 <ppCalTxAMPDULength-0x44>) */ /* literal: GOT slot for ppEmptyDelimiterLength */
  ppEmptyDelimiterLength(a2, a3, a4, a5); /* call via literal slot */ /* 0135: callx8 a8 */
  a10 = a3 - a10; /* 0138: sub a10, a3, a10 */
  a13 = MEM32(a1 + 72); /* 013b: l32i a13, a1, 72 */
  a15 = MEM32(a1 + 76); /* 013e: l32i a15, a1, 76 */
  a12 = MEM32(a1 + 68); /* 0141: l32i a12, a1, 68 */
  a11 = MEM32(a1 + 64); /* 0144: l32i a11, a1, 64 */
  MEM32(a13 + 68) = a10; /* 0147: s32i a10, a13, 68 */
L_14a:;
  if (a12 != 0) goto L_189; /* 014a: bnez.n a12, 189 <ppCalTxAMPDULength+0x145> */
  a2 = MEM32(a6 + 8); /* 014c: l32i.n a2, a6, 8 */
  a10 = a6; /* 014e: mov.n a10, a6 */
  MEM32(a2 + 8) = a12; /* 0150: s32i.n a12, a2, 8 */
  MEMW(); /* 0152: memw  */
  goto L_15e; /* 0155: j 15e <ppCalTxAMPDULength+0x11a> */
L_158:;
  a10 = MEM32(a2 + 8); /* 0158: l32i.n a10, a2, 8 */
  MEM32(a10 + 8) = a12; /* 015a: s32i.n a12, a10, 8 */
  a10 = a2; /* 015c: mov.n a10, a2 */
L_15e:;
  a2 = MEM32(a10 + 40); /* 015e: l32i.n a2, a10, 40 */
  if (a2 != 0) goto L_158; /* 0160: bnez a2, 158 <ppCalTxAMPDULength+0x114> */
  a12 = a4 + a4; /* 0163: add.n a12, a4, a4 */
  MEM32(a6 + 40) = a2; /* 0165: s32i.n a2, a6, 40 */
  a2 = (a4 << 2) + a4; /* 0167: addx2 a2, a4, a4 */
  a2 = a2 << (4 & 31); /* 016a: slli a2, a2, 4 */
  a2 = a11 + a2; /* 016d: add.n a2, a11, a2 */
  a13 = MEM32(a2 + 32); /* 016f: l32i.n a13, a2, 32 */
  MEM32(a10 + 40) = a13; /* 0171: s32i.n a13, a10, 40 */
  if (a13 != 0) goto L_17a; /* 0173: bnez.n a13, 17a <ppCalTxAMPDULength+0x136> */
  a10 = a10 + (40); /* 0175: addi a10, a10, 40 */
  MEM32(a2 + 36) = a10; /* 0178: s32i.n a10, a2, 36 */
L_17a:;
  a2 = a12 + a4; /* 017a: add.n a2, a12, a4 */
  a2 = a2 << (4 & 31); /* 017c: slli a2, a2, 4 */
  a11 = a11 + a2; /* 017f: add.n a11, a11, a2 */
  MEM32(a11 + 32) = a15; /* 0181: s32i.n a15, a11, 32 */
  MEMW(); /* 0183: memw  */
  goto L_192; /* 0186: j 192 <ppCalTxAMPDULength+0x14e> */
L_189:;
  a3 = a3 + a12; /* 0189: add.n a3, a3, a12 */
  a6 = a15; /* 018b: mov.n a6, a15 */
L_18d:;
  a15 = MEM32(a6 + 40); /* 018d: l32i.n a15, a6, 40 */
  if (a15 != 0) goto L_ba; /* 018f: bnez a15, ba <ppCalTxAMPDULength+0x76> */
L_192:;
  a2 = MEM32(a7 + 44); /* 0192: l32i.n a2, a7, 44 */
  a2 = MEM32(a2 + 0); /* 0194: l32i.n a2, a2, 0 */
  if (!((a2 >> 22) & 1)) goto L_1aa; /* 0196: bbci a2, 22, 1aa <ppCalTxAMPDULength+0x166> */
L_199:;
  a15 = (a4 << 2) + a4; /* 0199: addx2 a15, a4, a4 */
  a15 = a15 << (4 & 31); /* 019c: slli a15, a15, 4 */
  a2 = a15 + (32); /* 019f: addi a2, a15, 32 */
  MEM32(a1 + 60) = a2; /* 01a2: s32i.n a2, a1, 60 */
  MEMW(); /* 01a4: memw  */
  goto L_295; /* 01a7: j 295 <ppCalTxAMPDULength+0x251> */
L_1aa:;
  a10 = a7; /* 01aa: mov.n a10, a7 */
  a8 = (uint32_t)&ppCalSubFrameLength; /* 01ac: l32r a8, 20 <ppCalTxAMPDULength-0x24> (0 <ppCalTxAMPDULength-0x44>) */ /* literal: GOT slot for ppCalSubFrameLength */
  ppCalSubFrameLength(a2, a3, a4, a5); /* call via literal slot */ /* 01af: callx8 a8 */
  a10 = a7; /* 01b2: mov.n a10, a7 */
  a8 = (uint32_t)&ppCalSubFrameLength; /* 01b4: l32r a8, 24 <ppCalTxAMPDULength-0x20> (0 <ppCalTxAMPDULength-0x44>) */ /* literal: GOT slot for ppCalSubFrameLength */
  ppCalSubFrameLength(a2, a3, a4, a5); /* call via literal slot */ /* 01b7: callx8 a8 */
  if (a10 == a3) goto L_199; /* 01ba: beq a10, a3, 199 <ppCalTxAMPDULength+0x155> */
  a12 = 0x1; /* 01bd: movi.n a12, 1 */
  a15 = 0xC2F; /* 01bf: l32r a15, 8 <ppCalTxAMPDULength-0x3c> (c2f <ppRxFragmentProc+0xbaf>) */ @0x8
  a11 = 0x800; /* 01c2: slli a11, a12, 11 */
  a10 = 0x6; /* 01c5: movi a10, 6 */
  a14 = (uint32_t)&lit_rodata_pp_default_event_handler_str1_1; /* 01c8: l32r a14, c <ppCalTxAMPDULength-0x38> (0 <ppCalTxAMPDULength-0x44>) */ /* literal @0xC: .rodata.pp_default_event_handler.str1.1 */
  a13 = (uint32_t)&lit_rodata_wlog_error_43; /* 01cb: l32r a13, 10 <ppCalTxAMPDULength-0x34> (0 <ppCalTxAMPDULength-0x44>) */ /* literal @0x10: .rodata_wlog_error.43 */
  a8 = (uint32_t)&wifi_log; /* 01ce: l32r a8, 28 <ppCalTxAMPDULength-0x1c> (0 <ppCalTxAMPDULength-0x44>) */ /* literal: GOT slot for wifi_log */
  wifi_log(a2, a3, a4, a5); /* call via literal slot */ /* 01d1: callx8 a8 */
L_1d4:;
  goto L_1d4; /* 01d4: j 1d4 <ppCalTxAMPDULength+0x190> */
  /* 01d7: .byte 00 */
L_1d8:;
  a10 = MEM32(a2 + 44); /* 01d8: l32i.n a10, a2, 44 */
  a10 = MEM32(a10 + 0); /* 01da: l32i.n a10, a10, 0 */
  if ((a10 >> 18) & 1) goto L_1e2; /* 01dc: bbsi a10, 18, 1e2 <ppCalTxAMPDULength+0x19e> */
  goto L_2a2; /* 01df: j 2a2 <ppCalTxAMPDULength+0x25e> */
L_1e2:;
  a10 = a2; /* 01e2: mov.n a10, a2 */
  MEM32(a1 + 76) = a15; /* 01e4: s32i a15, a1, 76 */
  MEMW(); /* 01e7: memw  */
  a8 = (uint32_t)&lmacAdjustTimestamp; /* 01ea: l32r a8, 2c <ppCalTxAMPDULength-0x18> (0 <ppCalTxAMPDULength-0x44>) */ /* literal: GOT slot for lmacAdjustTimestamp */
  lmacAdjustTimestamp(a2, a3, a4, a5); /* call via literal slot */ /* 01ed: callx8 a8 */
  a13 = a2; /* 01f0: mov.n a13, a2 */
  a11 = MEM32(a2 + 8); /* 01f2: l32i.n a11, a2, 8 */
  a12 = 0xBFFFFFFF; /* 01f4: l32r a12, 4 <ppCalTxAMPDULength-0x40> (bfffffff <ppRxFragmentProc+0xbfffff7f>) */ @0x4
  MEMW(); /* 01f7: memw  */
  a10 = MEM32(a11 + 0); /* 01fa: l32i.n a10, a11, 0 */
  a10 = a10 & a12; /* 01fc: and a10, a10, a12 */
  MEMW(); /* 01ff: memw  */
  MEM32(a11 + 0) = a10; /* 0202: s32i.n a10, a11, 0 */
  a11 = a3; /* 0204: mov.n a11, a3 */
  a12 = MEM32(a1 + 56); /* 0206: l32i.n a12, a1, 56 */
  a14 = MEM32(a1 + 48); /* 0208: l32i.n a14, a1, 48 */
  a10 = MEM32(a1 + 52); /* 020a: l32i.n a10, a1, 52 */
  MEMW(); /* 020c: memw  */
  a8 = (uint32_t)&ppCheckTxAMPDUlength; /* 020f: l32r a8, 30 <ppCalTxAMPDULength-0x14> (0 <ppCalTxAMPDULength-0x44>) */ /* literal: GOT slot for ppCheckTxAMPDUlength */
  ppCheckTxAMPDUlength(a2, a3, a4, a5); /* call via literal slot */ /* 0212: callx8 a8 */
  a13 = a10; /* 0215: mov.n a13, a10 */
  a8 = (uint32_t)&pTxRx; /* 0217: l32r a8, 0 <ppCalTxAMPDULength-0x44> (0 <ppCalTxAMPDULength-0x44>) */ /* literal @0x0: pTxRx */
  a15 = MEM32(a1 + 76); /* 021a: l32i a15, a1, 76 */
  a11 = MEM32(a8 + 0); /* 021d: l32i.n a11, a8, 0 */
  a12 = a11 + a15; /* 021f: add.n a12, a11, a15 */
  a10 = MEM8(a12 + 76); /* 0221: l8ui a10, a12, 76 */
  if (a10 == 0) goto L_273; /* 0224: beqz a10, 273 <ppCalTxAMPDULength+0x22f> */
  a8 = MEM32(a1 + 48); /* 0227: l32i.n a8, a1, 48 */
  if ((a5 & a8) == 0) goto L_273; /* 0229: bnone a5, a8, 273 <ppCalTxAMPDULength+0x22f> */
  a10 = 0x1; /* 022c: movi.n a10, 1 */
  a10 = 0x40000000; /* 022e: slli a10, a10, 30 */
  a14 = MEM32(a6 + 8); /* 0231: l32i.n a14, a6, 8 */
  MEMW(); /* 0233: memw  */
  a5 = MEM32(a14 + 0); /* 0236: l32i.n a5, a14, 0 */
  a5 = a5 | a10; /* 0238: or a5, a5, a10 */
  a10 = a6; /* 023b: mov.n a10, a6 */
  MEMW(); /* 023d: memw  */
  MEM32(a14 + 0) = a5; /* 0240: s32i.n a5, a14, 0 */
  a5 = 0x2; /* 0242: movi.n a5, 2 */
  MEM8(a12 + 65) = a5; /* 0244: s8i a5, a12, 65 */
  MEMW(); /* 0247: memw  */
  a5 = 0x0; /* 024a: movi.n a5, 0 */
  MEM32(a1 + 64) = a11; /* 024c: s32i a11, a1, 64 */
  MEM32(a1 + 68) = a12; /* 024f: s32i a12, a1, 68 */
  MEM32(a1 + 72) = a13; /* 0252: s32i a13, a1, 72 */
  MEM32(a1 + 76) = a15; /* 0255: s32i a15, a1, 76 */
  MEMW(); /* 0258: memw  */
  a8 = (uint32_t)&ppEmptyDelimiterLength; /* 025b: l32r a8, 34 <ppCalTxAMPDULength-0x10> (0 <ppCalTxAMPDULength-0x44>) */ /* literal: GOT slot for ppEmptyDelimiterLength */
  ppEmptyDelimiterLength(a2, a3, a4, a5); /* call via literal slot */ /* 025e: callx8 a8 */
  a10 = a3 - a10; /* 0261: sub a10, a3, a10 */
  a12 = MEM32(a1 + 68); /* 0264: l32i a12, a1, 68 */
  a15 = MEM32(a1 + 76); /* 0267: l32i a15, a1, 76 */
  a13 = MEM32(a1 + 72); /* 026a: l32i a13, a1, 72 */
  a11 = MEM32(a1 + 64); /* 026d: l32i a11, a1, 64 */
  MEM32(a12 + 68) = a10; /* 0270: s32i a10, a12, 68 */
L_273:;
  if (a13 == 0) goto L_2a2; /* 0273: beqz.n a13, 2a2 <ppCalTxAMPDULength+0x25e> */
  a10 = a11 + a15; /* 0275: add.n a10, a11, a15 */
  a12 = MEM32(a10 + 32); /* 0277: l32i.n a12, a10, 32 */
  a12 = MEM32(a12 + 40); /* 0279: l32i.n a12, a12, 40 */
  MEM32(a10 + 32) = a12; /* 027b: s32i.n a12, a10, 32 */
  if (a12 != 0) goto L_285; /* 027d: bnez.n a12, 285 <ppCalTxAMPDULength+0x241> */
  a8 = MEM32(a1 + 60); /* 027f: l32i.n a8, a1, 60 */
  a11 = a11 + a8; /* 0281: add.n a11, a11, a8 */
  MEM32(a10 + 36) = a11; /* 0283: s32i.n a11, a10, 36 */
L_285:;
  a3 = a3 + a13; /* 0285: add.n a3, a3, a13 */
  a8 = MEM32(a6 + 8); /* 0287: l32i.n a8, a6, 8 */
  a10 = MEM32(a2 + 4); /* 0289: l32i.n a10, a2, 4 */
  MEM32(a6 + 40) = a2; /* 028b: s32i.n a2, a6, 40 */
  a6 = a2; /* 028d: mov.n a6, a2 */
  MEM32(a8 + 8) = a10; /* 028f: s32i.n a10, a8, 8 */
  a8 = 0x0; /* 0291: movi.n a8, 0 */
  MEM32(a2 + 40) = a8; /* 0293: s32i.n a8, a2, 40 */
L_295:;
  a8 = (uint32_t)&pTxRx; /* 0295: l32r a8, 0 <ppCalTxAMPDULength-0x44> (0 <ppCalTxAMPDULength-0x44>) */ /* literal @0x0: pTxRx */
  a2 = MEM32(a8 + 0); /* 0298: l32i.n a2, a8, 0 */
  a2 = a2 + a15; /* 029a: add.n a2, a2, a15 */
  a2 = MEM32(a2 + 32); /* 029c: l32i a2, a2, 32 */
  if (a2 != 0) goto L_1d8; /* 029f: bnez a2, 1d8 <ppCalTxAMPDULength+0x194> */
L_2a2:;
  a10 = a6; /* 02a2: mov.n a10, a6 */
  MEMW(); /* 02a4: memw  */
  a8 = (uint32_t)&ppEmptyDelimiterLength; /* 02a7: l32r a8, 38 <ppCalTxAMPDULength-0xc> (0 <ppCalTxAMPDULength-0x44>) */ /* literal: GOT slot for ppEmptyDelimiterLength */
  ppEmptyDelimiterLength(a2, a3, a4, a5); /* call via literal slot */ /* 02aa: callx8 a8 */
  a8 = (uint32_t)&pTxRx; /* 02ad: l32r a8, 0 <ppCalTxAMPDULength-0x44> (0 <ppCalTxAMPDULength-0x44>) */ /* literal @0x0: pTxRx */
  a10 = a3 - a10; /* 02b0: sub a10, a3, a10 */
  if (a5 != 1) goto L_2c4; /* 02b3: bnei a5, 1, 2c4 <ppCalTxAMPDULength+0x280> */
  a3 = (a4 << 2) + a4; /* 02b6: addx2 a3, a4, a4 */
  a3 = a3 << (4 & 31); /* 02b9: slli a3, a3, 4 */
  a2 = MEM32(a8 + 0); /* 02bc: l32i.n a2, a8, 0 */
  a2 = a2 + a3; /* 02be: add a2, a2, a3 */
  MEM32(a2 + 68) = a10; /* 02c1: s32i a10, a2, 68 */
L_2c4:;
  a12 = (a10 >> 0) & 0xFFFF; /* 02c4: extui a12, a10, 0, 16 */
  a11 = a6; /* 02c7: mov.n a11, a6 */
  a10 = a7; /* 02c9: mov.n a10, a7 */
  a2 = a4 + (1); /* 02cb: addi.n a2, a4, 1 */
  MEM32(a1 + 64) = a8; /* 02cd: s32i a8, a1, 64 */
  MEMW(); /* 02d0: memw  */
  a8 = (uint32_t)&ppAssembleAMPDU; /* 02d3: l32r a8, 3c <ppCalTxAMPDULength-0x8> (0 <ppCalTxAMPDULength-0x44>) */ /* literal: GOT slot for ppAssembleAMPDU */
  ppAssembleAMPDU(a2, a3, a4, a5); /* call via literal slot */ /* 02d6: callx8 a8 */
  a2 = (a2 << 2) + a2; /* 02d9: addx2 a2, a2, a2 */
  a2 = a2 << (4 & 31); /* 02dc: slli a2, a2, 4 */
  a10 = a4; /* 02df: mov.n a10, a4 */
  a8 = MEM32(a1 + 64); /* 02e1: l32i a8, a1, 64 */
  a3 = MEM32(a8 + 0); /* 02e4: l32i.n a3, a8, 0 */
  a2 = a3 + a2; /* 02e6: add.n a2, a3, a2 */
  MEM32(a2 + 4) = a7; /* 02e8: s32i a7, a2, 4 */
  MEMW(); /* 02eb: memw  */
  a8 = (uint32_t)&ppPauseTxAMPDU; /* 02ee: l32r a8, 40 <ppCalTxAMPDULength-0x4> (0 <ppCalTxAMPDULength-0x44>) */ /* literal: GOT slot for ppPauseTxAMPDU */
  ppPauseTxAMPDU(a2, a3, a4, a5); /* call via literal slot */ /* 02f1: callx8 a8 */
  a2 = a7; /* 02f4: mov.n a2, a7 */
  return (int32_t)a2; /* 02f6: retw.n  */
}

/* ppAMPDU2Normal @ pp.o 00000014 size 150B bind GLOBAL
 * Calls: rcGetSched[got], ppCalFrameTimes[got] | Data refs: rcGetSched, ppCalFrameTimes
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 2 call(s), 2 data ref(s)
 * Fidelity: medium - 57 instr, 0 branches, calls resolved */
int32_t ppAMPDU2Normal(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .wifiextrairam.41; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_14:;
  /* 0014: entry a1, 32 */
  a9 = MEM32(a2 + 4); /* 0017: l32i.n a9, a2, 4 */
  a11 = MEM32(a9 + 4); /* 0019: l32i.n a11, a9, 4 */
  a8 = MEM16(a2 + 20); /* 001b: l16ui a8, a2, 20 */
  a8 = a8 + (-4); /* 001e: addi a8, a8, -4 */
  a8 = (a8 >> 0) & 0xFFFF; /* 0021: extui a8, a8, 0, 16 */
  a10 = MEM32(a11 + 0); /* 0024: l32i.n a10, a11, 0 */
  a11 = a11 + (4); /* 0026: addi.n a11, a11, 4 */
  a10 = (a10 >> 0) & 0xFFF; /* 0028: extui a10, a10, 0, 12 */
  MEM16(a2 + 20) = a8; /* 002b: s16i a8, a2, 20 */
  a8 = a10 - a8; /* 002e: sub a8, a10, a8 */
  MEM16(a2 + 22) = a8; /* 0031: s16i a8, a2, 22 */
  MEMW(); /* 0034: memw  */
  MEMW(); /* 0037: memw  */
  a8 = MEM32(a9 + 0); /* 003a: l32i.n a8, a9, 0 */
  a10 = 0xDFFFFFFF; /* 003c: l32r a10, 0 <ppAMPDU2Normal-0x14> (dfffffff <ppRxFragmentProc+0xdfffff7f>) */ @0x0
  a8 = a8 & a10; /* 003f: and a8, a8, a10 */
  MEMW(); /* 0042: memw  */
  MEM32(a9 + 0) = a8; /* 0045: s32i.n a8, a9, 0 */
  MEMW(); /* 0047: memw  */
  a8 = MEM32(a9 + 0); /* 004a: l32i.n a8, a9, 0 */
  a8 = (a8 >> 12) & 0xFFF; /* 004c: extui a8, a8, 12, 12 */
  a8 = a8 + (-4); /* 004f: addi a8, a8, -4 */
  a8 = (a8 >> 0) & 0xFFF; /* 0052: extui a8, a8, 0, 12 */
  MEMW(); /* 0055: memw  */
  a10 = MEM32(a9 + 0); /* 0058: l32i.n a10, a9, 0 */
  a8 = a8 << (12 & 31); /* 005a: slli a8, a8, 12 */
  a12 = 0xFF000FFF; /* 005d: l32r a12, 4 <ppAMPDU2Normal-0x10> (ff000fff <ppRxFragmentProc+0xff000f7f>) */ @0x4
  a10 = a10 & a12; /* 0060: and a10, a10, a12 */
  a8 = a10 | a8; /* 0063: or a8, a10, a8 */
  MEMW(); /* 0066: memw  */
  MEM32(a9 + 0) = a8; /* 0069: s32i.n a8, a9, 0 */
  MEM32(a9 + 4) = a11; /* 006b: s32i.n a11, a9, 4 */
  a11 = MEM32(a2 + 44); /* 006d: l32i.n a11, a2, 44 */
  a8 = MEM8(a11 + 4); /* 006f: l8ui a8, a11, 4 */
  a9 = 0xFFB3FEFF; /* 0072: l32r a9, 8 <ppAMPDU2Normal-0xc> (ffb3feff <ppRxFragmentProc+0xffb3fe7f>) */ @0x8
  MEM32(a11 + 4) = a8; /* 0075: s32i.n a8, a11, 4 */
  a8 = MEM32(a11 + 0); /* 0077: l32i.n a8, a11, 0 */
  a8 = a8 & a9; /* 0079: and a8, a8, a9 */
  a10 = MEM32(a2 + 36); /* 007c: l32i.n a10, a2, 36 */
  MEM32(a11 + 0) = a8; /* 007e: s32i.n a8, a11, 0 */
  MEMW(); /* 0080: memw  */
  a8 = (uint32_t)&rcGetSched; /* 0083: l32r a8, c <ppAMPDU2Normal-0x8> (0 <ppAMPDU2Normal-0x14>) */ /* literal: GOT slot for rcGetSched */
  rcGetSched(a2, a3, a4, a5); /* call via literal slot */ /* 0086: callx8 a8 */
  a10 = a2; /* 0089: mov.n a10, a2 */
  a8 = (uint32_t)&ppCalFrameTimes; /* 008b: l32r a8, 10 <ppAMPDU2Normal-0x4> (0 <ppAMPDU2Normal-0x14>) */ /* literal: GOT slot for ppCalFrameTimes */
  ppCalFrameTimes(a2, a3, a4, a5); /* call via literal slot */ /* 008e: callx8 a8 */
  a8 = 0x1; /* 0091: movi.n a8, 1 */
  a9 = MEM32(a2 + 8); /* 0093: l32i.n a9, a2, 8 */
  a8 = 0x40000000; /* 0095: slli a8, a8, 30 */
  MEMW(); /* 0098: memw  */
  a2 = MEM32(a9 + 0); /* 009b: l32i.n a2, a9, 0 */
  a2 = a2 | a8; /* 009d: or a2, a2, a8 */
  MEMW(); /* 00a0: memw  */
  MEM32(a9 + 0) = a2; /* 00a3: s32i.n a2, a9, 0 */
  MEMW(); /* 00a5: memw  */
  return (int32_t)a2; /* 00a8: retw.n  */
}

/* ppProcessTxQ @ pp.o 00000030 size 278B bind GLOBAL
 * Calls: lmacIsIdle[got], ppSearchTxframe[got], pm_is_waked[got], ppAMPDU2Normal[got], trc_isTxAmpduOperational[got], trc_tid_isTxAmpduOperational[got], ppCalTxAMPDULength[got], pp_coex_tx_request[got], lmacTxFrame[got] | Data refs: lmacIsIdle, g_mesh_is_started, ppSearchTxframe, g_mesh_is_root, pm_is_waked, ppAMPDU2Normal, trc_isTxAmpduOperational, trc_tid_isTxAmpduOperational, ppCalTxAMPDULength, pTxRx, pp_coex_tx_request, lmacTxFrame
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 9 call(s), 12 data ref(s)
 * Fidelity: medium - 113 instr, 20 branches, calls resolved */
int32_t ppProcessTxQ(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .wifi0iram.23; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_30:;
  /* 0030: entry a1, 32 */
  a4 = (a2 >> 0) & 0xFF; /* 0033: extui a4, a2, 0, 8 */
  a10 = a4; /* 0036: mov.n a10, a4 */
  a8 = (uint32_t)&lmacIsIdle; /* 0038: l32r a8, c <ppProcessTxQ-0x24> (0 <ppProcessTxQ-0x30>) */ /* literal: GOT slot for lmacIsIdle */
  lmacIsIdle(a2, a3, a4, a5); /* call via literal slot */ /* 003b: callx8 a8 */
  if (a10 != 0) goto L_45; /* 003e: bnez.n a10, 45 <ppProcessTxQ+0x15> */
L_40:;
  a2 = 0xFFFFFFFF; /* 0040: movi.n a2, -1 */
  goto L_144; /* 0042: j 144 <ppProcessTxQ+0x114> */
L_45:;
  a2 = (uint32_t)&g_mesh_is_started; /* 0045: l32r a2, 0 <ppProcessTxQ-0x30> (0 <ppProcessTxQ-0x30>) */ /* literal @0x0: g_mesh_is_started */
  a2 = MEM8(a2 + 0); /* 0048: l8ui a2, a2, 0 */
  if (a2 != 0) goto L_60; /* 004b: bnez.n a2, 60 <ppProcessTxQ+0x30> */
L_4d:;
  a10 = a4; /* 004d: mov.n a10, a4 */
  a8 = (uint32_t)&ppSearchTxframe; /* 004f: l32r a8, 10 <ppProcessTxQ-0x20> (0 <ppProcessTxQ-0x30>) */ /* literal: GOT slot for ppSearchTxframe */
  ppSearchTxframe(a2, a3, a4, a5); /* call via literal slot */ /* 0052: callx8 a8 */
  a3 = a10; /* 0055: mov.n a3, a10 */
  a2 = 0xFFFFFFFE; /* 0057: movi.n a2, -2 */
  if (a10 != 0) goto L_7c; /* 0059: bnez.n a10, 7c <ppProcessTxQ+0x4c> */
  goto L_144; /* 005b: j 144 <ppProcessTxQ+0x114> */
  /* 005e: .byte 00 */
  /* 005f: .byte 00 */
L_60:;
  a2 = (uint32_t)&g_mesh_is_root; /* 0060: l32r a2, 4 <ppProcessTxQ-0x2c> (0 <ppProcessTxQ-0x30>) */ /* literal @0x4: g_mesh_is_root */
  MEMW(); /* 0063: memw  */
  a2 = MEM8(a2 + 0); /* 0066: l8ui a2, a2, 0 */
  a2 = (a2 >> 0) & 0xFF; /* 0069: extui a2, a2, 0, 8 */
  if (a2 != 0) goto L_4d; /* 006c: bnez a2, 4d <ppProcessTxQ+0x1d> */
  a8 = (uint32_t)&pm_is_waked; /* 006f: l32r a8, 14 <ppProcessTxQ-0x1c> (0 <ppProcessTxQ-0x30>) */ /* literal: GOT slot for pm_is_waked */
  pm_is_waked(a2, a3, a4, a5); /* call via literal slot */ /* 0072: callx8 a8 */
  if (a10 != 0) goto L_4d; /* 0075: bnez a10, 4d <ppProcessTxQ+0x1d> */
  goto L_40; /* 0078: j 40 <ppProcessTxQ+0x10> */
  /* 007b: .byte 00 */
L_7c:;
  a2 = MEM32(a10 + 44); /* 007c: l32i.n a2, a10, 44 */
  a2 = MEM32(a2 + 0); /* 007e: l32i.n a2, a2, 0 */
  if ((a2 >> 18) & 1) goto L_86; /* 0080: bbsi a2, 18, 86 <ppProcessTxQ+0x56> */
  goto L_12d; /* 0083: j 12d <ppProcessTxQ+0xfd> */
L_86:;
  a10 = MEM32(a10 + 36); /* 0086: l32i.n a10, a10, 36 */
  if (a10 != 0) goto L_99; /* 0088: bnez.n a10, 99 <ppProcessTxQ+0x69> */
L_8a:;
  a10 = a3; /* 008a: mov.n a10, a3 */
  a8 = (uint32_t)&ppAMPDU2Normal; /* 008c: l32r a8, 18 <ppProcessTxQ-0x18> (0 <ppProcessTxQ-0x30>) */ /* literal: GOT slot for ppAMPDU2Normal */
  ppAMPDU2Normal(a2, a3, a4, a5); /* call via literal slot */ /* 008f: callx8 a8 */
  a11 = MEM32(a3 + 40); /* 0092: l32i.n a11, a3, 40 */
  if (a11 != 0) goto L_c2; /* 0094: bnez.n a11, c2 <ppProcessTxQ+0x92> */
  goto L_115; /* 0096: j 115 <ppProcessTxQ+0xe5> */
L_99:;
  a8 = (uint32_t)&trc_isTxAmpduOperational; /* 0099: l32r a8, 1c <ppProcessTxQ-0x14> (0 <ppProcessTxQ-0x30>) */ /* literal: GOT slot for trc_isTxAmpduOperational */
  trc_isTxAmpduOperational(a2, a3, a4, a5); /* call via literal slot */ /* 009c: callx8 a8 */
  if (a10 == 0) goto L_8a; /* 009f: beqz a10, 8a <ppProcessTxQ+0x5a> */
  a2 = MEM32(a3 + 44); /* 00a2: l32i.n a2, a3, 44 */
  a11 = MEM32(a2 + 4); /* 00a4: l32i.n a11, a2, 4 */
  a11 = (a11 >> 0) & 0xF; /* 00a6: extui a11, a11, 0, 4 */
  a10 = MEM32(a3 + 36); /* 00a9: l32i.n a10, a3, 36 */
  a8 = (uint32_t)&trc_tid_isTxAmpduOperational; /* 00ab: l32r a8, 20 <ppProcessTxQ-0x10> (0 <ppProcessTxQ-0x30>) */ /* literal: GOT slot for trc_tid_isTxAmpduOperational */
  trc_tid_isTxAmpduOperational(a2, a3, a4, a5); /* call via literal slot */ /* 00ae: callx8 a8 */
  if (a10 == 0) goto L_8a; /* 00b1: beqz a10, 8a <ppProcessTxQ+0x5a> */
  a10 = a3; /* 00b4: mov.n a10, a3 */
  a8 = (uint32_t)&ppCalTxAMPDULength; /* 00b6: l32r a8, 24 <ppProcessTxQ-0xc> (0 <ppProcessTxQ-0x30>) */ /* literal: GOT slot for ppCalTxAMPDULength */
  ppCalTxAMPDULength(a2, a3, a4, a5); /* call via literal slot */ /* 00b9: callx8 a8 */
  if (a10 == 0) goto L_8a; /* 00bc: beqz a10, 8a <ppProcessTxQ+0x5a> */
  goto L_12d; /* 00bf: j 12d <ppProcessTxQ+0xfd> */
L_c2:;
  a8 = MEM32(a3 + 8); /* 00c2: l32i.n a8, a3, 8 */
  a2 = 0x0; /* 00c4: movi.n a2, 0 */
  MEM32(a3 + 40) = a2; /* 00c6: s32i.n a2, a3, 40 */
  MEM32(a8 + 8) = a2; /* 00c8: s32i.n a2, a8, 8 */
  a8 = a11; /* 00ca: mov.n a8, a11 */
L_cc:;
  a13 = a8; /* 00cc: mov.n a13, a8 */
  a9 = MEM32(a8 + 8); /* 00ce: l32i.n a9, a8, 8 */
  a8 = MEM32(a8 + 40); /* 00d0: l32i.n a8, a8, 40 */
  MEM32(a9 + 8) = a2; /* 00d2: s32i.n a2, a9, 8 */
  if (a8 != 0) goto L_cc; /* 00d4: bnez a8, cc <ppProcessTxQ+0x9c> */
  a2 = (uint32_t)&pTxRx; /* 00d7: l32r a2, 8 <ppProcessTxQ-0x28> (0 <ppProcessTxQ-0x30>) */ /* literal @0x8: pTxRx */
  a12 = MEM32(a2 + 0); /* 00da: l32i.n a12, a2, 0 */
  a2 = MEM32(a3 + 44); /* 00dc: l32i.n a2, a3, 44 */
  a8 = MEM32(a2 + 16); /* 00de: l32i.n a8, a2, 16 */
  a8 = (a8 >> 20) & 0xF; /* 00e0: extui a8, a8, 20, 4 */
  a10 = (a8 << 2) + a8; /* 00e3: addx2 a10, a8, a8 */
  a10 = a10 << (4 & 31); /* 00e6: slli a10, a10, 4 */
  a10 = a12 + a10; /* 00e9: add.n a10, a12, a10 */
  a2 = MEM32(a10 + 32); /* 00eb: l32i.n a2, a10, 32 */
  a9 = a8 + a8; /* 00ed: add.n a9, a8, a8 */
  MEM32(a13 + 40) = a2; /* 00ef: s32i.n a2, a13, 40 */
  if (a2 != 0) goto L_f8; /* 00f1: bnez.n a2, f8 <ppProcessTxQ+0xc8> */
  a13 = a13 + (40); /* 00f3: addi a13, a13, 40 */
  MEM32(a10 + 36) = a13; /* 00f6: s32i.n a13, a10, 36 */
L_f8:;
  a9 = a9 + a8; /* 00f8: add.n a9, a9, a8 */
  a8 = a8 + (1); /* 00fa: addi.n a8, a8, 1 */
  a9 = a9 << (4 & 31); /* 00fc: slli a9, a9, 4 */
  a8 = (a8 << 2) + a8; /* 00ff: addx2 a8, a8, a8 */
  a9 = a12 + a9; /* 0102: add.n a9, a12, a9 */
  a8 = a8 << (4 & 31); /* 0104: slli a8, a8, 4 */
  MEM32(a9 + 32) = a11; /* 0107: s32i.n a11, a9, 32 */
  a12 = a12 + a8; /* 0109: add.n a12, a12, a8 */
  a2 = 0x0; /* 010b: movi.n a2, 0 */
  MEM32(a12 + 4) = a2; /* 010d: s32i.n a2, a12, 4 */
  MEMW(); /* 010f: memw  */
  goto L_12d; /* 0112: j 12d <ppProcessTxQ+0xfd> */
L_115:;
  a8 = MEM32(a3 + 44); /* 0115: l32i.n a8, a3, 44 */
  a8 = MEM32(a8 + 16); /* 0117: l32i.n a8, a8, 16 */
  a8 = (a8 >> 20) & 0xF; /* 0119: extui a8, a8, 20, 4 */
  a8 = a8 + (1); /* 011c: addi.n a8, a8, 1 */
  a8 = (a8 << 2) + a8; /* 011e: addx2 a8, a8, a8 */
  a2 = (uint32_t)&pTxRx; /* 0121: l32r a2, 8 <ppProcessTxQ-0x28> (0 <ppProcessTxQ-0x30>) */ /* literal @0x8: pTxRx */
  a8 = a8 << (4 & 31); /* 0124: slli a8, a8, 4 */
  a2 = MEM32(a2 + 0); /* 0127: l32i.n a2, a2, 0 */
  a2 = a2 + a8; /* 0129: add.n a2, a2, a8 */
  MEM32(a2 + 4) = a11; /* 012b: s32i.n a11, a2, 4 */
L_12d:;
  a10 = a3; /* 012d: mov.n a10, a3 */
  MEMW(); /* 012f: memw  */
  a8 = (uint32_t)&pp_coex_tx_request; /* 0132: l32r a8, 28 <ppProcessTxQ-0x8> (0 <ppProcessTxQ-0x30>) */ /* literal: GOT slot for pp_coex_tx_request */
  pp_coex_tx_request(a2, a3, a4, a5); /* call via literal slot */ /* 0135: callx8 a8 */
  a11 = a4; /* 0138: mov.n a11, a4 */
  a10 = a3; /* 013a: mov.n a10, a3 */
  a8 = (uint32_t)&lmacTxFrame; /* 013c: l32r a8, 2c <ppProcessTxQ-0x4> (0 <ppProcessTxQ-0x30>) */ /* literal: GOT slot for lmacTxFrame */
  lmacTxFrame(a2, a3, a4, a5); /* call via literal slot */ /* 013f: callx8 a8 */
  a2 = 0x0; /* 0142: movi.n a2, 0 */
L_144:;
  return (int32_t)a2; /* 0144: retw.n  */
}

/* ppResortTxAMPDU @ pp.o 0000004c size 1010B bind GLOBAL
 * Calls: GetAccess[got], wifi_log[got], memcpy[got], lmacMSDUAged[got], ppCalSubFrameLength[got], ppSubFromAMPDU[got], lmacRecycleMPDU[got], lmacDiscardAgedMSDU[got], rcUpdateTxDoneAmpdu2[got], trc_isTxAmpduOperational[got], trc_tid_isTxAmpduOperational[got], ppAMPDU2Normal[got], ppFillAMPDUBar[got], ppReSendBar[got], ppResumeTxAMPDU[got], ppProcessTxQ[got] | Data refs: pTxRx, GetAccess, .rodata.pp_default_event_handler.str1.1, .rodata_wlog_error.46, wifi_log, memcpy, lmacMSDUAged, ppCalSubFrameLength, ppSubFromAMPDU, lmacRecycleMPDU, lmacDiscardAgedMSDU, rcUpdateTxDoneAmpdu2, trc_isTxAmpduOperational, trc_tid_isTxAmpduOperational, ppAMPDU2Normal, ppFillAMPDUBar, ppReSendBar, ppResumeTxAMPDU, ppProcessTxQ
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 16 call(s), 19 data ref(s)
 * Fidelity: medium - 384 instr, 55 branches, 0 indirect; flow + direct calls mapped, GOT-indirects enumerated (verified against section disasm) */
int32_t ppResortTxAMPDU(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .wifi0iram.45; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4c:;
  /* 004c: entry a1, 192 */
  a6 = (uint32_t)&pTxRx; /* 004f: l32r a6, 0 <ppResortTxAMPDU-0x4c> (0 <ppResortTxAMPDU-0x4c>) */ /* literal @0x0: pTxRx */
  a2 = (a2 >> 0) & 0xFF; /* 0052: extui a2, a2, 0, 8 */
  a5 = (a2 << 2) + a2; /* 0055: addx2 a5, a2, a2 */
  a5 = a5 << (4 & 31); /* 0058: slli a5, a5, 4 */
  a4 = a2 + a2; /* 005b: add.n a4, a2, a2 */
  a3 = MEM32(a6 + 0); /* 005d: l32i.n a3, a6, 0 */
  a10 = 0x4; /* 005f: movi.n a10, 4 */
  a3 = a3 + a5; /* 0061: add.n a3, a3, a5 */
  a3 = MEM8(a3 + 44); /* 0063: l8ui a3, a3, 44 */
  if (a3 >= 8) goto L_80; /* 0066: bgeui a3, 8, 80 <ppResortTxAMPDU+0x34> */
  if (a3 == 0) goto L_7e; /* 0069: beqz.n a3, 7e <ppResortTxAMPDU+0x32> */
  if (a3 == 3) goto L_7e; /* 006b: beqi a3, 3, 7e <ppResortTxAMPDU+0x32> */
  a10 = 0x3; /* 006e: movi.n a10, 3 */
  if (a3 < a10) goto L_80; /* 0070: bltu a3, a10, 80 <ppResortTxAMPDU+0x34> */
  a10 = 0x1; /* 0073: movi.n a10, 1 */
  if (a3 < 6) goto L_80; /* 0075: bltui a3, 6, 80 <ppResortTxAMPDU+0x34> */
  a10 = 0x0; /* 0078: movi.n a10, 0 */
  goto L_80; /* 007a: j 80 <ppResortTxAMPDU+0x34> */
  /* 007d: .byte 00 */
L_7e:;
  a10 = 0x2; /* 007e: movi.n a10, 2 */
L_80:;
  a8 = (uint32_t)&GetAccess; /* 0080: l32r a8, c <ppResortTxAMPDU-0x40> (0 <ppResortTxAMPDU-0x4c>) */ /* literal: GOT slot for GetAccess */
  GetAccess(a2, a3, a4, a5); /* call via literal slot */ /* 0083: callx8 a8 */
  a9 = MEM32(a6 + 0); /* 0086: l32i.n a9, a6, 0 */
  a8 = (a2 << 2) + a2; /* 0088: addx2 a8, a2, a2 */
  a8 = a8 << (4 & 31); /* 008b: slli a8, a8, 4 */
  a8 = a9 + a8; /* 008e: add.n a8, a9, a8 */
  a7 = MEM32(a8 + 52); /* 0090: l32i.n a7, a8, 52 */
  MEM32(a1 + 116) = a10; /* 0092: s32i a10, a1, 116 */
  if (a7 == 0) goto L_411; /* 0095: beqz a7, 411 <ppResortTxAMPDU+0x3c5> */
  a5 = a4 + a2; /* 0098: add.n a5, a4, a2 */
  a5 = a5 << (4 & 31); /* 009a: slli a5, a5, 4 */
  a5 = a9 + a5; /* 009d: add.n a5, a9, a5 */
  a6 = MEM8(a5 + 41); /* 009f: l8ui a6, a5, 41 */
  if (a6 != 0) goto L_c4; /* 00a2: bnez.n a6, c4 <ppResortTxAMPDU+0x78> */
  a15 = 0x67F; /* 00a4: movi a15, 0x67f */
  a12 = 0x1; /* 00a7: movi.n a12, 1 */
  a14 = (uint32_t)&lit_rodata_pp_default_event_handler_str1_1; /* 00a9: l32r a14, 4 <ppResortTxAMPDU-0x48> (0 <ppResortTxAMPDU-0x4c>) */ /* literal @0x4: .rodata.pp_default_event_handler.str1.1 */
  a15 = 0xCFE; /* 00ac: add.n a15, a15, a15 */
  a11 = 0x800; /* 00ae: slli a11, a12, 11 */
  a10 = 0x6; /* 00b1: movi a10, 6 */
  a13 = (uint32_t)&lit_rodata_wlog_error_46; /* 00b4: l32r a13, 8 <ppResortTxAMPDU-0x44> (0 <ppResortTxAMPDU-0x4c>) */ /* literal @0x8: .rodata_wlog_error.46 */
  MEMW(); /* 00b7: memw  */
  a8 = (uint32_t)&wifi_log; /* 00ba: l32r a8, 10 <ppResortTxAMPDU-0x3c> (0 <ppResortTxAMPDU-0x4c>) */ /* literal: GOT slot for wifi_log */
  wifi_log(a2, a3, a4, a5); /* call via literal slot */ /* 00bd: callx8 a8 */
L_c0:;
  goto L_c0; /* 00c0: j c0 <ppResortTxAMPDU+0x74> */
  /* 00c3: .byte 00 */
L_c4:;
  a6 = MEM32(a7 + 44); /* 00c4: l32i.n a6, a7, 44 */
  a12 = 0x20; /* 00c6: movi.n a12, 32 */
  a11 = a6; /* 00c8: mov.n a11, a6 */
  a10 = a1 + (48); /* 00ca: addi a10, a1, 48 */
  MEM32(a1 + 148) = a8; /* 00cd: s32i a8, a1, 148 */
  MEM32(a1 + 152) = a9; /* 00d0: s32i a9, a1, 152 */
  MEMW(); /* 00d3: memw  */
  a8 = (uint32_t)&memcpy; /* 00d6: l32r a8, 14 <ppResortTxAMPDU-0x38> (0 <ppResortTxAMPDU-0x4c>) */ /* literal: GOT slot for memcpy */
  memcpy(a2, a3, a4, a5); /* call via literal slot */ /* 00d9: callx8 a8 */
  a10 = 0x0; /* 00dc: movi.n a10, 0 */
  MEM16(a1 + 54) = a10; /* 00de: s16i a10, a1, 54 */
  a10 = 0x5; /* 00e1: movi.n a10, 5 */
  MEM8(a1 + 67) = a10; /* 00e3: s8i a10, a1, 67 */
  MEMW(); /* 00e6: memw  */
  a10 = a1 + (80); /* 00e9: addi a10, a1, 80 */
  MEM32(a1 + 8) = a10; /* 00ec: s32i.n a10, a1, 8 */
  a10 = MEM32(a7 + 4); /* 00ee: l32i.n a10, a7, 4 */
  MEM32(a1 + 88) = a10; /* 00f0: s32i a10, a1, 88 */
  a10 = MEM8(a5 + 77); /* 00f3: l8ui a10, a5, 77 */
  MEM32(a1 + 40) = a7; /* 00f6: s32i.n a7, a1, 40 */
  a8 = MEM32(a1 + 148); /* 00f8: l32i a8, a1, 148 */
  a9 = MEM32(a1 + 152); /* 00fb: l32i a9, a1, 152 */
  if (a10 != 0) goto L_110; /* 00fe: bnez.n a10, 110 <ppResortTxAMPDU+0xc4> */
  a10 = MEM8(a5 + 65); /* 0100: l8ui a10, a5, 65 */
  if (a10 != 2) goto L_110; /* 0103: bnei a10, 2, 110 <ppResortTxAMPDU+0xc4> */
  a5 = MEM32(a5 + 68); /* 0106: l32i a5, a5, 68 */
  MEMW(); /* 0109: memw  */
  goto L_118; /* 010c: j 118 <ppResortTxAMPDU+0xcc> */
  /* 010f: .byte 00 */
L_110:;
  a10 = MEM16(a7 + 22); /* 0110: l16ui a10, a7, 22 */
  a5 = MEM16(a7 + 20); /* 0113: l16ui a5, a7, 20 */
  a5 = a10 + a5; /* 0116: add.n a5, a10, a5 */
L_118:;
  a4 = a4 + a2; /* 0118: add.n a4, a4, a2 */
  a4 = a4 << (4 & 31); /* 011a: slli a4, a4, 4 */
  a9 = a9 + a4; /* 011d: add.n a9, a9, a4 */
  a4 = MEM16(a9 + 42); /* 011f: l16ui a4, a9, 42 */
  MEM32(a1 + 124) = a4; /* 0122: s32i a4, a1, 124 */
  a4 = 0x1; /* 0125: movi.n a4, 1 */
  /* 0127: ssl a3 */ /* UNMODELED: a3 clobbered */
  /* 012a: sll a4, a4 */ /* UNMODELED: a4 clobbered */
  MEM32(a1 + 112) = a5; /* 012d: s32i a5, a1, 112 */
  a5 = MEM32(a8 + 60); /* 0130: l32i.n a5, a8, 60 */
  a8 = MEM32(a8 + 56); /* 0132: l32i.n a8, a8, 56 */
  MEM32(a1 + 100) = a4; /* 0134: s32i a4, a1, 100 */
  a4 = 0xFFFFFFFF; /* 0137: movi.n a4, -1 */
  MEM32(a1 + 132) = a8; /* 0139: s32i a8, a1, 132 */
  a8 = MEM32(a1 + 100); /* 013c: l32i a8, a1, 100 */
  a4 = a4 ^ a8; /* 013f: xor a4, a4, a8 */
  a8 = (a2 << 2) + a2; /* 0142: addx2 a8, a2, a2 */
  a4 = (a4 >> 0) & 0xFF; /* 0145: extui a4, a4, 0, 8 */
  a9 = MEM8(a9 + 40); /* 0148: l8ui a9, a9, 40 */
  a8 = a8 << (4 & 31); /* 014b: slli a8, a8, 4 */
  a6 = MEM8(a6 + 5); /* 014e: l8ui a6, a6, 5 */
  MEM32(a1 + 136) = a9; /* 0151: s32i a9, a1, 136 */
  a9 = 0x0; /* 0154: movi.n a9, 0 */
  MEM32(a1 + 104) = a6; /* 0156: s32i a6, a1, 104 */
  MEM32(a1 + 128) = a5; /* 0159: s32i a5, a1, 128 */
  MEM32(a1 + 120) = a4; /* 015c: s32i a4, a1, 120 */
  a4 = 0x0; /* 015f: mov.n a4, a9 */
  a6 = MEM32(a7 + 36); /* 0161: l32i.n a6, a7, 36 */
  a5 = (uint32_t)&pTxRx; /* 0163: l32r a5, 0 <ppResortTxAMPDU-0x4c> (0 <ppResortTxAMPDU-0x4c>) */ /* literal @0x0: pTxRx */
  MEM32(a1 + 108) = a9; /* 0166: s32i a9, a1, 108 */
  MEM32(a1 + 96) = a1; /* 0169: s32i a1, a1, 96 */
  MEM32(a1 + 140) = a8; /* 016c: s32i a8, a1, 140 */
  MEMW(); /* 016f: memw  */
  goto L_2e8; /* 0172: j 2e8 <ppResortTxAMPDU+0x29c> */
L_175:;
  a10 = MEM32(a5 + 0); /* 0175: l32i.n a10, a5, 0 */
  a13 = MEM32(a1 + 140); /* 0177: l32i a13, a1, 140 */
  a10 = a10 + a13; /* 017a: add.n a10, a10, a13 */
  a11 = MEM8(a10 + 77); /* 017c: l8ui a11, a10, 77 */
  if (a11 != 0) goto L_1a9; /* 017f: bnez.n a11, 1a9 <ppResortTxAMPDU+0x15d> */
  a10 = MEM8(a10 + 65); /* 0181: l8ui a10, a10, 65 */
  if (a10 != 2) goto L_1a9; /* 0184: bnei a10, 2, 1a9 <ppResortTxAMPDU+0x15d> */
  if (a4 != 0) goto L_194; /* 0187: bnez.n a4, 194 <ppResortTxAMPDU+0x148> */
  a10 = MEM8(a1 + 55); /* 0189: l8ui a10, a1, 55 */
  a10 = a10 + (1); /* 018c: addi.n a10, a10, 1 */
  MEM8(a1 + 55) = a10; /* 018e: s8i a10, a1, 55 */
  MEMW(); /* 0191: memw  */
L_194:;
  a10 = MEM32(a8 + 8); /* 0194: l32i.n a10, a8, 8 */
  MEMW(); /* 0196: memw  */
  a10 = MEM32(a10 + 0); /* 0199: l32i.n a10, a10, 0 */
  if (!((a10 >> 30) & 1)) goto L_1b4; /* 019b: bbci a10, 30, 1b4 <ppResortTxAMPDU+0x168> */
  a4 = 0x1; /* 019e: addi.n a4, a4, 1 */
  a4 = 0x1; /* 01a0: extui a4, a4, 0, 8 */
  MEMW(); /* 01a3: memw  */
  goto L_1b4; /* 01a6: j 1b4 <ppResortTxAMPDU+0x168> */
L_1a9:;
  a10 = MEM8(a1 + 55); /* 01a9: l8ui a10, a1, 55 */
  a10 = a10 + (1); /* 01ac: addi.n a10, a10, 1 */
  MEM8(a1 + 55) = a10; /* 01ae: s8i a10, a1, 55 */
  MEMW(); /* 01b1: memw  */
L_1b4:;
  a11 = 0xC0; /* 01b4: movi a11, 192 */
  a10 = MEM32(a8 + 4); /* 01b7: l32i a10, a8, 4 */
  a10 = MEM32(a10 + 4); /* 01ba: l32i a10, a10, 4 */
  a13 = MEM32(a1 + 124); /* 01bd: l32i a13, a1, 124 */
  a10 = MEM8(a10 + 3); /* 01c0: l8ui a10, a10, 3 */
  a10 = a10 - a13; /* 01c3: sub a10, a10, a13 */
  if ((a10 & a11) != 0) goto L_1ee; /* 01c6: bany a10, a11, 1ee <ppResortTxAMPDU+0x1a2> */
  a12 = 0xE0; /* 01c9: movi a12, 224 */
  a13 = MEM32(a1 + 128); /* 01cc: l32i a13, a1, 128 */
  a11 = (a10 >> 0) & 0xFF; /* 01cf: extui a11, a10, 0, 8 */
  if ((a10 & a12) == 0) goto L_1d8; /* 01d2: bnone a10, a12, 1d8 <ppResortTxAMPDU+0x18c> */
  a13 = MEM32(a1 + 132); /* 01d5: l32i a13, a1, 132 */
L_1d8:;
  if (!((a13 >> (a11 & 31)) & 1)) goto L_1ee; /* 01d8: bbc a13, a11, 1ee <ppResortTxAMPDU+0x1a2> */
  a12 = 0x1; /* 01db: movi.n a12, 1 */
  a10 = MEM8(a1 + 54); /* 01dd: l8ui a10, a1, 54 */
  a10 = a10 + (1); /* 01e0: addi.n a10, a10, 1 */
  MEM8(a1 + 54) = a10; /* 01e2: s8i a10, a1, 54 */
  MEMW(); /* 01e5: memw  */
  MEMW(); /* 01e8: memw  */
  goto L_249; /* 01eb: j 249 <ppResortTxAMPDU+0x1fd> */
L_1ee:;
  a10 = a8; /* 01ee: mov.n a10, a8 */
  MEM32(a1 + 148) = a8; /* 01f0: s32i a8, a1, 148 */
  MEM32(a1 + 152) = a9; /* 01f3: s32i a9, a1, 152 */
  MEMW(); /* 01f6: memw  */
  a8 = (uint32_t)&lmacMSDUAged; /* 01f9: l32r a8, 18 <ppResortTxAMPDU-0x34> (0 <ppResortTxAMPDU-0x4c>) */ /* literal: GOT slot for lmacMSDUAged */
  lmacMSDUAged(a2, a3, a4, a5); /* call via literal slot */ /* 01fc: callx8 a8 */
  a12 = 0x0; /* 01ff: movi.n a12, 0 */
  a8 = MEM32(a1 + 148); /* 0201: l32i a8, a1, 148 */
  a9 = MEM32(a1 + 152); /* 0204: l32i a9, a1, 152 */
  if (a10 != a12) goto L_249; /* 0207: bne a10, a12, 249 <ppResortTxAMPDU+0x1fd> */
  if (a4 == a12) goto L_21a; /* 020a: beq a4, a12, 21a <ppResortTxAMPDU+0x1ce> */
  if (a4 != 1) goto L_238; /* 020d: bnei a4, 1, 238 <ppResortTxAMPDU+0x1ec> */
  a10 = MEM32(a8 + 8); /* 0210: l32i.n a10, a8, 8 */
  MEMW(); /* 0212: memw  */
  a10 = MEM32(a10 + 0); /* 0215: l32i.n a10, a10, 0 */
  if (!((a10 >> 30) & 1)) goto L_238; /* 0217: bbci a10, 30, 238 <ppResortTxAMPDU+0x1ec> */
L_21a:;
  a10 = MEM32(a8 + 4); /* 021a: l32i.n a10, a8, 4 */
  a11 = MEM32(a10 + 4); /* 021c: l32i.n a11, a10, 4 */
  a10 = MEM32(a8 + 44); /* 021e: l32i a10, a8, 44 */
  a10 = MEM32(a10 + 0); /* 0221: l32i a10, a10, 0 */
  if (!((a10 >> 18) & 1)) goto L_22a; /* 0224: bbci a10, 18, 22a <ppResortTxAMPDU+0x1de> */
  a11 = a11 + (4); /* 0227: addi a11, a11, 4 */
L_22a:;
  a12 = 0x8; /* 022a: movi.n a12, 8 */
  a10 = MEM8(a11 + 1); /* 022c: l8ui a10, a11, 1 */
  a10 = a10 | a12; /* 022f: or a10, a10, a12 */
  MEM8(a11 + 1) = a10; /* 0232: s8i a10, a11, 1 */
  MEMW(); /* 0235: memw  */
L_238:;
  a13 = MEM32(a1 + 96); /* 0238: l32i a13, a1, 96 */
  a13 = MEM32(a13 + 40); /* 023b: l32i.n a13, a13, 40 */
  MEM32(a1 + 108) = a8; /* 023d: s32i a8, a1, 108 */
  MEM32(a1 + 96) = a13; /* 0240: s32i a13, a1, 96 */
  MEMW(); /* 0243: memw  */
  goto L_2e8; /* 0246: j 2e8 <ppResortTxAMPDU+0x29c> */
L_249:;
  a10 = a8; /* 0249: mov.n a10, a8 */
  MEM32(a1 + 152) = a9; /* 024b: s32i a9, a1, 152 */
  MEM32(a1 + 144) = a12; /* 024e: s32i a12, a1, 144 */
  MEM32(a1 + 148) = a8; /* 0251: s32i a8, a1, 148 */
  MEMW(); /* 0254: memw  */
  a8 = (uint32_t)&ppCalSubFrameLength; /* 0257: l32r a8, 1c <ppResortTxAMPDU-0x30> (0 <ppResortTxAMPDU-0x4c>) */ /* literal: GOT slot for ppCalSubFrameLength */
  ppCalSubFrameLength(a2, a3, a4, a5); /* call via literal slot */ /* 025a: callx8 a8 */
  a8 = MEM32(a1 + 148); /* 025d: l32i a8, a1, 148 */
  a11 = a8 | a8; /* 0260: or a11, a8, a8 */
  a10 = MEM32(a1 + 96); /* 0263: l32i a10, a1, 96 */
  a8 = (uint32_t)&ppSubFromAMPDU; /* 0266: l32r a8, 20 <ppResortTxAMPDU-0x2c> (0 <ppResortTxAMPDU-0x4c>) */ /* literal: GOT slot for ppSubFromAMPDU */
  ppSubFromAMPDU(a2, a3, a4, a5); /* call via literal slot */ /* 0269: callx8 a8 */
  a10 = 0x1; /* 026c: movi.n a10, 1 */
  a10 = 0x400000; /* 026e: slli a10, a10, 22 */
  a8 = MEM32(a1 + 148); /* 0271: l32i a8, a1, 148 */
  a14 = MEM32(a8 + 44); /* 0274: l32i.n a14, a8, 44 */
  a11 = MEM32(a14 + 0); /* 0276: l32i.n a11, a14, 0 */
  a10 = a11 | a10; /* 0278: or a10, a11, a10 */
  a12 = MEM32(a1 + 144); /* 027b: l32i a12, a1, 144 */
  MEM32(a14 + 0) = a10; /* 027e: s32i.n a10, a14, 0 */
  a9 = MEM32(a1 + 152); /* 0280: l32i a9, a1, 152 */
  if (a12 == 0) goto L_2c4; /* 0283: beqz.n a12, 2c4 <ppResortTxAMPDU+0x278> */
  a10 = MEM8(a6 + 38); /* 0285: l8ui a10, a6, 38 */
  a13 = MEM32(a1 + 100); /* 0288: l32i a13, a1, 100 */
  a12 = a10 & a13; /* 028b: and a12, a10, a13 */
  if (a13 != a12) goto L_2ad; /* 028e: bne a13, a12, 2ad <ppResortTxAMPDU+0x261> */
  a9 = 0x0; /* 0291: movi.n a9, 0 */
  if (!((a11 >> 19) & 1)) goto L_2a1; /* 0293: bbci a11, 19, 2a1 <ppResortTxAMPDU+0x255> */
  a9 = MEM32(a8 + 4); /* 0296: l32i.n a9, a8, 4 */
  a9 = MEM32(a9 + 4); /* 0298: l32i a9, a9, 4 */
  if (!((a11 >> 18) & 1)) goto L_2a1; /* 029b: bbci a11, 18, 2a1 <ppResortTxAMPDU+0x255> */
  a9 = a9 + (4); /* 029e: addi a9, a9, 4 */
L_2a1:;
  a13 = MEM32(a1 + 120); /* 02a1: l32i a13, a1, 120 */
  a10 = a10 & a13; /* 02a4: and a10, a10, a13 */
  MEM8(a6 + 38) = a10; /* 02a7: s8i a10, a6, 38 */
  MEMW(); /* 02aa: memw  */
L_2ad:;
  a12 = 0x0; /* 02ad: movi.n a12, 0 */
  a11 = a8; /* 02af: mov.n a11, a8 */
  a10 = MEM32(a1 + 116); /* 02b1: l32i a10, a1, 116 */
  MEM32(a1 + 152) = a9; /* 02b4: s32i a9, a1, 152 */
  MEMW(); /* 02b7: memw  */
  a8 = (uint32_t)&lmacRecycleMPDU; /* 02ba: l32r a8, 24 <ppResortTxAMPDU-0x28> (0 <ppResortTxAMPDU-0x4c>) */ /* literal: GOT slot for lmacRecycleMPDU */
  lmacRecycleMPDU(a2, a3, a4, a5); /* call via literal slot */ /* 02bd: callx8 a8 */
  goto L_2e5; /* 02c0: j 2e5 <ppResortTxAMPDU+0x299> */
  /* 02c3: .byte 00 */
L_2c4:;
  a9 = 0x0; /* 02c4: mov.n a9, a12 */
  if (!((a11 >> 19) & 1)) goto L_2d2; /* 02c6: bbci a11, 19, 2d2 <ppResortTxAMPDU+0x286> */
  a9 = MEM32(a8 + 4); /* 02c9: l32i.n a9, a8, 4 */
  a9 = MEM32(a9 + 4); /* 02cb: l32i.n a9, a9, 4 */
  if (!((a11 >> 18) & 1)) goto L_2d2; /* 02cd: bbci a11, 18, 2d2 <ppResortTxAMPDU+0x286> */
  a9 = a9 + (4); /* 02d0: addi.n a9, a9, 4 */
L_2d2:;
  a12 = 0x0; /* 02d2: movi.n a12, 0 */
  a11 = a8; /* 02d4: mov.n a11, a8 */
  a10 = MEM32(a1 + 116); /* 02d6: l32i a10, a1, 116 */
  MEM32(a1 + 152) = a9; /* 02d9: s32i a9, a1, 152 */
  MEMW(); /* 02dc: memw  */
  a8 = (uint32_t)&lmacDiscardAgedMSDU; /* 02df: l32r a8, 28 <ppResortTxAMPDU-0x24> (0 <ppResortTxAMPDU-0x4c>) */ /* literal: GOT slot for lmacDiscardAgedMSDU */
  lmacDiscardAgedMSDU(a2, a3, a4, a5); /* call via literal slot */ /* 02e2: callx8 a8 */
L_2e5:;
  a9 = MEM32(a1 + 152); /* 02e5: l32i a9, a1, 152 */
L_2e8:;
  a13 = MEM32(a1 + 96); /* 02e8: l32i a13, a1, 96 */
  a8 = MEM32(a13 + 40); /* 02eb: l32i.n a8, a13, 40 */
  if (a8 != 0) goto L_175; /* 02ed: bnez a8, 175 <ppResortTxAMPDU+0x129> */
  a4 = MEM32(a1 + 136); /* 02f0: l32i a4, a1, 136 */
  if (a4 != 0) goto L_311; /* 02f3: bnez.n a4, 311 <ppResortTxAMPDU+0x2c5> */
  a4 = 0x1; /* 02f5: movi.n a4, 1 */
  MEM8(a1 + 67) = a4; /* 02f7: s8i a4, a1, 67 */
  MEMW(); /* 02fa: memw  */
  a4 = MEM32(a7 + 44); /* 02fd: l32i.n a4, a7, 44 */
  a4 = MEM8(a4 + 13); /* 02ff: l8ui a4, a4, 13 */
  MEM8(a1 + 61) = a4; /* 0302: s8i a4, a1, 61 */
  MEMW(); /* 0305: memw  */
  MEMW(); /* 0308: memw  */
  goto L_31c; /* 030b: j 31c <ppResortTxAMPDU+0x2d0> */
  /* 030e: .byte 00 */
  /* 030f: .byte 00 */
  /* 0310: .byte 00 */
L_311:;
  a8 = MEM32(a1 + 104); /* 0311: l32i a8, a1, 104 */
  a4 = a8 + (1); /* 0314: addi.n a4, a8, 1 */
  a4 = (a4 >> 0) & 0xFF; /* 0316: extui a4, a4, 0, 8 */
  MEM32(a1 + 104) = a4; /* 0319: s32i a4, a1, 104 */
L_31c:;
  a11 = a1 + (48); /* 031c: addi a11, a1, 48 */
  a10 = a6; /* 031f: mov.n a10, a6 */
  a4 = MEM32(a1 + 112); /* 0321: l32i a4, a1, 112 */
  a12 = (a4 >> 0) & 0xFFFF; /* 0324: extui a12, a4, 0, 16 */
  a4 = a2 + (1); /* 0327: addi.n a4, a2, 1 */
  a13 = MEM32(a1 + 104); /* 0329: l32i a13, a1, 104 */
  MEM32(a1 + 152) = a9; /* 032c: s32i a9, a1, 152 */
  MEM8(a1 + 53) = a13; /* 032f: s8i a13, a1, 53 */
  MEMW(); /* 0332: memw  */
  MEMW(); /* 0335: memw  */
  a8 = (uint32_t)&rcUpdateTxDoneAmpdu2; /* 0338: l32r a8, 2c <ppResortTxAMPDU-0x20> (0 <ppResortTxAMPDU-0x4c>) */ /* literal: GOT slot for rcUpdateTxDoneAmpdu2 */
  rcUpdateTxDoneAmpdu2(a2, a3, a4, a5); /* call via literal slot */ /* 033b: callx8 a8 */
  a10 = a6; /* 033e: mov.n a10, a6 */
  a7 = MEM32(a1 + 40); /* 0340: l32i a7, a1, 40 */
  a8 = (uint32_t)&trc_isTxAmpduOperational; /* 0343: l32r a8, 30 <ppResortTxAMPDU-0x1c> (0 <ppResortTxAMPDU-0x4c>) */ /* literal: GOT slot for trc_isTxAmpduOperational */
  trc_isTxAmpduOperational(a2, a3, a4, a5); /* call via literal slot */ /* 0346: callx8 a8 */
  a9 = MEM32(a1 + 152); /* 0349: l32i a9, a1, 152 */
  if (a10 == 0) goto L_380; /* 034c: beqz.n a10, 380 <ppResortTxAMPDU+0x334> */
  a11 = a3; /* 034e: mov.n a11, a3 */
  a10 = a6; /* 0350: mov.n a10, a6 */
  a8 = (uint32_t)&trc_tid_isTxAmpduOperational; /* 0352: l32r a8, 34 <ppResortTxAMPDU-0x18> (0 <ppResortTxAMPDU-0x4c>) */ /* literal: GOT slot for trc_tid_isTxAmpduOperational */
  trc_tid_isTxAmpduOperational(a2, a3, a4, a5); /* call via literal slot */ /* 0355: callx8 a8 */
  a9 = MEM32(a1 + 152); /* 0358: l32i a9, a1, 152 */
  if (a10 == 0) goto L_380; /* 035b: beqz.n a10, 380 <ppResortTxAMPDU+0x334> */
  a4 = (a4 << 2) + a4; /* 035d: addx2 a4, a4, a4 */
  a4 = a4 << (4 & 31); /* 0360: slli a4, a4, 4 */
  a5 = MEM32(a5 + 0); /* 0363: l32i.n a5, a5, 0 */
  a4 = a5 + a4; /* 0365: add.n a4, a5, a4 */
  MEM32(a4 + 4) = a7; /* 0367: s32i.n a7, a4, 4 */
  if (a7 == 0) goto L_3e6; /* 0369: beqz a7, 3e6 <ppResortTxAMPDU+0x39a> */
  a5 = 0x9; /* 036c: movi.n a5, 9 */
  a5 = 0x480000; /* 036e: slli a5, a5, 19 */
  a6 = MEM32(a7 + 44); /* 0371: l32i.n a6, a7, 44 */
  a4 = MEM32(a6 + 0); /* 0373: l32i.n a4, a6, 0 */
  a4 = a4 | a5; /* 0375: or a4, a4, a5 */
  MEM32(a6 + 0) = a4; /* 0378: s32i.n a4, a6, 0 */
  MEMW(); /* 037a: memw  */
  goto L_3e6; /* 037d: j 3e6 <ppResortTxAMPDU+0x39a> */
L_380:;
  if (a7 == 0) goto L_3d8; /* 0380: beqz a7, 3d8 <ppResortTxAMPDU+0x38c> */
  a6 = MEM32(a5 + 0); /* 0383: l32i.n a6, a5, 0 */
  a8 = (a4 << 2) + a4; /* 0385: addx2 a8, a4, a4 */
  a8 = a8 << (4 & 31); /* 0388: slli a8, a8, 4 */
  a6 = a6 + a8; /* 038b: add.n a6, a6, a8 */
  a6 = MEM32(a6 + 4); /* 038d: l32i.n a6, a6, 4 */
  if (a6 != a7) goto L_3a4; /* 038f: bne a6, a7, 3a4 <ppResortTxAMPDU+0x358> */
  a10 = a7 | a7; /* 0392: or a10, a7, a7 */
  MEM32(a1 + 152) = a9; /* 0395: s32i a9, a1, 152 */
  MEMW(); /* 0398: memw  */
  a8 = (uint32_t)&ppAMPDU2Normal; /* 039b: l32r a8, 38 <ppResortTxAMPDU-0x14> (0 <ppResortTxAMPDU-0x4c>) */ /* literal: GOT slot for ppAMPDU2Normal */
  ppAMPDU2Normal(a2, a3, a4, a5); /* call via literal slot */ /* 039e: callx8 a8 */
  a9 = MEM32(a1 + 152); /* 03a1: l32i a9, a1, 152 */
L_3a4:;
  a6 = a7; /* 03a4: mov.n a6, a7 */
  a8 = 0x0; /* 03a6: movi.n a8, 0 */
  goto L_3b1; /* 03a8: j 3b1 <ppResortTxAMPDU+0x365> */
L_3ab:;
  a10 = MEM32(a6 + 8); /* 03ab: l32i.n a10, a6, 8 */
  a6 = MEM32(a6 + 40); /* 03ad: l32i.n a6, a6, 40 */
  MEM32(a10 + 8) = a8; /* 03af: s32i.n a8, a10, 8 */
L_3b1:;
  a13 = MEM32(a1 + 108); /* 03b1: l32i a13, a1, 108 */
  if (a6 != a13) goto L_3ab; /* 03b4: bne a6, a13, 3ab <ppResortTxAMPDU+0x35f> */
  a8 = (a2 << 2) + a2; /* 03b7: addx2 a8, a2, a2 */
  a8 = a8 << (4 & 31); /* 03ba: slli a8, a8, 4 */
  a10 = MEM32(a5 + 0); /* 03bd: l32i.n a10, a5, 0 */
  a11 = a2 + a2; /* 03bf: add.n a11, a2, a2 */
  a8 = a10 + a8; /* 03c1: add.n a8, a10, a8 */
  a12 = MEM32(a8 + 32); /* 03c3: l32i.n a12, a8, 32 */
  MEM32(a6 + 40) = a12; /* 03c5: s32i.n a12, a6, 40 */
  if (a12 != 0) goto L_3ce; /* 03c7: bnez.n a12, 3ce <ppResortTxAMPDU+0x382> */
  a6 = a6 + (40); /* 03c9: addi a6, a6, 40 */
  MEM32(a8 + 36) = a6; /* 03cc: s32i.n a6, a8, 36 */
L_3ce:;
  a6 = a11 + a2; /* 03ce: add.n a6, a11, a2 */
  a6 = a6 << (4 & 31); /* 03d0: slli a6, a6, 4 */
  a10 = a10 + a6; /* 03d3: add a10, a10, a6 */
  MEM32(a10 + 32) = a7; /* 03d6: s32i.n a7, a10, 32 */
L_3d8:;
  a4 = (a4 << 2) + a4; /* 03d8: addx2 a4, a4, a4 */
  a4 = a4 << (4 & 31); /* 03db: slli a4, a4, 4 */
  a5 = MEM32(a5 + 0); /* 03de: l32i.n a5, a5, 0 */
  a4 = a5 + a4; /* 03e0: add.n a4, a5, a4 */
  a5 = 0x0; /* 03e2: movi.n a5, 0 */
  MEM32(a4 + 4) = a5; /* 03e4: s32i.n a5, a4, 4 */
L_3e6:;
  if (a9 == 0) goto L_411; /* 03e6: beqz.n a9, 411 <ppResortTxAMPDU+0x3c5> */
  a11 = a9 + (4); /* 03e8: addi.n a11, a9, 4 */
  a12 = a9 + (10); /* 03ea: addi.n a12, a9, 10 */
  a10 = a3; /* 03ec: mov.n a10, a3 */
  a13 = MEM16(a9 + 22); /* 03ee: l16ui a13, a9, 22 */
  a13 = a13 >> (4 & 31); /* 03f1: srli a13, a13, 4 */
  a13 = a13 + (1); /* 03f4: addi.n a13, a13, 1 */
  a13 = (a13 >> 0) & 0xFFF; /* 03f6: extui a13, a13, 0, 12 */
  MEMW(); /* 03f9: memw  */
  a8 = (uint32_t)&ppFillAMPDUBar; /* 03fc: l32r a8, 3c <ppResortTxAMPDU-0x10> (0 <ppResortTxAMPDU-0x4c>) */ /* literal: GOT slot for ppFillAMPDUBar */
  ppFillAMPDUBar(a2, a3, a4, a5); /* call via literal slot */ /* 03ff: callx8 a8 */
  a11 = a2; /* 0402: mov.n a11, a2 */
  a10 = a3; /* 0404: mov.n a10, a3 */
  a8 = (uint32_t)&ppReSendBar; /* 0406: l32r a8, 40 <ppResortTxAMPDU-0xc> (0 <ppResortTxAMPDU-0x4c>) */ /* literal: GOT slot for ppReSendBar */
  ppReSendBar(a2, a3, a4, a5); /* call via literal slot */ /* 0409: callx8 a8 */
  a2 = 0x0; /* 040c: movi.n a2, 0 */
  goto L_43c; /* 040e: j 43c <ppResortTxAMPDU+0x3f0> */
L_411:;
  a10 = 0x0; /* 0411: mov.n a10, a2 */
  a8 = (uint32_t)&ppResumeTxAMPDU; /* 0413: l32r a8, 44 <ppResortTxAMPDU-0x8> (0 <ppResortTxAMPDU-0x4c>) */ /* literal: GOT slot for ppResumeTxAMPDU */
  ppResumeTxAMPDU(a2, a3, a4, a5); /* call via literal slot */ /* 0416: callx8 a8 */
  a10 = 0x4; /* 0419: movi.n a10, 4 */
  if (a3 >= 8) goto L_434; /* 041b: bgeui a3, 8, 434 <ppResortTxAMPDU+0x3e8> */
  if (a3 == 0) goto L_432; /* 041e: beqz.n a3, 432 <ppResortTxAMPDU+0x3e6> */
  if (a3 == 3) goto L_432; /* 0420: beqi a3, 3, 432 <ppResortTxAMPDU+0x3e6> */
  a10 = 0x3; /* 0423: movi.n a10, 3 */
  if (a3 < a10) goto L_434; /* 0425: bltu a3, a10, 434 <ppResortTxAMPDU+0x3e8> */
  a10 = 0x1; /* 0428: movi.n a10, 1 */
  if (a3 < 6) goto L_434; /* 042a: bltui a3, 6, 434 <ppResortTxAMPDU+0x3e8> */
  a10 = 0x0; /* 042d: movi.n a10, 0 */
  goto L_434; /* 042f: j 434 <ppResortTxAMPDU+0x3e8> */
L_432:;
  a10 = 0x2; /* 0432: movi.n a10, 2 */
L_434:;
  a8 = (uint32_t)&ppProcessTxQ; /* 0434: l32r a8, 48 <ppResortTxAMPDU-0x4> (0 <ppResortTxAMPDU-0x4c>) */ /* literal: GOT slot for ppProcessTxQ */
  ppProcessTxQ(a2, a3, a4, a5); /* call via literal slot */ /* 0437: callx8 a8 */
  a2 = 0x2; /* 043a: mov.n a2, a10 */
L_43c:;
  return (int32_t)a2; /* 043c: retw.n  */
}

/* ppTask @ pp.o 0000006c size 507B bind GLOBAL
 * Calls: .rodata[tail], .rodata[got], pp_timer_do_process[got], pp_timer_do_process[got], .bss.g_timer_func[got], .bss.g_timer_func[got], ppProcessTxQ[got], ppProcTxDone[got], .bss.g_net80211_tx_func[got], ppRxPkt[got], .bss.g_net80211_tx_func[got], ppResortTxAMPDU[got], .bss.g_net80211_tx_func[got], ppProcessRxPktHdr[got], .bss.g_net80211_tx_func[got], lmacProcessTxTimeout[got], .bss.g_net80211_tx_func[got], lmacProcessTxComplete[got], .bss.g_net80211_tx_func[got], lmacProcessCollisions_task[got], .bss.g_net80211_tx_func[got], wifi_gpio_debug[got], .bss.g_net80211_tx_func[got], wdevProcessRxSucDataAll[got], .bss.g_net80211_tx_func[got], wdev_process_misc_pkt[got], wifi_log[got], pp_default_event_handler[got], .bss.s_pp_task_create_sem[got], .bss.s_pp_task_del_sem[got], .bss.s_pp_task_create_sem[got], g_osi_funcs_p[got] | Data refs: g_osi_funcs_p, .bss.s_pp_task_create_sem, xphyQueue, g_intr_lock_mux, pp_sig_cnt, .rodata, pp_timer_do_process, .bss.g_timer_func, .bss.g_config_func, ppProcessTxQ, .bss.g_net80211_tx_func, ppProcTxDone, ppRxPkt, ppResortTxAMPDU, ppProcessRxPktHdr, lmacProcessTxTimeout, lmacProcessTxComplete, lmacProcessCollisions_task, wifi_gpio_debug, wdevProcessRxSucDataAll, wdev_process_misc_pkt, .rodata_wlog_error.10, wifi_log, pp_default_event_handler, .bss.s_pp_task_del_sem, s_wifi_queue, .bss.pp_task_hdl
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 32 call(s), 27 data ref(s)
 * Fidelity: low - 198 instr, 26 branches, 5 indirect; jx computed dispatch at +0xf8 (movi 26 at +0xe6, bgeu at +0xea, l32r at +0xf0 + addx4 at +0xf3, jx a5); per-case targets structural - need jump-table case decode to raise */
int32_t ppTask(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .wifi0iram.9; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_6c:;
  /* 006c: entry a1, 48 */
  a2 = (uint32_t)&g_osi_funcs_p; /* 006f: l32r a2, 4 <ppTask-0x68> (0 <ppTask-0x6c>) */ /* literal @0x4: g_osi_funcs_p */
  a4 = (uint32_t)&bss_s_pp_task_create_sem; /* 0072: l32r a4, 0 <ppTask-0x6c> (0 <ppTask-0x6c>) */ /* literal @0x0: .bss.s_pp_task_create_sem */
  a3 = MEM32(a2 + 0); /* 0075: l32i.n a3, a2, 0 */
  a10 = MEM32(a4 + 0); /* 0077: l32i.n a10, a4, 0 */
  a4 = 0x0; /* 0079: movi.n a4, 0 */
  a3 = MEM32(a3 + 64); /* 007b: l32i a3, a3, 64 */
  ((int32_t(*)())a3)(a2, a3, a4, a5); /* 007e: callx8 a3 */ /* indirect */
  a3 = (uint32_t)&xphyQueue; /* 0081: l32r a3, 8 <ppTask-0x64> (0 <ppTask-0x6c>) */ /* literal @0x8: xphyQueue */
  goto L_8a; /* 0084: j 8a <ppTask+0x1e> */
  /* 0087: .byte 00 */
L_88:;
  a4 = 0x1; /* 0088: movi.n a4, 1 */
L_8a:;
  a5 = MEM32(a2 + 0); /* 008a: l32i.n a5, a2, 0 */
  a12 = 0xFFFFFFFF; /* 008c: movi.n a12, -1 */
  a11 = a1; /* 008e: mov.n a11, a1 */
  a5 = MEM32(a5 + 116); /* 0090: l32i a5, a5, 116 */
  a10 = MEM32(a3 + 0); /* 0093: l32i a10, a3, 0 */
  ((int32_t(*)())a5)(a2, a3, a4, a5); /* 0096: callx8 a5 */ /* indirect */
  if (a10 == 1) goto L_9f; /* 0099: beqi a10, 1, 9f <ppTask+0x33> */
  goto L_224; /* 009c: j 224 <ppTask+0x1b8> */
L_9f:;
  a8 = 0x1D; /* 009f: movi.n a8, 29 */
  a5 = MEM32(a1 + 0); /* 00a1: l32i.n a5, a1, 0 */
  if (a8 < a5) goto L_e6; /* 00a3: bltu a8, a5, e6 <ppTask+0x7a> */
  a5 = a5 + (-13); /* 00a6: addi a5, a5, -13 */
  a8 = 0x0; /* 00a9: movi.n a8, 0 */
  if (a5 == 0) a10 = a8; /* 00ab: moveqz a10, a8, a5 */
  a10 = (a10 >> 0) & 0xFF; /* 00ae: extui a10, a10, 0, 8 */
  if (a10 == a8) goto L_e6; /* 00b1: beq a10, a8, e6 <ppTask+0x7a> */
  a5 = (uint32_t)&g_intr_lock_mux; /* 00b4: l32r a5, c <ppTask-0x60> (0 <ppTask-0x6c>) */ /* literal @0xC: g_intr_lock_mux */
  a8 = MEM32(a2 + 0); /* 00b7: l32i.n a8, a2, 0 */
  a10 = MEM32(a5 + 0); /* 00b9: l32i.n a10, a5, 0 */
  a8 = MEM32(a8 + 40); /* 00bb: l32i.n a8, a8, 40 */
  ((int32_t(*)())a8)(a2, a3, a4, a5); /* 00bd: callx8 a8 */ /* indirect */
  a11 = a10; /* 00c0: mov.n a11, a10 */
  a8 = MEM32(a1 + 0); /* 00c2: l32i.n a8, a1, 0 */
  a9 = (uint32_t)&pp_sig_cnt; /* 00c4: l32r a9, 10 <ppTask-0x5c> (0 <ppTask-0x6c>) */ /* literal @0x10: pp_sig_cnt */
  a9 = a9 + a8; /* 00c7: add.n a9, a9, a8 */
  MEMW(); /* 00c9: memw  */
  a8 = MEM8(a9 + 0); /* 00cc: l8ui a8, a9, 0 */
  a8 = a8 + (-1); /* 00cf: addi.n a8, a8, -1 */
  a8 = (a8 >> 0) & 0xFF; /* 00d1: extui a8, a8, 0, 8 */
  MEMW(); /* 00d4: memw  */
  MEM8(a9 + 0) = a8; /* 00d7: s8i a8, a9, 0 */
  a8 = MEM32(a2 + 0); /* 00da: l32i.n a8, a2, 0 */
  a10 = MEM32(a5 + 0); /* 00dc: l32i.n a10, a5, 0 */
  a8 = MEM32(a8 + 44); /* 00de: l32i.n a8, a8, 44 */
  MEMW(); /* 00e0: memw  */
  ((int32_t(*)())a8)(a2, a3, a4, a5); /* 00e3: callx8 a8 */ /* indirect */
L_e6:;
  a5 = 0x1A; /* 00e6: movi.n a5, 26 */
  a10 = MEM32(a1 + 0); /* 00e8: l32i.n a10, a1, 0 */
  if (a5 >= a10) goto L_f0; /* 00ea: bgeu a5, a10, f0 <ppTask+0x84> */
  goto L_21c; /* 00ed: j 21c <ppTask+0x1b0> */
L_f0:;
  a5 = (uint32_t)&lit_rodata; /* 00f0: l32r a5, 14 <ppTask-0x58> (0 <ppTask-0x6c>) */ /* literal @0x14: .rodata */
  a5 = (a10 << 4) + a5; /* 00f3: addx4 a5, a10, a5 */
  a5 = MEM32(a5 + 0); /* 00f6: l32i.n a5, a5, 0 */
  /* 00f8: jx a5 */ /* jx a5: computed tail jump; modeled as return */
  return (int32_t)a2;
  /* 00fb: .byte 00 */
  a5 = MEM32(a2 + 0); /* 00fc: l32i.n a5, a2, 0 */
  a5 = MEM32(a5 + 216); /* 00fe: l32i a5, a5, 216 */
  ((int32_t(*)())a5)(a2, a3, a4, a5); /* 0101: callx8 a5 */ /* indirect */
  a10 = MEM32(a1 + 4); /* 0104: l32i.n a10, a1, 4 */
  a8 = (uint32_t)&pp_timer_do_process; /* 0106: l32r a8, 34 <ppTask-0x38> (0 <ppTask-0x6c>) */ /* literal: GOT slot for pp_timer_do_process */
  pp_timer_do_process(a2, a3, a4, a5); /* call via literal slot */ /* 0109: callx8 a8 */
  goto L_128; /* 010c: j 128 <ppTask+0xbc> */
  /* 010f: .byte 00 */
  /* 0110: .byte 00 */
  a8 = MEM32(a2 + 0); /* 0111: l32i.n a8, a2, 0 */
  a5 = (uint32_t)&bss_g_timer_func; /* 0113: l32r a5, 18 <ppTask-0x54> (0 <ppTask-0x6c>) */ /* literal @0x18: .bss.g_timer_func */
L_116:;
  a9 = MEM32(a5 + 0); /* 0116: l32i.n a9, a5, 0 */
  if (a9 == 0) goto L_224; /* 0118: beqz a9, 224 <ppTask+0x1b8> */
  a8 = MEM32(a8 + 216); /* 011b: l32i a8, a8, 216 */
  pp_timer_do_process(a2, a3, a4, a5); /* call via literal slot */ /* 011e: callx8 a8 */
  a10 = MEM32(a1 + 4); /* 0121: l32i.n a10, a1, 4 */
  a5 = MEM32(a5 + 0); /* 0123: l32i.n a5, a5, 0 */
  bss_g_timer_func(a2, a3, a4, a5); /* call via literal slot */ /* 0125: callx8 a5 */
L_128:;
  a5 = MEM32(a2 + 0); /* 0128: l32i.n a5, a2, 0 */
  a5 = MEM32(a5 + 220); /* 012a: l32i a5, a5, 220 */
  bss_g_timer_func(a2, a3, a4, a5); /* call via literal slot */ /* 012d: callx8 a5 */
  goto L_224; /* 0130: j 224 <ppTask+0x1b8> */
  /* 0133: .byte 00 */
  a8 = MEM32(a2 + 0); /* 0134: l32i.n a8, a2, 0 */
  a5 = (uint32_t)&bss_g_config_func; /* 0136: l32r a5, 1c <ppTask-0x50> (0 <ppTask-0x6c>) */ /* literal @0x1C: .bss.g_config_func */
  goto L_116; /* 0139: j 116 <ppTask+0xaa> */
  a10 = 0x4; /* 013c: movi.n a10, 4 */
  a8 = (uint32_t)&ppProcessTxQ; /* 013e: l32r a8, 38 <ppTask-0x34> (0 <ppTask-0x6c>) */ /* literal: GOT slot for ppProcessTxQ */
  ppProcessTxQ(a2, a3, a4, a5); /* call via literal slot */ /* 0141: callx8 a8 */
  goto L_224; /* 0144: j 224 <ppTask+0x1b8> */
  /* 0147: .byte 00 */
  a5 = (uint32_t)&bss_g_net80211_tx_func; /* 0148: l32r a5, 20 <ppTask-0x4c> (0 <ppTask-0x6c>) */ /* literal @0x20: .bss.g_net80211_tx_func */
  a10 = MEM32(a5 + 0); /* 014b: l32i.n a10, a5, 0 */
  ((int32_t(*)())a10)(a2, a3, a4, a5); /* 014d: callx8 a10 */ /* indirect */
  goto L_224; /* 0150: j 224 <ppTask+0x1b8> */
  /* 0153: .byte 00 */
  a10 = 0x1; /* 0154: movi.n a10, 1 */
  a8 = (uint32_t)&ppProcTxDone; /* 0156: l32r a8, 3c <ppTask-0x30> (0 <ppTask-0x6c>) */ /* literal: GOT slot for ppProcTxDone */
  ppProcTxDone(a2, a3, a4, a5); /* call via literal slot */ /* 0159: callx8 a8 */
  goto L_224; /* 015c: j 224 <ppTask+0x1b8> */
  a5 = MEM32(a2 + 0); /* 015f: l32i a5, a2, 0 */
  a5 = MEM32(a5 + 216); /* 0162: l32i a5, a5, 216 */
  bss_g_net80211_tx_func(a2, a3, a4, a5); /* call via literal slot */ /* 0165: callx8 a5 */
  a8 = (uint32_t)&ppRxPkt; /* 0168: l32r a8, 40 <ppTask-0x2c> (0 <ppTask-0x6c>) */ /* literal: GOT slot for ppRxPkt */
  ppRxPkt(a2, a3, a4, a5); /* call via literal slot */ /* 016b: callx8 a8 */
  goto L_128; /* 016e: j 128 <ppTask+0xbc> */
  a5 = MEM32(a2 + 0); /* 0171: l32i.n a5, a2, 0 */
  a5 = MEM32(a5 + 216); /* 0173: l32i a5, a5, 216 */
  bss_g_net80211_tx_func(a2, a3, a4, a5); /* call via literal slot */ /* 0176: callx8 a5 */
  a10 = MEM8(a1 + 4); /* 0179: l8ui a10, a1, 4 */
  a8 = (uint32_t)&ppResortTxAMPDU; /* 017c: l32r a8, 44 <ppTask-0x28> (0 <ppTask-0x6c>) */ /* literal: GOT slot for ppResortTxAMPDU */
  ppResortTxAMPDU(a2, a3, a4, a5); /* call via literal slot */ /* 017f: callx8 a8 */
  goto L_128; /* 0182: j 128 <ppTask+0xbc> */
  a5 = MEM32(a2 + 0); /* 0185: l32i.n a5, a2, 0 */
  a5 = MEM32(a5 + 216); /* 0187: l32i a5, a5, 216 */
  bss_g_net80211_tx_func(a2, a3, a4, a5); /* call via literal slot */ /* 018a: callx8 a5 */
  a10 = MEM32(a1 + 4); /* 018d: l32i.n a10, a1, 4 */
  a8 = (uint32_t)&ppProcessRxPktHdr; /* 018f: l32r a8, 48 <ppTask-0x24> (0 <ppTask-0x6c>) */ /* literal: GOT slot for ppProcessRxPktHdr */
  ppProcessRxPktHdr(a2, a3, a4, a5); /* call via literal slot */ /* 0192: callx8 a8 */
  goto L_128; /* 0195: j 128 <ppTask+0xbc> */
  a5 = MEM32(a2 + 0); /* 0198: l32i.n a5, a2, 0 */
  a5 = MEM32(a5 + 216); /* 019a: l32i a5, a5, 216 */
  bss_g_net80211_tx_func(a2, a3, a4, a5); /* call via literal slot */ /* 019d: callx8 a5 */
  a8 = (uint32_t)&lmacProcessTxTimeout; /* 01a0: l32r a8, 4c <ppTask-0x20> (0 <ppTask-0x6c>) */ /* literal: GOT slot for lmacProcessTxTimeout */
  lmacProcessTxTimeout(a2, a3, a4, a5); /* call via literal slot */ /* 01a3: callx8 a8 */
  goto L_1ca; /* 01a6: j 1ca <ppTask+0x15e> */
  a5 = MEM32(a2 + 0); /* 01a9: l32i.n a5, a2, 0 */
  a5 = MEM32(a5 + 216); /* 01ab: l32i a5, a5, 216 */
  bss_g_net80211_tx_func(a2, a3, a4, a5); /* call via literal slot */ /* 01ae: callx8 a5 */
  a8 = (uint32_t)&lmacProcessTxComplete; /* 01b1: l32r a8, 50 <ppTask-0x1c> (0 <ppTask-0x6c>) */ /* literal: GOT slot for lmacProcessTxComplete */
  lmacProcessTxComplete(a2, a3, a4, a5); /* call via literal slot */ /* 01b4: callx8 a8 */
  goto L_128; /* 01b7: j 128 <ppTask+0xbc> */
  /* 01ba: .byte 00 */
  /* 01bb: .byte 00 */
  a5 = MEM32(a2 + 0); /* 01bc: l32i.n a5, a2, 0 */
  a5 = MEM32(a5 + 216); /* 01be: l32i a5, a5, 216 */
  bss_g_net80211_tx_func(a2, a3, a4, a5); /* call via literal slot */ /* 01c1: callx8 a5 */
  a8 = (uint32_t)&lmacProcessCollisions_task; /* 01c4: l32r a8, 54 <ppTask-0x18> (0 <ppTask-0x6c>) */ /* literal: GOT slot for lmacProcessCollisions_task */
  lmacProcessCollisions_task(a2, a3, a4, a5); /* call via literal slot */ /* 01c7: callx8 a8 */
L_1ca:;
  a5 = MEM32(a2 + 0); /* 01ca: l32i.n a5, a2, 0 */
  a5 = MEM32(a5 + 220); /* 01cc: l32i a5, a5, 220 */
  bss_g_net80211_tx_func(a2, a3, a4, a5); /* call via literal slot */ /* 01cf: callx8 a5 */
  a11 = 0x4; /* 01d2: movi.n a11, 4 */
  a10 = 0xA; /* 01d4: movi.n a10, 10 */
  a8 = (uint32_t)&wifi_gpio_debug; /* 01d6: l32r a8, 58 <ppTask-0x14> (0 <ppTask-0x6c>) */ /* literal: GOT slot for wifi_gpio_debug */
  wifi_gpio_debug(a2, a3, a4, a5); /* call via literal slot */ /* 01d9: callx8 a8 */
  goto L_224; /* 01dc: j 224 <ppTask+0x1b8> */
  /* 01df: .byte 00 */
  a5 = MEM32(a2 + 0); /* 01e0: l32i.n a5, a2, 0 */
  a5 = MEM32(a5 + 216); /* 01e2: l32i a5, a5, 216 */
  bss_g_net80211_tx_func(a2, a3, a4, a5); /* call via literal slot */ /* 01e5: callx8 a5 */
  a10 = MEM32(a1 + 4); /* 01e8: l32i.n a10, a1, 4 */
  a8 = (uint32_t)&wdevProcessRxSucDataAll; /* 01ea: l32r a8, 5c <ppTask-0x10> (0 <ppTask-0x6c>) */ /* literal: GOT slot for wdevProcessRxSucDataAll */
  wdevProcessRxSucDataAll(a2, a3, a4, a5); /* call via literal slot */ /* 01ed: callx8 a8 */
  goto L_128; /* 01f0: j 128 <ppTask+0xbc> */
  /* 01f3: .byte 00 */
  a5 = MEM32(a2 + 0); /* 01f4: l32i.n a5, a2, 0 */
  a5 = MEM32(a5 + 216); /* 01f6: l32i a5, a5, 216 */
  bss_g_net80211_tx_func(a2, a3, a4, a5); /* call via literal slot */ /* 01f9: callx8 a5 */
  a8 = (uint32_t)&wdev_process_misc_pkt; /* 01fc: l32r a8, 60 <ppTask-0xc> (0 <ppTask-0x6c>) */ /* literal: GOT slot for wdev_process_misc_pkt */
  wdev_process_misc_pkt(a2, a3, a4, a5); /* call via literal slot */ /* 01ff: callx8 a8 */
  goto L_128; /* 0202: j 128 <ppTask+0xbc> */
  /* 0205: .byte 00 */
  a12 = 0x1; /* 0206: movi.n a12, 1 */
  a14 = MEM32(a1 + 4); /* 0208: l32i.n a14, a1, 4 */
  a11 = 0x800; /* 020a: slli a11, a12, 11 */
  a10 = 0x6; /* 020d: movi.n a10, 6 */
  a13 = (uint32_t)&lit_rodata_wlog_error_10; /* 020f: l32r a13, 24 <ppTask-0x48> (0 <ppTask-0x6c>) */ /* literal @0x24: .rodata_wlog_error.10 */
  a8 = (uint32_t)&wifi_log; /* 0212: l32r a8, 64 <ppTask-0x8> (0 <ppTask-0x6c>) */ /* literal: GOT slot for wifi_log */
  wifi_log(a2, a3, a4, a5); /* call via literal slot */ /* 0215: callx8 a8 */
L_218:;
  goto L_218; /* 0218: j 218 <ppTask+0x1ac> */
  /* 021b: .byte 00 */
L_21c:;
  a11 = MEM32(a1 + 4); /* 021c: l32i.n a11, a1, 4 */
  a8 = (uint32_t)&pp_default_event_handler; /* 021e: l32r a8, 68 <ppTask-0x4> (0 <ppTask-0x6c>) */ /* literal: GOT slot for pp_default_event_handler */
  pp_default_event_handler(a2, a3, a4, a5); /* call via literal slot */ /* 0221: callx8 a8 */
L_224:;
  if (a4 == 0) goto L_8a; /* 0224: beqz a4, 8a <ppTask+0x1e> */
  a4 = MEM32(a2 + 0); /* 0227: l32i.n a4, a2, 0 */
  a10 = MEM32(a3 + 0); /* 0229: l32i.n a10, a3, 0 */
  a4 = MEM32(a4 + 120); /* 022b: l32i a4, a4, 120 */
  bss_s_pp_task_create_sem(a2, a3, a4, a5); /* call via literal slot */ /* 022e: callx8 a4 */
  if (a10 != 0) goto L_88; /* 0231: bnez a10, 88 <ppTask+0x1c> */
  a3 = (uint32_t)&bss_s_pp_task_del_sem; /* 0234: l32r a3, 28 <ppTask-0x44> (0 <ppTask-0x6c>) */ /* literal @0x28: .bss.s_pp_task_del_sem */
  a10 = MEM32(a3 + 0); /* 0237: l32i.n a10, a3, 0 */
  if (a10 == 0) goto L_244; /* 0239: beqz.n a10, 244 <ppTask+0x1d8> */
  a3 = MEM32(a2 + 0); /* 023b: l32i a3, a2, 0 */
  a3 = MEM32(a3 + 64); /* 023e: l32i a3, a3, 64 */
  bss_s_pp_task_del_sem(a2, a3, a4, a5); /* call via literal slot */ /* 0241: callx8 a3 */
L_244:;
  a3 = (uint32_t)&s_wifi_queue; /* 0244: l32r a3, 2c <ppTask-0x40> (0 <ppTask-0x6c>) */ /* literal @0x2C: s_wifi_queue */
  a4 = MEM32(a2 + 0); /* 0247: l32i.n a4, a2, 0 */
  a10 = MEM32(a3 + 0); /* 0249: l32i.n a10, a3, 0 */
  a4 = MEM32(a4 + 384); /* 024b: l32i a4, a4, 0x180 */
  bss_s_pp_task_create_sem(a2, a3, a4, a5); /* call via literal slot */ /* 024e: callx8 a4 */
  a10 = 0x0; /* 0251: movi.n a10, 0 */
  a2 = MEM32(a2 + 0); /* 0253: l32i.n a2, a2, 0 */
  MEM32(a3 + 0) = a10; /* 0255: s32i.n a10, a3, 0 */
  a3 = (uint32_t)&bss_pp_task_hdl; /* 0257: l32r a3, 30 <ppTask-0x3c> (0 <ppTask-0x6c>) */ /* literal @0x30: .bss.pp_task_hdl */
  a2 = MEM32(a2 + 152); /* 025a: l32i a2, a2, 152 */
  MEM32(a3 + 0) = a10; /* 025d: s32i.n a10, a3, 0 */
  MEMW(); /* 025f: memw  */
  g_osi_funcs_p(a2, a3, a4, a5); /* call via literal slot */ /* 0262: callx8 a2 */
  return (int32_t)a2; /* 0265: retw.n  */
}

/* ppDirectRecycleAmpdu @ pp.o 0000000c size 77B bind GLOBAL
 * Calls: ppResumeTxAMPDU[got], esf_buf_recycle[got] | Data refs: pTxRx, ppResumeTxAMPDU, esf_buf_recycle
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 2 call(s), 3 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t ppDirectRecycleAmpdu(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .wifiextrairam.72; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_c:;
  /* 000c: entry a1, 32 */
  a3 = MEM32(a2 + 44); /* 000f: l32i.n a3, a2, 44 */
  a10 = MEM32(a3 + 16); /* 0011: l32i.n a10, a3, 16 */
  a10 = (a10 >> 20) & 0xF; /* 0013: extui a10, a10, 20, 4 */
  a8 = a10 + (1); /* 0016: addi.n a8, a10, 1 */
  a8 = (a8 << 2) + a8; /* 0018: addx2 a8, a8, a8 */
  a3 = (uint32_t)&pTxRx; /* 001b: l32r a3, 0 <ppDirectRecycleAmpdu-0xc> (0 <ppDirectRecycleAmpdu-0xc>) */ /* literal @0x0: pTxRx */
  a8 = a8 << (4 & 31); /* 001e: slli a8, a8, 4 */
  a3 = MEM32(a3 + 0); /* 0021: l32i.n a3, a3, 0 */
  a8 = a3 + a8; /* 0023: add.n a8, a3, a8 */
  a3 = 0x0; /* 0025: movi.n a3, 0 */
  MEM32(a8 + 4) = a3; /* 0027: s32i.n a3, a8, 4 */
  MEMW(); /* 0029: memw  */
  a8 = (uint32_t)&ppResumeTxAMPDU; /* 002c: l32r a8, 4 <ppDirectRecycleAmpdu-0x8> (0 <ppDirectRecycleAmpdu-0xc>) */ /* literal: GOT slot for ppResumeTxAMPDU */
  ppResumeTxAMPDU(a2, a3, a4, a5); /* call via literal slot */ /* 002f: callx8 a8 */
L_32:;
  a10 = a2; /* 0032: mov.n a10, a2 */
  a9 = 0x1; /* 0034: movi.n a9, 1 */
  a9 = 0x400000; /* 0036: slli a9, a9, 22 */
  a8 = MEM32(a10 + 8); /* 0039: l32i.n a8, a10, 8 */
  a11 = MEM32(a10 + 44); /* 003b: l32i.n a11, a10, 44 */
  a2 = MEM32(a2 + 40); /* 003d: l32i.n a2, a2, 40 */
  MEM32(a10 + 40) = a3; /* 003f: s32i.n a3, a10, 40 */
  MEM32(a8 + 8) = a3; /* 0041: s32i.n a3, a8, 8 */
  a8 = MEM32(a11 + 0); /* 0043: l32i.n a8, a11, 0 */
  a8 = a8 | a9; /* 0045: or a8, a8, a9 */
  MEM32(a11 + 0) = a8; /* 0048: s32i a8, a11, 0 */
  MEMW(); /* 004b: memw  */
  a8 = (uint32_t)&esf_buf_recycle; /* 004e: l32r a8, 8 <ppDirectRecycleAmpdu-0x4> (0 <ppDirectRecycleAmpdu-0xc>) */ /* literal: GOT slot for esf_buf_recycle */
  esf_buf_recycle(a2, a3, a4, a5); /* call via literal slot */ /* 0051: callx8 a8 */
  if (a2 != 0) goto L_32; /* 0054: bnez a2, 32 <ppDirectRecycleAmpdu+0x26> */
  return (int32_t)a2; /* 0057: retw.n  */
}

/* ppClearTxq @ pp.o 00000010 size 67B bind GLOBAL
 * Calls: esf_buf_recycle, ppDequeueTxQ, ppDirectRecycleAmpdu | Data refs: esf_buf_recycle, pTxRx, ppDequeueTxQ, ppDirectRecycleAmpdu
 *   MMIO: none
 *   funcdb v3: 3 call(s), 4 ref(s); disasm: 3 call(s), 4 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t ppClearTxq(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.ppClearTxq; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_10:;
  /* 0010: entry a1, 32 */
  a8 = (uint32_t)&pTxRx; /* 0013: l32r a8, 0 <ppClearTxq-0x10> (0 <ppClearTxq-0x10>) */ /* literal @0x0: pTxRx */
  a2 = (a2 >> 0) & 0xFF; /* 0016: extui a2, a2, 0, 8 */
  a9 = MEM32(a8 + 0); /* 0019: l32i.n a9, a8, 0 */
  a8 = (a2 << 2) + a2; /* 001b: addx2 a8, a2, a2 */
  a8 = a8 << (4 & 31); /* 001e: slli a8, a8, 4 */
  a8 = a9 + a8; /* 0021: add.n a8, a9, a8 */
  a8 = MEM8(a8 + 41); /* 0023: l8ui a8, a8, 41 */
  if (a8 != 0) goto L_46; /* 0026: bnez.n a8, 46 <ppClearTxq+0x36> */
  a8 = a2 + (1); /* 0028: addi.n a8, a2, 1 */
  a8 = (a8 << 2) + a8; /* 002a: addx2 a8, a8, a8 */
  a8 = a8 << (4 & 31); /* 002d: slli a8, a8, 4 */
  a9 = a9 + a8; /* 0030: add.n a9, a9, a8 */
  a10 = MEM32(a9 + 4); /* 0032: l32i.n a10, a9, 4 */
  if (a10 == 0) goto L_46; /* 0034: beqz.n a10, 46 <ppClearTxq+0x36> */
  a8 = (uint32_t)&ppDirectRecycleAmpdu; /* 0036: l32r a8, 4 <ppClearTxq-0xc> (0 <ppClearTxq-0x10>) */ /* literal: GOT slot for ppDirectRecycleAmpdu */
  ppDirectRecycleAmpdu(a2, a3, a4, a5); /* call via literal slot */ /* 0039: callx8 a8 */
  goto L_46; /* 003c: j 46 <ppClearTxq+0x36> */
  /* 003f: .byte 00 */
L_40:;
  a8 = (uint32_t)&esf_buf_recycle; /* 0040: l32r a8, 8 <ppClearTxq-0x8> (0 <ppClearTxq-0x10>) */ /* literal: GOT slot for esf_buf_recycle */
  esf_buf_recycle(a2, a3, a4, a5); /* call via literal slot */ /* 0043: callx8 a8 */
L_46:;
  a10 = a2; /* 0046: mov.n a10, a2 */
  a8 = (uint32_t)&ppDequeueTxQ; /* 0048: l32r a8, c <ppClearTxq-0x4> (0 <ppClearTxq-0x10>) */ /* literal: GOT slot for ppDequeueTxQ */
  ppDequeueTxQ(a2, a3, a4, a5); /* call via literal slot */ /* 004b: callx8 a8 */
  if (a10 != 0) goto L_40; /* 004e: bnez a10, 40 <ppClearTxq+0x30> */
  return (int32_t)a2; /* 0051: retw.n  */
}

/* ppClearAlldataTxq_ifx @ pp.o 00000014 size 139B bind GLOBAL
 * Calls: esf_buf_recycle, ppClearTxq | Data refs: esf_buf_recycle, g_osi_funcs_p, g_wifi_global_lock, pTxRx, ppClearTxq
 *   MMIO: none
 *   funcdb v3: 2 call(s), 5 ref(s); disasm: 4 call(s), 5 data ref(s)
 * Fidelity: medium - 53 instr, 5 branches, calls resolved */
int32_t ppClearAlldataTxq_ifx(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.ppClearAlldataTxq_ifx; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_14:;
  /* 0014: entry a1, 32 */
  a5 = (uint32_t)&g_osi_funcs_p; /* 0017: l32r a5, 4 <ppClearAlldataTxq_ifx-0x10> (0 <ppClearAlldataTxq_ifx-0x14>) */ /* literal @0x4: g_osi_funcs_p */
  a2 = (a2 >> 0) & 0xFF; /* 001a: extui a2, a2, 0, 8 */
  a7 = a2 << (3 & 31); /* 001d: slli a7, a2, 3 */
  a4 = (uint32_t)&g_wifi_global_lock; /* 0020: l32r a4, 0 <ppClearAlldataTxq_ifx-0x14> (0 <ppClearAlldataTxq_ifx-0x14>) */ /* literal @0x0: g_wifi_global_lock */
  a3 = MEM32(a5 + 0); /* 0023: l32i.n a3, a5, 0 */
  a10 = MEM32(a4 + 0); /* 0025: l32i.n a10, a4, 0 */
  a3 = MEM32(a3 + 84); /* 0027: l32i a3, a3, 84 */
  ((int32_t(*)())a3)(a2, a3, a4, a5); /* 002a: callx8 a3 */ /* indirect */
  a3 = a2 + (102); /* 002d: addi a3, a2, 102 */
  a3 = a3 << (3 & 31); /* 0030: slli a3, a3, 3 */
  a3 = a3 + (4); /* 0033: addi.n a3, a3, 4 */
  goto L_51; /* 0035: j 51 <ppClearAlldataTxq_ifx+0x3d> */
L_38:;
  a6 = MEM32(a10 + 40); /* 0038: l32i.n a6, a10, 40 */
  MEM32(a9 + 820) = a6; /* 003a: s32i a6, a9, 0x334 */
  if (a6 != 0) goto L_44; /* 003d: bnez.n a6, 44 <ppClearAlldataTxq_ifx+0x30> */
  a8 = a8 + a3; /* 003f: add.n a8, a8, a3 */
  MEM32(a9 + 824) = a8; /* 0041: s32i a8, a9, 0x338 */
L_44:;
  a6 = 0x0; /* 0044: movi.n a6, 0 */
  MEM32(a10 + 40) = a6; /* 0046: s32i.n a6, a10, 40 */
  MEMW(); /* 0048: memw  */
  a8 = (uint32_t)&esf_buf_recycle; /* 004b: l32r a8, c <ppClearAlldataTxq_ifx-0x8> (0 <ppClearAlldataTxq_ifx-0x14>) */ /* literal: GOT slot for esf_buf_recycle */
  esf_buf_recycle(a2, a3, a4, a5); /* call via literal slot */ /* 004e: callx8 a8 */
L_51:;
  a6 = (uint32_t)&pTxRx; /* 0051: l32r a6, 8 <ppClearAlldataTxq_ifx-0xc> (0 <ppClearAlldataTxq_ifx-0x14>) */ /* literal @0x8: pTxRx */
  a8 = MEM32(a6 + 0); /* 0054: l32i.n a8, a6, 0 */
  a9 = a8 + a7; /* 0056: add.n a9, a8, a7 */
  a10 = MEM32(a9 + 820); /* 0058: l32i a10, a9, 0x334 */
  if (a10 != 0) goto L_38; /* 005b: bnez a10, 38 <ppClearAlldataTxq_ifx+0x24> */
  a3 = MEM32(a5 + 0); /* 005e: l32i a3, a5, 0 */
  a10 = MEM32(a4 + 0); /* 0061: l32i a10, a4, 0 */
  a3 = MEM32(a3 + 88); /* 0064: l32i a3, a3, 88 */
  ((int32_t(*)())a3)(a2, a3, a4, a5); /* 0067: callx8 a3 */ /* indirect */
  a3 = 0x4; /* 006a: movi.n a3, 4 */
L_6c:;
  a9 = 0xC; /* 006c: addx2 a9, a3, a3 */
  a8 = MEM32(a6 + 0); /* 006f: l32i.n a8, a6, 0 */
  a9 = 0xC0; /* 0071: slli a9, a9, 4 */
  a8 = a8 + a9; /* 0074: add.n a8, a8, a9 */
  a8 = MEM8(a8 + 46); /* 0076: l8ui a8, a8, 46 */
  if (a8 != a2) goto L_98; /* 0079: bne a8, a2, 98 <ppClearAlldataTxq_ifx+0x84> */
  a8 = MEM32(a5 + 0); /* 007c: l32i.n a8, a5, 0 */
  a10 = MEM32(a4 + 0); /* 007e: l32i.n a10, a4, 0 */
  a8 = MEM32(a8 + 84); /* 0080: l32i a8, a8, 84 */
  ((int32_t(*)())a8)(a2, a3, a4, a5); /* 0083: callx8 a8 */ /* indirect */
  a10 = a3; /* 0086: mov.n a10, a3 */
  a8 = (uint32_t)&ppClearTxq; /* 0088: l32r a8, 10 <ppClearAlldataTxq_ifx-0x4> (0 <ppClearAlldataTxq_ifx-0x14>) */ /* literal: GOT slot for ppClearTxq */
  ppClearTxq(a2, a3, a4, a5); /* call via literal slot */ /* 008b: callx8 a8 */
  a8 = MEM32(a5 + 0); /* 008e: l32i.n a8, a5, 0 */
  a10 = MEM32(a4 + 0); /* 0090: l32i.n a10, a4, 0 */
  a8 = MEM32(a8 + 88); /* 0092: l32i a8, a8, 88 */
  ppClearTxq(a2, a3, a4, a5); /* call via literal slot */ /* 0095: callx8 a8 */
L_98:;
  a3 = a3 + (1); /* 0098: addi.n a3, a3, 1 */
  if (a3 != 16) goto L_6c; /* 009a: bnei a3, 16, 6c <ppClearAlldataTxq_ifx+0x58> */
  return (int32_t)a2; /* 009d: retw.n  */
}

/* pp_stop_sw_txq @ pp.o 00000018 size 107B bind GLOBAL
 * Calls: esf_buf_recycle, ppClearRxFragment, ppClearTxq, ppDequeueTxDone_Locked | Data refs: esf_buf_recycle, pTxRx, ppClearRxFragment, ppClearTxq, ppDequeueTxDone_Locked
 *   MMIO: none
 *   funcdb v3: 4 call(s), 5 ref(s); disasm: 5 call(s), 5 data ref(s)
 * Fidelity: medium - 42 instr, 8 branches, calls resolved */
int32_t pp_stop_sw_txq(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pp_stop_sw_txq; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_18:;
  /* 0018: entry a1, 32 */
  a2 = 0x0; /* 001b: movi.n a2, 0 */
  a4 = 0x334; /* 001d: movi a4, 0x334 */
  goto L_4f; /* 0020: j 4f <pp_stop_sw_txq+0x37> */
  /* 0023: .byte 00 */
L_24:;
  a11 = MEM32(a10 + 40); /* 0024: l32i.n a11, a10, 40 */
  MEM32(a9 + 820) = a11; /* 0026: s32i a11, a9, 0x334 */
  if (a11 != 0) goto L_30; /* 0029: bnez.n a11, 30 <pp_stop_sw_txq+0x18> */
  a8 = a8 + a3; /* 002b: add.n a8, a8, a3 */
  MEM32(a9 + 824) = a8; /* 002d: s32i a8, a9, 0x338 */
L_30:;
  a8 = 0x0; /* 0030: movi.n a8, 0 */
  MEM32(a10 + 40) = a8; /* 0032: s32i.n a8, a10, 40 */
  MEMW(); /* 0034: memw  */
  a8 = (uint32_t)&esf_buf_recycle; /* 0037: l32r a8, 4 <pp_stop_sw_txq-0x14> (0 <pp_stop_sw_txq-0x18>) */ /* literal: GOT slot for esf_buf_recycle */
  esf_buf_recycle(a2, a3, a4, a5); /* call via literal slot */ /* 003a: callx8 a8 */
L_3d:;
  a6 = (uint32_t)&pTxRx; /* 003d: l32r a6, 0 <pp_stop_sw_txq-0x18> (0 <pp_stop_sw_txq-0x18>) */ /* literal @0x0: pTxRx */
  a8 = MEM32(a6 + 0); /* 0040: l32i.n a8, a6, 0 */
  a9 = a8 + a5; /* 0042: add.n a9, a8, a5 */
  a10 = MEM32(a9 + 820); /* 0044: l32i a10, a9, 0x334 */
  if (a10 != 0) goto L_24; /* 0047: bnez a10, 24 <pp_stop_sw_txq+0xc> */
  a2 = a2 + (1); /* 004a: addi.n a2, a2, 1 */
  if (a2 == 3) goto L_58; /* 004c: beqi a2, 3, 58 <pp_stop_sw_txq+0x40> */
L_4f:;
  a5 = a2 << (3 & 31); /* 004f: slli a5, a2, 3 */
  a3 = (a2 << 8) + a4; /* 0052: addx8 a3, a2, a4 */
  goto L_3d; /* 0055: j 3d <pp_stop_sw_txq+0x25> */
L_58:;
  a2 = a10; /* 0058: mov.n a2, a10 */
L_5a:;
  a10 = a2; /* 005a: mov.n a10, a2 */
  a2 = a2 + (1); /* 005c: addi.n a2, a2, 1 */
  a8 = (uint32_t)&ppClearTxq; /* 005e: l32r a8, 8 <pp_stop_sw_txq-0x10> (0 <pp_stop_sw_txq-0x18>) */ /* literal: GOT slot for ppClearTxq */
  ppClearTxq(a2, a3, a4, a5); /* call via literal slot */ /* 0061: callx8 a8 */
  if (a2 != 16) goto L_5a; /* 0064: bnei a2, 16, 5a <pp_stop_sw_txq+0x42> */
  goto L_72; /* 0067: j 72 <pp_stop_sw_txq+0x5a> */
  /* 006a: .byte 00 */
  /* 006b: .byte 00 */
L_6c:;
  a8 = (uint32_t)&esf_buf_recycle; /* 006c: l32r a8, c <pp_stop_sw_txq-0xc> (0 <pp_stop_sw_txq-0x18>) */ /* literal: GOT slot for esf_buf_recycle */
  esf_buf_recycle(a2, a3, a4, a5); /* call via literal slot */ /* 006f: callx8 a8 */
L_72:;
  a8 = (uint32_t)&ppDequeueTxDone_Locked; /* 0072: l32r a8, 10 <pp_stop_sw_txq-0x8> (0 <pp_stop_sw_txq-0x18>) */ /* literal: GOT slot for ppDequeueTxDone_Locked */
  ppDequeueTxDone_Locked(a2, a3, a4, a5); /* call via literal slot */ /* 0075: callx8 a8 */
  if (a10 != 0) goto L_6c; /* 0078: bnez a10, 6c <pp_stop_sw_txq+0x54> */
  a8 = (uint32_t)&ppClearRxFragment; /* 007b: l32r a8, 14 <pp_stop_sw_txq-0x4> (0 <pp_stop_sw_txq-0x18>) */ /* literal: GOT slot for ppClearRxFragment */
  ppClearRxFragment(a2, a3, a4, a5); /* call via literal slot */ /* 007e: callx8 a8 */
  return (int32_t)a2; /* 0081: retw.n  */
}

/* ppRecycleAmpdu @ pp.o 00000014 size 115B bind GLOBAL
 * Calls: GetAccess[got], ppResumeTxAMPDU[got], lmacDiscardAgedMSDU[got], lmacDiscardAgedMSDU[got] | Data refs: GetAccess, pTxRx, ppResumeTxAMPDU, lmacDiscardAgedMSDU
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 4 call(s), 4 data ref(s)
 * Fidelity: medium - 47 instr, 2 branches, calls resolved */
int32_t ppRecycleAmpdu(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .wifiextrairam.73; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_14:;
  /* 0014: entry a1, 32 */
  a4 = MEM32(a2 + 44); /* 0017: l32i.n a4, a2, 44 */
  a3 = (a3 >> 0) & 0xFF; /* 0019: extui a3, a3, 0, 8 */
  a10 = MEM32(a4 + 4); /* 001c: l32i.n a10, a4, 4 */
  a10 = (a10 >> 4) & 0xF; /* 001e: extui a10, a10, 4, 4 */
  a5 = MEM32(a4 + 16); /* 0021: l32i.n a5, a4, 16 */
  a8 = (uint32_t)&GetAccess; /* 0023: l32r a8, 4 <ppRecycleAmpdu-0x10> (0 <ppRecycleAmpdu-0x14>) */ /* literal: GOT slot for GetAccess */
  GetAccess(a2, a3, a4, a5); /* call via literal slot */ /* 0026: callx8 a8 */
  a5 = (a5 >> 20) & 0xF; /* 0029: extui a5, a5, 20, 4 */
  a8 = a5 + (1); /* 002c: addi.n a8, a5, 1 */
  a8 = (a8 << 2) + a8; /* 002e: addx2 a8, a8, a8 */
  a4 = (uint32_t)&pTxRx; /* 0031: l32r a4, 0 <ppRecycleAmpdu-0x14> (0 <ppRecycleAmpdu-0x14>) */ /* literal @0x0: pTxRx */
  a8 = a8 << (4 & 31); /* 0034: slli a8, a8, 4 */
  a6 = a10; /* 0037: mov.n a6, a10 */
  a10 = a5; /* 0039: mov.n a10, a5 */
  a4 = MEM32(a4 + 0); /* 003b: l32i.n a4, a4, 0 */
  a8 = a4 + a8; /* 003d: add.n a8, a4, a8 */
  a4 = 0x0; /* 003f: movi.n a4, 0 */
  MEM32(a8 + 4) = a4; /* 0041: s32i a4, a8, 4 */
  MEMW(); /* 0044: memw  */
  a8 = (uint32_t)&ppResumeTxAMPDU; /* 0047: l32r a8, 8 <ppRecycleAmpdu-0xc> (0 <ppRecycleAmpdu-0x14>) */ /* literal: GOT slot for ppResumeTxAMPDU */
  ppResumeTxAMPDU(a2, a3, a4, a5); /* call via literal slot */ /* 004a: callx8 a8 */
L_4d:;
  a8 = 0x1; /* 004d: movi.n a8, 1 */
  a8 = 0x400000; /* 004f: slli a8, a8, 22 */
  a5 = MEM32(a2 + 8); /* 0052: l32i.n a5, a2, 8 */
  a9 = MEM32(a2 + 44); /* 0054: l32i.n a9, a2, 44 */
  a7 = MEM32(a2 + 40); /* 0056: l32i.n a7, a2, 40 */
  MEM32(a2 + 40) = a4; /* 0058: s32i.n a4, a2, 40 */
  MEM32(a5 + 8) = a4; /* 005a: s32i.n a4, a5, 8 */
  a5 = MEM32(a9 + 0); /* 005c: l32i.n a5, a9, 0 */
  a5 = a5 | a8; /* 005e: or a5, a5, a8 */
  MEM32(a9 + 0) = a5; /* 0061: s32i.n a5, a9, 0 */
  if (a7 == 0) goto L_79; /* 0063: beqz.n a7, 79 <ppRecycleAmpdu+0x65> */
  a11 = a2; /* 0065: mov.n a11, a2 */
  a12 = a4; /* 0067: mov.n a12, a4 */
  a10 = a6; /* 0069: mov.n a10, a6 */
  MEMW(); /* 006b: memw  */
  a8 = (uint32_t)&lmacDiscardAgedMSDU; /* 006e: l32r a8, c <ppRecycleAmpdu-0x8> (0 <ppRecycleAmpdu-0x14>) */ /* literal: GOT slot for lmacDiscardAgedMSDU */
  lmacDiscardAgedMSDU(a2, a3, a4, a5); /* call via literal slot */ /* 0071: callx8 a8 */
  a2 = a7; /* 0074: mov.n a2, a7 */
  goto L_4d; /* 0076: j 4d <ppRecycleAmpdu+0x39> */
L_79:;
  a12 = a3; /* 0079: mov.n a12, a3 */
  a11 = a2; /* 007b: mov.n a11, a2 */
  a10 = a6; /* 007d: mov.n a10, a6 */
  a8 = (uint32_t)&lmacDiscardAgedMSDU; /* 007f: l32r a8, 10 <ppRecycleAmpdu-0x4> (0 <ppRecycleAmpdu-0x14>) */ /* literal: GOT slot for lmacDiscardAgedMSDU */
  lmacDiscardAgedMSDU(a2, a3, a4, a5); /* call via literal slot */ /* 0082: callx8 a8 */
  return (int32_t)a2; /* 0085: retw.n  */
}

/* ppRegressAmpdu @ pp.o 00000010 size 124B bind GLOBAL
 * Calls: ppAMPDU2Normal[got], ppResumeTxAMPDU[got], pp_post[got] | Data refs: ppAMPDU2Normal, pTxRx, ppResumeTxAMPDU, pp_post
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 3 call(s), 4 data ref(s)
 * Fidelity: medium - 50 instr, 4 branches, calls resolved */
int32_t ppRegressAmpdu(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .wifiextrairam.74; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_10:;
  /* 0010: entry a1, 32 */
  a4 = MEM32(a2 + 44); /* 0013: l32i.n a4, a2, 44 */
  a3 = (a3 >> 0) & 0xFF; /* 0015: extui a3, a3, 0, 8 */
  a5 = a2; /* 0018: mov.n a5, a2 */
  a9 = 0x0; /* 001a: movi.n a9, 0 */
  a4 = MEM32(a4 + 16); /* 001c: l32i.n a4, a4, 16 */
  a4 = (a4 >> 20) & 0xF; /* 001e: extui a4, a4, 20, 4 */
  goto L_2a; /* 0021: j 2a <ppRegressAmpdu+0x1a> */
L_24:;
  a5 = MEM32(a5 + 8); /* 0024: l32i.n a5, a5, 8 */
  MEM32(a5 + 8) = a9; /* 0026: s32i.n a9, a5, 8 */
  a5 = a8; /* 0028: mov.n a5, a8 */
L_2a:;
  a8 = MEM32(a5 + 40); /* 002a: l32i a8, a5, 40 */
  if (a8 != 0) goto L_24; /* 002d: bnez a8, 24 <ppRegressAmpdu+0x14> */
  a10 = a2 | a2; /* 0030: or a10, a2, a2 */
  MEMW(); /* 0033: memw  */
  a8 = (uint32_t)&ppAMPDU2Normal; /* 0036: l32r a8, 4 <ppRegressAmpdu-0xc> (0 <ppRegressAmpdu-0x10>) */ /* literal: GOT slot for ppAMPDU2Normal */
  ppAMPDU2Normal(a2, a3, a4, a5); /* call via literal slot */ /* 0039: callx8 a8 */
  a8 = (uint32_t)&pTxRx; /* 003c: l32r a8, 0 <ppRegressAmpdu-0x10> (0 <ppRegressAmpdu-0x10>) */ /* literal @0x0: pTxRx */
  a9 = (a4 << 2) + a4; /* 003f: addx2 a9, a4, a4 */
  a9 = a9 << (4 & 31); /* 0042: slli a9, a9, 4 */
  a10 = MEM32(a8 + 0); /* 0045: l32i.n a10, a8, 0 */
  a8 = a4 + a4; /* 0047: add.n a8, a4, a4 */
  a9 = a10 + a9; /* 0049: add.n a9, a10, a9 */
  a11 = MEM32(a9 + 32); /* 004b: l32i.n a11, a9, 32 */
  MEM32(a5 + 40) = a11; /* 004d: s32i.n a11, a5, 40 */
  if (a11 != 0) goto L_56; /* 004f: bnez.n a11, 56 <ppRegressAmpdu+0x46> */
  a5 = a5 + (40); /* 0051: addi a5, a5, 40 */
  MEM32(a9 + 36) = a5; /* 0054: s32i.n a5, a9, 36 */
L_56:;
  a8 = a8 + a4; /* 0056: add.n a8, a8, a4 */
  a5 = a4 + (1); /* 0058: addi.n a5, a4, 1 */
  a8 = a8 << (4 & 31); /* 005a: slli a8, a8, 4 */
  a5 = (a5 << 2) + a5; /* 005d: addx2 a5, a5, a5 */
  a8 = a10 + a8; /* 0060: add.n a8, a10, a8 */
  a5 = a5 << (4 & 31); /* 0062: slli a5, a5, 4 */
  a10 = a10 + a5; /* 0065: add.n a10, a10, a5 */
  MEM32(a8 + 32) = a2; /* 0067: s32i.n a2, a8, 32 */
  a5 = 0x0; /* 0069: movi.n a5, 0 */
  MEM32(a10 + 4) = a5; /* 006b: s32i.n a5, a10, 4 */
  a10 = a4; /* 006d: mov.n a10, a4 */
  MEMW(); /* 006f: memw  */
  a8 = (uint32_t)&ppResumeTxAMPDU; /* 0072: l32r a8, 8 <ppRegressAmpdu-0x8> (0 <ppRegressAmpdu-0x10>) */ /* literal: GOT slot for ppResumeTxAMPDU */
  ppResumeTxAMPDU(a2, a3, a4, a5); /* call via literal slot */ /* 0075: callx8 a8 */
  if (a3 == a5) goto L_8a; /* 0078: beq a3, a5, 8a <ppRegressAmpdu+0x7a> */
  a11 = a5; /* 007b: mov.n a11, a5 */
  a2 = MEM32(a2 + 44); /* 007d: l32i.n a2, a2, 44 */
  a10 = MEM32(a2 + 4); /* 007f: l32i.n a10, a2, 4 */
  a10 = (a10 >> 4) & 0xF; /* 0081: extui a10, a10, 4, 4 */
  a8 = (uint32_t)&pp_post; /* 0084: l32r a8, c <ppRegressAmpdu-0x4> (0 <ppRegressAmpdu-0x10>) */ /* literal: GOT slot for pp_post */
  pp_post(a2, a3, a4, a5); /* call via literal slot */ /* 0087: callx8 a8 */
L_8a:;
  return (int32_t)a2; /* 008a: retw.n  */
}

/* ppGetTaskHdl @ pp.o 00000004 size 10B bind GLOBAL
 * Calls: none | Data refs: .bss.pp_task_hdl
 *   MMIO: none
 *   funcdb v3: 0 call(s), 1 ref(s); disasm: 0 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t ppGetTaskHdl(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.ppGetTaskHdl; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a8 = (uint32_t)&bss_pp_task_hdl; /* 0007: l32r a8, 0 <ppGetTaskHdl-0x4> (0 <ppGetTaskHdl-0x4>) */ /* literal @0x0: .bss.pp_task_hdl */
  a2 = MEM32(a8 + 0); /* 000a: l32i.n a2, a8, 0 */
  return (int32_t)a2; /* 000c: retw.n  */
}

/* ppMessageInQ @ pp.o 00000008 size 24B bind GLOBAL
 * Calls: g_osi_funcs_p[got] | Data refs: g_osi_funcs_p, xphyQueue
 *   MMIO: none
 *   funcdb v3: 0 call(s), 2 ref(s); disasm: 1 call(s), 2 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t ppMessageInQ(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.ppMessageInQ; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_8:;
  /* 0008: entry a1, 32 */
  a8 = (uint32_t)&g_osi_funcs_p; /* 000b: l32r a8, 4 <ppMessageInQ-0x4> (0 <ppMessageInQ-0x8>) */ /* literal @0x4: g_osi_funcs_p */
  a9 = (uint32_t)&xphyQueue; /* 000e: l32r a9, 0 <ppMessageInQ-0x8> (0 <ppMessageInQ-0x8>) */ /* literal @0x0: xphyQueue */
  a8 = MEM32(a8 + 0); /* 0011: l32i.n a8, a8, 0 */
  a10 = MEM32(a9 + 0); /* 0013: l32i a10, a9, 0 */
  a8 = MEM32(a8 + 120); /* 0016: l32i a8, a8, 120 */
  g_osi_funcs_p(a2, a3, a4, a5); /* call via literal slot */ /* 0019: callx8 a8 */
  a2 = a10; /* 001c: mov.n a2, a10 */
  return (int32_t)a2; /* 001e: retw.n  */
}

/* ppProcessLifeTime @ pp.o 00000020 size 148B bind GLOBAL
 * Calls: pm_get_null_max_tx_time[got], wifi_log[got] | Data refs: lmacConfMib, pm_get_null_max_tx_time, g_offchan_packet_lifetime, .rodata.pp_default_event_handler.str1.1, .rodata_wlog_error.76, wifi_log
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 2 call(s), 6 data ref(s)
 * Fidelity: medium - 57 instr, 13 branches, calls resolved */
int32_t ppProcessLifeTime(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .wifi0iram.75; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_20:;
  /* 0020: entry a1, 32 */
  a13 = MEM32(a2 + 44); /* 0023: l32i.n a13, a2, 44 */
  a8 = MEM32(a13 + 0); /* 0025: l32i.n a8, a13, 0 */
  a9 = (uint32_t)&lmacConfMib; /* 0027: l32r a9, 0 <ppProcessLifeTime-0x20> (0 <ppProcessLifeTime-0x20>) */ /* literal @0x0: lmacConfMib */
  if (!((a8 >> 22) & 1)) goto L_32; /* 002a: bbci a8, 22, 32 <ppProcessLifeTime+0x12> */
  a10 = MEM32(a9 + 0); /* 002d: l32i.n a10, a9, 0 */
  goto L_34; /* 002f: j 34 <ppProcessLifeTime+0x14> */
L_32:;
  a10 = MEM32(a9 + 8); /* 0032: l32i.n a10, a9, 8 */
L_34:;
  a10 = a10 << (10 & 31); /* 0034: slli a10, a10, 10 */
  a9 = 0x10020; /* 0037: l32r a9, 4 <ppProcessLifeTime-0x1c> (10020 <ppRxFragmentProc+0xffa0>) */ @0x4
  if ((a8 & a9) == 0) goto L_ad; /* 003a: bnone a8, a9, ad <ppProcessLifeTime+0x8d> */
  a2 = MEM32(a2 + 4); /* 003d: l32i.n a2, a2, 4 */
  a11 = MEM32(a2 + 4); /* 003f: l32i.n a11, a2, 4 */
  if (!((a8 >> 18) & 1)) goto L_46; /* 0041: bbci a8, 18, 46 <ppProcessLifeTime+0x26> */
  a11 = a11 + (4); /* 0044: addi.n a11, a11, 4 */
L_46:;
  a2 = 0xFFFFFFF0; /* 0046: movi.n a2, -16 */
  a12 = 0xC; /* 0048: movi.n a12, 12 */
  a8 = MEM8(a11 + 0); /* 004a: l8ui a8, a11, 0 */
  a9 = 0x1; /* 004d: movi.n a9, 1 */
  a12 = a8 & a12; /* 004f: and a12, a8, a12 */
  a8 = a8 & a2; /* 0052: and a8, a8, a2 */
  a2 = 0x0; /* 0055: movi a2, 0 */
  if (a12 != 0) a9 = a2; /* 0058: movnez a9, a2, a12 */
  a9 = (a9 >> 0) & 0xFF; /* 005b: extui a9, a9, 0, 8 */
  if (a8 != 64) goto L_64; /* 005e: bnei a8, 64, 64 <ppProcessLifeTime+0x44> */
  if (a9 != a2) goto L_a8; /* 0061: bne a9, a2, a8 <ppProcessLifeTime+0x88> */
L_64:;
  if (a12 != 8) goto L_78; /* 0064: bnei a12, 8, 78 <ppProcessLifeTime+0x58> */
  a10 = MEM8(a11 + 1); /* 0067: l8ui a10, a11, 1 */
  a10 = (a10 >> 4) & 0x1; /* 006a: extui a10, a10, 4, 1 */
  a11 = MEM32(a13 + 24); /* 006d: l32i.n a11, a13, 24 */
  a8 = (uint32_t)&pm_get_null_max_tx_time; /* 006f: l32r a8, 18 <ppProcessLifeTime-0x8> (0 <ppProcessLifeTime-0x20>) */ /* literal: GOT slot for pm_get_null_max_tx_time */
  pm_get_null_max_tx_time(a2, a3, a4, a5); /* call via literal slot */ /* 0072: callx8 a8 */
  goto L_ad; /* 0075: j ad <ppProcessLifeTime+0x8d> */
L_78:;
  a2 = 0xFFFFFF30; /* 0078: movi a2, -208 */
  a8 = a8 + a2; /* 007b: add.n a8, a8, a2 */
  if (a8 != 0) goto L_8e; /* 007d: bnez.n a8, 8e <ppProcessLifeTime+0x6e> */
  if (a9 == 0) goto L_8e; /* 007f: beqz.n a9, 8e <ppProcessLifeTime+0x6e> */
  a2 = (uint32_t)&g_offchan_packet_lifetime; /* 0081: l32r a2, 8 <ppProcessLifeTime-0x18> (0 <ppProcessLifeTime-0x20>) */ /* literal @0x8: g_offchan_packet_lifetime */
  a8 = MEM32(a2 + 0); /* 0084: l32i.n a8, a2, 0 */
  if (a8 == 0) goto L_ad; /* 0086: beqz.n a8, ad <ppProcessLifeTime+0x8d> */
  a10 = a8 << (10 & 31); /* 0088: slli a10, a8, 10 */
  goto L_ad; /* 008b: j ad <ppProcessLifeTime+0x8d> */
L_8e:;
  a12 = 0x1; /* 008e: movi.n a12, 1 */
  a15 = 0x1281; /* 0090: l32r a15, c <ppProcessLifeTime-0x14> (1281 <ppRxFragmentProc+0x1201>) */ @0xC
  a11 = 0x800; /* 0093: slli a11, a12, 11 */
  a10 = 0x6; /* 0096: movi.n a10, 6 */
  a14 = (uint32_t)&lit_rodata_pp_default_event_handler_str1_1; /* 0098: l32r a14, 10 <ppProcessLifeTime-0x10> (0 <ppProcessLifeTime-0x20>) */ /* literal @0x10: .rodata.pp_default_event_handler.str1.1 */
  a13 = (uint32_t)&lit_rodata_wlog_error_76; /* 009b: l32r a13, 14 <ppProcessLifeTime-0xc> (0 <ppProcessLifeTime-0x20>) */ /* literal @0x14: .rodata_wlog_error.76 */
  a8 = (uint32_t)&wifi_log; /* 009e: l32r a8, 1c <ppProcessLifeTime-0x4> (0 <ppProcessLifeTime-0x20>) */ /* literal: GOT slot for wifi_log */
  wifi_log(a2, a3, a4, a5); /* call via literal slot */ /* 00a1: callx8 a8 */
L_a4:;
  goto L_a4; /* 00a4: j a4 <ppProcessLifeTime+0x84> */
  /* 00a7: .byte 00 */
L_a8:;
  a10 = 0xF; /* 00a8: movi.n a10, 15 */
  a10 = 0x1E000; /* 00aa: slli a10, a10, 13 */
L_ad:;
  MEM32(a4 + 0) = a10; /* 00ad: s32i.n a10, a4, 0 */
  MEMW(); /* 00af: memw  */
  return (int32_t)a2; /* 00b2: retw.n  */
}

/* pp_delete_task_manually @ pp.o 00000000 size 69B bind LOCAL
 * Calls: none | Data refs: none
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: medium - 23 instr, 2 branches, calls resolved */
static int32_t pp_delete_task_manually(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.pp_delete_task_manually; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
  /* 000c: entry a1, 32 */
  a2 = 0x0; /* 000f: l32r a2, 0 <.text.pp_delete_task_manually> (0 <.text.pp_delete_task_manually>) */ @0x0
  a10 = MEM32(a2 + 0); /* 0012: l32i.n a10, a2, 0 */
  if (a10 == 0) goto L_25; /* 0014: beqz.n a10, 25 <.text.pp_delete_task_manually+0x25> */
  a8 = 0x0; /* 0016: l32r a8, 4 <.text.pp_delete_task_manually+0x4> (0 <.text.pp_delete_task_manually>) */ @0x4
  a8 = MEM32(a8 + 0); /* 0019: l32i.n a8, a8, 0 */
  a8 = MEM32(a8 + 152); /* 001b: l32i a8, a8, 152 */
  ((int32_t(*)())a8)(a2, a3, a4, a5); /* 001e: callx8 a8 */ /* indirect */
  a8 = 0x0; /* 0021: movi.n a8, 0 */
  MEM32(a2 + 0) = a8; /* 0023: s32i.n a8, a2, 0 */
L_25:;
  a2 = 0x0; /* 0025: l32r a2, 8 <.text.pp_delete_task_manually+0x8> (0 <.text.pp_delete_task_manually>) */ @0x8
  a10 = MEM32(a2 + 0); /* 0028: l32i.n a10, a2, 0 */
  if (a10 == 0) goto L_3e; /* 002a: beqz.n a10, 3e <.text.pp_delete_task_manually+0x3e> */
  a8 = 0x0; /* 002c: l32r a8, 4 <.text.pp_delete_task_manually+0x4> (0 <.text.pp_delete_task_manually>) */ @0x4
  a8 = MEM32(a8 + 0); /* 002f: l32i.n a8, a8, 0 */
  a8 = MEM32(a8 + 384); /* 0031: l32i a8, a8, 0x180 */
  MEMW(); /* 0034: memw  */
  ((int32_t(*)())a8)(a2, a3, a4, a5); /* 0037: callx8 a8 */ /* indirect */
  a8 = 0x0; /* 003a: movi.n a8, 0 */
  MEM32(a2 + 0) = a8; /* 003c: s32i.n a8, a2, 0 */
L_3e:;
  a2 = 0x0; /* 003e: movi.n a2, 0 */
  MEMW(); /* 0040: memw  */
  return (int32_t)a2; /* 0043: retw.n  */
}

