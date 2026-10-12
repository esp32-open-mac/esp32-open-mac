/* ===== lmac.o : reconstructed from libpp.a (ESP32, Xtensa, esp-2022r1) =====
 * Toolchain: xtensa-esp32-elf (GCC 11.2.0 crosstool-NG esp-2022r1).
 * ABI: args a2..a7, return a2 (all functions take a2..a7, return int32_t).
 * memw barriers preserved as MEMW(). MMIO as REG32/REG16/REG8(addr).
 * Calls with unknown arg counts are modeled with 4 live args (a2..a5);
 * a2..a7 are clobbered across calls (windowed-ABI approximation).
 * Sections: .iram1.12, .iram1.13, .iram1.14, .iram1.15, .text.dbg_lmac_get_acs, .text.esp_wifi_internal_get_mib, .text.esp_wifi_internal_get_rts, .text.esp_wifi_internal_set_msdu_lifetime, .text.esp_wifi_internal_set_retry_counter, .text.esp_wifi_internal_set_rts, .text.esp_wifi_set_11b_tx_plcp, .text.lmacDebugTxDrop, .text.lmacDisableTransmit, .text.lmacDiscardMSDU, .text.lmacEndRetryAMPDUFail, .text.lmacGetTxFrame, .text.lmacInit, .text.lmacInitAc, .text.lmacIsIdle, .text.lmacIsLongFrame, .text.lmacProcessAckTimeout, .text.lmacProcessCollision, .text.lmacProcessCollisions_task, .text.lmacProcessCtsTimeout, .text.lmacProcessLongRetryFail, .text.lmacProcessShortRetryFail, .text.lmacProcessTxError, .text.lmacProcessTxRtsError, .text.lmacProcessTxTimeout, .text.lmacProcessTxopSuccess, .text.lmacProcessTxseckiderr, .text.lmacReachLongLimit, .text.lmacReachShortLimit, .text.lmacRetryTxFrame, .text.lmacRxDone, .text.lmacSetAcParam, .text.lmacStopTransmit, .text.lmac_record_txtime, .text.lmac_stop_hw_txq, .text.lmac_update_tx_statistic, .text.offchan_in_progress, .wifi0iram.11, .wifi0iram.18, .wifi0iram.2, .wifi0iram.22, .wifi0iram.23, .wifi0iram.25, .wifi0iram.28, .wifi0iram.3, .wifi0iram.5, .wifi0iram.7, .wifi0iram.8, .wifi0iram.9, .wifiextrairam.10, .wifiextrairam.16, .wifiextrairam.4, .wifiextrairam.6
 * Undefined refs (55): RC_SetBasicRate, esf_buf_recycle, ets_delay_us, g_lmac_cnt, g_mesh_init_ps_type, g_mesh_is_root, g_mesh_is_started, g_osi_funcs_p, g_wifi_mac_time_delta, hal_mac_clr_txq_state, hal_mac_get_txq_pmd, hal_mac_get_txq_state, hal_mac_is_txq_valid, hal_mac_set_txq_invalid, hal_mac_tx_config_edca, hal_mac_tx_config_timeout, hal_mac_tx_get_blockack, hal_mac_tx_is_cbw40, hal_mac_tx_set_cca, hal_mac_tx_set_ppdu, hal_mac_txq_disable, hal_mac_txq_enable, hal_random, memcpy...
 */
#include <stdint.h>
#define REG32(a) (*(volatile uint32_t *)(a))
#define REG16(a) (*(volatile uint16_t *)(a))
#define REG8(a)  (*(volatile uint8_t *)(a))
#define MEM32(a) (*(volatile uint32_t *)(a))
#define MEM16(a) (*(volatile uint16_t *)(a))
#define MEM8(a)  (*(volatile uint8_t *)(a))
#define MEMW() __asm__ volatile("memw" ::: "memory")

extern uint32_t bss_our_instances; /* .bss.our_instances (verify defined-here with nm) */
uint32_t lmacConfMib; /* defined here (.bss/.data); was: lmacConfMib */
extern int32_t wDev_is_low_rate_enable();
extern uint32_t g_mesh_is_started; /* g_mesh_is_started */
extern uint32_t g_mesh_is_root; /* g_mesh_is_root */
extern uint32_t g_mesh_init_ps_type; /* g_mesh_init_ps_type */
extern uint32_t g_osi_funcs_p; /* g_osi_funcs_p */
extern uint32_t g_wifi_mac_time_delta; /* g_wifi_mac_time_delta */
extern int32_t ppProcessLifeTime();
extern int32_t hal_mac_tx_config_timeout();
extern int32_t pTxRx();
extern int32_t hal_mac_tx_set_ppdu();
extern int32_t RC_SetBasicRate();
extern int32_t rcAttach();
extern uint32_t rodata_FUNCTION_14; /* .rodata.__FUNCTION__$14 */
extern uint32_t rodata_lmacProcessTxopSuccess_str1_1; /* .rodata.lmacProcessTxopSuccess.str1.1 */
extern int32_t wifi_assert();
extern int32_t trc_isTxAmpduOperational();
extern int32_t ppRecordBarRRC();
extern int32_t ppFillAMPDUBar();
extern int32_t ppReSendBar();
extern int32_t ppRegressAmpdu();
extern int32_t pp_post();
extern uint32_t g_lmac_cnt; /* g_lmac_cnt */
extern int32_t memcpy();
extern uint32_t rodata_wlog_info_21; /* .rodata_wlog_info.21 */
extern int32_t wifi_log();
extern int32_t ppProcTxCallback();
extern int32_t ppEnqueueTxDone();
extern int32_t rcUpdateTxDone();
extern uint32_t rodata_FUNCTION_0; /* .rodata.__FUNCTION__$0 */
extern int32_t ppProcessTxQ();
extern int32_t lmacDebugTxDrop(); /* fwd: static in another object */
extern int32_t ppDequeueTxQ();
extern uint32_t rodata_wlog_debug_24; /* .rodata_wlog_debug.24 */
extern int32_t wDev_isNANPktInValidSlot();
extern int32_t ppRecycleAmpdu();
extern uint32_t rodata_FUNCTION_1; /* .rodata.__FUNCTION__$1 */
extern int32_t hal_random();
extern int32_t hal_mac_tx_config_edca();
extern int32_t wifi_gpio_debug();
extern int32_t hal_mac_txq_enable();
extern int32_t rcGetRate();
extern int32_t ppCalFrameTimes();
extern uint32_t rodata_wlog_info_19; /* .rodata_wlog_info.19 */
extern uint32_t rodata_FUNCTION_11; /* .rodata.__FUNCTION__$11 */
extern int32_t ppResortTxAMPDU();
extern uint32_t rodata_FUNCTION_10; /* .rodata.__FUNCTION__$10 */
extern int32_t memset();
extern int32_t hal_mac_tx_get_blockack();
extern int32_t hal_mac_tx_is_cbw40();
extern int32_t ppTxqUpdateBitmap();
extern uint32_t rodata_FUNCTION_13; /* .rodata.__FUNCTION__$13 */
extern uint32_t rodata_FUNCTION_12; /* .rodata.__FUNCTION__$12 */
extern uint32_t rodata_FUNCTION_7; /* .rodata.__FUNCTION__$7 */
extern int32_t rcReachRetryLimit();
extern uint32_t rodata_FUNCTION_5; /* .rodata.__FUNCTION__$5 */
extern uint32_t rodata_FUNCTION_6; /* .rodata.__FUNCTION__$6 */
extern uint32_t rodata_FUNCTION_9; /* .rodata.__FUNCTION__$9 */
extern int32_t hal_mac_get_txq_state();
extern int32_t hal_mac_txq_disable();
extern int32_t hal_mac_clr_txq_state();
extern uint32_t rodata_FUNCTION_4; /* .rodata.__FUNCTION__$4 */
extern uint32_t rodata_FUNCTION_3; /* .rodata.__FUNCTION__$3 */
extern uint32_t rodata_wlog_warning_20; /* .rodata_wlog_warning.20 */
extern uint32_t rodata_FUNCTION_2; /* .rodata.__FUNCTION__$2 */
extern int32_t pm_is_sleeping();
uint32_t g_pp_tx_pkt_num; /* defined here (.bss/.data); was: g_pp_tx_pkt_num */
extern int32_t tx_pwctrl_background();
extern uint32_t rodata_wlog_info_17; /* .rodata_wlog_info.17 */
extern int32_t hal_mac_get_txq_pmd();
extern int32_t rodata();
extern uint32_t rodata_FUNCTION_8; /* .rodata.__FUNCTION__$8 */
extern int32_t ppEnqueueRxq();
extern int32_t hal_mac_tx_set_cca();
extern int32_t ets_delay_us();
extern int32_t hal_mac_is_txq_valid();
extern int32_t hal_mac_set_txq_invalid();
extern int32_t ppDirectRecycleAmpdu();
extern int32_t esf_buf_recycle();
extern uint32_t rodata_wlog_info_26; /* .rodata_wlog_info.26 */
extern uint32_t rodata_wlog_warning_27; /* .rodata_wlog_warning.27 */

/* pool[offchan_in_progress]: +0x0=0x00000000 */
/* pool[lmacIsIdle]: +0x0=0x00000000(.bss.our_instances) */
/* pool[lmacGetTxFrame]: +0x0=0x00000000(.bss.our_instances) */
/* pool[lmacReachShortLimit]: +0x0=0x00000000(lmacConfMib) */
/* pool[lmacReachLongLimit]: +0x0=0x00000000(lmacConfMib) */
/* pool[lmacIsLongFrame]: +0x0=0x00000000(lmacConfMib) */
/* pool[lmacSetTxFrame]: +0x24=0x00000000(wDev_is_low_rate_enable), +0x0=0xFF00FF00, +0x4=0x00000000(lmacConfMib), +0x8=0x00000000(g_mesh_is_started), +0xc=0x00000000(g_mesh_is_root), +0x10=0x00000000(g_mesh_init_ps_type), +0x14=0x00000000(g_osi_funcs_p), +0x18=0x3FF73C00, +0x1c=0x00000000(g_wifi_mac_time_delta), +0x28=0x00000000(ppProcessLifeTime), +0x2c=0x00000000(hal_mac_tx_config_timeout), +0x20=0x00000000(pTxRx), +0x30=0x00000000(hal_mac_tx_set_ppdu) */
/* pool[lmacSetAcParam]: +0x0=0x00000000(.bss.our_instances) */
/* pool[lmacInitAc]: +0x0=0x00000000(.bss.our_instances) */
/* pool[lmacInit]: +0x0=0x00000000(lmacConfMib), +0x4=0x092A2020, +0x8=0x0FFF015F, +0xc=0x00000000(lmacInitAc), +0x10=0x00000000(lmacInitAc), +0x14=0x00000000(lmacInitAc), +0x18=0x00000000(lmacInitAc), +0x1c=0x00000000(lmacInitAc), +0x20=0x00000000(RC_SetBasicRate), +0x24=0x00000000(rcAttach) */
/* pool[lmacProcessTxopSuccess]: +0x0=0x00000000(.rodata.__FUNCTION__$14), +0x4=0x00000000(.rodata.lmacProcessTxopSuccess.str1.1), +0xc=0x00000000(wifi_assert), +0x8=0x00000000(.bss.our_instances), +0x10=0x00000000(wifi_assert), +0x14=0x00000000(wifi_assert), +0x18=0x00000000(wifi_assert) */
/* pool[GetAccess]: +0x0=0x00000000(.bss.our_instances) */
/* pool[lmacEndRetryAMPDUFail]: +0x0=0x00000000(trc_isTxAmpduOperational), +0x4=0x00000000(ppRecordBarRRC), +0x8=0x00000000(ppFillAMPDUBar), +0xc=0x00000000(ppReSendBar), +0x10=0x00000000(ppRegressAmpdu) */
/* pool[lmacProcessCollisions]: +0x0=0x00000000(pp_post) */
/* pool[lmacProcessAllTxTimeout]: +0x0=0x00000000(pp_post) */
/* pool[lmacPostTxComplete]: +0x0=0x00000000(pp_post) */
/* pool[lmacProcessRxSucData]: +0x0=0x00000000(g_mesh_is_started), +0x4=0x00000000(g_mesh_is_root), +0x8=0x00000000(g_mesh_init_ps_type), +0xc=0x00000000(g_osi_funcs_p), +0x10=0x3FF73C00, +0x14=0x00000000(g_wifi_mac_time_delta), +0x18=0x00000000(pp_post) */
/* pool[lmacMSDUAged]: +0x0=0x00000000(g_mesh_is_started), +0x4=0x00000000(g_mesh_is_root), +0x8=0x00000000(g_mesh_init_ps_type), +0xc=0x00000000(g_osi_funcs_p), +0x10=0x3FF73C00, +0x14=0x00000000(g_wifi_mac_time_delta), +0x18=0x00000000(lmacConfMib), +0x1c=0x00000000(ppProcessLifeTime) */
/* pool[dbg_cnt_lmac_drop]: +0x0=0x00000000(lmacConfMib), +0x4=0x00000000(g_lmac_cnt), +0x8=0x00000000(lmacMSDUAged) */
/* pool[esp_wifi_internal_set_retry_counter]: +0x0=0x00000000(lmacConfMib) */
/* pool[esp_wifi_internal_set_msdu_lifetime]: +0x0=0x00000000(lmacConfMib) */
/* pool[esp_wifi_internal_get_mib]: +0x0=0x00000000(lmacConfMib), +0x4=0x00000000(memcpy) */
/* pool[esp_wifi_internal_set_rts]: +0x0=0x00000000(lmacConfMib), +0x4=0x00000000(.rodata_wlog_info.21), +0x8=0x00000000(wifi_log) */
/* pool[esp_wifi_internal_get_rts]: +0x0=0x00000000(lmacConfMib) */
/* pool[lmacAdjustTimestamp]: +0x0=0x00000000(g_mesh_is_started), +0x4=0x3FF73C00, +0x8=0x00000000(g_wifi_mac_time_delta), +0xc=0x00000000(lmacConfMib) */
/* pool[lmacTxDone]: +0x14=0x00000000(ppProcTxCallback), +0x18=0x00000000(ppEnqueueTxDone), +0x0=0x00400008, +0x1c=0x00000000(rcUpdateTxDone), +0x20=0x00000000(pp_post), +0x10=0x00000000(.bss.our_instances), +0x4=0x000009B7, +0x8=0x00000000(.rodata.__FUNCTION__$0), +0xc=0x00000000(.rodata.lmacProcessTxopSuccess.str1.1), +0x24=0x00000000(wifi_assert), +0x28=0x00000000(ppProcessTxQ) */
/* pool[lmacDiscardMSDU]: +0x0=0x0000000C(.text.lmacDebugTxDrop), +0x4=0x00000000(lmacTxDone), +0x8=0x00000000(ppDequeueTxQ), +0xc=0x00000000(lmacTxDone) */
/* pool[lmacDiscardAgedMSDU]: +0x0=0x00000000(lmacDiscardMSDU) */
/* pool[lmacTxFrame]: +0x0=0x00000000(.bss.our_instances), +0x2c=0x00000004(.text.offchan_in_progress), +0x4=0x00000000(.rodata_wlog_debug.24), +0x30=0x00000000(wifi_log), +0x34=0x00000000(wDev_isNANPktInValidSlot), +0x38=0x00000000(lmacDiscardAgedMSDU), +0x3c=0x00000000(ppRecycleAmpdu), +0x40=0x00000000(pp_post), +0x8=0x00000000(.rodata.__FUNCTION__$1), +0xc=0x00000000(.rodata.lmacProcessTxopSuccess.str1.1), +0x44=0x00000000(wifi_assert), +0x10=0x00000000(g_osi_funcs_p), +0x48=0x00000000(wifi_assert), +0x14=0x000008C7, +0x4c=0x00000000(wifi_assert), +0x18=0x00002102, +0x1c=0x00002002, +0x20=0xFFFFEFFF, +0x50=0x00000000(lmacIsLongFrame), +0x24=0x00000000(lmacConfMib), +0x54=0x00000000(lmacSetTxFrame), +0x28=0x00000000(g_lmac_cnt), +0x58=0x00000000(lmacIsLongFrame), +0x5c=0x00000000(hal_random), +0x60=0x00000000(hal_random), +0x64=0x00000000(hal_mac_tx_config_edca), +0x68=0x00000000(wifi_gpio_debug), +0x6c=0x00000000(hal_mac_txq_enable) */
/* pool[lmacRetryTxFrame]: +0x4=0x00000000(rcGetRate), +0x8=0x00000000(ppCalFrameTimes), +0xc=0x00000000(lmacTxFrame), +0x0=0x00000000(.rodata_wlog_info.19), +0x10=0x00000000(wifi_log), +0x14=0x00000000(lmacDiscardAgedMSDU), +0x18=0x00000000(ppRecycleAmpdu) */
/* pool[lmacDiscardFrameExchangeSequence]: +0x0=0x00000000(.rodata.__FUNCTION__$11), +0x4=0x00000000(.rodata.lmacProcessTxopSuccess.str1.1), +0xc=0x00000000(wifi_assert), +0x10=0x00000000(ppRecordBarRRC), +0x14=0x00000000(ppResortTxAMPDU), +0x18=0x00000000(ppRecycleAmpdu), +0x8=0x00000000(lmacConfMib), +0x1c=0x00000000(lmacDiscardMSDU) */
/* pool[lmacRecycleMPDU]: +0x0=0x00000000(lmacTxDone) */
/* pool[lmacEndFrameExchangeSequence]: +0x0=0x00000000(.rodata.__FUNCTION__$10), +0x4=0x00000000(.rodata.lmacProcessTxopSuccess.str1.1), +0x10=0x00000000(wifi_assert), +0x14=0x00000000(ppRecordBarRRC), +0x18=0x00000000(ppResortTxAMPDU), +0x1c=0x00000000(ppRecycleAmpdu), +0x8=0x00000000(lmacConfMib), +0x20=0x00000000(lmacDiscardMSDU), +0x24=0x00000000(wifi_assert), +0x28=0x00000000(memset), +0x2c=0x00000000(hal_mac_tx_get_blockack), +0xc=0x00000000(pTxRx), +0x30=0x00000000(hal_mac_tx_is_cbw40), +0x34=0x00000000(ppTxqUpdateBitmap), +0x38=0x00000000(ppRecycleAmpdu), +0x3c=0x00000000(ppResortTxAMPDU), +0x40=0x00000000(wifi_assert), +0x44=0x00000000(trc_isTxAmpduOperational), +0x48=0x00000000(ppReSendBar), +0x4c=0x00000000(ppRegressAmpdu), +0x50=0x00000000(lmacRecycleMPDU), +0x54=0x00000000(wifi_assert), +0x58=0x00000000(wifi_assert), +0x5c=0x00000000(lmacRetryTxFrame), +0x60=0x00000000(lmacIsLongFrame), +0x64=0x00000000(lmacRetryTxFrame), +0x68=0x00000000(lmacEndRetryAMPDUFail) */
/* pool[lmacProcessTBSuccess]: +0x0=0x00000000(.rodata.__FUNCTION__$13), +0x4=0x00000000(.rodata.lmacProcessTxopSuccess.str1.1), +0xc=0x00000000(wifi_assert), +0x8=0x00000000(.bss.our_instances), +0x10=0x00000000(lmacEndFrameExchangeSequence) */
/* pool[lmacProcessTxSuccess]: +0x4=0x00000000(.rodata.lmacProcessTxopSuccess.str1.1), +0x0=0x00000000(.rodata.__FUNCTION__$12), +0xc=0x00000000(wifi_assert), +0x8=0x00000000(.bss.our_instances), +0x10=0x00000000(lmacIsLongFrame), +0x14=0x00000000(lmacEndFrameExchangeSequence) */
/* pool[lmacProcessShortRetryFail]: +0x0=0x00000000(.rodata.__FUNCTION__$7), +0x4=0x00000000(.rodata.lmacProcessTxopSuccess.str1.1), +0x14=0x00000000(wifi_assert), +0x8=0x00000000(lmacConfMib), +0x18=0x00000000(wifi_assert), +0x1c=0x00000000(rcReachRetryLimit), +0xc=0x00400100, +0x20=0x00000000(lmacMSDUAged), +0x24=0x00000000(lmacIsLongFrame), +0x28=0x00000000(lmacEndRetryAMPDUFail), +0x2c=0x00000000(lmacDiscardFrameExchangeSequence), +0x30=0x00000000(lmacEndFrameExchangeSequence), +0x10=0x00600002, +0x34=0x00000000(wifi_assert), +0x38=0x00000000(lmacRetryTxFrame) */
/* pool[lmacProcessCtsTimeout]: +0x8=0x00000000(.bss.our_instances), +0x0=0x00000000(.rodata.__FUNCTION__$5), +0x4=0x00000000(.rodata.lmacProcessTxopSuccess.str1.1), +0xc=0x00000000(wifi_assert), +0x10=0x00000000(lmacProcessShortRetryFail) */
/* pool[lmacProcessLongRetryFail]: +0x0=0x00000000(lmacConfMib), +0x4=0x00000000(.rodata.__FUNCTION__$6), +0x8=0x00000000(.rodata.lmacProcessTxopSuccess.str1.1), +0x10=0x00000000(wifi_assert), +0x14=0x00000000(rcReachRetryLimit), +0x18=0x00000000(lmacMSDUAged), +0x1c=0x00000000(lmacDiscardFrameExchangeSequence), +0xc=0x00400002, +0x20=0x00000000(lmacEndFrameExchangeSequence), +0x24=0x00000000(wifi_assert), +0x28=0x00000000(lmacRetryTxFrame) */
/* pool[lmacProcessCollision]: +0x0=0x00000000(.rodata.__FUNCTION__$9), +0x4=0x00000000(.rodata.lmacProcessTxopSuccess.str1.1), +0xc=0x00000000(wifi_assert), +0x8=0x00000000(.bss.our_instances), +0x10=0x00000000(wifi_assert), +0x14=0x00000000(wifi_assert), +0x18=0x00000000(lmacIsLongFrame), +0x1c=0x00000000(lmacProcessShortRetryFail), +0x20=0x00000000(lmacProcessLongRetryFail) */
/* pool[lmacProcessCollisions_task]: +0x0=0x00000000(hal_mac_get_txq_state), +0x4=0x00000000(hal_mac_txq_disable), +0x8=0x00000000(hal_mac_clr_txq_state), +0xc=0x00000000(lmacProcessCollision) */
/* pool[lmacProcessAckTimeout]: +0x0=0x00000000(.rodata.__FUNCTION__$4), +0x4=0x00000000(.rodata.lmacProcessTxopSuccess.str1.1), +0xc=0x00000000(wifi_assert), +0x10=0x00000000(wifi_assert), +0x8=0x00000000(.bss.our_instances), +0x14=0x00000000(wifi_assert), +0x18=0x00000000(lmacProcessLongRetryFail), +0x1c=0x00000000(lmacProcessShortRetryFail), +0x20=0x00000000(wifi_assert) */
/* pool[lmacProcessTxRtsError]: +0x0=0x00000000(.rodata.__FUNCTION__$3), +0x4=0x00000000(.rodata.lmacProcessTxopSuccess.str1.1), +0x10=0x00000000(wifi_assert), +0x14=0x00000000(lmacProcessCollision), +0x8=0x00000000(.bss.our_instances), +0x18=0x00000000(lmacEndFrameExchangeSequence), +0xc=0x00000000(.rodata_wlog_warning.20), +0x1c=0x00000000(wifi_log), +0x20=0x00000000(wifi_assert) */
/* pool[lmacProcessTxseckiderr]: +0x0=0x00000000(lmacEndFrameExchangeSequence) */
/* pool[lmacProcessTxError]: +0x0=0x00000809, +0x4=0x00000000(.rodata.__FUNCTION__$2), +0x8=0x00000000(.rodata.lmacProcessTxopSuccess.str1.1), +0x10=0x00000000(wifi_assert), +0x14=0x00000000(lmacProcessCollision), +0xc=0x00000000(.bss.our_instances), +0x18=0x00000000(lmacProcessTxseckiderr), +0x1c=0x00000000(lmacProcessCtsTimeout), +0x20=0x00000000(lmacProcessAckTimeout) */
/* pool[lmacProcessTxComplete]: +0x1c=0x00000000(hal_mac_get_txq_state), +0x0=0x00000000(g_osi_funcs_p), +0x20=0x00000000(pm_is_sleeping), +0x4=0x00000000(g_pp_tx_pkt_num), +0x24=0x00000000(tx_pwctrl_background), +0x8=0x00000000(.bss.our_instances), +0x28=0x00000000(hal_mac_clr_txq_state), +0xc=0x00000000(.rodata_wlog_info.17), +0x2c=0x00000000(wifi_log), +0x30=0x00000000(hal_mac_get_txq_pmd), +0x34=0x00000000(hal_mac_clr_txq_state), +0x38=0x00000000(wifi_gpio_debug), +0x10=0x00000000(.rodata), +0x3c=0x00000000(lmacProcessTxSuccess), +0x40=0x00000000(lmacProcessTxRtsError), +0x44=0x00000000(lmacProcessCtsTimeout), +0x48=0x00000000(lmacProcessAckTimeout), +0x4c=0x00000000(lmacProcessTxError), +0x14=0x00000000(.rodata.__FUNCTION__$8), +0x18=0x00000000(.rodata.lmacProcessTxopSuccess.str1.1), +0x50=0x00000000(wifi_assert) */
/* pool[lmacRxDone]: +0x0=0x00000000(ppEnqueueRxq), +0x4=0x00000000(pp_post) */
/* pool[lmacDisableTransmit]: +0x4=0x00000000(hal_mac_tx_set_cca), +0x8=0x00000000(ets_delay_us), +0xc=0x00000000(hal_mac_is_txq_valid), +0x10=0x00000000(hal_mac_set_txq_invalid), +0x14=0x00000000(hal_mac_tx_set_cca), +0x0=0x00000000(.bss.our_instances), +0x18=0x00000000(hal_mac_txq_disable), +0x1c=0x00000000(lmacDiscardFrameExchangeSequence) */
/* pool[lmacProcessTxTimeout]: +0x0=0x00000000(hal_mac_get_txq_state), +0x4=0x00000000(lmacDisableTransmit), +0x8=0x00000000(hal_mac_clr_txq_state) */
/* pool[lmacStopTransmit]: +0x8=0x00000000(hal_mac_tx_set_cca), +0xc=0x00000000(ets_delay_us), +0x10=0x00000000(hal_mac_is_txq_valid), +0x14=0x00000000(hal_mac_set_txq_invalid), +0x18=0x00000000(hal_mac_tx_set_cca), +0x0=0x00000000(.bss.our_instances), +0x1c=0x00000000(hal_mac_txq_disable), +0x4=0x00000000(pTxRx), +0x20=0x00000000(ppDirectRecycleAmpdu), +0x24=0x00000000(esf_buf_recycle), +0x28=0x00000000(ppDirectRecycleAmpdu) */
/* pool[dbg_lmac_get_acs]: +0x0=0x00000000(.bss.our_instances) */
/* pool[lmac_stop_hw_txq]: +0x0=0x00000000(.rodata_wlog_info.26), +0xc=0x00000000(wifi_log), +0x4=0x00000000(.bss.our_instances), +0x8=0x00000000(.rodata_wlog_warning.27), +0x10=0x00000000(wifi_log), +0x14=0x00000000(lmacStopTransmit) */
/* pool[is_lmac_idle]: +0x0=0x00000000(.bss.our_instances) */
/* pool[esp_wifi_set_11b_tx_plcp]: +0x0=0x00000000(lmacConfMib) */

/* lmacIsIdle @ lmac.o 00000004 size 27B bind GLOBAL
 * Calls: none | Data refs: .bss.our_instances
 *   MMIO: none
 *   funcdb v3: 0 call(s), 1 ref(s); disasm: 0 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t lmacIsIdle(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.lmacIsIdle; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a8 = (uint32_t)&bss_our_instances; /* 0007: l32r a8, 0 <lmacIsIdle-0x4> (0 <lmacIsIdle-0x4>) */ /* literal @0x0: .bss.our_instances */
  a2 = (a2 >> 0) & 0xFF; /* 000a: extui a2, a2, 0, 8 */
  a2 = (a2 << 8) + a2; /* 000d: addx8 a2, a2, a2 */
  a2 = (a2 << 4) + a8; /* 0010: addx4 a2, a2, a8 */
  a8 = 0x0; /* 0013: movi.n a8, 0 */
  a9 = MEM8(a2 + 18); /* 0015: l8ui a9, a2, 18 */
  a2 = 0x1; /* 0018: movi.n a2, 1 */
  if (a9 != 0) a2 = a8; /* 001a: movnez a2, a8, a9 */
  return (int32_t)a2; /* 001d: retw.n  */
}

/* lmacGetTxFrame @ lmac.o 00000004 size 27B bind GLOBAL
 * Calls: none | Data refs: .bss.our_instances
 *   MMIO: none
 *   funcdb v3: 0 call(s), 1 ref(s); disasm: 0 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t lmacGetTxFrame(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.lmacGetTxFrame; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a8 = (uint32_t)&bss_our_instances; /* 0007: l32r a8, 0 <lmacGetTxFrame-0x4> (0 <lmacGetTxFrame-0x4>) */ /* literal @0x0: .bss.our_instances */
  a2 = (a2 >> 0) & 0xFF; /* 000a: extui a2, a2, 0, 8 */
  a2 = (a2 << 8) + a2; /* 000d: addx8 a2, a2, a2 */
  a8 = (a2 << 4) + a8; /* 0010: addx4 a8, a2, a8 */
  a2 = 0x0; /* 0013: movi.n a2, 0 */
  a9 = MEM8(a8 + 18); /* 0015: l8ui a9, a8, 18 */
  if (a9 == a2) goto L_1d; /* 0018: beq a9, a2, 1d <lmacGetTxFrame+0x19> */
  a2 = MEM32(a8 + 0); /* 001b: l32i.n a2, a8, 0 */
L_1d:;
  return (int32_t)a2; /* 001d: retw.n  */
}

/* lmacReachShortLimit @ lmac.o 00000004 size 25B bind GLOBAL
 * Calls: none | Data refs: lmacConfMib
 *   MMIO: none
 *   funcdb v3: 0 call(s), 1 ref(s); disasm: 0 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t lmacReachShortLimit(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.lmacReachShortLimit; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a9 = (uint32_t)&lmacConfMib; /* 0007: l32r a9, 0 <lmacReachShortLimit-0x4> (0 <lmacReachShortLimit-0x4>) */ /* literal @0x0: lmacConfMib */
  a2 = (a2 >> 0) & 0xFF; /* 000a: extui a2, a2, 0, 8 */
  a8 = 0x1; /* 000d: movi.n a8, 1 */
  a9 = MEM8(a9 + 21); /* 000f: l8ui a9, a9, 21 */
  if (a2 >= a9) goto L_18; /* 0012: bgeu a2, a9, 18 <lmacReachShortLimit+0x14> */
  a8 = 0x0; /* 0015: movi a8, 0 */
L_18:;
  a2 = 0x0; /* 0018: extui a2, a8, 0, 1 */
  return (int32_t)a2; /* 001b: retw.n  */
}

/* lmacReachLongLimit @ lmac.o 00000004 size 25B bind GLOBAL
 * Calls: none | Data refs: lmacConfMib
 *   MMIO: none
 *   funcdb v3: 0 call(s), 1 ref(s); disasm: 0 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t lmacReachLongLimit(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.lmacReachLongLimit; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a9 = (uint32_t)&lmacConfMib; /* 0007: l32r a9, 0 <lmacReachLongLimit-0x4> (0 <lmacReachLongLimit-0x4>) */ /* literal @0x0: lmacConfMib */
  a2 = (a2 >> 0) & 0xFF; /* 000a: extui a2, a2, 0, 8 */
  a8 = 0x1; /* 000d: movi.n a8, 1 */
  a9 = MEM8(a9 + 20); /* 000f: l8ui a9, a9, 20 */
  if (a2 >= a9) goto L_18; /* 0012: bgeu a2, a9, 18 <lmacReachLongLimit+0x14> */
  a8 = 0x0; /* 0015: movi a8, 0 */
L_18:;
  a2 = 0x0; /* 0018: extui a2, a8, 0, 1 */
  return (int32_t)a2; /* 001b: retw.n  */
}

/* lmacIsLongFrame @ lmac.o 00000004 size 29B bind GLOBAL
 * Calls: none | Data refs: lmacConfMib
 *   MMIO: none
 *   funcdb v3: 0 call(s), 1 ref(s); disasm: 0 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t lmacIsLongFrame(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.lmacIsLongFrame; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a8 = MEM16(a2 + 22); /* 0007: l16ui a8, a2, 22 */
  a2 = MEM16(a2 + 20); /* 000a: l16ui a2, a2, 20 */
  a8 = a8 + a2; /* 000d: add.n a8, a8, a2 */
  a2 = (uint32_t)&lmacConfMib; /* 000f: l32r a2, 0 <lmacIsLongFrame-0x4> (0 <lmacIsLongFrame-0x4>) */ /* literal @0x0: lmacConfMib */
  a9 = MEM16(a2 + 22); /* 0012: l16ui a9, a2, 22 */
  a2 = 0x1; /* 0015: movi.n a2, 1 */
  if (a9 < a8) goto L_1c; /* 0017: blt a9, a8, 1c <lmacIsLongFrame+0x18> */
  a2 = 0x0; /* 001a: movi.n a2, 0 */
L_1c:;
  a2 = 0x0; /* 001c: extui a2, a2, 0, 1 */
  return (int32_t)a2; /* 001f: retw.n  */
}

/* lmacProcessLongFrameSuccess @ lmac.o 00000000 size 22B bind GLOBAL
 * Calls: none | Data refs: none
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t lmacProcessLongFrameSuccess(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .wifi0iram.2; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_0:;
  /* 0000: entry a1, 32 */
  a8 = MEM8(a2 + 9); /* 0003: l8ui a8, a2, 9 */
  MEM8(a2 + 8) = a8; /* 0006: s8i a8, a2, 8 */
  a8 = 0x0; /* 0009: movi.n a8, 0 */
  MEM8(a2 + 12) = a8; /* 000b: s8i a8, a2, 12 */
  MEMW(); /* 000e: memw  */
  MEMW(); /* 0011: memw  */
  return (int32_t)a2; /* 0014: retw.n  */
}

/* lmacProcessShortFrameSuccess @ lmac.o 00000000 size 22B bind GLOBAL
 * Calls: none | Data refs: none
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t lmacProcessShortFrameSuccess(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .wifi0iram.3; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_0:;
  /* 0000: entry a1, 32 */
  a8 = MEM8(a2 + 9); /* 0003: l8ui a8, a2, 9 */
  MEM8(a2 + 8) = a8; /* 0006: s8i a8, a2, 8 */
  a8 = 0x0; /* 0009: movi.n a8, 0 */
  MEM8(a2 + 11) = a8; /* 000b: s8i a8, a2, 11 */
  MEMW(); /* 000e: memw  */
  MEMW(); /* 0011: memw  */
  return (int32_t)a2; /* 0014: retw.n  */
}

/* lmacSetTxFrame @ lmac.o 00000034 size 342B bind GLOBAL
 * Calls: wDev_is_low_rate_enable[got], ppProcessLifeTime[got], hal_mac_tx_config_timeout[got], hal_mac_tx_set_ppdu[got] | Data refs: wDev_is_low_rate_enable, lmacConfMib, g_mesh_is_started, g_mesh_is_root, g_mesh_init_ps_type, g_osi_funcs_p, g_wifi_mac_time_delta, ppProcessLifeTime, hal_mac_tx_config_timeout, pTxRx, hal_mac_tx_set_ppdu
 *   MMIO: 0x3FF73C00
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 4 call(s), 11 data ref(s)
 * Fidelity: medium - 134 instr, 25 branches, calls resolved */
int32_t lmacSetTxFrame(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .wifiextrairam.4; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_34:;
  /* 0034: entry a1, 48 */
  a3 = (a3 >> 0) & 0xFF; /* 0037: extui a3, a3, 0, 8 */
  if (a3 != 0) goto L_180; /* 003a: bnez a3, 180 <lmacSetTxFrame+0x14c> */
  a4 = MEM32(a2 + 0); /* 003d: l32i.n a4, a2, 0 */
  a3 = MEM32(a4 + 44); /* 003f: l32i.n a3, a4, 44 */
  a5 = MEM32(a4 + 4); /* 0041: l32i.n a5, a4, 4 */
  a6 = MEM32(a3 + 0); /* 0043: l32i.n a6, a3, 0 */
  a5 = MEM32(a5 + 4); /* 0045: l32i.n a5, a5, 4 */
  if (!((a6 >> 18) & 1)) goto L_4c; /* 0047: bbci a6, 18, 4c <lmacSetTxFrame+0x18> */
  a5 = a5 + (4); /* 004a: addi.n a5, a5, 4 */
L_4c:;
  a6 = MEM16(a3 + 10); /* 004c: l16ui a6, a3, 10 */
  a8 = (uint32_t)&wDev_is_low_rate_enable; /* 004f: l32r a8, 24 <lmacSetTxFrame-0x10> (0 <lmacSetTxFrame-0x34>) */ /* literal: GOT slot for wDev_is_low_rate_enable */
  wDev_is_low_rate_enable(a2, a3, a4, a5); /* call via literal slot */ /* 0052: callx8 a8 */
  a9 = MEM32(a4 + 44); /* 0055: l32i.n a9, a4, 44 */
  if (a10 == 0) goto L_74; /* 0057: beqz.n a10, 74 <lmacSetTxFrame+0x40> */
  a8 = 0x9; /* 0059: movi.n a8, 9 */
  a3 = MEM8(a9 + 12); /* 005b: l8ui a3, a9, 12 */
  if (a3 != a8) goto L_69; /* 005e: bne a3, a8, 69 <lmacSetTxFrame+0x35> */
  a3 = 0xE; /* 0061: movi.n a3, 14 */
  goto L_6e; /* 0063: j 6e <lmacSetTxFrame+0x3a> */
  /* 0066: .byte 00 */
  /* 0067: .byte 00 */
  /* 0068: .byte 00 */
L_69:;
  if (a3 != 10) goto L_74; /* 0069: bnei a3, 10, 74 <lmacSetTxFrame+0x40> */
  a3 = 0xF; /* 006c: movi.n a3, 15 */
L_6e:;
  MEM8(a9 + 12) = a3; /* 006e: s8i a3, a9, 12 */
  MEMW(); /* 0071: memw  */
L_74:;
  a3 = MEM32(a9 + 0); /* 0074: l32i.n a3, a9, 0 */
  if (!((a3 >> 22) & 1)) goto L_80; /* 0076: bbci a3, 22, 80 <lmacSetTxFrame+0x4c> */
  MEMW(); /* 0079: memw  */
  goto L_96; /* 007c: j 96 <lmacSetTxFrame+0x62> */
  /* 007f: .byte 00 */
L_80:;
  a8 = MEM32(a2 + 12); /* 0080: l32i.n a8, a2, 12 */
  a3 = 0xFF00FF00; /* 0082: l32r a3, 0 <lmacSetTxFrame-0x34> (ff00ff00 <lmacTxFrame+0xff00fe90>) */ @0x0
  if ((a8 & a3) != 0) goto L_9c; /* 0085: bany a8, a3, 9c <lmacSetTxFrame+0x68> */
  a8 = 0xF; /* 0088: movi.n a8, 15 */
  a3 = MEM8(a9 + 12); /* 008a: l8ui a3, a9, 12 */
  a3 = a3 + (-16); /* 008d: addi a3, a3, -16 */
  a3 = (a3 >> 0) & 0xFF; /* 0090: extui a3, a3, 0, 8 */
  if (a8 < a3) goto L_9c; /* 0093: bltu a8, a3, 9c <lmacSetTxFrame+0x68> */
L_96:;
  MEM16(a5 + 2) = a6; /* 0096: s16i a6, a5, 2 */
  MEMW(); /* 0099: memw  */
L_9c:;
  a5 = (uint32_t)&lmacConfMib; /* 009c: l32r a5, 4 <lmacSetTxFrame-0x30> (0 <lmacSetTxFrame-0x34>) */ /* literal @0x4: lmacConfMib */
  a3 = MEM8(a5 + 46); /* 009f: l8ui a3, a5, 46 */
  if (a3 == 0) goto L_cc; /* 00a2: beqz.n a3, cc <lmacSetTxFrame+0x98> */
  a3 = MEM8(a5 + 45); /* 00a4: l8ui a3, a5, 45 */
  a8 = MEM8(a9 + 12); /* 00a7: l8ui a8, a9, 12 */
  if (a3 == 0) goto L_bb; /* 00aa: beqz.n a3, bb <lmacSetTxFrame+0x87> */
  a8 = a8 + (-4); /* 00ac: addi a8, a8, -4 */
  a8 = (a8 >> 0) & 0xFF; /* 00af: extui a8, a8, 0, 8 */
  if (a8 >= 4) goto L_cc; /* 00b2: bgeui a8, 4, cc <lmacSetTxFrame+0x98> */
  MEMW(); /* 00b5: memw  */
  goto L_c6; /* 00b8: j c6 <lmacSetTxFrame+0x92> */
L_bb:;
  a3 = a8 + (-1); /* 00bb: addi.n a3, a8, -1 */
  a3 = (a3 >> 0) & 0xFF; /* 00bd: extui a3, a3, 0, 8 */
  if (a3 >= 3) goto L_cc; /* 00c0: bgeui a3, 3, cc <lmacSetTxFrame+0x98> */
  a8 = a8 + (4); /* 00c3: addi a8, a8, 4 */
L_c6:;
  MEM8(a9 + 12) = a8; /* 00c6: s8i a8, a9, 12 */
  MEMW(); /* 00c9: memw  */
L_cc:;
  a6 = (uint32_t)&g_mesh_is_started; /* 00cc: l32r a6, 8 <lmacSetTxFrame-0x2c> (0 <lmacSetTxFrame-0x34>) */ /* literal @0x8: g_mesh_is_started */
  a3 = MEM8(a6 + 0); /* 00cf: l8ui a3, a6, 0 */
  if (a3 == 0) goto L_fd; /* 00d2: beqz.n a3, fd <lmacSetTxFrame+0xc9> */
  a3 = (uint32_t)&g_mesh_is_root; /* 00d4: l32r a3, c <lmacSetTxFrame-0x28> (0 <lmacSetTxFrame-0x34>) */ /* literal @0xC: g_mesh_is_root */
  MEMW(); /* 00d7: memw  */
  a3 = MEM8(a3 + 0); /* 00da: l8ui a3, a3, 0 */
  a3 = (a3 >> 0) & 0xFF; /* 00dd: extui a3, a3, 0, 8 */
  if (a3 != 0) goto L_fd; /* 00e0: bnez.n a3, fd <lmacSetTxFrame+0xc9> */
  a3 = (uint32_t)&g_mesh_init_ps_type; /* 00e2: l32r a3, 10 <lmacSetTxFrame-0x24> (0 <lmacSetTxFrame-0x34>) */ /* literal @0x10: g_mesh_init_ps_type */
  a3 = MEM32(a3 + 0); /* 00e5: l32i.n a3, a3, 0 */
  if (a3 == 0) goto L_fd; /* 00e7: beqz.n a3, fd <lmacSetTxFrame+0xc9> */
  a3 = (uint32_t)&g_osi_funcs_p; /* 00e9: l32r a3, 14 <lmacSetTxFrame-0x20> (0 <lmacSetTxFrame-0x34>) */ /* literal @0x14: g_osi_funcs_p */
  a3 = MEM32(a3 + 0); /* 00ec: l32i a3, a3, 0 */
  a10 = MEM32(a3 + 272); /* 00ef: l32i a10, a3, 0x110 */
  MEMW(); /* 00f2: memw  */
  ((int32_t(*)())a10)(a2, a3, a4, a5); /* 00f5: callx8 a10 */ /* indirect */
  a3 = a10; /* 00f8: mov.n a3, a10 */
  goto L_10c; /* 00fa: j 10c <lmacSetTxFrame+0xd8> */
L_fd:;
  a3 = 0x3FF73C00; /* 00fd: l32r a3, 18 <lmacSetTxFrame-0x1c> (3ff73c00 <lmacTxFrame+0x3ff73b90>) */ /* MMIO base */ @0x18
  a8 = (uint32_t)&g_wifi_mac_time_delta; /* 0100: l32r a8, 1c <lmacSetTxFrame-0x18> (0 <lmacSetTxFrame-0x34>) */ /* literal @0x1C: g_wifi_mac_time_delta */
  MEMW(); /* 0103: memw  */
  a3 = REG32(0x3FF73C00); /* 0106: l32i.n a3, a3, 0 */ /* MMIO read: base 0x3FF73C00+0 */
  a8 = MEM32(a8 + 0); /* 0108: l32i.n a8, a8, 0 */
  a3 = a3 + a8; /* 010a: add.n a3, a3, a8 */
L_10c:;
  a6 = MEM8(a6 + 0); /* 010c: l8ui a6, a6, 0 */
  a8 = MEM32(a4 + 44); /* 010f: l32i.n a8, a4, 44 */
  if (a6 == 0) goto L_12c; /* 0111: beqz.n a6, 12c <lmacSetTxFrame+0xf8> */
  a10 = MEM32(a8 + 24); /* 0113: l32i.n a10, a8, 24 */
  a10 = a3 - a10; /* 0115: sub a10, a3, a10 */
  a10 = a10 >> (10 & 31); /* 0118: srli a10, a10, 10 */
  a11 = MEM32(a5 + 8); /* 011b: l32i.n a11, a5, 8 */
  a10 = a11 - a10; /* 011d: sub a10, a11, a10 */
  if (a11 < a10) goto L_168; /* 0120: bltu a11, a10, 168 <lmacSetTxFrame+0x134> */
  a11 = 0x1; /* 0123: movi.n a11, 1 */
  /* 0125: maxu a11, a10, a11 */ /* UNMODELED: a11 clobbered */
  goto L_168; /* 0128: j 168 <lmacSetTxFrame+0x134> */
  /* 012b: .byte 00 */
L_12c:;
  a6 = MEM32(a8 + 0); /* 012c: l32i.n a6, a8, 0 */
  if (!((a6 >> 22) & 1)) goto L_136; /* 012e: bbci a6, 22, 136 <lmacSetTxFrame+0x102> */
  a8 = MEM32(a5 + 0); /* 0131: l32i.n a8, a5, 0 */
  goto L_138; /* 0133: j 138 <lmacSetTxFrame+0x104> */
L_136:;
  a8 = MEM32(a5 + 8); /* 0136: l32i.n a8, a5, 8 */
L_138:;
  a10 = a4; /* 0138: mov.n a10, a4 */
  a8 = a8 << (10 & 31); /* 013a: slli a8, a8, 10 */
  a11 = a3; /* 013d: mov.n a11, a3 */
  a12 = a1; /* 013f: mov.n a12, a1 */
  MEM32(a1 + 0) = a8; /* 0141: s32i a8, a1, 0 */
  MEMW(); /* 0144: memw  */
  a8 = (uint32_t)&ppProcessLifeTime; /* 0147: l32r a8, 28 <lmacSetTxFrame-0xc> (0 <lmacSetTxFrame-0x34>) */ /* literal: GOT slot for ppProcessLifeTime */
  ppProcessLifeTime(a2, a3, a4, a5); /* call via literal slot */ /* 014a: callx8 a8 */
  a11 = 0xA; /* 014d: movi.n a11, 10 */
  a4 = MEM32(a4 + 44); /* 014f: l32i.n a4, a4, 44 */
  a5 = MEM32(a1 + 0); /* 0151: l32i.n a5, a1, 0 */
  a10 = MEM32(a4 + 24); /* 0153: l32i.n a10, a4, 24 */
  a10 = a5 + a10; /* 0155: add.n a10, a5, a10 */
  a10 = a10 - a3; /* 0157: sub a10, a10, a3 */
  if (a10 >= a5) goto L_168; /* 015a: bgeu a10, a5, 168 <lmacSetTxFrame+0x134> */
  /* 015d: ssr a11 */ /* UNMODELED: a11 clobbered */
  /* 0160: srl a11, a10 */ /* UNMODELED: a11 clobbered */
  a3 = 0x1; /* 0163: movi.n a3, 1 */
  /* 0165: maxu a11, a11, a3 */ /* UNMODELED: a11 clobbered */
L_168:;
  a10 = a2; /* 0168: mov.n a10, a2 */
  a8 = (uint32_t)&hal_mac_tx_config_timeout; /* 016a: l32r a8, 2c <lmacSetTxFrame-0x8> (0 <lmacSetTxFrame-0x34>) */ /* literal: GOT slot for hal_mac_tx_config_timeout */
  hal_mac_tx_config_timeout(a2, a3, a4, a5); /* call via literal slot */ /* 016d: callx8 a8 */
  a3 = (uint32_t)&pTxRx; /* 0170: l32r a3, 20 <lmacSetTxFrame-0x14> (0 <lmacSetTxFrame-0x34>) */ /* literal @0x20: pTxRx */
  a10 = a2; /* 0173: mov.n a10, a2 */
  a11 = MEM32(a3 + 0); /* 0175: l32i.n a11, a3, 0 */
  a8 = (uint32_t)&hal_mac_tx_set_ppdu; /* 0177: l32r a8, 30 <lmacSetTxFrame-0x4> (0 <lmacSetTxFrame-0x34>) */ /* literal: GOT slot for hal_mac_tx_set_ppdu */
  hal_mac_tx_set_ppdu(a2, a3, a4, a5); /* call via literal slot */ /* 017a: callx8 a8 */
  return (int32_t)a2; /* 017d: retw.n  */
  /* 017f: .byte 00 */
L_180:;
  a2 = 0x0; /* 0180: movi.n a2, 0 */
  MEMW(); /* 0182: memw  */
  a2 = MEM32(a2 + 44); /* 0185: l32i.n a2, a2, 44 */
  /* 0187: break 1, 15 */
}

/* lmacSetAcParam @ lmac.o 00000004 size 80B bind GLOBAL
 * Calls: none | Data refs: .bss.our_instances
 *   MMIO: none
 *   funcdb v3: 0 call(s), 1 ref(s); disasm: 0 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t lmacSetAcParam(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.lmacSetAcParam; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a2 = (a2 >> 0) & 0xFF; /* 0007: extui a2, a2, 0, 8 */
  a10 = (uint32_t)&bss_our_instances; /* 000a: l32r a10, 0 <lmacSetAcParam-0x4> (0 <lmacSetAcParam-0x4>) */ /* literal @0x0: .bss.our_instances */
  a8 = (a2 << 8) + a2; /* 000d: addx8 a8, a2, a2 */
  a8 = (a8 << 4) + a10; /* 0010: addx4 a8, a8, a10 */
  a4 = (a4 >> 0) & 0xFF; /* 0013: extui a4, a4, 0, 8 */
  a5 = (a5 >> 0) & 0xFF; /* 0016: extui a5, a5, 0, 8 */
  a11 = MEM8(a8 + 8); /* 0019: l8ui a11, a8, 8 */
  a9 = a2 << (3 & 31); /* 001c: slli a9, a2, 3 */
  MEM8(a8 + 5) = a3; /* 001f: s8i a3, a8, 5 */
  MEM8(a8 + 9) = a4; /* 0022: s8i a4, a8, 9 */
  MEM8(a8 + 10) = a5; /* 0025: s8i a5, a8, 10 */
  MEMW(); /* 0028: memw  */
  if (a5 >= a11) goto L_3c; /* 002b: bgeu a5, a11, 3c <lmacSetAcParam+0x38> */
  MEM8(a8 + 8) = a5; /* 002e: s8i a5, a8, 8 */
  MEMW(); /* 0031: memw  */
  MEMW(); /* 0034: memw  */
  goto L_42; /* 0037: j 42 <lmacSetAcParam+0x3e> */
  /* 003a: .byte 00 */
  /* 003b: .byte 00 */
L_3c:;
  if (a11 >= a4) goto L_42; /* 003c: bgeu a11, a4, 42 <lmacSetAcParam+0x3e> */
  MEM8(a8 + 8) = a4; /* 003f: s8i a4, a8, 8 */
L_42:;
  a9 = a9 + a2; /* 0042: add.n a9, a9, a2 */
  a9 = (a9 << 4) + a10; /* 0044: addx4 a9, a9, a10 */
  a2 = 0x0; /* 0047: movi.n a2, 0 */
  MEM16(a9 + 24) = a2; /* 0049: s16i a2, a9, 24 */
  MEMW(); /* 004c: memw  */
  MEMW(); /* 004f: memw  */
  return (int32_t)a2; /* 0052: retw.n  */
}

/* lmacInitAc @ lmac.o 00000004 size 61B bind GLOBAL
 * Calls: none | Data refs: .bss.our_instances
 *   MMIO: none
 *   funcdb v3: 0 call(s), 1 ref(s); disasm: 0 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t lmacInitAc(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.lmacInitAc; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a2 = (a2 >> 0) & 0xFF; /* 0007: extui a2, a2, 0, 8 */
  a9 = (uint32_t)&bss_our_instances; /* 000a: l32r a9, 0 <lmacInitAc-0x4> (0 <lmacInitAc-0x4>) */ /* literal @0x0: .bss.our_instances */
  a8 = (a2 << 8) + a2; /* 000d: addx8 a8, a2, a2 */
  a8 = (a8 << 4) + a9; /* 0010: addx4 a8, a8, a9 */
  a4 = (a4 >> 0) & 0xFF; /* 0013: extui a4, a4, 0, 8 */
  a9 = 0x0; /* 0016: movi.n a9, 0 */
  MEM8(a8 + 4) = a2; /* 0018: s8i a2, a8, 4 */
  a2 = 0x0; /* 001b: movi.n a2, 0 */
  MEM8(a8 + 5) = a3; /* 001d: s8i a3, a8, 5 */
  MEM8(a8 + 9) = a4; /* 0020: s8i a4, a8, 9 */
  MEM8(a8 + 10) = a5; /* 0023: s8i a5, a8, 10 */
  MEM8(a8 + 8) = a4; /* 0026: s8i a4, a8, 8 */
  MEM16(a8 + 24) = a9; /* 0029: s16i a9, a8, 24 */
  MEM8(a8 + 11) = a9; /* 002c: s8i a9, a8, 11 */
  MEM8(a8 + 12) = a9; /* 002f: s8i a9, a8, 12 */
  MEM8(a8 + 18) = a9; /* 0032: s8i a9, a8, 18 */
  MEMW(); /* 0035: memw  */
  MEM32(a8 + 28) = a2; /* 0038: s32i.n a2, a8, 28 */
  MEM32(a8 + 32) = a2; /* 003a: s32i.n a2, a8, 32 */
  MEMW(); /* 003c: memw  */
  return (int32_t)a2; /* 003f: retw.n  */
}

/* lmacInit @ lmac.o 00000028 size 160B bind GLOBAL
 * Calls: RC_SetBasicRate, lmacInitAc, rcAttach | Data refs: RC_SetBasicRate, lmacConfMib, lmacInitAc, rcAttach
 *   MMIO: none
 *   funcdb v3: 3 call(s), 4 ref(s); disasm: 7 call(s), 4 data ref(s)
 * Fidelity: medium - 64 instr, 0 branches, calls resolved */
int32_t lmacInit(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.lmacInit; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_28:;
  /* 0028: entry a1, 32 */
  a8 = (uint32_t)&lmacConfMib; /* 002b: l32r a8, 0 <lmacInit-0x28> (0 <lmacInit-0x28>) */ /* literal @0x0: lmacConfMib */
  a9 = 0x9; /* 002e: movi.n a9, 9 */
  a14 = 0x0; /* 0030: movi.n a14, 0 */
  a13 = 0xA; /* 0032: movi.n a13, 10 */
  a12 = 0x4; /* 0034: movi.n a12, 4 */
  MEM16(a8 + 28) = a9; /* 0036: s16i a9, a8, 28 */
  MEMW(); /* 0039: memw  */
  a9 = 0x600; /* 003c: movi a9, 0x600 */
  a11 = 0x3; /* 003f: movi.n a11, 3 */
  a10 = 0x2; /* 0041: movi.n a10, 2 */
  MEM32(a8 + 0) = a9; /* 0043: s32i.n a9, a8, 0 */
  a9 = 0x400; /* 0045: movi a9, 0x400 */
  MEM32(a8 + 4) = a9; /* 0048: s32i.n a9, a8, 4 */
  MEM32(a8 + 8) = a9; /* 004a: s32i.n a9, a8, 8 */
  a9 = 0x200; /* 004c: movi a9, 0x200 */
  MEM32(a8 + 12) = a9; /* 004f: s32i.n a9, a8, 12 */
  MEM32(a8 + 16) = a9; /* 0051: s32i.n a9, a8, 16 */
  a9 = 0x92A2020; /* 0053: l32r a9, 4 <lmacInit-0x24> (92a2020 <lmacTxFrame+0x92a1fb0>) */ @0x4
  MEM32(a8 + 20) = a9; /* 0056: s32i.n a9, a8, 20 */
  a9 = 0x100; /* 0058: movi a9, 0x100 */
  MEM16(a8 + 24) = a9; /* 005b: s16i a9, a8, 24 */
  MEMW(); /* 005e: memw  */
  a9 = 0xFFF015F; /* 0061: l32r a9, 8 <lmacInit-0x20> (fff015f <lmacTxFrame+0xfff00ef>) */ @0x8
  MEM32(a8 + 36) = a9; /* 0064: s32i a9, a8, 36 */
  MEMW(); /* 0067: memw  */
  a8 = (uint32_t)&lmacInitAc; /* 006a: l32r a8, c <lmacInit-0x1c> (0 <lmacInit-0x28>) */ /* literal: GOT slot for lmacInitAc */
  lmacInitAc(a2, a3, a4, a5); /* call via literal slot */ /* 006d: callx8 a8 */
  a14 = 0x0; /* 0070: movi.n a14, 0 */
  a13 = 0xA; /* 0072: movi.n a13, 10 */
  a12 = 0x4; /* 0074: movi.n a12, 4 */
  a11 = 0x7; /* 0076: movi.n a11, 7 */
  a10 = 0x3; /* 0078: movi a10, 3 */
  a8 = (uint32_t)&lmacInitAc; /* 007b: l32r a8, 10 <lmacInit-0x18> (0 <lmacInit-0x28>) */ /* literal: GOT slot for lmacInitAc */
  lmacInitAc(a2, a3, a4, a5); /* call via literal slot */ /* 007e: callx8 a8 */
  a14 = 0x2F; /* 0081: movi.n a14, 47 */
  a14 = 0xBC0; /* 0083: slli a14, a14, 6 */
  a13 = 0x4; /* 0086: movi.n a13, 4 */
  a12 = 0x3; /* 0088: movi.n a12, 3 */
  a11 = 0x2; /* 008a: movi.n a11, 2 */
  a10 = 0x1; /* 008c: movi.n a10, 1 */
  a8 = (uint32_t)&lmacInitAc; /* 008e: l32r a8, 14 <lmacInit-0x14> (0 <lmacInit-0x28>) */ /* literal: GOT slot for lmacInitAc */
  lmacInitAc(a2, a3, a4, a5); /* call via literal slot */ /* 0091: callx8 a8 */
  a12 = 0x2; /* 0094: movi.n a12, 2 */
  a11 = 0x2; /* 0096: mov.n a11, a12 */
  a14 = 0x5E0; /* 0098: movi a14, 0x5e0 */
  a13 = 0x3; /* 009b: movi.n a13, 3 */
  a10 = 0x0; /* 009d: movi.n a10, 0 */
  a8 = (uint32_t)&lmacInitAc; /* 009f: l32r a8, 18 <lmacInit-0x10> (0 <lmacInit-0x28>) */ /* literal: GOT slot for lmacInitAc */
  lmacInitAc(a2, a3, a4, a5); /* call via literal slot */ /* 00a2: callx8 a8 */
  a14 = 0x0; /* 00a5: movi.n a14, 0 */
  a13 = 0x0; /* 00a7: mov.n a13, a14 */
  a12 = 0x0; /* 00a9: mov.n a12, a14 */
  a11 = 0x1; /* 00ab: movi.n a11, 1 */
  a10 = 0x4; /* 00ad: movi.n a10, 4 */
  a8 = (uint32_t)&lmacInitAc; /* 00af: l32r a8, 1c <lmacInit-0xc> (0 <lmacInit-0x28>) */ /* literal: GOT slot for lmacInitAc */
  lmacInitAc(a2, a3, a4, a5); /* call via literal slot */ /* 00b2: callx8 a8 */
  a11 = 0x1; /* 00b5: movi.n a11, 1 */
  a10 = 0x15F; /* 00b7: movi a10, 0x15f */
  a8 = (uint32_t)&RC_SetBasicRate; /* 00ba: l32r a8, 20 <lmacInit-0x8> (0 <lmacInit-0x28>) */ /* literal: GOT slot for RC_SetBasicRate */
  RC_SetBasicRate(a2, a3, a4, a5); /* call via literal slot */ /* 00bd: callx8 a8 */
  a8 = (uint32_t)&rcAttach; /* 00c0: l32r a8, 24 <lmacInit-0x4> (0 <lmacInit-0x28>) */ /* literal: GOT slot for rcAttach */
  rcAttach(a2, a3, a4, a5); /* call via literal slot */ /* 00c3: callx8 a8 */
  return (int32_t)a2; /* 00c6: retw.n  */
}

/* lmacProcessTxopSuccess @ lmac.o 0000001c size 120B bind GLOBAL
 * Calls: wifi_assert | Data refs: .bss.our_instances, .rodata.__FUNCTION__$14, .rodata.lmacProcessTxopSuccess.str1.1, wifi_assert
 *   MMIO: none
 *   funcdb v3: 1 call(s), 4 ref(s); disasm: 4 call(s), 4 data ref(s)
 * Fidelity: medium - 46 instr, 3 branches, calls resolved */
int32_t lmacProcessTxopSuccess(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.lmacProcessTxopSuccess; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_1c:;
  /* 001c: entry a1, 32 */
  a2 = (a2 >> 0) & 0xFF; /* 001f: extui a2, a2, 0, 8 */
  if (a2 != 10) goto L_2c; /* 0022: bnei a2, 10, 2c <lmacProcessTxopSuccess+0x10> */
  a2 = 0x0; /* 0025: movi.n a2, 0 */
  goto L_8c; /* 0027: j 8c <lmacProcessTxopSuccess+0x70> */
  /* 002a: .byte 00 */
  /* 002b: .byte 00 */
L_2c:;
  a4 = (uint32_t)&lit_rodata_FUNCTION_14; /* 002c: l32r a4, 0 <lmacProcessTxopSuccess-0x1c> (0 <lmacProcessTxopSuccess-0x1c>) */ /* literal @0x0: .rodata.__FUNCTION__$14 */
  a10 = 0x1; /* 002f: movi.n a10, 1 */
  a3 = (uint32_t)&lit_rodata_lmacProcessTxopSuccess_str1_1; /* 0031: l32r a3, 4 <lmacProcessTxopSuccess-0x18> (0 <lmacProcessTxopSuccess-0x1c>) */ /* literal @0x4: .rodata.lmacProcessTxopSuccess.str1.1 */
  if (a2 < 5) goto L_39; /* 0034: bltui a2, 5, 39 <lmacProcessTxopSuccess+0x1d> */
  a10 = 0x0; /* 0037: movi.n a10, 0 */
L_39:;
  a13 = 0x27B; /* 0039: movi a13, 0x27b */
  a12 = a4 | a4; /* 003c: or a12, a4, a4 */
  a11 = a3 | a3; /* 003f: or a11, a3, a3 */
  a8 = (uint32_t)&wifi_assert; /* 0042: l32r a8, c <lmacProcessTxopSuccess-0x10> (0 <lmacProcessTxopSuccess-0x1c>) */ /* literal: GOT slot for wifi_assert */
  wifi_assert(a2, a3, a4, a5); /* call via literal slot */ /* 0045: callx8 a8 */
  a5 = (uint32_t)&bss_our_instances; /* 0048: l32r a5, 8 <lmacProcessTxopSuccess-0x14> (0 <lmacProcessTxopSuccess-0x1c>) */ /* literal @0x8: .bss.our_instances */
  a2 = (a2 << 8) + a2; /* 004b: addx8 a2, a2, a2 */
  a2 = (a2 << 4) + a5; /* 004e: addx4 a2, a2, a5 */
  a5 = 0x1; /* 0051: movi.n a5, 1 */
  a13 = 0x27E; /* 0053: movi a13, 0x27e */
  a8 = MEM8(a2 + 18); /* 0056: l8ui a8, a2, 18 */
  a2 = 0x0; /* 0059: movi.n a2, 0 */
  a8 = a8 + (-2); /* 005b: addi a8, a8, -2 */
  a10 = 0x0; /* 005e: mov.n a10, a2 */
  if (a8 == 0) a10 = a5; /* 0060: moveqz a10, a5, a8 */
  a12 = a4; /* 0063: mov.n a12, a4 */
  a11 = a3; /* 0065: mov.n a11, a3 */
  a8 = (uint32_t)&wifi_assert; /* 0067: l32r a8, 10 <lmacProcessTxopSuccess-0xc> (0 <lmacProcessTxopSuccess-0x1c>) */ /* literal: GOT slot for wifi_assert */
  wifi_assert(a2, a3, a4, a5); /* call via literal slot */ /* 006a: callx8 a8 */
  a13 = 0x27F; /* 006d: movi a13, 0x27f */
  a12 = a4; /* 0070: mov.n a12, a4 */
  a11 = a3; /* 0072: mov.n a11, a3 */
  a10 = a5 | a5; /* 0074: or a10, a5, a5 */
  a8 = (uint32_t)&wifi_assert; /* 0077: l32r a8, 14 <lmacProcessTxopSuccess-0x8> (0 <lmacProcessTxopSuccess-0x1c>) */ /* literal: GOT slot for wifi_assert */
  wifi_assert(a2, a3, a4, a5); /* call via literal slot */ /* 007a: callx8 a8 */
  a13 = 0x280; /* 007d: movi a13, 0x280 */
  a12 = a4; /* 0080: mov.n a12, a4 */
  a11 = a3; /* 0082: mov.n a11, a3 */
  a10 = a2; /* 0084: mov.n a10, a2 */
  a8 = (uint32_t)&wifi_assert; /* 0086: l32r a8, 18 <lmacProcessTxopSuccess-0x4> (0 <lmacProcessTxopSuccess-0x1c>) */ /* literal: GOT slot for wifi_assert */
  wifi_assert(a2, a3, a4, a5); /* call via literal slot */ /* 0089: callx8 a8 */
L_8c:;
  MEMW(); /* 008c: memw  */
  a2 = MEM32(a2 + 44); /* 008f: l32i.n a2, a2, 44 */
  /* 0091: break 1, 15 */
  /* no retw observed; falls through */
  return (int32_t)a2;
}

/* GetAccess @ lmac.o 00000004 size 17B bind GLOBAL
 * Calls: none | Data refs: .bss.our_instances
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t GetAccess(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .wifi0iram.7; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a8 = (uint32_t)&bss_our_instances; /* 0007: l32r a8, 0 <GetAccess-0x4> (0 <GetAccess-0x4>) */ /* literal @0x0: .bss.our_instances */
  a2 = (a2 >> 0) & 0xFF; /* 000a: extui a2, a2, 0, 8 */
  a2 = (a2 << 8) + a2; /* 000d: addx8 a2, a2, a2 */
  a2 = (a2 << 4) + a8; /* 0010: addx4 a2, a2, a8 */
  return (int32_t)a2; /* 0013: retw.n  */
}

/* lmacEndRetryAMPDUFail @ lmac.o 00000014 size 122B bind GLOBAL
 * Calls: ppFillAMPDUBar, ppReSendBar, ppRecordBarRRC, ppRegressAmpdu, trc_isTxAmpduOperational | Data refs: ppFillAMPDUBar, ppReSendBar, ppRecordBarRRC, ppRegressAmpdu, trc_isTxAmpduOperational
 *   MMIO: none
 *   funcdb v3: 5 call(s), 5 ref(s); disasm: 5 call(s), 5 data ref(s)
 * Fidelity: medium - 46 instr, 3 branches, calls resolved */
int32_t lmacEndRetryAMPDUFail(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.lmacEndRetryAMPDUFail; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_14:;
  /* 0014: entry a1, 32 */
  a4 = 0x0; /* 0017: movi a4, 0 */
  MEM8(a2 + 18) = a4; /* 001a: s8i a4, a2, 18 */
  MEMW(); /* 001d: memw  */
  a10 = MEM32(a3 + 36); /* 0020: l32i a10, a3, 36 */
  MEMW(); /* 0023: memw  */
  a8 = (uint32_t)&trc_isTxAmpduOperational; /* 0026: l32r a8, 0 <lmacEndRetryAMPDUFail-0x14> (0 <lmacEndRetryAMPDUFail-0x14>) */ /* literal: GOT slot for trc_isTxAmpduOperational */
  trc_isTxAmpduOperational(a2, a3, a4, a5); /* call via literal slot */ /* 0029: callx8 a8 */
  if (a10 == 0) goto L_77; /* 002c: beqz a10, 77 <lmacEndRetryAMPDUFail+0x63> */
  a8 = MEM32(a3 + 44); /* 002f: l32i.n a8, a3, 44 */
  a4 = MEM32(a3 + 4); /* 0031: l32i.n a4, a3, 4 */
  a9 = MEM32(a8 + 0); /* 0033: l32i.n a9, a8, 0 */
  a4 = MEM32(a4 + 4); /* 0035: l32i.n a4, a4, 4 */
  if (!((a9 >> 18) & 1)) goto L_3c; /* 0037: bbci a9, 18, 3c <lmacEndRetryAMPDUFail+0x28> */
  a4 = a4 + (4); /* 003a: addi.n a4, a4, 4 */
L_3c:;
  a11 = 0x1; /* 003c: movi.n a11, 1 */
  a10 = MEM32(a8 + 16); /* 003e: l32i.n a10, a8, 16 */
  a10 = (a10 >> 20) & 0xF; /* 0040: extui a10, a10, 20, 4 */
  a8 = (uint32_t)&ppRecordBarRRC; /* 0043: l32r a8, 4 <lmacEndRetryAMPDUFail-0x10> (0 <lmacEndRetryAMPDUFail-0x14>) */ /* literal: GOT slot for ppRecordBarRRC */
  ppRecordBarRRC(a2, a3, a4, a5); /* call via literal slot */ /* 0046: callx8 a8 */
  a11 = a4 + (4); /* 0049: addi.n a11, a4, 4 */
  a8 = MEM32(a3 + 44); /* 004b: l32i.n a8, a3, 44 */
  a12 = a4 + (10); /* 004d: addi a12, a4, 10 */
  a13 = MEM16(a4 + 22); /* 0050: l16ui a13, a4, 22 */
  a13 = a13 >> (4 & 31); /* 0053: srli a13, a13, 4 */
  a10 = MEM32(a8 + 4); /* 0056: l32i a10, a8, 4 */
  a10 = (a10 >> 0) & 0xF; /* 0059: extui a10, a10, 0, 4 */
  a8 = (uint32_t)&ppFillAMPDUBar; /* 005c: l32r a8, 8 <lmacEndRetryAMPDUFail-0xc> (0 <lmacEndRetryAMPDUFail-0x14>) */ /* literal: GOT slot for ppFillAMPDUBar */
  ppFillAMPDUBar(a2, a3, a4, a5); /* call via literal slot */ /* 005f: callx8 a8 */
  a3 = MEM32(a3 + 44); /* 0062: l32i.n a3, a3, 44 */
  a11 = MEM32(a3 + 16); /* 0064: l32i.n a11, a3, 16 */
  a11 = (a11 >> 20) & 0xF; /* 0066: extui a11, a11, 20, 4 */
  a10 = MEM32(a3 + 4); /* 0069: l32i.n a10, a3, 4 */
  a10 = (a10 >> 0) & 0xF; /* 006b: extui a10, a10, 0, 4 */
  a8 = (uint32_t)&ppReSendBar; /* 006e: l32r a8, c <lmacEndRetryAMPDUFail-0x8> (0 <lmacEndRetryAMPDUFail-0x14>) */ /* literal: GOT slot for ppReSendBar */
  ppReSendBar(a2, a3, a4, a5); /* call via literal slot */ /* 0071: callx8 a8 */
  goto L_81; /* 0074: j 81 <lmacEndRetryAMPDUFail+0x6d> */
L_77:;
  a11 = 0x1; /* 0077: movi.n a11, 1 */
  a10 = a3; /* 0079: mov.n a10, a3 */
  a8 = (uint32_t)&ppRegressAmpdu; /* 007b: l32r a8, 10 <lmacEndRetryAMPDUFail-0x4> (0 <lmacEndRetryAMPDUFail-0x14>) */ /* literal: GOT slot for ppRegressAmpdu */
  ppRegressAmpdu(a2, a3, a4, a5); /* call via literal slot */ /* 007e: callx8 a8 */
L_81:;
  a3 = 0x8; /* 0081: movi.n a3, 8 */
  MEM8(a2 + 19) = a3; /* 0083: s8i a3, a2, 19 */
  MEMW(); /* 0086: memw  */
  MEMW(); /* 0089: memw  */
  return (int32_t)a2; /* 008c: retw.n  */
}

/* lmacProcessCollisions @ lmac.o 00000004 size 15B bind GLOBAL
 * Calls: pp_post[got] | Data refs: pp_post
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 1 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t lmacProcessCollisions(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .iram1.12; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a11 = 0x0; /* 0007: movi.n a11, 0 */
  a10 = 0x18; /* 0009: movi.n a10, 24 */
  a8 = (uint32_t)&pp_post; /* 000b: l32r a8, 0 <lmacProcessCollisions-0x4> (0 <lmacProcessCollisions-0x4>) */ /* literal: GOT slot for pp_post */
  pp_post(a2, a3, a4, a5); /* call via literal slot */ /* 000e: callx8 a8 */
  return (int32_t)a2; /* 0011: retw.n  */
}

/* lmacProcessAllTxTimeout @ lmac.o 00000004 size 15B bind GLOBAL
 * Calls: pp_post[got] | Data refs: pp_post
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 1 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t lmacProcessAllTxTimeout(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .iram1.13; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a11 = 0x0; /* 0007: movi.n a11, 0 */
  a10 = 0x16; /* 0009: movi.n a10, 22 */
  a8 = (uint32_t)&pp_post; /* 000b: l32r a8, 0 <lmacProcessAllTxTimeout-0x4> (0 <lmacProcessAllTxTimeout-0x4>) */ /* literal: GOT slot for pp_post */
  pp_post(a2, a3, a4, a5); /* call via literal slot */ /* 000e: callx8 a8 */
  return (int32_t)a2; /* 0011: retw.n  */
}

/* lmacPostTxComplete @ lmac.o 00000004 size 15B bind GLOBAL
 * Calls: pp_post[got] | Data refs: pp_post
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 1 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t lmacPostTxComplete(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .iram1.14; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a11 = 0x0; /* 0007: movi.n a11, 0 */
  a10 = 0x17; /* 0009: movi.n a10, 23 */
  a8 = (uint32_t)&pp_post; /* 000b: l32r a8, 0 <lmacPostTxComplete-0x4> (0 <lmacPostTxComplete-0x4>) */ /* literal: GOT slot for pp_post */
  pp_post(a2, a3, a4, a5); /* call via literal slot */ /* 000e: callx8 a8 */
  return (int32_t)a2; /* 0011: retw.n  */
}

/* lmacProcessRxSucData @ lmac.o 0000001c size 75B bind GLOBAL
 * Calls: pp_post[got] | Data refs: g_mesh_is_started, g_mesh_is_root, g_mesh_init_ps_type, g_osi_funcs_p, g_wifi_mac_time_delta, pp_post
 *   MMIO: 0x3FF73C00
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 1 call(s), 6 data ref(s)
 * Fidelity: medium - 29 instr, 4 branches, calls resolved */
int32_t lmacProcessRxSucData(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .iram1.15; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_1c:;
  /* 001c: entry a1, 32 */
  a8 = (uint32_t)&g_mesh_is_started; /* 001f: l32r a8, 0 <lmacProcessRxSucData-0x1c> (0 <lmacProcessRxSucData-0x1c>) */ /* literal @0x0: g_mesh_is_started */
  a8 = MEM8(a8 + 0); /* 0022: l8ui a8, a8, 0 */
  if (a8 == 0) goto L_4c; /* 0025: beqz.n a8, 4c <lmacProcessRxSucData+0x30> */
  a8 = (uint32_t)&g_mesh_is_root; /* 0027: l32r a8, 4 <lmacProcessRxSucData-0x18> (0 <lmacProcessRxSucData-0x1c>) */ /* literal @0x4: g_mesh_is_root */
  MEMW(); /* 002a: memw  */
  a8 = MEM8(a8 + 0); /* 002d: l8ui a8, a8, 0 */
  a8 = (a8 >> 0) & 0xFF; /* 0030: extui a8, a8, 0, 8 */
  if (a8 != 0) goto L_4c; /* 0033: bnez.n a8, 4c <lmacProcessRxSucData+0x30> */
  a8 = (uint32_t)&g_mesh_init_ps_type; /* 0035: l32r a8, 8 <lmacProcessRxSucData-0x14> (0 <lmacProcessRxSucData-0x1c>) */ /* literal @0x8: g_mesh_init_ps_type */
  a8 = MEM32(a8 + 0); /* 0038: l32i.n a8, a8, 0 */
  if (a8 == 0) goto L_4c; /* 003a: beqz.n a8, 4c <lmacProcessRxSucData+0x30> */
  a8 = (uint32_t)&g_osi_funcs_p; /* 003c: l32r a8, c <lmacProcessRxSucData-0x10> (0 <lmacProcessRxSucData-0x1c>) */ /* literal @0xC: g_osi_funcs_p */
  a8 = MEM32(a8 + 0); /* 003f: l32i a8, a8, 0 */
  a10 = MEM32(a8 + 272); /* 0042: l32i a10, a8, 0x110 */
  ((int32_t(*)())a10)(a2, a3, a4, a5); /* 0045: callx8 a10 */ /* indirect */
  goto L_5b; /* 0048: j 5b <lmacProcessRxSucData+0x3f> */
  /* 004b: .byte 00 */
L_4c:;
  a8 = 0x3FF73C00; /* 004c: l32r a8, 10 <lmacProcessRxSucData-0xc> (3ff73c00 <lmacTxFrame+0x3ff73b90>) */ /* MMIO base */ @0x10
  MEMW(); /* 004f: memw  */
  a10 = REG32(0x3FF73C00); /* 0052: l32i.n a10, a8, 0 */ /* MMIO read: base 0x3FF73C00+0 */
  a8 = (uint32_t)&g_wifi_mac_time_delta; /* 0054: l32r a8, 14 <lmacProcessRxSucData-0x8> (0 <lmacProcessRxSucData-0x1c>) */ /* literal @0x14: g_wifi_mac_time_delta */
  a8 = MEM32(a8 + 0); /* 0057: l32i.n a8, a8, 0 */
  a10 = a10 + a8; /* 0059: add.n a10, a10, a8 */
L_5b:;
  a11 = a10; /* 005b: mov.n a11, a10 */
  a10 = 0x19; /* 005d: movi.n a10, 25 */
  a8 = (uint32_t)&pp_post; /* 005f: l32r a8, 18 <lmacProcessRxSucData-0x4> (0 <lmacProcessRxSucData-0x1c>) */ /* literal: GOT slot for pp_post */
  pp_post(a2, a3, a4, a5); /* call via literal slot */ /* 0062: callx8 a8 */
  return (int32_t)a2; /* 0065: retw.n  */
}

/* lmacMSDUAged @ lmac.o 00000020 size 130B bind GLOBAL
 * Calls: ppProcessLifeTime[got] | Data refs: g_mesh_is_started, g_mesh_is_root, g_mesh_init_ps_type, g_osi_funcs_p, g_wifi_mac_time_delta, lmacConfMib, ppProcessLifeTime
 *   MMIO: 0x3FF73C00
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 1 call(s), 7 data ref(s)
 * Fidelity: medium - 51 instr, 8 branches, calls resolved */
int32_t lmacMSDUAged(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .wifi0iram.18; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_20:;
  /* 0020: entry a1, 48 */
  a3 = (uint32_t)&g_mesh_is_started; /* 0023: l32r a3, 0 <lmacMSDUAged-0x20> (0 <lmacMSDUAged-0x20>) */ /* literal @0x0: g_mesh_is_started */
  a3 = MEM8(a3 + 0); /* 0026: l8ui a3, a3, 0 */
  if (a3 == 0) goto L_51; /* 0029: beqz.n a3, 51 <lmacMSDUAged+0x31> */
  a3 = (uint32_t)&g_mesh_is_root; /* 002b: l32r a3, 4 <lmacMSDUAged-0x1c> (0 <lmacMSDUAged-0x20>) */ /* literal @0x4: g_mesh_is_root */
  MEMW(); /* 002e: memw  */
  a3 = MEM8(a3 + 0); /* 0031: l8ui a3, a3, 0 */
  a3 = (a3 >> 0) & 0xFF; /* 0034: extui a3, a3, 0, 8 */
  if (a3 != 0) goto L_51; /* 0037: bnez.n a3, 51 <lmacMSDUAged+0x31> */
  a3 = (uint32_t)&g_mesh_init_ps_type; /* 0039: l32r a3, 8 <lmacMSDUAged-0x18> (0 <lmacMSDUAged-0x20>) */ /* literal @0x8: g_mesh_init_ps_type */
  a3 = MEM32(a3 + 0); /* 003c: l32i.n a3, a3, 0 */
  if (a3 == 0) goto L_51; /* 003e: beqz.n a3, 51 <lmacMSDUAged+0x31> */
  a3 = (uint32_t)&g_osi_funcs_p; /* 0040: l32r a3, c <lmacMSDUAged-0x14> (0 <lmacMSDUAged-0x20>) */ /* literal @0xC: g_osi_funcs_p */
  a3 = MEM32(a3 + 0); /* 0043: l32i a3, a3, 0 */
  a10 = MEM32(a3 + 272); /* 0046: l32i a10, a3, 0x110 */
  ((int32_t(*)())a10)(a2, a3, a4, a5); /* 0049: callx8 a10 */ /* indirect */
  a3 = a10; /* 004c: mov.n a3, a10 */
  goto L_60; /* 004e: j 60 <lmacMSDUAged+0x40> */
L_51:;
  a3 = 0x3FF73C00; /* 0051: l32r a3, 10 <lmacMSDUAged-0x10> (3ff73c00 <lmacTxFrame+0x3ff73b90>) */ /* MMIO base */ @0x10
  a8 = (uint32_t)&g_wifi_mac_time_delta; /* 0054: l32r a8, 14 <lmacMSDUAged-0xc> (0 <lmacMSDUAged-0x20>) */ /* literal @0x14: g_wifi_mac_time_delta */
  MEMW(); /* 0057: memw  */
  a3 = REG32(0x3FF73C00); /* 005a: l32i.n a3, a3, 0 */ /* MMIO read: base 0x3FF73C00+0 */
  a8 = MEM32(a8 + 0); /* 005c: l32i.n a8, a8, 0 */
  a3 = a3 + a8; /* 005e: add.n a3, a3, a8 */
L_60:;
  a8 = MEM32(a2 + 44); /* 0060: l32i.n a8, a2, 44 */
  a9 = MEM32(a8 + 0); /* 0062: l32i.n a9, a8, 0 */
  a8 = (uint32_t)&lmacConfMib; /* 0064: l32r a8, 18 <lmacMSDUAged-0x8> (0 <lmacMSDUAged-0x20>) */ /* literal @0x18: lmacConfMib */
  if (!((a9 >> 22) & 1)) goto L_70; /* 0067: bbci a9, 22, 70 <lmacMSDUAged+0x50> */
  a8 = MEM32(a8 + 0); /* 006a: l32i.n a8, a8, 0 */
  goto L_72; /* 006c: j 72 <lmacMSDUAged+0x52> */
  /* 006f: .byte 00 */
L_70:;
  a8 = MEM32(a8 + 8); /* 0070: l32i.n a8, a8, 8 */
L_72:;
  a8 = a8 << (10 & 31); /* 0072: slli a8, a8, 10 */
  a11 = a3; /* 0075: mov.n a11, a3 */
  a10 = a2; /* 0077: mov.n a10, a2 */
  a12 = a1; /* 0079: mov.n a12, a1 */
  MEM32(a1 + 0) = a8; /* 007b: s32i.n a8, a1, 0 */
  MEMW(); /* 007d: memw  */
  a8 = (uint32_t)&ppProcessLifeTime; /* 0080: l32r a8, 1c <lmacMSDUAged-0x4> (0 <lmacMSDUAged-0x20>) */ /* literal: GOT slot for ppProcessLifeTime */
  ppProcessLifeTime(a2, a3, a4, a5); /* call via literal slot */ /* 0083: callx8 a8 */
  a2 = MEM32(a2 + 44); /* 0086: l32i.n a2, a2, 44 */
  a2 = MEM32(a2 + 24); /* 0088: l32i.n a2, a2, 24 */
  a3 = a3 - a2; /* 008a: sub a3, a3, a2 */
  a2 = 0x1; /* 008d: movi.n a2, 1 */
  a8 = MEM32(a1 + 0); /* 008f: l32i.n a8, a1, 0 */
  if (a8 < a3) goto L_a0; /* 0091: bltu a8, a3, a0 <lmacMSDUAged+0x80> */
  a8 = a8 + ((0xffffec00) << 8); /* 0094: addmi a8, a8, 0xffffec00 */
  if (a8 < a3) goto L_9d; /* 0097: bltu a8, a3, 9d <lmacMSDUAged+0x7d> */
  a2 = 0x0; /* 009a: movi a2, 0 */
L_9d:;
  a2 = 0x0; /* 009d: extui a2, a2, 0, 8 */
L_a0:;
  return (int32_t)a2; /* 00a0: retw.n  */
}

/* dbg_cnt_lmac_drop @ lmac.o 0000000c size 129B bind GLOBAL
 * Calls: lmacMSDUAged[got] | Data refs: lmacConfMib, g_lmac_cnt, lmacMSDUAged
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 1 call(s), 3 data ref(s)
 * Fidelity: medium - 47 instr, 8 branches, calls resolved */
int32_t dbg_cnt_lmac_drop(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.lmacDebugTxDrop; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_c:;
  /* 000c: entry a1, 32 */
  a10 = a2; /* 000f: mov.n a10, a2 */
  if (a2 == 0) goto L_88; /* 0011: beqz a2, 88 <dbg_cnt_lmac_drop+0x7c> */
  a8 = MEM32(a2 + 44); /* 0014: l32i.n a8, a2, 44 */
  a3 = MEM32(a8 + 4); /* 0016: l32i.n a3, a8, 4 */
  a3 = (a3 >> 4) & 0xF; /* 0018: extui a3, a3, 4, 4 */
  if (a3 >= 5) goto L_88; /* 001b: bgei a3, 5, 88 <dbg_cnt_lmac_drop+0x7c> */
  a3 = a3 + (14); /* 001e: addi.n a3, a3, 14 */
  a9 = (uint32_t)&lmacConfMib; /* 0020: l32r a9, 0 <dbg_cnt_lmac_drop-0xc> (0 <dbg_cnt_lmac_drop-0xc>) */ /* literal @0x0: lmacConfMib */
  a12 = MEM8(a8 + 6); /* 0023: l8ui a12, a8, 6 */
  a11 = MEM8(a9 + 21); /* 0026: l8ui a11, a9, 21 */
  a4 = (uint32_t)&g_lmac_cnt; /* 0029: l32r a4, 4 <dbg_cnt_lmac_drop-0x8> (0 <dbg_cnt_lmac_drop-0xc>) */ /* literal @0x4: g_lmac_cnt */
  if (a12 < a11) goto L_44; /* 002c: bltu a12, a11, 44 <dbg_cnt_lmac_drop+0x38> */
  a3 = (a3 << 8) + a4; /* 002f: addx8 a3, a3, a4 */
  a4 = MEM8(a3 + 13); /* 0032: l8ui a4, a3, 13 */
  a4 = a4 + (1); /* 0035: addi.n a4, a4, 1 */
  MEM8(a3 + 13) = a4; /* 0037: s8i a4, a3, 13 */
  MEMW(); /* 003a: memw  */
  MEMW(); /* 003d: memw  */
  goto L_88; /* 0040: j 88 <dbg_cnt_lmac_drop+0x7c> */
  /* 0043: .byte 00 */
L_44:;
  a11 = MEM8(a8 + 7); /* 0044: l8ui a11, a8, 7 */
  a8 = MEM8(a9 + 20); /* 0047: l8ui a8, a9, 20 */
  if (a11 < a8) goto L_61; /* 004a: bltu a11, a8, 61 <dbg_cnt_lmac_drop+0x55> */
  a3 = (a3 << 8) + a4; /* 004d: addx8 a3, a3, a4 */
  a4 = MEM8(a3 + 12); /* 0050: l8ui a4, a3, 12 */
  a4 = a4 + (1); /* 0053: addi.n a4, a4, 1 */
  MEM8(a3 + 12) = a4; /* 0055: s8i a4, a3, 12 */
  MEMW(); /* 0058: memw  */
  MEMW(); /* 005b: memw  */
  goto L_88; /* 005e: j 88 <dbg_cnt_lmac_drop+0x7c> */
L_61:;
  a8 = (uint32_t)&lmacMSDUAged; /* 0061: l32r a8, 8 <dbg_cnt_lmac_drop-0x4> (0 <dbg_cnt_lmac_drop-0xc>) */ /* literal: GOT slot for lmacMSDUAged */
  lmacMSDUAged(a2, a3, a4, a5); /* call via literal slot */ /* 0064: callx8 a8 */
  a3 = (a3 << 8) + a4; /* 0067: addx8 a3, a3, a4 */
  if (a10 == 0) goto L_7d; /* 006a: beqz.n a10, 7d <dbg_cnt_lmac_drop+0x71> */
  a4 = MEM8(a3 + 14); /* 006c: l8ui a4, a3, 14 */
  a4 = a4 + (1); /* 006f: addi.n a4, a4, 1 */
  MEM8(a3 + 14) = a4; /* 0071: s8i a4, a3, 14 */
  MEMW(); /* 0074: memw  */
  MEMW(); /* 0077: memw  */
  goto L_88; /* 007a: j 88 <dbg_cnt_lmac_drop+0x7c> */
L_7d:;
  a4 = MEM8(a3 + 15); /* 007d: l8ui a4, a3, 15 */
  a4 = a4 + (1); /* 0080: addi.n a4, a4, 1 */
  MEM8(a3 + 15) = a4; /* 0082: s8i a4, a3, 15 */
  MEMW(); /* 0085: memw  */
L_88:;
  MEMW(); /* 0088: memw  */
  return (int32_t)a2; /* 008b: retw.n  */
}

/* esp_wifi_internal_set_retry_counter @ lmac.o 00000004 size 22B bind GLOBAL
 * Calls: none | Data refs: lmacConfMib
 *   MMIO: none
 *   funcdb v3: 0 call(s), 1 ref(s); disasm: 0 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t esp_wifi_internal_set_retry_counter(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.esp_wifi_internal_set_retry_counter; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a8 = (uint32_t)&lmacConfMib; /* 0007: l32r a8, 0 <esp_wifi_internal_set_retry_counter-0x4> (0 <esp_wifi_internal_set_retry_counter-0x4>) */ /* literal @0x0: lmacConfMib */
  MEM8(a8 + 21) = a2; /* 000a: s8i a2, a8, 21 */
  a2 = 0x0; /* 000d: movi.n a2, 0 */
  MEM8(a8 + 20) = a3; /* 000f: s8i a3, a8, 20 */
  MEMW(); /* 0012: memw  */
  MEMW(); /* 0015: memw  */
  return (int32_t)a2; /* 0018: retw.n  */
}

/* esp_wifi_internal_set_msdu_lifetime @ lmac.o 00000004 size 17B bind GLOBAL
 * Calls: none | Data refs: lmacConfMib
 *   MMIO: none
 *   funcdb v3: 0 call(s), 1 ref(s); disasm: 0 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t esp_wifi_internal_set_msdu_lifetime(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.esp_wifi_internal_set_msdu_lifetime; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a8 = (uint32_t)&lmacConfMib; /* 0007: l32r a8, 0 <esp_wifi_internal_set_msdu_lifetime-0x4> (0 <esp_wifi_internal_set_msdu_lifetime-0x4>) */ /* literal @0x0: lmacConfMib */
  MEM32(a8 + 16) = a2; /* 000a: s32i.n a2, a8, 16 */
  a2 = 0x0; /* 000c: movi.n a2, 0 */
  MEM32(a8 + 8) = a3; /* 000e: s32i.n a3, a8, 8 */
  MEMW(); /* 0010: memw  */
  return (int32_t)a2; /* 0013: retw.n  */
}

/* esp_wifi_internal_get_mib @ lmac.o 00000008 size 26B bind GLOBAL
 * Calls: memcpy | Data refs: lmacConfMib, memcpy
 *   MMIO: none
 *   funcdb v3: 1 call(s), 2 ref(s); disasm: 1 call(s), 2 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t esp_wifi_internal_get_mib(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.esp_wifi_internal_get_mib; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_8:;
  /* 0008: entry a1, 32 */
  a10 = a2; /* 000b: mov.n a10, a2 */
  a2 = 0x102; /* 000d: movi a2, 0x102 */
  if (a10 == 0) goto L_20; /* 0010: beqz.n a10, 20 <esp_wifi_internal_get_mib+0x18> */
  a11 = (uint32_t)&lmacConfMib; /* 0012: l32r a11, 0 <esp_wifi_internal_get_mib-0x8> (0 <esp_wifi_internal_get_mib-0x8>) */ /* literal @0x0: lmacConfMib */
  a12 = 0x30; /* 0015: movi a12, 48 */
  a8 = (uint32_t)&memcpy; /* 0018: l32r a8, 4 <esp_wifi_internal_get_mib-0x4> (0 <esp_wifi_internal_get_mib-0x8>) */ /* literal: GOT slot for memcpy */
  memcpy(a2, a3, a4, a5); /* call via literal slot */ /* 001b: callx8 a8 */
  a2 = 0x0; /* 001e: movi.n a2, 0 */
L_20:;
  return (int32_t)a2; /* 0020: retw.n  */
}

/* esp_wifi_internal_set_rts @ lmac.o 0000000c size 75B bind GLOBAL
 * Calls: wifi_log | Data refs: .rodata_wlog_info.21, lmacConfMib, wifi_log
 *   MMIO: none
 *   funcdb v3: 1 call(s), 3 ref(s); disasm: 1 call(s), 3 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t esp_wifi_internal_set_rts(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.esp_wifi_internal_set_rts; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_c:;
  /* 000c: entry a1, 48 */
  a8 = a2; /* 000f: mov.n a8, a2 */
  a2 = 0x102; /* 0011: movi a2, 0x102 */
  if (a8 == 0) goto L_55; /* 0014: beqz.n a8, 55 <esp_wifi_internal_set_rts+0x49> */
  a14 = MEM16(a8 + 0); /* 0016: l16ui a14, a8, 0 */
  a12 = 0x3; /* 0019: movi.n a12, 3 */
  a11 = 0x1; /* 001b: movi.n a11, 1 */
  a10 = 0x6; /* 001d: movi.n a10, 6 */
  a9 = (uint32_t)&lmacConfMib; /* 001f: l32r a9, 0 <esp_wifi_internal_set_rts-0xc> (0 <esp_wifi_internal_set_rts-0xc>) */ /* literal @0x0: lmacConfMib */
  MEM16(a9 + 22) = a14; /* 0022: s16i a14, a9, 22 */
  MEMW(); /* 0025: memw  */
  a15 = MEM8(a8 + 2); /* 0028: l8ui a15, a8, 2 */
  MEM8(a9 + 42) = a15; /* 002b: s8i a15, a9, 42 */
  MEMW(); /* 002e: memw  */
  a2 = MEM8(a8 + 3); /* 0031: l8ui a2, a8, 3 */
  MEM8(a9 + 43) = a2; /* 0034: s8i a2, a9, 43 */
  MEMW(); /* 0037: memw  */
  a8 = MEM8(a8 + 4); /* 003a: l8ui a8, a8, 4 */
  a13 = (uint32_t)&lit_rodata_wlog_info_21; /* 003d: l32r a13, 4 <esp_wifi_internal_set_rts-0x8> (0 <esp_wifi_internal_set_rts-0xc>) */ /* literal @0x4: .rodata_wlog_info.21 */
  MEM8(a9 + 44) = a8; /* 0040: s8i a8, a9, 44 */
  MEMW(); /* 0043: memw  */
  MEM32(a1 + 0) = a2; /* 0046: s32i.n a2, a1, 0 */
  a2 = 0x0; /* 0048: movi.n a2, 0 */
  MEM32(a1 + 4) = a8; /* 004a: s32i.n a8, a1, 4 */
  MEMW(); /* 004c: memw  */
  a8 = (uint32_t)&wifi_log; /* 004f: l32r a8, 8 <esp_wifi_internal_set_rts-0x4> (0 <esp_wifi_internal_set_rts-0xc>) */ /* literal: GOT slot for wifi_log */
  wifi_log(a2, a3, a4, a5); /* call via literal slot */ /* 0052: callx8 a8 */
L_55:;
  return (int32_t)a2; /* 0055: retw.n  */
}

/* esp_wifi_internal_get_rts @ lmac.o 00000004 size 57B bind GLOBAL
 * Calls: none | Data refs: lmacConfMib
 *   MMIO: none
 *   funcdb v3: 0 call(s), 1 ref(s); disasm: 0 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t esp_wifi_internal_get_rts(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.esp_wifi_internal_get_rts; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a8 = a2; /* 0007: mov.n a8, a2 */
  a2 = 0x102; /* 0009: movi a2, 0x102 */
  if (a8 == 0) goto L_38; /* 000c: beqz.n a8, 38 <esp_wifi_internal_get_rts+0x34> */
  a9 = (uint32_t)&lmacConfMib; /* 000e: l32r a9, 0 <esp_wifi_internal_get_rts-0x4> (0 <esp_wifi_internal_get_rts-0x4>) */ /* literal @0x0: lmacConfMib */
  a2 = MEM16(a9 + 22); /* 0011: l16ui a2, a9, 22 */
  MEM16(a8 + 0) = a2; /* 0014: s16i a2, a8, 0 */
  MEMW(); /* 0017: memw  */
  a2 = MEM8(a9 + 42); /* 001a: l8ui a2, a9, 42 */
  MEM8(a8 + 2) = a2; /* 001d: s8i a2, a8, 2 */
  MEMW(); /* 0020: memw  */
  a2 = MEM8(a9 + 43); /* 0023: l8ui a2, a9, 43 */
  MEM8(a8 + 3) = a2; /* 0026: s8i a2, a8, 3 */
  MEMW(); /* 0029: memw  */
  a2 = MEM8(a9 + 44); /* 002c: l8ui a2, a9, 44 */
  MEM8(a8 + 4) = a2; /* 002f: s8i a2, a8, 4 */
  MEMW(); /* 0032: memw  */
  a2 = 0x0; /* 0035: movi a2, 0 */
L_38:;
  MEMW(); /* 0038: memw  */
  return (int32_t)a2; /* 003b: retw.n  */
}

/* lmacAdjustTimestamp @ lmac.o 00000010 size 74B bind GLOBAL
 * Calls: none | Data refs: g_mesh_is_started, g_wifi_mac_time_delta, lmacConfMib
 *   MMIO: 0x3FF73C00
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 3 data ref(s)
 * Fidelity: medium - 29 instr, 5 branches, calls resolved */
int32_t lmacAdjustTimestamp(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .wifi0iram.22; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_10:;
  /* 0010: entry a1, 32 */
  a8 = (uint32_t)&g_mesh_is_started; /* 0013: l32r a8, 0 <lmacAdjustTimestamp-0x10> (0 <lmacAdjustTimestamp-0x10>) */ /* literal @0x0: g_mesh_is_started */
  a8 = MEM8(a8 + 0); /* 0016: l8ui a8, a8, 0 */
  if (a8 != 0) goto L_55; /* 0019: bnez.n a8, 55 <lmacAdjustTimestamp+0x45> */
  a11 = MEM32(a2 + 44); /* 001b: l32i.n a11, a2, 44 */
  a8 = MEM32(a11 + 0); /* 001d: l32i.n a8, a11, 0 */
  if ((a8 >> 5) & 1) goto L_55; /* 001f: bbsi a8, 5, 55 <lmacAdjustTimestamp+0x45> */
  a9 = 0x3FF73C00; /* 0022: l32r a9, 4 <lmacAdjustTimestamp-0xc> (3ff73c00 <lmacTxFrame+0x3ff73b90>) */ /* MMIO base */ @0x4
  a10 = (uint32_t)&g_wifi_mac_time_delta; /* 0025: l32r a10, 8 <lmacAdjustTimestamp-0x8> (0 <lmacAdjustTimestamp-0x10>) */ /* literal @0x8: g_wifi_mac_time_delta */
  MEMW(); /* 0028: memw  */
  a9 = REG32(0x3FF73C00); /* 002b: l32i.n a9, a9, 0 */ /* MMIO read: base 0x3FF73C00+0 */
  a10 = MEM32(a10 + 0); /* 002d: l32i.n a10, a10, 0 */
  a9 = a9 + a10; /* 002f: add.n a9, a9, a10 */
  a10 = (uint32_t)&lmacConfMib; /* 0031: l32r a10, c <lmacAdjustTimestamp-0x4> (0 <lmacAdjustTimestamp-0x10>) */ /* literal @0xC: lmacConfMib */
  if (!((a8 >> 22) & 1)) goto L_3e; /* 0034: bbci a8, 22, 3e <lmacAdjustTimestamp+0x2e> */
  a8 = MEM32(a10 + 0); /* 0037: l32i.n a8, a10, 0 */
  a10 = MEM32(a10 + 4); /* 0039: l32i.n a10, a10, 4 */
  goto L_42; /* 003b: j 42 <lmacAdjustTimestamp+0x32> */
L_3e:;
  a8 = MEM32(a10 + 8); /* 003e: l32i.n a8, a10, 8 */
  a10 = MEM32(a10 + 12); /* 0040: l32i.n a10, a10, 12 */
L_42:;
  a8 = a8 - a10; /* 0042: sub a8, a8, a10 */
  a8 = a8 << (10 & 31); /* 0045: slli a8, a8, 10 */
  a10 = MEM32(a11 + 24); /* 0048: l32i.n a10, a11, 24 */
  a10 = a9 - a10; /* 004a: sub a10, a9, a10 */
  if (a8 >= a10) goto L_55; /* 004d: bgeu a8, a10, 55 <lmacAdjustTimestamp+0x45> */
  a9 = a9 - a8; /* 0050: sub a9, a9, a8 */
  MEM32(a11 + 24) = a9; /* 0053: s32i.n a9, a11, 24 */
L_55:;
  MEMW(); /* 0055: memw  */
  return (int32_t)a2; /* 0058: retw.n  */
}

/* lmac_record_txtime @ lmac.o 00000000 size 5B bind GLOBAL
 * Calls: none | Data refs: none
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t lmac_record_txtime(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.lmac_record_txtime; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_0:;
  /* 0000: entry a1, 32 */
  return (int32_t)a2; /* 0003: retw.n  */
}

/* lmac_update_tx_statistic @ lmac.o 00000000 size 5B bind GLOBAL
 * Calls: none | Data refs: none
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t lmac_update_tx_statistic(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.lmac_update_tx_statistic; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_0:;
  /* 0000: entry a1, 32 */
  return (int32_t)a2; /* 0003: retw.n  */
}

/* lmacTxDone @ lmac.o 0000002c size 108B bind GLOBAL
 * Calls: ppProcTxCallback[got], ppEnqueueTxDone[got], rcUpdateTxDone[got], pp_post[got], wifi_assert[got], ppProcessTxQ[got] | Data refs: ppProcTxCallback, ppEnqueueTxDone, rcUpdateTxDone, pp_post, .bss.our_instances, .rodata.__FUNCTION__$0, .rodata.lmacProcessTxopSuccess.str1.1, wifi_assert, ppProcessTxQ
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 6 call(s), 9 data ref(s)
 * Fidelity: medium - 41 instr, 2 branches, calls resolved */
int32_t lmacTxDone(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .wifi0iram.25; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_2c:;
  /* 002c: entry a1, 32 */
  a4 = MEM32(a2 + 44); /* 002f: l32i.n a4, a2, 44 */
  a11 = 0x1; /* 0031: movi.n a11, 1 */
  a10 = a2; /* 0033: mov.n a10, a2 */
  a3 = (a3 >> 0) & 0xFF; /* 0035: extui a3, a3, 0, 8 */
  a4 = MEM32(a4 + 4); /* 0038: l32i.n a4, a4, 4 */
  a8 = (uint32_t)&ppProcTxCallback; /* 003a: l32r a8, 14 <lmacTxDone-0x18> (0 <lmacTxDone-0x2c>) */ /* literal: GOT slot for ppProcTxCallback */
  ppProcTxCallback(a2, a3, a4, a5); /* call via literal slot */ /* 003d: callx8 a8 */
  a10 = a2; /* 0040: mov.n a10, a2 */
  a8 = (uint32_t)&ppEnqueueTxDone; /* 0042: l32r a8, 18 <lmacTxDone-0x14> (0 <lmacTxDone-0x2c>) */ /* literal: GOT slot for ppEnqueueTxDone */
  ppEnqueueTxDone(a2, a3, a4, a5); /* call via literal slot */ /* 0045: callx8 a8 */
  a4 = (a4 >> 4) & 0xF; /* 0048: extui a4, a4, 4, 4 */
  a11 = MEM32(a2 + 44); /* 004b: l32i.n a11, a2, 44 */
  a9 = 0x400008; /* 004d: l32r a9, 0 <lmacTxDone-0x2c> (400008 <lmacTxFrame+0x3fff98>) */ @0x0
  a8 = MEM32(a11 + 0); /* 0050: l32i.n a8, a11, 0 */
  a8 = a8 & a9; /* 0052: and a8, a8, a9 */
  if (a8 != 8) goto L_60; /* 0055: bnei a8, 8, 60 <lmacTxDone+0x34> */
  a10 = MEM32(a2 + 36); /* 0058: l32i.n a10, a2, 36 */
  a8 = (uint32_t)&rcUpdateTxDone; /* 005a: l32r a8, 1c <lmacTxDone-0x10> (0 <lmacTxDone-0x2c>) */ /* literal: GOT slot for rcUpdateTxDone */
  rcUpdateTxDone(a2, a3, a4, a5); /* call via literal slot */ /* 005d: callx8 a8 */
L_60:;
  a11 = 0x0; /* 0060: movi.n a11, 0 */
  a10 = 0x10; /* 0062: movi.n a10, 16 */
  a8 = (uint32_t)&pp_post; /* 0064: l32r a8, 20 <lmacTxDone-0xc> (0 <lmacTxDone-0x2c>) */ /* literal: GOT slot for pp_post */
  pp_post(a2, a3, a4, a5); /* call via literal slot */ /* 0067: callx8 a8 */
  if (a3 == 0) goto L_96; /* 006a: beqz.n a3, 96 <lmacTxDone+0x6a> */
  a8 = (uint32_t)&bss_our_instances; /* 006c: l32r a8, 10 <lmacTxDone-0x1c> (0 <lmacTxDone-0x2c>) */ /* literal @0x10: .bss.our_instances */
  a2 = (a4 << 8) + a4; /* 006f: addx8 a2, a4, a4 */
  a2 = (a2 << 4) + a8; /* 0072: addx4 a2, a2, a8 */
  a10 = 0x1; /* 0075: movi.n a10, 1 */
  a8 = MEM8(a2 + 18); /* 0077: l8ui a8, a2, 18 */
  a2 = 0x0; /* 007a: movi.n a2, 0 */
  if (a8 != 0) a10 = a2; /* 007c: movnez a10, a2, a8 */
  a13 = 0x9B7; /* 007f: l32r a13, 4 <lmacTxDone-0x28> (9b7 <lmacTxFrame+0x947>) */ @0x4
  a12 = (uint32_t)&lit_rodata_FUNCTION_0; /* 0082: l32r a12, 8 <lmacTxDone-0x24> (0 <lmacTxDone-0x2c>) */ /* literal @0x8: .rodata.__FUNCTION__$0 */
  a11 = (uint32_t)&lit_rodata_lmacProcessTxopSuccess_str1_1; /* 0085: l32r a11, c <lmacTxDone-0x20> (0 <lmacTxDone-0x2c>) */ /* literal @0xC: .rodata.lmacProcessTxopSuccess.str1.1 */
  a8 = (uint32_t)&wifi_assert; /* 0088: l32r a8, 24 <lmacTxDone-0x8> (0 <lmacTxDone-0x2c>) */ /* literal: GOT slot for wifi_assert */
  wifi_assert(a2, a3, a4, a5); /* call via literal slot */ /* 008b: callx8 a8 */
  a10 = a4; /* 008e: mov.n a10, a4 */
  a8 = (uint32_t)&ppProcessTxQ; /* 0090: l32r a8, 28 <lmacTxDone-0x4> (0 <lmacTxDone-0x2c>) */ /* literal: GOT slot for ppProcessTxQ */
  ppProcessTxQ(a2, a3, a4, a5); /* call via literal slot */ /* 0093: callx8 a8 */
L_96:;
  return (int32_t)a2; /* 0096: retw.n  */
}

/* lmacDiscardMSDU @ lmac.o 00000010 size 86B bind GLOBAL
 * Calls: lmacTxDone, ppDequeueTxQ, .text.lmacDebugTxDrop[got] | Data refs: lmacTxDone, ppDequeueTxQ, .text.lmacDebugTxDrop
 *   MMIO: none
 *   funcdb v3: 2 call(s), 2 ref(s); disasm: 4 call(s), 3 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t lmacDiscardMSDU(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.lmacDiscardMSDU; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_10:;
  /* 0010: entry a1, 32 */
  a5 = (a5 >> 0) & 0xFF; /* 0013: extui a5, a5, 0, 8 */
  a7 = 0xC0; /* 0016: movi a7, 192 */
L_19:;
  a10 = a3; /* 0019: mov.n a10, a3 */
  a8 = (uint32_t)&ext_lmacDebugTxDrop; /* 001b: l32r a8, 0 <lmacDiscardMSDU-0x10> (c <lmacDiscardMSDU-0x4>) */ /* literal: GOT slot for .text.lmacDebugTxDrop */
  ext_lmacDebugTxDrop(a2, a3, a4, a5); /* call via literal slot */ /* 001e: callx8 a8 */
  a6 = MEM32(a2 + 32); /* 0021: l32i.n a6, a2, 32 */
  a6 = a6 + (1); /* 0023: addi.n a6, a6, 1 */
  a8 = MEM32(a3 + 44); /* 0025: l32i.n a8, a3, 44 */
  MEM32(a2 + 32) = a6; /* 0027: s32i.n a6, a2, 32 */
  MEM8(a8 + 19) = a4; /* 0029: s8i a4, a8, 19 */
  MEMW(); /* 002c: memw  */
  a6 = MEM32(a8 + 16); /* 002f: l32i.n a6, a8, 16 */
  a6 = (a6 >> 20) & 0xF; /* 0031: extui a6, a6, 20, 4 */
  a8 = MEM32(a8 + 0); /* 0034: l32i.n a8, a8, 0 */
  a8 = a7 & a8; /* 0036: and a8, a7, a8 */
  if (a8 != 128) goto L_5a; /* 0039: bnei a8, 128, 5a <lmacDiscardMSDU+0x4a> */
  a10 = a3; /* 003c: mov.n a10, a3 */
  a11 = 0x0; /* 003e: movi.n a11, 0 */
  MEMW(); /* 0040: memw  */
  a8 = (uint32_t)&lmacTxDone; /* 0043: l32r a8, 4 <lmacDiscardMSDU-0xc> (0 <lmacDiscardMSDU-0x10>) */ /* literal: GOT slot for lmacTxDone */
  lmacTxDone(a2, a3, a4, a5); /* call via literal slot */ /* 0046: callx8 a8 */
  a10 = a6; /* 0049: mov.n a10, a6 */
  a8 = (uint32_t)&ppDequeueTxQ; /* 004b: l32r a8, 8 <lmacDiscardMSDU-0x8> (0 <lmacDiscardMSDU-0x10>) */ /* literal: GOT slot for ppDequeueTxQ */
  ppDequeueTxQ(a2, a3, a4, a5); /* call via literal slot */ /* 004e: callx8 a8 */
  a3 = a10; /* 0051: mov.n a3, a10 */
  if (a10 != 0) goto L_19; /* 0053: bnez a10, 19 <lmacDiscardMSDU+0x9> */
  goto L_64; /* 0056: j 64 <lmacDiscardMSDU+0x54> */
  /* 0059: .byte 00 */
L_5a:;
  a11 = a5; /* 005a: mov.n a11, a5 */
  a10 = a3; /* 005c: mov.n a10, a3 */
  a8 = (uint32_t)&lmacTxDone; /* 005e: l32r a8, c <lmacDiscardMSDU-0x4> (0 <lmacDiscardMSDU-0x10>) */ /* literal: GOT slot for lmacTxDone */
  lmacTxDone(a2, a3, a4, a5); /* call via literal slot */ /* 0061: callx8 a8 */
L_64:;
  return (int32_t)a2; /* 0064: retw.n  */
}

/* lmacDiscardAgedMSDU @ lmac.o 00000004 size 20B bind GLOBAL
 * Calls: lmacDiscardMSDU[got] | Data refs: lmacDiscardMSDU
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 1 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t lmacDiscardAgedMSDU(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .wifi0iram.8; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a13 = (a4 >> 0) & 0xFF; /* 0007: extui a13, a4, 0, 8 */
  a12 = 0x4; /* 000a: movi.n a12, 4 */
  a11 = a3; /* 000c: mov.n a11, a3 */
  a10 = a2; /* 000e: mov.n a10, a2 */
  a8 = (uint32_t)&lmacDiscardMSDU; /* 0010: l32r a8, 0 <lmacDiscardAgedMSDU-0x4> (0 <lmacDiscardAgedMSDU-0x4>) */ /* literal: GOT slot for lmacDiscardMSDU */
  lmacDiscardMSDU(a2, a3, a4, a5); /* call via literal slot */ /* 0013: callx8 a8 */
  return (int32_t)a2; /* 0016: retw.n  */
}

/* lmacTxFrame @ lmac.o 00000070 size 622B bind GLOBAL
 * Calls: .text.offchan_in_progress[got], wifi_log[got], wDev_isNANPktInValidSlot[got], lmacDiscardAgedMSDU[got], ppRecycleAmpdu[got], pp_post[got], wifi_assert[got], wifi_assert[got], wifi_assert[got], lmacIsLongFrame[got], lmacSetTxFrame[got], lmacIsLongFrame[got], hal_random[got], hal_random[got], hal_mac_tx_config_edca[got], wifi_gpio_debug[got], hal_mac_txq_enable[got] | Data refs: .bss.our_instances, .text.offchan_in_progress, .rodata_wlog_debug.24, wifi_log, wDev_isNANPktInValidSlot, lmacDiscardAgedMSDU, ppRecycleAmpdu, pp_post, .rodata.__FUNCTION__$1, .rodata.lmacProcessTxopSuccess.str1.1, wifi_assert, g_osi_funcs_p, lmacIsLongFrame, lmacConfMib, lmacSetTxFrame, g_lmac_cnt, hal_random, hal_mac_tx_config_edca, wifi_gpio_debug, hal_mac_txq_enable
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 17 call(s), 20 data ref(s)
 * Fidelity: low - 240 instr, 22 branches, 2 indirect; call-sequence + MMIO skeleton */
int32_t lmacTxFrame(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .wifi0iram.23; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_70:;
  /* 0070: entry a1, 48 */
  a7 = a2; /* 0073: mov.n a7, a2 */
  a2 = MEM32(a2 + 44); /* 0075: l32i.n a2, a2, 44 */
  a5 = (a3 >> 0) & 0xFF; /* 0077: extui a5, a3, 0, 8 */
  a3 = (a5 << 8) + a5; /* 007a: addx8 a3, a5, a5 */
  a4 = a5 << (3 & 31); /* 007d: slli a4, a5, 3 */
  a6 = (uint32_t)&bss_our_instances; /* 0080: l32r a6, 0 <lmacTxFrame-0x70> (0 <lmacTxFrame-0x70>) */ /* literal @0x0: .bss.our_instances */
  a3 = (a3 << 4) + a6; /* 0083: addx4 a3, a3, a6 */
  a2 = MEM16(a2 + 2); /* 0086: l16ui a2, a2, 2 */
  if (!((a2 >> 0) & 1)) goto L_c8; /* 0089: bbci a2, 0, c8 <lmacTxFrame+0x58> */
  a8 = (uint32_t)&offchan_in_progress; /* 008c: l32r a8, 2c <lmacTxFrame-0x44> (4 <lmacTxFrame-0x6c>) */ /* literal: GOT slot for .text.offchan_in_progress */
  offchan_in_progress(a2, a3, a4, a5); /* call via literal slot */ /* 008f: callx8 a8 */
  if (a10 != 0) goto L_c8; /* 0092: bnez.n a10, c8 <lmacTxFrame+0x58> */
L_94:;
  a4 = a4 + a5; /* 0094: add.n a4, a4, a5 */
  a4 = (a4 << 4) + a6; /* 0096: addx4 a4, a4, a6 */
  a2 = 0x0; /* 0099: movi.n a2, 0 */
  a13 = (uint32_t)&lit_rodata_wlog_debug_24; /* 009b: l32r a13, 4 <lmacTxFrame-0x6c> (0 <lmacTxFrame-0x70>) */ /* literal @0x4: .rodata_wlog_debug.24 */
  a12 = 0x4; /* 009e: movi.n a12, 4 */
  a11 = 0x40; /* 00a0: movi.n a11, 64 */
  a10 = 0x6; /* 00a2: movi.n a10, 6 */
  MEM32(a4 + 0) = a2; /* 00a4: s32i.n a2, a4, 0 */
  MEM8(a4 + 18) = a2; /* 00a6: s8i a2, a4, 18 */
  MEMW(); /* 00a9: memw  */
  MEMW(); /* 00ac: memw  */
  a8 = (uint32_t)&wifi_log; /* 00af: l32r a8, 30 <lmacTxFrame-0x40> (0 <lmacTxFrame-0x70>) */ /* literal: GOT slot for wifi_log */
  wifi_log(a2, a3, a4, a5); /* call via literal slot */ /* 00b2: callx8 a8 */
  a4 = MEM32(a7 + 44); /* 00b5: l32i.n a4, a7, 44 */
  a12 = MEM32(a4 + 0); /* 00b7: l32i.n a12, a4, 0 */
  a4 = 0x1; /* 00b9: movi.n a4, 1 */
  a4 = 0x400000; /* 00bb: slli a4, a4, 22 */
  a12 = a12 & a4; /* 00be: and a12, a12, a4 */
  if (a12 == a2) goto L_d6; /* 00c1: beq a12, a2, d6 <lmacTxFrame+0x66> */
  goto L_e4; /* 00c4: j e4 <lmacTxFrame+0x74> */
  /* 00c7: .byte 00 */
L_c8:;
  a10 = a7; /* 00c8: mov.n a10, a7 */
  a8 = (uint32_t)&wDev_isNANPktInValidSlot; /* 00ca: l32r a8, 34 <lmacTxFrame-0x3c> (0 <lmacTxFrame-0x70>) */ /* literal: GOT slot for wDev_isNANPktInValidSlot */
  wDev_isNANPktInValidSlot(a2, a3, a4, a5); /* call via literal slot */ /* 00cd: callx8 a8 */
  if (a10 != 0) goto L_fe; /* 00d0: bnez.n a10, fe <lmacTxFrame+0x8e> */
  goto L_94; /* 00d2: j 94 <lmacTxFrame+0x24> */
  /* 00d5: .byte 00 */
L_d6:;
  a11 = a7; /* 00d6: mov.n a11, a7 */
  a10 = a3; /* 00d8: mov.n a10, a3 */
  a8 = (uint32_t)&lmacDiscardAgedMSDU; /* 00da: l32r a8, 38 <lmacTxFrame-0x38> (0 <lmacTxFrame-0x70>) */ /* literal: GOT slot for lmacDiscardAgedMSDU */
  lmacDiscardAgedMSDU(a2, a3, a4, a5); /* call via literal slot */ /* 00dd: callx8 a8 */
  goto L_ee; /* 00e0: j ee <lmacTxFrame+0x7e> */
  /* 00e3: .byte 00 */
L_e4:;
  a11 = a2; /* 00e4: mov.n a11, a2 */
  a10 = a7; /* 00e6: mov.n a10, a7 */
  a8 = (uint32_t)&ppRecycleAmpdu; /* 00e8: l32r a8, 3c <lmacTxFrame-0x34> (0 <lmacTxFrame-0x70>) */ /* literal: GOT slot for ppRecycleAmpdu */
  ppRecycleAmpdu(a2, a3, a4, a5); /* call via literal slot */ /* 00eb: callx8 a8 */
L_ee:;
  a11 = 0x0; /* 00ee: movi.n a11, 0 */
  a10 = a5; /* 00f0: mov.n a10, a5 */
  a8 = (uint32_t)&pp_post; /* 00f2: l32r a8, 40 <lmacTxFrame-0x30> (0 <lmacTxFrame-0x70>) */ /* literal: GOT slot for pp_post */
  pp_post(a2, a3, a4, a5); /* call via literal slot */ /* 00f5: callx8 a8 */
  goto L_2dc; /* 00f8: j 2dc <lmacTxFrame+0x26c> */
  /* 00fb: .byte 00 */
  /* 00fc: .byte 00 */
  /* 00fd: .byte 00 */
L_fe:;
  a2 = a4 + a5; /* 00fe: add.n a2, a4, a5 */
  a2 = (a2 << 4) + a6; /* 0100: addx4 a2, a2, a6 */
  a11 = MEM8(a2 + 18); /* 0103: l8ui a11, a2, 18 */
  a13 = 0x45B; /* 0106: movi a13, 0x45b */
  a2 = a11 + (-3); /* 0109: addi a2, a11, -3 */
  a2 = (a2 >> 0) & 0xFF; /* 010c: extui a2, a2, 0, 8 */
  a13 = 0x8B6; /* 010f: add.n a13, a13, a13 */
  a15 = (uint32_t)&lit_rodata_FUNCTION_1; /* 0111: l32r a15, 8 <lmacTxFrame-0x68> (0 <lmacTxFrame-0x70>) */ /* literal @0x8: .rodata.__FUNCTION__$1 */
  a8 = 0x1; /* 0114: movi.n a8, 1 */
  a14 = (uint32_t)&lit_rodata_lmacProcessTxopSuccess_str1_1; /* 0116: l32r a14, c <lmacTxFrame-0x64> (0 <lmacTxFrame-0x70>) */ /* literal @0xC: .rodata.lmacProcessTxopSuccess.str1.1 */
  if (a2 < 2) goto L_11e; /* 0119: bltui a2, 2, 11e <lmacTxFrame+0xae> */
  a8 = 0x0; /* 011c: movi.n a8, 0 */
L_11e:;
  a2 = 0x0; /* 011e: movi.n a2, 0 */
  a9 = 0x1; /* 0120: movi.n a9, 1 */
  a10 = 0x0; /* 0122: mov.n a10, a2 */
  if (a11 == 0) a10 = a9; /* 0124: moveqz a10, a9, a11 */
  a10 = a10 | a8; /* 0127: or a10, a10, a8 */
  a11 = a14; /* 012a: mov.n a11, a14 */
  a10 = a10 & a9; /* 012c: and a10, a10, a9 */
  a12 = a15; /* 012f: mov.n a12, a15 */
  MEM32(a1 + 8) = a9; /* 0131: s32i.n a9, a1, 8 */
  MEM32(a1 + 4) = a14; /* 0133: s32i.n a14, a1, 4 */
  MEM32(a1 + 0) = a15; /* 0135: s32i a15, a1, 0 */
  MEMW(); /* 0138: memw  */
  a8 = (uint32_t)&wifi_assert; /* 013b: l32r a8, 44 <lmacTxFrame-0x2c> (0 <lmacTxFrame-0x70>) */ /* literal: GOT slot for wifi_assert */
  wifi_assert(a2, a3, a4, a5); /* call via literal slot */ /* 013e: callx8 a8 */
  a8 = (uint32_t)&g_osi_funcs_p; /* 0141: l32r a8, 10 <lmacTxFrame-0x60> (0 <lmacTxFrame-0x70>) */ /* literal @0x10: g_osi_funcs_p */
  a10 = MEM32(a8 + 0); /* 0144: l32i.n a10, a8, 0 */
  a10 = MEM32(a10 + 216); /* 0146: l32i a10, a10, 216 */
  ((int32_t(*)())a10)(a2, a3, a4, a5); /* 0149: callx8 a10 */ /* indirect */
  a10 = a4 + a5; /* 014c: add.n a10, a4, a5 */
  a10 = (a10 << 4) + a6; /* 014e: addx4 a10, a10, a6 */
  a11 = MEM8(a10 + 18); /* 0151: l8ui a11, a10, 18 */
  a9 = MEM32(a1 + 8); /* 0154: l32i.n a9, a1, 8 */
  a14 = MEM32(a1 + 4); /* 0156: l32i.n a14, a1, 4 */
  a15 = MEM32(a1 + 0); /* 0158: l32i.n a15, a1, 0 */
  if (a11 != 4) goto L_17c; /* 015a: bnei a11, 4, 17c <lmacTxFrame+0x10c> */
  a13 = 0x45F; /* 015d: movi a13, 0x45f */
  a13 = 0x8BE; /* 0160: add.n a13, a13, a13 */
  a12 = a15; /* 0162: mov.n a12, a15 */
  a11 = MEM32(a10 + 0); /* 0164: l32i.n a11, a10, 0 */
  a10 = a2 | a2; /* 0166: or a10, a2, a2 */
  a11 = a11 - a7; /* 0169: sub a11, a11, a7 */
  if (a11 == 0) a10 = a9; /* 016c: moveqz a10, a9, a11 */
  a11 = a14 | a14; /* 016f: or a11, a14, a14 */
  a8 = (uint32_t)&wifi_assert; /* 0172: l32r a8, 48 <lmacTxFrame-0x28> (0 <lmacTxFrame-0x70>) */ /* literal: GOT slot for wifi_assert */
  wifi_assert(a2, a3, a4, a5); /* call via literal slot */ /* 0175: callx8 a8 */
  goto L_23c; /* 0178: j 23c <lmacTxFrame+0x1cc> */
  /* 017b: .byte 00 */
L_17c:;
  a13 = 0x8C7; /* 017c: l32r a13, 14 <lmacTxFrame-0x5c> (8c7 <lmacTxFrame+0x857>) */ @0x14
  a12 = a15; /* 017f: mov.n a12, a15 */
  a11 = a14; /* 0181: mov.n a11, a14 */
  MEM32(a10 + 0) = a7; /* 0183: s32i.n a7, a10, 0 */
  a10 = a9; /* 0185: mov.n a10, a9 */
  MEM32(a1 + 8) = a9; /* 0187: s32i.n a9, a1, 8 */
  MEMW(); /* 0189: memw  */
  a8 = (uint32_t)&wifi_assert; /* 018c: l32r a8, 4c <lmacTxFrame-0x24> (0 <lmacTxFrame-0x70>) */ /* literal: GOT slot for wifi_assert */
  wifi_assert(a2, a3, a4, a5); /* call via literal slot */ /* 018f: callx8 a8 */
  a2 = MEM32(a7 + 44); /* 0192: l32i.n a2, a7, 44 */
  a11 = 0x2102; /* 0194: l32r a11, 18 <lmacTxFrame-0x58> (2102 <lmacTxFrame+0x2092>) */ @0x18
  a10 = MEM32(a2 + 0); /* 0197: l32i.n a10, a2, 0 */
  a11 = a10 & a11; /* 0199: and a11, a10, a11 */
  a9 = MEM32(a1 + 8); /* 019c: l32i.n a9, a1, 8 */
  a12 = a9 << (13 & 31); /* 019e: slli a12, a9, 13 */
  if (a11 != a12) goto L_1ac; /* 01a1: bne a11, a12, 1ac <lmacTxFrame+0x13c> */
  a9 = a9 << (12 & 31); /* 01a4: slli a9, a9, 12 */
  a10 = a10 | a9; /* 01a7: or a10, a10, a9 */
  MEM32(a2 + 0) = a10; /* 01aa: s32i.n a10, a2, 0 */
L_1ac:;
  a9 = 0x3; /* 01ac: movi.n a9, 3 */
  a9 = 0xC0000; /* 01ae: slli a9, a9, 18 */
  a10 = MEM32(a2 + 16); /* 01b1: l32i.n a10, a2, 16 */
  a10 = a10 & a9; /* 01b3: and a10, a10, a9 */
  a9 = 0x1; /* 01b6: movi.n a9, 1 */
  a9 = 0x80000; /* 01b8: slli a9, a9, 19 */
  if (a10 != a9) goto L_1d6; /* 01bb: bne a10, a9, 1d6 <lmacTxFrame+0x166> */
  a9 = MEM32(a2 + 0); /* 01be: l32i.n a9, a2, 0 */
  a10 = 0x1; /* 01c0: movi.n a10, 1 */
  a10 = 0x2000; /* 01c2: slli a10, a10, 13 */
  a11 = 0x2002; /* 01c5: l32r a11, 1c <lmacTxFrame-0x54> (2002 <lmacTxFrame+0x1f92>) */ @0x1C
  a11 = a9 & a11; /* 01c8: and a11, a9, a11 */
  if (a11 != a10) goto L_1d6; /* 01cb: bne a11, a10, 1d6 <lmacTxFrame+0x166> */
  a10 = 0xFFFFEFFF; /* 01ce: l32r a10, 20 <lmacTxFrame-0x50> (ffffefff <lmacTxFrame+0xffffef8f>) */ @0x20
  a9 = a9 & a10; /* 01d1: and a9, a9, a10 */
  MEM32(a2 + 0) = a9; /* 01d4: s32i.n a9, a2, 0 */
L_1d6:;
  a10 = a7; /* 01d6: mov.n a10, a7 */
  MEMW(); /* 01d8: memw  */
  a8 = (uint32_t)&lmacIsLongFrame; /* 01db: l32r a8, 50 <lmacTxFrame-0x20> (0 <lmacTxFrame-0x70>) */ /* literal: GOT slot for lmacIsLongFrame */
  lmacIsLongFrame(a2, a3, a4, a5); /* call via literal slot */ /* 01de: callx8 a8 */
  if (a10 == 0) goto L_1f6; /* 01e1: beqz.n a10, 1f6 <lmacTxFrame+0x186> */
  a9 = MEM32(a2 + 0); /* 01e3: l32i.n a9, a2, 0 */
  if ((a9 >> 1) & 1) goto L_1f6; /* 01e5: bbsi a9, 1, 1f6 <lmacTxFrame+0x186> */
  a10 = 0xFFFFEFFF; /* 01e8: l32r a10, 20 <lmacTxFrame-0x50> (ffffefff <lmacTxFrame+0xffffef8f>) */ @0x20
  a9 = a9 & a10; /* 01eb: and a9, a9, a10 */
  a10 = 0x100; /* 01ee: movi a10, 0x100 */
  a9 = a9 | a10; /* 01f1: or a9, a9, a10 */
  MEM32(a2 + 0) = a9; /* 01f4: s32i.n a9, a2, 0 */
L_1f6:;
  a9 = MEM32(a2 + 0); /* 01f6: l32i.n a9, a2, 0 */
  if (!((a9 >> 12) & 1)) goto L_22e; /* 01f8: bbci a9, 12, 22e <lmacTxFrame+0x1be> */
  a10 = a4 + a5; /* 01fb: add.n a10, a4, a5 */
  a10 = (a10 << 4) + a6; /* 01fd: addx4 a10, a10, a6 */
  a10 = MEM8(a10 + 18); /* 0200: l8ui a10, a10, 18 */
  if (a10 != 3) goto L_22e; /* 0203: bnei a10, 3, 22e <lmacTxFrame+0x1be> */
  a10 = (uint32_t)&lmacConfMib; /* 0206: l32r a10, 24 <lmacTxFrame-0x4c> (0 <lmacTxFrame-0x70>) */ /* literal @0x24: lmacConfMib */
  a11 = MEM8(a2 + 5); /* 0209: l8ui a11, a2, 5 */
  a10 = MEM8(a10 + 42); /* 020c: l8ui a10, a10, 42 */
  if (a11 < a10) goto L_22e; /* 020f: bltu a11, a10, 22e <lmacTxFrame+0x1be> */
  a10 = 0xFFFFEFFF; /* 0212: l32r a10, 20 <lmacTxFrame-0x50> (ffffefff <lmacTxFrame+0xffffef8f>) */ @0x20
  a9 = a9 & a10; /* 0215: and a9, a9, a10 */
  a10 = 0x100; /* 0218: movi a10, 0x100 */
  a9 = a9 | a10; /* 021b: or a9, a9, a10 */
  MEM32(a2 + 0) = a9; /* 021e: s32i.n a9, a2, 0 */
  a9 = MEM8(a2 + 6); /* 0220: l8ui a9, a2, 6 */
  MEM8(a2 + 7) = a9; /* 0223: s8i a9, a2, 7 */
  a9 = 0x0; /* 0226: movi.n a9, 0 */
  MEM8(a2 + 6) = a9; /* 0228: s8i a9, a2, 6 */
  MEMW(); /* 022b: memw  */
L_22e:;
  a11 = 0x0; /* 022e: movi.n a11, 0 */
  a10 = a3 | a3; /* 0230: or a10, a3, a3 */
  MEMW(); /* 0233: memw  */
  a8 = (uint32_t)&lmacSetTxFrame; /* 0236: l32r a8, 54 <lmacTxFrame-0x1c> (0 <lmacTxFrame-0x70>) */ /* literal: GOT slot for lmacSetTxFrame */
  lmacSetTxFrame(a2, a3, a4, a5); /* call via literal slot */ /* 0239: callx8 a8 */
L_23c:;
  a2 = MEM32(a7 + 44); /* 023c: l32i.n a2, a7, 44 */
  a2 = MEM32(a2 + 4); /* 023e: l32i.n a2, a2, 4 */
  a2 = (a2 >> 4) & 0xF; /* 0240: extui a2, a2, 4, 4 */
  a2 = a2 + (14); /* 0243: addi.n a2, a2, 14 */
  a9 = (uint32_t)&g_lmac_cnt; /* 0245: l32r a9, 28 <lmacTxFrame-0x48> (0 <lmacTxFrame-0x70>) */ /* literal @0x28: g_lmac_cnt */
  a2 = (a2 << 8) + a9; /* 0248: addx8 a2, a2, a9 */
  a9 = MEM32(a2 + 8); /* 024b: l32i.n a9, a2, 8 */
  a9 = a9 + (1); /* 024d: addi.n a9, a9, 1 */
  MEM32(a2 + 8) = a9; /* 024f: s32i.n a9, a2, 8 */
  a2 = a4 + a5; /* 0251: add.n a2, a4, a5 */
  a2 = (a2 << 4) + a6; /* 0253: addx4 a2, a2, a6 */
  a9 = MEM8(a2 + 9); /* 0256: l8ui a9, a2, 9 */
  a9 = a9 + a9; /* 0259: add.n a9, a9, a9 */
  a10 = MEM8(a2 + 8); /* 025b: l8ui a10, a2, 8 */
  if (a9 >= a10) goto L_27d; /* 025e: bge a9, a10, 27d <lmacTxFrame+0x20d> */
  a10 = a7; /* 0261: mov.n a10, a7 */
  MEMW(); /* 0263: memw  */
  a8 = (uint32_t)&lmacIsLongFrame; /* 0266: l32r a8, 58 <lmacTxFrame-0x18> (0 <lmacTxFrame-0x70>) */ /* literal: GOT slot for lmacIsLongFrame */
  lmacIsLongFrame(a2, a3, a4, a5); /* call via literal slot */ /* 0269: callx8 a8 */
  if (a10 != 0) goto L_27d; /* 026c: bnez.n a10, 27d <lmacTxFrame+0x20d> */
  a8 = (uint32_t)&hal_random; /* 026e: l32r a8, 5c <lmacTxFrame-0x14> (0 <lmacTxFrame-0x70>) */ /* literal: GOT slot for hal_random */
  hal_random(a2, a3, a4, a5); /* call via literal slot */ /* 0271: callx8 a8 */
  a2 = MEM8(a2 + 9); /* 0274: l8ui a2, a2, 9 */
  a2 = a2 + a2; /* 0277: add.n a2, a2, a2 */
  goto L_28b; /* 0279: j 28b <lmacTxFrame+0x21b> */
  /* 027c: .byte 00 */
L_27d:;
  a2 = a4 + a5; /* 027d: add.n a2, a4, a5 */
  a2 = (a2 << 4) + a6; /* 027f: addx4 a2, a2, a6 */
  a8 = (uint32_t)&hal_random; /* 0282: l32r a8, 60 <lmacTxFrame-0x10> (0 <lmacTxFrame-0x70>) */ /* literal: GOT slot for hal_random */
  hal_random(a2, a3, a4, a5); /* call via literal slot */ /* 0285: callx8 a8 */
  a2 = MEM8(a2 + 8); /* 0288: l8ui a2, a2, 8 */
L_28b:;
  a8 = 0xFFFFFFFF; /* 028b: movi.n a8, -1 */
  /* 028d: ssl a2 */ /* UNMODELED: a2 clobbered */
  /* 0290: sll a2, a8 */ /* UNMODELED: a2 clobbered */
  a8 = a8 ^ a2; /* 0293: xor a8, a8, a2 */
  a10 = a8 & a10; /* 0296: and a10, a8, a10 */
  a4 = a4 + a5; /* 0299: add.n a4, a4, a5 */
  a4 = (a4 << 4) + a6; /* 029b: addx4 a4, a4, a6 */
  a10 = (a10 >> 0) & 0xFFFF; /* 029e: extui a10, a10, 0, 16 */
  MEM16(a4 + 6) = a10; /* 02a1: s16i a10, a4, 6 */
  MEMW(); /* 02a4: memw  */
  a10 = a3; /* 02a7: mov.n a10, a3 */
  MEMW(); /* 02a9: memw  */
  a8 = (uint32_t)&hal_mac_tx_config_edca; /* 02ac: l32r a8, 64 <lmacTxFrame-0xc> (0 <lmacTxFrame-0x70>) */ /* literal: GOT slot for hal_mac_tx_config_edca */
  hal_mac_tx_config_edca(a2, a3, a4, a5); /* call via literal slot */ /* 02af: callx8 a8 */
  a2 = 0x1; /* 02b2: movi.n a2, 1 */
  a11 = 0x2; /* 02b4: movi.n a11, 2 */
  MEM8(a4 + 18) = a2; /* 02b6: s8i a2, a4, 18 */
  MEMW(); /* 02b9: memw  */
  a10 = 0x9; /* 02bc: movi a10, 9 */
  MEMW(); /* 02bf: memw  */
  a8 = (uint32_t)&wifi_gpio_debug; /* 02c2: l32r a8, 68 <lmacTxFrame-0x8> (0 <lmacTxFrame-0x70>) */ /* literal: GOT slot for wifi_gpio_debug */
  wifi_gpio_debug(a2, a3, a4, a5); /* call via literal slot */ /* 02c5: callx8 a8 */
  a10 = MEM8(a4 + 4); /* 02c8: l8ui a10, a4, 4 */
  a8 = (uint32_t)&hal_mac_txq_enable; /* 02cb: l32r a8, 6c <lmacTxFrame-0x4> (0 <lmacTxFrame-0x70>) */ /* literal: GOT slot for hal_mac_txq_enable */
  hal_mac_txq_enable(a2, a3, a4, a5); /* call via literal slot */ /* 02ce: callx8 a8 */
  a3 = (uint32_t)&g_osi_funcs_p; /* 02d1: l32r a3, 10 <lmacTxFrame-0x60> (0 <lmacTxFrame-0x70>) */ /* literal @0x10: g_osi_funcs_p */
  a2 = MEM32(a3 + 0); /* 02d4: l32i.n a2, a3, 0 */
  a2 = MEM32(a2 + 220); /* 02d6: l32i a2, a2, 220 */
  ((int32_t(*)())a2)(a2, a3, a4, a5); /* 02d9: callx8 a2 */ /* indirect */
L_2dc:;
  return (int32_t)a2; /* 02dc: retw.n  */
}

/* lmacRetryTxFrame @ lmac.o 0000001c size 172B bind GLOBAL
 * Calls: lmacDiscardAgedMSDU, lmacTxFrame, ppCalFrameTimes, ppRecycleAmpdu, rcGetRate, wifi_log | Data refs: .rodata_wlog_info.19, lmacDiscardAgedMSDU, lmacTxFrame, ppCalFrameTimes, ppRecycleAmpdu, rcGetRate, wifi_log
 *   MMIO: none
 *   funcdb v3: 6 call(s), 7 ref(s); disasm: 6 call(s), 7 data ref(s)
 * Fidelity: medium - 67 instr, 9 branches, calls resolved */
int32_t lmacRetryTxFrame(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.lmacRetryTxFrame; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_1c:;
  /* 001c: entry a1, 32 */
  a4 = MEM32(a2 + 0); /* 001f: l32i.n a4, a2, 0 */
  a3 = (a3 >> 0) & 0xFF; /* 0021: extui a3, a3, 0, 8 */
  a11 = MEM32(a4 + 44); /* 0024: l32i.n a11, a4, 44 */
  a5 = MEM32(a4 + 4); /* 0026: l32i.n a5, a4, 4 */
  a9 = MEM32(a11 + 0); /* 0028: l32i a9, a11, 0 */
  a5 = MEM32(a5 + 4); /* 002b: l32i a5, a5, 4 */
  if ((a9 >> 17) & 1) goto L_89; /* 002e: bbsi a9, 17, 89 <lmacRetryTxFrame+0x6d> */
  if (a3 != 0) goto L_c6; /* 0031: bnez a3, c6 <lmacRetryTxFrame+0xaa> */
  a8 = MEM8(a2 + 13); /* 0034: l8ui a8, a2, 13 */
  if (a8 != 0) goto L_c6; /* 0037: bnez a8, c6 <lmacRetryTxFrame+0xaa> */
  a10 = MEM8(a2 + 15); /* 003a: l8ui a10, a2, 15 */
  if (a10 == 0) goto L_49; /* 003d: beqz a10, 49 <lmacRetryTxFrame+0x2d> */
  MEM8(a2 + 15) = a8; /* 0040: s8i a8, a2, 15 */
  MEM8(a2 + 13) = a8; /* 0043: s8i a8, a2, 13 */
  MEMW(); /* 0046: memw  */
L_49:;
  if (!((a9 >> 18) & 1)) goto L_4e; /* 0049: bbci a9, 18, 4e <lmacRetryTxFrame+0x32> */
  a5 = a5 + (4); /* 004c: addi.n a5, a5, 4 */
L_4e:;
  a10 = MEM32(a4 + 36); /* 004e: l32i.n a10, a4, 36 */
  MEMW(); /* 0050: memw  */
  a8 = (uint32_t)&rcGetRate; /* 0053: l32r a8, 4 <lmacRetryTxFrame-0x18> (0 <lmacRetryTxFrame-0x1c>) */ /* literal: GOT slot for rcGetRate */
  rcGetRate(a2, a3, a4, a5); /* call via literal slot */ /* 0056: callx8 a8 */
  a10 = MEM32(a2 + 0); /* 0059: l32i.n a10, a2, 0 */
  a4 = MEM32(a10 + 44); /* 005b: l32i.n a4, a10, 44 */
  a4 = MEM32(a4 + 0); /* 005d: l32i.n a4, a4, 0 */
  if (!((a4 >> 6) & 1)) goto L_75; /* 005f: bbci a4, 6, 75 <lmacRetryTxFrame+0x59> */
  a8 = (uint32_t)&ppCalFrameTimes; /* 0062: l32r a8, 8 <lmacRetryTxFrame-0x14> (0 <lmacRetryTxFrame-0x1c>) */ /* literal: GOT slot for ppCalFrameTimes */
  ppCalFrameTimes(a2, a3, a4, a5); /* call via literal slot */ /* 0065: callx8 a8 */
  a4 = MEM32(a2 + 0); /* 0068: l32i.n a4, a2, 0 */
  a4 = MEM32(a4 + 44); /* 006a: l32i.n a4, a4, 44 */
  a4 = MEM16(a4 + 10); /* 006c: l16ui a4, a4, 10 */
  MEM16(a5 + 2) = a4; /* 006f: s16i a4, a5, 2 */
  MEMW(); /* 0072: memw  */
L_75:;
  a11 = MEM8(a2 + 4); /* 0075: l8ui a11, a2, 4 */
  a10 = MEM32(a2 + 0); /* 0078: l32i a10, a2, 0 */
  MEMW(); /* 007b: memw  */
  a8 = (uint32_t)&lmacTxFrame; /* 007e: l32r a8, c <lmacRetryTxFrame-0x10> (0 <lmacRetryTxFrame-0x1c>) */ /* literal: GOT slot for lmacTxFrame */
  lmacTxFrame(a2, a3, a4, a5); /* call via literal slot */ /* 0081: callx8 a8 */
  goto L_c6; /* 0084: j c6 <lmacRetryTxFrame+0xaa> */
  /* 0087: .byte 00 */
  /* 0088: .byte 00 */
L_89:;
  a5 = 0x0; /* 0089: movi.n a5, 0 */
  a13 = (uint32_t)&lit_rodata_wlog_info_19; /* 008b: l32r a13, 0 <lmacRetryTxFrame-0x1c> (0 <lmacRetryTxFrame-0x1c>) */ /* literal @0x0: .rodata_wlog_info.19 */
  a12 = 0x3; /* 008e: movi.n a12, 3 */
  a11 = 0x40; /* 0090: movi.n a11, 64 */
  a10 = 0x6; /* 0092: movi.n a10, 6 */
  MEM32(a2 + 0) = a5; /* 0094: s32i.n a5, a2, 0 */
  MEM8(a2 + 18) = a5; /* 0096: s8i a5, a2, 18 */
  MEMW(); /* 0099: memw  */
  MEMW(); /* 009c: memw  */
  a8 = (uint32_t)&wifi_log; /* 009f: l32r a8, 10 <lmacRetryTxFrame-0xc> (0 <lmacRetryTxFrame-0x1c>) */ /* literal: GOT slot for wifi_log */
  wifi_log(a2, a3, a4, a5); /* call via literal slot */ /* 00a2: callx8 a8 */
  a5 = MEM32(a4 + 44); /* 00a5: l32i.n a5, a4, 44 */
  a5 = MEM32(a5 + 0); /* 00a7: l32i.n a5, a5, 0 */
  if ((a5 >> 22) & 1) goto L_bc; /* 00a9: bbsi a5, 22, bc <lmacRetryTxFrame+0xa0> */
  a12 = 0x1; /* 00ac: movi.n a12, 1 */
  a11 = a4; /* 00ae: mov.n a11, a4 */
  a10 = a2; /* 00b0: mov.n a10, a2 */
  a8 = (uint32_t)&lmacDiscardAgedMSDU; /* 00b2: l32r a8, 14 <lmacRetryTxFrame-0x8> (0 <lmacRetryTxFrame-0x1c>) */ /* literal: GOT slot for lmacDiscardAgedMSDU */
  lmacDiscardAgedMSDU(a2, a3, a4, a5); /* call via literal slot */ /* 00b5: callx8 a8 */
  goto L_c6; /* 00b8: j c6 <lmacRetryTxFrame+0xaa> */
  /* 00bb: .byte 00 */
L_bc:;
  a11 = 0x1; /* 00bc: movi.n a11, 1 */
  a10 = a4; /* 00be: mov.n a10, a4 */
  a8 = (uint32_t)&ppRecycleAmpdu; /* 00c0: l32r a8, 18 <lmacRetryTxFrame-0x4> (0 <lmacRetryTxFrame-0x1c>) */ /* literal: GOT slot for ppRecycleAmpdu */
  ppRecycleAmpdu(a2, a3, a4, a5); /* call via literal slot */ /* 00c3: callx8 a8 */
L_c6:;
  return (int32_t)a2; /* 00c6: retw.n  */
}

/* lmacDiscardFrameExchangeSequence @ lmac.o 00000020 size 150B bind GLOBAL
 * Calls: wifi_assert[got], ppRecordBarRRC[got], ppResortTxAMPDU[got], ppRecycleAmpdu[got], lmacDiscardMSDU[got] | Data refs: .rodata.__FUNCTION__$11, .rodata.lmacProcessTxopSuccess.str1.1, wifi_assert, ppRecordBarRRC, ppResortTxAMPDU, ppRecycleAmpdu, lmacConfMib, lmacDiscardMSDU
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 5 call(s), 8 data ref(s)
 * Fidelity: medium - 56 instr, 6 branches, calls resolved */
int32_t lmacDiscardFrameExchangeSequence(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .wifiextrairam.10; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_20:;
  /* 0020: entry a1, 32 */
  a8 = MEM8(a2 + 18); /* 0023: l8ui a8, a2, 18 */
  a5 = 0x0; /* 0026: movi.n a5, 0 */
  a8 = a8 + (-6); /* 0028: addi a8, a8, -6 */
  a10 = 0x0; /* 002b: mov.n a10, a5 */
  a4 = 0x1; /* 002d: movi a4, 1 */
  a12 = (uint32_t)&lit_rodata_FUNCTION_11; /* 0030: l32r a12, 0 <lmacDiscardFrameExchangeSequence-0x20> (0 <lmacDiscardFrameExchangeSequence-0x20>) */ /* literal @0x0: .rodata.__FUNCTION__$11 */
  if (a8 == 0) a10 = a4; /* 0033: moveqz a10, a4, a8 */
  a13 = 0x32F; /* 0036: movi a13, 0x32f */
  a11 = (uint32_t)&lit_rodata_lmacProcessTxopSuccess_str1_1; /* 0039: l32r a11, 4 <lmacDiscardFrameExchangeSequence-0x1c> (0 <lmacDiscardFrameExchangeSequence-0x20>) */ /* literal @0x4: .rodata.lmacProcessTxopSuccess.str1.1 */
  a3 = MEM32(a2 + 0); /* 003c: l32i.n a3, a2, 0 */
  a8 = (uint32_t)&wifi_assert; /* 003e: l32r a8, c <lmacDiscardFrameExchangeSequence-0x14> (0 <lmacDiscardFrameExchangeSequence-0x20>) */ /* literal: GOT slot for wifi_assert */
  wifi_assert(a2, a3, a4, a5); /* call via literal slot */ /* 0041: callx8 a8 */
  MEM8(a2 + 18) = a5; /* 0044: s8i a5, a2, 18 */
  MEMW(); /* 0047: memw  */
  a8 = MEM32(a3 + 44); /* 004a: l32i.n a8, a3, 44 */
  MEM32(a2 + 0) = a5; /* 004c: s32i.n a5, a2, 0 */
  a5 = MEM32(a8 + 0); /* 004e: l32i.n a5, a8, 0 */
  if (!((a5 >> 21) & 1)) goto L_7c; /* 0050: bbci a5, 21, 7c <lmacDiscardFrameExchangeSequence+0x5c> */
  a11 = MEM8(a8 + 5); /* 0053: l8ui a11, a8, 5 */
  a11 = a11 + (2); /* 0056: addi.n a11, a11, 2 */
  a11 = (a11 >> 0) & 0xFF; /* 0058: extui a11, a11, 0, 8 */
  a10 = MEM32(a8 + 16); /* 005b: l32i.n a10, a8, 16 */
  a10 = (a10 >> 20) & 0xF; /* 005d: extui a10, a10, 20, 4 */
  MEMW(); /* 0060: memw  */
  a8 = (uint32_t)&ppRecordBarRRC; /* 0063: l32r a8, 10 <lmacDiscardFrameExchangeSequence-0x10> (0 <lmacDiscardFrameExchangeSequence-0x20>) */ /* literal: GOT slot for ppRecordBarRRC */
  ppRecordBarRRC(a2, a3, a4, a5); /* call via literal slot */ /* 0066: callx8 a8 */
  a2 = MEM32(a3 + 44); /* 0069: l32i a2, a3, 44 */
  a10 = MEM32(a2 + 16); /* 006c: l32i a10, a2, 16 */
  a10 = (a10 >> 20) & 0xF; /* 006f: extui a10, a10, 20, 4 */
  a8 = (uint32_t)&ppResortTxAMPDU; /* 0072: l32r a8, 14 <lmacDiscardFrameExchangeSequence-0xc> (0 <lmacDiscardFrameExchangeSequence-0x20>) */ /* literal: GOT slot for ppResortTxAMPDU */
  ppResortTxAMPDU(a2, a3, a4, a5); /* call via literal slot */ /* 0075: callx8 a8 */
  goto L_b4; /* 0078: j b4 <lmacDiscardFrameExchangeSequence+0x94> */
  /* 007b: .byte 00 */
L_7c:;
  if (!((a5 >> 22) & 1)) goto L_8c; /* 007c: bbci a5, 22, 8c <lmacDiscardFrameExchangeSequence+0x6c> */
  a11 = a4; /* 007f: mov.n a11, a4 */
  a10 = a3; /* 0081: mov.n a10, a3 */
  a8 = (uint32_t)&ppRecycleAmpdu; /* 0083: l32r a8, 18 <lmacDiscardFrameExchangeSequence-0x8> (0 <lmacDiscardFrameExchangeSequence-0x20>) */ /* literal: GOT slot for ppRecycleAmpdu */
  ppRecycleAmpdu(a2, a3, a4, a5); /* call via literal slot */ /* 0086: callx8 a8 */
  goto L_b4; /* 0089: j b4 <lmacDiscardFrameExchangeSequence+0x94> */
L_8c:;
  a5 = (uint32_t)&lmacConfMib; /* 008c: l32r a5, 8 <lmacDiscardFrameExchangeSequence-0x18> (0 <lmacDiscardFrameExchangeSequence-0x20>) */ /* literal @0x8: lmacConfMib */
  a13 = a4; /* 008f: mov.n a13, a4 */
  a12 = 0x2; /* 0091: movi.n a12, 2 */
  a10 = MEM8(a8 + 6); /* 0093: l8ui a10, a8, 6 */
  a9 = MEM8(a5 + 21); /* 0096: l8ui a9, a5, 21 */
  if (a10 >= a9) goto L_aa; /* 0099: bgeu a10, a9, aa <lmacDiscardFrameExchangeSequence+0x8a> */
  a12 = 0x3; /* 009c: movi.n a12, 3 */
  a8 = MEM8(a8 + 7); /* 009e: l8ui a8, a8, 7 */
  a5 = MEM8(a5 + 20); /* 00a1: l8ui a5, a5, 20 */
  if (a8 >= a5) goto L_aa; /* 00a4: bgeu a8, a5, aa <lmacDiscardFrameExchangeSequence+0x8a> */
  a12 = 0x4; /* 00a7: movi a12, 4 */
L_aa:;
  a11 = a3; /* 00aa: mov.n a11, a3 */
  a10 = a2; /* 00ac: mov.n a10, a2 */
  a8 = (uint32_t)&lmacDiscardMSDU; /* 00ae: l32r a8, 1c <lmacDiscardFrameExchangeSequence-0x4> (0 <lmacDiscardFrameExchangeSequence-0x20>) */ /* literal: GOT slot for lmacDiscardMSDU */
  lmacDiscardMSDU(a2, a3, a4, a5); /* call via literal slot */ /* 00b1: callx8 a8 */
L_b4:;
  return (int32_t)a2; /* 00b4: retw.n  */
}

/* lmacRecycleMPDU @ lmac.o 00000004 size 35B bind GLOBAL
 * Calls: lmacTxDone[got] | Data refs: lmacTxDone
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 1 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t lmacRecycleMPDU(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .wifi0iram.9; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a8 = MEM32(a2 + 28); /* 0007: l32i.n a8, a2, 28 */
  a10 = a3; /* 0009: mov.n a10, a3 */
  a8 = a8 + (1); /* 000b: addi.n a8, a8, 1 */
  a11 = (a4 >> 0) & 0xFF; /* 000d: extui a11, a4, 0, 8 */
  MEM32(a2 + 28) = a8; /* 0010: s32i.n a8, a2, 28 */
  a8 = 0x1; /* 0012: movi.n a8, 1 */
  a2 = MEM32(a3 + 44); /* 0014: l32i.n a2, a3, 44 */
  MEM8(a2 + 19) = a8; /* 0016: s8i a8, a2, 19 */
  MEMW(); /* 0019: memw  */
  MEMW(); /* 001c: memw  */
  a8 = (uint32_t)&lmacTxDone; /* 001f: l32r a8, 0 <lmacRecycleMPDU-0x4> (0 <lmacRecycleMPDU-0x4>) */ /* literal: GOT slot for lmacTxDone */
  lmacTxDone(a2, a3, a4, a5); /* call via literal slot */ /* 0022: callx8 a8 */
  return (int32_t)a2; /* 0025: retw.n  */
}

/* lmacEndFrameExchangeSequence @ lmac.o 0000006c size 682B bind GLOBAL
 * Calls: wifi_assert[got], ppRecordBarRRC[got], ppResortTxAMPDU[got], ppRecycleAmpdu[got], lmacDiscardMSDU[got], wifi_assert[got], memset[got], hal_mac_tx_get_blockack[got], hal_mac_tx_is_cbw40[got], ppTxqUpdateBitmap[got], ppRecycleAmpdu[got], ppResortTxAMPDU[got], wifi_assert[got], trc_isTxAmpduOperational[got], ppReSendBar[got], ppRegressAmpdu[got], lmacRecycleMPDU[got], wifi_assert[got], wifi_assert[got], lmacRetryTxFrame[got], lmacIsLongFrame[got], lmacRetryTxFrame[got], lmacEndRetryAMPDUFail[got] | Data refs: .rodata.__FUNCTION__$10, .rodata.lmacProcessTxopSuccess.str1.1, wifi_assert, ppRecordBarRRC, ppResortTxAMPDU, ppRecycleAmpdu, lmacConfMib, lmacDiscardMSDU, memset, hal_mac_tx_get_blockack, pTxRx, hal_mac_tx_is_cbw40, ppTxqUpdateBitmap, trc_isTxAmpduOperational, ppReSendBar, ppRegressAmpdu, lmacRecycleMPDU, lmacRetryTxFrame, lmacIsLongFrame, lmacEndRetryAMPDUFail
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 23 call(s), 20 data ref(s)
 * Fidelity: low - 262 instr, 34 branches, 0 indirect; call-sequence + MMIO skeleton */
int32_t lmacEndFrameExchangeSequence(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .wifi0iram.11; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_6c:;
  /* 006c: entry a1, 48 */
  a4 = (a4 >> 0) & 0xFF; /* 006f: extui a4, a4, 0, 8 */
  a8 = MEM8(a2 + 18); /* 0072: l8ui a8, a2, 18 */
  a3 = (a3 >> 0) & 0xFF; /* 0075: extui a3, a3, 0, 8 */
  if (a4 != 0) goto L_289; /* 0078: bnez a4, 289 <lmacEndFrameExchangeSequence+0x21d> */
  if (a8 == 6) goto L_81; /* 007b: beqi a8, 6, 81 <lmacEndFrameExchangeSequence+0x15> */
  goto L_128; /* 007e: j 128 <lmacEndFrameExchangeSequence+0xbc> */
L_81:;
  MEM8(a2 + 18) = a4; /* 0081: s8i a4, a2, 18 */
  MEMW(); /* 0084: memw  */
  a4 = 0xA; /* 0087: movi.n a4, 10 */
  a5 = MEM32(a2 + 0); /* 0089: l32i.n a5, a2, 0 */
  if (a3 != 0) goto L_a6; /* 008b: bnez.n a3, a6 <lmacEndFrameExchangeSequence+0x3a> */
  a10 = 0x1; /* 008d: movi.n a10, 1 */
  a13 = 0x48A; /* 008f: movi a13, 0x48a */
  if (a5 == 0) a10 = a3; /* 0092: moveqz a10, a3, a5 */
  a12 = (uint32_t)&lit_rodata_FUNCTION_10; /* 0095: l32r a12, 0 <lmacEndFrameExchangeSequence-0x6c> (0 <lmacEndFrameExchangeSequence-0x6c>) */ /* literal @0x0: .rodata.__FUNCTION__$10 */
  a4 = 0x9; /* 0098: movi.n a4, 9 */
  a11 = (uint32_t)&lit_rodata_lmacProcessTxopSuccess_str1_1; /* 009a: l32r a11, 4 <lmacEndFrameExchangeSequence-0x68> (0 <lmacEndFrameExchangeSequence-0x6c>) */ /* literal @0x4: .rodata.lmacProcessTxopSuccess.str1.1 */
  MEMW(); /* 009d: memw  */
  a8 = (uint32_t)&wifi_assert; /* 00a0: l32r a8, 10 <lmacEndFrameExchangeSequence-0x5c> (0 <lmacEndFrameExchangeSequence-0x6c>) */ /* literal: GOT slot for wifi_assert */
  wifi_assert(a2, a3, a4, a5); /* call via literal slot */ /* 00a3: callx8 a8 */
L_a6:;
  a11 = 0x1; /* 00a6: movi.n a11, 1 */
  MEM8(a2 + 19) = a4; /* 00a8: s8i a4, a2, 19 */
  MEMW(); /* 00ab: memw  */
  a3 = MEM32(a5 + 44); /* 00ae: l32i.n a3, a5, 44 */
  a4 = MEM32(a3 + 0); /* 00b0: l32i a4, a3, 0 */
  if (!((a4 >> 21) & 1)) goto L_e0; /* 00b3: bbci a4, 21, e0 <lmacEndFrameExchangeSequence+0x74> */
  a11 = MEM8(a3 + 5); /* 00b6: l8ui a11, a3, 5 */
  a11 = a11 + (2); /* 00b9: addi a11, a11, 2 */
  a11 = (a11 >> 0) & 0xFF; /* 00bc: extui a11, a11, 0, 8 */
  a10 = MEM32(a3 + 16); /* 00bf: l32i.n a10, a3, 16 */
  a10 = (a10 >> 20) & 0xF; /* 00c1: extui a10, a10, 20, 4 */
  MEMW(); /* 00c4: memw  */
  a8 = (uint32_t)&ppRecordBarRRC; /* 00c7: l32r a8, 14 <lmacEndFrameExchangeSequence-0x58> (0 <lmacEndFrameExchangeSequence-0x6c>) */ /* literal: GOT slot for ppRecordBarRRC */
  ppRecordBarRRC(a2, a3, a4, a5); /* call via literal slot */ /* 00ca: callx8 a8 */
  a2 = MEM32(a5 + 44); /* 00cd: l32i a2, a5, 44 */
  a10 = MEM32(a2 + 16); /* 00d0: l32i a10, a2, 16 */
  a10 = (a10 >> 20) & 0xF; /* 00d3: extui a10, a10, 20, 4 */
  a8 = (uint32_t)&ppResortTxAMPDU; /* 00d6: l32r a8, 18 <lmacEndFrameExchangeSequence-0x54> (0 <lmacEndFrameExchangeSequence-0x6c>) */ /* literal: GOT slot for ppResortTxAMPDU */
  ppResortTxAMPDU(a2, a3, a4, a5); /* call via literal slot */ /* 00d9: callx8 a8 */
  goto L_314; /* 00dc: j 314 <lmacEndFrameExchangeSequence+0x2a8> */
  /* 00df: .byte 00 */
L_e0:;
  a6 = a11 << (22 & 31); /* 00e0: slli a6, a11, 22 */
  a4 = a4 & a6; /* 00e3: and a4, a4, a6 */
  if (a4 == 0) goto L_f5; /* 00e6: beqz.n a4, f5 <lmacEndFrameExchangeSequence+0x89> */
  a10 = a5; /* 00e8: mov.n a10, a5 */
  a8 = (uint32_t)&ppRecycleAmpdu; /* 00ea: l32r a8, 1c <lmacEndFrameExchangeSequence-0x50> (0 <lmacEndFrameExchangeSequence-0x6c>) */ /* literal: GOT slot for ppRecycleAmpdu */
  ppRecycleAmpdu(a2, a3, a4, a5); /* call via literal slot */ /* 00ed: callx8 a8 */
  goto L_314; /* 00f0: j 314 <lmacEndFrameExchangeSequence+0x2a8> */
  /* 00f3: .byte 00 */
  /* 00f4: .byte 00 */
L_f5:;
  a6 = MEM8(a2 + 18); /* 00f5: l8ui a6, a2, 18 */
  a13 = a4; /* 00f8: mov.n a13, a4 */
  if (a6 == 0) a13 = a11; /* 00fa: moveqz a13, a11, a6 */
  a12 = 0x2; /* 00fd: movi.n a12, 2 */
  a4 = (uint32_t)&lmacConfMib; /* 00ff: l32r a4, 8 <lmacEndFrameExchangeSequence-0x64> (0 <lmacEndFrameExchangeSequence-0x6c>) */ /* literal @0x8: lmacConfMib */
  a7 = MEM8(a3 + 6); /* 0102: l8ui a7, a3, 6 */
  a6 = MEM8(a4 + 21); /* 0105: l8ui a6, a4, 21 */
  if (a7 >= a6) goto L_11a; /* 0108: bgeu a7, a6, 11a <lmacEndFrameExchangeSequence+0xae> */
  a12 = 0x4; /* 010b: movi a12, 4 */
  a6 = MEM8(a3 + 7); /* 010e: l8ui a6, a3, 7 */
  a3 = MEM8(a4 + 20); /* 0111: l8ui a3, a4, 20 */
  if (a6 < a3) goto L_11a; /* 0114: bltu a6, a3, 11a <lmacEndFrameExchangeSequence+0xae> */
  a12 = 0x3; /* 0117: movi a12, 3 */
L_11a:;
  a11 = a5; /* 011a: mov.n a11, a5 */
  a10 = a2; /* 011c: mov.n a10, a2 */
  a8 = (uint32_t)&lmacDiscardMSDU; /* 011e: l32r a8, 20 <lmacEndFrameExchangeSequence-0x4c> (0 <lmacEndFrameExchangeSequence-0x6c>) */ /* literal: GOT slot for lmacDiscardMSDU */
  lmacDiscardMSDU(a2, a3, a4, a5); /* call via literal slot */ /* 0121: callx8 a8 */
  goto L_314; /* 0124: j 314 <lmacEndFrameExchangeSequence+0x2a8> */
  /* 0127: .byte 00 */
L_128:;
  a6 = (uint32_t)&lit_rodata_FUNCTION_10; /* 0128: l32r a6, 0 <lmacEndFrameExchangeSequence-0x6c> (0 <lmacEndFrameExchangeSequence-0x6c>) */ /* literal @0x0: .rodata.__FUNCTION__$10 */
  a5 = (uint32_t)&lit_rodata_lmacProcessTxopSuccess_str1_1; /* 012b: l32r a5, 4 <lmacEndFrameExchangeSequence-0x68> (0 <lmacEndFrameExchangeSequence-0x6c>) */ /* literal @0x4: .rodata.lmacProcessTxopSuccess.str1.1 */
  if (a8 == 5) goto L_134; /* 012e: beqi a8, 5, 134 <lmacEndFrameExchangeSequence+0xc8> */
  goto L_275; /* 0131: j 275 <lmacEndFrameExchangeSequence+0x209> */
L_134:;
  a3 = 0x1; /* 0134: movi.n a3, 1 */
  a8 = a4; /* 0136: mov.n a8, a4 */
  a11 = a5; /* 0138: mov.n a11, a5 */
  a10 = MEM32(a2 + 0); /* 013a: l32i.n a10, a2, 0 */
  a13 = 0x4AA; /* 013c: movi a13, 0x4aa */
  if (a10 != 0) a8 = a3; /* 013f: movnez a8, a3, a10 */
  a10 = a8; /* 0142: mov.n a10, a8 */
  a12 = a6; /* 0144: mov.n a12, a6 */
  MEM8(a2 + 18) = a4; /* 0146: s8i a4, a2, 18 */
  MEMW(); /* 0149: memw  */
  MEMW(); /* 014c: memw  */
  a8 = (uint32_t)&wifi_assert; /* 014f: l32r a8, 24 <lmacEndFrameExchangeSequence-0x48> (0 <lmacEndFrameExchangeSequence-0x6c>) */ /* literal: GOT slot for wifi_assert */
  wifi_assert(a2, a3, a4, a5); /* call via literal slot */ /* 0152: callx8 a8 */
  a10 = a3 << (19 & 31); /* 0155: slli a10, a3, 19 */
  a11 = MEM32(a2 + 0); /* 0158: l32i.n a11, a2, 0 */
  a7 = MEM32(a11 + 44); /* 015a: l32i.n a7, a11, 44 */
  a8 = MEM32(a7 + 0); /* 015c: l32i.n a8, a7, 0 */
  a10 = a8 & a10; /* 015e: and a10, a8, a10 */
  if (a10 == 0) goto L_209; /* 0161: beqz a10, 209 <lmacEndFrameExchangeSequence+0x19d> */
  a11 = a4; /* 0164: mov.n a11, a4 */
  a12 = 0xC; /* 0166: movi.n a12, 12 */
  a10 = a1; /* 0168: mov.n a10, a1 */
  a8 = (uint32_t)&memset; /* 016a: l32r a8, 28 <lmacEndFrameExchangeSequence-0x44> (0 <lmacEndFrameExchangeSequence-0x6c>) */ /* literal: GOT slot for memset */
  memset(a2, a3, a4, a5); /* call via literal slot */ /* 016d: callx8 a8 */
  a4 = MEM32(a7 + 4); /* 0170: l32i.n a4, a7, 4 */
  a11 = a1; /* 0172: mov.n a11, a1 */
  a4 = (a4 >> 0) & 0xF; /* 0174: extui a4, a4, 0, 4 */
  a3 = a3 << (21 & 31); /* 0177: slli a3, a3, 21 */
  a10 = MEM8(a2 + 4); /* 017a: l8ui a10, a2, 4 */
  MEM8(a1 + 0) = a4; /* 017d: s8i a4, a1, 0 */
  MEMW(); /* 0180: memw  */
  MEMW(); /* 0183: memw  */
  a8 = (uint32_t)&hal_mac_tx_get_blockack; /* 0186: l32r a8, 2c <lmacEndFrameExchangeSequence-0x40> (0 <lmacEndFrameExchangeSequence-0x6c>) */ /* literal: GOT slot for hal_mac_tx_get_blockack */
  hal_mac_tx_get_blockack(a2, a3, a4, a5); /* call via literal slot */ /* 0189: callx8 a8 */
  a4 = MEM32(a2 + 0); /* 018c: l32i.n a4, a2, 0 */
  a5 = MEM32(a4 + 44); /* 018e: l32i.n a5, a4, 44 */
  a4 = MEM32(a5 + 0); /* 0190: l32i.n a4, a5, 0 */
  a4 = a4 & a3; /* 0192: and a4, a4, a3 */
  a10 = MEM32(a5 + 16); /* 0195: l32i.n a10, a5, 16 */
  if (a4 != 0) goto L_1c6; /* 0197: bnez.n a4, 1c6 <lmacEndFrameExchangeSequence+0x15a> */
  a3 = (uint32_t)&pTxRx; /* 0199: l32r a3, c <lmacEndFrameExchangeSequence-0x60> (0 <lmacEndFrameExchangeSequence-0x6c>) */ /* literal @0xC: pTxRx */
  a5 = MEM32(a3 + 0); /* 019c: l32i.n a5, a3, 0 */
  a3 = (a10 >> 20) & 0xF; /* 019e: extui a3, a10, 20, 4 */
  a3 = (a3 << 2) + a3; /* 01a1: addx2 a3, a3, a3 */
  a3 = a3 << (4 & 31); /* 01a4: slli a3, a3, 4 */
  a5 = a5 + a3; /* 01a7: add.n a5, a5, a3 */
  a10 = MEM8(a2 + 4); /* 01a9: l8ui a10, a2, 4 */
  a8 = (uint32_t)&hal_mac_tx_is_cbw40; /* 01ac: l32r a8, 30 <lmacEndFrameExchangeSequence-0x3c> (0 <lmacEndFrameExchangeSequence-0x6c>) */ /* literal: GOT slot for hal_mac_tx_is_cbw40 */
  hal_mac_tx_is_cbw40(a2, a3, a4, a5); /* call via literal slot */ /* 01af: callx8 a8 */
  a14 = a4; /* 01b2: mov.n a14, a4 */
  a3 = MEM32(a2 + 0); /* 01b4: l32i.n a3, a2, 0 */
  a3 = MEM32(a3 + 44); /* 01b6: l32i.n a3, a3, 44 */
  MEM8(a5 + 77) = a10; /* 01b8: s8i a10, a5, 77 */
  MEMW(); /* 01bb: memw  */
  a10 = MEM32(a3 + 16); /* 01be: l32i.n a10, a3, 16 */
  MEMW(); /* 01c0: memw  */
  goto L_1ce; /* 01c3: j 1ce <lmacEndFrameExchangeSequence+0x162> */
L_1c6:;
  a14 = MEM8(a5 + 5); /* 01c6: l8ui a14, a5, 5 */
  a14 = a14 + (1); /* 01c9: addi.n a14, a14, 1 */
  a14 = (a14 >> 0) & 0xFF; /* 01cb: extui a14, a14, 0, 8 */
L_1ce:;
  a10 = (a10 >> 20) & 0xF; /* 01ce: extui a10, a10, 20, 4 */
  a13 = MEM32(a1 + 8); /* 01d1: l32i.n a13, a1, 8 */
  a12 = MEM32(a1 + 4); /* 01d3: l32i.n a12, a1, 4 */
  a11 = MEM16(a1 + 2); /* 01d5: l16ui a11, a1, 2 */
  a8 = (uint32_t)&ppTxqUpdateBitmap; /* 01d8: l32r a8, 34 <lmacEndFrameExchangeSequence-0x38> (0 <lmacEndFrameExchangeSequence-0x6c>) */ /* literal: GOT slot for ppTxqUpdateBitmap */
  ppTxqUpdateBitmap(a2, a3, a4, a5); /* call via literal slot */ /* 01db: callx8 a8 */
  a10 = MEM32(a2 + 0); /* 01de: l32i.n a10, a2, 0 */
  a3 = MEM32(a10 + 44); /* 01e0: l32i.n a3, a10, 44 */
  a4 = MEM32(a3 + 0); /* 01e2: l32i.n a4, a3, 0 */
  if (!((a4 >> 17) & 1)) goto L_1f9; /* 01e4: bbci a4, 17, 1f9 <lmacEndFrameExchangeSequence+0x18d> */
  a4 = MEM8(a10 + 26); /* 01e7: l8ui a4, a10, 26 */
  if (a4 == 5) goto L_1f9; /* 01ea: beqi a4, 5, 1f9 <lmacEndFrameExchangeSequence+0x18d> */
  a11 = 0x1; /* 01ed: movi.n a11, 1 */
  a8 = (uint32_t)&ppRecycleAmpdu; /* 01ef: l32r a8, 38 <lmacEndFrameExchangeSequence-0x34> (0 <lmacEndFrameExchangeSequence-0x6c>) */ /* literal: GOT slot for ppRecycleAmpdu */
  ppRecycleAmpdu(a2, a3, a4, a5); /* call via literal slot */ /* 01f2: callx8 a8 */
  goto L_204; /* 01f5: j 204 <lmacEndFrameExchangeSequence+0x198> */
  /* 01f8: .byte 00 */
L_1f9:;
  a10 = MEM32(a3 + 16); /* 01f9: l32i.n a10, a3, 16 */
  a10 = (a10 >> 20) & 0xF; /* 01fb: extui a10, a10, 20, 4 */
  a8 = (uint32_t)&ppResortTxAMPDU; /* 01fe: l32r a8, 3c <lmacEndFrameExchangeSequence-0x30> (0 <lmacEndFrameExchangeSequence-0x6c>) */ /* literal: GOT slot for ppResortTxAMPDU */
  ppResortTxAMPDU(a2, a3, a4, a5); /* call via literal slot */ /* 0201: callx8 a8 */
L_204:;
  a3 = 0x1; /* 0204: movi.n a3, 1 */
  goto L_2fe; /* 0206: j 2fe <lmacEndFrameExchangeSequence+0x292> */
L_209:;
  if (!((a8 >> 22) & 1)) goto L_25c; /* 0209: bbci a8, 22, 25c <lmacEndFrameExchangeSequence+0x1f0> */
  a4 = 0x2; /* 020c: movi.n a4, 2 */
  a13 = 0x4C9; /* 020e: movi a13, 0x4c9 */
  a12 = a6 | a6; /* 0211: or a12, a6, a6 */
  a11 = a5 | a5; /* 0214: or a11, a5, a5 */
  a8 = (uint32_t)&wifi_assert; /* 0217: l32r a8, 40 <lmacEndFrameExchangeSequence-0x2c> (0 <lmacEndFrameExchangeSequence-0x6c>) */ /* literal: GOT slot for wifi_assert */
  wifi_assert(a2, a3, a4, a5); /* call via literal slot */ /* 021a: callx8 a8 */
  MEM8(a2 + 19) = a4; /* 021d: s8i a4, a2, 19 */
  MEMW(); /* 0220: memw  */
  a4 = MEM32(a2 + 0); /* 0223: l32i a4, a2, 0 */
  a10 = MEM32(a4 + 36); /* 0226: l32i a10, a4, 36 */
  MEMW(); /* 0229: memw  */
  a8 = (uint32_t)&trc_isTxAmpduOperational; /* 022c: l32r a8, 44 <lmacEndFrameExchangeSequence-0x28> (0 <lmacEndFrameExchangeSequence-0x6c>) */ /* literal: GOT slot for trc_isTxAmpduOperational */
  trc_isTxAmpduOperational(a2, a3, a4, a5); /* call via literal slot */ /* 022f: callx8 a8 */
  if (a10 == 0) goto L_24e; /* 0232: beqz.n a10, 24e <lmacEndFrameExchangeSequence+0x1e2> */
  a2 = MEM32(a2 + 0); /* 0234: l32i.n a2, a2, 0 */
  a2 = MEM32(a2 + 44); /* 0236: l32i.n a2, a2, 44 */
  a11 = MEM32(a2 + 16); /* 0238: l32i.n a11, a2, 16 */
  a11 = (a11 >> 20) & 0xF; /* 023a: extui a11, a11, 20, 4 */
  a10 = MEM32(a2 + 4); /* 023d: l32i.n a10, a2, 4 */
  a10 = (a10 >> 0) & 0xF; /* 023f: extui a10, a10, 0, 4 */
  a8 = (uint32_t)&ppReSendBar; /* 0242: l32r a8, 48 <lmacEndFrameExchangeSequence-0x24> (0 <lmacEndFrameExchangeSequence-0x6c>) */ /* literal: GOT slot for ppReSendBar */
  ppReSendBar(a2, a3, a4, a5); /* call via literal slot */ /* 0245: callx8 a8 */
  goto L_314; /* 0248: j 314 <lmacEndFrameExchangeSequence+0x2a8> */
  /* 024b: .byte 00 */
  /* 024c: .byte 00 */
  /* 024d: .byte 00 */
L_24e:;
  a10 = MEM32(a2 + 0); /* 024e: l32i.n a10, a2, 0 */
  a11 = a3; /* 0250: mov.n a11, a3 */
  a8 = (uint32_t)&ppRegressAmpdu; /* 0252: l32r a8, 4c <lmacEndFrameExchangeSequence-0x20> (0 <lmacEndFrameExchangeSequence-0x6c>) */ /* literal: GOT slot for ppRegressAmpdu */
  ppRegressAmpdu(a2, a3, a4, a5); /* call via literal slot */ /* 0255: callx8 a8 */
  goto L_314; /* 0258: j 314 <lmacEndFrameExchangeSequence+0x2a8> */
  /* 025b: .byte 00 */
L_25c:;
  a4 = 0x3; /* 025c: movi.n a4, 3 */
  MEM8(a2 + 19) = a4; /* 025e: s8i a4, a2, 19 */
  MEMW(); /* 0261: memw  */
  a12 = a3; /* 0264: mov.n a12, a3 */
  a10 = a2; /* 0266: mov.n a10, a2 */
  MEMW(); /* 0268: memw  */
  a8 = (uint32_t)&lmacRecycleMPDU; /* 026b: l32r a8, 50 <lmacEndFrameExchangeSequence-0x1c> (0 <lmacEndFrameExchangeSequence-0x6c>) */ /* literal: GOT slot for lmacRecycleMPDU */
  lmacRecycleMPDU(a2, a3, a4, a5); /* call via literal slot */ /* 026e: callx8 a8 */
  goto L_314; /* 0271: j 314 <lmacEndFrameExchangeSequence+0x2a8> */
  /* 0274: .byte 00 */
L_275:;
  a13 = 0x4D8; /* 0275: movi a13, 0x4d8 */
  a12 = a6; /* 0278: mov.n a12, a6 */
  a11 = a5; /* 027a: mov.n a11, a5 */
  a10 = a4; /* 027c: mov.n a10, a4 */
  a8 = (uint32_t)&wifi_assert; /* 027e: l32r a8, 54 <lmacEndFrameExchangeSequence-0x18> (0 <lmacEndFrameExchangeSequence-0x6c>) */ /* literal: GOT slot for wifi_assert */
  wifi_assert(a2, a3, a4, a5); /* call via literal slot */ /* 0281: callx8 a8 */
  goto L_314; /* 0284: j 314 <lmacEndFrameExchangeSequence+0x2a8> */
  /* 0287: .byte 00 */
  /* 0288: .byte 00 */
L_289:;
  a8 = a8 + (-1); /* 0289: addi.n a8, a8, -1 */
  a8 = (a8 >> 0) & 0xFF; /* 028b: extui a8, a8, 0, 8 */
  a10 = 0x1; /* 028e: movi.n a10, 1 */
  if (a8 < 2) goto L_295; /* 0290: bltui a8, 2, 295 <lmacEndFrameExchangeSequence+0x229> */
  a10 = 0x0; /* 0293: movi.n a10, 0 */
L_295:;
  a12 = (uint32_t)&lit_rodata_FUNCTION_10; /* 0295: l32r a12, 0 <lmacEndFrameExchangeSequence-0x6c> (0 <lmacEndFrameExchangeSequence-0x6c>) */ /* literal @0x0: .rodata.__FUNCTION__$10 */
  a13 = 0x4DB; /* 0298: movi a13, 0x4db */
  a11 = (uint32_t)&lit_rodata_lmacProcessTxopSuccess_str1_1; /* 029b: l32r a11, 4 <lmacEndFrameExchangeSequence-0x68> (0 <lmacEndFrameExchangeSequence-0x6c>) */ /* literal @0x4: .rodata.lmacProcessTxopSuccess.str1.1 */
  a8 = (uint32_t)&wifi_assert; /* 029e: l32r a8, 58 <lmacEndFrameExchangeSequence-0x14> (0 <lmacEndFrameExchangeSequence-0x6c>) */ /* literal: GOT slot for wifi_assert */
  wifi_assert(a2, a3, a4, a5); /* call via literal slot */ /* 02a1: callx8 a8 */
  if (a3 != 0) goto L_2c1; /* 02a4: bnez.n a3, 2c1 <lmacEndFrameExchangeSequence+0x255> */
  a4 = 0x3; /* 02a6: movi.n a4, 3 */
  a11 = a3; /* 02a8: mov.n a11, a3 */
  MEM8(a2 + 18) = a4; /* 02aa: s8i a4, a2, 18 */
  MEMW(); /* 02ad: memw  */
  a10 = a2 | a2; /* 02b0: or a10, a2, a2 */
  MEMW(); /* 02b3: memw  */
  a8 = (uint32_t)&lmacRetryTxFrame; /* 02b6: l32r a8, 5c <lmacEndFrameExchangeSequence-0x10> (0 <lmacEndFrameExchangeSequence-0x6c>) */ /* literal: GOT slot for lmacRetryTxFrame */
  lmacRetryTxFrame(a2, a3, a4, a5); /* call via literal slot */ /* 02b9: callx8 a8 */
  a3 = 0x5; /* 02bc: movi.n a3, 5 */
  goto L_2fe; /* 02be: j 2fe <lmacEndFrameExchangeSequence+0x292> */
L_2c1:;
  a3 = MEM32(a2 + 0); /* 02c1: l32i.n a3, a2, 0 */
  a4 = MEM32(a3 + 44); /* 02c3: l32i.n a4, a3, 44 */
  a5 = MEM32(a4 + 0); /* 02c5: l32i.n a5, a4, 0 */
  if (!((a5 >> 22) & 1)) goto L_2e6; /* 02c7: bbci a5, 22, 2e6 <lmacEndFrameExchangeSequence+0x27a> */
  a5 = (uint32_t)&lmacConfMib; /* 02ca: l32r a5, 8 <lmacEndFrameExchangeSequence-0x64> (0 <lmacEndFrameExchangeSequence-0x6c>) */ /* literal @0x8: lmacConfMib */
  a4 = MEM8(a4 + 5); /* 02cd: l8ui a4, a4, 5 */
  a6 = MEM8(a5 + 43); /* 02d0: l8ui a6, a5, 43 */
  if (a4 < a6) goto L_2e6; /* 02d3: bltu a4, a6, 2e6 <lmacEndFrameExchangeSequence+0x27a> */
  a10 = a3; /* 02d6: mov.n a10, a3 */
  a8 = (uint32_t)&lmacIsLongFrame; /* 02d8: l32r a8, 60 <lmacEndFrameExchangeSequence-0xc> (0 <lmacEndFrameExchangeSequence-0x6c>) */ /* literal: GOT slot for lmacIsLongFrame */
  lmacIsLongFrame(a2, a3, a4, a5); /* call via literal slot */ /* 02db: callx8 a8 */
  if (a10 != 0) goto L_30a; /* 02de: bnez.n a10, 30a <lmacEndFrameExchangeSequence+0x29e> */
  a5 = MEM8(a5 + 44); /* 02e0: l8ui a5, a5, 44 */
  if (a4 >= a5) goto L_30a; /* 02e3: bgeu a4, a5, 30a <lmacEndFrameExchangeSequence+0x29e> */
L_2e6:;
  a3 = 0x3; /* 02e6: movi.n a3, 3 */
  a11 = 0x0; /* 02e8: movi.n a11, 0 */
  MEM8(a2 + 18) = a3; /* 02ea: s8i a3, a2, 18 */
  MEMW(); /* 02ed: memw  */
  a10 = a2 | a2; /* 02f0: or a10, a2, a2 */
  MEMW(); /* 02f3: memw  */
  a8 = (uint32_t)&lmacRetryTxFrame; /* 02f6: l32r a8, 64 <lmacEndFrameExchangeSequence-0x8> (0 <lmacEndFrameExchangeSequence-0x6c>) */ /* literal: GOT slot for lmacRetryTxFrame */
  lmacRetryTxFrame(a2, a3, a4, a5); /* call via literal slot */ /* 02f9: callx8 a8 */
  a3 = 0x7; /* 02fc: movi.n a3, 7 */
L_2fe:;
  MEM8(a2 + 19) = a3; /* 02fe: s8i a3, a2, 19 */
  MEMW(); /* 0301: memw  */
  MEMW(); /* 0304: memw  */
  goto L_314; /* 0307: j 314 <lmacEndFrameExchangeSequence+0x2a8> */
L_30a:;
  a11 = 0x7; /* 030a: mov.n a11, a3 */
  a10 = a2; /* 030c: mov.n a10, a2 */
  a8 = (uint32_t)&lmacEndRetryAMPDUFail; /* 030e: l32r a8, 68 <lmacEndFrameExchangeSequence-0x4> (0 <lmacEndFrameExchangeSequence-0x6c>) */ /* literal: GOT slot for lmacEndRetryAMPDUFail */
  lmacEndRetryAMPDUFail(a2, a3, a4, a5); /* call via literal slot */ /* 0311: callx8 a8 */
L_314:;
  return (int32_t)a2; /* 0314: retw.n  */
}

/* lmacProcessTBSuccess @ lmac.o 00000014 size 66B bind GLOBAL
 * Calls: wifi_assert[got], lmacEndFrameExchangeSequence[got] | Data refs: .rodata.__FUNCTION__$13, .rodata.lmacProcessTxopSuccess.str1.1, wifi_assert, .bss.our_instances, lmacEndFrameExchangeSequence
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 2 call(s), 5 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t lmacProcessTBSuccess(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .wifi0iram.5; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_14:;
  /* 0014: entry a1, 32 */
  a2 = (a2 >> 0) & 0xFF; /* 0017: extui a2, a2, 0, 8 */
  a10 = 0x1; /* 001a: movi.n a10, 1 */
  if (a2 < 4) goto L_21; /* 001c: bltui a2, 4, 21 <lmacProcessTBSuccess+0xd> */
  a10 = 0x0; /* 001f: movi.n a10, 0 */
L_21:;
  a12 = (uint32_t)&lit_rodata_FUNCTION_13; /* 0021: l32r a12, 0 <lmacProcessTBSuccess-0x14> (0 <lmacProcessTBSuccess-0x14>) */ /* literal @0x0: .rodata.__FUNCTION__$13 */
  a13 = 0x29D; /* 0024: movi a13, 0x29d */
  a11 = (uint32_t)&lit_rodata_lmacProcessTxopSuccess_str1_1; /* 0027: l32r a11, 4 <lmacProcessTBSuccess-0x10> (0 <lmacProcessTBSuccess-0x14>) */ /* literal @0x4: .rodata.lmacProcessTxopSuccess.str1.1 */
  a8 = (uint32_t)&wifi_assert; /* 002a: l32r a8, c <lmacProcessTBSuccess-0x8> (0 <lmacProcessTBSuccess-0x14>) */ /* literal: GOT slot for wifi_assert */
  wifi_assert(a2, a3, a4, a5); /* call via literal slot */ /* 002d: callx8 a8 */
  a8 = (a2 << 8) + a2; /* 0030: addx8 a8, a2, a2 */
  a9 = 0x5; /* 0033: movi.n a9, 5 */
  a10 = (uint32_t)&bss_our_instances; /* 0035: l32r a10, 8 <lmacProcessTBSuccess-0xc> (0 <lmacProcessTBSuccess-0x14>) */ /* literal @0x8: .bss.our_instances */
  a12 = 0x0; /* 0038: movi.n a12, 0 */
  a8 = (a8 << 4) + a10; /* 003a: addx4 a8, a8, a10 */
  a11 = 0x1; /* 003d: movi.n a11, 1 */
  a10 = a8 | a8; /* 003f: or a10, a8, a8 */
  MEM8(a8 + 18) = a9; /* 0042: s8i a9, a8, 18 */
  MEMW(); /* 0045: memw  */
  a2 = (a2 << 8) + a2; /* 0048: addx8 a2, a2, a2 */
  MEMW(); /* 004b: memw  */
  a8 = (uint32_t)&lmacEndFrameExchangeSequence; /* 004e: l32r a8, 10 <lmacProcessTBSuccess-0x4> (0 <lmacProcessTBSuccess-0x14>) */ /* literal: GOT slot for lmacEndFrameExchangeSequence */
  lmacEndFrameExchangeSequence(a2, a3, a4, a5); /* call via literal slot */ /* 0051: callx8 a8 */
  return (int32_t)a2; /* 0054: retw.n  */
}

/* lmacProcessTxSuccess @ lmac.o 00000018 size 198B bind GLOBAL
 * Calls: wifi_assert[got], lmacIsLongFrame[got], lmacEndFrameExchangeSequence[got] | Data refs: .rodata.lmacProcessTxopSuccess.str1.1, .rodata.__FUNCTION__$12, wifi_assert, .bss.our_instances, lmacIsLongFrame, lmacEndFrameExchangeSequence
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 3 call(s), 6 data ref(s)
 * Fidelity: medium - 72 instr, 8 branches, calls resolved */
int32_t lmacProcessTxSuccess(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .wifiextrairam.6; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_18:;
  /* 0018: entry a1, 32 */
  a2 = (a2 >> 0) & 0xFF; /* 001b: extui a2, a2, 0, 8 */
  a3 = (a3 >> 0) & 0xFF; /* 001e: extui a3, a3, 0, 8 */
  a10 = 0x1; /* 0021: movi.n a10, 1 */
  if (a2 < 5) goto L_28; /* 0023: bltui a2, 5, 28 <lmacProcessTxSuccess+0x10> */
  a10 = 0x0; /* 0026: movi.n a10, 0 */
L_28:;
  a11 = (uint32_t)&lit_rodata_lmacProcessTxopSuccess_str1_1; /* 0028: l32r a11, 4 <lmacProcessTxSuccess-0x14> (0 <lmacProcessTxSuccess-0x18>) */ /* literal @0x4: .rodata.lmacProcessTxopSuccess.str1.1 */
  a13 = 0x2AC; /* 002b: movi a13, 0x2ac */
  a5 = (a2 << 8) + a2; /* 002e: addx8 a5, a2, a2 */
  a4 = a2 << (3 & 31); /* 0031: slli a4, a2, 3 */
  a12 = (uint32_t)&lit_rodata_FUNCTION_12; /* 0034: l32r a12, 0 <lmacProcessTxSuccess-0x18> (0 <lmacProcessTxSuccess-0x18>) */ /* literal @0x0: .rodata.__FUNCTION__$12 */
  a8 = (uint32_t)&wifi_assert; /* 0037: l32r a8, c <lmacProcessTxSuccess-0xc> (0 <lmacProcessTxSuccess-0x18>) */ /* literal: GOT slot for wifi_assert */
  wifi_assert(a2, a3, a4, a5); /* call via literal slot */ /* 003a: callx8 a8 */
  a11 = 0x402; /* 003d: movi a11, 0x402 */
  a6 = (uint32_t)&bss_our_instances; /* 0040: l32r a6, 8 <lmacProcessTxSuccess-0x10> (0 <lmacProcessTxSuccess-0x18>) */ /* literal @0x8: .bss.our_instances */
  a5 = (a5 << 4) + a6; /* 0043: addx4 a5, a5, a6 */
  a10 = MEM32(a5 + 0); /* 0046: l32i.n a10, a5, 0 */
  a7 = MEM32(a10 + 44); /* 0048: l32i.n a7, a10, 44 */
  a9 = MEM32(a7 + 0); /* 004a: l32i.n a9, a7, 0 */
  a11 = a9 & a11; /* 004c: and a11, a9, a11 */
  if (a11 != 0) goto L_61; /* 004f: bnez.n a11, 61 <lmacProcessTxSuccess+0x49> */
  a12 = 0x9; /* 0051: movi.n a12, 9 */
  a12 = 0x480000; /* 0053: slli a12, a12, 19 */
  a13 = 0x1; /* 0056: movi.n a13, 1 */
  a12 = a9 & a12; /* 0058: and a12, a9, a12 */
  a13 = 0x400000; /* 005b: slli a13, a13, 22 */
  if (a12 != a13) goto L_94; /* 005e: bne a12, a13, 94 <lmacProcessTxSuccess+0x7c> */
L_61:;
  a8 = (uint32_t)&lmacIsLongFrame; /* 0061: l32r a8, 10 <lmacProcessTxSuccess-0x8> (0 <lmacProcessTxSuccess-0x18>) */ /* literal: GOT slot for lmacIsLongFrame */
  lmacIsLongFrame(a2, a3, a4, a5); /* call via literal slot */ /* 0064: callx8 a8 */
  a8 = a4 + a2; /* 0067: add.n a8, a4, a2 */
  a8 = (a8 << 4) + a6; /* 0069: addx4 a8, a8, a6 */
  a3 = MEM8(a8 + 9); /* 006c: l8ui a3, a8, 9 */
  MEM8(a8 + 8) = a3; /* 006f: s8i a3, a8, 8 */
  MEMW(); /* 0072: memw  */
  if (a10 == 0) goto L_85; /* 0075: beqz.n a10, 85 <lmacProcessTxSuccess+0x6d> */
  a3 = 0x0; /* 0077: movi.n a3, 0 */
  MEM8(a8 + 12) = a3; /* 0079: s8i a3, a8, 12 */
  MEMW(); /* 007c: memw  */
  MEMW(); /* 007f: memw  */
  goto L_8b; /* 0082: j 8b <lmacProcessTxSuccess+0x73> */
L_85:;
  MEM8(a8 + 11) = a10; /* 0085: s8i a10, a8, 11 */
  MEMW(); /* 0088: memw  */
L_8b:;
  a3 = 0x7F; /* 008b: movi a3, 127 */
  MEMW(); /* 008e: memw  */
  goto L_b7; /* 0091: j b7 <lmacProcessTxSuccess+0x9f> */
L_94:;
  a10 = MEM8(a5 + 9); /* 0094: l8ui a10, a5, 9 */
  a12 = 0x100; /* 0097: movi a12, 0x100 */
  a9 = a9 & a12; /* 009a: and a9, a9, a12 */
  MEM8(a5 + 8) = a10; /* 009d: s8i a10, a5, 8 */
  MEMW(); /* 00a0: memw  */
  if (a9 != 0) goto L_b1; /* 00a3: bnez.n a9, b1 <lmacProcessTxSuccess+0x99> */
  MEM8(a5 + 11) = a9; /* 00a5: s8i a9, a5, 11 */
  MEMW(); /* 00a8: memw  */
  MEMW(); /* 00ab: memw  */
  goto L_b7; /* 00ae: j b7 <lmacProcessTxSuccess+0x9f> */
L_b1:;
  MEM8(a5 + 11) = a11; /* 00b1: s8i a11, a5, 11 */
  MEM8(a5 + 12) = a11; /* 00b4: s8i a11, a5, 12 */
L_b7:;
  a4 = a4 + a2; /* 00b7: add.n a4, a4, a2 */
  a4 = (a4 << 4) + a6; /* 00b9: addx4 a4, a4, a6 */
  a2 = 0x5; /* 00bc: movi.n a2, 5 */
  a12 = 0x0; /* 00be: movi.n a12, 0 */
  MEM8(a7 + 13) = a3; /* 00c0: s8i a3, a7, 13 */
  a11 = 0x1; /* 00c3: movi.n a11, 1 */
  a10 = a5; /* 00c5: mov.n a10, a5 */
  MEM8(a4 + 18) = a2; /* 00c7: s8i a2, a4, 18 */
  a2 = 0x1; /* 00ca: movi a2, 1 */
  MEM8(a7 + 19) = a2; /* 00cd: s8i a2, a7, 19 */
  MEMW(); /* 00d0: memw  */
  MEMW(); /* 00d3: memw  */
  a8 = (uint32_t)&lmacEndFrameExchangeSequence; /* 00d6: l32r a8, 14 <lmacProcessTxSuccess-0x4> (0 <lmacProcessTxSuccess-0x18>) */ /* literal: GOT slot for lmacEndFrameExchangeSequence */
  lmacEndFrameExchangeSequence(a2, a3, a4, a5); /* call via literal slot */ /* 00d9: callx8 a8 */
  return (int32_t)a2; /* 00dc: retw.n  */
}

/* lmacProcessShortRetryFail @ lmac.o 0000003c size 479B bind GLOBAL
 * Calls: lmacDiscardFrameExchangeSequence, lmacEndFrameExchangeSequence, lmacEndRetryAMPDUFail, lmacIsLongFrame, lmacMSDUAged, lmacRetryTxFrame, rcReachRetryLimit, wifi_assert | Data refs: .rodata.__FUNCTION__$7, .rodata.lmacProcessTxopSuccess.str1.1, lmacConfMib, lmacDiscardFrameExchangeSequence, lmacEndFrameExchangeSequence, lmacEndRetryAMPDUFail, lmacIsLongFrame, lmacMSDUAged, lmacRetryTxFrame, rcReachRetryLimit, wifi_assert
 *   MMIO: none
 *   funcdb v3: 8 call(s), 11 ref(s); disasm: 10 call(s), 11 data ref(s)
 * Fidelity: low - 182 instr, 34 branches, 0 indirect; call-sequence + MMIO skeleton */
int32_t lmacProcessShortRetryFail(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.lmacProcessShortRetryFail; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_3c:;
  /* 003c: entry a1, 48 */
  a6 = (a3 >> 0) & 0xFF; /* 003f: extui a6, a3, 0, 8 */
  a5 = (a5 >> 0) & 0xFF; /* 0042: extui a5, a5, 0, 8 */
  a3 = 0x1; /* 0045: movi.n a3, 1 */
  a4 = (a4 >> 0) & 0xFF; /* 0047: extui a4, a4, 0, 8 */
  a5 = a5 ^ a3; /* 004a: xor a5, a5, a3 */
  a5 = a4 | a5; /* 004d: or a5, a4, a5 */
  a5 = (a5 >> 0) & 0xFF; /* 0050: extui a5, a5, 0, 8 */
  if (a5 != 0) goto L_5a; /* 0053: bnez.n a5, 5a <lmacProcessShortRetryFail+0x1e> */
  a7 = a5; /* 0055: mov.n a7, a5 */
  if (a6 == 0) goto L_5c; /* 0057: beqz a6, 5c <lmacProcessShortRetryFail+0x20> */
L_5a:;
  a7 = MEM32(a2 + 0); /* 005a: l32i.n a7, a2, 0 */
L_5c:;
  a8 = 0x0; /* 005c: movi.n a8, 0 */
  a10 = 0x1; /* 005e: movi.n a10, 1 */
  if (a7 == 0) a10 = a8; /* 0060: moveqz a10, a8, a7 */
  a13 = 0x64D; /* 0063: movi a13, 0x64d */
  a3 = (uint32_t)&lit_rodata_FUNCTION_7; /* 0066: l32r a3, 0 <lmacProcessShortRetryFail-0x3c> (0 <lmacProcessShortRetryFail-0x3c>) */ /* literal @0x0: .rodata.__FUNCTION__$7 */
  a12 = a3; /* 0069: mov.n a12, a3 */
  a11 = (uint32_t)&lit_rodata_lmacProcessTxopSuccess_str1_1; /* 006b: l32r a11, 4 <lmacProcessShortRetryFail-0x38> (0 <lmacProcessShortRetryFail-0x3c>) */ /* literal @0x4: .rodata.lmacProcessTxopSuccess.str1.1 */
  a8 = (uint32_t)&wifi_assert; /* 006e: l32r a8, 14 <lmacProcessShortRetryFail-0x28> (0 <lmacProcessShortRetryFail-0x3c>) */ /* literal: GOT slot for wifi_assert */
  wifi_assert(a2, a3, a4, a5); /* call via literal slot */ /* 0071: callx8 a8 */
  a8 = (uint32_t)&lmacConfMib; /* 0074: l32r a8, 8 <lmacProcessShortRetryFail-0x34> (0 <lmacProcessShortRetryFail-0x3c>) */ /* literal @0x8: lmacConfMib */
  a10 = MEM8(a2 + 11); /* 0077: l8ui a10, a2, 11 */
  a11 = MEM8(a8 + 21); /* 007a: l8ui a11, a8, 21 */
  if (a10 >= a11) goto L_a0; /* 007d: bgeu a10, a11, a0 <lmacProcessShortRetryFail+0x64> */
  a10 = a10 + (1); /* 0080: addi.n a10, a10, 1 */
  a10 = (a10 >> 0) & 0xFF; /* 0082: extui a10, a10, 0, 8 */
  MEM8(a2 + 11) = a10; /* 0085: s8i a10, a2, 11 */
  MEMW(); /* 0088: memw  */
  if (a10 >= a11) goto L_a0; /* 008b: bgeu a10, a11, a0 <lmacProcessShortRetryFail+0x64> */
  a10 = MEM8(a2 + 8); /* 008e: l8ui a10, a2, 8 */
  a11 = MEM8(a2 + 10); /* 0091: l8ui a11, a2, 10 */
  if (a10 >= a11) goto L_a9; /* 0094: bgeu a10, a11, a9 <lmacProcessShortRetryFail+0x6d> */
  a10 = a10 + (1); /* 0097: addi.n a10, a10, 1 */
  MEMW(); /* 0099: memw  */
  goto L_a3; /* 009c: j a3 <lmacProcessShortRetryFail+0x67> */
  /* 009f: .byte 00 */
L_a0:;
  a10 = MEM8(a2 + 9); /* 00a0: l8ui a10, a2, 9 */
L_a3:;
  MEM8(a2 + 8) = a10; /* 00a3: s8i a10, a2, 8 */
  MEMW(); /* 00a6: memw  */
L_a9:;
  a10 = MEM32(a7 + 44); /* 00a9: l32i.n a10, a7, 44 */
  a11 = MEM8(a10 + 6); /* 00ab: l8ui a11, a10, 6 */
  a11 = a11 + (1); /* 00ae: addi.n a11, a11, 1 */
  MEM8(a10 + 6) = a11; /* 00b0: s8i a11, a10, 6 */
  MEMW(); /* 00b3: memw  */
  if (a4 != 0) goto L_c6; /* 00b6: bnez.n a4, c6 <lmacProcessShortRetryFail+0x8a> */
  if (a6 != 0) goto L_c6; /* 00b8: bnez.n a6, c6 <lmacProcessShortRetryFail+0x8a> */
  a11 = MEM8(a10 + 5); /* 00ba: l8ui a11, a10, 5 */
  a11 = a11 + (1); /* 00bd: addi a11, a11, 1 */
  MEM8(a10 + 5) = a11; /* 00c0: s8i a11, a10, 5 */
  MEMW(); /* 00c3: memw  */
L_c6:;
  a10 = 0x1; /* 00c6: movi.n a10, 1 */
  a11 = MEM8(a2 + 18); /* 00c8: l8ui a11, a2, 18 */
  a11 = a11 + (-1); /* 00cb: addi.n a11, a11, -1 */
  a11 = (a11 >> 0) & 0xFF; /* 00cd: extui a11, a11, 0, 8 */
  if (a11 < 2) goto L_d5; /* 00d0: bltui a11, 2, d5 <lmacProcessShortRetryFail+0x99> */
  a10 = 0x0; /* 00d3: movi.n a10, 0 */
L_d5:;
  a11 = (uint32_t)&lit_rodata_lmacProcessTxopSuccess_str1_1; /* 00d5: l32r a11, 4 <lmacProcessShortRetryFail-0x38> (0 <lmacProcessShortRetryFail-0x3c>) */ /* literal @0x4: .rodata.lmacProcessTxopSuccess.str1.1 */
  a13 = 0x672; /* 00d8: movi a13, 0x672 */
  a12 = a3; /* 00db: mov.n a12, a3 */
  MEMW(); /* 00dd: memw  */
  a8 = (uint32_t)&wifi_assert; /* 00e0: l32r a8, 18 <lmacProcessShortRetryFail-0x24> (0 <lmacProcessShortRetryFail-0x3c>) */ /* literal: GOT slot for wifi_assert */
  wifi_assert(a2, a3, a4, a5); /* call via literal slot */ /* 00e3: callx8 a8 */
  a10 = MEM32(a7 + 44); /* 00e6: l32i.n a10, a7, 44 */
  a8 = (uint32_t)&rcReachRetryLimit; /* 00e8: l32r a8, 1c <lmacProcessShortRetryFail-0x20> (0 <lmacProcessShortRetryFail-0x3c>) */ /* literal: GOT slot for rcReachRetryLimit */
  rcReachRetryLimit(a2, a3, a4, a5); /* call via literal slot */ /* 00eb: callx8 a8 */
  if (a10 == 0) goto L_102; /* 00ee: beqz.n a10, 102 <lmacProcessShortRetryFail+0xc6> */
L_f0:;
  a4 = MEM32(a7 + 44); /* 00f0: l32i.n a4, a7, 44 */
  a8 = 0x400100; /* 00f2: l32r a8, c <lmacProcessShortRetryFail-0x30> (400100 <lmacTxFrame+0x400090>) */ @0xC
  a3 = MEM32(a4 + 0); /* 00f5: l32i.n a3, a4, 0 */
  a3 = a3 & a8; /* 00f7: and a3, a3, a8 */
  if (a3 != a8) goto L_160; /* 00fa: bne a3, a8, 160 <lmacProcessShortRetryFail+0x124> */
  goto L_12d; /* 00fd: j 12d <lmacProcessShortRetryFail+0xf1> */
  /* 0100: .byte 00 */
  /* 0101: .byte 00 */
L_102:;
  a10 = MEM32(a7 + 44); /* 0102: l32i.n a10, a7, 44 */
  a8 = (uint32_t)&lmacConfMib; /* 0104: l32r a8, 8 <lmacProcessShortRetryFail-0x34> (0 <lmacProcessShortRetryFail-0x3c>) */ /* literal @0x8: lmacConfMib */
  a11 = MEM8(a10 + 6); /* 0107: l8ui a11, a10, 6 */
  a10 = MEM8(a8 + 21); /* 010a: l8ui a10, a8, 21 */
  if (a11 >= a10) goto L_f0; /* 010d: bgeu a11, a10, f0 <lmacProcessShortRetryFail+0xb4> */
  a10 = a7; /* 0110: mov.n a10, a7 */
  a8 = (uint32_t)&lmacMSDUAged; /* 0112: l32r a8, 20 <lmacProcessShortRetryFail-0x1c> (0 <lmacProcessShortRetryFail-0x3c>) */ /* literal: GOT slot for lmacMSDUAged */
  lmacMSDUAged(a2, a3, a4, a5); /* call via literal slot */ /* 0115: callx8 a8 */
  if (a10 != 0) goto L_f0; /* 0118: bnez a10, f0 <lmacProcessShortRetryFail+0xb4> */
  a10 = MEM32(a7 + 44); /* 011b: l32i.n a10, a7, 44 */
  a14 = 0x1; /* 011d: movi.n a14, 1 */
  a14 = 0x10000000; /* 011f: slli a14, a14, 28 */
  a10 = MEM32(a10 + 0); /* 0122: l32i.n a10, a10, 0 */
  a14 = a10 & a14; /* 0124: and a14, a10, a14 */
  if (a14 != 0) goto L_f0; /* 0127: bnez a14, f0 <lmacProcessShortRetryFail+0xb4> */
  goto L_181; /* 012a: j 181 <lmacProcessShortRetryFail+0x145> */
L_12d:;
  a10 = a7; /* 012d: mov.n a10, a7 */
  a8 = (uint32_t)&lmacIsLongFrame; /* 012f: l32r a8, 24 <lmacProcessShortRetryFail-0x18> (0 <lmacProcessShortRetryFail-0x3c>) */ /* literal: GOT slot for lmacIsLongFrame */
  lmacIsLongFrame(a2, a3, a4, a5); /* call via literal slot */ /* 0132: callx8 a8 */
  if (a10 == 0) goto L_140; /* 0135: beqz.n a10, 140 <lmacProcessShortRetryFail+0x104> */
  a5 = (uint32_t)&lmacConfMib; /* 0137: l32r a5, 8 <lmacProcessShortRetryFail-0x34> (0 <lmacProcessShortRetryFail-0x3c>) */ /* literal @0x8: lmacConfMib */
  a3 = MEM8(a5 + 43); /* 013a: l8ui a3, a5, 43 */
  goto L_146; /* 013d: j 146 <lmacProcessShortRetryFail+0x10a> */
L_140:;
  a8 = (uint32_t)&lmacConfMib; /* 0140: l32r a8, 8 <lmacProcessShortRetryFail-0x34> (0 <lmacProcessShortRetryFail-0x3c>) */ /* literal @0x8: lmacConfMib */
  a3 = MEM8(a8 + 44); /* 0143: l8ui a3, a8, 44 */
L_146:;
  a11 = a7; /* 0146: mov.n a11, a7 */
  a10 = a2; /* 0148: mov.n a10, a2 */
  MEM8(a4 + 5) = a3; /* 014a: s8i a3, a4, 5 */
  MEMW(); /* 014d: memw  */
  a3 = 0x0; /* 0150: movi.n a3, 0 */
  MEM32(a2 + 0) = a3; /* 0152: s32i.n a3, a2, 0 */
  MEMW(); /* 0154: memw  */
  a8 = (uint32_t)&lmacEndRetryAMPDUFail; /* 0157: l32r a8, 28 <lmacProcessShortRetryFail-0x14> (0 <lmacProcessShortRetryFail-0x3c>) */ /* literal: GOT slot for lmacEndRetryAMPDUFail */
  lmacEndRetryAMPDUFail(a2, a3, a4, a5); /* call via literal slot */ /* 015a: callx8 a8 */
  goto L_219; /* 015d: j 219 <lmacProcessShortRetryFail+0x1dd> */
L_160:;
  a3 = 0x6; /* 0160: movi.n a3, 6 */
  MEM8(a2 + 18) = a3; /* 0162: s8i a3, a2, 18 */
  MEMW(); /* 0165: memw  */
  if (a6 != 0) goto L_176; /* 0168: bnez.n a6, 176 <lmacProcessShortRetryFail+0x13a> */
  a12 = a6; /* 016a: mov.n a12, a6 */
  a11 = 0x1; /* 016c: movi.n a11, 1 */
  if (a5 != 0) goto L_18a; /* 016e: bnez.n a5, 18a <lmacProcessShortRetryFail+0x14e> */
  MEMW(); /* 0170: memw  */
  goto L_219; /* 0173: j 219 <lmacProcessShortRetryFail+0x1dd> */
L_176:;
  a10 = a2; /* 0176: mov.n a10, a2 */
  a8 = (uint32_t)&lmacDiscardFrameExchangeSequence; /* 0178: l32r a8, 2c <lmacProcessShortRetryFail-0x10> (0 <lmacProcessShortRetryFail-0x3c>) */ /* literal: GOT slot for lmacDiscardFrameExchangeSequence */
  lmacDiscardFrameExchangeSequence(a2, a3, a4, a5); /* call via literal slot */ /* 017b: callx8 a8 */
  goto L_219; /* 017e: j 219 <lmacProcessShortRetryFail+0x1dd> */
L_181:;
  if (a6 != 0) goto L_1e5; /* 0181: bnez a6, 1e5 <lmacProcessShortRetryFail+0x1a9> */
  if (a4 == 0) goto L_195; /* 0184: beqz.n a4, 195 <lmacProcessShortRetryFail+0x159> */
L_186:;
  a12 = 0x1; /* 0186: movi.n a12, 1 */
  a11 = 0x1; /* 0188: mov.n a11, a12 */
L_18a:;
  a10 = a2; /* 018a: mov.n a10, a2 */
  a8 = (uint32_t)&lmacEndFrameExchangeSequence; /* 018c: l32r a8, 30 <lmacProcessShortRetryFail-0xc> (0 <lmacProcessShortRetryFail-0x3c>) */ /* literal: GOT slot for lmacEndFrameExchangeSequence */
  lmacEndFrameExchangeSequence(a2, a3, a4, a5); /* call via literal slot */ /* 018f: callx8 a8 */
  goto L_219; /* 0192: j 219 <lmacProcessShortRetryFail+0x1dd> */
L_195:;
  a3 = 0x600002; /* 0195: l32r a3, 10 <lmacProcessShortRetryFail-0x2c> (600002 <lmacTxFrame+0x5fff92>) */ @0x10
  if ((a10 & a3) != 0) goto L_1b8; /* 0198: bany a10, a3, 1b8 <lmacProcessShortRetryFail+0x17c> */
  a3 = MEM32(a7 + 4); /* 019b: l32i.n a3, a7, 4 */
  a3 = MEM32(a3 + 4); /* 019d: l32i.n a3, a3, 4 */
  if (!((a10 >> 18) & 1)) goto L_1a4; /* 019f: bbci a10, 18, 1a4 <lmacProcessShortRetryFail+0x168> */
  a3 = a3 + (4); /* 01a2: addi.n a3, a3, 4 */
L_1a4:;
  a6 = 0x8; /* 01a4: movi.n a6, 8 */
  a4 = MEM8(a3 + 1); /* 01a6: l8ui a4, a3, 1 */
  a4 = a4 | a6; /* 01a9: or a4, a4, a6 */
  MEM8(a3 + 1) = a4; /* 01ac: s8i a4, a3, 1 */
  MEMW(); /* 01af: memw  */
  MEMW(); /* 01b2: memw  */
  goto L_1dd; /* 01b5: j 1dd <lmacProcessShortRetryFail+0x1a1> */
L_1b8:;
  if (!((a10 >> 22) & 1)) goto L_1dd; /* 01b8: bbci a10, 22, 1dd <lmacProcessShortRetryFail+0x1a1> */
  a6 = 0x8; /* 01bb: movi.n a6, 8 */
L_1bd:;
  a4 = MEM32(a7 + 44); /* 01bd: l32i.n a4, a7, 44 */
  a3 = MEM32(a7 + 4); /* 01bf: l32i.n a3, a7, 4 */
  a4 = MEM32(a4 + 0); /* 01c1: l32i a4, a4, 0 */
  a3 = MEM32(a3 + 4); /* 01c4: l32i.n a3, a3, 4 */
  if (!((a4 >> 18) & 1)) goto L_1cc; /* 01c6: bbci a4, 18, 1cc <lmacProcessShortRetryFail+0x190> */
  a3 = a3 + (4); /* 01c9: addi a3, a3, 4 */
L_1cc:;
  a4 = MEM8(a3 + 1); /* 01cc: l8ui a4, a3, 1 */
  a4 = a4 | a6; /* 01cf: or a4, a4, a6 */
  MEM8(a3 + 1) = a4; /* 01d2: s8i a4, a3, 1 */
  MEMW(); /* 01d5: memw  */
  a7 = MEM32(a7 + 40); /* 01d8: l32i.n a7, a7, 40 */
  if (a7 != 0) goto L_1bd; /* 01da: bnez a7, 1bd <lmacProcessShortRetryFail+0x181> */
L_1dd:;
  if (a5 == 0) goto L_219; /* 01dd: beqz.n a5, 219 <lmacProcessShortRetryFail+0x1dd> */
  MEMW(); /* 01df: memw  */
  goto L_186; /* 01e2: j 186 <lmacProcessShortRetryFail+0x14a> */
L_1e5:;
  a4 = MEM8(a2 + 18); /* 01e5: l8ui a4, a2, 18 */
  a10 = 0x1; /* 01e8: movi.n a10, 1 */
  a4 = a4 + (-1); /* 01ea: addi.n a4, a4, -1 */
  if (a4 != 0) a10 = a14; /* 01ec: movnez a10, a14, a4 */
  a12 = a3; /* 01ef: mov.n a12, a3 */
  a11 = (uint32_t)&lit_rodata_lmacProcessTxopSuccess_str1_1; /* 01f1: l32r a11, 4 <lmacProcessShortRetryFail-0x38> (0 <lmacProcessShortRetryFail-0x3c>) */ /* literal @0x4: .rodata.lmacProcessTxopSuccess.str1.1 */
  a13 = 0x6B9; /* 01f4: movi a13, 0x6b9 */
  a3 = 0x4; /* 01f7: movi.n a3, 4 */
  MEM32(a1 + 0) = a14; /* 01f9: s32i.n a14, a1, 0 */
  MEMW(); /* 01fb: memw  */
  a8 = (uint32_t)&wifi_assert; /* 01fe: l32r a8, 34 <lmacProcessShortRetryFail-0x8> (0 <lmacProcessShortRetryFail-0x3c>) */ /* literal: GOT slot for wifi_assert */
  wifi_assert(a2, a3, a4, a5); /* call via literal slot */ /* 0201: callx8 a8 */
  a10 = a2; /* 0204: mov.n a10, a2 */
  a14 = MEM32(a1 + 0); /* 0206: l32i.n a14, a1, 0 */
  a11 = a14; /* 0208: mov.n a11, a14 */
  MEM8(a2 + 18) = a3; /* 020a: s8i a3, a2, 18 */
  MEMW(); /* 020d: memw  */
  MEMW(); /* 0210: memw  */
  a8 = (uint32_t)&lmacRetryTxFrame; /* 0213: l32r a8, 38 <lmacProcessShortRetryFail-0x4> (0 <lmacProcessShortRetryFail-0x3c>) */ /* literal: GOT slot for lmacRetryTxFrame */
  lmacRetryTxFrame(a2, a3, a4, a5); /* call via literal slot */ /* 0216: callx8 a8 */
L_219:;
  return (int32_t)a2; /* 0219: retw.n  */
}

/* lmacProcessCtsTimeout @ lmac.o 00000014 size 83B bind GLOBAL
 * Calls: lmacProcessShortRetryFail, wifi_assert | Data refs: .bss.our_instances, .rodata.__FUNCTION__$5, .rodata.lmacProcessTxopSuccess.str1.1, lmacProcessShortRetryFail, wifi_assert
 *   MMIO: none
 *   funcdb v3: 2 call(s), 5 ref(s); disasm: 2 call(s), 5 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t lmacProcessCtsTimeout(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.lmacProcessCtsTimeout; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_14:;
  /* 0014: entry a1, 32 */
  a2 = (a2 >> 0) & 0xFF; /* 0017: extui a2, a2, 0, 8 */
  a3 = (a3 >> 0) & 0xFF; /* 001a: extui a3, a3, 0, 8 */
  if (a2 != 10) goto L_2c; /* 001d: bnei a2, 10, 2c <lmacProcessCtsTimeout+0x18> */
  a2 = 0x0; /* 0020: movi a2, 0 */
  MEMW(); /* 0023: memw  */
  a2 = MEM32(a2 + 44); /* 0026: l32i a2, a2, 44 */
  /* 0029: break 1, 15 */
L_2c:;
  a4 = (uint32_t)&bss_our_instances; /* 002c: l32r a4, 8 <lmacProcessCtsTimeout-0xc> (0 <lmacProcessCtsTimeout-0x14>) */ /* literal @0x8: .bss.our_instances */
  a8 = (a2 << 8) + a2; /* 002f: addx8 a8, a2, a2 */
  a8 = (a8 << 4) + a4; /* 0032: addx4 a8, a8, a4 */
  a10 = 0x1; /* 0035: movi.n a10, 1 */
  a8 = MEM8(a8 + 18); /* 0037: l8ui a8, a8, 18 */
  a8 = a8 + (-1); /* 003a: addi.n a8, a8, -1 */
  a8 = (a8 >> 0) & 0xFF; /* 003c: extui a8, a8, 0, 8 */
  if (a8 < 2) goto L_44; /* 003f: bltui a8, 2, 44 <lmacProcessCtsTimeout+0x30> */
  a10 = 0x0; /* 0042: movi.n a10, 0 */
L_44:;
  a12 = (uint32_t)&lit_rodata_FUNCTION_5; /* 0044: l32r a12, 0 <lmacProcessCtsTimeout-0x14> (0 <lmacProcessCtsTimeout-0x14>) */ /* literal @0x0: .rodata.__FUNCTION__$5 */
  a13 = 0x789; /* 0047: movi a13, 0x789 */
  a2 = (a2 << 8) + a2; /* 004a: addx8 a2, a2, a2 */
  a11 = (uint32_t)&lit_rodata_lmacProcessTxopSuccess_str1_1; /* 004d: l32r a11, 4 <lmacProcessCtsTimeout-0x10> (0 <lmacProcessCtsTimeout-0x14>) */ /* literal @0x4: .rodata.lmacProcessTxopSuccess.str1.1 */
  a8 = (uint32_t)&wifi_assert; /* 0050: l32r a8, c <lmacProcessCtsTimeout-0x8> (0 <lmacProcessCtsTimeout-0x14>) */ /* literal: GOT slot for wifi_assert */
  wifi_assert(a2, a3, a4, a5); /* call via literal slot */ /* 0053: callx8 a8 */
  a13 = a3; /* 0056: mov.n a13, a3 */
  a12 = 0x1; /* 0058: movi.n a12, 1 */
  a11 = 0x0; /* 005a: movi.n a11, 0 */
  a10 = (a2 << 4) + a4; /* 005c: addx4 a10, a2, a4 */
  a8 = (uint32_t)&lmacProcessShortRetryFail; /* 005f: l32r a8, 10 <lmacProcessCtsTimeout-0x4> (0 <lmacProcessCtsTimeout-0x14>) */ /* literal: GOT slot for lmacProcessShortRetryFail */
  lmacProcessShortRetryFail(a2, a3, a4, a5); /* call via literal slot */ /* 0062: callx8 a8 */
  return (int32_t)a2; /* 0065: retw.n  */
}

/* lmacProcessLongRetryFail @ lmac.o 0000002c size 366B bind GLOBAL
 * Calls: lmacDiscardFrameExchangeSequence, lmacEndFrameExchangeSequence, lmacMSDUAged, lmacRetryTxFrame, rcReachRetryLimit, wifi_assert | Data refs: .rodata.__FUNCTION__$6, .rodata.lmacProcessTxopSuccess.str1.1, lmacConfMib, lmacDiscardFrameExchangeSequence, lmacEndFrameExchangeSequence, lmacMSDUAged, lmacRetryTxFrame, rcReachRetryLimit, wifi_assert
 *   MMIO: none
 *   funcdb v3: 6 call(s), 9 ref(s); disasm: 7 call(s), 9 data ref(s)
 * Fidelity: medium - 139 instr, 25 branches, calls resolved */
int32_t lmacProcessLongRetryFail(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.lmacProcessLongRetryFail; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_2c:;
  /* 002c: entry a1, 48 */
  a9 = (a4 >> 0) & 0xFF; /* 002f: extui a9, a4, 0, 8 */
  a5 = 0x0; /* 0032: movi.n a5, 0 */
  a3 = (a3 >> 0) & 0xFF; /* 0034: extui a3, a3, 0, 8 */
  if (a9 != a5) goto L_3c; /* 0037: bne a9, a5, 3c <lmacProcessLongRetryFail+0x10> */
  a5 = MEM32(a2 + 0); /* 003a: l32i.n a5, a2, 0 */
L_3c:;
  a6 = (uint32_t)&lmacConfMib; /* 003c: l32r a6, 0 <lmacProcessLongRetryFail-0x2c> (0 <lmacProcessLongRetryFail-0x2c>) */ /* literal @0x0: lmacConfMib */
  a8 = MEM8(a2 + 12); /* 003f: l8ui a8, a2, 12 */
  a4 = MEM8(a6 + 20); /* 0042: l8ui a4, a6, 20 */
  if (a8 >= a4) goto L_69; /* 0045: bgeu a8, a4, 69 <lmacProcessLongRetryFail+0x3d> */
  a8 = a8 + (1); /* 0048: addi.n a8, a8, 1 */
  a8 = (a8 >> 0) & 0xFF; /* 004a: extui a8, a8, 0, 8 */
  MEM8(a2 + 12) = a8; /* 004d: s8i a8, a2, 12 */
  MEMW(); /* 0050: memw  */
  if (a8 >= a4) goto L_69; /* 0053: bgeu a8, a4, 69 <lmacProcessLongRetryFail+0x3d> */
  a4 = MEM8(a2 + 8); /* 0056: l8ui a4, a2, 8 */
  a7 = MEM8(a2 + 10); /* 0059: l8ui a7, a2, 10 */
  if (a4 >= a7) goto L_72; /* 005c: bgeu a4, a7, 72 <lmacProcessLongRetryFail+0x46> */
  a4 = a4 + (1); /* 005f: addi.n a4, a4, 1 */
  MEMW(); /* 0061: memw  */
  goto L_6c; /* 0064: j 6c <lmacProcessLongRetryFail+0x40> */
  /* 0067: .byte 00 */
  /* 0068: .byte 00 */
L_69:;
  a4 = MEM8(a2 + 9); /* 0069: l8ui a4, a2, 9 */
L_6c:;
  MEM8(a2 + 8) = a4; /* 006c: s8i a4, a2, 8 */
  MEMW(); /* 006f: memw  */
L_72:;
  a4 = MEM32(a5 + 44); /* 0072: l32i.n a4, a5, 44 */
  a7 = MEM8(a4 + 7); /* 0074: l8ui a7, a4, 7 */
  a7 = a7 + (1); /* 0077: addi.n a7, a7, 1 */
  MEM8(a4 + 7) = a7; /* 0079: s8i a7, a4, 7 */
  MEMW(); /* 007c: memw  */
  if (a3 != 0) goto L_8c; /* 007f: bnez.n a3, 8c <lmacProcessLongRetryFail+0x60> */
  a7 = MEM8(a4 + 5); /* 0081: l8ui a7, a4, 5 */
  a7 = a7 + (1); /* 0084: addi.n a7, a7, 1 */
  MEM8(a4 + 5) = a7; /* 0086: s8i a7, a4, 5 */
  MEMW(); /* 0089: memw  */
L_8c:;
  a10 = 0x1; /* 008c: movi.n a10, 1 */
  a8 = MEM8(a2 + 18); /* 008e: l8ui a8, a2, 18 */
  a8 = a8 + (-1); /* 0091: addi.n a8, a8, -1 */
  a8 = (a8 >> 0) & 0xFF; /* 0093: extui a8, a8, 0, 8 */
  a4 = (uint32_t)&lit_rodata_FUNCTION_6; /* 0096: l32r a4, 4 <lmacProcessLongRetryFail-0x28> (0 <lmacProcessLongRetryFail-0x2c>) */ /* literal @0x4: .rodata.__FUNCTION__$6 */
  a7 = (uint32_t)&lit_rodata_lmacProcessTxopSuccess_str1_1; /* 0099: l32r a7, 8 <lmacProcessLongRetryFail-0x24> (0 <lmacProcessLongRetryFail-0x2c>) */ /* literal @0x8: .rodata.lmacProcessTxopSuccess.str1.1 */
  if (a8 < 2) goto L_a1; /* 009c: bltui a8, 2, a1 <lmacProcessLongRetryFail+0x75> */
  a10 = 0x0; /* 009f: movi.n a10, 0 */
L_a1:;
  a13 = 0x747; /* 00a1: movi a13, 0x747 */
  a12 = a4; /* 00a4: mov.n a12, a4 */
  a11 = a7; /* 00a6: mov.n a11, a7 */
  MEM32(a1 + 0) = a9; /* 00a8: s32i a9, a1, 0 */
  MEMW(); /* 00ab: memw  */
  a8 = (uint32_t)&wifi_assert; /* 00ae: l32r a8, 10 <lmacProcessLongRetryFail-0x1c> (0 <lmacProcessLongRetryFail-0x2c>) */ /* literal: GOT slot for wifi_assert */
  wifi_assert(a2, a3, a4, a5); /* call via literal slot */ /* 00b1: callx8 a8 */
  a10 = MEM32(a5 + 44); /* 00b4: l32i.n a10, a5, 44 */
  a8 = (uint32_t)&rcReachRetryLimit; /* 00b6: l32r a8, 14 <lmacProcessLongRetryFail-0x18> (0 <lmacProcessLongRetryFail-0x2c>) */ /* literal: GOT slot for rcReachRetryLimit */
  rcReachRetryLimit(a2, a3, a4, a5); /* call via literal slot */ /* 00b9: callx8 a8 */
  a9 = MEM32(a1 + 0); /* 00bc: l32i.n a9, a1, 0 */
  if (a10 == 0) goto L_d0; /* 00be: beqz.n a10, d0 <lmacProcessLongRetryFail+0xa4> */
L_c0:;
  a4 = 0x6; /* 00c0: movi.n a4, 6 */
  MEM8(a2 + 18) = a4; /* 00c2: s8i a4, a2, 18 */
  MEMW(); /* 00c5: memw  */
  if (a3 == 0) goto L_f2; /* 00c8: beqz.n a3, f2 <lmacProcessLongRetryFail+0xc6> */
  MEMW(); /* 00ca: memw  */
  goto L_fc; /* 00cd: j fc <lmacProcessLongRetryFail+0xd0> */
L_d0:;
  a8 = MEM32(a5 + 44); /* 00d0: l32i.n a8, a5, 44 */
  a6 = MEM8(a6 + 20); /* 00d2: l8ui a6, a6, 20 */
  a8 = MEM8(a8 + 7); /* 00d5: l8ui a8, a8, 7 */
  if (a8 >= a6) goto L_c0; /* 00d8: bgeu a8, a6, c0 <lmacProcessLongRetryFail+0x94> */
  a10 = a5; /* 00db: mov.n a10, a5 */
  MEM32(a1 + 0) = a9; /* 00dd: s32i.n a9, a1, 0 */
  MEMW(); /* 00df: memw  */
  a8 = (uint32_t)&lmacMSDUAged; /* 00e2: l32r a8, 18 <lmacProcessLongRetryFail-0x14> (0 <lmacProcessLongRetryFail-0x2c>) */ /* literal: GOT slot for lmacMSDUAged */
  lmacMSDUAged(a2, a3, a4, a5); /* call via literal slot */ /* 00e5: callx8 a8 */
  a6 = a10; /* 00e8: mov.n a6, a10 */
  a9 = MEM32(a1 + 0); /* 00ea: l32i.n a9, a1, 0 */
  if (a10 != 0) goto L_c0; /* 00ec: bnez a10, c0 <lmacProcessLongRetryFail+0x94> */
  goto L_107; /* 00ef: j 107 <lmacProcessLongRetryFail+0xdb> */
L_f2:;
  a12 = a9; /* 00f2: mov.n a12, a9 */
  a11 = 0x1; /* 00f4: movi.n a11, 1 */
  if (a9 == 0) goto L_15d; /* 00f6: beqz a9, 15d <lmacProcessLongRetryFail+0x131> */
  goto L_198; /* 00f9: j 198 <lmacProcessLongRetryFail+0x16c> */
L_fc:;
  a10 = a2; /* 00fc: mov.n a10, a2 */
  a8 = (uint32_t)&lmacDiscardFrameExchangeSequence; /* 00fe: l32r a8, 1c <lmacProcessLongRetryFail-0x10> (0 <lmacProcessLongRetryFail-0x2c>) */ /* literal: GOT slot for lmacDiscardFrameExchangeSequence */
  lmacDiscardFrameExchangeSequence(a2, a3, a4, a5); /* call via literal slot */ /* 0101: callx8 a8 */
  goto L_198; /* 0104: j 198 <lmacProcessLongRetryFail+0x16c> */
L_107:;
  if (a3 != 0) goto L_16b; /* 0107: bnez a3, 16b <lmacProcessLongRetryFail+0x13f> */
  a3 = MEM32(a5 + 44); /* 010a: l32i.n a3, a5, 44 */
  a4 = MEM32(a3 + 0); /* 010c: l32i.n a4, a3, 0 */
  a3 = 0x400002; /* 010e: l32r a3, c <lmacProcessLongRetryFail-0x20> (400002 <lmacTxFrame+0x3fff92>) */ @0xC
  if ((a4 & a3) != 0) goto L_131; /* 0111: bany a4, a3, 131 <lmacProcessLongRetryFail+0x105> */
  a3 = MEM32(a5 + 4); /* 0114: l32i.n a3, a5, 4 */
  a3 = MEM32(a3 + 4); /* 0116: l32i.n a3, a3, 4 */
  if (!((a4 >> 18) & 1)) goto L_11d; /* 0118: bbci a4, 18, 11d <lmacProcessLongRetryFail+0xf1> */
  a3 = a3 + (4); /* 011b: addi.n a3, a3, 4 */
L_11d:;
  a5 = 0x8; /* 011d: movi.n a5, 8 */
  a4 = MEM8(a3 + 1); /* 011f: l8ui a4, a3, 1 */
  a4 = a4 | a5; /* 0122: or a4, a4, a5 */
  MEM8(a3 + 1) = a4; /* 0125: s8i a4, a3, 1 */
  MEMW(); /* 0128: memw  */
  MEMW(); /* 012b: memw  */
  goto L_156; /* 012e: j 156 <lmacProcessLongRetryFail+0x12a> */
L_131:;
  if (!((a4 >> 22) & 1)) goto L_156; /* 0131: bbci a4, 22, 156 <lmacProcessLongRetryFail+0x12a> */
  a6 = 0x8; /* 0134: movi.n a6, 8 */
L_136:;
  a4 = MEM32(a5 + 44); /* 0136: l32i.n a4, a5, 44 */
  a3 = MEM32(a5 + 4); /* 0138: l32i.n a3, a5, 4 */
  a4 = MEM32(a4 + 0); /* 013a: l32i.n a4, a4, 0 */
  a3 = MEM32(a3 + 4); /* 013c: l32i a3, a3, 4 */
  if (!((a4 >> 18) & 1)) goto L_145; /* 013f: bbci a4, 18, 145 <lmacProcessLongRetryFail+0x119> */
  a3 = a3 + (4); /* 0142: addi a3, a3, 4 */
L_145:;
  a4 = MEM8(a3 + 1); /* 0145: l8ui a4, a3, 1 */
  a4 = a4 | a6; /* 0148: or a4, a4, a6 */
  MEM8(a3 + 1) = a4; /* 014b: s8i a4, a3, 1 */
  MEMW(); /* 014e: memw  */
  a5 = MEM32(a5 + 40); /* 0151: l32i.n a5, a5, 40 */
  if (a5 != 0) goto L_136; /* 0153: bnez a5, 136 <lmacProcessLongRetryFail+0x10a> */
L_156:;
  if (a9 != 0) goto L_198; /* 0156: bnez.n a9, 198 <lmacProcessLongRetryFail+0x16c> */
  a12 = 0x1; /* 0158: movi.n a12, 1 */
  a11 = 0x1; /* 015a: or a11, a12, a12 */
L_15d:;
  a10 = a2; /* 015d: mov.n a10, a2 */
  MEMW(); /* 015f: memw  */
  a8 = (uint32_t)&lmacEndFrameExchangeSequence; /* 0162: l32r a8, 20 <lmacProcessLongRetryFail-0xc> (0 <lmacProcessLongRetryFail-0x2c>) */ /* literal: GOT slot for lmacEndFrameExchangeSequence */
  lmacEndFrameExchangeSequence(a2, a3, a4, a5); /* call via literal slot */ /* 0165: callx8 a8 */
  goto L_198; /* 0168: j 198 <lmacProcessLongRetryFail+0x16c> */
L_16b:;
  a3 = MEM8(a2 + 18); /* 016b: l8ui a3, a2, 18 */
  a10 = 0x1; /* 016e: movi.n a10, 1 */
  a3 = a3 + (-1); /* 0170: addi.n a3, a3, -1 */
  if (a3 != 0) a10 = a6; /* 0172: movnez a10, a6, a3 */
  a11 = a7; /* 0175: mov.n a11, a7 */
  a13 = 0x776; /* 0177: movi a13, 0x776 */
  a12 = a4; /* 017a: mov.n a12, a4 */
  a8 = (uint32_t)&wifi_assert; /* 017c: l32r a8, 24 <lmacProcessLongRetryFail-0x8> (0 <lmacProcessLongRetryFail-0x2c>) */ /* literal: GOT slot for wifi_assert */
  wifi_assert(a2, a3, a4, a5); /* call via literal slot */ /* 017f: callx8 a8 */
  a3 = 0x4; /* 0182: movi.n a3, 4 */
  MEM8(a2 + 18) = a3; /* 0184: s8i a3, a2, 18 */
  MEMW(); /* 0187: memw  */
  a11 = a6; /* 018a: mov.n a11, a6 */
  a10 = a2 | a2; /* 018c: or a10, a2, a2 */
  MEMW(); /* 018f: memw  */
  a8 = (uint32_t)&lmacRetryTxFrame; /* 0192: l32r a8, 28 <lmacProcessLongRetryFail-0x4> (0 <lmacProcessLongRetryFail-0x2c>) */ /* literal: GOT slot for lmacRetryTxFrame */
  lmacRetryTxFrame(a2, a3, a4, a5); /* call via literal slot */ /* 0195: callx8 a8 */
L_198:;
  return (int32_t)a2; /* 0198: retw.n  */
}

/* lmacProcessCollision @ lmac.o 00000024 size 154B bind GLOBAL
 * Calls: lmacIsLongFrame, lmacProcessLongRetryFail, lmacProcessShortRetryFail, wifi_assert | Data refs: .bss.our_instances, .rodata.__FUNCTION__$9, .rodata.lmacProcessTxopSuccess.str1.1, lmacIsLongFrame, lmacProcessLongRetryFail, lmacProcessShortRetryFail, wifi_assert
 *   MMIO: none
 *   funcdb v3: 4 call(s), 7 ref(s); disasm: 6 call(s), 7 data ref(s)
 * Fidelity: medium - 57 instr, 4 branches, calls resolved */
int32_t lmacProcessCollision(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.lmacProcessCollision; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_24:;
  /* 0024: entry a1, 32 */
  a2 = (a2 >> 0) & 0xFF; /* 0027: extui a2, a2, 0, 8 */
  a5 = (uint32_t)&lit_rodata_FUNCTION_9; /* 002a: l32r a5, 0 <lmacProcessCollision-0x24> (0 <lmacProcessCollision-0x24>) */ /* literal @0x0: .rodata.__FUNCTION__$9 */
  a10 = 0x1; /* 002d: movi.n a10, 1 */
  a4 = (uint32_t)&lit_rodata_lmacProcessTxopSuccess_str1_1; /* 002f: l32r a4, 4 <lmacProcessCollision-0x20> (0 <lmacProcessCollision-0x24>) */ /* literal @0x4: .rodata.lmacProcessTxopSuccess.str1.1 */
  if (a2 < 5) goto L_38; /* 0032: bltui a2, 5, 38 <lmacProcessCollision+0x14> */
  a10 = 0x0; /* 0035: movi a10, 0 */
L_38:;
  a11 = a4; /* 0038: mov.n a11, a4 */
  a13 = 0x52F; /* 003a: movi a13, 0x52f */
  a12 = a5; /* 003d: mov.n a12, a5 */
  a8 = (uint32_t)&wifi_assert; /* 003f: l32r a8, c <lmacProcessCollision-0x18> (0 <lmacProcessCollision-0x24>) */ /* literal: GOT slot for wifi_assert */
  wifi_assert(a2, a3, a4, a5); /* call via literal slot */ /* 0042: callx8 a8 */
  a6 = (uint32_t)&bss_our_instances; /* 0045: l32r a6, 8 <lmacProcessCollision-0x1c> (0 <lmacProcessCollision-0x24>) */ /* literal @0x8: .bss.our_instances */
  a3 = (a2 << 8) + a2; /* 0048: addx8 a3, a2, a2 */
  a3 = (a3 << 4) + a6; /* 004b: addx4 a3, a3, a6 */
  a7 = 0x0; /* 004e: movi.n a7, 0 */
  a6 = 0x1; /* 0050: movi.n a6, 1 */
  a8 = MEM32(a3 + 0); /* 0052: l32i.n a8, a3, 0 */
  a10 = 0x0; /* 0054: or a10, a7, a7 */
  if (a8 != 0) a10 = a6; /* 0057: movnez a10, a6, a8 */
  a11 = a4 | a4; /* 005a: or a11, a4, a4 */
  a13 = 0x531; /* 005d: movi a13, 0x531 */
  a12 = a5 | a5; /* 0060: or a12, a5, a5 */
  a8 = (uint32_t)&wifi_assert; /* 0063: l32r a8, 10 <lmacProcessCollision-0x14> (0 <lmacProcessCollision-0x24>) */ /* literal: GOT slot for wifi_assert */
  wifi_assert(a2, a3, a4, a5); /* call via literal slot */ /* 0066: callx8 a8 */
  a8 = MEM8(a3 + 18); /* 0069: l8ui a8, a3, 18 */
  a10 = a7; /* 006c: mov.n a10, a7 */
  a8 = a8 + (-1); /* 006e: addi.n a8, a8, -1 */
  if (a8 == 0) a10 = a6; /* 0070: moveqz a10, a6, a8 */
  a11 = a4 | a4; /* 0073: or a11, a4, a4 */
  a13 = 0x532; /* 0076: movi a13, 0x532 */
  a12 = a5 | a5; /* 0079: or a12, a5, a5 */
  a8 = (uint32_t)&wifi_assert; /* 007c: l32r a8, 14 <lmacProcessCollision-0x10> (0 <lmacProcessCollision-0x24>) */ /* literal: GOT slot for wifi_assert */
  wifi_assert(a2, a3, a4, a5); /* call via literal slot */ /* 007f: callx8 a8 */
  a10 = MEM32(a3 + 0); /* 0082: l32i.n a10, a3, 0 */
  a2 = MEM32(a10 + 44); /* 0084: l32i a2, a10, 44 */
  a4 = MEM32(a2 + 0); /* 0087: l32i a4, a2, 0 */
  a2 = 0x300; /* 008a: movi a2, 0x300 */
  a2 = a2 & a4; /* 008d: and a2, a2, a4 */
  if (a2 != a7) goto L_9c; /* 0090: bne a2, a7, 9c <lmacProcessCollision+0x78> */
  a8 = (uint32_t)&lmacIsLongFrame; /* 0093: l32r a8, 18 <lmacProcessCollision-0xc> (0 <lmacProcessCollision-0x24>) */ /* literal: GOT slot for lmacIsLongFrame */
  lmacIsLongFrame(a2, a3, a4, a5); /* call via literal slot */ /* 0096: callx8 a8 */
  if (a10 != a7) goto L_b0; /* 0099: bne a10, a7, b0 <lmacProcessCollision+0x8c> */
L_9c:;
  a12 = 0x1; /* 009c: movi.n a12, 1 */
  a13 = 0x0; /* 009e: movi.n a13, 0 */
  a11 = 0x1; /* 00a0: or a11, a12, a12 */
  a10 = a3 | a3; /* 00a3: or a10, a3, a3 */
  a8 = (uint32_t)&lmacProcessShortRetryFail; /* 00a6: l32r a8, 1c <lmacProcessCollision-0x8> (0 <lmacProcessCollision-0x24>) */ /* literal: GOT slot for lmacProcessShortRetryFail */
  lmacProcessShortRetryFail(a2, a3, a4, a5); /* call via literal slot */ /* 00a9: callx8 a8 */
  goto L_bc; /* 00ac: j bc <lmacProcessCollision+0x98> */
  /* 00af: .byte 00 */
L_b0:;
  a12 = a2; /* 00b0: mov.n a12, a2 */
  a11 = a6; /* 00b2: mov.n a11, a6 */
  a10 = a3; /* 00b4: mov.n a10, a3 */
  a8 = (uint32_t)&lmacProcessLongRetryFail; /* 00b6: l32r a8, 20 <lmacProcessCollision-0x4> (0 <lmacProcessCollision-0x24>) */ /* literal: GOT slot for lmacProcessLongRetryFail */
  lmacProcessLongRetryFail(a2, a3, a4, a5); /* call via literal slot */ /* 00b9: callx8 a8 */
L_bc:;
  return (int32_t)a2; /* 00bc: retw.n  */
}

/* lmacProcessCollisions_task @ lmac.o 00000010 size 82B bind GLOBAL
 * Calls: hal_mac_clr_txq_state, hal_mac_get_txq_state, hal_mac_txq_disable, lmacProcessCollision | Data refs: hal_mac_clr_txq_state, hal_mac_get_txq_state, hal_mac_txq_disable, lmacProcessCollision
 *   MMIO: none
 *   funcdb v3: 4 call(s), 4 ref(s); disasm: 4 call(s), 4 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t lmacProcessCollisions_task(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.lmacProcessCollisions_task; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_10:;
  /* 0010: entry a1, 32 */
  a10 = 0x0; /* 0013: movi a10, 0 */
  a8 = (uint32_t)&hal_mac_get_txq_state; /* 0016: l32r a8, 0 <lmacProcessCollisions_task-0x10> (0 <lmacProcessCollisions_task-0x10>) */ /* literal: GOT slot for hal_mac_get_txq_state */
  hal_mac_get_txq_state(a2, a3, a4, a5); /* call via literal slot */ /* 0019: callx8 a8 */
  a3 = 0x0; /* 001c: or a3, a10, a10 */
  if (a10 == 0) goto L_60; /* 001f: beqz.n a10, 60 <lmacProcessCollisions_task+0x50> */
  a4 = 0x1; /* 0021: movi a4, 1 */
L_24:;
  a10 = 0x0; /* 0024: neg a10, a3 */
  a10 = 0x0; /* 0027: and a10, a10, a3 */
  a10 = __builtin_clz(a10) /* approx for nsau */; /* 002a: nsau a10, a10 */
  a10 = -a10; /* 002d: neg a10, a10 */
  a2 = a10 + (31); /* 0030: addi a2, a10, 31 */
  a10 = a2 | a2; /* 0033: or a10, a2, a2 */
  a8 = (uint32_t)&hal_mac_txq_disable; /* 0036: l32r a8, 4 <lmacProcessCollisions_task-0xc> (0 <lmacProcessCollisions_task-0x10>) */ /* literal: GOT slot for hal_mac_txq_disable */
  hal_mac_txq_disable(a2, a3, a4, a5); /* call via literal slot */ /* 0039: callx8 a8 */
  /* 003c: ssl a2 */ /* UNMODELED: a2 clobbered */
  /* 003f: sll a5, a4 */ /* UNMODELED: a5 clobbered */
  a11 = a5; /* 0042: mov.n a11, a5 */
  a10 = 0x0; /* 0044: movi a10, 0 */
  a8 = (uint32_t)&hal_mac_clr_txq_state; /* 0047: l32r a8, 8 <lmacProcessCollisions_task-0x8> (0 <lmacProcessCollisions_task-0x10>) */ /* literal: GOT slot for hal_mac_clr_txq_state */
  hal_mac_clr_txq_state(a2, a3, a4, a5); /* call via literal slot */ /* 004a: callx8 a8 */
  a10 = a2; /* 004d: mov.n a10, a2 */
  a8 = (uint32_t)&lmacProcessCollision; /* 004f: l32r a8, c <lmacProcessCollisions_task-0x4> (0 <lmacProcessCollisions_task-0x10>) */ /* literal: GOT slot for lmacProcessCollision */
  lmacProcessCollision(a2, a3, a4, a5); /* call via literal slot */ /* 0052: callx8 a8 */
  a11 = 0xFFFFFFFF; /* 0055: movi.n a11, -1 */
  a11 = a11 ^ a5; /* 0057: xor a11, a11, a5 */
  a3 = a3 & a11; /* 005a: and a3, a3, a11 */
  if (a3 != 0) goto L_24; /* 005d: bnez a3, 24 <lmacProcessCollisions_task+0x14> */
L_60:;
  return (int32_t)a2; /* 0060: retw.n  */
}

/* lmacProcessAckTimeout @ lmac.o 00000024 size 191B bind GLOBAL
 * Calls: lmacProcessLongRetryFail, lmacProcessShortRetryFail, wifi_assert | Data refs: .bss.our_instances, .rodata.__FUNCTION__$4, .rodata.lmacProcessTxopSuccess.str1.1, lmacProcessLongRetryFail, lmacProcessShortRetryFail, wifi_assert
 *   MMIO: none
 *   funcdb v3: 3 call(s), 6 ref(s); disasm: 6 call(s), 6 data ref(s)
 * Fidelity: medium - 77 instr, 7 branches, calls resolved */
int32_t lmacProcessAckTimeout(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.lmacProcessAckTimeout; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_24:;
  /* 0024: entry a1, 32 */
  a2 = (a2 >> 0) & 0xFF; /* 0027: extui a2, a2, 0, 8 */
  a6 = (uint32_t)&lit_rodata_FUNCTION_4; /* 002a: l32r a6, 0 <lmacProcessAckTimeout-0x24> (0 <lmacProcessAckTimeout-0x24>) */ /* literal @0x0: .rodata.__FUNCTION__$4 */
  a7 = 0x0; /* 002d: movi.n a7, 0 */
  a8 = a2 + (-10); /* 002f: addi a8, a2, -10 */
  a4 = 0x1; /* 0032: movi.n a4, 1 */
  a10 = 0x0; /* 0034: mov.n a10, a7 */
  a5 = (uint32_t)&lit_rodata_lmacProcessTxopSuccess_str1_1; /* 0036: l32r a5, 4 <lmacProcessAckTimeout-0x20> (0 <lmacProcessAckTimeout-0x24>) */ /* literal @0x4: .rodata.lmacProcessTxopSuccess.str1.1 */
  if (a8 != 0) a10 = a4; /* 0039: movnez a10, a4, a8 */
  a13 = 0x799; /* 003c: movi a13, 0x799 */
  a12 = a6; /* 003f: mov.n a12, a6 */
  a11 = a5; /* 0041: mov.n a11, a5 */
  a3 = (a3 >> 0) & 0xFF; /* 0043: extui a3, a3, 0, 8 */
  a8 = (uint32_t)&wifi_assert; /* 0046: l32r a8, c <lmacProcessAckTimeout-0x18> (0 <lmacProcessAckTimeout-0x24>) */ /* literal: GOT slot for wifi_assert */
  wifi_assert(a2, a3, a4, a5); /* call via literal slot */ /* 0049: callx8 a8 */
  if (a2 != 10) goto L_59; /* 004c: bnei a2, 10, 59 <lmacProcessAckTimeout+0x35> */
  MEMW(); /* 004f: memw  */
  a2 = MEM32(a7 + 44); /* 0052: l32i.n a2, a7, 44 */
  goto L_de; /* 0054: j de <lmacProcessAckTimeout+0xba> */
  /* 0057: .byte 00 */
  /* 0058: .byte 00 */
L_59:;
  a10 = a4; /* 0059: mov.n a10, a4 */
  if (a2 < 5) goto L_60; /* 005b: bltui a2, 5, 60 <lmacProcessAckTimeout+0x3c> */
  a10 = a7; /* 005e: mov.n a10, a7 */
L_60:;
  a13 = 0x79C; /* 0060: movi a13, 0x79c */
  a12 = a6; /* 0063: mov.n a12, a6 */
  a11 = a5; /* 0065: mov.n a11, a5 */
  a8 = (uint32_t)&wifi_assert; /* 0067: l32r a8, 10 <lmacProcessAckTimeout-0x14> (0 <lmacProcessAckTimeout-0x24>) */ /* literal: GOT slot for wifi_assert */
  wifi_assert(a2, a3, a4, a5); /* call via literal slot */ /* 006a: callx8 a8 */
  if (a3 != 0) goto L_c8; /* 006d: bnez a3, c8 <lmacProcessAckTimeout+0xa4> */
  a7 = (uint32_t)&bss_our_instances; /* 0070: l32r a7, 8 <lmacProcessAckTimeout-0x1c> (0 <lmacProcessAckTimeout-0x24>) */ /* literal @0x8: .bss.our_instances */
  a4 = (a2 << 8) + a2; /* 0073: addx8 a4, a2, a2 */
  a4 = (a4 << 4) + a7; /* 0076: addx4 a4, a4, a7 */
  a11 = a5; /* 0079: mov.n a11, a5 */
  a13 = 0x7A7; /* 007b: movi a13, 0x7a7 */
  a7 = MEM32(a4 + 0); /* 007e: l32i.n a7, a4, 0 */
  a12 = a6; /* 0080: mov.n a12, a6 */
  a10 = 0x1; /* 0082: movi.n a10, 1 */
  a8 = (uint32_t)&wifi_assert; /* 0084: l32r a8, 14 <lmacProcessAckTimeout-0x10> (0 <lmacProcessAckTimeout-0x24>) */ /* literal: GOT slot for wifi_assert */
  wifi_assert(a2, a3, a4, a5); /* call via literal slot */ /* 0087: callx8 a8 */
  a2 = a4; /* 008a: mov.n a2, a4 */
  a5 = MEM32(a7 + 44); /* 008c: l32i.n a5, a7, 44 */
  a5 = MEM32(a5 + 0); /* 008e: l32i.n a5, a5, 0 */
  if (!((a5 >> 8) & 1)) goto L_b6; /* 0090: bbci a5, 8, b6 <lmacProcessAckTimeout+0x92> */
  a12 = a3; /* 0093: mov.n a12, a3 */
  a11 = a3 | a3; /* 0095: or a11, a3, a3 */
  a5 = MEM8(a4 + 9); /* 0098: l8ui a5, a4, 9 */
  a10 = a4 | a4; /* 009b: or a10, a4, a4 */
  MEM8(a4 + 8) = a5; /* 009e: s8i a5, a4, 8 */
  MEM8(a4 + 11) = a3; /* 00a1: s8i a3, a4, 11 */
  MEMW(); /* 00a4: memw  */
  MEMW(); /* 00a7: memw  */
  a8 = (uint32_t)&lmacProcessLongRetryFail; /* 00aa: l32r a8, 18 <lmacProcessAckTimeout-0xc> (0 <lmacProcessAckTimeout-0x24>) */ /* literal: GOT slot for lmacProcessLongRetryFail */
  lmacProcessLongRetryFail(a2, a3, a4, a5); /* call via literal slot */ /* 00ad: callx8 a8 */
  goto L_e1; /* 00b0: j e1 <lmacProcessAckTimeout+0xbd> */
  /* 00b3: .byte 00 */
  /* 00b4: .byte 00 */
  /* 00b5: .byte 00 */
L_b6:;
  a13 = a3; /* 00b6: mov.n a13, a3 */
  a12 = a3; /* 00b8: mov.n a12, a3 */
  a11 = a3; /* 00ba: mov.n a11, a3 */
  a10 = a4; /* 00bc: mov.n a10, a4 */
  a8 = (uint32_t)&lmacProcessShortRetryFail; /* 00be: l32r a8, 1c <lmacProcessAckTimeout-0x8> (0 <lmacProcessAckTimeout-0x24>) */ /* literal: GOT slot for lmacProcessShortRetryFail */
  lmacProcessShortRetryFail(a2, a3, a4, a5); /* call via literal slot */ /* 00c1: callx8 a8 */
  goto L_e1; /* 00c4: j e1 <lmacProcessAckTimeout+0xbd> */
  /* 00c7: .byte 00 */
L_c8:;
  a13 = 0x7A7; /* 00c8: movi a13, 0x7a7 */
  a12 = a6; /* 00cb: mov.n a12, a6 */
  a11 = a5; /* 00cd: mov.n a11, a5 */
  a10 = 0x1; /* 00cf: movi.n a10, 1 */
  a2 = 0x0; /* 00d1: movi.n a2, 0 */
  a8 = (uint32_t)&wifi_assert; /* 00d3: l32r a8, 20 <lmacProcessAckTimeout-0x4> (0 <lmacProcessAckTimeout-0x24>) */ /* literal: GOT slot for wifi_assert */
  wifi_assert(a2, a3, a4, a5); /* call via literal slot */ /* 00d6: callx8 a8 */
  MEMW(); /* 00d9: memw  */
  a2 = MEM32(a2 + 44); /* 00dc: l32i.n a2, a2, 44 */
L_de:;
  /* 00de: break 1, 15 */
L_e1:;
  return (int32_t)a2; /* 00e1: retw.n  */
}

/* lmacProcessTxRtsError @ lmac.o 00000024 size 162B bind GLOBAL
 * Calls: lmacEndFrameExchangeSequence, lmacProcessCollision, wifi_assert, wifi_log | Data refs: .bss.our_instances, .rodata.__FUNCTION__$3, .rodata.lmacProcessTxopSuccess.str1.1, .rodata_wlog_warning.20, lmacEndFrameExchangeSequence, lmacProcessCollision, wifi_assert, wifi_log
 *   MMIO: none
 *   funcdb v3: 4 call(s), 8 ref(s); disasm: 5 call(s), 8 data ref(s)
 * Fidelity: medium - 59 instr, 11 branches, calls resolved */
int32_t lmacProcessTxRtsError(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.lmacProcessTxRtsError; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_24:;
  /* 0024: entry a1, 32 */
  a3 = (a3 >> 0) & 0xFF; /* 0027: extui a3, a3, 0, 8 */
  a2 = (a2 >> 0) & 0xFF; /* 002a: extui a2, a2, 0, 8 */
  a4 = (a4 >> 0) & 0xFF; /* 002d: extui a4, a4, 0, 8 */
  if (a3 != 10) goto L_3d; /* 0030: bnei a3, 10, 3d <lmacProcessTxRtsError+0x19> */
  a2 = 0x0; /* 0033: movi.n a2, 0 */
  MEMW(); /* 0035: memw  */
  a2 = MEM32(a2 + 44); /* 0038: l32i.n a2, a2, 44 */
  /* 003a: break 1, 15 */
L_3d:;
  a6 = (uint32_t)&lit_rodata_FUNCTION_3; /* 003d: l32r a6, 0 <lmacProcessTxRtsError-0x24> (0 <lmacProcessTxRtsError-0x24>) */ /* literal @0x0: .rodata.__FUNCTION__$3 */
  a10 = 0x1; /* 0040: movi a10, 1 */
  a5 = (uint32_t)&lit_rodata_lmacProcessTxopSuccess_str1_1; /* 0043: l32r a5, 4 <lmacProcessTxRtsError-0x20> (0 <lmacProcessTxRtsError-0x24>) */ /* literal @0x4: .rodata.lmacProcessTxopSuccess.str1.1 */
  if (a3 < 5) goto L_4c; /* 0046: bltui a3, 5, 4c <lmacProcessTxRtsError+0x28> */
  a10 = 0x0; /* 0049: movi a10, 0 */
L_4c:;
  a13 = 0x7CB; /* 004c: movi a13, 0x7cb */
  a12 = a6; /* 004f: mov.n a12, a6 */
  a11 = a5; /* 0051: mov.n a11, a5 */
  a8 = (uint32_t)&wifi_assert; /* 0053: l32r a8, 10 <lmacProcessTxRtsError-0x14> (0 <lmacProcessTxRtsError-0x24>) */ /* literal: GOT slot for wifi_assert */
  wifi_assert(a2, a3, a4, a5); /* call via literal slot */ /* 0056: callx8 a8 */
  if (a2 >= 6) goto L_65; /* 0059: bgeui a2, 6, 65 <lmacProcessTxRtsError+0x41> */
  if (a2 >= 3) goto L_6e; /* 005c: bgeui a2, 3, 6e <lmacProcessTxRtsError+0x4a> */
  if (a2 == 1) goto L_6e; /* 005f: beqi a2, 1, 6e <lmacProcessTxRtsError+0x4a> */
  goto L_a3; /* 0062: j a3 <lmacProcessTxRtsError+0x7f> */
L_65:;
  a8 = 0xC0; /* 0065: movi a8, 192 */
  if (a2 == a8) goto L_79; /* 0068: beq a2, a8, 79 <lmacProcessTxRtsError+0x55> */
  goto L_a3; /* 006b: j a3 <lmacProcessTxRtsError+0x7f> */
L_6e:;
  a10 = a3; /* 006e: mov.n a10, a3 */
  a8 = (uint32_t)&lmacProcessCollision; /* 0070: l32r a8, 14 <lmacProcessTxRtsError-0x10> (0 <lmacProcessTxRtsError-0x24>) */ /* literal: GOT slot for lmacProcessCollision */
  lmacProcessCollision(a2, a3, a4, a5); /* call via literal slot */ /* 0073: callx8 a8 */
  goto L_c4; /* 0076: j c4 <lmacProcessTxRtsError+0xa0> */
L_79:;
  a10 = (uint32_t)&bss_our_instances; /* 0079: l32r a10, 8 <lmacProcessTxRtsError-0x1c> (0 <lmacProcessTxRtsError-0x24>) */ /* literal @0x8: .bss.our_instances */
  a2 = (a3 << 8) + a3; /* 007c: addx8 a2, a3, a3 */
  a2 = (a2 << 4) + a10; /* 007f: addx4 a2, a2, a10 */
  a5 = 0x6; /* 0082: movi.n a5, 6 */
  MEM8(a2 + 18) = a5; /* 0084: s8i a5, a2, 18 */
  MEMW(); /* 0087: memw  */
  if (a4 != 0) goto L_c4; /* 008a: bnez.n a4, c4 <lmacProcessTxRtsError+0xa0> */
  a12 = a4; /* 008c: mov.n a12, a4 */
  a11 = 0x1; /* 008e: movi a11, 1 */
  a10 = a2 | a2; /* 0091: or a10, a2, a2 */
  a3 = (a3 << 8) + a3; /* 0094: addx8 a3, a3, a3 */
  MEMW(); /* 0097: memw  */
  a8 = (uint32_t)&lmacEndFrameExchangeSequence; /* 009a: l32r a8, 18 <lmacProcessTxRtsError-0xc> (0 <lmacProcessTxRtsError-0x24>) */ /* literal: GOT slot for lmacEndFrameExchangeSequence */
  lmacEndFrameExchangeSequence(a2, a3, a4, a5); /* call via literal slot */ /* 009d: callx8 a8 */
  goto L_c4; /* 00a0: j c4 <lmacProcessTxRtsError+0xa0> */
L_a3:;
  a13 = (uint32_t)&lit_rodata_wlog_warning_20; /* 00a3: l32r a13, c <lmacProcessTxRtsError-0x18> (0 <lmacProcessTxRtsError-0x24>) */ /* literal @0xC: .rodata_wlog_warning.20 */
  a12 = 0x2; /* 00a6: movi.n a12, 2 */
  a11 = 0x40; /* 00a8: movi.n a11, 64 */
  a10 = 0x6; /* 00aa: movi.n a10, 6 */
  a14 = a2 | a2; /* 00ac: or a14, a2, a2 */
  a8 = (uint32_t)&wifi_log; /* 00af: l32r a8, 1c <lmacProcessTxRtsError-0x8> (0 <lmacProcessTxRtsError-0x24>) */ /* literal: GOT slot for wifi_log */
  wifi_log(a2, a3, a4, a5); /* call via literal slot */ /* 00b2: callx8 a8 */
  a13 = 0x7F0; /* 00b5: movi a13, 0x7f0 */
  a12 = a6; /* 00b8: mov.n a12, a6 */
  a11 = a5; /* 00ba: mov.n a11, a5 */
  a10 = 0x0; /* 00bc: movi.n a10, 0 */
  a8 = (uint32_t)&wifi_assert; /* 00be: l32r a8, 20 <lmacProcessTxRtsError-0x4> (0 <lmacProcessTxRtsError-0x24>) */ /* literal: GOT slot for wifi_assert */
  wifi_assert(a2, a3, a4, a5); /* call via literal slot */ /* 00c1: callx8 a8 */
L_c4:;
  return (int32_t)a2; /* 00c4: retw.n  */
}

/* lmacProcessTxseckiderr @ lmac.o 00000004 size 18B bind GLOBAL
 * Calls: lmacEndFrameExchangeSequence | Data refs: lmacEndFrameExchangeSequence
 *   MMIO: none
 *   funcdb v3: 1 call(s), 1 ref(s); disasm: 1 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t lmacProcessTxseckiderr(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.lmacProcessTxseckiderr; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a12 = 0x0; /* 0007: movi.n a12, 0 */
  a11 = 0x1; /* 0009: movi.n a11, 1 */
  a10 = a2 | a2; /* 000b: or a10, a2, a2 */
  a8 = (uint32_t)&lmacEndFrameExchangeSequence; /* 000e: l32r a8, 0 <lmacProcessTxseckiderr-0x4> (0 <lmacProcessTxseckiderr-0x4>) */ /* literal: GOT slot for lmacEndFrameExchangeSequence */
  lmacEndFrameExchangeSequence(a2, a3, a4, a5); /* call via literal slot */ /* 0011: callx8 a8 */
  return (int32_t)a2; /* 0014: retw.n  */
}

/* lmacProcessTxError @ lmac.o 00000024 size 155B bind GLOBAL
 * Calls: lmacProcessAckTimeout, lmacProcessCollision, lmacProcessCtsTimeout, lmacProcessTxseckiderr, wifi_assert | Data refs: .bss.our_instances, .rodata.__FUNCTION__$2, .rodata.lmacProcessTxopSuccess.str1.1, lmacProcessAckTimeout, lmacProcessCollision, lmacProcessCtsTimeout, lmacProcessTxseckiderr, wifi_assert
 *   MMIO: none
 *   funcdb v3: 5 call(s), 8 ref(s); disasm: 5 call(s), 8 data ref(s)
 * Fidelity: medium - 60 instr, 15 branches, calls resolved */
int32_t lmacProcessTxError(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.lmacProcessTxError; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_24:;
  /* 0024: entry a1, 32 */
  a2 = (a2 >> 0) & 0xFF; /* 0027: extui a2, a2, 0, 8 */
  a3 = (a3 >> 0) & 0xFF; /* 002a: extui a3, a3, 0, 8 */
  a4 = (a4 >> 0) & 0xFF; /* 002d: extui a4, a4, 0, 8 */
  if (a2 != 10) goto L_3e; /* 0030: bnei a2, 10, 3e <lmacProcessTxError+0x1a> */
  a2 = 0x0; /* 0033: movi.n a2, 0 */
  MEMW(); /* 0035: memw  */
  a2 = MEM32(a2 + 44); /* 0038: l32i a2, a2, 44 */
  /* 003b: break 1, 15 */
L_3e:;
  a10 = 0x1; /* 003e: movi.n a10, 1 */
  if (a2 < 5) goto L_45; /* 0040: bltui a2, 5, 45 <lmacProcessTxError+0x21> */
  a10 = 0x0; /* 0043: movi.n a10, 0 */
L_45:;
  a13 = 0x809; /* 0045: l32r a13, 0 <lmacProcessTxError-0x24> (809 <lmacTxFrame+0x799>) */ @0x0
  a12 = (uint32_t)&lit_rodata_FUNCTION_2; /* 0048: l32r a12, 4 <lmacProcessTxError-0x20> (0 <lmacProcessTxError-0x24>) */ /* literal @0x4: .rodata.__FUNCTION__$2 */
  a11 = (uint32_t)&lit_rodata_lmacProcessTxopSuccess_str1_1; /* 004b: l32r a11, 8 <lmacProcessTxError-0x1c> (0 <lmacProcessTxError-0x24>) */ /* literal @0x8: .rodata.lmacProcessTxopSuccess.str1.1 */
  a8 = (uint32_t)&wifi_assert; /* 004e: l32r a8, 10 <lmacProcessTxError-0x14> (0 <lmacProcessTxError-0x24>) */ /* literal: GOT slot for wifi_assert */
  wifi_assert(a2, a3, a4, a5); /* call via literal slot */ /* 0051: callx8 a8 */
  if (a3 >= 6) goto L_64; /* 0054: bgeui a3, 6, 64 <lmacProcessTxError+0x40> */
  if (a3 >= 3) goto L_6e; /* 0057: bgeui a3, 3, 6e <lmacProcessTxError+0x4a> */
  if (a3 == 0) goto L_a6; /* 005a: beqz a3, a6 <lmacProcessTxError+0x82> */
  if (a3 == 1) goto L_6e; /* 005d: beqi a3, 1, 6e <lmacProcessTxError+0x4a> */
  goto L_b3; /* 0060: j b3 <lmacProcessTxError+0x8f> */
  /* 0063: .byte 00 */
L_64:;
  a8 = 0xC0; /* 0064: movi a8, 192 */
  if (a3 == a8) goto L_81; /* 0067: beq a3, a8, 81 <lmacProcessTxError+0x5d> */
  goto L_b3; /* 006a: j b3 <lmacProcessTxError+0x8f> */
  /* 006d: .byte 00 */
L_6e:;
  if (a4 != 0) goto L_7c; /* 006e: bnez.n a4, 7c <lmacProcessTxError+0x58> */
  a10 = a2; /* 0070: mov.n a10, a2 */
  a8 = (uint32_t)&lmacProcessCollision; /* 0072: l32r a8, 14 <lmacProcessTxError-0x10> (0 <lmacProcessTxError-0x24>) */ /* literal: GOT slot for lmacProcessCollision */
  lmacProcessCollision(a2, a3, a4, a5); /* call via literal slot */ /* 0075: callx8 a8 */
  goto L_bd; /* 0078: j bd <lmacProcessTxError+0x99> */
  /* 007b: .byte 00 */
L_7c:;
  a11 = 0x1; /* 007c: movi.n a11, 1 */
  goto L_b5; /* 007e: j b5 <lmacProcessTxError+0x91> */
L_81:;
  a8 = (uint32_t)&bss_our_instances; /* 0081: l32r a8, c <lmacProcessTxError-0x18> (0 <lmacProcessTxError-0x24>) */ /* literal @0xC: .bss.our_instances */
  a3 = (a2 << 8) + a2; /* 0084: addx8 a3, a2, a2 */
  a3 = (a3 << 4) + a8; /* 0087: addx4 a3, a3, a8 */
  a9 = 0x6; /* 008a: movi.n a9, 6 */
  MEM8(a3 + 18) = a9; /* 008c: s8i a9, a3, 18 */
  MEMW(); /* 008f: memw  */
  if (a4 != 0) goto L_bd; /* 0092: bnez.n a4, bd <lmacProcessTxError+0x99> */
  a11 = a2; /* 0094: mov.n a11, a2 */
  a10 = a3; /* 0096: mov.n a10, a3 */
  MEMW(); /* 0098: memw  */
  a8 = (uint32_t)&lmacProcessTxseckiderr; /* 009b: l32r a8, 18 <lmacProcessTxError-0xc> (0 <lmacProcessTxError-0x24>) */ /* literal: GOT slot for lmacProcessTxseckiderr */
  lmacProcessTxseckiderr(a2, a3, a4, a5); /* call via literal slot */ /* 009e: callx8 a8 */
  goto L_bd; /* 00a1: j bd <lmacProcessTxError+0x99> */
  /* 00a4: .byte 00 */
  /* 00a5: .byte 00 */
L_a6:;
  a11 = a4; /* 00a6: mov.n a11, a4 */
  a10 = a2; /* 00a8: mov.n a10, a2 */
  a8 = (uint32_t)&lmacProcessCtsTimeout; /* 00aa: l32r a8, 1c <lmacProcessTxError-0x8> (0 <lmacProcessTxError-0x24>) */ /* literal: GOT slot for lmacProcessCtsTimeout */
  lmacProcessCtsTimeout(a2, a3, a4, a5); /* call via literal slot */ /* 00ad: callx8 a8 */
  goto L_bd; /* 00b0: j bd <lmacProcessTxError+0x99> */
L_b3:;
  a11 = a4; /* 00b3: mov.n a11, a4 */
L_b5:;
  a10 = a2; /* 00b5: mov.n a10, a2 */
  a8 = (uint32_t)&lmacProcessAckTimeout; /* 00b7: l32r a8, 20 <lmacProcessTxError-0x4> (0 <lmacProcessTxError-0x24>) */ /* literal: GOT slot for lmacProcessAckTimeout */
  lmacProcessAckTimeout(a2, a3, a4, a5); /* call via literal slot */ /* 00ba: callx8 a8 */
L_bd:;
  return (int32_t)a2; /* 00bd: retw.n  */
}

/* lmacProcessTxComplete @ lmac.o 00000054 size 342B bind GLOBAL
 * Calls: hal_mac_get_txq_state[got], pm_is_sleeping[got], tx_pwctrl_background[got], hal_mac_clr_txq_state[got], wifi_log[got], hal_mac_get_txq_pmd[got], hal_mac_clr_txq_state[got], wifi_gpio_debug[got], .rodata[tail], lmacProcessTxSuccess[got], lmacProcessTxRtsError[got], lmacProcessCtsTimeout[got], lmacProcessAckTimeout[got], lmacProcessTxError[got], wifi_assert[got] | Data refs: hal_mac_get_txq_state, g_osi_funcs_p, pm_is_sleeping, g_pp_tx_pkt_num, tx_pwctrl_background, .bss.our_instances, hal_mac_clr_txq_state, .rodata_wlog_info.17, wifi_log, hal_mac_get_txq_pmd, wifi_gpio_debug, .rodata, lmacProcessTxSuccess, lmacProcessTxRtsError, lmacProcessCtsTimeout, lmacProcessAckTimeout, lmacProcessTxError, .rodata.__FUNCTION__$8, .rodata.lmacProcessTxopSuccess.str1.1, wifi_assert
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 15 call(s), 20 data ref(s)
 * Fidelity: low - 131 instr, 15 branches, 1 indirect; call-sequence + MMIO skeleton */
int32_t lmacProcessTxComplete(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .wifiextrairam.16; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_54:;
  /* 0054: entry a1, 48 */
  a10 = 0x2; /* 0057: movi a10, 2 */
  a8 = (uint32_t)&hal_mac_get_txq_state; /* 005a: l32r a8, 1c <lmacProcessTxComplete-0x38> (0 <lmacProcessTxComplete-0x54>) */ /* literal: GOT slot for hal_mac_get_txq_state */
  hal_mac_get_txq_state(a2, a3, a4, a5); /* call via literal slot */ /* 005d: callx8 a8 */
  a2 = (uint32_t)&g_osi_funcs_p; /* 0060: l32r a2, 0 <lmacProcessTxComplete-0x54> (0 <lmacProcessTxComplete-0x54>) */ /* literal @0x0: g_osi_funcs_p */
  a3 = 0x2; /* 0063: mov.n a3, a10 */
  a2 = MEM32(a2 + 0); /* 0065: l32i.n a2, a2, 0 */
  a10 = MEM32(a2 + 4); /* 0067: l32i.n a10, a2, 4 */
  ((int32_t(*)())a10)(a2, a3, a4, a5); /* 0069: callx8 a10 */ /* indirect */
  if (a10 == 0) goto L_a4; /* 006c: beqz.n a10, a4 <lmacProcessTxComplete+0x50> */
  a8 = (uint32_t)&pm_is_sleeping; /* 006e: l32r a8, 20 <lmacProcessTxComplete-0x34> (0 <lmacProcessTxComplete-0x54>) */ /* literal: GOT slot for pm_is_sleeping */
  pm_is_sleeping(a2, a3, a4, a5); /* call via literal slot */ /* 0071: callx8 a8 */
  if (a10 != 0) goto L_a4; /* 0074: bnez.n a10, a4 <lmacProcessTxComplete+0x50> */
  a4 = (uint32_t)&g_pp_tx_pkt_num; /* 0076: l32r a4, 4 <lmacProcessTxComplete-0x50> (0 <lmacProcessTxComplete-0x54>) */ /* literal @0x4: g_pp_tx_pkt_num */
  a2 = MEM8(a4 + 0); /* 0079: l8ui a2, a4, 0 */
  a2 = a2 + (1); /* 007c: addi.n a2, a2, 1 */
  a2 = (a2 >> 0) & 0xFF; /* 007e: extui a2, a2, 0, 8 */
  if (a2 >= 5) goto L_90; /* 0081: bgeui a2, 5, 90 <lmacProcessTxComplete+0x3c> */
  MEM8(a4 + 0) = a2; /* 0084: s8i a2, a4, 0 */
  MEMW(); /* 0087: memw  */
  MEMW(); /* 008a: memw  */
  goto L_a4; /* 008d: j a4 <lmacProcessTxComplete+0x50> */
L_90:;
  MEM8(a4 + 0) = a10; /* 0090: s8i a10, a4, 0 */
  MEMW(); /* 0093: memw  */
  a11 = a10; /* 0096: mov.n a11, a10 */
  a10 = 0x1; /* 0098: movi a10, 1 */
  MEMW(); /* 009b: memw  */
  a8 = (uint32_t)&tx_pwctrl_background; /* 009e: l32r a8, 24 <lmacProcessTxComplete-0x30> (0 <lmacProcessTxComplete-0x54>) */ /* literal: GOT slot for tx_pwctrl_background */
  tx_pwctrl_background(a2, a3, a4, a5); /* call via literal slot */ /* 00a1: callx8 a8 */
L_a4:;
  a2 = 0x0; /* 00a4: movi.n a2, 0 */
  MEM32(a1 + 0) = a2; /* 00a6: s32i.n a2, a1, 0 */
  a4 = 0x1; /* 00a8: movi.n a4, 1 */
  MEMW(); /* 00aa: memw  */
  goto L_1a5; /* 00ad: j 1a5 <lmacProcessTxComplete+0x151> */
L_b0:;
  a2 = -a3; /* 00b0: neg a2, a3 */
  a2 = a2 & a3; /* 00b3: and a2, a2, a3 */
  a2 = __builtin_clz(a2) /* approx for nsau */; /* 00b6: nsau a2, a2 */
  a2 = -a2; /* 00b9: neg a2, a2 */
  a2 = a2 + (31); /* 00bc: addi a2, a2, 31 */
  /* 00bf: ssl a2 */ /* UNMODELED: a2 clobbered */
  /* 00c2: sll a7, a4 */ /* UNMODELED: a7 clobbered */
  a5 = 0xFFFFFFFF; /* 00c5: movi.n a5, -1 */
  a5 = a5 ^ a7; /* 00c7: xor a5, a5, a7 */
  a3 = a3 & a5; /* 00ca: and a3, a3, a5 */
  a6 = (uint32_t)&bss_our_instances; /* 00cd: l32r a6, 8 <lmacProcessTxComplete-0x4c> (0 <lmacProcessTxComplete-0x54>) */ /* literal @0x8: .bss.our_instances */
  a5 = a2 << (3 & 31); /* 00d0: slli a5, a2, 3 */
  if (a2 >= 5) goto L_e1; /* 00d3: bgei a2, 5, e1 <lmacProcessTxComplete+0x8d> */
  a8 = a5 + a2; /* 00d6: add.n a8, a5, a2 */
  a8 = (a8 << 4) + a6; /* 00d8: addx4 a8, a8, a6 */
  a8 = MEM8(a8 + 18); /* 00db: l8ui a8, a8, 18 */
  if (a8 == 1) goto L_108; /* 00de: beqi a8, 1, 108 <lmacProcessTxComplete+0xb4> */
L_e1:;
  a11 = a7; /* 00e1: mov.n a11, a7 */
  a5 = a5 + a2; /* 00e3: add.n a5, a5, a2 */
  a10 = 0x2; /* 00e5: movi.n a10, 2 */
  a8 = (uint32_t)&hal_mac_clr_txq_state; /* 00e7: l32r a8, 28 <lmacProcessTxComplete-0x2c> (0 <lmacProcessTxComplete-0x54>) */ /* literal: GOT slot for hal_mac_clr_txq_state */
  hal_mac_clr_txq_state(a2, a3, a4, a5); /* call via literal slot */ /* 00ea: callx8 a8 */
  a5 = (a5 << 4) + a6; /* 00ed: addx4 a5, a5, a6 */
  a14 = MEM8(a5 + 18); /* 00f0: l8ui a14, a5, 18 */
  a15 = a2; /* 00f3: mov.n a15, a2 */
  a12 = 0x3; /* 00f5: movi.n a12, 3 */
  a11 = 0x40; /* 00f7: movi.n a11, 64 */
  a10 = 0x6; /* 00f9: movi.n a10, 6 */
  a13 = (uint32_t)&lit_rodata_wlog_info_17; /* 00fb: l32r a13, c <lmacProcessTxComplete-0x48> (0 <lmacProcessTxComplete-0x54>) */ /* literal @0xC: .rodata_wlog_info.17 */
  a8 = (uint32_t)&wifi_log; /* 00fe: l32r a8, 2c <lmacProcessTxComplete-0x28> (0 <lmacProcessTxComplete-0x54>) */ /* literal: GOT slot for wifi_log */
  wifi_log(a2, a3, a4, a5); /* call via literal slot */ /* 0101: callx8 a8 */
  goto L_1a5; /* 0104: j 1a5 <lmacProcessTxComplete+0x151> */
  /* 0107: .byte 00 */
L_108:;
  a11 = a1; /* 0108: mov.n a11, a1 */
  a10 = a2; /* 010a: mov.n a10, a2 */
  a8 = (uint32_t)&hal_mac_get_txq_pmd; /* 010c: l32r a8, 30 <lmacProcessTxComplete-0x24> (0 <lmacProcessTxComplete-0x54>) */ /* literal: GOT slot for hal_mac_get_txq_pmd */
  hal_mac_get_txq_pmd(a2, a3, a4, a5); /* call via literal slot */ /* 010f: callx8 a8 */
  a11 = a7; /* 0112: mov.n a11, a7 */
  a10 = 0x2; /* 0114: movi.n a10, 2 */
  a8 = (uint32_t)&hal_mac_clr_txq_state; /* 0116: l32r a8, 34 <lmacProcessTxComplete-0x20> (0 <lmacProcessTxComplete-0x54>) */ /* literal: GOT slot for hal_mac_clr_txq_state */
  hal_mac_clr_txq_state(a2, a3, a4, a5); /* call via literal slot */ /* 0119: callx8 a8 */
  a8 = 0xF; /* 011c: movi.n a8, 15 */
  a5 = MEM32(a1 + 0); /* 011e: l32i.n a5, a1, 0 */
  a8 = 0xF000; /* 0120: slli a8, a8, 12 */
  a5 = a5 & a8; /* 0123: and a5, a5, a8 */
  a11 = 0x3; /* 0126: movi.n a11, 3 */
  a6 = 0x2; /* 0128: movi.n a6, 2 */
  if (a5 == 0) a11 = a6; /* 012a: moveqz a11, a6, a5 */
  a10 = 0xA; /* 012d: movi.n a10, 10 */
  a8 = (uint32_t)&wifi_gpio_debug; /* 012f: l32r a8, 38 <lmacProcessTxComplete-0x1c> (0 <lmacProcessTxComplete-0x54>) */ /* literal: GOT slot for wifi_gpio_debug */
  wifi_gpio_debug(a2, a3, a4, a5); /* call via literal slot */ /* 0132: callx8 a8 */
  a8 = MEM32(a1 + 0); /* 0135: l32i.n a8, a1, 0 */
  a8 = (a8 >> 12) & 0xF; /* 0137: extui a8, a8, 12, 4 */
  if (a8 >= 6) goto L_194; /* 013a: bgeui a8, 6, 194 <lmacProcessTxComplete+0x140> */
  a5 = (uint32_t)&lit_rodata; /* 013d: l32r a5, 10 <lmacProcessTxComplete-0x44> (0 <lmacProcessTxComplete-0x54>) */ /* literal @0x10: .rodata */
  a8 = (a8 << 4) + a5; /* 0140: addx4 a8, a8, a5 */
  a5 = MEM32(a8 + 0); /* 0143: l32i.n a5, a8, 0 */
  return lit_rodata(a2, a3, a4, a5); /* tail jump */ /* 0145: jx a5 */
  /* 0148: .byte 00 */
  a11 = MEM8(a1 + 2); /* 0149: l8ui a11, a1, 2 */
  a10 = a2; /* 014c: mov.n a10, a2 */
  a8 = (uint32_t)&lmacProcessTxSuccess; /* 014e: l32r a8, 3c <lmacProcessTxComplete-0x18> (0 <lmacProcessTxComplete-0x54>) */ /* literal: GOT slot for lmacProcessTxSuccess */
  lmacProcessTxSuccess(a2, a3, a4, a5); /* call via literal slot */ /* 0151: callx8 a8 */
  goto L_1a5; /* 0154: j 1a5 <lmacProcessTxComplete+0x151> */
  a10 = MEM8(a1 + 0); /* 0157: l8ui a10, a1, 0 */
  a12 = 0x0; /* 015a: movi.n a12, 0 */
  a11 = a2; /* 015c: mov.n a11, a2 */
  a8 = (uint32_t)&lmacProcessTxRtsError; /* 015e: l32r a8, 40 <lmacProcessTxComplete-0x14> (0 <lmacProcessTxComplete-0x54>) */ /* literal: GOT slot for lmacProcessTxRtsError */
  lmacProcessTxRtsError(a2, a3, a4, a5); /* call via literal slot */ /* 0161: callx8 a8 */
  goto L_1a5; /* 0164: j 1a5 <lmacProcessTxComplete+0x151> */
  a11 = 0x0; /* 0167: movi.n a11, 0 */
  a10 = a2; /* 0169: mov.n a10, a2 */
  a8 = (uint32_t)&lmacProcessCtsTimeout; /* 016b: l32r a8, 44 <lmacProcessTxComplete-0x10> (0 <lmacProcessTxComplete-0x54>) */ /* literal: GOT slot for lmacProcessCtsTimeout */
  lmacProcessCtsTimeout(a2, a3, a4, a5); /* call via literal slot */ /* 016e: callx8 a8 */
  goto L_1a5; /* 0171: j 1a5 <lmacProcessTxComplete+0x151> */
  /* 0174: .byte 00 */
  /* 0175: .byte 00 */
  a11 = 0x0; /* 0176: movi.n a11, 0 */
  a10 = a2; /* 0178: mov.n a10, a2 */
  a8 = (uint32_t)&lmacProcessAckTimeout; /* 017a: l32r a8, 48 <lmacProcessTxComplete-0xc> (0 <lmacProcessTxComplete-0x54>) */ /* literal: GOT slot for lmacProcessAckTimeout */
  lmacProcessAckTimeout(a2, a3, a4, a5); /* call via literal slot */ /* 017d: callx8 a8 */
  goto L_1a5; /* 0180: j 1a5 <lmacProcessTxComplete+0x151> */
  a11 = MEM8(a1 + 0); /* 0183: l8ui a11, a1, 0 */
  a12 = 0x0; /* 0186: movi.n a12, 0 */
  a10 = a2; /* 0188: mov.n a10, a2 */
  a8 = (uint32_t)&lmacProcessTxError; /* 018a: l32r a8, 4c <lmacProcessTxComplete-0x8> (0 <lmacProcessTxComplete-0x54>) */ /* literal: GOT slot for lmacProcessTxError */
  lmacProcessTxError(a2, a3, a4, a5); /* call via literal slot */ /* 018d: callx8 a8 */
  goto L_1a5; /* 0190: j 1a5 <lmacProcessTxComplete+0x151> */
  /* 0193: .byte 00 */
L_194:;
  a12 = (uint32_t)&lit_rodata_FUNCTION_8; /* 0194: l32r a12, 14 <lmacProcessTxComplete-0x40> (0 <lmacProcessTxComplete-0x54>) */ /* literal @0x14: .rodata.__FUNCTION__$8 */
  a13 = 0x627; /* 0197: movi a13, 0x627 */
  a10 = 0x0; /* 019a: movi.n a10, 0 */
  a11 = (uint32_t)&lit_rodata_lmacProcessTxopSuccess_str1_1; /* 019c: l32r a11, 18 <lmacProcessTxComplete-0x3c> (0 <lmacProcessTxComplete-0x54>) */ /* literal @0x18: .rodata.lmacProcessTxopSuccess.str1.1 */
  a8 = (uint32_t)&wifi_assert; /* 019f: l32r a8, 50 <lmacProcessTxComplete-0x4> (0 <lmacProcessTxComplete-0x54>) */ /* literal: GOT slot for wifi_assert */
  wifi_assert(a2, a3, a4, a5); /* call via literal slot */ /* 01a2: callx8 a8 */
L_1a5:;
  if (a3 != 0) goto L_b0; /* 01a5: bnez a3, b0 <lmacProcessTxComplete+0x5c> */
  return (int32_t)a2; /* 01a8: retw.n  */
}

/* lmacRxDone @ lmac.o 00000008 size 24B bind GLOBAL
 * Calls: ppEnqueueRxq, pp_post | Data refs: ppEnqueueRxq, pp_post
 *   MMIO: none
 *   funcdb v3: 2 call(s), 2 ref(s); disasm: 2 call(s), 2 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t lmacRxDone(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.lmacRxDone; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_8:;
  /* 0008: entry a1, 32 */
  a10 = a2 | a2; /* 000b: or a10, a2, a2 */
  a8 = (uint32_t)&ppEnqueueRxq; /* 000e: l32r a8, 0 <lmacRxDone-0x8> (0 <lmacRxDone-0x8>) */ /* literal: GOT slot for ppEnqueueRxq */
  ppEnqueueRxq(a2, a3, a4, a5); /* call via literal slot */ /* 0011: callx8 a8 */
  a11 = 0x0; /* 0014: movi.n a11, 0 */
  a10 = 0x11; /* 0016: movi.n a10, 17 */
  a8 = (uint32_t)&pp_post; /* 0018: l32r a8, 4 <lmacRxDone-0x4> (0 <lmacRxDone-0x8>) */ /* literal: GOT slot for pp_post */
  pp_post(a2, a3, a4, a5); /* call via literal slot */ /* 001b: callx8 a8 */
  return (int32_t)a2; /* 001e: retw.n  */
}

/* lmacDisableTransmit @ lmac.o 00000020 size 133B bind GLOBAL
 * Calls: ets_delay_us, hal_mac_is_txq_valid, hal_mac_set_txq_invalid, hal_mac_tx_set_cca, hal_mac_txq_disable, lmacDiscardFrameExchangeSequence | Data refs: .bss.our_instances, ets_delay_us, hal_mac_is_txq_valid, hal_mac_set_txq_invalid, hal_mac_tx_set_cca, hal_mac_txq_disable, lmacDiscardFrameExchangeSequence
 *   MMIO: none
 *   funcdb v3: 6 call(s), 7 ref(s); disasm: 7 call(s), 7 data ref(s)
 * Fidelity: medium - 49 instr, 4 branches, calls resolved */
int32_t lmacDisableTransmit(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.lmacDisableTransmit; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_20:;
  /* 0020: entry a1, 32 */
  a10 = 0x3; /* 0023: movi a10, 3 */
  a8 = (uint32_t)&hal_mac_tx_set_cca; /* 0026: l32r a8, 4 <lmacDisableTransmit-0x1c> (0 <lmacDisableTransmit-0x20>) */ /* literal: GOT slot for hal_mac_tx_set_cca */
  hal_mac_tx_set_cca(a2, a3, a4, a5); /* call via literal slot */ /* 0029: callx8 a8 */
  a10 = 0x10; /* 002c: movi a10, 16 */
  a2 = (a2 >> 0) & 0xFF; /* 002f: extui a2, a2, 0, 8 */
  a8 = (uint32_t)&ets_delay_us; /* 0032: l32r a8, 8 <lmacDisableTransmit-0x18> (0 <lmacDisableTransmit-0x20>) */ /* literal: GOT slot for ets_delay_us */
  ets_delay_us(a2, a3, a4, a5); /* call via literal slot */ /* 0035: callx8 a8 */
  a10 = a2; /* 0038: mov.n a10, a2 */
  a8 = (uint32_t)&hal_mac_is_txq_valid; /* 003a: l32r a8, c <lmacDisableTransmit-0x14> (0 <lmacDisableTransmit-0x20>) */ /* literal: GOT slot for hal_mac_is_txq_valid */
  hal_mac_is_txq_valid(a2, a3, a4, a5); /* call via literal slot */ /* 003d: callx8 a8 */
  a5 = a10; /* 0040: mov.n a5, a10 */
  a10 = a2; /* 0042: mov.n a10, a2 */
  a8 = (uint32_t)&hal_mac_set_txq_invalid; /* 0044: l32r a8, 10 <lmacDisableTransmit-0x10> (0 <lmacDisableTransmit-0x20>) */ /* literal: GOT slot for hal_mac_set_txq_invalid */
  hal_mac_set_txq_invalid(a2, a3, a4, a5); /* call via literal slot */ /* 0047: callx8 a8 */
  a10 = 0x0; /* 004a: movi.n a10, 0 */
  a8 = (uint32_t)&hal_mac_tx_set_cca; /* 004c: l32r a8, 14 <lmacDisableTransmit-0xc> (0 <lmacDisableTransmit-0x20>) */ /* literal: GOT slot for hal_mac_tx_set_cca */
  hal_mac_tx_set_cca(a2, a3, a4, a5); /* call via literal slot */ /* 004f: callx8 a8 */
  a3 = a2 << (3 & 31); /* 0052: slli a3, a2, 3 */
  a4 = (uint32_t)&bss_our_instances; /* 0055: l32r a4, 0 <lmacDisableTransmit-0x20> (0 <lmacDisableTransmit-0x20>) */ /* literal @0x0: .bss.our_instances */
  if (a5 == 0) goto L_87; /* 0058: beqz.n a5, 87 <lmacDisableTransmit+0x67> */
  a10 = a2; /* 005a: mov.n a10, a2 */
  a8 = (uint32_t)&hal_mac_txq_disable; /* 005c: l32r a8, 18 <lmacDisableTransmit-0x8> (0 <lmacDisableTransmit-0x20>) */ /* literal: GOT slot for hal_mac_txq_disable */
  hal_mac_txq_disable(a2, a3, a4, a5); /* call via literal slot */ /* 005f: callx8 a8 */
  a3 = a3 + a2; /* 0062: add.n a3, a3, a2 */
  a3 = (a3 << 4) + a4; /* 0064: addx4 a3, a3, a4 */
  a8 = 0x6; /* 0067: movi a8, 6 */
  MEM8(a3 + 18) = a8; /* 006a: s8i a8, a3, 18 */
  MEMW(); /* 006d: memw  */
  a3 = MEM32(a3 + 0); /* 0070: l32i a3, a3, 0 */
  if (a3 == 0) goto L_a0; /* 0073: beqz.n a3, a0 <lmacDisableTransmit+0x80> */
  a2 = (a2 << 8) + a2; /* 0075: addx8 a2, a2, a2 */
  a10 = (a2 << 4) + a4; /* 0078: addx4 a10, a2, a4 */
  MEMW(); /* 007b: memw  */
  a8 = (uint32_t)&lmacDiscardFrameExchangeSequence; /* 007e: l32r a8, 1c <lmacDisableTransmit-0x4> (0 <lmacDisableTransmit-0x20>) */ /* literal: GOT slot for lmacDiscardFrameExchangeSequence */
  lmacDiscardFrameExchangeSequence(a2, a3, a4, a5); /* call via literal slot */ /* 0081: callx8 a8 */
  goto L_a0; /* 0084: j a0 <lmacDisableTransmit+0x80> */
L_87:;
  a3 = a3 + a2; /* 0087: add.n a3, a3, a2 */
  a3 = (a3 << 4) + a4; /* 0089: addx4 a3, a3, a4 */
  a2 = MEM32(a3 + 0); /* 008c: l32i.n a2, a3, 0 */
  if (a2 == 0) goto L_a0; /* 008e: beqz.n a2, a0 <lmacDisableTransmit+0x80> */
  a3 = 0x1; /* 0090: movi.n a3, 1 */
  a3 = 0x20000; /* 0092: slli a3, a3, 17 */
  a4 = MEM32(a2 + 44); /* 0095: l32i.n a4, a2, 44 */
  a2 = MEM32(a4 + 0); /* 0097: l32i a2, a4, 0 */
  a2 = a2 | a3; /* 009a: or a2, a2, a3 */
  MEM32(a4 + 0) = a2; /* 009d: s32i a2, a4, 0 */
L_a0:;
  MEMW(); /* 00a0: memw  */
  return (int32_t)a2; /* 00a3: retw.n  */
}

/* lmacProcessTxTimeout @ lmac.o 0000000c size 74B bind GLOBAL
 * Calls: hal_mac_clr_txq_state, hal_mac_get_txq_state, lmacDisableTransmit | Data refs: hal_mac_clr_txq_state, hal_mac_get_txq_state, lmacDisableTransmit
 *   MMIO: none
 *   funcdb v3: 3 call(s), 3 ref(s); disasm: 3 call(s), 3 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t lmacProcessTxTimeout(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.lmacProcessTxTimeout; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_c:;
  /* 000c: entry a1, 32 */
  a10 = 0x1; /* 000f: movi a10, 1 */
  a8 = (uint32_t)&hal_mac_get_txq_state; /* 0012: l32r a8, 0 <lmacProcessTxTimeout-0xc> (0 <lmacProcessTxTimeout-0xc>) */ /* literal: GOT slot for hal_mac_get_txq_state */
  hal_mac_get_txq_state(a2, a3, a4, a5); /* call via literal slot */ /* 0015: callx8 a8 */
  a3 = 0x1; /* 0018: or a3, a10, a10 */
  if (a10 == 0) goto L_54; /* 001b: beqz.n a10, 54 <lmacProcessTxTimeout+0x48> */
  a4 = 0x1; /* 001d: movi a4, 1 */
L_20:;
  a10 = 0xFFFFFFFF; /* 0020: neg a10, a3 */
  a10 = 0x1; /* 0023: and a10, a10, a3 */
  a10 = __builtin_clz(a10) /* approx for nsau */; /* 0026: nsau a10, a10 */
  a10 = -a10; /* 0029: neg a10, a10 */
  a2 = a10 + (31); /* 002c: addi a2, a10, 31 */
  a10 = a2 | a2; /* 002f: or a10, a2, a2 */
  a8 = (uint32_t)&lmacDisableTransmit; /* 0032: l32r a8, 4 <lmacProcessTxTimeout-0x8> (0 <lmacProcessTxTimeout-0xc>) */ /* literal: GOT slot for lmacDisableTransmit */
  lmacDisableTransmit(a2, a3, a4, a5); /* call via literal slot */ /* 0035: callx8 a8 */
  /* 0038: ssl a2 */ /* UNMODELED: a2 clobbered */
  /* 003b: sll a2, a4 */ /* UNMODELED: a2 clobbered */
  a11 = a2; /* 003e: mov.n a11, a2 */
  a10 = 0x1; /* 0040: movi a10, 1 */
  a8 = (uint32_t)&hal_mac_clr_txq_state; /* 0043: l32r a8, 8 <lmacProcessTxTimeout-0x4> (0 <lmacProcessTxTimeout-0xc>) */ /* literal: GOT slot for hal_mac_clr_txq_state */
  hal_mac_clr_txq_state(a2, a3, a4, a5); /* call via literal slot */ /* 0046: callx8 a8 */
  a8 = 0xFFFFFFFF; /* 0049: movi.n a8, -1 */
  a2 = a8 ^ a2; /* 004b: xor a2, a8, a2 */
  a3 = a3 & a2; /* 004e: and a3, a3, a2 */
  if (a3 != 0) goto L_20; /* 0051: bnez a3, 20 <lmacProcessTxTimeout+0x14> */
L_54:;
  return (int32_t)a2; /* 0054: retw.n  */
}

/* lmacStopTransmit @ lmac.o 0000002c size 214B bind GLOBAL
 * Calls: esf_buf_recycle, ets_delay_us, hal_mac_is_txq_valid, hal_mac_set_txq_invalid, hal_mac_tx_set_cca, hal_mac_txq_disable, ppDirectRecycleAmpdu | Data refs: .bss.our_instances, esf_buf_recycle, ets_delay_us, hal_mac_is_txq_valid, hal_mac_set_txq_invalid, hal_mac_tx_set_cca, hal_mac_txq_disable, pTxRx, ppDirectRecycleAmpdu
 *   MMIO: none
 *   funcdb v3: 7 call(s), 9 ref(s); disasm: 9 call(s), 9 data ref(s)
 * Fidelity: medium - 81 instr, 10 branches, calls resolved */
int32_t lmacStopTransmit(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.lmacStopTransmit; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_2c:;
  /* 002c: entry a1, 32 */
  a10 = 0x3; /* 002f: movi a10, 3 */
  a8 = (uint32_t)&hal_mac_tx_set_cca; /* 0032: l32r a8, 8 <lmacStopTransmit-0x24> (0 <lmacStopTransmit-0x2c>) */ /* literal: GOT slot for hal_mac_tx_set_cca */
  hal_mac_tx_set_cca(a2, a3, a4, a5); /* call via literal slot */ /* 0035: callx8 a8 */
  a10 = 0x10; /* 0038: movi a10, 16 */
  a2 = (a2 >> 0) & 0xFF; /* 003b: extui a2, a2, 0, 8 */
  a8 = (uint32_t)&ets_delay_us; /* 003e: l32r a8, c <lmacStopTransmit-0x20> (0 <lmacStopTransmit-0x2c>) */ /* literal: GOT slot for ets_delay_us */
  ets_delay_us(a2, a3, a4, a5); /* call via literal slot */ /* 0041: callx8 a8 */
  a10 = a2; /* 0044: mov.n a10, a2 */
  a8 = (uint32_t)&hal_mac_is_txq_valid; /* 0046: l32r a8, 10 <lmacStopTransmit-0x1c> (0 <lmacStopTransmit-0x2c>) */ /* literal: GOT slot for hal_mac_is_txq_valid */
  hal_mac_is_txq_valid(a2, a3, a4, a5); /* call via literal slot */ /* 0049: callx8 a8 */
  a6 = a10; /* 004c: mov.n a6, a10 */
  a10 = a2; /* 004e: mov.n a10, a2 */
  a8 = (uint32_t)&hal_mac_set_txq_invalid; /* 0050: l32r a8, 14 <lmacStopTransmit-0x18> (0 <lmacStopTransmit-0x2c>) */ /* literal: GOT slot for hal_mac_set_txq_invalid */
  hal_mac_set_txq_invalid(a2, a3, a4, a5); /* call via literal slot */ /* 0053: callx8 a8 */
  a10 = 0x0; /* 0056: movi.n a10, 0 */
  a8 = (uint32_t)&hal_mac_tx_set_cca; /* 0058: l32r a8, 18 <lmacStopTransmit-0x14> (0 <lmacStopTransmit-0x2c>) */ /* literal: GOT slot for hal_mac_tx_set_cca */
  hal_mac_tx_set_cca(a2, a3, a4, a5); /* call via literal slot */ /* 005b: callx8 a8 */
  a4 = (uint32_t)&bss_our_instances; /* 005e: l32r a4, 0 <lmacStopTransmit-0x2c> (0 <lmacStopTransmit-0x2c>) */ /* literal @0x0: .bss.our_instances */
  a5 = (a2 << 8) + a2; /* 0061: addx8 a5, a2, a2 */
  a5 = (a5 << 4) + a4; /* 0064: addx4 a5, a5, a4 */
  a3 = a2 << (3 & 31); /* 0067: slli a3, a2, 3 */
  a5 = MEM32(a5 + 0); /* 006a: l32i a5, a5, 0 */
  if (a6 == 0) goto L_c9; /* 006d: beqz a6, c9 <lmacStopTransmit+0x9d> */
  a10 = a2; /* 0070: mov.n a10, a2 */
  a8 = (uint32_t)&hal_mac_txq_disable; /* 0072: l32r a8, 1c <lmacStopTransmit-0x10> (0 <lmacStopTransmit-0x2c>) */ /* literal: GOT slot for hal_mac_txq_disable */
  hal_mac_txq_disable(a2, a3, a4, a5); /* call via literal slot */ /* 0075: callx8 a8 */
  if (a5 == 0) goto L_100; /* 0078: beqz a5, 100 <lmacStopTransmit+0xd4> */
  a8 = MEM32(a5 + 44); /* 007b: l32i.n a8, a5, 44 */
  a10 = a5; /* 007d: mov.n a10, a5 */
  a9 = MEM32(a8 + 0); /* 007f: l32i.n a9, a8, 0 */
  if ((a9 >> 22) & 1) goto L_a4; /* 0081: bbsi a9, 22, a4 <lmacStopTransmit+0x78> */
  a9 = MEM8(a5 + 26); /* 0084: l8ui a9, a5, 26 */
  if (a9 != 5) goto L_ad; /* 0087: bnei a9, 5, ad <lmacStopTransmit+0x81> */
  a8 = MEM32(a8 + 16); /* 008a: l32i.n a8, a8, 16 */
  a8 = (a8 >> 20) & 0xF; /* 008c: extui a8, a8, 20, 4 */
  a8 = a8 + (1); /* 008f: addi.n a8, a8, 1 */
  a8 = (a8 << 2) + a8; /* 0091: addx2 a8, a8, a8 */
  a5 = (uint32_t)&pTxRx; /* 0094: l32r a5, 4 <lmacStopTransmit-0x28> (0 <lmacStopTransmit-0x2c>) */ /* literal @0x4: pTxRx */
  a8 = a8 << (4 & 31); /* 0097: slli a8, a8, 4 */
  a5 = MEM32(a5 + 0); /* 009a: l32i.n a5, a5, 0 */
  a5 = a5 + a8; /* 009c: add.n a5, a5, a8 */
  a10 = MEM32(a5 + 4); /* 009e: l32i a10, a5, 4 */
  if (a10 == 0) goto L_b3; /* 00a1: beqz a10, b3 <lmacStopTransmit+0x87> */
L_a4:;
  a8 = (uint32_t)&ppDirectRecycleAmpdu; /* 00a4: l32r a8, 20 <lmacStopTransmit-0xc> (0 <lmacStopTransmit-0x2c>) */ /* literal: GOT slot for ppDirectRecycleAmpdu */
  ppDirectRecycleAmpdu(a2, a3, a4, a5); /* call via literal slot */ /* 00a7: callx8 a8 */
  goto L_b3; /* 00aa: j b3 <lmacStopTransmit+0x87> */
L_ad:;
  a8 = (uint32_t)&esf_buf_recycle; /* 00ad: l32r a8, 24 <lmacStopTransmit-0x8> (0 <lmacStopTransmit-0x2c>) */ /* literal: GOT slot for esf_buf_recycle */
  esf_buf_recycle(a2, a3, a4, a5); /* call via literal slot */ /* 00b0: callx8 a8 */
L_b3:;
  a3 = a3 + a2; /* 00b3: add.n a3, a3, a2 */
  a3 = (a3 << 4) + a4; /* 00b5: addx4 a3, a3, a4 */
  a2 = 0x0; /* 00b8: movi.n a2, 0 */
  MEM32(a3 + 0) = a2; /* 00ba: s32i.n a2, a3, 0 */
  MEM8(a3 + 18) = a2; /* 00bc: s8i a2, a3, 18 */
  MEMW(); /* 00bf: memw  */
  MEMW(); /* 00c2: memw  */
  goto L_100; /* 00c5: j 100 <lmacStopTransmit+0xd4> */
  /* 00c8: .byte 00 */
L_c9:;
  if (a5 == 0) goto L_100; /* 00c9: beqz.n a5, 100 <lmacStopTransmit+0xd4> */
  a3 = MEM32(a5 + 44); /* 00cb: l32i.n a3, a5, 44 */
  a4 = 0x1; /* 00cd: movi.n a4, 1 */
  a4 = 0x20000; /* 00cf: slli a4, a4, 17 */
  a2 = MEM32(a3 + 0); /* 00d2: l32i.n a2, a3, 0 */
  a2 = a2 | a4; /* 00d4: or a2, a2, a4 */
  MEM32(a3 + 0) = a2; /* 00d7: s32i.n a2, a3, 0 */
  a2 = MEM8(a5 + 26); /* 00d9: l8ui a2, a5, 26 */
  if (a2 != 5) goto L_100; /* 00dc: bnei a2, 5, 100 <lmacStopTransmit+0xd4> */
  a8 = MEM32(a3 + 16); /* 00df: l32i.n a8, a3, 16 */
  a8 = (a8 >> 20) & 0xF; /* 00e1: extui a8, a8, 20, 4 */
  a8 = a8 + (1); /* 00e4: addi.n a8, a8, 1 */
  a8 = (a8 << 2) + a8; /* 00e6: addx2 a8, a8, a8 */
  a2 = (uint32_t)&pTxRx; /* 00e9: l32r a2, 4 <lmacStopTransmit-0x28> (0 <lmacStopTransmit-0x2c>) */ /* literal @0x4: pTxRx */
  a8 = a8 << (4 & 31); /* 00ec: slli a8, a8, 4 */
  a2 = MEM32(a2 + 0); /* 00ef: l32i.n a2, a2, 0 */
  a2 = a2 + a8; /* 00f1: add.n a2, a2, a8 */
  a10 = MEM32(a2 + 4); /* 00f3: l32i.n a10, a2, 4 */
  if (a10 == 0) goto L_100; /* 00f5: beqz.n a10, 100 <lmacStopTransmit+0xd4> */
  MEMW(); /* 00f7: memw  */
  a8 = (uint32_t)&ppDirectRecycleAmpdu; /* 00fa: l32r a8, 28 <lmacStopTransmit-0x4> (0 <lmacStopTransmit-0x2c>) */ /* literal: GOT slot for ppDirectRecycleAmpdu */
  ppDirectRecycleAmpdu(a2, a3, a4, a5); /* call via literal slot */ /* 00fd: callx8 a8 */
L_100:;
  return (int32_t)a2; /* 0100: retw.n  */
}

/* dbg_lmac_get_acs @ lmac.o 00000004 size 8B bind GLOBAL
 * Calls: none | Data refs: .bss.our_instances
 *   MMIO: none
 *   funcdb v3: 0 call(s), 1 ref(s); disasm: 0 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t dbg_lmac_get_acs(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.dbg_lmac_get_acs; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a2 = (uint32_t)&bss_our_instances; /* 0007: l32r a2, 0 <dbg_lmac_get_acs-0x4> (0 <dbg_lmac_get_acs-0x4>) */ /* literal @0x0: .bss.our_instances */
  return (int32_t)a2; /* 000a: retw.n  */
}

/* lmac_stop_hw_txq @ lmac.o 00000018 size 68B bind GLOBAL
 * Calls: lmacStopTransmit, wifi_log | Data refs: .bss.our_instances, .rodata_wlog_info.26, .rodata_wlog_warning.27, lmacStopTransmit, wifi_log
 *   MMIO: none
 *   funcdb v3: 2 call(s), 5 ref(s); disasm: 3 call(s), 5 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t lmac_stop_hw_txq(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.lmac_stop_hw_txq; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_18:;
  /* 0018: entry a1, 32 */
  a13 = (uint32_t)&lit_rodata_wlog_info_26; /* 001b: l32r a13, 0 <lmac_stop_hw_txq-0x18> (0 <lmac_stop_hw_txq-0x18>) */ /* literal @0x0: .rodata_wlog_info.26 */
  a12 = 0x3; /* 001e: movi a12, 3 */
  a11 = 0x1; /* 0021: movi.n a11, 1 */
  a10 = 0x6; /* 0023: movi a10, 6 */
  a8 = (uint32_t)&wifi_log; /* 0026: l32r a8, c <lmac_stop_hw_txq-0xc> (0 <lmac_stop_hw_txq-0x18>) */ /* literal: GOT slot for wifi_log */
  wifi_log(a2, a3, a4, a5); /* call via literal slot */ /* 0029: callx8 a8 */
  a3 = (uint32_t)&bss_our_instances; /* 002c: l32r a3, 4 <lmac_stop_hw_txq-0x14> (0 <lmac_stop_hw_txq-0x18>) */ /* literal @0x4: .bss.our_instances */
  a2 = 0x0; /* 002f: movi.n a2, 0 */
L_31:;
  a15 = MEM8(a3 + 18); /* 0031: l8ui a15, a3, 18 */
  if (a15 == 0) goto L_50; /* 0034: beqz.n a15, 50 <lmac_stop_hw_txq+0x38> */
  a10 = 0x6; /* 0036: movi.n a10, 6 */
  a14 = 0x0; /* 0038: mov.n a14, a2 */
  a13 = (uint32_t)&lit_rodata_wlog_warning_27; /* 003a: l32r a13, 8 <lmac_stop_hw_txq-0x10> (0 <lmac_stop_hw_txq-0x18>) */ /* literal @0x8: .rodata_wlog_warning.27 */
  a12 = 0x2; /* 003d: movi.n a12, 2 */
  a11 = 0x40; /* 003f: movi a11, 64 */
  a8 = (uint32_t)&wifi_log; /* 0042: l32r a8, 10 <lmac_stop_hw_txq-0x8> (0 <lmac_stop_hw_txq-0x18>) */ /* literal: GOT slot for wifi_log */
  wifi_log(a2, a3, a4, a5); /* call via literal slot */ /* 0045: callx8 a8 */
  a10 = a2; /* 0048: mov.n a10, a2 */
  a8 = (uint32_t)&lmacStopTransmit; /* 004a: l32r a8, 14 <lmac_stop_hw_txq-0x4> (0 <lmac_stop_hw_txq-0x18>) */ /* literal: GOT slot for lmacStopTransmit */
  lmacStopTransmit(a2, a3, a4, a5); /* call via literal slot */ /* 004d: callx8 a8 */
L_50:;
  a2 = a2 + (1); /* 0050: addi.n a2, a2, 1 */
  a3 = a3 + (36); /* 0052: addi a3, a3, 36 */
  if (a2 != 5) goto L_31; /* 0055: bnei a2, 5, 31 <lmac_stop_hw_txq+0x19> */
  a2 = 0x0; /* 0058: movi.n a2, 0 */
  return (int32_t)a2; /* 005a: retw.n  */
}

/* is_lmac_idle @ lmac.o 00000004 size 29B bind GLOBAL
 * Calls: none | Data refs: .bss.our_instances
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t is_lmac_idle(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .wifi0iram.28; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a9 = (uint32_t)&bss_our_instances; /* 0007: l32r a9, 0 <is_lmac_idle-0x4> (0 <is_lmac_idle-0x4>) */ /* literal @0x0: .bss.our_instances */
  a8 = 0x5; /* 000a: movi a8, 5 */
  /* 000d: loop a8, 18 <is_lmac_idle+0x14> */ /* loop a8 times, end L_18; body shown single-pass */
  a2 = MEM8(a9 + 18); /* 0010: l8ui a2, a9, 18 */
  if (a2 != 0) goto L_1d; /* 0013: bnez.n a2, 1d <is_lmac_idle+0x19> */
  a9 = a9 + (36); /* 0015: addi a9, a9, 36 */
L_18:;
  a2 = 0x1; /* 0018: movi.n a2, 1 */
  goto L_1f; /* 001a: j 1f <is_lmac_idle+0x1b> */
L_1d:;
  a2 = 0x0; /* 001d: movi.n a2, 0 */
L_1f:;
  return (int32_t)a2; /* 001f: retw.n  */
}

/* esp_wifi_set_11b_tx_plcp @ lmac.o 00000004 size 20B bind GLOBAL
 * Calls: none | Data refs: lmacConfMib
 *   MMIO: none
 *   funcdb v3: 0 call(s), 1 ref(s); disasm: 0 call(s), 1 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
int32_t esp_wifi_set_11b_tx_plcp(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.esp_wifi_set_11b_tx_plcp; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
L_4:;
  /* 0004: entry a1, 32 */
  a8 = (uint32_t)&lmacConfMib; /* 0007: l32r a8, 0 <esp_wifi_set_11b_tx_plcp-0x4> (0 <esp_wifi_set_11b_tx_plcp-0x4>) */ /* literal @0x0: lmacConfMib */
  MEM8(a8 + 45) = a3; /* 000a: s8i a3, a8, 45 */
  MEM8(a8 + 46) = a2; /* 000d: s8i a2, a8, 46 */
  MEMW(); /* 0010: memw  */
  MEMW(); /* 0013: memw  */
  return (int32_t)a2; /* 0016: retw.n  */
}

/* offchan_in_progress @ lmac.o 00000000 size 15B bind LOCAL
 * Calls: none | Data refs: none
 *   MMIO: none
 *   funcdb v3: 0 call(s), 0 ref(s); disasm: 0 call(s), 0 data ref(s)
 * Fidelity: high - straight-line / few branches, all refs resolved */
static int32_t offchan_in_progress(uint32_t a2, uint32_t a3, uint32_t a4,
                     uint32_t a5, uint32_t a6, uint32_t a7) {
  /* section .text.offchan_in_progress; Xtensa ABI: args a2..a7, return a2 */
  uint32_t a0 = 0, a1 = 0, a8 = 0, a9 = 0, a10 = 0, a11 = 0,
           a12 = 0, a13 = 0, a14 = 0, a15 = 0;
  /* 0000: .word 0x00000000 (literal pool) */
  /* 0004: entry a1, 32 */
  a8 = 0x0; /* 0007: l32r a8, 0 <.text.offchan_in_progress> (0 <.text.offchan_in_progress>) */ @0x0
  a2 = MEM8(a8 + 0); /* 000a: l8ui a2, a8, 0 */
  return (int32_t)a2; /* 000d: retw.n  */
}

