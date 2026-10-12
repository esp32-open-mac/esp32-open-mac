/* ieee80211_timer.o - reconstructed control-path C (offline, from objdump -d -r).
 * 37 code sections recovered. Fidelity per function below.
 * Conventions: args a2..a7 (Xtensa windowed ABI); outgoing call args
 * traced as a10..; u32 used for pointers/regs; opaque_* marks unrecovered.
 */
#include <stdint.h>
typedef unsigned char u8; typedef unsigned short u16; typedef unsigned int u32;
static u32 opaque_result, last_call_result;
/* ---- externals (U symbols + literal refs) ---- */
extern u32 rodata___FUNCTION___0; /* .rodata.__FUNCTION__$0 */
extern u32 rodata___FUNCTION___1; /* .rodata.__FUNCTION__$1 */
extern u32 rodata___FUNCTION___10; /* .rodata.__FUNCTION__$10 */
extern u32 rodata___FUNCTION___11; /* .rodata.__FUNCTION__$11 */
extern u32 rodata___FUNCTION___12; /* .rodata.__FUNCTION__$12 */
extern u32 rodata___FUNCTION___13; /* .rodata.__FUNCTION__$13 */
extern u32 rodata___FUNCTION___14; /* .rodata.__FUNCTION__$14 */
extern u32 rodata___FUNCTION___15; /* .rodata.__FUNCTION__$15 */
extern u32 rodata___FUNCTION___16; /* .rodata.__FUNCTION__$16 */
extern u32 rodata___FUNCTION___2; /* .rodata.__FUNCTION__$2 */
extern u32 rodata___FUNCTION___3; /* .rodata.__FUNCTION__$3 */
extern u32 rodata___FUNCTION___4; /* .rodata.__FUNCTION__$4 */
extern u32 rodata___FUNCTION___5; /* .rodata.__FUNCTION__$5 */
extern u32 rodata___FUNCTION___6; /* .rodata.__FUNCTION__$6 */
extern u32 rodata___FUNCTION___7; /* .rodata.__FUNCTION__$7 */
extern u32 rodata___FUNCTION___8; /* .rodata.__FUNCTION__$8 */
extern u32 rodata___FUNCTION___9; /* .rodata.__FUNCTION__$9 */
extern u32 rodata_wlog_error_23; /* .rodata_wlog_error.23 */
extern u32 rodata_wlog_error_24; /* .rodata_wlog_error.24 */
extern u32 rodata_wlog_error_25; /* .rodata_wlog_error.25 */
extern u32 rodata_wlog_error_26; /* .rodata_wlog_error.26 */
extern u32 rodata_wlog_info_10; /* .rodata_wlog_info.10 */
extern u32 rodata_wlog_info_11; /* .rodata_wlog_info.11 */
extern u32 rodata_wlog_info_12; /* .rodata_wlog_info.12 */
extern u32 rodata_wlog_info_13; /* .rodata_wlog_info.13 */
extern u32 rodata_wlog_info_14; /* .rodata_wlog_info.14 */
extern u32 rodata_wlog_info_15; /* .rodata_wlog_info.15 */
extern u32 rodata_wlog_info_16; /* .rodata_wlog_info.16 */
extern u32 rodata_wlog_info_17; /* .rodata_wlog_info.17 */
extern u32 rodata_wlog_info_18; /* .rodata_wlog_info.18 */
extern u32 rodata_wlog_info_19; /* .rodata_wlog_info.19 */
extern u32 rodata_wlog_info_2; /* .rodata_wlog_info.2 */
extern u32 rodata_wlog_info_20; /* .rodata_wlog_info.20 */
extern u32 rodata_wlog_info_3; /* .rodata_wlog_info.3 */
extern u32 rodata_wlog_info_4; /* .rodata_wlog_info.4 */
extern u32 rodata_wlog_info_5; /* .rodata_wlog_info.5 */
extern u32 rodata_wlog_info_6; /* .rodata_wlog_info.6 */
extern u32 rodata_wlog_info_7; /* .rodata_wlog_info.7 */
extern u32 rodata_wlog_info_8; /* .rodata_wlog_info.8 */
extern u32 rodata_wlog_info_9; /* .rodata_wlog_info.9 */
extern u32 rodata_wlog_warning_21; /* .rodata_wlog_warning.21 */
extern u32 rodata_wlog_warning_22; /* .rodata_wlog_warning.22 */
extern u32 text_ieee80211_hostap_handle; /* .text.ieee80211_hostap_handle */
extern u32 text_ieee80211_send_beacon; /* .text.ieee80211_send_beacon */
extern u32 addba_timeout_process(); /* addba_timeout_process */
extern u32 ap_sa_query_timeout_process(); /* ap_sa_query_timeout_process */
extern u32 ap_try_sa_query_process(); /* ap_try_sa_query_process */
extern u32 chm_end_op_timeout_process(); /* chm_end_op_timeout_process */
extern u32 cnx_assoc_timeout_process(); /* cnx_assoc_timeout_process */
extern u32 cnx_auth_timeout_process(); /* cnx_auth_timeout_process */
extern u32 cnx_beacon_timeout_process(); /* cnx_beacon_timeout_process */
extern u32 cnx_connect_next_ap_timeout_process(); /* cnx_connect_next_ap_timeout_process */
extern u32 cnx_csa_fn_process(); /* cnx_csa_fn_process */
extern u32 cnx_handshake_timeout_process(); /* cnx_handshake_timeout_process */
extern u32 esp_sta_reset_rmac_process(); /* esp_sta_reset_rmac_process */
extern u32 g_ic; /* g_ic */
extern u32 g_osi_funcs_p; /* g_osi_funcs_p */
extern u32 g_timer_info; /* g_timer_info */
extern u32 hostap_handle_timer_process(); /* hostap_handle_timer_process */
extern u32 ieee80211_ampdu_age_all(); /* ieee80211_ampdu_age_all */
extern u32 ieee80211_hostap_send_beacon_process(); /* ieee80211_hostap_send_beacon_process */
extern u32 mgd_probe_send_timeout_process(); /* mgd_probe_send_timeout_process */
extern u32 nan_dw_end_process(); /* nan_dw_end_process */
extern u32 nan_dw_start_process(); /* nan_dw_start_process */
extern u32 nan_faw_end_process(); /* nan_faw_end_process */
extern u32 nan_faw_start_process(); /* nan_faw_start_process */
extern u32 nan_ndc_start_process(); /* nan_ndc_start_process */
extern u32 nan_ndp_inactivity_timeout_process(); /* nan_ndp_inactivity_timeout_process */
extern u32 nan_ndp_setup_timeout_process(); /* nan_ndp_setup_timeout_process */
extern u32 nan_scan_timeout_process(); /* nan_scan_timeout_process */
extern u32 nan_send_action_process(); /* nan_send_action_process */
extern u32 nan_send_disc_bcn_process(); /* nan_send_disc_bcn_process */
extern u32 nan_send_sync_bcn_process(); /* nan_send_sync_bcn_process */
extern u32 nan_warmup_timeout_process(); /* nan_warmup_timeout_process */
extern u32 pp_post(); /* pp_post */
extern u32 scan_enter_oper_channel_process(); /* scan_enter_oper_channel_process */
extern u32 scan_inter_channel_timeout_process(); /* scan_inter_channel_timeout_process */
extern u32 send_wake_null_timeout_process(); /* send_wake_null_timeout_process */
extern u32 sta_retry_assoc(); /* sta_retry_assoc */
extern u32 sta_sa_query_process_timeout(); /* sta_sa_query_process_timeout */
extern u32 sta_try_sa_query_process(); /* sta_try_sa_query_process */
extern u32 wifi_api_lock(); /* wifi_api_lock */
extern u32 wifi_api_unlock(); /* wifi_api_unlock */
extern u32 wifi_get_init_state(); /* wifi_get_init_state */
extern u32 wifi_log(); /* wifi_log */

/* DISPATCH (verified offline):
 * g_timer_info is a byte-id table with 8-byte stride { u8 id; u8 pad[3]; u32 handler }.
 * ieee80211_timer_do_process(timer): id = *(u8*)arg; if id > 35 -> wifi_log warn;
 *   fast path addx8 direct-index check, else linear loop (movi 36, loop) comparing
 *   entry ids; on hit calls handler(entry_arg) then g_osi_funcs_p slot +176.
 *   Thin wrappers (ieee80211_nan_*, ieee80211_addba, ieee80211_assoc/auth/handshake/
 *   beacon/csa/probe_send/scan_*/hostap_handle/send_beacon/send_wake_null/sta_*,
 *   all 0x13B) forward *(u32*)(arg+4) to their *_process counterpart, return 1.
 * ieee80211_timer_process(a2=timer, a3=id?, ...): wifi_api_lock gate;
 *   init-state==3 required else wifi_log + return 0x3001; allocates via
 *   g_osi_funcs_p slot +0x16c, posts via pp_post, unlocks via wifi_api_unlock.
 */
/* ---- literal-rooted access patterns (offsets observed; layout NOT confirmed) ----
 * g_ic: u32+16, u32+16, u32+20, u32+20
 * g_osi_funcs_p: u32+0, u32+0, u32+176
 * g_timer_info: u8+0
/* ---- funcdb-v2 cross-check (calls[] vs section relocs; disasm is ground truth) ----
 * confirmed funcdb edges: 6; rejected funcdb-only (no exact reloc in
 * callee section; caller-side .rela.text.<f> prefix-collision artifacts): 0;
 * disasm-only edges kept (static-local callees + funcdb relsec:null gaps): 50;
 */
/* ==== functions of ieee80211_timer.o ==== */

/* ieee80211_timer_connect @ ieee80211_timer.o 0x00000000 size 7B bind LOCAL
 * Calls: none | Data refs: none
 * Fidelity: high - straight-line, fully mapped (3 insns) */
u32 ieee80211_timer_connect(void)
{
    /* frame: entry a1,32; 3 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* immediates: 1 */
    return 1;
}

/* ieee80211_nan_ndp_inactive_timeout @ ieee80211_timer.o 0x00000004 size 19B bind LOCAL
 * Calls: nan_ndp_inactivity_timeout_process | Data refs: none
 * Fidelity: high - straight-line, fully mapped (6 insns) */
u32 ieee80211_nan_ndp_inactive_timeout(u32 a2)
{
    /* frame: entry a1,32; 6 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* immediates: 1 */
    /* mem ld32: base=(?) off=4 */
    /* site +0xe: nan_ndp_inactivity_timeout_process(*(?+4)) */
    nan_ndp_inactivity_timeout_process(*(?+4));
    return 1;
}

/* ieee80211_nan_ndp_setup_timeout @ ieee80211_timer.o 0x00000004 size 19B bind LOCAL
 * Calls: nan_ndp_setup_timeout_process | Data refs: none
 * Fidelity: high - straight-line, fully mapped (6 insns) */
u32 ieee80211_nan_ndp_setup_timeout(u32 a2)
{
    /* frame: entry a1,32; 6 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* immediates: 1 */
    /* mem ld32: base=(?) off=4 */
    /* site +0xe: nan_ndp_setup_timeout_process(*(?+4)) */
    nan_ndp_setup_timeout_process(*(?+4));
    return 1;
}

/* ieee80211_nan_ndc_start @ ieee80211_timer.o 0x00000004 size 19B bind LOCAL
 * Calls: nan_ndc_start_process | Data refs: none
 * Fidelity: high - straight-line, fully mapped (6 insns) */
u32 ieee80211_nan_ndc_start(u32 a2)
{
    /* frame: entry a1,32; 6 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* immediates: 1 */
    /* mem ld32: base=(?) off=4 */
    /* site +0xe: nan_ndc_start_process(*(?+4)) */
    nan_ndc_start_process(*(?+4));
    return 1;
}

/* ieee80211_nan_faw_end @ ieee80211_timer.o 0x00000004 size 19B bind LOCAL
 * Calls: nan_faw_end_process | Data refs: none
 * Fidelity: high - straight-line, fully mapped (6 insns) */
u32 ieee80211_nan_faw_end(u32 a2)
{
    /* frame: entry a1,32; 6 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* immediates: 1 */
    /* mem ld32: base=(?) off=4 */
    /* site +0xe: nan_faw_end_process(*(?+4)) */
    nan_faw_end_process(*(?+4));
    return 1;
}

/* ieee80211_nan_faw_start @ ieee80211_timer.o 0x00000004 size 19B bind LOCAL
 * Calls: nan_faw_start_process | Data refs: none
 * Fidelity: high - straight-line, fully mapped (6 insns) */
u32 ieee80211_nan_faw_start(u32 a2)
{
    /* frame: entry a1,32; 6 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* immediates: 1 */
    /* mem ld32: base=(?) off=4 */
    /* site +0xe: nan_faw_start_process(*(?+4)) */
    nan_faw_start_process(*(?+4));
    return 1;
}

/* ieee80211_nan_send_action @ ieee80211_timer.o 0x00000004 size 19B bind LOCAL
 * Calls: nan_send_action_process | Data refs: none
 * Fidelity: high - straight-line, fully mapped (6 insns) */
u32 ieee80211_nan_send_action(u32 a2)
{
    /* frame: entry a1,32; 6 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* immediates: 1 */
    /* mem ld32: base=(?) off=4 */
    /* site +0xe: nan_send_action_process(*(?+4)) */
    nan_send_action_process(*(?+4));
    return 1;
}

/* ieee80211_nan_send_sync_bcn @ ieee80211_timer.o 0x00000004 size 19B bind LOCAL
 * Calls: nan_send_sync_bcn_process | Data refs: none
 * Fidelity: high - straight-line, fully mapped (6 insns) */
u32 ieee80211_nan_send_sync_bcn(u32 a2)
{
    /* frame: entry a1,32; 6 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* immediates: 1 */
    /* mem ld32: base=(?) off=4 */
    /* site +0xe: nan_send_sync_bcn_process(*(?+4)) */
    nan_send_sync_bcn_process(*(?+4));
    return 1;
}

/* ieee80211_nan_send_disc_bcn @ ieee80211_timer.o 0x00000004 size 19B bind LOCAL
 * Calls: nan_send_disc_bcn_process | Data refs: none
 * Fidelity: high - straight-line, fully mapped (6 insns) */
u32 ieee80211_nan_send_disc_bcn(u32 a2)
{
    /* frame: entry a1,32; 6 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* immediates: 1 */
    /* mem ld32: base=(?) off=4 */
    /* site +0xe: nan_send_disc_bcn_process(*(?+4)) */
    nan_send_disc_bcn_process(*(?+4));
    return 1;
}

/* ieee80211_nan_dw_end @ ieee80211_timer.o 0x00000004 size 19B bind LOCAL
 * Calls: nan_dw_end_process | Data refs: none
 * Fidelity: high - straight-line, fully mapped (6 insns) */
u32 ieee80211_nan_dw_end(u32 a2)
{
    /* frame: entry a1,32; 6 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* immediates: 1 */
    /* mem ld32: base=(?) off=4 */
    /* site +0xe: nan_dw_end_process(*(?+4)) */
    nan_dw_end_process(*(?+4));
    return 1;
}

/* ieee80211_nan_dw_start @ ieee80211_timer.o 0x00000004 size 19B bind LOCAL
 * Calls: nan_dw_start_process | Data refs: none
 * Fidelity: high - straight-line, fully mapped (6 insns) */
u32 ieee80211_nan_dw_start(u32 a2)
{
    /* frame: entry a1,32; 6 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* immediates: 1 */
    /* mem ld32: base=(?) off=4 */
    /* site +0xe: nan_dw_start_process(*(?+4)) */
    nan_dw_start_process(*(?+4));
    return 1;
}

/* ieee80211_nan_scan_timeout @ ieee80211_timer.o 0x00000004 size 19B bind LOCAL
 * Calls: nan_scan_timeout_process | Data refs: none
 * Fidelity: high - straight-line, fully mapped (6 insns) */
u32 ieee80211_nan_scan_timeout(u32 a2)
{
    /* frame: entry a1,32; 6 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* immediates: 1 */
    /* mem ld32: base=(?) off=4 */
    /* site +0xe: nan_scan_timeout_process(*(?+4)) */
    nan_scan_timeout_process(*(?+4));
    return 1;
}

/* ieee80211_nan_warmup_timeout @ ieee80211_timer.o 0x00000004 size 19B bind LOCAL
 * Calls: nan_warmup_timeout_process | Data refs: none
 * Fidelity: high - straight-line, fully mapped (6 insns) */
u32 ieee80211_nan_warmup_timeout(u32 a2)
{
    /* frame: entry a1,32; 6 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* immediates: 1 */
    /* mem ld32: base=(?) off=4 */
    /* site +0xe: nan_warmup_timeout_process(*(?+4)) */
    nan_warmup_timeout_process(*(?+4));
    return 1;
}

/* ieee80211_ampdu_age_handle @ ieee80211_timer.o 0x00000004 size 19B bind LOCAL
 * Calls: ieee80211_ampdu_age_all | Data refs: none
 * Fidelity: high - straight-line, fully mapped (6 insns) */
u32 ieee80211_ampdu_age_handle(u32 a2)
{
    /* frame: entry a1,32; 6 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* immediates: 1 */
    /* mem ld32: base=(?) off=4 */
    /* site +0xe: ieee80211_ampdu_age_all(*(?+4)) */
    ieee80211_ampdu_age_all(*(?+4));
    return 1;
}

/* ieee80211_addba @ ieee80211_timer.o 0x00000004 size 19B bind LOCAL
 * Calls: addba_timeout_process | Data refs: none
 * Fidelity: high - straight-line, fully mapped (6 insns) */
u32 ieee80211_addba(u32 a2)
{
    /* frame: entry a1,32; 6 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* immediates: 1 */
    /* mem ld32: base=(?) off=4 */
    /* site +0xe: addba_timeout_process(*(?+4)) */
    addba_timeout_process(*(?+4));
    return 1;
}

/* ieee80211_chm_dwell @ ieee80211_timer.o 0x00000004 size 19B bind LOCAL
 * Calls: chm_end_op_timeout_process | Data refs: none
 * Fidelity: high - straight-line, fully mapped (6 insns) */
u32 ieee80211_chm_dwell(u32 a2)
{
    /* frame: entry a1,32; 6 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* immediates: 1 */
    /* mem ld32: base=(?) off=4 */
    /* site +0xe: chm_end_op_timeout_process(*(?+4)) */
    chm_end_op_timeout_process(*(?+4));
    return 1;
}

/* ieee80211_csa @ ieee80211_timer.o 0x00000008 size 36B bind LOCAL
 * Calls: cnx_csa_fn_process | Data refs: g_ic
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 ieee80211_csa(void)
{
    /* frame: entry a1,32; 10 insns, 1 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0, 1 */
    /* first predicate: beq a8, a2, 22 <.text.ieee80211_csa+0x22> (condition opaque) */
    /* mem ld8: base=((lit:g_ic+65536)) off=235 */
    /* site +0x1d: cnx_csa_fn_process(/* no traced args */) */
    cnx_csa_fn_process(/* no traced args */);
    return 1;
}

/* ieee80211_ap_try_sa_query @ ieee80211_timer.o 0x00000014 size 68B bind GLOBAL
 * Calls: wifi_log, ap_try_sa_query_process | Data refs: g_ic, .rodata.__FUNCTION__$16, .rodata_wlog_info.16
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque (weak) */
u32 ieee80211_ap_try_sa_query(u32 a3)
{
    /* frame: entry a1,32; 19 insns, 1 cond-branches, 0 loops, 1 jumps */
    /* immediates: 1, 3 */
    /* first predicate: bnez.n a4, 38 <ieee80211_ap_try_sa_query+0x24> (condition opaque) */
    /* mem ld32: base=(lit:g_ic) off=20 */
    /* mem ld32: base=(*(g_ic+20)) off=4 */
    /* site +0x32: wifi_log(1, (1 slli 16), 3, lit:.rodata_wlog_info.16, lit:.rodata.__FUNCTION__$16) */
    wifi_log(1, (1 slli 16), 3, lit:.rodata_wlog_info.16, lit:.rodata.__FUNCTION__$16);
    /* site +0x3f: ap_try_sa_query_process(*(*(g_ic+20)+4), (1 slli 16), 3, lit:.rodata_wlog_info.16, lit:.rodata.__FUNCTION__$16) */
    ap_try_sa_query_process(*(*(g_ic+20)+4), (1 slli 16), 3, lit:.rodata_wlog_info.16, lit:.rodata.__FUNCTION__$16);
    return 1;
}

/* ieee80211_ap_sa_query_timeout @ ieee80211_timer.o 0x00000014 size 68B bind GLOBAL
 * Calls: wifi_log, ap_sa_query_timeout_process | Data refs: g_ic, .rodata.__FUNCTION__$15, .rodata_wlog_info.17
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque (weak) */
u32 ieee80211_ap_sa_query_timeout(u32 a3)
{
    /* frame: entry a1,32; 19 insns, 1 cond-branches, 0 loops, 1 jumps */
    /* immediates: 1, 3 */
    /* first predicate: bnez.n a4, 38 <ieee80211_ap_sa_query_timeout+0x24> (condition opaque) */
    /* mem ld32: base=(lit:g_ic) off=20 */
    /* mem ld32: base=(*(g_ic+20)) off=4 */
    /* site +0x32: wifi_log(1, (1 slli 16), 3, lit:.rodata_wlog_info.17, lit:.rodata.__FUNCTION__$15) */
    wifi_log(1, (1 slli 16), 3, lit:.rodata_wlog_info.17, lit:.rodata.__FUNCTION__$15);
    /* site +0x3f: ap_sa_query_timeout_process(*(*(g_ic+20)+4), (1 slli 16), 3, lit:.rodata_wlog_info.17, lit:.rodata.__FUNCTION__$15) */
    ap_sa_query_timeout_process(*(*(g_ic+20)+4), (1 slli 16), 3, lit:.rodata_wlog_info.17, lit:.rodata.__FUNCTION__$15);
    return 1;
}

/* ieee80211_sta_reset_rmac @ ieee80211_timer.o 0x00000014 size 64B bind LOCAL
 * Calls: wifi_log, esp_sta_reset_rmac_process | Data refs: g_ic, .rodata.__FUNCTION__$14, .rodata_wlog_info.20
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 ieee80211_sta_reset_rmac(u32 a2)
{
    /* frame: entry a1,32; 17 insns, 1 cond-branches, 0 loops, 1 jumps */
    /* immediates: 1, 3 */
    /* first predicate: bnez.n a3, 38 <.text.ieee80211_sta_reset_rmac+0x38> (condition opaque) */
    /* mem ld32: base=(lit:g_ic) off=16 */
    /* site +0x32: wifi_log(1, (1 slli 16), 3, lit:g_ic, lit:g_ic) */
    wifi_log(1, (1 slli 16), 3, lit:g_ic, lit:g_ic);
    /* site +0x3b: esp_sta_reset_rmac_process(ret@32, (1 slli 16), 3, lit:g_ic, lit:g_ic) */
    esp_sta_reset_rmac_process(ret@32, (1 slli 16), 3, lit:g_ic, lit:g_ic);
    return *(g_ic+16);
}

/* ieee80211_send_wake_null @ ieee80211_timer.o 0x00000014 size 64B bind LOCAL
 * Calls: wifi_log, send_wake_null_timeout_process | Data refs: g_ic, .rodata.__FUNCTION__$13, .rodata_wlog_info.19
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 ieee80211_send_wake_null(u32 a2)
{
    /* frame: entry a1,32; 17 insns, 1 cond-branches, 0 loops, 1 jumps */
    /* immediates: 1, 3 */
    /* first predicate: bnez.n a3, 38 <.text.ieee80211_send_wake_null+0x38> (condition opaque) */
    /* mem ld32: base=(lit:g_ic) off=16 */
    /* site +0x32: wifi_log(1, (1 slli 16), 3, lit:g_ic, lit:g_ic) */
    wifi_log(1, (1 slli 16), 3, lit:g_ic, lit:g_ic);
    /* site +0x3b: send_wake_null_timeout_process(ret@32, (1 slli 16), 3, lit:g_ic, lit:g_ic) */
    send_wake_null_timeout_process(ret@32, (1 slli 16), 3, lit:g_ic, lit:g_ic);
    return *(g_ic+16);
}

/* ieee80211_cnx_connect_next_ap @ ieee80211_timer.o 0x00000014 size 64B bind LOCAL
 * Calls: wifi_log, cnx_connect_next_ap_timeout_process | Data refs: g_ic, .rodata.__FUNCTION__$12, .rodata_wlog_info.18
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 ieee80211_cnx_connect_next_ap(u32 a2)
{
    /* frame: entry a1,32; 17 insns, 1 cond-branches, 0 loops, 1 jumps */
    /* immediates: 1, 3 */
    /* first predicate: bnez.n a3, 38 <.text.ieee80211_cnx_connect_next_ap+0x38> (condition opaque) */
    /* mem ld32: base=(lit:g_ic) off=16 */
    /* site +0x32: wifi_log(1, (1 slli 16), 3, lit:g_ic, lit:g_ic) */
    wifi_log(1, (1 slli 16), 3, lit:g_ic, lit:g_ic);
    /* site +0x3b: cnx_connect_next_ap_timeout_process(ret@32, (1 slli 16), 3, lit:g_ic, lit:g_ic) */
    cnx_connect_next_ap_timeout_process(ret@32, (1 slli 16), 3, lit:g_ic, lit:g_ic);
    return *(g_ic+16);
}

/* ieee80211_sta_retry_assoc @ ieee80211_timer.o 0x00000014 size 64B bind LOCAL
 * Calls: wifi_log, sta_retry_assoc | Data refs: g_ic, .rodata.__FUNCTION__$11, .rodata_wlog_info.15
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 ieee80211_sta_retry_assoc(u32 a2)
{
    /* frame: entry a1,32; 17 insns, 1 cond-branches, 0 loops, 1 jumps */
    /* immediates: 1, 3 */
    /* first predicate: bnez.n a3, 38 <.text.ieee80211_sta_retry_assoc+0x38> (condition opaque) */
    /* mem ld32: base=(lit:g_ic) off=16 */
    /* site +0x32: wifi_log(1, (1 slli 16), 3, lit:g_ic, lit:g_ic) */
    wifi_log(1, (1 slli 16), 3, lit:g_ic, lit:g_ic);
    /* site +0x3b: sta_retry_assoc(ret@32, (1 slli 16), 3, lit:g_ic, lit:g_ic) */
    sta_retry_assoc(ret@32, (1 slli 16), 3, lit:g_ic, lit:g_ic);
    return *(g_ic+16);
}

/* ieee80211_sta_sa_query_timeout @ ieee80211_timer.o 0x00000014 size 64B bind LOCAL
 * Calls: wifi_log, sta_sa_query_process_timeout | Data refs: g_ic, .rodata.__FUNCTION__$10, .rodata_wlog_info.14
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 ieee80211_sta_sa_query_timeout(u32 a2)
{
    /* frame: entry a1,32; 17 insns, 1 cond-branches, 0 loops, 1 jumps */
    /* immediates: 1, 3 */
    /* first predicate: bnez.n a3, 38 <.text.ieee80211_sta_sa_query_timeout+0x38> (condition opaque) */
    /* mem ld32: base=(lit:g_ic) off=16 */
    /* site +0x32: wifi_log(1, (1 slli 16), 3, lit:g_ic, lit:g_ic) */
    wifi_log(1, (1 slli 16), 3, lit:g_ic, lit:g_ic);
    /* site +0x3b: sta_sa_query_process_timeout(ret@32, (1 slli 16), 3, lit:g_ic, lit:g_ic) */
    sta_sa_query_process_timeout(ret@32, (1 slli 16), 3, lit:g_ic, lit:g_ic);
    return *(g_ic+16);
}

/* ieee80211_sta_try_sa_query @ ieee80211_timer.o 0x00000014 size 64B bind LOCAL
 * Calls: wifi_log, sta_try_sa_query_process | Data refs: g_ic, .rodata.__FUNCTION__$9, .rodata_wlog_info.13
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 ieee80211_sta_try_sa_query(u32 a2)
{
    /* frame: entry a1,32; 17 insns, 1 cond-branches, 0 loops, 1 jumps */
    /* immediates: 1, 3 */
    /* first predicate: bnez.n a3, 38 <.text.ieee80211_sta_try_sa_query+0x38> (condition opaque) */
    /* mem ld32: base=(lit:g_ic) off=16 */
    /* site +0x32: wifi_log(1, (1 slli 16), 3, lit:g_ic, lit:g_ic) */
    wifi_log(1, (1 slli 16), 3, lit:g_ic, lit:g_ic);
    /* site +0x3b: sta_try_sa_query_process(ret@32, (1 slli 16), 3, lit:g_ic, lit:g_ic) */
    sta_try_sa_query_process(ret@32, (1 slli 16), 3, lit:g_ic, lit:g_ic);
    return *(g_ic+16);
}

/* ieee80211_assoc @ ieee80211_timer.o 0x00000014 size 64B bind LOCAL
 * Calls: wifi_log, cnx_assoc_timeout_process | Data refs: g_ic, .rodata.__FUNCTION__$8, .rodata_wlog_info.11
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 ieee80211_assoc(u32 a2)
{
    /* frame: entry a1,32; 17 insns, 1 cond-branches, 0 loops, 1 jumps */
    /* immediates: 1, 3 */
    /* first predicate: bnez.n a3, 38 <.text.ieee80211_assoc+0x38> (condition opaque) */
    /* mem ld32: base=(lit:g_ic) off=16 */
    /* site +0x32: wifi_log(1, (1 slli 16), 3, lit:g_ic, lit:g_ic) */
    wifi_log(1, (1 slli 16), 3, lit:g_ic, lit:g_ic);
    /* site +0x3b: cnx_assoc_timeout_process(ret@32, (1 slli 16), 3, lit:g_ic, lit:g_ic) */
    cnx_assoc_timeout_process(ret@32, (1 slli 16), 3, lit:g_ic, lit:g_ic);
    return *(g_ic+16);
}

/* ieee80211_auth @ ieee80211_timer.o 0x00000014 size 64B bind LOCAL
 * Calls: wifi_log, cnx_auth_timeout_process | Data refs: g_ic, .rodata.__FUNCTION__$7, .rodata_wlog_info.10
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 ieee80211_auth(u32 a2)
{
    /* frame: entry a1,32; 17 insns, 1 cond-branches, 0 loops, 1 jumps */
    /* immediates: 1, 3 */
    /* first predicate: bnez.n a3, 38 <.text.ieee80211_auth+0x38> (condition opaque) */
    /* mem ld32: base=(lit:g_ic) off=16 */
    /* site +0x32: wifi_log(1, (1 slli 16), 3, lit:g_ic, lit:g_ic) */
    wifi_log(1, (1 slli 16), 3, lit:g_ic, lit:g_ic);
    /* site +0x3b: cnx_auth_timeout_process(ret@32, (1 slli 16), 3, lit:g_ic, lit:g_ic) */
    cnx_auth_timeout_process(ret@32, (1 slli 16), 3, lit:g_ic, lit:g_ic);
    return *(g_ic+16);
}

/* ieee80211_handshake @ ieee80211_timer.o 0x00000014 size 64B bind LOCAL
 * Calls: wifi_log, cnx_handshake_timeout_process | Data refs: g_ic, .rodata.__FUNCTION__$6, .rodata_wlog_info.8
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 ieee80211_handshake(u32 a2)
{
    /* frame: entry a1,32; 17 insns, 1 cond-branches, 0 loops, 1 jumps */
    /* immediates: 1, 3 */
    /* first predicate: bnez.n a3, 38 <.text.ieee80211_handshake+0x38> (condition opaque) */
    /* mem ld32: base=(lit:g_ic) off=16 */
    /* site +0x32: wifi_log(1, (1 slli 16), 3, lit:g_ic, lit:g_ic) */
    wifi_log(1, (1 slli 16), 3, lit:g_ic, lit:g_ic);
    /* site +0x3b: cnx_handshake_timeout_process(ret@32, (1 slli 16), 3, lit:g_ic, lit:g_ic) */
    cnx_handshake_timeout_process(ret@32, (1 slli 16), 3, lit:g_ic, lit:g_ic);
    return *(g_ic+16);
}

/* ieee80211_beacon @ ieee80211_timer.o 0x00000018 size 80B bind LOCAL
 * Calls: wifi_log, cnx_beacon_timeout_process | Data refs: g_ic, .rodata.__FUNCTION__$5, .rodata_wlog_info.6, .rodata_wlog_info.7
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 ieee80211_beacon(u32 a2)
{
    /* frame: entry a1,32; 21 insns, 2 cond-branches, 0 loops, 1 jumps */
    /* immediates: 1, 3 */
    /* first predicate: beqz.n a3, 35 <.text.ieee80211_beacon+0x35> (condition opaque) */
    /* mem ld32: base=(lit:g_ic) off=16 */
    /* mem ld32: base=(*(g_ic+16)) off=228 */
    /* site +0x3f: wifi_log(1, (1 slli 16), 3, lit:g_ic, lit:g_ic) */
    wifi_log(1, (1 slli 16), 3, lit:g_ic, lit:g_ic);
    /* site +0x4b: cnx_beacon_timeout_process(ret@3f, (1 slli 16), 3, lit:g_ic, lit:g_ic) */
    cnx_beacon_timeout_process(ret@3f, (1 slli 16), 3, lit:g_ic, lit:g_ic);
    return *(*(g_ic+16)+228);
}

/* ieee80211_probe_send @ ieee80211_timer.o 0x00000018 size 80B bind LOCAL
 * Calls: wifi_log, mgd_probe_send_timeout_process | Data refs: g_ic, .rodata.__FUNCTION__$4, .rodata_wlog_info.4, .rodata_wlog_info.5
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 ieee80211_probe_send(u32 a2)
{
    /* frame: entry a1,32; 21 insns, 2 cond-branches, 0 loops, 1 jumps */
    /* immediates: 1, 3 */
    /* first predicate: beqz.n a3, 35 <.text.ieee80211_probe_send+0x35> (condition opaque) */
    /* mem ld32: base=(lit:g_ic) off=16 */
    /* mem ld32: base=(*(g_ic+16)) off=228 */
    /* site +0x3f: wifi_log(1, (1 slli 16), 3, lit:g_ic, lit:g_ic) */
    wifi_log(1, (1 slli 16), 3, lit:g_ic, lit:g_ic);
    /* site +0x4b: mgd_probe_send_timeout_process(ret@3f, (1 slli 16), 3, lit:g_ic, lit:g_ic) */
    mgd_probe_send_timeout_process(ret@3f, (1 slli 16), 3, lit:g_ic, lit:g_ic);
    return *(*(g_ic+16)+228);
}

/* ieee80211_scan_enter_op_chan @ ieee80211_timer.o 0x00000014 size 68B bind LOCAL
 * Calls: wifi_log, scan_enter_oper_channel_process | Data refs: g_ic, .rodata.__FUNCTION__$3, .rodata_wlog_info.3
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 ieee80211_scan_enter_op_chan(u32 a3)
{
    /* frame: entry a1,32; 19 insns, 1 cond-branches, 0 loops, 1 jumps */
    /* immediates: 1, 3 */
    /* first predicate: bnez.n a4, 38 <.text.ieee80211_scan_enter_op_chan+0x38> (condition opaque) */
    /* mem ld32: base=(lit:g_ic) off=16 */
    /* mem ld32: base=(*(g_ic+16)) off=4 */
    /* site +0x32: wifi_log(1, (1 slli 16), 3, lit:g_ic, lit:g_ic) */
    wifi_log(1, (1 slli 16), 3, lit:g_ic, lit:g_ic);
    /* site +0x3f: scan_enter_oper_channel_process(*(*(g_ic+16)+4), (1 slli 16), 3, lit:g_ic, lit:g_ic) */
    scan_enter_oper_channel_process(*(*(g_ic+16)+4), (1 slli 16), 3, lit:g_ic, lit:g_ic);
    return 1;
}

/* ieee80211_scan_inter_chan @ ieee80211_timer.o 0x00000014 size 68B bind LOCAL
 * Calls: wifi_log, scan_inter_channel_timeout_process | Data refs: g_ic, .rodata.__FUNCTION__$2, .rodata_wlog_info.2
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 ieee80211_scan_inter_chan(u32 a3)
{
    /* frame: entry a1,32; 19 insns, 1 cond-branches, 0 loops, 1 jumps */
    /* immediates: 1, 3 */
    /* first predicate: bnez.n a4, 38 <.text.ieee80211_scan_inter_chan+0x38> (condition opaque) */
    /* mem ld32: base=(lit:g_ic) off=16 */
    /* mem ld32: base=(*(g_ic+16)) off=4 */
    /* site +0x32: wifi_log(1, (1 slli 16), 3, lit:g_ic, lit:g_ic) */
    wifi_log(1, (1 slli 16), 3, lit:g_ic, lit:g_ic);
    /* site +0x3f: scan_inter_channel_timeout_process(*(*(g_ic+16)+4), (1 slli 16), 3, lit:g_ic, lit:g_ic) */
    scan_inter_channel_timeout_process(*(*(g_ic+16)+4), (1 slli 16), 3, lit:g_ic, lit:g_ic);
    return 1;
}

/* ieee80211_hostap_handle @ ieee80211_timer.o 0x00000014 size 68B bind LOCAL
 * Calls: wifi_log, hostap_handle_timer_process | Data refs: g_ic, .rodata.__FUNCTION__$1, .rodata_wlog_info.12
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 ieee80211_hostap_handle(u32 a3)
{
    /* frame: entry a1,32; 19 insns, 1 cond-branches, 0 loops, 1 jumps */
    /* immediates: 1, 3 */
    /* first predicate: bnez.n a4, 38 <.text.ieee80211_hostap_handle+0x38> (condition opaque) */
    /* mem ld32: base=(lit:g_ic) off=20 */
    /* mem ld32: base=(*(g_ic+20)) off=4 */
    /* site +0x32: wifi_log(1, (1 slli 16), 3, lit:g_ic, lit:g_ic) */
    wifi_log(1, (1 slli 16), 3, lit:g_ic, lit:g_ic);
    /* site +0x3f: hostap_handle_timer_process(*(*(g_ic+20)+4), (1 slli 16), 3, lit:g_ic, lit:g_ic) */
    hostap_handle_timer_process(*(*(g_ic+20)+4), (1 slli 16), 3, lit:g_ic, lit:g_ic);
    return 1;
}

/* ieee80211_send_beacon @ ieee80211_timer.o 0x00000014 size 66B bind LOCAL
 * Calls: wifi_log, ieee80211_hostap_send_beacon_process | Data refs: g_ic, .rodata.__FUNCTION__$0, .rodata_wlog_info.9
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 ieee80211_send_beacon(u32 a2)
{
    /* frame: entry a1,32; 18 insns, 1 cond-branches, 0 loops, 1 jumps */
    /* immediates: 1, 3, 0 */
    /* first predicate: bnez.n a3, 38 <.text.ieee80211_send_beacon+0x38> (condition opaque) */
    /* mem ld32: base=(lit:g_ic) off=20 */
    /* site +0x32: wifi_log(1, (1 slli 16), 3, lit:g_ic, lit:g_ic) */
    wifi_log(1, (1 slli 16), 3, lit:g_ic, lit:g_ic);
    /* site +0x3d: ieee80211_hostap_send_beacon_process(0, (1 slli 16), 3, lit:g_ic, lit:g_ic) */
    ieee80211_hostap_send_beacon_process(0, (1 slli 16), 3, lit:g_ic, lit:g_ic);
    return *(g_ic+20);
}

/* ieee80211_register_hostap_timer @ ieee80211_timer.o 0x0000000c size 48B bind GLOBAL
 * Calls: none | Data refs: g_timer_info, .text.ieee80211_send_beacon, .text.ieee80211_hostap_handle
 * Fidelity: low - 17 insns, 3 branches, 1 loops; skeleton only */
u32 ieee80211_register_hostap_timer(void)
{
    /* frame: entry a1,32; 17 insns, 3 cond-branches, 1 loops, 1 jumps */
    /* immediates: 9, 36 */
    /* first predicate: loop a9, 37 <ieee80211_register_hostap_timer+0x2b> (condition opaque) */
    /* mem ld8: base=(lit:g_timer_info) off=0 */
    /* mem st32: base=(lit:g_timer_info) off=4 */
    /* mem st32: base=(lit:g_timer_info) off=4 */
    return opaque_result; /* full dataflow not recovered */
}

/* ieee80211_timer_do_process @ ieee80211_timer.o 0x00000018 size 142B bind GLOBAL
 * Calls: wifi_log, indirect(a8), indirect(a8), wifi_log, indirect(a8) | Data refs: .rodata_wlog_warning.21, g_timer_info, g_osi_funcs_p, .rodata_wlog_warning.22
 * Fidelity: low - 54 insns, 6 branches, 1 loops; skeleton only */
u32 ieee80211_timer_do_process(u32 a2, u32 a4)
{
    /* frame: entry a1,32; 54 insns, 6 cond-branches, 1 loops, 4 jumps */
    /* immediates: 1, 2, 35, 0, 36 */
    /* first predicate: bnez.n a2, 34 <ieee80211_timer_do_process+0x1c> (condition opaque) */
    /* mem ld8: base=(?) off=0 */
    /* mem ld8: base=(35) off=0 */
    /* mem ld8: base=(lit:g_timer_info) off=0 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=176 */
    /* mem ld32: base=(*(g_osi_funcs_p+176)) off=4 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=176 */
    /* site +0x2d: wifi_log(1, (1 slli 16), 2, lit:.rodata_wlog_warning.21) */
    wifi_log(1, (1 slli 16), 2, lit:.rodata_wlog_warning.21);
    /* site +0x63: indirect call via a8 (base (0+1)); args: ?, 36, (lit:g_timer_info+8), *(lit:g_timer_info+0) */
    opaque_indirect_a8();
    /* site +0x72: indirect call via a8 (base *(g_osi_funcs_p+176)); args: ?, 36, (lit:g_timer_info+8), *(lit:g_timer_info+0) */
    opaque_indirect_a8();
    /* site +0x92: wifi_log(1, (1 slli 16), 2, lit:.rodata_wlog_warning.22) */
    wifi_log(1, (1 slli 16), 2, lit:.rodata_wlog_warning.22);
    /* site +0xa1: indirect call via a8 (base *(g_osi_funcs_p+176)); args: 1, (1 slli 16), 2, lit:.rodata_wlog_warning.22 */
    opaque_indirect_a8();
    return 0;
}

/* ieee80211_timer_process @ ieee80211_timer.o 0x00000040 size 185B bind GLOBAL
 * Calls: wifi_api_lock, wifi_log, wifi_get_init_state, wifi_api_unlock, wifi_log, indirect(a5), pp_post, wifi_api_unlock, indirect(a2), wifi_api_unlock, wifi_api_unlock, wifi_log | Data refs: .rodata_wlog_error.23, .rodata_wlog_error.24, g_osi_funcs_p, .rodata_wlog_error.25, .rodata_wlog_error.26
 * Fidelity: low - 68 insns, 4 branches, 0 loops; skeleton only */
u32 ieee80211_timer_process(u32 a2, u32 a3, u32 a4, u32 a7)
{
    /* frame: entry a1,32; 68 insns, 4 cond-branches, 0 loops, 4 jumps */
    /* immediates: 1, 8, 6, -1 */
    /* first predicate: beqz.n a10, 69 <ieee80211_timer_process+0x29> (condition opaque) */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=0x16c */
    /* mem st8: base=(ret@9e) off=0 */
    /* mem st32: base=(ret@9e) off=4 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=176 */
    /* site +0x46: wifi_api_lock(/* no traced args */) */
    wifi_api_lock(/* no traced args */);
    /* site +0x61: wifi_log(1, (1 slli 16), 1, lit:.rodata_wlog_error.23) */
    wifi_log(1, (1 slli 16), 1, lit:.rodata_wlog_error.23);
    /* site +0x6c: wifi_get_init_state(ret@61, (1 slli 16), 1, lit:.rodata_wlog_error.23) */
    wifi_get_init_state(ret@61, (1 slli 16), 1, lit:.rodata_wlog_error.23);
    /* site +0x75: wifi_api_unlock(ret@6c, (1 slli 16), 1, lit:.rodata_wlog_error.23) */
    wifi_api_unlock(ret@6c, (1 slli 16), 1, lit:.rodata_wlog_error.23);
    /* site +0x89: wifi_log(ret@75, (1 slli 16), 1, lit:.rodata_wlog_error.24) */
    wifi_log(ret@75, (1 slli 16), 1, lit:.rodata_wlog_error.24);
    /* site +0x9e: indirect call via a5 (base *(*(g_osi_funcs_p+0)+0x16c)); args: 8, (1 slli 16), 1, lit:.rodata_wlog_error.24 */
    opaque_indirect_a5();
    /* site +0xb7: pp_post(?, ret@9e, 1, lit:.rodata_wlog_error.24) */
    pp_post(?, ret@9e, 1, lit:.rodata_wlog_error.24);
    /* site +0xbf: wifi_api_unlock(ret@b7, ret@9e, 1, lit:.rodata_wlog_error.24) */
    wifi_api_unlock(ret@b7, ret@9e, 1, lit:.rodata_wlog_error.24);
    /* site +0xc9: indirect call via a2 (base *(*(g_osi_funcs_p+0)+176)); args: ret@9e, ret@9e, 1, lit:.rodata_wlog_error.24 */
    opaque_indirect_a2();
    /* site +0xd7: wifi_api_unlock(ret@c9, ret@9e, 1, lit:.rodata_wlog_error.25) */
    wifi_api_unlock(ret@c9, ret@9e, 1, lit:.rodata_wlog_error.25);
    /* site +0xe0: wifi_api_unlock(ret@d7, ret@9e, 1, lit:.rodata_wlog_error.25) */
    wifi_api_unlock(ret@d7, ret@9e, 1, lit:.rodata_wlog_error.25);
    /* site +0xf2: wifi_log(6, (1 slli 16), 1, lit:.rodata_wlog_error.26) */
    wifi_log(6, (1 slli 16), 1, lit:.rodata_wlog_error.26);
    return -1;
}
