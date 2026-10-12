/* ieee80211_nan_disc.c - reconstructed from ieee80211_nan_disc.o (55120 bytes on disk).
 * Toolchain: xtensa-esp32-elf (esp-15.2.0), ABI args a2..a7, return a2.
 * Prototypes are generic (arity unknown); bodies preserve the observed
 * call order, branch/loop skeleton, and notable immediates from disasm.
 * Data refs appear in headers only; they are NOT typed (layouts unknown).
 * funcdb v2 edges merged: Calls/Data refs start from funcdb
 * calls[]/refs[] (R_XTENSA_ASM_EXPAND/R_XTENSA_32 rela-matched),
 * plus section-local calls (.text.X+off) from disasm relocs that
 * funcdb v2 omits; call-site order is from disasm. Tags: [v2-only]
 * = in funcdb v2 but no call site found in section disasm (appended);
 * [local] = section-local target funcdb v2 omits.
 */
#include <stdint.h>
#include <stddef.h>
#include <string.h>

extern int __umoddi3();  /* external, prototype unknown */
extern int chm_is_at_home_channel();  /* external, prototype unknown */
extern int chm_return_home_channel();  /* external, prototype unknown */
extern int hal_now();  /* external, prototype unknown */
extern int ic_ebuf_recycle_rx();  /* external, prototype unknown */
extern int ic_ebuf_recycle_tx();  /* external, prototype unknown */
extern int ieee80211_timer_process();  /* external, prototype unknown */
extern int nan_action_frames_queued();  /* external, prototype unknown */
extern int nan_alloc_beacon();  /* external, prototype unknown */
extern int nan_disc_enable_rx();  /* external, prototype unknown */
extern int nan_dp_has_active_datapath();  /* external, prototype unknown */
extern int nan_dp_indicate_faw_start();  /* external, prototype unknown */
extern int nan_dp_indicate_ndc_start();  /* external, prototype unknown */
extern int nan_dp_schedule_ndc_start();  /* external, prototype unknown */
extern int nan_dp_schedule_next_faw();  /* external, prototype unknown */
extern int nan_fill_country_code_attr();  /* external, prototype unknown */
extern int nan_get_random_byte();  /* external, prototype unknown */
extern int nan_get_random_word();  /* external, prototype unknown */
extern int nan_get_tsf();  /* external, prototype unknown */
extern int nan_is_in_dw();  /* external, prototype unknown */
extern int nan_post_event();  /* external, prototype unknown */
extern int nan_send_static_sdfs();  /* external, prototype unknown */
extern int nan_static_sdfs_present();  /* external, prototype unknown */
extern int nan_transmit_bcn();  /* external, prototype unknown */
extern int nan_tx_queued_action_frames();  /* external, prototype unknown */
extern int nan_update_static_sdfs();  /* external, prototype unknown */
extern int nan_update_tsf();  /* external, prototype unknown */
extern int wifi_log();  /* external, prototype unknown */
extern int wifi_set_rx_policy();  /* external, prototype unknown */

int nan_in_transit_event_hdlr(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
static int nan_schedule_next_dwstart(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
static int nan_update_tsf_from_bcn(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
static int nan_compare_mr(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
static int nan_update_amr_for_non_anchor(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
static int nan_adjust_non_anchor_tsf(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
static int nan_common_dwstart_ops(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
static int nan_recycle_rx_bcn(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
static int nan_stop_handler(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
static int nan_common_dwend_ops(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
static int nan_update_bcn_stats(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
static int nan_init_event_hdlr(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
static int nan_ndc_start_timeout(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
static int nan_faw_end_timeout(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
static int nan_faw_start_timeout(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
static int nan_action_timeout(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
static int nan_disc_bcn_timeout(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
static int nan_sync_bcn_timeout(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
static int nan_dwend_timeout(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
static int nan_warmup_timeout(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
static int nan_scan_timeout(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
static int nan_dwstart_timeout(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
static int nan_is_ambtt_too_old_isra_0(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_nmns_event_hdlr(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_nms_event_hdlr(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_send_started_event(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_schedule_disc_bcn(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_master_event_hdlr(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_fill_dynamic_attr(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
static int nan_construct_beacon(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_scan_event_hdlr(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_am_event_hdlr(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_sm_handle_event_internal(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_sm_handle_event(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_warmup_timeout_process(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_scan_timeout_process(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_dw_start_process(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_dw_end_process(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_send_disc_bcn_process(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_send_sync_bcn_process(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_send_action_process(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_faw_start_process(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_faw_end_process(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_ndc_start_process(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_sm_init(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_sm_deinit(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_sm_start(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_sm_stop(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);

/* nan_in_transit_event_hdlr @ ieee80211_nan_disc.o 00000000 size 7B bind GLOBAL
 * Calls: none | Data refs: none
 * Fidelity: high - trivial: straight-line, all targets resolved */
int nan_in_transit_event_hdlr(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2 */
    /* immediates: 6 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_schedule_next_dwstart @ ieee80211_nan_disc.o 00000000 size 70B bind LOCAL (no symbol; sec .text.nan_schedule_next_dwstart)
 * Calls: nan_get_tsf | Data refs: g_osi_funcs_p
 * Fidelity: medium - small frame, 1 call + 1 branch(es) mapped */
static int nan_schedule_next_dwstart(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: none observed */
    /* struct offsets touched: 248 */
    /* immediates: 1, 255, 0, 48 */
    /* branches: +0x28 bgeu->0x34 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    nan_get_tsf(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_update_tsf_from_bcn @ ieee80211_nan_disc.o 00000000 size 188B bind LOCAL (no symbol; sec .text.nan_update_tsf_from_bcn)
 * Calls: hal_now, nan_get_tsf, nan_update_tsf | Data refs: none
 * Fidelity: medium - small frame, 3 calls + 8 branch(es) mapped */
static int nan_update_tsf_from_bcn(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2, a3 */
    /* struct offsets touched: 24, 25, 26, 27, 28, 29, 30, 31, 44 */
    /* immediates: -1, 1, 0, 5 */
    /* branches: +0x5e bgeu->0x66; +0x61 j->0x68; +0x6c bltu->0x71; +0x7f bltu->0x84; +0x98 bltu->0x9D; +0xa3 bgei->0xBA; +0xa6 bnez.n->0xB0; +0xad bltu->0xBA */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    hal_now(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_get_tsf(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_update_tsf(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_compare_mr @ ieee80211_nan_disc.o 00000000 size 162B bind LOCAL (no symbol; sec .text.nan_compare_mr)
 * Calls: memcmp | Data refs: none
 * Fidelity: medium - small frame, 1 call + 0 branch(es) mapped */
static int nan_compare_mr(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,48; early arg regs: a2 */
    /* struct offsets touched: 8, 12 */
    /* immediates: 255, 8 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    memcmp(0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_update_amr_for_non_anchor @ ieee80211_nan_disc.o 00000000 size 653B bind LOCAL (no symbol; sec .text.nan_update_amr_for_non_anchor)
 * Calls: memcpy, nan_compare_mr[+0x4][local], memcmp | Data refs: none
 * Fidelity: low - large/complex: 13 branches, 0 loop(s), 3 calls; skeleton only */
static int nan_update_amr_for_non_anchor(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,48; early arg regs: a2, a3, a6, a7 */
    /* struct offsets touched: 24, 25, 26, 27, 58, 59, 60, 61, 62, 89, 280, 284, 294, 296 */
    /* immediates: 0x110, 50, 1, 8, 0x119, 0x11d, 0x126, 0x108, 6 */
    /* branches: +0x38 bnez->0x8D; +0x8a j->0x288; +0x9e bgez->0x16D; +0xb7 bnez.n->0xE9; +0xe3 bgeu->0xE9; +0xe6 j->0x288; +0x168 j->0x27D; +0x170 beqz->0x225; +0x18b bnez->0x27D; +0x1d9 bgei->0x1E4 (+3 more) */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    memcpy(0, 0, 0);  /* ordered call */
    nan_compare_mr(0, 0, 0, 0, 0, 0);  /* ordered call[+0x4] [local] */
    memcmp(0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_adjust_non_anchor_tsf @ ieee80211_nan_disc.o 00000000 size 200B bind LOCAL (no symbol; sec .text.nan_adjust_non_anchor_tsf)
 * Calls: nan_compare_mr[+0x4][local], memcmp, nan_update_tsf_from_bcn[+0xc][local] | Data refs: none
 * Fidelity: low - large/complex: 10 branches, 0 loop(s), 3 calls; skeleton only */
static int nan_adjust_non_anchor_tsf(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2, a3, a4 */
    /* struct offsets touched: 24, 25, 26, 27, 58, 59, 60, 61, 62, 294, 296 */
    /* immediates: 0x110, 50, 0x11d, 0x108, 6 */
    /* branches: +0x3b bnez.n->0x60; +0x40 bnez.n->0x60; +0x74 blti->0x89; +0x84 bnez.n->0xBE; +0x86 j->0xAF; +0x89 beqz.n->0xAF; +0x9b blti->0xC6; +0xaa bnez.n->0xBE; +0xac j->0xC6; +0xbb bgeu->0xC6 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    nan_compare_mr(0, 0, 0, 0, 0, 0);  /* ordered call[+0x4] [local] */
    memcmp(0, 0, 0);  /* ordered call */
    nan_update_tsf_from_bcn(0, 0, 0, 0, 0, 0);  /* ordered call[+0xc] [local] */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_common_dwstart_ops @ ieee80211_nan_disc.o 00000000 size 42B bind LOCAL (no symbol; sec .text.nan_common_dwstart_ops)
 * Calls: memset, nan_update_static_sdfs | Data refs: none
 * Fidelity: medium - small frame, 2 calls + 1 branch(es) mapped */
static int nan_common_dwstart_ops(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2 */
    /* struct offsets touched: 88 */
    /* immediates: 0x12a, 6, 0 */
    /* branches: +0x20 beqz.n->0x28 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    memset(0, 0, 0);  /* ordered call */
    nan_update_static_sdfs(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_recycle_rx_bcn @ ieee80211_nan_disc.o 00000000 size 26B bind LOCAL (no symbol; sec .text.nan_recycle_rx_bcn)
 * Calls: ic_ebuf_recycle_rx | Data refs: none
 * Fidelity: high - trivial: straight-line, all targets resolved */
static int nan_recycle_rx_bcn(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2 */
    /* immediates: 0 */
    /* branches: +0x9 beqz.n->0x15 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    ic_ebuf_recycle_rx(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_stop_handler @ ieee80211_nan_disc.o 00000000 size 399B bind LOCAL (no symbol; sec .text.nan_stop_handler)
 * Calls: nan_recycle_rx_bcn[+0x4][local], ic_ebuf_recycle_tx | Data refs: g_osi_funcs_p
 * Fidelity: low - large/complex: 4 branches, 0 loop(s), 2 calls; skeleton only */
static int nan_stop_handler(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,64; early arg regs: a2, a3, a4, a5, a6, a7 */
    /* struct offsets touched: 8, 12, 16, 20, 44, 236, 240, 312, 316 */
    /* immediates: 8, 128, 148, 168, 28, 88, 48, 68, 108, 188, 0 */
    /* branches: +0x14b bbci->0x15C; +0x159 j->0x162; +0x169 bbci->0x17C; +0x177 j->0x182 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    nan_recycle_rx_bcn(0, 0, 0, 0, 0, 0);  /* ordered call[+0x4] [local] */
    ic_ebuf_recycle_tx(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_common_dwend_ops @ ieee80211_nan_disc.o 00000000 size 488B bind LOCAL (no symbol; sec .text.nan_common_dwend_ops)
 * Calls: memcmp, nan_compare_mr[+0x4][local], nan_get_tsf, nan_dp_schedule_next_faw, nan_dp_schedule_ndc_start, nan_dp_has_active_datapath, nan_get_random_byte | Data refs: g_osi_funcs_p
 * Fidelity: low - large/complex: 30 branches, 10 loop(s), 7 calls; skeleton only */
static int nan_common_dwend_ops(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2, a3, a4, a5, a6 */
    /* struct offsets touched: 24, 42, 43, 44, 45, 46, 47, 75, 90, 108, 248, 280, 284, 352 */
    /* immediates: 0x108, 0x110, 6, 2, 3, 5, 4, 168, 148, 188, 1, 8 */
    /* branches: +0x40 bnei->0x72; +0x50 bnez.n->0x5A; +0x54 j->0x114; +0x64 bgez->0x52 [loop]; +0x6a bnez->0xF4; +0x6d j->0xAB; +0x7c bgez->0x52 [loop]; +0x9f bltu->0x52 [loop]; +0xa5 bnei->0xB6; +0xa8 j->0x67 [loop] (+20 more) */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    memcmp(0, 0, 0);  /* ordered call */
    nan_compare_mr(0, 0, 0, 0, 0, 0);  /* ordered call[+0x4] [local] */
    nan_get_tsf(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_dp_schedule_next_faw(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_dp_schedule_ndc_start(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_dp_has_active_datapath(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_get_random_byte(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_update_bcn_stats @ ieee80211_nan_disc.o 00000000 size 238B bind LOCAL (no symbol; sec .text.nan_update_bcn_stats)
 * Calls: nan_is_in_dw, memcpy, nan_compare_mr[+0x4][local] | Data refs: none
 * Fidelity: low - large/complex: 13 branches, 0 loop(s), 3 calls; skeleton only */
static int nan_update_bcn_stats(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,48; early arg regs: a2, a3, a4 */
    /* struct offsets touched: 16, 24, 42, 43, 44, 45, 46, 58 */
    /* immediates: 6, 10, 0x108, 0x110, 50, -59, 1, -74 */
    /* branches: +0x19 beqz->0xE9; +0x72 blti->0x9D; +0x78 blt->0x8C; +0x89 j->0x92; +0x8f blt->0x9D; +0x9d bnez->0xE9; +0xa3 bgez->0xAC; +0xa9 j->0xBF; +0xb4 beqz.n->0xE9; +0xbc bgez->0xE9 (+3 more) */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    nan_is_in_dw(0, 0, 0, 0, 0, 0);  /* ordered call */
    memcpy(0, 0, 0);  /* ordered call */
    nan_compare_mr(0, 0, 0, 0, 0, 0);  /* ordered call[+0x4] [local] */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_init_event_hdlr @ ieee80211_nan_disc.o 00000000 size 356B bind LOCAL (no symbol; sec .text.nan_init_event_hdlr)
 * Calls: memcpy, memset, nan_recycle_rx_bcn[+0x4][local] | Data refs: g_ic, .text.nan_scan_timeout, g_osi_funcs_p, .text.nan_warmup_timeout, .text.nan_dwstart_timeout, .text.nan_dwend_timeout, .text.nan_sync_bcn_timeout, .text.nan_disc_bcn_timeout, .text.nan_action_timeout, .text.nan_faw_start_timeout, .text.nan_faw_end_timeout, .text.nan_ndc_start_timeout
 * Fidelity: low - large/complex: 7 branches, 0 loop(s), 3 calls; skeleton only */
static int nan_init_event_hdlr(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2, a3 */
    /* struct offsets touched: 244, 356, 360 */
    /* immediates: 254, 6, 24, 68, 0x144, 0x108, 8, 28, 48, 88, 108, 128 */
    /* branches: +0x43 bnei->0x49; +0x46 j->0x158; +0x4c beq->0x55; +0x4f beqz->0x139; +0x52 j->0x160; +0x134 j->0x160; +0x155 j->0x162 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    memcpy(0, 0, 0);  /* ordered call */
    memset(0, 0, 0);  /* ordered call */
    nan_recycle_rx_bcn(0, 0, 0, 0, 0, 0);  /* ordered call[+0x4] [local] */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_ndc_start_timeout @ ieee80211_nan_disc.o 00000000 size 68B bind LOCAL (no symbol; sec .text.nan_ndc_start_timeout)
 * Calls: wifi_log, ieee80211_timer_process | Data refs: g_nan_started, .rodata_wlog_warning.14
 * Fidelity: medium - small frame, 2 calls + 2 branch(es) mapped */
static int nan_ndc_start_timeout(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2 */
    /* immediates: 1, 2, 34, 7 */
    /* branches: +0x21 bnez.n->0x38; +0x35 j->0x42 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    wifi_log(0, 0, 0, 0, 0, 0);  /* ordered call */
    ieee80211_timer_process(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_faw_end_timeout @ ieee80211_nan_disc.o 00000000 size 68B bind LOCAL (no symbol; sec .text.nan_faw_end_timeout)
 * Calls: wifi_log, ieee80211_timer_process | Data refs: g_nan_started, .rodata_wlog_warning.13
 * Fidelity: medium - small frame, 2 calls + 2 branch(es) mapped */
static int nan_faw_end_timeout(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2 */
    /* immediates: 1, 2, 33, 7 */
    /* branches: +0x21 bnez.n->0x38; +0x35 j->0x42 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    wifi_log(0, 0, 0, 0, 0, 0);  /* ordered call */
    ieee80211_timer_process(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_faw_start_timeout @ ieee80211_nan_disc.o 00000000 size 68B bind LOCAL (no symbol; sec .text.nan_faw_start_timeout)
 * Calls: wifi_log, ieee80211_timer_process | Data refs: g_nan_started, .rodata_wlog_warning.12
 * Fidelity: medium - small frame, 2 calls + 2 branch(es) mapped */
static int nan_faw_start_timeout(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2 */
    /* immediates: 1, 2, 32, 7 */
    /* branches: +0x21 bnez.n->0x38; +0x35 j->0x42 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    wifi_log(0, 0, 0, 0, 0, 0);  /* ordered call */
    ieee80211_timer_process(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_action_timeout @ ieee80211_nan_disc.o 00000000 size 68B bind LOCAL (no symbol; sec .text.nan_action_timeout)
 * Calls: wifi_log, ieee80211_timer_process | Data refs: g_nan_started, .rodata_wlog_warning.11
 * Fidelity: medium - small frame, 2 calls + 2 branch(es) mapped */
static int nan_action_timeout(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2 */
    /* immediates: 1, 2, 31, 7 */
    /* branches: +0x21 bnez.n->0x38; +0x35 j->0x42 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    wifi_log(0, 0, 0, 0, 0, 0);  /* ordered call */
    ieee80211_timer_process(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_disc_bcn_timeout @ ieee80211_nan_disc.o 00000000 size 68B bind LOCAL (no symbol; sec .text.nan_disc_bcn_timeout)
 * Calls: wifi_log, ieee80211_timer_process | Data refs: g_nan_started, .rodata_wlog_warning.10
 * Fidelity: medium - small frame, 2 calls + 2 branch(es) mapped */
static int nan_disc_bcn_timeout(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2 */
    /* immediates: 1, 2, 29, 7 */
    /* branches: +0x21 bnez.n->0x38; +0x35 j->0x42 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    wifi_log(0, 0, 0, 0, 0, 0);  /* ordered call */
    ieee80211_timer_process(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_sync_bcn_timeout @ ieee80211_nan_disc.o 00000000 size 68B bind LOCAL (no symbol; sec .text.nan_sync_bcn_timeout)
 * Calls: wifi_log, ieee80211_timer_process | Data refs: g_nan_started, .rodata_wlog_warning.9
 * Fidelity: medium - small frame, 2 calls + 2 branch(es) mapped */
static int nan_sync_bcn_timeout(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2 */
    /* immediates: 1, 2, 30, 7 */
    /* branches: +0x21 bnez.n->0x38; +0x35 j->0x42 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    wifi_log(0, 0, 0, 0, 0, 0);  /* ordered call */
    ieee80211_timer_process(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_dwend_timeout @ ieee80211_nan_disc.o 00000000 size 194B bind LOCAL (no symbol; sec .text.nan_dwend_timeout)
 * Calls: wifi_log, nan_get_random_byte, nan_schedule_next_dwstart[+0xc][local], ieee80211_timer_process | Data refs: g_nan_started, .rodata_wlog_warning.8, .rodata_wlog_warning.4
 * Fidelity: medium - small frame, 4 calls + 6 branch(es) mapped */
static int nan_dwend_timeout(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a3 */
    /* struct offsets touched: 14, 15, 74, 89, 209 */
    /* immediates: 1, 2, 240, 0, 28, 7 */
    /* branches: +0x2f bnez.n->0x48; +0x44 j->0xC0; +0x51 bnez.n->0x69; +0x65 j->0xB4; +0x6f beqz.n->0x7D; +0x83 bne->0xA9 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    wifi_log(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_get_random_byte(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_schedule_next_dwstart(0, 0, 0, 0, 0, 0);  /* ordered call[+0xc] [local] */
    ieee80211_timer_process(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_warmup_timeout @ ieee80211_nan_disc.o 00000000 size 68B bind LOCAL (no symbol; sec .text.nan_warmup_timeout)
 * Calls: wifi_log, ieee80211_timer_process | Data refs: g_nan_started, .rodata_wlog_warning.6
 * Fidelity: medium - small frame, 2 calls + 2 branch(es) mapped */
static int nan_warmup_timeout(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2 */
    /* immediates: 1, 2, 25, 7 */
    /* branches: +0x21 bnez.n->0x38; +0x35 j->0x42 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    wifi_log(0, 0, 0, 0, 0, 0);  /* ordered call */
    ieee80211_timer_process(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_scan_timeout @ ieee80211_nan_disc.o 00000000 size 68B bind LOCAL (no symbol; sec .text.nan_scan_timeout)
 * Calls: wifi_log, ieee80211_timer_process | Data refs: g_nan_started, .rodata_wlog_warning.5
 * Fidelity: medium - small frame, 2 calls + 2 branch(es) mapped */
static int nan_scan_timeout(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2 */
    /* immediates: 1, 2, 26, 7 */
    /* branches: +0x21 bnez.n->0x38; +0x35 j->0x42 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    wifi_log(0, 0, 0, 0, 0, 0);  /* ordered call */
    ieee80211_timer_process(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_dwstart_timeout @ ieee80211_nan_disc.o 00000000 size 356B bind LOCAL (no symbol; sec .text.nan_dwstart_timeout)
 * Calls: wifi_log, chm_is_at_home_channel, chm_return_home_channel, nan_action_frames_queued, nan_static_sdfs_present, nan_get_random_word, ieee80211_timer_process | Data refs: g_nan_started, .rodata_wlog_warning.7, .rodata_wlog_warning.2, .rodata_wlog_info.3, g_osi_funcs_p
 * Fidelity: low - large/complex: 8 branches, 0 loop(s), 7 calls; skeleton only */
static int nan_dwstart_timeout(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a3, a4 */
    /* struct offsets touched: 24, 236, 248 */
    /* immediates: 1, 2, 3, -2, 88, 0, 68, 9, 128, 7, 27 */
    /* branches: +0x47 bnez.n->0x60; +0x5c j->0x162; +0x69 bnez.n->0x80; +0x7d j->0x156; +0x86 bnez.n->0xA2; +0xaa bgeui->0xDD; +0x10a bnez->0x110; +0x10d beqz->0x156 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    wifi_log(0, 0, 0, 0, 0, 0);  /* ordered call */
    chm_is_at_home_channel(0, 0, 0, 0, 0, 0);  /* ordered call */
    chm_return_home_channel(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_action_frames_queued(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_static_sdfs_present(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_get_random_word(0, 0, 0, 0, 0, 0);  /* ordered call */
    ieee80211_timer_process(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_is_ambtt_too_old_isra_0 @ ieee80211_nan_disc.o 00000000 size 78B bind LOCAL (no symbol; sec .text.nan_is_ambtt_too_old$isra$0)
 * Calls: nan_get_tsf | Data refs: none
 * Fidelity: medium - small frame, 1 call + 2 branch(es) mapped */
static int nan_is_ambtt_too_old_isra_0(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2, a3 */
    /* struct offsets touched: 58, 59, 60, 61, 62 */
    /* immediates: 0, 1 */
    /* branches: +0x12 beq->0x4C; +0x43 bltu->0x49 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    nan_get_tsf(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_nmns_event_hdlr @ ieee80211_nan_disc.o 0000004c size 321B bind GLOBAL
 * Calls: nan_common_dwstart_ops[+0x8][local], nan_common_dwend_ops[+0x30][local], nan_is_in_dw, nan_is_ambtt_too_old_isra_0[+0x4][local], nan_update_amr_for_non_anchor[+0x24][local], nan_adjust_non_anchor_tsf[+0x14][local], nan_update_bcn_stats[+0x10][local], nan_recycle_rx_bcn[+0x4][local], nan_stop_handler[+0x14][local], nan_send_static_sdfs, nan_tx_queued_action_frames, wifi_log, nan_dp_indicate_faw_start, nan_dp_schedule_next_faw, nan_dp_indicate_ndc_start | Data refs: .rodata.nan_nmns_event_hdlr, g_osi_funcs_p, .rodata_wlog_debug.26
 * Fidelity: low - large/complex: 21 branches, 15 loop(s), 15 calls; skeleton only */
int nan_nmns_event_hdlr(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a3, a4 */
    /* struct offsets touched: 24, 25, 26, 27, 32, 33, 236, 352 */
    /* immediates: 13, 5, -1, 12, 254, 108, 31, 0x200, 0, 1, 4, 168 */
    /* branches: +0x51 bltu->0x20 [loop]; +0x56 beqz->0x13D; +0x5d bltu->0x44 [loop]; +0x71 beq->0x2B [loop]; +0x74 j->0x13D; +0x85 j->0x13D; +0x92 j->0x13D; +0xa2 j->0x13D; +0xb1 bnez.n->0x8D [loop]; +0xd6 bany->0xC2 [loop] (+11 more) */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    nan_common_dwstart_ops(0, 0, 0, 0, 0, 0);  /* ordered call[+0x8] [local] */
    nan_common_dwend_ops(0, 0, 0, 0, 0, 0);  /* ordered call[+0x30] [local] */
    nan_is_in_dw(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_is_ambtt_too_old_isra_0(0, 0, 0, 0, 0, 0);  /* ordered call[+0x4] [local] */
    nan_update_amr_for_non_anchor(0, 0, 0, 0, 0, 0);  /* ordered call[+0x24] [local] */
    nan_adjust_non_anchor_tsf(0, 0, 0, 0, 0, 0);  /* ordered call[+0x14] [local] */
    nan_update_bcn_stats(0, 0, 0, 0, 0, 0);  /* ordered call[+0x10] [local] */
    nan_recycle_rx_bcn(0, 0, 0, 0, 0, 0);  /* ordered call[+0x4] [local] */
    nan_stop_handler(0, 0, 0, 0, 0, 0);  /* ordered call[+0x14] [local] */
    nan_send_static_sdfs(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_tx_queued_action_frames(0, 0, 0, 0, 0, 0);  /* ordered call */
    wifi_log(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_dp_indicate_faw_start(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_dp_schedule_next_faw(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_dp_indicate_ndc_start(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_nms_event_hdlr @ ieee80211_nan_disc.o 00000054 size 352B bind GLOBAL
 * Calls: nan_common_dwstart_ops[+0x8][local], nan_common_dwend_ops[+0x30][local], nan_is_in_dw, nan_is_ambtt_too_old_isra_0[+0x4][local], nan_update_amr_for_non_anchor[+0x24][local], nan_adjust_non_anchor_tsf[+0x14][local], nan_update_bcn_stats[+0x10][local], nan_recycle_rx_bcn[+0x4][local], nan_transmit_bcn, nan_send_static_sdfs, nan_tx_queued_action_frames, wifi_log, nan_dp_indicate_faw_start, nan_dp_schedule_next_faw, nan_dp_indicate_ndc_start, nan_stop_handler[+0x14][local] | Data refs: .rodata.nan_nms_event_hdlr, g_osi_funcs_p, .rodata_wlog_debug.25
 * Fidelity: low - large/complex: 26 branches, 16 loop(s), 16 calls; skeleton only */
int nan_nms_event_hdlr(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a3 */
    /* struct offsets touched: 24, 25, 26, 27, 32, 33, 236, 312, 320, 352 */
    /* immediates: 13, -1, 12, 254, 108, 4, 31, 0x200, 1, 168, 148, 0 */
    /* branches: +0x59 bltu->0x21 [loop]; +0x5c beqz->0x15A; +0x63 bgeu->0x15 [loop]; +0x66 j->0x15A; +0x78 beq->0x2A [loop]; +0x7b j->0x15A; +0x8c j->0x15A; +0x98 j->0x15C; +0xa7 j->0x15C; +0xb8 bnez.n->0x8C [loop] (+16 more) */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    nan_common_dwstart_ops(0, 0, 0, 0, 0, 0);  /* ordered call[+0x8] [local] */
    nan_common_dwend_ops(0, 0, 0, 0, 0, 0);  /* ordered call[+0x30] [local] */
    nan_is_in_dw(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_is_ambtt_too_old_isra_0(0, 0, 0, 0, 0, 0);  /* ordered call[+0x4] [local] */
    nan_update_amr_for_non_anchor(0, 0, 0, 0, 0, 0);  /* ordered call[+0x24] [local] */
    nan_adjust_non_anchor_tsf(0, 0, 0, 0, 0, 0);  /* ordered call[+0x14] [local] */
    nan_update_bcn_stats(0, 0, 0, 0, 0, 0);  /* ordered call[+0x10] [local] */
    nan_recycle_rx_bcn(0, 0, 0, 0, 0, 0);  /* ordered call[+0x4] [local] */
    nan_transmit_bcn(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_send_static_sdfs(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_tx_queued_action_frames(0, 0, 0, 0, 0, 0);  /* ordered call */
    wifi_log(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_dp_indicate_faw_start(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_dp_schedule_next_faw(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_dp_indicate_ndc_start(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_stop_handler(0, 0, 0, 0, 0, 0);  /* ordered call[+0x14] [local] */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_send_started_event @ ieee80211_nan_disc.o 00000004 size 18B bind GLOBAL
 * Calls: nan_post_event | Data refs: none
 * Fidelity: high - trivial: straight-line, all targets resolved */
int nan_send_started_event(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: none observed */
    /* immediates: 0, 35 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    nan_post_event(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_schedule_disc_bcn @ ieee80211_nan_disc.o 0000000c size 84B bind GLOBAL
 * Calls: nan_get_tsf, __umoddi3 | Data refs: g_osi_funcs_p
 * Fidelity: medium - small frame, 2 calls + 1 branch(es) mapped */
int nan_schedule_disc_bcn(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a3, a4 */
    /* struct offsets touched: 236, 248 */
    /* immediates: 25, 0, 31, 108 */
    /* branches: +0x34 bany->0x34 [loop] */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    nan_get_tsf(0, 0, 0, 0, 0, 0);  /* ordered call */
    __umoddi3(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_master_event_hdlr @ ieee80211_nan_disc.o 0000005c size 373B bind GLOBAL
 * Calls: nan_schedule_disc_bcn, nan_common_dwstart_ops[+0x8][local], nan_common_dwend_ops[+0x30][local], nan_is_in_dw, nan_is_ambtt_too_old_isra_0[+0x4][local], nan_update_amr_for_non_anchor[+0x24][local], nan_adjust_non_anchor_tsf[+0x14][local], nan_update_bcn_stats[+0x10][local], nan_recycle_rx_bcn[+0x4][local], nan_transmit_bcn, nan_send_static_sdfs, nan_tx_queued_action_frames, wifi_log, nan_dp_indicate_faw_start, nan_dp_schedule_next_faw, nan_dp_indicate_ndc_start, nan_stop_handler[+0x14][local] | Data refs: .rodata.nan_master_event_hdlr, .rodata_wlog_debug.24
 * Fidelity: low - large/complex: 27 branches, 22 loop(s), 17 calls; skeleton only */
int nan_master_event_hdlr(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a3, a4 */
    /* struct offsets touched: 24, 25, 26, 27, 32, 33, 312, 316, 320, 352 */
    /* immediates: 13, 3, -1, 12, 254, 31, 0x200, 1, 4, 168, 148, 0 */
    /* branches: +0x61 bltu->0x21 [loop]; +0x66 beqz->0x171; +0x6d bltu->0x40 [loop]; +0x82 beq->0x2C [loop]; +0x85 j->0x171; +0x90 j->0x171; +0x9e j->0x171; +0xae j->0x171; +0xbd bnez.n->0x89 [loop]; +0xe2 bany->0xBE [loop] (+17 more) */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    nan_schedule_disc_bcn(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_common_dwstart_ops(0, 0, 0, 0, 0, 0);  /* ordered call[+0x8] [local] */
    nan_common_dwend_ops(0, 0, 0, 0, 0, 0);  /* ordered call[+0x30] [local] */
    nan_is_in_dw(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_is_ambtt_too_old_isra_0(0, 0, 0, 0, 0, 0);  /* ordered call[+0x4] [local] */
    nan_update_amr_for_non_anchor(0, 0, 0, 0, 0, 0);  /* ordered call[+0x24] [local] */
    nan_adjust_non_anchor_tsf(0, 0, 0, 0, 0, 0);  /* ordered call[+0x14] [local] */
    nan_update_bcn_stats(0, 0, 0, 0, 0, 0);  /* ordered call[+0x10] [local] */
    nan_recycle_rx_bcn(0, 0, 0, 0, 0, 0);  /* ordered call[+0x4] [local] */
    nan_transmit_bcn(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_send_static_sdfs(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_tx_queued_action_frames(0, 0, 0, 0, 0, 0);  /* ordered call */
    wifi_log(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_dp_indicate_faw_start(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_dp_schedule_next_faw(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_dp_indicate_ndc_start(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_stop_handler(0, 0, 0, 0, 0, 0);  /* ordered call[+0x14] [local] */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_fill_dynamic_attr @ ieee80211_nan_disc.o 0000000c size 131B bind GLOBAL
 * Calls: memcpy, nan_fill_country_code_attr | Data refs: NAN_STANDARD_OUI
 * Fidelity: medium - small frame, 2 calls + 0 branch(es) mapped */
int nan_fill_dynamic_attr(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2, a3 */
    /* struct offsets touched: 14, 15, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47 */
    /* immediates: -35, 30, 16, 0, 2, 0x110, 50, 1, 13, 63 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    memcpy(0, 0, 0);  /* ordered call */
    nan_fill_country_code_attr(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_construct_beacon @ ieee80211_nan_disc.o 00000000 size 87B bind LOCAL (no symbol; sec .text.nan_construct_beacon)
 * Calls: nan_fill_dynamic_attr | Data refs: none
 * Fidelity: medium - small frame, 1 call + 2 branch(es) mapped */
static int nan_construct_beacon(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2, a3, a4 */
    /* struct offsets touched: 20, 22, 32, 33, 312, 316 */
    /* immediates: 2, 100, 0, 68 */
    /* branches: +0xf bnez.n->0x26; +0x23 j->0x3B */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    nan_fill_dynamic_attr(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_scan_event_hdlr @ ieee80211_nan_disc.o 0000012c size 1967B bind GLOBAL
 * Calls: nan_disc_enable_rx, wifi_log, wifi_set_rx_policy, memcpy, nan_get_random_byte, nan_compare_mr[+0x4][local], memset, hal_now, nan_post_event, nan_update_tsf, nan_alloc_beacon, nan_construct_beacon[+0x4][local], nan_schedule_next_dwstart[+0xc][local], nan_send_started_event, memcmp, nan_get_tsf, ic_ebuf_recycle_tx, nan_update_static_sdfs, nan_recycle_rx_bcn[+0x4][local], nan_stop_handler[+0x14][local], nan_is_in_dw, nan_transmit_bcn, nan_schedule_disc_bcn | Data refs: .rodata_wlog_debug.20, g_osi_funcs_p, .rodata_wlog_debug.21, .rodata.nan_scan_event_hdlr.str1.1, NAN_STANDARD_BSSID, .rodata_wlog_debug.19, .rodata_wlog_error.17, .rodata_wlog_error.18, .rodata_wlog_debug.22
 * Fidelity: low - large/complex: 65 branches, 49 loop(s), 23 calls; skeleton only */
int nan_scan_event_hdlr(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,96; early arg regs: a2, a3, a6 */
    /* struct offsets touched: 8, 12, 14, 15, 16, 23, 24, 25, 26, 27, 28, 29, 30, 31 */
    /* immediates: 254, 1, 10, 4, 12, 105, 5, 8, 0, 11, 224, 0x130 */
    /* branches: +0x133 bnei->0xD [loop]; +0x136 j->0x339; +0x139 bgeui->0x1C [loop]; +0x13c bnei->0x16 [loop]; +0x13f j->0x74C; +0x142 beqi->0x94 [loop]; +0x145 j->0x8E [loop]; +0x148 bnei->0x22 [loop]; +0x14b j->0x783; +0x153 beq->0x2D [loop] (+55 more) */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    nan_disc_enable_rx(0, 0, 0, 0, 0, 0);  /* ordered call */
    wifi_log(0, 0, 0, 0, 0, 0);  /* ordered call */
    wifi_set_rx_policy(0, 0, 0, 0, 0, 0);  /* ordered call */
    memcpy(0, 0, 0);  /* ordered call */
    nan_get_random_byte(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_compare_mr(0, 0, 0, 0, 0, 0);  /* ordered call[+0x4] [local] */
    memset(0, 0, 0);  /* ordered call */
    hal_now(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_post_event(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_update_tsf(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_alloc_beacon(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_construct_beacon(0, 0, 0, 0, 0, 0);  /* ordered call[+0x4] [local] */
    nan_schedule_next_dwstart(0, 0, 0, 0, 0, 0);  /* ordered call[+0xc] [local] */
    nan_send_started_event(0, 0, 0, 0, 0, 0);  /* ordered call */
    memcmp(0, 0, 0);  /* ordered call */
    nan_get_tsf(0, 0, 0, 0, 0, 0);  /* ordered call */
    ic_ebuf_recycle_tx(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_update_static_sdfs(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_recycle_rx_bcn(0, 0, 0, 0, 0, 0);  /* ordered call[+0x4] [local] */
    nan_stop_handler(0, 0, 0, 0, 0, 0);  /* ordered call[+0x14] [local] */
    nan_is_in_dw(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_transmit_bcn(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_schedule_disc_bcn(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_am_event_hdlr @ ieee80211_nan_disc.o 00000090 size 840B bind GLOBAL
 * Calls: memcmp, memcpy, memset, nan_schedule_disc_bcn, nan_get_random_byte, nan_fill_dynamic_attr, nan_common_dwstart_ops[+0x8][local], nan_common_dwend_ops[+0x30][local], nan_is_in_dw, nan_is_ambtt_too_old_isra_0[+0x4][local], nan_compare_mr[+0x4][local], nan_update_tsf_from_bcn[+0xc][local], nan_update_bcn_stats[+0x10][local], nan_recycle_rx_bcn[+0x4][local], nan_transmit_bcn, nan_send_static_sdfs, nan_tx_queued_action_frames, wifi_log, nan_dp_indicate_faw_start, nan_dp_schedule_next_faw, nan_dp_indicate_ndc_start, nan_stop_handler[+0x14][local] | Data refs: .rodata.nan_am_event_hdlr, g_osi_funcs_p, .rodata_wlog_debug.23
 * Fidelity: low - large/complex: 38 branches, 29 loop(s), 22 calls; skeleton only */
int nan_am_event_hdlr(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a3, a4, a6 */
    /* struct offsets touched: 14, 15, 22, 23, 24, 25, 26, 27, 32, 33, 58, 59, 60, 61 */
    /* immediates: 13, 2, -1, 12, 254, 0x110, 0x108, 6, 0x11d, 0x118, 5, 8 */
    /* branches: +0x95 bltu->0x20 [loop]; +0x9a beqz->0x344; +0xa1 bltu->0x88 [loop]; +0xb5 beq->0x2B [loop]; +0xb8 j->0x344; +0xd3 bnez.n->0x71 [loop]; +0x11a j->0x344; +0x180 j->0x88 [loop]; +0x18c j->0x88 [loop]; +0x199 j->0x344 (+28 more) */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    memcmp(0, 0, 0);  /* ordered call */
    memcpy(0, 0, 0);  /* ordered call */
    memset(0, 0, 0);  /* ordered call */
    nan_schedule_disc_bcn(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_get_random_byte(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_fill_dynamic_attr(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_common_dwstart_ops(0, 0, 0, 0, 0, 0);  /* ordered call[+0x8] [local] */
    nan_common_dwend_ops(0, 0, 0, 0, 0, 0);  /* ordered call[+0x30] [local] */
    nan_is_in_dw(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_is_ambtt_too_old_isra_0(0, 0, 0, 0, 0, 0);  /* ordered call[+0x4] [local] */
    nan_compare_mr(0, 0, 0, 0, 0, 0);  /* ordered call[+0x4] [local] */
    nan_update_tsf_from_bcn(0, 0, 0, 0, 0, 0);  /* ordered call[+0xc] [local] */
    nan_update_bcn_stats(0, 0, 0, 0, 0, 0);  /* ordered call[+0x10] [local] */
    nan_recycle_rx_bcn(0, 0, 0, 0, 0, 0);  /* ordered call[+0x4] [local] */
    nan_transmit_bcn(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_send_static_sdfs(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_tx_queued_action_frames(0, 0, 0, 0, 0, 0);  /* ordered call */
    wifi_log(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_dp_indicate_faw_start(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_dp_schedule_next_faw(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_dp_indicate_ndc_start(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_stop_handler(0, 0, 0, 0, 0, 0);  /* ordered call[+0x14] [local] */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_sm_handle_event_internal @ ieee80211_nan_disc.o 00000004 size 52B bind GLOBAL
 * Calls: none | Data refs: gNanSm
 * Fidelity: medium - small frame, 0 calls + 2 branch(es) mapped */
int nan_sm_handle_event_internal(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2, a3, a4 */
    /* immediates: 254 */
    /* branches: +0x1c j->0x2D; +0x33 bne->0x1C [loop] */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_sm_handle_event @ ieee80211_nan_disc.o 00000004 size 15B bind GLOBAL
 * Calls: nan_sm_handle_event_internal | Data refs: none
 * Fidelity: high - trivial: straight-line, all targets resolved */
int nan_sm_handle_event(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2, a3 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    nan_sm_handle_event_internal(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_warmup_timeout_process @ ieee80211_nan_disc.o 00000004 size 15B bind GLOBAL
 * Calls: nan_sm_handle_event | Data refs: none
 * Fidelity: high - trivial: straight-line, all targets resolved */
int nan_warmup_timeout_process(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2 */
    /* immediates: 3 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    nan_sm_handle_event(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_scan_timeout_process @ ieee80211_nan_disc.o 00000004 size 32B bind GLOBAL
 * Calls: nan_sm_handle_event | Data refs: none
 * Fidelity: high - trivial: straight-line, all targets resolved */
int nan_scan_timeout_process(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2 */
    /* struct offsets touched: 108 */
    /* immediates: 13, 2 */
    /* branches: +0xf beqz.n->0x16; +0x17 bnei->0x18 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    nan_sm_handle_event(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_dw_start_process @ ieee80211_nan_disc.o 0000000c size 40B bind GLOBAL
 * Calls: nan_sm_handle_event, wifi_log | Data refs: .rodata_wlog_warning.15
 * Fidelity: medium - small frame, 2 calls + 2 branch(es) mapped */
int nan_dw_start_process(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2 */
    /* immediates: 4, 1, 2 */
    /* branches: +0x13 beqz.n->0x14; +0x1d j->0x26 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    nan_sm_handle_event(0, 0, 0, 0, 0, 0);  /* ordered call */
    wifi_log(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_dw_end_process @ ieee80211_nan_disc.o 0000000c size 40B bind GLOBAL
 * Calls: nan_sm_handle_event, wifi_log | Data refs: .rodata_wlog_warning.16
 * Fidelity: medium - small frame, 2 calls + 2 branch(es) mapped */
int nan_dw_end_process(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2 */
    /* immediates: 5, 1, 2 */
    /* branches: +0x13 beqz.n->0x14; +0x1d j->0x26 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    nan_sm_handle_event(0, 0, 0, 0, 0, 0);  /* ordered call */
    wifi_log(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_send_disc_bcn_process @ ieee80211_nan_disc.o 00000004 size 19B bind GLOBAL
 * Calls: nan_sm_handle_event | Data refs: none
 * Fidelity: high - trivial: straight-line, all targets resolved */
int nan_send_disc_bcn_process(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2 */
    /* immediates: 8 */
    /* branches: +0xb beqz.n->0x11 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    nan_sm_handle_event(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_send_sync_bcn_process @ ieee80211_nan_disc.o 00000004 size 19B bind GLOBAL
 * Calls: nan_sm_handle_event | Data refs: none
 * Fidelity: high - trivial: straight-line, all targets resolved */
int nan_send_sync_bcn_process(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2 */
    /* immediates: 7 */
    /* branches: +0xb beqz.n->0x11 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    nan_sm_handle_event(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_send_action_process @ ieee80211_nan_disc.o 00000004 size 19B bind GLOBAL
 * Calls: nan_sm_handle_event | Data refs: none
 * Fidelity: high - trivial: straight-line, all targets resolved */
int nan_send_action_process(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2 */
    /* immediates: 9 */
    /* branches: +0xb beqz.n->0x11 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    nan_sm_handle_event(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_faw_start_process @ ieee80211_nan_disc.o 00000004 size 19B bind GLOBAL
 * Calls: nan_sm_handle_event | Data refs: none
 * Fidelity: high - trivial: straight-line, all targets resolved */
int nan_faw_start_process(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2 */
    /* immediates: 10 */
    /* branches: +0xb beqz.n->0x11 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    nan_sm_handle_event(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_faw_end_process @ ieee80211_nan_disc.o 00000004 size 19B bind GLOBAL
 * Calls: nan_sm_handle_event | Data refs: none
 * Fidelity: high - trivial: straight-line, all targets resolved */
int nan_faw_end_process(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2 */
    /* immediates: 11 */
    /* branches: +0xb beqz.n->0x11 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    nan_sm_handle_event(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_ndc_start_process @ ieee80211_nan_disc.o 00000004 size 19B bind GLOBAL
 * Calls: nan_sm_handle_event | Data refs: none
 * Fidelity: high - trivial: straight-line, all targets resolved */
int nan_ndc_start_process(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2 */
    /* immediates: 12 */
    /* branches: +0xb beqz.n->0x11 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    nan_sm_handle_event(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_sm_init @ ieee80211_nan_disc.o 00000004 size 23B bind GLOBAL
 * Calls: nan_sm_handle_event | Data refs: none
 * Fidelity: high - trivial: straight-line, all targets resolved */
int nan_sm_init(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2 */
    /* immediates: 0, 254 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    nan_sm_handle_event(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_sm_deinit @ ieee80211_nan_disc.o 00000004 size 18B bind GLOBAL
 * Calls: memset | Data refs: none
 * Fidelity: high - trivial: straight-line, all targets resolved */
int nan_sm_deinit(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2 */
    /* immediates: 0x180, 0 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    memset(0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_sm_start @ ieee80211_nan_disc.o 00000004 size 18B bind GLOBAL
 * Calls: nan_sm_handle_event | Data refs: none
 * Fidelity: high - trivial: straight-line, all targets resolved */
int nan_sm_start(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2 */
    /* branches: +0xb bnez->0x10 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    nan_sm_handle_event(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_sm_stop @ ieee80211_nan_disc.o 00000004 size 19B bind GLOBAL
 * Calls: nan_sm_handle_event | Data refs: none
 * Fidelity: high - trivial: straight-line, all targets resolved */
int nan_sm_stop(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2 */
    /* immediates: 1 */
    /* branches: +0xb beqz.n->0x11 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    nan_sm_handle_event(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* Notable rodata/log strings in this object (grounded, from Contents sections):
 *   [.text.nan_in_transit_event_hdlr] "6A..b.."
 *   [.text.nan_schedule_next_dwstart] "............6A.."
 *   [.text.nan_schedule_next_dwstart] "................"
 *   [.text.nan_schedule_next_dwstart] ".....P........P."
 *   [.text.nan_schedule_next_dwstart] "...........0...("
 *   [.text.nan_schedule_next_dwstart] ">....."
 *   [.text.nan_update_tsf_from_bcn] "............6A.."
 *   [.text.nan_update_tsf_from_bcn] ".....(.8.(...8.""
 *   [.text.nan_update_tsf_from_bcn] "..."....." ....."
 *   [.text.nan_update_tsf_from_bcn] ". . "...".." ..."
 *   [.text.nan_update_tsf_from_bcn] "........ ......."
 *   [.text.nan_update_tsf_from_bcn] ". 2...3..3 ....."
 *   [.text.nan_update_tsf_from_bcn] "........*(...2.."
 *   [.text.nan_update_tsf_from_bcn] ".:9...... ......"
 *   [.text.nan_update_tsf_from_bcn] ":...0.......1..0"
 *   [.text.nan_update_tsf_from_bcn] ".....0...9......"
 *   [.text.nan_update_tsf_from_bcn] ".......h.X`...8."
 *   [.text.nan_update_tsf_from_bcn] "............"
 *   [.text.nan_compare_mr] "....6a.........."
 *   [.text.nan_compare_mr] ".u..A...).... ."
 *   [.text.nan_compare_mr] ".. ............."
 *   [.text.nan_compare_mr] ". .(...u..A... ."
 *   [.text.nan_compare_mr] "..... ..... ..."
 *   [.text.nan_compare_mr] ")..!..u . .1...8"
 *   [.text.nan_compare_mr] "A.3.......0. .."
 */
