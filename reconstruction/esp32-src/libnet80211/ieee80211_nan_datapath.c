/* ieee80211_nan_datapath.c - reconstructed from ieee80211_nan_datapath.o (131976 bytes on disk).
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

extern int chm_acquire_lock();  /* external, prototype unknown */
extern int chm_get_current_channel();  /* external, prototype unknown */
extern int chm_get_home_channel();  /* external, prototype unknown */
extern int chm_is_at_home_channel();  /* external, prototype unknown */
extern int chm_release_lock();  /* external, prototype unknown */
extern int chm_return_home_channel();  /* external, prototype unknown */
extern int chm_set_current_channel();  /* external, prototype unknown */
extern int chm_start_op();  /* external, prototype unknown */
extern int cnx_rc_update_rssi();  /* external, prototype unknown */
extern int ic_del_key();  /* external, prototype unknown */
extern int ic_ebuf_recycle_rx();  /* external, prototype unknown */
extern int ic_ebuf_recycle_tx();  /* external, prototype unknown */
extern int ic_get_random();  /* external, prototype unknown */
extern int ieee80211_add_htcap();  /* external, prototype unknown */
extern int ieee80211_ht_node_cleanup();  /* external, prototype unknown */
extern int ieee80211_ht_node_init();  /* external, prototype unknown */
extern int ieee80211_ht_updatehtcap();  /* external, prototype unknown */
extern int ieee80211_send_nulldata();  /* external, prototype unknown */
extern int ieee80211_setup_htrates();  /* external, prototype unknown */
extern int ieee80211_setup_phy_mode();  /* external, prototype unknown */
extern int ieee80211_setup_rates();  /* external, prototype unknown */
extern int ieee80211_timer_process();  /* external, prototype unknown */
extern int nan_alloc_action();  /* external, prototype unknown */
extern int nan_call_ndp_confirm_cb();  /* external, prototype unknown */
extern int nan_call_ndp_indication_cb();  /* external, prototype unknown */
extern int nan_call_ndp_response_indication_cb();  /* external, prototype unknown */
extern int nan_call_ndp_terminated_cb();  /* external, prototype unknown */
extern int nan_clear_peer_integrity_keys();  /* external, prototype unknown */
extern int nan_get_clust_id();  /* external, prototype unknown */
extern int nan_get_peer_svc_record();  /* external, prototype unknown */
extern int nan_get_service_by_id();  /* external, prototype unknown */
extern int nan_get_service_by_index();  /* external, prototype unknown */
extern int nan_get_tsf();  /* external, prototype unknown */
extern int nan_is_pmf_enabled();  /* external, prototype unknown */
extern int nan_set_trc();  /* external, prototype unknown */
extern int nan_set_update_sdf_pending();  /* external, prototype unknown */
extern int nan_tx_action_frame();  /* external, prototype unknown */
extern int ppTxPkt();  /* external, prototype unknown */
extern int wifi_log();  /* external, prototype unknown */

static int nan_get_avail_by_map_id(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
static int nan_dp_clear_tmp_data(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
static int nan_ndp_inactivity_handler(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
static int nan_ndp_setup_timeout(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
static int ndc_txop_end(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
static int ndc_txop_start(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_sched_in_ndc_slot(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_sched_is_peer_available(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_sched_alloc_time_slots(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_sched_get_chan_bitmap(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_sched_allocate_crbs(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_sched_alloc_conditional(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_sched_reset_avail_flags_sdf(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_sched_avail_entries_len(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_sched_add_entry(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_sched_construct_availability(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_dp_node_available(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_dp_alloc_node(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_dp_remove_node(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_dp_search_node(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_dp_log_rx(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_dp_node_exists(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_dp_get_peer_ndp(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_dp_get_peer_ndl(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_dp_get_ndl_by_bss(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_ndp_inactivity_timeout_process(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_ndp_start_inactivity_timer(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_dp_alloc_ndp(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_dp_alloc_ndl(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_dp_delete_peer(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_dp_setup_peer(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_dp_confirm_peer(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_dp_construct_device_caps(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_dp_post_tx(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_ndp_setup_timeout_process(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_construct_ndp_confirm(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_construct_ndp_terminate(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_construct_ndp_resp(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_construct_ndp_req(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_send_ndp_confirm(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_send_ndp_terminate(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_construct_ndp_security_key_install(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_send_security_key_install(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_send_ndp_resp(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_send_ndp_req(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_dp_parse_ndpa(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_dp_parse_ndla(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_dp_parse_elem_container(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_dp_parse_dev_caps(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_dp_chan_from_bitmap(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_dp_parse_time_bitmap(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_dp_parse_ndca(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_sched_parse_avail_entries(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_dp_parse_availability(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_parse_ndp_req(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_parse_ndp_resp(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_parse_ndp_confirm(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_parse_ndp_security_install(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_parse_ndp_terminate(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_dp_get_attr(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_rx_naf(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_naf_txcb(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_datapath_send_req(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_datapath_send_resp(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_datapath_end(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_sched_init_availability(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_dp_init(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_dp_deinit(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_dp_update_ndi(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_dp_has_active_datapath(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_dp_get_own_ndi(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_dp_indicate_ndc_start(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_dp_indicate_faw_start(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_dp_schedule_next_faw(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_dp_schedule_ndc_start(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_nulldata_txcb(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);

/* nan_get_avail_by_map_id @ ieee80211_nan_datapath.o 00000000 size 38B bind LOCAL (no symbol; sec .text.nan_get_avail_by_map_id)
 * Calls: none | Data refs: none
 * Fidelity: medium - small frame, 0 calls + 4 branch(es) mapped */
static int nan_get_avail_by_map_id(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2, a3, a4 */
    /* struct offsets touched: 88 */
    /* immediates: 0, 1, 92 */
    /* branches: +0x7 j->0x1F; +0x12 beqz.n->0x1A; +0x17 beq->0x24; +0x1f blt->0xD [loop] */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_dp_clear_tmp_data @ ieee80211_nan_datapath.o 00000000 size 114B bind LOCAL (no symbol; sec .text.nan_dp_clear_tmp_data)
 * Calls: memset | Data refs: g_osi_funcs_p
 * Fidelity: medium - small frame, 1 call + 6 branch(es) mapped */
static int nan_dp_clear_tmp_data(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2 */
    /* struct offsets touched: 176, 516, 520, 524, 532, 536 */
    /* immediates: 0x204, 24, 0 */
    /* branches: +0xb beqz->0x70; +0x11 beqz->0x20; +0x23 beqz.n->0x31; +0x34 beqz.n->0x41; +0x44 beqz.n->0x51; +0x54 beqz.n->0x61 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    memset(0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_ndp_inactivity_handler @ ieee80211_nan_datapath.o 00000000 size 22B bind LOCAL (no symbol; sec .text.nan_ndp_inactivity_handler)
 * Calls: ieee80211_timer_process | Data refs: none
 * Fidelity: high - trivial: straight-line, all targets resolved */
static int nan_ndp_inactivity_handler(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2 */
    /* immediates: 36, 7 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    ieee80211_timer_process(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_ndp_setup_timeout @ ieee80211_nan_datapath.o 00000000 size 22B bind LOCAL (no symbol; sec .text.nan_ndp_setup_timeout)
 * Calls: ieee80211_timer_process | Data refs: none
 * Fidelity: high - trivial: straight-line, all targets resolved */
static int nan_ndp_setup_timeout(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2 */
    /* immediates: 35, 7 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    ieee80211_timer_process(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* ndc_txop_end @ ieee80211_nan_datapath.o 00000000 size 25B bind LOCAL (no symbol; sec .text.ndc_txop_end)
 * Calls: chm_release_lock, chm_return_home_channel | Data refs: none
 * Fidelity: medium - small frame, 2 calls + 0 branch(es) mapped */
static int ndc_txop_end(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: none observed */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    chm_release_lock(0, 0, 0, 0, 0, 0);  /* ordered call */
    chm_return_home_channel(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* ndc_txop_start @ ieee80211_nan_datapath.o 00000000 size 55B bind LOCAL (no symbol; sec .text.ndc_txop_start)
 * Calls: ppTxPkt | Data refs: s_dp
 * Fidelity: medium - small frame, 1 call + 4 branch(es) mapped */
static int ndc_txop_start(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2, a3 */
    /* struct offsets touched: 40 */
    /* immediates: 0, 1 */
    /* branches: +0x13 beqz.n->0x35; +0x19 beqz.n->0x35; +0x20 bnez->0x25; +0x32 j->0x17 [loop] */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    ppTxPkt(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_sched_in_ndc_slot @ ieee80211_nan_datapath.o 0000000c size 72B bind GLOBAL
 * Calls: nan_get_tsf | Data refs: s_dp
 * Fidelity: medium - small frame, 1 call + 3 branch(es) mapped */
int nan_sched_in_ndc_slot(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2, a3 */
    /* struct offsets touched: 252 */
    /* immediates: 0, 31, 1 */
    /* branches: +0x1a beq->0x46; +0x40 bltu->0x39 [loop]; +0x47 bgeu->0x40 [loop] */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    nan_get_tsf(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_sched_is_peer_available @ ieee80211_nan_datapath.o 00000008 size 56B bind GLOBAL
 * Calls: nan_get_tsf | Data refs: none
 * Fidelity: medium - small frame, 1 call + 4 branch(es) mapped */
int nan_sched_is_peer_available(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2 */
    /* struct offsets touched: 500, 504, 508, 512 */
    /* immediates: 1, 0 */
    /* branches: +0x1a bgeu->0x1E; +0x23 bltu->0x34; +0x2b bgeu->0x34; +0x33 bltu->0x31 [loop] */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    nan_get_tsf(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_sched_alloc_time_slots @ ieee80211_nan_datapath.o 00000004 size 92B bind GLOBAL
 * Calls: none | Data refs: s_dp
 * Fidelity: medium - small frame, 0 calls + 6 branch(es) mapped */
int nan_sched_alloc_time_slots(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2, a3 */
    /* struct offsets touched: 252 */
    /* immediates: 2, 1, 30, 31, 0 */
    /* branches: +0x1b bany->0x1E; +0x38 j->0x4F; +0x43 bnone->0x4D; +0x46 bany->0x4D; +0x53 bgeu->0x58; +0x59 bgeu->0x37 [loop] */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_sched_get_chan_bitmap @ ieee80211_nan_datapath.o 00000004 size 102B bind GLOBAL
 * Calls: none | Data refs: .data.g_opclass_chan_tbl
 * Fidelity: medium - small frame, 0 calls + 7 branch(es) mapped */
int nan_sched_get_chan_bitmap(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2, a4 */
    /* immediates: 0, 14, 2, 12, 1, 16 */
    /* branches: +0x1b bne->0x2C; +0x2d j->0x5B; +0x37 j->0x64; +0x41 beqz.n->0x64; +0x48 bne->0x59; +0x5f bgeu->0x64; +0x65 bgeu->0x36 [loop] */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_sched_allocate_crbs @ ieee80211_nan_datapath.o 0000002c size 467B bind GLOBAL
 * Calls: memcpy, memset, nan_get_avail_by_map_id[local], wifi_log, nan_set_update_sdf_pending | Data refs: s_dp, s_dp+0x10, .rodata_wlog_error.2, .rodata_wlog_info.3
 * Fidelity: low - large/complex: 32 branches, 27 loop(s), 5 calls; skeleton only */
int nan_sched_allocate_crbs(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,96; early arg regs: a3, a4, a6, a7 */
    /* struct offsets touched: 8, 12, 16, 20, 22, 24, 28, 32, 36, 40, 47, 48, 64, 88 */
    /* immediates: 28, 44, -1, 0, 0x101, 0x128, 1, 2, 30, 31, 3 */
    /* branches: +0x34 beqz->0x51; +0x3d bnez.n->0x24 [loop]; +0x4c j->0x2A [loop]; +0x86 beqz.n->0x6C [loop]; +0x95 bnez->0x1C8; +0x9b beqz->0x84 [loop]; +0xad bnez->0x1C8; +0xb0 beqz.n->0xAC [loop]; +0xb5 bnez.n->0x98 [loop]; +0xb7 beqi->0xAC [loop] (+22 more) */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    memcpy(0, 0, 0);  /* ordered call */
    memset(0, 0, 0);  /* ordered call */
    nan_get_avail_by_map_id(0, 0, 0, 0, 0, 0);  /* ordered call [local] */
    wifi_log(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_set_update_sdf_pending(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_sched_alloc_conditional @ ieee80211_nan_datapath.o 00000028 size 313B bind GLOBAL
 * Calls: nan_get_avail_by_map_id[local], wifi_log, nan_sched_get_chan_bitmap, nan_sched_alloc_time_slots | Data refs: .rodata.nan_sched_alloc_conditional.str1.1, .rodata_wlog_info.4, g_def_2g_channels, s_dp
 * Fidelity: low - large/complex: 23 branches, 17 loop(s), 4 calls; skeleton only */
int nan_sched_alloc_conditional(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,64; early arg regs: a2, a4, a5, a6 */
    /* struct offsets touched: 16, 17, 18, 19, 33, 34, 35, 36, 52, 56, 64, 68, 92, 96 */
    /* immediates: 140, 1, 0, 3, 11, 81, 4, 14, -1 */
    /* branches: +0x43 beqz->0x70; +0x4c beqz->0x69; +0x55 beqz.n->0x44 [loop]; +0x69 bnez->0x127; +0x6f bnez.n->0x56 [loop]; +0x71 beqi->0x6E [loop]; +0x79 bnez.n->0x58 [loop]; +0x7b j->0x6E [loop]; +0x8e j->0x129; +0x93 j->0x70 [loop] (+13 more) */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    nan_get_avail_by_map_id(0, 0, 0, 0, 0, 0);  /* ordered call [local] */
    wifi_log(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_sched_get_chan_bitmap(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_sched_alloc_time_slots(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_sched_reset_avail_flags_sdf @ ieee80211_nan_datapath.o 0000000c size 117B bind GLOBAL
 * Calls: wifi_log | Data refs: .rodata_wlog_error.5
 * Fidelity: medium - small frame, 1 call + 8 branch(es) mapped */
int nan_sched_reset_avail_flags_sdf(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2 */
    /* struct offsets touched: 22, 44 */
    /* immediates: 4, 30, 18, -6, 3, 1, -49 */
    /* branches: +0x17 bbci->0x10 [loop]; +0x1f bbsi->0x70; +0x2f j->0x55; +0x45 bgeu->0x50; +0x58 j->0x70; +0x5c beq->0x61; +0x64 bgeui->0x28 [loop]; +0x67 j->0x70 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    wifi_log(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_sched_avail_entries_len @ ieee80211_nan_datapath.o 00000004 size 42B bind GLOBAL
 * Calls: none | Data refs: s_dp
 * Fidelity: medium - small frame, 0 calls + 3 branch(es) mapped */
int nan_sched_avail_entries_len(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2 */
    /* struct offsets touched: 36, 64, 92 */
    /* immediates: 0, 1, -4 */
    /* branches: +0x18 beqz->0x1A; +0x20 beqz.n->0x20 [loop]; +0x27 beqz.n->0x28 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_sched_add_entry @ ieee80211_nan_datapath.o 00000004 size 180B bind GLOBAL
 * Calls: nan_sched_get_chan_bitmap | Data refs: none
 * Fidelity: medium - small frame, 1 call + 0 branch(es) mapped */
int nan_sched_add_entry(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2, a3, a4 */
    /* struct offsets touched: 8, 9, 10, 11, 12, 13, 14, 15, 17, 20, 21, 22, 23 */
    /* immediates: 17, -249, -64, 3, 24, 4, 14, 0, 16 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    nan_sched_get_chan_bitmap(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_sched_construct_availability @ ieee80211_nan_datapath.o 00000020 size 244B bind GLOBAL
 * Calls: nan_sched_add_entry | Data refs: s_dp, s_dp+0x10, s_dp+0x2c, s_dp+0x48, s_avail_seq
 * Fidelity: medium - small frame, 1 call + 8 branch(es) mapped */
int nan_sched_construct_availability(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2, a3, a4, a5 */
    /* struct offsets touched: 36, 64, 92, 100, 101 */
    /* immediates: 18, -16, 6, 4, 16, 1, 0, -128, 2, 32, -3 */
    /* branches: +0x4c beqz->0x51; +0x74 beqz.n->0x94; +0x8b beqz.n->0x85 [loop]; +0x8d beqz->0x85 [loop]; +0xb7 beqz.n->0xC5; +0xcd beqz.n->0xC5 [loop]; +0xcf beqz.n->0xC5 [loop]; +0xeb beqz.n->0xD8 [loop] */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    nan_sched_add_entry(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_dp_node_available @ ieee80211_nan_datapath.o 00000004 size 31B bind GLOBAL
 * Calls: none | Data refs: g_ic
 * Fidelity: high - trivial: straight-line, all targets resolved */
int nan_dp_node_available(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2 */
    /* struct offsets touched: 580, 584, 672 */
    /* immediates: 1, 0 */
    /* branches: +0x14 beqz.n->0x1D */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_dp_alloc_node @ ieee80211_nan_datapath.o 00000030 size 300B bind GLOBAL
 * Calls: wifi_log, memset, memcpy, ieee80211_setup_phy_mode, nan_set_trc | Data refs: g_ic, .rodata_wlog_debug.6, g_osi_funcs_p, .rodata_wlog_debug.7
 * Fidelity: medium - small frame, 5 calls + 4 branch(es) mapped */
int nan_dp_alloc_node(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,64; early arg regs: a2, a3, a6 */
    /* struct offsets touched: 8, 12, 16, 20, 24, 38, 52, 55, 58, 312, 376, 580, 584, 672 */
    /* immediates: 1, 4, 0, 0x3d0, 174, 36, 210, -16, 18, 2, 246, 6 */
    /* branches: +0x6f beqz.n->0x4D [loop]; +0x74 beqz.n->0x4B [loop]; +0x78 j->0x12A; +0x96 beqz->0x46 [loop] */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    wifi_log(0, 0, 0, 0, 0, 0);  /* ordered call */
    memset(0, 0, 0);  /* ordered call */
    memcpy(0, 0, 0);  /* ordered call */
    ieee80211_setup_phy_mode(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_set_trc(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_dp_remove_node @ ieee80211_nan_datapath.o 00000014 size 181B bind GLOBAL
 * Calls: nan_set_trc, ic_del_key, ieee80211_ht_node_cleanup | Data refs: g_ic, g_osi_funcs_p
 * Fidelity: medium - small frame, 3 calls + 6 branch(es) mapped */
int nan_dp_remove_node(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2, a3, a4, a5, a6, a7 */
    /* struct offsets touched: 12, 52, 164, 176, 236, 240, 320, 580, 584, 672 */
    /* immediates: 0x13c, 1, 0, 24, 80, -17, 144 */
    /* branches: +0x3f beq->0x39 [loop]; +0x45 bne->0xB0; +0x4a j->0x3B [loop]; +0x62 bltu->0x7E; +0x6b beqz->0x7E; +0x9f bbci->0x9A [loop] */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    nan_set_trc(0, 0, 0, 0, 0, 0);  /* ordered call */
    ic_del_key(0, 0, 0, 0, 0, 0);  /* ordered call */
    ieee80211_ht_node_cleanup(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_dp_search_node @ ieee80211_nan_datapath.o 00000018 size 98B bind GLOBAL
 * Calls: wifi_log, memcmp | Data refs: g_ic, .rodata.str1.1, .rodata_wlog_error.9
 * Fidelity: medium - small frame, 2 calls + 7 branch(es) mapped */
int nan_dp_search_node(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2, a3, a4 */
    /* struct offsets touched: 576, 580, 584, 672 */
    /* immediates: 1, 0x250, 6, 4, 0 */
    /* branches: +0x23 bnez.n->0x29; +0x3c j->0x24 [loop]; +0x44 bbsi->0x5D; +0x4a beqz.n->0x44 [loop]; +0x5a beqz.n->0x60; +0x5f beqz.n->0x60; +0x72 j->0x60 [loop] */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    wifi_log(0, 0, 0, 0, 0, 0);  /* ordered call */
    memcmp(0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_dp_log_rx @ ieee80211_nan_datapath.o 00000000 size 5B bind GLOBAL
 * Calls: none | Data refs: none
 * Fidelity: high - trivial: straight-line, all targets resolved */
int nan_dp_log_rx(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: none observed */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_dp_node_exists @ ieee80211_nan_datapath.o 00000010 size 68B bind GLOBAL
 * Calls: wifi_log | Data refs: g_ic, .rodata.str1.1, .rodata_wlog_error.12
 * Fidelity: medium - small frame, 1 call + 4 branch(es) mapped */
int nan_dp_node_exists(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2 */
    /* struct offsets touched: 580, 584, 672 */
    /* immediates: 1, 0, 0x280 */
    /* branches: +0x1b beqz.n->0x28; +0x22 beq->0x40; +0x33 j->0x40; +0x4c j->0x3C [loop] */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    wifi_log(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_dp_get_peer_ndp @ ieee80211_nan_datapath.o 00000014 size 106B bind GLOBAL
 * Calls: memcmp | Data refs: s_dp, s_dp+0x68, s_dp+0x2ac
 * Fidelity: medium - small frame, 1 call + 7 branch(es) mapped */
int nan_dp_get_peer_ndp(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2, a3, a4, a5, a6, a7 */
    /* struct offsets touched: 12, 113 */
    /* immediates: 1, 0, 6, 112 */
    /* branches: +0x1e beqz->0x68; +0x31 bnez->0x66; +0x39 bnez.n->0x66; +0x49 beqz.n->0x48 [loop]; +0x58 bnez.n->0x68; +0x6f bne->0x68 [loop]; +0x77 j->0x68 [loop] */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    memcmp(0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_dp_get_peer_ndl @ ieee80211_nan_datapath.o 00000014 size 119B bind GLOBAL
 * Calls: memcmp | Data refs: s_dp+0x68, s_dp+0x2ac, s_dp
 * Fidelity: low - large/complex: 11 branches, 5 loop(s), 1 call; skeleton only */
int nan_dp_get_peer_ndl(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2 */
    /* immediates: 0x102, 6, 0x105, 1, 104, 0 */
    /* branches: +0x1a beqz->0x70; +0x20 bnez->0x14 [loop]; +0x26 beqz.n->0x38; +0x35 beqz.n->0x59; +0x47 bnez.n->0x70; +0x49 j->0x57; +0x4f bnez->0x14 [loop]; +0x55 bnez->0x14 [loop]; +0x5b bnez->0x14 [loop]; +0x64 bnez->0x14 [loop] (+1 more) */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    memcmp(0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_dp_get_ndl_by_bss @ ieee80211_nan_datapath.o 00000004 size 48B bind GLOBAL
 * Calls: none | Data refs: s_dp
 * Fidelity: medium - small frame, 0 calls + 5 branch(es) mapped */
int nan_dp_get_ndl_by_bss(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2 */
    /* struct offsets touched: 388, 968 */
    /* immediates: 1, 0, 104 */
    /* branches: +0x7 beqz.n->0x2E; +0xf beq->0x19; +0x15 bne->0x2C; +0x1a j->0x1B; +0x2d j->0x2E */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_ndp_inactivity_timeout_process @ ieee80211_nan_datapath.o 00000008 size 24B bind GLOBAL
 * Calls: nan_dp_node_exists, ieee80211_send_nulldata | Data refs: none
 * Fidelity: medium - small frame, 2 calls + 1 branch(es) mapped */
int nan_ndp_inactivity_timeout_process(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2 */
    /* branches: +0x14 beqz.n->0x16 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    nan_dp_node_exists(0, 0, 0, 0, 0, 0);  /* ordered call */
    ieee80211_send_nulldata(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_ndp_start_inactivity_timer @ ieee80211_nan_datapath.o 00000014 size 108B bind GLOBAL
 * Calls: ic_get_random | Data refs: s_dp, g_osi_funcs_p, .text.nan_ndp_inactivity_handler
 * Fidelity: medium - small frame, 1 call + 2 branch(es) mapped */
int nan_ndp_start_inactivity_timer(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2, a3, a4 */
    /* struct offsets touched: 102, 232, 236, 244 */
    /* immediates: 0x13c, 0 */
    /* branches: +0x17 beqz->0x6A; +0x20 beqz->0x6A */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    ic_get_random(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_dp_alloc_ndp @ ieee80211_nan_datapath.o 00000000 size 74B bind GLOBAL
 * Calls: none | Data refs: none
 * Fidelity: medium - small frame, 0 calls + 5 branch(es) mapped */
int nan_dp_alloc_ndp(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2, a3, a4 */
    /* struct offsets touched: 8, 9 */
    /* immediates: 0, 1, 0x106, 8, 0x102 */
    /* branches: +0x17 bnez.n->0x45; +0x1c bnez.n->0x45; +0x27 bnez.n->0x48; +0x2c bnez.n->0x48; +0x40 j->0x48 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_dp_alloc_ndl @ ieee80211_nan_datapath.o 00000008 size 131B bind GLOBAL
 * Calls: memcpy | Data refs: s_dp
 * Fidelity: low - large/complex: 10 branches, 2 loop(s), 1 call; skeleton only */
int nan_dp_alloc_ndl(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2, a3, a4 */
    /* struct offsets touched: 12, 104, 105, 106, 107, 108, 109, 588, 592 */
    /* immediates: 0, 0x244, 1, 104, 6, 0x24c */
    /* branches: +0x15 bgeui->0x81; +0x21 j->0x1E [loop]; +0x29 bnez->0x7A; +0x2f bnez->0x7A; +0x35 bnez->0x7A; +0x3b bnez->0x7A; +0x41 bnez.n->0x7A; +0x46 bnez.n->0x7A; +0x7f j->0x81; +0x84 bnei->0x1C [loop] */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    memcpy(0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_dp_delete_peer @ ieee80211_nan_datapath.o 00000034 size 347B bind GLOBAL
 * Calls: wifi_log, nan_clear_peer_integrity_keys, nan_dp_clear_tmp_data[+0x8][local], nan_dp_remove_node, ic_ebuf_recycle_tx, nan_set_update_sdf_pending, memset | Data refs: .rodata_wlog_debug.13, s_dp, s_dp+0x51c, g_osi_funcs_p, s_dp+0x508
 * Fidelity: low - large/complex: 13 branches, 12 loop(s), 7 calls; skeleton only */
int nan_dp_delete_peer(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,48; early arg regs: a2, a3 */
    /* struct offsets touched: 8, 12, 40, 48, 56, 64, 92, 100, 176, 236, 252, 284, 484, 488 */
    /* immediates: 1, 4, 0, -1, 0x1e4, 0x101, 0x244 */
    /* branches: +0x37 beqz->0x159; +0x7c beqz->0x57 [loop]; +0x91 beqz.n->0x68 [loop]; +0xa2 bnez.n->0x9D [loop]; +0xb3 j->0x98 [loop]; +0xba bnez.n->0x8A [loop]; +0xce bnez->0x82 [loop]; +0xee j->0xD6 [loop]; +0xf6 bnez.n->0xC9 [loop]; +0x10d bnez->0xBD [loop] (+3 more) */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    wifi_log(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_clear_peer_integrity_keys(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_dp_clear_tmp_data(0, 0, 0, 0, 0, 0);  /* ordered call[+0x8] [local] */
    nan_dp_remove_node(0, 0, 0, 0, 0, 0);  /* ordered call */
    ic_ebuf_recycle_tx(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_set_update_sdf_pending(0, 0, 0, 0, 0, 0);  /* ordered call */
    memset(0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_dp_setup_peer @ ieee80211_nan_datapath.o 00000024 size 142B bind GLOBAL
 * Calls: ieee80211_setup_rates, ieee80211_ht_node_init, ieee80211_ht_updatehtcap, ieee80211_setup_htrates, ieee80211_setup_phy_mode, nan_dp_clear_tmp_data[+0x8][local], cnx_rc_update_rssi, nan_ndp_start_inactivity_timer | Data refs: g_ic
 * Fidelity: medium - small frame, 8 calls + 5 branch(es) mapped */
int nan_dp_setup_peer(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2, a3, a4 */
    /* struct offsets touched: 12, 36, 288, 344, 516, 520, 524, 672 */
    /* immediates: 0, 66, 1, 2 */
    /* branches: +0x33 bnez.n->0x14 [loop]; +0x35 beqz->0x1E [loop]; +0x45 beqz.n->0x5A; +0x4a bbci->0x5A; +0x7b j->0x5C [loop] */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    ieee80211_setup_rates(0, 0, 0, 0, 0, 0);  /* ordered call */
    ieee80211_ht_node_init(0, 0, 0, 0, 0, 0);  /* ordered call */
    ieee80211_ht_updatehtcap(0, 0, 0, 0, 0, 0);  /* ordered call */
    ieee80211_setup_htrates(0, 0, 0, 0, 0, 0);  /* ordered call */
    ieee80211_setup_phy_mode(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_dp_clear_tmp_data(0, 0, 0, 0, 0, 0);  /* ordered call[+0x8] [local] */
    cnx_rc_update_rssi(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_ndp_start_inactivity_timer(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_dp_confirm_peer @ ieee80211_nan_datapath.o 00000020 size 132B bind GLOBAL
 * Calls: wifi_log, nan_dp_alloc_node, nan_sched_allocate_crbs, nan_dp_setup_peer, nan_call_ndp_confirm_cb | Data refs: .rodata_wlog_info.14, g_ic, s_dp+0x6, s_dp
 * Fidelity: medium - small frame, 5 calls + 1 branch(es) mapped */
int nan_dp_confirm_peer(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,48; early arg regs: a3, a5 */
    /* struct offsets touched: 32, 48, 152, 284, 564, 672 */
    /* immediates: 1, 3, 0x101, 5, 0x228, 0 */
    /* branches: +0x48 beqz->0x7D */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    wifi_log(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_dp_alloc_node(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_sched_allocate_crbs(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_dp_setup_peer(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_call_ndp_confirm_cb(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_dp_construct_device_caps @ ieee80211_nan_datapath.o 00000000 size 97B bind GLOBAL
 * Calls: none | Data refs: none
 * Fidelity: medium - small frame, 0 calls + 0 branch(es) mapped */
int nan_dp_construct_device_caps(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2, a3 */
    /* struct offsets touched: 8, 9, 10, 11 */
    /* immediates: 15, -8, 9, 0, 1, -4, 4, 17, 12 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_dp_post_tx @ ieee80211_nan_datapath.o 00000024 size 264B bind GLOBAL
 * Calls: nan_sched_in_ndc_slot, nan_sched_is_peer_available, wifi_log, ppTxPkt, ic_ebuf_recycle_tx | Data refs: s_dp, .rodata_wlog_debug.15, .rodata_wlog_debug.16
 * Fidelity: low - large/complex: 15 branches, 3 loop(s), 5 calls; skeleton only */
int nan_dp_post_tx(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,48; early arg regs: a2, a3, a4, a5 */
    /* struct offsets touched: 8, 9, 12, 40, 388, 968 */
    /* immediates: 40, 1, 4, 104, 0x250, 0 */
    /* branches: +0x33 beqz.n->0x37; +0x3b beqz->0xFC; +0x44 bnez->0xE4; +0x58 j->0x104; +0x5b beqz.n->0x4D [loop]; +0x63 beq->0x78; +0x6b bne->0xA0; +0x6e j->0x76; +0x97 j->0xBF; +0xbc bnez->0xE4 (+5 more) */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    nan_sched_in_ndc_slot(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_sched_is_peer_available(0, 0, 0, 0, 0, 0);  /* ordered call */
    wifi_log(0, 0, 0, 0, 0, 0);  /* ordered call */
    ppTxPkt(0, 0, 0, 0, 0, 0);  /* ordered call */
    ic_ebuf_recycle_tx(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_ndp_setup_timeout_process @ ieee80211_nan_datapath.o 0000001c size 118B bind GLOBAL
 * Calls: wifi_log, nan_call_ndp_confirm_cb, nan_dp_delete_peer | Data refs: .rodata_wlog_debug.18, .rodata_wlog_debug.19, s_dp+0x6
 * Fidelity: medium - small frame, 3 calls + 2 branch(es) mapped */
int nan_ndp_setup_timeout_process(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,48; early arg regs: a2 */
    /* struct offsets touched: 8, 9, 12 */
    /* immediates: 1, 4, 0x228, 0, 2, 11 */
    /* branches: +0x27 bnez.n->0x20 [loop]; +0x38 j->0x74 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    wifi_log(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_call_ndp_confirm_cb(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_dp_delete_peer(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_construct_ndp_confirm @ ieee80211_nan_datapath.o 00000044 size 620B bind GLOBAL
 * Calls: nan_dp_get_peer_ndp, nan_dp_get_peer_ndl, wifi_log | Data refs: NAN_ACTION_OUI, .rodata_wlog_error.20, .rodata_wlog_error.21, .rodata_wlog_debug.22, g_nan_secure_dp_funcs, .rodata_wlog_error.23, .rodata_wlog_error.24, .rodata_wlog_error.25
 * Fidelity: low - large/complex: 26 branches, 21 loop(s), 3 calls; skeleton only */
int nan_construct_ndp_confirm(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,96; early arg regs: a3, a4, a5, a6, a7 */
    /* struct offsets touched: 8, 9, 10, 11, 12, 16, 19, 20, 22, 32, 44, 48, 52, 56 */
    /* immediates: 4, 9, 7, 0, 32, 1, 8, 16, -16, 41, 11, 2 */
    /* branches: +0x5b bbci->0x1C [loop]; +0xca beqz.n->0xB9 [loop]; +0xf9 j->0x228; +0xfd bnez.n->0xEF [loop]; +0x130 j->0x228; +0x179 bnei->0x14C [loop]; +0x18d j->0x199; +0x190 beqz->0x190 [loop]; +0x19c beqz.n->0x168 [loop]; +0x1a9 j->0x16F [loop] (+16 more) */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    nan_dp_get_peer_ndp(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_dp_get_peer_ndl(0, 0, 0, 0, 0, 0);  /* ordered call */
    wifi_log(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_construct_ndp_terminate @ ieee80211_nan_datapath.o 00000010 size 174B bind GLOBAL
 * Calls: nan_dp_get_peer_ndp, wifi_log | Data refs: NAN_ACTION_OUI, .rodata_wlog_error.26
 * Fidelity: medium - small frame, 2 calls + 3 branch(es) mapped */
int nan_construct_ndp_terminate(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a3, a4, a5 */
    /* struct offsets touched: 8, 9, 10, 11, 19, 22, 44 */
    /* immediates: 4, 9, 7, 11, 16, 0, -16, 28, 1 */
    /* branches: +0x1f bbci->0x14 [loop]; +0x7a beq->0x76 [loop]; +0xa5 beq->0xAC */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    nan_dp_get_peer_ndp(0, 0, 0, 0, 0, 0);  /* ordered call */
    wifi_log(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_construct_ndp_resp @ ieee80211_nan_datapath.o 00000094 size 1726B bind GLOBAL
 * Calls: nan_dp_get_peer_ndl, wifi_log, nan_dp_get_peer_ndp, nan_dp_construct_device_caps, memcpy, nan_sched_construct_availability, ieee80211_add_htcap, nan_get_service_by_id | Data refs: g_ic, NAN_ACTION_OUI, .rodata_wlog_warning.27, .rodata_wlog_warning.28, .rodata_wlog_info.29, s_dp, NAN_STANDARD_BSSID, .rodata_wlog_warning.30, .rodata_wlog_info.31, g_nan_secure_dp_funcs, .rodata_wlog_error.32, .rodata_wlog_info.33, s_dp+0x6
 * Fidelity: low - large/complex: 61 branches, 52 loop(s), 8 calls; skeleton only */
int nan_construct_ndp_resp(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,128; early arg regs: a2, a3, a4, a5, a6, a7 */
    /* struct offsets touched: 8, 9, 10, 11, 12, 13, 16, 20, 21, 22, 24, 28, 32, 36 */
    /* immediates: 4, 9, 7, 0, 6, 32, 1, 2, -1, 3, 0x128, 20 */
    /* branches: +0xb8 bbci->0x2A [loop]; +0x11c bnei->0x8E [loop]; +0x11f j->0x139; +0x130 beq->0xD3 [loop]; +0x164 j->0x114 [loop]; +0x178 bnez.n->0x11A [loop]; +0x1aa j->0x6BC; +0x1d3 beq->0x170 [loop]; +0x1dc bne->0x15A [loop]; +0x1e4 bne->0x15C [loop] (+51 more) */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    nan_dp_get_peer_ndl(0, 0, 0, 0, 0, 0);  /* ordered call */
    wifi_log(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_dp_get_peer_ndp(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_dp_construct_device_caps(0, 0, 0, 0, 0, 0);  /* ordered call */
    memcpy(0, 0, 0);  /* ordered call */
    nan_sched_construct_availability(0, 0, 0, 0, 0, 0);  /* ordered call */
    ieee80211_add_htcap(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_get_service_by_id(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_construct_ndp_req @ ieee80211_nan_datapath.o 0000007c size 1071B bind GLOBAL
 * Calls: nan_dp_get_peer_ndp, wifi_log, nan_dp_construct_device_caps, memcpy, nan_get_service_by_index, nan_get_peer_svc_record, nan_sched_construct_availability, nan_dp_get_peer_ndl, ieee80211_add_htcap | Data refs: g_ic, .rodata_wlog_error.34, NAN_ACTION_OUI, s_dp, .rodata_wlog_debug.35, g_nan_secure_dp_funcs, .rodata_wlog_error.36, .rodata_wlog_debug.37, .rodata_wlog_debug.38, .rodata_wlog_error.39, .rodata_wlog_error.40
 * Fidelity: low - large/complex: 28 branches, 22 loop(s), 9 calls; skeleton only */
int nan_construct_ndp_req(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,112; early arg regs: a2, a3, a4, a5, a7 */
    /* struct offsets touched: 8, 9, 10, 12, 13, 14, 15, 16, 17, 20, 22, 28, 32, 36 */
    /* immediates: 4, 7, 1, 9, 5, 6, 41, 0, 8, -38, 37, 23 */
    /* branches: +0x93 bbci->0x1D [loop]; +0xc1 bnez.n->0x7D [loop]; +0xf4 j->0x42D; +0x14a beqz->0x181; +0x19f beqz.n->0x130 [loop]; +0x1af beqz.n->0x149 [loop]; +0x1fa j->0x204; +0x250 beqz.n->0x1E1 [loop]; +0x260 beqz.n->0x1FA [loop]; +0x28e beqz->0x2EC (+18 more) */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    nan_dp_get_peer_ndp(0, 0, 0, 0, 0, 0);  /* ordered call */
    wifi_log(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_dp_construct_device_caps(0, 0, 0, 0, 0, 0);  /* ordered call */
    memcpy(0, 0, 0);  /* ordered call */
    nan_get_service_by_index(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_get_peer_svc_record(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_sched_construct_availability(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_dp_get_peer_ndl(0, 0, 0, 0, 0, 0);  /* ordered call */
    ieee80211_add_htcap(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_send_ndp_confirm @ ieee80211_nan_datapath.o 0000003c size 268B bind GLOBAL
 * Calls: nan_get_clust_id, nan_dp_get_peer_ndp, wifi_log, nan_dp_get_peer_ndl, nan_is_pmf_enabled, nan_alloc_action, nan_construct_ndp_confirm, ic_ebuf_recycle_tx, nan_tx_action_frame | Data refs: g_nan_secure_dp_funcs, .rodata_wlog_debug.41, .rodata_wlog_error.42
 * Fidelity: low - large/complex: 13 branches, 7 loop(s), 9 calls; skeleton only */
int nan_send_ndp_confirm(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,80; early arg regs: a2, a3, a4, a5, a6, a7 */
    /* struct offsets touched: 8, 16, 20, 32, 44, 112, 197 */
    /* immediates: 0, 14, 4, 1, 16, 20, 0x101, -1, 0x500 */
    /* branches: +0x6a beqz.n->0x61 [loop]; +0x6f beqz->0x102; +0x72 bnei->0x3C [loop]; +0x75 j->0x102; +0x7f beqz->0x104; +0x85 beqz->0x104; +0x98 j->0x104; +0xda bnez.n->0xB6 [loop]; +0xef j->0x10A; +0x104 beqz.n->0xD9 [loop] (+3 more) */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    nan_get_clust_id(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_dp_get_peer_ndp(0, 0, 0, 0, 0, 0);  /* ordered call */
    wifi_log(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_dp_get_peer_ndl(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_is_pmf_enabled(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_alloc_action(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_construct_ndp_confirm(0, 0, 0, 0, 0, 0);  /* ordered call */
    ic_ebuf_recycle_tx(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_tx_action_frame(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_send_ndp_terminate @ ieee80211_nan_datapath.o 00000024 size 138B bind GLOBAL
 * Calls: nan_get_clust_id, nan_dp_get_peer_ndl, nan_is_pmf_enabled, nan_alloc_action, wifi_log, nan_construct_ndp_terminate, nan_tx_action_frame | Data refs: .rodata_wlog_error.43
 * Fidelity: medium - small frame, 7 calls + 2 branch(es) mapped */
int nan_send_ndp_terminate(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,48; early arg regs: a2, a3, a4, a5 */
    /* struct offsets touched: 8, 44 */
    /* immediates: 4, 0, 14, 1, 0x101, 0x700 */
    /* branches: +0x5f bne->0x56 [loop]; +0x77 j->0x88 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    nan_get_clust_id(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_dp_get_peer_ndl(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_is_pmf_enabled(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_alloc_action(0, 0, 0, 0, 0, 0);  /* ordered call */
    wifi_log(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_construct_ndp_terminate(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_tx_action_frame(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_construct_ndp_security_key_install @ ieee80211_nan_datapath.o 00000030 size 574B bind GLOBAL
 * Calls: nan_dp_get_peer_ndp, memcpy, wifi_log | Data refs: NAN_ACTION_OUI, .rodata_wlog_error.44, .rodata_wlog_error.45, g_nan_secure_dp_funcs, .rodata_wlog_error.46
 * Fidelity: low - large/complex: 17 branches, 11 loop(s), 3 calls; skeleton only */
int nan_construct_ndp_security_key_install(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,48; early arg regs: a3, a4, a5, a6, a7 */
    /* struct offsets touched: 8, 9, 10, 11, 12, 16, 19, 20, 21, 22, 23, 44, 52, 56 */
    /* immediates: 4, 9, 7, 8, 21, 41, 3, -2, -5, 6, -33, 13 */
    /* branches: +0x4c bbci->0x22 [loop]; +0x91 beqz->0x142; +0xaf beqz->0x15C; +0xc8 bnei->0xA1 [loop]; +0x127 beqz.n->0x128; +0x129 beqz.n->0x128 [loop]; +0x16f j->0x1D1; +0x185 bnez.n->0x16D [loop]; +0x199 j->0x23C; +0x1bb bnei->0x194 [loop] (+7 more) */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    nan_dp_get_peer_ndp(0, 0, 0, 0, 0, 0);  /* ordered call */
    memcpy(0, 0, 0);  /* ordered call */
    wifi_log(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_send_security_key_install @ ieee80211_nan_datapath.o 00000044 size 396B bind GLOBAL
 * Calls: nan_get_clust_id, nan_dp_get_peer_ndl, wifi_log, nan_dp_get_peer_ndp, nan_is_pmf_enabled, nan_alloc_action, nan_construct_ndp_security_key_install, nan_tx_action_frame | Data refs: .rodata_wlog_error.47, .rodata_wlog_error.48, g_nan_secure_dp_funcs, .rodata_wlog_error.49
 * Fidelity: low - large/complex: 11 branches, 9 loop(s), 8 calls; skeleton only */
int nan_send_security_key_install(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,96; early arg regs: a3, a4, a5, a6, a7 */
    /* struct offsets touched: 8, 12, 16, 32, 34, 36, 44, 48, 52, 56, 60, 548, 572 */
    /* immediates: 0, 32, 1, -1, 8, 14, 17, 36, 0x101, 3, 0x228, 0x600 */
    /* branches: +0x74 beq->0x64 [loop]; +0xa4 j->0xA1 [loop]; +0xb2 bnez.n->0xA6 [loop]; +0xe7 j->0x188; +0x100 beqz.n->0xCC [loop]; +0x105 beqz.n->0xCC [loop]; +0x112 bnei->0xE8 [loop]; +0x11a beqz.n->0xE8 [loop]; +0x11e beqz.n->0xE8 [loop]; +0x14e bnez.n->0x125 [loop] (+1 more) */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    nan_get_clust_id(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_dp_get_peer_ndl(0, 0, 0, 0, 0, 0);  /* ordered call */
    wifi_log(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_dp_get_peer_ndp(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_is_pmf_enabled(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_alloc_action(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_construct_ndp_security_key_install(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_tx_action_frame(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_send_ndp_resp @ ieee80211_nan_datapath.o 00000074 size 722B bind GLOBAL
 * Calls: wifi_log, nan_dp_get_peer_ndp, nan_sched_avail_entries_len, nan_get_service_by_id, nan_get_clust_id, nan_is_pmf_enabled, nan_alloc_action, nan_construct_ndp_resp, ic_ebuf_recycle_tx, nan_tx_action_frame, nan_dp_get_peer_ndl, nan_call_ndp_terminated_cb, nan_dp_delete_peer | Data refs: .rodata_wlog_debug.50, g_nan_secure_dp_funcs, .rodata_wlog_warning.51, s_dp, .rodata_wlog_debug.52, .rodata_wlog_debug.53, .rodata_wlog_warning.54, .rodata_wlog_warning.55
 * Fidelity: low - large/complex: 38 branches, 32 loop(s), 13 calls; skeleton only */
int nan_send_ndp_resp(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,112; early arg regs: a3, a4, a5, a6 */
    /* struct offsets touched: 8, 12, 16, 20, 24, 32, 36, 44, 48, 52, 56, 60, 64, 68 */
    /* immediates: 1, 4, 0, 2, 29, 27, 72, 3, -1, 0x238, 56, 36 */
    /* branches: +0xcc bnei->0x5E [loop]; +0xcf j->0xDC; +0xe0 bne->0x79 [loop]; +0xea j->0xDC [loop]; +0xf2 beqz->0x6F [loop]; +0xfa bnez.n->0xC7 [loop]; +0x138 j->0xDC [loop]; +0x13d beqz->0x88 [loop]; +0x148 beqz->0x88 [loop]; +0x14b j->0x6F [loop] (+28 more) */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    wifi_log(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_dp_get_peer_ndp(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_sched_avail_entries_len(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_get_service_by_id(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_get_clust_id(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_is_pmf_enabled(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_alloc_action(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_construct_ndp_resp(0, 0, 0, 0, 0, 0);  /* ordered call */
    ic_ebuf_recycle_tx(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_tx_action_frame(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_dp_get_peer_ndl(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_call_ndp_terminated_cb(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_dp_delete_peer(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_send_ndp_req @ ieee80211_nan_datapath.o 00000034 size 295B bind GLOBAL
 * Calls: nan_sched_avail_entries_len, nan_dp_get_peer_ndp, nan_get_service_by_index, nan_get_peer_svc_record, nan_get_clust_id, nan_is_pmf_enabled, nan_alloc_action, nan_construct_ndp_req, nan_tx_action_frame | Data refs: g_nan_secure_dp_funcs
 * Fidelity: low - large/complex: 11 branches, 8 loop(s), 9 calls; skeleton only */
int nan_send_ndp_req(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,64; early arg regs: a2, a3, a4, a6, a7 */
    /* struct offsets touched: 8, 12, 16, 20, 44, 197, 204, 336 */
    /* immediates: 34, 45, 44, 0, 1, -1, 0x300 */
    /* branches: +0x5c beqz->0xC4; +0x62 beqz->0xC4; +0x82 bnez.n->0x6D [loop]; +0x9e beq->0x70 [loop]; +0xab beq->0x89 [loop]; +0xb1 beq->0x89 [loop]; +0xc4 beq->0xA1 [loop]; +0xc9 beq->0xA1 [loop]; +0xdc beq->0xBC [loop]; +0xe2 beq->0xBC [loop] (+1 more) */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    nan_sched_avail_entries_len(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_dp_get_peer_ndp(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_get_service_by_index(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_get_peer_svc_record(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_get_clust_id(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_is_pmf_enabled(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_alloc_action(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_construct_ndp_req(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_tx_action_frame(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_dp_parse_ndpa @ ieee80211_nan_datapath.o 00000054 size 721B bind GLOBAL
 * Calls: nan_dp_alloc_ndp, memcpy, wifi_log, nan_dp_get_peer_ndp | Data refs: .rodata_wlog_error.56, .rodata_wlog_error.57, .rodata_wlog_error.58, .rodata_wlog_error.59, .rodata_wlog_error.60, .rodata_wlog_error.61, g_osi_funcs_p, .rodata_wlog_error.62
 * Fidelity: low - large/complex: 49 branches, 28 loop(s), 4 calls; skeleton only */
int nan_dp_parse_ndpa(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,64; early arg regs: a3, a4, a5, a6, a7 */
    /* struct offsets touched: 9, 10, 12, 13, 14, 16, 20, 24, 28, 48, 176, 197, 376, 564 */
    /* immediates: 0, 14, -11, 1, 6, 3, -12, 15, -16, 20, -17, -6 */
    /* branches: +0x8a bnez->0xA8; +0x9d beqz.n->0x4E [loop]; +0x9f j->0xC6; +0xbf beqz.n->0x84 [loop]; +0xc4 beqz->0x142; +0xda beqz.n->0x90 [loop]; +0xe7 bbsi->0x99 [loop]; +0xea j->0x16D; +0xf8 j->0x16D; +0xfc bnei->0x121 (+39 more) */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    nan_dp_alloc_ndp(0, 0, 0, 0, 0, 0);  /* ordered call */
    memcpy(0, 0, 0);  /* ordered call */
    wifi_log(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_dp_get_peer_ndp(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_dp_parse_ndla @ ieee80211_nan_datapath.o 00000004 size 41B bind GLOBAL
 * Calls: nan_dp_alloc_ndl | Data refs: none
 * Fidelity: high - trivial: straight-line, all targets resolved */
int nan_dp_parse_ndla(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2, a3 */
    /* struct offsets touched: 33, 36 */
    /* immediates: 1 */
    /* branches: +0x10 beqz.n->0x22 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    nan_dp_alloc_ndl(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_dp_parse_elem_container @ ieee80211_nan_datapath.o 00000014 size 308B bind GLOBAL
 * Calls: wifi_log, memcpy | Data refs: .rodata_wlog_debug.63, g_osi_funcs_p
 * Fidelity: low - large/complex: 24 branches, 10 loop(s), 2 calls; skeleton only */
int nan_dp_parse_elem_container(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a3, a4, a5, a6 */
    /* struct offsets touched: 176, 376, 516, 520, 524, 532, 536 */
    /* immediates: 4, -1, 50, 2, 1, 45, 221, 255, 0 */
    /* branches: +0x2b j->0x127; +0x39 bgeu->0x3C; +0x4c j->0x130; +0x50 beq->0x85; +0x53 bltu->0x4D [loop]; +0x56 beqi->0x60; +0x5b beq->0xA9; +0x5e j->0x120; +0x64 beq->0xCD; +0x6a bne->0x5C [loop] (+14 more) */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    wifi_log(0, 0, 0, 0, 0, 0);  /* ordered call */
    memcpy(0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_dp_parse_dev_caps @ ieee80211_nan_datapath.o 00000000 size 53B bind GLOBAL
 * Calls: none | Data refs: none
 * Fidelity: medium - small frame, 0 calls + 1 branch(es) mapped */
int nan_dp_parse_dev_caps(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2, a3 */
    /* struct offsets touched: 11, 240, 548 */
    /* immediates: -1, 0 */
    /* branches: +0xa bbci->0x30 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_dp_chan_from_bitmap @ ieee80211_nan_datapath.o 00000000 size 57B bind GLOBAL
 * Calls: none | Data refs: none
 * Fidelity: medium - small frame, 0 calls + 3 branch(es) mapped */
int nan_dp_chan_from_bitmap(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2, a3, a4 */
    /* immediates: 0, 1, 32, -1 */
    /* branches: +0xb j->0x2F; +0x2f beqz.n->0x34; +0x31 bltu->0xE [loop] */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_dp_parse_time_bitmap @ ieee80211_nan_datapath.o 0000001c size 356B bind GLOBAL
 * Calls: wifi_log | Data refs: .rodata_wlog_error.64, .rodata_wlog_error.65, .rodata_wlog_warning.66
 * Fidelity: low - large/complex: 19 branches, 10 loop(s), 1 call; skeleton only */
int nan_dp_parse_time_bitmap(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,64; early arg regs: a2, a4, a5, a6 */
    /* struct offsets touched: 16, 20, 24 */
    /* immediates: 1, 64, 16, 0, 32, -1, 2, 3, 8 */
    /* branches: +0x2e bltui->0x28 [loop]; +0x41 j->0x58; +0x51 beq->0x5D; +0x56 beqz.n->0x5D; +0x63 bgeu->0x5D [loop]; +0x76 j->0x162; +0xa3 j->0xE2; +0xad bgeu->0xA8 [loop]; +0xc6 bgeu->0xC1 [loop]; +0xdd beq->0xE0 (+9 more) */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    wifi_log(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_dp_parse_ndca @ ieee80211_nan_datapath.o 00000014 size 72B bind GLOBAL
 * Calls: memcpy, nan_dp_parse_time_bitmap, wifi_log | Data refs: .rodata_wlog_debug.67
 * Fidelity: medium - small frame, 3 calls + 0 branch(es) mapped */
int nan_dp_parse_ndca(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2, a3 */
    /* struct offsets touched: 8, 10, 13 */
    /* immediates: 3, 6, 14, 1, 11, 4 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    memcpy(0, 0, 0);  /* ordered call */
    nan_dp_parse_time_bitmap(0, 0, 0, 0, 0, 0);  /* ordered call */
    wifi_log(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_sched_parse_avail_entries @ ieee80211_nan_datapath.o 00000018 size 419B bind GLOBAL
 * Calls: memset, nan_dp_parse_time_bitmap, nan_dp_chan_from_bitmap, memcpy | Data refs: g_def_2g_channels
 * Fidelity: low - large/complex: 30 branches, 12 loop(s), 4 calls; skeleton only */
int nan_sched_parse_avail_entries(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,80; early arg regs: a3, a4, a5 */
    /* struct offsets touched: 17, 20, 24, 32 */
    /* immediates: 28, 0, 2, 4, 7, -1, 3, 1, 81, 13, 14, 11 */
    /* branches: +0x49 bbci->0x59; +0x4e bgeu->0x3C [loop]; +0x51 j->0x1A1; +0x59 bgeu->0x47 [loop]; +0x5c j->0x1A1; +0x6e j->0x5B [loop]; +0x7f bgeu->0x6D [loop]; +0x82 j->0x1A1; +0x90 beqz->0x121; +0x9d j->0xD5 (+20 more) */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    memset(0, 0, 0);  /* ordered call */
    nan_dp_parse_time_bitmap(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_dp_chan_from_bitmap(0, 0, 0, 0, 0, 0);  /* ordered call */
    memcpy(0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_dp_parse_availability @ ieee80211_nan_datapath.o 00000070 size 948B bind GLOBAL
 * Calls: wifi_log, nan_sched_parse_avail_entries, memcpy, memset, chm_get_home_channel, nan_sched_alloc_time_slots | Data refs: .rodata_wlog_error.68, .rodata_wlog_error.69, .rodata_wlog_error.70, s_dp, s_dp+0x2c, .rodata_wlog_debug.71, .rodata_wlog_error.72, .rodata_wlog_error.73, .rodata_wlog_error.74, .rodata_wlog_error.75, .rodata_wlog_debug.76
 * Fidelity: low - large/complex: 39 branches, 30 loop(s), 6 calls; skeleton only */
int nan_dp_parse_availability(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,80; early arg regs: a4, a5, a6 */
    /* struct offsets touched: 12, 13, 16, 32, 33, 36, 40, 44, 45, 46, 47, 61, 64, 68 */
    /* immediates: 0x128, 6, -3, 0x129, 0x148, 0x12c, 72, 1, 4, 2, 0x106, 28 */
    /* branches: +0xdb j->0x10B; +0xed bgeui->0x94 [loop]; +0x100 j->0x111; +0x106 blt->0xAC [loop]; +0x119 j->0x111 [loop]; +0x124 bnone->0xC0 [loop]; +0x12b j->0xC7 [loop]; +0x130 bbci->0xDB [loop]; +0x148 j->0xF8 [loop]; +0x14e bnei->0xF8 [loop] (+29 more) */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    wifi_log(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_sched_parse_avail_entries(0, 0, 0, 0, 0, 0);  /* ordered call */
    memcpy(0, 0, 0);  /* ordered call */
    memset(0, 0, 0);  /* ordered call */
    chm_get_home_channel(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_sched_alloc_time_slots(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_parse_ndp_req @ ieee80211_nan_datapath.o 00000094 size 947B bind GLOBAL
 * Calls: nan_dp_get_peer_ndl, wifi_log, nan_call_ndp_terminated_cb, nan_dp_delete_peer, nan_dp_node_available, nan_dp_parse_ndla, nan_dp_parse_ndpa, nan_get_service_by_id, nan_dp_parse_dev_caps, nan_dp_parse_availability, nan_dp_parse_ndca, nan_dp_parse_elem_container, nan_call_ndp_indication_cb, nan_send_ndp_resp | Data refs: .rodata_wlog_error.77, .rodata_wlog_debug.78, .rodata_wlog_info.79, .rodata_wlog_error.80, .rodata_wlog_error.81, .rodata_wlog_debug.82, .rodata_wlog_debug.83, .rodata_wlog_debug.84, g_nan_secure_dp_funcs, .rodata_wlog_debug.85, .rodata_wlog_error.86, .text.nan_ndp_setup_timeout, s_dp+0x508, g_osi_funcs_p, s_dp
 * Fidelity: low - large/complex: 54 branches, 44 loop(s), 14 calls; skeleton only */
int nan_parse_ndp_req(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,112; early arg regs: a3, a4, a5, a6, a7 */
    /* struct offsets touched: 8, 9, 10, 11, 12, 16, 20, 28, 32, 33, 36, 40, 44, 48 */
    /* immediates: 0, 1, 32, 4, 3, 11, 0x105, 8, 28, 20, 0x110, 200 */
    /* branches: +0x9d bne->0x10 [loop]; +0xa2 beqz.n->0x1C [loop]; +0xa6 beqz.n->0x1C [loop]; +0xaa beqz.n->0x1C [loop]; +0xae bnez.n->0x2D [loop]; +0xbd j->0x56 [loop]; +0xc1 bnez.n->0x31 [loop]; +0xd0 bnez->0xC4 [loop]; +0xdb beqz->0x3A8; +0xf0 j->0x3B1 (+44 more) */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    nan_dp_get_peer_ndl(0, 0, 0, 0, 0, 0);  /* ordered call */
    wifi_log(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_call_ndp_terminated_cb(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_dp_delete_peer(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_dp_node_available(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_dp_parse_ndla(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_dp_parse_ndpa(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_get_service_by_id(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_dp_parse_dev_caps(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_dp_parse_availability(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_dp_parse_ndca(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_dp_parse_elem_container(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_call_ndp_indication_cb(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_send_ndp_resp(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_parse_ndp_resp @ ieee80211_nan_datapath.o 000000d8 size 1084B bind GLOBAL
 * Calls: nan_dp_get_peer_ndl, wifi_log, nan_dp_parse_ndpa, memcpy, nan_dp_node_available, nan_dp_parse_availability, nan_dp_parse_elem_container, nan_call_ndp_response_indication_cb, nan_send_ndp_confirm, nan_dp_confirm_peer, nan_call_ndp_confirm_cb, nan_dp_delete_peer | Data refs: .rodata.nan_parse_ndp_resp.str1.1, .rodata, .rodata_wlog_debug.87, .rodata_wlog_error.88, .rodata_wlog_error.89, .rodata_wlog_error.90, .rodata_wlog_warning.91, .rodata_wlog_debug.92, .rodata_wlog_debug.93, g_nan_secure_dp_funcs, .rodata_wlog_debug.94, .rodata_wlog_error.97, .rodata_wlog_debug.95, .rodata_wlog_debug.96, .rodata_wlog_debug.98, .rodata_wlog_debug.99, .rodata_wlog_error.100, .rodata_wlog_info.101, .rodata_wlog_debug.102, s_dp+0x508, g_osi_funcs_p, s_dp+0x6, s_dp
 * Fidelity: low - large/complex: 58 branches, 45 loop(s), 12 calls; skeleton only */
int nan_parse_ndp_resp(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,96; early arg regs: a3, a5, a6, a7 */
    /* struct offsets touched: 8, 10, 11, 12, 13, 16, 20, 28, 32, 36, 38, 39, 40, 42 */
    /* immediates: 0, 44, 4, 1, 6, 14, 38, 8, 240, 2, 200, 3 */
    /* branches: +0xfe bne->0x2E [loop]; +0x103 beqz->0x43A; +0x108 beqz->0x43A; +0x10d beqz->0x43A; +0x120 bnez->0x43A; +0x12b bnez->0x5C [loop]; +0x131 beqz->0x70 [loop]; +0x144 j->0x43A; +0x14c bnez->0x42D; +0x152 j->0x96 [loop] (+48 more) */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    nan_dp_get_peer_ndl(0, 0, 0, 0, 0, 0);  /* ordered call */
    wifi_log(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_dp_parse_ndpa(0, 0, 0, 0, 0, 0);  /* ordered call */
    memcpy(0, 0, 0);  /* ordered call */
    nan_dp_node_available(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_dp_parse_availability(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_dp_parse_elem_container(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_call_ndp_response_indication_cb(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_send_ndp_confirm(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_dp_confirm_peer(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_call_ndp_confirm_cb(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_dp_delete_peer(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_parse_ndp_confirm @ ieee80211_nan_datapath.o 000000e0 size 934B bind GLOBAL
 * Calls: nan_dp_get_peer_ndl, wifi_log, nan_dp_node_available, nan_dp_confirm_peer, nan_dp_get_peer_ndp, nan_send_security_key_install, nan_dp_parse_ndpa, nan_dp_delete_peer, nan_call_ndp_confirm_cb | Data refs: .rodata_wlog_error.103, .rodata_wlog_error.104, .rodata_wlog_error.105, .rodata_wlog_error.106, .rodata_wlog_error.107, .rodata_wlog_debug.108, .rodata_wlog_error.109, .rodata_wlog_debug.110, g_nan_secure_dp_funcs, .rodata_wlog_debug.111, .rodata_wlog_error.112, .rodata_wlog_info.113, s_dp+0x508, g_osi_funcs_p, .rodata_wlog_warning.114, .rodata_wlog_error.115, .rodata_wlog_error.116, .rodata_wlog_error.117, .rodata_wlog_error.118, .rodata_wlog_error.119, .rodata_wlog_error.120, .rodata_wlog_debug.121, .rodata_wlog_debug.122, .rodata_wlog_error.123, .rodata_wlog_info.124, .rodata_wlog_error.125, .rodata_wlog_error.126, .rodata_wlog_warning.127, .rodata_wlog_error.128, s_dp+0x6, s_dp
 * Fidelity: low - large/complex: 60 branches, 44 loop(s), 9 calls; skeleton only */
int nan_parse_ndp_confirm(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,80; early arg regs: a3, a5, a6, a7 */
    /* struct offsets touched: 9, 10, 12, 16, 28, 32, 36, 44, 48, 52, 80, 96, 197, 205 */
    /* immediates: 16, 1, 8, 4, -16, 3, 2, 240, 0, 0x228 */
    /* branches: +0xe5 bnez->0x19D; +0xea bnez->0x19D; +0xf0 beqz->0x1C [loop]; +0xf9 beqi->0x25 [loop]; +0xff j->0x35 [loop]; +0x110 beqz.n->0x45 [loop]; +0x122 j->0x3A4; +0x12c bnez.n->0x59 [loop]; +0x136 j->0x31A; +0x13f bnez->0x35 [loop] (+50 more) */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    nan_dp_get_peer_ndl(0, 0, 0, 0, 0, 0);  /* ordered call */
    wifi_log(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_dp_node_available(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_dp_confirm_peer(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_dp_get_peer_ndp(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_send_security_key_install(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_dp_parse_ndpa(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_dp_delete_peer(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_call_ndp_confirm_cb(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_parse_ndp_security_install @ ieee80211_nan_datapath.o 00000098 size 639B bind GLOBAL
 * Calls: wifi_log, nan_dp_get_peer_ndl, nan_dp_get_peer_ndp, nan_dp_confirm_peer, nan_call_ndp_confirm_cb, nan_dp_delete_peer | Data refs: .rodata.nan_parse_ndp_resp.str1.1, .rodata_wlog_error.129, .rodata_wlog_debug.130, .rodata_wlog_error.131, .rodata_wlog_error.132, .rodata_wlog_debug.133, .rodata_wlog_warning.134, s_dp+0x6, .rodata_wlog_error.135, g_nan_secure_dp_funcs, .rodata_wlog_debug.136, .rodata_wlog_debug.137, .rodata_wlog_debug.138, .rodata_wlog_error.139, .rodata_wlog_debug.140, s_dp+0x508, g_osi_funcs_p, .rodata_wlog_info.141, s_dp
 * Fidelity: low - large/complex: 22 branches, 17 loop(s), 6 calls; skeleton only */
int nan_parse_ndp_security_install(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,96; early arg regs: a3, a4, a5, a7 */
    /* struct offsets touched: 8, 12, 16, 20, 24, 32, 44, 48, 52, 84, 96, 197, 236, 288 */
    /* immediates: 0, 1, 4, 32, 240, 2, 0x228, 3, -1 */
    /* branches: +0xa6 bne->0x2D [loop]; +0xab bne->0x2D [loop]; +0xc0 j->0x27D; +0x10a beqz.n->0xA4 [loop]; +0x138 j->0x27D; +0x14b bnez.n->0xCC [loop]; +0x160 j->0x27D; +0x191 bnei->0x129 [loop]; +0x1be j->0x263; +0x1c4 beqz->0x134 [loop] (+12 more) */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    wifi_log(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_dp_get_peer_ndl(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_dp_get_peer_ndp(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_dp_confirm_peer(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_call_ndp_confirm_cb(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_dp_delete_peer(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_parse_ndp_terminate @ ieee80211_nan_datapath.o 00000010 size 66B bind GLOBAL
 * Calls: nan_dp_get_peer_ndl, nan_dp_get_peer_ndp, nan_call_ndp_terminated_cb, nan_dp_delete_peer | Data refs: none
 * Fidelity: medium - small frame, 4 calls + 4 branch(es) mapped */
int nan_parse_ndp_terminate(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,48; early arg regs: a2, a3, a4 */
    /* struct offsets touched: 12 */
    /* branches: +0x16 bnez->0xE [loop]; +0x1c beqz.n->0x40; +0x2b bnez.n->0x40; +0x39 beqz.n->0x40 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    nan_dp_get_peer_ndl(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_dp_get_peer_ndp(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_call_ndp_terminated_cb(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_dp_delete_peer(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_dp_get_attr @ ieee80211_nan_datapath.o 00000000 size 44B bind GLOBAL
 * Calls: none | Data refs: none
 * Fidelity: medium - small frame, 0 calls + 4 branch(es) mapped */
int nan_dp_get_attr(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2, a4 */
    /* immediates: 3, 0 */
    /* branches: +0x6 j->0x22; +0x17 bltu->0x28; +0x1d beq->0x2A; +0x25 bgeui->0x9 [loop] */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_rx_naf @ ieee80211_nan_datapath.o 0000004c size 436B bind GLOBAL
 * Calls: nan_get_clust_id, memcmp, memset, wifi_log, nan_parse_ndp_req, nan_parse_ndp_resp, nan_parse_ndp_confirm, nan_parse_ndp_terminate, nan_parse_ndp_security_install, ic_ebuf_recycle_rx | Data refs: .rodata_wlog_error.142, .rodata_wlog_error.143, .rodata.nan_rx_naf, .rodata_wlog_debug.144, .rodata_wlog_error.145
 * Fidelity: low - large/complex: 29 branches, 15 loop(s), 10 calls; skeleton only */
int nan_rx_naf(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,112; early arg regs: a2, a3, a5, a6, a7 */
    /* struct offsets touched: 8, 16, 20, 22, 28, 30, 32, 36, 40, 44, 48, 52, 64, 68 */
    /* immediates: 6, 16, 24, 56, 31, 3, 1, -11, 30, 4, -5, 8 */
    /* branches: +0x64 bnez->0x1B2; +0x8e bgei->0x48 [loop]; +0x91 j->0x19D; +0x9f j->0x128; +0xb3 bnez.n->0x6C [loop]; +0xb5 beqz->0x134; +0xba bgeu->0x84 [loop]; +0xcd j->0x134; +0xd8 bltu->0xFD; +0xeb j->0x118 (+19 more) */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    nan_get_clust_id(0, 0, 0, 0, 0, 0);  /* ordered call */
    memcmp(0, 0, 0);  /* ordered call */
    memset(0, 0, 0);  /* ordered call */
    wifi_log(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_parse_ndp_req(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_parse_ndp_resp(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_parse_ndp_confirm(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_parse_ndp_terminate(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_parse_ndp_security_install(0, 0, 0, 0, 0, 0);  /* ordered call */
    ic_ebuf_recycle_rx(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_naf_txcb @ ieee80211_nan_datapath.o 000000a8 size 835B bind GLOBAL
 * Calls: nan_dp_get_peer_ndl, wifi_log, nan_send_ndp_req, nan_dp_confirm_peer, nan_send_ndp_resp, nan_call_ndp_confirm_cb, nan_send_ndp_confirm, nan_send_security_key_install, nan_send_ndp_terminate, nan_call_ndp_terminated_cb, nan_dp_delete_peer | Data refs: .rodata_wlog_error.146, .rodata.nan_naf_txcb, .rodata_wlog_info.147, g_nan_secure_dp_funcs, .rodata_wlog_debug.148, s_dp+0x51c, .rodata_wlog_error.149, .rodata_wlog_debug.150, s_dp+0x508, g_osi_funcs_p, s_dp+0x6, .rodata_wlog_debug.151, .rodata_wlog_debug.152, .rodata_wlog_debug.153, .rodata_wlog_error.154, .rodata_wlog_debug.155, .rodata_wlog_error.156, .rodata_wlog_error.157, s_dp
 * Fidelity: low - large/complex: 57 branches, 41 loop(s), 11 calls; skeleton only */
int nan_naf_txcb(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,96; early arg regs: a2, a3, a4, a5, a6 */
    /* struct offsets touched: 8, 9, 12, 16, 18, 19, 32, 33, 34, 44, 48, 52, 56, 205 */
    /* immediates: 0, 32, 4, 8, -1, 1, 125, 3, 2, 0x228, 11 */
    /* branches: +0xd6 bne->0x34 [loop]; +0xd9 j->0x334; +0xe5 beqi->0x5E [loop]; +0xee beqz.n->0x5A [loop]; +0xff j->0x5E [loop]; +0x10c bltui->0x6A [loop]; +0x10f j->0x331; +0x120 beqz->0xBD [loop]; +0x156 beqz->0x341; +0x15f bnez->0x10D [loop] (+47 more) */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    nan_dp_get_peer_ndl(0, 0, 0, 0, 0, 0);  /* ordered call */
    wifi_log(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_send_ndp_req(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_dp_confirm_peer(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_send_ndp_resp(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_call_ndp_confirm_cb(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_send_ndp_confirm(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_send_security_key_install(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_send_ndp_terminate(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_call_ndp_terminated_cb(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_dp_delete_peer(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_datapath_send_req @ ieee80211_nan_datapath.o 0000008c size 700B bind GLOBAL
 * Calls: nan_dp_get_peer_ndl, nan_dp_node_available, wifi_log, nan_dp_alloc_ndl, nan_dp_alloc_ndp, nan_get_service_by_index, nan_get_peer_svc_record, nan_sched_alloc_conditional, memcpy, nan_send_ndp_req, nan_dp_delete_peer | Data refs: .rodata_wlog_error.158, .rodata_wlog_error.159, .rodata_wlog_error.160, s_ndp_id, .rodata_wlog_error.161, g_nan_secure_dp_funcs, .rodata_wlog_debug.162, .rodata_wlog_warning.163, .rodata_wlog_error.164, .rodata_wlog_error.165, s_dp, .rodata_wlog_error.166, .text.nan_ndp_setup_timeout, s_dp+0x508, g_osi_funcs_p
 * Fidelity: low - large/complex: 30 branches, 23 loop(s), 11 calls; skeleton only */
int nan_datapath_send_req(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,96; early arg regs: a2, a3, a5, a6 */
    /* struct offsets touched: 8, 10, 12, 16, 20, 24, 28, 32, 33, 34, 36, 48, 52, 64 */
    /* immediates: 1, 0, 36, 0x105, -1, 32, 2, 4, 22, 24, 3, 8 */
    /* branches: +0xa8 beq->0x59 [loop]; +0xb0 beq->0x2A [loop]; +0xb3 j->0x2B8; +0xbc bnez.n->0x48 [loop]; +0xd0 j->0x2B8; +0xe0 bnez.n->0x71 [loop]; +0xf7 j->0x2B8; +0x111 bnez->0x1B6; +0x135 beqz->0x104 [loop]; +0x13b beqz->0x104 [loop] (+20 more) */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    nan_dp_get_peer_ndl(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_dp_node_available(0, 0, 0, 0, 0, 0);  /* ordered call */
    wifi_log(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_dp_alloc_ndl(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_dp_alloc_ndp(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_get_service_by_index(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_get_peer_svc_record(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_sched_alloc_conditional(0, 0, 0, 0, 0, 0);  /* ordered call */
    memcpy(0, 0, 0);  /* ordered call */
    nan_send_ndp_req(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_dp_delete_peer(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_datapath_send_resp @ ieee80211_nan_datapath.o 0000003c size 368B bind GLOBAL
 * Calls: nan_dp_get_peer_ndl, wifi_log, nan_dp_get_peer_ndp, memcpy, nan_send_ndp_resp, nan_call_ndp_terminated_cb, nan_dp_delete_peer | Data refs: .rodata_wlog_warning.167, .rodata_wlog_warning.168, s_dp, g_osi_funcs_p
 * Fidelity: low - large/complex: 13 branches, 8 loop(s), 7 calls; skeleton only */
int nan_datapath_send_resp(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,96; early arg regs: a2, a3, a4, a6 */
    /* struct offsets touched: 8, 12, 16, 32, 33, 34, 48, 56, 376, 548, 572 */
    /* immediates: 2, 32, 1, -1, 8, 28, 0x228, 0, 3, 0x101 */
    /* branches: +0x4f beqz.n->0x48 [loop]; +0x80 j->0x16C; +0x9c bnez.n->0x9C [loop]; +0xd4 j->0x154; +0xdb beqz->0x12A; +0x103 beqz.n->0xF6 [loop]; +0x108 beqz.n->0xF6 [loop]; +0x118 beqz->0x160; +0x163 j->0x16C; +0x182 j->0x163 [loop] (+3 more) */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    nan_dp_get_peer_ndl(0, 0, 0, 0, 0, 0);  /* ordered call */
    wifi_log(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_dp_get_peer_ndp(0, 0, 0, 0, 0, 0);  /* ordered call */
    memcpy(0, 0, 0);  /* ordered call */
    nan_send_ndp_resp(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_call_ndp_terminated_cb(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_dp_delete_peer(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_datapath_end @ ieee80211_nan_datapath.o 00000014 size 144B bind GLOBAL
 * Calls: nan_dp_get_peer_ndl, wifi_log, nan_send_ndp_terminate | Data refs: .rodata_wlog_error.169, g_osi_funcs_p
 * Fidelity: medium - small frame, 3 calls + 3 branch(es) mapped */
int nan_datapath_end(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,64; early arg regs: a2, a3, a4 */
    /* struct offsets touched: 8, 12, 16, 34, 236, 240, 284 */
    /* immediates: 1, 0, 16, 0x105, 3, 0x13c */
    /* branches: +0x2e beqz.n->0x21 [loop]; +0x33 bnez.n->0x55; +0x65 j->0x8E */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    nan_dp_get_peer_ndl(0, 0, 0, 0, 0, 0);  /* ordered call */
    wifi_log(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_send_ndp_terminate(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_sched_init_availability @ ieee80211_nan_datapath.o 00000010 size 79B bind GLOBAL
 * Calls: memcpy, nan_sched_get_chan_bitmap | Data refs: s_dp, g_def_2g_channels
 * Fidelity: medium - small frame, 2 calls + 0 branch(es) mapped */
int nan_sched_init_availability(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2, a3, a4 */
    /* struct offsets touched: 72, 74, 89, 92, 96 */
    /* immediates: 0x303, 75, 81, 11, -2 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    memcpy(0, 0, 0);  /* ordered call */
    nan_sched_get_chan_bitmap(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_dp_init @ ieee80211_nan_datapath.o 00000010 size 90B bind GLOBAL
 * Calls: memset, nan_sched_init_availability | Data refs: s_dp, g_ic
 * Fidelity: medium - small frame, 2 calls + 0 branch(es) mapped */
int nan_dp_init(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2, a3 */
    /* struct offsets touched: 8, 10, 24, 102, 240 */
    /* immediates: 0x52c, 0, 20, 24 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    memset(0, 0, 0);  /* ordered call */
    nan_sched_init_availability(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_dp_deinit @ ieee80211_nan_datapath.o 00000024 size 207B bind GLOBAL
 * Calls: nan_dp_delete_peer, ic_del_key, memset | Data refs: s_dp+0x68, s_dp, g_ic, g_osi_funcs_p, s_dp+0x508
 * Fidelity: low - large/complex: 11 branches, 11 loop(s), 3 calls; skeleton only */
int nan_dp_deinit(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2, a3, a4, a5 */
    /* struct offsets touched: 53, 55, 58, 176, 236, 240, 312, 328, 332, 576, 672 */
    /* immediates: 0x4f0, 0x244, 2, 0, 3, -1, 0x52c */
    /* branches: +0x38 bnez.n->0x31 [loop]; +0x3d bnez.n->0x31 [loop]; +0x42 bnez.n->0x31 [loop]; +0x47 bnez.n->0x31 [loop]; +0x4c bnez->0x31 [loop]; +0x52 beqz->0x39 [loop]; +0x5f bne->0x11 [loop]; +0x6b beqz.n->0x61 [loop]; +0x88 beqz.n->0x81 [loop]; +0xa8 beqz.n->0xA6 [loop] (+1 more) */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    nan_dp_delete_peer(0, 0, 0, 0, 0, 0);  /* ordered call */
    ic_del_key(0, 0, 0, 0, 0, 0);  /* ordered call */
    memset(0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_dp_update_ndi @ ieee80211_nan_datapath.o 00000008 size 20B bind GLOBAL
 * Calls: memcpy | Data refs: s_dp
 * Fidelity: high - trivial: straight-line, all targets resolved */
int nan_dp_update_ndi(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2 */
    /* immediates: 6 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    memcpy(0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_dp_has_active_datapath @ ieee80211_nan_datapath.o 00000004 size 18B bind GLOBAL
 * Calls: none | Data refs: s_dp
 * Fidelity: high - trivial: straight-line, all targets resolved */
int nan_dp_has_active_datapath(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2 */
    /* struct offsets touched: 12 */
    /* immediates: 0, 1 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_dp_get_own_ndi @ ieee80211_nan_datapath.o 00000004 size 8B bind GLOBAL
 * Calls: none | Data refs: s_dp+0x6, s_dp
 * Fidelity: high - trivial: straight-line, all targets resolved */
int nan_dp_get_own_ndi(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_dp_indicate_ndc_start @ ieee80211_nan_datapath.o 0000001c size 112B bind GLOBAL
 * Calls: chm_get_current_channel, ndc_txop_start[+0x8][local], chm_acquire_lock, chm_start_op | Data refs: s_dp, .text.ndc_txop_end
 * Fidelity: medium - small frame, 4 calls + 5 branch(es) mapped */
int nan_dp_indicate_ndc_start(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,48; early arg regs: a2 */
    /* struct offsets touched: 47, 252 */
    /* immediates: 0, 1, 3, 16 */
    /* branches: +0x49 bnez.n->0x6E; +0x4e bnez.n->0x6E; +0x53 bne->0x4C [loop]; +0x64 j->0x6E; +0x75 bnez.n->0x6E [loop] */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    chm_get_current_channel(0, 0, 0, 0, 0, 0);  /* ordered call */
    ndc_txop_start(0, 0, 0, 0, 0, 0);  /* ordered call[+0x8] [local] */
    chm_acquire_lock(0, 0, 0, 0, 0, 0);  /* ordered call */
    chm_start_op(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_dp_indicate_faw_start @ ieee80211_nan_datapath.o 00000024 size 239B bind GLOBAL
 * Calls: chm_get_current_channel, nan_get_avail_by_map_id[local], chm_set_current_channel, nan_get_tsf, ppTxPkt, wifi_log | Data refs: .rodata_wlog_debug.170
 * Fidelity: low - large/complex: 17 branches, 11 loop(s), 6 calls; skeleton only */
int nan_dp_indicate_faw_start(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,64; early arg regs: a2, a3, a4 */
    /* struct offsets touched: 16, 17, 22, 40, 128, 220, 224, 240, 284, 484, 488 */
    /* immediates: 0x128, 0, 1, 16, 0x1e4, 4 */
    /* branches: +0x35 beqz.n->0x24 [loop]; +0x46 bnez.n->0x61; +0x4e beqz.n->0x3C [loop]; +0x5e bnez.n->0x61; +0x62 beq->0x61 [loop]; +0x68 bne->0x52 [loop]; +0x6b beqi->0x61 [loop]; +0x71 beq->0x61 [loop]; +0x92 bnez->0xED; +0x98 bnez->0xED (+7 more) */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    chm_get_current_channel(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_get_avail_by_map_id(0, 0, 0, 0, 0, 0);  /* ordered call [local] */
    chm_set_current_channel(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_get_tsf(0, 0, 0, 0, 0, 0);  /* ordered call */
    ppTxPkt(0, 0, 0, 0, 0, 0);  /* ordered call */
    wifi_log(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_dp_schedule_next_faw @ ieee80211_nan_datapath.o 00000018 size 228B bind GLOBAL
 * Calls: chm_is_at_home_channel, chm_return_home_channel, nan_get_tsf | Data refs: s_dp, g_osi_funcs_p
 * Fidelity: low - large/complex: 23 branches, 14 loop(s), 3 calls; skeleton only */
int nan_dp_schedule_next_faw(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a4, a6 */
    /* struct offsets touched: 64, 236, 248, 604, 608, 612, 616 */
    /* immediates: 0, 1, 0x3e7, 104, 0x244 */
    /* branches: +0x21 bnez.n->0x11 [loop]; +0x2f bnez.n->0x1E [loop]; +0x33 j->0xE0; +0x52 j->0x3F [loop]; +0x5a beqz->0x95; +0x60 beqz->0x95; +0x66 bgeu->0x61 [loop]; +0x6c bgeu->0x95; +0x76 j->0x95; +0x79 bgeu->0x6C [loop] (+13 more) */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    chm_is_at_home_channel(0, 0, 0, 0, 0, 0);  /* ordered call */
    chm_return_home_channel(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_get_tsf(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_dp_schedule_ndc_start @ ieee80211_nan_datapath.o 00000018 size 100B bind GLOBAL
 * Calls: nan_dp_indicate_ndc_start, nan_get_tsf | Data refs: s_dp, g_osi_funcs_p
 * Fidelity: medium - small frame, 2 calls + 4 branch(es) mapped */
int nan_dp_schedule_ndc_start(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a3 */
    /* struct offsets touched: 236, 248, 252 */
    /* immediates: 31, 0 */
    /* branches: +0x24 beqz->0x62; +0x27 bnei->0x1C [loop]; +0x30 j->0x62; +0x58 bltu->0x46 [loop] */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    nan_dp_indicate_ndc_start(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_get_tsf(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_nulldata_txcb @ ieee80211_nan_datapath.o 00000020 size 132B bind GLOBAL
 * Calls: nan_dp_search_node, nan_dp_get_ndl_by_bss, nan_send_ndp_terminate, wifi_log, nan_ndp_start_inactivity_timer | Data refs: g_osi_funcs_p, .rodata_wlog_error.171
 * Fidelity: medium - small frame, 5 calls + 5 branch(es) mapped */
int nan_nulldata_txcb(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2, a3 */
    /* struct offsets touched: 9, 19, 34, 44, 236, 240 */
    /* immediates: 4, 0, 0x13c, 1 */
    /* branches: +0x3a beqi->0x7C; +0x3d beqz->0x82; +0x48 beqz.n->0x68; +0x84 j->0x82 [loop]; +0x98 j->0x82 [loop] */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    nan_dp_search_node(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_dp_get_ndl_by_bss(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_send_ndp_terminate(0, 0, 0, 0, 0, 0);  /* ordered call */
    wifi_log(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_ndp_start_inactivity_timer(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* Notable rodata/log strings in this object (grounded, from Contents sections):
 *   [.text.nan_get_avail_by_map_id] "6A.............X"
 *   [.text.nan_get_avail_by_map_id] "-..J...G......\7"
 *   [.text.nan_get_avail_by_map_id] ")....."
 *   [.text.nan_dp_clear_tmp_data] "........6A.....""
 *   [.text.nan_dp_clear_tmp_data] "........(..(,..."
 *   [.text.nan_dp_clear_tmp_data] ".".......(..(,.."
 *   [.text.nan_dp_clear_tmp_data] "..".........(,.."
 *   [.text.nan_dp_clear_tmp_data] "..".........(,.."
 *   [.text.nan_dp_clear_tmp_data] "..".........(,.."
 *   [.text.nan_dp_clear_tmp_data] "................"
 *   [.text.nan_ndp_inactivity_handler] "....6A...,K....."
 *   [.text.nan_ndp_inactivity_handler] "......"
 *   [.text.nan_ndp_setup_timeout] "....6A...,;....."
 *   [.text.nan_ndp_setup_timeout] "......"
 *   [.text.ndc_txop_end] "........6A......"
 *   [.text.ndc_txop_end] "........."
 *   [.text.ndc_txop_start] "........6A.!.."."
 *   [.text.ndc_txop_start] ".8............b."
 *   [.text.ndc_txop_start] "V..)...9.. ....."
 *   [.text.ndc_txop_start] "..F...."
 *   [.text.nan_sched_in_ndc_slot] "............6A.!"
 *   [.text.nan_sched_in_ndc_slot] ".."..2"?..'.40.`"
 *   [.text.nan_sched_in_ndc_slot] "0....@..`... 8.."
 *   [.text.nan_sched_in_ndc_slot] "..........@....."
 *   [.text.nan_sched_in_ndc_slot] ".:.....7.... ..."
 */
