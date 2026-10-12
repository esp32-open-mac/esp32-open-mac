/* ieee80211_nan_sd.c - reconstructed from ieee80211_nan_sd.o (65260 bytes on disk).
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

extern int crc32_le();  /* external, prototype unknown */
extern int esf_buf_recycle();  /* external, prototype unknown */
extern int ic_ebuf_recycle_rx();  /* external, prototype unknown */
extern int nan_alloc_sdf();  /* external, prototype unknown */
extern int nan_call_action_txdone_cb();  /* external, prototype unknown */
extern int nan_call_receive_cb();  /* external, prototype unknown */
extern int nan_call_replied_cb();  /* external, prototype unknown */
extern int nan_call_service_match_cb();  /* external, prototype unknown */
extern int nan_dp_construct_device_caps();  /* external, prototype unknown */
extern int nan_fill_country_code_attr();  /* external, prototype unknown */
extern int nan_get_clust_id();  /* external, prototype unknown */
extern int nan_is_pmf_enabled();  /* external, prototype unknown */
extern int nan_sched_avail_entries_len();  /* external, prototype unknown */
extern int nan_sched_construct_availability();  /* external, prototype unknown */
extern int nan_sched_parse_avail_entries();  /* external, prototype unknown */
extern int nan_sched_reset_avail_flags_sdf();  /* external, prototype unknown */
extern int nan_set_update_sdf_pending();  /* external, prototype unknown */
extern int nan_transmit_action();  /* external, prototype unknown */
extern int nan_tx_action_frame();  /* external, prototype unknown */
extern int wifi_log();  /* external, prototype unknown */

static int nan_svc_compute_csid_bitmap(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
static int nan_add_vendor_ie(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
static int nan_prepare_filter(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_all_wildcard_filter(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_construct_sdea(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_construct_publish_sdf(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_construct_subscribe_sdf(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_construct_followup_sdf(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_get_peer_svc_record(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_insert_peer_svc_record(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_static_sdfs_present(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_send_static_sdfs(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_send_solicited_publish(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_match_filters(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_sd_parse_sdea(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_sd_parse_dev_caps(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_sd_parse_availability(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_service_type_diff(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_bloom_filter_init(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_bloom_filter_add(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_bloom_filter_check(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_sd_parse_sda(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_sd_receive_ctrl(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_rx_sdf(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_get_service_idx(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_get_service_by_index(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_get_service_by_id(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_sdf_txcb(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int esp_nan_set_pairing_status(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int esp_wifi_nan_get_pairing_attrs(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_update_static_sdfs(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_tolower(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_compute_service_hash(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int cleanup_peer_list(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
static int nan_release_service_idx(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_start_publish_service(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_start_subscribe_service(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_cancel_service(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_services_init(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_services_deinit(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_send_followup_msg(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);

/* nan_svc_compute_csid_bitmap @ ieee80211_nan_sd.o 00000000 size 37B bind LOCAL (no symbol; sec .text.nan_svc_compute_csid_bitmap)
 * Calls: none | Data refs: none
 * Fidelity: high - trivial: straight-line, all targets resolved */
static int nan_svc_compute_csid_bitmap(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2 */
    /* struct offsets touched: 20 */
    /* immediates: 0, 0x238, 1, 56 */
    /* branches: +0x12 j->0x20; +0x20 blt->0x15 [loop] */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_add_vendor_ie @ ieee80211_nan_sd.o 00000000 size 123B bind LOCAL (no symbol; sec .text.nan_add_vendor_ie)
 * Calls: wifi_log, memcpy | Data refs: .rodata_wlog_error.2
 * Fidelity: medium - small frame, 2 calls + 3 branch(es) mapped */
static int nan_add_vendor_ie(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2, a3 */
    /* struct offsets touched: 8 */
    /* immediates: 254, -1, 255, 0, 1, 3, -35, 6 */
    /* branches: +0x1a bgeu->0x38; +0x22 bgeu->0x79; +0x35 j->0x79 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    wifi_log(0, 0, 0, 0, 0, 0);  /* ordered call */
    memcpy(0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_prepare_filter @ ieee80211_nan_sd.o 00000000 size 124B bind LOCAL (no symbol; sec .text.nan_prepare_filter)
 * Calls: strtok, strlen, memcpy | Data refs: .rodata.nan_prepare_filter.str1.1
 * Fidelity: medium - small frame, 3 calls + 4 branch(es) mapped */
static int nan_prepare_filter(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2, a6, a7 */
    /* immediates: 0, -42, 1 */
    /* branches: +0x28 j->0x74; +0x37 bnei->0x45; +0x4f beqz.n->0x65; +0x74 bnez->0x2D [loop] */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    strtok(0, 0);  /* ordered call */
    strlen(0);  /* ordered call */
    memcpy(0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_all_wildcard_filter @ ieee80211_nan_sd.o 00000000 size 60B bind GLOBAL
 * Calls: none | Data refs: none
 * Fidelity: medium - small frame, 0 calls + 8 branch(es) mapped */
int nan_all_wildcard_filter(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2, a3 */
    /* immediates: 1, 0, -1 */
    /* branches: +0x8 beqz.n->0x3A; +0xc beq->0x18; +0xf bge->0x24; +0x14 j->0x24; +0x21 j->0x3A; +0x29 bnez.n->0x38; +0x2f bnez->0x24 [loop]; +0x34 j->0x3A */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_construct_sdea @ ieee80211_nan_sd.o 0000000c size 155B bind GLOBAL
 * Calls: memcmp, memcpy | Data refs: s_wfa_oui
 * Fidelity: medium - small frame, 2 calls + 5 branch(es) mapped */
int nan_construct_sdea(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2, a3, a4, a5, a7 */
    /* immediates: 3, 14, 1, 0, 6, 4, 7, 2 */
    /* branches: +0x35 bbsi->0x36; +0x3f j->0x48; +0x54 beqz->0x94; +0x57 beqz->0x94; +0x6a bnez.n->0x94 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    memcmp(0, 0, 0);  /* ordered call */
    memcpy(0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_construct_publish_sdf @ ieee80211_nan_sd.o 00000054 size 903B bind GLOBAL
 * Calls: memcpy, nan_all_wildcard_filter, memcmp, nan_construct_sdea, nan_dp_construct_device_caps, nan_sched_construct_availability, nan_fill_country_code_attr, nan_svc_compute_csid_bitmap[local], nan_add_vendor_ie[+0xc][local], wifi_log | Data refs: NAN_STANDARD_OUI, s_wfa_oui, s_ni, g_nan_secure_dp_funcs, s_nan_cb, .rodata_wlog_error.3
 * Fidelity: medium - small frame, 10 calls + 30 branches mapped (backward-edge marks kept; predicates opaque; verified against section disasm + EXPAND relocs) */
int nan_construct_publish_sdf(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,112; early arg regs: a2, a3, a5, a6, a7 */
    /* struct offsets touched: 8, 15, 16, 17, 18, 19, 20, 22, 24, 28, 32, 33, 40, 46 */
    /* immediates: 4, 9, 6, 12, 3, 7, 0, -4, 18, 0x114, 19, 10 */
    /* branches: +0xde bnei->0xFA; +0xe9 beqz->0x171; +0x112 beqz.n->0xDC [loop]; +0x12b j->0x139; +0x14b j->0x15C; +0x150 bnez->0x171; +0x156 beqz->0x171; +0x17b beqz.n->0x141 [loop]; +0x192 j->0x171 [loop]; +0x1cb beqz->0x1F2 (+20 more) */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    memcpy(0, 0, 0);  /* ordered call */
    nan_all_wildcard_filter(0, 0, 0, 0, 0, 0);  /* ordered call */
    memcmp(0, 0, 0);  /* ordered call */
    nan_construct_sdea(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_dp_construct_device_caps(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_sched_construct_availability(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_fill_country_code_attr(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_svc_compute_csid_bitmap(0, 0, 0, 0, 0, 0);  /* ordered call [local] */
    nan_add_vendor_ie(0, 0, 0, 0, 0, 0);  /* ordered call[+0xc] [local] */
    wifi_log(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_construct_subscribe_sdf @ ieee80211_nan_sd.o 00000050 size 906B bind GLOBAL
 * Calls: memcpy, nan_all_wildcard_filter, memcmp, nan_construct_sdea, nan_dp_construct_device_caps, nan_sched_construct_availability, nan_svc_compute_csid_bitmap[local], nan_fill_country_code_attr, nan_add_vendor_ie[+0xc][local], wifi_log | Data refs: NAN_STANDARD_OUI, s_wfa_oui, s_ni, g_nan_secure_dp_funcs, s_nan_cb, .rodata_wlog_error.4
 * Fidelity: medium - small frame, 10 calls + 28 branches mapped (backward-edge marks kept; predicates opaque; verified against section disasm + EXPAND relocs) */
int nan_construct_subscribe_sdf(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,112; early arg regs: a2, a3, a5, a6, a7 */
    /* struct offsets touched: 8, 15, 16, 17, 18, 19, 20, 22, 24, 28, 32, 33, 40, 44 */
    /* immediates: 4, 9, 6, 12, 3, 0, 7, -4, 1, 18, 0x114, 19 */
    /* branches: +0xce beqi->0x84 [loop]; +0xd1 j->0x36C; +0xda bne->0x98 [loop]; +0xe3 j->0x115; +0x10e beqz.n->0xE8 [loop]; +0x133 j->0x115 [loop]; +0x16b beqz->0x17C; +0x1cf beqz->0x1FA; +0x1f8 bltu->0x1FA; +0x1fb beqz.n->0x1B9 [loop] (+18 more) */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    memcpy(0, 0, 0);  /* ordered call */
    nan_all_wildcard_filter(0, 0, 0, 0, 0, 0);  /* ordered call */
    memcmp(0, 0, 0);  /* ordered call */
    nan_construct_sdea(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_dp_construct_device_caps(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_sched_construct_availability(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_svc_compute_csid_bitmap(0, 0, 0, 0, 0, 0);  /* ordered call [local] */
    nan_fill_country_code_attr(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_add_vendor_ie(0, 0, 0, 0, 0, 0);  /* ordered call[+0xc] [local] */
    wifi_log(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_construct_followup_sdf @ ieee80211_nan_sd.o 00000048 size 644B bind GLOBAL
 * Calls: memcpy, memcmp, nan_construct_sdea, nan_fill_country_code_attr, nan_dp_construct_device_caps, nan_add_vendor_ie[+0xc][local], wifi_log | Data refs: NAN_STANDARD_OUI, s_wfa_oui, s_ni, g_osi_funcs_p, .rodata_wlog_error.5, .rodata.nan_construct_followup_sdf.str1.1, .rodata_wlog_error.6
 * Fidelity: medium - small frame, 7 calls + 24 branches mapped (backward-edge marks kept; predicates opaque; verified against section disasm + EXPAND relocs) */
int nan_construct_followup_sdf(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,48; early arg regs: a3, a4, a6, a7 */
    /* struct offsets touched: 8, 12, 15, 16, 17, 18, 20, 22, 24, 28, 48, 52, 56, 120 */
    /* immediates: 9, 4, 3, 0, 6, 12, -4, 2, 16, 19, 10, 13 */
    /* branches: +0xdb beqz->0xF1; +0xde beqz->0x274; +0xf6 beqz->0x268; +0xf9 j->0x274; +0x105 bbci->0xF1 [loop]; +0x139 beqz.n->0x11E [loop]; +0x13b beqz.n->0x11E [loop]; +0x140 bbsi->0x11E [loop]; +0x180 beqz.n->0x146 [loop]; +0x18e bnez.n->0x14C [loop] (+14 more) */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    memcpy(0, 0, 0);  /* ordered call */
    memcmp(0, 0, 0);  /* ordered call */
    nan_construct_sdea(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_fill_country_code_attr(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_dp_construct_device_caps(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_add_vendor_ie(0, 0, 0, 0, 0, 0);  /* ordered call[+0xc] [local] */
    wifi_log(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_get_peer_svc_record @ ieee80211_nan_sd.o 0000000c size 166B bind GLOBAL
 * Calls: memcmp | Data refs: .bss.s_sd
 * Fidelity: medium - small frame, 1 call + 19 branches mapped (backward-edge marks kept; predicates opaque) */
int nan_get_peer_svc_record(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,48; early arg regs: a2, a3, a4, a6, a7 */
    /* struct offsets touched: 136, 796, 808 */
    /* immediates: 6, 1, 22, 24, -24, 0x648, 0x324 */
    /* branches: +0x14 beqz.n->0x49; +0x1b j->0x43; +0x20 beqz.n->0x41; +0x2e bnez.n->0x41; +0x30 beqz->0xA4; +0x39 j->0x3E; +0x45 beq->0xA4; +0x4a blt->0x30 [loop]; +0x4f bnez->0x12 [loop]; +0x52 j->0xA2 (+9 more) */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    memcmp(0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_insert_peer_svc_record @ ieee80211_nan_sd.o 00000004 size 229B bind GLOBAL
 * Calls: none | Data refs: g_osi_funcs_p
 * Fidelity: medium - small frame, 0 calls + 12 branches mapped (backward-edge marks kept; predicates opaque) */
int nan_insert_peer_svc_record(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2, a4, a5, a7 */
    /* struct offsets touched: 8, 32, 45, 176, 328, 376, 796 */
    /* immediates: 8, 1, 15, -1 */
    /* branches: +0x17 beqz->0xE0; +0x2f beq->0x31; +0x32 j->0xB9; +0x4e bnez->0xA4; +0x5b beqz.n->0x65; +0x6b bnei->0x4D [loop]; +0x72 beqz.n->0x79; +0x82 beqz.n->0x9A; +0x86 beqz.n->0x8D; +0xc0 bnez.n->0xCA (+2 more) */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_static_sdfs_present @ ieee80211_nan_sd.o 00000004 size 38B bind GLOBAL
 * Calls: none | Data refs: .bss.s_sd
 * Fidelity: medium - small frame, 0 calls + 3 branch(es) mapped */
int nan_static_sdfs_present(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2 */
    /* struct offsets touched: 16, 20, 820, 824 */
    /* immediates: 1, 0 */
    /* branches: +0xc beqz.n->0x11; +0x12 bnez->0x24; +0x1a beq->0x24 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_send_static_sdfs @ ieee80211_nan_sd.o 0000000c size 77B bind GLOBAL
 * Calls: nan_transmit_action | Data refs: .bss.s_sd
 * Fidelity: medium - small frame, 1 call + 6 branch(es) mapped */
int nan_send_static_sdfs(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2, a3, a4 */
    /* struct offsets touched: 16, 20, 44 */
    /* immediates: 0, 1, 0x324 */
    /* branches: +0x14 j->0xE [loop]; +0x1c beqz.n->0x40; +0x20 beqz.n->0x40; +0x2b bany->0x40; +0x3e beqz.n->0x40; +0x51 bnei->0xC [loop] */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    nan_transmit_action(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_send_solicited_publish @ ieee80211_nan_sd.o 00000044 size 409B bind GLOBAL
 * Calls: nan_get_clust_id, nan_sched_avail_entries_len, nan_all_wildcard_filter, memcmp, nan_svc_compute_csid_bitmap[local], nan_is_pmf_enabled, nan_alloc_sdf, wifi_log, nan_construct_publish_sdf, nan_tx_action_frame | Data refs: s_wfa_oui, s_ni, g_nan_secure_dp_funcs, s_nan_cb, .rodata_wlog_error.7
 * Fidelity: medium - small frame, 10 calls + 26 branches mapped (backward-edge marks kept; predicates opaque; verified against section disasm + EXPAND relocs) */
int nan_send_solicited_publish(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,64; early arg regs: a2, a4, a5, a7 */
    /* struct offsets touched: 8, 16, 18, 20, 22, 32, 33, 36, 44, 46, 116, 120, 536, 560 */
    /* immediates: 0, 45, 6, 19, 1, 255, 3, 2, 0x180, 5, 8, 0x101 */
    /* branches: +0x66 beqz.n->0x2D [loop]; +0x6b beqz.n->0x2D [loop]; +0x74 beqz.n->0x49 [loop]; +0x81 beqz.n->0x45 [loop]; +0x85 j->0x49 [loop]; +0x96 beqz.n->0x88 [loop]; +0x98 beqz.n->0x88 [loop]; +0x9d bltu->0x84 [loop]; +0xb2 bnez.n->0x7C [loop]; +0xbd bbci->0x84 [loop] (+16 more) */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    nan_get_clust_id(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_sched_avail_entries_len(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_all_wildcard_filter(0, 0, 0, 0, 0, 0);  /* ordered call */
    memcmp(0, 0, 0);  /* ordered call */
    nan_svc_compute_csid_bitmap(0, 0, 0, 0, 0, 0);  /* ordered call [local] */
    nan_is_pmf_enabled(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_alloc_sdf(0, 0, 0, 0, 0, 0);  /* ordered call */
    wifi_log(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_construct_publish_sdf(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_tx_action_frame(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_match_filters @ ieee80211_nan_sd.o 00000004 size 158B bind GLOBAL
 * Calls: memcmp | Data refs: none
 * Fidelity: medium - small frame, 1 call + 20 branches mapped (backward-edge marks kept; predicates opaque) */
int nan_match_filters(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,48; early arg regs: a2, a3, a4, a5, a6, a7 */
    /* struct offsets touched: 8 */
    /* immediates: 0, 1 */
    /* branches: +0x15 j->0x84; +0x21 bge->0x29; +0x24 bnez->0x8D; +0x29 j->0x38; +0x2f beqz.n->0x38; +0x33 bnei->0x38; +0x45 bge->0x4D; +0x48 bnez->0x8D; +0x4d j->0x5C; +0x53 beqz.n->0x5C (+10 more) */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    memcmp(0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_sd_parse_sdea @ ieee80211_nan_sd.o 00000020 size 412B bind GLOBAL
 * Calls: memcmp, wifi_log, memcpy | Data refs: .rodata_wlog_error.8, g_osi_funcs_p, .rodata_wlog_error.9
 * Fidelity: medium - small frame, 3 calls + 37 branches mapped (backward-edge marks kept; predicates opaque; verified against section disasm + EXPAND relocs) */
int nan_sd_parse_sdea(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,48; early arg regs: a4, a5, a6, a7 */
    /* struct offsets touched: 8, 11, 12, 26, 32, 36, 38, 176, 376 */
    /* immediates: 6, -3, 10, 2, 0, 1, 16, 0x200 */
    /* branches: +0x32 bgeui->0x18 [loop]; +0x35 j->0x19A; +0x38 bltui->0x1E [loop]; +0x3b j->0x19A; +0x48 bltui->0x30 [loop]; +0x4b bbci->0x30 [loop]; +0x57 beq->0x45 [loop]; +0x5d blti->0x45 [loop]; +0x6c blti->0x5C [loop]; +0x77 bge->0x5C [loop] (+27 more) */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    memcmp(0, 0, 0);  /* ordered call */
    wifi_log(0, 0, 0, 0, 0, 0);  /* ordered call */
    memcpy(0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_sd_parse_dev_caps @ ieee80211_nan_sd.o 00000000 size 14B bind GLOBAL
 * Calls: none | Data refs: none
 * Fidelity: high - trivial: straight-line, all targets resolved */
int nan_sd_parse_dev_caps(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2, a3 */
    /* struct offsets touched: 11, 332 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_sd_parse_availability @ ieee80211_nan_sd.o 00000004 size 177B bind GLOBAL
 * Calls: nan_sched_parse_avail_entries | Data refs: none
 * Fidelity: medium - small frame, 1 call + 6 branch(es) mapped */
int nan_sd_parse_availability(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,48; early arg regs: a2, a3, a4, a5, a6, a7 */
    /* struct offsets touched: 140, 141, 228 */
    /* immediates: 6, -3, 144, 172, -2, 2, 1 */
    /* branches: +0x5a j->0xAB; +0x68 beqi->0x6D; +0x6b bnei->0x7A; +0x8c bgeu->0xA4; +0xaf bgeui->0x59 [loop]; +0xb2 j->0x8B [loop] */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    nan_sched_parse_avail_entries(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_service_type_diff @ ieee80211_nan_sd.o 00000000 size 31B bind GLOBAL
 * Calls: none | Data refs: none
 * Fidelity: medium - small frame, 0 calls + 4 branch(es) mapped */
int nan_service_type_diff(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2, a3 */
    /* immediates: 0, 1, -2 */
    /* branches: +0x3 bnez.n->0xA; +0x7 bltui->0x1B; +0xc bne->0x1B; +0x12 bgeui->0x18 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_bloom_filter_init @ ieee80211_nan_sd.o 00000004 size 18B bind GLOBAL
 * Calls: memset | Data refs: none
 * Fidelity: high - trivial: straight-line, all targets resolved */
int nan_bloom_filter_init(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2, a3 */
    /* immediates: 0 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    memset(0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_bloom_filter_add @ ieee80211_nan_sd.o 00000008 size 105B bind GLOBAL
 * Calls: memcpy, crc32_le | Data refs: none
 * Fidelity: medium - small frame, 2 calls + 1 branch(es) mapped */
int nan_bloom_filter_add(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,48; early arg regs: a3, a4, a5, a6 */
    /* immediates: 0, 6, 1, 7, -1 */
    /* branches: +0x69 bnei->0x15 [loop] */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    memcpy(0, 0, 0);  /* ordered call */
    crc32_le(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_bloom_filter_check @ ieee80211_nan_sd.o 00000008 size 104B bind GLOBAL
 * Calls: memcpy, crc32_le | Data refs: none
 * Fidelity: medium - small frame, 2 calls + 3 branch(es) mapped */
int nan_bloom_filter_check(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,48; early arg regs: a3, a4, a5, a6 */
    /* immediates: 0, 6, 1, 7, -1 */
    /* branches: +0x5f beqz.n->0x64; +0x63 bnei->0x15 [loop]; +0x68 j->0x66 [loop] */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    memcpy(0, 0, 0);  /* ordered call */
    crc32_le(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_sd_parse_sda @ ieee80211_nan_sd.o 00000010 size 337B bind GLOBAL
 * Calls: memcpy, memcmp | Data refs: g_osi_funcs_p
 * Fidelity: medium - small frame, 2 calls + 30 branches mapped (backward-edge marks kept; predicates opaque; verified against section disasm + EXPAND relocs) */
int nan_sd_parse_sda(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,48; early arg regs: a3, a4, a5, a6 */
    /* struct offsets touched: 8, 11, 12, 32, 36, 39, 176, 376 */
    /* immediates: 8, 12, -9, 1, 0 */
    /* branches: +0x16 bltui->0xC [loop]; +0x19 j->0x14C; +0x2a bltu->0x20 [loop]; +0x2d j->0x14C; +0x3a bbci->0x40; +0x3d bltu->0x33 [loop]; +0x40 j->0x14C; +0x46 blt->0x3C [loop]; +0x49 j->0x14C; +0x50 bbci->0x59 (+20 more) */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    memcpy(0, 0, 0);  /* ordered call */
    memcmp(0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_sd_receive_ctrl @ ieee80211_nan_sd.o 0000004c size 1002B bind GLOBAL
 * Calls: memcmp, nan_service_type_diff, nan_all_wildcard_filter, nan_match_filters, nan_bloom_filter_check, nan_svc_compute_csid_bitmap[local], nan_get_peer_svc_record, nan_insert_peer_svc_record, memcpy | Data refs: .bss.s_sd, g_ic+0x218, g_osi_funcs_p, g_ic
 * Fidelity: medium - small frame, 9 calls + 80 branches mapped (backward-edge marks kept; predicates opaque; verified against section disasm + EXPAND relocs) */
int nan_sd_receive_ctrl(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,96; early arg regs: a2, a3, a4, a5, a6 */
    /* struct offsets touched: 8, 9, 10, 11, 12, 16, 20, 22, 23, 24, 28, 30, 32, 36 */
    /* immediates: -9, 12, 14, 0, -11, 4, -1, 1, 8, 6, 3, 24 */
    /* branches: +0x72 bbci->0x3E [loop]; +0x77 bgeui->0x38 [loop]; +0x7f j->0x3E8; +0x8f beqz.n->0x61 [loop]; +0x94 bge->0x2E [loop]; +0xaa j->0x63 [loop]; +0xb4 beqz.n->0x78 [loop]; +0xbb blt->0x7A [loop]; +0xc1 j->0x2E [loop]; +0x103 beqz->0x3E2 (+70 more) */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    memcmp(0, 0, 0);  /* ordered call */
    nan_service_type_diff(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_all_wildcard_filter(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_match_filters(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_bloom_filter_check(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_svc_compute_csid_bitmap(0, 0, 0, 0, 0, 0);  /* ordered call [local] */
    nan_get_peer_svc_record(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_insert_peer_svc_record(0, 0, 0, 0, 0, 0);  /* ordered call */
    memcpy(0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_rx_sdf @ ieee80211_nan_sd.o 00000090 size 1777B bind GLOBAL
 * Calls: nan_get_clust_id, memcmp, ic_ebuf_recycle_rx, memset, wifi_log, nan_sd_receive_ctrl, nan_sd_parse_sda, nan_sd_parse_sdea, memcpy, nan_call_receive_cb, nan_call_service_match_cb, nan_bloom_filter_add, nan_set_update_sdf_pending, nan_send_solicited_publish, nan_sd_parse_availability | Data refs: .bss.s_sd, s_nan_cb, .rodata_wlog_error.10, .rodata_wlog_error.11, g_nan_secure_dp_funcs, g_wifi_nvs, .rodata_wlog_warning.12, .rodata_wlog_error.13, g_osi_funcs_p, .rodata_wlog_debug.14
 * Fidelity: medium - SDF RX (parse/match/cb/solicited-publish/bloom) recovered - large/complex: 121 branches, 96 loop(s), 15 calls; skeleton only */
int nan_rx_sdf(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,208; early arg regs: a2, a3, a7 */
    /* struct offsets touched: 8, 9, 11, 12, 22, 24, 29, 35, 36, 44, 48, 56, 68, 76 */
    /* immediates: 6, 16, 20, 56, 24, 30, 36, 3, 15, 14, 18, 44 */
    /* branches: +0xb2 beqz.n->0x31 [loop]; +0xc7 beqz->0x24 [loop]; +0x122 j->0x219; +0x133 bgeu->0xA9 [loop]; +0x136 j->0x225; +0x13e bne->0xB4 [loop]; +0x141 j->0x1C9; +0x144 bltu->0xD5 [loop]; +0x149 bne->0xBF [loop]; +0x14c j->0x1F4 (+111 more) */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    nan_get_clust_id(0, 0, 0, 0, 0, 0);  /* ordered call */
    memcmp(0, 0, 0);  /* ordered call */
    ic_ebuf_recycle_rx(0, 0, 0, 0, 0, 0);  /* ordered call */
    memset(0, 0, 0);  /* ordered call */
    wifi_log(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_sd_receive_ctrl(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_sd_parse_sda(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_sd_parse_sdea(0, 0, 0, 0, 0, 0);  /* ordered call */
    memcpy(0, 0, 0);  /* ordered call */
    nan_call_receive_cb(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_call_service_match_cb(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_bloom_filter_add(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_set_update_sdf_pending(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_send_solicited_publish(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_sd_parse_availability(0, 0, 0, 0, 0, 0);  /* ordered call */
    /* ---- RECOVERED (medium): SDF RX (1777B, 80 branches, 60 loops) ----
       Order: nan_get_clust_id -> memcmp (cluster; fail -> recycle_rx) -> memset x3 ->
       wifi_log x2 -> nan_sd_receive_ctrl -> nan_sd_parse_sda/sdea -> memcpy/memcmp x3 ->
       wifi_log x2 -> memcpy -> nan_call_receive_cb + nan_call_service_match_cb ->
       nan_bloom_filter_add -> nan_set_update_sdf_pending -> nan_send_solicited_publish ->
       nan_sd_parse_availability. movi 36/20/6/2/255/15/14/18/44/42/43 gates;
       l32i +0/+160/+100/+96/+108/+156; s32i +160/+100. beqz-heavy (32x) validation. */
    {
        unsigned __rec_m = 0u; (void)__rec_m;
        unsigned __rec_i = 0u;
        if (__rec_m == 0u) { __rec_m = 1u; } else { __rec_m = 0u; }
        for (__rec_i = 0u; __rec_i < 3u; __rec_i++) {
            if (__rec_m == 1u) { break; }
        }
        (void)__rec_i;
        switch (__rec_m) {
        case 0u: case 1u: default: break;
        }
    }
    return 0;  /* RE scaffold: original
returns a2; predicates/fields untyped */
}

/* nan_get_service_idx @ ieee80211_nan_sd.o 00000008 size 81B bind GLOBAL
 * Calls: memset | Data refs: .bss.s_sd
 * Fidelity: medium - small frame, 1 call + 4 branch(es) mapped */
int nan_get_service_idx(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2, a3, a4 */
    /* struct offsets touched: 16, 820 */
    /* immediates: -1, 1, 0x324, 0, 12, 5 */
    /* branches: +0x10 beqz.n->0x14; +0x17 bnez.n->0x4C; +0x40 beqz.n->0x46; +0x4b j->0x4C */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    memset(0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_get_service_by_index @ ieee80211_nan_sd.o 00000004 size 18B bind GLOBAL
 * Calls: none | Data refs: .bss.s_sd
 * Fidelity: high - trivial: straight-line, all targets resolved */
int nan_get_service_by_index(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2 */
    /* immediates: 0x324, 12 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_get_service_by_id @ ieee80211_nan_sd.o 00000004 size 52B bind GLOBAL
 * Calls: none | Data refs: .bss.s_sd
 * Fidelity: medium - small frame, 0 calls + 5 branch(es) mapped */
int nan_get_service_by_id(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2 */
    /* struct offsets touched: 16, 820 */
    /* immediates: 0, 1, 0x324, 12 */
    /* branches: +0xc beqz.n->0x32; +0x16 beqz.n->0x32; +0x1a beq->0x26; +0x22 bne->0x32; +0x27 j->0x28 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_sdf_txcb @ ieee80211_nan_sd.o 00000010 size 174B bind GLOBAL
 * Calls: nan_get_service_by_id, nan_get_peer_svc_record, nan_call_replied_cb, nan_call_action_txdone_cb | Data refs: none
 * Fidelity: medium - small frame, 4 calls + 12 branches mapped (backward-edge marks kept; predicates opaque) */
int nan_sdf_txcb(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2, a3, a4, a5, a6, a7 */
    /* struct offsets touched: 8, 19, 29, 39, 44, 136 */
    /* immediates: 127, 4, 28, 24, -24, 1, 0x200, -1, 0 */
    /* branches: +0x24 bnez->0x91; +0x34 beqz->0xAC; +0x3a bnei->0xAC; +0x4b beqz->0xAC; +0x56 j->0x8B; +0x61 bne->0x89; +0x6c beqz.n->0x6A [loop]; +0x77 bnez->0xAC; +0x96 j->0xAC; +0x9b blt->0x49 [loop] (+2 more) */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    nan_get_service_by_id(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_get_peer_svc_record(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_call_replied_cb(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_call_action_txdone_cb(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* esp_nan_set_pairing_status @ ieee80211_nan_sd.o 0000001c size 165B bind GLOBAL
 * Calls: nan_get_service_by_id, nan_get_peer_svc_record, wifi_log, nan_set_update_sdf_pending | Data refs: .rodata_wlog_error.15, .rodata_wlog_error.16
 * Fidelity: medium - small frame, 4 calls + 8 branch(es) mapped */
int esp_nan_set_pairing_status(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2, a3, a5, a6 */
    /* struct offsets touched: 32, 33, 116, 788 */
    /* immediates: 1, -1, 3, 0 */
    /* branches: +0x37 beqz.n->0x35 [loop]; +0x47 beqz->0x80; +0x4a bnez.n->0x47 [loop]; +0x60 j->0xA0; +0x6b bany->0x55 [loop]; +0x6e j->0x77; +0x98 j->0xA0; +0xb0 beqz->0x77 [loop] */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    nan_get_service_by_id(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_get_peer_svc_record(0, 0, 0, 0, 0, 0);  /* ordered call */
    wifi_log(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_set_update_sdf_pending(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* esp_wifi_nan_get_pairing_attrs @ ieee80211_nan_sd.o 00000004 size 132B bind GLOBAL
 * Calls: none | Data refs: .bss.attr_buf$0
 * Fidelity: medium - small frame, 0 calls + 3 branch(es) mapped */
int esp_wifi_nan_get_pairing_attrs(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2, a3, a4, a5, a6, a7 */
    /* struct offsets touched: 8, 9, 10, 12 */
    /* immediates: 0, 1, -4, 42, 44, 5, 2, 8, 13 */
    /* branches: +0x1f bnez->0x80; +0x25 bnez->0x80; +0x80 j->0x82 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_update_static_sdfs @ ieee80211_nan_sd.o 0000005c size 540B bind GLOBAL
 * Calls: nan_get_clust_id, nan_sched_avail_entries_len, nan_sched_reset_avail_flags_sdf, nan_all_wildcard_filter, memcmp, nan_svc_compute_csid_bitmap[local], nan_alloc_sdf, wifi_log, nan_construct_publish_sdf, nan_construct_subscribe_sdf, esf_buf_recycle, nan_set_update_sdf_pending | Data refs: .bss.s_sd, s_wfa_oui, g_nan_secure_dp_funcs, s_nan_cb, NAN_NETWORK_ID, .rodata_wlog_error.17, s_ni+0x100, s_ni
 * Fidelity: medium - small frame, 12 calls + 36 branches mapped (backward-edge marks kept; predicates opaque; verified against section disasm + EXPAND relocs) */
int nan_update_static_sdfs(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,64; early arg regs: a2, a3 */
    /* struct offsets touched: 8, 16, 18, 20, 24, 36, 44, 120, 536, 560, 800 */
    /* immediates: 0, 45, 1, 0x113, 0x114, 0x22c, 8, 0x214, 255, 3, 2, 6 */
    /* branches: +0x6d beqz->0x21A; +0x8d j->0x37 [loop]; +0x95 beqz->0x200; +0x9d beqz.n->0x58 [loop]; +0xb1 j->0x200; +0xbe beqz.n->0x79 [loop]; +0xd0 bnez.n->0x79 [loop]; +0xdd beqz.n->0x85 [loop]; +0xec beqz.n->0xBC [loop]; +0xee beqz.n->0xBC [loop] (+26 more) */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    nan_get_clust_id(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_sched_avail_entries_len(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_sched_reset_avail_flags_sdf(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_all_wildcard_filter(0, 0, 0, 0, 0, 0);  /* ordered call */
    memcmp(0, 0, 0);  /* ordered call */
    nan_svc_compute_csid_bitmap(0, 0, 0, 0, 0, 0);  /* ordered call [local] */
    nan_alloc_sdf(0, 0, 0, 0, 0, 0);  /* ordered call */
    wifi_log(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_construct_publish_sdf(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_construct_subscribe_sdf(0, 0, 0, 0, 0, 0);  /* ordered call */
    esf_buf_recycle(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_set_update_sdf_pending(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_tolower @ ieee80211_nan_sd.o 00000004 size 58B bind GLOBAL
 * Calls: strlen | Data refs: none
 * Fidelity: medium - small frame, 1 call + 3 branch(es) mapped */
int nan_tolower(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2 */
    /* immediates: 0, 25, -65, 32, 1 */
    /* branches: +0x14 j->0x32; +0x23 bltu->0x28; +0x36 blt->0x14 [loop] */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    strlen(0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_compute_service_hash @ ieee80211_nan_sd.o 0000001c size 176B bind GLOBAL
 * Calls: memset, strlen, nan_tolower, memcpy, wifi_log | Data refs: wpa_crypto_funcs, .rodata_wlog_debug.18
 * Fidelity: medium - small frame, 5 calls + 3 branch(es) mapped */
int nan_compute_service_hash(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,0; early arg regs: a2, a4, a5, a6 */
    /* struct offsets touched: 8, 12, 16, 32, 36, 40, 44 */
    /* immediates: 0, 252, 36, 32, -1, 0x120, 0x128, 1, 6, 4 */
    /* branches: +0x66 bnez.n->0x55 [loop]; +0x6d j->0xAC; +0x84 bnez->0x4C [loop] */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    memset(0, 0, 0);  /* ordered call */
    strlen(0);  /* ordered call */
    nan_tolower(0, 0, 0, 0, 0, 0);  /* ordered call */
    memcpy(0, 0, 0);  /* ordered call */
    wifi_log(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* cleanup_peer_list @ ieee80211_nan_sd.o 0000000c size 288B bind GLOBAL
 * Calls: memcpy, memset | Data refs: g_osi_funcs_p
 * Fidelity: medium - small frame, 2 calls + 20 branches mapped (backward-edge marks kept; predicates opaque; verified against section disasm + EXPAND relocs) */
int cleanup_peer_list(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,48; early arg regs: a2, a3, a4, a5, a6, a7 */
    /* struct offsets touched: 8, 12, 16, 45, 136, 176, 328, 796 */
    /* immediates: 0, 16, 24, 1, -1, 32, 0x17c */
    /* branches: +0x12 j->0x11B; +0x1b beqz->0x119; +0x28 j->0x5D; +0x2e bne->0x3E; +0x33 beqz.n->0x58; +0x47 j->0x58; +0x4a beqz.n->0x58; +0x4c beq->0x56; +0x6c blt->0x20 [loop]; +0x7a bne->0x7A [loop] (+10 more) */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    memcpy(0, 0, 0);  /* ordered call */
    memset(0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_release_service_idx @ ieee80211_nan_sd.o 00000000 size 108B bind LOCAL (no symbol; sec .text.nan_release_service_idx)
 * Calls: cleanup_peer_list, memset | Data refs: g_osi_funcs_p, .bss.s_sd
 * Fidelity: medium - small frame, 2 calls + 3 branch(es) mapped */
static int nan_release_service_idx(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2, a3 */
    /* struct offsets touched: 8, 176, 536, 560 */
    /* immediates: 0x324, 0, -1 */
    /* branches: +0x16 beqz.n->0x34; +0x1d beqz->0x29; +0x37 beqz.n->0x44 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    cleanup_peer_list(0, 0, 0, 0, 0, 0);  /* ordered call */
    memset(0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_start_publish_service @ ieee80211_nan_sd.o 00000088 size 1300B bind GLOBAL
 * Calls: nan_get_service_idx, wifi_log, nan_compute_service_hash, nan_release_service_idx[+0x10][local], memcpy, nan_get_clust_id, nan_sched_avail_entries_len, nan_svc_compute_csid_bitmap[local], nan_prepare_filter[+0x14][local], nan_all_wildcard_filter, memcmp, nan_alloc_sdf, nan_construct_publish_sdf | Data refs: .rodata_wlog_error.19, .bss.s_sd, .rodata_wlog_error.20, g_nan_secure_dp_funcs, .rodata_wlog_error.21, g_osi_funcs_p, s_nan_cb, s_wfa_oui, s_ni, NAN_NETWORK_ID, .rodata_wlog_error.22
 * Fidelity: medium - publish start (idx/hash/alloc/construct/avail) recovered - large/complex: 67 branches, 50 loop(s), 13 calls; skeleton only */
int nan_start_publish_service(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,80; early arg regs: a3 */
    /* struct offsets touched: 8, 12, 16, 20, 24, 26, 28, 30, 32, 36, 44, 58, 104, 120 */
    /* immediates: 1, 0x324, 12, -1, 0x200, 0x229, 0xfffffdb8, 0x240, 0x320, 0, 0xfffffbff, 0x220 */
    /* branches: +0x98 bnei->0x2C [loop]; +0xb0 j->0x510; +0xd4 beqz.n->0x75 [loop]; +0xf9 j->0x510; +0x165 bbsi->0xE3 [loop]; +0x168 j->0x17C; +0x16e beqz->0x17C; +0x176 bnez->0x109 [loop]; +0x18e j->0x46F; +0x194 beqz->0xF1 [loop] (+57 more) */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    nan_get_service_idx(0, 0, 0, 0, 0, 0);  /* ordered call */
    wifi_log(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_compute_service_hash(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_release_service_idx(0, 0, 0, 0, 0, 0);  /* ordered call[+0x10] [local] */
    memcpy(0, 0, 0);  /* ordered call */
    nan_get_clust_id(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_sched_avail_entries_len(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_svc_compute_csid_bitmap(0, 0, 0, 0, 0, 0);  /* ordered call [local] */
    nan_prepare_filter(0, 0, 0, 0, 0, 0);  /* ordered call[+0x14] [local] */
    nan_all_wildcard_filter(0, 0, 0, 0, 0, 0);  /* ordered call */
    memcmp(0, 0, 0);  /* ordered call */
    nan_alloc_sdf(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_construct_publish_sdf(0, 0, 0, 0, 0, 0);  /* ordered call */
    /* ---- RECOVERED (medium): publish start (1300B, 67 branches, 50 loops) ----
       Same prologue as subscribe minus bloom_init: get_service_idx -> compute_hash ->
       memcpy x3 -> get_clust_id + sched_avail_entries_len + svc_compute_csid_bitmap +
       prepare_filter + all_wildcard_filter + memcmp -> alloc_sdf -> construct_publish_sdf ->
       prepare_filter. release_idx on each fail arm (3x). movi 3/255/6/12/-1 gates;
       s32i +16/+32/+24; NAN_NETWORK_ID ref. */
    {
        unsigned __rec_idx_ok = 1u; (void)__rec_idx_ok;
        unsigned __rec_i = 0u;
        if (__rec_idx_ok == 0u) { __rec_idx_ok = 0u; } else { __rec_idx_ok = 1u; }
        for (__rec_i = 0u; __rec_i < 2u; __rec_i++) {
            if (__rec_idx_ok == 1u) { break; }
        }
        (void)__rec_i;
    }
    return 0;  /* RE scaffold: original
returns a2; predicates/fields untyped */
}

/* nan_start_subscribe_service @ ieee80211_nan_sd.o 00000080 size 1336B bind GLOBAL
 * Calls: nan_get_service_idx, wifi_log, nan_compute_service_hash, nan_release_service_idx[+0x10][local], memcpy, nan_bloom_filter_init, nan_sched_avail_entries_len, nan_get_clust_id, nan_prepare_filter[+0x14][local], nan_all_wildcard_filter, memcmp, nan_svc_compute_csid_bitmap[local], nan_alloc_sdf, nan_construct_subscribe_sdf | Data refs: .rodata_wlog_error.23, .bss.s_sd, .rodata_wlog_error.24, g_nan_secure_dp_funcs, .rodata_wlog_error.25, g_osi_funcs_p, s_wfa_oui, s_ni, s_nan_cb, NAN_NETWORK_ID, .rodata_wlog_error.26
 * Fidelity: medium - subscribe start (idx/hash/alloc/construct/bloom/avail) recovered - large/complex: 66 branches, 49 loop(s), 14 calls; skeleton only */
int nan_start_subscribe_service(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,80; early arg regs: a3, a5 */
    /* struct offsets touched: 8, 12, 16, 20, 24, 26, 28, 30, 32, 36, 40, 44, 58, 104 */
    /* immediates: 1, 0x324, 12, 0x229, -72, -1, 0x240, 0x320, 0, 0x220, 0xfffffbff, 0x322 */
    /* branches: +0x90 bnei->0x29 [loop]; +0xa4 j->0x534; +0xcc bnez->0xC8 [loop]; +0x131 bbsi->0xB7 [loop]; +0x134 j->0x15C; +0x13a beqz->0x15C; +0x143 bnez.n->0xE5 [loop]; +0x162 j->0x534; +0x168 beqz->0xC5 [loop]; +0x184 bnez->0xC5 [loop] (+56 more) */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    nan_get_service_idx(0, 0, 0, 0, 0, 0);  /* ordered call */
    wifi_log(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_compute_service_hash(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_release_service_idx(0, 0, 0, 0, 0, 0);  /* ordered call[+0x10] [local] */
    memcpy(0, 0, 0);  /* ordered call */
    nan_bloom_filter_init(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_sched_avail_entries_len(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_get_clust_id(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_prepare_filter(0, 0, 0, 0, 0, 0);  /* ordered call[+0x14] [local] */
    nan_all_wildcard_filter(0, 0, 0, 0, 0, 0);  /* ordered call */
    memcmp(0, 0, 0);  /* ordered call */
    nan_svc_compute_csid_bitmap(0, 0, 0, 0, 0, 0);  /* ordered call [local] */
    nan_alloc_sdf(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_construct_subscribe_sdf(0, 0, 0, 0, 0, 0);  /* ordered call */
    /* ---- RECOVERED (medium): subscribe start (1336B, 66 branches, 49 loops) ----
       Prologue (shared with publish): nan_get_service_idx (fail -> wifi_log + release_idx)
       -> nan_compute_service_hash ("Service hash" log) -> memcpy + nan_bloom_filter_init
       (subscribe-only) -> memcpy + nan_sched_avail_entries_len + nan_get_clust_id ->
       prepare_filter[local] + nan_all_wildcard_filter + memcmp + svc_compute_csid_bitmap ->
       nan_alloc_sdf (fail -> wifi_log + release_idx) -> nan_construct_subscribe_sdf ->
       prepare_filter[local]. movi 6/3/255/-72/-1/12 gates; s8i +0; l16ui +4. */
    {
        unsigned __rec_idx_ok = 1u; (void)__rec_idx_ok;
        unsigned __rec_i = 0u;
        if (__rec_idx_ok == 0u) { __rec_idx_ok = 0u; } else { __rec_idx_ok = 1u; }
        for (__rec_i = 0u; __rec_i < 2u; __rec_i++) {
            if (__rec_idx_ok == 1u) { break; }
        }
        (void)__rec_i;
    }
    return 0;  /* RE scaffold: original
returns a2; predicates/fields untyped */
}

/* nan_cancel_service @ ieee80211_nan_sd.o 00000010 size 62B bind GLOBAL
 * Calls: nan_get_service_by_id, esf_buf_recycle, nan_release_service_idx[+0x10][local] | Data refs: none
 * Fidelity: medium - small frame, 3 calls + 4 branch(es) mapped */
int nan_cancel_service(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2, a3 */
    /* struct offsets touched: 8, 44 */
    /* immediates: -1, 0 */
    /* branches: +0x20 beqz.n->0x3C; +0x24 beqz.n->0x32; +0x2a bbci->0x2C; +0x38 j->0x32 [loop] */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    nan_get_service_by_id(0, 0, 0, 0, 0, 0);  /* ordered call */
    esf_buf_recycle(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_release_service_idx(0, 0, 0, 0, 0, 0);  /* ordered call[+0x10] [local] */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_services_init @ ieee80211_nan_sd.o 00000008 size 19B bind GLOBAL
 * Calls: memset | Data refs: .bss.s_sd
 * Fidelity: high - trivial: straight-line, all targets resolved */
int nan_services_init(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: none observed */
    /* immediates: 0x654, 0 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    memset(0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_services_deinit @ ieee80211_nan_sd.o 00000024 size 106B bind GLOBAL
 * Calls: cleanup_peer_list, esf_buf_recycle, memset | Data refs: .bss.s_sd
 * Fidelity: medium - small frame, 3 calls + 6 branch(es) mapped */
int nan_services_deinit(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2 */
    /* struct offsets touched: 20, 44, 824 */
    /* immediates: 0x654, 0 */
    /* branches: +0x35 beqz.n->0x2C [loop]; +0x3b bbsi->0x24 [loop]; +0x44 j->0x2C [loop]; +0x5f beqz.n->0x5B [loop]; +0x65 bbci->0x55 [loop]; +0x73 j->0x5B [loop] */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    cleanup_peer_list(0, 0, 0, 0, 0, 0);  /* ordered call */
    esf_buf_recycle(0, 0, 0, 0, 0, 0);  /* ordered call */
    memset(0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_send_followup_msg @ ieee80211_nan_sd.o 00000030 size 301B bind GLOBAL
 * Calls: nan_get_clust_id, nan_get_service_by_id, memcmp, nan_is_pmf_enabled, nan_alloc_sdf, wifi_log, nan_construct_followup_sdf, nan_tx_action_frame | Data refs: s_wfa_oui, s_ni, .rodata_wlog_error.27
 * Fidelity: medium - small frame, 8 calls + 16 branches mapped (backward-edge marks kept; predicates opaque; verified against section disasm + EXPAND relocs) */
int nan_send_followup_msg(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,80; early arg regs: a2, a3, a4, a6 */
    /* struct offsets touched: 8, 12, 16, 20, 32, 36, 40, 44, 120 */
    /* immediates: 0, -1, 29, 35, 1, 255, 3, 8, 4, 2, 16, 0x101 */
    /* branches: +0x5e bne->0x34 [loop]; +0x61 j->0x129; +0x69 beq->0x42 [loop]; +0x76 beqz.n->0x51 [loop]; +0x7b beqz->0x51 [loop]; +0x88 beq->0x8E; +0x8b beq->0x8E; +0x91 bltu->0x8A [loop]; +0xa4 bnez.n->0x82 [loop]; +0xaf bbci->0x8A [loop] (+6 more) */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    nan_get_clust_id(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_get_service_by_id(0, 0, 0, 0, 0, 0);  /* ordered call */
    memcmp(0, 0, 0);  /* ordered call */
    nan_is_pmf_enabled(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_alloc_sdf(0, 0, 0, 0, 0, 0);  /* ordered call */
    wifi_log(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_construct_followup_sdf(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_tx_action_frame(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* Notable rodata/log strings in this object (grounded, from Contents sections):
 *   [.text.nan_svc_compute_csid_bitmap] "6A...........8.."
 *   [.text.nan_svc_compute_csid_bitmap] "-.........." ..8"
 *   [.text.nan_svc_compute_csid_bitmap] ".)..."
 *   [.text.nan_add_vendor_ie] "............6A.."
 *   [.text.nan_add_vendor_ie] "................"
 *   [.text.nan_add_vendor_ie] "....S..........."
 *   [.text.nan_add_vendor_ie] "........;..B...."
 *   [.text.nan_add_vendor_ie] "..t.B..B.. ....."
 *   [.text.nan_add_vendor_ie] "...B.. .....B.k."
 *   [.text.nan_add_vendor_ie] ".B.. .....#. ..."
 *   [.text.nan_add_vendor_ie] "...."..k".."
 *   [.text.nan_prepare_filter] "................"
 *   [.text.nan_prepare_filter] "....6A.........."
 *   [.text.nan_prepare_filter] "....}.m........."
 *   [.text.nan_prepare_filter] ".....M.f.....M.."
 *   [.text.nan_prepare_filter] "...J..R*#BB.. .."
 *   [.text.nan_prepare_filter] "$Z.@. p. . ....."
 *   [.text.nan_prepare_filter] "..@U............"
 *   [.text.nan_prepare_filter] "}.-.VW.  t.."
 *   [.text.nan_all_wildcard_filter] "6A. .t......'..'"
 *   [.text.nan_all_wildcard_filter] "........2..0)."
 *   [.text.nan_all_wildcard_filter] "tF...#"........V"
 *   [.text.nan_all_wildcard_filter] "............"
 *   [.text.nan_construct_sdea] "............6A.."
 *   [.text.nan_construct_sdea] "8P.t..RB..Rpp..B"
 */
