/* Reconstructed ESP32 WiFi MAC data-path: ieee80211_scan.o
 * Blob: esp32/libnet80211.a(ieee80211_scan.o) -> /tmp/re_esp32/libnet80211/ieee80211_scan.o
 * Metadata: re/esp32/funcdb_libnet80211.json | Disasm: re/esp32/disasm_full/libnet80211/ieee80211_scan.dis
 * Toolchain: xtensa-esp-elf esp-15.2.0_20251204 (GCC crosstool-NG esp-2022r1 11.2.0) | ABI: args a2..a7, return a2
 * Method: fully offline; calls/refs/offsets/constants cited from disasm sections;
 * funcdb calls[]/refs[] are empty for this lib, so headers below use disasm-observed edges.
 * Undefined (imports): chm_acquire_lock, chm_cancel_op, chm_get_chan_info, chm_get_channel_index, chm_get_current_channel, chm_get_home_channel, chm_release_lock, chm_return_home_channel, chm_start_op, cnx_add_rc, cnx_bss_alloc, cnx_bss_init, cnx_check_bssid_in_blacklist, cnx_rc_search, cnx_rc_update_age, cnx_rc_update_rssi, cnx_rc_update_state_metric, cnx_update_bss, cnx_update_bss_more, g_authmode_incompatible, g_authmode_threshold_failure, g_chm, g_ic, g_in_blacklist_flag...
 */
/* Common decompilation notes (all files in this directory):
 * - Xtensa ABI: incoming args a2..a7, return value in a2. `entry a1,N` = stack frame N bytes.
 * - ebuf (esfbuf) layout observed via disasm: word at +0 (flags/refcnt?), +4 (data/len ptr),
 *   +20/+22 (u16 length fields, see s16i/l16ui pairs), +44 (priv/control word).
 * - 802.11 header offsets used below: +0 FC, +2 duration, +4 addr1, +10 addr2,
 *   +16 addr3, +22 len/seqctl, +24 seqctl/addr4/QoS, +26 QoS/HT.
 * - Key PN/counter words observed at key+152 (low32) / key+156 (high32),
 *   key bytes at +153/+154/+155/+158/+159 (l8ui/s8i sequences in *_encap).
 * - `Calls:`/`Data refs:` in each header are observed in that function's
 *   disasm section (R_XTENSA_ASM_EXPAND / R_XTENSA_32), NOT the empty
 *   funcdb calls[]/refs[] (funcdb has no per-function edges for this lib).
 * - Constants appear literally in disasm (movi/extui/slli/mask immediates).
 */
#include <stdint.h>
#include <string.h>
/* Additional imports observed in detailed paths (unspecified args): */
extern int sta_get_owe_data();
extern int sta_support_auto_mode_connect_passive_channel_hidden_ap();
extern int wifi_gpio_debug();
extern int wifi_log();
extern int wifi_nvs_commit();
extern int wifi_nvs_set();
extern int wifi_set_rx_policy();
/* Forward declarations for intra-object calls (definitions follow in funcdb order): */
int cannel_scan_connect_state(void *a2, void *a3, unsigned a4, unsigned a5);
int cannel_scan_connect_state(void *a2, void *a3, unsigned a4, unsigned a5);
int check_bss_queue(void *a2, void *a3, unsigned a4, unsigned a5);
int check_bss_queue(void *a2, void *a3, unsigned a4, unsigned a5);
int clear_bss_queue(void *a2, void *a3, unsigned a4, unsigned a5);
int clear_bss_queue(void *a2, void *a3, unsigned a4, unsigned a5);
int cnx_get_authtype_strength(void *a2, void *a3, unsigned a4, unsigned a5);
int cnx_get_authtype_strength(void *a2, void *a3, unsigned a4, unsigned a5);
int free_bss_info(void *a2, void *a3, unsigned a4, unsigned a5);
int free_bss_info(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_cipher_name(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_cipher_name(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_scan_attach(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_scan_attach(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_scan_deattach(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_scan_deattach(void *a2, void *a3, unsigned a4, unsigned a5);
int owe_trans_data_del(void *a2, void *a3, unsigned a4, unsigned a5);
int owe_trans_data_del(void *a2, void *a3, unsigned a4, unsigned a5);
int scan_add_bssid(void *a2, void *a3, unsigned a4, unsigned a5);
int scan_add_bssid(void *a2, void *a3, unsigned a4, unsigned a5);
int scan_add_probe_ssid(void *a2, void *a3, unsigned a4, unsigned a5);
int scan_add_probe_ssid(void *a2, void *a3, unsigned a4, unsigned a5);
int scan_bitmap_to_channel_list(void *a2, void *a3, unsigned a4, unsigned a5);
int scan_bitmap_to_channel_list(void *a2, void *a3, unsigned a4, unsigned a5);
int scan_build_chan_list(void *a2, void *a3, unsigned a4, unsigned a5);
int scan_build_chan_list(void *a2, void *a3, unsigned a4, unsigned a5);
int scan_cancel(void *a2, void *a3, unsigned a4, unsigned a5);
int scan_cancel(void *a2, void *a3, unsigned a4, unsigned a5);
int scan_check_hidden(void *a2, void *a3, unsigned a4, unsigned a5);
int scan_check_hidden(void *a2, void *a3, unsigned a4, unsigned a5);
int scan_connect_state(void *a2, void *a3, unsigned a4, unsigned a5);
int scan_connect_state(void *a2, void *a3, unsigned a4, unsigned a5);
int scan_enter_oper_channel_handler(void *a2, void *a3, unsigned a4, unsigned a5);
int scan_enter_oper_channel_handler(void *a2, void *a3, unsigned a4, unsigned a5);
int scan_enter_oper_channel_process(void *a2, void *a3, unsigned a4, unsigned a5);
int scan_enter_oper_channel_process(void *a2, void *a3, unsigned a4, unsigned a5);
int scan_fill_wps_scan_ie(void *a2, void *a3, unsigned a4, unsigned a5);
int scan_fill_wps_scan_ie(void *a2, void *a3, unsigned a4, unsigned a5);
int scan_flush_all_tx_buf(void *a2, void *a3, unsigned a4, unsigned a5);
int scan_flush_all_tx_buf(void *a2, void *a3, unsigned a4, unsigned a5);
int scan_get_apnum(void *a2, void *a3, unsigned a4, unsigned a5);
int scan_get_apnum(void *a2, void *a3, unsigned a4, unsigned a5);
int scan_get_scan_id(void *a2, void *a3, unsigned a4, unsigned a5);
int scan_get_scan_id(void *a2, void *a3, unsigned a4, unsigned a5);
int scan_get_type(void *a2, void *a3, unsigned a4, unsigned a5);
int scan_get_type(void *a2, void *a3, unsigned a4, unsigned a5);
int scan_inter_channel_timeout_process(void *a2, void *a3, unsigned a4, unsigned a5);
int scan_inter_channel_timeout_process(void *a2, void *a3, unsigned a4, unsigned a5);
int scan_owe_pref_chan(void *a2, void *a3, unsigned a4, unsigned a5);
int scan_owe_pref_chan(void *a2, void *a3, unsigned a4, unsigned a5);
int scan_parse_beacon(void *a2, void *a3, unsigned a4, unsigned a5);
int scan_parse_beacon(void *a2, void *a3, unsigned a4, unsigned a5);
int scan_parse_ht2040_coex(void *a2, void *a3, unsigned a4, unsigned a5);
int scan_parse_ht2040_coex(void *a2, void *a3, unsigned a4, unsigned a5);
int scan_pm_channel_op_cb(void *a2, void *a3, unsigned a4, unsigned a5);
int scan_pm_channel_op_cb(void *a2, void *a3, unsigned a4, unsigned a5);
int scan_pm_offchan(void *a2, void *a3, unsigned a4, unsigned a5);
int scan_pm_offchan(void *a2, void *a3, unsigned a4, unsigned a5);
int scan_prefer_chan(void *a2, void *a3, unsigned a4, unsigned a5);
int scan_prefer_chan(void *a2, void *a3, unsigned a4, unsigned a5);
int scan_profile_check(void *a2, void *a3, unsigned a4, unsigned a5);
int scan_profile_check(void *a2, void *a3, unsigned a4, unsigned a5);
int scan_remove_bssid(void *a2, void *a3, unsigned a4, unsigned a5);
int scan_remove_bssid(void *a2, void *a3, unsigned a4, unsigned a5);
int scan_remove_probe_ssid(void *a2, void *a3, unsigned a4, unsigned a5);
int scan_remove_probe_ssid(void *a2, void *a3, unsigned a4, unsigned a5);
int scan_reset_cipher_and_akm(void *a2, void *a3, unsigned a4, unsigned a5);
int scan_reset_cipher_and_akm(void *a2, void *a3, unsigned a4, unsigned a5);
int scan_reset_default_app_params(void *a2, void *a3, unsigned a4, unsigned a5);
int scan_reset_default_app_params(void *a2, void *a3, unsigned a4, unsigned a5);
int scan_reset_offchan_duration(void *a2, void *a3, unsigned a4, unsigned a5);
int scan_reset_offchan_duration(void *a2, void *a3, unsigned a4, unsigned a5);
int scan_set_act_duration(void *a2, void *a3, unsigned a4, unsigned a5);
int scan_set_act_duration(void *a2, void *a3, unsigned a4, unsigned a5);
int scan_set_current_scan_times(void *a2, void *a3, unsigned a4, unsigned a5);
int scan_set_current_scan_times(void *a2, void *a3, unsigned a4, unsigned a5);
int scan_set_default_params(void *a2, void *a3, unsigned a4, unsigned a5);
int scan_set_default_params(void *a2, void *a3, unsigned a4, unsigned a5);
int scan_set_desChan(void *a2, void *a3, unsigned a4, unsigned a5);
int scan_set_desChan(void *a2, void *a3, unsigned a4, unsigned a5);
int scan_set_home_chan_dwell_time(void *a2, void *a3, unsigned a4, unsigned a5);
int scan_set_home_chan_dwell_time(void *a2, void *a3, unsigned a4, unsigned a5);
int scan_set_max_offchan_duration(void *a2, void *a3, unsigned a4, unsigned a5);
int scan_set_max_offchan_duration(void *a2, void *a3, unsigned a4, unsigned a5);
int scan_set_pas_duration(void *a2, void *a3, unsigned a4, unsigned a5);
int scan_set_pas_duration(void *a2, void *a3, unsigned a4, unsigned a5);
int scan_set_scan_id(void *a2, void *a3, unsigned a4, unsigned a5);
int scan_set_scan_id(void *a2, void *a3, unsigned a4, unsigned a5);
int scan_start(void *a2, void *a3, unsigned a4, unsigned a5);
int scan_start(void *a2, void *a3, unsigned a4, unsigned a5);
int scan_start_handler(void *a2, void *a3, unsigned a4, unsigned a5);
int scan_start_handler(void *a2, void *a3, unsigned a4, unsigned a5);
int scan_update_scan_history(void *a2, void *a3, unsigned a4, unsigned a5);
int scan_update_scan_history(void *a2, void *a3, unsigned a4, unsigned a5);
int wifi_sta_set_scan_default_params(void *a2, void *a3, unsigned a4, unsigned a5);
int wifi_sta_set_scan_default_params(void *a2, void *a3, unsigned a4, unsigned a5);

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long u64;
struct ebuf { u32 w0; u32 _r1; void *data; u32 _r2[3]; u16 len20; u16 len22; u32 _r3[5]; u32 w44; };
struct ic { u32 _pad[128]; };
struct node { u8 mac[6]; };
struct key { u32 _pad[38]; u32 pn_lo; /* +152 */ u32 pn_hi; /* +156 */ };
extern struct ic *g_ic;
extern void *g_osi_funcs_p;
extern void *g_scan;
extern void *g_chm;

/* Observed callees (declarations with unspecified args; definitions follow where local): */
extern int chm_acquire_lock();
extern int chm_cancel_op();
extern int chm_get_chan_info();
extern int chm_get_channel_index();
extern int chm_get_current_channel();
extern int chm_get_home_channel();
extern int chm_release_lock();
extern int chm_return_home_channel();
extern int chm_start_op();
extern int cnx_add_rc();
extern int cnx_bss_alloc();
extern int cnx_bss_init();
extern int cnx_check_bssid_in_blacklist();
extern int cnx_rc_search();
extern int cnx_rc_update_age();
extern int cnx_rc_update_rssi();
extern int cnx_rc_update_state_metric();
extern int cnx_update_bss();
extern int cnx_update_bss_more();
extern int hal_get_tsf_time();
extern int hal_now();
extern int ic_ebuf_recycle_tx();
extern int ic_tx_pkt();
extern int ieee80211_amsdu_negotiate();
extern int ieee80211_parse_rsn();
extern int ieee80211_parse_wapi();
extern int ieee80211_parse_wpa();
extern int ieee80211_regdomain_chan_in_range();
extern int ieee80211_regdomain_is_active_scan();
extern int ieee80211_regdomain_update_in_scan();
extern int ieee80211_send_probereq();
extern int ieee80211_timer_process();
extern int pm_coex_customized_wifi_time_slice();
extern int pm_coex_update_wifi_time_slice_state();
extern int pm_is_force_return_home_chan();
extern int pm_is_open();
extern int pm_offchan_execute_ready_cb();
extern int pm_offchan_is_waiting();
extern int pm_offchan_ready_or_defer();
extern int pm_on_channel();
extern int pm_on_coex_schm_process_restart();
extern int pm_on_coex_schm_status_config();

/* cannel_scan_connect_state @ ieee80211_scan.o 00000008 size 25B bind GLOBAL
 * Calls: none | Data refs: g_ic
 * Fidelity: high - leaf; full insn sequence captured, no hidden control flow */
/* disasm section: .text.cannel_scan_connect_state */
int cannel_scan_connect_state(void *a2, void *a3, unsigned a4, unsigned a5);
int cannel_scan_connect_state(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 32B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed branches: bbcix1 */
  /* observed memory traffic (first 2): */
    /* l32i.n a8, a9, -- 28: HT */
    /* s32i a8, a9, -- 28: HT */
  /* observed calls: none (leaf) */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[8] = *(u32 *)(((u8 *)0) + 28); /* l32i.n a8,a9+28 → +28: HT */
  *(u32 *)(((u8 *)0) + 28) = regs[8]; /* s32i a8,a9+28 → +28: HT */
  /* no calls observed: leaf */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* check_bss_queue @ ieee80211_scan.o 00000010 size 80B bind GLOBAL
 * Calls: memcmp | Data refs: g_wifi_global_lock, g_osi_funcs_p, g_ic, memcmp
 * Fidelity: medium - call order + branch skeleton from disasm; some field names inferred */
/* disasm section: .text.check_bss_queue */
int check_bss_queue(void *a2, void *a3, unsigned a4, unsigned a5);
int check_bss_queue(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 32B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 6, 1 */
  /* observed branches: bnez.nx1 */
  /* observed memory traffic (first 10): */
    /* l32i.n a3, a5, -- 0: frame control */
    /* l32i.n a10, a4, -- 0: frame control */
    /* l32i a3, a3, -- off 84 */
    /* l32i a3, a3, -- 0x130: ic/eb control word */
    /* l32i.n a2, a5, -- 0: frame control */
    /* l32i.n a10, a4, -- 0: frame control */
    /* l32i a2, a2, -- off 88 */
    /* l32i.n a3, a3, -- 0: frame control */
    /* l32i.n a2, a5, -- 0: frame control */
    /* l32i.n a10, a4, -- 0: frame control */
  /* observed call sequence (in order): memcmp */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[3] = *(u32 *)((u8 *)(uintptr_t)a4 + 0); /* l32i.n a3,a5+0 → +0: frame control */
  regs[1] = *(u32 *)(eb8 + 0); /* l32i.n a10,a4+0 → +0: frame control */
  regs[3] = *(u32 *)((u8 *)a3 + 84); /* l32i a3,a3+84 → +84:  */
  regs[3] = *(u32 *)((u8 *)a3 + 304); /* l32i a3,a3+304 → +304: ic/eb control word */
  regs[2] = *(u32 *)((u8 *)(uintptr_t)a4 + 0); /* l32i.n a2,a5+0 → +0: frame control */
  regs[1] = *(u32 *)(eb8 + 0); /* l32i.n a10,a4+0 → +0: frame control */
  (void)((int(*)())memcmp)(); /* observed call (disasm order; args a2..a5) */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* clear_bss_queue @ ieee80211_scan.o 00000020 size 95B bind GLOBAL
 * Calls: wifi_log, free_bss_info | Data refs: .rodata_wlog_debug.100, g_wifi_global_lock, g_osi_funcs_p, g_ic, g_ic+0x130, scannum, wifi_log, free_bss_info
 * Fidelity: medium - call order + branch skeleton from disasm; some field names inferred */
/* disasm section: .text.clear_bss_queue */
int clear_bss_queue(void *a2, void *a3, unsigned a4, unsigned a5);
int clear_bss_queue(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 32B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 4, 8, 1 */
  /* observed memory traffic (first 10): */
    /* l32i.n a2, a4, -- 0: frame control */
    /* l32i.n a10, a3, -- 0: frame control */
    /* l32i a2, a2, -- off 84 */
    /* l32i.n a8, a10, -- 0: frame control */
    /* s32i a8, a2, -- 0x130: ic/eb control word */
    /* s32i a8, a2, -- off 0x134 */
    /* l32i a10, a2, -- 0x130: ic/eb control word */
    /* s16i a10, a2, -- 0: frame control */
    /* l32i.n a2, a4, -- 0: frame control */
    /* l32i.n a10, a3, -- 0: frame control */
  /* observed call sequence (in order): wifi_log -> free_bss_info */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[2] = *(u32 *)(eb8 + 0); /* l32i.n a2,a4+0 → +0: frame control */
  regs[1] = *(u32 *)((u8 *)a3 + 0); /* l32i.n a10,a3+0 → +0: frame control */
  regs[2] = *(u32 *)((u8 *)a2 + 84); /* l32i a2,a2+84 → +84:  */
  regs[8] = *(u32 *)(((u8 *)0) + 0); /* l32i.n a8,a10+0 → +0: frame control */
  *(u32 *)((u8 *)a2 + 304) = regs[8]; /* s32i a8,a2+304 → +304: ic/eb control word */
  *(u32 *)((u8 *)a2 + 308) = regs[8]; /* s32i a8,a2+308 → +308:  */
  (void)((int(*)())wifi_log)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())free_bss_info)(); /* observed call (disasm order; args a2..a5) */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* cnx_get_authtype_strength @ ieee80211_scan.o 00000004 size 26B bind GLOBAL
 * Calls: none | Data refs: .rodata.CSWTCH$531
 * Fidelity: high - leaf; full insn sequence captured, no hidden control flow */
/* disasm section: .text.cnx_get_authtype_strength */
int cnx_get_authtype_strength(void *a2, void *a3, unsigned a4, unsigned a5);
int cnx_get_authtype_strength(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 32B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 17, -1 */
  /* observed branches: bltux1 */
  /* observed memory traffic (first 1): */
    /* l8ui a2, a8, -- 0: frame control */
  /* observed calls: none (leaf) */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[2] = *(u8 *)(((u8 *)0) + 0); /* l8ui → +0: frame control */
  /* no calls observed: leaf */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* free_bss_info @ ieee80211_scan.o 0000000c size 64B bind GLOBAL
 * Calls: wifi_log | Data refs: .rodata_wlog_debug.99, g_osi_funcs_p, wifi_log
 * Fidelity: medium - call order + branch skeleton from disasm; some field names inferred */
/* disasm section: .text.free_bss_info */
int free_bss_info(void *a2, void *a3, unsigned a4, unsigned a5);
int free_bss_info(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 32B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 4, 8, 1 */
  /* observed branches: bnez.nx1, beqz.nx2 */
  /* observed memory traffic (first 8): */
    /* l32i.n a10, a2, -- off 52 */
    /* l32i.n a8, a3, -- 0: frame control */
    /* l32i a8, a8, -- off 176 */
    /* l32i.n a10, a2, -- off 56 */
    /* l32i.n a8, a3, -- 0: frame control */
    /* l32i a8, a8, -- off 176 */
    /* l32i.n a3, a3, -- 0: frame control */
    /* l32i a3, a3, -- off 176 */
  /* observed call sequence (in order): wifi_log */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[1] = *(u32 *)((u8 *)a2 + 52); /* l32i.n a10,a2+52 → +52:  */
  regs[8] = *(u32 *)((u8 *)a3 + 0); /* l32i.n a8,a3+0 → +0: frame control */
  regs[8] = *(u32 *)(((u8 *)0) + 176); /* l32i a8,a8+176 → +176:  */
  regs[1] = *(u32 *)((u8 *)a2 + 56); /* l32i.n a10,a2+56 → +56:  */
  regs[8] = *(u32 *)((u8 *)a3 + 0); /* l32i.n a8,a3+0 → +0: frame control */
  regs[8] = *(u32 *)(((u8 *)0) + 176); /* l32i a8,a8+176 → +176:  */
  (void)((int(*)())wifi_log)(); /* observed call (disasm order; args a2..a5) */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* ieee80211_cipher_name @ ieee80211_scan.o 00000008 size 23B bind GLOBAL
 * Calls: none | Data refs: .rodata.ieee80211_cipher_name.str1.1, .rodata.CSWTCH$533
 * Fidelity: high - leaf; full insn sequence captured, no hidden control flow */
/* disasm section: .text.ieee80211_cipher_name */
int ieee80211_cipher_name(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_cipher_name(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 32B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 32 */
  /* observed branches: bltux1 */
  /* observed memory traffic (first 1): */
    /* l32i.n a2, a8, -- 0: frame control */
  /* observed calls: none (leaf) */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[2] = *(u32 *)(((u8 *)0) + 0); /* l32i.n a2,a8+0 → +0: frame control */
  /* no calls observed: leaf */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* ieee80211_scan_attach @ ieee80211_scan.o 00000020 size 170B bind GLOBAL
 * Calls: scan_reset_default_app_params, wifi_log | Data refs: g_scan, .data.g_scan_chan_list, .text.scan_inter_channel_timeout, g_osi_funcs_p, .text.scan_enter_oper_channel, .rodata_wlog_verbose.2, scan_reset_default_app_params, wifi_log
 * Fidelity: medium - call order + offsets from disasm; straight-line details summarised */
/* disasm section: .text.ieee80211_scan_attach */
int ieee80211_scan_attach(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_scan_attach(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 48B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 0, -1, 30, 120, 14, 5, 9, 1 */
  /* observed memory traffic (first 10): */
    /* l32i.n a8, a4, -- 0: frame control */
    /* s32i.n a8, a2, -- 4: addr1 */
    /* s32i.n a5, a8, -- off 56 */
    /* s8i a3, a8, -- 155: key PN/counter region */
    /* s32i.n a3, a8, -- off 48 */
    /* s32i a5, a8, -- off 76 */
    /* s32i.n a3, a8, -- off 52 */
    /* s8i a3, a8, -- off 163 */
    /* s8i a5, a8, -- off 72 */
    /* s8i a3, a5, -- 16: addr3 */
  /* observed call sequence (in order): scan_reset_default_app_params -> wifi_log */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[8] = *(u32 *)(eb8 + 0); /* l32i.n a8,a4+0 → +0: frame control */
  *(u32 *)((u8 *)a2 + 4) = regs[8]; /* s32i.n a8,a2+4 → +4: addr1 */
  *(u32 *)(((u8 *)0) + 56) = regs[5]; /* s32i.n a5,a8+56 → +56:  */
  *(u8 *)(((u8 *)0) + 155) = (u8)regs[3]; /* s8i → +155: key PN/counter region */
  *(u32 *)(((u8 *)0) + 48) = regs[3]; /* s32i.n a3,a8+48 → +48:  */
  *(u32 *)(((u8 *)0) + 76) = regs[5]; /* s32i a5,a8+76 → +76:  */
  (void)((int(*)())scan_reset_default_app_params)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())wifi_log)(); /* observed call (disasm order; args a2..a5) */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* ieee80211_scan_deattach @ ieee80211_scan.o 00000008 size 36B bind GLOBAL
 * Calls: none | Data refs: g_scan, g_osi_funcs_p
 * Fidelity: high - leaf; full insn sequence captured, no hidden control flow */
/* disasm section: .text.ieee80211_scan_deattach */
int ieee80211_scan_deattach(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_scan_deattach(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 32B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed memory traffic (first 6): */
    /* l32i.n a8, a2, -- 0: frame control */
    /* l32i.n a10, a3, -- 0: frame control */
    /* l32i a8, a8, -- off 240 */
    /* l32i.n a2, a2, -- 0: frame control */
    /* l32i.n a10, a3, -- 0: frame control */
    /* l32i a2, a2, -- off 240 */
  /* observed calls: none (leaf) */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[8] = *(u32 *)((u8 *)a2 + 0); /* l32i.n a8,a2+0 → +0: frame control */
  regs[1] = *(u32 *)((u8 *)a3 + 0); /* l32i.n a10,a3+0 → +0: frame control */
  regs[8] = *(u32 *)(((u8 *)0) + 240); /* l32i a8,a8+240 → +240:  */
  regs[2] = *(u32 *)((u8 *)a2 + 0); /* l32i.n a2,a2+0 → +0: frame control */
  regs[1] = *(u32 *)((u8 *)a3 + 0); /* l32i.n a10,a3+0 → +0: frame control */
  regs[2] = *(u32 *)((u8 *)a2 + 240); /* l32i a2,a2+240 → +240:  */
  /* no calls observed: leaf */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* owe_trans_data_del @ ieee80211_scan.o 0000001c size 90B bind GLOBAL
 * Calls: sta_get_owe_data, memcmp, memset, wifi_nvs_set, wifi_nvs_commit | Data refs: g_wifi_nvs, g_ic, sta_get_owe_data, memcmp, memset, wifi_nvs_set, wifi_nvs_commit
 * Fidelity: medium - call order + offsets from disasm; straight-line details summarised */
/* disasm section: .text.owe_trans_data_del */
int owe_trans_data_del(void *a2, void *a3, unsigned a4, unsigned a5);
int owe_trans_data_del(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 32B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 0, 88, 1, 46 */
  /* observed branches: bnex2, bnez.nx1 */
  /* observed memory traffic (first 4): */
    /* l32i.n a10, a2, -- 0: frame control */
    /* l32i.n a8, a3, -- off 36 */
    /* l32i.n a12, a10, -- 4: addr1 */
    /* l8ui a8, a8, -- off 31 */
  /* observed call sequence (in order): sta_get_owe_data -> memcmp -> memset -> wifi_nvs_set -> wifi_nvs_commit */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[1] = *(u32 *)((u8 *)a2 + 0); /* l32i.n a10,a2+0 → +0: frame control */
  regs[8] = *(u32 *)((u8 *)a3 + 36); /* l32i.n a8,a3+36 → +36:  */
  regs[1] = *(u32 *)(((u8 *)0) + 4); /* l32i.n a12,a10+4 → +4: addr1 */
  regs[8] = *(u8 *)(((u8 *)0) + 31); /* l8ui → +31:  */
  (void)((int(*)())sta_get_owe_data)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())memcmp)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())memset)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())wifi_nvs_set)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())wifi_nvs_commit)(); /* observed call (disasm order; args a2..a5) */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* scan_add_bssid @ ieee80211_scan.o 00000008 size 37B bind GLOBAL
 * Calls: memcpy | Data refs: g_scan, memcpy
 * Fidelity: high - leaf; full insn sequence captured, no hidden control flow */
/* disasm section: .text.scan_add_bssid */
int scan_add_bssid(void *a2, void *a3, unsigned a4, unsigned a5);
int scan_add_bssid(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 32B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 156, 6, 1 */
  /* observed memory traffic (first 2): */
    /* l32i.n a3, a3, -- 0: frame control */
    /* s8i a8, a3, -- off 162 */
  /* observed call sequence (in order): memcpy */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[3] = *(u32 *)((u8 *)a3 + 0); /* l32i.n a3,a3+0 → +0: frame control */
  *(u8 *)((u8 *)a3 + 162) = (u8)regs[8]; /* s8i → +162:  */
  (void)((int(*)())memcpy)(); /* observed call (disasm order; args a2..a5) */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* scan_add_probe_ssid @ ieee80211_scan.o 0000000c size 102B bind GLOBAL
 * Calls: memset, memcpy | Data refs: g_scan, memset, memcpy
 * Fidelity: medium - call order + branch skeleton from disasm; some field names inferred */
/* disasm section: .text.scan_add_probe_ssid */
int scan_add_probe_ssid(void *a2, void *a3, unsigned a4, unsigned a5);
int scan_add_probe_ssid(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 32B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 0, 32 */
  /* observed branches: bneix1, bltux1 */
  /* observed memory traffic (first 5): */
    /* l32i a10, a7, -- 0: frame control */
    /* s32i a4, a6, -- off 80 */
    /* l32i.n a10, a7, -- 0: frame control */
    /* l32i.n a6, a3, -- 0: frame control */
    /* s8i a5, a6, -- 152: key PN/counter region */
  /* observed call sequence (in order): memset -> memcpy */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[1] = *(u32 *)(((u8 *)0) + 0); /* l32i a10,a7+0 → +0: frame control */
  *(u32 *)(eb8 + 80) = regs[4]; /* s32i a4,a6+80 → +80:  */
  regs[1] = *(u32 *)(((u8 *)0) + 0); /* l32i.n a10,a7+0 → +0: frame control */
  regs[6] = *(u32 *)((u8 *)a3 + 0); /* l32i.n a6,a3+0 → +0: frame control */
  *(u8 *)(eb8 + 152) = (u8)regs[5]; /* s8i → +152: key PN/counter region */
  (void)((int(*)())memset)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())memcpy)(); /* observed call (disasm order; args a2..a5) */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* scan_bitmap_to_channel_list @ ieee80211_scan.o 00000050 size 415B bind GLOBAL
 * Calls: wifi_log | Data refs: g_ic, .rodata_wlog_warning.56, .rodata_wlog_warning.57, .rodata_wlog_warning.58, .rodata_wlog_warning.59, .rodata_wlog_warning.60, .rodata_wlog_warning.61, .rodata_wlog_error.62, .rodata_wlog_error.63, g_scan
 * Fidelity: medium - call order + offsets from disasm; straight-line details summarised */
/* disasm section: .text.scan_bitmap_to_channel_list */
int scan_bitmap_to_channel_list(void *a2, void *a3, unsigned a4, unsigned a5);
int scan_bitmap_to_channel_list(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 32B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 2, 8, 0, 1, 4, -1, -2, 14, 36, 11 */
  /* observed branches: bneix2, bnez.nx4, bbcix1, bbsix1, beqx2, banyx1, beqz.nx1, bnonex1 */
  /* observed memory traffic (first 7): */
    /* l8ui a10, a4, -- off 173 */
    /* l32i.n a4, a12, -- 0: frame control */
    /* l32i a13, a4, -- off 76 */
    /* s8i a5, a8, -- 0: frame control */
    /* s8i a9, a8, -- 0: frame control */
    /* l32i.n a2, a12, -- 0: frame control */
    /* s8i a8, a2, -- off 72 */
  /* observed call sequence (in order): wifi_log */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[1] = *(u8 *)(eb8 + 173); /* l8ui → +173:  */
  regs[4] = *(u32 *)(((u8 *)0) + 0); /* l32i.n a4,a12+0 → +0: frame control */
  regs[1] = *(u32 *)(eb8 + 76); /* l32i a13,a4+76 → +76:  */
  *(u8 *)(((u8 *)0) + 0) = (u8)regs[5]; /* s8i → +0: frame control */
  *(u8 *)(((u8 *)0) + 0) = (u8)regs[9]; /* s8i → +0: frame control */
  regs[2] = *(u32 *)(((u8 *)0) + 0); /* l32i.n a2,a12+0 → +0: frame control */
  (void)((int(*)())wifi_log)(); /* observed call (disasm order; args a2..a5) */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* scan_build_chan_list @ ieee80211_scan.o 0000001c size 222B bind GLOBAL
 * Calls: sta_get_owe_data, chm_get_channel_index, wifi_log | Data refs: g_scan, g_ic, .rodata_wlog_debug.48, .rodata_wlog_debug.49, sta_get_owe_data, chm_get_channel_index, wifi_log
 * Fidelity: medium - call order + offsets from disasm; straight-line details summarised */
/* disasm section: .text.scan_build_chan_list */
int scan_build_chan_list(void *a2, void *a3, unsigned a4, unsigned a5);
int scan_build_chan_list(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 32B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 0, 14, 255, 4, 8, 1 */
  /* observed branches: bbsix1, bltux2, bbcix1, beqx2, bgeux1 */
  /* observed memory traffic (first 10): */
    /* l32i.n a10, a4, -- 0: frame control */
    /* l32i a10, a10, -- off 76 */
    /* s8i a8, a10, -- 0: frame control */
    /* l32i.n a9, a4, -- 0: frame control */
    /* s8i a8, a9, -- off 72 */
    /* l8ui a10, a10, -- 0: frame control */
    /* s8i a10, a2, -- 0: frame control */
    /* l32i.n a2, a4, -- 0: frame control */
    /* l32i a2, a2, -- off 76 */
    /* s8i a3, a2, -- 0: frame control */
  /* observed call sequence (in order): sta_get_owe_data -> chm_get_channel_index -> wifi_log */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[1] = *(u32 *)(eb8 + 0); /* l32i.n a10,a4+0 → +0: frame control */
  regs[1] = *(u32 *)(((u8 *)0) + 76); /* l32i a10,a10+76 → +76:  */
  *(u8 *)(((u8 *)0) + 0) = (u8)regs[8]; /* s8i → +0: frame control */
  regs[9] = *(u32 *)(eb8 + 0); /* l32i.n a9,a4+0 → +0: frame control */
  *(u8 *)(((u8 *)0) + 72) = (u8)regs[8]; /* s8i → +72:  */
  regs[1] = *(u8 *)(((u8 *)0) + 0); /* l8ui → +0: frame control */
  (void)((int(*)())sta_get_owe_data)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())chm_get_channel_index)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())wifi_log)(); /* observed call (disasm order; args a2..a5) */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* scan_cancel @ ieee80211_scan.o 00000020 size 171B bind GLOBAL
 * Calls: wifi_log, chm_cancel_op, .text.scan_set_global_scan_times$constprop$0, scan_reset_offchan_duration | Data refs: g_scan, .rodata_wlog_debug.27, g_osi_funcs_p, g_ic, wifi_log, chm_cancel_op, .text.scan_set_global_scan_times$constprop$0, scan_reset_offchan_duration
 * Fidelity: medium - call order + offsets from disasm; straight-line details summarised */
/* disasm section: .text.scan_cancel */
int scan_cancel(void *a2, void *a3, unsigned a4, unsigned a5);
int scan_cancel(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 32B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 4, 8, 1, 0 */
  /* observed branches: bbsix1, bnez.nx1 */
  /* observed memory traffic (first 10): */
    /* l32i.n a3, a2, -- 0: frame control */
    /* l8ui a14, a3, -- off 70 */
    /* l8ui a15, a3, -- off 71 */
    /* l32i.n a5, a2, -- 0: frame control */
    /* s16i a3, a5, -- off 70 */
    /* l32i.n a8, a5, -- 0: frame control */
    /* l32i.n a10, a2, -- 0: frame control */
    /* l32i a8, a8, -- off 236 */
    /* l32i.n a5, a5, -- 0: frame control */
    /* l32i.n a10, a2, -- 0: frame control */
  /* observed call sequence (in order): wifi_log -> chm_cancel_op -> .text.scan_set_global_scan_times$constprop$0+0x8 -> scan_reset_offchan_duration */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[3] = *(u32 *)((u8 *)a2 + 0); /* l32i.n a3,a2+0 → +0: frame control */
  regs[1] = *(u8 *)((u8 *)a3 + 70); /* l8ui → +70:  */
  regs[1] = *(u8 *)((u8 *)a3 + 71); /* l8ui → +71:  */
  regs[5] = *(u32 *)((u8 *)a2 + 0); /* l32i.n a5,a2+0 → +0: frame control */
  *(u16 *)((u8 *)(uintptr_t)a4 + 70) = (u16)regs[3]; /* s16i → +70:  */
  regs[8] = *(u32 *)((u8 *)(uintptr_t)a4 + 0); /* l32i.n a8,a5+0 → +0: frame control */
  (void)((int(*)())wifi_log)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())chm_cancel_op)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())scan_reset_offchan_duration)(); /* observed call (disasm order; args a2..a5) */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* scan_check_hidden @ ieee80211_scan.o 00000000 size 38B bind GLOBAL
 * Calls: none | Data refs: none
 * Fidelity: high - leaf; full insn sequence captured, no hidden control flow */
/* disasm section: .text.scan_check_hidden */
int scan_check_hidden(void *a2, void *a3, unsigned a4, unsigned a5);
int scan_check_hidden(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 32B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 1, 0 */
  /* observed branches: beqz.nx1, bnez.nx1, bltux1 */
  /* observed memory traffic (first 2): */
    /* l8ui a9, a2, -- 1: frame control/duration */
    /* l8ui a10, a10, -- 2: duration */
  /* observed calls: none (leaf) */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[9] = *(u8 *)((u8 *)a2 + 1); /* l8ui → +1: frame control/duration */
  regs[1] = *(u8 *)(((u8 *)0) + 2); /* l8ui → +2: duration */
  /* no calls observed: leaf */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* scan_connect_state @ ieee80211_scan.o 00000010 size 63B bind GLOBAL
 * Calls: none | Data refs: g_ic
 * Fidelity: medium - call order + branch skeleton from disasm; some field names inferred */
/* disasm section: .text.cannel_scan_connect_state */
int scan_connect_state(void *a2, void *a3, unsigned a4, unsigned a5);
int scan_connect_state(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 32B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed branches: bbcix1 */
  /* observed memory traffic (first 2): */
    /* l32i.n a8, a9, -- 28: HT */
    /* s32i a8, a9, -- 28: HT */
  /* observed calls: none (leaf) */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[8] = *(u32 *)(((u8 *)0) + 28); /* l32i.n a8,a9+28 → +28: HT */
  *(u32 *)(((u8 *)0) + 28) = regs[8]; /* s32i a8,a9+28 → +28: HT */
  /* no calls observed: leaf */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* scan_enter_oper_channel_handler @ ieee80211_scan.o 0000000c size 36B bind GLOBAL
 * Calls: wifi_log, .text.scan_next_channel | Data refs: .rodata_wlog_debug.51, wifi_log, .text.scan_next_channel
 * Fidelity: medium - call order + branch skeleton from disasm; some field names inferred */
/* disasm section: .text.scan_enter_oper_channel_handler */
int scan_enter_oper_channel_handler(void *a2, void *a3, unsigned a4, unsigned a5);
int scan_enter_oper_channel_handler(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 32B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 8, 1 */
  /* observed branches: bneix1 */
  /* observed call sequence (in order): wifi_log -> .text.scan_next_channel+0x68 */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  (void)((int(*)())wifi_log)(); /* observed call (disasm order; args a2..a5) */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* scan_enter_oper_channel_process @ ieee80211_scan.o 00000018 size 51B bind GLOBAL
 * Calls: hal_now, wifi_log, scan_pm_offchan | Data refs: g_scan, .rodata_wlog_verbose.52, scan_enter_oper_channel_handler, hal_now, wifi_log, scan_pm_offchan
 * Fidelity: medium - call order + branch skeleton from disasm; some field names inferred */
/* disasm section: .text.scan_enter_oper_channel_process */
int scan_enter_oper_channel_process(void *a2, void *a3, unsigned a4, unsigned a5);
int scan_enter_oper_channel_process(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 32B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 1, 5, 8 */
  /* observed branches: bbcix1 */
  /* observed memory traffic (first 2): */
    /* l32i a8, a8, -- 0: frame control */
    /* l8ui a8, a8, -- off 70 */
  /* observed call sequence (in order): hal_now -> wifi_log -> scan_pm_offchan */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[8] = *(u32 *)(((u8 *)0) + 0); /* l32i a8,a8+0 → +0: frame control */
  regs[8] = *(u8 *)(((u8 *)0) + 70); /* l8ui → +70:  */
  (void)((int(*)())hal_now)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())wifi_log)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())scan_pm_offchan)(); /* observed call (disasm order; args a2..a5) */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* scan_fill_wps_scan_ie @ ieee80211_scan.o 00000000 size 49B bind GLOBAL
 * Calls: none | Data refs: none
 * Fidelity: medium - call order + branch skeleton from disasm; some field names inferred */
/* disasm section: .text.scan_fill_wps_scan_ie */
int scan_fill_wps_scan_ie(void *a2, void *a3, unsigned a4, unsigned a5);
int scan_fill_wps_scan_ie(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 32B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 0 */
  /* observed memory traffic (first 10): */
    /* l32i.n a8, a2, -- 0: frame control */
    /* s32i.n a8, a3, -- 0: frame control */
    /* l8ui a8, a2, -- 4: addr1 */
    /* s8i a8, a3, -- 4: addr1 */
    /* l16ui a8, a2, -- 6: 802.11 header region */
    /* s16i a8, a3, -- 6: 802.11 header region */
    /* l32i.n a8, a2, -- off 36 */
    /* s32i.n a8, a3, -- 8: 802.11 header region */
    /* l32i.n a8, a2, -- off 52 */
    /* s32i.n a8, a3, -- 12: 802.11 header region */
  /* observed calls: none (leaf) */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[8] = *(u32 *)((u8 *)a2 + 0); /* l32i.n a8,a2+0 → +0: frame control */
  *(u32 *)((u8 *)a3 + 0) = regs[8]; /* s32i.n a8,a3+0 → +0: frame control */
  regs[8] = *(u8 *)((u8 *)a2 + 4); /* l8ui → +4: addr1 */
  *(u8 *)((u8 *)a3 + 4) = (u8)regs[8]; /* s8i → +4: addr1 */
  regs[8] = *(u16 *)((u8 *)a2 + 6); /* l16ui → +6: 802.11 header region */
  *(u16 *)((u8 *)a3 + 6) = (u16)regs[8]; /* s16i → +6: 802.11 header region */
  /* no calls observed: leaf */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* scan_flush_all_tx_buf @ ieee80211_scan.o 00000020 size 100B bind GLOBAL
 * Calls: wifi_log, ic_tx_pkt, ic_ebuf_recycle_tx | Data refs: .rodata_wlog_verbose.20, g_ic, g_ic+0x1a4, .rodata_wlog_info.21, wifi_log, ic_tx_pkt, ic_ebuf_recycle_tx
 * Fidelity: medium - call order + branch skeleton from disasm; some field names inferred */
/* disasm section: .text.scan_flush_all_tx_buf */
int scan_flush_all_tx_buf(void *a2, void *a3, unsigned a4, unsigned a5);
int scan_flush_all_tx_buf(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 32B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 5, 8, 1, 0, 3, 64 */
  /* observed branches: beqx1 */
  /* observed memory traffic (first 6): */
    /* l32i a8, a4, -- 0x1a4: ic/eb control word */
    /* l32i.n a8, a8, -- off 40 */
    /* s32i a8, a4, -- 0x1a4: ic/eb control word */
    /* s32i a8, a4, -- off 0x1a8 */
    /* s32i.n a8, a3, -- off 40 */
    /* l32i a3, a4, -- 0x1a4: ic/eb control word */
  /* observed call sequence (in order): wifi_log -> ic_tx_pkt -> ic_ebuf_recycle_tx */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[8] = *(u32 *)(eb8 + 420); /* l32i a8,a4+420 → +420: ic/eb control word */
  regs[8] = *(u32 *)(((u8 *)0) + 40); /* l32i.n a8,a8+40 → +40:  */
  *(u32 *)(eb8 + 420) = regs[8]; /* s32i a8,a4+420 → +420: ic/eb control word */
  *(u32 *)(eb8 + 424) = regs[8]; /* s32i a8,a4+424 → +424:  */
  *(u32 *)((u8 *)a3 + 40) = regs[8]; /* s32i.n a8,a3+40 → +40:  */
  regs[3] = *(u32 *)(eb8 + 420); /* l32i a3,a4+420 → +420: ic/eb control word */
  (void)((int(*)())wifi_log)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())ic_tx_pkt)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())ic_ebuf_recycle_tx)(); /* observed call (disasm order; args a2..a5) */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* scan_get_apnum @ ieee80211_scan.o 00000004 size 11B bind GLOBAL
 * Calls: none | Data refs: scannum
 * Fidelity: high - leaf; full insn sequence captured, no hidden control flow */
/* disasm section: .text.scan_get_apnum */
int scan_get_apnum(void *a2, void *a3, unsigned a4, unsigned a5);
int scan_get_apnum(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 32B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed memory traffic (first 1): */
    /* l16ui a2, a8, -- 0: frame control */
  /* observed calls: none (leaf) */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[2] = *(u16 *)(((u8 *)0) + 0); /* l16ui → +0: frame control */
  /* no calls observed: leaf */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* scan_get_scan_id @ ieee80211_scan.o 00000014 size 63B bind GLOBAL
 * Calls: wifi_log | Data refs: g_wifi_global_lock, g_osi_funcs_p, g_scan, .rodata_wlog_verbose.130, wifi_log
 * Fidelity: medium - call order + branch skeleton from disasm; some field names inferred */
/* disasm section: .text.scan_get_scan_id */
int scan_get_scan_id(void *a2, void *a3, unsigned a4, unsigned a5);
int scan_get_scan_id(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 32B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 5, 8, 1 */
  /* observed memory traffic (first 10): */
    /* l32i a2, a5, -- 0: frame control */
    /* l32i.n a10, a4, -- 0: frame control */
    /* l32i a2, a2, -- off 84 */
    /* l32i.n a5, a5, -- 0: frame control */
    /* l32i.n a2, a3, -- 0: frame control */
    /* l32i a5, a5, -- off 88 */
    /* l32i.n a10, a4, -- 0: frame control */
    /* l32i a2, a2, -- off 0x114 */
    /* l32i.n a3, a3, -- 0: frame control */
    /* l32i a14, a3, -- off 0x114 */
  /* observed call sequence (in order): wifi_log */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[2] = *(u32 *)((u8 *)(uintptr_t)a4 + 0); /* l32i a2,a5+0 → +0: frame control */
  regs[1] = *(u32 *)(eb8 + 0); /* l32i.n a10,a4+0 → +0: frame control */
  regs[2] = *(u32 *)((u8 *)a2 + 84); /* l32i a2,a2+84 → +84:  */
  regs[5] = *(u32 *)((u8 *)(uintptr_t)a4 + 0); /* l32i.n a5,a5+0 → +0: frame control */
  regs[2] = *(u32 *)((u8 *)a3 + 0); /* l32i.n a2,a3+0 → +0: frame control */
  regs[5] = *(u32 *)((u8 *)(uintptr_t)a4 + 88); /* l32i a5,a5+88 → +88:  */
  (void)((int(*)())wifi_log)(); /* observed call (disasm order; args a2..a5) */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* scan_get_type @ ieee80211_scan.o 00000004 size 12B bind GLOBAL
 * Calls: none | Data refs: g_scan
 * Fidelity: high - leaf; full insn sequence captured, no hidden control flow */
/* disasm section: .text.scan_get_type */
int scan_get_type(void *a2, void *a3, unsigned a4, unsigned a5);
int scan_get_type(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 32B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed memory traffic (first 2): */
    /* l32i.n a8, a8, -- 0: frame control */
    /* l32i.n a2, a8, -- 0: frame control */
  /* observed calls: none (leaf) */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[8] = *(u32 *)(((u8 *)0) + 0); /* l32i.n a8,a8+0 → +0: frame control */
  regs[2] = *(u32 *)(((u8 *)0) + 0); /* l32i.n a2,a8+0 → +0: frame control */
  /* no calls observed: leaf */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* scan_inter_channel_timeout_process @ ieee80211_scan.o 0000001c size 108B bind GLOBAL
 * Calls: wifi_log, .text.scan_next_channel | Data refs: g_scan, .rodata_wlog_verbose.54, .rodata_wlog_verbose.55, g_osi_funcs_p, wifi_log, .text.scan_next_channel
 * Fidelity: medium - call order + branch skeleton from disasm; some field names inferred */
/* disasm section: .text.scan_inter_channel_timeout_process */
int scan_inter_channel_timeout_process(void *a2, void *a3, unsigned a4, unsigned a5);
int scan_inter_channel_timeout_process(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 32B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 5, 1, 8, 10, 0 */
  /* observed branches: bbcix2, beqz.nx1 */
  /* observed memory traffic (first 10): */
    /* l32i.n a8, a3, -- 0: frame control */
    /* l8ui a15, a8, -- off 70 */
    /* l32i.n a10, a3, -- 0: frame control */
    /* l8ui a12, a10, -- off 70 */
    /* l32i.n a10, a3, -- 0: frame control */
    /* l32i.n a3, a3, -- 0: frame control */
    /* l32i a3, a3, -- off 232 */
    /* l32i.n a3, a10, -- 0: frame control */
    /* l32i.n a3, a3, -- 0: frame control */
    /* l32i.n a11, a10, -- off 40 */
  /* observed call sequence (in order): wifi_log -> .text.scan_next_channel+0x68 */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[8] = *(u32 *)((u8 *)a3 + 0); /* l32i.n a8,a3+0 → +0: frame control */
  regs[1] = *(u8 *)(((u8 *)0) + 70); /* l8ui → +70:  */
  regs[1] = *(u32 *)((u8 *)a3 + 0); /* l32i.n a10,a3+0 → +0: frame control */
  regs[1] = *(u8 *)(((u8 *)0) + 70); /* l8ui → +70:  */
  regs[1] = *(u32 *)((u8 *)a3 + 0); /* l32i.n a10,a3+0 → +0: frame control */
  regs[3] = *(u32 *)((u8 *)a3 + 0); /* l32i.n a3,a3+0 → +0: frame control */
  (void)((int(*)())wifi_log)(); /* observed call (disasm order; args a2..a5) */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* scan_owe_pref_chan @ ieee80211_scan.o 00000010 size 154B bind GLOBAL
 * Calls: sta_get_owe_data, chm_get_channel_index | Data refs: g_ic, sta_get_owe_data, chm_get_channel_index
 * Fidelity: medium - call order + branch skeleton from disasm; some field names inferred */
/* disasm section: .text.scan_owe_pref_chan */
int scan_owe_pref_chan(void *a2, void *a3, unsigned a4, unsigned a5);
int scan_owe_pref_chan(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 32B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 0, 1, -255, 13 */
  /* observed branches: bnex1, bltux2, bneix1, bgeux2 */
  /* observed memory traffic (first 3): */
    /* l8ui a5, a10, -- off 84 */
    /* l8ui a3, a10, -- off 85 */
    /* l8ui a11, a2, -- off 173 */
  /* observed call sequence (in order): sta_get_owe_data -> chm_get_channel_index */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[5] = *(u8 *)(((u8 *)0) + 84); /* l8ui → +84:  */
  regs[3] = *(u8 *)(((u8 *)0) + 85); /* l8ui → +85:  */
  regs[1] = *(u8 *)((u8 *)a2 + 173); /* l8ui → +173:  */
  (void)((int(*)())sta_get_owe_data)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())chm_get_channel_index)(); /* observed call (disasm order; args a2..a5) */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* scan_parse_beacon @ ieee80211_scan.o 000001d0 size 3413B bind GLOBAL
 * Calls: sta_get_owe_data, memcmp, scan_check_hidden, chm_get_chan_info, wifi_log, ieee80211_regdomain_chan_in_range, sta_support_auto_mode_connect_passive_channel_hidden_ap, ieee80211_regdomain_is_active_scan, .text.scan_send_probe, chm_get_current_channel, memset, memcpy, scan_parse_ht2040_coex, wifi_sta_get_prof_password, check_bss_queue, .text.scan_add_ssid$isra$0, .text.scan_parse_owe_opclass_chan$constprop$0$isra$0, .text.is_profile_match, strncmp, scan_update_scan_history, scan_fill_wps_scan_ie, hal_get_tsf_time, cnx_rc_search, scan_profile_check, cnx_bss_alloc, cnx_bss_init, cnx_rc_update_rssi, cnx_rc_update_state_metric, cnx_rc_update_age, cnx_update_bss, ieee80211_amsdu_negotiate, cnx_update_bss_more, wifi_mesh_event_post, cnx_add_rc, .text.scan_add_ssid_do$constprop$0, wifi_event_post, owe_trans_data_del | Data refs: g_ic, g_wifi_nvs, .rodata.scan_op_start.str1.1, .rodata_wlog_error.137, .rodata_wlog_debug.138, .bss.passive_scan_send_probereq, .rodata_wlog_debug.136, .rodata_wlog_error.64, .rodata_wlog_debug.65, g_scan
 * Fidelity: medium - state-machine edges + call order from disasm; timer callbacks cited */
/* disasm section: .text.scan_parse_beacon */
int scan_parse_beacon(void *a2, void *a3, unsigned a4, unsigned a5);
int scan_parse_beacon(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 160B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 0, 6, 1, 4, 8, 13, 28, 44, -149, 10 */
  /* observed branches: beqz.nx22, bneix7, bnez.nx33, beqx11, bltux9, bnonex2, bgeux2, bgex2 */
  /* observed memory traffic (first 10): */
    /* s32i.n a2, a1, -- off 56 */
    /* l32i.n a2, a2, -- 44: eb priv word */
    /* l8ui a2, a2, -- 8: 802.11 header region */
    /* s32i.n a2, a1, -- off 48 */
    /* l32i.n a5, a1, -- off 56 */
    /* l32i.n a2, a2, -- 16: addr3 */
    /* s32i a2, a1, -- off 72 */
    /* l32i.n a2, a5, -- 16: addr3 */
    /* l8ui a6, a2, -- 0: frame control */
    /* l32i.n a2, a2, -- 20: eb len field region */
  /* observed call sequence (in order): sta_get_owe_data -> memcmp -> scan_check_hidden -> chm_get_chan_info -> wifi_log -> ieee80211_regdomain_chan_in_range -> sta_support_auto_mode_connect_passive_channel_hidden_ap -> ieee80211_regdomain_is_active_scan -> .text.scan_send_probe+0x34 -> chm_get_current_channel -> memset -> memcpy -> scan_parse_ht2040_coex -> wifi_sta_get_prof_password */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  *(u32 *)(((u8 *)a1_spill) + 56) = regs[2]; /* s32i.n a2,a1+56 → +56:  */
  regs[2] = *(u32 *)((u8 *)a2 + 44); /* l32i.n a2,a2+44 → +44: eb priv word */
  regs[2] = *(u8 *)((u8 *)a2 + 8); /* l8ui → +8: 802.11 header region */
  *(u32 *)(((u8 *)a1_spill) + 48) = regs[2]; /* s32i.n a2,a1+48 → +48:  */
  regs[5] = *(u32 *)(((u8 *)a1_spill) + 56); /* l32i.n a5,a1+56 → +56:  */
  regs[2] = *(u32 *)((u8 *)a2 + 16); /* l32i.n a2,a2+16 → +16: addr3 */
  (void)((int(*)())sta_get_owe_data)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())memcmp)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())scan_check_hidden)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())chm_get_chan_info)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())wifi_log)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())ieee80211_regdomain_chan_in_range)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())sta_support_auto_mode_connect_passive_channel_hidden_ap)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())ieee80211_regdomain_is_active_scan)(); /* observed call (disasm order; args a2..a5) */

    /* RX-ENTRY: called per beacon/proberesp; validates chan (chm_get_chan_info+regdomain), hidden-ssid (scan_check_hidden), profile match (is_profile_match/scan_profile_check incl RSN/WPA/WAPI parses), updates cnx rc (cnx_bss_alloc/init, rc_update_rssi/age/state, cnx_update_bss[_more]), posts mesh/event. */
    return 0;
  
}

/* scan_parse_ht2040_coex @ ieee80211_scan.o 00000014 size 104B bind GLOBAL
 * Calls: wifi_log | Data refs: g_ic, .rodata_wlog_info.131, .rodata_wlog_info.132, wifi_log
 * Fidelity: medium - call order + branch skeleton from disasm; some field names inferred */
/* disasm section: .text.scan_parse_ht2040_coex */
int scan_parse_ht2040_coex(void *a2, void *a3, unsigned a4, unsigned a5);
int scan_parse_ht2040_coex(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 32B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 1, 3, 32, 4, 0 */
  /* observed branches: bneix1, bnez.nx1, bbcix1 */
  /* observed memory traffic (first 10): */
    /* l32i.n a8, a3, -- 16: addr3 */
    /* l32i a3, a8, -- off 228 */
    /* l32i a8, a8, -- 152: key PN/counter region */
    /* l32i a8, a2, -- off 68 */
    /* l8ui a14, a2, -- 4: addr1 */
    /* l32i a2, a3, -- off 0x2e0 */
    /* s32i a2, a3, -- off 0x2e0 */
    /* l16ui a8, a8, -- 2: duration */
    /* l8ui a14, a2, -- 4: addr1 */
    /* l32i a8, a3, -- off 0x2e4 */
  /* observed call sequence (in order): wifi_log */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[8] = *(u32 *)((u8 *)a3 + 16); /* l32i.n a8,a3+16 → +16: addr3 */
  regs[3] = *(u32 *)(((u8 *)0) + 228); /* l32i a3,a8+228 → +228:  */
  regs[8] = *(u32 *)(((u8 *)0) + 152); /* l32i a8,a8+152 → +152: key PN/counter region */
  regs[8] = *(u32 *)((u8 *)a2 + 68); /* l32i a8,a2+68 → +68:  */
  regs[1] = *(u8 *)((u8 *)a2 + 4); /* l8ui → +4: addr1 */
  regs[2] = *(u32 *)((u8 *)a3 + 736); /* l32i a2,a3+736 → +736:  */
  (void)((int(*)())wifi_log)(); /* observed call (disasm order; args a2..a5) */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* scan_pm_channel_op_cb @ ieee80211_scan.o 00000008 size 46B bind GLOBAL
 * Calls: none | Data refs: g_scan, g_osi_funcs_p
 * Fidelity: high - leaf; full insn sequence captured, no hidden control flow */
/* disasm section: .text.scan_pm_channel_op_cb */
int scan_pm_channel_op_cb(void *a2, void *a3, unsigned a4, unsigned a5);
int scan_pm_channel_op_cb(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 32B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 0 */
  /* observed branches: bbcix1 */
  /* observed memory traffic (first 7): */
    /* l32i.n a10, a3, -- 0: frame control */
    /* l8ui a2, a10, -- off 70 */
    /* l32i a8, a2, -- 0: frame control */
    /* l32i a8, a8, -- off 236 */
    /* l32i.n a2, a2, -- 0: frame control */
    /* l32i.n a10, a3, -- 0: frame control */
    /* l32i a2, a2, -- off 232 */
  /* observed calls: none (leaf) */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[1] = *(u32 *)((u8 *)a3 + 0); /* l32i.n a10,a3+0 → +0: frame control */
  regs[2] = *(u8 *)(((u8 *)0) + 70); /* l8ui → +70:  */
  regs[8] = *(u32 *)((u8 *)a2 + 0); /* l32i a8,a2+0 → +0: frame control */
  regs[8] = *(u32 *)(((u8 *)0) + 236); /* l32i a8,a8+236 → +236:  */
  regs[2] = *(u32 *)((u8 *)a2 + 0); /* l32i.n a2,a2+0 → +0: frame control */
  regs[1] = *(u32 *)((u8 *)a3 + 0); /* l32i.n a10,a3+0 → +0: frame control */
  /* no calls observed: leaf */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* scan_pm_offchan @ ieee80211_scan.o 00000010 size 64B bind GLOBAL
 * Calls: pm_offchan_ready_or_defer, wifi_log | Data refs: g_ic, .rodata_wlog_warning.7, pm_offchan_ready_or_defer, wifi_log
 * Fidelity: medium - call order + branch skeleton from disasm; some field names inferred */
/* disasm section: .text.scan_pm_offchan */
int scan_pm_offchan(void *a2, void *a3, unsigned a4, unsigned a5);
int scan_pm_offchan(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 32B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 0, 8, 1, -1 */
  /* observed branches: bneix1 */
  /* observed memory traffic (first 1): */
    /* l32i a3, a3, -- off 116 */
  /* observed call sequence (in order): pm_offchan_ready_or_defer -> wifi_log */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[3] = *(u32 *)((u8 *)a3 + 116); /* l32i a3,a3+116 → +116:  */
  (void)((int(*)())pm_offchan_ready_or_defer)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())wifi_log)(); /* observed call (disasm order; args a2..a5) */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* scan_prefer_chan @ ieee80211_scan.o 00000088 size 636B bind GLOBAL
 * Calls: chm_get_home_channel, memset, wifi_log, strncmp, strlen, memcpy, sta_get_owe_data, scan_owe_pref_chan | Data refs: g_ic, g_wifi_nvs, .rodata, .rodata_wlog_verbose.37, .rodata_wlog_verbose.38, .rodata_wlog_verbose.39, g_scan, .rodata_wlog_verbose.40, .rodata_wlog_verbose.41, .rodata_wlog_verbose.42
 * Fidelity: medium - call order + offsets from disasm; straight-line details summarised */
/* disasm section: .text.scan_prefer_chan */
int scan_prefer_chan(void *a2, void *a3, unsigned a4, unsigned a5);
int scan_prefer_chan(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 144B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 31, 0, 5, 8, 1, 32, 164, 160, 33, 29 */
  /* observed branches: bnez.nx3, beqx1, bgeux2, bnex1, beqz.nx1 */
  /* observed memory traffic (first 10): */
    /* l32i.n a5, a3, -- 16: addr3 */
    /* l32i a6, a3, -- 0: frame control */
    /* l8ui a8, a3, -- 0: frame control */
    /* l8ui a3, a3, -- 1: frame control/duration */
    /* s8i a8, a1, -- off 49 */
    /* s8i a3, a1, -- off 50 */
    /* l8ui a2, a7, -- 0: frame control */
    /* l32i a7, a5, -- off 228 */
    /* l8ui a15, a7, -- off 171 */
    /* l32i a2, a5, -- off 228 */
  /* observed call sequence (in order): chm_get_home_channel -> memset -> wifi_log -> strncmp -> strlen -> memcpy -> sta_get_owe_data -> scan_owe_pref_chan */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[5] = *(u32 *)((u8 *)a3 + 16); /* l32i.n a5,a3+16 → +16: addr3 */
  regs[6] = *(u32 *)((u8 *)a3 + 0); /* l32i a6,a3+0 → +0: frame control */
  regs[8] = *(u8 *)((u8 *)a3 + 0); /* l8ui → +0: frame control */
  regs[3] = *(u8 *)((u8 *)a3 + 1); /* l8ui → +1: frame control/duration */
  *(u8 *)(((u8 *)a1_spill) + 49) = (u8)regs[8]; /* s8i → +49:  */
  *(u8 *)(((u8 *)a1_spill) + 50) = (u8)regs[3]; /* s8i → +50:  */
  (void)((int(*)())chm_get_home_channel)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())memset)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())wifi_log)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())strncmp)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())strlen)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())memcpy)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())sta_get_owe_data)(); /* observed call (disasm order; args a2..a5) */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* scan_profile_check @ ieee80211_scan.o 000001a4 size 2512B bind GLOBAL
 * Calls: memset, sta_get_owe_data, wifi_log, memcmp, .text.scan_parse_owe_opclass_chan$constprop$0$isra$0, .text.scan_add_owe_channel, scan_check_hidden, scan_reset_cipher_and_akm, ieee80211_parse_rsn, ieee80211_cipher_name, ieee80211_parse_wpa, ieee80211_parse_wapi, strlen, memcpy, wifi_sta_get_prof_password, cnx_get_authtype_strength, cnx_check_bssid_in_blacklist | Data refs: .rodata.scan_profile_check.str1.1, g_wifi_nvs, g_ic, .rodata_wlog_debug.68, g_authmode_threshold_failure, .rodata_wlog_error.69, g_authmode_incompatible, .rodata_wlog_debug.70, .rodata_wlog_debug.71, .rodata_wlog_error.72
 * Fidelity: medium - state-machine edges + call order from disasm; timer callbacks cited */
/* disasm section: .text.scan_profile_check */
int scan_profile_check(void *a2, void *a3, unsigned a4, unsigned a5);
int scan_profile_check(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 128B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 36, 0, 1, 4, 8, 147, 6, 2, 5, -17 */
  /* observed branches: bnez.nx20, bneix7, beqz.nx30, bbsix2, bltix1, bnex7, beqx1, beqix6 */
  /* observed memory traffic (first 10): */
    /* l32i a2, a6, -- 0: frame control */
    /* l8ui a8, a5, -- off 97 */
    /* s32i a9, a1, -- off 80 */
    /* l8ui a8, a8, -- 159: key PN/counter region */
    /* s32i a8, a1, -- off 80 */
    /* l8ui a8, a5, -- 24: seqctl/addr4/QoS */
    /* l8ui a8, a8, -- 21: 802.11 header region */
    /* l8ui a8, a8, -- off 165 */
    /* l16ui a8, a3, -- 6: 802.11 header region */
    /* l32i a8, a3, -- off 128 */
  /* observed call sequence (in order): memset -> sta_get_owe_data -> wifi_log -> memcmp -> .text.scan_parse_owe_opclass_chan$constprop$0$isra$0+0x4 -> .text.scan_add_owe_channel+0x14 -> scan_check_hidden -> scan_reset_cipher_and_akm -> ieee80211_parse_rsn -> ieee80211_cipher_name -> ieee80211_parse_wpa -> ieee80211_parse_wapi -> strlen -> memcpy */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[2] = *(u32 *)(eb8 + 0); /* l32i a2,a6+0 → +0: frame control */
  regs[8] = *(u8 *)((u8 *)(uintptr_t)a4 + 97); /* l8ui → +97:  */
  *(u32 *)(((u8 *)a1_spill) + 80) = regs[9]; /* s32i a9,a1+80 → +80:  */
  regs[8] = *(u8 *)(((u8 *)0) + 159); /* l8ui → +159: key PN/counter region */
  *(u32 *)(((u8 *)a1_spill) + 80) = regs[8]; /* s32i a8,a1+80 → +80:  */
  regs[8] = *(u8 *)((u8 *)(uintptr_t)a4 + 24); /* l8ui → +24: seqctl/addr4/QoS */
  (void)((int(*)())memset)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())sta_get_owe_data)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())wifi_log)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())memcmp)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())scan_check_hidden)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())scan_reset_cipher_and_akm)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())ieee80211_parse_rsn)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())ieee80211_cipher_name)(); /* observed call (disasm order; args a2..a5) */

    /* MATCH: SSID/BSSID/auth/cipher/akm gates; calls ieee80211_parse_rsn/wpa/wapi + cipher_name + cnx_check_bssid_in_blacklist; returns match bitmap. */
    return 0;
  
}

/* scan_remove_bssid @ ieee80211_scan.o 00000004 size 21B bind GLOBAL
 * Calls: none | Data refs: g_scan
 * Fidelity: high - leaf; full insn sequence captured, no hidden control flow */
/* disasm section: .text.scan_remove_bssid */
int scan_remove_bssid(void *a2, void *a3, unsigned a4, unsigned a5);
int scan_remove_bssid(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 32B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 0 */
  /* observed memory traffic (first 2): */
    /* l32i.n a8, a8, -- 0: frame control */
    /* s8i a9, a8, -- off 162 */
  /* observed calls: none (leaf) */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[8] = *(u32 *)(((u8 *)0) + 0); /* l32i.n a8,a8+0 → +0: frame control */
  *(u8 *)(((u8 *)0) + 162) = (u8)regs[9]; /* s8i → +162:  */
  /* no calls observed: leaf */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* scan_remove_probe_ssid @ ieee80211_scan.o 00000004 size 45B bind GLOBAL
 * Calls: none | Data refs: g_scan
 * Fidelity: high - leaf; full insn sequence captured, no hidden control flow */
/* disasm section: .text.scan_remove_probe_ssid */
int scan_remove_probe_ssid(void *a2, void *a3, unsigned a4, unsigned a5);
int scan_remove_probe_ssid(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 32B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 152, 0 */
  /* observed memory traffic (first 3): */
    /* l32i.n a9, a8, -- 0: frame control */
    /* s8i a10, a8, -- 0: frame control */
    /* s32i a8, a2, -- off 80 */
  /* observed calls: none (leaf) */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[9] = *(u32 *)(((u8 *)0) + 0); /* l32i.n a9,a8+0 → +0: frame control */
  *(u8 *)(((u8 *)0) + 0) = (u8)regs[1]; /* s8i → +0: frame control */
  *(u32 *)((u8 *)a2 + 80) = regs[8]; /* s32i a8,a2+80 → +80:  */
  /* no calls observed: leaf */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* scan_reset_cipher_and_akm @ ieee80211_scan.o 00000004 size 40B bind GLOBAL
 * Calls: none | Data refs: g_ic
 * Fidelity: high - leaf; full insn sequence captured, no hidden control flow */
/* disasm section: .text.scan_reset_cipher_and_akm */
int scan_reset_cipher_and_akm(void *a2, void *a3, unsigned a4, unsigned a5);
int scan_reset_cipher_and_akm(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 32B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 0 */
  /* observed memory traffic (first 6): */
    /* s16i a9, a8, -- 156: key PN/counter region */
    /* s16i a10, a8, -- 0: frame control */
    /* s8i a9, a8, -- 2: duration */
    /* s8i a9, a8, -- 4: addr1 */
    /* s16i a9, a8, -- 8: 802.11 header region */
    /* s8i a9, a8, -- 10: addr2 */
  /* observed calls: none (leaf) */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  *(u16 *)(((u8 *)0) + 156) = (u16)regs[9]; /* s16i → +156: key PN/counter region */
  *(u16 *)(((u8 *)0) + 0) = (u16)regs[1]; /* s16i → +0: frame control */
  *(u8 *)(((u8 *)0) + 2) = (u8)regs[9]; /* s8i → +2: duration */
  *(u8 *)(((u8 *)0) + 4) = (u8)regs[9]; /* s8i → +4: addr1 */
  *(u16 *)(((u8 *)0) + 8) = (u16)regs[9]; /* s16i → +8: 802.11 header region */
  *(u8 *)(((u8 *)0) + 10) = (u8)regs[9]; /* s8i → +10: addr2 */
  /* no calls observed: leaf */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* scan_reset_default_app_params @ ieee80211_scan.o 00000014 size 78B bind GLOBAL
 * Calls: .text.scan_set_global_scan_times$constprop$0, wifi_log | Data refs: app_scan_params, .bss.s_current_max_scan_duration, .rodata_wlog_debug.3, .text.scan_set_global_scan_times$constprop$0, wifi_log
 * Fidelity: medium - call order + branch skeleton from disasm; some field names inferred */
/* disasm section: .text.scan_reset_default_app_params */
int scan_reset_default_app_params(void *a2, void *a3, unsigned a4, unsigned a5);
int scan_reset_default_app_params(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 48B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 0, 120, 30, 4, 8, 1 */
  /* observed memory traffic (first 9): */
    /* s32i.n a2, a8, -- 0: frame control */
    /* s32i.n a3, a8, -- 4: addr1 */
    /* s32i.n a4, a8, -- 8: 802.11 header region */
    /* s8i a9, a8, -- 12: 802.11 header region */
    /* s16i a2, a8, -- 14: 802.11 header region */
    /* s32i a2, a8, -- 0: frame control */
    /* s32i.n a2, a1, -- 8: 802.11 header region */
    /* s32i.n a8, a1, -- 4: addr1 */
    /* s32i.n a4, a1, -- 0: frame control */
  /* observed call sequence (in order): .text.scan_set_global_scan_times$constprop$0+0x8 -> wifi_log */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  *(u32 *)(((u8 *)0) + 0) = regs[2]; /* s32i.n a2,a8+0 → +0: frame control */
  *(u32 *)(((u8 *)0) + 4) = regs[3]; /* s32i.n a3,a8+4 → +4: addr1 */
  *(u32 *)(((u8 *)0) + 8) = regs[4]; /* s32i.n a4,a8+8 → +8: 802.11 header region */
  *(u8 *)(((u8 *)0) + 12) = (u8)regs[9]; /* s8i → +12: 802.11 header region */
  *(u16 *)(((u8 *)0) + 14) = (u16)regs[2]; /* s16i → +14: 802.11 header region */
  *(u32 *)(((u8 *)0) + 0) = regs[2]; /* s32i a2,a8+0 → +0: frame control */
  (void)((int(*)())wifi_log)(); /* observed call (disasm order; args a2..a5) */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* scan_reset_offchan_duration @ ieee80211_scan.o 00000010 size 38B bind GLOBAL
 * Calls: none | Data refs: .bss.s_current_scan_duration, .bss.s_current_max_scan_duration, .data.s_max_scan_duration, .bss.s_current_channel_duration
 * Fidelity: high - leaf; full insn sequence captured, no hidden control flow */
/* disasm section: .text.scan_reset_offchan_duration */
int scan_reset_offchan_duration(void *a2, void *a3, unsigned a4, unsigned a5);
int scan_reset_offchan_duration(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 32B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 0, 120 */
  /* observed branches: bnex1 */
  /* observed memory traffic (first 4): */
    /* s32i.n a9, a8, -- 0: frame control */
    /* l32i.n a8, a8, -- 0: frame control */
    /* s32i.n a8, a9, -- 0: frame control */
    /* s32i.n a9, a8, -- 0: frame control */
  /* observed calls: none (leaf) */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  *(u32 *)(((u8 *)0) + 0) = regs[9]; /* s32i.n a9,a8+0 → +0: frame control */
  regs[8] = *(u32 *)(((u8 *)0) + 0); /* l32i.n a8,a8+0 → +0: frame control */
  *(u32 *)(((u8 *)0) + 0) = regs[8]; /* s32i.n a8,a9+0 → +0: frame control */
  *(u32 *)(((u8 *)0) + 0) = regs[9]; /* s32i.n a9,a8+0 → +0: frame control */
  /* no calls observed: leaf */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* scan_set_act_duration @ ieee80211_scan.o 00000004 size 17B bind GLOBAL
 * Calls: none | Data refs: g_scan
 * Fidelity: high - leaf; full insn sequence captured, no hidden control flow */
/* disasm section: .text.scan_set_act_duration */
int scan_set_act_duration(void *a2, void *a3, unsigned a4, unsigned a5);
int scan_set_act_duration(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 32B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed memory traffic (first 3): */
    /* l32i.n a8, a8, -- 0: frame control */
    /* s32i.n a2, a8, -- off 52 */
    /* s32i.n a3, a8, -- off 48 */
  /* observed calls: none (leaf) */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[8] = *(u32 *)(((u8 *)0) + 0); /* l32i.n a8,a8+0 → +0: frame control */
  *(u32 *)(((u8 *)0) + 52) = regs[2]; /* s32i.n a2,a8+52 → +52:  */
  *(u32 *)(((u8 *)0) + 48) = regs[3]; /* s32i.n a3,a8+48 → +48:  */
  /* no calls observed: leaf */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* scan_set_current_scan_times @ ieee80211_scan.o 00000008 size 143B bind GLOBAL
 * Calls: none | Data refs: app_scan_params, g_scan
 * Fidelity: medium - call order + offsets from disasm; straight-line details summarised */
/* disasm section: .text.scan_set_current_scan_times */
int scan_set_current_scan_times(void *a2, void *a3, unsigned a4, unsigned a5);
int scan_set_current_scan_times(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 48B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 0, 120, 150, -106 */
  /* observed branches: bgeux5, beqz.nx1, bltux3 */
  /* observed memory traffic (first 9): */
    /* l32i.n a9, a8, -- 4: addr1 */
    /* l32i.n a10, a8, -- 0: frame control */
    /* l32i.n a8, a2, -- 0: frame control */
    /* s32i.n a10, a8, -- off 52 */
    /* s32i.n a9, a8, -- off 48 */
    /* s32i.n a4, a8, -- off 56 */
    /* s32i.n a3, a8, -- off 56 */
    /* s8i a5, a8, -- 24: seqctl/addr4/QoS */
    /* s8i a2, a8, -- 24: seqctl/addr4/QoS */
  /* observed calls: none (leaf) */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[9] = *(u32 *)(((u8 *)0) + 4); /* l32i.n a9,a8+4 → +4: addr1 */
  regs[1] = *(u32 *)(((u8 *)0) + 0); /* l32i.n a10,a8+0 → +0: frame control */
  regs[8] = *(u32 *)((u8 *)a2 + 0); /* l32i.n a8,a2+0 → +0: frame control */
  *(u32 *)(((u8 *)0) + 52) = regs[1]; /* s32i.n a10,a8+52 → +52:  */
  *(u32 *)(((u8 *)0) + 48) = regs[9]; /* s32i.n a9,a8+48 → +48:  */
  *(u32 *)(((u8 *)0) + 56) = regs[4]; /* s32i.n a4,a8+56 → +56:  */
  /* no calls observed: leaf */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* scan_set_default_params @ ieee80211_scan.o 00000010 size 148B bind GLOBAL
 * Calls: scan_set_max_offchan_duration, .text.scan_set_global_scan_times$constprop$0 | Data refs: app_scan_params, scan_set_max_offchan_duration, .text.scan_set_global_scan_times$constprop$0
 * Fidelity: medium - call order + offsets from disasm; straight-line details summarised */
/* disasm section: .text.scan_set_default_params */
int scan_set_default_params(void *a2, void *a3, unsigned a4, unsigned a5);
int scan_set_default_params(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 32B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 0, 120, 30 */
  /* observed branches: beqz.nx4, bgeux3, bltux2 */
  /* observed memory traffic (first 10): */
    /* l32i.n a8, a2, -- 4: addr1 */
    /* s32i.n a8, a2, -- 4: addr1 */
    /* l32i.n a9, a2, -- 0: frame control */
    /* l32i.n a8, a2, -- 4: addr1 */
    /* l32i.n a8, a2, -- 8: 802.11 header region */
    /* s32i.n a8, a2, -- 8: 802.11 header region */
    /* l8ui a8, a2, -- 12: 802.11 header region */
    /* s8i a8, a2, -- 12: 802.11 header region */
    /* l16ui a10, a2, -- 14: 802.11 header region */
    /* s32i.n a9, a8, -- 0: frame control */
  /* observed call sequence (in order): scan_set_max_offchan_duration -> .text.scan_set_global_scan_times$constprop$0+0x8 */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[8] = *(u32 *)((u8 *)a2 + 4); /* l32i.n a8,a2+4 → +4: addr1 */
  *(u32 *)((u8 *)a2 + 4) = regs[8]; /* s32i.n a8,a2+4 → +4: addr1 */
  regs[9] = *(u32 *)((u8 *)a2 + 0); /* l32i.n a9,a2+0 → +0: frame control */
  regs[8] = *(u32 *)((u8 *)a2 + 4); /* l32i.n a8,a2+4 → +4: addr1 */
  regs[8] = *(u32 *)((u8 *)a2 + 8); /* l32i.n a8,a2+8 → +8: 802.11 header region */
  *(u32 *)((u8 *)a2 + 8) = regs[8]; /* s32i.n a8,a2+8 → +8: 802.11 header region */
  (void)((int(*)())scan_set_max_offchan_duration)(); /* observed call (disasm order; args a2..a5) */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* scan_set_desChan @ ieee80211_scan.o 00000004 size 19B bind GLOBAL
 * Calls: none | Data refs: g_scan
 * Fidelity: high - leaf; full insn sequence captured, no hidden control flow */
/* disasm section: .text.scan_set_desChan */
int scan_set_desChan(void *a2, void *a3, unsigned a4, unsigned a5);
int scan_set_desChan(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 32B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed memory traffic (first 2): */
    /* l32i.n a8, a8, -- 0: frame control */
    /* s8i a2, a8, -- 155: key PN/counter region */
  /* observed calls: none (leaf) */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[8] = *(u32 *)(((u8 *)0) + 0); /* l32i.n a8,a8+0 → +0: frame control */
  *(u8 *)(((u8 *)0) + 155) = (u8)regs[2]; /* s8i → +155: key PN/counter region */
  /* no calls observed: leaf */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* scan_set_home_chan_dwell_time @ ieee80211_scan.o 00000004 size 22B bind GLOBAL
 * Calls: none | Data refs: g_scan
 * Fidelity: high - leaf; full insn sequence captured, no hidden control flow */
/* disasm section: .text.scan_set_home_chan_dwell_time */
int scan_set_home_chan_dwell_time(void *a2, void *a3, unsigned a4, unsigned a5);
int scan_set_home_chan_dwell_time(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 32B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed memory traffic (first 2): */
    /* l32i.n a8, a8, -- 0: frame control */
    /* s8i a2, a8, -- 24: seqctl/addr4/QoS */
  /* observed calls: none (leaf) */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[8] = *(u32 *)(((u8 *)0) + 0); /* l32i.n a8,a8+0 → +0: frame control */
  *(u8 *)(((u8 *)0) + 24) = (u8)regs[2]; /* s8i → +24: seqctl/addr4/QoS */
  /* no calls observed: leaf */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* scan_set_max_offchan_duration @ ieee80211_scan.o 00000008 size 25B bind GLOBAL
 * Calls: none | Data refs: .bss.s_current_max_scan_duration
 * Fidelity: high - leaf; full insn sequence captured, no hidden control flow */
/* disasm section: .text.scan_set_max_offchan_duration */
int scan_set_max_offchan_duration(void *a2, void *a3, unsigned a4, unsigned a5);
int scan_set_max_offchan_duration(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 32B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed branches: bltux1 */
  /* observed memory traffic (first 1): */
    /* s32i.n a2, a8, -- 0: frame control */
  /* observed calls: none (leaf) */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  *(u32 *)(((u8 *)0) + 0) = regs[2]; /* s32i.n a2,a8+0 → +0: frame control */
  /* no calls observed: leaf */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* scan_set_pas_duration @ ieee80211_scan.o 00000004 size 15B bind GLOBAL
 * Calls: none | Data refs: g_scan
 * Fidelity: high - leaf; full insn sequence captured, no hidden control flow */
/* disasm section: .text.scan_set_pas_duration */
int scan_set_pas_duration(void *a2, void *a3, unsigned a4, unsigned a5);
int scan_set_pas_duration(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 32B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed memory traffic (first 2): */
    /* l32i.n a8, a8, -- 0: frame control */
    /* s32i.n a2, a8, -- off 56 */
  /* observed calls: none (leaf) */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[8] = *(u32 *)(((u8 *)0) + 0); /* l32i.n a8,a8+0 → +0: frame control */
  *(u32 *)(((u8 *)0) + 56) = regs[2]; /* s32i.n a2,a8+56 → +56:  */
  /* no calls observed: leaf */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* scan_set_scan_id @ ieee80211_scan.o 00000014 size 67B bind GLOBAL
 * Calls: wifi_log | Data refs: g_wifi_global_lock, g_osi_funcs_p, g_scan, .rodata_wlog_verbose.129, wifi_log
 * Fidelity: medium - call order + branch skeleton from disasm; some field names inferred */
/* disasm section: .text.scan_set_scan_id */
int scan_set_scan_id(void *a2, void *a3, unsigned a4, unsigned a5);
int scan_set_scan_id(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 32B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 5, 8, 1 */
  /* observed memory traffic (first 10): */
    /* l32i a3, a5, -- 0: frame control */
    /* l32i a10, a4, -- 0: frame control */
    /* l32i a3, a3, -- off 84 */
    /* l32i.n a5, a5, -- 0: frame control */
    /* l32i.n a8, a3, -- 0: frame control */
    /* l32i a5, a5, -- off 88 */
    /* l32i.n a10, a4, -- 0: frame control */
    /* s32i a2, a8, -- off 0x114 */
    /* l32i.n a3, a3, -- 0: frame control */
    /* l32i a14, a3, -- off 0x114 */
  /* observed call sequence (in order): wifi_log */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[3] = *(u32 *)((u8 *)(uintptr_t)a4 + 0); /* l32i a3,a5+0 → +0: frame control */
  regs[1] = *(u32 *)(eb8 + 0); /* l32i a10,a4+0 → +0: frame control */
  regs[3] = *(u32 *)((u8 *)a3 + 84); /* l32i a3,a3+84 → +84:  */
  regs[5] = *(u32 *)((u8 *)(uintptr_t)a4 + 0); /* l32i.n a5,a5+0 → +0: frame control */
  regs[8] = *(u32 *)((u8 *)a3 + 0); /* l32i.n a8,a3+0 → +0: frame control */
  regs[5] = *(u32 *)((u8 *)(uintptr_t)a4 + 88); /* l32i a5,a5+88 → +88:  */
  (void)((int(*)())wifi_log)(); /* observed call (disasm order; args a2..a5) */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* scan_start @ ieee80211_scan.o 00000030 size 168B bind GLOBAL
 * Calls: chm_acquire_lock, wifi_log, wifi_gpio_debug, scan_pm_offchan | Data refs: g_ic, g_scan, connect_scan_flag, g_osi_funcs_p, .bss.passive_scan_send_probereq, .text.scan_done, .rodata_wlog_warning.13, scan_start_handler, chm_acquire_lock, wifi_log
 * Fidelity: medium - state-machine edges + call order from disasm; timer callbacks cited */
/* disasm section: .text.scan_start */
int scan_start(void *a2, void *a3, unsigned a4, unsigned a5);
int scan_start(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 32B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 0, 2, 8, 1, -1, 15 */
  /* observed branches: bneix2, bbcix1 */
  /* observed memory traffic (first 10): */
    /* l32i.n a10, a7, -- 16: addr3 */
    /* l8ui a6, a6, -- off 84 */
    /* l32i.n a8, a8, -- 0: frame control */
    /* l8ui a8, a8, -- off 70 */
    /* s8i a6, a8, -- 0: frame control */
    /* l32i.n a8, a6, -- 0: frame control */
    /* l32i a8, a8, -- off 236 */
    /* l32i.n a6, a6, -- 0: frame control */
    /* l32i.n a10, a7, -- 16: addr3 */
    /* l32i a6, a6, -- off 240 */
  /* observed call sequence (in order): chm_acquire_lock -> wifi_log -> wifi_gpio_debug -> scan_pm_offchan */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[1] = *(u32 *)(((u8 *)0) + 16); /* l32i.n a10,a7+16 → +16: addr3 */
  regs[6] = *(u8 *)(eb8 + 84); /* l8ui → +84:  */
  regs[8] = *(u32 *)(((u8 *)0) + 0); /* l32i.n a8,a8+0 → +0: frame control */
  regs[8] = *(u8 *)(((u8 *)0) + 70); /* l8ui → +70:  */
  *(u8 *)(((u8 *)0) + 0) = (u8)regs[6]; /* s8i → +0: frame control */
  regs[8] = *(u32 *)(eb8 + 0); /* l32i.n a8,a6+0 → +0: frame control */
  (void)((int(*)())chm_acquire_lock)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())wifi_log)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())wifi_gpio_debug)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())scan_pm_offchan)(); /* observed call (disasm order; args a2..a5) */

    /* STATE: IDLE->START: chm_acquire_lock(); on fail wifi_log+gpio_debug; scan_pm_offchan() defers if PM busy. */
    return 0;
  
}

/* scan_start_handler @ ieee80211_scan.o 00000040 size 227B bind GLOBAL
 * Calls: wifi_log, wifi_set_rx_policy, chm_get_channel_index, clear_bss_queue, hal_now, scan_inter_channel_timeout_process | Data refs: .rodata_wlog_debug.8, g_scan, .rodata_wlog_debug.9, .rodata_wlog_debug.10, .rodata_wlog_debug.11, g_ic, .rodata_wlog_warning.12, wifi_log, wifi_set_rx_policy, chm_get_channel_index
 * Fidelity: medium - state-machine edges + call order from disasm; timer callbacks cited */
/* disasm section: .text.scan_start_handler */
int scan_start_handler(void *a2, void *a3, unsigned a4, unsigned a5);
int scan_start_handler(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 64B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 4, 8, 1, 3, 12, 0, 2 */
  /* observed branches: beqix1, bbsix1, bnez.nx1, bnonex2 */
  /* observed memory traffic (first 10): */
    /* l32i a3, a2, -- 0: frame control */
    /* l8ui a3, a3, -- off 70 */
    /* l32i.n a3, a2, -- 0: frame control */
    /* l32i.n a10, a3, -- 0: frame control */
    /* s8i a8, a3, -- off 69 */
    /* l8ui a10, a3, -- 155: key PN/counter region */
    /* s8i a10, a3, -- off 69 */
    /* l32i.n a8, a2, -- 0: frame control */
    /* l32i.n a3, a8, -- 0: frame control */
    /* l8ui a4, a8, -- off 68 */
  /* observed call sequence (in order): wifi_log -> wifi_set_rx_policy -> chm_get_channel_index -> clear_bss_queue -> hal_now -> scan_inter_channel_timeout_process */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[3] = *(u32 *)((u8 *)a2 + 0); /* l32i a3,a2+0 → +0: frame control */
  regs[3] = *(u8 *)((u8 *)a3 + 70); /* l8ui → +70:  */
  regs[3] = *(u32 *)((u8 *)a2 + 0); /* l32i.n a3,a2+0 → +0: frame control */
  regs[1] = *(u32 *)((u8 *)a3 + 0); /* l32i.n a10,a3+0 → +0: frame control */
  *(u8 *)((u8 *)a3 + 69) = (u8)regs[8]; /* s8i → +69:  */
  regs[1] = *(u8 *)((u8 *)a3 + 155); /* l8ui → +155: key PN/counter region */
  (void)((int(*)())wifi_log)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())wifi_set_rx_policy)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())chm_get_channel_index)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())clear_bss_queue)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())hal_now)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())scan_inter_channel_timeout_process)(); /* observed call (disasm order; args a2..a5) */

    /* STATE: START->ITERATE: wifi_set_rx_policy(); chm_get_channel_index(); clear_bss_queue(); hal_now() timestamp; dispatch scan_inter_channel_timeout_process() (first channel) or scan_next_channel+0x68. */
    return 0;
  
}

/* scan_update_scan_history @ ieee80211_scan.o 0000002c size 381B bind GLOBAL
 * Calls: wifi_log, strncmp, memcpy | Data refs: g_scan, .rodata_wlog_verbose.44, .rodata_wlog_verbose.45, .rodata_wlog_verbose.46, .rodata_wlog_verbose.47, wifi_log, strncmp, memcpy
 * Fidelity: medium - call order + offsets from disasm; straight-line details summarised */
/* disasm section: .text.scan_update_scan_history */
int scan_update_scan_history(void *a2, void *a3, unsigned a4, unsigned a5);
int scan_update_scan_history(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 80B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 0, 31, 5, 8, 1, 197, 164, 32 */
  /* observed branches: bnex1, bltux1, bnez.nx2, bgeux2 */
  /* observed memory traffic (first 10): */
    /* s32i.n a5, a1, -- 24: seqctl/addr4/QoS */
    /* l32i.n a6, a5, -- 0: frame control */
    /* l8ui a6, a6, -- off 70 */
    /* s32i.n a6, a1, -- 16: addr3 */
    /* l32i.n a2, a1, -- 16: addr3 */
    /* s32i.n a3, a1, -- 0: frame control */
    /* l8ui a9, a14, -- 0: frame control */
    /* s8i a9, a14, -- 0: frame control */
    /* s32i.n a9, a1, -- 28: HT */
    /* s32i.n a13, a1, -- off 36 */
  /* observed call sequence (in order): wifi_log -> strncmp -> memcpy */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  *(u32 *)(((u8 *)a1_spill) + 24) = regs[5]; /* s32i.n a5,a1+24 → +24: seqctl/addr4/QoS */
  regs[6] = *(u32 *)((u8 *)(uintptr_t)a4 + 0); /* l32i.n a6,a5+0 → +0: frame control */
  regs[6] = *(u8 *)(eb8 + 70); /* l8ui → +70:  */
  *(u32 *)(((u8 *)a1_spill) + 16) = regs[6]; /* s32i.n a6,a1+16 → +16: addr3 */
  regs[2] = *(u32 *)(((u8 *)a1_spill) + 16); /* l32i.n a2,a1+16 → +16: addr3 */
  *(u32 *)(((u8 *)a1_spill) + 0) = regs[3]; /* s32i.n a3,a1+0 → +0: frame control */
  (void)((int(*)())wifi_log)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())strncmp)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())memcpy)(); /* observed call (disasm order; args a2..a5) */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* wifi_sta_set_scan_default_params @ ieee80211_scan.o 00000024 size 111B bind GLOBAL
 * Calls: wifi_log, scan_set_default_params | Data refs: g_ic, gScanStruct, .rodata_wlog_error.4, .rodata_wlog_error.5, app_scan_params, .rodata_wlog_debug.6, wifi_log, scan_set_default_params
 * Fidelity: medium - call order + branch skeleton from disasm; some field names inferred */
/* disasm section: .text.wifi_sta_set_scan_default_params */
int wifi_sta_set_scan_default_params(void *a2, void *a3, unsigned a4, unsigned a5);
int wifi_sta_set_scan_default_params(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 48B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 1, 4, 0, 8 */
  /* observed branches: bbcix1, beqz.nx1, bneix1 */
  /* observed memory traffic (first 10): */
    /* l8ui a9, a9, -- off 70 */
    /* l32i.n a8, a8, -- 16: addr3 */
    /* l8ui a10, a8, -- off 84 */
    /* l16ui a9, a8, -- 14: 802.11 header region */
    /* s32i.n a9, a1, -- 8: 802.11 header region */
    /* l8ui a9, a8, -- 12: 802.11 header region */
    /* s32i.n a9, a1, -- 4: addr1 */
    /* l32i.n a9, a8, -- 8: 802.11 header region */
    /* s32i.n a9, a1, -- 0: frame control */
    /* l32i.n a15, a8, -- 4: addr1 */
  /* observed call sequence (in order): wifi_log -> scan_set_default_params */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[9] = *(u8 *)(((u8 *)0) + 70); /* l8ui → +70:  */
  regs[8] = *(u32 *)(((u8 *)0) + 16); /* l32i.n a8,a8+16 → +16: addr3 */
  regs[1] = *(u8 *)(((u8 *)0) + 84); /* l8ui → +84:  */
  regs[9] = *(u16 *)(((u8 *)0) + 14); /* l16ui → +14: 802.11 header region */
  *(u32 *)(((u8 *)a1_spill) + 8) = regs[9]; /* s32i.n a9,a1+8 → +8: 802.11 header region */
  regs[9] = *(u8 *)(((u8 *)0) + 12); /* l8ui → +12: 802.11 header region */
  (void)((int(*)())wifi_log)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())scan_set_default_params)(); /* observed call (disasm order; args a2..a5) */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}
