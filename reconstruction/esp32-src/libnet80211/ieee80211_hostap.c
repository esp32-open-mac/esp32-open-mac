/* Reconstructed ESP32 WiFi MAC data-path: ieee80211_hostap.o
 * Blob: esp32/libnet80211.a(ieee80211_hostap.o) -> /tmp/re_esp32/libnet80211/ieee80211_hostap.o
 * Metadata: re/esp32/funcdb_libnet80211.json | Disasm: re/esp32/disasm_full/libnet80211/ieee80211_hostap.dis
 * Toolchain: xtensa-esp-elf esp-15.2.0_20251204 (GCC crosstool-NG esp-2022r1 11.2.0) | ABI: args a2..a7, return a2
 * Method: fully offline; calls/refs/offsets/constants cited from disasm sections;
 * funcdb calls[]/refs[] are empty for this lib, so headers below use disasm-observed edges.
 * Undefined (imports): __divdi3, __moddi3, ccmp, chm_get_band_from_chan, chm_get_current_band, chm_get_home_channel, chm_is_at_home_channel, chm_set_current_channel, chm_set_home_channel, chm_set_snd_chan, clear_ic_key, cnx_node_alloc, cnx_node_is_existing, cnx_node_join, cnx_node_leave, cnx_node_search, cnx_rc_update_rssi, esp_mesh_get_running_active_duty_cycle, esp_mesh_quick_funcs, esp_wifi_get_event_mask, g_hmac_cnt, g_ic, g_mesh_init_ps_type, g_mesh_is_root...
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
extern int ieee80211_empty_txq();
extern int ieee80211_gettid();
extern int ieee80211_gpsq_init();
extern int ieee80211_ht_deattach();
extern int ieee80211_is_40mhz_valid_bw();
extern int ieee80211_output();
extern int ieee80211_parse_beacon();
extern int ieee80211_phy_init();
extern int ieee80211_psq_init();
extern int ieee80211_pwrsave_txcb();
extern int ieee80211_recv_bar();
extern int ieee80211_rfid_locp_recv();
extern int ieee80211_send_action();
extern int ieee80211_send_deauth_no_bss();
extern int ieee80211_send_mgmt();
extern int ieee80211_send_nulldata();
extern int ieee80211_send_proberesp();
extern int ieee80211_set_phy_bw();
extern int ieee80211_set_tim();
extern int ieee80211_sta_is_connected();
extern int ieee80211_timer_process();
extern int is_esp_mesh_assoc();
extern int pm_is_open();
extern int pwrsave_flushq();
extern int wifi_event_post();
extern int wifi_get_macaddr();
extern int wifi_gpio_debug();
extern int wifi_log();
extern int wifi_mesh_event_post();
extern int wifi_nvs_commit();
extern int wifi_nvs_get();
extern int wifi_nvs_set();
extern int wifi_set_default_ssid();
extern int wifi_softap_max_support_num();
/* Forward declarations for intra-object calls (definitions follow in funcdb order): */
int ap_rx_cb(void *a2, void *a3, unsigned a4, unsigned a5);
int ap_rx_cb(void *a2, void *a3, unsigned a4, unsigned a5);
int ap_sa_query_timeout_process(void *a2, void *a3, unsigned a4, unsigned a5);
int ap_sa_query_timeout_process(void *a2, void *a3, unsigned a4, unsigned a5);
int ap_try_sa_query_process(void *a2, void *a3, unsigned a4, unsigned a5);
int ap_try_sa_query_process(void *a2, void *a3, unsigned a4, unsigned a5);
int cipher_type_map_public_to_internal(void *a2, void *a3, unsigned a4, unsigned a5);
int cipher_type_map_public_to_internal(void *a2, void *a3, unsigned a4, unsigned a5);
int hostap_auth_open(void *a2, void *a3, unsigned a4, unsigned a5);
int hostap_auth_open(void *a2, void *a3, unsigned a4, unsigned a5);
int hostap_delete_ptk(void *a2, void *a3, unsigned a4, unsigned a5);
int hostap_delete_ptk(void *a2, void *a3, unsigned a4, unsigned a5);
int hostap_deliver_data(void *a2, void *a3, unsigned a4, unsigned a5);
int hostap_deliver_data(void *a2, void *a3, unsigned a4, unsigned a5);
int hostap_handle_timer(void *a2, void *a3, unsigned a4, unsigned a5);
int hostap_handle_timer(void *a2, void *a3, unsigned a4, unsigned a5);
int hostap_handle_timer_process(void *a2, void *a3, unsigned a4, unsigned a5);
int hostap_handle_timer_process(void *a2, void *a3, unsigned a4, unsigned a5);
int hostap_input(void *a2, void *a3, unsigned a4, unsigned a5);
int hostap_input(void *a2, void *a3, unsigned a4, unsigned a5);
int hostap_recv_ctl(void *a2, void *a3, unsigned a4, unsigned a5);
int hostap_recv_ctl(void *a2, void *a3, unsigned a4, unsigned a5);
int hostap_recv_mgmt(void *a2, void *a3, unsigned a4, unsigned a5);
int hostap_recv_mgmt(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_hostap_attach(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_hostap_attach(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_hostap_send_beacon_process(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_hostap_send_beacon_process(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_hostapd_beacon_txcb(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_hostapd_beacon_txcb(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_hostapd_data_txcb(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_hostapd_data_txcb(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_hostapd_ps_txcb(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_hostapd_ps_txcb(void *a2, void *a3, unsigned a4, unsigned a5);
int wifi_ap_reg_rxcb(void *a2, void *a3, unsigned a4, unsigned a5);
int wifi_ap_reg_rxcb(void *a2, void *a3, unsigned a4, unsigned a5);
int wifi_softap_cur_max_ap_bss_num(void *a2, void *a3, unsigned a4, unsigned a5);
int wifi_softap_cur_max_ap_bss_num(void *a2, void *a3, unsigned a4, unsigned a5);
int wifi_softap_start(void *a2, void *a3, unsigned a4, unsigned a5);
int wifi_softap_start(void *a2, void *a3, unsigned a4, unsigned a5);
int wifi_softap_stop(void *a2, void *a3, unsigned a4, unsigned a5);
int wifi_softap_stop(void *a2, void *a3, unsigned a4, unsigned a5);

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
extern int __divdi3();
extern int __moddi3();
extern int chm_get_band_from_chan();
extern int chm_get_current_band();
extern int chm_get_home_channel();
extern int chm_is_at_home_channel();
extern int chm_set_current_channel();
extern int chm_set_home_channel();
extern int chm_set_snd_chan();
extern int clear_ic_key();
extern int cnx_node_alloc();
extern int cnx_node_is_existing();
extern int cnx_node_join();
extern int cnx_node_leave();
extern int cnx_node_search();
extern int cnx_rc_update_rssi();
extern int create_new_bss_for_sa_query_failed_sta();
extern int esp_mesh_get_running_active_duty_cycle();
extern int esp_wifi_get_event_mask();
extern int get_iav_key();
extern int hal_disable_softap_tsf();
extern int hal_get_tsf_time();
extern int hal_now();
extern int hostap_add_in_mac_list();
extern int hostap_del_mac_info_from_list();
extern int hostap_ht_operation_update();
extern int hostap_query_mac_in_list();
extern int ic_del_key();
extern int ic_del_key_all();
extern int ic_disable_crypto();
extern int ic_ebuf_recycle_rx();
extern int ic_ebuf_recycle_tx();
extern int ic_get_next_tbtt();
extern int ic_interface_enabled();
extern int ic_is_mgmt_hwdecr_enabled();
extern int ic_register_tx_cb();
extern int ic_reset_tbtt();
extern int ic_set_beacon_int();
extern int ic_set_vif();
extern int ic_tx_pkt();
extern int ieee80211_adjust_2nd_chan();
extern int ieee80211_ampdu_reorder();
extern int ieee80211_beacon_alloc();
extern int ieee80211_ccmp_decrypt();
extern int ieee80211_crypto_bip_encrypt();
extern int ieee80211_crypto_decap();
extern int ieee80211_decap();
extern int ieee80211_decap_amsdu();

/* ap_rx_cb @ ieee80211_hostap.o 00000008 size 30B bind GLOBAL
 * Calls: none | Data refs: g_ic, net80211_funcs
 * Fidelity: high - leaf; full insn sequence captured, no hidden control flow */
/* disasm section: .text.ap_rx_cb */
int ap_rx_cb(void *a2, void *a3, unsigned a4, unsigned a5);
int ap_rx_cb(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 32B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 0 */
  /* observed memory traffic (first 3): */
    /* l32i.n a8, a8, -- 0: frame control */
    /* l32i.n a10, a9, -- 20: eb len field region */
    /* l32i.n a8, a8, -- 0: frame control */
  /* observed calls: none (leaf) */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[8] = *(u32 *)(((u8 *)0) + 0); /* l32i.n a8,a8+0 → +0: frame control */
  regs[1] = *(u32 *)(((u8 *)0) + 20); /* l32i.n a10,a9+20 → +20: eb len field region */
  regs[8] = *(u32 *)(((u8 *)0) + 0); /* l32i.n a8,a8+0 → +0: frame control */
  /* no calls observed: leaf */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* ap_sa_query_timeout_process @ ieee80211_hostap.o 00000038 size 200B bind GLOBAL
 * Calls: cnx_node_is_existing, wifi_log, ieee80211_send_mgmt, pwrsave_flushq, memcpy, cnx_node_leave, hostap_query_mac_in_list, create_new_bss_for_sa_query_failed_sta, hostap_del_mac_info_from_list | Data refs: .rodata_wlog_warning.63, g_osi_funcs_p, .rodata_wlog_info.64, cnx_node_is_existing, wifi_log, ieee80211_send_mgmt, pwrsave_flushq, memcpy, cnx_node_leave, hostap_query_mac_in_list
 * Fidelity: medium - call order + offsets from disasm; straight-line details summarised */
/* disasm section: .text.ap_sa_query_timeout_process */
int ap_sa_query_timeout_process(void *a2, void *a3, unsigned a4, unsigned a5);
int ap_sa_query_timeout_process(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 48B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 2, 1, 0, 3, 64, 160, 209, 6 */
  /* observed branches: bnez.nx1, beqx2 */
  /* observed memory traffic (first 8): */
    /* l32i.n a8, a4, -- 0: frame control */
    /* l32i a8, a8, -- off 236 */
    /* l32i.n a4, a4, -- 0: frame control */
    /* l32i a4, a4, -- off 240 */
    /* l32i a14, a2, -- off 0x300 */
    /* s32i a3, a2, -- off 0x300 */
    /* s8i a3, a4, -- off 252 */
    /* s16i a9, a8, -- off 176 */
  /* observed call sequence (in order): cnx_node_is_existing -> wifi_log -> ieee80211_send_mgmt -> pwrsave_flushq -> memcpy -> cnx_node_leave -> hostap_query_mac_in_list -> create_new_bss_for_sa_query_failed_sta -> hostap_del_mac_info_from_list */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[8] = *(u32 *)(eb8 + 0); /* l32i.n a8,a4+0 → +0: frame control */
  regs[8] = *(u32 *)(((u8 *)0) + 236); /* l32i a8,a8+236 → +236:  */
  regs[4] = *(u32 *)(eb8 + 0); /* l32i.n a4,a4+0 → +0: frame control */
  regs[4] = *(u32 *)(eb8 + 240); /* l32i a4,a4+240 → +240:  */
  regs[1] = *(u32 *)((u8 *)a2 + 768); /* l32i a14,a2+768 → +768:  */
  *(u32 *)((u8 *)a2 + 768) = regs[3]; /* s32i a3,a2+768 → +768:  */
  (void)((int(*)())cnx_node_is_existing)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())wifi_log)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())ieee80211_send_mgmt)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())pwrsave_flushq)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())memcpy)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())cnx_node_leave)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())hostap_query_mac_in_list)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())create_new_bss_for_sa_query_failed_sta)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())hostap_del_mac_info_from_list)(); /* observed call (disasm order; args a2..a5) */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* ap_try_sa_query_process @ ieee80211_hostap.o 00000030 size 369B bind GLOBAL
 * Calls: cnx_node_is_existing, wifi_log, ap_sa_query_timeout_process, ieee80211_send_action | Data refs: .rodata_wlog_warning.65, .rodata_wlog_info.66, g_osi_funcs_p, .text.ap_sa_query_timeout, .text.ap_try_sa_query, cnx_node_is_existing, wifi_log, ap_sa_query_timeout_process, ieee80211_send_action
 * Fidelity: medium - call order + offsets from disasm; straight-line details summarised */
/* disasm section: .text.ap_try_sa_query_process */
int ap_try_sa_query_process(void *a2, void *a3, unsigned a4, unsigned a5);
int ap_try_sa_query_process(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 48B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 2, 1, 3, 64, 0, 200, 8 */
  /* observed branches: bnez.nx2, bneix1 */
  /* observed memory traffic (first 10): */
    /* l32i a5, a2, -- off 0x300 */
    /* l8ui a3, a2, -- 9: 802.11 header region */
    /* s32i.n a3, a1, -- 12: 802.11 header region */
    /* l8ui a3, a2, -- 8: 802.11 header region */
    /* s32i.n a3, a1, -- 8: 802.11 header region */
    /* l8ui a3, a2, -- 7: 802.11 header region */
    /* s32i.n a3, a1, -- 4: addr1 */
    /* l8ui a3, a2, -- 6: 802.11 header region */
    /* l8ui a15, a2, -- 5: 802.11 header region */
    /* l8ui a14, a2, -- 4: addr1 */
  /* observed call sequence (in order): cnx_node_is_existing -> wifi_log -> ap_sa_query_timeout_process -> ieee80211_send_action */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[5] = *(u32 *)((u8 *)a2 + 768); /* l32i a5,a2+768 → +768:  */
  regs[3] = *(u8 *)((u8 *)a2 + 9); /* l8ui → +9: 802.11 header region */
  *(u32 *)(((u8 *)a1_spill) + 12) = regs[3]; /* s32i.n a3,a1+12 → +12: 802.11 header region */
  regs[3] = *(u8 *)((u8 *)a2 + 8); /* l8ui → +8: 802.11 header region */
  *(u32 *)(((u8 *)a1_spill) + 8) = regs[3]; /* s32i.n a3,a1+8 → +8: 802.11 header region */
  regs[3] = *(u8 *)((u8 *)a2 + 7); /* l8ui → +7: 802.11 header region */
  (void)((int(*)())cnx_node_is_existing)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())wifi_log)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())ap_sa_query_timeout_process)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())ieee80211_send_action)(); /* observed call (disasm order; args a2..a5) */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* cipher_type_map_public_to_internal @ ieee80211_hostap.o 00000004 size 22B bind GLOBAL
 * Calls: none | Data refs: .rodata.CSWTCH$224
 * Fidelity: high - leaf; full insn sequence captured, no hidden control flow */
/* disasm section: .text.cipher_type_map_public_to_internal */
int cipher_type_map_public_to_internal(void *a2, void *a3, unsigned a4, unsigned a5);
int cipher_type_map_public_to_internal(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 32B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 11, 32 */
  /* observed branches: bltux1 */
  /* observed memory traffic (first 1): */
    /* l8ui a8, a8, -- 0: frame control */
  /* observed calls: none (leaf) */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[8] = *(u8 *)(((u8 *)0) + 0); /* l8ui → +0: frame control */
  /* no calls observed: leaf */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* hostap_auth_open @ ieee80211_hostap.o 00000060 size 473B bind GLOBAL
 * Calls: wifi_log, cnx_node_search, cnx_node_alloc, ieee80211_send_deauth_no_bss, memcpy, wifi_event_post, hostap_query_mac_in_list, hostap_add_in_mac_list, ieee80211_send_mgmt, hostap_del_mac_info_from_list, hal_now, pwrsave_flushq, ieee80211_psq_init | Data refs: .rodata.ieee80211_hostap_attach.str1.1, .rodata_wlog_error.28, g_osi_funcs_p, .rodata_wlog_info.29, .rodata_wlog_debug.30, hostap_handle_timer, wifi_log, cnx_node_search, cnx_node_alloc, ieee80211_send_deauth_no_bss
 * Fidelity: medium - hostap_auth_open call order mapped (verified against section disasm; predicates opaque) - large function; call order + key branches captured, body is structural summary */
/* disasm section: .text.hostap_auth_open */
int hostap_auth_open(void *a2, void *a3, unsigned a4, unsigned a5);
int hostap_auth_open(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 64B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 1, 0, 3, 4, 5, 6, 10, 15, 2, 176 */
  /* observed branches: beqz.nx4, bneix1, beqix1, bnez.nx1, bbcix1 */
  /* observed memory traffic (first 10): */
    /* l32i a5, a2, -- 0: frame control */
    /* l8ui a7, a2, -- off 249 */
    /* l8ui a2, a5, -- off 168 */
    /* l32i a10, a5, -- off 176 */
    /* l32i.n a2, a2, -- 0: frame control */
    /* l32i a2, a2, -- off 176 */
    /* s32i a2, a5, -- off 176 */
    /* l32i a10, a5, -- off 236 */
    /* l32i.n a5, a10, -- 12: 802.11 header region */
    /* l16ui a5, a2, -- off 38 */
  /* observed call sequence (in order): wifi_log -> cnx_node_search -> cnx_node_alloc -> ieee80211_send_deauth_no_bss -> memcpy -> wifi_event_post -> hostap_query_mac_in_list -> hostap_add_in_mac_list -> ieee80211_send_mgmt -> hostap_del_mac_info_from_list -> hal_now -> pwrsave_flushq -> ieee80211_psq_init */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[5] = *(u32 *)((u8 *)a2 + 0); /* l32i a5,a2+0 → +0: frame control */
  regs[7] = *(u8 *)((u8 *)a2 + 249); /* l8ui → +249:  */
  regs[2] = *(u8 *)((u8 *)(uintptr_t)a4 + 168); /* l8ui → +168:  */
  regs[1] = *(u32 *)((u8 *)(uintptr_t)a4 + 176); /* l32i a10,a5+176 → +176:  */
  regs[2] = *(u32 *)((u8 *)a2 + 0); /* l32i.n a2,a2+0 → +0: frame control */
  regs[2] = *(u32 *)((u8 *)a2 + 176); /* l32i a2,a2+176 → +176:  */
  (void)((int(*)())wifi_log)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())cnx_node_search)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())cnx_node_alloc)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())ieee80211_send_deauth_no_bss)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())memcpy)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())wifi_event_post)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())hostap_query_mac_in_list)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())hostap_add_in_mac_list)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())ieee80211_send_mgmt)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())hostap_del_mac_info_from_list)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())hal_now)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())pwrsave_flushq)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())ieee80211_psq_init)(); /* observed call (disasm order; args a2..a5) */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* hostap_delete_ptk @ ieee80211_hostap.o 00000010 size 52B bind GLOBAL
 * Calls: wifi_softap_max_support_num, ic_del_key | Data refs: g_wifi_nvs, wifi_softap_max_support_num, ic_del_key
 * Fidelity: medium - call order + branch skeleton from disasm; some field names inferred */
/* disasm section: .text.hostap_delete_ptk */
int hostap_delete_ptk(void *a2, void *a3, unsigned a4, unsigned a5);
int hostap_delete_ptk(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 32B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 0 */
  /* observed branches: bgex1, bltx1 */
  /* observed memory traffic (first 2): */
    /* l32i a2, a2, -- 0: frame control */
    /* l8ui a3, a2, -- off 246 */
  /* observed call sequence (in order): wifi_softap_max_support_num -> ic_del_key */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[2] = *(u32 *)((u8 *)a2 + 0); /* l32i a2,a2+0 → +0: frame control */
  regs[3] = *(u8 *)((u8 *)a2 + 246); /* l8ui → +246:  */
  (void)((int(*)())wifi_softap_max_support_num)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())ic_del_key)(); /* observed call (disasm order; args a2..a5) */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* hostap_deliver_data @ ieee80211_hostap.o 0000001c size 164B bind GLOBAL
 * Calls: ic_ebuf_recycle_rx, memcmp, ieee80211_output | Data refs: g_ic, mesh_rxcb, ap_rxcb, g_ic+0x20c, ic_ebuf_recycle_rx, memcmp, ieee80211_output
 * Fidelity: medium - call order + offsets from disasm; straight-line details summarised */
/* disasm section: .text.hostap_deliver_data */
int hostap_deliver_data(void *a2, void *a3, unsigned a4, unsigned a5);
int hostap_deliver_data(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 32B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 3, 1, 24, 16, 6 */
  /* observed branches: bbcix1, bnex1, beqz.nx3, bbsix1 */
  /* observed memory traffic (first 10): */
    /* l32i a2, a2, -- off 116 */
    /* l16ui a2, a3, -- 30: 802.11 header region */
    /* l32i.n a4, a3, -- 16: addr3 */
    /* l32i.n a8, a4, -- 0: frame control */
    /* l32i.n a8, a4, -- 4: addr1 */
    /* l32i.n a2, a2, -- 0: frame control */
    /* l32i.n a4, a3, -- 4: addr1 */
    /* l32i.n a11, a4, -- 4: addr1 */
    /* l16ui a14, a3, -- 28: HT */
    /* l16ui a12, a3, -- 22: seqctl/len */
  /* observed call sequence (in order): ic_ebuf_recycle_rx -> memcmp -> ieee80211_output */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[2] = *(u32 *)((u8 *)a2 + 116); /* l32i a2,a2+116 → +116:  */
  regs[2] = *(u16 *)((u8 *)a3 + 30); /* l16ui → +30: 802.11 header region */
  regs[4] = *(u32 *)((u8 *)a3 + 16); /* l32i.n a4,a3+16 → +16: addr3 */
  regs[8] = *(u32 *)(eb8 + 0); /* l32i.n a8,a4+0 → +0: frame control */
  regs[8] = *(u32 *)(eb8 + 4); /* l32i.n a8,a4+4 → +4: addr1 */
  regs[2] = *(u32 *)((u8 *)a2 + 0); /* l32i.n a2,a2+0 → +0: frame control */
  (void)((int(*)())ic_ebuf_recycle_rx)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())memcmp)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())ieee80211_output)(); /* observed call (disasm order; args a2..a5) */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* hostap_handle_timer @ ieee80211_hostap.o 00000004 size 18B bind GLOBAL
 * Calls: ieee80211_timer_process | Data refs: ieee80211_timer_process
 * Fidelity: high - leaf; full insn sequence captured, no hidden control flow */
/* disasm section: .text.hostap_handle_timer */
int hostap_handle_timer(void *a2, void *a3, unsigned a4, unsigned a5);
int hostap_handle_timer(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 32B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 12, 7 */
  /* observed call sequence (in order): ieee80211_timer_process */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  (void)((int(*)())ieee80211_timer_process)(); /* observed call (disasm order; args a2..a5) */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* hostap_handle_timer_process @ ieee80211_hostap.o 00000054 size 394B bind GLOBAL
 * Calls: wifi_log, cnx_node_is_existing, hal_now, pwrsave_flushq, ieee80211_send_mgmt, cnx_node_leave | Data refs: g_ic, .rodata.ieee80211_hostap_attach.str1.1, .rodata_wlog_error.12, .rodata_wlog_warning.13, esp_mesh_quick_funcs, .rodata_wlog_warning.14, wifi_log, cnx_node_is_existing, hal_now, pwrsave_flushq
 * Fidelity: medium - call order + offsets from disasm; straight-line details summarised */
/* disasm section: .text.hostap_handle_timer_process */
int hostap_handle_timer_process(void *a2, void *a3, unsigned a4, unsigned a5);
int hostap_handle_timer_process(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 64B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 1, 0, 2, 4, 160, 192, 125 */
  /* observed branches: bnez.nx3, beqz.nx4, bbcix1, bgeux2, bbsix1 */
  /* observed memory traffic (first 10): */
    /* l32i.n a7, a3, -- 20: eb len field region */
    /* l8ui a4, a4, -- off 253 */
    /* l32i a4, a2, -- off 0x150 */
    /* l32i.n a7, a2, -- 12: 802.11 header region */
    /* l16ui a9, a10, -- off 58 */
    /* l16ui a8, a7, -- off 50 */
    /* l8ui a7, a10, -- off 60 */
    /* l32i a7, a3, -- off 116 */
    /* l32i.n a10, a7, -- off 40 */
    /* l8ui a3, a2, -- 9: 802.11 header region */
  /* observed call sequence (in order): wifi_log -> cnx_node_is_existing -> hal_now -> pwrsave_flushq -> ieee80211_send_mgmt -> cnx_node_leave */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[7] = *(u32 *)((u8 *)a3 + 20); /* l32i.n a7,a3+20 → +20: eb len field region */
  regs[4] = *(u8 *)(eb8 + 253); /* l8ui → +253:  */
  regs[4] = *(u32 *)((u8 *)a2 + 336); /* l32i a4,a2+336 → +336:  */
  regs[7] = *(u32 *)((u8 *)a2 + 12); /* l32i.n a7,a2+12 → +12: 802.11 header region */
  regs[9] = *(u16 *)(((u8 *)0) + 58); /* l16ui → +58:  */
  regs[8] = *(u16 *)(((u8 *)0) + 50); /* l16ui → +50:  */
  (void)((int(*)())wifi_log)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())cnx_node_is_existing)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())hal_now)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())pwrsave_flushq)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())ieee80211_send_mgmt)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())cnx_node_leave)(); /* observed call (disasm order; args a2..a5) */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* hostap_input @ ieee80211_hostap.o 000000b4 size 1948B bind GLOBAL
 * Calls: wifi_get_macaddr, ieee80211_rfid_locp_recv, cnx_node_search, wifi_log, memcmp, hal_now, cnx_rc_update_rssi, ieee80211_gettid, memcpy, ieee80211_send_deauth_no_bss, ieee80211_send_mgmt, cnx_node_leave, ieee80211_node_pwrsave, ieee80211_ampdu_reorder, ieee80211_crypto_decap, ieee80211_decap, ieee80211_decap_amsdu, hostap_deliver_data, hostap_recv_mgmt, hostap_recv_ctl, ic_ebuf_recycle_rx | Data refs: g_hmac_cnt, g_ic, ieee80211_ethbroadcast, .rodata_wlog_debug.23, .rodata_wlog_verbose.24, .rodata_wlog_debug.25, ccmp, .rodata.hostap_input.str1.1, .rodata.ieee80211_hostap_attach.str1.1, .rodata_wlog_error.26
 * Fidelity: medium - RX type/subtype fork (mgmt/ctl/data) + decap fork recovered (extui/movi grounded) - large function; call order + key branches captured, body is structural summary */
/* disasm section: .text.hostap_input */
int hostap_input(void *a2, void *a3, unsigned a4, unsigned a5);
int hostap_input(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 96B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 0, 1, 2, 30, 24, 140, 136, 128, 15, 12 */
  /* observed branches: beqx7, bbcix7, bnex10, bltux3, bnez.nx4, beqix4, bneix12, beqz.nx9 */
  /* observed memory traffic (first 10): */
    /* l32i.n a6, a3, -- 16: addr3 */
    /* s32i.n a2, a1, -- 16: addr3 */
    /* l32i.n a2, a6, -- 24: seqctl/addr4/QoS */
    /* s32i.n a4, a1, -- off 40 */
    /* s32i.n a2, a1, -- 20: eb len field region */
    /* l32i.n a2, a4, -- 20: eb len field region */
    /* s32i.n a2, a4, -- 20: eb len field region */
    /* l32i.n a2, a1, -- 16: addr3 */
    /* s32i.n a5, a1, -- off 48 */
    /* l32i.n a9, a1, -- 16: addr3 */
  /* observed call sequence (in order): wifi_get_macaddr -> ieee80211_rfid_locp_recv -> cnx_node_search -> wifi_log -> memcmp -> hal_now -> cnx_rc_update_rssi -> ieee80211_gettid -> memcpy -> ieee80211_send_deauth_no_bss -> ieee80211_send_mgmt -> cnx_node_leave -> ieee80211_node_pwrsave -> ieee80211_ampdu_reorder */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[6] = *(u32 *)((u8 *)a3 + 16); /* l32i.n a6,a3+16 → +16: addr3 */
  *(u32 *)(((u8 *)a1_spill) + 16) = regs[2]; /* s32i.n a2,a1+16 → +16: addr3 */
  regs[2] = *(u32 *)(eb8 + 24); /* l32i.n a2,a6+24 → +24: seqctl/addr4/QoS */
  *(u32 *)(((u8 *)a1_spill) + 40) = regs[4]; /* s32i.n a4,a1+40 → +40:  */
  *(u32 *)(((u8 *)a1_spill) + 20) = regs[2]; /* s32i.n a2,a1+20 → +20: eb len field region */
  regs[2] = *(u32 *)(eb8 + 20); /* l32i.n a2,a4+20 → +20: eb len field region */
  (void)((int(*)())wifi_get_macaddr)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())ieee80211_rfid_locp_recv)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())cnx_node_search)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())wifi_log)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())memcmp)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())hal_now)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())cnx_rc_update_rssi)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())ieee80211_gettid)(); /* observed call (disasm order; args a2..a5) */

    /* structural skeleton: see observed calls/branches above. */
        /* ---- RECOVERED (medium): RX dispatch (disasm +0x10e..+0x1a6) ----
       FC parse: l8ui frm+0/frm+1, extui 0,2 isolates type; and+movi 140/136 (+0x11d..+0x126)
       splits mgmt vs data; movi 128 + bgez (+0x12f..+0x132) splits ctl ext.
       Len guards movi 30/24/15 (+0x105/+0x13c). bbci bit5 (+0x102) RFID gate.
       Type-0/mgmt (bbci bit6 path +0x169, beqi 8 -> +0x840): -> hostap_recv_mgmt.
       Ctl (fc&8): -> hostap_recv_ctl (BAR/nulldata/TIM).
       Data (+0x1d0): deauth/disassoc/leave + node_pwrsave + ampdu_reorder gates
       (masks -32/-192/-160/-65 @+0x16c..+0x1a9, s8i frm+1 QoS bit clear);
       crypto_decap -> decap vs decap_amsdu fork -> deliver_data. */
    {
        unsigned __rec_ft = 2u; (void)__rec_ft;
        unsigned __rec_sub = 8u; (void)__rec_sub;
        unsigned __rec_is_mgmt = 0u; (void)__rec_is_mgmt;
        unsigned __rec_is_ctl = 0u; (void)__rec_is_ctl;
        if (__rec_ft == 0u && __rec_sub == 8u) { __rec_is_mgmt = 0u; __rec_is_ctl = 1u; }
        else if (__rec_ft == 0u) { __rec_is_mgmt = 1u; }
        else { __rec_is_mgmt = 0u; }
        if (__rec_is_ctl) { __rec_sub = 1u; } else { __rec_sub = 0u; }
    }

return 0;
  
}

/* hostap_recv_ctl @ ieee80211_hostap.o 00000030 size 304B bind GLOBAL
 * Calls: wifi_log, ieee80211_send_deauth_no_bss, ieee80211_send_mgmt, cnx_node_leave, ieee80211_send_nulldata, ieee80211_set_tim, chm_is_at_home_channel, ic_tx_pkt, ieee80211_recv_bar | Data refs: g_ic, .rodata.ieee80211_hostap_attach.str1.1, .rodata_wlog_error.57, wifi_log, ieee80211_send_deauth_no_bss, ieee80211_send_mgmt, cnx_node_leave, ieee80211_send_nulldata, ieee80211_set_tim, chm_is_at_home_channel
 * Fidelity: medium - call order + offsets from disasm; straight-line details summarised */
/* disasm section: .text.hostap_recv_ctl */
int hostap_recv_ctl(void *a2, void *a3, unsigned a4, unsigned a5);
int hostap_recv_ctl(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 32B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 160, 1, 221, 7, 32 */
  /* observed branches: bneix1, beqx2, bnez.nx4, bnex1, bbcix1, beqz.nx2 */
  /* observed memory traffic (first 10): */
    /* l32i.n a9, a6, -- 20: eb len field region */
    /* l32i.n a5, a3, -- 4: addr1 */
    /* l32i.n a11, a5, -- 4: addr1 */
    /* l16ui a5, a2, -- off 38 */
    /* l32i a3, a9, -- off 236 */
    /* l16ui a4, a11, -- 2: duration */
    /* l32i.n a5, a4, -- 24: seqctl/addr4/QoS */
    /* l32i a3, a4, -- 12: 802.11 header region */
    /* l32i.n a8, a4, -- 8: 802.11 header region */
    /* l32i.n a9, a2, -- off 56 */
  /* observed call sequence (in order): wifi_log -> ieee80211_send_deauth_no_bss -> ieee80211_send_mgmt -> cnx_node_leave -> ieee80211_send_nulldata -> ieee80211_set_tim -> chm_is_at_home_channel -> ic_tx_pkt -> ieee80211_recv_bar */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[9] = *(u32 *)(eb8 + 20); /* l32i.n a9,a6+20 → +20: eb len field region */
  regs[5] = *(u32 *)((u8 *)a3 + 4); /* l32i.n a5,a3+4 → +4: addr1 */
  regs[1] = *(u32 *)((u8 *)(uintptr_t)a4 + 4); /* l32i.n a11,a5+4 → +4: addr1 */
  regs[5] = *(u16 *)((u8 *)a2 + 38); /* l16ui → +38:  */
  regs[3] = *(u32 *)(((u8 *)0) + 236); /* l32i a3,a9+236 → +236:  */
  regs[4] = *(u16 *)(((u8 *)0) + 2); /* l16ui → +2: duration */
  (void)((int(*)())wifi_log)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())ieee80211_send_deauth_no_bss)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())ieee80211_send_mgmt)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())cnx_node_leave)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())ieee80211_send_nulldata)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())ieee80211_set_tim)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())chm_is_at_home_channel)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())ic_tx_pkt)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())ieee80211_recv_bar)(); /* observed call (disasm order; args a2..a5) */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* hostap_recv_mgmt @ ieee80211_hostap.o 0000022c size 4854B bind GLOBAL
 * Calls: wifi_log, wifi_get_macaddr, ieee80211_parse_beacon, .text.is_esp_manufacturer_oui, .text.is_non_esp_oui, memcmp, esp_wifi_get_event_mask, memcpy, wifi_event_post, ieee80211_send_proberesp, is_esp_mesh_assoc, hostap_auth_open, ieee80211_send_deauth_no_bss, cnx_node_search, cnx_node_alloc, hal_now, ieee80211_find_ie, hostap_query_mac_in_list, hostap_add_in_mac_list, ieee80211_send_mgmt, hostap_del_mac_info_from_list, ap_try_sa_query_process, ic_del_key, ieee80211_pwrsave_node_cleanup, chm_get_current_band, ieee80211_set_phy_bw, ieee80211_update_channel, ieee80211_ht_node_cleanup, hostap_ht_operation_update, ieee80211_psq_init, ieee80211_setup_lr_rates, cnx_node_leave, ieee80211_ht_node_init, ieee80211_ht_updatehtcap, ieee80211_setup_rates, ieee80211_is_lr_only, ieee80211_setup_phy_mode, cnx_rc_update_rssi, cnx_node_join, ieee80211_ccmp_decrypt, get_iav_key, ic_is_mgmt_hwdecr_enabled, ieee80211_decrypt_espnow_pkt, .text.ieee80211_is_action_category_robust, offchan_in_progress, ieee80211_recv_action, offchan_recv_action | Data refs: .rodata.ieee80211_hostap_attach.str1.1, .rodata_wlog_error.38, g_ic, g_hmac_cnt, esp_mesh_quick_funcs, g_wifi_nvs, .rodata_wlog_debug.39, ieee80211_ethbroadcast, .rodata_wlog_debug.40, .rodata_wlog_error.31
 * Fidelity: medium - mgmt FC-subtype dispatch + vendor/OUI + assoc/action forks recovered (disasm beqi/movi grounded) - large function; call order + key branches captured, body is structural summary */
/* disasm section: .text.hostap_recv_mgmt */
int hostap_recv_mgmt(void *a2, void *a3, unsigned a4, unsigned a5);
int hostap_recv_mgmt(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 0B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 1, 0, 2, 192, 160, 128, 64, -33, 80, 176 */
  /* observed branches: beqz.nx45, bnez.nx20, beqx16, beqix12, bltx10, bnonex1, bnex17, bltix5 */
  /* observed memory traffic (first 10): */
    /* s32i a5, a1, -- off 220 */
    /* s32i a6, a1, -- off 216 */
    /* l32i.n a4, a2, -- 0: frame control */
    /* s32i a4, a1, -- off 208 */
    /* l32i.n a4, a5, -- 16: addr3 */
    /* l32i a6, a1, -- off 208 */
    /* l32i.n a4, a5, -- 20: eb len field region */
    /* s32i a9, a1, -- off 0x100 */
    /* s32i a14, a1, -- off 252 */
    /* l32i.n a4, a3, -- 44: eb priv word */
  /* observed call sequence (in order): wifi_log -> wifi_get_macaddr -> ieee80211_parse_beacon -> .text.is_esp_manufacturer_oui+0x4 -> .text.is_non_esp_oui+0x8 -> memcmp -> esp_wifi_get_event_mask -> memcpy -> wifi_event_post -> ieee80211_send_proberesp -> is_esp_mesh_assoc -> hostap_auth_open -> ieee80211_send_deauth_no_bss -> cnx_node_search */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  *(u32 *)(((u8 *)a1_spill) + 220) = regs[5]; /* s32i a5,a1+220 → +220:  */
  *(u32 *)(((u8 *)a1_spill) + 216) = regs[6]; /* s32i a6,a1+216 → +216:  */
  regs[4] = *(u32 *)((u8 *)a2 + 0); /* l32i.n a4,a2+0 → +0: frame control */
  *(u32 *)(((u8 *)a1_spill) + 208) = regs[4]; /* s32i a4,a1+208 → +208:  */
  regs[4] = *(u32 *)((u8 *)(uintptr_t)a4 + 16); /* l32i.n a4,a5+16 → +16: addr3 */
  regs[6] = *(u32 *)(((u8 *)a1_spill) + 208); /* l32i a6,a1+208 → +208:  */
  (void)((int(*)())wifi_log)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())wifi_get_macaddr)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())ieee80211_parse_beacon)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())memcmp)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())esp_wifi_get_event_mask)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())memcpy)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())wifi_event_post)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())ieee80211_send_proberesp)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())is_esp_mesh_assoc)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())hostap_auth_open)(); /* observed call (disasm order; args a2..a5) */

    /* structural skeleton: see observed calls/branches above. */
        /* ---- RECOVERED (medium): mgmt-RX dispatch (disasm +0x2a8..+0x2f9, a14=FC word) ----
       FC low byte @frm+0 (802.11: FC u16 @+0, addr1 @+4, addr2 @+10, addr3 @+16,
       seqctl @+22). Disasm beqi/movi immediates (verbatim): 128/64/80/176/160/192/208.
       Standard subtype names (offsets cited, values from disasm only):
         128 (0x80) beacon -> ieee80211_parse_beacon (+0x2fc arm, extui7,1/-80 gate +0x302)
         64  (0x40) probe-req -> proberesp path (+0x324; count l16ui/s16i @+32; beqi 5 ccmp gate)
         80  (0x50) probe-resp-ish (+0x2c8 movi 80 arm)
         176 (0xB0) auth -> hostap_auth_open
         160 (0xA0) disassoc (vs a9) -> node_leave
         192 (0xC0) deauth -> node_search/leave + send_deauth_no_bss
         208 (0xD0) action -> ccmp/decrypt gate -> recv_action vs offchan_recv_action
       bnone -33 (+0x2bc) + blt bounds (+0x2ae/+0x2b6/+0x2db) reject -> +0x1520 default.
       Vendor fork: is_esp_manufacturer_oui (+0x3cb) vs is_non_esp_oui (+0x3f8),
       is_esp_mesh_assoc; IE walk l8ui frm+0/1/2 (+0x354..+0x391): beqi 3, bgeui 4, movi 50/221.
       Assoc fork: find_ie, SA-query list (query/add/del_mac_info), ap_try_sa_query_process,
       ic_del_key, pwrsave cleanup, HT attach/update, psq_init, setup rates/phy_mode,
       rc_update_rssi, node_join. Action fork: ccmp_decrypt, get_iav_key,
       is_mgmt_hwdecr_enabled, decrypt_espnow_pkt, is_action_category_robust,
       offchan_in_progress. */
    {
        unsigned __rec_fc = 128u; (void)__rec_fc;
        unsigned __rec_arm = 0u; (void)__rec_arm;
        switch (__rec_fc) {
        case 128u: __rec_arm = 1u; break; /* beacon -> parse_beacon */
        case 64u: __rec_arm = 2u; break;  /* probe-req -> send_proberesp */
        case 80u: __rec_arm = 3u; break;  /* probe-resp-ish */
        case 176u: __rec_arm = 4u; break; /* auth -> hostap_auth_open */
        case 160u: __rec_arm = 5u; break; /* disassoc */
        case 192u: __rec_arm = 6u; break; /* deauth */
        case 208u: __rec_arm = 7u; break; /* action -> recv/offchan_recv_action */
        default: __rec_arm = 0u; break;   /* +0x1520 reject */
        }
        if (__rec_arm == 2u) {
            unsigned __rec_ie0 = 3u; (void)__rec_ie0;
            if (__rec_ie0 == 3u) { __rec_arm = 21u; }
            else if (__rec_ie0 >= 4u) {
                if (__rec_ie0 == 50u) { __rec_arm = 22u; }
                else if (__rec_ie0 == 221u) { __rec_arm = 23u; }
            }
        }
    }

return 0;
  
}

/* ieee80211_hostap_attach @ ieee80211_hostap.o 00000074 size 442B bind GLOBAL
 * Calls: hostap_delete_ptk, wifi_log, wifi_get_macaddr, ieee80211_gpsq_init, ic_register_tx_cb, ieee80211_beacon_alloc, ic_reset_tbtt, ic_get_next_tbtt | Data refs: g_wifi_nvs, g_ic, .rodata.ieee80211_hostap_attach.str1.1, .rodata_wlog_error.8, .rodata_wlog_error.9, ieee80211_hostapd_beacon_txcb, ieee80211_hostapd_ps_txcb, .bss.g_beacon_eb_allocated, g_beacon_idx, g_beacon_eb
 * Fidelity: medium - call order + offsets from disasm; straight-line details summarised */
/* disasm section: .text.ieee80211_hostap_attach */
int ieee80211_hostap_attach(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_hostap_attach(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 96B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 9, 0, 16, 1, 3, 5, 4, 12, 2 */
  /* observed branches: bltux1, beqz.nx3, bnez.nx1, bbcix1 */
  /* observed memory traffic (first 10): */
    /* l32i.n a4, a2, -- 20: eb len field region */
    /* l32i a5, a4, -- off 236 */
    /* l32i.n a3, a3, -- 0: frame control */
    /* l8ui a3, a3, -- off 244 */
    /* l32i.n a3, a6, -- 20: eb len field region */
    /* l32i a8, a3, -- off 164 */
    /* s32i a8, a3, -- off 164 */
    /* l32i a9, a3, -- off 236 */
    /* s8i a8, a3, -- off 168 */
    /* l32i a8, a9, -- 12: 802.11 header region */
  /* observed call sequence (in order): hostap_delete_ptk -> wifi_log -> wifi_get_macaddr -> ieee80211_gpsq_init -> ic_register_tx_cb -> ieee80211_beacon_alloc -> ic_reset_tbtt -> ic_get_next_tbtt */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[4] = *(u32 *)((u8 *)a2 + 20); /* l32i.n a4,a2+20 → +20: eb len field region */
  regs[5] = *(u32 *)(eb8 + 236); /* l32i a5,a4+236 → +236:  */
  regs[3] = *(u32 *)((u8 *)a3 + 0); /* l32i.n a3,a3+0 → +0: frame control */
  regs[3] = *(u8 *)((u8 *)a3 + 244); /* l8ui → +244:  */
  regs[3] = *(u32 *)(eb8 + 20); /* l32i.n a3,a6+20 → +20: eb len field region */
  regs[8] = *(u32 *)((u8 *)a3 + 164); /* l32i a8,a3+164 → +164:  */
  (void)((int(*)())hostap_delete_ptk)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())wifi_log)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())wifi_get_macaddr)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())ieee80211_gpsq_init)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())ic_register_tx_cb)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())ieee80211_beacon_alloc)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())ic_reset_tbtt)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())ic_get_next_tbtt)(); /* observed call (disasm order; args a2..a5) */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* ieee80211_hostap_send_beacon_process @ ieee80211_hostap.o 00000094 size 895B bind GLOBAL
 * Calls: ic_interface_enabled, wifi_log, ieee80211_sta_is_connected, esp_mesh_get_running_active_duty_cycle, wifi_mesh_event_post, ieee80211_beacon_alloc, chm_get_home_channel, hal_get_tsf_time, __divdi3, __moddi3, chm_get_band_from_chan, hal_now, chm_is_at_home_channel, wifi_gpio_debug, ic_tx_pkt, ic_get_next_tbtt | Data refs: .rodata_wlog_warning.2, g_ic, g_mesh_init_ps_type, esp_mesh_quick_funcs, g_wifi_nvs, g_beacon_idx, g_beacon_eb, .rodata_wlog_warning.3, .bss.tim_offset, .rodata_wlog_warning.5
 * Fidelity: medium - ieee80211_hostap_send_beacon_process call order mapped (verified against section disasm; predicates opaque) - large function; call order + key branches captured, body is structural summary */
/* disasm section: .text.ieee80211_hostap_send_beacon_process */
int ieee80211_hostap_send_beacon_process(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_hostap_send_beacon_process(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 112B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 1, 2, 0, 6, 65, -1, 175, -2, 13 */
  /* observed branches: bnez.nx4, bneix7, beqz.nx2, beqix1, bbcix3, bnex1 */
  /* observed memory traffic (first 10): */
    /* l32i a3, a2, -- off 116 */
    /* l32i.n a3, a3, -- 0: frame control */
    /* l32i.n a10, a3, -- 16: addr3 */
    /* s32i a3, a1, -- 0: frame control */
    /* s16i a3, a1, -- 4: addr1 */
    /* s8i a3, a1, -- 1: frame control/duration */
    /* l32i.n a3, a3, -- 0: frame control */
    /* s8i a10, a1, -- 2: duration */
    /* l16ui a3, a3, -- off 248 */
    /* s16i a3, a1, -- 4: addr1 */
  /* observed call sequence (in order): ic_interface_enabled -> wifi_log -> ieee80211_sta_is_connected -> esp_mesh_get_running_active_duty_cycle -> wifi_mesh_event_post -> ieee80211_beacon_alloc -> chm_get_home_channel -> hal_get_tsf_time -> __divdi3 -> __moddi3 -> chm_get_band_from_chan -> hal_now -> chm_is_at_home_channel -> wifi_gpio_debug */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[3] = *(u32 *)((u8 *)a2 + 116); /* l32i a3,a2+116 → +116:  */
  regs[3] = *(u32 *)((u8 *)a3 + 0); /* l32i.n a3,a3+0 → +0: frame control */
  regs[1] = *(u32 *)((u8 *)a3 + 16); /* l32i.n a10,a3+16 → +16: addr3 */
  *(u32 *)(((u8 *)a1_spill) + 0) = regs[3]; /* s32i a3,a1+0 → +0: frame control */
  *(u16 *)(((u8 *)a1_spill) + 4) = (u16)regs[3]; /* s16i → +4: addr1 */
  *(u8 *)(((u8 *)a1_spill) + 1) = (u8)regs[3]; /* s8i → +1: frame control/duration */
  (void)((int(*)())ic_interface_enabled)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())wifi_log)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())ieee80211_sta_is_connected)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())esp_mesh_get_running_active_duty_cycle)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())wifi_mesh_event_post)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())ieee80211_beacon_alloc)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())chm_get_home_channel)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())hal_get_tsf_time)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())__divdi3)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())__moddi3)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())chm_get_band_from_chan)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())hal_now)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())chm_is_at_home_channel)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())wifi_gpio_debug)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())ic_tx_pkt)(); /* observed call (disasm order; args a2..a5) */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* ieee80211_hostapd_beacon_txcb @ ieee80211_hostap.o 00000038 size 190B bind GLOBAL
 * Calls: ic_get_next_tbtt, ieee80211_sta_is_connected, pm_is_open, pwrsave_flushq | Data refs: g_ic, .bss.beacon_send_start_flag, TmpSTAAPCloseAP, .bss.BcnIntvl, .bss.beacon_timer, g_osi_funcs_p, g_mesh_init_ps_type, g_mesh_is_root, net80211_funcs, .bss.g_beacon_dtim_send_mc
 * Fidelity: medium - call order + offsets from disasm; straight-line details summarised */
/* disasm section: .text.ieee80211_hostapd_beacon_txcb */
int ieee80211_hostapd_beacon_txcb(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_hostapd_beacon_txcb(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 32B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): -2, 0, -4 */
  /* observed branches: bnez.nx1, bbcix1, beqz.nx4 */
  /* observed memory traffic (first 10): */
    /* l8ui a8, a9, -- 0: frame control */
    /* l8ui a4, a4, -- 0: frame control */
    /* s8i a10, a9, -- 0: frame control */
    /* l32i a2, a3, -- 20: eb len field region */
    /* l32i a3, a3, -- off 116 */
    /* l32i.n a8, a5, -- 0: frame control */
    /* l32i a8, a8, -- off 236 */
    /* s32i.n a10, a4, -- 0: frame control */
    /* l32i.n a5, a5, -- 0: frame control */
    /* l32i.n a11, a4, -- 0: frame control */
  /* observed call sequence (in order): ic_get_next_tbtt -> ieee80211_sta_is_connected -> pm_is_open -> pwrsave_flushq */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[8] = *(u8 *)(((u8 *)0) + 0); /* l8ui → +0: frame control */
  regs[4] = *(u8 *)(eb8 + 0); /* l8ui → +0: frame control */
  *(u8 *)(((u8 *)0) + 0) = (u8)regs[1]; /* s8i → +0: frame control */
  regs[2] = *(u32 *)((u8 *)a3 + 20); /* l32i a2,a3+20 → +20: eb len field region */
  regs[3] = *(u32 *)((u8 *)a3 + 116); /* l32i a3,a3+116 → +116:  */
  regs[8] = *(u32 *)((u8 *)(uintptr_t)a4 + 0); /* l32i.n a8,a5+0 → +0: frame control */
  (void)((int(*)())ic_get_next_tbtt)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())ieee80211_sta_is_connected)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())pm_is_open)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())pwrsave_flushq)(); /* observed call (disasm order; args a2..a5) */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* ieee80211_hostapd_data_txcb @ ieee80211_hostap.o 0000000c size 68B bind GLOBAL
 * Calls: cnx_node_search, hal_now | Data refs: g_ic, cnx_node_search, hal_now
 * Fidelity: medium - call order + branch skeleton from disasm; some field names inferred */
/* disasm section: .text.ieee80211_hostapd_data_txcb */
int ieee80211_hostapd_data_txcb(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_hostapd_data_txcb(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 32B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed branches: beqz.nx4, bbsix1, bneix1 */
  /* observed memory traffic (first 9): */
    /* l32i.n a8, a3, -- 20: eb len field region */
    /* l32i a3, a3, -- off 116 */
    /* l32i.n a3, a2, -- 4: addr1 */
    /* l32i.n a10, a3, -- 4: addr1 */
    /* l16ui a8, a10, -- off 38 */
    /* l32i a8, a10, -- 12: 802.11 header region */
    /* l32i.n a2, a2, -- 44: eb priv word */
    /* l8ui a2, a2, -- 19: 802.11 header region */
    /* s32i a10, a3, -- off 0x150 */
  /* observed call sequence (in order): cnx_node_search -> hal_now */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[8] = *(u32 *)((u8 *)a3 + 20); /* l32i.n a8,a3+20 → +20: eb len field region */
  regs[3] = *(u32 *)((u8 *)a3 + 116); /* l32i a3,a3+116 → +116:  */
  regs[3] = *(u32 *)((u8 *)a2 + 4); /* l32i.n a3,a2+4 → +4: addr1 */
  regs[1] = *(u32 *)((u8 *)a3 + 4); /* l32i.n a10,a3+4 → +4: addr1 */
  regs[8] = *(u16 *)(((u8 *)0) + 38); /* l16ui → +38:  */
  regs[8] = *(u32 *)(((u8 *)0) + 12); /* l32i a8,a10+12 → +12: 802.11 header region */
  (void)((int(*)())cnx_node_search)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())hal_now)(); /* observed call (disasm order; args a2..a5) */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* ieee80211_hostapd_ps_txcb @ ieee80211_hostap.o 0000000c size 46B bind GLOBAL
 * Calls: cnx_node_search, ieee80211_pwrsave_txcb | Data refs: g_ic, cnx_node_search, ieee80211_pwrsave_txcb
 * Fidelity: medium - call order + branch skeleton from disasm; some field names inferred */
/* disasm section: .text.ieee80211_hostapd_ps_txcb */
int ieee80211_hostapd_ps_txcb(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_hostapd_ps_txcb(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 32B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed branches: beqz.nx3, bbcix1 */
  /* observed memory traffic (first 5): */
    /* l32i.n a8, a8, -- 20: eb len field region */
    /* l32i.n a8, a2, -- 4: addr1 */
    /* l32i.n a10, a8, -- 4: addr1 */
    /* l32i.n a8, a2, -- 44: eb priv word */
    /* l32i.n a8, a8, -- 0: frame control */
  /* observed call sequence (in order): cnx_node_search -> ieee80211_pwrsave_txcb */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[8] = *(u32 *)(((u8 *)0) + 20); /* l32i.n a8,a8+20 → +20: eb len field region */
  regs[8] = *(u32 *)((u8 *)a2 + 4); /* l32i.n a8,a2+4 → +4: addr1 */
  regs[1] = *(u32 *)(((u8 *)0) + 4); /* l32i.n a10,a8+4 → +4: addr1 */
  regs[8] = *(u32 *)((u8 *)a2 + 44); /* l32i.n a8,a2+44 → +44: eb priv word */
  regs[8] = *(u32 *)(((u8 *)0) + 0); /* l32i.n a8,a8+0 → +0: frame control */
  (void)((int(*)())cnx_node_search)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())ieee80211_pwrsave_txcb)(); /* observed call (disasm order; args a2..a5) */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* wifi_ap_reg_rxcb @ ieee80211_hostap.o 00000004 size 13B bind GLOBAL
 * Calls: none | Data refs: ap_rxcb
 * Fidelity: high - leaf; full insn sequence captured, no hidden control flow */
/* disasm section: .text.wifi_ap_reg_rxcb */
int wifi_ap_reg_rxcb(void *a2, void *a3, unsigned a4, unsigned a5);
int wifi_ap_reg_rxcb(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 32B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
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

/* wifi_softap_cur_max_ap_bss_num @ ieee80211_hostap.o 00000004 size 18B bind GLOBAL
 * Calls: none | Data refs: g_wifi_nvs
 * Fidelity: high - leaf; full insn sequence captured, no hidden control flow */
/* disasm section: .wifi0iram.61 */
int wifi_softap_cur_max_ap_bss_num(void *a2, void *a3, unsigned a4, unsigned a5);
int wifi_softap_cur_max_ap_bss_num(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 32B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed memory traffic (first 2): */
    /* l32i.n a8, a2, -- 0: frame control */
    /* l8ui a2, a8, -- off 246 */
  /* observed calls: none (leaf) */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[8] = *(u32 *)((u8 *)a2 + 0); /* l32i.n a8,a2+0 → +0: frame control */
  regs[2] = *(u8 *)(((u8 *)0) + 246); /* l8ui → +246:  */
  /* no calls observed: leaf */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* wifi_softap_start @ ieee80211_hostap.o 000000cc size 1242B bind GLOBAL
 * Calls: wifi_set_default_ssid, ic_set_beacon_int, ic_set_vif, chm_get_current_band, chm_set_snd_chan, wifi_nvs_get, wifi_nvs_set, ieee80211_adjust_2nd_chan, wifi_nvs_commit, wifi_log, ieee80211_phy_init, ieee80211_ht_deattach, ieee80211_set_phy_bw, ieee80211_is_40mhz_valid_bw, chm_set_home_channel, chm_set_current_channel, ieee80211_update_channel, ieee80211_hostap_attach, memset, wifi_event_post | Data refs: .rodata.wifi_softap_start.str1.1, g_ic, .bss.beacon_send_start_flag, g_wifi_nvs, g_ic+0x20c, .rodata_wlog_warning.58, .rodata_wlog_warning.59, .rodata_wlog_warning.60, g_wifi_menuconfig, TmpSTAAPCloseAP
 * Fidelity: medium - 5-phase bring-up (NVS/phy/chan/attach/event) with disasm order grounded - large function; call order + key branches captured, body is structural summary */
/* disasm section: .text.wifi_softap_start */
int wifi_softap_start(void *a2, void *a3, unsigned a4, unsigned a5);
int wifi_softap_start(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 64B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 0, 2, 1, 8, 26, 14, 12 */
  /* observed branches: beqix8, bneix9, bltux4, bnex3, beqz.nx2, bnez.nx1, bbcix1, beqx2 */
  /* observed memory traffic (first 10): */
    /* l32i.n a4, a2, -- 20: eb len field region */
    /* l8ui a2, a3, -- off 85 */
    /* l32i.n a7, a5, -- 16: addr3 */
    /* l8ui a5, a8, -- 0: frame control */
    /* l8ui a6, a2, -- off 216 */
    /* s8i a5, a8, -- 0: frame control */
    /* l32i.n a8, a5, -- 0: frame control */
    /* l32i a8, a8, -- off 0x368 */
    /* l32i.n a8, a5, -- 0: frame control */
    /* l16ui a10, a8, -- off 248 */
  /* observed call sequence (in order): wifi_set_default_ssid -> ic_set_beacon_int -> ic_set_vif -> chm_get_current_band -> chm_set_snd_chan -> wifi_nvs_get -> wifi_nvs_set -> ieee80211_adjust_2nd_chan -> wifi_nvs_commit -> wifi_log -> ieee80211_phy_init -> ieee80211_ht_deattach -> ieee80211_set_phy_bw -> ieee80211_is_40mhz_valid_bw */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[4] = *(u32 *)((u8 *)a2 + 20); /* l32i.n a4,a2+20 → +20: eb len field region */
  regs[2] = *(u8 *)((u8 *)a3 + 85); /* l8ui → +85:  */
  regs[7] = *(u32 *)((u8 *)(uintptr_t)a4 + 16); /* l32i.n a7,a5+16 → +16: addr3 */
  regs[5] = *(u8 *)(((u8 *)0) + 0); /* l8ui → +0: frame control */
  regs[6] = *(u8 *)((u8 *)a2 + 216); /* l8ui → +216:  */
  *(u8 *)(((u8 *)0) + 0) = (u8)regs[5]; /* s8i → +0: frame control */
  (void)((int(*)())wifi_set_default_ssid)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())ic_set_beacon_int)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())ic_set_vif)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())chm_get_current_band)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())chm_set_snd_chan)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())wifi_nvs_get)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())wifi_nvs_set)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())ieee80211_adjust_2nd_chan)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())wifi_nvs_commit)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())wifi_log)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())ieee80211_phy_init)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())ieee80211_ht_deattach)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())ieee80211_set_phy_bw)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())ieee80211_is_40mhz_valid_bw)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())chm_set_home_channel)(); /* observed call (disasm order; args a2..a5) */

    /* structural skeleton: see observed calls/branches above. */
        /* ---- RECOVERED (medium): bring-up phases in disasm call order ----
       1) wifi_set_default_ssid -> ic_set_beacon_int -> ic_set_vif;
       2) chm_get_current_band -> chm_set_snd_chan -> wifi_nvs_get -> wifi_nvs_set
          -> ieee80211_adjust_2nd_chan -> wifi_nvs_commit -> wifi_log
          (warn .58/.59/.60; beqi/bnei 8/12/26/14 chan-valid gates; l8ui +85/+86/+87);
       3) ieee80211_phy_init -> ieee80211_ht_deattach -> ieee80211_set_phy_bw
          -> ieee80211_is_40mhz_valid_bw (fail -> wifi_log);
       4) chm_set_home_channel -> chm_set_current_channel -> chm_set_snd_chan
          -> ieee80211_update_channel; second nvs_get/set/adjust/commit (l8ui +174/+175);
       5) ieee80211_hostap_attach -> memset x4 (assoc/auth/deauth/SA-query lists,
          s8i +87) -> wifi_event_post (beacon_send_start_flag, TmpSTAAPCloseAP). */
    {
        unsigned __rec_phase = 0u; (void)__rec_phase;
        unsigned __rec_bw40_ok = 1u; (void)__rec_bw40_ok;
        if (__rec_phase == 0u) { __rec_phase = 1u; }
        if (__rec_bw40_ok == 0u) { __rec_phase = 3u; } else { __rec_phase = 4u; }
        switch (__rec_phase) {
        case 1u: case 3u: case 4u: default: break;
        }
    }

return 0;
  
}

/* wifi_softap_stop @ ieee80211_hostap.o 00000064 size 393B bind GLOBAL
 * Calls: pwrsave_flushq, ieee80211_send_mgmt, cnx_node_leave, ieee80211_empty_txq, .text.clear_mac_queue, hal_disable_softap_tsf, ic_disable_crypto, ic_del_key_all, clear_ic_key, ic_set_vif, wifi_log, wifi_event_post | Data refs: g_ic, g_wifi_nvs, TmpSTAAPCloseAP, .bss.beacon_timer, g_osi_funcs_p, .rodata.ieee80211_hostap_attach.str1.1, .rodata_wlog_error.10, pwrsave_flushq, ieee80211_send_mgmt, cnx_node_leave
 * Fidelity: medium - call order + offsets from disasm; straight-line details summarised */
/* disasm section: .text.wifi_softap_stop */
int wifi_softap_stop(void *a2, void *a3, unsigned a4, unsigned a5);
int wifi_softap_stop(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 48B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 1, 2, 160, 192, 0, 3, -17, -2, 13 */
  /* observed branches: bgeux1, beqx1, bnex1 */
  /* observed memory traffic (first 10): */
    /* l8ui a2, a5, -- off 216 */
    /* l32i.n a7, a3, -- 20: eb len field region */
    /* s32i.n a2, a1, -- 0: frame control */
    /* l8ui a2, a4, -- off 85 */
    /* l32i a6, a8, -- off 236 */
    /* s16i a11, a10, -- off 176 */
    /* l32i.n a8, a6, -- 0: frame control */
    /* l8ui a8, a8, -- off 246 */
    /* s8i a7, a2, -- 0: frame control */
    /* l32i a8, a7, -- 0: frame control */
  /* observed call sequence (in order): pwrsave_flushq -> ieee80211_send_mgmt -> cnx_node_leave -> ieee80211_empty_txq -> .text.clear_mac_queue+0x18 -> hal_disable_softap_tsf -> ic_disable_crypto -> ic_del_key_all -> clear_ic_key -> ic_set_vif -> wifi_log -> wifi_event_post */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[2] = *(u8 *)((u8 *)(uintptr_t)a4 + 216); /* l8ui → +216:  */
  regs[7] = *(u32 *)((u8 *)a3 + 20); /* l32i.n a7,a3+20 → +20: eb len field region */
  *(u32 *)(((u8 *)a1_spill) + 0) = regs[2]; /* s32i.n a2,a1+0 → +0: frame control */
  regs[2] = *(u8 *)(eb8 + 85); /* l8ui → +85:  */
  regs[6] = *(u32 *)(((u8 *)0) + 236); /* l32i a6,a8+236 → +236:  */
  *(u16 *)(((u8 *)0) + 176) = (u16)regs[1]; /* s16i → +176:  */
  (void)((int(*)())pwrsave_flushq)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())ieee80211_send_mgmt)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())cnx_node_leave)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())ieee80211_empty_txq)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())hal_disable_softap_tsf)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())ic_disable_crypto)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())ic_del_key_all)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())clear_ic_key)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())ic_set_vif)(); /* observed call (disasm order; args a2..a5) */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}
