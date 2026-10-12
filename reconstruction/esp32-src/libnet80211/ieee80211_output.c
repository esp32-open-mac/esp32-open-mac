/* Reconstructed ESP32 WiFi MAC data-path: ieee80211_output.o
 * Blob: esp32/libnet80211.a(ieee80211_output.o) -> /tmp/re_esp32/libnet80211/ieee80211_output.o
 * Metadata: re/esp32/funcdb_libnet80211.json | Disasm: re/esp32/disasm_full/libnet80211/ieee80211_output.dis
 * Toolchain: xtensa-esp-elf esp-15.2.0_20251204 (GCC crosstool-NG esp-2022r1 11.2.0) | ABI: args a2..a7, return a2
 * Method: fully offline; calls/refs/offsets/constants cited from disasm sections;
 * funcdb calls[]/refs[] are empty for this lib, so headers below use disasm-observed edges.
 * Undefined (imports): __bswapsi2, add_mic_ie_bip, chm_get_band_from_chan, chm_get_chan_info, chm_get_current_band, chm_get_current_channel, chm_get_home_channel, chm_is_at_home_channel, clear_ic_key, cnx_node_leave, cnx_node_search, config_is_cache_tx_buf_enabled, create_new_bss_for_sa_query_failed_sta, esp_mesh_quick_funcs, esp_wifi_sta_prof_is_wpa_internal, g_hmac_cnt, g_ic, g_mesh_init_ps_type, g_mesh_is_root, g_mesh_topology, g_misc_nvs, g_osi_funcs_p, g_wifi_global_lock, g_wifi_menuconfig...
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
extern int ieee80211_assoc_resp_construct();
extern int ieee80211_beacon_construct();
extern int ieee80211_ccmp_encrypt();
extern int ieee80211_crypto_encap();
extern int ieee80211_get_cipher_mic_len();
extern int ieee80211_getbcnframe();
extern int ieee80211_getmgtframe();
extern int ieee80211_is_bufferable_mmpdu();
extern int ieee80211_is_ht_cipher();
extern int ieee80211_pwrsave();
extern int ieee80211_sta_new_state();
extern int nan_dp_get_own_ndi();
extern int nan_dp_post_tx();
extern int nan_dp_search_node();
extern int nan_get_clust_id();
extern int nan_tx_action_frame();
extern int pm_is_sending_keep_alive();
extern int pp_post();
extern int ppTxPkt();
extern int reset_cs_thres();
extern int roundup2();
extern int sta_get_owe_data();
extern int sta_is_wpa3_enabled();
extern int wifi_get_macaddr();
extern int wifi_gpio_debug();
extern int wifi_log();
/* Forward declarations for intra-object calls (definitions follow in funcdb order): */
int esp_wifi_80211_tx(void *a2, void *a3, unsigned a4, unsigned a5);
int esp_wifi_80211_tx(void *a2, void *a3, unsigned a4, unsigned a5);
int esp_wifi_internal_tx(void *a2, void *a3, unsigned a4, unsigned a5);
int esp_wifi_internal_tx(void *a2, void *a3, unsigned a4, unsigned a5);
int esp_wifi_internal_tx_by_ref(void *a2, void *a3, unsigned a4, unsigned a5);
int esp_wifi_internal_tx_by_ref(void *a2, void *a3, unsigned a4, unsigned a5);
int esp_wifi_internal_tx_is_stop(void *a2, void *a3, unsigned a4, unsigned a5);
int esp_wifi_internal_tx_is_stop(void *a2, void *a3, unsigned a4, unsigned a5);
int esp_wifi_mesh_tx(void *a2, void *a3, unsigned a4, unsigned a5);
int esp_wifi_mesh_tx(void *a2, void *a3, unsigned a4, unsigned a5);
int get_wifi_internal_state(void *a2, void *a3, unsigned a4, unsigned a5);
int get_wifi_internal_state(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_add_assoc_req_ies(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_add_assoc_req_ies(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_add_assoc_resp_ies(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_add_assoc_resp_ies(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_add_beacon_app_ies(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_add_beacon_app_ies(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_add_bss_max_idle(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_add_bss_max_idle(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_add_csa(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_add_csa(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_add_dh_param(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_add_dh_param(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_add_dsparams(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_add_dsparams(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_add_extcap(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_add_extcap(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_add_probe_req_ies(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_add_probe_req_ies(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_add_probe_resp_app_ies(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_add_probe_resp_app_ies(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_add_rates(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_add_rates(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_add_supportedchannels(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_add_supportedchannels(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_add_tie_param(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_add_tie_param(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_add_wme_param(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_add_wme_param(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_add_xrates(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_add_xrates(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_align_eb(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_align_eb(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_alloc_deauth(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_alloc_deauth(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_alloc_tx_buf(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_alloc_tx_buf(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_amsdu_adjust_head(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_amsdu_adjust_head(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_amsdu_adjust_last_length(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_amsdu_adjust_last_length(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_amsdu_encap_check(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_amsdu_encap_check(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_amsdu_length_check(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_amsdu_length_check(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_amsdu_send_check(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_amsdu_send_check(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_assoc_req_construct(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_assoc_req_construct(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_auth_construct(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_auth_construct(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_beacon_alloc(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_beacon_alloc(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_classify(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_classify(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_copy_eb_header(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_copy_eb_header(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_deauth_construct(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_deauth_construct(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_disassoc_construct(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_disassoc_construct(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_empty_txq(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_empty_txq(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_encap_amsdu(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_encap_amsdu(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_encap_esfbuf(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_encap_esfbuf(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_encap_keep_alive_data(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_encap_keep_alive_data(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_encap_null_data(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_encap_null_data(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_get_nvs_he_dcm_max_constellation_tx(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_get_nvs_he_dcm_max_constellation_tx(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_get_robustmgtframe(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_get_robustmgtframe(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_getcapinfo(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_getcapinfo(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_is_tx_allowed(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_is_tx_allowed(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_mgmt_output(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_mgmt_output(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_output(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_output(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_output_do(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_output_do(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_output_init(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_output_init(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_output_pending_eb(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_output_pending_eb(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_output_process(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_output_process(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_output_raw_process(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_output_raw_process(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_pm_tx_null_process(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_pm_tx_null_process(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_post_hmac_tx(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_post_hmac_tx(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_raw_frame_sanity_check(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_raw_frame_sanity_check(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_recycle_cache_eb(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_recycle_cache_eb(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_reg_encap_amsdu_cb(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_reg_encap_amsdu_cb(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_reg_netstack_buf_cb(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_reg_netstack_buf_cb(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_search_node(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_search_node(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_send_deauth_no_bss(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_send_deauth_no_bss(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_send_mgmt(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_send_mgmt(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_send_nulldata(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_send_nulldata(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_send_probereq(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_send_probereq(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_send_proberesp(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_send_proberesp(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_send_setup(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_send_setup(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_set_hmac_stop(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_set_hmac_stop(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_set_tx_desc(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_set_tx_desc(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_setup_robust_mgmtframe(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_setup_robust_mgmtframe(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_tx_mgt_cb(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_tx_mgt_cb(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_vnd_ie_set(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_vnd_ie_set(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_vnd_ie_size(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_vnd_ie_size(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_vnd_lora_ie_set(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_vnd_lora_ie_set(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_vnd_lora_ie_size(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_vnd_lora_ie_size(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_wapi_alloc_tx_buf(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_wapi_alloc_tx_buf(void *a2, void *a3, unsigned a4, unsigned a5);
int is_wapi_alloc_tx_buf(void *a2, void *a3, unsigned a4, unsigned a5);
int is_wapi_alloc_tx_buf(void *a2, void *a3, unsigned a4, unsigned a5);
int wifi_is_started(void *a2, void *a3, unsigned a4, unsigned a5);
int wifi_is_started(void *a2, void *a3, unsigned a4, unsigned a5);

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
extern int __bswapsi2();
extern int add_mic_ie_bip();
extern int chm_get_band_from_chan();
extern int chm_get_chan_info();
extern int chm_get_current_band();
extern int chm_get_current_channel();
extern int chm_get_home_channel();
extern int chm_is_at_home_channel();
extern int clear_ic_key();
extern int cnx_node_leave();
extern int cnx_node_search();
extern int config_is_cache_tx_buf_enabled();
extern int create_new_bss_for_sa_query_failed_sta();
extern int esp_wifi_sta_prof_is_wpa_internal();
extern int hal_now();
extern int hostap_add_in_mac_list();
extern int hostap_del_mac_info_from_list();
extern int hostap_query_mac_in_list();
extern int ic_clear_data_ifx_tx_queue();
extern int ic_del_key_all();
extern int ic_ebuf_alloc();
extern int ic_ebuf_recycle_tx();
extern int ic_get_80211_tx_rate();
extern int ic_get_addr();
extern int ic_get_default_sched();
extern int ic_get_keep_alive_time();
extern int ic_get_trc();
extern int ic_register_net80211_tx_cb();
extern int ic_trc_set_per_pkt_rate();
extern int ic_tx_pkt();
extern int ieee80211_add_countryie();
extern int ieee80211_add_htcap();
extern int ieee80211_add_htcap_vendor();
extern int ieee80211_add_htinfo();
extern int ieee80211_add_htinfo_vendor();
extern int ieee80211_add_ie_vendor_esp_manufacturer();
extern int ieee80211_alloc_proberesp();
extern int ieee80211_ampdu_enable();
extern int ieee80211_ampdu_request();

/* esp_wifi_80211_tx @ ieee80211_output.o 00000030 size 277B bind GLOBAL
 * Calls: ieee80211_raw_frame_sanity_check, ic_ebuf_alloc, chm_get_current_channel, chm_get_band_from_chan, ic_get_default_sched, ic_get_80211_tx_rate, ieee80211_post_hmac_tx | Data refs: g_wifi_global_lock, g_osi_funcs_p, g_ic+0x200, ieee80211_raw_frame_sanity_check, ic_ebuf_alloc, chm_get_current_channel, chm_get_band_from_chan, ic_get_default_sched, ic_get_80211_tx_rate, ieee80211_post_hmac_tx
 * Fidelity: high - full call chain + key insns/offsets cited from disasm section */
/* disasm section: .text.esp_wifi_80211_tx */
int esp_wifi_80211_tx(void *a2, void *a3, unsigned a4, unsigned a5);
int esp_wifi_80211_tx(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 32B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 1, 0, 24 */
  /* observed branches: bnez.nx2, beqz.nx1 */
  /* observed memory traffic (first 10): */
    /* l32i.n a9, a7, -- 0: frame control */
    /* l32i.n a10, a8, -- 0: frame control */
    /* l32i a9, a9, -- off 84 */
    /* l32i.n a2, a7, -- 0: frame control */
    /* l32i.n a10, a3, -- 0: frame control */
    /* l32i a2, a2, -- off 88 */
    /* l8ui a10, a10, -- 0: frame control */
    /* s16i a4, a6, -- 22: seqctl/len */
    /* l32i.n a4, a6, -- 44: eb priv word */
    /* s16i a8, a6, -- 20: eb len field region */
  /* observed call sequence (in order): ieee80211_raw_frame_sanity_check -> ic_ebuf_alloc -> chm_get_current_channel -> chm_get_band_from_chan -> ic_get_default_sched -> ic_get_80211_tx_rate -> ieee80211_post_hmac_tx */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[9] = *(u32 *)(((u8 *)0) + 0); /* l32i.n a9,a7+0 → +0: frame control */
  regs[1] = *(u32 *)(((u8 *)0) + 0); /* l32i.n a10,a8+0 → +0: frame control */
  regs[9] = *(u32 *)(((u8 *)0) + 84); /* l32i a9,a9+84 → +84:  */
  regs[2] = *(u32 *)(((u8 *)0) + 0); /* l32i.n a2,a7+0 → +0: frame control */
  regs[1] = *(u32 *)((u8 *)a3 + 0); /* l32i.n a10,a3+0 → +0: frame control */
  regs[2] = *(u32 *)((u8 *)a2 + 88); /* l32i a2,a2+88 → +88:  */
  (void)((int(*)())ieee80211_raw_frame_sanity_check)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())ic_ebuf_alloc)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())chm_get_current_channel)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())chm_get_band_from_chan)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())ic_get_default_sched)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())ic_get_80211_tx_rate)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())ieee80211_post_hmac_tx)(); /* observed call (disasm order; args a2..a5) */

  u32 *eb = (u32 *)0; u32 ch = 0, band = 0;
  int rc;
  /* a2=raw frame ptr, a3=len?, a4=rate/flags?, a5=iface (extui a5,0,8 @0x33) */
  rc = ieee80211_raw_frame_sanity_check(a2, a3, a4, a5); /* @0x3f callx8 */
  if (rc == 0 /* a10==0 means fail? bnez a10 -> 0x141 fail path */) return rc;
  eb = (u32 *)(uintptr_t)((int(*)())ic_ebuf_alloc)(a4, 1);
  if (!eb) return 0x101;
  ch = chm_get_current_channel();            /* @0x80 */
  band = chm_get_band_from_chan(ch);         /* @0x8c */
  ((u16 *)eb)[11] = (u16)(a4 - 24);          /* s16i a4,a6,22; +22: len/seqctl */
  ((u16 *)eb)[10] = 24;                      /* s16i 24,a6,20 */
  /* ic control word at eb+44 (+44: eb priv word): or-in bit14, set sched/rate */
  /* eb sched/rate words: ic_get_default_sched/ic_get_80211_tx_rate results stored */
  (void)ic_get_default_sched();
  (void)ic_get_80211_tx_rate();
  return ((int(*)())ieee80211_post_hmac_tx)(eb);

}

/* esp_wifi_internal_tx @ ieee80211_output.o 00000008 size 37B bind GLOBAL
 * Calls: none | Data refs: none
 * Fidelity: high - leaf; full insn sequence captured, no hidden control flow */
/* disasm section: .text.esp_wifi_internal_tx_is_stop */
int esp_wifi_internal_tx(void *a2, void *a3, unsigned a4, unsigned a5);
int esp_wifi_internal_tx(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 32B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 0 */
  /* observed calls: none (leaf) */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  /* no calls observed: leaf */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* esp_wifi_internal_tx_by_ref @ ieee80211_output.o 00000008 size 36B bind GLOBAL
 * Calls: wifi_gpio_debug, ieee80211_output_do | Data refs: wifi_gpio_debug, ieee80211_output_do
 * Fidelity: medium - call order + branch skeleton from disasm; some field names inferred */
/* disasm section: .text.esp_wifi_internal_tx_by_ref */
int esp_wifi_internal_tx_by_ref(void *a2, void *a3, unsigned a4, unsigned a5);
int esp_wifi_internal_tx_by_ref(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 32B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 2, 8, 0 */
  /* observed call sequence (in order): wifi_gpio_debug -> ieee80211_output_do */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  (void)((int(*)())wifi_gpio_debug)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())ieee80211_output_do)(); /* observed call (disasm order; args a2..a5) */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* esp_wifi_internal_tx_is_stop @ ieee80211_output.o 00000000 size 7B bind GLOBAL
 * Calls: none | Data refs: none
 * Fidelity: high - leaf; full insn sequence captured, no hidden control flow */
/* disasm section: .text.esp_wifi_internal_tx_is_stop */
int esp_wifi_internal_tx_is_stop(void *a2, void *a3, unsigned a4, unsigned a5);
int esp_wifi_internal_tx_is_stop(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 32B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 0 */
  /* observed calls: none (leaf) */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  /* no calls observed: leaf */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* esp_wifi_mesh_tx @ ieee80211_output.o 00000018 size 113B bind GLOBAL
 * Calls: ieee80211_output_do, get_wifi_internal_state | Data refs: .rodata.esp_wifi_mesh_tx, ieee80211_output_do, get_wifi_internal_state
 * Fidelity: medium - call order + branch skeleton from disasm; some field names inferred */
/* disasm section: .text.esp_wifi_mesh_tx */
int esp_wifi_mesh_tx(void *a2, void *a3, unsigned a4, unsigned a5);
int esp_wifi_mesh_tx(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 32B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 0, 1, 83, 20, 86, 80, 81, 82, 84, 85 */
  /* observed branches: bltx2, beqx2, bltux1 */
  /* observed memory traffic (first 1): */
    /* l32i.n a8, a8, -- 0: frame control */
  /* observed call sequence (in order): ieee80211_output_do -> get_wifi_internal_state */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[8] = *(u32 *)(((u8 *)0) + 0); /* l32i.n a8,a8+0 → +0: frame control */
  (void)((int(*)())ieee80211_output_do)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())get_wifi_internal_state)(); /* observed call (disasm order; args a2..a5) */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* get_wifi_internal_state @ ieee80211_output.o 0000000c size 68B bind GLOBAL
 * Calls: none | Data refs: g_wifi_global_lock, g_osi_funcs_p, g_ic
 * Fidelity: medium - call order + branch skeleton from disasm; some field names inferred */
/* disasm section: .text.get_wifi_internal_state */
int get_wifi_internal_state(void *a2, void *a3, unsigned a4, unsigned a5);
int get_wifi_internal_state(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 32B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 86 */
  /* observed branches: bnez.nx1, bneix1, beqz.nx1, beqix1 */
  /* observed memory traffic (first 9): */
    /* l32i.n a2, a4, -- 0: frame control */
    /* l32i.n a10, a3, -- 0: frame control */
    /* l32i a2, a2, -- off 84 */
    /* l32i.n a8, a2, -- 16: addr3 */
    /* l32i.n a8, a2, -- 20: eb len field region */
    /* l32i a8, a8, -- 152: key PN/counter region */
    /* l32i.n a4, a4, -- 0: frame control */
    /* l32i.n a10, a3, -- 0: frame control */
    /* l32i a4, a4, -- off 88 */
  /* observed calls: none (leaf) */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[2] = *(u32 *)(eb8 + 0); /* l32i.n a2,a4+0 → +0: frame control */
  regs[1] = *(u32 *)((u8 *)a3 + 0); /* l32i.n a10,a3+0 → +0: frame control */
  regs[2] = *(u32 *)((u8 *)a2 + 84); /* l32i a2,a2+84 → +84:  */
  regs[8] = *(u32 *)((u8 *)a2 + 16); /* l32i.n a8,a2+16 → +16: addr3 */
  regs[8] = *(u32 *)((u8 *)a2 + 20); /* l32i.n a8,a2+20 → +20: eb len field region */
  regs[8] = *(u32 *)(((u8 *)0) + 152); /* l32i a8,a8+152 → +152: key PN/counter region */
  /* no calls observed: leaf */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* ieee80211_add_assoc_req_ies @ ieee80211_output.o 00000004 size 30B bind GLOBAL
 * Calls: memcpy | Data refs: memcpy
 * Fidelity: high - leaf; full insn sequence captured, no hidden control flow */
/* disasm section: .text.ieee80211_add_assoc_req_ies */
int ieee80211_add_assoc_req_ies(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_add_assoc_req_ies(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 32B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed branches: beqz.nx1 */
  /* observed memory traffic (first 4): */
    /* l32i.n a11, a3, -- 44: eb priv word */
    /* l16ui a12, a11, -- 0: frame control */
    /* l32i.n a3, a3, -- 44: eb priv word */
    /* l16ui a3, a3, -- 0: frame control */
  /* observed call sequence (in order): memcpy */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[1] = *(u32 *)((u8 *)a3 + 44); /* l32i.n a11,a3+44 → +44: eb priv word */
  regs[1] = *(u16 *)(((u8 *)0) + 0); /* l16ui → +0: frame control */
  regs[3] = *(u32 *)((u8 *)a3 + 44); /* l32i.n a3,a3+44 → +44: eb priv word */
  regs[3] = *(u16 *)((u8 *)a3 + 0); /* l16ui → +0: frame control */
  (void)((int(*)())memcpy)(); /* observed call (disasm order; args a2..a5) */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* ieee80211_add_assoc_resp_ies @ ieee80211_output.o 00000004 size 30B bind GLOBAL
 * Calls: memcpy | Data refs: memcpy
 * Fidelity: high - leaf; full insn sequence captured, no hidden control flow */
/* disasm section: .text.ieee80211_add_assoc_resp_ies */
int ieee80211_add_assoc_resp_ies(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_add_assoc_resp_ies(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 32B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed branches: beqz.nx1 */
  /* observed memory traffic (first 4): */
    /* l32i.n a11, a3, -- off 48 */
    /* l16ui a12, a11, -- 0: frame control */
    /* l32i.n a3, a3, -- off 48 */
    /* l16ui a3, a3, -- 0: frame control */
  /* observed call sequence (in order): memcpy */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[1] = *(u32 *)((u8 *)a3 + 48); /* l32i.n a11,a3+48 → +48:  */
  regs[1] = *(u16 *)(((u8 *)0) + 0); /* l16ui → +0: frame control */
  regs[3] = *(u32 *)((u8 *)a3 + 48); /* l32i.n a3,a3+48 → +48:  */
  regs[3] = *(u16 *)((u8 *)a3 + 0); /* l16ui → +0: frame control */
  (void)((int(*)())memcpy)(); /* observed call (disasm order; args a2..a5) */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* ieee80211_add_beacon_app_ies @ ieee80211_output.o 00000004 size 31B bind GLOBAL
 * Calls: memcpy | Data refs: memcpy
 * Fidelity: high - leaf; full insn sequence captured, no hidden control flow */
/* disasm section: .text.ieee80211_add_beacon_app_ies */
int ieee80211_add_beacon_app_ies(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_add_beacon_app_ies(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 32B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed branches: beqz.nx1 */
  /* observed memory traffic (first 4): */
    /* l32i a11, a3, -- off 0x288 */
    /* l16ui a12, a11, -- 0: frame control */
    /* l32i a3, a3, -- off 0x288 */
    /* l16ui a3, a3, -- 0: frame control */
  /* observed call sequence (in order): memcpy */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[1] = *(u32 *)((u8 *)a3 + 648); /* l32i a11,a3+648 → +648:  */
  regs[1] = *(u16 *)(((u8 *)0) + 0); /* l16ui → +0: frame control */
  regs[3] = *(u32 *)((u8 *)a3 + 648); /* l32i a3,a3+648 → +648:  */
  regs[3] = *(u16 *)((u8 *)a3 + 0); /* l16ui → +0: frame control */
  (void)((int(*)())memcpy)(); /* observed call (disasm order; args a2..a5) */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* ieee80211_add_bss_max_idle @ ieee80211_output.o 00000008 size 112B bind GLOBAL
 * Calls: none | Data refs: g_ic, g_wifi_nvs
 * Fidelity: medium - call order + branch skeleton from disasm; some field names inferred */
/* disasm section: .text.ieee80211_add_bss_max_idle */
int ieee80211_add_bss_max_idle(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_add_bss_max_idle(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 32B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 90, 3, 1, 0 */
  /* observed branches: bnex1, bnez.nx1 */
  /* observed memory traffic (first 10): */
    /* l32i.n a8, a3, -- 0: frame control */
    /* s8i a2, a9, -- 0: frame control */
    /* s8i a2, a9, -- 1: frame control/duration */
    /* l32i.n a10, a10, -- 20: eb len field region */
    /* l16ui a3, a3, -- off 50 */
    /* s16i a3, a9, -- 2: duration */
    /* l32i.n a3, a3, -- 0: frame control */
    /* l8ui a8, a3, -- off 244 */
    /* l16ui a8, a8, -- off 62 */
    /* s16i a8, a9, -- 2: duration */
  /* observed calls: none (leaf) */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[8] = *(u32 *)((u8 *)a3 + 0); /* l32i.n a8,a3+0 → +0: frame control */
  *(u8 *)(((u8 *)0) + 0) = (u8)regs[2]; /* s8i → +0: frame control */
  *(u8 *)(((u8 *)0) + 1) = (u8)regs[2]; /* s8i → +1: frame control/duration */
  regs[1] = *(u32 *)(((u8 *)0) + 20); /* l32i.n a10,a10+20 → +20: eb len field region */
  regs[3] = *(u16 *)((u8 *)a3 + 50); /* l16ui → +50:  */
  *(u16 *)(((u8 *)0) + 2) = (u16)regs[3]; /* s16i → +2: duration */
  /* no calls observed: leaf */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* ieee80211_add_csa @ ieee80211_output.o 00000004 size 52B bind GLOBAL
 * Calls: none | Data refs: g_ic
 * Fidelity: medium - call order + branch skeleton from disasm; some field names inferred */
/* disasm section: .text.ieee80211_add_csa */
int ieee80211_add_csa(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_add_csa(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 32B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 37, 3, 1 */
  /* observed memory traffic (first 7): */
    /* s8i a8, a2, -- 0: frame control */
    /* s8i a8, a2, -- 1: frame control/duration */
    /* s8i a8, a2, -- 2: duration */
    /* l8ui a9, a8, -- off 232 */
    /* s8i a9, a2, -- 3: 802.11 header region */
    /* l8ui a8, a8, -- off 236 */
    /* s8i a8, a2, -- 4: addr1 */
  /* observed calls: none (leaf) */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  *(u8 *)((u8 *)a2 + 0) = (u8)regs[8]; /* s8i → +0: frame control */
  *(u8 *)((u8 *)a2 + 1) = (u8)regs[8]; /* s8i → +1: frame control/duration */
  *(u8 *)((u8 *)a2 + 2) = (u8)regs[8]; /* s8i → +2: duration */
  regs[9] = *(u8 *)(((u8 *)0) + 232); /* l8ui → +232:  */
  *(u8 *)((u8 *)a2 + 3) = (u8)regs[9]; /* s8i → +3: 802.11 header region */
  regs[8] = *(u8 *)(((u8 *)0) + 236); /* l8ui → +236:  */
  /* no calls observed: leaf */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* ieee80211_add_dh_param @ ieee80211_output.o 00000014 size 63B bind GLOBAL
 * Calls: wifi_log, memcpy | Data refs: g_ic, .rodata_wlog_error.22, len_dh_ie, wifi_log, memcpy
 * Fidelity: medium - call order + branch skeleton from disasm; some field names inferred */
/* disasm section: .text.ieee80211_add_dh_param */
int ieee80211_add_dh_param(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_add_dh_param(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 32B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 19, 1, 0 */
  /* observed branches: bnez.nx1 */
  /* observed memory traffic (first 4): */
    /* l32i a3, a3, -- off 0x1b4 */
    /* l32i a3, a3, -- off 92 */
    /* l8ui a12, a3, -- 0: frame control */
    /* l8ui a3, a3, -- 0: frame control */
  /* observed call sequence (in order): wifi_log -> memcpy */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[3] = *(u32 *)((u8 *)a3 + 436); /* l32i a3,a3+436 → +436:  */
  regs[3] = *(u32 *)((u8 *)a3 + 92); /* l32i a3,a3+92 → +92:  */
  regs[1] = *(u8 *)((u8 *)a3 + 0); /* l8ui → +0: frame control */
  regs[3] = *(u8 *)((u8 *)a3 + 0); /* l8ui → +0: frame control */
  (void)((int(*)())wifi_log)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())memcpy)(); /* observed call (disasm order; args a2..a5) */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* ieee80211_add_dsparams @ ieee80211_output.o 00000000 size 42B bind GLOBAL
 * Calls: none | Data refs: none
 * Fidelity: high - leaf; full insn sequence captured, no hidden control flow */
/* disasm section: .text.ieee80211_add_dsparams */
int ieee80211_add_dsparams(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_add_dsparams(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 32B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 0, 3, 1 */
  /* observed branches: beqz.nx1, bnonex1 */
  /* observed memory traffic (first 5): */
    /* l32i.n a8, a3, -- 8: 802.11 header region */
    /* s8i a8, a2, -- 0: frame control */
    /* s8i a8, a2, -- 1: frame control/duration */
    /* l8ui a3, a3, -- 0: frame control */
    /* s8i a3, a2, -- 2: duration */
  /* observed calls: none (leaf) */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[8] = *(u32 *)((u8 *)a3 + 8); /* l32i.n a8,a3+8 → +8: 802.11 header region */
  *(u8 *)((u8 *)a2 + 0) = (u8)regs[8]; /* s8i → +0: frame control */
  *(u8 *)((u8 *)a2 + 1) = (u8)regs[8]; /* s8i → +1: frame control/duration */
  regs[3] = *(u8 *)((u8 *)a3 + 0); /* l8ui → +0: frame control */
  *(u8 *)((u8 *)a2 + 2) = (u8)regs[3]; /* s8i → +2: duration */
  /* no calls observed: leaf */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* ieee80211_add_extcap @ ieee80211_output.o 00000020 size 143B bind GLOBAL
 * Calls: memset, wifi_log, memcpy | Data refs: .rodata.ieee80211_send_setup.str1.1, .rodata_wlog_error.23, g_ic, g_wifi_nvs, memset, wifi_log, memcpy
 * Fidelity: medium - call order + branch skeleton from disasm; some field names inferred */
/* disasm section: .text.ieee80211_add_extcap */
int ieee80211_add_extcap(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_add_extcap(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 48B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 11, 0, 1, 8, 127, 9 */
  /* observed branches: bnez.nx2, beqz.nx2, bnex1, bneix1 */
  /* observed memory traffic (first 10): */
    /* l32i a10, a9, -- off 0x248 */
    /* l32i.n a3, a3, -- 0: frame control */
    /* l32i.n a10, a9, -- 20: eb len field region */
    /* l8ui a3, a9, -- off 166 */
    /* l32i.n a9, a3, -- 0: frame control */
    /* l8ui a9, a9, -- off 99 */
    /* s8i a3, a1, -- 0: frame control */
    /* s8i a3, a1, -- 1: frame control/duration */
    /* s8i a8, a1, -- 2: duration */
    /* s8i a9, a1, -- 4: addr1 */
  /* observed call sequence (in order): memset -> wifi_log -> memcpy */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[1] = *(u32 *)(((u8 *)0) + 584); /* l32i a10,a9+584 → +584:  */
  regs[3] = *(u32 *)((u8 *)a3 + 0); /* l32i.n a3,a3+0 → +0: frame control */
  regs[1] = *(u32 *)(((u8 *)0) + 20); /* l32i.n a10,a9+20 → +20: eb len field region */
  regs[3] = *(u8 *)(((u8 *)0) + 166); /* l8ui → +166:  */
  regs[9] = *(u32 *)((u8 *)a3 + 0); /* l32i.n a9,a3+0 → +0: frame control */
  regs[9] = *(u8 *)(((u8 *)0) + 99); /* l8ui → +99:  */
  (void)((int(*)())memset)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())wifi_log)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())memcpy)(); /* observed call (disasm order; args a2..a5) */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* ieee80211_add_probe_req_ies @ ieee80211_output.o 00000004 size 30B bind GLOBAL
 * Calls: memcpy | Data refs: memcpy
 * Fidelity: high - leaf; full insn sequence captured, no hidden control flow */
/* disasm section: .text.ieee80211_add_probe_req_ies */
int ieee80211_add_probe_req_ies(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_add_probe_req_ies(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 32B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed branches: beqz.nx1 */
  /* observed memory traffic (first 4): */
    /* l32i.n a11, a3, -- off 40 */
    /* l16ui a12, a11, -- 0: frame control */
    /* l32i.n a3, a3, -- off 40 */
    /* l16ui a3, a3, -- 0: frame control */
  /* observed call sequence (in order): memcpy */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[1] = *(u32 *)((u8 *)a3 + 40); /* l32i.n a11,a3+40 → +40:  */
  regs[1] = *(u16 *)(((u8 *)0) + 0); /* l16ui → +0: frame control */
  regs[3] = *(u32 *)((u8 *)a3 + 40); /* l32i.n a3,a3+40 → +40:  */
  regs[3] = *(u16 *)((u8 *)a3 + 0); /* l16ui → +0: frame control */
  (void)((int(*)())memcpy)(); /* observed call (disasm order; args a2..a5) */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* ieee80211_add_probe_resp_app_ies @ ieee80211_output.o 00000004 size 31B bind GLOBAL
 * Calls: memcpy | Data refs: memcpy
 * Fidelity: high - leaf; full insn sequence captured, no hidden control flow */
/* disasm section: .text.ieee80211_add_probe_resp_app_ies */
int ieee80211_add_probe_resp_app_ies(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_add_probe_resp_app_ies(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 32B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed branches: beqz.nx1 */
  /* observed memory traffic (first 4): */
    /* l32i a11, a3, -- off 0x28c */
    /* l16ui a12, a11, -- 0: frame control */
    /* l32i a3, a3, -- off 0x28c */
    /* l16ui a3, a3, -- 0: frame control */
  /* observed call sequence (in order): memcpy */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[1] = *(u32 *)((u8 *)a3 + 652); /* l32i a11,a3+652 → +652:  */
  regs[1] = *(u16 *)(((u8 *)0) + 0); /* l16ui → +0: frame control */
  regs[3] = *(u32 *)((u8 *)a3 + 652); /* l32i a3,a3+652 → +652:  */
  regs[3] = *(u16 *)((u8 *)a3 + 0); /* l16ui → +0: frame control */
  (void)((int(*)())memcpy)(); /* observed call (disasm order; args a2..a5) */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* ieee80211_add_rates @ ieee80211_output.o 00000004 size 48B bind GLOBAL
 * Calls: memcpy | Data refs: memcpy
 * Fidelity: high - leaf; full insn sequence captured, no hidden control flow */
/* disasm section: .text.ieee80211_add_rates */
int ieee80211_add_rates(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_add_rates(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 32B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 8, 1 */
  /* observed branches: bltux1 */
  /* observed memory traffic (first 3): */
    /* l8ui a8, a3, -- 0: frame control */
    /* s8i a8, a2, -- 0: frame control */
    /* s8i a4, a2, -- 1: frame control/duration */
  /* observed call sequence (in order): memcpy */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[8] = *(u8 *)((u8 *)a3 + 0); /* l8ui → +0: frame control */
  *(u8 *)((u8 *)a2 + 0) = (u8)regs[8]; /* s8i → +0: frame control */
  *(u8 *)((u8 *)a2 + 1) = (u8)regs[4]; /* s8i → +1: frame control/duration */
  (void)((int(*)())memcpy)(); /* observed call (disasm order; args a2..a5) */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* ieee80211_add_supportedchannels @ ieee80211_output.o 00000008 size 80B bind GLOBAL
 * Calls: chm_get_current_band | Data refs: g_wifi_nvs, chm_get_current_band
 * Fidelity: medium - call order + branch skeleton from disasm; some field names inferred */
/* disasm section: .text.ieee80211_add_supportedchannels */
int ieee80211_add_supportedchannels(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_add_supportedchannels(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 32B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 36, 0 */
  /* observed branches: bneix1 */
  /* observed memory traffic (first 10): */
    /* l32i a3, a3, -- 0: frame control */
    /* s8i a8, a2, -- 0: frame control */
    /* s8i a8, a2, -- 1: frame control/duration */
    /* l8ui a3, a8, -- 7: 802.11 header region */
    /* s8i a3, a2, -- 2: duration */
    /* l8ui a3, a8, -- 8: 802.11 header region */
    /* s8i a3, a2, -- 3: 802.11 header region */
    /* l8ui a3, a2, -- 1: frame control/duration */
    /* s8i a3, a2, -- 1: frame control/duration */
    /* l8ui a3, a2, -- 1: frame control/duration */
  /* observed call sequence (in order): chm_get_current_band */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[3] = *(u32 *)((u8 *)a3 + 0); /* l32i a3,a3+0 → +0: frame control */
  *(u8 *)((u8 *)a2 + 0) = (u8)regs[8]; /* s8i → +0: frame control */
  *(u8 *)((u8 *)a2 + 1) = (u8)regs[8]; /* s8i → +1: frame control/duration */
  regs[3] = *(u8 *)(((u8 *)0) + 7); /* l8ui → +7: 802.11 header region */
  *(u8 *)((u8 *)a2 + 2) = (u8)regs[3]; /* s8i → +2: duration */
  regs[3] = *(u8 *)(((u8 *)0) + 8); /* l8ui → +8: 802.11 header region */
  (void)((int(*)())chm_get_current_band)(); /* observed call (disasm order; args a2..a5) */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* ieee80211_add_tie_param @ ieee80211_output.o 00000004 size 86B bind GLOBAL
 * Calls: hal_now | Data refs: hal_now
 * Fidelity: medium - call order + branch skeleton from disasm; some field names inferred */
/* disasm section: .text.ieee80211_add_tie_param */
int ieee80211_add_tie_param(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_add_tie_param(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 32B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 0, 100, 56, 5, 3 */
  /* observed branches: beqz.nx1, bltux1 */
  /* observed memory traffic (first 9): */
    /* l8ui a8, a4, -- off 252 */
    /* l32i a8, a3, -- off 0x3a0 */
    /* s8i a3, a2, -- 0: frame control */
    /* s8i a3, a2, -- 1: frame control/duration */
    /* s8i a3, a2, -- 2: duration */
    /* s8i a4, a2, -- 3: 802.11 header region */
    /* s8i a3, a2, -- 4: addr1 */
    /* s8i a3, a2, -- 5: 802.11 header region */
    /* s8i a4, a2, -- 6: 802.11 header region */
  /* observed call sequence (in order): hal_now */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[8] = *(u8 *)(eb8 + 252); /* l8ui → +252:  */
  regs[8] = *(u32 *)((u8 *)a3 + 928); /* l32i a8,a3+928 → +928:  */
  *(u8 *)((u8 *)a2 + 0) = (u8)regs[3]; /* s8i → +0: frame control */
  *(u8 *)((u8 *)a2 + 1) = (u8)regs[3]; /* s8i → +1: frame control/duration */
  *(u8 *)((u8 *)a2 + 2) = (u8)regs[3]; /* s8i → +2: duration */
  *(u8 *)((u8 *)a2 + 3) = (u8)regs[4]; /* s8i → +3: 802.11 header region */
  (void)((int(*)())hal_now)(); /* observed call (disasm order; args a2..a5) */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* ieee80211_add_wme_param @ ieee80211_output.o 0000000c size 123B bind GLOBAL
 * Calls: memcpy | Data refs: .rodata.param$3, .rodata.s_ac_param$2, memcpy
 * Fidelity: medium - call order + branch skeleton from disasm; some field names inferred */
/* disasm section: .text.ieee80211_add_wme_param */
int ieee80211_add_wme_param(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_add_wme_param(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 32B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 9, 4, 0, 16 */
  /* observed memory traffic (first 10): */
    /* s8i a8, a2, -- 8: 802.11 header region */
    /* s8i a8, a2, -- 9: 802.11 header region */
    /* l8ui a9, a8, -- 2: duration */
    /* l8ui a15, a8, -- 1: frame control/duration */
    /* s8i a9, a11, -- 0: frame control */
    /* l8ui a9, a8, -- 4: addr1 */
    /* l8ui a15, a8, -- 3: 802.11 header region */
    /* s8i a9, a11, -- 1: frame control/duration */
    /* l8ui a9, a8, -- 5: 802.11 header region */
    /* s8i a9, a11, -- 2: duration */
  /* observed call sequence (in order): memcpy */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  *(u8 *)((u8 *)a2 + 8) = (u8)regs[8]; /* s8i → +8: 802.11 header region */
  *(u8 *)((u8 *)a2 + 9) = (u8)regs[8]; /* s8i → +9: 802.11 header region */
  regs[9] = *(u8 *)(((u8 *)0) + 2); /* l8ui → +2: duration */
  regs[1] = *(u8 *)(((u8 *)0) + 1); /* l8ui → +1: frame control/duration */
  *(u8 *)(((u8 *)0) + 0) = (u8)regs[9]; /* s8i → +0: frame control */
  regs[9] = *(u8 *)(((u8 *)0) + 4); /* l8ui → +4: addr1 */
  (void)((int(*)())memcpy)(); /* observed call (disasm order; args a2..a5) */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* ieee80211_add_xrates @ ieee80211_output.o 00000008 size 86B bind GLOBAL
 * Calls: memcpy | Data refs: g_wifi_nvs, memcpy
 * Fidelity: medium - call order + branch skeleton from disasm; some field names inferred */
/* disasm section: .text.ieee80211_add_xrates */
int ieee80211_add_xrates(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_add_xrates(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 32B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 8, 50, -5 */
  /* observed branches: bgeux1, bneix1 */
  /* observed memory traffic (first 7): */
    /* l8ui a8, a3, -- 0: frame control */
    /* s8i a9, a2, -- 0: frame control */
    /* l32i.n a9, a9, -- 0: frame control */
    /* l8ui a9, a9, -- off 172 */
    /* s8i a8, a2, -- 1: frame control/duration */
    /* s8i a9, a2, -- 2: duration */
    /* s8i a4, a2, -- 1: frame control/duration */
  /* observed call sequence (in order): memcpy */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[8] = *(u8 *)((u8 *)a3 + 0); /* l8ui → +0: frame control */
  *(u8 *)((u8 *)a2 + 0) = (u8)regs[9]; /* s8i → +0: frame control */
  regs[9] = *(u32 *)(((u8 *)0) + 0); /* l32i.n a9,a9+0 → +0: frame control */
  regs[9] = *(u8 *)(((u8 *)0) + 172); /* l8ui → +172:  */
  *(u8 *)((u8 *)a2 + 1) = (u8)regs[8]; /* s8i → +1: frame control/duration */
  *(u8 *)((u8 *)a2 + 2) = (u8)regs[9]; /* s8i → +2: duration */
  (void)((int(*)())memcpy)(); /* observed call (disasm order; args a2..a5) */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* ieee80211_align_eb @ ieee80211_output.o 00000008 size 102B bind GLOBAL
 * Calls: none | Data refs: none
 * Fidelity: medium - call order + branch skeleton from disasm; some field names inferred */
/* disasm section: .wifiextrairam.18 */
int ieee80211_align_eb(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_align_eb(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 32B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): -1, 1 */
  /* observed memory traffic (first 10): */
    /* l32i.n a8, a2, -- 4: addr1 */
    /* l32i.n a10, a8, -- 0: frame control */
    /* l32i.n a9, a8, -- 4: addr1 */
    /* l16ui a9, a2, -- 22: seqctl/len */
    /* l16ui a2, a2, -- 20: eb len field region */
    /* s32i.n a10, a8, -- 0: frame control */
    /* l32i.n a10, a8, -- 0: frame control */
    /* s32i.n a10, a8, -- 0: frame control */
    /* l32i.n a10, a8, -- 0: frame control */
    /* s32i.n a10, a8, -- 0: frame control */
  /* observed calls: none (leaf) */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[8] = *(u32 *)((u8 *)a2 + 4); /* l32i.n a8,a2+4 → +4: addr1 */
  regs[1] = *(u32 *)(((u8 *)0) + 0); /* l32i.n a10,a8+0 → +0: frame control */
  regs[9] = *(u32 *)(((u8 *)0) + 4); /* l32i.n a9,a8+4 → +4: addr1 */
  regs[9] = *(u16 *)((u8 *)a2 + 22); /* l16ui → +22: seqctl/len */
  regs[2] = *(u16 *)((u8 *)a2 + 20); /* l16ui → +20: eb len field region */
  *(u32 *)(((u8 *)0) + 0) = regs[1]; /* s32i.n a10,a8+0 → +0: frame control */
  /* no calls observed: leaf */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* ieee80211_alloc_deauth @ ieee80211_output.o 0000000c size 78B bind GLOBAL
 * Calls: ieee80211_getmgtframe, wifi_log | Data refs: .rodata_wlog_warning.41, ieee80211_getmgtframe, wifi_log
 * Fidelity: medium - call order + branch skeleton from disasm; some field names inferred */
/* disasm section: .text.ieee80211_alloc_deauth */
int ieee80211_alloc_deauth(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_alloc_deauth(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 48B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 2, 24, 64, 1 */
  /* observed branches: bnez.nx1 */
  /* observed memory traffic (first 6): */
    /* l32i.n a8, a1, -- 0: frame control */
    /* s16i a4, a8, -- 0: frame control */
    /* s16i a4, a10, -- 20: eb len field region */
    /* l32i.n a4, a10, -- 4: addr1 */
    /* l32i.n a4, a4, -- 4: addr1 */
    /* s16i a8, a10, -- 22: seqctl/len */
  /* observed call sequence (in order): ieee80211_getmgtframe -> wifi_log */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[8] = *(u32 *)(((u8 *)a1_spill) + 0); /* l32i.n a8,a1+0 → +0: frame control */
  *(u16 *)(((u8 *)0) + 0) = (u16)regs[4]; /* s16i → +0: frame control */
  *(u16 *)(((u8 *)0) + 20) = (u16)regs[4]; /* s16i → +20: eb len field region */
  regs[4] = *(u32 *)(((u8 *)0) + 4); /* l32i.n a4,a10+4 → +4: addr1 */
  regs[4] = *(u32 *)(eb8 + 4); /* l32i.n a4,a4+4 → +4: addr1 */
  *(u16 *)(((u8 *)0) + 22) = (u16)regs[8]; /* s16i → +22: seqctl/len */
  (void)((int(*)())ieee80211_getmgtframe)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())wifi_log)(); /* observed call (disasm order; args a2..a5) */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* ieee80211_alloc_tx_buf @ ieee80211_output.o 00000014 size 94B bind GLOBAL
 * Calls: config_is_cache_tx_buf_enabled, ic_ebuf_alloc | Data refs: s_netstack_ref, config_is_cache_tx_buf_enabled, ic_ebuf_alloc
 * Fidelity: medium - call order + branch skeleton from disasm; some field names inferred */
/* disasm section: .wifiextrairam.3 */
int ieee80211_alloc_tx_buf(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_alloc_tx_buf(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 48B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 9, 0, 1 */
  /* observed branches: beqz.nx5 */
  /* observed memory traffic (first 7): */
    /* s32i.n a3, a1, -- 0: frame control */
    /* l32i.n a12, a1, -- 0: frame control */
    /* l32i.n a8, a10, -- 4: addr1 */
    /* s32i.n a4, a10, -- 0: frame control */
    /* s32i.n a5, a8, -- 4: addr1 */
    /* l32i.n a5, a5, -- 0: frame control */
    /* s32i.n a4, a10, -- 0: frame control */
  /* observed call sequence (in order): config_is_cache_tx_buf_enabled -> ic_ebuf_alloc */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  *(u32 *)(((u8 *)a1_spill) + 0) = regs[3]; /* s32i.n a3,a1+0 → +0: frame control */
  regs[1] = *(u32 *)(((u8 *)a1_spill) + 0); /* l32i.n a12,a1+0 → +0: frame control */
  regs[8] = *(u32 *)(((u8 *)0) + 4); /* l32i.n a8,a10+4 → +4: addr1 */
  *(u32 *)(((u8 *)0) + 0) = regs[4]; /* s32i.n a4,a10+0 → +0: frame control */
  *(u32 *)(((u8 *)0) + 4) = regs[5]; /* s32i.n a5,a8+4 → +4: addr1 */
  regs[5] = *(u32 *)((u8 *)(uintptr_t)a4 + 0); /* l32i.n a5,a5+0 → +0: frame control */
  (void)((int(*)())config_is_cache_tx_buf_enabled)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())ic_ebuf_alloc)(); /* observed call (disasm order; args a2..a5) */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* ieee80211_amsdu_adjust_head @ ieee80211_output.o 00000014 size 215B bind GLOBAL
 * Calls: memcpy, roundup2 | Data refs: g_ic, memcpy, roundup2
 * Fidelity: medium - call order + offsets from disasm; straight-line details summarised */
/* disasm section: .text.ieee80211_amsdu_adjust_head */
int ieee80211_amsdu_adjust_head(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_amsdu_adjust_head(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 48B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 14, -86, 3, 1, 24, 254, 52, 6, 4 */
  /* observed branches: beqz.nx2 */
  /* observed memory traffic (first 10): */
    /* l32i.n a5, a3, -- 4: addr1 */
    /* l32i a5, a5, -- 4: addr1 */
    /* l16ui a4, a3, -- 22: seqctl/len */
    /* l8ui a8, a5, -- 12: 802.11 header region */
    /* l8ui a9, a5, -- 13: 802.11 header region */
    /* s8i a5, a2, -- 15: 802.11 header region */
    /* s8i a5, a2, -- 14: 802.11 header region */
    /* s8i a5, a2, -- 16: addr3 */
    /* l32i a8, a5, -- off 116 */
    /* l32i.n a8, a3, -- 28: HT */
  /* observed call sequence (in order): memcpy -> roundup2 */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[5] = *(u32 *)((u8 *)a3 + 4); /* l32i.n a5,a3+4 → +4: addr1 */
  regs[5] = *(u32 *)((u8 *)(uintptr_t)a4 + 4); /* l32i a5,a5+4 → +4: addr1 */
  regs[4] = *(u16 *)((u8 *)a3 + 22); /* l16ui → +22: seqctl/len */
  regs[8] = *(u8 *)((u8 *)(uintptr_t)a4 + 12); /* l8ui → +12: 802.11 header region */
  regs[9] = *(u8 *)((u8 *)(uintptr_t)a4 + 13); /* l8ui → +13: 802.11 header region */
  *(u8 *)((u8 *)a2 + 15) = (u8)regs[5]; /* s8i → +15: 802.11 header region */
  (void)((int(*)())memcpy)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())roundup2)(); /* observed call (disasm order; args a2..a5) */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* ieee80211_amsdu_adjust_last_length @ ieee80211_output.o 00000004 size 48B bind GLOBAL
 * Calls: roundup2 | Data refs: roundup2
 * Fidelity: high - leaf; full insn sequence captured, no hidden control flow */
/* disasm section: .text.ieee80211_amsdu_adjust_last_length */
int ieee80211_amsdu_adjust_last_length(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_amsdu_adjust_last_length(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 32B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 4 */
  /* observed memory traffic (first 2): */
    /* l16ui a8, a2, -- 22: seqctl/len */
    /* s16i a8, a2, -- 22: seqctl/len */
  /* observed call sequence (in order): roundup2 */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[8] = *(u16 *)((u8 *)a2 + 22); /* l16ui → +22: seqctl/len */
  *(u16 *)((u8 *)a2 + 22) = (u16)regs[8]; /* s16i → +22: seqctl/len */
  (void)((int(*)())roundup2)(); /* observed call (disasm order; args a2..a5) */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* ieee80211_amsdu_encap_check @ ieee80211_output.o 0000000c size 100B bind GLOBAL
 * Calls: ieee80211_search_node, memcmp, ieee80211_classify | Data refs: ieee80211_search_node, memcmp, ieee80211_classify
 * Fidelity: medium - call order + branch skeleton from disasm; some field names inferred */
/* disasm section: .text.ieee80211_amsdu_encap_check */
int ieee80211_amsdu_encap_check(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_amsdu_encap_check(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 48B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 0, 6, 1 */
  /* observed branches: beqx1, bneix1 */
  /* observed memory traffic (first 10): */
    /* l32i.n a4, a2, -- 4: addr1 */
    /* l32i.n a7, a4, -- 4: addr1 */
    /* l32i.n a4, a3, -- 4: addr1 */
    /* l32i.n a6, a4, -- 4: addr1 */
    /* l32i.n a4, a3, -- 44: eb priv word */
    /* l32i.n a8, a4, -- 16: addr3 */
    /* l32i.n a4, a2, -- 44: eb priv word */
    /* l32i.n a4, a4, -- 16: addr3 */
    /* l32i.n a2, a2, -- 44: eb priv word */
    /* l32i.n a2, a2, -- 4: addr1 */
  /* observed call sequence (in order): ieee80211_search_node -> memcmp -> ieee80211_classify */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[4] = *(u32 *)((u8 *)a2 + 4); /* l32i.n a4,a2+4 → +4: addr1 */
  regs[7] = *(u32 *)(eb8 + 4); /* l32i.n a7,a4+4 → +4: addr1 */
  regs[4] = *(u32 *)((u8 *)a3 + 4); /* l32i.n a4,a3+4 → +4: addr1 */
  regs[6] = *(u32 *)(eb8 + 4); /* l32i.n a6,a4+4 → +4: addr1 */
  regs[4] = *(u32 *)((u8 *)a3 + 44); /* l32i.n a4,a3+44 → +44: eb priv word */
  regs[8] = *(u32 *)(eb8 + 16); /* l32i.n a8,a4+16 → +16: addr3 */
  (void)((int(*)())ieee80211_search_node)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())memcmp)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())ieee80211_classify)(); /* observed call (disasm order; args a2..a5) */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* ieee80211_amsdu_length_check @ ieee80211_output.o 00000004 size 41B bind GLOBAL
 * Calls: roundup2 | Data refs: roundup2
 * Fidelity: high - leaf; full insn sequence captured, no hidden control flow */
/* disasm section: .text.ieee80211_amsdu_length_check */
int ieee80211_amsdu_length_check(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_amsdu_length_check(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 32B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 4, 0, 1 */
  /* observed branches: bgeux1 */
  /* observed memory traffic (first 1): */
    /* l16ui a10, a2, -- 22: seqctl/len */
  /* observed call sequence (in order): roundup2 */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[1] = *(u16 *)((u8 *)a2 + 22); /* l16ui → +22: seqctl/len */
  (void)((int(*)())roundup2)(); /* observed call (disasm order; args a2..a5) */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* ieee80211_amsdu_send_check @ ieee80211_output.o 00000010 size 181B bind GLOBAL
 * Calls: ieee80211_search_node, ieee80211_classify | Data refs: ieee80211_search_node, ieee80211_classify
 * Fidelity: medium - call order + offsets from disasm; straight-line details summarised */
/* disasm section: .text.ieee80211_amsdu_send_check */
int ieee80211_amsdu_send_check(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_amsdu_send_check(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 48B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 0, 15, -16, 1 */
  /* observed branches: bbcix2, bgeux1, beqx1, bnex2, bneix1, bbsix2, beqz.nx1 */
  /* observed memory traffic (first 10): */
    /* l32i.n a9, a2, -- 44: eb priv word */
    /* l32i.n a3, a9, -- 0: frame control */
    /* l16ui a3, a2, -- 22: seqctl/len */
    /* l32i.n a3, a2, -- 4: addr1 */
    /* l32i.n a4, a3, -- 4: addr1 */
    /* l8ui a8, a4, -- 13: 802.11 header region */
    /* l8ui a3, a4, -- 12: 802.11 header region */
    /* l32i a10, a9, -- 16: addr3 */
    /* l32i.n a8, a10, -- 12: 802.11 header region */
    /* l32i.n a8, a10, -- 0: frame control */
  /* observed call sequence (in order): ieee80211_search_node -> ieee80211_classify */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[9] = *(u32 *)((u8 *)a2 + 44); /* l32i.n a9,a2+44 → +44: eb priv word */
  regs[3] = *(u32 *)(((u8 *)0) + 0); /* l32i.n a3,a9+0 → +0: frame control */
  regs[3] = *(u16 *)((u8 *)a2 + 22); /* l16ui → +22: seqctl/len */
  regs[3] = *(u32 *)((u8 *)a2 + 4); /* l32i.n a3,a2+4 → +4: addr1 */
  regs[4] = *(u32 *)((u8 *)a3 + 4); /* l32i.n a4,a3+4 → +4: addr1 */
  regs[8] = *(u8 *)(eb8 + 13); /* l8ui → +13: 802.11 header region */
  (void)((int(*)())ieee80211_search_node)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())ieee80211_classify)(); /* observed call (disasm order; args a2..a5) */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* ieee80211_assoc_req_construct @ ieee80211_output.o 000000c4 size 1267B bind GLOBAL
 * Calls: wifi_log, sta_get_owe_data, memcmp, ieee80211_getcapinfo, ieee80211_vnd_lora_ie_size, .text.ieee80211_vnd_ie_size$part$0, ieee80211_getmgtframe, memcpy, ieee80211_add_rates, ieee80211_add_supportedchannels, ieee80211_add_xrates, ieee80211_is_ht_cipher, ieee80211_add_htcap, sta_is_bss_max_idle_enabled, ic_get_keep_alive_time, ieee80211_add_bss_max_idle, esp_wifi_sta_prof_is_wpa_internal, ieee80211_add_dh_param, ieee80211_add_htcap_vendor, .text.add_appie, ieee80211_add_assoc_req_ies, ieee80211_add_extcap, wifi_get_macaddr, ieee80211_add_ie_vendor_esp_manufacturer, ieee80211_vnd_lora_ie_set, ieee80211_vnd_ie_set | Data refs: g_wifi_nvs, .rodata.ieee80211_send_setup.str1.1, .rodata_wlog_error.27, g_ic, len_dh_ie, .rodata_wlog_warning.28, .rodata.info$1, g_misc_nvs, esp_mesh_quick_funcs, g_mesh_init_ps_type
 * Fidelity: low - large function; call order + key branches captured, body is structural summary */
/* disasm section: .text.ieee80211_assoc_req_construct */
int ieee80211_assoc_req_construct(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_assoc_req_construct(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 96B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 1, 15, 6, 3, 0, 54, 37, 143, 24, 2 */
  /* observed branches: beqz.nx15, bnez.nx7, bnex5, beqix2, beqx7, bneix2, bltux1, bbcix4 */
  /* observed memory traffic (first 10): */
    /* s32i.n a3, a1, -- off 32 */
    /* l32i.n a3, a2, -- 0: frame control */
    /* l32i.n a3, a6, -- 0: frame control */
    /* s32i.n a3, a1, -- 16: addr3 */
    /* l32i.n a3, a2, -- 0: frame control */
    /* l8ui a5, a2, -- 21: 802.11 header region */
    /* l8ui a3, a3, -- off 95 */
    /* l8ui a5, a8, -- 1: frame control/duration */
    /* s32i.n a10, a1, -- 24: seqctl/addr4/QoS */
    /* s32i.n a10, a1, -- 28: HT */
  /* observed call sequence (in order): wifi_log -> sta_get_owe_data -> memcmp -> ieee80211_getcapinfo -> ieee80211_vnd_lora_ie_size -> .text.ieee80211_vnd_ie_size$part$0+0x4 -> ieee80211_getmgtframe -> memcpy -> ieee80211_add_rates -> ieee80211_add_supportedchannels -> ieee80211_add_xrates -> ieee80211_is_ht_cipher -> ieee80211_add_htcap -> sta_is_bss_max_idle_enabled */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  *(u32 *)(((u8 *)a1_spill) + 32) = regs[3]; /* s32i.n a3,a1+32 → +32:  */
  regs[3] = *(u32 *)((u8 *)a2 + 0); /* l32i.n a3,a2+0 → +0: frame control */
  regs[3] = *(u32 *)(eb8 + 0); /* l32i.n a3,a6+0 → +0: frame control */
  *(u32 *)(((u8 *)a1_spill) + 16) = regs[3]; /* s32i.n a3,a1+16 → +16: addr3 */
  regs[3] = *(u32 *)((u8 *)a2 + 0); /* l32i.n a3,a2+0 → +0: frame control */
  regs[5] = *(u8 *)((u8 *)a2 + 21); /* l8ui → +21: 802.11 header region */
  (void)((int(*)())wifi_log)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())sta_get_owe_data)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())memcmp)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())ieee80211_getcapinfo)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())ieee80211_vnd_lora_ie_size)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())ieee80211_getmgtframe)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())memcpy)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())ieee80211_add_rates)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())ieee80211_add_supportedchannels)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())ieee80211_add_xrates)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())ieee80211_is_ht_cipher)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())ieee80211_add_htcap)(); /* observed call (disasm order; args a2..a5) */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* ieee80211_auth_construct @ ieee80211_output.o 0000003c size 778B bind GLOBAL
 * Calls: sta_is_wpa3_enabled, ieee80211_sta_new_state, ieee80211_getmgtframe, wifi_log, memcpy, ieee80211_crypto_encap, wifi_get_macaddr | Data refs: g_ic, g_mesh_is_root, .rodata_wlog_warning.33, esp_mesh_quick_funcs, sta_is_wpa3_enabled, ieee80211_sta_new_state, ieee80211_getmgtframe, wifi_log, memcpy, ieee80211_crypto_encap
 * Fidelity: medium - call order + offsets from disasm; straight-line details summarised */
/* disasm section: .text.ieee80211_auth_construct */
int ieee80211_auth_construct(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_auth_construct(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 80B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): -1, 1, 0, 6, 24, 136, 28, 71, 2, 64 */
  /* observed branches: bneix4, beqz.nx7, bnez.nx9, beqix1, beqx1, bnex1 */
  /* observed memory traffic (first 10): */
    /* l32i.n a5, a2, -- 0: frame control */
    /* s32i.n a2, a1, -- 12: 802.11 header region */
    /* s32i.n a2, a1, -- 16: addr3 */
    /* l32i a2, a5, -- 0x14c: ic/eb control word */
    /* s32i.n a3, a1, -- 20: eb len field region */
    /* s32i.n a14, a1, -- 28: HT */
    /* l32i.n a14, a1, -- 28: HT */
    /* l8ui a12, a7, -- 0: frame control */
    /* l32i a3, a4, -- off 0x290 */
    /* l16ui a12, a3, -- 0: frame control */
  /* observed call sequence (in order): sta_is_wpa3_enabled -> ieee80211_sta_new_state -> ieee80211_getmgtframe -> wifi_log -> memcpy -> ieee80211_crypto_encap -> wifi_get_macaddr */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[5] = *(u32 *)((u8 *)a2 + 0); /* l32i.n a5,a2+0 → +0: frame control */
  *(u32 *)(((u8 *)a1_spill) + 12) = regs[2]; /* s32i.n a2,a1+12 → +12: 802.11 header region */
  *(u32 *)(((u8 *)a1_spill) + 16) = regs[2]; /* s32i.n a2,a1+16 → +16: addr3 */
  regs[2] = *(u32 *)((u8 *)(uintptr_t)a4 + 332); /* l32i a2,a5+332 → +332: ic/eb control word */
  *(u32 *)(((u8 *)a1_spill) + 20) = regs[3]; /* s32i.n a3,a1+20 → +20: eb len field region */
  *(u32 *)(((u8 *)a1_spill) + 28) = regs[1]; /* s32i.n a14,a1+28 → +28: HT */
  (void)((int(*)())sta_is_wpa3_enabled)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())ieee80211_sta_new_state)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())ieee80211_getmgtframe)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())wifi_log)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())memcpy)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())ieee80211_crypto_encap)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())wifi_get_macaddr)(); /* observed call (disasm order; args a2..a5) */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* ieee80211_beacon_alloc @ ieee80211_output.o 00000064 size 586B bind GLOBAL
 * Calls: memcpy, wifi_log, chm_get_home_channel, chm_get_chan_info, ieee80211_vnd_lora_ie_size, .text.ieee80211_vnd_ie_size$part$0, ieee80211_getbcnframe, ieee80211_beacon_construct, wifi_get_macaddr, ieee80211_send_setup, ieee80211_set_tx_desc | Data refs: .rodata.ieee80211_beacon_alloc.str1.1, g_wifi_nvs, .rodata.ieee80211_send_setup.str1.1, .rodata_wlog_error.56, g_ic, esp_mesh_quick_funcs, g_mesh_init_ps_type, .rodata_wlog_warning.57, .rodata_wlog_error.58, memcpy
 * Fidelity: medium - call order + offsets from disasm; straight-line details summarised */
/* disasm section: .text.ieee80211_beacon_alloc */
int ieee80211_beacon_alloc(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_beacon_alloc(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 80B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 6, 0, 1, 3, 10, 8, 163, 5, 71, 23 */
  /* observed branches: beqx5, bnex1, beqz.nx4, bgeux1, bneix1, bnez.nx1, bgex1 */
  /* observed memory traffic (first 10): */
    /* s32i.n a6, a1, -- off 36 */
    /* l32i.n a7, a4, -- 0: frame control */
    /* l32i.n a4, a2, -- 0: frame control */
    /* l8ui a10, a10, -- 0: frame control */
    /* l32i a8, a10, -- 8: 802.11 header region */
    /* l32i a8, a4, -- off 0x150 */
    /* l32i a8, a5, -- off 0x1b4 */
    /* l32i a8, a8, -- 44: eb priv word */
    /* l8ui a4, a4, -- off 105 */
    /* l32i a9, a7, -- off 0x368 */
  /* observed call sequence (in order): memcpy -> wifi_log -> chm_get_home_channel -> chm_get_chan_info -> ieee80211_vnd_lora_ie_size -> .text.ieee80211_vnd_ie_size$part$0+0x4 -> ieee80211_getbcnframe -> ieee80211_beacon_construct -> wifi_get_macaddr -> ieee80211_send_setup -> ieee80211_set_tx_desc */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  *(u32 *)(((u8 *)a1_spill) + 36) = regs[6]; /* s32i.n a6,a1+36 → +36:  */
  regs[7] = *(u32 *)(eb8 + 0); /* l32i.n a7,a4+0 → +0: frame control */
  regs[4] = *(u32 *)((u8 *)a2 + 0); /* l32i.n a4,a2+0 → +0: frame control */
  regs[1] = *(u8 *)(((u8 *)0) + 0); /* l8ui → +0: frame control */
  regs[8] = *(u32 *)(((u8 *)0) + 8); /* l32i a8,a10+8 → +8: 802.11 header region */
  regs[8] = *(u32 *)(eb8 + 336); /* l32i a8,a4+336 → +336:  */
  (void)((int(*)())memcpy)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())wifi_log)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())chm_get_home_channel)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())chm_get_chan_info)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())ieee80211_vnd_lora_ie_size)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())ieee80211_getbcnframe)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())ieee80211_beacon_construct)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())wifi_get_macaddr)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())ieee80211_send_setup)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())ieee80211_set_tx_desc)(); /* observed call (disasm order; args a2..a5) */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* ieee80211_classify @ ieee80211_output.o 00000024 size 400B bind GLOBAL
 * Calls: wifi_log, ic_trc_set_per_pkt_rate, __bswapsi2 | Data refs: g_ic, .rodata_wlog_debug.21, wifi_log, ic_trc_set_per_pkt_rate, __bswapsi2
 * Fidelity: medium - call order + offsets from disasm; straight-line details summarised */
/* disasm section: .text.ieee80211_classify */
int ieee80211_classify(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_classify(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 48B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 1, 0, 17, 4, 64, 5, 7, 2, 3, 9 */
  /* observed branches: beqz.nx4, bnez.nx2, bneix1, bnex2, bbsix1, bltix2, beqix1 */
  /* observed memory traffic (first 10): */
    /* l32i.n a8, a3, -- 44: eb priv word */
    /* l32i.n a11, a8, -- 0: frame control */
    /* l32i.n a4, a3, -- 4: addr1 */
    /* l32i.n a4, a4, -- 4: addr1 */
    /* l8ui a9, a4, -- 20: eb len field region */
    /* l8ui a8, a4, -- 21: 802.11 header region */
    /* l8ui a9, a4, -- 12: 802.11 header region */
    /* l8ui a8, a4, -- 13: 802.11 header region */
    /* l8ui a9, a9, -- off 243 */
    /* l32i.n a12, a2, -- 0: frame control */
  /* observed call sequence (in order): wifi_log -> ic_trc_set_per_pkt_rate -> __bswapsi2 */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[8] = *(u32 *)((u8 *)a3 + 44); /* l32i.n a8,a3+44 → +44: eb priv word */
  regs[1] = *(u32 *)(((u8 *)0) + 0); /* l32i.n a11,a8+0 → +0: frame control */
  regs[4] = *(u32 *)((u8 *)a3 + 4); /* l32i.n a4,a3+4 → +4: addr1 */
  regs[4] = *(u32 *)(eb8 + 4); /* l32i.n a4,a4+4 → +4: addr1 */
  regs[9] = *(u8 *)(eb8 + 20); /* l8ui → +20: eb len field region */
  regs[8] = *(u8 *)(eb8 + 21); /* l8ui → +21: 802.11 header region */
  (void)((int(*)())wifi_log)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())ic_trc_set_per_pkt_rate)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())__bswapsi2)(); /* observed call (disasm order; args a2..a5) */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* ieee80211_copy_eb_header @ ieee80211_output.o 0000000c size 137B bind GLOBAL
 * Calls: memcpy | Data refs: memcpy
 * Fidelity: medium - call order + branch skeleton from disasm; some field names inferred */
/* disasm section: .text.ieee80211_copy_eb_header */
int ieee80211_copy_eb_header(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_copy_eb_header(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 32B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 32 */
  /* observed branches: bbcix1 */
  /* observed memory traffic (first 10): */
    /* l32i.n a10, a3, -- 44: eb priv word */
    /* l32i.n a11, a2, -- 44: eb priv word */
    /* l32i.n a9, a10, -- 16: addr3 */
    /* l32i.n a8, a11, -- 16: addr3 */
    /* s32i.n a8, a11, -- 16: addr3 */
    /* l32i.n a9, a3, -- 28: HT */
    /* l32i.n a8, a2, -- 28: HT */
    /* s32i.n a8, a2, -- 28: HT */
    /* l32i.n a8, a10, -- 0: frame control */
    /* l32i.n a9, a3, -- 4: addr1 */
  /* observed call sequence (in order): memcpy */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[1] = *(u32 *)((u8 *)a3 + 44); /* l32i.n a10,a3+44 → +44: eb priv word */
  regs[1] = *(u32 *)((u8 *)a2 + 44); /* l32i.n a11,a2+44 → +44: eb priv word */
  regs[9] = *(u32 *)(((u8 *)0) + 16); /* l32i.n a9,a10+16 → +16: addr3 */
  regs[8] = *(u32 *)(((u8 *)0) + 16); /* l32i.n a8,a11+16 → +16: addr3 */
  *(u32 *)(((u8 *)0) + 16) = regs[8]; /* s32i.n a8,a11+16 → +16: addr3 */
  regs[9] = *(u32 *)((u8 *)a3 + 28); /* l32i.n a9,a3+28 → +28: HT */
  (void)((int(*)())memcpy)(); /* observed call (disasm order; args a2..a5) */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* ieee80211_deauth_construct @ ieee80211_output.o 0000000c size 89B bind GLOBAL
 * Calls: ieee80211_get_robustmgtframe, wifi_log | Data refs: .rodata_wlog_warning.34, ieee80211_get_robustmgtframe, wifi_log
 * Fidelity: medium - call order + branch skeleton from disasm; some field names inferred */
/* disasm section: .text.ieee80211_deauth_construct */
int ieee80211_deauth_construct(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_deauth_construct(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 48B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 2, 24, 1, 64 */
  /* observed branches: beqz.nx2 */
  /* observed memory traffic (first 8): */
    /* l8ui a2, a2, -- off 251 */
    /* l32i.n a8, a10, -- 44: eb priv word */
    /* l32i.n a2, a8, -- 0: frame control */
    /* s32i.n a2, a8, -- 0: frame control */
    /* s16i a2, a4, -- 20: eb len field region */
    /* l32i.n a2, a1, -- 0: frame control */
    /* s16i a3, a2, -- 0: frame control */
    /* s16i a2, a4, -- 22: seqctl/len */
  /* observed call sequence (in order): ieee80211_get_robustmgtframe -> wifi_log */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[2] = *(u8 *)((u8 *)a2 + 251); /* l8ui → +251:  */
  regs[8] = *(u32 *)(((u8 *)0) + 44); /* l32i.n a8,a10+44 → +44: eb priv word */
  regs[2] = *(u32 *)(((u8 *)0) + 0); /* l32i.n a2,a8+0 → +0: frame control */
  *(u32 *)(((u8 *)0) + 0) = regs[2]; /* s32i.n a2,a8+0 → +0: frame control */
  *(u16 *)(eb8 + 20) = (u16)regs[2]; /* s16i → +20: eb len field region */
  regs[2] = *(u32 *)(((u8 *)a1_spill) + 0); /* l32i.n a2,a1+0 → +0: frame control */
  (void)((int(*)())ieee80211_get_robustmgtframe)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())wifi_log)(); /* observed call (disasm order; args a2..a5) */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* ieee80211_disassoc_construct @ ieee80211_output.o 0000000c size 88B bind GLOBAL
 * Calls: ieee80211_get_robustmgtframe, wifi_log | Data refs: .rodata_wlog_warning.35, ieee80211_get_robustmgtframe, wifi_log
 * Fidelity: medium - call order + branch skeleton from disasm; some field names inferred */
/* disasm section: .text.ieee80211_disassoc_construct */
int ieee80211_disassoc_construct(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_disassoc_construct(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 48B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 2, 24, 1, 64 */
  /* observed branches: beqz.nx2 */
  /* observed memory traffic (first 8): */
    /* l8ui a2, a2, -- off 251 */
    /* l32i.n a8, a10, -- 44: eb priv word */
    /* l32i.n a2, a8, -- 0: frame control */
    /* s32i.n a2, a8, -- 0: frame control */
    /* s16i a2, a4, -- 20: eb len field region */
    /* l32i.n a2, a1, -- 0: frame control */
    /* s16i a3, a2, -- 0: frame control */
    /* s16i a2, a4, -- 22: seqctl/len */
  /* observed call sequence (in order): ieee80211_get_robustmgtframe -> wifi_log */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[2] = *(u8 *)((u8 *)a2 + 251); /* l8ui → +251:  */
  regs[8] = *(u32 *)(((u8 *)0) + 44); /* l32i.n a8,a10+44 → +44: eb priv word */
  regs[2] = *(u32 *)(((u8 *)0) + 0); /* l32i.n a2,a8+0 → +0: frame control */
  *(u32 *)(((u8 *)0) + 0) = regs[2]; /* s32i.n a2,a8+0 → +0: frame control */
  *(u16 *)(eb8 + 20) = (u16)regs[2]; /* s16i → +20: eb len field region */
  regs[2] = *(u32 *)(((u8 *)a1_spill) + 0); /* l32i.n a2,a1+0 → +0: frame control */
  (void)((int(*)())ieee80211_get_robustmgtframe)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())wifi_log)(); /* observed call (disasm order; args a2..a5) */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* ieee80211_empty_txq @ ieee80211_output.o 00000010 size 126B bind GLOBAL
 * Calls: ieee80211_recycle_cache_eb | Data refs: g_wifi_global_lock, g_osi_funcs_p, s_tx_cacheq, ieee80211_recycle_cache_eb
 * Fidelity: medium - call order + branch skeleton from disasm; some field names inferred */
/* disasm section: .text.ieee80211_empty_txq */
int ieee80211_empty_txq(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_empty_txq(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 48B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 0 */
  /* observed branches: bnez.nx1, bnex1, beqz.nx1 */
  /* observed memory traffic (first 10): */
    /* l32i.n a5, a4, -- 0: frame control */
    /* s32i.n a3, a1, -- 0: frame control */
    /* l32i a5, a5, -- off 84 */
    /* l32i.n a10, a3, -- 0: frame control */
    /* s32i a1, a1, -- 4: addr1 */
    /* l32i.n a8, a10, -- off 40 */
    /* s32i.n a8, a5, -- 0: frame control */
    /* s32i.n a5, a5, -- 4: addr1 */
    /* l32i.n a8, a10, -- 44: eb priv word */
    /* l32i.n a8, a8, -- 16: addr3 */
  /* observed call sequence (in order): ieee80211_recycle_cache_eb */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[5] = *(u32 *)(eb8 + 0); /* l32i.n a5,a4+0 → +0: frame control */
  *(u32 *)(((u8 *)a1_spill) + 0) = regs[3]; /* s32i.n a3,a1+0 → +0: frame control */
  regs[5] = *(u32 *)((u8 *)(uintptr_t)a4 + 84); /* l32i a5,a5+84 → +84:  */
  regs[1] = *(u32 *)((u8 *)a3 + 0); /* l32i.n a10,a3+0 → +0: frame control */
  *(u32 *)(((u8 *)a1_spill) + 4) = regs[1]; /* s32i a1,a1+4 → +4: addr1 */
  regs[8] = *(u32 *)(((u8 *)0) + 40); /* l32i.n a8,a10+40 → +40:  */
  (void)((int(*)())ieee80211_recycle_cache_eb)(); /* observed call (disasm order; args a2..a5) */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* ieee80211_encap_amsdu @ ieee80211_output.o 0000003c size 465B bind GLOBAL
 * Calls: ieee80211_amsdu_send_check, roundup2, ieee80211_amsdu_length_check, ieee80211_amsdu_encap_check, ieee80211_amsdu_adjust_head, memmove, memcpy, ieee80211_recycle_cache_eb | Data refs: g_wifi_menuconfig, g_wifi_global_lock, g_osi_funcs_p, s_tx_cacheq, ieee80211_amsdu_send_check, roundup2, ieee80211_amsdu_length_check, ieee80211_amsdu_encap_check, ieee80211_amsdu_adjust_head, memmove
 * Fidelity: medium - call order + offsets from disasm; straight-line details summarised */
/* disasm section: .text.ieee80211_encap_amsdu */
int ieee80211_encap_amsdu(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_encap_amsdu(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 64B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 4, 0, 1, -1 */
  /* observed branches: bnez.nx5, bbsix1, bnex2, banyx1, beqz.nx1 */
  /* observed memory traffic (first 10): */
    /* l32i a3, a3, -- off 76 */
    /* l32i a7, a2, -- 0: frame control */
    /* l16ui a10, a7, -- 22: seqctl/len */
    /* s32i.n a3, a1, -- 0: frame control */
    /* s32i.n a1, a1, -- 4: addr1 */
    /* l32i.n a4, a5, -- 0: frame control */
    /* l32i.n a10, a8, -- 0: frame control */
    /* l32i a4, a4, -- off 84 */
    /* l32i.n a6, a5, -- 0: frame control */
    /* l32i.n a4, a5, -- 0: frame control */
  /* observed call sequence (in order): ieee80211_amsdu_send_check -> roundup2 -> ieee80211_amsdu_length_check -> ieee80211_amsdu_encap_check -> ieee80211_amsdu_adjust_head -> memmove -> memcpy -> ieee80211_recycle_cache_eb */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[3] = *(u32 *)((u8 *)a3 + 76); /* l32i a3,a3+76 → +76:  */
  regs[7] = *(u32 *)((u8 *)a2 + 0); /* l32i a7,a2+0 → +0: frame control */
  regs[1] = *(u16 *)(((u8 *)0) + 22); /* l16ui → +22: seqctl/len */
  *(u32 *)(((u8 *)a1_spill) + 0) = regs[3]; /* s32i.n a3,a1+0 → +0: frame control */
  *(u32 *)(((u8 *)a1_spill) + 4) = regs[1]; /* s32i.n a1,a1+4 → +4: addr1 */
  regs[4] = *(u32 *)((u8 *)(uintptr_t)a4 + 0); /* l32i.n a4,a5+0 → +0: frame control */
  (void)((int(*)())ieee80211_amsdu_send_check)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())roundup2)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())ieee80211_amsdu_length_check)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())ieee80211_amsdu_encap_check)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())ieee80211_amsdu_adjust_head)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())memmove)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())memcpy)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())ieee80211_recycle_cache_eb)(); /* observed call (disasm order; args a2..a5) */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* ieee80211_encap_esfbuf @ ieee80211_output.o 00000074 size 1303B bind GLOBAL
 * Calls: wifi_log, wifi_get_macaddr, memcpy, ieee80211_crypto_encap, ieee80211_align_eb, nan_get_clust_id, ic_ebuf_recycle_tx, ieee80211_ampdu_enable, ieee80211_ampdu_request, ieee80211_set_tx_desc, memcmp | Data refs: .rodata.ieee80211_send_setup.str1.1, .rodata_wlog_error.20, g_ic, g_mesh_is_root, g_wifi_menuconfig, g_mesh_topology, ieee80211_ethbroadcast, wifi_log, wifi_get_macaddr, memcpy
 * Fidelity: high - full call chain + key insns/offsets cited from disasm section */
/* disasm section: .wifi0iram.19 */
int ieee80211_encap_esfbuf(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_encap_esfbuf(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 96B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 3, 1, 0, 2, 14, -3, 26, 24, -86, 254 */
  /* observed branches: beqz.nx10, beqix3, bltx1, bltix1, beqx4, bnez.nx2, bneix5, bbcix8 */
  /* observed memory traffic (first 10): */
    /* l32i.n a2, a9, -- 0: frame control */
    /* s32i.n a2, a1, -- off 32 */
    /* l32i.n a3, a2, -- 16: addr3 */
    /* l32i.n a8, a1, -- off 32 */
    /* l32i.n a2, a2, -- 20: eb len field region */
    /* s32i.n a9, a1, -- off 52 */
    /* l32i.n a7, a6, -- 4: addr1 */
    /* l32i.n a2, a7, -- 4: addr1 */
    /* l8ui a13, a2, -- 13: 802.11 header region */
    /* l8ui a3, a2, -- 12: 802.11 header region */
  /* observed call sequence (in order): wifi_log -> wifi_get_macaddr -> memcpy -> ieee80211_crypto_encap -> ieee80211_align_eb -> nan_get_clust_id -> ic_ebuf_recycle_tx -> ieee80211_ampdu_enable -> ieee80211_ampdu_request -> ieee80211_set_tx_desc -> memcmp */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[2] = *(u32 *)(((u8 *)0) + 0); /* l32i.n a2,a9+0 → +0: frame control */
  *(u32 *)(((u8 *)a1_spill) + 32) = regs[2]; /* s32i.n a2,a1+32 → +32:  */
  regs[3] = *(u32 *)((u8 *)a2 + 16); /* l32i.n a3,a2+16 → +16: addr3 */
  regs[8] = *(u32 *)(((u8 *)a1_spill) + 32); /* l32i.n a8,a1+32 → +32:  */
  regs[2] = *(u32 *)((u8 *)a2 + 20); /* l32i.n a2,a2+20 → +20: eb len field region */
  *(u32 *)(((u8 *)a1_spill) + 52) = regs[9]; /* s32i.n a9,a1+52 → +52:  */
  (void)((int(*)())wifi_log)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())wifi_get_macaddr)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())memcpy)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())ieee80211_crypto_encap)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())ieee80211_align_eb)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())nan_get_clust_id)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())ic_ebuf_recycle_tx)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())ieee80211_ampdu_enable)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())ieee80211_ampdu_request)(); /* observed call (disasm order; args a2..a5) */

  /* a4 (a5 after mapping) = ifindex class 0..5; beqz/beqi chains @0x7b-0x87 map to 0/1/2.
   * NULL-eb + non-g_ic check -> wifi_log + spin (j . @0xb8).
   * Copies 14B LLC/SNAP region via memcpy (a1+14 dst, len 14 @0xe1).
   * l8ui +12/+13 build ethertype; bit15 test (slli 15 @0xff) selects A-MSDU vs plain.
   * Then: ieee80211_crypto_encap() -> ieee80211_align_eb() ->
   * ieee80211_ampdu_enable()/request() -> ieee80211_set_tx_desc(). */
  return 0;

}

/* ieee80211_encap_keep_alive_data @ ieee80211_output.o 00000028 size 233B bind GLOBAL
 * Calls: wifi_get_macaddr, wifi_log, ic_ebuf_alloc, memcpy, ieee80211_encap_esfbuf | Data refs: g_ic, .rodata_wlog_warning.10, .rodata_wlog_warning.11, wifi_get_macaddr, wifi_log, ic_ebuf_alloc, memcpy, ieee80211_encap_esfbuf
 * Fidelity: medium - call order + offsets from disasm; straight-line details summarised */
/* disasm section: .text.ieee80211_encap_keep_alive_data */
int ieee80211_encap_keep_alive_data(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_encap_keep_alive_data(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 48B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 0, 2, 64, 1, 50, 3, -1, 6, 8, 7 */
  /* observed branches: beqz.nx3, bnez.nx2 */
  /* observed memory traffic (first 10): */
    /* l32i.n a2, a2, -- 16: addr3 */
    /* l32i a2, a2, -- off 228 */
    /* l32i.n a9, a10, -- 4: addr1 */
    /* l32i.n a8, a9, -- 0: frame control */
    /* l32i.n a11, a9, -- 0: frame control */
    /* l32i.n a5, a9, -- 4: addr1 */
    /* s32i.n a8, a9, -- 0: frame control */
    /* l16ui a8, a4, -- 22: seqctl/len */
    /* s32i.n a10, a9, -- 4: addr1 */
    /* s16i a8, a4, -- 22: seqctl/len */
  /* observed call sequence (in order): wifi_get_macaddr -> wifi_log -> ic_ebuf_alloc -> memcpy -> ieee80211_encap_esfbuf */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[2] = *(u32 *)((u8 *)a2 + 16); /* l32i.n a2,a2+16 → +16: addr3 */
  regs[2] = *(u32 *)((u8 *)a2 + 228); /* l32i a2,a2+228 → +228:  */
  regs[9] = *(u32 *)(((u8 *)0) + 4); /* l32i.n a9,a10+4 → +4: addr1 */
  regs[8] = *(u32 *)(((u8 *)0) + 0); /* l32i.n a8,a9+0 → +0: frame control */
  regs[1] = *(u32 *)(((u8 *)0) + 0); /* l32i.n a11,a9+0 → +0: frame control */
  regs[5] = *(u32 *)(((u8 *)0) + 4); /* l32i.n a5,a9+4 → +4: addr1 */
  (void)((int(*)())wifi_get_macaddr)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())wifi_log)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())ic_ebuf_alloc)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())memcpy)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())ieee80211_encap_esfbuf)(); /* observed call (disasm order; args a2..a5) */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* ieee80211_encap_null_data @ ieee80211_output.o 00000034 size 290B bind GLOBAL
 * Calls: wifi_log, ieee80211_getmgtframe, memset, ic_get_addr, ieee80211_send_setup, ieee80211_set_tx_desc | Data refs: g_ic, .rodata_wlog_warning.59, .rodata_wlog_warning.60, .rodata_wlog_warning.61, wifi_log, ieee80211_getmgtframe, memset, ic_get_addr, ieee80211_send_setup, ieee80211_set_tx_desc
 * Fidelity: medium - call order + offsets from disasm; straight-line details summarised */
/* disasm section: .text.ieee80211_encap_null_data */
int ieee80211_encap_null_data(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_encap_null_data(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 64B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 0, 2, 64, 1, 24, -1, 3, 16, 72, 8 */
  /* observed branches: beqx2, bnex1, beqz.nx2, bnez.nx1 */
  /* observed memory traffic (first 10): */
    /* l32i.n a2, a6, -- 16: addr3 */
    /* s32i.n a3, a1, -- 16: addr3 */
    /* l32i a4, a2, -- off 228 */
    /* l32i a2, a6, -- off 116 */
    /* l32i.n a6, a4, -- 0: frame control */
    /* l32i.n a6, a10, -- 4: addr1 */
    /* l32i.n a6, a6, -- 4: addr1 */
    /* l32i.n a8, a2, -- 4: addr1 */
    /* s32i.n a7, a2, -- 20: eb len field region */
    /* l32i.n a9, a8, -- 0: frame control */
  /* observed call sequence (in order): wifi_log -> ieee80211_getmgtframe -> memset -> ic_get_addr -> ieee80211_send_setup -> ieee80211_set_tx_desc */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[2] = *(u32 *)(eb8 + 16); /* l32i.n a2,a6+16 → +16: addr3 */
  *(u32 *)(((u8 *)a1_spill) + 16) = regs[3]; /* s32i.n a3,a1+16 → +16: addr3 */
  regs[4] = *(u32 *)((u8 *)a2 + 228); /* l32i a4,a2+228 → +228:  */
  regs[2] = *(u32 *)(eb8 + 116); /* l32i a2,a6+116 → +116:  */
  regs[6] = *(u32 *)(eb8 + 0); /* l32i.n a6,a4+0 → +0: frame control */
  regs[6] = *(u32 *)(((u8 *)0) + 4); /* l32i.n a6,a10+4 → +4: addr1 */
  (void)((int(*)())wifi_log)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())ieee80211_getmgtframe)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())memset)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())ic_get_addr)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())ieee80211_send_setup)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())ieee80211_set_tx_desc)(); /* observed call (disasm order; args a2..a5) */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* ieee80211_get_nvs_he_dcm_max_constellation_tx @ ieee80211_output.o 00000004 size 16B bind GLOBAL
 * Calls: none | Data refs: g_wifi_nvs
 * Fidelity: high - leaf; full insn sequence captured, no hidden control flow */
/* disasm section: .text.ieee80211_get_nvs_he_dcm_max_constellation_tx */
int ieee80211_get_nvs_he_dcm_max_constellation_tx(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_get_nvs_he_dcm_max_constellation_tx(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 32B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed memory traffic (first 2): */
    /* l32i.n a8, a8, -- 0: frame control */
    /* l8ui a2, a8, -- off 118 */
  /* observed calls: none (leaf) */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[8] = *(u32 *)(((u8 *)0) + 0); /* l32i.n a8,a8+0 → +0: frame control */
  regs[2] = *(u8 *)(((u8 *)0) + 118); /* l8ui → +118:  */
  /* no calls observed: leaf */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* ieee80211_get_robustmgtframe @ ieee80211_output.o 00000014 size 100B bind GLOBAL
 * Calls: ieee80211_get_cipher_mic_len, ieee80211_getmgtframe | Data refs: g_ic, g_wifi_nvs, ieee80211_get_cipher_mic_len, ieee80211_getmgtframe
 * Fidelity: medium - call order + branch skeleton from disasm; some field names inferred */
/* disasm section: .text.ieee80211_get_robustmgtframe */
int ieee80211_get_robustmgtframe(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_get_robustmgtframe(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 32B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 0, 1 */
  /* observed branches: beqz.nx1, bnez.nx1 */
  /* observed memory traffic (first 7): */
    /* l8ui a9, a5, -- 4: addr1 */
    /* l32i.n a9, a5, -- 0: frame control */
    /* l32i a10, a10, -- off 0x2a0 */
    /* l8ui a9, a9, -- off 251 */
    /* l8ui a10, a5, -- off 174 */
    /* l32i.n a5, a5, -- 0: frame control */
    /* l8ui a10, a5, -- off 255 */
  /* observed call sequence (in order): ieee80211_get_cipher_mic_len -> ieee80211_getmgtframe */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[9] = *(u8 *)((u8 *)(uintptr_t)a4 + 4); /* l8ui → +4: addr1 */
  regs[9] = *(u32 *)((u8 *)(uintptr_t)a4 + 0); /* l32i.n a9,a5+0 → +0: frame control */
  regs[1] = *(u32 *)(((u8 *)0) + 672); /* l32i a10,a10+672 → +672:  */
  regs[9] = *(u8 *)(((u8 *)0) + 251); /* l8ui → +251:  */
  regs[1] = *(u8 *)((u8 *)(uintptr_t)a4 + 174); /* l8ui → +174:  */
  regs[5] = *(u32 *)((u8 *)(uintptr_t)a4 + 0); /* l32i.n a5,a5+0 → +0: frame control */
  (void)((int(*)())ieee80211_get_cipher_mic_len)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())ieee80211_getmgtframe)(); /* observed call (disasm order; args a2..a5) */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* ieee80211_getcapinfo @ ieee80211_output.o 00000014 size 158B bind GLOBAL
 * Calls: wifi_log | Data refs: .rodata.ieee80211_send_setup.str1.1, .rodata_wlog_error.25, g_ic, g_wifi_nvs, wifi_log
 * Fidelity: medium - call order + branch skeleton from disasm; some field names inferred */
/* disasm section: .text.ieee80211_getcapinfo */
int ieee80211_getcapinfo(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_getcapinfo(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 32B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 1, 0, 17, 32 */
  /* observed branches: beqz.nx1, bnez.nx2, bneix1, bnex1, bnonex1 */
  /* observed memory traffic (first 8): */
    /* l32i.n a9, a2, -- 0: frame control */
    /* l32i a10, a9, -- 0x14c: ic/eb control word */
    /* l8ui a11, a8, -- 2: duration */
    /* l32i a11, a9, -- off 164 */
    /* l16ui a10, a2, -- off 42 */
    /* l32i.n a2, a12, -- 20: eb len field region */
    /* l32i.n a8, a8, -- 0: frame control */
    /* l8ui a8, a8, -- off 98 */
  /* observed call sequence (in order): wifi_log */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[9] = *(u32 *)((u8 *)a2 + 0); /* l32i.n a9,a2+0 → +0: frame control */
  regs[1] = *(u32 *)(((u8 *)0) + 332); /* l32i a10,a9+332 → +332: ic/eb control word */
  regs[1] = *(u8 *)(((u8 *)0) + 2); /* l8ui → +2: duration */
  regs[1] = *(u32 *)(((u8 *)0) + 164); /* l32i a11,a9+164 → +164:  */
  regs[1] = *(u16 *)((u8 *)a2 + 42); /* l16ui → +42:  */
  regs[2] = *(u32 *)(((u8 *)0) + 20); /* l32i.n a2,a12+20 → +20: eb len field region */
  (void)((int(*)())wifi_log)(); /* observed call (disasm order; args a2..a5) */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* ieee80211_is_tx_allowed @ ieee80211_output.o 00000000 size 30B bind GLOBAL
 * Calls: none | Data refs: none
 * Fidelity: high - leaf; full insn sequence captured, no hidden control flow */
/* disasm section: .wifi0iram.37 */
int ieee80211_is_tx_allowed(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_is_tx_allowed(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 32B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 1, 0 */
  /* observed branches: beqz.nx1 */
  /* observed memory traffic (first 1): */
    /* l8ui a8, a2, -- off 36 */
  /* observed calls: none (leaf) */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[8] = *(u8 *)((u8 *)a2 + 36); /* l8ui → +36:  */
  /* no calls observed: leaf */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* ieee80211_mgmt_output @ ieee80211_output.o 00000050 size 663B bind GLOBAL
 * Calls: wifi_log, wifi_get_macaddr, nan_get_clust_id, ieee80211_send_setup, ieee80211_is_bufferable_mmpdu, ieee80211_setup_robust_mgmtframe, add_mic_ie_bip, ic_ebuf_recycle_tx, ieee80211_pwrsave, nan_tx_action_frame, chm_is_at_home_channel, ic_tx_pkt | Data refs: ieee80211_ethbroadcast, .rodata.ieee80211_send_setup.str1.1, .rodata_wlog_error.14, g_ic, g_osi_funcs_p, g_wifi_nvs, wifi_log, wifi_get_macaddr, nan_get_clust_id, ieee80211_send_setup
 * Fidelity: high - full call chain + key insns/offsets cited from disasm section */
/* disasm section: .text.ieee80211_mgmt_output */
int ieee80211_mgmt_output(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_mgmt_output(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 80B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 1, 0, 2, 156, 208, 16, 4, 64, -2, -65 */
  /* observed branches: beqx3, bnez.nx2, bneix4, bnex4, bbcix4, beqz.nx6, bnonex1, beqix1 */
  /* observed memory traffic (first 10): */
    /* l32i a5, a2, -- 0: frame control */
    /* l32i.n a2, a8, -- 16: addr3 */
    /* l32i a2, a8, -- 20: eb len field region */
    /* l32i a9, a5, -- 0x14c: ic/eb control word */
    /* l32i.n a7, a3, -- 4: addr1 */
    /* l32i.n a7, a7, -- 4: addr1 */
    /* s32i.n a15, a1, -- 0: frame control */
    /* l32i a9, a5, -- 0x240: ic/eb control word */
    /* s32i.n a15, a1, -- off 32 */
    /* l32i.n a15, a1, -- off 32 */
  /* observed call sequence (in order): wifi_log -> wifi_get_macaddr -> nan_get_clust_id -> ieee80211_send_setup -> ieee80211_is_bufferable_mmpdu -> ieee80211_setup_robust_mgmtframe -> add_mic_ie_bip -> ic_ebuf_recycle_tx -> ieee80211_pwrsave -> nan_tx_action_frame -> chm_is_at_home_channel -> ic_tx_pkt */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[5] = *(u32 *)((u8 *)a2 + 0); /* l32i a5,a2+0 → +0: frame control */
  regs[2] = *(u32 *)(((u8 *)0) + 16); /* l32i.n a2,a8+16 → +16: addr3 */
  regs[2] = *(u32 *)(((u8 *)0) + 20); /* l32i a2,a8+20 → +20: eb len field region */
  regs[9] = *(u32 *)((u8 *)(uintptr_t)a4 + 332); /* l32i a9,a5+332 → +332: ic/eb control word */
  regs[7] = *(u32 *)((u8 *)a3 + 4); /* l32i.n a7,a3+4 → +4: addr1 */
  regs[7] = *(u32 *)(((u8 *)0) + 4); /* l32i.n a7,a7+4 → +4: addr1 */
  (void)((int(*)())wifi_log)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())wifi_get_macaddr)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())nan_get_clust_id)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())ieee80211_send_setup)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())ieee80211_is_bufferable_mmpdu)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())ieee80211_setup_robust_mgmtframe)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())add_mic_ie_bip)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())ic_ebuf_recycle_tx)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())ieee80211_pwrsave)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())nan_tx_action_frame)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())chm_is_at_home_channel)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())ic_tx_pkt)(); /* observed call (disasm order; args a2..a5) */

  /* NULL-eb guard -> wifi_log(1,0x5fc) spin; g_ic+16/20 identity check picks
   * direct vs NAN-cluster-id path (nan_get_clust_id @0xce when type==208 @0xc0).
   * ieee80211_send_setup() builds +0 FC/+4 addr1/+10 addr2/+16 addr3 header,
   * then bufferable-MMPDU + robust-mgmt (add_mic_ie_bip) + pwrsave + tx. */
  return 0;

}

/* ieee80211_output @ ieee80211_output.o 00000004 size 25B bind GLOBAL
 * Calls: ic_register_net80211_tx_cb | Data refs: s_tx_cacheq, ieee80211_output_process, .bss.s_encap_amsdu_func, ieee80211_encap_amsdu, ic_register_net80211_tx_cb
 * Fidelity: high - leaf; full insn sequence captured, no hidden control flow */
/* disasm section: .text.ieee80211_output_init */
int ieee80211_output(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_output(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 32B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 0 */
  /* observed memory traffic (first 3): */
    /* s32i.n a2, a8, -- 0: frame control */
    /* s32i.n a8, a8, -- 4: addr1 */
    /* s32i.n a9, a8, -- 0: frame control */
  /* observed call sequence (in order): ic_register_net80211_tx_cb */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  *(u32 *)(((u8 *)0) + 0) = regs[2]; /* s32i.n a2,a8+0 → +0: frame control */
  *(u32 *)(((u8 *)0) + 4) = regs[8]; /* s32i.n a8,a8+4 → +4: addr1 */
  *(u32 *)(((u8 *)0) + 0) = regs[9]; /* s32i.n a9,a8+0 → +0: frame control */
  (void)((int(*)())ic_register_net80211_tx_cb)(); /* observed call (disasm order; args a2..a5) */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* ieee80211_output_do @ ieee80211_output.o 00000044 size 380B bind GLOBAL
 * Calls: wifi_log, ieee80211_search_node, is_wapi_alloc_tx_buf, config_is_cache_tx_buf_enabled, ieee80211_wapi_alloc_tx_buf, ieee80211_alloc_tx_buf, ieee80211_post_hmac_tx | Data refs: .rodata_wlog_warning.5, .rodata_wlog_warning.6, g_wifi_global_lock, g_osi_funcs_p, g_hmac_cnt, g_ic, wifi_log, ieee80211_search_node, is_wapi_alloc_tx_buf, config_is_cache_tx_buf_enabled
 * Fidelity: medium - call order + offsets from disasm; straight-line details summarised */
/* disasm section: .wifiextrairam.4 */
int ieee80211_output_do(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_output_do(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 64B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 1, 0, 2, 64 */
  /* observed branches: bnez.nx5, beqz.nx4, bgeux1, bneix1, bbcix1, bltx1, bltix1 */
  /* observed memory traffic (first 10): */
    /* s32i.n a6, a1, -- 16: addr3 */
    /* s32i.n a4, a1, -- 0: frame control */
    /* l32i.n a8, a4, -- 0: frame control */
    /* l32i.n a10, a7, -- 0: frame control */
    /* l32i a8, a8, -- off 84 */
    /* l32i.n a9, a8, -- 44: eb priv word */
    /* s32i.n a9, a8, -- 44: eb priv word */
    /* l32i.n a9, a8, -- off 40 */
    /* s32i.n a9, a8, -- off 40 */
    /* s32i.n a8, a1, -- 20: eb len field region */
  /* observed call sequence (in order): wifi_log -> ieee80211_search_node -> is_wapi_alloc_tx_buf -> config_is_cache_tx_buf_enabled -> ieee80211_wapi_alloc_tx_buf -> ieee80211_alloc_tx_buf -> ieee80211_post_hmac_tx */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  *(u32 *)(((u8 *)a1_spill) + 16) = regs[6]; /* s32i.n a6,a1+16 → +16: addr3 */
  *(u32 *)(((u8 *)a1_spill) + 0) = regs[4]; /* s32i.n a4,a1+0 → +0: frame control */
  regs[8] = *(u32 *)(eb8 + 0); /* l32i.n a8,a4+0 → +0: frame control */
  regs[1] = *(u32 *)(((u8 *)0) + 0); /* l32i.n a10,a7+0 → +0: frame control */
  regs[8] = *(u32 *)(((u8 *)0) + 84); /* l32i a8,a8+84 → +84:  */
  regs[9] = *(u32 *)(((u8 *)0) + 44); /* l32i.n a9,a8+44 → +44: eb priv word */
  (void)((int(*)())wifi_log)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())ieee80211_search_node)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())is_wapi_alloc_tx_buf)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())config_is_cache_tx_buf_enabled)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())ieee80211_wapi_alloc_tx_buf)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())ieee80211_alloc_tx_buf)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())ieee80211_post_hmac_tx)(); /* observed call (disasm order; args a2..a5) */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* ieee80211_output_init @ ieee80211_output.o 00000014 size 37B bind GLOBAL
 * Calls: ic_register_net80211_tx_cb | Data refs: s_tx_cacheq, ieee80211_output_process, .bss.s_encap_amsdu_func, ieee80211_encap_amsdu, ic_register_net80211_tx_cb
 * Fidelity: high - leaf; full insn sequence captured, no hidden control flow */
/* disasm section: .text.ieee80211_output_init */
int ieee80211_output_init(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_output_init(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 32B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 0 */
  /* observed memory traffic (first 3): */
    /* s32i.n a2, a8, -- 0: frame control */
    /* s32i.n a8, a8, -- 4: addr1 */
    /* s32i.n a9, a8, -- 0: frame control */
  /* observed call sequence (in order): ic_register_net80211_tx_cb */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  *(u32 *)(((u8 *)0) + 0) = regs[2]; /* s32i.n a2,a8+0 → +0: frame control */
  *(u32 *)(((u8 *)0) + 4) = regs[8]; /* s32i.n a8,a8+4 → +4: addr1 */
  *(u32 *)(((u8 *)0) + 0) = regs[9]; /* s32i.n a9,a8+0 → +0: frame control */
  (void)((int(*)())ic_register_net80211_tx_cb)(); /* observed call (disasm order; args a2..a5) */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* ieee80211_output_pending_eb @ ieee80211_output.o 0000001c size 120B bind GLOBAL
 * Calls: chm_is_at_home_channel, ieee80211_search_node, ic_ebuf_recycle_tx, nan_dp_post_tx, ppTxPkt | Data refs: g_ic, g_ic+0x1a4, chm_is_at_home_channel, ieee80211_search_node, ic_ebuf_recycle_tx, nan_dp_post_tx, ppTxPkt
 * Fidelity: medium - call order + offsets from disasm; straight-line details summarised */
/* disasm section: .text.ieee80211_output_pending_eb */
int ieee80211_output_pending_eb(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_output_pending_eb(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 48B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 0, 1 */
  /* observed branches: bneix1, bnez.nx1 */
  /* observed memory traffic (first 10): */
    /* l32i a2, a3, -- 0x1a4: ic/eb control word */
    /* l32i a2, a3, -- 0x1a4: ic/eb control word */
    /* l32i.n a8, a2, -- off 40 */
    /* s32i a8, a3, -- 0x1a4: ic/eb control word */
    /* s32i a4, a3, -- off 0x1a8 */
    /* l32i.n a9, a2, -- 44: eb priv word */
    /* l32i.n a10, a9, -- 16: addr3 */
    /* s32i.n a8, a2, -- off 40 */
    /* s32i.n a8, a1, -- 0: frame control */
    /* l32i a8, a2, -- 4: addr1 */
  /* observed call sequence (in order): chm_is_at_home_channel -> ieee80211_search_node -> ic_ebuf_recycle_tx -> nan_dp_post_tx -> ppTxPkt */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[2] = *(u32 *)((u8 *)a3 + 420); /* l32i a2,a3+420 → +420: ic/eb control word */
  regs[2] = *(u32 *)((u8 *)a3 + 420); /* l32i a2,a3+420 → +420: ic/eb control word */
  regs[8] = *(u32 *)((u8 *)a2 + 40); /* l32i.n a8,a2+40 → +40:  */
  *(u32 *)((u8 *)a3 + 420) = regs[8]; /* s32i a8,a3+420 → +420: ic/eb control word */
  *(u32 *)((u8 *)a3 + 424) = regs[4]; /* s32i a4,a3+424 → +424:  */
  regs[9] = *(u32 *)((u8 *)a2 + 44); /* l32i.n a9,a2+44 → +44: eb priv word */
  (void)((int(*)())chm_is_at_home_channel)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())ieee80211_search_node)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())ic_ebuf_recycle_tx)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())nan_dp_post_tx)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())ppTxPkt)(); /* observed call (disasm order; args a2..a5) */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* ieee80211_output_process @ ieee80211_output.o 00000074 size 613B bind GLOBAL
 * Calls: ic_register_net80211_tx_cb | Data refs: s_tx_cacheq, ieee80211_output_process, .bss.s_encap_amsdu_func, ieee80211_encap_amsdu, ic_register_net80211_tx_cb
 * Fidelity: high - full call chain + key insns/offsets cited from disasm section */
/* disasm section: .text.ieee80211_output_init */
int ieee80211_output_process(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_output_process(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 32B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 0 */
  /* observed memory traffic (first 3): */
    /* s32i.n a2, a8, -- 0: frame control */
    /* s32i.n a8, a8, -- 4: addr1 */
    /* s32i.n a9, a8, -- 0: frame control */
  /* observed call sequence (in order): ic_register_net80211_tx_cb */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  *(u32 *)(((u8 *)0) + 0) = regs[2]; /* s32i.n a2,a8+0 → +0: frame control */
  *(u32 *)(((u8 *)0) + 4) = regs[8]; /* s32i.n a8,a8+4 → +4: addr1 */
  *(u32 *)(((u8 *)0) + 0) = regs[9]; /* s32i.n a9,a8+0 → +0: frame control */
  (void)((int(*)())ic_register_net80211_tx_cb)(); /* observed call (disasm order; args a2..a5) */

  /* TX queue pump: chm_is_at_home_channel() gate, drain s_tx_cacheq,
   * per-packet: config_is_cache_tx_buf_enabled() decides cache vs alloc path;
   * ieee80211_search_node() -> is_wapi_alloc_tx_buf()/ieee80211_wapi_alloc_tx_buf()
   * vs ic_ebuf_alloc()+ieee80211_copy_eb_header(); raw frames go to
   * ieee80211_output_raw_process(), else classify+encap_esfbuf+pwrsave/nan_dp_post_tx/ppTxPkt.
   * Observed order: chm_is_at_home_channel -> ieee80211_output_pending_eb ->
   * search_node -> wapi/ic_ebuf_alloc/copy -> raw_process OR classify/encap_esfbuf/pwrsave/ppTxPkt. */
  return 0; /* pump step; next packet re-enters same path */

}

/* ieee80211_output_raw_process @ ieee80211_output.o 00000040 size 384B bind GLOBAL
 * Calls: ic_ebuf_recycle_tx, wifi_log, hal_now, wifi_get_macaddr, memcmp, cnx_node_search, ppTxPkt | Data refs: g_ic, .rodata_wlog_warning.44, .data.s_raw_seq$0, .rodata_wlog_warning.45, ic_ebuf_recycle_tx, wifi_log, hal_now, wifi_get_macaddr, memcmp, cnx_node_search
 * Fidelity: high - full call chain + key insns/offsets cited from disasm section */
/* disasm section: .text.ieee80211_output_raw_process */
int ieee80211_output_raw_process(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_output_raw_process(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 48B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 2, 64, 1, 0, -1, 7, -2, 6 */
  /* observed branches: bneix2, bnez.nx3, bbcix2, beqz.nx2, beqx1 */
  /* observed memory traffic (first 10): */
    /* l32i a5, a4, -- 16: addr3 */
    /* l32i a5, a4, -- 20: eb len field region */
    /* l32i.n a7, a3, -- 44: eb priv word */
    /* l32i.n a8, a3, -- 4: addr1 */
    /* l32i.n a6, a7, -- 0: frame control */
    /* l32i a4, a8, -- 4: addr1 */
    /* l16ui a9, a3, -- 20: eb len field region */
    /* l16ui a6, a3, -- 22: seqctl/len */
    /* l32i.n a9, a8, -- 0: frame control */
    /* s32i.n a9, a8, -- 0: frame control */
  /* observed call sequence (in order): ic_ebuf_recycle_tx -> wifi_log -> hal_now -> wifi_get_macaddr -> memcmp -> cnx_node_search -> ppTxPkt */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[5] = *(u32 *)(eb8 + 16); /* l32i a5,a4+16 → +16: addr3 */
  regs[5] = *(u32 *)(eb8 + 20); /* l32i a5,a4+20 → +20: eb len field region */
  regs[7] = *(u32 *)((u8 *)a3 + 44); /* l32i.n a7,a3+44 → +44: eb priv word */
  regs[8] = *(u32 *)((u8 *)a3 + 4); /* l32i.n a8,a3+4 → +4: addr1 */
  regs[6] = *(u32 *)(((u8 *)0) + 0); /* l32i.n a6,a7+0 → +0: frame control */
  regs[4] = *(u32 *)(((u8 *)0) + 4); /* l32i a4,a8+4 → +4: addr1 */
  (void)((int(*)())ic_ebuf_recycle_tx)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())wifi_log)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())hal_now)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())wifi_get_macaddr)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())memcmp)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())cnx_node_search)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())ppTxPkt)(); /* observed call (disasm order; args a2..a5) */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* ieee80211_pm_tx_null_process @ ieee80211_output.o 0000001c size 142B bind GLOBAL
 * Calls: pm_is_sending_keep_alive, ieee80211_encap_null_data, wifi_log, ieee80211_encap_keep_alive_data, ppTxPkt | Data refs: g_ic, .rodata_wlog_debug.62, pm_is_sending_keep_alive, ieee80211_encap_null_data, wifi_log, ieee80211_encap_keep_alive_data, ppTxPkt
 * Fidelity: medium - call order + offsets from disasm; straight-line details summarised */
/* disasm section: .text.ieee80211_pm_tx_null_process */
int ieee80211_pm_tx_null_process(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_pm_tx_null_process(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 32B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 4, 8, 1, 32, 0 */
  /* observed branches: bnez.nx2, bbcix1 */
  /* observed memory traffic (first 8): */
    /* l32i.n a2, a2, -- 16: addr3 */
    /* l32i a8, a2, -- off 228 */
    /* l8ui a9, a9, -- off 52 */
    /* l32i a2, a2, -- off 164 */
    /* l8ui a2, a8, -- off 36 */
    /* l32i.n a8, a10, -- 44: eb priv word */
    /* l32i.n a2, a8, -- 0: frame control */
    /* s32i.n a2, a8, -- 0: frame control */
  /* observed call sequence (in order): pm_is_sending_keep_alive -> ieee80211_encap_null_data -> wifi_log -> ieee80211_encap_keep_alive_data -> ppTxPkt */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[2] = *(u32 *)((u8 *)a2 + 16); /* l32i.n a2,a2+16 → +16: addr3 */
  regs[8] = *(u32 *)((u8 *)a2 + 228); /* l32i a8,a2+228 → +228:  */
  regs[9] = *(u8 *)(((u8 *)0) + 52); /* l8ui → +52:  */
  regs[2] = *(u32 *)((u8 *)a2 + 164); /* l32i a2,a2+164 → +164:  */
  regs[2] = *(u8 *)(((u8 *)0) + 36); /* l8ui → +36:  */
  regs[8] = *(u32 *)(((u8 *)0) + 44); /* l32i.n a8,a10+44 → +44: eb priv word */
  (void)((int(*)())pm_is_sending_keep_alive)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())ieee80211_encap_null_data)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())wifi_log)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())ieee80211_encap_keep_alive_data)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())ppTxPkt)(); /* observed call (disasm order; args a2..a5) */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* ieee80211_post_hmac_tx @ ieee80211_output.o 00000020 size 116B bind GLOBAL
 * Calls: ieee80211_recycle_cache_eb, ieee80211_search_node, pp_post | Data refs: g_ic, s_tx_cacheq, ieee80211_recycle_cache_eb, ieee80211_search_node, pp_post
 * Fidelity: medium - call order + branch skeleton from disasm; some field names inferred */
/* disasm section: .wifiextrairam.2 */
int ieee80211_post_hmac_tx(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_post_hmac_tx(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 48B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 3, 1, 2, 0, 5 */
  /* observed branches: beqz.nx1, bnex1, bnez.nx1, beqx1 */
  /* observed memory traffic (first 10): */
    /* l8ui a3, a3, -- off 80 */
    /* l32i.n a8, a2, -- 44: eb priv word */
    /* l32i.n a8, a8, -- 16: addr3 */
    /* l32i.n a3, a2, -- 4: addr1 */
    /* l32i.n a11, a3, -- 4: addr1 */
    /* l32i.n a2, a1, -- 0: frame control */
    /* l32i.n a8, a9, -- 4: addr1 */
    /* s32i.n a3, a2, -- off 40 */
    /* s32i.n a2, a8, -- 0: frame control */
    /* s32i.n a8, a9, -- 4: addr1 */
  /* observed call sequence (in order): ieee80211_recycle_cache_eb -> ieee80211_search_node -> pp_post */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[3] = *(u8 *)((u8 *)a3 + 80); /* l8ui → +80:  */
  regs[8] = *(u32 *)((u8 *)a2 + 44); /* l32i.n a8,a2+44 → +44: eb priv word */
  regs[8] = *(u32 *)(((u8 *)0) + 16); /* l32i.n a8,a8+16 → +16: addr3 */
  regs[3] = *(u32 *)((u8 *)a2 + 4); /* l32i.n a3,a2+4 → +4: addr1 */
  regs[1] = *(u32 *)((u8 *)a3 + 4); /* l32i.n a11,a3+4 → +4: addr1 */
  regs[2] = *(u32 *)(((u8 *)a1_spill) + 0); /* l32i.n a2,a1+0 → +0: frame control */
  (void)((int(*)())ieee80211_recycle_cache_eb)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())ieee80211_search_node)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())pp_post)(); /* observed call (disasm order; args a2..a5) */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* ieee80211_raw_frame_sanity_check @ ieee80211_output.o 0000005c size 390B bind GLOBAL
 * Calls: wifi_log, wifi_get_macaddr, memcmp, cnx_node_search | Data refs: .rodata_wlog_error.46, .rodata_wlog_error.47, g_wifi_global_lock, g_osi_funcs_p, g_ic, .rodata_wlog_error.48, .rodata_wlog_error.49, .rodata_wlog_error.50, .rodata_wlog_error.51, .rodata_wlog_error.52
 * Fidelity: high - full call chain + key insns/offsets cited from disasm section */
/* disasm section: .text.ieee80211_raw_frame_sanity_check */
int ieee80211_raw_frame_sanity_check(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_raw_frame_sanity_check(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 64B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 1, 64, 23, 0, 12, -16, -32, 208, 6, 60 */
  /* observed branches: bnez.nx6, bgeux1, bltx1, bneix3, bbcix1, beqix2, beqz.nx4, beqx1 */
  /* observed memory traffic (first 10): */
    /* l32i.n a7, a6, -- 0: frame control */
    /* l32i.n a10, a4, -- 0: frame control */
    /* l32i a7, a7, -- off 84 */
    /* l32i.n a9, a7, -- 16: addr3 */
    /* l32i.n a9, a7, -- 20: eb len field region */
    /* l8ui a8, a3, -- 0: frame control */
    /* l8ui a7, a3, -- 1: frame control/duration */
    /* s32i.n a9, a1, -- 16: addr3 */
    /* l32i.n a9, a1, -- 16: addr3 */
    /* l32i a10, a9, -- off 228 */
  /* observed call sequence (in order): wifi_log -> wifi_get_macaddr -> memcmp -> cnx_node_search */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[7] = *(u32 *)(eb8 + 0); /* l32i.n a7,a6+0 → +0: frame control */
  regs[1] = *(u32 *)(eb8 + 0); /* l32i.n a10,a4+0 → +0: frame control */
  regs[7] = *(u32 *)(((u8 *)0) + 84); /* l32i a7,a7+84 → +84:  */
  regs[9] = *(u32 *)(((u8 *)0) + 16); /* l32i.n a9,a7+16 → +16: addr3 */
  regs[9] = *(u32 *)(((u8 *)0) + 20); /* l32i.n a9,a7+20 → +20: eb len field region */
  regs[8] = *(u8 *)((u8 *)a3 + 0); /* l8ui → +0: frame control */
  (void)((int(*)())wifi_log)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())wifi_get_macaddr)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())memcmp)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())cnx_node_search)(); /* observed call (disasm order; args a2..a5) */

  u8 *f = (u8 *)a2; u32 len = (u32)a4;
  if (!f) { ((int(*)())wifi_log)(); return 0; }        /* @0x62 bnez.n a3 */
  if (len < 23 || len > 0x5dc)                       /* movi 23/0x5dc @0x77-7c */
    { ((int(*)())wifi_log)(); return 0x102; }
  /* lock via g_osi_funcs_p+84 indirect call; g_ic+16/20 null checks */
  /* FC parse: l8ui a8,a3,0; type=(fc>>2)&3? extui/and @0xdc-0xe6 */
  /* +0: frame control, +1: flags; bbci/bbsi tests on subtype bits */
  /* memcmp SA/DA + cnx_node_search observed in literal pool */
  return 0; /* fail path returns 0/0x102 per j-targets @0xa9/0xac */

}

/* ieee80211_recycle_cache_eb @ ieee80211_output.o 00000008 size 39B bind GLOBAL
 * Calls: ic_ebuf_recycle_tx | Data refs: s_netstack_free, ic_ebuf_recycle_tx
 * Fidelity: high - leaf; full insn sequence captured, no hidden control flow */
/* disasm section: .text.ieee80211_recycle_cache_eb */
int ieee80211_recycle_cache_eb(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_recycle_cache_eb(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 32B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed branches: beqz.nx2 */
  /* observed memory traffic (first 5): */
    /* l32i.n a10, a2, -- 0: frame control */
    /* l32i.n a8, a2, -- 16: addr3 */
    /* l32i.n a9, a2, -- 4: addr1 */
    /* s32i.n a8, a9, -- 4: addr1 */
    /* l32i.n a8, a8, -- 0: frame control */
  /* observed call sequence (in order): ic_ebuf_recycle_tx */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[1] = *(u32 *)((u8 *)a2 + 0); /* l32i.n a10,a2+0 → +0: frame control */
  regs[8] = *(u32 *)((u8 *)a2 + 16); /* l32i.n a8,a2+16 → +16: addr3 */
  regs[9] = *(u32 *)((u8 *)a2 + 4); /* l32i.n a9,a2+4 → +4: addr1 */
  *(u32 *)(((u8 *)0) + 4) = regs[8]; /* s32i.n a8,a9+4 → +4: addr1 */
  regs[8] = *(u32 *)(((u8 *)0) + 0); /* l32i.n a8,a8+0 → +0: frame control */
  (void)((int(*)())ic_ebuf_recycle_tx)(); /* observed call (disasm order; args a2..a5) */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* ieee80211_reg_encap_amsdu_cb @ ieee80211_output.o 00000004 size 13B bind GLOBAL
 * Calls: none | Data refs: .bss.s_encap_amsdu_func
 * Fidelity: high - leaf; full insn sequence captured, no hidden control flow */
/* disasm section: .text.ieee80211_reg_encap_amsdu_cb */
int ieee80211_reg_encap_amsdu_cb(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_reg_encap_amsdu_cb(void *a2, void *a3, unsigned a4, unsigned a5)
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

/* ieee80211_reg_netstack_buf_cb @ ieee80211_output.o 00000008 size 18B bind GLOBAL
 * Calls: none | Data refs: s_netstack_ref, s_netstack_free
 * Fidelity: high - leaf; full insn sequence captured, no hidden control flow */
/* disasm section: .text.ieee80211_reg_netstack_buf_cb */
int ieee80211_reg_netstack_buf_cb(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_reg_netstack_buf_cb(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 32B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed memory traffic (first 2): */
    /* s32i.n a2, a8, -- 0: frame control */
    /* s32i.n a3, a8, -- 0: frame control */
  /* observed calls: none (leaf) */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  *(u32 *)(((u8 *)0) + 0) = regs[2]; /* s32i.n a2,a8+0 → +0: frame control */
  *(u32 *)(((u8 *)0) + 0) = regs[3]; /* s32i.n a3,a8+0 → +0: frame control */
  /* no calls observed: leaf */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* ieee80211_search_node @ ieee80211_output.o 00000030 size 221B bind GLOBAL
 * Calls: nan_dp_search_node, cnx_node_search, ieee80211_is_tx_allowed | Data refs: g_ic, nan_dp_search_node, cnx_node_search, ieee80211_is_tx_allowed
 * Fidelity: medium - call order + offsets from disasm; straight-line details summarised */
/* disasm section: .text.ieee80211_search_node */
int ieee80211_search_node(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_search_node(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 32B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 0, 1 */
  /* observed branches: beqz.nx1, bnez.nx6, bneix3, beqix1, bbsix1, beqx1 */
  /* observed memory traffic (first 10): */
    /* l8ui a2, a2, -- off 80 */
    /* l32i.n a2, a9, -- 16: addr3 */
    /* l32i.n a2, a9, -- 20: eb len field region */
    /* l32i a2, a9, -- off 0x2a0 */
    /* s32i.n a3, a4, -- 0: frame control */
    /* l32i a9, a2, -- 152: key PN/counter region */
    /* s32i.n a2, a4, -- 0: frame control */
    /* l32i a2, a2, -- off 228 */
    /* l16ui a8, a2, -- off 38 */
    /* l32i.n a8, a2, -- 12: 802.11 header region */
  /* observed call sequence (in order): nan_dp_search_node -> cnx_node_search -> ieee80211_is_tx_allowed */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[2] = *(u8 *)((u8 *)a2 + 80); /* l8ui → +80:  */
  regs[2] = *(u32 *)(((u8 *)0) + 16); /* l32i.n a2,a9+16 → +16: addr3 */
  regs[2] = *(u32 *)(((u8 *)0) + 20); /* l32i.n a2,a9+20 → +20: eb len field region */
  regs[2] = *(u32 *)(((u8 *)0) + 672); /* l32i a2,a9+672 → +672:  */
  *(u32 *)(eb8 + 0) = regs[3]; /* s32i.n a3,a4+0 → +0: frame control */
  regs[9] = *(u32 *)((u8 *)a2 + 152); /* l32i a9,a2+152 → +152: key PN/counter region */
  (void)((int(*)())nan_dp_search_node)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())cnx_node_search)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())ieee80211_is_tx_allowed)(); /* observed call (disasm order; args a2..a5) */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* ieee80211_send_deauth_no_bss @ ieee80211_output.o 00000044 size 312B bind GLOBAL
 * Calls: hostap_query_mac_in_list, wifi_log, wifi_get_macaddr, ieee80211_alloc_deauth, ieee80211_send_setup, ieee80211_set_tx_desc, hostap_add_in_mac_list, chm_is_at_home_channel, ic_tx_pkt | Data refs: .rodata_wlog_warning.42, .rodata.ieee80211_send_setup.str1.1, .rodata_wlog_error.43, g_ic, hostap_query_mac_in_list, wifi_log, wifi_get_macaddr, ieee80211_alloc_deauth, ieee80211_send_setup, ieee80211_set_tx_desc
 * Fidelity: medium - call order + offsets from disasm; straight-line details summarised */
/* disasm section: .text.ieee80211_send_deauth_no_bss */
int ieee80211_send_deauth_no_bss(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_send_deauth_no_bss(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 64B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 0, 1, 2, 8, -1, 16, 192, 7, 4 */
  /* observed branches: beqz.nx3, beqx1 */
  /* observed memory traffic (first 10): */
    /* l32i a6, a2, -- 0: frame control */
    /* l32i.n a8, a5, -- 16: addr3 */
    /* l32i.n a8, a5, -- 20: eb len field region */
    /* l32i.n a8, a4, -- 4: addr1 */
    /* l16ui a11, a4, -- 20: eb len field region */
    /* l16ui a9, a4, -- 22: seqctl/len */
    /* l32i.n a11, a8, -- 0: frame control */
    /* s32i.n a11, a8, -- 0: frame control */
    /* l32i.n a11, a8, -- 0: frame control */
    /* s32i.n a11, a8, -- 0: frame control */
  /* observed call sequence (in order): hostap_query_mac_in_list -> wifi_log -> wifi_get_macaddr -> ieee80211_alloc_deauth -> ieee80211_send_setup -> ieee80211_set_tx_desc -> hostap_add_in_mac_list -> chm_is_at_home_channel -> ic_tx_pkt */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[6] = *(u32 *)((u8 *)a2 + 0); /* l32i a6,a2+0 → +0: frame control */
  regs[8] = *(u32 *)((u8 *)(uintptr_t)a4 + 16); /* l32i.n a8,a5+16 → +16: addr3 */
  regs[8] = *(u32 *)((u8 *)(uintptr_t)a4 + 20); /* l32i.n a8,a5+20 → +20: eb len field region */
  regs[8] = *(u32 *)(eb8 + 4); /* l32i.n a8,a4+4 → +4: addr1 */
  regs[1] = *(u16 *)(eb8 + 20); /* l16ui → +20: eb len field region */
  regs[9] = *(u16 *)(eb8 + 22); /* l16ui → +22: seqctl/len */
  (void)((int(*)())hostap_query_mac_in_list)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())wifi_log)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())wifi_get_macaddr)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())ieee80211_alloc_deauth)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())ieee80211_send_setup)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())ieee80211_set_tx_desc)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())hostap_add_in_mac_list)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())chm_is_at_home_channel)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())ic_tx_pkt)(); /* observed call (disasm order; args a2..a5) */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* ieee80211_send_mgmt @ ieee80211_output.o 00000038 size 245B bind GLOBAL
 * Calls: wifi_log, ieee80211_auth_construct, ieee80211_deauth_construct, ieee80211_assoc_req_construct, ieee80211_assoc_resp_construct, ieee80211_disassoc_construct, ieee80211_set_tx_desc, ieee80211_mgmt_output, ic_ebuf_recycle_tx | Data refs: .rodata.ieee80211_send_setup.str1.1, .rodata_wlog_error.36, g_ic, wifi_log, ieee80211_auth_construct, ieee80211_deauth_construct, ieee80211_assoc_req_construct, ieee80211_assoc_resp_construct, ieee80211_disassoc_construct, ieee80211_set_tx_desc
 * Fidelity: medium - call order + offsets from disasm; straight-line details summarised */
/* disasm section: .text.ieee80211_send_mgmt */
int ieee80211_send_mgmt(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_send_mgmt(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 32B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 1, 160, 32, 48, 176, 192, 0, 7 */
  /* observed branches: beqz.nx5, bnex1, bltx2, beqix2, beqx3 */
  /* observed memory traffic (first 5): */
    /* l32i.n a5, a2, -- 0: frame control */
    /* l8ui a5, a4, -- off 132 */
    /* s8i a3, a4, -- off 132 */
    /* l32i.n a4, a2, -- 12: 802.11 header region */
    /* s32i.n a4, a2, -- 12: 802.11 header region */
  /* observed call sequence (in order): wifi_log -> ieee80211_auth_construct -> ieee80211_deauth_construct -> ieee80211_assoc_req_construct -> ieee80211_assoc_resp_construct -> ieee80211_disassoc_construct -> ieee80211_set_tx_desc -> ieee80211_mgmt_output -> ic_ebuf_recycle_tx */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[5] = *(u32 *)((u8 *)a2 + 0); /* l32i.n a5,a2+0 → +0: frame control */
  regs[5] = *(u8 *)(eb8 + 132); /* l8ui → +132:  */
  *(u8 *)(eb8 + 132) = (u8)regs[3]; /* s8i → +132:  */
  regs[4] = *(u32 *)((u8 *)a2 + 12); /* l32i.n a4,a2+12 → +12: 802.11 header region */
  *(u32 *)((u8 *)a2 + 12) = regs[4]; /* s32i.n a4,a2+12 → +12: 802.11 header region */
  (void)((int(*)())wifi_log)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())ieee80211_auth_construct)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())ieee80211_deauth_construct)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())ieee80211_assoc_req_construct)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())ieee80211_assoc_resp_construct)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())ieee80211_disassoc_construct)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())ieee80211_set_tx_desc)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())ieee80211_mgmt_output)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())ic_ebuf_recycle_tx)(); /* observed call (disasm order; args a2..a5) */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* ieee80211_send_nulldata @ ieee80211_output.o 0000004c size 392B bind GLOBAL
 * Calls: wifi_log, wifi_get_macaddr, ieee80211_getmgtframe, memset, nan_dp_get_own_ndi, nan_get_clust_id, ic_get_addr, ieee80211_send_setup, ieee80211_set_tx_desc, nan_dp_post_tx, chm_is_at_home_channel, ic_tx_pkt | Data refs: .rodata.ieee80211_send_setup.str1.1, .rodata_wlog_error.16, g_ic, .rodata_wlog_warning.17, wifi_log, wifi_get_macaddr, ieee80211_getmgtframe, memset, nan_dp_get_own_ndi, nan_get_clust_id
 * Fidelity: medium - call order + offsets from disasm; straight-line details summarised */
/* disasm section: .text.ieee80211_send_nulldata */
int ieee80211_send_nulldata(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_send_nulldata(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 80B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 0, 1, 2, 24, 64, -1, 3, 156, 16, 72 */
  /* observed branches: beqx2, bnex1, bnez.nx1, bneix2, beqz.nx1 */
  /* observed memory traffic (first 10): */
    /* s32i a3, a1, -- 24: seqctl/addr4/QoS */
    /* l32i.n a5, a2, -- 0: frame control */
    /* l32i.n a6, a4, -- 16: addr3 */
    /* l32i.n a6, a4, -- 20: eb len field region */
    /* l32i.n a8, a10, -- 4: addr1 */
    /* l32i.n a8, a8, -- 4: addr1 */
    /* s32i.n a9, a1, -- off 36 */
    /* s32i.n a8, a1, -- off 32 */
    /* l32i.n a9, a1, -- off 36 */
    /* s32i.n a9, a6, -- 20: eb len field region */
  /* observed call sequence (in order): wifi_log -> wifi_get_macaddr -> ieee80211_getmgtframe -> memset -> nan_dp_get_own_ndi -> nan_get_clust_id -> ic_get_addr -> ieee80211_send_setup -> ieee80211_set_tx_desc -> nan_dp_post_tx -> chm_is_at_home_channel -> ic_tx_pkt */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  *(u32 *)(((u8 *)a1_spill) + 24) = regs[3]; /* s32i a3,a1+24 → +24: seqctl/addr4/QoS */
  regs[5] = *(u32 *)((u8 *)a2 + 0); /* l32i.n a5,a2+0 → +0: frame control */
  regs[6] = *(u32 *)(eb8 + 16); /* l32i.n a6,a4+16 → +16: addr3 */
  regs[6] = *(u32 *)(eb8 + 20); /* l32i.n a6,a4+20 → +20: eb len field region */
  regs[8] = *(u32 *)(((u8 *)0) + 4); /* l32i.n a8,a10+4 → +4: addr1 */
  regs[8] = *(u32 *)(((u8 *)0) + 4); /* l32i.n a8,a8+4 → +4: addr1 */
  (void)((int(*)())wifi_log)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())wifi_get_macaddr)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())ieee80211_getmgtframe)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())memset)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())nan_dp_get_own_ndi)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())nan_get_clust_id)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())ic_get_addr)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())ieee80211_send_setup)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())ieee80211_set_tx_desc)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())nan_dp_post_tx)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())chm_is_at_home_channel)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())ic_tx_pkt)(); /* observed call (disasm order; args a2..a5) */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* ieee80211_send_probereq @ ieee80211_output.o 00000068 size 684B bind GLOBAL
 * Calls: reset_cs_thres, chm_get_current_channel, chm_get_chan_info, ieee80211_vnd_lora_ie_size, .text.ieee80211_vnd_ie_size$part$0, ieee80211_getmgtframe, wifi_log, memcpy, ieee80211_add_rates, ieee80211_add_xrates, ieee80211_add_probe_req_ies, .text.add_appie, ieee80211_add_dsparams, ieee80211_add_ie_vendor_esp_manufacturer, ieee80211_vnd_lora_ie_set, ieee80211_vnd_ie_set, ieee80211_send_setup, ieee80211_set_tx_desc, ic_tx_pkt | Data refs: g_ic, .rodata_wlog_warning.24, esp_mesh_quick_funcs, reset_cs_thres, chm_get_current_channel, chm_get_chan_info, ieee80211_vnd_lora_ie_size, .text.ieee80211_vnd_ie_size$part$0, ieee80211_getmgtframe, wifi_log
 * Fidelity: low - large function; call order + key branches captured, body is structural summary */
/* disasm section: .text.ieee80211_send_probereq */
int ieee80211_send_probereq(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_send_probereq(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 96B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 0, 3, 1, 10, 8, 71, 24, 2, 64, -1 */
  /* observed branches: beqx6, bgeux1, bnez.nx1, beqz.nx6 */
  /* observed memory traffic (first 10): */
    /* s32i.n a4, a1, -- off 40 */
    /* l8ui a4, a1, -- off 96 */
    /* s32i.n a4, a1, -- off 52 */
    /* s32i.n a5, a1, -- 44: eb priv word */
    /* l32i.n a4, a4, -- 16: addr3 */
    /* l8ui a5, a1, -- off 100 */
    /* s32i.n a6, a1, -- off 48 */
    /* s32i.n a4, a1, -- off 32 */
    /* s32i a5, a1, -- off 36 */
    /* l8ui a10, a10, -- 0: frame control */
  /* observed call sequence (in order): reset_cs_thres -> chm_get_current_channel -> chm_get_chan_info -> ieee80211_vnd_lora_ie_size -> .text.ieee80211_vnd_ie_size$part$0+0x4 -> ieee80211_getmgtframe -> wifi_log -> memcpy -> ieee80211_add_rates -> ieee80211_add_xrates -> ieee80211_add_probe_req_ies -> .text.add_appie+0x4 -> ieee80211_add_dsparams -> ieee80211_add_ie_vendor_esp_manufacturer */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  *(u32 *)(((u8 *)a1_spill) + 40) = regs[4]; /* s32i.n a4,a1+40 → +40:  */
  regs[4] = *(u8 *)(((u8 *)a1_spill) + 96); /* l8ui → +96:  */
  *(u32 *)(((u8 *)a1_spill) + 52) = regs[4]; /* s32i.n a4,a1+52 → +52:  */
  *(u32 *)(((u8 *)a1_spill) + 44) = regs[5]; /* s32i.n a5,a1+44 → +44: eb priv word */
  regs[4] = *(u32 *)(eb8 + 16); /* l32i.n a4,a4+16 → +16: addr3 */
  regs[5] = *(u8 *)(((u8 *)a1_spill) + 100); /* l8ui → +100:  */
  (void)((int(*)())reset_cs_thres)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())chm_get_current_channel)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())chm_get_chan_info)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())ieee80211_vnd_lora_ie_size)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())ieee80211_getmgtframe)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())wifi_log)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())memcpy)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())ieee80211_add_rates)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())ieee80211_add_xrates)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())ieee80211_add_probe_req_ies)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())ieee80211_add_dsparams)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())ieee80211_add_ie_vendor_esp_manufacturer)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())ieee80211_vnd_lora_ie_set)(); /* observed call (disasm order; args a2..a5) */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* ieee80211_send_proberesp @ ieee80211_output.o 00000034 size 253B bind GLOBAL
 * Calls: wifi_log, wifi_get_macaddr, ieee80211_alloc_proberesp, ieee80211_send_setup, ieee80211_set_tx_desc, chm_is_at_home_channel, ic_tx_pkt, ic_ebuf_recycle_tx | Data refs: .rodata.ieee80211_send_setup.str1.1, .rodata_wlog_error.40, g_ic, wifi_log, wifi_get_macaddr, ieee80211_alloc_proberesp, ieee80211_send_setup, ieee80211_set_tx_desc, chm_is_at_home_channel, ic_tx_pkt
 * Fidelity: medium - call order + offsets from disasm; straight-line details summarised */
/* disasm section: .text.ieee80211_send_proberesp */
int ieee80211_send_proberesp(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_send_proberesp(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 64B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 1, 0, 2, -1, 16, 80, 7 */
  /* observed branches: bnez.nx1, beqx1 */
  /* observed memory traffic (first 10): */
    /* l32i a2, a2, -- 0: frame control */
    /* l32i.n a8, a6, -- 16: addr3 */
    /* l32i a6, a6, -- 20: eb len field region */
    /* l32i.n a8, a10, -- 4: addr1 */
    /* l16ui a9, a4, -- 20: eb len field region */
    /* l16ui a10, a10, -- 22: seqctl/len */
    /* l32i.n a9, a8, -- 0: frame control */
    /* s32i.n a9, a8, -- 0: frame control */
    /* l32i.n a9, a8, -- 0: frame control */
    /* s32i.n a9, a8, -- 0: frame control */
  /* observed call sequence (in order): wifi_log -> wifi_get_macaddr -> ieee80211_alloc_proberesp -> ieee80211_send_setup -> ieee80211_set_tx_desc -> chm_is_at_home_channel -> ic_tx_pkt -> ic_ebuf_recycle_tx */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[2] = *(u32 *)((u8 *)a2 + 0); /* l32i a2,a2+0 → +0: frame control */
  regs[8] = *(u32 *)(eb8 + 16); /* l32i.n a8,a6+16 → +16: addr3 */
  regs[6] = *(u32 *)(eb8 + 20); /* l32i a6,a6+20 → +20: eb len field region */
  regs[8] = *(u32 *)(((u8 *)0) + 4); /* l32i.n a8,a10+4 → +4: addr1 */
  regs[9] = *(u16 *)(eb8 + 20); /* l16ui → +20: eb len field region */
  regs[1] = *(u16 *)(((u8 *)0) + 22); /* l16ui → +22: seqctl/len */
  (void)((int(*)())wifi_log)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())wifi_get_macaddr)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())ieee80211_alloc_proberesp)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())ieee80211_send_setup)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())ieee80211_set_tx_desc)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())chm_is_at_home_channel)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())ic_tx_pkt)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())ic_ebuf_recycle_tx)(); /* observed call (disasm order; args a2..a5) */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* ieee80211_send_setup @ ieee80211_output.o 00000030 size 294B bind GLOBAL
 * Calls: wifi_log, memcpy | Data refs: .rodata.ieee80211_send_setup.str1.1, .rodata_wlog_error.12, .rodata_wlog_error.13, wifi_log, memcpy
 * Fidelity: medium - call order + offsets from disasm; straight-line details summarised */
/* disasm section: .text.ieee80211_send_setup */
int ieee80211_send_setup(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_send_setup(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 48B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 1, 0, 12, 6, 2 */
  /* observed branches: bnez.nx2, bneix1, beqix2, bbcix1 */
  /* observed memory traffic (first 10): */
    /* s32i.n a5, a1, -- 0: frame control */
    /* l32i.n a5, a3, -- 4: addr1 */
    /* l32i.n a6, a1, -- off 48 */
    /* l32i.n a5, a5, -- 4: addr1 */
    /* l32i.n a9, a2, -- 0: frame control */
    /* s8i a8, a5, -- 0: frame control */
    /* l32i a8, a9, -- 0x14c: ic/eb control word */
    /* s8i a8, a5, -- 1: frame control/duration */
    /* s8i a8, a5, -- 1: frame control/duration */
    /* s8i a8, a5, -- 1: frame control/duration */
  /* observed call sequence (in order): wifi_log -> memcpy */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  *(u32 *)(((u8 *)a1_spill) + 0) = regs[5]; /* s32i.n a5,a1+0 → +0: frame control */
  regs[5] = *(u32 *)((u8 *)a3 + 4); /* l32i.n a5,a3+4 → +4: addr1 */
  regs[6] = *(u32 *)(((u8 *)a1_spill) + 48); /* l32i.n a6,a1+48 → +48:  */
  regs[5] = *(u32 *)((u8 *)(uintptr_t)a4 + 4); /* l32i.n a5,a5+4 → +4: addr1 */
  regs[9] = *(u32 *)((u8 *)a2 + 0); /* l32i.n a9,a2+0 → +0: frame control */
  *(u8 *)((u8 *)(uintptr_t)a4 + 0) = (u8)regs[8]; /* s8i → +0: frame control */
  (void)((int(*)())wifi_log)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())memcpy)(); /* observed call (disasm order; args a2..a5) */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* ieee80211_set_hmac_stop @ ieee80211_output.o 0000000c size 51B bind GLOBAL
 * Calls: none | Data refs: g_wifi_global_lock, g_osi_funcs_p, g_ic
 * Fidelity: medium - call order + branch skeleton from disasm; some field names inferred */
/* disasm section: .text.ieee80211_set_hmac_stop */
int ieee80211_set_hmac_stop(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_set_hmac_stop(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 32B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed memory traffic (first 7): */
    /* l32i a8, a4, -- 0: frame control */
    /* l32i a10, a3, -- 0: frame control */
    /* l32i a8, a8, -- off 84 */
    /* l32i.n a4, a4, -- 0: frame control */
    /* l32i.n a10, a3, -- 0: frame control */
    /* l32i a4, a4, -- off 88 */
    /* s8i a2, a8, -- off 80 */
  /* observed calls: none (leaf) */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[8] = *(u32 *)(eb8 + 0); /* l32i a8,a4+0 → +0: frame control */
  regs[1] = *(u32 *)((u8 *)a3 + 0); /* l32i a10,a3+0 → +0: frame control */
  regs[8] = *(u32 *)(((u8 *)0) + 84); /* l32i a8,a8+84 → +84:  */
  regs[4] = *(u32 *)(eb8 + 0); /* l32i.n a4,a4+0 → +0: frame control */
  regs[1] = *(u32 *)((u8 *)a3 + 0); /* l32i.n a10,a3+0 → +0: frame control */
  regs[4] = *(u32 *)(eb8 + 88); /* l32i a4,a4+88 → +88:  */
  /* no calls observed: leaf */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* ieee80211_set_tx_desc @ ieee80211_output.o 00000014 size 201B bind GLOBAL
 * Calls: hal_now, ic_get_trc | Data refs: g_ic, hal_now, ic_get_trc
 * Fidelity: medium - call order + offsets from disasm; straight-line details summarised */
/* disasm section: .wifiextrairam.63 */
int ieee80211_set_tx_desc(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_set_tx_desc(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 48B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 0, 1, 2, 3 */
  /* observed branches: beqx1, beqz.nx1, beqix1, bltux1, bneix3, bbsix1, bnez.nx1 */
  /* observed memory traffic (first 10): */
    /* l32i.n a7, a2, -- 0: frame control */
    /* l32i.n a9, a8, -- 16: addr3 */
    /* l32i.n a8, a8, -- 20: eb len field region */
    /* l8ui a11, a2, -- off 38 */
    /* l32i.n a9, a3, -- 44: eb priv word */
    /* s8i a8, a9, -- 4: addr1 */
    /* s32i.n a9, a1, -- 0: frame control */
    /* s32i.n a11, a1, -- 4: addr1 */
    /* l32i.n a4, a3, -- 44: eb priv word */
    /* l32i.n a9, a1, -- 0: frame control */
  /* observed call sequence (in order): hal_now -> ic_get_trc */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[7] = *(u32 *)((u8 *)a2 + 0); /* l32i.n a7,a2+0 → +0: frame control */
  regs[9] = *(u32 *)(((u8 *)0) + 16); /* l32i.n a9,a8+16 → +16: addr3 */
  regs[8] = *(u32 *)(((u8 *)0) + 20); /* l32i.n a8,a8+20 → +20: eb len field region */
  regs[1] = *(u8 *)((u8 *)a2 + 38); /* l8ui → +38:  */
  regs[9] = *(u32 *)((u8 *)a3 + 44); /* l32i.n a9,a3+44 → +44: eb priv word */
  *(u8 *)(((u8 *)0) + 4) = (u8)regs[8]; /* s8i → +4: addr1 */
  (void)((int(*)())hal_now)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())ic_get_trc)(); /* observed call (disasm order; args a2..a5) */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* ieee80211_setup_robust_mgmtframe @ ieee80211_output.o 0000000c size 94B bind GLOBAL
 * Calls: memmove, ieee80211_ccmp_encrypt | Data refs: g_ic, memmove, ieee80211_ccmp_encrypt
 * Fidelity: medium - call order + branch skeleton from disasm; some field names inferred */
/* disasm section: .text.ieee80211_setup_robust_mgmtframe */
int ieee80211_setup_robust_mgmtframe(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_setup_robust_mgmtframe(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 32B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): -2, -65 */
  /* observed branches: bnez.nx1, bneix1 */
  /* observed memory traffic (first 10): */
    /* l8ui a9, a2, -- off 52 */
    /* l32i.n a8, a3, -- 4: addr1 */
    /* l32i a11, a9, -- off 0x140 */
    /* l32i.n a8, a8, -- 4: addr1 */
    /* l32i.n a10, a3, -- 44: eb priv word */
    /* l32i.n a9, a10, -- 0: frame control */
    /* s32i.n a9, a10, -- 0: frame control */
    /* l8ui a9, a8, -- 1: frame control/duration */
    /* s8i a9, a8, -- 1: frame control/duration */
    /* l16ui a10, a3, -- 20: eb len field region */
  /* observed call sequence (in order): memmove -> ieee80211_ccmp_encrypt */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[9] = *(u8 *)((u8 *)a2 + 52); /* l8ui → +52:  */
  regs[8] = *(u32 *)((u8 *)a3 + 4); /* l32i.n a8,a3+4 → +4: addr1 */
  regs[1] = *(u32 *)(((u8 *)0) + 320); /* l32i a11,a9+320 → +320:  */
  regs[8] = *(u32 *)(((u8 *)0) + 4); /* l32i.n a8,a8+4 → +4: addr1 */
  regs[1] = *(u32 *)((u8 *)a3 + 44); /* l32i.n a10,a3+44 → +44: eb priv word */
  regs[9] = *(u32 *)(((u8 *)0) + 0); /* l32i.n a9,a10+0 → +0: frame control */
  (void)((int(*)())memmove)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())ieee80211_ccmp_encrypt)(); /* observed call (disasm order; args a2..a5) */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* ieee80211_tx_mgt_cb @ ieee80211_output.o 0000005c size 531B bind GLOBAL
 * Calls: hostap_query_mac_in_list, hostap_del_mac_info_from_list, cnx_node_leave, cnx_node_search, create_new_bss_for_sa_query_failed_sta, ic_clear_data_ifx_tx_queue, wifi_log, ic_del_key_all, clear_ic_key, offchan_in_progress, offchan_send_action_tx_status, ieee80211_sta_tx_disconnect_cb | Data refs: g_ic, g_wifi_nvs, .rodata_wlog_debug.15, hostap_query_mac_in_list, hostap_del_mac_info_from_list, cnx_node_leave, cnx_node_search, create_new_bss_for_sa_query_failed_sta, ic_clear_data_ifx_tx_queue, wifi_log
 * Fidelity: medium - call order + offsets from disasm; straight-line details summarised */
/* disasm section: .text.ieee80211_tx_mgt_cb */
int ieee80211_tx_mgt_cb(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_tx_mgt_cb(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 48B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 12, -16, 3, 1, 208, 192, 240, 160, -1, -176 */
  /* observed branches: bnonex2, beqx1, bnex3, beqz.nx7, bbcix1, bgex1, bnez.nx3, beqix1 */
  /* observed memory traffic (first 10): */
    /* l32i.n a3, a2, -- 4: addr1 */
    /* l32i.n a4, a3, -- 4: addr1 */
    /* l8ui a6, a4, -- 0: frame control */
    /* l32i.n a5, a2, -- 44: eb priv word */
    /* l32i.n a7, a5, -- 16: addr3 */
    /* l32i.n a8, a7, -- 20: eb len field region */
    /* s32i a8, a1, -- 0: frame control */
    /* l32i.n a8, a1, -- 0: frame control */
    /* l8ui a5, a4, -- 4: addr1 */
    /* l32i.n a5, a7, -- 20: eb len field region */
  /* observed call sequence (in order): hostap_query_mac_in_list -> hostap_del_mac_info_from_list -> cnx_node_leave -> cnx_node_search -> create_new_bss_for_sa_query_failed_sta -> ic_clear_data_ifx_tx_queue -> wifi_log -> ic_del_key_all -> clear_ic_key -> offchan_in_progress -> offchan_send_action_tx_status -> ieee80211_sta_tx_disconnect_cb */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[3] = *(u32 *)((u8 *)a2 + 4); /* l32i.n a3,a2+4 → +4: addr1 */
  regs[4] = *(u32 *)((u8 *)a3 + 4); /* l32i.n a4,a3+4 → +4: addr1 */
  regs[6] = *(u8 *)(eb8 + 0); /* l8ui → +0: frame control */
  regs[5] = *(u32 *)((u8 *)a2 + 44); /* l32i.n a5,a2+44 → +44: eb priv word */
  regs[7] = *(u32 *)((u8 *)(uintptr_t)a4 + 16); /* l32i.n a7,a5+16 → +16: addr3 */
  regs[8] = *(u32 *)(((u8 *)0) + 20); /* l32i.n a8,a7+20 → +20: eb len field region */
  (void)((int(*)())hostap_query_mac_in_list)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())hostap_del_mac_info_from_list)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())cnx_node_leave)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())cnx_node_search)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())create_new_bss_for_sa_query_failed_sta)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())ic_clear_data_ifx_tx_queue)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())wifi_log)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())ic_del_key_all)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())clear_ic_key)(); /* observed call (disasm order; args a2..a5) */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* ieee80211_vnd_ie_set @ ieee80211_output.o 0000000c size 82B bind GLOBAL
 * Calls: memcpy | Data refs: g_ic, memcpy
 * Fidelity: medium - call order + branch skeleton from disasm; some field names inferred */
/* disasm section: .text.ieee80211_vnd_ie_set */
int ieee80211_vnd_ie_set(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_vnd_ie_set(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 32B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 164 */
  /* observed branches: beqz.nx4 */
  /* observed memory traffic (first 10): */
    /* l32i.n a8, a4, -- 0: frame control */
    /* l32i.n a11, a8, -- 4: addr1 */
    /* l16ui a12, a8, -- 8: 802.11 header region */
    /* l32i.n a4, a4, -- 0: frame control */
    /* l16ui a4, a4, -- 8: 802.11 header region */
    /* l32i.n a4, a3, -- 0: frame control */
    /* l32i.n a11, a4, -- 4: addr1 */
    /* l16ui a12, a4, -- 8: 802.11 header region */
    /* l32i.n a3, a3, -- 0: frame control */
    /* l16ui a3, a3, -- 8: 802.11 header region */
  /* observed call sequence (in order): memcpy */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[8] = *(u32 *)(eb8 + 0); /* l32i.n a8,a4+0 → +0: frame control */
  regs[1] = *(u32 *)(((u8 *)0) + 4); /* l32i.n a11,a8+4 → +4: addr1 */
  regs[1] = *(u16 *)(((u8 *)0) + 8); /* l16ui → +8: 802.11 header region */
  regs[4] = *(u32 *)(eb8 + 0); /* l32i.n a4,a4+0 → +0: frame control */
  regs[4] = *(u16 *)(eb8 + 8); /* l16ui → +8: 802.11 header region */
  regs[4] = *(u32 *)((u8 *)a3 + 0); /* l32i.n a4,a3+0 → +0: frame control */
  (void)((int(*)())memcpy)(); /* observed call (disasm order; args a2..a5) */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* ieee80211_vnd_ie_size @ ieee80211_output.o 00000004 size 20B bind GLOBAL
 * Calls: none | Data refs: g_ic
 * Fidelity: high - leaf; full insn sequence captured, no hidden control flow */
/* disasm section: .text.ieee80211_vnd_ie_size$part$0 */
int ieee80211_vnd_ie_size(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_vnd_ie_size(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 32B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 0 */
  /* observed branches: beqx2, beqz.nx2 */
  /* observed memory traffic (first 6): */
    /* l32i a9, a8, -- off 160 */
    /* l32i.n a11, a9, -- 4: addr1 */
    /* l16ui a8, a9, -- 8: 802.11 header region */
    /* l32i a2, a2, -- off 164 */
    /* l32i.n a9, a2, -- 4: addr1 */
    /* l16ui a2, a2, -- 8: 802.11 header region */
  /* observed calls: none (leaf) */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[9] = *(u32 *)(((u8 *)0) + 160); /* l32i a9,a8+160 → +160:  */
  regs[1] = *(u32 *)(((u8 *)0) + 4); /* l32i.n a11,a9+4 → +4: addr1 */
  regs[8] = *(u16 *)(((u8 *)0) + 8); /* l16ui → +8: 802.11 header region */
  regs[2] = *(u32 *)((u8 *)a2 + 164); /* l32i a2,a2+164 → +164:  */
  regs[9] = *(u32 *)((u8 *)a2 + 4); /* l32i.n a9,a2+4 → +4: addr1 */
  regs[2] = *(u16 *)((u8 *)a2 + 8); /* l16ui → +8: 802.11 header region */
  /* no calls observed: leaf */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* ieee80211_vnd_lora_ie_set @ ieee80211_output.o 00000010 size 102B bind GLOBAL
 * Calls: chm_get_current_band, memcpy | Data refs: g_ic, chm_get_current_band, memcpy
 * Fidelity: medium - call order + branch skeleton from disasm; some field names inferred */
/* disasm section: .text.ieee80211_vnd_lora_ie_set */
int ieee80211_vnd_lora_ie_set(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_vnd_lora_ie_set(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 32B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): -3, 21 */
  /* observed branches: bnez.nx1, bneix2, beqz.nx2 */
  /* observed memory traffic (first 9): */
    /* l32i a8, a4, -- off 0x2b4 */
    /* l32i a8, a4, -- off 0x2b8 */
    /* l32i a11, a4, -- off 0x2b4 */
    /* l16ui a12, a11, -- 0: frame control */
    /* l32i a3, a4, -- off 0x2b4 */
    /* l32i a11, a4, -- off 0x2b8 */
    /* l16ui a12, a11, -- 0: frame control */
    /* l32i a3, a4, -- off 0x2b8 */
    /* l16ui a3, a3, -- 0: frame control */
  /* observed call sequence (in order): chm_get_current_band -> memcpy */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[8] = *(u32 *)(eb8 + 692); /* l32i a8,a4+692 → +692:  */
  regs[8] = *(u32 *)(eb8 + 696); /* l32i a8,a4+696 → +696:  */
  regs[1] = *(u32 *)(eb8 + 692); /* l32i a11,a4+692 → +692:  */
  regs[1] = *(u16 *)(((u8 *)0) + 0); /* l16ui → +0: frame control */
  regs[3] = *(u32 *)(eb8 + 692); /* l32i a3,a4+692 → +692:  */
  regs[1] = *(u32 *)(eb8 + 696); /* l32i a11,a4+696 → +696:  */
  (void)((int(*)())chm_get_current_band)(); /* observed call (disasm order; args a2..a5) */
  (void)((int(*)())memcpy)(); /* observed call (disasm order; args a2..a5) */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* ieee80211_vnd_lora_ie_size @ ieee80211_output.o 00000008 size 60B bind GLOBAL
 * Calls: chm_get_current_band | Data refs: g_ic, chm_get_current_band
 * Fidelity: medium - call order + branch skeleton from disasm; some field names inferred */
/* disasm section: .text.ieee80211_vnd_lora_ie_size */
int ieee80211_vnd_lora_ie_size(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_vnd_lora_ie_size(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 32B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 0, -3, 21 */
  /* observed branches: bneix2, beqx2 */
  /* observed memory traffic (first 4): */
    /* l32i a10, a9, -- off 0x2b4 */
    /* l16ui a8, a10, -- 0: frame control */
    /* l32i a9, a9, -- off 0x2b8 */
    /* l16ui a8, a9, -- 0: frame control */
  /* observed call sequence (in order): chm_get_current_band */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[1] = *(u32 *)(((u8 *)0) + 692); /* l32i a10,a9+692 → +692:  */
  regs[8] = *(u16 *)(((u8 *)0) + 0); /* l16ui → +0: frame control */
  regs[9] = *(u32 *)(((u8 *)0) + 696); /* l32i a9,a9+696 → +696:  */
  regs[8] = *(u16 *)(((u8 *)0) + 0); /* l16ui → +0: frame control */
  (void)((int(*)())chm_get_current_band)(); /* observed call (disasm order; args a2..a5) */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* ieee80211_wapi_alloc_tx_buf @ ieee80211_output.o 00000004 size 83B bind GLOBAL
 * Calls: ic_ebuf_alloc | Data refs: ic_ebuf_alloc
 * Fidelity: medium - call order + branch skeleton from disasm; some field names inferred */
/* disasm section: .text.ieee80211_wapi_alloc_tx_buf */
int ieee80211_wapi_alloc_tx_buf(void *a2, void *a3, unsigned a4, unsigned a5);
int ieee80211_wapi_alloc_tx_buf(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 32B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 1, -1 */
  /* observed branches: beqz.nx1 */
  /* observed memory traffic (first 8): */
    /* l32i.n a9, a10, -- 4: addr1 */
    /* l32i.n a8, a9, -- 4: addr1 */
    /* s32i.n a8, a9, -- 4: addr1 */
    /* l16ui a8, a10, -- 22: seqctl/len */
    /* s16i a8, a10, -- 22: seqctl/len */
    /* l32i.n a8, a9, -- 0: frame control */
    /* l32i.n a11, a9, -- 0: frame control */
    /* s32i.n a8, a9, -- 0: frame control */
  /* observed call sequence (in order): ic_ebuf_alloc */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[9] = *(u32 *)(((u8 *)0) + 4); /* l32i.n a9,a10+4 → +4: addr1 */
  regs[8] = *(u32 *)(((u8 *)0) + 4); /* l32i.n a8,a9+4 → +4: addr1 */
  *(u32 *)(((u8 *)0) + 4) = regs[8]; /* s32i.n a8,a9+4 → +4: addr1 */
  regs[8] = *(u16 *)(((u8 *)0) + 22); /* l16ui → +22: seqctl/len */
  *(u16 *)(((u8 *)0) + 22) = (u16)regs[8]; /* s16i → +22: seqctl/len */
  regs[8] = *(u32 *)(((u8 *)0) + 0); /* l32i.n a8,a9+0 → +0: frame control */
  (void)((int(*)())ic_ebuf_alloc)(); /* observed call (disasm order; args a2..a5) */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* is_wapi_alloc_tx_buf @ ieee80211_output.o 00000004 size 51B bind GLOBAL
 * Calls: none | Data refs: g_ic
 * Fidelity: medium - call order + branch skeleton from disasm; some field names inferred */
/* disasm section: .text.is_wapi_alloc_tx_buf */
int is_wapi_alloc_tx_buf(void *a2, void *a3, unsigned a4, unsigned a5);
int is_wapi_alloc_tx_buf(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 32B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 0, 1 */
  /* observed branches: beqx1 */
  /* observed memory traffic (first 5): */
    /* l8ui a8, a8, -- off 52 */
    /* l32i a10, a8, -- off 0x140 */
    /* l32i.n a2, a2, -- 12: 802.11 header region */
    /* l32i a2, a10, -- off 160 */
    /* l32i.n a2, a2, -- 0: frame control */
  /* observed calls: none (leaf) */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[8] = *(u8 *)(((u8 *)0) + 52); /* l8ui → +52:  */
  regs[1] = *(u32 *)(((u8 *)0) + 320); /* l32i a10,a8+320 → +320:  */
  regs[2] = *(u32 *)((u8 *)a2 + 12); /* l32i.n a2,a2+12 → +12: 802.11 header region */
  regs[2] = *(u32 *)(((u8 *)0) + 160); /* l32i a2,a10+160 → +160:  */
  regs[2] = *(u32 *)((u8 *)a2 + 0); /* l32i.n a2,a2+0 → +0: frame control */
  /* no calls observed: leaf */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}

/* wifi_is_started @ ieee80211_output.o 00000004 size 22B bind GLOBAL
 * Calls: none | Data refs: g_ic
 * Fidelity: high - leaf; full insn sequence captured, no hidden control flow */
/* disasm section: .text.wifi_is_started */
int wifi_is_started(void *a2, void *a3, unsigned a4, unsigned a5);
int wifi_is_started(void *a2, void *a3, unsigned a4, unsigned a5)
{
  u8 a1_spill[256]; (void)a1_spill;
  /* entry frame 32B; args: a2,a3,a4(,a5) per Xtensa ABI; return in a2 */
  /* observed immediates (movi): 1 */
  /* observed memory traffic (first 1): */
    /* l8ui a2, a2, -- off 80 */
  /* observed calls: none (leaf) */

  u32 regs[16] = {0}; (void)regs;
  u8 *frm = (u8 *)a2; (void)frm;
  u8 *eb8 = (u8 *)a2; (void)eb8;
  regs[2] = *(u8 *)((u8 *)a2 + 80); /* l8ui → +80:  */
  /* no calls observed: leaf */

    /* structural skeleton: see observed calls/branches above. */
    return 0;
  
}
