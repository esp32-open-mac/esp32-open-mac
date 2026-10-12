/* ieee80211_supplicant.c - reconstructed from ieee80211_supplicant.o (94684 bytes on disk).
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

extern int chm_get_band_from_chan();  /* external, prototype unknown */
extern int cipher_type_map_public_to_internal();  /* external, prototype unknown */
extern int cnx_auth_done();  /* external, prototype unknown */
extern int cnx_do_handoff_internal();  /* external, prototype unknown */
extern int cnx_node_search();  /* external, prototype unknown */
extern int cnx_rc_search();  /* external, prototype unknown */
extern int esp_mesh_map_deauth();  /* external, prototype unknown */
extern int esp_wifi_get_band_mode();  /* external, prototype unknown */
extern int esp_wifi_get_country_code();  /* external, prototype unknown */
extern int esp_wifi_ipc_internal();  /* external, prototype unknown */
extern int get_channel_max_bandwidth();  /* external, prototype unknown */
extern int ic_del_key();  /* external, prototype unknown */
extern int ic_del_ptk_and_gtk_alg();  /* external, prototype unknown */
extern int ic_get_key();  /* external, prototype unknown */
extern int ic_register_tx_cb();  /* external, prototype unknown */
extern int ic_set_bssid();  /* external, prototype unknown */
extern int ic_set_key();  /* external, prototype unknown */
extern int ic_set_mac();  /* external, prototype unknown */
extern int ic_set_rx_policy();  /* external, prototype unknown */
extern int ic_set_rx_policy_ubssid_check();  /* external, prototype unknown */
extern int ieee80211_get_regdomain();  /* external, prototype unknown */
extern int ieee80211_ioctl();  /* external, prototype unknown */
extern int ieee80211_regdomain_chan_in_range();  /* external, prototype unknown */
extern int ieee80211_sta_new_state();  /* external, prototype unknown */
extern int nan_get_clust_id();  /* external, prototype unknown */
extern int nan_set_nm_tk_key();  /* external, prototype unknown */
extern int net80211_printf();  /* external, prototype unknown */
extern int ppClearRxFragment();  /* external, prototype unknown */
extern int wifi_event_post();  /* external, prototype unknown */
extern int wifi_get_macaddr();  /* external, prototype unknown */
extern int wifi_init_completed();  /* external, prototype unknown */
extern int wifi_log();  /* external, prototype unknown */
extern int wifi_nvs_commit();  /* external, prototype unknown */
extern int wifi_nvs_set();  /* external, prototype unknown */
extern int wifi_set_wps_start_flag();  /* external, prototype unknown */
extern int wifi_sta_reg_eapol_txdone_cb();  /* external, prototype unknown */

int wifi_sta_connect_internal_process(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
static int esp_wifi_get_sta_hw_key_idx_internal(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int esp_wifi_ap_get_prof_pmk_internal(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int esp_wifi_sta_get_prof_pmk_internal(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int esp_wifi_sta_update_ap_info_internal(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int esp_wifi_sta_get_ap_info_prof_pmk_internal(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int esp_wifi_ap_get_prof_ap_ssid_internal(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int esp_wifi_sta_get_prof_ssid_internal(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int esp_wifi_ap_get_prof_authmode_internal(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int esp_wifi_ap_get_max_sta_conn(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int esp_wifi_ap_get_prof_pairwise_cipher_internal(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int esp_wifi_ap_get_owe_config_internal(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int esp_wifi_ap_get_sae_ext_config_internal(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int esp_wifi_ap_get_gtk_rekeying_config_internal(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int esp_wifi_sta_get_prof_authmode_internal(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int esp_wifi_get_pmf_config_internal(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int esp_wifi_get_config_sae_pwe_h2e_internal(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int esp_wifi_sta_get_ie(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int esp_wifi_sta_disable_wpa2_authmode_internal(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int esp_wifi_sta_get_config_sae_pk_internal(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int esp_wifi_sta_disable_sae_pk_internal(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int esp_wifi_enable_sae_pk_only_mode_internal(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int esp_wifi_sta_disable_owe_trans_internal(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int esp_wifi_sta_notify_dpp_config_set_internal(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int esp_wifi_ap_notify_node_sae_auth_done(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int esp_wifi_ap_is_sta_sae_reauth_node(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int esp_wifi_sta_get_sae_identifier_internal(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int esp_wifi_sta_is_ap_notify_completed_rsne_internal(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int esp_wifi_ap_get_prof_password_internal(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int wifi_sta_get_prof_password(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int wifi_ap_pmf_enabled(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int esp_wifi_sta_get_prof_password_internal(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int esp_wifi_sta_get_reset_nvs_pmk_internal(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int esp_wifi_sta_set_reset_nvs_pmk_internal(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int esp_wifi_sta_prof_is_wpa_internal(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int esp_wifi_sta_prof_is_wpa2_internal(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int esp_wifi_sta_prof_is_wapi_internal(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int esp_wifi_sta_prof_is_rsn_internal(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int esp_wifi_sta_get_pairwise_cipher_internal(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int esp_wifi_sta_get_group_cipher_internal(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int ieee80211_get_key(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int ieee80211_set_key(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int ieee80211_get_sta_gtk_index(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int ieee80211_set_sta_gtk_index(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int ieee80211_set_gtk(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int ieee80211_get_ptk(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int ieee80211_get_spp(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int esp_wifi_wpa_ptk_init_done_internal(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int esp_wifi_enable_sta_privacy_internal(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int esp_wifi_sta_is_running_internal(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int esp_wifi_auth_done_internal(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int esp_wifi_unregister_wpa2_cb_internal(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int esp_wifi_register_wpa2_cb_internal(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int ieee80211_unregister_wapi_cb(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int ieee80211_register_wapi_cb(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int esp_wifi_unregister_wpa_cb_internal(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int esp_wifi_register_wpa_cb_internal(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int esp_wifi_get_assoc_bssid_internal(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int ieee80211_sta_is_connected(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int esp_wifi_get_hostap_private_internal(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int esp_wifi_deauthenticate_internal(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int esp_wifi_get_spp_attrubute_internal(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int esp_wifi_get_user_init_flag_internal(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int wifi_set_rx_policy(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int ieee80211_espnow_get_init_flag(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int ieee80211_espnow_set_init_flag(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int ieee80211_mt_key_is_mask(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int ieee80211_mt_key_is_mask_zero(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int ieee80211_mt_key_set_mask(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int ieee80211_mt_key_clear_mask(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int ieee80211_get_mac_addr_from_frame(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int clear_ic_key(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int esp_wifi_del_key_internal(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int esp_wifi_set_key_internal(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int esp_wifi_get_key_internal(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int esp_wifi_register_tx_cb_internal(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int esp_wifi_register_eapol_txdonecb_internal(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int esp_wifi_get_macaddr_internal(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int esp_wifi_ap_deauth_internal(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int wifi_init_key(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int esp_wifi_set_ap_key_internal(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int ppInstallKey(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int esp_wifi_set_sta_key_internal(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int esp_wifi_get_sta_key_internal(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int esp_wifi_get_appie_internal(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int esp_wifi_set_appie_internal(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int esp_wifi_unset_appie_internal(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int esp_wifi_sta_wpa2_ent_enable_internal(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int esp_wifi_sta_wpa2_ent_disable_internal(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int esp_wifi_set_wpa2_ent_state_internal(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int esp_wifi_set_wps_type_internal(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int esp_wifi_get_wps_type_internal(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int esp_wifi_get_wps_status_internal(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int esp_wifi_disarm_sta_connection_timer_internal(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int esp_wifi_set_wps_status_internal(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int esp_wifi_set_wps_cb_internal(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int esp_wifi_internal_supplicant_header_md5_check(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int esp_wifi_set_wps_start_flag_internal(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int esp_wifi_sta_pmf_enabled(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int esp_wifi_sta_get_mgmt_group_cipher(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int esp_wifi_set_igtk_internal(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int ieee80211w_get_active_igtk_key_id(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int ieee80211w_get_igtk_from_keyidx(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int ieee80211w_get_active_bigtk_key_id(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int ieee80211w_get_bigtk_from_keyidx(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_get_peer_igtk(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_get_peer_bigtk(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_clear_peer_integrity_keys(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int esp_wifi_set_nan_key_internal(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int nan_clear_all_integrity_keys(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int esp_wifi_use_supp_pmk_cache(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int esp_wifi_set_rssi_threshold(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int esp_wifi_is_rm_enabled_internal(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int esp_wifi_is_btm_enabled_internal(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int esp_wifi_is_mbo_enabled_internal(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int esp_wifi_is_ft_enabled_internal(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int esp_wifi_register_mgmt_frame_internal(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int esp_wifi_send_mgmt_frm_internal(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int esp_wifi_action_tx_req(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int esp_wifi_remain_on_channel(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int esp_wifi_sta_connect_internal(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int esp_wifi_ap_get_transition_disable_internal(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int esp_wifi_ap_set_group_mgmt_cipher_internal(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int esp_wifi_is_wpa3_compatible_mode_enabled(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int esp_wifi_set_sigma_internal(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);
int esp_wifi_op_class_supported_internal(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);

/* wifi_sta_connect_internal_process @ ieee80211_supplicant.o 00000004 size 37B bind GLOBAL
 * Calls: cnx_do_handoff_internal | Data refs: none
 * Fidelity: high - trivial: straight-line, all targets resolved */
int wifi_sta_connect_internal_process(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2 */
    /* immediates: 0, -1, 1, -4 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    cnx_do_handoff_internal(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* esp_wifi_get_sta_hw_key_idx_internal @ ieee80211_supplicant.o 00000000 size 30B bind LOCAL (no symbol; sec .text.esp_wifi_get_sta_hw_key_idx_internal)
 * Calls: none | Data refs: none
 * Fidelity: medium - small frame, 0 calls + 4 branch(es) mapped */
static int esp_wifi_get_sta_hw_key_idx_internal(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2, a3 */
    /* immediates: 4, -1, 1 */
    /* branches: +0x5 bbsi->0x1A; +0x8 bbc->0x1A; +0xd bgeui->0x15; +0x12 j->0x1A */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* esp_wifi_ap_get_prof_pmk_internal @ ieee80211_supplicant.o 00000004 size 15B bind GLOBAL
 * Calls: none | Data refs: g_wifi_nvs
 * Fidelity: high - trivial: straight-line, all targets resolved */
int esp_wifi_ap_get_prof_pmk_internal(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2 */
    /* immediates: 0x514 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* esp_wifi_sta_get_prof_pmk_internal @ ieee80211_supplicant.o 00000004 size 13B bind GLOBAL
 * Calls: none | Data refs: g_wifi_nvs
 * Fidelity: high - trivial: straight-line, all targets resolved */
int esp_wifi_sta_get_prof_pmk_internal(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2 */
    /* immediates: 112 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* esp_wifi_sta_update_ap_info_internal @ ieee80211_supplicant.o 00000010 size 45B bind GLOBAL
 * Calls: wifi_nvs_set, wifi_nvs_commit | Data refs: g_ic, g_wifi_nvs
 * Fidelity: medium - small frame, 2 calls + 0 branch(es) mapped */
int esp_wifi_sta_update_ap_info_internal(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2 */
    /* struct offsets touched: 31 */
    /* immediates: 0, 1, 13, 160 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    wifi_nvs_set(0, 0, 0, 0, 0, 0);  /* ordered call */
    wifi_nvs_commit(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* esp_wifi_sta_get_ap_info_prof_pmk_internal @ ieee80211_supplicant.o 00000004 size 27B bind GLOBAL
 * Calls: none | Data refs: g_wifi_nvs
 * Fidelity: high - trivial: straight-line, all targets resolved */
int esp_wifi_sta_get_ap_info_prof_pmk_internal(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2 */
    /* struct offsets touched: 159 */
    /* immediates: 0x10b */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* esp_wifi_ap_get_prof_ap_ssid_internal @ ieee80211_supplicant.o 00000004 size 15B bind GLOBAL
 * Calls: none | Data refs: g_wifi_nvs
 * Fidelity: high - trivial: straight-line, all targets resolved */
int esp_wifi_ap_get_prof_ap_ssid_internal(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2 */
    /* immediates: 0x368 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* esp_wifi_sta_get_prof_ssid_internal @ ieee80211_supplicant.o 00000004 size 12B bind GLOBAL
 * Calls: none | Data refs: g_wifi_nvs
 * Fidelity: high - trivial: straight-line, all targets resolved */
int esp_wifi_sta_get_prof_ssid_internal(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2 */
    /* immediates: 4 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* esp_wifi_ap_get_prof_authmode_internal @ ieee80211_supplicant.o 00000004 size 16B bind GLOBAL
 * Calls: none | Data refs: g_wifi_nvs
 * Fidelity: high - trivial: straight-line, all targets resolved */
int esp_wifi_ap_get_prof_authmode_internal(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2 */
    /* struct offsets touched: 244 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* esp_wifi_ap_get_max_sta_conn @ ieee80211_supplicant.o 00000004 size 16B bind GLOBAL
 * Calls: none | Data refs: g_wifi_nvs
 * Fidelity: high - trivial: straight-line, all targets resolved */
int esp_wifi_ap_get_max_sta_conn(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2 */
    /* struct offsets touched: 246 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* esp_wifi_ap_get_prof_pairwise_cipher_internal @ ieee80211_supplicant.o 00000004 size 16B bind GLOBAL
 * Calls: none | Data refs: g_wifi_nvs
 * Fidelity: high - trivial: straight-line, all targets resolved */
int esp_wifi_ap_get_prof_pairwise_cipher_internal(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2 */
    /* struct offsets touched: 255 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* esp_wifi_ap_get_owe_config_internal @ ieee80211_supplicant.o 00000004 size 16B bind GLOBAL
 * Calls: none | Data refs: g_wifi_nvs
 * Fidelity: high - trivial: straight-line, all targets resolved */
int esp_wifi_ap_get_owe_config_internal(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2 */
    /* struct offsets touched: 69 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* esp_wifi_ap_get_sae_ext_config_internal @ ieee80211_supplicant.o 00000004 size 16B bind GLOBAL
 * Calls: none | Data refs: g_wifi_nvs
 * Fidelity: high - trivial: straight-line, all targets resolved */
int esp_wifi_ap_get_sae_ext_config_internal(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* esp_wifi_ap_get_gtk_rekeying_config_internal @ ieee80211_supplicant.o 00000004 size 16B bind GLOBAL
 * Calls: none | Data refs: g_wifi_nvs
 * Fidelity: high - trivial: straight-line, all targets resolved */
int esp_wifi_ap_get_gtk_rekeying_config_internal(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* esp_wifi_sta_get_prof_authmode_internal @ ieee80211_supplicant.o 00000004 size 14B bind GLOBAL
 * Calls: none | Data refs: g_ic
 * Fidelity: high - trivial: straight-line, all targets resolved */
int esp_wifi_sta_get_prof_authmode_internal(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* esp_wifi_get_pmf_config_internal @ ieee80211_supplicant.o 00000004 size 80B bind GLOBAL
 * Calls: none | Data refs: g_wifi_nvs
 * Fidelity: medium - small frame, 0 calls + 2 branch(es) mapped */
int esp_wifi_get_pmf_config_internal(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2, a3 */
    /* struct offsets touched: 96, 97, 253, 254 */
    /* immediates: 1, 0 */
    /* branches: +0x14 bnez.n->0x2C; +0x2d j->0x45 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* esp_wifi_get_config_sae_pwe_h2e_internal @ ieee80211_supplicant.o 0000000c size 60B bind GLOBAL
 * Calls: wifi_log | Data refs: g_wifi_nvs, .rodata_wlog_error.2
 * Fidelity: medium - small frame, 1 call + 4 branch(es) mapped */
int esp_wifi_get_config_sae_pwe_h2e_internal(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2 */
    /* struct offsets touched: 23, 172 */
    /* immediates: 1, 4, 0 */
    /* branches: +0x12 bnez.n->0x18; +0x1f j->0x3A; +0x24 bnei->0x29; +0x32 j->0x3A */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    wifi_log(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* esp_wifi_sta_get_ie @ ieee80211_supplicant.o 00000018 size 122B bind GLOBAL
 * Calls: cnx_rc_search, wifi_log | Data refs: g_ic, .rodata_wlog_debug.3, .rodata_wlog_debug.4
 * Fidelity: medium - small frame, 2 calls + 13 branches mapped (backward-edge marks kept; predicates opaque) */
int esp_wifi_sta_get_ie(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2, a3 */
    /* struct offsets touched: 16, 824, 952, 956 */
    /* immediates: 48, 41, 43, 244, 0x33e, 4, 64, 1, 0 */
    /* branches: +0x25 beqz->0x78; +0x30 beqz->0x69; +0x35 beq->0x3C; +0x38 bltu->0x30 [loop]; +0x3d beq->0x44; +0x42 beq->0x4C; +0x45 j->0x55; +0x4b bne->0x55; +0x51 j->0x78; +0x59 j->0x78 (+3 more) */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    cnx_rc_search(0, 0, 0, 0, 0, 0);  /* ordered call */
    wifi_log(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* esp_wifi_sta_disable_wpa2_authmode_internal @ ieee80211_supplicant.o 00000018 size 71B bind GLOBAL
 * Calls: wifi_log | Data refs: g_wifi_nvs, .rodata_wlog_debug.5, g_ic, .rodata_wlog_debug.6
 * Fidelity: medium - small frame, 1 call + 2 branch(es) mapped */
int esp_wifi_sta_disable_wpa2_authmode_internal(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2 */
    /* struct offsets touched: 22, 159 */
    /* immediates: 4, 8, 1 */
    /* branches: +0x26 bnei->0x36; +0x4b j->0x45 [loop] */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    wifi_log(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* esp_wifi_sta_get_config_sae_pk_internal @ ieee80211_supplicant.o 00000004 size 16B bind GLOBAL
 * Calls: none | Data refs: g_wifi_nvs
 * Fidelity: high - trivial: straight-line, all targets resolved */
int esp_wifi_sta_get_config_sae_pk_internal(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2 */
    /* struct offsets touched: 24 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* esp_wifi_sta_disable_sae_pk_internal @ ieee80211_supplicant.o 00000004 size 22B bind GLOBAL
 * Calls: none | Data refs: g_ic
 * Fidelity: high - trivial: straight-line, all targets resolved */
int esp_wifi_sta_disable_sae_pk_internal(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: none observed */
    /* struct offsets touched: 157 */
    /* immediates: 0 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* esp_wifi_enable_sae_pk_only_mode_internal @ ieee80211_supplicant.o 00000010 size 54B bind GLOBAL
 * Calls: wifi_log | Data refs: g_wifi_nvs, g_ic, .rodata_wlog_debug.7
 * Fidelity: medium - small frame, 1 call + 2 branch(es) mapped */
int esp_wifi_enable_sae_pk_only_mode_internal(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: none observed */
    /* struct offsets touched: 22, 158 */
    /* immediates: 0x101, 4, 1 */
    /* branches: +0x1e beqz.n->0x25; +0x32 j->0x34 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    wifi_log(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* esp_wifi_sta_disable_owe_trans_internal @ ieee80211_supplicant.o 00000018 size 74B bind GLOBAL
 * Calls: wifi_log | Data refs: g_wifi_nvs, g_ic, .rodata_wlog_debug.8, .rodata_wlog_debug.9
 * Fidelity: medium - small frame, 1 call + 2 branch(es) mapped */
int esp_wifi_sta_disable_owe_trans_internal(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: none observed */
    /* struct offsets touched: 22, 165 */
    /* immediates: 4, 1, 8 */
    /* branches: +0x26 beqz.n->0x39; +0x4c j->0x48 [loop] */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    wifi_log(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* esp_wifi_sta_notify_dpp_config_set_internal @ ieee80211_supplicant.o 00000014 size 46B bind GLOBAL
 * Calls: wifi_log | Data refs: .rodata.esp_wifi_sta_notify_dpp_config_set_~, g_ic, .rodata_wlog_debug.10
 * Fidelity: high - trivial: straight-line, all targets resolved */
int esp_wifi_sta_notify_dpp_config_set_internal(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2 */
    /* immediates: 4, 1 */
    /* branches: +0x29 bnez.n->0x1A [loop] */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    wifi_log(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* esp_wifi_ap_notify_node_sae_auth_done @ ieee80211_supplicant.o 0000000c size 76B bind GLOBAL
 * Calls: ieee80211_ioctl | Data refs: g_osi_funcs_p, wifi_ap_sta_sae_auth_done_process
 * Fidelity: medium - small frame, 1 call + 3 branch(es) mapped */
int esp_wifi_ap_notify_node_sae_auth_done(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2 */
    /* struct offsets touched: 8, 10, 12, 376 */
    /* immediates: 0, 24, 102, 1 */
    /* branches: +0xf bnez.n->0xC [loop]; +0x13 j->0x4A; +0x25 beqz->0x5 [loop] */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    ieee80211_ioctl(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* esp_wifi_ap_is_sta_sae_reauth_node @ ieee80211_supplicant.o 00000004 size 29B bind GLOBAL
 * Calls: cnx_node_search | Data refs: none
 * Fidelity: medium - small frame, 1 call + 3 branch(es) mapped */
int esp_wifi_ap_is_sta_sae_reauth_node(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2 */
    /* struct offsets touched: 15 */
    /* immediates: 0 */
    /* branches: +0x7 bnez.n->0xA; +0xb j->0x1B; +0x16 beqz->0x5 [loop] */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    cnx_node_search(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* esp_wifi_sta_get_sae_identifier_internal @ ieee80211_supplicant.o 00000004 size 15B bind GLOBAL
 * Calls: none | Data refs: g_wifi_nvs
 * Fidelity: high - trivial: straight-line, all targets resolved */
int esp_wifi_sta_get_sae_identifier_internal(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2 */
    /* immediates: 0x47d */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* esp_wifi_sta_is_ap_notify_completed_rsne_internal @ ieee80211_supplicant.o 00000004 size 21B bind GLOBAL
 * Calls: none | Data refs: g_ic
 * Fidelity: high - trivial: straight-line, all targets resolved */
int esp_wifi_sta_is_ap_notify_completed_rsne_internal(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2 */
    /* immediates: 0, 1 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* esp_wifi_ap_get_prof_password_internal @ ieee80211_supplicant.o 00000004 size 15B bind GLOBAL
 * Calls: none | Data refs: g_wifi_nvs
 * Fidelity: high - trivial: straight-line, all targets resolved */
int esp_wifi_ap_get_prof_password_internal(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2 */
    /* immediates: 0x392 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* wifi_sta_get_prof_password @ ieee80211_supplicant.o 00000004 size 13B bind GLOBAL
 * Calls: none | Data refs: g_wifi_nvs
 * Fidelity: high - trivial: straight-line, all targets resolved */
int wifi_sta_get_prof_password(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2 */
    /* immediates: 47 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* wifi_ap_pmf_enabled @ ieee80211_supplicant.o 00000008 size 75B bind GLOBAL
 * Calls: none | Data refs: g_ic, g_wifi_nvs
 * Fidelity: medium - small frame, 0 calls + 8 branch(es) mapped */
int wifi_ap_pmf_enabled(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2 */
    /* struct offsets touched: 20, 68, 246, 251, 253 */
    /* immediates: 240, 1, 4, 0 */
    /* branches: +0x12 beqz.n->0x49; +0x1f beqz.n->0x28; +0x2b j->0x44; +0x36 bnez->0x19 [loop]; +0x39 j->0x49; +0x3e beqz.n->0x40; +0x46 bnez.n->0x49; +0x4c bge->0x34 [loop] */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* esp_wifi_sta_get_prof_password_internal @ ieee80211_supplicant.o 00000004 size 13B bind GLOBAL
 * Calls: none | Data refs: g_wifi_nvs
 * Fidelity: high - trivial: straight-line, all targets resolved */
int esp_wifi_sta_get_prof_password_internal(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2 */
    /* immediates: 47 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* esp_wifi_sta_get_reset_nvs_pmk_internal @ ieee80211_supplicant.o 00000004 size 14B bind GLOBAL
 * Calls: none | Data refs: g_ic
 * Fidelity: high - trivial: straight-line, all targets resolved */
int esp_wifi_sta_get_reset_nvs_pmk_internal(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* esp_wifi_sta_set_reset_nvs_pmk_internal @ ieee80211_supplicant.o 00000004 size 22B bind GLOBAL
 * Calls: none | Data refs: g_ic
 * Fidelity: high - trivial: straight-line, all targets resolved */
int esp_wifi_sta_set_reset_nvs_pmk_internal(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2 */
    /* immediates: 0 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* esp_wifi_sta_prof_is_wpa_internal @ ieee80211_supplicant.o 00000004 size 57B bind GLOBAL
 * Calls: none | Data refs: g_ic
 * Fidelity: medium - small frame, 0 calls + 3 branch(es) mapped */
int esp_wifi_sta_prof_is_wpa_internal(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2 */
    /* struct offsets touched: 512 */
    /* immediates: -2, -6, 0, 1, 0xfffffbfb */
    /* branches: +0x16 bltui->0x35; +0x26 bnez.n->0x35; +0x36 j->0x37 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* esp_wifi_sta_prof_is_wpa2_internal @ ieee80211_supplicant.o 00000008 size 69B bind GLOBAL
 * Calls: none | Data refs: g_ic, .rodata.CSWTCH$163
 * Fidelity: medium - small frame, 0 calls + 4 branch(es) mapped */
int esp_wifi_sta_prof_is_wpa2_internal(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2 */
    /* immediates: -4, -14, 0, 1, -7 */
    /* branches: +0x1a bltui->0x3E; +0x2a bne->0x3E; +0x33 bgeui->0x40; +0x41 j->0x40 [loop] */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* esp_wifi_sta_prof_is_wapi_internal @ ieee80211_supplicant.o 00000004 size 30B bind GLOBAL
 * Calls: none | Data refs: g_ic
 * Fidelity: high - trivial: straight-line, all targets resolved */
int esp_wifi_sta_prof_is_wapi_internal(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2 */
    /* immediates: 1, -11, 0 */
    /* branches: +0x18 bltui->0x19 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* esp_wifi_sta_prof_is_rsn_internal @ ieee80211_supplicant.o 00000008 size 69B bind GLOBAL
 * Calls: none | Data refs: g_ic, .rodata.CSWTCH$166
 * Fidelity: medium - small frame, 0 calls + 4 branch(es) mapped */
int esp_wifi_sta_prof_is_rsn_internal(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2 */
    /* immediates: -4, -14, 0, 1, -7, 11 */
    /* branches: +0x1a bltui->0x3E; +0x2a bne->0x3E; +0x35 bltu->0x40; +0x43 j->0x40 [loop] */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* esp_wifi_sta_get_pairwise_cipher_internal @ ieee80211_supplicant.o 00000004 size 14B bind GLOBAL
 * Calls: none | Data refs: g_ic
 * Fidelity: high - trivial: straight-line, all targets resolved */
int esp_wifi_sta_get_pairwise_cipher_internal(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* esp_wifi_sta_get_group_cipher_internal @ ieee80211_supplicant.o 00000004 size 14B bind GLOBAL
 * Calls: none | Data refs: g_ic
 * Fidelity: high - trivial: straight-line, all targets resolved */
int esp_wifi_sta_get_group_cipher_internal(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* ieee80211_get_key @ ieee80211_supplicant.o 00000004 size 24B bind GLOBAL
 * Calls: none | Data refs: g_ic
 * Fidelity: high - trivial: straight-line, all targets resolved */
int ieee80211_get_key(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2 */
    /* struct offsets touched: 320 */
    /* immediates: 24, 0 */
    /* branches: +0xe bltu->0x16 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* ieee80211_set_key @ ieee80211_supplicant.o 00000008 size 62B bind GLOBAL
 * Calls: none | Data refs: g_ic, g_osi_funcs_p
 * Fidelity: medium - small frame, 0 calls + 5 branch(es) mapped */
int ieee80211_set_key(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2, a3, a4, a5 */
    /* struct offsets touched: 176 */
    /* immediates: 24, 80, 1, 0 */
    /* branches: +0x10 bltu->0x3A; +0x13 beqz.n->0x3A; +0x22 beq->0x3C; +0x25 beqz->0x2C; +0x3e j->0x3C [loop] */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* ieee80211_get_sta_gtk_index @ ieee80211_supplicant.o 00000004 size 19B bind GLOBAL
 * Calls: none | Data refs: g_ic
 * Fidelity: high - trivial: straight-line, all targets resolved */
int ieee80211_get_sta_gtk_index(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2 */
    /* struct offsets touched: 16, 53, 228 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* ieee80211_set_sta_gtk_index @ ieee80211_supplicant.o 00000004 size 41B bind GLOBAL
 * Calls: none | Data refs: g_ic
 * Fidelity: high - trivial: straight-line, all targets resolved */
int ieee80211_set_sta_gtk_index(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2, a3 */
    /* struct offsets touched: 16, 53, 228 */
    /* immediates: 0x137 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* ieee80211_set_gtk @ ieee80211_supplicant.o 00000010 size 65B bind GLOBAL
 * Calls: wifi_log, cnx_node_search | Data refs: .rodata.ieee80211_set_gtk.str1.1, .rodata_wlog_error.11
 * Fidelity: medium - small frame, 2 calls + 3 branch(es) mapped */
int ieee80211_set_gtk(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2, a3 */
    /* struct offsets touched: 53 */
    /* immediates: 1, 0x188 */
    /* branches: +0x16 bnez.n->0x23; +0x30 j->0x20 [loop]; +0x3e beqz.n->0x3C [loop] */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    wifi_log(0, 0, 0, 0, 0, 0);  /* ordered call */
    cnx_node_search(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* ieee80211_get_ptk @ ieee80211_supplicant.o 00000004 size 26B bind GLOBAL
 * Calls: cnx_node_search | Data refs: none
 * Fidelity: high - trivial: straight-line, all targets resolved */
int ieee80211_get_ptk(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2 */
    /* struct offsets touched: 52 */
    /* immediates: 0 */
    /* branches: +0x13 beq->0x18 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    cnx_node_search(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* ieee80211_get_spp @ ieee80211_supplicant.o 00000008 size 49B bind GLOBAL
 * Calls: cnx_node_search | Data refs: g_ic
 * Fidelity: medium - small frame, 1 call + 5 branch(es) mapped */
int ieee80211_get_spp(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2, a3 */
    /* struct offsets touched: 16, 228, 247 */
    /* immediates: 0 */
    /* branches: +0x10 bnez.n->0x20; +0x17 bnez.n->0x18; +0x1b j->0x2F; +0x23 j->0x26; +0x2e beqz->0x11 [loop] */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    cnx_node_search(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* esp_wifi_wpa_ptk_init_done_internal @ ieee80211_supplicant.o 00000020 size 134B bind GLOBAL
 * Calls: cnx_node_search, wifi_log, memcpy, wifi_event_post | Data refs: .rodata.ieee80211_set_gtk.str1.1, .rodata_wlog_error.12, g_ic
 * Fidelity: medium - small frame, 4 calls + 3 branch(es) mapped */
int esp_wifi_wpa_ptk_init_done_internal(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,48; early arg regs: a2, a3 */
    /* struct offsets touched: 12, 36, 38, 116, 249 */
    /* immediates: 1, 0x1bc, 0, 4, 6, 8, 14 */
    /* branches: +0x2e bnez.n->0x2C [loop]; +0x48 j->0x28 [loop]; +0x54 beq->0x3D [loop] */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    cnx_node_search(0, 0, 0, 0, 0, 0);  /* ordered call */
    wifi_log(0, 0, 0, 0, 0, 0);  /* ordered call */
    memcpy(0, 0, 0);  /* ordered call */
    wifi_event_post(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* esp_wifi_enable_sta_privacy_internal @ ieee80211_supplicant.o 00000004 size 28B bind GLOBAL
 * Calls: none | Data refs: g_ic
 * Fidelity: high - trivial: straight-line, all targets resolved */
int esp_wifi_enable_sta_privacy_internal(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2 */
    /* struct offsets touched: 16, 164 */
    /* immediates: 16, 1 */
    /* branches: +0xc beqz.n->0x15 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* esp_wifi_sta_is_running_internal @ ieee80211_supplicant.o 00000004 size 30B bind GLOBAL
 * Calls: none | Data refs: g_ic
 * Fidelity: high - trivial: straight-line, all targets resolved */
int esp_wifi_sta_is_running_internal(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2 */
    /* struct offsets touched: 16, 152 */
    /* immediates: 1, 0, -5 */
    /* branches: +0xe beqz.n->0x1C */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* esp_wifi_auth_done_internal @ ieee80211_supplicant.o 00000004 size 13B bind GLOBAL
 * Calls: cnx_auth_done | Data refs: none
 * Fidelity: high - trivial: straight-line, all targets resolved */
int esp_wifi_auth_done_internal(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2 */
    /* immediates: 1 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    cnx_auth_done(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* esp_wifi_unregister_wpa2_cb_internal @ ieee80211_supplicant.o 00000008 size 32B bind GLOBAL
 * Calls: none | Data refs: g_ic, g_osi_funcs_p
 * Fidelity: high - trivial: straight-line, all targets resolved */
int esp_wifi_unregister_wpa2_cb_internal(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2, a3 */
    /* struct offsets touched: 176, 440 */
    /* immediates: 0 */
    /* branches: +0x11 beqz.n->0x16 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* esp_wifi_register_wpa2_cb_internal @ ieee80211_supplicant.o 00000008 size 22B bind GLOBAL
 * Calls: esp_wifi_unregister_wpa2_cb_internal | Data refs: g_ic
 * Fidelity: high - trivial: straight-line, all targets resolved */
int esp_wifi_register_wpa2_cb_internal(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2 */
    /* struct offsets touched: 440 */
    /* immediates: 0 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    esp_wifi_unregister_wpa2_cb_internal(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* ieee80211_unregister_wapi_cb @ ieee80211_supplicant.o 00000008 size 32B bind GLOBAL
 * Calls: none | Data refs: g_ic, g_osi_funcs_p
 * Fidelity: high - trivial: straight-line, all targets resolved */
int ieee80211_unregister_wapi_cb(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2, a3 */
    /* struct offsets touched: 176, 640 */
    /* immediates: 0 */
    /* branches: +0x11 beqz.n->0x16 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* ieee80211_register_wapi_cb @ ieee80211_supplicant.o 00000008 size 22B bind GLOBAL
 * Calls: ieee80211_unregister_wapi_cb | Data refs: g_ic
 * Fidelity: high - trivial: straight-line, all targets resolved */
int ieee80211_register_wapi_cb(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2 */
    /* struct offsets touched: 640 */
    /* immediates: 1 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    ieee80211_unregister_wapi_cb(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* esp_wifi_unregister_wpa_cb_internal @ ieee80211_supplicant.o 00000008 size 32B bind GLOBAL
 * Calls: none | Data refs: g_ic, g_osi_funcs_p
 * Fidelity: high - trivial: straight-line, all targets resolved */
int esp_wifi_unregister_wpa_cb_internal(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2, a3 */
    /* struct offsets touched: 176, 436 */
    /* immediates: 0 */
    /* branches: +0x11 beqz.n->0x16 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* esp_wifi_register_wpa_cb_internal @ ieee80211_supplicant.o 00000008 size 22B bind GLOBAL
 * Calls: esp_wifi_unregister_wpa_cb_internal | Data refs: g_ic
 * Fidelity: high - trivial: straight-line, all targets resolved */
int esp_wifi_register_wpa_cb_internal(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2 */
    /* struct offsets touched: 436 */
    /* immediates: 0 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    esp_wifi_unregister_wpa_cb_internal(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* esp_wifi_get_assoc_bssid_internal @ ieee80211_supplicant.o 00000010 size 80B bind GLOBAL
 * Calls: memcpy | Data refs: g_wifi_global_lock, g_osi_funcs_p, g_ic
 * Fidelity: medium - small frame, 1 call + 4 branch(es) mapped */
int esp_wifi_get_assoc_bssid_internal(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a3, a4 */
    /* struct offsets touched: 16, 84, 88, 152, 228 */
    /* immediates: 6, 4, 0, -1 */
    /* branches: +0x29 beqz.n->0x42; +0x2e bnei->0x42; +0x34 beqz.n->0x42; +0x4e j->0x4E [loop] */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    memcpy(0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* ieee80211_sta_is_connected @ ieee80211_supplicant.o 00000004 size 20B bind GLOBAL
 * Calls: none | Data refs: g_sta_connected_flag
 * Fidelity: high - trivial: straight-line, all targets resolved */
int ieee80211_sta_is_connected(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2 */
    /* immediates: 0, 1, -1 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* esp_wifi_get_hostap_private_internal @ ieee80211_supplicant.o 00000004 size 15B bind GLOBAL
 * Calls: none | Data refs: g_ic
 * Fidelity: high - trivial: straight-line, all targets resolved */
int esp_wifi_get_hostap_private_internal(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2 */
    /* struct offsets touched: 20, 336 */
    /* branches: +0xc beqz.n->0xD */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* esp_wifi_deauthenticate_internal @ ieee80211_supplicant.o 00000008 size 46B bind GLOBAL
 * Calls: ieee80211_sta_new_state | Data refs: g_ic
 * Fidelity: medium - small frame, 1 call + 3 branch(es) mapped */
int esp_wifi_deauthenticate_internal(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2 */
    /* struct offsets touched: 16, 84, 152 */
    /* immediates: -1, 0 */
    /* branches: +0x16 beqz.n->0x2C; +0x23 bltui->0x21 [loop]; +0x26 bnei->0x2C */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    ieee80211_sta_new_state(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* esp_wifi_get_spp_attrubute_internal @ ieee80211_supplicant.o 00000004 size 36B bind GLOBAL
 * Calls: none | Data refs: g_ic
 * Fidelity: medium - small frame, 0 calls + 3 branch(es) mapped */
int esp_wifi_get_spp_attrubute_internal(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2 */
    /* struct offsets touched: 124, 126 */
    /* immediates: 0 */
    /* branches: +0xa bnez.n->0x14; +0x15 j->0x22; +0x1a bnei->0x22 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* esp_wifi_get_user_init_flag_internal @ ieee80211_supplicant.o 00000004 size 25B bind GLOBAL
 * Calls: none | Data refs: g_ic
 * Fidelity: high - trivial: straight-line, all targets resolved */
int esp_wifi_get_user_init_flag_internal(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2 */
    /* struct offsets touched: 237 */
    /* immediates: 1, 0 */
    /* branches: +0x12 bgeui->0x14 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* wifi_set_rx_policy @ ieee80211_supplicant.o 0000005c size 374B bind GLOBAL
 * Calls: ic_set_mac, ic_set_rx_policy, ic_set_bssid, nan_get_clust_id, ic_set_rx_policy_ubssid_check | Data refs: g_ic, .rodata.wifi_set_rx_policy, g_ic+0x212, g_ic+0x20c, g_ic+0x218, g_offchan_ctx, g_ic+0x200
 * Fidelity: low - large/complex: 16 branches, 13 loop(s), 5 calls; skeleton only */
int wifi_set_rx_policy(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2, a3, a4 */
    /* struct offsets touched: 8, 16, 25, 26, 96, 116, 152, 188 */
    /* immediates: 13, 0, 1, 2, 4 */
    /* branches: +0x6b bgeu->0x15 [loop]; +0x6e j->0x171; +0xae j->0x74 [loop]; +0xda j->0x163; +0xe3 j->0x72 [loop]; +0xe9 j->0x64 [loop]; +0xf4 j->0x74 [loop]; +0xfb bnei->0x6C [loop]; +0x119 bnez.n->0xC1 [loop]; +0x129 j->0x163 (+6 more) */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    ic_set_mac(0, 0, 0, 0, 0, 0);  /* ordered call */
    ic_set_rx_policy(0, 0, 0, 0, 0, 0);  /* ordered call */
    ic_set_bssid(0, 0, 0, 0, 0, 0);  /* ordered call */
    nan_get_clust_id(0, 0, 0, 0, 0, 0);  /* ordered call */
    ic_set_rx_policy_ubssid_check(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* ieee80211_espnow_get_init_flag @ ieee80211_supplicant.o 00000004 size 14B bind GLOBAL
 * Calls: none | Data refs: g_ic
 * Fidelity: high - trivial: straight-line, all targets resolved */
int ieee80211_espnow_get_init_flag(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2 */
    /* struct offsets touched: 212 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* ieee80211_espnow_set_init_flag @ ieee80211_supplicant.o 00000004 size 20B bind GLOBAL
 * Calls: none | Data refs: g_ic
 * Fidelity: high - trivial: straight-line, all targets resolved */
int ieee80211_espnow_set_init_flag(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2 */
    /* struct offsets touched: 212 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* ieee80211_mt_key_is_mask @ ieee80211_supplicant.o 00000004 size 36B bind GLOBAL
 * Calls: none | Data refs: g_ic
 * Fidelity: high - trivial: straight-line, all targets resolved */
int ieee80211_mt_key_is_mask(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2, a3 */
    /* struct offsets touched: 456 */
    /* immediates: 1, 0 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* ieee80211_mt_key_is_mask_zero @ ieee80211_supplicant.o 00000004 size 24B bind GLOBAL
 * Calls: none | Data refs: g_ic
 * Fidelity: high - trivial: straight-line, all targets resolved */
int ieee80211_mt_key_is_mask_zero(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2 */
    /* struct offsets touched: 456 */
    /* immediates: 0, 1 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* ieee80211_mt_key_set_mask @ ieee80211_supplicant.o 00000004 size 35B bind GLOBAL
 * Calls: none | Data refs: g_ic
 * Fidelity: high - trivial: straight-line, all targets resolved */
int ieee80211_mt_key_set_mask(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2, a3 */
    /* struct offsets touched: 8 */
    /* immediates: 112, 1 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* ieee80211_mt_key_clear_mask @ ieee80211_supplicant.o 00000004 size 35B bind GLOBAL
 * Calls: none | Data refs: g_ic
 * Fidelity: high - trivial: straight-line, all targets resolved */
int ieee80211_mt_key_clear_mask(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2, a3 */
    /* struct offsets touched: 8 */
    /* immediates: 112, -2 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* ieee80211_get_mac_addr_from_frame @ ieee80211_supplicant.o 00000000 size 22B bind GLOBAL
 * Calls: none | Data refs: none
 * Fidelity: high - trivial: straight-line, all targets resolved */
int ieee80211_get_mac_addr_from_frame(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2 */
    /* struct offsets touched: 44 */
    /* immediates: 4 */
    /* branches: +0x3 beqz.n->0x14; +0xd bbci->0x12 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* clear_ic_key @ ieee80211_supplicant.o 00000008 size 45B bind GLOBAL
 * Calls: none | Data refs: g_ic, g_osi_funcs_p
 * Fidelity: high - trivial: straight-line, all targets resolved */
int clear_ic_key(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2 */
    /* struct offsets touched: 176 */
    /* immediates: 24, 80, 0 */
    /* branches: +0x10 bltu->0x28; +0x1e beqz.n->0x28 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* esp_wifi_del_key_internal @ ieee80211_supplicant.o 00000004 size 14B bind GLOBAL
 * Calls: ic_del_key | Data refs: none
 * Fidelity: high - trivial: straight-line, all targets resolved */
int esp_wifi_del_key_internal(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    ic_del_key(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* esp_wifi_set_key_internal @ ieee80211_supplicant.o 0000000c size 96B bind GLOBAL
 * Calls: ieee80211_get_spp, ic_set_key | Data refs: g_ic
 * Fidelity: medium - small frame, 2 calls + 0 branch(es) mapped */
int esp_wifi_set_key_internal(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,64; early arg regs: a2, a6, a7 */
    /* struct offsets touched: 8, 16, 20, 24, 28, 64 */
    /* immediates: 0, 1 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    ieee80211_get_spp(0, 0, 0, 0, 0, 0);  /* ordered call */
    ic_set_key(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* esp_wifi_get_key_internal @ ieee80211_supplicant.o 00000004 size 34B bind GLOBAL
 * Calls: ic_get_key | Data refs: none
 * Fidelity: high - trivial: straight-line, all targets resolved */
int esp_wifi_get_key_internal(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,48; early arg regs: a2, a3, a4, a5, a6, a7 */
    /* struct offsets touched: 48 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    ic_get_key(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* esp_wifi_register_tx_cb_internal @ ieee80211_supplicant.o 00000004 size 20B bind GLOBAL
 * Calls: ic_register_tx_cb | Data refs: none
 * Fidelity: high - trivial: straight-line, all targets resolved */
int esp_wifi_register_tx_cb_internal(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2, a3 */
    /* immediates: 1, 0 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    ic_register_tx_cb(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* esp_wifi_register_eapol_txdonecb_internal @ ieee80211_supplicant.o 00000004 size 16B bind GLOBAL
 * Calls: wifi_sta_reg_eapol_txdone_cb | Data refs: none
 * Fidelity: high - trivial: straight-line, all targets resolved */
int esp_wifi_register_eapol_txdonecb_internal(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2 */
    /* immediates: 0 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    wifi_sta_reg_eapol_txdone_cb(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* esp_wifi_get_macaddr_internal @ ieee80211_supplicant.o 00000004 size 18B bind GLOBAL
 * Calls: wifi_get_macaddr | Data refs: none
 * Fidelity: high - trivial: straight-line, all targets resolved */
int esp_wifi_get_macaddr_internal(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2, a3 */
    /* immediates: -1 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    wifi_get_macaddr(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* esp_wifi_ap_deauth_internal @ ieee80211_supplicant.o 00000014 size 87B bind GLOBAL
 * Calls: esp_mesh_map_deauth, ieee80211_ioctl | Data refs: g_ic, g_osi_funcs_p, wifi_ap_remove_sta_node_process
 * Fidelity: medium - small frame, 2 calls + 4 branch(es) mapped */
int esp_wifi_ap_deauth_internal(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2, a3, a4, a5 */
    /* struct offsets touched: 8, 10, 12, 116, 376 */
    /* immediates: 0x102, 24, 93 */
    /* branches: +0x1f beqz.n->0x1D [loop]; +0x2e j->0x55; +0x34 beqz.n->0x55; +0x46 beqz.n->0x55 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    esp_mesh_map_deauth(0, 0, 0, 0, 0, 0);  /* ordered call */
    ieee80211_ioctl(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* wifi_init_key @ ieee80211_supplicant.o 00000008 size 32B bind GLOBAL
 * Calls: memset | Data refs: none
 * Fidelity: high - trivial: straight-line, all targets resolved */
int wifi_init_key(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2 */
    /* immediates: 168, 0, 144, 255, 8 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    memset(0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* esp_wifi_set_ap_key_internal @ ieee80211_supplicant.o 0000004c size 361B bind GLOBAL
 * Calls: ieee80211_set_gtk, ieee80211_get_ptk, ic_del_key, ic_del_ptk_and_gtk_alg, memcpy, wifi_ap_pmf_enabled, ieee80211_get_spp, ic_set_key, ppClearRxFragment, wifi_init_key, ieee80211_set_key | Data refs: g_ic, g_osi_funcs_p, tkip, ccmp, wep
 * Fidelity: low - large/complex: 16 branches, 14 loop(s), 11 calls; skeleton only */
int esp_wifi_set_ap_key_internal(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,96; early arg regs: a2, a3, a4, a7 */
    /* struct offsets touched: 8, 48, 152, 156, 160, 164, 176, 364 */
    /* immediates: 1, -5, 8, 80, 16, 24, 32, 40, 0, 168, 0x101 */
    /* branches: +0x52 bbci->0x1B [loop]; +0x64 j->0x36 [loop]; +0x6c bnei->0x2C [loop]; +0x74 j->0x36 [loop]; +0x82 bnez.n->0x69 [loop]; +0x97 beqz.n->0x5A [loop]; +0xb1 j->0x167; +0xb5 bnei->0x91 [loop]; +0xda j->0x98 [loop]; +0x14b beqz->0x164 (+6 more) */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    ieee80211_set_gtk(0, 0, 0, 0, 0, 0);  /* ordered call */
    ieee80211_get_ptk(0, 0, 0, 0, 0, 0);  /* ordered call */
    ic_del_key(0, 0, 0, 0, 0, 0);  /* ordered call */
    ic_del_ptk_and_gtk_alg(0, 0, 0, 0, 0, 0);  /* ordered call */
    memcpy(0, 0, 0);  /* ordered call */
    wifi_ap_pmf_enabled(0, 0, 0, 0, 0, 0);  /* ordered call */
    ieee80211_get_spp(0, 0, 0, 0, 0, 0);  /* ordered call */
    ic_set_key(0, 0, 0, 0, 0, 0);  /* ordered call */
    ppClearRxFragment(0, 0, 0, 0, 0, 0);  /* ordered call */
    wifi_init_key(0, 0, 0, 0, 0, 0);  /* ordered call */
    ieee80211_set_key(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* ppInstallKey @ ieee80211_supplicant.o 00000040 size 310B bind GLOBAL
 * Calls: ieee80211_set_sta_gtk_index, ppClearRxFragment, ic_del_key, ieee80211_get_spp, ic_set_key, wifi_init_key, ieee80211_set_key, memcpy | Data refs: g_osi_funcs_p, g_ic, tkip, ccmp, wep, sms4
 * Fidelity: low - large/complex: 14 branches, 11 loop(s), 8 calls; skeleton only */
int ppInstallKey(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,64; early arg regs: a3, a4, a5, a7 */
    /* struct offsets touched: 8, 16, 20, 24, 64, 68, 72, 160, 164, 364 */
    /* immediates: 168, 0x101, 1, 0, -5, 152, 8 */
    /* branches: +0x46 bgei->0x15 [loop]; +0x55 bnei->0x3C [loop]; +0x76 bnez->0xA0; +0x79 j->0x132; +0xd8 beqz->0x132; +0xdb j->0x18 [loop]; +0x108 bnei->0xD1 [loop]; +0x10e j->0xD7 [loop]; +0x111 bnei->0xE0 [loop]; +0x11d j->0x118 [loop] (+4 more) */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    ieee80211_set_sta_gtk_index(0, 0, 0, 0, 0, 0);  /* ordered call */
    ppClearRxFragment(0, 0, 0, 0, 0, 0);  /* ordered call */
    ic_del_key(0, 0, 0, 0, 0, 0);  /* ordered call */
    ieee80211_get_spp(0, 0, 0, 0, 0, 0);  /* ordered call */
    ic_set_key(0, 0, 0, 0, 0, 0);  /* ordered call */
    wifi_init_key(0, 0, 0, 0, 0, 0);  /* ordered call */
    ieee80211_set_key(0, 0, 0, 0, 0, 0);  /* ordered call */
    memcpy(0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* esp_wifi_set_sta_key_internal @ ieee80211_supplicant.o 00000008 size 96B bind GLOBAL
 * Calls: esp_wifi_get_sta_hw_key_idx_internal[local], ppInstallKey | Data refs: none
 * Fidelity: medium - small frame, 2 calls + 5 branch(es) mapped */
int esp_wifi_set_sta_key_internal(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,64; early arg regs: a4, a7 */
    /* struct offsets touched: 8, 16, 64, 68, 72 */
    /* immediates: 12, -4, 1, 2 */
    /* branches: +0x22 bbsi->0x34; +0x25 bbci->0x3C; +0x2b bnez.n->0x3A; +0x38 j->0x3C; +0x3e j->0x3C [loop] */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    esp_wifi_get_sta_hw_key_idx_internal(0, 0, 0, 0, 0, 0);  /* ordered call [local] */
    ppInstallKey(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* esp_wifi_get_sta_key_internal @ ieee80211_supplicant.o 00000008 size 72B bind GLOBAL
 * Calls: esp_wifi_get_sta_hw_key_idx_internal[local], ic_get_key | Data refs: none
 * Fidelity: medium - small frame, 2 calls + 3 branch(es) mapped */
int esp_wifi_get_sta_key_internal(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,64; early arg regs: a4, a5 */
    /* struct offsets touched: 16, 64 */
    /* immediates: -1, 0 */
    /* branches: +0x22 bbci->0x44; +0x2a bgez->0x44; +0x48 j->0x46 [loop] */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    esp_wifi_get_sta_hw_key_idx_internal(0, 0, 0, 0, 0, 0);  /* ordered call [local] */
    ic_get_key(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* esp_wifi_get_appie_internal @ ieee80211_supplicant.o 00000004 size 23B bind GLOBAL
 * Calls: none | Data refs: g_ic
 * Fidelity: high - trivial: straight-line, all targets resolved */
int esp_wifi_get_appie_internal(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2 */
    /* struct offsets touched: 40 */
    /* immediates: 10, 0 */
    /* branches: +0xe bltu->0x15 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* esp_wifi_set_appie_internal @ ieee80211_supplicant.o 00000014 size 86B bind GLOBAL
 * Calls: wifi_init_completed, ieee80211_ioctl | Data refs: g_osi_funcs_p, wifi_set_appie_process
 * Fidelity: medium - small frame, 2 calls + 2 branch(es) mapped */
int esp_wifi_set_appie_internal(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2, a4, a5, a6 */
    /* struct offsets touched: 8, 9, 10, 12, 20, 376 */
    /* immediates: 24, 0x101, 46, 0 */
    /* branches: +0x29 beqz.n->0x54; +0x3b beqz.n->0x54 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    wifi_init_completed(0, 0, 0, 0, 0, 0);  /* ordered call */
    ieee80211_ioctl(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* esp_wifi_unset_appie_internal @ ieee80211_supplicant.o 00000004 size 22B bind GLOBAL
 * Calls: esp_wifi_set_appie_internal | Data refs: none
 * Fidelity: high - trivial: straight-line, all targets resolved */
int esp_wifi_unset_appie_internal(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2 */
    /* immediates: 0 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    esp_wifi_set_appie_internal(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* esp_wifi_sta_wpa2_ent_enable_internal @ ieee80211_supplicant.o 00000014 size 84B bind GLOBAL
 * Calls: wifi_init_completed, ieee80211_ioctl | Data refs: g_osi_funcs_p, wifi_wpa2_ent_enable_process
 * Fidelity: medium - small frame, 2 calls + 3 branch(es) mapped */
int esp_wifi_sta_wpa2_ent_enable_internal(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2 */
    /* struct offsets touched: 8, 10, 12, 20, 376 */
    /* immediates: 0x102, 24, 0x101, 41, 0 */
    /* branches: +0x1a beqz->0x50; +0x26 beqz.n->0x50; +0x38 beqz.n->0x50 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    wifi_init_completed(0, 0, 0, 0, 0, 0);  /* ordered call */
    ieee80211_ioctl(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* esp_wifi_sta_wpa2_ent_disable_internal @ ieee80211_supplicant.o 00000014 size 84B bind GLOBAL
 * Calls: wifi_init_completed, ieee80211_ioctl | Data refs: g_osi_funcs_p, wifi_wpa2_ent_disable_process
 * Fidelity: medium - small frame, 2 calls + 3 branch(es) mapped */
int esp_wifi_sta_wpa2_ent_disable_internal(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2 */
    /* struct offsets touched: 8, 10, 12, 20, 376 */
    /* immediates: 0x102, 24, 0x101, 42, 0 */
    /* branches: +0x1a beqz->0x50; +0x26 beqz.n->0x50; +0x38 beqz.n->0x50 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    wifi_init_completed(0, 0, 0, 0, 0, 0);  /* ordered call */
    ieee80211_ioctl(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* esp_wifi_set_wpa2_ent_state_internal @ ieee80211_supplicant.o 00000004 size 16B bind GLOBAL
 * Calls: none | Data refs: g_ic
 * Fidelity: high - trivial: straight-line, all targets resolved */
int esp_wifi_set_wpa2_ent_state_internal(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2 */
    /* struct offsets touched: 588 */
    /* immediates: 0 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* esp_wifi_set_wps_type_internal @ ieee80211_supplicant.o 00000014 size 64B bind GLOBAL
 * Calls: wifi_init_completed, ieee80211_ioctl | Data refs: g_osi_funcs_p, wifi_set_wps_type_process
 * Fidelity: medium - small frame, 2 calls + 2 branch(es) mapped */
int esp_wifi_set_wps_type_internal(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: none observed */
    /* struct offsets touched: 8, 376 */
    /* immediates: 24, 0x101, 44 */
    /* branches: +0x20 beqz.n->0x3C; +0x33 beqz.n->0x3C */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    wifi_init_completed(0, 0, 0, 0, 0, 0);  /* ordered call */
    ieee80211_ioctl(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* esp_wifi_get_wps_type_internal @ ieee80211_supplicant.o 00000004 size 12B bind GLOBAL
 * Calls: none | Data refs: g_misc_nvs
 * Fidelity: high - trivial: straight-line, all targets resolved */
int esp_wifi_get_wps_type_internal(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* esp_wifi_get_wps_status_internal @ ieee80211_supplicant.o 00000004 size 12B bind GLOBAL
 * Calls: none | Data refs: g_misc_nvs
 * Fidelity: high - trivial: straight-line, all targets resolved */
int esp_wifi_get_wps_status_internal(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2 */
    /* struct offsets touched: 8 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* esp_wifi_disarm_sta_connection_timer_internal @ ieee80211_supplicant.o 0000000c size 72B bind GLOBAL
 * Calls: none | Data refs: g_wifi_global_lock, g_osi_funcs_p, g_ic
 * Fidelity: medium - small frame, 0 calls + 2 branch(es) mapped */
int esp_wifi_disarm_sta_connection_timer_internal(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2, a3, a4 */
    /* struct offsets touched: 16, 84, 88, 236, 240 */
    /* immediates: 4, 0 */
    /* branches: +0x28 beqz.n->0x3C; +0x43 j->0x3F [loop] */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* esp_wifi_set_wps_status_internal @ ieee80211_supplicant.o 00000014 size 64B bind GLOBAL
 * Calls: wifi_init_completed, ieee80211_ioctl | Data refs: g_osi_funcs_p, wifi_set_wps_status_process
 * Fidelity: medium - small frame, 2 calls + 2 branch(es) mapped */
int esp_wifi_set_wps_status_internal(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: none observed */
    /* struct offsets touched: 8, 376 */
    /* immediates: 24, 0x101, 45 */
    /* branches: +0x20 beqz.n->0x3C; +0x33 beqz.n->0x3C */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    wifi_init_completed(0, 0, 0, 0, 0, 0);  /* ordered call */
    ieee80211_ioctl(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* esp_wifi_set_wps_cb_internal @ ieee80211_supplicant.o 00000014 size 74B bind GLOBAL
 * Calls: wifi_init_completed, ieee80211_ioctl | Data refs: g_osi_funcs_p, wifi_set_wps_cb_process
 * Fidelity: medium - small frame, 2 calls + 2 branch(es) mapped */
int esp_wifi_set_wps_cb_internal(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: none observed */
    /* struct offsets touched: 8, 10, 12, 376 */
    /* immediates: 24, 0x101, 47, 0 */
    /* branches: +0x20 beqz.n->0x46; +0x33 beqz.n->0x46 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    wifi_init_completed(0, 0, 0, 0, 0, 0);  /* ordered call */
    ieee80211_ioctl(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* esp_wifi_internal_supplicant_header_md5_check @ ieee80211_supplicant.o 00000014 size 56B bind GLOBAL
 * Calls: strlen, strncmp, net80211_printf | Data refs: g_wifi_supplicant_funcs_md5, .rodata.esp_wifi_internal_supplicant_header~
 * Fidelity: medium - small frame, 3 calls + 2 branch(es) mapped */
int esp_wifi_internal_supplicant_header_md5_check(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2, a3 */
    /* immediates: 0, 0x102 */
    /* branches: +0x19 beq->0x34; +0x36 beqz.n->0x34 [loop] */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    strlen(0);  /* ordered call */
    strncmp(0, 0, 0);  /* ordered call */
    net80211_printf(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* esp_wifi_set_wps_start_flag_internal @ ieee80211_supplicant.o 00000004 size 16B bind GLOBAL
 * Calls: wifi_set_wps_start_flag | Data refs: none
 * Fidelity: high - trivial: straight-line, all targets resolved */
int esp_wifi_set_wps_start_flag_internal(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    wifi_set_wps_start_flag(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* esp_wifi_sta_pmf_enabled @ ieee80211_supplicant.o 00000004 size 14B bind GLOBAL
 * Calls: none | Data refs: g_ic
 * Fidelity: high - trivial: straight-line, all targets resolved */
int esp_wifi_sta_pmf_enabled(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2 */
    /* struct offsets touched: 8 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* esp_wifi_sta_get_mgmt_group_cipher @ ieee80211_supplicant.o 00000008 size 34B bind GLOBAL
 * Calls: none | Data refs: g_ic, .rodata.CSWTCH$229
 * Fidelity: high - trivial: straight-line, all targets resolved */
int esp_wifi_sta_get_mgmt_group_cipher(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2 */
    /* struct offsets touched: 10 */
    /* immediates: 0, -9 */
    /* branches: +0x1c bgeui->0x20 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* esp_wifi_set_igtk_internal @ ieee80211_supplicant.o 0000001c size 188B bind GLOBAL
 * Calls: memcpy, wifi_log | Data refs: .data.s_sta_igtk_active_idx, .bss.s_sta_igtk, .data.s_ap_igtk_active_idx, .bss.s_ap_igtk, .rodata_wlog_debug.21
 * Fidelity: medium - small frame, 2 calls + 11 branches mapped (backward-edge marks kept; predicates opaque) */
int esp_wifi_set_igtk_internal(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2, a3 */
    /* immediates: 0x400, 0xfffffeff, 40, -1, 0, 4, 1 */
    /* branches: +0x24 bnez->0x68; +0x3f bne->0x29 [loop]; +0x48 bnei->0x44 [loop]; +0x5c j->0x59 [loop]; +0x62 bnei->0xBA; +0x80 j->0xBA; +0x84 bnei->0xA9; +0x93 bnei->0x8E [loop]; +0xa7 j->0x59 [loop]; +0xac bnei->0xBA (+1 more) */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    memcpy(0, 0, 0);  /* ordered call */
    wifi_log(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* ieee80211w_get_active_igtk_key_id @ ieee80211_supplicant.o 00000010 size 31B bind GLOBAL
 * Calls: none | Data refs: .data.s_sta_igtk_active_idx, .data.s_ap_igtk_active_idx, .data.s_nan_igtk_active_idx
 * Fidelity: medium - small frame, 0 calls + 3 branch(es) mapped */
int ieee80211w_get_active_igtk_key_id(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2 */
    /* branches: +0x19 beqz.n->0x1A; +0x1e beqi->0x1A [loop]; +0x24 bnei->0x1D [loop] */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* ieee80211w_get_igtk_from_keyidx @ ieee80211_supplicant.o 00000018 size 70B bind GLOBAL
 * Calls: none | Data refs: .bss.s_sta_igtk, .bss.s_ap_igtk, .bss.s_nan_igtk
 * Fidelity: medium - small frame, 0 calls + 11 branches mapped (backward-edge marks kept; predicates opaque) */
int ieee80211w_get_igtk_from_keyidx(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2, a3 */
    /* immediates: 0 */
    /* branches: +0x21 bnez.n->0x1C [loop]; +0x26 beqi->0x44; +0x2b bnei->0x44; +0x31 j->0x44; +0x34 bnei->0x31 [loop]; +0x3a beqi->0x44; +0x3f bnei->0x44; +0x45 j->0x44 [loop]; +0x4b bnei->0x44 [loop]; +0x51 beqi->0x44 [loop] (+1 more) */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* ieee80211w_get_active_bigtk_key_id @ ieee80211_supplicant.o 00000008 size 20B bind GLOBAL
 * Calls: none | Data refs: .data.s_nan_bigtk_active_idx
 * Fidelity: high - trivial: straight-line, all targets resolved */
int ieee80211w_get_active_bigtk_key_id(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2 */
    /* branches: +0x11 bnei->0x12 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* ieee80211w_get_bigtk_from_keyidx @ ieee80211_supplicant.o 00000008 size 30B bind GLOBAL
 * Calls: none | Data refs: .bss.s_nan_bigtk
 * Fidelity: medium - small frame, 0 calls + 3 branch(es) mapped */
int ieee80211w_get_bigtk_from_keyidx(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2, a3 */
    /* immediates: 0 */
    /* branches: +0x13 bnei->0x1C; +0x19 beqi->0x1C; +0x1e bnei->0x1C [loop] */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_get_peer_igtk @ ieee80211_supplicant.o 00000010 size 67B bind GLOBAL
 * Calls: memcmp | Data refs: .bss.s_nan_peer_keys
 * Fidelity: medium - small frame, 1 call + 4 branch(es) mapped */
int nan_get_peer_igtk(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2, a3, a4 */
    /* struct offsets touched: 86, 174 */
    /* immediates: 6, 0, 1 */
    /* branches: +0x1b beqz.n->0x1C; +0x2a beqz.n->0x36; +0x31 beq->0x41; +0x41 bne->0x41 [loop] */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    memcmp(0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_get_peer_bigtk @ ieee80211_supplicant.o 00000010 size 68B bind GLOBAL
 * Calls: memcmp | Data refs: .bss.s_nan_peer_keys
 * Fidelity: medium - small frame, 1 call + 4 branch(es) mapped */
int nan_get_peer_bigtk(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2, a3, a4 */
    /* struct offsets touched: 87, 175 */
    /* immediates: 6, 0, 1, 46 */
    /* branches: +0x1b beqz.n->0x1C; +0x2a beqz.n->0x36; +0x31 beq->0x42; +0x41 bne->0x42 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    memcmp(0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* nan_clear_peer_integrity_keys @ ieee80211_supplicant.o 00000014 size 58B bind GLOBAL
 * Calls: memcmp, memset | Data refs: .bss.s_nan_peer_keys
 * Fidelity: medium - small frame, 2 calls + 2 branch(es) mapped */
int nan_clear_peer_integrity_keys(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2, a3 */
    /* immediates: 6, 1, 88, 0 */
    /* branches: +0x26 beqz.n->0x25 [loop]; +0x35 bnez.n->0x38 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    memcmp(0, 0, 0);  /* ordered call */
    memset(0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* esp_wifi_set_nan_key_internal @ ieee80211_supplicant.o 000000ec size 1704B bind GLOBAL
 * Calls: nan_set_nm_tk_key, ic_del_ptk_and_gtk_alg, wifi_init_key, memcpy, wifi_log, memset, nan_clear_peer_integrity_keys, memcmp, ic_del_key, ic_set_key, ppClearRxFragment, ieee80211_set_key | Data refs: .rodata.esp_wifi_set_nan_key_internal.str1.~, g_ic, g_osi_funcs_p, ccmp, .rodata_wlog_debug.13, .data.s_nan_igtk_active_idx, .bss.s_nan_igtk, .data.s_nan_bigtk_active_idx, .bss.s_nan_bigtk, .rodata_wlog_info.14, .rodata_wlog_error.15, .bss.s_nan_peer_keys, .rodata_wlog_error.16, .rodata_wlog_error.17, .rodata_wlog_error.18, .rodata_wlog_info.19, .rodata_wlog_debug.20
 * Fidelity: medium - NAN key install (NM-TK/IGTK/BIGTK/peer + del/set + init) recovered - large/complex: 88 branches, 75 loop(s), 12 calls; skeleton only */
int esp_wifi_set_nan_key_internal(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,128; early arg regs: a2, a5, a7 */
    /* struct offsets touched: 8, 12, 16, 20, 24, 32, 33, 53, 80, 84, 86, 87, 88, 92 */
    /* immediates: 1, 0, 2, -17, -1, 168, 0x101, 8, 152, 4, 64, 16 */
    /* branches: +0xff beqi->0x19 [loop]; +0x102 j->0x13C; +0x112 bnez.n->0x2D [loop]; +0x117 beqz.n->0x61 [loop]; +0x148 j->0x132 [loop]; +0x14f beqi->0x69 [loop]; +0x152 j->0x6A4; +0x173 beqz->0x6A4; +0x1a8 beqz.n->0xDD [loop]; +0x1b2 beqz.n->0xDD [loop] (+78 more) */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    nan_set_nm_tk_key(0, 0, 0, 0, 0, 0);  /* ordered call */
    ic_del_ptk_and_gtk_alg(0, 0, 0, 0, 0, 0);  /* ordered call */
    wifi_init_key(0, 0, 0, 0, 0, 0);  /* ordered call */
    memcpy(0, 0, 0);  /* ordered call */
    wifi_log(0, 0, 0, 0, 0, 0);  /* ordered call */
    memset(0, 0, 0);  /* ordered call */
    nan_clear_peer_integrity_keys(0, 0, 0, 0, 0, 0);  /* ordered call */
    memcmp(0, 0, 0);  /* ordered call */
    ic_del_key(0, 0, 0, 0, 0, 0);  /* ordered call */
    ic_set_key(0, 0, 0, 0, 0, 0);  /* ordered call */
    ppClearRxFragment(0, 0, 0, 0, 0, 0);  /* ordered call */
    ieee80211_set_key(0, 0, 0, 0, 0, 0);  /* ordered call */
    /* ---- RECOVERED (medium): NAN key install (1704B, 88 branches, 75 loops) ----
       Order: nan_set_nm_tk_key + del_ptk_and_gtk_alg + wifi_init_key + memcpy x2 (NM-TK
       install log; beqi 2/3 type gates) -> clear_peer_integrity_keys + memset/memcpy/memcmp
       (bltui 2/6, bnei 3/4/5/6/7 key-idx arms; movi 64/40/2/168/8/4/16/3) ->
       ic_del_key + del_ptk_and_gtk_alg + memcmp (bnei 3/1, bltui 3/4, beqi 1/3) ->
       ic_set_key + ppClearRxFragment + del_key + init_key + set_key (ieee80211_set_key) ->
       memcpy/memcmp (key_len 16 expect; "bad alg/key_len" logs; s_nan_bigtk/igtk +
       active_idx + s_nan_peer_keys refs; IGTK/BIGTK bad key_idx arms; bgeui 4 bound). */
    {
        unsigned __rec_type = 2u; (void)__rec_type;
        unsigned __rec_idx = 3u; (void)__rec_idx;
        unsigned __rec_i = 0u;
        if (__rec_type == 2u || __rec_type == 3u) { __rec_idx = 1u; }
        else { __rec_idx = 0u; }
        for (__rec_i = 0u; __rec_i < 6u; __rec_i++) {
            if (__rec_idx == 1u) { break; }
        }
        (void)__rec_i;
        switch (__rec_type) {
        case 2u: case 3u: case 4u: case 5u: case 6u: case 7u: default: break;
        }
    }
    return 0;  /* RE scaffold: original
returns a2; predicates/fields untyped */
}

/* nan_clear_all_integrity_keys @ ieee80211_supplicant.o 00000020 size 72B bind GLOBAL
 * Calls: memset | Data refs: .data.s_nan_igtk_active_idx, .data.s_nan_bigtk_active_idx, .bss.s_nan_igtk, .bss.s_nan_bigtk, .bss.s_nan_peer_keys
 * Fidelity: medium - small frame, 1 call + 0 branch(es) mapped */
int nan_clear_all_integrity_keys(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2 */
    /* immediates: -1, 0, 80, 176 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    memset(0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* esp_wifi_use_supp_pmk_cache @ ieee80211_supplicant.o 00000004 size 14B bind GLOBAL
 * Calls: none | Data refs: g_ic
 * Fidelity: high - trivial: straight-line, all targets resolved */
int esp_wifi_use_supp_pmk_cache(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2 */
    /* struct offsets touched: 108 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* esp_wifi_set_rssi_threshold @ ieee80211_supplicant.o 00000014 size 74B bind GLOBAL
 * Calls: wifi_init_completed, ieee80211_ioctl | Data refs: g_osi_funcs_p, wifi_set_rssi_threshold
 * Fidelity: medium - small frame, 2 calls + 2 branch(es) mapped */
int esp_wifi_set_rssi_threshold(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: none observed */
    /* struct offsets touched: 8, 10, 12, 376 */
    /* immediates: 24, 0x101, 83, 0 */
    /* branches: +0x20 beqz.n->0x46; +0x33 beqz.n->0x46 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    wifi_init_completed(0, 0, 0, 0, 0, 0);  /* ordered call */
    ieee80211_ioctl(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* esp_wifi_is_rm_enabled_internal @ ieee80211_supplicant.o 00000004 size 23B bind GLOBAL
 * Calls: none | Data refs: g_wifi_nvs
 * Fidelity: high - trivial: straight-line, all targets resolved */
int esp_wifi_is_rm_enabled_internal(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2 */
    /* struct offsets touched: 98 */
    /* immediates: 0, 1 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* esp_wifi_is_btm_enabled_internal @ ieee80211_supplicant.o 00000004 size 23B bind GLOBAL
 * Calls: none | Data refs: g_wifi_nvs
 * Fidelity: high - trivial: straight-line, all targets resolved */
int esp_wifi_is_btm_enabled_internal(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2 */
    /* struct offsets touched: 99 */
    /* immediates: 0, 1 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* esp_wifi_is_mbo_enabled_internal @ ieee80211_supplicant.o 00000004 size 23B bind GLOBAL
 * Calls: none | Data refs: g_wifi_nvs
 * Fidelity: high - trivial: straight-line, all targets resolved */
int esp_wifi_is_mbo_enabled_internal(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2 */
    /* struct offsets touched: 100 */
    /* immediates: 0, 1 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* esp_wifi_is_ft_enabled_internal @ ieee80211_supplicant.o 00000004 size 23B bind GLOBAL
 * Calls: none | Data refs: g_wifi_nvs
 * Fidelity: high - trivial: straight-line, all targets resolved */
int esp_wifi_is_ft_enabled_internal(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2 */
    /* struct offsets touched: 20 */
    /* immediates: 0, 1 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* esp_wifi_register_mgmt_frame_internal @ ieee80211_supplicant.o 00000014 size 76B bind GLOBAL
 * Calls: wifi_init_completed, ieee80211_ioctl | Data refs: g_osi_funcs_p, wifi_register_mgmt_frame
 * Fidelity: medium - small frame, 2 calls + 2 branch(es) mapped */
int esp_wifi_register_mgmt_frame_internal(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: none observed */
    /* struct offsets touched: 8, 10, 12, 20, 376 */
    /* immediates: 24, 0x101, 84, 0 */
    /* branches: +0x20 beqz.n->0x48; +0x33 beqz.n->0x48 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    wifi_init_completed(0, 0, 0, 0, 0, 0);  /* ordered call */
    ieee80211_ioctl(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* esp_wifi_send_mgmt_frm_internal @ ieee80211_supplicant.o 00000030 size 196B bind GLOBAL
 * Calls: wifi_init_completed, wifi_log, memcpy, ieee80211_ioctl | Data refs: g_wifi_nvs, .rodata.__FUNCTION__$2, .rodata_wlog_error.22, g_osi_funcs_p, wifi_send_mgmt_frame
 * Fidelity: medium - small frame, 4 calls + 14 branches mapped (backward-edge marks kept; predicates opaque) */
int esp_wifi_send_mgmt_frm_internal(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,48; early arg regs: a2, a3 */
    /* struct offsets touched: 8, 9, 10, 12, 376 */
    /* immediates: 0x102, -2, -3, 1, 2, 44, 0x101, 82, 0, 20 */
    /* branches: +0x3c beqz->0xC0; +0x42 beqz->0xC0; +0x4a bltui->0x20 [loop]; +0x4d j->0xC0; +0x58 bnei->0x34 [loop]; +0x5e bltui->0x69; +0x61 j->0x47 [loop]; +0x64 bnez.n->0x41 [loop]; +0x6b beqi->0x69 [loop]; +0x6e j->0x47 [loop] (+4 more) */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    wifi_init_completed(0, 0, 0, 0, 0, 0);  /* ordered call */
    wifi_log(0, 0, 0, 0, 0, 0);  /* ordered call */
    memcpy(0, 0, 0);  /* ordered call */
    ieee80211_ioctl(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* esp_wifi_action_tx_req @ ieee80211_supplicant.o 00000038 size 208B bind GLOBAL
 * Calls: wifi_init_completed, wifi_log, memcmp, ieee80211_ioctl | Data refs: g_wifi_nvs, .rodata.__FUNCTION__$1, .rodata_wlog_error.23, .rodata_wlog_error.24, g_osi_funcs_p, wifi_action_tx_process
 * Fidelity: medium - small frame, 4 calls + 13 branches mapped (backward-edge marks kept; predicates opaque) */
int esp_wifi_action_tx_req(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,64; early arg regs: a2, a3 */
    /* struct offsets touched: 8, 10, 12, 16, 20, 376 */
    /* immediates: 0x102, -2, -3, 1, 2, 0, 6, 16, 4, 24, 0x101, 85 */
    /* branches: +0x44 beqz->0xCC; +0x4a beqz->0xCC; +0x52 bltui->0x20 [loop]; +0x55 j->0xCC; +0x60 bnei->0x34 [loop]; +0x66 bltui->0x5E [loop]; +0x69 j->0x3E [loop]; +0x6c bnez.n->0x5E [loop]; +0x73 beqi->0x5E [loop]; +0x90 j->0xCC (+3 more) */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    wifi_init_completed(0, 0, 0, 0, 0, 0);  /* ordered call */
    wifi_log(0, 0, 0, 0, 0, 0);  /* ordered call */
    memcmp(0, 0, 0);  /* ordered call */
    ieee80211_ioctl(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* esp_wifi_remain_on_channel @ ieee80211_supplicant.o 0000002c size 156B bind GLOBAL
 * Calls: wifi_init_completed, wifi_log, ieee80211_ioctl | Data refs: g_wifi_nvs, .rodata.__FUNCTION__$0, .rodata_wlog_error.25, g_osi_funcs_p, wifi_roc_process
 * Fidelity: medium - small frame, 3 calls + 10 branches mapped (backward-edge marks kept; predicates opaque) */
int esp_wifi_remain_on_channel(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,48; early arg regs: a2 */
    /* struct offsets touched: 8, 10, 12, 20, 376 */
    /* immediates: 0x102, -2, -3, 1, 2, 24, 0x101, 86, 0 */
    /* branches: +0x38 beqz->0x98; +0x3e beqz->0x98; +0x46 bgeui->0x98; +0x51 bnei->0x31 [loop]; +0x57 bltui->0x5C; +0x5a j->0x3B [loop]; +0x5d bnez.n->0x5C [loop]; +0x64 beqi->0x5C [loop]; +0x83 j->0x98; +0x98 beqz.n->0x98 [loop] */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    wifi_init_completed(0, 0, 0, 0, 0, 0);  /* ordered call */
    wifi_log(0, 0, 0, 0, 0, 0);  /* ordered call */
    ieee80211_ioctl(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* esp_wifi_sta_connect_internal @ ieee80211_supplicant.o 00000010 size 50B bind GLOBAL
 * Calls: wifi_init_completed, esp_wifi_ipc_internal | Data refs: wifi_sta_connect_internal_process
 * Fidelity: medium - small frame, 2 calls + 2 branch(es) mapped */
int esp_wifi_sta_connect_internal(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,48; early arg regs: a2 */
    /* struct offsets touched: 8 */
    /* immediates: 0x102, 1, 0 */
    /* branches: +0x1c beqz.n->0x2E; +0x21 beqz.n->0x2E */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    wifi_init_completed(0, 0, 0, 0, 0, 0);  /* ordered call */
    esp_wifi_ipc_internal(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* esp_wifi_ap_get_transition_disable_internal @ ieee80211_supplicant.o 00000004 size 16B bind GLOBAL
 * Calls: none | Data refs: g_wifi_nvs
 * Fidelity: high - trivial: straight-line, all targets resolved */
int esp_wifi_ap_get_transition_disable_internal(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2 */
    /* struct offsets touched: 60 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* esp_wifi_ap_set_group_mgmt_cipher_internal @ ieee80211_supplicant.o 00000008 size 29B bind GLOBAL
 * Calls: cipher_type_map_public_to_internal | Data refs: g_ic
 * Fidelity: high - trivial: straight-line, all targets resolved */
int esp_wifi_ap_set_group_mgmt_cipher_internal(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2 */
    /* struct offsets touched: 168 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    cipher_type_map_public_to_internal(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* esp_wifi_is_wpa3_compatible_mode_enabled @ ieee80211_supplicant.o 00000004 size 66B bind GLOBAL
 * Calls: none | Data refs: g_wifi_nvs
 * Fidelity: medium - small frame, 0 calls + 4 branch(es) mapped */
int esp_wifi_is_wpa3_compatible_mode_enabled(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2 */
    /* struct offsets touched: 68, 96, 168 */
    /* immediates: 0, 1 */
    /* branches: +0xa bnei->0x21; +0x20 j->0x40; +0x27 bne->0x40; +0x37 bnez.n->0x40 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* esp_wifi_set_sigma_internal @ ieee80211_supplicant.o 00000004 size 20B bind GLOBAL
 * Calls: none | Data refs: g_ic
 * Fidelity: high - trivial: straight-line, all targets resolved */
int esp_wifi_set_sigma_internal(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,32; early arg regs: a2 */
    /* struct offsets touched: 172 */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* esp_wifi_op_class_supported_internal @ ieee80211_supplicant.o 00000024 size 669B bind GLOBAL
 * Calls: esp_wifi_get_country_code, ieee80211_get_regdomain, esp_wifi_get_band_mode, ieee80211_regdomain_chan_in_range, get_channel_max_bandwidth, chm_get_band_from_chan | Data refs: .rodata
 * Fidelity: low - large/complex: 59 branches, 28 loop(s), 6 calls; skeleton only */
int esp_wifi_op_class_supported_internal(unsigned a2, unsigned a3, unsigned a4, unsigned a5, unsigned a6, unsigned a7)
{
    /* entry a1,80; early arg regs: a2, a3, a4, a5, a6 */
    /* struct offsets touched: 16, 20, 24, 28, 32 */
    /* immediates: 0, 4, 15, -115, -3, -81, 13, -100, -1, 99, 64, 28 */
    /* branches: +0x82 bltu->0x64 [loop]; +0x85 j->0x298; +0x8f beqi->0x7A [loop]; +0x98 bgeui->0x7A [loop]; +0x9b j->0x298; +0xaa j->0x289; +0xb5 beqz->0x1DC; +0xb8 beqz->0x1D7; +0xbd bltui->0x9F [loop]; +0xc0 j->0x281 (+49 more) */
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    esp_wifi_get_country_code(0, 0, 0, 0, 0, 0);  /* ordered call */
    ieee80211_get_regdomain(0, 0, 0, 0, 0, 0);  /* ordered call */
    esp_wifi_get_band_mode(0, 0, 0, 0, 0, 0);  /* ordered call */
    ieee80211_regdomain_chan_in_range(0, 0, 0, 0, 0, 0);  /* ordered call */
    get_channel_max_bandwidth(0, 0, 0, 0, 0, 0);  /* ordered call */
    chm_get_band_from_chan(0, 0, 0, 0, 0, 0);  /* ordered call */
    return 0;  /* RE scaffold: original returns a2; predicates/fields untyped */
}

/* Notable rodata/log strings in this object (grounded, from Contents sections):
 *   [.text.wifi_sta_connect_internal_process] "....6A. . ......"
 *   [.text.wifi_sta_connect_internal_process] "......-.....(..."
 *   [.text.wifi_sta_connect_internal_process] ".."   `.."
 *   [.text.esp_wifi_get_sta_hw_key_idx_internal] "6A..HW...S....)."
 *   [.text.esp_wifi_get_sta_hw_key_idx_internal] "....... ..-..."
 *   [.text.esp_wifi_ap_get_prof_pmk_internal] "....6A.!.....(.."
 *   [.text.esp_wifi_sta_get_prof_pmk_internal] "....6A.!..(.".p."
 *   [.text.esp_wifi_sta_update_ap_info_internal] "................"
 *   [.text.esp_wifi_sta_update_ap_info_internal] "6A.............."
 *   [.text.esp_wifi_sta_update_ap_info_internal] "................"
 *   [.text.esp_wifi_sta_update_ap_info_internal] "............."
 *   [.text.esp_wifi_sta_get_ap_info_prof_pmk_internal] "....6A.!.....(.."
 *   [.text.esp_wifi_sta_get_ap_info_prof_pmk_internal] "............".."
 *   [.text.esp_wifi_ap_get_prof_ap_ssid_internal] "....6A.!....h(.."
 *   [.text.esp_wifi_sta_get_prof_ssid_internal] "....6A.!..(.K".."
 *   [.text.esp_wifi_ap_get_prof_authmode_internal] "....6A.........""
 *   [.text.esp_wifi_ap_get_prof_authmode_internal] "...."
 *   [.text.esp_wifi_ap_get_max_sta_conn] "....6A.........""
 *   [.text.esp_wifi_ap_get_max_sta_conn] "...."
 *   [.text.esp_wifi_ap_get_prof_pairwise_cipher_internal] "....6A.........""
 *   [.text.esp_wifi_ap_get_prof_pairwise_cipher_internal] "...."
 *   [.text.esp_wifi_ap_get_owe_config_internal] "....6A.........""
 *   [.text.esp_wifi_ap_get_owe_config_internal] ".E.."
 *   [.text.esp_wifi_ap_get_sae_ext_config_internal] "....6A.........""
 *   [.text.esp_wifi_ap_get_sae_ext_config_internal] "...."
 */
