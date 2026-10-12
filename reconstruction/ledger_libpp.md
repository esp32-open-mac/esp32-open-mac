# libpp.a reconstruction ledger (ESP32)

Offline reverse-engineering of `libpp.a` (PHY/power/HAL layer) into reconstructed C
under `re/esp32/src/libpp/`. Sources of truth: `/tmp/re_esp32/libpp/*.o`,
`re/esp32/funcdb_libpp.json` (**funcdb v3**: `.rela.text.f` relocs matched, so
calls[] via R_XTENSA_ASM_EXPAND and refs[] globals are populated: 600 call edges,
1270 ref edges, exact per-function after the v3 sibling-section-bleed fix),
`re/esp32/disasm_full/libpp/*.dis`. Xtensa ABI:
args a2..a7, return a2. Toolchain esp-2022r1 (GCC 11.2.0).

Edge-source policy: per-function `Calls`/`Data refs` = UNION of funcdb v3 edges
(authoritative for direct calls + touched globals) and disasm evidence (GOT-slot
indirect calls e.g. pp_timer wrappers, LOCAL statics like pm_set_state, exact MMIO
literal values). Where disasm showed an unresolved indirect call but funcdb v3 names
a target, the emission carries a `funcdb v3 probable:` correction note.

Cross-check: 412 functions where funcdb refs confirm disasm data refs;
0 functions with funcdb-v3 call-target corrections on indirect calls;
86 functions touch MMIO with zero funcdb refs (pure-HAL MMIO,
disasm-only evidence: hal_mac_tx/rx/tsf/sniffer + pm predicates).
v3-vs-disasm call agreement: 0 v3 calls missed by disasm recovery
(disasm recovers every v3 direct call; union only adds GOT-indirect/static/tail
edges invisible to relocs: pp_timer wrappers, RC_GetDuration, pm_set_state, ...).

## Coverage

- funcdb functions: 706 (706 expected) | emitted C functions (incl. LOCAL statics): 751
- Every emitted file: braces balanced (asserted at generation).
- Sweep 2026-10-12 (small ≤256B lows): 8 moved to medium
  (`esf_buf_free_static`, `pm_beacon_monitor_tbtt_start`, `pm_update_params`,
  `pm_deattach`, `pm_set_sleep_type`, `pm_get_null_max_tx_time`,
  `pm_coex_update_wifi_time_slice_state`, `wDev_SnifferRxAmpdu` - flow + direct
  calls mapped, GOT-indirects enumerated); 5 kept low with sharpened notes
  (`esf_buf_recycle`, `TRC_AMPDU_PER_DOWN_THRESHOLD`,
  `TRC_AMPDU_PER_UP_THRESHOLD`, `trc_NeedRTS`, `rc11NRate2SchedIdx` - jx
  computed tail dispatch, case decode is the resolver).
- LOCAL statics (e.g. pm.o `pm_set_state`, pp_timer wrappers' siblings) emitted as
  `static` functions; stubs (0 code sections) recorded below.

| object | funcdb | emitted | mmio addrs |
|---|---|---|---|
| esf_buf.o | 12 | 12 | 0 |
| hal_ampdu.o | 6 | 6 | 8 |
| hal_coex.o | 0 | 0 | 0 |
| hal_crypto.o | 9 | 9 | 14 |
| hal_he_common.o | 0 | 0 | 0 |
| hal_mac.o | 49 | 49 | 100 |
| hal_mac_rx.o | 5 | 5 | 10 |
| hal_mac_tx.o | 9 | 9 | 14 |
| hal_pwr.o | 0 | 0 | 0 |
| hal_sniffer.o | 4 | 4 | 7 |
| hal_tsf.o | 5 | 5 | 5 |
| if_hecfg.o | 0 | 0 | 0 |
| if_hwctrl.o | 104 | 104 | 6 |
| lmac.o | 56 | 57 | 4 |
| pm.o | 138 | 158 | 6 |
| pm_beacon_offset.o | 30 | 32 | 1 |
| pm_coex.o | 9 | 9 | 2 |
| pm_extend.o | 0 | 0 | 0 |
| pm_mbssid.o | 0 | 0 | 0 |
| pm_twt.o | 0 | 0 | 0 |
| pp.o | 109 | 110 | 3 |
| pp_debug.o | 19 | 19 | 43 |
| pp_he.o | 0 | 0 | 0 |
| pp_he_ctrl.o | 0 | 0 | 0 |
| pp_test.o | 0 | 0 | 0 |
| pp_timer.o | 3 | 17 | 0 |
| pp_vht.o | 0 | 0 | 0 |
| rate_control.o | 6 | 7 | 0 |
| trc.o | 68 | 74 | 5 |
| wdev.o | 65 | 65 | 13 |

## Stub objects (480B, no .text — verify + record target)

- `hal_coex.o`: no code sections (only .comment/.xtensa.info). Contributes no functions;
- `hal_he_common.o`: no code sections (only .comment/.xtensa.info). Contributes no functions;
- `hal_pwr.o`: no code sections (only .comment/.xtensa.info). Contributes no functions;
- `if_hecfg.o`: no code sections (only .comment/.xtensa.info). Contributes no functions;
- `pm_extend.o`: no code sections (only .comment/.xtensa.info). Contributes no functions;
- `pm_mbssid.o`: no code sections (only .comment/.xtensa.info). Contributes no functions;
- `pm_twt.o`: no code sections (only .comment/.xtensa.info). Contributes no functions;
- `pp_he.o`: no code sections (only .comment/.xtensa.info). Contributes no functions;
- `pp_he_ctrl.o`: no code sections (only .comment/.xtensa.info). Contributes no functions;
- `pp_test.o`: no code sections (only .comment/.xtensa.info). Contributes no functions;
- `pp_vht.o`: no code sections (only .comment/.xtensa.info). Contributes no functions;
  related symbols (hal_coex_*, hal_pwr_*, pm_twt_*, pm_extend_*, pm_mbssid_*,
  pp_he/vht/he_ctrl, if_hecfg) resolve outside libpp.a (check libnet80211/libpp link).

## ic_* adapter/HAL surface defined here (101 functions)

NOTE: task brief estimated 102 `ic_*` functions; funcdb v3 recount =
101 defined in libpp.a. The delta is documented, not forced — the one
extra symbol (if any) is expected to resolve in libnet80211 (verify with a
cross-archive `nm`).

Called by the net80211 layer (ic_ebuf_alloc, ic_set_80211_tx_rate, ...). Full list:

### if_hwctrl.o
- `ic_add_rx_ba`
- `ic_ampdu_op`
- `ic_bb_check_noise_init`
- `ic_beacon_monitor_configure`
- `ic_beacon_offset_configure`
- `ic_beacon_offset_set_rx_beacon_standard`
- `ic_clear_data_ifx_tx_queue`
- `ic_clear_interrupt_handler`
- `ic_create_wifi_task`
- `ic_csi_set_config`
- `ic_deinit`
- `ic_del_key`
- `ic_del_key_all`
- `ic_del_ptk_and_gtk_alg`
- `ic_del_rx_ba`
- `ic_delete_wifi_task`
- `ic_disable_crypto`
- `ic_disable_rx`
- `ic_disable_sniffer`
- `ic_ebuf_alloc`
- `ic_ebuf_recycle_rx`
- `ic_ebuf_recycle_tx`
- `ic_enable_rx`
- `ic_enable_sniffer`
- `ic_get_80211_tx_rate`
- `ic_get_80211_tx_rate_config`
- `ic_get_G6M_sched`
- `ic_get_addr`
- `ic_get_default_sched`
- `ic_get_espnow_rate`
- `ic_get_fix_rate`
- `ic_get_keep_alive_time`
- `ic_get_key`
- `ic_get_next_bcnoffset`
- `ic_get_next_tbtt`
- `ic_get_pp_hdl`
- `ic_get_promis_ctrl_filter`
- `ic_get_promis_filter`
- `ic_get_ptk_alg`
- `ic_get_random`
- `ic_get_rssi`
- `ic_get_trc`
- `ic_init`
- `ic_interface_enabled`
- `ic_is_mgmt_hwdecr_enabled`
- `ic_is_pure_sta`
- `ic_mac_deinit`
- `ic_mac_init`
- `ic_obtain_key`
- `ic_pp_post`
- `ic_register_config_cb`
- `ic_register_csi_rx_cb`
- `ic_register_ftm_callbacks`
- `ic_register_michael_mic_failure_cb`
- `ic_register_nan_callbacks`
- `ic_register_net80211_tx_cb`
- `ic_register_pm_tx_null_cb`
- `ic_register_pp_tx_done_cb`
- `ic_register_promis_rx_cb`
- `ic_register_rx_cb`
- `ic_register_timer_cb`
- `ic_register_timer_post_cb`
- `ic_register_tx_cb`
- `ic_reset_rx_ba`
- `ic_reset_tbtt`
- `ic_rx_disable_bssid_check`
- `ic_rx_enable_bssid_check`
- `ic_set_80211_tx_rate`
- `ic_set_80211_tx_rate_config`
- `ic_set_ac_param`
- `ic_set_bar_rate`
- `ic_set_beacon_int`
- `ic_set_bssid`
- `ic_set_csi`
- `ic_set_current_channel`
- `ic_set_fix_rate`
- `ic_set_interface`
- `ic_set_interrupt_handler`
- `ic_set_keep_alive_time`
- `ic_set_key`
- `ic_set_mac`
- `ic_set_promis_ctrl_filter`
- `ic_set_promis_filter`
- `ic_set_rx_policy`
- `ic_set_rx_policy_ubssid_check`
- `ic_set_sleep_min_active_time`
- `ic_set_sleep_wait_broadcast_data_time`
- `ic_set_trc`
- `ic_set_vif`
- `ic_stop_hw_txq`
- `ic_stop_sw_txq`
- `ic_trc_set_per_pkt_rate`
- `ic_trc_update_def_rate`
- `ic_trc_update_ifx_phy_mode`
- `ic_tx_is_idle`
- `ic_tx_pkt`
- `ic_txq_empty`
- `ic_update_light_sleep_default_params`
- `ic_update_listen_interval`
- `ic_update_modem_sleep_default_params`
- `ic_update_trc_params`

## MMIO REGISTER MAP (dynamic-analysis hook list)

Address | Object.Func | R/W | Width | Purpose-if-known
|---|---|---|---|---|
| 0x3FF00024 | wdev.wdev_process_panic_watchdog | R/W | 32 | wdev |
| 0x3FF40078 | wdev.wdev_process_panic_watchdog | R | 32 | wdev |
| 0x3FF5D04C | if_hwctrl.bb_intr_handl | R | 32 | unknown - hook candidate |
| 0x3FF73080 | hal_mac.mac_rxbuf_init | R/W | 32 | unknown - hook candidate |
| 0x3FF73084 | hal_mac.hal_mac_rx_disable | R/W | 32 | RX path |
| 0x3FF73084 | hal_mac.hal_mac_rx_enable | R/W | 32 | RX path |
| 0x3FF73084 | hal_mac.mac_txrx_init | R/W | 32 | RX path |
| 0x3FF73084 | hal_mac_rx.hal_mac_rx_is_dscr_reload | R | 32 | RX path |
| 0x3FF73084 | hal_mac_rx.hal_mac_rx_set_dscr_reload | R/W | 32 | RX path |
| 0x3FF73084 | if_hwctrl.ic_disable_rx | R/W | 32 | unknown - hook candidate |
| 0x3FF73084 | if_hwctrl.ic_enable_rx | R/W | 32 | unknown - hook candidate |
| 0x3FF73084 | if_hwctrl.ic_set_vif | R/W | 32 | unknown - hook candidate |
| 0x3FF73084 | wdev.wdev_mac_sleep | R/W | 32 | power: sleep |
| 0x3FF73084 | wdev.wdev_mac_wakeup | R/W | 32 | power: wake |
| 0x3FF73088 | hal_mac.hal_enable_mac | W | 32 | unknown - hook candidate |
| 0x3FF73088 | hal_mac.hal_mac_rx_set_base | W | 32 | RX path |
| 0x3FF73088 | hal_mac.mac_rxbuf_init | W | 32 | unknown - hook candidate |
| 0x3FF73088 | wdev.wdev_record_rx_linked_list | R | 32 | RX path |
| 0x3FF7308C | hal_mac.hal_mac_rx_read_rxdscrnext | R | 32 | RX path |
| 0x3FF7308C | wdev.wdev_record_rx_linked_list | R | 32 | RX path |
| 0x3FF73090 | hal_mac.hal_mac_rx_read_rxdscrlast | R | 32 | RX path |
| 0x3FF73090 | hal_mac_rx.hal_mac_rx_get_last_dscr | R | 32 | RX path |
| 0x3FF73090 | wdev.wdev_record_rx_linked_list | R | 32 | RX path |
| 0x3FF73094 | pp_debug.dbg_lmac_hw_statis_dump | R | 32 | LMAC |
| 0x3FF73098 | wdev.wdev_record_rx_linked_list | R | 32 | RX path |
| 0x3FF7309C | hal_mac.hal_init | R/W | 32 | unknown - hook candidate |
| 0x3FF7309C | hal_mac.hal_mac_set_csi | R/W | 32 | unknown - hook candidate |
| 0x3FF7309C | hal_mac.mac_last_rxbuf_deinit | R/W | 32 | unknown - hook candidate |
| 0x3FF7309C | hal_mac.mac_last_rxbuf_init | R/W | 32 | unknown - hook candidate |
| 0x3FF730A4 | hal_mac_rx.hal_mac_rx_get_end_info | R | 32 | RX path |
| 0x3FF730A4 | hal_mac_rx.hal_mac_rx_get_end_state | R | 32 | RX path |
| 0x3FF730D8 | hal_mac.mac_txrx_init | R/W | 32 | RX path |
| 0x3FF730E4 | hal_sniffer.hal_sniffer_disable | R/W | 32 | sniffer |
| 0x3FF730E4 | hal_sniffer.hal_sniffer_enable | R/W | 32 | sniffer |
| 0x3FF730F4 | wdev.wdev_set_promis_misc_pkt | R/W | 32 | promiscuous |
| 0x3FF730F8 | hal_mac.mac_txrx_init | R/W | 32 | RX path |
| 0x3FF730F8 | hal_sniffer.hal_sniffer_rx_set_promis | R/W | 32 | sniffer |
| 0x3FF730F8 | if_hwctrl.ic_csi_set_config | R/W | 32 | unknown - hook candidate |
| 0x3FF730FC | hal_mac.mac_txrx_init | R/W | 32 | RX path |
| 0x3FF730FC | hal_sniffer.hal_sniffer_rx_set_promis | R/W | 32 | sniffer |
| 0x3FF730FC | if_hwctrl.ic_csi_set_config | R/W | 32 | unknown - hook candidate |
| 0x3FF73100 | hal_mac.mac_txrx_init | R/W | 32 | RX path |
| 0x3FF73104 | hal_mac.mac_txrx_init | R/W | 32 | RX path |
| 0x3FF73104 | hal_sniffer.hal_sniffer_rx_set_promis | R/W | 32 | sniffer |
| 0x3FF7310C | hal_mac.mac_txrx_init | R/W | 32 | RX path |
| 0x3FF73114 | hal_mac.mac_txrx_init | R/W | 32 | RX path |
| 0x3FF73118 | hal_mac.mac_rxbuf_init | W | 32 | unknown - hook candidate |
| 0x3FF7311C | hal_mac.mac_rxbuf_init | W | 32 | unknown - hook candidate |
| 0x3FF73120 | hal_mac.mac_rxbuf_init | W | 32 | unknown - hook candidate |
| 0x3FF73124 | hal_mac.mac_rxbuf_init | W | 32 | unknown - hook candidate |
| 0x3FF73148 | hal_mac.mac_last_rxbuf_deinit | R/W | 32 | unknown - hook candidate |
| 0x3FF73148 | hal_mac.mac_last_rxbuf_init | R/W | 32 | unknown - hook candidate |
| 0x3FF7314C | hal_mac.mac_last_rxbuf_deinit | W | 32 | unknown - hook candidate |
| 0x3FF7314C | hal_mac.mac_last_rxbuf_init | W | 32 | unknown - hook candidate |
| 0x3FF73158 | hal_mac.mac_last_rxbuf_deinit | W | 32 | unknown - hook candidate |
| 0x3FF73158 | hal_mac.mac_last_rxbuf_init | W | 32 | unknown - hook candidate |
| 0x3FF73164 | hal_mac.mac_last_rxbuf_deinit | W | 32 | unknown - hook candidate |
| 0x3FF73164 | hal_mac.mac_last_rxbuf_init | W | 32 | unknown - hook candidate |
| 0x3FF73250 | hal_ampdu.hal_ba_session_restore | R/W | 32 | unknown - hook candidate |
| 0x3FF73250 | hal_ampdu.hal_ba_session_store | R | 32 | unknown - hook candidate |
| 0x3FF7325C | hal_ampdu.hal_ba_session_restore | R/W | 32 | unknown - hook candidate |
| 0x3FF7325C | hal_ampdu.hal_ba_session_store | R | 32 | unknown - hook candidate |
| 0x3FF73260 | hal_ampdu.hal_ba_session_restore | W | 32 | unknown - hook candidate |
| 0x3FF73264 | hal_ampdu.hal_ba_session_restore | W | 32 | unknown - hook candidate |
| 0x3FF73268 | hal_ampdu.hal_ba_session_store | R | 32 | unknown - hook candidate |
| 0x3FF7326C | hal_ampdu.hal_ba_session_store | R | 32 | unknown - hook candidate |
| 0x3FF73284 | hal_mac_tx.hal_attenna_init | R/W | 32 | antenna table (sic) |
| 0x3FF73288 | hal_mac.hal_deinit | R/W | 32 | unknown - hook candidate |
| 0x3FF73288 | hal_mac.mac_txrx_init | R/W | 32 | RX path |
| 0x3FF7328C | pp_debug.dbg_lmac_hw_statis_dump | R | 32 | LMAC |
| 0x3FF73290 | pp_debug.dbg_lmac_hw_statis_dump | R | 32 | LMAC |
| 0x3FF73294 | pp_debug.dbg_lmac_hw_statis_dump | R | 32 | LMAC |
| 0x3FF73298 | pp_debug.dbg_lmac_hw_statis_dump | R | 32 | LMAC |
| 0x3FF7329C | pp_debug.dbg_lmac_hw_statis_dump | R | 32 | LMAC |
| 0x3FF732A0 | pp_debug.dbg_lmac_hw_statis_dump | R | 32 | LMAC |
| 0x3FF732A4 | pp_debug.dbg_lmac_hw_statis_dump | R | 32 | LMAC |
| 0x3FF732A8 | pp_debug.dbg_lmac_hw_statis_dump | R | 32 | LMAC |
| 0x3FF732AC | pp_debug.dbg_lmac_rxtx_statis_dump | R | 32 | LMAC |
| 0x3FF732B0 | pp_debug.dbg_lmac_hw_statis_dump | R | 32 | LMAC |
| 0x3FF732B4 | pp_debug.dbg_lmac_hw_statis_dump | R | 32 | LMAC |
| 0x3FF732B8 | pp_debug.dbg_lmac_hw_statis_dump | R | 32 | LMAC |
| 0x3FF732BC | pp_debug.dbg_lmac_hw_statis_dump | R | 32 | LMAC |
| 0x3FF732C0 | pp_debug.dbg_lmac_hw_statis_dump | R | 32 | LMAC |
| 0x3FF732C4 | pp_debug.dbg_lmac_hw_statis_dump | R | 32 | LMAC |
| 0x3FF732C8 | pp_debug.dbg_lmac_hw_statis_dump | R | 32 | LMAC |
| 0x3FF732CC | pp_debug.dbg_lmac_rxtx_statis_dump | R | 32 | LMAC |
| 0x3FF732D0 | pp_debug.dbg_lmac_rxtx_statis_dump | R | 32 | LMAC |
| 0x3FF732D8 | pp_debug.dbg_lmac_hw_statis_dump | R | 32 | LMAC |
| 0x3FF732DC | pp_debug.dbg_lmac_rxtx_statis_dump | R | 32 | LMAC |
| 0x3FF732E0 | pp_debug.dbg_lmac_hw_statis_dump | R | 32 | LMAC |
| 0x3FF732F0 | hal_mac_rx.hal_mac_rx_get_end_info | R | 32 | RX path |
| 0x3FF732F0 | pp_debug.dbg_lmac_diag_statis_dump | R | 32 | LMAC |
| 0x3FF732F4 | hal_mac_rx.hal_mac_rx_get_end_info | R | 32 | RX path |
| 0x3FF732F4 | pp_debug.dbg_lmac_diag_statis_dump | R | 32 | LMAC |
| 0x3FF732F4 | wdev.wdev_record_rx_linked_list | R | 32 | RX path |
| 0x3FF732F8 | hal_mac_rx.hal_mac_rx_get_end_info | R | 32 | RX path |
| 0x3FF732F8 | pp_debug.dbg_lmac_diag_statis_dump | R | 32 | LMAC |
| 0x3FF732FC | pp_debug.dbg_lmac_diag_statis_dump | R | 32 | LMAC |
| 0x3FF732FC | wdev.wdev_record_rx_linked_list | R | 32 | RX path |
| 0x3FF73400 | hal_mac_tx.hal_mac_rate_autoack_init | W | 32 | rate/auto-ACK table |
| 0x3FF73404 | hal_mac_tx.hal_mac_rate_autoack_init | W | 32 | rate/auto-ACK table |
| 0x3FF73408 | hal_mac_tx.hal_mac_rate_autoack_init | W | 32 | rate/auto-ACK table |
| 0x3FF7340C | hal_mac_tx.hal_mac_rate_autoack_init | W | 32 | rate/auto-ACK table |
| 0x3FF73410 | hal_mac_tx.hal_mac_rate_autoack_init | W | 32 | rate/auto-ACK table |
| 0x3FF73414 | hal_mac_tx.hal_mac_rate_autoack_init | W | 32 | rate/auto-ACK table |
| 0x3FF73418 | hal_mac.hal_mac_disable_low_rate | W | 32 | rate table |
| 0x3FF73418 | hal_mac.hal_mac_enable_low_rate | W | 32 | rate table |
| 0x3FF73418 | hal_mac_tx.hal_mac_rate_autoack_init | W | 32 | rate/auto-ACK table |
| 0x3FF7341C | hal_mac.hal_mac_disable_low_rate | W | 32 | rate table |
| 0x3FF7341C | hal_mac.hal_mac_enable_low_rate | W | 32 | rate table |
| 0x3FF7341C | hal_mac_tx.hal_mac_rate_autoack_init | W | 32 | rate/auto-ACK table |
| 0x3FF73424 | pp_debug.dbg_lmac_diag_statis_dump | R | 32 | LMAC |
| 0x3FF73428 | pp_debug.dbg_lmac_diag_statis_dump | R | 32 | LMAC |
| 0x3FF7342C | pp_debug.dbg_lmac_diag_statis_dump | R | 32 | LMAC |
| 0x3FF73430 | pp_debug.dbg_lmac_diag_statis_dump | R | 32 | LMAC |
| 0x3FF73800 | hal_crypto.hal_crypto_init | W | 32 | crypto key |
| 0x3FF73804 | hal_crypto.hal_crypto_disable | W | 32 | crypto key |
| 0x3FF73804 | hal_crypto.hal_crypto_init | W | 32 | crypto key |
| 0x3FF73804 | hal_crypto.hal_crypto_mgmt_rx_enabled | R | 32 | RX path |
| 0x3FF73808 | hal_crypto.hal_crypto_enable | R/W | 32 | crypto key |
| 0x3FF73808 | hal_crypto.hal_crypto_init | W | 32 | crypto key |
| 0x3FF7380C | hal_crypto.hal_crypto_init | W | 32 | crypto key |
| 0x3FF73810 | hal_crypto.hal_crypto_enable | R/W | 32 | crypto key |
| 0x3FF73810 | hal_crypto.hal_crypto_init | W | 32 | crypto key |
| 0x3FF73814 | hal_crypto.hal_crypto_clr_key_entry | R/W | 32 | crypto key |
| 0x3FF73814 | hal_crypto.hal_crypto_disable | R/W | 32 | crypto key |
| 0x3FF73814 | hal_crypto.hal_crypto_is_key_valid | R | 32 | crypto key |
| 0x3FF73814 | hal_crypto.hal_crypto_set_key_entry | R/W | 32 | crypto key |
| 0x3FF73C00 | hal_mac.hal_now | R | 32 | unknown - hook candidate |
| 0x3FF73C00 | lmac.lmacAdjustTimestamp | R | 32 | LMAC |
| 0x3FF73C00 | lmac.lmacMSDUAged | R | 32 | LMAC |
| 0x3FF73C00 | lmac.lmacProcessRxSucData | R | 32 | LMAC |
| 0x3FF73C00 | lmac.lmacSetTxFrame | R | 32 | LMAC |
| 0x3FF73C00 | pm.pm_tbtt_process | R | 32 | TBTT |
| 0x3FF73C00 | pm.pm_update_next_tbtt | R | 32 | TBTT |
| 0x3FF73C00 | pm_beacon_offset.pm_beacon_offset_sample | R | 32 | beacon |
| 0x3FF73C00 | pm_coex.pm_coex_recalculate_wifi_time_slice | R | 32 | coexistence |
| 0x3FF73C00 | pm_coex.pm_get_null_max_tx_time | R | 32 | power management |
| 0x3FF73C00 | pp.ppReSendBar | R | 32 | unknown - hook candidate |
| 0x3FF73C00 | pp.ppRxFragmentProc | R | 32 | unknown - hook candidate |
| 0x3FF73C00 | pp.ppTxPkt | R | 32 | unknown - hook candidate |
| 0x3FF73C00 | pp_debug.dbg_perf_throughput_cal | R | 32 | RF |
| 0x3FF73C00 | trc.rcAmpduLowerRate | R | 32 | AMPDU/BA |
| 0x3FF73C00 | trc.rcLowerSched | R | 32 | unknown - hook candidate |
| 0x3FF73C00 | trc.rcUpSched | R | 32 | unknown - hook candidate |
| 0x3FF73C00 | trc.rcUpdateRate | R | 32 | rate table |
| 0x3FF73C00 | trc.rcUpdateTxDoneAmpdu2 | R | 32 | AMPDU/BA |
| 0x3FF73C04 | hal_mac.hal_disable_mac | R/W | 32 | unknown - hook candidate |
| 0x3FF73C04 | hal_mac.hal_enable_mac | R/W | 32 | unknown - hook candidate |
| 0x3FF73C04 | wdev.wdev_mac_wakeup | R/W | 32 | power: wake |
| 0x3FF73C1C | hal_mac.mac_txrx_init | R/W | 32 | RX path |
| 0x3FF73C20 | hal_mac.mac_txrx_init | R/W | 32 | RX path |
| 0x3FF73C24 | hal_mac.mac_txrx_init | R/W | 32 | RX path |
| 0x3FF73C30 | hal_mac.hal_disable_mac | W | 32 | unknown - hook candidate |
| 0x3FF73C40 | hal_mac.hal_deinit | R/W | 32 | unknown - hook candidate |
| 0x3FF73C40 | hal_mac.hal_disable_mac | R/W | 32 | unknown - hook candidate |
| 0x3FF73C40 | hal_mac.hal_enable_mac | W | 32 | unknown - hook candidate |
| 0x3FF73C40 | hal_mac.hal_init | W | 32 | unknown - hook candidate |
| 0x3FF73C40 | hal_sniffer.hal_sniffer_rx_set_promis | R | 32 | sniffer |
| 0x3FF73C44 | hal_mac.hal_disable_mac | W | 32 | unknown - hook candidate |
| 0x3FF73C48 | hal_mac.hal_mac_interrupt_get_event | R | 32 | unknown - hook candidate |
| 0x3FF73C4C | hal_mac.hal_deinit | W | 32 | unknown - hook candidate |
| 0x3FF73C4C | hal_mac.hal_init | W | 32 | unknown - hook candidate |
| 0x3FF73C4C | hal_mac.hal_mac_interrupt_clr_event | W | 32 | unknown - hook candidate |
| 0x3FF73C4C | hal_mac.hal_mac_interrupt_clr_watchdog | R/W | 32 | unknown - hook candidate |
| 0x3FF73C54 | hal_mac.mac_txrx_init | R/W | 32 | RX path |
| 0x3FF73C58 | hal_mac.hal_mac_deinit | R/W | 32 | unknown - hook candidate |
| 0x3FF73C58 | hal_mac.hal_mac_tx_set_cca | R/W | 32 | CCA |
| 0x3FF73C5C | hal_mac.mac_txrx_init | R/W | 32 | RX path |
| 0x3FF73C6C | hal_mac.mac_txrx_init | R/W | 32 | RX path |
| 0x3FF73C74 | hal_mac.mac_txrx_init | R/W | 32 | RX path |
| 0x3FF73C78 | hal_mac.mac_txrx_init | R/W | 32 | RX path |
| 0x3FF73C88 | hal_mac.mac_txrx_init | R/W | 32 | RX path |
| 0x3FF73CAC | hal_mac.mac_txrx_init | R/W | 32 | RX path |
| 0x3FF73CB8 | hal_mac.hal_mac_deinit | R/W | 32 | unknown - hook candidate |
| 0x3FF73CB8 | hal_mac.hal_mac_init | R/W | 32 | unknown - hook candidate |
| 0x3FF73CB8 | pm.hal_pm_unblock_txq | R/W | 32 | TX queue |
| 0x3FF73CB8 | pm.pm_coex_go_to_sleep | R/W | 32 | coexistence |
| 0x3FF73CB8 | pm.pm_coex_schm_process | R/W | 32 | coexistence |
| 0x3FF73CB8 | pm.pm_off_channel | R/W | 32 | power management |
| 0x3FF73CBC | hal_mac_tx.hal_mac_clr_txq_state | R/W | 32 | TX queue |
| 0x3FF73CC0 | hal_mac_tx.hal_mac_get_txq_state | R | 32 | TX queue |
| 0x3FF73CC4 | hal_mac_tx.hal_mac_clr_txq_state | R/W | 32 | TX queue |
| 0x3FF73CC8 | hal_mac_tx.hal_mac_get_txq_state | R | 32 | TX queue |
| 0x3FF73D24 | hal_mac.hal_deinit | R/W | 32 | unknown - hook candidate |
| 0x3FF73D24 | hal_mac.hal_init | R/W | 32 | unknown - hook candidate |
| 0x3FF73D58 | pp_debug.dbg_lmac_hw_statis_dump | R | 32 | LMAC |
| 0x3FF73D5C | pp_debug.dbg_lmac_hw_statis_dump | R | 32 | LMAC |
| 0x3FF73D60 | pp_debug.dbg_lmac_hw_statis_dump | R | 32 | LMAC |
| 0x3FF73D64 | pp_debug.dbg_lmac_hw_statis_dump | R | 32 | LMAC |
| 0x3FF73D68 | pp_debug.dbg_lmac_hw_statis_dump | R | 32 | LMAC |
| 0x3FF73D6C | pp_debug.dbg_lmac_hw_statis_dump | R | 32 | LMAC |
| 0x3FF73D70 | pp_debug.dbg_lmac_hw_statis_dump | R | 32 | LMAC |
| 0x3FF73D78 | hal_mac.mac_txrx_init | R/W | 32 | RX path |
| 0x3FF73D7C | hal_sniffer.hal_sniffer_rx_clr_statistics | R/W | 32 | sniffer |
| 0x3FF73D84 | hal_mac_rx.hal_mac_rx_get_end_info | R | 32 | RX path |
| 0x3FF73D88 | hal_mac_rx.hal_mac_rx_get_end_info | R | 32 | RX path |
| 0x3FF73DAC | pp_debug.dbg_lmac_diag_statis_dump | R | 32 | LMAC |
| 0x3FF73DB0 | pp_debug.dbg_lmac_diag_statis_dump | R | 32 | LMAC |
| 0x3FF73DB4 | pp_debug.dbg_lmac_diag_statis_dump | R | 32 | LMAC |
| 0x3FF73DB8 | pp_debug.dbg_lmac_diag_statis_dump | R | 32 | LMAC |
| 0x3FF73DBC | pp_debug.dbg_lmac_diag_statis_dump | R | 32 | LMAC |
| 0x3FF7425C | hal_mac_tx.hal_attenna_init | R/W | 32 | antenna table (sic) |
| 0x3FF7442C | hal_crypto.hal_crypto_get_using_key_idx | R | 32 | crypto key |
| 0x3FF75010 | hal_mac.hal_get_tsf_time | R/W | 32 | TSF timer |
| 0x3FF75010 | hal_mac.hal_mac_tsf_get_time | R/W | 32 | TSF timer |
| 0x3FF75010 | hal_mac.hal_mac_tsf_reset | R/W | 32 | TSF timer |
| 0x3FF75010 | hal_mac.hal_mac_tsf_set_time | R/W | 32 | TSF timer |
| 0x3FF75014 | hal_mac.hal_get_tsf_time | R | 32 | TSF timer |
| 0x3FF75018 | hal_mac.hal_get_tsf_time | R | 32 | TSF timer |
| 0x3FF75020 | hal_mac.hal_mac_tsf_reset | R/W | 32 | TSF timer |
| 0x3FF75020 | hal_tsf.hal_disable_sta_tsf | R/W | 32 | TSF timer |
| 0x3FF75020 | hal_tsf.hal_enable_sta_tsf | R/W | 32 | TSF timer |
| 0x3FF75024 | hal_mac.hal_mac_tsf_reset | W | 32 | TSF timer |
| 0x3FF75028 | hal_mac.hal_mac_tsf_reset | W | 32 | TSF timer |
| 0x3FF75054 | hal_mac.hal_get_tsf_time | R | 32 | TSF timer |
| 0x3FF75054 | hal_mac.hal_mac_tsf_get_time | R | 32 | TSF timer |
| 0x3FF75058 | hal_mac.hal_get_tsf_time | R | 32 | TSF timer |
| 0x3FF7505C | hal_mac.hal_mac_tsf_reset | R/W | 32 | TSF timer |
| 0x3FF7505C | hal_tsf.hal_disable_softap_tsf | R/W | 32 | TSF timer |
| 0x3FF75060 | hal_mac.hal_mac_tsf_reset | W | 32 | TSF timer |
| 0x3FF75060 | hal_mac.hal_mac_tsf_set_time | W | 32 | TSF timer |
| 0x3FF75064 | hal_mac.hal_mac_tsf_reset | W | 32 | TSF timer |
| 0x3FF75064 | hal_mac.hal_mac_tsf_set_time | W | 32 | TSF timer |
| 0x3FF75090 | hal_mac.hal_mac_tsf_get_time | R | 32 | TSF timer |
| 0x3FF75094 | hal_mac.hal_mac_tsf_get_time | R | 32 | TSF timer |
| 0x3FF75098 | hal_mac.hal_mac_tsf_reset | R/W | 32 | TSF timer |
| 0x3FF75098 | hal_tsf.hal_disable_nan_tsf | R/W | 32 | TSF timer |
| 0x3FF75098 | hal_tsf.hal_enable_nan_tsf | R/W | 32 | TSF timer |
| 0x3FF7509C | hal_mac.hal_mac_tsf_reset | W | 32 | TSF timer |
| 0x3FF7509C | hal_mac.hal_mac_tsf_set_time | W | 32 | TSF timer |
| 0x3FF750A0 | hal_mac.hal_mac_tsf_reset | W | 32 | TSF timer |
| 0x3FF750A0 | hal_mac.hal_mac_tsf_set_time | W | 32 | TSF timer |
| 0x3FF75144 | hal_mac.hal_random | R | 32 | unknown - hook candidate |
| 0x6001C06C | wdev.wDev_ProcessFiq | R | 32 | wdev |
| 0x6001C860 | hal_mac.hal_mac_disable_low_rate | R/W | 32 | rate table |
| 0x6001C860 | hal_mac.hal_mac_enable_low_rate | R/W | 32 | rate table |
| 0x6001C860 | hal_mac.hal_mac_is_low_rate_enabled | R | 32 | rate table |
| 0x6001C87C | hal_mac.hal_mac_disable_low_rate | R/W | 32 | rate table |
| 0x6001C87C | hal_mac.hal_mac_enable_low_rate | R/W | 32 | rate table |
| 0x6001C87C | hal_mac.hal_mac_is_low_rate_enabled | R | 32 | rate table |

Notes:
- `?` direction = literal referenced but no width-tagged access resolved in-function
  (usually GOT/pointer chains); hook the address and confirm direction at runtime.
- Loop-indexed tables (antenna/PMD, stride 60B) are emitted with first-iteration
  addresses; hook the base with a range covering 8 entries (480B).
- 0x3FF7xxxx = WiFi MAC region; 0x6001C8xx = modem/system control;
  0x3FFAXXXX = DRAM heap/buffers (esf_buf, not MMIO - excluded where identified).

## Upgrade pass 2026-10-12 (low -> medium, offline, disasm-grounded)

Only `Fidelity: low` function touched; all others byte-identical. Braces balanced.

| file | function(size) | old -> new | unlock notes |
|---|---|---|---|
| pp.c | ppRxFragmentProc(1109B, .wifirxiram.26) | low -> medium | fragment reassembly (s_fragment null -> recycle/clear; mesh gates is_started/is_root/init_ps + osi+0x110 indirect; REG32(0x3FF73C00 MMIO)+time_delta vs lmacConfMib window bgeu; ptk_alg + TID/seq extui chain; hdrsize FC arms bnei 2/4; frag link + gettid x2 + memcmp + seq gates; TKIP-MIC via obtain_key/CalTkipMic/memcmp + mic-fail cb) |

## Mid-size (257–1024B) pass 2026-10-12 (offline, disasm-grounded)

Only in-range `Fidelity: low` functions touched (33 low->medium, 5 sharpened
low); others byte-identical. Braces balanced; non-Fidelity lines identical.
All upgraded functions verified loop-free in the true-loop sense (0 backward
conditionals, 0 `loop` insns) with no `jx`; counts preserved from headers.

- Upgraded to medium (flow + direct calls mapped, GOT-indirects enumerated):
  `esf_buf_alloc_dynamic`(452B), `ic_set_vif`(431B), `lmacTxFrame`(622B),
  `lmacEndFrameExchangeSequence`(682B), `lmacProcessShortRetryFail`(479B),
  `pm_dream`(314B), `pm_sleep`(499B), `pm_update_by_connectionless_status`(318B),
  `pm_set_next_tbtt`(558B), `pm_update_next_tbtt`(734B),
  `pm_tx_null_data_done_process`(668B), `pm_process_tim`(343B),
  `pm_tx_data_process`(507B), `pm_start`(466B), `pm_stop`(514B),
  `pm_enable_beacon_monitor_timer`(290B), `pm_tbtt_process`(419B),
  `pm_beacon_offset_get_params`(587B), `pm_beacon_offset_check`(453B),
  `pp_create_task`(378B), `pp_post`(322B), `ppTxPkt`(475B),
  `ppCalTxAMPDULength`(692B), `ppResortTxAMPDU`(1010B),
  `dbg_lmac_hw_statis_dump`(503B), `rcUpdateTxDoneAmpdu2`(807B),
  `rcUpdateRate`(509B), `wdev_csi_rx_process`(274B),
  `wDev_SnifferRxData`(604B), `wDev_Rxbuf_Init`(498B),
  `wDev_IndicateFrame`(662B), `wDev_IndicateAmpdu`(752B),
  `wDev_ProcessRxSucData`(905B).
- Sharpened, remain low: `esf_buf_alloc`(jx +0x3b), `lmacProcessTxComplete`
  (jx +0x145), `ppTask`(jx +0xf8), `rssi_margin`(jx +0x27, rssi_margin table),
  `mac_txrx_init`(loop +0x99, MMIO 0x3FF730D8) — each note cites exact
  bounds/table/jx offsets + case-decode or loop-trip resolver. phy/coex
  functions untouched (other workers).
