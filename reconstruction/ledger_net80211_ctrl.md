# ledger_net80211_ctrl — ESP32 libnet80211 control-path reconstruction

Scope: 14 objects of `esp32/libnet80211.a` → `re/esp32/src/libnet80211/<object>.c`
(692 code sections recovered). Fully offline (objdump -d -r + readelf + nm).
Ground truth = section relocs (`R_XTENSA_ASM_EXPAND` → calls,
`R_XTENSA_32` literal pool → data refs). Disasm snapshots:
`/tmp/re_ctrl/disasm/*.dis`. Generator: `/tmp/re_ctrl/gen.py`.

## 1. Fidelity table (per-function headers in the .c files)

| object | funcs | high | medium | low |
|---|---|---|---|---|
| ieee80211_api.o | 236 | 27 | 194 | 15 |
| ieee80211_ioctl.o | 197 | 51 | 117 | 29 |
| ieee80211_sta.o | 41 | 12 | 25 | 4 |
| wl_cnx.o | 78 | 17 | 44 | 17 |
| ieee80211.o | 30 | 9 | 19 | 2 |
| ieee80211_proto.o | 7 | 2 | 5 | 0 |
| ieee80211_timer.o | 37 | 17 | 19 | 1 |
| ieee80211_nvs.o | 29 | 7 | 18 | 4 |
| ieee80211_power.o | 16 | 2 | 14 | 0 |
| ieee80211_ets.o | 2 | 0 | 2 | 0 |
| ieee80211_debug.o | 3 | 0 | 2 | 1 |
| ieee80211_rfid.o | 6 | 3 | 3 | 0 |
| ieee80211_ie_vendor.o | 8 | 0 | 8 | 0 |
| test.o | 2 | 0 | 2 | 0 |
| TOTAL | 692 | 147 | 473 | 72 |

Sweep 2026-10-12 (small ≤256B lows): this worker upgraded 3 to high
(nan_key_is_all_ff constprop, is_valid_sta_mac, register_hostap_timer - exact
bodies) and 46 to medium (loop-free, EXPAND+funcdb-v3 verified); 2 kept low
with sharpened notes (esp_wifi_set_protocol jx switch, timer_do_process table
loop). Table recount reflects the files; rows for ioctl/sta/wl_cnx/test also
include upgrades by parallel workers (low 48→29, 11→4, 27→17, high 1→0).

Grading: high = straight-line ≤14 insns fully mapped; medium = loop-free,
call sequence mapped, predicates opaque; low = loops/multi-branch skeleton
(ordered calls + memop offsets + immediates, no invented conditions).

## 2. funcdb versions (v2 → v3)

- v1 (task start): calls[]/refs[] empty (unmatched `.rela.text.<f>` sections).
- v2: populated, but caller-side rela-section **prefix collision**: funcdb-only
  edges (68) with NO exact reloc in the callee's own section, all involving a
  longer sibling (`cnx_assoc_timeout`←`..._process` edges,
  `ieee80211_find_elem`/`find_ie` off-by-one shift, `wifi_deinit`→`wifi_deinit`
  self entry = truncated `wifi_deinit_in_caller_task`,
  `esp_wifi_config_80211_tx`→`ic_set_80211_tx_rate` = truncated
  `ic_set_80211_tx_rate_config`), plus `relsec:null` gaps (`sta_input` 14 calls,
  `wifi_rf_phy_enable/disable`, `wifi_ant_update`, all static locals).
  Disasm ground truth kept; v2 edges adopted only with exact-reloc proof.
- v3: exact. Machine cross-check per object (in each .c prologue):
  **1377 funcdb edges confirmed by exact section relocs, 0 rejected**;
  255 disasm-only edges kept (static-local callees such as
  `wifi_station_get_config_local`, plus remaining funcdb gaps).
  v3 `refs[]` likewise exact (e.g. `ieee80211_ioctl` refs = 2 rodata +
  `g_osi_funcs_p` + 8 call-targets, matching the literal pool).

## 3. IPC dispatch map (WiFi-task handlers in scope: 98 `*_process`, 18 `*_timeout`)

- Transport: caller builds req → `pp_post(type 6, …)` or `g_osi_funcs_p+176/+68`
  indirection → `ieee80211_ioctl` gate → `ieee80211_ioctl_process` in task
  (`handler = *(req+4)`, `pm_wake_up/done` pairing except cmd ranges
  [52,54] and [57,81]) → `wifi_*_process` handler.
- Lifecycle: `wifi_init/start/stop/deinit/restart/restore_process`,
  `wifi_hw_start/stop`, `wifi_rf_phy_enable/disable`, `wifi_reset_mac`.
- STA: `wifi_connect/disconnect_process`, `wifi_scan_start/stop_process`,
  `wifi_sta_*` (change_mac, save_ap_channel, disconnect), STA timers
  (`cnx_assoc/auth/handshake/beacon/connect_next_ap/csa_timeout_process`,
  `send_wake_null_timeout_process`, `mgd_probe_send_timeout_process`).
- Config set/get pairs: mode/bw/channel/home_channel/protocol(s)/ps/country/
  band(_mode)/scan_params/ap_list/ap_record/ap_info/sta_list/tsf/mac/promis/
  fix_rate/appie/vnd_ie/log_mod/event_mask/csi/rssi/wps/type/status/rxcb.
- AP: `wifi_deauth_sta_process`, `wifi_ap_remove_sta_node_process`,
  `wifi_ap_sta_sae_auth_done_process`, `wifi_set_mac_process`.
- Mesh (`*_progress` + ps): ie_crypto_funcs/key_set, parent_candidate/monitor,
  router_bssid, rssi_threshold, roots_ie/ie get/set/init/deinit, beacon_interval,
  sta_disassoc, switch_channel, assoc_expire, root_conflicts, ps_duty set/get/ext,
  act_duty_signaling, map_deauth.
- NAN/NDP: `wifi_nan_{config,publish,subscribe,followup}_process`,
  `wifi_ndp_{req,resp,end}_process`, thin `ieee80211_nan_*` timer wrappers.
- Coex/PM/power: `wifi_coex_pwr_process`, `wifi_on_coex_{start,schm_phase}_process`,
  `wifi_force_wakeup_process`, `wifi_update_listen_interval_process`,
  `wifi_configure_wake_{window,interval}_process`, `wifi_sample_beacon_process`,
  `wifi_tbtt_quick_wake_configure_process`, `wifi_disable_pmf_config_process`.
- WPS/WPA2: `wifi_set_wps_{start_flag,type,status,cb}_process`,
  `wifi_wpa2_ent_{enable,disable}_process`, `wifi_{wps,wpa2}_is_started`.
- Misc: `wifi_roc/action_tx_process`, `wifi_offchan_cancel_process`,
  `wifi_send_mgmt_frame`, `wifi_register_mgmt_frame`, `wifi_set_rssi_threshold`,
  `wifi_set_dynamic_cs_process`, `wifi_softap_set_obss_overlap_process`,
  `wifi_get/set_partial_ru_max_txpwr_process`, timer dispatch
  (`ieee80211_timer_process` gate, `ieee80211_timer_do_process` id table).

## 4. Recovered structs / globals (offsets observed in disasm; layout unconfirmed)

- `s_ioctl_table` (`ieee80211_ioctl.o`, `.data` 24B = 3×{u32 id; u32 handler},
  via `objdump -s` + `.rela.data.s_ioctl_table`): 1→`wifi_ioctl_ht2040_set`,
  2→`wifi_ioctl_ht2040_get`, 3→NULL. Consumed where TBD (only 3 ids).
- `ioctl_req` (≥5 offsets in `ieee80211_ioctl[_process]`): u8@0 cmd id
  (range vs 121; special 49), u8@1 flags (bit0 in-task, bit1 cont, mask 2 bits),
  u32@4 handler ptr, u32@12 status slot, u32@16 completion slot.
- `timer_entry` (`g_timer_info`, stride 8 via `addx8`): u8@0 id (max 35),
  u32@4 handler; 36-entry linear-search fallback (`movi 36, loop`).
- Byte-maps: `CSWTCH$424` (4B `02 00 01 02`, SAE-PWE map 0..3, dflt −1),
  `CSWTCH$491` (11B, cipher map 0..10, bounds 10/12),
  `CSWTCH$391` (10B, consulted by `wifi_softap_set_config`, index TBD).
- `g_osi_funcs_p` indirect-call slots (u32 loads → callx): +0, +8, +52, +64,
  +68, +176, +232, +364 (0x16c). Semantics per slot TBD.
- `g_ic` offsets: +0, +16, +20, +100, +116 (mesh-root gate), +228, +232,
  +0x1c4 (RFID cb slot), +0x2c8 (deinit).
- `g_cnxMgr` offsets: +0, +4, +12, +16, +20, +88, +96, +116, +174, +688.
- `g_wifi_menuconfig` offsets incl. +56 (beacon size floor), +80 (softap max).
- RFID: single cb slot `g_ic+0x1c4`; recv-on = bit0 of `*(arg+4)` && slot.
- Error/return consts (verbatim immediates): 0x101, 0x102, 0x3001, −1.

## 5. Unknowns (not in disasm; do not invent)

osi slot semantics; init-state enum (3 = ?); 0x101/0x102/0x3001 code meanings;
full `ioctl_req` layout; `CSWTCH$391` index; `g_timer_info` table size origin;
pm-wake bypass rationale for cmds [52,54]/[57,81]; `.wifislprxiram` placement
(`wifi_rf_phy_*`); weak-symbol resolution (`adc2_wifi_*`,
`map_wifi_config_sae_pwe_to_supp`); `g_wifi_nvs` addmi-scaled (+0x40000-class)
keyederivation.

## 6. Verification

- Coverage: every `.text.*`/`.wifislprxiram.*` code section of the 14 objects
  has exactly one reconstructed function (692 total; 614 with funcdb entries,
  78 static locals by section name). Braces balanced per file (asserted at
  generation). Re-run: `cd /tmp/re_ctrl && python3 gen.py` (writes the 14
  `.c` files + `/tmp/re_ctrl/stats.json`).

## 7. Upgrade pass 2026-10-12 (low -> medium, offline, disasm-grounded)

Only `Fidelity: low` functions touched; others byte-identical. Braces balanced.

| file | function(size) | old -> new | unlock notes |
|---|---|---|---|
| ieee80211_sta.c | ieee80211_sta_new_state(3592B) | low -> medium | STA state machine (movi 0-6 states via state_desc$0; per-state arms: leave/blacklist/send_mgmt/ptk/coex/event; s_disconnect_evt_pending slots; predicates opaque) |
| ieee80211_sta.c | sta_recv_mgmt(2691B) | low -> medium | STA mgmt dispatch (beqi 128 beacon, 16 auth-seq, 1/5/2/3/4 cat gates; arms in call order incl. csa, auth variants, assoc, action/offchan, SA-query, new_state) |
| ieee80211_sta.c | sta_recv_assoc(1672B) | low -> medium | assoc-resp IE application order (find_ie beqi 3; rates/phy/HT/WME/OBSS/idle/shortslot/rx_policy/new_state) |
| ieee80211_sta.c | sta_input(1418B) | low -> medium | STA RX fork (FC extui/movi 140/136/128; data: gettid/bss_queue/reorder/decap/eapol-vs-amsdu/mesh/pm; mgmt: recv_mgmt+bip; ctl: recv_ctl; recycle) |
| ieee80211_ioctl.c | wifi_softap_set_config(2958B) | low -> medium | AP validate + NVS order (SSID strnlen, pmk_valid, chan/band via regdomain+band2str, CSWTCH$391 index TBD, adjust_2nd_chan, compare_diff/set/commit) |
| ieee80211_ioctl.c | wifi_set_config_process(1368B) | low -> medium | STA/AP fan-out (blacklist, strnlen/strlen, authtype_strength, wpa3 gate, sae_pwe map, pmk_valid, constprop$0 x2, nan_set_config) |
| ieee80211_ioctl.c | wifi_station_set_config_local_2$constprop$0(1636B) | low -> medium | STA NVS persist (get/strnlen/memcpy/set xN, diff memcmp arms, sae_pwe map, commit; movi 32/64 lens) |
| ieee80211_nvs.c | wifi_nvs_cfg_init(3244B) | low -> medium | NVS table init (~90 item_init over verbatim s_wifi_nvs offsets; memset + warn/err gates) |
| wl_cnx.c | cnx_auth_done(1181B) | low -> medium | auth-done (OWE, nvs set/commit, phy_mode/cipher_name, remove_rc_except/clear_blacklist, coex, sta_pm/wake, save_ap_channel, event, obss_scan; CSWTCH$289 arms) |
| wl_cnx.c | cnx_update_bss_more(1139B) | low -> medium | BSS-more (memcpy/memset, connected gate, shortslot/WME/rates/phy/HT/update_channel/regdomain/max-rate/OBSS) |

## 8. Mid-size (257–1024B) pass 2026-10-12 (offline, disasm-grounded)

Only in-range `Fidelity: low` functions touched (64 low->medium, 4 sharpened
low); others byte-identical. Braces balanced; non-Fidelity lines identical.
Every upgraded function verified against its section disasm (0 backward
conditionals, 0 `loop` insns, 0 `jx`); counts preserved, predicates opaque.
phy/coex functions untouched (other workers).

- `ieee80211_api.c` (14): `esp_wifi_get_negotiated_bw_local`(260B),
  `wifi_station_get_config_local`(500B), `wifi_softap_get_config`(434B),
  `wifi_set_user_ie`(278B), `esp_wifi_init_internal`(275B),
  `esp_wifi_stop`(394B), `esp_wifi_scan_start`(390B),
  `esp_wifi_config_80211_tx`(456B), `esp_wifi_ipc_internal`(278B),
  `esp_wifi_nan_load_saved_creds`(341B),
  `esp_wifi_nan_save_creds_for_peer`(312B),
  `esp_wifi_scan_get_cur_ap_record`(316B),
  `esp_wifi_scan_sort_ap_records`(342B),
  `esp_wifi_scan_sort_get_cur_ap_record`(404B).
- `ieee80211_ioctl.c` (26): `print_sta_pmk`(272B), `_do_wifi_stop`(311B),
  `_do_wifi_disconnect`(283B), `wifi_set_mac_process`(322B),
  `wifi_hw_start`(286B), `wifi_hw_stop`(268B), `wifi_set_mode_process`(339B),
  `wifi_menuconfig_init`(429B), `wifi_init_process`(372B),
  `wifi_stop_process`(314B), `wifi_connect_process`(880B),
  `wifi_scan_start_process`(393B), `wifi_get_ap_list_process`(270B),
  `wifi_get_ap_info_process`(350B), `wifi_get_sta_list_process`(312B),
  `wifi_set_protocol_process`(279B), `wifi_set_channel_process`(344B),
  `wifi_set_country`(388B), `wifi_set_band_process`(380B),
  `wifi_set_band_mode_process`(434B), `wifi_set_vnd_ie_process`(266B),
  `ieee80211_set_appie`(401B), `wifi_send_mgmt_frame`(744B),
  `wifi_disable_pmf_config_process`(398B),
  `wifi_ap_remove_sta_node_process`(364B), `ieee80211_ioctl`(442B).
- `ieee80211_sta.c` (4): `sta_rx_csa`(532B), `sta_auth_shared`(294B),
  `sta_auth_sae`(330B), `sta_try_sa_query_process`(362B).
- `wl_cnx.c` (16): `cnx_connect_op`(531B), `cnx_sta_scan_cmd`(774B),
  `cnx_softap_csa`(369B), `cnx_connect_to_bss`(676B),
  `cnx_csa_fn_process`(268B), `cnx_bss_alloc`(332B), `cnx_choose_rc`(642B),
  `cnx_do_handoff`(992B), `cnx_sta_connect_cmd`(622B),
  `ieee80211_max_bandwidth_negotiation_process`(470B),
  `mgd_probe_send_timeout_process`(274B), `cnx_node_remove`(389B),
  `cnx_sta_leave`(694B), `cnx_sta_associated`(348B), `cnx_node_leave`(618B),
  `cnx_node_join`(806B).
- `ieee80211.c` (1): `ieee80211_recv_sa_query_resp`(258B).
  `ieee80211_debug.c` (1): `dbg_hmac_rxtx_statis_dump`(471B).
  `ieee80211_nvs.c` (2): `wifi_nvs_compare_cfg_diff`(386B),
  `wifi_nvs_load`(822B).
- Sharpened, remain low: `wifi_mode_set` (jx a2 +0x62, bltui 5),
  `wifi_hw_mode_switch` (jx a3 +0x41, bltui 5), `wifi_nvs_set` (jx a2 +0x78,
  bltui 8), `cnx_obss_scan_done_cb` (loop a11 +0x109) — each note cites exact
  bounds/table/jx/loop offsets + case-decode or loop-trip resolver.
