# Ledger — libnet80211 11n/supplicant/NAN/MESH glue reconstruction (esp32)

Date: 2026-10-12. Scope: 22 objects of `esp32/libnet80211.a` (extracted to
`/tmp/re_esp32/libnet80211/`). Output: `re/esp32/src/libnet80211/<object>.c`.
Toolchain: `xtensa-esp32-elf` esp-15.2.0. ABI: args a2..a7, return a2.
Method: fully offline. Per-function headers carry `Calls`/`Data refs` merged
from **funcdb v2** `calls[]`/`refs[]` (rela-matched, see §0) plus disasm-reloc
section-local calls funcdb omits (tagged `[local]`); call-site order is from
disasm. Prototypes are generic (arity unknown); struct layouts untyped.

## §0 funcdb v2 (follow-up fix)

The original funcdb had empty `calls[]`/`refs[]` (`.rela.text.f` not matched).
The rebuilt `re/esp32/funcdb_libnet80211.json` populates them
(`R_XTENSA_ASM_EXPAND`/`R_XTENSA_32`). Effect on this task:

- (a) Filled call targets previously `none`: e.g. `ieee80211_regdomain_get_country`
  had zero resolved call sites from literal tracking alone; v2 adds
  `chm_get_band_from_chan`, `ieee80211_get_regdomain` (tagged `[v2-only]` where
  no call site was found in the section disasm; 21 such tags total).
- (b) Corrected literal-pool-only sequences: v2 adds spill/reload-hidden calls
  such as `memset` in `ieee80211_add_htcap`, `chm_get_home_channel` in
  `ieee80211_add_htinfo`, `memcmp` in `ieee80211_get_regdomain`.
- v2 is NOT a superset: it omits section-local calls (`.text.X+off` targets:
  `nan_prepare_filter`, `nan_release_service_idx`, `nan_svc_compute_csid_bitmap`,
  `nan_add_vendor_ie`, `ampdu_rx_stop$constprop$0`, `ampdu_tx_stop`,
  `ieee80211_ampdu_stop_age_timer$isra$0`, `esp_wifi_get_sta_hw_key_idx_internal`,
  `*_body` helpers). These are kept from disasm relocs (179 `[local]` tags).
  v2 also records one self-edge (`ieee80211_regdomain_update` → itself).
- Finished high-fidelity units were patched (edges only), not rewritten.

## §1 Fidelity table

| object | size | funcs/units | high | med | low | verdict |
|---|---|---|---|---|---|---|
| ieee80211_ht.o | 71 KB | 38/55 | 5 | 29 | 21 | real; BA core mapped |
| ieee80211_supplicant.o | 95 KB | 125/126 | 73 | 42 | 11 | real; key-install/config glue |
| ieee80211_regdomain.o | 15 KB | 21/21 | 10 | 9 | 2 | real; table walk recovered |
| ieee80211_phy.o | 11 KB | 7/7 | 1 | 3 | 3 | real; init/ratetable |
| ieee80211_mesh_quick.o | 9.6 KB | 7/7 | 1 | 4 | 2 | real; awake-action glue |
| ieee80211_nan_common.o | 45 KB | 40/44 | 21 | 18 | 5 | real; tx/cb infra |
| ieee80211_nan_disc.o | 55 KB | 24/48 | 16 | 20 | 12 | real; SM event handlers |
| ieee80211_nan_datapath.o | 132 KB | 66/76 | 8 | 38 | 30 | real; NDP+FAW sched |
| ieee80211_nan_sd.o | 65 KB | 37/41 | 5 | 19 | 17 | real; pub/sub/SDF |
| 13 stubs (below) | 480 B ea | 0 | high (vacuous) | – | – | **EMPTY, see §5** |

Units > funcs: LOCAL statics (`$isra$0`/`$constprop$0`, `addba_*`, `ht_*`,
`nan_*` helpers) and `.wifirxiram.NN`/`.wifi0iram.NN` residents
(`ampdu_dispatch*`, `ieee80211_ampdu_reorder`, `nan_dp_search_node` (weak),
`nan_dp_node_exists`). Extra sections were resolved via `objdump -t`, not invented.

## §2 BA map (ieee80211_ht.o)

- Setup (originator+recipient): `ampdu_alloc_rx_ba_index` (bitmap `@g_ic+0x1da`,
  slot match vs `g_ic+16/+20/+0x2a0`, null-arg → `wifi_log` err `0x112`);
  `ampdu_rx_start$constprop$0` → `ampdu_alloc_rx_ba_index`,
  `ampdu_rx_stop$constprop$0[local]`; `ieee80211_ampdu_request` → `hal_now`,
  `wifi_log`, `ieee80211_send_action` (refs `.bss.tokens$1`, `.text.addba_timeout`).
- ADDBA action RX: `ht_recv_action_ba_addba_request` → `ampdu_rx_start[local]`,
  `ampdu_rx_stop[local]`, `ieee80211_send_action`;
  `ht_recv_action_ba_addba_response` (`"(declined)"` rodata) →
  `addba_stop_timeout[local]`, `ic_ampdu_op`; `ht_recv_action_ba_delba` →
  `ampdu_tx_stop[local]`, `ampdu_rx_stop[local]`.
- ADDBA action TX: `ht_send_action_ba_addba` / `ht_send_action_ba_delba` →
  `ieee80211_get_robustmgtframe`, `ht_action_output` (+ `ampdu_rx_stop[local]`
  on the ADDBA path); `ht_action_output` → `ieee80211_mgmt_output`,
  `ieee80211_set_tx_desc`; `addba_response_txcb` → `cnx_node_search`,
  `nan_dp_search_node` (cross-object edge into NAN datapath), `ic_add_rx_ba`.
- Teardown: `ampdu_tx_stop` (TID range-check `bltui a3,8` → `wifi_log` warn
  `0x400`; clears slot `+0x244`) → `ic_ampdu_op`, `addba_stop_timeout[local]`,
  osi-table free; `ieee80211_ampdu_stop` → `ampdu_tx_stop[local]`,
  `ieee80211_send_action`; `addba_stop_timeout` = 2 osi-table calls (off 236/240);
  timers `addba_timeout`, `ieee80211_ampdu_timeout`, `..._isra$0` age helpers.
- BAR/seqno: `ieee80211_recv_bar` → `ieee80211_process_bar_info` →
  `ampdu_dispatch_upto`; reorder `ieee80211_ampdu_reorder` (542 B, `.wifirxiram.48`)
  fans out to `ampdu_dispatch{,_all,_upto,_as_many_as_possible}`,
  `ampdu_dispatch_movement`, `ampdu_process_multicast_address_qos_frame`,
  `ieee80211_ampdu_start_age_timer`, `ic_reset_rx_ba`, `ic_ebuf_recycle_rx`;
  `ampdu_dispatch` → `sta_input`; `ieee80211_decap1` → `memmove`;
  `ieee80211_decap_amsdu` → `memcmp`, `ieee80211_output`, `ic_ebuf_recycle_rx`.
- HT cap/IE builders (`ieee80211_add_htcap_body` 793 B etc.), `ieee80211_parse_htcap`,
  `ieee80211_ht_attach`/`deattach`, `ieee80211_update_channel` (1154 B, low) follow
  the same header scheme; details in-file.

## §3 EAPOL/key-install map (ieee80211_supplicant.o)

This object is the key-install + Wi-Fi-config glue; the 4-way-handshake state
machine itself is NOT here (no EAPOL frame parser found; only
`esp_wifi_register_eapol_txdonecb_internal` hook + `esp_wifi_action_tx_req`).

- AP key path: `esp_wifi_set_ap_key_internal` (361 B) → `ieee80211_set_gtk`,
  `ieee80211_get_ptk`, `ic_del_key`, `ic_del_ptk_and_gtk_alg`, `memcpy`,
  `wifi_ap_pmf_enabled`, `ieee80211_get_spp`, `ic_set_key`, `ppClearRxFragment`,
  `wifi_init_key`, `ieee80211_set_key`.
- STA key path: `esp_wifi_set_sta_key_internal` → hw-idx helper `[local]` +
  `ppInstallKey` (310 B) → `ic_del_key`, `ic_set_key`, `ieee80211_get_spp`,
  `ieee80211_set_key`, `ieee80211_set_sta_gtk_index`, `memcpy`,
  `ppClearRxFragment`, `wifi_init_key`.
- IGTK/BIGTK: `esp_wifi_set_igtk_internal` → `memcpy`, `wifi_log`
  (state `.bss.s_{sta,ap}_igtk` + active-idx); getters
  `ieee80211w_get_{,active_}igtk/bigtk_from_keyidx`.
- NAN keys: `esp_wifi_set_nan_key_internal` (1704 B, biggest here) →
  `nan_set_nm_tk_key`, `nan_clear_peer_integrity_keys`, `ic_set_key`,
  `ic_del_key`, `ieee80211_set_key`, …; log strings pin roles:
  `NAN key install: hw_idx=%d, type=%d…`, `NAN IGTK/BIGTK: bad key_idx`,
  `NAN %s: bad alg=%d key_len=%d (expect … len=16)`, `NAN NM-TK install`.
- PTK-done: `esp_wifi_wpa_ptk_init_done_internal` → `cnx_node_search`,
  `wifi_log`, `memcpy`, `wifi_event_post`.
- Bitmask helpers: `ieee80211_mt_key_{set,is,clear}_mask[_zero]` (leaf, high).
- Remainder (~100 small units): `esp_wifi_{ap,sta}_*_{internal}` config
  getters/setters (PMK/SSID/cipher/PMF/WPS/SAE/OWE/MBO/FT/RM/BTM), `wifi_set_rx_policy`
  → `ic_set_rx_policy`, `ic_set_bssid/mac`, `nan_get_clust_id`; all high fidelity.

## §4 NAN maps

- Publish/subscribe (`ieee80211_nan_sd.o`): `nan_start_publish_service` /
  `nan_start_subscribe_service` (80 B frames) share the prologue
  `nan_get_service_idx → nan_compute_service_hash ("Service \"%s\" hash:
  %02x:…" log) → nan_alloc_sdf → nan_construct_{publish,subscribe}_sdf →
  bloom (`nan_bloom_filter_{init,add,check}` via `crc32_le`)`; subscribe adds
  `nan_bloom_filter_init`; both use `[local]` filter/csid-index helpers.
- SDF RX (`nan_rx_sdf`, 1777 B): `nan_sd_parse_{sdea,sda,availability,dev_caps}`
  → `nan_match_filters` → `nan_call_{service_match,receive}_cb`,
  `nan_send_solicited_publish`, `nan_set_update_sdf_pending`;
  `nan_sd_receive_ctrl` parses pairing attrs (NIRA/SSI length-cap logs).
- Datapath (`ieee80211_nan_datapath.o`): TX `nan_send_ndp_{req,resp,confirm,terminate}`
  all → `nan_get_clust_id`, `nan_is_pmf_enabled`, `nan_alloc_action`,
  `nan_construct_ndp_*`, `nan_tx_action_frame`; RX `nan_rx_naf` dispatches to
  `nan_parse_ndp_{req,resp,confirm,terminate,security_install}`; req-parse ends
  in `nan_call_ndp_indication_cb` + auto `nan_send_ndp_resp`; setup
  `nan_dp_setup_peer` → `ieee80211_setup_rates`, `ieee80211_ht_node_init`,
  `ieee80211_ht_updatehtcap`, `ieee80211_setup_htrates`,
  `nan_ndp_start_inactivity_timer`; sched `nan_sched_allocate_crbs`,
  `nan_sched_construct_availability` over `s_dp` state.
- Discovery SM (`ieee80211_nan_disc.o`): `nan_scan_event_hdlr` (1967 B) is the
  bring-up path (`nan_alloc_beacon`, `nan_construct_beacon[local]`,
  `nan_schedule_next_dwstart[local]`); role handlers
  `nan_{master,am,nms,nmns}_event_hdlr` share
  `nan_common_{dwstart,dwend}_ops[local]`, AMR/TSF adjust `[local]`s,
  `nan_transmit_bcn`, `nan_send_static_sdfs`, `nan_tx_queued_action_frames`,
  `nan_dp_indicate_{faw,ndc}_start`, `nan_dp_schedule_next_faw`.
- Common (`ieee80211_nan_common.o`): `nan_transmit_action`/`nan_transmit_bcn`/
  `nan_alloc_{action,beacon,sdf}`, `nan_mgmt_txcb`, `nan_call_*_cb` fan-out,
  `nan_set_config_local` (290 B).
- Mesh-quick: `ieee80211_mesh_quick_init` → `ieee80211_init_mesh_assoc_ie`,
  `esp_wifi_internal_set_{msdu_lifetime,retry_counter}`,
  `ieee80211_recv_action_register` (+`g_mesh_*` refs); awake TX
  `ieee80211_public_action_send_mesh_awake` → `ieee80211_getmgtframe`,
  `ieee80211_send_setup`, `ieee80211_set_tx_desc`, `ic_tx_pkt`.
- Regdomain: `ieee80211_regdomain_update` (352 B) validates the country string
  (`memcmp`), does divide-by-3 channel math (`mulsh 0x55555556`), then
  `chm_get_current_band` → `memcpy`/`ieee80211_update_phy_country`;
  `ieee80211_regdomain_get_country_info` walks the table from
  `ieee80211_get_regdomain` filtering by `chm_get_band_from_chan` (byte loads
  +3/+4, `extui 3,6`); `ieee80211_add_countryie` builds the IE (`"01"` rodata);
  `ieee80211_get_regdomain` compares against `regdomain_table`/`regulatory_data`.
  Thin wrappers (`_min/max_chan`, `_chan_num`, `_policy`, …) are high fidelity.
  No open-source `components/esp_wifi/regulatory/` copy exists on this disk,
  so the table schema itself stays untyped (see Unknowns).

## §5 Stub correction (task assumption vs evidence)

The brief described the 13 small objects as "480-byte stubs (single external
jump)". Disasm evidence refutes the jump part: each file is 480 B with
`.text` size **0**, `nm` reporting **no symbols**, funcdb 0 functions/0 undefs,
and disassembly containing only `.comment`/`.xtensa.info`. There is **no jump
and no target to record** — they are fully compiled-out (config-excluded)
translation units, so each `.c` is a high-fidelity vacuous stub (no functions,
by design, not padded). Affected:
`ieee80211_{btwt,ftm,he,vht,twt,mbssid,node,crypto_gcmp}.o`,
`test_{rx_bfee,rx_htc,rx_sniffer,rx_trig,tx_mbssid}.o`.
Corollaries: VHT/HE/TWT/BTWT absence is consistent with an 11n-only target;
`ieee80211_node.o` emptiness means node-table code lives in another lib
(candidates: libpp); GCMP/test hooks are compiled out.

## §6 Unknowns (not recovered — would be guessing)

1. All struct layouts (`g_ic`, node/ni, key, BA-session, `s_dp`, `s_sd`,
   `s_ni`, `s_nan_cb`): only untyped offsets recorded (e.g. `+0x244` BA slot,
   `+0x1da` bitmap, `+0x2a0` node ptr, key `+152/+156` PN words in sibling
   crypto objects — not re-verified here).
2. True prototype arities/return semantics: generic
   `int f(unsigned×6)` + `return 0` scaffolding; predicates untyped.
3. Indirect calls via `g_osi_funcs_p[236/240/…]`, `g_ic` tables: counted as
   table calls, targets unknown.
4. `regdomain_table`/`regulatory_data` row schema; country-entry stride seen
   (`addx4`) but field meanings (beyond band/modex bytes) unconfirmed.
5. Bodies of low-fidelity giants (`ieee80211_update_channel`,
   `nan_scan_event_hdlr`, `esp_wifi_set_nan_key_internal`, `nan_rx_sdf`,
   `ieee80211_ampdu_reorder`): skeletons only.
6. `.wifirxiram`/`.wifi0iram` placement rationale (RX-IRAM residency) and the
   weak binding of `nan_dp_search_node`.
7. Whether empty objects have implementations in sibling libs (node→libpp?
   FTM/MBSSID?) — cross-lib check out of scope.

## §7 Verification

- Coverage: every funcdb function present in its `.c` (header match incl.
  `$`→`_` sanitized names); extra LOCAL/wifirxiram/wifi0iram units included
  (55/126/21/7/7/44/48/76/41 units vs 38/125/21/7/7/40/24/66/37 funcs).
- Braces: balanced in all 22 files (comment/string-aware recount; two raw
  `}` hits are inside quoted binary-dump strings in regdomain comments).
- Compile: `gcc -fsyntax-only -std=c99 -w` passes on all 22 files.
- Constants: all immediates/offsets/strings in bodies/headers appear in disasm;
  no logic invented (predicates/fields explicitly untyped; `[v2-only]`/`[local]`
  tags mark edge provenance).
