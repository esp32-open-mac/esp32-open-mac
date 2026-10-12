# libnet80211 data-path ledger (ESP32, offline RE)

Scope: ONLY the 15 TX/RX/scan/crypto/channel objects below. Other libnet80211
objects belong to other workers and are not covered here.
Blobs: `esp32/libnet80211.a` -> `/tmp/re_esp32/libnet80211/`
Metadata: `re/esp32/funcdb_libnet80211.json` (per-function calls[]/refs[] are
EMPTY for this lib — headers in `src/libnet80211/*.c` use disasm-observed edges)
Disasm: `re/esp32/disasm_full/libnet80211/*.dis`
Toolchain: `~/.espressif/tools/xtensa-esp-elf/esp-15.2.0_20251204/.../xtensa-esp32-elf-{objdump,readelf,nm}`
ABI: args a2..a7, return a2. `entry a1,N` = stack frame N bytes.
Verify: `gcc -fsyntax-only src/libnet80211/<object>.c` → 0 errors (warnings ok);
braces balanced; header count == funcdb count per object (checked 2026-10-12).

## 1. Fidelity table

| Object | Funcs | high | med | low | Notes |
|---|---|---|---|---|---|
| ieee80211_output.o | 76 | 26 | 48 | 2 | TX hot path high (esp_wifi_80211_tx, raw_frame_sanity_check, output_process, encap_esfbuf, mgmt_output, output_raw_process cite insns). Long assoc/beacon/proberesp constructors low-med (structural summaries). |
| ieee80211_input.o | 20 | 7 | 11 | 2 | parse_rsn (2558B) + parse_beacon (1535B) low-med: call order + IE-walk branches captured, per-IE field maps partial. Leaf rate/cipher helpers high. |
| ieee80211_scan.o | 48 | 18 | 30 | 0 | State handlers medium (edges + timer callbacks cited); leaf setters high. scan_parse_beacon (3413B) medium: match/update call chain captured. |
| ieee80211_crypto.o | 11 | 4 | 7 | 0 | BIP/CMAC/GMAC: key-load + compare + replay-log sequence cited; primitive via wpa_crypto_funcs (not invented). attach/available/setkey trivial high. |
| ieee80211_crypto_ccmp.o | 5 | 4 | 1 | 0 | ccmp_encap/decap + encrypt/decrypt high: PN +152/+156 carry, IV s8i 0..7, ExtIV/reserved/replay checks with rodata strings cited. |
| ieee80211_crypto_tkip.o | 2 | 2 | 0 | 0 | tkip_encap/decal shared skeleton with ccmp + TSC low16 at key+152; +1 +carry (bltu). |
| ieee80211_crypto_wep.o | 2 | 2 | 0 | 0 | wep_encap: IV s8i [0]=lo,[1]=lo>>8,[2]=lo>>16(extui16,16),[3]=keyid; +1 +carry. decap leaf. |
| ieee80211_crypto_sms4.o | 2 (synth; funcdb lists 0) | 2 | 0 | 0 | sms4_encap 10-byte IV + memcpy; sms4_decap gettid + PN compare. Addrs synthesised 0x0 (funcdb empty) — see unknowns. No SMS4 rounds invented. |
| ieee80211_action.o | 6 | 2 | 4 | 0 | Category-dispatch tables (.data ba/ht/vendor/sa_query/public send/recv tables); register/unregister leaf high. |
| ieee80211_action_vendor.o | 13 | 7 | 6 | 0 | construct_action_vendor_spec (877B) medium: OUI/seq/get_iav_key/cnx_node_search chain cited. ESP-NOW recv path high-med. |
| ieee80211_hostap.o | 21 | 5 | 11 | 5 | hostap_input (1948B), hostap_recv_mgmt (4854B) low: dispatch order cited, per-subtype detail partial. Beacon/txcb/timer procs medium. |
| ieee80211_node.o | 0 | — | — | — | EMPTY object: only .comment/.xtensa.info, 0 funcdb funcs, 0 disasm sections. Marker TU only. |
| wl_chm.o | 22 | 12 | 10 | 0 | set_current/home/init/mhz2num cite g_chm + phy_change_channel path; trivial getters high. |
| wl_offchan.o | 8 | 5 | 8 | 0 | roc/action-tx req + txop/roc start/end cite chm lock + pm_offchan hooks; progress predicates high. (8 funcdb funcs; section helpers roc_op_end/sess_handler etc. folded into their callers' notes.) |
| if_eagle.o | 0 | — | — | — | EMPTY object, same as node.o. Marker TU only. |

Fidelity key: high = call order + branch skeleton + key insn offsets cited, body mirrors disasm;
medium = call order + offsets captured, straight-line detail summarised; low = large fn, key edges only.
`funcdb calls[]/refs[]` are empty for every function in this lib — no exceptions found.

## 2. TX path map (injection path confirmed)

```
esp_wifi_80211_tx @ ieee80211_output.o:0x30 (277B)
 ├─ ieee80211_raw_frame_sanity_check (390B)   # NULL/len<23/len>0x5dc guards, FC parse l8ui +0, memcmp+cnx_node_search
 ├─ ic_ebuf_alloc                             # fail → return 0x101 via g_osi_funcs_p+88 path
 ├─ chm_get_current_channel  → chm_get_band_from_chan
 │    # s16i eb+22=len-24 (+22: len/seqctl), s16i eb+20=24, bit14 OR into eb+44 word
 ├─ ic_get_default_sched → ic_get_80211_tx_rate  # sched/rate words into eb+44 priv region
 └─ ieee80211_post_hmac_tx                    # hand to MAC/HMAC queue
```

Queue pump: `ieee80211_output_process` (chm_is_at_home_channel gate →
output_pending_eb → search_node → wapi? vs ic_ebuf_alloc+copy_eb_header →
raw_process XOR classify+encap_esfbuf+crypto_encap+align+ampdu+set_tx_desc →
pwrsave/nan_dp_post_tx/ppTxPkt). Mgmt fork: `ieee80211_send_mgmt` →
auth/deauth/assoc_req/assoc_resp/disassoc_construct → set_tx_desc →
`ieee80211_mgmt_output` (bufferable-MMPDU + robust-mgmt/add_mic_ie_bip + tx).
Null/keepalive: `ieee80211_pm_tx_null_process` → encap_null_data / encap_keep_alive_data.

## 3. RX path map

```
hostap_input @ ieee80211_hostap.o (1948B)   # AP RX entry
 ├─ wifi_get_macaddr, ieee80211_rfid_locp_recv, cnx_node_search xN
 ├─ memcmp SA/DA/BSSID, hal_now, cnx_rc_update_rssi, ieee80211_gettid
 ├─ deauth/disassoc/leave + pwrsave + ampdu_reorder gates
 ├─ ieee80211_crypto_decap → ieee80211_decap / ieee80211_decap_amsdu → hostap_deliver_data
 │    (hostap_deliver_data → mesh_rxcb/ap_rxcb or ieee80211_output forward)
 ├─ hostap_recv_mgmt (4854B: probe/auth/assoc/SA-query/robust-action-espnow/offchan_recv_action)
 └─ hostap_recv_ctl → ieee80211_recv_bar / nulldata / TIM / ic_tx_pkt
```

Parse helpers (ieee80211_input.o): `ieee80211_decap` (414B), `ieee80211_parse_beacon`
(1535B: SSID/rates/DS/HT/RSN/WPA/WAPI IE walk + regdomain_chan_in_range),
`ieee80211_parse_rsn` (2558B: AKM/cipher select via better_rsn_pairwise_cipher,
ent/11r/wpa3 gates), `ieee80211_parse_wpa/_wapi/_action`, rate-setup family
(setup_rates/set_max_rate/setup_phy_mode/setup_lr_rates/is_ht_cipher…).
Note: STA RX (`sta_rx_cb`) and RX dispatch registration live in ieee80211.o —
out of scope for this worker.

## 4. Scan state machine sketch (from branch structure + timer callbacks)

States recovered from `scan_start*`, `scan_next_channel`, `scan_op_end`,
`scan_done` + `.text.scan_enter_oper_channel` / `.text.scan_inter_channel_timeout`
trampolines (both → `ieee80211_timer_process`):

```
IDLE --scan_start()--> START --scan_start_handler()--> ITERATE(ch)
  START: chm_acquire_lock(); fail→wifi_log+gpio_debug; scan_pm_offchan()
         (pm_offchan_ready_or_defer → defer if PM busy)
  ITERATE: wifi_set_rx_policy(); chm_get_channel_index(); clear_bss_queue();
           hal_now(); → inter_channel_timeout_process (first ch)
  NEXT (scan_next_channel): regdomain_chan_in_range filter; chm_get_chan_info();
           active? (regdomain_is_active_scan → scan_send_probe → ieee80211_send_probereq)
           : passive dwell; chm_start_op() tune; list end → scan_done+0x88
  CHAN_END (scan_op_end): pm_is_open/coex hooks; check_bss_queue+cnx_rc_search;
           pm_is_force_return_home_chan (x3 observed) → chm_return_home_channel
           else → scan_next_channel+0x68; final → scan_done+0x88
  DONE (scan_done): pm_offchan_is_waiting? execute_ready_cb; chm_return_home_channel;
           scan_flush_all_tx_buf (ic_tx_pkt/ebuf_recycle); chm_release_lock;
           wifi_set_rx_policy; wifi_event_post; clear_bss_queue;
           wifi_scan_restore_random_mac.
RX-ENTRY (scan_parse_beacon, 3413B): chan validate → hidden check
  (scan_check_hidden) → profile match (is_profile_match/scan_profile_check:
  SSID/BSSID/auth/cipher/AKM + parse_rsn/wpa/wapi + blacklist) →
  cnx_bss_alloc/init + rc_update_{rssi,age,state_metric} + cnx_update_bss[_more] →
  mesh/event post + OWE/history update.
```

Channel list: `scan_build_chan_list` + `scan_bitmap_to_channel_list` (+prefer_chan/
owe_pref_chan, regdomain_update_in_scan). BSS queue: check/clear/free_bss_info
(g_osi_funcs_p free path). Timers: enter_oper_channel_handler,
inter_channel_timeout_process → scan_next_channel+0x68.

## 5. Crypto observations (no invented steps)

- Common encap skeleton (ccmp/tkip/wep/sms4): reserve headroom
  (`l32i eb+4; l32i rsv, sym+4; sub/s32i; s16i eb+22 += rsv`), bump PN
  (`l32i key+152 lo, key+156 hi; +1 (+2 sms4-flag path); bltu carry`),
  build IV with `s8i` byte stores + `memw` barriers. Key bytes via
  `l16ui key+154 / l8ui key+155 / l32i key+156 (>>8)…`.
- CCMP: IV[3] = keyid|32 (`or 32 @0x4d`); decap validates ExtIV + keyid bits
  (bbsi/bnei/beqi); decrypt checks reserved-bit (`"used non-zero reserved bit"`),
  ExtIV (`"did not have ExtIV bit set to 1"`), PN-vs-RSC u64
  (`"CCMP replay detected: … PN=%llu, RSC=%llu seq=%u"`), TID via gettid.
- TKIP: TSC low16 reuse of key+152 path + `or 32` keyid mix at IV[1]
  (`extui 0,7 + or`); decap gettid + bbsi/bnei/beqi chain.
- WEP: IV[2] = (lo>>16) (`extui 16,16`), IV[3] = keyid octet.
- SMS4/WAPI: 10-byte IV + payload `memcpy`; flag word `and 2` selects +1/+2
  counter path; `"WAPI: pn err …"` string in funcdb; gettid + wifi_log on decap.
- BIP (802.11w): IGTK via `ieee80211w_get_active_igtk_key_id` /
  `ieee80211w_get_igtk_from_keyidx`; AAD `memcpy`, `memset` pad, `memcmp` verify;
  `"BIP replay detected"`, `"Invalid MMIE"`, `"MIC mismatch …"` strings;
  primitive always via `wpa_crypto_funcs` (+g_osi_funcs_p) — never inlined.

## 6. Unknowns / limits

1. ebuf/esfbuf exact struct: +0/+4/+20/+22/+44 roles inferred from access
   patterns only (flags?/data-len/len16 pair/priv word). ic offsets (0x14c,
   0x1a4, 0x200, 0x20c…) likewise opaque control words.
2. funcdb has no per-function calls/refs for this lib; all edges used here come
   from disasm literal pools — section-level attribution (one section ≈ one
   function; helpers like `add_appie`, `scan_add_ssid_do$constprop$0`,
   `chm_phy_change_channel$constprop$0` attributed to their caller sections).
3. sms4 addrs: funcdb lists 0 functions for the object; `sms4_encap/decap`
   headers use synth addr 0x0 with real section names + sizes 101/163B from
   disasm — relink against `nm` if exact addrs needed.
4. `ieee80211_node.o`, `if_eagle.o`: provably empty (only .comment/.xtensa.info;
   0 funcdb funcs, 0 disasm sections). Marker TUs document the finding.
5. Off-channel/PM handshakes (`pm_offchan_*`, `ppTxPkt`/`pp_post`, `ic_*`
   methods) are call-graph leaves here — implementations live in libpp/libcore.
6. STA-mode RX entry (`sta_rx_cb`) and ic method tables live outside scope
   (ieee80211.o). Hostap recv_mgmt per-IE offsets beyond the cited ones are
   summarised, not exhaustively mapped.
7. Shared `/tmp/gen_net80211.py` was clobbered by a sibling worker mid-task;
   repaired outputs in place (unique-name generators recommended for shared /tmp).

## 7. Upgrade pass 2026-10-12 (low -> medium, offline, disasm-grounded)

Only functions tagged `Fidelity: low` touched; all others byte-identical.
Headers re-tagged to medium; braces balanced (comment-aware recount 0 diff);
hostap/input/output still `gcc -fsyntax-only -std=c99 -w` clean.

| file | function(size) | old -> new | unlock notes |
|---|---|---|---|
| ieee80211_hostap.c | hostap_recv_mgmt(4854B) | low -> medium | FC-subtype dispatch on a14 (beqi 128/64/80/176/160/192/208 at +0x2a8..+0x2f9; bnone -33, blt bounds -> +0x1520); vendor OUI fork (is_esp_manufacturer_oui/is_non_esp_oui), IE walk l8ui +0/1/2 (beqi 3, bgeui 4, 50/221); assoc + action forks listed in call order |
| ieee80211_hostap.c | hostap_input(1948B) | low -> medium | type/subtype fork (extui 0,2; movi 140/136/128; bbci bit5/6); mgmt -> recv_mgmt, ctl -> recv_ctl, data -> deauth/pwrsave/ampdu_reorder -> crypto_decap -> decap/amsdu -> deliver_data |
| ieee80211_hostap.c | wifi_softap_start(1242B) | low -> medium | 5-phase bring-up in disasm call order (default-ssid/vif, NVS+2nd-chan+commit, phy/HT/bw40 gate, home/current/snd+update, attach+memset x4+event) |
| ieee80211_input.c | ieee80211_parse_rsn(2558B) | low -> medium | RSN IE field map (id 48 @+0, len @+1, ver @+2 beqi 1, group @+4, pairwise cnt/list @+8, AKM, caps beqi 32, PMKID) + better_pairwise + ent/11r/wpa3 gates + override-OUI |
| ieee80211_input.c | ieee80211_parse_beacon(1535B) | low -> medium | IE walk (beqi 1 arm; ids 0/1/3/5/7/HT/RSN/WPA, 221/127 markers) + regdomain_chan_in_range x2 gate |
| ieee80211_output.c | ieee80211_assoc_req_construct(1267B) | low -> medium | IE build order (capinfo, lora/vnd size, getmgtframe, rates/chan/xrates, htcap gate, idle/dh/vendor/ht-vendor, appie x2, esp-mfr, lora/vnd set) |
