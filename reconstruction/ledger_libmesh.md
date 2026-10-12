# libmesh.a reconstruction ledger

Source blob: `/Users/chaitanyarahalkar/esp32-wifi-lib/esp32/libmesh.a` (15 objects).
Output: `re/esp32/src/libmesh/*.c` (15 files, one per object).
Generator: `/tmp/re_esp32/gen_libmesh.py` (kept out of tree; rerunnable offline).

## 1. Method and ground truth (fully offline)

1. `xtensa-esp32-elf-objdump -d` per object → exact instruction stream per
   `.text.<func>` section. `readelf -rW` → relocations. `objdump -s` → literal
   pools + `.rodata` bytes. `readelf -sW` → symbols.
2. **Direct calls = `R_XTENSA_ASM_EXPAND` relocs** (Xtensa GCC emits every static
   call as `l32r`+`callx`; the EXPAND reloc sits at the sequence start, up to
   10 bytes before the `callx`). Associated greedily to the next `callx`.
3. **funcdb_libmesh.json v3** supplies `calls[]`/`refs[]` per function. v3 fixed
   the v2 union bug (sibling-section bleed); v3 edges are now exact per-function.
   Usage here: (a) order-aligned attribution of leftover indirect sites,
   (b) verification of reloc-derived edges. Result over all 548 funcdb
   functions: **0 mismatches, 0 unplaced v3 calls, 0 demotions** — v3 confirms
   the disassembly ground truth exactly, and no high-fidelity function had to be
   rewritten (only patched: label/extui fixes below).
4. Model: Xtensa windowed ABI flattened; `a0`–`a15` are `u32` locals, `f0`–`f15`
   are `float` locals, `b0`–`b15` are `u32` boolean regs; memory via `LD/ST`
   macros; control flow 1:1 via labels+gotos. No named structs are invented
   (no multi-offset struct evidence was claimed); same-object `.bss`/`.data`
   statics appear as `LOCAL_*` stand-ins, referenced `.rodata` sections are
   emitted byte-exact with decoded strings.

## 2. Coverage

- funcdb functions reconstructed: **548/548** (all objects), plus **12 extra
  code sections** funcdb does not list (see §6) → **560 functions total**.
- `mesh_input.o` (480 B) verified empty stub: 7 sections, `.text`/`.data`/`.bss`
  size 0, no symbols, no relocs. `mesh_input.c` documents this; nothing to
  reconstruct.
- Verification (scripted): every funcdb name present with exact
  `@ <object>.o <addr> size <size>B bind <bind>` header; braces and parens
  balanced (comments/strings stripped); labels unique per function; every
  function carries `Fidelity:` and `Edges: funcdb-v3` lines.

## 3. Fidelity table

Rule: `high` = ≤200 B, no indirect calls, no jump table, fully mapped.
`low` = jump-table `jx` present, or size >1800 B (large state machine), or
unmodeled insns (0 remain anywhere). Else `medium` (all calls/constants mapped;
residual indirect call sites cite the nearest driving load).

| object | funcs | high | medium | low | unknown-indirect sites |
|---|---|---|---|---|---|
| mesh_parent.o | 150 (146+4 clones) | 67 | 79 | 4 | 438 |
| mesh_schedule.o | 50 | 6 | 39 | 5 | 426 |
| mesh_main.o | 16 | 1 | 14 | 1 | 125 |
| mesh_network.o | 5 | 0 | 5 | 0 | 48 |
| mesh_config.o | 6 | 4 | 1 | 1 | 23 |
| mesh_wifi.o | 7 | 0 | 7 | 0 | 47 |
| mesh_input.o | 0 (stub) | — | — | — | — |
| mesh_route.o | 37 | 13 | 24 | 0 | 125 |
| mesh_quick.o | 126 (118+8 clones) | 70 | 54 | 2 | 106 |
| mesh_timer.o | 8 | 7 | 1 | 0 | 5 |
| mesh_io.o | 11 | 3 | 7 | 1 | 21 |
| mesh_utilities.o | 24 | 13 | 8 | 3 | 16 |
| mesh.o | 103 | 45 | 56 | 2 | 292 |
| mesh_sleep.o | 9 | 6 | 3 | 0 | 5 |
| mesh_common.o | 8 | 4 | 4 | 0 | 11 |
| total | 560 | 239 | 302 | 19 | 1688 |

Low-fidelity set (19): `mesh_nwk_task_main` (12979 B, 1 jx),
`esp_mesh_parent_select` (2122 B), `mesh_parent_select_done` (2052 B),
`mesh_wifi_event_cb` (2 jx), `esp_mesh_txupQ_pending` (2910 B),
`mesh_tx_task_main`, `mesh_xon_task_main`, `esp_mesh_process_ucast` (2264 B),
plus 11 small functions containing a `jx` switch
(`esp_mesh_send`, `mesh_parse_option`, `ieee80211_mesh_quick_get/set`,
`mesh_nwk_io_process`, `esp_mesh_nvs_operate`, `esp_mesh_tx_task_init`,
`mesh_check_tid_mbox_full`, `discnx_reason_id2str`, `dutytype2str`,
`wifi_event_id2str`). All retain exact goto skeletons; only switch-case
recovery is missing.

## 4. Parent-selection map (mesh_parent.o, decision level)

Pipeline: `esp_mesh_scan_done[_vote]` → `mesh_parent_insert_candidate` →
`esp_mesh_parent_select` → `mesh_select_parent`
(`mesh_select_parent_try_rssi` / `mesh_select_parent_try_layer` /
`mesh_select_parent_limit_layer2_cap`, each gated by
`mesh_select_set_ignore`) → `mesh_select_is_better_parent` →
`mesh_is_better_parent` (high-fidelity leaf) → `mesh_parent_select_done` →
`mesh_connect_to_candidate` / `mesh_connect_to_router` (+ `mesh_select_router`).

- `mesh_is_better_parent` (46 B, high): compares two packed records —
  `bltu` on bits[31:16], then `bne`, then unsigned `bgeu` on bits[15:8], then
  `sub` + signed `bgei …, 2`. Decision order: high-half, low-byte, margin ≥ 2.
- `mesh_select_is_better_parent` (242 B): adds a `100`-scale step
  (`movi …, 100` + float via `__divsf3`/`__extendsfdf2` in the caller) before
  delegating to `mesh_is_better_parent`.
- `mesh_select_parent_try_rssi` (460 B): observed compare immediates
  `{0,1,3,5}` plus two large literals `1847/1867` (log-line ids); selects on
  RSSI with a small-int preference ladder.
- `mesh_select_parent_try_layer` (296 B): immediates `{0,1,2,3}` + literals
  `937/7555`; layer-first selection.
- `mesh_select_parent_limit_layer2_cap` (544 B): immediates `{-1,0,1,2,3,100}`
  + literals `7299–7353`; caps layer-2 attachment, 100-scale rank blend.
- `mesh_select_parent_compute_rank` (104 B, high): single-constant rank
  (`movi …, 0` base); pure arithmetic, no calls.
- `mesh_select_parent` (524 B): `{−1,0,1,2,3,5,32,36,64,7723}`; tries RSSI,
  then layer, then updates current parent; `-1` = none-found sentinel.
- Root candidacy/voting: `mesh_init_rcandidate` (`{−2,0,1,3,127,128,1729}`),
  `mesh_update_rcandidate_rssi`, `mesh_check_last_rcandidate` (534 B),
  `mesh_check_rc_expire` (794 B, TTL compares `{−128,−120,−17,−2,…}`),
  `_mesh_find_root_competitor` (1584 B, `{…,127,128,136,294,295,…,65536}`),
  `mesh_vote_root_candidate` (1254 B, float vote math +
  `g_mesh_cfg_vote_percent`), `esp_mesh_compute_votes` /
  `esp_mesh_compute_my_votes` (`{−120,…,6,31,38}`; `-120` dBm = invalid-RSSI
  sentinel, also in `mesh_set_root_candidate` `{−128,−120,0,6,10}` and
  `mesh_is_last_rc_existing`).
- Switch/monitor: `esp_mesh_is_switch_parent` (466 B, `{0,1,3,6,690,694,714}`,
  consults `is_mesh_last_parent` + `esp_mesh_get_ap_connections`),
  `candidate_monitor_timer_start` (410 B,
  `{−119,0,1,3,9,14,32,41,46,2004}`; `ic_get_random` jitter),
  `esp_mesh_parent_reselect` (167 B, high).
- Thresholds: `mesh_set_default_rssi_threshold` bakes `{−85,−82,−78}` dBm;
  `esp_mesh_set_rssi_threshold` (50 B, high) validates (`movi …, 12` bound)
  then `esp_mesh_set_rssi_threshold_internal`.
- Scan: `esp_mesh_scan_done` (1682 B) sorts (`esp_wifi_scan_sort_ap_records`),
  expires (`esp_mesh_ap_list_clear_expire`), enqueues
  (`esp_mesh_ap_enqueue`), weak-AP path (`mesh_scan_done_process_weak`,
  `{…,300,…}`); `esp_mesh_scan_done_vote` adds `esp_mesh_send_stop_vote`.
- Timers/intervals observed: `esp_mesh_set_beacon_interval` clamps
  `{300,1000}` ms; `mesh_adjust_passive_scan_time` steps
  `{100,300,600,1000,1500}` ms; `candidate_monitor_timer_start` uses `2004`;
  `esp_mesh_get_beacon_interval` reads literal `8694`.
- Election tie-break: `mesh_is_yield_root` → `is_self_mac_greater` (memcmp on
  6-byte MACs); `esp_mesh_send_root_switch`, `esp_mesh_parent_check_root_conflict`.

## 5. Route map (mesh_route.o + helpers)

- Lookup: `esp_mesh_lookup_route` (298 B, `{…,64,193,255,…}`) →
  `esp_mesh_lookup_sub_route` (182 B, high); `esp_mesh_match_self`,
  `esp_mesh_get_child_idx`, `esp_mesh_lookup_sub_route` memcmp-based.
- Refresh cycle: `esp_mesh_refresh_routing_table` (1666 B) drives
  `esp_mesh_check_multi_redundant_ack`, `esp_mesh_combine_multi_redundant_ack`
  (`{…,127,…}` bit-index space), `esp_mesh_monitor_nonassociated_children` →
  `mesh_update_route_table` (913 B; deauths stale STAs via
  `esp_wifi_deauth_sta`, flushes TIDs), `esp_mesh_remove_nonassociated_children`.
- Announce/pack: `esp_mesh_send_add_announcement` (180 B, high),
  `esp_mesh_send_rtable_request` / `esp_mesh_send_rtable_ack` (450 B),
  `esp_mesh_pack_multi_routing_table` (1193 B), `mesh_pack_rmv_announcement`
  (189 B, high) → `mesh_malloc_rmv_announcement` /
  `mesh_construct_rmv_announcement` / `mesh_fill_rmv_sub_child`
  (subtree deltas `{139,153,162}` reappear across pack/unpack).
- Capacity/IE: `esp_mesh_ie_update_capacity` (342 B) → `mesh_rt_change_timer_start`;
  `esp_mesh_print_route_table` (131 B, high).
- Roots IE (mesh_quick.o): `_mesh_roots_process_announce/gone/yield/stop/
  fixed/conflict_table`, `_mesh_check_window_open/close_expire`
  (`119999`/`14999` µs-scale windows, `-91` = `0xA5` tag check),
  `mesh_process_roots_ie` + TTL variant, conflict-root add/find/remove/update,
  `esp_mesh_get_vnd_roots_len`, PS duty signaling
  (`mesh_parse_ps_entire_rule` 1086 B, `mesh_parse_ps_uplink_rule`).
- TX windows (mesh_schedule.o): `esp_mesh_txupQ_pending` (2910 B),
  `mesh_xon_task_main` (2366 B), `mesh_tx_task_main` (2158 B), XON
  deliver/flush/expire/disconnect/no-wnd handlers, send-block init/start/main.

## 6. Compiler clones (funcdb-silent, reconstructed)

12 `.text.*` sections with no funcdb entry and no named symbol (local calls
only), reconstructed as `clone_*` (bind LOCAL) in the same object file:

- mesh_parent.o (4): `clone_esp_mesh_clear_parent_part_0` (358 B),
  `clone_esp_mesh_clear_parent_constprop_0_isra_0` (27 B, forwards to part_0),
  `clone_esp_mesh_set_ie_constprop_0_isra_0` (42 B),
  `clone_mesh_nwk_find_conflict_roots_part_0` (87 B).
- mesh_quick.o (8): five 48–59 B `is_*` predicate leaves
  (`clone_is_zero_addr`, `clone_is_esp_mesh_ssid` — checks magic `0xf9cb01e8`
  in the SSID, `clone_is_esp_mesh_roots_{announce,yield,fixed,gone}`) plus
  `clone__mesh_roots_process_fixed_part_0` (113 B),
  `clone__wifi_vnd_ext_mesh_roots_free_part_0` (60 B).

All former `(local-section)` call sites now resolve to these names (0 remain).

## 7. Unknowns and limits (do not treat as established)

1. ~1688 indirect `callx` sites (mostly `g_osi_funcs_p` table + struct field
   `+0x150/+0x158` + callback regs): nearest driving load cited per site;
   exact OSI slot semantics unknown.
2. 15 `jx` jump tables (switch dispatch): bounds checks preserved, case bodies
   not partitioned — listed in §3.
3. Stack-spill values (`a1`-relative) are structurally preserved but the stack
   contents are untracked; cross-block register liveness for call args is a
   reaching-writes heuristic (documented per call site).
4. Signatures are register contracts (`u32 a2..`), not C prototypes; compare
   with `esp_mesh.h` for the public API. No struct layouts are claimed.
5. `.bss`/`.data` statics are `LOCAL_*` stand-ins (real sizes/types unknown);
   `g_*` globals are externs resolved at link time.
6. `mesh_nwk_task_main` (12 979 B event loop) and `esp_mesh_send`/`mesh_recv`
   flag/topo paths are goto-faithful but not summarized to state charts.

## 8. Verification

- 548/548 funcdb-v3 functions + 12 clones = 560 generated; per-function header
  (`name @ object addr size bind / Calls / Data refs / Fidelity / Edges`)
  matches funcdb exactly; braces/parens balanced; labels unique per function.
- Reloc↔funcdb-v3 edge audit: 0 corrections, 0 unplaced calls — disassembly
  ground truth and funcdb-v3 agree everywhere.
- Patches applied during the task (no rewrites of finished functions):
  `.rela`→`.text` reloc keying, `R_XTENSA_ASM_EXPAND`→next-`callx` window
  association, `L_ret` label dedup, `extui` mask-width decode
  (`mask=(1<<(mi+1))−1`), `.byte` padding skip, `bbsi/bbci`, `l16ui`,
  float/bool regs (`lsi/ssi/wfr/rfr/ufloat.s/olt.s…` + `bt/bf`), `mul16u`,
  `src` (SAR-untracked placeholder), funcdb-v2→v3 label rollover, clone pass.
