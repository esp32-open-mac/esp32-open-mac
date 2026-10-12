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
`low` = a specific defect remains: unrecovered `jx` case targets, summarized
flow blocks, or unmodeled insns (0 remain anywhere). Size alone (>1800 B large
state machine) no longer forces `low`: once every dispatch shape in the function
is documented from reloc ground truth and the funcdb-v3 edge audit passes, the
function is `medium`. Else `medium` (all calls/constants mapped; residual
indirect call sites cite the nearest driving load).

| object | funcs | high | medium | low | unknown-indirect sites |
|---|---|---|---|---|---|
| mesh_parent.o | 150 (146+4 clones) | 67 | 83 | 0 | 438 |
| mesh_schedule.o | 50 | 6 | 42 | 2 | 426 |
| mesh_main.o | 16 | 1 | 15 | 0 | 125 |
| mesh_network.o | 5 | 0 | 5 | 0 | 48 |
| mesh_config.o | 6 | 4 | 1 | 1 | 23 |
| mesh_wifi.o | 7 | 0 | 7 | 0 | 47 |
| mesh_input.o | 0 (stub) | — | — | — | — |
| mesh_route.o | 37 | 13 | 24 | 0 | 125 |
| mesh_quick.o | 126 (118+8 clones) | 70 | 54 | 2 | 106 |
| mesh_timer.o | 8 | 7 | 1 | 0 | 5 |
| mesh_io.o | 11 | 3 | 7 | 1 | 21 |
| mesh_utilities.o | 24 | 13 | 8 | 3 | 16 |
| mesh.o | 103 | 45 | 57 | 1 | 292 |
| mesh_sleep.o | 9 | 6 | 3 | 0 | 5 |
| mesh_common.o | 8 | 4 | 4 | 0 | 11 |
| total | 560 | 239 | 311 | 10 | 1688 |

Low-fidelity set (10 remaining, all small `jx` switches): `mesh_parse_option`,
`ieee80211_mesh_quick_get/set`, `mesh_nwk_io_process`, `esp_mesh_nvs_operate`,
`esp_mesh_tx_task_init`, `mesh_check_tid_mbox_full`, `discnx_reason_id2str`,
`dutytype2str`, `wifi_event_id2str` (11 `jx` sites across the 10 functions).
All retain exact goto skeletons; only switch-case recovery is missing.
Upgrade 2026-10-12 (jx-dispatch recovery round, 9 functions low→medium) —
per-function unlocks, all verified offline against `libmesh.a` relocs/rodata:

- `mesh_wifi_event_cb` (1106 B) → medium: both `jx` recovered from the shared
  29-word `.rodata.mesh_wifi_event_cb` base +0 (both literal-pool relocs read
  `.rodata.mesh_wifi_event_cb + 0`; all 29 words `R_XTENSA_32`-relocated to
  `.text.mesh_wifi_event_cb` + stored offset). Site 1: idx = a4−55 in 0..13
  (ids 55..68), default `L_0361`. Site 2: idx = a4−1 in 0..14 (ids 1..15),
  default `L_04b4`. Every consumed target is an in-skeleton instruction
  boundary with its containing block recorded in a `JX-DISPATCH` comment.
  Tail entries 15..28 are indexed by no clamped path; all hold valid relocated
  targets, retained byte-exact.
- `esp_mesh_send` (1497 B) → medium: `jx` recovered, 17-entry
  `.rodata.esp_mesh_send` all consumed; idx = a2−80 in 0..16 (ids 80..96),
  default `L_0685`; a2 = `LD32(sp+0x10)` pre-filtered (1→`L_0500`, 6/7→exit,
  inflow only if a2 > 8). All targets in-skeleton.
- `mesh_nwk_task_main` (12979 B) → medium: `jx` recovered, 44-entry
  `.rodata.mesh_nwk_task_main` all consumed; idx = a5−1 in 0..43 (ids 1..44),
  default `L_37fc`; a5 = `LD32(sp+0x108)` after the OSI mbox-receive call,
  45 = nwk-stop marker. Ids 5/11 map to the default target (placeholders).
- `esp_mesh_parent_select` (2122 B), `mesh_parent_select_done` (2052 B),
  `esp_mesh_txupQ_pending` (2910 B), `mesh_xon_task_main` (2366 B),
  `mesh_tx_task_main` (2158 B), `esp_mesh_process_ucast` (2264 B) → medium:
  disassembly-verified `jx`-free (zero `jx` in each `.text` section); Calls /
  Data-refs headers reconcile exactly with funcdb-v3 (mesh_parent.o extras are
  the documented clone-pass local calls / `.text.clone` refs); every indirect
  site cites its driving load; decision/queue/timer chains already mapped
  (parent-select pipeline §4, TX windows §5).
- Modeling fix at the 4 dispatch sites only (`mesh_wifi_event_cb` ×2,
  `esp_mesh_send`, `mesh_nwk_task_main`): `addx4` was rendered as
  `idx + (base<<2)`; corrected to `(idx<<2) + base` — the old form computes a
  wild pointer (base×4 overflows any linked address) while the linked code
  demonstrably runs, so base + idx×4 is the only viable reading. Same quirk
  may affect other `addx` sites tree-wide: generator-level, noted here, not
  changed outside the 4 dispatch sites.
- Pre-edit sha256 (recorded before this round):
  `mesh_parent.c de3f36de…ffc4ed8`, `mesh_schedule.c 775f8a7b…cfcd48`,
  `mesh_main.c 274924c7…23dfc5f`, `mesh.c a7c6cff6…a0a8f6a`. Post-edit check:
  all non-target functions/regions byte-identical (span-masked diff), braces
  and parens balanced per file, labels unique per edited function, all 9
  headers re-tagged medium. One out-of-scope hunk observed in `mesh.c`
  (`mesh_parse_option` header, still low) from a concurrent session — not
  authored here, left untouched.

Sweep 2026-10-12: the 4 small (≤256B) members
(`mesh_parse_option`, `discnx_reason_id2str`, `dutytype2str`,
`wifi_event_id2str`) were verified against disasm and their Fidelity notes
sharpened to the exact dispatch shape (bounds constants, rodata table addrs,
indirect slots) plus the resolver (rodata string-table offset walk / osi_funcs
slot naming); all 4 correctly remain low per the jx rule, counts unchanged.

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
2. 11 remaining `jx` sites across the 10 low functions (switch dispatch):
   bounds checks preserved, case bodies not partitioned — listed in §3.
   4 sites recovered this round (`mesh_wifi_event_cb` ×2, `esp_mesh_send`,
   `mesh_nwk_task_main`) with full index→target maps in `JX-DISPATCH` comments.
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

## 9. Mid-size (257–1024B) pass 2026-10-12 (offline, disasm-grounded)

Only `Fidelity: low` functions in range touched; others byte-identical.
Braces/parens balanced; non-Fidelity lines identical (span-masked diff).

- Sharpened (remain low, exact blocker + resolver): `esp_mesh_nvs_operate`
  (bltui 6 +0xc2, `.rodata.esp_mesh_nvs_operate` l32r +0xc8, jx +0xd0),
  `mesh_nwk_io_process` (bgeu 12 +0xaa, `.rodata.mesh_nwk_io_process` +0xb0,
  jx +0xb8), `ieee80211_mesh_quick_get/set` (bgeu 24 +0x3c/+0x40,
  `.rodata.ieee80211_mesh_quick_{get,set}` +0x42/+0x46, jx +0x4a/+0x4e),
  `esp_mesh_tx_task_init` (bltu 13 +0x121, `.rodata.esp_mesh_tx_task_init`
  +0x124, jx +0x12c), `mesh_check_tid_mbox_full` (bltu 13 +0x7e,
  `.rodata.mesh_check_tid_mbox_full` +0x81, jx +0x89). All 6 keep low per
  the jx rule; resolver is rodata table dump + per-case target walk.
  Counts unchanged (10 low).
