# libcoexist.a reconstruction ledger (ESP32)

Offline reverse-engineering of `esp-coex-lib/esp32/libcoexist.a` into reconstructed C
under `re/esp32-coex/src/`. Sources of truth: `/tmp/re_coex/libcoexist/*.o` (11 objects),
`re/esp32-coex/funcdb_libcoexist.json` (funcdb v3: exact per-function `calls[]`/`refs[]`,
96 functions), `re/esp32-coex/disasm/*.dis`
(`xtensa-esp32-elf-objdump -dr`, esp-15.2.0_20251204). NO DWARF in these objects
(verified) — all signatures `[inferred]` from register use. Xtensa ABI: args a2..a7,
return a2; outgoing args a10.. (callee result lands in caller a10); caller a0..a7
survive calls. Error constants observed: `0` ok, `0x101`, `0x102` (= ESP_ERR_INVALID_ARG),
`0x103`; `-1` Dart-style failure; referee mapping conventional, not asserted.

Per-function headers in `src/` carry `Calls`/`Data refs` verbatim from funcdb v3
(machine-checked CLEAN against funcdb: addr/size/bind/calls/refs for all 96).

## 1. Coverage

| object | funcdb | emitted (incl. statics) | notes |
|---|---|---|---|
| coexist_api.o | 27 | 27 | public shims; owner 0=BT / 1=WiFi |
| coexist_arbit.o | 8 | 10 (+arbit_bitmap_find, arbit_unlink) | .iram1.6/.iram1.12, no symtab entries |
| coexist_core.o | 17 | 20 (+coex_lock, coex_unlock, coex_reschedule) | .iram1.7/.iram1.8/.iram1.11, no symtab entries |
| coexist_dbg.o | 6 | 6 | log_level=1, gpio cb=0 defaults |
| coexist_hw.o | 3 | 6 (+coex_flush_read, coex_bb_setup, coex_bb_restore) | .iram1.0/.iram1.11/.iram1.15 |
| coexist_scheme.o | 22 | 26 (+status_change, is_loop_allowed, change_phase, timeout_process) | .text.* statics, no symtab entries |
| coexist_timer.o | 13 | 13 | adapter time base + TS timers |
| external_coex.o | 0 | 0 | 480B stub, no code sections |
| coexist_iso.o | 0 | 0 | 480B stub |
| coexist_param.o | 0 | 0 | 480B stub (g_coex_param lives in core) |
| hal_external_coexist.o | 0 | 0 | 480B stub |
| total | 96 | 102 headers | 96 funcdb headers verified present; braces balanced OK |

VERIFY: all 96 funcdb headers present, braces balanced (comment/string-stripped check).

## 2. Fidelity table

high = control flow + calls + constants exact; medium = skeleton + calls exact, some
expression/role approximation (noted); low = decision-level only (noted).

### coexist_api.o (27; 26 high, 1 medium)

| function | fidelity | note |
|---|---|---|
| coex_bb_reset_lock/unlock | high | unlock returns entry a2 (no result move) |
| coex_bt_request/release, coex_wifi_request/release | high | owner 0/1, (event,p3,p4)/(event), result moved |
| coex_deinit, coex_disable | high | no result move (undefined return) |
| coex_enable, coex_init | high | result moved |
| coex_event_duration_get | high | (event,out) forwarded |
| coex_is_running | high | `status == 1` via addi/movnez |
| coex_pre_init | high | version print (`*libcoexist_reversion_git` = "eec362d") then pre_init |
| coex_preference_set | high | 7B stub returns 0 |
| coex_register_bt_cb/wifi_cb | high | owner 0/1 |
| coex_register_start_cb | high | arg forwarded (or a10), result moved |
| coex_status_get | high | `(~u8mask & bitmap)==0 -> 0` else core status |
| coex_update_lpclk_interval | medium | guarded cb call; callee args unknown (no arg moves) |
| coex_version_get | high | returns "2.0.0" |
| coex_version_get_value | high | NULL->0x102 else {2,0,0}, 0 |
| coex_wifi_register_update_lpclk_callback | high | plain store, no result move |
| esp_coex_adapter_funcs_md5_check | high | NULL->0; match->0; else printf + 0x102 (internal "6964e7f") |
| esp_coex_i154_funcs_md5_check | high | identical shape (internal "85dae7a") |
| esp_coex_adapter_register | high | dup->0; NULL->puts+0x102; ver(+0)!=2 / magic(+92)!=0xdeadbeaf -> printf + 0x102 |
| esp_coex_status_bit_set/clear | high | type0->WiFi printf+0x102; BT {8,16}\|32; BLE {16,32}; 15.4 ==1; else schm + 0 |

### coexist_arbit.o (8; 5 high, 3 medium)

| function | fidelity | note |
|---|---|---|
| arbit_bitmap_find (static) | high | bit test, pool+id*24 else NULL |
| arbit_unlink (static) | high | DLL remove + bit clear (id=u8 node+10) + count-- |
| coex_arbit_insert | medium | skeleton + time-order predicate `(req-node)<1` exact; linkage stores 1:1 |
| coex_arbit_delete | high | match `(key^w0)&0x00ff00ff==0`; 0 / 0x102 |
| coex_arbit_first/next | high | payload = node+8; iterator exact |
| coex_arbit_clean_overtime | high | unlink expired via is_in_time(node+16, window) |
| coex_arbit_dump | high | walk-only (gutted, prints nothing) |
| coex_arbit_init | medium | muxes + 0x3f0 pool; error strings exact; success returns entry-a2 (0 at call site) |
| coex_arbit_deinit | medium | assert-hangs 0x1b7/8/9 exact; one stale-a2 store (f6) called out |

### coexist_core.o (17; 9 high, 8 medium)

| function | fidelity | note |
|---|---|---|
| coex_lock/unlock (statics) | medium | env+8 gate + adapter offsets (+48/+32/+20/+40, +48/+44/+20) exact; take/give roles inferred |
| coex_reschedule (static) | high | disalarm both, clear, first-or-alarm(diff) |
| coex_core_ts_start | medium | phase skeleton + constants (200, evt 12/14, cbarg 18) exact; force/unforce arm decision-level |
| coex_core_ts_end | high | null-state printf (0x123) + hang; dbg 13/15; clean(200) |
| coex_timer_ts_start/end_handler | high | lock; run unless failed/disalarmed; unlock |
| coex_core_request/release | medium | codes (-1, 0x103) + req build (prio_tab, w1=now+p4, w2=+p5+now) exact |
| coex_core_event_duration_get | high | events 4/7/9/39/40 -> slots; 0 ok / -1 |
| coex_core_pre_init | medium | adapter+24 sema, +4 bb mux, schm, gpio; cleanups exact |
| coex_core_init/deinit | high | 7B stubs return 0 |
| coex_core_enable/disable | medium | refcount (init on 2nd ref), timer+arbit, fwm mux, status=1, unwind exact |
| coex_core_status_get | high | env+12 |
| coex_core_register_cb/start_cb | high | env+16/+20/+28 slots; 0x103 on lock-fail |
| coex_core_bb_reset_lock | medium | flag + adapter+12 take |
| coex_core_bb_reset_unlock | high | give(mux), returns arg |

### coexist_dbg.o (6; all high)

Trivial stores/getters; `coex_dbg_output` guards cb(a2,a3); max_event = 17.

### coexist_hw.o (3; 1 high, 1 medium, 1 low)

| function | fidelity | note |
|---|---|---|
| coex_flush_read (static) | medium | insn-exact (0x3ff40078 + *a2 reads, rsil/wsr/rsync); flush intent inferred |
| coex_bb_setup/restore (statics) | medium | take/give + constants exact (141, 0x80 spin, 0xFFFCFFFF, +8/-8, 0x3ffb0000, +0x30000; 6-7/6-13/6 clears) |
| coex_gpio_init | high | bit6 clear at 0x3ff441c4/c8 |
| coex_force_wifi_mode | low | decision-level: dbg(0,8), 129/168, state==7 && val==39 RF gate, 25000/30 polls on 0x3ff51110/0x3ff5110c, codes -124..-127 |
| coex_unforce_wifi_mode | medium | bit7 -> btdm_rf_bb_reg_init + clear; bit20 polls; adapter unforce; dbg(1,11) |

### coexist_scheme.o (22; 16 high, 6 medium)

| function | fidelity | note |
|---|---|---|
| status_change (static) | medium | top predicates + group order + all leaves exact per literal relocs; two `(l&(b\|m))` stale-mask sites determined by dataflow (62c, 5d9) |
| is_loop_allowed (static) | high | nonzero{wifi,bt-word,flags,mesh} >= 2 |
| change_phase (static) | medium | restart/advance, period gates (3, 64), arm = period*interval*phase[2] (adapter+80), cb select (ph[3]->+52, ph[4]->+20); always -1 |
| timeout_process (static) | high | change_phase(0), no result move |
| coex_schm_lock/unlock | high | adapter+40(mux,-1)/+44(mux); 0 iff rc==1 else -1; null -> 0x103 |
| coex_schm_status_bit_set | medium | per-type OR, change on loop-flip, change_phase(1) on period gate; extra stale-a4 gate (caller garbage) documented, not modeled |
| coex_schm_status_bit_clear | high | per-type AND-clear, always status_change; returns entry type |
| coex_schm_status_get | high | 0->+6, 1->+8, 2->+10, else 0; lock rc passthrough |
| coex_schm_status_bitmap_get | high | wifi:1 bt:2 ble:4 flags:8 (mesh==0):16; no lock |
| coex_schm_curr_phase_idx_set | medium | null/range -> -1; store, unlock, cb(0), 0 |
| coex_schm_curr_phase_idx_get | high | lock-fail -1 else u8 +4 |
| coex_schm_interval_get/set | high | +12; fail 0 / -1 |
| coex_schm_curr_period_get | high | fail/null -> 1 else table[1] |
| coex_schm_curr_phase_get/get_phase_by_idx | high | table+idx*4+2 or NULL |
| coex_schm_register_callback | high | owner0->+52, owner1->+20, else -1 |
| coex_wifi_channel_set/get | high | +24/+25 bytes; null outs -> printf + 0x102; chan_cb(ch1,ch2) |
| coex_register_wifi_channel_change_callback | high | store +28 (even NULL) |
| coex_schm_process_restart | high | change_phase(1) |
| coex_schm_flexible_period_set/get | high | +58 byte, no validation |
| coex_schm_init | medium | adapter+24 mux once; table=all_default; adapter+76 setfn(+0x20, timeout_process, 0) |
| coex_schm_deinit | high | adapter+72(+0x20), no result move |

### coexist_timer.o (13; 8 high, 5 medium)

time_now/diff/is_past/is_in_time/flags high (derivations in src);
now_ms medium (upper dividend word stale); alarms/init/deinit medium (adapter
offsets 80/68/76/72 cited, arg roles inferred). Pairing proved:
start = {.dram1.4 flag, .dram1.2 struct}, end = {.dram1.3, .dram1.1}.

## 3. Struct map (named only with 2+ offset evidence)

- `coex_arbit_state_t` (.dram1.1, 20B): head+0, tail+4, count+8, bitmap+12/+16.
- `coex_arbit_entry_t` (24B): prev+0, next+4, key+8, time+12, aux+16, aux2+20; id = u8 +10.
- `coex_env_t` (coex_env, 32B): +0 ts ptr, +4 arbit ptr, +8 mux, +12 status, +16/+20 cbs, +24 u8 force, +28 start_cb.
- `coex_schm_env_t` (64B): table+0, idx+4, wifi+6, bt+8, ble+10, interval+12, mux+16, cb1+20, chan+24/+25, chan_cb+28, cb0+52, flags+56, flex+58, mesh+60.
- Tables: `g_coex_param` = {25000, 5000, 20000, 25000, 50000};
  `coex_prio_tab` (42B) =
  0c 09 0b 00 0a 09 09 09 09 09 09 07 06 05 0c 00
  08 0a 08 08 0a 08 0a 08 08 08 0a 0a 0a 08 0a 08
  08 03 0a 0a 0f 0e 08 0c 0c 0f;
  version "2.0.0"; md5s basic "6691b5d" / i154 "85dae7a" / adapter "6964e7f";
  git "eec362d" / remote "eec362d-remote" (place-addends 0/8/16, 0x27/0x18).

## 4. Arbitration map

- Request path: `coex_{wifi,bt}_request` -> `coex_core_request(owner, event, p4, p5)`
  builds 16B req {owner, prio_tab[event], event} + w1 = now+p4, w2 = now+p4+p5,
  `coex_arbit_insert` (dedupe by event, time-ordered, pool slot = event id),
  `coex_reschedule` (arm earliest via `coex_timer_ts_start_alarm(diff)`).
- Fire path: `coex_timer_ts_{start,end}_handler` -> lock -> `coex_core_ts_{start,end}`
  (window 200 for is_in_time/clean_overtime; force/unforce RF on phase entry/exit).
- Scheme path: `esp_coex_status_bit_{set,clear}` validates (BT {8,16}|32; BLE {16,32};
  15.4 ==1; WiFi rejected) -> `coex_schm_status_bit_*` updates env bitmaps ->
  `coex_schm_status_change` swaps `env+0` phase table -> `coex_schm_change_phase`
  arms per-phase timer (period*interval*phase[2]) and fires table callbacks.
- Status_change groups: freeze (+56.0) -> hold; (bt|mesh)==0 -> plain `bt_*`;
  bt&8 -> `ble_mesh_config_*`; (bt&16)|((bt&0x3a)==2) -> `ble_mesh_traffic_*`;
  bt&32 -> `ble_mesh_standby_*`; else (mesh-gated) -> `ble_default_*`;
  wifi rows bit0 scan / bit1 connecting / bit2 conn; ble ladders per group in
  disasm order (see src). ~140 weak phase-table objects (6/10/14/22B) enumerate
  every leaf (full list in funcdb strings).

## 5. Trace confirmations (live QEMU scan trace + scan.elf)

- `/tmp/func_mmio.json` (74 funcs): ZERO `coex_*`/`arbit*`/`schm*` keys. No libcoexist
  function appears in the matrix — expected: scan.elf contains no libcoexist symbols
  (only `coex_*_wrapper` shims + pm_/pp_/wifi_ coex consumers). Verdict: libcoexist
  never executes in the scan build; nothing to confirm per-function.
- `0x3ff51000` region: only `3ff5103c` appears in `/tmp/mmio_func.json`
  (via esp_dport_access_reg_read/tx_paon_set/bb_bss_cbw40). No BT-status polling
  observed — consistent with BT dummy-mapped/absent in this trace.
- `coex_bt_high_prio` (scan.elf `0x40093064`, IRAM, NOT in libcoexist.a — resolves
  from another archive): full RMW sequence via esp_dport_access_reg_read + direct
  stores, constants exact from ELF disasm: `3ff5c080 &= ~0xC0`; `600310d0 &= ~0xF0`;
  `60031300 &= ~0xF0`; `60033d30 |= 1`, `= (v&0xF0FFFFFF)|0x1000000`,
  `= (v&0xFF0FFFFF)|0x400000`; `60033d38 = (v&0xFFFF)|0xC800000`,
  `= (v&0xFFFF0000)|10`; `60033d40 = (v&~0x38)|0x10`; `600041c4 |= 0x40`.
  BT-high-priority BB/MAC override. It has no entry in func_mmio.json either
  (runs during init, outside the attributed scan window / unattributed `??`).

## 6. Unknowns (not invented; left abstract)

1. OS-adapter struct layout behind `g_coa_funcs_p` (source not on disk; only
   `libesp_coex.a` binary + wrapper names in scan.elf). All adapter calls cite raw
   byte offsets (+4/+8/+12/+16/+20/+24/+28/+32/+36/+40/+44/+48/+52/+56/+60/+68/
   +72/+76/+80); take/give/setfn/arm roles inferred from use, medium fidelity.
2. `coex_update_lpclk_interval` callback signature (no arg moves in disasm).
3. `coex_schm_status_bit_set` change_phase gate includes stale entry-a4
   (caller garbage on wrapper path); modeled without it.
4. arbit_deinit `s32i a2,(pool)` stores stale a2 (adapter+12 target); value kept as-is.
5. arbit_init/deinit success paths return entry-a2 (0 at actual call sites); modeled `return 0`.
6. status_change `(l & (b|m))` predicates at 62c/5d9 ride stale a2 holding (B|M) —
   value determined by dataflow, intent unclear; encoded as-is.
7. `coex_force_wifi_mode` inner timeout-loop bounds (low fidelity); outer
   constants exact.
8. `coex_bt_high_prio` out of scope (not libcoexist.a); register touches only.
9. Entry-a2 return conventions (`coex_deinit`, `coex_disable`, `coex_schm_status_bit_clear`
   return entry a2/type) preserved with notes, not normalized.
