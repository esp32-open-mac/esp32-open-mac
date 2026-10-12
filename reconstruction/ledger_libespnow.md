# Ledger — ESP32 libespnow.a reconstruction

- Blob: `/Users/chaitanyarahalkar/esp32-wifi-lib/esp32/libespnow.a` (Xtensa ELF32, 2 objects, 43 funcdb functions)
- Outputs: `re/esp32/src/libespnow/espnow.c` (API/mutex layer), `re/esp32/src/libespnow/manatick.c` (core)
- funcdb: `re/esp32/funcdb_libespnow.json` **v3 used** (calls[]/refs[] exact per-function;
  verified no sibling-section bleed in this lib — v3 matches disasm ground truth everywhere checked).
  Known funcdb limitation (kept, worked around via disasm): calls[] covers only
  EXTERNAL R_XTENSA_ASM_EXPAND edges. The 7 LOCAL statics are called through
  section-relative literals and never appear in calls[] (8 manatick.o functions
  show empty calls[] for this reason — they are NOT leaf stubs).
- Toolchain: `~/.espressif/tools/xtensa-esp-elf/esp-15.2.0_20251204/...`
- ABI verified from code: incoming a2..a7; outgoing caller a10..a15 → callee a2..a7;
  target any reg via callx8; return in caller a10 (=a2 at retw); caller regs a0–a9
  preserved across calls (entry spill + callee saves), a10–a15 clobbered.
  Log idiom at every site: `t=_log_timestamp(); _log_write(level,"ESPNOW",fmt,t,"ESPNOW"[,...])`.

## Fidelity table

### espnow.o (23/23 in espnow.c: 22 funcdb GLOBAL + 1 LOCAL)

| Function | Fidelity | Why |
|---|---|---|
| wifi_sta_restore_default_mac_wrapper (LOCAL) | high | 3-instruction trampoline |
| esp_now_init | high | full block trace incl. IPC struct, levels, literals |
| esp_now_deinit | high | exact incl. set_flag(0) via reused zero return |
| esp_now_register/unregister_recv/send_cb | high | canonical template, exact |
| esp_now_add/del/mod_peer | high | canonical template, exact |
| esp_now_get_peer | high | 2-arg forward, exact |
| esp_now_fetch_peer | high | bool masked to u8 (extui), exact |
| esp_now_is_peer_exist | high | exact incl. quirks (create-fail→1, not-init→0) |
| esp_now_get_peer_num | high | canonical template, exact |
| esp_now_get/set_version, set_pmk, set_user_oui, get_user_oui | high | lock-only (no init check observed), exact |
| esp_now_set_wake_window | high | u16 mask + init check, exact |
| esp_now_send | high | unicast path + broadcast fetch loop exact |
| esp_now_set_peer_rate_config | medium | validation chain/constants/strings/returns exact; config-word and NVS-byte semantics inferred |
| esp_now_switch_channel_tx | medium | checks/mallocs/memcpys/ioctl/returns exact; req-struct field layout opaque (offsets as observed) |
| esp_now_remain_on_channel | medium | same as above; wifi_roc_process stored-not-called confirmed by funcdb refs |

### manatick.o (28/28 in manatick.c: 21 funcdb GLOBAL + 7 LOCAL)

| Function | Fidelity | Why |
|---|---|---|
| mt_recv_cb, mt_send_cb (LOCAL) | high | dispatch + INFO logs fully traced |
| mt_clear_lmk, mt_get_lmk (LOCAL) | high | offsets/calls exact; callee semantics opaque |
| mt_get_key_idx (LOCAL constprop) | medium | scan + 0xFFFF sentinel exact; mask semantics need libnet80211 |
| mt_set_lmk, mt_copy_peer (LOCAL) | medium | flow + keystruct offsets (0/160/168/184/185/186) exact; crypto/ic_set_key prototypes opaque |
| mt_init | high | zero/square init, cb regs, wake default, version log exact |
| mt_deinit | high | teardown order, node-walk frees, assert-hangs exact |
| mt_register/unregister_recv/send_cb | high | exact (unregister returns void — no a2 set) |
| mt_send | high | validation/channel-check/error map exact |
| mt_del_peer | high | unlink topologies, frees, counts exact |
| mt_mod_peer | high | 3 encrypt transitions, mode-arg tracing exact |
| mt_get_peer, mt_get_peer_info | high | exact (info returns internal node*) |
| mt_fetch_peer | high | cursor/multicast-skip/copy exact |
| mt_is_peer_exist | high | exact |
| mt_add_peer | high | validation/alloc/link/assert chain exact |
| mt_get_peer_num, mt_get_version | high | exact |
| mt_set_pmk | high | exact (dst g_mt+0 via rela addend) |
| mt_set_wake_window | high | exact |
| mt_set_peer_rate_config | low/med | ladder: all branches/constants/strings/returns exact, field semantics inferred; store path high |
| mt_set/get_user_oui | high | exact (NULL set = no-op success) |

## Recovered structs / globals

- `peer_node_t` (28B, `_wifi_malloc(28)`): next+0, prev+4, channel u8+8, ifidx u8+9,
  mac[6]+10, priv+16, key(struct*)+20, rate(12B*)+24. Padding +6..7 unobserved.
- `mt_state_t` = g_mt (60B, `.bss.g_mt`): key_state[16]+0, head+28, tail+32,
  total+36, enc_count+40, cursor+44, recv_cb+48, send_cb+52, wake u16+56.
  +16..27 unobserved.
- `g_mt_version` u32 = 2 (`.data` bytes observed); `g_espnow_user_oui[3]` =
  18:fe:34 (`.data` bytes observed, matches header default).
- `g_espnow_lock` (void*, `.bss`), `g_osi_funcs_p` (extern table).
- OSI slots verified vs `wifi_os_adapter.h` (ESP32): +76 recursive_mutex_create,
  +84 lock, +88 unlock, +172 malloc, +176 free, +336 log_write, +344 timestamp,
  +364 wifi_malloc, +376 wifi_zalloc.
- Public `esp_now_peer_info_t` (36B) layout confirmed behaviorally
  (MAC+0, LMK+6, channel+22, ifidx-word+24, encrypt+28, priv+32).

## Quirks preserved (verified, not bugs in reconstruction)

1. `esp_now_is_peer_exist` returns 1 on mutex-create failure, 0 when not init.
2. `esp_now_send` broadcast passes the init-flag value as `from_head` (observed 1).
3. `mt_set_lmk` crypto-fail logs "Encryption Failed", zeroes keystruct[0..15], still programs key.
4. `mt_add_peer` set-lmk-fail returns FULL (0x3068), not NO_MEM.
5. `mt_set_peer_rate_config` store-found path returns `(int)&g_mt` (nonzero) — a2=g_mt live at retw.
6. Deinit/init assert blocks: log + `manatick.c` + line, then `j .` self-loop hang.
7. `mt_set_pmk` overwrites g_mt+0..15 (same cells mt_init fills with i*i).

## Unknowns + what would resolve them

1. `g_mt.key_state[16]` semantics (i*i init vs PMK store) and `ieee80211_mt_key_*`
   contracts → need libnet80211 (symbols present but blob-only here).
2. `wpa_crypto_funcs[16/20]`, `ccmp` key-seal/open prototypes → need libwapi/wpa blob or symbols.
3. `ic_set_key`/`ic_del_key`, `ieee80211_send_action_vendor_spec` full prototypes → libnet80211 headers.
4. `wifi_log(x=1,y=2,fmt)` args; `wifi_action_tx_process`/`wifi_roc_process` req layouts → blob-only.
5. `g_wifi_menuconfig`/`g_wifi_nvs` byte meanings (+97 privacy, +80 enc-max, LR caps) → menuconfig/NVS map.
6. `esp_wifi_ipc_internal` block layout beyond {fn,0,0}+sync → wifi task IPC docs.
7. mt_set_lmk `mode` param name (0=alloc-slot/fresh, nonzero=reuse; values traced per call site).

## Counts

- funcdb: 22 espnow.o + 21 manatick.o = 43/43 covered, plus 8 LOCALs (1 wrapper + 7 statics).
- espnow.c functions: 23 (22 funcdb + 1 LOCAL wrapper) + 4 static reconstruction helpers
  (espnow_log, espnow_logx, espnow_ensure_lock, espnow_lock_and_check — shared
  idioms factored, each marked). manatick.c functions: 28 (21 funcdb + 7 LOCAL
  statics) + 3 static helpers (mt_log, mt_logx, mt_assert_hang — marked).
