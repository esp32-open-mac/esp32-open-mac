# Ledger — libcore.a + libwapi.a reconstruction (ESP32, Xtensa)

Sources: `re/esp32/disasm_full/{libcore/misc_nvs,libwapi/wapi_sms4_algo,wapi_glue,wapi}.dis`,
`funcdb_libcore.json`, `funcdb_libwapi.json`, `nm`/`readelf`/`size` dumps of the
four objects in `/tmp/re_esp32/{libcore,libwapi}/`. All numeric constants in the
`.c` files were taken from the disassembly; nothing was invented.

## Per-function fidelity

### libcore.a : misc_nvs.o → `src/libcore/misc_nvs.c`

| Function | Addr | Size | Fidelity | Why |
|---|---|---|---|---|
| misc_nvs_load | 0x24 | 131B | medium | all branches/callees resolved; nvs_open return polarity (err-code) inferred from fail-log text |
| misc_nvs_deinit | 0x10 | 70B | high | straight-line/branchy glue, all table slots + offsets observed |
| misc_nvs_init | 0x0c | 46B | high | tiny guard + exact 2-call sequence |
| misc_nvs_restore | 0x04 | 16B | high | single tail call, const arg 1 |

### libwapi.a : wapi_sms4_algo.o → `src/libwapi/wapi_sms4_algo.c`

| Function | Addr | Size | Fidelity | Why |
|---|---|---|---|---|
| sms4_crypt (LOCAL) | sect+0x10 | 655B | medium | 8x loop (=32 rounds), Sbox + ssai rotations observed; round wiring structural |
| sms4_key_expansion (LOCAL) | sect+0x20 | 549B | medium | FK/CK/Sbox + 8x loop + reversal tail observed; L' wiring structural |
| wapi_sm_wpi_crypt$part$0 (LOCAL) | sect+0x0c | 180B | medium | frame, key schedule, 16B loop + remainder loop observed |
| wapi_sm_wpi_encrypt | 0x04 | 30B | high | shuffle + len==0→1 + mode-0 tail call |
| wapi_sm_wpi_decrypt | 0x04 | 30B | high | shuffle + mode-1 tail call; len==0 asymmetry preserved |
| wapi_sm_wpi_calc_mic | 0x14 | 196B | medium | early-outs, block loop, memcpy tail + final crypt observed |

### libwapi.a : wapi_glue.o → `src/libwapi/wapi_glue.c`

| Function | Addr | Size | Fidelity | Why |
|---|---|---|---|---|
| wapi_put_be32 (LOCAL) | sect+0x00 | 38B | high | exact stores (0,20,114) + cursor bump |
| wapi_selector_to_bitfield (LOCAL) | sect+0x00 | 64B | high | BE load, 2-constant compare, 1<<10 return |
| wapi_neg_complete | 0x04 | 11B | high | single tail call, passthrough return |
| wapi_sm_asue_challenge | 0x0c | 40B | high | slot-0x144 call + bgez + log shape |
| wapi_sm_check_header | 0x1c | 174B | medium | 6 checks + constants/strings recovered; (sm,seq,len) roles inferred |
| wapi_sm_get_param | 0x00 | 53B | high | full id switch, exact offsets |
| wapi_sm_parse_wapi_ie | 0x50 | 550B | low | phased pseudocode; selector/count semantics partly inferred |
| wapi_sm_set_ap_wapi_ie | 0x10 | 118B | medium | free/alloc shapes + clear path observed; (ie,len) roles inferred |
| wapi_sm_set_assoc_wapi_ie_default | 0x40 | 364B | low | phases follow stores/calls; selection/len-cap logic structural |
| wapi_sm_set_header | 0x00 | 58B | high | all 12 stores + p+12 return |
| wapi_sm_set_param | 0x00 | 67B | high | full id switch; NULL→-1 |
| wapi_supplicant_key_neg_complete | 0x18 | 116B | medium | MAC/log packing + stores observed; string-index polarity inferred |

### libwapi.a : wapi.o → `src/libwapi/wapi.c`

| Function | Addr | Size | Fidelity | Why |
|---|---|---|---|---|
| esp_wifi_internal_wapi_deinit | 0x04 | 13B | high | single tail call |
| esp_wifi_internal_wapi_init | 0x04 | 13B | high | single tail call |
| key_derivation_hmac_sha256 | 0x08 | 122B | medium | counter loop (62/32/31) + primitive shape observed; arg roles inferred |
| wapi_process_packet_type | 0x104 | 1418B | medium | header/frag/12-way dispatch gates + per-branch call sequences transcribed; state numbers/layouts structural |
| wapi_sm_deinit | 0x0c | 94B | high | 4 member frees + clear + unregister tail |
| wapi_sm_init | 0x58 | 367B | medium | alloc sizes, callback stores, memsets, -1/-2/-3 paths observed; slot meanings from section names |
| wapi_sm_set_own_addr | 0x04 | 20B | high | memcpy(sm+204, mac, 6) |
| wapi_txcb | 0x18 | 174B | low | phases observed; buffer roles inferred |

Counts cross-check: libcore 4/4, sms4_algo 3/3 globals (+3 locals), glue 10/10
globals (+2 locals), wapi 8/8 globals (locals prototyped, summarized).

## Recovered structs / globals (object-relative; runtime link addresses unknown)

- `misc_nvs_t` (60B, libcore): `raw[56]` + `handle@56` (2+ accesses: load
  passes buf+56 as open out-param; deinit reads + clears it). `u32@8` zeroed
  once — kept as raw bytes, not a named member.
- `wapi_sm_t` (glue view): `f08@8`, `f174@0x174`, `f178@0x178`, `f17c@0x17c`
  (each with 2+ accesses across set/get_param, parse, check_header,
  supplicant_complete). AP lens `@0x128/@0x12c`, assoc lens `@0x120/@0x124`,
  seq words `@0x170/@0x172`, frag `@0x198/@0x19c`, MACs `@204/+210`,
  key ids `@216/@220`, flag `@0x180` — observed offsets, single- or dual-use,
  listed in `wapi.c` header comment, not promoted to typed members.
- `g_misc_nvs` (BSS ptr, 4B), `g_misc_nvs_init` (BSS u8 flag),
  `g_log_mod` (24B) + `g_log_level` (4B) defined in misc_nvs.o;
  `gWapiSm` (BSS ptr, 4B, in `.bss.gWapiSm`) in wapi.o.
- `Sbox` (256B), `CK` (128B), `FK` (16B: a3b1bac6 56aa3350 677d9197 b27022dc).
- `libcore_reversion_git` / `libwapi_reversion_git` = `"6135a40"`.
- `wapi_process_packet_type` jump table: `.rodata.wapi_process_packet_type`,
  48B = 12 × u32 (relocatable code addresses).

## Unresolved unknowns (what would resolve each)

1. `g_osi_funcs_p` table layout (slots 0x12c/0x130/0x144/0x15c/0x16c/176/0xb0/
   0x178) — need the ESP-IDF `osi_funcs` struct definition or a linked image
   with symbols; would turn indirect calls into named calls (malloc/free,
   nvs_open/close, random-fill).
2. `g_wifi_menuconfig+36` flag meaning — need menuconfig struct / SDK config
   header; would name the NVS-enable condition.
3. `wifi_log(1, 0x100/4, 1/2, ...)` signature — need ROM/log header; would
   name mod/level args (currently passed through literally).
4. `wpa_crypto_funcs[8]` primitive exact prototype — need wpa_supplicant
   crypto ops struct; would fix key_derivation/mic arg lists.
5. SMS4 round-function exactness — compare against public SMS4 spec test
   vectors (encrypt a known block with linked code); would raise mediums.
6. `wapi_sm_init` callback-table slot meanings — need `ieee80211_register_wapi_cb`
   struct definition; would name the 7+3 stored function pointers.
7. `wapi_process_packet_type` state numbers / payload layouts — need 802.11 +
   WAPI (GB 15629.11) frame documentation plus a live trace; would raise low.
8. `wapi_sm_parse_wapi_ie` selector semantics (0x147201/0x147202/0xffeb8e00,
   count-18/30/62 relatives) — need WAPI IE spec section; would raise low.
9. Absolute addresses of BSS/rodata (all objects are relocatable, Addr=0) —
   need a linked binary (e.g. libnet80211-linked ELF) to give load addresses.
10. `wapi_txcb` buffer roles (0x150B copy, swap windows, vtable+4 target) —
    need caller context (`ic_register_tx_cb` registration site); would raise low.
