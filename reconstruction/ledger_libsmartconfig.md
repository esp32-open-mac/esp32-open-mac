# Ledger — libsmartconfig.a reconstruction (ESP32)

Source blob: `esp32/libsmartconfig.a` (Xtensa ELF32, 8 objects, 98 GLOBAL funcs).
Disassembly: `re/esp32/disasm_full/libsmartconfig/*.dis` (objdump, literal pools + `-r` relocs).
Output: `re/esp32/src/libsmartconfig/<object>.c` (8 files).
Funcdb: **v2** — `re/esp32/funcdb_libsmartconfig.json` re-read after the
`.rela.text.<func>` attribution fix; calls[]/refs[] now populated (~15% empty,
all true leaf stubs). Open-source ESP-IDF `smartconfig.c`/`esp_smartconfig.h`
were **not available offline** (no checkout on disk); API correlation below is
by symbol name only.

## Fidelity table (per function; H=high, M=medium, L=low)

### sc_crypt.o (4)
| func | fid | note |
|---|---|---|
| sc_get_encrypt_type | H | `return 1`, 3 insns |
| sc_aes_crypt_init | H | memset(aes_key,0,32) |
| sc_set_key | H | NULL/len==16 gate; -1-or-log-ret vs memcpy+0 paths |
| sc_get_key | H | memcpy(dst,aes_key,len&0xff) |

### sc_ieee80211.o (5)
| func | fid | note |
|---|---|---|
| sc_get_apinfo | H | sentinel-head walk +88, memcmp(node+0,6) |
| sc_cmp_bssid_crc | M | crc8-count then band==2-gated channel set; cfg+0xa00 field roles inferred |
| sc_get_apinfo_by_ssid | H | strcmp(node+51) walk |
| sc_ieee80211_aplist_process | H | stub returns 0 |
| sc_ieee80211_data_extract | M | br-compare + apinfo + encry gate; subtype bits approximate |

### sc_ht40.o (5)
| func | fid | note |
|---|---|---|
| ht40_init | H | sizes 15/15/64 memsets exact |
| ht40_lock_channel | H | 1..13 vote, >=2 confirm |
| ht40_scanning_sync_frame | M | window (164,1098], sync table, RSSI/filter gates |
| sc_ht40_get_qos_auth_group_info | M | vote counters; exact slots approximate |
| sc_recv_callback_ht40_ctrl | L | 494-insn mimo machine; phases/logs observed |

### sc_broadcast.o (5)
| func | fid | note |
|---|---|---|
| sc_get_data_score | H | 0x3e6 double bound + score_level walk transcribed |
| sc_is_sync_frame | M | apinfo/channel-lock phases; +0xa00 layout approximate |
| sc_try_to_sync_pos | M | strides 4/8/32, seed 100, +2/+44/+46 slot checks |
| sc_try_to_replace_same_pos | M-H | lane-vote loop transcribed; addr polynomials approximate |
| sc_recv_callback_broadcast | L | 641-insn machine; call order + logs observed |

### sc_esptouch_v2.o (31 + 1 static)
| func | fid | note |
|---|---|---|
| sc_decode_data$part$0 (static) | M | 6-bit unpack, fast/bit paths |
| sc_uptime_ms | H | osi+0x110 us / 1000 via __divdi3 |
| sc_os_get_time_ms | H | 0x10000-biased monotonic ms |
| sc_get_status | H | SnifGlob[17]/[18] 0/4/1 ladder |
| sc_set_state | H | 5-step indexed byte store |
| sc_set_dst_chan | H | empty stub |
| sc_recv_callback_wps/action | H | return-0 stubs |
| sc_zero_ssid | H | 33-byte all-zero test |
| sc_start_frame | H | 0x418 / +0x42f / ranges transcribed, total_seq log |
| sc_group_frame | H | (len-128)<=39 |
| sc_get_group_index | H | ((v-127)<<3)&0xff gated on start_frame |
| sc_data_frame | H | bit6 + ((v>>7)&0x7f)<8 |
| sc_get_data_index | H | ((v>>7)&0xf)+1 |
| sc_pkg_cmp/save | H | u16 slot compare/store |
| sc_decode_data | H | (a3==0\|\|a4==0)->0 else part0 |
| sc_dec_to_bin | M-H | self-recursive; log args approximate |
| sc_get_encode_len | H | muluh 0xcccccccd/0xaaaaaaab codec transcribed |
| sc_get_data_len | H | 0->8, >311->303 clamp |
| sc_recv_completed | L | 1114-insn voter; crc/len/AP checks observed |
| sc_set_mask_status | H | mask_data=(old&~m)\|v |
| TOUCH_v2_init_glob | M | 16B + 0xb08B allocs; mask/lock init |
| TOUCH_v2_free_glob | M-H | +0xa8b/33 +0xa4a/65 +0xaac/65 memsets exact |
| sc_get_ssid_passwd | L | 1500-insn decrypt/assembly; checks observed |
| sc_time_elapsed_ms_since | H | now-since |
| sc_restart_switch_channel | M | timer re-arm + cfg memsets; bases approximate |
| sc_ciper_type_transfer | H | CSWTCH {0,1,1,2,3,4}, else 0xff + warn |
| sc_recv_callback | M-H | 64B staging, nibble@21, extract->broadcast chain |
| sc_is_invalid_pkg | H | valid 127..1160 |
| sc_sniffer_cb | M-H | 5000ms (0x271<<3) dwell -> restart_switch_channel |
| sc_pack_handle | H | SnifGlob[16] fast path; L-4 adjust; 127..1160 filter |

### sc_sniffer.o (26)
H: fast_mode_local (50/100), all 5 IPC wrappers, get_version/type,
set_type/timeout_locals, internal_set_encrypt (99/0x19c/0x1da),
internal_start/stop, sc_free_sniffer_glob, sc_PackCallback dispatch,
smartstatus pieces. M: init/free globs, stop_local, listen_next_channel,
channel_timer_cb_local, add_bss, system_init_done, wifi_scan_done,
restart_local, start_local, get_rvd_data, smartconfig_get_status.
(v2-bleed notes inline for the 4 tiny wrappers.)

### sc_airkiss.o (11 + 2 static)
H: KISS_Find_channel dispatcher (frm+32/+44 vs AK_Group_bssid),
KISS_Deal_with dispatcher (rssi>=-84, type==2, trans/diret select),
all 6 init/free globs. M: Get_sequ_data (136/64..511 gates), Find_end/
trans/direct correlators. L: Deal_with_ht20 body (calls union from v2).

### sc_esptouch.o (11 + 1 static)
H: restart/get/set delay flags, init/free globs + guide. M-H: none.
L: Find_sync_ht20/ht40 + constprop End + Deal_with (gates/logs observed).

Counts: H≈55, M≈30, L≈13 (of 98 + 4 static partitions).

## Protocol observations
- ESPTOUCH_V2 (broadcast + HT40-ctrl MIMO): length-codec; start 1048 (0x418);
  group window len-128<=39; data = bit6 + 7-bit field <8; 6-bit symbols
  unpacked by part$0 (8 outer x 6 inner); encode-len via fixed-point
  muluh (/5-ish 0xcccccccd, /6-ish 0xaaaaaaab);crc8 per seq (esp_crc8);
  score voter with 0x3e6 bound + score_level table; completion needs all
  seqs + AP crc match + bssid; AES-128 credential decrypt (32B aes_key).
- ESPTOUCH v1: guide/multicast-broadcast classify, g_sync_min 512
  (412/474 encrypted), F|/T| two-stage length codec, enc_evt 216B staging.
- AirKiss: AK ff:ff:ff:ff:ff:ff group compare at frm+32 (trans) / +44
  (direct); seq gate frm[28]==136, L in [64,511]; RSSI floor -85 (0xab),
  bear 18 (0x12); rssi gate -84 in Deal dispatcher.
- Channels: 1..13 vote (ht40), 1..14 dwell (sniffer); 5000ms v2 lock dwell;
  timeouts: g_touch_timeout 30, g_ET_TimeOut >=15s clamp; encrypt preset
  (99, 412, 474); CHANGE_CH_FREQ 50/100; sScanTime 1/2; SC v3.0.3, git 6135a40.
- Length validity universal: 127..1160 (0x431 span); data-len clamp 303/311.

## Unknowns / risks
1. g_config_data blob layout (+0xa00 region): only accessed offsets known
   (+55 start flag, +56/57 mode, +59..66 length codec, +244, +65 rvd len,
   +49/+54/+237 AP-match, +20 state); struct NOT reconstructed (single-offset
   evidence each) — all uses via byte offsets.
2. SnifGlob[32] byte roles: [16] v2-active, [17] status, [18] count,
   [20] done-word, [24]/[25] kiss/sel flags, [0] channel — multi-offset but
   cross-object; kept as byte array pending cross-object struct proof.
3. Log-call (osi 0x150/0x158) argument order; free/malloc return paths on
   osi==NULL legs; __func__ strings truncated in dump ("mallo", "promi").
4. funcdb v2 calls[]/refs[] are **prefix-union supersets**: verified via
   `readelf -r` that e.g. sc_channel_timer_cb's own relocs contain only
   esp_wifi_ipc_internal while v2 unions _local's sc_listen_next_channel;
   same for esp_smartconfig_set_type/esp_esptouch_set_timeout (+_local's
   smartconfig_get_status), sc_get_apinfo (+by_ssid's strcmp),
   sc_smartconfig_restart (+_local's 3), KISS_Find_channel*,
   TOUCH_Find_sync_ht20*, KISS_Deal_with(+ht20 body), sc_dec_to_bin self
   (SLOT0-only, no EXPAND), sc_decode_data->part$0 (local label). Per-function
   headers use own-section ASM_EXPAND ground truth; v2 used for data refs +
   union attribution to static partitions.
5. funcdb addrs in sc_broadcast.o overlap (0x0c twice) — section-relative
   quirk; disassembly bodies authoritative.
6. TOUCH_v2 malloc-fail tail, Deal_with inner slot strides, ht40 per-limb
   stack offsets: approximate, flagged in file headers.
