# PHY/RF blob ledger — DWARF-driven reconstruction

Scope: DWARF-bearing objects only (all of libphy/librftest/librtc/libbttestmode
except `librtc/eagle.app.o`, which has no `.debug_info` and no symbols).
Toolchain: `~/.espressif/tools/xtensa-esp-elf/esp-15.2.0_20251204/xtensa-esp-elf/bin`
(`xtensa-esp32-elf-{readelf,objdump,nm,addr2line}`). Producer string in every CU:
`GNU C11 5.2.0 -mlongcalls -mtext-section-literals -mfix-esp32-psram-cache-issue
-g -O2 -fno-inline-functions -ffunction-sections -fdata-sections`.
Xtensa ABI: args a2..a7, return a2 (caller-visible); with windowed `call8/callx8`
the callee's a2..a7 are the caller's a10..a15 and the return value arrives in
caller a10. Caller a0..a7 are callee-invisible and survive calls (used in
`write_wifi_chan_data`, `chip_v7_set_chan_nomac` reconstructions).

Artifacts:
- `dwarf_<lib>.json` — CU list, subprogram DIEs (name, decl file:line,
  return-type chain, params, low_pc/high_pc/ranges, abstract/inlined flags),
  type table. Parser: `extract_dwarf.py` over readelf text output.
- `disasm/<lib>/*.dis` (plain) + `*.rdis` (`-dr`, with `R_XTENSA_ASM_EXPAND`
  callee names). The `-S` (source-interleaved) dump was abandoned: it hangs on
  these objects; `addr2line -e ~/wifi-re/build/scan.elf` gives the same line
  mapping from the linked ELF.
- `src/<object>.c` — one file per object (35 files, names unique across libs).
  Generator: `gen_src.py`. Hand reconstructions applied with `replace_func.py`
  (see `/tmp/re_phy/blocks/` for the 20 applied blocks).
- `trace_xcheck.json` — live-trace cross-check (script `trace_xcheck.py`).

## 1. CU map

One CU per object (matches object basename):

| lib | object | CU source | comp_dir |
|-----|--------|-----------|----------|
| libphy | phy.o, phy_chip_v7.o, phy_chip_v7_ana.o, phy_chip_v7_cal.o | phy.c, phy_chip_v7.c, phy_chip_v7_ana.c, phy_chip_v7_cal.c | /home/lxf/gittree/chip7.1_phy/chip_7.1/board_code/app_test/pp/phy |
| libphy | phy_fpga_v7_cal.o, phy_fpga_v7_init.o | phy_fpga_v7_cal.c, phy_fpga_v7_init.c (empty CUs: 0 DIEs, 0 funcs) | same |
| librftest | ate_test, bb_common, crypto_common, esp_phy_api, mac_common, mod_subtest, rf_test, rtc_command, simple_wdt, wifi (.o) | same-basename .c | .../pp/rftest |
| librftest | esp32_se.o, i2s_test.o, io_config.o | CU present, 0 subprograms, 0 funcdb functions (data/comment-only objects) | .../pp/rftest |
| librtc | bt_bb, pm, rtc, rtc_analog, rtc_cntl, rtc_mac (.o) | same-basename .c | /home/cff/gittree/chip_rtc/chip7.1_rtc/.../pp/rtc |
| librtc | eagle.app.o | NO DWARF, NO symbols (out of scope; stub `src/eagle.app.c` placeholder) | - |
| libbttestmode | bt, bt_bb_common, bt_le_common, bt_rw, bt_rw_le_testmode, bt_rw_testmode, bt_testmode, cmd_polling (.o) | same-basename .c | .../chip7.1_rtc/.../pp/bt_testmode |
| libbttestmode | bt_lc_common.o | CU present, 0 subprograms, 0 functions (empty) | same |

## 2. DWARF JSON count consistency (funcdb vs DIEs)

funcdb counts GLOBAL symtab functions; DWARF counts all subprogram DIEs
(incl. statics, abstract + concrete inlined instances), so DWARF ≥ funcdb
everywhere except empty CUs (equal at 0). Verified 2026-10-12:

- libphy: phy.o 6/3, phy_chip_v7.o 216/152, phy_chip_v7_ana.o 101/76,
  phy_chip_v7_cal.o 79/56, fpga 0/0.
- librftest: wifi.o 314/74 (most inlined instances), rf_test.o 128/56,
  bb_common.o 80/33, others proportional; esp32_se/i2s_test/io_config 0/0.
- librtc: pm.o 29/16, rtc.o 27/24, rtc_analog.o 27/19, bt_bb.o 25/15,
  rtc_cntl.o 6/4, rtc_mac.o 3/2, eagle.app.o 0/0.
- libbttestmode: bt_testmode.o 240/150, bt_rw_testmode.o 240/132,
  bt.o 68/2 (66 statics!), bt_bb_common.o 71/43, bt_le_common.o 62/36,
  bt_rw_le_testmode.o 80/54, bt_rw.o 20/19, cmd_polling.o 8/4, bt_lc 0/0.

`funcdb_missing_in_dwarf` residuals, all resolved:
- `$part$` clones (GCC cold-part splits, e.g. `spur_cal$part$8`,
  `rw_frm_refresh$part$5`): base name always present as concrete DIE →
  headers use `[dwarf-sig-base]`.
- 5–7 byte LOCAL/GLOBAL stubs with no DIE (`rf_rw_force_agc_enable`,
  `rf_rw_sleep`, `rf_rw_txpwr_dec`, `rxlink_count`, `pm_prepare_to_sleep`,
  `flash_init_param_print$part$1` base present): bodies exact per disasm
  (`return 0/1;` or bare `return;`), fidelity high, `[inferred]` only where
  no DIE exists at all.

## 3. Fidelity table (per-function headers in `src/`)

1090 funcdb headers + 7 DWARF-only statics = 1097 headers. Braces balanced
(comment/string-stripped check), every funcdb name present — VERIFY OK.

- high (24): trivial stubs with exact bodies (e.g. `rf_rw_reg_rd`,
  `chip_v7_se
...[truncated 6154 chars]
## 4. Worker session 2026-10-12 — 11 low->medium/high upgrades (offline)

Scope: REAL functional targets only; rftest/bt_testmode factory-test files
untouched. All 11 targets verified still `Fidelity: low` on read (no clash
with the concurrent small-leaf worker). No live-trace coverage for these
functions exists in /tmp/func_mmio_{assoc,scan}.json (ATE/test-path code, not
hit by live traces) — therefore no [trace-confirmed] tags; all claims are
disasm+DWARF+rodata grounded instead.

Methods: xtensa toolchain (esp-15.2.0_20251204) `objdump -dr` (relocs give
exact callees), `readelf -r` (R_XTENSA_32 pool -> g_phyFuns/symbol/fmt-string
resolution), `readelf -x`/`objdump -s` (.rodata.str1.4 exact printf formats,
.rodata.CSWTCH$* exact jump-table contents). Windowed-ABI register-liveness
rules applied (caller a2..a7 survive calls; a8..a15 clobbered; return in
caller a10) to resolve stale-register value reuse (rtc_init_full a5/a6 mask
reuse, get_iq_est_snr round-2 first addr via preserved a5).

Per-function old->new (all verified: header re-tagged, braces balanced,
gcc -fsyntax-only clean inside upgraded spans; remaining file errors are
pre-existing in untouched/other-worker code):

- rtc.c:rtc_init_full low->high. Full 40-read RMW chain with exact
  masks/addrs, pwrctl_init gate, 8 fpu-bit lanes, dec_hbw/inc_hbp bits,
  rtc_dbias/dig_dbias 3-bit field-packs, rtc_init_clk(0,fast,div,ana,dcap,
  dfreq) tail. 4 params proven unused (no stack read): rtcreg_fpu,
  rtcdboost_fpu, x32k_dac, lslp_meminf_pd. Unlock: RTC clock/power bring-up
  path now exact.
- ate_test.c:module_test_cal_print low->medium-high. All 57 phy_printf sites
  with exact .rodata.str1.4 formats, loop bounds/steps/ends (pool symbols),
  (f>>6)&0x1f / f&0x3f field-decode clamps (15/31), zero-default 0x100 RXDC
  lane. Redundant print_en gates folded (entry gate dominates). Unlock:
  entire cal-dump table readable.
- ate_test.c:get_iq_est_snr low->medium. 8 divdi3 quotient blocks (exact read
  pairs, add/sub order, (s<<14)/0x7fe03 scale; round-2 sum/diff swap proven
  via a5-liveness), 64-bit square-accumulate + carry chains, get_power slots
  (u64[3..6] partials, u64[0..2] finals), shift normalization, print gate,
  linear_to_db x2 + S16 dB-diff return. Unlock: IQ-imbalance SNR primitive.
- ate_test.c:freq_offset_get_pwr low->medium. Tone/RXIQ setup RMWs
  (0x3ff450a8 &~3, 0x3ff460b8 field/or), 1<<loop_bits loop, hook81/hook82
  (g_phyFuns[0][81]/[82]) + prologue/epilogue hook15 per-iter order,
  get_iq_est_snr(scratch,corr,print), exact 7-lane u64 ADC swizzle
  (p[0]+=s[1],p[1]+=s[0],straight rest), funnel normalize, rxiq_sign-gated
  dB tail, *rxiq_remain=(snr+8)>>4, 0x3ff460b8&=~bit18 restore. Unlocks
  freq-offset correction loop.
- phy_chip_v7.c:get_iq_est_snr_1 low->medium. Same 8 quotient blocks as the
  rftest twin (verified identical pairs/order), partials u64[4]+u64[3] only
  (u64[5]/[6] stores proven absent), print-gated normalize+print, void tail
  stores u64[0..2]; no dB tail. Unlock: PHY-side twin of the SNR primitive.
- phy_chip_v7_cal.c:pbus_rx_dco_cal_1step low->medium. samp=(mode==1)?8:16,
  hook47 x2 + hook46 lanes (slots via g_phyFuns[0]), popcount-6 + SAR-step
  ladder, mode==1 single-stage vs 3-stage (hook46/ets10/rxdc_est_min x2 with
  dc diffs + max) paths, threshold ladder (49/44/45/9/0x186 exact
  immediates), [0,0x1ff] clamp walk, dc_flag updates, final hook pair.
  Unlock: RX-DCO cal step.
- phy_chip_v7_ana.c:bt_get_i2c_data low->medium-high. hook42/hook38 prologue,
  i2c_num==0 return, exact chained 11-lane table (mst/block/addr/atx/dtx/
  arx/drx constants per lane verified op-by-op), rd_en chaining
  (lane0 sets 1, chains preset 0, tail sets index), >=11 blank-lane tail
  loop. Header Calls line corrected (no DPORT reloc in disasm). Unlock: BT
  i2c table programmer.
- phy_chip_v7_ana.c:bt_i2c_write_set low->medium. Prologue 0x3ff4e0c4 RMW +
  num==0 early store/return, rd_en bitmask loop -> 0x3ff4e164, phase-1
  (i>>3 -> 0x100/104/108, pointer-xor mask idiom reproduced exactly),
  phase-2 (i>>1 jx -> 9 regs + 0x110 default, byte-pack), phase-3 (0x128/
  0x12c + (i>>3) -> 0xd0(+0x11c)/0xd4(+0x120)/0x124(+0x124)), phase-4
  double-switch on addr_rx/tx[i]>>2 (-> 0xc8/0xcc/0x114/0x118). Unlock:
  BT i2c write programmer skeleton.
- mac_common.c:fill_tx_frame low->medium. crypto_disable first, queue mask +
  exact CSWTCH$47/45/49 triples (27 entries embedded) + defaults, rate-clear
  via CSWTCH$51 (else-branch writes 0x60033d1c), tx_rate>15 big/small
  descriptor builds (exact words incl. 0x200b000/0x7000000/0xf000000
  markers), psdu-zero early return, psdu-count select, MAC header fill +
  cumulative-bound scatter loop (DWARF packet0..3 locals used). Unlock: TX
  descriptor builder.
- bb_common.c:ate_rxframe_fb low->medium. Addr-get quartet, set_chan,
  setup print, 16-op setup RMW chain (exact), fill_txdataframe prefill
  (4/fb_len/0x10203040/0x5060/"test" + frame-slot rate/gi), conf mask,
  poll/timeout(0x1e8480)/GetStopCmd("rx stoped!") loop, seq->bitmap0..3
  lanes, harvest + tx_add_pocketnum + re-arm. Unlock: ATE RX feedback loop.
- bb_common.c:do_rx_poll low->medium. Zero-fill + setup RMW chain,
  desired_count=10*(f-0x400)+3 law, flash_test_run + bany gates, poll loop
  (reads, get_rx_freq_local, err/correct counters, min/max ladder,
  rssi_base ring, ets_delay_us(30), bb_wdt, GetStopCmd back-edge), tail with
  exact 8 formats and verified gates (correct_count, err-loop, short_log_en,
  rssi_min_max_print 1-byte flag, frame[0x684] rate-hi byte). Unlock: RX
  polling/measurement loop.

Support edits (additive only): REG_READ/REG_WRITE helper blocks added to
rtc.c, ate_test.c, bb_common.c, mac_common.c (same convention as phy files);
same-TU forward decls (bb_common.c x4, ate_test.c x2, phy_chip_v7_cal.c x1);
footers extended (mac_common.c +TXBUF/PSDU symbols 4->9; bb_common.c
+rssi_min_max_print 53->54). No non-target function bodies touched; no
rftest/bt_testmode factory-test files touched.

VERIFY: per-file brace balance OK (46/46, 27/27, 37/37, 148/148, 102/102,
271/271, 25/25); gcc -fsyntax-only reports no errors inside any upgraded
span (remaining errors pre-existing in untouched/other-worker code:
unknown types, NULL/false/int16 conventions, cross-stub conflicts).

## 5. Leaf-upgrade pass 2026-10-12 — 14/14 live-observed lows + fabrication fixes (offline)

Triage order per mandate: (1) all functions in /tmp/func_mmio.json that map
to PHY funcdb entries, by trace weight; (2) leaves >100B by descending size
as budget allowed; (3) bulk inventory verification for the rest. Xtensa ABI
(callee a2..a7 = caller a10..a15, return in caller a10, caller a0..a7
survive) applied throughout; every numeric constant comes from disasm
literals (l32r/pool/movi), verified by `xcheck_bodies.py` (movi-positive
<= 0xFFF empirically; single-bit and low-mask extui/bbci idioms allowlisted).
DWARF JSON untouched (read-only). Braces balanced (35/35 files), all 1090
funcdb names present.

### 5a. Upgraded leaves (15)

14/14 live-observed low leaves (all funcdb-mapped trace functions that were
low fidelity), each [trace-confirmed] (trace MMIO explained: direct-addrs
present = strong; subtree-only = consistency; top-N truncation noted):

- high: ram_tx_pwctrl_bg_init (g_phyFuns[71] hook + 0x3ff4e060 set-bit1),
  ram_iq_est_disable (dual 0x3ff4607c clear-bit lanes + delay),
  ram_en_pwdet (5-lane 05c/050/0c0 RMW chain + pwdet_sar2_init).
- medium: txcal_debuge_mode (6 indirect hooks + arg computation),
  txpwr_offset (gate/hooks/pack/6B copy/SRAM stores; m_offset vestigial —
  clobbered unread, cf. ram_iq_est_enable precedent),
  ram_get_fm_sar_dout (RMW prologue, bnez poll loop, g_phyFuns[75] hook,
  saturating compares), tx_gain_table_set (staging, 8x g11 loop, gate,
  force/set/dig-gain tail), ram_txiq_get_mis_pwr (bit-pack, RMW, dual
  g77 hooks, gain-code), write_txrate_power_offset (clear path, dual
  accumulate/store loops, lr_enable gate, RMW pair),
  rfcal_txiq (prologue, func_sel dispatch, measure/track loop, cover+clamps),
  set_rx_gain_table (staging, hooks, dual gen/testchip/wr dispatch, gates,
  RMW tail), set_rx_gain_testchip_70 (BT on/off paths, cal dispatch),
  ram_set_pbus_mem (staging, jump table per .rodata.ram_set_pbus_mem —
  order extracted from the object, pack/tail lanes, inner copy loop;
  trace W counts 76/38 match loop structure exactly),
  register_chipv7_phy (init dispatch, cal-data branches, restore/program
  tails, path-dependent hook base documented, not "fixed").
- medium-low (reconstructed in place): set_rx_gain_cal_iq — prior body was
  fabricated (0x3ff44794/0x3ff4579x + pseudo-helpers with no relocs);
  replaced with lane-faithful sweep/select skeleton (exact prologue/tail,
  search-law outcomes still TODO).

### 5b. Proven-error fixes in high/medium (untouched except these)

- agc_reg_init (high): prior 20-lane body was a bb_reg_init copy-paste (12
  BB lanes absent from its pool); replaced with the true 18-lane program
  (all literals pool-verified; lane-4 dead-literal reuse and 0x37400
  mask-reuse noted). bb_reg_init itself verified legitimate (own pool).
- get_spur4m_pwr (medium): final lane `& ~0x8000000` (bit27) corrected to
  `& 0xff7fffff` (bit23) per disasm.
- tx_delay_cfg (high): HT40-lane addrs 0x3ff5c030 corrected to 0x3ff5d030
  (both lanes use d030/d000); header MMIO likewise.
- esp_tx_state_out (high): no change needed — 0x3ff44530 is the
  shift-folded form of disasm `(idx + 0x0ffd114c) << 2`; comment added.
- Header MMIO inventory corrections (ELF+.o adjudicated, own-frame
  convention): force_txrx_off (drop 0x3ff4e060, keep 0x3ff460a0),
  phy_pwdet_onetime_en (0x3ff4e080 -> 0x3ff4e060),
  ram_set_chan_cal_interp (11 addrs -> none; pure arithmetic, verified),
  get_chan_pwr_index / get_phy_target_power / set_chan_dig_gain (-> none;
  claims were shared-pool contamination, reloc tables confirm),
  tx_pwctrl_cal (drop 0x3ff4e050, keep 0x3ff46008/0x3ff4e060),
  set_most_pwr_reg / bt_track_tx_power (revert unverifiable additions),
  phy_force_wifi_chan (drop 0x3ff5c07c; keep 0x3ff4e0c4 per .o lanes),
  pll_correct_dcap (drop 0x3ff5d040/0x40000000; keep c0/c4/4e130/c8 per .o
  lanes — the 0x3ff5d03c line belongs to bb_rst_en_set's range).
- Bulk inventory pass (`verify_headers.py --fix`, low/medium-low only, with
  body-reference guard): 10 headers corrected (bb_bss_cbw40 +0x3ff5cc0c
  40MHz lane; phy_reg_check region bases; set_most_pwr_reg review;
  bt_i2c_write_set 27-addr program; phy_force_wifi_chan/set_chan_dig_gain/
  tx_pwctrl_background/tx_pwctrl_cal/set_chan_freq_hw_init call lists;
  bt_track_tx_power review).
- bt_get_i2c_data: superseded — parallel worker upgraded it to medium-high
  (header rewritten without the ungrounded claim) after this review.

### 5c. Verification results

- `verify_headers.py` (range-exact attribution by symtab, rdis+.dis
  merged, section-aware pool handling): 1089 checked, 1059 ok (97%).
  30 residual mismatches, all triaged: 1 no-disasm-label ($part$4 clone),
  29 hands-off high/medium (mask-literal class, shared-tail inferences,
  header-under-claims on bodies whose lanes are TODO — listed in tool output,
  none actionable under the hands-off rule; 0 upgradeable remain — the last
  one, bt_get_i2c_data, was upgraded by the parallel worker).
- `xcheck_bodies.py` (260 hand bodies): 10 residual flags, all adjudicated
  non-errors (inline LE-assemble idiom, g-table hook shorthand, shared-tail
  entries, shift-folded bases, rodata-table addresses, single-bit tests).
- Fidelity census at pass end: 1098 headers = high 145 / medium 80 /
  medium-low 37 / low 836 (parallel worker concurrently upgraded ~12 more
  leaves; see §4).

### 5d. Methodology findings (for future passes)

- Shared-.iram1 literal pools contaminate label-based attribution; missing
  labels in .dis cause bleed the other way. Range-exact attribution by
  object symtab (extracted objects in leafobj/) fixes both; pool-dump
  lines are never attributed (gaps), inline values always are.
- scan.elf links a DIFFERENT libphy build than esp-phy-lib/esp32/*.a
  (prologue-level divergence, e.g. pll_correct_dcap). The ELF is therefore
  valid ONLY for live-trace cross-checks, never for .o corrections.
- nm -S sizes can be short vs actual extent (pll 0xe2 vs 0xee+tail);
  funcdb sizes used for ranges.
- Trace attribution in /tmp/func_mmio.json is on-stack (includes callee
  subtrees) and top-N truncated per function.

### 5e. Remaining low leaves (836 low + 37 medium-low)

- 390 unobserved >100B: 183 libbttestmode + 146 librftest (factory-test,
  out of scope per worker split) + 39 librtc + 22 libphy core (future
  hand work; same tooling applies).
- 426 small (<=100B) unobserved: stubs verified-as-is (call/MMIO
  inventories match disasm; bodies honestly TODO).
- 37 medium-low: skeletons with verified backbones; search-law/detail
  TODOs as noted per function.
- Tooling kept in-tree: verify_headers.py, xcheck_bodies.py,
  pool_resolve.py (exploratory), leafobj/extract_all.py + extracted
  objects for range-exact parsing.

## 6. BT-testmode factory-test pass 2026-10-12 — 12 low->medium upgrades (offline)

Scope: the 12 ESP32 BT-testmode factory-test functions named in the work
order (wifi.c untouched — run_rftest_case still medium, verified).
Ground truth: dwarf_libbttestmode.json (read-only), libbttestmode/*.rdis
(`-dr` relocs = exact callees; l32r literals = exact immediates/MMIO/fmts),
.rodata.str1.4 of bt.o/bt_rw_testmode.o/bt_testmode.o/bt_rw_le_testmode.o
(extracted via xtensa-esp32-elf-ar + objdump -s; every phy_printf format
used is byte-exact from rodata), .rela pool resolution for the loopback
packet tables. Windowed-ABI liveness (caller a0..a7 survive calls) used to
resolve rw_init_cs stack args (chan/freq) and stale-register reuse.
No live-trace coverage (ATE/test-path code) — no [trace-confirmed] tags.

Methods per family (repetition exploited: rw_rx_per mapped fully, then
deltas; same for LE and BT_rx_*):
- rw_rx_per (reference): all 17 rw_init_cs args resolved
  (format=3, ltaddr=0, edr, whdsb=1, bdaddr=0x6bc6967e/0, txpwr=0,
  hoppe=0, freq=chan, tx_eir=0, rxwide=1, rxwinsz=20, txdesc=0,
  maxfrmtime=5, rxthr=1); exact EM program words; 16x EM bit-expand
  (0x2000301) and clear (0xffffffcf) loops; GetStopCmd 0/3 exit protocol;
  sticky status-bit0 + priority error ladder; gain/RSSI accumulate;
  get_bt_rx_rssi lane order; both print formats exact.
- Dispatchers (rw_autotest 70 strcmp / BTAutotest 64 strcmp): exact command
  strings in exact order with exact per-branch callees, print formats and
  para lanes (byte/half/word sizes + stack spill lanes as observed);
  "rw_le_rx_per_syncw" is a verified no-op slot; "rw_le_rx_per" aliases
  rw_le_rx_per_syncw; strcmp-zero a10 idiom (set_chan_freq_sw_start(0,p0))
  and command-pointer reuse (BT_rx_noise link args) preserved.
- Loopback: reloc-resolved packet order per link_type path
  (1: NULL..DV x8; 2: EV3/4/5; else: 2EV3..3DH5 + NULL/POLL/FHS/DM1 x18),
  ets_delay_us(100) + debug per round, GetStopCmd back-edge.
- Tester: gate funnel, opcode/ncop prints, hopping check, TA print,
  5-arm scenario switch, senario_print, verified nibble->type4 law
  (0/1/2/other -> 4/2/5/3), "\n" print, 16-count loop, link RMWs,
  LM_test_control (9 args), TC print, conditional lm_state.

Per-function old->new (all low->medium; headers re-tagged, [dwarf-sig]
kept; braces balanced 240/240, 70/70, 171/171, 97/97; gcc shows only
pre-existing error classes — implicit cross-TU decls, strcmp convention
as in wifi.c — plus zero conflicting-types after forward decls):
- bt_rw_testmode.c: rw_rx_per, rw_rx_per_ulap (+PRBS9 seed/harvest,
  btrx_result[6]/btrx_valid stores, valid-gated re-poll, 21-lane print),
  rw_rx_per_ulap_rssi (+RSSI track, 25-lane summary, "%x "-dump + "\n"),
  rw_autotest (full dispatch).
- bt.c: BTAutotest (full dispatch incl. BT_rx_noise 8-call chain +
  "%x %x %x %x" tail, RdMem loop, hook-slot calls).
- bt_testmode.c: BT_rx_per (hook slot 32, type-switch bounds 56/67/83,
  quou average, 32-lane print with 21 passed words noted),
  BT_rx_ber (PRBS9, tick/time_out gate, bits-budget exit, 36-lane print),
  BT_loopback_master, BT_testmode_lm_model_tester.
- bt_rw_le_testmode.c: rw_le_rx_per (LE init chain incl. 0xdeadbeef/
  0x71764129/0x555555, dual-descriptor unpack, 21-lane print),
  rw_le_rx_per_syncw (+syncw init, esp_rx_result/valid, short_log_en
  "rx_num/rx_rssi" line), rw_le_rx_per_syncw_rssi (+sext RSSI "r" lanes).

Support edits (additive only): REG_READ/REG_WRITE + same-TU forward
decls in all 4 files; packet_struct (5-word, marshal-verified) in
bt_testmode.c. Non-targets untouched: low==TODO count invariant holds
in all 4 files (128/128, 1/1, 146/146, 51/51); wifi.c untouched.
Approximate (flagged per header): error-counter DWARF-name routing
(slot order exact; i/total_p/pwr lanes verified), multi-word packing
in a few dispatcher branches, tester per-arm table immediates,
g_phyFuns hook-slot identities.
