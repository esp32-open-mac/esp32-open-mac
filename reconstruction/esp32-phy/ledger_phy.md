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