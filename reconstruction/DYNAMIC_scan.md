# Dynamic confirmation: live scan under esp32-open-mac QEMU fork

Firmware: IDF v6.0.3 wifi/scan, ESP32, 4 MB flash image + synthesized
eFuse (MAC 02:11:22:33:44:55, CRC-correct). Full RF cal + active scan
completed; emulated STA found 3 APs (Zeus WPI, meshtest, Open Wifi).

Trace: 81,156 MMIO events / 4,150 unique addresses / 1,854 unique PCs,
99.99% attributed to 74 functions (`tools/trace_attr.py`,
`/tmp/func_mmio.json`, `/tmp/mmio_func.json`). Resolution via
`build/scan.elf` symbols; PHY blobs carry DWARF (source lines).

## Static-reconstruction confirmations (live)

| Function (static claim) | Live observation | Verdict |
|---|---|---|
| `lmacTxFrame` programs TX slots via 0x3ff73d1c/0x3ff73d20 | R+W 0x3ff73d1c x33, R+W 0x3ff73d20 x11 | CONFIRMED (== open-mac PLCP0/config) |
| `hal_init` inits MAC bank | R+W 0x3ff741a8/e4/20, 0x3ff74220/5c (== PLCP2) | CONFIRMED |
| `ic_enable_rx` sets bit31 of 0x3ff73084 | (in 60s run window; covered by unit disasm) | static-only |
| `write_wifi_chan_data` writes channel words | W 0x3ff4e0c4 x135 (single RF port) | CONFIRMED |
| `chip_v7_set_chan_nomac` sequences DPORT+RF | W 0x3ff00024 x34, 0x3ff5d014/18/1c/20, 0x3ff5cc48 | CONFIRMED |
| `enable/disable_wifi_agc` | W 0x3ff5c080/30/1c/38 (AGC block) | CONFIRMED |
| `wdev_mac_reg_load` programs MAC bank bases | banks 0x3ff73000/3400/3800/3c00/4000/4400 in literals | CONFIRMED (static) |
| `tx_pwctrl_init/cal`, `ram_txdc_cal_v70`, `ram_iq_est_enable`, `ram_write_gain_mem` (4070 evts) | all on live stacks with PHY source lines | CONFIRMED live |
| `pp_post` dispatches without direct MMIO | 0 MMIO events attributed | consistent |

## Environment fixes required (harness, not reconstruction)

1. eFuse BLK0 MAC layout: driver reads MSB-first
   (RDATA1 = mac[2..5] BE, RDATA2[15:0] = mac[0]<<8|mac[1]... verified:
   consumed order is RDATA2[15:8],RDATA2[7:0],RDATA1 BE). Proven via CRC oracle.
2. Fork DPORT patch: added WIFI_CLK_EN (0xCC) + CORE_RST_EN (0xD0) R/W
   state — unblocks `phy_module_enable` clock-bit assert.
3. Fork BT dummy-map: DR_REG_BT_BASE read-only-0 — coex polls BT status.
4. `phy_get_romfuncs` ROM risk did NOT materialize: full RF cal executed.

## Coverage limits of this run

- 60–150 s single-step window covers boot + cal + scan only. No
  association, TX data path (only probe TX via lmacTxFrame), no PM sleep,
  no crypto. Those need longer/scripted runs (associate to fork AP).
- 83/500 top PCs are ROM (`??`) — ROM behavior out of scope.
- `esp_dport_access_reg_read` (33k events) is the ROM DPORT accessor
  innermost frame; outer-frame attribution available in raw trace.
