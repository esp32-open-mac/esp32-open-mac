# Cross-validation: our blob RE vs esp32-open-mac ground truth

Date: 2026-10-12. Blob set: current master (open-mac used IDF v5.0.1 era blobs).

## Register map: 10/15 direct hits, 5/5 explained

142 unique MMIO addresses recovered in `ledger_libpp.md` (241-row map).
Checked open-mac `main/hardware.c` key registers:

| Register (open-mac) | Addr | In our map? |
|---|---|---|
| DMA int status / clr | 0x3ff73c48 / 4c | YES |
| RX base / next / last desc | 0x3ff73088 / 8c / 90 | YES |
| TXQ complete / clr | 0x3ff73cc8 / c4 | YES |
| MAC ctrl | 0x3ff73cb8 | YES (== open-mac `ic_mac_init`: `&= 0xffffe800`) |
| bitmask 084 | 0x3ff73084 | YES |
| rx policy | 0x3ff730d8 | YES |
| TX PLCP0 / TX config / TX PLCP1 | 0x3ff73d20 / 1c / 0x3ff74258 | banked (see below) |
| MAC addr slot0 / BSSID filter | 0x3ff73040 / 0x3ff73000 | banked (see below) |

The 5 "misses" never appear as literals because the blob programs MAC
register **banks**: `wdev_mac_reg_load` (wdev.o) loads bases
0x3ff73000, 0x3ff73400, 0x3ff73800, 0x3ff73c00, 0x3ff74000, 0x3ff74400…
from its literal pool and issues them via struct/window-relative accesses
(`wDevCtrl`, `if_ctrl`). Open-mac's absolutes fall inside these banks
(e.g. 0x3ff73d20 = bank 0x3ff73c00 + 0x120). AGREEMENT, not conflict.

## Init path: version drift found

- `ic_enable`, `config_get_wifi_task_core_id` exist ONLY in open-mac's
  trimmed v5.0.1 `libpp.a`, not in current blobs. Current init goes
  `wifi_hw_start` -> chip_enable, chm_init, ic_mac_init(x2),
  ic_set_interrupt_handler, pm_noise_check_enable, pm_mac_wakeup,
  pm_disconnected_start (+ wifi_log, ieee80211_set_hmac_stop, wifi_reset_mac).
- `wifi_module_enable` is open source (`esp_hw_support/periph_ctrl.c:141`).
- `phy_get_romfuncs` is mask ROM @ 0x40004100 (`esp32.rom.ld:189`).
- `chip_v7_set_chan_nomac`, `tx_pwctrl_background`, AGC, `coex_bt_high_prio`
  live in esp-phy-lib / esp-coex-lib (indexed: 1090 + 96 funcs).

## Implication for "remaining" work

Open-mac's TX/RX/filter/IRQ semantics are confirmed against current blobs
and can be trusted as ground truth for dynamic-trace interpretation.
Init must be re-derived against current blobs (done statically, see init
closure: 44 funcs / 3 hops from `wifi_hw_start`); QEMU trace will confirm.
`phy_get_romfuncs` (ROM @0x40004100) is the top dynamic-analysis risk:
if the QEMU fork doesn't emulate that ROM region, PHY cal will fault.
