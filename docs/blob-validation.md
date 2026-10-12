# Validation of open-mac register findings against current blobs

Independent check of `main/hardware.c` register semantics against
(a) disassembly of current-master WiFi/PHY blobs and
(b) a live MMIO trace (81k+ events) of IDF v6.0.3 wifi/scan +
a station associate/DHCP run under the esp32-open-mac QEMU fork.

## Confirmed registers

| Register | Addr | Confirmed by |
|---|---|---|
| DMA int status / clear | 0x3ff73c48 / 0x3ff73c4c | disasm + live trace |
| RX base / next / last descriptor | 0x3ff73088 / 0x3ff7308c / 0x3ff73090 | disasm + live RX chain (22k events) |
| TXQ complete / clear | 0x3ff73cc8 / 0x3ff73cc4 | disasm |
| TX PLCP0 / TX config | 0x3ff73d20 / 0x3ff73d1c | live TX (`lmacTxFrame`) |
| TX PLCP1 / PLCP2 | 0x3ff74258 / 0x3ff7425c | disasm (`hal_mac_tx`) + live (`hal_init`) |
| MAC ctrl (`ic_mac_init` mask `0xffffe800`) | 0x3ff73cb8 | disasm, exact match |
| RX enable bit 31 | 0x3ff73084 (`ic_enable_rx`, 29 B) | disasm, exact match |
| RX policy | 0x3ff730d8 | disasm + live (`sta_input`) |
| BSSID/MAC filter banks | 0x3ff73000 / 0x3ff73040 | live filter programming |
| AGC block | 0x3ff5c01c–0x3ff5c080 | live (`enable/disable_wifi_agc`) |
| RF channel data port | 0x3ff4e0c4 | live (`write_wifi_chan_data` x135) |

Note on MAC registers: the blob never materializes most MAC addresses
as literals. `wdev_mac_reg_load` (libpp `wdev.o`) programs register
**bank bases** (`0x3ff73000/3400/3800/3c00/4000/4400…`) and accesses
everything struct-relative (`wDevCtrl`/`if_ctrl`). Absolute addresses in
`hardware.c` fall inside these banks (e.g. `0x3ff73d20` = bank
`0x3ff73c00` + `0x120`). Same hardware, different addressing idiom.

## Init sequence in current blobs (differs from v5.0.1)

`wifi_hw_start` (`ieee80211_ioctl.o`) calls, in order:
`wifi_log`, `ieee80211_set_hmac_stop`, `wifi_reset_mac`, `ic_mac_init`,
`chm_init`, `ic_set_interrupt_handler`, `chip_enable`,
`pm_noise_check_enable`, `pm_mac_wakeup`, `pm_disconnected_start`, …

Version drift warning: `ic_enable` and `config_get_wifi_task_core_id`
(used in `main/hwinit.c` / `main/proprietary.h`) exist only in the
IDF v5.0.1-era blobs. Current blobs split `ic_enable` into `hal_init`
plus per-function enables, and the WiFi task core is fixed. Porting
`hwinit.c` forward needs the chain above, not `ic_enable`.

Symbol homes for the remaining init externs: `chip_v7_set_chan_nomac`,
TX-power and AGC functions live in esp-phy-lib (`phy_chip_v7*.o`, which
ship DWARF — signatures and source lines recoverable); `coex_bt_high_prio`
lives in esp-phy-lib `bt_bb.o`; `wifi_module_enable` is open source
(`esp_hw_support/periph_ctrl.c`); `phy_get_romfuncs` is mask ROM
(`0x40004100`, `esp32.rom.ld`).
