# Dynamic confirmation: association + data path (open network)

Firmware: IDF v6.0.3 wifi/station, SSID meshtest (open, ch 2).
Result: authenticated + associated (aid 1) + **DHCP completed
(10.0.2.15)** via slirp user-net backend; 53 data frames exchanged
both directions (up to 612 B).

Trace: 274,854 MMIO events / 2,117 unique PCs / 99 functions,
0.0% unresolved (`/tmp/func_mmio_assoc.json`, `/tmp/mmio_func_assoc.json`,
resolver map rebuilt for wifi_station.elf).

## Confirmations beyond the scan run

| Function | Live observation | Verdict |
|---|---|---|
| `wdev_record_rx_linked_list` | R 0x3ff73088/8c/90/98 (RX desc chain, 22,920 evts) | CONFIRMED == open-mac regs |
| `hal_mac_rx_get_last_dscr` | R 0x3ff73090 x22,888 (RX poll loop) | CONFIRMED |
| `lmacTxFrame` (data frames) | R+W TX config, R 0x3ff73c00 bank + 0x6001c860/7c DMA, 477 evts | CONFIRMED |
| `pm_update_next_tbtt` | R 0x3ff73c00 x5,712 — PM TBTT tracking alive post-assoc | CONFIRMED (PM runs) |
| `coex_bt_high_prio` | W 0x3ff73d30/38 (MAC coex), 0x600310d0/0x60031300 | CONFIRMED |
| `sta_input` | RMW 0x3ff73024, 0x3ff730d8 (filter/policy on assoc) | CONFIRMED |
| auth/assoc exchange | QEMU frame log: auth req/resp, assoc req/resp, aid 1 | CONFIRMED (frame level) |
| DHCP + IP data | DISCOVER/OFFER/REQUEST/ACK via slirp; type=2 data both ways | CONFIRMED (frame level) |
| `cnx_assoc/auth`, `ppInstallKey`, `ieee80211_output` | 0 MMIO — control plane via IPC/shared mem, no direct regs | consistent (open net: no EAPOL/keys) |

## Still not live-observed (need WPA2 run / sleep run)

- EAPOL/key install (`ppInstallKey`, CCMP encrypt path) — needs WPA2 AP;
  fork AP model is open-only (would need fork extension).
- Modem sleep/wake (`pm_sleep` entry, `hal_mac_tsf` sleep regs).
- ESP-NOW / SmartConfig / mesh (separate firmwares + peer models).
