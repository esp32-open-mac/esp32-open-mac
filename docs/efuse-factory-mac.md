# eFuse BLK0 factory MAC layout (ESP32)

Proven by CRC oracle against live IDF v6.0.3 (`calc_crc` log output):
the driver consumes the 48-bit `MAC_FACTORY` field **MSB-first**.

| eFuse word | Bits | Content |
|---|---|---|
| BLK0 RDATA1 | 31:24 | mac[2] |
| BLK0 RDATA1 | 23:16 | mac[3] |
| BLK0 RDATA1 | 15:8 | mac[4] |
| BLK0 RDATA1 | 7:0 | mac[5] |
| BLK0 RDATA2 | 15:8 | mac[0] |
| BLK0 RDATA2 | 7:0 | mac[1] |
| BLK0 RDATA2 | 23:16 | CRC8 over mac[0..5] |

CRC8 = reflected, poly `0x8c`, init `0x00` — identical to
`esp_rom_efuse_mac_address_crc8` (`components/esp_rom/linux/esp_rom_efuse.c`).

Example (MAC `02:11:22:33:44:55`, CRC `0xd6`):
`RDATA1 = 0x22334455`, `RDATA2 = 0x00d60211`.

A zero/invalid MAC fails WiFi init with `ESP_ERR_INVALID_CRC`
(`get_efuse_factory_mac`, `components/esp_hw_support/mac_addr.c`).
Useful when synthesizing eFuse images for emulation (e.g. QEMU runs
without hardware).
