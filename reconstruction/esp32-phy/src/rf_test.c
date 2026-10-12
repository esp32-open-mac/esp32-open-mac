/* Reconstruction of rf_test.o (librftest.a)
 * CU: rf_test.c | comp_dir: /home/lxf/gittree/chip7.1_phy/chip_7.1/board_code/app_test/pp/rftest
 * producer: GNU C11 5.2.0 -mlongcalls -mtext-section-literals -mfix-esp32-psram-cache-issue -g -O2 -fno-inline-functions -ffunction-sections -fdata-sections
 * DWARF subprograms: 128 | funcdb functions: 56
 * Disasm: re/esp32-phy/disasm/librftest/rf_test.rdis
 * Signatures tagged [dwarf-sig] (concrete DIE), [dwarf-sig-decl] (declaration-only DIE),
 * [dwarf-sig-base] (split $part$ clone; signature of base), or [inferred] (no DIE).
 * Fidelity: high = exact (stub or hand-verified); medium = structure + calls/MMIO verified,
 *   some expressions approximate; low = signature + header only, logic TODO.
 */
#include <stdint.h>
/* DWARF-derived fixed-width aliases (Xtensa LE, ILP32). bool is an 8-bit
 * unsigned type in this TU per DWARF (bool -> unsigned char). */
typedef unsigned char U8, u8, uint8, uint8_t, SDL_Octet, bool;
typedef signed char S8, s8, sint8, int8;
typedef unsigned short U16, u16, uint16, UnsignedShortInt;
typedef short S16, s16, sint16, ShortInt;
typedef unsigned int U32, u32, uint32, uint32_t, STATUS, CriticalType;
typedef int S32, s32, sint32, int32;
typedef unsigned long long U64, u64, uint64;
typedef long long S64, s64;

/* ESP_TEST_GPIO_func rf_test.c:809 @ rf_test.o size 30B [dwarf-sig]
 * Calls: ESP_TEST_GPIO, phy_printf | Data refs: .rodata.str1.4, ESP_TEST_GPIO, phy_printf | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void ESP_TEST_GPIO_func(uint32 * para_array)
{
    (void)para_array;
    /* DWARF locals: u32[] Input_result@l811 */
    /* TODO(ground-truth): reconstruct from librftest/rf_test.rdis
     * function <ESP_TEST_GPIO_func> (12 insns) + DWARF line rows for rf_test.c:809.
     * Ordered callee relocs: ESP_TEST_GPIO, phy_printf.
     */
}

/* PsramQIOConf rf_test.c:1386 @ rf_test.o size 288B [dwarf-sig]
 * Calls: esp_dport_access_reg_read, gpio_output_set, SPIPsramInitCheck, SPIPsramEnable, SPIPsramEnterQIO | Data refs: SPIPsramEnable, SPIPsramEnterQIO, SPIPsramInitCheck, esp_dport_access_reg_read, gpio_output_set | MMIO: 0x3ff42008, 0x3ff4201c, 0x3ff42020, 0x3ff42024, 0x3ff4202c, 0x3ff42034
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
uint32_t PsramQIOConf(uint8_t PSRAM_CS_IO, uint8_t PSRAM_CLK_IO, uint32_t clk_div, uint32_t drv)
{
    (void)PSRAM_CS_IO;
    (void)PSRAM_CLK_IO;
    (void)clk_div;
    (void)drv;
    /* TODO(ground-truth): reconstruct from librftest/rf_test.rdis
     * function <PsramQIOConf> (112 insns) + DWARF line rows for rf_test.c:1386.
     * Ordered callee relocs: esp_dport_access_reg_read, gpio_output_set, SPIPsramInitCheck, SPIPsramEnable, SPIPsramEnterQIO.
     */
}

/* PsramQIORead rf_test.c:1412 @ rf_test.o size 132B [dwarf-sig]
 * Calls: esp_dport_access_reg_read | Data refs: esp_dport_access_reg_read | MMIO: 0x3ff42000, 0x3ff42004, 0x3ff42034
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void PsramQIORead(uint32_t spi_addr, uint32_t length)
{
    (void)spi_addr;
    (void)length;
    /* DWARF locals: uint32 len@l1416 */
    /* TODO(ground-truth): reconstruct from librftest/rf_test.rdis
     * function <PsramQIORead> (51 insns) + DWARF line rows for rf_test.c:1412.
     * Ordered callee relocs: esp_dport_access_reg_read.
     */
}

/* RF_init_sel rf_test.c:465 @ rf_test.o size 724B [dwarf-sig]
 * Calls: memset, read_flash_init_para, esp_crc8, phy_printf, register_chipv7_phy_init_param, rf_init, bb_init, chip_v7_set_chan_offset | Data refs: .rodata.str1.4, bb_init, chip7_sleep_params, chip_v7_set_chan_offset, esp_crc8, init_param_default, memset, phy_freq_offset, phy_printf, read_flash_init_para, register_chipv7_phy_init_param, rf_init, rfpll_offset_delta, tx_rf_ana_gain, tx_rf_ana_gain_init | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void RF_init_sel(bool init_bin_sel, u32 flash_addr)
{
    (void)init_bin_sel;
    (void)flash_addr;
    /* DWARF locals: s8[] init_params_define@l468, S16 phy_freq_offset@l469, sint16 rfpll_offset_delta@l470, s8 crc8_init@l471, u8 err_code@l472, u8 i@l472 */
    /* TODO(ground-truth): reconstruct from librftest/rf_test.rdis
     * function <RF_init_sel> (277 insns) + DWARF line rows for rf_test.c:465.
     * Ordered callee relocs: memset, read_flash_init_para, esp_crc8, phy_printf, register_chipv7_phy_init_param, rf_init, bb_init, chip_v7_set_chan_offset.
     */
}

/* SPIPsramCLK rf_test.c:1317 @ rf_test.o size 50B [dwarf-sig-decl]
 * Calls: PsramEnableVspiClk, spi_clk_config, PsramDisableVspiClk | Data refs: PsramDisableVspiClk, PsramEnableVspiClk, spi_clk_config | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void SPIPsramCLK(uint8_t div)
{
    (void)div;
    /* TODO(ground-truth): reconstruct from librftest/rf_test.rdis
     * function <SPIPsramCLK> (19 insns) + DWARF line rows for rf_test.c:1317.
     * Ordered callee relocs: PsramEnableVspiClk, spi_clk_config, PsramDisableVspiClk.
     */
}

/* SPIPsramEnable rf_test.c:1334 @ rf_test.o size 364B [dwarf-sig]
 * Calls: esp_dport_access_reg_read, SPIPsramCLK, gpio_matrix_out, gpio_matrix_in, gpio_pad_select_gpio | Data refs: SPIPsramCLK, esp_dport_access_reg_read, gpio_matrix_in, gpio_matrix_out, gpio_pad_select_gpio | MMIO: 0x3ff4201c
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
int SPIPsramEnable(uint8_t PSRAM_CS_IO, uint8_t PSRAM_CLK_IO, uint8_t div)
{
    (void)PSRAM_CS_IO;
    (void)PSRAM_CLK_IO;
    (void)div;
    /* TODO(ground-truth): reconstruct from librftest/rf_test.rdis
     * function <SPIPsramEnable> (142 insns) + DWARF line rows for rf_test.c:1334.
     * Ordered callee relocs: esp_dport_access_reg_read, SPIPsramCLK, gpio_matrix_out, gpio_matrix_in, gpio_pad_select_gpio.
     */
}

/* SPIPsramEnterQIO rf_test.c:1285 @ rf_test.o size 274B [dwarf-sig]
 * Calls: esp_dport_access_reg_read | Data refs: esp_dport_access_reg_read | MMIO: 0x3ff42000, 0x3ff42004, 0x3ff4201c, 0x3ff42020, 0x3ff42024, 0x3ff42034
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void SPIPsramEnterQIO(uint8_t div)
{
    (void)div;
    /* DWARF locals: uint32_t cmdBitLen@l1289 */
    /* TODO(ground-truth): reconstruct from librftest/rf_test.rdis
     * function <SPIPsramEnterQIO> (99 insns) + DWARF line rows for rf_test.c:1285.
     * Ordered callee relocs: esp_dport_access_reg_read.
     */
}

/* SPIPsramExitQIO rf_test.c:1214 @ rf_test.o size 206B [dwarf-sig]
 * Calls: esp_dport_access_reg_read | Data refs: esp_dport_access_reg_read | MMIO: 0x3ff42000, 0x3ff4201c, 0x3ff42020, 0x3ff42028, 0x3ff42034, 0x3ff42080
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void SPIPsramExitQIO(uint8_t div)
{
    (void)div;
    /* DWARF locals: uint32_t txData@l1218, uint32_t txDataBitLen@l1219 */
    /* TODO(ground-truth): reconstruct from librftest/rf_test.rdis
     * function <SPIPsramExitQIO> (78 insns) + DWARF line rows for rf_test.c:1214.
     * Ordered callee relocs: esp_dport_access_reg_read.
     */
}

/* SPIPsramInitCheck rf_test.c:1374 @ rf_test.o size 54B [dwarf-sig]
 * Calls: SPIPsramEnable, SPIPsramReadID | Data refs: SPIPsramEnable, SPIPsramReadID | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
uint32_t SPIPsramInitCheck(uint8_t PSRAM_CS_IO, uint8_t PSRAM_CLK_IO, uint8_t div)
{
    (void)PSRAM_CS_IO;
    (void)PSRAM_CLK_IO;
    (void)div;
    /* DWARF locals: uint32_t id@l1376 */
    /* TODO(ground-truth): reconstruct from librftest/rf_test.rdis
     * function <SPIPsramInitCheck> (20 insns) + DWARF line rows for rf_test.c:1374.
     * Ordered callee relocs: SPIPsramEnable, SPIPsramReadID.
     */
}

/* SPIPsramReadID rf_test.c:1242 @ rf_test.o size 366B [dwarf-sig]
 * Calls: SPIPsramExitQIO, esp_dport_access_reg_read | Data refs: SPIPsramExitQIO, esp_dport_access_reg_read | MMIO: 0x3ff42000, 0x3ff42004, 0x3ff4201c, 0x3ff42020, 0x3ff42024, 0x3ff4202c, 0x3ff42034, 0x3ff42080
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
uint32_t SPIPsramReadID(uint8_t div)
{
    (void)div;
    /* DWARF locals: uint32_t addr@l1247, uint32_t dummy_bits@l1248, uint32_t cmdBitLen@l1249 */
    /* TODO(ground-truth): reconstruct from librftest/rf_test.rdis
     * function <SPIPsramReadID> (133 insns) + DWARF line rows for rf_test.c:1242.
     * Ordered callee relocs: SPIPsramExitQIO, esp_dport_access_reg_read.
     */
}

/* SPI_SET_QE rf_test.c:1020 @ rf_test.o size 11B [dwarf-sig]
 * Calls: SPI_get_id | Data refs: SPI_get_id | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void SPI_SET_QE(void)
{
    /* DWARF locals: u32 flash_id@l1022 */
    /* TODO(ground-truth): reconstruct from librftest/rf_test.rdis
     * function <SPI_SET_QE> (4 insns) + DWARF line rows for rf_test.c:1020.
     * Ordered callee relocs: SPI_get_id.
     */
}

/* SPI_get_id rf_test.c:1025 @ rf_test.o size 60B [dwarf-sig]
 * Calls: esp_dport_access_reg_read | Data refs: esp_dport_access_reg_read | MMIO: 0x3ff42000, 0x3ff42080
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
uint32 SPI_get_id(void)
{
    /* DWARF locals: uint32 rdid@l1027 */
    /* TODO(ground-truth): reconstruct from librftest/rf_test.rdis
     * function <SPI_get_id> (23 insns) + DWARF line rows for rf_test.c:1025.
     * Ordered callee relocs: esp_dport_access_reg_read.
     */
}

/* SPI_page_program_local rf_test.c:1114 @ rf_test.o size 227B [dwarf-sig]
 * Calls: esp_dport_access_reg_read | Data refs: esp_dport_access_reg_read | MMIO: 0x3ff42000, 0x3ff42004, 0x3ff4201c, 0x3ff42028, 0x3ff42080, 0x3ff42084, 0x3ff42088, 0x3ff4208c, 0x3ff42090, 0x3ff42094, 0x3ff42098, 0x3ff4209c
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void SPI_page_program_local(uint32 spi_addr, sint32 length)
{
    (void)spi_addr;
    (void)length;
    /* DWARF locals: uint32 len@l1116, uint8 i@l1117 */
    /* TODO(ground-truth): reconstruct from librftest/rf_test.rdis
     * function <SPI_page_program_local> (94 insns) + DWARF line rows for rf_test.c:1114.
     * Ordered callee relocs: esp_dport_access_reg_read.
     */
}

/* SPI_read_local rf_test.c:1096 @ rf_test.o size 126B [dwarf-sig]
 * Calls: esp_dport_access_reg_read, phy_printf | Data refs: .rodata.str1.4, esp_dport_access_reg_read, phy_printf | MMIO: 0x3ff42000, 0x3ff42004, 0x3ff42080
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void SPI_read_local(uint32 spi_addr, sint32 length)
{
    (void)spi_addr;
    (void)length;
    /* DWARF locals: uint32 len@l1098, uint32 idx@l1099, uint32 freqbits@l1100 */
    /* TODO(ground-truth): reconstruct from librftest/rf_test.rdis
     * function <SPI_read_local> (50 insns) + DWARF line rows for rf_test.c:1096.
     * Ordered callee relocs: esp_dport_access_reg_read, phy_printf.
     */
}

/* bt_tx_tone rf_test.c:450 @ rf_test.o size 18B [dwarf-sig]
 * Calls: fcc_bt_force_tx_tone | Data refs: fcc_bt_force_tx_tone | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void bt_tx_tone(u32 start, u32 bt_chan, u32 backoff)
{
    (void)start;
    (void)bt_chan;
    (void)backoff;
    /* TODO(ground-truth): reconstruct from librftest/rf_test.rdis
     * function <bt_tx_tone> (7 insns) + DWARF line rows for rf_test.c:450.
     * Ordered callee relocs: fcc_bt_force_tx_tone.
     */
}

/* cbw40m_en rf_test.c:71 @ rf_test.o size 28B [dwarf-sig]
 * Calls: phy_printf | Data refs: .rodata.str1.4, phy_printf, tx_cbw40m_en | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void cbw40m_en(bool en)
{
    (void)en;
    /* TODO(ground-truth): reconstruct from librftest/rf_test.rdis
     * function <cbw40m_en> (10 insns) + DWARF line rows for rf_test.c:71.
     * Ordered callee relocs: phy_printf.
     */
}

/* esp_ble_rx_func rf_test.c:460 @ rf_test.o size 15B [dwarf-sig]
 * Calls: rw_le_rx_per_func | Data refs: rw_le_rx_per_func | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void esp_ble_rx_func(u32 chan, u32 syncw, u32 rate)
{
    (void)chan;
    (void)syncw;
    (void)rate;
    /* TODO(ground-truth): reconstruct from librftest/rf_test.rdis
     * function <esp_ble_rx_func> (6 insns) + DWARF line rows for rf_test.c:460.
     * Ordered callee relocs: rw_le_rx_per_func.
     */
}

/* esp_ble_tx_func rf_test.c:455 @ rf_test.o size 23B [dwarf-sig]
 * Calls: fcc_le_tx_syncw_func | Data refs: fcc_le_tx_syncw_func | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void esp_ble_tx_func(u32 txpwr, u32 chan, u32 len, u32 data_type, u32 syncw, u32 rate, u32 tx_num_in)
{
    (void)txpwr;
    (void)chan;
    (void)len;
    (void)data_type;
    (void)syncw;
    (void)rate;
    (void)tx_num_in;
    /* TODO(ground-truth): reconstruct from librftest/rf_test.rdis
     * function <esp_ble_tx_func> (10 insns) + DWARF line rows for rf_test.c:455.
     * Ordered callee relocs: fcc_le_tx_syncw_func.
     */
}

/* esp_chg_freqoff rf_test.c:517 @ rf_test.o size 311B [dwarf-sig]
 * Calls: read_flash_init_para, esp_crc8, register_chipv7_phy_init_param, chip_v7_set_chan_offset, write_flash_init_para, phy_printf | Data refs: .rodata.str1.4, chip_v7_set_chan_offset, esp_crc8, init_param_default, phy_printf, read_flash_init_para, register_chipv7_phy_init_param, write_flash_init_para | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void esp_chg_freqoff(s8 ppm, u32 init_params_addr)
{
    (void)ppm;
    (void)init_params_addr;
    /* DWARF locals: s16 freq_offst@l519, s8[] param_default@l520, s8[] init_data_all@l520, u8 i@l521, bool flag@l522, s8 crc8_init@l530 */
    /* TODO(ground-truth): reconstruct from librftest/rf_test.rdis
     * function <esp_chg_freqoff> (113 insns) + DWARF line rows for rf_test.c:517.
     * Ordered callee relocs: read_flash_init_para, esp_crc8, register_chipv7_phy_init_param, chip_v7_set_chan_offset, write_flash_init_para, phy_printf.
     */
}

/* esp_chk_mac rf_test.c:779 @ rf_test.o size 103B [dwarf-sig]
 * Calls: check_usermac_from_efuse, phy_printf | Data refs: .rodata.str1.4, check_usermac_from_efuse, phy_printf | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void esp_chk_mac(void)
{
    /* DWARF locals: u8[] macaddr@l781, u8 chk_result@l782 */
    /* TODO(ground-truth): reconstruct from librftest/rf_test.rdis
     * function <esp_chk_mac> (36 insns) + DWARF line rows for rf_test.c:779.
     * Ordered callee relocs: check_usermac_from_efuse, phy_printf.
     */
}

/* esp_en_reboot rf_test.c:61 @ rf_test.o size 118B [dwarf-sig]
 * Calls: esp_dport_access_reg_read | Data refs: esp_dport_access_reg_read | MMIO: 0x3ff4808c, 0x3ff48090, 0x3ff48094, 0x3ff48098, 0x3ff4809c, 0x40000000
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void esp_en_reboot(void)
{
    /* TODO(ground-truth): reconstruct from librftest/rf_test.rdis
     * function <esp_en_reboot> (44 insns) + DWARF line rows for rf_test.c:61.
     * Ordered callee relocs: esp_dport_access_reg_read.
     */
}

/* esp_get_target_txp rf_test.c:675 @ rf_test.o size 139B [dwarf-sig]
 * Calls: ets_efuse_get_spiconfig, spi_flash_attach, read_flash_init_para, esp_crc8, phy_printf | Data refs: .rodata.str1.4, esp_crc8, ets_efuse_get_spiconfig, phy_printf, read_flash_init_para, spi_flash_attach | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void esp_get_target_txp(uint32 * para_array)
{
    (void)para_array;
    /* DWARF locals: u32 init_params_addr@l677, s8[] param_default@l678, uint32_t spiconfig0@l680, s8 crc8_init@l684 */
    /* TODO(ground-truth): reconstruct from librftest/rf_test.rdis
     * function <esp_get_target_txp> (47 insns) + DWARF line rows for rf_test.c:675.
     * Ordered callee relocs: ets_efuse_get_spiconfig, spi_flash_attach, read_flash_init_para, esp_crc8, phy_printf.
     */
}

/* esp_origin_mac rf_test.c:761 @ rf_test.o size 62B [dwarf-sig]
 * Calls: esp_dport_access_reg_read, phy_printf | Data refs: .rodata.str1.4, esp_dport_access_reg_read, phy_printf | MMIO: 0x3ff5a004, 0x3ff5a008
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void esp_origin_mac(void)
{
    /* DWARF locals: u32 mac_l@l763, u32 mac_h@l763, u8[] macaddr@l764 */
    /* TODO(ground-truth): reconstruct from librftest/rf_test.rdis
     * function <esp_origin_mac> (21 insns) + DWARF line rows for rf_test.c:761.
     * Ordered callee relocs: esp_dport_access_reg_read, phy_printf.
     */
}

/* esp_rx_func rf_test.c:321 @ rf_test.o size 154B [dwarf-sig]
 * Calls: set_macrxfilter, setmacaddr, rx_gain_level, RFChannelSel, phy_printf, WifiRxStart | Data refs: .rodata.str1.4, RFChannelSel, WifiRxStart, g_phyFuns, mac_filter_en, phy_printf, rx_gain_level, set_macrxfilter, setmacaddr, tx_cbw40m_en | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void esp_rx_func(uint32 chan, uint32 rate)
{
    (void)chan;
    (void)rate;
    /* DWARF locals: uint32[] mac_addr@l323 */
    /* TODO(ground-truth): reconstruct from librftest/rf_test.rdis
     * function <esp_rx_func> (59 insns) + DWARF line rows for rf_test.c:321.
     * Ordered callee relocs: set_macrxfilter, setmacaddr, rx_gain_level, RFChannelSel, phy_printf, WifiRxStart.
     */
}

/* esp_set_mac rf_test.c:794 @ rf_test.o size 79B [dwarf-sig]
 * Calls: write_usermac_to_efuse, phy_printf | Data refs: .rodata.str1.4, phy_printf, write_usermac_to_efuse | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void esp_set_mac(u32 mac_upper, u32 mac_lower)
{
    (void)mac_upper;
    (void)mac_lower;
    /* DWARF locals: u8 write_result@l797 */
    /* TODO(ground-truth): reconstruct from librftest/rf_test.rdis
     * function <esp_set_mac> (27 insns) + DWARF line rows for rf_test.c:794.
     * Ordered callee relocs: write_usermac_to_efuse, phy_printf.
     */
}

/* esp_set_target_txp rf_test.c:569 @ rf_test.o size 855B [dwarf-sig]
 * Calls: memset, ets_efuse_get_spiconfig, spi_flash_attach, read_flash_init_para, esp_crc8, write_flash_init_para, phy_printf, register_chipv7_phy_init_param, rf_init, bb_init, chip_v7_set_chan_offset | Data refs: .rodata.str1.4, bb_init, chip7_sleep_params, chip_v7_set_chan_offset, esp_crc8, ets_efuse_get_spiconfig, memset, phy_printf, read_flash_init_para, register_chipv7_phy_init_param, rf_init, spi_flash_attach, write_flash_init_para | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void esp_set_target_txp(uint32 * para_array)
{
    (void)para_array;
    /* DWARF locals: u32 init_params_addr@l571, s8[] get_param_default@l572, s8[] param_default@l572, s8[] init_data_all@l572, s8[] init_params_define@l573, u8 i@l574, u8 result@l574, bool flag@l575, bool init_bin_sel@l577 */
    /* TODO(ground-truth): reconstruct from librftest/rf_test.rdis
     * function <esp_set_target_txp> (314 insns) + DWARF line rows for rf_test.c:569.
     * Ordered callee relocs: memset, ets_efuse_get_spiconfig, spi_flash_attach, read_flash_init_para, esp_crc8, write_flash_init_para, phy_printf, register_chipv7_phy_init_param, rf_init, bb_init, chip_v7_set_chan_offset.
     */
}

/* esp_tx_func rf_test.c:270 @ rf_test.o size 32B [dwarf-sig]
 * Calls: wifitxout_func, esp_tx_func_org | Data refs: esp_tx_func_org, fcc_mode_sel, wifitxout_func | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void esp_tx_func(int * para_array, int para_num)
{
    (void)para_array;
    (void)para_num;
    /* TODO(ground-truth): reconstruct from librftest/rf_test.rdis
     * function <esp_tx_func> (12 insns) + DWARF line rows for rf_test.c:270.
     * Ordered callee relocs: wifitxout_func, esp_tx_func_org.
     */
}

/* esp_tx_func_5p rf_test.c:278 @ rf_test.o size 42B [dwarf-sig]
 * Calls: wifitxout_func, esp_tx_func_org | Data refs: esp_tx_func_org, fcc_mode_sel, wifitxout_func | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void esp_tx_func_5p(u32 chan, u32 rate, u32 backoff, u32 pocket_len, u32 delay_time)
{
    (void)chan;
    (void)rate;
    (void)backoff;
    (void)pocket_len;
    (void)delay_time;
    /* DWARF locals: u32[] para_array@l280 */
    /* TODO(ground-truth): reconstruct from librftest/rf_test.rdis
     * function <esp_tx_func_5p> (17 insns) + DWARF line rows for rf_test.c:278.
     * Ordered callee relocs: wifitxout_func, esp_tx_func_org.
     */
}

/* esp_tx_func_duty rf_test.c:211 @ rf_test.o size 263B [dwarf-sig]
 * Calls: change_data_rate, RFChannelSel, target_power_backoff, phy_printf, FillTxPacket, WifiTxStart, esp_dport_access_reg_read | Data refs: .rodata.str1.4, FillTxPacket, RFChannelSel, WifiTxStart, change_data_rate, esp_dport_access_reg_read, phy_printf, phy_tx_pwr_correct_en, phy_tx_pwr_track_en, short_gi_enable, target_power_backoff, tx_cbw40m_en | MMIO: 0x60033c68
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void esp_tx_func_duty(u32 chan, u32 rate, u32 backoff, u8 duty)
{
    (void)chan;
    (void)rate;
    (void)backoff;
    (void)duty;
    /* DWARF locals: u32 short_gi@l214, u32 rate_bps@l215, u32 len_ext@l215, u32 pocket_time@l215, u32 pocket_delay@l215, u32 pocket_length@l215, u32 len_byte@l215 */
    /* TODO(ground-truth): reconstruct from librftest/rf_test.rdis
     * function <esp_tx_func_duty> (101 insns) + DWARF line rows for rf_test.c:211.
     * Ordered callee relocs: change_data_rate, RFChannelSel, target_power_backoff, phy_printf, FillTxPacket, WifiTxStart, esp_dport_access_reg_read.
     */
}

/* esp_tx_func_notxon rf_test.c:190 @ rf_test.o size 171B [dwarf-sig]
 * Calls: RFChannelSel, target_power_backoff, phy_printf, FillTxPacket, WifiTxStart, esp_dport_access_reg_read | Data refs: .rodata.str1.4, FillTxPacket, RFChannelSel, WifiTxStart, esp_dport_access_reg_read, phy_printf, short_gi_enable, target_power_backoff, tx_cbw40m_en | MMIO: 0x60033c68
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void esp_tx_func_notxon(u32 chan, u32 rate, u32 backoff, u32 pocket_len, u32 delay_time)
{
    (void)chan;
    (void)rate;
    (void)backoff;
    (void)pocket_len;
    (void)delay_time;
    /* DWARF locals: u32 pocket_length@l193, u32 short_gi@l194, u32 rate_bps@l195, u32 len_ext@l195, u32 pocket_time@l195, u32 pocket_delay@l195 */
    /* TODO(ground-truth): reconstruct from librftest/rf_test.rdis
     * function <esp_tx_func_notxon> (67 insns) + DWARF line rows for rf_test.c:190.
     * Ordered callee relocs: RFChannelSel, target_power_backoff, phy_printf, FillTxPacket, WifiTxStart, esp_dport_access_reg_read.
     */
}

/* esp_tx_func_org rf_test.c:143 @ rf_test.o size 304B [dwarf-sig]
 * Calls: change_data_rate, RFChannelSel, target_power_backoff, phy_printf, FillTxPacket, WifiTxStart, esp_dport_access_reg_read | Data refs: .rodata.str1.4, FillTxPacket, RFChannelSel, WifiTxStart, change_data_rate, esp_dport_access_reg_read, phy_printf, short_gi_enable, target_power_backoff, tx_cbw40m_en | MMIO: 0x60033c68
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void esp_tx_func_org(uint32 * para_array, uint32 para_num)
{
    (void)para_array;
    (void)para_num;
    /* DWARF locals: u32 chan@l145, u32 rate@l146, s16 backoff@l147, u32 pocket_length@l148, u32 short_gi@l149, u32 rate_bps@l150, u32 len_ext@l150, u32 pocket_time@l150, u32 pocket_delay@l150, uint32 packet_num@l151, uint32[] mac_addr@l157, uint32 ap_mac_5@l158, uint32 ap_mac_4@l158, uint32 ap_mac_3@l158, uint32 ap_mac_2@l158, uint32 ap_mac_1@l158 */
    /* TODO(ground-truth): reconstruct from librftest/rf_test.rdis
     * function <esp_tx_func_org> (122 insns) + DWARF line rows for rf_test.c:143.
     * Ordered callee relocs: change_data_rate, RFChannelSel, target_power_backoff, phy_printf, FillTxPacket, WifiTxStart, esp_dport_access_reg_read.
     */
}

/* fcc_bt_tx_func rf_test.c:343 @ rf_test.o size 198B [dwarf-sig]
 * Calls: set_chan_freq_sw_start, phy_dis_hw_set_freq, bt_3200_opt, phy_en_hw_set_freq, phy_printf, fcc_tx | Data refs: .rodata.str1.4, bt_3200_opt, chip7_phy_init_ctrl, fcc_mode_sel, fcc_tx, force_hw_set_freq_flag, phy_dis_hw_set_freq, phy_en_hw_set_freq, phy_printf, set_chan_freq_sw_start | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void fcc_bt_tx_func(u32 txpwr, u32 hoppe, u32 chan, u32 rate, u32 DH_type, u32 data_type)
{
    (void)txpwr;
    (void)hoppe;
    (void)chan;
    (void)rate;
    (void)DH_type;
    (void)data_type;
    /* DWARF locals: sint16 freq_offset@l345, uint8 bt_chan_freq@l346 */
    /* TODO(ground-truth): reconstruct from librftest/rf_test.rdis
     * function <fcc_bt_tx_func> (76 insns) + DWARF line rows for rf_test.c:343.
     * Ordered callee relocs: set_chan_freq_sw_start, phy_dis_hw_set_freq, bt_3200_opt, phy_en_hw_set_freq, phy_printf, fcc_tx.
     */
}

/* fcc_le_tx_func rf_test.c:362 @ rf_test.o size 127B [dwarf-sig]
 * Calls: set_chan_freq_sw_start, phy_dis_hw_set_freq, bt_3200_opt, phy_printf, fcc_le_tx, phy_en_hw_set_freq | Data refs: .rodata.str1.4, bt_3200_opt, chip7_phy_init_ctrl, fcc_le_tx, fcc_mode_sel, force_hw_set_freq_flag, phy_dis_hw_set_freq, phy_en_hw_set_freq, phy_printf, set_chan_freq_sw_start | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void fcc_le_tx_func(u32 txpwr, u32 chan, u32 len, u32 data_type)
{
    (void)txpwr;
    (void)chan;
    (void)len;
    (void)data_type;
    /* DWARF locals: sint16 freq_offset@l364, uint8 chan_freq@l365 */
    /* TODO(ground-truth): reconstruct from librftest/rf_test.rdis
     * function <fcc_le_tx_func> (46 insns) + DWARF line rows for rf_test.c:362.
     * Ordered callee relocs: set_chan_freq_sw_start, phy_dis_hw_set_freq, bt_3200_opt, phy_printf, fcc_le_tx, phy_en_hw_set_freq.
     */
}

/* fcc_le_tx_syncw_func rf_test.c:382 @ rf_test.o size 136B [dwarf-sig-decl]
 * Calls: set_chan_freq_sw_start, phy_dis_hw_set_freq, bt_3200_opt, phy_printf, fcc_le_tx_syncw, phy_en_hw_set_freq | Data refs: .rodata.str1.4, bt_3200_opt, chip7_phy_init_ctrl, fcc_le_tx_syncw, fcc_mode_sel, force_hw_set_freq_flag, phy_dis_hw_set_freq, phy_en_hw_set_freq, phy_printf, set_chan_freq_sw_start | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void fcc_le_tx_syncw_func(u32 txpwr, u32 chan, u32 len, u32 data_type, u32 syncw, u32 tx_num_in)
{
    (void)txpwr;
    (void)chan;
    (void)len;
    (void)data_type;
    (void)syncw;
    (void)tx_num_in;
    /* DWARF locals: sint16 freq_offset@l384, uint8 chan_freq@l385 */
    /* TODO(ground-truth): reconstruct from librftest/rf_test.rdis
     * function <fcc_le_tx_syncw_func> (51 insns) + DWARF line rows for rf_test.c:382.
     * Ordered callee relocs: set_chan_freq_sw_start, phy_dis_hw_set_freq, bt_3200_opt, phy_printf, fcc_le_tx_syncw, phy_en_hw_set_freq.
     */
}

/* flash_test_init rf_test.c:1134 @ rf_test.o size 96B [dwarf-sig]
 * Calls: SPI_get_id, phy_printf, spi_test_init | Data refs: .rodata.str1.4, SPI_get_id, flash_test_enable, g_rom_spiflash_dummy_len_plus, phy_printf, spi_test_init | MMIO: 0x3ff42018
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void flash_test_init(uint32 clk_div, uint32 drv, u32 flash_mode)
{
    (void)clk_div;
    (void)drv;
    (void)flash_mode;
    /* DWARF locals: uint8 dummy_len_plus@l1138, u32 flash_id@l1141 */
    /* TODO(ground-truth): reconstruct from librftest/rf_test.rdis
     * function <flash_test_init> (35 insns) + DWARF line rows for rf_test.c:1134.
     * Ordered callee relocs: SPI_get_id, phy_printf, spi_test_init.
     */
}

/* flash_test_run rf_test.c:1153 @ rf_test.o size 91B [dwarf-sig]
 * Calls: SPI_page_program_local, SPI_read_local, PsramQIORead, gpio_test_run, phy_printf | Data refs: .rodata.str1.4, PsramQIORead, SPI_page_program_local, SPI_read_local, flash_test_enable, gpio_test_enable, gpio_test_run, phy_printf, psram_test_enable, uart_test_enable | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void flash_test_run(u32 length)
{
    (void)length;
    /* TODO(ground-truth): reconstruct from librftest/rf_test.rdis
     * function <flash_test_run> (32 insns) + DWARF line rows for rf_test.c:1153.
     * Ordered callee relocs: SPI_page_program_local, SPI_read_local, PsramQIORead, gpio_test_run, phy_printf.
     */
}

/* gpio_set_flash_drv rf_test.c:1036 @ rf_test.o size 596B [dwarf-sig]
 * Calls: ets_efuse_get_spiconfig, esp_dport_access_reg_read, spi_flash_attach, phy_printf, gpio_pad_set_drv | Data refs: .rodata.str1.4, esp_dport_access_reg_read, ets_efuse_get_spiconfig, gpio_pad_set_drv, phy_printf, spi_flash_attach | MMIO: 0x3ff42000, 0x3ff42004, 0x3ff42080, 0x3ff49030, 0x3ff49034, 0x3ff49038, 0x3ff4903c, 0x3ff49040, 0x3ff49048, 0x3ff49054, 0x3ff49058, 0x3ff4905c, 0x3ff49060, 0x3ff49064, 0x3ff49068
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void gpio_set_flash_drv(u8 clk_drv, u8 cmd_drv, u8 data0_drv, u8 data1_drv, u8 data2_drv, u8 data3_drv)
{
    (void)clk_drv;
    (void)cmd_drv;
    (void)data0_drv;
    (void)data1_drv;
    (void)data2_drv;
    (void)data3_drv;
    /* DWARF locals: uint32_t spiconfig0@l1038, uint8[] pad_drv@l1039, uint32_t spiconfig1@l1041 */
    /* TODO(ground-truth): reconstruct from librftest/rf_test.rdis
     * function <gpio_set_flash_drv> (227 insns) + DWARF line rows for rf_test.c:1036.
     * Ordered callee relocs: ets_efuse_get_spiconfig, esp_dport_access_reg_read, spi_flash_attach, phy_printf, gpio_pad_set_drv.
     */
}

/* gpio_set_psram_drv rf_test.c:1200 @ rf_test.o size 79B [dwarf-sig]
 * Calls: gpio_pad_set_drv | Data refs: gpio_pad_set_drv | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void gpio_set_psram_drv(uint32_t spiconfig0, uint8_t spiconfig1, uint8_t drv)
{
    (void)spiconfig0;
    (void)spiconfig1;
    (void)drv;
    /* TODO(ground-truth): reconstruct from librftest/rf_test.rdis
     * function <gpio_set_psram_drv> (28 insns) + DWARF line rows for rf_test.c:1200.
     * Ordered callee relocs: gpio_pad_set_drv.
     */
}

/* gpio_test_init rf_test.c:1169 @ rf_test.o size 43B [dwarf-sig]
 * Calls: test_pad_mode_sel | Data refs: gpio_test_en, gpio_test_enable, test_pad_mode_sel | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void gpio_test_init(u32 gpio_en)
{
    (void)gpio_en;
    /* TODO(ground-truth): reconstruct from librftest/rf_test.rdis
     * function <gpio_test_init> (18 insns) + DWARF line rows for rf_test.c:1169.
     * Ordered callee relocs: test_pad_mode_sel.
     */
}

/* gpio_test_run rf_test.c:1178 @ rf_test.o size 70B [dwarf-sig]
 * Calls: gpio_output_set, ets_delay_us | Data refs: ets_delay_us, gpio_output_set, gpio_test_enable | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void gpio_test_run(void)
{
    /* DWARF locals: u8 i@l1180, u8 j@l1180, bool level@l1181 */
    /* TODO(ground-truth): reconstruct from librftest/rf_test.rdis
     * function <gpio_test_run> (28 insns) + DWARF line rows for rf_test.c:1178.
     * Ordered callee relocs: gpio_output_set, ets_delay_us.
     */
}

/* pvt_test_func rf_test.c:816 @ rf_test.o size 64B [dwarf-sig]
 * Calls: pvt_pwr_ctrl, ets_delay_us, pvt_test, phy_printf | Data refs: .rodata.str1.4, ets_delay_us, phy_printf, pvt_pwr_ctrl, pvt_test | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void pvt_test_func(void)
{
    /* TODO(ground-truth): reconstruct from librftest/rf_test.rdis
     * function <pvt_test_func> (23 insns) + DWARF line rows for rf_test.c:816.
     * Ordered callee relocs: pvt_pwr_ctrl, ets_delay_us, pvt_test, phy_printf.
     */
}

/* remove_head_newline rf_test.c:831 @ rf_test.o size 23B [dwarf-sig]
 * Calls: (none) | Data refs: (none) | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
bool remove_head_newline(char * strln, char * * pnext)
{
    (void)strln;
    (void)pnext;
    /* DWARF locals: char * pchar@l833, int i@l834 */
    /* TODO(ground-truth): reconstruct from librftest/rf_test.rdis
     * function <remove_head_newline> (9 insns) + DWARF line rows for rf_test.c:831.
     */
}

/* rfpll_1p2_test rf_test.c:696 @ rf_test.o size 222B [dwarf-sig]
 * Calls: esp_dport_access_reg_read, phy_printf | Data refs: .rodata, .rodata.str1.4, esp_dport_access_reg_read, g_phyFuns, phy_printf | MMIO: 0x3ff48030
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rfpll_1p2_test(void)
{
    /* DWARF locals: uint8[] reg@l698, uint8 i@l699, uint8 data@l699, uint8 dreg_1p2@l699, uint8 result@l700 */
    /* TODO(ground-truth): reconstruct from librftest/rf_test.rdis
     * function <rfpll_1p2_test> (83 insns) + DWARF line rows for rf_test.c:696.
     * Ordered callee relocs: esp_dport_access_reg_read, phy_printf.
     */
}

/* rfpll_cal_time rf_test.c:1427 @ rf_test.o size 510B [dwarf-sig]
 * Calls: write_wifi_chan_data, esp_dport_access_reg_read, ets_delay_us, phy_printf | Data refs: .rodata.str1.4, esp_dport_access_reg_read, ets_delay_us, g_phyFuns, phy_printf, write_wifi_chan_data | MMIO: 0x3ff4e0c4, 0x60033c00
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rfpll_cal_time(u8 chan_freq, u8 mode)
{
    (void)chan_freq;
    (void)mode;
    /* DWARF locals: uint8[] or_pll_cap@l1429, uint8 i@l1429, uint8 j@l1429, uint8 ir_cap_ext@l1429, u32 t0@l1430, u32 t1@l1430 */
    /* TODO(ground-truth): reconstruct from librftest/rf_test.rdis
     * function <rfpll_cal_time> (191 insns) + DWARF line rows for rf_test.c:1427.
     * Ordered callee relocs: write_wifi_chan_data, esp_dport_access_reg_read, ets_delay_us, phy_printf.
     */
}

/* rftest_init rf_test.c:37 @ rf_test.o size 137B [dwarf-sig]
 * Calls: register_chipv7_phy, coex_bt_high_prio, rf_rw_init, mac_init | Data refs: coex_bt_high_prio, init_param_default, mac_init, re_entry, register_chipv7_phy, rf_rw_init, tx_rf_ana_gain, tx_rf_ana_gain_init | MMIO: 0x3ff000c0, 0x3ff000cc, 0x3ff4808c, 0x3ff5f048
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rftest_init(void)
{
    /* DWARF locals: struct rwip_rf_api api@l40, u8[] rf_cal_data@l49 */
    /* TODO(ground-truth): reconstruct from librftest/rf_test.rdis
     * function <rftest_init> (54 insns) + DWARF line rows for rf_test.c:37.
     * Ordered callee relocs: register_chipv7_phy, coex_bt_high_prio, rf_rw_init, mac_init.
     */
}

/* rw_le_rx_per_func rf_test.c:425 @ rf_test.o size 179B [dwarf-sig]
 * Calls: bt_set_freq_cal, phy_dis_hw_set_freq, bt_3200_opt, get_rfrx_dcap_bt, bt_2480_opt_enter, phy_printf, rw_le_rx_per_syncw, bt_2480_opt_exit, phy_en_hw_set_freq | Data refs: .rodata.str1.4, bt_2480_opt_enter, bt_2480_opt_exit, bt_3200_opt, bt_set_freq_cal, fcc_mode_sel, force_hw_set_freq_flag, g_phyFuns, get_rfrx_dcap_bt, phy_dis_hw_set_freq, phy_en_hw_set_freq, phy_printf, rw_le_rx_per_syncw | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rw_le_rx_per_func(u32 chan, u32 syncw)
{
    (void)chan;
    (void)syncw;
    /* DWARF locals: uint32 chan_in@l427 */
    /* TODO(ground-truth): reconstruct from librftest/rf_test.rdis
     * function <rw_le_rx_per_func> (67 insns) + DWARF line rows for rf_test.c:425.
     * Ordered callee relocs: bt_set_freq_cal, phy_dis_hw_set_freq, bt_3200_opt, get_rfrx_dcap_bt, bt_2480_opt_enter, phy_printf, rw_le_rx_per_syncw, bt_2480_opt_exit, phy_en_hw_set_freq.
     */
}

/* rw_rx_per_func rf_test.c:403 @ rf_test.o size 183B [dwarf-sig]
 * Calls: bt_set_freq_cal, phy_dis_hw_set_freq, bt_3200_opt, get_rfrx_dcap_bt, bt_2480_opt_enter, phy_printf, rw_rx_per_ulap, bt_2480_opt_exit, phy_en_hw_set_freq | Data refs: .rodata.str1.4, bt_2480_opt_enter, bt_2480_opt_exit, bt_3200_opt, bt_set_freq_cal, fcc_mode_sel, force_hw_set_freq_flag, g_phyFuns, get_rfrx_dcap_bt, phy_dis_hw_set_freq, phy_en_hw_set_freq, phy_printf, rw_rx_per_ulap | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void rw_rx_per_func(u32 edr, u32 chan, u32 ulap, u32 ltaddr)
{
    (void)edr;
    (void)chan;
    (void)ulap;
    (void)ltaddr;
    /* TODO(ground-truth): reconstruct from librftest/rf_test.rdis
     * function <rw_rx_per_func> (70 insns) + DWARF line rows for rf_test.c:403.
     * Ordered callee relocs: bt_set_freq_cal, phy_dis_hw_set_freq, bt_3200_opt, get_rfrx_dcap_bt, bt_2480_opt_enter, phy_printf, rw_rx_per_ulap, bt_2480_opt_exit, phy_en_hw_set_freq.
     */
}

/* spi_clk_local rf_test.c:1073 @ rf_test.o size 51B [dwarf-sig-decl]
 * Calls: (none) | Data refs: (none) | MMIO: 0x3ff42018
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void spi_clk_local(uint8 freqdiv)
{
    (void)freqdiv;
    /* DWARF locals: uint32 freqbits@l1075 */
    /* TODO(ground-truth): reconstruct from librftest/rf_test.rdis
     * function <spi_clk_local> (19 insns) + DWARF line rows for rf_test.c:1073.
     */
}

/* spi_qe0 rf_test.c:970 @ rf_test.o size 70B [dwarf-sig]
 * Calls: spi_usr_cmd, spi_flash_wren, WaitFlashIdle | Data refs: WaitFlashIdle, spi_flash_wren, spi_usr_cmd | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
uint32_t spi_qe0(uint32_t spi_no)
{
    (void)spi_no;
    /* DWARF locals: uint32_t sta_0@l971, uint32_t sta@l972 */
    /* TODO(ground-truth): reconstruct from librftest/rf_test.rdis
     * function <spi_qe0> (30 insns) + DWARF line rows for rf_test.c:970.
     * Ordered callee relocs: spi_usr_cmd, spi_flash_wren, WaitFlashIdle.
     */
}

/* spi_qe1 rf_test.c:986 @ rf_test.o size 106B [dwarf-sig]
 * Calls: spi_flash_wren, spi_usr_cmd, WaitFlashIdle | Data refs: WaitFlashIdle, spi_flash_wren, spi_usr_cmd | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
uint32_t spi_qe1(uint32_t spi_no)
{
    (void)spi_no;
    /* DWARF locals: uint32_t sta_0@l987, uint32_t sta_1@l988, uint32_t sta@l989 */
    /* TODO(ground-truth): reconstruct from librftest/rf_test.rdis
     * function <spi_qe1> (43 insns) + DWARF line rows for rf_test.c:986.
     * Ordered callee relocs: spi_flash_wren, spi_usr_cmd, WaitFlashIdle.
     */
}

/* spi_qe2 rf_test.c:1003 @ rf_test.o size 72B [dwarf-sig]
 * Calls: spi_flash_wren, spi_usr_cmd, WaitFlashIdle | Data refs: WaitFlashIdle, spi_flash_wren, spi_usr_cmd | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
uint32_t spi_qe2(uint32_t spi_no)
{
    (void)spi_no;
    /* DWARF locals: uint32_t sta_0@l1004, uint32_t sta@l1005 */
    /* TODO(ground-truth): reconstruct from librftest/rf_test.rdis
     * function <spi_qe2> (30 insns) + DWARF line rows for rf_test.c:1003.
     * Ordered callee relocs: spi_flash_wren, spi_usr_cmd, WaitFlashIdle.
     */
}

/* spi_test_init rf_test.c:1088 @ rf_test.o size 84B [dwarf-sig]
 * Calls: gpio_set_flash_drv, SPIReadModeCnfig | Data refs: SPIReadModeCnfig, gpio_set_flash_drv | MMIO: 0x3ff42018
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void spi_test_init(uint32 flash_mode, uint32 clk_div, uint32 drv)
{
    (void)flash_mode;
    (void)clk_div;
    (void)drv;
    /* TODO(ground-truth): reconstruct from librftest/rf_test.rdis
     * function <spi_test_init> (32 insns) + DWARF line rows for rf_test.c:1088.
     * Ordered callee relocs: gpio_set_flash_drv, SPIReadModeCnfig.
     */
}

/* tx_contin_en rf_test.c:245 @ rf_test.o size 126B [dwarf-sig]
 * Calls: phy_printf, esp_dport_access_reg_read | Data refs: .rodata.str1.4, esp_dport_access_reg_read, fcc_mode_sel, flash_test_enable, phy_printf, psram_test_enable | MMIO: 0x600312e0
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void tx_contin_en(u8 contin_en)
{
    (void)contin_en;
    /* TODO(ground-truth): reconstruct from librftest/rf_test.rdis
     * function <tx_contin_en> (46 insns) + DWARF line rows for rf_test.c:245.
     * Ordered callee relocs: phy_printf, esp_dport_access_reg_read.
     */
}

/* wifiscwout rf_test.c:294 @ rf_test.o size 190B [dwarf-sig]
 * Calls: phy_printf, RFChannelSel, txcal_debuge_mode, esp_dport_access_reg_read | Data refs: .rodata.str1.4, RFChannelSel, esp_dport_access_reg_read, g_phyFuns, para_array, phy_printf, short_log_en, txcal_debuge_mode | MMIO: 0x3ff46004
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void wifiscwout(uint32 en, uint32 chan, uint32 backoff)
{
    (void)en;
    (void)chan;
    (void)backoff;
    /* DWARF locals: int atten_f@l296, int atten@l297 */
    /* TODO(ground-truth): reconstruct from librftest/rf_test.rdis
     * function <wifiscwout> (70 insns) + DWARF line rows for rf_test.c:294.
     * Ordered callee relocs: phy_printf, RFChannelSel, txcal_debuge_mode, esp_dport_access_reg_read.
     */
}

/* wifitxout rf_test.c:261 @ rf_test.o size 32B [dwarf-sig]
 * Calls: wifitxout_func, esp_tx_func_org | Data refs: esp_tx_func_org, fcc_mode_sel, wifitxout_func | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void wifitxout(uint32 * para_array, uint32 para_num)
{
    (void)para_array;
    (void)para_num;
    /* TODO(ground-truth): reconstruct from librftest/rf_test.rdis
     * function <wifitxout> (12 insns) + DWARF line rows for rf_test.c:261.
     * Ordered callee relocs: wifitxout_func, esp_tx_func_org.
     */
}

/* wifitxout_func rf_test.c:77 @ rf_test.o size 422B [dwarf-sig]
 * Calls: change_data_rate, phy_printf, RFChannelSel, tx_cont_cfg, esp_dport_access_reg_read, remove_11b_4p8G_spur, target_power_backoff, FillTxPacket, WifiTxStart | Data refs: .rodata.str1.4, FillTxPacket, RFChannelSel, WifiTxStart, change_data_rate, esp_dport_access_reg_read, fcc_mode_flag, g_phyFuns, phy_printf, phy_tx_pwr_correct_en, phy_tx_pwr_track_en, rc_cal_en, remove_11b_4p8G_spur, short_gi_enable, target_power_backoff, tx_cbw40m_en, tx_cont_cfg | MMIO: 0x3ff5c400, 0x60033c68
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void wifitxout_func(uint32 * para_array, uint32 para_num)
{
    (void)para_array;
    (void)para_num;
    /* DWARF locals: u32 chan@l79, u32 rate@l80, s8 backoff@l81, u32 fcc_length@l82, u32 short_gi@l83, u32 rate_bps@l84, u32 len_ext@l84, u32 pocket_time@l84, u32 pocket_delay@l84, u8 dig_data@l85, bool correct_en@l86, bool track_en@l86 */
    /* TODO(ground-truth): reconstruct from librftest/rf_test.rdis
     * function <wifitxout_func> (165 insns) + DWARF line rows for rf_test.c:77.
     * Ordered callee relocs: change_data_rate, phy_printf, RFChannelSel, tx_cont_cfg, esp_dport_access_reg_read, remove_11b_4p8G_spur, target_power_backoff, FillTxPacket, WifiTxStart.
     */
}

/* ---- static (DWARF-only, no funcdb GLOBAL) ---- */
/* GetStopCmd rf_test.c:891 @ rf_test.o (static) [dwarf-sig]
 * Calls: esp_phy_getstopcmd | MMIO: (none)
 * Fidelity: low - signature only */
static STATUS GetStopCmd(void)
{
    /* TODO */
}

/* esp_phy_getstopcmd rf_test.c:896 @ rf_test.o (static) [dwarf-sig]
 * Calls: cmdstop_callback, phy_printf | MMIO: (none)
 * Fidelity: low - signature only */
static STATUS esp_phy_getstopcmd(void)
{
    /* TODO */
}

/* gpio_input_get rf_test.c:1561 @ rf_test.o (static) [dwarf-sig]
 * Calls: esp_dport_access_reg_read | MMIO: 0x3ff4403c
 * Fidelity: low - signature only */
static uint32 gpio_input_get(void)
{
    /* TODO */
}

/* gpio_input_get_high rf_test.c:1569 @ rf_test.o (static) [dwarf-sig]
 * Calls: esp_dport_access_reg_read | MMIO: 0x3ff44040
 * Fidelity: low - signature only */
static uint32 gpio_input_get_high(void)
{
    /* TODO */
}

/* gpio_output_set rf_test.c:1545 @ rf_test.o (static) [dwarf-sig]
 * Calls: (see disasm) | MMIO: 0x3ff44008, 0x3ff4400c, 0x3ff44024, 0x3ff44028
 * Fidelity: low - signature only */
static void gpio_output_set(uint32 set_mask, uint32 clear_mask, uint32 enable_mask, uint32 disable_mask)
{
    (void)set_mask;
    (void)clear_mask;
    (void)enable_mask;
    (void)disable_mask;
    /* TODO */
}

/* gpio_output_set_high rf_test.c:1553 @ rf_test.o (static) [dwarf-sig]
 * Calls: (see disasm) | MMIO: 0x3ff44014, 0x3ff44018, 0x3ff44030, 0x3ff44034
 * Fidelity: low - signature only */
static void gpio_output_set_high(uint32 set_mask, uint32 clear_mask, uint32 enable_mask, uint32 disable_mask)
{
    (void)set_mask;
    (void)clear_mask;
    (void)enable_mask;
    (void)disable_mask;
    /* TODO */
}

/* Undefined refs (83): ESP_TEST_GPIO, FillTxPacket, PsramDisableVspiClk, PsramEnableVspiClk, RFChannelSel, SPIReadModeCnfig, WaitFlashIdle, WifiRxStart, WifiTxStart, bb_init, bt_2480_opt_enter, bt_2480_opt_exit, bt_3200_opt, bt_set_freq_cal, change_data_rate, check_usermac_from_efuse, chip7_phy_init_ctrl, chip7_sleep_params, chip_v7_set_chan_offset, cmdstop_callback, coex_bt_high_prio, esp_crc8, esp_dport_access_reg_read, ets_delay_us, ets_efuse_get_spiconfig, fcc_bt_force_tx_tone, fcc_le_tx, fcc_le_tx_syncw, fcc_mode_flag, fcc_mode_sel, fcc_tx, force_hw_set_freq_flag, g_phyFuns, g_rom_spiflash_dummy_len_plus, get_rfrx_dcap_bt, gpio_matrix_in, gpio_matrix_out, gpio_pad_select_gpio, gpio_pad_set_drv, init_param_default, mac_filter_en, mac_init, memset, para_array, phy_dis_hw_set_freq, phy_en_hw_set_freq, phy_freq_offset, phy_printf, phy_tx_pwr_correct_en, phy_tx_pwr_track_en, pvt_pwr_ctrl, pvt_test, rc_cal_en, re_entry, read_flash_init_para, register_chipv7_phy, register_chipv7_phy_init_param, remove_11b_4p8G_spur, rf_init, rf_rw_init... */