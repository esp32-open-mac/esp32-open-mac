/* Reconstruction of mod_subtest.o (librftest.a)
 * CU: mod_subtest.c | comp_dir: /home/lxf/gittree/chip7.1_phy/chip_7.1/board_code/app_test/pp/rftest
 * producer: GNU C11 5.2.0 -mlongcalls -mtext-section-literals -mfix-esp32-psram-cache-issue -g -O2 -fno-inline-functions -ffunction-sections -fdata-sections
 * DWARF subprograms: 56 | funcdb functions: 34
 * Disasm: re/esp32-phy/disasm/librftest/mod_subtest.rdis
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

/* CMDSTOP_GPIO mod_subtest.c:611 @ mod_subtest.o size 47B [dwarf-sig]
 * Calls: phy_printf | Data refs: .rodata.str1.4, ini_gpio_val, phy_printf | MMIO: 0x3ff49004
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void CMDSTOP_GPIO(void)
{
    /* DWARF locals: u8 i@l612 */
    /* TODO(ground-truth): reconstruct from librftest/mod_subtest.rdis
     * function <CMDSTOP_GPIO> (19 insns) + DWARF line rows for mod_subtest.c:611.
     * Ordered callee relocs: phy_printf.
     */
}

/* DIG_pwc_mea_ate mod_subtest.c:1729 @ mod_subtest.o size 238B [dwarf-sig]
 * Calls: esp_dport_access_reg_read | Data refs: esp_dport_access_reg_read | MMIO: 0x3ff48078, 0x3ff4807c, 0x3ff480a8, 0x3ff4880c, 0x3ff4882c, 0x3ff48894, 0x3fffffff
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void DIG_pwc_mea_ate(u32 bias, u8 pad)
{
    (void)bias;
    (void)pad;
    /* TODO(ground-truth): reconstruct from librftest/mod_subtest.rdis
     * function <DIG_pwc_mea_ate> (84 insns) + DWARF line rows for mod_subtest.c:1729.
     * Ordered callee relocs: esp_dport_access_reg_read.
     */
}

/* ESP_TEST_GPIO mod_subtest.c:498 @ mod_subtest.o size 534B [dwarf-sig]
 * Calls: phy_printf, uart_wait_idle, ets_delay_us, esp_dport_access_reg_read, test_pad_mode_sel, gpio_output_set, gpio_output_set_high, gpio_input_get, gpio_input_get_high | Data refs: .rodata.str1.4, esp_dport_access_reg_read, ets_delay_us, gpio_input_get, gpio_input_get_high, gpio_output_set, gpio_output_set_high, ini_gpio_val, phy_printf, test_pad_mode_sel, uart_wait_idle | MMIO: 0x3ff49004
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void ESP_TEST_GPIO(u32 * test_gpio, u32 * Input_result)
{
    (void)test_gpio;
    (void)Input_result;
    /* DWARF locals: u8 i@l500, u8 j@l500, u8 get_value@l500, u8 gpio_set@l500, u8 gpio_num@l500, bool Input_flag@l501, u32[] Input_value@l502 */
    /* TODO(ground-truth): reconstruct from librftest/mod_subtest.rdis
     * function <ESP_TEST_GPIO> (202 insns) + DWARF line rows for mod_subtest.c:498.
     * Ordered callee relocs: phy_printf, uart_wait_idle, ets_delay_us, esp_dport_access_reg_read, test_pad_mode_sel, gpio_output_set, gpio_output_set_high, gpio_input_get, gpio_input_get_high.
     */
}

/* ESP_TEST_GPIO_DRV mod_subtest.c:554 @ mod_subtest.o size 546B [dwarf-sig]
 * Calls: phy_printf, uart_wait_idle, ets_delay_us, esp_dport_access_reg_read, test_pad_mode_sel, test_digital_pads_drv, gpio_output_set, gpio_output_set_high, gpio_input_get, gpio_input_get_high | Data refs: .rodata.str1.4, esp_dport_access_reg_read, ets_delay_us, gpio_input_get, gpio_input_get_high, gpio_output_set, gpio_output_set_high, ini_gpio_val, phy_printf, test_digital_pads_drv, test_pad_mode_sel, uart_wait_idle | MMIO: 0x3ff49004
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void ESP_TEST_GPIO_DRV(u32 * test_gpio, u32 * Input_result, u8 drv)
{
    (void)test_gpio;
    (void)Input_result;
    (void)drv;
    /* DWARF locals: u8 i@l556, u8 j@l556, u8 get_value@l556, u8 gpio_set@l556, u8 gpio_num@l556, bool Input_flag@l557, u32[] Input_value@l558 */
    /* TODO(ground-truth): reconstruct from librftest/mod_subtest.rdis
     * function <ESP_TEST_GPIO_DRV> (208 insns) + DWARF line rows for mod_subtest.c:554.
     * Ordered callee relocs: phy_printf, uart_wait_idle, ets_delay_us, esp_dport_access_reg_read, test_pad_mode_sel, test_digital_pads_drv, gpio_output_set, gpio_output_set_high, gpio_input_get, gpio_input_get_high.
     */
}

/* GPIO_cali mod_subtest.c:691 @ mod_subtest.o size 132B [dwarf-sig]
 * Calls: esp_dport_access_reg_read, ets_delay_us | Data refs: esp_dport_access_reg_read, ets_delay_us | MMIO: 0x3ff44128, 0x3ff4412c
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
uint32 GPIO_cali(u32 num)
{
    (void)num;
    /* DWARF locals: uint32 value@l693 */
    /* TODO(ground-truth): reconstruct from librftest/mod_subtest.rdis
     * function <GPIO_cali> (46 insns) + DWARF line rows for mod_subtest.c:691.
     * Ordered callee relocs: esp_dport_access_reg_read, ets_delay_us.
     */
}

/* RTC_pwc_mea_ate mod_subtest.c:1762 @ mod_subtest.o size 233B [dwarf-sig]
 * Calls: esp_dport_access_reg_read | Data refs: esp_dport_access_reg_read | MMIO: 0x3ff48078, 0x3ff4807c, 0x3ff480a8, 0x3ff4880c, 0x3ff4882c, 0x3ff48894, 0x3fffffff
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void RTC_pwc_mea_ate(u32 bias, u8 pad)
{
    (void)bias;
    (void)pad;
    /* TODO(ground-truth): reconstruct from librftest/mod_subtest.rdis
     * function <RTC_pwc_mea_ate> (83 insns) + DWARF line rows for mod_subtest.c:1762.
     * Ordered callee relocs: esp_dport_access_reg_read.
     */
}

/* Vsar2_pwc_mea_ate mod_subtest.c:1701 @ mod_subtest.o size 241B [dwarf-sig]
 * Calls: esp_dport_access_reg_read | Data refs: esp_dport_access_reg_read | MMIO: 0x3ff48078, 0x3ff4807c, 0x3ff480a8, 0x3ff4880c, 0x3ff4882c, 0x3ff48894, 0x3fffffff, 0x40000000
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void Vsar2_pwc_mea_ate(u32 bias, u8 pad)
{
    (void)bias;
    (void)pad;
    /* TODO(ground-truth): reconstruct from librftest/mod_subtest.rdis
     * function <Vsar2_pwc_mea_ate> (85 insns) + DWARF line rows for mod_subtest.c:1701.
     * Ordered callee relocs: esp_dport_access_reg_read.
     */
}

/* check_usermac_from_efuse mod_subtest.c:795 @ mod_subtest.o size 352B [dwarf-sig]
 * Calls: esp_dport_access_reg_read | Data refs: esp_dport_access_reg_read | MMIO: 0x3ff5a078, 0x3ff5a079, 0x3ff5a07a, 0x3ff5a07b, 0x3ff5a07c, 0x3ff5a07d, 0x3ff5a07e, 0x3ff5a08f
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
u8 check_usermac_from_efuse(uint8 * macaddr)
{
    (void)macaddr;
    /* DWARF locals: u8[] temp@l797, u8 chk_result@l797, u8 i@l797, u8 user_mac_flag@l798, u8 user_mac_crc8@l799 */
    /* TODO(ground-truth): reconstruct from librftest/mod_subtest.rdis
     * function <check_usermac_from_efuse> (132 insns) + DWARF line rows for mod_subtest.c:795.
     * Ordered callee relocs: esp_dport_access_reg_read.
     */
}

/* clk8M mod_subtest.c:672 @ mod_subtest.o size 75B [dwarf-sig]
 * Calls: rtc_8m_ena, esp_dport_access_reg_read, ets_delay_us, rtc_slowck_cali | Data refs: esp_dport_access_reg_read, ets_delay_us, rtc_8m_ena, rtc_slowck_cali | MMIO: 0x3ff48070
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
uint32 clk8M(u32 req, u32 delay)
{
    (void)req;
    (void)delay;
    /* DWARF locals: u32 period@l674, u32 freq@l674 */
    /* TODO(ground-truth): reconstruct from librftest/mod_subtest.rdis
     * function <clk8M> (27 insns) + DWARF line rows for mod_subtest.c:672.
     * Ordered callee relocs: rtc_8m_ena, esp_dport_access_reg_read, ets_delay_us, rtc_slowck_cali.
     */
}

/* clr_pwc_mea mod_subtest.c:1791 @ mod_subtest.o size 113B [dwarf-sig]
 * Calls: esp_dport_access_reg_read | Data refs: esp_dport_access_reg_read | MMIO: 0x3ff48078, 0x3ff480a8, 0x3ff4880c, 0x3ff4882c, 0x3fffffff
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void clr_pwc_mea(void)
{
    /* TODO(ground-truth): reconstruct from librftest/mod_subtest.rdis
     * function <clr_pwc_mea> (41 insns) + DWARF line rows for mod_subtest.c:1791.
     * Ordered callee relocs: esp_dport_access_reg_read.
     */
}

/* count_ones mod_subtest.c:954 @ mod_subtest.o size 30B [dwarf-sig-decl]
 * Calls: (none) | Data refs: (none) | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
unsigned char count_ones(unsigned char in)
{
    (void)in;
    /* DWARF locals: unsigned char out@l955 */
    /* TODO(ground-truth): reconstruct from librftest/mod_subtest.rdis
     * function <count_ones> (12 insns) + DWARF line rows for mod_subtest.c:954.
     */
}

/* esp_crc8 mod_subtest.c:775 @ mod_subtest.o size 54B [dwarf-sig-decl]
 * Calls: (none) | Data refs: (none) | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
unsigned char esp_crc8(const unsigned char * p, unsigned int len)
{
    (void)p;
    (void)len;
    /* DWARF locals: unsigned char i@l777, unsigned char crc@l778 */
    /* TODO(ground-truth): reconstruct from librftest/mod_subtest.rdis
     * function <esp_crc8> (20 insns) + DWARF line rows for mod_subtest.c:775.
     */
}

/* make_efuse mod_subtest.c:964 @ mod_subtest.o size 531B [dwarf-sig]
 * Calls: (none) | Data refs: (none) | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void make_efuse(u8 * all_bytes, u8 * efuse_result)
{
    (void)all_bytes;
    (void)efuse_result;
    /* DWARF locals: u8 i@l966, u8 j@l966, u8[] burn_value@l967, u8[] parity@l968, u8[] ones@l969, u32[] efuse_raw@l970 */
    /* TODO(ground-truth): reconstruct from librftest/mod_subtest.rdis
     * function <make_efuse> (201 insns) + DWARF line rows for mod_subtest.c:964.
     */
}

/* pvt mod_subtest.c:622 @ mod_subtest.o size 232B [dwarf-sig]
 * Calls: esp_dport_access_reg_read, ets_delay_us | Data refs: esp_dport_access_reg_read, ets_delay_us | MMIO: 0x3ff48030, 0x3ff4807c, 0x3ff4e0f8
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
uint16 pvt(u16 dig_dbias, bool pvt_res_en, u16 pvt_delay)
{
    (void)dig_dbias;
    (void)pvt_res_en;
    (void)pvt_delay;
    /* DWARF locals: uint16 Count@l624 */
    /* TODO(ground-truth): reconstruct from librftest/mod_subtest.rdis
     * function <pvt> (83 insns) + DWARF line rows for mod_subtest.c:622.
     * Ordered callee relocs: esp_dport_access_reg_read, ets_delay_us.
     */
}

/* pvt_pwr_ctrl mod_subtest.c:663 @ mod_subtest.o size 79B [dwarf-sig]
 * Calls: esp_dport_access_reg_read | Data refs: esp_dport_access_reg_read | MMIO: 0x3ff48030, 0x3ff4807c
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void pvt_pwr_ctrl(u8 pvt_pu_en)
{
    (void)pvt_pu_en;
    /* TODO(ground-truth): reconstruct from librftest/mod_subtest.rdis
     * function <pvt_pwr_ctrl> (29 insns) + DWARF line rows for mod_subtest.c:663.
     * Ordered callee relocs: esp_dport_access_reg_read.
     */
}

/* pvt_test mod_subtest.c:640 @ mod_subtest.o size 241B [dwarf-sig]
 * Calls: esp_dport_access_reg_read, ets_delay_us | Data refs: esp_dport_access_reg_read, ets_delay_us | MMIO: 0x3ff4807c, 0x3ff4e0f8
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
uint16 pvt_test(u16 dig_dbias, bool pvt_res_en, u16 pvt_delay)
{
    (void)dig_dbias;
    (void)pvt_res_en;
    (void)pvt_delay;
    /* DWARF locals: uint16 Count@l642 */
    /* TODO(ground-truth): reconstruct from librftest/mod_subtest.rdis
     * function <pvt_test> (84 insns) + DWARF line rows for mod_subtest.c:640.
     * Ordered callee relocs: esp_dport_access_reg_read, ets_delay_us.
     */
}

/* slow_clk_read_temp mod_subtest.c:733 @ mod_subtest.o size 122B [dwarf-sig]
 * Calls: GPIO_cali, esp_dport_access_reg_read, phy_printf | Data refs: .rodata.str1.4, GPIO_cali, esp_dport_access_reg_read, phy_printf, temp_offset, temp_wr | MMIO: 0x3ff5a014
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
u8 slow_clk_read_temp(void)
{
    /* DWARF locals: u32[] rd_efuse_reg@l735, u32 blk0_rdata5@l735, u32 read_slow_clk@l735, u32 offset_val@l735, s16 read_delta@l736, s16 tmp@l736, u8[] rd_data@l737, u8 temp@l737, u8 i@l737 */
    /* TODO(ground-truth): reconstruct from librftest/mod_subtest.rdis
     * function <slow_clk_read_temp> (44 insns) + DWARF line rows for mod_subtest.c:733.
     * Ordered callee relocs: GPIO_cali, esp_dport_access_reg_read, phy_printf.
     */
}

/* slow_clk_write_efuse mod_subtest.c:707 @ mod_subtest.o size 126B [dwarf-sig]
 * Calls: GPIO_cali, phy_printf, burn_efuse | Data refs: .rodata.str1.4, GPIO_cali, burn_efuse, phy_printf, temp_wr, wr_data, wr_en | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
u8 slow_clk_write_efuse(u8 set_temp)
{
    (void)set_temp;
    /* DWARF locals: u32 offset_val@l709, u32 init_val@l709, u16 write_delta@l710, int result@l711, u8 slope@l712 */
    /* TODO(ground-truth): reconstruct from librftest/mod_subtest.rdis
     * function <slow_clk_write_efuse> (45 insns) + DWARF line rows for mod_subtest.c:707.
     * Ordered callee relocs: GPIO_cali, phy_printf, burn_efuse.
     */
}

/* test_digital_pads_GPIO mod_subtest.c:146 @ mod_subtest.o size 99B [dwarf-sig]
 * Calls: esp_dport_access_reg_read | Data refs: esp_dport_access_reg_read | MMIO: 0x3ff49004, 0x3ff49084, 0x3ff49090
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void test_digital_pads_GPIO(u32 maskl, u32 maskh)
{
    (void)maskl;
    (void)maskh;
    /* DWARF locals: u32 i@l148, u32 mask0@l149 */
    /* TODO(ground-truth): reconstruct from librftest/mod_subtest.rdis
     * function <test_digital_pads_GPIO> (36 insns) + DWARF line rows for mod_subtest.c:146.
     * Ordered callee relocs: esp_dport_access_reg_read.
     */
}

/* test_digital_pads_drv mod_subtest.c:86 @ mod_subtest.o size 100B [dwarf-sig]
 * Calls: esp_dport_access_reg_read | Data refs: esp_dport_access_reg_read | MMIO: 0x3ff49004, 0x3ff49084, 0x3ff49090
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void test_digital_pads_drv(u32 maskl, u32 maskh, u32 value)
{
    (void)maskl;
    (void)maskh;
    (void)value;
    /* DWARF locals: u32 i@l87, u32 mask0@l88 */
    /* TODO(ground-truth): reconstruct from librftest/mod_subtest.rdis
     * function <test_digital_pads_drv> (36 insns) + DWARF line rows for mod_subtest.c:86.
     * Ordered callee relocs: esp_dport_access_reg_read.
     */
}

/* test_digital_pads_ie mod_subtest.c:162 @ mod_subtest.o size 102B [dwarf-sig]
 * Calls: esp_dport_access_reg_read | Data refs: esp_dport_access_reg_read | MMIO: 0x3ff49004, 0x3ff49084, 0x3ff49090
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void test_digital_pads_ie(u32 maskl, u32 maskh, u32 value)
{
    (void)maskl;
    (void)maskh;
    (void)value;
    /* DWARF locals: u32 i@l163, u32 mask0@l164 */
    /* TODO(ground-truth): reconstruct from librftest/mod_subtest.rdis
     * function <test_digital_pads_ie> (36 insns) + DWARF line rows for mod_subtest.c:162.
     * Ordered callee relocs: esp_dport_access_reg_read.
     */
}

/* test_digital_pads_pd mod_subtest.c:71 @ mod_subtest.o size 102B [dwarf-sig]
 * Calls: esp_dport_access_reg_read | Data refs: esp_dport_access_reg_read | MMIO: 0x3ff49004, 0x3ff49084, 0x3ff49090
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void test_digital_pads_pd(u32 maskl, u32 maskh, u32 value)
{
    (void)maskl;
    (void)maskh;
    (void)value;
    /* DWARF locals: u32 i@l72, u32 mask0@l73 */
    /* TODO(ground-truth): reconstruct from librftest/mod_subtest.rdis
     * function <test_digital_pads_pd> (36 insns) + DWARF line rows for mod_subtest.c:71.
     * Ordered callee relocs: esp_dport_access_reg_read.
     */
}

/* test_digital_pads_pu mod_subtest.c:101 @ mod_subtest.o size 102B [dwarf-sig]
 * Calls: esp_dport_access_reg_read | Data refs: esp_dport_access_reg_read | MMIO: 0x3ff49004, 0x3ff49084, 0x3ff49090
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void test_digital_pads_pu(u32 maskl, u32 maskh, u32 value)
{
    (void)maskl;
    (void)maskh;
    (void)value;
    /* DWARF locals: u32 i@l102, u32 mask0@l103 */
    /* TODO(ground-truth): reconstruct from librftest/mod_subtest.rdis
     * function <test_digital_pads_pu> (36 insns) + DWARF line rows for mod_subtest.c:101.
     * Ordered callee relocs: esp_dport_access_reg_read.
     */
}

/* test_digital_pads_slpoe mod_subtest.c:131 @ mod_subtest.o size 106B [dwarf-sig]
 * Calls: esp_dport_access_reg_read | Data refs: esp_dport_access_reg_read | MMIO: 0x3ff49004, 0x3ff49084, 0x3ff49090
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void test_digital_pads_slpoe(u32 maskl, u32 maskh, u32 value)
{
    (void)maskl;
    (void)maskh;
    (void)value;
    /* DWARF locals: u32 i@l133, u32 mask0@l134 */
    /* TODO(ground-truth): reconstruct from librftest/mod_subtest.rdis
     * function <test_digital_pads_slpoe> (41 insns) + DWARF line rows for mod_subtest.c:131.
     * Ordered callee relocs: esp_dport_access_reg_read.
     */
}

/* test_digital_pads_slppd mod_subtest.c:116 @ mod_subtest.o size 98B [dwarf-sig]
 * Calls: esp_dport_access_reg_read | Data refs: esp_dport_access_reg_read | MMIO: 0x3ff49004, 0x3ff49084, 0x3ff49090
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void test_digital_pads_slppd(u32 maskl, u32 maskh, u32 value)
{
    (void)maskl;
    (void)maskh;
    (void)value;
    /* DWARF locals: u32 i@l117, u32 mask0@l118 */
    /* TODO(ground-truth): reconstruct from librftest/mod_subtest.rdis
     * function <test_digital_pads_slppd> (36 insns) + DWARF line rows for mod_subtest.c:116.
     * Ordered callee relocs: esp_dport_access_reg_read.
     */
}

/* test_digital_pads_slppu mod_subtest.c:56 @ mod_subtest.o size 98B [dwarf-sig]
 * Calls: esp_dport_access_reg_read | Data refs: esp_dport_access_reg_read | MMIO: 0x3ff49004, 0x3ff49084, 0x3ff49090
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void test_digital_pads_slppu(u32 maskl, u32 maskh, u32 value)
{
    (void)maskl;
    (void)maskh;
    (void)value;
    /* DWARF locals: u32 i@l57, u32 mask0@l58 */
    /* TODO(ground-truth): reconstruct from librftest/mod_subtest.rdis
     * function <test_digital_pads_slppu> (36 insns) + DWARF line rows for mod_subtest.c:56.
     * Ordered callee relocs: esp_dport_access_reg_read.
     */
}

/* test_digital_pads_slpsel mod_subtest.c:42 @ mod_subtest.o size 98B [dwarf-sig]
 * Calls: esp_dport_access_reg_read | Data refs: esp_dport_access_reg_read | MMIO: 0x3ff49004, 0x3ff49084, 0x3ff49090
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void test_digital_pads_slpsel(u32 maskl, u32 maskh, u32 value)
{
    (void)maskl;
    (void)maskh;
    (void)value;
    /* DWARF locals: u32 i@l43, u32 mask0@l44 */
    /* TODO(ground-truth): reconstruct from librftest/mod_subtest.rdis
     * function <test_digital_pads_slpsel> (36 insns) + DWARF line rows for mod_subtest.c:42.
     * Ordered callee relocs: esp_dport_access_reg_read.
     */
}

/* test_pad_mode_sel mod_subtest.c:238 @ mod_subtest.o size 284B [dwarf-sig]
 * Calls: phy_printf, ets_delay_us, test_digital_pads_slpsel, test_digital_pads_slpoe, test_digital_pads_slppu, test_digital_pads_slppd, test_digital_pads_pu, test_digital_pads_pd, test_digital_pads_ie, test_rtc_pads_muxsel, test_slp_pad_ctrl, test_digital_pads_GPIO | Data refs: .rodata.str1.4, ets_delay_us, phy_printf, test_digital_pads_GPIO, test_digital_pads_ie, test_digital_pads_pd, test_digital_pads_pu, test_digital_pads_slpoe, test_digital_pads_slppd, test_digital_pads_slppu, test_digital_pads_slpsel, test_rtc_pads_muxsel, test_slp_pad_ctrl | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void test_pad_mode_sel(u8 mode, u32 maskl, u32 maskh)
{
    (void)mode;
    (void)maskl;
    (void)maskh;
    /* TODO(ground-truth): reconstruct from librftest/mod_subtest.rdis
     * function <test_pad_mode_sel> (111 insns) + DWARF line rows for mod_subtest.c:238.
     * Ordered callee relocs: phy_printf, ets_delay_us, test_digital_pads_slpsel, test_digital_pads_slpoe, test_digital_pads_slppu, test_digital_pads_slppd, test_digital_pads_pu, test_digital_pads_pd, test_digital_pads_ie, test_rtc_pads_muxsel, test_slp_pad_ctrl, test_digital_pads_GPIO.
     */
}

/* test_rtc_pads_muxsel mod_subtest.c:178 @ mod_subtest.o size 780B [dwarf-sig]
 * Calls: esp_dport_access_reg_read | Data refs: esp_dport_access_reg_read | MMIO: 0x3ff4847c, 0x3ff48480, 0x3ff48484, 0x3ff48488, 0x3ff4848c, 0x3ff48494, 0x3ff48498, 0x3ff4849c, 0x3ff484a0, 0x3ff484a4, 0x3ff484a8, 0x3ff484ac, 0x3ff484b0
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void test_rtc_pads_muxsel(u32 mask, u32 value)
{
    (void)mask;
    (void)value;
    /* TODO(ground-truth): reconstruct from librftest/mod_subtest.rdis
     * function <test_rtc_pads_muxsel> (284 insns) + DWARF line rows for mod_subtest.c:178.
     * Ordered callee relocs: esp_dport_access_reg_read.
     */
}

/* test_slp_pad_ctrl mod_subtest.c:201 @ mod_subtest.o size 284B [dwarf-sig]
 * Calls: test_digital_pads_slpsel, test_digital_pads_slpoe, test_digital_pads_slppu, test_digital_pads_slppd, test_digital_pads_pu, test_digital_pads_pd, test_digital_pads_ie, rtc_pads_muxsel, rtc_pads_slpsel, rtc_pads_slpoe, rtc_pads_slpie, rtc_pads_pu, rtc_pads_pd, rtc_pads_funsel, esp_dport_access_reg_read, test_digital_pads_GPIO | Data refs: esp_dport_access_reg_read, rtc_pads_funsel, rtc_pads_muxsel, rtc_pads_pd, rtc_pads_pu, rtc_pads_slpie, rtc_pads_slpoe, rtc_pads_slpsel, test_digital_pads_GPIO, test_digital_pads_ie, test_digital_pads_pd, test_digital_pads_pu, test_digital_pads_slpoe, test_digital_pads_slppd, test_digital_pads_slppu, test_digital_pads_slpsel | MMIO: 0x3ff44004, 0x3ff44010, 0x3ff44020, 0x3ff4402c, 0x3ff4840c
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void test_slp_pad_ctrl(u32 rtc_excpt_mask)
{
    (void)rtc_excpt_mask;
    /* DWARF locals: u32 rtc_mask@l211 */
    /* TODO(ground-truth): reconstruct from librftest/mod_subtest.rdis
     * function <test_slp_pad_ctrl> (112 insns) + DWARF line rows for mod_subtest.c:201.
     * Ordered callee relocs: test_digital_pads_slpsel, test_digital_pads_slpoe, test_digital_pads_slppu, test_digital_pads_slppd, test_digital_pads_pu, test_digital_pads_pd, test_digital_pads_ie, rtc_pads_muxsel, rtc_pads_slpsel, rtc_pads_slpoe, rtc_pads_slpie, rtc_pads_pu, rtc_pads_pd, rtc_pads_funsel, esp_dport_access_reg_read, test_digital_pads_GPIO.
     */
}

/* wr_adc_blk0 mod_subtest.c:848 @ mod_subtest.o size 62B [dwarf-sig]
 * Calls: burn_efuse | Data refs: burn_efuse, wr_data, wr_en | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
u8 wr_adc_blk0(void)
{
    /* DWARF locals: u8 write_result@l850 */
    /* TODO(ground-truth): reconstruct from librftest/mod_subtest.rdis
     * function <wr_adc_blk0> (23 insns) + DWARF line rows for mod_subtest.c:848.
     * Ordered callee relocs: burn_efuse.
     */
}

/* wr_adc_blk0_data3_14b mod_subtest.c:865 @ mod_subtest.o size 46B [dwarf-sig]
 * Calls: burn_efuse | Data refs: burn_efuse, wr_data, wr_en | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
u8 wr_adc_blk0_data3_14b(void)
{
    /* DWARF locals: u8 write_result@l867 */
    /* TODO(ground-truth): reconstruct from librftest/mod_subtest.rdis
     * function <wr_adc_blk0_data3_14b> (17 insns) + DWARF line rows for mod_subtest.c:865.
     * Ordered callee relocs: burn_efuse.
     */
}

/* write_coding_to_efuse mod_subtest.c:877 @ mod_subtest.o size 48B [dwarf-sig-decl]
 * Calls: burn_efuse | Data refs: burn_efuse, wr_data, wr_en | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
u8 write_coding_to_efuse(void)
{
    /* DWARF locals: u8 write_result@l879 */
    /* TODO(ground-truth): reconstruct from librftest/mod_subtest.rdis
     * function <write_coding_to_efuse> (18 insns) + DWARF line rows for mod_subtest.c:877.
     * Ordered callee relocs: burn_efuse.
     */
}

/* write_usermac_to_efuse mod_subtest.c:890 @ mod_subtest.o size 347B [dwarf-sig]
 * Calls: burn_efuse, esp_dport_access_reg_read, make_efuse | Data refs: burn_efuse, esp_dport_access_reg_read, make_efuse, wr_data, wr_en | MMIO: 0x3ff5a018
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
u8 write_usermac_to_efuse(u32 mac_upper, u32 mac_lower)
{
    (void)mac_upper;
    (void)mac_lower;
    /* DWARF locals: u8[] macaddr@l893, u8 i@l893, u8 user_mac_flag@l894, u8 user_mac_crc8@l895, u8[] wr_efuse_val@l895, u8[] all_bytes@l895, u8 write_result@l896, u8 code_result@l896, u8 result@l896, u32 blk0_rdata6@l897 */
    /* TODO(ground-truth): reconstruct from librftest/mod_subtest.rdis
     * function <write_usermac_to_efuse> (129 insns) + DWARF line rows for mod_subtest.c:890.
     * Ordered callee relocs: burn_efuse, esp_dport_access_reg_read, make_efuse.
     */
}

/* Undefined refs (18): burn_efuse, esp_dport_access_reg_read, ets_delay_us, gpio_input_get, gpio_input_get_high, gpio_output_set, gpio_output_set_high, phy_printf, rtc_8m_ena, rtc_pads_funsel, rtc_pads_muxsel, rtc_pads_pd, rtc_pads_pu, rtc_pads_slpie, rtc_pads_slpoe, rtc_pads_slpsel, rtc_slowck_cali, uart_wait_idle */