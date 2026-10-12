/* Reconstruction of esp_phy_api.o (librftest.a)
 * CU: esp_phy_api.c | comp_dir: /home/lxf/gittree/chip7.1_phy/chip_7.1/board_code/app_test/pp/rftest
 * producer: GNU C11 5.2.0 -mlongcalls -mtext-section-literals -mfix-esp32-psram-cache-issue -g -O2 -fno-inline-functions -ffunction-sections -fdata-sections
 * DWARF subprograms: 23 | funcdb functions: 12
 * Disasm: re/esp32-phy/disasm/librftest/esp_phy_api.rdis
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

/* esp_phy_ble_rx esp_phy_api.c:126 @ esp_phy_api.o size 18B [dwarf-sig]
 * Calls: esp_ble_rx_func | Data refs: esp_ble_rx_func | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void esp_phy_ble_rx(u32 chan, u32 syncw, esp_phy_ble_rate_t rate)
{
    (void)chan;
    (void)syncw;
    (void)rate;
    /* TODO(ground-truth): reconstruct from librftest/esp_phy_api.rdis
     * function <esp_phy_ble_rx> (7 insns) + DWARF line rows for esp_phy_api.c:126.
     * Ordered callee relocs: esp_ble_rx_func.
     */
}

/* esp_phy_ble_tx esp_phy_api.c:121 @ esp_phy_api.o size 27B [dwarf-sig]
 * Calls: esp_ble_tx_func | Data refs: esp_ble_tx_func | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void esp_phy_ble_tx(u32 txpwr, u32 chan, u32 len, esp_phy_ble_type_t data_type, u32 syncw, esp_phy_ble_rate_t rate, u32 tx_num_in)
{
    (void)txpwr;
    (void)chan;
    (void)len;
    (void)data_type;
    (void)syncw;
    (void)rate;
    (void)tx_num_in;
    /* TODO(ground-truth): reconstruct from librftest/esp_phy_api.rdis
     * function <esp_phy_ble_tx> (12 insns) + DWARF line rows for esp_phy_api.c:121.
     * Ordered callee relocs: esp_ble_tx_func.
     */
}

/* esp_phy_bt_tx_tone esp_phy_api.c:131 @ esp_phy_api.o size 18B [dwarf-sig]
 * Calls: bt_tx_tone | Data refs: bt_tx_tone | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void esp_phy_bt_tx_tone(u32 start, u32 chan, u32 backoff)
{
    (void)start;
    (void)chan;
    (void)backoff;
    /* TODO(ground-truth): reconstruct from librftest/esp_phy_api.rdis
     * function <esp_phy_bt_tx_tone> (7 insns) + DWARF line rows for esp_phy_api.c:131.
     * Ordered callee relocs: bt_tx_tone.
     */
}

/* esp_phy_cbw40m_en esp_phy_api.c:78 @ esp_phy_api.o size 14B [dwarf-sig]
 * Calls: cbw40m_en | Data refs: cbw40m_en | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void esp_phy_cbw40m_en(bool en)
{
    (void)en;
    /* TODO(ground-truth): reconstruct from librftest/esp_phy_api.rdis
     * function <esp_phy_cbw40m_en> (5 insns) + DWARF line rows for esp_phy_api.c:78.
     * Ordered callee relocs: cbw40m_en.
     */
}

/* esp_phy_get_rx_result esp_phy_api.c:100 @ esp_phy_api.o size 36B [dwarf-sig]
 * Calls: (none) | Data refs: esp_rx_result, esp_rx_valid | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void esp_phy_get_rx_result(esp_phy_rx_result * rx_result)
{
    (void)rx_result;
    /* TODO(ground-truth): reconstruct from librftest/esp_phy_api.rdis
     * function <esp_phy_get_rx_result> (16 insns) + DWARF line rows for esp_phy_api.c:100.
     */
}

/* esp_phy_rftest_config esp_phy_api.c:62 @ esp_phy_api.o size 14B [dwarf-sig]
 * Calls: idf_enable | Data refs: idf_enable | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void esp_phy_rftest_config(uint8 conf)
{
    (void)conf;
    /* TODO(ground-truth): reconstruct from librftest/esp_phy_api.rdis
     * function <esp_phy_rftest_config> (5 insns) + DWARF line rows for esp_phy_api.c:62.
     * Ordered callee relocs: idf_enable.
     */
}

/* esp_phy_rftest_init esp_phy_api.c:67 @ esp_phy_api.o size 11B [dwarf-sig]
 * Calls: rftest_init | Data refs: rftest_init | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void esp_phy_rftest_init(void)
{
    /* TODO(ground-truth): reconstruct from librftest/esp_phy_api.rdis
     * function <esp_phy_rftest_init> (4 insns) + DWARF line rows for esp_phy_api.c:67.
     * Ordered callee relocs: rftest_init.
     */
}

/* esp_phy_short_gi_en esp_phy_api.c:114 @ esp_phy_api.o size 24B [dwarf-sig]
 * Calls: phy_printf | Data refs: .rodata.str1.4, phy_printf, short_gi_enable | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void esp_phy_short_gi_en(bool en)
{
    (void)en;
    /* TODO(ground-truth): reconstruct from librftest/esp_phy_api.rdis
     * function <esp_phy_short_gi_en> (9 insns) + DWARF line rows for esp_phy_api.c:114.
     * Ordered callee relocs: phy_printf.
     */
}

/* esp_phy_tx_contin_en esp_phy_api.c:73 @ esp_phy_api.o size 14B [dwarf-sig]
 * Calls: tx_contin_en | Data refs: tx_contin_en | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void esp_phy_tx_contin_en(bool contin_en)
{
    (void)contin_en;
    /* TODO(ground-truth): reconstruct from librftest/esp_phy_api.rdis
     * function <esp_phy_tx_contin_en> (5 insns) + DWARF line rows for esp_phy_api.c:73.
     * Ordered callee relocs: tx_contin_en.
     */
}

/* esp_phy_wifi_rx esp_phy_api.c:94 @ esp_phy_api.o size 15B [dwarf-sig]
 * Calls: esp_rx_func | Data refs: esp_rx_func | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void esp_phy_wifi_rx(u32 chan, esp_phy_wifi_rate_t rate)
{
    (void)chan;
    (void)rate;
    /* DWARF locals: int[] para_array@l96 */
    /* TODO(ground-truth): reconstruct from librftest/esp_phy_api.rdis
     * function <esp_phy_wifi_rx> (6 insns) + DWARF line rows for esp_phy_api.c:94.
     * Ordered callee relocs: esp_rx_func.
     */
}

/* esp_phy_wifi_tx esp_phy_api.c:83 @ esp_phy_api.o size 30B [dwarf-sig]
 * Calls: esp_tx_func | Data refs: esp_tx_func | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void esp_phy_wifi_tx(u32 chan, esp_phy_wifi_rate_t rate, s8 backoff, u32 length_byte, u32 packet_delay, u32 packet_num)
{
    (void)chan;
    (void)rate;
    (void)backoff;
    (void)length_byte;
    (void)packet_delay;
    (void)packet_num;
    /* DWARF locals: int[] para_array@l85 */
    /* TODO(ground-truth): reconstruct from librftest/esp_phy_api.rdis
     * function <esp_phy_wifi_tx> (13 insns) + DWARF line rows for esp_phy_api.c:83.
     * Ordered callee relocs: esp_tx_func.
     */
}

/* esp_phy_wifi_tx_tone esp_phy_api.c:108 @ esp_phy_api.o size 18B [dwarf-sig]
 * Calls: wifiscwout | Data refs: wifiscwout | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void esp_phy_wifi_tx_tone(u32 start, u32 chan, u32 backoff)
{
    (void)start;
    (void)chan;
    (void)backoff;
    /* DWARF locals: int[] para_array@l110 */
    /* TODO(ground-truth): reconstruct from librftest/esp_phy_api.rdis
     * function <esp_phy_wifi_tx_tone> (7 insns) + DWARF line rows for esp_phy_api.c:108.
     * Ordered callee relocs: wifiscwout.
     */
}

/* Undefined refs (14): bt_tx_tone, cbw40m_en, esp_ble_rx_func, esp_ble_tx_func, esp_rx_func, esp_rx_result, esp_rx_valid, esp_tx_func, idf_enable, phy_printf, rftest_init, short_gi_enable, tx_contin_en, wifiscwout */