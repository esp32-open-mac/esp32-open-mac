/* Reconstruction of simple_wdt.o (librftest.a)
 * CU: simple_wdt.c | comp_dir: /home/lxf/gittree/chip7.1_phy/chip_7.1/board_code/app_test/pp/rftest
 * producer: GNU C11 5.2.0 -mlongcalls -mtext-section-literals -mfix-esp32-psram-cache-issue -g -O2 -fno-inline-functions -ffunction-sections -fdata-sections
 * DWARF subprograms: 12 | funcdb functions: 9
 * Disasm: re/esp32-phy/disasm/librftest/simple_wdt.rdis
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

/* rtc_get_reset_reason simple_wdt.c:5 @ simple_wdt.o size 40B [dwarf-sig-decl]
 * Calls: esp_dport_access_reg_read | Data refs: esp_dport_access_reg_read | MMIO: 0x3ff48018, 0x3ff48034
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
RESET_REASON rtc_get_reset_reason(void)
{
    /* DWARF locals: u32 result@l7 */
    /* TODO(ground-truth): reconstruct from librftest/simple_wdt.rdis
     * function <rtc_get_reset_reason> (14 insns) + DWARF line rows for simple_wdt.c:5.
     * Ordered callee relocs: esp_dport_access_reg_read.
     */
}

/* t0_start_toggle simple_wdt.c:65 @ simple_wdt.o size 166B [dwarf-sig]
 * Calls: esp_dport_access_reg_read | Data refs: esp_dport_access_reg_read | MMIO: 0x3ff5f000, 0x3ff5f010, 0x3ff5f014, 0x3ff5f018, 0x3ff5f01c, 0x3ff5f020, 0x3ff5f098, 0x60000c00
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void t0_start_toggle(u32 alarm)
{
    (void)alarm;
    /* TODO(ground-truth): reconstruct from librftest/simple_wdt.rdis
     * function <t0_start_toggle> (66 insns) + DWARF line rows for simple_wdt.c:65.
     * Ordered callee relocs: esp_dport_access_reg_read.
     */
}

/* t0_toggle_service simple_wdt.c:85 @ simple_wdt.o size 58B [dwarf-sig]
 * Calls: esp_dport_access_reg_read, phy_printf | Data refs: .rodata.str1.4, esp_dport_access_reg_read, phy_printf | MMIO: 0x3ff5f000, 0x3ff5f0a4
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void t0_toggle_service(void)
{
    /* TODO(ground-truth): reconstruct from librftest/simple_wdt.rdis
     * function <t0_toggle_service> (21 insns) + DWARF line rows for simple_wdt.c:85.
     * Ordered callee relocs: esp_dport_access_reg_read, phy_printf.
     */
}

/* t1_start_toggle simple_wdt.c:93 @ simple_wdt.o size 166B [dwarf-sig]
 * Calls: esp_dport_access_reg_read | Data refs: esp_dport_access_reg_read | MMIO: 0x3ff5f024, 0x3ff5f034, 0x3ff5f038, 0x3ff5f03c, 0x3ff5f040, 0x3ff5f044, 0x3ff5f098, 0x60000c00
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void t1_start_toggle(u32 alarm)
{
    (void)alarm;
    /* TODO(ground-truth): reconstruct from librftest/simple_wdt.rdis
     * function <t1_start_toggle> (66 insns) + DWARF line rows for simple_wdt.c:93.
     * Ordered callee relocs: esp_dport_access_reg_read.
     */
}

/* t1_toggle_service simple_wdt.c:113 @ simple_wdt.o size 58B [dwarf-sig]
 * Calls: esp_dport_access_reg_read, phy_printf | Data refs: .rodata.str1.4, esp_dport_access_reg_read, phy_printf | MMIO: 0x3ff5f024, 0x3ff5f0a4
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void t1_toggle_service(void)
{
    /* TODO(ground-truth): reconstruct from librftest/simple_wdt.rdis
     * function <t1_toggle_service> (21 insns) + DWARF line rows for simple_wdt.c:113.
     * Ordered callee relocs: esp_dport_access_reg_read, phy_printf.
     */
}

/* wdt_feed simple_wdt.c:61 @ simple_wdt.o size 15B [dwarf-sig]
 * Calls: (none) | Data refs: (none) | MMIO: 0x3ff5f060
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void wdt_feed(void)
{
    /* TODO(ground-truth): reconstruct from librftest/simple_wdt.rdis
     * function <wdt_feed> (6 insns) + DWARF line rows for simple_wdt.c:61.
     */
}

/* wdt_init simple_wdt.c:32 @ simple_wdt.o size 197B [dwarf-sig]
 * Calls: esp_dport_access_reg_read | Data refs: esp_dport_access_reg_read | MMIO: 0x3ff5f048, 0x3ff5f050, 0x3ff5f054, 0x3ff5f058, 0x3ff5f05c
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void wdt_init(u32 stage, u32 mode, u32 timeout)
{
    (void)stage;
    (void)mode;
    (void)timeout;
    /* TODO(ground-truth): reconstruct from librftest/simple_wdt.rdis
     * function <wdt_init> (69 insns) + DWARF line rows for simple_wdt.c:32.
     * Ordered callee relocs: esp_dport_access_reg_read.
     */
}

/* wdt_nrst simple_wdt.c:27 @ simple_wdt.o size 16B [dwarf-sig]
 * Calls: esp_dport_access_reg_read | Data refs: esp_dport_access_reg_read | MMIO: 0x3ff4804c
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
uint32_t wdt_nrst(void)
{
    /* TODO(ground-truth): reconstruct from librftest/simple_wdt.rdis
     * function <wdt_nrst> (6 insns) + DWARF line rows for simple_wdt.c:27.
     * Ordered callee relocs: esp_dport_access_reg_read.
     */
}

/* wdt_nrst_inc simple_wdt.c:20 @ simple_wdt.o size 74B [dwarf-sig]
 * Calls: esp_dport_access_reg_read | Data refs: esp_dport_access_reg_read | MMIO: 0x3ff48018, 0x3ff48034, 0x3ff4804c
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void wdt_nrst_inc(void)
{
    /* DWARF locals: u32 reset_reason@l21 */
    /* TODO(ground-truth): reconstruct from librftest/simple_wdt.rdis
     * function <wdt_nrst_inc> (27 insns) + DWARF line rows for simple_wdt.c:20.
     * Ordered callee relocs: esp_dport_access_reg_read.
     */
}

/* Undefined refs (2): esp_dport_access_reg_read, phy_printf */