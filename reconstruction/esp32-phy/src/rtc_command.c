/* Reconstruction of rtc_command.o (librftest.a)
 * CU: rtc_command.c | comp_dir: /home/lxf/gittree/chip7.1_phy/chip_7.1/board_code/app_test/pp/rftest
 * producer: GNU C11 5.2.0 -mlongcalls -mtext-section-literals -mfix-esp32-psram-cache-issue -g -O2 -fno-inline-functions -ffunction-sections -fdata-sections
 * DWARF subprograms: 27 | funcdb functions: 17
 * Disasm: re/esp32-phy/disasm/librftest/rtc_command.rdis
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

/* read_rtc_mem rtc_command.c:80 @ rtc_command.o size 55B [dwarf-sig]
 * Calls: esp_dport_access_reg_read, phy_printf | Data refs: .rodata.str1.4, esp_dport_access_reg_read, phy_printf | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void read_rtc_mem(u32 start, u32 num)
{
    (void)start;
    (void)num;
    /* DWARF locals: u32 i@l82, u32 rd_mem@l82 */
    /* TODO(ground-truth): reconstruct from librftest/rtc_command.rdis
     * function <read_rtc_mem> (21 insns) + DWARF line rows for rtc_command.c:80.
     * Ordered callee relocs: esp_dport_access_reg_read, phy_printf.
     */
}

/* rtc_cmd_cpu_wakeup rtc_command.c:67 @ rtc_command.o size 11B [dwarf-sig-decl]
 * Calls: (none) | Data refs: (none) | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
u32 rtc_cmd_cpu_wakeup(u32 wake)
{
    (void)wake;
    /* TODO(ground-truth): reconstruct from librftest/rtc_command.rdis
     * function <rtc_cmd_cpu_wakeup> (4 insns) + DWARF line rows for rtc_command.c:67.
     */
}

/* rtc_cmd_force_branch rtc_command.c:55 @ rtc_command.o size 14B [dwarf-sig]
 * Calls: (none) | Data refs: (none) | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
u32 rtc_cmd_force_branch(u32 branch)
{
    (void)branch;
    /* TODO(ground-truth): reconstruct from librftest/rtc_command.rdis
     * function <rtc_cmd_force_branch> (5 insns) + DWARF line rows for rtc_command.c:55.
     */
}

/* rtc_cmd_meas_end rtc_command.c:75 @ rtc_command.o size 8B [dwarf-sig-decl]
 * Calls: (none) | Data refs: (none) | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
u32 rtc_cmd_meas_end(void)
{
    /* TODO(ground-truth): reconstruct from librftest/rtc_command.rdis
     * function <rtc_cmd_meas_end> (3 insns) + DWARF line rows for rtc_command.c:75.
     */
}

/* rtc_cmd_meas_saradc rtc_command.c:38 @ rtc_command.o size 29B [dwarf-sig-decl]
 * Calls: (none) | Data refs: (none) | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
u32 rtc_cmd_meas_saradc(u32 meas_cyc, u32 sar_sel, u32 sar_mux, u32 dreg)
{
    (void)meas_cyc;
    (void)sar_sel;
    (void)sar_mux;
    (void)dreg;
    /* TODO(ground-truth): reconstruct from librftest/rtc_command.rdis
     * function <rtc_cmd_meas_saradc> (10 insns) + DWARF line rows for rtc_command.c:38.
     */
}

/* rtc_cmd_meas_tsens rtc_command.c:34 @ rtc_command.o size 17B [dwarf-sig-decl]
 * Calls: (none) | Data refs: (none) | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
u32 rtc_cmd_meas_tsens(u32 meas_cyc, u32 delay)
{
    (void)meas_cyc;
    (void)delay;
    /* TODO(ground-truth): reconstruct from librftest/rtc_command.rdis
     * function <rtc_cmd_meas_tsens> (6 insns) + DWARF line rows for rtc_command.c:34.
     */
}

/* rtc_cmd_rd_reg rtc_command.c:22 @ rtc_command.o size 23B [dwarf-sig]
 * Calls: (none) | Data refs: (none) | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
u32 rtc_cmd_rd_reg(u32 addr, u32 high_bit, u32 low_bit)
{
    (void)addr;
    (void)high_bit;
    (void)low_bit;
    /* TODO(ground-truth): reconstruct from librftest/rtc_command.rdis
     * function <rtc_cmd_rd_reg> (8 insns) + DWARF line rows for rtc_command.c:22.
     */
}

/* rtc_cmd_reg0_alu rtc_command.c:47 @ rtc_command.o size 23B [dwarf-sig]
 * Calls: (none) | Data refs: (none) | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
u32 rtc_cmd_reg0_alu(u32 mask, u32 alu, u32 dreg)
{
    (void)mask;
    (void)alu;
    (void)dreg;
    /* TODO(ground-truth): reconstruct from librftest/rtc_command.rdis
     * function <rtc_cmd_reg0_alu> (8 insns) + DWARF line rows for rtc_command.c:47.
     */
}

/* rtc_cmd_reg0_branch rtc_command.c:59 @ rtc_command.o size 23B [dwarf-sig]
 * Calls: (none) | Data refs: (none) | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
u32 rtc_cmd_reg0_branch(u32 branch, u32 judge, u32 thres)
{
    (void)branch;
    (void)judge;
    (void)thres;
    /* TODO(ground-truth): reconstruct from librftest/rtc_command.rdis
     * function <rtc_cmd_reg0_branch> (8 insns) + DWARF line rows for rtc_command.c:59.
     */
}

/* rtc_cmd_sleep_cyc_sel rtc_command.c:71 @ rtc_command.o size 11B [dwarf-sig-decl]
 * Calls: (none) | Data refs: (none) | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
u32 rtc_cmd_sleep_cyc_sel(u32 cyc_sel)
{
    (void)cyc_sel;
    /* TODO(ground-truth): reconstruct from librftest/rtc_command.rdis
     * function <rtc_cmd_sleep_cyc_sel> (4 insns) + DWARF line rows for rtc_command.c:71.
     */
}

/* rtc_cmd_stage_alu rtc_command.c:51 @ rtc_command.o size 20B [dwarf-sig]
 * Calls: (none) | Data refs: (none) | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
u32 rtc_cmd_stage_alu(u32 flag, u32 alu)
{
    (void)flag;
    (void)alu;
    /* TODO(ground-truth): reconstruct from librftest/rtc_command.rdis
     * function <rtc_cmd_stage_alu> (7 insns) + DWARF line rows for rtc_command.c:51.
     */
}

/* rtc_cmd_stage_branch rtc_command.c:63 @ rtc_command.o size 23B [dwarf-sig]
 * Calls: (none) | Data refs: (none) | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
u32 rtc_cmd_stage_branch(u32 branch, u32 judge, u32 thres)
{
    (void)branch;
    (void)judge;
    (void)thres;
    /* TODO(ground-truth): reconstruct from librftest/rtc_command.rdis
     * function <rtc_cmd_stage_branch> (8 insns) + DWARF line rows for rtc_command.c:63.
     */
}

/* rtc_cmd_wait_delay rtc_command.c:30 @ rtc_command.o size 11B [dwarf-sig]
 * Calls: (none) | Data refs: (none) | MMIO: 0x40000000
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
u32 rtc_cmd_wait_delay(u32 delay)
{
    (void)delay;
    /* TODO(ground-truth): reconstruct from librftest/rtc_command.rdis
     * function <rtc_cmd_wait_delay> (4 insns) + DWARF line rows for rtc_command.c:30.
     */
}

/* rtc_cmd_wr_i2c rtc_command.c:26 @ rtc_command.o size 41B [dwarf-sig]
 * Calls: (none) | Data refs: (none) | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
u32 rtc_cmd_wr_i2c(u32 wr_en, u32 i2c_sel, u32 addr, u32 high_bit, u32 low_bit, u32 data)
{
    (void)wr_en;
    (void)i2c_sel;
    (void)addr;
    (void)high_bit;
    (void)low_bit;
    (void)data;
    /* TODO(ground-truth): reconstruct from librftest/rtc_command.rdis
     * function <rtc_cmd_wr_i2c> (14 insns) + DWARF line rows for rtc_command.c:26.
     */
}

/* rtc_cmd_wr_reg rtc_command.c:18 @ rtc_command.o size 29B [dwarf-sig-decl]
 * Calls: (none) | Data refs: (none) | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
u32 rtc_cmd_wr_reg(u32 addr, u32 high_bit, u32 low_bit, u32 data)
{
    (void)addr;
    (void)high_bit;
    (void)low_bit;
    (void)data;
    /* TODO(ground-truth): reconstruct from librftest/rtc_command.rdis
     * function <rtc_cmd_wr_reg> (10 insns) + DWARF line rows for rtc_command.c:18.
     */
}

/* rtc_cmd_write_mem rtc_command.c:42 @ rtc_command.o size 23B [dwarf-sig-decl]
 * Calls: (none) | Data refs: (none) | MMIO: 0x60000000
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
u32 rtc_cmd_write_mem(u32 write_way, u32 result_mux, u32 dreg)
{
    (void)write_way;
    (void)result_mux;
    (void)dreg;
    /* TODO(ground-truth): reconstruct from librftest/rtc_command.rdis
     * function <rtc_cmd_write_mem> (8 insns) + DWARF line rows for rtc_command.c:42.
     */
}

/* test_rtc_cmd rtc_command.c:89 @ rtc_command.o size 280B [dwarf-sig]
 * Calls: esp_dport_access_reg_read, ets_delay_us, read_rtc_mem | Data refs: .rodata.test_rtc_cmd, esp_dport_access_reg_read, ets_delay_us, read_rtc_mem | MMIO: 0x3ff48018, 0x3ff48890, 0x60000000, 0x60000004, 0x60000008, 0x6000000c, 0x60000010, 0x60000014, 0x60000018, 0x60021000
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
u32 test_rtc_cmd(u32 sar1_en_pad, u32 sar2_en_pad)
{
    (void)sar1_en_pad;
    (void)sar2_en_pad;
    /* DWARF locals: u32 i@l94, u32 data@l94 */
    /* TODO(ground-truth): reconstruct from librftest/rtc_command.rdis
     * function <test_rtc_cmd> (102 insns) + DWARF line rows for rtc_command.c:89.
     * Ordered callee relocs: esp_dport_access_reg_read, ets_delay_us, read_rtc_mem.
     */
}

/* Undefined refs (3): esp_dport_access_reg_read, ets_delay_us, phy_printf */