/* Reconstruction of cmd_polling.o (libbttestmode.a)
 * CU: cmd_polling.c | comp_dir: /home/lxf/gittree/chip7.1_rtc/board_code/app_test/pp/bt_testmode
 * producer: GNU C11 5.2.0 -mlongcalls -mtext-section-literals -g -O2 -fno-inline-functions -ffunction-sections -fdata-sections
 * DWARF subprograms: 8 | funcdb functions: 4
 * Disasm: re/esp32-phy/disasm/libbttestmode/cmd_polling.rdis
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

/* cmd_polling_attach cmd_polling.c:55 @ cmd_polling.o size 88B [dwarf-sig]
 * Calls: (none) | Data refs: cmd_queue | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
bool cmd_polling_attach(bool duplicate, u32 dup_id, _xtos_handler cmd_handler, void * args)
{
    (void)duplicate;
    (void)dup_id;
    (void)cmd_handler;
    (void)args;
    /* DWARF locals: u32 i@l56 */
    /* TODO(ground-truth): reconstruct from libbttestmode/cmd_polling.rdis
     * function <cmd_polling_attach> (35 insns) + DWARF line rows for cmd_polling.c:55.
     */
}

/* cmd_polling_dettach cmd_polling.c:84 @ cmd_polling.o size 70B [dwarf-sig]
 * Calls: (none) | Data refs: cmd_queue | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
bool cmd_polling_dettach(bool duplicate, u32 dup_id, _xtos_handler cmd_handler)
{
    (void)duplicate;
    (void)dup_id;
    (void)cmd_handler;
    /* DWARF locals: u32 i@l85 */
    /* TODO(ground-truth): reconstruct from libbttestmode/cmd_polling.rdis
     * function <cmd_polling_dettach> (27 insns) + DWARF line rows for cmd_polling.c:84.
     */
}

/* cmd_polling_handler cmd_polling.c:43 @ cmd_polling.o size 68B [dwarf-sig]
 * Calls: (none) | indirect-call(s) present (likely via g_phyFuns table) | Data refs: cmd_queue | MMIO: 0x6001f000, 0x6001f0a4
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void cmd_polling_handler(void)
{
    /* DWARF locals: u32 i@l44 */
    /* TODO(ground-truth): reconstruct from libbttestmode/cmd_polling.rdis
     * function <cmd_polling_handler> (25 insns) + DWARF line rows for cmd_polling.c:43.
     */
}

/* cmd_polling_start cmd_polling.c:108 @ cmd_polling.o size 48B [dwarf-sig]
 * Calls: intr_matrix_set, _xtos_set_interrupt_handler_arg, t0_start_toggle, _xtos_ints_on | Data refs: _xtos_ints_on, _xtos_set_interrupt_handler_arg, cmd_polling_handler, intr_matrix_set, t0_start_toggle | MMIO: (none)
 * Fidelity: low - logic TODO; signature + call/MMIO inventory from ground truth */
void cmd_polling_start(u32 period)
{
    (void)period;
    /* TODO(ground-truth): reconstruct from libbttestmode/cmd_polling.rdis
     * function <cmd_polling_start> (18 insns) + DWARF line rows for cmd_polling.c:108.
     * Ordered callee relocs: intr_matrix_set, _xtos_set_interrupt_handler_arg, t0_start_toggle, _xtos_ints_on.
     */
}

/* Undefined refs (4): _xtos_ints_on, _xtos_set_interrupt_handler_arg, intr_matrix_set, t0_start_toggle */