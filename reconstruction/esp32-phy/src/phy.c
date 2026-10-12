/* Reconstruction of phy.o (libphy.a)
 * CU: phy.c | comp_dir: /home/lxf/gittree/chip7.1_phy/chip_7.1/board_code/app_test/pp/phy
 * producer: GNU C11 5.2.0 -mlongcalls -mtext-section-literals -mfix-esp32-psram-cache-issue -g -O2 -fno-inline-functions -ffunction-sections -fdata-sections
 * DWARF subprograms: 6 | funcdb functions: 3
 * Disasm: re/esp32-phy/disasm/libphy/phy.rdis
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

/* RFChannelSel phy.c:? @ phy.o size 17B [dwarf-sig]
 * Calls: chip_v7_set_chan | Data refs: chip_v7_set_chan (reloc) | MMIO: (none)
 * Fidelity: high - arg-forwarding wrapper verified per disasm */
void RFChannelSel(int8 channel, int8 sub_chan_cfg)
{
    chip_v7_set_chan((int8)channel, (int8)sub_chan_cfg);  /* sext lanes */
}
/* phy_change_channel phy.c:? @ phy.o size 19B [dwarf-sig]
 * Calls: set_chanfreq | Data refs: set_chanfreq (reloc) | MMIO: (none)
 * Fidelity: high - wrapper verified; bHomeChan/pBReset unused, STATUS 0 */
STATUS phy_change_channel(uint16 chanFreq, bool bHomeChan, bool pBReset, int8 sub_chan_cfg)
{
    (void)bHomeChan; (void)pBReset;   /* no dataflow in disasm */
    extern void set_chanfreq(uint16 f, int8 s);  /* usage-typed arity */
    set_chanfreq((uint16)(chanFreq & 0xffffu), sub_chan_cfg);  /* extui/sext */
    return 0;                         /* movi a2,0 */
}
/* phy_change_channel_nomac phy.c:? @ phy.o size 19B [dwarf-sig]
 * Calls: set_chanfreq_nomac | Data refs: set_chanfreq_nomac (reloc) | MMIO: (none)
 * Fidelity: high - wrapper verified; bHomeChan/pBReset unused, STATUS 0 */
STATUS phy_change_channel_nomac(uint16 chanFreq, bool bHomeChan, bool pBReset, int8 sub_chan_cfg)
{
    (void)bHomeChan; (void)pBReset;   /* no dataflow in disasm */
    extern void set_chanfreq_nomac(uint16 f, int8 s);  /* usage-typed arity */
    set_chanfreq_nomac((uint16)(chanFreq & 0xffffu), sub_chan_cfg);
    return 0;
}
/* Undefined refs (3): chip_v7_set_chan, set_chanfreq, set_chanfreq_nomac */