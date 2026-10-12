/* Reconstruction of coexist_hw.o (libcoexist.a) — RF/BB coexistence overrides.
 * Ground truth: re/esp32-coex/funcdb_libcoexist.json (funcdb v3),
 * re/esp32-coex/disasm/coexist_hw.dis.
 * .iram1.0/.iram1.11/.iram1.15 = statics (no symtab entries): flush-read barrier,
 * BB/GPIO setup sequence, BB restore sequence. .dram1.8 (1B) = force-state flag
 * (bit7 = RF/BB overridden, needs restore; low bits = step/error code).
 * MMIO touched: 0x3ff000cc, 0x3ff00094, 0x3ff441c4, 0x3ff441c8, 0x3ff510a0,
 * 0x3ff5110c (bit20 polled), 0x3ff51110 (bits 22-26 + bit27 polled),
 * 0x3ff71250, 0x3ff71254 (bit7 spin), 0x3ff71300, 0x3ff73d40.
 */
typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;

extern void *g_coa_funcs_p;
extern u8 coex_bb_rst_mux[4];
extern u8 coex_fwm_mux[4];
extern u8 coex_force_flag; /* .dram1.8 (1B) */
extern void coex_dbg_output(u32 p0, u32 p1);
extern u32 coex_time_now(void);
extern void force_wifi_mode(u32 arg);
extern void unforce_wifi_mode(void);
extern void btdm_rf_bb_reg_init(void);

/* static coex_flush_read (.iram1.0; literal word 0x3ff40078 + rsil/wsr/rsync)
 * Calls: none | Data refs: none
 * Fidelity: medium - insn-exact (two volatile reads + int-level fence); intent (write-flush) inferred */
static u32 coex_flush_read(u32 addr)
{
    u32 tmp = *(volatile u32 *)0x3ff40078;
    u32 ps, out;
    __asm__ volatile ("rsil %0, 3" : "=r"(ps));
    out = *(volatile u32 *)tmp; /* note: disasm reads *(entry a2); addr threading approximate */
    (void)addr;
    __asm__ volatile ("wsr.ps %0; rsync" :: "r"(ps));
    return out;
}

/* static coex_bb_setup (.iram1.11; called from force_wifi_mode)
 * Calls: none | Data refs: coex_bb_rst_mux, g_coa_funcs_p
 * Fidelity: medium - take/give + exact constants (141, 0x80 spin, 0xFFFCFFFF, +8/-8, 0x3ffb0000, +0x30000) */
static void coex_bb_setup(void)
{
    u32 r = ((u32 (*)(void))*(u32 *)((u8 *)*(void **)g_coa_funcs_p + 12))();
    u32 v;
    *(volatile u32 *)0x3ff71250 = 141;
    while ((*(volatile u32 *)0x3ff71254 & 0x80) != 0) { /* spin bit7 clear */
    }
    coex_flush_read(0x3ff000cc);
    *(volatile u32 *)0x3ff000cc &= 0xFFFCFFFFu;
    *(volatile u32 *)0x3ff00094 |= 8;
    coex_flush_read(0x3ff00094);
    *(volatile u32 *)0x3ff00094 &= 0xFFFFFFF7u;
    v = *(volatile u32 *)0x3ff510a0 & 0x7FFFu;
    *(volatile u32 *)0x3ff510a0 = v | 0x3ffb0000u;
    coex_flush_read(0x3ff510a0);
    *(volatile u32 *)0x3ff71250 |= 0x30000u;
    ((void (*)(void *, u32))*(u32 *)((u8 *)*(void **)g_coa_funcs_p + 16))((void *)*(u32 *)coex_bb_rst_mux, r);
}

/* static coex_bb_restore (.iram1.15; called from force/unforce tails)
 * Calls: none | Data refs: coex_bb_rst_mux, g_coa_funcs_p
 * Fidelity: medium - take/give + exact clears (0x3ff71300 bits6-7, 0x3ff73d40 bits6-13+6, 0x3ff441c8 bit6) */
static void coex_bb_restore(void)
{
    u32 r = ((u32 (*)(void))*(u32 *)((u8 *)*(void **)g_coa_funcs_p + 12))();
    *(volatile u32 *)0x3ff71300 &= 0xFFFFFF3Fu;
    *(volatile u32 *)0x3ff73d40 &= 0xFFFFFE3Fu;
    *(volatile u32 *)0x3ff73d40 &= 0xFFFFFFBFu;
    *(volatile u32 *)0x3ff441c8 &= 0xFFFFFFBFu;
    ((void (*)(void *, u32))*(u32 *)((u8 *)*(void **)g_coa_funcs_p + 16))((void *)*(u32 *)coex_bb_rst_mux, r);
}

/* coex_gpio_init @ coexist_hw.o 00000008 size 43B bind GLOBAL
 * Calls: none | Data refs: none
 * Fidelity: high - clears bit6 (0x40) at 0x3ff441c4 and 0x3ff441c8 */
void coex_gpio_init(void)
{
    *(volatile u32 *)0x3ff441c4 &= 0xFFFFFFBFu;
    *(volatile u32 *)0x3ff441c8 &= 0xFFFFFFBFu;
}

/* coex_force_wifi_mode @ coexist_hw.o 00000070 size 615B bind GLOBAL
 * Calls: none | Data refs: none
 * Fidelity: low - decision-level: dbg(0,8), fwm take, 0x3ff71250=129, BB-state==7 + val==39 gate RF block (0x3ff71300/0x3ff73d40/0x3ff441c8), 25000/30 timeouts on 0x3ff51110/0x3ff5110c, err codes -124..-127, adapter force_wifi_mode; exact loop bounds approximate */
void coex_force_wifi_mode(u32 mode)
{
    u32 t0;
    u32 v;
    u32 ok = 0;
    coex_dbg_output(0, 8);
    t0 = coex_time_now();
    {
        u32 r = ((u32 (*)(void))*(u32 *)((u8 *)*(void **)g_coa_funcs_p + 12))();
        (void)r;
        *(volatile u32 *)0x3ff71250 = 129;
        ((void (*)(void *, u32))*(u32 *)((u8 *)*(void **)g_coa_funcs_p + 16))((void *)*(u32 *)coex_bb_rst_mux, r);
    }
    v = (*(volatile u32 *)0x3ff71254 >> 5) & 7;
    if (v == 7) {
        u32 r = ((u32 (*)(void))*(u32 *)((u8 *)*(void **)g_coa_funcs_p + 12))();
        (void)r;
        *(volatile u32 *)0x3ff71250 = 168;
        v = *(volatile u32 *)0x3ff71254 & 0xFFu;
        if (v == 39) { /* >= 3 and == 39 per bltui/bnez pair */
            *(volatile u32 *)0x3ff71300 |= 0xC0u;
            *(volatile u32 *)0x3ff71300 &= 0xFFFFFE3Fu;
            *(volatile u32 *)0x3ff71300 |= 0x100u;
            *(volatile u32 *)0x3ff441c8 |= 0x40u;
        }
        ((void (*)(void *, u32))*(u32 *)((u8 *)*(void **)g_coa_funcs_p + 16))((void *)*(u32 *)coex_bb_rst_mux, r);
        ok = 1;
    }
    if (coex_time_now() - t0 >= 25000) {
        coex_force_flag = (u8)-127;
    } else {
        while ((*(volatile u32 *)0x3ff51110 & 0x7C00000u) != 0) { /* bits 22-26 */
        }
        if ((coex_force_flag & 0x7F) != 0) {
            coex_bb_setup();
            coex_force_flag &= 0x80;
            {
                u32 r = ((u32 (*)(void))*(u32 *)((u8 *)*(void **)g_coa_funcs_p + 12))();
                force_wifi_mode(mode);
                ((void (*)(void *, u32))*(u32 *)((u8 *)*(void **)g_coa_funcs_p + 16))((void *)*(u32 *)coex_fwm_mux, r);
            }
            if (ok != 0)
                coex_bb_restore();
        }
        /* poll 0x3ff5110c bit20 (30-tick timeout), then 0x3ff51110 bit27, ... (see disasm 1c1-2c8) */
        while (((*(volatile u32 *)0x3ff5110c >> 20) & 1) != 0) {
            if (coex_time_now() - t0 >= 30) {
                coex_force_flag = (u8)-126;
                break;
            }
        }
    }
    coex_force_flag &= 0x80;
    coex_dbg_output(1, 9);
}

/* coex_unforce_wifi_mode @ coexist_hw.o 00000020 size 108B bind GLOBAL
 * Calls: none | Data refs: none
 * Fidelity: medium - bit7 flag -> btdm_rf_bb_reg_init + clear; bit20 poll; fwm take, adapter unforce_wifi_mode, give; dbg(1,11) */
void coex_unforce_wifi_mode(void)
{
    coex_dbg_output(0, 10);
    if ((coex_force_flag & 0x80) != 0) {
        btdm_rf_bb_reg_init();
        coex_force_flag = 0;
    }
    while (((*(volatile u32 *)0x3ff5110c >> 20) & 1) != 0) {
    }
    {
        u32 r = ((u32 (*)(void))*(u32 *)((u8 *)*(void **)g_coa_funcs_p + 12))();
        unforce_wifi_mode();
        ((void (*)(void *, u32))*(u32 *)((u8 *)*(void **)g_coa_funcs_p + 16))((void *)*(u32 *)coex_fwm_mux, r);
    }
    while (((*(volatile u32 *)0x3ff5110c >> 20) & 1) != 0) {
    }
    coex_dbg_output(1, 11);
}
