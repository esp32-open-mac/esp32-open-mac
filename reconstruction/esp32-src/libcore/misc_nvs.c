/* Reconstructed C for libcore.a : misc_nvs.o (Xtensa ELF32 relocatable).
 * Source disasm: re/esp32/disasm_full/libcore/misc_nvs.dis
 * Windowed ABI: incoming args a2..a7, return in a2, outgoing call args in
 * a10/a11/a12/..., targets from R_XTENSA_ASM_EXPAND relocs.
 * All numeric constants below appear verbatim in the disassembly.
 */
typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef int s32;

/* BSS (object-local, link address unknown until linked) */
extern u32 g_misc_nvs;        /* .bss.g_misc_nvs, 4B: pointer to 60B state buffer */
extern u8  g_misc_nvs_init;   /* .bss.g_misc_nvs_init, 1B: init flag */
extern u8  g_log_mod[24];     /* .bss.g_log_mod, 24B */
extern u32 g_log_level;       /* .bss.g_log_level, 4B */

/* Undefined externals (defined elsewhere at link time) */
extern void *g_osi_funcs_p;   /* opaque function-pointer table; used slots: 0x12c, 0x130, 0x15c, 176 */
extern void *g_wifi_menuconfig; /* byte +36 tested for nonzero */
extern void *memset(void *d, int v, unsigned n);
extern int wifi_log(int a, int b, int c, const char *fmt, ...);

/* misc_nvs_t: 60B buffer (alloc/memset size 60 observed).
 * Offset evidence: +56 read+written as u32 open-handle/out-param
 * (misc_nvs_load passes buf+56 to open; misc_nvs_deinit reads/clears it).
 * Offset +8 written once (u32 zero) in misc_nvs_load: kept as raw bytes. */
typedef struct {
    u8  raw[56];
    u32 handle; /* offset 56 */
    u8  tail[4];  /* 56+4..60 */
} misc_nvs_t;

/* misc_nvs_load @ misc_nvs.o 00000024 size 131B bind GLOBAL
 * Calls: wifi_log, memset | Data refs: g_osi_funcs_p, g_misc_nvs, g_wifi_menuconfig, .rodata.misc_nvs_load.str1.1("misc"), .rodata_wlog_warning.2("misc nvs f"), .rodata_wlog_warning.3("wifi osi_nvs_open fail ret=%d")
 * Fidelity: medium - all branches/callees resolved; open-return polarity inferred from fail-log text */
int misc_nvs_load(u32 arg)
{
    /* if low byte of arg != 0: skip load, clear state word, return 0
     * (extui a2,0,8 + bnez to shared epilogue at +0x78) */
    if ((arg & 0xffu) != 0)
        goto done_zero;

    /* g_misc_nvs = ((u32*(*) (u32))g_osi_funcs_p[0x15c/4])(60);
     * l32i chain: table[0] + 0x15c, outgoing a10 = 60 (movi.n 60). */
    g_misc_nvs = (u32)((u32 *(*) (u32))(*(u32 **)g_osi_funcs_p + 0x15cu / 4u))(60u);
    if (g_misc_nvs == 0) {
        /* wifi_log(1, 0x100, 2, "misc nvs f"); return log's return value
         * (a10=1, a11=0x100, a12=2 observed; then jump to return). */
        return wifi_log(1, 0x100, 2, "misc nvs f");
    }

    /* memset(g_misc_nvs, (int)arg, 60); a11 = incoming a2 (low byte 0 here),
     * a12 = 60, call via table symbol memset. */
    memset((void *)g_misc_nvs, (int)arg, 60u);

    /* if (*(u32*)(g_wifi_menuconfig + 36) == 0) goto done_zero; */
    if (*(u32 *)((u8 *)g_wifi_menuconfig + 36) == 0)
        goto done_zero;

    /* err = ((int(*)(const char*,u32,void*))table[0x12c/4])("misc", 1, buf+56);
     * outgoing a10="misc" (.rodata str1.1), a11=1, a12=g_misc_nvs+56. */
    {
        int err = ((int (*)(const char *, u32, void *))(*(u32 **)g_osi_funcs_p + 0x12cu / 4u))(
            "misc", 1u, (void *)(g_misc_nvs + 56u));
        if (err == 0)
            goto done_zero; /* success (0) falls into shared zero epilogue */
        /* wifi_log(1, 0x100, 2, "wifi osi_nvs_open fail ret=%d", err); */
        wifi_log(1, 0x100, 2, "wifi osi_nvs_open fail ret=%d", err);
        return err;
    }

done_zero:
    /* ((u32*)g_misc_nvs)[2] = 0 (s32i.n a2=0 at offset 8); return 0. */
    ((u32 *)g_misc_nvs)[2] = 0u;
    return 0;
}

/* misc_nvs_deinit @ misc_nvs.o 00000010 size 70B bind GLOBAL
 * Calls: none directly (3 indirect calls via g_osi_funcs_p slots 0x130, 176) | Data refs: g_misc_nvs, g_wifi_menuconfig, g_osi_funcs_p, .bss.g_misc_nvs_init
 * Fidelity: high - straight-line/branchy glue, all slots and offsets observed */
int misc_nvs_deinit(void)
{
    misc_nvs_t *p = (misc_nvs_t *)g_misc_nvs;

    if (p == 0)
        goto out; /* beqz to +0x34 */

    /* Skip nvs-close when menuconfig flag or stored handle is zero:
     * a9 = *(g_wifi_menuconfig+36); a10 = p->handle (offset 56). */
    if (*(u32 *)((u8 *)g_wifi_menuconfig + 36) != 0 && p->handle != 0) {
        /* ((void(*)(u32))table[0x130/4])(p->handle); table base = *g_osi_funcs_p */
        ((void (*)(u32))(*(u32 **)g_osi_funcs_p + 0x130u / 4u))(p->handle);
        p->handle = 0; /* s32i.n 0 at +56 */
    }

    /* ((void(*)(void*))table[176/4])(p); outgoing a10 = p. Frees the buffer. */
    ((void (*)(void *))(*(u32 **)g_osi_funcs_p + 176u / 4u))(p);

out:
    g_misc_nvs = 0;
    g_misc_nvs_init = 0; /* s8i 0 */
    return 0;
}

/* misc_nvs_init @ misc_nvs.o 0000000c size 46B bind GLOBAL
 * Calls: misc_nvs_load, misc_nvs_deinit | Data refs: .bss.g_misc_nvs_init
 * Fidelity: high - tiny init guard with exact call sequence */
int misc_nvs_init(void)
{
    if (g_misc_nvs_init != 0)
        return 0; /* bne to return; preserves a2 = 0 */
    g_misc_nvs_init = 1;
    {
        int err = misc_nvs_load(0u); /* outgoing a10 = 0 */
        if (err != 0)
            misc_nvs_deinit(); /* return value discarded; returns load's err */
        return err;
    }
}

/* misc_nvs_restore @ misc_nvs.o 00000004 size 16B bind GLOBAL
 * Calls: misc_nvs_load | Data refs: none
 * Fidelity: high - single tail call with constant arg */
int misc_nvs_restore(void)
{
    return misc_nvs_load(1u); /* movi a10,1; callx8; return value passthrough */
}
