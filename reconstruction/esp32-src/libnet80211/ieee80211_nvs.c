/* ieee80211_nvs.o - reconstructed control-path C (offline, from objdump -d -r).
 * 29 code sections recovered. Fidelity per function below.
 * Conventions: args a2..a7 (Xtensa windowed ABI); outgoing call args
 * traced as a10..; u32 used for pointers/regs; opaque_* marks unrecovered.
 */
#include <stdint.h>
typedef unsigned char u8; typedef unsigned short u16; typedef unsigned int u32;
static u32 opaque_result, last_call_result;
/* ---- externals (U symbols + literal refs) ---- */
extern u32 bss_g_wifi_nvs_cfg; /* .bss.g_wifi_nvs_cfg */
extern u32 rodata_ieee80211_nvs_set_default_ssid_str1_1; /* .rodata.ieee80211_nvs_set_default_ssid.str1.1 */
extern u32 rodata_wifi_nvs_cfg_init_str1_1; /* .rodata.wifi_nvs_cfg_init.str1.1 */
extern u32 rodata_wifi_nvs_init_str1_1; /* .rodata.wifi_nvs_init.str1.1 */
extern u32 rodata_wifi_nvs_set; /* .rodata.wifi_nvs_set */
extern u32 rodata_wlog_error_16; /* .rodata_wlog_error.16 */
extern u32 rodata_wlog_error_2; /* .rodata_wlog_error.2 */
extern u32 rodata_wlog_error_3; /* .rodata_wlog_error.3 */
extern u32 rodata_wlog_error_5; /* .rodata_wlog_error.5 */
extern u32 rodata_wlog_warning_10; /* .rodata_wlog_warning.10 */
extern u32 rodata_wlog_warning_11; /* .rodata_wlog_warning.11 */
extern u32 rodata_wlog_warning_12; /* .rodata_wlog_warning.12 */
extern u32 rodata_wlog_warning_13; /* .rodata_wlog_warning.13 */
extern u32 rodata_wlog_warning_14; /* .rodata_wlog_warning.14 */
extern u32 rodata_wlog_warning_15; /* .rodata_wlog_warning.15 */
extern u32 rodata_wlog_warning_4; /* .rodata_wlog_warning.4 */
extern u32 rodata_wlog_warning_6; /* .rodata_wlog_warning.6 */
extern u32 rodata_wlog_warning_7; /* .rodata_wlog_warning.7 */
extern u32 rodata_wlog_warning_8; /* .rodata_wlog_warning.8 */
extern u32 rodata_wlog_warning_9; /* .rodata_wlog_warning.9 */
extern u32 chm_get_snd_chan_mode(); /* chm_get_snd_chan_mode */
extern u32 g_ic; /* g_ic */
extern u32 g_osi_funcs_p; /* g_osi_funcs_p */
extern u32 g_wifi_menuconfig; /* g_wifi_menuconfig */
extern u32 g_wifi_nvs; /* g_wifi_nvs */
extern u32 ieee80211_regdomain_ap_min_chan(); /* ieee80211_regdomain_ap_min_chan */
extern u32 ieee80211_regdomain_check_ap_channel(); /* ieee80211_regdomain_check_ap_channel */
extern u32 memcmp(); /* memcmp */
extern u32 memcpy(); /* memcpy */
extern u32 memset(); /* memset */
extern u32 net80211_funcs; /* net80211_funcs */
extern u32 s_wifi_nvs; /* s_wifi_nvs */
extern u32 s_wifi_nvs_0x1; /* s_wifi_nvs+0x1 */
extern u32 s_wifi_nvs_0x2e; /* s_wifi_nvs+0x2e */
extern u32 s_wifi_nvs_0x2f; /* s_wifi_nvs+0x2f */
extern u32 s_wifi_nvs_0x35c; /* s_wifi_nvs+0x35c */
extern u32 s_wifi_nvs_0x35d; /* s_wifi_nvs+0x35d */
extern u32 s_wifi_nvs_0x35e; /* s_wifi_nvs+0x35e */
extern u32 s_wifi_nvs_0x35f; /* s_wifi_nvs+0x35f */
extern u32 s_wifi_nvs_0x360; /* s_wifi_nvs+0x360 */
extern u32 s_wifi_nvs_0x361; /* s_wifi_nvs+0x361 */
extern u32 s_wifi_nvs_0x362; /* s_wifi_nvs+0x362 */
extern u32 s_wifi_nvs_0x363; /* s_wifi_nvs+0x363 */
extern u32 s_wifi_nvs_0x364; /* s_wifi_nvs+0x364 */
extern u32 s_wifi_nvs_0x368; /* s_wifi_nvs+0x368 */
extern u32 s_wifi_nvs_0x392; /* s_wifi_nvs+0x392 */
extern u32 s_wifi_nvs_0x3d3; /* s_wifi_nvs+0x3d3 */
extern u32 s_wifi_nvs_0x3f3; /* s_wifi_nvs+0x3f3 */
extern u32 s_wifi_nvs_0x3f4; /* s_wifi_nvs+0x3f4 */
extern u32 s_wifi_nvs_0x3f5; /* s_wifi_nvs+0x3f5 */
extern u32 s_wifi_nvs_0x3f6; /* s_wifi_nvs+0x3f6 */
extern u32 s_wifi_nvs_0x3f8; /* s_wifi_nvs+0x3f8 */
extern u32 s_wifi_nvs_0x3fa; /* s_wifi_nvs+0x3fa */
extern u32 s_wifi_nvs_0x3fb; /* s_wifi_nvs+0x3fb */
extern u32 s_wifi_nvs_0x3fc; /* s_wifi_nvs+0x3fc */
extern u32 s_wifi_nvs_0x3fd; /* s_wifi_nvs+0x3fd */
extern u32 s_wifi_nvs_0x3fe; /* s_wifi_nvs+0x3fe */
extern u32 s_wifi_nvs_0x3ff; /* s_wifi_nvs+0x3ff */
extern u32 s_wifi_nvs_0x4; /* s_wifi_nvs+0x4 */
extern u32 s_wifi_nvs_0x400; /* s_wifi_nvs+0x400 */
extern u32 s_wifi_nvs_0x401; /* s_wifi_nvs+0x401 */
extern u32 s_wifi_nvs_0x402; /* s_wifi_nvs+0x402 */
extern u32 s_wifi_nvs_0x404; /* s_wifi_nvs+0x404 */
extern u32 s_wifi_nvs_0x414; /* s_wifi_nvs+0x414 */
extern u32 s_wifi_nvs_0x415; /* s_wifi_nvs+0x415 */
extern u32 s_wifi_nvs_0x416; /* s_wifi_nvs+0x416 */
extern u32 s_wifi_nvs_0x417; /* s_wifi_nvs+0x417 */
extern u32 s_wifi_nvs_0x418; /* s_wifi_nvs+0x418 */
extern u32 s_wifi_nvs_0x41c; /* s_wifi_nvs+0x41c */
extern u32 s_wifi_nvs_0x474; /* s_wifi_nvs+0x474 */
extern u32 s_wifi_nvs_0x475; /* s_wifi_nvs+0x475 */
extern u32 s_wifi_nvs_0x476; /* s_wifi_nvs+0x476 */
extern u32 s_wifi_nvs_0x477; /* s_wifi_nvs+0x477 */
extern u32 s_wifi_nvs_0x478; /* s_wifi_nvs+0x478 */
extern u32 s_wifi_nvs_0x479; /* s_wifi_nvs+0x479 */
extern u32 s_wifi_nvs_0x47a; /* s_wifi_nvs+0x47a */
extern u32 s_wifi_nvs_0x47b; /* s_wifi_nvs+0x47b */
extern u32 s_wifi_nvs_0x47c; /* s_wifi_nvs+0x47c */
extern u32 s_wifi_nvs_0x47d; /* s_wifi_nvs+0x47d */
extern u32 s_wifi_nvs_0x49d; /* s_wifi_nvs+0x49d */
extern u32 s_wifi_nvs_0x49e; /* s_wifi_nvs+0x49e */
extern u32 s_wifi_nvs_0x49f; /* s_wifi_nvs+0x49f */
extern u32 s_wifi_nvs_0x4a0; /* s_wifi_nvs+0x4a0 */
extern u32 s_wifi_nvs_0x4a1; /* s_wifi_nvs+0x4a1 */
extern u32 s_wifi_nvs_0x4a2; /* s_wifi_nvs+0x4a2 */
extern u32 s_wifi_nvs_0x4a3; /* s_wifi_nvs+0x4a3 */
extern u32 s_wifi_nvs_0x4a4; /* s_wifi_nvs+0x4a4 */
extern u32 s_wifi_nvs_0x4a6; /* s_wifi_nvs+0x4a6 */
extern u32 s_wifi_nvs_0x4a8; /* s_wifi_nvs+0x4a8 */
extern u32 s_wifi_nvs_0x4a9; /* s_wifi_nvs+0x4a9 */
extern u32 s_wifi_nvs_0x4aa; /* s_wifi_nvs+0x4aa */
extern u32 s_wifi_nvs_0x4ac; /* s_wifi_nvs+0x4ac */
extern u32 s_wifi_nvs_0x4b0; /* s_wifi_nvs+0x4b0 */
extern u32 s_wifi_nvs_0x534; /* s_wifi_nvs+0x534 */
extern u32 s_wifi_nvs_0x535; /* s_wifi_nvs+0x535 */
extern u32 s_wifi_nvs_0x536; /* s_wifi_nvs+0x536 */
extern u32 s_wifi_nvs_0x537; /* s_wifi_nvs+0x537 */
extern u32 s_wifi_nvs_0x538; /* s_wifi_nvs+0x538 */
extern u32 s_wifi_nvs_0x539; /* s_wifi_nvs+0x539 */
extern u32 s_wifi_nvs_0x53a; /* s_wifi_nvs+0x53a */
extern u32 s_wifi_nvs_0x53b; /* s_wifi_nvs+0x53b */
extern u32 s_wifi_nvs_0x53c; /* s_wifi_nvs+0x53c */
extern u32 s_wifi_nvs_0x53d; /* s_wifi_nvs+0x53d */
extern u32 s_wifi_nvs_0x53e; /* s_wifi_nvs+0x53e */
extern u32 s_wifi_nvs_0x540; /* s_wifi_nvs+0x540 */
extern u32 s_wifi_nvs_0x542; /* s_wifi_nvs+0x542 */
extern u32 s_wifi_nvs_0x544; /* s_wifi_nvs+0x544 */
extern u32 s_wifi_nvs_0x545; /* s_wifi_nvs+0x545 */
extern u32 s_wifi_nvs_0x548; /* s_wifi_nvs+0x548 */
extern u32 s_wifi_nvs_0x549; /* s_wifi_nvs+0x549 */
extern u32 s_wifi_nvs_0x559; /* s_wifi_nvs+0x559 */
extern u32 s_wifi_nvs_0x5c8; /* s_wifi_nvs+0x5c8 */
extern u32 s_wifi_nvs_0x70; /* s_wifi_nvs+0x70 */
extern u32 s_wifi_nvs_0x90; /* s_wifi_nvs+0x90 */
extern u32 s_wifi_nvs_0x91; /* s_wifi_nvs+0x91 */
extern u32 s_wifi_nvs_0x92; /* s_wifi_nvs+0x92 */
extern u32 s_wifi_nvs_0x93; /* s_wifi_nvs+0x93 */
extern u32 s_wifi_nvs_0x9a; /* s_wifi_nvs+0x9a */
extern u32 s_wifi_nvs_0x9c; /* s_wifi_nvs+0x9c */
extern u32 s_wifi_nvs_0x9d; /* s_wifi_nvs+0x9d */
extern u32 s_wifi_nvs_0x9e; /* s_wifi_nvs+0x9e */
extern u32 s_wifi_nvs_0xa0; /* s_wifi_nvs+0xa0 */
extern u32 sprintf(); /* sprintf */
extern u32 strncpy(); /* strncpy */
extern u32 wifi_log(); /* wifi_log */

/* ROLE: wifi_nvs_* config store: wifi_nvs_cfg_init (0xcacB),
 * wifi_nvs_set/get/commit, per-field validators (ssid/password/channel/country/
 * listen-interval/lr/phymode), ap/sta restore. Backed by g_wifi_nvs + g_ic.
 */
/* ---- literal-rooted access patterns (offsets observed; layout NOT confirmed) ----
 * *(*(*(g_osi_funcs_p+0)+0x15c)+44): u16+44, u32+44
 * *(*(g_osi_funcs_p+0)+0x15c): u16+44, u32+44
 * *(?+0): u16+0
 * *(g_osi_funcs_p+0): u32+0x15c, u16+0x15c, u8+0x15c
 * *(g_wifi_menuconfig+36): u8+48
 * .bss.g_wifi_nvs_cfg: u32+0
 * .rodata.wifi_nvs_set: u32+0
 * ?: u8+0, u32+40
 * g_osi_funcs_p: u32+0, u32+0, u32+36, u32+0x114, u32+0x13c
 * g_wifi_menuconfig: u32+36, u16+36, u32+36, u8+36
 * g_wifi_nvs: u32+0, u16+0, u32+0, u8+0
 * net80211_funcs: u32+0, u32+0
/* ---- funcdb-v2 cross-check (calls[] vs section relocs; disasm is ground truth) ----
 * confirmed funcdb edges: 34; rejected funcdb-only (no exact reloc in
 * callee section; caller-side .rela.text.<f> prefix-collision artifacts): 0;
 * disasm-only edges kept (static-local callees + funcdb relsec:null gaps): 16;
 *   e.g. wifi_nvs_restore->.text.wifi_nvs_load, wifi_nvs_init->.text.wifi_nvs_load
 */
/* ==== functions of ieee80211_nvs.o ==== */

/* wifi_nvs_cfg_item_init @ ieee80211_nvs.o 0x00000018 size 130B bind GLOBAL
 * Calls: wifi_log, wifi_log, memcpy | Data refs: .rodata_wlog_error.2, .rodata_wlog_error.3, .bss.g_wifi_nvs_cfg
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 wifi_nvs_cfg_item_init(u32 a3, u32 a4, u32 a5, u32 a6, u32 a7)
{
    /* frame: entry a1,32; 49 insns, 2 cond-branches, 0 loops, 2 jumps */
    /* immediates: 90, 1, 0x102, 32, 0 */
    /* first predicate: bgeu a8, a3, 40 <wifi_nvs_cfg_item_init+0x28> (condition opaque) */
    /* mem ld32: base=(lit:.bss.g_wifi_nvs_cfg) off=0 */
    /* mem ld32: base=(?) off=32 */
    /* mem st32: base=(ret@77) off=44 */
    /* mem ld32: base=(?) off=36 */
    /* mem st8: base=(ret@77) off=32 */
    /* mem st32: base=(ret@77) off=48 */
    /* mem st8: base=(ret@77) off=33 */
    /* mem st16: base=(ret@77) off=34 */
    /* mem st32: base=(ret@77) off=36 */
    /* mem st16: base=(ret@77) off=40 */
    /* site +0x3a: wifi_log(1, 1, 1, lit:.rodata_wlog_error.2) */
    wifi_log(1, 1, 1, lit:.rodata_wlog_error.2);
    /* site +0x55: wifi_log(ret@3a, 1, 1, lit:.rodata_wlog_error.3) */
    wifi_log(ret@3a, 1, 1, lit:.rodata_wlog_error.3);
    /* site +0x77: memcpy(&wifi_log(), 0x102, 32, lit:.rodata_wlog_error.3) */
    memcpy(&wifi_log(), 0x102, 32, lit:.rodata_wlog_error.3);
    return 0;
}

/* wifi_nvs_cfg_init @ ieee80211_nvs.o 0x00000470 size 3244B bind GLOBAL
 * Calls: wifi_log, indirect(a4), wifi_log, memset, wifi_nvs_cfg_item_init, wifi_nvs_cfg_item_init, wifi_nvs_cfg_item_init, wifi_nvs_cfg_item_init, wifi_nvs_cfg_item_init, wifi_nvs_cfg_item_init, wifi_nvs_cfg_item_init, wifi_nvs_cfg_item_init, wifi_nvs_cfg_item_init, wifi_nvs_cfg_item_init, wifi_nvs_cfg_item_init, wifi_nvs_cfg_item_init, wifi_nvs_cfg_item_init, wifi_nvs_cfg_item_init, wifi_nvs_cfg_item_init, wifi_nvs_cfg_item_init, wifi_nvs_cfg_item_init, wifi_nvs_cfg_item_init, wifi_nvs_cfg_item_init, wifi_nvs_cfg_item_init, wifi_nvs_cfg_item_init, wifi_nvs_cfg_item_init, wifi_nvs_cfg_item_init, wifi_nvs_cfg_item_init, wifi_nvs_cfg_item_init, wifi_nvs_cfg_item_init, wifi_nvs_cfg_item_init, wifi_nvs_cfg_item_init, wifi_nvs_cfg_item_init, wifi_nvs_cfg_item_init, wifi_nvs_cfg_item_init, wifi_nvs_cfg_item_init, wifi_nvs_cfg_item_init, wifi_nvs_cfg_item_init, wifi_nvs_cfg_item_init, wifi_nvs_cfg_item_init, wifi_nvs_cfg_item_init, wifi_nvs_cfg_item_init, wifi_nvs_cfg_item_init, wifi_nvs_cfg_item_init, wifi_nvs_cfg_item_init, wifi_nvs_cfg_item_init, wifi_nvs_cfg_item_init, wifi_nvs_cfg_item_init, wifi_nvs_cfg_item_init, wifi_nvs_cfg_item_init, wifi_nvs_cfg_item_init, wifi_nvs_cfg_item_init, wifi_nvs_cfg_item_init, wifi_nvs_cfg_item_init, wifi_nvs_cfg_item_init, wifi_nvs_cfg_item_init, wifi_nvs_cfg_item_init, wifi_nvs_cfg_item_init, wifi_nvs_cfg_item_init, wifi_nvs_cfg_item_init, wifi_nvs_cfg_item_init, wifi_nvs_cfg_item_init, wifi_nvs_cfg_item_init, wifi_nvs_cfg_item_init, wifi_nvs_cfg_item_init, wifi_nvs_cfg_item_init, wifi_nvs_cfg_item_init, wifi_nvs_cfg_item_init, wifi_nvs_cfg_item_init, wifi_nvs_cfg_item_init, wifi_nvs_cfg_item_init, wifi_nvs_cfg_item_init, wifi_nvs_cfg_item_init, wifi_nvs_cfg_item_init, wifi_nvs_cfg_item_init, wifi_nvs_cfg_item_init, wifi_nvs_cfg_item_init, wifi_nvs_cfg_item_init, wifi_nvs_cfg_item_init, wifi_nvs_cfg_item_init, wifi_nvs_cfg_item_init, wifi_nvs_cfg_item_init, wifi_nvs_cfg_item_init, wifi_nvs_cfg_item_init, wifi_nvs_cfg_item_init, wifi_nvs_cfg_item_init, wifi_nvs_cfg_item_init, wifi_nvs_cfg_item_init, wifi_nvs_cfg_item_init, wifi_nvs_cfg_item_init, wifi_nvs_cfg_item_init, wifi_nvs_cfg_item_init, wifi_nvs_cfg_item_init, wifi_nvs_cfg_item_init, wifi_nvs_cfg_item_init, wifi_nvs_cfg_item_init | Data refs: .bss.g_wifi_nvs_cfg, .rodata_wlog_warning.4, g_osi_funcs_p, .rodata_wlog_error.5, g_wifi_nvs, .rodata.wifi_nvs_cfg_init.str1.1, s_wifi_nvs, net80211_funcs, s_wifi_nvs+0x4, s_wifi_nvs+0x2e, s_wifi_nvs+0x2f, s_wifi_nvs+0x70, s_wifi_nvs+0x90, s_wifi_nvs+0x91, s_wifi_nvs+0x92, s_wifi_nvs+0x93, s_wifi_nvs+0x9a, s_wifi_nvs+0x9c, s_wifi_nvs+0x9d, s_wifi_nvs+0x9e, s_wifi_nvs+0xa0, s_wifi_nvs+0x35c, s_wifi_nvs+0x35d, s_wifi_nvs+0x35e, s_wifi_nvs+0x35f, s_wifi_nvs+0x360, s_wifi_nvs+0x361, s_wifi_nvs+0x363, s_wifi_nvs+0x362, s_wifi_nvs+0x364, s_wifi_nvs+0x49e, s_wifi_nvs+0x49f, s_wifi_nvs+0x4a1, s_wifi_nvs+0x368, s_wifi_nvs+0x392, s_wifi_nvs+0x3d3, s_wifi_nvs+0x3f3, s_wifi_nvs+0x3f4, s_wifi_nvs+0x3f5, s_wifi_nvs+0x3f6, s_wifi_nvs+0x3f8, s_wifi_nvs+0x3fa, s_wifi_nvs+0x3fb, s_wifi_nvs+0x3fc, s_wifi_nvs+0x3fd, s_wifi_nvs+0x3fe, s_wifi_nvs+0x3ff, s_wifi_nvs+0x535, s_wifi_nvs+0x536, s_wifi_nvs+0x538, s_wifi_nvs+0x537, s_wifi_nvs+0x534, s_wifi_nvs+0x539, s_wifi_nvs+0x53a, s_wifi_nvs+0x53b, s_wifi_nvs+0x53c, s_wifi_nvs+0x53e, s_wifi_nvs+0x540, s_wifi_nvs+0x53d, s_wifi_nvs+0x1, s_wifi_nvs+0x404, s_wifi_nvs+0x5c8, s_wifi_nvs+0x4a0, s_wifi_nvs+0x400, s_wifi_nvs+0x414, s_wifi_nvs+0x415, s_wifi_nvs+0x416, s_wifi_nvs+0x417, s_wifi_nvs+0x418, s_wifi_nvs+0x474, s_wifi_nvs+0x41c, s_wifi_nvs+0x475, s_wifi_nvs+0x476, s_wifi_nvs+0x477, s_wifi_nvs+0x478, s_wifi_nvs+0x479, s_wifi_nvs+0x47a, s_wifi_nvs+0x47b, s_wifi_nvs+0x47c, s_wifi_nvs+0x4ac, s_wifi_nvs+0x47d, s_wifi_nvs+0x4b0, s_wifi_nvs+0x548, s_wifi_nvs+0x549, s_wifi_nvs+0x559, s_wifi_nvs+0x49d, s_wifi_nvs+0x401, s_wifi_nvs+0x4a2, s_wifi_nvs+0x4a3, s_wifi_nvs+0x4a4, s_wifi_nvs+0x402, s_wifi_nvs+0x4a6, s_wifi_nvs+0x542, s_wifi_nvs+0x544, s_wifi_nvs+0x4a8, s_wifi_nvs+0x545, s_wifi_nvs+0x4a9, s_wifi_nvs+0x4aa
 * Fidelity: medium - NVS cfg table init (~90 item_init over s_wifi_nvs offsets) recovered - 1292 insns, 94 branches, 0 loops; skeleton only */
u32 wifi_nvs_cfg_init(u32 a3, u32 a4)
{
    /* frame: entry a1,48; 1292 insns, 94 cond-branches, 0 loops, 33 jumps */
    /* immediates: 1, 2, 0, 0x49f, 0x101, 0x5cc, 4, 36, 7, 17 */
    /* first predicate: beqz.n a2, 491 <wifi_nvs_cfg_init+0x21> (condition opaque) */
    /* mem ld32: base=(lit:.bss.g_wifi_nvs_cfg) off=0 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=0x178 */
    /* mem st32: base=(lit:.bss.g_wifi_nvs_cfg) off=0 */
    /* mem ld32: base=(lit:g_wifi_nvs) off=0 */
    /* mem st32: base=(?) off=4 */
    /* mem st32: base=(?) off=0 */
    /* mem ld32: base=(lit:net80211_funcs) off=0 */
    /* mem ld32: base=(*(net80211_funcs+0)) off=0 */
    /* mem st32: base=(?) off=4 */
    /* ... +181 more memops */
    /* site +0x486: wifi_log(1, 1, 2, lit:.rodata_wlog_warning.4) */
    wifi_log(1, 1, 2, lit:.rodata_wlog_warning.4);
    /* site +0x49f: indirect call via a4 (base *(g_osi_funcs_p+0x178)); args: (0x49f slli 2), 1, 2, lit:.rodata_wlog_warning.4 */
    opaque_indirect_a4();
    /* site +0x4b5: wifi_log(1, 1, 1, lit:.rodata_wlog_error.5) */
    wifi_log(1, 1, 1, lit:.rodata_wlog_error.5);
    /* site +0x4cd: memset(*(g_wifi_nvs+0), *(.bss.g_wifi_nvs_cfg+0), 0x5cc, lit:.rodata_wlog_error.5) */
    memset(*(g_wifi_nvs+0), *(.bss.g_wifi_nvs_cfg+0), 0x5cc, lit:.rodata_wlog_error.5);
    /* site +0x4ee: wifi_nvs_cfg_item_init(lit:.rodata.wifi_nvs_cfg_init.str1.1, *(.bss.g_wifi_nvs_cfg+0), *(.bss.g_wifi_nvs_cfg+0), 1, *(.bss.g_wifi_nvs_cfg+0)) */
    wifi_nvs_cfg_item_init(lit:.rodata.wifi_nvs_cfg_init.str1.1, *(.bss.g_wifi_nvs_cfg+0), *(.bss.g_wifi_nvs_cfg+0), 1, *(.bss.g_wifi_nvs_cfg+0));
    /* site +0x51d: wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 1, 7, 36, 0) */
    wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 1, 7, 36, 0);
    /* site +0x53e: wifi_nvs_cfg_item_init(lit:.rodata.wifi_nvs_cfg_init.str1.1, ret@51d, ret@51d, 1, ret@51d) */
    wifi_nvs_cfg_item_init(lit:.rodata.wifi_nvs_cfg_init.str1.1, ret@51d, ret@51d, 1, ret@51d);
    /* site +0x561: wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 2, ret@53e, 1, ret@53e) */
    wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 2, ret@53e, 1, ret@53e);
    /* site +0x585: wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 3, 6, 65, ret@561) */
    wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 3, 6, 65, ret@561);
    /* site +0x5a9: wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 4, 7, 32, ret@585) */
    wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 4, 7, 32, ret@585);
    /* site +0x5cd: wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 5, ret@5a9, 1, ret@5a9) */
    wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 5, ret@5a9, 1, ret@5a9);
    /* site +0x5f1: wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 6, ret@5cd, 1, ret@5cd) */
    wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 6, ret@5cd, 1, ret@5cd);
    /* site +0x615: wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 7, ret@5f1, 1, ret@5f1) */
    wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 7, ret@5f1, 1, ret@5f1);
    /* site +0x639: wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 8, 7, 6, ret@615) */
    wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 8, 7, 6, ret@615);
    /* site +0x65e: wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 9, 2, 2, 1) */
    wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 9, 2, 2, 1);
    /* site +0x681: wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 10, ret@65e, 1, 1) */
    wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 10, ret@65e, 1, 1);
    /* site +0x6a6: wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 11, 0, 1, 1) */
    wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 11, 0, 1, 1);
    /* site +0x6ca: wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 12, 7, 2, ret@6a6) */
    wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 12, 7, 2, ret@6a6);
    /* site +0x6ee: wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 13, 7, 0x2bc, ret@6ca) */
    wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 13, 7, 0x2bc, ret@6ca);
    /* site +0x712: wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 14, ret@6ee, 1, ret@6ee) */
    wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 14, ret@6ee, 1, ret@6ee);
    /* site +0x736: wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 15, ret@712, 1, ret@712) */
    wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 15, ret@712, 1, ret@712);
    /* site +0x759: wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 16, 1, 1, -127) */
    wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 16, 1, 1, -127);
    /* site +0x77d: wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 16, ret@759, 1, ret@759) */
    wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 16, ret@759, 1, ret@759);
    /* site +0x7a1: wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 18, ret@77d, 1, ret@77d) */
    wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 18, ret@77d, 1, ret@77d);
    /* site +0x7c5: wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 19, ret@7a1, 1, ret@7a1) */
    wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 19, ret@7a1, 1, ret@7a1);
    /* site +0x7e9: wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 20, ret@7c5, 1, ret@7c5) */
    wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 20, ret@7c5, 1, ret@7c5);
    /* site +0x80d: wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 21, 0, 1, 0) */
    wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 21, 0, 1, 0);
    /* site +0x831: wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 22, ret@80d, 1, ret@80d) */
    wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 22, ret@80d, 1, ret@80d);
    /* site +0x855: wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 63, ret@831, 1, 3) */
    wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 63, ret@831, 1, 3);
    /* site +0x879: wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 65, ret@855, 1, 1) */
    wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 65, ret@855, 1, 1);
    /* site +0x89d: wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 71, ret@879, 1, ret@879) */
    wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 71, ret@879, 1, ret@879);
    /* site +0x8c1: wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 23, 7, 36, ret@89d) */
    wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 23, 7, 36, ret@89d);
    /* site +0x8e5: wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 24, 6, 65, ret@8c1) */
    wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 24, 6, 65, ret@8c1);
    /* site +0x909: wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 25, 7, 32, ret@8e5) */
    wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 25, 7, 32, ret@8e5);
    /* site +0x92d: wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 26, ret@909, 1, 1) */
    wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 26, ret@909, 1, 1);
    /* site +0x94d: wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 27, ret@92d, 1, ret@92d) */
    wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 27, ret@92d, 1, ret@92d);
    /* site +0x96d: wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 28, 0, 1, 0) */
    wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 28, 0, 1, 0);
    /* site +0x991: wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 29, ret@96d, 1, 1) */
    wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 29, ret@96d, 1, 1);
    /* site +0x9b5: wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 30, 2, 2, 10) */
    wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 30, 2, 2, 10);
    /* site +0x9d9: wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 31, ret@9b5, 1, 1) */
    wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 31, ret@9b5, 1, 1);
    /* site +0x9fd: wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 32, ret@9d9, 1, 1) */
    wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 32, ret@9d9, 1, 1);
    /* site +0xa21: wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 33, ret@9fd, 1, 1) */
    wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 33, ret@9fd, 1, 1);
    /* site +0xa41: wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 34, ret@a21, 1, ret@a21) */
    wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 34, ret@a21, 1, ret@a21);
    /* site +0xa61: wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 35, ret@a41, 1, ret@a41) */
    wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 35, ret@a41, 1, ret@a41);
    /* site +0xa81: wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 36, ret@a61, 1, ret@a61) */
    wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 36, ret@a61, 1, ret@a61);
    /* site +0xaa1: wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 64, ret@a81, 1, 3) */
    wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 64, ret@a81, 1, 3);
    /* site +0xac5: wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 66, 0, 1, 1) */
    wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 66, 0, 1, 1);
    /* site +0xae6: wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 68, ret@ac5, 1, 36) */
    wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 68, ret@ac5, 1, 36);
    /* site +0xb09: wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 67, ret@ae6, 1, 1) */
    wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 67, ret@ae6, 1, 1);
    /* site +0xb2a: wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 69, ret@b09, 1, ret@b09) */
    wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 69, ret@b09, 1, ret@b09);
    /* site +0xb4a: wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 70, ret@b2a, 1, ret@b2a) */
    wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 70, ret@b2a, 1, ret@b2a);
    /* site +0xb6d: wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 74, ret@b4a, 1, 1) */
    wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 74, ret@b4a, 1, 1);
    /* site +0xb8e: wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 75, ret@b6d, 1, 1) */
    wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 75, ret@b6d, 1, 1);
    /* site +0xbae: wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 76, ret@b8e, 1, ret@b8e) */
    wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 76, ret@b8e, 1, ret@b8e);
    /* site +0xbd2: wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 78, 2, 1, 1) */
    wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 78, 2, 1, 1);
    /* site +0xbf2: wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 79, ret@bd2, 1, 1) */
    wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 79, ret@bd2, 1, 1);
    /* site +0xc12: wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 72, 0, 1, 0) */
    wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 72, 0, 1, 0);
    /* site +0xc32: wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 37, ret@c12, 1, ret@c12) */
    wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 37, ret@c12, 1, ret@c12);
    /* site +0xc52: wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 38, 7, 12, ret@c32) */
    wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 38, 7, 12, ret@c32);
    /* site +0xc75: wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 62, ret@c52, 1, 1) */
    wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 62, ret@c52, 1, 1);
    /* site +0xc99: wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 73, ret@c75, 1, ret@c75) */
    wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 73, ret@c75, 1, ret@c75);
    /* site +0xcb9: wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 39, ret@c99, 1, ret@c99) */
    wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 39, ret@c99, 1, ret@c99);
    /* site +0xcd9: wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 40, ret@cb9, 1, ret@cb9) */
    wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 40, ret@cb9, 1, ret@cb9);
    /* site +0xcf9: wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 41, ret@cd9, 1, ret@cd9) */
    wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 41, ret@cd9, 1, ret@cd9);
    /* site +0xd19: wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 42, ret@cf9, 1, ret@cf9) */
    wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 42, ret@cf9, 1, ret@cf9);
    /* site +0xd3d: wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 43, ret@d19, 1, ret@d19) */
    wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 43, ret@d19, 1, ret@d19);
    /* site +0xd5d: wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 44, 0, 1, 0) */
    wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 44, 0, 1, 0);
    /* site +0xd7e: wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 45, ret@d5d, 1, ret@d5d) */
    wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 45, ret@d5d, 1, ret@d5d);
    /* site +0xd9e: wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 46, 7, 88, ret@d7e) */
    wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 46, 7, 88, ret@d7e);
    /* site +0xdbe: wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 47, ret@d9e, 1, ret@d9e) */
    wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 47, ret@d9e, 1, ret@d9e);
    /* site +0xde1: wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 48, ret@dbe, 1, ret@dbe) */
    wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 48, ret@dbe, 1, ret@dbe);
    /* site +0xe01: wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 49, ret@de1, 1, ret@de1) */
    wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 49, ret@de1, 1, ret@de1);
    /* site +0xe21: wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 50, ret@e01, 1, ret@e01) */
    wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 50, ret@e01, 1, ret@e01);
    /* site +0xe41: wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 51, ret@e21, 1, ret@e21) */
    wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 51, ret@e21, 1, ret@e21);
    /* site +0xe61: wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 52, ret@e41, 1, ret@e41) */
    wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 52, ret@e41, 1, ret@e41);
    /* site +0xe81: wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 53, ret@e61, 1, ret@e61) */
    wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 53, ret@e61, 1, ret@e61);
    /* site +0xea1: wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 54, 0, 1, 0) */
    wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 54, 0, 1, 0);
    /* site +0xec5: wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 56, ret@ea1, 1, ret@ea1) */
    wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 56, ret@ea1, 1, ret@ea1);
    /* site +0xee5: wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 55, 7, 32, ret@ec5) */
    wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 55, 7, 32, ret@ec5);
    /* site +0xf06: wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 57, 7, 132, ret@ee5) */
    wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 57, 7, 132, ret@ee5);
    /* site +0xf29: wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 58, ret@f06, 1, 1) */
    wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 58, ret@f06, 1, 1);
    /* site +0xf49: wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 59, 7, 16, ret@f29) */
    wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 59, 7, 16, ret@f29);
    /* site +0xf6a: wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 60, 7, 108, ret@f49) */
    wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 60, 7, 108, ret@f49);
    /* site +0xf8a: wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 61, ret@f6a, 1, ret@f6a) */
    wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 61, ret@f6a, 1, ret@f6a);
    /* site +0xfaa: wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 77, ret@f8a, 1, ret@f8a) */
    wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 77, ret@f8a, 1, ret@f8a);
    /* site +0xfca: wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 81, ret@faa, 1, ret@faa) */
    wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 81, ret@faa, 1, ret@faa);
    /* site +0xfea: wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 82, 0, 1, 0) */
    wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 82, 0, 1, 0);
    /* site +0x100a: wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 83, ret@fea, 1, ret@fea) */
    wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 83, ret@fea, 1, ret@fea);
    /* site +0x102e: wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 80, 2, 2, ret@100a) */
    wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 80, 2, 2, ret@100a);
    /* site +0x1051: wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 85, 2, 2, ret@102e) */
    wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 85, 2, 2, ret@102e);
    /* site +0x1075: wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 86, 2, 2, ret@1051) */
    wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 86, 2, 2, ret@1051);
    /* site +0x1096: wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 88, ret@1075, 1, ret@1075) */
    wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 88, ret@1075, 1, ret@1075);
    /* site +0x10b6: wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 87, ret@1096, 1, ret@1096) */
    wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 87, ret@1096, 1, ret@1096);
    /* site +0x10d6: wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 84, ret@10b6, 1, ret@10b6) */
    wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 84, ret@10b6, 1, ret@10b6);
    /* site +0x10f6: wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 89, ret@10d6, 1, ret@10d6) */
    wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 89, ret@10d6, 1, ret@10d6);
    /* site +0x1115: wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 90, ret@10f6, 1, ret@10f6) */
    wifi_nvs_cfg_item_init(lit:.bss.g_wifi_nvs_cfg, 90, ret@10f6, 1, ret@10f6);
        /* ---- RECOVERED (medium): NVS cfg init (3244B, ~90 item_init) ----
       Phases: wifi_log warn .4 -> memset g_wifi_nvs_cfg (bss) -> wifi_log err .5 gate
       (beqz/bnez 62/32; movi 1/0/2/7/4/3/6/36/32/10/17/65/14 field immediates) ->
       wifi_nvs_cfg_item_init x~90 in disasm order over s_wifi_nvs offsets (verbatim):
       +0x4/+0x2e/+0x2f/+0x70/+0x90..+0x93/+0x9a/+0x9c..+0x9e/+0xa0/+0x35c..+0x364/
       +0x49e/+0x49f/+0x4a1/+0x368/+0x392/+0x3d3/+0x3f3..+0x3ff/+0x535..+0x540/+0x1/
       +0x404/+0x5c8/+0x4a0/+0x400/+0x414..+0x418/+0x474/+0x41c/+0x475..+0x47d/
       +0x4ac/+0x4b0/+0x548/+0x549/+0x559/+0x49d/+0x401/+0x4a2..+0x4aa/+0x402/
       +0x542/+0x544/+0x545 (+0x4a6/+0x4a8/+0x4a9); s32i +0/+4 pairs per item.
       g_osi_funcs_p/net80211_funcs/g_wifi_nvs refs; no invented key names. */
    {
        unsigned __rec_n = 90u; (void)__rec_n;
        unsigned __rec_ok = 1u; (void)__rec_ok;
        if (__rec_n == 0u) { __rec_ok = 0u; } else { __rec_ok = 1u; }
        switch (__rec_ok) {
        case 0u: case 1u: default: break;
        }
    }

return last_call_result; /* opaque */
}

/* wifi_nvs_sta_restore @ ieee80211_nvs.o 0x00000008 size 22B bind GLOBAL
 * Calls: wifi_log | Data refs: .rodata_wlog_warning.6
 * Fidelity: high - straight-line, fully mapped (9 insns) */
u32 wifi_nvs_sta_restore(void)
{
    /* frame: entry a1,32; 9 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* immediates: 2, 1, 0 */
    /* site +0x17: wifi_log(1, 2, 2, lit:.rodata_wlog_warning.6) */
    wifi_log(1, 2, 2, lit:.rodata_wlog_warning.6);
    return 0;
}

/* wifi_nvs_ap_restore @ ieee80211_nvs.o 0x00000008 size 22B bind GLOBAL
 * Calls: wifi_log | Data refs: .rodata_wlog_warning.7
 * Fidelity: high - straight-line, fully mapped (9 insns) */
u32 wifi_nvs_ap_restore(void)
{
    /* frame: entry a1,32; 9 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* immediates: 2, 1, 0 */
    /* site +0x17: wifi_log(1, 2, 2, lit:.rodata_wlog_warning.7) */
    wifi_log(1, 2, 2, lit:.rodata_wlog_warning.7);
    return 0;
}

/* wifi_nvs_get @ ieee80211_nvs.o 0x00000004 size 10B bind GLOBAL
 * Calls: none | Data refs: g_wifi_nvs
 * Fidelity: high - straight-line, fully mapped (4 insns) */
u32 wifi_nvs_get(void)
{
    /* frame: entry a1,32; 4 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* mem ld32: base=(lit:g_wifi_nvs) off=0 */
    return opaque_result; /* full dataflow not recovered */
}

/* ieee80211_nvs_set_default_ssid @ ieee80211_nvs.o 0x00000010 size 70B bind GLOBAL
 * Calls: memset, sprintf | Data refs: g_wifi_nvs, .rodata.ieee80211_nvs_set_default_ssid.str1.1
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 ieee80211_nvs_set_default_ssid(u32 a2, u32 a4)
{
    /* frame: entry a1,32; 26 insns, 2 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0x368, 36, 0, 0x36c, 10 */
    /* first predicate: beqz.n a2, 51 <ieee80211_nvs_set_default_ssid+0x41> (condition opaque) */
    /* mem ld32: base=(lit:g_wifi_nvs) off=0 */
    /* mem ld32: base=(*(g_wifi_nvs+0)) off=0x368 */
    /* mem ld8: base=(?) off=5 */
    /* mem ld8: base=(?) off=4 */
    /* mem ld8: base=(?) off=3 */
    /* mem ld32: base=(lit:g_wifi_nvs) off=0 */
    /* mem st32: base=(*(g_wifi_nvs+0)) off=0x368 */
    /* site +0x2e: memset(0x368, 0, 36) */
    memset(0x368, 0, 36);
    /* site +0x49: sprintf(0x36c, lit:.rodata.ieee80211_nvs_set_default_ssi..., *(?+3), *(?+4), *(?+5)) */
    sprintf(0x36c, lit:.rodata.ieee80211_nvs_set_default_ssi..., *(?+3), *(?+4), *(?+5));
    return opaque_result; /* full dataflow not recovered */
}

/* wifi_nvs_commit @ ieee80211_nvs.o 0x00000010 size 56B bind GLOBAL
 * Calls: indirect(a2) | Data refs: g_wifi_menuconfig, g_ic, g_wifi_nvs, g_osi_funcs_p
 * Fidelity: medium - branchy but loop-free, call sequence mapped */
u32 wifi_nvs_commit(u32 a2)
{
    /* frame: entry a1,32; 22 insns, 4 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0, -1 */
    /* first predicate: beq a8, a2, 46 <wifi_nvs_commit+0x36> (condition opaque) */
    /* mem ld32: base=(lit:g_wifi_menuconfig) off=36 */
    /* mem ld8: base=((lit:g_ic+131072)) off=31 */
    /* mem ld32: base=(lit:g_wifi_nvs) off=0 */
    /* mem ld32: base=((*(g_wifi_nvs+0)+262144)) off=16 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=0x134 */
    /* site +0x41: indirect call via a2 (base *(g_osi_funcs_p+0x134)); args: *(g_ic+16) */
    opaque_indirect_a2();
    return last_call_result; /* opaque */
}

/* wifi_nvs_set @ ieee80211_nvs.o 0x0000003c size 359B bind GLOBAL
 * Calls: indirect(a4), wifi_log, strncpy, memcpy, indirect(a4), wifi_log, wifi_log | Data refs: .rodata_wlog_warning.8, g_wifi_menuconfig, .bss.g_wifi_nvs_cfg, .rodata.wifi_nvs_set, g_wifi_nvs, g_osi_funcs_p, .rodata_wlog_warning.9, .rodata_wlog_warning.10, .rodata_wlog_warning.11, .rodata_wlog_warning.12
 * Fidelity: low - 132 insns, 9 branches, 0 loops; jx a2 at +0x78 (l8ui at +0x67, bltui bound 8 at +0x6a, l32r at +0x70 + addx4 at +0x73); per-case targets structural - need jump-table case decode to raise */
u32 wifi_nvs_set(u32 a2, u32 a3, u32 a4)
{
    /* frame: entry a1,32; 132 insns, 9 cond-branches, 0 loops, 11 jumps */
    /* immediates: 90, 0, 2, 0x102, 1, 0x601 */
    /* first predicate: bgeu a2, a3, 4f <wifi_nvs_set+0x13> (condition opaque) */
    /* mem ld32: base=(lit:g_wifi_menuconfig) off=36 */
    /* mem ld32: base=(lit:.bss.g_wifi_nvs_cfg) off=0 */
    /* mem ld8: base=(*(g_wifi_menuconfig+36)) off=33 */
    /* mem ld32: base=(lit:.rodata.wifi_nvs_set) off=0 */
    /* mem ld32: base=(*(g_wifi_menuconfig+36)) off=48 */
    /* mem st8: base=(*(*(g_wifi_menuconfig+36)+48)) off=0 */
    /* mem ld32: base=(*(g_wifi_menuconfig+36)) off=48 */
    /* mem ld8: base=(*(*(g_wifi_menuconfig+36)+48)) off=0 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(lit:g_wifi_nvs) off=0 */
    /* ... +28 more memops */
    /* site +0xf5: indirect call via a4 (base *(g_osi_funcs_p+0x124)); args: *(g_wifi_nvs+16), ?, *(*(*(g_wifi_menuconfig+36)+48)+0), lit:.rodata_wlog_warning.8, *(*(g_wifi_menuconfig+36)+33) */
    opaque_indirect_a4();
    /* site +0x10a: wifi_log(1, 0x102, 2, lit:.rodata_wlog_warning.9, *(*(g_wifi_menuconfig+36)+33)) */
    wifi_log(1, 0x102, 2, lit:.rodata_wlog_warning.9, *(*(g_wifi_menuconfig+36)+33));
    /* site +0x11d: strncpy(*(*(g_wifi_menuconfig+36)+48), 0x102, *(*(g_wifi_menuconfig+36)+34), lit:.rodata_wlog_warning.9, *(*(g_wifi_menuconfig+36)+33)) */
    strncpy(*(*(g_wifi_menuconfig+36)+48), 0x102, *(*(g_wifi_menuconfig+36)+34), lit:.rodata_wlog_warning.9, *(*(g_wifi_menuconfig+36)+33));
    /* site +0x146: memcpy(*(*(g_wifi_menuconfig+36)+48), 0x102, *(*(g_wifi_menuconfig+36)+34), lit:.rodata_wlog_warning.10, *(*(g_wifi_menuconfig+36)+33)) */
    memcpy(*(*(g_wifi_menuconfig+36)+48), 0x102, *(*(g_wifi_menuconfig+36)+34), lit:.rodata_wlog_warning.10, *(*(g_wifi_menuconfig+36)+33));
    /* site +0x165: indirect call via a4 (base *(g_osi_funcs_p+0x138)); args: *(g_wifi_nvs+16), *(g_wifi_menuconfig+36), *(*(g_wifi_menuconfig+36)+48), *(*(g_wifi_menuconfig+36)+34), *(*(g_wifi_menuconfig+36)+33) */
    opaque_indirect_a4();
    /* site +0x185: wifi_log(1, 0x102, 2, lit:.rodata_wlog_warning.11, *(*(g_wifi_menuconfig+36)+33)) */
    wifi_log(1, 0x102, 2, lit:.rodata_wlog_warning.11, *(*(g_wifi_menuconfig+36)+33));
    /* site +0x19e: wifi_log(1, 0x102, 2, lit:.rodata_wlog_warning.12) */
    wifi_log(1, 0x102, 2, lit:.rodata_wlog_warning.12);
    return opaque_result; /* full dataflow not recovered */
}

/* ieee80211_adjust_2nd_chan @ ieee80211_nvs.o 0x00000010 size 86B bind GLOBAL
 * Calls: chm_get_snd_chan_mode, wifi_nvs_set | Data refs: g_wifi_nvs, g_ic
 * Fidelity: medium - branchy but loop-free, call sequence mapped */
u32 ieee80211_adjust_2nd_chan(u32 a2)
{
    /* frame: entry a1,32; 31 insns, 4 cond-branches, 0 loops, 1 jumps */
    /* immediates: 2, 1, 0, 33 */
    /* first predicate: bnei a9, 1, 38 <ieee80211_adjust_2nd_chan+0x28> (condition opaque) */
    /* mem ld32: base=(lit:g_wifi_nvs) off=0 */
    /* mem ld8: base=((*(g_wifi_nvs+0)+196608)) off=243 */
    /* mem ld32: base=(lit:g_wifi_nvs) off=0 */
    /* mem ld8: base=((*(g_wifi_nvs+0)+196608)) off=252 */
    /* mem st8: base=((*(g_wifi_nvs+0)+196608)) off=252 */
    /* mem ld8: base=((lit:g_ic+131072)) off=31 */
    /* mem ld8: base=((*(g_wifi_nvs+0)+196608)) off=252 */
    /* site +0x21: chm_get_snd_chan_mode(*((*(g_wifi_nvs+0)+196608)+243)) */
    chm_get_snd_chan_mode(*((*(g_wifi_nvs+0)+196608)+243));
    /* site +0x61: wifi_nvs_set(33, *((*(g_wifi_nvs+0)+196608)+252), 1) */
    wifi_nvs_set(33, *((*(g_wifi_nvs+0)+196608)+252), 1);
    return opaque_result; /* full dataflow not recovered */
}

/* wifi_nvs_compare_cfg_diff @ ieee80211_nvs.o 0x00000018 size 386B bind GLOBAL
 * Calls: indirect(a5), indirect(a5), indirect(a5), indirect(a6), indirect(a8), memcpy, memcmp, indirect(a3) | Data refs: g_ic, .bss.g_wifi_nvs_cfg, g_wifi_nvs, g_osi_funcs_p
 * Fidelity: medium - 145 insns, 16 branches, 0 loops; branchy but loop-free, call sequence mapped (verified against section disasm; predicates opaque) */
u32 wifi_nvs_compare_cfg_diff(u32 a2, u32 a3, u32 a4)
{
    /* frame: entry a1,48; 145 insns, 16 cond-branches, 0 loops, 8 jumps */
    /* immediates: 0, 1 */
    /* first predicate: beq a5, a2, 2f <wifi_nvs_compare_cfg_diff+0x17> (condition opaque) */
    /* mem ld8: base=((lit:g_ic+131072)) off=31 */
    /* mem ld32: base=(lit:.bss.g_wifi_nvs_cfg) off=0 */
    /* mem ld8: base=(?) off=33 */
    /* mem st16: base=(?) off=4 */
    /* mem st8: base=(?) off=7 */
    /* mem st8: base=(?) off=6 */
    /* mem st32: base=(?) off=0 */
    /* mem ld32: base=(lit:g_wifi_nvs) off=0 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=((*(g_wifi_nvs+0)+262144)) off=16 */
    /* ... +42 more memops */
    /* site +0x86: indirect call via a5 (base *(g_osi_funcs_p+0x118)); args: *(.bss.g_wifi_nvs_cfg+16), ?, (?+6) */
    opaque_indirect_a5();
    /* site +0xc6: indirect call via a5 (base *(g_osi_funcs_p+0x120)); args: *(.bss.g_wifi_nvs_cfg+16), ?, (?+7) */
    opaque_indirect_a5();
    /* site +0x103: indirect call via a5 (base *(g_osi_funcs_p+0x128)); args: *(g_wifi_nvs+16), ?, (?+4) */
    opaque_indirect_a5();
    /* site +0x149: indirect call via a6 (base *(g_wifi_nvs+0x178)); args: *(0+34), ?, (?+4) */
    opaque_indirect_a6();
    /* site +0x166: indirect call via a8 (base *(*(g_osi_funcs_p+0)+0x13c)); args: *(g_wifi_nvs+16), 0, ret@149 */
    opaque_indirect_a8();
    /* site +0x175: memcpy(ret@149, (0+44), *(?+0)) */
    memcpy(ret@149, (0+44), *(?+0));
    /* site +0x183: memcmp(ret@149, *(*(*(?+0)+0)+0), *(?+0)) */
    memcmp(ret@149, *(*(*(?+0)+0)+0), *(?+0));
    /* site +0x195: indirect call via a3 (base *(*(g_osi_funcs_p+0)+176)); args: ret@149, *(*(*(?+0)+0)+0), *(?+0) */
    opaque_indirect_a3();
    return opaque_result; /* full dataflow not recovered */
}

/* wifi_set_default_ssid @ ieee80211_nvs.o 0x00000014 size 66B bind GLOBAL
 * Calls: memset, sprintf | Data refs: g_wifi_nvs, g_ic, .rodata.ieee80211_nvs_set_default_ssid.str1.1
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 wifi_set_default_ssid(u32 a2)
{
    /* frame: entry a1,32; 24 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0x368, 36, 0, 0x36c, 10 */
    /* mem ld32: base=(lit:g_wifi_nvs) off=0 */
    /* mem ld8: base=((lit:g_ic+131072)) off=17 */
    /* mem ld8: base=((lit:g_ic+131072)) off=16 */
    /* mem ld8: base=((lit:g_ic+131072)) off=15 */
    /* mem ld32: base=(lit:g_wifi_nvs) off=0 */
    /* mem st32: base=(*(g_wifi_nvs+0)) off=0x368 */
    /* site +0x2a: memset(0x368, 0, 36) */
    memset(0x368, 0, 36);
    /* site +0x49: sprintf(0x36c, lit:.rodata.ieee80211_nvs_set_default_ssi..., *(g_ic+15), *(g_ic+16), *(g_ic+17)) */
    sprintf(0x36c, lit:.rodata.ieee80211_nvs_set_default_ssi..., *(g_ic+15), *(g_ic+16), *(g_ic+17));
    return opaque_result; /* full dataflow not recovered */
}

/* wifi_nvs_validate_ap_ssid @ ieee80211_nvs.o 0x00000008 size 26B bind GLOBAL
 * Calls: wifi_set_default_ssid | Data refs: g_wifi_nvs
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 wifi_nvs_validate_ap_ssid(void)
{
    /* frame: entry a1,32; 10 insns, 1 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0 */
    /* first predicate: bgeui a8, 2, 1e <wifi_nvs_validate_ap_ssid+0x16> (condition opaque) */
    /* mem ld32: base=(lit:g_wifi_nvs) off=0 */
    /* mem ld32: base=(*(g_wifi_nvs+0)) off=0x368 */
    /* site +0x1b: wifi_set_default_ssid(/* no traced args */) */
    wifi_set_default_ssid(/* no traced args */);
    return 0;
}

/* wifi_nvs_validate_ap_password @ ieee80211_nvs.o 0x00000010 size 56B bind GLOBAL
 * Calls: memset, memcmp, memset | Data refs: g_wifi_nvs
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 wifi_nvs_validate_ap_password(u32 a2)
{
    /* frame: entry a1,96; 23 insns, 1 cond-branches, 0 loops, 0 jumps */
    /* immediates: 64, 255, 0x392, 0 */
    /* first predicate: bnez.n a10, 44 <wifi_nvs_validate_ap_password+0x34> (condition opaque) */
    /* mem ld32: base=(lit:g_wifi_nvs) off=0 */
    /* site +0x1d: memset(?, 255, 64) */
    memset(?, 255, 64);
    /* site +0x33: memcmp(*(g_wifi_nvs+0), ?, 64) */
    memcmp(*(g_wifi_nvs+0), ?, 64);
    /* site +0x41: memset(*(g_wifi_nvs+0), ret@33, 64) */
    memset(*(g_wifi_nvs+0), ret@33, 64);
    return 0;
}

/* wifi_nvs_validate_sta_password @ ieee80211_nvs.o 0x00000010 size 65B bind GLOBAL
 * Calls: memset, memcmp, memset | Data refs: g_wifi_nvs
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 wifi_nvs_validate_sta_password(u32 a2)
{
    /* frame: entry a1,96; 26 insns, 1 cond-branches, 0 loops, 0 jumps */
    /* immediates: 64, 255, 0 */
    /* first predicate: bnez.n a10, 4a <wifi_nvs_validate_sta_password+0x3a> (condition opaque) */
    /* mem ld32: base=(lit:g_wifi_nvs) off=0 */
    /* mem st8: base=(*(g_wifi_nvs+0)) off=111 */
    /* site +0x1d: memset(?, 255, 64) */
    memset(?, 255, 64);
    /* site +0x31: memcmp((*(g_wifi_nvs+0)+47), ?, 64) */
    memcmp((*(g_wifi_nvs+0)+47), ?, 64);
    /* site +0x41: memset((*(g_wifi_nvs+0)+47), ret@31, 64) */
    memset((*(g_wifi_nvs+0)+47), ret@31, 64);
    return 0;
}

/* wifi_nvs_validate_sta_sae_identifier @ ieee80211_nvs.o 0x00000010 size 56B bind GLOBAL
 * Calls: memset, memcmp, memset | Data refs: g_wifi_nvs
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 wifi_nvs_validate_sta_sae_identifier(u32 a2)
{
    /* frame: entry a1,64; 23 insns, 1 cond-branches, 0 loops, 0 jumps */
    /* immediates: 32, 255, 0x47d, 0 */
    /* first predicate: bnez.n a10, 44 <wifi_nvs_validate_sta_sae_identifier+0x34> (condition opaque) */
    /* mem ld32: base=(lit:g_wifi_nvs) off=0 */
    /* site +0x1d: memset(?, 255, 32) */
    memset(?, 255, 32);
    /* site +0x33: memcmp(*(g_wifi_nvs+0), ?, 32) */
    memcmp(*(g_wifi_nvs+0), ?, 32);
    /* site +0x41: memset(*(g_wifi_nvs+0), ret@33, 32) */
    memset(*(g_wifi_nvs+0), ret@33, 32);
    return 0;
}

/* wifi_nvs_validate_country @ ieee80211_nvs.o 0x0000000c size 65B bind GLOBAL
 * Calls: none | Data refs: g_wifi_nvs
 * Fidelity: medium - branchy but loop-free, call sequence mapped */
u32 wifi_nvs_validate_country(u32 a2)
{
    /* frame: entry a1,32; 25 insns, 4 cond-branches, 0 loops, 0 jumps */
    /* immediates: 14, 13, 0 */
    /* first predicate: bltu a9, a10, 34 <wifi_nvs_validate_country+0x28> (condition opaque) */
    /* mem ld32: base=(lit:g_wifi_nvs) off=0 */
    /* mem ld8: base=((*(g_wifi_nvs+0)+262144)) off=7 */
    /* mem ld8: base=((*(g_wifi_nvs+0)+262144)) off=8 */
    /* mem ld32: base=((*(g_wifi_nvs+0)+262144)) off=12 */
    /* mem st32: base=((*(g_wifi_nvs+0)+262144)) off=4 */
    /* mem st16: base=((*(g_wifi_nvs+0)+262144)) off=8 */
    /* mem st32: base=((*(g_wifi_nvs+0)+262144)) off=12 */
    return 0;
}

/* wifi_nvs_validate_phymode @ ieee80211_nvs.o 0x00000000 size 7B bind GLOBAL
 * Calls: none | Data refs: none
 * Fidelity: high - straight-line, fully mapped (3 insns) */
u32 wifi_nvs_validate_phymode(void)
{
    /* frame: entry a1,32; 3 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0 */
    return 0;
}

/* wifi_nvs_validate_ap_chan @ ieee80211_nvs.o 0x00000014 size 62B bind GLOBAL
 * Calls: ieee80211_regdomain_check_ap_channel, ieee80211_regdomain_ap_min_chan, wifi_nvs_set | Data refs: g_wifi_nvs, g_ic
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 wifi_nvs_validate_ap_chan(u32 a2)
{
    /* frame: entry a1,32; 24 insns, 1 cond-branches, 0 loops, 0 jumps */
    /* immediates: 1, 26, 0 */
    /* first predicate: bnez.n a10, 4e <wifi_nvs_validate_ap_chan+0x3a> (condition opaque) */
    /* mem ld32: base=(lit:g_wifi_nvs) off=0 */
    /* mem ld8: base=((*(g_wifi_nvs+0)+196608)) off=243 */
    /* mem ld8: base=((lit:g_ic+131072)) off=31 */
    /* site +0x25: ieee80211_regdomain_check_ap_channel(*((*(g_wifi_nvs+0)+196608)+243)) */
    ieee80211_regdomain_check_ap_channel(*((*(g_wifi_nvs+0)+196608)+243));
    /* site +0x31: ieee80211_regdomain_ap_min_chan(1) */
    ieee80211_regdomain_ap_min_chan(1);
    /* site +0x4b: wifi_nvs_set(26, ret@31, ret@25) */
    wifi_nvs_set(26, ret@31, ret@25);
    return 0;
}

/* wifi_nvs_validate_ap_num @ ieee80211_nvs.o 0x00000004 size 29B bind GLOBAL
 * Calls: none | Data refs: g_wifi_nvs
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 wifi_nvs_validate_ap_num(void)
{
    /* frame: entry a1,32; 11 insns, 1 cond-branches, 0 loops, 0 jumps */
    /* immediates: 5, 0 */
    /* first predicate: bltui a9, 6, 1a <wifi_nvs_validate_ap_num+0x16> (condition opaque) */
    /* mem ld32: base=(lit:g_wifi_nvs) off=0 */
    /* mem ld8: base=(*(g_wifi_nvs+0)) off=158 */
    /* mem st8: base=(*(g_wifi_nvs+0)) off=158 */
    return 0;
}

/* wifi_nvs_validate_sta_listen_interval @ ieee80211_nvs.o 0x00000004 size 28B bind GLOBAL
 * Calls: none | Data refs: g_wifi_nvs
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 wifi_nvs_validate_sta_listen_interval(void)
{
    /* frame: entry a1,32; 11 insns, 1 cond-branches, 0 loops, 0 jumps */
    /* immediates: 3, 0 */
    /* first predicate: bnez.n a9, 19 <wifi_nvs_validate_sta_listen_interval+0x15> (condition opaque) */
    /* mem ld32: base=(lit:g_wifi_nvs) off=0 */
    /* mem ld16: base=(*(g_wifi_nvs+0)) off=154 */
    /* mem st16: base=(*(g_wifi_nvs+0)) off=154 */
    return 0;
}

/* wifi_nvs_get_sta_listen_interval @ ieee80211_nvs.o 0x00000004 size 13B bind GLOBAL
 * Calls: none | Data refs: g_wifi_nvs
 * Fidelity: high - straight-line, fully mapped (5 insns) */
u32 wifi_nvs_get_sta_listen_interval(void)
{
    /* frame: entry a1,32; 5 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* mem ld32: base=(lit:g_wifi_nvs) off=0 */
    /* mem ld16: base=(*(g_wifi_nvs+0)) off=154 */
    return opaque_result; /* full dataflow not recovered */
}

/* wifi_nvs_set_sta_listen_interval @ ieee80211_nvs.o 0x00000004 size 19B bind GLOBAL
 * Calls: none | Data refs: g_wifi_nvs
 * Fidelity: high - straight-line, fully mapped (7 insns) */
u32 wifi_nvs_set_sta_listen_interval(u32 a2)
{
    /* frame: entry a1,32; 7 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* mem ld32: base=(lit:g_wifi_nvs) off=0 */
    /* mem st16: base=(*(g_wifi_nvs+0)) off=154 */
    return opaque_result; /* full dataflow not recovered */
}

/* wifi_nvs_get_low_rate_enable @ ieee80211_nvs.o 0x00000004 size 30B bind GLOBAL
 * Calls: none | Data refs: g_wifi_nvs
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 wifi_nvs_get_low_rate_enable(u32 a2)
{
    /* frame: entry a1,32; 11 insns, 1 cond-branches, 0 loops, 1 jumps */
    /* first predicate: bnez.n a2, 1a <wifi_nvs_get_low_rate_enable+0x16> (condition opaque) */
    /* mem ld32: base=(lit:g_wifi_nvs) off=0 */
    /* mem ld8: base=((*(g_wifi_nvs+0)+262144)) off=161 */
    /* mem ld8: base=(((*(g_wifi_nvs+0)+262144)+327680)) off=61 */
    return opaque_result; /* full dataflow not recovered */
}

/* wifi_nvs_reset_current_ap_info @ ieee80211_nvs.o 0x00000018 size 113B bind GLOBAL
 * Calls: memset, memset, wifi_nvs_set, wifi_nvs_commit | Data refs: g_wifi_nvs, g_ic
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 wifi_nvs_reset_current_ap_info(u32 a2)
{
    /* frame: entry a1,32; 42 insns, 1 cond-branches, 0 loops, 0 jumps */
    /* immediates: 160, 140, 0, 0x10b, 32, 255, 1, 13 */
    /* first predicate: bne a10, a3, 85 <wifi_nvs_reset_current_ap_info+0x6d> (condition opaque) */
    /* mem ld32: base=(lit:g_wifi_nvs) off=0 */
    /* mem ld8: base=(*(g_wifi_nvs+0)) off=159 */
    /* mem ld32: base=(lit:g_wifi_nvs) off=0 */
    /* mem st8: base=((lit:g_ic+131072)) off=6 */
    /* mem ld8: base=((lit:g_ic+131072)) off=31 */
    /* mem ld32: base=(lit:g_wifi_nvs) off=0 */
    /* site +0x3d: memset(*(g_wifi_nvs+0), 0, 140) */
    memset(*(g_wifi_nvs+0), 0, 140);
    /* site +0x52: memset(*(g_wifi_nvs+0), 255, 32) */
    memset(*(g_wifi_nvs+0), 255, 32);
    /* site +0x79: wifi_nvs_set(13, *(g_wifi_nvs+0), 1) */
    wifi_nvs_set(13, *(g_wifi_nvs+0), 1);
    /* site +0x82: wifi_nvs_commit(ret@79, *(g_wifi_nvs+0), 1) */
    wifi_nvs_commit(ret@79, *(g_wifi_nvs+0), 1);
    return last_call_result; /* opaque */
}

/* wifi_nvs_validate_lr_info @ ieee80211_nvs.o 0x00000004 size 49B bind GLOBAL
 * Calls: none | Data refs: g_wifi_nvs
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 wifi_nvs_validate_lr_info(void)
{
    /* frame: entry a1,32; 18 insns, 3 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0 */
    /* first predicate: bnei a9, 1, 2e <wifi_nvs_validate_lr_info+0x2a> (condition opaque) */
    /* mem ld32: base=(lit:g_wifi_nvs) off=0 */
    /* mem ld8: base=(*(g_wifi_nvs+0)) off=1 */
    /* mem ld8: base=((*(g_wifi_nvs+0)+327680)) off=61 */
    /* mem ld8: base=((*(g_wifi_nvs+0)+262144)) off=161 */
    /* mem st8: base=((*(g_wifi_nvs+0)+262144)) off=161 */
    /* mem st8: base=((*(g_wifi_nvs+0)+327680)) off=61 */
    /* mem st8: base=(*(g_wifi_nvs+0)) off=1 */
    return 0;
}

/* wifi_nvs_load @ ieee80211_nvs.o 0x00000054 size 822B bind LOCAL
 * Calls: indirect(a3), wifi_log, memset, wifi_log, indirect(a9), indirect(a9), indirect(a9), indirect(a9), indirect(a9), indirect(a9), indirect(a9), indirect(a2), memcpy, wifi_nvs_validate_sta_sae_identifier, wifi_nvs_validate_sta_password, wifi_nvs_validate_sta_listen_interval, wifi_nvs_validate_country, wifi_nvs_validate_ap_ssid, wifi_nvs_validate_ap_password, wifi_nvs_validate_ap_chan, wifi_nvs_validate_ap_num, ieee80211_adjust_2nd_chan, wifi_nvs_validate_lr_info, wifi_nvs_commit, indirect(a2) | Data refs: g_osi_funcs_p, .rodata_wlog_warning.13, .bss.g_wifi_nvs_cfg, .rodata_wlog_warning.14, g_wifi_menuconfig, g_wifi_nvs
 * Fidelity: medium - 274 insns, 40 branches, 0 loops; branchy but loop-free, call sequence mapped (verified against section disasm; predicates opaque) */
u32 wifi_nvs_load(u32 a4, u32 a7)
{
    /* frame: entry a1,48; 274 insns, 40 cond-branches, 0 loops, 20 jumps */
    /* immediates: 0x400, 2, 0x101, 1, 255, 0, 0x102, -1, 91, 6 */
    /* first predicate: bnez.n a10, 80 <.text.wifi_nvs_load+0x80> (condition opaque) */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=0x15c */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld8: base=(*(*(g_osi_funcs_p+0)+0x15c)) off=32 */
    /* mem ld8: base=(*(*(g_osi_funcs_p+0)+0x15c)) off=33 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=36 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=((*(g_osi_funcs_p+0)+262144)) off=16 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=0x118 */
    /* ... +69 more memops */
    /* site +0x62: indirect call via a3 (base *(*(g_osi_funcs_p+0)+0x15c)); args: 0x400 */
    opaque_indirect_a3();
    /* site +0x76: wifi_log(1, 0x101, 2, lit:g_osi_funcs_p) */
    wifi_log(1, 0x101, 2, lit:g_osi_funcs_p);
    /* site +0x89: memset(ret@76, 255, 0x400, lit:g_osi_funcs_p) */
    memset(ret@76, 255, 0x400, lit:g_osi_funcs_p);
    /* site +0xb1: wifi_log(1, 0x102, 2, lit:g_osi_funcs_p, 0) */
    wifi_log(1, 0x102, 2, lit:g_osi_funcs_p, 0);
    /* site +0xf5: indirect call via a9 (base *(g_osi_funcs_p+0x118)); args: *(g_osi_funcs_p+16), *(*(g_osi_funcs_p+0)+0x15c), (?+6), lit:g_osi_funcs_p, 0 */
    opaque_indirect_a9();
    /* site +0x151: indirect call via a9 (base *(g_osi_funcs_p+0x120)); args: *(g_osi_funcs_p+16), *(*(g_osi_funcs_p+0)+0x15c), (?+7), lit:g_osi_funcs_p, 0 */
    opaque_indirect_a9();
    /* site +0x18d: indirect call via a9 (base *(g_osi_funcs_p+0x11c)); args: *(g_osi_funcs_p+16), *(*(g_osi_funcs_p+0)+0x15c), *(*(*(g_osi_funcs_p+0)+0x15c)+44), lit:g_osi_funcs_p, 0 */
    opaque_indirect_a9();
    /* site +0x1c1: indirect call via a9 (base *(g_osi_funcs_p+0x128)); args: *(g_osi_funcs_p+16), *(*(*(g_osi_funcs_p+0)+0x15c)+44), (?+4), lit:g_osi_funcs_p, 0 */
    opaque_indirect_a9();
    /* site +0x1fe: indirect call via a9 (base *(g_osi_funcs_p+0x124)); args: *(g_osi_funcs_p+16), *(*(*(g_osi_funcs_p+0)+0x15c)+44), *(*(*(*(g_osi_funcs_p+0)+0x15c)+44)+44), lit:g_osi_funcs_p, 0 */
    opaque_indirect_a9();
    /* site +0x23e: indirect call via a9 (base *(g_osi_funcs_p+0x13c)); args: *(g_osi_funcs_p+16), *(*(*(*(g_osi_funcs_p+0)+0x15c)+44)+44), *(*(*(*(*(g_osi_funcs_p+0)+0x15c)+44)+44)..., ?, 0 */
    opaque_indirect_a9();
    /* site +0x251: indirect call via a9 (base *(g_osi_funcs_p+0x138)); args: *(g_osi_funcs_p+16), *(*(*(*(g_osi_funcs_p+0)+0x15c)+44)+44), ret@62, ?, 0 */
    opaque_indirect_a9();
    /* site +0x25d: indirect call via a2 (base *(*(g_osi_funcs_p+0)+176)); args: ret@62, *(*(*(*(g_osi_funcs_p+0)+0x15c)+44)+44), ret@62, ?, 0 */
    opaque_indirect_a2();
    /* site +0x271: memcpy(*(*(*(*(*(g_osi_funcs_p+0)+0x15c)+44)+44)..., *(*(*(*(g_osi_funcs_p+0)+0x15c)+44)+44), *(*(*(*(*(g_osi_funcs_p+0)+0x15c)+44)+44)..., ?, 0) */
    memcpy(*(*(*(*(*(g_osi_funcs_p+0)+0x15c)+44)+44)..., *(*(*(*(g_osi_funcs_p+0)+0x15c)+44)+44), *(*(*(*(*(g_osi_funcs_p+0)+0x15c)+44)+44)..., ?, 0);
    /* site +0x281: wifi_nvs_validate_sta_sae_identifier(ret@271, *(*(*(*(g_osi_funcs_p+0)+0x15c)+44)+44), *(*(*(*(*(g_osi_funcs_p+0)+0x15c)+44)+44)..., ?, 0) */
    wifi_nvs_validate_sta_sae_identifier(ret@271, *(*(*(*(g_osi_funcs_p+0)+0x15c)+44)+44), *(*(*(*(*(g_osi_funcs_p+0)+0x15c)+44)+44)..., ?, 0);
    /* site +0x287: wifi_nvs_validate_sta_password(ret@281, *(*(*(*(g_osi_funcs_p+0)+0x15c)+44)+44), *(*(*(*(*(g_osi_funcs_p+0)+0x15c)+44)+44)..., ?, 0) */
    wifi_nvs_validate_sta_password(ret@281, *(*(*(*(g_osi_funcs_p+0)+0x15c)+44)+44), *(*(*(*(*(g_osi_funcs_p+0)+0x15c)+44)+44)..., ?, 0);
    /* site +0x28d: wifi_nvs_validate_sta_listen_interval(ret@287, *(*(*(*(g_osi_funcs_p+0)+0x15c)+44)+44), *(*(*(*(*(g_osi_funcs_p+0)+0x15c)+44)+44)..., ?, 0) */
    wifi_nvs_validate_sta_listen_interval(ret@287, *(*(*(*(g_osi_funcs_p+0)+0x15c)+44)+44), *(*(*(*(*(g_osi_funcs_p+0)+0x15c)+44)+44)..., ?, 0);
    /* site +0x293: wifi_nvs_validate_country(ret@28d, *(*(*(*(g_osi_funcs_p+0)+0x15c)+44)+44), *(*(*(*(*(g_osi_funcs_p+0)+0x15c)+44)+44)..., ?, 0) */
    wifi_nvs_validate_country(ret@28d, *(*(*(*(g_osi_funcs_p+0)+0x15c)+44)+44), *(*(*(*(*(g_osi_funcs_p+0)+0x15c)+44)+44)..., ?, 0);
    /* site +0x299: wifi_nvs_validate_ap_ssid(ret@293, *(*(*(*(g_osi_funcs_p+0)+0x15c)+44)+44), *(*(*(*(*(g_osi_funcs_p+0)+0x15c)+44)+44)..., ?, 0) */
    wifi_nvs_validate_ap_ssid(ret@293, *(*(*(*(g_osi_funcs_p+0)+0x15c)+44)+44), *(*(*(*(*(g_osi_funcs_p+0)+0x15c)+44)+44)..., ?, 0);
    /* site +0x29f: wifi_nvs_validate_ap_password(ret@299, *(*(*(*(g_osi_funcs_p+0)+0x15c)+44)+44), *(*(*(*(*(g_osi_funcs_p+0)+0x15c)+44)+44)..., ?, 0) */
    wifi_nvs_validate_ap_password(ret@299, *(*(*(*(g_osi_funcs_p+0)+0x15c)+44)+44), *(*(*(*(*(g_osi_funcs_p+0)+0x15c)+44)+44)..., ?, 0);
    /* site +0x2a5: wifi_nvs_validate_ap_chan(ret@29f, *(*(*(*(g_osi_funcs_p+0)+0x15c)+44)+44), *(*(*(*(*(g_osi_funcs_p+0)+0x15c)+44)+44)..., ?, 0) */
    wifi_nvs_validate_ap_chan(ret@29f, *(*(*(*(g_osi_funcs_p+0)+0x15c)+44)+44), *(*(*(*(*(g_osi_funcs_p+0)+0x15c)+44)+44)..., ?, 0);
    /* site +0x2ab: wifi_nvs_validate_ap_num(ret@2a5, *(*(*(*(g_osi_funcs_p+0)+0x15c)+44)+44), *(*(*(*(*(g_osi_funcs_p+0)+0x15c)+44)+44)..., ?, 0) */
    wifi_nvs_validate_ap_num(ret@2a5, *(*(*(*(g_osi_funcs_p+0)+0x15c)+44)+44), *(*(*(*(*(g_osi_funcs_p+0)+0x15c)+44)+44)..., ?, 0);
    /* site +0x311: ieee80211_adjust_2nd_chan(ret@2ab, *(*(*(*(g_osi_funcs_p+0)+0x15c)+44)+44), *(*(*(*(*(g_osi_funcs_p+0)+0x15c)+44)+44)..., ?, 0) */
    ieee80211_adjust_2nd_chan(ret@2ab, *(*(*(*(g_osi_funcs_p+0)+0x15c)+44)+44), *(*(*(*(*(g_osi_funcs_p+0)+0x15c)+44)+44)..., ?, 0);
    /* site +0x317: wifi_nvs_validate_lr_info(ret@311, *(*(*(*(g_osi_funcs_p+0)+0x15c)+44)+44), *(*(*(*(*(g_osi_funcs_p+0)+0x15c)+44)+44)..., ?, 0) */
    wifi_nvs_validate_lr_info(ret@311, *(*(*(*(g_osi_funcs_p+0)+0x15c)+44)+44), *(*(*(*(*(g_osi_funcs_p+0)+0x15c)+44)+44)..., ?, 0);
    /* site +0x325: wifi_nvs_commit(ret@317, *(*(*(*(g_osi_funcs_p+0)+0x15c)+44)+44), *(*(*(*(*(g_osi_funcs_p+0)+0x15c)+44)+44)..., ?, 0) */
    wifi_nvs_commit(ret@317, *(*(*(*(g_osi_funcs_p+0)+0x15c)+44)+44), *(*(*(*(*(g_osi_funcs_p+0)+0x15c)+44)+44)..., ?, 0);
    /* site +0x32f: indirect call via a2 (base *(g_osi_funcs_p+176)); args: ret@62, *(*(*(*(g_osi_funcs_p+0)+0x15c)+44)+44), *(*(*(*(*(g_osi_funcs_p+0)+0x15c)+44)+44)..., ?, 0 */
    opaque_indirect_a2();
    return 0;
}

/* wifi_nvs_restore @ ieee80211_nvs.o 0x00000004 size 16B bind GLOBAL
 * Calls: wifi_nvs_load | Data refs: none
 * Fidelity: high - straight-line, fully mapped (6 insns) */
u32 wifi_nvs_restore(void)
{
    /* frame: entry a1,32; 6 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* immediates: 1, 0 */
    /* site +0xd: wifi_nvs_load(1) */
    wifi_nvs_load(1);
    return 0;
}

/* wifi_nvs_deinit @ ieee80211_nvs.o 0x00000010 size 71B bind GLOBAL
 * Calls: indirect(a8), indirect(a3) | Data refs: .bss.g_wifi_nvs_cfg, g_wifi_menuconfig, g_wifi_nvs, g_osi_funcs_p
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 wifi_nvs_deinit(u32 a2)
{
    /* frame: entry a1,32; 29 insns, 3 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0 */
    /* first predicate: beqz.n a3, 4e <wifi_nvs_deinit+0x3e> (condition opaque) */
    /* mem ld32: base=(lit:.bss.g_wifi_nvs_cfg) off=0 */
    /* mem ld32: base=(lit:g_wifi_menuconfig) off=36 */
    /* mem ld32: base=(lit:g_wifi_nvs) off=0 */
    /* mem ld32: base=((*(g_wifi_nvs+0)+262144)) off=16 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=0x130 */
    /* mem ld32: base=(lit:g_wifi_nvs) off=0 */
    /* mem st32: base=((*(g_wifi_nvs+0)+262144)) off=16 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(lit:.bss.g_wifi_nvs_cfg) off=0 */
    /* ... +2 more memops */
    /* site +0x35: indirect call via a8 (base *(*(g_osi_funcs_p+0)+0x130)); args: *((*(g_wifi_nvs+0)+262144)+16) */
    opaque_indirect_a8();
    /* site +0x4b: indirect call via a3 (base *(g_osi_funcs_p+176)); args: *(.bss.g_wifi_nvs_cfg+0) */
    opaque_indirect_a3();
    return opaque_result; /* full dataflow not recovered */
}

/* wifi_nvs_init @ ieee80211_nvs.o 0x0000002c size 117B bind GLOBAL
 * Calls: wifi_nvs_cfg_init, indirect(a2), wifi_log, wifi_nvs_load, wifi_log, wifi_nvs_deinit | Data refs: g_wifi_menuconfig, g_wifi_nvs, .rodata.wifi_nvs_init.str1.1, g_osi_funcs_p, .rodata_wlog_warning.15, .rodata_wlog_error.16
 * Fidelity: medium - branchy but loop-free, call sequence mapped */
u32 wifi_nvs_init(void)
{
    /* frame: entry a1,32; 44 insns, 4 cond-branches, 0 loops, 2 jumps */
    /* immediates: 0x410, 1, 2, 0x102 */
    /* first predicate: bnez a10, 88 <wifi_nvs_init+0x5c> (condition opaque) */
    /* mem ld32: base=(lit:g_wifi_menuconfig) off=36 */
    /* mem ld32: base=(lit:g_wifi_nvs) off=0 */
    /* mem ld32: base=(lit:g_osi_funcs_p) off=0 */
    /* mem ld32: base=(*(g_osi_funcs_p+0)) off=0x12c */
    /* site +0x32: wifi_nvs_cfg_init(/* no traced args */) */
    wifi_nvs_cfg_init(/* no traced args */);
    /* site +0x59: indirect call via a2 (base *(g_osi_funcs_p+0x12c)); args: lit:.rodata.wifi_nvs_init.str1.1, 1, *(g_wifi_nvs+0) */
    opaque_indirect_a2();
    /* site +0x75: wifi_log(1, 0x102, 2, lit:.rodata_wlog_warning.15, ret@59) */
    wifi_log(1, 0x102, 2, lit:.rodata_wlog_warning.15, ret@59);
    /* site +0x81: wifi_nvs_load(ret@59, 0x102, 2, lit:.rodata_wlog_warning.15, ret@59) */
    wifi_nvs_load(ret@59, 0x102, 2, lit:.rodata_wlog_warning.15, ret@59);
    /* site +0x96: wifi_log(1, 1, 1, lit:.rodata_wlog_error.16, ret@81) */
    wifi_log(1, 1, 1, lit:.rodata_wlog_error.16, ret@81);
    /* site +0x9c: wifi_nvs_deinit(ret@96, 1, 1, lit:.rodata_wlog_error.16, ret@81) */
    wifi_nvs_deinit(ret@96, 1, 1, lit:.rodata_wlog_error.16, ret@81);
    return opaque_result; /* full dataflow not recovered */
}
