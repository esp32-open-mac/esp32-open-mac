/* Reconstruction of coexist_dbg.o (libcoexist.a) — debug output + log level.
 * Ground truth: re/esp32-coex/funcdb_libcoexist.json (funcdb v3),
 * re/esp32-coex/disasm/coexist_dbg.dis.
 * .dram1.1 (4B) = coex_log_level (init 1); .dram1.2 (4B) = gpio debug callback (init 0).
 */
typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;

extern u32 coex_log_level;  /* .dram1.1 */
extern void *coex_gpio_dbg_cb; /* .dram1.2 */

/* coex_gpio_debug_matrix_init @ coexist_dbg.o 00000000 size 7B bind GLOBAL
 * Calls: none | Data refs: none
 * Fidelity: high - stub: entry/retw only, returns 0 */
u32 coex_gpio_debug_matrix_init(void)
{
    return 0;
}

/* coex_gpio_debug_matrix_config @ coexist_dbg.o 00000000 size 7B bind GLOBAL
 * Calls: none | Data refs: none
 * Fidelity: high - stub: entry/retw only, returns 0 */
u32 coex_gpio_debug_matrix_config(void)
{
    return 0;
}

/* coex_set_gpio_debug_cb @ coexist_dbg.o 00000004 size 13B bind GLOBAL
 * Calls: none | Data refs: .dram1.2
 * Fidelity: high - stores callback, no result move */
void coex_set_gpio_debug_cb(void *cb)
{
    coex_gpio_dbg_cb = cb;
}

/* coex_dbg_output @ coexist_dbg.o 00000004 size 19B bind GLOBAL
 * Calls: none | Data refs: none
 * Fidelity: high - if cb set: cb(a2, a3); (a10/a11 moves, target via a8) */
void coex_dbg_output(u32 p0, u32 p1)
{
    if (coex_gpio_dbg_cb != 0)
        ((void (*)(u32, u32))coex_gpio_dbg_cb)(p0, p1);
}

/* coex_gpio_debug_max_event_get @ coexist_dbg.o 00000000 size 7B bind GLOBAL
 * Calls: none | Data refs: none
 * Fidelity: high - returns constant 17 (movi.n a2, 17) */
u32 coex_gpio_debug_max_event_get(void)
{
    return 17;
}

/* coex_dbg_set_log_level @ coexist_dbg.o 00000004 size 13B bind GLOBAL
 * Calls: none | Data refs: coex_log_level
 * Fidelity: high - stores level, no result move */
void coex_dbg_set_log_level(u32 level)
{
    coex_log_level = level;
}
