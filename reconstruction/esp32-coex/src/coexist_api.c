/* Reconstruction of coexist_api.o (libcoexist.a) — public coex API shims.
 * Ground truth: re/esp32-coex/funcdb_libcoexist.json (funcdb v3: exact calls[]/refs[]),
 * re/esp32-coex/disasm/coexist_api.dis (xtensa-esp32-elf-objdump -dr).
 * Xtensa ABI: args a2..a7, return a2 (outgoing args a10..; callee result in caller a10).
 * Signatures [inferred] from register use (no DWARF in these objects).
 * Return convention: wrappers move callee result (mov a2,a10) except where noted.
 * Error constant 0x102 = ESP_ERR_INVALID_ARG; 0 = success.
 */
typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;

extern int coex_core_bb_reset_lock(void);
extern void coex_core_bb_reset_unlock(u32 arg);
extern int coex_core_deinit(void);
extern int coex_core_disable(void);
extern int coex_core_enable(void);
extern int coex_core_event_duration_get(u32 event, u32 *out);
extern int coex_core_init(void);
extern int coex_core_pre_init(void);
extern int coex_core_register_cb(u32 owner, void *cb);
extern int coex_core_register_start_cb(void *cb);
extern int coex_core_release(u32 owner, u32 event);
extern int coex_core_request(u32 owner, u32 event, u32 p3, u32 p4);
extern int coex_core_status_get(void);
extern int coex_schm_status_bit_clear(u32 type, u32 status);
extern int coex_schm_status_bit_set(u32 type, u32 status);
extern u32 coex_schm_status_bitmap_get(void);
extern int coexist_printf(const char *fmt, ...);
extern int puts(const char *s);
extern u32 strlen(const char *s);
extern int strncmp(const char *a, const char *b, u32 n);

/* Adapter table pointer set by esp_coex_adapter_register (opaque, .data). */
extern void *g_coa_funcs_p;
/* Internal md5 strings (.data pointers into .rodata.str1.1). */
extern const char *g_coex_adapter_funcs_md5; /* -> "6964e7f" (str+16) */
extern const char *g_coex_i154_funcs_md5;    /* -> "85dae7a" (str+8) */
extern const char *libcoexist_reversion_git; /* -> "eec362d" (str+39) */
extern void *s_set_lpclk_source_cb;          /* .bss.s_set_lpclk_source_cb */

/* coex_bb_reset_lock @ coexist_api.o 00000004 size 13B bind GLOBAL
 * Calls: none | Data refs: none
 * Fidelity: high - direct tail-call shim, result moved */
int coex_bb_reset_lock(void)
{
    return coex_core_bb_reset_lock();
}

/* coex_bb_reset_unlock @ coexist_api.o 00000004 size 14B bind GLOBAL
 * Calls: none | Data refs: none
 * Fidelity: high - arg forwarded (or a10,a2,a2), no result move: returns entry a2 */
u32 coex_bb_reset_unlock(u32 arg)
{
    coex_core_bb_reset_unlock(arg);
    return arg; /* disasm: retw without mov a2,a10 */
}

/* coex_bt_release @ coexist_api.o 00000004 size 17B bind GLOBAL
 * Calls: none | Data refs: none
 * Fidelity: high - owner=0 (BT) release shim, result moved */
int coex_bt_release(u32 event)
{
    return coex_core_release(0, event);
}

/* coex_bt_request @ coexist_api.o 00000004 size 21B bind GLOBAL
 * Calls: none | Data refs: none
 * Fidelity: high - owner=0 (BT) request shim, result moved */
int coex_bt_request(u32 event, u32 p3, u32 p4)
{
    return coex_core_request(0, event, p3, p4);
}

/* coex_deinit @ coexist_api.o 00000004 size 11B bind GLOBAL
 * Calls: coex_core_deinit | Data refs: coex_core_deinit
 * Fidelity: high - direct shim, no result move (returns entry a2) */
u32 coex_deinit(void)
{
    coex_core_deinit();
    /* disasm: retw without mov a2,a10; no meaningful return */
}

/* coex_disable @ coexist_api.o 00000004 size 11B bind GLOBAL
 * Calls: coex_core_disable | Data refs: coex_core_disable
 * Fidelity: high - direct shim, no result move (returns entry a2) */
u32 coex_disable(void)
{
    coex_core_disable();
    /* disasm: retw without mov a2,a10; no meaningful return */
}

/* coex_enable @ coexist_api.o 00000004 size 13B bind GLOBAL
 * Calls: coex_core_enable | Data refs: coex_core_enable
 * Fidelity: high - direct shim, result moved */
int coex_enable(void)
{
    return coex_core_enable();
}

/* coex_event_duration_get @ coexist_api.o 00000004 size 17B bind GLOBAL
 * Calls: coex_core_event_duration_get | Data refs: coex_core_event_duration_get
 * Fidelity: high - (event, out) forwarded, result moved */
int coex_event_duration_get(u32 event, u32 *out)
{
    return coex_core_event_duration_get(event, out);
}

/* coex_init @ coexist_api.o 00000004 size 13B bind GLOBAL
 * Calls: coex_core_init | Data refs: coex_core_init
 * Fidelity: high - direct shim, result moved */
int coex_init(void)
{
    return coex_core_init();
}

/* coex_is_running @ coexist_api.o 00000004 size 20B bind GLOBAL
 * Calls: coex_core_status_get | Data refs: coex_core_status_get
 * Fidelity: high - returns (coex_core_status_get() == 1) via addi/movnez */
u32 coex_is_running(void)
{
    return (coex_core_status_get() == 1) ? 1 : 0;
}

/* coex_pre_init @ coexist_api.o 00000010 size 27B bind GLOBAL
 * Calls: coex_core_pre_init, coexist_printf | Data refs: .rodata.coex_pre_init.str1.1, coex_core_pre_init, coexist_printf, libcoexist_reversion_git
 * Fidelity: high - prints "coex firmware version: %s" then inits, result moved */
int coex_pre_init(void)
{
    coexist_printf("coex firmware version: %s\n", *libcoexist_reversion_git);
    return coex_core_pre_init();
}

/* coex_preference_set @ coexist_api.o 00000000 size 7B bind GLOBAL
 * Calls: none | Data refs: none
 * Fidelity: high - stub: entry/retw only, returns 0 */
u32 coex_preference_set(void)
{
    return 0;
}

/* coex_register_bt_cb @ coexist_api.o 00000004 size 17B bind GLOBAL
 * Calls: coex_core_register_cb | Data refs: coex_core_register_cb
 * Fidelity: high - owner=0 (BT) register shim, result moved */
int coex_register_bt_cb(void *cb)
{
    return coex_core_register_cb(0, cb);
}

/* coex_register_start_cb @ coexist_api.o 00000004 size 16B bind GLOBAL
 * Calls: coex_core_register_start_cb | Data refs: coex_core_register_start_cb
 * Fidelity: high - arg forwarded (or a10,a2,a2), result moved */
int coex_register_start_cb(void *cb)
{
    return coex_core_register_start_cb(cb);
}

/* coex_register_wifi_cb @ coexist_api.o 00000004 size 17B bind GLOBAL
 * Calls: coex_core_register_cb | Data refs: coex_core_register_cb
 * Fidelity: high - owner=1 (WiFi) register shim, result moved */
int coex_register_wifi_cb(void *cb)
{
    return coex_core_register_cb(1, cb);
}

/* coex_status_get @ coexist_api.o 00000008 size 32B bind GLOBAL
 * Calls: none | Data refs: none
 * Fidelity: high - mask test: (~(arg&0xFF) & bitmap)==0 -> 0 else core status */
u32 coex_status_get(u32 mask)
{
    u32 bitmap = coex_schm_status_bitmap_get();
    u32 lo = mask & 0xFFu;
    if ((((u32)-1 ^ lo) & bitmap) == 0)
        return 0;
    return (u32)coex_core_status_get();
}

/* coex_update_lpclk_interval @ coexist_api.o 00000004 size 15B bind GLOBAL
 * Calls: none | Data refs: .bss.s_set_lpclk_source_cb
 * Fidelity: medium - guarded indirect call via a10 target (no arg moves: callee args unknown) */
void coex_update_lpclk_interval(void)
{
    if (s_set_lpclk_source_cb != 0)
        ((void (*)(void))s_set_lpclk_source_cb)();
}

/* coex_version_get @ coexist_api.o 00000004 size 8B bind GLOBAL
 * Calls: none | Data refs: .rodata.coex_version_str
 * Fidelity: high - returns pointer to "2.0.0" */
const char *coex_version_get(void)
{
    return "2.0.0"; /* .rodata.coex_version_str */
}

/* coex_version_get_value @ coexist_api.o 00000000 size 33B bind GLOBAL
 * Calls: none | Data refs: none
 * Fidelity: high - NULL -> 0x102 else buf[0..2] = {2,0,0}, return 0 */
u32 coex_version_get_value(u8 *buf)
{
    if (buf == 0)
        return 0x102;
    buf[0] = 2;
    buf[1] = 0;
    buf[2] = 0;
    return 0;
}

/* coex_wifi_register_update_lpclk_callback @ coexist_api.o 00000004 size 13B bind GLOBAL
 * Calls: none | Data refs: .bss.s_set_lpclk_source_cb
 * Fidelity: high - stores callback pointer, no result move */
void coex_wifi_register_update_lpclk_callback(void *cb)
{
    s_set_lpclk_source_cb = cb;
}

/* coex_wifi_release @ coexist_api.o 00000004 size 17B bind GLOBAL
 * Calls: none | Data refs: none
 * Fidelity: high - owner=1 (WiFi) release shim, result moved */
int coex_wifi_release(u32 event)
{
    return coex_core_release(1, event);
}

/* coex_wifi_request @ coexist_api.o 00000004 size 21B bind GLOBAL
 * Calls: coex_core_request | Data refs: coex_core_request
 * Fidelity: high - owner=1 (WiFi) request shim, result moved */
int coex_wifi_request(u32 event, u32 p3, u32 p4)
{
    return coex_core_request(1, event, p3, p4);
}

/* esp_coex_adapter_funcs_md5_check @ coexist_api.o 00000014 size 56B bind GLOBAL
 * Calls: coexist_printf, strlen, strncmp | Data refs: .rodata.esp_coex_adapter_funcs_md5_check.str1.1, coexist_printf, g_coex_adapter_funcs_md5, strlen, strncmp
 * Fidelity: high - NULL -> 0; match -> 0; mismatch -> printf + 0x102 */
u32 esp_coex_adapter_funcs_md5_check(const char *md5)
{
    const char *internal;
    u32 len;
    if (md5 == 0)
        return 0;
    internal = g_coex_adapter_funcs_md5; /* "6964e7f" */
    len = strlen(internal);
    if (strncmp(internal, md5, len) == 0)
        return 0;
    coexist_printf("Invalid coexist adapter function md5, internal: %s, idf: %s",
                   internal, md5);
    return 0x102;
}

/* esp_coex_adapter_register @ coexist_api.o 0000001c size 73B bind GLOBAL
 * Calls: coexist_printf, puts | Data refs: .rodata.esp_coex_adapter_register.str1.1, coexist_printf, g_coa_funcs_p, puts
 * Fidelity: high - already-set -> 0; NULL -> puts + 0x102; version(+0)!=2 / magic(+92)!=0xdeadbeaf -> printf + 0x102 */
u32 esp_coex_adapter_register(void *funcs)
{
    u32 magic;
    u32 magic92;
    if (*(void **)g_coa_funcs_p != 0)
        return 0; /* already registered */
    if (funcs == 0) {
        puts("coexist adapter function is NULL");
        return 0x102;
    }
    magic = *(u32 *)funcs; /* +0: version, expect 2 */
    if (magic != 2) {
        coexist_printf("coexist adapter function version error! Version %x is expected, but it is %x",
                       2, magic);
        return 0x102;
    }
    magic92 = *(u32 *)((u8 *)funcs + 92); /* +92: magic, expect 0xdeadbeaf */
    if (magic92 != 0xdeadbeaf) {
        coexist_printf("coexist adapter function magic error! Magic %x is expected, but it is %x",
                       0xdeadbeaf, magic92);
        return 0x102;
    }
    *(void **)g_coa_funcs_p = funcs;
    return 0;
}

/* esp_coex_i154_funcs_md5_check @ coexist_api.o 00000014 size 56B bind GLOBAL
 * Calls: coexist_printf, strlen, strncmp | Data refs: .rodata.esp_coex_i154_funcs_md5_check.str1.1, coexist_printf, g_coex_i154_funcs_md5, strlen, strncmp
 * Fidelity: high - NULL -> 0; match -> 0; mismatch -> printf + 0x102 */
u32 esp_coex_i154_funcs_md5_check(const char *md5)
{
    const char *internal;
    u32 len;
    if (md5 == 0)
        return 0;
    internal = (const char *)1; /* g_coex_i154_funcs_md5 -> "85dae7a" */
    len = strlen(internal);
    if (strncmp(internal, md5, len) == 0)
        return 0;
    coexist_printf("Invalid coexist i154 event type function md5, internal: %s, idf: %s",
                   internal, md5);
    return 0x102;
}

/* esp_coex_status_bit_clear @ coexist_api.o 00000020 size 168B bind GLOBAL
 * Calls: coex_schm_status_bit_clear, coexist_printf | Data refs: .dram1.6, .dram1.7, .dram1.8, .dram1.9, coex_schm_status_bit_clear, coexist_printf, g_coa_funcs_p
 * Fidelity: high - type/status validation mirrors set path, then schm clear; invalid -> printf + 0x102 else 0 */
u32 esp_coex_status_bit_clear(u32 type, u32 status)
{
    u32 t;
    u32 (*adapter_time_now)(void);
    if (type == 0) {
        /* adapter+60 with no args (target loaded into a10); result feeds log line */
        adapter_time_now = *(u32 (**)(void))((u8 *)*(void **)g_coa_funcs_p + 60);
        t = adapter_time_now();
        coexist_printf("[%u] Do not support set coexistence WiFi status\n", t);
        return 0x102;
    }
    if (type == 1) { /* BT: valid status in {8,16} or == 32 */
        if (((status - 8) & 0xFFFFFFF7u) == 0)
            goto ok;
        if (status == 32)
            goto ok;
        adapter_time_now = *(u32 (**)(void))((u8 *)*(void **)g_coa_funcs_p + 60);
        t = adapter_time_now();
        coexist_printf("[%u] Incorrect coexistence BT status: %d\n", t, status);
        return 0x102;
    }
    if (type == 2) { /* BLE: valid status in {16,32} */
        if (((status - 16) & 0xFFFFFFEFu) == 0)
            goto ok;
        adapter_time_now = *(u32 (**)(void))((u8 *)*(void **)g_coa_funcs_p + 60);
        t = adapter_time_now();
        coexist_printf("[%u] Incorrect coexistence BLE status: %d\n", t, status);
        return 0x102;
    }
    if (type == 4 && status != 1) { /* 802.15.4: only status 1 */
        adapter_time_now = *(u32 (**)(void))((u8 *)*(void **)g_coa_funcs_p + 60);
        t = adapter_time_now();
        coexist_printf("[%u] Incorrect coexistence 802.15.4 status: %d\n", t, status);
        return 0x102;
    }
ok:
    coex_schm_status_bit_clear(type, status);
    return 0;
}

/* esp_coex_status_bit_set @ coexist_api.o 00000020 size 168B bind GLOBAL
 * Calls: coex_schm_status_bit_set, coexist_printf | Data refs: .dram1.2, .dram1.3, .dram1.4, .dram1.5, coex_schm_status_bit_set, coexist_printf, g_coa_funcs_p
 * Fidelity: high - type/status validation then schm set; invalid -> printf + 0x102 else 0 */
u32 esp_coex_status_bit_set(u32 type, u32 status)
{
    u32 t;
    u32 (*adapter_time_now)(void);
    if (type == 0) {
        adapter_time_now = *(u32 (**)(void))((u8 *)*(void **)g_coa_funcs_p + 60);
        t = adapter_time_now();
        coexist_printf("[%u] Do not support set coexistence WiFi status\n", t);
        return 0x102;
    }
    if (type == 1) { /* BT: valid status in {8,16} or == 32 */
        if (((status - 8) & 0xFFFFFFF7u) == 0)
            goto ok;
        if (status == 32)
            goto ok;
        adapter_time_now = *(u32 (**)(void))((u8 *)*(void **)g_coa_funcs_p + 60);
        t = adapter_time_now();
        coexist_printf("[%u] Incorrect coexistence BT status: %d\n", t, status);
        return 0x102;
    }
    if (type == 2) { /* BLE: valid status in {16,32} */
        if (((status - 16) & 0xFFFFFFEFu) == 0)
            goto ok;
        adapter_time_now = *(u32 (**)(void))((u8 *)*(void **)g_coa_funcs_p + 60);
        t = adapter_time_now();
        coexist_printf("[%u] Incorrect coexistence BLE status: %d\n", t, status);
        return 0x102;
    }
    if (type == 4 && status != 1) { /* 802.15.4: only status 1 */
        adapter_time_now = *(u32 (**)(void))((u8 *)*(void **)g_coa_funcs_p + 60);
        t = adapter_time_now();
        coexist_printf("[%u] Incorrect coexistence 802.15.4 status: %d\n", t, status);
        return 0x102;
    }
ok:
    coex_schm_status_bit_set(type, status);
    return 0;
}
