/* Reconstruction of coexist_timer.o (libcoexist.a) — time base + TS timers.
 * Ground truth: re/esp32-coex/funcdb_libcoexist.json (funcdb v3),
 * re/esp32-coex/disasm/coexist_timer.dis.
 * Time source is adapter fn@60 (no-arg indirect call, target in a10);
 * TS arm/disarm go through adapter fns @80/@68/@76/@72 with byte offsets cited.
 * .dram1.1 (20B) = end-timer struct; .dram1.2 (20B) = start-timer struct;
 * .dram1.3 (1B) = end disalarmed flag; .dram1.4 (1B) = start disalarmed flag.
 * (Pairing proved by ts_end_alarm [.dram1.3 + .dram1.1] vs ts_start_alarm [.dram1.4 + .dram1.2].)
 */
typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long u64;

extern void *g_coa_funcs_p;
extern u8 ts_end_disalarmed;   /* .dram1.3 */
extern u8 ts_start_disalarmed; /* .dram1.4 */
extern u8 ts_end_timer[20];    /* .dram1.1 */
extern u8 ts_start_timer[20];  /* .dram1.2 */
extern long long __divdi3(long long a, long long b);

/* coex_time_diff @ coexist_timer.o 00000000 size 8B bind GLOBAL
 * Calls: none | Data refs: none
 * Fidelity: high - single sub: return a3-a2 */
u32 coex_time_diff(u32 t1, u32 t2)
{
    return t2 - t1;
}

/* coex_time_now @ coexist_timer.o 00000004 size 17B bind GLOBAL
 * Calls: none | Data refs: none
 * Fidelity: high - adapter fn@60 no-arg call, result moved */
u32 coex_time_now(void)
{
    u32 (*fn)(void) = *(u32 (**)(void))((u8 *)*(void **)g_coa_funcs_p + 60);
    return fn();
}

/* coex_time_is_past @ coexist_timer.o 00000004 size 22B bind GLOBAL
 * Calls: none | Data refs: none
 * Fidelity: high - bit31(~(now-t)): returns (t <= now) */
u32 coex_time_is_past(u32 t)
{
    u32 now = coex_time_now();
    return ((~(now - t)) >> 31) & 1u; /* 1 iff t <= now */
}

/* coex_time_is_in_time @ coexist_timer.o 00000004 size 34B bind GLOBAL
 * Calls: none | Data refs: none
 * Fidelity: high - (now>=start) -> 1 else window>=(start-now) -> 1 else 0 */
u32 coex_time_is_in_time(u32 start, u32 window)
{
    u32 now = coex_time_now();
    u32 elapsed = now - start; /* bgez => now >= start */
    if ((int)elapsed >= 0)
        return 1;
    if (window >= start - now)
        return 1;
    return 0;
}

/* coex_time_now_ms @ coexist_timer.o 00000008 size 28B bind GLOBAL
 * Calls: none | Data refs: none
 * Fidelity: medium - __divdi3(time_now, 1000); upper dividend word is entry garbage per disasm */
u32 coex_time_now_ms(void)
{
    return (u32)__divdi3((long long)coex_time_now(), 1000);
}

/* coex_ts_end_timer_dislarmed @ coexist_timer.o 00000004 size 11B bind GLOBAL
 * Calls: none | Data refs: none
 * Fidelity: high - returns u8 flag .dram1.3 */
u32 coex_ts_end_timer_dislarmed(void)
{
    return ts_end_disalarmed;
}

/* coex_ts_start_timer_dislarmed @ coexist_timer.o 00000004 size 11B bind GLOBAL
 * Calls: none | Data refs: none
 * Fidelity: high - returns u8 flag .dram1.4 */
u32 coex_ts_start_timer_dislarmed(void)
{
    return ts_start_disalarmed;
}

/* coex_timer_ts_end_alarm @ coexist_timer.o 0000000c size 38B bind GLOBAL
 * Calls: none | Data refs: none
 * Fidelity: medium - flag clear + adapter@80(struct,end_us,0); adapter arg roles inferred from moves */
void coex_timer_ts_end_alarm(u32 us)
{
    void *ad = *(void **)g_coa_funcs_p;
    void (*arm)(void *, u32, u32);
    ts_end_disalarmed = 0;
    arm = *(void (**)(void *, u32, u32))((u8 *)ad + 80);
    arm(ts_end_timer, us, 0);
}

/* coex_timer_ts_end_disalarm @ coexist_timer.o 0000000c size 34B bind GLOBAL
 * Calls: none | Data refs: none
 * Fidelity: medium - flag set + adapter@68(struct); adapter fn roles inferred from offsets */
void coex_timer_ts_end_disalarm(void)
{
    void *ad = *(void **)g_coa_funcs_p;
    void (*disarm)(void *);
    ts_end_disalarmed = 1;
    disarm = *(void (**)(void *))((u8 *)ad + 68);
    disarm(ts_end_timer);
}

/* coex_timer_ts_start_alarm @ coexist_timer.o 0000000c size 38B bind GLOBAL
 * Calls: none | Data refs: none
 * Fidelity: medium - flag clear + adapter@80(struct,start_us,0); mirrors end alarm */
void coex_timer_ts_start_alarm(u32 us)
{
    void *ad = *(void **)g_coa_funcs_p;
    void (*arm)(void *, u32, u32);
    ts_start_disalarmed = 0;
    arm = *(void (**)(void *, u32, u32))((u8 *)ad + 80);
    arm(ts_start_timer, us, 0);
}

/* coex_timer_ts_start_disalarm @ coexist_timer.o 0000000c size 34B bind GLOBAL
 * Calls: none | Data refs: none
 * Fidelity: medium - flag set + adapter@68(struct); mirrors end disalarm */
void coex_timer_ts_start_disalarm(void)
{
    void *ad = *(void **)g_coa_funcs_p;
    void (*disarm)(void *);
    ts_start_disalarmed = 1;
    disarm = *(void (**)(void *))((u8 *)ad + 68);
    disarm(ts_start_timer);
}

/* coex_timer_init @ coexist_timer.o 00000010 size 54B bind GLOBAL
 * Calls: none | Data refs: .dram1.1, .dram1.2, .dram1.3, g_coa_funcs_p
 * Fidelity: medium - clears end flag, adapter@76 setfn for start struct/cb then end struct/cb; returns 2nd setfn rc (no result move in disasm) */
u32 coex_timer_init(void *start_cb, void *end_cb)
{
    void *ad = *(void **)g_coa_funcs_p;
    u32 (*setfn)(void *, void *, u32);
    u32 rc;
    ts_end_disalarmed = 0;
    setfn = *(u32 (**)(void *, void *, u32))((u8 *)ad + 76);
    setfn(ts_start_timer, start_cb, 0);
    rc = setfn(ts_end_timer, end_cb, 0);
    return rc;
}

/* coex_timer_deinit @ coexist_timer.o 0000000c size 32B bind GLOBAL
 * Calls: none | Data refs: .dram1.1, .dram1.2, g_coa_funcs_p
 * Fidelity: medium - adapter@72 teardown for both timer structs, returns 0 */
u32 coex_timer_deinit(void)
{
    void *ad = *(void **)g_coa_funcs_p;
    void (*teardown)(void *);
    teardown = *(void (**)(void *))((u8 *)ad + 72);
    teardown(ts_start_timer);
    teardown = *(void (**)(void *))((u8 *)ad + 72);
    teardown(ts_end_timer);
    return 0;
}
