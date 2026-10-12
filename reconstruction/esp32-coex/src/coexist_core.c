/* Reconstruction of coexist_core.o (libcoexist.a) — TS engine + lifecycle.
 * Ground truth: re/esp32-coex/funcdb_libcoexist.json (funcdb v3),
 * re/esp32-coex/disasm/coexist_core.dis.
 * coex_env (32B, .dram1.1): +0 ts_state ptr, +4 cur_arbit ptr, +8 mux-present,
 * +12 status, +16 evt_cb (owner0/BT), +20 evt_cb (owner1/WiFi), +24 u8 force_active,
 * +28 start_cb. g_coex_param (20B) = {25000,5000,20000,25000,50000}.
 * coex_prio_tab (42B, .dram1.5) indexed by event id.
 * .iram1.7/.iram1.8/.iram1.11 = lock/unlock/reschedule statics (no symtab entries).
 */
typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;

extern void *g_coa_funcs_p;
extern u8 coex_env[32];
extern u8 coex_bb_rst_mux[4];
extern u8 coex_fwm_mux[4];
extern u8 coex_enabled_ref; /* .bss 1B */
extern u8 g_coex_param[20];
extern u8 coex_prio_tab[42];
extern int coexist_printf(const char *fmt, ...);
extern void coex_dbg_output(u32 p0, u32 p1);
extern u32 coex_time_now(void);
extern u32 coex_time_diff(u32 t1, u32 t2);
extern u32 coex_time_is_in_time(u32 start, u32 window);
extern void coex_arbit_clean_overtime(u32 window);
extern void *coex_arbit_first(void);
extern void *coex_arbit_next(void *p);
extern u32 coex_arbit_insert(void *req);
extern u32 coex_arbit_delete(void *req);
extern u32 coex_arbit_init(void);
extern u32 coex_arbit_deinit(void);
extern u32 coex_timer_init(void *start_cb, void *end_cb);
extern u32 coex_timer_deinit(void);
extern void coex_timer_ts_start_alarm(u32 us);
extern void coex_timer_ts_start_disalarm(void);
extern void coex_timer_ts_end_alarm(u32 us);
extern void coex_timer_ts_end_disalarm(void);
extern u32 coex_ts_start_timer_dislarmed(void);
extern u32 coex_ts_end_timer_dislarmed(void);
extern void coex_force_wifi_mode(u32 arg);
extern void coex_unforce_wifi_mode(void);
extern u32 coex_schm_init(void);
extern void coex_gpio_init(void);
static u8 coex_bb_rst_flag; /* .dram1.4 (1B) in coexist_core.o */

/* static coex_lock (.iram1.7; called from enable/disable/register/request/release/ Merlin paths)
 * Calls: none | Data refs: coex_env, g_coa_funcs_p
 * Fidelity: medium - env+8 gating + adapter +48/+32/+20/+40 offsets exact; ISR-vs-task branch roles inferred */
static int coex_lock(void)
{
    void *ad = *(void **)g_coa_funcs_p;
    u32 r;
    if (*(u32 *)(coex_env + 8) == 0)
        return 0x103;
    r = ((u32 (*)(void))*(u32 *)((u8 *)ad + 48))();
    if (r == 0) {
        /* ISR-ish path: adapter+40(env+8, -1) */
        r = ((u32 (*)(void *, int))*(u32 *)((u8 *)ad + 40))((void *)*(u32 *)(coex_env + 8), -1);
    } else {
        /* task path: adapter+32(stack_slot, env+8), then adapter+20 on success */
        u32 slot = 0;
        r = ((u32 (*)(void *, void *))*(u32 *)((u8 *)ad + 32))(&slot, (void *)*(u32 *)(coex_env + 8));
        if (slot != 0)
            r = ((u32 (*)(void))*(u32 *)((u8 *)ad + 20))();
    }
    return (r == 1) ? 0 : -1;
}

/* static coex_unlock (.iram1.8; called from enable/disable/register/handlers)
 * Calls: none | Data refs: coex_env, g_coa_funcs_p
 * Fidelity: medium - env+8 gating + adapter +48/+44/+20 offsets exact; give/take roles inferred */
static void coex_unlock(void)
{
    void *ad = *(void **)g_coa_funcs_p;
    u32 r;
    if (*(u32 *)(coex_env + 8) == 0)
        return;
    r = ((u32 (*)(void))*(u32 *)((u8 *)ad + 48))();
    if (r == 0)
        ((void (*)(void *))*(u32 *)((u8 *)ad + 44))((void *)*(u32 *)(coex_env + 8));
    else
        ((void (*)(u32))*(u32 *)((u8 *)ad + 20))(r);
}

/* coex_core_ts_start @ coexist_core.o 00000044 size 312B bind GLOBAL
 * Calls: none | Data refs: none
 * Fidelity: medium - exact phase skeleton + constants (200, evt 12/14, cbarg 18); force/unforce arm mapped at decision level */
void coex_core_ts_start(void)
{
    u8 *env = coex_env;
    u8 *cur;
    u8 *next;
    u32 now;
again:
    cur = *(u8 **)(env + 4);
    if (cur == 0)
        goto tail;
    {
        u32 evt = (cur[0] == 0) ? 12 : 14;
        coex_dbg_output(evt, 0);
        {
            u8 *st = *(u8 **)(env + 0);
            if (st != 0 && st[1] < cur[1]) {
                coex_timer_ts_end_disalarm();
                *(u8 **)(env + 0) = cur;
            }
        }
        next = (u8 *)coex_arbit_next(cur);
        *(u8 **)(env + 4) = next;
        if (next != 0) {
            if (coex_time_is_in_time(*(u32 *)(next + 4), 200) != 0)
                goto again;
            coex_timer_ts_start_alarm(coex_time_diff(*(u32 *)(next + 4), coex_time_now()));
        }
        {
            u8 *st0 = *(u8 **)(env + 0);
            if (st0 != 0 && coex_time_is_in_time(*(u32 *)(st0 + 8), 200) != 0) {
                *(u8 **)(env + 0) = 0;
                coex_arbit_clean_overtime(200);
                *(u8 **)(env + 4) = (u8 *)coex_arbit_first();
                return;
            }
            now = coex_time_now();
            coex_timer_ts_end_alarm(coex_time_diff(*(u32 *)(st0 + 8), now));
        }
    }
tail:
    {
        u8 *st0 = *(u8 **)(env + 0);
        u8 fa = *(env + 24);
        if (st0 == 0) {
            if (fa != 1)
                goto count;
            coex_unforce_wifi_mode();
            *(env + 24) = 0;
            if (*(u8 **)(env + 16) != 0)
                ((void (*)(u32, u32)) * (void **)(env + 16))(18, 0);
            goto count;
        }
        if (fa == 1) {
            if (st0[0] == 0)
                goto call16;
            coex_unforce_wifi_mode();
            *(env + 24) = st0[0];
            goto call16;
        }
        if (st0[0] != 1)
            goto call16;
        coex_force_wifi_mode(st0[0]);
        *(env + 24) = st0[0];
call16:
        if (*(u8 **)(env + 16) != 0)
            ((void (*)(u32, u32)) * (void **)(env + 16))(st0[2], *(u16 *)(st0 + 12));
count:
        if (st0 != 0)
            (*(u16 *)(st0 + 12))++;
    }
}

/* static coex_reschedule (.iram1.11; called from ts_end, request, release)
 * Calls: coex_timer_ts_start_disalarm, coex_timer_ts_end_disalarm, coex_arbit_first, coex_core_ts_start, coex_time_is_in_time, coex_time_now, coex_time_diff, coex_timer_ts_start_alarm | Data refs: coex_env
 * Fidelity: high - disalarm both, clear state, first or alarm(diff) */
static void coex_reschedule(void)
{
    u8 *env = coex_env;
    u8 *first;
    coex_timer_ts_start_disalarm();
    coex_timer_ts_end_disalarm();
    *(u8 **)(env + 0) = 0;
    first = (u8 *)coex_arbit_first();
    *(u8 **)(env + 4) = first;
    if (first == 0) {
        coex_core_ts_start();
        return;
    }
    if (coex_time_is_in_time(*(u32 *)(first + 4), 200) != 0)
        return;
    coex_timer_ts_start_alarm(coex_time_diff(*(u32 *)(first + 4), coex_time_now()));
}

/* coex_core_ts_end @ coexist_core.o 00000020 size 84B bind GLOBAL
 * Calls: none | Data refs: none
 * Fidelity: high - null-state printf (0x123) + hang; else dbg(13/15,1), clear, clean(200), reschedule */
void coex_core_ts_end(void)
{
    u8 *env = coex_env;
    u8 *st = *(u8 **)(env + 0);
    if (st == 0) {
        coexist_printf("[%u] %s %u\n",
                       ((u32 (*)(void))*(u32 *)((u8 *)*(void **)g_coa_funcs_p + 60))(),
                       "coexist_core.c", 0x123);
        for (;;) { }
    }
    coex_dbg_output((st[0] == 0) ? 13 : 15, 1);
    *(u8 **)(env + 0) = 0;
    coex_arbit_clean_overtime(200);
    coex_reschedule();
}

/* coex_timer_ts_start_handler @ coexist_core.o 00000010 size 38B bind GLOBAL
 * Calls: none | Data refs: none
 * Fidelity: high - lock; unless failed and not disalarmed: ts_start; unlock */
void coex_timer_ts_start_handler(void)
{
    if (coex_lock() != 0)
        return;
    if (coex_ts_start_timer_dislarmed() == 0)
        coex_core_ts_start();
    coex_unlock();
}

/* coex_timer_ts_end_handler @ coexist_core.o 00000010 size 38B bind GLOBAL
 * Calls: none | Data refs: none
 * Fidelity: high - lock; unless failed and not disalarmed: ts_end; unlock */
void coex_timer_ts_end_handler(void)
{
    if (coex_lock() != 0)
        return;
    if (coex_ts_end_timer_dislarmed() == 0)
        coex_core_ts_end();
    coex_unlock();
}

/* coex_core_request @ coexist_core.o 0000002c size 165B bind GLOBAL
 * Calls: none | Data refs: none
 * Fidelity: medium - exact codes (-1 lock, 0x103 idle); req build (prio_tab, w1=now+a4, w2=+a5+now) exact; insert+reschedule */
int coex_core_request(u32 owner, u32 event, u32 p4, u32 p5)
{
    u8 req[16];
    u32 now;
    int rc;
    coex_dbg_output(owner ? 4 : 0, 0);
    if (coex_lock() != 0) {
        coex_dbg_output(owner ? 5 : 1, 1);
        return -1;
    }
    if (*(u32 *)(coex_env + 12) == 0) {
        coex_unlock();
        return 0x103;
    }
    req[0] = (u8)owner;
    req[1] = coex_prio_tab[event];
    req[2] = (u8)event;
    /* req[3] unwritten (stack garbage, copied by the 16B memcpy) */
    now = coex_time_now();
    *(u32 *)(req + 4) = now + p4;
    *(u32 *)(req + 8) = p4 + p5 + coex_time_now();
    *(u16 *)(req + 12) = 0; /* disasm stores lock result (0 here) */
    rc = (int)coex_arbit_insert(req);
    if (rc == 0)
        coex_reschedule();
    coex_unlock();
    coex_dbg_output(owner ? 5 : 1, 1);
    return rc;
}

/* coex_core_release @ coexist_core.o 0000002c size 180B bind GLOBAL
 * Calls: none | Data refs: none
 * Fidelity: medium - exact codes; delete then conditional disalarms (event-byte match) + reschedule */
int coex_core_release(u32 owner, u32 event)
{
    u8 req[16];
    int rc;
    coex_dbg_output(owner ? 6 : 2, 0);
    if (coex_lock() != 0) {
        coex_dbg_output(owner ? 3 : 7, 1);
        return -1;
    }
    if (*(u32 *)(coex_env + 12) == 0) {
        rc = 0x103;
        goto out;
    }
    req[0] = (u8)owner;
    req[1] = coex_prio_tab[event];
    req[2] = (u8)event;
    rc = (int)coex_arbit_delete(req);
    if (rc != 0)
        goto out;
    {
        u8 *st = *(u8 **)(coex_env + 0);
        if (st != 0 && req[2] == st[2]) {
            coex_timer_ts_end_disalarm();
            *(u8 **)(coex_env + 0) = 0;
        }
        st = *(u8 **)(coex_env + 4);
        if (st != 0 && req[2] == ((u8 *)st)[2]) {
            coex_timer_ts_start_disalarm();
            *(u8 **)(coex_env + 4) = 0;
        }
    }
    coex_reschedule();
    rc = 0;
out:
    coex_unlock();
    coex_dbg_output(owner ? 3 : 7, 1);
    return rc;
}

/* coex_core_event_duration_get @ coexist_core.o 00000004 size 101B bind GLOBAL
 * Calls: none | Data refs: g_coex_param
 * Fidelity: high - event 4/7/9/39/40 -> param slots 0/1/2/3/4, 0 ok; else *out=0, -1 */
int coex_core_event_duration_get(u32 event, u32 *out)
{
    u32 *param = (u32 *)g_coex_param; /* {25000,5000,20000,25000,50000} */
    u32 val;
    if (out == 0)
        return -1;
    if (event == 9)
        val = param[2];
    else if (event > 9) {
        if (event == 39)
            val = param[3];
        else if (event == 40)
            val = param[4];
        else
            goto unknown;
    } else if (event == 4)
        val = param[0];
    else if (event == 7)
        val = param[1];
    else
        goto unknown;
    *out = val;
    return 0;
unknown:
    *out = 0;
    return -1;
}

/* coex_core_pre_init @ coexist_core.o 0000002c size 170B bind GLOBAL
 * Calls: coex_gpio_init, coex_schm_init, coexist_printf | Data refs: .dram1.20, .dram1.21, .dram1.22, coex_bb_rst_mux, coex_env, coex_gpio_init, coex_schm_init, coexist_printf, g_coa_funcs_p
 * Fidelity: medium - adapter+24 sema, adapter+4 bb mux, schm_init, gpio_init; error strings + adapter+28/+8 cleanup exact */
int coex_core_pre_init(void)
{
    u32 r;
    if (*(u32 *)(coex_env + 8) == 0) {
        r = ((u32 (*)(void))*(u32 *)((u8 *)*(void **)g_coa_funcs_p + 24))();
        *(u32 *)(coex_env + 8) = r;
        if (r == 0) {
            coexist_printf("[%u] CO: create semaphore error!\n",
                           ((u32 (*)(void))*(u32 *)((u8 *)*(void **)g_coa_funcs_p + 60))());
            return 0x101;
        }
    }
    if (*(void **)coex_bb_rst_mux == 0) {
        r = ((u32 (*)(void))*(u32 *)((u8 *)*(void **)g_coa_funcs_p + 4))();
        *(void **)coex_bb_rst_mux = (void *)r;
        if (r == 0) {
            coexist_printf("[%u] CO: create bb reset mutex error!\n",
                           ((u32 (*)(void))*(u32 *)((u8 *)*(void **)g_coa_funcs_p + 60))());
            ((void (*)(void *))*(u32 *)((u8 *)*(void **)g_coa_funcs_p + 28))((void *)*(u32 *)(coex_env + 8));
            return 0x101;
        }
    }
    r = coex_schm_init();
    if (r != 0) {
        coexist_printf("[%u] CO: init coex schm error!\n",
                       ((u32 (*)(void))*(u32 *)((u8 *)*(void **)g_coa_funcs_p + 60))());
        ((void (*)(void *))*(u32 *)((u8 *)*(void **)g_coa_funcs_p + 8))(*(void **)coex_bb_rst_mux);
        return 0x101;
    }
    coex_gpio_init();
    return 0;
}

/* coex_core_init @ coexist_core.o 00000000 size 7B bind GLOBAL
 * Calls: none | Data refs: none
 * Fidelity: high - stub: entry/retw only, returns 0 */
u32 coex_core_init(void)
{
    return 0;
}

/* coex_core_deinit @ coexist_core.o 00000000 size 7B bind GLOBAL
 * Calls: none | Data refs: none
 * Fidelity: high - stub: entry/retw only, returns 0 */
u32 coex_core_deinit(void)
{
    return 0;
}

/* coex_core_enable @ coexist_core.o 00000048 size 244B bind GLOBAL
 * Calls: .iram1.7, .iram1.8, coex_arbit_deinit, coex_arbit_init, coex_timer_deinit, coex_timer_init, coexist_printf | Data refs: .bss.coex_enabled_ref, .dram1.23, .dram1.24, .iram1.7, .iram1.8, .rodata.str1.1, coex_arbit_deinit, coex_arbit_init, coex_env, coex_fwm_mux, coex_timer_deinit, coex_timer_init, coex_timer_ts_end_handler, coex_timer_ts_start_handler, coexist_printf, g_coa_funcs_p
 * Fidelity: medium - refcount (2nd ref inits), timer+arbit init, fwm mux, status=1, start_cb; unwind exact; returns init rc */
int coex_core_enable(void)
{
    int rc;
    if (((u32 (*)(void))*(u32 *)((u8 *)*(void **)g_coa_funcs_p + 48))() != 0) {
        coexist_printf("[%u] %s %u\n", 0, "coexist_core.c", 0x21a);
        for (;;) { }
    }
    if (coex_lock() != 0)
        return -1;
    coex_enabled_ref++;
    if (coex_enabled_ref != 2) {
        coex_unlock();
        return 0;
    }
    rc = (int)coex_timer_init(coex_timer_ts_start_handler, coex_timer_ts_end_handler);
    if (rc != 0)
        goto unwind;
    rc = (int)coex_arbit_init();
    if (rc != 0)
        goto unwind;
    *(u8 **)(coex_env + 0) = 0;
    *(u8 **)(coex_env + 4) = 0;
    *(void **)coex_fwm_mux = (void *)((u32 (*)(void))*(u32 *)((u8 *)*(void **)g_coa_funcs_p + 4))();
    if (*(void **)coex_fwm_mux == 0) {
        coexist_printf("[%u] CO: create fwn mutex error!\n",
                       ((u32 (*)(void))*(u32 *)((u8 *)*(void **)g_coa_funcs_p + 60))());
        goto unwind;
    }
    *(u32 *)(coex_env + 12) = 1;
    coex_unlock();
    if (*(u8 **)(coex_env + 28) != 0)
        (*(void (*)(void))*(u8 **)(coex_env + 28))();
    return 0;
unwind:
    coex_timer_deinit();
    coex_arbit_deinit();
    if (*(void **)coex_fwm_mux != 0) {
        ((void (*)(void *))*(u32 *)((u8 *)*(void **)g_coa_funcs_p + 8))(*(void **)coex_fwm_mux);
        *(void **)coex_fwm_mux = 0;
    }
    coex_enabled_ref--;
    coex_unlock();
    return rc;
}

/* coex_core_disable @ coexist_core.o 00000038 size 178B bind GLOBAL
 * Calls: .iram1.7, .iram1.8, coex_arbit_deinit, coex_timer_deinit, coex_timer_ts_end_disalarm, coex_timer_ts_start_disalarm, coex_unforce_wifi_mode, coexist_printf | Data refs: .bss.coex_enabled_ref, .dram1.25, .iram1.7, .iram1.8, .rodata.str1.1, coex_arbit_deinit, coex_env, coex_fwm_mux, coex_timer_deinit, coex_timer_ts_end_disalarm, coex_timer_ts_start_disalarm, coex_unforce_wifi_mode, coexist_printf, g_coa_funcs_p
 * Fidelity: medium - refcount down; last ref tears down timers/arbit/fwm mux; force-state restore exact */
int coex_core_disable(void)
{
    if (((u32 (*)(void))*(u32 *)((u8 *)*(void **)g_coa_funcs_p + 48))() != 0) {
        coexist_printf("[%u] %s %u\n", 0, "coexist_core.c", 0x257);
        for (;;) { }
    }
    if (coex_lock() != 0)
        return -1;
    coex_enabled_ref--;
    if (coex_enabled_ref != 0) {
        coex_unlock();
        return 0;
    }
    *(u32 *)(coex_env + 12) = 0;
    coex_timer_ts_start_disalarm();
    coex_timer_ts_end_disalarm();
    {
        u8 *st = *(u8 **)(coex_env + 0);
        if (st != 0 && st[0] == 1) {
            coex_unforce_wifi_mode();
            if (*(u8 **)(coex_env + 16) != 0)
                ((void (*)(u32, u32)) * (void **)(coex_env + 16))(18, 0);
        }
    }
    coex_timer_deinit();
    coex_arbit_deinit();
    if (*(void **)coex_fwm_mux != 0) {
        ((void (*)(void *))*(u32 *)((u8 *)*(void **)g_coa_funcs_p + 8))(*(void **)coex_fwm_mux);
        *(void **)coex_fwm_mux = 0;
    }
    coex_unlock();
    return 0;
}

/* coex_core_status_get @ coexist_core.o 00000004 size 10B bind GLOBAL
 * Calls: none | Data refs: none
 * Fidelity: high - returns env+12 word */
u32 coex_core_status_get(void)
{
    return *(u32 *)(coex_env + 12);
}

/* coex_core_register_cb @ coexist_core.o 0000000c size 53B bind GLOBAL
 * Calls: .iram1.7, .iram1.8 | Data refs: .iram1.7, .iram1.8, coex_env
 * Fidelity: high - lock; owner0 -> env+16, owner1 -> env+20, else ignore; unlock; return lock rc */
int coex_core_register_cb(u32 owner, void *cb)
{
    int rc = coex_lock();
    if (rc != 0)
        return 0x103;
    if (owner == 0)
        *(void **)(coex_env + 16) = cb;
    else if (owner == 1)
        *(void **)(coex_env + 20) = cb;
    coex_unlock();
    return rc;
}

/* coex_core_bb_reset_lock @ coexist_core.o 0000000c size 50B bind GLOBAL
 * Calls: none | Data refs: none
 * Fidelity: medium - flag(.dram1.4)=0; mux null -> return 0 else flag=1, adapter+12 take, return rc */
u32 coex_core_bb_reset_lock(void)
{
    coex_bb_rst_flag = 0;
    if (*(void **)coex_bb_rst_mux == 0)
        return 0;
    coex_bb_rst_flag = 1;
    return ((u32 (*)(void))*(u32 *)((u8 *)*(void **)g_coa_funcs_p + 12))();
}

/* coex_core_bb_reset_unlock @ coexist_core.o 0000000c size 32B bind GLOBAL
 * Calls: none | Data refs: none
 * Fidelity: high - mux null or flag clear -> return arg; else adapter+16 give(mux), return arg */
u32 coex_core_bb_reset_unlock(u32 arg)
{
    if (*(void **)coex_bb_rst_mux == 0)
        return arg;
    if (coex_bb_rst_flag == 0)
        return arg;
    ((void (*)(void *))*(u32 *)((u8 *)*(void **)g_coa_funcs_p + 16))(*(void **)coex_bb_rst_mux);
    return arg;
}

/* coex_core_register_start_cb @ coexist_core.o 0000000c size 37B bind GLOBAL
 * Calls: .iram1.7, .iram1.8 | Data refs: .iram1.7, .iram1.8, coex_env
 * Fidelity: high - lock; store start_cb at env+28; unlock; lock-fail -> 0x103 */
int coex_core_register_start_cb(void *cb)
{
    int rc = coex_lock();
    if (rc != 0)
        return 0x103;
    *(void **)(coex_env + 28) = cb;
    coex_unlock();
    return rc;
}
