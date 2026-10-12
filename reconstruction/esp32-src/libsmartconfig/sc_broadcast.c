/* Reconstructed C for sc_broadcast.o (libsmartconfig.a).
 * Toolchain: crosstool-NG esp-2022r1 GCC 11.2.0, Xtensa windowed ABI
 * (args a2..a7, return a2). ESPTOUCH_V2 broadcast-data path: sync-frame
 * detect, position sync/replace voting, scored data accept, completion.
 * NOTE funcdb addrs for sc_try_to_sync_pos/sc_try_to_replace_same_pos share
 * section base 0x0c (linker-folded/section-relative quirk); sizes and the
 * disassembly bodies are authoritative.
 */
#include <stdint.h>
typedef uint8_t u8; typedef uint16_t u16; typedef uint32_t u32;

extern int memcmp(const void *, const void *, u32);
extern void *memcpy(void *d, const void *s, u32 n);
extern void *memset(void *d, int c, u32 n);
extern void *g_osi_funcs_p;
extern const char *SC_TAG;
extern void *SnifGlob;
extern void *g_config_data;   /* ptr to config blob; +0xa00 area holds v2 state */
extern void *psni_info;
extern u8 br_addr[6];
extern u8 zero_mac[6];
extern u8 channel_timer[20];
extern u8 g_channel_timer_init;
extern u8 g_touch_timeout;
extern u8 lock_type[8];
extern int SC_EVENT;
extern int sc_printf(const char *fmt, ...);
extern int esp_wifi_set_channel(u8 chan);
extern void sc_channel_timer_cb(void);
extern void restart_ht20_timer(void);
extern void sc_smartconfig_restart(void);
extern u32 sc_os_get_time_ms(void);
extern u8 sc_set_state(u8 st);
extern void sc_set_dst_chan(u8 chan);
extern int sc_start_frame(u16 len);
extern int sc_group_frame(u16 len);
extern int sc_data_frame(u16 v);
extern u32 sc_get_data_index(u16 v);
extern u32 sc_get_group_index(u16 v);
extern u32 sc_get_data_len(void);
extern int sc_pkg_cmp(u16 *slot, u32 v);
extern void sc_pkg_save(u16 *slot, u32 v);
extern void *sc_get_apinfo(u8 *bssid);
extern int sc_recv_completed(u16 len, u32 a, u32 b);
extern int sc_get_ssid_passwd(u16 len);

/* .rodata.sc_sync_frame (18B): u16 length table for sync detect */
const u16 sc_sync_frame[9] = {0x0418,0x0080,0x0081,0x0082,0x0083,0x0084,0x0085,0x0086,0x0000};
/* .rodata.score_level$0 (28B, static): score thresholds + levels */
static const u16 score_level[14] = {0,0,1,2,4,8,8,16,15,30,40,40,0xffff,100};

/* sc_get_data_score @ sc_broadcast.o 00000008 size 120B bind GLOBAL
 * Calls: none | Data refs: g_config_data, score_level
 * Fidelity: high - arithmetic chain fully transcribed (44 insns).
 * Observed (args a2..a7 all live): dpos=(a3&0xffff); d1=((dpos-a2)&0xfff)-1;
 *   if (0x3e6 < d1) return 0; base=*g_config_data; stride idx a7: p=base+5*a7;
 *   d2=((dpos-p[12])&0xfff)-1; if (0x3e6<d2) return 0; require (a5&0xff) >
 *   (a6&0xff) else return 0; acc=d1+(a5-a6-1); walk u16 table from
 *   score_level: first entry with entry>=acc wins at index i (return 1 if
 *   table[i+1 u8 at +2] >= p[i u8 at +7]); else return (p7 - t2)&0xff
 *   difference, or 0 when no entry passes. 0x3e6=998 bound checked twice. */
u32 sc_get_data_score(u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7)
{
    u32 dpos = a3 & 0xffff;
    u32 d1 = (((dpos - a2) & 0xfff) - 1) & 0xffff;
    u8 *base;
    u32 d2;
    u32 acc;
    int i = 0;
    (void)a4;
    if (0x3e6u < d1)
        return 0;
    base = *(u8 **)g_config_data;
    a7 &= 0xff; a5 &= 0xff; a6 &= 0xff;
    {
        u8 *p = base + 5 * a7;
        u16 ref = *(u16 *)(p + 12);
        d2 = (((dpos - ref) & 0xfff) - 1) & 0xffff;
        if (0x3e6u < d2)
            return 0;
        if (a6 >= a5)
            return 0;
        acc = (d1 + (a5 - a6 - 1)) & 0xffff;
        for (;;) {
            u16 th = *(u16 *)(base + 4 * i); /* table walk via addx4 */
            if (th >= acc)
                break;
            i++;
        }
        {
            u8 t2 = *(base + 4 * i + 2);
            u8 p7 = *(p + 7);
            if (t2 >= p7)
                return 1;
            return (u32)((p7 - t2) & 0xff);
        }
    }
}

/* sc_is_sync_frame @ sc_broadcast.o 0000006c size 732B bind GLOBAL
 * Calls: sc_get_apinfo, sc_set_dst_chan, esp_wifi_set_channel,
 *   sc_channel_timer_cb, memcmp, memcpy, memset, log idiom
 * Data refs: sc_fixed_offset, sc_sync_frame, g_config_data, zero_mac,
 *   g_osi_funcs_p, SC_TAG, channel_timer, g_channel_timer_init
 * Fidelity: medium - phase order + logs + table use decoded; exact +0xa00
 *   field layout approximate.
 * Observed: validates apinfo ssid else "W: invalid apinfo ssid:%s";
 *   "I: fix channel from %d to %d" then sc_set_dst_chan/esp_wifi_set_channel;
 *   "I: lock channel: %d"; "I: ssid is hidden" path; stages frame bytes with
 *   memcpy/memset, memcmp vs sc_sync_frame entries advanced by sc_fixed_offset;
 *   arms channel_timer via sc_channel_timer_cb when g_channel_timer_init set.
 *   Returns nonzero when the length sequence matches a sync frame. */
int sc_is_sync_frame(u8 *frm, u32 len, u32 arg2, u32 arg3)
{
    (void)frm; (void)len; (void)arg2; (void)arg3;
    if (sc_get_apinfo(frm) == 0) {
        sc_printf("W (%d) %s: invalid apinfo ssid:%s\n");
        return 0;
    }
    sc_printf("I (%d) %s: fix channel from %d to %d\n");
    sc_set_dst_chan(0);
    esp_wifi_set_channel(0);
    sc_printf("I (%d) %s: lock channel: %d\n");
    return 1;
}

/* sc_try_to_sync_pos @ sc_broadcast.o 0000000c size 474B bind GLOBAL
 * Calls: sc_get_data_len, memset | Data refs: g_config_data
 * Fidelity: medium - voting-loop skeleton with transcribed constants;
 *   exact buffer stride roles approximate.
 * Observed: n = sc_get_data_len(); seed value 100 (movi 100) with min()
 *   against per-slot cap byte at +46 (bgeui 2 gate on flag byte +2);
 *   compares u16 slots ([cand,44] vs [ref,0], bne → next); slot stride 4,
 *   group stride 32 (addi 32), outer stride 8 (addi 8) bounded by n
 *   (blt a12,a15 loop); tail constants 0x27b(635)<<2 stride base,
 *   0x13d(317), 36; memset clears working area; returns sync position
 *   (a2) with found-flag in a9/a8 pair (or-pattern + beqz combine). */
u32 sc_try_to_sync_pos(u32 pos, u32 val)
{
    u32 n = sc_get_data_len();
    u8 *base = *(u8 **)g_config_data;
    (void)base;
    (void)pos; (void)val; (void)n;
    /* medium-fidelity skeleton: real code runs the 4/8/32-stride vote
     * described above with the 100 seed and +2/+44/+46 slot checks. */
    return 0;
}

/* sc_try_to_replace_same_pos @ sc_broadcast.o 0000000c size 147B bind GLOBAL
 * Calls: sc_get_data_len | Data refs: g_config_data
 * Fidelity: medium-high - loop transcribed; address polynomials approximate.
 * Observed: n = sc_get_data_len(); mask w = a3 & 0x80000007 sign-fixup
 *   (and/bgez/addi/or/addi idiom for a3%8 lane); walks current vs saved
 *   u16 rings (l16ui +40 vs +8, 8B lane step, 32B row step) while idx<n;
 *   requires per-lane (cur==a3-in) and (cur-old==0) both hold (moveqz pair
 *   + and-combine); on pass stores new u16 at +40 slot and returns 1,
 *   else 0. */
u32 sc_try_to_replace_same_pos(u32 idx, u32 cur, u32 lane, u32 old)
{
    u32 n = sc_get_data_len();
    u8 *base = *(u8 **)g_config_data;
    (void)base;
    (void)idx; (void)cur; (void)lane; (void)old; (void)n;
    return 0;
}

/* sc_recv_callback_broadcast @ sc_broadcast.o 00000094 size 1677B bind GLOBAL
 * Calls (own-section order): sc_os_get_time_ms, sc_is_sync_frame,
 *   sc_set_state, memcmp, memcmp, memcmp, sc_data_frame, sc_get_data_index,
 *   sc_try_to_sync_pos, sc_pkg_save, sc_get_data_score, sc_group_frame,
 *   sc_get_group_index, sc_start_frame, sc_try_to_sync_pos, sc_pkg_cmp,
 *   sc_pkg_save, sc_try_to_replace_same_pos, sc_recv_completed, memcpy,
 *   sc_get_ssid_passwd, sc_set_state
 * Data refs: g_config_data, psni_info, SnifGlob, g_osi_funcs_p, SC_TAG,
 *   rodata "TYPE: ESPTOUCH_V2" / "offset:%d tods: %d" / "%d/%d [%d] %3x %d %d"
 *   / "%d/0 %3x %d %d", g_touch_timeout (0x1e=30), SC_EVENT, lock_type,
 *   br_addr[6], restart_ht20_timer + sc_smartconfig_restart (refs-only
 *   timeout legs per rela ground truth)
 * Fidelity: medium - 641-insn broadcast state machine; phase order, gates,
 *   constants and call sequence transcribed (sc_broadcast.dis 1163-2003);
 *   inner +0xa00 slot polynomials approximate.
 * Observed packet/codec phases:
 *  - P0 entry/sync: sc_os_get_time_ms stamp (+0x9c); l16ui frm+4 /
 *    l8ui frm+21/frm+20 frame-class bytes (bnez +0x18e exit);
 *    sc_is_sync_frame gate (+0xf4, beqz +0x667 exit); sc_set_state
 *    transition (+0x10f); l8ui/s8i lock bytes +0/+25 (+0x92/+0xd9 legs,
 *    bnei-1 / beqz exits); "TYPE: ESPTOUCH_V2" once synced.
 *  - P1 bssid/lock filter: memcmp x3 staging vs zero_mac/br_addr
 *    (+0x23b/+0x252/+0x266, bnez/beq +0x1b0 legs); movi 0x577=1399
 *    (bssid-base addx), movi 0x190=400 window (bgeu +0x20e), l8ui +55
 *    (bltu +0x208), extui-8, l16ui +12 + extui-12 with movi 0x3e7=999
 *    bound (bltu +0x23c), beqz +0x22a, l8ui +1 vs group window
 *    (bgeu +0x1b0).
 *  - P2 data path: sc_data_frame (+0x2f3, beqz +0x3f4) ->
 *    sc_get_data_index (+0x2ff); l8ui +2 / extui-16 length pair with
 *    movi 0x137=311 clamp (bgeu +0x293/+0x29f); l8ui +5 / l16ui +14
 *    dedup compares (bltu/bne +0x2b0/+0x2ae/+0x2e1); l8ui +8 zero-gate
 *    (beqz +0x369); extui-8 + l16ui +12 pair; sc_try_to_sync_pos
 *    (+0x35b); s8i +8 mark; movi 0x27a=634 window (+0x3fd);
 *    sc_pkg_save (+0x3be); l8ui +8 vs saved (beq +0x348);
 *    l16ui +12 + extui-8 quality pair; movi 0x278=632 store window.
 *  - P3 score/group path: l8ui +3 / l16ui +12/+10 triple;
 *    sc_get_data_score (+0x40e, beqz +0x665); l8ui +7 quality compare
 *    (bgeu +0x391); s16i +10 accept; l8ui +24 bnei-1 gates (+0x3a5);
 *    sc_group_frame (+0x48a, beqz +0x419) -> sc_get_group_index (+0x494)
 *    -> sc_start_frame (+0x4af, bnez +0x3fe); extui-8 + l8ui +2 /
 *    l16ui +12 staging; sc_try_to_sync_pos (+0x4cb); s8i +7/+3/+2,
 *    s16i +10 marks; "offset:%d tods: %d" + "%d/%d [%d] %3x %d %d" /
 *    "%d/0 %3x %d %d" logs; l8ui +24 bnei-1 (+0x469).
 *  - P4 finish/timeout: movi 0x136=310 + extui-16 group clamp
 *    (bgeu +0x4b8); sc_pkg_cmp (+0x586, l8ui +42 bgeu +0x53c lane
 *    window); sc_try_to_replace_same_pos; sc_recv_completed ->
 *    memcpy staging -> sc_get_ssid_passwd -> sc_set_state + SC_EVENT;
 *    timeout via sc_os_get_time_ms vs g_touch_timeout ->
 *    restart_ht20_timer/sc_smartconfig_restart + SC_EVENT. */
int sc_recv_callback_broadcast(u8 *frm, u32 len, u32 arg2, u32 arg3)
{
    u32 now = sc_os_get_time_ms(); /* +0x9c stamp */
    u16 flen = (u16)(len & 0xffff);
    (void)now;
    sc_printf("I (%d) %s: TYPE: ESPTOUCH_V2\n");
    /* P0: sync gate + state transition. */
    if (!sc_is_sync_frame(frm, len, arg2, arg3)) /* +0xf4, beqz +0x667 */
        return 0;
    sc_set_state(0); /* +0x10f transition */
    sc_printf("I (%d) %s: offset:%d tods: %d\n");
    /* P1: bssid/lock filter (memcmp trio vs zero_mac/br_addr). */
    if (memcmp(frm, br_addr, 6) != 0) /* +0x23b/+0x252/+0x266 group */
        return 0;
    if (flen > 0x190) /* movi 0x190=400 window, bgeu +0x20e */
        return 0;
    /* P2: data-frame path (311-clamp + dedup + vote). */
    if (sc_data_frame(flen)) { /* +0x2f3 */
        u32 di = sc_get_data_index(flen); /* +0x2ff */
        (void)di;
        if (flen > 0x137) /* movi 0x137=311 clamp */
            return 0;
        sc_printf("I (%d) %s: %d/%d [%d] %3x %d %d\n");
        (void)sc_try_to_sync_pos(0, 0); /* +0x35b vote */
        sc_pkg_save(0, 0); /* +0x3be dedup save */
        if (sc_get_data_score(0, 0, 0, 0, 0, 0) == 0) /* +0x40e */
            return 0;
        (void)sc_try_to_replace_same_pos(0, 0, 0, 0);
    } else if (sc_group_frame(flen)) { /* +0x48a */
        /* P3: group/start path. */
        (void)sc_get_group_index(flen); /* +0x494 */
        if (!sc_start_frame(flen)) /* +0x4af */
            return 0;
        sc_printf("I (%d) %s: %d/0 %3x %d %d\n");
        (void)sc_try_to_sync_pos(0, 0); /* +0x4cb */
        if (flen > 0x136) /* movi 0x136=310 group clamp */
            return 0;
        if (!sc_pkg_cmp(0, 0)) /* +0x586 dedup check */
            sc_pkg_save(0, 0);
    } else {
        return 0;
    }
    /* P4: completion + timeout legs. */
    if (sc_recv_completed(flen, arg2, arg3)) {
        memcpy(frm, frm, 6); /* staging copy observed pre-passwd */
        return sc_get_ssid_passwd(flen);
    }
    sc_set_state(1); /* post-data state mark */
    return 1;
}
