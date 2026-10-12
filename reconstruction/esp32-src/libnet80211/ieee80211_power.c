/* ieee80211_power.o - reconstructed control-path C (offline, from objdump -d -r).
 * 16 code sections recovered. Fidelity per function below.
 * Conventions: args a2..a7 (Xtensa windowed ABI); outgoing call args
 * traced as a10..; u32 used for pointers/regs; opaque_* marks unrecovered.
 */
#include <stdint.h>
typedef unsigned char u8; typedef unsigned short u16; typedef unsigned int u32;
static u32 opaque_result, last_call_result;
/* ---- externals (U symbols + literal refs) ---- */
extern u32 rodata_wlog_info_2; /* .rodata_wlog_info.2 */
extern u32 chm_is_at_home_channel(); /* chm_is_at_home_channel */
extern u32 g_hmac_cnt; /* g_hmac_cnt */
extern u32 g_ic; /* g_ic */
extern u32 g_ic_0x1af; /* g_ic+0x1af */
extern u32 g_wifi_menuconfig; /* g_wifi_menuconfig */
extern u32 g_wifi_nvs; /* g_wifi_nvs */
extern u32 hal_now(); /* hal_now */
extern u32 ic_ebuf_recycle_tx(); /* ic_ebuf_recycle_tx */
extern u32 ic_tx_pkt(); /* ic_tx_pkt */
extern u32 memset(); /* memset */
extern u32 wifi_log(); /* wifi_log */

/* ROLE: power-save queues: psq (per-STA buffered frames), gpsq,
 * pwrsave flush/tx-complete callbacks. Backed by g_ic + g_wifi_nvs.
 */
/* ---- literal-rooted access patterns (offsets observed; layout NOT confirmed) ----
 * *(g_ic+20): u32+240
 * *(g_ic+236): u32+12
 * ?: u32+4, u32+16, u8+44, u32+44
 * g_hmac_cnt: u16+50, u16+52, u32+424
 * g_ic: u32+20, u32+20, u32+236, u32+424
 * g_wifi_menuconfig: u32+8, u32+12, u32+16
 * g_wifi_nvs: u32+0
/* ---- funcdb-v2 cross-check (calls[] vs section relocs; disasm is ground truth) ----
 * confirmed funcdb edges: 21; rejected funcdb-only (no exact reloc in
 * callee section; caller-side .rela.text.<f> prefix-collision artifacts): 0;
 * disasm-only edges kept (static-local callees + funcdb relsec:null gaps): 3;
 */
/* ==== functions of ieee80211_power.o ==== */

/* ieee80211_psq_init @ ieee80211_power.o 0x00000004 size 25B bind GLOBAL
 * Calls: memset | Data refs: none
 * Fidelity: high - straight-line, fully mapped (10 insns) */
u32 ieee80211_psq_init(u32 a2)
{
    /* frame: entry a1,32; 10 insns, 0 cond-branches, 0 loops, 0 jumps */
    /* immediates: 40, 0, 10 */
    /* mem st32: base=(?) off=8 */
    /* site +0x11: memset(?, 0, 40) */
    memset(?, 0, 40);
    return opaque_result; /* full dataflow not recovered */
}

/* ieee80211_gpsq_init @ ieee80211_power.o 0x00000010 size 55B bind GLOBAL
 * Calls: memset, wifi_log | Data refs: g_wifi_menuconfig, .rodata_wlog_info.2
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 ieee80211_gpsq_init(u32 a2)
{
    /* frame: entry a1,32; 22 insns, 1 cond-branches, 0 loops, 1 jumps */
    /* immediates: 20, 0, 3, 16, 1 */
    /* first predicate: bnez.n a9, 2c <ieee80211_gpsq_init+0x1c> (condition opaque) */
    /* mem ld32: base=(lit:g_wifi_menuconfig) off=8 */
    /* mem ld32: base=(lit:g_wifi_menuconfig) off=12 */
    /* mem ld32: base=(lit:g_wifi_menuconfig) off=16 */
    /* mem st32: base=(?) off=4 */
    /* site +0x1d: memset(?, 0, 20) */
    memset(?, 0, 20);
    /* site +0x42: wifi_log(1, 16, 3, lit:.rodata_wlog_info.2, (*(g_wifi_menuconfig+16) srai 1)) */
    wifi_log(1, 16, 3, lit:.rodata_wlog_info.2, (*(g_wifi_menuconfig+16) srai 1));
    return opaque_result; /* full dataflow not recovered */
}

/* ieee80211_psq_cleanup @ ieee80211_power.o 0x00000000 size 5B bind GLOBAL
 * Calls: none | Data refs: none
 * Fidelity: high - straight-line, fully mapped (2 insns) */
u32 ieee80211_psq_cleanup(void)
{
    /* frame: entry a1,32; 2 insns, 0 cond-branches, 0 loops, 0 jumps */
    return opaque_result; /* full dataflow not recovered */
}

/* ieee80211_psq_find_max_bss @ ieee80211_power.o 0x00000008 size 51B bind GLOBAL
 * Calls: none | Data refs: g_ic, g_wifi_nvs
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 ieee80211_psq_find_max_bss(u32 a2)
{
    /* frame: entry a1,32; 20 insns, 3 cond-branches, 0 loops, 1 jumps */
    /* immediates: 0 */
    /* first predicate: beqz.n a11, 34 <ieee80211_psq_find_max_bss+0x2c> (condition opaque) */
    /* mem ld32: base=(lit:g_ic) off=20 */
    /* mem ld32: base=(lit:g_wifi_nvs) off=0 */
    /* mem ld8: base=((*(g_wifi_nvs+0)+196608)) off=246 */
    /* mem ld32: base=(*(g_ic+20)) off=240 */
    /* mem ld32: base=(*(*(g_ic+20)+240)) off=0x108 */
    return *(*(g_ic+20)+240);
}

/* ieee80211_set_tim @ ieee80211_power.o 0x00000008 size 141B bind GLOBAL
 * Calls: none | Data refs: g_ic, g_ic+0x1af
 * Fidelity: medium - branchy but loop-free, call sequence mapped (weak) */
u32 ieee80211_set_tim(u32 a2, u32 a3, u32 a4)
{
    /* frame: entry a1,32; 47 insns, 4 cond-branches, 0 loops, 1 jumps */
    /* immediates: 1, 0, -1, -2 */
    /* first predicate: beq a3, a13, 88 <ieee80211_set_tim+0x80> (condition opaque) */
    /* mem ld32: base=(lit:g_ic) off=20 */
    /* mem ld16: base=(?) off=38 */
    /* mem ld32: base=(*(g_ic+20)) off=236 */
    /* mem ld8: base=(?) off=0 */
    /* mem st8: base=(?) off=0 */
    /* mem ld8: base=((lit:g_ic+65536)) off=174 */
    /* mem st8: base=((lit:g_ic+65536)) off=174 */
    /* mem st8: base=(?) off=0 */
    /* mem ld8: base=(((lit:g_ic+65536)+65536)) off=174 */
    /* mem st8: base=(((lit:g_ic+65536)+65536)) off=174 */
    return opaque_result; /* full dataflow not recovered */
}

/* ieee80211_psq_take_head @ ieee80211_power.o 0x00000004 size 65B bind GLOBAL
 * Calls: none | Data refs: g_ic
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 ieee80211_psq_take_head(u32 a2)
{
    /* frame: entry a1,32; 28 insns, 2 cond-branches, 0 loops, 1 jumps */
    /* immediates: 0 */
    /* first predicate: bne a11, a2, 24 <ieee80211_psq_take_head+0x20> (condition opaque) */
    /* mem ld32: base=(lit:g_ic) off=20 */
    /* mem ld32: base=(?) off=20 */
    /* mem ld32: base=(?) off=16 */
    /* mem st32: base=(?) off=20 */
    /* mem st32: base=(?) off=16 */
    /* mem ld32: base=(*(?+16)) off=40 */
    /* mem st32: base=(?) off=16 */
    /* mem st32: base=(*(?+16)) off=40 */
    /* mem ld32: base=(?) off=24 */
    /* mem st32: base=(?) off=24 */
    /* ... +4 more memops */
    return opaque_result; /* full dataflow not recovered */
}

/* ieee80211_psq_take_tail @ ieee80211_power.o 0x00000004 size 69B bind GLOBAL
 * Calls: none | Data refs: g_ic
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 ieee80211_psq_take_tail(u32 a2)
{
    /* frame: entry a1,32; 30 insns, 3 cond-branches, 0 loops, 1 jumps */
    /* immediates: 0 */
    /* first predicate: bne a9, a2, 21 <ieee80211_psq_take_tail+0x1d> (condition opaque) */
    /* mem ld32: base=(?) off=16 */
    /* mem ld32: base=(lit:g_ic) off=20 */
    /* mem ld32: base=(?) off=20 */
    /* mem st32: base=(?) off=20 */
    /* mem st32: base=(?) off=16 */
    /* mem ld32: base=(0) off=40 */
    /* mem st32: base=(?) off=20 */
    /* mem st32: base=(0) off=40 */
    /* mem ld32: base=(?) off=24 */
    /* mem st32: base=(?) off=24 */
    /* ... +4 more memops */
    return opaque_result; /* full dataflow not recovered */
}

/* ieee80211_psq_drop_one_pkt @ ieee80211_power.o 0x00000014 size 87B bind GLOBAL
 * Calls: ieee80211_psq_take_head, ic_ebuf_recycle_tx, ieee80211_set_tim | Data refs: g_ic, g_hmac_cnt
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 ieee80211_psq_drop_one_pkt(u32 a2, u32 a3)
{
    /* frame: entry a1,32; 32 insns, 2 cond-branches, 0 loops, 0 jumps */
    /* immediates: 0x108 */
    /* first predicate: beqz.n a10, 66 <ieee80211_psq_drop_one_pkt+0x52> (condition opaque) */
    /* mem ld32: base=(lit:g_ic) off=20 */
    /* mem ld32: base=(?) off=0x114 */
    /* mem st32: base=(?) off=0x114 */
    /* mem ld32: base=(*(g_ic+20)) off=0x140 */
    /* mem ld32: base=(?) off=0x108 */
    /* mem st32: base=((*(g_ic+20)+65536)) off=64 */
    /* mem ld32: base=(?) off=0x10c */
    /* mem ld16: base=(lit:g_hmac_cnt) off=52 */
    /* mem st16: base=(lit:g_hmac_cnt) off=52 */
    /* site +0x25: ieee80211_psq_take_head(0x108) */
    ieee80211_psq_take_head(0x108);
    /* site +0x2d: ic_ebuf_recycle_tx(ret@25) */
    ic_ebuf_recycle_tx(ret@25);
    /* site +0x55: ieee80211_set_tim(?, *(?+0x108)) */
    ieee80211_set_tim(?, *(?+0x108));
    return opaque_result; /* full dataflow not recovered */
}

/* ieee80211_psq_send_one_pkt @ ieee80211_power.o 0x00000014 size 101B bind GLOBAL
 * Calls: ieee80211_psq_take_head, chm_is_at_home_channel, ic_tx_pkt | Data refs: g_ic, g_hmac_cnt
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 ieee80211_psq_send_one_pkt(u32 a2, u32 a5)
{
    /* frame: entry a1,32; 36 insns, 2 cond-branches, 0 loops, 1 jumps */
    /* immediates: 0x108 */
    /* first predicate: beqz a10, 74 <ieee80211_psq_send_one_pkt+0x60> (condition opaque) */
    /* mem ld32: base=(lit:g_ic) off=20 */
    /* mem ld16: base=(lit:g_hmac_cnt) off=50 */
    /* mem st16: base=(lit:g_hmac_cnt) off=50 */
    /* mem ld32: base=(lit:g_hmac_cnt) off=0x1a8 */
    /* mem st32: base=((*(g_hmac_cnt+50)+1)) off=40 */
    /* mem st32: base=(*(g_hmac_cnt+0x1a8)) off=0 */
    /* mem st32: base=(lit:g_hmac_cnt) off=0x1a8 */
    /* mem ld32: base=(?) off=0x10c */
    /* mem st32: base=(?) off=0x10c */
    /* mem ld32: base=(*(g_ic+20)) off=0x13c */
    /* ... +1 more memops */
    /* site +0x26: ieee80211_psq_take_head(0x108) */
    ieee80211_psq_take_head(0x108);
    /* site +0x31: chm_is_at_home_channel(ret@26) */
    chm_is_at_home_channel(ret@26);
    /* site +0x3d: ic_tx_pkt(ret@31) */
    ic_tx_pkt(ret@31);
    return opaque_result; /* full dataflow not recovered */
}

/* ieee80211_psq_is_buff_pkt @ ieee80211_power.o 0x00000010 size 60B bind GLOBAL
 * Calls: ieee80211_psq_find_max_bss, ieee80211_psq_drop_one_pkt, ieee80211_psq_send_one_pkt | Data refs: g_ic
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 ieee80211_psq_is_buff_pkt(u32 a2)
{
    /* frame: entry a1,32; 21 insns, 3 cond-branches, 0 loops, 1 jumps */
    /* immediates: 1 */
    /* first predicate: blt a9, a8, 48 <ieee80211_psq_is_buff_pkt+0x38> (condition opaque) */
    /* mem ld32: base=(lit:g_ic) off=20 */
    /* mem ld32: base=(*(g_ic+20)) off=0x138 */
    /* mem ld32: base=(*(g_ic+20)) off=0x134 */
    /* mem ld32: base=(*(g_ic+20)) off=236 */
    /* mem ld32: base=(ret@27) off=0x108 */
    /* mem ld32: base=(*(g_ic+236)) off=0x108 */
    /* site +0x27: ieee80211_psq_find_max_bss(/* no traced args */) */
    ieee80211_psq_find_max_bss(/* no traced args */);
    /* site +0x39: ieee80211_psq_drop_one_pkt(ret@27) */
    ieee80211_psq_drop_one_pkt(ret@27);
    /* site +0x45: ieee80211_psq_send_one_pkt(*(g_ic+236)) */
    ieee80211_psq_send_one_pkt(*(g_ic+236));
    return 1;
}

/* ieee80211_pwrsave @ ieee80211_power.o 0x00000010 size 132B bind GLOBAL
 * Calls: ieee80211_psq_is_buff_pkt, ic_ebuf_recycle_tx, ieee80211_set_tim | Data refs: g_ic
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque (weak) */
u32 ieee80211_pwrsave(u32 a2, u32 a3)
{
    /* frame: entry a1,32; 48 insns, 3 cond-branches, 0 loops, 2 jumps */
    /* immediates: 0x108, 1, 0 */
    /* first predicate: bnez.n a10, 4c <ieee80211_pwrsave+0x3c> (condition opaque) */
    /* mem ld32: base=(lit:g_ic) off=20 */
    /* mem ld32: base=((?+65536)) off=20 */
    /* mem st32: base=((?+65536)) off=20 */
    /* mem ld32: base=((*(g_ic+20)+65536)) off=64 */
    /* mem st32: base=((*(g_ic+20)+65536)) off=64 */
    /* mem ld32: base=(&ic_ebuf_recycle_tx()) off=28 */
    /* mem st32: base=(&ic_ebuf_recycle_tx()) off=24 */
    /* mem st32: base=(*(&ic_ebuf_recycle_tx()+28)) off=40 */
    /* mem ld32: base=(&ic_ebuf_recycle_tx()) off=32 */
    /* mem st32: base=(?) off=40 */
    /* ... +6 more memops */
    /* site +0x22: ieee80211_psq_is_buff_pkt(0x108) */
    ieee80211_psq_is_buff_pkt(0x108);
    /* site +0x43: ic_ebuf_recycle_tx(/* no traced args */) */
    ic_ebuf_recycle_tx(/* no traced args */);
    /* site +0x7f: ieee80211_set_tim(?, (*(&ic_ebuf_recycle_tx()+8)+1)) */
    ieee80211_set_tim(?, (*(&ic_ebuf_recycle_tx()+8)+1));
    return 0;
}

/* pwrsave_flushq @ ieee80211_power.o 0x00000014 size 209B bind GLOBAL
 * Calls: chm_is_at_home_channel, ic_tx_pkt, hal_now, ic_ebuf_recycle_tx | Data refs: g_ic
 * Fidelity: medium - branchy but loop-free, call sequence mapped (verified: section R_XTENSA_ASM_EXPAND + funcdb v3 agree; predicates opaque) */
u32 pwrsave_flushq(u32 a2, u32 a3, u32 a5, u32 a7)
{
    /* frame: entry a1,32; 79 insns, 9 cond-branches, 0 loops, 4 jumps */
    /* immediates: 32, 0 */
    /* first predicate: beqz a2, e0 <pwrsave_flushq+0xcc> (condition opaque) */
    /* mem ld32: base=(lit:g_ic) off=20 */
    /* mem ld32: base=((?+65536)) off=24 */
    /* mem ld32: base=(?) off=4 */
    /* mem ld32: base=(*(?+4)) off=4 */
    /* mem ld32: base=(?) off=44 */
    /* mem ld32: base=(*(?+44)) off=0 */
    /* mem ld32: base=(?) off=40 */
    /* mem ld8: base=((*(*(?+4)+4)+4)) off=1 */
    /* mem st8: base=((*(*(?+4)+4)+4)) off=1 */
    /* mem ld32: base=(lit:g_ic) off=0x1a8 */
    /* ... +24 more memops */
    /* site +0x55: chm_is_at_home_channel(*((*(*(?+4)+4)+4)+1)) */
    chm_is_at_home_channel(*((*(*(?+4)+4)+4)+1));
    /* site +0x5f: ic_tx_pkt(/* no traced args */) */
    ic_tx_pkt(/* no traced args */);
    /* site +0x93: hal_now(ret@5f) */
    hal_now(ret@5f);
    /* site +0xb7: ic_ebuf_recycle_tx(/* no traced args */) */
    ic_ebuf_recycle_tx(/* no traced args */);
    return opaque_result; /* full dataflow not recovered */
}

/* ieee80211_node_pwrsave @ ieee80211_power.o 0x00000010 size 106B bind GLOBAL
 * Calls: pwrsave_flushq, ieee80211_set_tim, pwrsave_flushq | Data refs: g_ic
 * Fidelity: medium - branchy but loop-free, call sequence mapped */
u32 ieee80211_node_pwrsave(u32 a2, u32 a3)
{
    /* frame: entry a1,32; 42 insns, 4 cond-branches, 0 loops, 1 jumps */
    /* immediates: 16, -17, 0 */
    /* first predicate: beqz.n a3, 40 <ieee80211_node_pwrsave+0x30> (condition opaque) */
    /* mem ld32: base=(lit:g_ic) off=20 */
    /* mem ld32: base=(*(g_ic+20)) off=236 */
    /* mem ld32: base=(?) off=12 */
    /* mem ld32: base=((*(g_ic+20)+65536)) off=48 */
    /* mem st32: base=(?) off=12 */
    /* mem st32: base=((*(g_ic+20)+65536)) off=48 */
    /* mem ld32: base=(*(g_ic+236)) off=12 */
    /* mem st32: base=(*(g_ic+236)) off=12 */
    /* mem st32: base=(*(*(g_ic+236)+12)) off=12 */
    /* mem st32: base=((*(g_ic+20)+65536)) off=48 */
    /* ... +3 more memops */
    /* site +0x5b: pwrsave_flushq(*(g_ic+236), ((*(g_ic+48)+1)+-1), -17) */
    pwrsave_flushq(*(g_ic+236), ((*(g_ic+48)+1)+-1), -17);
    /* site +0x66: ieee80211_set_tim(ret@5b, 0, -17) */
    ieee80211_set_tim(ret@5b, 0, -17);
    /* site +0x75: pwrsave_flushq(*(*(g_ic+236)+12), 0, -17) */
    pwrsave_flushq(*(*(g_ic+236)+12), 0, -17);
    return opaque_result; /* full dataflow not recovered */
}

/* ieee80211_pwrsave_node_cleanup @ ieee80211_power.o 0x0000000c size 59B bind GLOBAL
 * Calls: pwrsave_flushq, pwrsave_flushq | Data refs: g_ic
 * Fidelity: medium - linear/small-diamond, calls mapped, predicates opaque */
u32 ieee80211_pwrsave_node_cleanup(u32 a2, u32 a3)
{
    /* frame: entry a1,32; 24 insns, 2 cond-branches, 0 loops, 0 jumps */
    /* immediates: 1, -17 */
    /* first predicate: bbci a2, 4, 45 <ieee80211_pwrsave_node_cleanup+0x39> (condition opaque) */
    /* mem ld32: base=(lit:g_ic) off=20 */
    /* mem ld32: base=(*(g_ic+20)) off=236 */
    /* mem ld32: base=(?) off=12 */
    /* mem ld32: base=((*(g_ic+20)+65536)) off=48 */
    /* mem st32: base=((*(g_ic+20)+65536)) off=48 */
    /* mem ld32: base=(*(g_ic+236)) off=12 */
    /* mem st32: base=(*(g_ic+236)) off=12 */
    /* site +0x1e: pwrsave_flushq(?, 1) */
    pwrsave_flushq(?, 1);
    /* site +0x42: pwrsave_flushq(*(g_ic+236), (*(g_ic+48)+-1)) */
    pwrsave_flushq(*(g_ic+236), (*(g_ic+48)+-1));
    return opaque_result; /* full dataflow not recovered */
}

/* ieee80211_pwrsave_txcb @ ieee80211_power.o 0x0000000c size 78B bind GLOBAL
 * Calls: hal_now, ieee80211_set_tim | Data refs: g_ic
 * Fidelity: medium - branchy but loop-free, call sequence mapped */
u32 ieee80211_pwrsave_txcb(u32 a2, u32 a3, u32 a4)
{
    /* frame: entry a1,32; 29 insns, 4 cond-branches, 0 loops, 0 jumps */
    /* first predicate: blti a8, 1, 44 <ieee80211_pwrsave_txcb+0x38> (condition opaque) */
    /* mem ld32: base=(lit:g_ic) off=20 */
    /* mem ld32: base=((?+65536)) off=12 */
    /* mem st32: base=((?+65536)) off=12 */
    /* mem ld32: base=(*(g_ic+20)) off=0x13c */
    /* mem st32: base=(*(g_ic+20)) off=0x13c */
    /* mem ld32: base=(*(g_ic+20)) off=236 */
    /* mem ld32: base=(?) off=44 */
    /* mem ld8: base=(*(?+44)) off=19 */
    /* mem st32: base=(?) off=0x150 */
    /* mem ld32: base=((?+65536)) off=8 */
    /* ... +1 more memops */
    /* site +0x3e: hal_now(/* no traced args */) */
    hal_now(/* no traced args */);
    /* site +0x55: ieee80211_set_tim(ret@3e, *(g_ic+8)) */
    ieee80211_set_tim(ret@3e, *(g_ic+8));
    return opaque_result; /* full dataflow not recovered */
}

/* ieee80211_is_bufferable_mmpdu @ ieee80211_power.o 0x00000000 size 82B bind GLOBAL
 * Calls: none | Data refs: none
 * Fidelity: medium - branchy but loop-free, call sequence mapped (weak) */
u32 ieee80211_is_bufferable_mmpdu(u32 a2)
{
    /* frame: entry a1,32; 32 insns, 5 cond-branches, 0 loops, 1 jumps */
    /* immediates: 12, 0, -16, 208, 1, 8 */
    /* first predicate: bbci a8, 18, 10 <ieee80211_is_bufferable_mmpdu+0x10> (condition opaque) */
    /* mem ld32: base=(?) off=44 */
    /* mem ld32: base=(?) off=4 */
    /* mem ld32: base=(*(?+44)) off=0 */
    /* mem ld32: base=(*(?+4)) off=4 */
    /* mem ld8: base=((*(*(?+4)+4)+4)) off=0 */
    /* mem ld8: base=((*(*(?+4)+4)+4)) off=0 */
    /* mem ld8: base=((*(*(?+4)+4)+4)) off=1 */
    return 12;
}
