/* Reconstruction of coexist_scheme.o (libcoexist.a) — phase-table scheme engine.
 * Ground truth: re/esp32-coex/funcdb_libcoexist.json (funcdb v3),
 * re/esp32-coex/disasm/coexist_scheme.dis.
 * coex_schm_env (64B): +0 cur_table ptr, +4 u8 phase_idx, +6 u16 wifi,
 * +8 u16 bt, +10 u16 ble, +12 u32 interval, +16 u32 mux, +20 u32 cb_owner1,
 * +24 u8 wifi_chan, +25 u8 wifi_chan2, +28 u32 wifi_chan_cb, +52 u32 cb_owner0,
 * +56 u16 flags (bit0 = freeze), +58 u8 flexible_period, +60 u16 mesh_stat.
 * Phase tables (.rodata weak objects, 6/10/14/22B): [0]=u8 count, [1]=u8 period,
 * entries of 4B from +2 (arm: byte1=len factor, byte2, byte3=cb class, byte4/5).
 * Statics (no symtab entries): status_change, is_loop_allowed, change_phase,
 * timeout_process — called via intra-object relocs, reconstructed as static.
 */
typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;

extern void *g_coa_funcs_p;
extern u8 coex_schm_env[64];
extern int coexist_printf(const char *fmt, ...);
extern void coex_dbg_output(u32 p0, u32 p1);

typedef struct coex_schm_env {
    void *table;    /* +0 */
    u8 phase_idx;   /* +4 */
    u8 _p5;
    u16 wifi;       /* +6 */
    u16 bt;         /* +8 */
    u16 ble;        /* +10 */
    u32 interval;   /* +12 */
    u32 mux;        /* +16 */
    u32 cb1;        /* +20 */
    u8 chan;        /* +24 */
    u8 chan2;       /* +25 */
    u8 _p26[2];
    u32 chan_cb;    /* +28 */
    u8 _p32[20];
    u32 cb0;        /* +52 */
    u16 flags;      /* +56 */
    u8 flex_period; /* +58 */
    u8 _p59;
    u16 mesh;       /* +60 */
    u8 _p62[2];
} coex_schm_env_t;

/* phase-table declarations (weak rodata objects; full list in ledger) */
extern u8 coex_schm_all_default[10];

/* static coex_schm_is_loop_allowed (.text.coex_schm_is_loop_allowed)
 * Calls: none | Data refs: coex_schm_env
 * Fidelity: high - count of nonzero {wifi,bt,flags,m_ext} >= 2 */
static u32 coex_schm_is_loop_allowed(void)
{
    coex_schm_env_t *e = (coex_schm_env_t *)coex_schm_env;
    u32 n = 0;
    if (e->wifi != 0)
        n++;
    if (*(u32 *)(coex_schm_env + 8) != 0) /* disasm l32i+8 (word test on bt half) */
        n++;
    if (e->flags != 0)
        n++;
    if (e->mesh != 0)
        n++;
    return (n >= 2) ? 1 : 0;
}

/* static coex_schm_status_change (.text.coex_schm_status_change; ~2KB decision tree)
 * Calls: none | Data refs: coex_schm_env + ~140 phase-table weak objects
 * Fidelity: medium - top predicates + group order + every leaf table exact per literal reloc;
 *   two (L & (B|M)) stale-mask predicates (notes 1,2) determined by dataflow, intent unclear.
 * Map: freeze(env+56 bit0) -> hold; (bt|mesh)==0 -> plain bt_* matrix;
 *   bt&8 -> ble_mesh_config_*; (bt&16)||((bt&0x3a)==2) -> ble_mesh_traffic_*;
 *   bt&32 (+mesh gate) -> ble_mesh_standby_*; else -> ble_default_*.
 *   wifi rows: bit0=scan, bit1=connecting, bit2=conn. Leaf ladders test ble bits
 *   in per-group order (0, then 6/1/5/4/0x88/2/0 variants), storing the table ptr at env+0.
 */
extern u8 coex_schm_bt_idle_wifi_scan[6];
extern u8 coex_schm_bt_page_wifi_scan[10];
extern u8 coex_schm_bt_inq_wifi_scan[10];
extern u8 coex_schm_bt_a2dp_paused_wifi_scan[10];
extern u8 coex_schm_bt_a2dp_wifi_scan[10];
extern u8 coex_schm_bt_sniff_sco_wifi_scan[6];
extern u8 coex_schm_bt_conn_wifi_scan[10];
extern u8 coex_schm_bt_piscan_wifi_scan[6];
extern u8 coex_schm_bt_default_wifi_scan[10];
extern u8 coex_schm_bt_idle_wifi_connecting[6];
extern u8 coex_schm_bt_a2dp_paused_wifi_connecting[10];
extern u8 coex_schm_bt_a2dp_wifi_connecting[10];
extern u8 coex_schm_bt_page_wifi_connecting[10];
extern u8 coex_schm_bt_inq_wifi_connecting[10];
extern u8 coex_schm_bt_sniff_sco_wifi_connecting[6];
extern u8 coex_schm_bt_conn_wifi_connecting[10];
extern u8 coex_schm_bt_piscan_wifi_connecting[6];
extern u8 coex_schm_bt_default_wifi_connecting[10];
extern u8 coex_schm_ble_mesh_config_wifi_scan[10];
extern u8 coex_schm_ble_mesh_config_bt_a2dp_paused_wifi_scan[14];
extern u8 coex_schm_ble_mesh_config_bt_a2dp_wifi_scan[14];
extern u8 coex_schm_ble_mesh_config_bt_sniff_sco_wifi_scan[10];
extern u8 coex_schm_ble_mesh_config_bt_conn_wifi_scan[14];
extern u8 coex_schm_ble_mesh_config_bt_piscan_wifi_scan[10];
extern u8 coex_schm_ble_mesh_config_bt_default_wifi_scan[14];
extern u8 coex_schm_ble_mesh_config_wifi_connecting[10];
extern u8 coex_schm_ble_mesh_config_bt_a2dp_paused_wifi_connecting[14];
extern u8 coex_schm_ble_mesh_config_bt_a2dp_wifi_connecting[14];
extern u8 coex_schm_ble_mesh_config_bt_sniff_sco_wifi_connecting[10];
extern u8 coex_schm_ble_mesh_config_bt_conn_wifi_connecting[14];
extern u8 coex_schm_ble_mesh_config_bt_piscan_wifi_connecting[10];
extern u8 coex_schm_ble_mesh_config_bt_default_wifi_connecting[14];
extern u8 coex_schm_ble_mesh_config_wifi_conn[10];
extern u8 coex_schm_ble_mesh_config_bt_a2dp_paused_wifi_conn[14];
extern u8 coex_schm_ble_mesh_config_bt_a2dp_wifi_conn[14];
extern u8 coex_schm_ble_mesh_config_bt_sniff_sco_wifi_conn[10];
extern u8 coex_schm_ble_mesh_config_bt_conn_wifi_conn[14];
extern u8 coex_schm_ble_mesh_config_bt_piscan_wifi_conn[10];
extern u8 coex_schm_ble_mesh_config_bt_default_wifi_conn[14];
extern u8 coex_schm_ble_mesh_traffic_wifi_scan[10];
extern u8 coex_schm_ble_mesh_traffic_bt_a2dp_paused_wifi_scan[14];
extern u8 coex_schm_ble_mesh_traffic_bt_a2dp_wifi_scan[14];
extern u8 coex_schm_ble_mesh_traffic_bt_sniff_sco_wifi_scan[10];
extern u8 coex_schm_ble_mesh_traffic_bt_conn_wifi_scan[14];
extern u8 coex_schm_ble_mesh_traffic_bt_piscan_wifi_scan[10];
extern u8 coex_schm_ble_mesh_traffic_bt_default_wifi_scan[22];
extern u8 coex_schm_ble_mesh_traffic_wifi_connecting[10];
extern u8 coex_schm_ble_mesh_traffic_bt_a2dp_paused_wifi_connecting[14];
extern u8 coex_schm_ble_mesh_traffic_bt_a2dp_wifi_connecting[14];
extern u8 coex_schm_ble_mesh_traffic_bt_sniff_sco_wifi_connecting[10];
extern u8 coex_schm_ble_mesh_traffic_bt_conn_wifi_connecting[14];
extern u8 coex_schm_ble_mesh_traffic_bt_piscan_wifi_connecting[10];
extern u8 coex_schm_ble_mesh_traffic_bt_default_wifi_connecting[22];
extern u8 coex_schm_ble_mesh_traffic_wifi_conn[10];
extern u8 coex_schm_ble_mesh_traffic_bt_a2dp_paused_wifi_conn[14];
extern u8 coex_schm_ble_mesh_traffic_bt_a2dp_wifi_conn[14];
extern u8 coex_schm_ble_mesh_traffic_bt_sniff_sco_wifi_conn[10];
extern u8 coex_schm_ble_mesh_traffic_bt_conn_wifi_conn[14];
extern u8 coex_schm_ble_mesh_traffic_bt_piscan_wifi_conn[10];
extern u8 coex_schm_ble_mesh_traffic_bt_default_wifi_conn[22];
extern u8 coex_schm_ble_mesh_standby_wifi_scan[10];
extern u8 coex_schm_ble_mesh_standby_bt_a2dp_paused_wifi_scan[14];
extern u8 coex_schm_ble_mesh_standby_bt_a2dp_wifi_scan[14];
extern u8 coex_schm_ble_mesh_standby_bt_sniff_sco_wifi_scan[10];
extern u8 coex_schm_ble_mesh_standby_bt_conn_wifi_scan[14];
extern u8 coex_schm_ble_mesh_standby_bt_piscan_wifi_scan[10];
extern u8 coex_schm_ble_mesh_standby_bt_default_wifi_scan[22];
extern u8 coex_schm_ble_mesh_standby_wifi_connecting[10];
extern u8 coex_schm_ble_mesh_standby_bt_a2dp_paused_wifi_connecting[14];
extern u8 coex_schm_ble_mesh_standby_bt_a2dp_wifi_connecting[22];
extern u8 coex_schm_ble_mesh_standby_bt_sniff_sco_wifi_connecting[10];
extern u8 coex_schm_ble_mesh_standby_bt_conn_wifi_connecting[14];
extern u8 coex_schm_ble_mesh_standby_bt_piscan_wifi_connecting[10];
extern u8 coex_schm_ble_mesh_standby_bt_default_wifi_connecting[22];
extern u8 coex_schm_ble_mesh_standby_wifi_conn[10];
extern u8 coex_schm_ble_mesh_standby_bt_a2dp_paused_wifi_conn[14];
extern u8 coex_schm_ble_mesh_standby_bt_a2dp_wifi_conn[14];
extern u8 coex_schm_ble_mesh_standby_bt_sniff_sco_wifi_conn[10];
extern u8 coex_schm_ble_mesh_standby_bt_conn_wifi_conn[14];
extern u8 coex_schm_ble_mesh_standby_bt_piscan_wifi_conn[10];
extern u8 coex_schm_ble_mesh_standby_bt_default_wifi_conn[22];
extern u8 coex_schm_ble_default_bt_idle_wifi_scan[10];
extern u8 coex_schm_ble_default_bt_idle_wifi_connecting[10];
extern u8 coex_schm_ble_default_bt_idle_wifi_conn[10];
extern u8 coex_schm_ble_default_bt_a2dp_wifi_scan[10];
extern u8 coex_schm_ble_default_bt_default_wifi_scan[10];
extern u8 coex_schm_ble_default_bt_a2dp_wifi_connecting[10];
extern u8 coex_schm_ble_default_bt_default_wifi_connecting[10];
extern u8 coex_schm_ble_default_bt_a2dp_wifi_conn[10];
extern u8 coex_schm_ble_default_bt_default_wifi_conn[10];
static void coex_schm_status_change(void)
{
    coex_schm_env_t *e = (coex_schm_env_t *)coex_schm_env;
    u16 w = e->wifi, b = e->bt, l = e->ble, m = e->mesh;
    void *t;
    if ((e->flags & 1) != 0)
        return; /* frozen (bbci +56.0) */
    if ((b | m) == 0) {
        if ((w & 1) == 0) {
            if ((w & 2) == 0) {
                if ((w & 4) == 0)
                    return;
                /* wifi-conn, no BT (2da ladder: 0,6,2,5,4,136,2,0,default) */
                if (l == 0) t = coex_schm_bt_idle_wifi_conn;
                else if (l & 0x40) t = coex_schm_bt_page_wifi_conn;
                else if (l & 2) t = coex_schm_bt_inq_wifi_conn;
                else if (l & 0x20) t = coex_schm_bt_a2dp_paused_wifi_conn;
                else if (l & 0x10) t = coex_schm_bt_a2dp_wifi_conn;
                else if (l & 0x88) t = coex_schm_bt_sniff_sco_wifi_conn;
                else if (l & 4) t = coex_schm_bt_conn_wifi_conn;
                else if (l & 1) t = coex_schm_bt_piscan_wifi_conn;
                else t = coex_schm_bt_default_wifi_conn;
            } else {
                /* wifi-connecting, no BT (250 ladder: 0,5,4,6,2,136,2,0,default) */
                if (l == 0) t = coex_schm_bt_idle_wifi_connecting;
                else if (l & 0x20) t = coex_schm_bt_a2dp_paused_wifi_connecting;
                else if (l & 0x10) t = coex_schm_bt_a2dp_wifi_connecting;
                else if (l & 0x40) t = coex_schm_bt_page_wifi_connecting;
                else if (l & 2) t = coex_schm_bt_inq_wifi_connecting;
                else if (l & 0x88) t = coex_schm_bt_sniff_sco_wifi_connecting;
                else if (l & 4) t = coex_schm_bt_conn_wifi_connecting;
                else if (l & 1) t = coex_schm_bt_piscan_wifi_connecting;
                else t = coex_schm_bt_default_wifi_connecting;
            }
        } else {
            /* wifi-scan, no BT (1c0 ladder: 0,6,1,5,4,136,2,0,default) */
            if (l == 0) t = coex_schm_bt_idle_wifi_scan;
            else if (l & 0x40) t = coex_schm_bt_page_wifi_scan;
            else if (l & 2) t = coex_schm_bt_inq_wifi_scan;
            else if (l & 0x20) t = coex_schm_bt_a2dp_paused_wifi_scan;
            else if (l & 0x10) t = coex_schm_bt_a2dp_wifi_scan;
            else if (l & 0x88) t = coex_schm_bt_sniff_sco_wifi_scan;
            else if (l & 4) t = coex_schm_bt_conn_wifi_scan;
            else if (l & 1) t = coex_schm_bt_piscan_wifi_scan;
            else t = coex_schm_bt_default_wifi_scan;
        }
    } else if ((b & 8) != 0) {
        /* BT bit3: ble_mesh_config_* (ladders 0,5,4,136,2,0,default) */
        if ((w & 1) == 0) {
            if ((w & 2) == 0)
                return;
            if (l == 0) t = coex_schm_ble_mesh_config_wifi_conn;
            else if (l & 0x20) t = coex_schm_ble_mesh_config_bt_a2dp_paused_wifi_conn;
            else if (l & 0x10) t = coex_schm_ble_mesh_config_bt_a2dp_wifi_conn;
            else if (l & 0x88) t = coex_schm_ble_mesh_config_bt_sniff_sco_wifi_conn;
            else if (l & 4) t = coex_schm_ble_mesh_config_bt_conn_wifi_conn;
            else if (l & 1) t = coex_schm_ble_mesh_config_bt_piscan_wifi_conn;
            else t = coex_schm_ble_mesh_config_bt_default_wifi_conn;
        } else if ((w & 2) == 0) {
            if (l == 0) t = coex_schm_ble_mesh_config_wifi_scan;
            else if (l & 0x20) t = coex_schm_ble_mesh_config_bt_a2dp_paused_wifi_scan;
            else if (l & 0x10) t = coex_schm_ble_mesh_config_bt_a2dp_wifi_scan;
            else if (l & 0x88) t = coex_schm_ble_mesh_config_bt_sniff_sco_wifi_scan;
            else if (l & 4) t = coex_schm_ble_mesh_config_bt_conn_wifi_scan;
            else if (l & 1) t = coex_schm_ble_mesh_config_bt_piscan_wifi_scan;
            else t = coex_schm_ble_mesh_config_bt_default_wifi_scan;
        } else {
            if (l == 0) t = coex_schm_ble_mesh_config_wifi_connecting;
            else if (l & 0x20) t = coex_schm_ble_mesh_config_bt_a2dp_paused_wifi_connecting;
            else if (l & 0x10) t = coex_schm_ble_mesh_config_bt_a2dp_wifi_connecting;
            else if (l & 0x88) t = coex_schm_ble_mesh_config_bt_sniff_sco_wifi_connecting;
            else if (l & 4) t = coex_schm_ble_mesh_config_bt_conn_wifi_connecting;
            else if (l & 1) t = coex_schm_ble_mesh_config_bt_piscan_wifi_connecting;
            else t = coex_schm_ble_mesh_config_bt_default_wifi_connecting;
        }
    } else if ((b & 16) != 0 || (b & 0x3a) == 2) {
        /* ble_mesh_traffic_* (ladders 0,5,4,136,2,0,default; conn uses bnone-2 at 5d9) */
        if ((w & 1) == 0) {
            if ((w & 2) == 0)
                return;
            if ((w & 4) == 0) {
                if (l == 0) t = coex_schm_ble_mesh_traffic_wifi_connecting;
                else if (l & 0x20) t = coex_schm_ble_mesh_traffic_bt_a2dp_paused_wifi_connecting;
                else if (l & 0x10) t = coex_schm_ble_mesh_traffic_bt_a2dp_wifi_connecting;
                else if (l & 0x88) t = coex_schm_ble_mesh_traffic_bt_sniff_sco_wifi_connecting;
                else if (l & 4) t = coex_schm_ble_mesh_traffic_bt_conn_wifi_connecting;
                else if (l & 1) t = coex_schm_ble_mesh_traffic_bt_piscan_wifi_connecting;
                else t = coex_schm_ble_mesh_traffic_bt_default_wifi_connecting;
            } else {
                if (l == 0) t = coex_schm_ble_mesh_traffic_wifi_conn;
                else if (l & 0x20) t = coex_schm_ble_mesh_traffic_bt_a2dp_paused_wifi_conn;
                else if (l & 0x10) t = coex_schm_ble_mesh_traffic_bt_a2dp_wifi_conn;
                else if (l & 0x88) t = coex_schm_ble_mesh_traffic_bt_sniff_sco_wifi_conn;
                /* NOTE(5d9): disasm tests (l & (b|m)) via stale a2, not (l & 2);
                 * dataflow-determined, intent unclear; conn leaf kept by table order */
                else if ((l & (b | m)) != 0) t = coex_schm_ble_mesh_traffic_bt_conn_wifi_conn;
                else if (l & 1) t = coex_schm_ble_mesh_traffic_bt_piscan_wifi_conn;
                else t = coex_schm_ble_mesh_traffic_bt_default_wifi_conn;
            }
        } else {
            if (l == 0) t = coex_schm_ble_mesh_traffic_wifi_scan;
            else if (l & 0x20) t = coex_schm_ble_mesh_traffic_bt_a2dp_paused_wifi_scan;
            else if (l & 0x10) t = coex_schm_ble_mesh_traffic_bt_a2dp_wifi_scan;
            else if (l & 0x88) t = coex_schm_ble_mesh_traffic_bt_sniff_sco_wifi_scan;
            else if (l & 4) t = coex_schm_ble_mesh_traffic_bt_conn_wifi_scan;
            else if (l & 1) t = coex_schm_ble_mesh_traffic_bt_piscan_wifi_scan;
            else t = coex_schm_ble_mesh_traffic_bt_default_wifi_scan;
        }
    } else if ((b & 32) != 0) {
        /* ble_mesh_standby_* */
        if ((w & 1) == 0) {
            if ((w & 2) == 0)
                return;
            if ((w & 4) == 0) {
                if (l == 0) t = coex_schm_ble_mesh_standby_wifi_connecting;
                else if ((l & 32) != 0) t = coex_schm_ble_mesh_standby_bt_a2dp_paused_wifi_connecting;
                else if (l & 0x10) t = coex_schm_ble_mesh_standby_bt_a2dp_wifi_connecting;
                else if (l & 0x88) t = coex_schm_ble_mesh_standby_bt_sniff_sco_wifi_connecting;
                else if (l & 4) t = coex_schm_ble_mesh_standby_bt_conn_wifi_connecting;
                else if (l & 1) t = coex_schm_ble_mesh_standby_bt_piscan_wifi_connecting;
                else t = coex_schm_ble_mesh_standby_bt_default_wifi_connecting;
            } else {
                if (l == 0) t = coex_schm_ble_mesh_standby_wifi_conn;
                else if (l & 0x20) t = coex_schm_ble_mesh_standby_bt_a2dp_paused_wifi_conn;
                else if (l & 0x10) t = coex_schm_ble_mesh_standby_bt_a2dp_wifi_conn;
                else if (l & 0x88) t = coex_schm_ble_mesh_standby_bt_sniff_sco_wifi_conn;
                else if (l & 4) t = coex_schm_ble_mesh_standby_bt_conn_wifi_conn;
                else if (l & 1) t = coex_schm_ble_mesh_standby_bt_piscan_wifi_conn;
                else t = coex_schm_ble_mesh_standby_bt_default_wifi_conn;
            }
        } else {
            if (l == 0) t = coex_schm_ble_mesh_standby_wifi_scan;
            else if ((l & 32) != 0) t = coex_schm_ble_mesh_standby_bt_a2dp_paused_wifi_scan;
            /* NOTE(62c): disasm tests (l & (b|m)) via stale a2 here; dataflow-determined */
            else if ((l & (b | m)) != 0) t = coex_schm_ble_mesh_standby_bt_a2dp_wifi_scan;
            else if (l & 0x88) t = coex_schm_ble_mesh_standby_bt_sniff_sco_wifi_scan;
            else if (l & 4) t = coex_schm_ble_mesh_standby_bt_conn_wifi_scan;
            else if (l & 1) t = coex_schm_ble_mesh_standby_bt_piscan_wifi_scan;
            else t = coex_schm_ble_mesh_standby_bt_default_wifi_scan;
        }
    } else {
        /* ble_default_*: 763 single-leaf iff ((b|l)==0 ? (m==1) : (b&32)), else 790 ladder */
        u32 to_single = ((b | l) == 0) ? (m == 1) : ((b & 32) != 0);
        if (to_single) {
            if ((w & 1) != 0) t = coex_schm_ble_default_bt_idle_wifi_scan;
            else if ((w & 2) != 0) t = coex_schm_ble_default_bt_idle_wifi_connecting;
            else if ((w & 4) != 0) t = coex_schm_ble_default_bt_idle_wifi_conn;
            else return;
        } else if ((w & 1) != 0) {
            if (l == 0) t = coex_schm_ble_default_bt_idle_wifi_scan;
            else if (l & 0x10) t = coex_schm_ble_default_bt_a2dp_wifi_scan;
            else t = coex_schm_ble_default_bt_default_wifi_scan;
        } else if ((w & 2) != 0) {
            if (l == 0) t = coex_schm_ble_default_bt_idle_wifi_connecting;
            else if (l & 0x10) t = coex_schm_ble_default_bt_a2dp_wifi_connecting;
            else t = coex_schm_ble_default_bt_default_wifi_connecting;
        } else if ((w & 4) != 0) {
            if (l == 0) t = coex_schm_ble_default_bt_idle_wifi_conn;
            else if (l & 0x10) t = coex_schm_ble_default_bt_a2dp_wifi_conn;
            else t = coex_schm_ble_default_bt_default_wifi_conn;
        } else
            return;
    }
    e->table = t;
}

/* static coex_schm_change_phase (.text.coex_schm_change_phase; entry at +0x20)
 * Calls: coex_schm_lock, coex_schm_unlock, coex_dbg_output | Data refs: coex_schm_env, coex_schm_lock, coex_schm_unlock
 * Fidelity: medium - restart/advance, period gates (3, 64), loop checks, phase-timer arm (period*interval*phase[2] via adapter+80), cb select (phase[3]->env+52, phase[4]->env+20); always returns -1 */
static int coex_schm_change_phase(u32 restart)
{
    coex_schm_env_t *e = (coex_schm_env_t *)coex_schm_env;
    u8 *table;
    u32 idx;
    u32 period;
    void *cbt = 0;
    void *cbp = 0;
    extern u32 coex_schm_lock(void);
    extern u32 coex_schm_unlock(void);
    if (coex_schm_lock() != 0)
        return -1;
    table = (u8 *)e->table;
    if (table == 0)
        goto done;
    if (restart == 0) {
        if (e->phase_idx < (u32)(table[0] - 1))
            goto advance;
        period = *(u16 *)(coex_schm_env + 6);
        if ((u16)(period - 1) >= 2 && period != 64)
            goto select_noarm;
        if (coex_schm_is_loop_allowed() == 0)
            goto done;
        goto advance;
    }
advance:
    ((void (*)(void *))*(u32 *)((u8 *)*(void **)g_coa_funcs_p + 68))((void *)(coex_schm_env + 32));
    if (restart == 0)
        e->phase_idx++;
    idx = e->phase_idx;
    if (idx != (u32)(table[0] - 1))
        goto arm;
    period = *(u16 *)(coex_schm_env + 6);
    if ((u16)(period - 1) < 2 || period == 64) {
        if (coex_schm_is_loop_allowed() == 0)
            goto select_noarm;
    }
arm:
    {
        u8 *ph = table + e->phase_idx * 4 + 2;
        u32 timeout = (u32)table[1] * e->interval * ph[2];
        ((void (*)(void *, u32, u32))*(u32 *)((u8 *)*(void **)g_coa_funcs_p + 80))((void *)(coex_schm_env + 32), timeout, 0);
    }
select_noarm:
    {
        u8 *ph = table + e->phase_idx * 4 + 2;
        if (ph[3] != 0)
            cbt = (void *)e->cb0; /* env+52 */
        if (ph[4] != 0)
            cbp = (void *)e->cb1; /* env+20 */
    }
done:
    coex_schm_unlock();
    coex_dbg_output(2, 16);
    if (cbt != 0)
        ((void (*)(u32))cbt)(0);
    if (cbp != 0)
        ((void (*)(u32))cbp)(0);
    return -1;
}

/* static coex_schm_timeout_process (.text.coex_schm_timeout_process)
 * Calls: none | Data refs: none
 * Fidelity: high - change_phase(0); no result move (returns entry a2, ignored) */
static void coex_schm_timeout_process(void)
{
    coex_schm_change_phase(0);
    /* disasm: retw without mov a2,a10 */
}

/* coex_schm_lock @ coexist_scheme.o 00000008 size 39B bind GLOBAL
 * Calls: none | Data refs: none
 * Fidelity: high - mux null -> 0x103 else adapter+40(mux,-1); 0 iff rc==1 else -1 */
u32 coex_schm_lock(void)
{
    u32 mux = ((coex_schm_env_t *)coex_schm_env)->mux;
    u32 r;
    if (mux == 0)
        return 0x103;
    r = ((u32 (*)(u32, int))*(u32 *)((u8 *)*(void **)g_coa_funcs_p + 40))(mux, -1);
    return (r == 1) ? 0 : (u32)-1;
}

/* coex_schm_unlock @ coexist_scheme.o 00000008 size 38B bind GLOBAL
 * Calls: none | Data refs: none
 * Fidelity: high - mux null -> 0x103 else adapter+44(mux); 0 iff rc==1 else -1 */
u32 coex_schm_unlock(void)
{
    u32 mux = ((coex_schm_env_t *)coex_schm_env)->mux;
    u32 r;
    if (mux == 0)
        return 0x103;
    r = ((u32 (*)(u32))*(u32 *)((u8 *)*(void **)g_coa_funcs_p + 44))(mux);
    return (r == 1) ? 0 : (u32)-1;
}

/* coex_schm_status_bit_set @ coexist_scheme.o 0000001c size 220B bind GLOBAL
 * Calls: coex_schm_lock, coex_schm_unlock | Data refs: coex_schm_env, coex_schm_lock, coex_schm_unlock
 * Fidelity: medium - per-type bit-OR into env+6/+8/+10/+60, status_change on loop-flip, change_phase(1) on (period<3|==64); extra a4-garbage gate noted */
u32 coex_schm_status_bit_set(u32 type, u32 status)
{
    coex_schm_env_t *e = (coex_schm_env_t *)coex_schm_env;
    u32 before;
    u32 after;
    u32 changed;
    u32 rc = coex_schm_lock();
    if (rc != 0)
        return rc; /* disasm f6: returns lock rc */
    before = coex_schm_is_loop_allowed();
    if (type == 2) {
        if ((status & (u32)~e->ble) == 0)
            goto recheck;
        e->ble |= (u16)status;
    } else if (type < 3) {
        if (type == 0) {
            if ((status & (u32)~e->wifi) == 0)
                goto recheck;
            e->wifi |= (u16)status;
        } else {
            if ((status & (u32)~e->bt) == 0)
                goto recheck;
            e->bt |= (u16)status;
        }
    } else if (type == 4) {
        if ((status & (u32)~e->mesh) == 0)
            goto recheck;
        e->mesh |= (u16)status;
    }
    changed = 1;
    goto finish;
recheck:
    changed = 0;
finish:
    after = coex_schm_is_loop_allowed();
    if (before != after)
        coex_schm_status_change();
    coex_schm_unlock();
    /* disasm gates change_phase on (changed & stale-entry-a4 & after & period-gate);
     * a4 is caller garbage on the wrapper path; modeled without it (see ledger) */
    if (changed && after) {
        u32 period = *(u16 *)(coex_schm_env + 6);
        if ((u16)(period - 1) < 2 || period == 64)
            coex_schm_change_phase(1);
    }
    return 0;
}

/* coex_schm_status_bit_clear @ coexist_scheme.o 00000010 size 157B bind GLOBAL
 * Calls: coex_schm_lock, coex_schm_unlock | Data refs: coex_schm_env, coex_schm_lock, coex_schm_unlock
 * Fidelity: high - per-type bit-AND-clear, always status_change + unlock; returns entry type (no result move) */
u32 coex_schm_status_bit_clear(u32 type, u32 status)
{
    coex_schm_env_t *e = (coex_schm_env_t *)coex_schm_env;
    u32 rc = coex_schm_lock();
    if (rc != 0)
        return rc; /* disasm ab: returns lock rc */
    if (type == 2)
        e->ble &= (u16)~status;
    else if (type < 3) {
        if (type == 0)
            e->wifi &= (u16)~status;
        else
            e->bt &= (u16)~status;
    } else if (type == 4)
        e->mesh &= (u16)~status;
    coex_schm_status_change();
    coex_schm_unlock();
    return type; /* disasm: retw without mov a2,a10 */
}

/* coex_schm_status_get @ coexist_scheme.o 0000000c size 59B bind GLOBAL
 * Calls: coex_schm_lock, coex_schm_unlock | Data refs: coex_schm_env, coex_schm_lock, coex_schm_unlock
 * Fidelity: high - lock-fail -> rc; 0->wifi(+6), 1->bt(+8), 2->ble(+10), else unlock + 0 */
u32 coex_schm_status_get(u32 type)
{
    coex_schm_env_t *e = (coex_schm_env_t *)coex_schm_env;
    u32 rc = coex_schm_lock();
    u32 out;
    if (rc != 0)
        return rc;
    if (type == 1)
        out = e->bt;
    else if (type == 2)
        out = e->ble;
    else if (type == 0)
        out = e->wifi;
    else {
        coex_schm_unlock();
        return 0;
    }
    coex_schm_unlock();
    return out;
}

/* coex_schm_status_bitmap_get @ coexist_scheme.o 00000004 size 73B bind GLOBAL
 * Calls: none | Data refs: none
 * Fidelity: high - bit0=wifi,bit1=bt,bit2=ble,bit3=flags,bit4=(mesh==0); no lock */
u32 coex_schm_status_bitmap_get(void)
{
    coex_schm_env_t *e = (coex_schm_env_t *)coex_schm_env;
    u32 b = 0;
    if (e->ble != 0)
        b |= 4;
    if (e->bt != 0)
        b |= 2;
    if (e->wifi != 0)
        b |= 1;
    if (e->flags != 0)
        b |= 8;
    if (e->mesh == 0)
        b |= 16;
    return b;
}

/* coex_schm_curr_phase_idx_set @ coexist_scheme.o 0000000c size 84B bind GLOBAL
 * Calls: coex_schm_lock, coex_schm_unlock | Data refs: coex_schm_env, coex_schm_lock, coex_schm_unlock
 * Fidelity: medium - lock-fail -> -1; null table/range-fail -> -1; store idx, unlock, cb(0) if set, 0 */
int coex_schm_curr_phase_idx_set(u32 idx)
{
    coex_schm_env_t *e = (coex_schm_env_t *)coex_schm_env;
    u8 *table;
    void *cb;
    if (coex_schm_lock() != 0)
        return -1;
    table = (u8 *)e->table;
    if (table == 0)
        goto fail;
    if (*(u16 *)(coex_schm_env + 6) != 64 && idx != table[0])
        goto range;
    goto store;
range:
    if (idx >= table[0])
        goto fail;
store:
    e->phase_idx = (u8)idx;
    cb = (void *)e->cb1; /* env+20 */
    coex_schm_unlock();
    if (cb != 0)
        ((void (*)(u32))cb)(0);
    return 0;
fail:
    coex_schm_unlock();
    return -1;
}

/* coex_schm_curr_phase_idx_get @ coexist_scheme.o 0000000c size 27B bind GLOBAL
 * Calls: none | Data refs: none
 * Fidelity: high - lock-fail -> -1 else env+4 u8, unlock */
int coex_schm_curr_phase_idx_get(void)
{
    coex_schm_env_t *e = (coex_schm_env_t *)coex_schm_env;
    u32 idx;
    if (coex_schm_lock() != 0)
        return -1;
    idx = e->phase_idx;
    coex_schm_unlock();
    return (int)idx;
}

/* coex_schm_interval_get @ coexist_scheme.o 0000000c size 27B bind GLOBAL
 * Calls: coex_schm_lock, coex_schm_unlock | Data refs: coex_schm_env, coex_schm_lock, coex_schm_unlock
 * Fidelity: high - lock-fail -> 0 else env+12, unlock */
u32 coex_schm_interval_get(void)
{
    coex_schm_env_t *e = (coex_schm_env_t *)coex_schm_env;
    u32 v;
    if (coex_schm_lock() != 0)
        return 0;
    v = e->interval;
    coex_schm_unlock();
    return v;
}

/* coex_schm_interval_set @ coexist_scheme.o 0000000c size 36B bind GLOBAL
 * Calls: none | Data refs: none
 * Fidelity: high - lock-fail -> -1 else env+12 = val, unlock, 0 */
int coex_schm_interval_set(u32 val)
{
    coex_schm_env_t *e = (coex_schm_env_t *)coex_schm_env;
    if (coex_schm_lock() != 0)
        return -1;
    e->interval = val;
    coex_schm_unlock();
    return 0;
}

/* coex_schm_curr_period_get @ coexist_scheme.o 0000000c size 32B bind GLOBAL
 * Calls: coex_schm_lock, coex_schm_unlock | Data refs: coex_schm_env, coex_schm_lock, coex_schm_unlock
 * Fidelity: high - lock-fail -> 1; null table -> 1; else table[1], unlock */
u32 coex_schm_curr_period_get(void)
{
    coex_schm_env_t *e = (coex_schm_env_t *)coex_schm_env;
    u8 *table;
    u32 period = 1;
    if (coex_schm_lock() != 0)
        return 1;
    table = (u8 *)e->table;
    if (table != 0)
        period = table[1];
    coex_schm_unlock();
    return period;
}

/* coex_schm_curr_phase_get @ coexist_scheme.o 0000000c size 45B bind GLOBAL
 * Calls: coex_schm_lock, coex_schm_unlock | Data refs: coex_schm_env, coex_schm_lock, coex_schm_unlock
 * Fidelity: high - lock-fail -> 0; null table -> 0; idx>=count -> 0 else table+idx*4+2, unlock */
void *coex_schm_curr_phase_get(void)
{
    coex_schm_env_t *e = (coex_schm_env_t *)coex_schm_env;
    u8 *table;
    void *ph = 0;
    if (coex_schm_lock() != 0)
        return 0;
    table = (u8 *)e->table;
    if (table != 0 && e->phase_idx < table[0])
        ph = table + e->phase_idx * 4 + 2;
    coex_schm_unlock();
    return ph;
}

/* coex_schm_get_phase_by_idx @ coexist_scheme.o 0000000c size 46B bind GLOBAL
 * Calls: coex_schm_lock, coex_schm_unlock | Data refs: coex_schm_env, coex_schm_lock, coex_schm_unlock
 * Fidelity: high - lock-fail -> 0; null table -> 0; idx>=count -> 0 else table+idx*4+2, unlock */
void *coex_schm_get_phase_by_idx(u32 idx)
{
    coex_schm_env_t *e = (coex_schm_env_t *)coex_schm_env;
    u8 *table;
    void *ph = 0;
    if (coex_schm_lock() != 0)
        return 0;
    table = (u8 *)e->table;
    if (table != 0 && idx < table[0])
        ph = table + idx * 4 + 2;
    coex_schm_unlock();
    return ph;
}

/* coex_schm_register_callback @ coexist_scheme.o 0000000c size 57B bind GLOBAL
 * Calls: coex_schm_lock, coex_schm_unlock | Data refs: coex_schm_env, coex_schm_lock, coex_schm_unlock
 * Fidelity: high - lock-fail -> -1; owner0 -> +52, owner1 -> +20, else -1; unlock, 0 */
int coex_schm_register_callback(u32 owner, void *cb)
{
    coex_schm_env_t *e = (coex_schm_env_t *)coex_schm_env;
    int rc = (int)coex_schm_lock();
    if (rc != 0)
        return -1;
    if (owner == 0)
        e->cb0 = (u32)cb;
    else if (owner == 1)
        e->cb1 = (u32)cb;
    else {
        coex_schm_unlock();
        return -1;
    }
    coex_schm_unlock();
    return 0;
}

/* coex_wifi_channel_set @ coexist_scheme.o 0000000c size 60B bind GLOBAL
 * Calls: coex_schm_lock, coex_schm_unlock | Data refs: coex_schm_env, coex_schm_lock, coex_schm_unlock
 * Fidelity: high - lock-fail -> -1; store chan(+24)/chan2(+25) low bytes, unlock, chan_cb(ch1,ch2) if set, 0 */
int coex_wifi_channel_set(u32 ch1, u32 ch2)
{
    coex_schm_env_t *e = (coex_schm_env_t *)coex_schm_env;
    void *cb;
    if (coex_schm_lock() != 0)
        return -1;
    e->chan = (u8)ch1;
    e->chan2 = (u8)ch2;
    cb = (void *)e->chan_cb;
    coex_schm_unlock();
    if (cb != 0)
        ((void (*)(u32, u32))cb)(ch1 & 0xFFu, ch2 & 0xFFu);
    return 0;
}

/* coex_wifi_channel_get @ coexist_scheme.o 0000001c size 104B bind GLOBAL
 * Calls: coex_schm_lock, coex_schm_unlock, coexist_printf | Data refs: .dram1.6, .rodata.__func__$0, coex_schm_env, coex_schm_lock, coex_schm_unlock, coexist_printf, g_coa_funcs_p
 * Fidelity: high - null outs -> printf("[%u] Invalid argument for %s") + 0x102; lock-fail -> rc; else copy chan/chan2 */
int coex_wifi_channel_get(u8 *ch1, u8 *ch2)
{
    coex_schm_env_t *e = (coex_schm_env_t *)coex_schm_env;
    u32 rc;
    if (ch1 == 0 || ch2 == 0) {
        coexist_printf("[%u] Invalid argument for %s\n",
                       ((u32 (*)(void))*(u32 *)((u8 *)*(void **)g_coa_funcs_p + 60))(),
                       "coex_wifi_channel_get");
        return 0x102;
    }
    rc = coex_schm_lock();
    if (rc != 0)
        return (int)rc;
    *ch1 = e->chan;
    *ch2 = e->chan2;
    coex_schm_unlock();
    return 0;
}

/* coex_register_wifi_channel_change_callback @ coexist_scheme.o 0000000c size 36B bind GLOBAL
 * Calls: coex_schm_lock, coex_schm_unlock | Data refs: coex_schm_env, coex_schm_lock, coex_schm_unlock
 * Fidelity: high - lock-fail -> -1; store +28 (even NULL), unlock, 0 */
int coex_register_wifi_channel_change_callback(void *cb)
{
    coex_schm_env_t *e = (coex_schm_env_t *)coex_schm_env;
    if (coex_schm_lock() != 0)
        return -1;
    e->chan_cb = (u32)cb;
    coex_schm_unlock();
    return 0;
}

/* coex_schm_process_restart @ coexist_scheme.o 00000004 size 16B bind GLOBAL
 * Calls: none | Data refs: none
 * Fidelity: high - change_phase(1), return its result (-1) */
int coex_schm_process_restart(void)
{
    return coex_schm_change_phase(1);
}

/* coex_schm_flexible_period_set @ coexist_scheme.o 0000000c size 44B bind GLOBAL
 * Calls: coex_schm_lock, coex_schm_unlock | Data refs: coex_schm_env, coex_schm_lock, coex_schm_unlock
 * Fidelity: high - lock-fail -> -1; env+58 = low byte, unlock, 0 */
int coex_schm_flexible_period_set(u32 period)
{
    if (coex_schm_lock() != 0)
        return -1;
    coex_schm_env[58] = (u8)period;
    coex_schm_unlock();
    return 0;
}

/* coex_schm_flexible_period_get @ coexist_scheme.o 00000004 size 11B bind GLOBAL
 * Calls: none | Data refs: coex_schm_env
 * Fidelity: high - returns env+58 u8, no lock */
u32 coex_schm_flexible_period_get(void)
{
    return coex_schm_env[58];
}

/* coex_schm_init @ coexist_scheme.o 0000001c size 84B bind GLOBAL
 * Calls: coexist_printf | Data refs: .dram1.7, coex_schm_all_default, coex_schm_env, coexist_printf, g_coa_funcs_p
 * Fidelity: medium - adapter+24 mux once; fail -> printf + 0x101; table=all_default, adapter+76 timer setfn(env+0x20, timeout_process, 0), 0 */
u32 coex_schm_init(void)
{
    coex_schm_env_t *e = (coex_schm_env_t *)coex_schm_env;
    u32 mux;
    if (e->mux == 0) {
        mux = ((u32 (*)(void))*(u32 *)((u8 *)*(void **)g_coa_funcs_p + 24))();
        e->mux = mux;
        if (mux == 0) {
            coexist_printf("[%u] CO: create schm semaphore error!\n",
                           ((u32 (*)(void))*(u32 *)((u8 *)*(void **)g_coa_funcs_p + 60))());
            return 0x101;
        }
    }
    e->table = coex_schm_all_default;
    ((void (*)(void *, void *, u32))*(u32 *)((u8 *)*(void **)g_coa_funcs_p + 76))((void *)(coex_schm_env + 32), coex_schm_timeout_process, 0);
    return 0;
}

/* coex_schm_deinit @ coexist_scheme.o 00000008 size 19B bind GLOBAL
 * Calls: none | Data refs: coex_schm_env, g_coa_funcs_p
 * Fidelity: high - adapter+72(env+0x20); no result move */
void coex_schm_deinit(void)
{
    ((void (*)(void *))*(u32 *)((u8 *)*(void **)g_coa_funcs_p + 72))((void *)(coex_schm_env + 32));
}
