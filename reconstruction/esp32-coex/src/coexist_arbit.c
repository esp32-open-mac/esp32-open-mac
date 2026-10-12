/* Reconstruction of coexist_arbit.o (libcoexist.a) — time-ordered arbit queue.
 * Ground truth: re/esp32-coex/funcdb_libcoexist.json (funcdb v3),
 * re/esp32-coex/disasm/coexist_arbit.dis.
 * Data map (.dram1.x): .dram1.1 (20B) = arbit state {head+0, tail+4, count+8,
 * bitmap+12,+16}; .dram1.2 (4B) = node-pool pointer (1008B = 42*24 via adapter+52);
 * .dram1.3 (4B) = mem-mux handle; .dram1.4 (4B) = arbit-mux handle.
 * Node (24B): prev+0, next+4, key+8 (req w0), time+12 (req w1), aux+16 (req w2),
 * +20 (req w3); slot id = u8 at +10 (pool index = event id, < 42 = coex_prio_tab len).
 * Mutex take/give = adapter fns @+12/@+16 (offsets cited, roles inferred from use).
 */
typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;

extern void *g_coa_funcs_p;
extern u8 arbit_state[20];   /* .dram1.1 */
extern void *arbit_pool;     /* .dram1.2 */
extern void *arbit_mem_mux;  /* .dram1.3 */
extern void *arbit_mux;      /* .dram1.4 */
extern int coexist_printf(const char *fmt, ...);
extern void *memset(void *d, int c, u32 n);
extern void *memcpy(void *d, const void *s, u32 n);
extern u32 coex_time_diff(u32 t1, u32 t2);
extern u32 coex_time_is_in_time(u32 start, u32 window);

typedef struct coex_arbit_state {
    u32 head;      /* +0: node pointer */
    u32 tail;      /* +4: node pointer */
    u32 count;     /* +8 */
    u32 bitmap[2]; /* +12,+16: 64 slot bits */
} coex_arbit_state_t;

typedef struct coex_arbit_entry {
    u32 prev;  /* +0: node pointer */
    u32 next;  /* +4: node pointer */
    u32 key;   /* +8: request w0 (type/prio/event) */
    u32 time;  /* +12: request w1 */
    u32 aux;   /* +16: request w2 */
    u32 aux2;  /* +20: request w3 */
} coex_arbit_entry_t;

/* static arbit_bitmap_find (.iram1.6, no symtab entry; called from insert/delete paths)
 * Calls: none | Data refs: .dram1.1, .dram1.2
 * Fidelity: high - bit test + pool+id*24, NULL when clear */
static void *arbit_bitmap_find(u32 id)
{
    coex_arbit_state_t *st = (coex_arbit_state_t *)arbit_state;
    u8 *pool = (u8 *)arbit_pool;
    u32 word = id >> 5;
    u32 bit = id & 31;
    if (((((u32 *)st)[3 + word]) & (1u << bit)) == 0)
        return 0;
    return pool + id * 24;
}

/* static arbit_unlink (.iram1.12, no symtab entry; called from insert/delete/deinit/clean)
 * Calls: none | Data refs: .dram1.1
 * Fidelity: high - doubly-linked remove + bitmap clear (id = u8 node+10) + count-- */
static void arbit_unlink(void *node_)
{
    coex_arbit_state_t *st = (coex_arbit_state_t *)arbit_state;
    u8 *node = (u8 *)node_;
    u32 prev, next, id;
    if (node == 0)
        return;
    prev = *(u32 *)(node + 0);
    next = *(u32 *)(node + 4);
    if (prev == 0)
        st->head = next;
    else
        *(u32 *)(prev + 4) = next;
    next = *(u32 *)(node + 4);
    if (next == 0)
        st->tail = prev;
    else
        *(u32 *)(next + 0) = prev;
    id = *(u8 *)(node + 10);
    {
        u32 wi = id >> 5; /* disasm: srli/addx4 + src-built clear mask, s32i +12 */
        ((u32 *)st)[3 + wi] &= ~(1u << (id & 31));
    }
    st->count--;
}

/* coex_arbit_insert @ coexist_arbit.o 00000034 size 298B bind GLOBAL
 * Calls: none | Data refs: none
 * Fidelity: medium - exact branch skeleton; linkage stores mapped 1:1, time-order predicate (req-node)<1 exact; adapter take/give offsets cited */
u32 coex_arbit_insert(void *req_)
{
    u8 *req = (u8 *)req_;
    u8 *node;
    u8 *pos;
    u32 r;
    if (req == 0)
        return 0x102;
    r = ((u32 (*)(void))*(u32 *)((u8 *)*(void **)g_coa_funcs_p + 12))();
    if (arbit_bitmap_find(req[2]) != 0)
        arbit_unlink(arbit_bitmap_find(req[2]));
    /* time-ordered scan for first node with (req.w1 - node.time) < 1 */
    pos = (u8 *)((coex_arbit_state_t *)arbit_state)->head;
    while (pos != 0) {
        if ((int)(coex_time_diff(*(u32 *)(pos + 12), *(u32 *)(req + 4))) < 1)
            break;
        pos = *(u8 **)(pos + 4);
    }
    if (arbit_bitmap_find(req[2]) != 0) {
        /* duplicate raced in: give + return 0x101 */
        ((void (*)(void *, u32))*(u32 *)((u8 *)*(void **)g_coa_funcs_p + 16))(arbit_mux, r);
        return 0x101;
    }
    node = (u8 *)arbit_pool + req[2] * 24;
    memset(node, 0, 24);
    memcpy(node + 8, req, 16);
    if (pos != 0) {
        if (*(u8 **)(pos + 0) != 0) {
            /* insert before pos */
            *(u8 **)(node + 0) = *(u8 **)(pos + 0);
            *(u8 **)(node + 4) = pos;
            *(u8 **)(*(u8 **)(pos + 0) + 4) = node;
            *(u8 **)(pos + 0) = node;
        } else {
            /* pos is head */
            *(u8 **)(node + 4) = pos;
            *(u8 **)(pos + 0) = node;
            ((coex_arbit_state_t *)arbit_state)->head = (u32)node;
        }
    } else {
        u8 *tail = (u8 *)((coex_arbit_state_t *)arbit_state)->tail;
        if (tail == 0 && ((coex_arbit_state_t *)arbit_state)->head == 0) {
            ((coex_arbit_state_t *)arbit_state)->tail = (u32)node;
            ((coex_arbit_state_t *)arbit_state)->head = (u32)node;
        } else {
            /* append at tail (degenerate head-set/tail-clear case loops via 10c path) */
            *(u8 **)(node + 0) = tail;
            *(u8 **)(tail + 4) = node;
            ((coex_arbit_state_t *)arbit_state)->tail = (u32)node;
        }
    }
    ((coex_arbit_state_t *)arbit_state)->count++;
    ((coex_arbit_state_t *)arbit_state)->bitmap[req[2] >> 5] |= 1u << (req[2] & 31);
    ((void (*)(void *, u32))*(u32 *)((u8 *)*(void **)g_coa_funcs_p + 16))(arbit_mux, r);
    return 0;
}

/* coex_arbit_delete @ coexist_arbit.o 00000014 size 100B bind GLOBAL
 * Calls: none | Data refs: none
 * Fidelity: high - match (node.key ^ req.w0) & 0x00ff00ff == 0; 0 ok / 0x102 not-found-or-null */
u32 coex_arbit_delete(void *req_)
{
    u8 *req = (u8 *)req_;
    u8 *node;
    u32 r;
    if (req == 0)
        return 0x102;
    r = ((u32 (*)(void))*(u32 *)((u8 *)*(void **)g_coa_funcs_p + 12))();
    node = (u8 *)((coex_arbit_state_t *)arbit_state)->head;
    while (node != 0) {
        if (((*(u32 *)(node + 8) ^ *(u32 *)(req + 0)) & 0x00ff00ffu) == 0)
            break;
        node = *(u8 **)(node + 4);
    }
    if (node == 0) {
        ((void (*)(void *, u32))*(u32 *)((u8 *)*(void **)g_coa_funcs_p + 16))(arbit_mux, r);
        return 0x102;
    }
    arbit_unlink(node);
    ((void (*)(void *, u32))*(u32 *)((u8 *)*(void **)g_coa_funcs_p + 16))(arbit_mux, r);
    return 0;
}

/* coex_arbit_first @ coexist_arbit.o 0000000c size 42B bind GLOBAL
 * Calls: none | Data refs: none
 * Fidelity: high - take; head ? head+8 (payload) : NULL; give */
void *coex_arbit_first(void)
{
    void *head;
    u32 r = ((u32 (*)(void))*(u32 *)((u8 *)*(void **)g_coa_funcs_p + 12))();
    head = (void *)((coex_arbit_state_t *)arbit_state)->head;
    if (head != 0)
        head = (u8 *)head + 8;
    ((void (*)(void *, u32))*(u32 *)((u8 *)*(void **)g_coa_funcs_p + 16))(arbit_mux, r);
    return head;
}

/* coex_arbit_next @ coexist_arbit.o 00000008 size 42B bind GLOBAL
 * Calls: none | Data refs: none
 * Fidelity: high - payload-8 -> next link -> payload; NULL at end; give */
void *coex_arbit_next(void *payload)
{
    void *out = 0;
    u32 r = ((u32 (*)(void))*(u32 *)((u8 *)*(void **)g_coa_funcs_p + 12))();
    if (payload != 0) {
        u8 *node = (u8 *)payload - 8;
        node = *(u8 **)(node + 4);
        if (node != 0)
            out = node + 8;
    }
    ((void (*)(void *, u32))*(u32 *)((u8 *)*(void **)g_coa_funcs_p + 16))(arbit_mux, r);
    return out;
}

/* coex_arbit_clean_overtime @ coexist_arbit.o 00000014 size 68B bind GLOBAL
 * Calls: none | Data refs: none
 * Fidelity: high - unlink nodes with coex_time_is_in_time(node+16, window); window=200 at call sites */
void coex_arbit_clean_overtime(u32 window)
{
    u8 *node;
    u32 r = ((u32 (*)(void))*(u32 *)((u8 *)*(void **)g_coa_funcs_p + 12))();
    node = (u8 *)((coex_arbit_state_t *)arbit_state)->head;
    while (node != 0) {
        u8 *next = *(u8 **)(node + 4);
        if (coex_time_is_in_time(*(u32 *)(node + 16), window) != 0)
            arbit_unlink(node);
        node = next;
    }
    ((void (*)(void *, u32))*(u32 *)((u8 *)*(void **)g_coa_funcs_p + 16))(arbit_mux, r);
}

/* coex_arbit_dump @ coexist_arbit.o 0000000c size 46B bind GLOBAL
 * Calls: none | Data refs: .dram1.1, .dram1.4, g_coa_funcs_p
 * Fidelity: high - take, walk to tail printing nothing (gutted), give */
void coex_arbit_dump(void)
{
    u8 *node;
    u32 r = ((u32 (*)(void))*(u32 *)((u8 *)*(void **)g_coa_funcs_p + 12))();
    node = (u8 *)((coex_arbit_state_t *)arbit_state)->head;
    while (node != 0)
        node = *(u8 **)(node + 4);
    ((void (*)(void *, u32))*(u32 *)((u8 *)*(void **)g_coa_funcs_p + 16))(arbit_mux, r);
}

/* coex_arbit_init @ coexist_arbit.o 00000024 size 170B bind GLOBAL
 * Calls: coexist_printf | Data refs: .dram1.1, .dram1.2, .dram1.24, .dram1.25, .dram1.26, .dram1.3, .dram1.4, coexist_printf, g_coa_funcs_p
 * Fidelity: medium - zero state, adapter+4 x2 muxes (.dram1.3 then .dram1.4), adapter+52 pool (0x3f0=1008B); error strings exact; success returns entry-a2 (0 at enable call site) */
u32 coex_arbit_init(void)
{
    u32 r;
    u32 r2;
    void *pool;
    coex_arbit_state_t *st = (coex_arbit_state_t *)arbit_state;
    st->head = 0;
    st->tail = 0;
    st->count = 0;
    r = ((u32 (*)(void))*(u32 *)((u8 *)*(void **)g_coa_funcs_p + 4))();
    arbit_mem_mux = (void *)r; /* .dram1.3 */
    if (r == 0) {
        coexist_printf("[%u] CO: create arbit mem mux error!\n",
                       ((u32 (*)(void))*(u32 *)((u8 *)*(void **)g_coa_funcs_p + 60))());
        goto out;
    }
    r2 = ((u32 (*)(void))*(u32 *)((u8 *)*(void **)g_coa_funcs_p + 4))();
    arbit_mux = (void *)r2; /* .dram1.4 */
    if (r2 == 0) {
        coexist_printf("[%u] CO: create arbit mux error!\n",
                       ((u32 (*)(void))*(u32 *)((u8 *)*(void **)g_coa_funcs_p + 60))());
        goto out;
    }
    st->bitmap[0] = 0;
    st->bitmap[1] = 0;
    pool = ((void *(*)(u32))*(u32 *)((u8 *)*(void **)g_coa_funcs_p + 52))(0x3f0);
    arbit_pool = pool; /* .dram1.2 */
    if (pool == 0) {
        coexist_printf("[%u] Coex arbit init: no memory!\n",
                       ((u32 (*)(void))*(u32 *)((u8 *)*(void **)g_coa_funcs_p + 60))());
        goto out;
    }
    return 0; /* disasm: no result move; enable call site passes outgoing a10=0 */
out:
    if (arbit_mem_mux != 0) {
        ((void (*)(void *))*(u32 *)((u8 *)*(void **)g_coa_funcs_p + 8))(arbit_mem_mux);
        arbit_mem_mux = 0;
    }
    if (arbit_mux != 0) {
        ((void (*)(void *))*(u32 *)((u8 *)*(void **)g_coa_funcs_p + 8))(arbit_mux);
        arbit_mux = 0;
    }
    return 0x101;
}

/* coex_arbit_deinit @ coexist_arbit.o 00000034 size 246B bind GLOBAL
 * Calls: .iram1.12, coexist_printf | Data refs: .dram1.1, .dram1.2, .dram1.27, .dram1.28, .dram1.29, .dram1.3, .dram1.4, .iram1.12, .rodata.str1.1, coexist_printf, g_coa_funcs_p
 * Fidelity: medium - all-or-nothing state asserts (0x1b7/0x1b8/0x1b9 hangs), drain via unlink, frees; one stale-a2 store noted */
u32 coex_arbit_deinit(void)
{
    u8 *node;
    u32 r;
    if (arbit_mux == 0) {
        if (arbit_mem_mux != 0)
            goto corrupt_b8; /* hang "[%u] %s %u" line 0x1b8 */
        if (arbit_pool != 0)
            goto corrupt_b9; /* hang line 0x1b9 */
        return 0x103; /* already deinit */
    }
    if (arbit_mem_mux == 0)
        goto corrupt_b7; /* hang line 0x1b7 */
    if (arbit_pool == 0)
        goto corrupt_b7; /* hang line 0x1b7 */
    r = ((u32 (*)(void))*(u32 *)((u8 *)*(void **)g_coa_funcs_p + 12))();
    node = (u8 *)((coex_arbit_state_t *)arbit_state)->head;
    while (node != 0) {
        u8 *next = *(u8 **)(node + 4);
        arbit_unlink(node);
        node = next;
    }
    ((void (*)(void *, u32))*(u32 *)((u8 *)*(void **)g_coa_funcs_p + 16))(arbit_mux, r);
    if (arbit_pool != 0) {
        ((void (*)(void *))*(u32 *)((u8 *)*(void **)g_coa_funcs_p + 56))(arbit_pool);
        /* disasm f6: s32i a2,(pool-var) with a2 stale (adapter+12 target from b9);
         * no zeroing insn present; stored value unresolvable offline (left as-is) */
    }
    if (arbit_mem_mux != 0) {
        ((void (*)(void *))*(u32 *)((u8 *)*(void **)g_coa_funcs_p + 8))(arbit_mem_mux);
        arbit_mem_mux = 0;
    }
    if (arbit_mux != 0) {
        ((void (*)(void *))*(u32 *)((u8 *)*(void **)g_coa_funcs_p + 8))(arbit_mux);
        arbit_mux = 0;
    }
    return 0x103;
corrupt_b7:
    coexist_printf("[%u] %s %u\n",
                   ((u32 (*)(void))*(u32 *)((u8 *)*(void **)g_coa_funcs_p + 60))(),
                   "coexist_arbit.c", 0x1b7);
    for (;;) { }
corrupt_b8:
    coexist_printf("[%u] %s %u\n",
                   ((u32 (*)(void))*(u32 *)((u8 *)*(void **)g_coa_funcs_p + 60))(),
                   "coexist_arbit.c", 0x1b8);
    for (;;) { }
corrupt_b9:
    coexist_printf("[%u] %s %u\n",
                   ((u32 (*)(void))*(u32 *)((u8 *)*(void **)g_coa_funcs_p + 60))(),
                   "coexist_arbit.c", 0x1b9);
    for (;;) { }
}
