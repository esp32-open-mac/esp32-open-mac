#pragma once
#include <stdint.h>

// All extern function shown here are symbols in the binary blobs
extern bool pp_post(uint32_t requestnum, uint32_t argument);

// Interrupt-related functions
extern void xt_unhandled_interrupt(void * arg);
extern uint32_t config_get_wifi_task_core_id();

// extern void wdev_process_panic_watchdog();

typedef struct xt_handler_table_entry {
    void * handler;
    void * arg;
} xt_handler_table_entry;
extern xt_handler_table_entry _xt_interrupt_table[XCHAL_NUM_INTERRUPTS*portNUM_PROCESSORS];