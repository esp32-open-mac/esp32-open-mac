#pragma once
#include <stdint.h>
#include "xtensa/config/core.h"

#define NUM_CORES 2

// All extern function shown here are symbols in the binary blobs
extern bool pp_post(uint32_t requestnum, uint32_t argument);

// Interrupt-related functions
extern void xt_unhandled_interrupt(void * arg);
extern uint32_t config_get_wifi_task_core_id();

// extern void wdev_process_panic_watchdog();

// Power calibration of TX
extern void tx_pwctrl_background(int a, int b);

// changing channel
extern void chip_v7_set_chan_nomac(uint8_t channel, uint8_t _unknown);
extern void disable_wifi_agc();
extern void enable_wifi_agc();

typedef struct xt_handler_table_entry {
    void * handler;
    void * arg;
} xt_handler_table_entry;
extern xt_handler_table_entry _xt_interrupt_table[XCHAL_NUM_INTERRUPTS*NUM_CORES];
