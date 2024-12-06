#pragma once
#include "esp_wifi.h"

void wifi_hardware_task(void* pvParameter);
extern uint8_t iface_1_mac_addr[6];
extern uint8_t iface_2_mac_addr[6];

#define _MMIO_DWORD(mem_addr) (*(volatile uint32_t *)(mem_addr))
#define _MMIO_ADDR(mem_addr) ((volatile uint32_t*)(mem_addr))