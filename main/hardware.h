#pragma once
#include "esp_wifi.h"

void wifi_hardware_task(void* pvParameter);
extern uint8_t module_mac_addr[6];

#define _MMIO_DWORD(mem_addr) (*(volatile uint32_t *)(mem_addr))
#define _MMIO_ADDR(mem_addr) ((volatile uint32_t*)(mem_addr))