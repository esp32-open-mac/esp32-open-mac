#pragma once
#include "esp_wifi.h"

typedef void rx_callback(wifi_promiscuous_pkt_t* packet);

typedef bool tx_func(uint8_t* packet, uint32_t len);

typedef void tx_func_callback(tx_func* t);

typedef struct hardware_mac_args {
	rx_callback* _rx_callback;
    tx_func_callback* _tx_func_callback;
} hardware_mac_args;

void wifi_hardware_task(hardware_mac_args* pvParameter);