#include "hardware.h"
typedef enum {
    IDLE,
    AUTHENTICATED,
    ASSOCIATED,
} openmac_sta_state_t;

void open_mac_rx_callback(wifi_promiscuous_pkt_t* packet);
void open_mac_tx_func_callback(tx_func* t);

void mac_task(void* pvParameters);