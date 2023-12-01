#include "esp_system.h"
#include "esp_event.h"
#include "freertos/FreeRTOS.h"

#include "hardware.h"
#include "mac.h"

#ifndef CONFIG_IDF_TARGET_ESP32
#error "This uses low-level hardware peripherals and hardcoded addresses, it is only tested on the plain ESP32 for now"
#endif

hardware_mac_args open_hw_args = {
	._rx_callback = open_mac_rx_callback,
	._tx_func_callback = open_mac_tx_func_callback
};

void app_main(void) {
	xTaskCreatePinnedToCore(&wifi_hardware_task, "wifi_hardware", 4096, &open_hw_args, /*prio*/ 5, NULL, /*core*/ 0);
	xTaskCreatePinnedToCore(&mac_task,           "open_mac",      4096, NULL,          /*prio*/ 3, NULL, /*core*/ 1);
}
