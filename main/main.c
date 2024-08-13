#include <string.h>


#include "esp_system.h"
#include "esp_event.h"
#include "freertos/FreeRTOS.h"
#include "esp_log.h"
#include "esp_phy_init.h" // for get_phy_version_str

#include "hardware.h"
#include "mac.h"

#include "80211_mac_rust.h"

static const char* TAG = "main";

#ifndef CONFIG_IDF_TARGET_ESP32
#error "This uses low-level hardware peripherals and hardcoded addresses, it is only tested on the plain ESP32 for now"
#endif

#if (!(ESP_IDF_VERSION_MAJOR == 5 && ESP_IDF_VERSION_MINOR == 0 && ESP_IDF_VERSION_PATCH == 1))
#error "This project currently still uses the proprietary wifi library for initialization, this was only tested with ESP-IDF v5.0.1"
#endif

hardware_mac_args open_hw_args = {
	._rx_callback = open_mac_rx_callback,
	._tx_func_callback = open_mac_tx_func_callback
};

void app_main(void) {
    ESP_LOGE(TAG, "%s\n", hello());
	const char* actual_version_string = get_phy_version_str();
	const char* expected_version_string = "4670,719f9f6,Feb 18 2021,17:07:07";
	if (strcmp(expected_version_string, actual_version_string) != 0) {
		ESP_LOGE(TAG, "get_phy_version_str() wrong: is '%s' but should be '%s'", actual_version_string, expected_version_string);
		abort();
	}

	esp_netif_init();
	// Low priority numbers denote low priority tasks.
	xTaskCreatePinnedToCore(&mac_task,           "open_mac",      4096, NULL,          /*prio*/ 23, NULL, /*core*/ 1);
	xTaskCreatePinnedToCore(&wifi_hardware_task, "wifi_hardware", 4096, &open_hw_args, /*prio*/ 23, NULL, /*core*/ 0);
	openmac_netif_start();
}
