#include "esp_wifi.h"
#include "esp_log.h"
#include "esp_phy_init.h"
#include "hardware.h"

static const char* TAG = "hwinit";

#define IC_MAC_INIT_REGISTER _MMIO_DWORD(0x3ff73cb8)

// Closed source symbols:
void wifi_hw_start(int a);
void wifi_module_enable();
void ic_mac_init();
void chm_init(void* ptr);
void ic_enable();
void chip_enable();
void pm_noise_check_enable();
int64_t esp_timer_get_time();
void coex_bt_high_prio();
extern void* g_ic;
extern uint32_t g_wifi_mac_time_delta;
// End of closed source symbols

// Open source symbols:
esp_err_t adc2_wifi_acquire();
void wifi_reset_mac();
void esp_phy_common_clock_enable();
void esp_phy_load_cal_and_init();
// End of open source symbols

void wifi_station_start_openmac() {
    // this does hal_enable_sta_tsf and ic_set_vif; which we already handle in open code
} 

esp_err_t _do_wifi_start_openmac(wifi_mode_t mode) {
    wifi_station_start_openmac();
    return ESP_OK;
}
void esp_wifi_internal_update_mac_time_openmac(uint32_t diff) {
    g_wifi_mac_time_delta += diff;
}
static inline void phy_update_wifi_mac_time(bool en_clock_stopped, int64_t now)
{
    static uint32_t s_common_clock_disable_time = 0;

    if (en_clock_stopped) {
        s_common_clock_disable_time = (uint32_t)now;
    } else {
        if (s_common_clock_disable_time) {
            uint32_t diff = (uint64_t)now - s_common_clock_disable_time;
            esp_wifi_internal_update_mac_time_openmac(diff);
            s_common_clock_disable_time = 0;
        }
    }
}
void esp_phy_enable_openmac() {
    // setting the time is only required on the ESP32
    int64_t phy_timestamp = esp_timer_get_time();
    // effectively a no-op
    phy_update_wifi_mac_time(false, phy_timestamp);

    esp_phy_common_clock_enable();

    // we assume the phy isn't calibrated yet, so we'll always calibrate it first.
    esp_phy_load_cal_and_init();

    // setting coex prio is only required on ESP32
    coex_bt_high_prio();
}

void ic_mac_init_openmac() {
    // taken from libpp/hal_mac.o hal_mac_init
    IC_MAC_INIT_REGISTER &= 0xffffe800;
}

void wifi_hw_start_openmac(wifi_mode_t mode) {
    // wifi_apb80m_request_wrapper is empty on ESP32
 
    // wifi_clock_enable_wrapper =
    wifi_module_enable();
    
    esp_phy_enable_openmac();

    // coex_enable_wrapper is empty on ESP32
    
    wifi_reset_mac();
    ic_mac_init_openmac();
    chm_init(&g_ic);
    ic_enable();
    chip_enable();
    pm_noise_check_enable();
}

void wifi_start_process_openmac() {
	ESP_ERROR_CHECK(adc2_wifi_acquire());
    wifi_hw_start_openmac(0);
    // not needed: ESP_ERROR_CHECK(wifi_mode_set(WIFI_MODE_STA));
    ESP_ERROR_CHECK(_do_wifi_start_openmac(WIFI_MODE_STA));
}

void hwinit() {
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
	cfg.static_rx_buf_num = 2; // we won't use these buffers, so reduce the amount from default 10, so we don't waste as much memory
	// Disable AMPDU and AMSDU for now, we don't support this (yet)
	cfg.ampdu_rx_enable = false;
	cfg.ampdu_tx_enable = false;
	cfg.amsdu_tx_enable = false;
	cfg.nvs_enable = false;
    ESP_LOGW(TAG, "calling esp_wifi_init");
	ESP_ERROR_CHECK(esp_wifi_init(&cfg));
	// esp_phy_common_clock_enable();
	ESP_LOGW(TAG, "done esp_wifi_init");

	ESP_LOGW(TAG, "Starting wifi_hardware task, running on %d", xPortGetCoreID());
	ESP_LOGW(TAG, "calling esp_wifi_set_mode");
	ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
	ESP_LOGW(TAG, "done esp_wifi_set_mode");

	ESP_LOGW(TAG, "calling esp_wifi_start");
	wifi_start_process_openmac();
	ESP_LOGW(TAG, "done esp_wifi_start");
}