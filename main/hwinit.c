#include "esp_log.h"
#include "esp_phy_init.h"
#include "hardware.h"

static const char* TAG = "hwinit";

#define IC_MAC_INIT_REGISTER _MMIO_DWORD(0x3ff73cb8)
#define WIFI_MAC_BITMASK_084 _MMIO_DWORD(0x3ff73084)

// Closed source symbols:
void wifi_hw_start(int a);
void wifi_module_enable();
void ic_mac_init();
void ic_enable();
void ic_enable_rx();
void pm_noise_check_enable();
int64_t esp_timer_get_time();
void coex_bt_high_prio();
void* phy_get_romfuncs();
void ets_timer_setfn(volatile void *, void *, void *);
void ieee80211_timer_process(uint32_t, uint32_t, void *);
void mutex_lock_wraper(void *);
void mutex_unlock_wraper(void *);
void hal_mac_tsf_reset();
uint32_t g_wifi_mac_time_delta_openmac;
extern void* g_wifi_nvs;
extern void* g_wifi_global_lock;

// End of closed source symbols

// Open source symbols:
esp_err_t adc2_wifi_acquire();
void wifi_reset_mac();
void esp_phy_common_clock_enable();
void esp_phy_load_cal_and_init();
// End of open source symbols

// [[openmac-coverage:implemented]]
void wifi_station_start_openmac() {
    // this does hal_enable_sta_tsf and ic_set_vif; which we already handle in open code
} 
void acquire_lock() {
    mutex_lock_wraper(g_wifi_global_lock);
}
void release_lock() {
    mutex_unlock_wraper(g_wifi_global_lock);
}

// [[openmac-coverage:implemented]]
esp_err_t _do_wifi_start_openmac(uint8_t mode) {
    wifi_station_start_openmac();
    hal_mac_tsf_reset(0);
    return ESP_OK;
}

void esp_wifi_internal_update_mac_time_openmac(uint32_t diff) {
    g_wifi_mac_time_delta_openmac += diff;
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

// [[openmac-coverage:implemented]]
void ic_mac_init_openmac() {
    // taken from libpp/hal_mac.o hal_mac_init
    IC_MAC_INIT_REGISTER &= 0xffffe800;
}

void hal_init();
void esp_wifi_power_domain_on();

void periph_module_reset(int a);

void wifi_hw_start_openmac(uint8_t mode) {
    esp_wifi_power_domain_on();
    wifi_module_enable();
    
    esp_phy_enable_openmac();

    // wifi_reset_mac();
    periph_module_reset(0x19);
    coex_bt_high_prio();
    WIFI_MAC_BITMASK_084 = WIFI_MAC_BITMASK_084 & 0x7fffffff;


    ic_mac_init_openmac();
    hal_init(); // the only needed function from ic_enable
    ic_enable_rx();
}

void hwinit() {
	ESP_ERROR_CHECK(adc2_wifi_acquire());
    wifi_hw_start_openmac(0);
    ESP_ERROR_CHECK(_do_wifi_start_openmac(0));
}