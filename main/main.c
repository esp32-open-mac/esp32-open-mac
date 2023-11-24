#include "freertos/FreeRTOS.h"

#include "esp_event.h"
#include "esp_system.h"
#include "esp_event.h"
#include "esp_wifi.h"
#include "esp_log.h"


#include "nvs_flash.h"
#include "string.h"

static const char* TAG = "esp32-open-mac";

void wifi_hw_start(int disable_power_management);
bool pp_post(uint32_t requestnum, uint32_t argument);
void wifi_set_rx_policy(uint8_t command);
void intr_matrix_set(uint32_t first, uint32_t second, uint32_t third);
uint32_t config_get_wifi_task_core_id();
void esp_cpu_intr_enable(uint32_t num);

uint8_t beacon_raw[] = {0x80, 0x00, 0x00, 0x00,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xba, 0xde, 0xaf, 0xfe, 0x00, 0x00,
	0xba, 0xde, 0xaf, 0xfe, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x64, 0x00, 0x31, 0x04, 0x00, 0x10, 0x45, 0x53, 0x50, 0x20, 0x62, 0x65, 0x61, 0x63, 0x6f, 0x6e, 0x20, 0x66, 0x72, 0x61, 0x6d, 0x65, 0x01, 0x08, 0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24, 0x03, 0x01, 0x01, 0x05, 0x04, 0x01, 0x02, 0x00, 0x00,
	0xef, 0xbe, 0xad, 0xde // last 4 bytes are a place holder FCS, because it is calculated by the hardware itself
};

inline void write_register(uint32_t address, uint32_t value) {
	*((volatile uint32_t*) address) = value;
}

inline uint32_t read_register(uint32_t address) {
	return *((volatile uint32_t*) address);
}

#define WIFI_DMA_OUTLINK 0x3ff73d20
#define WIFI_TX_CONFIG_0 0x3ff73d1c

#define MAC_TX_PLCP1 0x3ff74258
#define MAC_TX_PLCP2 0x3ff7425c
#define MAC_TX_DURATION 0x3ff74268

#define WIFI_DMA_INT_STATUS 0x3ff73c48

void transmit_one(uint8_t index) {
	uint32_t buffer_len = sizeof(beacon_raw); // this includes the FCS
	uint32_t size_len = buffer_len + 32;

	// change the ssid, so that we're sure we're transmitting different packets
	beacon_raw[38] = 'a' + (index % 26);

	// owner 1, eof 1, unknown 6, lenght 12, size 12
	uint32_t dma_item_first = ((1 << 31) | (1 << 30) | (buffer_len << 12) | size_len);

	uint32_t dma_item[3] = {dma_item_first, ((uint32_t) beacon_raw), 0};

	write_register(WIFI_TX_CONFIG_0, read_register(WIFI_TX_CONFIG_0) | 0xa);

	write_register(WIFI_DMA_OUTLINK,
		(((uint32_t)dma_item) & 0xfffff) |
		(0x00600000));

	write_register(MAC_TX_PLCP1, 0x1000004d);
	write_register(MAC_TX_PLCP2, 0x00000020);
	write_register(MAC_TX_DURATION, 0);
	
	write_register(WIFI_TX_CONFIG_0, read_register(WIFI_TX_CONFIG_0) | 0x02000000);

	write_register(WIFI_TX_CONFIG_0, read_register(WIFI_TX_CONFIG_0) | 0x00003000);
	
	// TRANSMIT!
	write_register(WIFI_DMA_OUTLINK, read_register(WIFI_DMA_OUTLINK) | 0xc0000000);

	ESP_LOGW(TAG, "packet should have been sent");
}

typedef struct
{
	uint32_t interrupt_received;
} rx_message;

QueueHandle_t rx_message_queue = NULL;

volatile int touched = 0;

void IRAM_ATTR wifi_interrupt_handler(void* args) {
	touched++;
	return;
	// while (true)  {
	// 	uint32_t cause = read_register(WIFI_DMA_INT_STATUS);
	// 	if (rx_message_queue != NULL) {
	// 		rx_message message;
	// 		message.interrupt_received = cause;
	// 		xQueueSendFromISR(rx_message_queue, &message, NULL);
	// 	}
	// 	write_register(WIFI_DMA_INT_STATUS, 0);

	// 	if (cause == 0) {
	// 		return;
	// 	}

	// 	if (cause & 0x800) {
	// 		// Watchdog panic
	// 		// TODO process this
	// 	}
	// 	if (cause & 0x600000) {
	// 		// TODO this is bad, we should reboot
	// 	}
	// 	if (cause & 0x1000024) {
	// 		// Receive message here 0x19
	// 	}
	// 	if (cause & 0x80) {
	// 		// lmacPostTxComplete 0x17
	// 		// Maybe only interrupt if we receive an ack?
	// 	}
	// 	if (cause & 0x80000) {
	// 		// lmacProcessAllTxTimeout 0x16
	// 	}
	// 	if (cause & 0x100) {
	// 		// lmacProcessCollisions 0x18
	// 	}
	// }
}

void setup_interrupt() {
	ESP_LOGW(TAG, "installing new interrupt handler");
	intr_matrix_set(config_get_wifi_task_core_id(), 0, 0);
	
	// Replace the existing wDev_ProcessFiq interrupt
	void* out = xt_set_interrupt_handler(0, &wifi_interrupt_handler, NULL);
	ESP_LOGW(TAG, "old was %p, new is %p", out, &wifi_interrupt_handler);

	esp_cpu_intr_enable(1);
}


void rx_task(void *pvParameter) {
	ESP_LOGW(TAG, "starting rx_task");
	rx_message_queue = xQueueCreate(16, sizeof(rx_message));
	if (rx_message_queue == NULL) {
		ESP_LOGE(TAG, "failed to create queue\n");
	}

	// setup_interrupt();

	// ESP_LOGW(TAG, "killing ppTask");
	// // Kill the wifi task
	// pp_post(0xf, 0);

	// Set RX policy
	wifi_set_rx_policy(3);

	ESP_LOGW(TAG, "starting to receive messages\n");
	
	while (true) {
		rx_message message;
		if (xQueueReceive(rx_message_queue, &(message), (TickType_t)5)) {
			ESP_LOGW(TAG, "Received message, interrupt = 0x%08lx", message.interrupt_received);
			// TODO: do something with message
		}
		vTaskDelay(1000 / portTICK_PERIOD_MS);
		transmit_one(2);
		ESP_LOGW(TAG, "transmitted, touched=%d, intr_status=%08lx", touched, read_register(WIFI_DMA_INT_STATUS));
	}
}

void tx_task(void *pvParameter) {
	ESP_LOGW(TAG, "wifi_hw_start");
	wifi_hw_start(1);
	vTaskDelay(200 / portTICK_PERIOD_MS);

	for (int i = 0; i < 2; i++) {
		uint8_t mac[6] = {0};
		if (esp_wifi_get_mac(i, mac) == ESP_OK) {
			ESP_LOGW(TAG, "MAC %d = %02x:%02x:%02x:%02x:%02x:%02x", i, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
		}
	}


	for (int i = 0; i < 3; i++) {
		ESP_LOGW(TAG, "going to transmit in %d", 3 - i);
		vTaskDelay(1000 / portTICK_PERIOD_MS);
	}
	
	ESP_LOGW(TAG, "transmitting now!");
	for (int i = 0; i < 2; i++) {
		ESP_LOGW(TAG, "transmit iter %d", i);
		transmit_one(i);
		ESP_LOGW(TAG, "still alive");
		vTaskDelay(500 / portTICK_PERIOD_MS);
	}
	xTaskCreate(&rx_task, "rx_task", 4096, NULL, 5, NULL);


	while (1) {
		ESP_LOGW(TAG, "tx done");
		vTaskDelay(5000 / portTICK_PERIOD_MS);
	}
}



void app_main(void) {
	ESP_LOGW(TAG, "initializing NVS");
	// Initialize NVS
	esp_err_t ret = nvs_flash_init();
	if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
		ESP_ERROR_CHECK(nvs_flash_erase());
		ret = nvs_flash_init();
	}
	ESP_ERROR_CHECK(ret);

	wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
	ESP_LOGW(TAG, "calling esp_wifi_init");
	ESP_ERROR_CHECK(esp_wifi_init(&cfg));
	ESP_LOGW(TAG, "done esp_wifi_init");

	xTaskCreate(&tx_task, "tx_task", 4096, NULL, 5, NULL);
}
