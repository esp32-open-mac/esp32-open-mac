#include "80211_mac_interface.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"

#include <stdlib.h>


typedef struct {
	void* ptr;
	rs_event_type_t event_type;
} rust_mac_event_queue_item_t;

QueueHandle_t rust_mac_event_queue = NULL;

void interface_init() {
	rust_mac_event_queue = xQueueCreate(30, sizeof(rust_mac_event_queue_item_t));
	assert(rust_mac_event_queue);
}

bool rs_get_next_mac_event_raw(uint32_t ms_to_wait, rs_event_type_t* event_type, void** ptr) {
	rust_mac_event_queue_item_t item;
	if (xQueueReceive(rust_mac_event_queue, &item, ms_to_wait / portTICK_PERIOD_MS)) {
		*event_type = item.event_type;
		*ptr = item.ptr;
		return true;
	}
	return false;
}
