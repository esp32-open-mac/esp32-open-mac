#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>

#include "80211_mac_interface.h"

#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"

#define IEEE80211_MAX_FRAME_LEN   (2352)

#define NUM_TX_SMART_FRAME_BUFFERS (5)

typedef struct {
	void* ptr;
	rs_event_type_t event_type;
} rust_mac_event_queue_item_t;

typedef struct {
	rs_smart_frame_t* frame;
	bool in_use;
} smart_frame_tracker_t;

static QueueHandle_t rust_mac_event_queue = NULL;
smart_frame_tracker_t smart_frame_tracker_list[NUM_TX_SMART_FRAME_BUFFERS] = {{0}};
bool init_done = false;

void interface_init() {
	// TODO remove hard-coded 30
	rust_mac_event_queue = xQueueCreate(30 + NUM_TX_SMART_FRAME_BUFFERS, sizeof(rust_mac_event_queue_item_t));
	assert(rust_mac_event_queue);

	for (int i = 0; i < NUM_TX_SMART_FRAME_BUFFERS; i++) {
		uint8_t* payload = malloc(IEEE80211_MAX_FRAME_LEN);
		rs_smart_frame_t* smart_frame = malloc(sizeof(rs_smart_frame_t));
		smart_frame->payload = payload;
		smart_frame->payload_size = IEEE80211_MAX_FRAME_LEN;
		smart_frame_tracker_list[i].frame = smart_frame;
		smart_frame_tracker_list[i].in_use = false;
	}
	init_done = true;
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

/*Called from the Rust MAC stack, to obtain a smart frame from the hardware, which can then be filled in*/
rs_smart_frame_t* rs_get_smart_frame(size_t size_required) {
	for (int i = 0; i < NUM_TX_SMART_FRAME_BUFFERS; i++) {
		if (!smart_frame_tracker_list[i].in_use && smart_frame_tracker_list[i].frame->payload_size >= size_required) {
			smart_frame_tracker_list[i].in_use = true;
			smart_frame_tracker_list[i].frame->payload_length = 0;
			return smart_frame_tracker_list[i].frame;
		}
	}
	return NULL;
}

// declaration
bool transmit_80211_frame(rs_smart_frame_t* frame);

/*Called from the Rust MAC stack, to TX a smart frame previously obtained via rs_get_smart_frame*/
void rs_tx_smart_frame(rs_smart_frame_t* frame) {
	// TODO eventually use a frame queue when we want to send more than 5 frames at a time
    transmit_80211_frame(frame);
}

void c_hand_rx_to_mac_stack(dma_list_item* item) {
	rust_mac_event_queue_item_t to_queue;
	to_queue.event_type = EVENT_TYPE_PHY_RX_DATA;
	to_queue.ptr = item;
	xQueueSendToBack(rust_mac_event_queue, &to_queue, 0);
}

/*
  Called from the hardware stack to recycle a smart frame after it was sent
*/
void c_recycle_tx_smart_frame(rs_smart_frame_t* frame) {
	for (int i = 0; i < NUM_TX_SMART_FRAME_BUFFERS; i++) {
		if (smart_frame_tracker_list[i].frame == frame) {
			smart_frame_tracker_list[i].in_use = false;
			return;
		}
	}
	// if we reached this, we somehow recycled a frame that doesn't correspond to a smart frame
	abort();
}

/*Called from the Rust MAC stack, to pass a data frame to the MAC stack. Expects the frame to be in Ethernet format*/
void rs_rx_mac_frame(uint8_t* frame, size_t len);

/*Called from the the IP stack, to hand an RX frame back*/
void c_recycle_rx_frame(uint8_t* frame) {

}

void c_mac_task() {
	interface_init();
	rust_mac_task();
}