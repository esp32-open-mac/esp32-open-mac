#pragma once
#include <stdint.h>
/**
 * QEMU WLAN device emulation
 *
 * Copyright (c) 2008 Clemens Kolbitsch
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 *
 * Modifications:
 *  2008-February-24  Clemens Kolbitsch :
 *                                  New implementation based on ne2000.c
 *  18/1/22 Martin Johnson : Modified for esp32 wifi emulation
 *  15/10/2023 redfast00: modified for ESP32 wifi implementation
 */

#define QEMU_PACKED __attribute__((packed))


#define IEEE80211_TYPE_MGT              0x00
#define IEEE80211_TYPE_CTL              0x01
#define IEEE80211_TYPE_DATA             0x02

#define IEEE80211_TYPE_MGT_SUBTYPE_BEACON           0x08
#define IEEE80211_TYPE_MGT_SUBTYPE_ACTION           0x0d
#define IEEE80211_TYPE_MGT_SUBTYPE_PROBE_REQ        0x04
#define IEEE80211_TYPE_MGT_SUBTYPE_PROBE_RESP       0x05
#define IEEE80211_TYPE_MGT_SUBTYPE_AUTHENTICATION   0x0b
#define IEEE80211_TYPE_MGT_SUBTYPE_DEAUTHENTICATION 0x0c
#define IEEE80211_TYPE_MGT_SUBTYPE_ASSOCIATION_REQ  0x00
#define IEEE80211_TYPE_MGT_SUBTYPE_ASSOCIATION_RESP 0x01
#define IEEE80211_TYPE_MGT_SUBTYPE_DISASSOCIATION   0x0a

#define IEEE80211_TYPE_CTL_SUBTYPE_ACK          0x0d

#define IEEE80211_TYPE_DATA_SUBTYPE_DATA        0x00

typedef uint8_t macaddr_t[6];

#define BROADCAST_MAC (uint8_t[]){0xff,0xff,0xff,0xff,0xff,0xff}

typedef struct mac80211_frame {
    struct mac80211_frame_control {
        unsigned    protocol_version    : 2;
        unsigned    type            : 2;
        unsigned    sub_type        : 4;
        unsigned    to_ds           : 1;
        unsigned    from_ds         : 1;
        unsigned    _flags:6;
    } QEMU_PACKED frame_control;
    uint16_t  duration_id;
    macaddr_t receiver_address;
    macaddr_t transmitter_address;
    macaddr_t address_3;
    struct mac80211_sequence_control {
        unsigned    fragment_number     : 4;
        unsigned    sequence_number     : 12;
    } QEMU_PACKED sequence_control;
    uint8_t data_and_fcs[2316];
}  QEMU_PACKED mac80211_frame;