# ESP32 open Wi-Fi MAC proof-of-concept

This is a proof-of-concept, showing how to use the ESP32 Wi-Fi hardware peripherals. Espressif (the manufacturer of the ESP32) did not document the Wi-Fi hardware peripherals in any of their (public) datasheets, so we had to reverse engineer the functionality of the hardware, see https://zeus.ugent.be/blog/23-24/open-source-esp32-wifi-mac/ for how this was done. The goal is to have a Wi-Fi capable, blob-free SDK/firmware for the ESP32.

## Features

Currently, we can send and receive frames, without any proprietary code *running* (proprietary code is still used to initialize the hardware in the begin, but is not needed anymore after that). We've implemented a minimal MAC layer that can scan all channels and then connect to a predefined open network.

- [X] Sending wifi frames
- [X] Receiving wifi frames
- [X] Send an ACK packet as reply to packets that are sent to the ESP32
- [X] intermediate goal: connect to an open access point & send UDP packets
- [X] intermediate goal: use the ESP-NETIF custom IO driver to tie our Wi-Fi driver into the higher-level lwIP stack
- [x] Switching channels
- [x] Changing rate
- [x] Adjusting TX power
- [X] Hardware packet filtering based on MAC address (we previously used promiscuous mode to receive all packets, but this is a bit inefficient)
- [ ] Implement wifi hardware initialization ourselves (this is now done using the functions in the proprietary blobs)
- [x] Connect our sending, receiving and other primitives to an open source 802.11 MAC implementation to handle association/authentication
- [ ] Connecting to WPA2 networks w/ hardware acceleration
- [ ] WPA3 dragonfly handshake
- [ ] AP mode
- [ ] 802.11s mesh networking
- [ ] dual AP/client
- [x] decouple blobs from ESP-IDF version

## Building instructions

TODO elaborate on this

- install ESP-IDF v5.0.1 (ideally via vscode)
- install ESP32 Rust toolchain (https://docs.esp-rs.org/book/installation/index.html)
- compile and flash to an ESP32

## Frequently asked questions

### What is the license of this project?

See the license/README.md in this repository

### What is the goal of this project?

At the moment, developers that use the ESP32 are dependent on Espressif for features and bug fixes related to the Wi-Fi functionality. If the MAC layer were to be open sourced, we could fix bugs and implement features ourselves (as long as only a software change is needed). The ESP32 seems to have a SoftMAC architecture, so most of the Wi-Fi implementation is done in software, not in hardware. An open-source implementation also allows for easier security audits. The goal of this project is to document how the Wi-Fi hardware inside the ESP32 and related chips work, in order to make open-source implementations possible.

My original goal was to have 802.11 standards compliant mesh networking (IEEE 802.11s) on the ESP32. Espressif has their own version of mesh networking, but their implementation has several technical drawbacks:

- it's not compatible with other devices
- it forces a rather awkward tree topology, forcing the entire network to be rebuild if the root node goes down
- it uses NAT instead of layer 2 ethernet routing, so it's hard to reach nodes in the mesh network from outside of the mesh network

### On what microcontrollers does this run?

At the moment, this only runs on the plain ESP32 (so not the ESP32-S2, ESP32-S3 or other variants).
This is because the location and functionality of the Wi-Fi hardware peripherals is hardcoded.
Porting this to other variants of the ESP32 might or might not be trivial, depending on how similar the internal hardware is. From some basic reverse engineering work, we're seeing that there are a lot of similarities.

This project was only tested against ESP-IDF v5.0.1; but now that the binary blobs are separated out, it should be possible to port it to other ESP-IDF versions with minimal changes.

### Can I contribute?

Yes! Join the [Matrix room](https://matrix.to/#/#esp32-open-mac:matrix.org) to coordinate.

### Are there other works related to this?

Yes:

- First blog post talking about this: https://zeus.ugent.be/blog/23-24/open-source-esp32-wifi-mac/
- ESP32 QEMU fork modified for reverse engineering: https://github.com/esp32-open-mac/qemu
- Setting up JTAG debugging on the ESP32: https://github.com/amirgon/ESP32-JTAG
- Espressifs wifi blobs: https://github.com/espressif/esp32-wifi-lib

### What will this project use as MAC layer?

We've decided to write our own MAC layer in Rust, see `components/80211_mac_rust`

### Why are there blobs in teh esp_wifi and esp_phy folders?

These are currently still needed for hardware initialization. They were separated out to make the blobs (mostly) independent from the ESP-IDF version. They will eventually be fully replaced with open source code.

You can verify that the blobs weren't altered: in commit `d1fcca071eb2e6e50f4c40930640586d7ee9487c`, the folders were copied over from ESP-IDF v5.0.1. In further commits, the cmake files were modified to reduce the amount of blobs compiled in.

### Some free ideas

Here are some idea's that are made easier by this project. I'm probably not going to execute them.

- Fuzzing the proprietary Wi-Fi implementation to find security vulnerabilities, using the modifications in QEMU
- Turning the ESP32 into a USB SoftMAC Wi-Fi adapter (the ESP32-S2 has native USB, so this would be a lot nicer than the plain ESP32)
- Using a similar approach to reverse engineer and reimplement the Bluetooth functionality
