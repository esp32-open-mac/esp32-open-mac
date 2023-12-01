# ESP32 open Wi-Fi MAC proof-of-concept

This is a proof-of-concept, showing how to use the ESP32 Wi-Fi hardware peripherals. Espressif (the manufacturer of the ESP32) did not document the Wi-Fi hardware peripherals in any of their (public) datasheets, so we had to reverse engineer the functionality of the hardware, see **TODO LINK TO BLOGPOST** for how this was done. The goal is to have a Wi-Fi capable, blob-free SDK/firmware for the ESP32.

## Features

Currently, we can send and receive frames, without any proprietary code *running* (proprietary code is still used to initialize the hardware in the begin, but is not needed anymore after that).

- [X] Sending wifi frames
- [X] Receiving wifi frames
- [ ] Switching channels
- [ ] Changing rate
- [ ] ACK-ing frames (likely done in hardware)
- [ ] Adjusting TX power
- [ ] Hardware packet filtering based on MAC address (at the moment, we receive all packets, but this is a bit inefficient)
- [ ] Implement wifi hardware initialization ourselves (this is now done using the functions in the proprietary blobs)
- [ ] Connect our sending, receiving and other primitives to an open source 802.11 MAC implementation

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

At the moment, this only runs on the plain ESP32 (so not the ESP32-S2, ESP32-S3 or other variants). This is because 
the location and functionality of the Wi-Fi hardware peripherals is hardcoded. Porting this to other variants of the
ESP32 might or might not be trivial, depending on how similar the internal hardware is.

### Can I contribute?

Yes! Please contact j@zeus.ugent.be to coordinate, so you don't waste your time trying to reverse engineer functionality someone else has already reverse engineered

### Are there other works related to this?

Yes:

- **TODO link to blog post**
- **TODO link to forked QEMU repository**
- **TODO link to ESP JTAG repo**
- **TODO link to espressifs blobs**

### What will this project use as MAC layer?

How we'll implement the MAC layer (this does among others the association with access points) is still an open question. The only open source 802.11 MAC implementation I know is the one in the Linux kernel, and I don't know how hard it will be to rip it out and combine it with FreeRTOS instead.

### Some free ideas

Here are some idea's that are made easier by this project. I'm probably not going to execute them.

- Fuzzing the proprietary Wi-Fi implementation to find security vulnerabilities, using the modifications in QEMU
- Turning the ESP32 into a USB SoftMAC Wi-Fi adapter (the ESP32-S2 has native USB, so this would be a lot nicer than the plain ESP32)
- Using a similar approach to reverse engineer and reimplement the Bluetooth functionality
