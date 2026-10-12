/* test_rx_sniffer.c - test_rx_sniffer.o is an EMPTY (compiled-out) object in esp32/libnet80211.a.
 * Evidence (offline, xtensa-esp32-elf readelf/nm/objdump): file 480 bytes;
 * .text section size 0; `nm` reports no symbols; funcdb lists 0 functions
 * and 0 undefined symbols; disasm file has only .comment/.xtensa.info.
 * There is NO single-jump stub and hence NO jump target to record: the
 * object contributes nothing at link time. Fidelity: high - vacuous
 * (nothing to reconstruct; verified empty, not padded or guessed).
 * Context: Test/RX sniffer hook. Compiled out (no code).
 * NOTE: this file intentionally defines no functions.
 */
