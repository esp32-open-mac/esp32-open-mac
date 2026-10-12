# Reconstructed ESP32 WiFi/PHY/Coex source

Reconstructed C for the ESP32 wireless blobs (`esp32-wifi-lib`,
`esp32-phy-lib`, `esp-coex-lib`), produced by disassembly + DWARF
extraction + live QEMU traces. ~155 files, ~4,900 functions.

This is **reconstruction, not vendor source**: every function carries a
header with its origin address/size, call/data edges, and a fidelity tag:

- `high` — exact control flow, calls, constants
- `medium` — all calls/constants mapped, some roles inferred
- `low` — structured pseudocode of observed behavior; states/layouts
  still to pin down

Per-library `ledger_*.md` files are the fidelity contract: coverage
tables, recovered structs/globals, MMIO maps, and unknowns (each unknown
says what evidence would resolve it).

## Layout

- `esp32-src/` — `libnet80211` (MAC/MLME/scan/crypto), `libpp`
  (PHY/HAL/power), `libmesh`, `libespnow`, `libsmartconfig`,
  `libcore`, `libwapi`, one file per blob object
- `esp32-phy/` — `libphy`/`librftest`/`librtc`/`libbttestmode`.
  These blobs ship DWARF, so signatures and original file:line are real
  (`[dwarf-sig]` tags)
- `esp32-coex/` — `libcoexist` arbitration/scheme
- `tools/` — the regen pipeline: `arx.py` (GNU `.a` extractor, macOS
  `ar` chokes on these archives), `build_funcdb.py` (function/call/reloc
  index), `extract_dwarf.py` (DWARF to JSON), `trace_attr.py`
  (attribute QEMU MMIO traces to functions)
- `ledger_*.md`, `VALIDATION_openmac.md`, `DYNAMIC_scan.md`,
  `DYNAMIC_assoc.md` — coverage, cross-validation against this repo's
  `main/hardware.c` findings, and live-trace confirmations

## License

Derived from Espressif's binary blobs, which are licensed Apache 2.0 —
see `LICENSE` (full text, same as sibling components) and `NOTICE`
(attribution + derivation statement) in this directory, plus
`../license/LICENSE.esp32-wifi-lib.txt`. This matches how this repo
handles blob-derived material in `../license/README.md`, with one
difference stated in NOTICE: this corpus is reconstruction, not a
clean-room rewrite.
