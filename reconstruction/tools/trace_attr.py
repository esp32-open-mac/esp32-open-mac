#!/usr/bin/env python3
"""Attribute QEMU MMIO trace events to firmware functions.

Reads /tmp/qemu_mmio_execution_trace.txt (mode addr value pc...),
resolves PCs via pc->function map, emits:
  - function x MMIO-address matrix (top addrs per function)
  - MMIO address x functions (who touches each reg)
Usage: python3 trace_attr.py
Needs: /tmp/pc_func.json {pc_hex: func} built beforehand.
"""
import json
from collections import defaultdict, Counter

pc_func = json.load(open("/tmp/pc_func.json"))
func_mmio = defaultdict(Counter)   # func -> Counter(addr)
mmio_func = defaultdict(Counter)   # addr -> Counter(func)
func_events = Counter()
n = unres = 0
for line in open("/tmp/qemu_mmio_execution_trace.txt", errors="replace"):
    p = line.split()
    if len(p) < 4 or p[0] not in ("R", "W"):
        continue
    n += 1
    mode, addr = p[0], p[1].lower()
    fn = None
    for pc in p[3:]:
        key = f"{int(pc, 16) & 0xfffffffc:08x}"
        if key in pc_func:
            fn = pc_func[key]
            break
    if fn is None:
        unres += 1
        fn = "??"
    func_events[fn] += 1
    func_mmio[fn][f"{mode}:{addr}"] += 1
    mmio_func[addr][fn] += 1

print(f"events={n} unresolved={unres} ({100*unres/n:.1f}%) funcs={len(func_events)}")
json.dump({f: dict(c.most_common(60)) for f, c in func_mmio.items()},
          open("/tmp/func_mmio.json", "w"), indent=0)
json.dump({a: dict(c) for a, c in mmio_func.items()},
          open("/tmp/mmio_func.json", "w"), indent=0)
print("top functions by MMIO events:")
for f, c in func_events.most_common(25):
    print(f"  {c:6d}  {f}")
