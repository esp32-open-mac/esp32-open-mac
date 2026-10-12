#!/usr/bin/env python3
"""Build function-level metadata DB for ESP32 WiFi blobs (Xtensa).

For each .a in ~/esp32-wifi-lib/esp32:
  - extract members to /tmp/re_esp32/<lib>/
  - parse symbols (nm), sections + relocations (readelf), strings
  - emit re/esp32/funcdb_<lib>.json + re/esp32/funcdb_summary.json

Call heuristic (verified against objdump -r output):
  R_XTENSA_ASM_EXPAND <sym>  -> call target (callx8/callx12 literal)
  R_XTENSA_SLOT0_OP <sym>    -> data/code reference (l32r literal pool)
"""
import os, re, json, subprocess, sys

TC = os.path.expanduser(
    "~/.espressif/tools/xtensa-esp-elf/esp-15.2.0_20251204/xtensa-esp-elf/bin")
LIBDIR = os.path.expanduser(os.environ.get("FUNCDB_LIBDIR",
                                           "~/esp32-wifi-lib/esp32"))
OUTDIR = os.path.expanduser(os.environ.get("FUNCDB_OUTDIR",
                                           "~/esp32-wifi-lib/re/esp32"))
TMP = os.environ.get("FUNCDB_TMP", "/tmp/re_esp32")
TAG = os.environ.get("FUNCDB_TAG", "")  # e.g. "phy_" prefix for out files
sys.path.insert(0, os.path.expanduser("~/esp32-wifi-lib/tools"))
from arx import parse as ar_parse  # noqa: E402


def run(tool, *args):
    p = subprocess.run([os.path.join(TC, tool), *args],
                       capture_output=True, text=True)
    return p.stdout


def parse_nm(path):
    """Return list of (addr, type, name)."""
    syms = []
    for line in run("xtensa-esp32-elf-nm", "-a", path).splitlines():
        m = re.match(r"^([0-9a-fA-F]+)?\s*([A-Za-z?])\s+(.+)$", line.strip())
        if m:
            syms.append({"addr": m.group(1), "type": m.group(2),
                         "name": m.group(3)})
    return syms


def parse_readelf_syms(path):
    """Return {name: {addr, size, type, bind, ndx}} for wide symtab."""
    out = {}
    for line in run("xtensa-esp32-elf-readelf", "-sW", path).splitlines():
        m = re.match(r"\s*\d+:\s*([0-9a-fA-F]+)\s+(\d+)\s+(\w+)\s+(\w+)\s+\w+\s+(\w+)\s+(.*)$", line)
        if m and m.group(6).strip():
            out[m.group(6).strip()] = {
                "addr": m.group(1), "size": int(m.group(2)),
                "type": m.group(3), "bind": m.group(4), "ndx": m.group(5)}
    return out


def parse_relocs(path):
    """Return {section: [{offset, type, sym}]}."""
    relocs = {}
    cur = None
    for line in run("xtensa-esp32-elf-readelf", "-rW", path).splitlines():
        m = re.match(r"Relocation section '([^']+)'", line)
        if m:
            cur = m.group(1)
            if cur.startswith(".rela."):
                cur = cur[len(".rela.") - 1:]  # .rela.text.f -> .text.f
            relocs[cur] = []
            continue
        if cur is None:
            continue
        m = re.match(r"\s*([0-9a-fA-F]+)\s+[0-9a-fA-F]+\s+(\S+)\s+[0-9a-fA-F]+\s+(.*?)\s*(?:\+\s*[0-9a-fA-F]+)?$", line)
        if m:
            relocs[cur].append({"offset": m.group(1), "type": m.group(2),
                                "sym": m.group(3).strip()})
    return relocs


def main():
    os.makedirs(OUTDIR, exist_ok=True)
    summary = {"libs": {}, "totals": {"functions": 0, "undef": 0}}
    for lib in sorted(os.listdir(LIBDIR)):
        if not lib.endswith(".a"):
            continue
        members = ar_parse(os.path.join(LIBDIR, lib))
        odir = os.path.join(TMP, lib[:-2])
        os.makedirs(odir, exist_ok=True)
        libdb = {"lib": lib, "objects": {}}
        nfunc = nundef = 0
        for name, body in members:
            opath = os.path.join(odir, os.path.basename(name))
            with open(opath, "wb") as f:
                f.write(body)
            symtab = parse_readelf_syms(opath)
            relocs = parse_relocs(opath)
            strs = subprocess.run(["strings", "-a", opath],
                                  capture_output=True, text=True).stdout.splitlines()
            funcs = []
            undef = []
            for nm, st in symtab.items():
                if st["type"] == "FUNC" and st["bind"] in ("GLOBAL", "LOCAL") \
                        and st["ndx"] != "UND" and not nm.startswith(".L"):
                    sec = None
                    calls, refs = [], []
                    # exact section match only: .rela.text.<nm> -> .text.<nm>.
                    # Sibling sections (.text.<nm>_local, .text.<nm>.constprop)
                    # belong to their own symbols, never union them.
                    want = f".text.{nm}"
                    if want not in relocs:
                        # non-.text homes (.wifirxiram.<nm>, .wifi0iram.<nm>):
                        cands = [r for r in relocs
                                 if r.rsplit(".", 1)[-1] == nm]
                        want = cands[0] if len(cands) == 1 else ".text"
                    if want not in relocs and ".text" in relocs:
                        want = ".text"  # shared-.text fallback
                    sec = want if want in relocs else None
                    if sec is not None:
                        for it in relocs[sec]:
                            s = it["sym"]
                            if s.startswith(".text.") or \
                                    s.startswith(".literal."):
                                continue  # own literal pool / local labels
                            if it["type"] == "R_XTENSA_ASM_EXPAND":
                                calls.append(s)
                            else:
                                refs.append(s)
                    funcs.append({"name": nm, "addr": st["addr"],
                                  "size": st["size"], "bind": st["bind"],
                                  "relsec": sec, "calls": sorted(set(calls)),
                                  "refs": sorted(set(refs))})
                elif st["ndx"] == "UND":
                    undef.append(nm)
            nfunc += len(funcs)
            nundef += len(undef)
            libdb["objects"][os.path.basename(name)] = {
                "functions": sorted(funcs, key=lambda x: x["name"]),
                "undefined": sorted(set(undef)),
                "string_count": len(strs),
                "strings": [s for s in strs if len(s) >= 4][:200],
            }
        libdb["function_count"] = nfunc
        with open(os.path.join(OUTDIR, f"funcdb_{TAG}{lib[:-2]}.json"), "w") as f:
            json.dump(libdb, f, indent=1)
        summary["libs"][lib] = {"objects": len(libdb["objects"]),
                                "functions": nfunc, "undef": nundef}
        summary["totals"]["functions"] += nfunc
        summary["totals"]["undef"] += nundef
        print(f"{lib}: {len(libdb['objects'])} objects, {nfunc} funcs",
              flush=True)
    with open(os.path.join(OUTDIR, "funcdb_summary.json"), "w") as f:
        json.dump(summary, f, indent=1)
    print(json.dumps(summary["totals"]))


if __name__ == "__main__":
    main()
