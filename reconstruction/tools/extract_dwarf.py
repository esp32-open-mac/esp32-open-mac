#!/usr/bin/env python3
"""Extract DWARF CU + subprogram + types from xtensa-esp32-elf-readelf --debug-dump=info text.
Offline. Uses only readelf text output.
"""
import re, subprocess, json, os, sys

TC = os.path.expanduser("~/.espressif/tools/xtensa-esp-elf/esp-15.2.0_20251204/xtensa-esp-elf/bin")
READELF = os.path.join(TC, "xtensa-esp32-elf-readelf")

DIE_RE = re.compile(r"^ <(\d+)><([0-9a-f]+)>: Abbrev Number: \d+ \(([^)]+)\)")
ATTR_RE = re.compile(r"^ +<([0-9a-f]+)>\s+(DW_\S+)\s*:\s*(.*)$")

def run_readelf(obj, dump="info"):
    out = subprocess.run([READELF, f"--debug-dump={dump}", obj],
                         capture_output=True, text=True)
    return out.stdout + out.stderr

def parse_info(text):
    dies = []  # list of dicts in order
    cur = None
    for line in text.splitlines():
        m = DIE_RE.match(line)
        if m:
            level, off, tag = int(m.group(1)), m.group(2).lower().lstrip("0") or "0", m.group(3)
            cur = {"level": level, "offset": off, "tag": tag, "attrs": {}, "raw_attrs": {}}
            dies.append(cur)
            continue
        m2 = ATTR_RE.match(line)
        if m2 and cur is not None:
            aoff, attr, val = m2.group(1), m2.group(2), m2.group(3).strip()
            cur["attrs"][attr] = val
            cur["raw_attrs"][attr] = val
    return dies

def attr_name(val):
    # "(indirect string, offset: 0x18e8): write_wifi_chan_data" -> "write_wifi_chan_data"
    # "write_wifi_chan_data" -> same; "1 byte block: ..." keep raw
    if val is None: return None
    if "): " in val:
        return val.split("): ", 1)[1].strip()
    return val.strip()

def attr_ref(val):
    m = re.search(r"<0x([0-9a-f]+)>", val or "")
    if m: return m.group(1).lower().lstrip("0") or "0"
    return None

def attr_int(val):
    if val is None: return None
    m = re.match(r"0x([0-9a-fA-F]+)", val.strip())
    if m:
        try: return int(m.group(1), 16)
        except: return None
    m2 = re.match(r"(-?\d+)", val.strip())
    if m2:
        try: return int(m2.group(1))
        except: return None
    return None

def build_type_str(diemap, off, depth=0):
    if depth > 12: return "RECURSION"
    if off is None: return "void"
    d = diemap.get(off)
    if d is None: return f"UNKNOWN<0x{off}>"
    tag = d["tag"]
    a = d["attrs"]
    if tag == "DW_TAG_base_type":
        return attr_name(a.get("DW_AT_name")) or "base"
    if tag == "DW_TAG_typedef":
        return attr_name(a.get("DW_AT_name")) or "typedef"
    if tag == "DW_TAG_pointer_type":
        t = attr_ref(a.get("DW_AT_type"))
        if t is None: return "void *"
        return build_type_str(diemap, t, depth+1) + " *"
    if tag == "DW_TAG_const_type":
        t = attr_ref(a.get("DW_AT_type"))
        if t is None: return "const void"
        return "const " + build_type_str(diemap, t, depth+1)
    if tag == "DW_TAG_volatile_type":
        t = attr_ref(a.get("DW_AT_type"))
        if t is None: return "volatile void"
        return "volatile " + build_type_str(diemap, t, depth+1)
    if tag == "DW_TAG_array_type":
        t = attr_ref(a.get("DW_AT_type"))
        base = build_type_str(diemap, t, depth+1) if t else "void"
        return base + "[]"
    if tag in ("DW_TAG_structure_type", "DW_TAG_union_type", "DW_TAG_enumeration_type"):
        n = attr_name(a.get("DW_AT_name"))
        kind = {"DW_TAG_structure_type": "struct", "DW_TAG_union_type": "union",
                "DW_TAG_enumeration_type": "enum"}[tag]
        return f"{kind} {n}" if n else kind
    if tag == "DW_TAG_subroutine_type":
        t = attr_ref(a.get("DW_AT_type"))
        r = build_type_str(diemap, t, depth+1) if t else "void"
        return r + " (*)()"
    if tag == "DW_TAG_reference_type":
        t = attr_ref(a.get("DW_AT_type"))
        base = build_type_str(diemap, t, depth+1) if t else "void"
        return base + " &"
    if tag == "DW_TAG_rvalue_reference_type":
        t = attr_ref(a.get("DW_AT_type"))
        base = build_type_str(diemap, t, depth+1) if t else "void"
        return base + " &&"
    return f"{tag}({attr_name(a.get('DW_AT_name')) or ('0x'+off)})"

def type_chain(diemap, off, depth=0):
    """Return list of steps resolving typedef chain."""
    chain = []
    seen = set()
    cur = off
    while cur and cur not in seen and depth < 12:
        seen.add(cur)
        d = diemap.get(cur)
        if d is None:
            chain.append(f"UNKNOWN<0x{cur}>"); break
        tag = d["tag"]; a = d["attrs"]
        nm = attr_name(a.get("DW_AT_name"))
        if tag == "DW_TAG_base_type":
            chain.append(nm or "base"); break
        elif tag == "DW_TAG_typedef":
            chain.append(nm or "typedef")
            cur = attr_ref(a.get("DW_AT_type")); depth += 1; continue
        elif tag == "DW_TAG_pointer_type":
            t = attr_ref(a.get("DW_AT_type"))
            inner = build_type_str(diemap, t) if t else "void"
            chain.append(inner + " *"); break
        elif tag in ("DW_TAG_const_type", "DW_TAG_volatile_type"):
            q = "const" if "const" in tag else "volatile"
            t = attr_ref(a.get("DW_AT_type"))
            inner = build_type_str(diemap, t) if t else "void"
            chain.append(f"{q} {inner}"); break
        elif tag == "DW_TAG_array_type":
            t = attr_ref(a.get("DW_AT_type"))
            inner = build_type_str(diemap, t) if t else "void"
            chain.append(inner + "[]"); break
        elif tag in ("DW_TAG_structure_type", "DW_TAG_union_type", "DW_TAG_enumeration_type"):
            kind = {"DW_TAG_structure_type": "struct", "DW_TAG_union_type": "union",
                    "DW_TAG_enumeration_type": "enum"}[tag]
            chain.append(f"{kind} {nm}" if nm else kind); break
        elif tag == "DW_TAG_subroutine_type":
            chain.append(build_type_str(diemap, cur)); break
        else:
            chain.append(f"{tag}({nm or ('0x'+cur)})"); break
    return chain

def extract_object(objpath):
    text = run_readelf(objpath, "info")
    dies = parse_info(text)
    diemap = {d["offset"]: d for d in dies}
    # index dies to find children ranges: children of DIE i are subsequent dies with level>i until level<=
    cus = []
    subprograms = []
    # CU list
    for i, d in enumerate(dies):
        if d["tag"] == "DW_TAG_compile_unit":
            cus.append({
                "die": "0x" + d["offset"],
                "name": attr_name(d["attrs"].get("DW_AT_name")),
                "comp_dir": attr_name(d["attrs"].get("DW_AT_comp_dir")),
                "producer": attr_name(d["attrs"].get("DW_AT_producer")),
                "language": d["attrs"].get("DW_AT_language"),
                "low_pc": d["attrs"].get("DW_AT_low_pc"),
                "ranges": d["attrs"].get("DW_AT_ranges"),
                "stmt_list": d["attrs"].get("DW_AT_stmt_list"),
            })
    # subprograms: collect with parent level children for params
    for i, d in enumerate(dies):
        if d["tag"] != "DW_TAG_subprogram":
            continue
        a = d["attrs"]
        lvl = d["level"]
        # gather direct children (level+1) until a DIE with level <= lvl
        params = []
        variables = []
        inlined = []
        j = i + 1
        while j < len(dies) and dies[j]["level"] > lvl:
            c = dies[j]
            if c["level"] == lvl + 1 and c["tag"] == "DW_TAG_formal_parameter":
                tref = attr_ref(c["attrs"].get("DW_AT_type"))
                params.append({
                    "name": attr_name(c["attrs"].get("DW_AT_name")),
                    "die": "0x" + c["offset"],
                    "decl_file": attr_int(c["attrs"].get("DW_AT_decl_file")),
                    "decl_line": attr_int(c["attrs"].get("DW_AT_decl_line")),
                    "type_ref": ("0x" + tref) if tref else None,
                    "type_resolved": build_type_str(diemap, tref),
                    "type_chain": type_chain(diemap, tref) if tref else ["void"],
                })
            elif c["level"] == lvl + 1 and c["tag"] == "DW_TAG_variable":
                tref = attr_ref(c["attrs"].get("DW_AT_type"))
                variables.append({
                    "name": attr_name(c["attrs"].get("DW_AT_name")),
                    "decl_line": attr_int(c["attrs"].get("DW_AT_decl_line")),
                    "type_resolved": build_type_str(diemap, tref),
                })
            elif c["tag"] == "DW_TAG_inlined_subroutine":
                ao = attr_ref(c["attrs"].get("DW_AT_abstract_origin"))
                nm = None
                if ao and ao in diemap:
                    nm = attr_name(diemap[ao]["attrs"].get("DW_AT_name"))
                inlined.append({"die": "0x" + c["offset"], "abstract_origin": ("0x" + ao) if ao else None,
                                "name": nm, "low_pc": c["attrs"].get("DW_AT_low_pc"),
                                "high_pc": c["attrs"].get("DW_AT_high_pc"),
                                "ranges": c["attrs"].get("DW_AT_ranges")})
            j += 1
        tref = attr_ref(a.get("DW_AT_type"))
        ao = attr_ref(a.get("DW_AT_abstract_origin"))
        subprograms.append({
            "name": attr_name(a.get("DW_AT_name")),
            "linkage_name": attr_name(a.get("DW_AT_linkage_name")) or attr_name(a.get("DW_AT_MIPS_linkage_name")),
            "die": "0x" + d["offset"],
            "level": lvl,
            "decl_file": attr_int(a.get("DW_AT_decl_file")),
            "decl_line": attr_int(a.get("DW_AT_decl_line")),
            "prototyped": a.get("DW_AT_prototyped"),
            "external": a.get("DW_AT_external"),
            "declaration": a.get("DW_AT_declaration"),
            "inline": a.get("DW_AT_inline"),
            "abstract_origin": ("0x" + ao) if ao else None,
            "return_type_ref": ("0x" + tref) if tref else None,
            "return_type_resolved": build_type_str(diemap, tref),
            "return_type_chain": type_chain(diemap, tref) if tref else ["void"],
            "low_pc": a.get("DW_AT_low_pc"),
            "high_pc": a.get("DW_AT_high_pc"),
            "ranges": a.get("DW_AT_ranges"),
            "frame_base": a.get("DW_AT_frame_base"),
            "params": params,
            "variables": [{"n": v["name"], "l": v["decl_line"], "t": v["type_resolved"]} for v in variables[:32]],
            "variable_count": len(variables),
            "inlined_count": len(inlined),
        })
    # types table (first 400 type DIEs summarized)
    types = {}
    for d in dies:
        if d["tag"] in ("DW_TAG_typedef", "DW_TAG_base_type", "DW_TAG_pointer_type",
                        "DW_TAG_const_type", "DW_TAG_volatile_type", "DW_TAG_structure_type",
                        "DW_TAG_union_type", "DW_TAG_enumeration_type", "DW_TAG_array_type",
                        "DW_TAG_subroutine_type"):
            try:
                types["0x" + d["offset"]] = build_type_str(diemap, d["offset"])
            except Exception as e:
                types["0x" + d["offset"]] = f"ERR {e}"
    return {"cus": cus, "subprograms": subprograms, "types": types,
            "die_count": len(dies)}

def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--lib", required=True)
    ap.add_argument("--dir", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--funcdb", default=None)
    args = ap.parse_args()
    objs = sorted([f for f in os.listdir(args.dir) if f.endswith(".o")])
    result = {"lib": args.lib, "objects": {}, "function_count": 0}
    funcdb = None
    if args.funcdb and os.path.exists(args.funcdb):
        with open(args.funcdb) as f:
            funcdb = json.load(f)
    for o in objs:
        print(f"parsing {o} ...", flush=True)
        info = extract_object(os.path.join(args.dir, o))
        entry = {"cus": info["cus"], "subprograms": info["subprograms"],
                 "types": info["types"], "die_count": info["die_count"],
                 "subprogram_count": len(info["subprograms"])}
        if funcdb and o in funcdb.get("objects", {}):
            fns = funcdb["objects"][o]["functions"]
            entry["funcdb_count"] = len(fns)
            entry["funcdb_names"] = [f["name"] for f in fns]
            # match check: funcdb names present in dwarf subprograms (any level, concrete)
            dsp = set(s["name"] for s in info["subprograms"] if s["name"])
            missing = [n for n in entry["funcdb_names"] if n not in dsp]
            entry["funcdb_missing_in_dwarf"] = missing
        result["objects"][o] = entry
    with open(args.out, "w") as f:
        json.dump(result, f, indent=1)
    print(f"wrote {args.out}")

if __name__ == "__main__":
    main()
