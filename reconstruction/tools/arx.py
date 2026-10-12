#!/usr/bin/env python3
"""Extract members from a GNU-format .a archive (works on macOS, no binutils needed).

Usage: python3 arx.py <archive.a> [-C outdir] [--list]
"""
import os, sys, struct

GLOBAL = b"!<arch>\n"

def parse(path):
    data = open(path, "rb").read()
    assert data[:8] == GLOBAL, "not an ar archive"
    off = 8
    longnames = b""
    members = []
    while off + 60 <= len(data):
        hdr = data[off:off+60]
        name = hdr[0:16].decode("latin1").rstrip()
        try:
            size = int(hdr[48:58].decode("latin1").strip())
        except ValueError:
            break
        body = data[off+60:off+60+size]
        raw = name
        if name == "//":
            longnames = body
        elif name in ("/", "/SYM64/"):
            pass  # symbol table
        else:
            if name.startswith("/") and name[1:].isdigit():
                o = int(name[1:])
                end = longnames.find(b"/\n", o)
                real = longnames[o:end].decode("latin1")
            else:
                real = name.rstrip("/")
            members.append((real, body))
        off += 60 + size + (size & 1)
    return members

def elf_machine(b):
    if b[:4] != b"\x7fELF":
        return "not-elf"
    e_machine = struct.unpack_from("<H", b, 18)[0]
    cls = "64" if b[4] == 2 else "32"
    names = {0x3e: "x86-64", 0x03: "i386", 0xf3: "RISC-V",
             0x5e: "Xtensa", 0x02: "SPARC", 0x28: "ARM", 0x2a: "SuperH"}
    return names.get(e_machine, f"machine=0x{e_machine:x}") + f" ELF{cls}"

def main():
    args = sys.argv[1:]
    list_only = "--list" in args
    if list_only: args.remove("--list")
    outdir = None
    if "-C" in args:
        i = args.index("-C"); outdir = args[i+1]; del args[i:i+2]
    arc = args[0]
    mem = parse(arc)
    for name, body in mem:
        info = elf_machine(body)
        if list_only:
            print(f"{name:40s} {len(body):>9d}  {info}")
        else:
            os.makedirs(outdir, exist_ok=True)
            dest = os.path.join(outdir, os.path.basename(name))
            open(dest, "wb").write(body)
    if not list_only:
        print(f"extracted {len(mem)} members -> {outdir}")

if __name__ == "__main__":
    main()
