use std::env;
use std::path::{Path, PathBuf};

fn main() {
    let target = env::var("TARGET").unwrap();
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

    run_bindgen(&target, &out_dir);
}

fn run_bindgen(target: &str, out_dir: &Path) {
    let header = "../include/80211_mac_interface.h";
    let out = out_dir.join("bindings.rs");

    let mut builder = bindgen::Builder::default();
    builder = builder.header(header).allowlist_item(r#"(rs_.*)"#);
    match target {
        "riscv32imc-esp-espidf" => {
            builder = builder.clang_arg("--target=riscv32");
            builder = builder.use_core();
            builder = builder.ctypes_prefix("crate::ffi");
        }
        "xtensa-esp32-none-elf" => {
            // Make sure that LLVM_CONFIG_PATH has been set to point to the
            // Xtensa build of llvm-config.
            builder = builder.clang_arg("--target=xtensa-esp32-none-elf");
            builder = builder.use_core();
        }
        "x86_64-unknown-linux-gnu" => {
            // TODO check if this is what we actually want
            builder = builder.use_core();
            builder = builder.clang_arg("--target=x86_64-unknown-linux-gnu");
        }
        _ => {
            panic!("Unexpect target arch: {}", &target);
        }
    }

    let bindings = builder.generate().expect("Couldn't generate bindings!");
    bindings
        .write_to_file(&out)
        .expect("Couldn't save bindings!");

    println!("cargo:rerun-if-changed={}", header);
    println!("cargo:rerun-if-changed={}", out.display());
}
