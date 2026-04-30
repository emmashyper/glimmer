use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    let target = env::var("TARGET").expect("TARGET set by Cargo");
    if target != "i686-pc-windows-msvc" {
        panic!(
            "glimmer-luajit-sys only supports `i686-pc-windows-msvc` (got {target}).\n\
             Use an x86 Native Tools command prompt and:\n\
               rustup target add i686-pc-windows-msvc\n\
               cargo build -p glimmer --target i686-pc-windows-msvc"
        );
    }

    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let luajit_root = manifest_dir.join("..").join("vendor").join("LuaJIT");
    let luajit_src = luajit_root.join("src");
    let msvcbuild = luajit_src.join("msvcbuild.bat");

    if !msvcbuild.is_file() {
        panic!(
            "LuaJIT not found at {}.\n\
             From the repo root run:\n\
               git submodule update --init --recursive",
            luajit_root.display()
        );
    }

    println!("cargo:rerun-if-changed={}", msvcbuild.display());
    println!(
        "cargo:rerun-if-changed={}",
        luajit_src.join("lua.h").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        luajit_src.join("lj_vm.c").display()
    );

    if env::var_os("INCLUDE").is_none() {
        panic!(
            "INCLUDE is not set. Open an **x86 Native Tools Command Prompt for VS** (or \
             Developer PowerShell for VS with the x86 toolchain) so `cl.exe` is available, \
             then run Cargo again."
        );
    }

    let status = Command::new("cmd")
        .args(["/C", "msvcbuild.bat", "static"])
        .current_dir(&luajit_src)
        .status()
        .unwrap_or_else(|e| panic!("failed to run msvcbuild.bat: {e}"));

    if !status.success() {
        panic!("msvcbuild.bat static failed with status {status}");
    }

    let shim = manifest_dir.join("shim.c");
    println!("cargo:rerun-if-changed={}", shim.display());
    cc::Build::new()
        .target(&target)
        .file(&shim)
        .include(&luajit_src)
        .warnings(false)
        .opt_level(2)
        .compile("glimmer_luajit_shim");

    let lib = luajit_src.join("lua51.lib");
    if !lib.is_file() {
        panic!(
            "expected {} after static build — check msvcbuild output",
            lib.display()
        );
    }

    println!("cargo:rustc-link-search=native={}", luajit_src.display());
    // `lua51` is linked from `glimmer` via `#[link(...)]` so the final link always sees it.
    // Symbols pulled by LuaJIT on Windows (static lib does not carry these)
    println!("cargo:rustc-link-lib=advapi32");
    println!("cargo:rustc-link-lib=winmm");
    println!("cargo:rustc-link-lib=ws2_32");
}
