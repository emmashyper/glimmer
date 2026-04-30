use std::env;
use std::ffi::{c_char, c_int, CString};
use std::path::Path;
use std::ptr;

mod bc;
mod cost;

#[repr(C)]
struct LuaState {
    _opaque: [u8; 0],
}

#[link(name = "lua51", kind = "static")]
extern "C" {
    fn luaL_newstate() -> *mut LuaState;
    fn lua_close(L: *mut LuaState);
    fn luaL_openlibs(L: *mut LuaState);
    fn luaL_loadstring(L: *mut LuaState, s: *const c_char) -> c_int;
    fn lua_pcall(L: *mut LuaState, nargs: c_int, nresults: c_int, errfunc: c_int) -> c_int;
    fn lua_tolstring(L: *mut LuaState, idx: c_int, len: *mut usize) -> *const c_char;
    fn lua_settop(L: *mut LuaState, idx: c_int);
}

struct LuaGuard(*mut LuaState);

impl Drop for LuaGuard {
    fn drop(&mut self) {
        unsafe {
            lua_close(self.0);
        }
    }
}

const LUA_OK: c_int = 0;

fn print_usage() {
    eprintln!(
        "Usage:\n  glimmer              Smoke-test LuaJIT (jit.version)\n  glimmer cost <file>  Estimated bytecode cost per function prototype"
    );
}

fn run_jit_smoke() -> i32 {
    const SCRIPT: &str = r#"return (jit and jit.version or "no jit") .. " | " .. _VERSION"#;

    unsafe {
        let l = luaL_newstate();
        if l.is_null() {
            eprintln!("luaL_newstate returned null");
            return 1;
        }
        let _guard = LuaGuard(l);

        luaL_openlibs(l);

        let chunk = CString::new(SCRIPT).expect("script has no interior NUL");
        let load = luaL_loadstring(l, chunk.as_ptr());
        if load != LUA_OK {
            print_lua_error("luaL_loadstring", l);
            return 1;
        }

        let pcall = lua_pcall(l, 0, 1, 0);
        if pcall != LUA_OK {
            print_lua_error("lua_pcall", l);
            return 1;
        }

        let s = lua_tolstring(l, -1, ptr::null_mut());
        if s.is_null() {
            eprintln!("expected string result on stack");
            return 1;
        }
        let msg = std::ffi::CStr::from_ptr(s);
        println!("{}", msg.to_string_lossy());
        lua_settop(l, 0);
    }
    0
}

fn run_cost(path: &Path) -> i32 {
    let r = cost::cost_file(path);
    if let Some(err) = &r.load_error {
        eprintln!("{}: {}", r.path, err);
        return 1;
    }
    println!("{} — prototypes: {}", r.path, r.protos.len());
    for (i, p) in r.protos.iter().enumerate() {
        println!(
            "  [{i}] lines {}..{}  intrinsic={}  transitive={}  unresolved_calls={}",
            p.first_line,
            p.first_line.saturating_add(p.num_lines.saturating_sub(1)),
            p.intrinsic,
            p.transitive,
            p.unresolved_calls
        );
    }
    0
}

fn main() {
    let mut args = env::args();
    let _exe = args.next();
    let code = match args.next().as_deref() {
        None | Some("jit") | Some("--jit") => run_jit_smoke(),
        Some("cost") | Some("bytecode-cost") => match args.next() {
            None => {
                eprintln!("glimmer cost: missing <file.lua>");
                print_usage();
                2
            }
            Some(p) if p == "-h" || p == "--help" => {
                print_usage();
                0
            }
            Some(p) => run_cost(Path::new(&p)),
        },
        Some("-h") | Some("--help") => {
            print_usage();
            0
        }
        Some(_) => {
            print_usage();
            2
        }
    };
    std::process::exit(code);
}

unsafe fn print_lua_error(phase: &str, l: *mut LuaState) {
    let s = lua_tolstring(l, -1, ptr::null_mut());
    if s.is_null() {
        eprintln!("{phase} failed (no message on stack)");
        return;
    }
    let msg = std::ffi::CStr::from_ptr(s);
    eprintln!("{phase}: {}", msg.to_string_lossy());
    lua_settop(l, 0);
}
