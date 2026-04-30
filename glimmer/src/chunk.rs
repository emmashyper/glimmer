//! Load Lua source into a `lua_State` and enumerate nested `GCproto` values.

use std::collections::{HashSet, VecDeque};
use std::ffi::{c_void, CStr, CString};
use std::path::Path;

use glimmer_luajit_sys::*;

const LUA_OK: i32 = 0;
#[allow(dead_code)]
const LUA_ERRSYNTAX: i32 = 3;
#[allow(dead_code)]
const LUA_ERRMEM: i32 = 4;

fn lua_load_error_label(st: i32) -> &'static str {
    match st {
        LUA_ERRSYNTAX => "syntax",
        LUA_ERRMEM => "memory",
        2 => "runtime",
        5 => "errfn",
        _ => "load",
    }
}

unsafe fn take_lua_stack_string(L: *mut lua_State) -> Option<String> {
    let p = lua_tolstring(L, -1, std::ptr::null_mut());
    if p.is_null() {
        lua_settop(L, 0);
        return None;
    }
    let s = CStr::from_ptr(p).to_string_lossy().into_owned();
    lua_settop(L, 0);
    Some(s)
}

pub(crate) struct LuaStateGuard(*mut lua_State);

impl LuaStateGuard {
    pub(crate) fn state(&self) -> *mut lua_State {
        self.0
    }
}

pub(crate) struct LoadedChunk {
    pub path: String,
    pub source_text: String,
    _state: LuaStateGuard,
    pub root_proto: *const c_void,
    pub protos: Vec<*const c_void>,
}

impl LoadedChunk {
    /// Active `lua_State` with the loaded chunk closure on the stack top.
    pub(crate) fn lua_state(&self) -> *mut lua_State {
        self._state.state()
    }
}

impl Drop for LuaStateGuard {
    fn drop(&mut self) {
        unsafe {
            lua_close(self.0);
        }
    }
}

pub(crate) fn collect_protos(root: *const c_void) -> Vec<*const c_void> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    let mut q = VecDeque::new();
    if root.is_null() {
        return out;
    }
    q.push_back(root);
    while let Some(p) = q.pop_front() {
        let id = p as usize;
        if !seen.insert(id) {
            continue;
        }
        out.push(p);
        let nkgc = unsafe { glimmer_proto_sizekgc(p) };
        for j in 1..=nkgc {
            let kidx = -(j as isize);
            let child = unsafe { glimmer_proto_kgc_proto_at(p, kidx) };
            if !child.is_null() {
                q.push_back(child);
            }
        }
    }
    out
}

pub(crate) unsafe fn proto_bc_words(pt: *const c_void) -> Vec<u32> {
    let n = glimmer_proto_sizebc(pt) as usize;
    let p = glimmer_proto_bc(pt);
    if p.is_null() || n == 0 {
        return Vec::new();
    }
    std::slice::from_raw_parts(p, n).to_vec()
}

/// Load a UTF-8 Lua file; returns `Err` on I/O or `luaL_loadbuffer` failure.
pub(crate) fn load_chunk(path: &Path) -> Result<LoadedChunk, String> {
    let path_str = path.to_string_lossy().into_owned();
    let src = std::fs::read(path).map_err(|e| {
        format!(
            "{}: cannot read file ({})",
            path_str,
            e.kind()
        )
    })?;
    let source_text = String::from_utf8_lossy(&src).into_owned();

    unsafe {
        let l = luaL_newstate();
        if l.is_null() {
            return Err(format!("{}: luaL_newstate returned null", path_str));
        }
        let _guard = LuaStateGuard(l);
        luaL_openlibs(l);
        let name = CString::new(path_str.as_str()).unwrap_or_else(|_| CString::new("=(glimmer)").unwrap());
        let chunk = CString::new(src.as_slice()).map_err(|_| {
            format!(
                "{}: source contains an embedded NUL byte; Lua sources must be valid UTF-8/Latin1 without interior '\\0'",
                path_str
            )
        })?;

        let st = luaL_loadbuffer(l, chunk.as_ptr(), chunk.as_bytes().len(), name.as_ptr());
        if st != LUA_OK {
            let detail = take_lua_stack_string(l)
                .map(|m| format!(": {m}"))
                .unwrap_or_default();
            return Err(format!(
                "{}: luaL_loadbuffer {} error (status={st}){detail}",
                path_str,
                lua_load_error_label(st),
            ));
        }

        let closure = lua_topointer(l, -1);
        if closure.is_null() || glimmer_is_lua_closure(closure) == 0 {
            return Err(format!(
                "{}: loaded chunk is not a Lua closure (wrong value type after load)",
                path_str
            ));
        }

        let root_proto = glimmer_closure_proto(closure);
        let protos = collect_protos(root_proto);

        Ok(LoadedChunk {
            path: path_str,
            source_text,
            _state: _guard,
            root_proto,
            protos,
        })
    }
}
