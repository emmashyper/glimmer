//! Builds and links LuaJIT from `vendor/LuaJIT` via `build.rs`, plus a tiny C shim
//! into `GCproto` / bytecode for static analysis.

#![allow(non_camel_case_types)]

use std::ffi::{c_char, c_void};

pub type lua_State = c_void;

extern "C" {
    pub fn luaL_newstate() -> *mut lua_State;
    pub fn lua_close(L: *mut lua_State);
    pub fn luaL_openlibs(L: *mut lua_State);
    pub fn lua_settop(L: *mut lua_State, idx: i32);
    pub fn lua_tolstring(L: *mut lua_State, idx: i32, len: *mut usize) -> *const c_char;
    pub fn lua_topointer(L: *mut lua_State, idx: i32) -> *const c_void;
    pub fn lua_pcall(L: *mut lua_State, nargs: i32, nresults: i32, errfunc: i32) -> i32;

    pub fn luaL_loadbuffer(
        L: *mut lua_State,
        buff: *const c_char,
        sz: usize,
        name: *const c_char,
    ) -> i32;

    pub fn glimmer_dump_stack_function(
        L: *mut lua_State,
        strip_debug: i32,
        out_bytes: *mut *mut u8,
        out_len: *mut usize,
    ) -> i32;

    pub fn glimmer_dump_bytes_free(p: *mut u8);

    pub fn glimmer_closure_proto(closure: *const c_void) -> *const c_void;
    pub fn glimmer_is_lua_closure(closure: *const c_void) -> i32;

    pub fn glimmer_proto_sizebc(pt: *const c_void) -> u32;
    pub fn glimmer_proto_sizekgc(pt: *const c_void) -> u32;
    pub fn glimmer_proto_bc(pt: *const c_void) -> *const u32;
    pub fn glimmer_proto_firstline(pt: *const c_void) -> u32;
    pub fn glimmer_proto_numline(pt: *const c_void) -> u32;
    pub fn glimmer_proto_numparams(pt: *const c_void) -> u8;
    pub fn glimmer_proto_framesize(pt: *const c_void) -> u8;

    pub fn glimmer_proto_kgc_proto_at(pt: *const c_void, kidx: isize) -> *const c_void;
    pub fn glimmer_proto_from_bc_kgc_d(pt: *const c_void, ins: u32) -> *const c_void;
    pub fn glimmer_kgc_index_from_bc_d(ins: u32) -> isize;

    pub fn glimmer_proto_uv_desc(pt: *const c_void, uvidx: u32) -> u16;

    pub fn glimmer_proto_line_at_bc(pt: *const c_void, bc_idx: u32) -> i32;
    pub fn glimmer_proto_has_lineinfo(pt: *const c_void) -> i32;
    pub fn glimmer_proto_chunkname_cstr(pt: *const c_void) -> *const c_char;

    pub fn glimmer_proto_kgc_str(
        pt: *const c_void,
        kidx: isize,
        data: *mut *const c_char,
        len: *mut usize,
    ) -> i32;

    pub fn glimmer_proto_knum_kind(
        pt: *const c_void,
        idx: u32,
        ival: *mut i32,
        fval: *mut f64,
    ) -> i32;
}
