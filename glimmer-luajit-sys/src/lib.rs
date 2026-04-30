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
    pub fn lua_topointer(L: *mut lua_State, idx: i32) -> *const c_void;

    pub fn luaL_loadbuffer(
        L: *mut lua_State,
        buff: *const c_char,
        sz: usize,
        name: *const c_char,
    ) -> i32;

    pub fn glimmer_closure_proto(closure: *const c_void) -> *const c_void;
    pub fn glimmer_is_lua_closure(closure: *const c_void) -> i32;

    pub fn glimmer_proto_sizebc(pt: *const c_void) -> u32;
    pub fn glimmer_proto_sizekgc(pt: *const c_void) -> u32;
    pub fn glimmer_proto_bc(pt: *const c_void) -> *const u32;
    pub fn glimmer_proto_firstline(pt: *const c_void) -> u32;
    pub fn glimmer_proto_numline(pt: *const c_void) -> u32;

    pub fn glimmer_proto_kgc_proto_at(pt: *const c_void, kidx: isize) -> *const c_void;
    pub fn glimmer_proto_from_bc_kgc_d(pt: *const c_void, ins: u32) -> *const c_void;
    pub fn glimmer_kgc_index_from_bc_d(ins: u32) -> isize;

    pub fn glimmer_proto_uv_desc(pt: *const c_void, uvidx: u32) -> u16;
}
