//! Estimated function cost from LuaJIT bytecode (`CONTEXT.md`).

use std::collections::{HashMap, HashSet, VecDeque};
use std::ffi::{c_void, CString};
use std::path::Path;

use glimmer_luajit_sys::*;

use crate::bc::{self, op};

const LUA_OK: i32 = 0;

/// Extra weight on top of the uniform base (v1 tuning).
const HOT_EXTRA: i64 = 2;
const LOOP_SITE_BUMP: i64 = 6;
const CALL_SITE_BUMP: i64 = 3;
const LOOKBACK_FOR_FNEW: usize = 48;

#[derive(Debug, Clone)]
pub struct ProtoCost {
    pub first_line: u32,
    pub num_lines: u32,
    pub intrinsic: i64,
    pub transitive: i64,
    pub unresolved_calls: u32,
}

#[derive(Debug)]
pub struct FileCostReport {
    pub path: String,
    pub protos: Vec<ProtoCost>,
    pub load_error: Option<String>,
}

fn is_hot_opcode(opc: u8) -> bool {
    matches!(
        opc,
        op::CALLM
            | op::CALL
            | op::CALLMT
            | op::CALLT
            | op::TGETV
            | op::TGETS
            | op::TGETB
            | op::TGETR
            | op::TSETV
            | op::TSETS
            | op::TSETB
            | op::TSETM
            | op::TSETR
            | op::GGET
            | op::GSET
            | op::KSTR
            | op::CAT
            | op::TNEW
            | op::TDUP
    )
}

fn is_loop_site_opcode(opc: u8) -> bool {
    matches!(
        opc,
        op::FORI
            | op::JFORI
            | op::FORL
            | op::IFORL
            | op::JFORL
            | op::ITERL
            | op::IITERL
            | op::JITERL
            | op::ITERN
    )
}

/// Versioned NYI-ish bumps (LuaJIT 2.1; revise when `vendor/LuaJIT` changes).
fn nyi_extra(opc: u8) -> i64 {
    match opc {
        op::POW => 8,
        op::KCDATA => 10,
        op::CAT => 4,
        op::UCLO => 3,
        op::ISNEXT => 5,
        op::JFORI | op::JFORL | op::JITERL | op::JLOOP => 2,
        op::JFUNCF | op::JFUNCV => 2,
        _ => 0,
    }
}

fn is_call_site_opcode(opc: u8) -> bool {
    matches!(
        opc,
        op::CALLM | op::CALL | op::CALLMT | op::CALLT | op::ITERC | op::ITERN
    )
}

unsafe fn proto_insns(pt: *const c_void) -> Vec<u32> {
    let n = glimmer_proto_sizebc(pt) as usize;
    let p = glimmer_proto_bc(pt);
    if p.is_null() || n == 0 {
        return Vec::new();
    }
    std::slice::from_raw_parts(p, n).to_vec()
}

fn collect_protos(root: *const c_void) -> Vec<*const c_void> {
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

fn intrinsic_score(insns: &[u32]) -> i64 {
    let mut total = 0i64;
    for ins in insns {
        let opc = bc::bc_op(*ins);
        let mut w = 1i64;
        if is_hot_opcode(opc) {
            w += HOT_EXTRA;
        }
        w += nyi_extra(opc);
        if is_loop_site_opcode(opc) {
            w += LOOP_SITE_BUMP;
        }
        if is_call_site_opcode(opc) {
            w += CALL_SITE_BUMP;
        }
        total += w;
    }
    total
}

/// `PROTO_UV_LOCAL` / `PROTO_UV_IMMUTABLE` in `lj_obj.h` (upvalue encoding in the child `GCproto`).
const PROTO_UV_LOCAL: u16 = 0x8000;
const PROTO_UV_IMMUTABLE: u16 = 0x4000;

/// For each nested Lua proto, record which proto's bytecode contains the closing `FNEW` and the
/// parent register that holds the new closure (used to match `UGET` + `CALL` to a sibling local).
fn build_parent_and_fnew_slots(
    protos: &[*const c_void],
) -> (HashMap<usize, *const c_void>, HashMap<usize, u8>) {
    let mut parent = HashMap::new();
    let mut fnew_slot = HashMap::new();
    let ids: HashSet<usize> = protos.iter().map(|p| *p as usize).collect();
    for &p in protos {
        let insns = unsafe { proto_insns(p) };
        for ins in &insns {
            if bc::bc_op(*ins) != op::FNEW {
                continue;
            }
            let child = unsafe { glimmer_proto_from_bc_kgc_d(p, *ins) };
            if child.is_null() || !ids.contains(&(child as usize)) {
                continue;
            }
            parent.insert(child as usize, p);
            fnew_slot.insert(child as usize, bc::bc_a(*ins));
        }
    }
    (parent, fnew_slot)
}

/// Walk backwards from a call/tail-call, following `MOV` chains, to an `FNEW` or `UGET` that
/// fills the callee slot.
fn find_call_value_origin(insns: &[u32], call_pc: usize, mut reg: u8) -> Option<usize> {
    let mut j = call_pc;
    while j > 0 && call_pc - j < LOOKBACK_FOR_FNEW {
        j -= 1;
        let pi = insns[j];
        match bc::bc_op(pi) {
            op::MOV if bc::bc_a(pi) == reg => {
                /* `BC_MOV` is `ins_AD`: dst = A, src = D (see `vm_x86.dasc`). */
                reg = (bc::bc_d(pi) & 0xff) as u8;
                continue;
            }
            op::UGET | op::FNEW if bc::bc_a(pi) == reg => return Some(j),
            _ => {}
        }
    }
    None
}

fn try_resolve_call_target(
    pt: *const c_void,
    insns: &[u32],
    call_pc: usize,
    proto_ids: &HashSet<usize>,
    parent: &HashMap<usize, *const c_void>,
    fnew_slot: &HashMap<usize, u8>,
    protos: &[*const c_void],
) -> Option<*const c_void> {
    let ins = insns[call_pc];
    let call_base = bc::bc_a(ins);
    let origin_pc = find_call_value_origin(insns, call_pc, call_base)?;
    let oins = insns[origin_pc];
    let oop = bc::bc_op(oins);
    if oop == op::FNEW {
        let callee = unsafe { glimmer_proto_from_bc_kgc_d(pt, oins) };
        if callee.is_null() || !proto_ids.contains(&(callee as usize)) {
            return None;
        }
        return Some(callee);
    }
    if oop != op::UGET {
        return None;
    }
    let uvidx = bc::bc_d(oins) as u16 as u32;
    let uvdesc = unsafe { glimmer_proto_uv_desc(pt, uvidx) };
    if uvdesc == 0xffff || (uvdesc & PROTO_UV_LOCAL) == 0 {
        return None;
    }
    let slot = (uvdesc & !(PROTO_UV_LOCAL | PROTO_UV_IMMUTABLE)) as u8;
    let parent_proto = *parent.get(&(pt as usize))?;
    for &cand in protos {
        if cand == pt {
            continue;
        }
        let cid = cand as usize;
        if parent.get(&cid).copied() != Some(parent_proto) {
            continue;
        }
        if fnew_slot.get(&cid).copied() == Some(slot) {
            return Some(cand);
        }
    }
    None
}

fn build_callee_edges(
    pt: *const c_void,
    insns: &[u32],
    proto_ids: &HashSet<usize>,
    parent: &HashMap<usize, *const c_void>,
    fnew_slot: &HashMap<usize, u8>,
    protos: &[*const c_void],
) -> (Vec<*const c_void>, u32) {
    let mut edges = Vec::new();
    let mut seen_edge = HashSet::new();
    let mut unresolved = 0u32;

    for (i, ins) in insns.iter().enumerate() {
        let opc = bc::bc_op(*ins);
        if !is_call_site_opcode(opc) {
            continue;
        }
        if let Some(c) =
            try_resolve_call_target(pt, insns, i, proto_ids, parent, fnew_slot, protos)
        {
            let key = (pt as usize, c as usize);
            if seen_edge.insert(key) {
                edges.push(c);
            }
        } else {
            unresolved += 1;
        }
    }

    (edges, unresolved)
}

fn transitive_from_root(
    root: *const c_void,
    intrinsic: &HashMap<usize, i64>,
    adj: &HashMap<usize, Vec<*const c_void>>,
) -> i64 {
    fn dfs(
        p: *const c_void,
        intrinsic: &HashMap<usize, i64>,
        adj: &HashMap<usize, Vec<*const c_void>>,
        stack: &mut Vec<usize>,
    ) -> i64 {
        let id = p as usize;
        let base = *intrinsic.get(&id).unwrap_or(&0);
        if stack.contains(&id) {
            return base;
        }
        stack.push(id);
        let mut t = base;
        if let Some(cs) = adj.get(&id) {
            for &c in cs {
                let cid = c as usize;
                if stack.contains(&cid) {
                    continue;
                }
                t += dfs(c, intrinsic, adj, stack);
            }
        }
        stack.pop();
        t
    }

    let mut stack = Vec::new();
    dfs(root, intrinsic, adj, &mut stack)
}

/// Analyze a UTF-8 Lua source file. Uses a fresh `lua_State` per call.
pub fn cost_file(path: &Path) -> FileCostReport {
    let path_str = path.to_string_lossy().into_owned();
    let src = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) => {
            return FileCostReport {
                path: path_str,
                protos: Vec::new(),
                load_error: Some(format!("read error: {e}")),
            };
        }
    };

    unsafe {
        let l = luaL_newstate();
        if l.is_null() {
            return FileCostReport {
                path: path_str,
                protos: Vec::new(),
                load_error: Some("luaL_newstate returned null".into()),
            };
        }
        luaL_openlibs(l);
        let name = CString::new(path_str.as_str()).unwrap_or_else(|_| CString::new("=(glimmer)").unwrap());
        let chunk = match CString::new(src.as_slice()) {
            Ok(c) => c,
            Err(_) => {
                lua_close(l);
                return FileCostReport {
                    path: path_str,
                    protos: Vec::new(),
                    load_error: Some("source contains interior NUL byte".into()),
                };
            }
        };

        let st = luaL_loadbuffer(
            l,
            chunk.as_ptr(),
            chunk.as_bytes().len(),
            name.as_ptr(),
        );
        if st != LUA_OK {
            lua_close(l);
            return FileCostReport {
                path: path_str,
                protos: Vec::new(),
                load_error: Some(format!("luaL_loadbuffer failed with status {st}")),
            };
        }

        let closure = lua_topointer(l, -1);
        if closure.is_null() || glimmer_is_lua_closure(closure) == 0 {
            lua_close(l);
            return FileCostReport {
                path: path_str,
                protos: Vec::new(),
                load_error: Some("loaded value is not a Lua closure".into()),
            };
        }

        let root = glimmer_closure_proto(closure);
        let protos = collect_protos(root);
        let proto_ids: HashSet<usize> = protos.iter().map(|p| *p as usize).collect();
        let (parent, fnew_slot) = build_parent_and_fnew_slots(&protos);

        let mut intrinsic_map: HashMap<usize, i64> = HashMap::new();
        let mut unresolved_map: HashMap<usize, u32> = HashMap::new();
        let mut adj: HashMap<usize, Vec<*const c_void>> = HashMap::new();

        for &p in &protos {
            let insns = proto_insns(p);
            intrinsic_map.insert(p as usize, intrinsic_score(&insns));
            let (edges, ur) =
                build_callee_edges(p, &insns, &proto_ids, &parent, &fnew_slot, &protos);
            unresolved_map.insert(p as usize, ur);
            adj.insert(p as usize, edges);
        }

        let mut report = Vec::new();
        for &p in &protos {
            let tr = transitive_from_root(p, &intrinsic_map, &adj);
            report.push(ProtoCost {
                first_line: glimmer_proto_firstline(p),
                num_lines: glimmer_proto_numline(p),
                intrinsic: *intrinsic_map.get(&(p as usize)).unwrap_or(&0),
                transitive: tr,
                unresolved_calls: *unresolved_map.get(&(p as usize)).unwrap_or(&0),
            });
        }

        report.sort_by_key(|r| (r.first_line, r.num_lines));

        lua_close(l);

        FileCostReport {
            path: path_str,
            protos: report,
            load_error: None,
        }
    }
}
