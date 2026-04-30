//! Estimated function cost from LuaJIT bytecode (`CONTEXT.md`).

use std::collections::{HashMap, HashSet};
use std::ffi::c_void;
use std::path::Path;

use glimmer_luajit_sys::*;

use crate::bc::{self, op};
use crate::chunk::{self, load_chunk};

/// Extra weight on top of the uniform base (v1 tuning).
const HOT_EXTRA: i64 = 2;
const LOOP_SITE_BUMP: i64 = 6;
const CALL_SITE_BUMP: i64 = 3;
const LOOKBACK_FOR_FNEW: usize = 48;

#[derive(Debug, Clone)]
pub struct ProtoCost {
    /// Best-effort name from source (`(main)` for the chunk closure, or `(anonymous @ line N)`).
    pub name: String,
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

fn simple_lua_name(token: &str) -> bool {
    let mut ch = token.chars();
    let Some(c) = ch.next() else {
        return false;
    };
    if !(c.is_ascii_alphabetic() || c == '_') {
        return false;
    }
    ch.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Parse `local function foo`, `function foo`, `foo = function` on `line_1based` (Lua line numbers).
fn guess_lua_function_name(source: &str, line_1based: u32) -> Option<String> {
    let idx = line_1based.saturating_sub(1) as usize;
    let line = source.lines().nth(idx)?;
    let s = line.trim_start();

    if let Some(rest) = s.strip_prefix("local") {
        let rest = rest.trim_start();
        if let Some(rest) = rest.strip_prefix("function") {
            let rest = rest.trim_start();
            let end = rest.find(|c: char| c == '(' || c.is_whitespace())?;
            let name = rest[..end].trim();
            if simple_lua_name(name) {
                return Some(name.to_string());
            }
        }
    }

    if let Some(rest) = s.strip_prefix("function") {
        let rest = rest.trim_start();
        let end = rest.find('(')?;
        let name = rest[..end].trim();
        if !name.is_empty() {
            return Some(name.to_string());
        }
    }

    if let Some(eq_pos) = s.find('=') {
        let left = s[..eq_pos].trim_end();
        let right = s[eq_pos + 1..].trim_start();
        if right.starts_with("function") && simple_lua_name(left.trim()) {
            return Some(left.trim().to_string());
        }
    }

    None
}

pub(crate) fn proto_display_name(
    proto: *const c_void,
    chunk_proto: *const c_void,
    source: &str,
    line: u32,
) -> String {
    if proto == chunk_proto {
        return "(main)".to_string();
    }
    guess_lua_function_name(source, line)
        .unwrap_or_else(|| format!("(anonymous @ line {})", line))
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
        let insns = unsafe { chunk::proto_bc_words(p) };
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
    let loaded = match load_chunk(path) {
        Ok(c) => c,
        Err(e) => {
            return FileCostReport {
                path: path.to_string_lossy().into_owned(),
                protos: Vec::new(),
                load_error: Some(e),
            };
        }
    };

    let path_str = loaded.path.clone();
    let root = loaded.root_proto;
    let source_text = loaded.source_text.as_str();
    let protos = &loaded.protos;

    unsafe {
        let proto_ids: HashSet<usize> = protos.iter().map(|p| *p as usize).collect();
        let (parent, fnew_slot) = build_parent_and_fnew_slots(protos);

        let mut intrinsic_map: HashMap<usize, i64> = HashMap::new();
        let mut unresolved_map: HashMap<usize, u32> = HashMap::new();
        let mut adj: HashMap<usize, Vec<*const c_void>> = HashMap::new();

        for &p in protos.iter() {
            let insns = chunk::proto_bc_words(p);
            intrinsic_map.insert(p as usize, intrinsic_score(&insns));
            let (edges, ur) =
                build_callee_edges(p, &insns, &proto_ids, &parent, &fnew_slot, protos);
            unresolved_map.insert(p as usize, ur);
            adj.insert(p as usize, edges);
        }

        let mut report = Vec::new();
        for &p in protos.iter() {
            let tr = transitive_from_root(p, &intrinsic_map, &adj);
            let first_line = glimmer_proto_firstline(p);
            report.push(ProtoCost {
                name: proto_display_name(p, root, source_text, first_line),
                first_line,
                num_lines: glimmer_proto_numline(p),
                intrinsic: *intrinsic_map.get(&(p as usize)).unwrap_or(&0),
                transitive: tr,
                unresolved_calls: *unresolved_map.get(&(p as usize)).unwrap_or(&0),
            });
        }

        report.sort_by(|a, b| {
            (a.first_line, a.num_lines, &a.name).cmp(&(b.first_line, b.num_lines, &b.name))
        });

        FileCostReport {
            path: path_str,
            protos: report,
            load_error: None,
        }
    }
}
