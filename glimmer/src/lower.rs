//! Lower LuaJIT prototypes to regenerated Lua source (best-effort).

use std::collections::{HashMap, HashSet};
use std::ffi::c_char;
use std::fmt::Write as _;

use crate::chunk::{proto_bc_words, LoadedChunk};
use crate::compile::{CfgObfuscationLevel, CfgObfuscationPlan};
use glimmer_luajit_sys::*;

const BCBIAS_J: i32 = 0x8000;

#[inline]
fn bc_op(ins: u32) -> u8 {
    (ins & 0xff) as u8
}
#[inline]
fn bc_a(ins: u32) -> u8 {
    ((ins >> 8) & 0xff) as u8
}
#[inline]
fn bc_b(ins: u32) -> u8 {
    ((ins >> 24) & 0xff) as u8
}
#[inline]
fn bc_c(ins: u32) -> u8 {
    ((ins >> 16) & 0xff) as u8
}
#[inline]
fn bc_d(ins: u32) -> u32 {
    ins >> 16
}

fn s16(d: u32) -> i32 {
    let u = (d & 0xffff) as i32;
    if u >= 0x8000 {
        u - 0x10000
    } else {
        u
    }
}

fn reg(r: u8) -> String {
    format!("_r{}", r)
}

fn uv_name(i: u32) -> String {
    format!("_u{}", i)
}

/// Resolved **1-based** destination PC for `BC_JMP` / `BC_UCLO` / fused-compare branch slots.
///
/// LuaJIT stores `setbc_d(jmp, dest - (jmp_pc0 + 1) + BCBIAS_J)` with **0-based** `jmp_pc0`
/// (`lj_parse.c:jmp_patchins`). So `dest0 = jmp_pc0 + 1 + (bc_d - BCBIAS_J)`.
/// Glimmer uses **1-based** `pc` (= `jmp_pc0 + 1`), hence `dest1 = pc + (bc_d - BCBIAS_J) + 1`.
///
/// The high half is stored as **unsigned** 16-bit; do not narrow through `i16` first (e.g. `+1`
/// encodes as `0x8001`).
fn jmp_target_pc(pc: i32, ins: u32) -> i32 {
    let rd = (ins >> 16) & 0xffff;
    pc + rd as i32 - BCBIAS_J + 1
}

/// PCs that are the destination of `BC_JMP` or `BC_UCLO` in this proto (1-based bytecode index).
fn collect_proto_jump_targets(bc: &[u32], sizebc: i32) -> HashSet<i32> {
    let mut targets = HashSet::new();
    let mut pc = 1i32;
    while pc <= sizebc {
        let ins = bc[(pc - 1) as usize];
        let op = bc_op(ins);
        if op == 88 || op == 50 {
            let tgt = jmp_target_pc(pc, ins);
            if (1..=sizebc).contains(&tgt) {
                targets.insert(tgt);
            }
        } else if (4..=11).contains(&op) {
            // Then-entry is only reached by fallthrough past the JMP slot; it may not be a JMP target.
            let then_pc = pc + 2;
            if (1..=sizebc).contains(&then_pc) {
                targets.insert(then_pc);
            }
        }
        pc += 1;
    }
    targets
}

/// Lua `goto` labels must be valid identifiers; never embed raw bytecode PCs (can be negative).
fn jump_target_labels(id: usize, jump_targets: &HashSet<i32>) -> HashMap<i32, String> {
    let mut pcs: Vec<i32> = jump_targets.iter().copied().collect();
    pcs.sort_unstable();
    pcs
        .into_iter()
        .enumerate()
        .map(|(seq, pc)| (pc, format!("__p{}_x{}", id, seq)))
        .collect()
}

unsafe fn knum_literal(pt: *const std::ffi::c_void, idx: u32) -> Result<String, String> {
    let mut ival: i32 = 0;
    let mut fval: f64 = 0.0;
    let k = glimmer_proto_knum_kind(pt, idx, &mut ival, &mut fval);
    match k {
        1 => Ok(ival.to_string()),
        2 => Ok(format_float_literal(fval)),
        _ => Err(format!("knum idx {idx}: unsupported constant tag")),
    }
}

fn format_float_literal(x: f64) -> String {
    if x.is_nan() {
        return "(0/0)".to_string();
    }
    if x.is_infinite() {
        return if x.is_sign_positive() {
            "(1/0)".to_string()
        } else {
            "(-1/0)".to_string()
        };
    }
    format!("{:.17}", x).trim_end_matches('0').trim_end_matches('.').to_string()
}

unsafe fn kgc_string_lua_literal(pt: *const std::ffi::c_void, ins: u32) -> Result<String, String> {
    let du = (bc_d(ins) & 0xffff) as i32;
    let kidx = -((du + 1) as isize);
    let mut data: *const c_char = std::ptr::null();
    let mut len: usize = 0;
    if glimmer_proto_kgc_str(pt, kidx, &mut data, &mut len) == 0 {
        return Err(format!(
            "kgc slot kidx {kidx}: expected string (operand d={})",
            bc_d(ins)
        ));
    }
    let bytes = std::slice::from_raw_parts(data as *const u8, len);
    Ok(lua_string_literal(bytes))
}

fn lua_string_literal(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() + 2);
    s.push('"');
    for &b in bytes {
        match b {
            b'\\' => s.push_str("\\\\"),
            b'"' => s.push_str("\\\""),
            b'\n' => s.push_str("\\n"),
            b'\r' => s.push_str("\\r"),
            b'\t' => s.push_str("\\t"),
            32..=126 if b != b'"' && b != b'\\' => s.push(b as char),
            _ => write!(&mut s, "\\{}", b).unwrap(),
        }
    }
    s.push('"');
    s
}

fn proto_ptr_key(p: *const std::ffi::c_void) -> usize {
    p as usize
}

/// Best-effort lower loaded chunk to Lua source; invoked as `return (function() ... end)()` tail.
///
/// `cfg_plan`: from [`CfgObfuscationPlan::parse_source`]; each prototype uses [`CfgObfuscationPlan::level_at_source_line`]
/// on LuaJIT `firstline`. **`high`** uses a bytecode **dispatcher** (`while` + block id). **`low`** matches **`none`**: linear **`goto`** lowering.
pub fn lower_loaded_chunk(chunk: &LoadedChunk, cfg_plan: &CfgObfuscationPlan) -> Result<String, String> {
    let mut idx_map: HashMap<usize, usize> = HashMap::new();
    for (i, &p) in chunk.protos.iter().enumerate() {
        idx_map.insert(proto_ptr_key(p), i);
    }

    let mut out = String::new();
    writeln!(
        out,
        "-- :) "
    )
    .unwrap();

    let names: Vec<String> = (0..chunk.protos.len())
        .map(|i| format!("__p{}", i))
        .collect();

    writeln!(
        out,
        "local {}",
        names.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")
    )
    .unwrap();

    for (id, &pt) in chunk.protos.iter().enumerate() {
        let firstline = unsafe { glimmer_proto_firstline(pt) };
        let cfg_level = cfg_plan.level_at_source_line(firstline);
        emit_proto(&mut out, id, pt, chunk, &idx_map, &names, cfg_level)?;
    }

    // Root is protos[0] per BFS from chunk.collect_protos
    let root_pt = chunk.protos[0];
    let root_uv_count = unsafe { proto_sizeuv(root_pt) };

    write!(out, "\nreturn (function()\n").unwrap();
    if root_uv_count == 0 {
        writeln!(out, "  return {}()", names[0]).unwrap();
    } else {
        // Pass _G once per upvalue slot (approximation for env-like chunks).
        write!(out, "  return {}(", names[0]).unwrap();
        for i in 0..root_uv_count {
            if i > 0 {
                out.push_str(", ");
            }
            out.push_str("_G");
        }
        writeln!(out, ")").unwrap();
    }
    writeln!(out, "end)()").unwrap();

    Ok(out)
}

unsafe fn proto_sizeuv(pt: *const std::ffi::c_void) -> u32 {
    let mut n = 0u32;
    loop {
        if glimmer_proto_uv_desc(pt, n) == 0xffff {
            break;
        }
        n += 1;
        if n > 255 {
            break;
        }
    }
    n
}

include!("lower_emit_insn.inc.rs");

fn emit_proto(
    out: &mut String,
    id: usize,
    pt: *const std::ffi::c_void,
    _chunk: &LoadedChunk,
    idx_map: &HashMap<usize, usize>,
    names: &[String],
    cfg_level: CfgObfuscationLevel,
) -> Result<(), String> {
    let sizebc = unsafe { glimmer_proto_sizebc(pt) } as usize;
    let bc = unsafe { proto_bc_words(pt) };
    if bc.is_empty() {
        return Err("prototype has no bytecode".into());
    }
    let framesize = unsafe { glimmer_proto_framesize(pt) };
    let numparams = unsafe { glimmer_proto_numparams(pt) };

    let sizeuv = unsafe { proto_sizeuv(pt) };

    let mut params = Vec::new();
    for i in 0..sizeuv {
        params.push(uv_name(i));
    }
    for i in 0..numparams {
        params.push(reg(i));
    }
    let param_list = params.join(", ");

    writeln!(
        out,
        "{} = function({})",
        names[id], param_list
    )
    .unwrap();

    if framesize as usize > numparams as usize {
        let mut extras = Vec::new();
        for r in numparams..framesize {
            extras.push(reg(r));
        }
        writeln!(out, "  local {}", extras.join(", ")).unwrap();
    }

    let sizebc_i = sizebc as i32;

    match cfg_level {
        CfgObfuscationLevel::None | CfgObfuscationLevel::Low => {
            let jump_targets = collect_proto_jump_targets(&bc, sizebc_i);
            let target_labels = jump_target_labels(id, &jump_targets);
            let branch = BranchStyle::Linear {
                target_labels: &target_labels,
                sizebc: sizebc_i,
                proto_id: id,
            };
            let mut pc = 1i32;
            while pc <= sizebc_i {
                let ins = bc[(pc - 1) as usize];
                if let Some(lbl) = target_labels.get(&pc) {
                    writeln!(out, "  ::{}::", lbl).unwrap();
                }
                if skip_fun_header(pc, ins) {
                    pc += 1;
                    continue;
                }
                let op = bc_op(ins);
                if is_eq_family_comparison(op) {
                    emit_comparison_jmp_pair(out, "  ", pt, id, pc, &bc, sizebc_i, &branch)?;
                    pc += 2;
                    continue;
                }
                emit_instruction(out, "  ", pt, id, pc, ins, idx_map, names, &branch)?;
                pc += 1;
            }
        }
        CfgObfuscationLevel::High => {
            let leaders = collect_block_leaders(&bc, sizebc_i);
            let blocks = basic_block_ranges(&leaders, sizebc_i);
            let pc_to_block = pc_to_block_index(&blocks);
            let entry = *pc_to_block
                .get(&1)
                .ok_or_else(|| format!("proto {}: dispatcher missing entry block at pc 1", id))?;
            let disp_var = format!("__dc_{}", id);
            writeln!(out, "  local {} = {}", disp_var, entry).unwrap();
            writeln!(out, "  while true do").unwrap();
            let branch = BranchStyle::Dispatcher {
                disp_var: disp_var.as_str(),
                pc_to_block: &pc_to_block,
                sizebc: sizebc_i,
                proto_id: id,
            };
            for (bi, &(start, end)) in blocks.iter().enumerate() {
                if bi == 0 {
                    writeln!(out, "    if {} == {} then", disp_var, bi).unwrap();
                } else {
                    writeln!(out, "    elseif {} == {} then", disp_var, bi).unwrap();
                }
                let mut pc = start;
                while pc <= end {
                    let ins = bc[(pc - 1) as usize];
                    if skip_fun_header(pc, ins) {
                        pc += 1;
                        continue;
                    }
                    let op = bc_op(ins);
                    if is_eq_family_comparison(op) {
                        if pc + 1 > end {
                            return Err(format!(
                                "proto {}: comparison at pc {} split across dispatcher block [{}, {}]",
                                id, pc, start, end
                            ));
                        }
                        emit_comparison_jmp_pair(
                            out,
                            "      ",
                            pt,
                            id,
                            pc,
                            &bc,
                            sizebc_i,
                            &branch,
                        )?;
                        pc += 2;
                        continue;
                    }
                    emit_instruction(out, "      ", pt, id, pc, ins, idx_map, names, &branch)?;
                    pc += 1;
                }
                let last_ins = bc[(end - 1) as usize];
                let last_op = bc_op(last_ins);
                if let Some(nb) = block_successor(&bc, sizebc_i, &pc_to_block, end)? {
                    writeln!(out, "      {} = {}", disp_var, nb).unwrap();
                } else if !terminates_control_flow(last_op)
                    && last_op != 88
                    && last_op != 50
                    && end == sizebc_i
                {
                    writeln!(out, "      return nil").unwrap();
                }
            }
            for k in 0..2usize {
                let phantom = 100_000 + id * 1_000 + k;
                writeln!(out, "    elseif {} == {} then", disp_var, phantom).unwrap();
                writeln!(out, "      local __ph_{}_{} = nil", id, k).unwrap();
            }
            writeln!(out, "    else").unwrap();
            writeln!(out, "      break").unwrap();
            writeln!(out, "    end").unwrap();
            writeln!(out, "  end").unwrap();
            writeln!(out, "  return nil").unwrap();
        }
    }

    writeln!(out, "end").unwrap();
    Ok(())
}

