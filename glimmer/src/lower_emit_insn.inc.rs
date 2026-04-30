// Included from `lower.rs` after `proto_sizeuv` — CFG dispatcher + shared opcode emission.

macro_rules! emitln {
    ($out:expr, $($arg:tt)*) => {
        writeln!($out, $($arg)*).map_err(|e| e.to_string())
    };
}

#[inline]
fn terminates_control_flow(op: u8) -> bool {
    matches!(op, 68 | 74 | 75 | 76)
}

#[inline]
fn skip_fun_header(pc: i32, ins: u32) -> bool {
    let op = bc_op(ins);
    (pc == 1 && matches!(op, 89 | 92)) || (pc == 2 && matches!(op, 90 | 93))
}

fn collect_block_leaders(bc: &[u32], sizebc: i32) -> Vec<i32> {
    let mut leaders: HashSet<i32> = HashSet::new();
    leaders.insert(1);
    let mut pc = 1i32;
    while pc <= sizebc {
        let ins = bc[(pc - 1) as usize];
        let op = bc_op(ins);
        if op == 88 || op == 50 {
            let tgt = jmp_target_pc(pc, ins);
            if (1..=sizebc).contains(&tgt) {
                leaders.insert(tgt);
            }
            if pc + 1 <= sizebc {
                leaders.insert(pc + 1);
            }
        }
        pc += 1;
    }
    let mut v: Vec<i32> = leaders.into_iter().collect();
    v.sort_unstable();
    v
}

fn basic_block_ranges(leaders: &[i32], sizebc: i32) -> Vec<(i32, i32)> {
    let mut blocks = Vec::new();
    if leaders.is_empty() {
        if sizebc >= 1 {
            blocks.push((1, sizebc));
        }
        return blocks;
    }
    for i in 0..leaders.len() {
        let start = leaders[i];
        let end = if i + 1 < leaders.len() {
            leaders[i + 1] - 1
        } else {
            sizebc
        };
        if start <= end {
            blocks.push((start, end));
        }
    }
    blocks
}

fn pc_to_block_index(blocks: &[(i32, i32)]) -> HashMap<i32, usize> {
    let mut m = HashMap::new();
    for (bi, &(s, e)) in blocks.iter().enumerate() {
        for pc in s..=e {
            m.insert(pc, bi);
        }
    }
    m
}

fn block_successor(
    bc: &[u32],
    sizebc: i32,
    pc_to_block: &HashMap<i32, usize>,
    block_end: i32,
) -> Result<Option<usize>, String> {
    let last_ins = bc[(block_end - 1) as usize];
    let op = bc_op(last_ins);
    if terminates_control_flow(op) || op == 88 || op == 50 {
        return Ok(None);
    }
    if block_end < sizebc {
        let nb = pc_to_block.get(&(block_end + 1)).copied().ok_or_else(|| {
            format!(
                "internal: fallthrough from pc {} missing block index",
                block_end
            )
        })?;
        return Ok(Some(nb));
    }
    Ok(None)
}

enum BranchStyle<'a> {
    Linear {
        target_labels: &'a HashMap<i32, String>,
        sizebc: i32,
        proto_id: usize,
    },
    Dispatcher {
        disp_var: &'a str,
        pc_to_block: &'a HashMap<i32, usize>,
        sizebc: i32,
        proto_id: usize,
    },
}

fn emit_jmp_or_uclo(
    out: &mut String,
    indent: &str,
    pc: i32,
    ins: u32,
    branch: &BranchStyle<'_>,
) -> Result<(), String> {
    let tgt = jmp_target_pc(pc, ins);
    match branch {
        BranchStyle::Linear {
            target_labels,
            sizebc,
            proto_id,
        } => {
            let lbl = target_labels.get(&tgt).ok_or_else(|| {
                format!(
                    "proto {} pc {}: branch targets invalid pc {} (sizebc={})",
                    proto_id, pc, tgt, sizebc
                )
            })?;
            emitln!(out, "{}goto {}", indent, lbl)?;
        }
        BranchStyle::Dispatcher {
            disp_var,
            pc_to_block,
            sizebc,
            proto_id,
        } => {
            let nb = pc_to_block.get(&tgt).copied().ok_or_else(|| {
                format!(
                    "proto {} pc {}: dispatcher target pc {} not mapped (sizebc={})",
                    proto_id, pc, tgt, sizebc
                )
            })?;
            emitln!(out, "{}{} = {}", indent, disp_var, nb)?;
        }
    }
    Ok(())
}

#[inline]
fn is_eq_family_comparison(op: u8) -> bool {
    (4..=11).contains(&op)
}

/// Equality/inequality subexpression for `ISEQV`…`ISNEP` (`a == rhs` as in the VM, before `if` inversion).
fn lua_eq_family_expr(op: u8, pt: *const std::ffi::c_void, ins: u32) -> Result<String, String> {
    let a = reg(bc_a(ins));
    match op {
        4 | 5 => {
            let rb = reg(s16(bc_d(ins)) as u8);
            Ok(format!("{} == {}", a, rb))
        }
        6 | 7 => {
            let lit = unsafe { kgc_string_lua_literal(pt, ins)? };
            Ok(format!("{} == {}", a, lit))
        }
        8 | 9 => {
            let kl = unsafe { knum_literal(pt, bc_d(ins))? };
            Ok(format!("{} == {}", a, kl))
        }
        10 | 11 => {
            let v = match bc_d(ins) & 0xffff {
                0 => "nil",
                1 => "false",
                2 => "true",
                _ => return Err(format!("ISEQP/ISNEP unknown pri {}", bc_d(ins))),
            };
            Ok(format!("{} == {}", a, v))
        }
        _ => Err(format!("lua_eq_family_expr: op {}", op)),
    }
}

/// Lua condition that when **true** matches the VM path into the **then** body at `cmp_pc + 2`
/// (fallthrough after the fused compare consumes the following `BC_JMP` without taking its offset).
/// After `bcemit_branch_t`, `if x == y` is emitted as `ISN*`; `if x ~= y` as `IS*`.
fn lua_if_jmp_then_cond(op: u8, pt: *const std::ffi::c_void, ins: u32) -> Result<String, String> {
    let eq = lua_eq_family_expr(op, pt, ins)?;
    Ok(if op % 2 == 1 {
        eq
    } else {
        format!("not ({})", eq)
    })
}

/// Target PC when the fused compare takes **`branchPC`** using the following slot’s displacement
/// (Lua “skip then” / false path). Not to be confused with the compare insn’s `D` operand
/// (`knum` / `kgc` / second reg for `ISEQN`…`ISNEP`).
fn jmp_skip_then_after_comparison(
    bc: &[u32],
    cmp_pc: i32,
    sizebc: i32,
    proto_id: usize,
) -> Result<i32, String> {
    let jmp_pc = cmp_pc + 1;
    if jmp_pc > sizebc {
        return Err(format!(
            "proto {}: comparison at pc {} must be followed by JMP",
            proto_id, cmp_pc
        ));
    }
    let jmp_ins = bc[(jmp_pc - 1) as usize];
    if bc_op(jmp_ins) != 88 {
        return Err(format!(
            "proto {}: expected BC_JMP after comparison at pc {}, got op {} at pc {}",
            proto_id,
            cmp_pc,
            bc_op(jmp_ins),
            jmp_pc
        ));
    }
    Ok(jmp_target_pc(jmp_pc, jmp_ins))
}

/// Emit `ISEQV`…`ISNEP` plus the mandatory following `BC_JMP` (two bytecode slots).
fn emit_comparison_jmp_pair(
    out: &mut String,
    indent: &str,
    pt: *const std::ffi::c_void,
    proto_id: usize,
    cmp_pc: i32,
    bc: &[u32],
    sizebc: i32,
    branch: &BranchStyle<'_>,
) -> Result<(), String> {
    let ins = bc[(cmp_pc - 1) as usize];
    let op = bc_op(ins);
    debug_assert!(is_eq_family_comparison(op));
    let cond = lua_if_jmp_then_cond(op, pt, ins)?;
    let jmp_then_pc = cmp_pc + 2;
    if jmp_then_pc > sizebc {
        return Err(format!(
            "proto {} pc {}: then-entry pc {} past sizebc {}",
            proto_id, cmp_pc, jmp_then_pc, sizebc
        ));
    }
    let skip_then_pc = jmp_skip_then_after_comparison(bc, cmp_pc, sizebc, proto_id)?;
    match branch {
        BranchStyle::Linear {
            target_labels,
            sizebc: sb,
            proto_id: pid,
        } => {
            let lbl_then = target_labels.get(&jmp_then_pc).ok_or_else(|| {
                format!(
                    "proto {} pc {}: linear lowering missing `then` label for pc {} (sizebc={})",
                    pid, cmp_pc, jmp_then_pc, *sb
                )
            })?;
            let lbl_skip = target_labels.get(&skip_then_pc).ok_or_else(|| {
                format!(
                    "proto {} pc {}: linear lowering missing skip label for pc {} (sizebc={})",
                    pid, cmp_pc, skip_then_pc, *sb
                )
            })?;
            emitln!(out, "{}if {} then", indent, cond)?;
            emitln!(out, "{}  goto {}", indent, lbl_then)?;
            emitln!(out, "{}else", indent)?;
            emitln!(out, "{}  goto {}", indent, lbl_skip)?;
            emitln!(out, "{}end", indent)?;
        }
        BranchStyle::Dispatcher {
            disp_var,
            pc_to_block,
            sizebc: sb,
            proto_id: pid,
        } => {
            if !(1..=*sb).contains(&skip_then_pc) {
                return Err(format!(
                    "proto {} pc {}: comparison false-branch pc {} out of range sizebc {}",
                    pid, cmp_pc, skip_then_pc, *sb
                ));
            }
            let bt = pc_to_block.get(&jmp_then_pc).copied().ok_or_else(|| {
                format!(
                    "proto {} pc {}: dispatcher missing jmp-then pc {}",
                    pid, cmp_pc, jmp_then_pc
                )
            })?;
            let bf = pc_to_block.get(&skip_then_pc).copied().ok_or_else(|| {
                format!(
                    "proto {} pc {}: dispatcher missing skip-then pc {}",
                    pid, cmp_pc, skip_then_pc
                )
            })?;
            emitln!(out, "{}if {} then", indent, cond)?;
            emitln!(out, "{}  {} = {}", indent, disp_var, bt)?;
            emitln!(out, "{}else", indent)?;
            emitln!(out, "{}  {} = {}", indent, disp_var, bf)?;
            emitln!(out, "{}end", indent)?;
        }
    }
    Ok(())
}

fn emit_instruction(
    out: &mut String,
    indent: &str,
    pt: *const std::ffi::c_void,
    proto_id: usize,
    pc: i32,
    ins: u32,
    idx_map: &HashMap<usize, usize>,
    names: &[String],
    branch: &BranchStyle<'_>,
) -> Result<(), String> {
    let op = bc_op(ins);
    match op {
        4..=11 => {
            return Err(format!(
                "proto {} pc {}: comparison opcode {} must be lowered with the following JMP as a pair",
                proto_id, pc, op
            ));
        }
        18 => {
            let a = bc_a(ins);
            let d = s16(bc_d(ins)) as u8;
            emitln!(out, "{}{} = {}", indent, reg(a), reg(d))?;
        }
        41 => {
            emitln!(
                out,
                "{}{} = {}",
                indent,
                reg(bc_a(ins)),
                s16(bc_d(ins))
            )?;
        }
        42 => {
            let lit = unsafe { knum_literal(pt, bc_d(ins)) }?;
            emitln!(out, "{}{} = {}", indent, reg(bc_a(ins)), lit)?;
        }
        43 => {
            let v = match bc_d(ins) {
                0 => "nil",
                1 => "false",
                2 => "true",
                _ => return Err(format!("KPRI unknown pri {}", bc_d(ins))),
            };
            emitln!(out, "{}{} = {}", indent, reg(bc_a(ins)), v)?;
        }
        39 => {
            let lit = unsafe { kgc_string_lua_literal(pt, ins) }?;
            emitln!(out, "{}{} = {}", indent, reg(bc_a(ins)), lit)?;
        }
        44 => {
            let a = bc_a(ins);
            let last = (bc_d(ins) & 0xffff) as u8;
            emitln!(
                out,
                "{}{} = nil",
                indent,
                (a..=last).map(reg).collect::<Vec<_>>().join(", ")
            )?;
        }
        45 => {
            emitln!(
                out,
                "{}{} = {}",
                indent,
                reg(bc_a(ins)),
                uv_name((bc_d(ins) & 0xffff) as u32)
            )?;
        }
        46 => {
            emitln!(
                out,
                "{}{} = {}",
                indent,
                uv_name(bc_a(ins) as u32),
                reg(s16(bc_d(ins)) as u8)
            )?;
        }
        54 => {
            let lit = unsafe { kgc_string_lua_literal(pt, ins) }?;
            emitln!(out, "{}{} = _G[{}]", indent, reg(bc_a(ins)), lit)?;
        }
        55 => {
            let lit = unsafe { kgc_string_lua_literal(pt, ins) }?;
            emitln!(out, "{}_G[{}] = {}", indent, lit, reg(bc_a(ins)))?;
        }
        22 | 23 | 24 | 25 | 26 => {
            let sym = match op {
                22 => "+",
                23 => "-",
                24 => "*",
                25 => "/",
                26 => "%",
                _ => unreachable!(),
            };
            let a = bc_a(ins);
            let b = bc_b(ins);
            let c = bc_c(ins);
            let kl = unsafe { knum_literal(pt, c as u32) }?;
            emitln!(out, "{}{} = {} {} {}", indent, reg(a), reg(b), sym, kl)?;
        }
        27 | 28 | 29 | 30 | 31 => {
            let sym = match op {
                27 => "+",
                28 => "-",
                29 => "*",
                30 => "/",
                31 => "%",
                _ => unreachable!(),
            };
            let a = bc_a(ins);
            let b = bc_b(ins);
            let c = bc_c(ins);
            let kl = unsafe { knum_literal(pt, b as u32) }?;
            emitln!(
                out,
                "{}{} = {} {} {}",
                indent,
                reg(a),
                kl,
                sym,
                reg(c)
            )?;
        }
        32 | 33 | 34 | 35 | 36 => {
            let sym = match op {
                32 => "+",
                33 => "-",
                34 => "*",
                35 => "/",
                36 => "%",
                _ => unreachable!(),
            };
            emitln!(
                out,
                "{}{} = {} {} {}",
                indent,
                reg(bc_a(ins)),
                reg(bc_b(ins)),
                sym,
                reg(bc_c(ins))
            )?;
        }
        37 => {
            emitln!(
                out,
                "{}{} = (math.pow)({}, {})",
                indent,
                reg(bc_a(ins)),
                reg(bc_b(ins)),
                reg(bc_c(ins))
            )?;
        }
        20 => {
            emitln!(
                out,
                "{}{} = -{}",
                indent,
                reg(bc_a(ins)),
                reg(s16(bc_d(ins)) as u8)
            )?;
        }
        19 => {
            emitln!(
                out,
                "{}{} = not {}",
                indent,
                reg(bc_a(ins)),
                reg(s16(bc_d(ins)) as u8)
            )?;
        }
        88 => emit_jmp_or_uclo(out, indent, pc, ins, branch)?,
        50 => emit_jmp_or_uclo(out, indent, pc, ins, branch)?,
        51 => {
            let child = unsafe { glimmer_proto_from_bc_kgc_d(pt, ins) };
            if child.is_null() {
                return Err("FNEW: child proto null".into());
            }
            let cid = *idx_map
                .get(&proto_ptr_key(child))
                .ok_or_else(|| "FNEW: child not in proto list".to_string())?;
            let cuv = unsafe { proto_sizeuv(child) };
            if cuv != 0 {
                return Err(format!(
                    "FNEW: child proto {} has {} upvalues (NYI for lowering v1)",
                    cid, cuv
                ));
            }
            emitln!(
                out,
                "{}{} = {}",
                indent,
                reg(bc_a(ins)),
                names[cid]
            )?;
        }
        66 => {
            let a = bc_a(ins);
            let b = bc_b(ins);
            let c = bc_c(ins);
            let nargs = c as i32 - 1;
            let nres = b as i32 - 1;
            let mut args = Vec::new();
            for i in 1..=nargs {
                args.push(reg((a as i32 + i) as u8));
            }
            let arglist = args.join(", ");
            let ftmp = format!("__fn_{}_{}", proto_id, pc);
            if nres <= 0 {
                emitln!(out, "{}{}({})", indent, reg(a), arglist)?;
            } else {
                emitln!(out, "{}local {} = {}", indent, ftmp, reg(a))?;
                let lhs: Vec<String> = (0..nres)
                    .map(|i| reg((a as i32 + i) as u8))
                    .collect();
                emitln!(out, "{}{} = {}({})", indent, lhs.join(", "), ftmp, arglist)?;
            }
        }
        68 => {
            let a = bc_a(ins);
            let nargs = s16(bc_d(ins)) - 1;
            let mut args = Vec::new();
            for i in 1..=nargs {
                args.push(reg((a as i32 + i) as u8));
            }
            emitln!(
                out,
                "{}return {}({})",
                indent,
                reg(a),
                args.join(", ")
            )?;
        }
        75 => emitln!(out, "{}return", indent)?,
        76 => emitln!(out, "{}return {}", indent, reg(bc_a(ins)))?,
        74 => {
            let a = bc_a(ins);
            let n = bc_d(ins) as i32 - 1;
            let mut vals: Vec<String> = Vec::new();
            for i in 0..n {
                vals.push(reg((a as i32 + i) as u8));
            }
            emitln!(out, "{}return {}", indent, vals.join(", "))?;
        }
        _ => {
            return Err(format!(
                "lowering NYI: opcode {} at proto {} pc {}",
                op, proto_id, pc
            ));
        }
    }
    Ok(())
}
