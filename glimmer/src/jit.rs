//! Static bytecode cues for LuaJIT trace recording (`lj_record.c` NYIBC paths).

use std::ffi::{c_void, CStr};
use std::path::Path;

use glimmer_luajit_sys::{
    glimmer_proto_chunkname_cstr, glimmer_proto_has_lineinfo, glimmer_proto_line_at_bc,
    glimmer_proto_firstline, glimmer_proto_numline,
};

use crate::bc::{self, op};
use crate::chunk::{load_chunk, proto_bc_words};
use crate::cost::proto_display_name;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NyiSite {
    /// Instruction index in the proto's `bc` array (0-based).
    pub pc: usize,
    /// Source line from LuaJIT debug info (`lj_debug_line`), when available.
    pub source_line: Option<u32>,
    pub mnemonic: &'static str,
    /// Short explanation for linter output (matches LuaJIT behaviour for pinned vendor revision).
    pub reason: &'static str,
    /// Raw 32-bit bytecode word as emitted by the VM (`BCIns`).
    pub ins_word: u32,
    /// Decoded A/B/C/D fields (see `lj_bc.h` instruction formats).
    pub operands: String,
}

#[derive(Debug, Clone)]
pub struct ProtoJitReport {
    /// LuaJIT `GCproto.chunkname` (often `@file.lua` for files).
    pub chunkname: String,
    pub name: String,
    pub first_line: u32,
    pub num_lines: u32,
    /// True when this proto's bytecode contains no unconditional NYIBC opcodes (`FNEW`, `UCLO`).
    pub trace_recording_clean: bool,
    pub unconditional_nyi: Vec<NyiSite>,
    /// `BC_VARG` is present; some vararg shapes still abort recording (`lj_record.c` nyivarg path).
    pub has_vararg_bytecode: bool,
    /// False when `lineinfo` is missing (stripped bytecode); line numbers are then unavailable.
    pub has_lineinfo: bool,
}

#[derive(Debug)]
pub struct FileJitReport {
    pub path: String,
    pub protos: Vec<ProtoJitReport>,
    pub load_error: Option<String>,
}

#[inline]
fn unconditional_nyi_kind(opc: u8) -> Option<(&'static str, &'static str)> {
    match opc {
        op::FNEW => Some((
            "FNEW",
            "LuaJIT aborts trace recording with NYI: bytecode FNEW (cannot record closure creation)",
        )),
        op::UCLO => Some((
            "UCLO",
            "LuaJIT aborts trace recording with NYI: bytecode UCLO (cannot record closing upvalues)",
        )),
        _ => None,
    }
}

fn format_bc_operands(ins: u32) -> String {
    format!(
        "word=0x{:08x} op={} A={} B={} C={} D={}",
        ins,
        bc::bc_op(ins),
        bc::bc_a(ins),
        bc::bc_b(ins),
        bc::bc_c(ins),
        bc::bc_d(ins),
    )
}

unsafe fn proto_chunkname_rust(pt: *const c_void) -> String {
    let p = glimmer_proto_chunkname_cstr(pt);
    if p.is_null() {
        return String::new();
    }
    CStr::from_ptr(p).to_string_lossy().into_owned()
}

fn build_nyi_site(pt: *const c_void, pc: usize, ins: u32) -> NyiSite {
    let (mnemonic, reason) = unconditional_nyi_kind(bc::bc_op(ins)).unwrap();
    let has_li = unsafe { glimmer_proto_has_lineinfo(pt) != 0 };
    let line_raw = unsafe { glimmer_proto_line_at_bc(pt, pc as u32) };
    let source_line = if has_li && line_raw >= 0 {
        Some(line_raw as u32)
    } else {
        None
    };
    NyiSite {
        pc,
        source_line,
        mnemonic,
        reason,
        ins_word: ins,
        operands: format_bc_operands(ins),
    }
}

fn analyze_insns(insns: &[u32], pt: *const c_void) -> (Vec<NyiSite>, bool) {
    let mut nyi = Vec::new();
    let mut has_varg = false;
    for (pc, ins) in insns.iter().enumerate() {
        let opc = bc::bc_op(*ins);
        if opc == op::VARG {
            has_varg = true;
        }
        if unconditional_nyi_kind(opc).is_some() {
            nyi.push(build_nyi_site(pt, pc, *ins));
        }
    }
    (nyi, has_varg)
}

/// Analyze bytecode for LuaJIT trace-recording NYI opcodes (see `CONTEXT.md`).
pub fn jit_file(path: &Path) -> FileJitReport {
    let loaded = match load_chunk(path) {
        Ok(c) => c,
        Err(e) => {
            return FileJitReport {
                path: path.to_string_lossy().into_owned(),
                protos: Vec::new(),
                load_error: Some(e),
            };
        }
    };

    let root = loaded.root_proto;
    let source = loaded.source_text.as_str();
    let path_str = loaded.path.clone();

    unsafe {
        let mut protos: Vec<ProtoJitReport> = Vec::new();
        for &p in loaded.protos.iter() {
            let insns = proto_bc_words(p);
            let (unconditional_nyi, has_vararg_bytecode) = analyze_insns(&insns, p);
            let trace_recording_clean = unconditional_nyi.is_empty();
            let first_line = glimmer_proto_firstline(p);
            let has_lineinfo = glimmer_proto_has_lineinfo(p) != 0;
            protos.push(ProtoJitReport {
                chunkname: proto_chunkname_rust(p),
                name: proto_display_name(p, root, source, first_line),
                first_line,
                num_lines: glimmer_proto_numline(p),
                trace_recording_clean,
                unconditional_nyi,
                has_vararg_bytecode,
                has_lineinfo,
            });
        }

        protos.sort_by(|a, b| {
            (a.first_line, a.num_lines, &a.name).cmp(&(b.first_line, b.num_lines, &b.name))
        });

        FileJitReport {
            path: path_str,
            protos,
            load_error: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn test_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../test_code")
    }

    #[test]
    fn jit_clean_function_has_no_unconditional_nyi() {
        let path = test_dir().join("jit_clean.lua");
        let r = jit_file(&path);
        assert!(r.load_error.is_none(), "{:?}", r.load_error);
        let add = r
            .protos
            .iter()
            .find(|p| p.name == "add")
            .expect("add proto");
        assert!(
            add.trace_recording_clean,
            "expected no FNEW/UCLO in add, got {:?}",
            add.unconditional_nyi
        );
        assert!(!add.has_vararg_bytecode);
        assert!(add.has_lineinfo, "parser-emitted protos should carry lineinfo");
    }

    #[test]
    fn jit_nested_closure_has_fnew_with_source_line() {
        let path = test_dir().join("jit_nested_closure.lua");
        let r = jit_file(&path);
        assert!(r.load_error.is_none(), "{:?}", r.load_error);
        let outer = r
            .protos
            .iter()
            .find(|p| p.name == "outer")
            .expect("outer proto");
        assert!(
            !outer.trace_recording_clean,
            "outer should contain FNEW for inner closure"
        );
        let fnew = outer
            .unconditional_nyi
            .iter()
            .find(|s| s.mnemonic == "FNEW")
            .expect("FNEW site");
        assert_eq!(
            fnew.source_line,
            Some(3),
            "inner `return function` should map to line 3"
        );
        assert!(
            outer.chunkname.contains("jit_nested_closure"),
            "chunkname={:?}",
            outer.chunkname
        );
    }

    #[test]
    fn jit_vararg_flags_varg_bytecode() {
        let path = test_dir().join("jit_vararg.lua");
        let r = jit_file(&path);
        assert!(r.load_error.is_none(), "{:?}", r.load_error);
        let va = r
            .protos
            .iter()
            .find(|p| p.name == "va")
            .expect("va proto");
        assert!(va.has_vararg_bytecode);
        assert!(
            va.trace_recording_clean,
            "plain vararg entry should not imply unconditional NYIBC by itself"
        );
    }

    #[test]
    fn jit_existing_fixture_main_is_clean_or_documented() {
        let path = test_dir().join("bc_cost.lua");
        let r = jit_file(&path);
        assert!(r.load_error.is_none(), "{:?}", r.load_error);
        let cheap = r
            .protos
            .iter()
            .find(|p| p.name == "cheap_function")
            .expect("cheap_function");
        assert!(
            cheap.trace_recording_clean,
            "cheap_function should not allocate closures or close upvalues in-body"
        );
    }
}
