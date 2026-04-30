//! Compile Lua sources to client bundles (stripped bytecode + profiling maps).
//!
//! ## Encrypted profiling map blob (v1)
//!
//! Layout: `nonce (12 bytes) || ciphertext`, where `ciphertext` is the
//! ChaCha20-Poly1305 output (includes the 16-byte authentication tag).
//!
//! Set `GLIMMER_MAP_KEY` to 64 hex digits (32 bytes) when compiling; keep the
//! same key on the server to decrypt. Use [`decrypt_profiling_map_json`] (or
//! [`decrypt_map_payload`] + JSON parse) to recover [`ProfilingMapV1`], then
//! [`lookup_line`] for `(proto_id, bc_idx) -> source line`.

use base64::engine::general_purpose::STANDARD as B64_ENGINE;
use base64::Engine;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::ffi::CStr;
use std::path::{Path, PathBuf};

use crate::chunk::{load_chunk, LoadedChunk};
use crate::lower;
use glimmer_luajit_sys::*;

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProfilingMapV1 {
    pub glimmer_profiling_map: u32,
    pub source_path: String,
    pub protos: Vec<ProtoLineMapV1>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProtoLineMapV1 {
    pub id: u32,
    pub chunkname: String,
    pub firstline: u32,
    pub numline: u32,
    /// One entry per bytecode instruction index `0 .. sizebc-1`; `-1` if unknown.
    pub line_per_bc: Vec<i32>,
}

pub fn dump_bytecode_strip(chunk: &LoadedChunk) -> Result<Vec<u8>, String> {
    unsafe {
        let l = chunk.lua_state();
        let mut p: *mut u8 = std::ptr::null_mut();
        let mut len: usize = 0;
        let st = glimmer_dump_stack_function(l, 1, &mut p, &mut len);
        match st {
            0 => {
                let v = std::slice::from_raw_parts(p, len).to_vec();
                glimmer_dump_bytes_free(p);
                Ok(v)
            }
            2 => Err("dump: stack empty".into()),
            3 => Err("dump: top value is not a Lua function".into()),
            4 => Err("dump: lj_bcwrite failed".into()),
            _ => Err(format!("dump: unknown status {st}")),
        }
    }
}

pub fn build_profiling_map(source_path: &str, protos: &[*const std::ffi::c_void]) -> ProfilingMapV1 {
    let mut protos_out = Vec::new();
    for (id, &pt) in protos.iter().enumerate() {
        let n = unsafe { glimmer_proto_sizebc(pt) };
        let mut line_per_bc = Vec::with_capacity(n as usize);
        for bc_idx in 0..n {
            line_per_bc.push(unsafe { glimmer_proto_line_at_bc(pt, bc_idx) });
        }
        let chunkname = unsafe {
            let p = glimmer_proto_chunkname_cstr(pt);
            CStr::from_ptr(p).to_string_lossy().into_owned()
        };
        protos_out.push(ProtoLineMapV1 {
            id: id as u32,
            chunkname,
            firstline: unsafe { glimmer_proto_firstline(pt) },
            numline: unsafe { glimmer_proto_numline(pt) },
            line_per_bc,
        });
    }
    ProfilingMapV1 {
        glimmer_profiling_map: 1,
        source_path: source_path.to_string(),
        protos: protos_out,
    }
}

pub fn encrypt_map_payload(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, String> {
    let cipher = ChaCha20Poly1305::new_from_slice(key).map_err(|e| e.to_string())?;
    let mut nonce_bytes = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ct = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| e.to_string())?;
    let mut out = nonce_bytes.to_vec();
    out.extend(ct);
    Ok(out)
}

pub fn decrypt_map_payload(key: &[u8; 32], blob: &[u8]) -> Result<Vec<u8>, String> {
    if blob.len() < 12 {
        return Err("encrypted map blob too short".into());
    }
    let cipher = ChaCha20Poly1305::new_from_slice(key).map_err(|e| e.to_string())?;
    let nonce = Nonce::from_slice(&blob[..12]);
    cipher
        .decrypt(nonce, &blob[12..])
        .map_err(|e| e.to_string())
}

pub fn decrypt_profiling_map_json(key: &[u8; 32], blob: &[u8]) -> Result<ProfilingMapV1, String> {
    let pt = decrypt_map_payload(key, blob)?;
    serde_json::from_slice(&pt).map_err(|e| e.to_string())
}

pub fn lookup_line(map: &ProfilingMapV1, proto_id: u32, bc_idx: u32) -> Option<i32> {
    let p = map.protos.get(proto_id as usize)?;
    let ln = *p.line_per_bc.get(bc_idx as usize)?;
    if ln < 0 {
        None
    } else {
        Some(ln)
    }
}

/// Control-flow obfuscation tier chosen by `--! cfg low` / `--! cfg high` in source (per line regions).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CfgObfuscationLevel {
    /// Before any `--! cfg low` / `--! cfg high` in the file, or unknown line.
    None,
    Low,
    High,
}

/// Line-based CFG obfuscation regions from `--! cfg ...` markers.
#[derive(Debug, Clone, Default)]
pub struct CfgObfuscationPlan {
    /// Sorted by source line (1-based). From this line **inclusive**, the level applies until the next entry or EOF.
    segments: Vec<(usize, CfgObfuscationLevel)>,
}

impl CfgObfuscationPlan {
    /// Parse `--! cfg low` / `--! cfg high` anywhere in the source (trimmed lines). Other `--!` prefixes are ignored.
    pub fn parse_source(source: &str) -> Result<Self, String> {
        let mut segments = Vec::new();
        for (idx, line) in source.lines().enumerate() {
            let line_no = idx + 1;
            if let Some(lvl) = parse_cfg_bang_cfg_directive(line.trim(), line_no)? {
                segments.push((line_no, lvl));
            }
        }
        Ok(Self { segments })
    }

    /// Level that applies at a given **1-based** source line (e.g. LuaJIT `firstline` for a prototype).
    pub fn level_at_source_line(&self, line: u32) -> CfgObfuscationLevel {
        if line == 0 {
            return CfgObfuscationLevel::None;
        }
        let l = line as usize;
        let mut cur = CfgObfuscationLevel::None;
        for &(start, lvl) in &self.segments {
            if start <= l {
                cur = lvl;
            } else {
                break;
            }
        }
        cur
    }

    pub fn has_cfg_regions(&self) -> bool {
        !self.segments.is_empty()
    }
}

fn parse_cfg_bang_cfg_directive(
    trimmed_line: &str,
    line_no: usize,
) -> Result<Option<CfgObfuscationLevel>, String> {
    let Some(rest) = trimmed_line.strip_prefix("--!") else {
        return Ok(None);
    };
    let body = rest.trim();
    if body.is_empty() {
        return Ok(None);
    }
    let mut words = body.split_whitespace();
    let Some(w0) = words.next() else {
        return Ok(None);
    };
    if !w0.eq_ignore_ascii_case("cfg") {
        return Ok(None);
    }
    let Some(w1) = words.next() else {
        return Err(format!(
            "line {line_no}: incomplete `--! cfg` directive (expected `low` or `high`)"
        ));
    };
    if words.next().is_some() {
        return Err(format!(
            "line {line_no}: invalid `--! cfg ...` directive: `{body}` (use exactly `cfg low` or `cfg high`)"
        ));
    }
    if w1.eq_ignore_ascii_case("low") {
        return Ok(Some(CfgObfuscationLevel::Low));
    }
    if w1.eq_ignore_ascii_case("high") {
        return Ok(Some(CfgObfuscationLevel::High));
    }
    Err(format!(
        "line {line_no}: unknown `--! cfg` mode `{w1}` (expected `low` or `high`)"
    ))
}

// TODO(glimmer-lint): `--! cfg low` / `--! cfg high` regions
// - Warn when a prototype's `firstline` falls in `None` but a later sibling uses `high` (style / intent).
// - Warn on repeated same-tier markers back-to-back; suggest merging.
// - Optional: require markers only immediately above `function` / local function (project style).
// - Validate unknown `--! foo` if we later reserve the prefix exclusively for glimmer.

pub fn parse_map_key_hex(s: &str) -> Result<[u8; 32], String> {
    let hex = s.trim().replace(' ', "");
    if hex.len() != 64 {
        return Err("GLIMMER_MAP_KEY must be 64 hex characters (32 bytes)".into());
    }
    let mut key = [0u8; 32];
    for i in 0..32 {
        let byte =
            u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).map_err(|_| "invalid hex in GLIMMER_MAP_KEY")?;
        key[i] = byte;
    }
    Ok(key)
}

pub struct CompileOptions {
    pub plaintext_maps: bool,
    /// Emit stripped bytecode + `loadstring` loader instead of regenerated Lua.
    pub bytecode_vm: bool,
}

pub fn compiled_output_path(path: &Path) -> PathBuf {
    let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("out");
    let parent = path.parent().unwrap_or(Path::new(""));
    parent.join(format!("{stem}_comp.lua"))
}

pub fn compile_file(path: &Path, opts: CompileOptions) -> Result<PathBuf, String> {
    let chunk = load_chunk(path)?;
    let map = build_profiling_map(&chunk.path, &chunk.protos);
    let json = serde_json::to_vec(&map).map_err(|e| e.to_string())?;

    let (map_blob_b64, map_mode): (String, &'static str) = if opts.plaintext_maps {
        eprintln!("glimmer compile: warning: profiling map embedded as plaintext (--plaintext-maps)");
        (B64_ENGINE.encode(&json), "plaintext")
    } else {
        let key_hex = std::env::var("GLIMMER_MAP_KEY").map_err(|_| {
            "set GLIMMER_MAP_KEY (64 hex chars) or pass --plaintext-maps for insecure dev builds".to_string()
        })?;
        let key = parse_map_key_hex(&key_hex)?;
        let enc = encrypt_map_payload(&key, &json)?;
        (B64_ENGINE.encode(&enc), "chacha20poly1305_v1")
    };

    let out_path = compiled_output_path(path);
    let lua = if opts.bytecode_vm {
        let bytecode = dump_bytecode_strip(&chunk)?;
        let bc_b64 = B64_ENGINE.encode(&bytecode);
        render_bundle_bytecode_vm(&bc_b64, &map_blob_b64, map_mode)
    } else {
        let cfg_plan = CfgObfuscationPlan::parse_source(&chunk.source_text)?;
        let body = lower::lower_loaded_chunk(&chunk, &cfg_plan)?;
        render_bundle_regenerated_lua(&body, &map_blob_b64, map_mode)
    };
    std::fs::write(&out_path, lua).map_err(|e| e.to_string())?;
    Ok(out_path)
}

fn render_bundle_regenerated_lua(lowered_body: &str, map_b64: &str, map_mode: &str) -> String {
    format!(
        r#"-- [[ << Assembled file >> glimmer bundle v1 ]]
-- Profiling map transport: {map_mode}
-- Execution: regenerated Lua (best-effort lowering). Map: server-side symbolication only.

GLIMMER_MAP_MODE = "{map_mode}"
GLIMMER_PROFILE_MAP_B64 = [[{map_b64}]]

{lowered_body}"#,
        map_mode = map_mode,
        map_b64 = map_b64,
        lowered_body = lowered_body,
    )
}

fn render_bundle_bytecode_vm(bc_b64: &str, map_b64: &str, map_mode: &str) -> String {
    format!(
        r#"-- [[ << Assembled file >> glimmer bundle v1 ]]
-- Profiling map transport: {map_mode}
-- Bytecode: LuaJIT binary for loadstring (fallback). Map: server-side symbolication only.

GLIMMER_MAP_MODE = "{map_mode}"
GLIMMER_PROFILE_MAP_B64 = [[{map_b64}]]

local function glimmer_b64dec(data)
  local b = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
  local rev = {{}}
  for i = 1, #b do rev[string.sub(b, i, i)] = i - 1 end
  data = string.gsub(data, "[^%w%+%/%=]", "")
  local out = {{}}
  local i = 1
  while i <= #data do
    local p = string.sub(data, i, i + 3)
    if #p < 4 then break end
    local c1 = rev[string.sub(p, 1, 1)] or 0
    local c2 = rev[string.sub(p, 2, 2)] or 0
    local c3 = rev[string.sub(p, 3, 3)] or 0
    local c4 = rev[string.sub(p, 4, 4)] or 0
    i = i + 4
    local triple = c1 * 262144 + c2 * 4096 + c3 * 64 + c4
    out[#out + 1] = string.char(math.floor(triple / 65536) % 256)
    local q3 = string.sub(p, 3, 3)
    local q4 = string.sub(p, 4, 4)
    if q3 ~= "=" then
      out[#out + 1] = string.char(math.floor(triple / 256) % 256)
      if q4 ~= "=" then
        out[#out + 1] = string.char(triple % 256)
      end
    end
  end
  return table.concat(out)
end

local _bc = glimmer_b64dec([[{bc_b64}]])
local _fn, _err = loadstring(_bc, "@=(glimmer)")
if not _fn then error(_err or "glimmer: loadstring failed") end
_fn()
"#,
        map_mode = map_mode,
        map_b64 = map_b64,
        bc_b64 = bc_b64,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;
    use std::path::PathBuf;

    const LUA_OK: i32 = 0;

    #[test]
    fn round_trip_bytecode_smoke() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let path = root.join("..").join("test_code").join("jit_clean.lua");
        let chunk = load_chunk(&path).expect("load");
        let bytes = dump_bytecode_strip(&chunk).expect("dump");
        assert!(!bytes.is_empty());
        assert_eq!(bytes[0], 0x1b);
        assert_eq!(bytes[1] as char, 'L');
        assert_eq!(bytes[2] as char, 'J');

        unsafe {
            let l = luaL_newstate();
            assert!(!l.is_null());
            luaL_openlibs(l);
            let name = CString::new("@roundtrip").unwrap();
            let st = luaL_loadbuffer(
                l,
                bytes.as_ptr() as *const _,
                bytes.len(),
                name.as_ptr(),
            );
            assert_eq!(st, LUA_OK, "loadbuffer bytecode");
            let pc = lua_pcall(l, 0, 0, 0);
            assert_eq!(pc, LUA_OK, "pcall bytecode chunk");
            lua_close(l);
        }
    }

    #[test]
    fn encrypt_decrypt_map_round_trip() {
        let key = [7u8; 32];
        let map = ProfilingMapV1 {
            glimmer_profiling_map: 1,
            source_path: "x.lua".into(),
            protos: vec![ProtoLineMapV1 {
                id: 0,
                chunkname: "@x".into(),
                firstline: 1,
                numline: 3,
                line_per_bc: vec![1, 1, 2],
            }],
        };
        let json = serde_json::to_vec(&map).unwrap();
        let blob = encrypt_map_payload(&key, &json).unwrap();
        let got = decrypt_profiling_map_json(&key, &blob).unwrap();
        assert_eq!(got, map);
    }

    #[test]
    fn cfg_bang_plan_empty() {
        let p = CfgObfuscationPlan::parse_source("local x = 1\n").unwrap();
        assert!(!p.has_cfg_regions());
        assert_eq!(p.level_at_source_line(1), CfgObfuscationLevel::None);
    }

    #[test]
    fn cfg_bang_plan_low_then_high() {
        let p = CfgObfuscationPlan::parse_source(
            "--! cfg low\nfunction a() end\n--! cfg high\nfunction b() end\n",
        )
        .unwrap();
        assert_eq!(p.level_at_source_line(1), CfgObfuscationLevel::Low);
        assert_eq!(p.level_at_source_line(2), CfgObfuscationLevel::Low);
        assert_eq!(p.level_at_source_line(3), CfgObfuscationLevel::High);
        assert_eq!(p.level_at_source_line(4), CfgObfuscationLevel::High);
    }

    #[test]
    fn cfg_bang_plan_trimmed_line() {
        let p = CfgObfuscationPlan::parse_source("  --! cfg high  \n").unwrap();
        assert_eq!(p.level_at_source_line(1), CfgObfuscationLevel::High);
    }

    #[test]
    fn cfg_bang_plan_rejects_unknown_mode() {
        assert!(CfgObfuscationPlan::parse_source("--! cfg medium\n").is_err());
    }

    #[test]
    fn cfg_bang_plan_rejects_extra_tokens() {
        assert!(CfgObfuscationPlan::parse_source("--! cfg low extra\n").is_err());
    }

    #[test]
    fn cfg_bang_plan_ignores_other_bang() {
        let p = CfgObfuscationPlan::parse_source("--! nolint\n--! cfg low\n").unwrap();
        assert_eq!(p.level_at_source_line(1), CfgObfuscationLevel::None);
        assert_eq!(p.level_at_source_line(2), CfgObfuscationLevel::Low);
    }

    #[test]
    fn lookup_line_respects_sentinel() {
        let map = ProfilingMapV1 {
            glimmer_profiling_map: 1,
            source_path: "".into(),
            protos: vec![ProtoLineMapV1 {
                id: 0,
                chunkname: "".into(),
                firstline: 0,
                numline: 0,
                line_per_bc: vec![10, -1],
            }],
        };
        assert_eq!(lookup_line(&map, 0, 0), Some(10));
        assert_eq!(lookup_line(&map, 0, 1), None);
    }
}
