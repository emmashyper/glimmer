# Glimmer — domain context

Terms are for product/domain language, not implementation details.

## Glossary

### Bytecode inspection (implementation)

v1 preference: inspect bytecode **from Rust** by extending the LuaJIT **FFI surface** (e.g. `Proto`, `BCIns`, related APIs exposed via `glimmer-luajit-sys` or a sibling crate), rather than driving `jit.util` from Lua for the core walk.

**NYI-related bumps** use a **versioned static map** in Rust (opcode and/or pattern → multiplier or flag), maintained to match the pinned `vendor/LuaJIT` revision; update when LuaJIT updates.

**Loop-related bumps** (v1): treat **numeric `for` and iterator loops** as loop sites—based on the **`FORI` / `FORL` / `ITERL` / `ITERN`** family and similar loop-header bytecode LuaJIT emits—not general arbitrary back-edges (those can be widened later).

**Base opcode weights** (v1): **mostly uniform** (one unit per instruction), with **explicit higher weights** for a small set of “hot” opcode families (e.g. `CALL*` / table get-set / string ops—exact list in implementation, tuned over time).

### Analysis scope (call graph)

The set of Lua sources used to **resolve callees** for transitive cost: (1) Lua files under the **working directory root** of the linted file (project root), and (2) Lua under a **vendored clone of** `https://github.com/Facepunch/garrysmod` (submodule path e.g. `vendor/garrysmod`), primarily the game’s shipped Lua tree such as `garrysmod/lua/`. Unknown targets outside this scope are not walked.

### Estimated function cost (reporting)

Lint output attaches a cost (and unresolved-call sidecar) to **every function prototype** emitted for a given source file—including nested locals and anonymous functions—each scored separately.

### Estimated function cost

A **hybrid** static score for a Lua function’s bytecode: a **base** contribution from each bytecode instruction (abstract weights), plus **explicit multipliers** (or additive bumps) for **calls**, **loops**, and **NYI-heavy** sites. The number is for **lint ranking and guidance**, not wall-clock time or guaranteed interpreter cost.

When a call target can be resolved within the **analysis scope**, **callee cost is included recursively** until targets are unknown, external, or cyclic (cycle policy below).

**Unresolved calls** (callee not in scope or not statically known) do **not** inflate the main hybrid score arbitrarily; the linter should surface them as a **separate metric or diagnostic** (count and/or list), alongside the main estimated function cost.

**Recursion / cycles:** when costing from a root function, use **depth-first traversal** of resolved callees: the **first visit** to a function contributes its intrinsic hybrid score and continues into callees; an edge to a function **already on the current DFS stack** contributes **zero** additional callee cost (avoids infinite expansion on direct/mutual recursion).

### JIT / trace recording (static bytecode cues)

LuaJIT compiles **traces**, not whole functions. Static analysis reports **bytecode that forces trace recording to abort** when the recorder executes it (`LJ_TRERR_NYIBC` in the pinned `vendor/LuaJIT`), not whether a line ever becomes hot enough to compile.

**Unconditional bytecode NYI** (v1): **`FNEW`** (closure creation) and **`UCLO`** (close upvalues) — see `lj_record.c` fallthrough before recording completes.

**Separate cue**: presence of **`BC_VARG`** — some vararg shapes hit the recorder’s `nyivarg` path and abort; listing vararg is informational, not a hard “never JIT” verdict.

**Default lint severity (v1):** **`FNEW`** and **`UCLO`** are both **warnings** when present in a prototype’s bytecode (same severity).

**Propagation (v1):** when a **call target is resolved** within analysis scope and that **callee prototype** contains unconditional bytecode NYI (`FNEW` / `UCLO`), the **caller** should surface a **propagated warning**. Walk **at most two hops** along resolved callees (direct call + one further resolved hop) so deep call trees do not flood diagnostics in v1.

**Propagated message shape (v1):** repeat the **full callee NYI site list** (PC, mnemonic, reason) on each ancestor diagnostic that fires due to propagation (accept verbosity for explicitness).

**Propagated severity:** same default severity as intrinsic NYI (**Warning**), not a softer tier.

Re-scan opcode lists when the LuaJIT submodule revision changes.

### Compiled bundle

The artifact produced by **`glimmer compile`** / **`glimmer -compile`**: a client-oriented Lua deliverable whose **default runnable body is regenerated Lua** (semantics recovered from compile-time LuaJIT prototype / bytecode information—not a verbatim copy of the author’s source), plus an embedded **profiling map** payload (base64; encrypted or dev-plaintext) for server-side symbolication. **v1 target:** this shape (not “ship stripped bytecode + `loadstring`”), because Garry’s Mod client Lua does not offer a reliable bytecode load path and regenerated Lua stays **LuaJIT–JIT friendly**.

**Optional fallback (non-default):** a **bytecode + tiny Lua interpreter** path may remain available behind an explicit flag for experiments or emergency use; it is **not** the canonical “compiled bundle” story for clients and does not replace the regenerated-Lua default.

### Copy friction (threat model)

**Primary adversary:** casual reuse (“script kiddies”)—copy-pasting readable addon Lua from dumps—**not** a motivated reverse engineer. The compile output aims to remove **low-friction literal theft** of the author’s original text and layout; it does **not** claim cryptographic or DRM-style protection of behavior or ideas.

### Regenerated Lua lowering (v1 quality)

**v1 policy (chosen):** **best-effort** lowering toward broad Lua semantics—prefer emitting runnable regenerated Lua whenever the toolchain can, and accept that **edge cases may be wrong** until coverage and diagnostics harden. This is intentionally **not** a formally verified whole-language decompiler in v1; it trades strict correctness guarantees for iteration speed and copy friction.

### CFG obfuscation regions (compile)

Authors mark **source line regions** with bang-comments (trimmed line must start with `--!`):

- `--! cfg low` — from this line **inclusive** until the next `--! cfg …`, use **linear lowering with `goto`** (same behavior as **no** directive; the marker is for authors / future lint).
- `--! cfg high` — from this line **inclusive**, use **dispatcher** lowering (`while` + block id) plus bogus branches.

Text before the first such marker uses tier **`None`** (no CFG directive). Each compiled **prototype** is assigned the tier active at its LuaJIT **`firstline`** (so nested functions can differ). **`--!` lines that are not `cfg low` / `cfg high`** (e.g. `--! nolint`) are **ignored** by compile today.

Malformed `cfg` lines (wrong mode, extra tokens, incomplete `cfg`) are **`glimmer compile` errors** with a line number. **`--! cfg low`** uses the same linear lowering as **no marker**: **`goto`** and stable labels. **`--! cfg high`** uses a **dispatcher** (`while` + numeric block id; jumps assign the id) plus extra **never-taken** `elseif` arms. A future **`glimmer` lint** should validate marker placement and intent **before** compile where possible.

### Profiling map

Compile-time capture of **per-prototype, per-bytecode-index → source line** (and chunk name metadata), serialized as JSON (`ProfilingMapV1`) at compile time from LuaJIT line info. At rest in the bundle it is either **ChaCha20-Poly1305** ciphertext (12-byte nonce + ciphertext including MAC, key from `GLIMMER_MAP_KEY`) or **plaintext** when `--plaintext-maps` is used (insecure, for development only).

### Symbolication

Given a decrypted profiling map and identifiers such as **`proto_id`** (index in the compile-time prototype enumeration) and **`bc_idx`** (bytecode instruction index within that prototype), resolving the original **source line** for profiling or server-side diagnostics—without exposing cleartext maps on the client in encrypted mode.
