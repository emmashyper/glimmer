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
