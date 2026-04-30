### ⚠️⚠️ Made using AI ⚠️⚠️
# Glimmer

The linter for Garry's Mod Lua.

## Building (Windows, LuaJIT)

Glimmer links **LuaJIT 2.1** built from the `vendor/LuaJIT` git submodule using MSVC. The Rust binary is **32-bit** (`i686-pc-windows-msvc`) to align with common Garry's Mod client builds.

1. Install [Rust](https://rustup.rs/) and the MSVC **32-bit** target:

   ```text
   rustup target add i686-pc-windows-msvc
   ```

2. Install **Visual Studio** (or Build Tools) with **Desktop development with C++**, including the **MSVC v143 (or current) x86/x64** toolset so **x86** libraries are available.

3. Open an **x86 Native Tools Command Prompt for VS** (not x64). `cl.exe` must be on `PATH` and `INCLUDE` must be set (the prompt does this for you).

4. Fetch LuaJIT into `vendor/LuaJIT`. If the submodule is already recorded in git:

   ```text
   git submodule update --init --recursive
   ```

   If you are wiring it for the first time:

   ```text
   git submodule add -b v2.1 https://github.com/LuaJIT/LuaJIT.git vendor/LuaJIT
   ```

   To pin a specific commit, `cd vendor\LuaJIT`, `git checkout <sha>`, then commit the submodule pointer from the repo root.

   If you previously had LuaJIT at the repository root, remove that old gitlink and submodule config before adding `vendor/LuaJIT`.

5. Build Glimmer:

   ```text
   cargo build -p glimmer --target i686-pc-windows-msvc
   ```

6. Run and confirm LuaJIT is loaded (prints `jit.version` and `_VERSION`):

   ```text
   cargo run -p glimmer --target i686-pc-windows-msvc
   ```

First lines of output should look like:

```text
LuaJIT 2.1.x | Lua 5.1
```

(Exact strings depend on the pinned LuaJIT revision.)

# Project Goals:

- [x] Compiles code using luajit for bytecode analysis.
- [x] Estimated function cost of execution.
- [x] Can this code be JIT compiled, if not, why?
- [ ] Provide type information via NDoc comments.
- [ ] lua-lint levels of linting.
- [x] Bytecode warnings.
- [ ] Performance lints.
- [x] Tiny Bytecode Executor. With source maps.
