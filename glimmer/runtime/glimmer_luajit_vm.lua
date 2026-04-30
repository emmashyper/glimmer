-- Glimmer: minimal LuaJIT 2.1 bytecode loader + interpreter (no loadstring).
-- Matches BCDUMP v2 as written by LuaJIT (strip + 32-bit / non-FR2).
-- Many opcodes are NYI; extend the dispatch as needed for your scripts.

local glimmer_luajit_vm = {}
local bit = require("bit") or bit32
if not bit then
  error("glimmer: need bit library (LuaJIT bit or bit32)")
end

local band, bor, bxor, rshift, lshift = bit.band, bit.bor, bit.bxor, bit.rshift, bit.lshift

-- Bytecode op order must match vendor LuaJIT lj_bc.h BCDEF
local BC = {
  ISLT=0,ISGE=1,ISLE=2,ISGT=3,ISEQV=4,ISNEV=5,ISEQS=6,ISNES=7,ISEQN=8,ISNEN=9,ISEQP=10,ISNEP=11,
  ISTC=12,ISFC=13,IST=14,ISF=15,ISTYPE=16,ISNUM=17,MOV=18,NOT=19,UNM=20,LEN=21,
  ADDVN=22,SUBVN=23,MULVN=24,DIVVN=25,MODVN=26,ADDNV=27,SUBNV=28,MULNV=29,DIVNV=30,MODNV=31,
  ADDVV=32,SUBVV=33,MULVV=34,DIVVV=35,MODVV=36,POW=37,CAT=38,
  KSTR=39,KCDATA=40,KSHORT=41,KNUM=42,KPRI=43,KNIL=44,UGET=45,USETV=46,USETS=47,USETN=48,USETP=49,UCLO=50,FNEW=51,
  TNEW=52,TDUP=53,GGET=54,GSET=55,TGETV=56,TGETS=57,TGETB=58,TGETR=59,TSETV=60,TSETS=61,TSETB=62,TSETM=63,TSETR=64,
  CALLM=65,CALL=66,CALLMT=67,CALLT=68,ITERC=69,ITERN=70,VARG=71,ISNEXT=72,RETM=73,RET=74,RET0=75,RET1=76,
  FORI=77,JFORI=78,FORL=79,IFORL=80,JFORL=81,ITERL=82,IITERL=83,JITERL=84,LOOP=85,ILOOP=86,JLOOP=87,JMP=88,
  FUNCF=89,IFUNCF=90,JFUNCF=91,FUNCV=92,IFUNCV=93,JFUNCV=94,FUNCC=95,FUNCCW=96
}
local BCDUMP_KGC_CHILD, BCDUMP_KGC_TAB, BCDUMP_KGC_STR = 0, 1, 5
local BCDUMP_KTAB_NIL, BCDUMP_KTAB_FALSE, BCDUMP_KTAB_TRUE, BCDUMP_KTAB_INT, BCDUMP_KTAB_NUM, BCDUMP_KTAB_STR = 0,1,2,3,4,5
local BCBIAS_J = 0x8000

local KPRI_NIL, KPRI_FALSE, KPRI_TRUE = 0, 1, 2

local function s16(u)
  u = band(u, 0xffff)
  if u >= 0x8000 then return u - 0x10000 end
  return u
end

local function decode_ins(i)
  local op = band(i, 0xff)
  local a = band(rshift(i, 8), 0xff)
  local b = band(rshift(i, 24), 0xff)
  local c = band(rshift(i, 16), 0xff)
  local d = band(rshift(i, 16), 0xffff)
  return op, a, b, c, d
end

local function kgc_idx_from_d(d)
  return -s16(d) - 1
end

--- IEEE754 double from two little-endian uint32 (LuaJIT knum layout).
local function knum_double(lo, hi)
  local sign = (hi >= 0x80000000) and -1 or 1
  local e = band(rshift(hi, 20), 0x7ff)
  local fh = band(hi, 0xfffff)
  if e == 0 then return 0 * sign end
  if e == 2047 then return sign * (1/0) end
  local mant = fh * 4294967296 + lo
  return sign * (mant + 2^52) * 2^(e - 1023 - 52)
end

local function read_byte(s, pos)
  return string.byte(s, pos), pos + 1
end

local function read_uleb128(s, pos)
  local v, sh = 0, 0
  while true do
    local b
    b, pos = read_byte(s, pos)
    v = v + band(b, 127) * lshift(1, sh)
    if b < 128 then break end
    sh = sh + 7
  end
  return v, pos
end

local function read_uleb128_33(s, pos)
  local b
  b, pos = read_byte(s, pos)
  local v = rshift(b, 1)
  if v >= 0x40 then
    local sh = -1
    v = band(v, 0x3f)
    repeat
      b, pos = read_byte(s, pos)
      v = bor(v, lshift(band(b, 0x7f), sh + 7))
      sh = sh + 7
    until b < 0x80
  end
  return v, pos
end

local function read_mem(s, pos, len)
  return string.sub(s, pos, pos + len - 1), pos + len
end

local function read_ktabk(s, pos, nil_marker_tab)
  local tp, v
  tp, pos = read_uleb128(s, pos)
  if tp >= BCDUMP_KTAB_STR then
    local len = tp - BCDUMP_KTAB_STR
    local raw
    raw, pos = read_mem(s, pos, len)
    return raw, pos
  elseif tp == BCDUMP_KTAB_INT then
    return read_uleb128(s, pos)
  elseif tp == BCDUMP_KTAB_NUM then
    local lo, hi
    lo, pos = read_uleb128(s, pos)
    hi, pos = read_uleb128(s, pos)
    return knum_double(lo, hi), pos
  elseif tp == BCDUMP_KTAB_NIL then
    return nil, pos
  elseif tp == BCDUMP_KTAB_FALSE then
    return false, pos
  elseif tp == BCDUMP_KTAB_TRUE then
    return true, pos
  elseif nil_marker_tab and tp == BCDUMP_KTAB_NIL then
    return nil_marker_tab, pos
  end
  error("glimmer vm: NYI ktabk type "..tostring(tp))
end

local function read_ktab(s, pos)
  local narray, nhash
  narray, pos = read_uleb128(s, pos)
  nhash, pos = read_uleb128(s, pos)
  local t = {}
  for i = 1, narray do
    local v
    v, pos = read_ktabk(s, pos, nil)
    t[i] = v
  end
  for _ = 1, nhash do
    local k, v
    k, pos = read_ktabk(s, pos, nil)
    v, pos = read_ktabk(s, pos, nil)
    t[k] = v
  end
  return t, pos
end

local function read_proto_blob(s, blob_pos, blob_end, proto_stack)
  local pos = blob_pos
  local flags, numparams, framesize, sizeuv
  flags, pos = read_byte(s, pos)
  numparams, pos = read_byte(s, pos)
  framesize, pos = read_byte(s, pos)
  sizeuv, pos = read_byte(s, pos)
  local sizekgc, sizekn, sizebc_raw
  sizekgc, pos = read_uleb128(s, pos)
  sizekn, pos = read_uleb128(s, pos)
  sizebc_raw, pos = read_uleb128(s, pos)
  local sizebc = sizebc_raw + 1

  local bc = {}
  for j = 1, sizebc do
    local b0, b1, b2, b3
    b0, pos = read_byte(s, pos)
    b1, pos = read_byte(s, pos)
    b2, pos = read_byte(s, pos)
    b3, pos = read_byte(s, pos)
    bc[j] = bor(b0, lshift(b1, 8), lshift(b2, 16), lshift(b3, 24))
  end

  local uv = {}
  for j = 1, sizeuv do
    local lo, hi
    lo, pos = read_byte(s, pos)
    hi, pos = read_byte(s, pos)
    uv[j] = bor(lo, lshift(hi, 8))
  end

  local kgc = {}
  for i = 1, sizekgc do
    local tp
    tp, pos = read_uleb128(s, pos)
    if tp >= BCDUMP_KGC_STR then
      local len = tp - BCDUMP_KGC_STR
      local raw
      raw, pos = read_mem(s, pos, len)
      kgc[i] = raw
    elseif tp == BCDUMP_KGC_TAB then
      local tab
      tab, pos = read_ktab(s, pos)
      kgc[i] = tab
    elseif tp == BCDUMP_KGC_CHILD then
      local child = table.remove(proto_stack)
      if not child then error("glimmer vm: CHILD underflow") end
      kgc[i] = child
    else
      error("glimmer vm: NYI kgc type "..tostring(tp))
    end
  end

  local knum = {}
  for i = 1, sizekn do
    local b_first
    b_first, pos = read_byte(s, pos)
    pos = pos - 1
    local isnum = band(b_first, 1)
    local lo
    lo, pos = read_uleb128_33(s, pos)
    if isnum ~= 0 then
      local hi
      hi, pos = read_uleb128(s, pos)
      knum[i] = knum_double(lo, hi)
    else
      knum[i] = lo
    end
  end

  if pos ~= blob_end + 1 then
    error("glimmer vm: proto blob length mismatch "..tostring(pos).." vs "..tostring(blob_end))
  end

  return {
    flags = flags,
    numparams = numparams,
    framesize = framesize,
    sizeuv = sizeuv,
    bc = bc,
    uv = uv,
    kgc = kgc,
    knum = knum,
    sizebc = sizebc,
  }
end

local function parse_bc_dump(bin, globals)
  local pos = 1
  local b1, b2, b3, ver
  b1, pos = read_byte(bin, pos)
  b2, pos = read_byte(bin, pos)
  b3, pos = read_byte(bin, pos)
  ver, pos = read_byte(bin, pos)
  if b1 ~= 0x1b or b2 ~= 0x4c or b3 ~= 0x4a then
    error("glimmer vm: not a LuaJIT bytecode dump")
  end
  if ver ~= 2 then
    error("glimmer vm: unsupported dump version "..tostring(ver))
  end
  local flags
  flags, pos = read_uleb128(bin, pos)
  if band(flags, 8) ~= 0 then
    error("glimmer vm: FR2 bytecode not supported in this interpreter")
  end
  if band(flags, 4) ~= 0 then
    error("glimmer vm: FFI bytecode NYI")
  end
  local strip = band(flags, 2) ~= 0
  if not strip then
    local nlen
    nlen, pos = read_uleb128(bin, pos)
    pos = pos + nlen
  end

  local proto_stack = {}
  while pos <= #bin do
    local z = string.byte(bin, pos)
    if z == 0 then
      pos = pos + 1
      break
    end
    local len
    len, pos = read_uleb128(bin, pos)
    if len == 0 then break end
    local blob_end = pos + len - 1
    local pt = read_proto_blob(bin, pos, blob_end, proto_stack)
    pos = blob_end + 1
    table.insert(proto_stack, pt)
  end

  if #proto_stack ~= 1 then
    error("glimmer vm: expected one root proto, got "..tostring(#proto_stack))
  end
  return proto_stack[1], globals or _G
end

local function pri_const(idx)
  if idx == KPRI_NIL then return nil end
  if idx == KPRI_FALSE then return false end
  if idx == KPRI_TRUE then return true end
  error("glimmer vm: bad KPRI "..tostring(idx))
end

local function make_closure(proto, uv_cells)
  return { glimmer_closure = true, p = proto, uv = uv_cells }
end

local function resolve_uv_desc(desc, base, stack, open_uv)
  local is_ro = band(desc, 0x8000) ~= 0
  local v = band(desc, 0xff)
  local tr = rshift(desc, 8)
  if tr == 0 then
    -- local register v on current stack frame
    local slot = base + v
    return function(x)
      if x ~= nil then stack[slot] = x end
      return stack[slot]
    end
  end
  error("glimmer vm: NYI upvalue outer chain (tr="..tostring(tr)..")")
end

local function run_proto(root_proto, _G)
  local stack = {}
  local open_uv = {}

  local function vm_call(closure, nargs, nwant, caller_pc_ref, caller_base, caller_vals, ret_slot)
    local proto = closure.p
    local uv_cells = closure.uv
    local base = #stack + 1
    -- Reserve frame: slot base is function value for LuaJIT layout
    stack[base] = closure
    for i = 1, proto.framesize do
      stack[base + i] = nil
    end
    -- Copy args (LuaJIT: first fixed arg at base+1)
    for i = 1, nargs do
      if i <= proto.numparams then
        stack[base + i] = caller_vals[caller_base + i]
      end
    end

    local pc = 1
    local bc = proto.bc

    while pc <= proto.sizebc do
      local ins = bc[pc]
      local op, a, rb, rc, d = decode_ins(ins)

      if op == BC.FUNCF or op == BC.FUNCV or op == BC.NOT then
        pc = pc + 1
      elseif op == BC.MOV then
        stack[base + a] = stack[base + s16(d)]
        pc = pc + 1
      elseif op == BC.KSHORT then
        stack[base + a] = s16(d)
        pc = pc + 1
      elseif op == BC.KNUM then
        stack[base + a] = proto.knum[d + 1]
        pc = pc + 1
      elseif op == BC.KPRI then
        stack[base + a] = pri_const(d)
        pc = pc + 1
      elseif op == BC.KSTR then
        local kidx = kgc_idx_from_d(d) + 1
        stack[base + a] = proto.kgc[kidx]
        pc = pc + 1
      elseif op == BC.KNIL then
        for r = a, band(rb, 0xff) do
          stack[base + r] = nil
        end
        pc = pc + 1
      elseif op == BC.UGET then
        stack[base + a] = uv_cells[d + 1]()
        pc = pc + 1
      elseif op == BC.USETV then
        uv_cells[a + 1](stack[base + rb])
        pc = pc + 1
      elseif op == BC.GGET then
        local k = proto.kgc[kgc_idx_from_d(d) + 1]
        stack[base + a] = _G[k]
        pc = pc + 1
      elseif op == BC.GSET then
        local k = proto.kgc[kgc_idx_from_d(d) + 1]
        _G[k] = stack[base + a]
        pc = pc + 1
      elseif op == BC.ADDVV then
        stack[base + a] = stack[base + rb] + stack[base + rc]
        pc = pc + 1
      elseif op == BC.ADDVN then
        stack[base + a] = stack[base + rb] + proto.knum[rc + 1]
        pc = pc + 1
      elseif op == BC.SUBVV then
        stack[base + a] = stack[base + rb] - stack[base + rc]
        pc = pc + 1
      elseif op == BC.MULVV then
        stack[base + a] = stack[base + rb] * stack[base + rc]
        pc = pc + 1
      elseif op == BC.DIVVV then
        stack[base + a] = stack[base + rb] / stack[base + rc]
        pc = pc + 1
      elseif op == BC.UNM then
        stack[base + a] = -stack[base + s16(d)]
        pc = pc + 1
      elseif op == BC.NOT then
        local v = stack[base + s16(d)]
        stack[base + a] = (not v)
        pc = pc + 1
      elseif op == BC.JMP then
        pc = pc + 1 + (s16(d) - BCBIAS_J)
      elseif op == BC.FNEW then
        local child = proto.kgc[kgc_idx_from_d(d) + 1]
        local cells = {}
        for ui = 1, child.sizeuv do
          cells[ui] = resolve_uv_desc(child.uv[ui], base, stack, open_uv)
        end
        stack[base + a] = make_closure(child, cells)
        pc = pc + 1
      elseif op == BC.UCLO then
        pc = pc + 1 + (s16(d) - BCBIAS_J)
      elseif op == BC.CALL then
        local func = stack[base + a]
        local nargs = rc - 1
        local nwant = rb - 1
        if type(func) == "function" then
          local args = {}
          for i = 1, nargs do args[i] = stack[base + a + i] end
          local res = { func(unpack(args)) }
          for i = 1, nwant do
            stack[base + a + i - 1] = res[i]
          end
          pc = pc + 1
        elseif func and func.glimmer_closure then
          local results = {}
          vm_call(func, nargs, nwant, pc, base, stack, results)
          for i = 1, nwant do
            stack[base + a + i - 1] = results[i]
          end
          pc = pc + 1
        else
          error("glimmer vm: CALL to non-function")
        end
      elseif op == BC.CALLT then
        local func = stack[base + a]
        local nargs = s16(d) - 1
        if func and func.glimmer_closure then
          local vals = {}
          for i = 1, nargs do vals[i] = stack[base + a + i] end
          vm_call(func, nargs, -1, pc, 0, vals, {})
          return
        end
        error("glimmer vm: NYI CALLT for non-closure")
      elseif op == BC.RET0 then
        return
      elseif op == BC.RET1 then
        local v = stack[base + a]
        caller_vals[ret_slot.base + ret_slot.idx] = v
        return
      elseif op == BC.RET then
        local n = d - 1
        for i = 1, n do
          caller_vals[ret_slot.base + ret_slot.idx + i - 1] = stack[base + a + i - 1]
        end
        return
      else
        error(("glimmer vm: NYI opcode %d at pc %d"):format(op, pc))
      end
    end
  end

  local root_cells = {}
  for ui = 1, root_proto.sizeuv do
    root_cells[ui] = resolve_uv_desc(root_proto.uv[ui], 1, stack, open_uv)
  end
  local root_cl = make_closure(root_proto, root_cells)
  vm_call(root_cl, 0, 0, nil, 1, stack, { base = 1, idx = 1 })
end

function glimmer_luajit_vm.exec(bin, globals)
  local root, g = parse_bc_dump(bin, globals)
  run_proto(root, g)
end

return glimmer_luajit_vm
