-- No FNEW/UCLO inside `add`: straightforward JIT-friendly bytecode shape.
local function add(a, b)
    return a + b
end

return add(1, 2)
