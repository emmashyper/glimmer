-- BC_VARG present; recording may still abort for some call shapes.
local function va(...)
    return select(1, ...)
end

return va(42)
