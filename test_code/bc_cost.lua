local function very_expensive_function()
    
    local tbl = {}
    
    for i = 1, 1000000 do
        tbl[i] = i
    end

    return tbl
end

local function transitive_expensive_function()
    return very_expensive_function()
end

local function cheap_function()
    return 1 + 1
end