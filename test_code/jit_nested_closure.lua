-- `outer` allocates an inner closure -> FNEW in outer's proto.
local function outer()
    return function()
        return 1
    end
end

return outer()()
