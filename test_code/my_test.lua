
--! cfg low
local function a()
    if 1 == 1 then
        print("Easy example")
    end
end


--! cfg high
local function b()
    if 1 == 1 then
        print("High example")
    end

    if 2 == 2 then
        print("High example 2")
    end

    if 3 == 3 then
        print("High example 3")
    end

    if 4 == 3 then
        print("High example 4")
    end
end

a()

b()