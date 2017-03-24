local cjson = require "json"
local plfile = require "pl.file"

local function getLine(content, offset)
    local eols, eole = string.find(content, "\r?\n", offset)
    local l = string.sub(content, offset, eols and eols - 1)
    local eol = eols and string.sub(content, eols, eole)
    offset = eols and eole + 1 or #content + 1
    
    return l, eol, offset
end

local function mergeRenpy(dir, ufile)
    local updates = cjson.decode(assert(plfile.read(ufile)))
    
    local index = 1
    while index <= #updates do
        local file = updates[index].fname
        print(file)
        
        local path = dir .. "/" .. file
        local content = assert(plfile.read(path))
        local output = assert(io.open(path, "w"))
        local line = 1
        local offset = 1
        
        while index <= #updates do
            local u = updates[index]
            if u.fname ~= file then
                break
            end
            local ls, eol, noff
            for i = line, u.lid - 1 do
                ls, eol, noff = getLine(content, offset)
                assert(eol and noff)
                output:write(ls)
                output:write(eol)
                offset = noff
            end
            
            ls, eol, noff = getLine(content, offset)
            local strs, stre = string.find(ls, "\".*\"")
            assert(strs and stre)
            output:write(string.sub(ls, 1, strs))
            output:write(u.trstr)
            output:write(string.sub(ls, stre))
            
            if eol then
                output:write(eol)
            end
            offset = noff
            
            line = u.lid + 1
            index = index + 1
        end
        
        output:write(string.sub(content, offset))
        output:close()
    end
end

local indir = arg[1]
local updatefile = arg[2]

if indir == nil or updatefile == nil then
    io.stderr:write("lua mergerpy.lua indir updatefile\n")
    os.exit(-1)
end

mergeRenpy(indir, updatefile)
