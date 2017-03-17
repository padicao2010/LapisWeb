local lapis = require("lapis")
local app_helpers = require("lapis.application")
local validate = require("lapis.validate")
local lfs = require("lfs")

local PER_PAGE = 10

local capture_errors, yield_error = app_helpers.capture_errors, app_helpers.yield_error
local assert_error = app_helpers.assert_error
local respond_to = app_helpers.respond_to

local Model = require("lapis.db.model").Model
local MProject = Model:extend("tr_project", {
    primary_key = "pid"
})
local MFile = Model:extend("tr_file", {
    primary_key = "fid"
})
local MFileText = Model:extend("tr_filetext", {
    primary_key = "fid"
})
local MLine = Model:extend("tr_line", {
    primary_key = { "fid", "lid" }
})
local MLog = Model:extend("tr_log", {
    primary_key = { "logid" }
})

local function analysisFile(file, content)
    local offset = 1
    local line = 1
    local orig
    local count = 0
    local ntred = 0
    local lastline
    local desc
    
    while true do
        local eols, eole = string.find(content, "\r?\n", offset)
        local l = string.sub(content, offset, eols and eols - 1)
        l = string.gsub(l, "^(%s+)", "")
        local s = string.match(l, "\"(.*)\"")
        if s then
            if not orig then
                desc = lastline
                orig = l
            else
                assert_error(MLine:create({
                    lid = line,
                    fid = file.fid,
                    pos = offset,
                    ldesc = desc or "",
                    orgstr = orig,
                    trstr = s,
                    nupd = (s ~= "") and 1 or 0
                }))
                if s ~= "" then
                    ntred = ntred + 1
                end
                count = count + 1
                orig = nil
                desc = nil
            end
        end
        if l ~= "" then
            lastline = #l < 254 and l or (string.sub(l, 1, 16) .. "...")
        end
        if not eols then
            break
        else
            offset = eole + 1
            line = line + 1
        end
    end
    return count, ntred
end

local app = lapis.Application()
app:enable("etlua")
app.layout = require "views.layout"

app.handle_error = function(self, err, trace)
    return { render = "error", status = 404 }
end

app:get("index", "/", function(self)
    self.projects = MProject:select()
    return { render = true }
end)

app:get("register", "/register", function(self)
    self.reg = true
    return { render = "user" }
end)

app:get("login", "/login", function(self)
    return { render = "user" }
end)

app:post("new", "/new", capture_errors(function(self)
    validate.assert_valid(self.params, {
        { "name", exists = true, min_length = 1, max_length = 44 },
        { "desc", exists = true, min_length = 1, max_length = 254 },
    })
    
    local project = assert_error(MProject:create({ pname = self.params.name, pdesc = self.params.desc }))
    
    lfs.mkdir("download/" .. project.pid)
    return { redirect_to = self:url_for("index") }
end))

app:get("project", "/project/p:pid(/page:pageid)", capture_errors(function(self)
    validate.assert_valid(self.params, {
        { "pid", exists = true, is_integer = true },
    })
    self.project = assert_error(MProject:find(self.params.pid))
        
    local paginated = MFile:paginated("where pid = ? order by fid asc", self.project.pid, { per_page = PER_PAGE })
    self.pageIndex = tonumber(self.params.pageid) or 1
    self.files = paginated:get_page(self.pageIndex)
    self.pageCount = math.ceil(self.project.pfile / PER_PAGE)
    
    return { render = true }
end))

app:post("project", "/project/p:pid(/page:pageid)", capture_errors(function(self)
    validate.assert_valid(self.params, {
        { "pid", exists = true, is_integer = true },
        { "desc", max_length = 254 },
        { "uploadfile", exists = true, is_file = true },
    })
    local upfile = self.params.uploadfile
    local project = assert_error(MProject:find(self.params.pid))
    local file = assert_error(MFile:create({
        pid = self.params.pid,
        fname = upfile.filename,
        fdesc = self.params.desc,
    }))
    assert_error(MFileText:create({
        fid = file.fid,
        ftext = upfile.content
    }))

    local count, ntred = analysisFile(file, upfile.content)
    if count > 0 then
        file.fline = count
        file.ntred = ntred 
        assert(file:update("fline", "ntred"))
    end
    
    project.pfile = project.pfile + 1
    project.pline = project.pline + count
    project.ntred = project.ntred + ntred
    assert_error(project:update("pfile", "pline", "ntred"))

    return { redirect_to = self:url_for("project", self.params) }
end))

app:get("file", "/file/p:pid/f:fid(/page:pageid)", capture_errors(function(self)
    validate.assert_valid(self.params, {
        { "pid", exists = true, is_integer = true },
        { "fid", exists = true, is_integer = true },
    })
    
    self.project = assert_error(MProject:find(self.params.pid))
    self.file = assert_error(MFile:find(self.params.fid))
    local paginated = MLine:paginated("where fid = ? order by lid asc", self.file.fid, { per_page = PER_PAGE })
    self.pageIndex = tonumber(self.params.pageid) or 1
    self.lines = paginated:get_page(self.pageIndex)
    self.pageCount = math.ceil(self.file.fline / PER_PAGE)
    if self.pageIndex <= 0 or self.pageIndex > self.pageCount then
        return { redirect_to = self:url_for("file", self.file) }
    else
        return { render = true }
    end
end))

app:post("file", "/file/p:pid/f:fid(/page:pageid)", capture_errors(function(self)
    validate.assert_valid(self.params, {
        { "pid", exists = true, is_integer = true },
        { "fid", exists = true, is_integer = true },
        { "pageid", exists = true, is_integer = true },
    })
    
    local pid = self.params.pid
    local fid = self.params.fid
    local pageid = tonumber(self.params.pageid) or 1
    
    local ntred = 0
    
    for k, v in pairs(self.params) do
        local lid = string.match(k, "line(%d+)")
        if lid then
            lid = tonumber(lid)
            v = string.gsub(v, "\r", "")
            local line = assert_error(MLine:find(fid, lid))
            if line and line.trstr ~= v then
                assert_error(MLog:create({
                    fid = fid,
                    lid = lid,
                    bfstr = v
                }))
                line.nupd = line.nupd + 1
                if line.nupd == 1 then
                    ntred = ntred + 1
                end
                
                line.trstr = v
                line:update("nupd", "trstr")
            end
        end
    end
    
    if ntred > 0 then
        local file = assert_error(MFile:find(fid))
        file.ntred = file.ntred + ntred
        assert_error(file:update("ntred"))
        local project = assert_error(MProject:find(pid))
        project.ntred = project.ntred + ntred
        assert_error(project:update("ntred"))
    end
    
    local t = {
        pid = pid,
        fid = fid,
        pageid = pageid + 1
    }
    return { redirect_to = self:url_for("file", t) }
end))

app:get("merge", "/merge/p:pid/f:fid", capture_errors(function(self)
    validate.assert_valid(self.params, {
        { "pid", exists = true, is_integer = true },
        { "fid", exists = true, is_integer = true },
    })
    
    local fid = self.params.fid
    local file = MFile:find(fid)
    local filetext = MFileText:find(fid)
    local content = filetext.ftext
    local lines = MLine:select("where fid = ? order by lid asc", fid)
    
    local offset = 1
    local outp = string.format("download/%d/%s", file.pid, file.fname)
    local output = assert(io.open(outp, "w"))
    for _, l in ipairs(lines) do
        if l.pos > offset then
            output:write(string.sub(content, offset, l.pos - 1))
        end
        local eols, eole = string.find(content, "\r?\n", l.pos)
        local s = string.sub(content, l.pos, eols and eols - 1)
        
        local strs, stre = string.find(s, "\".*\"")
        output:write(string.sub(s, 1, strs))
        output:write(l.trstr)
        output:write(string.sub(s, stre))
        
        if eols then
            output:write(string.sub(content, eols, eole))
            offset = eole + 1
        else
            break
        end
    end
    output:close()
    
    return { redirect_to = "/" .. outp }
end))

return app
