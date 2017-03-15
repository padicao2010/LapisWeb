local lapis = require("lapis")
local app_helpers = require("lapis.application")
local validate = require("lapis.validate")

local capture_errors, yield_error = app_helpers.capture_errors, app_helpers.yield_error
local assert_error = app_helpers.assert_error

local Model = require("lapis.db.model").Model
local MProject = Model:extend("tr_project", {
    primary_key = "pid"
})
local MFile = Model:extend("tr_file", {
    primary_key = "fid"
})
local MLine = Model:extend("tr_line", {
    primary_key = { "fid", "lid" }
})
local MLog = Model:extend("tr_log", {
    primary_key = { "logid" }
})

local function analysisFile(file)
    local offset = 1
    local line = 1
    local orig
    local count = 0
    
    while true do
        local eols, eole = string.find(file.ftext, "\r?\n", offset)
        local l = string.sub(file.ftext, offset, eols and eols - 1)
        local s = string.match(l, "\"(.*)\"")
        if s then
            if not orig then
                orig = string.gsub(s, "^(%s+)", "")
            else
                assert_error(MLine:create({
                    lid = line,
                    fid = file.fid,
                    pos = offset,
                    orgstr = orig,
                    trstr = s
                }))
                count = count + 1
                orig = nil
            end
        end
        if not eols then
            break
        else
            offset = eole + 1
            line = line + 1
        end
    end
    return count
end

local app = lapis.Application()
app:enable("etlua")
app.layout = require "views.layout"

app:get("index", "/", function(self)
    self.projects = MProject:select()
    return { render = true }
end)

app:get("new", "/new", function(self)
    return { render = "newproject" }
end)

app:post("new", "/new", capture_errors(function(self)
    validate.assert_valid(self.params, {
        { "name", exists = true, min_length = 1, max_length = 22 },
        { "desc", exists = true, min_length = 1, max_length = 254 },
    })
    
    assert_error(MProject:create({ pname = self.params.name, pdesc = self.params.desc }))
    return { redirect_to = self:url_for("index") }
end))

app:get("project", "/project/:pid", capture_errors(function(self)
    validate.assert_valid(self.params, {
        { "pid", exists = true, is_integer = true },
    })
    self.project = assert_error(MProject:find(self.params.pid))
    self.files = assert_error(MFile:select(
        "where pid = ?", self.params.pid,
        { fields = "pid, fid, fname, fline"} ))
    
    return { render = true }
end))

app:post("project", "/project/:pid", capture_errors(function(self)
    validate.assert_valid(self.params, {
        { "pid", exists = true, is_integer = true },
        { "uploadfile", exists = true, is_file = true },
    })
    local upfile = self.params.uploadfile
    local file = assert_error(MFile:create({
        pid = self.params.pid,
        fname = upfile.filename,
        ftext = upfile.content
    }))
    
    local count = analysisFile(file)
    if count > 0 then
        file.fline = count 
        file:update("fline")
    end

    return { redirect_to = self:url_for("project", self.params) }
end))

app:get("file", "/file/:pid/:fid", capture_errors(function(self)
    validate.assert_valid(self.params, {
        { "pid", exists = true, is_integer = true },
        { "fid", exists = true, is_integer = true },
    })
    
    local file = assert_error(MFile:find(self.params.fid))
    local lines = assert_error(MLine:select("where fid = ?", file.fid))
    
    return { render = true }
}

return app
