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

local app = lapis.Application()
app:enable("etlua")
app.layout = require "views.layout"

app:get("index", "/", function(self)
    self.nproj = MProject:count()
    self.projects = MProject:select()
    return { render = "index" }
end)

app:get("new", "/new", function(self)
    return { render = "newproject" }
end)

app:post("new", "/new", capture_errors(function(self)
    validate.assert_valid(self.params, {
        { "name", exists = true, min_length = 1, max_length = 22 },
        { "desc", exists = true, min_length = 1, max_length = 254 },
    })
    
    assert(MProject:create({ pname = self.params.name, pdesc = self.params.desc }))
    return { redirect_to = self:url_for("index") }
end))

return app
