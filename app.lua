local lapis = require("lapis")

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

app:get("/", function(self)
    self.nproj = MProject:count()
    self.projects = MProject:select()
    return { render = "index" }
end)

return app
