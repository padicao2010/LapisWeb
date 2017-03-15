local lapis = require("lapis")
local lfs = require("lfs")

local function getProjects()
    local t = {}
    for d in lfs.dir("projects") do
        table.insert(t, d)
    end
    return t
end

local app = lapis.Application()
app:enable("etlua")
app.layout = require "views.layout"

app:get("/", function(self)
    self.projects = getProjects()
    return { render = "index" }
end)

return app
