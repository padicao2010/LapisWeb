local lapis = require("lapis")
local app_helpers = require("lapis.application")
local validate = require("lapis.validate")
local encoding = require("lapis.util.encoding")
local lfs = require("lfs")
local date = require("date")
local db = require("lapis.db")
local util = require("lapis.util")

local config = require("lapis.config").get()

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
local MLine = Model:extend("tr_line", {
    primary_key = { "fid", "lid" }
})
local MLog = Model:extend("tr_log", {
    primary_key = "logid"
})
local MUser = Model:extend("tr_user", {
    primary_key = "uid"
})
local MDict = Model:extend("tr_dict", {
    primary_key = "did"
})
local MDictLog = Model:extend("tr_dictlog", {
    primary_key = "dlogid"
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
                local ldata = assert_error(MLine:create({
                    lid = line,
                    fid = file.fid,
                    ldesc = desc or "",
                    orgstr = orig,
                    trstr = ""
                }))
                if s ~= "" then
                    local logdata = assert_error(MLog:create({
                        fid = file.fid,
                        lid = ldata.lid,
                        uid = 1,
                        bfstr = s
                    }))
                    ldata.nupd = 1
                    ldata.acceptlog = logdata.logid
                    ldata.trstr = s
                    assert_error(ldata:update("nupd", "acceptlog", "trstr"))
                        
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

app:before_filter(function(self)
    local id = self.session.user_id
        
    if id then
        self.current_user = MUser:find(id)
        if self.current_user and id == 0 then
            self.admin_state = true
        end
    end
end)

app.cookie_attributes = function(self)
  local expires = date(true):adddays(30):fmt("${http}")
  return "Expires=" .. expires .. "; Path=/; HttpOnly"
end

app:get("index", "/", function(self)
    self.projects = MProject:select()
    return { render = true }
end)

local function doLogin(req, user)
    req.session.user_id = user.uid
end

local function doLogout(req, user)
    req.session.user_id = nil
end

app:get("register", "/register", function(self)
    if self.current_user then
        return { redirect_to = self:url_for("index") }
    end
    
    self.reg = true
    return { render = "user" }
end)

app:post("register", "/register", capture_errors(function(self)
    validate.assert_valid(self.params, {
        { "username", exists = true },
        { "password", exists = true }
    })
    
    local user = assert_error(MUser:create({
        uname = self.params.username,
        upasswd = encoding.encode_base64(encoding.hmac_sha1(config.secret, self.params.password))
    }))
    
    doLogin(self, user)
    
    return { redirect_to = self:url_for("index") }
end))

app:get("login", "/login", function(self)
    if self.current_user then
        return { redirect_to = self:url_for("index") }
    end
    
    return { render = "user" }
end)

app:post("login", "/login", capture_errors(function(self)
    validate.assert_valid(self.params, {
        { "username", exists = true },
        { "password", exists = true }
    })
    
    local user = assert_error(MUser:find({
        uname = self.username,
        upasswd = encoding.encode_base64(encoding.hmac_sha1(config.secret, self.params.password)),
    }))
    
    doLogin(self, user)
    
    return { redirect_to = self:url_for("index") }
end))

app:get("logout", "/logout", function(self)
    if self.current_user then
        doLogout(self, self.current_user)
    end
    
    return { redirect_to = self:url_for("index") }
end)

app:post("new", "/project/new", capture_errors(function(self)
    validate.assert_valid(self.params, {
        { "name", exists = true, min_length = 1, max_length = 44 },
        { "desc", exists = true, min_length = 1, max_length = 254 },
    })
    
    assert_error(self.admin_state, "创建新项目必须管理员权限！")
    
    local project = assert_error(MProject:create({ pname = self.params.name, pdesc = self.params.desc }))
    
    lfs.mkdir("download/" .. project.pid)
    return { redirect_to = self:url_for("index") }
end))

app:get("project", "/project/p:pid/files(/page:pageid)", capture_errors(function(self)
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

app:post("project", "/project/p:pid/files(/page:pageid)", capture_errors(function(self)
    validate.assert_valid(self.params, {
        { "pid", exists = true, is_integer = true },
        { "desc", max_length = 254 },
        { "uploadfile", exists = true, is_file = true },
    })
    
    assert_error(self.admin_state, "上传文件必须管理员权限！")
    
    local upfile = self.params.uploadfile
    local project = assert_error(MProject:find(self.params.pid))
    local file = assert_error(MFile:create({
        pid = self.params.pid,
        fname = upfile.filename,
        fdesc = self.params.desc,
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
    
    ngx.shared.filepn:flush_all()

    return { redirect_to = self:url_for("project", self.params) }
end))

app:get("file", "/project/p:pid/file/f:fid(/page:pageid)", capture_errors(function(self)
    validate.assert_valid(self.params, {
        { "pid", exists = true, is_integer = true },
        { "fid", exists = true, is_integer = true },
    })
    
    local pid = self.params.pid
    self.project = assert_error(MProject:find(pid))
    self.file = assert_error(MFile:find(self.params.fid))
    local paginated = MLine:paginated("where fid = ? order by lid asc", self.file.fid, { per_page = PER_PAGE })
    self.pageIndex = tonumber(self.params.pageid) or 1
    self.pageCount = math.ceil(self.file.fline / PER_PAGE)
    self.lines = paginated:get_page(self.pageIndex)
    for _, l in ipairs(self.lines) do
        l.pid = pid
    end

    local lkey = string.format("p%df%d", self.params.pid, self.params.fid)
    local filepn = ngx.shared.filepn
    
    local prevkey = lkey .. "p"
    local prevfid = filepn:get(prevkey)
    if not prevfid then
        local prevfile = assert_error(db.select("MAX(fid) FROM tr_file WHERE pid = ? and fid < ?",
            self.params.pid, self.params.fid))
        prevfid = tonumber(prevfile[1]["MAX(fid)"]) or -1
        filepn:set(prevkey, prevfid)
    end
    if prevfid > 0 then
        self.prevf = { pid = self.file.pid, fid = prevfid }
    end
    
    local nextkey = lkey .. "n"
    local nextfid = filepn:get(nextkey)
    if not nextfid then
        local nextfile = assert_error(db.select("MIN(fid) FROM tr_file WHERE pid = ? and fid > ?", 
            self.params.pid, self.params.fid))
        nextfid = tonumber(nextfile[1]["MIN(fid)"]) or -1
        filepn:set(nextkey, nextfid)
    end
    if nextfid > 0 then
        self.nextf = { pid = self.file.pid, fid = nextfid }
    end
    
    return { render = true }
end))

app:post("file", "/project/p:pid/file/f:fid(/page:pageid)", capture_errors(function(self)
    validate.assert_valid(self.params, {
        { "pid", exists = true, is_integer = true },
        { "fid", exists = true, is_integer = true },
    })
    
    assert_error(self.current_user, "翻译修改必须登录！")
    
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
                local log = assert_error(MLog:create({
                    fid = fid,
                    lid = lid,
                    uid = self.current_user.uid,
                    bfstr = v
                }))
                line.nupd = line.nupd + 1
                if line.nupd == 1 then
                    ntred = ntred + 1
                end
                
                line.acceptlog = log.logid
                line.trstr = v
                assert_error(line:update("nupd", "trstr", "acceptlog"))
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
    
    self.session.last_update = { pid = pid, fid = fid, pageid = pageid }
    
    local t = {
        pid = pid,
        fid = fid,
        pageid = pageid + 1
    }
    return { redirect_to = self:url_for("file", t) }
end))

app:get("log", "/project/p:pid/file/f:fid/line/l:lid", capture_errors(function(self)
    validate.assert_valid(self.params, {
        { "pid", exists = true, is_integer = true },
        { "fid", exists = true, is_integer = true },
        { "lid", exists = true, is_integer = true },
    })
    
    local pid, fid, lid = self.params.pid, self.params.fid, self.params.lid
    self.file = assert_error(MFile:find(fid))
    self.project = assert_error(MProject:find(pid))
    self.line = assert_error(MLine:find(fid, lid))
    
    self.logs = assert_error(db.select("l.logid, l.lid, l.bfstr, l.utime, u.uname FROM tr_log l, tr_user u WHERE l.fid = ? AND l.lid = ? AND l.uid = u.uid ORDER BY l.utime ASC", fid, lid))
    for _, log in ipairs(self.logs) do
        log.fid = fid
        log.pid = pid
    end
        
    return { render = true }
end))

app:get("setlog", "/project/p:pid/file/f:fid/line/l:lid/set/log:logid", capture_errors(function(self)
    validate.assert_valid(self.params, {
        { "pid", exists = true, is_integer = true },
        { "fid", exists = true, is_integer = true },
        { "lid", exists = true, is_integer = true },
    })
    
    assert_error(self.admin_state, "设置翻译项选择，需要管理员权限！")
    
    local line = assert_error(MLine:find(self.params.fid, self.params.lid))
    local log = assert_error(MLog:find(self.params.logid))
    line.acceptlog = log.logid
    line.trstr = log.bfstr
    assert_error(line:update("acceptlog", "trstr"))
    
    return { redirect_to = self:url_for("log", self.params) }
end))

app:get("dict", "/project/p:pid/dicts", capture_errors(function(self)
    validate.assert_valid(self.params, {
        { "pid", exists = true, is_integer = true }
    })
    
    local pid = self.params.pid
    self.project = assert_error(MProject:find(pid))
    self.dicts = assert_error(MDict:select("WHERE pid = ? ORDER BY did ASC", pid))
    for _, d in ipairs(self.dicts) do
        d.pid = pid
    end
    
    return { render = true }
end))

app:post("dict", "/project/p:pid/dicts", capture_errors(function(self)
    validate.assert_valid(self.params, {
        { "pid", exists = true, is_integer = true },
        { "sourceword", exists = true, max_length = 60 },
        { "destword", exists = true, max_length = 60 }
    })
    
    assert_error(self.current_user, "添加词典必须登录！")
    
    local dict = MDict:find({ pid = self.params.pid, sstr = self.params.sourceword })
    if dict then
        if dict.dstr ~= self.params.destword then
            dict.dstr = self.params.destword
            dict:update("dstr")
        end
    else
        dict = assert_error(MDict:create({ pid = self.params.pid, 
            sstr = self.params.sourceword,
            dstr = self.params.destword }))
    end
    
    local log = assert_error(MDictLog:create({
        did = dict.did,
        uid = self.current_user.uid,
        ndstr = self.params.destword
    }))
    
    dict.acceptlog = log.dlogid
    assert_error(dict:update("acceptlog"))
        
    return { redirect_to = self:url_for("dict", self.params) }
end))

app:get("dictlog", "/project/p:pid/dict/d:did", capture_errors(function(self)
    validate.assert_valid(self.params, {
        { "pid", exists = true, is_integer = true },
        { "did", exists = true, is_integer = true },
    })
    
    local pid = self.params.pid
    self.project = assert_error(MProject:find(pid))
    self.dict = assert_error(MDict:find(self.params.did))
    self.dictlogs = assert_error(db.select("l.dlogid, l.did, l.ndstr, u.uname, l.utime FROM tr_dictlog l, tr_user u WHERE l.uid = u.uid AND did = ? ORDER BY l.utime", self.params.did))
    for _, dl in ipairs(self.dictlogs) do
        dl.pid = pid
    end
    
    return { render = true }
end))

app:get("setdictlog", "/project/p:pid/dict/d:did/set/dl:dlogid", capture_errors(function(self)
    validate.assert_valid(self.params, {
        { "pid", exists = true, is_integer = true },
        { "did", exists = true, is_integer = true },
        { "dlogid", exists = true, is_integer = true },
    })
    
    assert_error(self.admin_state, "设置词典项选择，需要管理员权限！")
    
    local dict = assert_error(MDict:find(self.params.did))
    local dlog = assert_error(MDictLog:find(self.params.dlogid))
    dict.acceptlog = dlog.dlogid
    dict.dstr = dlog.ndstr
    assert_error(dict:update("acceptlog", "dstr"))
    
    return { redirect_to = self:url_for("dictlog", self.params) }
end)) 

app:get("download", "/project/p:pid/downloads", capture_errors(function(self)
    validate.assert_valid(self.params, {
        { "pid", exists = true, is_integer = true }
    })
    
    local pid = self.params.pid
    self.project = assert_error(MProject:find(pid))
    
    self.files = {}
    local dir = "download/" .. pid
    for p in lfs.dir(dir) do
        local attrs = lfs.attributes(dir .. "/" .. p)
        if attrs.mode == "file" then
            table.insert(self.files, { name = p, utime = attrs.modification, size = attrs.size, uri = string.format("/%s/%s", dir, p) })
        end
    end
    table.sort(self.files, function(f1, f2)
        return f1.name < f2.name
    end)
    
    return { render = true }
end))

app:get("checklines", "/project/p:pid/checklines", capture_errors(function(self)
    validate.assert_valid(self.params, {
        { "pid", exists = true, is_integer = true }
    })
    
    assert_error(self.admin_state, "生成新更新文件需要管理员权限！")
    
    local pid = self.params.pid
    self.project = assert_error(MProject:find(pid))
    
    self.prevtime = self.project.lastupdate
    self.curtime = db.format_date()
    
    self.lines = assert_error(db.select("* FROM tr_line l WHERE EXISTS (SELECT * FROM tr_file f WHERE f.pid = ? AND f.fid = l.fid) AND EXISTS (SELECT * FROM tr_log lg WHERE lg.fid = l.fid AND lg.lid = l.lid AND lg.utime >= ? AND lg.utime < ?) ORDER BY l.fid, l.lid", pid, self.prevtime, self.curtime))
    
    for _, l in ipairs(self.lines) do
        l.pid = pid
    end
    
    return { render = true }
end))

app:get("checkdicts", "/project/p:pid/checkdicts(/t:time)", capture_errors(function(self)
    validate.assert_valid(self.params, {
        { "pid", exists = true, is_integer = true }
    })
    
    assert_error(self.admin_state, "生成新更新文件需要管理员权限！")
    
    local pid = self.params.pid
    self.project = assert_error(MProject:find(pid))
    
    self.prevtime = self.project.lastupdate
    self.curtime = self.params.time and util.unescape(self.params.time) or db.format_date()
    
    self.dicts = assert_error(db.select("* FROM tr_dict d WHERE d.pid = ? AND EXISTS (SELECT * FROM tr_dictlog dl WHERE dl.did = d.did AND dl.utime >= ? AND dl.utime < ?) ORDER BY d.did", pid, self.prevtime, self.curtime))
    
    for _, d in ipairs(self.dicts) do
        d.pid = pid
    end
    
    return { render = true }
end))

app:get("genupdate", "/project/p:pid/genupdate/t:time", capture_errors(function(self)
    validate.assert_valid(self.params, {
        { "pid", exists = true, is_integer = true }
    })
    
    assert_error(self.admin_state, "生成新更新文件需要管理员权限！")
    
    local pid = self.params.pid
    local project = assert_error(MProject:find(pid))
    
    local prevtime = project.lastupdate
    local curtime = self.params.time and util.unescape(self.params.time) or db.format_date()
    
    local lines = assert_error(db.select("f.fname, l.lid, l.trstr FROM tr_line l, tr_file f WHERE f.pid = ? AND f.fid = l.fid AND EXISTS (SELECT * FROM tr_log lg WHERE lg.fid = l.fid AND lg.lid = l.lid AND lg.utime >= ? AND lg.utime < ?) ORDER BY l.fid, l.lid", pid, prevtime, curtime))
    
    local path = string.format("download/%d/update-%s.json", pid, curtime)
    local output = assert_error(io.open(path, "w"))
    output:write(require("cjson").encode(lines))
    output:close()
    
    project.lastupdate = curtime
    assert_error(project:update("lastupdate"))
    
    return { redirect_to = self:url_for("download", self.params) }
end))

return app
