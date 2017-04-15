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
local MComment = Model:extend("tr_comment", {
    primary_key = "cid"
})

local function getRenpyLine(content, offset, line, trhead)
    local stage = 1
    local srcfilename, srcfileline
    local linehead
    local orgstr, trstr, lid
    local desc
    local hasline
    
    while true do
        local eols, eole = string.find(content, "\r?\n", offset)
        local l = string.sub(content, offset, eols and eols - 1)
        l = string.gsub(l, "^(%s+)", "")
        
        if stage == 1 then
            local tempfilename, tempfileline = string.match(l, "^# (.*):(%d+)")
            if tempfilename then
                srcfilename, srcfileline = tempfilename, tempfileline
            elseif string.match(l, "^translate.*:") then
                trhead = l
            elseif string.match(l, "^old%s") then
                orgstr = l
                desc = trhead .. (srcfilename and string.format(" (%s:%d)", srcfilename, srcfileline) or "")
                stage = 6
            else
                local temphead = string.match(l, "^#%s+([^\"]*)\".*\"")
                if temphead then
                    linehead = temphead
                    orgstr = l
                    desc = trhead .. (srcfilename and string.format(" (%s:%d)", srcfilename, srcfileline) or "")
                    stage = 4
                end
            end
        elseif stage == 4 then
            local tempstr = string.match(l, "^" .. linehead .. "\"(.*)\"")
            if tempstr then
                lid = line
                trstr = tempstr
                hasline = true
                stage = 1
            end
        elseif stage == 6 then
            if string.match(l, "^new%s") then
                lid = line
                trstr = string.match(l, "\"(.*)\"")
                hasline = true
                stage = 1
            end
        end
        
        if eols then
            offset = eole + 1
            line = line + 1
        else
            offset = #content + 1
        end
    
        if hasline then
            return offset, lid, desc, orgstr, trstr, trhead
        elseif not eols then
            return nil
        end
    end
end

local function analysisRenpyFile(proj, name, content, fdesc)
    local file = assert_error(MFile:create({
        pid = proj.pid,
        fname = name,
        fdesc = fdesc,
    }), "该文件已存在！")
    
    local offset, line = 1, 1
    local count, ntred = 0, 0
    local trhead
    while true do
        local noff, lid, desc, orgstr, trstr, ntrhead = getRenpyLine(content, offset, line, trhead)
        
        if noff then
            local ldata = assert_error(MLine:create({
                lid = lid,
                fid = file.fid,
                ldesc = desc or "",
                orgstr = orgstr,
                trstr = ""
            }))
            if trstr ~= "" then
                local logdata = assert_error(MLog:create({
                    fid = file.fid,
                    lid = ldata.lid,
                    uid = 1,
                    utime = db.format_date(1000000),
                    bfstr = trstr
                }))
                ldata.nupd = 1
                ldata.acceptlog = logdata.logid
                ldata.trstr = trstr
                assert_error(ldata:update("nupd", "acceptlog", "trstr"))
                    
                ntred = ntred + 1
            end
            count = count + 1
                
            offset = noff
            line = lid + 1
            trhead = ntrhead
        else
            break
        end
    end
    
    if count > 0 then
        file.fline = count
        file.ntred = ntred 
        assert(file:update("fline", "ntred"))
    end
    
    return 1, count, ntred
end

local function analysisLuaFile(proj, name, content, fdesc)
    local plpretty = require "pl.pretty"
    local trs = plpretty.read(content)
    
    local nfile, count, ntred = 0, 0, 0
    
    for _, tr in ipairs(trs) do
        local file = assert_error(MFile:create({
            pid = proj.pid,
            fname = tr[2],
            fdesc = string.format("%s\n%s", tr[1], tr[3]),
            fline = #tr - 5,
            ntred = tr[4]
        }))
        nfile = nfile + 1
        count = count + file.fline
        ntred = ntred + file.ntred
        
        for i = 6, #tr do
            local s = tr[i]
            local lineid = i - 5
            local linedesc = s[1]
            if #s == 5 and s[4] then
                linedesc = string.format("%s (英：%s)", linedesc, s[4])
            end
            local line = assert_error(MLine:create({
                fid = file.fid,
                lid = lineid,
                ldesc = linedesc,
                orgstr = s[3],
                trstr = ""
            }))

            if s[2] == 1 then
                local logdata = assert_error(MLog:create({
                    fid = file.fid,
                    lid = lineid,
                    uid = 1,
                    bfstr = s[#s],
                    utime = db.format_date(1000000)
                }))
                
                line.nupd = 1
                line.acceptlog = logdata.logid
                line.trstr = logdata.bfstr
                assert_error(line:update("nupd", "acceptlog", "trstr"))
            end
        end
    end
    
    return nfile, count, ntred
end

local function uploadUpdateRenpyFile(project, file, lines, content)
    local curline = 1
    local appendlines = {}
    
    local offset, line = 1, 1
    local trhead
    local count, ntred = 1, 1
    while true do
        local noff, lid, desc, orgstr, trstr, ntrhead = getRenpyLine(content, offset, line, trhead)
        
        if noff then
            if curline <= #lines then
                local ldata = lines[curline]
                assert_error(ldata.lid == lid and ldata.orgstr == orgstr, "不支持该种更新！")
            else
                local ldata = assert_error(MLine:create({
                    lid = lid,
                    fid = file.fid,
                    ldesc = desc or "",
                    orgstr = orgstr,
                    trstr = ""
                }))
                if trstr ~= "" then
                    local logdata = assert_error(MLog:create({
                        fid = file.fid,
                        lid = ldata.lid,
                        uid = 1,
                        utime = db.format_date(1000000),
                        bfstr = trstr
                    }))
                    ldata.nupd = 1
                    ldata.acceptlog = logdata.logid
                    ldata.trstr = trstr
                    assert_error(ldata:update("nupd", "acceptlog", "trstr"))
                    ntred = ntred + 1
                end
                count = count + 1
                
                ldata.pid = project.pid
                table.insert(appendlines, ldata)
            end
            
            offset = noff
            line = lid + 1
            trhead = ntrhead
            curline = curline + 1
        else
            break
        end
    end
    
    if count > 0 then
        file.ntred = file.ntred + ntred
        file.fline = file.fline + count
        assert_error(file:update("fline", "ntred"))
        
        project.ntred = project.ntred + ntred
        project.pline = project.pline + count
        assert_error(project:update("pline", "ntred"))
    end
    
    return appendlines
end

local app = lapis.Application()
app:enable("etlua")
app.layout = require "views.layout"

app.handle_error = function(self, err, trace)
    self.errstr = "无此访问路径！"
    return { render = "error", status = 404 }
end

local function my_capture_errors(func)
    return capture_errors({
        on_error = function(self)
            self.errstr = self.errors[1]
            return { render = "error", status = 404 }
        end, 
        func
    })
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
    
    self.lasturl = self.req.headers["Referer"]
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
    }), "用户名已存在！")
    
    doLogin(self, user)
    
    return { redirect_to = self.params.lasturl or self:url_for("index") }
end))

app:get("login", "/login", function(self)
    if self.current_user then
        return { redirect_to = self:url_for("index") }
    end
    
    self.lasturl = self.req.headers["Referer"]
    return { render = "user" }
end)

app:post("login", "/login", my_capture_errors(function(self)
    validate.assert_valid(self.params, {
        { "username", exists = true },
        { "password", exists = true }
    })
    
    local user = assert_error(MUser:find({
        uname = self.username,
        upasswd = encoding.encode_base64(encoding.hmac_sha1(config.secret, self.params.password)),
    }), "用户名不存在或密码不正确！")
    
    doLogin(self, user)
    
    return { redirect_to = self.params.lasturl or self:url_for("index") }
end))

app:get("logout", "/logout", function(self)
    if self.current_user then
        doLogout(self, self.current_user)
    end
    
    local lasturl = self.req.headers["Referer"]
    return { redirect_to = lasturl or self:url_for("index") }
end)

app:post("new", "/project/new", my_capture_errors(function(self)
    validate.assert_valid(self.params, {
        { "name", exists = true, min_length = 1, max_length = 44 },
        { "desc", exists = true, min_length = 1, max_length = 254 },
    })
    
    assert_error(self.admin_state, "创建新项目必须管理员权限！")
    
    local project = assert_error(MProject:create({ pname = self.params.name, pdesc = self.params.desc }))
    
    lfs.mkdir("download/" .. project.pid)
    return { redirect_to = self:url_for("index") }
end))

app:get("project", "/project/p:pid/files(/page:pageid)", my_capture_errors(function(self)
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

app:post("project", "/project/p:pid/files(/page:pageid)", my_capture_errors(function(self)
    validate.assert_valid(self.params, {
        { "pid", exists = true, is_integer = true },
        { "type", exists = true },
        { "desc", max_length = 254 },
        { "uploadfile", exists = true, is_file = true },
    })
    
    assert_error(self.admin_state, "上传文件必须管理员权限！")
    
    local filetype = self.params.type
    local upfile = self.params.uploadfile
    
    local project = assert_error(MProject:find(self.params.pid))

    local nfile, count, ntred
    if filetype == "renpy" then
        nfile, count, ntred = analysisRenpyFile(project, upfile.filename, upfile.content, self.params.desc)
    elseif filetype == "lua" then
        nfile, count, ntred = analysisLuaFile(project, upfile.filename, upfile.content, self.params.desc)
    else
        assert_error(nil, "文件类型不支持：" .. tostring(filetype))
    end
    
    project.pfile = project.pfile + nfile
    project.pline = project.pline + count
    project.ntred = project.ntred + ntred
    assert_error(project:update("pfile", "pline", "ntred"))
    
    ngx.shared.filepn:flush_all()

    return { redirect_to = self:url_for("project", self.params) }
end))

app:get("file", "/project/p:pid/file/f:fid(/page:pageid)", my_capture_errors(function(self)
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

app:post("file", "/project/p:pid/file/f:fid(/page:pageid)", my_capture_errors(function(self)
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
                    uid = self.admin_state and 1 or self.current_user.uid,
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

app:get("log", "/project/p:pid/file/f:fid/line/l:lid", my_capture_errors(function(self)
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

app:post("log", "/project/p:pid/file/f:fid/line/l:lid", my_capture_errors(function(self)
    validate.assert_valid(self.params, {
        { "pid", exists = true, is_integer = true },
        { "fid", exists = true, is_integer = true },
        { "lid", exists = true, is_integer = true },
        { "newstr", exists = true }
    })
    
    assert_error(self.current_user, "修改翻译必须登录！")
    
    local pid, fid, lid = self.params.pid, self.params.fid, self.params.lid
    local newstr = self.params.newstr
    
    local project = assert_error(MProject:find(pid))
    local file = assert_error(MFile:find(fid))
    local line = assert_error(MLine:find(fid, lid))
    if line.trstr ~= newstr then
        local linelog = assert_error(MLog:create{
                fid = fid,
                lid = lid,
                uid = self.admin_state and 1 or self.current_user.uid,
                bfstr = newstr
        })
    
        line.trstr = newstr
        line.nupd = line.nupd + 1
        line.acceptlog = linelog.logid
        assert_error(line:update("nupd", "trstr", "acceptlog"))
    
        if line.nupd == 1 then
                file.ntred = file.ntred + 1
                assert_error(file:update("ntred"))
        
                project.ntred = project.ntred + 1
                assert_error(project:update("ntred"))
        end
    end
    
    return { redirect_to = self:url_for("log", self.params) }
end))

app:get("setlog", "/project/p:pid/file/f:fid/line/l:lid/set/log:logid", my_capture_errors(function(self)
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

app:get("dict", "/project/p:pid/dicts", my_capture_errors(function(self)
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

app:post("dict", "/project/p:pid/dicts", my_capture_errors(function(self)
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
        uid = self.admin_state and 1 or self.current_user.uid,
        ndstr = self.params.destword
    }))
    
    dict.acceptlog = log.dlogid
    assert_error(dict:update("acceptlog"))
        
    return { redirect_to = self:url_for("dict", self.params) }
end))

app:get("dictlog", "/project/p:pid/dict/d:did", my_capture_errors(function(self)
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

app:get("setdictlog", "/project/p:pid/dict/d:did/set/dl:dlogid", my_capture_errors(function(self)
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

app:get("download", "/project/p:pid/downloads", my_capture_errors(function(self)
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

app:get("checklines", "/project/p:pid/checklines", my_capture_errors(function(self)
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

app:get("checkdicts", "/project/p:pid/checkdicts(/t:time)", my_capture_errors(function(self)
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

app:get("genupdate", "/project/p:pid/genupdate/t:time", my_capture_errors(function(self)
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

app:get("comment", "/project/p:pid/comments", my_capture_errors(function(self)
    validate.assert_valid(self.params, {
        { "pid", exists = true, is_integer = true }
    })
    local pid = self.params.pid
    
    self.project = assert_error(MProject:find(pid))
    
    if self.admin_state then
        self.comments = assert_error(db.select("u.uid, u.uname, c.cid, c.pid, c.utime, c.content, c.cacc, c.ctop FROM tr_comment c, tr_user u WHERE u.uid = c.uid AND c.pid = ? ORDER BY c.ctop DESC, c.utime DESC", pid))
    else
        self.comments = assert_error(db.select("u.uid, u.uname, c.cid, c.pid, c.utime, c.content, c.cacc, c.ctop FROM tr_comment c, tr_user u WHERE u.uid = c.uid AND c.pid = ? AND (c.cacc = 0 OR c.uid = ?) ORDER BY c.ctop DESC, c.utime DESC",
            pid, 
            self.current_user and self.current_user.uid or "-1"))
    end
    
    return { render = true }
end))

app:post("comment", "/project/p:pid/comments", my_capture_errors(function(self)
    validate.assert_valid(self.params, {
        { "pid", exists = true, is_integer = true },
        { "content", exists = true, max_length = 256 },
    })
    
    assert_error(self.current_user, "留言必须登录！")
    
    local pid = self.params.pid
    local project = assert_error(MProject:find(pid))
    local acc = (self.params.access and self.params.access == "private") and 1 or 0
    local top = (self.admin_state and self.params.top and self.params.top == "top") and 1 or 0
    
    assert_error(MComment:create({
        pid = pid,
        uid = self.current_user.uid,
        content = self.params.content,
        cacc = acc,
        ctop = top
    }))
   
    return { redirect_to = self:url_for("comment", self.params) }
end))

app:get("delcom", "/project/p:pid/comment/c:cid", my_capture_errors(function(self)
    validate.assert_valid(self.params, {
        { "pid", exists = true, is_integer = true },
        { "cid", exists = true, is_integer = true },
    })
    
    assert_error(self.current_user, "删除留言必须登录！")
    
    local comment = assert_error(MComment:find(self.params.cid))
    
    assert_error(self.admin_state or comment.uid == self.current_user.uid, "非管理员不能删除其他用户的留言！")

    comment:delete()
    
    return { redirect_to = self:url_for("comment", self.params) }
end))

app:get("swtopcom", "/project/p:pid/comment/c:cid/swtop", my_capture_errors(function(self)
    validate.assert_valid(self.params, {
        { "pid", exists = true, is_integer = true },
        { "cid", exists = true, is_integer = true },
    })
    
    assert_error(self.admin_state, "修改留言置顶需要管理员权限！")
    
    local comment = assert_error(MComment:find(self.params.cid))
    comment.ctop = 1 - comment.ctop
    comment:update("ctop")
    
    return { redirect_to = self:url_for("comment", self.params) }
end))

app:get("swprivcom", "/project/p:pid/comment/c:cid/swpriv", my_capture_errors(function(self)
    validate.assert_valid(self.params, {
        { "pid", exists = true, is_integer = true },
        { "cid", exists = true, is_integer = true },
    })
    
    assert_error(self.current_user, "修改留言可见性必须登录！")
    
    local comment = assert_error(MComment:find(self.params.cid))
    
    assert_error(self.admin_state or comment.uid == self.current_user.uid, "非管理员不能修改其他用户的留言的可见性！")

    comment.cacc = 1 - comment.cacc
    comment:update("cacc")
    
    return { redirect_to = self:url_for("comment", self.params) }
end))

app:get("other", "/project/p:pid/others", my_capture_errors(function(self)
    validate.assert_valid(self.params, {
        { "pid", exists = true, is_integer = true }
    })
    
    self.project = assert_error(MProject:find(self.params.pid))
    return { render = true }
end))

app:post("search", "/project/p:pid/others/search", my_capture_errors(function(self)
    validate.assert_valid(self.params, {
        { "pid", exists = true, is_integer = true },
        { "searchtype", exists = true },
        { "searchkey", exists = true}
    })
    
    local pid = self.params.pid
    self.stype = self.params.searchtype
    self.skey = self.params.searchkey
    
    self.project = assert_error(MProject:find(pid))
    
    if self.stype == "orgstr" then
        self.lines = assert_error(db.select("f.pid, f.fid, l.lid, l.orgstr, l.trstr FROM tr_line l, tr_file f WHERE f.pid = ? AND f.fid = l.fid AND orgstr REGEXP ?", 
            pid, self.skey))
    elseif self.stype == "trstr" then
        self.lines = assert_error(db.select("f.pid, f.fid, l.lid, l.orgstr, l.trstr FROM tr_line l, tr_file f WHERE f.pid = ? AND f.fid = l.fid AND trstr REGEXP ?", 
            pid, self.skey))
    else
        assert_error(nil, "未找到匹配的搜索类型！")
    end
    
    return { render = true }
end))

app:post("replace", "/project/p:pid/others/replace", my_capture_errors(function(self)
    validate.assert_valid(self.params, {
        { "pid", exists = true, is_integer = true },
        { "sword", exists = true },
        { "dword", exists = true}
    })
    
    assert_error(self.admin_state, "替换操作需要管理员权限！")
    
    local pid = self.params.pid
    local sword = self.params.sword
    local dword = self.params.dword
    
    self.project = assert_error(MProject:find(pid))
    
    local lines = assert_error(db.select("f.pid, f.fid, l.lid, l.orgstr, l.trstr FROM tr_line l, tr_file f WHERE f.pid = ? AND f.fid = l.fid AND trstr REGEXP ?", 
            pid, sword))
    for _, l in ipairs(lines) do
        local line = assert_error(MLine:find(l.fid, l.lid))
        local newstr = string.gsub(line.trstr, sword, dword)
        
        local linelog = assert_error(MLog:create{
            fid = line.fid,
            lid = line.lid,
            uid = 1,
            bfstr = newstr
        })
    
        line.trstr = newstr
        line.nupd = line.nupd + 1
        line.acceptlog = linelog.logid
        assert_error(line:update("nupd", "trstr", "acceptlog"))
        
        l.trstr = newstr
    end
    
    self.lines = lines
    self.sword = sword
    self.dword = dword
            
    return { render = true }
end))

app:post("uploadupdate", "/project/p:pid/others/uploadupdate", my_capture_errors(function(self)
    validate.assert_valid(self.params, {
        { "pid", exists = true, is_integer = true },
        { "uploadtype", exists = true },
        { "uploadfile", exists = true, is_file = true }
    })
    
    assert_error(self.admin_state, "上传更新文件需要管理员权限！")
    
    local pid = self.params.pid
    local uptype = self.params.uploadtype
    local upfile = self.params.uploadfile
    
    local project = assert_error(MProject:find(pid))
    local file = assert_error(MFile:find({ pid = pid, fname = upfile.filename }), "找不到指定文件！")
    local lines = MLine:select("where fid = ? ORDER BY lid", file.fid)
    
    assert_error(uptype == "renpy", "不支持的上传类型！")
    
    local appendlines = uploadUpdateRenpyFile(project, file, lines, upfile.content)
    
    self.project = project
    self.file = file
    self.lines = appendlines
    
    return { render = true }
end))

app:post("deletefile", "/project/p:pid/others/deletefile", my_capture_errors(function(self)
    validate.assert_valid(self.params, {
        { "pid", exists = true, is_integer = true },
        { "filename", exists = true },
    })
    
    assert_error(self.admin_state, "删除文件需要管理员权限！")
    
    local project = assert_error(MProject:find(self.params.pid))
    local file = assert_error(MFile:find({ pid = project.pid, fname = self.params.filename }), "找不到指定文件！")
    
    assert_error(db.delete("tr_log", { fid = file.fid }))
    assert_error(db.delete("tr_line", { fid = file.fid }))
    assert_error(db.delete("tr_file", { fid = file.fid }))
    
    project.pfile = project.pfile - 1
    project.pline = project.pline - file.fline
    project.ntred = project.ntred - file.ntred
    
    project:update("pfile", "pline", "ntred")
    
    return { redirect_to = self:url_for("project", project) }
end))

app:get("untred", "/project/p:pid/others/untred(/n:num)", my_capture_errors(function(self)
    validate.assert_valid(self.params, {
        { "pid", exists = true, is_integer = true },
        { "num", exists = true, is_integer = true }
    })
    
    local pid = self.params.pid
    local num = tonumber(self.params.num)
    
    self.project = assert_error(MProject:find(pid))
    
    self.lines = assert_error(db.select("f.pid, l.fid, l.lid, l.orgstr, l.trstr FROM tr_file f, tr_line l WHERE f.pid = ? AND f.fid = l.fid AND l.nupd = 0 ORDER BY l.fid, l.lid LIMIT ?",
        pid, num))
        
    return { render = true }
end))

return app
