local http = require 'resty.http'
local util = require("lapis.util")

local config = require("lapis.config").get()

local mstr = {}
local kvs = {
  en = "en",
  cn = "zh-CHS",
  jp = "ja"
}

local EXPIRED = 9 * 60

local function getLanguageCode(s)
  return kvs[s] or s
end

local function filterString(s)
  local ns
  if string.match(s, "^# ") or string.match(s, "^old ") then
    ns = string.match(s, "\"(.*)\"")
    ns = ns or s
  end
  ns = string.gsub(ns, "<[^>]*>", "")
  ns = string.gsub(ns, "#c.%d", "")

  return ns
end

local function updateAccessToken()
  if mstr.token and ngx.now() < mstr.token_expired then
    return true
  end

  local httpc = http.new()
  local res, err = httpc:request_uri("https://api.cognitive.microsoft.com/sts/v1.0/issueToken", {
    method = "POST",
    body = "",
    headers = {
      ["Ocp-Apim-Subscription-Key"] = config.mskey
    },
    ssl_verify = false
  })

  if not res then
    return nil, err
  end

  if tonumber(res.status) ~= 200 then
    print(res.body)
    return nil, "Error status: " .. res.status
  end

  mstr.token = res.body
  mstr.token_expired = ngx.now() + EXPIRED

  print("TOKEN: " .. mstr.token)
  return true
end

function mstr.translate(sl, dl, stext)
  local status, err = updateAccessToken()
  if not status then
    return nil, err
  end

  local httpc = http.new()
  local res, err = httpc:request_uri("https://api.microsofttranslator.com/V2/Http.svc/Translate?" .. 
    util.encode_query_string({
      from = getLanguageCode(sl),
      to = getLanguageCode(dl),
      text = filterString(stext)
    }), {
    headers = {
      ["Authorization"] = "Bearer " .. mstr.token
    },
    ssl_verify = false
  })

  if not res then
    return nil, err
  end

  if tonumber(res.status) ~= 200 then
    print(res.body)
    return nil, "ERROR status: " .. res.status
  end

  local dest = string.match(res.body, "<string[^>]*>(.*)</string>")
  dest = dest or res.body

  httpc:set_keepalive()

  return dest
end

return mstr
