local ngx = require 'ngx'
local cjson = require 'cjson'
local Constants = require("lua_resty_netacea_constants")

local _M = {}

local function shouldServeCaptchaAsJson(enableCaptchaContentNegotiation, netaceaCaptchaPath)
  if not enableCaptchaContentNegotiation then return false end
  if not netaceaCaptchaPath then return false end

  local accept = ngx.var and ngx.var.http_accept or nil
  if type(accept) ~= "string" then return false end

  accept = accept:lower()
  return accept:find("application/json", 1, true) ~= nil
    and accept:find("text/html", 1, true) == nil
end

local function buildCaptchaJson(captchaPath, trackingId)
  local scheme = (ngx.var and ngx.var.scheme) or "http"
  local host = (ngx.var and (ngx.var.http_host or ngx.var.host)) or ""
  local relativeURL = captchaPath and captchaPath or "null"
  local absoluteURL = captchaPath and (scheme .. "://" .. host .. captchaPath) or "null"

  if captchaPath and trackingId and trackingId ~= "" then
    local separator = captchaPath:find("?", 1, true) and "&" or "?"
    relativeURL = captchaPath .. separator .. "trackingId=" .. trackingId
    absoluteURL = scheme .. "://" .. host .. relativeURL
  end

  return string.format(
    '{"captchaRelativeURL":%s,"captchaAbsoluteURL":%s}',
    relativeURL == "null" and "null" or string.format("%q", relativeURL),
    absoluteURL == "null" and "null" or string.format("%q", absoluteURL)
  )
end

local function extractTrackingId(captchaBody)
  if type(captchaBody) ~= "string" then return nil end

  local ok, decoded = pcall(cjson.decode, captchaBody)
  if not ok or type(decoded) ~= "table" then return nil end

  local trackingId = decoded.trackingId
  if type(trackingId) ~= "string" or trackingId == "" then
    return nil
  end

  return trackingId
end

function _M.getBestMitigation(protector_result)
  if not protector_result then return nil end

  local mitigate = protector_result.mitigate
  local captcha = protector_result.captcha

  if (mitigate == Constants.mitigationTypes.NONE) then return nil end
  if (not Constants.mitigationTypesText[mitigate]) then return nil end
  if (mitigate == Constants.mitigationTypes.ALLOW) then return nil end

  -- Handle captcha pass
  if (captcha == Constants.captchaStates.PASS) then return nil end
  if (captcha == Constants.captchaStates.COOKIEPASS) then return nil end

  -- Handle checkpoint pass
  if (captcha == Constants.checkpointStates.PASS) then return nil end
  if (captcha == Constants.checkpointStates.COOKIEPASS) then return nil end

  -- Handle captcha serve
  if (mitigate == Constants.mitigationTypes.BLOCKED
      and (captcha == Constants.captchaStates.SERVE
        or captcha == Constants['captchaStates'].COOKIEFAIL)) then
    return 'captcha'
  end

  -- handle checkpoint serve
  if (mitigate == Constants.mitigationTypes.BLOCKED
      and (captcha == Constants.checkpointStates.SERVE
        or captcha == Constants['checkpointStates'].COOKIEFAIL)) then
    return 'checkpoint'
  end

  if (mitigate == Constants.mitigationTypes.MONETISED) then
    return 'monetise'
  end

  if (mitigate == Constants.mitigationTypes.FLAGGED) then
    return 'flag'
  end

  if (mitigate == Constants.mitigationTypes.BLOCKED) then
    return 'block'
  end

  if (mitigate == Constants.mitigationTypes.HARDBLOCKED) then
    return 'block'
  end

  return nil
end

function _M.serveCaptcha(captchaBody, options)
  options = options or {}
  ngx.status = ngx.HTTP_FORBIDDEN
  if shouldServeCaptchaAsJson(options.enableCaptchaContentNegotiation, options.netaceaCaptchaPath) then
    ngx.header["content-type"] = "application/json"
    ngx.header["Cache-Control"] = "max-age=0, no-cache, no-store, must-revalidate"
    local trackingId = options.trackingId or extractTrackingId(captchaBody)
    if not trackingId or trackingId == "" then
      error("NETACEA CAPTCHA - missing trackingId for negotiated JSON response")
    end
    ngx.print(buildCaptchaJson(options.captchaPath, trackingId))
    return ngx.exit(ngx.HTTP_OK)
  end

  ngx.header["content-type"] = "text/html"
  ngx.header["Cache-Control"] = "max-age=0, no-cache, no-store, must-revalidate"
  ngx.print(captchaBody)
  return ngx.exit(ngx.HTTP_OK)
end

function _M.serveBlock(blockedResponseStatus)
  local status = tonumber(blockedResponseStatus) or ngx.HTTP_FORBIDDEN
  ngx.status = status;
  ngx.header["Cache-Control"] = "max-age=0, no-cache, no-store, must-revalidate"
  ngx.print(tostring(status) .. " Forbidden");
  return ngx.exit(status);
end

function _M.serveMonetisationRedirect(location)
  ngx.status = 303;
  ngx.header["Location"] = location
  ngx.header["Cache-Control"] = "max-age=0, no-cache, no-store, must-revalidate"
  ngx.print("303 See Other");
  return ngx.exit(303);
end

function _M.serveMonetisationFallback()
  ngx.status = 402;
  ngx.header["Cache-Control"] = "max-age=0, no-cache, no-store, must-revalidate"
  ngx.print("402 Payment Required");
  return ngx.exit(402);
end

return _M
