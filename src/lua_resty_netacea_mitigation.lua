local ngx = require 'ngx'
local Constants = require("lua_resty_netacea_constants")

local _M = {}

function _M.getBestMitigation(protector_result)
  if not protector_result then return nil end

  local mitigate = protector_result.mitigate
  local captcha = protector_result.captcha

  if (mitigate == Constants.mitigationTypes.NONE) then return nil end
  if (not Constants.mitigationTypesText[mitigate]) then return nil end

  if (mitigate == Constants.mitigationTypes.ALLOW) then return nil end
  if (captcha == Constants.captchaStates.PASS) then return nil end
  if (captcha == Constants.captchaStates.COOKIEPASS) then return nil end

  if (mitigate == Constants.mitigationTypes.BLOCKED
      and (captcha == Constants.captchaStates.SERVE
        or captcha == Constants['captchaStates'].COOKIEFAIL)) then
    return 'captcha'
  end

  if (mitigate == Constants.mitigationTypes.MONETISED) then
    return 'monetise'
  end

  return 'block'
end

function _M.serveCaptcha(captchaBody)
  ngx.status = ngx.HTTP_FORBIDDEN
  ngx.header["content-type"] = "text/html"
  ngx.header["Cache-Control"] = "max-age=0, no-cache, no-store, must-revalidate"
  ngx.print(captchaBody)
  return ngx.exit(ngx.HTTP_OK)
end

function _M.serveBlock()
  ngx.status = ngx.HTTP_FORBIDDEN;
  ngx.header["Cache-Control"] = "max-age=0, no-cache, no-store, must-revalidate"
  ngx.print("403 Forbidden");
  return ngx.exit(ngx.HTTP_FORBIDDEN);
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
