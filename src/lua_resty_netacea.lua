local b64 = require("ngx.base64")

local Ingest = require("lua_resty_netacea_ingest")
local netacea_cookies = require('lua_resty_netacea_cookies_v3')
local utils = require("netacea_utils")
local protector_client = require("lua_resty_netacea_protector_client")

local _N = {}
_N._VERSION = '0.2.2'
_N._TYPE = 'nginx'

local ngx = require 'ngx'
local cjson = require 'cjson'
local http = require 'resty.http'

local function serveCaptcha(captchaBody)
  ngx.status = ngx.HTTP_FORBIDDEN
  ngx.header["content-type"] = "text/html"
  ngx.header["Cache-Control"] = "max-age=0, no-cache, no-store, must-revalidate"
  ngx.print(captchaBody)
  return ngx.exit(ngx.HTTP_OK)
end

local function serveBlock()
  ngx.status = ngx.HTTP_FORBIDDEN;
  ngx.header["Cache-Control"] = "max-age=0, no-cache, no-store, must-revalidate"
  ngx.print("403 Forbidden");
  return ngx.exit(ngx.HTTP_FORBIDDEN);
end

function _N:new(options)
  local n = {}
  setmetatable(n, self)
  self.__index = self
  
  -- ingest:optional:ingestEnabled
  n.ingestEnabled = options.ingestEnabled or false
  -- ingest:required:ingestEndpoint
  n.ingestEndpoint = options.ingestEndpoint
  
  n.kinesisProperties = options.kinesisProperties or nil

  if not n.kinesisProperties then
    n.ingestEnabled = false
  else
    -- Validate kinesisProperties structure
    if type(n.kinesisProperties) ~= 'table' or
       not n.kinesisProperties.stream_name or
       not n.kinesisProperties.region or
       not n.kinesisProperties.aws_access_key or
        not n.kinesisProperties.aws_secret_key
       then
      ngx.log(ngx.ERR, "NETACEA CONFIG - Invalid kinesisProperties structure")
      n.ingestEnabled = false
    end
  end
  -- mitigate:optional:mitigationEnabled
  n.mitigationEnabled = options.mitigationEnabled or false
  -- mitigate:required:mitigationEndpoint
  n.mitigationEndpoint = options.mitigationEndpoint
  if type(n.mitigationEndpoint) ~= 'table' then
    n.mitigationEndpoint = { n.mitigationEndpoint }
  end
  if not n.mitigationEndpoint[1] or n.mitigationEndpoint[1] == '' then
    n.mitigationEnabled = false
  end
  -- mitigate:required:mitigationType
  n.mitigationType = utils.parseOption(options.mitigationType, '')
  if not n.mitigationType or (n.mitigationType ~= 'MITIGATE' and n.mitigationType ~= 'INJECT') then
    n.mitigationEnabled = false
  end
  -- mitigate:required:secretKey
  n.secretKey = b64.decode_base64url(options.secretKey) or ''
  if not n.secretKey or n.secretKey == '' then
    n.mitigationEnabled = false
  end
  -- global:optional:cookieName
  n.cookieName = utils.parseOption(options.cookieName, '_mitata')
  -- global:optional:cookieAttributes
  n.cookieAttributes = utils.parseOption(options.cookieAttributes, 'Max-Age=86400; Path=/;')
  -- global:optional:captchaCookieName
  n.captchaCookieName = utils.parseOption(options.captchaCookieName, '_mitatacaptcha')  --options.captchaCookieName or '_mitatacaptcha'
  -- global:optional:captchaCookieAttributes
  n.captchaCookieAttributes = utils.parseOption(options.captchaCookieAttributes, 'Max-Age=86400; Path=/;')
  -- global:optional:realIpHeader
  n.realIpHeader = utils.parseOption(options.realIpHeader, '')
  -- global:optional:userIdKey
  n.userIdKey = utils.parseOption(options.userIdKey, '')
  -- global:required:apiKey
  n.apiKey = utils.parseOption(options.apiKey, nil)
  if not n.apiKey then
    n.ingestEnabled = false
    n.mitigationEnabled = false
  end

  n.endpointIndex = 0
  n._MODULE_TYPE = _N._TYPE
  n._MODULE_VERSION = _N._VERSION


  if n.ingestEnabled then
    n.ingestPipeline = Ingest:new(options.kinesisProperties or {}, n)
    n.ingestPipeline:start_timers()
  end

  if n.mitigationEnabled then
    n.protectorClient = protector_client:new{
      apiKey = n.apiKey,
      mitigationEndpoint = n.mitigationEndpoint
    }
  end

  return n
end

function _N:getBestMitigation(protector_result)
  if not protector_result then return nil end

  local mitigate = protector_result.mitigate
  local captcha = protector_result.captcha

  if (mitigate == Constants.mitigationTypes.NONE) then return nil end
  if (not Constants.mitigationTypesText[mitigate]) then return nil end

  if (mitigate == Constants.mitigationTypes.ALLOW) then return nil end
  if (captcha == Constants.captchaStates.PASS) then return nil end
  if (captcha == Constants.captchaStates.COOKIEPASS) then return nil end

  if (mitigate == Constants.mitigationTypes.BLOCKED and (captcha == Constants.captchaStates.SERVE or captcha == Constants['captchaStates'].COOKIEFAIL )) then
    return 'captcha'
  end

  return 'block'
end

function _N:setBcType(match, mitigate, captcha)
  local UNKNOWN = 'unknown'
  local mitigationApplied = ''

  if (match ~= '0') then
    mitigationApplied = mitigationApplied .. (Constants.matchBcTypes[match] or UNKNOWN) .. '_'
  end
  if (mitigate ~= '0') then
    mitigationApplied = mitigationApplied .. (Constants.mitigateBcTypes[mitigate] or UNKNOWN)
  end
  if (captcha ~= '0') then
    mitigationApplied = mitigationApplied .. ',' .. (Constants.captchaBcTypes[captcha] or UNKNOWN)
  end
  return mitigationApplied
end

function _N:ingest()
  ngx.log(ngx.DEBUG, "NETACEA INGEST - in netacea:ingest(): ", self.ingestEnabled)
  if not self.ingestEnabled then return nil end
  ngx.ctx.NetaceaState.bc_type = self:setBcType(
    tostring(ngx.ctx.NetaceaState.protector_result.match or Constants['idTypes'].NONE),
    tostring(ngx.ctx.NetaceaState.protector_result.mitigate or Constants['mitigationTypes'].NONE),
    tostring(ngx.ctx.NetaceaState.protector_result.captcha or Constants['captchaStates'].NONE)
  )
  return self.ingestPipeline:ingest()
end

function _N:handleSession()
  ngx.ctx.NetaceaState = {}
  ngx.ctx.NetaceaState.client = utils:getIpAddress(ngx.var, self.realIpHeader)
  ngx.ctx.NetaceaState.user_agent = ngx.var.http_user_agent or ''

  -- Check cookie
  local cookie = ngx.var['cookie_' .. self.cookieName] or ''
  local parsed_cookie = netacea_cookies.parseMitataCookie(cookie, self.secretKey)
  ngx.log(ngx.DEBUG, "NETACEA MITIGATE - parsed cookie: ", cjson.encode(parsed_cookie))
  if parsed_cookie.user_id then
    ngx.ctx.NetaceaState.UserId = parsed_cookie.user_id
  end

  -- Get captcha cookie
  local captcha_cookie_raw = ngx.var['cookie_' .. self.captchaCookieName] or ''
  local captcha_cookie = netacea_cookies.decrypt(self.secretKey, captcha_cookie_raw)
  if captcha_cookie and captcha_cookie ~= '' then
    ngx.ctx.NetaceaState.captcha_cookie = captcha_cookie
  end
  return parsed_cookie
end

function _N:refreshSession(reason)
  local protector_result = ngx.ctx.NetaceaState.protector_result

  local grace_period = ngx.ctx.NetaceaState.grace_period or 60

  local new_cookie = netacea_cookies.generateNewCookieValue(
      self.secretKey,
      ngx.ctx.NetaceaState.client,
      ngx.ctx.NetaceaState.UserId,
      netacea_cookies.newUserId(),
      reason,
      os.time(),
      grace_period,
      protector_result.match,
      protector_result.mitigate,
      protector_result.captcha,
      {}
    )
    local cookies = {
      self.cookieName .. '=' .. new_cookie.mitata_jwe .. ';' .. self.cookieAttributes
    }
    
    if protector_result.captcha_cookie and protector_result.captcha_cookie ~= '' then
      local captcha_cookie_encrypted = netacea_cookies.encrypt(self.secretKey, protector_result.captcha_cookie)
      table.insert(cookies, self.captchaCookieName .. '=' .. captcha_cookie_encrypted .. ';')
    end
    
    ngx.header['Set-Cookie'] = cookies
end

function _N:handleCaptcha()
  local parsed_cookie = self:handleSession()

  ngx.req.read_body()
  local captcha_data = ngx.req.get_body_data()
  local protector_result = self.protectorClient:validateCaptcha(captcha_data)
  ngx.ctx.NetaceaState.protector_result = protector_result
  ngx.ctx.NetaceaState.grace_period = -1000
  ngx.log(ngx.DEBUG, "NETACEA CAPTCHA - protector result: ", cjson.encode(ngx.ctx.NetaceaState))
  
  self:refreshSession(Constants['issueReasons'].CAPTCHA_POST)
  ngx.exit(protector_result.exit_status)
end


function _N:mitigate()
  if not self.mitigationEnabled then return nil end
  local parsed_cookie = self:handleSession()

  if not parsed_cookie.valid then
    if not ngx.ctx.NetaceaState.UserId then
      ngx.ctx.NetaceaState.UserId = netacea_cookies.newUserId()
    end

    local protector_result = self.protectorClient:checkReputation()

    ngx.ctx.NetaceaState.protector_result = protector_result

    ngx.log(ngx.DEBUG, "NETACEA MITIGATE - protector result: ", cjson.encode(ngx.ctx.NetaceaState))

    local best_mitigation = self:getBestMitigation(protector_result)
    if best_mitigation == 'captcha' then
      ngx.log(ngx.DEBUG, "NETACEA MITIGATE - serving captcha")
      local captchaBody = protector_result.response.body
      ngx.ctx.NetaceaState.grace_period = -1000
      self:refreshSession(parsed_cookie.reason)
      serveCaptcha(captchaBody)
      return
    elseif best_mitigation == 'block' then
      ngx.log(ngx.DEBUG, "NETACEA MITIGATE - serving block")
      ngx.ctx.NetaceaState.grace_period = -1000
      self:refreshSession(parsed_cookie.reason)
      serveBlock()
      return
    else
      ngx.log(ngx.DEBUG, "NETACEA MITIGATE - no mitigation applied")
      self:refreshSession(parsed_cookie.reason)
    end
  else
    ngx.log(ngx.DEBUG, "NETACEA MITIGATE - valid cookie found, skipping mitigation")
    ngx.ctx.NetaceaState.protector_result = {
      match = parsed_cookie.data.mat,
      mitigate = parsed_cookie.data.mit,
      captcha = parsed_cookie.data.cap
    }
  end
end
return _N