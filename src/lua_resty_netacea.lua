local b64 = require("ngx.base64")

local Ingest = require("lua_resty_netacea_ingest")
local netacea_cookies = require('lua_resty_netacea_cookies_v3')
local utils = require("netacea_utils")
local protector_client = require("lua_resty_netacea_protector_client")
local Constants = require("lua_resty_netacea_constants")
local mitigation = require("lua_resty_netacea_mitigation")

local _N = {}
_N._VERSION = '1.2.0'
_N._TYPE = 'nginx'

local ngx = require 'ngx'
local cjson = require 'cjson'

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
  -- mitigate:required:cookieEncryptionKey
  -- secretKey is kept as a backwards-compatible alias.
  local encodedCookieEncryptionKey = options.cookieEncryptionKey or options.secretKey
  n.cookieEncryptionKey = b64.decode_base64url(encodedCookieEncryptionKey) or ''
  n.secretKey = n.cookieEncryptionKey
  n.sessionEnabled = n.cookieEncryptionKey and n.cookieEncryptionKey ~= ''
  if not n.cookieEncryptionKey or n.cookieEncryptionKey == '' then
    n.mitigationEnabled = false
  end
  -- global:optional:cookieName
  n.cookieName = utils.parseOption(options.cookieName, '_mitata')
  -- global:optional:cookieAttributes
  n.cookieAttributes = utils.parseOption(options.cookieAttributes, 'Max-Age=86400; Path=/;')
  -- global:optional:captchaCookieName
  n.captchaCookieName = utils.parseOption(options.captchaCookieName, '_mitatacaptcha')
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
  local NetaceaState = ngx.ctx.NetaceaState
  local protector_result = NetaceaState and NetaceaState.protector_result
  if protector_result then
    NetaceaState.bc_type = self:setBcType(
      tostring(protector_result.match or Constants['idTypes'].NONE),
      tostring(protector_result.mitigate or Constants['mitigationTypes'].NONE),
      tostring(protector_result.captcha or Constants['captchaStates'].NONE)
    )
  end
  return self.ingestPipeline:ingest()
end

function _N:handleSession()
  ngx.ctx.NetaceaState = {}
  ngx.ctx.NetaceaState.client = utils:getIpAddress(ngx.var, self.realIpHeader)
  ngx.ctx.NetaceaState.user_agent = ngx.var.http_user_agent or ''

  -- Check cookie
  local cookie = ngx.var['cookie_' .. self.cookieName] or ''
  ngx.ctx.mitata = cookie
  local parsed_cookie = netacea_cookies.parseMitataCookie(cookie, self.cookieEncryptionKey)
  ngx.log(ngx.DEBUG, "NETACEA MITIGATE - parsed cookie: ", cjson.encode(parsed_cookie))
  if parsed_cookie.user_id then
    ngx.ctx.NetaceaState.UserId = parsed_cookie.user_id
  end

  -- Get captcha cookie
  local captcha_cookie_raw = ngx.var['cookie_' .. self.captchaCookieName] or ''
  local captcha_cookie = netacea_cookies.decrypt(self.cookieEncryptionKey, captcha_cookie_raw)
  if captcha_cookie and captcha_cookie ~= '' then
    ngx.ctx.NetaceaState.captcha_cookie = captcha_cookie
  end
  return parsed_cookie
end

function _N:refreshSession(reason)
  local protector_result = ngx.ctx.NetaceaState.protector_result or {
    match = Constants['idTypes'].NONE,
    mitigate = Constants['mitigationTypes'].NONE,
    captcha = Constants['captchaStates'].NONE
  }

  local grace_period = ngx.ctx.NetaceaState.grace_period or 60

  local new_cookie = netacea_cookies.generateNewCookieValue(
      self.cookieEncryptionKey,
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
    ngx.ctx.mitata = new_cookie.mitata_jwe

    if protector_result.captcha_cookie and protector_result.captcha_cookie ~= '' then
      local captcha_cookie_encrypted = netacea_cookies.encrypt(
        self.cookieEncryptionKey,
        protector_result.captcha_cookie
      )
      table.insert(cookies,
        self.captchaCookieName .. '=' .. captcha_cookie_encrypted .. ';'.. self.captchaCookieAttributes)
    end

    ngx.header['Set-Cookie'] = cookies
end

function _N:handleCaptcha()
  self:handleSession()

  ngx.req.read_body()
  local captcha_data = ngx.req.get_body_data()
  local protector_result = self.protectorClient:validateCaptcha(captcha_data)
  ngx.ctx.NetaceaState.protector_result = protector_result
  ngx.ctx.NetaceaState.grace_period = -1000
  ngx.log(ngx.DEBUG, "NETACEA CAPTCHA - protector result: ", cjson.encode(ngx.ctx.NetaceaState))

  self:refreshSession(Constants['issueReasons'].CAPTCHA_POST)
  ngx.exit(protector_result.exit_status)
end


function _N:refreshIngestSession()
  local parsed_cookie = self:handleSession()

  if parsed_cookie.valid then
    ngx.ctx.NetaceaState.protector_result = {
      match = parsed_cookie.data.mat,
      mitigate = parsed_cookie.data.mit,
      captcha = parsed_cookie.data.cap
    }
    return parsed_cookie
  end

  if not ngx.ctx.NetaceaState.UserId then
    ngx.ctx.NetaceaState.UserId = netacea_cookies.newUserId()
  end

  self:refreshSession(parsed_cookie.reason)
  return parsed_cookie
end

function _N:mitigate()
  if not self.mitigationEnabled then
    if self.sessionEnabled then
      return self:refreshIngestSession()
    end
    return nil
  end
  local parsed_cookie = self:handleSession()

  if not parsed_cookie.valid then
    if not ngx.ctx.NetaceaState.UserId then
      ngx.ctx.NetaceaState.UserId = netacea_cookies.newUserId()
    end

    local protector_result = self.protectorClient:checkReputation()

    ngx.ctx.NetaceaState.protector_result = protector_result

    ngx.log(ngx.DEBUG, "NETACEA MITIGATE - protector result: ", cjson.encode(ngx.ctx.NetaceaState))

    local best_mitigation = mitigation.getBestMitigation(protector_result)

    if best_mitigation == 'captcha' then
      ngx.log(ngx.DEBUG, "NETACEA MITIGATE - serving captcha")
      local captchaBody = protector_result.response.body
      ngx.ctx.NetaceaState.grace_period = -1000
      self:refreshSession(parsed_cookie.reason)
      mitigation.serveCaptcha(captchaBody)
      return
    end

    if best_mitigation == 'block' then
      ngx.log(ngx.DEBUG, "NETACEA MITIGATE - serving block")
      ngx.ctx.NetaceaState.grace_period = -1000
      self:refreshSession(parsed_cookie.reason)
      mitigation.serveBlock()
      return
    end

    if best_mitigation == 'monetise' then
      ngx.log(ngx.DEBUG, "NETACEA MITIGATE - serving monetise")
      ngx.ctx.NetaceaState.grace_period = -1000
      self:refreshSession(parsed_cookie.reason)
      if protector_result.redirectHost then
        local redirect_location = "https://" .. protector_result.redirectHost .. ngx.var.request_uri
        mitigation.serveMonetisationRedirect(redirect_location)
      else
        mitigation.serveMonetisationFallback()
      end
      return
    end

    ngx.log(ngx.DEBUG, "NETACEA MITIGATE - no mitigation applied")
    self:refreshSession(parsed_cookie.reason)
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
