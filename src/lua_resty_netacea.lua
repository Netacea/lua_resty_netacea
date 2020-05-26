local _N = {}
local ngx = require 'ngx'
local cjson = require 'cjson'
local http = require 'resty.http'
local COOKIE_DELIMITER = '_/@#/'

local function buildResult(idType, mitigationType, captchaState)
  return {
    idType = idType or _N.idTypes.NONE,
    mitigationType = mitigationType or _N.mitigationTypes.NONE,
    captchaState = captchaState or _N.captchaStates.NONE
  }
end

local function serveCaptcha(captchaBody)
  ngx.status = ngx.HTTP_FORBIDDEN
  ngx.header["content-type"] = "text/html"
  ngx.print(captchaBody)
  return ngx.exit(ngx.HTTP_OK)
end

local function serveBlock()
  ngx.status = ngx.HTTP_FORBIDDEN;
  ngx.print("403 Forbidden");
  return ngx.exit(ngx.HTTP_FORBIDDEN);
end

function _N:new(options)
  local n = {}
  setmetatable(n, self)
  self.__index = self

  -- ingest:optional:ingestEnabled
  self.ingestEnabled = options.ingestEnabled or false
  -- ingest:required:ingestEndpoint
  self.ingestEndpoint = options.ingestEndpoint
  if not self.ingestEndpoint or self.ingestEndpoint == '' then
    self.ingestEnabled = false
  end
  -- mitigate:optional:mitigationEnabled
  self.mitigationEnabled = options.mitigationEnabled or false
  -- mitigate:required:mitigationEndpoint
  self.mitigationEndpoint = options.mitigationEndpoint
  if type(self.mitigationEndpoint) ~= 'table' then
    self.mitigationEndpoint = { self.mitigationEndpoint }
  end
  if not self.mitigationEndpoint[1] or self.mitigationEndpoint[1] == '' then
    self.mitigationEnabled = false
  end
  -- mitigate:required:secretKey
  self.secretKey = options.secretKey
  if not self.secretKey or self.secretKey == '' then
    self.mitigationEnabled = false
  end
  -- global:optional:realIpHeader
  self.realIpHeader = options.realIpHeader or ''
  -- global:optional:userIdKey
  self.userIdKey = options.userIdKey or ''
  -- global:required:apiKey
  self.apiKey = options.apiKey
  if not self.apiKey then
    self.ingestEnabled = false
    self.mitigationEnabled = false
  end

  self.endpointIndex = 0

  return n
end

function _N:getIpAddress(vars)
  if not self.realIpHeader then return vars.remote_addr end
  return vars['http_' .. self.realIpHeader] or vars.remote_addr
end

function _N:getMitigationRequestHeaders()
  local vars = ngx.var
  local requestMitata = vars.cookie__mitata or ''
  local requestMitataCaptcha = vars.cookie__mitatacaptcha or ''
  local cookie = '_mitata=' .. requestMitata .. ';_mitatacaptcha=' .. requestMitataCaptcha
  local headers = {
    ["x-netacea-api-key"] = self.apiKey,
    ["content-type"] = 'application/x-www-form-urlencoded',
    ["cookie"] = cookie,
    ["user-agent"] = vars.http_user_agent,
    ["x-netacea-client-ip"] = self:getIpAddress(vars)
  }

  if (self.userIdKey ~= '' and vars[self.userIdKey]) then
    headers['x-netacea-userid'] = vars[self.userIdKey]
  end

  return headers
end

function _N:validateCaptcha(onEventFunc)
  local hc = http:new()

  ngx.req.read_body()
  local payload = ngx.req.get_body_data()

  local headers = self:getMitigationRequestHeaders()

  self.endpointIndex = (self.endpointIndex + 1) % table.getn(self.mitigationEndpoint)

  local res, err = hc:request_uri(
    self.mitigationEndpoint[self.endpointIndex + 1] .. '/AtaVerifyCaptcha',
    {
      method = 'POST',
      headers = headers,
      timeout = 1000,
      body = payload
    }
  )
  if (err) then return nil end

  local mitataCaptchaVal = res.headers['x-netacea-mitatacaptcha-value'] or ''
  local mitataCaptchaExp = res.headers['x-netacea-mitatacaptcha-expiry'] or 0

  local idType = res.headers['x-netacea-match'] or self.idTypes.NONE
  local mitigationType = res.headers['x-netacea-mitigate'] or self.mitigationTypes.NONE
  local captchaState = res.headers['x-netacea-captcha'] or self.captchaStates.NONE

  self:addCookie('_mitatacaptcha', mitataCaptchaVal, mitataCaptchaExp)

  local exit_status = ngx.HTTP_FORBIDDEN
  if (captchaState == self.captchaStates.PASS) then
    exit_status = ngx.HTTP_OK

    local mitataVal = res.headers['x-netacea-mitata-value'] or ''
    local mitataExp = res.headers['x-netacea-mitata-expiry'] or 0
    self:addMitataCookie(mitataVal, mitataExp)
  end

  if onEventFunc then onEventFunc(buildResult(idType, mitigationType, captchaState)) end

  ngx.status = exit_status
  return ngx.exit(exit_status)
end

function _N:addMitataCookie(mitataVal, mitataExp)
  self:addCookie('_mitata', mitataVal, mitataExp)
  -- set to context so we can get this value for ingest service
  ngx.ctx.mitata = mitataVal
end

function _N:addCookie(name, value, expiry)
  local cookies = ngx.ctx.cookies or {};
  local expiryTime = ngx.cookie_time(ngx.time() + expiry)
  local newCookie = name .. '=' .. value .. '; Path=/; Expires=' .. expiryTime
  cookies[name] = newCookie
  ngx.ctx.cookies = cookies

  local setCookies = {}
  for _, val in pairs(cookies) do
    table.insert(setCookies, val)
  end
  ngx.header["Set-Cookie"] = setCookies
end

function _N:bToHex(b)
  local hex = ''
  for i = 1, #b do
    hex = hex .. string.format('%.2x', b:byte(i))
  end
  return hex
end

function _N:get_mitata_cookie()
  local mitata_cookie = ngx.var.cookie__mitata or ''
  if (mitata_cookie == '') then return nil end

  local hash, epoch, uid, mitigation_values = mitata_cookie:match(
    '(.*)' ..  COOKIE_DELIMITER .. '(.*)' ..  COOKIE_DELIMITER .. '(.*)' ..  COOKIE_DELIMITER .. '(.*)')
  epoch = tonumber(epoch)
  if (hash == nil or
    epoch == nil or
    uid == nil or
    uid == '' or
    mitigation_values == nil or
    mitigation_values == ''
  ) then
    return nil
  end

  if (ngx.time() > epoch) then
    return nil
  end

  local hmac = require 'openssl.hmac'
  local base64 = require('base64')
  local to_hash = epoch .. COOKIE_DELIMITER .. uid .. COOKIE_DELIMITER .. mitigation_values
  local our_hash = hmac.new(self.secretKey, 'sha256'):final(to_hash)
  our_hash = self:bToHex(our_hash)
  our_hash = base64.encode(our_hash)

  if (our_hash ~= hash) then
    return nil
  end

  return {
    original = mitata_cookie,
    hash = hash,
    epoch = epoch,
    uid = uid,
    mitigation = mitigation_values
  }
end

function _N:getMitigationResultFromService(onEventFunc)
  if not self.mitigationEnabled then return nil end
  local mitata_cookie = self:get_mitata_cookie()

  if (mitata_cookie) then
    local idType = string.sub(mitata_cookie.mitigation, 1, 1)
    local mitigationType = string.sub(mitata_cookie.mitigation, 2, 2)
    local captchaState = string.sub(mitata_cookie.mitigation, 3, 3)
    self:setBcType(idType, mitigationType, captchaState)
    if (mitigationType == _N.mitigationTypes.NONE) then return nil end

    if (captchaState ~= _N.captchaStates.SERVE) then
      if (captchaState == _N.captchaStates.PASS) then
        captchaState = _N.captchaStates.COOKIEPASS
      elseif (captchaState == _N.captchaStates.FAIL) then
        captchaState = _N.captchaStates.COOKIEFAIL
      end

      local shouldForwardToMitService = captchaState == _N.captchaStates.COOKIEFAIL
      if not shouldForwardToMitService then
        if onEventFunc then onEventFunc(buildResult(idType, mitigationType, captchaState)) end
        self:setBcType(idType, mitigationType, captchaState)
        return {
          match = idType,
          mitigate = mitigationType,
          captcha = captchaState,
          res = nil
        }
      end

    end
  end

  local hc = http:new()
  local headers = self:getMitigationRequestHeaders()

  self.endpointIndex = (self.endpointIndex + 1) % table.getn(self.mitigationEndpoint)

  local res, err = hc:request_uri(
   self.mitigationEndpoint[self.endpointIndex + 1],
    {
      method = 'GET',
      headers = headers,
      timeout = 1000
    }
  )
  if (err) then return nil end

  local mitataVal = res.headers['x-netacea-mitata-value'] or ''
  local mitataExp = res.headers['x-netacea-mitata-expiry'] or 0
  self:addMitataCookie(mitataVal, mitataExp)
  local match = res.headers['x-netacea-match'] or self.idTypes.NONE
  local mitigate = res.headers['x-netacea-mitigate'] or self.mitigationTypes.NONE
  local captcha = res.headers['x-netacea-captcha'] or self.captchaStates.NONE
  if onEventFunc then onEventFunc(buildResult(match, mitigate, captcha)) end
  self:setBcType(match, mitigate, captcha)
  return {
    match = match,
    mitigate = mitigate,
    captcha = captcha,
    res = res
  }
end

function _N:mitigate(onEventFunc)
  if not self.mitigationEnabled then return nil end
  local vars = ngx.var

  local captchaMatch = string.match(vars.request_uri, '.*AtaVerifyCaptcha.*')
  if captchaMatch then
    return self:validateCaptcha(onEventFunc)
  end
  local mitigationResult = self:getMitigationResultFromService(onEventFunc)
  if mitigationResult == nil then
    return nil
  end
  return self:getBestMitigation(mitigationResult.mitigate, mitigationResult.captcha, mitigationResult.res)
end

function _N:inject(onEventFunc)
  if not self.mitigationEnabled then return nil end
  local mitigationResult = self:getMitigationResultFromService(onEventFunc)
  if mitigationResult == nil then
    mitigationResult = {
      match = self.idTypes.NONE,
      mitigate = self.mitigationTypes.NONE,
      captcha = self.mitigationTypes.NONE
    }
  end
  ngx.req.set_header('x-netacea-match', mitigationResult.match)
  ngx.req.set_header('x-netacea-mitigate', mitigationResult.mitigate)
  ngx.req.set_header('x-netacea-captcha',  mitigationResult.captcha)
  return nil
end

function _N:getBestMitigation(mitigationType, captchaState, res)
  if (mitigationType == _N.mitigationTypes.NONE) then return nil end
  if (not _N.mitigationTypesText[mitigationType]) then return nil end

  if (mitigationType == _N.mitigationTypes.ALLOW) then return nil end
  if (captchaState == _N.captchaStates.PASS) then return nil end
  if (captchaState == _N.captchaStates.COOKIEPASS) then return nil end

  if (mitigationType == _N.mitigationTypes.BLOCKED and captchaState == _N.captchaStates.SERVE and res ~= nil) then
    return serveCaptcha(res.body)
  end

  return serveBlock()
end

function _N:setBcType(match, mitigate, captcha)
  local UNKNOWN = 'unknown'
  local mitigationApplied = ''

  if (match ~= '0') then
    mitigationApplied = mitigationApplied .. (self.matchBcTypes[match] or UNKNOWN) .. '_'
  end
  if (mitigate ~= '0') then
    mitigationApplied = mitigationApplied .. (self.mitigateBcTypes[mitigate] or UNKNOWN)
  end
  if (captcha ~= '0') then
    mitigationApplied = mitigationApplied .. ',' .. (self.captchaBcTypes[captcha] or UNKNOWN)
  end
  ngx.ctx.bc_type = mitigationApplied
  return mitigationApplied
end

function _N:ingest()
  if not self.ingestEnabled then return nil end
  local vars = ngx.var
  local mitata = ngx.ctx.mitata or vars.cookie__mitata or ''

  local data = {
    Request = vars.request_method .. " " .. vars.request_uri .. " " .. vars.server_protocol,
    TimeLocal = vars.msec * 1000,
    RealIp = self:getIpAddress(vars),
    UserAgent = vars.http_user_agent or "-",
    Status = vars.status,
    RequestTime = vars.request_time,
    BytesSent = vars.bytes_sent,
    Referer = vars.http_referer or "-",
    NetaceaUserIdCookie = mitata,
    NetaceaMitigationApplied = ngx.ctx.bc_type
  }

  local command = table.concat({
    "curl",
    "-X POST",
    "-m 5",
    "-s",
    "-o /dev/null",
  "-H 'Content-Type:application/json'",
    "-H 'x-netacea-api-key:" .. self.apiKey .. "'",
    "-d '" .. cjson.encode(data) .. "'",
    self.ingestEndpoint
  }, " ")

  os.execute(command .. " &")
end

_N['idTypesText'] = {}
_N['idTypes'] = {
  NONE = '0',
  UA = '1',
  IP = '2',
  VISITOR = '3',
  DATACENTER = '4',
  SEV = '5'
}

_N['mitigationTypesText'] = {}
_N['mitigationTypes'] = {
  NONE = '0',
  BLOCKED = '1',
  ALLOW = '2',
  HARDBLOCKED = '3'
}

_N['captchaStatesText'] = {}
_N['captchaStates'] = {
  NONE = '0',
  SERVE = '1',
  PASS = '2',
  FAIL = '3',
  COOKIEPASS = '4',
  COOKIEFAIL = '5'
}


_N['matchBcTypes'] = {
  ['1'] = 'ua',
  ['2'] = 'ip',
  ['3'] = 'visitor',
  ['4'] = 'datacenter',
  ['5'] = 'sev'
}

_N['mitigateBcTypes'] = {
  ['1'] = 'blocked',
  ['2'] = 'allow',
  ['3'] = 'hardblocked',
  ['4'] = 'block'
}

_N['captchaBcTypes'] = {
  ['1'] = 'captcha_serve',
  ['2'] = 'captcha_pass',
  ['3'] = 'captcha_fail',
  ['4'] = 'captcha_cookiepass',
  ['5'] = 'captcha_cookiefail'
}

local function reversifyTable(table)
  for k,v in pairs(_N[table]) do _N[table .. 'Text'][v] = k end
end

reversifyTable('idTypes')
reversifyTable('mitigationTypes')
reversifyTable('captchaStates')

return _N
