local http = require 'resty.http'
local constants = require 'lua_resty_netacea_constants'

local ProtectorClient = {}
ProtectorClient.__index = ProtectorClient

local function createHttpConnection()
  local hc = http:new()

  -- hc will be nil on error
  if hc then
    -- syntax: httpc:set_timeouts(connect_timeout, send_timeout, read_timeout)
    hc:set_timeouts(500, 750, 750)
  end

  return hc
end

function ProtectorClient:new(options)
    local n = {}
    setmetatable(n, self)
    
    n.apiKey = options.apiKey
    n.mitigationEndpoint = options.mitigationEndpoint or {}
    n.endpointIndex = 0

    return n
end

function ProtectorClient:getMitigationRequestHeaders()
    local NetaceaState = ngx.ctx.NetaceaState

    local cookie = ''
    if NetaceaState ~= nil and NetaceaState.captcha_cookie ~= nil then
        cookie = '_mitatacaptcha=' .. NetaceaState.captcha_cookie
    end

    local headers = {
        ["x-netacea-api-key"] = self.apiKey,
        ["content-type"] = 'application/x-www-form-urlencoded',
        ["cookie"] = cookie,
        ["user-agent"] = NetaceaState.user_agent or '',
        ["x-netacea-client-ip"] = NetaceaState.client or '',
        ['x-netacea-userid'] = NetaceaState.UserId or ''
    }

    return headers
end

function ProtectorClient:checkReputation()
    local headers = self:getMitigationRequestHeaders()
    local hc = createHttpConnection()
    ngx.log(ngx.ERR, 'Netacea mitigation headers: ' .. require('cjson').encode(headers))
    self.endpointIndex = (self.endpointIndex + 1) % table.getn(self.mitigationEndpoint)

    local res, err = hc:request_uri(
        self.mitigationEndpoint[self.endpointIndex + 1],
        {
        method = 'GET',
        headers = headers
        }
    )
    if (err) then return nil end

    local result = {
        response = {
            status = res.status,
            body = res.body,
            headers = res.headers
        },
        match = res['headers']['x-netacea-match'] or constants['idTypes'].NONE,
        mitigate = res['headers']['x-netacea-mitigate'] or constants['mitigationTypes'].NONE,
        captcha = res['headers']['x-netacea-captcha'] or constants['captchaStates'].NONE
    }
    return result
end

function ProtectorClient:validateCaptcha(captcha_data)
    local hc = createHttpConnection()

  local headers = self:getMitigationRequestHeaders()

  self.endpointIndex = (self.endpointIndex + 1) % table.getn(self.mitigationEndpoint)

  local res, err = hc:request_uri(
    self.mitigationEndpoint[self.endpointIndex + 1] .. '/AtaVerifyCaptcha',
    {
      method = 'POST',
      headers = headers,
      body = captcha_data
    }
  )
  if (err) then return nil end

  local idType = res.headers['x-netacea-match'] or constants['idTypes'].NONE
  local mitigationType = res.headers['x-netacea-mitigate'] or constants['mitigationTypes'].NONE
  local captchaState = res.headers['x-netacea-captcha'] or constants['captchaStates'].NONE

  ngx.log(ngx.ERR, 'Netacea captcha validation response: match=' .. idType .. ', mitigate=' .. mitigationType .. ', captcha=' .. captchaState)
  
  local exit_status = ngx.HTTP_FORBIDDEN
  if (captchaState == constants['captchaStates'].PASS) then
    exit_status = ngx.HTTP_OK
    
  end
    return {
        response = {
            status = res.status,
            body = res.body,
            headers = res.headers
        },
        match = idType,
        mitigate = mitigationType,
        captcha = captchaState,
        exit_status = exit_status,
        captcha_cookie = res.headers['X-Netacea-MitATACaptcha-Value'] or nil
    }
end


return ProtectorClient