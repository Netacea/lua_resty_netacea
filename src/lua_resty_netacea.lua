local _N = {}
_N._VERSION = '0.2.0'
_N._TYPE = 'nginx'

local ngx = require 'ngx'
local cjson = require 'cjson'
local http = require 'resty.http'

local COOKIE_DELIMITER = '_/@#/'
local ONE_HOUR = 60 * 60
local ONE_DAY = ONE_HOUR * 24

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

local function buildRandomString(length)
  local chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
  local randomString = ''

  math.randomseed(os.time())

  local charTable = {}
  for c in chars:gmatch"." do
      table.insert(charTable, c)
  end

  for i=1, length do -- luacheck: ignore i
      randomString = randomString .. charTable[math.random(1, #charTable)]
  end

  return randomString
end

function _N:new(options)
  local n = {}
  setmetatable(n, self)
  self.__index = self

  -- ingest:optional:ingestEnabled
  n.ingestEnabled = options.ingestEnabled or false
  -- ingest:required:ingestEndpoint
  n.ingestEndpoint = options.ingestEndpoint
  if not n.ingestEndpoint or n.ingestEndpoint == '' then
    n.ingestEnabled = false
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
  n.mitigationType = options.mitigationType or ''
  if not n.mitigationType or (n.mitigationType ~= 'MITIGATE' and n.mitigationType ~= 'INJECT') then
    n.mitigationEnabled = false
  end
  -- mitigate:required:secretKey
  n.secretKey = options.secretKey
  if not n.secretKey or n.secretKey == '' then
    n.mitigationEnabled = false
  end
  -- global:optional:realIpHeader
  n.realIpHeader = options.realIpHeader or ''
  -- global:optional:userIdKey
  n.userIdKey = options.userIdKey or ''
  -- global:required:apiKey
  n.apiKey = options.apiKey
  if not n.apiKey then
    n.ingestEnabled = false
    n.mitigationEnabled = false
  end

  n.endpointIndex = 0
  n._MODULE_TYPE = _N._TYPE
  n._MODULE_VERSION = _N._VERSION

  _N:start_timers();

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

function _N:parseMitataCookie()
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

  return {
    mitata_cookie = mitata_cookie,
    hash = hash,
    epoch = epoch,
    uid = uid,
    mitigation_values = mitigation_values
  }
end

function _N:buildMitataValToHash(hash, epoch, uid, mitigation_values)
  local unhashed = self:buildNonHashedMitataVal(epoch, uid, mitigation_values)
  return hash .. COOKIE_DELIMITER .. unhashed
end

function _N:buildNonHashedMitataVal(epoch, uid, mitigation_values)
  return epoch .. COOKIE_DELIMITER .. uid .. COOKIE_DELIMITER .. mitigation_values
end

function _N:generateUid()
  local randomString = buildRandomString(15)
  return 'c' .. randomString
end

function _N:setIngestMitataCookie()
  local mitata_values = self:parseMitataCookie()
  local currentTime = ngx.time()
  local epoch = currentTime + ONE_HOUR
  local uid = self:generateUid()
  local mitigation_values = _N.idTypes.NONE .. _N.mitigationTypes.NONE .. _N.captchaStates.NONE
  local mitataExpiry = ONE_DAY

  local new_hash = self:hashMitataCookie(epoch, uid, mitigation_values)
  local mitataVal = self:buildMitataValToHash(new_hash, epoch, uid, mitigation_values)

  if (not mitata_values) then
    self:addMitataCookie(mitataVal, mitataExpiry)
    return nil
  end

  local our_hash = self:hashMitataCookie(mitata_values.epoch, mitata_values.uid, mitata_values.mitigation_values)

  if (our_hash ~= mitata_values.hash) then
    self:addMitataCookie(mitataVal, mitataExpiry)
    return nil
  end

  if (currentTime >= mitata_values.epoch) then
    uid = mitata_values.uid
    new_hash = self:hashMitataCookie(epoch, uid, mitigation_values)
    mitataVal = self:buildMitataValToHash(new_hash, epoch, uid, mitigation_values)
    self:addMitataCookie(mitataVal, mitataExpiry)
    return nil
  end

end

function _N:get_mitata_cookie()
  local mitata_values = self:parseMitataCookie()

  if (not mitata_values) then
    return nil
  end

  if (ngx.time() >= mitata_values.epoch) then
    return nil
  end

  local our_hash = self:hashMitataCookie(mitata_values.epoch, mitata_values.uid, mitata_values.mitigation_values)

  if (our_hash ~= mitata_values.hash) then
    return nil
  end

  return {
    original = mitata_values.mitata_cookie,
    hash = mitata_values.hash,
    epoch = mitata_values.epoch,
    uid = mitata_values.uid,
    mitigation = mitata_values.mitigation_values
  }
end

function _N:hashMitataCookie(epoch, uid, mitigation_values)
  local hmac = require 'openssl.hmac'
  local base64 = require('base64')
  local to_hash = self:buildNonHashedMitataVal(epoch, uid, mitigation_values)
  local hashed = hmac.new(self.secretKey, 'sha256'):final(to_hash)
  hashed = self:bToHex(hashed)
  hashed = base64.encode(hashed)

  return hashed
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

function _N:run(onEventFunc)
  if self.ingestEnabled and not self.mitigationEnabled then
    self:setIngestMitataCookie()
  end

  if self.mitigationEnabled then
    if self.mitigationType == 'MITIGATE' then
      self:mitigate(onEventFunc)
    elseif self.mitigationType == 'INJECT' then
      self:inject(onEventFunc)
    end
  end
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

----------------------------------------------------------------------
-- start STASH code to enable async HTTP requests from logging context

local function new_queue(size, allow_wrapping)
  -- Head is next insert, tail is next read
  local head, tail = 1, 1;
  local items = 0; -- Number of stored items
  local t = {}; -- Table to hold items
  return {
    _items = t;
    size = size;
    count = function (_) return items; end;
    push = function (_, item)
      if items >= size then
        if allow_wrapping then
          tail = (tail%size)+1; -- Advance to next oldest item
          items = items - 1;
        else
          return nil, "queue full";
        end
      end
      t[head] = item;
      items = items + 1;
      head = (head%size)+1;
      return true;
    end;
    pop = function (_)
      if items == 0 then
        return nil;
      end
      local item;
      item, t[tail] = t[tail], 0;
      tail = (tail%size)+1;
      items = items - 1;
      return item;
    end;
    peek = function (_)
      if items == 0 then
        return nil;
      end
      return t[tail];
    end;
    items = function (self)
      return function (pos)
        if pos >= t:count() then
          return nil;
        end
        local read_pos = tail + pos;
        if read_pos > t.size then
          read_pos = (read_pos%size);
        end
        return pos+1, t._items[read_pos];
      end, self, 0;
    end;
  };
end

local semaphore  = require "ngx.semaphore";

local async_queue_low_priority = new_queue(5000, true);
local queue_sema_low_priority  = semaphore.new();
local requests_sema            = semaphore.new();

requests_sema:post(1024); -- allow up to 1024 sending timer contexts

--------------------------------------------------------
-- start timers to execute requests tasks
local timers_running = false;

function _N:start_timers()

  if timers_running == true then return end

  -- start requests executor
  local executor;
  executor = function( premature )

    if premature then return end
    local execution_thread = ngx.thread.spawn( function()

      while true do
        while async_queue_low_priority:count() == 0 do
          if ngx.worker.exiting() == true then return end

          queue_sema_low_priority:wait(0.3); -- sleeping for 300 milliseconds
        end

        repeat
          if ngx.worker.exiting() == true then return end

          -- to make sure that there are only up to 1024 executor's timers at any time
          local ok, _ = requests_sema:wait(0.1);
        until ok and ok == true;

        local task = async_queue_low_priority:pop();
        if task then
          -- run tasks in separate timer contexts to avoid accumulating large numbers of dead corutines
          ngx.timer.at( 0, function()
            local ok, err = pcall( task );
            if not ok and err then
              ngx.log( ngx.ERR, "NETACEA API - sending task has failed with error: ", err );
            end

            local cnt = 1;

            while async_queue_low_priority:count() > 0 and cnt < 100 do

              local next_task = async_queue_low_priority:pop();

              if not next_task then
                queue_sema_low_priority:wait(0.3); -- sleeping for 300 milliseconds
                next_task = async_queue_low_priority:pop();
              end

              if next_task then
                ok, err = pcall( next_task );
                if not ok and err then
                  ngx.log( ngx.ERR, "NETACEA - sending task has failed with error: ", err );
                else
                  ngx.sleep(0.01);
                end
              else
                if queue_sema_low_priority:count() > async_queue_low_priority:count() then
                  queue_sema_low_priority:wait(0)
                end
                break;
              end

              cnt = cnt + 1;
            end

            requests_sema:post(1);
          end );
        else -- semaphore is out of sync with queue - need to drain it
          if queue_sema_low_priority:count() > async_queue_low_priority:count() then
            queue_sema_low_priority:wait(0)
          end
          requests_sema:post(1);
        end

      end
    end );

    local ok, err = ngx.thread.wait( execution_thread );
    if not ok and err then
      ngx.log( ngx.ERR, "NETACEA - executor thread has failed with error: ", err );
    end

    -- If the worker is exiting, don't queue another executor
    if ngx.worker.exiting() then
      return
    end

    ngx.timer.at( 0, executor );
  end

  ngx.timer.at( 0, executor );

  timers_running = true;
end
-- end STASH code

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
    NetaceaMitigationApplied = ngx.ctx.bc_type,
    IntegrationType = self._MODULE_TYPE,
    IntegrationVersion = self._MODULE_VERSION
  }

  -- start STASH code
  local request_params = {};

  request_params.body  = cjson.encode(data);
  request_params.method  = "POST";
  request_params.headers = {
    ["Content-Length"] = #request_params.body,
    ["Content-Type"] = "application/json",
    ["x-netacea-api-key"] = self.apiKey;
  };
  request_params.timeout = 1000; -- 1 second

  local request_task = function()
    local hc = http:new();

    local res, err = hc:request_uri( self.ingestEndpoint, request_params );

    if not res and err then
      ngx.log( ngx.ERR, "Netacea ingest - failed API request - error: ", err );
      return;
    else
      if res.status ~= 200 and res.status ~= 201 then
        ngx.log( ngx.ERR, "Netacea ingest - failed API request - status: ", res.status );
        return;
      end
    end
  end

  -- request_params are not going to get deallocated as long as function stays in the queue
  local ok, _ = async_queue_low_priority:push( request_task );
  if ok then queue_sema_low_priority:post(1) end

  -- end STASH code
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
