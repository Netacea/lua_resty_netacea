local Kinesis = require("kinesis_resty")

local _N = {}
_N._VERSION = '0.2.2'
_N._TYPE = 'nginx'

local ngx = require 'ngx'
local cjson = require 'cjson'
local http = require 'resty.http'

local COOKIE_DELIMITER = '_/@#/'
local ONE_HOUR = 60 * 60
local ONE_DAY = ONE_HOUR * 24

local function createHttpConnection()
  local hc = http:new()

  -- hc will be nil on error
  if hc then
    -- syntax: httpc:set_timeouts(connect_timeout, send_timeout, read_timeout)
    hc:set_timeouts(500, 750, 750)
  end

  return hc
end

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
  self.ingestEnabled = options.ingestEnabled or false
  -- ingest:required:ingestEndpoint
  self.ingestEndpoint = options.ingestEndpoint
  if not self.ingestEndpoint or self.ingestEndpoint == '' then
    self.ingestEnabled = false
  end
  self.kinesisProperties = options.kinesisProperties or nil
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
  -- mitigate:required:mitigationType
  self.mitigationType = options.mitigationType or ''
  if not self.mitigationType or (self.mitigationType ~= 'MITIGATE' and self.mitigationType ~= 'INJECT') then
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
  self._MODULE_TYPE = _N._TYPE
  self._MODULE_VERSION = _N._VERSION

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
  local hc = createHttpConnection()

  ngx.req.read_body()
  local payload = ngx.req.get_body_data()

  local headers = self:getMitigationRequestHeaders()

  self.endpointIndex = (self.endpointIndex + 1) % table.getn(self.mitigationEndpoint)

  local res, err = hc:request_uri(
    self.mitigationEndpoint[self.endpointIndex + 1] .. '/AtaVerifyCaptcha',
    {
      method = 'POST',
      headers = headers,
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

  local hc = createHttpConnection()

  local headers = self:getMitigationRequestHeaders()

  self.endpointIndex = (self.endpointIndex + 1) % table.getn(self.mitigationEndpoint)

  local res, err = hc:request_uri(
   self.mitigationEndpoint[self.endpointIndex + 1],
    {
      method = 'GET',
      headers = headers
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

---------------------------------------------------------
-- Async ingest from logging context

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

-- Data queue for batch processing
local data_queue = new_queue(5000, true);
local dead_letter_queue = new_queue(1000, true);
local BATCH_SIZE = 25; -- Kinesis PutRecords supports up to 500 records, using 25 for more frequent sends
local BATCH_TIMEOUT = 1.0; -- Send batch after 1 second even if not full

--------------------------------------------------------
-- start batch processor for Kinesis data

function _N:start_timers()

  -- start batch processor
  local batch_processor;
  batch_processor = function( premature )

    if premature then return end
    
    local execution_thread = ngx.thread.spawn( function()
      local batch = {}
      local last_send_time = ngx.now()

      while true do
        -- Check if worker is exiting
        if ngx.worker.exiting() == true then 
          -- Send any remaining data before exiting
          if #batch > 0 then
            self:send_batch_to_kinesis(batch)
          end
          return 
        end

        local current_time = ngx.now()
        local should_send_batch = false

        -- Check dead_letter_queue first
        while dead_letter_queue:count() > 0 and #batch < BATCH_SIZE do
          local dlq_item = dead_letter_queue:pop()
          if dlq_item then
            table.insert(batch, dlq_item)
          end
        end

        -- Collect data items for batch
        while data_queue:count() > 0 and #batch < BATCH_SIZE do
          local data_item = data_queue:pop()
          if data_item then
            table.insert(batch, data_item)
          end
        end

        -- Determine if we should send the batch
        if #batch >= BATCH_SIZE then
          should_send_batch = true
          ngx.log(ngx.DEBUG, "NETACEA BATCH - sending full batch of ", #batch, " items")
        elseif #batch > 0 and (current_time - last_send_time) >= BATCH_TIMEOUT then
          should_send_batch = true
          ngx.log(ngx.DEBUG, "NETACEA BATCH - sending timeout batch of ", #batch, " items")
        end

        -- Send batch if conditions are met
        if should_send_batch then
          self:send_batch_to_kinesis(batch)
          batch = {}  -- Reset batch
          last_send_time = current_time
        end

        -- Sleep briefly if no data to process
        if data_queue:count() == 0 then
          ngx.sleep(0.1)
        end
      end
    end )

    local ok, err = ngx.thread.wait( execution_thread );
    if not ok and err then
      ngx.log( ngx.ERR, "NETACEA - batch processor thread has failed with error: ", err );
    end

    -- If the worker is exiting, don't queue another processor
    if ngx.worker.exiting() then
      return
    end

    ngx.timer.at( 0, batch_processor );
  end

  ngx.timer.at( 0, batch_processor );

end

function _N:send_batch_to_kinesis(batch)
  if not batch or #batch == 0 then return end
  
  local client = Kinesis.new(
      self.kinesisProperties.stream_name,
      self.kinesisProperties.region,
      self.kinesisProperties.aws_access_key,
      self.kinesisProperties.aws_secret_key
  )

  -- Convert batch data to Kinesis records format
  local records = {}
  for _, data_item in ipairs(batch) do
    table.insert(records, {
      partition_key = buildRandomString(10),
      data = "[" .. cjson.encode(data_item) .. "]"
    })
  end

  ngx.log( ngx.DEBUG, "NETACEA BATCH - sending batch of ", #records, " records to Kinesis stream ", self.kinesisProperties.stream_name );

  local res, err = client:put_records(records)
  if err then
    ngx.log( ngx.ERR, "NETACEA BATCH - error sending batch to Kinesis: ", err );
    for _, record in ipairs(records) do
      local ok, dlq_err = dead_letter_queue:push(record)
      if not ok and dlq_err then
        ngx.log( ngx.ERR, "NETACEA BATCH - failed to push record to dead letter queue: ", dlq_err );
      end
    end
  else
    ngx.log( ngx.DEBUG, "NETACEA BATCH - successfully sent batch to Kinesis, response status: ", res.status .. ", body: " .. (res.body or '') );
  end

end

function _N:ingest()
  if not self.ingestEnabled then return nil end
  local vars = ngx.var
  local mitata = ngx.ctx.mitata or vars.cookie__mitata or ''

  local data = {
    Request = vars.request_method .. " " .. vars.request_uri .. " " .. vars.server_protocol,
    TimeLocal = vars.time_local,
    TimeUnixMsUTC = vars.msec * 1000,
    RealIp = self:getIpAddress(vars),
    UserAgent = vars.http_user_agent or "-",
    Status = vars.status,
    RequestTime = vars.request_time,
    BytesSent = vars.bytes_sent,
    Referer = vars.http_referer or "-",
    NetaceaUserIdCookie = mitata,
    NetaceaMitigationApplied = ngx.ctx.bc_type,
    IntegrationType = self._MODULE_TYPE,
    IntegrationVersion = self._MODULE_VERSION,
    Query = vars.query_string or "",
    RequestHost = vars.host or "-",
    RequestId = vars.request_id or "-",
    ProtectionMode = self.mitigationType or "ERROR",
    -- TODO
    BytesReceived = vars.bytes_received or 0, -- Doesn't seem to work
    NetaceaUserIdCookieStatus = 1,
    Optional = {}
  }

  -- Add data directly to the queue for batch processing
  local ok, err = data_queue:push(data)
  if not ok and err then
    ngx.log(ngx.WARN, "NETACEA INGEST - failed to queue data: ", err)
  else
    ngx.log(ngx.DEBUG, "NETACEA INGEST - queued data item, queue size: ", data_queue:count())
  end

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
