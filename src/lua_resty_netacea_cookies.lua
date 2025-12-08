--- Netacea Cookie Management Module
-- This module provides functionality for creating, parsing, and validating
-- Netacea mitata cookies used for user identification and mitigation state tracking.
-- 
-- The mitata cookie format uses a cryptographically signed structure:
-- hash_/@#/_epoch_/@#/_uid_/@#/_mitigation_values
--
-- Key features:
-- - Cookie creation with proper HTTP formatting and expiration
-- - Cryptographic validation using HMAC-SHA256
-- - Parsing of complex mitata cookie structures
-- - Time-based expiration handling
-- 
-- @module NetaceaCookies
-- @author Netacea
-- @version 0.2

local NetaceaCookies = {}
NetaceaCookies.__index = NetaceaCookies

local COOKIE_DELIMITER = '_/@#/'
local ONE_HOUR = 60 * 60
local ONE_DAY = ONE_HOUR * 24


--- Creates a formatted HTTP cookie string with expiration
-- @param name string The cookie name
-- @param value string The cookie value  
-- @param expiry number The expiry time in seconds from now
-- @return table Array of formatted cookie strings ready for Set-Cookie header
function NetaceaCookies.createSetCookieValues(name, value, expiry)
    local cookies = ngx.ctx.cookies or {};
    local expiryTime = ngx.cookie_time(ngx.time() + tonumber(expiry))
    local newCookie = name .. '=' .. value .. '; Path=/; Expires=' .. expiryTime
    cookies[name] = newCookie
    ngx.ctx.cookies = cookies

    local setCookies = {}
    for _, val in pairs(cookies) do
        table.insert(setCookies, val)
    end
    return setCookies
end

--- Parses a Netacea mitata cookie value into its components
-- @param mitata_cookie string The raw mitata cookie value
-- @return table|nil Parsed cookie components or nil if invalid
--   - mitata_cookie: original cookie string
--   - hash: the hash portion
--   - epoch: expiration timestamp  
--   - uid: user identifier
--   - mitigation_values: mitigation state values
function NetaceaCookies.parseMitataCookie(mitata_cookie)
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

--- Validates a mitata cookie against its cryptographic signature
-- @param secretKey string Secret key used for HMAC validation
-- @param mitata_cookie string Raw mitata cookie value to validate
-- @return table|nil Validated cookie data or nil if invalid/expired
--   - original: original cookie string
--   - hash: hash portion
--   - epoch: expiration timestamp
--   - uid: user identifier  
--   - mitigation: mitigation values string
function NetaceaCookies.validateMitataCookie(secretKey, mitata_cookie)
  local mitata_values = NetaceaCookies.parseMitataCookie(mitata_cookie)

  -- Invalid cookie format
  if (not mitata_values) then
    return nil
  end

  -- Expired cookie
  if (ngx.time() >= mitata_values.epoch) then
    return nil
  end

  -- Invalid hash
  local our_hash = NetaceaCookies.hashMitataCookie(secretKey, mitata_values.epoch, mitata_values.uid, mitata_values.mitigation_values)
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

--- Validates a Mitata cookie using the provided secret key.
-- This function verifies the integrity and authenticity of a Mitata cookie
-- by validating it against the given secret key.
--
-- @param secretKey string The secret key used for cookie validation
-- @param mitata_cookie string The Mitata cookie value to be validated
-- @return table Returns table of cookie properties including:
--   - valid: boolean indicating if the cookie is valid
--   - uid: string User identifier from the cookie (nil if invalid)
--   - mitata_cookie: string The (possibly new) Mitata cookie value
--   - expiry: number Time in seconds until cookie expiry
-- @usage
--   local mitata = NetaceaCookies.validateIngestMitataCookie(secret, cookie)
--   if mitata and mitata.valid then
--     -- Cookie is valid, proceed with request
--   end
function NetaceaCookies.validateIngestMitataCookie(secretKey, mitata_cookie)
  local mitata_values = NetaceaCookies.parseMitataCookie(mitata_cookie)
  local currentTime = ngx.time()
  local epoch = currentTime + ONE_HOUR
  local uid = NetaceaCookies.generateUserid()
  local mitigation_values = NetaceaCookies.idTypes.NONE .. NetaceaCookies.mitigationTypes.NONE .. NetaceaCookies.captchaStates.NONE
  local mitataExpiry = ONE_DAY

  -- Invalid cookie format
  if (not mitata_values) then
    local new_hash = NetaceaCookies.hashMitataCookie(secretKey, epoch, uid, mitigation_values)
    local mitataVal = NetaceaCookies.buildMitataValToHash(new_hash, epoch, uid, mitigation_values)
    return {
      valid = false,
      uid = nil,
      mitata_cookie = mitataVal,
      expiry = mitataExpiry
    }
  end

  -- Invalid hash
  local our_hash = NetaceaCookies.hashMitataCookie(secretKey, mitata_values.epoch, mitata_values.uid, mitata_values.mitigation_values)
  if (our_hash ~= mitata_values.hash) then
    local new_hash = NetaceaCookies.hashMitataCookie(secretKey, epoch, uid, mitigation_values)
    local mitataVal = NetaceaCookies.buildMitataValToHash(new_hash, epoch, uid, mitigation_values)
    return {
      valid = false,
      uid = nil,
      mitata_cookie = mitataVal,
      expiry = mitataExpiry
    }
  end

  if (ngx.time() >= mitata_values.epoch) then
    uid = mitata_values.uid
    local new_hash = NetaceaCookies.hashMitataCookie(secretKey, epoch, uid, mitigation_values)
    local mitataVal = NetaceaCookies.buildMitataValToHash(new_hash, epoch, uid, mitigation_values)
    return {
      valid = false,
      uid = mitata_values.uid,
      mitata_cookie = mitataVal,
      expiry = mitataExpiry
    }
  end

  return {
    valid = true,
    uid = mitata_values.uid,
    mitata_cookie = mitata_cookie,
    expiry = mitata_values.epoch - currentTime
  }
end

--- Builds a complete mitata cookie value with hash prefix
-- @param hash string The hash value to prefix
-- @param epoch number Expiration timestamp
-- @param uid string User identifier
-- @param mitigation_values string Mitigation state values
-- @return string Complete mitata cookie value with hash
function NetaceaCookies.buildMitataValToHash(hash, epoch, uid, mitigation_values)
  local unhashed = NetaceaCookies.buildNonHashedMitataVal(epoch, uid, mitigation_values)
  return hash .. COOKIE_DELIMITER .. unhashed
end

--- Builds the non-hashed portion of a mitata cookie value
-- @param epoch number Expiration timestamp
-- @param uid string User identifier
-- @param mitigation_values string Mitigation state values
-- @return string Non-hashed mitata cookie components joined by delimiter
function NetaceaCookies.buildNonHashedMitataVal(epoch, uid, mitigation_values)
  return epoch .. COOKIE_DELIMITER .. uid .. COOKIE_DELIMITER .. mitigation_values
end

--- Converts binary data to hexadecimal string representation
-- @param b string Binary data to convert
-- @return string Hexadecimal representation
function NetaceaCookies.bToHex(b)
  local hex = ''
  for i = 1, #b do
    hex = hex .. string.format('%.2x', b:byte(i))
  end
  return hex
end

--- Creates a cryptographic hash of mitata cookie components
-- @param secretKey string Secret key for HMAC
-- @param epoch number Expiration timestamp
-- @param uid string User identifier
-- @param mitigation_values string Mitigation state values
-- @return string Base64-encoded hash
function NetaceaCookies.hashMitataCookie(secretKey, epoch, uid, mitigation_values)
  local hmac = require 'openssl.hmac'
  local base64 = require('base64')
  local to_hash = NetaceaCookies.buildNonHashedMitataVal(epoch, uid, mitigation_values)
  local hashed = hmac.new(secretKey, 'sha256'):final(to_hash)
  hashed = NetaceaCookies.bToHex(hashed)
  hashed = base64.encode(hashed)

  return hashed
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

function NetaceaCookies.generateUserid()
  local randomString = buildRandomString(15)
  return 'c' .. randomString
end


NetaceaCookies['idTypesText'] = {}
NetaceaCookies['idTypes'] = {
  NONE = '0',
  UA = '1',
  IP = '2',
  VISITOR = '3',
  DATACENTER = '4',
  SEV = '5'
}

NetaceaCookies['mitigationTypesText'] = {}
NetaceaCookies['mitigationTypes'] = {
  NONE = '0',
  BLOCKED = '1',
  ALLOW = '2',
  HARDBLOCKED = '3'
}

NetaceaCookies['captchaStatesText'] = {}
NetaceaCookies['captchaStates'] = {
  NONE = '0',
  SERVE = '1',
  PASS = '2',
  FAIL = '3',
  COOKIEPASS = '4',
  COOKIEFAIL = '5'
}


NetaceaCookies['matchBcTypes'] = {
  ['1'] = 'ua',
  ['2'] = 'ip',
  ['3'] = 'visitor',
  ['4'] = 'datacenter',
  ['5'] = 'sev'
}

NetaceaCookies['mitigateBcTypes'] = {
  ['1'] = 'blocked',
  ['2'] = 'allow',
  ['3'] = 'hardblocked',
  ['4'] = 'block'
}

NetaceaCookies['captchaBcTypes'] = {
  ['1'] = 'captcha_serve',
  ['2'] = 'captcha_pass',
  ['3'] = 'captcha_fail',
  ['4'] = 'captcha_cookiepass',
  ['5'] = 'captcha_cookiefail'
}



return NetaceaCookies