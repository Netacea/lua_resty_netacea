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


return NetaceaCookies