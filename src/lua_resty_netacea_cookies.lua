local NetaceaCookies = {}
NetaceaCookies.__index = NetaceaCookies

local COOKIE_DELIMITER = '_/@#/'

function NetaceaCookies.addCookie(name, value, expiry)
    ngx.log(ngx.ERR, 'Setting cookie: ' .. name .. '=' .. value .. ', expiry=' .. expiry)
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

function NetaceaCookies.buildMitataValToHash(hash, epoch, uid, mitigation_values)
  local unhashed = NetaceaCookies.buildNonHashedMitataVal(epoch, uid, mitigation_values)
  return hash .. COOKIE_DELIMITER .. unhashed
end

function NetaceaCookies.buildNonHashedMitataVal(epoch, uid, mitigation_values)
  return epoch .. COOKIE_DELIMITER .. uid .. COOKIE_DELIMITER .. mitigation_values
end

return NetaceaCookies