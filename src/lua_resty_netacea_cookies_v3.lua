local jwt = require "resty.jwt"
local ngx = require 'ngx'

local constants = require 'lua_resty_netacea_constants'
local utils = require 'netacea_utils'
local NetaceaCookies = {}
NetaceaCookies.__index = NetaceaCookies


function NetaceaCookies.decrypt(secretKey, value)
    local decoded = jwt:verify(secretKey, value)
    if not decoded.verified then
        return nil
    end
    return decoded.payload
end

function NetaceaCookies.encrypt(secretKey, payload)
    local encoded = jwt:sign(secretKey, {
        header={ typ="JWE", alg="dir", enc="A128CBC-HS256" },
        payload = payload
    })
    return encoded
end

function NetaceaCookies.newUserId()
    local randomBytes = utils.buildRandomString(15)
    return 'c'..randomBytes
end

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


function NetaceaCookies.generateNewCookieValue(secretKey, client, user_id, cookie_id, issue_reason, issue_timestamp, grace_period, match, mitigation, captcha, settings)
    local plaintext = ngx.encode_args({
        cip = client,
        uid = user_id,
        cid = cookie_id,
        isr = issue_reason,
        ist = issue_timestamp,
        grp = grace_period,
        mat = match or 0,
        mit = mitigation or 0,
        cap = captcha or 0,
        fCAPR = settings.fCAPR or 0
    })

    local encoded = NetaceaCookies.encrypt(secretKey, plaintext)
    
    return {
        mitata_jwe = encoded,
        mitata_plaintext = plaintext
    }
end

function NetaceaCookies.parseMitataCookie(cookie, secretKey)
    if not cookie or cookie == '' then
        return {
            valid = false,
            reason = constants['issueReasons'].NO_SESSION
        }
    end

    local decoded_str = NetaceaCookies.decrypt(secretKey, cookie)
    local decoded = ngx.decode_args(decoded_str)
    if not decoded then
        return {
            valid = false,
            reason = constants['issueReasons'].INVALID_SESSION
        }
    end

    if not decoded or type(decoded) ~= 'table' then
        return {
            valid = false,
            reason = constants['issueReasons'].INVALID_SESSION
        }
    end

    -- Check for required properties
    local required_fields = {'cip', 'uid', 'cid', 'isr', 'ist', 'grp', 'mat', 'mit', 'cap', 'fCAPR'}
    for _, field in ipairs(required_fields) do
        if not decoded[field] then
            return {
                valid = false,
                reason = constants['issueReasons'].INVALID_SESSION
            }
        end
    end

    if tonumber(decoded.ist) + tonumber(decoded.grp) < ngx.time() then
        return {
            valid = false,
            user_id = decoded.uid,
            reason = constants['issueReasons'].EXPIRED_SESSION
        }
    end

    if decoded.cip ~= ngx.ctx.NetaceaState.client then
        return {
            valid = false,
            user_id = decoded.uid,
            reason = constants['issueReasons'].IP_CHANGE
        }
    end

    return {
        valid = true,
        user_id = decoded.uid,
        data = decoded
    }
end

return NetaceaCookies