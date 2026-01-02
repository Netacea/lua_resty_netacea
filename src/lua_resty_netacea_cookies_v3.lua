local jwt = require "resty.jwt"
local ngx = require 'ngx'

local constants = require 'lua_resty_netacea_constants'

local NetaceaCookies = {}
NetaceaCookies.__index = NetaceaCookies

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

    local encoded = jwt:sign(secretKey, {
        header={ typ="JWE", alg="dir", enc="A128CBC-HS256" },
        payload = plaintext
    })
    
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

    local decoded = jwt:verify(secretKey, cookie)
    if not decoded.verified then
        return {
            valid = false,
            reason = constants['issueReasons'].INVALID_SESSION
        }
    end

    local result = ngx.decode_args(decoded.payload)
    if not result or type(result) ~= 'table' then
        return {
            valid = false,
            reason = constants['issueReasons'].INVALID_SESSION
        }
    end

    -- Check for required properties
    local required_fields = {'cip', 'uid', 'cid', 'isr', 'ist', 'grp', 'mat', 'mit', 'cap', 'fCAPR'}
    for _, field in ipairs(required_fields) do
        if not result[field] then
            return {
                valid = false,
                reason = constants['issueReasons'].INVALID_SESSION
            }
        end
    end

    if tonumber(result.ist) + tonumber(result.grp) < ngx.time() then
        return {
            valid = false,
            user_id = result.uid,
            reason = constants['issueReasons'].EXPIRED_SESSION
        }
    end

    if result.cip ~= ngx.ctx.NetaceaState.client then
        return {
            valid = false,
            user_id = result.uid,
            reason = constants['issueReasons'].IP_CHANGE
        }
    end

    return {
        valid = true,
        user_id = result.uid,
        data = result
    }
end

return NetaceaCookies