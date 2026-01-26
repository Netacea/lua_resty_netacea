require("silence_g_write_guard")
require 'busted.runner'()

package.path = "../src/?.lua;" .. package.path
local match = require("luassert.match")

describe("lua_resty_netacea_cookies_v3", function()
    local NetaceaCookies
    local jwt_mock
    local ngx_mock
    local constants_mock

    before_each(function()
        -- Mock jwt module
        jwt_mock = {
            sign = spy.new(function(self, secretKey, payload)
                return "mock_jwt_token_" .. secretKey
            end),
            verify = spy.new(function(self, secretKey, token)
                if token == "valid_token" then
                    return {
                        verified = true,
                        payload = "cip=192.168.1.1&uid=user123&cid=cookie123&isr=no_session&ist=1640995200&grp=3600&mat=0&mit=0&cap=0&fCAPR=0"
                    }
                elseif token == "expired_token" then
                    return {
                        verified = true,
                        payload = "cip=192.168.1.1&uid=user123&cid=cookie123&isr=no_session&ist=1000000000&grp=3600&mat=0&mit=0&cap=0&fCAPR=0"
                    }
                elseif token == "ip_mismatch_token" then
                    return {
                        verified = true,
                        payload = "cip=10.0.0.1&uid=user123&cid=cookie123&isr=no_session&ist=1640995200&grp=3600&mat=0&mit=0&cap=0&fCAPR=0"
                    }
                elseif token == "missing_fields_token" then
                    return {
                        verified = true,
                        payload = "cip=192.168.1.1&uid=user123"
                    }
                elseif token == "invalid_payload_token" then
                    return {
                        verified = true,
                        payload = "invalid_payload_format"
                    }
                else
                    return {
                        verified = false
                    }
                end
            end)
        }

        -- Mock ngx module
        ngx_mock = {
            ctx = {
                cookies = nil,
                NetaceaState = {
                    client = "192.168.1.1"
                }
            },
            time = spy.new(function() return 1640995200 end), -- Fixed timestamp
            cookie_time = spy.new(function(timestamp) 
                return "Thu, 01 Jan 2022 00:00:00 GMT" 
            end),
            encode_args = spy.new(function(args)
                local parts = {}
                for k, v in pairs(args) do
                    table.insert(parts, k .. "=" .. tostring(v))
                end
                return table.concat(parts, "&")
            end),
            decode_args = spy.new(function(str)
                if str == "invalid_payload_format" then
                    return nil
                end
                local result = {}
                for pair in str:gmatch("[^&]+") do
                    local key, value = pair:match("([^=]+)=([^=]*)")
                    if key and value then
                        result[key] = value
                    end
                end
                return result
            end)
        }

        -- Import actual constants
        local constants = require('lua_resty_netacea_constants')

        -- Set up package mocks
        package.loaded['resty.jwt'] = jwt_mock
        package.loaded['ngx'] = ngx_mock
        package.loaded['lua_resty_netacea_constants'] = constants

        NetaceaCookies = require('lua_resty_netacea_cookies_v3')
    end)

    after_each(function()
        -- Clear mocks and cached modules
        package.loaded['lua_resty_netacea_cookies_v3'] = nil
        package.loaded['resty.jwt'] = nil
        package.loaded['ngx'] = nil
        package.loaded['lua_resty_netacea_constants'] = nil
        
        -- Reset ngx context
        ngx_mock.ctx.cookies = nil
    end)

    describe("createSetCookieValues", function()
        it("should create a properly formatted cookie string", function()
            local result = NetaceaCookies.createSetCookieValues("test_cookie", "test_value", 3600)
            
            assert.is.table(result)
            assert.is.equal(1, #result)
            assert.is.equal("test_cookie=test_value; Path=/; Expires=Thu, 01 Jan 2022 00:00:00 GMT", result[1])
            
            assert.spy(ngx_mock.time).was.called()
            assert.spy(ngx_mock.cookie_time).was.called_with(1640995200 + 3600)
        end)

        it("should store cookie in ngx.ctx.cookies", function()
            NetaceaCookies.createSetCookieValues("test_cookie", "test_value", 3600)
            
            assert.is.table(ngx_mock.ctx.cookies)
            assert.is.equal("test_cookie=test_value; Path=/; Expires=Thu, 01 Jan 2022 00:00:00 GMT", 
                           ngx_mock.ctx.cookies["test_cookie"])
        end)

        it("should handle multiple cookies", function()
            NetaceaCookies.createSetCookieValues("cookie1", "value1", 3600)
            local result = NetaceaCookies.createSetCookieValues("cookie2", "value2", 7200)
            
            assert.is.equal(2, #result)
            assert.is.table(ngx_mock.ctx.cookies)
            assert.is.truthy(ngx_mock.ctx.cookies["cookie1"])
            assert.is.truthy(ngx_mock.ctx.cookies["cookie2"])
        end)

        it("should handle existing cookies in context", function()
            ngx_mock.ctx.cookies = {
                existing_cookie = "existing_cookie=existing_value; Path=/; Expires=Thu, 01 Jan 2022 00:00:00 GMT"
            }
            
            local result = NetaceaCookies.createSetCookieValues("new_cookie", "new_value", 3600)
            
            assert.is.equal(2, #result)
        end)

        it("should handle zero expiry time", function()
            local result = NetaceaCookies.createSetCookieValues("test_cookie", "test_value", 0)
            
            assert.is.table(result)
            assert.is.equal(1, #result)
            assert.spy(ngx_mock.cookie_time).was.called_with(1640995200)
        end)

        it("should convert expiry to number", function()
            local result = NetaceaCookies.createSetCookieValues("test_cookie", "test_value", "3600")
            
            assert.is.table(result)
            assert.spy(ngx_mock.cookie_time).was.called_with(1640995200 + 3600)
        end)
    end)

    describe("generateNewCookieValue", function()
        it("should generate a new cookie value with all parameters", function()
            local _ = match._
            local settings = { fCAPR = 1 }
            local result = NetaceaCookies.generateNewCookieValue(
                "secret_key", 
                "192.168.1.1", 
                "user123", 
                "cookie123", 
                "no_session", 
                1640995200, 
                3600, 
                1, 
                2, 
                3, 
                settings
            )
            
            assert.is.table(result)
            assert.is.string(result.mitata_jwe)
            assert.is.string(result.mitata_plaintext)
            assert.is.equal("mock_jwt_token_secret_key", result.mitata_jwe)
            
            assert.spy(ngx_mock.encode_args).was.called()
            assert.spy(jwt_mock.sign).was.called_with(match.is_not_nil(), "secret_key", {
                header = { typ="JWE", alg="dir", enc="A128CBC-HS256" },
                payload = "ist=1640995200&mit=2&isr=no_session&cip=192.168.1.1&grp=3600&uid=user123&fCAPR=1&cid=cookie123&cap=3&mat=1"
            })
        end)

        it("should use default values for optional parameters", function()
            local settings = {}
            local result = NetaceaCookies.generateNewCookieValue(
                "secret_key", 
                "192.168.1.1", 
                "user123", 
                "cookie123", 
                "no_session", 
                1640995200, 
                3600, 
                nil, -- match
                nil, -- mitigation
                nil, -- captcha
                settings
            )
            
            assert.is.table(result)
            assert.spy(ngx_mock.encode_args).was.called_with({
                cip = "192.168.1.1",
                uid = "user123",
                cid = "cookie123",
                isr = "no_session",
                ist = 1640995200,
                grp = 3600,
                mat = 0,
                mit = 0,
                cap = 0,
                fCAPR = 0
            })
        end)

        it("should handle empty settings", function()
            local result = NetaceaCookies.generateNewCookieValue(
                "secret_key", 
                "192.168.1.1", 
                "user123", 
                "cookie123", 
                "no_session", 
                1640995200, 
                3600, 
                1, 
                2, 
                3, 
                {}
            )
            
            assert.is.table(result)
            assert.is.string(result.mitata_jwe)
            assert.is.string(result.mitata_plaintext)
        end)
    end)

    describe("parseMitataCookie", function()
        it("should return invalid result for nil cookie", function()
            local result = NetaceaCookies.parseMitataCookie(nil, "secret_key")
            
            assert.is.table(result)
            assert.is_false(result.valid)
            assert.is.equal('no_session', result.reason)
        end)

        it("should return invalid result for empty cookie", function()
            local result = NetaceaCookies.parseMitataCookie("", "secret_key")
            
            assert.is.table(result)
            assert.is_false(result.valid)
            assert.is.equal('no_session', result.reason)
        end)

        it("should return invalid result for unverified JWT", function()
            local _ = match._
            local result = NetaceaCookies.parseMitataCookie("invalid_token", "secret_key")
            
            assert.is.table(result)
            assert.is_false(result.valid)
            assert.is.equal('invalid_session', result.reason)
            assert.spy(jwt_mock.verify).was.called_with(match.is_not_nil(), "secret_key", "invalid_token")
        end)

        it("should return invalid result for invalid payload format", function()
            local result = NetaceaCookies.parseMitataCookie("invalid_payload_token", "secret_key")
            
            assert.is.table(result)
            assert.is_false(result.valid)
            assert.is.equal('invalid_session', result.reason)
        end)

        it("should return invalid result for missing required fields", function()
            local result = NetaceaCookies.parseMitataCookie("missing_fields_token", "secret_key")
            
            assert.is.table(result)
            assert.is_false(result.valid)
            assert.is.equal('invalid_session', result.reason)
        end)

        it("should return invalid result for expired cookie", function()
            local result = NetaceaCookies.parseMitataCookie("expired_token", "secret_key")
            
            assert.is.table(result)
            assert.is_false(result.valid)
            assert.is.equal('expired_session', result.reason)
            assert.is.equal('user123', result.user_id)
        end)

        it("should return invalid result for IP mismatch", function()
            local result = NetaceaCookies.parseMitataCookie("ip_mismatch_token", "secret_key")
            
            assert.is.table(result)
            assert.is_false(result.valid)
            assert.is.equal('ip_change', result.reason)
            assert.is.equal('user123', result.user_id)
        end)

        it("should return valid result for valid cookie", function()
            local result = NetaceaCookies.parseMitataCookie("valid_token", "secret_key")
            
            assert.is.table(result)
            assert.is_true(result.valid)
            assert.is.equal('user123', result.user_id)
            assert.is.table(result.data)
            assert.is.equal('192.168.1.1', result.data.cip)
            assert.is.equal('user123', result.data.uid)
            assert.is.equal('cookie123', result.data.cid)
        end)

        it("should call jwt.verify with correct parameters", function()
            NetaceaCookies.parseMitataCookie("test_cookie", "test_secret")
            
            assert.spy(jwt_mock.verify).was.called_with(match.is_not_nil(), "test_secret", "test_cookie")
        end)

        it("should check all required fields", function()
            -- This test ensures all required fields are checked
            local required_fields = {'cip', 'uid', 'cid', 'isr', 'ist', 'grp', 'mat', 'mit', 'cap', 'fCAPR'}
            
            -- Create a mock that returns a payload missing each field one at a time
            for _, missing_field in ipairs(required_fields) do
                jwt_mock.verify = spy.new(function(secretKey, token)
                    local payload_parts = {}
                    for _, field in ipairs(required_fields) do
                        if field ~= missing_field then
                            table.insert(payload_parts, field .. "=value")
                        end
                    end
                    return {
                        verified = true,
                        payload = table.concat(payload_parts, "&")
                    }
                end)
                
                local result = NetaceaCookies.parseMitataCookie("test_token", "secret_key")
                assert.is_false(result.valid, "Should be invalid when missing field: " .. missing_field)
                assert.is.equal('invalid_session', result.reason)
            end
        end)
    end)
    describe("newUserId #only", function()
        it("should generate a user ID starting with 'c' followed by 15 characters", function()
            local userId = NetaceaCookies.newUserId()
            
            assert.is_string(userId)
            assert.is.equal(16, #userId)
            assert.is.equal('c', userId:sub(1,1))
        end)

        it("should generate different user IDs on multiple calls", function()
            local userId1 = NetaceaCookies.newUserId()
            local userId2 = NetaceaCookies.newUserId()
            
            assert.is_not.equal(userId1, userId2)
        end)

        it("should generate user ID with alphanumeric characters", function()
            local userId = NetaceaCookies.newUserId()
            local pattern = "^c[%w_%-]+$"  -- Alphanumeric, underscore, hyphen
            
            assert.is_true(userId:match(pattern) ~= nil, "User ID should match pattern: " .. pattern)
        end)
    end)
end)
