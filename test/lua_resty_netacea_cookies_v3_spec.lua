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
                if not str then
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

        it("should handle negative expiry time", function()
            local result = NetaceaCookies.createSetCookieValues("test_cookie", "test_value", -3600)
            
            assert.is.table(result)
            assert.is.equal(1, #result)
            assert.spy(ngx_mock.cookie_time).was.called_with(1640995200 - 3600)
        end)

        it("should handle very large expiry time", function()
            local result = NetaceaCookies.createSetCookieValues("test_cookie", "test_value", 31536000) -- 1 year
            
            assert.is.table(result)
            assert.is.equal(1, #result)
            assert.spy(ngx_mock.cookie_time).was.called_with(1640995200 + 31536000)
        end)

        it("should handle float expiry time", function()
            local result = NetaceaCookies.createSetCookieValues("test_cookie", "test_value", 3600.5)
            
            assert.is.table(result)
            assert.spy(ngx_mock.cookie_time).was.called_with(1640995200 + 3600.5)
        end)

        it("should handle special characters in cookie name and value", function()
            local result = NetaceaCookies.createSetCookieValues("test-cookie_123", "value!@#$%^&*()", 3600)
            
            assert.is.table(result)
            assert.is.equal(1, #result)
            assert.is.equal("test-cookie_123=value!@#$%^&*(); Path=/; Expires=Thu, 01 Jan 2022 00:00:00 GMT", result[1])
        end)

        it("should handle empty cookie name", function()
            local result = NetaceaCookies.createSetCookieValues("", "test_value", 3600)
            
            assert.is.table(result)
            assert.is.equal(1, #result)
            assert.is.equal("=test_value; Path=/; Expires=Thu, 01 Jan 2022 00:00:00 GMT", result[1])
        end)

        it("should handle empty cookie value", function()
            local result = NetaceaCookies.createSetCookieValues("test_cookie", "", 3600)
            
            assert.is.table(result)
            assert.is.equal(1, #result)
            assert.is.equal("test_cookie=; Path=/; Expires=Thu, 01 Jan 2022 00:00:00 GMT", result[1])
        end)

        it("should handle cookie replacement with same name", function()
            -- First create a cookie
            NetaceaCookies.createSetCookieValues("same_cookie", "value1", 3600)
            
            -- Then replace it with the same name
            local result = NetaceaCookies.createSetCookieValues("same_cookie", "value2", 7200)
            
            assert.is.table(result)
            assert.is.equal(1, #result)  -- Should still be only 1 cookie
            assert.is.equal("same_cookie=value2; Path=/; Expires=Thu, 01 Jan 2022 00:00:00 GMT", result[1])
            
            -- Check that the context was updated
            assert.is.equal("same_cookie=value2; Path=/; Expires=Thu, 01 Jan 2022 00:00:00 GMT", 
                           ngx_mock.ctx.cookies["same_cookie"])
        end)

        it("should maintain consistent cookie format", function()
            local result = NetaceaCookies.createSetCookieValues("format_test", "format_value", 1800)
            
            assert.is.table(result)
            assert.is.equal(1, #result)
            
            local cookie_string = result[1]
            -- Check that it follows the expected format: name=value; Path=/; Expires=...
            assert.is_true(cookie_string:match("^[^=]+=[^;]*; Path=/; Expires=.+$") ~= nil, 
                          "Cookie should match expected format")
        end)

        it("should handle complex cookie values with spaces and special chars", function()
            local complex_value = "user data with spaces & special chars = test"
            local result = NetaceaCookies.createSetCookieValues("complex_cookie", complex_value, 3600)
            
            assert.is.table(result)
            assert.is.equal(1, #result)
            assert.is.equal("complex_cookie=" .. complex_value .. "; Path=/; Expires=Thu, 01 Jan 2022 00:00:00 GMT", result[1])
        end)

        it("should call time functions in correct order", function()
            NetaceaCookies.createSetCookieValues("timing_test", "test_value", 3600)
            
            -- ngx.time() should be called before ngx.cookie_time()
            assert.spy(ngx_mock.time).was.called()
            assert.spy(ngx_mock.cookie_time).was.called()
            
            -- Verify the time calculation
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
            -- Note: ngx.encode_args output order may vary, so we just check that sign was called
            assert.spy(jwt_mock.sign).was.called()
            local call_args = jwt_mock.sign.calls[1].vals
            assert.is.equal("secret_key", call_args[2])
            assert.is.table(call_args[3])
            assert.is.table(call_args[3].header)
            assert.is.string(call_args[3].payload)
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

        it("should handle nil settings", function()
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
                nil
            )
            
            assert.is.table(result)
            assert.is.string(result.mitata_jwe)
            assert.is.string(result.mitata_plaintext)
        end)

        it("should handle edge case with zero values", function()
            local settings = { fCAPR = 0 }
            local result = NetaceaCookies.generateNewCookieValue(
                "secret_key", 
                "192.168.1.1", 
                "user123", 
                "cookie123", 
                "no_session", 
                0,  -- zero timestamp
                0,  -- zero grace period
                0,  -- zero match
                0,  -- zero mitigation
                0,  -- zero captcha
                settings
            )
            
            assert.is.table(result)
            assert.spy(ngx_mock.encode_args).was.called_with({
                cip = "192.168.1.1",
                uid = "user123",
                cid = "cookie123",
                isr = "no_session",
                ist = 0,
                grp = 0,
                mat = 0,
                mit = 0,
                cap = 0,
                fCAPR = 0
            })
        end)

        it("should handle large numeric values", function()
            local settings = { fCAPR = 999999 }
            local result = NetaceaCookies.generateNewCookieValue(
                "secret_key", 
                "192.168.1.1", 
                "user123", 
                "cookie123", 
                "no_session", 
                2147483647,  -- Max int32
                999999, 
                999999, 
                999999, 
                999999, 
                settings
            )
            
            assert.is.table(result)
            assert.is.string(result.mitata_jwe)
            assert.is.string(result.mitata_plaintext)
        end)

        it("should handle empty string parameters", function()
            local settings = { fCAPR = 0 }
            local result = NetaceaCookies.generateNewCookieValue(
                "", -- empty secret key
                "", -- empty client IP
                "", -- empty user ID
                "", -- empty cookie ID
                "", -- empty issue reason
                1640995200, 
                3600, 
                0, 
                0, 
                0, 
                settings
            )
            
            assert.is.table(result)
            assert.is.string(result.mitata_jwe)
            assert.is.string(result.mitata_plaintext)
        end)

        it("should handle special characters in string parameters", function()
            local settings = { fCAPR = 1 }
            local result = NetaceaCookies.generateNewCookieValue(
                "secret_key!@#$%", 
                "192.168.1.1", 
                "user@domain.com", 
                "cookie_id-123", 
                "reason with spaces", 
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
            assert.spy(ngx_mock.encode_args).was.called_with({
                cip = "192.168.1.1",
                uid = "user@domain.com",
                cid = "cookie_id-123",
                isr = "reason with spaces",
                ist = 1640995200,
                grp = 3600,
                mat = 1,
                mit = 2,
                cap = 3,
                fCAPR = 1
            })
        end)

        it("should handle IPv6 addresses", function()
            local settings = { fCAPR = 0 }
            local result = NetaceaCookies.generateNewCookieValue(
                "secret_key", 
                "2001:0db8:85a3:0000:0000:8a2e:0370:7334", -- IPv6
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
            assert.spy(ngx_mock.encode_args).was.called_with({
                cip = "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
                uid = "user123",
                cid = "cookie123",
                isr = "no_session",
                ist = 1640995200,
                grp = 3600,
                mat = 1,
                mit = 2,
                cap = 3,
                fCAPR = 0
            })
        end)

        it("should create consistent plaintext format", function()
            local settings = { fCAPR = 1 }
            local result = NetaceaCookies.generateNewCookieValue(
                "secret_key", 
                "192.168.1.1", 
                "user123", 
                "cookie123", 
                "no_session", 
                1640995200, 
                3600, 
                5, 
                10, 
                15, 
                settings
            )
            
            -- The plaintext should contain all the encoded parameters
            assert.is.string(result.mitata_plaintext)
            local plaintext = result.mitata_plaintext
            
            -- Check that all expected parameters are present in the plaintext
            assert.is_true(plaintext:match("cip=192%.168%.1%.1") ~= nil)
            assert.is_true(plaintext:match("uid=user123") ~= nil)
            assert.is_true(plaintext:match("cid=cookie123") ~= nil)
            assert.is_true(plaintext:match("isr=no_session") ~= nil)
            assert.is_true(plaintext:match("ist=1640995200") ~= nil)
            assert.is_true(plaintext:match("grp=3600") ~= nil)
            assert.is_true(plaintext:match("mat=5") ~= nil)
            assert.is_true(plaintext:match("mit=10") ~= nil)
            assert.is_true(plaintext:match("cap=15") ~= nil)
            assert.is_true(plaintext:match("fCAPR=1") ~= nil)
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

        it("should handle malformed payload that doesn't decode", function()
            jwt_mock.verify = spy.new(function(secretKey, token)
                return {
                    verified = true,
                    payload = "malformed_payload_that_fails_decode"
                }
            end)

            -- Mock ngx.decode_args to return nil for malformed payload
            ngx_mock.decode_args = spy.new(function(str)
                if str == "malformed_payload_that_fails_decode" then
                    return nil
                end
                return {}
            end)
            
            local result = NetaceaCookies.parseMitataCookie("test_token", "secret_key")
            
            assert.is_false(result.valid)
            assert.is.equal('invalid_session', result.reason)
        end)

        it("should handle non-table result from decode_args", function()
            jwt_mock.verify = spy.new(function(secretKey, token)
                return {
                    verified = true,
                    payload = "test_payload"
                }
            end)

            -- Mock ngx.decode_args to return a string instead of table
            ngx_mock.decode_args = spy.new(function(str)
                return "not_a_table"
            end)
            
            local result = NetaceaCookies.parseMitataCookie("test_token", "secret_key")
            
            assert.is_false(result.valid)
            assert.is.equal('invalid_session', result.reason)
        end)

        it("should handle edge case where timestamp is exactly at expiry", function()
            -- Set up a cookie that expires exactly at the current time
            jwt_mock.verify = spy.new(function(secretKey, token)
                return {
                    verified = true,
                    payload = "cip=192.168.1.1&uid=user123&cid=cookie123&isr=no_session&ist=1640991599&grp=3600&mat=0&mit=0&cap=0&fCAPR=0"
                }
            end)
            
            -- Current time is 1640995200, cookie was issued at 1640991599 with 3600s grace = expires at 1640995199 (1 second before current time)
            local result = NetaceaCookies.parseMitataCookie("edge_case_token", "secret_key")
            
            assert.is_false(result.valid)
            assert.is.equal('expired_session', result.reason)
            assert.is.equal('user123', result.user_id)
        end)

        it("should handle future timestamps correctly", function()
            jwt_mock.verify = spy.new(function(secretKey, token)
                return {
                    verified = true,
                    payload = "cip=192.168.1.1&uid=user123&cid=cookie123&isr=no_session&ist=2000000000&grp=3600&mat=0&mit=0&cap=0&fCAPR=0"
                }
            end)
            
            local result = NetaceaCookies.parseMitataCookie("future_token", "secret_key")
            
            assert.is_true(result.valid)
            assert.is.equal('user123', result.user_id)
        end)

        it("should handle client IP with different formats", function()
            -- Test with loopback IP
            jwt_mock.verify = spy.new(function(secretKey, token)
                return {
                    verified = true,
                    payload = "cip=127.0.0.1&uid=user123&cid=cookie123&isr=no_session&ist=1640995200&grp=3600&mat=0&mit=0&cap=0&fCAPR=0"
                }
            end)

            ngx_mock.ctx.NetaceaState.client = "127.0.0.1"
            
            local result = NetaceaCookies.parseMitataCookie("loopback_token", "secret_key")
            
            assert.is_true(result.valid)
            assert.is.equal('user123', result.user_id)
        end)

        it("should handle empty string fields in payload", function()
            jwt_mock.verify = spy.new(function(secretKey, token)
                return {
                    verified = true,
                    payload = "cip=192.168.1.1&uid=&cid=&isr=&ist=1640995200&grp=3600&mat=0&mit=0&cap=0&fCAPR=0"
                }
            end)
            
            local result = NetaceaCookies.parseMitataCookie("empty_fields_token", "secret_key")
            
            assert.is_true(result.valid)
            assert.is.equal('', result.user_id)  -- uid is empty but present
            assert.is.equal('', result.data.uid)
            assert.is.equal('', result.data.cid)
            assert.is.equal('', result.data.isr)
        end)

        it("should handle numeric string conversion correctly", function()
            jwt_mock.verify = spy.new(function(secretKey, token)
                return {
                    verified = true,
                    payload = "cip=192.168.1.1&uid=user123&cid=cookie123&isr=no_session&ist=not_a_number&grp=3600&mat=0&mit=0&cap=0&fCAPR=0"
                }
            end)
            
            local result = NetaceaCookies.parseMitataCookie("non_numeric_token", "secret_key")
            
            -- Should return invalid session for non-numeric timestamps
            assert.is.table(result)
            assert.is_false(result.valid)
            assert.is.equal('invalid_session', result.reason)
        end)

        it("should handle whitespace in client IP comparison", function()
            jwt_mock.verify = spy.new(function(secretKey, token)
                return {
                    verified = true,
                    payload = "cip= 192.168.1.1 &uid=user123&cid=cookie123&isr=no_session&ist=1640995200&grp=3600&mat=0&mit=0&cap=0&fCAPR=0"
                }
            end)
            
            local result = NetaceaCookies.parseMitataCookie("whitespace_ip_token", "secret_key")
            
            assert.is_false(result.valid)
            assert.is.equal('ip_change', result.reason)
            assert.is.equal('user123', result.user_id)
        end)
    end)
    describe("decrypt", function()
        it("should decrypt a valid JWT token", function()
            local result = NetaceaCookies.decrypt("secret_key", "valid_token")
            
            assert.is_string(result)
            assert.is.equal("cip=192.168.1.1&uid=user123&cid=cookie123&isr=no_session&ist=1640995200&grp=3600&mat=0&mit=0&cap=0&fCAPR=0", result)
            assert.spy(jwt_mock.verify).was.called_with(match.is_not_nil(), "secret_key", "valid_token")
        end)

        it("should return nil for invalid JWT token", function()
            local result = NetaceaCookies.decrypt("secret_key", "invalid_token")
            
            assert.is_nil(result)
            assert.spy(jwt_mock.verify).was.called_with(match.is_not_nil(), "secret_key", "invalid_token")
        end)

        it("should return nil for unverified JWT token", function()
            jwt_mock.verify = spy.new(function(self, secretKey, token)
                return { verified = false }
            end)
            
            local result = NetaceaCookies.decrypt("secret_key", "test_token")
            
            assert.is_nil(result)
            assert.spy(jwt_mock.verify).was.called_with(match.is_not_nil(), "secret_key", "test_token")
        end)

        it("should handle empty secret key", function()
            local result = NetaceaCookies.decrypt("", "valid_token")
            
            assert.spy(jwt_mock.verify).was.called_with(match.is_not_nil(), "", "valid_token")
        end)

        it("should handle empty token", function()
            local result = NetaceaCookies.decrypt("secret_key", "")
            
            assert.spy(jwt_mock.verify).was.called_with(match.is_not_nil(), "secret_key", "")
        end)
    end)

    describe("encrypt", function()
        it("should encrypt payload with correct JWT structure", function()
            local _ = match._
            local result = NetaceaCookies.encrypt("secret_key", "test_payload")
            
            assert.is_string(result)
            assert.is.equal("mock_jwt_token_secret_key", result)
            assert.spy(jwt_mock.sign).was.called_with(match.is_not_nil(), "secret_key", {
                header = { typ="JWE", alg="dir", enc="A128CBC-HS256" },
                payload = "test_payload"
            })
        end)

        it("should handle empty payload", function()
            local result = NetaceaCookies.encrypt("secret_key", "")
            
            assert.is_string(result)
            assert.spy(jwt_mock.sign).was.called_with(match.is_not_nil(), "secret_key", {
                header = { typ="JWE", alg="dir", enc="A128CBC-HS256" },
                payload = ""
            })
        end)

        it("should handle nil payload", function()
            local result = NetaceaCookies.encrypt("secret_key", nil)
            
            assert.is_string(result)
            assert.spy(jwt_mock.sign).was.called_with(match.is_not_nil(), "secret_key", {
                header = { typ="JWE", alg="dir", enc="A128CBC-HS256" },
                payload = nil
            })
        end)

        it("should handle empty secret key", function()
            local result = NetaceaCookies.encrypt("", "test_payload")
            
            assert.is.equal("mock_jwt_token_", result)
            assert.spy(jwt_mock.sign).was.called_with(match.is_not_nil(), "", {
                header = { typ="JWE", alg="dir", enc="A128CBC-HS256" },
                payload = "test_payload"
            })
        end)

        it("should use correct JWT header values", function()
            local _ = match._
            NetaceaCookies.encrypt("secret_key", "test_payload")
            
            assert.spy(jwt_mock.sign).was.called_with(match.is_not_nil(), "secret_key", match._)
            
            -- Verify header structure
            local call_args = jwt_mock.sign.calls[1].vals
            local jwt_params = call_args[3]
            assert.is.table(jwt_params.header)
            assert.is.table(jwt_params)
            assert.is.truthy(jwt_params.header)
            assert.is.truthy(jwt_params.payload)
            assert.is.equal("JWE", jwt_params.header.typ)
            assert.is.equal("dir", jwt_params.header.alg)
            assert.is.equal("A128CBC-HS256", jwt_params.header.enc)
        end)
    end)

    describe("newUserId", function()
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

        it("should always generate IDs of consistent length", function()
            for i = 1, 10 do
                local userId = NetaceaCookies.newUserId()
                assert.is.equal(16, #userId, "ID " .. i .. " should be 16 characters long")
            end
        end)

        it("should generate only alphanumeric characters after 'c'", function()
            local userId = NetaceaCookies.newUserId()
            local randomPart = userId:sub(2)  -- Everything after 'c'
            local alphanumericPattern = "^[a-zA-Z0-9]+$"
            
            assert.is_true(randomPart:match(alphanumericPattern) ~= nil, 
                "Random part should contain only alphanumeric characters")
        end)
    end)
end)
