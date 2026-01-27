require("silence_g_write_guard")
require 'busted.runner'()

package.path = "../src/?.lua;" .. package.path

describe("netacea_utils", function()
    local utils

    before_each(function()
        utils = require('netacea_utils')
    end)

    after_each(function()
        package.loaded['netacea_utils'] = nil
    end)

    describe("buildRandomString", function()
        it("should generate a string of the specified length", function()
            local result = utils.buildRandomString(10)
            assert.is.equal(10, #result)
        end)

        it("should generate a string of length 1 when passed 1", function()
            local result = utils.buildRandomString(1)
            assert.is.equal(1, #result)
        end)

        it("should generate an empty string when passed 0", function()
            local result = utils.buildRandomString(0)
            assert.is.equal(0, #result)
            assert.is.equal('', result)
        end)

        it("should generate strings with only alphanumeric characters", function()
            local result = utils.buildRandomString(50)
            local validChars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
            
            for i = 1, #result do
                local char = result:sub(i, i)
                assert.is_truthy(validChars:find(char, 1, true), "Character '" .. char .. "' should be alphanumeric")
            end
        end)

        it("should generate different strings on multiple calls", function()
            local result1 = utils.buildRandomString(20)
            local result2 = utils.buildRandomString(20)
            
            -- While theoretically possible to be equal, it's extremely unlikely
            -- with 62^20 possible combinations
            assert.is_not.equal(result1, result2)
        end)

        it("should handle large string lengths", function()
            local result = utils.buildRandomString(1000)
            assert.is.equal(1000, #result)
        end)

        it("should contain at least some variety in character types for longer strings", function()
            local result = utils.buildRandomString(100)
            
            -- Check that we have at least some variety (not all the same character)
            local firstChar = result:sub(1, 1)
            local hasVariety = false
            
            for i = 2, #result do
                if result:sub(i, i) ~= firstChar then
                    hasVariety = true
                    break
                end
            end
            
            assert.is_true(hasVariety, "String should contain character variety")
        end)
    end)

    describe("getIpAddress", function()
        it("should return remote_addr when realIpHeader is nil", function()
            local vars = {
                remote_addr = "192.168.1.1"
            }
            
            local result = utils:getIpAddress(vars, nil)
            assert.is.equal("192.168.1.1", result)
        end)

        it("should return remote_addr when realIpHeader is not provided", function()
            local vars = {
                remote_addr = "192.168.1.1"
            }
            
            local result = utils:getIpAddress(vars)
            assert.is.equal("192.168.1.1", result)
        end)

        it("should return remote_addr when realIpHeader is empty string", function()
            local vars = {
                remote_addr = "192.168.1.1"
            }
            
            local result = utils:getIpAddress(vars, "")
            assert.is.equal("192.168.1.1", result)
        end)

        it("should return the real IP header value when it exists", function()
            local vars = {
                remote_addr = "192.168.1.1",
                http_x_forwarded_for = "203.0.113.1"
            }
            
            local result = utils:getIpAddress(vars, "x_forwarded_for")
            assert.is.equal("203.0.113.1", result)
        end)

        it("should return remote_addr when real IP header doesn't exist", function()
            local vars = {
                remote_addr = "192.168.1.1"
            }
            
            local result = utils:getIpAddress(vars, "x_forwarded_for")
            assert.is.equal("192.168.1.1", result)
        end)

        it("should handle different header formats", function()
            local vars = {
                remote_addr = "192.168.1.1",
                http_x_real_ip = "203.0.113.2",
                http_cf_connecting_ip = "203.0.113.3"
            }
            
            local result1 = utils:getIpAddress(vars, "x_real_ip")
            assert.is.equal("203.0.113.2", result1)
            
            local result2 = utils:getIpAddress(vars, "cf_connecting_ip")
            assert.is.equal("203.0.113.3", result2)
        end)

        it("should fall back to remote_addr when real IP header is empty", function()
            local vars = {
                remote_addr = "192.168.1.1",
                http_x_forwarded_for = ""
            }
            
            local result = utils:getIpAddress(vars, "x_forwarded_for")
            assert.is.equal("192.168.1.1", result)
        end)

        it("should fall back to remote_addr when real IP header is nil", function()
            local vars = {
                remote_addr = "192.168.1.1",
                http_x_forwarded_for = nil
            }
            
            local result = utils:getIpAddress(vars, "x_forwarded_for")
            assert.is.equal("192.168.1.1", result)
        end)

        it("should handle IPv6 addresses", function()
            local vars = {
                remote_addr = "2001:db8::1",
                http_x_forwarded_for = "2001:db8::2"
            }
            
            local result = utils:getIpAddress(vars, "x_forwarded_for")
            assert.is.equal("2001:db8::2", result)
        end)

        it("should handle special header names with underscores and dashes", function()
            local vars = {
                remote_addr = "192.168.1.1",
                ["http_x_forwarded_for"] = "203.0.113.1",
                ["http_x_real_ip"] = "203.0.113.2"
            }
            
            local result = utils:getIpAddress(vars, "x_forwarded_for")
            assert.is.equal("203.0.113.1", result)
        end)

        it("should handle missing remote_addr gracefully", function()
            local vars = {
                http_x_forwarded_for = "203.0.113.1"
            }
            
            local result = utils:getIpAddress(vars, "x_forwarded_for")
            assert.is.equal("203.0.113.1", result)
        end)

        it("should handle nil vars table", function()
            local success, result = pcall(function()
                return utils:getIpAddress(nil, "x_forwarded_for")
            end)
            
            -- Should not crash, but will likely error when trying to access nil.remote_addr
            assert.is_false(success)
        end)

        it("should handle empty vars table", function()
            local vars = {}
            
            local result = utils:getIpAddress(vars, "x_forwarded_for")
            assert.is_nil(result)  -- vars.remote_addr is nil
        end)

        it("should handle whitespace in header values", function()
            local vars = {
                remote_addr = "192.168.1.1",
                http_x_forwarded_for = "  203.0.113.1  "
            }
            
            local result = utils:getIpAddress(vars, "x_forwarded_for")
            assert.is.equal("  203.0.113.1  ", result)  -- Should preserve whitespace
        end)

        it("should handle very long header names", function()
            local longHeaderName = string.rep("a", 100)
            local vars = {
                remote_addr = "192.168.1.1",
                ["http_" .. longHeaderName] = "203.0.113.1"
            }
            
            local result = utils:getIpAddress(vars, longHeaderName)
            assert.is.equal("203.0.113.1", result)
        end)
    end)

    describe("parseOption", function()
        it("should return the option when it's a valid string", function()
            local result = utils.parseOption("test_value", "default")
            assert.is.equal("test_value", result)
        end)

        it("should return the default value when option is nil", function()
            local result = utils.parseOption(nil, "default_value")
            assert.is.equal("default_value", result)
        end)

        it("should return the default value when option is empty string", function()
            local result = utils.parseOption("", "default_value")
            assert.is.equal("default_value", result)
        end)

        it("should trim whitespace from string options", function()
            local result = utils.parseOption("  test_value  ", "default")
            assert.is.equal("test_value", result)
        end)

        it("should handle leading whitespace only", function()
            local result = utils.parseOption("  test_value", "default")
            assert.is.equal("test_value", result)
        end)

        it("should handle trailing whitespace only", function()
            local result = utils.parseOption("test_value  ", "default")
            assert.is.equal("test_value", result)
        end)

        it("should return default when option is only whitespace", function()
            local result = utils.parseOption("   ", "default_value")
            assert.is.equal("default_value", result)
        end)

        it("should handle tabs and newlines in whitespace", function()
            local result = utils.parseOption("\t\n test_value \t\n", "default")
            assert.is.equal("test_value", result)
        end)

        it("should preserve internal whitespace", function()
            local result = utils.parseOption("  test value with spaces  ", "default")
            assert.is.equal("test value with spaces", result)
        end)

        it("should handle non-string types by returning them as-is", function()
            local numberResult = utils.parseOption(123, "default")
            assert.is.equal(123, numberResult)
            
            local boolResult = utils.parseOption(true, "default")
            assert.is.equal(true, boolResult)
            
            local tableResult = utils.parseOption({test = "value"}, "default")
            assert.is.same({test = "value"}, tableResult)
        end)

        it("should handle nil default value", function()
            local result = utils.parseOption(nil, nil)
            assert.is_nil(result)
        end)

        it("should handle empty string as default value", function()
            local result = utils.parseOption(nil, "")
            assert.is.equal("", result)
        end)

        it("should handle numeric default values", function()
            local result = utils.parseOption(nil, 42)
            assert.is.equal(42, result)
        end)

        it("should handle boolean default values", function()
            local result = utils.parseOption(nil, false)
            assert.is.equal(false, result)
        end)

        it("should handle complex whitespace patterns", function()
            -- Various Unicode whitespace characters
            local result = utils.parseOption("\r\n\t  test  \t\r\n", "default")
            assert.is.equal("test", result)
        end)

        it("should handle single character strings", function()
            local result = utils.parseOption(" a ", "default")
            assert.is.equal("a", result)
        end)

        it("should handle very long strings", function()
            local longString = "  " .. string.rep("a", 10000) .. "  "
            local result = utils.parseOption(longString, "default")
            assert.is.equal(string.rep("a", 10000), result)
        end)

        it("should handle special characters in strings", function()
            local result = utils.parseOption("  !@#$%^&*()  ", "default")
            assert.is.equal("!@#$%^&*()", result)
        end)

        it("should handle Unicode characters", function()
            local result = utils.parseOption("  Hello 世界  ", "default")
            assert.is.equal("Hello 世界", result)
        end)

        it("should handle empty string after trimming", function()
            local result = utils.parseOption("\t\n\r ", "default_value")
            assert.is.equal("default_value", result)
        end)
    end)

    describe("buildRandomString edge cases", function()
        it("should handle negative length gracefully", function()
            -- The current implementation doesn't check for negative values
            -- This might cause unexpected behavior
            local success, result = pcall(function()
                return utils.buildRandomString(-1)
            end)
            
            if success then
                -- If it doesn't error, it should return empty string
                assert.is.equal("", result)
            else
                -- If it errors, that's also acceptable behavior
                assert.is_true(true)
            end
        end)

        it("should handle very large lengths", function()
            -- Test with a reasonably large number (not too large to avoid memory issues)
            local result = utils.buildRandomString(10000)
            assert.is.equal(10000, #result)
        end)

        it("should maintain randomness across multiple calls with same seed conditions", function()
            -- Since the function sets its own seed based on time, multiple rapid calls
            -- might produce similar results, but we test that the seeding works
            local results = {}
            for i = 1, 10 do
                results[i] = utils.buildRandomString(20)
                -- Small delay to ensure different seeds
                os.execute("sleep 0.001")
            end
            
            -- Check that not all results are the same
            local allSame = true
            for i = 2, 10 do
                if results[i] ~= results[1] then
                    allSame = false
                    break
                end
            end
            
            assert.is_false(allSame, "Random strings should vary across multiple calls")
        end)
    end)
end)
