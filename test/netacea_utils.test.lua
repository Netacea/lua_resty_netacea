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
    end)
end)
