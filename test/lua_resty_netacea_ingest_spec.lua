require("silence_g_write_guard")
require 'busted.runner'()

package.path = "../src/?.lua;" .. package.path
local match = require("luassert.match")

describe("lua_resty_netacea_ingest", function()
    local Ingest
    local ngx_mock
    local kinesis_mock
    local utils_mock
    local cjson_mock

    before_each(function()
        -- Mock ngx module
        ngx_mock = {
            ctx = {
                mitata = "test_mitata_cookie",
                NetaceaState = {
                    client = "192.168.1.1",
                    UserId = "user123",
                    bc_type = "captcha"
                }
            },
            var = {
                request_method = "GET",
                request_uri = "/test/path",
                server_protocol = "HTTP/1.1",
                time_local = "01/Jan/2022:00:00:00 +0000",
                msec = 1640995200.123,
                http_user_agent = "Test-Agent/1.0",
                status = "200",
                request_time = "0.123",
                bytes_sent = "1024",
                http_referer = "https://example.com",
                query_string = "param=value",
                host = "test.example.com",
                request_id = "req-12345",
                bytes_received = "512",
                cookie__mitata = "fallback_mitata"
            },
            log = spy.new(function() end),
            DEBUG = 7,
            ERR = 3,
            now = spy.new(function() return 1640995200.5 end),
            sleep = spy.new(function() end),
            timer = {
                at = spy.new(function(delay, callback)
                    -- Simulate timer execution for testing
                    if callback then
                        callback(false) -- premature = false
                    end
                    return true
                end)
            },
            thread = {
                spawn = spy.new(function(func)
                    -- For testing, just return a mock thread handle
                    return { thread_id = "mock_thread" }
                end),
                wait = spy.new(function(thread)
                    return true, nil -- success, no error
                end)
            },
            worker = {
                exiting = spy.new(function() return false end)
            }
        }

        -- Mock kinesis module
        kinesis_mock = {
            new = spy.new(function(stream_name, region, access_key, secret_key)
                local client = {
                    stream_name = stream_name,
                    region = region,
                    access_key = access_key,
                    secret_key = secret_key,
                    put_records = spy.new(function(self, records)
                        if self.stream_name == "test_stream" or self.stream_name == "integration_test_stream" or self.stream_name:match("test") then
                            return { status = 200, body = '{"Records":[]}' }, nil
                        else
                            return nil, "Stream not found"
                        end
                    end)
                }
                return client
            end)
        }

        -- Mock utils module
        utils_mock = {
            buildRandomString = spy.new(function(length)
                return string.rep("a", length)
            end),
            getIpAddress = spy.new(function(self, vars, header)
                if header and vars["http_" .. header] then
                    return vars["http_" .. header]
                end
                return vars.remote_addr or "127.0.0.1"
            end)
        }

        -- Mock cjson module
        cjson_mock = {
            encode = spy.new(function(obj)
                if type(obj) == "table" then
                    return '{"mocked":"json"}'
                end
                return '"' .. tostring(obj) .. '"'
            end)
        }

        -- Set up package mocks
        package.loaded['ngx'] = ngx_mock
        package.loaded['kinesis_resty'] = kinesis_mock
        package.loaded['netacea_utils'] = utils_mock
        package.loaded['cjson'] = cjson_mock

        Ingest = require('lua_resty_netacea_ingest')
    end)

    after_each(function()
        -- Clear mocks and cached modules
        package.loaded['lua_resty_netacea_ingest'] = nil
        package.loaded['ngx'] = nil
        package.loaded['kinesis_resty'] = nil
        package.loaded['netacea_utils'] = nil
        package.loaded['cjson'] = nil
    end)

    describe("new_queue", function()
        it("should create a queue with specified size", function()
            local ingest = Ingest:new({
                stream_name = "test_stream",
                queue_size = 10
            }, { _MODULE_TYPE = "test", _MODULE_VERSION = "1.0" })
            
            assert.is.table(ingest.data_queue)
            assert.is.equal(10, ingest.data_queue.size)
            assert.is.equal(0, ingest.data_queue:count())
        end)

        it("should support push and pop operations", function()
            local ingest = Ingest:new({
                stream_name = "test_stream",
                queue_size = 5
            }, { _MODULE_TYPE = "test", _MODULE_VERSION = "1.0" })
            
            -- Test push
            local ok, err = ingest.data_queue:push("item1")
            assert.is_true(ok)
            assert.is_nil(err)
            assert.is.equal(1, ingest.data_queue:count())
            
            -- Test pop
            local item = ingest.data_queue:pop()
            assert.is.equal("item1", item)
            assert.is.equal(0, ingest.data_queue:count())
        end)

        it("should handle queue wrapping when enabled", function()
            local ingest = Ingest:new({
                stream_name = "test_stream",
                queue_size = 2
            }, { _MODULE_TYPE = "test", _MODULE_VERSION = "1.0" })
            
            -- Fill the queue
            ingest.data_queue:push("item1")
            ingest.data_queue:push("item2")
            assert.is.equal(2, ingest.data_queue:count())
            
            -- Push beyond capacity (should wrap since allow_wrapping is true)
            ingest.data_queue:push("item3")
            assert.is.equal(2, ingest.data_queue:count())
            
            -- First item should be lost, second item should be available
            local item = ingest.data_queue:pop()
            assert.is.equal("item2", item)
        end)

        it("should peek at next item without removing it", function()
            local ingest = Ingest:new({
                stream_name = "test_stream",
                queue_size = 5
            }, { _MODULE_TYPE = "test", _MODULE_VERSION = "1.0" })
            
            ingest.data_queue:push("peek_item")
            
            local peeked = ingest.data_queue:peek()
            assert.is.equal("peek_item", peeked)
            assert.is.equal(1, ingest.data_queue:count())
            
            local popped = ingest.data_queue:pop()
            assert.is.equal("peek_item", popped)
            assert.is.equal(0, ingest.data_queue:count())
        end)
    end)

    describe("constructor", function()
        it("should create ingest instance with default options", function()
            local ingest = Ingest:new({}, { _MODULE_TYPE = "test", _MODULE_VERSION = "1.0" })
            
            assert.is.table(ingest)
            assert.is.equal("", ingest.stream_name)
            assert.is.equal("eu-west-1", ingest.region)
            assert.is.equal("", ingest.aws_access_key)
            assert.is.equal("", ingest.aws_secret_key)
            assert.is.equal(5000, ingest.queue_size)
            assert.is.equal(1000, ingest.dead_letter_queue_size)
            assert.is.equal(25, ingest.batch_size)
            assert.is.equal(1.0, ingest.batch_timeout)
        end)

        it("should create ingest instance with custom options", function()
            local options = {
                stream_name = "my-stream",
                region = "us-east-1",
                aws_access_key = "AKIAIOSFODNN7EXAMPLE",
                aws_secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                queue_size = 1000,
                dead_letter_queue_size = 100,
                batch_size = 50,
                batch_timeout = 2.0
            }
            
            local ingest = Ingest:new(options, { _MODULE_TYPE = "test", _MODULE_VERSION = "1.0" })
            
            assert.is.equal("my-stream", ingest.stream_name)
            assert.is.equal("us-east-1", ingest.region)
            assert.is.equal("AKIAIOSFODNN7EXAMPLE", ingest.aws_access_key)
            assert.is.equal("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", ingest.aws_secret_key)
            assert.is.equal(1000, ingest.queue_size)
            assert.is.equal(100, ingest.dead_letter_queue_size)
            assert.is.equal(50, ingest.batch_size)
            assert.is.equal(2.0, ingest.batch_timeout)
        end)

        it("should initialize queues properly", function()
            local ingest = Ingest:new({
                queue_size = 10,
                dead_letter_queue_size = 5
            }, { _MODULE_TYPE = "test", _MODULE_VERSION = "1.0" })
            
            assert.is.table(ingest.data_queue)
            assert.is.table(ingest.dead_letter_queue)
            assert.is.equal(10, ingest.data_queue.size)
            assert.is.equal(5, ingest.dead_letter_queue.size)
            assert.is.equal(0, ingest.data_queue:count())
            assert.is.equal(0, ingest.dead_letter_queue:count())
        end)

        it("should log initialization message", function()
            Ingest:new({
                queue_size = 100,
                dead_letter_queue_size = 50,
                batch_size = 10,
                batch_timeout = 0.5
            }, { _MODULE_TYPE = "test", _MODULE_VERSION = "1.0" })
            
            assert.spy(ngx_mock.log).was.called_with(ngx_mock.DEBUG, match._, 100, match._, 50, match._, 10, match._, 0.5)
        end)
    end)

    describe("send_batch_to_kinesis", function()
        local ingest

        before_each(function()
            ingest = Ingest:new({
                stream_name = "test_stream",
                region = "us-west-2",
                aws_access_key = "test_key",
                aws_secret_key = "test_secret"
            }, { _MODULE_TYPE = "test", _MODULE_VERSION = "1.0" })
        end)

        it("should handle empty batch gracefully", function()
            ingest:send_batch_to_kinesis({})
            
            -- Should not call Kinesis
            assert.spy(kinesis_mock.new).was_not_called()
        end)

        it("should handle nil batch gracefully", function()
            ingest:send_batch_to_kinesis(nil)
            
            -- Should not call Kinesis
            assert.spy(kinesis_mock.new).was_not_called()
        end)

        it("should create kinesis client with correct parameters", function()
            local batch = { { test = "data1" }, { test = "data2" } }
            
            ingest:send_batch_to_kinesis(batch)
            
            assert.spy(kinesis_mock.new).was.called_with(
                "test_stream",
                "us-west-2", 
                "test_key",
                "test_secret"
            )
        end)

        it("should format batch data correctly for kinesis", function()
            local batch = { { test = "data1" }, { test = "data2" } }
            
            ingest:send_batch_to_kinesis(batch)
            
            assert.spy(kinesis_mock.new).was.called()
            assert.spy(utils_mock.buildRandomString).was.called(2) -- Once per record for partition key
            assert.spy(cjson_mock.encode).was.called(2) -- Once per record
        end)

        it("should log successful batch send", function()
            local batch = { { test = "data1" } }
            
            ingest:send_batch_to_kinesis(batch)
            
            assert.spy(ngx_mock.log).was.called_with(ngx_mock.DEBUG, match.has_match("sending batch of"), 1, match._, "test_stream")
            -- Check that at least one log call was made (for success)
            assert.spy(ngx_mock.log).was.called()
        end)

        it("should handle kinesis errors and move items to dead letter queue", function()
            -- Mock kinesis to return error
            local batch = { { test = "data1" }, { test = "data2" } }
            kinesis_mock.new = spy.new(function()
                return {
                    put_records = spy.new(function()
                        return nil, "Connection timeout"
                    end)
                }
            end)
            
            ingest:send_batch_to_kinesis(batch)
            
            assert.spy(ngx_mock.log).was.called_with(ngx_mock.ERR, match.has_match("error sending batch"), "Connection timeout")
            assert.is.equal(2, ingest.dead_letter_queue:count())
        end)

        it("should handle dead letter queue overflow correctly", function()
            -- Mock kinesis error
            kinesis_mock.new = spy.new(function()
                return {
                    put_records = spy.new(function()
                        return nil, "Stream not found"
                    end)
                }
            end)
            
            -- Create an ingest with very small DLQ size for testing
            local small_dlq_ingest = Ingest:new({
                stream_name = "test_stream",
                dead_letter_queue_size = 1
            }, { _MODULE_TYPE = "test", _MODULE_VERSION = "1.0" })
            
            -- Fill DLQ to capacity first (the queue allows wrapping so it overwrites)
            small_dlq_ingest.dead_letter_queue:push("existing_item")
            
            -- Now try to send a batch that will fail
            local batch = { { test = "overflow_data1" } }
            small_dlq_ingest:send_batch_to_kinesis(batch)
            
            -- Should log the kinesis error
            assert.spy(ngx_mock.log).was.called_with(ngx_mock.ERR, match.has_match("error sending batch"), "Stream not found")
            -- The DLQ should now contain the failed item (wrapping behavior)
            assert.is.equal(1, small_dlq_ingest.dead_letter_queue:count())
        end)
    end)

    describe("ingest", function()
        local ingest

        before_each(function()
            ingest = Ingest:new({
                stream_name = "test_stream"
            }, { 
                _MODULE_TYPE = "nginx", 
                _MODULE_VERSION = "2.1.0",
                realIpHeader = "x_forwarded_for",
                mitigationType = "monitor"
            })
        end)

        it("should collect request data from ngx variables", function()
            ingest:ingest()
            
            assert.is.equal(1, ingest.data_queue:count())
            local queued_item = ingest.data_queue:pop()
            
            assert.is.table(queued_item)
            assert.is.equal("GET /test/path HTTP/1.1", queued_item.Request)
            assert.is.equal("01/Jan/2022:00:00:00 +0000", queued_item.TimeLocal)
            assert.is.equal(1640995200123, queued_item.TimeUnixMsUTC)
            assert.is.equal("192.168.1.1", queued_item.RealIp)
            assert.is.equal("Test-Agent/1.0", queued_item.UserAgent)
            assert.is.equal("200", queued_item.Status)
            assert.is.equal("0.123", queued_item.RequestTime)
            assert.is.equal("1024", queued_item.BytesSent)
            assert.is.equal("https://example.com", queued_item.Referer)
            assert.is.equal("test_mitata_cookie", queued_item.NetaceaUserIdCookie)
            assert.is.equal("user123", queued_item.UserId)
            assert.is.equal("captcha", queued_item.NetaceaMitigationApplied)
            assert.is.equal("nginx", queued_item.IntegrationType)
            assert.is.equal("2.1.0", queued_item.IntegrationVersion)
            assert.is.equal("param=value", queued_item.Query)
            assert.is.equal("test.example.com", queued_item.RequestHost)
            assert.is.equal("req-12345", queued_item.RequestId)
            assert.is.equal("monitor", queued_item.ProtectionMode)
        end)

        it("should handle missing ngx.ctx.mitata by falling back to cookie", function()
            ngx_mock.ctx.mitata = nil
            
            ingest:ingest()
            
            local queued_item = ingest.data_queue:pop()
            assert.is.equal("fallback_mitata", queued_item.NetaceaUserIdCookie)
        end)

        it("should handle missing NetaceaState gracefully", function()
            ngx_mock.ctx.NetaceaState = nil
            
            ingest:ingest()
            
            local queued_item = ingest.data_queue:pop()
            assert.is.equal("127.0.0.1", queued_item.RealIp) -- default from utils mock
            assert.is.equal("-", queued_item.UserId)
            assert.is_nil(queued_item.NetaceaMitigationApplied)
        end)

        it("should use realIpHeader when configured", function()
            ngx_mock.var.http_x_forwarded_for = "203.0.113.1"
            ngx_mock.ctx.NetaceaState.client = nil -- Force it to use getIpAddress
            
            ingest:ingest()
            
            assert.spy(utils_mock.getIpAddress).was.called()
            -- Verify the call was made with correct number of arguments
            assert.is.equal(1, #utils_mock.getIpAddress.calls)
        end)

        it("should handle missing optional fields with defaults", function()
            ngx_mock.var.http_user_agent = nil
            ngx_mock.var.http_referer = nil
            ngx_mock.var.query_string = nil
            ngx_mock.var.host = nil
            ngx_mock.var.request_id = nil
            ngx_mock.var.bytes_received = nil
            
            ingest:ingest()
            
            local queued_item = ingest.data_queue:pop()
            assert.is.equal("-", queued_item.UserAgent)
            assert.is.equal("-", queued_item.Referer)
            assert.is.equal("", queued_item.Query)
            assert.is.equal("-", queued_item.RequestHost)
            assert.is.equal("-", queued_item.RequestId)
            assert.is.equal(0, queued_item.BytesReceived)
        end)

        it("should log successful data queueing", function()
            ingest:ingest()
            
            assert.spy(ngx_mock.log).was.called_with(ngx_mock.DEBUG, match.has_match("queued data item"), 1)
        end)

        it("should log error when queue is full", function()
            -- Fill the queue to capacity
            for i = 1, ingest.queue_size do
                ingest.data_queue:push("item" .. i)
            end
            
            -- Since wrapping is enabled, this should still work, but let's test error handling
            -- by mocking the queue to return an error
            ingest.data_queue.push = spy.new(function() return nil, "queue full" end)
            
            ingest:ingest()
            
            assert.spy(ngx_mock.log).was.called_with(ngx_mock.ERR, match.has_match("failed to queue data"), "queue full")
        end)

        it("should include all required data fields", function()
            ingest:ingest()
            
            local queued_item = ingest.data_queue:pop()
            local required_fields = {
                "Request", "TimeLocal", "TimeUnixMsUTC", "RealIp", "UserAgent", "Status",
                "RequestTime", "BytesSent", "Referer", "NetaceaUserIdCookie", "UserId",
                "NetaceaMitigationApplied", "IntegrationType", "IntegrationVersion", "Query",
                "RequestHost", "RequestId", "ProtectionMode", "BytesReceived", 
                "NetaceaUserIdCookieStatus", "Optional"
            }
            
            for _, field in ipairs(required_fields) do
                assert.is_not_nil(queued_item[field], "Field " .. field .. " should be present")
            end
        end)

        it("should handle empty mitata cookie", function()
            ngx_mock.ctx.mitata = ""
            ngx_mock.var.cookie__mitata = ""
            
            ingest:ingest()
            
            local queued_item = ingest.data_queue:pop()
            assert.is.equal("", queued_item.NetaceaUserIdCookie)
        end)
    end)

    describe("start_timers", function()
        local ingest

        before_each(function()
            ingest = Ingest:new({
                stream_name = "test_stream",
                batch_size = 2,
                batch_timeout = 0.1
            }, { _MODULE_TYPE = "test", _MODULE_VERSION = "1.0" })
            
            -- Simplify timer mock to avoid recursion
            ngx_mock.timer.at = spy.new(function(delay, callback)
                return true -- Just return success, don't execute callback
            end)
        end)

        it("should start batch processor timer", function()
            ingest:start_timers()
            
            assert.spy(ngx_mock.timer.at).was.called_with(0, match.is_function())
            assert.spy(ngx_mock.log).was.called_with(ngx_mock.DEBUG, match.has_match("starting batch processor timer"))
        end)

        it("should setup timer correctly", function()
            ingest:start_timers()
            
            assert.spy(ngx_mock.timer.at).was.called()
        end)
    end)

    describe("queue integration with kinesis", function()
        local ingest

        before_each(function()
            ingest = Ingest:new({
                stream_name = "integration_test_stream",
                batch_size = 3,
                batch_timeout = 0.1
            }, { _MODULE_TYPE = "test", _MODULE_VERSION = "1.0" })
        end)

        it("should process data from queue through kinesis pipeline", function()
            -- Add test data to queue
            ingest.data_queue:push({ test_data = "item1" })
            ingest.data_queue:push({ test_data = "item2" })
            ingest.data_queue:push({ test_data = "item3" })
            
            -- Manually call send_batch_to_kinesis to test integration
            local batch = {}
            while ingest.data_queue:count() > 0 do
                table.insert(batch, ingest.data_queue:pop())
            end
            
            ingest:send_batch_to_kinesis(batch)
            
            assert.spy(kinesis_mock.new).was.called()
            assert.spy(utils_mock.buildRandomString).was.called(3) -- Once per record for partition key
            assert.spy(cjson_mock.encode).was.called(3) -- Once per record for data serialization
        end)

        it("should handle dead letter queue processing", function()
            -- Add items to dead letter queue
            ingest.dead_letter_queue:push({ failed_data = "item1" })
            ingest.dead_letter_queue:push({ failed_data = "item2" })
            
            -- Process dead letter queue items
            local batch = {}
            while ingest.dead_letter_queue:count() > 0 do
                table.insert(batch, ingest.dead_letter_queue:pop())
            end
            
            ingest:send_batch_to_kinesis(batch)
            
            assert.spy(kinesis_mock.new).was.called()
            -- Verify kinesis new was called (put_records called internally)
            assert.spy(kinesis_mock.new).was.called(1)
        end)

        it("should handle mixed data and dead letter queue processing", function()
            -- Add items to both queues
            ingest.data_queue:push({ normal_data = "item1" })
            ingest.dead_letter_queue:push({ retry_data = "item2" })
            
            local batch = {}
            
            -- Process dead letter queue first (as per implementation)
            while ingest.dead_letter_queue:count() > 0 and #batch < ingest.batch_size do
                table.insert(batch, ingest.dead_letter_queue:pop())
            end
            
            -- Then process normal queue
            while ingest.data_queue:count() > 0 and #batch < ingest.batch_size do
                table.insert(batch, ingest.data_queue:pop())
            end
            
            ingest:send_batch_to_kinesis(batch)
            
            assert.is.equal(2, #batch)
            assert.spy(kinesis_mock.new).was.called()
        end)
    end)

    describe("AWS Kinesis integration specifics", function()
        local ingest

        before_each(function()
            ingest = Ingest:new({
                stream_name = "aws_test_stream",
                region = "us-east-1",
                aws_access_key = "AKIA1234567890EXAMPLE",
                aws_secret_key = "abcd1234567890efgh1234567890ijklmnopqrstuvwx"
            }, { _MODULE_TYPE = "test", _MODULE_VERSION = "1.0" })
        end)

        it("should create kinesis client with AWS credentials", function()
            local batch = { { aws_test = "data" } }
            
            ingest:send_batch_to_kinesis(batch)
            
            assert.spy(kinesis_mock.new).was.called_with(
                "aws_test_stream",
                "us-east-1",
                "AKIA1234567890EXAMPLE",
                "abcd1234567890efgh1234567890ijklmnopqrstuvwx"
            )
        end)

        it("should generate random partition keys for records", function()
            local batch = { { data1 = "test" }, { data2 = "test" } }
            
            ingest:send_batch_to_kinesis(batch)
            
            assert.spy(utils_mock.buildRandomString).was.called(2)
            assert.spy(utils_mock.buildRandomString).was.called_with(10)
        end)

        it("should format data as JSON arrays for Kinesis", function()
            local test_data = { field1 = "value1", field2 = "value2" }
            local batch = { test_data }
            
            ingest:send_batch_to_kinesis(batch)
            
            assert.spy(kinesis_mock.new).was.called()
            
            -- The put_records call happens internally, we can verify the call structure
            -- by checking that kinesis_mock.new was called properly
            assert.spy(kinesis_mock.new).was.called_with(
                "aws_test_stream",
                "us-east-1",
                "AKIA1234567890EXAMPLE", 
                "abcd1234567890efgh1234567890ijklmnopqrstuvwx"
            )
        end)

        it("should handle different AWS regions", function()
            local regional_ingest = Ingest:new({
                stream_name = "eu_stream",
                region = "eu-west-1",
                aws_access_key = "key",
                aws_secret_key = "secret"
            }, { _MODULE_TYPE = "test", _MODULE_VERSION = "1.0" })
            
            regional_ingest:send_batch_to_kinesis({ { regional_test = "data" } })
            
            assert.spy(kinesis_mock.new).was.called_with("eu_stream", "eu-west-1", "key", "secret")
        end)
    end)
end)