require("silence_g_write_guard")
require 'busted.runner'()

package.path = "../src/?.lua;" .. package.path

describe("lua_resty_netacea_protector_client", function()
    local ProtectorClient
    local ngx_mock
    local http_mock_instance
    local http_mock
    local constants

    before_each(function()
        constants = require('lua_resty_netacea_constants')

        ngx_mock = {
            ctx = {
                NetaceaState = {
                    client = "192.168.1.1",
                    user_agent = "Test-Agent/1.0",
                    UserId = "user123",
                    captcha_cookie = nil
                }
            },
            log = spy.new(function() end),
            ERR = 3,
            HTTP_FORBIDDEN = 403,
            HTTP_OK = 200
        }

        http_mock_instance = {
            set_timeouts = spy.new(function() end),
            request_uri = spy.new(function(self, url, opts)
                return {
                    status = 200,
                    body = "<html>response</html>",
                    headers = {
                        ['x-netacea-match'] = constants.idTypes.IP,
                        ['x-netacea-mitigate'] = constants.mitigationTypes.BLOCKED,
                        ['x-netacea-captcha'] = constants.captchaStates.SERVE,
                        ['x-netacea-redirect-host'] = nil
                    }
                }, nil
            end)
        }

        http_mock = {
            new = function()
                return http_mock_instance
            end
        }

        package.loaded['ngx'] = ngx_mock
        package.loaded['resty.http'] = http_mock
        package.loaded['cjson'] = {
            encode = function(obj) return '{}' end
        }
        package.loaded['lua_resty_netacea_protector_client'] = nil

        ProtectorClient = require('lua_resty_netacea_protector_client')
    end)

    after_each(function()
        package.loaded['lua_resty_netacea_protector_client'] = nil
        package.loaded['ngx'] = nil
        package.loaded['resty.http'] = nil
        package.loaded['cjson'] = nil
    end)

    describe("new", function()
        it("should create a new instance with provided options", function()
            local client = ProtectorClient:new({
                apiKey = "test-api-key",
                mitigationEndpoint = { "https://endpoint1.example.com" }
            })
            assert.are.equal("test-api-key", client.apiKey)
            assert.are.same({ "https://endpoint1.example.com" }, client.mitigationEndpoint)
            assert.are.equal(0, client.endpointIndex)
        end)

        it("should default mitigationEndpoint to empty table", function()
            local client = ProtectorClient:new({ apiKey = "key" })
            assert.are.same({}, client.mitigationEndpoint)
        end)
    end)

    describe("getMitigationRequestHeaders", function()
        it("should return headers with api key and client info", function()
            local client = ProtectorClient:new({
                apiKey = "test-api-key",
                mitigationEndpoint = { "https://endpoint1.example.com" }
            })
            local headers = client:getMitigationRequestHeaders()
            assert.are.equal("test-api-key", headers["x-netacea-api-key"])
            assert.are.equal("application/x-www-form-urlencoded", headers["content-type"])
            assert.are.equal("Test-Agent/1.0", headers["user-agent"])
            assert.are.equal("192.168.1.1", headers["x-netacea-client-ip"])
            assert.are.equal("user123", headers["x-netacea-userid"])
        end)

        it("should include captcha cookie when present", function()
            ngx_mock.ctx.NetaceaState.captcha_cookie = "captcha_value_123"
            local client = ProtectorClient:new({
                apiKey = "test-api-key",
                mitigationEndpoint = { "https://endpoint1.example.com" }
            })
            local headers = client:getMitigationRequestHeaders()
            assert.are.equal("_mitatacaptcha=captcha_value_123", headers["cookie"])
        end)

        it("should set empty cookie when captcha cookie is nil", function()
            ngx_mock.ctx.NetaceaState.captcha_cookie = nil
            local client = ProtectorClient:new({
                apiKey = "test-api-key",
                mitigationEndpoint = { "https://endpoint1.example.com" }
            })
            local headers = client:getMitigationRequestHeaders()
            assert.are.equal("", headers["cookie"])
        end)

        it("should default user_agent to empty string when nil", function()
            ngx_mock.ctx.NetaceaState.user_agent = nil
            local client = ProtectorClient:new({
                apiKey = "test-api-key",
                mitigationEndpoint = { "https://endpoint1.example.com" }
            })
            local headers = client:getMitigationRequestHeaders()
            assert.are.equal("", headers["user-agent"])
        end)

        it("should default client to empty string when nil", function()
            ngx_mock.ctx.NetaceaState.client = nil
            local client = ProtectorClient:new({
                apiKey = "test-api-key",
                mitigationEndpoint = { "https://endpoint1.example.com" }
            })
            local headers = client:getMitigationRequestHeaders()
            assert.are.equal("", headers["x-netacea-client-ip"])
        end)

        it("should default UserId to empty string when nil", function()
            ngx_mock.ctx.NetaceaState.UserId = nil
            local client = ProtectorClient:new({
                apiKey = "test-api-key",
                mitigationEndpoint = { "https://endpoint1.example.com" }
            })
            local headers = client:getMitigationRequestHeaders()
            assert.are.equal("", headers["x-netacea-userid"])
        end)
    end)

    describe("checkReputation", function()
        it("should make a GET request to the mitigation endpoint", function()
            local client = ProtectorClient:new({
                apiKey = "test-api-key",
                mitigationEndpoint = { "https://endpoint1.example.com" }
            })
            client:checkReputation()
            assert.spy(http_mock_instance.request_uri).was.called(1)
            local call_args = http_mock_instance.request_uri.calls[1]
            assert.are.equal("https://endpoint1.example.com", call_args.vals[2])
            assert.are.equal("GET", call_args.vals[3].method)
        end)

        it("should return parsed response with mitigation headers", function()
            local client = ProtectorClient:new({
                apiKey = "test-api-key",
                mitigationEndpoint = { "https://endpoint1.example.com" }
            })
            local result = client:checkReputation()
            assert.are.equal(200, result.response.status)
            assert.are.equal("<html>response</html>", result.response.body)
            assert.are.equal(constants.idTypes.IP, result.match)
            assert.are.equal(constants.mitigationTypes.BLOCKED, result.mitigate)
            assert.are.equal(constants.captchaStates.SERVE, result.captcha)
            assert.is_nil(result.redirectHost)
        end)

        it("should include redirectHost when present in response", function()
            http_mock_instance.request_uri = spy.new(function()
                return {
                    status = 200,
                    body = "",
                    headers = {
                        ['x-netacea-match'] = constants.idTypes.IP,
                        ['x-netacea-mitigate'] = constants.mitigationTypes.MONETISED,
                        ['x-netacea-captcha'] = constants.captchaStates.NONE,
                        ['x-netacea-redirect-host'] = 'redirect.example.com'
                    }
                }, nil
            end)
            local client = ProtectorClient:new({
                apiKey = "test-api-key",
                mitigationEndpoint = { "https://endpoint1.example.com" }
            })
            local result = client:checkReputation()
            assert.are.equal("redirect.example.com", result.redirectHost)
        end)

        it("should default missing headers to NONE constants", function()
            http_mock_instance.request_uri = spy.new(function()
                return {
                    status = 200,
                    body = "",
                    headers = {}
                }, nil
            end)
            local client = ProtectorClient:new({
                apiKey = "test-api-key",
                mitigationEndpoint = { "https://endpoint1.example.com" }
            })
            local result = client:checkReputation()
            assert.are.equal(constants.idTypes.NONE, result.match)
            assert.are.equal(constants.mitigationTypes.NONE, result.mitigate)
            assert.are.equal(constants.captchaStates.NONE, result.captcha)
        end)

        it("should return nil on HTTP error", function()
            http_mock_instance.request_uri = spy.new(function()
                return nil, "connection refused"
            end)
            local client = ProtectorClient:new({
                apiKey = "test-api-key",
                mitigationEndpoint = { "https://endpoint1.example.com" }
            })
            local result = client:checkReputation()
            assert.is_nil(result)
        end)

        it("should round-robin across multiple endpoints", function()
            local client = ProtectorClient:new({
                apiKey = "test-api-key",
                mitigationEndpoint = {
                    "https://endpoint1.example.com",
                    "https://endpoint2.example.com"
                }
            })
            client:checkReputation()
            local first_url = http_mock_instance.request_uri.calls[1].vals[2]
            assert.are.equal("https://endpoint2.example.com", first_url)

            client:checkReputation()
            local second_url = http_mock_instance.request_uri.calls[2].vals[2]
            assert.are.equal("https://endpoint1.example.com", second_url)

            client:checkReputation()
            local third_url = http_mock_instance.request_uri.calls[3].vals[2]
            assert.are.equal("https://endpoint2.example.com", third_url)
        end)
    end)

    describe("validateCaptcha", function()
        it("should make a POST request to the captcha endpoint", function()
            local client = ProtectorClient:new({
                apiKey = "test-api-key",
                mitigationEndpoint = { "https://endpoint1.example.com" }
            })
            client:validateCaptcha("captcha_response_data")
            assert.spy(http_mock_instance.request_uri).was.called(1)
            local call_args = http_mock_instance.request_uri.calls[1]
            assert.are.equal("https://endpoint1.example.com/AtaVerifyCaptcha", call_args.vals[2])
            assert.are.equal("POST", call_args.vals[3].method)
            assert.are.equal("captcha_response_data", call_args.vals[3].body)
        end)

        it("should return exit_status HTTP_OK when captcha passes", function()
            http_mock_instance.request_uri = spy.new(function()
                return {
                    status = 200,
                    body = "",
                    headers = {
                        ['x-netacea-match'] = constants.idTypes.IP,
                        ['x-netacea-mitigate'] = constants.mitigationTypes.BLOCKED,
                        ['x-netacea-captcha'] = constants.captchaStates.PASS,
                        ['X-Netacea-MitATACaptcha-Value'] = 'captcha_cookie_val'
                    }
                }, nil
            end)
            local client = ProtectorClient:new({
                apiKey = "test-api-key",
                mitigationEndpoint = { "https://endpoint1.example.com" }
            })
            local result = client:validateCaptcha("captcha_data")
            assert.are.equal(ngx_mock.HTTP_OK, result.exit_status)
            assert.are.equal(constants.captchaStates.PASS, result.captcha)
            assert.are.equal("captcha_cookie_val", result.captcha_cookie)
        end)

        it("should return exit_status HTTP_FORBIDDEN when captcha fails", function()
            http_mock_instance.request_uri = spy.new(function()
                return {
                    status = 200,
                    body = "",
                    headers = {
                        ['x-netacea-match'] = constants.idTypes.IP,
                        ['x-netacea-mitigate'] = constants.mitigationTypes.BLOCKED,
                        ['x-netacea-captcha'] = constants.captchaStates.FAIL
                    }
                }, nil
            end)
            local client = ProtectorClient:new({
                apiKey = "test-api-key",
                mitigationEndpoint = { "https://endpoint1.example.com" }
            })
            local result = client:validateCaptcha("captcha_data")
            assert.are.equal(ngx_mock.HTTP_FORBIDDEN, result.exit_status)
            assert.are.equal(constants.captchaStates.FAIL, result.captcha)
        end)

        it("should default missing headers to NONE constants", function()
            http_mock_instance.request_uri = spy.new(function()
                return {
                    status = 200,
                    body = "",
                    headers = {}
                }, nil
            end)
            local client = ProtectorClient:new({
                apiKey = "test-api-key",
                mitigationEndpoint = { "https://endpoint1.example.com" }
            })
            local result = client:validateCaptcha("captcha_data")
            assert.are.equal(constants.idTypes.NONE, result.match)
            assert.are.equal(constants.mitigationTypes.NONE, result.mitigate)
            assert.are.equal(constants.captchaStates.NONE, result.captcha)
            assert.are.equal(ngx_mock.HTTP_FORBIDDEN, result.exit_status)
        end)

        it("should return nil captcha_cookie when header is missing", function()
            http_mock_instance.request_uri = spy.new(function()
                return {
                    status = 200,
                    body = "",
                    headers = {
                        ['x-netacea-match'] = constants.idTypes.NONE,
                        ['x-netacea-mitigate'] = constants.mitigationTypes.NONE,
                        ['x-netacea-captcha'] = constants.captchaStates.FAIL
                    }
                }, nil
            end)
            local client = ProtectorClient:new({
                apiKey = "test-api-key",
                mitigationEndpoint = { "https://endpoint1.example.com" }
            })
            local result = client:validateCaptcha("captcha_data")
            assert.is_nil(result.captcha_cookie)
        end)

        it("should return nil on HTTP error", function()
            http_mock_instance.request_uri = spy.new(function()
                return nil, "timeout"
            end)
            local client = ProtectorClient:new({
                apiKey = "test-api-key",
                mitigationEndpoint = { "https://endpoint1.example.com" }
            })
            local result = client:validateCaptcha("captcha_data")
            assert.is_nil(result)
        end)

        it("should round-robin endpoints for captcha validation", function()
            local client = ProtectorClient:new({
                apiKey = "test-api-key",
                mitigationEndpoint = {
                    "https://endpoint1.example.com",
                    "https://endpoint2.example.com"
                }
            })
            client:validateCaptcha("data1")
            local first_url = http_mock_instance.request_uri.calls[1].vals[2]
            assert.are.equal("https://endpoint2.example.com/AtaVerifyCaptcha", first_url)

            client:validateCaptcha("data2")
            local second_url = http_mock_instance.request_uri.calls[2].vals[2]
            assert.are.equal("https://endpoint1.example.com/AtaVerifyCaptcha", second_url)
        end)

        it("should include full response in result", function()
            http_mock_instance.request_uri = spy.new(function()
                return {
                    status = 200,
                    body = "response body",
                    headers = {
                        ['x-netacea-match'] = constants.idTypes.IP,
                        ['x-netacea-mitigate'] = constants.mitigationTypes.BLOCKED,
                        ['x-netacea-captcha'] = constants.captchaStates.SERVE
                    }
                }, nil
            end)
            local client = ProtectorClient:new({
                apiKey = "test-api-key",
                mitigationEndpoint = { "https://endpoint1.example.com" }
            })
            local result = client:validateCaptcha("captcha_data")
            assert.are.equal(200, result.response.status)
            assert.are.equal("response body", result.response.body)
        end)
    end)
end)
