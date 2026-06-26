require("silence_g_write_guard")
require 'busted.runner'()

package.path = "../src/?.lua;" .. package.path

insulate("lua_resty_netacea", function()
    describe("lua_resty_netacea", function()
        local Netacea
        local ngx_mock
        local ingest_instance
        local cookies_mock
        local protector_client_mock
        local protector_client_instance
        local decode_base64url_mock
        local mitigation_mock

        before_each(function()
            ngx_mock = {
                ctx = {},
                var = {
                    remote_addr = "127.0.0.1",
                    http_user_agent = "Test-Agent",
                    cookie__mitata = ""
                },
                header = {},
                log = spy.new(function() end),
                print = spy.new(function() end),
                exit = spy.new(function() end),
                req = {
                    read_body = spy.new(function() end),
                    get_body_data = spy.new(function() return "captcha-response" end),
                    get_body_file = spy.new(function() return nil end),
                    set_header = spy.new(function() end)
                },
                DEBUG = 7,
                WARN = 4,
                ERR = 3
            }

            ingest_instance = {
                start_timers = spy.new(function() end),
                ingest = spy.new(function() return "ingested" end)
            }

            package.loaded['ngx'] = ngx_mock
            decode_base64url_mock = spy.new(function(value)
                if value == nil or value == "" then return nil end
                if value == "invalid-cookie-encryption-key" then return nil end
                return "decoded-" .. value
            end)
            package.loaded['ngx.base64'] = {
                decode_base64url = decode_base64url_mock
            }
            package.loaded['lua_resty_netacea_ingest'] = {
                new = spy.new(function() return ingest_instance end)
            }
            cookies_mock = {
                parseMitataCookie = spy.new(function()
                    return {
                        valid = false,
                        reason = "no_session"
                    }
                end),
                generateNewCookieValue = spy.new(function()
                    return {
                        mitata_jwe = "new-session-cookie",
                        mitata_plaintext = "plaintext"
                    }
                end),
                newUserId = spy.new(function() return "new-user-id" end),
                decrypt = spy.new(function() return nil end),
                encrypt = spy.new(function() return "encrypted" end)
            }
            package.loaded['lua_resty_netacea_cookies_v3'] = cookies_mock
            package.loaded['netacea_utils'] = {
                parseOption = function(value, default)
                    if value == nil then return default end
                    return value
                end,
                normalizeRelativePath = function(path)
                    if type(path) ~= 'string' then return nil end
                    path = path:match("^%s*(.-)%s*$")
                    if path == '' then return nil end
                    if path:sub(1, 1) ~= '/' then
                        path = '/' .. path
                    end
                    if not path:match("^/[A-Za-z0-9/]*$") then
                        return nil
                    end
                    return path
                end,
                isSafeTrackingId = function(value)
                    return type(value) == 'string' and value:match("^[A-Za-z0-9._~-]+$") ~= nil
                end,
                getIpAddress = spy.new(function()
                    return "127.0.0.1"
                end)
            }
            protector_client_instance = {
                checkReputation = spy.new(function()
                    return {
                        match = "0",
                        mitigate = "0",
                        captcha = "0"
                    }
                end),
                validateCaptcha = spy.new(function()
                    return {
                        match = "0",
                        mitigate = "0",
                        captcha = "2",
                        exit_status = 200,
                        captcha_cookie = "captcha-cookie-value"
                    }
                end)
            }
            protector_client_mock = {
                new = spy.new(function() return protector_client_instance end)
            }
            package.loaded['lua_resty_netacea_protector_client'] = protector_client_mock
            mitigation_mock = {
                getBestMitigation = spy.new(function() return nil end),
                serveCaptcha = spy.new(function() end),
                serveBlock = spy.new(function() end),
                serveMonetisationRedirect = spy.new(function() end),
                serveMonetisationFallback = spy.new(function() end)
            }
            package.loaded['lua_resty_netacea_mitigation'] = mitigation_mock
            package.loaded['cjson'] = {
                encode = function() return "{}" end
            }
            package.loaded['lua_resty_netacea'] = nil

            Netacea = require('lua_resty_netacea')
        end)

        after_each(function()
            package.loaded['lua_resty_netacea'] = nil
            package.loaded['ngx'] = nil
            package.loaded['ngx.base64'] = nil
            package.loaded['lua_resty_netacea_ingest'] = nil
            package.loaded['lua_resty_netacea_cookies_v3'] = nil
            package.loaded['netacea_utils'] = nil
            package.loaded['lua_resty_netacea_protector_client'] = nil
            package.loaded['lua_resty_netacea_mitigation'] = nil
            package.loaded['cjson'] = nil
        end)

        local function new_ingest_enabled_netacea(options)
            options = options or {}
            local config = {
                ingestEnabled = true,
                mitigationType = options.mitigationType or '',
                mitigationEndpoint = options.mitigationEndpoint or '',
                apiKey = "test-api-key",
                cookieEncryptionKey = options.cookieEncryptionKey,
                secretKey = options.secretKey or "test-secret-key",
                blockedResponseStatus = options.blockedResponseStatus,
                kinesisProperties = {
                    stream_name = "test-stream",
                    region = "eu-west-1",
                    aws_access_key = "test-access-key",
                    aws_secret_key = "test-secret-key"
                }
            }
            if options.mitigationEnabled ~= nil then
                config.mitigationEnabled = options.mitigationEnabled
            end
            return Netacea:new(config)
        end

        describe("startup logging", function()
            it("should log ingest mode when only ingest is enabled", function()
                new_ingest_enabled_netacea()

                assert.spy(ngx_mock.log).was.called_with(
                    ngx_mock.DEBUG,
                    "NETACEA CONFIG - integration mode: ",
                    "INGEST"
                )
            end)

            it("should log mitigation mode when mitigation is enabled", function()
                new_ingest_enabled_netacea({
                    mitigationEnabled = true,
                    mitigationType = "MITIGATE",
                    mitigationEndpoint = "https://mitigation.example",
                    cookieEncryptionKey = "test-cookie-encryption-key"
                })

                assert.spy(ngx_mock.log).was.called_with(
                    ngx_mock.DEBUG,
                    "NETACEA CONFIG - integration mode: ",
                    "MITIGATE"
                )
            end)

            it("should log disabled mode when no integration paths are enabled", function()
                Netacea:new({
                    ingestEnabled = false,
                    mitigationEnabled = false,
                    mitigationEndpoint = "",
                    mitigationType = "",
                    apiKey = "test-api-key",
                    cookieEncryptionKey = "test-cookie-encryption-key"
                })

                assert.spy(ngx_mock.log).was.called_with(
                    ngx_mock.DEBUG,
                    "NETACEA CONFIG - integration mode: ",
                    "DISABLED"
                )
            end)
        end)

        describe("protection mode config", function()
            it("should store the configured blocked response status", function()
                local netacea = Netacea:new({
                    ingestEnabled = true,
                    mitigationType = "MITIGATE",
                    mitigationEndpoint = "https://mitigation.example",
                    apiKey = "test-api-key",
                    cookieEncryptionKey = "test-cookie-encryption-key",
                    blockedResponseStatus = "429",
                    kinesisProperties = {
                        stream_name = "test-stream",
                        region = "eu-west-1",
                        aws_access_key = "test-access-key",
                        aws_secret_key = "test-secret-key"
                    }
                })

                assert.are.equal(429, netacea.blockedResponseStatus)
            end)

            it("should disable mitigation when mitigationType is INGEST", function()
                local netacea = Netacea:new({
                    ingestEnabled = true,
                    mitigationType = "INGEST",
                    mitigationEndpoint = "https://mitigation.example",
                    apiKey = "test-api-key",
                    cookieEncryptionKey = "test-cookie-encryption-key",
                    kinesisProperties = {
                        stream_name = "test-stream",
                        region = "eu-west-1",
                        aws_access_key = "test-access-key",
                        aws_secret_key = "test-secret-key"
                    }
                })

                assert.are.equal("INGEST", netacea.mitigationType)
                assert.is_false(netacea.mitigationEnabled)
                assert.spy(protector_client_mock.new).was_not_called()
            end)

            it("should treat mitigationEnabled false as deprecated ingest mode", function()
                local netacea = Netacea:new({
                    ingestEnabled = true,
                    mitigationEnabled = false,
                    mitigationType = "MITIGATE",
                    mitigationEndpoint = "https://mitigation.example",
                    apiKey = "test-api-key",
                    cookieEncryptionKey = "test-cookie-encryption-key",
                    kinesisProperties = {
                        stream_name = "test-stream",
                        region = "eu-west-1",
                        aws_access_key = "test-access-key",
                        aws_secret_key = "test-secret-key"
                    }
                })

                assert.are.equal("INGEST", netacea.mitigationType)
                assert.is_false(netacea.mitigationEnabled)
                assert.spy(ngx_mock.log).was.called_with(
                    ngx_mock.WARN,
                    "NETACEA CONFIG - mitigationEnabled is deprecated; set mitigationType to INGEST instead"
                )
            end)

            it("should inject the recommendation headers without serving mitigation", function()
                protector_client_instance.checkReputation = spy.new(function()
                    return {
                        match = "2",
                        mitigate = "1",
                        captcha = "1",
                        response = {
                            body = "<html>captcha</html>"
                        }
                    }
                end)

                local netacea = Netacea:new({
                    ingestEnabled = false,
                    mitigationType = "INJECT",
                    mitigationEndpoint = "https://mitigation.example",
                    apiKey = "test-api-key",
                    cookieEncryptionKey = "test-cookie-encryption-key"
                })

                netacea:mitigate()

                assert.spy(ngx_mock.req.set_header).was.called_with("x-netacea-match", "2")
                assert.spy(ngx_mock.req.set_header).was.called_with("x-netacea-mitigate", "1")
                assert.spy(ngx_mock.req.set_header).was.called_with("x-netacea-captcha", "1")
                assert.spy(cookies_mock.generateNewCookieValue).was.called(1)
                assert.spy(mitigation_mock.getBestMitigation).was_not_called()
                assert.spy(mitigation_mock.serveCaptcha).was_not_called()
                assert.spy(mitigation_mock.serveBlock).was_not_called()
                assert.spy(mitigation_mock.serveMonetisationRedirect).was_not_called()
                assert.spy(mitigation_mock.serveMonetisationFallback).was_not_called()
                assert.spy(ngx_mock.exit).was_not_called()
            end)

            it("should return HTTP_OK for checkpointSignalPath without proxying to origin", function()
                cookies_mock.parseMitataCookie = spy.new(function()
                    return {
                        valid = true,
                        user_id = "existing-user-id",
                        data = {
                            mat = "2",
                            mit = "4",
                            cap = "0"
                        }
                    }
                end)
                local netacea = Netacea:new({
                    ingestEnabled = false,
                    mitigationType = "MITIGATE",
                    mitigationEndpoint = "https://mitigation.example",
                    apiKey = "test-api-key",
                    cookieEncryptionKey = "test-cookie-encryption-key",
                    checkpointSignalPath = "/CustomCheck"
                })
                ngx_mock.var.uri = "/CustomCheck"

                netacea:mitigate()

                assert.spy(ngx_mock.exit).was.called_with(ngx_mock.OK)
                assert.are.equal("ip_flagged,checkpoint_signal", ngx_mock.ctx.NetaceaState.bc_type)
                assert.spy(protector_client_instance.checkReputation).was_not_called()
                assert.spy(mitigation_mock.getBestMitigation).was_not_called()
                assert.spy(cookies_mock.generateNewCookieValue).was_not_called()
                assert.is_nil(ngx_mock.header["Set-Cookie"])
            end)

            it("should keep checkpointSignalPath unset when omitted", function()
                local netacea = Netacea:new({
                    ingestEnabled = false,
                    mitigationType = "MITIGATE",
                    mitigationEndpoint = "https://mitigation.example",
                    apiKey = "test-api-key",
                    cookieEncryptionKey = "test-cookie-encryption-key"
                })

                assert.is_nil(netacea.checkpointSignalPath)
            end)

            it("should normalize a valid netaceaCaptchaPath and keep matching case-sensitive", function()
                local netacea = Netacea:new({
                    ingestEnabled = false,
                    mitigationType = "MITIGATE",
                    mitigationEndpoint = "https://mitigation.example",
                    apiKey = "test-api-key",
                    cookieEncryptionKey = "test-cookie-encryption-key",
                    netaceaCaptchaPath = "Captcha/Path"
                })

                assert.are.equal("/Captcha/Path", netacea.netaceaCaptchaPath)
            end)

            it("should disable an invalid netaceaCaptchaPath", function()
                local netacea = Netacea:new({
                    ingestEnabled = false,
                    mitigationType = "MITIGATE",
                    mitigationEndpoint = "https://mitigation.example",
                    apiKey = "test-api-key",
                    cookieEncryptionKey = "test-cookie-encryption-key",
                    netaceaCaptchaPath = "/captcha-path"
                })

                assert.is_nil(netacea.netaceaCaptchaPath)
            end)

            it("should inject the recommendation headers from a valid session", function()
                cookies_mock.parseMitataCookie = spy.new(function()
                    return {
                        valid = true,
                        user_id = "existing-user-id",
                        data = {
                            mat = "2",
                            mit = "4",
                            cap = "0"
                        }
                    }
                end)
                ngx_mock.var.cookie__mitata = "existing-session-cookie"

                local netacea = Netacea:new({
                    ingestEnabled = false,
                    mitigationType = "INJECT",
                    mitigationEndpoint = "https://mitigation.example",
                    apiKey = "test-api-key",
                    cookieEncryptionKey = "test-cookie-encryption-key"
                })

                netacea:mitigate()

                assert.spy(ngx_mock.req.set_header).was.called_with("x-netacea-match", "2")
                assert.spy(ngx_mock.req.set_header).was.called_with("x-netacea-mitigate", "4")
                assert.spy(ngx_mock.req.set_header).was.called_with("x-netacea-captcha", "0")
                assert.spy(protector_client_instance.checkReputation).was_not_called()
                assert.spy(cookies_mock.generateNewCookieValue).was_not_called()
                assert.spy(mitigation_mock.getBestMitigation).was_not_called()
                assert.spy(ngx_mock.exit).was_not_called()
            end)

            it("should inject the recommendation headers when best mitigation is flag", function()
                protector_client_instance.checkReputation = spy.new(function()
                    return {
                        match = "2",
                        mitigate = "4",
                        captcha = "0",
                        response = {
                            body = ""
                        }
                    }
                end)
                mitigation_mock.getBestMitigation = spy.new(function()
                    return "flag"
                end)

                local netacea = Netacea:new({
                    ingestEnabled = false,
                    mitigationType = "MITIGATE",
                    mitigationEndpoint = "https://mitigation.example",
                    apiKey = "test-api-key",
                    cookieEncryptionKey = "test-cookie-encryption-key"
                })

                netacea:mitigate()

                assert.spy(ngx_mock.req.set_header).was.called_with("x-netacea-match", "2")
                assert.spy(ngx_mock.req.set_header).was.called_with("x-netacea-mitigate", "4")
                assert.spy(ngx_mock.req.set_header).was.called_with("x-netacea-captcha", "0")
                assert.spy(cookies_mock.generateNewCookieValue).was.called(1)
                assert.spy(mitigation_mock.serveCaptcha).was_not_called()
                assert.spy(mitigation_mock.serveBlock).was_not_called()
                assert.spy(mitigation_mock.serveMonetisationRedirect).was_not_called()
                assert.spy(mitigation_mock.serveMonetisationFallback).was_not_called()
                assert.spy(ngx_mock.exit).was_not_called()
            end)

            it("should inject the recommendation headers from a valid flagged session without calling the protector api", function()
                cookies_mock.parseMitataCookie = spy.new(function()
                    return {
                        valid = true,
                        user_id = "existing-user-id",
                        data = {
                            mat = "2",
                            mit = "4",
                            cap = "0"
                        }
                    }
                end)
                ngx_mock.var.cookie__mitata = "existing-session-cookie"

                local netacea = Netacea:new({
                    ingestEnabled = false,
                    mitigationType = "MITIGATE",
                    mitigationEndpoint = "https://mitigation.example",
                    apiKey = "test-api-key",
                    cookieEncryptionKey = "test-cookie-encryption-key"
                })

                netacea:mitigate()

                assert.spy(ngx_mock.req.set_header).was.called_with("x-netacea-match", "2")
                assert.spy(ngx_mock.req.set_header).was.called_with("x-netacea-mitigate", "4")
                assert.spy(ngx_mock.req.set_header).was.called_with("x-netacea-captcha", "0")
                assert.spy(protector_client_instance.checkReputation).was_not_called()
                assert.spy(cookies_mock.generateNewCookieValue).was_not_called()
                assert.spy(mitigation_mock.getBestMitigation).was_not_called()
                assert.spy(ngx_mock.exit).was_not_called()
            end)

            it("should serve captcha on the configured captcha path with valid trackingId", function()
                protector_client_instance.getCaptchaPage = spy.new(function(_, trackingId)
                    assert.are.equal("e334cc64-6cc2-4193-92dd-237e38bab4a7", trackingId)
                    return {
                        response = {
                            body = "<html>captcha</html>"
                        }
                    }
                end)
                ngx_mock.var.uri = "/captcha"
                ngx_mock.var.arg_trackingId = "e334cc64-6cc2-4193-92dd-237e38bab4a7"

                local netacea = Netacea:new({
                    ingestEnabled = false,
                    mitigationType = "MITIGATE",
                    mitigationEndpoint = "https://mitigation.example",
                    apiKey = "test-api-key",
                    cookieEncryptionKey = "test-cookie-encryption-key",
                    netaceaCaptchaPath = "/captcha"
                })

                netacea:mitigate()

                assert.spy(protector_client_instance.checkReputation).was_not_called()
                assert.spy(protector_client_instance.getCaptchaPage).was.called(1)
                assert.spy(mitigation_mock.serveCaptcha).was.called_with("<html>captcha</html>", {
                    enableCaptchaContentNegotiation = false,
                    netaceaCaptchaPath = "/captcha",
                    captchaPath = "/captcha",
                    trackingId = "e334cc64-6cc2-4193-92dd-237e38bab4a7"
                })
                assert.spy(ngx_mock.exit).was_not_called()
            end)

            it("should serve json captcha when content negotiation is enabled and html is not accepted", function()
                protector_client_instance.checkReputation = spy.new(function()
                    return {
                        match = "2",
                        mitigate = "4",
                        captcha = "1",
                        response = {
                            body = "<html>captcha</html>"
                        }
                    }
                end)
                ngx_mock.var.http_accept = "application/json"

                local netacea = Netacea:new({
                    ingestEnabled = false,
                    mitigationType = "MITIGATE",
                    mitigationEndpoint = "https://mitigation.example",
                    apiKey = "test-api-key",
                    cookieEncryptionKey = "test-cookie-encryption-key",
                    enableCaptchaContentNegotiation = true
                })

                mitigation_mock.getBestMitigation = spy.new(function()
                    return "captcha"
                end)
                netacea:mitigate()

                assert.spy(mitigation_mock.serveCaptcha).was.called_with("<html>captcha</html>", {
                    enableCaptchaContentNegotiation = true,
                    captchaPath = nil
                })
                assert.spy(ngx_mock.exit).was_not_called()
            end)

            it("should keep serving html captcha when netaceaCaptchaPath is configured", function()
                protector_client_instance.checkReputation = spy.new(function()
                    return {
                        match = "2",
                        mitigate = "4",
                        captcha = "1",
                        response = {
                            body = "<html>captcha</html>"
                        }
                    }
                end)
                ngx_mock.var.http_accept = "application/json"

                local netacea = Netacea:new({
                    ingestEnabled = false,
                    mitigationType = "MITIGATE",
                    mitigationEndpoint = "https://mitigation.example",
                    apiKey = "test-api-key",
                    cookieEncryptionKey = "test-cookie-encryption-key",
                    enableCaptchaContentNegotiation = true,
                    netaceaCaptchaPath = "/captcha"
                })

                mitigation_mock.getBestMitigation = spy.new(function()
                    return "captcha"
                end)
                netacea:mitigate()

                assert.spy(mitigation_mock.serveCaptcha).was.called_with("<html>captcha</html>", {
                    enableCaptchaContentNegotiation = true,
                    netaceaCaptchaPath = "/captcha",
                    captchaPath = "/captcha"
                })
                assert.spy(ngx_mock.exit).was_not_called()
            end)

            it("should serve negotiated json for checkpoint responses when netaceaCaptchaPath is configured", function()
                protector_client_instance.checkReputation = spy.new(function()
                    return {
                        match = "2",
                        mitigate = "4",
                        captcha = "1",
                        response = {
                            body = '{"trackingId":"b0343c30-a382-42ad-9d65-fdb005fef054"}'
                        }
                    }
                end)
                ngx_mock.var.http_accept = "application/json"

                local netacea = Netacea:new({
                    ingestEnabled = false,
                    mitigationType = "MITIGATE",
                    mitigationEndpoint = "https://mitigation.example",
                    apiKey = "test-api-key",
                    cookieEncryptionKey = "test-cookie-encryption-key",
                    enableCaptchaContentNegotiation = true,
                    netaceaCaptchaPath = "/captcha"
                })

                mitigation_mock.getBestMitigation = spy.new(function()
                    return "checkpoint"
                end)
                netacea:mitigate()

                assert.spy(mitigation_mock.serveCaptcha).was.called_with('{"trackingId":"b0343c30-a382-42ad-9d65-fdb005fef054"}', {
                    enableCaptchaContentNegotiation = true,
                    netaceaCaptchaPath = "/captcha",
                    captchaPath = "/captcha"
                })
                assert.spy(ngx_mock.exit).was_not_called()
            end)

            it("should not invent a captcha path when netaceaCaptchaPath is unset", function()
                protector_client_instance.checkReputation = spy.new(function()
                    return {
                        match = "2",
                        mitigate = "4",
                        captcha = "1",
                        response = {
                            body = "<html>captcha</html>"
                        }
                    }
                end)
                ngx_mock.var.http_accept = "application/json"

                local netacea = Netacea:new({
                    ingestEnabled = false,
                    mitigationType = "MITIGATE",
                    mitigationEndpoint = "https://mitigation.example",
                    apiKey = "test-api-key",
                    cookieEncryptionKey = "test-cookie-encryption-key",
                    enableCaptchaContentNegotiation = true
                })

                mitigation_mock.getBestMitigation = spy.new(function()
                    return "captcha"
                end)
                netacea:mitigate()

                assert.spy(mitigation_mock.serveCaptcha).was.called_with("<html>captcha</html>", {
                    enableCaptchaContentNegotiation = true,
                    netaceaCaptchaPath = nil,
                    captchaPath = nil
                })
                assert.spy(ngx_mock.exit).was_not_called()
            end)

            it("should ignore invalid trackingId on the configured captcha path", function()
                protector_client_instance.getCaptchaPage = spy.new(function(_, trackingId)
                    assert.is_nil(trackingId)
                    return {
                        response = {
                            body = "<html>captcha</html>"
                        }
                    }
                end)
                ngx_mock.var.uri = "/captcha"
                ngx_mock.var.arg_trackingId = "not a uuid"

                local netacea = Netacea:new({
                    ingestEnabled = false,
                    mitigationType = "MITIGATE",
                    mitigationEndpoint = "https://mitigation.example",
                    apiKey = "test-api-key",
                    cookieEncryptionKey = "test-cookie-encryption-key",
                    netaceaCaptchaPath = "/captcha"
                })

                netacea:mitigate()

                assert.spy(protector_client_instance.checkReputation).was_not_called()
                assert.spy(protector_client_instance.getCaptchaPage).was.called(1)
                assert.spy(mitigation_mock.serveCaptcha).was.called_with("<html>captcha</html>", {
                    enableCaptchaContentNegotiation = false,
                    netaceaCaptchaPath = "/captcha",
                    captchaPath = "/captcha"
                })
                assert.spy(ngx_mock.exit).was_not_called()
            end)

            it("should only enable captcha content negotiation when set to true", function()
                local enabled = Netacea:new({
                    ingestEnabled = false,
                    mitigationType = "MITIGATE",
                    mitigationEndpoint = "https://mitigation.example",
                    apiKey = "test-api-key",
                    cookieEncryptionKey = "test-cookie-encryption-key",
                    enableCaptchaContentNegotiation = true
                })
                local disabled = Netacea:new({
                    ingestEnabled = false,
                    mitigationType = "MITIGATE",
                    mitigationEndpoint = "https://mitigation.example",
                    apiKey = "test-api-key",
                    cookieEncryptionKey = "test-cookie-encryption-key",
                    enableCaptchaContentNegotiation = "true"
                })

                assert.is_true(enabled.enableCaptchaContentNegotiation)
                assert.is_false(disabled.enableCaptchaContentNegotiation)
            end)
        end)

        describe("cookie encryption key config", function()
            it("should pass realIpHeaderIndex to IP address lookup", function()
                local netacea = Netacea:new({
                    ingestEnabled = false,
                    mitigationEnabled = false,
                    mitigationEndpoint = "",
                    mitigationType = "",
                    apiKey = "test-api-key",
                    cookieEncryptionKey = "test-cookie-encryption-key",
                    realIpHeader = "x_forwarded_for",
                    realIpHeaderIndex = -1
                })

                netacea:mitigate()

                assert.spy(package.loaded['netacea_utils'].getIpAddress).was.called_with(
                    package.loaded['netacea_utils'],
                    ngx_mock.var,
                    "x_forwarded_for",
                    -1
                )
            end)

            it("should prefer cookieEncryptionKey as the internal key name", function()
                local netacea = new_ingest_enabled_netacea({
                    cookieEncryptionKey = "test-cookie-encryption-key"
                })

                assert.are.equal("decoded-test-cookie-encryption-key", netacea.cookieEncryptionKey)
                assert.are.equal("decoded-test-cookie-encryption-key", netacea.secretKey)
                assert.spy(decode_base64url_mock).was.called_with("test-cookie-encryption-key")
            end)

            it("should keep secretKey as a backwards-compatible alias", function()
                local netacea = new_ingest_enabled_netacea({
                    secretKey = "test-secret-key"
                })

                assert.are.equal("decoded-test-secret-key", netacea.cookieEncryptionKey)
                assert.are.equal("decoded-test-secret-key", netacea.secretKey)
                assert.spy(decode_base64url_mock).was.called_with("test-secret-key")
            end)

            it("should ignore secretKey when cookieEncryptionKey is also configured", function()
                local netacea = new_ingest_enabled_netacea({
                    cookieEncryptionKey = "test-cookie-encryption-key",
                    secretKey = "ignored-secret-key"
                })

                assert.are.equal("decoded-test-cookie-encryption-key", netacea.cookieEncryptionKey)
                assert.are.equal("decoded-test-cookie-encryption-key", netacea.secretKey)
                assert.spy(decode_base64url_mock).was.called(1)
                assert.spy(decode_base64url_mock).was.called_with("test-cookie-encryption-key")
            end)

            it("should disable sessions and mitigation when the configured key cannot be decoded", function()
                local netacea = new_ingest_enabled_netacea({
                    cookieEncryptionKey = "invalid-cookie-encryption-key",
                    mitigationEnabled = true,
                    mitigationType = "MITIGATE",
                    mitigationEndpoint = "https://mitigation.example"
                })

                assert.are.equal("", netacea.cookieEncryptionKey)
                assert.are.equal("", netacea.secretKey)
                assert.is_false(netacea.sessionEnabled)
                assert.is_false(netacea.mitigationEnabled)
                assert.spy(decode_base64url_mock).was.called(1)
                assert.spy(decode_base64url_mock).was.called_with("invalid-cookie-encryption-key")
                assert.spy(protector_client_mock.new).was_not_called()
            end)

            it("should use cookieEncryptionKey for session cookie operations", function()
                local netacea = new_ingest_enabled_netacea({
                    cookieEncryptionKey = "test-cookie-encryption-key"
                })

                netacea:mitigate()

                assert.spy(cookies_mock.parseMitataCookie).was.called_with(
                    "",
                    "decoded-test-cookie-encryption-key"
                )
                assert.spy(cookies_mock.decrypt).was.called_with(
                    "decoded-test-cookie-encryption-key",
                    ""
                )
            end)
        end)

        describe("ingest", function()
            it("should support ingest-only mode when NetaceaState is missing", function()
                local netacea = new_ingest_enabled_netacea()
                ngx_mock.ctx.NetaceaState = nil

                local result = netacea:ingest()

                assert.are.equal("ingested", result)
                assert.spy(ingest_instance.ingest).was.called(1)
            end)

            it("should support ingest-only mode when protector_result is missing", function()
                local netacea = new_ingest_enabled_netacea()
                ngx_mock.ctx.NetaceaState = {}

                netacea:ingest()

                assert.is_nil(ngx_mock.ctx.NetaceaState.bc_type)
                assert.spy(ingest_instance.ingest).was.called(1)
            end)

            it("should set bc_type when mitigation state is available", function()
                local netacea = new_ingest_enabled_netacea()
                ngx_mock.ctx.NetaceaState = {
                    protector_result = {
                        match = "2",
                        mitigate = "1",
                        captcha = "0"
                    }
                }

                netacea:ingest()

                assert.are.equal("ip_blocked", ngx_mock.ctx.NetaceaState.bc_type)
                assert.spy(ingest_instance.ingest).was.called(1)
            end)
        end)

        describe("session cookie in ingest-only mode", function()
            it("should set a session cookie when mitigation is disabled", function()
                local netacea = new_ingest_enabled_netacea()

                netacea:mitigate()

                assert.are.same({
                    "_mitata=new-session-cookie;Max-Age=86400; Path=/;"
                }, ngx_mock.header["Set-Cookie"])
                assert.are.equal("new-session-cookie", ngx_mock.ctx.mitata)
                assert.are.equal("new-user-id", ngx_mock.ctx.NetaceaState.UserId)
                assert.spy(cookies_mock.generateNewCookieValue).was.called(1)
                assert.spy(protector_client_instance.checkReputation).was_not_called()
            end)

            it("should not refresh a valid session cookie when mitigation is disabled", function()
                cookies_mock.parseMitataCookie = spy.new(function()
                    return {
                        valid = true,
                        user_id = "existing-user-id",
                        data = {
                            mat = "0",
                            mit = "0",
                            cap = "0"
                        }
                    }
                end)
                ngx_mock.var.cookie__mitata = "existing-session-cookie"
                local netacea = new_ingest_enabled_netacea()

                netacea:mitigate()

                assert.is_nil(ngx_mock.header["Set-Cookie"])
                assert.are.equal("existing-session-cookie", ngx_mock.ctx.mitata)
                assert.are.equal("existing-user-id", ngx_mock.ctx.NetaceaState.UserId)
                assert.spy(cookies_mock.generateNewCookieValue).was_not_called()
                assert.spy(protector_client_instance.checkReputation).was_not_called()
            end)
        end)

        describe("captcha handling", function()
            local function new_mitigation_enabled_netacea()
                return Netacea:new({
                    ingestEnabled = false,
                    mitigationEnabled = true,
                    mitigationType = "MITIGATE",
                    mitigationEndpoint = "https://mitigation.example",
                    apiKey = "test-api-key",
                    cookieEncryptionKey = "test-cookie-encryption-key"
                })
            end

            it("should NOT refresh cookies when captcha fails", function()
                protector_client_instance.validateCaptcha = spy.new(function()
                    return {
                        match = "0",
                        mitigate = "0",
                        captcha = "3",
                        exit_status = 403,
                        captcha_cookie = "failed-captcha-cookie",
                        response = {
                            body = "Unauthorized"
                        }
                    }
                end)
                local netacea = new_mitigation_enabled_netacea()

                netacea:handleCaptcha()

                assert.are.same({}, ngx_mock.header["Set-Cookie"] or {})
                assert.spy(cookies_mock.generateNewCookieValue).was_not_called()
                assert.spy(cookies_mock.encrypt).was_not_called()
                assert.spy(ngx_mock.print).was.called_with("Unauthorized")
                assert.spy(ngx_mock.exit).was.called_with(403)
            end)

            it("should refresh session and captcha cookies when captcha passes", function()
                protector_client_instance.validateCaptcha = spy.new(function()
                    return {
                        match = "1",
                        mitigate = "1",
                        captcha = "2",
                        exit_status = 200,
                        captcha_cookie = "captcha-cookie-value",
                        response = {
                            body = "Captcha OK"
                        }
                    }
                end)
                local netacea = new_mitigation_enabled_netacea()

                netacea:handleCaptcha()

                assert.are.same({
                    "_mitata=new-session-cookie;Max-Age=86400; Path=/;",
                    "_mitatacaptcha=encrypted;Max-Age=86400; Path=/;"
                }, ngx_mock.header["Set-Cookie"])
                assert.spy(cookies_mock.generateNewCookieValue).was.called(1)
                assert.spy(cookies_mock.encrypt).was.called_with(
                    "decoded-test-cookie-encryption-key",
                    "captcha-cookie-value"
                )
                assert.spy(ngx_mock.print).was.called_with("Captcha OK")
                assert.spy(ngx_mock.exit).was.called_with(200)
            end)

            it("should read captcha request bodies from the temporary file when needed", function()
                local body_file = os.tmpname()
                local file = assert(io.open(body_file, "wb"))
                file:write("captcha-from-file")
                file:close()

                ngx_mock.req.get_body_data = spy.new(function()
                    return nil
                end)
                ngx_mock.req.get_body_file = spy.new(function()
                    return body_file
                end)

                local captured_body
                protector_client_instance.validateCaptcha = spy.new(function(_, body)
                    captured_body = body
                    return {
                        match = "1",
                        mitigate = "1",
                        captcha = "2",
                        exit_status = 200,
                        captcha_cookie = nil,
                        response = {
                            body = "Captcha OK"
                        }
                    }
                end)

                local netacea = new_mitigation_enabled_netacea()

                netacea:handleCaptcha()

                assert.are.equal("captcha-from-file", captured_body)
                os.remove(body_file)
            end)

            it("should return nil captcha body when the body file cannot be read", function()
                ngx_mock.req.get_body_data = spy.new(function()
                    return nil
                end)
                ngx_mock.req.get_body_file = spy.new(function()
                    return "/tmp/definitely-not-a-real-body-file"
                end)

                local captured_body
                protector_client_instance.validateCaptcha = spy.new(function(_, body)
                    captured_body = body
                    return {
                        match = "1",
                        mitigate = "1",
                        captcha = "2",
                        exit_status = 200,
                        captcha_cookie = nil,
                        response = {
                            body = "Captcha OK"
                        }
                    }
                end)

                local netacea = new_mitigation_enabled_netacea()

                netacea:handleCaptcha()

                assert.is_nil(captured_body)
            end)
        end)
    end)
end)
