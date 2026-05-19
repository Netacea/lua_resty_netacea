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
                exit = spy.new(function() end),
                req = {
                    read_body = spy.new(function() end),
                    get_body_data = spy.new(function() return "captcha-response" end)
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
            package.loaded['lua_resty_netacea_mitigation'] = {}
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

            it("should not set session or captcha cookies when captcha fails", function()
                protector_client_instance.validateCaptcha = spy.new(function()
                    return {
                        match = "0",
                        mitigate = "0",
                        captcha = "3",
                        exit_status = 403,
                        captcha_cookie = "failed-captcha-cookie"
                    }
                end)
                local netacea = new_mitigation_enabled_netacea()

                netacea:handleCaptcha()

                assert.is_nil(ngx_mock.header["Set-Cookie"])
                assert.spy(cookies_mock.generateNewCookieValue).was_not_called()
                assert.spy(cookies_mock.encrypt).was_not_called()
                assert.spy(ngx_mock.exit).was.called_with(403)
            end)

            it("should refresh session and captcha cookies when captcha passes", function()
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
                assert.spy(ngx_mock.exit).was.called_with(200)
            end)
        end)
    end)
end)
