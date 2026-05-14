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
                DEBUG = 7,
                ERR = 3
            }

            ingest_instance = {
                start_timers = spy.new(function() end),
                ingest = spy.new(function() return "ingested" end)
            }

            package.loaded['ngx'] = ngx_mock
            package.loaded['ngx.base64'] = {
                decode_base64url = spy.new(function() return "decoded-secret" end)
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
                getIpAddress = function()
                    return "127.0.0.1"
                end
            }
            protector_client_instance = {
                checkReputation = spy.new(function()
                    return {
                        match = "0",
                        mitigate = "0",
                        captcha = "0"
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
            return Netacea:new({
                ingestEnabled = true,
                mitigationEnabled = options.mitigationEnabled or false,
                mitigationType = options.mitigationType or '',
                mitigationEndpoint = options.mitigationEndpoint or '',
                apiKey = "test-api-key",
                secretKey = "test-secret-key",
                kinesisProperties = {
                    stream_name = "test-stream",
                    region = "eu-west-1",
                    aws_access_key = "test-access-key",
                    aws_secret_key = "test-secret-key"
                }
            })
        end

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
    end)
end)
