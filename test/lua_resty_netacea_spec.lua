require("silence_g_write_guard")
require 'busted.runner'()

package.path = "../src/?.lua;" .. package.path

insulate("lua_resty_netacea", function()
    describe("lua_resty_netacea", function()
        local Netacea
        local ngx_mock
        local ingest_instance

        before_each(function()
            ngx_mock = {
                ctx = {},
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
            package.loaded['lua_resty_netacea_cookies_v3'] = {}
            package.loaded['netacea_utils'] = {
                parseOption = function(value, default)
                    if value == nil then return default end
                    return value
                end
            }
            package.loaded['lua_resty_netacea_protector_client'] = {
                new = spy.new(function() return {} end)
            }
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
    end)
end)
