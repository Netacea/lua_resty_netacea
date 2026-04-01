require("silence_g_write_guard")
require 'busted.runner'()

package.path = "../src/?.lua;" .. package.path

describe("lua_resty_netacea_mitigation", function()
    local mitigation
    local ngx_mock
    local Constants

    before_each(function()
        ngx_mock = {
            HTTP_FORBIDDEN = 403,
            HTTP_OK = 200,
            status = 0,
            header = {},
            print = spy.new(function() end),
            exit = spy.new(function() end)
        }

        package.loaded['ngx'] = ngx_mock
        package.loaded['lua_resty_netacea_mitigation'] = nil
        mitigation = require('lua_resty_netacea_mitigation')
        Constants = require('lua_resty_netacea_constants')
    end)

    after_each(function()
        package.loaded['lua_resty_netacea_mitigation'] = nil
        package.loaded['ngx'] = nil
    end)

    describe("serveCaptcha", function()
        it("should set status to HTTP_FORBIDDEN", function()
            mitigation.serveCaptcha("<html>captcha</html>")
            assert.are.equal(403, ngx_mock.status)
        end)

        it("should set content-type to text/html", function()
            mitigation.serveCaptcha("<html>captcha</html>")
            assert.are.equal("text/html", ngx_mock.header["content-type"])
        end)

        it("should set Cache-Control to no-cache", function()
            mitigation.serveCaptcha("<html>captcha</html>")
            assert.are.equal("max-age=0, no-cache, no-store, must-revalidate", ngx_mock.header["Cache-Control"])
        end)

        it("should print the captcha body", function()
            mitigation.serveCaptcha("<html>captcha</html>")
            assert.spy(ngx_mock.print).was.called_with("<html>captcha</html>")
        end)

        it("should exit with HTTP_OK", function()
            mitigation.serveCaptcha("<html>captcha</html>")
            assert.spy(ngx_mock.exit).was.called_with(200)
        end)
    end)

    describe("serveBlock", function()
        it("should set status to HTTP_FORBIDDEN", function()
            mitigation.serveBlock()
            assert.are.equal(403, ngx_mock.status)
        end)

        it("should set Cache-Control to no-cache", function()
            mitigation.serveBlock()
            assert.are.equal("max-age=0, no-cache, no-store, must-revalidate", ngx_mock.header["Cache-Control"])
        end)

        it("should print 403 Forbidden", function()
            mitigation.serveBlock()
            assert.spy(ngx_mock.print).was.called_with("403 Forbidden")
        end)

        it("should exit with HTTP_FORBIDDEN", function()
            mitigation.serveBlock()
            assert.spy(ngx_mock.exit).was.called_with(403)
        end)
    end)

    describe("serveMonetisationRedirect", function()
        it("should set status to 303", function()
            mitigation.serveMonetisationRedirect("https://example.com/path")
            assert.are.equal(303, ngx_mock.status)
        end)

        it("should set Location header", function()
            mitigation.serveMonetisationRedirect("https://example.com/path")
            assert.are.equal("https://example.com/path", ngx_mock.header["Location"])
        end)

        it("should set Cache-Control to no-cache", function()
            mitigation.serveMonetisationRedirect("https://example.com/path")
            assert.are.equal("max-age=0, no-cache, no-store, must-revalidate", ngx_mock.header["Cache-Control"])
        end)

        it("should print 303 See Other", function()
            mitigation.serveMonetisationRedirect("https://example.com/path")
            assert.spy(ngx_mock.print).was.called_with("303 See Other")
        end)

        it("should exit with 303", function()
            mitigation.serveMonetisationRedirect("https://example.com/path")
            assert.spy(ngx_mock.exit).was.called_with(303)
        end)
    end)

    describe("serveMonetisationFallback", function()
        it("should set status to 402", function()
            mitigation.serveMonetisationFallback()
            assert.are.equal(402, ngx_mock.status)
        end)

        it("should set Cache-Control to no-cache", function()
            mitigation.serveMonetisationFallback()
            assert.are.equal("max-age=0, no-cache, no-store, must-revalidate", ngx_mock.header["Cache-Control"])
        end)

        it("should print 402 Payment Required", function()
            mitigation.serveMonetisationFallback()
            assert.spy(ngx_mock.print).was.called_with("402 Payment Required")
        end)

        it("should exit with 402", function()
            mitigation.serveMonetisationFallback()
            assert.spy(ngx_mock.exit).was.called_with(402)
        end)
    end)

    describe("getBestMitigation", function()
        it("should return nil when protector_result is nil", function()
            assert.is_nil(mitigation.getBestMitigation(nil))
        end)

        it("should return nil when mitigate is NONE", function()
            local result = {
                mitigate = Constants.mitigationTypes.NONE,
                captcha = Constants.captchaStates.NONE
            }
            assert.is_nil(mitigation.getBestMitigation(result))
        end)

        it("should return nil when mitigate is not a known type", function()
            local result = {
                mitigate = 'unknown_value',
                captcha = Constants.captchaStates.NONE
            }
            assert.is_nil(mitigation.getBestMitigation(result))
        end)

        it("should return nil when mitigate is ALLOW", function()
            local result = {
                mitigate = Constants.mitigationTypes.ALLOW,
                captcha = Constants.captchaStates.NONE
            }
            assert.is_nil(mitigation.getBestMitigation(result))
        end)

        it("should return nil when captcha is PASS", function()
            local result = {
                mitigate = Constants.mitigationTypes.BLOCKED,
                captcha = Constants.captchaStates.PASS
            }
            assert.is_nil(mitigation.getBestMitigation(result))
        end)

        it("should return nil when captcha is COOKIEPASS", function()
            local result = {
                mitigate = Constants.mitigationTypes.BLOCKED,
                captcha = Constants.captchaStates.COOKIEPASS
            }
            assert.is_nil(mitigation.getBestMitigation(result))
        end)

        it("should return captcha when mitigate is BLOCKED and captcha is SERVE", function()
            local result = {
                mitigate = Constants.mitigationTypes.BLOCKED,
                captcha = Constants.captchaStates.SERVE
            }
            assert.are.equal('captcha', mitigation.getBestMitigation(result))
        end)

        it("should return captcha when mitigate is BLOCKED and captcha is COOKIEFAIL", function()
            local result = {
                mitigate = Constants.mitigationTypes.BLOCKED,
                captcha = Constants.captchaStates.COOKIEFAIL
            }
            assert.are.equal('captcha', mitigation.getBestMitigation(result))
        end)

        it("should return monetise when mitigate is MONETISED", function()
            local result = {
                mitigate = Constants.mitigationTypes.MONETISED,
                captcha = Constants.captchaStates.NONE
            }
            assert.are.equal('monetise', mitigation.getBestMitigation(result))
        end)

        it("should return block when mitigate is BLOCKED and captcha is NONE", function()
            local result = {
                mitigate = Constants.mitigationTypes.BLOCKED,
                captcha = Constants.captchaStates.NONE
            }
            assert.are.equal('block', mitigation.getBestMitigation(result))
        end)

        it("should return block when mitigate is BLOCKED and captcha is FAIL", function()
            local result = {
                mitigate = Constants.mitigationTypes.BLOCKED,
                captcha = Constants.captchaStates.FAIL
            }
            assert.are.equal('block', mitigation.getBestMitigation(result))
        end)

        it("should return block when mitigate is HARDBLOCKED", function()
            local result = {
                mitigate = Constants.mitigationTypes.HARDBLOCKED,
                captcha = Constants.captchaStates.NONE
            }
            assert.are.equal('block', mitigation.getBestMitigation(result))
        end)

        it("should return block when mitigate is FLAGGED", function()
            local result = {
                mitigate = Constants.mitigationTypes.FLAGGED,
                captcha = Constants.captchaStates.NONE
            }
            assert.are.equal('block', mitigation.getBestMitigation(result))
        end)
    end)
end)
