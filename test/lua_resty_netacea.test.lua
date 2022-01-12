require 'busted.runner'()

package.path = "../src/?.lua;" .. package.path

local runner = require 'luacov.runner'
runner.tick = true
runner.init({savestepsize = 3})
jit.off()

local COOKIE_DELIMITER = '_/@#/'

local netacea_default_params = {
  ingestEndpoint     = 'ingest.endpoint',
  mitigationEndpoint = 'mitigation.endpoint',
  apiKey             = 'api-key',
  secretKey          = 'secret-key',
  realIpHeader       = '',
  ingestEnabled      = true,
  mitigationEnabled  = true,
  mitigationType     = 'MITIGATE'
}

local function copy_table(orig, overrides)
  local copy = {}
  for orig_key, orig_value in pairs(orig) do
      copy[orig_key] = orig_value
  end
  if (overrides) then
    for override_key, override_value in pairs(overrides) do
        copy[override_key] = override_value
    end
  end
  return copy
end

local function wrap_table(table, proxy_table)
  setmetatable(proxy_table, {
    __index = function(_, key)
      return table[key]
    end,
    __newindex = function(_, key, value)
      table[key] = value
    end
  })
  return proxy_table
end

local function build_mitata_cookie(epoch, uid, mitigation_values, key)
  local hmac = require 'openssl.hmac'
  local base64 = require 'base64'
  local netacea = require 'lua_resty_netacea'

  local value = epoch .. COOKIE_DELIMITER .. uid .. COOKIE_DELIMITER .. mitigation_values
  local hash = hmac.new(key, 'sha256'):final(value)
  hash = netacea:bToHex(hash)
  hash = base64.encode(hash)

  return hash .. COOKIE_DELIMITER .. value
end

local function generate_uid()
  return '0000000012345678'
end

insulate("lua_resty_netacea.lua", function()
  describe('new', function()

    it('returns an object with ingest and mitigation enabled on initialisation', function()
      local netacea = (require 'lua_resty_netacea'):new(netacea_default_params)
      assert.is_true(netacea.mitigationEnabled)
      assert.is_true(netacea.ingestEnabled)
    end)

    it('sets endpoint index to 0 on initialisation', function()
      local netacea = (require 'lua_resty_netacea'):new(netacea_default_params)
      assert.is.equal(netacea.endpointIndex, 0)
    end)

    it('sets mitigationEnabled to false if mitigationEndpoint is an empty string', function()
      local params = copy_table(netacea_default_params)
      params.mitigationEndpoint = ''
      local netacea = (require 'lua_resty_netacea'):new(params)
      assert.is_false(netacea.mitigationEnabled)
    end)

    it('sets mitigationEnabled to false if mitigationEndpoint is nil', function()
      local params = copy_table(netacea_default_params)
      params.mitigationEndpoint = nil
      local netacea = (require 'lua_resty_netacea'):new(params)
      assert.is_false(netacea.mitigationEnabled)
    end)

    it('sets mitigationEnabled to false if mitigationEndpoint is nil', function()
      local params = copy_table(netacea_default_params)
      params.mitigationEndpoint = {}
      local netacea = (require 'lua_resty_netacea'):new(params)
      assert.is_false(netacea.mitigationEnabled)
    end)

    it('sets mitigationEnabled to false if mitigationType is nil', function()
      local params = copy_table(netacea_default_params)
      params.mitigationType = {}
      local netacea = (require 'lua_resty_netacea'):new(params)
      assert.is_false(netacea.mitigationEnabled)
    end)

    it('sets mitigationEnabled to false if mitigationType is not MITIGATE or INJECT', function()
      local paramsMitigate = copy_table(netacea_default_params)
      paramsMitigate.mitigationType = 'MITIGATE'
      local netaceaMitigate = (require 'lua_resty_netacea'):new(paramsMitigate)
      assert.is_true(netaceaMitigate.mitigationEnabled)

      local paramsInject = copy_table(netacea_default_params)
      paramsInject.mitigationType = 'INJECT'
      local netaceaInject = (require 'lua_resty_netacea'):new(paramsInject)
      assert.is_true(netaceaInject.mitigationEnabled)

      local paramsOther = copy_table(netacea_default_params)
      paramsOther.mitigationType = 'wefwwg'
      local netaceaOther = (require 'lua_resty_netacea'):new(paramsOther)
      assert.is_false(netaceaOther.mitigationEnabled)
    end)

    it('sets mitigationEndpoint if an array is provided', function()
      local endpointArray = { 'mitigation.endpoint', 'mitigation2.endpoint' }
      local netacea = (require 'lua_resty_netacea'):new(
        copy_table(
          netacea_default_params,
          { mitigationEndpoint = endpointArray }
        )
      )
      assert.are.same(netacea.mitigationEndpoint, endpointArray)
    end)

    it('sets mitigationEndpoint to an array if a string is provided', function()
      local endpoint = 'mitigation.endpoint'
      local netacea = (require 'lua_resty_netacea'):new(
        copy_table(
          netacea_default_params,
          { mitigationEndpoint = endpoint }
        )
      )
      assert.are.same(netacea.mitigationEndpoint, { endpoint })
    end)

    it('sets the module version and type', function()
      local netacea = (require 'lua_resty_netacea'):new(netacea_default_params)
      assert.is.equal(netacea._MODULE_VERSION, '0.2.0')
      assert.is.equal(netacea._MODULE_TYPE, 'nginx')
    end)
  end)

  describe('get_mitata_cookie', function()

    local netacea_init_params = {
      ingestEndpoint     = '',
      mitigationEndpoint = '',
      apiKey             = '',
      secretKey          = 'super_secret',
      realIpHeader       = '',
      ingestEnabled      = false,
      mitigationEnabled  = true,
      mitigationType     = 'MITIGATE'
    }

    it('returns nil if cookie is not present', function()
      local ngx_stub = require 'ngx'
      ngx_stub.var = {
        cookie__mitata = '',
      }
      package.loaded['ngx'] = ngx_stub

      local netacea = (require 'lua_resty_netacea'):new(netacea_init_params)

      local result = netacea:get_mitata_cookie()

      assert(result == nil)
    end)

    it('returns nil if the cookie expiration is not in the future', function()
      local ngx_stub = require 'ngx'
      local t = ngx_stub.time() - 20
      ngx_stub.var = {
        cookie__mitata = build_mitata_cookie(t, generate_uid(), '000', netacea_init_params.secretKey, '000')
      }
      package.loaded['ngx'] = ngx_stub

      local netacea = (require 'lua_resty_netacea'):new(netacea_init_params)

      local result = netacea:get_mitata_cookie()
      assert(result == nil)
    end)

    it('returns nil if the userID is not present', function()
      local ngx_stub = require 'ngx'
      local t = ngx_stub.time() + 20
      ngx_stub.var = {
        cookie__mitata = build_mitata_cookie(t, '', '000', netacea_init_params.secretKey)
      }
      package.loaded['ngx'] = ngx_stub

      local netacea = (require 'lua_resty_netacea'):new(netacea_init_params)

      local result = netacea:get_mitata_cookie()
      assert(result == nil)
    end)

    it('returns nil if the hash value does not match', function()
      local ngx_stub = require 'ngx'
      local t = ngx_stub.time() + 20
      ngx_stub.var = {
        cookie__mitata = 'invalid_hash' .. COOKIE_DELIMITER ..  t .. COOKIE_DELIMITER .. generate_uid()
      }
      package.loaded['ngx'] = ngx_stub

      local netacea = (require 'lua_resty_netacea'):new(netacea_init_params)

      local result = netacea:get_mitata_cookie()
      assert(result == nil)
    end)

    it('returns nil if the cookie is invalid', function()
      local ngx_stub = require 'ngx'
      ngx_stub.var = {
        cookie__mitata = 'someinvalidcookie'
      }
      package.loaded['ngx'] = ngx_stub

      local netacea = (require 'lua_resty_netacea'):new(netacea_init_params)

      local result = netacea:get_mitata_cookie()
      assert(result == nil)
    end)

    it('returns the parsed cookie if the cookie is valid', function()
      local ngx_stub = require 'ngx'
      local t = ngx_stub.time() + 20
      local cookie = build_mitata_cookie(t, generate_uid(), '000', netacea_init_params.secretKey)
      ngx_stub.var = {
        cookie__mitata = cookie
      }
      package.loaded['ngx'] = ngx_stub

      local netacea = (require 'lua_resty_netacea'):new(netacea_init_params)

      local hash, epoch, uid, mitigation = cookie:match('(.*)_/@#/(.*)_/@#/(.*)_/@#/(.*)')
      local expected = {
        original = ngx_stub.var.cookie__mitata,
        hash = hash,
        epoch = tonumber(epoch),
        uid = uid,
        mitigation = mitigation
      }
      local result = netacea:get_mitata_cookie()
      assert.are.same(expected, result)
    end)
  end)

  describe('mitigate', function()
    local match = require('luassert.match')
    local mit_svc_url = 'someurl'
    local mit_svc_url_captcha = mit_svc_url .. '/AtaVerifyCaptcha'
    local mit_svc_api_key = 'somekey'
    local mit_svc_secret = 'somesecret'
    local ngx = nil

    local function stubNgx()
      local ngx_stub = {}

      ngx_stub.var = {
        http_user_agent = 'some_user_agent',
        remote_addr = 'some_remote_addr',
        cookie__mitata = 'some_mitata_cookie',
        request_uri = '-'
      }
      ngx_stub.ctx = {
      }
      ngx_stub.req = {
        read_body = function() return nil end,
        get_body_data = function() return nil end
      }

      ngx_stub.header = {}
      ngx_stub.status = 0
      ngx_stub.HTTP_FORBIDDEN = 402

      ngx_stub.exit = spy.new(function(_, _) return nil end)
      ngx_stub.print = spy.new(function(_, _) return nil end)

      ngx = wrap_table(require 'ngx', ngx_stub)
      package.loaded['ngx'] = ngx
    end

    local function setHttpResponse(url, response, err)
      package.loaded['http'] = nil
      local http_mock = require('resty.http')

      local req_spy = spy.new(function(_, _url, _)
        if (url) then
          assert(_url == url)
        end
        return response, err
      end)

      http_mock.new = function()
        return {
          request_uri = req_spy
        }
      end

      package.loaded['http'] = http_mock

      return req_spy
    end

    before_each(function()
      package.loaded['lua_resty_netacea'] = nil

      stubNgx()
    end)

    it('forwards to mit svc if mitata cookie check fails', function()
      local req_spy = setHttpResponse(mit_svc_url, nil, 'error')

      local netacea = (require 'lua_resty_netacea'):new({
        ingestEndpoint     = '',
        mitigationEndpoint = mit_svc_url,
        apiKey             = mit_svc_api_key,
        secretKey          = mit_svc_secret,
        realIpHeader       = '',
        ingestEnabled      = false,
        mitigationEnabled  = true,
        mitigationType     = 'MITIGATE'
      })

      netacea.get_mitata_cookie = spy.new(function () return nil end)

      netacea:run()

      local _ = match._

      assert.spy(req_spy).was.called(1)
      assert.spy(req_spy).was.called_with(_, mit_svc_url, {
        method = 'GET',
        headers = {
          ['x-netacea-api-key'] = mit_svc_api_key,
          ['content-type'] = 'application/x-www-form-urlencoded',
          ['user-agent'] = ngx.var.http_user_agent,
          ['x-netacea-client-ip'] = ngx.var.remote_addr,
          ["cookie"] = "_mitata=" .. ngx.var.cookie__mitata .. ';_mitatacaptcha='
        },
        timeout = 1000 -- default I suppose
      })
    end)

    it('does not forward to mit svc if mitata cookie is valid', function()
      local req_spy = setHttpResponse('-', nil, 'error')

      local netacea = (require 'lua_resty_netacea'):new({
        ingestEndpoint     = '',
        mitigationEndpoint = mit_svc_url,
        apiKey             = mit_svc_api_key,
        secretKey          = mit_svc_secret,
        realIpHeader       = '',
        ingestEnabled      = false,
        mitigationEnabled  = true,
        mitigationType     = 'MITIGATE'
      })

      local cookie = {
        mitigation = "000"
      }

      netacea.get_mitata_cookie = spy.new(function () return cookie end)

      netacea:run()

      assert.spy(req_spy).was.not_called()
    end)

    it('does not forward to mit service if mitata cookie is ALLOW', function()
      local req_spy = setHttpResponse('-', nil, 'error')

      local netacea = require 'lua_resty_netacea'
      local mit = netacea.idTypes.IP .. netacea.mitigationTypes.ALLOW .. netacea.captchaStates.NONE
      ngx.var.cookie__mitata = build_mitata_cookie(ngx.time() + 20, generate_uid(), mit, mit_svc_secret)

      package.loaded['lua_resty_netacea'] = nil
      netacea = (require 'lua_resty_netacea'):new({
        ingestEndpoint     = '',
        mitigationEndpoint = mit_svc_url,
        apiKey             = mit_svc_api_key,
        secretKey          = mit_svc_secret,
        realIpHeader       = '',
        ingestEnabled      = false,
        mitigationEnabled  = true,
        mitigationType     = 'MITIGATE'
      })

      local logFunc = spy.new(function(res)
        assert.equal(netacea.idTypes.IP, res.idType)
        assert.equal(netacea.mitigationTypes.ALLOW, res.mitigationType)
        assert.equal(netacea.captchaStates.NONE, res.captchaState)
      end)

      netacea:run(logFunc)

      assert.spy(req_spy).was.not_called()
      assert.spy(logFunc).was.called()
    end)

    it('does not forward to mit service if mitata cookie is BLOCK', function()
      local req_spy = setHttpResponse('-', nil, 'error')

      local netacea = (require 'lua_resty_netacea'):new({
        ingestEndpoint     = '',
        mitigationEndpoint = mit_svc_url,
        apiKey             = mit_svc_api_key,
        secretKey          = mit_svc_secret,
        realIpHeader       = '',
        ingestEnabled      = false,
        mitigationEnabled  = true,
        mitigationType     = 'MITIGATE'
      })

      local mit = netacea.idTypes.IP .. netacea.mitigationTypes.BLOCKED .. netacea.captchaStates.NONE
      ngx.var.cookie__mitata = build_mitata_cookie(ngx.time() + 20, generate_uid(), mit, mit_svc_secret)

      local logFunc = spy.new(function(res)
        assert(res.idType == netacea.idTypes.IP)
        assert(res.mitigationType == netacea.mitigationTypes.BLOCKED)
        assert(res.captchaState == netacea.captchaStates.NONE)
      end)

      netacea:run(logFunc)

      assert.spy(req_spy).was.not_called()
      assert(ngx.status == ngx.HTTP_FORBIDDEN)
      assert.spy(ngx.print).was.called_with('403 Forbidden')

      assert(ngx.header['Cache-Control'] == 'max-age=0, no-cache, no-store, must-revalidate')
      assert.spy(ngx.exit).was.called()
      assert.spy(logFunc).was.called()
    end)

    it('allows customisation of response if mitata cookie is BLOCK', function()
      local expected_block_status_code = 499
      local expected_block_body = 'Blocked'

      local req_spy = setHttpResponse('-', nil, 'error')

      local netacea = (require 'lua_resty_netacea'):new({
        ingestEndpoint     = '',
        mitigationEndpoint = mit_svc_url,
        apiKey             = mit_svc_api_key,
        secretKey          = mit_svc_secret,
        realIpHeader       = '',
        ingestEnabled      = false,
        mitigationEnabled  = true,
        mitigationType     = 'MITIGATE',
        blockStatusCode    = expected_block_status_code,
        blockBody          = expected_block_body
      })

      local mit = netacea.idTypes.IP .. netacea.mitigationTypes.BLOCKED .. netacea.captchaStates.NONE
      ngx.var.cookie__mitata = build_mitata_cookie(ngx.time() + 20, generate_uid(), mit, mit_svc_secret)

      local logFunc = spy.new(function(res)
        assert(res.idType == netacea.idTypes.IP)
        assert(res.mitigationType == netacea.mitigationTypes.BLOCKED)
        assert(res.captchaState == netacea.captchaStates.NONE)
      end)

      netacea:run(logFunc)

      assert.spy(req_spy).was.not_called()
      assert(ngx.status == expected_block_status_code)
      assert.spy(ngx.print).was.called_with(expected_block_body)

      assert(ngx.header['Cache-Control'] == 'max-age=0, no-cache, no-store, must-revalidate')
      assert.spy(ngx.exit).was.called()
      assert.spy(logFunc).was.called()
    end)

    it('forwards to mit service if mitata cookie is CAPTCHA SERVE', function()
      local expected_captcha_body = 'some captcha body'
      local netacea = require 'lua_resty_netacea'
      local req_spy = setHttpResponse(mit_svc_url, {
        headers = {
          ['x-netacea-match'] = netacea.idTypes.IP,
          ['x-netacea-mitigate'] = netacea.mitigationTypes.BLOCKED,
          ['x-netacea-captcha'] = netacea.captchaStates.SERVE
        },
        status = 200,
        body = expected_captcha_body
      }, nil)

      package.loaded['lua_resty_netacea'] = nil
      netacea = (require 'lua_resty_netacea'):new({
        ingestEndpoint     = '',
        mitigationEndpoint = mit_svc_url,
        apiKey             = mit_svc_api_key,
        secretKey          = mit_svc_secret,
        realIpHeader       = '',
        ingestEnabled      = false,
        mitigationEnabled  = true,
        mitigationType     = 'MITIGATE'
      })

      local mit = netacea.idTypes.IP .. netacea.mitigationTypes.BLOCKED .. netacea.captchaStates.SERVE
      ngx.var.cookie__mitata = build_mitata_cookie(ngx.time() + 20, generate_uid(), mit, mit_svc_secret)

      local logFunc = spy.new(function(res)
        assert(res.idType == netacea.idTypes.IP)
        assert(res.mitigationType == netacea.mitigationTypes.BLOCKED)
        assert(res.captchaState == netacea.captchaStates.SERVE)
      end)

      netacea:run(logFunc)

      assert.spy(req_spy).was.called()
      assert(ngx.status == ngx.HTTP_FORBIDDEN)
      assert.spy(ngx.print).was.called_with(expected_captcha_body)
      assert(ngx.header['Cache-Control'] == 'max-age=0, no-cache, no-store, must-revalidate')
      assert.spy(ngx.exit).was.called()
      assert.spy(logFunc).was.called()
    end)

    it('it allows custom HTTP status code if mitata cookie is CAPTCHA SERVE', function()
      local expected_captcha_status_code = 498
      local expected_captcha_body = 'some captcha body'
      local netacea = require 'lua_resty_netacea'
      local req_spy = setHttpResponse(mit_svc_url, {
        headers = {
          ['x-netacea-match'] = netacea.idTypes.IP,
          ['x-netacea-mitigate'] = netacea.mitigationTypes.BLOCKED,
          ['x-netacea-captcha'] = netacea.captchaStates.SERVE
        },
        status = 200,
        body = expected_captcha_body
      }, nil)

      package.loaded['lua_resty_netacea'] = nil
      netacea = (require 'lua_resty_netacea'):new({
        ingestEndpoint     = '',
        mitigationEndpoint = mit_svc_url,
        apiKey             = mit_svc_api_key,
        secretKey          = mit_svc_secret,
        realIpHeader       = '',
        ingestEnabled      = false,
        mitigationEnabled  = true,
        mitigationType     = 'MITIGATE',
        captchaStatusCode  = expected_captcha_status_code
      })

      local mit = netacea.idTypes.IP .. netacea.mitigationTypes.BLOCKED .. netacea.captchaStates.SERVE
      ngx.var.cookie__mitata = build_mitata_cookie(ngx.time() + 20, generate_uid(), mit, mit_svc_secret)

      local logFunc = spy.new(function(res)
        assert(res.idType == netacea.idTypes.IP)
        assert(res.mitigationType == netacea.mitigationTypes.BLOCKED)
        assert(res.captchaState == netacea.captchaStates.SERVE)
      end)

      netacea:run(logFunc)

      assert.spy(req_spy).was.called()
      assert(ngx.status == expected_captcha_status_code)
      assert.spy(ngx.print).was.called_with(expected_captcha_body)
      assert(ngx.header['Cache-Control'] == 'max-age=0, no-cache, no-store, must-revalidate')
      assert.spy(ngx.exit).was.called()
      assert.spy(logFunc).was.called()
    end)

    it('serves captcha if client is mitigated', function()
      local expected_captcha_body = 'some captcha body'

      local netacea = require 'lua_resty_netacea'

      local req_spy = setHttpResponse(mit_svc_url, {
        headers = {
          ['x-netacea-match'] = netacea.idTypes.IP,
          ['x-netacea-mitigate'] = netacea.mitigationTypes.BLOCKED,
          ['x-netacea-captcha'] = netacea.captchaStates.SERVE
        },
        status = 200,
        body = expected_captcha_body
      }, nil)

      package.loaded['lua_resty_netacea'] = nil
      netacea = (require 'lua_resty_netacea'):new({
        ingestEndpoint     = '',
        mitigationEndpoint = mit_svc_url,
        apiKey             = mit_svc_api_key,
        secretKey          = mit_svc_secret,
        realIpHeader       = '',
        ingestEnabled      = false,
        mitigationEnabled  = true,
        mitigationType     = 'MITIGATE'
      })

      local logFunc = spy.new(function(res)
        assert(res.idType == netacea.idTypes.IP)
        assert(res.mitigationType == netacea.mitigationTypes.BLOCKED)
        assert(res.captchaState == netacea.captchaStates.SERVE)
      end)

      netacea:run(logFunc)

      assert(ngx.status == ngx.HTTP_FORBIDDEN)
      assert.spy(req_spy).was.called()
      assert.spy(ngx.exit).was.called()
      assert.spy(ngx.print).was.called_with(expected_captcha_body)
      assert.spy(logFunc).was.called()
    end)

    it('returns captcha pass state on positive verification', function()
      ngx.var.request_uri = 'AtaVerifyCaptcha'

      local netacea = require 'lua_resty_netacea'

      setHttpResponse(mit_svc_url_captcha, {
        headers = {
          ['x-netacea-mitatacaptcha-value'] = nil,
          ['x-netacea-mitatacaptcha-expiry'] = nil,
          ['x-netacea-captcha'] = netacea.captchaStates.PASS
        },
        status = 200,
        body = 'body'
      }, nil)

      package.loaded['lua_resty_netacea'] = nil
      netacea = (require 'lua_resty_netacea'):new({
        ingestEndpoint     = '',
        mitigationEndpoint = mit_svc_url,
        apiKey             = mit_svc_api_key,
        secretKey          = mit_svc_secret,
        realIpHeader       = '',
        ingestEnabled      = false,
        mitigationEnabled  = true,
        mitigationType     = 'MITIGATE'
      })

      local logFunc = spy.new(function(res)
        assert(res.captchaState == netacea.captchaStates.PASS)
      end)

      netacea:run(logFunc)

      assert.spy(logFunc).was.called()
    end)

    it('returns captcha fail state on negative verification', function()
      ngx.var.request_uri = 'AtaVerifyCaptcha'

      local netacea = require 'lua_resty_netacea'
      package.loaded['lua_resty_netacea'] = nil

      setHttpResponse(mit_svc_url_captcha, {
        headers = {
          ['x-netacea-mitatacaptcha-value'] = nil,
          ['x-netacea-mitatacaptcha-expiry'] = nil,
          ['x-netacea-captcha'] = netacea.captchaStates.FAIL
        },
        status = 200,
        body = 'body'
      }, nil)

      netacea = (require 'lua_resty_netacea'):new({
        ingestEndpoint     = '',
        mitigationEndpoint = mit_svc_url,
        apiKey             = mit_svc_api_key,
        secretKey          = mit_svc_secret,
        realIpHeader       = '',
        ingestEnabled      = false,
        mitigationEnabled  = true,
        mitigationType     = 'MITIGATE'
      })

      local logFunc = spy.new(function(res)
        assert(res.captchaState == netacea.captchaStates.FAIL)
      end)

      netacea:run(logFunc)

      assert.spy(logFunc).was.called()
    end)

    it('returns correct state', function()
      local netacea = require 'lua_resty_netacea'
      package.loaded['lua_resty_netacea'] = nil

      local testMitigationTypes = netacea.mitigationTypes
      local testIdTypes = netacea.idTypes
      local testCaptchaStates = netacea.captchaStates
      local unknownHeader = 'Q'
      testMitigationTypes['UNKNOWN'] = unknownHeader
      testIdTypes['UNKNOWN'] = unknownHeader
      testCaptchaStates['UNKNOWN'] = unknownHeader

      for _, id in pairs(testIdTypes) do
        for _, mit in pairs(testMitigationTypes) do
          for _, captcha in pairs(testCaptchaStates) do
            local allowed = (mit == netacea.mitigationTypes.NONE or
              mit == unknownHeader or
              mit == netacea.mitigationTypes.ALLOW or
              captcha == netacea.captchaStates.PASS or
              captcha == netacea.captchaStates.COOKIEPASS)

            ngx.status = 0
            ngx.exit:clear()

            local req_spy = setHttpResponse(mit_svc_url, {
              headers = {
                ['x-netacea-match'] = id,
                ['x-netacea-mitigate'] = mit,
                ['x-netacea-captcha'] = captcha
              },
              status = 200
            }, nil)

            package.loaded['lua_resty_netacea'] = nil
            netacea = (require 'lua_resty_netacea'):new({
              ingestEndpoint     = '',
              mitigationEndpoint = mit_svc_url,
              apiKey             = mit_svc_api_key,
              secretKey          = mit_svc_secret,
              realIpHeader       = '',
              ingestEnabled      = false,
              mitigationEnabled  = true,
              mitigationType     = 'MITIGATE'
            })


            local logFunc = spy.new(function(res)
              assert.are.equal(res.idType, id)
              assert.are.equal(res.mitigationType, mit)
              assert.are.equal(res.captchaState, captcha)
            end)

            netacea:run(logFunc)

            if not allowed then
              if ngx.status ~= ngx.HTTP_FORBIDDEN then
                assert.spy(ngx.exit).was.called_with(ngx.HTTP_FORBIDDEN)
              else
                assert.are.equal(ngx.HTTP_FORBIDDEN, ngx.status)
                assert.spy(ngx.exit).was.called()
              end

              assert.spy(logFunc).was.called()
            else
              if ngx.status ~= ngx.HTTP_FORBIDDEN then
                assert.spy(ngx.exit).was_not_called_with(ngx.HTTP_FORBIDDEN)
                assert.spy(ngx.exit).was_not.called()
              else
                assert.are.not_equal(ngx.HTTP_FORBIDDEN, ngx.status)
                assert.spy(ngx.exit).was_not.called()
              end
            end

            assert.spy(req_spy).was.called()
          end
        end
      end
    end)

    it('Uses and forwards configured user id variable', function()
      local userIdKey = 'customUserIdValue'
      local userIdVal = 'someCustomUserId'

      local req_spy = setHttpResponse(mit_svc_url, nil, 'error')
      ngx.var[userIdKey] = userIdVal

      local netacea = (require 'lua_resty_netacea'):new({
        mitigationEndpoint = mit_svc_url,
        apiKey             = mit_svc_api_key,
        secretKey          = mit_svc_secret,
        mitigationEnabled  = true,
        userIdKey          = userIdKey,
        mitigationType     = 'MITIGATE'
      })

      netacea:run()

      local _ = match._
      assert.spy(req_spy).was.called_with(_, mit_svc_url, {
        method = 'GET',
        headers = {
          ['x-netacea-api-key'] = mit_svc_api_key,
          ['user-agent'] = ngx.var.http_user_agent,
          ["content-type"] = 'application/x-www-form-urlencoded',
          ['x-netacea-client-ip'] = ngx.var.remote_addr,
          ["cookie"] = "_mitata=" .. ngx.var.cookie__mitata .. ';_mitatacaptcha=',
          ["x-netacea-userid"] = userIdVal
        },
        timeout = 1000 -- default I suppose
      })
    end)

    it('Does not send custom id header if var is not set', function()
      local userIdKey = 'customUserIdValue'

      local req_spy = setHttpResponse(mit_svc_url, nil, 'error')

      local netacea = (require 'lua_resty_netacea'):new({
        mitigationEndpoint = mit_svc_url,
        apiKey             = mit_svc_api_key,
        secretKey          = mit_svc_secret,
        mitigationEnabled  = true,
        userIdKey          = userIdKey,
        mitigationType     = 'MITIGATE'
      })

      netacea:run()

      local _ = match._
      assert.spy(req_spy).was.called_with(_, mit_svc_url, {
        method = 'GET',
        headers = {
          ['x-netacea-api-key'] = mit_svc_api_key,
          ['content-type'] = 'application/x-www-form-urlencoded',
          ['user-agent'] = ngx.var.http_user_agent,
          ['x-netacea-client-ip'] = ngx.var.remote_addr,
          ["cookie"] = "_mitata=" .. ngx.var.cookie__mitata .. ';_mitatacaptcha='
        },
        timeout = 1000 -- default I suppose
      })
    end)

    it('converts non-captcha attempt captcha PASS to COOKIEPASS', function()
      local netacea = (require 'lua_resty_netacea')
      setHttpResponse(mit_svc_url, {
        headers = {
          ['x-netacea-match'] = netacea.idTypes.IP,
          ['x-netacea-mitigate'] = netacea.mitigationTypes.BLOCKED,
          ['x-netacea-captcha'] = netacea.captchaStates.PASS
        },
        status = 200
      }, nil)

      local mit = netacea.idTypes.IP .. netacea.mitigationTypes.BLOCKED .. netacea.captchaStates.PASS
      ngx.var.cookie__mitata = build_mitata_cookie(ngx.time() + 20, generate_uid(), mit, mit_svc_secret)

      package.loaded['lua_resty_netacea'] = nil

      netacea = (require 'lua_resty_netacea'):new({
        mitigationEndpoint = mit_svc_url,
        apiKey             = mit_svc_api_key,
        secretKey          = mit_svc_secret,
        mitigationEnabled  = true,
        mitigationType     = 'MITIGATE'
      })

      local logFunc = spy.new(function(res)
        assert.are.equal(res.idType, netacea.idTypes.IP)
        assert.are.equal(res.mitigationType, netacea.mitigationTypes.BLOCKED)
        assert.are.equal(res.captchaState, netacea.captchaStates.COOKIEPASS)
      end)

      netacea:run(logFunc)

      assert.spy(logFunc).was.called()
    end)

    it('forwards non-captcha attempt captcha FAIL to mit service and expects COOKIEFAIL response', function()
      local netacea = (require 'lua_resty_netacea')
      setHttpResponse(mit_svc_url, {
        headers = {
          ['x-netacea-match'] = netacea.idTypes.IP,
          ['x-netacea-mitigate'] = netacea.mitigationTypes.BLOCKED,
          ['x-netacea-captcha'] = netacea.captchaStates.COOKIEFAIL
        },
        status = 200
      }, nil)

      local mit = netacea.idTypes.IP .. netacea.mitigationTypes.BLOCKED .. netacea.captchaStates.FAIL
      ngx.var.cookie__mitata = build_mitata_cookie(ngx.time() + 20, generate_uid(), mit, mit_svc_secret)

      package.loaded['lua_resty_netacea'] = nil

      netacea = (require 'lua_resty_netacea'):new({
        mitigationEndpoint = mit_svc_url,
        apiKey             = mit_svc_api_key,
        secretKey          = mit_svc_secret,
        mitigationEnabled  = true,
        mitigationType     = 'MITIGATE'
      })

      local logFunc = spy.new(function(res)
        assert.are.equal(res.idType, netacea.idTypes.IP)
        assert.are.equal(res.mitigationType, netacea.mitigationTypes.BLOCKED)
        assert.are.equal(res.captchaState, netacea.captchaStates.COOKIEFAIL)
      end)

      netacea:run(logFunc)

      assert.spy(logFunc).was.called()

    end)

    it('Uses and forwards configured user id variable when verifying captcha', function()
      local userIdKey = 'customUserIdValue'
      local userIdVal = 'someCustomUserId'
      ngx.var[userIdKey] = userIdVal
      ngx.var.request_uri = 'AtaVerifyCaptcha'

      local req_spy = setHttpResponse(mit_svc_url_captcha, nil, 'error')
      local netacea = (require 'lua_resty_netacea'):new({
        mitigationEndpoint = mit_svc_url,
        apiKey             = mit_svc_api_key,
        secretKey          = mit_svc_secret,
        mitigationEnabled  = true,
        userIdKey          = userIdKey,
        mitigationType     = 'MITIGATE'
      })

      netacea:run()

      local _ = match._
      assert.spy(req_spy).was.called_with(_, mit_svc_url_captcha, {
        method = 'POST',
        headers = {
          ['x-netacea-api-key'] = mit_svc_api_key,
          ['content-type'] = 'application/x-www-form-urlencoded',
          ["cookie"] = '_mitata=' .. ngx.var.cookie__mitata .. ';_mitatacaptcha=',
          ["x-netacea-userid"] = userIdVal,
          ['user-agent'] = ngx.var.http_user_agent,
          ['x-netacea-client-ip'] = ngx.var.remote_addr
        },
        timeout = 1000 -- default I suppose
      })
    end)

    it('Works with a single mitigation service endpoint', function()
      local req_spy = setHttpResponse('mitigation.endpoint', nil, 'error')
      local netacea = (require 'lua_resty_netacea'):new(netacea_default_params)

      netacea:run()

      assert.spy(req_spy).was.called(1)
      assert.spy(req_spy).was.called_with(match._, 'mitigation.endpoint', match.is_table())
    end)

    it('Round Robins between multiple mitigation service endpoints', function()
      local endpointArray = { 'mitigation.endpoint', 'mitigation2.endpoint', 'mitigation3.endpoint' }
      local netacea = (require 'lua_resty_netacea'):new(
        copy_table(
          netacea_default_params,
          { mitigationEndpoint = endpointArray }
        )
      )

      local req_spy = setHttpResponse(nil, nil, 'error')
      netacea:run() -- request 1 - endpoint 2
      assert.spy(req_spy).was.called(1)
      assert.spy(req_spy).was.called_with(match._, endpointArray[2], match.is_table())
      assert.spy(req_spy).was_not.called_with(match._, endpointArray[3], match.is_table())
      assert.spy(req_spy).was_not.called_with(match._, endpointArray[1], match.is_table())
      netacea:run() -- request 2 - endpoint 3
      assert.spy(req_spy).was.called(2)
      assert.spy(req_spy).was.called_with(match._, endpointArray[3], match.is_table())
      assert.spy(req_spy).was_not.called_with(match._, endpointArray[1], match.is_table())
      netacea:run() -- request 3 - endpoint 1
      assert.spy(req_spy).was.called(3)
      assert.spy(req_spy).was.called_with(match._, endpointArray[1], match.is_table())
      req_spy = setHttpResponse(nil, nil, 'error') -- reset call history for spy
      netacea:run() -- request 4 - endpoint 2
      assert.spy(req_spy).was.called(1)
      assert.spy(req_spy).was.called_with(match._, endpointArray[2], match.is_table())
      assert.spy(req_spy).was_not.called_with(match._, endpointArray[3], match.is_table())
      assert.spy(req_spy).was_not.called_with(match._, endpointArray[1], match.is_table())
      netacea:run() -- request 5 - endpoint 3
      assert.spy(req_spy).was.called(2)
      assert.spy(req_spy).was.called_with(match._, endpointArray[3], match.is_table())
      assert.spy(req_spy).was_not.called_with(match._, endpointArray[1], match.is_table())
      netacea:run() -- request 6 - endpoint 1
      assert.spy(req_spy).was.called(3)
      assert.spy(req_spy).was.called_with(match._, endpointArray[1], match.is_table())
    end)

    it('Passes idTypes even if idType is not found in idTypes dict', function()
      local netacea = (require 'lua_resty_netacea')
      setHttpResponse(mit_svc_url, {
        headers = {
          ['x-netacea-match'] = 'q',
          ['x-netacea-mitigate'] = netacea.mitigationTypes.BLOCKED,
          ['x-netacea-captcha'] = netacea.captchaStates.NONE
        },
        status = 200
      }, nil)

      package.loaded['lua_resty_netacea'] = nil

      netacea = (require 'lua_resty_netacea'):new({
        mitigationEndpoint = mit_svc_url,
        apiKey             = mit_svc_api_key,
        secretKey          = mit_svc_secret,
        mitigationEnabled  = true,
        mitigationType     = 'MITIGATE'
      })

      local logFunc = spy.new(function(res)
        assert.are.equal(res.idType, 'q')
        assert.are.equal(res.mitigationType, netacea.mitigationTypes.BLOCKED)
        assert.are.equal(res.captchaState, netacea.captchaStates.NONE)
      end)

      netacea:run(logFunc)

      assert.spy(logFunc).was.called()
    end)

    it('Passes mitigationType even if mitigationType is not found in mitigationTypes dict', function()
      local netacea = (require 'lua_resty_netacea')
      setHttpResponse(mit_svc_url, {
        headers = {
          ['x-netacea-match'] = netacea.idTypes.IP,
          ['x-netacea-mitigate'] = 'q',
          ['x-netacea-captcha'] = netacea.captchaStates.NONE
        },
        status = 200
      }, nil)

      package.loaded['lua_resty_netacea'] = nil

      netacea = (require 'lua_resty_netacea'):new({
        mitigationEndpoint = mit_svc_url,
        apiKey             = mit_svc_api_key,
        secretKey          = mit_svc_secret,
        mitigationEnabled  = true,
        mitigationType     = 'MITIGATE'
      })

      local logFunc = spy.new(function(res)
        assert.are.equal(res.idType, netacea.idTypes.IP)
        assert.are.equal(res.mitigationType, 'q')
        assert.are.equal(res.captchaState, netacea.captchaStates.NONE)
      end)

      netacea:run(logFunc)

      assert.spy(logFunc).was.called()
    end)

    it('Passes catchaState even if captchaState is not found in captchaStates dict', function()
      local netacea = (require 'lua_resty_netacea')
      setHttpResponse(mit_svc_url, {
        headers = {
          ['x-netacea-match'] = netacea.idTypes.IP,
          ['x-netacea-mitigate'] = netacea.mitigationTypes.BLOCKED,
          ['x-netacea-captcha'] = 'q'
        },
        status = 200
      }, nil)

      package.loaded['lua_resty_netacea'] = nil

      netacea = (require 'lua_resty_netacea'):new({
        mitigationEndpoint = mit_svc_url,
        apiKey             = mit_svc_api_key,
        secretKey          = mit_svc_secret,
        mitigationEnabled  = true,
        mitigationType     = 'MITIGATE'
      })

      local logFunc = spy.new(function(res)
        assert.are.equal(res.idType, netacea.idTypes.IP)
        assert.are.equal(res.mitigationType, netacea.mitigationTypes.BLOCKED)
        assert.are.equal(res.captchaState, 'q')
      end)

      netacea:run(logFunc)

      assert.spy(logFunc).was.called()
    end)
  end)

  describe('inject', function()
    local luaMatch = require('luassert.match')
    local mit_svc_url = 'someurl'
    local mit_svc_api_key = 'somekey'
    local mit_svc_secret = 'somesecret'
    local ngx = nil

    local function stubNgx()
      local ngx_stub = {}

      ngx_stub.var = {
        http_user_agent = 'some_user_agent',
        remote_addr = 'some_remote_addr',
        cookie__mitata = 'some_mitata_cookie',
        request_uri = '-'
      }

      ngx_stub.req = {
        read_body = function() return nil end,
        get_body_data = function() return nil end
      }

      ngx_stub.header = {}
      ngx_stub.req = {
        set_header = spy.new(function(_, _) return nil end)
      }
      ngx_stub.status = 0
      ngx_stub.HTTP_FORBIDDEN = 402

      ngx_stub.exit = spy.new(function(_, _) return nil end)
      ngx_stub.print = spy.new(function(_, _) return nil end)
      ngx_stub.ctx = {
      }
      ngx = wrap_table(require 'ngx', ngx_stub)
      package.loaded['ngx'] = ngx
    end

    local function setHttpResponse(url, response, err)
      package.loaded['http'] = nil
      local http_mock = require('resty.http')

      local req_spy = spy.new(function(_, _url, _)
        if (url) then
          assert(_url == url)
        end
        return response, err
      end)

      http_mock.new = function()
        return {
          request_uri = req_spy
        }
      end

      package.loaded['http'] = http_mock

      return req_spy
    end

    before_each(function()
      package.loaded['lua_resty_netacea'] = nil

      stubNgx()
    end)

    it('forwards to mit svc if mitata cookie check fails', function()
      local req_spy = setHttpResponse(mit_svc_url, nil, 'error')

      local netacea = (require 'lua_resty_netacea'):new({
        ingestEndpoint     = '',
        mitigationEndpoint = mit_svc_url,
        apiKey             = mit_svc_api_key,
        secretKey          = mit_svc_secret,
        realIpHeader       = '',
        ingestEnabled      = false,
        mitigationEnabled  = true,
        mitigationType     = 'INJECT'
      })

      netacea.get_mitata_cookie = spy.new(function () return nil end)

      netacea:run()

      local _ = luaMatch._

      assert.spy(req_spy).was.called(1)
      assert.spy(req_spy).was.called_with(_, mit_svc_url, {
        method = 'GET',
        headers = {
          ['x-netacea-api-key'] = mit_svc_api_key,
          ['content-type'] = 'application/x-www-form-urlencoded',
          ['user-agent'] = ngx.var.http_user_agent,
          ['x-netacea-client-ip'] = ngx.var.remote_addr,
          ["cookie"] = "_mitata=" .. ngx.var.cookie__mitata .. ';_mitatacaptcha='
        },
        timeout = 1000 -- default I suppose
      })
    end)

    it('does not forward to mit svc if mitata cookie is valid', function()
      local req_spy = setHttpResponse('-', nil, 'error')

      local netacea = (require 'lua_resty_netacea'):new({
        ingestEndpoint     = '',
        mitigationEndpoint = mit_svc_url,
        apiKey             = mit_svc_api_key,
        secretKey          = mit_svc_secret,
        realIpHeader       = '',
        ingestEnabled      = false,
        mitigationEnabled  = true,
        mitigationType     = 'INJECT'
      })

      local cookie = {
        mitigation = "000"
      }

      netacea.get_mitata_cookie = spy.new(function () return cookie end)

      netacea:run()

      assert.spy(req_spy).was.not_called()
    end)

    it('does not forward to mit service if mitata cookie is ALLOW', function()
      local req_spy = setHttpResponse('-', nil, 'error')

      local netacea = require 'lua_resty_netacea'
      local match = netacea.idTypes.IP
      local mitigate = netacea.mitigationTypes.ALLOW
      local captcha = netacea.captchaStates.NONE
      local mit = match .. mitigate .. captcha
      ngx.var.cookie__mitata = build_mitata_cookie(ngx.time() + 20, generate_uid(), mit, mit_svc_secret)

      package.loaded['lua_resty_netacea'] = nil
      netacea = (require 'lua_resty_netacea'):new({
        ingestEndpoint     = '',
        mitigationEndpoint = mit_svc_url,
        apiKey             = mit_svc_api_key,
        secretKey          = mit_svc_secret,
        realIpHeader       = '',
        ingestEnabled      = false,
        mitigationEnabled  = true,
        mitigationType     = 'INJECT'
      })

      local logFunc = spy.new(function(res)
        assert.equal(netacea.idTypes.IP, res.idType)
        assert.equal(netacea.mitigationTypes.ALLOW, res.mitigationType)
        assert.equal(netacea.captchaStates.NONE, res.captchaState)
      end)

      netacea:run(logFunc)
      assert(ngx.status == ngx.OK)
      assert.spy(ngx.req.set_header).was.called_with('x-netacea-match', match)
      assert.spy(ngx.req.set_header).was.called_with('x-netacea-mitigate', mitigate)
      assert.spy(ngx.req.set_header).was.called_with('x-netacea-captcha', captcha)
      assert.spy(req_spy).was.not_called()
      assert.spy(logFunc).was.called()
    end)

    it('does not forward to mit service if mitata cookie is BLOCK', function()
      local req_spy = setHttpResponse('-', nil, 'error')

      local netacea = (require 'lua_resty_netacea'):new({
        ingestEndpoint     = '',
        mitigationEndpoint = mit_svc_url,
        apiKey             = mit_svc_api_key,
        secretKey          = mit_svc_secret,
        realIpHeader       = '',
        ingestEnabled      = false,
        mitigationEnabled  = true,
        mitigationType     = 'INJECT'
      })
      local match = netacea.idTypes.IP
      local mitigate = netacea.mitigationTypes.BLOCKED
      local captcha = netacea.captchaStates.NONE
      local mit = match .. mitigate .. captcha
      ngx.var.cookie__mitata = build_mitata_cookie(ngx.time() + 20, generate_uid(), mit, mit_svc_secret)

      local logFunc = spy.new(function(res)
        assert(res.idType == match)
        assert(res.mitigationType == mitigate)
        assert(res.captchaState == captcha)
      end)

      netacea:run(logFunc)

      assert.spy(req_spy).was.not_called()
      assert(ngx.status == ngx.OK)
      assert.spy(ngx.req.set_header).was.called_with('x-netacea-match', match)
      assert.spy(ngx.req.set_header).was.called_with('x-netacea-mitigate', mitigate)
      assert.spy(ngx.req.set_header).was.called_with('x-netacea-captcha', captcha)
      assert.spy(logFunc).was.called()
    end)

    it('forwards to mit service if mitata cookie is CAPTCHA SERVE', function()
      local expected_captcha_body = 'some captcha body'
      local netacea = require 'lua_resty_netacea'
      local req_spy = setHttpResponse(mit_svc_url, {
        headers = {
          ['x-netacea-match'] = netacea.idTypes.IP,
          ['x-netacea-mitigate'] = netacea.mitigationTypes.BLOCKED,
          ['x-netacea-captcha'] = netacea.captchaStates.SERVE
        },
        status = 200,
        body = expected_captcha_body
      }, nil)

      package.loaded['lua_resty_netacea'] = nil
      netacea = (require 'lua_resty_netacea'):new({
        ingestEndpoint     = '',
        mitigationEndpoint = mit_svc_url,
        apiKey             = mit_svc_api_key,
        secretKey          = mit_svc_secret,
        realIpHeader       = '',
        ingestEnabled      = false,
        mitigationEnabled  = true,
        mitigationType     = 'INJECT'
      })

      local mit = netacea.idTypes.IP .. netacea.mitigationTypes.BLOCKED .. netacea.captchaStates.SERVE
      ngx.var.cookie__mitata = build_mitata_cookie(ngx.time() + 20, generate_uid(), mit, mit_svc_secret)

      local logFunc = spy.new(function(res)
        assert(res.idType == netacea.idTypes.IP)
        assert(res.mitigationType == netacea.mitigationTypes.BLOCKED)
        assert(res.captchaState == netacea.captchaStates.SERVE)
      end)

      netacea:run(logFunc)

      assert.spy(req_spy).was.called()
      assert(ngx.status == ngx.OK)
      assert.spy(ngx.print).was.not_called()
      assert.spy(ngx.exit).was.not_called()
      assert.spy(logFunc).was.called()
    end)
  end)
end)
