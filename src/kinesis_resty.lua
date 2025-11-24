-- kinesis_resty.lua
-- OpenResty-compatible AWS Kinesis client
-- No external dependencies, fully thread-safe

local ffi = require "ffi"
local http = require "resty.http"
local cjson = require "cjson.safe"
local sha256 = require "resty.sha256"
local str = require "resty.string"
local ngx = ngx

local Kinesis = {}
Kinesis.__index = Kinesis

ngx.log(ngx.ERR, "*** kinesis_resty module loaded ***")

-- FFI-based HMAC-SHA256
ffi.cdef[[
unsigned char *HMAC(const void *evp_md,
                    const void *key, int key_len,
                    const unsigned char *d, size_t n,
                    unsigned char *md, unsigned int *md_len);
const void* EVP_sha256(void);
]]

local function hmac_sha256(key, data)
    local md = ffi.new("unsigned char[32]")
    local md_len = ffi.new("unsigned int[1]")
    ffi.C.HMAC(ffi.C.EVP_sha256(),
               key, #key,
               data, #data,
               md, md_len)
    return ffi.string(md, md_len[0])
end

-- SHA256 helper
local function sha256_bin(data)
    local sha = sha256:new()
    sha:update(data)
    return sha:final()
end

local function hex(bin)
    return str.to_hex(bin)
end

-- Derive AWS signing key
local function get_signing_key(secret_key, date, region, service)
    local kDate   = hmac_sha256("AWS4"..secret_key, date)
    local kRegion = hmac_sha256(kDate, region)
    local kService= hmac_sha256(kRegion, service)
    local kSign   = hmac_sha256(kService, "aws4_request")
    return kSign
end

-- Constructor
function Kinesis.new(stream_name, region, access_key, secret_key)
    local self = setmetatable({}, Kinesis)
    self.stream_name = stream_name
    self.region = region
    self.access_key = access_key
    self.secret_key = secret_key
    self.host = "kinesis."..region..".amazonaws.com"
    self.endpoint = "https://"..self.host.."/"
    return self
end

-- Generate SigV4 headers
function Kinesis:_sign_request(payload, target)
    local now = os.date("!%Y%m%dT%H%M%SZ")  -- UTC time in ISO8601 basic
    local date = os.date("!%Y%m%d")         -- YYYYMMDD for scope

    local headers = {
        ["Host"] = self.host,
        ["Content-Type"] = "application/x-amz-json-1.1",
        ["X-Amz-Date"] = now,
        ["X-Amz-Target"] = target
    }

    -- canonical headers
    local canonical_headers = ""
    local signed_headers = {}
    local keys = {}
    for k,_ in pairs(headers) do table.insert(keys,k) end
    table.sort(keys, function(a,b) return a:lower() < b:lower() end)
    for _,k in ipairs(keys) do
        canonical_headers = canonical_headers .. k:lower()..":"..headers[k].."\n"
        table.insert(signed_headers, k:lower())
    end
    local signed_headers_str = table.concat(signed_headers,";")

    local payload_hash = hex(sha256_bin(payload))

    local canonical_request = table.concat{
        "POST\n",
        "/\n",
        "\n",
        canonical_headers .. "\n",
        signed_headers_str .. "\n",
        payload_hash
    }

    local canonical_request_hash = hex(sha256_bin(canonical_request))

    local scope = date.."/"..self.region.."/kinesis/aws4_request"
    local string_to_sign = table.concat{
        "AWS4-HMAC-SHA256\n",
        now.."\n",
        scope.."\n",
        canonical_request_hash
    }

    local signing_key = get_signing_key(self.secret_key, date, self.region, "kinesis")
    local signature = hex(hmac_sha256(signing_key, string_to_sign))

    headers["Authorization"] = string.format(
        "AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
        self.access_key, scope, signed_headers_str, signature
    )

    headers["Content-Length"] = #payload

    return headers
end

-- Internal send
function Kinesis:_send(target, payload)
    local httpc = http.new()
    httpc:set_timeout(5000)
    local headers = self:_sign_request(payload, target)
    ngx.log(ngx.ERR, "Kinesis Request Headers: ", cjson.encode(headers))
    local res, err = httpc:request_uri(self.endpoint, {
        method = "POST",
        body = payload,
        headers = headers,
        ssl_verify = true
    })
    return res, err
end

-- PutRecord
function Kinesis:put_record(partition_key, data)
    local payload = cjson.encode{
        StreamName = self.stream_name,
        PartitionKey = partition_key,
        Data = ngx.encode_base64(data)
    }
    return self:_send("Kinesis_20131202.PutRecord", payload)
end

-- PutRecords
function Kinesis:put_records(records)
    local recs = {}
    for _,r in ipairs(records) do
        table.insert(recs, {
            PartitionKey = r.partition_key,
            Data = ngx.encode_base64(r.data)
        })
    end
    local payload = cjson.encode{
        StreamName = self.stream_name,
        Records = recs
    }
    return self:_send("Kinesis_20131202.PutRecords", payload)
end

return Kinesis
