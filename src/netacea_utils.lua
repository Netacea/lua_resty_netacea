local M = {}

function M.buildRandomString(length)
  local chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
  local randomString = ''

  local seed = os.time() * 1000000 + (os.clock() * 1000000) % 1000000
  math.randomseed(seed)

  local charTable = {}
  for c in chars:gmatch"." do
      table.insert(charTable, c)
  end

  for i=1, length do -- luacheck: ignore i
      randomString = randomString .. charTable[math.random(1, #charTable)]
  end

  return randomString
end

local function normalizeHeaderName(headerName)
  if type(headerName) ~= 'string' then return headerName end
  return headerName:lower():gsub('-', '_')
end

local function getIndexedHeaderValue(realIpHeaderValue, realIpHeaderIndex)
  if type(realIpHeaderIndex) ~= 'number' then return realIpHeaderValue end
  if realIpHeaderIndex % 1 ~= 0 then return realIpHeaderValue end

  local headerValues = {}
  for value in string.gmatch(realIpHeaderValue, '([^,]+)') do
    table.insert(headerValues, value:match("^%s*(.-)%s*$"))
  end

  local luaIndex = realIpHeaderIndex + 1
  if realIpHeaderIndex < 0 then
    luaIndex = #headerValues + realIpHeaderIndex + 1
  end

  local headerValue = headerValues[luaIndex]
  if headerValue == '' then return nil end
  return headerValue
end

function M:getIpAddress(vars, realIpHeader, realIpHeaderIndex)
  if not realIpHeader then return vars.remote_addr end
  local normalizedRealIpHeader = normalizeHeaderName(realIpHeader)
  local realIpHeaderValue = vars['http_' .. normalizedRealIpHeader]
  if not realIpHeaderValue or realIpHeaderValue == '' then
      return vars.remote_addr
  end
  if realIpHeaderIndex ~= nil then
      return getIndexedHeaderValue(realIpHeaderValue, realIpHeaderIndex) or vars.remote_addr
  end
  return realIpHeaderValue or vars.remote_addr
end

function M.parseOption(option, defaultValue)
  if type(option) == "string" then
    option = option:match("^%s*(.-)%s*$")
  end
  if option == nil or option == '' then
      return defaultValue
  end
  return option
end

function M.env(name, defaultValue)
  return os.getenv(name) or defaultValue
end

function M.envEnabled(name, defaultValue)
  local value = os.getenv(name)
  if value == nil then
    return defaultValue
  end

  return value == 'true'
end


return M
