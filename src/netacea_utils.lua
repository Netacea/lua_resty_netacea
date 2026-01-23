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

function M:getIpAddress(vars, realIpHeader)
  if not realIpHeader then return vars.remote_addr end
  local realIpHeaderValue = vars['http_' .. realIpHeader]
  if not realIpHeaderValue or realIpHeaderValue == '' then
      return vars.remote_addr
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


return M