local M = {}

function M.buildRandomString(length)
  local chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
  local randomString = ''

  math.randomseed(os.time())

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
  return vars['http_' .. realIpHeader] or vars.remote_addr
end


return M