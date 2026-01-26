local Constants = {}

Constants['idTypesText'] = {}
Constants['idTypes'] = {
  NONE = '0',
  UA = '1',
  IP = '2',
  VISITOR = '3',
  DATACENTER = '4',
  SEV = '5',
  ORGANISATION = '6',
  ASN = '7',
  COUNTRY = '8',
  COMBINATION = '9',
  HEADERFP = 'b'
}

Constants['mitigationTypesText'] = {}
Constants['mitigationTypes'] = {
  NONE = '0',
  BLOCKED = '1',
  ALLOW = '2',
  HARDBLOCKED = '3'
}

Constants['captchaStatesText'] = {}
Constants['captchaStates'] = {
  NONE = '0',
  SERVE = '1',
  PASS = '2',
  FAIL = '3',
  COOKIEPASS = '4',
  COOKIEFAIL = '5'
}

Constants['issueReasons'] = {
    NO_SESSION = 'no_session',
    EXPIRED_SESSION = 'expired_session',
    INVALID_SESSION = 'invalid_session',
    IP_CHANGE = 'ip_change',
    FORCED_REVALIDATION = 'forced_validation',
    CAPTCHA_POST = 'captcha_post',
    CAPTCHA_GET = 'captcha_get',
}


Constants['matchBcTypes'] = {
  ['1'] = 'ua',
  ['2'] = 'ip',
  ['3'] = 'visitor',
  ['4'] = 'datacenter',
  ['5'] = 'sev',
  ['6'] = 'organisation',
  ['7'] = 'asn',
  ['8'] = 'country',
  ['9'] = 'combination',
  ['b'] = 'headerFP'
}

Constants['mitigateBcTypes'] = {
  ['1'] = 'blocked',
  ['2'] = 'allow',
  ['3'] = 'hardblocked',
  ['4'] = 'block'
}

Constants['captchaBcTypes'] = {
  ['1'] = 'captcha_serve',
  ['2'] = 'captcha_pass',
  ['3'] = 'captcha_fail',
  ['4'] = 'captcha_cookiepass',
  ['5'] = 'captcha_cookiefail'
}

local function reversifyTable(table)
  for k,v in pairs(Constants[table]) do Constants[table .. 'Text'][v] = k end
end

reversifyTable('idTypes')
reversifyTable('mitigationTypes')
reversifyTable('captchaStates')

return Constants