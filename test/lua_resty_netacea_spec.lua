require("silence_g_write_guard")
require 'busted.runner'()
-- Test file for lua_resty_netacea

insulate("lua_resty_netacea", function()
    
    describe("lua_resty_netacea", function()
        it("should always pass", function()
            assert.is_true(true)
        end)
    end)
end)