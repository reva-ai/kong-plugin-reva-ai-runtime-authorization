package = "kong-plugin-reva-ai-runtime-authorization"
version = "0.1.0-1"

source = {
  url = "git+https://github.com/reva-ai/kong-plugin-reva-ai-runtime-authorization.git",
  tag = "v0.1.0",
}

description = {
  summary  = "Reva AI Runtime Authorization: authorize agent, MCP and LLM traffic through Reva Trust Guardian.",
  detailed = [[
    Translates OpenAI-style model calls, MCP tool calls and A2A agent calls
    passing through Kong into Reva evaluation requests, asks Reva Trust
    Guardian for a decision, and blocks the request when that decision is
    deny.
  ]],
  homepage = "https://reva.ai",
  license  = "Apache-2.0",
}

dependencies = {
  "lua >= 5.1",
}

local pluginName = "reva-ai-runtime-authorization"

build = {
  type = "builtin",
  modules = {
    ["kong.plugins." .. pluginName .. ".handler"] = "kong/plugins/" .. pluginName .. "/handler.lua",
    ["kong.plugins." .. pluginName .. ".schema"]  = "kong/plugins/" .. pluginName .. "/schema.lua",
  },
}
