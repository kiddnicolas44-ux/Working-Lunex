-- Lunex Prometheus Runner
-- Reads Lua source from stdin, obfuscates with Prometheus, writes to stdout
-- Usage: echo "source" | lua5.1 lua/run.lua [preset]
-- Preset: Weak | Medium | Strong | Maximum (default: Strong)

-- Setup environment for Lua 5.1 compatibility
arg = arg or {}
unpack = unpack or table.unpack
loadstring = loadstring or load

-- Set package path relative to this script's location
local script_dir = debug.getinfo(1, "S").source:match("^@(.+[/\\])") or "./"
package.path = script_dir .. "?.lua;" ..
               script_dir .. "?/init.lua;" ..
               (package.path or "")

-- Load Prometheus
local ok, err = pcall(function()
    _G._Prometheus = require("prometheus")
    _G._Prometheus.Logger.logLevel = _G._Prometheus.Logger.LogLevel.Error
end)
if not ok then
    io.stderr:write("LUNEX_ERR: Failed to load Prometheus: " .. tostring(err) .. "\n")
    os.exit(1)
end

local presets = require("presets")

-- Read preset from arg
local preset_name = arg[1] or "Strong"
local preset = presets[preset_name]
if not preset then
    io.stderr:write("LUNEX_ERR: Unknown preset: " .. tostring(preset_name) .. "\n")
    os.exit(1)
end

-- Read source from stdin
local source = io.read("*all")
if not source or source == "" then
    io.stderr:write("LUNEX_ERR: No source provided on stdin\n")
    os.exit(1)
end

-- Run obfuscation
local pipeline = _G._Prometheus.Pipeline:fromConfig(preset)
local run_ok, result = pcall(function()
    return pipeline:apply(source)
end)

if not run_ok then
    io.stderr:write("LUNEX_ERR: Obfuscation failed: " .. tostring(result) .. "\n")
    os.exit(1)
end

-- Output to stdout
io.write(result)
