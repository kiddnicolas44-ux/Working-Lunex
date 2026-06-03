-- Deobfuscator module adapted from skama.net deobf
-- Runs in-browser via wasmoon — no filesystem or curl access

local INDENT = "    "

local function xor(a, b)
    if bit32 then return bit32.bxor(a, b) end
    local r = 0
    for i = 0, 7 do
        if a % 2 ~= b % 2 then r = r + 2^i end
        a = math.floor(a / 2)
        b = math.floor(b / 2)
    end
    return r
end

local function decode(key, bytes)
    local out = ""
    for _, b in ipairs(bytes) do
        out = out .. string.char(xor(b, key))
    end
    return out
end

local function find_key(src)
    local k = src:match("%)%((%d+)%)%s*;")
    if k then return tonumber(k) end
    for n in src:gmatch("%)%((%d+)%)") do
        n = tonumber(n)
        if n and n > 0 and n < 256 then return n end
    end
    return nil
end

local function printable(s)
    for i = 1, #s do
        local b = s:byte(i)
        if b < 32 and b ~= 9 and b ~= 10 and b ~= 13 then return false end
    end
    return true
end

local function esc(s)
    return s:gsub("([%(%)%.%%%+%-%*%?%[%^%$])", "%%%1")
end

local function rebuild(src, key)
    local replaced = 0
    local changed = true
    while changed do
        changed = false
        for name, args in src:gmatch("([%w_]+)%((%d[%d%s,]+)%)") do
            local bytes, ok = {}, true
            for n in args:gmatch("%d+") do
                n = tonumber(n)
                if not n or n < 0 or n > 255 then ok = false break end
                bytes[#bytes+1] = n
            end
            if ok and #bytes >= 3 then
                local decoded = decode(key, bytes)
                if printable(decoded) then
                    local full_call = name .. "(" .. args .. ")"
                    local safe = decoded:gsub('"', '\\"')
                    local new_src = src:gsub(esc(full_call), '"' .. safe .. '"', 1)
                    if new_src ~= src then
                        src = new_src
                        replaced = replaced + 1
                        changed = true
                    end
                end
            end
        end
    end
    return src, replaced
end

local function strip_decoder(src)
    return src:gsub("local [%w_]+=%(function%([%w_]+%)return function%(.%.%.%).-end end%)%(%d+%);\n?", "")
end

local function rename_vars(src)
    local renames = {}
    local counters = { var = 0, str = 0 }
    local function next_name(prefix)
        counters[prefix] = (counters[prefix] or 0) + 1
        return prefix .. "_" .. counters[prefix]
    end

    local decoder_name = src:match("local ([%w_]+)=%s*%(function%([%w_]+%)return function")
    if decoder_name then renames[decoder_name] = "decoder" end

    local main_name = src:match("local ([%w_]+)%s*=%s*function%(%)\n?%s*getgenv")
    if main_name then renames[main_name] = "main" end

    local pcall_err = src:match("local _,([%w_]+)%s*=pcall")
    if pcall_err then renames[pcall_err] = "ok" end

    for gvar, val in src:gmatch('getgenv%(%)%.([%w_]+)%s*=%s*"([^"]*)"') do
        if val:match("^https?://") then
            if val:match("webhook") then
                renames[gvar] = "webhook_url"
            elseif val:match("HttpGet") or val:match("loader") or val:match("luarmor") then
                renames[gvar] = "loader_url"
            else
                renames[gvar] = "remote_url"
            end
        end
    end
    for gvar, val in src:gmatch("getgenv%(%)%.([%w_]+)%s*=%s*(%d+)") do
        local n = tonumber(val)
        if n and n > 1000000 then
            renames[gvar] = "user_id"
        elseif n == 1 then
            renames[gvar] = "mode"
        elseif n == 2 then
            renames[gvar] = "flag"
        end
    end
    for gvar in src:gmatch("getgenv%(%)%.([%w_]+)%s*=%s*{") do
        renames[gvar] = "brainrots"
    end

    for varname in src:gmatch("local ([%w_]+)%s*=%s*%d+%s*;") do
        if not renames[varname] and varname:match("^_") then
            renames[varname] = next_name("var")
        end
    end
    for varname in src:gmatch('local ([%w_]+)%s*=%s*"[^"]*"%s*;') do
        if not renames[varname] and varname:match("^_") then
            renames[varname] = next_name("str")
        end
    end

    local order = {}
    for old in pairs(renames) do order[#order+1] = old end
    table.sort(order, function(a, b) return #a > #b end)

    for _, old in ipairs(order) do
        local new = renames[old]
        src = src:gsub("([^%w_])" .. esc(old) .. "([^%w_])", "%1" .. new .. "%2")
        src = src:gsub("^" .. esc(old) .. "([^%w_])", new .. "%1")
        src = src:gsub("([^%w_])" .. esc(old) .. "$", "%1" .. new)
    end

    return src, renames
end

-- Simple tokenizer for generic beautification (non-XOR code)
local function simple_tokenize(source)
    local tokens = {}
    local i = 1
    local len = #source

    local function peek(offset)
        local pos = i + (offset or 0)
        if pos > len then return "" end
        return source:sub(pos, pos)
    end

    local function match_str(s)
        return source:sub(i, i + #s - 1) == s
    end

    while i <= len do
        local c = source:sub(i, i)

        if c == " " or c == "\t" or c == "\r" or c == "\n" then
            i = i + 1

        elseif match_str("--") then
            if match_str("--[[") then
                local close = source:find("%]%]", i + 4, false)
                if close then
                    table.insert(tokens, {kind = "comment", value = source:sub(i, close + 1)})
                    i = close + 2
                else
                    table.insert(tokens, {kind = "comment", value = source:sub(i)})
                    i = len + 1
                end
            else
                local nl = source:find("\n", i)
                if nl then
                    table.insert(tokens, {kind = "comment", value = source:sub(i, nl - 1)})
                    i = nl + 1
                else
                    table.insert(tokens, {kind = "comment", value = source:sub(i)})
                    i = len + 1
                end
            end

        elseif match_str("[[") or match_str("[=[") or match_str("[==[") then
            local eq = ""
            local j = i + 1
            while j <= len and source:sub(j, j) == "=" do eq = eq .. "=" j = j + 1 end
            if j <= len and source:sub(j, j) == "[" then
                local close_pat = "]" .. eq .. "]"
                local close_pos = source:find(close_pat, j + 1, true)
                if close_pos then
                    table.insert(tokens, {kind = "string", value = source:sub(i, close_pos + #close_pat - 1)})
                    i = close_pos + #close_pat
                else
                    table.insert(tokens, {kind = "string", value = source:sub(i)})
                    i = len + 1
                end
            else
                table.insert(tokens, {kind = "symbol", value = "["})
                i = i + 1
            end

        elseif c == '"' or c == "'" then
            local quote = c
            local j = i + 1
            while j <= len do
                local ch = source:sub(j, j)
                if ch == "\\" then j = j + 2
                elseif ch == quote then j = j + 1 break
                else j = j + 1 end
            end
            table.insert(tokens, {kind = "string", value = source:sub(i, j - 1)})
            i = j

        elseif c:match("[0-9]") or (c == "." and peek(1):match("[0-9]")) then
            local j = i
            if c == "0" and (peek(1) == "x" or peek(1) == "X") then
                j = j + 2
                while j <= len and source:sub(j, j):match("[0-9a-fA-F]") do j = j + 1 end
            else
                while j <= len and source:sub(j, j):match("[0-9]") do j = j + 1 end
                if j <= len and source:sub(j, j) == "." then
                    j = j + 1
                    while j <= len and source:sub(j, j):match("[0-9]") do j = j + 1 end
                end
                if j <= len and (source:sub(j, j) == "e" or source:sub(j, j) == "E") then
                    j = j + 1
                    if j <= len and (source:sub(j, j) == "+" or source:sub(j, j) == "-") then j = j + 1 end
                    while j <= len and source:sub(j, j):match("[0-9]") do j = j + 1 end
                end
            end
            table.insert(tokens, {kind = "number", value = source:sub(i, j - 1)})
            i = j

        elseif c:match("[%a_]") then
            local j = i + 1
            while j <= len and source:sub(j, j):match("[%w_]") do j = j + 1 end
            local word = source:sub(i, j - 1)
            local keywords = {
                ["and"]=true,["break"]=true,["do"]=true,["else"]=true,["elseif"]=true,
                ["end"]=true,["false"]=true,["for"]=true,["function"]=true,["goto"]=true,
                ["if"]=true,["in"]=true,["local"]=true,["nil"]=true,["not"]=true,
                ["or"]=true,["repeat"]=true,["return"]=true,["then"]=true,["true"]=true,
                ["until"]=true,["while"]=true
            }
            if keywords[word] then
                table.insert(tokens, {kind = "keyword", value = word})
            else
                table.insert(tokens, {kind = "ident", value = word})
            end
            i = j

        elseif match_str("...") then table.insert(tokens, {kind="symbol",value="..."}); i=i+3
        elseif match_str("..") then table.insert(tokens, {kind="symbol",value=".."}); i=i+2
        elseif match_str("==") then table.insert(tokens, {kind="symbol",value="=="}); i=i+2
        elseif match_str("~=") then table.insert(tokens, {kind="symbol",value="~="}); i=i+2
        elseif match_str("<=") then table.insert(tokens, {kind="symbol",value="<="}); i=i+2
        elseif match_str(">=") then table.insert(tokens, {kind="symbol",value=">="}); i=i+2
        elseif c:match("[%(%)%{%}%[%]%;%,%+%-%*%/%%%^%#%<%>%=%:%.]") then
            table.insert(tokens, {kind = "symbol", value = c}); i = i + 1
        else
            i = i + 1
        end
    end
    return tokens
end

-- Reformat tokens with proper indentation
local function reformat(source)
    local tokens = simple_tokenize(source)
    if not tokens or #tokens == 0 then return source end

    local lines = {}
    local indent = 0
    local current_line = {}
    local n = #tokens

    local function flush_line()
        if #current_line > 0 then
            local prefix = string.rep(INDENT, math.max(0, indent))
            table.insert(lines, prefix .. table.concat(current_line, " "))
            current_line = {}
        end
    end

    local BLOCK_OPEN = {["do"]=true,["then"]=true,["repeat"]=true}
    local BLOCK_CLOSE = {["end"]=true,["until"]=true}
    local STMT_START = {
        ["local"]=true,["return"]=true,["if"]=true,["for"]=true,
        ["while"]=true,["repeat"]=true,["break"]=true,["goto"]=true
    }

    local i = 1
    while i <= n do
        local tok = tokens[i]
        local val = tok.value

        if tok.kind == "comment" then
            flush_line()
            table.insert(current_line, val)
            flush_line()
            i = i + 1

        elseif tok.kind == "keyword" and BLOCK_CLOSE[val] then
            flush_line()
            indent = math.max(0, indent - 1)
            table.insert(current_line, val)
            flush_line()
            i = i + 1

        elseif tok.kind == "keyword" and val == "else" then
            flush_line()
            indent = math.max(0, indent - 1)
            table.insert(current_line, val)
            flush_line()
            indent = indent + 1
            i = i + 1

        elseif tok.kind == "keyword" and val == "elseif" then
            flush_line()
            indent = math.max(0, indent - 1)
            table.insert(current_line, val)
            i = i + 1
            while i <= n do
                local t = tokens[i]
                table.insert(current_line, t.value)
                if t.kind == "keyword" and t.value == "then" then
                    flush_line()
                    indent = indent + 1
                    i = i + 1
                    break
                end
                i = i + 1
            end

        elseif tok.kind == "keyword" and BLOCK_OPEN[val] then
            table.insert(current_line, val)
            flush_line()
            indent = indent + 1
            i = i + 1

        elseif tok.kind == "keyword" and val == "function" then
            table.insert(current_line, val)
            i = i + 1
            local depth = 0
            while i <= n do
                local t = tokens[i]
                table.insert(current_line, t.value)
                if t.kind == "symbol" and t.value == "(" then depth = depth + 1 end
                if t.kind == "symbol" and t.value == ")" then
                    depth = depth - 1
                    if depth <= 0 then i = i + 1 break end
                end
                i = i + 1
            end
            flush_line()
            indent = indent + 1

        elseif tok.kind == "symbol" and val == ";" then
            flush_line()
            i = i + 1

        elseif tok.kind == "keyword" and STMT_START[val] then
            flush_line()
            table.insert(current_line, val)
            i = i + 1

        else
            table.insert(current_line, val)
            i = i + 1
        end
    end

    flush_line()
    local result = table.concat(lines, "\n")
    result = result:gsub("\n\n\n+", "\n\n")
    return result
end

-- Main beautify function: tries XOR deobfuscation first, then reformats
local function beautify(source)
    local output = source
    local key = find_key(source)

    if key then
        -- Prometheus-style XOR obfuscation detected
        output = rebuild(output, key)
        output = strip_decoder(output)
        output, _ = rename_vars(output)
    end

    -- Always reformat for readability
    output = reformat(output)

    return output
end

return {
    beautify = beautify,
}
