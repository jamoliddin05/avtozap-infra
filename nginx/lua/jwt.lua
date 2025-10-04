local jwt   = require("resty.jwt")
local http  = require("resty.http")
local cjson = require("cjson")

-- ===== Helpers =====
local function json_response(status, msg, errs)
    ngx.status = status
    local body = { success = false, message = msg }
    if errs and #errs > 0 then body.errors = errs end
    ngx.header.content_type = "application/json"
    ngx.say(cjson.encode(body))
    return ngx.exit(status)
end

local function b64url_to_b64(s)
    if not s then return nil end
    s = s:gsub("-", "+"):gsub("_", "/")
    local pad = #s % 4
    if pad ~= 0 then s = s .. string.rep("=", 4 - pad) end
    return s
end

local function asn1_len(len)
    if len < 128 then return string.char(len) end
    local t = {}
    while len > 0 do table.insert(t, 1, string.char(len % 256)); len = math.floor(len / 256) end
    return string.char(0x80 + #t) .. table.concat(t)
end

local function asn1_int(bin)
    if not bin or #bin == 0 then return nil end
    if string.byte(bin, 1) >= 0x80 then bin = "\0" .. bin end
    return string.char(0x02) .. asn1_len(#bin) .. bin
end

local function build_pem(n_bin, e_bin)
    local n_i, e_i = asn1_int(n_bin), asn1_int(e_bin)
    if not n_i or not e_i then return nil, "ASN.1 int failed" end
    local rsa_seq = string.char(0x30) .. asn1_len(#n_i + #e_i) .. n_i .. e_i
    local alg_id = string.char(0x30,0x0D,0x06,0x09,0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x01,0x01,0x05,0x00)
    local bit_str = string.char(0x03) .. asn1_len(#rsa_seq + 1) .. "\0" .. rsa_seq
    local spki = string.char(0x30) .. asn1_len(#alg_id + #bit_str) .. alg_id .. bit_str
    local b64 = ngx.encode_base64(spki)
    return "-----BEGIN PUBLIC KEY-----\n" .. b64:gsub("(%S%S%S%S%S%S%S%S%S%S%S%S%S%S%S%S%S%S%S%S%S%S%S%S%S%S%S%S%S%S%S%S%S%S%S%S%S%S%S%S%S%S%S%S%S%S%S%S%S%S%S%S%S%S%S%S%S%S%S%S%S%S%S%S)", "%1\n") .. "\n-----END PUBLIC KEY-----\n"
end

-- ===== Main Flow =====

-- 1) Extract token
local auth = ngx.var.http_authorization
if not auth then return json_response(401, "Missing Authorization header") end
local token = auth:match("Bearer%s+(.+)")
if not token then return json_response(401, "Invalid Authorization header") end

-- 2) Parse JWT header
local header_b64 = token:match("^([^.]+)")
local header_json = ngx.decode_base64(b64url_to_b64(header_b64 or ""))
if not header_json then return json_response(401, "Invalid JWT header") end
local ok, header = pcall(cjson.decode, header_json)
if not ok then return json_response(401, "Malformed JWT header") end

-- 3) Fetch JWKS
local res, err = http.new():request_uri("http://auth:8080/auth/.well-known/jwks.json", { method = "GET" })
if not res or res.status ~= 200 then
    return json_response(500, "Failed to fetch JWKS", { err or res and res.status or "unknown" })
end
local ok2, jwks = pcall(cjson.decode, res.body)
if not ok2 or not jwks or not jwks.keys then
    return json_response(500, "Invalid JWKS format")
end

-- 4) Select key by kid
local key
for _, k in ipairs(jwks.keys) do
    if k.kid == header.kid then key = k break end
end
key = key or jwks.keys[1]
if not key or not key.n or not key.e then
    return json_response(500, "JWKS key missing required fields")
end

-- 5) Build PEM
local n_bin = ngx.decode_base64(b64url_to_b64(key.n))
local e_bin = ngx.decode_base64(b64url_to_b64(key.e))
local pem, perr = build_pem(n_bin, e_bin)
if not pem then return json_response(500, "Failed to build PEM", { perr }) end

-- 6) Verify JWT
local ok3, verified = pcall(function() return jwt:verify(pem, token) end)
if not ok3 or not verified or not verified.verified then
    return json_response(401, "Invalid JWT", { (verified and verified.reason) or verified or "verify failed" })
end

-- 7) Propagate claims
local claims = verified.payload or {}
ngx.req.set_header("X-User-Id", claims.user_id or "")
ngx.req.set_header("X-User-Roles", table.concat(claims.roles or {}, ","))
ngx.req.set_header("X-User-Iss", claims.iss or "")

-- Allow request upstream
return
