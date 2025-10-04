-- /etc/nginx/lua/jwt.lua
-- Requires: resty.jwt, resty.http, cjson
-- Builds PEM from JWK (n/e) w/out resty.openssl.bn and verifies signature.

local jwt = require("resty.jwt")
local http = require("resty.http")
local cjson = require("cjson")

local function log_info(...) ngx.log(ngx.INFO, ...) end
local function log_err(...)  ngx.log(ngx.ERR, ...)  end

-- base64url -> base64 (with padding)
local function b64url_to_b64(s)
    if not s then return nil end
    s = s:gsub("-", "+"):gsub("_", "/")
    local pad = #s % 4
    if pad ~= 0 then s = s .. string.rep("=", 4 - pad) end
    return s
end

-- hex prefix (for debugging)
local function hex_prefix(s, n)
    if not s then return "<nil>" end
    n = n or 16
    local out = {}
    for i = 1, math.min(#s, n) do out[#out+1] = string.format("%02X", string.byte(s, i)) end
    return table.concat(out, " ")
end

-- ASN.1 length encoder
local function asn1_len(len)
    if len < 128 then
        return string.char(len)
    end
    local bytes = {}
    while len > 0 do
        table.insert(bytes, 1, string.char(len % 256))
        len = math.floor(len / 256)
    end
    return string.char(0x80 + #bytes) .. table.concat(bytes)
end

-- ASN.1 INTEGER from raw big-endian bytes (prepend 0x00 if high bit set)
local function asn1_int_from_bin(bin)
    if not bin then return nil end
    if #bin == 0 then return nil end
    local first = string.byte(bin, 1)
    if first >= 0x80 then
        bin = "\0" .. bin
    end
    return string.char(0x02) .. asn1_len(#bin) .. bin
end

-- Build SubjectPublicKeyInfo PEM from modulus (n_bin) and exponent (e_bin)
local function build_rsa_spki_pem(n_bin, e_bin)
    -- RSAPublicKey SEQUENCE { INTEGER n, INTEGER e }
    local n_int = asn1_int_from_bin(n_bin)
    local e_int = asn1_int_from_bin(e_bin)
    if not n_int or not e_int then return nil, "failed to create ASN.1 integers" end

    local rsa_seq = string.char(0x30) .. asn1_len(#n_int + #e_int) .. n_int .. e_int

    -- AlgorithmIdentifier for rsaEncryption OID 1.2.840.113549.1.1.1
    -- DER bytes: SEQ{ OID, NULL } => 30 0D 06 09 2A 86 48 86 F7 0D 01 01 01 05 00
    local alg_id = string.char(0x30, 0x0D,
                               0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01,
                               0x05, 0x00)

    -- BIT STRING containing the RSAPublicKey (with leading 0x00 for unused bits)
    local bit_string = string.char(0x03) .. asn1_len(#rsa_seq + 1) .. string.char(0x00) .. rsa_seq

    -- SubjectPublicKeyInfo: SEQ{ alg_id, bit_string }
    local spki = string.char(0x30) .. asn1_len(#alg_id + #bit_string) .. alg_id .. bit_string

    -- PEM: base64-encode and wrap at 64 chars
    local b64 = ngx.encode_base64(spki)
    local pem_lines = { "-----BEGIN PUBLIC KEY-----" }
    for i = 1, #b64, 64 do
        pem_lines[#pem_lines + 1] = b64:sub(i, i + 63)
    end
    pem_lines[#pem_lines + 1] = "-----END PUBLIC KEY-----"
    local pem = table.concat(pem_lines, "\n") .. "\n"
    return pem
end

-- 1) get Authorization header + token
local auth_header = ngx.var.http_authorization
if not auth_header then
    log_info("JWT DEBUG: Missing Authorization header")
    ngx.status = ngx.HTTP_UNAUTHORIZED
    ngx.say("Missing Authorization header")
    return ngx.exit(ngx.HTTP_UNAUTHORIZED)
end

local token = string.match(auth_header, "Bearer%s+(.+)")
if not token then
    log_info("JWT DEBUG: Authorization header present but no Bearer token match")
    ngx.status = ngx.HTTP_UNAUTHORIZED
    ngx.say("Invalid Authorization header format")
    return ngx.exit(ngx.HTTP_UNAUTHORIZED)
end
log_info("JWT DEBUG: token len=", tostring(#token))

-- 2) decode header to get kid/alg
local header_b64 = token:match("^([^.]+)")
if not header_b64 then
    log_err("JWT DEBUG: cannot extract header from token")
    ngx.status = ngx.HTTP_UNAUTHORIZED
    ngx.say("Invalid token")
    return ngx.exit(ngx.HTTP_UNAUTHORIZED)
end

local header_json = ngx.decode_base64(b64url_to_b64(header_b64))
if not header_json then
    log_err("JWT DEBUG: header base64 decode failed")
    ngx.status = ngx.HTTP_UNAUTHORIZED
    ngx.say("Invalid token header")
    return ngx.exit(ngx.HTTP_UNAUTHORIZED)
end

local header = cjson.decode(header_json)
log_info("JWT DEBUG: token header=", header_json)

-- 3) fetch JWKS
local jwks_url = "http://auth:8080/auth/.well-known/jwks.json"
local httpc = http.new()
httpc:set_timeout(3000)
local res, err = httpc:request_uri(jwks_url, { method = "GET" })
if not res then
    log_err("JWT DEBUG: JWKS fetch failed: " .. tostring(err))
    ngx.status = ngx.HTTP_INTERNAL_SERVER_ERROR
    ngx.say("JWKS fetch failed")
    return ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
end
if res.status ~= 200 then
    log_err("JWT DEBUG: JWKS non-200: " .. tostring(res.status) .. " body=" .. tostring(res.body))
    ngx.status = ngx.HTTP_INTERNAL_SERVER_ERROR
    ngx.say("JWKS fetch failed")
    return ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
end

local jwks = cjson.decode(res.body)
if not jwks or not jwks.keys then
    log_err("JWT DEBUG: JWKS parse failed")
    ngx.status = ngx.HTTP_INTERNAL_SERVER_ERROR
    ngx.say("Invalid JWKS")
    return ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
end

log_info("JWT DEBUG: JWKS keys count=", tostring(#jwks.keys))
local kid_list = {}
for i,k in ipairs(jwks.keys) do kid_list[#kid_list+1] = tostring(k.kid or "<no kid>") end
log_info("JWT DEBUG: JWKS kids=", table.concat(kid_list, ", "))

-- 4) select key by kid
local selected = nil
if header and header.kid then
    for _,k in ipairs(jwks.keys) do if tostring(k.kid) == tostring(header.kid) then selected = k; break end end
end
if not selected then
    log_info("JWT DEBUG: no matching kid, falling back to first key")
    selected = jwks.keys[1]
end
if not selected then
    log_err("JWT DEBUG: no key available in JWKS")
    ngx.status = ngx.HTTP_INTERNAL_SERVER_ERROR
    ngx.say("No JWKS key available")
    return ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
end
log_info("JWT DEBUG: selected kid=", tostring(selected.kid), " kty=", tostring(selected.kty), " alg=", tostring(selected.alg))

-- 5) decode n/e into raw binary
local n_b64 = b64url_to_b64(selected.n)
local e_b64 = b64url_to_b64(selected.e)
if not n_b64 or not e_b64 then
    log_err("JWT DEBUG: selected key missing n/e")
    ngx.status = ngx.HTTP_INTERNAL_SERVER_ERROR
    ngx.say("JWKS key malformed")
    return ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
end

local n_bin = ngx.decode_base64(n_b64)
local e_bin = ngx.decode_base64(e_b64)
if not n_bin or not e_bin then
    log_err("JWT DEBUG: decode_base64 of n/e failed (n_b64 len=" .. tostring(#n_b64) .. ")")
    ngx.status = ngx.HTTP_INTERNAL_SERVER_ERROR
    ngx.say("Invalid JWK encoding")
    return ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
end

log_info("JWT DEBUG: n bytes=", tostring(#n_bin), " n prefix(hex)=", hex_prefix(n_bin, 12))
log_info("JWT DEBUG: e bytes=", tostring(#e_bin), " e prefix(hex)=", hex_prefix(e_bin, 8))

-- 6) build PEM from n/e (ASN.1 DER -> PEM)
local pem, pem_err = build_rsa_spki_pem(n_bin, e_bin)
if not pem then
    log_err("JWT DEBUG: build_rsa_spki_pem failed: " .. tostring(pem_err))
    ngx.status = ngx.HTTP_INTERNAL_SERVER_ERROR
    ngx.say("Failed to build public key")
    return ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
end

log_info("JWT DEBUG: generated PEM len=", tostring(#pem))
log_info("JWT DEBUG: PEM preview: ", pem:sub(1, 200))

-- 7) verify JWT (protected call)
local ok, verified_or_err = pcall(function() return jwt:verify(pem, token) end)
if not ok then
    log_err("JWT DEBUG: jwt:verify threw: " .. tostring(verified_or_err))
    ngx.status = ngx.HTTP_UNAUTHORIZED
    ngx.say("Invalid JWT (verify error)")
    return ngx.exit(ngx.HTTP_UNAUTHORIZED)
end
local verified = verified_or_err

-- 8) debug output for verification
log_info("=== JWT VERIFY ===")
if verified then
    log_info("JWT VERIFY: verified=", tostring(verified.verified))
    log_info("JWT VERIFY: reason=", tostring(verified.reason))
    log_info("JWT VERIFY: header=", cjson.encode(verified.header or {}))
    log_info("JWT VERIFY: payload=", cjson.encode(verified.payload or {}))
else
    log_info("JWT VERIFY: result is nil")
end
log_info("=== END VERIFY ===")

-- 9) react to verification result
if not verified or not verified.verified then
    ngx.status = ngx.HTTP_UNAUTHORIZED
    ngx.say("Invalid JWT: " .. (verified and (verified.reason or "unknown") or "verification failed"))
    return ngx.exit(ngx.HTTP_UNAUTHORIZED)
end

-- 10) propagate claims
local claims = verified.payload or {}
ngx.req.set_header("X-User-Id", claims.user_id or "")
ngx.req.set_header("X-User-Roles", table.concat(claims.roles or {}, ","))
ngx.req.set_header("X-User-Iss", claims.iss or "")

-- allow request to continue upstream
return
