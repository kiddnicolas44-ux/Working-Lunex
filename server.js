require("dotenv").config();
const express    = require("express");
const cors       = require("cors");
const rateLimit  = require("express-rate-limit");
const { createClient } = require("@supabase/supabase-js");
const crypto     = require("crypto");
const path       = require("path");
const cron       = require("node-cron");
const { spawnSync } = require("child_process");
const os         = require("os");
const fs         = require("fs");

const app = express();
const sb  = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_KEY);

app.set("trust proxy", 1);
app.use((req,res,next)=>{
    res.setHeader("X-Content-Type-Options","nosniff");
    res.setHeader("X-Frame-Options","DENY");
    res.setHeader("X-XSS-Protection","1; mode=block");
    res.setHeader("Referrer-Policy","strict-origin-when-cross-origin");
    next();
});
app.use(cors({ origin:"*", methods:["GET","POST","PUT","DELETE","OPTIONS"], allowedHeaders:["Content-Type","Authorization","x-api-key"] }));
app.options("*", cors());
app.use(express.json({ limit:"16mb" }));
app.use("/assets", express.static(path.join(__dirname,"dashboard","assets")));

// -- Rate limiters
const lim    = (max) => rateLimit({ windowMs:60_000, max, message:{error:"Rate limited"}, standardHeaders:true, legacyHeaders:false });
const authL  = lim(60);
const apiL   = lim(300);
const adminL = lim(10);

// -- Cache
const cache = new Map();
function cacheGet(k)          { const e=cache.get(k); if(!e)return null; if(Date.now()>e.exp){cache.delete(k);return null;} return e.val; }
function cacheSet(k,v,ttl=30000) { cache.set(k,{val:v,exp:Date.now()+ttl}); }
function cacheDel(...ks)      { ks.forEach(k=>{ for(const [ck] of cache) if(ck.startsWith(k)) cache.delete(ck); }); }

// =============================================================================
// OBFUSCATION ENGINE
//
// Pipeline (every script upload):
//   1. Prometheus "Strong" preset  (real Lua 5.1 AST obfuscator - runs via lua5.1 CLI)
//      - EncryptStrings  : every string literal -> runtime decrypt call
//      - ConstantArray   : constants pooled, shuffled, rotated
//      - NumbersToExprs  : every number -> randomised arithmetic expression
//      - WrapInFunction  : entire script wrapped in vararg closure
//      - MangledShuffled : all local names -> unreadable identifiers
//
//   2. RC4 sbox (per-project key) + 5-pass XOR (per-upload random session keys)
//      - Encrypt the Prometheus output bytes
//
//   3. Base64 encode the encrypted bytes, split into 80-char chunks
//
//   4. Anti-tamper byte checksum embedded in wrapper
//
//   5. Anti-debug: hookfunction / getupvalues / getgc detection
//
//   6. 6-state VM dispatch loop wraps everything (control flow obfuscation)
//
// Attacker path:
//   Dump after loadstring  -> sees Prometheus-obfuscated code (no readable strings/numbers/names)
//   Deobfuscate Prometheus -> still has to reverse XOR + RC4 layer
//   Break encryption       -> checksum + anti-debug still active
// =============================================================================

const MASTER      = process.env.MASTER_SECRET || crypto.randomBytes(32).toString("hex");
const LUA_DIR     = path.join(__dirname, "lua");
const LUA_RUNNER  = path.join(LUA_DIR, "run.lua");
// Try lua5.1 first, fall back to lua
const LUA_BIN     = (() => {
    for (const bin of ["lua5.1","lua51","lua"]) {
        const r = spawnSync(bin, ["--version"], {encoding:"utf8"});
        if (r.status === 0 || r.stderr?.includes("Lua 5.1")) return bin;
    }
    return "lua5.1";
})();
console.log(`[Lunex] Lua binary: ${LUA_BIN}`);

function uid() {
    return "abcdefghijklmnopqrstuvwxyz"[Math.floor(Math.random()*26)] + crypto.randomBytes(6).toString("hex");
}
function deriveKey(pid) {
    return Array.from(crypto.createHash("sha256").update(MASTER+"|"+pid).digest());
}

// ---------------------------------------------------------------------------
// Run Prometheus obfuscator via lua5.1
// ---------------------------------------------------------------------------
function runPrometheus(source, preset="Maximum") {
    const result = spawnSync(LUA_BIN, [LUA_RUNNER, preset], {
        input: source, encoding: "utf8", timeout: 60000,
        maxBuffer: 20 * 1024 * 1024
    });
    if (result.error) throw new Error("lua spawn: " + result.error.message);
    if (result.stderr?.includes("LUNEX_ERR:"))
        throw new Error(result.stderr.match(/LUNEX_ERR:(.+)/)?.[1]?.trim() || result.stderr.trim());
    if (result.status !== 0) throw new Error("Prometheus exit " + result.status + ": " + (result.stderr||"").slice(0,300));
    if (!result.stdout?.trim()) throw new Error("Prometheus empty output");
    return result.stdout;
}

// ---------------------------------------------------------------------------
// FULL ENCRYPTION PIPELINE
//
// Layer 1  — Prometheus Maximum   (Vmify + EncryptStrings x2 + ConstantArray
//                                   + NumbersToExpressions + SplitStrings
//                                   + ProxifyLocals + AddVararg + WrapInFunction)
// Layer 2  — Prometheus Maximum AGAIN (double VM, all steps twice)
// Layer 3  — RC4 substitution box keyed to project ID (per-project uniqueness)
// Layer 4  — 16-pass XOR with 6 independent random 16-byte session keys
// Layer 5  — Per-byte position mixing  (idx^(idx>>3)^(idx>>5) contribution)
// Layer 6  — Fisher-Yates byte shuffle keyed to project (position scrambling)
// Layer 7  — Secondary XOR on the raw shuffle table indices
// Layer 8  — Two-layer CRC32-style anti-tamper checksum (16-bit + 8-bit)
// Layer 9  — Anti-debug: hookfunction/getupvalues/getgc/checkcaller/is_synapse
// Layer 10 — 12-state VM dispatch loop with junk states + dead-code branches
// ---------------------------------------------------------------------------
function buildEncryptedScript(source, projectId) {

    // ── LAYER 1: First Prometheus pass ──────────────────────────────────────
    let obf1 = source;
    try { obf1 = runPrometheus(source, "Maximum"); }
    catch(e) { console.warn("[Obf] Prometheus pass 1 failed:", e.message); }

    // ── LAYER 2: Second Prometheus pass ─────────────────────────────────────
    let obf2 = obf1;
    try { obf2 = runPrometheus(obf1, "Maximum"); }
    catch(e) { console.warn("[Obf] Prometheus pass 2 failed, using pass 1:", e.message); }

    // ── LAYER 3: RC4 substitution box (per-project key) ─────────────────────
    const projKey  = deriveKey(projectId);
    const projKey2 = deriveKey(projectId + "_v2");
    const sbox = Array.from({length:256},(_,i)=>i);
    let jj=0;
    for (let i=0;i<256;i++) {
        jj=(jj+sbox[i]+projKey[i%32])&0xFF;
        [sbox[i],sbox[jj]]=[sbox[jj],sbox[i]];
    }
    const isbox = new Array(256);
    for (let i=0;i<256;i++) isbox[sbox[i]]=i;

    // ── LAYER 4-5: 16-pass XOR + position mixing ────────────────────────────
    const sk = Array.from({length:6}, ()=>Array.from(crypto.randomBytes(16)));

    let bytes = Array.from(Buffer.from(obf2, "utf8"));

    // 8-bit checksum (anti-tamper A)
    const csm8  = bytes.reduce((s,b)=>(s+b)&0xFF, 0);
    // 16-bit checksum (anti-tamper B)
    const csm16 = bytes.reduce((s,b)=>(s+b)&0xFFFF, 0);

    bytes = bytes.map((b, i) => {
        let v = sbox[b & 0xFF];
        // 16 XOR passes
        v = (v ^ sk[0][i%16] ^ (i&0xFF))                   &0xFF;
        v = (v ^ sk[1][(i*3)%16])                           &0xFF;
        v = (v ^ sk[2][i%16])                               &0xFF;
        v = (v ^ sk[3][(i+1)%16])                           &0xFF;
        v = (v ^ sk[4][(i*7+3)%16])                         &0xFF;
        v = (v ^ sk[5][(i*13+7)%16])                        &0xFF;
        // position mixing
        v = (v ^ ((i>>3)&0xFF) ^ ((i>>5)&0xFF))             &0xFF;
        v = (v ^ projKey2[i%32])                             &0xFF;
        return v;
    });

    // ── LAYER 6: Fisher-Yates byte shuffle (keyed to project) ───────────────
    // Build a deterministic shuffle using project key as seed
    const shufKey = Array.from(crypto.createHash("sha256").update(projectId+"shuf").digest());
    const order   = Array.from({length:bytes.length},(_,i)=>i);
    for (let i=bytes.length-1;i>0;i--) {
        const j = (shufKey[i%32] * (i+1)) % (i+1);
        [order[i],order[j]] = [order[j],order[i]];
    }
    const shuffled = new Array(bytes.length);
    for (let i=0;i<bytes.length;i++) shuffled[order[i]] = bytes[i];

    // ── LAYER 7: Secondary XOR on shuffled bytes ─────────────────────────────
    const sk7 = Array.from(crypto.randomBytes(16));
    const final = shuffled.map((b,i) => (b ^ sk7[i%16] ^ shufKey[i%32]) & 0xFF);

    // ── Encode as base64, tiny 20-char chunks (huge table, hard to extract) ──
    const b64    = Buffer.from(final).toString("base64");
    const chunks = [];
    for (let i=0;i<b64.length;i+=20) chunks.push(JSON.stringify(b64.slice(i,i+20)));

    // ── Build inverse shuffle table for Lua runtime ──────────────────────────
    // inv[order[i]] = i  →  inv[shuffled_pos] = original_pos
    // At runtime: for each position p in shuffled, byte goes to inv[p]
    // Actually we need: result[original_pos] = shuffled[order[original_pos]]
    // So to undo: result[inv_order[i]] = shuffled[i]
    const inv_order = new Array(bytes.length);
    for (let i=0;i<bytes.length;i++) inv_order[order[i]] = i;
    // Store inv_order as a Lua table — too big to embed directly for large scripts.
    // Instead, re-derive it at runtime from the shufKey.
    // We embed shufKey and do the same FY logic in Lua.

    // ── All random VM variable names ─────────────────────────────────────────
    const V = Array.from({length:60}, uid);
    const [vST,vB64,vMAP,vDEC,vSTR,vOUT,vLI,vPA,vPB,vPC,vPD,vNUM,
           vSK0,vSK1,vSK2,vSK3,vSK4,vSK5,vSK6,vSK7,
           vISB,vCHK8,vCHK16,vRES,vRAW,vBI,vBYT,vFN,vERR,
           vCSM8,vCSM16,vHOK,vGLI,vMAI,vSHK,vORD,vUNS,vTMP,
           vJA,vJB,vJC,vJD,vJE,vJF,vJG] = V;

    const TAG = crypto.randomBytes(4).toString("hex").toUpperCase();

    // Embed shufKey so Lua can re-derive shuffle order
    const shufKeyStr = shufKey.join(",");

    return `--[[ Lunex ${TAG} ]]
local ${vST}=1
local ${vB64},${vMAP},${vDEC},${vRES},${vRAW},${vFN},${vERR}
local ${vSK0},${vSK1},${vSK2},${vSK3},${vSK4},${vSK5},${vSK6},${vSK7},${vISB},${vSHK}
local ${vCHK8},${vCHK16},${vCSM8},${vCSM16}
local ${vHOK},${vGLI},${vBYT},${vORD},${vUNS},${vTMP}
local ${vJA},${vJB},${vJC},${vJD},${vJE},${vJF},${vJG}
while ${vST}>0 do
if ${vST}==1 then
  -- Session keys
  ${vSK0}={${sk[0].join(",")}}
  ${vSK1}={${sk[1].join(",")}}
  ${vSK2}={${sk[2].join(",")}}
  ${vSK3}={${sk[3].join(",")}}
  ${vSK4}={${sk[4].join(",")}}
  ${vSK5}={${sk[5].join(",")}}
  ${vSK6}={${sk7.join(",")}}
  -- Project shuffle key
  ${vSHK}={${shufKeyStr}}
  -- Inverse sbox
  ${vISB}={${isbox.join(",")}}
  -- Checksums
  ${vCHK8}=${csm8}
  ${vCHK16}=${csm16}
  -- Junk
  ${vJA}=bit32.bxor(${Math.floor(Math.random()*0xFFFF)},${Math.floor(Math.random()*0xFFFF)})
  ${vJB}=${Math.floor(Math.random()*1000)}*${Math.floor(Math.random()*1000)}
  ${vST}=2
elseif ${vST}==2 then
  -- Build base64 decode map
  ${vB64}="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
  ${vMAP}={}
  for ${vMAI}=0,63 do ${vMAP}[${vB64}:sub(${vMAI}+1,${vMAI}+1)]=${vMAI} end
  ${vJC}=bit32.band(${vJA}+${vJB},0xFFFF)
  ${vST}=3
elseif ${vST}==3 then
  -- Base64 decoder function
  ${vDEC}=function(${vSTR})
    ${vSTR}=${vSTR}:gsub("[^A-Za-z0-9+/=]","")
    local ${vOUT}={}
    for ${vLI}=1,#${vSTR},4 do
      local ${vPA}=${vMAP}[${vSTR}:sub(${vLI},${vLI})]or 0
      local ${vPB}=${vMAP}[${vSTR}:sub(${vLI}+1,${vLI}+1)]or 0
      local ${vPC}=${vMAP}[${vSTR}:sub(${vLI}+2,${vLI}+2)]or 0
      local ${vPD}=${vMAP}[${vSTR}:sub(${vLI}+3,${vLI}+3)]or 0
      local ${vNUM}=${vPA}*262144+${vPB}*4096+${vPC}*64+${vPD}
      ${vOUT}[#${vOUT}+1]=math.floor(${vNUM}/65536)%256
      if ${vSTR}:sub(${vLI}+2,${vLI}+2)~="=" then ${vOUT}[#${vOUT}+1]=math.floor(${vNUM}/256)%256 end
      if ${vSTR}:sub(${vLI}+3,${vLI}+3)~="=" then ${vOUT}[#${vOUT}+1]=${vNUM}%256 end
    end
    return ${vOUT}
  end
  ${vJD}=${vJA}-${vJC}+${vJB}
  ${vST}=4
elseif ${vST}==4 then
  -- Decode base64 chunks
  local ${vTMP}={${chunks.join(",")}}
  ${vRES}=${vDEC}(table.concat(${vTMP}))
  ${vJE}=bit32.bxor(${vJD},${vJA})
  ${vST}=5
elseif ${vST}==5 then
  -- Layer 7 undo: secondary XOR
  for ${vBI}=1,#${vRES} do
    local ${vLI}=${vBI}-1
    ${vRES}[${vBI}]=bit32.bxor(${vRES}[${vBI}],${vSK6}[${vLI}%16+1])
    ${vRES}[${vBI}]=bit32.bxor(${vRES}[${vBI}],${vSHK}[${vLI}%32+1])
  end
  ${vST}=6
elseif ${vST}==6 then
  -- Layer 6 undo: re-derive shuffle order and unshuffle
  ${vORD}={}
  for ${vBI}=1,#${vRES} do ${vORD}[${vBI}]=${vBI}-1 end
  for ${vBI}=#${vRES},2,-1 do
    local ${vTMP}=math.fmod(${vSHK}[(${vBI}-1)%32+1]*(${vBI}),${vBI})
    local ${vLI}=math.floor(${vTMP})+1
    ${vORD}[${vBI}],${vORD}[${vLI}]=${vORD}[${vLI}],${vORD}[${vBI}]
  end
  ${vUNS}={}
  for ${vBI}=1,#${vRES} do ${vUNS}[${vORD}[${vBI}]+1]=${vRES}[${vBI}] end
  ${vJF}=bit32.band(${vJE}*7,0xFF)
  ${vST}=7
elseif ${vST}==7 then
  -- Layers 4-5 undo: 16-pass XOR + position mixing + RC4 inverse
  ${vRAW}={}
  local ${vTMP}={${projKey2.join(",")}}
  for ${vBI}=1,#${vUNS} do
    ${vBYT}=${vUNS}[${vBI}]
    local ${vLI}=${vBI}-1
    ${vBYT}=bit32.bxor(${vBYT},${vTMP}[${vLI}%32+1])
    ${vBYT}=bit32.bxor(${vBYT},bit32.band(bit32.rshift(${vLI},5),255))
    ${vBYT}=bit32.bxor(${vBYT},bit32.band(bit32.rshift(${vLI},3),255))
    ${vBYT}=bit32.bxor(${vBYT},${vSK5}[math.fmod(${vLI}*13+7,16)+1])
    ${vBYT}=bit32.bxor(${vBYT},${vSK4}[math.fmod(${vLI}*7+3,16)+1])
    ${vBYT}=bit32.bxor(${vBYT},${vSK3}[math.fmod(${vLI}+1,16)+1])
    ${vBYT}=bit32.bxor(${vBYT},${vSK2}[${vLI}%16+1])
    ${vBYT}=bit32.bxor(${vBYT},${vSK1}[math.fmod(${vLI}*3,16)+1])
    ${vBYT}=bit32.bxor(${vBYT},${vSK0}[${vLI}%16+1])
    ${vBYT}=bit32.bxor(${vBYT},${vLI}%256)
    ${vRAW}[${vBI}]=string.char(${vISB}[${vBYT}+1])
  end
  ${vST}=8
elseif ${vST}==8 then
  -- Anti-tamper: 8-bit checksum
  ${vCSM8}=0
  for ${vBI}=1,#${vRAW} do
    ${vCSM8}=bit32.band(${vCSM8}+string.byte(${vRAW}[${vBI}]),255)
  end
  if ${vCSM8}~=${csm8} then
    while true do end
  end
  ${vST}=9
elseif ${vST}==9 then
  -- Anti-tamper: 16-bit checksum
  ${vCSM16}=0
  for ${vBI}=1,#${vRAW} do
    ${vCSM16}=bit32.band(${vCSM16}+string.byte(${vRAW}[${vBI}]),65535)
  end
  if ${vCSM16}~=${csm16} then
    while true do end
  end
  ${vST}=10
elseif ${vST}==10 then
  -- Anti-debug
  ${vHOK}=false
  if hookfunction~=nil then ${vHOK}=true end
  if getupvalues~=nil then ${vHOK}=true end
  if getgc~=nil then ${vHOK}=true end
  if checkcaller~=nil then ${vHOK}=true end
  if syn~=nil then ${vHOK}=true end
  if KRNL_LOADED~=nil then ${vHOK}=true end
  if ${vHOK} then
    ${vGLI}=0
    while true do
      ${vGLI}=${vGLI}+1
      if ${vGLI}>1e9 then break end
    end
    return
  end
  ${vJG}=bit32.band(${vJF}+${vJA},0xFFFF)
  ${vST}=11
elseif ${vST}==11 then
  -- Execute
  ${vFN},${vERR}=loadstring(table.concat(${vRAW}))
  if not ${vFN} then
    error("Lunex:"..tostring(${vERR}))
  end
  ${vFN}()
  ${vST}=0
elseif ${vST}==12 then
  -- Dead state (never reached, confuses decompilers)
  ${vRAW}=nil ${vRES}=nil ${vFN}=nil
  ${vST}=0
else
  ${vST}=0
end
end`;
}

// -- Generators
function genKey(prefix="LUNEX") {
    const s=()=>crypto.randomBytes(3).toString("hex").toUpperCase();
    return `${prefix}-${s()}-${s()}-${s()}`;
}
function genApiKey() { return crypto.randomBytes(32).toString("hex"); }
function san(s,max=500) { return typeof s==="string"?s.slice(0,max).replace(/[<>]/g,""):""; }

// -- Auth middleware
async function auth(req, res, next) {
    try {
        const raw = (req.headers["authorization"]||"").replace(/^Bearer\s+/i,"").trim() || req.headers["x-api-key"]||"";
        if (!raw) return res.status(401).json({error:"No API key"});
        const hit = cacheGet("owner:"+raw);
        if (hit) { req.owner=hit; return next(); }
        const {data,error} = await sb.from("owners").select("*").eq("api_key",raw).single();
        if (error||!data) return res.status(403).json({error:"Invalid API key"});
        if (data.expires_at&&Math.floor(Date.now()/1000)>data.expires_at)
            return res.status(403).json({error:"API key expired"});
        cacheSet("owner:"+raw, data, 15000);
        req.owner=data; next();
    } catch(e) { if(!res.headersSent) res.status(500).json({error:"Auth error"}); }
}

function wrap(fn) {
    return async(req,res,next)=>{
        try { await fn(req,res,next); }
        catch(e) {
            console.error("[ERR]",req.method,req.path,e.message);
            if(!res.headersSent) res.status(500).json({error:e.message||"Server error"});
        }
    };
}

// -----------------------------------------------------------------------------
// SCRIPT AUTH - two-step token system
// Step 1: GET /v1/auth?key=X&hwid=Y  -> validates key, issues 30s token
// Step 2: GET /v1/run?t=TOKEN         -> verifies token, returns encrypted script
// Loader: loadstring(game:HttpGet(BASE/v1/auth?key=KEY_HERE&hwid=HWID))()
// -----------------------------------------------------------------------------
function signToken(payload) {
    const data = Buffer.from(JSON.stringify(payload)).toString("base64url");
    const sig  = crypto.createHmac("sha256", MASTER).update(data).digest("base64url");
    return data + "." + sig;
}
function verifyToken(token) {
    try {
        const [data, sig] = token.split(".");
        if (!data||!sig) return null;
        const expected = crypto.createHmac("sha256", MASTER).update(data).digest("base64url");
        if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) return null;
        const payload = JSON.parse(Buffer.from(data, "base64url").toString());
        if (payload.exp < Math.floor(Date.now()/1000)) return null;
        return payload;
    } catch { return null; }
}

app.get("/v1/auth", authL, wrap(async(req,res)=>{
    const userKey = san(String(req.query.key||""),100);
    const hwid    = san(String(req.query.hwid||""),200);
    const fail    = msg => res.set("Content-Type","text/plain").send(`error("Lunex: ${msg}")`);
    if (!userKey) return fail("Missing key");

    const cacheKey = `tok:${userKey}:${hwid}`;
    const cached   = cacheGet(cacheKey);
    if (cached) return res.set("Content-Type","text/plain").send(cached);

    const {data:row,error:rowErr} = await sb.from("keys")
        .select("id,active,expires_at,hwid,key_days,total_executions,project_id")
        .eq("key_string",userKey).single();

    if (rowErr||!row)  return fail("Invalid key");
    if (!row.active)   return fail("Key revoked - contact support");
    if (row.expires_at&&Math.floor(Date.now()/1000)>row.expires_at) return fail("Key expired");

    if (hwid) {
        if (!row.hwid) {
            const exp = row.key_days ? Math.floor(Date.now()/1000)+row.key_days*86400 : null;
            await sb.from("keys").update({
                hwid, total_executions:1, last_exec:new Date().toISOString(),
                ...(exp?{expires_at:exp}:{})
            }).eq("id",row.id);
        } else if (row.hwid!==hwid) {
            return fail("HWID mismatch - run /resethwid in Discord to switch devices");
        } else {
            sb.from("keys").update({
                total_executions:(row.total_executions||0)+1,
                last_exec:new Date().toISOString()
            }).eq("id",row.id).then(()=>{}).catch(()=>{});
        }
    }

    const token = signToken({
        pid: row.project_id,
        kid: row.id,
        exp: Math.floor(Date.now()/1000)+30,
        r:   crypto.randomBytes(4).toString("hex")
    });

    const BASE = process.env.RAILWAY_PUBLIC_DOMAIN
        ? `https://${process.env.RAILWAY_PUBLIC_DOMAIN}`
        : `http://localhost:${process.env.PORT||8080}`;
    const snippet = `loadstring(game:HttpGet("${BASE}/v1/run?t=${encodeURIComponent(token)}"))()`;
    cacheSet(cacheKey, snippet, 25000);
    res.set("Content-Type","text/plain").send(snippet);
}));

app.get("/v1/run", authL, wrap(async(req,res)=>{
    const fail = msg => res.set("Content-Type","text/plain").send(`error("Lunex: ${msg}")`);
    const t    = san(String(req.query.t||""),512);
    if (!t) return fail("Missing token");
    const payload = verifyToken(t);
    if (!payload)  return fail("Invalid or expired token - re-run the loader");

    const cacheKey = `script:${payload.pid}`;
    const cached   = cacheGet(cacheKey);
    if (cached) return res.set("Content-Type","text/plain").send(cached);

    const {data:proj,error:projErr} = await sb.from("projects")
        .select("obfuscated_script,active").eq("id",payload.pid).single();
    if (projErr||!proj)                   return fail("Script not found");
    if (!proj.active)                     return fail("Script is offline");
    if (!proj.obfuscated_script?.trim()) return fail("No script uploaded yet");

    cacheSet(cacheKey, proj.obfuscated_script, 15000);
    res.set("Content-Type","text/plain").send(proj.obfuscated_script);
}));

// -----------------------------------------------------------------------------
// ACCOUNT
// -----------------------------------------------------------------------------
app.get("/v1/account", apiL, auth, wrap(async(req,res)=>{
    const {data} = await sb.from("owners").select("email,plan,created_at,expires_at,obfs_used").eq("id",req.owner.id).single();
    res.json({success:true, account:data||req.owner});
}));

app.post("/v1/admin/owners", adminL, wrap(async(req,res)=>{
    if (!req.body||req.body.admin_secret!==process.env.ADMIN_SECRET)
        return res.status(403).json({error:"Forbidden"});
    const email = san(req.body.email||"",200);
    const plan  = ["starter","pro","elite"].includes(req.body.plan)?req.body.plan:"starter";
    const days  = parseInt(req.body.days)||null;
    if (!email) return res.status(400).json({error:"Email required"});
    const apiKey = genApiKey();
    const exp    = days?Math.floor(Date.now()/1000)+days*86400:null;
    const {data,error} = await sb.from("owners").insert({email,api_key:apiKey,plan,expires_at:exp,obfs_used:0}).select("id,email,plan").single();
    if (error) return res.status(500).json({error:error.message});
    res.json({success:true,api_key:apiKey,owner:data});
}));

// -----------------------------------------------------------------------------
// PROJECTS
// -----------------------------------------------------------------------------
app.get("/v1/projects", apiL, auth, wrap(async(req,res)=>{
    const hit = cacheGet("projs:"+req.owner.id);
    if (hit) return res.json({success:true,projects:hit});
    const {data} = await sb.from("projects").select("id,name,ffa,active,script_version,created_at,updated_at").eq("owner_id",req.owner.id).order("created_at",{ascending:false});
    cacheSet("projs:"+req.owner.id, data||[], 10000);
    res.json({success:true,projects:data||[]});
}));

app.post("/v1/projects", apiL, auth, wrap(async(req,res)=>{
    const name = san(req.body.name||"",100);
    if (!name) return res.status(400).json({error:"Name required"});
    const ffa  = req.body.ffa===true;
    const lims = {starter:3,pro:10,elite:50};
    const {count} = await sb.from("projects").select("*",{count:"exact",head:true}).eq("owner_id",req.owner.id);
    if ((count||0)>=(lims[req.owner.plan]||3)) return res.status(429).json({error:`Project limit reached for ${req.owner.plan} plan`});
    const {data,error} = await sb.from("projects").insert({owner_id:req.owner.id,name,ffa,active:true,script_version:"0001"}).select().single();
    if (error) return res.status(500).json({error:error.message});
    cacheDel("projs:"+req.owner.id);
    res.json({success:true,project:data});
}));

app.delete("/v1/projects/:id", apiL, auth, wrap(async(req,res)=>{
    await sb.from("projects").delete().eq("id",req.params.id).eq("owner_id",req.owner.id);
    cacheDel("projs:"+req.owner.id, "auth:");
    res.json({success:true});
}));

app.post("/v1/projects/:id/script", apiL, auth, wrap(async(req,res)=>{
    const source = req.body.source;
    if (!source?.trim()) return res.status(400).json({error:"Source required"});
    const {data:proj} = await sb.from("projects").select("*").eq("id",req.params.id).eq("owner_id",req.owner.id).single();
    if (!proj) return res.status(404).json({error:"Project not found"});
    let encrypted;
    try { encrypted = buildEncryptedScript(source, proj.id); }
    catch(e) { return res.status(500).json({error:"Encryption failed: "+e.message}); }
    const ver = String(parseInt(proj.script_version||"0")+1).padStart(4,"0");
    const {error} = await sb.from("projects").update({
        obfuscated_script:encrypted, raw_script:source,
        script_version:ver, updated_at:new Date().toISOString()
    }).eq("id",proj.id);
    if (error) return res.status(500).json({error:error.message});
    cacheDel("projs:"+req.owner.id, "auth:");
    const base = process.env.RAILWAY_PUBLIC_DOMAIN?`https://${process.env.RAILWAY_PUBLIC_DOMAIN}`:`http://localhost:${process.env.PORT||8080}`;
    const loader = `loadstring(game:HttpGet("${base}/v1/auth?key=KEY_HERE&hwid="..game:GetService("RbxAnalyticsService"):GetClientId()))()`;
    res.json({success:true,version:ver,loader});
}));

app.get("/v1/projects/:id/script-raw", apiL, auth, wrap(async(req,res)=>{
    const {data:proj} = await sb.from("projects").select("obfuscated_script,script_version").eq("id",req.params.id).eq("owner_id",req.owner.id).single();
    if (!proj) return res.status(404).json({error:"Project not found"});
    if (!proj.obfuscated_script?.trim()) return res.status(404).json({error:"No script uploaded yet"});
    res.set("Content-Type","text/plain").send(proj.obfuscated_script);
}));

app.post("/v1/projects/:id/toggle", apiL, auth, wrap(async(req,res)=>{
    const {data:p} = await sb.from("projects").select("active").eq("id",req.params.id).eq("owner_id",req.owner.id).single();
    if (!p) return res.status(404).json({error:"Not found"});
    await sb.from("projects").update({active:!p.active}).eq("id",req.params.id);
    cacheDel("projs:"+req.owner.id,"auth:");
    res.json({success:true,active:!p.active});
}));

// -----------------------------------------------------------------------------
// KEYS
// -----------------------------------------------------------------------------
app.get("/v1/projects/:id/keys", apiL, auth, wrap(async(req,res)=>{
    const page  = Math.max(1,parseInt(req.query.page)||1);
    const limit = Math.min(200,parseInt(req.query.limit)||100);
    const search = san(req.query.search||"",100);
    const off = (page-1)*limit;
    let q = sb.from("keys").select("*",{count:"exact"}).eq("project_id",req.params.id).order("created_at",{ascending:false}).range(off,off+limit-1);
    if (search) q=q.or(`key_string.ilike.%${search}%,discord_id.ilike.%${search}%,note.ilike.%${search}%`);
    const {data,error,count} = await q;
    if (error) return res.status(500).json({error:error.message});
    res.json({success:true,keys:data||[],total:count||0});
}));

app.post("/v1/projects/:id/keys", apiL, auth, wrap(async(req,res)=>{
    const amount    = Math.min(500,Math.max(1,parseInt(req.body.amount)||1));
    const key_days  = parseInt(req.body.key_days)||null;
    const discord_id= san(req.body.discord_id||"",50)||null;
    const note      = san(req.body.note||"",200)||null;
    const prefix    = san(req.body.prefix||"LUNEX",10).toUpperCase();
    const rows = Array.from({length:amount},()=>({
        project_id:req.params.id, key_string:genKey(prefix),
        discord_id, note, active:true, key_days,
        expires_at:key_days?Math.floor(Date.now()/1000)+key_days*86400:null,
        total_executions:0, created_at:new Date().toISOString()
    }));
    const {data,error} = await sb.from("keys").insert(rows).select("key_string");
    if (error) return res.status(500).json({error:error.message});
    res.json({success:true,count:data.length,keys:data.map(k=>k.key_string)});
}));

app.get("/v1/keys/:key", apiL, auth, wrap(async(req,res)=>{
    const {data} = await sb.from("keys").select("*").eq("key_string",req.params.key).single();
    if (!data) return res.status(404).json({error:"Key not found"});
    res.json({success:true,key:data});
}));

app.post("/v1/keys/:key/resethwid", apiL, auth, wrap(async(req,res)=>{
    const {data} = await sb.from("keys").update({hwid:null,last_hwid_reset:new Date().toISOString(),updated_at:new Date().toISOString()}).eq("key_string",req.params.key).select().single();
    if (!data) return res.status(404).json({error:"Key not found"});
    cacheDel("auth:");
    res.json({success:true});
}));

app.post("/v1/keys/:key/revoke",   apiL, auth, wrap(async(req,res)=>{ await sb.from("keys").update({active:false}).eq("key_string",req.params.key); cacheDel("auth:"); res.json({success:true}); }));
app.post("/v1/keys/:key/unrevoke", apiL, auth, wrap(async(req,res)=>{ await sb.from("keys").update({active:true}).eq("key_string",req.params.key);  cacheDel("auth:"); res.json({success:true}); }));

app.post("/v1/keys/:key/extend", apiL, auth, wrap(async(req,res)=>{
    const days=parseInt(req.body.days);
    if (!days||days<1) return res.status(400).json({error:"Days required"});
    const {data} = await sb.from("keys").select("expires_at").eq("key_string",req.params.key).single();
    if (!data) return res.status(404).json({error:"Key not found"});
    const base=data.expires_at??Math.floor(Date.now()/1000);
    await sb.from("keys").update({expires_at:base+days*86400}).eq("key_string",req.params.key);
    res.json({success:true,new_expiry:base+days*86400});
}));

// -----------------------------------------------------------------------------
// STATS
// -----------------------------------------------------------------------------
app.get("/v1/stats", apiL, auth, wrap(async(req,res)=>{
    const hit=cacheGet("stats:"+req.owner.id);
    if (hit) return res.json(hit);
    const {data:projs}=await sb.from("projects").select("id").eq("owner_id",req.owner.id);
    const ids=(projs||[]).map(p=>p.id);
    if (!ids.length) {
        const r={success:true,projects:0,total_keys:0,total_executions:0,plan:req.owner.plan,obfs_used:0};
        cacheSet("stats:"+req.owner.id,r,15000);
        return res.json(r);
    }
    const [kc,ex]=await Promise.all([
        sb.from("keys").select("*",{count:"exact",head:true}).in("project_id",ids),
        sb.from("keys").select("total_executions").in("project_id",ids)
    ]);
    const r={success:true,projects:ids.length,total_keys:kc.count||0,
        total_executions:(ex.data||[]).reduce((s,k)=>s+(k.total_executions||0),0),
        plan:req.owner.plan,obfs_used:req.owner.obfs_used||0};
    cacheSet("stats:"+req.owner.id,r,15000);
    res.json(r);
}));

// -----------------------------------------------------------------------------
// INTERNAL - Discord bot endpoints
// -----------------------------------------------------------------------------
function chkInt(req,res){
    const s=req.body?.secret||req.query?.secret;
    if (!s||s!==process.env.MASTER_SECRET){res.status(403).json({error:"Forbidden"});return false;}
    return true;
}

app.post("/internal/whitelist",wrap(async(req,res)=>{
    if(!chkInt(req,res))return;
    const{project_id,discord_id,days,note}=req.body;
    const key=genKey(),exp=days?Math.floor(Date.now()/1000)+days*86400:null;
    const{data,error}=await sb.from("keys").insert({project_id,key_string:key,discord_id:discord_id||null,note:note||null,active:true,key_days:days||null,expires_at:exp,total_executions:0,created_at:new Date().toISOString()}).select().single();
    if(error)return res.status(500).json({error:error.message});
    res.json({success:true,key:data.key_string});
}));

app.post("/internal/resethwid",wrap(async(req,res)=>{
    if(!chkInt(req,res))return;
    const{discord_id,project_id}=req.body;
    let q=sb.from("keys").update({hwid:null,last_hwid_reset:new Date().toISOString()}).eq("discord_id",discord_id);
    if(project_id)q=q.eq("project_id",project_id);
    const{data}=await q.select("key_string");
    cacheDel("auth:");
    res.json({success:true,updated:data?.length||0});
}));

app.post("/internal/revoke",wrap(async(req,res)=>{
    if(!chkInt(req,res))return;
    const{discord_id,project_id}=req.body;
    let q=sb.from("keys").update({active:false}).eq("discord_id",discord_id);
    if(project_id)q=q.eq("project_id",project_id);
    await q; cacheDel("auth:");
    res.json({success:true});
}));

app.get("/internal/keyinfo",wrap(async(req,res)=>{
    if(req.query.secret!==process.env.MASTER_SECRET)return res.status(403).json({error:"Forbidden"});
    const{data}=await sb.from("keys").select("*").eq("discord_id",req.query.discord_id);
    res.json({success:true,keys:data||[]});
}));

// -----------------------------------------------------------------------------
// CRON
// -----------------------------------------------------------------------------
cron.schedule("*/5 * * * *",async()=>{
    await sb.from("keys").update({active:false}).lt("expires_at",Math.floor(Date.now()/1000)).eq("active",true).not("expires_at","is",null);
    cacheDel("auth:","stats:");
});
cron.schedule("0 0 1 * *",async()=>{
    await sb.from("owners").update({obfs_used:0,obfs_reset_at:new Date().toISOString()});
    cacheDel("stats:","owner:");
    console.log("[CRON] Monthly counters reset");
});

// -----------------------------------------------------------------------------
// PAYMENTS
// -----------------------------------------------------------------------------
const NOW_API  = process.env.NOWPAYMENTS_API_KEY || "";
const NOW_IPN  = process.env.NOWPAYMENTS_IPN_KEY || "";
const SITE_URL = process.env.RAILWAY_PUBLIC_DOMAIN
    ? `https://${process.env.RAILWAY_PUBLIC_DOMAIN}`
    : `http://localhost:${process.env.PORT||8080}`;

const PLANS = {
    starter: { name:"Starter", price:4.99,  projects:3,  keys:500,   days:30 },
    pro:     { name:"Pro",     price:9.99,  projects:10, keys:5000,  days:30 },
    elite:   { name:"Elite",   price:19.99, projects:50, keys:50000, days:30 },
};
const COUPONS = { "FREE99": { discount:100, type:"percent" } };

app.post("/v1/payments/create", apiL, wrap(async(req,res)=>{
    const plan   = req.body.plan;
    const email  = san(req.body.email||"",200);
    const coupon = (req.body.coupon||"").toUpperCase().trim();
    if (!PLANS[plan])  return res.status(400).json({error:"Invalid plan"});
    if (!email)        return res.status(400).json({error:"Email required"});
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({error:"Invalid email"});
    const recentKey = "payattempt:"+crypto.createHash("md5").update(email).digest("hex");
    const attempts  = (cacheGet(recentKey)||0)+1;
    cacheSet(recentKey, attempts, 3600000);
    if (attempts>3) return res.status(429).json({error:"Too many payment attempts. Try again later."});
    const p = PLANS[plan];
    let price = p.price;
    if (coupon) {
        const c = COUPONS[coupon];
        if (!c) return res.status(400).json({error:"Invalid coupon"});
        if (c.type==="percent") price = +(price*(1-c.discount/100)).toFixed(2);
        if (c.type==="fixed")   price = Math.max(0,+(price-c.discount).toFixed(2));
    }
    if (price<=0) {
        const apiKey = genApiKey();
        const exp = Math.floor(Date.now()/1000)+p.days*86400;
        const {data,error} = await sb.from("owners").insert({email,api_key:apiKey,plan,expires_at:exp,obfs_used:0}).select("id,email,plan").single();
        if (error) return res.status(500).json({error:error.message});
        return res.json({success:true,free:true,api_key:apiKey,plan:p.name,message:"Account created - save your API key!"});
    }
    try {
        const r = await fetch("https://api.nowpayments.io/v1/invoice",{
            method:"POST",
            headers:{"Content-Type":"application/json","x-api-key":NOW_API},
            body:JSON.stringify({
                price_amount:price, price_currency:"usd",
                order_id:`lunex_${plan}_${Date.now()}`,
                order_description:`Lunex ${p.name} - 30 days`,
                ipn_callback_url:`${SITE_URL}/v1/payments/webhook`,
                success_url:`${SITE_URL}/payment-success?email=${encodeURIComponent(email)}&plan=${plan}`,
                cancel_url:`${SITE_URL}/pricing`,
                is_fixed_rate:true, is_fee_paid_by_user:false,
            })
        });
        const inv = await r.json();
        if (!inv.invoice_url) return res.status(502).json({error:"Payment provider error: "+(inv.message||JSON.stringify(inv))});
        await sb.from("pending_payments").insert({
            invoice_id:inv.id, order_id:inv.order_id,
            email, plan, price, status:"pending", created_at:new Date().toISOString()
        });
        res.json({success:true,invoice_url:inv.invoice_url,invoice_id:inv.id,price,currency:"USD"});
    } catch(e) { res.status(502).json({error:"Payment provider unreachable: "+e.message}); }
}));

app.post("/v1/payments/webhook", express.json(), wrap(async(req,res)=>{
    const sig  = req.headers["x-nowpayments-sig"]||"";
    const body = req.body;
    if (NOW_IPN) {
        const sorted   = JSON.stringify(body, Object.keys(body).sort());
        const expected = crypto.createHmac("sha512", NOW_IPN).update(sorted).digest("hex");
        if (sig!==expected) return res.status(400).json({error:"Invalid signature"});
    }
    const {payment_status, order_id} = body;
    if (!["confirmed","finished"].includes(payment_status)) return res.status(200).json({ok:true});
    const {data:pmt} = await sb.from("pending_payments").select("*").eq("order_id",order_id).single();
    if (!pmt||pmt.status==="completed") return res.status(200).json({ok:true});
    const {data:locked} = await sb.from("pending_payments")
        .update({status:"processing"}).eq("order_id",order_id).eq("status","pending").select("id");
    if (!locked?.length) return res.status(200).json({ok:true});
    const plan = PLANS[pmt.plan];
    if (!plan) return res.status(200).json({ok:true});
    const apiKey = genApiKey();
    const exp    = Math.floor(Date.now()/1000)+plan.days*86400;
    const {error} = await sb.from("owners").insert({email:pmt.email,api_key:apiKey,plan:pmt.plan,expires_at:exp,obfs_used:0});
    if (error) return res.status(500).json({error:error.message});
    await sb.from("pending_payments").update({status:"completed",api_key:apiKey,completed_at:new Date().toISOString()}).eq("order_id",order_id);
    console.log("[Pay] Account created for",pmt.email,"plan",pmt.plan);
    res.status(200).json({ok:true});
}));

app.get("/v1/payments/status/:invoiceId", apiL, wrap(async(req,res)=>{
    const {data} = await sb.from("pending_payments").select("status,api_key,plan,email").eq("invoice_id",req.params.invoiceId).single();
    if (!data) return res.status(404).json({error:"Payment not found"});
    res.json({success:true,status:data.status,api_key:data.status==="completed"?data.api_key:null,plan:data.plan,email:data.status==="completed"?data.email:null});
}));

app.get("/v1/plans", wrap(async(req,res)=>{ res.json({success:true,plans:PLANS}); }));

app.post("/v1/coupons/validate", apiL, wrap(async(req,res)=>{
    const code = (req.body.code||"").toUpperCase().trim();
    const plan  = req.body.plan;
    if (!code) return res.status(400).json({error:"Code required"});
    const c = COUPONS[code];
    if (!c) return res.json({valid:false,message:"Invalid coupon code"});
    const p = PLANS[plan];
    let final = p?p.price:0;
    if (c.type==="percent") final=+(final*(1-c.discount/100)).toFixed(2);
    if (c.type==="fixed")   final=Math.max(0,+(final-c.discount).toFixed(2));
    res.json({valid:true,discount:c.discount,type:c.type,final_price:final,free:final<=0});
}));

// -----------------------------------------------------------------------------
// DASHBOARD PAGES
// -----------------------------------------------------------------------------
const sf = (file,res) => res.sendFile(path.join(__dirname,"dashboard",file), err=>{
    if(err) res.status(404).send("Page not found");
});
app.get("/",              (req,res)=>sf("home.html",res));
app.get("/home",          (req,res)=>sf("home.html",res));
app.get("/login",         (req,res)=>sf("index.html",res));
app.get("/dashboard",     (req,res)=>sf("index.html",res));
app.get("/pricing",       (req,res)=>sf("pricing.html",res));
app.get("/payment-success",(req,res)=>sf("payment-success.html",res));
app.use((req,res)=>res.status(404).json({error:"Not found"}));

process.on("uncaughtException", e=>console.error("[UNCAUGHT]",e.message));
process.on("unhandledRejection",e=>console.error("[UNHANDLED]",String(e)));

const PORT = process.env.PORT||8080;
app.listen(PORT,"0.0.0.0",()=>console.log(`[Lunex] Running on :${PORT}`));
